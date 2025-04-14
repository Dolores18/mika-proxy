use std::error::Error as StdError;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use futures::ready;
use tokio::io::{AsyncRead, AsyncWrite};
use netstack_smoltcp::TcpStream as NetstackTcpStream;
use std::num::NonZeroUsize;
use crate::flow::*;
/// TcpStream适配器和转换器
pub struct TunStreamAdapter {
    stream_handle: Option<Box<dyn Stream>>,
    reader: Option<StreamReader>,
}

impl TunStreamAdapter {
    pub fn new(reader: StreamReader, flow: Box<dyn Stream>) -> Self {
        Self {
            reader: Some(reader),
            stream_handle: Some(flow),
        }
    }
    
    /// 获取并移除内部流对象
    pub fn take_stream(&mut self) -> Option<Box<dyn Stream>> {
        self.stream_handle.take()
    }
}

/// TcpStream工厂 - 负责创建和管理TcpStream连接
#[derive(Clone)]
pub struct TunStreamFactory {
    pub stream_handler: Arc<dyn StreamHandler>,
}

impl TunStreamFactory {
    pub fn new(stream_handler: Arc<dyn StreamHandler>) -> Self {
        Self { stream_handler }
    }
    
    /// 从netstack_smoltcp::TcpStream创建适配器
    pub async fn create_adapter_from_netstack(
        &self,
        stream: NetstackTcpStream,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> TunStreamAdapter {
        // 将netstack的TcpStream包装成CompatFlow
        let compat_flow = NetstackStreamAdapter::new(stream);
        let stream_impl = Box::new(compat_flow) as Box<dyn Stream>;
        
        // 创建一个空的StreamReader
        let reader = StreamReader::new(8192, Buffer::new());
        
        TunStreamAdapter::new(reader, stream_impl)
    }
    
    /// 处理入站连接
    pub fn handle_connection(
        &self,
        mut adapter: TunStreamAdapter,
        context: Box<FlowContext>,
    ) {
        // 直接将流和上下文交给处理器
        if let Some(stream) = adapter.take_stream() {
            self.stream_handler.on_stream(stream, Buffer::new(), context);
        }
    }
}

/// 适配器：将netstack_smoltcp::TcpStream转换为实现Stream trait的类型
pub struct NetstackStreamAdapter {
    inner: NetstackTcpStream,
    rx_buf: Option<Buffer>,
    tx_buf: Option<(Buffer, usize)>,
}

impl NetstackStreamAdapter {
    pub fn new(stream: NetstackTcpStream) -> Self {
        // 增加缓冲区大小为32KB，并预先分配rx_buf
        const BUFFER_SIZE: usize = 32 * 1024; // 32KB缓冲区
        
        Self {
            inner: stream,
            rx_buf: Some(Buffer::with_capacity(BUFFER_SIZE)), // 预分配接收缓冲区
            tx_buf: Some((Buffer::with_capacity(BUFFER_SIZE), 0)), // 增大发送缓冲区
        }
    }
}

impl Stream for NetstackStreamAdapter {
    // Read
    fn poll_request_size(&mut self, _cx: &mut Context<'_>) -> Poll<FlowResult<SizeHint>> {
        Poll::Ready(Ok(SizeHint::Unknown { overhead: 0 }))
    }
    
    fn commit_rx_buffer(&mut self, buffer: Buffer) -> Result<(), (Buffer, FlowError)> {
        println!("🔍 tunstream commit_rx_buffer: 准备提交缓冲区, 大小: {}, 容量: {}", buffer.len(), buffer.capacity());
        // 确保接收缓冲区有足够容量
        if buffer.capacity() < 8192 {
            let mut new_buffer = Buffer::with_capacity(32 * 1024);
            new_buffer.extend_from_slice(&buffer);
            println!("🔍 tunstream commit_rx_buffer: 扩展缓冲区容量到32KB, 新大小: {}", new_buffer.len());
            self.rx_buf = Some(new_buffer);
        } else {
            self.rx_buf = Some(buffer);
        }
        println!("🔍 tunstream commit_rx_buffer: 接收缓冲区已提交");
        Ok(())
    }
    
    fn poll_rx_buffer(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Buffer, (Buffer, FlowError)>> {
        println!("🔍 tunstream poll_rx_buffer: 开始轮询接收缓冲区");
        // 确保我们有可用的缓冲区，如果没有则创建一个
        if self.rx_buf.is_none() {
            println!("🔍 tunstream poll_rx_buffer: 创建新的接收缓冲区(32KB)");
            self.rx_buf = Some(Buffer::with_capacity(32 * 1024));
        }
        
        let rx_buf = self.rx_buf.as_mut().unwrap();
        
        // 确保缓冲区有足够的空间
        let old_capacity = rx_buf.capacity();
        rx_buf.reserve(8192);
        if rx_buf.capacity() > old_capacity {
            println!("🔍 tunstream poll_rx_buffer: 扩展缓冲区, 原容量: {}, 新容量: {}", old_capacity, rx_buf.capacity());
        }
        
        println!("🔍 tunstream poll_rx_buffer: 准备读取, 缓冲区长度: {}, 可用空间: {}", rx_buf.len(), rx_buf.capacity() - rx_buf.len());
        let mut read_buf = tokio::io::ReadBuf::uninit(rx_buf.spare_capacity_mut());
        println!("🔍 tunstream poll_rx_buffer: ReadBuf初始化, 空间大小: {}", read_buf.capacity());
        
        match ready!(Pin::new(&mut self.inner).poll_read(cx, &mut read_buf)) {
            Ok(()) => {
                let filled = read_buf.filled().len();
                println!("🔍 tunstream poll_rx_buffer: 读取完成, 填充大小: {}", filled);
                
                let mut rx_buf = self.rx_buf.take().unwrap();
                if filled == 0 {
                    println!("🔍 tunstream poll_rx_buffer: 读取为0字节, 返回EOF");
                    Poll::Ready(Err((rx_buf, FlowError::Eof)))
                } else {
                    println!("🔍 tunstream poll_rx_buffer: 设置新长度: {} + {} = {}", rx_buf.len(), filled, rx_buf.len() + filled);
                    unsafe {
                        rx_buf.set_len(rx_buf.len() + filled);
                    }
                    Poll::Ready(Ok(rx_buf))
                }
            }
            Err(e) => {
                println!("🔍 tunstream poll_rx_buffer: 读取错误: {}", e);
                Poll::Ready(Err((self.rx_buf.take().unwrap(), e.into())))
            }
        }
    }

    // Write
    fn poll_tx_buffer(
        &mut self,
        cx: &mut Context<'_>,
        size: NonZeroUsize,
    ) -> Poll<FlowResult<Buffer>> {
        ready!(self.poll_flush_tx(cx))?;
        
        // 创建或重用缓冲区
        let (mut tx_buf, _) = self.tx_buf.take().unwrap_or_else(|| {
            (Buffer::with_capacity(32 * 1024), 0)
        });
        
        tx_buf.clear();
        // 确保足够大的容量，至少是请求的大小，可能更多
        let required_size = size.get().max(8192);
        tx_buf.reserve(required_size);

        
        Poll::Ready(Ok(tx_buf))
    }
    
    fn commit_tx_buffer(&mut self, buffer: Buffer) -> FlowResult<()> {
        println!("🔍 tunstream commit_tx_buffer: 准备提交发送缓冲区, 大小: {}, 容量: {}", buffer.len(), buffer.capacity());
        
        // 验证缓冲区是否为空
        if buffer.is_empty() {
            println!("🔍 tunstream commit_tx_buffer: 警告 - 提交了空缓冲区");
        }
        
        // 确保缓冲区已初始化
        if buffer.len() > buffer.capacity() {
            println!("🔍 tunstream commit_tx_buffer: 错误 - 缓冲区长度超过容量!");
            return Err(FlowError::Eof);
        }
        
        // 确保存储缓冲区和重置偏移量
        self.tx_buf = Some((buffer, 0));
        println!("🔍 tunstream commit_tx_buffer: 发送缓冲区已提交, 准备发送, 缓冲区内容: {:0x?}", self.tx_buf);
        
        Ok(())
    }
    
    fn poll_flush_tx(&mut self, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        let Some((tx_buf, offset)) = self.tx_buf.as_mut() else {
            println!("🔍 tunstream poll_flush_tx: 没有待发送的数据");
            return Poll::Ready(Ok(()));
        };
        
        println!("🔍 tunstream poll_flush_tx: 开始发送数据, 偏移量: {}, 总长度: {}", *offset, tx_buf.len());
        
        while *offset < tx_buf.len() {
            let remaining = &tx_buf[*offset..];
            println!("🔍 tunstream poll_flush_tx: 准备发送 {} 字节数据", remaining.len());
            
            let written = ready!(Pin::new(&mut self.inner).poll_write(cx, remaining))?;
            println!("🔍 tunstream poll_flush_tx: 成功写入 {} 字节", written);
            
            *offset += written;
            println!("🔍 tunstream poll_flush_tx: 更新偏移量到 {}", *offset);
        }
        
        println!("🔍 tunstream poll_flush_tx: 所有数据已发送，执行flush");
        ready!(Pin::new(&mut self.inner).poll_flush(cx))?;
        println!("🔍 tunstream poll_flush_tx: flush完成");
        
        Poll::Ready(Ok(()))
    }

    fn poll_close_tx(&mut self, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        ready!(self.poll_flush_tx(cx))?;
        ready!(Pin::new(&mut self.inner).poll_shutdown(cx))?;
        Poll::Ready(Ok(()))
    }
}