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
use log::info;
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
        // 获取流并使用tokio::spawn异步处理
        if let Some(stream) = adapter.take_stream() {
            let handler = self.stream_handler.clone();
            
            // 使用tokio::spawn包裹on_stream调用，避免阻塞
            tokio::spawn(async move {
                info!("🔍 tunstream: 开始处理新的TCP连接");
                handler.on_stream(stream, Buffer::new(), context);
                info!("🔍 tunstream: 连接处理已交给下一级处理器");
            });
        } else {
            info!("🔍 tunstream: 警告 - 尝试处理无效的连接（stream为None）");
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
        info!("🔍 tunstream commit_rx_buffer: 准备提交缓冲区, 大小: {}, 容量: {}", buffer.len(), buffer.capacity());
        // 确保接收缓冲区有足够容量
        if buffer.capacity() < 8192 {
            let mut new_buffer = Buffer::with_capacity(32 * 1024);
            new_buffer.extend_from_slice(&buffer);
            info!("🔍 tunstream commit_rx_buffer: 扩展缓冲区容量到32KB, 新大小: {}", new_buffer.len());
            self.rx_buf = Some(new_buffer);
        } else {
            self.rx_buf = Some(buffer);
        }
        info!("🔍 tunstream commit_rx_buffer: 接收缓冲区已提交");
        Ok(())
    }
    
    fn poll_rx_buffer(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Buffer, (Buffer, FlowError)>> {
        info!("🔍 tunstream poll_rx_buffer: 开始轮询接收缓冲区");
        // 确保我们有可用的缓冲区，如果没有则创建一个
        if self.rx_buf.is_none() {
            info!("🔍 tunstream poll_rx_buffer: 创建新的接收缓冲区(32KB)");
            self.rx_buf = Some(Buffer::with_capacity(32 * 1024));
        }
        
        let rx_buf = self.rx_buf.as_mut().unwrap();
        
        // 确保缓冲区有足够的空间
        let old_capacity = rx_buf.capacity();
        rx_buf.reserve(8192);
        if rx_buf.capacity() > old_capacity {
            info!("🔍 tunstream poll_rx_buffer: 扩展缓冲区, 原容量: {}, 新容量: {}", old_capacity, rx_buf.capacity());
        }
        
        info!("🔍 tunstream poll_rx_buffer: 准备读取, 缓冲区长度: {}, 可用空间: {}", rx_buf.len(), rx_buf.capacity() - rx_buf.len());

        // 创建一个初始化的缓冲区，而不是使用未初始化的缓冲区
        // 预分配一个临时缓冲区并初始化为0
        let mut temp_buf = vec![0u8; 8192]; 
        let mut read_buf = tokio::io::ReadBuf::new(&mut temp_buf);
        
        info!("🔍 tunstream poll_rx_buffer: ReadBuf初始化, 空间大小: {}", read_buf.capacity());
        
        match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let filled = read_buf.filled().len();
                info!("🔍 tunstream poll_rx_buffer: 读取完成, 填充大小: {}", filled);
                
                let mut rx_buf = self.rx_buf.take().unwrap();
                if filled == 0 {
                    // filled == 0 表示流结束 (EOF)
                    info!("🔍 tunstream poll_rx_buffer: 读取为0字节，识别为 EOF");
                    // 清空缓冲区，因为没有新数据
                    rx_buf.clear();
                    // 返回包含空缓冲区和 EOF 错误的 Poll::Ready
                    Poll::Ready(Err((rx_buf, FlowError::Eof)))
                } else {
                    // 将读取到的数据复制到rx_buf中
                    rx_buf.extend_from_slice(&read_buf.filled());
                 info!("🔍 tunstream poll_rx_buffer: 添加{}字节到缓冲区, 总大小: {}", filled, rx_buf.len());
                    Poll::Ready(Ok(rx_buf))
                }
            }
            Poll::Ready(Err(e)) => {
                // 打印更详细的错误信息，包括错误类型
                info!("🔍 tunstream poll_rx_buffer: 读取错误: {}, Kind: {:?}", e, e.kind());
                // 只有真正的错误才返回EOF
                Poll::Ready(Err((self.rx_buf.take().unwrap(), e.into())))
            }
            Poll::Pending => {
                info!("🔍 tunstream poll_rx_buffer: 读取挂起，等待更多数据");
                Poll::Pending
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
        info!("🔍 tunstream commit_tx_buffer: 准备提交发送缓冲区, 大小: {}, 容量: {}", 
                 buffer.len(), buffer.capacity());
        
        // 验证缓冲区是否为空，但不要阻止提交
        if buffer.is_empty() {
            info!("🔍 tunstream commit_tx_buffer: 警告 - 提交了空缓冲区，但仍继续处理");
        }
        
        // 移除过于严格的检查
        // if buffer.len() > buffer.capacity() {
        //     println!("🔍 tunstream commit_tx_buffer: 错误 - 缓冲区长度超过容量!");
        //     return Err(FlowError::Eof);
        // }
        
        // 确保存储缓冲区和重置偏移量
        self.tx_buf = Some((buffer, 0));
        
        // 打印缓冲区的前几个字节，帮助调试
        if let Some((buf, _)) = &self.tx_buf {
            if !buf.is_empty() {
                let preview_len = buf.len().min(32);
                info!("🔍 tunstream commit_tx_buffer: 发送缓冲区已提交, 准备发送");
                info!("🔍 tunstream commit_tx_buffer: 缓冲区前{}字节: {:02x?}", 
                         preview_len, &buf[..preview_len]);
            } else {
                info!("🔍 tunstream commit_tx_buffer: 发送缓冲区已提交(空)");
            }
        }
        
        Ok(())
    }
    
    
    
    fn poll_flush_tx(&mut self, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        let Some((tx_buf, offset)) = self.tx_buf.as_mut() else {
            info!("🔍 tunstream poll_flush_tx: 没有待发送的数据");
            return Poll::Ready(Ok(()));
        };
        
        info!("🔍 tunstream poll_flush_tx: 开始发送数据, 偏移量: {}, 总长度: {}", *offset, tx_buf.len());
        
        // 如果没有数据要发送或已经发送完毕，直接返回成功
        if tx_buf.is_empty() || *offset >= tx_buf.len() {
            info!("🔍 tunstream poll_flush_tx: 没有数据需要发送或已发送完毕");
            return Poll::Ready(Ok(()));
        }
        
        // 尝试写入剩余数据
        let remaining = &tx_buf[*offset..];
        info!("🔍 tunstream poll_flush_tx: 准备发送 {} 字节数据", remaining.len());
        
        match Pin::new(&mut self.inner).poll_write(cx, remaining) {
            Poll::Ready(Ok(written)) => {
                info!("🔍 tunstream poll_flush_tx: 成功写入 {} 字节", written);
                *offset += written;
                
                // 如果还有数据未发送完，返回Pending让调用者继续发送
                if *offset < tx_buf.len() {
                    info!("🔍 tunstream poll_flush_tx: 还有 {} 字节未发送，继续发送", tx_buf.len() - *offset);
                    return Poll::Pending;
                }
                
                // 数据发送完毕，执行flush
                info!("🔍 tunstream poll_flush_tx: 所有数据已发送，执行flush");
                match Pin::new(&mut self.inner).poll_flush(cx) {
                    Poll::Ready(Ok(())) => {
                        info!("🔍 tunstream poll_flush_tx: flush完成");
                        Poll::Ready(Ok(()))
                    }
                    Poll::Ready(Err(e)) => {
                        info!("🔍 tunstream poll_flush_tx: flush错误: {}", e);
                        Poll::Ready(Err(e.into()))
                    }
                    Poll::Pending => {
                        info!("🔍 tunstream poll_flush_tx: flush挂起，稍后再试");
                        Poll::Pending
                    }
                }
            }
            Poll::Ready(Err(e)) => {
                info!("🔍 tunstream poll_flush_tx: 写入错误: {}", e);
                Poll::Ready(Err(e.into()))
            }
            Poll::Pending => {
                info!("🔍 tunstream poll_flush_tx: 写入挂起，稍后再试");
                Poll::Pending
            }
        }
    }
    

    fn poll_close_tx(&mut self, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        ready!(self.poll_flush_tx(cx))?;
        ready!(Pin::new(&mut self.inner).poll_shutdown(cx))?;
        Poll::Ready(Ok(()))
    }
}