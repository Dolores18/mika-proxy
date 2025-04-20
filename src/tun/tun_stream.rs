use std::io;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::{Arc, Weak, Mutex};
use std::task::{Context, Poll};
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use futures::ready;
use log::{debug, error, info};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, AsyncWriteExt};

use super::{Buffer, FlowContext, FlowError, FlowResult, SizeHint, Stream, StreamHandler, StreamOutboundFactory};
use crate::flow::*;
// TunTcpStream implementation
pub struct TunTcpStream {
    inner: netstack_smoltcp::TcpStream,
    context: Arc<FlowContext>,
    pending_write: Vec<u8>,         // 改为直接使用Vec<u8>，去掉Arc<Mutex<>>
    has_pending_data: bool,         // 改为直接使用bool，去掉Arc<AtomicBool>
}

impl TunTcpStream {
    pub fn new(stream: netstack_smoltcp::TcpStream, local_addr: SocketAddr, remote_addr: SocketAddr) -> Self {
        let remote_dest = DestinationAddr::from(remote_addr);
        println!("[TunTcpStream::new] 创建新连接: {} -> {}", remote_addr, local_addr);
        Self {
            inner: stream,
            context: Arc::new(FlowContext::new(local_addr, remote_dest)),
            pending_write: Vec::new(),   // 直接初始化为空Vec
            has_pending_data: false,     // 直接初始化为false
        }
    }

    pub fn new_af_sensitive(stream: netstack_smoltcp::TcpStream, local_addr: SocketAddr, remote_addr: SocketAddr) -> Self {
        let remote_dest = DestinationAddr::from(remote_addr);
        info!("[TunTcpStream::new_af_sensitive] 创建新连接: {} -> {}", remote_addr, local_addr);
        Self {
            inner: stream,
            context: Arc::new(FlowContext::new_af_sensitive(local_addr, remote_dest)),
            pending_write: Vec::new(),   // 直接初始化为空Vec
            has_pending_data: false,     // 直接初始化为false
        }
    }

    pub fn get_context(&self) -> &FlowContext {
        &self.context
    }

    // 添加一个方法，用于保持连接活跃
    pub fn keep_alive(&self) -> impl Future<Output = ()> + 'static {
        info!("[TunTcpStream::keep_alive] 启动保活任务");
        let remote_addr = self.context.remote_peer.to_string();
        async move {
            loop {
                info!("[TunTcpStream::keep_alive] 连接 {} 保持活跃中...", remote_addr);
                tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
            }
        }
    }
}

// 错误转换函数
fn convert_error(err: io::Error) -> FlowError {
    use io::ErrorKind;
    match err.kind() {
        ErrorKind::BrokenPipe => FlowError::Eof,
        ErrorKind::NotConnected => FlowError::NoOutbound,
        ErrorKind::InvalidData => FlowError::UnexpectedData,
        _ => FlowError::Io(err),
    }
}

impl Stream for TunTcpStream {
    fn poll_request_size(&mut self, _cx: &mut Context<'_>) -> Poll<FlowResult<SizeHint>> {
        // 直接返回未知大小，假设底层流无法提供具体大小提示
        Poll::Ready(Ok(SizeHint::Unknown { overhead: 0 }))
    }

    fn commit_rx_buffer(&mut self, buffer: Buffer) -> Result<(), (Buffer, FlowError)> {
        // 直接忽略传入的缓冲区，因为我们将直接使用 inner 的读取逻辑
        Ok(())
    }

    fn poll_rx_buffer(&mut self, cx: &mut Context<'_>) -> Poll<Result<Buffer, (Buffer, FlowError)>> {
    info!("[TunTcpStream::poll_rx_buffer] 开始读取数据");
        // 创建一个新的缓冲区，预分配 16KB
        let mut buffer = Vec::with_capacity(16384);
        // 确保缓冲区有足够空间
        buffer.resize(16384, 0); // 显式初始化为 0
        let mut read_buf = ReadBuf::new(&mut buffer[..]);

        match ready!(Pin::new(&mut self.inner).poll_read(cx, &mut read_buf)) {
            Ok(()) => {
                let filled = read_buf.filled().len();
                if filled == 0 {
                    // EOF
                    println!("[TunTcpStream::poll_rx_buffer] 接收到EOF，连接已关闭");
                    Poll::Ready(Err((Vec::new(), FlowError::Eof)))
                } else {
                    // 只保留实际填充的数据
                    buffer.truncate(filled);
                    println!("[TunTcpStream::poll_rx_buffer] 读取到 {} 字节数据", filled);
                    Poll::Ready(Ok(buffer))
                }
            }
            Err(e) => {
                // 返回空的缓冲区和错误
                info!("[TunTcpStream::poll_rx_buffer] 读取错误: {:?}", e);
                Poll::Ready(Err((Vec::new(), convert_error(e))))
            }
        }
    }

    fn poll_tx_buffer(&mut self, _cx: &mut Context<'_>, size: NonZeroUsize) -> Poll<FlowResult<Buffer>> {
        // 直接返回一个新的缓冲区，准备接收待发送的数据
        info!("[TunTcpStream::poll_tx_buffer] 分配发送缓冲区，请求大小: {}", size.get());
        let buffer = Vec::with_capacity(size.get());
        Poll::Ready(Ok(buffer))
    }

    fn commit_tx_buffer(&mut self, buffer: Buffer) -> FlowResult<()> {
        // 避免提交空缓冲区
        if buffer.is_empty() {
            info!("[TunTcpStream::commit_tx_buffer] 跳过空缓冲区");
            return Ok(());  // 静默跳过空缓冲区，不作为错误处理
        }
        
        info!("[TunTcpStream::commit_tx_buffer] 提交发送缓冲区，大小: {}", buffer.len());
        
        // 直接操作pending_write，不需要锁
        if !self.pending_write.is_empty() {
            info!("[TunTcpStream::commit_tx_buffer] 合并到现有缓冲区 (原大小: {})", self.pending_write.len());
            self.pending_write.extend_from_slice(&buffer);
        } else {
            self.pending_write = buffer;
        }
        
        info!("[TunTcpStream::commit_tx_buffer] 更新后缓冲区大小: {}", self.pending_write.len());
        self.has_pending_data = true;
        
        info!("[TunTcpStream::commit_tx_buffer] 数据已放入缓冲区，等待下次poll_flush_tx发送");
        Ok(())
    }

    fn poll_flush_tx(&mut self, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        info!("[TunTcpStream::poll_flush_tx] 极简版开始执行");

        // 检查是否有待发送数据
        if self.has_pending_data && !self.pending_write.is_empty() {
            info!("[TunTcpStream::poll_flush_tx] 尝试写入 {} 字节", self.pending_write.len());
            
            // 取出数据
            let data = std::mem::take(&mut self.pending_write);
            self.has_pending_data = false;
            
            // 尝试一次性写入
            match Pin::new(&mut self.inner).poll_write(cx, &data) {
                Poll::Ready(Ok(n)) => {
                    info!("[TunTcpStream::poll_flush_tx] 写入了 {} 字节", n);
                    // 不处理部分写入情况，即使 n < data.len() 也不管
                }
                Poll::Ready(Err(e)) => {
                    info!("[TunTcpStream::poll_flush_tx] 写入错误: {:?}", e);
                    return Poll::Ready(Err(convert_error(e)));
                }
                Poll::Pending => {
                    // 将数据放回缓冲区，因为写入未完成
                    self.pending_write = data;
                    self.has_pending_data = true;
                    info!("[TunTcpStream::poll_flush_tx] 写入挂起");
                    return Poll::Pending;
                }
            }
        }

        // 直接尝试刷新底层流
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                info!("[TunTcpStream::poll_flush_tx] 刷新成功");
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => {
                info!("[TunTcpStream::poll_flush_tx] 刷新错误: {:?}", e);
                Poll::Ready(Err(convert_error(e)))
            }
            Poll::Pending => {
                info!("[TunTcpStream::poll_flush_tx] 刷新挂起");
                Poll::Pending
            }
        }
    }

    fn poll_close_tx(&mut self, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        info!("[TunTcpStream::poll_close_tx] 开始关闭发送通道");
        
        // 检查是否有待发送数据
        if self.has_pending_data {
            info!("[TunTcpStream::poll_close_tx] 发现未发送的数据，先刷新缓冲区");
            // 先确保数据被发送出去
            match self.poll_flush_tx(cx) {
                Poll::Ready(Ok(())) => {
                    info!("[TunTcpStream::poll_close_tx] 刷新成功，继续关闭");
                }
                Poll::Ready(Err(e)) => {
                    info!("[TunTcpStream::poll_close_tx] 刷新失败: {:?}", e);
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => {
                    info!("[TunTcpStream::poll_close_tx] 刷新操作未完成，等待下一次尝试");
                    return Poll::Pending;
                }
            }
        }
        
        // 数据已刷新完毕，现在可以安全关闭连接
        match ready!(Pin::new(&mut self.inner).poll_shutdown(cx)) {
            Ok(()) => {
                info!("[TunTcpStream::poll_close_tx] 关闭成功");
                Poll::Ready(Ok(()))
            },
            Err(e) => {
                info!("[TunTcpStream::poll_close_tx] 关闭错误: {:?}", e);
                Poll::Ready(Err(convert_error(e)))
            },
        }
    }
}
// Stream Handler for TunTcpStream
pub struct TunStreamHandler {
    next: Weak<dyn StreamHandler>,
}

impl TunStreamHandler {
    pub fn new(next: Weak<dyn StreamHandler>) -> Self {
        Self { next }
    }
    
    // Helper function to create a TunTcpStream
    pub fn create_tun_stream(
        stream: netstack_smoltcp::TcpStream,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        af_sensitive: bool,
    ) -> TunTcpStream {
        if af_sensitive {
            TunTcpStream::new_af_sensitive(stream, local_addr, remote_addr)
        } else {
            TunTcpStream::new(stream, local_addr, remote_addr)
        }
    }
}

impl StreamHandler for TunStreamHandler {
    fn on_stream(
        &self,
        lower: Box<dyn Stream>,
        initial_data: Buffer,
        context: Box<FlowContext>,
    ) {
        let next = match self.next.upgrade() {
            Some(next) => next,
            None => {
                info!("Next handler is not available");
                return;
            }
        };
        
        // Just pass along to the next handler in the chain
        info!("TunStreamHandler passing stream to next handler");
        next.on_stream(lower, initial_data, context);
    }
}