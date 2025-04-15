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
    pending_write: Arc<Mutex<Buffer>>, // 改为Arc<Mutex<Buffer>>
    has_pending_data: Arc<AtomicBool>, // 改为Arc<AtomicBool>
}

impl TunTcpStream {
    pub fn new(stream: netstack_smoltcp::TcpStream, local_addr: SocketAddr, remote_addr: SocketAddr) -> Self {
        let remote_dest = DestinationAddr::from(remote_addr);
        println!("[TunTcpStream::new] 创建新连接: {} -> {}", remote_addr, local_addr);
        Self {
            inner: stream,
            context: Arc::new(FlowContext::new(local_addr, remote_dest)),
            pending_write: Arc::new(Mutex::new(Vec::new())),
            has_pending_data: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn new_af_sensitive(stream: netstack_smoltcp::TcpStream, local_addr: SocketAddr, remote_addr: SocketAddr) -> Self {
        let remote_dest = DestinationAddr::from(remote_addr);
        println!("[TunTcpStream::new_af_sensitive] 创建新连接: {} -> {}", remote_addr, local_addr);
        Self {
            inner: stream,
            context: Arc::new(FlowContext::new_af_sensitive(local_addr, remote_dest)),
            pending_write: Arc::new(Mutex::new(Vec::new())),
            has_pending_data: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn get_context(&self) -> &FlowContext {
        &self.context
    }

    // 添加一个方法，用于保持连接活跃
    pub fn keep_alive(&self) -> impl Future<Output = ()> + 'static {
        println!("[TunTcpStream::keep_alive] 启动保活任务");
        let remote_addr = self.context.remote_peer.to_string();
        async move {
            loop {
                println!("[TunTcpStream::keep_alive] 连接 {} 保持活跃中...", remote_addr);
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
        println!("[TunTcpStream::poll_rx_buffer] 开始读取数据");
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
                println!("[TunTcpStream::poll_rx_buffer] 读取错误: {:?}", e);
                Poll::Ready(Err((Vec::new(), convert_error(e))))
            }
        }
    }

    fn poll_tx_buffer(&mut self, _cx: &mut Context<'_>, size: NonZeroUsize) -> Poll<FlowResult<Buffer>> {
        // 直接返回一个新的缓冲区，准备接收待发送的数据
        println!("[TunTcpStream::poll_tx_buffer] 分配发送缓冲区，请求大小: {}", size.get());
        let mut buffer = Vec::with_capacity(size.get());
        Poll::Ready(Ok(buffer))
    }

    fn commit_tx_buffer(&mut self, buffer: Buffer) -> FlowResult<()> {
        // 立即发送数据，不再只是暂存
        println!("[TunTcpStream::commit_tx_buffer] 提交发送缓冲区，大小: {}", buffer.len());
        
        // 避免提交空缓冲区
        if buffer.is_empty() {
            println!("[TunTcpStream::commit_tx_buffer] 跳过空缓冲区");
            return Ok(());  // 静默跳过空缓冲区，不作为错误处理
        }
        
        // TcpStream只实现了AsyncWrite，不能在这里同步发送
        // 将数据保存到缓冲区，由poll_flush_tx处理
        if let Ok(mut pending) = self.pending_write.lock() {
            // 添加到现有缓冲区
            if !pending.is_empty() {
                println!("[TunTcpStream::commit_tx_buffer] 合并到现有缓冲区 (原大小: {})", pending.len());
                pending.extend_from_slice(&buffer);
            } else {
                *pending = buffer;
            }
            
            println!("[TunTcpStream::commit_tx_buffer] 更新后缓冲区大小: {}", pending.len());
            self.has_pending_data.store(true, std::sync::atomic::Ordering::SeqCst);
            
            // 不再使用后台任务尝试立即发送，而是直接设置标志等待下一次poll_flush_tx
            println!("[TunTcpStream::commit_tx_buffer] 数据已放入缓冲区，等待下次poll_flush_tx发送");
            
            // 添加一个立即触发的唤醒机制
            // 这将尝试"伪造"一个微任务唤醒
            #[cfg(feature = "fake_poll_wakeup")]
            {
                // 只有在特定feature启用时才包含此代码
                use std::task::Wake;
                
                struct FakeWaker;
                impl Wake for FakeWaker {
                    fn wake(self: Arc<Self>) {
                        // 不做任何事，只为了尽快唤醒任务
                    }
                }
                
                // 创建一个假唤醒器尝试触发任务唤醒
                let waker = Arc::new(FakeWaker).into_waker();
                let mut ctx = std::task::Context::from_waker(&waker);
                
                // 尝试直接获取写入进度
                let _ = Pin::new(&mut self.inner).poll_flush(&mut ctx);
            }
            
            Ok(())
        } else {
            println!("[TunTcpStream::commit_tx_buffer] 错误：无法锁定待发送缓冲区");
            Err(FlowError::UnexpectedData)
        }
    }

    fn poll_flush_tx(&mut self, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        println!("[TunTcpStream::poll_flush_tx] 开始刷新发送缓冲区");

        // 使用循环确保所有待处理数据都被尝试写入
        loop {
            let mut buffer = match self.pending_write.lock() {
                Ok(mut guard) => {
                    if guard.is_empty() {
                        // 没有待发送的数据了
                        self.has_pending_data.store(false, Ordering::SeqCst);
                        break; // 跳出循环，进行最后的 flush
                    }
                    // 取出缓冲区内容进行处理，清空Mutex内部的Vec
                    std::mem::take(&mut *guard)
                }
                Err(_) => {
                    println!("[TunTcpStream::poll_flush_tx] 错误：无法锁定待发送缓冲区");
                    return Poll::Ready(Err(FlowError::UnexpectedData));
                }
            };

            println!("[TunTcpStream::poll_flush_tx] 发现待发送数据 {} 字节", buffer.len());
            let mut offset = 0;

            // 循环写入当前缓冲区的数据
            while offset < buffer.len() {
                match Pin::new(&mut self.inner).poll_write(cx, &buffer[offset..]) {
                    Poll::Ready(Ok(n)) => {
                        if n == 0 {
                            // 写入0字节通常表示错误或连接关闭
                            println!("[TunTcpStream::poll_flush_tx] 写入0字节，视为错误");
                            // 把未发送的数据放回 pending_write
                            if offset < buffer.len() {
                                if let Ok(mut guard) = self.pending_write.lock() {
                                    let remaining_data = buffer.split_off(offset);
                                    guard.extend_from_slice(&remaining_data);
                                    self.has_pending_data.store(true, Ordering::SeqCst);
                                }
                            }
                            return Poll::Ready(Err(FlowError::Io(io::Error::new(io::ErrorKind::WriteZero, "write zero"))));
                        }
                        println!("[TunTcpStream::poll_flush_tx] 发送了 {} 字节", n);
                        offset += n;
                    }
                    Poll::Ready(Err(e)) => {
                        println!("[TunTcpStream::poll_flush_tx] 发送错误: {:?}", e);
                        // 把未发送的数据放回 pending_write
                        if offset < buffer.len() {
                           if let Ok(mut guard) = self.pending_write.lock() {
                                let remaining_data = buffer.split_off(offset);
                                guard.extend_from_slice(&remaining_data);
                                self.has_pending_data.store(true, Ordering::SeqCst);
                            }
                        }
                        return Poll::Ready(Err(convert_error(e)));
                    }
                    Poll::Pending => {
                        println!("[TunTcpStream::poll_flush_tx] 写入挂起，保存剩余数据");
                        // 把未发送的数据放回 pending_write
                        if offset < buffer.len() {
                            if let Ok(mut guard) = self.pending_write.lock() {
                                let remaining_data = buffer.split_off(offset);
                                guard.extend_from_slice(&remaining_data);
                                self.has_pending_data.store(true, Ordering::SeqCst);
                            } else {
                                println!("[TunTcpStream::poll_flush_tx] 警告：无法锁定待发送缓冲区保存剩余数据");
                                // 如果无法锁定，最好也返回Pending，避免丢失数据
                            }
                        }
                        return Poll::Pending; // 底层流阻塞，稍后重试
                    }
                }
            }
            // 当前 buffer 处理完毕，循环继续检查 pending_write 是否还有数据
        }

        // 所有数据已写入或写入被阻塞
        // 现在执行最终的 flush 操作
        println!("[TunTcpStream::poll_flush_tx] 所有待发送数据已尝试写入，执行最终刷新");
        match ready!(Pin::new(&mut self.inner).poll_flush(cx)) {
            Ok(()) => {
                println!("[TunTcpStream::poll_flush_tx] 刷新成功");
                Poll::Ready(Ok(()))
            }
            Err(e) => {
                println!("[TunTcpStream::poll_flush_tx] 刷新错误: {:?}", e);
                Poll::Ready(Err(convert_error(e)))
            }
        }
    }

    fn poll_close_tx(&mut self, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        println!("[TunTcpStream::poll_close_tx] 开始关闭发送通道");
        
        // 检查是否有待发送数据
        let has_pending_data = self.has_pending_data.load(std::sync::atomic::Ordering::SeqCst);
        
        // 如果有待发送数据，先刷新
        if has_pending_data {
            println!("[TunTcpStream::poll_close_tx] 发现未发送的数据，先刷新缓冲区");
            // 先确保数据被发送出去
            match self.poll_flush_tx(cx) {
                Poll::Ready(Ok(())) => {
                    println!("[TunTcpStream::poll_close_tx] 刷新成功，继续关闭");
                }
                Poll::Ready(Err(e)) => {
                    println!("[TunTcpStream::poll_close_tx] 刷新失败: {:?}", e);
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => {
                    println!("[TunTcpStream::poll_close_tx] 刷新操作未完成，等待下一次尝试");
                    return Poll::Pending;
                }
            }
        }
        
        // 数据已刷新完毕，现在可以安全关闭连接
        match ready!(Pin::new(&mut self.inner).poll_shutdown(cx)) {
            Ok(()) => {
                println!("[TunTcpStream::poll_close_tx] 关闭成功");
                Poll::Ready(Ok(()))
            },
            Err(e) => {
                println!("[TunTcpStream::poll_close_tx] 关闭错误: {:?}", e);
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