use crate::flow::{Buffer, TunBufferToken, TunBufferSignature, Tun};
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;
use std::io::{self, Result as IoResult};
use std::process::Command;
use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf, AsyncRead, AsyncWrite};
use std::path::PathBuf;
use tun::AbstractDevice;
use log::{info, error, debug};
use tun::AsyncDevice;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use futures_core::ready;
use std::io::{IoSlice, Read, Write};
use futures::FutureExt;
use futures_core::future::Future;
use tokio::sync::mpsc;
use tokio::sync::Mutex as TokioMutex;
use futures::stream::StreamExt;
use futures::sink::SinkExt;
use std::sync::atomic::{AtomicBool, Ordering};
use once_cell::sync::Lazy;

// Inner state for the read state machine
enum ReadState {
    // Initial state or waiting for next read
    Idle,
    // Reading from the underlying device
    Reading,
    // Packet ready to be consumed
    Ready(Vec<u8>),
    // Error occurred during reading
    Error(io::Error),
    // Channel closed, no more data
    Closed,
}

// Inner state for the write state machine
enum WriteState {
    // Initial state or waiting for next write
    Idle,
    // Writing to the underlying device
    Writing(Vec<u8>),
    // Write completed successfully
    Complete(usize),
    // Error occurred during writing
    Error(io::Error),
    // Channel closed, no more writes
    Closed,
}

// Reader state machine that manages reading from TUN device
struct TunReader {
    // Current state of the reader
    state: ReadState,
    // Communication channel to receive packets from background task
    rx: mpsc::Receiver<Vec<u8>>,
    // Optional waker to wake up task when data is available
    waker: Option<Waker>,
}

// Writer state machine that manages writing to TUN device
struct TunWriter {
    // Current state of the writer
    state: WriteState,
    // Communication channel to send packets to background task
    tx: mpsc::Sender<Vec<u8>>,
    // Optional waker to wake up task when write is completed
    waker: Option<Waker>,
}

impl TunReader {
    // Create a new reader with the given receiver channel
    fn new(rx: mpsc::Receiver<Vec<u8>>) -> Self {
        Self {
            state: ReadState::Idle,
            rx,
            waker: None,
        }
    }

    // Poll for the next packet
    fn poll_read(&mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        // Store the waker for later use
        self.waker = Some(cx.waker().clone());

        match &mut self.state {
            ReadState::Idle => {
                // Try to receive a packet from the channel
                match self.rx.poll_recv(cx) {
                    Poll::Ready(Some(packet)) => {
                        self.state = ReadState::Ready(packet);
                        // Continue to process the ready packet
                        self.poll_read(cx, buf)
                    }
                    Poll::Ready(None) => {
                        // Channel closed
                        self.state = ReadState::Closed;
                        Poll::Ready(Ok(()))
                    }
                    Poll::Pending => {
                        // No packet available yet
                        Poll::Pending
                    }
                }
            }
            ReadState::Ready(packet) => {
                // Copy data from packet to the provided buffer
                let bytes_to_copy = packet.len().min(buf.remaining());
                buf.put_slice(&packet[..bytes_to_copy]);
                
                // Reset state to idle for next read
                self.state = ReadState::Idle;
                Poll::Ready(Ok(()))
            }
            ReadState::Error(err) => {
                // Return error and reset state
                let error = io::Error::new(err.kind(), err.to_string());
                self.state = ReadState::Idle;
                Poll::Ready(Err(error))
            }
            ReadState::Reading => {
                // This state shouldn't be reached in this implementation
                // as we're delegating actual reads to the background task
                debug!("TunReader in unexpected Reading state");
                self.state = ReadState::Idle;
                Poll::Pending
            }
            ReadState::Closed => {
                // Channel has been closed, return EOF
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl TunWriter {
    // Create a new writer with the given sender channel
    fn new(tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            state: WriteState::Idle,
            tx,
            waker: None,
        }
    }

    // Poll to write a packet
    fn poll_write(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        // Store the waker for later use
        self.waker = Some(cx.waker().clone());

        match &mut self.state {
            WriteState::Idle => {
                let packet = buf.to_vec();
                let len = packet.len();
                
                // 检查通道是否已关闭
                if self.tx.is_closed() {
                    self.state = WriteState::Closed;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "TUN device write channel closed"
                    )));
                }
                
                // 使用 try_send 进行非阻塞发送尝试
                match self.tx.try_send(packet.clone()) {
                    Ok(()) => {
                        // 发送成功，标记完成
                        self.state = WriteState::Complete(len);
                        Poll::Ready(Ok(len))
                    }
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        // 通道已满，保存数据并标记为等待写入
                        self.state = WriteState::Writing(packet);
                        // 注册 waker 并返回 Pending
                        Poll::Pending
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        // 通道已关闭
                        self.state = WriteState::Closed;
                        Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "TUN device write channel closed"
                        )))
                    }
                }
            }
            WriteState::Writing(packet) => {
                let len = packet.len();
                
                // 重试发送
                match self.tx.try_send(packet.clone()) {
                    Ok(()) => {
                        // 发送成功
                        self.state = WriteState::Complete(len);
                        Poll::Ready(Ok(len))
                    }
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        // 通道仍然已满
                        Poll::Pending
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        // 通道已关闭
                        self.state = WriteState::Closed;
                        Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "TUN device write channel closed during send"
                        )))
                    }
                }
            }
            WriteState::Complete(len) => {
                // Reset state and return completed length
                let written = *len;
                self.state = WriteState::Idle;
                Poll::Ready(Ok(written))
            }
            WriteState::Error(err) => {
                // Return error and reset state
                let error = io::Error::new(err.kind(), err.to_string());
                self.state = WriteState::Idle;
                Poll::Ready(Err(error))
            }
            WriteState::Closed => {
                // Channel closed, return error
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "TUN device write channel closed"
                )))
            }
        }
    }

    // Poll to flush pending writes
    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &self.state {
            WriteState::Idle | WriteState::Complete(_) => {
                // Nothing to flush
                Poll::Ready(Ok(()))
            }
            WriteState::Writing(_) => {
                // Wait for writing to complete
                Poll::Pending
            }
            WriteState::Error(err) => {
                // Return error and reset state
                let error = io::Error::new(err.kind(), err.to_string());
                self.state = WriteState::Idle;
                Poll::Ready(Err(error))
            }
            WriteState::Closed => {
                // Channel closed, return error
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "TUN device write channel closed"
                )))
            }
        }
    }

    // Poll to shut down the writer
    fn poll_shutdown(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Mark the writer as closed
        self.state = WriteState::Closed;
        Poll::Ready(Ok(()))
    }
}

// MacTun设备类型，使用tokio进行异步操作
pub struct MacTun {
    // 内部tun设备实例
    device: Arc<AsyncDevice>,
    // 设备名称
    name: String,
    // 设备IP地址
    address: Ipv4Addr,
    // IPv6地址
    address_v6: Option<Ipv6Addr>,
    // 网络掩码
    netmask: Ipv4Addr,
    // 用于共享状态的队列
    buffer_pool: Arc<Mutex<VecDeque<Buffer>>>,
    // 接收和发送缓冲区的大小
    mtu: usize,
    // 读取和写入状态机
    reader: TokioMutex<TunReader>,
    writer: TokioMutex<TunWriter>,
}

// 创建一个全局共享的tokio运行时
static GLOBAL_RT: Lazy<Result<tokio::runtime::Runtime, std::io::Error>> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(1) // 使用单个工作线程减少资源消耗
        .thread_name("tun-global-rt")
        .build()
});

// 初始化标志，确保只初始化一次
static RUNTIME_INITIALIZED: AtomicBool = AtomicBool::new(false);

impl MacTun {
    /// 创建并初始化MacTun设备
    pub async fn new(
        name: &str, 
        address: Ipv4Addr,  // 使用传入的IP地址
        netmask: Ipv4Addr,  // 使用传入的网络掩码
        mtu: Option<usize>
    ) -> Result<Self, io::Error> {
        // 使用传入的IP地址和掩码
        // 禁用IPv6，防止系统发送自动配置和路由公告包
        let address_v6 = None;
        
        // 创建TUN设备配置
        let mut config = tun::Configuration::default();
        config
            .tun_name(name)
            .address(address)
            .netmask(netmask)
            .mtu(mtu.unwrap_or(1500) as u16)
            .up();
            
        // 创建TUN设备
        let device = tun::create_as_async(&config)?;
        // 获取实际设备名称
        let actual_name = device.tun_name().unwrap_or_else(|_| name.to_string());

        let mtu_val = mtu.unwrap_or(1500);
        
        // 创建内部通道
        let (tx_device_to_app, rx_device_to_app) = mpsc::channel(100);  // Device -> App
        let (tx_app_to_device, rx_app_to_device) = mpsc::channel(100);  // App -> Device
        
        // 创建设备的Arc包装，用于后台任务
        let device_arc = Arc::new(device);
        
        // 启动后台任务处理数据流动
        Self::start_background_tasks(
            device_arc.clone(), 
            tx_device_to_app, 
            rx_app_to_device,
            mtu_val
        );
        
        // 创建读写状态机
        let reader = TunReader::new(rx_device_to_app);
        let writer = TunWriter::new(tx_app_to_device);
        
        // 创建MacTun实例
        let mac_tun = Self {
            device: device_arc,
            name: actual_name,
            address,
            address_v6,
            netmask,
            buffer_pool: Arc::new(Mutex::new(VecDeque::new())),
            mtu: mtu_val,
            reader: TokioMutex::new(reader),
            writer: TokioMutex::new(writer),
        };
        
        // 如果支持IPv6，使用ifconfig命令手动配置
        if let Some(ipv6_addr) = &mac_tun.address_v6 {
            info!("配置IPv6地址: {}", ipv6_addr);
            // 使用ifconfig命令配置IPv6地址
            let _ = Command::new("ifconfig")
                .arg(&mac_tun.name)
                .arg("inet6")
                .arg(ipv6_addr.to_string())
                .arg("prefixlen")
                .arg("64")
                .arg("alias")
                .output();
        }
        
        Ok(mac_tun)
    }

    // 启动后台任务处理数据流动
    fn start_background_tasks(
        device: Arc<AsyncDevice>, 
        tx_device_to_app: mpsc::Sender<Vec<u8>>, 
        mut rx_app_to_device: mpsc::Receiver<Vec<u8>>,
        mtu: usize
    ) {
        // 启动读取任务 - 从TUN设备到应用
        let device_read = device.clone();
        tokio::spawn(async move {
            info!("启动TUN设备读取任务");
            let mut buffer = vec![0u8; mtu];
            
            loop {
                match device_read.recv(&mut buffer).await {
                    Ok(n) if n > 0 => {
                        let packet = buffer[..n].to_vec();
                        debug!("从TUN设备读取 {} 字节", n);
                        
                        // 将数据发送到应用程序
                        if let Err(e) = tx_device_to_app.send(packet).await {
                            error!("发送数据到应用程序失败: {}", e);
                            // 短暂等待后重试
                            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                        }
                    },
                    Ok(_) => {
                        // 读取到0字节，继续尝试
                        tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
                    },
                    Err(e) => {
                        error!("从TUN设备读取错误: {}", e);
                        // 短暂等待后重试
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    }
                }
            }
        });
        
        // 启动写入任务 - 从应用到TUN设备
        let device_write = device.clone();
        tokio::spawn(async move {
            info!("启动TUN设备写入任务");
            
            while let Some(packet) = rx_app_to_device.recv().await {
                debug!("向TUN设备写入 {} 字节", packet.len());
                
                match device_write.send(&packet).await {
                    Ok(n) => {
                        debug!("成功写入TUN设备 {} 字节", n);
                    },
                    Err(e) => {
                        error!("写入TUN设备错误: {}", e);
                        // 短暂等待后继续
                        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                    }
                }
            }
            
            info!("TUN设备写入任务结束");
        });
    }

    /// 获取TUN设备名称
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// 获取TUN设备IP地址
    pub fn get_address(&self) -> Ipv4Addr {
        self.address
    }
    
    /// 关闭TUN设备
    pub fn shutdown(&self) {
        info!("关闭TUN设备: {}", self.name);
        // 使用ifconfig命令将接口设置为down状态
        let _ = Command::new("ifconfig")
            .arg(&self.name)
            .arg("down")
            .output();
        
        info!("TUN设备已关闭: {}", self.name);
    }
    
    /// 接收数据包 - 直接委托给内部设备
    pub async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.device.recv(buf).await
    }
    
    /// 发送数据包 - 直接委托给内部设备
    pub async fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.device.send(buf).await
    }

    // 提取异步接收逻辑到单独的方法
    async fn async_recv_packet(&self) -> Option<Buffer> {
        // 从TUN设备循环读取直到成功
        loop {
            // 创建缓冲区
            let mut buffer = vec![0u8; self.mtu];
            
            // 尝试读取数据，如果读取超时则继续尝试
            match tokio::time::timeout(
                tokio::time::Duration::from_secs(1),
                self.device.recv(&mut buffer)
            ).await {
                // 成功读取数据
                Ok(Ok(n)) if n > 0 => {
                    // 缩减缓冲区到实际数据大小
                    buffer.truncate(n);
                    
                    // 将Vec<u8>转换为Buffer并返回
                    let mut result = Buffer::new();
                    result.extend_from_slice(&buffer);
                    return Some(result);
                },
                // 底层设备错误
                Ok(Err(e)) => {
                    eprintln!("TUN设备读取错误: {}", e);
                    
                    // 短暂等待后继续尝试
                    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                    continue;
                },
                // 读取到0字节或超时
                _ => {
                    // 短暂等待后继续尝试
                    tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
                    continue;
                }
            }
        }
    }
}

// 实现AsyncRead trait，使用读取状态机
impl AsyncRead for MacTun {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf,
    ) -> Poll<std::io::Result<()>> {
        // 获取可变引用
        let this = self.get_mut();
        
        // 获取读取器的互斥锁
        let fut = this.reader.lock();
        // 将Future转换为Pin
        let mut fut = Box::pin(fut);
        
        // 轮询锁定操作
        let mut guard = ready!(fut.as_mut().poll(cx));
        
        // 一旦获取锁，轮询读取操作
        guard.poll_read(cx, buf)
    }
}

// 实现AsyncWrite trait，使用写入状态机
impl AsyncWrite for MacTun {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // 获取可变引用
        let this = self.get_mut();
        
        // 获取写入器的互斥锁
        let fut = this.writer.lock();
        // 将Future转换为Pin
        let mut fut = Box::pin(fut);
        
        // 轮询锁定操作
        let mut guard = ready!(fut.as_mut().poll(cx));
        
        // 一旦获取锁，轮询写入操作
        guard.poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        // 获取可变引用
        let this = self.get_mut();
        
        // 获取写入器的互斥锁
        let fut = this.writer.lock();
        // 将Future转换为Pin
        let mut fut = Box::pin(fut);
        
        // 轮询锁定操作
        let mut guard = ready!(fut.as_mut().poll(cx));
        
        // 一旦获取锁，轮询刷新操作
        guard.poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        // 获取可变引用
        let this = self.get_mut();
        
        // 获取写入器的互斥锁
        let fut = this.writer.lock();
        // 将Future转换为Pin
        let mut fut = Box::pin(fut);
        
        // 轮询锁定操作
        let mut guard = ready!(fut.as_mut().poll(cx));
        
        // 一旦获取锁，轮询关闭操作
        guard.poll_shutdown(cx)
    }
}

impl Tun for MacTun {
    fn blocking_recv(&self) -> Option<Buffer> {
        // 使用全局共享的运行时而不是每次创建新的
        let rt = match &*GLOBAL_RT {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("获取全局tokio运行时失败: {}", e);
                // 如果全局运行时不可用，尝试创建临时运行时，但仅作为降级方案
                if !RUNTIME_INITIALIZED.load(Ordering::SeqCst) {
                    eprintln!("警告: 使用临时运行时作为降级方案");
                    RUNTIME_INITIALIZED.store(true, Ordering::SeqCst);
                    
                    match tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build() {
                        Ok(temp_rt) => {
                            return temp_rt.block_on(self.async_recv_packet());
                        }
                        Err(e) => {
                            eprintln!("创建临时tokio运行时失败: {}", e);
                            return None;
                        }
                    }
                } else {
                    // 已经尝试过临时运行时，但失败了
                    return None;
                }
            }
        };
        
        // 在全局运行时上执行异步接收
        rt.block_on(self.async_recv_packet())
    }
    
    fn return_recv_buffer(&self, buf: Buffer) {
        // 将缓冲区放回池中以便重用
        info!("🐶MACTUN: 返还接收缓冲区，长度: {}", buf.len());
        self.buffer_pool.lock().unwrap().push_back(buf);
    }
    
    fn get_tx_buffer(&self) -> Option<TunBufferToken> {
        // 创建一个新的缓冲区
        let data = Box::new(vec![0u8; self.mtu]);
        let data_ptr = Box::into_raw(data);
        
        // 创建一个静态的可变引用
        let static_slice = unsafe {
            std::slice::from_raw_parts_mut((*data_ptr).as_mut_ptr(), self.mtu)
        };
        
        // 构造签名
        let signature = [data_ptr as *mut usize, std::ptr::null_mut()];
        
        info!("🐶MACTUN: 创建发送缓冲区，大小: {}", self.mtu);
        
        // 安全性：我们确保签名可以安全地发送到其他线程
        unsafe {
            Some(TunBufferToken::new(signature, static_slice))
        }
    }
    
    fn send(&self, buf: TunBufferToken, len: usize) {
        info!("🍓MACTUN: 发送数据包，长度: {}", len);
        
        let (signature, data) = buf.into_parts();
        
        // 获取临时数据的副本
        let data_to_send = data[..len].to_vec();
        
        // 先释放原始缓冲区
        unsafe {
            let data_ptr = signature[0] as *mut Vec<u8>;
            if !data_ptr.is_null() {
                drop(Box::from_raw(data_ptr));
            }
        }
        
        // 克隆设备引用以便在异步任务中使用
        let device = self.device.clone();
        
        // 在临时运行时中执行异步发送操作
        tokio::task::block_in_place(|| {
            let rt = tokio::runtime::Handle::current();
            
            // 创建一个发送任务
            rt.spawn(async move {
                // 使用克隆的设备引用直接发送数据
                match device.send(&data_to_send).await {
                    Ok(n) => {
                        debug!("成功发送数据到TUN设备: {} 字节", n);
                    }
                    Err(e) => {
                        error!("发送数据到TUN设备错误: {}", e);
                    }
                }
            });
        });
    }
    
    fn return_tx_buffer(&self, buf: TunBufferToken) {
        // 释放缓冲区
        info!("TUN: 返还发送缓冲区");
        unsafe {
            let (signature, _) = buf.into_parts();
            let data_ptr = signature[0] as *mut Vec<u8>;
            if !data_ptr.is_null() {
                drop(Box::from_raw(data_ptr));
            }
        }
    }
}