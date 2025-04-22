use crate::flow::{Buffer, TunBufferToken, TunBufferSignature, Tun};
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;
use std::io::{self, Result as IoResult};
use std::process::Command;
use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};
use std::thread;
use log::{info, error, debug, warn};
use tun::AbstractDevice;
use tun::AsyncDevice;
use tokio::sync::{mpsc, oneshot};
use std::pin::Pin;
use std::task::{Context, Poll};
use futures::{Stream, Sink, SinkExt, StreamExt, Future};

// 异步设备句柄结构，管理发送和接收操作
struct DeviceHandle {
    // 异步发送通道 - 使用tokio::sync::mpsc
    sender: mpsc::Sender<Vec<u8>>,
    // 异步接收通道
    receiver: Arc<tokio::sync::Mutex<mpsc::Receiver<(Vec<u8>, usize)>>>,
    // 管理线程是否已关闭的标志
    is_closed: Arc<tokio::sync::Mutex<bool>>,
}

impl DeviceHandle {
    // 创建新的设备句柄，接管设备所有权
    fn new(device: AsyncDevice) -> Self {
        // 异步发送通道
        let (tx_sender, mut tx_receiver) = mpsc::channel::<Vec<u8>>(100); // 限制队列大小为100
        // 异步接收通道
        let (rx_sender, rx_receiver) = mpsc::channel::<(Vec<u8>, usize)>(100);
        let rx_receiver = Arc::new(tokio::sync::Mutex::new(rx_receiver));
        
        // 关闭标志
        let is_closed = Arc::new(tokio::sync::Mutex::new(false));
        let is_closed_clone = is_closed.clone();
        
        // 复制接收通道的引用用于线程
        let rx_receiver_clone = rx_receiver.clone();
        
        // 启动设备管理线程 - 使用tokio异步运行时
        tokio::spawn(async move {
            let mut recv_buf = vec![0u8; 8192]; // 足够大的接收缓冲区
            
            // 设备循环
            loop {
                // 检查是否收到关闭信号
                if *is_closed_clone.lock().await {
                    info!("收到关闭信号，设备管理线程准备退出");
                    break;
                }
                
                // 使用tokio select在发送和接收之间切换
                tokio::select! {
                    // 接收数据包发送请求
                    Some(packet) = tx_receiver.recv() => {
                        if let Err(e) = device.send(&packet).await {
                            error!("TUN发送失败: {:?}", e);
                        }
                    },
                    
                    // 尝试从设备接收数据
                    recv_result = async {
                        match tokio::time::timeout(
                            tokio::time::Duration::from_millis(100), 
                            device.recv(&mut recv_buf)
                        ).await {
                            Ok(result) => result,
                            Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "接收超时"))
                        }
                    } => {
                        match recv_result {
                            Ok(len) => {
                                // 复制接收到的数据并发送到通道
                                let received_data = recv_buf[..len].to_vec();
                                if let Err(e) = rx_sender.send((received_data, len)).await {
                                    error!("无法发送接收到的数据: {:?}", e);
                                    // 通道错误表示接收端已关闭，退出线程
                                    break;
                                }
                            },
                            Err(e) => {
                                // 如果是临时错误，继续循环
                                if e.kind() == io::ErrorKind::WouldBlock || 
                                   e.kind() == io::ErrorKind::TimedOut {
                                    // 短暂休眠避免过度循环
                                    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                                    continue;
                                }
                                
                                error!("TUN接收失败: {:?}", e);
                                // 严重错误，退出线程
                                if e.kind() == io::ErrorKind::BrokenPipe {
                                    break;
                                }
                            }
                        }
                    },
                    
                    // 添加一个超时分支，避免在没有数据时永久阻塞
                    _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {
                        // 空操作，只是为了防止永久阻塞
                    }
                }
            }
            
            info!("TUN设备管理线程结束");
        });
        
        Self { 
            sender: tx_sender,
            receiver: rx_receiver_clone,
            is_closed,
        }
    }
    
    // 异步发送数据包
    async fn send(&self, data: Vec<u8>) -> io::Result<()> {
        // 检查是否已关闭
        if *self.is_closed.lock().await {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "设备已关闭"));
        }
        
        // 使用发送时超时，确保不会永久阻塞
        match tokio::time::timeout(
            tokio::time::Duration::from_millis(100),
            self.sender.send(data)
        ).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(_)) => Err(io::Error::new(io::ErrorKind::BrokenPipe, "发送通道已关闭")),
            Err(_) => {
                // 发送超时，记录警告但不认为是错误
                warn!("发送数据包超时，可能通道已满");
                Ok(())
            }
        }
    }
    
    // 异步接收数据包
    async fn recv(&self, buf: &mut Vec<u8>) -> io::Result<usize> {
        // 检查是否已关闭
        if *self.is_closed.lock().await {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "设备已关闭"));
        }
        
        // 尝试获取接收锁，设置超时
        let mut receiver_lock = match tokio::time::timeout(
            tokio::time::Duration::from_millis(100),
            self.receiver.lock()
        ).await {
            Ok(lock) => lock,
            Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "接收器锁定超时"))
        };
        
        // 尝试从接收通道获取数据，带超时
        match tokio::time::timeout(
            tokio::time::Duration::from_millis(100),
            receiver_lock.recv()
        ).await {
            Ok(Some((data, len))) => {
                // 确保buf有足够空间
                buf.clear();
                buf.extend_from_slice(&data);
                Ok(len)
            },
            Ok(None) => Err(io::Error::new(io::ErrorKind::BrokenPipe, "接收通道已关闭")),
            Err(_) => Err(io::Error::new(io::ErrorKind::WouldBlock, "暂无数据可读"))
        }
    }
    
    // 异步关闭设备句柄
    async fn close(&self) {
        let mut closed = self.is_closed.lock().await;
        *closed = true;
        info!("设备句柄已标记为关闭");
        
        // 尝试清理通道资源，避免线程被永久阻塞
        // 发送一个空包，帮助打破可能的阻塞状态
        let _ = self.sender.send(Vec::new()).await;
        
        // 短暂等待，确保关闭信号被处理
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    }
}

// 实现Clone
impl Clone for DeviceHandle {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            receiver: self.receiver.clone(),
            is_closed: self.is_closed.clone(),
        }
    }
}

/// Mac平台下的TUN设备实现
pub struct MacTun {
    device_handle: DeviceHandle,
    buffer_pool: Arc<Mutex<VecDeque<Buffer>>>,
    mtu: usize,
    name: String,
    address: IpAddr,
    // Tokio的发送和接收通道
    tx: Option<mpsc::Sender<Vec<u8>>>,
    rx: Option<mpsc::Receiver<Vec<u8>>>,
}

// 为MacTun实现Clone
impl Clone for MacTun {
    fn clone(&self) -> Self {
        Self {
            device_handle: self.device_handle.clone(),
            buffer_pool: self.buffer_pool.clone(),
            mtu: self.mtu,
            name: self.name.clone(),
            address: self.address,
            tx: self.tx.clone(),
            rx: None, // 接收通道不能被Clone，新实例没有接收功能
        }
    }
}

impl MacTun {
    /// 使用配置参数创建一个新的TUN设备和MacTun实例
    pub async fn new(
        name: Option<&str>, 
        address: IpAddr, 
        netmask: IpAddr, 
        mtu: Option<usize>
    ) -> IoResult<Self> {
        // 创建TUN设备配置
        let mut config = tun::Configuration::default();
        
        // 设置TUN设备参数
        if let Some(name) = name {
            config.tun_name(name);
        }
        
        config
            .address(address)
            .netmask(netmask)
            .mtu(mtu.unwrap_or(1500) as u16)
            .up();
            
        // 创建TUN设备
        let device = tun::create_as_async(&config)?;
        info!("创建TUN设备成功：{:?}", device.mtu());
        
        let name_str = name.unwrap_or("utun").to_string();
        
        // 创建设备句柄，移交设备所有权
        let device_handle = DeviceHandle::new(device);
        
        Ok(Self {
            device_handle,
            buffer_pool: Arc::new(Mutex::new(VecDeque::new())),
            mtu: mtu.unwrap_or(1500),
            name: name_str,
            address,
            tx: None,
            rx: None,
        })
    }
    
    /// 专门用于IPv4的便捷方法，直接接受IPv4地址和子网掩码
    pub async fn new_ipv4(
        name: &str,
        address: Ipv4Addr,
        netmask: Ipv4Addr,
        mtu: Option<usize>
    ) -> IoResult<Self> {
        Self::new(
            Some(name),
            IpAddr::V4(address),
            IpAddr::V4(netmask),
            mtu
        ).await
    }
    
    /// 从已有的AsyncDevice创建MacTun实例
    pub fn from_device(device: AsyncDevice) -> Self {
        let mtu = device.mtu().unwrap_or(1500) as usize;
        let device_handle = DeviceHandle::new(device);
        
        Self {
            device_handle,
            buffer_pool: Arc::new(Mutex::new(VecDeque::new())),
            mtu,
            name: "unknown".to_string(),
            address: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            tx: None,
            rx: None,
        }
    }
    
    /// 获取设备MTU
    pub fn mtu(&self) -> usize {
        self.mtu
    }
    
    /// 获取设备名称
    pub fn get_name(&self) -> &str {
        &self.name
    }
    
    /// 获取设备IP地址
    pub fn get_address(&self) -> IpAddr {
        self.address
    }
    
    /// 异步关闭TUN设备
    pub async fn shutdown(&self) {
        info!("正在关闭TUN设备: {}", self.name);
        
        // 异步标记设备为关闭状态
        self.device_handle.close().await;
        
        // 清理缓冲池
        if let Ok(mut pool) = self.buffer_pool.lock() {
            pool.clear();
            info!("已清空TUN设备缓冲池");
        }
        
        // 使用ifconfig关闭TUN设备 - 这是系统调用，使用tokio的spawn_blocking
        let interface_name = self.name.clone(); // 克隆保存接口名
        let output = tokio::task::spawn_blocking(move || {
            // 这里interface_name被移动到闭包中
            Command::new("ifconfig")
                .args(&[&interface_name, "down"])
                .output()
        }).await.unwrap_or_else(|e| {
            warn!("执行ifconfig命令时发生错误: {}", e);
            Err(io::Error::new(io::ErrorKind::Other, format!("执行线程错误: {}", e)))
        });
            
        // 这里需要使用self.name，因为interface_name已被移动
        match output {
            Ok(output) if output.status.success() => {
                info!("成功关闭网络接口: {}", self.name);
            }
            Ok(_) => {
                warn!("关闭网络接口时返回非零状态码: {}", self.name);
            }
            Err(e) => {
                warn!("关闭网络接口时出错: {}, 错误: {}", self.name, e);
            }
        }
        
        info!("TUN设备关闭完成: {}", self.name);
    }

    /// 将TUN设备转换为帧模式并启动异步读写任务
    pub fn into_framed(mut self) -> IoResult<Self> {
        // 创建Tokio通道用于异步通信
        let (tx, rx) = mpsc::channel::<Vec<u8>>(100);
        self.tx = Some(tx);
        self.rx = Some(rx);
        
        Ok(self)
    }
    
    // 新增：异步接收数据包
    pub async fn async_recv(&self) -> IoResult<Buffer> {
        // 尝试从缓冲池获取缓冲区，或创建新的
        let mut buf = {
            let mut pool = self.buffer_pool.lock().unwrap();
            pool.pop_front().unwrap_or_else(|| Buffer::new())
        };
        
        // 确保缓冲区有足够容量
        if buf.capacity() < self.mtu {
            buf = Buffer::with_capacity(self.mtu);
        }
        
        // 异步接收数据
        match self.device_handle.recv(&mut buf).await {
            Ok(len) => {
                // 调整buffer长度为实际接收的数据长度
                unsafe {
                    buf.set_len(len);
                }
                Ok(buf)  // 成功接收，返回数据
            },
            Err(e) => Err(e)
        }
    }
    
    // 新增：异步发送数据包
    pub async fn async_send(&self, data: Vec<u8>) -> IoResult<()> {
        self.device_handle.send(data).await
    }
}

impl Tun for MacTun {
    fn blocking_recv(&self) -> Option<Buffer> {
        // 创建缓冲区
        let mut buf = {
            let mut pool = self.buffer_pool.lock().unwrap();
            pool.pop_front().unwrap_or_else(|| Buffer::new())
        };
        
        // 确保缓冲区有足够容量
        if buf.capacity() < self.mtu {
            buf = Buffer::with_capacity(self.mtu);
        }
        
        // 使用自定义的轮询机制处理异步接收操作
        use futures::task::noop_waker;
        let waker = noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);
        
        let device_handle = self.device_handle.clone();
        let mut attempts = 0;
        
        loop {
            // 每次循环创建新的接收缓冲区，避免借用冲突
            let mut recv_buf = vec![0u8; self.mtu];
            let mut received_len = 0;
            
            // 轮询异步接收操作
            {
                let future = device_handle.recv(&mut recv_buf);
                let mut pinned_future = Box::pin(future);
                
                match pinned_future.as_mut().poll(&mut cx) {
                    Poll::Ready(Ok(len)) => {
                        // 记录接收到的数据长度
                        received_len = len;
                        // future将在作用域结束时被丢弃
                    },
                    Poll::Ready(Err(e)) => {
                        if e.kind() == io::ErrorKind::WouldBlock {
                            // 暂时没有数据，短暂休眠后重试
                            std::thread::sleep(std::time::Duration::from_millis(10));
                            
                            attempts += 1;
                            if attempts > 1000 { // 10秒后重新评估
                                attempts = 0;
                                debug!("长时间未收到数据，但将继续尝试");
                            }
                        } else if e.kind() == io::ErrorKind::BrokenPipe {
                            // 设备已关闭，但我们不能返回None
                            error!("TUN设备已关闭，但将继续尝试: {:?}", e);
                            std::thread::sleep(std::time::Duration::from_millis(1000));
                        } else {
                            // 其他错误，记录后继续尝试
                            error!("TUN接收失败: {:?}，继续尝试", e);
                            std::thread::sleep(std::time::Duration::from_millis(1000));
                        }
                        
                        // 继续下一次循环
                        continue;
                    },
                    Poll::Pending => {
                        // Future未准备好，短暂休眠后继续轮询
                        std::thread::sleep(std::time::Duration::from_millis(10));
                        
                        // 继续下一次循环
                        continue;
                    }
                }
            } // pinned_future 在这里被丢弃，可变借用结束
            
            // 此时future已经被丢弃，可以安全使用接收到的数据
            if received_len > 0 {
                // 成功接收数据，复制到返回缓冲区
                buf.clear();
                buf.extend_from_slice(&recv_buf[..received_len]);
                return Some(buf);
            }
            
            // 如果没有接收到数据，继续下一次循环
        }
    }
    
    fn return_recv_buffer(&self, buf: Buffer) {
        // 将用完的缓冲区返回到缓冲池
        let mut pool = self.buffer_pool.lock().unwrap();
        if pool.len() < 64 { // 限制池大小以避免内存泄漏
            pool.push_back(buf);
        }
    }
    
    fn get_tx_buffer(&self) -> Option<TunBufferToken> {
        let mut buf = vec![0u8; self.mtu];
        
        // 创建一个静态生命周期的缓冲区
        // 安全：我们通过Token的生命周期管理这块内存
        let static_buf = Box::leak(buf.into_boxed_slice());
        
        // 创建签名，使用指针地址作为唯一标识
        let signature = [
            static_buf.as_ptr() as *mut usize,
            static_buf.len() as *mut usize,
        ];
        
        // 安全：我们确保签名和缓冲区在使用期间保持有效
        unsafe {
            Some(TunBufferToken::new(signature, static_buf))
        }
    }
    
    fn send(&self, buf: TunBufferToken, len: usize) {
        let (_, data) = buf.into_parts();
        let data_vec = data[..len].to_vec(); // 截取并复制数据
        let device_handle = self.device_handle.clone();
    
        // 异步发送交给 Tokio，快速返回
        tokio::spawn(async move {
            if let Err(e) = device_handle.send(data_vec).await {
                error!("发送数据包失败: {:?}", e);
            }
        });
    
        // 释放原始缓冲区
        unsafe {
            let _ = Box::from_raw(data);
        }
    }
    
    
    fn return_tx_buffer(&self, buf: TunBufferToken) {
        // 释放静态缓冲区
        let (_, data) = buf.into_parts();
        unsafe {
            let _ = Box::from_raw(data);
        }
    }
}

impl Drop for MacTun {
    fn drop(&mut self) {
        info!("正在销毁MacTun实例: {}", self.name);
        
        // 同步标记设备为关闭状态
        let _ = Command::new("ifconfig")
            .args(&[&self.name, "down"])
            .output();
        
        // 清理资源，避免使用异步方法
        // 注意：这个实现完全同步，不依赖Tokio运行时
        info!("TUN设备关闭完成: {}", self.name);
    }
}