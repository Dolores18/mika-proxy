use crate::flow::{Buffer, TunBufferToken, TunBufferSignature, Tun};
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;
use std::io::{self, Result as IoResult};
use std::process::Command;
use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf, AsyncRead, AsyncWrite};
use std::thread;
use crossbeam_channel::{bounded, Sender, Receiver, TrySendError, TryRecvError};
use log::{info, error, debug, warn};
use tun::AbstractDevice;
use tun::AsyncDevice;

// 设备句柄结构，管理发送和接收操作
struct DeviceHandle {
    // 发送通道 - 使用std::sync::mpsc的同步发送器
    sender: Sender<Vec<u8>>,
    // 接收通道 - 新增
    receiver: Arc<Mutex<Receiver<(Vec<u8>, usize)>>>,
    // 管理线程是否已关闭的标志
    is_closed: Arc<Mutex<bool>>,
}

impl DeviceHandle {
    // 创建新的设备句柄，接管设备所有权
    fn new(device: AsyncDevice) -> Self {
        // 发送通道
        let (tx_sender, tx_receiver) = bounded::<Vec<u8>>(100); // 限制队列大小为100
        // 接收通道 - 新增
        let (rx_sender, rx_receiver) = bounded::<(Vec<u8>, usize)>(100);
        let rx_receiver = Arc::new(Mutex::new(rx_receiver));
        
        // 关闭标志
        let is_closed = Arc::new(Mutex::new(false));
        let is_closed_clone = is_closed.clone();
        
        // 复制接收通道的引用用于线程
        let rx_receiver_clone = rx_receiver.clone();
        
        // 启动设备管理线程
        thread::spawn(move || {
            // 创建tokio运行时 - 使用独立的运行时避免与主运行时冲突
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build() 
            {
                Ok(rt) => rt,
                Err(e) => {
                    error!("无法创建设备管理线程运行时: {:?}", e);
                    return;
                }
            };
            
            // 在线程中运行事件循环
            rt.block_on(async {
                let mut recv_buf = vec![0u8; 8192]; // 足够大的接收缓冲区
                
                loop {
                    // 检查是否收到关闭信号
                    if *is_closed_clone.lock().unwrap() {
                        info!("收到关闭信号，设备管理线程准备退出");
                        break;
                    }
                
                    // 处理发送请求 - 检查是否有数据要发送
                    while let Ok(packet) = tx_receiver.try_recv() {
                        if let Err(e) = device.send(&packet).await {
                            error!("TUN发送失败: {:?}", e);
                        }
                    }
                    
                    // 使用tokio select在发送和接收之间切换
                    tokio::select! {
                        // 尝试接收数据，使用超时避免永久阻塞
                        recv_result = async {
                            match tokio::time::timeout(
                                tokio::time::Duration::from_millis(10), 
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
                                    if let Err(e) = rx_sender.send((received_data, len)) {
                                        error!("无法发送接收到的数据: {:?}", e);
                                        // 通道错误表示接收端已关闭，退出线程
                                        break;
                                    }
                                },
                                Err(e) => {
                                    // 如果是临时错误，继续循环
                                    if e.kind() == io::ErrorKind::WouldBlock || 
                                       e.kind() == io::ErrorKind::TimedOut {
                                        // 继续循环而不延迟
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
                        
                        // 检查是否有发送请求
                        Some(packet) = async {
                            match tx_receiver.try_recv() {
                                Ok(packet) => Some(packet),
                                Err(_) => {
                                    // 短暂休眠避免CPU高占用
                                    tokio::time::sleep(tokio::time::Duration::from_micros(100)).await;
                                    None
                                }
                            }
                        } => {
                            if let Err(e) = device.send(&packet).await {
                                error!("TUN发送失败: {:?}", e);
                            }
                        }
                    }
                }
                
                info!("TUN设备管理线程结束");
            });
        });
        
        Self { 
            sender: tx_sender,
            receiver: rx_receiver_clone,
            is_closed,
        }
    }
    
    // 非阻塞发送数据包
    fn send(&self, data: Vec<u8>) -> io::Result<()> {
        // 检查是否已关闭
        if *self.is_closed.lock().unwrap() {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "设备已关闭"));
        }
        
        // 使用try_send代替send，确保非阻塞操作
        match self.sender.try_send(data) {
            Ok(_) => Ok(()),
            Err(crossbeam_channel::TrySendError::Full(data)) => {
                // 通道已满，记录警告并丢弃数据包
                warn!("发送通道已满，丢弃数据包({}字节)", data.len());
                Ok(()) // 返回成功，因为这是预期行为，不应阻塞或失败
            },
            Err(crossbeam_channel::TrySendError::Disconnected(_)) => {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "发送通道已关闭"))
            }
        }
    }
    
    // 阻塞接收数据包
    fn recv(&self, buf: &mut Vec<u8>) -> io::Result<usize> {
        // 检查是否已关闭
        if *self.is_closed.lock().unwrap() {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "设备已关闭"));
        }
        
        // 尝试非阻塞接收，避免永久阻塞
        match self.receiver.lock().unwrap().try_recv() {
            Ok((data, len)) => {
                // 确保buf有足够空间
                buf.clear();
                buf.extend_from_slice(&data);
                Ok(len)
            },
            Err(crossbeam_channel::TryRecvError::Empty) => {
                // 没有数据可读，返回WouldBlock错误
                Err(io::Error::new(io::ErrorKind::WouldBlock, "暂无数据可读"))
            },
            Err(crossbeam_channel::TryRecvError::Disconnected) => Err(io::Error::new(io::ErrorKind::BrokenPipe, "接收通道已关闭")),
        }
    }
    
    // 关闭设备句柄
    fn close(&self) {
        let mut closed = self.is_closed.lock().unwrap();
        *closed = true;
        info!("设备句柄已标记为关闭");
        
        // 尝试清理通道资源，避免线程被永久阻塞
        // 我们不关心是否成功，只是尝试打破可能的等待状态
        let _ = self.sender.try_send(Vec::new());
        
        // 等待一小段时间，让设备管理线程有机会发现关闭标志
        std::thread::sleep(std::time::Duration::from_millis(50));
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
    // 仅保留DeviceHandle，移除inner
    device_handle: DeviceHandle,
    buffer_pool: Arc<Mutex<VecDeque<Buffer>>>,
    mtu: usize,
    name: String,
    address: IpAddr,
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
        }
    }
}

impl MacTun {
    /// 使用配置参数创建一个新的TUN设备和MacTun实例
    pub fn new(
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
        })
    }
    
    /// 专门用于IPv4的便捷方法，直接接受IPv4地址和子网掩码
    pub fn new_ipv4(
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
        )
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
    
    /// 关闭TUN设备
    pub fn shutdown(&self) {
        info!("正在关闭TUN设备: {}", self.name);
        
        // 标记设备为关闭状态
        self.device_handle.close();
        
        // 清理缓冲池
        if let Ok(mut pool) = self.buffer_pool.lock() {
            pool.clear();
            info!("已清空TUN设备缓冲池");
        }
        
        // 给线程一些时间处理关闭信号
        std::thread::sleep(std::time::Duration::from_millis(100));
        
        // 使用ifconfig关闭TUN设备
        let interface_name = self.name.clone();
        let output = Command::new("ifconfig")
            .args(&[&interface_name, "down"])
            .output();
            
        match output {
            Ok(output) if output.status.success() => {
                info!("成功关闭网络接口: {}", interface_name);
            }
            Ok(_) => {
                warn!("关闭网络接口时返回非零状态码: {}", interface_name);
            }
            Err(e) => {
                warn!("关闭网络接口时出错: {}, 错误: {}", interface_name, e);
            }
        }
        
        info!("TUN设备关闭完成: {}", self.name);
    }
}

impl Tun for MacTun {
    fn blocking_recv(&self) -> Option<Buffer> {
        // 持续尝试接收数据，直到成功或设备关闭
        loop {
            // 检查设备是否已关闭
            if let Ok(is_closed) = self.device_handle.is_closed.lock() {
                if *is_closed {
                    debug!("设备已关闭，停止接收数据");
                    return None;
                }
            }
            
            // 尝试从缓冲池获取缓冲区，或创建新的
            let mut buf = {
                let mut pool = self.buffer_pool.lock().unwrap();
                pool.pop_front().unwrap_or_else(|| Buffer::new())
            };
            
            // 确保缓冲区有足够容量
            if buf.capacity() < self.mtu {
                buf = Buffer::with_capacity(self.mtu);
            }
            
            // 尝试接收数据
            match self.device_handle.recv(&mut buf) {
                Ok(len) => {
                    // 调整buffer长度为实际接收的数据长度
                    unsafe {
                        buf.set_len(len);
                    }
                    return Some(buf);  // 成功接收，返回数据
                },
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // 没有数据，短暂睡眠后重试
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;  // 继续循环
                },
                Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                    // 设备已关闭，返回None
                    error!("TUN设备已关闭，停止接收数据");
                    
                    // 将缓冲区返回池中以避免泄漏
                    let mut pool = self.buffer_pool.lock().unwrap();
                    pool.push_back(buf);
                    return None;  // 结束循环
                },
            Err(e) => {
                    // 其他错误，记录后继续尝试
                    error!("TUN接收失败: {:?}，继续尝试", e);
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    
                    // 将缓冲区返回池中以避免泄漏
                    let mut pool = self.buffer_pool.lock().unwrap();
                    pool.push_back(buf);
                    continue;  // 继续循环
                }
            }
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
        
        // 复制要发送的数据
        let data_vec = data[..len].to_vec();
        
        // 非阻塞发送数据
        if let Err(e) = self.device_handle.send(data_vec) {
            error!("发送数据包失败: {:?}", e);
        }
        
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
        // 由于我们已经在shutdown方法中实现了完整的关闭逻辑
        // 在Drop时只需记录日志即可，避免重复关闭操作
        info!("销毁MacTun实例: {}", self.name);
    }
}