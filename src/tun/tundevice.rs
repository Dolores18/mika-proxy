use super::*;
use std::sync::Mutex;
use std::collections::VecDeque;
use std::mem::ManuallyDrop;
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::process::Command;
use tun::{self, Device, Configuration};
use log::{trace, error, info, debug};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

// TUN设备状态机状态
#[derive(Debug, Clone, PartialEq)]
enum TunState {
    Idle,          // 空闲状态，等待操作 
    Reading,       // 正在读取数据
    Writing,       // 正在写入数据
    Error,         // 出错状态
    Closed,        // 设备已关闭
}

/// A TUN device implementation using the `tun` crate.
pub struct TunDevice {
    // The underlying tun device, wrapped in Arc for shared ownership
    device: Arc<Mutex<tun::Device>>,
    // MTU for the device
    mtu: usize,
    // IP address for the device
    ip_addr: Option<Ipv4Addr>,
    // Netmask for the device
    netmask: Option<Ipv4Addr>,
    // Device name
    name: String,
    // Pool of pre-allocated receive buffers
    rx_buffers: Mutex<VecDeque<Buffer>>,
    // Pool of pre-allocated transmit buffers
    tx_buffers: Mutex<VecDeque<TunBufferToken>>,
    // Current state of the device
    state: Mutex<TunState>,
    // Running flag for background tasks
    running: Arc<AtomicBool>,
    // 数据发送通道，用于从外部发送数据到TUN设备
    tx_sender: Option<mpsc::Sender<TunBufferToken>>,
    // 数据接收通道，用于将数据从TUN设备传递到外部
    rx_sender: Option<mpsc::Sender<Buffer>>,
    // 后台任务句柄
    background_task: Mutex<Option<JoinHandle<()>>>,
}

impl TunDevice {
    /// Creates a new TUN device with the specified name and MTU.
    pub fn new(name: &str, mtu: usize, buffer_count: usize) -> std::io::Result<Self> {
        // Configure the TUN device
        let mut config = Configuration::default();
        config
            .tun_name(name)
            .mtu(mtu as u16)
            .up(); // bring the interface up immediately
            
        // Create the device
        let device = tun::create(&config)?;
        
        // Pre-allocate receive buffers
        let mut rx_buffers = VecDeque::with_capacity(buffer_count);
        for _ in 0..buffer_count {
            let mut buffer = Buffer::new();
            buffer.resize(mtu, 0);
            rx_buffers.push_back(buffer);
        }
        
        // Pre-allocate transmit buffers
        let mut tx_buffers = VecDeque::with_capacity(buffer_count);
        for _ in 0..buffer_count {
            // Allocate a static buffer (this is safe because we control the lifetime with TunBufferToken)
            let data = Box::leak(vec![0u8; mtu].into_boxed_slice());
            
            // Create a signature (using the Box raw pointer as an identifier)
            let ptr = data.as_ptr() as *mut usize;
            let signature = [ptr, ptr];
            
            // Create the token
            let token = unsafe { TunBufferToken::new(signature, data) };
            tx_buffers.push_back(token);
        }
        
        let self_obj = Self {
            device: Arc::new(Mutex::new(device)),
            mtu,
            ip_addr: None,
            netmask: None,
            name: name.to_string(),
            rx_buffers: Mutex::new(rx_buffers),
            tx_buffers: Mutex::new(tx_buffers),
            state: Mutex::new(TunState::Idle),
            running: Arc::new(AtomicBool::new(false)),
            tx_sender: None,
            rx_sender: None,
            background_task: Mutex::new(None),
        };
        
        // 打印设备模式信息
        println!("TUN设备已创建：{}", name);
        
        Ok(self_obj)
    }
    
    /// Configures the IP address and netmask for the TUN device
    pub fn configure_ip(&mut self, ip_addr: Ipv4Addr, netmask: Ipv4Addr) -> std::io::Result<()> {
        self.ip_addr = Some(ip_addr);
        self.netmask = Some(netmask);
        
        // 在macOS上，ifconfig命令为点对点TUN设备需要同时指定地址和目标地址
        // 例如: ifconfig utun11 inet 172.16.0.1 172.16.0.1 netmask 255.255.255.0 up
        let output = Command::new("ifconfig")
            .arg(&self.name)
            .arg("inet")
            .arg(ip_addr.to_string())
            .arg(ip_addr.to_string()) // 目标地址与IP地址相同
            .arg("netmask")
            .arg(netmask.to_string())
            .arg("up")
            .output()?;
            
        if !output.status.success() {
            error!("警告: 配置TUN设备IP地址失败: {}", 
                     String::from_utf8_lossy(&output.stderr));
        } else {
            println!("✅ 成功配置TUN设备IP地址: {}", ip_addr);
            
            // 尝试设置为点对点模式
            let _ = Command::new("ifconfig")
                .arg(&self.name)
                .arg("link0")  // 启用POINTOPOINT模式
                .output();
        }
        
        Ok(())
    }
    
    /// 启动TUN设备的读写循环
    pub fn start(&self, buffer_size: usize) -> (mpsc::Sender<TunBufferToken>, mpsc::Receiver<Buffer>) {
        let (tx_sender, tx_receiver) = mpsc::channel::<TunBufferToken>(buffer_size);
        let (rx_sender, rx_receiver) = mpsc::channel::<Buffer>(buffer_size);
        
        // 保存发送端
        let mut device_arc = Arc::new(self.clone());
        let device_arc_clone = device_arc.clone();
        let running = self.running.clone();
        
        // 设置运行标志
        running.store(true, Ordering::SeqCst);
        
        // 启动后台任务
        let task = tokio::spawn(async move {
            TunDevice::io_loop(device_arc_clone, tx_receiver, rx_sender, running).await;
        });
        
        // 保存任务句柄
        if let Ok(mut background_task) = self.background_task.lock() {
            *background_task = Some(task);
        }
        
        (tx_sender, rx_receiver)
    }
    
    /// 数据读写循环
    async fn io_loop(
        device: Arc<TunDevice>,
        mut tx_receiver: mpsc::Receiver<TunBufferToken>,
        rx_sender: mpsc::Sender<Buffer>,
        running: Arc<AtomicBool>,
    ) {
        debug!("TUN IO循环已启动");
        
        while running.load(Ordering::SeqCst) {
            // 尝试接收要发送的数据
            tokio::select! {
                Some(tx_buffer) = tx_receiver.recv() => {
                    // 有数据需要发送到TUN设备
                    if let Err(e) = device.send_buffer(tx_buffer) {
                        error!("TUN发送数据错误: {:?}", e);
                    }
                }
                
                // 轮询TUN设备接收数据
                _ = tokio::time::sleep(Duration::from_millis(1)) => {
                    // 尝试从TUN设备读取数据
                    match device.blocking_recv() {
                        Some(buffer) => {
                            // 发送到接收通道
                            match rx_sender.send(buffer).await {
                                Ok(_) => {
                                    trace!("成功发送数据包到接收通道");
                                },
                                Err(e) => {
                                    error!("TUN无法发送接收到的数据到通道: {}", e);
                                    // 不要立即退出循环，记录错误并继续
                                    tokio::time::sleep(Duration::from_millis(100)).await;
                                }
                            }
                        },
                        None => {
                            // 没有数据，短暂休眠，降低CPU使用率
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                    }
                }
            }
            
            // 添加错误恢复机制，防止循环过快
            if !running.load(Ordering::SeqCst) {
                debug!("检测到停止标志，IO循环将退出");
                break;
            }
        }
        
        debug!("TUN IO循环已停止");
    }
    
    /// 内部函数：发送缓冲区到TUN设备
    fn send_buffer(&self, buf: TunBufferToken) -> Result<(), String> {
        let (signature, data) = buf.into_parts();
        let len = data.len();
        
        // 使用ManuallyDrop防止数据被提前释放
        let buf = ManuallyDrop::new(unsafe { 
            TunBufferToken::new(signature, data) 
        });
        
        // 写入TUN设备
        if let Ok(mut device) = self.device.lock() {
            let slice = &buf.data[..len];
            
            // 调试日志
            if len >= 20 {
                let version = slice[0] >> 4;
                let protocol = if version == 4 { slice[9] } else { 0 };
                trace!("TunDevice发送: {}字节, v{}, 协议:{}", len, version, protocol);
            }
            
            match device.write(slice) {
                Ok(_) => {
                    // 成功写入
                    trace!("成功写入TUN设备: {} 字节", len);
                }
                Err(e) => {
                    // 写入出错
                    error!("TunDevice写入错误: {}", e);
                    return Err(format!("写入TUN设备失败: {}", e));
                }
            }
        } else {
            return Err("无法获取TUN设备锁".to_string());
        }
        
        // 手动释放缓冲区
        let buf = ManuallyDrop::into_inner(buf);
        self.return_tx_buffer(buf);
        
        Ok(())
    }
    
    /// 停止TUN设备读写循环
    pub fn stop(&self) {
        // 设置运行标志为false
        self.running.store(false, Ordering::SeqCst);
        
        // 等待后台任务结束
        if let Ok(mut background_task) = self.background_task.lock() {
            if let Some(task) = background_task.take() {
                // 使用tokio::spawn让等待在后台运行
                tokio::spawn(async move {
                    match tokio::time::timeout(Duration::from_secs(5), task).await {
                        Ok(_) => info!("TUN设备后台任务已成功关闭"),
                        Err(_) => error!("TUN设备后台任务关闭超时")
                    }
                });
                info!("正在停止TUN设备后台任务");
            }
        }
    }
    
    /// 添加路由规则，将指定目的地的流量通过TUN设备
    pub fn add_route(&self, target: &str) -> std::io::Result<()> {
        if let Some(ip) = self.ip_addr {
            println!("添加路由规则: {} -> {}", target, self.name);
            
            // 配置路由规则，将目标流量通过TUN设备
            let output = Command::new("route")
                .arg("-n")
                .arg("add")
                .arg("-net")
                .arg(target)
                .arg("-interface")
                .arg(&self.name)
                .output()?;
                
            if output.status.success() {
                println!("✅ 成功添加路由: {} -> {}", target, self.name);
            } else {
                let error = String::from_utf8_lossy(&output.stderr);
                error!("⚠️ 添加路由失败: {} -> {}: {}", 
                         target, self.name, error);
            }
        }
        
        Ok(())
    }
    
    /// 添加默认路由，将所有流量通过TUN设备(小心使用)
    pub fn add_default_routes(&self) -> std::io::Result<()> {
        // 添加两个路由规则覆盖整个IP地址范围
        self.add_route("0.0.0.0/1")?;
        self.add_route("128.0.0.0/1")?;
        println!("✅ 已添加默认路由，所有流量将通过 {} 设备", self.name);
        Ok(())
    }
    
    /// Returns the device name
    pub fn get_name(&self) -> &str {
        &self.name
    }
    
    /// Returns the IP address if set
    pub fn get_address(&self) -> Option<Ipv4Addr> {
        self.ip_addr
    }
    
    /// Returns the netmask if set
    pub fn get_netmask(&self) -> Option<Ipv4Addr> {
        self.netmask
    }
}

impl Clone for TunDevice {
    fn clone(&self) -> Self {
        // 只是共享底层TUN设备的引用，而不是创建新设备
        Self {
            device: self.device.clone(), // Clone Arc，增加引用计数
            mtu: self.mtu,
            ip_addr: self.ip_addr,
            netmask: self.netmask,
            name: self.name.clone(),
            rx_buffers: Mutex::new(VecDeque::new()),
            tx_buffers: Mutex::new(VecDeque::new()),
            state: Mutex::new(TunState::Idle),
            running: self.running.clone(),
            tx_sender: None,
            rx_sender: None,
            background_task: Mutex::new(None),
        }
    }
}

impl Tun for TunDevice {
    fn blocking_recv(&self) -> Option<Buffer> {
        // Try to get a buffer from the pool
        let mut buffer = match self.rx_buffers.lock().ok()?.pop_front() {
            Some(buf) => buf,
            None => {
                // If no buffer is available, create a new one
                let mut new_buf = Buffer::new();
                new_buf.resize(self.mtu, 0);
                new_buf
            }
        };
        
        // Make sure the buffer has the right size
        buffer.resize(self.mtu, 0);
        
        // Read from the device
        let read_result = {
            let mut guard = match self.device.lock() {
                Ok(guard) => guard,
                Err(_) => return None,
            };
            
            // Perform blocking read
            match guard.read(&mut buffer) {
                Ok(n) => {
                    if n > 0 {
                        // Resize buffer to actual data length
                        buffer.truncate(n);
                        // 调试：打印接收到的IP包头部信息
                        if buffer.len() >= 20 {
                            let version = buffer[0] >> 4;
                            let protocol = if version == 4 { buffer[9] } else { 0 };
                            trace!("TunDevice接收: {}字节, v{}, 协议:{}", buffer.len(), version, protocol);
                        }
                        Some(buffer)
                    } else {
                        // No data read, return the buffer to the pool
                        let mut rx_buffers = match self.rx_buffers.lock() {
                            Ok(guard) => guard,
                            Err(_) => return None,
                        };
                        rx_buffers.push_back(buffer);
                        None
                    }
                },
                Err(e) => {
                    // Error reading, return the buffer to the pool
                    error!("TunDevice读取错误: {}", e);
                    let mut rx_buffers = match self.rx_buffers.lock() {
                        Ok(guard) => guard,
                        Err(_) => return None,
                    };
                    rx_buffers.push_back(buffer);
                    None
                }
            }
        };
        
        read_result
    }
    
    fn return_recv_buffer(&self, buf: Buffer) {
        // Return the buffer to the pool
        if let Ok(mut rx_buffers) = self.rx_buffers.lock() {
            rx_buffers.push_back(buf);
        }
    }
    
    fn get_tx_buffer(&self) -> Option<TunBufferToken> {
        // Get a buffer from the pool
        let mut tx_buffers = match self.tx_buffers.lock() {
            Ok(guard) => guard,
            Err(_) => return None,
        };
        
        tx_buffers.pop_front()
    }
    
    fn send(&self, buf: TunBufferToken, len: usize) {
        // Get the slice with the actual data length
        let (signature, data) = buf.into_parts();
        
        // Use a ManuallyDrop to prevent data from being freed
        let buf = ManuallyDrop::new(unsafe { 
            TunBufferToken::new(signature, data) 
        });
        
        // Write the data to the device
        if let Ok(mut device) = self.device.lock() {
            let slice = &buf.data[..len];
            
            // 调试：打印发送的IP包头部信息
            if len >= 20 {
                let version = slice[0] >> 4;
                let protocol = if version == 4 { slice[9] } else { 0 };
                trace!("TunDevice发送: {}字节, v{}, 协议:{}", len, version, protocol);
            }
            
            match device.write(slice) {
                Ok(_) => {},
                Err(e) => error!("TunDevice写入错误: {}", e)
            }
        }
        
        // Now manually free the ManuallyDrop by returning the buffer
        let buf = ManuallyDrop::into_inner(buf);
        self.return_tx_buffer(buf);
    }
    
    fn return_tx_buffer(&self, buf: TunBufferToken) {
        // Return the buffer to the pool
        if let Ok(mut tx_buffers) = self.tx_buffers.lock() {
            tx_buffers.push_back(buf);
        }
    }
}

impl Drop for TunDevice {
    fn drop(&mut self) {
        // 停止后台任务
        self.stop();
        
        // Clean up leaked tx buffers when the device is dropped
        if let Ok(mut tx_buffers) = self.tx_buffers.lock() {
            while let Some(token) = tx_buffers.pop_front() {
                let (_, data) = token.into_parts();
                // Convert back to a Box and drop it
                unsafe {
                    let _ = Box::from_raw(data);
                }
            }
        }
    }
}