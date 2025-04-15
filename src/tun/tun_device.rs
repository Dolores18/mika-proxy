use crate::flow::{Buffer, TunBufferToken, TunBufferSignature, Tun};
use std::io::{self, Result as IoResult, Read, Write};
use std::process::Command;
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::sync::mpsc::{self, Sender, Receiver};
use tokio::io::{Interest, AsyncReadExt, AsyncWriteExt};
use log::info;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tun::{Device as TunDevice, Configuration};
use tun::AbstractDevice;
use tokio::io::unix::AsyncFd;
use std::sync::Mutex;
use std::cell::RefCell;
use nix::unistd::{read, write};

// 无锁版MacTun设备
pub struct MacTun {
    device: Arc<AsyncFd<TunDevice>>, // 异步封装的TUN设备
    name: String,
    address: Ipv4Addr,
    address_v6: Option<Ipv6Addr>,
    netmask: Ipv4Addr,
    // 接收通道
    rx_rx: Mutex<Receiver<Buffer>>,   // 接收数据的通道接收端
    rx_tx: Sender<Buffer>,            // 接收数据的通道发送端
    // 发送通道 - 只保留发送端
    tx_tx: Sender<Vec<u8>>,           // 发送数据的通道发送端
    // 空闲缓冲区池
    buffer_pool_rx: Mutex<Receiver<Box<Vec<u8>>>>, // 缓冲区池接收端
    buffer_pool_tx: Sender<Box<Vec<u8>>>,          // 缓冲区池发送端
    mtu: usize,
    // 关闭信号通道
    shutdown_tx: Sender<()>,           // 关闭信号发送端
    shutdown_rx: Mutex<Receiver<()>>,  // 关闭信号接收端
}

impl MacTun {
    /// 创建并初始化MacTun设备
    pub async fn new(
        name: &str, 
        address: Ipv4Addr,
        netmask: Ipv4Addr,
        mtu: Option<usize>
    ) -> IoResult<Self> {
        let address_v6 = None;
        let mtu_val = mtu.unwrap_or(1500);
    
        // 创建tun设备配置
        let mut config = Configuration::default();
        config
            .tun_name(name)
            .address(address)
            .netmask(netmask)
            .mtu(mtu_val as u16)
            .up();
    
        // 创建TUN设备
        let device = tun::create(&config)?;
        
        // 获取设备文件描述符
        let fd = device.as_raw_fd();
        
        // 设置为非阻塞模式
        set_non_blocking(fd)?;
        
        // 使用AsyncFd包装原始设备，使其可以用于tokio的异步操作
        let async_device = AsyncFd::new(device)?;
        
        // 获取实际设备名称
        let actual_name = async_device.get_ref().tun_name().unwrap_or_else(|_| name.to_string());
    
        // 创建通道
        let (rx_tx, rx_rx) = mpsc::channel::<Buffer>(1024);
        let (tx_tx, tx_rx) = mpsc::channel::<Vec<u8>>(1024);
        let (buffer_pool_tx, buffer_pool_rx) = mpsc::channel::<Box<Vec<u8>>>(1024);
        // 创建关闭信号通道
        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);
    
        let device_arc = Arc::new(async_device);
    
        // 创建MacTun实例
        let mac_tun = Self {
            device: device_arc.clone(),
            name: actual_name,
            address,
            address_v6,
            netmask,
            rx_rx: Mutex::new(rx_rx),
            rx_tx,
            tx_tx,
            buffer_pool_rx: Mutex::new(buffer_pool_rx),
            buffer_pool_tx,
            mtu: mtu_val,
            shutdown_tx,
            shutdown_rx: Mutex::new(shutdown_rx),
        };
    
        // 如果支持IPv6，配置IPv6地址
        if let Some(ipv6_addr) = &mac_tun.address_v6 {
            configure_ipv6(&mac_tun.name, ipv6_addr)?;
        }
    
        // 启动后台读写任务
        let rx_tx_clone = mac_tun.rx_tx.clone();
        let shutdown_rx1 = mac_tun.shutdown_rx.lock().unwrap().resubscribe();
        tokio::spawn(Self::read_loop(device_arc.clone(), rx_tx_clone, mtu_val, shutdown_rx1));
        
        // 直接传递tx_rx的所有权，不再尝试克隆
        let shutdown_rx2 = mac_tun.shutdown_rx.lock().unwrap().resubscribe();
        tokio::spawn(Self::write_loop(device_arc.clone(), tx_rx, shutdown_rx2));
    
        // 预填充缓冲区池
        let buffer_pool_tx_clone = mac_tun.buffer_pool_tx.clone();
        tokio::spawn(async move {
            for _ in 0..64 {  // 预先创建64个缓冲区
                let buf = Box::new(vec![0u8; mtu_val]);
                if buffer_pool_tx_clone.send(buf).await.is_err() {
                    break;
                }
            }
        });
    
        Ok(mac_tun)
    }

    // 读取循环 - 从TUN设备读取数据并发送到通道
    async fn read_loop(
        device: Arc<AsyncFd<TunDevice>>, 
        tx: Sender<Buffer>, 
        mtu: usize,
        mut shutdown: Receiver<()>
    ) {
        let mut buf = vec![0u8; mtu];
        
        loop {
            // 检查关闭信号
            if let Ok(Some(_)) = shutdown.try_recv().map_err(|_| ()) {
                info!("读取循环接收到关闭信号，正在退出");
                break;
            }
            
            // 使用tokio::select等待可读性或关闭信号
            tokio::select! {
                // 等待设备可读
                readable = device.readable() => {
                    match readable {
                        Ok(_) => {
                            let fd = device.get_ref().as_raw_fd();
                            // 使用nix直接操作文件描述符
                            match read(fd, &mut buf) {
                                Ok(n) if n > 0 => {
                                    let packet = Buffer::from(&buf[..n]);
                                    // 使用try_send代替send避免在关闭时阻塞
                                    if tx.try_send(packet).is_err() {
                                        // 如果发送失败，可能是接收端已关闭
                                        break;
                                    }
                                }
                                Ok(_) => continue,
                                Err(e) if e == nix::errno::Errno::EAGAIN => continue,
                                Err(e) => {
                                    eprintln!("Read error: {:?}", e);
                                    break;
                                }
                            }
                        },
                        Err(_) => continue,
                    }
                }
                // 等待关闭信号
                _ = shutdown.recv() => {
                    info!("读取循环接收到关闭信号，正在退出");
                    break;
                }
            }
        }
        info!("TUN读取循环已退出");
    }

    // 写入循环同样修改
    async fn write_loop(
        device: Arc<AsyncFd<TunDevice>>, 
        mut rx: Receiver<Vec<u8>>,
        mut shutdown: Receiver<()>
    ) {
        loop {
            // 使用tokio::select等待数据或关闭信号
            let buf = tokio::select! {
                // 等待接收数据
                Some(buf) = rx.recv() => buf,
                // 等待关闭信号
                _ = shutdown.recv() => {
                    info!("写入循环接收到关闭信号，正在退出");
                    break;
                }
            };
            
            // 使用tokio::select等待可写性或关闭信号
            tokio::select! {
                // 等待设备可写
                writable = device.writable() => {
                    match writable {
                        Ok(_) => {
                            let fd = device.get_ref().as_raw_fd();
                            // 使用nix直接操作文件描述符
                            match write(fd, &buf) {
                                Ok(n) => {
                                    if n < buf.len() {
                                        eprintln!("Partial write: {}/{}", n, buf.len());
                                    }
                                }
                                Err(e) if e == nix::errno::Errno::EAGAIN => continue,
                                Err(e) => eprintln!("Write error: {:?}", e),
                            }
                        },
                        Err(_) => continue,
                    }
                }
                // 等待关闭信号
                _ = shutdown.recv() => {
                    info!("写入循环接收到关闭信号，正在退出");
                    break;
                }
            }
        }
        info!("TUN写入循环已退出");
    }
    
    // 获取空闲缓冲区
    async fn get_buffer(&self) -> Box<Vec<u8>> {
        // 尝试从池中获取缓冲区
        // 使用Mutex来安全地获取可变引用
        let mut rx = self.buffer_pool_rx.lock().unwrap();
        match rx.try_recv() {
            Ok(buf) => buf,
            Err(_) => Box::new(vec![0u8; self.mtu]) // 如果池为空，创建新的
        }
    }
    
    // 返回缓冲区到池中
    async fn return_buffer(&self, buf: Box<Vec<u8>>) {
        // 如果池未满，将缓冲区放回池中
        let _ = self.buffer_pool_tx.send(buf).await;
    }

    /// 获取TUN设备名称
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// 获取TUN设备IP地址
    pub fn get_address(&self) -> Ipv4Addr {
        self.address
    }
}

// 辅助函数：设置文件描述符为非阻塞模式
fn set_non_blocking(fd: RawFd) -> IoResult<()> {
    use nix::fcntl::{fcntl, FcntlArg, OFlag};
    
    let flags = fcntl(fd, FcntlArg::F_GETFL)?;
    let flags = OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK;
    fcntl(fd, FcntlArg::F_SETFL(flags))?;
    Ok(())
}

// 辅助函数：配置IPv6地址
fn configure_ipv6(device_name: &str, ipv6_addr: &Ipv6Addr) -> IoResult<()> {
    Command::new("ifconfig")
        .arg(device_name)
        .arg("inet6")
        .arg(ipv6_addr.to_string())
        .arg("prefixlen")
        .arg("64")
        .arg("alias")
        .output()?;
    Ok(())
}

impl Tun for MacTun {
    fn blocking_recv(&self) -> Option<Buffer> {
        // 使用tokio的阻塞执行器执行异步操作
        // 使用Mutex来安全地获取可变引用
        let mut rx = self.rx_rx.lock().unwrap();
        tokio::runtime::Handle::current().block_on(async {
            rx.recv().await
        })
    }

    fn return_recv_buffer(&self, buf: Buffer) {
        info!("🐶MACTUN: 返还接收缓冲区，长度: {}", buf.len());
        // 在无锁版本中，我们不需要手动管理接收缓冲区
        // Buffer会在离开作用域时自动释放
    }

    fn get_tx_buffer(&self) -> Option<TunBufferToken> {
        let mtu = self.mtu;
        
        // 创建新的缓冲区
        let boxed_buf = Box::new(vec![0u8; mtu]);
        let data_ptr = Box::into_raw(boxed_buf);
        
        // 创建可变切片
        let static_slice = unsafe {
            std::slice::from_raw_parts_mut((*data_ptr).as_mut_ptr(), mtu)
        };

        // 创建签名
        let signature = [data_ptr as *mut usize, std::ptr::null_mut()];
        
        info!("🐶MACTUN: 创建发送缓冲区，大小: {}", mtu);
        
        // 创建TunBufferToken
        unsafe {
            Some(TunBufferToken::new(signature, static_slice))
        }
    }

    fn send(&self, buf: TunBufferToken, len: usize) -> Result<(), io::Error> {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        info!("🍓MACTUN: 发送数据包，长度: {}, 时间: {}s {}ms", len, now.as_secs(), now.subsec_millis());

        // 分解TunBufferToken
        let (signature, data) = buf.into_parts();
        let data_ptr = signature[0] as *mut Vec<u8>;
        
        // 确保数据指针有效
        if data_ptr.is_null() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "无效的缓冲区指针"));
        }
        
        // 复制需要发送的数据
        let send_data = Vec::from(&data[..len]);
        
        // 释放原始缓冲区
        unsafe {
            let _ = Box::from_raw(data_ptr);
        }
        
        // 发送数据到通道
        tokio::runtime::Handle::current().block_on(async {
            match self.tx_tx.send(send_data).await {
                Ok(_) => Ok(()),
                Err(_) => Err(io::Error::new(io::ErrorKind::BrokenPipe, "发送通道已关闭"))
            }
        })
    }

    fn return_tx_buffer(&self, buf: TunBufferToken) {
        info!("TUN: 返还发送缓冲区");
        
        // 分解TunBufferToken
        let (signature, _) = buf.into_parts();
        let data_ptr = signature[0] as *mut Vec<u8>;
        
        // 确保数据指针有效后释放
        unsafe {
            if !data_ptr.is_null() {
                let _ = Box::from_raw(data_ptr);
            }
        }
    }
}

// 扩展Tun特质，添加shutdown方法
pub trait ShutdownableTun: Tun {
    // 关闭TUN设备
    fn shutdown(&self);
}

// 为MacTun实现ShutdownableTun特质
impl ShutdownableTun for MacTun {
    fn shutdown(&self) {
        info!("正在关闭TUN设备: {}", self.name);
        // 发送关闭信号，忽略错误（如果接收端已关闭）
        let _ = self.shutdown_tx.try_send(());
    }
}