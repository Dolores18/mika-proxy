use crate::flow::{Buffer, TunBufferToken, TunBufferSignature, Tun};
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;
use std::io::{self, Read, Write, Result as IoResult};
use std::process::Command;
use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};
use tun::{Device as TunDevicePlatform};
use std::path::PathBuf;
use log::info;
use std::os::unix::io::{AsRawFd, RawFd};
use std::time::{Duration, Instant};
use tun::AbstractDevice;
use tun::Configuration;

// MacTun设备类型，使用改进的锁策略
pub struct MacTun {
    // 内部tun设备实例 - 使用可超时的互斥锁
    device: Arc<parking_lot::Mutex<TunDevicePlatform>>,
    // 设备名称
    name: String,
    // 设备IP地址
    address: Ipv4Addr,
    // IPv6地址
    address_v6: Option<Ipv6Addr>,
    // 网络掩码
    netmask: Ipv4Addr,
    // 接收缓冲区池
    rx_pool: Arc<Mutex<Vec<Buffer>>>,
    // 发送缓冲区池
    tx_pool: Arc<Mutex<Vec<Box<Vec<u8>>>>>,
    // 设备文件描述符 - 用于IO多路复用
    fd: RawFd,
    // 接收和发送缓冲区的大小
    mtu: usize,
    // 最大锁持有时间（毫秒）
    max_lock_time: u64,
}

impl MacTun {
    /// 创建并初始化MacTun设备
    pub fn new(
        name: &str, 
        address: Ipv4Addr,
        netmask: Ipv4Addr,
        mtu: Option<usize>
    ) -> IoResult<Self> {
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
        let mut device = tun::create(&config)?;
        
        // 获取文件描述符，用于IO多路复用
        let fd = device.as_raw_fd();
        
        // 将设备设置为非阻塞模式
        use nix::fcntl::{fcntl, FcntlArg, OFlag};
        let flags = fcntl(fd, FcntlArg::F_GETFL)?;
        let flags = OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK;
        fcntl(fd, FcntlArg::F_SETFL(flags))?;
        
        // 获取实际设备名称
        let actual_name = device.tun_name().unwrap_or_else(|_| name.to_string());
        let mtu_val = mtu.unwrap_or(1500);
        
        // 创建MacTun实例，使用parking_lot库的互斥锁
        let mac_tun = Self {
            device: Arc::new(parking_lot::Mutex::new(device)),
            name: actual_name,
            address,
            address_v6,
            netmask,
            rx_pool: Arc::new(Mutex::new(Vec::new())),
            tx_pool: Arc::new(Mutex::new(Vec::new())),
            fd,
            mtu: mtu_val,
            max_lock_time: 100, // 最大锁持有时间：100毫秒
        };
        
        // 如果支持IPv6，配置IPv6地址
        if let Some(ipv6_addr) = &mac_tun.address_v6 {
            println!("配置IPv6地址: {}", ipv6_addr);
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

    /// 获取TUN设备名称
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// 获取TUN设备IP地址
    pub fn get_address(&self) -> Ipv4Addr {
        self.address
    }
    
    // 等待设备可读，带超时
    fn wait_readable(&self, timeout_ms: u64) -> bool {
        use nix::poll::{poll, PollFd, PollFlags};
        let mut fds = [PollFd::new(self.fd, PollFlags::POLLIN)];
        match poll(&mut fds, timeout_ms as i32) {
            Ok(n) if n > 0 => true,
            _ => false
        }
    }
    
    // 等待设备可写，带超时
    fn wait_writable(&self, timeout_ms: u64) -> bool {
        use nix::poll::{poll, PollFd, PollFlags};
        let mut fds = [PollFd::new(self.fd, PollFlags::POLLOUT)];
        match poll(&mut fds, timeout_ms as i32) {
            Ok(n) if n > 0 => true,
            _ => false
        }
    }
}

impl Tun for MacTun {
    fn blocking_recv(&self) -> Option<Buffer> {
        loop {  // 一直循环尝试接收
            // 尝试从接收池获取缓冲区，如果没有则创建新的
            let mut buffer = Vec::new();
            buffer.resize(self.mtu, 0);
            
            // 等待设备可读
            if !self.wait_readable(100) {
                // 设备不可读，短暂休眠后继续
                std::thread::sleep(Duration::from_millis(5));
                continue;  // 继续循环，而不是返回None
            }
            
            // 获取设备锁
            let mut device_guard = self.device.lock();
            
            // 从设备读取数据
            match device_guard.read(&mut buffer) {
                Ok(n) if n > 0 => {
                    buffer.resize(n, 0);
                    return Some(Buffer::from(buffer));
                },
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // 短暂休眠，避免CPU空转
                    std::thread::sleep(Duration::from_millis(1));
                    continue;  // 继续循环，而不是返回None
                },
                Err(e) => {
                    eprintln!("读取TUN设备错误: {}", e);
                    // 对于错误，可以短暂暂停后继续，除非是致命错误
                    if e.kind() == io::ErrorKind::BrokenPipe ||
                       e.kind() == io::ErrorKind::NotConnected {
                        return None;  // 只有严重错误才退出
                    }
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                },
                _ => continue  // 其他情况继续循环，而不是返回None
            }
        }
    }
    
    fn return_recv_buffer(&self, buf: Buffer) {
        // 将缓冲区放回池中以便重用
        info!("🐶MACTUN: 返还接收缓冲区，长度: {}", buf.len());
        if let Ok(mut rx_pool) = self.rx_pool.lock() {
            rx_pool.push(buf);
        }
    }
    
    fn get_tx_buffer(&self) -> Option<TunBufferToken> {
        // 尝试从发送池获取缓冲区
        let mut tx_pool = match self.tx_pool.lock() {
            Ok(pool) => pool,
            Err(e) => {
                eprintln!("无法获取发送池锁: {:?}", e);
                return None;
            }
        };
        
        // 优先从池中获取，如果池为空则创建新的
        let boxed_buf = tx_pool.pop().unwrap_or_else(|| Box::new(vec![0u8; self.mtu]));
        
        // 将盒子转换为静态引用
        let data_ptr = Box::into_raw(boxed_buf);
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
    
    fn send(&self, buf: TunBufferToken, len: usize) -> Result<(), io::Error> {
        info!("🍓MACTUN: 发送数据包，长度: {}", len);
        
        let (signature, data) = buf.into_parts();
        
        // 释放原始缓冲区的引用
        let data_ptr = signature[0] as *mut Vec<u8>;
        
        // 添加数据包分析...（根据原代码）
        if len >= 20 {
            let version = data[0] >> 4;
            // ... 其他分析代码 ...
        }
        
        // 等待设备可写，最多等待100ms
        if !self.wait_writable(100) {
            // 设备不可写，返回错误
            let err = io::Error::new(io::ErrorKind::WouldBlock, "TUN设备写入超时");
            
            // 将缓冲区放回池中
            unsafe {
                if !data_ptr.is_null() {
                    let boxed_buf = Box::from_raw(data_ptr);
                    if let Ok(mut pool) = self.tx_pool.lock() {
                        pool.push(boxed_buf);
                    }
                }
            }
            
            return Err(err);
        }
        
        println!("🔒 请求: 尝试获取设备锁进行写入");
        let start_time = Instant::now();
        let mut device_guard = self.device.lock();
        println!("🔒 请求: 成功获取设备锁进行写入");
        
        // 设置写入超时
        let write_start = Instant::now();
        let max_write_time = Duration::from_millis(self.max_lock_time);
        
        // 循环尝试写入，直到成功或超时
        let result = loop {
            match device_guard.write(&data[..len]) {
                Ok(written) => {
                    if written == 0 {
                        break Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "TUN设备写入0字节，设备可能已不再接受数据"
                        ));
                    } else if written < len {
                        println!("⚠️ 注意：只写入了 {} 字节，而不是请求的全部 {} 字节", written, len);
                        break Ok(());
                    } else {
                        println!("✅ 请求: 写入TUN设备成功: {} 字节", written);
                        // 尝试刷新
                        let _ = device_guard.flush();
                        break Ok(());
                    }
                },
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // 如果操作会阻塞且已经超过最大写入时间，则退出循环
                    if write_start.elapsed() > max_write_time {
                        println!("⏱️ 请求: 写入超时");
                        break Err(io::Error::new(io::ErrorKind::WouldBlock, "TUN设备写入超时"));
                    }
                    // 短暂休眠，避免CPU空转
                    std::thread::sleep(Duration::from_millis(1));
                    continue;
                },
                Err(e) => {
                    break Err(e);
                }
            }
        };
        
        // 释放设备锁
        drop(device_guard);
        let elapsed = start_time.elapsed();
        println!("🔓 请求: 释放设备锁，持有时间: {:?}", elapsed);
        
        // 归还缓冲区
        unsafe {
            if !data_ptr.is_null() {
                let boxed_buf = Box::from_raw(data_ptr);
                if let Ok(mut pool) = self.tx_pool.lock() {
                    pool.push(boxed_buf);
                }
            }
        }
        
        result
    }
    
    fn return_tx_buffer(&self, buf: TunBufferToken) {
        // 释放缓冲区并放回池中
        info!("TUN: 返还发送缓冲区");
        unsafe {
            let (signature, _) = buf.into_parts();
            let data_ptr = signature[0] as *mut Vec<u8>;
            if !data_ptr.is_null() {
                // 将指针转回Box并放入发送池
                let boxed_buf = Box::from_raw(data_ptr);
                if let Ok(mut pool) = self.tx_pool.lock() {
                    pool.push(boxed_buf);
                } else {
                    // 如果无法获取锁，则直接丢弃
                    drop(boxed_buf);
                }
            }
        }
    }
}