use crate::flow::{Buffer, TunBufferToken, TunBufferSignature, Tun};
use std::sync::{Arc, RwLock}; // 使用RwLock
use std::io::{self, Read, Write, Result as IoResult};
use std::process::Command;
use std::net::{Ipv4Addr, Ipv6Addr};
use tun::{Device as TunDevicePlatform};
use log::info;
use std::os::unix::io::{AsRawFd, RawFd};
use std::time::{Duration, Instant};
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::poll::{poll, PollFd, PollFlags};
use tun::AbstractDevice;

// MacTun设备类型，使用RW锁
pub struct MacTun {
    device: Arc<RwLock<TunDevicePlatform>>, // 使用RwLock
    name: String,
    address: Ipv4Addr,
    address_v6: Option<Ipv6Addr>,
    netmask: Ipv4Addr,
    rx_pool: Arc<RwLock<Vec<Buffer>>>, // 使用RwLock
    tx_pool: Arc<RwLock<Vec<Box<Vec<u8>>>>>, // 使用RwLock
    fd: RawFd,
    mtu: usize,
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
        let device = tun::create(&config)?;

        // 获取文件描述符，用于IO多路复用
        let fd = device.as_raw_fd();
        
        // 将设备设置为非阻塞模式
        set_non_blocking(fd)?;

        // 获取实际设备名称
        let actual_name = device.tun_name().unwrap_or_else(|_| name.to_string());
        let mtu_val = mtu.unwrap_or(1500);

        let mac_tun = Self {
            device: Arc::new(RwLock::new(device)), // 使用RwLock
            name: actual_name,
            address,
            address_v6,
            netmask,
            rx_pool: Arc::new(RwLock::new(Vec::new())), // 使用RwLock
            tx_pool: Arc::new(RwLock::new(Vec::new())), // 使用RwLock
            fd,
            mtu: mtu_val,
            max_lock_time: 100, // 最大锁持有时间：100毫秒
        };

        // 如果支持IPv6，配置IPv6地址
        if let Some(ipv6_addr) = &mac_tun.address_v6 {
            configure_ipv6(&mac_tun.name, ipv6_addr)?;
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
        self.wait_for_poll(PollFlags::POLLIN, timeout_ms)
    }

    // 等待设备可写，带超时
    fn wait_writable(&self, timeout_ms: u64) -> bool {
        self.wait_for_poll(PollFlags::POLLOUT, timeout_ms)
    }

    // 通用的等待函数
    fn wait_for_poll(&self, flags: PollFlags, timeout_ms: u64) -> bool {
        let mut fds = [PollFd::new(self.fd, flags)];
        match poll(&mut fds, timeout_ms as i32) {
            Ok(n) if n > 0 => true,
            _ => false,
        }
    }

    // 向MacTun添加shutdown方法
    pub fn shutdown(&self) {
        log::info!("正在关闭TUN设备: {}", self.get_name());
        
        // 尝试获取设备锁并关闭
        if let Ok(mut device) = self.device.write() {
            // 强制关闭底层文件描述符
            unsafe {
                let fd = device.as_raw_fd();
                // 使用nix关闭文件描述符
                if let Err(e) = nix::unistd::close(fd) {
                    log::error!("关闭TUN设备文件描述符时出错: {:?}", e);
                } else {
                    log::info!("成功关闭TUN设备文件描述符");
                }
            }
        } else {
            log::error!("无法获取TUN设备锁进行关闭");
        }
        
        // 清空缓冲区池
        if let Ok(mut pool) = self.rx_pool.write() {
            pool.clear();
        }
        
        if let Ok(mut pool) = self.tx_pool.write() {
            pool.clear();
        }
        
        log::info!("TUN设备资源已释放: {}", self.get_name());
    }
}

// 辅助函数：设置文件描述符为非阻塞模式
fn set_non_blocking(fd: RawFd) -> IoResult<()> {
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
        loop {
            let mut buffer = vec![0; self.mtu];

            // 等待设备可读
            if !self.wait_readable(100) {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }

            // 获取设备锁
            let mut device_guard = self.device.write().unwrap(); // 使用RwLock的写锁进行读取操作
            match device_guard.read(&mut buffer) {
                Ok(n) if n > 0 => {
                    buffer.resize(n, 0);
                    return Some(Buffer::from(buffer));
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1));
                    continue;
                }
                Err(e) => {
                    eprintln!("读取TUN设备错误: {}", e);
                    if matches!(e.kind(), io::ErrorKind::BrokenPipe | io::ErrorKind::NotConnected) {
                        return None;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }
                _ => continue,
            }
        }
    }

    fn return_recv_buffer(&self, buf: Buffer) {
        info!("🐶MACTUN: 返还接收缓冲区，长度: {}", buf.len());
        if let Ok(mut rx_pool) = self.rx_pool.write() { // 使用RwLock的写锁
            rx_pool.push(buf);
        }
    }

    fn get_tx_buffer(&self) -> Option<TunBufferToken> {
        let mut tx_pool = match self.tx_pool.write() { // 使用RwLock的写锁
            Ok(pool) => pool,
            Err(e) => {
                eprintln!("无法获取发送池锁: {:?}", e);
                return None;
            }
        };

        let boxed_buf = tx_pool.pop().unwrap_or_else(|| Box::new(vec![0u8; self.mtu]));
        
        let data_ptr = Box::into_raw(boxed_buf);
        let static_slice = unsafe {
            std::slice::from_raw_parts_mut((*data_ptr).as_mut_ptr(), self.mtu)
        };

        let signature = [data_ptr as *mut usize, std::ptr::null_mut()];

        info!("🐶MACTUN: 创建发送缓冲区，大小: {}", self.mtu);
        
        unsafe {
            Some(TunBufferToken::new(signature, static_slice))
        }
    }

    fn send(&self, buf: TunBufferToken, len: usize) -> Result<(), io::Error> {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        info!("🍓MACTUN: 发送数据包，长度: {}, 时间: {}s {}ms", len, now.as_secs(), now.subsec_millis());

        let (signature, data) = buf.into_parts();
        let data_ptr = signature[0] as *mut Vec<u8>;

        if !self.wait_writable(100) {
            let err = io::Error::new(io::ErrorKind::WouldBlock, "TUN设备写入超时");
            return recycle_buffer(data_ptr, &self.tx_pool, err);
        }

        println!("🔒 请求: 尝试获取设备锁进行写入");
        let mut device_guard = self.device.write().unwrap(); // 使用RwLock的写锁
        println!("🔒 请求: 成功获取设备锁进行写入");

        let result = loop {
            match device_guard.write(&data[..len]) {
                Ok(written) if written == 0 => {
                    break Err(io::Error::new(io::ErrorKind::WriteZero, "TUN设备写入0字节，设备可能已不再接受数据"));
                }
                Ok(written) if written < len => {
                    println!("⚠️ 注意：只写入了 {} 字节，而不是请求的全部 {} 字节", written, len);
                    break Ok(());
                }
                Ok(written) => {
                    println!("✅ 请求: 写入TUN设备成功: {} 字节", written);
                    let end_time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
                    println!("✅ 请求: 写入完成时间: {}s {}ms", end_time.as_secs(), end_time.subsec_millis());
                    let _ = device_guard.flush();
                    break Ok(());
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1));
                    continue;
                }
                Err(e) => {
                    break Err(e);
                }
            }
        };

        drop(device_guard);

        // 如果结果是错误，调用recycle_buffer并返回错误
        if let Err(err) = result {
            return recycle_buffer(data_ptr, &self.tx_pool, err);
        }
        
        // 否则，手动回收缓冲区并返回成功
        unsafe {
            if !data_ptr.is_null() {
                let boxed_buf = Box::from_raw(data_ptr);
                if let Ok(mut tx_pool) = self.tx_pool.write() {
                    tx_pool.push(boxed_buf);
                }
            }
        }
        Ok(())
    }

    fn return_tx_buffer(&self, buf: TunBufferToken) {
        info!("TUN: 返还发送缓冲区");
        unsafe {
            let (signature, _) = buf.into_parts();
            let data_ptr = signature[0] as *mut Vec<u8>;
            if !data_ptr.is_null() {
                let boxed_buf = Box::from_raw(data_ptr);
                if let Ok(mut pool) = self.tx_pool.write() { // 使用RwLock的写锁
                    pool.push(boxed_buf);
                } else {
                    drop(boxed_buf); // 如果无法获取锁，则直接丢弃
                }
            }
        }
    }
}

// 辅助函数：回收缓冲区
fn recycle_buffer(data_ptr: *mut Vec<u8>, pool: &Arc<RwLock<Vec<Box<Vec<u8>>>>>, err: io::Error) -> Result<(), io::Error> {
    unsafe {
        if !data_ptr.is_null() {
            let boxed_buf = Box::from_raw(data_ptr);
            if let Ok(mut tx_pool) = pool.write() { // 使用RwLock的写锁
                tx_pool.push(boxed_buf);
            }
        }
    }
    Err(err)
}
