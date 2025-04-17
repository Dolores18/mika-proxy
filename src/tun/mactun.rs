use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::sync::{Arc, Mutex, Once};
use std::{mem, ptr, slice};
use std::ffi::{CStr, CString};
use std::process::Command;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Semaphore};
use libc;
use flume;
use crate::flow::{Buffer, Tun, TunBufferToken as FlowTunBufferToken};
use once_cell::sync::Lazy;

// 添加全局共享的运行时实例
static SEND_RUNTIME: Lazy<tokio::runtime::Runtime> = Lazy::new(|| {
    // 创建一个不启用I/O和定时器的最小化runtime
    // 仅使用当前线程执行器，避免创建额外线程池
    tokio::runtime::Builder::new_current_thread()
        // 只启用time功能，不启用I/O驱动
        .enable_time()
        .build()
        .expect("Failed to create global runtime for TUN send operations")
});

const BUFFER_SIZE: usize = 2048; // 调整为适当大小，应大于MTU
const TUN_NAME: &str = "utun5"; // 可以根据需要更改
const MAX_CONCURRENT_SENDS: usize = 100; // 最大并发发送数量

pub type TunBufferSignature = [*mut usize; 2];

#[derive(Debug)]
pub struct TunBufferToken {
    /// 不透明数据
    signature: TunBufferSignature,
    pub data: &'static mut [u8],
}

unsafe impl Send for TunBufferToken {}
unsafe impl Sync for TunBufferToken {}

impl Clone for TunBufferToken {
    fn clone(&self) -> Self {
        unsafe {
            Self {
                signature: self.signature,
                data: std::slice::from_raw_parts_mut(
                    self.data.as_ptr() as *mut u8,
                    self.data.len()
                ),
            }
        }
    }
}

impl TunBufferToken {
    /// # Safety
    ///
    /// 用户必须确保`signature`可以安全地发送到其他线程。
    pub unsafe fn new(signature: TunBufferSignature, data: &'static mut [u8]) -> Self {
        Self { signature, data }
    }
    
    pub fn into_parts(self) -> (TunBufferSignature, &'static mut [u8]) {
        (self.signature, self.data)
    }
}

// 异步TUN接收器
struct AsyncTunReceiver {
    file: tokio::fs::File,
    rx_pool: Arc<Mutex<Vec<Buffer>>>,
    packet_sender: flume::Sender<Buffer>,
}

// 新增：用于共享发送状态的结构体
#[derive(Clone)]
struct TunSenderState {
    tokio_fd: RawFd,
    send_semaphore: Arc<Semaphore>,
}

// macOS TUN实现
pub struct MacOSTun {
    // 文件描述符相关 - file 不再需要，fd 移到 TunSenderState
    // file: Mutex<File>,
    sender_state: Arc<TunSenderState>, // 替换 tokio_fd 和 send_semaphore
    
    // 缓冲区池 (使用本地 TunBufferToken)
    tx_pool: Mutex<Vec<TunBufferToken>>, 
    rx_pool: Arc<Mutex<Vec<Buffer>>>,
    
    // 设备信息
    name: String,
    
    // 多路复用相关
    packet_sender: flume::Sender<Buffer>,
    packet_receiver: flume::Receiver<Buffer>,
    // send_semaphore: Arc<Semaphore>, // 已移到 TunSenderState
}

impl MacOSTun {
    pub fn new() -> io::Result<Arc<Self>> {
        // 使用默认TUN_NAME
        Self::new_with_name(TUN_NAME)
    }
    
    pub fn new_with_name(tun_name: &str) -> io::Result<Arc<Self>> {
        // 创建TUN设备
        let (file, name) = Self::create_tun_device_with_name(tun_name)?;
        
        // 配置接口
        Self::configure_interface(&name)?;
        
        // 获取文件描述符并设置为非阻塞
        let fd = file.as_raw_fd();
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            if flags < 0 {
                // 需要手动关闭 file，因为它不会被包含在 MacOSTun 中自动 Drop
                drop(file);
                return Err(io::Error::last_os_error());
            }
            if libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
                // 需要手动关闭 file
                drop(file);
                return Err(io::Error::last_os_error());
            }
        }
        
        // 忘记 file，因为它的 fd 由 tokio 管理，不能关闭
        mem::forget(file);

        // 创建缓冲区池
        let tx_pool = Mutex::new(Vec::with_capacity(10));
        let rx_pool = Arc::new(Mutex::new(Vec::with_capacity(10)));
        
        // 预分配一些缓冲区
        {
            let mut tx_guard = tx_pool.lock().unwrap();
            for _ in 0..5 {
                tx_guard.push(Self::allocate_tx_buffer());
            }
            
            let mut rx_guard = rx_pool.lock().unwrap();
            for _ in 0..5 {
                rx_guard.push(Vec::with_capacity(BUFFER_SIZE));
            }
        }
        
        // 创建信号量用于控制并发发送
        let send_semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_SENDS));
        
        // 创建 TunSenderState
        let sender_state = Arc::new(TunSenderState {
            tokio_fd: fd,
            send_semaphore,
        });

        // 创建数据包通道
        let (packet_sender, packet_receiver) = flume::unbounded();
        
        // 创建TUN实例
        let tun = Arc::new(Self {
            // file: Mutex::new(file), // 移除
            sender_state: sender_state.clone(),
            tx_pool,
            rx_pool: rx_pool.clone(),
            name,
            packet_sender: packet_sender.clone(),
            packet_receiver,
            // send_semaphore: send_semaphore.clone(), // 移除
        });
        
        // 启动异步读取任务
        let receiver = AsyncTunReceiver {
            // 注意：这里传递 fd 可能不安全，因为 file 已经被 forget
            // 但 tokio::fs::File::from_raw_fd 需要一个有效的 fd
            // 确保 fd 在 MacOSTun 的生命周期内有效
            file: unsafe { tokio::fs::File::from_raw_fd(fd) }, 
            rx_pool: rx_pool.clone(),
            packet_sender,
        };
        
        tokio::spawn(async move {
            if let Err(e) = Self::run_async_receiver(receiver).await {
                eprintln!("❌ 异步接收器错误: {:?}", e);
            }
        });
        
        println!("✅ 创建macOS TUN设备: {}", tun.name);
        Ok(tun)
    }
    
    // 添加获取设备名称的方法
    pub fn get_name(&self) -> &str {
        &self.name
    }
    
    // 添加获取设备IP地址的方法
    pub fn get_address(&self) -> String {
        // 目前固定返回配置的IP地址
        // 可以改进为实际获取系统中的IP地址
        "192.168.42.1".to_string()
    }
    
    // 运行异步接收器
    async fn run_async_receiver(receiver: AsyncTunReceiver) -> io::Result<()> {
        let AsyncTunReceiver { mut file, rx_pool, packet_sender } = receiver;
        
        // 创建读取缓冲区
        let mut read_buf = vec![0u8; BUFFER_SIZE];
        
        loop {
            // 异步读取数据
            match file.read(&mut read_buf).await {
                Ok(n) if n >= 4 => {
                    // 获取一个缓冲区，如果池中没有则创建新的
                    let mut buffer = {
                        let mut pool = rx_pool.lock().unwrap();
                        pool.pop().unwrap_or_else(|| Vec::with_capacity(BUFFER_SIZE))
                    };
                    
                    // 清除旧数据并复制新数据（跳过4字节头部）
                    buffer.clear();
                    buffer.extend_from_slice(&read_buf[4..n]);
                    
                    // 发送到通道
                    if let Err(e) = packet_sender.send(buffer) {
                        eprintln!("❌ 发送数据包到通道失败: {:?}", e);
                        // 如果发送失败，将缓冲区放回池中
                        let mut pool = rx_pool.lock().unwrap();
                        pool.push(e.into_inner());
                    }
                },
                Ok(n) => {
                    println!("⚠️ 收到太小的数据包: {} 字节", n);
                    continue;
                },
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // 没有更多数据，等待一下再试
                    tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
                    continue;
                },
                Err(e) => {
                    eprintln!("❌ 读取TUN错误: {:?}", e);
                    // 对于其他错误，等待一段时间再重试
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    continue;
                }
            }
        }
    }
    
    // 创建TUN设备
    fn create_tun_device() -> io::Result<(File, String)> {
        Self::create_tun_device_with_name(TUN_NAME)
    }
    
    // 创建指定名称的TUN设备
    fn create_tun_device_with_name(tun_name: &str) -> io::Result<(File, String)> {
        // 提取utun号
        let utun_num = match tun_name.strip_prefix("utun") {
            Some(num) => num.parse::<u32>().unwrap_or(5),
            None => 5, // 默认为utun5
        };
        
        // 打开一个socket
        let fd = unsafe {
            libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL)
        };
        
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        
        // 从socket fd创建文件，当丢弃时会关闭
        let socket_file = unsafe { File::from_raw_fd(fd) };
        
        // 控制信息结构
        let mut ctl_info = unsafe { mem::zeroed::<libc::ctl_info>() };
        let ctl_name = CString::new("com.apple.net.utun_control").unwrap();
        
        unsafe {
            ptr::copy_nonoverlapping(
                ctl_name.as_ptr(),
                ctl_info.ctl_name.as_mut_ptr() as *mut i8,
                ctl_name.as_bytes().len(),
            );
            
            // 获取控制ID
            if libc::ioctl(fd, libc::CTLIOCGINFO, &mut ctl_info as *mut _) < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        
        // 连接到控制设备
        let mut sc = unsafe { mem::zeroed::<libc::sockaddr_ctl>() };
        sc.sc_id = ctl_info.ctl_id;
        sc.sc_len = mem::size_of::<libc::sockaddr_ctl>() as u8;
        sc.sc_family = libc::AF_SYSTEM as u8;
        sc.ss_sysaddr = libc::AF_SYS_CONTROL as u16;
        sc.sc_unit = utun_num as u32;  // utun设备号
        
        let addr_ptr = &sc as *const _ as *const libc::sockaddr;
        let result = unsafe {
            libc::connect(
                fd,
                addr_ptr,
                mem::size_of::<libc::sockaddr_ctl>() as u32,
            )
        };
        
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        
        // 获取接口名称
        let mut if_name_buf = [0u8; libc::IFNAMSIZ];
        let mut name_len = if_name_buf.len() as u32;
        let name_ptr = if_name_buf.as_mut_ptr() as *mut libc::c_void;
        
        let result = unsafe {
            libc::getsockopt(
                fd,
                libc::SYSPROTO_CONTROL,
                libc::UTUN_OPT_IFNAME,
                name_ptr,
                &mut name_len as *mut u32,
            )
        };
        
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        
        let if_name = unsafe {
            CStr::from_ptr(if_name_buf.as_ptr() as *const i8)
                .to_string_lossy()
                .into_owned()
        };
        
        println!("✅ 创建TUN设备: {}", if_name);
        
        Ok((socket_file, if_name))
    }
    
    // 配置接口
    fn configure_interface(if_name: &str) -> io::Result<()> {
        // 设置IPv4地址并启用接口
        let status = Command::new("ifconfig")
            .args(&[if_name, "inet", "192.168.42.1", "192.168.42.2", "up"])
            .status()?;
            
        if !status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("配置IPv4失败: {}", if_name),
            ));
        }
        
        // 设置IPv6地址（可选）
        let _ = Command::new("ifconfig")
            .args(&[if_name, "inet6", "fd00::1", "prefixlen", "64"])
            .status();
            
        // 设置MTU
        let status = Command::new("ifconfig")
            .args(&[if_name, "mtu", "1500"])
            .status()?;
            
        if !status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("设置MTU失败: {}", if_name),
            ));
        }
        
        println!("✅ 配置接口 {}: IPv4 192.168.42.1/24, MTU 1500", if_name);
        Ok(())
    }
    
    // 分配TX缓冲区
    fn allocate_tx_buffer() -> TunBufferToken {
        // 分配静态缓冲区
        let buffer = Box::new([0u8; BUFFER_SIZE]);
        let buffer_ptr = Box::into_raw(buffer);
        
        // 使用指针地址生成签名
        let signature = [buffer_ptr as *mut usize, ptr::null_mut()];
        
        // 从缓冲区创建静态切片
        let data = unsafe {
            slice::from_raw_parts_mut(buffer_ptr as *mut u8, BUFFER_SIZE)
        };
        
        // 创建并返回本地令牌
        unsafe { TunBufferToken::new(signature, data) }
    }
    
    // 从池中获取缓冲区
    fn get_buffer_from_pool(&self) -> Option<Buffer> {
        let mut pool = self.rx_pool.lock().unwrap();
        pool.pop().or_else(|| Some(Vec::with_capacity(BUFFER_SIZE)))
    }
    
    // 修改 async_send，接收 sender_state
    async fn async_send(sender_state: Arc<TunSenderState>, buf: TunBufferToken, len: usize) -> io::Result<()> {
        // 获取信号量许可
        let permit = sender_state.send_semaphore.clone().acquire_owned().await.map_err(|_| io::Error::new(io::ErrorKind::Other, "Semaphore closed"))?;
        
        // 创建写入缓冲区
        let mut write_buf = Vec::with_capacity(len + 4);
        let family = if len > 0 && (buf.data[0] >> 4) == 6 {
            libc::AF_INET6
        } else {
            libc::AF_INET
        };
        write_buf.extend_from_slice(&(family as u32).to_be_bytes());
        write_buf.extend_from_slice(&buf.data[..len]);
        
        // 使用原始fd进行写入操作，避免创建tokio::fs::File
        let fd = sender_state.tokio_fd;
        
        // 使用std::io::Write直接写入，而不是异步写入
        // 这里用spawn_blocking包装写入操作，避免阻塞异步任务执行器
        let result = tokio::task::spawn_blocking(move || {
            // 安全地创建临时File，用于写入
            let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
            let write_result = file.write_all(&write_buf);
            // 防止关闭fd
            std::mem::forget(file);
            write_result
        }).await.unwrap_or_else(|e| Err(io::Error::new(io::ErrorKind::Other, format!("Join error: {}", e))));
        
        // 将permit放在这里drop，以确保在整个操作完成后才释放信号量
        drop(permit);
        
        result
    }
}

impl Tun for MacOSTun {
    fn blocking_recv(&self) -> Option<Buffer> {
        // 使用通道接收数据包
        match self.packet_receiver.recv() {
            Ok(buffer) => Some(buffer),
            Err(e) => {
                eprintln!("❌ 从通道接收数据包失败: {:?}", e);
                None
            }
        }
    }
    
    fn return_recv_buffer(&self, buf: Buffer) {
        let mut pool = self.rx_pool.lock().unwrap();
        if pool.len() < 10 { // 限制池大小
            pool.push(buf);
        }
    }
    
    fn get_tx_buffer(&self) -> Option<FlowTunBufferToken> {
        let mut pool = self.tx_pool.lock().unwrap();
        let local_buf = pool.pop().or_else(|| Some(Self::allocate_tx_buffer()));
        
        local_buf.map(|buf| {
            let (signature, data) = buf.into_parts();
            // 安全转换：因为我们拥有数据并且知道生命周期
            unsafe { FlowTunBufferToken::new(signature, data) }
        })
    }
    
    // 接收 flow::TunBufferToken
    fn send(&self, buf: FlowTunBufferToken, len: usize) -> Result<(), io::Error> {
        if len > buf.data.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("缓冲区长度 {} 超过最大值 {}", len, buf.data.len())
            ));
        }
        
        let (signature, data) = buf.into_parts();
        let local_buf = unsafe { TunBufferToken::new(signature, data) }; 

        let state_clone = self.sender_state.clone();
        
        // 先尝试简单的同步写入方式
        let family = if len > 0 && (local_buf.data[0] >> 4) == 6 {
            libc::AF_INET6
        } else {
            libc::AF_INET
        };
        
        // 创建写入缓冲区
        let mut write_buf = Vec::with_capacity(len + 4);
        write_buf.extend_from_slice(&(family as u32).to_be_bytes());
        write_buf.extend_from_slice(&local_buf.data[..len]);
        
        // 直接执行同步写入操作
        unsafe {
            let fd = state_clone.tokio_fd;
            let bytes_written = libc::write(
                fd, 
                write_buf.as_ptr() as *const libc::c_void, 
                write_buf.len()
            );
            
            if bytes_written < 0 {
                let err = io::Error::last_os_error();
                // WouldBlock或Interrupted错误需要重试
                if err.kind() == io::ErrorKind::WouldBlock || err.kind() == io::ErrorKind::Interrupted {
                    // 当直接写入失败时，退回到异步模式
                    return tokio::task::block_in_place(move || {
                        SEND_RUNTIME.block_on(MacOSTun::async_send(state_clone, local_buf, len))
                    });
                }
                return Err(err);
            }
            
            if bytes_written as usize != write_buf.len() {
                // 部分写入，这种情况很少见，但如果发生，我们也退回到异步模式
                return tokio::task::block_in_place(move || {
                    SEND_RUNTIME.block_on(MacOSTun::async_send(state_clone, local_buf, len))
                });
            }
            
            // 成功完成写入
            Ok(())
        }
    }
    
    fn return_tx_buffer(&self, buf: FlowTunBufferToken) {
        // 将 flow::TunBufferToken 转换回本地 TunBufferToken 以放回池中
        let (signature, data) = buf.into_parts();
        // 安全转换：我们将所有权转交给池
        let local_buf = unsafe { TunBufferToken::new(signature, data) }; 
        
        let mut pool = self.tx_pool.lock().unwrap();
        if pool.len() < 10 { 
            pool.push(local_buf);
        } else {
            // 释放缓冲区避免内存泄漏
            let (signature, _) = local_buf.into_parts();
            unsafe {
                let ptr = signature[0] as *mut [u8; BUFFER_SIZE];
                if !ptr.is_null() {
                    drop(Box::from_raw(ptr));
                }
            }
        }
    }
}

impl Drop for MacOSTun {
    fn drop(&mut self) {
        println!("🔄 清理TUN设备: {}", self.name);
        
        // 关闭发送端，通知接收任务退出
        // 注意：packet_sender 的 drop 会自动关闭通道

        // 释放所有TX缓冲区
        let mut tx_pool = self.tx_pool.lock().unwrap();
        while let Some(buf) = tx_pool.pop() {
            let (signature, _) = buf.into_parts();
            unsafe {
                let ptr = signature[0] as *mut [u8; BUFFER_SIZE];
                if !ptr.is_null() {
                    drop(Box::from_raw(ptr));
                }
            }
        }
        
        // 尝试关闭接口 (tokio_fd 现在由 sender_state 管理，其 Arc 引用计数减少时会自动处理？)
        // 需要确保 fd 在所有使用者都释放后被关闭
        // 这里的 File 已经被 forget，所以不能在这里关闭。
        // fd 的关闭依赖于 tokio::fs::File 的 Drop，以及 sender_state 的 Drop
        // 可能需要更精细的生命周期管理来确保 fd 被正确关闭一次
        // 暂时依赖 Arc 计数和 tokio::fs::File 的 Drop 行为
        
        // 运行 ifconfig down 命令仍然是有意义的
        let _ = Command::new("ifconfig")
            .args(&[&self.name, "down"])
            .status();
    }
}
