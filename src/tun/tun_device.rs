use crate::flow::{Buffer, TunBufferToken, TunBufferSignature, Tun};
use std::sync::{Arc, RwLock, atomic::{AtomicBool, Ordering}};
use std::io::{self, Read, Write, Result as IoResult};
use std::process::Command;
use std::net::{Ipv4Addr, Ipv6Addr};
use tun::{Device as TunDevicePlatform};
use log::{info, error, warn, debug};
use std::os::unix::io::{AsRawFd, RawFd};
use std::time::{Duration};
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::poll::{poll, PollFd, PollFlags};
use tun::AbstractDevice;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::runtime::{Runtime, Builder};
use std::thread;
use futures::executor;

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

// 辅助函数：等待文件描述符可读
fn wait_readable(fd: RawFd, timeout_ms: u64) -> bool {
    let mut fds = [PollFd::new(fd, PollFlags::POLLIN)];
    match poll(&mut fds, timeout_ms as i32) {
        Ok(n) if n > 0 => true,
        _ => false,
    }
}

// 辅助函数：等待文件描述符可写
fn wait_writable(fd: RawFd, timeout_ms: u64) -> bool {
    let mut fds = [PollFd::new(fd, PollFlags::POLLOUT)];
    match poll(&mut fds, timeout_ms as i32) {
        Ok(n) if n > 0 => true,
        _ => false,
    }
}

// 用于发送数据的任务结构，使用oneshot通道
struct TxTask {
    data: Vec<u8>,
    response_sender: oneshot::Sender<Result<(), io::Error>>,
}

pub struct MacTun {
    device: Arc<RwLock<TunDevicePlatform>>,
    name: String,
    address: Ipv4Addr,
    address_v6: Option<Ipv6Addr>,
    netmask: Ipv4Addr,
    fd: RawFd,
    mtu: usize,
    max_lock_time: u64,
    // 使用 Mutex 包装 Receiver，允许通过不可变引用修改
    rx_receiver: Mutex<mpsc::Receiver<Buffer>>,
    // 用于提交 TUN 发送任务的异步通道
    tx_sender: mpsc::Sender<TxTask>,
    // 不再内部维护运行时，而是使用外部提供的运行时句柄
    runtime_handle: tokio::runtime::Handle,
    // 添加关闭标志
    shutdown_flag: Arc<AtomicBool>,
    // 关闭通道
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl MacTun {
    /// 创建并初始化 MacTun 设备，接收一个外部运行时句柄
    pub fn new(
        name: &str, 
        address: Ipv4Addr,
        netmask: Ipv4Addr,
        mtu: Option<usize>,
        runtime_handle: tokio::runtime::Handle
    ) -> IoResult<Self> {
        let address_v6 = None;
        let mtu_val = mtu.unwrap_or(1500);

        // 创建 TUN 设备配置
        let mut config = tun::Configuration::default();
        config
            .tun_name(name)
            .address(address)
            .netmask(netmask)
            .mtu(mtu_val as u16)
            .up();

        // 创建 TUN 设备
        let device = tun::create(&config)?;
        let fd = device.as_raw_fd();
        set_non_blocking(fd)?;

        let actual_name = device.tun_name().unwrap_or_else(|_| name.to_string());

        // 如果支持IPv6，进行配置
        if let Some(ipv6_addr) = &address_v6 {
            configure_ipv6(&actual_name, ipv6_addr)?;
        }

        let device = Arc::new(RwLock::new(device));

        // 创建tokio的通道，提高并发性能
        let (rx_sender, rx_receiver) = mpsc::channel::<Buffer>(1000); // 增大缓冲区大小
        let (tx_sender, mut tx_receiver) = mpsc::channel::<TxTask>(1000); // 增大缓冲区大小
        
        // 创建关闭信号通道
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        let shutdown_flag = Arc::new(AtomicBool::new(false));

        // 使用 Mutex 包装接收器
        let rx_receiver = Mutex::new(rx_receiver);

        // 克隆需要在线程中使用的设备指针和运行时
        let device_clone_for_rx = Arc::clone(&device);
        let runtime_handle_clone = runtime_handle.clone();
        let fd_for_rx = fd;
        let shutdown_flag_clone = Arc::clone(&shutdown_flag);
        
        // 启动 TUN 读取线程
        thread::spawn(move || {
            // 使用专用的线程在运行时上下文外执行阻塞操作
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Failed to create thread-local runtime");
            
            rt.block_on(async move {
                loop {
                    // 检查关闭标志
                    if shutdown_flag_clone.load(Ordering::SeqCst) {
                        debug!("读取线程检测到关闭信号，退出");
                        break;
                    }
                    
                    // 使用tokio::select来同时监听关闭信号和处理常规逻辑
                    tokio::select! {
                        _ = shutdown_rx.recv() => {
                            debug!("读取线程接收到关闭信号，退出");
                            break;
                        }
                        _ = async {
                            // 分配一个缓冲区
                            let mut buf = vec![0u8; mtu_val];
                            
                            // 等待可读
                            if !wait_readable(fd_for_rx, 100) {
                                tokio::time::sleep(Duration::from_millis(5)).await;
                                return;
                            }

                            // 读取数据
                            let n = {
                                // 锁定设备进行读取操作
                                let mut dev = match device_clone_for_rx.write() {
                                    Ok(guard) => guard,
                                    Err(e) => {
                                        error!("读取线程获取设备锁失败: {:?}", e);
                                        tokio::time::sleep(Duration::from_millis(10)).await;
                                        return;
                                    }
                                };

                                match dev.read(&mut buf) {
                                    Ok(n) if n > 0 => n,
                                    Ok(_) => return, // 读到0字节则忽略
                                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                                        tokio::time::sleep(Duration::from_millis(1)).await;
                                        return;
                                    }
                                    Err(e) => {
                                        error!("读取TUN设备错误: {:?}", e);
                                        tokio::time::sleep(Duration::from_millis(100)).await;
                                        return;
                                    }
                                }
                            };

                            buf.resize(n, 0);
                            // 使用异步发送，避免阻塞
                            if rx_sender.send(Buffer::from(buf)).await.is_err() {
                                error!("读取线程：接收者已断开，退出读取线程");
                                return;
                            }
                        } => {}
                    }
                }
                debug!("读取线程已退出");
            });
        });

        // 克隆设备到发送线程中使用
        let device_clone_for_tx = Arc::clone(&device);
        let runtime_handle_clone_tx = runtime_handle.clone();
        let fd_for_tx = fd;
        let shutdown_flag_clone_tx = Arc::clone(&shutdown_flag);
        
        // 启动 TUN 写入线程，使用tokio异步处理
        thread::spawn(move || {
            // 同样使用专用的线程本地运行时
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Failed to create thread-local runtime");
                
            rt.block_on(async move {
                loop {
                    // 检查关闭标志
                    if shutdown_flag_clone_tx.load(Ordering::SeqCst) {
                        debug!("写入线程检测到关闭信号，退出");
                        break;
                    }
                    
                    // 等待任务或关闭信号
                    let task = tokio::select! {
                        Some(task) = tx_receiver.recv() => task,
                        else => {
                            // 如果通道已关闭或收到关闭信号，退出循环
                            debug!("写入线程：发送通道已关闭，退出");
                            break;
                        }
                    };
                    
                    if !wait_writable(fd_for_tx, 100) {
                        let _ = task.response_sender.send(Err(io::Error::new(
                            io::ErrorKind::WouldBlock, 
                            "TUN设备写入超时"
                        )));
                        continue;
                    }
                    
                    let result = {
                        let mut dev = match device_clone_for_tx.write() {
                            Ok(guard) => guard,
                            Err(e) => {
                                let _ = task.response_sender.send(Err(io::Error::new(
                                    io::ErrorKind::Other, 
                                    format!("设备锁错误: {:?}", e)
                                )));
                                continue;
                            }
                        };
                        
                        // 循环写入直到完成或出错
                        let mut result = Ok(());
                        let mut remaining_data = &task.data[..];
                        
                        while !remaining_data.is_empty() {
                            match dev.write(remaining_data) {
                                Ok(0) => {
                                    result = Err(io::Error::new(
                                        io::ErrorKind::WriteZero, 
                                        "写入0字节，设备可能不接受数据"
                                    ));
                                    break;
                                }
                                Ok(written) => {
                                    remaining_data = &remaining_data[written..];
                                    if remaining_data.is_empty() {
                                        let _ = dev.flush();
                                        break;
                                    }
                                }
                                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                                    // 释放锁，避免长时间持有
                                    drop(dev);
                                    
                                    // 异步等待可写
                                    if !wait_writable(fd_for_tx, 100) {
                                        result = Err(io::Error::new(
                                            io::ErrorKind::TimedOut, 
                                            "写入超时"
                                        ));
                                        break;
                                    }
                                    
                                    // 重新获取锁
                                    dev = match device_clone_for_tx.write() {
                                        Ok(guard) => guard,
                                        Err(e) => {
                                            result = Err(io::Error::new(
                                                io::ErrorKind::Other, 
                                                format!("重新获取设备锁失败: {:?}", e)
                                            ));
                                            break;
                                        }
                                    };
                                    continue;
                                }
                                Err(e) => {
                                    result = Err(e);
                                    break;
                                }
                            }
                        }
                        
                        result
                    };
                    
                    // 通过oneshot通道反馈结果
                    let _ = task.response_sender.send(result);
                }
                debug!("写入线程已退出");
            });
        });

        Ok(MacTun {
            device,
            name: actual_name,
            address,
            address_v6,
            netmask,
            fd,
            mtu: mtu_val,
            max_lock_time: 100,
            rx_receiver,
            tx_sender,
            runtime_handle,
            shutdown_flag,
            shutdown_tx: Some(shutdown_tx),
        })
    }

    /// 获取 TUN 设备名称
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// 获取 TUN 设备 IP 地址
    pub fn get_address(&self) -> Ipv4Addr {
        self.address
    }
    
    /// 关闭TUN设备及相关资源
    pub fn shutdown(&self) {
        info!("正在关闭TUN设备: {}", self.get_name());
        
        // 设置关闭标志，让读写线程可以主动检测到关闭请求
        self.shutdown_flag.store(true, Ordering::SeqCst);
        
        // 发送关闭信号到读取线程
        if let Some(shutdown_tx) = &self.shutdown_tx {
            if let Err(e) = shutdown_tx.try_send(()) {
                error!("发送关闭信号失败: {:?}", e);
            } else {
                debug!("已发送关闭信号到读写线程");
            }
        }
        
        // 关闭设备文件描述符
        if let Ok(mut device) = self.device.write() {
            // 强制关闭底层文件描述符
            unsafe {
                let fd = device.as_raw_fd();
                // 使用nix关闭文件描述符
                if let Err(e) = nix::unistd::close(fd) {
                    error!("关闭TUN设备文件描述符时出错: {:?}", e);
                } else {
                    info!("成功关闭TUN设备文件描述符");
                }
            }
        } else {
            error!("无法获取TUN设备锁进行关闭");
        }
        
        info!("TUN设备资源已释放: {}", self.get_name());
    }
}

impl Tun for MacTun {
    /// 从内部接收通道阻塞读取一个 Buffer
    fn blocking_recv(&self) -> Option<Buffer> {
        // 检查设备是否已关闭
        if self.shutdown_flag.load(Ordering::SeqCst) {
            return None;
        }
        
        // 使用已有的运行时句柄来执行异步操作
        let rt_handle = self.runtime_handle.clone();
        
        // 在当前线程上下文中执行异步操作
        executor::block_on(async move {
            // 锁定接收器
            let mut rx = self.rx_receiver.lock().await;
            match rx.recv().await {
                Some(buffer) => Some(buffer),
                None => {
                    error!("接收通道已关闭");
                    None
                }
            }
        })
    }
    /// 对于接收缓冲区，采用自动回收（这里无需额外处理）
    fn return_recv_buffer(&self, _buf: Buffer) {
        debug!("🐶MACTUN: 接收缓冲区自动回收");
        // 不需要手动归还，由读取线程自动分配
    }

    /// 分配一个用于发送数据的缓冲区
    fn get_tx_buffer(&self) -> Option<TunBufferToken> {
        // 检查设备是否已关闭
        if self.shutdown_flag.load(Ordering::SeqCst) {
            return None;
        }
        
        // 为了与原接口保持兼容，我们分配一个大小为 mtu 的 Box<Vec<u8>>
        let boxed_buf = Box::new(vec![0u8; self.mtu]);
        // 这里构造一个 signature，保存缓冲区的指针，后续在 send() 中用来恢复 Vec<u8>
        let data_ptr = Box::into_raw(boxed_buf);
        let static_slice = unsafe {
            std::slice::from_raw_parts_mut((*data_ptr).as_mut_ptr(), self.mtu)
        };
        let signature = [data_ptr as *mut usize, std::ptr::null_mut()];
        debug!("🐶MACTUN: 创建发送缓冲区，大小: {}", self.mtu);
        // 返回 token
        unsafe { Some(TunBufferToken::new(signature, static_slice)) }
    }

    /// 发送数据，提取 token 中的数据，使用oneshot通道等待结果
    fn send(&self, buf: TunBufferToken, len: usize) -> Result<(), io::Error> {
        // 检查设备是否已关闭
        if self.shutdown_flag.load(Ordering::SeqCst) {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "TUN设备已关闭"));
        }
        
        let (signature, data) = buf.into_parts();
        let data_ptr = signature[0] as *mut Vec<u8>;
        if data_ptr.is_null() {
            return Err(io::Error::new(io::ErrorKind::Other, "无效的发送缓冲区"));
        }
        
        let boxed_buf = unsafe { Box::from_raw(data_ptr) };
        let data_vec = boxed_buf[..len].to_vec();
        
        // 创建oneshot通道用于等待结果
        let (resp_tx, resp_rx) = oneshot::channel();
        
        // 发送任务
        let send_result = self.tx_sender.try_send(TxTask {
            data: data_vec,
            response_sender: resp_tx,
        });
        
        if let Err(e) = send_result {
            return match e {
                tokio::sync::mpsc::error::TrySendError::Full(_) => {
                    Err(io::Error::new(io::ErrorKind::WouldBlock, "发送队列已满"))
                }
                tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                    Err(io::Error::new(io::ErrorKind::Other, "发送通道已关闭"))
                }
            };
        }
        
        // 使用 futures::executor::block_on 来等待结果
        match futures::executor::block_on(resp_rx) {
            Ok(result) => result,
            Err(_) => Err(io::Error::new(io::ErrorKind::Other, "接收结果失败，发送方已关闭"))
        }
    }


    /// 对发送缓冲区的归还，由于已交由发送线程处理，此处直接忽略即可
    fn return_tx_buffer(&self, _buf: TunBufferToken) {
        debug!("TUN: 发送缓冲区归还（新模型中无操作）");
        // 缓冲区已通过 send() 交由任务处理，无需额外归还
    }
}