use crate::flow::{Buffer, TunBufferToken, TunBufferSignature, Tun};
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;
use std::io::{self, Result as IoResult};
use std::process::Command;
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex as TokioMutex;
use std::path::PathBuf;
use tun::AbstractDevice;
// MacTun设备类型，使用tokio进行异步操作
pub struct MacTun {
    // 内部tun设备实例
    device: Arc<TokioMutex<tun::AsyncDevice>>,
    // 设备名称
    name: String,
    // 设备IP地址
    address: Ipv4Addr,
    // 网络掩码
    netmask: Ipv4Addr,
    // 原始路由信息用于恢复
    original_routes: Arc<Mutex<OriginalRoutes>>,
    // 用于共享状态的队列
    recv_queue: Arc<Mutex<VecDeque<Buffer>>>,
    buffer_pool: Arc<Mutex<VecDeque<Buffer>>>,
    // 接收和发送缓冲区的大小
    mtu: usize,
}

// 存储原始路由信息的结构
struct OriginalRoutes {
    default_gateway: Option<(String, String)>, // (网关IP, 接口名)
}

impl OriginalRoutes {
    // 保存当前系统路由
    fn backup() -> Self {
        let output = Command::new("netstat")
            .arg("-nr")
            .output()
            .unwrap_or_else(|_| panic!("无法执行netstat命令"));

        let routes = String::from_utf8_lossy(&output.stdout);

        // macOS路由表格式: default  192.168.1.1    UGSc   en0
        let default_gateway = routes.lines()
            .find(|line| line.contains("default"))
            .and_then(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    // 提取网关IP和接口名
                    Some((parts[1].to_string(), parts[parts.len()-1].to_string()))
                } else {
                    None
                }
            });

        OriginalRoutes {
            default_gateway
        }
    }

    // 恢复原始路由
    fn restore(&self) {
        // 移除添加的路由
        let _ = Command::new("route")
            .arg("-n")
            .arg("delete")
            .arg("-net")
            .arg("0.0.0.0/1")
            .output();

        let _ = Command::new("route")
            .arg("-n")
            .arg("delete")
            .arg("-net")
            .arg("128.0.0.0/1")
            .output();

        // 恢复原始默认路由
        if let Some((gateway, _)) = &self.default_gateway {
            let _ = Command::new("route")
                .arg("-n")
                .arg("add")
                .arg("default")
                .arg(gateway)
                .output();
        }
    }
}

impl MacTun {
    /// 创建并初始化MacTun设备
    pub async fn new(
        name: &str, 
        address: Ipv4Addr, 
        netmask: Ipv4Addr,
        mtu: Option<usize>
    ) -> IoResult<Self> {
        // 备份当前路由配置
        let original_routes = Arc::new(Mutex::new(OriginalRoutes::backup()));
        
        // 创建TUN设备配置
        let mut config = tun::Configuration::default();
        config
            .tun_name(name)
            .address(address)
            .netmask(netmask)
            .mtu(mtu.unwrap_or(1500) as u16) // 修复: 将usize转换为u16
            .up();

        // 创建TUN设备
        let device = tun::create_as_async(&config)?;
        // 获取实际设备名称，根据tun库API调整
        let actual_name = device.tun_name().unwrap_or_else(|_| name.to_string());

        let mtu_val = mtu.unwrap_or(1500);
        
        // 创建MacTun实例
        let mac_tun = Self {
            device: Arc::new(TokioMutex::new(device)),
            name: actual_name,
            address,
            netmask,
            original_routes,
            recv_queue: Arc::new(Mutex::new(VecDeque::new())),
            buffer_pool: Arc::new(Mutex::new(VecDeque::new())),
            mtu: mtu_val,
        };

        // 配置路由
        mac_tun.configure_routing()?;
        
        // 启动接收数据包的后台任务
        mac_tun.start_packet_receiver();
        
        Ok(mac_tun)
    }

    /// 启动后台任务接收数据包
    fn start_packet_receiver(&self) {
        let recv_queue = self.recv_queue.clone();
        let buffer_pool = self.buffer_pool.clone();
        let device = self.device.clone();
        let mtu = self.mtu;
        
        tokio::spawn(async move {
            let mut read_buf = vec![0u8; mtu];
            let device = device.clone();
            
            loop {
                // 获取锁
                let mut device_lock = device.lock().await;
                
                match device_lock.read(&mut read_buf).await {
                    Ok(n) if n > 0 => {
                        // 从缓冲池中获取缓冲区或创建新的
                        let mut buffer = match buffer_pool.lock().unwrap().pop_front() {
                            Some(buffer) => buffer,
                            None => Buffer::new(),
                        };
                        
                        // 调整大小并复制数据
                        buffer.resize(n, 0);
                        buffer[..n].copy_from_slice(&read_buf[..n]);
                        
                        // 将数据包加入接收队列
                        recv_queue.lock().unwrap().push_back(buffer);
                    },
                    Err(e) => {
                        eprintln!("读取TUN设备错误: {}", e);
                        break;
                    },
                    _ => {}
                }
                
                // 释放锁，避免长时间持有
                drop(device_lock);
            }
        });
    }

    /// 配置系统路由表
    fn configure_routing(&self) -> IoResult<()> {
        // 配置路由，将所有流量引导到TUN设备
        // 使用0.0.0.0/1和128.0.0.0/1组合表示所有IP地址
        let _ = Command::new("route")
            .arg("-n")
            .arg("add")
            .arg("-net")
            .arg("0.0.0.0/1")
            .arg("-interface")
            .arg(&self.name)
            .output()?;

        let _ = Command::new("route")
            .arg("-n")
            .arg("add")
            .arg("-net")
            .arg("128.0.0.0/1")
            .arg("-interface")
            .arg(&self.name)
            .output()?;

        Ok(())
    }

    /// 清理路由配置
    pub fn cleanup_routing(&self) -> IoResult<()> {
        self.original_routes.lock().unwrap().restore();
        Ok(())
    }

    /// 获取TUN设备名称
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// 获取TUN设备IP地址
    pub fn get_address(&self) -> Ipv4Addr {
        self.address
    }

    /// 获取原始默认网关
    pub fn get_default_gateway(&self) -> Option<String> {
        self.original_routes.lock().unwrap()
            .default_gateway
            .as_ref()
            .map(|(gateway, _)| gateway.clone())
    }

    /// 为指定目标添加直接路由（绕过TUN设备）
    pub fn add_direct_route(&self, dest: &str) -> IoResult<()> {
        if let Some((gateway, _)) = &self.original_routes.lock().unwrap().default_gateway {
            Command::new("route")
                .arg("-n")
                .arg("add")
                .arg(dest)
                .arg("-gateway")
                .arg(gateway)
                .output()?;
        }
        Ok(())
    }
}

impl Tun for MacTun {
    fn blocking_recv(&self) -> Option<Buffer> {
        self.recv_queue.lock().unwrap().pop_front()
    }
    
    fn return_recv_buffer(&self, buf: Buffer) {
        // 将缓冲区放回池中以便重用
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
        
        // 安全性：我们确保签名可以安全地发送到其他线程
        unsafe {
            Some(TunBufferToken::new(signature, static_slice))
        }
    }
    
    fn send(&self, buf: TunBufferToken, len: usize) {
        let (signature, data) = buf.into_parts();
        
        // 获取临时数据的副本
        let data_to_send = data[..len].to_vec();
        
        // 先释放原始缓冲区，避免在异步任务中使用原始指针
        unsafe {
            let data_ptr = signature[0] as *mut Vec<u8>;
            if !data_ptr.is_null() {
                drop(Box::from_raw(data_ptr));
            }
        }
        
        // 使用tokio运行时发送数据副本
        let device = self.device.clone();
        tokio::spawn(async move {
            let mut device_guard = device.lock().await;
            if let Err(e) = device_guard.write(&data_to_send).await {
                eprintln!("写入TUN设备错误: {}", e);
            }
        });
    }
    
    fn return_tx_buffer(&self, buf: TunBufferToken) {
        // 释放缓冲区
        unsafe {
            let (signature, _) = buf.into_parts();
            let data_ptr = signature[0] as *mut Vec<u8>;
            if !data_ptr.is_null() {
                drop(Box::from_raw(data_ptr));
            }
        }
    }
}

impl Drop for MacTun {
    fn drop(&mut self) {
        // 尝试清理路由配置
        if let Err(e) = self.cleanup_routing() {
            eprintln!("清理路由失败: {}", e);
        }
    }
}