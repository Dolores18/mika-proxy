use crate::flow::{Buffer, TunBufferToken, TunBufferSignature, Tun};
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;
use std::io::{self, Result as IoResult, Read, Write};
use std::process::Command;
use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};
use std::path::PathBuf;
use tun::AbstractDevice;
use smoltcp::phy::TxToken as SmolTxToken;
use log::info;
use std::sync::mpsc::{self, Sender, Receiver};
use std::thread;
use std::time::Instant;

// 定义写入任务结构体
struct WriteTask {
    data: Vec<u8>,
    len: usize,
    created_time: Instant,
}

// MacTun设备类型，使用同步设备
pub struct MacTun {
    // 内部tun设备实例，改为同步设备
    device: Arc<Mutex<tun::Device>>,
    // 设备名称
    name: String,
    // 设备IP地址
    address: Ipv4Addr,
    // IPv6地址
    address_v6: Option<Ipv6Addr>,
    // 网络掩码
    netmask: Ipv4Addr,
    // 原始路由信息用于恢复
    original_routes: Arc<Mutex<OriginalRoutes>>,
    // 用于共享状态的队列
    buffer_pool: Arc<Mutex<VecDeque<Buffer>>>,
    // 接收和发送缓冲区的大小
    mtu: usize,
    // 写入任务发送通道
    writer_tx: Sender<WriteTask>,
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
    pub fn new(
        name: &str, 
        address: Ipv4Addr,  // 使用传入的IP地址
        netmask: Ipv4Addr,  // 使用传入的网络掩码
        mtu: Option<usize>
    ) -> IoResult<Self> {
        // 使用传入的IP地址和掩码
        // 禁用IPv6，防止系统发送自动配置和路由公告包
        let address_v6 = None; // 之前是: Some("fd00::2".parse::<Ipv6Addr>().expect("无效的IPv6地址"))
        
        // 备份当前路由配置
        let original_routes = Arc::new(Mutex::new(OriginalRoutes::backup()));
        
        // 创建TUN设备配置
        let mut config = tun::Configuration::default();
        config
            .tun_name(name)
            .address(address)
            .netmask(netmask)
            .mtu(mtu.unwrap_or(1500) as u16)
            .up();
            
        // 创建同步TUN设备
        let device = tun::create(&config)?;
        // 获取实际设备名称
        let actual_name = device.tun_name().unwrap_or_else(|_| name.to_string());

        let mtu_val = mtu.unwrap_or(1500);
        
        // 创建TUN设备共享实例
        let device_arc = Arc::new(Mutex::new(device));
        
        // 创建写入线程的通道
        let (tx, rx) = mpsc::channel::<WriteTask>();
        let rx = Arc::new(Mutex::new(rx));
        
        // 创建4个写入工作线程
        let worker_count = 4;
        for id in 0..worker_count {
            let device_clone = device_arc.clone();
            let rx_clone = rx.clone();
            
            // 启动工作线程
            thread::spawn(move || {
                MacTun::writer_thread(id, device_clone, rx_clone);
            });
        }
        
        println!("✅ TUN设备写入线程池已启动，共 {} 个工作线程", worker_count);
        
        // 创建MacTun实例
        let mac_tun = Self {
            device: device_arc,
            name: actual_name,
            address,
            address_v6,
            netmask,
            original_routes,
            buffer_pool: Arc::new(Mutex::new(VecDeque::new())),
            mtu: mtu_val,
            writer_tx: tx,
        };

        // 配置路由
        mac_tun.configure_routing()?;
        
        // 如果支持IPv6，使用ifconfig命令手动配置
        if let Some(ipv6_addr) = &mac_tun.address_v6 {
            println!("配置IPv6地址: {}", ipv6_addr);
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
    
    // 写入工作线程函数
    fn writer_thread(
        id: u32,
        device: Arc<Mutex<tun::Device>>,
        rx: Arc<Mutex<mpsc::Receiver<WriteTask>>>,
    ) {
        println!("🧵 TUN写入工作线程 #{} 已启动", id);
        
        // 持续处理写入任务
        while let Ok(rx_guard) = rx.lock() {
            match rx_guard.recv() {
                Ok(task) => {
                    // 释放锁
                    drop(rx_guard);
                    
                    // 计算任务在队列中等待的时间
                    let queue_time = task.created_time.elapsed();
                    
                    // 开始写入任务计时
                    let write_start = Instant::now();
                    
                    // 同步写入数据到TUN设备
                    let write_result = {
                        let mut device_guard = device.lock().unwrap();
                        device_guard.write(&task.data)
                    };
                    
                    // 计算写入耗时
                    let write_time = write_start.elapsed();
                    
                    // 处理写入结果
                    match write_result {
                        Ok(n) => {
                            println!("✅ 线程#{}: TUN写入成功: {} 字节, 队列耗时: {:?}, 写入耗时: {:?}", 
                                     id, n, queue_time, write_time);
                            if n != task.len {
                                println!("⚠️ 线程#{}: 警告: 写入字节数({})与请求字节数({})不一致", 
                                         id, n, task.len);
                            }
                        },
                        Err(e) => {
                            eprintln!("❌ 线程#{}: TUN写入失败: {}, 队列耗时: {:?}, 写入耗时: {:?}", 
                                      id, e, queue_time, write_time);
                        }
                    }
                },
                Err(_) => {
                    break;
                }
            }
        }
        
        println!("🧵 TUN写入工作线程 #{} 已终止", id);
    }

    /// 执行路由命令并处理结果
    fn execute_route_cmd(&self, action: &str, target: &str, interface: Option<&str>) -> IoResult<()> {
        let mut cmd = Command::new("route");
        cmd.arg("-n").arg(action);
        
        // 根据目标格式决定是否添加-net参数
        if target.contains("/") {
            cmd.arg("-net");
        }
        
        cmd.arg(target);
        
        // 对于添加操作，如果提供了接口则使用接口路由
        if action == "add" && interface.is_some() {
            cmd.arg("-interface").arg(interface.unwrap());
        }
        
        let result = cmd.output();
        
        match result {
            Ok(output) => {
                if output.status.success() {
                    println!("✅ 成功{}路由: {}", if action == "add" { "添加" } else { "删除" }, target);
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    eprintln!("⚠️ {}路由 {} 时出现问题: {}", 
                             if action == "add" { "添加" } else { "删除" }, 
                             target, stderr);
                }
                Ok(())
            },
            Err(e) => {
                eprintln!("⚠️ 执行route {}命令失败: {}", action, e);
                Err(e)
            }
        }
    }
    
    /// 添加路由
    fn add_route(&self, target: &str, use_interface: bool) -> IoResult<()> {
        if use_interface {
            self.execute_route_cmd("add", target, Some(&self.name))
        } else {
            self.execute_route_cmd("add", target, None)
        }
    }
    
    /// 删除路由
    fn delete_route(&self, target: &str) -> IoResult<()> {
        self.execute_route_cmd("delete", target, None)
    }

    /// 配置系统路由表 - 删除所有路由配置逻辑
    fn configure_routing(&self) -> IoResult<()> {
        // 不再配置任何路由
        println!("路由配置已禁用，不再添加任何路由规则");
        Ok(())
    }

    /// 清理路由配置 - 删除所有清理逻辑
    pub fn cleanup_routing(&self) -> IoResult<()> {
        // 不再清理任何路由
        println!("路由清理已禁用");
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

    /// 为指定目标添加直接路由（绕过TUN设备）- 删除此功能
    pub fn add_direct_route(&self, _dest: &str) -> IoResult<()> {
        // 不再添加任何直接路由
        println!("直接路由功能已禁用");
        Ok(())
    }
}

impl Tun for MacTun {
    fn blocking_recv(&self) -> Option<Buffer> {
        // 创建一个缓冲区来存储数据
        let mut buffer = Buffer::new();
        buffer.resize(self.mtu, 0);
        
        // 从设备读取数据
        let read_result = {
            // 获取设备引用并保持足够长
            let mut device_guard = self.device.lock().unwrap();
            // 使用Read trait的方法读取数据
            device_guard.read(&mut buffer)
        };
        
        match read_result {
            Ok(n) if n > 0 => {
                // 调整缓冲区大小为实际读取的数据量
                buffer.resize(n, 0);
                
                // 分析IP包详情
                if buffer.len() >= 20 {  // 至少需要IP头部
                    let version = buffer[0] >> 4;
                    let ihl = if version == 4 { (buffer[0] & 0x0F) * 4 } else { 0 };  // IP头部长度(4字节单位)
                    
                    if version == 4 && buffer.len() >= ihl as usize {  // IPv4
                        let protocol = buffer[9];
                        let src_ip = format!("{}.{}.{}.{}", buffer[12], buffer[13], buffer[14], buffer[15]);
                        let dst_ip = format!("{}.{}.{}.{}", buffer[16], buffer[17], buffer[18], buffer[19]);
                        
                        let proto_name = match protocol {
                            1 => "ICMP",
                            6 => "TCP",
                            17 => "UDP",
                            _ => "未知"
                        };
                        
                        info!("📦 接收IP包: IPv4, 协议: {}({}), 源IP: {}, 目标IP: {}",
                                proto_name, protocol, src_ip, dst_ip);
                        
                        // 如果是TCP/UDP，尝试打印端口信息
                        if (protocol == 6 || protocol == 17) && buffer.len() >= (ihl + 4) as usize {
                            let src_port = (buffer[ihl as usize] as u16) << 8 | buffer[(ihl+1) as usize] as u16;
                            let dst_port = (buffer[(ihl+2) as usize] as u16) << 8 | buffer[(ihl+3) as usize] as u16;
                            info!("📦 接收端口: 源端口: {}, 目标端口: {}", src_port, dst_port);
                        }
                        
                        info!("TUN设备接收: IP版本: {}, 协议: {}, 长度: {}", 
                                version, protocol, buffer.len());
                    } else if version == 6 && buffer.len() >= 40 {  // IPv6
                        let next_header = buffer[6];
                        // 简化的IPv6地址打印
                        info!("📦 接收IP包: IPv6, 下一头部: {}", next_header);
                        
                        info!("🐶MACTUN: IP版本: {}, 协议: {}, 长度: {}", 
                                version, next_header, buffer.len());
                    } else {
                        info!("🐶MACTUN: IP版本: {}, 长度: {}", version, buffer.len());
                    }
                } else {
                    info!("🐶MACTUN: 数据包太小，无法解析IP头");
                }
                
                info!("🐶MACTUN: 收到数据包，长度: {}", buffer.len());
                Some(buffer)
            },
            Err(e) => {
                eprintln!("读取TUN设备错误: {}", e);
                None
            },
            _ => None
        }
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
        println!("🍓MACTUN: 发送数据包，长度: {}", len);
        
        let (signature, data) = buf.into_parts();
        println!("🍓MACTUN: 发送数据包，签名是: {:?}, data长度: {}", signature, data.len());
        
        // 添加额外日志，分析IP包内容
        if len >= 20 {  // IP包头至少20字节
            let version = data[0] >> 4;
            let ihl = (data[0] & 0x0F) * 4;  // IP头部长度(以4字节为单位)
            
            if version == 4 && len >= ihl as usize {  // IPv4
                let protocol = data[9];
                let src_ip = format!("{}.{}.{}.{}", data[12], data[13], data[14], data[15]);
                let dst_ip = format!("{}.{}.{}.{}", data[16], data[17], data[18], data[19]);
                
                let proto_name = match protocol {
                    1 => "ICMP",
                    6 => "TCP",
                    17 => "UDP",
                    _ => "未知"
                };
                
                info!("📦 IP包详情: IPv4, 协议: {}({}), 源IP: {}, 目标IP: {}", 
                        proto_name, protocol, src_ip, dst_ip);
                
                // 如果是TCP/UDP，尝试打印端口信息
                if (protocol == 6 || protocol == 17) && len >= (ihl + 4) as usize {
                    let src_port = (data[ihl as usize] as u16) << 8 | data[(ihl+1) as usize] as u16;
                    let dst_port = (data[(ihl+2) as usize] as u16) << 8 | data[(ihl+3) as usize] as u16;
                    info!("📦 端口信息: 源端口: {}, 目标端口: {}", src_port, dst_port);
                }
            } else if version == 6 && len >= 40 {  // IPv6
                let next_header = data[6];
                // 简化的IPv6地址打印
                info!("📦 IP包详情: IPv6, 下一头部: {}", next_header);
            }
        }
        
        // 计算发送前的数据哈希以便跟踪
        let mut send_hash: u32 = 0;
        for i in 0..len {
            send_hash = send_hash.wrapping_add(data[i] as u32);
        }
        println!("🔢 发送前数据哈希: {}, 长度: {}", send_hash, len);
        
        // 获取数据的副本
        let data_to_send = data[..len].to_vec();
        
        // 创建写入任务
        let write_task = WriteTask {
            data: data_to_send,
            len,
            created_time: Instant::now(),
        };
        
        // 将任务发送到写入线程池
        println!("📤 通过线程池发送数据到TUN设备");
        match self.writer_tx.send(write_task) {
            Ok(_) => println!("✅ 发送任务已加入线程池队列"),
            Err(e) => eprintln!("❌ 无法发送任务到线程池: {}", e),
        }
        
        // 释放原始缓冲区前检查缓冲区内容
        println!("🔍 释放前检查缓冲区: 签名={:?}", signature);
        if !signature[0].is_null() {
            unsafe {
                let data_ptr = signature[0] as *mut Vec<u8>;
                println!("🔍 缓冲区指针有效，即将释放: {:p}", data_ptr);
                
                // 如果可以，检查Vec的内容
                if !data_ptr.is_null() && (*data_ptr).len() > 0 {
                    println!("🔍 缓冲区内容长度: {}", (*data_ptr).len());
                    if (*data_ptr).len() <= 64 {
                        println!("🔍 缓冲区内容: {:02x?}", &*data_ptr);
                    } else {
                        println!("🔍 缓冲区前64字节: {:02x?}", &(*data_ptr)[..64]);
                    }
                } else {
                    println!("🔍 缓冲区内容为空或无法访问");
                }
            }
        } else {
            println!("🔍 缓冲区指针为空，无法检查");
        }
        
        // 释放原始缓冲区
        unsafe {
            let data_ptr = signature[0] as *mut Vec<u8>;
            if !data_ptr.is_null() {
                drop(Box::from_raw(data_ptr));
                println!("✅ 原始缓冲区已释放");
            } else {
                println!("⚠️ 原始缓冲区指针为空，无需释放");
            }
        }
        
        println!("✅ 数据包已提交给线程池处理");
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

impl Drop for MacTun {
    fn drop(&mut self) {
        // 尝试清理路由配置
        if let Err(e) = self.cleanup_routing() {
            eprintln!("清理路由失败: {}", e);
        }
    }
}