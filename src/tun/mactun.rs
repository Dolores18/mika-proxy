use crate::flow::{Buffer, TunBufferToken, TunBufferSignature, Tun};
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;
use std::io::{self, Result as IoResult};
use std::process::Command;
use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex as TokioMutex;
use std::path::PathBuf;
use tun::AbstractDevice;
use smoltcp::phy::TxToken as SmolTxToken;

// MacTun设备类型，使用tokio进行异步操作
pub struct MacTun {
    // 内部tun设备实例
    device: Arc<TokioMutex<tun::AsyncDevice>>,
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
        address: Ipv4Addr,  // 使用传入的IP地址
        netmask: Ipv4Addr,  // 使用传入的网络掩码
        mtu: Option<usize>
    ) -> IoResult<Self> {
        // 使用传入的IP地址和掩码
        let address_v6 = Some(
            "fd00::2".parse::<Ipv6Addr>().expect("无效的IPv6地址")
        );
        
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
            
        // 创建TUN设备
        let device = tun::create_as_async(&config)?;
        // 获取实际设备名称
        let actual_name = device.tun_name().unwrap_or_else(|_| name.to_string());

        let mtu_val = mtu.unwrap_or(1500);
        
        // 创建MacTun实例
        let mac_tun = Self {
            device: Arc::new(TokioMutex::new(device)),
            name: actual_name,
            address,
            address_v6,
            netmask,
            original_routes,
            buffer_pool: Arc::new(Mutex::new(VecDeque::new())),
            mtu: mtu_val,
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

    /// 配置系统路由表 - 只对特定IP进行代理
    fn configure_routing(&self) -> IoResult<()> {
        // 删除所有现有的路由
        println!("清理现有路由...");
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

        // 添加FakeIP范围路由
        println!("配置FakeIP范围路由 (198.18.0.0/15)...");
        let fakeip_route = Command::new("route")
            .arg("-n")
            .arg("add")
            .arg("-net")
            .arg("198.18.0.0/15")
            .arg("-interface")
            .arg(&self.name)
            .output();

        match fakeip_route {
            Ok(output) => {
                if output.status.success() {
                    println!("✅ 成功添加FakeIP范围路由");
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    eprintln!("❌ 添加FakeIP范围路由失败: {}", stderr);
                }
            },
            Err(e) => {
                eprintln!("❌ 执行FakeIP范围路由命令失败: {}", e);
                return Err(e);
            }
        }

        // 添加DNS服务器路由
        println!("配置DNS服务器路由...");
        let dns_servers = ["8.8.8.8", "9.9.9.9"];
        
        for dns in dns_servers.iter() {
            let dns_route = Command::new("route")
                .arg("-n")
                .arg("add")
                .arg(dns)
                .arg("-interface")
                .arg(&self.name)
                .output();

            match dns_route {
                Ok(output) => {
                    if output.status.success() {
                        println!("✅ 成功添加DNS服务器 {} 的路由", dns);
                    } else {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        eprintln!("❌ 添加DNS服务器 {} 路由失败: {}", dns, stderr);
                    }
                },
                Err(e) => {
                    eprintln!("❌ 执行DNS服务器 {} 路由命令失败: {}", dns, e);
                    return Err(e);
                }
            }
        }
            
        Ok(())
    }

    /// 清理路由配置
    pub fn cleanup_routing(&self) -> IoResult<()> {
        // 移除特定IP的路由
        println!("清理路由: 移除8.8.8.8的路由");
        let cmd_result = Command::new("route")
            .arg("-n")
            .arg("delete")
            .arg("8.8.8.8")
            .output();
            
        match cmd_result {
            Ok(output) => {
                if output.status.success() {
                    println!("✅ 成功移除8.8.8.8的路由");
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    eprintln!("⚠️ 移除8.8.8.8路由的过程中出现问题: {}", stderr);
                }
            },
            Err(e) => {
                eprintln!("⚠️ 执行route delete命令失败: {}", e);
            }
        }

        // 恢复原始路由
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
        // 创建一个缓冲区来存储数据
        let mut buffer = Buffer::new();
        buffer.resize(self.mtu, 0);
        
        // 从设备读取数据
        let read_result = {
            let runtime = tokio::runtime::Handle::current();
            // 获取设备引用并保持足够长
            let mut device_guard = self.device.blocking_lock();
            runtime.block_on(device_guard.read(&mut buffer))
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
                        
                        println!("📦 接收IP包: IPv4, 协议: {}({}), 源IP: {}, 目标IP: {}",
                                proto_name, protocol, src_ip, dst_ip);
                        
                        // 如果是TCP/UDP，尝试打印端口信息
                        if (protocol == 6 || protocol == 17) && buffer.len() >= (ihl + 4) as usize {
                            let src_port = (buffer[ihl as usize] as u16) << 8 | buffer[(ihl+1) as usize] as u16;
                            let dst_port = (buffer[(ihl+2) as usize] as u16) << 8 | buffer[(ihl+3) as usize] as u16;
                            println!("📦 接收端口: 源端口: {}, 目标端口: {}", src_port, dst_port);
                        }
                        
                        println!("TUN设备接收: IP版本: {}, 协议: {}, 长度: {}", 
                                version, protocol, buffer.len());
                    } else if version == 6 && buffer.len() >= 40 {  // IPv6
                        let next_header = buffer[6];
                        // 简化的IPv6地址打印
                        println!("📦 接收IP包: IPv6, 下一头部: {}", next_header);
                        
                        println!("🐶MACTUN: IP版本: {}, 协议: {}, 长度: {}", 
                                version, next_header, buffer.len());
                    } else {
                        println!("🐶MACTUN: IP版本: {}, 长度: {}", version, buffer.len());
                    }
                } else {
                    println!("🐶MACTUN: 数据包太小，无法解析IP头");
                }
                
                println!("🐶MACTUN: 收到数据包，长度: {}", buffer.len());
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
        println!("🐶MACTUN: 返还接收缓冲区，长度: {}", buf.len());
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
        
        println!("🐶MACTUN: 创建发送缓冲区，大小: {}", self.mtu);
        
        // 安全性：我们确保签名可以安全地发送到其他线程
        unsafe {
            Some(TunBufferToken::new(signature, static_slice))
        }
    }
    
    fn send(&self, buf: TunBufferToken, len: usize) {
        println!("🐶MACTUN: 发送数据包，长度: {}", len);
        
        let (signature, data) = buf.into_parts();
        
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
                
                println!("📦 IP包详情: IPv4, 协议: {}({}), 源IP: {}, 目标IP: {}", 
                        proto_name, protocol, src_ip, dst_ip);
                
                // 如果是TCP/UDP，尝试打印端口信息
                if (protocol == 6 || protocol == 17) && len >= (ihl + 4) as usize {
                    let src_port = (data[ihl as usize] as u16) << 8 | data[(ihl+1) as usize] as u16;
                    let dst_port = (data[(ihl+2) as usize] as u16) << 8 | data[(ihl+3) as usize] as u16;
                    println!("📦 端口信息: 源端口: {}, 目标端口: {}", src_port, dst_port);
                }
            } else if version == 6 && len >= 40 {  // IPv6
                let next_header = data[6];
                // 简化的IPv6地址打印
                println!("📦 IP包详情: IPv6, 下一头部: {}", next_header);
            }
        }
        
        // 获取临时数据的副本
        let data_to_send = data[..len].to_vec();
        
        // 先释放原始缓冲区，避免在异步任务中使用原始指针
        unsafe {
            let data_ptr = signature[0] as *mut Vec<u8>;
            if !data_ptr.is_null() {
                drop(Box::from_raw(data_ptr));
            }
        }
        
        // 使用tokio::spawn来异步处理写入操作
        let device = self.device.clone();
        tokio::spawn(async move {
            let mut device_guard = device.lock().await;
            if let Err(e) = device_guard.write(&data_to_send).await {
                eprintln!("写入TUN设备错误: {}", e);
            } else {
                println!("TUN: 成功写入MacTun设备 {} 字节, 数据包内容(十六进制): {:02x?}", data_to_send.len(), data_to_send);
            }
        });
    }
    
    fn return_tx_buffer(&self, buf: TunBufferToken) {
        // 释放缓冲区
        println!("TUN: 返还发送缓冲区");
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