use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::flow::*;
use log::{debug, info, trace, warn};

// UDP NAT映射表的键，包含原始请求信息
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct UdpNatKey {
    // 代理使用的本地地址（发送请求时使用的地址）
    local_addr: SocketAddr,
    // 外部目标地址（原始DNS服务器地址）
    remote_addr: SocketAddr,
}

// UDP NAT映射表的值，包含原始客户端信息
#[derive(Debug, Clone)]
struct UdpNatValue {
    // 原始客户端地址
    client_addr: SocketAddr,
    // 映射创建时间，用于清理过期映射
    created_at: Instant,
}

// UDP NAT管理器
#[derive(Debug, Clone)]
pub struct UdpNatManager {
    // 使用Arc<Mutex<>>以便在多线程环境中安全共享
    mappings: Arc<Mutex<HashMap<UdpNatKey, UdpNatValue>>>,
    // 映射超时时间
    timeout: Duration,
}

impl UdpNatManager {
    pub fn new(timeout_secs: u64) -> Self {
        let instance = Self {
            mappings: Arc::new(Mutex::new(HashMap::new())),
            timeout: Duration::from_secs(timeout_secs),
        };
        
        // 创建一个克隆用于清理线程
        let cleaner = instance.clone();
        
        // 启动清理任务
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                cleaner.cleanup();
            }
        });
        
        instance
    }
    
    // 记录一个新映射
    pub fn add_mapping(&self, 
                      client_addr: SocketAddr, 
                      local_addr: SocketAddr, 
                      remote_addr: SocketAddr) {
        let mut mappings = self.mappings.lock().unwrap();
        let key = UdpNatKey {
            local_addr,
            remote_addr,
        };
        
        let value = UdpNatValue {
            client_addr,
            created_at: Instant::now(),
        };
        
        mappings.insert(key, value);
        debug!("UDP NAT 添加映射: {}:{} -> {}:{} (通过 {}:{})",
               client_addr.ip(), client_addr.port(),
               remote_addr.ip(), remote_addr.port(),
               local_addr.ip(), local_addr.port());
    }
    
    // 查找映射的客户端地址
    pub fn lookup_client(&self, local_addr: SocketAddr, remote_addr: SocketAddr) -> Option<SocketAddr> {
        let key = UdpNatKey {
            local_addr,
            remote_addr,
        };
        
        let mappings = self.mappings.lock().unwrap();
        if let Some(value) = mappings.get(&key) {
            debug!("UDP NAT 查找匹配: {}:{} <- {}:{} (通过 {}:{})",
                  value.client_addr.ip(), value.client_addr.port(),
                  remote_addr.ip(), remote_addr.port(),
                  local_addr.ip(), local_addr.port());
            Some(value.client_addr)
        } else {
            debug!("UDP NAT 查找失败: 未找到 {}:{} -> {}:{} 的映射",
                  local_addr.ip(), local_addr.port(),
                  remote_addr.ip(), remote_addr.port());
            None
        }
    }
    
    // 清理过期的映射
    fn cleanup(&self) {
        let mut mappings = self.mappings.lock().unwrap();
        let now = Instant::now();
        let before_count = mappings.len();
        
        // 移除超过超时时间的映射
        mappings.retain(|_, value| {
            now.duration_since(value.created_at) < self.timeout
        });
        
        let removed = before_count - mappings.len();
        if removed > 0 {
            info!("UDP NAT 清理: 移除了 {} 个过期映射，剩余 {} 个", 
                 removed, mappings.len());
        }
    }
}

// 创建全局单例实例
lazy_static::lazy_static! {
    pub static ref UDP_NAT: UdpNatManager = UdpNatManager::new(300); // 5分钟超时
}

// 用于DNS请求特定的辅助函数
// 重定向DNS请求到本地FakeIP服务器并记录映射
pub fn redirect_dns_request(
    client_addr: SocketAddr,
    original_dest: DestinationAddr,
) -> DestinationAddr {
    // 如果是DNS请求（目标端口53）则重定向到本地FakeIP服务器
    if original_dest.port == 53 {
        if let HostName::Ip(ip) = &original_dest.host {
            // 获取UDP NAT实例
            let udp_nat = &UDP_NAT;
            
            // 记录原始请求信息
            let local_addr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0);
            let remote_addr = SocketAddr::new(*ip, original_dest.port);
            
            // 添加映射
            udp_nat.add_mapping(client_addr, local_addr, remote_addr);
            
            // 返回重定向后的目标地址
            let mut redirected = original_dest.clone();
            redirected.host = HostName::Ip(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
            redirected.port = 6353; // FakeIP DNS服务器端口
            
            debug!("DNS请求重定向: {}:{} -> {}:{} => {}:{}",
                  client_addr.ip(), client_addr.port(),
                  ip, original_dest.port,
                  std::net::Ipv4Addr::LOCALHOST, 6353);
            
            return redirected;
        }
    }
    
    // 非DNS请求则不做重定向
    original_dest
}

// 对于DNS响应，查找原始客户端并更新目标地址
pub fn lookup_original_client(
    server_addr: SocketAddr,
    local_addr: SocketAddr,
) -> Option<SocketAddr> {
    // 获取UDP NAT实例
    let udp_nat = &UDP_NAT;
    
    // 查找映射
    let client_addr = udp_nat.lookup_client(local_addr, server_addr);
    
    if let Some(addr) = &client_addr {
        debug!("DNS响应重定向: {}:{} -> {}:{}",
              server_addr.ip(), server_addr.port(),
              addr.ip(), addr.port());
    }
    
    client_addr
} 