use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};
use crate::flow::datagram::*;
use crate::flow::*;
use log::{error, info};

// 通用UDP会话信息特征
pub trait UdpSessionInfo: Send + Sync {
    fn get_created_time(&self) -> Instant;
    fn get_last_active(&self) -> Instant;
    fn update_last_active(&mut self);
    fn is_expired(&self, timeout: Duration) -> bool {
        Instant::now().duration_since(self.get_last_active()) > timeout
    }
}

// 基本会话信息结构
#[derive(Clone)]
pub struct BaseUdpSessionInfo {
    pub created_at: Instant,
    pub last_active: Instant,
    pub handler: Weak<dyn DatagramSessionHandler>,
}

impl UdpSessionInfo for BaseUdpSessionInfo {
    fn get_created_time(&self) -> Instant {
        self.created_at
    }
    
    fn get_last_active(&self) -> Instant {
        self.last_active
    }
    
    fn update_last_active(&mut self) {
        self.last_active = Instant::now();
    }
}

// SOCKS5会话信息
#[derive(Clone)]
pub struct Socks5UdpSessionInfo {
    pub base: BaseUdpSessionInfo,
    pub relay_addr: SocketAddr,
    pub assoc_id: Option<usize>,
}

impl UdpSessionInfo for Socks5UdpSessionInfo {
    fn get_created_time(&self) -> Instant {
        self.base.get_created_time()
    }
    
    fn get_last_active(&self) -> Instant {
        self.base.get_last_active()
    }
    
    fn update_last_active(&mut self) {
        self.base.update_last_active();
    }
}

// 通用UDP会话管理器
pub struct UdpSessionManager<T: UdpSessionInfo + 'static> {
    sessions: Mutex<HashMap<SocketAddr, T>>,
    timeout: Duration,
}

impl<T: UdpSessionInfo + 'static> UdpSessionManager<T> {
    pub fn new(timeout: Duration) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            timeout,
        }
    }
    
    pub fn insert(&self, addr: SocketAddr, session: T) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.insert(addr, session);
        info!("添加UDP会话: {}", addr);
    }
    
    pub fn get(&self, addr: &SocketAddr) -> Option<T> where T: Clone {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(addr) {
            session.update_last_active();
            return Some(session.clone());
        }
        None
    }
    
    pub fn get_mut<F, R>(&self, addr: &SocketAddr, f: F) -> Option<R>
    where
        F: FnOnce(&mut T) -> R,
    {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(addr) {
            session.update_last_active();
            return Some(f(session));
        }
        None
    }
    
    pub fn remove(&self, addr: &SocketAddr) -> Option<T> {
        let mut sessions = self.sessions.lock().unwrap();
        let result = sessions.remove(addr);
        if result.is_some() {
            info!("移除UDP会话: {}", addr);
        }
        result
    }
    
    pub fn cleanup_expired(&self) where T: Clone {
        let mut sessions = self.sessions.lock().unwrap();
        
        // 找出过期会话
        let expired: Vec<SocketAddr> = sessions
            .iter()
            .filter(|(_, session)| session.is_expired(self.timeout))
            .map(|(addr, _)| *addr)
            .collect();
        
        // 移除过期会话
        for addr in expired {
            if sessions.remove(&addr).is_some() {
                info!("清理过期UDP会话: {}", addr);
            }
        }
    }
    
    // 启动清理任务
    pub fn start_cleanup_task(manager: Arc<Self>) where T: Clone {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                manager.cleanup_expired();
            }
        });
    }
}

// 为特定协议创建具体的会话管理器实例
lazy_static::lazy_static! {
    // 通用UDP会话管理器
    pub static ref GLOBAL_UDP_SESSIONS: Arc<UdpSessionManager<BaseUdpSessionInfo>> = {
        let manager = Arc::new(UdpSessionManager::new(Duration::from_secs(300)));
        UdpSessionManager::start_cleanup_task(manager.clone());
        manager
    };
    
    // SOCKS5特定UDP会话管理器
    pub static ref SOCKS5_UDP_SESSIONS: Arc<UdpSessionManager<Socks5UdpSessionInfo>> = {
        let manager = Arc::new(UdpSessionManager::new(Duration::from_secs(300)));
        UdpSessionManager::start_cleanup_task(manager.clone());
        manager
    };
} 