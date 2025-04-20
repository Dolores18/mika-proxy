use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use async_trait::async_trait;
use lru::LruCache;
use serde::{Deserialize, Serialize};
use smallvec::smallvec;
use tokio::sync::Notify;

use crate::data::PluginCache;
use crate::flow::*;

const CACHE_CAPACITY: NonZeroUsize = NonZeroUsize::new(1000).unwrap();
const PLUGIN_CACHE_KEY: &str = "map";

struct Inner {
    current: u16,
    cache: LruCache<String, u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InnerCache {
    current: u16,
    cache: BTreeMap<String, u16>,
}

pub struct FakeIp {
    prefix_v4: u16,
    prefix_v6: [u8; 14],
    inner: Arc<Mutex<Inner>>,
    plugin_cache: PluginCache,
    new_notify: Arc<Notify>,
}

impl FakeIp {
    pub fn new(prefix_v4: [u8; 2], prefix_v6: [u8; 14], plugin_cache: PluginCache) -> Self {
        let mut lru = LruCache::new(CACHE_CAPACITY);
        let inner = match plugin_cache
            .get::<InnerCache>(PLUGIN_CACHE_KEY)
            .ok()
            .flatten()
        {
            Some(cache) => {
                let entries_count = cache.cache.len();
                println!("✅ 从数据库加载FakeIP缓存成功，共 {} 条映射记录", entries_count);
                for (k, v) in cache.cache {
                    lru.put(k, v);
                }
                Inner {
                    current: cache.current,
                    cache: lru,
                }
            }
            None => {
                println!("ℹ️ 数据库中没有FakeIP缓存，将创建新的缓存");
                Inner {
                    current: 1,
                    cache: lru,
                }
            }
        };
        Self {
            prefix_v4: u16::from_be_bytes(prefix_v4),
            prefix_v6,
            inner: Arc::new(Mutex::new(inner)),
            plugin_cache,
            new_notify: Arc::new(Notify::new()),
        }
    }
    fn lookup_or_alloc(&self, domain: String) -> u16 {
        let ret = {
            let mut inner = self.inner.lock().unwrap();
            let cached = inner.cache.get(&*domain).copied();
            if let Some(cached) = cached {
                return cached;
            }
            let ret = inner.current;
            inner.cache.put(domain, ret);
            inner.current = inner.current.wrapping_add(1);
            ret
        };
        self.new_notify.notify_one();
        ret
    }
    fn save_cache(&self) {
        let cache = {
            let inner = self.inner.lock().unwrap();
            InnerCache {
                current: inner.current,
                cache: inner.cache.iter().map(|(k, v)| (k.clone(), *v)).collect(),
            }
        };
        
        // 增加日志来跟踪缓存保存过程
        let entries_count = {
            let inner = self.inner.lock().unwrap();
            inner.cache.len()
        };
        
        match self.plugin_cache.set(PLUGIN_CACHE_KEY, &cache) {
            Ok(_) => {
                println!("✅ 成功保存FakeIP缓存到数据库，共 {} 条映射记录", entries_count);
            },
            Err(e) => {
                eprintln!("❌ 保存FakeIP缓存到数据库失败: {:?}", e);
            }
        }
    }

    // 新增方法: 检查IP是否由FakeIP分配
    pub fn is_fake_ip_v4(&self, ip: Ipv4Addr) -> bool {
        let ip_bytes = ip.octets();
        let prefix = ((ip_bytes[0] as u16) << 8) | (ip_bytes[1] as u16);
        prefix == self.prefix_v4
    }

    pub fn is_fake_ip_v6(&self, ip: Ipv6Addr) -> bool {
        let ip_bytes = ip.octets();
        let mut prefix = [0u8; 14];
        prefix.copy_from_slice(&ip_bytes[..14]);
        prefix == self.prefix_v6
    }

    // 新增方法: 尝试将FakeIP反向映射到域名
    pub fn lookup_domain_by_fake_ip(&self, ip: IpAddr) -> Option<String> {
        match ip {
            IpAddr::V4(ipv4) => self.lookup_domain_by_fake_ipv4(ipv4),
            IpAddr::V6(ipv6) => self.lookup_domain_by_fake_ipv6(ipv6),
        }
    }

    fn lookup_domain_by_fake_ipv4(&self, ip: Ipv4Addr) -> Option<String> {
        if !self.is_fake_ip_v4(ip) {
            return None;
        }

        let ip_bytes = ip.octets();
        let index = ((ip_bytes[2] as u16) << 8) | (ip_bytes[3] as u16);
        
        let inner = self.inner.lock().unwrap();
        for (domain, &idx) in inner.cache.iter() {
            if idx == index {
                return Some(domain.clone());
            }
        }
        None
    }

    fn lookup_domain_by_fake_ipv6(&self, ip: Ipv6Addr) -> Option<String> {
        if !self.is_fake_ip_v6(ip) {
            return None;
        }

        let ip_bytes = ip.octets();
        let index = ((ip_bytes[14] as u16) << 8) | (ip_bytes[15] as u16);
        
        let inner = self.inner.lock().unwrap();
        for (domain, &idx) in inner.cache.iter() {
            if idx == index {
                return Some(domain.clone());
            }
        }
        None
    }
}

#[async_trait]
impl Resolver for FakeIp {
    async fn resolve_ipv4(&self, domain: String) -> ResolveResultV4 {
        Ok(smallvec![(((self.prefix_v4 as u32) << 16)
            | (self.lookup_or_alloc(domain) as u32))
            .to_be_bytes()
            .into()])
    }
    async fn resolve_ipv6(&self, domain: String) -> ResolveResultV6 {
        let mut bytes = [0; 16];
        bytes[..14].copy_from_slice(&self.prefix_v6);
        let index = self.lookup_or_alloc(domain);
        bytes[14] = (index >> 8) as u8;
        bytes[15] = (index & 0xFF) as u8;
        Ok(smallvec![bytes.into()])
    }
}

impl Drop for FakeIp {
    fn drop(&mut self) {
        self.save_cache();
    }
}

pub async fn cache_writer(plugin: Arc<FakeIp>) {
    let (plugin, notify) = {
        let notify = plugin.new_notify.clone();
        let weak = Arc::downgrade(&plugin);
        drop(plugin);
        (weak, notify)
    };
    if plugin.strong_count() == 0 {
        panic!("fakeip has no strong reference left for cache_writer");
    }

    use tokio::select;
    use tokio::time::{sleep, Duration};
    loop {
        let mut notified_fut = notify.notified();
        let mut sleep_fut = sleep(Duration::from_secs(3600));
        'debounce: loop {
            select! {
                _ = notified_fut => {
                    notified_fut = notify.notified();
                    sleep_fut = sleep(Duration::from_secs(3));
                }
                _ = sleep_fut => {
                    break 'debounce;
                }
            }
        }
        match plugin.upgrade() {
            Some(plugin) => plugin.save_cache(),
            None => break,
        }
    }
}

// 为FakeIp实现Debug trait
impl fmt::Debug for FakeIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeIp")
            .field("prefix_v4", &self.prefix_v4)
            .field("prefix_v6", &format!("{:?}", self.prefix_v6))
            .finish()
    }
}