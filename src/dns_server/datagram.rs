use std::collections::BTreeMap;
use std::hash::Hash;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use futures::future::poll_fn;
use lru::LruCache;
use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, Semaphore};
use trust_dns_resolver::proto::op::{Message as DnsMessage, MessageType, ResponseCode};
use trust_dns_resolver::proto::rr::{RData, Record, RecordType};
use trust_dns_resolver::proto::serialize::binary::BinDecodable;

use crate::data::PluginCache;
use crate::flow::*;

const CACHE_CAPACITY: NonZeroUsize = NonZeroUsize::new(1024).unwrap();
const REVERSE_MAPPING_V4_CACHE_KEY: &str = "rev_v4";
const REVERSE_MAPPING_V6_CACHE_KEY: &str = "rev_v6";
const FORWARD_CACHE_V4_KEY: &str = "fwd_v4";
const FORWARD_CACHE_V6_KEY: &str = "fwd_v6";

// 带过期时间的缓存项
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheEntry<T> {
    value: T,
    expires_at: u64, // 保存为Unix时间戳，单位秒
}

// 域名到IP的正向缓存
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ForwardCache<T> {
    entries: BTreeMap<String, Vec<CacheEntry<T>>>,
}

impl<T> Default for ForwardCache<T> {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }
}

pub struct DnsServer {
    concurrency_limit: Arc<Semaphore>,
    resolver: Weak<dyn Resolver>,
    ttl: u32,
    pub(super) reverse_mapping_v4: Arc<Mutex<LruCache<Ipv4Addr, String>>>,
    pub(super) reverse_mapping_v6: Arc<Mutex<LruCache<Ipv6Addr, String>>>,
    forward_cache_v4: Arc<Mutex<ForwardCache<Ipv4Addr>>>,
    forward_cache_v6: Arc<Mutex<ForwardCache<Ipv6Addr>>>,
    plugin_cache: PluginCache,
    pub(super) new_notify: Arc<Notify>,
}

impl Clone for DnsServer {
    fn clone(&self) -> Self {
        Self {
            concurrency_limit: self.concurrency_limit.clone(),
            resolver: self.resolver.clone(),
            ttl: self.ttl,
            reverse_mapping_v4: self.reverse_mapping_v4.clone(),
            reverse_mapping_v6: self.reverse_mapping_v6.clone(),
            forward_cache_v4: self.forward_cache_v4.clone(),
            forward_cache_v6: self.forward_cache_v6.clone(),
            plugin_cache: self.plugin_cache.clone(),
            new_notify: self.new_notify.clone(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
struct ReverseMappingCache<T: Ord>(BTreeMap<T, String>);

impl DnsServer {
    pub fn new(
        concurrency_limit: usize,
        resolver: Weak<dyn Resolver>,
        ttl: u32,
        plugin_cache: PluginCache,
    ) -> Self {
        println!("初始化DNS服务器，TTL：{}秒, 并发限制: {}", ttl, concurrency_limit);
        
        let concurrency_limit = Arc::new(Semaphore::new(concurrency_limit));
        let mut reverse_mapping_v4 = LruCache::new(CACHE_CAPACITY);
        let mut reverse_mapping_v6 = LruCache::new(CACHE_CAPACITY);
        
        println!("开始加载DNS缓存...");
        // 加载IPv4缓存
        if let Some(reverse_mapping_v4_cache) = plugin_cache
            .get::<ReverseMappingCache<_>>(REVERSE_MAPPING_V4_CACHE_KEY)
            .ok()
            .flatten()
        {
            let items_count = reverse_mapping_v4_cache.0.len();
            println!("✅ 成功加载IPv4反向映射缓存，项目数量: {}", items_count);
            for (k, v) in reverse_mapping_v4_cache.0 {
                reverse_mapping_v4.put(k, v);
            }
        } else {
            println!("⚠️ 未找到IPv4反向映射缓存或加载失败，使用空缓存");
        }
        
        // 加载IPv6缓存
        if let Some(reverse_mapping_v6_cache) = plugin_cache
            .get::<ReverseMappingCache<_>>(REVERSE_MAPPING_V6_CACHE_KEY)
            .ok()
            .flatten()
        {
            let items_count = reverse_mapping_v6_cache.0.len();
            println!("✅ 成功加载IPv6反向映射缓存，项目数量: {}", items_count);
            for (k, v) in reverse_mapping_v6_cache.0 {
                reverse_mapping_v6.put(k, v);
            }
        } else {
            println!("⚠️ 未找到IPv6反向映射缓存或加载失败，使用空缓存");
        }
        
        // 加载域名到IPv4的正向缓存
        let forward_cache_v4 = plugin_cache
            .get::<ForwardCache<Ipv4Addr>>(FORWARD_CACHE_V4_KEY)
            .ok()
            .flatten()
            .unwrap_or_default();
        
        // 加载域名到IPv6的正向缓存
        let forward_cache_v6 = plugin_cache
            .get::<ForwardCache<Ipv6Addr>>(FORWARD_CACHE_V6_KEY)
            .ok()
            .flatten()
            .unwrap_or_default();
        
        // 清理过期的缓存项
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let mut valid_v4_count = 0;
        let mut expired_v4_count = 0;
        let mut valid_v6_count = 0;
        let mut expired_v6_count = 0;
        
        // 清理过期的IPv4缓存
        let forward_cache_v4 = {
            let mut new_cache = ForwardCache::default();
            for (domain, entries) in forward_cache_v4.entries {
                let valid_entries: Vec<_> = entries
                    .into_iter()
                    .filter(|entry| {
                        if entry.expires_at > now {
                            valid_v4_count += 1;
                            true
                        } else {
                            expired_v4_count += 1;
                            false
                        }
                    })
                    .collect();
                
                if !valid_entries.is_empty() {
                    new_cache.entries.insert(domain, valid_entries);
                }
            }
            new_cache
        };
        
        // 清理过期的IPv6缓存
        let forward_cache_v6 = {
            let mut new_cache = ForwardCache::default();
            for (domain, entries) in forward_cache_v6.entries {
                let valid_entries: Vec<_> = entries
                    .into_iter()
                    .filter(|entry| {
                        if entry.expires_at > now {
                            valid_v6_count += 1;
                            true
                        } else {
                            expired_v6_count += 1;
                            false
                        }
                    })
                    .collect();
                
                if !valid_entries.is_empty() {
                    new_cache.entries.insert(domain, valid_entries);
                }
            }
            new_cache
        };
        
        println!("✅ 域名到IPv4缓存：有效项 {} 个，过期项 {} 个", valid_v4_count, expired_v4_count);
        println!("✅ 域名到IPv6缓存：有效项 {} 个，过期项 {} 个", valid_v6_count, expired_v6_count);
        
        println!("DNS缓存加载完成");
        
        DnsServer {
            concurrency_limit,
            resolver,
            ttl,
            reverse_mapping_v4: Arc::new(Mutex::new(reverse_mapping_v4)),
            reverse_mapping_v6: Arc::new(Mutex::new(reverse_mapping_v6)),
            forward_cache_v4: Arc::new(Mutex::new(forward_cache_v4)),
            forward_cache_v6: Arc::new(Mutex::new(forward_cache_v6)),
            plugin_cache,
            new_notify: Arc::new(Notify::new()),
        }
    }

    fn save_reverse_mapping_cache<T: Serialize + Hash + Eq + Ord + Clone>(
        &self,
        cache: &Mutex<LruCache<T, String>>,
        key: &str,
    ) {
        println!("开始保存DNS缓存 - {}", key);
        
        let cache_data = {
            let inner = cache.lock().unwrap();
            let items_count = inner.len();
            println!("缓存项数量: {} (key: {})", items_count, key);
            
            ReverseMappingCache(
                (&*inner)
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
            )
        };
        
        match self.plugin_cache.set(key, &cache_data) {
            Ok(_) => println!("✅ 成功保存DNS缓存: {}", key),
            Err(e) => println!("❌ 保存DNS缓存失败: {} - 错误: {:?}", key, e),
        }
    }
    
    // 保存所有缓存数据
    pub(crate) fn save_cache(&self) {
        println!("开始保存DNS反向映射缓存...");
        self.save_reverse_mapping_cache(&self.reverse_mapping_v4, REVERSE_MAPPING_V4_CACHE_KEY);
        self.save_reverse_mapping_cache(&self.reverse_mapping_v6, REVERSE_MAPPING_V6_CACHE_KEY);
        
        // 保存域名到IP的正向缓存
        println!("开始保存DNS正向缓存...");
        match self.plugin_cache.set(FORWARD_CACHE_V4_KEY, &*self.forward_cache_v4.lock().unwrap()) {
            Ok(_) => println!("✅ 成功保存DNS正向缓存: IPv4"),
            Err(e) => println!("❌ 保存DNS正向缓存失败: IPv4 - 错误: {:?}", e),
        }
        
        match self.plugin_cache.set(FORWARD_CACHE_V6_KEY, &*self.forward_cache_v6.lock().unwrap()) {
            Ok(_) => println!("✅ 成功保存DNS正向缓存: IPv6"),
            Err(e) => println!("❌ 保存DNS正向缓存失败: IPv6 - 错误: {:?}", e),
        }
        
        println!("DNS缓存保存完成");
    }
    
    // 查找域名对应的IPv4地址
    pub fn lookup_ipv4_cache(&self, domain: &str) -> Option<Vec<Ipv4Addr>> {
        let cache = self.forward_cache_v4.lock().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        if let Some(entries) = cache.entries.get(domain) {
            let valid_entries: Vec<_> = entries
                .iter()
                .filter(|entry| entry.expires_at > now)
                .map(|entry| entry.value)
                .collect();
            
            if !valid_entries.is_empty() {
                println!("✅ DNS缓存命中: {} -> {:?} (IPv4)", domain, valid_entries);
                return Some(valid_entries);
            }
        }
        println!("❌ DNS缓存未命中: {} (IPv4)", domain);
        None
    }
    
    // 查找域名对应的IPv6地址
    pub fn lookup_ipv6_cache(&self, domain: &str) -> Option<Vec<Ipv6Addr>> {
        let cache = self.forward_cache_v6.lock().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        if let Some(entries) = cache.entries.get(domain) {
            let valid_entries: Vec<_> = entries
                .iter()
                .filter(|entry| entry.expires_at > now)
                .map(|entry| entry.value)
                .collect();
            
            if !valid_entries.is_empty() {
                println!("✅ DNS缓存命中: {} -> {:?} (IPv6)", domain, valid_entries);
                return Some(valid_entries);
            }
        }
        println!("❌ DNS缓存未命中: {} (IPv6)", domain);
        None
    }
    
    // 更新IPv4缓存
    pub fn update_ipv4_cache(&self, domain: String, ips: &[Ipv4Addr], ttl: u32) {
        let mut cache = self.forward_cache_v4.lock().unwrap();
        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + ttl as u64;
        
        let entries = cache.entries.entry(domain.clone()).or_default();
        
        // 清除已有条目再添加新的
        entries.clear();
        
        for &ip in ips {
            entries.push(CacheEntry {
                value: ip,
                expires_at,
            });
        }
        
        println!("✅ DNS缓存已更新: {} -> {:?} (IPv4), TTL: {}秒", domain, ips, ttl);
    }
    
    // 更新IPv6缓存
    pub fn update_ipv6_cache(&self, domain: String, ips: &[Ipv6Addr], ttl: u32) {
        let mut cache = self.forward_cache_v6.lock().unwrap();
        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + ttl as u64;
        
        let entries = cache.entries.entry(domain.clone()).or_default();
        
        // 清除已有条目再添加新的
        entries.clear();
        
        for &ip in ips {
            entries.push(CacheEntry {
                value: ip,
                expires_at,
            });
        }
        
        println!("✅ DNS缓存已更新: {} -> {:?} (IPv6), TTL: {}秒", domain, ips, ttl);
    }

    // 通知缓存更新，用于触发缓存保存
    pub fn notify_cache_update(&self) {
        println!("收到缓存更新通知");
        self.new_notify.notify_one();
    }
}

impl DatagramSessionHandler for DnsServer {
    fn on_session(&self, mut session: Box<dyn DatagramSession>, _context: Box<FlowContext>) {
        let resolver = match self.resolver.upgrade() {
            Some(resolver) => resolver,
            None => return,
        };
        let concurrency_limit = self.concurrency_limit.clone();
        let ttl = self.ttl;
        let reverse_mapping_v4 = self.reverse_mapping_v4.clone();
        let reverse_mapping_v6 = self.reverse_mapping_v6.clone();
        let new_notify = self.new_notify.clone();
        
        // 克隆self的引用以便在异步闭包中使用
        let dns_server = Arc::new(self.clone());
        
        tokio::spawn(async move {
            let mut send_ready = true;
            while let Some((dest, buf)) = poll_fn(|cx| {
                if !send_ready {
                    send_ready = session.as_mut().poll_send_ready(cx).is_ready()
                }
                session.as_mut().poll_recv_from(cx)
            })
            .await
            {
                let _concurrency_permit = match concurrency_limit.acquire().await {
                    Ok(permit) => permit,
                    Err(_) => break,
                };

                let mut msg = match DnsMessage::from_bytes(&buf) {
                    Ok(msg) => msg,
                    Err(_) => continue,
                };
                
                println!("📝 收到DNS查询请求");
                
                let mut res_code = ResponseCode::NoError;
                let mut ans_records = Vec::with_capacity(msg.queries().len());
                let mut notify_cache_update = false;
                
                for query in msg.queries() {
                    let name = query.name();
                    let name_str = name.to_lowercase().to_ascii();
                    
                    println!("🔍 查询: {} (类型: {:?})", name_str, query.query_type());
                    
                    match query.query_type() {
                        RecordType::A => {
                            // 先查缓存
                            if let Some(cached_ips) = dns_server.lookup_ipv4_cache(&name_str) {
                                // 使用缓存结果
                                ans_records.extend(
                                    cached_ips.into_iter().map(|addr| {
                                        Record::from_rdata(name.clone(), ttl, RData::A(addr))
                                    }),
                                );
                                continue;
                            }
                            
                            // 缓存未命中，查询resolver
                            println!("🌐 通过resolver查询: {} (IPv4)", name_str);
                            let start = Instant::now();
                            
                            let ips = match resolver.resolve_ipv4(name_str.clone()).await {
                                Ok(addrs) => addrs,
                                Err(_) => {
                                    println!("❌ 解析失败: {} (IPv4)", name_str);
                                    res_code = ResponseCode::NXDomain;
                                    continue;
                                }
                            };
                            
                            println!("✅ 解析成功: {} -> {:?} (IPv4), 耗时: {:?}", 
                                     name_str, ips, start.elapsed());
                            
                            // 更新缓存
                            dns_server.update_ipv4_cache(name_str.clone(), &ips, ttl);
                            
                            // 更新反向映射
                            let mut reverse_mapping = reverse_mapping_v4.lock().unwrap();
                            for ip in &ips {
                                notify_cache_update |= reverse_mapping
                                    .peek_mut(ip)
                                    .filter(|n| *n == &name_str)
                                    .is_none();
                                reverse_mapping.get_or_insert(*ip, || name_str.clone());
                            }
                            
                            ans_records.extend(
                                ips.into_iter().map(|addr| {
                                    Record::from_rdata(name.clone(), ttl, RData::A(addr))
                                }),
                            )
                        }
                        RecordType::AAAA => {
                            // 先查缓存
                            if let Some(cached_ips) = dns_server.lookup_ipv6_cache(&name_str) {
                                // 使用缓存结果
                                ans_records.extend(
                                    cached_ips.into_iter().map(|addr| {
                                        Record::from_rdata(name.clone(), ttl, RData::AAAA(addr))
                                    }),
                                );
                                continue;
                            }
                            
                            // 缓存未命中，查询resolver
                            println!("🌐 通过resolver查询: {} (IPv6)", name_str);
                            let start = Instant::now();
                            
                            let ips = match resolver.resolve_ipv6(name_str.clone()).await {
                                Ok(addrs) => addrs,
                                Err(_) => {
                                    println!("❌ 解析失败: {} (IPv6)", name_str);
                                    res_code = ResponseCode::NXDomain;
                                    continue;
                                }
                            };
                            
                            println!("✅ 解析成功: {} -> {:?} (IPv6), 耗时: {:?}", 
                                     name_str, ips, start.elapsed());
                            
                            // 更新缓存
                            dns_server.update_ipv6_cache(name_str.clone(), &ips, ttl);
                            
                            // 更新反向映射
                            let mut reverse_mapping = reverse_mapping_v6.lock().unwrap();
                            for ip in &ips {
                                notify_cache_update |= reverse_mapping
                                    .peek_mut(ip)
                                    .filter(|n| *n == &name_str)
                                    .is_none();
                                reverse_mapping.get_or_insert(*ip, || name_str.clone());
                            }
                            
                            ans_records.extend(ips.into_iter().map(|addr| {
                                Record::from_rdata(name.clone(), ttl, RData::AAAA(addr))
                            }))
                        }
                        // TODO: SRV
                        _ => {
                            println!("❌ 不支持的查询类型: {:?}", query.query_type());
                            res_code = ResponseCode::NotImp;
                            continue;
                        }
                    }
                }
                
                if notify_cache_update {
                    println!("🔄 DNS缓存有更新，即将触发保存");
                    new_notify.notify_one();
                }

                *msg.set_message_type(MessageType::Response)
                    .set_response_code(res_code)
                    .answers_mut() = ans_records;

                let response = match msg.to_vec() {
                    Ok(vec) => vec,
                    Err(_) => continue,
                };
                
                println!("📤 发送DNS响应");
                
                if !send_ready {
                    poll_fn(|cx| session.as_mut().poll_send_ready(cx)).await;
                }
                session.as_mut().send_to(dest, response);
                send_ready = false;
            }
            poll_fn(|cx| session.as_mut().poll_shutdown(cx)).await
        });
    }
}
