use std::sync::Arc;
use async_trait::async_trait;
use log::info;

use crate::dns_server::DnsServer;
use crate::flow::*;

/// CachingResolver 结合了DNS缓存和底层解析器
/// 先查询缓存，缓存未命中时使用底层解析器
pub struct CachingResolver {
    cache: Arc<DnsServer>,
    fallback: Arc<dyn Resolver>,
}

impl CachingResolver {
    /// 创建新的缓存解析器
    pub fn new(cache: Arc<DnsServer>, fallback: Arc<dyn Resolver>) -> Self {
        Self { cache, fallback }
    }
}

#[async_trait]
impl Resolver for CachingResolver {
    /// 解析IPv4地址，先查缓存再查询底层解析器
    async fn resolve_ipv4(&self, domain: String) -> ResolveResultV4 {
        // 1. 先查询DnsServer的缓存
        if let Some(ips) = self.cache.lookup_ipv4_cache(&domain) {
            info!("🔍 缓存命中: {} -> {:?} (IPv4)", domain, ips);
            return Ok(ips.into());
        }
        
        // 2. 缓存未命中，使用fallback resolver
        info!("🌐 缓存未命中，使用底层解析器: {} (IPv4)", domain);
        let result = self.fallback.resolve_ipv4(domain.clone()).await;
        
        // 3. 如果解析成功，更新缓存
        if let Ok(ref ips) = result {
            info!("✅ 解析成功，更新缓存: {} -> {:?} (IPv4)", domain, ips);
            self.cache.update_ipv4_cache(domain, ips, 3600); // 使用1小时的TTL
            // 通知可能需要保存缓存
            self.cache.notify_cache_update();
        } else {
            info!("❌ 解析失败: {} (IPv4)", domain);
        }
        
        result
    }
    
    /// 解析IPv6地址，先查缓存再查询底层解析器
    async fn resolve_ipv6(&self, domain: String) -> ResolveResultV6 {
        // 1. 先查询DnsServer的缓存
        if let Some(ips) = self.cache.lookup_ipv6_cache(&domain) {
            info!("🔍 缓存命中: {} -> {:?} (IPv6)", domain, ips);
            return Ok(ips.into());
        }
        
        // 2. 缓存未命中，使用fallback resolver
        info!("🌐 缓存未命中，使用底层解析器: {} (IPv6)", domain);
        let result = self.fallback.resolve_ipv6(domain.clone()).await;
        
        // 3. 如果解析成功，更新缓存
        if let Ok(ref ips) = result {
            info!("✅ 解析成功，更新缓存: {} -> {:?} (IPv6)", domain, ips);
            self.cache.update_ipv6_cache(domain, ips, 3600); // 使用1小时的TTL
            // 通知可能需要保存缓存
            self.cache.notify_cache_update();
        } else {
            info!("❌ 解析失败: {} (IPv6)", domain);
        }
        
        result
    }
} 