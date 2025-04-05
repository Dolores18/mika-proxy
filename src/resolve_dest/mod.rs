mod forward;

pub use forward::{DatagramForwardResolver, StreamForwardResolver};

use std::sync::Arc;

use crate::flow::*;

async fn try_resolve_forward(
    is_ipv6: bool,
    resolver: Arc<dyn Resolver>,
    domain: String,
    port: u16,
) -> DestinationAddr {
    println!("🔍 尝试解析域名: {}, IPv6模式: {}", domain, is_ipv6);
    
    match if is_ipv6 {
        resolver
            .resolve_ipv6(domain.clone())
            .await
            .ok()
            .and_then(|ips| ips.first().cloned())
            .map(Into::into)
    } else {
        resolver
            .resolve_ipv4(domain.clone())
            .await
            .ok()
            .and_then(|ips| ips.first().cloned())
            .map(Into::into)
    } {
        Some(ip) => {
            println!("✅ 域名解析成功: {} -> {}", domain, ip);
            DestinationAddr {
                host: HostName::Ip(ip),
                port,
            }
        },

        None => {
            println!("❌ 域名解析失败: {}", domain);
            DestinationAddr {
                host: HostName::DomainName(domain),
                port,
            }
        },
    }
}
