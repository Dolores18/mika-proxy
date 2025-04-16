use std::sync::{Arc, Weak};
use async_trait::async_trait;
use crate::flow::*;
use crate::shadowsocks::crypto::Aes128Gcm;
use crate::shadowsocks::factory::stream::ShadowsocksStreamOutboundFactory;

/// 双栈出站工厂
/// 
/// 根据目标地址类型自动选择IPv4或IPv6代理
pub struct DualStackOutboundFactory {
    ipv4_factory: Arc<ShadowsocksStreamOutboundFactory<Aes128Gcm>>,
    ipv6_factory: Option<Arc<ShadowsocksStreamOutboundFactory<Aes128Gcm>>>,
}

impl DualStackOutboundFactory {
    /// 创建新的双栈出站工厂
    /// 
    /// # 参数
    /// * `ipv4_factory` - IPv4代理工厂
    /// * `ipv6_factory` - 可选的IPv6代理工厂
    pub fn new(
        ipv4_factory: Arc<ShadowsocksStreamOutboundFactory<Aes128Gcm>>,
        ipv6_factory: Option<Arc<ShadowsocksStreamOutboundFactory<Aes128Gcm>>>,
    ) -> Self {
        Self {
            ipv4_factory,
            ipv6_factory,
        }
    }
}

#[async_trait]
impl StreamOutboundFactory for DualStackOutboundFactory {
    async fn create_outbound(
        &self,
        context: &mut FlowContext,
        initial_data: &'_ [u8],
    ) -> FlowResult<(Box<dyn Stream>, Buffer)> {
        // 根据目标地址类型选择合适的工厂
        match &context.remote_peer.host {
            HostName::Ip(ip) if ip.is_ipv6() => {
                if let Some(ipv6_factory) = &self.ipv6_factory {
                    println!("🌐 使用IPv6代理连接: {:?}", ip);
                    return ipv6_factory.create_outbound(context, initial_data).await;
                }
            },
            _ => {}
        }
        
        // 默认或未找到IPv6工厂时使用IPv4工厂
        println!("🌐 使用IPv4代理连接: {:?}", context.remote_peer.host);
        self.ipv4_factory.create_outbound(context, initial_data).await
    }
} 