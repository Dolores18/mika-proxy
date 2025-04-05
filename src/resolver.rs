use crate::flow::*;
use crate::redirect::*;
use async_trait::async_trait;
use std::net::ToSocketAddrs;
use std::sync::Arc;

#[derive(Clone)]
struct ProxyPeerProvider {
    host: String,
    port: u16,
}

impl PeerProvider for ProxyPeerProvider {
    fn get_peer(&self) -> DestinationAddr {
        DestinationAddr {
            host: self.host.parse().unwrap(),
            port: self.port,
        }
    }
}

pub struct SmartResolver {
    inner: StreamRedirectOutboundFactory<ProxyPeerProvider>,
    direct_domains: Vec<String>,
}

impl SmartResolver {
    pub fn new(
        redirect: StreamRedirectOutboundFactory<ProxyPeerProvider>,
        direct_domains: Vec<String>,
    ) -> Self {
        Self {
            inner: redirect,
            direct_domains,
        }
    }

    fn should_resolve(&self, domain: &str) -> bool {
        self.direct_domains.iter().any(|d| domain.contains(d))
    }
}

#[async_trait]
impl StreamOutboundFactory for SmartResolver {
    async fn create_outbound(
        &self,
        context: &mut FlowContext,
        initial_data: &'_ [u8],
    ) -> FlowResult<(Box<dyn Stream>, Buffer)> {
        if let HostName::DomainName(domain) = &context.remote_peer.host {
            if self.should_resolve(domain) {
                let addr_str = format!("{}:{}", domain, context.remote_peer.port);
                if let Ok(mut addrs) = addr_str.to_socket_addrs() {
                    if let Some(addr) = addrs.next() {
                        context.remote_peer.host = HostName::Ip(addr.ip());
                        log::info!("Resolved {} to {}", domain, addr.ip());
                    } else {
                        log::warn!("No IP addresses found for {}", domain);
                    }
                } else {
                    log::warn!("Failed to resolve domain: {}", domain);
                }
            }
        }

        self.inner.create_outbound(context, initial_data).await
    }
}

pub fn create_smart_resolver(
    proxy_host: String,
    proxy_port: u16,
    direct_domains: Vec<String>,
) -> SmartResolver {
    let provider = ProxyPeerProvider {
        host: proxy_host,
        port: proxy_port,
    };

    let redirect = StreamRedirectOutboundFactory::new(provider);
    SmartResolver::new(redirect, direct_domains)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_resolve() {
        let resolver = create_smart_resolver(
            "proxy.example.com".to_string(),
            1234,
            vec!["baidu.com".to_string(), "qq.com".to_string()],
        );

        assert!(resolver.should_resolve("www.baidu.com"));
        assert!(resolver.should_resolve("map.baidu.com"));
        assert!(resolver.should_resolve("qq.com"));
        assert!(!resolver.should_resolve("google.com"));
    }
}
