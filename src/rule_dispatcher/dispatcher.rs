use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Weak};

use async_trait::async_trait;
use futures::future::join;
use smallvec::SmallVec;

use super::*;

pub type ActionSet = SmallVec<[Action; 8]>;

pub struct RuleDispatcher {
    pub resolver: Option<Weak<dyn Resolver>>, // TODO: set to None when no IP rules
    pub rule_set: set::RuleSet,
    pub actions: ActionSet,
    pub fallback: Action,
    pub me: Weak<Self>,
}

struct AsyncMatchContext {
    src: Option<SocketAddr>,
    dst_domain: String,
    dst_port: Option<u16>,
    resolver: Arc<dyn Resolver>,
    // 缓存解析结果
    resolved_ipv4: Option<Ipv4Addr>,
    resolved_ipv6: Option<Ipv6Addr>,
}

impl AsyncMatchContext {
    async fn try_match<'m>(&mut self, me: &'m RuleDispatcher) -> FlowResult<&'m Action> {
        // 首先解析域名为IP地址，供规则匹配使用
        
        let (v4_res, v6_res) = join(
            self.resolver.resolve_ipv4(self.dst_domain.clone()),
            self.resolver.resolve_ipv6(self.dst_domain.clone()),
        )
        .await;
        
        
        // 保存解析结果到缓存
        if let Ok(ips) = &v4_res {
            if !ips.is_empty() {
                self.resolved_ipv4 = Some(ips[0]);
                println!("🔄 成功解析IPv4地址用于规则匹配: {} -> {}", self.dst_domain, ips[0]);
            }
        }
        
        if let Ok(ips) = &v6_res {
            if !ips.is_empty() {
                self.resolved_ipv6 = Some(ips[0]);
            }
        }
        
        let dst_ip_v4 = v4_res.unwrap_or_default().first().copied();
        let dst_ip_v6 = v6_res.unwrap_or_default().first().copied();
        let dst_domain = Some(self.dst_domain.as_str());
        
        // 使用解析结果以及原始域名进行规则匹配
        let res = me
            .rule_set
            .r#match(self.src, dst_ip_v4, dst_ip_v6, dst_domain, self.dst_port)
            .map(|id| me.actions.get(id.0 as usize));
            
        // 返回匹配的Action
        match res {
            Some(Some(a)) => Ok(a),
            Some(None) => Err(FlowError::NoOutbound),
            None => Ok(&me.fallback),
        }
    }
}

enum TryMatchResult<'a> {
    Matched(&'a Action),
    NeedAsync(AsyncMatchContext),
    Err(FlowError),
}

impl RuleDispatcher {
    fn try_match(&'_ self, context: &FlowContext) -> TryMatchResult<'_> {
        let src = Some(context.local_peer);
        let dst_port = Some(context.remote_peer.port);
        let mut dst_ip_v4 = None;
        let mut dst_ip_v6 = None;
        let mut dst_domain = None;
        match (&context.remote_peer.host, &self.resolver) {
            (HostName::DomainName(domain), Some(resolver))
                if self.rule_set.should_resolve(src, domain, dst_port) =>
            {
                let Some(resolver) = resolver.upgrade() else {
                    return TryMatchResult::Err(FlowError::NoOutbound);
                };
                return TryMatchResult::NeedAsync(AsyncMatchContext {
                    src,
                    dst_domain: domain.clone(),
                    dst_port,
                    resolver,
                    resolved_ipv4: None,
                    resolved_ipv6: None,
                });
            }
            (HostName::DomainName(domain), _) => {
                println!("🔍 直接匹配域名规则: {}", domain);
                dst_domain = Some(domain.as_str())
            }
            (HostName::Ip(ip), _) => {
                println!("🔍 匹配 IP 规则: {}", ip);
                match ip {
                    IpAddr::V4(v4) => dst_ip_v4 = Some(*v4),
                    IpAddr::V6(v6) => dst_ip_v6 = Some(*v6),
                }
            }
        }
        let res = self
            .rule_set
            .r#match(src, dst_ip_v4, dst_ip_v6, dst_domain, dst_port)
            .map(|id| {
                println!("✅ 匹配到规则: RuleHandle({:?})", id);
                let action = self.actions.get(id.0 as usize);
                if let Some(action) = action {
                    if let Some(tcp_next) = action.tcp_next.upgrade() {
                        println!(
                            "👉 Action TCP handler: {:?}",
                            std::any::type_name_of_val(&*tcp_next)
                        );
                    }
                    if let Some(resolver) = action.resolver.upgrade() {
                        println!(
                            "👉 Action resolver: {:?}",
                            std::any::type_name_of_val(&*resolver)
                        );
                    }
                }
                action
            });
        match res {
            Some(Some(a)) => {
                println!("👉 使用匹配的 Action");
                TryMatchResult::Matched(a)
            }
            Some(None) => {
                println!("❌ 规则匹配失败: NoOutbound");
                TryMatchResult::Err(FlowError::NoOutbound)
            }
            None => {
                println!("⚠️ 未匹配规则，使用 fallback");
                TryMatchResult::Matched(&self.fallback)
            }
        }
    }
    fn try_match_with(
        &self,
        mut context: Box<FlowContext>,
        cb: impl FnOnce(Box<FlowContext>, &Action) + Send + 'static,
    ) {
        match self.try_match(&context) {
            TryMatchResult::Matched(a) => {
                cb(context, a)
            },
            TryMatchResult::NeedAsync(mut async_ctx) => {
                let me = self.me.upgrade().unwrap();
                
                tokio::spawn(async move {
                    // 执行规则匹配并获取适当的Action
                    match async_ctx.try_match(&me).await {
                        Ok(a) => {
                            
                            // 在这里，如果源是域名，将其替换为已缓存的IP
                            if let HostName::DomainName(_) = context.remote_peer.host {
                                
                                // 优先使用IPv4地址
                                if let Some(ipv4) = async_ctx.resolved_ipv4 {
                                    // 替换context中的域名为IP
                                    context.remote_peer.host = HostName::Ip(IpAddr::V4(ipv4));
                                } else if let Some(ipv6) = async_ctx.resolved_ipv6 {
                                    println!("🔄 使用缓存的解析结果更新Context: {} -> {}", async_ctx.dst_domain, ipv6);
                                    // 替换context中的域名为IP
                                    context.remote_peer.host = HostName::Ip(IpAddr::V6(ipv6));
                                }
                            }
                            
                            // 调用回调函数
                            cb(context, a)
                        },
                        Err(e) => {
                            // TODO: log error
                            return;
                        }
                    }
                });
            }
            TryMatchResult::Err(e) => {
                // TODO: log error
                return;
            }
        }
    }
    async fn match_domain(&self, domain: &str) -> FlowResult<&Action> {
        if let (Some(resolver), true) = (
            self.resolver.as_ref(),
            self.rule_set.should_resolve(None, domain, None),
        ) {
            let mut ctx = AsyncMatchContext {
                src: None,
                dst_domain: domain.into(),
                dst_port: None,
                resolver: resolver.upgrade().ok_or(FlowError::NoOutbound)?,
                resolved_ipv4: None,
                resolved_ipv6: None,
            };
            ctx.try_match(self).await
        } else {
            let res = self
                .rule_set
                .r#match(None, None, None, Some(domain), None)
                .map(|id| self.actions.get(id.0 as usize));
            match res {
                Some(Some(a)) => Ok(a),
                Some(None) => Err(FlowError::NoOutbound),
                None => Ok(&self.fallback),
            }
        }
    }
}

impl StreamHandler for RuleDispatcher {
    fn on_stream(&self, lower: Box<dyn Stream>, initial_data: Buffer, context: Box<FlowContext>) {
        self.try_match_with(context, |context, a| {
            if let Some(tcp_next) = a.tcp_next.upgrade() {
                tcp_next.on_stream(lower, initial_data, context)
            }
        })
    }
}

#[async_trait]
impl Resolver for RuleDispatcher {
    async fn resolve_ipv4(&self, domain: String) -> ResolveResultV4 {
        let action = self.match_domain(&domain).await?;
        let resolver = action.resolver.upgrade().ok_or(FlowError::NoOutbound)?;
        resolver.resolve_ipv4(domain).await
    }
    async fn resolve_ipv6(&self, domain: String) -> ResolveResultV6 {
        let action = self.match_domain(&domain).await?;
        let resolver = action.resolver.upgrade().ok_or(FlowError::NoOutbound)?;        println!("📣 [RuleDispatcher::resolve_ipv6] 将解析请求委托给匹配的规则解析器: {}", domain);
        resolver.resolve_ipv6(domain).await
    }
}
