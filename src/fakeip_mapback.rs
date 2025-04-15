use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex, Weak};
use std::task::{ready, Context, Poll};

use crate::fakeip::FakeIp;
use crate::flow::*;
use log::{debug, trace};

/// FakeIP MapBack处理器
/// 用于将FakeIP分配的IP地址映射回域名
#[derive(Clone)]
pub struct FakeIpMapBackStreamHandler {
    fakeip: Arc<FakeIp>,
    next: Weak<dyn StreamHandler>,
}

impl FakeIpMapBackStreamHandler {
    pub fn new(fakeip: Arc<FakeIp>, next: Weak<dyn StreamHandler>) -> Self {
        Self {
            fakeip,
            next,
        }
    }
    
    // 尝试将主机名从FakeIP映射回域名
    fn map_back_host(&self, host: &mut HostName) {
        if let HostName::Ip(ip) = host {
            if let Some(domain) = self.fakeip.lookup_domain_by_fake_ip(*ip) {
                debug!("FakeIP MapBack: 将 {} 映射回域名 {}", ip, domain);
                *host = HostName::DomainName(domain);
            }
        }
    }
}

impl StreamHandler for FakeIpMapBackStreamHandler {
    fn on_stream(
        &self,
        lower: Box<dyn Stream>,
        initial_data: Buffer,
        mut context: Box<FlowContext>,
    ) {
        let Some(next) = self.next.upgrade() else {
            return;
        };
        
        // 尝试将远程对等方地址从FakeIP映射回域名
        self.map_back_host(&mut context.remote_peer.host);
        
        next.on_stream(lower, initial_data, context)
    }
}

pub struct FakeIpMapBackDatagramSessionHandler {
    fakeip: Arc<FakeIp>,
    next: Weak<dyn DatagramSessionHandler>,
}

impl DatagramSessionHandler for FakeIpMapBackDatagramSessionHandler {
    fn on_session(&self, session: Box<dyn DatagramSession>, mut context: Box<FlowContext>) {
        let Some(next) = self.next.upgrade() else {
            return;
        };
        
        // 尝试将远程对等方地址从FakeIP映射回域名
        if let HostName::Ip(ip) = &context.remote_peer.host {
            if let Some(domain) = self.fakeip.lookup_domain_by_fake_ip(*ip) {
                debug!("FakeIP MapBack: 将 {} 映射回域名 {}", ip, domain);
                context.remote_peer.host = HostName::DomainName(domain);
            }
        }
        
        next.on_session(
            Box::new(FakeIpMapBackDatagramSession {
                fakeip: self.fakeip.clone(),
                lower: session,
                local_forward_mapping: Default::default(),
            }),
            context,
        )
    }
}

struct FakeIpMapBackDatagramSession {
    fakeip: Arc<FakeIp>,
    lower: Box<dyn DatagramSession>,
    local_forward_mapping: HashMap<String, IpAddr>,
}

impl FakeIpMapBackDatagramSessionHandler {
    pub fn new(fakeip: Arc<FakeIp>, next: Weak<dyn DatagramSessionHandler>) -> Self {
        Self {
            fakeip,
            next,
        }
    }
}

impl DatagramSession for FakeIpMapBackDatagramSession {
    fn poll_recv_from(&mut self, cx: &mut Context) -> Poll<Option<(DestinationAddr, Buffer)>> {
        let Some((mut dest, buf)) = ready!(self.lower.as_mut().poll_recv_from(cx)) else {
            return Poll::Ready(None);
        };
        
        // 尝试将目标地址从FakeIP映射回域名
        if let HostName::Ip(ip) = &dest.host {
            // 先复制IP值，避免借用冲突
            let ip_copy = *ip;
            if let Some(domain) = self.fakeip.lookup_domain_by_fake_ip(ip_copy) {
                debug!("FakeIP MapBack: 在接收时将 {} 映射回域名 {}", ip_copy, domain);
                dest.host = HostName::DomainName(domain.clone());
                // 保存映射关系，以便在发送时使用
                self.local_forward_mapping.insert(domain, ip_copy);
            }
        }
        
        Poll::Ready(Some((dest, buf)))
    }

    fn poll_send_ready(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        self.lower.as_mut().poll_send_ready(cx)
    }

    fn send_to(&mut self, mut remote_peer: DestinationAddr, buf: Buffer) {
        // 如果目标是域名，并且我们有缓存的映射，则使用FakeIP
        if let HostName::DomainName(domain) = &remote_peer.host {
            if let Some(ip) = self.local_forward_mapping.get(domain) {
                debug!("FakeIP MapBack: 在发送时将域名 {} 映射为IP {}", domain, ip);
                remote_peer.host = HostName::Ip(*ip);
            }
        }
        
        self.lower.send_to(remote_peer, buf)
    }

    fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        self.lower.as_mut().poll_shutdown(cx)
    }
} 

