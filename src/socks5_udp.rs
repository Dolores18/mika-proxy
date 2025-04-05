use crate::flow::datagram::*;
use crate::flow::*;
use crate::shadowsocks::util::parse_dest;
use futures::ready;
use log::{error, info};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Weak;
use std::task::{Context, Poll};

pub struct Socks5UdpHandler {
    bind_addr: Option<DestinationAddr>,
    next: Weak<dyn DatagramSessionHandler>,
}

impl Socks5UdpHandler {
    pub fn new(bind_addr: Option<DestinationAddr>, next: Weak<dyn DatagramSessionHandler>) -> Self {
        Self { bind_addr, next }
    }
}

impl DatagramSessionHandler for Socks5UdpHandler {
    fn on_session(&self, mut session: Box<dyn DatagramSession>, mut context: Box<FlowContext>) {
        let next = match self.next.upgrade() {
            Some(next) => next,
            None => {
                println!("❌ 上层处理器不可用");
                return;
            }
        };

        println!(
            "✅ 接受新的UDP连接: {:?}:{}",
            context.local_peer.ip(),
            context.local_peer.port()
        );

        // 创建一个新的会话，处理数据转换
        let new_session = Box::new(TransparentSession {
            inner: session,
            first_packet: None,
            client_addr: None,
        });

        println!("🔄 转交给上层处理器");
        // 将新会话交给上层处理器
        next.on_session(new_session, context);
        println!("✅ 成功转交给上层处理器");
    }
}

// 透明代理会话
struct TransparentSession {
    inner: Box<dyn DatagramSession>,
    first_packet: Option<Vec<u8>>,
    client_addr: Option<DestinationAddr>,
}

impl DatagramSession for TransparentSession {
    fn poll_recv_from(&mut self, cx: &mut Context) -> Poll<Option<(DestinationAddr, Buffer)>> {
        match ready!(self.inner.poll_recv_from(cx)) {
            Some((addr, data)) => {
                // 保存客户端地址
                self.client_addr = Some(addr.clone());

                // 跳过前3个字节(RSV和FRAG)
                if data.len() > 3 {
                    // 使用parse_dest解析目标地址
                    if let Some((dest_addr, header_len)) = parse_dest(&data[3..]) {
                        println!("✅ 解析目标地址成功: {:?}", dest_addr);
                        // 提取原始数据（跳过SOCKS5 UDP头部）
                        let original_data = data[3 + header_len..].to_vec();
                        println!("✅ 提取原始数据，长度: {}", original_data.len());
                        return Poll::Ready(Some((dest_addr, original_data)));
                    } else {
                        println!("❌ 解析SOCKS5 UDP目标地址失败");
                    }
                } else {
                    println!("❌ 数据包太短，无法解析SOCKS5 UDP头部");
                }
                Poll::Ready(None)
            }
            None => Poll::Ready(None),
        }
    }

    fn poll_send_ready(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        self.inner.poll_send_ready(cx)
    }

    fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        self.inner.poll_shutdown(cx)
    }

    fn send_to(&mut self, addr: DestinationAddr, buf: Buffer) {
        // 构造SOCKS5 UDP响应
        let mut response = Vec::new();
        // RSV(2) + FRAG(1)
        response.extend_from_slice(&[0, 0, 0]);

        // ATYP: IPv4
        response.push(1);

        // 添加IP地址
        if let HostName::Ip(IpAddr::V4(ip)) = addr.host {
            response.extend_from_slice(&ip.octets());
        }

        // 添加端口
        response.extend_from_slice(&addr.port.to_be_bytes());

        // 添加实际数据
        response.extend_from_slice(&buf);

        println!("📤 发送SOCKS5 UDP响应，总长度: {}", response.len());

        // 直接发送响应，底层会使用正确的客户端地址
        self.inner.send_to(addr, response);
    }
}
