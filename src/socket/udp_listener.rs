use std::collections::BTreeMap;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Weak};
use std::task::{ready, Context, Poll};

use flume::{bounded, SendError};
use socket2::Socket;

use crate::flow::*;

pub fn listen_udp(
    next: Weak<dyn DatagramSessionHandler>,
    addr: impl ToSocketAddrs + Send + 'static,
) -> io::Result<tokio::task::JoinHandle<()>> {
    let mut session_map = BTreeMap::new();
    
    // 获取地址
    let addr = addr.to_socket_addrs()?.next().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "无效的UDP监听地址")
    })?;
    
    // 使用socket2创建socket，以便设置更多选项
    let socket = Socket::new(
        if addr.is_ipv4() { socket2::Domain::IPV4 } else { socket2::Domain::IPV6 },
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    
    // 设置重用地址和端口选项
    socket.set_reuse_address(true)?;
    #[cfg(not(windows))]
    socket.set_reuse_port(true)?;
    
    // 设置非阻塞模式
    socket.set_nonblocking(true)?;
    
    // 绑定地址并转换为标准库socket
    socket.bind(&addr.into())?;
    let listener = socket.into();
    
    Ok(tokio::spawn(async move {
        let listener = Arc::new(
            tokio::net::UdpSocket::from_std(listener)
                .expect("Calling listen_udp when runtime is not set"),
        );
        let listen_addr: DestinationAddr = match listener.local_addr() {
            Ok(addr) => addr,
            // TODO: log error
            Err(_) => return,
        }
        .into();
        let mut buf = [0u8; 4096];
        loop {
            let (size, from) = match listener.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(_) => {
                    // TODO: log error
                    break;
                }
            };
            let tx = session_map.entry(from).or_insert_with(|| {
                let (tx, rx) = bounded(64);
                if let Some(next) = next.upgrade() {
                    let context =
                        Box::new(FlowContext::new_af_sensitive(from, listen_addr.clone()));
                    let client_addr = DestinationAddr {
                        host: HostName::Ip(from.ip()),
                        port: from.port(),
                    };

                    next.on_session(
                        Box::new(MultiplexedDatagramSessionAdapter::new(
                            InboundUdpSession {
                                socket: listener.clone(),
                                tx_buf: None,
                                client_addr: client_addr,
                            },
                            rx.into_stream(),
                            120,
                        )),
                        context,
                    );
                }
                tx
            });
            if let Err(SendError(_)) = tx
                .send_async((listen_addr.clone(), buf[..size].to_vec()))
                .await
            {
                session_map.remove(&from);
            }
        }
    }))
}

struct InboundUdpSession {
    socket: Arc<tokio::net::UdpSocket>,
    tx_buf: Option<(SocketAddr, Buffer)>,
    client_addr: DestinationAddr,
}

impl MultiplexedDatagramSession for InboundUdpSession {
    fn on_close(&mut self) {}

    fn poll_send_ready(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        let _ = ready!(self.socket.poll_send_ready(cx)).ok();
        if let Some((addr, buf)) = &mut self.tx_buf {
            let _ = ready!(self.socket.poll_send_to(cx, buf, *addr));
            self.tx_buf = None;
        }
        Poll::Ready(())
    }

    fn send_to(&mut self, _: DestinationAddr, buf: Buffer) {
        if let HostName::Ip(ip) = self.client_addr.host {
            self.tx_buf = Some((SocketAddr::new(ip, self.client_addr.port), buf));
        }
    }
}
