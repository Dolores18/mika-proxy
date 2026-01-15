use std::error::Error as StdError;
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Weak;
use std::task::{Context, Poll};

use hyper::client::connect::{Connected, Connection};
use hyper::rt::Executor;
use hyper::service::Service as TowerService;
use hyper::Uri;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::flow::*;
use smallvec;

#[derive(Clone)]
pub struct FlowAdapterConnector {
    pub next: Weak<dyn StreamOutboundFactory>,
}

pub struct CompatStreamAdapter {
    stream: CompatStream,
    use_h2: bool,
}

pub struct TokioHyperExecutor(tokio::runtime::Handle);

impl TokioHyperExecutor {
    pub fn new_current() -> Self {
        Self(tokio::runtime::Handle::current())
    }
}

impl Executor<Pin<Box<dyn Future<Output = ()> + Send>>> for TokioHyperExecutor {
    fn execute(&self, fut: Pin<Box<dyn Future<Output = ()> + Send>>) {
        self.0.spawn(fut);
    }
}

impl TowerService<Uri> for FlowAdapterConnector {
    type Response = CompatStreamAdapter;

    type Error = Box<dyn StdError + Send + Sync>;

    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        println!("FlowAdapterConnector: 开始创建到 {} 的连接", dst);

        let host = dst
            .authority()
            .expect("h2 url must have authority")
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']');

        println!("FlowAdapterConnector: 解析主机名: {}", host);

        let next_host = if let Ok(ip) = Ipv4Addr::from_str(host) {
            HostName::Ip(ip.into())
        } else if let Ok(ip) = Ipv6Addr::from_str(host) {
            HostName::Ip(ip.into())
        } else {
            let mut host = host.to_string();
            if !host.ends_with('.') {
                host.push('.');
            }
            HostName::from_domain_name(host).expect("invalid hostname")
        };

        let remote_peer = DestinationAddr {
            host: next_host.clone(),
            port: dst
                .port_u16()
                .unwrap_or(if dst.scheme_str() == Some("https") {
                    443
                } else {
                    80
                }),
        };

        println!(
            "FlowAdapterConnector: 目标地址: {:?}:{:?}",
            next_host, remote_peer.port
        );

        let next = self.next.clone();
        Box::pin(async move {
            let next = next.upgrade().ok_or("next is gone")?;

            let mut ctx = FlowContext::new(
                SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), 0),
                remote_peer,
            );
            
            // 根据协议选择应用层协议
            let is_https = dst.scheme_str() == Some("https");
            if is_https {
                ctx.application_layer_protocol = smallvec::smallvec!["h2"];
                println!("FlowAdapterConnector: 开始创建 TCP 连接, 使用 HTTP/2");
            } else {
                ctx.application_layer_protocol = smallvec::smallvec!["http/1.1"];
                println!("FlowAdapterConnector: 开始创建 TCP 连接, 使用 HTTP/1.1");
            }

            let (stream, inital_data) = next
                .create_outbound(&mut ctx, &[])
                .await
                .map_err(|e| e.to_string())?;

            // 确定是否使用HTTP/2
            let use_h2 = is_https;
            println!(
                "FlowAdapterConnector: TCP 连接创建成功, 使用 H2: {}",
                use_h2
            );

            Ok(CompatStreamAdapter {
                stream: CompatStream {
                    inner: stream,
                    reader: StreamReader::new(4096, inital_data),
                },
                use_h2,
            })
        })
    }
}

impl AsyncRead for CompatStreamAdapter {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for CompatStreamAdapter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl Connection for CompatStreamAdapter {
    fn connected(&self) -> Connected {
        println!(
            "Negotiated protocol: {}",
            if self.use_h2 { "h2" } else { "http/1.1" }
        );
        if self.use_h2 {
            Connected::new().negotiated_h2()
        } else {
            Connected::new()
        }
    }
}
