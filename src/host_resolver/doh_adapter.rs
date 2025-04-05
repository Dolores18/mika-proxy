use std::pin::Pin;
use std::sync::Weak;
use std::task::{ready, Context, Poll};

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use futures::{FutureExt, SinkExt};
use http::header::{ACCEPT, CONTENT_TYPE};
use http::uri::Uri;
use http::{Method, Request};
use hyper::body::{Bytes, HttpBody};
use hyper::client::ResponseFuture;
use hyper::{Body, Client as HyperClient};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use log::info;
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

use crate::flow::*;
use crate::h2::{FlowAdapterConnector, TokioHyperExecutor};

pub struct DohDatagramAdapterFactory {
    client: HyperClient<HttpsConnector<FlowAdapterConnector>, Body>,
    url: Uri,
}

#[derive(Default)]
enum DohDatagramAdapterTxState {
    #[default]
    Idle,
    PendingResponse(ResponseFuture),
    ReadingResponse(Body, Vec<Bytes>),
}

struct DohDatagramAdapter {
    url: Uri,
    client: HyperClient<HttpsConnector<FlowAdapterConnector>, Body>,
    tx_state: DohDatagramAdapterTxState,
    rx_chan: (Option<PollSender<Buffer>>, mpsc::Receiver<Buffer>),
}

impl DohDatagramAdapterFactory {
    pub fn new(url: Uri, next: Weak<dyn StreamOutboundFactory>) -> Self {
        // 创建自定义连接器
        let flow_connector = FlowAdapterConnector { next };

        // 使用 hyper_rustls 的构建器 API
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
            .expect("failed to load native root certificates")
            .https_only()
            .enable_http2()
            .wrap_connector(flow_connector);

        // 创建支持 HTTP2 的 hyper client
        let client = hyper::Client::builder()
            .http2_only(false) // 允许回退到 HTTP/1.1
            .http2_keep_alive_interval(std::time::Duration::from_secs(1))
            .http2_keep_alive_timeout(std::time::Duration::from_secs(5))
            .http2_adaptive_window(true)
            .retry_canceled_requests(true)
            .set_host(true)
            .pool_idle_timeout(std::time::Duration::from_secs(30))
            .pool_max_idle_per_host(1)
            .executor(TokioHyperExecutor::new_current())
            .build::<_, Body>(https);

        //println!("Created DoH client for URL: {}", url);

        Self { client, url }
    }
}

#[async_trait]
impl DatagramSessionFactory for DohDatagramAdapterFactory {
    async fn bind(&self, _context: Box<FlowContext>) -> FlowResult<Box<dyn DatagramSession>> {
        let (rx_tx, rx_rx) = mpsc::channel(4);
        Ok(Box::new(DohDatagramAdapter {
            client: self.client.clone(),
            tx_state: Default::default(),
            rx_chan: (Some(PollSender::new(rx_tx)), rx_rx),
            url: self.url.clone(),
        }))
    }
}

impl DatagramSession for DohDatagramAdapter {
    fn poll_recv_from(&mut self, cx: &mut Context) -> Poll<Option<(DestinationAddr, Buffer)>> {
        let buf = match ready!(self.rx_chan.1.poll_recv(cx)) {
            Some(buf) => buf,
            None => return Poll::Ready(None),
        };
        let dummy_addr = DestinationAddr {
            host: HostName::Ip([1, 1, 1, 1].into()),
            port: 53,
        };
        Poll::Ready(Some((dummy_addr, buf)))
    }

    fn poll_send_ready(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        loop {
            let Some(tx) = self.rx_chan.0.as_mut() else {
                break Poll::Ready(());
            };
            let _ = ready!(tx.poll_ready_unpin(cx)).ok();
            match std::mem::take(&mut self.tx_state) {
                DohDatagramAdapterTxState::Idle => break Poll::Ready(()),
                DohDatagramAdapterTxState::PendingResponse(mut fut) => match fut.poll_unpin(cx) {
                    Poll::Ready(Ok(resp)) => {
                        println!("Received DoH response with status: {}", resp.status());
                        if resp.status().is_success() {
                            self.tx_state = DohDatagramAdapterTxState::ReadingResponse(
                                resp.into_body(),
                                Vec::new(),
                            );
                        } else {
                            let status = resp.status();
                            self.tx_state = DohDatagramAdapterTxState::ReadingResponse(
                                resp.into_body(),
                                Vec::new(),
                            );
                            println!("Error status: {}, reading error body...", status);
                        }
                    }
                    Poll::Ready(Err(e)) => {
                        println!("Request error: {:?}", e);
                        self.rx_chan.0 = None;
                    }
                    Poll::Pending => {
                        self.tx_state = DohDatagramAdapterTxState::PendingResponse(fut);
                        break Poll::Pending;
                    }
                },
                DohDatagramAdapterTxState::ReadingResponse(mut body, mut byte_bufs) => {
                    let current_buf_len = byte_bufs.iter().map(|c| c.len()).sum();
                    match Pin::new(&mut body).poll_data(cx) {
                        Poll::Ready(None) => {
                            let mut buf = Vec::with_capacity(current_buf_len);
                            for b in byte_bufs {
                                buf.extend_from_slice(&b[..]);
                            }
                            info!(
                                "Successfully received DoH response with {} bytes",
                                current_buf_len
                            );
                            info!(
                                "Response content (first 50 bytes): {:?}",
                                &buf[..50.min(buf.len())]
                            );
                            if tx.start_send_unpin(buf).is_err() {
                                self.rx_chan.0 = None;
                            }
                            self.tx_state = DohDatagramAdapterTxState::Idle;
                        }
                        Poll::Ready(Some(Err(e))) => {
                            info!("Error reading DoH response: {:?}", e);
                            self.rx_chan.0 = None;
                        }
                        Poll::Ready(Some(Ok(chunk))) => {
                            info!("Response chunk: {:?}", String::from_utf8_lossy(&chunk));
                            byte_bufs.push(chunk);
                            self.tx_state =
                                DohDatagramAdapterTxState::ReadingResponse(body, byte_bufs);
                        }
                        Poll::Pending => {
                            self.tx_state =
                                DohDatagramAdapterTxState::ReadingResponse(body, byte_bufs);
                            break Poll::Pending;
                        }
                    }
                }
            }
        }
    }

    fn send_to(&mut self, _remote_peer: DestinationAddr, buf: Buffer) {
        info!("Sending DoH request to {}", self.url);
        info!("DNS query packet length: {}", buf.len());
        info!("DNS header: {:?}", &buf[..12]);

        let req = Request::builder()
            .method(Method::POST)
            .uri(self.url.clone())
            .header(CONTENT_TYPE, "application/dns-message")
            .header(ACCEPT, "application/dns-message")
            .header("Content-Length", buf.len().to_string())
            .body(buf.into())
            .unwrap();

        info!("Full request headers: {:?}", req.headers());

        let fut = self.client.request(req);
        self.tx_state = DohDatagramAdapterTxState::PendingResponse(fut);
    }

    fn poll_shutdown(&mut self, _cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        Poll::Ready(Ok(()))
    }
}
