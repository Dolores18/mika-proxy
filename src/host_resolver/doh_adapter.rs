use std::pin::Pin;
use std::sync::Weak;
use std::task::{ready, Context, Poll};
use std::time::Instant;

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
use crate::host_resolver::dns_packet_parser;
use crate::flow::*;
use crate::h2::{FlowAdapterConnector, TokioHyperExecutor};
use rustls;

pub struct DohDatagramAdapterFactory {
    client_https: HyperClient<HttpsConnector<FlowAdapterConnector>, Body>,
    client_http: HyperClient<hyper::client::HttpConnector, Body>,
    url: Uri,
}

#[derive(Default)]
enum DohDatagramAdapterTxState {
    #[default]
    Idle,
    PendingResponse(ResponseFuture),
    ReadingResponse(Body, Vec<Bytes>, u16),
}

struct DohDatagramAdapter {
    url: Uri,
    client_https: HyperClient<HttpsConnector<FlowAdapterConnector>, Body>,
    client_http: HyperClient<hyper::client::HttpConnector, Body>,
    tx_state: DohDatagramAdapterTxState,
    rx_chan: (Option<PollSender<Buffer>>, mpsc::Receiver<Buffer>),
    current_query_id: u16,
    request_start_time: Option<Instant>,
}

impl DohDatagramAdapterFactory {
    pub fn new(url: Uri, next: Weak<dyn StreamOutboundFactory>) -> Self {
        // 创建自定义连接器
        let flow_connector = FlowAdapterConnector { next };

        let is_https = url.scheme() == Some(&http::uri::Scheme::HTTPS);
        println!("Creating DoH client for URL: {} (is_https: {})", url, is_https);

        // 创建 HTTPS 客户端
        let https_connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
            .expect("failed to load native root certificates")
            .https_or_http() // 允许HTTP连接
            .enable_http2()
            .wrap_connector(flow_connector.clone());
        
        let client_https = hyper::Client::builder()
            .http2_only(false) // 允许回退到 HTTP/1.1
            .http2_keep_alive_interval(std::time::Duration::from_secs(1))
            .http2_keep_alive_timeout(std::time::Duration::from_secs(5))
            .http2_adaptive_window(true)
            .retry_canceled_requests(true)
            .set_host(true)
            .pool_idle_timeout(std::time::Duration::from_secs(30))
            .pool_max_idle_per_host(1)
            .executor(TokioHyperExecutor::new_current())
            .build::<_, Body>(https_connector);

        // 创建纯 HTTP 客户端 (用于本地连接)
        let mut http_connector = hyper::client::HttpConnector::new();
        http_connector.enforce_http(false);
        
        let client_http = hyper::Client::builder()
            .http2_only(true) // 强制使用 HTTP/2
            .http2_keep_alive_interval(std::time::Duration::from_secs(1))
            .http2_keep_alive_timeout(std::time::Duration::from_secs(5))
            .http2_adaptive_window(true)
            .retry_canceled_requests(true)
            .set_host(true)
            .pool_idle_timeout(std::time::Duration::from_secs(30))
            .pool_max_idle_per_host(1)
            .executor(TokioHyperExecutor::new_current())
            .build::<_, Body>(http_connector);

        println!("DoH客户端创建完成，支持HTTP和HTTPS，URL: {}", url);

        Self { client_https, client_http, url }
    }
}

#[async_trait]
impl DatagramSessionFactory for DohDatagramAdapterFactory {
    async fn bind(&self, _context: Box<FlowContext>) -> FlowResult<Box<dyn DatagramSession>> {
        let (rx_tx, rx_rx) = mpsc::channel(4);
        Ok(Box::new(DohDatagramAdapter {
            client_https: self.client_https.clone(),
            client_http: self.client_http.clone(),
            tx_state: Default::default(),
            rx_chan: (Some(PollSender::new(rx_tx)), rx_rx),
            url: self.url.clone(),
            current_query_id: 0,
            request_start_time: None,
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
                        // 计算并打印从请求到收到响应头的时间（毫秒）
                        if let Some(start_time) = self.request_start_time {
                            let duration = start_time.elapsed();
                            println!("【计时】从DoH请求到响应头: {}ms", duration.as_millis());
                        }
                        
                        println!("Received DoH response with status: {}", resp.status());
                        
                        // 使用成员变量中的查询ID
                        let query_id = self.current_query_id;
                        
                        if resp.status().is_success() {
                            self.tx_state = DohDatagramAdapterTxState::ReadingResponse(
                                resp.into_body(),
                                Vec::new(),
                                query_id,  // 传递查询ID
                            );
                        } else {
                            let status = resp.status();
                            self.tx_state = DohDatagramAdapterTxState::ReadingResponse(
                                resp.into_body(),
                                Vec::new(),
                                query_id,  // 传递查询ID
                            );
                            println!("Error status: {}, reading error body...", status);
                        }
                    }
                    Poll::Ready(Err(e)) => {
                        // 打印请求错误和已经花费的时间
                        if let Some(start_time) = self.request_start_time.take() {
                            let duration = start_time.elapsed();
                            println!("【计时】请求失败耗时: {}ms, 错误: {:?}", duration.as_millis(), e);
                        } else {
                            println!("Request error: {:?}", e);
                        }
                        self.rx_chan.0 = None;
                    }
                    Poll::Pending => {
                        self.tx_state = DohDatagramAdapterTxState::PendingResponse(fut);
                        break Poll::Pending;
                    }
                },
                DohDatagramAdapterTxState::ReadingResponse(mut body, mut byte_bufs, query_id) => {
                    let current_buf_len = byte_bufs.iter().map(|c| c.len()).sum();
                    match Pin::new(&mut body).poll_data(cx) {
                        Poll::Ready(None) => {
                            // 计算并打印从请求到完整接收响应的总时间（毫秒）
                            if let Some(start_time) = self.request_start_time.take() {
                                let duration = start_time.elapsed();
                                println!("【计时】DoH完整请求-响应周期: {}ms，数据大小: {}字节", 
                                         duration.as_millis(), current_buf_len);
                            }
                            
                            let mut buf = Vec::with_capacity(current_buf_len);
                            for b in byte_bufs {
                                buf.extend_from_slice(&b[..]);
                            }
                            info!(
                                "Successfully received DoH response with {} bytes",
                                current_buf_len
                            );
                            
                            // 检查URL是否为JSON API端点
                            let path = self.url.path();
                            let is_json_api = path.ends_with("/resolve") || path.ends_with("/resolver");
                            
                            if is_json_api {
                                // 打印JSON响应内容
                                match std::str::from_utf8(&buf) {
                                    Ok(json_str) => {
                                        println!("JSON API Response: {}", json_str);
                                        
                                        // 将JSON解析为DNS响应，使用传递的查询ID
                                        if let Some(dns_packet) = crate::host_resolver::dns_packet_parser::json_to_dns_message(json_str, query_id) {
                                            println!("成功将JSON转换为DNS二进制包，长度: {}, 查询ID: {}", dns_packet.len(), query_id);
                                            buf = dns_packet;
                                        } else {
                                            println!("错误：无法将JSON转换为DNS包");
                                        }
                                    },
                                    Err(_) => println!("JSON API Response: 无法解析为UTF-8字符串")
                                }
                            } else {
                                // 对于标准二进制响应，只打印前面一部分
                                info!(
                                    "Standard DoH response (first 50 bytes): {:?}",
                                    &buf[..50.min(buf.len())]
                                );
                            }
                            
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
                            // 打印每个响应块
                            if let Ok(chunk_str) = std::str::from_utf8(&chunk) {
                                info!("Response chunk: {}", chunk_str);
                            } else {
                                info!("Response chunk (binary): {} bytes", chunk.len());
                            }
                            byte_bufs.push(chunk);
                            self.tx_state =
                                DohDatagramAdapterTxState::ReadingResponse(body, byte_bufs, query_id);
                        }
                        Poll::Pending => {
                            self.tx_state =
                                DohDatagramAdapterTxState::ReadingResponse(body, byte_bufs, query_id);
                            break Poll::Pending;
                        }
                    }
                }
            }
        }
    }

    fn send_to(&mut self, _remote_peer: DestinationAddr, buf: Buffer) {
        // 记录请求开始时间
        self.request_start_time = Some(Instant::now());
        
        info!("Sending DoH request to {}", self.url);
        info!("DNS query packet length: {}", buf.len());
        
        // 检查URL是否为 /resolve 或 /resolver 端点
        let path = self.url.path();
        let is_json_api = path.ends_with("/resolve") || path.ends_with("/resolver");
        
        // 判断是否使用HTTPS
        let is_https = self.url.scheme() == Some(&http::uri::Scheme::HTTPS);
        
        if is_json_api {
            // 使用新模块解析DNS查询包
            match crate::host_resolver::dns_packet_parser::parse_dns_query(&buf) {
                Some(query_info) => {
                    // 保存查询ID到结构体
                    self.current_query_id = query_info.dns_id;
                    
                    // 构建GET请求，带上正确的参数
                    let params = crate::host_resolver::dns_packet_parser::dns_query_to_doh_params(&query_info);
                    let uri = format!("{}?{}", self.url, params);
                    
                    println!("发送JSON API DoH请求: {}, 查询ID: {}", uri, self.current_query_id);
                    
                    let req = Request::builder()
                        .method(Method::GET)
                        .uri(uri)
                        .header(ACCEPT, "application/dns-json")
                        .body(Body::empty())
                        .unwrap();
                    
                    info!("JSON API请求头: {:?}", req.headers());
                    
                    // 根据URL类型选择客户端
                    if is_https {
                        let fut = self.client_https.request(req);
                        self.tx_state = DohDatagramAdapterTxState::PendingResponse(fut);
                    } else {
                        let fut = self.client_http.request(req);
                        self.tx_state = DohDatagramAdapterTxState::PendingResponse(fut);
                    }
                }
                None => {
                    // 如果无法解析，回退到标准DoH请求
                    let req = Request::builder()
                        .method(Method::POST)
                        .uri(self.url.clone())
                        .header(CONTENT_TYPE, "application/dns-message")
                        .header(ACCEPT, "application/dns-message")
                        .header("Content-Length", buf.len().to_string())
                        .body(buf.into())
                        .unwrap();

                    info!("标准DoH请求头: {:?}", req.headers());
                    
                    // 根据URL类型选择客户端
                    if is_https {
                        let fut = self.client_https.request(req);
                        self.tx_state = DohDatagramAdapterTxState::PendingResponse(fut);
                    } else {
                        let fut = self.client_http.request(req);
                        self.tx_state = DohDatagramAdapterTxState::PendingResponse(fut);
                    }
                }
            }
        } else {
            // 提取查询ID，用于标准DoH请求
            if let Some(query_info) = crate::host_resolver::dns_packet_parser::parse_dns_query(&buf) {
                self.current_query_id = query_info.dns_id;
            }
            
            // 原始的二进制DoH请求方法，不变
            let req = Request::builder()
                .method(Method::POST)
                .uri(self.url.clone())
                .header(CONTENT_TYPE, "application/dns-message")
                .header(ACCEPT, "application/dns-message")
                .header("Content-Length", buf.len().to_string())
                .body(buf.into())
                .unwrap();

            info!("Full request headers: {:?}", req.headers());
            
            // 根据URL类型选择客户端
            if is_https {
                let fut = self.client_https.request(req);
                self.tx_state = DohDatagramAdapterTxState::PendingResponse(fut);
            } else {
                let fut = self.client_http.request(req);
                self.tx_state = DohDatagramAdapterTxState::PendingResponse(fut);
            }
        }
    }

    fn poll_shutdown(&mut self, _cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        Poll::Ready(Ok(()))
    }
}
