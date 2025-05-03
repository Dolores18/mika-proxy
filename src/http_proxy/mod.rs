pub(crate) mod util;

use std::io::Write;
use std::sync::Weak;

use crate::flow::*;
use async_trait::async_trait;
use base64::prelude::BASE64_STANDARD;
use base64::prelude::*;
use futures::future::poll_fn;
use log::{debug, error, info};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::time::{timeout, Duration};
const REQ_BEFORE_ADDR: &[u8] = b"CONNECT ";
const REQ_AFTER_ADDR_PART: &[u8] = b" HTTP/1.1";
const BASIC_AUTH_HEADER: &[u8] = b"\r\nAuthorization: Basic ";

pub struct HttpProxyOutboundFactory {
    req_after_addr: Vec<u8>,
    next: Weak<dyn StreamOutboundFactory>,
}

impl HttpProxyOutboundFactory {
    pub fn new(
        cred: Option<(&'_ [u8], &'_ [u8])>,
        next: Weak<dyn StreamOutboundFactory>,
    ) -> HttpProxyOutboundFactory {
        fn estimate_b64_len(l: usize) -> usize {
            l * 4 / 3 + 4
        }
        let (cred_plain, auth_header) = cred
            .map(|(user, pass)| {
                let mut cred_plain = Vec::with_capacity(user.len() + pass.len() + 1);
                cred_plain.extend_from_slice(user);
                cred_plain.push(b':');
                cred_plain.extend_from_slice(pass);
                (cred_plain, BASIC_AUTH_HEADER)
            })
            .unwrap_or_default();
        let cred_plain_b64_len = estimate_b64_len(cred_plain.len());
        let mut req_after_addr = Vec::with_capacity(
            REQ_AFTER_ADDR_PART.len() + auth_header.len() + cred_plain_b64_len + 4,
        );
        req_after_addr.extend_from_slice(REQ_AFTER_ADDR_PART);
        req_after_addr.extend_from_slice(auth_header);
        {
            // Append credential
            let offset = req_after_addr.len();
            req_after_addr.resize(offset + cred_plain_b64_len, 0);
            let written = BASE64_STANDARD
                .encode_slice(cred_plain, &mut req_after_addr[offset..])
                .expect("Estimated base64 length is not enough");
            req_after_addr.resize(offset + written, 0);
        }
        req_after_addr.extend_from_slice(b"\r\n\r\n");
        HttpProxyOutboundFactory {
            req_after_addr,
            next,
        }
    }
}

#[async_trait]
impl StreamOutboundFactory for HttpProxyOutboundFactory {
    async fn create_outbound(
        &self,
        context: &mut FlowContext,
        initial_data: &'_ [u8],
    ) -> FlowResult<(Box<dyn Stream>, Buffer)> {
        let outbound_factory = self.next.upgrade().ok_or(FlowError::NoOutbound)?;
        let (mut lower, initial_res) = {
            let mut req = Vec::with_capacity(
                REQ_BEFORE_ADDR.len() + 261 + self.req_after_addr.len() + initial_data.len(),
            );
            req.extend_from_slice(REQ_BEFORE_ADDR);
            match &context.remote_peer.host {
                HostName::DomainName(domain) => {
                    let domain = domain.trim_end_matches('.').as_bytes();
                    req.extend_from_slice(domain)
                }
                HostName::Ip(ip) => write!(&mut req, "{}", ip).unwrap(),
            };
            req.push(b':');
            let mut port_buf = [0u8; 5];
            let port_len = util::format_u16(context.remote_peer.port, &mut port_buf);
            req.extend_from_slice(&port_buf[..port_len]);
            req.extend_from_slice(&self.req_after_addr[..]);
            req.extend_from_slice(initial_data);
            outbound_factory.create_outbound(context, &req[..]).await?
        };
        let initial_res = {
            let mut reader = StreamReader::new(4096, initial_res);
            let mut expected_header_size = 1;
            let mut code = None;
            let mut res_header_size = 0;
            let mut on_data = |data: &mut [u8]| {
                if data.len() > 1024 {
                    return Err(FlowError::UnexpectedData);
                }
                let mut res_headers = [httparse::EMPTY_HEADER; 4];
                let mut res = httparse::Response::new(&mut res_headers[..]);
                let ret = res.parse(data).map_err(|_| FlowError::UnexpectedData)?;
                Ok(match ret {
                    httparse::Status::Partial => Some(data.len()),
                    httparse::Status::Complete(len) => {
                        res_header_size = len;
                        code = res.code;
                        None
                    }
                })
            };
            while let Some(read_len) = reader
                .peek_at_least(&mut *lower, expected_header_size, &mut on_data)
                .await??
            {
                expected_header_size = read_len + 1;
            }
            code.filter(|c| (200..=299).contains(c))
                .ok_or(FlowError::UnexpectedData)?;
            reader.advance(res_header_size);
            reader.into_buffer().unwrap_or_default()
        };
        Ok((lower, initial_res))
    }
}

pub struct HttpHandler {
    auth_header: Option<Arc<String>>,
    next: Weak<dyn StreamHandler>,
}

impl HttpHandler {
    pub fn new(cred: Option<(&[u8], &[u8])>, next: Weak<dyn StreamHandler>) -> Self {
        let auth_header = cred.map(|(user, pass)| {
            let cred = format!(
                "{}:{}",
                String::from_utf8_lossy(user),
                String::from_utf8_lossy(pass)
            );
            format!("Basic {}", base64::encode(cred.as_bytes()))
        });

        Self {
            auth_header: auth_header.map(Arc::new),
            next,
        }
    }
}

impl StreamHandler for HttpHandler {
    fn on_stream(
        &self,
        mut lower: Box<dyn Stream>,
        initial_data: Buffer,
        mut context: Box<FlowContext>,
    ) {
        let next = match self.next.upgrade() {
            Some(next) => next,
            None => {
                info!("Next handler is not available");
                return;
            }
        };

        info!("New HTTP CONNECT request received");

        let auth_header = self.auth_header.clone();
        tokio::spawn(async move {
            let result = timeout(
                Duration::from_secs(10),
                handle_http_connect(&mut *lower, initial_data, auth_header),
            )
            .await;

            match result {
                Ok(Ok((initial_data, dest))) => {
                    info!("HTTP CONNECT successful to {:?}", dest);
                    context.remote_peer = dest;
                    context.af_sensitive = false;
                    next.on_stream(lower, initial_data, context);
                }
                Ok(Err(e)) => {
                    error!("HTTP CONNECT error: {:?}", e);
                }
                Err(_) => {
                    error!("HTTP CONNECT timeout");
                }
            }
        });
    }
}

use base64;

#[derive(Debug)]
pub enum DestRequest {
    Connect(DestinationAddr),
    Http {
        method: String,
        host: String,
        port: u16,
        path: String,
    },
}

fn should_redirect(domain: &str, redirect_domains: &[&str]) -> bool {
    redirect_domains.iter().any(|&d| domain.contains(d))
}

async fn handle_http_connect(
    stream: &mut dyn Stream,
    initial_data: Buffer,
    auth_header: Option<Arc<String>>,
) -> FlowResult<(Buffer, DestinationAddr)> {
    let mut reader = StreamReader::new(4096, initial_data);
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut req = httparse::Request::new(&mut headers);

    // 读取和查找头部结束位置
    let (header_end, header_data) = read_http_headers(stream, &mut reader).await?;

    // 解析 HTTP 请求
    match req.parse(&header_data[..header_end]) {
        Ok(_) => (),
        Err(_) => return Err(FlowError::UnexpectedData),
    }

    // 提取请求信息
    let request = parse_request(&req)?;

    match request {
        DestRequest::Connect(dest) => {
            // 验证认证信息
            if let Some(auth_required) = auth_header {
                let auth_valid = req
                    .headers
                    .iter()
                    .find(|h| h.name.eq_ignore_ascii_case("Authorization"))
                    .map(|h| String::from_utf8_lossy(h.value).eq(&*auth_required))
                    .unwrap_or(false);

                if !auth_valid {
                    send(
                        stream,
                        b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                        Proxy-Authenticate: Basic realm=\"proxy\"\r\n\
                        Connection: close\r\n\r\n",
                    )
                    .await?;
                    return Err(FlowError::UnexpectedData);
                }
            }

            // 对于 CONNECT 请求，直接建立隧道连接
            let response = b"HTTP/1.1 200 Connection Established\r\n\
                           Proxy-Agent: MyProxy/1.0\r\n\
                           Connection: close\r\n\r\n";

            send(stream, response).await?;
            poll_fn(|cx| stream.poll_flush_tx(cx)).await?;

            reader.advance(header_end + 4);
            Ok((reader.into_buffer().unwrap_or_default(), dest))
        }

        DestRequest::Http { host, port, .. } => {
            // 对于普通 HTTP 请求，可以考虑重定向
            let redirect_domains = vec!["baidu.com"];

            if redirect_domains.iter().any(|&d| host.contains(d)) {
                // 返回重定向响应
                let response = format!(
                    "HTTP/1.1 302 Found\r\n\
                     Location: http://{}\r\n\
                     Connection: close\r\n\r\n",
                    host
                );
                send(stream, response.as_bytes()).await?;
                return Err(FlowError::UnexpectedData);
            }

            let dest = DestinationAddr {
                host: if let Ok(ip) = host.parse::<IpAddr>() {
                    HostName::Ip(ip)
                } else {
                    HostName::DomainName(host)
                },
                port,
            };

            Ok((reader.into_buffer().unwrap_or_default(), dest))
        }
    }
}

fn parse_request(req: &httparse::Request) -> FlowResult<DestRequest> {
    match req.method {
        Some("CONNECT") => {
            if let Some(path) = req.path {
                Ok(DestRequest::Connect(parse_host_port(path)?))
            } else {
                Err(FlowError::UnexpectedData)
            }
        }
        Some(method) => {
            // 解析普通HTTP请求
            let (host, port) = extract_host_port_from_headers(req)?;
            let path = req.path.ok_or(FlowError::UnexpectedData)?;

            // 检查请求的协议是否为 HTTP 或 HTTPS
            if !path.starts_with("http://") && !path.starts_with("https://") {
                return Err(FlowError::UnexpectedData);
            }

            Ok(DestRequest::Http {
                method: method.to_string(),
                host,
                port,
                path: path.to_string(),
            })
        }
        None => Err(FlowError::UnexpectedData),
    }
}

fn extract_host_port_from_headers(req: &httparse::Request) -> FlowResult<(String, u16)> {
    // 首先尝试从Host头部获取
    if let Some(host_header) = req
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("Host"))
    {
        let host_str =
            std::str::from_utf8(host_header.value).map_err(|_| FlowError::UnexpectedData)?;

        // 如果Host头部包含端口
        if let Some((host, port_str)) = host_str.rsplit_once(':') {
            let port = port_str.parse().map_err(|_| FlowError::UnexpectedData)?;
            Ok((host.to_string(), port))
        } else {
            // 没有端口，使用默认的80端口
            Ok((host_str.to_string(), 80))
        }
    } else {
        // 尝试从URL中提取
        if let Some(path) = req.path {
            if path.starts_with("http://") || path.starts_with("https://") {
                if let Ok(url) = url::Url::parse(path) {
                    let host = url.host_str().ok_or(FlowError::UnexpectedData)?;
                    let port = url
                        .port()
                        .unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
                    return Ok((host.to_string(), port));
                }
            }
        }
        Err(FlowError::UnexpectedData)
    }
}

// 其他辅助函数保持不变
async fn read_http_headers(
    stream: &mut dyn Stream,
    reader: &mut StreamReader,
) -> FlowResult<(usize, Vec<u8>)> {
    let mut header_data = Vec::new();
    let mut should_break = false;

    // 设置一个总体超时
    let timeout = tokio::time::Duration::from_secs(1); // 10秒总超时
    let start_time = tokio::time::Instant::now();

    loop {
        // 检查是否超时
        if start_time.elapsed() > timeout {
            should_break = true; // 改用 should_break 而不是直接返回错误
        }

        // 如果需要break就退出循环
        if should_break {
            break;
        }

        let _ = reader
            .peek_at_least(stream, 1, |data| {
                if header_data.is_empty() {
                    if data.is_empty()
                        || !(data.starts_with(b"GET")
                            || data.starts_with(b"POST")
                            || data.starts_with(b"CONNECT"))
                    {
                        should_break = true;
                    }
                }

                header_data.extend_from_slice(data);
                if header_data.len() >= 4096 {
                    return Err(FlowError::UnexpectedData);
                }
                Ok(())
            })
            .await?;

        if let Some(pos) = find_header_end(&header_data) {
            return Ok((pos, header_data));
        }
    }

    // 循环结束后统一处理
    Err(FlowError::UnexpectedData)
}
fn find_header_end(data: &[u8]) -> Option<usize> {
    if data.len() < 4 {
        return None;
    }

    for i in 0..data.len() - 3 {
        if &data[i..i + 4] == b"\r\n\r\n" {
            return Some(i);
        }
    }
    None
}

fn parse_host_port(addr: &str) -> FlowResult<DestinationAddr> {
    let (host, port_str) = addr.rsplit_once(':').ok_or(FlowError::UnexpectedData)?;

    let port = port_str.parse().map_err(|_| FlowError::UnexpectedData)?;

    let host = if let Ok(ip) = host.parse::<IpAddr>() {
        HostName::Ip(ip)
    } else {
        HostName::DomainName(host.to_string())
    };

    Ok(DestinationAddr { host, port })
}

async fn send(stream: &mut dyn Stream, data: &[u8]) -> FlowResult<()> {
    let len = match data.len().try_into() {
        Ok(len) => len,
        Err(_) => return Ok(()),
    };
    let mut tx_buf = poll_fn(|cx| stream.poll_tx_buffer(cx, len)).await?;
    tx_buf.extend(data);
    stream.commit_tx_buffer(tx_buf)
}
