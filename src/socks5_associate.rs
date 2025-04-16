use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, Weak};

use async_trait::async_trait;
use futures::future::poll_fn;
use log::{debug, error, info};

use crate::flow::*;
use crate::shadowsocks::util::*;
use crate::socks5::get_cred_req;

// UDP关联会话映射，存储TCP会话ID和对应的UDP会话信息
struct UdpAssociation {
    client_addr: SocketAddr,       // 客户端地址
    relay_addr: SocketAddr,        // UDP中继地址
    session: Weak<dyn DatagramSessionHandler>,  // UDP会话处理器
}

// 全局UDP关联映射表
lazy_static::lazy_static! {
    static ref UDP_ASSOCIATIONS: Mutex<HashMap<usize, UdpAssociation>> = Mutex::new(HashMap::new());
}

pub struct Socks5UdpAssociateHandler {
    auth_req: Option<Arc<[u8]>>,
    udp_session_handler: Weak<dyn DatagramSessionHandler>,
    udp_relay_addr: SocketAddr,  // UDP中继地址
}

impl Socks5UdpAssociateHandler {
    pub fn new(
        cred: Option<(&[u8], &[u8])>, 
        udp_session_handler: Weak<dyn DatagramSessionHandler>,
        udp_relay_addr: SocketAddr,
    ) -> Self {
        let auth_req = cred.map(|cred| get_cred_req(cred).into());
        Self { 
            auth_req, 
            udp_session_handler,
            udp_relay_addr,
        }
    }
}

impl StreamHandler for Socks5UdpAssociateHandler {
    fn on_stream(
        &self,
        mut lower: Box<dyn Stream>,
        initial_data: Buffer,
        mut context: Box<FlowContext>,
    ) {
        let next = match self.udp_session_handler.upgrade() {
            Some(next) => Arc::downgrade(&next),
            None => {
                info!("UDP会话处理器不可用");
                return;
            }
        };
        
        let auth_req = self.auth_req.clone();
        let udp_relay_addr = self.udp_relay_addr;
        
        // 生成唯一的会话ID
        let session_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as usize;
        
        tokio::spawn(async move {
            // 处理SOCKS5握手
            match handle_socks5_handshake(&mut *lower, initial_data, auth_req, session_id, udp_relay_addr, next).await {
                Ok(_) => {
                    info!("UDP ASSOCIATE成功建立，会话ID: {}", session_id);
                    
                    // 保持TCP连接，直到关闭
                    let _ = keep_tcp_alive(&mut *lower).await;
                    
                    // TCP连接关闭，清理UDP关联
                    cleanup_udp_association(session_id);
                    info!("TCP连接关闭，已清理UDP关联 {}", session_id);
                },
                Err(e) => {
                    error!("SOCKS5握手失败: {:?}", e);
                }
            }
        });
    }
}

// 自定义实现发送响应的函数
async fn send_response(lower: &mut dyn Stream, data: &[u8]) -> FlowResult<()> {
    send(lower, data).await?;
    poll_fn(|cx| lower.poll_flush_tx(cx)).await
}

// 实现发送数据的辅助函数
async fn send(lower: &mut dyn Stream, data: &[u8]) -> FlowResult<()> {
    let len = match data.len().try_into() {
        Ok(len) => len,
        Err(_) => return Ok(()),
    };
    let mut tx_buf = poll_fn(|cx| lower.poll_tx_buffer(cx, len)).await?;
    tx_buf.extend(data);
    lower.commit_tx_buffer(tx_buf)
}

async fn handle_socks5_handshake(
    stream: &mut dyn Stream,
    initial_data: Buffer,
    auth_req: Option<Arc<[u8]>>,
    session_id: usize,
    udp_relay_addr: SocketAddr,
    udp_handler: Weak<dyn DatagramSessionHandler>,
) -> FlowResult<()> {
    info!("开始SOCKS5握手");
    let mut reader = StreamReader::new(128, initial_data);

    // 读取初始握手数据
    let nauth = reader
        .read_exact(stream, 2, |buf| {
            info!("收到初始字节: {:?}", buf);
            let res = buf[1];
            if buf[0] != 0x05 {
                info!("不支持的SOCKS版本: {}", buf[0]);
                return Err(FlowError::UnexpectedData);
            }
            Ok(res)
        })
        .await??;

    if nauth == 0 {
        info!("未提供认证方法");
        send_response(stream, &[0x05, 0xff]).await?;
        return Err(FlowError::UnexpectedData);
    }

    // 处理认证方法
    if let Some(auth_req) = auth_req {
        // 用户名密码认证
        let auth_method_found = reader
            .read_exact(stream, nauth as usize, |buf| {
                info!("收到认证方法: {:?}", buf);
                buf.iter().any(|&a| a == 0x02)
            })
            .await?;

        if auth_method_found {
            info!("找到用户名/密码认证方法");
            send_response(stream, &[0x05, 0x02]).await?;
        } else {
            info!("未找到支持的认证方法");
            send_response(stream, &[0x05, 0xff]).await?;
            return Err(FlowError::UnexpectedData);
        }

        // 处理认证请求
        let idlen = reader
            .peek_at_least(stream, 1 + 1, |buf| {
                info!("认证请求初始字节: {:?}", &buf[..2]);
                let idlen = buf[1];
                if buf[0] != 0x01 {
                    info!("不支持的认证版本: {}", buf[0]);
                    return Err(FlowError::UnexpectedData);
                }
                Ok(idlen)
            })
            .await?? as usize;

        let pwlen = reader
            .peek_at_least(stream, 1 + 1 + idlen + 1, |buf| {
                info!("密码长度字节: {}", buf[1 + 1 + idlen]);
                let pwlen = buf[1 + 1 + idlen];
                if buf[0] != 0x01 {
                    info!("不支持的认证版本: {}", buf[0]);
                    return Err(FlowError::UnexpectedData);
                }
                Ok(pwlen)
            })
            .await?? as usize;

        let req_match = reader
            .read_exact(stream, 1 + 1 + idlen + 1 + pwlen, |buf| {
                info!("完整认证请求: {:?}", buf);
                subtle::ConstantTimeEq::ct_eq(buf, &*auth_req).into()
            })
            .await?;

        info!("认证结果: {}", req_match);
        send_response(stream, if req_match { &[0x01, 0] } else { &[0x01, 0xff] }).await?;
        
        if !req_match {
            return Err(FlowError::UnexpectedData);
        }
    } else {
        // 无认证
        let auth_method_found = reader
            .read_exact(stream, nauth as usize, |buf| {
                info!("收到认证方法: {:?}", buf);
                buf.iter().any(|&a| a == 0)
            })
            .await?;

        if auth_method_found {
            info!("找到无认证方法");
            send_response(stream, &[0x05, 0]).await?;
        } else {
            info!("无认证方法未找到");
            send_response(stream, &[0x05, 0xff]).await?;
            return Err(FlowError::UnexpectedData);
        }
    }

    // 读取请求
    let (cmd, req_len) = match reader
        .peek_at_least(stream, 5, |buf| {
            info!("连接请求初始字节: {:?}", &buf[..5]);
            let dst_len = match buf[3] {
                1 => 4,
                3 => buf[4] as usize + 1,
                4 => 16,
                _ => return Err(FlowError::UnexpectedData),
            } + 6;
            if buf[0] != 0x05 {
                info!("不支持的SOCKS版本: {}", buf[0]);
                return Err(FlowError::UnexpectedData);
            }
            Ok((buf[1], dst_len))
        })
        .await?
    {
        Ok(result) => result,
        Err(_) => {
            info!("读取连接请求时出错");
            send_response(stream, &[0x05, 0x07, 0, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            return Err(FlowError::UnexpectedData);
        }
    };

    // 检查是否是UDP ASSOCIATE命令
    if cmd != 3 {
        info!("不支持的命令: {}，只支持UDP ASSOCIATE(3)", cmd);
        send_response(stream, &[0x05, 0x07, 0, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        return Err(FlowError::UnexpectedData);
    }

    // 读取目标地址
    let client_addr = reader
        .read_exact(stream, req_len, |buf| {
            info!("完整UDP ASSOCIATE请求: {:?}", buf);
            // 解析客户端地址
            if let Some((addr, _)) = parse_dest(&buf[3..]) {
                if let HostName::Ip(ip) = addr.host {
                    // 构造客户端地址
                    Some(SocketAddr::new(ip, addr.port))
                } else {
                    None
                }
            } else {
                None
            }
        })
        .await?;

    // 如果客户端发送0.0.0.0:0，使用默认设置
    let client_addr = match client_addr {
        Some(addr) if addr.ip() != IpAddr::from([0, 0, 0, 0]) && addr.port() != 0 => {
            info!("使用客户端指定的地址: {}", addr);
            addr
        },
        _ => {
            // 由于Stream没有remote_addr方法，使用一个默认地址
            let default_addr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)), 0);
            info!("使用默认地址: {}", default_addr);
            default_addr
        }
    };

    // 准备UDP关联响应
    let mut response = vec![0x05, 0x00, 0x00]; // 成功响应

    // 添加UDP中继地址
    match udp_relay_addr.ip() {
        IpAddr::V4(ipv4) => {
            response.push(0x01); // IPv4
            response.extend_from_slice(&ipv4.octets());
        },
        IpAddr::V6(ipv6) => {
            response.push(0x04); // IPv6
            response.extend_from_slice(&ipv6.octets());
        }
    }

    // 添加UDP中继端口
    response.extend_from_slice(&udp_relay_addr.port().to_be_bytes());

    // 发送UDP关联响应
    send_response(stream, &response).await?;
    info!("UDP关联响应已发送，中继地址: {}", udp_relay_addr);

    // 存储UDP关联信息
    store_udp_association(session_id, client_addr, udp_relay_addr, udp_handler);

    Ok(())
}

// 保持TCP连接，直到关闭
async fn keep_tcp_alive(stream: &mut dyn Stream) -> FlowResult<()> {
    loop {
        // 读取数据
        match poll_fn(|cx| stream.poll_rx_buffer(cx)).await {
            Ok(mut rx_buf) => {
                if rx_buf.is_empty() {
                    // 连接关闭
                    break;
                }
                
                // 丢弃数据，仅保持连接
                if let Err(_) = stream.commit_rx_buffer(rx_buf) {
                    break;
                }
            },
            Err(_) => {
                // 连接错误
                break;
            }
        }
    }
    
    Ok(())
}

// 存储UDP关联信息
fn store_udp_association(
    session_id: usize,
    client_addr: SocketAddr,
    relay_addr: SocketAddr,
    udp_handler: Weak<dyn DatagramSessionHandler>,
) {
    let association = UdpAssociation {
        client_addr,
        relay_addr,
        session: udp_handler,
    };
    
    let mut associations = UDP_ASSOCIATIONS.lock().unwrap();
    associations.insert(session_id, association);
    info!("UDP关联已存储，会话ID: {}, 客户端地址: {}", session_id, client_addr);
}

// 清理UDP关联
fn cleanup_udp_association(session_id: usize) {
    let mut associations = UDP_ASSOCIATIONS.lock().unwrap();
    associations.remove(&session_id);
    info!("UDP关联已清理，会话ID: {}", session_id);
} 