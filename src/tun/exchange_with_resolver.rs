use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{RData, Record, rdata::{A, AAAA}, RecordType},
};
use log::{debug, trace};
use std::error::Error;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::fakeip::FakeIp;
use crate::flow::Resolver;

// 定义自己的DNS错误类型
#[derive(Debug)]
pub enum DNSError {
    InvalidOpQuery(String),
    QueryFailed(String),
}

impl fmt::Display for DNSError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DNSError::InvalidOpQuery(msg) => write!(f, "Invalid query operation: {}", msg),
            DNSError::QueryFailed(msg) => write!(f, "DNS query failed: {}", msg),
        }
    }
}

impl Error for DNSError {}

static DEFAULT_DNS_SERVER_TTL: u32 = 60;

pub async fn exchange_with_resolver<'a>(
    resolver: &'a FakeIp,
    req: &'a Message,
    enhanced: bool,
) -> Result<Message, DNSError> {
    // 获取查询的域名
    let name = req
        .query()
        .ok_or(DNSError::InvalidOpQuery(
            "malformed query message".to_string(),
        ))?
        .name();

    let host = req
        .query()
        .map(|x| x.name().to_ascii().trim_end_matches('.').to_owned())
        .unwrap();
        
    println!("🔍 FakeIP处理DNS查询: {}", host);

    // 创建响应消息
    let mut res = Message::new();
    res.set_id(req.id());
    res.set_message_type(hickory_proto::op::MessageType::Response);
    res.add_queries(req.queries().iter().map(|x| x.to_owned()));
    res.set_recursion_available(false);
    res.set_authoritative(true);
    res.set_recursion_desired(req.recursion_desired());
    res.set_checking_disabled(req.checking_disabled());
    if let Some(edns) = req.extensions().clone() {
        res.set_edns(edns);
    }

    // 获取查询类型
    let query_type = req.query().map(|q| q.query_type()).unwrap_or(RecordType::A);
    println!("🔍 查询类型: {:?}", query_type);

    // 检查是A记录(IPv4)查询还是AAAA记录(IPv6)查询
    if query_type == RecordType::A {
        // 处理IPv4 (A记录) 查询
        match resolver.resolve_ipv4(host.clone()).await {
            Ok(ips) if !ips.is_empty() => {
                let ip = Ipv4Addr::from(ips[0]);
                let rdata = RData::A(A(ip));

                println!("🔍 FakeIP分配成功(IPv4): {} => {}", host, ip);

                let records = vec![Record::from_rdata(
                    name.clone(),
                    DEFAULT_DNS_SERVER_TTL,
                    rdata,
                )];

                res.set_response_code(ResponseCode::NoError);
                res.set_answer_count(records.len() as u16);
                res.add_answers(records);

                trace!("FakeIP DNS response (IPv4): {:?} -> {:?}", name, ip);
                Ok(res)
            }
            Ok(_) => {
                // 没有找到IP地址
                println!("🔍 FakeIP分配失败(IPv4): {} => 无可用IP", host);
                res.set_response_code(ResponseCode::NXDomain);
                Ok(res)
            }
            Err(e) => {
                println!("🔍 FakeIP解析错误(IPv4): {} => {:?}", host, e);
                debug!("DNS resolve error (IPv4): {:?}", e);
                Err(DNSError::QueryFailed(format!("{:?}", e)))
            }
        }
    } else if query_type == RecordType::AAAA {
        // 处理IPv6 (AAAA记录) 查询
        match resolver.resolve_ipv6(host.clone()).await {
            Ok(ips) if !ips.is_empty() => {
                let ip = Ipv6Addr::from(ips[0]);
                let rdata = RData::AAAA(AAAA(ip));

                println!("🔍 FakeIP分配成功(IPv6): {} => {}", host, ip);

                let records = vec![Record::from_rdata(
                    name.clone(),
                    DEFAULT_DNS_SERVER_TTL,
                    rdata,
                )];

                res.set_response_code(ResponseCode::NoError);
                res.set_answer_count(records.len() as u16);
                res.add_answers(records);

                trace!("FakeIP DNS response (IPv6): {:?} -> {:?}", name, ip);
                Ok(res)
            }
            Ok(_) => {
                // 没有找到IP地址
                println!("🔍 FakeIP分配失败(IPv6): {} => 无可用IP", host);
                res.set_response_code(ResponseCode::NXDomain);
                Ok(res)
            }
            Err(e) => {
                println!("🔍 FakeIP解析错误(IPv6): {} => {:?}", host, e);
                debug!("DNS resolve error (IPv6): {:?}", e);
                Err(DNSError::QueryFailed(format!("{:?}", e)))
            }
        }
    } else {
        // 对于其他类型的查询，返回NXDOMAIN
        println!("🔍 不支持的查询类型: {:?}", query_type);
        res.set_response_code(ResponseCode::NXDomain);
        Ok(res)
    }
}