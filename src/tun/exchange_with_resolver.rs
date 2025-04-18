use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{RData, Record, rdata::A, RecordType},
};
use log::{debug, trace};
use std::error::Error;
use std::fmt;
use std::net::Ipv4Addr;

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

    // 检查查询类型是否为AAAA(IPv6地址)
    if let Some(query) = req.query() {
        if query.query_type() == RecordType::AAAA {
            println!("🔍 不支持AAAA查询，返回Refused: {}", host);
            
            // 创建拒绝响应消息
            let mut resp = Message::error_msg(
                req.id(),
                req.op_code(),
                ResponseCode::Refused
            );
            
            // 保留原始查询
            resp.add_query(query.clone());
            
            // 设置适当的标志
            resp.set_recursion_available(false);
            resp.set_authoritative(true);
            resp.set_recursion_desired(req.recursion_desired());
            resp.set_checking_disabled(req.checking_disabled());
            
            // 复制EDNS扩展(如果有)
            if let Some(edns) = req.extensions().clone() {
                resp.set_edns(edns);
            }
            
            return Ok(resp);
        }
    }

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

    // 使用FakeIp解析域名
    match resolver.resolve_ipv4(host.clone()).await {
        Ok(ips) if !ips.is_empty() => {
            let ip = Ipv4Addr::from(ips[0]);
            let rdata = RData::A(A(ip));

            println!("🔍 FakeIP分配成功: {} => {}", host, ip);

            let records = vec![Record::from_rdata(
                name.clone(),
                DEFAULT_DNS_SERVER_TTL,
                rdata,
            )];

            res.set_response_code(ResponseCode::NoError);
            res.set_answer_count(records.len() as u16);
            res.add_answers(records);

            trace!("FakeIP DNS response: {:?} -> {:?}", name, ip);
            Ok(res)
        }
        Ok(_) => {
            // 没有找到IP地址
            println!("🔍 FakeIP分配失败: {} => 无可用IP", host);
            res.set_response_code(ResponseCode::NXDomain);
            Ok(res)
        }
        Err(e) => {
            println!("🔍 FakeIP解析错误: {} => {:?}", host, e);
            debug!("DNS resolve error: {:?}", e);
            Err(DNSError::QueryFailed(format!("{:?}", e)))
        }
    }
}

