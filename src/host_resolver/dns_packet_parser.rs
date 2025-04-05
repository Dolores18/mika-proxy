use trust_dns_resolver::proto::op::Message as DnsMessage;
use trust_dns_resolver::proto::serialize::binary::BinDecodable;
use trust_dns_resolver::proto::rr::RecordType;
use serde_json::Value;
use trust_dns_resolver::proto::op::{Message, MessageType, OpCode, ResponseCode};
use trust_dns_resolver::proto::rr::{Name, RData, Record};
use trust_dns_resolver::proto::rr::record_type::RecordType as _; // 避免名称冲突
use trust_dns_resolver::proto::rr::DNSClass;
use std::str::FromStr;
use std::net::{Ipv4Addr, Ipv6Addr};

/// DNS查询信息结构体，包含查询的域名和记录类型
#[derive(Debug, Clone)]
pub struct DnsQueryInfo {
    pub domain: String,   // 查询的域名
    pub query_type: u16,  // 查询类型（如A=1, AAAA=28等）
    pub dns_id: u16,      // DNS查询ID，用于响应匹配
}

/// 解析DNS查询包，提取查询信息
pub fn parse_dns_query(buf: &[u8]) -> Option<DnsQueryInfo> {
    // 尝试解析为标准DNS消息
    if let Ok(message) = DnsMessage::from_bytes(buf) {
        // 从第一个查询中提取信息
        if let Some(query) = message.queries().first() {
            let domain = query.name().to_lowercase().to_ascii();
            let query_type = query.query_type().into();
            let dns_id = message.header().id();
            
            return Some(DnsQueryInfo {
                domain, 
                query_type,
                dns_id,
            });
        }
    }
    
    // 如果无法解析或没有查询，则返回None
    None
}

/// 获取记录类型的字符串表示
pub fn get_record_type_name(query_type: u16) -> &'static str {
    match query_type {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR", 
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        _ => "OTHER",
    }
}

/// 将DNS查询信息转换为DoH JSON API所需的参数
pub fn dns_query_to_doh_params(query_info: &DnsQueryInfo) -> String {
    format!(
        "name={}&type={}",
        query_info.domain, 
        get_record_type_name(query_info.query_type)
    )
}

/// 从JSON API响应构建DNS响应包
pub fn json_to_dns_message(json_str: &str, query_id: u16) -> Option<Vec<u8>> {
    // 解析JSON
    let parsed: Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(e) => {
            println!("解析JSON失败: {}", e);
            return None;
        }
    };
    
    // 创建DNS响应消息
    let mut message = Message::new();
    message.set_id(query_id);  // 使用传入的查询ID
    println!("使用查询ID: {}", query_id);  // 调试输出
    
    message.set_message_type(MessageType::Response);
    message.set_op_code(OpCode::Query);
    message.set_authoritative(false);
    message.set_recursion_desired(true);
    message.set_recursion_available(true);
    
    // 检查响应码
    let status = parsed.get("Status").and_then(|s| s.as_u64()).unwrap_or(0);
    let response_code = match status {
        0 => ResponseCode::NoError,
        1 => ResponseCode::FormErr,
        2 => ResponseCode::ServFail,
        3 => ResponseCode::NXDomain,
        4 => ResponseCode::NotImp,
        5 => ResponseCode::Refused,
        _ => ResponseCode::ServFail,
    };
    message.set_response_code(response_code);
    
    // 检查Question部分
    if let Some(question) = parsed.get("Question").and_then(|q| q.as_array()).and_then(|a| a.first()) {
        let domain = question.get("name").and_then(|n| n.as_str()).unwrap_or(".");
        let qtype = question.get("type").and_then(|t| t.as_u64()).unwrap_or(1);
        
        if let Ok(name) = Name::from_str(domain) {
            let record_type = match qtype {
                1 => RecordType::A,
                28 => RecordType::AAAA,
                5 => RecordType::CNAME,
                // 其他记录类型...
                _ => RecordType::A,
            };
            
            let query = trust_dns_resolver::proto::op::Query::query(name.clone(), record_type);
            message.add_query(query);
        }
    }
    
    // 添加Answer部分
    if let Some(answers) = parsed.get("Answer").and_then(|a| a.as_array()) {
        for answer in answers {
            let domain = answer.get("name").and_then(|n| n.as_str()).unwrap_or(".");
            let rtype = answer.get("type").and_then(|t| t.as_u64()).unwrap_or(1);
            let ttl = answer.get("TTL").and_then(|t| t.as_u64()).unwrap_or(300) as u32;
            let data = answer.get("data").and_then(|d| d.as_str()).unwrap_or("");
            
            if let Ok(name) = Name::from_str(domain) {
                let rdata = match rtype {
                    1 => { // A记录
                        if let Ok(ip) = Ipv4Addr::from_str(data) {
                            Some(RData::A(ip))
                        } else {
                            None
                        }
                    },
                    28 => { // AAAA记录
                        if let Ok(ip) = Ipv6Addr::from_str(data) {
                            Some(RData::AAAA(ip))
                        } else {
                            None
                        }
                    },
                    5 => { // CNAME记录
                        if let Ok(target) = Name::from_str(data) {
                            Some(RData::CNAME(target))
                        } else {
                            None
                        }
                    },
                    // 其他记录类型...
                    _ => None,
                };
                
                if let Some(rdata) = rdata {
                    let mut record = Record::new();
                    record.set_name(name);
                    record.set_ttl(ttl);
                    record.set_record_type(RecordType::from(rtype as u16));
                    record.set_rdata(rdata);
                    record.set_dns_class(DNSClass::IN);
                    
                    message.add_answer(record);
                }
            }
        }
    }
    
    // 将消息序列化为二进制
    match message.to_vec() {
        Ok(bytes) => Some(bytes),
        Err(e) => {
            println!("序列化DNS消息失败: {}", e);
            None
        }
    }
}
