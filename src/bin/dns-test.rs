use std::net::UdpSocket;
use std::time::Duration;

// 解析域名
fn parse_domain_name(buf: &[u8], mut offset: usize) -> (String, usize) {
    let mut domain = String::new();
    let mut length = buf[offset] as usize;

    while length > 0 {
        offset += 1;
        // 处理压缩指针
        if (length & 0xC0) == 0xC0 {
            let pointer = (((length & 0x3F) as usize) << 8) | buf[offset] as usize;
            let (pointed_domain, _) = parse_domain_name(buf, pointer);
            domain.push_str(&pointed_domain);
            offset += 1;
            break;
        }

        // 添加域名段
        domain.push_str(std::str::from_utf8(&buf[offset..offset + length]).unwrap_or("?"));
        offset += length;
        length = buf[offset] as usize;
        if length > 0 {
            domain.push('.');
        }
    }

    (domain, offset + 1)
}

fn main() -> std::io::Result<()> {
    // 创建 DNS 查询报文 (查询 www.example.com)
    let dns_query = [
        0x12, 0x34, // Transaction ID
        0x01, 0x00, // Flags (标准查询)
        0x00, 0x01, // Questions
        0x00, 0x00, // Answer RRs
        0x00, 0x00, // Authority RRs
        0x00, 0x00, // Additional RRs
        // 查询 www.example.com
        0x03, b'w', b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o',
        b'm', 0x00, // 结束符
        0x00, 0x01, // Type (A记录)
        0x00, 0x01, // Class (IN)
    ];

    // 创建 UDP socket 并连接到代理服务器
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("127.0.0.1:1082")?; // 连接到UDP代理端口
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;

    println!("发送 DNS 查询请求...");
    socket.send(&dns_query)?;

    let max_retries = 3;
    for attempt in 1..=max_retries {
        println!("尝试接收响应 (第 {} 次)...", attempt);

        let mut buf = [0u8; 512];
        match socket.recv(&mut buf) {
            Ok(received) => {
                println!("\n收到响应，长度: {} 字节", received);

                // 解析 DNS 头
                if received > 12 {
                    let transaction_id = format!("{:02x}{:02x}", buf[0], buf[1]);
                    let flags = ((buf[2] as u16) << 8) | buf[3] as u16;
                    let questions = ((buf[4] as u16) << 8) | buf[5] as u16;
                    let answers = ((buf[6] as u16) << 8) | buf[7] as u16;
                    let authority = ((buf[8] as u16) << 8) | buf[9] as u16;
                    let additional = ((buf[10] as u16) << 8) | buf[11] as u16;

                    println!("\nDNS 响应头:");
                    println!("- 事务 ID: 0x{}", transaction_id);
                    println!("- 标志: 0x{:04x}", flags);
                    println!(
                        "  • QR (查询/响应): {}",
                        if (flags & 0x8000) != 0 {
                            "响应"
                        } else {
                            "查询"
                        }
                    );
                    println!("  • Opcode: {}", (flags >> 11) & 0xF);
                    println!(
                        "  • AA (权威应答): {}",
                        if (flags & 0x0400) != 0 { "是" } else { "否" }
                    );
                    println!(
                        "  • TC (截断): {}",
                        if (flags & 0x0200) != 0 { "是" } else { "否" }
                    );
                    println!(
                        "  • RD (期望递归): {}",
                        if (flags & 0x0100) != 0 { "是" } else { "否" }
                    );
                    println!(
                        "  • RA (递归可用): {}",
                        if (flags & 0x0080) != 0 { "是" } else { "否" }
                    );
                    println!("  • RCODE: {}", flags & 0x000F);
                    println!("- 问题数: {}", questions);
                    println!("- 回答数: {}", answers);
                    println!("- 授权数: {}", authority);
                    println!("- 附加数: {}", additional);

                    // 解析问题部分
                    let mut offset = 12;
                    println!("\n问题部分:");
                    for i in 0..questions {
                        let (domain, new_offset) = parse_domain_name(&buf, offset);
                        offset = new_offset;
                        let qtype = ((buf[offset] as u16) << 8) | buf[offset + 1] as u16;
                        let qclass = ((buf[offset + 2] as u16) << 8) | buf[offset + 3] as u16;
                        offset += 4;

                        println!("问题 {}:", i + 1);
                        println!("- 域名: {}", domain);
                        println!(
                            "- 类型: {}",
                            match qtype {
                                1 => "A",
                                2 => "NS",
                                5 => "CNAME",
                                6 => "SOA",
                                12 => "PTR",
                                15 => "MX",
                                16 => "TXT",
                                28 => "AAAA",
                                _ => "未知",
                            }
                        );
                        println!(
                            "- 类: {}",
                            match qclass {
                                1 => "IN",
                                _ => "未知",
                            }
                        );
                    }

                    // 解析回答部分
                    println!("\n回答部分:");
                    for i in 0..answers {
                        let (domain, new_offset) = parse_domain_name(&buf, offset);
                        offset = new_offset;

                        let rtype = ((buf[offset] as u16) << 8) | buf[offset + 1] as u16;
                        let rclass = ((buf[offset + 2] as u16) << 8) | buf[offset + 3] as u16;
                        let ttl = ((buf[offset + 4] as u32) << 24)
                            | ((buf[offset + 5] as u32) << 16)
                            | ((buf[offset + 6] as u32) << 8)
                            | buf[offset + 7] as u32;
                        let rdlength = ((buf[offset + 8] as u16) << 8) | buf[offset + 9] as u16;
                        offset += 10;

                        println!("回答 {}:", i + 1);
                        println!("- 域名: {}", domain);
                        println!(
                            "- 类型: {}",
                            match rtype {
                                1 => "A",
                                2 => "NS",
                                5 => "CNAME",
                                6 => "SOA",
                                12 => "PTR",
                                15 => "MX",
                                16 => "TXT",
                                28 => "AAAA",
                                _ => "未知",
                            }
                        );
                        println!(
                            "- 类: {}",
                            match rclass {
                                1 => "IN",
                                _ => "未知",
                            }
                        );
                        println!("- TTL: {} 秒", ttl);
                        println!("- 数据长度: {} 字节", rdlength);

                        // 解析记录数据
                        match rtype {
                            1 => {
                                // A 记录
                                if rdlength == 4 {
                                    println!(
                                        "- IP地址: {}.{}.{}.{}",
                                        buf[offset],
                                        buf[offset + 1],
                                        buf[offset + 2],
                                        buf[offset + 3]
                                    );
                                }
                            }
                            5 => {
                                // CNAME 记录
                                let (cname, _) = parse_domain_name(&buf, offset);
                                println!("- CNAME: {}", cname);
                            }
                            28 => {
                                // AAAA 记录
                                if rdlength == 16 {
                                    println!("- IPv6地址: {:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                                        buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3],
                                        buf[offset + 4], buf[offset + 5], buf[offset + 6], buf[offset + 7],
                                        buf[offset + 8], buf[offset + 9], buf[offset + 10], buf[offset + 11],
                                        buf[offset + 12], buf[offset + 13], buf[offset + 14], buf[offset + 15]);
                                }
                            }
                            _ => {
                                println!("- 原始数据: ");
                                for i in 0..rdlength as usize {
                                    print!("{:02x} ", buf[offset + i]);
                                }
                                println!();
                            }
                        }
                        offset += rdlength as usize;
                    }
                }
                return Ok(());
            }
            Err(e) => {
                println!("第 {} 次接收响应失败: {}", attempt, e);
                if attempt == max_retries {
                    println!("达到最大重试次数，退出");
                    return Err(e);
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }

    Ok(())
}
