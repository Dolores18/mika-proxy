use std::task::Context;
use std::task::Poll;

use super::*;
use crate::flow::*;
use std::net::Ipv4Addr;
pub(super) struct IpStackDatagramSession {
    pub(super) stack: Arc<Mutex<IpStackInner>>,
    pub(super) local_endpoint: SocketAddr,
}

impl MultiplexedDatagramSession for IpStackDatagramSession {
    fn on_close(&mut self) {
        let mut stack_guard = self.stack.lock().unwrap();
        stack_guard.udp_sockets.remove(&self.local_endpoint);
    }
    fn poll_send_ready(&mut self, _cx: &mut Context<'_>) -> Poll<()> {
        Poll::Ready(())
    }
    fn send_to(&mut self, src: DestinationAddr, buf: Buffer) {
        println!("📤📤 准备发送UDP响应: 从{:?}发送到{:?}, 长度: {}", src, self.local_endpoint, buf.len());
        
        // 打印UDP响应数据包的十六进制内容
        println!("  UDP响应数据包内容(十六进制):");
        for (i, chunk) in buf.chunks(16).enumerate() {
            let hex_values: Vec<String> = chunk.iter().map(|b| format!("{:02x}", b)).collect();
            let ascii_values: String = chunk.iter()
                .map(|&b| if b >= 32 && b <= 126 { b as char } else { '.' })
                .collect();
            println!("  {:04x}: {:48} {}", i * 16, hex_values.join(" "), ascii_values);
        }
        
        let payload_len: u16 = match buf.len().try_into().ok().filter(|&l| l <= 1500 - 48) {
            Some(l) => l,
            // Ignore oversized packet
            None => {
                println!("❌ 数据包过大，无法发送: {}", buf.len());
                return;
            }
        };
        let _from_ip = match &src.host {
            HostName::Ip(ip) => ip,
            // TODO: print diagnostic message: Cannot send datagram to unresolved destination
            _ => {
                println!("❌ 目标地址未解析，无法发送");
                return;
            }
        };

        let mut stack_guard = self.stack.lock().unwrap();
        use smoltcp::phy::{Device, TxToken};
        let sender = stack_guard.dev.transmit(Instant::now().into());
        let ip_buf = match sender {
            Some(b) => b,
            None => {
                println!("❌ 无法获取发送缓冲区");
                return;
            }
        };
        
        println!("🏗️ 开始构建响应IP数据包");
        match (&self.local_endpoint, &src.host) {
            (SocketAddr::V4(dst_v4), HostName::Ip(IpAddr::V4(src_ip))) => {
                println!("  构建IPv4数据包: {}:{} -> {}", src_ip, src.port, dst_v4);
                //let src_ip: Ipv4Address = Ipv4Addr::new(8, 8, 8, 8).into();

                let src_ip: Ipv4Address = (*src_ip).into();
                println!("🌹udp客户端测试用IPv4 发送数据包: {}", src_ip);
                println!("🌹本地端口是: {}", self.local_endpoint.port());
                //let src_ip: Ipv4Address = Ipv4Addr::new(1, 1, 1, 1).into();
               
                println!("  准备调用ip_buf.consume");
                ip_buf.consume(buf.len() + 48, |ip_buf| {
                    let mut ip_packet = Ipv4Packet::new_unchecked(ip_buf);
                    ip_packet.set_version(4);
                    ip_packet.set_header_len(20);
                    ip_packet.set_total_len(20 + 8 + payload_len);
                    ip_packet.set_dont_frag(true);
                    ip_packet.set_frag_offset(0);
                    ip_packet.set_hop_limit(255);
                    ip_packet.set_next_header(IpProtocol::Udp);
                    ip_packet.set_dst_addr((*dst_v4.ip()).into());
                    ip_packet.set_src_addr(src_ip);
                    let mut udp_packet = UdpPacket::new_unchecked(ip_packet.payload_mut());
                    udp_packet.set_dst_port(self.local_endpoint.port());
                    udp_packet.set_src_port(src.port);
                    udp_packet.set_len(8 + payload_len);
                    udp_packet.payload_mut()[..buf.len()].copy_from_slice(&buf);
                    udp_packet.fill_checksum(&src_ip.into(), &(*dst_v4.ip()).into());
                    ip_packet.fill_checksum();
                    println!("✅ IPv4数据包已构建完成，长度: {}", 20 + 8 + payload_len);
                });
                println!("  ip_buf.consume已完成（回调返回）");
            }
            (SocketAddr::V6(dst_v6), HostName::Ip(IpAddr::V6(src_ip))) => {
                println!("  构建IPv6数据包: {}:{} -> {}", src_ip, src.port, dst_v6);
                let src_ip: Ipv6Address = (*src_ip).into();
                ip_buf.consume(buf.len() + 48, |ip_buf| {
                    let mut ip_packet = Ipv6Packet::new_unchecked(ip_buf);
                    ip_packet.set_version(6);
                    ip_packet.set_hop_limit(255);
                    ip_packet.set_next_header(IpProtocol::Udp);
                    ip_packet.set_dst_addr((*dst_v6.ip()).into());
                    ip_packet.set_src_addr(src_ip);
                    ip_packet.set_payload_len(8 + payload_len);
                    ip_packet.set_flow_label(dst_v6.flowinfo());
                    let mut udp_packet = UdpPacket::new_unchecked(ip_packet.payload_mut());
                    udp_packet.set_dst_port(self.local_endpoint.port());
                    udp_packet.set_src_port(src.port);
                    udp_packet.set_len(8 + payload_len);
                    udp_packet.payload_mut()[..buf.len()].copy_from_slice(&buf);
                    udp_packet.fill_checksum(&src_ip.into(), &(*dst_v6.ip()).into());
                    println!("✅ IPv6数据包已构建完成，长度: {}", 40 + 8 + payload_len);
                });
            }
            // Ignore unmatched IP version
            _ => {
                println!("❌ IP版本不匹配，无法构建数据包: {:?} vs {:?}", self.local_endpoint, src.host);
            }
        }
        println!("📤📤 UDP响应已构建，但TxToken可能未正确使用！");
        println!("检查：这里缺少实际发送操作，TxToken在回调之后可能已自动释放");
    }
}