mod datagram;
mod stream;
mod tcp_socket_entry;

use std::collections::btree_map::{BTreeMap, Entry};
use std::future::Future;
use std::mem::ManuallyDrop;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use flume::{bounded, Sender, TrySendError};
use smoltcp::iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Checksum, ChecksumCapabilities, DeviceCapabilities, Medium};
use smoltcp::socket::tcp::Socket as TcpSocket;
use smoltcp::storage::RingBuffer;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpProtocol, Ipv4Address, Ipv4Packet,
    Ipv6Address, Ipv6Packet, TcpPacket, UdpPacket,
};
use tokio::time::sleep_until;

use crate::flow::*;
use crate::fakeip::FakeIp;
use crate::tun::exchange_with_resolver;
struct Device {
    tx: Option<TunBufferToken>,
    rx: Option<Buffer>,
    tun: Arc<dyn Tun>,
}

impl smoltcp::phy::Device for Device {
    type RxToken<'d> = RxToken<'d>;
    type TxToken<'d> = TxToken<'d>;
    fn receive(&mut self, _: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let Self { tx, rx, tun } = self;
        rx.as_ref()?;
        if tx.is_none() {
            *tx = Some(tun.get_tx_buffer()?);
        };
        Some((RxToken(rx, &**tun), TxToken(tx, &**tun)))
    }
    fn transmit(&mut self, _: SmolInstant) -> Option<Self::TxToken<'_>> {
        let Self { tx, tun, .. } = self;
        if tx.is_none() {
            *tx = Some(tun.get_tx_buffer()?);
        };
        Some(TxToken(tx, &**tun))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut checksum = ChecksumCapabilities::default();
        checksum.tcp = Checksum::Tx;
        checksum.udp = Checksum::Tx;
        checksum.ipv4 = Checksum::Tx;
        checksum.icmpv4 = Checksum::Tx;
        let mut dev = DeviceCapabilities::default();
        dev.medium = Medium::Ip;
        dev.max_transmission_unit = 1500;
        dev.checksum = checksum;
        dev
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        if let Some(rx_buf) = self.rx.take() {
            self.tun.return_recv_buffer(rx_buf);
        }
        if let Some(tx_token) = self.tx.take() {
            self.tun.return_tx_buffer(tx_token);
        }
    }
}

struct RxToken<'d>(&'d mut Option<Buffer>, &'d dyn Tun);
impl<'d> smoltcp::phy::RxToken for RxToken<'d> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let buf = self
            .0
            .take()
            .expect("Consuming a RxToken without tx buffer set");

        struct BufReturnGuard<'d>(ManuallyDrop<Buffer>, &'d dyn Tun);
        impl<'d> Drop for BufReturnGuard<'d> {
            fn drop(&mut self) {
                unsafe {
                    self.1.return_recv_buffer(ManuallyDrop::take(&mut self.0));
                }
            }
        }
        let mut guard = BufReturnGuard(ManuallyDrop::new(buf), self.1);

        f(&mut guard.0)
    }
}

struct TxToken<'d>(&'d mut Option<TunBufferToken>, &'d dyn Tun);
impl<'d> smoltcp::phy::TxToken for TxToken<'d> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let buf = self
            .0
            .as_mut()
            .expect("Consuming a TxToken without tx buffer set");
        if len > buf.data.len() {
            panic!("smoltcp cannot write a packet to a TUN interface with smaller MTU set.")
        }
        let res = f(&mut buf.data[..len]);
        self.1.send(self.0.take().unwrap(), len);
        res
    }
}


type IpStack = Arc<Mutex<IpStackInner>>;

struct IpStackInner {
    netif: Interface,
    dev: Device,
    socket_set: SocketSet<'static>,
    // TODO: (router) also record src ip
    tcp_sockets: BTreeMap<SocketAddr, SocketHandle>,
    udp_sockets: BTreeMap<SocketAddr, Sender<(DestinationAddr, Buffer)>>,
    tcp_next: Weak<dyn StreamHandler>,
    udp_next: Weak<dyn DatagramSessionHandler>,
}

pub fn run(
    tun: Arc<dyn Tun>,
    tcp_next: Weak<dyn StreamHandler>,
    udp_next: Weak<dyn DatagramSessionHandler>,
    dns_hijack: bool,
    resolver: Option<Arc<FakeIp>>,
) -> tokio::task::JoinHandle<()> {
    let mut dev = Device {
        tx: None,
        rx: None,
        tun: tun.clone(),
    };
    let mut netif = Interface::new(
        InterfaceConfig::new(HardwareAddress::Ip),
        &mut dev,
        Instant::now().into(),
    );
    netif.set_any_ip(true);
    netif.update_ip_addrs(|ips| {
        ips.push(IpCidr::new(Ipv4Address::new(192, 168, 3, 1).into(), 0))
            .expect("IPv4 address should not exceed capacity");
    });
    netif
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::new(192, 168, 3, 1))
        .expect("IPv4 route should not exceed capacity");
    netif
        .routes_mut()
        .add_default_ipv6_route(Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, 2))
        .expect("IPv6 route should not exceed capacity");

    let stack = Arc::new(Mutex::new(IpStackInner {
        netif,
        dev,
        socket_set: SocketSet::new(vec![]),
        tcp_sockets: BTreeMap::new(),
        udp_sockets: BTreeMap::new(),
        tcp_next,
        udp_next,
    }));
    println!("🍎ip_stack: 启动IP栈");
    tokio::runtime::Handle::current().spawn_blocking(move || {
        while let Some(recv_buf) = tun.blocking_recv() {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
            //println!("🍎ip_stack: 收到数据包，时间: {}s {}ms，长度: {}", now.as_secs(), now.subsec_millis(), recv_buf.len());
            process_packet(&stack, recv_buf,dns_hijack, &resolver);
        }
    })
}

fn process_packet(stack: &IpStack, packet: Buffer, dns_hijack: bool, resolver: &Option<Arc<FakeIp>>) {
    if packet.len() < 20 {
        return;
    }
    match packet[0] >> 4 {
        0b0100 => {
            let mut ipv4_packet = match Ipv4Packet::new_checked(packet) {
                Ok(p) => p,
                Err(_) => return,
            };
            let (src_addr, dst_addr) = (ipv4_packet.src_addr(), ipv4_packet.dst_addr());
            match ipv4_packet.next_header() {
                IpProtocol::Tcp => {
                    let p = match TcpPacket::new_checked(ipv4_packet.payload_mut()) {
                        Ok(p) => p,
                        Err(_) => return,
                    };
                    let (src_port, dst_port, is_syn) = (p.src_port(), p.dst_port(), p.syn());
                    //println!("🍎ip_stack: TCP包，源端口: {}, 目标端口: {}, SYN: {}", src_port, dst_port, is_syn);
                 
                    process_tcp(
                        stack,
                        SocketAddr::new(smoltcp_addr_to_std(src_addr.into()), src_port),
                        dst_addr.into(),
                        dst_port,
                        is_syn,
                        ipv4_packet.into_inner(),
                    );
                }
                IpProtocol::Udp => {
                    let mut p = match UdpPacket::new_checked(ipv4_packet.payload_mut()) {
                        Ok(p) => p,
                        Err(_) => return,
                    };
                    let (src_port, dst_port) = (p.src_port(), p.dst_port());
                    process_udp(
                        stack,
                        SocketAddr::new(smoltcp_addr_to_std(src_addr.into()), src_port),
                        dst_addr.into(),
                        dst_port,
                        p.payload_mut(),
                        dns_hijack,
                        resolver,
                    );
                }
                _ => {}
            }
        }
        0b0110 => {
            let mut ipv6_packet = match Ipv6Packet::new_checked(packet) {
                Ok(p) => p,
                Err(_) => return,
            };
            let (src_addr, dst_addr) = (ipv6_packet.src_addr(), ipv6_packet.dst_addr());
            match ipv6_packet.next_header() {
                IpProtocol::Tcp => {
                    let p = match TcpPacket::new_checked(ipv6_packet.payload_mut()) {
                        Ok(p) => p,
                        Err(_) => return,
                    };
                    let (src_port, dst_port, is_syn) = (p.src_port(), p.dst_port(), p.syn());
                    process_tcp(
                        stack,
                        SocketAddr::new(smoltcp_addr_to_std(src_addr.into()), src_port),
                        dst_addr.into(),
                        dst_port,
                        is_syn,
                        ipv6_packet.into_inner(),
                    );
                }
                IpProtocol::Udp => {
                    let mut p = match UdpPacket::new_checked(ipv6_packet.payload_mut()) {
                        Ok(p) => p,
                        Err(_) => return,
                    };
                    let (src_port, dst_port) = (p.src_port(), p.dst_port());
                    process_udp(
                        stack,
                        SocketAddr::new(smoltcp_addr_to_std(src_addr.into()), src_port),
                        dst_addr.into(),
                        dst_port,
                        p.payload_mut(),
                        dns_hijack,
                        resolver,
                    );
                }
                _ => {}
            }
        }
        _ => {}
    };
}

fn process_tcp(
    stack: &IpStack,
    src_addr: SocketAddr,
    dst_addr: smoltcp::wire::IpAddress,
    dst_port: u16,
    is_syn: bool,
    packet: Buffer,

) {
    println!("🍎ip_stack: TCP包，数据包内容(十六进制): {:02x?}", &packet[0..20]);

    


    let mut guard = stack.lock().unwrap();
    let IpStackInner {
        netif,
        tcp_sockets,
        tcp_next,
        dev,
        socket_set,
        ..
    } = &mut *guard;

    dev.rx = Some(packet);

    let tcp_socket_count = tcp_sockets.len();
    println!(" 🍎当前 TCP 连接数: {}", tcp_socket_count);

    if let Entry::Vacant(vac) = tcp_sockets.entry(src_addr) {
        /* 
        if !is_syn || tcp_socket_count >= 1 << 10 {
            println!(" 🍎 拒绝连接: 不是 SYN 包或连接数超限");
            return;
        }*/
        let next = match tcp_next.upgrade() {
            Some(n) => n,
            None => {
                println!(" 🍎 无法获取 TCP 处理器");
                return;
            }
        };
       // println!(" 🍎创建新的 TCP 连接创建内部发送缓冲区和接受缓冲区");
        let mut socket = TcpSocket::new(
            RingBuffer::new(vec![0; 1024 * 14]),
            RingBuffer::new(vec![0; 10240]),
        );
        socket
            .listen(IpEndpoint::new(dst_addr, dst_port))
            .unwrap();
        socket.set_nagle_enabled(false);
        socket.set_ack_delay(None);
        let socket_handle = socket_set.add(socket);
        vac.insert(socket_handle);
        let ctx = FlowContext::new(
            src_addr,
            DestinationAddr {
                host: HostName::Ip(smoltcp_addr_to_std(dst_addr)),
                port: dst_port,
            },
        );
        //println!(" 🍎启动 TCP 流处理任务");
        tokio::spawn({
            let stack = stack.clone();
            async move {
                let mut stream = stream::IpStackStream {
                    socket_entry: tcp_socket_entry::TcpSocketEntry {
                        socket_handle,
                        stack,
                        local_endpoint: src_addr,
                        most_recent_scheduled_poll: Arc::new(AtomicI64::new(i64::MAX)),
                    },
                    rx_buf: None,
                    tx_buf: Some((Vec::with_capacity(4 * 1024), 0)),
                };
                if stream.handshake().await.is_ok() {
                    //println!(" 🍎 TCP 握手成功");
                    next.on_stream(Box::new(stream) as _, Buffer::new(), Box::new(ctx));
                } else {
                    //println!(" 🍎 TCP 握手失败");
                }
            }
        });
    } else {
        //println!(" 🍎已存在的 TCP 连接");
    };
    let now = Instant::now();
    let _ = netif.poll(now.into(), dev, socket_set);
    //println!(" 🍎 完成网络接口轮询");
}

fn process_udp(
    stack: &IpStack,
    src_addr: SocketAddr,
    dst_addr: smoltcp::wire::IpAddress,
    dst_port: u16,
    payload: &mut [u8],
    dns_hijack: bool,
    resolver: &Option<Arc<FakeIp>>,
) {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    println!("开始处理UDP包，时间: {}s {}ms", now.as_secs(), now.subsec_millis());
    println!("  源地址: {}, 目标地址: {}:{}, 负载长度: {}", src_addr, 
             smoltcp_addr_to_std(dst_addr), dst_port, payload.len());
    
    // 检查是否为DNS请求(UDP 53端口)，且启用了DNS劫持
    if dns_hijack && dst_port == 53 {
        println!("🔍 检测到DNS请求，尝试劫持并使用FakeIP处理");
        
        // 确保resolver有效
        if let Some(resolver) = resolver {
            // 尝试解析为DNS消息
            match hickory_proto::op::Message::from_vec(payload) {
                Ok(request_msg) => {
                    // 获取查询的域名
                    let query_domain = request_msg.query()
                        .map(|q| q.name().to_ascii())
                        .unwrap_or_else(|| "未知域名".to_string());
                        
                    println!("🔍 DNS查询域名: {}", query_domain);
                    
                    // 检查是否为AAAA查询
                    if let Some(query) = request_msg.query() {
                        if query.query_type() == hickory_proto::rr::RecordType::AAAA {
                            println!("🔍 不支持AAAA查询，返回Refused: {}", query_domain);
                            
                            // 创建拒绝响应消息
                            let mut response = hickory_proto::op::Message::error_msg(
                                request_msg.id(),
                                request_msg.op_code(),
                                hickory_proto::op::ResponseCode::Refused
                            );
                            
                            // 保留原始查询
                            response.add_query(query.clone());
                            
                            // 设置适当的标志
                            response.set_recursion_available(false);
                            response.set_authoritative(true);
                            response.set_recursion_desired(request_msg.recursion_desired());
                            response.set_checking_disabled(request_msg.checking_disabled());
                            
                            // 复制EDNS扩展(如果有)
                            if let Some(edns) = request_msg.extensions().clone() {
                                response.set_edns(edns);
                            }
                            
                            // 将响应消息序列化为二进制
                            match response.to_vec() {
                                Ok(response_data) => {
                                    // 获取发送缓冲区并构建响应包
                                    let mut stack_guard = stack.lock().unwrap();
                                    let dev = &mut stack_guard.dev;
                                    
                                    // 获取发送缓冲区
                                    let tx_buf = match dev.tun.get_tx_buffer() {
                                        Some(buf) => buf,
                                        None => {
                                            println!("❌ 无法获取发送缓冲区");
                                            return;
                                        }
                                    };
                                    
                                    // 检查负载长度
                                    if response_data.len() > 1500 - 28 {
                                        println!("❌ DNS响应数据过大: {}", response_data.len());
                                        dev.tun.return_tx_buffer(tx_buf);
                                        return;
                                    }
                                    
                                    // 构建回复包
                                    match (src_addr, dst_addr) {
                                        (SocketAddr::V4(src_v4), IpAddress::Ipv4(dst_ipv4)) => {
                                            println!("  构建IPv4 DNS响应包");
                                            
                                            // 构建IPv4包头
                                            let mut packet_data = Vec::with_capacity(20 + 8 + response_data.len());
                                            
                                            // IPv4 头部
                                            let mut header = [0u8; 20];
                                            header[0] = 0x45;  // 版本4，头部长度5 (5*4=20字节)
                                            
                                            // 总长度 (大端序)
                                            let total_len = (20 + 8 + response_data.len()) as u16;
                                            header[2] = (total_len >> 8) as u8;
                                            header[3] = (total_len & 0xFF) as u8;
                                            
                                            // 标识符、标志和片偏移都为0
                                            
                                            // TTL=64
                                            header[8] = 64;
                                            
                                            // 协议=UDP(17)
                                            header[9] = 17;
                                            
                                            // 源IP (DNS服务器，即原来的目标IP)
                                            let src_ip_bytes = dst_ipv4.as_bytes();
                                            header[12] = src_ip_bytes[0];
                                            header[13] = src_ip_bytes[1];
                                            header[14] = src_ip_bytes[2];
                                            header[15] = src_ip_bytes[3];
                                            
                                            // 目标IP (客户端，即原来的源IP)
                                            let dst_ip_bytes = src_v4.ip().octets();
                                            header[16] = dst_ip_bytes[0];
                                            header[17] = dst_ip_bytes[1];
                                            header[18] = dst_ip_bytes[2];
                                            header[19] = dst_ip_bytes[3];
                                            
                                            // 计算IP头校验和
                                            let mut checksum: u32 = 0;
                                            for i in 0..10 {
                                                checksum += ((header[i*2] as u32) << 8) | (header[i*2+1] as u32);
                                            }
                                            
                                            while checksum > 0xFFFF {
                                                checksum = (checksum & 0xFFFF) + (checksum >> 16);
                                            }
                                            
                                            let checksum = !checksum as u16;
                                            header[10] = (checksum >> 8) as u8;
                                            header[11] = (checksum & 0xFF) as u8;
                                            
                                            // 添加IP头部
                                            packet_data.extend_from_slice(&header);
                                            
                                            // UDP头部
                                            let mut udp_header = [0u8; 8];
                                            
                                            // 源端口 (使用原始请求的目标端口)
                                            udp_header[0] = (dst_port >> 8) as u8;
                                            udp_header[1] = (dst_port & 0xFF) as u8;
                                            
                                            // 目标端口 (客户端端口)
                                            let src_port = src_v4.port();
                                            udp_header[2] = (src_port >> 8) as u8;
                                            udp_header[3] = (src_port & 0xFF) as u8;
                                            
                                            // UDP长度
                                            let udp_len = (8 + response_data.len()) as u16;
                                            udp_header[4] = (udp_len >> 8) as u8;
                                            udp_header[5] = (udp_len & 0xFF) as u8;
                                            
                                            // UDP校验和设为0（可选）
                                            udp_header[6] = 0;
                                            udp_header[7] = 0;
                                            
                                            // 添加UDP头部
                                            packet_data.extend_from_slice(&udp_header);
                                            
                                            // 添加DNS响应数据
                                            packet_data.extend_from_slice(&response_data);
                                            
                                            // 复制数据到缓冲区
                                            let packet_len = packet_data.len();
                                            tx_buf.data[..packet_len].copy_from_slice(&packet_data);
                                            
                                            // 发送数据包
                                            dev.tun.send(tx_buf, packet_len);
                                            
                                            // 已处理响应，直接返回
                                            return;
                                        },
                                        (SocketAddr::V6(src_v6), IpAddress::Ipv6(dst_ipv6)) => {
                                            println!("  构建IPv6 DNS响应包");
                                            
                                            // IPv6处理类似，但头部格式不同
                                            println!("⚠️ IPv6 DNS响应暂未实现，释放缓冲区");
                                            dev.tun.return_tx_buffer(tx_buf);
                                            
                                            // 这里可以添加IPv6实现，类似IPv4
                                        },
                                        _ => {
                                            println!("❌ IP版本不匹配，无法构建DNS响应包");
                                            dev.tun.return_tx_buffer(tx_buf);
                                        }
                                    }
                                },
                                Err(e) => {
                                    println!("❌ 无法序列化DNS响应: {:?}", e);
                                }
                            }
                            
                            // 已处理AAAA请求，不继续处理FakeIP
                            return;
                        }
                    }
                    
                    // 使用exchange_with_resolver处理DNS请求
                    let enhanced = true; // 启用增强功能
                    
                    // 创建一个tokio运行时用于执行异步任务
                    let rt = tokio::runtime::Handle::current();
                    
                    let response_future = exchange_with_resolver::exchange_with_resolver(
                        resolver, 
                        &request_msg,
                        enhanced
                    );
                    
                    let response_result = rt.block_on(response_future);
                    
                    match response_result {
                        Ok(mut response) => {
                            // 确保保留原始请求的ID
                            response.set_id(request_msg.id());
                            
                            println!("🔍 DNS请求已成功处理，发送响应");
                            
                            // 将响应消息序列化为二进制
                            match response.to_vec() {
                                Ok(response_data) => {
                                    // 获取发送缓冲区并构建响应包
                                    let mut stack_guard = stack.lock().unwrap();
                                    let dev = &mut stack_guard.dev;
                                    
                                    // 获取发送缓冲区
                                    let tx_buf = match dev.tun.get_tx_buffer() {
                                        Some(buf) => buf,
                                        None => {
                                            println!("❌ 无法获取发送缓冲区");
                                            return;
                                        }
                                    };
                                    
                                    // 检查负载长度
                                    if response_data.len() > 1500 - 28 {
                                        println!("❌ DNS响应数据过大: {}", response_data.len());
                                        dev.tun.return_tx_buffer(tx_buf);
                                        return;
                                    }
                                    
                                    // 构建回复包
                                    match (src_addr, dst_addr) {
                                        (SocketAddr::V4(src_v4), IpAddress::Ipv4(dst_ipv4)) => {
                                            println!("  构建IPv4 DNS响应包");
                                            
                                            // 构建IPv4包头
                                            let mut packet_data = Vec::with_capacity(20 + 8 + response_data.len());
                                            
                                            // IPv4 头部
                                            let mut header = [0u8; 20];
                                            header[0] = 0x45;  // 版本4，头部长度5 (5*4=20字节)
                                            
                                            // 总长度 (大端序)
                                            let total_len = (20 + 8 + response_data.len()) as u16;
                                            header[2] = (total_len >> 8) as u8;
                                            header[3] = (total_len & 0xFF) as u8;
                                            
                                            // 标识符、标志和片偏移都为0
                                            
                                            // TTL=64
                                            header[8] = 64;
                                            
                                            // 协议=UDP(17)
                                            header[9] = 17;
                                            
                                            // 源IP (DNS服务器，即原来的目标IP)
                                            let src_ip_bytes = dst_ipv4.as_bytes();
                                            header[12] = src_ip_bytes[0];
                                            header[13] = src_ip_bytes[1];
                                            header[14] = src_ip_bytes[2];
                                            header[15] = src_ip_bytes[3];
                                            
                                            // 目标IP (客户端，即原来的源IP)
                                            let dst_ip_bytes = src_v4.ip().octets();
                                            header[16] = dst_ip_bytes[0];
                                            header[17] = dst_ip_bytes[1];
                                            header[18] = dst_ip_bytes[2];
                                            header[19] = dst_ip_bytes[3];
                                            
                                            // 计算IP头校验和
                                            let mut checksum: u32 = 0;
                                            for i in 0..10 {
                                                checksum += ((header[i*2] as u32) << 8) | (header[i*2+1] as u32);
                                            }
                                            
                                            while checksum > 0xFFFF {
                                                checksum = (checksum & 0xFFFF) + (checksum >> 16);
                                            }
                                            
                                            let checksum = !checksum as u16;
                                            header[10] = (checksum >> 8) as u8;
                                            header[11] = (checksum & 0xFF) as u8;
                                            
                                            // 添加IP头部
                                            packet_data.extend_from_slice(&header);
                                            
                                            // UDP头部
                                            let mut udp_header = [0u8; 8];
                                            
                                            // 源端口 (使用原始请求的目标端口)
                                            udp_header[0] = (dst_port >> 8) as u8;
                                            udp_header[1] = (dst_port & 0xFF) as u8;
                                            
                                            // 目标端口 (客户端端口)
                                            let src_port = src_v4.port();
                                            udp_header[2] = (src_port >> 8) as u8;
                                            udp_header[3] = (src_port & 0xFF) as u8;
                                            
                                            // UDP长度
                                            let udp_len = (8 + response_data.len()) as u16;
                                            udp_header[4] = (udp_len >> 8) as u8;
                                            udp_header[5] = (udp_len & 0xFF) as u8;
                                            
                                            // UDP校验和设为0（可选）
                                            udp_header[6] = 0;
                                            udp_header[7] = 0;
                                            
                                            // 添加UDP头部
                                            packet_data.extend_from_slice(&udp_header);
                                            
                                            // 添加DNS响应数据
                                            packet_data.extend_from_slice(&response_data);
                                            
                                            // 复制数据到缓冲区
                                            let packet_len = packet_data.len();
                                            tx_buf.data[..packet_len].copy_from_slice(&packet_data);
                                            
                                            // 发送数据包
                                            dev.tun.send(tx_buf, packet_len);
                                            
                                            // 已处理响应，直接返回
                                            return;
                                        },
                                        (SocketAddr::V6(src_v6), IpAddress::Ipv6(dst_ipv6)) => {
                                            println!("  构建IPv6 DNS响应包");
                                            
                                            // IPv6处理类似，但头部格式不同
                                            println!("⚠️ IPv6 DNS响应暂未实现，释放缓冲区");
                                            dev.tun.return_tx_buffer(tx_buf);
                                            
                                            // 这里可以添加IPv6实现，类似IPv4
                                        },
                                        _ => {
                                            println!("❌ IP版本不匹配，无法构建DNS响应包");
                                            dev.tun.return_tx_buffer(tx_buf);
                                        }
                                    }
                                },
                                Err(e) => {
                                    println!("❌ 无法序列化DNS响应: {:?}", e);
                                }
                            }
                        },
                        Err(e) => {
                            println!("❌ 处理DNS请求失败: {:?}", e);
                        }
                    }
                },
                Err(e) => {
                    println!("❌ 无法解析UDP负载为DNS消息: {:?}", e);
                }
            }
        } else {
            println!("⚠️ DNS劫持已启用，但未提供FakeIP解析器");
        }
    }
    
    // 打印UDP数据包的十六进制内容
    println!("  UDP数据包内容(十六进制):");
    for (i, chunk) in payload.chunks(16).enumerate() {
        let mut hex_line = format!("    {:04x}: ", i * 16);
        let mut ascii_line = String::new();
        
        for byte in chunk {
            hex_line.push_str(&format!("{:02x} ", byte));
            ascii_line.push(if (32..127).contains(byte) { *byte as char } else { '.' });
        }
        
        // 对齐ASCII部分
        if chunk.len() < 16 {
            for _ in 0..(16 - chunk.len()) {
                hex_line.push_str("   ");
            }
        }
        
        println!("{} {}", hex_line, ascii_line);
    }
    
    let mut guard = stack.lock().unwrap();
    let IpStackInner {
        udp_sockets,
        udp_next,
        ..
    } = &mut *guard;
    let tx = match udp_sockets.entry(src_addr) {
        Entry::Occupied(ent) => {
            println!("  找到已存在的UDP会话: {}", src_addr);
            ent.into_mut()
        }
        Entry::Vacant(vac) => {
            println!("开始创建UDP会话");
            let next = match udp_next.upgrade() {
                Some(next) => next,
                None => {
                    println!("  无法获取UDP处理器引用，放弃处理");
                    return;
                }
            };
            let (tx, rx) = bounded(48);
            let stack_inner = stack.clone();
            println!("  创建新的UDP会话: {}", src_addr);
            tokio::spawn(async move {
                println!("  启动新的UDP会话处理器");
                next.on_session(
                    Box::new(MultiplexedDatagramSessionAdapter::new(
                        datagram::IpStackDatagramSession {
                            stack: stack_inner,
                            local_endpoint: src_addr,
                        },
                        rx.into_stream(),
                        120,
                    )),
                    Box::new(FlowContext::new_af_sensitive(
                        src_addr,
                        DestinationAddr {
                            host: HostName::Ip(smoltcp_addr_to_std(dst_addr)),
                            port: dst_port,
                        },
                    )),
                );
                println!("  UDP会话处理器已启动");
            });
            vac.insert(tx)
        }
    };
    
    let payload_copy = payload.to_vec();
    let dest_addr = DestinationAddr {
        host: HostName::Ip(smoltcp_addr_to_std(dst_addr)),
        port: dst_port,
    };
    
    println!("  尝试发送UDP数据到处理器");
    match tx.try_send((
        dest_addr,
        payload_copy,
    )) {
        Ok(_) => {
            let end_time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
            println!("  成功将UDP数据包发送到处理器队列，时间: {}s {}ms", end_time.as_secs(), end_time.subsec_millis());
        },
        Err(TrySendError::Full(_)) => println!("  处理器队列已满，丢弃数据包"),
        Err(TrySendError::Disconnected(_)) => {
            println!("  UDP会话已断开，移除会话");
            udp_sockets.remove(&src_addr);
        }
    }
    // Drop packet when buffer is full
}

fn schedule_repoll(
    stack: Arc<Mutex<IpStackInner>>,
    poll_at: Instant,
    most_recent_scheduled_poll: Arc<AtomicI64>,
) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
    let stack_cloned = stack.clone();
    Box::pin(async move {
        sleep_until(tokio::time::Instant::from_std(poll_at)).await;
        if smoltcp::time::Instant::from(Instant::now()).total_millis()
            > most_recent_scheduled_poll.load(Ordering::Relaxed)
        {
            // A more urgent poll was scheduled.
            return;
        }
        let mut stack_guard = stack.lock().unwrap();
        let IpStackInner {
            netif,
            socket_set,
            dev,
            ..
        } = &mut *stack_guard;
        let _ = netif.poll(poll_at.into(), dev, socket_set);
        if let Some(delay) = netif.poll_delay(poll_at.into(), socket_set) {
            let scheduled_poll_milli =
                (smoltcp::time::Instant::from(Instant::now()) + delay).total_millis();
            if scheduled_poll_milli >= most_recent_scheduled_poll.load(Ordering::Relaxed) {
                return;
            }
            // TODO: CAS spin loop
            most_recent_scheduled_poll.store(scheduled_poll_milli, Ordering::Relaxed);

            tokio::spawn(schedule_repoll(
                stack_cloned,
                poll_at + Duration::from(delay),
                most_recent_scheduled_poll,
            ));
        }
    }) as _
}

fn smoltcp_addr_to_std(addr: IpAddress) -> IpAddr {
    match addr {
        IpAddress::Ipv4(ip) => IpAddr::V4(ip.into()),
        IpAddress::Ipv6(ip) => IpAddr::V6(ip.into()),
    }
}