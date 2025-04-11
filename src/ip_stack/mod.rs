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
        // 检查缓冲区是否存在
        if self.0.is_none() {
            println!("🔴错误: TxToken中缓冲区为空! Consuming a TxToken without tx buffer set");
            // 创建一个空结果返回，避免panic
            return f(&mut []);
        }
        
        let buf = self.0.as_mut().unwrap();
        
        // 检查长度是否超过限制
        if len > buf.data.len() {
            println!("🔴错误: 数据长度{}超过缓冲区大小{}! smoltcp cannot write a packet to a TUN interface with smaller MTU set.",
                    len, buf.data.len());
            
            // 使用可用缓冲区尽可能运行函数
            let res = f(&mut buf.data);
            return res;
        }
        
        println!("✅准备将数据写入缓冲区，长度: {}", len);
        let res = f(&mut buf.data[..len]);
        println!("🍎ip_stack与tun交互，长度: {}", len);
        
        // 安全地获取缓冲区并发送
        match self.0.take() {
            Some(buffer) => {
                println!("✅发送数据到TUN设备，长度: {}", len);
                // 打印缓冲区内容帮助调试
                if len > 0 && len <= 64 {
                    println!("✅发送数据内容(前{}字节): {:02x?}", 
                             std::cmp::min(len, 64), 
                             &buffer.data[..std::cmp::min(len, 64)]);
                }
                
                // 发送数据到TUN设备，添加重试机制
                const MAX_RETRIES: usize = 3;
                let mut retry_count = 0;
                loop {
                    match self.1.send(buffer.clone(), len) {
                        Ok(_) => {
                            println!("✅数据已成功发送到TUN设备");
                            break;
                        },
                        Err(e) => {
                            if e.kind() == std::io::ErrorKind::Interrupted && retry_count < MAX_RETRIES {
                                retry_count += 1;
                                println!("⚠️ 发送被中断，正在进行第{}次重试", retry_count);
                                continue;
                            } else if e.kind() == std::io::ErrorKind::WouldBlock && retry_count < MAX_RETRIES {
                                retry_count += 1;
                                println!("⚠️ 发送会阻塞，正在进行第{}次重试", retry_count);
                                // 短暂等待后重试，避免立即重试造成的资源浪费
                                std::thread::sleep(std::time::Duration::from_millis(10));
                                continue;
                            } else {
                                println!("❌ 发送到TUN设备失败: {:?}", e);
                                if retry_count > 0 {
                                    println!("❌ 已重试{}次，放弃发送", retry_count);
                                }
                                break;
                            }
                        }
                    }
                }
            },
            None => {
                println!("🔴错误: 尝试发送数据时缓冲区为空!");
            }
        }
        
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
            println!("🍎ip_stack: 收到数据包，时间: {}s {}ms，长度: {}, 数据包内容(十六进制): {:02x?}", now.as_secs(), now.subsec_millis(), recv_buf.len(), recv_buf);
            process_packet(&stack, recv_buf);
        }
    })
}

fn process_packet(stack: &IpStack, packet: Buffer) {
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
                    println!("🍎ip_stack: TCP包，源端口: {}, 目标端口: {}, SYN: {}", src_port, dst_port, is_syn);
                 
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
    println!("🍎ip_stack: TCP包，数据包内容(十六进制): {:02x?}", packet);

    


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
        if !is_syn || tcp_socket_count >= 1 << 10 {
            println!(" 🍎 拒绝连接: 不是 SYN 包或连接数超限");
            return;
        }
        let next = match tcp_next.upgrade() {
            Some(n) => n,
            None => {
                println!(" 🍎 无法获取 TCP 处理器");
                return;
            }
        };
        println!(" 🍎创建新的 TCP 连接创建内部发送缓冲区和接受缓冲区");
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
        println!(" 🍎启动 TCP 流处理任务");
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
                    println!(" 🍎 TCP 握手成功");
                    next.on_stream(Box::new(stream) as _, Buffer::new(), Box::new(ctx));
                } else {
                    println!(" 🍎 TCP 握手失败");
                }
            }
        });
    } else {
        println!(" 🍎已存在的 TCP 连接");
    };
    let now = Instant::now();
    let _ = netif.poll(now.into(), dev, socket_set);
    println!(" 🍎 完成网络接口轮询");
}

fn process_udp(
    stack: &IpStack,
    src_addr: SocketAddr,
    dst_addr: smoltcp::wire::IpAddress,
    dst_port: u16,
    payload: &mut [u8],
) {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    println!("开始处理UDP包，时间: {}s {}ms", now.as_secs(), now.subsec_millis());
    println!("  源地址: {}, 目标地址: {}:{}, 负载长度: {}", src_addr, 
             smoltcp_addr_to_std(dst_addr), dst_port, payload.len());
    
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