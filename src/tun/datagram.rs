use std::task::{Context, Poll};
use std::sync::Arc;
use futures::{StreamExt, SinkExt, future};
use netstack_smoltcp::UdpSocket;
use crate::flow::datagram::*;
use crate::flow::*;
use log::{info, error, warn, debug, trace};
use tokio::sync::mpsc::{self, Sender, Receiver};
use std::net::{SocketAddr, IpAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::net::Ipv4Addr;
use std::collections::HashMap;
/// UDP数据包结构
#[derive(Debug)]
pub struct UdpPacket {
    pub data: Vec<u8>,
    pub src_addr: SocketAddr,
    pub dst_addr: SocketAddr,
}

/// MPSC通道驱动的UDP会话
pub struct TunDatagramSession {
    // 用于发送和接收数据的通道
    rx_receiver: Receiver<(DestinationAddr, Buffer)>,
    tx_sender: Sender<UdpPacket>,
    // 会话状态标志
    closed: Arc<AtomicBool>,
    // 会话上下文，用于存储地址信息
    flow_context: Arc<Mutex<Box<FlowContext>>>,
}

impl TunDatagramSession {
    pub fn new(socket: UdpSocket, flow_context: Box<FlowContext>) -> Self {
        // 分离socket读写部分
        let (mut lr, mut ls) = socket.split();
        
        // 创建转发通道，用于写入TUN设备
        let (dup_ls, mut dup_lr) = mpsc::channel(32);
        
        // 创建会话内外部通信通道
        let (rx_sender, rx_receiver) = mpsc::channel::<(DestinationAddr, Buffer)>(100);
        let (tx_sender, mut tx_receiver) = mpsc::channel::<UdpPacket>(100);
        
        // 关闭状态标志
        let closed = Arc::new(AtomicBool::new(false));
        
        // 将FlowContext包装在Arc<Mutex>中以便共享
        let flow_context = Arc::new(Mutex::new(flow_context));
        
        // 启动写入转发任务
        tokio::spawn(async move {
            debug!("UDP写入任务已启动");
            while let Some((data, local, remote)) = dup_lr.recv().await {
                if let Err(e) = ls.send((data, local, remote)).await {
                    warn!("发送UDP数据包到netstack失败: {}", e);
                    // 继续处理下一个数据包
                }
            }
            debug!("UDP写入任务已停止");
        });
        
        // 转发通道句柄
        let ls_handle = dup_ls.clone();
        
        // 创建端口映射表，用于跟踪请求和响应的对应关系
        let port_mappings = Arc::new(Mutex::new(HashMap::<u16, SocketAddr>::new()));
        let port_mappings_clone = port_mappings.clone();
        
        // FakeIP处理点1: 下行数据处理任务
        let ctx_for_tx = flow_context.clone();
        let fut1 = tokio::spawn(async move {
            debug!("UDP下行处理任务已启动");
            while let Some(mut pkt) = tx_receiver.recv().await {
                // 查找对应的客户端地址
                let dst_addr = {
                    let mappings = port_mappings.lock().unwrap();
                    // 使用源端口作为键来查找对应的客户端地址
                    if let Some(client_addr) = mappings.get(&pkt.src_addr.port()) {
                        *client_addr
                    } else {
                        // 如果找不到映射，使用原始目标地址
                        pkt.dst_addr
                    }
                };
                
                // 设置DNS服务器地址为8.8.8.8:53
                pkt.src_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
                
                println!("🍎UDP下行数据包(从服务器到客户端): {}→{}, 大小: {}", 
                         pkt.src_addr, dst_addr, pkt.data.len());
                
                // 发送数据包到netstack
                if let Err(e) = ls_handle.send((pkt.data, pkt.src_addr, dst_addr)).await {
                    println!("🍎发送UDP数据包到netstack失败: {}", e);
                    // 继续处理下一个数据包
                }
            }
            debug!("UDP下行处理任务已停止");
        });
        
        // FakeIP处理点2: 上行数据处理任务
        let ctx_for_rx = flow_context.clone();
        let fut2 = tokio::spawn(async move {
            debug!("UDP上行处理任务已启动");
            
            'read_packet: while let Some((data, src_addr, dst_addr)) = lr.next().await {
                // 过滤多播地址
                if dst_addr.ip().is_multicast() {
                    trace!("跳过多播地址数据包: {}", dst_addr);
                    continue 'read_packet;
                }
                
                trace!("收到上行UDP数据包: {}→{}, 大小: {}", src_addr, dst_addr, data.len());
                
                // 更新上下文中的地址信息（每个包都更新）
                {
                    let mut ctx = ctx_for_rx.lock().unwrap();
                    ctx.local_peer = src_addr;  // 本地地址是源地址（客户端地址）
                    ctx.remote_peer = DestinationAddr {
                        host: HostName::Ip(dst_addr.ip()),
                        port: dst_addr.port(),
                    };
                    println!("🍎已更新FlowContext地址信息 - 本地: {:?}, 远程: {:?}", 
                             ctx.local_peer, ctx.remote_peer);
                }
                
                // 保存端口映射关系
                {
                    let mut mappings = port_mappings_clone.lock().unwrap();
                    // 使用目标端口作为键，保存客户端地址
                    mappings.insert(dst_addr.port(), src_addr);
                    println!("🍎已保存端口映射: {}:{} -> {}", 
                             dst_addr.ip(), dst_addr.port(), src_addr);
                }
                
                // 转换为目的地址格式
                let dest_addr = DestinationAddr {
                    host: HostName::Ip(dst_addr.ip()),
                    port: dst_addr.port(),
                };
                
                // 发送到接收通道
                if let Err(e) = rx_sender.send((dest_addr, Buffer::from(data))).await {
                    error!("转发UDP数据到接收通道失败: {}", e);
                    // 继续处理下一个数据包
                    continue 'read_packet;
                }
            }
            
            debug!("UDP上行处理任务已停止");
        });
        
        // 启动监控任务，等待上面两个任务完成
        tokio::spawn(async move {
            debug!("UDP会话监控任务已启动");
            let _ = future::join(fut1, fut2).await;
            debug!("UDP会话所有任务已完成");
        });
        
        Self {
            tx_sender,
            rx_receiver,
            closed,
            flow_context,
        }
    }
}


impl DatagramSession for TunDatagramSession {
    fn poll_recv_from(&mut self, cx: &mut Context) -> Poll<Option<(DestinationAddr, Buffer)>> {
        match self.rx_receiver.poll_recv(cx) {
            Poll::Ready(Some(data)) => Poll::Ready(Some(data)),
            Poll::Ready(None) => {
                debug!("UDP接收通道已关闭");
                self.closed.store(true, Ordering::Relaxed);
                Poll::Ready(None)
            },
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_send_ready(&mut self, _cx: &mut Context<'_>) -> Poll<()> {
        Poll::Ready(())
    }

    fn send_to(&mut self, remote_peer: DestinationAddr, buf: Buffer) {
        if let HostName::Ip(ip) = remote_peer.host {
            // 获取上下文中的地址
            let flow_ctx = self.flow_context.lock().unwrap();
            
            // 对于下行数据包（从服务器到客户端的响应）:
            // - 源地址应该是远程服务器(remote_peer)
            // - 目标地址应该是本地客户端(local_peer)
            let src_addr = std::net::SocketAddr::new(ip, remote_peer.port); // 远程服务器地址
            let dst_addr = flow_ctx.local_peer; // 本地客户端地址
     
            println!("🍎UDP响应数据包 - 源(远程服务器): {} → 目标(本地客户端): {}", src_addr, dst_addr);
        
            
            let data = buf.to_vec();
            
            // 创建数据包
            let pkt = UdpPacket {
                data,
                src_addr,
                dst_addr,
            };
            
            // 获取发送者通道的克隆
            let tx = self.tx_sender.clone();
            
            // 异步发送数据包，无需阻塞当前方法
            tokio::spawn(async move {
                if let Err(e) = tx.send(pkt).await {
                    error!("发送UDP数据到处理通道失败: {}", e);
                }
            });
        }
    }

    fn poll_shutdown(&mut self, _cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        // 标记会话为已关闭
        self.closed.store(true, Ordering::Relaxed);
        debug!("UDP会话标记为已关闭");
        
        // 返回完成状态
        Poll::Ready(Ok(()))
    }
}

impl Drop for TunDatagramSession {
    fn drop(&mut self) {
        debug!("UDP会话正在关闭...");
        self.closed.store(true, Ordering::Relaxed);
        debug!("UDP会话已关闭");
    }
}
/// UDP会话处理器
pub struct TunDatagramHandler {
    next: std::sync::Weak<dyn DatagramSessionHandler>,
}

impl TunDatagramHandler {
    pub fn new(next: std::sync::Weak<dyn DatagramSessionHandler>) -> Self {
        Self { next }
    }
}

impl DatagramSessionHandler for TunDatagramHandler {
    fn on_session(&self, session: Box<dyn DatagramSession>, context: Box<FlowContext>) {
        if let Some(next) = self.next.upgrade() {
            info!("UDP会话转交给上层处理器");
            next.on_session(session, context);
        } else {
            error!("上层处理器不可用");
        }
    }
}