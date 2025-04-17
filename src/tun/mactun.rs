use crate::flow::{Buffer, TunBufferToken, TunBufferSignature, Tun};
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;
use std::io::{self, Result as IoResult};
use std::process::Command;
use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf, AsyncRead, AsyncWrite};
use std::path::PathBuf;
use tun::AbstractDevice;
use log::info;
use tun::AsyncDevice;
use std::pin::Pin;
use std::task::{Context, Poll};
use futures_core::ready;
use std::io::{IoSlice, Read, Write};
use futures::FutureExt;
use futures_core::future::Future;

// MacTun设备类型，使用tokio进行异步操作
pub struct MacTun {
    // 内部tun设备实例
    device: Arc<AsyncDevice>,
    // 设备名称
    name: String,
    // 设备IP地址
    address: Ipv4Addr,
    // IPv6地址
    address_v6: Option<Ipv6Addr>,
    // 网络掩码
    netmask: Ipv4Addr,
    // 用于共享状态的队列
    buffer_pool: Arc<Mutex<VecDeque<Buffer>>>,
    // 接收和发送缓冲区的大小
    mtu: usize,
}

impl MacTun {
    /// 创建并初始化MacTun设备
    pub async fn new(
        name: &str, 
        address: Ipv4Addr,  // 使用传入的IP地址
        netmask: Ipv4Addr,  // 使用传入的网络掩码
        mtu: Option<usize>
    ) -> Result<Self, io::Error> {
        // 使用传入的IP地址和掩码
        // 禁用IPv6，防止系统发送自动配置和路由公告包
        let address_v6 = None;
        
        // 创建TUN设备配置
        let mut config = tun::Configuration::default();
        config
            .tun_name(name)
            .address(address)
            .netmask(netmask)
            .mtu(mtu.unwrap_or(1500) as u16)
            .up();
            
        // 创建TUN设备
        let device = tun::create_as_async(&config)?;
        // 获取实际设备名称
        let actual_name = device.tun_name().unwrap_or_else(|_| name.to_string());

        let mtu_val = mtu.unwrap_or(1500);
        
        // 创建MacTun实例
        let mac_tun = Self {
            device: Arc::new(device),
            name: actual_name,
            address,
            address_v6,
            netmask,
            buffer_pool: Arc::new(Mutex::new(VecDeque::new())),
            mtu: mtu_val,
        };
        
        // 如果支持IPv6，使用ifconfig命令手动配置
        if let Some(ipv6_addr) = &mac_tun.address_v6 {
            println!("配置IPv6地址: {}", ipv6_addr);
            // 使用ifconfig命令配置IPv6地址
            let _ = Command::new("ifconfig")
                .arg(&mac_tun.name)
                .arg("inet6")
                .arg(ipv6_addr.to_string())
                .arg("prefixlen")
                .arg("64")
                .arg("alias")
                .output();
        }
        
        Ok(mac_tun)
    }

    /// 获取TUN设备名称
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// 获取TUN设备IP地址
    pub fn get_address(&self) -> Ipv4Addr {
        self.address
    }
    
    /// 关闭TUN设备
    pub fn shutdown(&self) {
        info!("关闭TUN设备: {}", self.name);
        // 使用ifconfig命令将接口设置为down状态
        let _ = Command::new("ifconfig")
            .arg(&self.name)
            .arg("down")
            .output();
        
        info!("TUN设备已关闭: {}", self.name);
    }
    
    /// 接收数据包
    pub async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.device.recv(buf).await
    }
    
    /// 发送数据包
    pub async fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.device.send(buf).await
    }
}

// 实现AsyncRead trait，将读操作委托给内部的AsyncDevice
impl AsyncRead for MacTun {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf,
    ) -> Poll<std::io::Result<()>> {
        // 创建一个临时缓冲区
        let mut temp_buf = vec![0u8; buf.remaining()];
        let temp_buf_ptr = temp_buf.as_mut_ptr();
        let temp_buf_len = temp_buf.len();
        
        // 使用Box::pin正确地处理Future
        let device = &self.device;
        let mut temp_buf_slice = unsafe { std::slice::from_raw_parts_mut(temp_buf_ptr, temp_buf_len) };
        let fut = device.recv(&mut temp_buf_slice);
        let mut pinned_fut = Box::pin(fut);
        
        // 使用Future trait的poll方法
        match Future::poll(pinned_fut.as_mut(), cx) {
            Poll::Ready(Ok(n)) => {
                // 确保temp_buf已更新
                unsafe {
                    let updated_slice = std::slice::from_raw_parts(temp_buf_ptr, n);
                    buf.put_slice(updated_slice);
                }
                Poll::Ready(Ok(()))
            },
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

// 实现AsyncWrite trait，将写操作委托给内部的AsyncDevice
impl AsyncWrite for MacTun {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // 使用Box::pin正确地处理Future
        let device = &self.device;
        let fut = device.send(buf);
        let mut pinned_fut = Box::pin(fut);
        
        // 使用Future trait的poll方法
        Future::poll(pinned_fut.as_mut(), cx)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // AsyncDevice没有显式的flush操作，但我们可以
        // 实现一个空的flush，因为TUN设备通常不需要flush
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // 我们可以简单地返回Ok，因为关闭操作在drop时处理
        Poll::Ready(Ok(()))
    }
}

impl Tun for MacTun {
    fn blocking_recv(&self) -> Option<Buffer> {
        // 创建一个缓冲区来存储数据
        let mut buffer = Buffer::new();
        buffer.resize(self.mtu, 0);
        
        // 使用通道来获取异步结果
        let (tx, rx) = std::sync::mpsc::channel();
        
        // 克隆设备引用用于异步任务
        let device = self.device.clone();
        let mut buffer_clone = buffer.clone();
        
        // 使用tokio::spawn异步接收数据
        tokio::spawn(async move {
            // 从设备读取数据
            match device.recv(&mut buffer_clone).await {
                Ok(n) if n > 0 => {
                    // 调整缓冲区大小为实际读取的数据量
                    let mut result_buffer = buffer_clone;
                    result_buffer.resize(n, 0);
                    let _ = tx.send(Some(result_buffer));
                },
                Err(e) => {
                    eprintln!("读取TUN设备错误: {}", e);
                    let _ = tx.send(None);
                },
                _ => {
                    let _ = tx.send(None);
                }
            }
        });
        
        // 阻塞等待异步操作完成
        match rx.recv() {
            Ok(Some(result_buffer)) => {
                // 分析IP包详情
                if result_buffer.len() >= 20 {  // 至少需要IP头部
                    let version = result_buffer[0] >> 4;
                    let ihl = if version == 4 { (result_buffer[0] & 0x0F) * 4 } else { 0 };  // IP头部长度(4字节单位)
                    
                    if version == 4 && result_buffer.len() >= ihl as usize {  // IPv4
                        let protocol = result_buffer[9];
                        let src_ip = format!("{}.{}.{}.{}", result_buffer[12], result_buffer[13], result_buffer[14], result_buffer[15]);
                        let dst_ip = format!("{}.{}.{}.{}", result_buffer[16], result_buffer[17], result_buffer[18], result_buffer[19]);
                        
                        let proto_name = match protocol {
                            1 => "ICMP",
                            6 => "TCP",
                            17 => "UDP",
                            _ => "未知"
                        };
                        
                        info!("📦 接收IP包: IPv4, 协议: {}({}), 源IP: {}, 目标IP: {}",
                                proto_name, protocol, src_ip, dst_ip);
                        
                        // 如果是TCP/UDP，尝试打印端口信息
                        if (protocol == 6 || protocol == 17) && result_buffer.len() >= (ihl + 4) as usize {
                            let src_port = (result_buffer[ihl as usize] as u16) << 8 | result_buffer[(ihl+1) as usize] as u16;
                            let dst_port = (result_buffer[(ihl+2) as usize] as u16) << 8 | result_buffer[(ihl+3) as usize] as u16;
                            info!("📦 接收端口: 源端口: {}, 目标端口: {}", src_port, dst_port);
                        }
                        
                        info!("TUN设备接收: IP版本: {}, 协议: {}, 长度: {}", 
                                version, protocol, result_buffer.len());
                    } else if version == 6 && result_buffer.len() >= 40 {  // IPv6
                        let next_header = result_buffer[6];
                        // 简化的IPv6地址打印
                        info!("📦 接收IP包: IPv6, 下一头部: {}", next_header);
                        
                        info!("🐶MACTUN: IP版本: {}, 协议: {}, 长度: {}", 
                                version, next_header, result_buffer.len());
                    } else {
                        info!("🐶MACTUN: IP版本: {}, 长度: {}", version, result_buffer.len());
                    }
                } else {
                    info!("🐶MACTUN: 数据包太小，无法解析IP头");
                }
                
                info!("🐶MACTUN: 收到数据包，长度: {}", result_buffer.len());
                Some(result_buffer)
            },
            _ => None
        }
    }
    
    fn return_recv_buffer(&self, buf: Buffer) {
        // 将缓冲区放回池中以便重用
        info!("🐶MACTUN: 返还接收缓冲区，长度: {}", buf.len());
        self.buffer_pool.lock().unwrap().push_back(buf);
    }
    
    fn get_tx_buffer(&self) -> Option<TunBufferToken> {
        // 创建一个新的缓冲区
        let data = Box::new(vec![0u8; self.mtu]);
        let data_ptr = Box::into_raw(data);
        
        // 创建一个静态的可变引用
        let static_slice = unsafe {
            std::slice::from_raw_parts_mut((*data_ptr).as_mut_ptr(), self.mtu)
        };
        
        // 构造签名
        let signature = [data_ptr as *mut usize, std::ptr::null_mut()];
        
        info!("🐶MACTUN: 创建发送缓冲区，大小: {}", self.mtu);
        
        // 安全性：我们确保签名可以安全地发送到其他线程
        unsafe {
            Some(TunBufferToken::new(signature, static_slice))
        }
    }
    
    fn send(&self, buf: TunBufferToken, len: usize) {
        info!("🍓MACTUN: 发送数据包，长度: {}", len);
        
        let (signature, data) = buf.into_parts();
        
        // 添加更详细的数据包分析
        if len >= 20 {  // IP包头至少20字节
            let version = data[0] >> 4;
            let ihl = (data[0] & 0x0F) * 4;  // IP头部长度(以4字节为单位)
            
            if version == 4 && len >= ihl as usize {  // IPv4
                let protocol = data[9];
                let src_ip = format!("{}.{}.{}.{}", data[12], data[13], data[14], data[15]);
                let dst_ip = format!("{}.{}.{}.{}", data[16], data[17], data[18], data[19]);
                
                let proto_name = match protocol {
                    1 => "ICMP",
                    6 => "TCP",
                    17 => "UDP",
                    _ => "未知"
                };
                
                info!("📦 发送IP包详情: IPv4, 协议: {}({}), 源IP: {}, 目标IP: {}", 
                        proto_name, protocol, src_ip, dst_ip);
                
                // 如果是TCP/UDP，打印端口信息和前20字节负载
                if (protocol == 6 || protocol == 17) && len >= (ihl + 4) as usize {
                    let src_port = (data[ihl as usize] as u16) << 8 | data[(ihl+1) as usize] as u16;
                    let dst_port = (data[(ihl+2) as usize] as u16) << 8 | data[(ihl+3) as usize] as u16;
                    info!("📦 发送端口信息: 源端口: {}, 目标端口: {}", src_port, dst_port);
                    
                    // 打印负载的前20字节（如果存在）
                    if len > (ihl + 20) as usize {
                        let payload_start = (ihl + 20) as usize;
                        let payload_end = std::cmp::min(payload_start + 20, len);
                        info!("📦 发送负载前20字节: {:02X?}", &data[payload_start..payload_end]);
                    }
                }
            } else if version == 6 && len >= 40 {  // IPv6
                let next_header = data[6];
                // 简化的IPv6地址打印
                info!("📦 IP包详情: IPv6, 下一头部: {}", next_header);
            }
        }
        
        // 获取临时数据的副本
        let data_to_send = data[..len].to_vec();
        
        // 先释放原始缓冲区
        unsafe {
            let data_ptr = signature[0] as *mut Vec<u8>;
            if !data_ptr.is_null() {
                drop(Box::from_raw(data_ptr));
            }
        }
        
        // 使用tokio::spawn来异步处理写入操作
        // 克隆设备以在异步闭包中使用
        let device = self.device.clone();
        tokio::spawn(async move {
            if let Err(e) = device.send(&data_to_send).await {
                eprintln!("写入TUN设备错误: {}", e);
            } else {
                info!("✅ TUN设备写入成功: {} 字节", data_to_send.len());
            }
        });
    }
    
    fn return_tx_buffer(&self, buf: TunBufferToken) {
        // 释放缓冲区
        info!("TUN: 返还发送缓冲区");
        unsafe {
            let (signature, _) = buf.into_parts();
            let data_ptr = signature[0] as *mut Vec<u8>;
            if !data_ptr.is_null() {
                drop(Box::from_raw(data_ptr));
            }
        }
    }
}