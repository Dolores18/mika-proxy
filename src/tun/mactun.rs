use crate::flow::{Buffer, TunBufferToken, TunBufferSignature, Tun};
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;
use std::io::{self, Result as IoResult};
use std::process::Command;
use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf, AsyncRead, AsyncWrite};

use tun::AbstractDevice;
use log::{info, error, debug};
use tun::AsyncDevice;


/// Mac平台下的TUN设备实现
pub struct MacTun {
    inner: AsyncDevice,
    buffer_pool: Arc<Mutex<VecDeque<Buffer>>>,
    mtu: usize,
    name: String,
    address: IpAddr,
}

impl MacTun {
    /// 使用配置参数创建一个新的TUN设备和MacTun实例
    pub fn new(
        name: Option<&str>, 
        address: IpAddr, 
        netmask: IpAddr, 
        mtu: Option<usize>
    ) -> IoResult<Self> {
        // 创建TUN设备配置
        let mut config = tun::Configuration::default();
        
        // 设置TUN设备参数
        if let Some(name) = name {
            config.tun_name(name);
        }
        
        config
            .address(address)
            .netmask(netmask)
            .mtu(mtu.unwrap_or(1500) as u16)
            .up();
            
        // 创建TUN设备
        let device = tun::create_as_async(&config)?;
        info!("创建TUN设备成功：{:?}", device.mtu());
        
        let name_str = name.unwrap_or("utun").to_string();
        
        Ok(Self {
            inner: device,
            buffer_pool: Arc::new(Mutex::new(VecDeque::new())),
            mtu: mtu.unwrap_or(1500),
            name: name_str,
            address,
        })
    }
    
    /// 专门用于IPv4的便捷方法，直接接受IPv4地址和子网掩码
    pub fn new_ipv4(
        name: &str,
        address: Ipv4Addr,
        netmask: Ipv4Addr,
        mtu: Option<usize>
    ) -> IoResult<Self> {
        Self::new(
            Some(name),
            IpAddr::V4(address),
            IpAddr::V4(netmask),
            mtu
        )
    }
    
    /// 从已有的AsyncDevice创建MacTun实例
    pub fn from_device(device: AsyncDevice) -> Self {
        let mtu = device.mtu().unwrap_or(1500) as usize;
        
        Self {
            inner: device,
            buffer_pool: Arc::new(Mutex::new(VecDeque::new())),
            mtu,
            name: "unknown".to_string(),
            address: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        }
    }
    
    /// 获取设备MTU
    pub fn mtu(&self) -> usize {
        self.mtu
    }
    
    /// 获取设备名称
    pub fn get_name(&self) -> &str {
        &self.name
    }
    
    /// 获取设备IP地址
    pub fn get_address(&self) -> IpAddr {
        self.address
    }
    
    /// 关闭TUN设备
    pub fn shutdown(&self) {
        info!("正在关闭TUN设备: {}", self.name);
        // TUN设备关闭逻辑在这里实现
        // 如果需要额外的资源清理，可以在这里添加
    }
}

impl Tun for MacTun {
    fn blocking_recv(&self) -> Option<Buffer> {
        // 尝试从缓冲池获取缓冲区，或创建新的
        let mut buf = {
            let mut pool = self.buffer_pool.lock().unwrap();
            pool.pop_front().unwrap_or_else(|| Buffer::new())
        };
        
        // 确保缓冲区有足够容量
        if buf.capacity() < self.mtu {
            buf = Buffer::with_capacity(self.mtu);
        }
        
        // 安全地将buf调整到MTU大小
        unsafe {
            buf.set_len(self.mtu);
        }
        
        // 使用tokio的block_in_place在当前线程阻塞，等待数据
        match tokio::task::block_in_place(|| {
            let rt = tokio::runtime::Handle::current();
            rt.block_on(async {
                // 使用AsyncDevice的recv方法接收数据
                self.inner.recv(&mut buf).await
            })
        }) {
            Ok(len) => {
                // 调整buffer长度为实际接收的数据长度
                unsafe {
                    buf.set_len(len);
                }
                Some(buf)
            },
            Err(e) => {
                error!("TUN接收失败: {:?}", e);
                // 返回缓冲区到池中
                let mut pool = self.buffer_pool.lock().unwrap();
                pool.push_back(buf);
                None
            }
        }
    }
    
    fn return_recv_buffer(&self, buf: Buffer) {
        // 将用完的缓冲区返回到缓冲池
        let mut pool = self.buffer_pool.lock().unwrap();
        if pool.len() < 64 { // 限制池大小以避免内存泄漏
            pool.push_back(buf);
        }
    }
    
    fn get_tx_buffer(&self) -> Option<TunBufferToken> {
        let mut buf = vec![0u8; self.mtu];
        
        // 创建一个静态生命周期的缓冲区
        // 安全：我们通过Token的生命周期管理这块内存
        let static_buf = Box::leak(buf.into_boxed_slice());
        
        // 创建签名，使用指针地址作为唯一标识
        let signature = [
            static_buf.as_ptr() as *mut usize,
            static_buf.len() as *mut usize,
        ];
        
        // 安全：我们确保签名和缓冲区在使用期间保持有效
        unsafe {
            Some(TunBufferToken::new(signature, static_buf))
        }
    }
    
    fn send(&self, buf: TunBufferToken, len: usize) {
        let (_, data) = buf.into_parts();
        
        // 使用tokio的runtime发送数据
        tokio::task::block_in_place(|| {
            let rt = tokio::runtime::Handle::current();
            let _ = rt.block_on(async {
                match self.inner.send(&data[..len]).await {
                    Ok(_) => {},
                    Err(e) => error!("TUN发送失败: {:?}", e),
                }
            });
        });
        
        // 释放静态缓冲区
        unsafe {
            let _ = Box::from_raw(data);
        }
    }
    
    fn return_tx_buffer(&self, buf: TunBufferToken) {
        // 释放静态缓冲区
        let (_, data) = buf.into_parts();
        unsafe {
            let _ = Box::from_raw(data);
        }
    }
}

impl Drop for MacTun {
    fn drop(&mut self) {
        // 清空缓冲池，释放所有缓冲区
        let mut pool = self.buffer_pool.lock().unwrap();
        pool.clear();
    }
}