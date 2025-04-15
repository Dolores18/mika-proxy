use tun::AbstractDevice;
use netstack_smoltcp::StackBuilder;
use futures::{sink::SinkExt, stream::StreamExt};
use log::{info, error};
use std::error::Error as StdError;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    error::Error,
    result::Result,
};

use crate::flow::{
    StreamHandler, Buffer,
};
use crate::tun::routes::macos::Tunconfig;
use crate::tun::routes::macos::add_route;
// 使用crate路径导入我们的tcpstream模块
use crate::tun::stream::{TunStreamFactory, TunStreamAdapter};
use crate::tun::datagram::{TunDatagramSession, TunDatagramHandler};
use crate::flow::*;
use std::net::{Ipv4Addr, Ipv6Addr};
use crate::fakeip::FakeIp; // 导入FakeIp
use crate::tun::tun_stream::TunStreamHandler; // 添加这一行导入TunStreamHandler
// 添加处理UDP连接的函数
async fn handle_inbound_udp(
    udp_socket: netstack_smoltcp::UdpSocket,
    datagram_handler: std::sync::Arc<dyn DatagramSessionHandler>,
    dns_hijack: bool,
    fakeip: Option<Arc<FakeIp>>, // 添加FakeIp参数
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    info!("创建UDP会话处理器");
    
    // 创建初始上下文，使用一个临时地址
   
    let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    
    // 为会话创建上下文
    let remote_for_session = DestinationAddr {
        host: HostName::Ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        port: 0,
    };
    let context_for_session = Box::new(FlowContext::new(local, remote_for_session));
    
    // 创建UDP会话，并传入上下文
    let session = Box::new(TunDatagramSession::new(udp_socket, context_for_session, dns_hijack, fakeip));
    
    // 创建新的上下文传递给处理器
    // 这个上下文稍后会被更新，但指针保持不变
    let remote_for_handler = DestinationAddr {
        host: HostName::Ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        port: 0,
    };
    let handler_context = Box::new(FlowContext::new(local, remote_for_handler));
    
    // 将会话传递给处理器
    datagram_handler.on_session(session, handler_context);
    
    // 一旦会话被传递给处理器，所有的处理都在后台发生
    info!("UDP会话处理器已启动");
    
    // 不立即返回，而是保持此函数运行，直到程序结束
    // 创建一个不会完成的future来保持任务活跃
    let forever = std::future::pending::<()>();
    forever.await;
    
    Ok(())
}


// 添加路由
fn maybe_add_routes(routes: Option<Vec<String>>, tun_name: &str) {
    if let Some(routes) = routes {
        for route in routes {
            match add_route(tun_name, &route) {
                Ok(_) => info!("成功添加路由: {} 到 {}", route, tun_name),
                Err(e) => error!("添加路由失败: {} 到 {}: {}", route, tun_name, e),
            }
        }
    }
}


// 辅助函数，用于错误转换
fn to_box_err<E>(e: E) -> Box<dyn StdError + Send + Sync>
where
    E: StdError + Send + Sync + 'static,
{
    Box::new(e)
}

// 修改 Runner 类型定义
pub type Runner = futures::future::BoxFuture<'static, Result<(), Box<dyn StdError + Send + Sync>>>;

pub fn get_runner(cfg: Tunconfig) -> Result<Option<Runner>, Box<dyn StdError + Send + Sync>> {
    if !cfg.enabled {
        return Ok(None);
    }
    
    // 创建TUN设备
    let device_name = cfg.tun_name.clone();
    let mut config = tun::Configuration::default();
    config.tun_name(&cfg.tun_name);
    // 设置MTU
    if let Some(mtu) = cfg.mtu {
        config.mtu(mtu as u16);
    }
    // 设置地址和子网掩码
    config.address(&cfg.gateway);
    if let Some(ref netmask) = cfg.netmask {
        config.netmask(netmask);
    }
    config.up();
    
    let tun = tun::create_as_async(&config).map_err(to_box_err)?;
    
    // 添加路由
    maybe_add_routes(cfg.routes, &device_name);
    
    // 配置网络栈
    let mut builder = StackBuilder::default()
        .enable_tcp(true)
        .enable_udp(true)
        .enable_icmp(false);
        
    let (stack, runner, udp_socket, tcp_listener) = builder.build().unwrap();
    let udp_socket = udp_socket.unwrap();
    let tcp_listener = tcp_listener.unwrap();
    
    if let Some(runner) = runner {
        tokio::spawn(runner);
    }
    
    // 获取stream_handler，如果有的话
    let stream_handler = cfg.stream_handler.and_then(|w| w.upgrade());
    let stream_handler = stream_handler.clone();

    // 获取datagram_handler
    
    // 创建 TunDatagramHandler 实例
    let tun_datagram_handler = cfg.datagram_handler.and_then(|w| w.upgrade());
    let tun_datagram_handler = tun_datagram_handler.clone();
    //是否拦截dns请求
    let dns_hijack = cfg.dns_hijack;
    
    // 获取FakeIp实例
    let fakeip = cfg.fakeip.clone();
    
    Ok(Some(Box::pin(async move {
        let framed = tun.into_framed();
        let (mut tun_sink, mut tun_stream) = framed.split();
        let (mut stack_sink, mut stack_stream) = stack.split();

        let mut futs: Vec<Runner> = vec![];

        // 从栈读取数据包并发送到TUN
        futs.push(Box::pin(async move {
            while let Some(pkt) = stack_stream.next().await {
                match pkt {
                    Ok(pkt) => {
                        if let Err(e) = tun_sink.send(pkt).await {
                            error!("发送数据包到TUN失败: {}", e);
                            return Err(to_box_err(e));
                        }
                    }
                    Err(e) => {
                        error!("网络栈错误: {}", e);
                        return Err(to_box_err(e));
                    }
                }
            }
            Ok(())
        }));

        // 从TUN读取数据包并发送到栈
        futs.push(Box::pin(async move {
            while let Some(pkt) = tun_stream.next().await {
                match pkt {
                    Ok(pkt) => {
                        if let Err(e) = stack_sink.send(pkt).await {
                            error!("发送数据包到网络栈失败: {}", e);
                            return Err(to_box_err(e));
                        }
                    }
                    Err(e) => {
                        error!("TUN错误: {}", e);
                        return Err(to_box_err(e));
                    }
                }
            }
            Ok(())
        }));

        // 处理TCP连接
        futs.push(Box::pin(async move {
            let mut tcp_listener = tcp_listener;
            
            // 创建TunStreamFactory实例，使用现有的stream_handler
            let stream_factory = match &stream_handler {
                Some(handler) => {
                    let handler_clone = handler.clone();
                    Some(crate::tun::stream::TunStreamFactory::new(handler_clone))
                },
                None => None
            };
            
            while let Some((stream, local_addr, remote_addr)) = tcp_listener.next().await {
                // 使用TunStreamFactory处理连接
                if let Some(factory) = &stream_factory {
                    let factory_clone = factory.clone();
                    
                    tokio::spawn(async move {
                        println!("[inbound] 处理新的TCP连接: {} -> {}", remote_addr, local_addr);
                        
                        // 创建流适配器
                        let adapter = factory_clone.create_adapter_from_netstack(
                            stream,
                            local_addr, 
                            remote_addr
                        ).await;
                        
                        // 创建上下文
                        let context = Box::new(FlowContext::new_af_sensitive(
                            local_addr, 
                            DestinationAddr::from(remote_addr)
                        ));
                        
                        // 处理连接
                        factory_clone.handle_connection(adapter, context);
                    });
                } else {
                    println!("[inbound] 警告: 没有配置TCP处理器，忽略连接: {} -> {}", remote_addr, local_addr);
                }
            }
            Ok(())
        }));
            // 获取datagram_handler
  
            // 处理udP连接
        // 修改 futures 中的调用
        futs.push(Box::pin(async move {
            handle_inbound_udp(
                udp_socket, 
                tun_datagram_handler.expect("UDP处理程序未配置"),
                dns_hijack,
                fakeip // 传递FakeIp实例
            )
                .await
                .map_err(|e| {
                    error!("UDP处理错误: {}", e);
                    e
                })
        }));
    
        // 执行所有futures
        futures::future::select_all(futs).await.0.map_err(|x| {
            error!("tun error: {}. stopped", x);
            x
        })
    })))
}