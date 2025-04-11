#![feature(generic_const_exprs)]
#![feature(stmt_expr_attributes)]
#![feature(array_chunks)]
#![feature(result_flattening)]
use async_trait::async_trait;
use http::Uri;
use smallvec::SmallVec;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;
use std::sync::{Arc, Weak};

mod flow;
use flow::*;
mod shadowsocks;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use shadowsocks::crypto::*;
use shadowsocks::factory::stream::*;
mod socks5;
use socks5::*;
mod system_resolver;
use log::{error, info};
use std::panic;
use system_resolver::*;
mod redirect;
use redirect::{StreamRedirectHandler, StreamRedirectOutboundFactory};

use std::collections::HashSet;
pub mod fallback;
use fallback::FallbackStream;
mod drop_handler;
use drop_handler::DropHandler;
pub mod config;
pub mod forward; // 只声明一次
pub use config::ServerConfig;
pub use forward::{DatagramForwardHandler, StatHandle, StreamForwardHandler};
use serde::{Deserialize, Serialize};

// 移除与 socket 相关的重复逻辑
// 直接从 socket 模块引入相关工厂
mod socket;
pub use socket::*;

// 添加 socks5_udp 模块
mod socks5_udp;
use socks5_udp::Socks5UdpHandler;

// 添加 datagram 相关的导入
use crate::flow::datagram::*;
mod h2;
mod host_resolver;
use crate::host_resolver::doh_adapter::DohDatagramAdapterFactory;
use host_resolver::HostResolver;
mod http_proxy;
use http_proxy::HttpProxyOutboundFactory;
// 从 forward 模块导入 DatagramHandler

mod rule_dispatcher;
use cidr::IpCidr;
use maxminddb::Reader;
use rule_dispatcher::{Action, ActionHandle, RuleDispatcher, RuleDispatcherBuilder, RuleSet};
mod resolve_dest;
use resolve_dest::*;
use crate::socks5::Socks5Handler;

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerStatus {
    pub server_address: String,
    pub connections: usize,
    pub uplink_bytes: u64,
    pub downlink_bytes: u64,
}

pub struct SmartOutboundFactory {
    direct_factory: Weak<dyn StreamOutboundFactory>,
    ss_factory: Weak<dyn StreamOutboundFactory>,
    direct_domains: Weak<HashSet<String>>,
}

impl SmartOutboundFactory {
    fn new(
        direct_factory: &Arc<SocketOutboundFactory>,
        ss_factory: &Arc<ShadowsocksStreamOutboundFactory<Aes128Gcm>>,
        direct_domains: &Arc<HashSet<String>>,
    ) -> Self {
        Self {
            direct_factory: Arc::downgrade(direct_factory) as Weak<dyn StreamOutboundFactory>,
            ss_factory: Arc::downgrade(ss_factory) as Weak<dyn StreamOutboundFactory>,
            direct_domains: Arc::downgrade(direct_domains),
        }
    }

    fn should_direct(&self, domain: &str) -> bool {
        if let Some(domains) = self.direct_domains.upgrade() {
            check_domain(domain, &domains)
        } else {
            false
        }
    }
}

#[async_trait]
impl StreamOutboundFactory for SmartOutboundFactory {
    async fn create_outbound(
        &self,
        context: &mut FlowContext,
        initial_data: &'_ [u8],
    ) -> FlowResult<(Box<dyn Stream>, Buffer)> {
        if let HostName::DomainName(domain) = &context.remote_peer.host {
            info!("检查域名是否需要直连: {}", domain);
            if self.should_direct(domain) {
                println!("✅ 直连: {}", domain);
                if let Some(direct_factory) = self.direct_factory.upgrade() {
                    return direct_factory.create_outbound(context, initial_data).await;
                }
                return Err(FlowError::NoOutbound);
            }
            println!("❌ 代理域名: {}", domain);
        }

        info!("使用代理连接: {:?}", context.remote_peer.host);
        if let Some(ss_factory) = self.ss_factory.upgrade() {
            ss_factory.create_outbound(context, initial_data).await
        } else {
            Err(FlowError::NoOutbound)
        }
    }
}

// 修改 check_domain 函数
fn check_domain(host: &str, domains: &HashSet<String>) -> bool {
    info!("正在检查域名: {}", host);
    let host = host.to_lowercase();

    // 直接检查 HashSet 是否包含完整域名
    if domains.contains(&host) {
        info!("✅ 完全匹配成功: {}", host);
        return true;
    }

    // 检查是否是子域名
    for domain in domains {
        if host.ends_with(&format!(".{}", domain)) {
            info!("✅ 子域名匹配成功: {} 属于 {}", host, domain);
            return true;
        }
    }

    info!("❌ 匹配失败: {} 不在直连列表中", host);
    false
}

// 修改 load_direct_domains 函数，只从direct列表加载域名
fn load_direct_domains(app_config: &config::AppConfig) -> HashSet<String> {
    // 从 AppConfig 中读取直连域名
    let mut domains = HashSet::new();
    
    // 添加直连域名
    if !app_config.domains.direct.is_empty() {
        println!("从配置文件加载直连域名列表");
        println!("🔍 配置文件中的直连域名列表:");
        for (idx, domain) in app_config.domains.direct.iter().enumerate() {
            println!("   [{:3}] {}", idx + 1, domain);
            domains.insert(domain.to_lowercase());
        }
        println!("成功加载直连域名列表，共 {} 个域名", domains.len());
        info!("直连域名列表: {:?}", domains);
        return domains;
    }
    
    // 如果配置文件中没有域名列表，则尝试从文件加载
    let current_dir = std::env::current_dir().unwrap_or_default();
    info!("当前执行目录: {:?}", current_dir);

    match std::fs::read_to_string("direct_domains.txt") {
        Ok(content) => {
            println!("成功读取文件内容");
            let file_domains: HashSet<String> = content
                .lines()
                .filter(|line| !line.trim().is_empty())
                .filter(|line| !line.starts_with('#'))
                .map(str::trim)
                .map(|s| s.to_lowercase()) // 统一转换为小写
                .collect();

            domains.extend(file_domains);
            
            if domains.is_empty() {
                error!("域名列表为空！");
            } else {
                println!("成功加载直连域名列表，共 {} 个域名", domains.len());
                info!("直连域名列表: {:?}", domains);
            }
            domains
        }
        Err(e) => {
            error!("无法读取 direct_domains.txt: {}", e);
            error!(
                "尝试的文件路径: {:?}",
                current_dir.join("direct_domains.txt")
            );
            domains
        }
    }
}

// 简化代理域名加载函数
fn load_proxy_domains(app_config: &config::AppConfig) -> HashSet<String> {
    let mut domains = HashSet::new();
    
    // 添加代理域名
    if !app_config.domains.proxy.is_empty() {
        println!("从配置文件加载代理域名列表");
        domains.extend(app_config.domains.proxy.iter().map(|s| s.to_lowercase()));
        
        println!("成功加载代理域名列表，共 {} 个域名", domains.len());
        info!("代理域名列表: {:?}", domains);
    }
    
    domains
}

// 从文件加载quanx规则
fn load_quanx_rules_from_file(file_path: &str) -> Vec<String> {
    println!("从文件加载quanx规则: {}", file_path);
    
    match std::fs::read_to_string(file_path) {
        Ok(content) => {
            let rules: Vec<String> = content
                .lines()
                .filter(|line| !line.trim().is_empty())
                .filter(|line| !line.starts_with('#'))
                .map(|line| line.trim().to_string())
                .collect();
                
            println!("成功从文件加载quanx规则，共 {} 条规则", rules.len());
            
            // 打印前几条规则作为示例
            let sample_count = std::cmp::min(5, rules.len());
            if sample_count > 0 {
                println!("规则示例:");
                for (idx, rule) in rules.iter().take(sample_count).enumerate() {
                    println!("   [{}] {}", idx + 1, rule);
                }
                
                if rules.len() > sample_count {
                    println!("   ... 还有 {} 条规则", rules.len() - sample_count);
                }
            }
            
            rules
        }
        Err(e) => {
            println!("⚠️ 无法读取规则文件 {}: {}", file_path, e);
            Vec::new()
        }
    }
}

// 将原来 main 函数中的逻辑封装成一个公共函数
pub async fn start_proxy_server(
    server_addrs: Vec<String>,
    server_config: ServerConfig,
    app_config: config::AppConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("启动代理服务器");
    info!("地址列表: {:?}", server_addrs);
    info!("服务器配置: {:?}", server_config);
      // 修改代理地址创建方式
    let server_config_clone = Arc::new(server_config.clone());
    let proxy_addr = server_config_clone.create_fixed_adrr();

    // 创建 Shadowsocks 工厂，使用配置中的密钥
    let psd = &app_config.features.ss_key;
    let key = BASE64.decode(psd).expect("Failed to decode");
    let key: [u8; 16] = key.try_into().expect("Invalid key length");
    // 创建域名规则集合并包装在 Arc 中
    let direct_domains = Arc::new(load_direct_domains(&app_config));

    // 创建系统解析器
    let resolver: Arc<dyn Resolver> = Arc::new(SystemResolver::new());

    // 创建 socket 出站工厂
    let socket_outbound_factory = Arc::new(SocketOutboundFactory {
        resolver: Arc::downgrade(&resolver),
        bind_addr_v4: Some(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        bind_addr_v6: Some(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
    });

    // 创建 HTTP 代理工厂
    let http_proxy_factory = Arc::new(HttpProxyOutboundFactory::new(
        None,
        Arc::downgrade(&socket_outbound_factory) as Weak<dyn StreamOutboundFactory>,
    ));

    // 创建专门用于 DoH 的 TCP 工厂
    let doh_tcp_factory = Arc::new(SocketOutboundFactory {
        resolver: Arc::downgrade(&resolver),
        bind_addr_v4: Some(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        bind_addr_v6: Some(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
    });
    //创建doh重定向工厂
    let doh_redirect_factory = Arc::new(StreamRedirectOutboundFactory {
        remote_peer: proxy_addr.clone(),
        next: Arc::downgrade(&doh_tcp_factory) as Weak<dyn StreamOutboundFactory>,
    });
    //创建doh ss加密工厂
    let doh_ss_factory = Arc::new(ShadowsocksStreamOutboundFactory::<Aes128Gcm>::new(
        key,
        Arc::downgrade(&doh_redirect_factory) as Weak<dyn StreamOutboundFactory>,
    ));

    // 创建 DoH 工厂时使用配置中指定的 DoH 服务器
    let doh_factories = vec![DohDatagramAdapterFactory::new(
        app_config.dns.doh.parse().unwrap(), // 使用配置中的中国 DoH 服务器
        Arc::downgrade(&doh_ss_factory) as Weak<dyn StreamOutboundFactory>,
    )];
    println!("Created DoH client for URL: {}", app_config.dns.doh);

    // 创建 HostResolver
    let resolver2: Arc<dyn Resolver> = Arc::new(HostResolver::new(vec![], doh_factories));
    // 创建 socket_outbound_factory
    let socket_outbound_factory2 = Arc::new(SocketOutboundFactory {
        resolver: Arc::downgrade(&resolver2),
        bind_addr_v4: Some(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        bind_addr_v6: Some(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
    });
    log::debug!("Created system resolver and DoH resolver");

    // 统计对象
    let stat = forward::StatHandle::default();
    
  
    // 创建重定向工厂
    let redirect_factory = Arc::new(StreamRedirectOutboundFactory {
        remote_peer: proxy_addr.clone(),
        next: Arc::downgrade(&socket_outbound_factory2) as Weak<dyn StreamOutboundFactory>,
    });



    let ss_factory = Arc::new(ShadowsocksStreamOutboundFactory::<Aes128Gcm>::new(
        key,
        Arc::downgrade(&redirect_factory) as Weak<dyn StreamOutboundFactory>,
    ));
    
    // 创建智能分流工厂
    let smart_factory = Arc::new(SmartOutboundFactory::new(
        &socket_outbound_factory2,
        &ss_factory,
        &direct_domains,
    ));

    // 创建 StreamForwardHandler 实例，使用智能分流工厂
    let stream_forward_handler = Arc::new(forward::StreamForwardHandler {
        outbound: Arc::downgrade(&smart_factory) as Weak<dyn StreamOutboundFactory>,
        request_timeout: 10000,
        stat: stat,
    });

    //创建socks5处理器
    let socks5_handler = Arc::new(Socks5Handler::new(
        None,
        Arc::downgrade(&stream_forward_handler) as Weak<dyn StreamHandler>,
    ));

    // 监听地址设置，使用配置文件中的值
    let listen_addr_v4 = app_config.client.listen_addr_v4.clone();
    let listen_addr_v6 = app_config.client.listen_addr_v6.clone();

    println!(
        "Smart proxy server listening on {} (IPv4) and {} (IPv6)",
        listen_addr_v4, listen_addr_v6
    );

    // 创建监听器
    let handle_v4 = listen_tcp(
        Arc::downgrade(&socks5_handler) as Weak<dyn StreamHandler>,
        listen_addr_v4,
    )?;

    let handle_v6 = listen_tcp(
        Arc::downgrade(&socks5_handler) as Weak<dyn StreamHandler>,
        listen_addr_v6,
    )?;

    log::info!("Proxy server initialization complete");

    // 等待监听器完成
    tokio::try_join!(handle_v4, handle_v6)?;

    Ok(())
}

pub async fn start_udp_server(
    server_addrs: Vec<String>,
    server_config: ServerConfig,
    app_config: config::AppConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("启动 UDP 代理服务器");
    info!("地址列表: {:?}", server_addrs);
    info!("服务器配置: {:?}", server_config);

    // 创建系统解析器
    let resolver: Arc<dyn Resolver> = Arc::new(SystemResolver::new());

    // 创建统计对象
    let stat = forward::StatHandle::default();

    // 创建 UDP 出站工厂
    let socket_outbound_factory = Arc::new(SocketOutboundFactory {
        resolver: Arc::downgrade(&resolver),
        bind_addr_v4: Some(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        bind_addr_v6: Some(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
    });

    // 创建 UDP 转发处理器
    let datagram_handler = Arc::new(forward::DatagramForwardHandler {
        outbound: Arc::downgrade(&socket_outbound_factory) as Weak<dyn DatagramSessionFactory>,
        stat: stat,
    });

    // 创建 SOCKS5 UDP 处理器
    let socks5_udp_handler = Arc::new(Socks5UdpHandler::new(
        None,
        Arc::downgrade(&datagram_handler) as Weak<dyn DatagramSessionHandler>,
    ));

    // UDP 监听地址
    let udp_listen_addr_v4 = app_config.client.udp_listen_addr_v4.clone();
    let udp_listen_addr_v6 = app_config.client.udp_listen_addr_v6.clone();

    println!("Starting UDP proxy server...");
    println!(
        "UDP proxy server listening on {} (IPv4) and {} (IPv6)",
        udp_listen_addr_v4, udp_listen_addr_v6
    );

    // 创建 UDP 监听器，使用 SOCKS5 UDP 处理器
    let handle_v4 = listen_udp(
        Arc::downgrade(&socks5_udp_handler) as Weak<dyn DatagramSessionHandler>,
        udp_listen_addr_v4,
    )?;
    
    let handle_v6 = listen_udp(
        Arc::downgrade(&socks5_udp_handler) as Weak<dyn DatagramSessionHandler>,
        udp_listen_addr_v6,
    )?;

    // 等待监听器完成
    tokio::try_join!(handle_v4, handle_v6)?;

    Ok(())
}

pub async fn start_dispatcher_server(
    server_addrs: Vec<String>,
    server_config: ServerConfig,
    app_config: config::AppConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("启动分发代理服务器");
    info!("地址列表: {:?}", server_addrs);
    info!("服务器配置: {:?}", server_config);
    // 修改代理地址创建方式
    let server_config_clone = Arc::new(server_config.clone());
    let proxy_addr = server_config_clone.create_fixed_adrr();
    // 创建 Shadowsocks 工厂，使用配置中的密钥
    let psd = &app_config.features.ss_key;
    let key = BASE64.decode(psd).expect("Failed to decode");
    let key: [u8; 16] = key.try_into().expect("Invalid key length"); 

    // 创建统计对象
    let stat = forward::StatHandle::default();

    // 1. 创建基础组件
    let direct_resolver: Arc<dyn Resolver> = Arc::new(SystemResolver::new());

    // 2. 创建 DoH 客户端和代理组件
    let doh_tcp_factory = Arc::new(SocketOutboundFactory {
        resolver: Arc::downgrade(&direct_resolver),
        bind_addr_v4: Some(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        bind_addr_v6: Some(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
    });
    // 
    //创建doh重定向工厂
    let doh_redirect_factory = Arc::new(StreamRedirectOutboundFactory {
        remote_peer: proxy_addr.clone(),
        next: Arc::downgrade(&doh_tcp_factory) as Weak<dyn StreamOutboundFactory>,
    });
    //创建doh ss加密工厂
    let doh_ss_factory = Arc::new(ShadowsocksStreamOutboundFactory::<Aes128Gcm>::new(
    key,
    Arc::downgrade(&doh_redirect_factory) as Weak<dyn StreamOutboundFactory>,
    ));

    let doh_factories = vec![DohDatagramAdapterFactory::new(
        app_config.dns.doh.parse().unwrap(), // 使用配置中的国际 DoH 服务器
        Arc::downgrade(&doh_ss_factory) as Weak<dyn StreamOutboundFactory>,
    )];
    println!("Created DoH client for URL: {}", app_config.dns.doh);

    // 创建代理解析器
    let proxy_resolver: Arc<dyn Resolver> = Arc::new(HostResolver::new(vec![], doh_factories));

    // 3. 创建直连出站工厂
    let direct_outbound_factory = Arc::new(SocketOutboundFactory {
        resolver: Arc::downgrade(&direct_resolver),
        bind_addr_v4: Some(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        bind_addr_v6: Some(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
    });
 
    // 4. 创建直连转发处理器
    let direct_forward_handler = Arc::new(forward::StreamForwardHandler {
        outbound: Arc::downgrade(&direct_outbound_factory) as Weak<dyn StreamOutboundFactory>,
        request_timeout: 10000,
        stat: stat.clone(),
    });


    // 5. 创建代理处理器链


    let redirect_factory = Arc::new(StreamRedirectOutboundFactory {
        remote_peer: proxy_addr,
        next: Arc::downgrade(&direct_outbound_factory) as Weak<dyn StreamOutboundFactory>,
    });

    // 使用配置中的SS密钥
    let psd = &app_config.features.ss_key;
    let key = BASE64.decode(psd).expect("Failed to decode");
    let key: [u8; 16] = key.try_into().expect("Invalid key length");

    let ss_factory = Arc::new(ShadowsocksStreamOutboundFactory::<Aes128Gcm>::new(
        key,
        Arc::downgrade(&redirect_factory) as Weak<dyn StreamOutboundFactory>,
    ));

    let proxy_forward_handler = Arc::new(forward::StreamForwardHandler {
        outbound: Arc::downgrade(&ss_factory) as Weak<dyn StreamOutboundFactory>,
        request_timeout: 10000,
        stat: stat.clone(),
    });

    // 创建一个规则分发全局解析器
    let proxy_with_resolver = Arc::new(StreamForwardResolver {
        resolver: Arc::downgrade(&proxy_resolver),
        next: Arc::downgrade(&proxy_forward_handler) as Weak<dyn StreamHandler>,
    });

   // 6. 创建规则分发器
    let rule_dispatcher = Arc::new_cyclic(|me| {
        let mut builder = RuleDispatcherBuilder::default();
        builder.set_resolver(Some(Arc::downgrade(&proxy_resolver) as Weak<dyn Resolver>));

        // 创建直连动作
        let direct_action = Action {
            tcp_next: Arc::downgrade(&direct_forward_handler) as Weak<dyn StreamHandler>,
            resolver: Arc::downgrade(&direct_resolver) as Weak<dyn Resolver>,
        };
        println!("✅ 创建直连动作成功");

        let direct_handle = builder
            .add_action(direct_action)
            .expect("Failed to add direct action");

        // 创建代理动作,代理动作不能经过steam_forward_handler
        let proxy_action = Action {
            tcp_next: Arc::downgrade(&proxy_forward_handler) as Weak<dyn StreamHandler>,
            resolver: Arc::downgrade(&proxy_resolver) as Weak<dyn Resolver>,
        };
        println!("✅ 创建代理动作成功");

        let proxy_handle = builder
            .add_action(proxy_action)
            .expect("Failed to add proxy action");
            
        // 创建一个BTreeMap来映射动作名称到ActionHandle
        let mut action_map = std::collections::BTreeMap::new();
        action_map.insert("direct", direct_handle);
        action_map.insert("proxy", proxy_handle);
        
        // 尝试从rules.txt文件加载规则
        let mut quanx_rules = load_quanx_rules_from_file("rules.txt");
        
        // 如果文件加载失败或规则为空，则使用之前的方式构建规则
        if quanx_rules.is_empty() {
            println!("未找到规则文件或规则为空，使用配置构建规则");
            
            // 从配置加载域名规则
            let direct_domains_set = load_direct_domains(&app_config);
            let proxy_domains_set = load_proxy_domains(&app_config);
            
            // 准备域名规则列表
            let domain_rules: Vec<(&str, ActionHandle)> = if direct_domains_set.is_empty() && proxy_domains_set.is_empty() {
                println!("使用硬编码的域名规则");
                
                // 硬编码的直连域名
                let direct_domains = vec![
                    "acg.tv",
                    "acgvideo.com",
                    "b23.tv",
                    "bigfun.cn",
                    "bigfunapp.cn",
                    "biliapi.com",
                    "biliapi.net",
                    "bilibili.com",
                    "bilibili.tv",
                    "biligame.com",
                    "biligame.net",
                    "bilivideo.cn",
                    "bilivideo.com",
                    "hdslb.com",
                    "im9.com",
                    "smtcdns.net",
                    "baidu.com",
                    "baidubcr.com",
                    "baidupcs.com", 
                    "baidustatic.com",
                    "bcebos.com",
                    "bdimg.com",
                    "bdstatic.com", 
                    "bdurl.net",
                    "hao123.com",
                    "hao123img.com",
                    "jomodns.com",
                    "yunjiasu-cdn.net",
                ];
                
                // 硬编码的代理域名
                let proxy_domains = vec![
                    "google.com",
                    "google-analytics.com",
                    "googleapis.com",
                    "gstatic.com",
                    "doubleclick.net",
                    "www.google-analytics.com",
                    "www.googleapis.com",
                    "www.gstatic.com",
                    "www.doubleclick.net",
                    "beacons.gcp.gvt2.com",
                ];
                
                // 合并域名规则
                proxy_domains.iter().map(|d| (*d, proxy_handle))
                    .chain(direct_domains.iter().map(|d| (*d, direct_handle)))
                    .collect()
            } else {
                println!("使用配置文件中的域名规则");
                
                // 将String引用转换为&str
                let proxy_domains: Vec<&str> = proxy_domains_set.iter().map(|s| s.as_str()).collect();
                let direct_domains: Vec<&str> = direct_domains_set.iter().map(|s| s.as_str()).collect();
                
                // 打印域名列表
                println!("🔍 代理域名列表 ({}个):", proxy_domains.len());
                for (idx, domain) in proxy_domains.iter().enumerate() {
                    println!("   [{:3}] {}", idx + 1, domain);
                }
                
                println!("🔍 直连域名列表 ({}个):", direct_domains.len());
                for (idx, domain) in direct_domains.iter().enumerate() {
                    println!("   [{:3}] {}", idx + 1, domain);
                }
                
                // 合并域名规则
                let rules = proxy_domains.iter().map(|d| (*d, proxy_handle))
                    .chain(direct_domains.iter().map(|d| (*d, direct_handle)))
                    .collect::<Vec<_>>();
                    
                println!("👉 合并后的规则数量: {}", rules.len());
                rules
            };
                
            println!("✅ 成功创建域名规则列表，共{}条规则", domain_rules.len());
            
            // 构建quanx格式的规则字符串，形如: "domain-suffix,google.com,proxy"
            quanx_rules = domain_rules.iter()
                .map(|(domain, action)| {
                    let action_name = if *action == direct_handle { "direct" } else { "proxy" };
                    format!("domain-suffix,{},{}", domain, action_name)
                })
                .collect();
                
            // 检查转换后的域名规则是否完整
            println!("🔍 检查转换后的域名规则是否完整:");
            let domain_set: HashSet<&str> = domain_rules.iter()
                .map(|(domain, _)| *domain)
                .collect();
            
            // 检查配置文件中的直连域名是否都包含在规则中
            println!("🔍 检查直连域名是否都包含在规则中:");
            for domain in direct_domains_set.iter() {
                if domain_set.contains(domain.as_str()) {
                    println!("   ✅ {} 已包含", domain);
                } else {
                    println!("   ❌ {} 缺失!", domain);
                }
            }
            
            // 检查配置文件中的代理域名是否都包含在规则中
            println!("🔍 检查代理域名是否都包含在规则中:");
            for domain in proxy_domains_set.iter() {
                if domain_set.contains(domain.as_str()) {
                    println!("   ✅ {} 已包含", domain);
                } else {
                    println!("   ❌ {} 缺失!", domain);
                }
            }
            
            // 添加GeoIP规则（与域名规则一起处理）
            quanx_rules.push("geoip,CN,direct".to_string());
            quanx_rules.push("geoip,US,proxy".to_string());
            println!("📍 添加GeoIP规则: geoip,CN,direct");
            println!("📍 添加GeoIP规则: geoip,US,proxy");
        }
        
        // 计算域名规则数量（不包括GeoIP规则）
        let domain_rules_count = quanx_rules.iter()
            .filter(|rule| !rule.starts_with("geoip"))
            .count();
        
        println!("📊 域名规则总数: {}", domain_rules_count);
        
        // 调试输出：所有规则
        println!("📝 完整规则列表:");
        for (idx, rule) in quanx_rules.iter().enumerate() {
            println!("   [{}] {}", idx + 1, rule);
        }
            
        // 尝试使用quanx_filter加载器
        // 读取GeoIP数据库
        let geoip_db = match std::fs::read(&app_config.client.geoip_db_path) {
            Ok(data) => {
                println!("✅ 成功加载 GeoIP 数据库");
                Some(Arc::from(data))
            }
            Err(e) => {
                println!("⚠️ 无法加载 GeoIP 数据库: {}", e);
                None
            }
        };
        
        // 使用quanx_filter构建完整规则集
        if let Some(rule_set) = RuleSet::load_quanx_filter(
            quanx_rules.iter().map(|s| s.as_str()),
            &action_map,
            geoip_db
        ) {
            println!("✅ 使用quanx_filter成功创建规则集");
            
            // 使用成功创建的规则集
            let mut rule_set = rule_set;
            
            // 确保first_resolving_rule_id设为较大值
            let resolving_rule_id = domain_rules_count as u32 + 1;
            
            // 添加调试日志，检查旧的first_resolving_rule_id，看是不是之前的bug在这里
            println!("🔧 当前first_resolving_rule_id: {:?}", rule_set.first_resolving_rule_id);
            
            // 重要：设置first_resolving_rule_id
            rule_set.first_resolving_rule_id = Some(resolving_rule_id);
            
            // 添加调试日志，确认新的first_resolving_rule_id已设置
            println!("🔧 修改后first_resolving_rule_id: {:?}", rule_set.first_resolving_rule_id);
            
            // 调试输出，显示规则优先级
            println!("📋 规则优先级设置: 域名规则 > GeoIP规则");
            println!("   - 域名规则数量: {}", domain_rules_count);
            println!("   - 域名规则ID范围: 1-{}", domain_rules_count);
            println!("   - GeoIP规则ID: {}", resolving_rule_id);
            
            // 创建分发器
            let fallback_action = Action {
                tcp_next: Arc::downgrade(&proxy_with_resolver) as Weak<dyn StreamHandler>,
                resolver: Arc::downgrade(&proxy_resolver) as Weak<dyn Resolver>,
            };

            builder.build(rule_set, fallback_action, me.clone())
        } else {
            println!("❌ 无法创建域名规则集");
            
            // 创建一个默认规则集
            let fallback_action = Action {
                tcp_next: Arc::downgrade(&proxy_with_resolver) as Weak<dyn StreamHandler>,
                resolver: Arc::downgrade(&proxy_resolver) as Weak<dyn Resolver>,
            };
            
            // 使用空规则集，所有请求都走fallback
            builder.build(RuleSet::default(), fallback_action, me.clone())
        }
    });

    // ⚠️ 重要修改：域名解析流程
    // 让规则分发器直接处理域名，而不是先解析为IP
    // 删除转发解析器，直接使用规则分发器
    let socks5_handler = Arc::new(Socks5Handler::new(
        None,
        Arc::downgrade(&rule_dispatcher) as Weak<dyn StreamHandler>,
    ));
    
    // 移除原来的解析器组合
    // let stream_forward_resolver = Arc::new(StreamForwardResolver {
    //     resolver: Arc::downgrade(&proxy_resolver),
    //     next: Arc::downgrade(&rule_dispatcher) as Weak<dyn StreamHandler>,
    // });
    
    // let socks5_handler = Arc::new(Socks5Handler::new(
    //     None,
    //     Arc::downgrade(&stream_forward_resolver) as Weak<dyn StreamHandler>,
    // ));

    let listen_addr_v4 = app_config.client.listen_addr_v4.clone();
    let listen_addr_v6 = app_config.client.listen_addr_v6.clone();

    println!(
        "Rule-based proxy server listening on {} (IPv4) and {} (IPv6)",
        listen_addr_v4, listen_addr_v6
    );

    let handle_v4 = listen_tcp(
        Arc::downgrade(&socks5_handler) as Weak<dyn StreamHandler>,
        listen_addr_v4,
    )?;

    let handle_v6 = listen_tcp(
        Arc::downgrade(&socks5_handler) as Weak<dyn StreamHandler>,
        listen_addr_v6,
    )?;

    tokio::try_join!(handle_v4, handle_v6)?;
    Ok(())
}
