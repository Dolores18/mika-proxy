#![feature(generic_const_exprs)]
#![feature(stmt_expr_attributes)]
#![feature(array_chunks)]
#![feature(result_flattening)]
#![feature(let_chains)]
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
use shadowsocks::factory::datagram::*;
mod socks5;
use socks5::*;
mod system_resolver;
use log::{error, info, trace};
use std::panic;
use system_resolver::*;
mod redirect;
use redirect::{StreamRedirectHandler, StreamRedirectOutboundFactory, DatagramSessionRedirectFactory};

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

// 添加 socks5_associate 模块
mod socks5_associate;
use socks5_associate::Socks5UdpAssociateHandler;

// 添加 dns_server 模块
mod dns_server;
use dns_server::{DnsServer, MapBackStreamHandler, MapBackDatagramSessionHandler, cache_writer};

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
mod data;
use data::PluginCache;
mod fakeip;
use fakeip::*;
mod ip_stack;
use ip_stack::*;
mod tun;
use tun::*;

// 添加dual_stack_factory模块
mod dual_stack_factory;
use dual_stack_factory::DualStackOutboundFactory;

// 添加fakeip_mapback模块
mod fakeip_mapback;
pub use fakeip_mapback::{FakeIpMapBackStreamHandler, FakeIpMapBackDatagramSessionHandler};
mod tuic;
mod tls;
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

// 修改 load_direct_domains 函数，支持从 AppConfig 读取域名
fn load_direct_domains(app_config: &config::AppConfig) -> HashSet<String> {
    // 首先尝试从 AppConfig 中读取域名
    if !app_config.domains.direct.is_empty() {
        println!("从配置文件加载直连域名列表");
        let domains: HashSet<String> = app_config.domains.direct
            .iter()
            .map(|s| s.to_lowercase())
            .collect();
        
        println!("成功加载直连域名列表，共 {} 个域名", domains.len());
        println!("直连域名列表: {:?}", domains);
        return domains;
    }
    
    // 如果配置文件中没有域名列表，则尝试从文件加载
    let current_dir = std::env::current_dir().unwrap_or_default();
    info!("当前执行目录: {:?}", current_dir);

    match std::fs::read_to_string("direct_domains.txt") {
        Ok(content) => {
            println!("成功读取文件内容");
            let domains: HashSet<String> = content
                .lines()
                .filter(|line| !line.trim().is_empty())
                .filter(|line| !line.starts_with('#'))
                .map(str::trim)
                .map(|s| s.to_lowercase()) // 统一转换为小写
                .collect();

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
            HashSet::new()
        }
    }
}

// 修改 init_rule_dispatcher 函数
/*
pub fn init_rule_dispatcher() -> Arc<RuleDispatcher> {
    // 创建一个基本的规则集
    let mut rule_set = RuleSet::default();

    // 尝试加载 GeoIP 数据库
    let geoip_db = match std::fs::read("GeoLite2-Country.mmdb") {
        Ok(data) => {
            info!("成功加载 GeoIP 数据库");
            let geoip_rules = vec![("CN".to_string(), RuleHandle::new(ActionHandle(0), 0))];

            rule_set.dst_geoip = Some(GeoIpSet {
                iso_code_rule: geoip_rules.into(),
                geoip_reader: maxminddb::Reader::from_source(Arc::from(data)).unwrap(),
            });

            info!("成功设置 GeoIP 规则");
            Some(())
        }
        Err(e) => {
            error!("无法加载 GeoIP 数据库: {}", e);
            None
        }
    };

    // 创建 direct action
    let direct_action = Action {
        tcp_next: Weak::<dyn StreamHandler>::new(),
        udp_next: Weak::<dyn DatagramSessionHandler>::new(),
        resolver: Weak::<dyn Resolver>::new(),
    };

    // 创建 proxy action (作为 fallback)
    let proxy_action = Action {
        tcp_next: Weak::<dyn StreamHandler>::new(),
        udp_next: Weak::<dyn DatagramSessionHandler>::new(),
        resolver: Weak::<dyn Resolver>::new(),
    };

    // 创建并返回 RuleDispatcher
    Arc::new_cyclic(|me| {
        let mut dispatcher = RuleDispatcher::new(
            rule_set,
            proxy_action, // 默认使用代理
            me.clone(),
        );

        // 添加 direct action 到 actions 列表
        dispatcher.actions.push(direct_action);

        dispatcher
    })
}
 */
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
        app_config.dns.doh.parse().unwrap(), // 使用配置中的国际 DoH 服务器
        Arc::downgrade(&doh_tcp_factory) as Weak<dyn StreamOutboundFactory>,
    )];
    println!("Created DoH client for URL: {}", app_config.dns.doh);

    // 创建代理解析器
    let proxy_resolver: Arc<dyn Resolver> = Arc::new(HostResolver::new(vec![], doh_factories));

    // 创建统计对象
    let stat = forward::StatHandle::default();

    // 创建DNS服务器用于缓存
    // 创建数据库连接
    let dns_db_path = std::path::Path::new("./proxy_cache.db");
    let dns_db = match data::Database::open(dns_db_path) {
        Ok(db) => {
            info!("✅ 成功打开/创建DNS缓存数据库: {:?}", dns_db_path);
            Some(db)
        },
        Err(e) => {
            error!("❌ 无法打开/创建DNS缓存数据库: {:?} - 错误: {:?}", dns_db_path, e);
            None
        }
    };
    
    // 使用新创建的数据库连接
    let dns_plugin_cache = data::PluginCache::new(data::PluginId(1), dns_db);
    let dns_server = Arc::new(DnsServer::new(
        100, // 并发限制
        Arc::downgrade(&proxy_resolver) as Weak<dyn Resolver>,
        3600, // TTL秒数 (1小时)
        dns_plugin_cache,
    ));
    
    // 启动缓存定期写入任务
    tokio::spawn(cache_writer(dns_server.clone()));
    println!("✅ DNS服务器缓存系统已启动，解析结果将持久化保存到数据库");
    
    // 创建缓存解析器，先查询缓存，未命中再使用DoH
    let caching_resolver: Arc<dyn Resolver> = Arc::new(host_resolver::CachingResolver::new(
        dns_server.clone(),
        proxy_resolver.clone()
    ));
    println!("✅ DNS缓存解析器已创建");

    // 3. 创建直连出站工厂
    let direct_outbound_factory = Arc::new(SocketOutboundFactory {
        resolver: Arc::downgrade(&caching_resolver),
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


    // 6. 创建规则分发器
    let rule_dispatcher = Arc::new_cyclic(|me| {
        let mut builder = RuleDispatcherBuilder::default();
        builder.set_resolver(Some(Arc::downgrade(&caching_resolver) as Weak<dyn Resolver>));

        // 创建直连动作
        let direct_action = Action {
            tcp_next: Arc::downgrade(&direct_forward_handler) as Weak<dyn StreamHandler>,
            resolver: Arc::downgrade(&caching_resolver) as Weak<dyn Resolver>,
        };
        println!("✅ 创建直连动作成功");

        let direct_handle = builder
            .add_action(direct_action)
            .expect("Failed to add direct action");

        // 创建代理动作
        let proxy_action = Action {
            tcp_next: Arc::downgrade(&proxy_forward_handler) as Weak<dyn StreamHandler>,
            resolver: Arc::downgrade(&caching_resolver) as Weak<dyn Resolver>,
        };
        println!("✅ 创建代理动作成功");

        let proxy_handle = builder
            .add_action(proxy_action)
            .expect("Failed to add proxy action");

        // 创建 Google 相关域名规则集
        let google_domains = vec![
            // 子域名匹配（以 . 开头）
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

        // 使用 build_surge_domainset 构建域名规则
        if let Some(domain_rule_set) =
            RuleSet::build_surge_domainset(google_domains.iter().map(|s| *s), proxy_handle)
        {
            println!("✅ 成功创建 Google 域名规则集");

            // 直接使用构建好的规则集
            let mut rule_set = domain_rule_set;

            // 添加 GeoIP 规则
            if let Some(geoip_db) = match std::fs::read(&app_config.client.geoip_db_path) {
                Ok(data) => {
                    println!("✅ 成功加载 GeoIP 数据库");
                    let code_action_mapping = vec![
                        ("CN".to_string(), direct_handle),
                        ("US".to_string(), proxy_handle),
                    ]
                    .into_iter();

                    RuleSet::build_dst_geoip_rule(code_action_mapping, Arc::from(data))
                }
                Err(e) => {
                    println!("❌ 无法加载 GeoIP 数据库: {}", e);
                    None
                }
            } {
                rule_set.dst_geoip = geoip_db.dst_geoip;
                rule_set.first_resolving_rule_id = Some(0);
            }

            // 创建分发器
            let fallback_action = Action {
                tcp_next: Arc::downgrade(&proxy_forward_handler) as Weak<dyn StreamHandler>,
                resolver: Arc::downgrade(&caching_resolver) as Weak<dyn Resolver>,
            };

            builder.build(rule_set, fallback_action, me.clone())
        } else {
            panic!("Failed to create domain rule set");
        }
    });

    // 添加MapBackStreamHandler将IP地址映射回域名
    let mapback_handler = Arc::new(MapBackStreamHandler::new(
        &dns_server,
        Arc::downgrade(&rule_dispatcher) as Weak<dyn StreamHandler>
    ));

    //创建doh响应结果映射回去
    let stream_forward_resolver = Arc::new(StreamForwardResolver {
        resolver: Arc::downgrade(&caching_resolver),
        next: Arc::downgrade(&mapback_handler) as Weak<dyn StreamHandler>,
    });
    
    // 7. 创建 SOCKS5 处理器并启动服务器
    let socks5_handler = Arc::new(Socks5Handler::new(
        None,
        Arc::downgrade(&stream_forward_resolver) as Weak<dyn StreamHandler>,
    ));
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

    // 统计对象
    let stat = forward::StatHandle::default();
    
    // 获取代理地址
    let server_config_clone = Arc::new(server_config.clone());
    let proxy_addr = server_config_clone.create_fixed_adrr();
    
    // 获取Shadowsocks密钥
    let psd = &app_config.features.ss_key;
    let key = BASE64.decode(psd).expect("Failed to decode");
    let key: [u8; 16] = key.try_into().expect("Invalid key length");

    // 创建 UDP 出站工厂
    let socket_outbound_factory = Arc::new(SocketOutboundFactory {
        resolver: Arc::downgrade(&resolver),
        bind_addr_v4: Some(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        bind_addr_v6: Some(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
    });

    // 创建UDP重定向工厂
    let udp_redirect_factory = Arc::new(DatagramSessionRedirectFactory {
        remote_peer: proxy_addr.clone(),
        next: Arc::downgrade(&socket_outbound_factory) as Weak<dyn DatagramSessionFactory>,
    });

    // 创建UDP SS工厂
    let ss_udp_factory = Arc::new(ShadowsocksDatagramSessionFactory::<Aes128Gcm>::new(
        key,
        Arc::downgrade(&udp_redirect_factory) as Weak<dyn DatagramSessionFactory>,
    ));


    // 创建 UDP 转发处理器
    let datagram_handler = Arc::new(forward::DatagramForwardHandler {
        outbound: Arc::downgrade(&ss_udp_factory) as Weak<dyn DatagramSessionFactory>,
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
    let udp_handle_v4 = listen_udp(
        Arc::downgrade(&socks5_udp_handler) as Weak<dyn DatagramSessionHandler>,
        udp_listen_addr_v4.clone(),
    )?;
    
    let udp_handle_v6 = listen_udp(
        Arc::downgrade(&socks5_udp_handler) as Weak<dyn DatagramSessionHandler>,
        udp_listen_addr_v6.clone(),
    )?;

    // 创建UDP关联处理器，处理SOCKS5 UDP ASSOCIATE命令
    let socks5_associate_handler = Arc::new(Socks5UdpAssociateHandler::new(
        None,
        Arc::downgrade(&socks5_udp_handler) as Weak<dyn DatagramSessionHandler>,
        udp_listen_addr_v4.parse().unwrap(), // 使用UDP监听地址作为中继地址
    ));

    // 创建TCP监听器，处理SOCKS5 UDP ASSOCIATE命令
    println!("Starting SOCKS5 UDP ASSOCIATE handler on TCP port...");
    let tcp_handle_v4 = listen_tcp(
        Arc::downgrade(&socks5_associate_handler) as Weak<dyn StreamHandler>,
        udp_listen_addr_v4.clone(),
    )?;
    
    let tcp_handle_v6 = listen_tcp(
        Arc::downgrade(&socks5_associate_handler) as Weak<dyn StreamHandler>,
        udp_listen_addr_v6.clone(),
    )?;

    // 等待所有监听器完成
    tokio::try_join!(udp_handle_v4, udp_handle_v6, tcp_handle_v4, tcp_handle_v6)?;

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
        Arc::downgrade(&doh_tcp_factory) as Weak<dyn StreamOutboundFactory>,
    )];
    println!("Created DoH client for URL: {}", app_config.dns.doh);

    // 创建代理解析器
    let proxy_resolver: Arc<dyn Resolver> = Arc::new(HostResolver::new(vec![], doh_factories));

    // 创建DNS服务器用于缓存
    // 创建数据库连接
    let dns_db_path = std::path::Path::new("./proxy_cache.db");
    let dns_db = match data::Database::open(dns_db_path) {
        Ok(db) => {
            info!("✅ 成功打开/创建DNS缓存数据库: {:?}", dns_db_path);
            Some(db)
        },
        Err(e) => {
            error!("❌ 无法打开/创建DNS缓存数据库: {:?} - 错误: {:?}", dns_db_path, e);
            None
        }
    };
    
    // 使用新创建的数据库连接
    let dns_plugin_cache = data::PluginCache::new(data::PluginId(1), dns_db);
    let dns_server = Arc::new(DnsServer::new(
        100, // 并发限制
        Arc::downgrade(&proxy_resolver) as Weak<dyn Resolver>,
        3600, // TTL秒数 (1小时)
        dns_plugin_cache,
    ));
    
    // 启动缓存定期写入任务
    tokio::spawn(cache_writer(dns_server.clone()));
    println!("✅ DNS服务器缓存系统已启动，解析结果将持久化保存到数据库");
    
    // 创建缓存解析器，先查询缓存，未命中再使用DoH
    let caching_resolver: Arc<dyn Resolver> = Arc::new(host_resolver::CachingResolver::new(
        dns_server.clone(),
        proxy_resolver.clone()
    ));
    println!("✅ DNS缓存解析器已创建");

    // 3. 创建直连出站工厂
    let direct_outbound_factory = Arc::new(SocketOutboundFactory {
        resolver: Arc::downgrade(&caching_resolver),
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


    // 6. 创建规则分发器
    let rule_dispatcher = Arc::new_cyclic(|me| {
        let mut builder = RuleDispatcherBuilder::default();
        builder.set_resolver(Some(Arc::downgrade(&caching_resolver) as Weak<dyn Resolver>));

        // 创建直连动作
        let direct_action = Action {
            tcp_next: Arc::downgrade(&direct_forward_handler) as Weak<dyn StreamHandler>,
            resolver: Arc::downgrade(&caching_resolver) as Weak<dyn Resolver>,
        };
        println!("✅ 创建直连动作成功");

        let direct_handle = builder
            .add_action(direct_action)
            .expect("Failed to add direct action");

        // 创建代理动作
        let proxy_action = Action {
            tcp_next: Arc::downgrade(&proxy_forward_handler) as Weak<dyn StreamHandler>,
            resolver: Arc::downgrade(&caching_resolver) as Weak<dyn Resolver>,
        };
        println!("✅ 创建代理动作成功");

        let proxy_handle = builder
            .add_action(proxy_action)
            .expect("Failed to add proxy action");

        // 创建 Google 相关域名规则集
        let google_domains = vec![
            // 子域名匹配（以 . 开头）
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

        // 使用 build_surge_domainset 构建域名规则
        if let Some(domain_rule_set) =
            RuleSet::build_surge_domainset(google_domains.iter().map(|s| *s), proxy_handle)
        {
            println!("✅ 成功创建 Google 域名规则集");

            // 直接使用构建好的规则集
            let mut rule_set = domain_rule_set;

            // 添加 GeoIP 规则
            if let Some(geoip_db) = match std::fs::read(&app_config.client.geoip_db_path) {
                Ok(data) => {
                    println!("✅ 成功加载 GeoIP 数据库");
                    let code_action_mapping = vec![
                        ("CN".to_string(), direct_handle),
                        ("US".to_string(), proxy_handle),
                    ]
                    .into_iter();

                    RuleSet::build_dst_geoip_rule(code_action_mapping, Arc::from(data))
                }
                Err(e) => {
                    println!("❌ 无法加载 GeoIP 数据库: {}", e);
                    None
                }
            } {
                rule_set.dst_geoip = geoip_db.dst_geoip;
                rule_set.first_resolving_rule_id = Some(0);
            }

            // 创建分发器
            let fallback_action = Action {
                tcp_next: Arc::downgrade(&proxy_forward_handler) as Weak<dyn StreamHandler>,
                resolver: Arc::downgrade(&caching_resolver) as Weak<dyn Resolver>,
            };

            builder.build(rule_set, fallback_action, me.clone())
        } else {
            panic!("Failed to create domain rule set");
        }
    });

    // 添加MapBackStreamHandler将IP地址映射回域名
    let mapback_handler = Arc::new(MapBackStreamHandler::new(
        &dns_server,
        Arc::downgrade(&rule_dispatcher) as Weak<dyn StreamHandler>
    ));

    //创建doh响应结果映射回去
    let stream_forward_resolver = Arc::new(StreamForwardResolver {
        resolver: Arc::downgrade(&caching_resolver),
        next: Arc::downgrade(&mapback_handler) as Weak<dyn StreamHandler>,
    });
    
    // 7. 创建 SOCKS5 处理器并启动服务器
    let socks5_handler = Arc::new(Socks5Handler::new(
        None,
        Arc::downgrade(&stream_forward_resolver) as Weak<dyn StreamHandler>,
    ));
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

/// 启动TUN服务器，创建虚拟网络接口并初始化IP栈
pub async fn start_tun1_server(
    tun_name: &str,
    tun_ip: Ipv4Addr,
    tun_netmask: Ipv4Addr,
    mtu: Option<u16>,
    server_config: ServerConfig,
    app_config: config::AppConfig,
    // 使用Handle而不是Runtime
    _runtime_handle: &tokio::runtime::Handle,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("开始初始化 TUN 服务器");
    
    // 创建系统解析器
    let system_resolver: Arc<dyn Resolver> = Arc::new(SystemResolver::new());
    
    // 统计对象
    let stat = forward::StatHandle::default();
    
    // 修改代理地址创建方式
    let server_config_clone = Arc::new(server_config.clone());
    let proxy_addr = server_config_clone.create_fixed_adrr();
    
    // 尝试获取IPv6代理地址，使用await而不是block_on
    let ipv6_factory_creator = server_config_clone.create_fixed_ipv6_adrr();
    let ipv6_dest_addr = ipv6_factory_creator().await;
    
    println!("代理地址信息:");
    println!("- IPv4代理: 已配置");
    if let Some(addr) = &ipv6_dest_addr {
        println!("- IPv6代理: 已配置，地址: {:?}", addr);
    } else {
        println!("- IPv6代理: 未配置或不可用");
    }

    // 创建 Shadowsocks 工厂，使用配置中的密钥
    let psd = &app_config.features.ss_key;
    let key = BASE64.decode(psd).expect("Failed to decode");
    let key: [u8; 16] = key.try_into().expect("Invalid key length");   
    
    // 创建socket出站工厂
    let socket_outbound_factory = Arc::new(SocketOutboundFactory {
        resolver: Arc::downgrade(&system_resolver),
        bind_addr_v4: Some(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        bind_addr_v6: Some(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
    });

    // 创建IPv4重定向工厂
    let ipv4_redirect_factory = Arc::new(StreamRedirectOutboundFactory {
        remote_peer: proxy_addr.clone(),
        next: Arc::downgrade(&socket_outbound_factory) as Weak<dyn StreamOutboundFactory>,
    });
    
    // 创建IPv4 SS工厂
    let ss_ipv4_factory = Arc::new(ShadowsocksStreamOutboundFactory::<Aes128Gcm>::new(
        key.clone(),
        Arc::downgrade(&ipv4_redirect_factory) as Weak<dyn StreamOutboundFactory>,
    ));
    
    // 创建IPv6 SS工厂（如果有可用的IPv6地址）
    let ss_ipv6_factory = if let Some(ipv6_addr) = ipv6_dest_addr {
        // 创建一个内部函数，每次返回相同的地址
        let ipv6_addr_clone = ipv6_addr.clone();
        let ipv6_fn = move || {
            let addr = ipv6_addr_clone.clone();
            Box::pin(async move { addr })
        };
        
        // 创建IPv6重定向工厂
        let ipv6_redirect_factory = Arc::new(StreamRedirectOutboundFactory {
            remote_peer: ipv6_fn,
            next: Arc::downgrade(&socket_outbound_factory) as Weak<dyn StreamOutboundFactory>,
        });
        
        // 创建IPv6 SS工厂
        Some(Arc::new(ShadowsocksStreamOutboundFactory::<Aes128Gcm>::new(
            key,
            Arc::downgrade(&ipv6_redirect_factory) as Weak<dyn StreamOutboundFactory>,
        )))
    } else {
        None
    };
    
    // 创建双栈地址选择器工厂
    let dual_stack_factory = Arc::new(DualStackOutboundFactory::new(
        ss_ipv4_factory,
        ss_ipv6_factory
    ));
    
    // 创建 StreamForwardHandler 实例
    let tcp_handler = Arc::new(forward::StreamForwardHandler {
        outbound: Arc::downgrade(&dual_stack_factory) as Weak<dyn StreamOutboundFactory>,
        request_timeout: 10000,
        stat: stat.clone(),
    });

    // 创建UDP socket出站工厂
    let udp_socket_outbound_factory = Arc::new(SocketOutboundFactory {
        resolver: Arc::downgrade(&system_resolver),
        bind_addr_v4: Some(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        bind_addr_v6: Some(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
    });

    // 创建UDP重定向工厂，使用与TCP相同的代理地址
    let udp_redirect_factory = Arc::new(DatagramSessionRedirectFactory {
        remote_peer: proxy_addr.clone(),
        next: Arc::downgrade(&udp_socket_outbound_factory) as Weak<dyn DatagramSessionFactory>,
    });

    // 创建UDP SS工厂，连接到重定向工厂而不是直接连接到socket工厂
    let ss_udp_factory = Arc::new(ShadowsocksDatagramSessionFactory::<Aes128Gcm>::new(
        key.clone(),
        Arc::downgrade(&udp_redirect_factory) as Weak<dyn DatagramSessionFactory>,
    ));

    // 创建 UDP 转发处理器，使用SS加密工厂
    let datagram_handler = Arc::new(forward::DatagramForwardHandler {
        outbound: Arc::downgrade(&ss_udp_factory) as Weak<dyn DatagramSessionFactory>,
        stat: stat,
    });

    let tun_handler = Arc::new(TunDatagramHandler::new(
        Arc::downgrade(&datagram_handler) as Weak<dyn DatagramSessionHandler>,
    ));

    // 创建FakeIP实例
    // 创建数据库连接
    let db_path = std::path::Path::new("./proxy_cache.db");
    
    // 尝试打开或创建数据库
    let db = match data::Database::open(db_path) {
        Ok(db) => {
            info!("✅ 成功打开/创建数据库: {:?}", db_path);
            Some(db)
        },
        Err(e) => {
            error!("❌ 无法打开/创建数据库: {:?} - 错误: {:?}", db_path, e);
            None
        }
    };
    
    // 创建FakeIP的plugin_cache，传入数据库连接
    let plugin_cache = data::PluginCache::new(data::PluginId(2), db);
    let fakeip = Arc::new(FakeIp::new(
        [198, 18], // 使用198.18.0.0/16作为FakeIP范围
        [0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],  // 使用fc00::/18作为IPv6前缀
        plugin_cache
    ));
    
    // 添加日志
    info!("✅ FakeIP服务已初始化，域名映射将持久化保存到数据库");
    
    // 启动FakeIP缓存写入任务
    let cache_task = tokio::spawn(fakeip::cache_writer(fakeip.clone()));

    // 创建TCP和UDP调用链 - 使用FakeIpMapBack处理器替代原来的DnsServer和MapBack
    
    // 为TCP创建FakeIpMapBackStreamHandler
    let tcp_with_mapback = Arc::new(FakeIpMapBackStreamHandler::new(
        fakeip.clone(),
        Arc::downgrade(&tcp_handler) as Weak<dyn StreamHandler>
    ));
    
    // 为UDP创建FakeIpMapBackDatagramSessionHandler
    let udp_with_mapback = Arc::new(FakeIpMapBackDatagramSessionHandler::new(
        fakeip.clone(), 
        Arc::downgrade(&tun_handler) as Weak<dyn DatagramSessionHandler>
    ));
    
    // 创建TUN配置
    let gateway_str = tun_ip.to_string();
    let netmask_str = tun_netmask.to_string();

    // 使用app_config中的路由配置，不再硬编码
    let routes = if app_config.tun.routes.is_empty() {
        info!("配置文件中没有指定路由，不配置路由");
        None
    } else {
        info!("使用配置文件中的路由配置: {:?}", app_config.tun.routes);
        Some(app_config.tun.routes.clone())
    };

    info!("TUN设备已创建，路由配置: {:?}", routes);
    
    // 创建TUN配置对象
    let mut tun_config = crate::tun::routes::macos::Tunconfig::new(
        tun_name.to_string(), 
        routes,
        mtu,
        Some(netmask_str),
        gateway_str
    );
    
    // 设置启用TUN，使用配置文件中的设置
    tun_config.enabled = app_config.tun.enabled;

    // 使用配置文件中的DNS劫持设置
    tun_config = tun_config.with_dns_hijack(app_config.tun.dns_hijack);
    tun_config = tun_config.with_fakeip(fakeip.clone());
    
    // 设置stream_handler和datagram_handler，使用带FakeIpMapBack的处理器
    tun_config = tun_config.with_stream_handler(Arc::downgrade(&tcp_with_mapback) as Weak<dyn StreamHandler>);
    tun_config = tun_config.with_datagram_handler(Arc::downgrade(&udp_with_mapback) as Weak<dyn DatagramSessionHandler>);
    
    info!("TUN配置已创建: {:?}", tun_config);
    
    // 获取TUN运行器
    match crate::tun::inbound::get_runner(tun_config) {
        Ok(Some(runner)) => {
            info!("TUN服务器已启动");
            println!("TUN服务器正在运行 - 按Ctrl+C退出");
            
            // 运行TUN服务并等待中断信号
            tokio::select! {
                result = runner => {
                    if let Err(e) = result {
                        error!("TUN服务器运行时错误: {}", e);
                    }
                },
                _ = tokio::signal::ctrl_c() => {
                    println!("收到中断信号，正在关闭TUN服务器...");
                }
            }
            
            // 等待缓存写入任务结束
            if !cache_task.is_finished() {
                println!("正在等待缓存写入任务完成...");
                // 尝试取消任务而不是等待它
                cache_task.abort();
            }
            
            info!("TUN服务器已关闭");
            Ok(())
        },
        Ok(None) => {
            error!("TUN服务器未启用");
            Err("TUN服务器未启用".into())
        },
        Err(e) => {
            error!("TUN服务器启动失败: {}", e);
            Err(e)
        }
    }
}
