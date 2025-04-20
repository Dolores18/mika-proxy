use std::net::Ipv4Addr;
use std::str::FromStr;
use proxy::{start_tun1_server, ServerConfig};
use proxy::config::AppConfig;
use log::{error, info};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 初始化日志
    env_logger::init();
    
    // 获取项目根目录
    let project_root = std::env::current_dir()?;
    let config_path = project_root.join("config.toml");
    let server_txt_path = project_root.join("server.txt");
    
    // 尝试加载 TOML 配置文件
    let app_config = match AppConfig::load_from_file(config_path.to_str().unwrap()) {
        Ok(config) => {
            println!("成功加载配置文件 {:?}", config_path);
            config
        }
        Err(e) => {
            error!("未找到 {:?} 或解析失败，使用默认配置: {}", config_path, e);
            // 从旧的 server.txt 中加载服务器地址
            let server_config = match ServerConfig::load_from_file(server_txt_path.to_str().unwrap()).await {
                Ok(config) => config,
                Err(e) => {
                    error!("无法读取服务器配置 {:?}: {}", server_txt_path, e);
                    return Err(e.into());
                }
            };
            
            // 创建默认配置，但使用从 server.txt 加载的地址
            let mut default_config = AppConfig::default();
            default_config.servers.addresses = server_config.get_all_addresses().await;
            default_config
        }
    };
    
    // 创建 ServerConfig
    let config = ServerConfig::from_app_config(&app_config);
    
    // 打印所有代理服务器地址
    let addresses = config.get_all_addresses().await;
    println!("=== 可用代理服务器地址 ===");
    for (index, addr) in addresses.iter().enumerate() {
        println!("服务器 {}: {}", index + 1, addr);
    }
    println!("===============================");
    
    // 从配置中读取TUN设置
    let tun_name = app_config.tun.name.clone();
    let tun_ip = Ipv4Addr::from_str(&app_config.tun.address).unwrap_or_else(|_| {
        println!("⚠️ 无效的TUN IP地址格式: {}, 使用默认值", app_config.tun.address);
        Ipv4Addr::from_str("172.16.0.1").unwrap()
    });
    let tun_netmask = Ipv4Addr::from_str(&app_config.tun.netmask).unwrap_or_else(|_| {
        println!("⚠️ 无效的网络掩码格式: {}, 使用默认值", app_config.tun.netmask);
        Ipv4Addr::from_str("255.255.255.0").unwrap()
    });
    let mtu = Some(app_config.tun.mtu);
    
    println!("启动TUN服务器...");
    println!("TUN设备名称: {}", tun_name);
    println!("TUN设备IP地址: {}", tun_ip);
    println!("TUN网络掩码: {}", tun_netmask);
    println!("MTU: {:?}", mtu);
    println!("DNS拦截: {}", if app_config.tun.dns_hijack { "已启用" } else { "已禁用" });
    println!("FakeIP: 已启用 (198.18.0.0/16域名映射)");
    
    if !app_config.tun.routes.is_empty() {
        println!("配置的路由:");
        for route in &app_config.tun.routes {
            println!("  - {}", route);
        }
    }
    
    // 启动TUN服务器，使用引用而不是所有权
    // 注意：由于#[tokio::main]宏已经创建了运行时，我们无需再传递runtime参数
    start_tun1_server(&tun_name, tun_ip, tun_netmask, mtu, config, app_config, &tokio::runtime::Handle::current()).await?;
    
    Ok(())
} 