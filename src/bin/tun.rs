use std::net::Ipv4Addr;
use std::str::FromStr;
use std::path::PathBuf;
use proxy::{start_tun1_server, ServerConfig};
use proxy::config::AppConfig;
use log::{error, info};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 初始化日志
    env_logger::init();
    
    // 获取项目根目录
    let project_root = std::env::current_dir()?;
    let config_path = project_root.join("config.toml");
    let server_txt_path = project_root.join("server.txt");
    
    // 解析命令行参数
    let args: Vec<String> = std::env::args().collect();
    let mut tun_name = "utun7".to_string();  // 默认TUN设备名称
    // 使用硬编码的IP地址，与mactun.rs保持一致
    let tun_ip = Ipv4Addr::from_str("192.168.3.1").unwrap();
    let tun_netmask = Ipv4Addr::from_str("255.255.255.0").unwrap();
    let mut mtu = Some(1500);
    

    
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
    
    println!("启动TUN服务器...");
    println!("TUN设备名称: {}", tun_name);
    println!("TUN设备IP地址: {}", tun_ip);
    println!("TUN网络掩码: {}", tun_netmask);
    println!("MTU: {:?}", mtu);
    println!("路由规则: 只代理8.8.8.8的流量");
    
    // 启动TUN服务器
    start_tun1_server(&tun_name, tun_ip, tun_netmask, mtu, config, app_config).await?;
    
    Ok(())
} 