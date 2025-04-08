use std::net::Ipv4Addr;
use std::str::FromStr;
use proxy::{start_tun1_server, ServerConfig};
use proxy::config::AppConfig;
use log::{error, info};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 初始化日志
    env_logger::init();
    
    // 解析命令行参数
    let args: Vec<String> = std::env::args().collect();
    let mut tun_name = "utun7".to_string();  // 默认TUN设备名称
    let mut tun_ip = Ipv4Addr::from_str("10.0.0.1").unwrap();
    let mut tun_netmask = Ipv4Addr::from_str("255.255.255.0").unwrap();
    let mut mtu = Some(1500);
    
    // 解析命令行参数
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--tun-name" => {
                if i + 1 < args.len() {
                    tun_name = args[i + 1].clone();
                    i += 2;
                } else {
                    error!("--tun-name 选项需要一个参数");
                    return Err("参数解析错误".into());
                }
            }
            "--tun-ip" => {
                if i + 1 < args.len() {
                    match Ipv4Addr::from_str(&args[i + 1]) {
                        Ok(ip) => {
                            tun_ip = ip;
                            i += 2;
                        }
                        Err(e) => {
                            error!("无效的IP地址格式: {}", e);
                            return Err("参数解析错误".into());
                        }
                    }
                } else {
                    error!("--tun-ip 选项需要一个参数");
                    return Err("参数解析错误".into());
                }
            }
            "--tun-netmask" => {
                if i + 1 < args.len() {
                    match Ipv4Addr::from_str(&args[i + 1]) {
                        Ok(mask) => {
                            tun_netmask = mask;
                            i += 2;
                        }
                        Err(e) => {
                            error!("无效的网络掩码格式: {}", e);
                            return Err("参数解析错误".into());
                        }
                    }
                } else {
                    error!("--tun-netmask 选项需要一个参数");
                    return Err("参数解析错误".into());
                }
            }
            "--mtu" => {
                if i + 1 < args.len() {
                    match args[i + 1].parse::<usize>() {
                        Ok(m) => {
                            mtu = Some(m);
                            i += 2;
                        }
                        Err(e) => {
                            error!("无效的MTU值: {}", e);
                            return Err("参数解析错误".into());
                        }
                    }
                } else {
                    error!("--mtu 选项需要一个参数");
                    return Err("参数解析错误".into());
                }
            }
            "--help" => {
                println!("TUN服务器命令行选项:");
                println!("  --tun-name NAME      指定TUN设备名称 (默认: utun7)");
                println!("  --tun-ip IP          指定TUN设备IP地址 (默认: 10.0.0.1)");
                println!("  --tun-netmask MASK   指定TUN设备网络掩码 (默认: 255.255.255.0)");
                println!("  --mtu VALUE          指定MTU值 (默认: 1500)");
                println!("  --help               显示此帮助信息");
                println!("");
                println!("注意: 当前的路由规则配置为只代理8.8.8.8的流量");
                return Ok(());
            }
            _ => {
                i += 1;
            }
        }
    }
    
    // 尝试加载 TOML 配置文件
    let app_config = match AppConfig::load_from_file("config.toml") {
        Ok(config) => {
            println!("成功加载配置文件 config.toml");
            config
        }
        Err(e) => {
            error!("未找到 config.toml 或解析失败，使用默认配置: {}", e);
            // 从旧的 server.txt 中加载服务器地址
            let server_config = match ServerConfig::load_from_file("server.txt").await {
                Ok(config) => config,
                Err(e) => {
                    error!("无法读取服务器配置: {}", e);
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