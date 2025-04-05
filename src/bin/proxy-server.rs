use proxy::{start_proxy_server, ServerConfig, StatHandle};
use proxy::config::AppConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 尝试加载 TOML 配置文件
    let app_config = match AppConfig::load_from_file("config.toml") {
        Ok(config) => {
            println!("成功加载配置文件 config.toml");
            config
        }
        Err(e) => {
            println!("未找到 config.toml 或解析失败，使用默认配置: {}", e);
            // 从旧的 server.txt 中加载服务器地址
            let server_config = match ServerConfig::load_from_file("server.txt").await {
                Ok(config) => config,
                Err(e) => {
                    eprintln!("无法读取服务器配置: {}", e);
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
    
    // 打印所有服务器地址
    let addresses = config.get_all_addresses().await;
    println!("=== 可用服务器地址 ===");
    for (index, addr) in addresses.iter().enumerate() {
        println!("服务器 {}: {}", index + 1, addr);
    }
    println!("===============================");
    
    // 获取服务器地址列表
    let server_addrs = config.get_all_addresses().await;

    println!("启动代理服务器...");

    // A调用库中的start_proxy_server函数，使用新的函数签名
    start_proxy_server(server_addrs, config, app_config).await?;

    Ok(())
}
