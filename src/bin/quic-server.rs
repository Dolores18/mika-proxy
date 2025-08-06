use log::info;
use std::env;
use proxy::start_quic_server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 初始化rustls加密提供程序
    // 在rustls 0.23版本中，需要为install_default提供一个CryptoProvider实例
   let _ = rustls::crypto::ring::default_provider().install_default();
    
    // 初始化日志
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "warn"),
    );
    
    info!("开始启动 QUIC 代理服务器");
    
    // 尝试加载 TOML 配置文件
    let app_config = match proxy::config::AppConfig::load_from_file("config.toml") {
        Ok(config) => {
            println!("成功加载配置文件 config.toml");
            config
        }
        Err(e) => {
            println!("无法加载配置文件 config.toml: {}", e);
            println!("使用默认配置");
            proxy::config::AppConfig::default()
        }
    };
    
    // 调用启动函数，使用加载的配置
    start_quic_server(app_config).await?;
    
    Ok(())
}