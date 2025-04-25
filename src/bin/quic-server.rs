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
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );
    
    info!("开始启动 QUIC 代理服务器");
    
    // 使用默认配置
    let default_config = proxy::config::AppConfig::default();
    
    // 调用启动函数，使用硬编码配置
    start_quic_server(default_config).await?;
    
    Ok(())
}