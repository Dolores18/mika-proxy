use log::error;
use proxy::start_hy2_server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 初始化 rustls 加密提供程序
    let _ = rustls::crypto::ring::default_provider().install_default();
    
    // 初始化日志 - 设置为 error 级别
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "error"),
    );
    
    // 加载配置文件
    let app_config = match proxy::config::AppConfig::load_from_file("config.toml") {
        Ok(config) => {
            println!("✅ 成功加载配置文件 config.toml");
            config
        }
        Err(e) => {
            error!("无法加载配置文件 config.toml: {}", e);
            println!("⚠️ 使用默认配置");
            proxy::config::AppConfig::default()
        }
    };
    
    println!("🚀 Hysteria2 代理服务器启动中...");
    
    // 启动 Hysteria2 服务器
    start_hy2_server(app_config).await?;
    
    Ok(())
}
