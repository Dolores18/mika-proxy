use crate::config::{ApiResponse, ConfigUpdate, ServerConfig, ServerStatus};
use crate::forward::StatHandle;
use log::info;
use std::convert::Infallible;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use warp::{Filter, Reply};

pub async fn start_api_server(
    config: ServerConfig,
    port: u16,
    stat: StatHandle,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = Arc::new(config);
    let stat = Arc::new(stat);

    // GET /api/status - 获取当前状态
    let status = {
        let config = config.clone();
        let stat = stat.clone();
        warp::path!("api" / "status")
            .and(warp::get())
            .and_then(move || {
                let config = config.clone();
                let stat = stat.clone();
                async move {
                    let addr = config.get_address().await;
                    let response = ApiResponse {
                        success: true,
                        message: "OK".to_string(),
                        data: Some(ServerStatus {
                            server_address: addr,
                            connections: stat.inner.tcp_connection_count.load(Ordering::Relaxed),
                            uplink_bytes: stat.inner.uplink_written.load(Ordering::Relaxed),
                            downlink_bytes: stat.inner.downlink_written.load(Ordering::Relaxed),
                        }),
                    };
                    Ok::<_, Infallible>(warp::reply::json(&response))
                }
            })
    };

    // POST /api/config - 更新配置
    let update_config = {
        let config = config.clone();
        warp::path!("api" / "config")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(move |update: ConfigUpdate| {
                let config = config.clone();
                async move {
                    match config.update_address(update.server_address).await {
                        Ok(()) => {
                            let response: ApiResponse<()> = ApiResponse {
                                success: true,
                                message: "配置已更新".to_string(),
                                data: None,
                            };
                            Ok::<_, Infallible>(warp::reply::json(&response))
                        }
                        Err(e) => {
                            let response: ApiResponse<()> = ApiResponse {
                                success: false,
                                message: e.to_string(),
                                data: None,
                            };
                            Ok(warp::reply::json(&response))
                        }
                    }
                }
            })
    };

    let routes = status.or(update_config);

    info!("API server starting on port {}", port);
    warp::serve(routes).run(([127, 0, 0, 1], port)).await;

    Ok(())
}
