use log::{error, info};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;
use toml::from_str;
use std::future::Future;
use std::pin::Pin;
use crate::flow::{DestinationAddr, HostName};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppConfig {
    pub servers: ServersConfig,
    pub dns: DnsConfig,
    pub features: FeaturesConfig,
    #[serde(default)]
    pub domains: DomainsConfig,
    #[serde(default)]
    pub client: ClientConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServersConfig {
    pub addresses: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnsConfig {
    pub china_doh: String,
    pub global_doh: String,
    pub doh: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeaturesConfig {
    pub ss_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct DomainsConfig {
    #[serde(default)]
    pub direct: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientConfig {
    pub listen_addr_v4: String,
    pub listen_addr_v6: String,
    pub udp_listen_addr_v4: String,
    pub udp_listen_addr_v6: String,
    pub geoip_db_path: String,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            listen_addr_v4: "127.0.0.1:1081".to_string(),
            listen_addr_v6: "[::]:1081".to_string(),
            udp_listen_addr_v4: "127.0.0.1:1083".to_string(),
            udp_listen_addr_v6: "[::]:1083".to_string(),
            geoip_db_path: "GeoLite2-Country.mmdb".to_string(),
        }
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            servers: ServersConfig {
                addresses: Vec::new(),
            },
            dns: DnsConfig {
                china_doh: "https://1.12.12.12/dns-query".to_string(),
                global_doh: "https://8.8.8.8/dns-query".to_string(),
                doh: "https://8.8.8.8/dns-query".to_string(),
            },
            features: FeaturesConfig {
                ss_key: "JtivfX27TuAkUkfgFXGuEQ==".to_string(),
            },
            domains: DomainsConfig::default(),
            client: ClientConfig::default(),
        }
    }
}

impl AppConfig {
    pub fn load_from_file(file_path: &str) -> std::io::Result<Self> {
        let content = fs::read_to_string(file_path)?;
        from_str(&content).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to parse TOML config: {}", e),
            )
        })
    }
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    addresses: Arc<RwLock<Vec<String>>>,
    current_index: Arc<RwLock<usize>>, // 添加当前使用的地址索引
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            addresses: Arc::new(RwLock::new(Vec::new())),
            current_index: Arc::new(RwLock::new(0)),
        }
    }
}

impl ServerConfig {
    pub fn new(initial_address: String) -> Self {
        Self {
            addresses: Arc::new(RwLock::new(vec![initial_address])),
            current_index: Arc::new(RwLock::new(0)),
        }
    }

    // 从 AppConfig 创建 ServerConfig
    pub fn from_app_config(config: &AppConfig) -> Self {
        Self {
            addresses: Arc::new(RwLock::new(config.servers.addresses.clone())),
            current_index: Arc::new(RwLock::new(0)),
        }
    }

    // 从文件加载服务器地址
    pub async fn load_from_file(file_path: &str) -> std::io::Result<Self> {
        let content = fs::read_to_string(file_path)?;
        let addresses: Vec<String> = content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .filter(|line| !line.starts_with('#'))
            .map(|line| line.trim().to_string())
            .collect();

        if addresses.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "No valid server addresses found in file",
            ));
        }

        info!("Loaded {} server addresses", addresses.len());
        Ok(Self {
            addresses: Arc::new(RwLock::new(addresses)),
            current_index: Arc::new(RwLock::new(0)),
        })
    }

    pub async fn get_address(&self) -> String {
        let addresses = self.addresses.read().await;
        let index = self.current_index.read().await;
        addresses.get(*index).cloned().unwrap_or_default()
    }

    // 获取所有地址
    pub async fn get_all_addresses(&self) -> Vec<String> {
        self.addresses.read().await.clone()
    }

    // 切换到下一个地址
    pub async fn switch_to_next_address(&self) -> String {
        let addresses = self.addresses.read().await;
        let mut index = self.current_index.write().await;
        *index = (*index + 1) % addresses.len();
        addresses[*index].clone()
    }

    pub async fn update_address(&self, new_addr: String) -> std::io::Result<()> {
        if let Ok(_) = IpAddr::from_str(&new_addr) {
            let mut addresses = self.addresses.write().await;
            if !addresses.contains(&new_addr) {
                addresses.push(new_addr.clone());
                info!("Added new server address: {}", new_addr);
            }
            Ok(())
        } else {
            error!("Invalid IP address format: {}", new_addr);
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid IP address format",
            ))
        }
    }
    pub fn create_fixed_adrr(&self) -> impl Fn() -> Pin<Box<dyn Future<Output = DestinationAddr> + Send>> + Clone {
        let server_config_clone = self.clone();
        move || {
            let config = server_config_clone.clone();
            Box::pin(async move {
                let addr = config.get_address().await;
    
                // 使用倒数第一个冒号分离IP和端口
                let parts: Vec<&str> = addr.rsplitn(2, ':').collect();
                if parts.len() != 2 {
                    panic!("无效的代理地址格式: {}", addr);
                }
    
                let ip = parts[1]; // 倒数第一个部分是IP
                let port = parts[0]
                    .parse()
                    .unwrap_or_else(|_| panic!("无效的端口号: {}", parts[0]));
    
                println!("代理地址: {}:{}", ip, port);
                DestinationAddr {
                    host: HostName::Ip(
                        IpAddr::from_str(ip).unwrap_or_else(|_| panic!("无法解析IP地址: {}", ip)),
                    ),
                    port,
                }
            })
        }
    }

}

// API 相关结构体
#[derive(Serialize, Deserialize)]
pub struct ConfigUpdate {
    pub server_address: String,
}

#[derive(Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub message: String,
    pub data: Option<T>,
}

#[derive(Serialize, Deserialize)]
pub struct ServerStatus {
    pub server_address: String,
    pub connections: u32,
    pub uplink_bytes: u64,
    pub downlink_bytes: u64,
}
