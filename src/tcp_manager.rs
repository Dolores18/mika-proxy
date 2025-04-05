use log::{info, warn};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf, ReuniteError};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

const SOURCE_PORT_START: u16 = 30000;
const SOURCE_PORT_END: u16 = 30009;

struct PooledConnection {
    read_half: OwnedReadHalf,
    write_half: OwnedWriteHalf,
    last_used: Instant,
    source_port: u16,
}

#[derive(Debug, Hash, Eq, PartialEq, Clone)]
struct ConnectionKey {
    target_addr: SocketAddr,
}

pub struct TcpManager {
    connections: Arc<Mutex<HashMap<ConnectionKey, Vec<PooledConnection>>>>,
    max_idle_time: Duration,
}

impl TcpManager {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            max_idle_time: Duration::from_secs(300),
        }
    }

    pub async fn get_connection(&self, target: SocketAddr) -> Option<TcpStream> {
        let mut connections = self.connections.lock().await;
        let key = ConnectionKey {
            target_addr: target,
        };

        if let Some(pool) = connections.get_mut(&key) {
            if let Some(pos) = pool
                .iter()
                .position(|conn| conn.last_used.elapsed() < self.max_idle_time)
            {
                let conn = pool.remove(pos);
                info!(
                    "Reusing connection to {:?} from port {}",
                    target, conn.source_port
                );
                // 重新组合读写流
                match conn.read_half.reunite(conn.write_half) {
                    Ok(stream) => return Some(stream),
                    Err(e) => {
                        warn!("Failed to reunite stream: {:?}", e);
                        return None;
                    }
                }
            }
        }
        None
    }

    pub async fn store_connection(&self, target: SocketAddr, stream: TcpStream, source_port: u16) {
        let mut connections = self.connections.lock().await;
        let key = ConnectionKey {
            target_addr: target,
        };

        let pool = connections.entry(key.clone()).or_insert_with(Vec::new);
        if pool.len() < (SOURCE_PORT_END - SOURCE_PORT_START + 1) as usize {
            info!(
                "Storing connection to {:?} from port {}",
                target, source_port
            );
            // 分离读写流
            let (read_half, write_half) = stream.into_split();
            pool.push(PooledConnection {
                read_half,
                write_half,
                last_used: Instant::now(),
                source_port,
            });
        }
    }

    pub async fn get_next_source_port(&self, target: SocketAddr) -> Option<u16> {
        let connections = self.connections.lock().await;
        let key = ConnectionKey {
            target_addr: target,
        };

        let used_ports = connections
            .get(&key)
            .map(|pool| pool.iter().map(|conn| conn.source_port).collect::<Vec<_>>())
            .unwrap_or_default();

        for port in SOURCE_PORT_START..=SOURCE_PORT_END {
            if !used_ports.contains(&port) {
                return Some(port);
            }
        }
        None
    }
}

lazy_static::lazy_static! {
    pub static ref GLOBAL_TCP_MANAGER: TcpManager = TcpManager::new();
}
