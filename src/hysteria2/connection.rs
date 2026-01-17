use super::codec::{Hy2TcpCodec, padding};
use super::stream::Hy2Stream;
use crate::flow::{DestinationAddr, Resolver};
use anyhow::{anyhow, Result};
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use quinn::{Connection, Endpoint};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::debug;
use h3::client::SendRequest;
use h3_quinn::OpenStreams;

/// Hysteria2 连接管理
pub struct Hy2Connection {
    conn: Arc<Connection>,
    // 保持 HTTP/3 连接活跃的 guard
    _guard: SendRequest<OpenStreams, Bytes>,
    // 连接创建时间，用于检测超时
    created_at: std::time::Instant,
}

impl Hy2Connection {
    /// 连接到 Hysteria2 服务器并进行认证
    pub async fn connect(
        endpoint: &Endpoint,
        server: &str,
        port: u16,
        password: &str,
        sni: Option<&str>,
        resolver: &dyn Resolver,
    ) -> Result<Arc<Self>> {
        // 解析服务器地址
        let server_addr = if let Ok(ip) = server.parse() {
            SocketAddr::new(ip, port)
        } else {
            let ips = resolver.resolve_ipv4(server.to_string()).await?;
            if ips.is_empty() {
                return Err(anyhow!("无法解析服务器地址: {}", server));
            }
            SocketAddr::new(ips[0].into(), port)
        };

        debug!("连接到 Hysteria2 服务器: {}", server_addr);

        // 建立 QUIC 连接
        let conn = endpoint
            .connect(server_addr, sni.unwrap_or(server))?
            .await?;

        debug!("QUIC 连接已建立，开始 HTTP/3 认证");

        // 执行 Hysteria2 认证，并获取 guard 保持连接活跃
        let guard = Self::auth(&conn, password).await?;

        Ok(Arc::new(Self {
            conn: Arc::new(conn),
            _guard: guard,
            created_at: std::time::Instant::now(),
        }))
    }

    /// Hysteria2 HTTP/3 认证
    /// 返回 SendRequest guard 用于保持 HTTP/3 连接活跃
    async fn auth(conn: &Connection, password: &str) -> Result<SendRequest<OpenStreams, Bytes>> {
        println!("🔐 [Hy2 Auth] 开始 Hysteria2 认证流程");
        
        // 创建 H3 连接
        println!("🔐 [Hy2 Auth] 创建 H3 连接...");
        let h3_conn = h3_quinn::Connection::new(conn.clone());
        
        // 构建 H3 客户端
        println!("🔐 [Hy2 Auth] 构建 H3 客户端...");
        let (_, mut sender) = h3::client::builder()
            .build::<_, _, Bytes>(h3_conn)
            .await?;
        println!("✅ [Hy2 Auth] H3 客户端构建成功");

        // 构建认证请求 - 使用 http 0.2 API
        let padding_bytes = padding(64..=512);
        let padding_str = String::from_utf8_lossy(&padding_bytes);
        
        println!("🔐 [Hy2 Auth] 构建认证请求...");
        println!("   - URI: https://hysteria/auth");
        println!("   - Method: POST");
        println!("   - Padding 长度: {} bytes", padding_bytes.len());
        
        let req = http::Request::builder()
            .method("POST")
            .uri("https://hysteria/auth")
            .header("Hysteria-Auth", password)
            .header("Hysteria-CC-RX", "0")
            .header("Hysteria-Padding", padding_str.as_ref())
            .body(())
            .unwrap();

        // 发送请求
        println!("📤 [Hy2 Auth] 发送认证请求...");
        let mut resp = sender.send_request(req).await?;
        resp.finish().await?;
        println!("✅ [Hy2 Auth] 认证请求已发送");

        // 接收响应
        println!("📥 [Hy2 Auth] 等待服务器响应...");
        let resp = resp.recv_response().await?;
        
        let status_code = resp.status().as_u16();
        println!("📥 [Hy2 Auth] 收到服务器响应");
        println!("   - 状态码: {}", status_code);
        println!("   - 响应头数量: {}", resp.headers().len());
        
        // 打印所有响应头
        println!("   - 响应头列表:");
        for (name, value) in resp.headers() {
            if let Ok(value_str) = value.to_str() {
                println!("     * {}: {}", name, value_str);
            } else {
                println!("     * {}: <binary>", name);
            }
        }

        // 检查状态码
        const HYSTERIA_STATUS_OK: u16 = 233;
        if status_code != HYSTERIA_STATUS_OK {
            println!("❌ [Hy2 Auth] 认证失败: 状态码不匹配");
            println!("   - 期望: {}", HYSTERIA_STATUS_OK);
            println!("   - 实际: {}", status_code);
            return Err(anyhow!(
                "Hysteria2 认证失败: status code {}",
                resp.status()
            ));
        }
        println!("✅ [Hy2 Auth] 状态码检查通过 (233)");

        // 验证必需的响应头
        println!("🔍 [Hy2 Auth] 检查响应头...");
        
        let cc_rx = resp
            .headers()
            .get("Hysteria-CC-RX")
            .ok_or_else(|| {
                println!("❌ [Hy2 Auth] 缺少 Hysteria-CC-RX 响应头");
                anyhow!("认证失败: 缺少 Hysteria-CC-RX 头")
            })?;
        let cc_rx_str = cc_rx.to_str()?;
        println!("✅ [Hy2 Auth] Hysteria-CC-RX: {}", cc_rx_str);

        let support_udp = resp
            .headers()
            .get("Hysteria-UDP")
            .ok_or_else(|| {
                println!("❌ [Hy2 Auth] 缺少 Hysteria-UDP 响应头");
                anyhow!("认证失败: 缺少 Hysteria-UDP 头")
            })?;
        let support_udp_str = support_udp.to_str()?;
        println!("✅ [Hy2 Auth] Hysteria-UDP: {}", support_udp_str);

        println!("🎉 [Hy2 Auth] ========== 认证成功 ==========");
        debug!("Hysteria2 认证成功");
        
        // 返回 sender 作为 guard，保持 HTTP/3 连接活跃
        Ok(sender)
    }

    /// 建立 TCP 连接
    pub async fn connect_tcp(&self, dest: DestinationAddr) -> Result<Hy2Stream> {
        tracing::debug!("🔗 [Hy2 TCP] 开始建立连接到: {}", dest);

        // 检查连接状态
        if let Some(reason) = self.conn.close_reason() {
            tracing::error!("❌ [Hy2 TCP] QUIC 连接已关闭: {:?}", reason);
            return Err(anyhow!("QUIC 连接已关闭: {:?}", reason));
        }

        // 打开双向流，添加超时
        let open_result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            self.conn.open_bi()
        ).await;

        let (mut tx, mut rx) = match open_result {
            Ok(Ok(streams)) => {
                tracing::debug!("✅ [Hy2 TCP] 双向流已打开");
                streams
            }
            Ok(Err(e)) => {
                tracing::error!("❌ [Hy2 TCP] 打开双向流失败: {}", e);
                return Err(anyhow!("打开双向流失败: {}", e));
            }
            Err(_) => {
                tracing::error!("❌ [Hy2 TCP] 打开双向流超时 (10秒)");
                return Err(anyhow!("打开双向流超时"));
            }
        };

        // 发送目标地址
        tracing::debug!("📤 [Hy2 TCP] 发送目标地址: {}", dest);
        if let Err(e) = tokio_util::codec::FramedWrite::new(&mut tx, Hy2TcpCodec)
            .send(&dest)
            .await
        {
            tracing::error!("❌ [Hy2 TCP] 发送目标地址失败: {}", e);
            return Err(anyhow!("发送目标地址失败: {}", e));
        }

        // 接收服务器响应，添加超时
        tracing::debug!("📥 [Hy2 TCP] 等待服务器响应...");
        let recv_result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            tokio_util::codec::FramedRead::new(&mut rx, Hy2TcpCodec).next()
        ).await;

        match recv_result {
            Ok(Some(Ok(resp))) => {
                if resp.status != 0x00 {
                    tracing::error!(
                        "❌ [Hy2 TCP] 服务器拒绝连接: status={}, msg={:?}",
                        resp.status,
                        resp.msg
                    );
                    return Err(anyhow!(
                        "服务器响应错误: status={}, msg={:?}",
                        resp.status,
                        resp.msg
                    ));
                }
                tracing::debug!(
                    "✅ [Hy2 TCP] 连接成功: status={}, msg={:?}",
                    resp.status, resp.msg
                );
            }
            Ok(Some(Err(e))) => {
                tracing::error!("❌ [Hy2 TCP] 读取服务器响应失败: {}", e);
                return Err(anyhow!("读取服务器响应失败: {}", e));
            }
            Ok(None) => {
                tracing::error!("❌ [Hy2 TCP] 未收到服务器响应 (连接关闭)");
                return Err(anyhow!("未收到服务器响应"));
            }
            Err(_) => {
                tracing::error!("❌ [Hy2 TCP] 等待服务器响应超时 (10秒)");
                return Err(anyhow!("等待服务器响应超时"));
            }
        }

        tracing::info!("🎉 [Hy2 TCP] Stream 建立完成: {}", dest);
        Ok(Hy2Stream::new(tx, rx))
    }

    /// 检查连接是否已关闭
    pub fn is_closed(&self) -> bool {
        self.conn.close_reason().is_some()
    }

    /// 检查连接是否可用（类似 TUIC 的 check_open）
    pub fn check_open(&self) -> Result<()> {
        match self.conn.close_reason() {
            Some(err) => {
                tracing::warn!("🔍 [Hy2] 连接已关闭: {:?}", err);
                Err(anyhow!("连接已关闭: {:?}", err))
            }
            None => Ok(()),
        }
    }

    /// 获取连接存活时间
    pub fn alive_duration(&self) -> std::time::Duration {
        self.created_at.elapsed()
    }
}
