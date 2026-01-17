mod codec;
mod stream;
mod connection;
mod salamander;

pub use stream::Hy2Stream;
pub use connection::Hy2Connection;
pub use salamander::Salamander;

use crate::flow::{FlowContext, FlowResult, Stream, Buffer, StreamOutboundFactory, Resolver};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::{Mutex as AsyncMutex, OnceCell};
use quinn::{
    ClientConfig as QuinnConfig, Endpoint as QuinnEndpoint,
    TransportConfig as QuinnTransportConfig, VarInt,
    EndpointConfig, TokioRuntime,
    crypto::rustls::QuicClientConfig,
};
use anyhow::Result;

#[derive(Debug, Clone)]
pub struct Hy2Options {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub password: String,
    pub sni: Option<String>,
    pub skip_cert_verify: bool,
    pub alpn: Vec<Vec<u8>>,
    pub disable_mtu_discovery: bool,
    pub obfs: Option<String>, // Salamander 混淆密钥
}

pub struct Hy2Handler {
    opts: Hy2Options,
    ep: OnceCell<QuinnEndpoint>,
    conn: AsyncMutex<Option<Arc<Hy2Connection>>>,
    resolver: Arc<dyn Resolver>,
}

impl std::fmt::Debug for Hy2Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hy2Handler")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl Hy2Handler {
    pub fn new(opts: Hy2Options, resolver: Arc<dyn Resolver>) -> Self {
        Self {
            opts,
            ep: OnceCell::new(),
            conn: AsyncMutex::new(None),
            resolver,
        }
    }

    async fn init_endpoint(opts: Hy2Options) -> Result<QuinnEndpoint> {
        use crate::tls::DefaultTlsVerifier;
        
        let verifier = DefaultTlsVerifier::new(None, opts.skip_cert_verify);
        let mut crypto = rustls::client::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();

        // 设置 ALPN，默认使用 h3
        crypto.alpn_protocols = if opts.alpn.is_empty() {
            vec![b"h3".to_vec()]
        } else {
            opts.alpn.clone()
        };

        let mut transport = QuinnTransportConfig::default();
        if opts.disable_mtu_discovery {
            transport.mtu_discovery_config(None);
        }
        transport.max_idle_timeout(Some(
            std::time::Duration::from_secs(300).try_into().unwrap(),
        ));
        transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));

        let quic_config: QuicClientConfig = crypto.try_into()?;
        let mut client_config = QuinnConfig::new(Arc::new(quic_config));
        client_config.transport_config(Arc::new(transport));

        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        let std_socket = socket.into_std()?;
        std_socket.set_nonblocking(true)?;

        // 如果配置了混淆，使用 Salamander 包装 socket
        let endpoint = if let Some(obfs_key) = opts.obfs {
            println!("🔐 启用 Salamander 混淆");
            let salamander = Arc::new(salamander::Salamander::new(
                std_socket,
                obfs_key.into_bytes(),
            )?);
            
            QuinnEndpoint::new_with_abstract_socket(
                EndpointConfig::default(),
                None,
                salamander,
                Arc::new(TokioRuntime),
            )?
        } else {
            println!("ℹ️  未启用混淆");
            QuinnEndpoint::new(
                EndpointConfig::default(),
                None,
                std_socket,
                Arc::new(TokioRuntime),
            )?
        };

        let mut endpoint = endpoint;
        endpoint.set_default_client_config(client_config);
        Ok(endpoint)
    }

    async fn get_conn(&self) -> Result<Arc<Hy2Connection>> {
        let endpoint = self
            .ep
            .get_or_try_init(|| Self::init_endpoint(self.opts.clone()))
            .await?;

        let mut guard = self.conn.lock().await;
        
        // 检查现有连接是否可用
        let need_reconnect = match guard.as_ref() {
            Some(conn) => {
                if conn.is_closed() {
                    tracing::warn!(
                        "🔄 [Hy2] 检测到连接已关闭，准备重连: {}:{}",
                        self.opts.server,
                        self.opts.port
                    );
                    true
                } else {
                    false
                }
            }
            None => {
                tracing::info!(
                    "🔌 [Hy2] 首次连接到服务器: {}:{}",
                    self.opts.server,
                    self.opts.port
                );
                true
            }
        };

        // 如果需要重连，创建新连接
        if need_reconnect {
            match Hy2Connection::connect(
                endpoint,
                &self.opts.server,
                self.opts.port,
                &self.opts.password,
                self.opts.sni.as_deref(),
                &*self.resolver,
            )
            .await
            {
                Ok(new_conn) => {
                    tracing::info!("✅ [Hy2] 连接成功");
                    *guard = Some(new_conn);
                }
                Err(e) => {
                    tracing::error!("❌ [Hy2] 连接失败: {}", e);
                    *guard = None;
                    return Err(e);
                }
            }
        }

        // 返回连接的克隆
        Ok(guard.as_ref().unwrap().clone())
    }

    async fn do_connect_stream(
        &self,
        context: &mut FlowContext,
    ) -> Result<Box<dyn Stream>> {
        let dest_addr = context.remote_peer.clone();
        
        // 尝试获取连接并创建 stream
        let conn = self.get_conn().await?;
        
        tracing::debug!("🌐 [Hy2] 尝试连接到目标: {}", dest_addr);
        
        match conn.connect_tcp(dest_addr.clone()).await {
            Ok(hy2_stream) => {
                tracing::debug!("✅ [Hy2] Stream 创建成功: {}", dest_addr);
                // 使用 CompatFlow 适配器
                use crate::flow::CompatFlow;
                let compat_stream = CompatFlow::new(hy2_stream, 8192);
                Ok(Box::new(compat_stream))
            }
            Err(e) => {
                tracing::error!("❌ [Hy2] Stream 创建失败: {} - 错误: {}", dest_addr, e);
                
                // 检查是否是连接级别的错误
                if conn.is_closed() {
                    tracing::warn!("🔄 [Hy2] 连接已断开，清除缓存的连接");
                    // 清除已断开的连接，下次会自动重连
                    let mut guard = self.conn.lock().await;
                    *guard = None;
                }
                
                Err(e)
            }
        }
    }

    async fn send_data(&self, stream: &mut dyn Stream, data: &[u8]) -> FlowResult<()> {
        use futures::future::poll_fn;
        
        let len = match data.len().try_into() {
            Ok(len) => len,
            Err(_) => return Ok(()),
        };
        
        let mut tx_buf = poll_fn(|cx| stream.poll_tx_buffer(cx, len)).await?;
        tx_buf.extend(data);
        stream.commit_tx_buffer(tx_buf)?;
        poll_fn(|cx| stream.poll_flush_tx(cx)).await
    }
}

#[async_trait]
impl StreamOutboundFactory for Hy2Handler {
    async fn create_outbound<'s, 'a, 'b>(
        &'s self,
        context: &'a mut FlowContext,
        initial_data: &'b [u8],
    ) -> FlowResult<(Box<dyn Stream>, Buffer)> {
        let mut stream = self.do_connect_stream(context).await
            .map_err(|e| {
                crate::flow::FlowError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Hysteria2 connection failed: {}", e)
                ))
            })?;
        
        if !initial_data.is_empty() {
            self.send_data(&mut *stream, initial_data).await?;
        }
        
        Ok((stream, Buffer::new()))
    }
}
