pub mod types;
mod handle_stream;
mod handle_task;
use uuid::Uuid;
use crate::tuic::types::UdpRelayMode;
use tokio::time::Duration;
use crate::tuic::types::CongestionControl;
use anyhow::Result;
use crate::tuic::types::TuicEndpoint;
use tokio::sync::{Mutex as AsyncMutex, OnceCell};
use crate::tuic::types::TuicConnection;
use std::sync::atomic::AtomicU16;
use std::sync::Arc;
use async_trait::async_trait;
use crate::flow::StreamOutboundFactory;
use crate::flow::*;
use quinn::{
    ClientConfig as QuinnConfig, Endpoint as QuinnEndpoint,
    TransportConfig as QuinnTransportConfig, VarInt, congestion::CubicConfig,
};
use quinn::{
    EndpointConfig, TokioRuntime,
    congestion::{BbrConfig, NewRenoConfig},
    crypto::rustls::QuicClientConfig,
};

use tracing::debug;
use crate::tls::DefaultTlsVerifier;
use crate::tuic::types::ServerAddr;
use crate::tuic::types::SocketAdderTrans;
use futures::future::poll_fn;

#[derive(Debug, Clone)]
pub struct HandlerOptions {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub uuid: Uuid,
    pub password: String,
    pub udp_relay_mode: UdpRelayMode,
    pub disable_sni: bool,
    pub alpn: Vec<Vec<u8>>,
    pub heartbeat_interval: Duration,
    pub reduce_rtt: bool,
    pub request_timeout: Duration,
    pub idle_timeout: Duration,
    pub congestion_controller: CongestionControl,
    pub max_open_stream: VarInt,
    pub gc_interval: Duration,
    pub gc_lifetime: Duration,
    pub send_window: u64,
    
    pub receive_window: VarInt,
    pub skip_cert_verify: bool,

    /// not used
    #[allow(dead_code)]
    pub max_udp_relay_packet_size: u64,
    #[allow(dead_code)]
    pub ip: Option<String>,
    #[allow(dead_code)]
    pub sni: Option<String>,
}

pub struct Handler {
    opts: HandlerOptions,
    ep: OnceCell<TuicEndpoint>,
    conn: AsyncMutex<Option<Arc<TuicConnection>>>,
    next_assoc_id: AtomicU16,
    resolver: Arc<dyn Resolver>,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tuic")
            .field("name", &self.opts.name)
            .finish()
    }
}


impl Handler {
    pub fn new(opts: HandlerOptions, resolver: Arc<dyn Resolver>) -> Self {
        Self {
            opts,
            ep: OnceCell::new(),
            conn: AsyncMutex::new(None),
            next_assoc_id: AtomicU16::new(0),
            resolver,
        }
    }

    async fn init_endpoint(
        opts: HandlerOptions
    ) -> Result<TuicEndpoint> {
        let verifier = DefaultTlsVerifier::new(None, opts.skip_cert_verify);
        let mut crypto =
            rustls::client::ClientConfig::builder_with_protocol_versions(&[
                &rustls::version::TLS13,
            ])
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        // TODO(error-handling) if alpn not match the following error will be
        // throw: aborted by peer: the cryptographic handshake failed: error
        // 120: peer doesn't support any known protocol
        crypto.alpn_protocols.clone_from(&opts.alpn);
        crypto.enable_early_data = true;
        crypto.enable_sni = !opts.disable_sni;

        let mut quinn_config =
            QuinnConfig::new(Arc::new(QuicClientConfig::try_from(crypto)?));
        let mut transport_config = QuinnTransportConfig::default();
        transport_config
            .max_concurrent_bidi_streams(opts.max_open_stream)
            .max_concurrent_uni_streams(opts.max_open_stream)
            .send_window(opts.send_window)
            .stream_receive_window(opts.receive_window)
            .max_idle_timeout(Some(opts.idle_timeout.try_into().unwrap()));
        match opts.congestion_controller {
            CongestionControl::Cubic => transport_config
                .congestion_controller_factory(Arc::new(CubicConfig::default())),
            CongestionControl::NewReno => transport_config
                .congestion_controller_factory(Arc::new(NewRenoConfig::default())),
            CongestionControl::Bbr => transport_config
                .congestion_controller_factory(Arc::new(BbrConfig::default())),
        };

        quinn_config.transport_config(Arc::new(transport_config));

        let socket = {
            // 直接使用IPv4绑定，不需要判断IPv6支持情况
            let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
            
            // 设置socket选项
            let std_socket = socket.into_std()?;
            
            // 设置为非阻塞模式
            std_socket.set_nonblocking(true)?;
            
            // 转回tokio的UdpSocket
            tokio::net::UdpSocket::from_std(std_socket)?
        };

        debug!("binding socket to: {:?}", socket.local_addr()?);

        let mut endpoint = QuinnEndpoint::new(
            EndpointConfig::default(),
            None,
            socket.into_std()?,
            Arc::new(TokioRuntime),
        )?;

        endpoint.set_default_client_config(quinn_config);
        let endpoint = TuicEndpoint {
            ep: endpoint,
            server: ServerAddr::new(opts.server.clone(), opts.port, None),
            uuid: opts.uuid,
            password: Arc::from(
                opts.password.clone().into_bytes().into_boxed_slice(),
            ),
            udp_relay_mode: opts.udp_relay_mode,
            zero_rtt_handshake: opts.reduce_rtt,
            heartbeat: opts.heartbeat_interval,
            gc_interval: opts.gc_interval,
            gc_lifetime: opts.gc_lifetime,
        };

        Ok(endpoint)
    }


    async fn get_conn(
        &self,
        resolver:&dyn Resolver,
    ) -> Result<Arc<TuicConnection>> {
        let endpoint = self
            .ep
            .get_or_try_init(|| {
                Self::init_endpoint(self.opts.clone())
            })
            .await?;

        let fut = async {
            let mut guard = self.conn.lock().await;
            if guard.is_none() {
                // init
                *guard = Some(endpoint.connect(resolver, false).await?);
            }
            let conn = guard.take().unwrap();
            let conn = if conn.check_open().is_err() {
                // reconnect
                endpoint.connect(resolver, true).await?
            } else {
                conn
            };
            *guard = Some(conn.clone());
            Ok(conn)
        };

        tokio::time::timeout(self.opts.request_timeout, fut).await?
    }

    // 修改内层连接函数，不接收initial_data
    async fn do_connect_stream(
        &self,
        context: &mut FlowContext,
    ) -> Result<Box<dyn Stream>> {
        // 获取TUIC连接
        let conn = self.get_conn(&*self.resolver).await?;
        

    
        // 从context中获取目标地址
        let dest_addr = context.remote_peer.clone().into_tuic();
        
        // 连接到目标服务器
        let tuic_tcp = conn.connect_tcp(dest_addr).await?;
        
        // 使用CompatFlow适配器将tuic_tcp适配为Flow系统的Stream
        let compat_stream = CompatFlow::new(tuic_tcp, 8192);
        
        // 只返回流对象，不处理initial_data
        Ok(Box::new(compat_stream))
    }

    // 添加发送数据的辅助函数
    async fn send_data(&self, stream: &mut dyn Stream, data: &[u8]) -> FlowResult<()> {
        let len = match data.len().try_into() {
            Ok(len) => len,
            Err(_) => return Ok(()),
        };
        
        // 获取传输缓冲区
        let mut tx_buf = poll_fn(|cx| stream.poll_tx_buffer(cx, len)).await?;
        
        // 将数据写入缓冲区
        tx_buf.extend(data);
        
        // 提交缓冲区
        stream.commit_tx_buffer(tx_buf)?;
        
        // 确保数据被刷新发送
        poll_fn(|cx| stream.poll_flush_tx(cx)).await
    }
}

#[async_trait]
impl StreamOutboundFactory for Handler {
    async fn create_outbound<'s, 'a, 'b>(
        &'s self,
        context: &'a mut FlowContext,
        initial_data: &'b [u8],
    ) -> FlowResult<(Box<dyn Stream>, Buffer)> {
        // 先调用内层函数建立连接
        let mut stream = self.do_connect_stream(context).await
            .map_err(|e| {
                FlowError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other, 
                    format!("TUIC connection failed: {}", e)
                ))
            })?;
        
        // 发送初始数据到TUIC流
        if !initial_data.is_empty() {
            println!("开始发送初始数据到TUIC流");
            self.send_data(&mut *stream, initial_data).await?;
        }
        
        // 返回流和空缓冲区
        Ok((stream, Buffer::new()))
    }
}