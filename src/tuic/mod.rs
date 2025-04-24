mod types;
mod handle_stream;
use uuid::Uuid;
use crate::tuic::types::UdpRelayMode;
use tokio::time::Duration;
use crate::tuic::types::CongestionControl;
use quinn::VarInt;
use crate::tuic::types::TuicEndpoint;
use tokio::sync::{Mutex as AsyncMutex, OnceCell};
use crate::tuic::types::TuicConnection;
use std::sync::atomic::AtomicU16;
use std::sync::Arc;
use async_trait::async_trait;
use crate::flow::StreamOutboundFactory;
use crate::flow::*;
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
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tuic")
            .field("name", &self.opts.name)
            .finish()
    }
}




#[async_trait]
impl  StreamOutboundFactory for Handler {

    async fn create_outbound(
        &self,
        context: &mut FlowContext,
        initial_data: &[u8],
    ) -> FlowResult<(Box<dyn Stream>, Buffer)> {
        let endpoint = self.get_conn(&resolver, sess).await?;
        let (stream, buffer) = endpoint.create_outbound(context, initial_data).await?;
        Ok((Box::new(stream), buffer))
    }



}

impl Handler {
    pub fn new(opts: HandlerOptions) -> Self {
        Self {
            opts,
            ep: OnceCell::new(),
            conn: AsyncMutex::new(None),
            next_assoc_id: AtomicU16::new(0),
        }
    }

    async fn init_endpoint(
        opts: HandlerOptions,
        resolver: ThreadSafeDNSResolver,
        sess: &Session,
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
            if resolver.ipv6() {
                new_udp_socket(
                    Some((Ipv6Addr::UNSPECIFIED, 0).into()),
                    sess.iface.clone(),
                    #[cfg(target_os = "linux")]
                    sess.so_mark,
                )
                .await?
            } else {
                new_udp_socket(
                    Some((Ipv4Addr::UNSPECIFIED, 0).into()),
                    None,
                    #[cfg(target_os = "linux")]
                    sess.so_mark,
                )
                .await?
            }
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
        resolver: &ThreadSafeDNSResolver,
        sess: &Session,
    ) -> Result<Arc<TuicConnection>> {
        let endpoint = self
            .ep
            .get_or_try_init(|| {
                Self::init_endpoint(self.opts.clone(), resolver.clone(), sess)
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

    async fn do_connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> Result<BoxedChainedStream> {
        let conn = self.get_conn(&resolver, sess).await?;
        let dest = sess.destination.clone().into_tuic();
        let tuic_tcp = conn.connect_tcp(dest).await?;
        let s = ChainedStreamWrapper::new(tuic_tcp);
        s.append_to_chain(self.name()).await;
        Ok(Box::new(s))
    }
}
