use crate::flow::*;
use async_trait::async_trait;
use pin_project_lite::pin_project;
use std::future::Future;
use std::sync::Weak;
use std::task::{Context, Poll};

#[async_trait]
pub trait PeerProvider: 'static + Send + Sync + Clone {
    async fn get_peer(&self) -> DestinationAddr;
}

#[async_trait]
impl<F, Fut> PeerProvider for F
where
    F: 'static + Send + Sync + Clone + Fn() -> Fut,
    Fut: Future<Output = DestinationAddr> + Send,
{
    async fn get_peer(&self) -> DestinationAddr {
        self().await
    }
}

pub struct StreamRedirectHandler<R: PeerProvider> {
    pub remote_peer: R,
    pub next: Weak<dyn StreamHandler>,
}

pub struct StreamRedirectOutboundFactory<R: PeerProvider> {
    pub remote_peer: R,
    pub next: Weak<dyn StreamOutboundFactory>,
}

pin_project! {
    struct DatagramRedirectSession<R: PeerProvider> {
        remote_peer: R,
        #[pin]
        lower: Box<dyn DatagramSession>,
    }
}

pub struct DatagramSessionRedirectHandler<R: PeerProvider> {
    pub remote_peer: R,
    pub next: Weak<dyn DatagramSessionHandler>,
}

pub struct DatagramSessionRedirectFactory<R: PeerProvider> {
    pub remote_peer: R,
    pub next: Weak<dyn DatagramSessionFactory>,
}

impl<R: PeerProvider> StreamHandler for StreamRedirectHandler<R> {
    fn on_stream(
        &self,
        lower: Box<dyn Stream>,
        initial_data: Buffer,
        mut context: Box<FlowContext>,
    ) {
        let next = match self.next.upgrade() {
            Some(n) => n,
            None => return,
        };

        let remote_peer = self.remote_peer.clone();
        tokio::spawn(async move {
            let future = remote_peer.get_peer();
            context.remote_peer = future.await;
            next.on_stream(lower, initial_data, context);
        });
    }
}

#[async_trait]
impl<R: PeerProvider> StreamOutboundFactory for StreamRedirectOutboundFactory<R> {
    async fn create_outbound(
        &self,
        context: &mut FlowContext,
        initial_data: &'_ [u8],
    ) -> FlowResult<(Box<dyn Stream>, Buffer)> {
        let next = match self.next.upgrade() {
            Some(n) => n,
            None => return Err(FlowError::NoOutbound),
        };
        context.remote_peer = self.remote_peer.get_peer().await;
        next.create_outbound(context, initial_data).await
    }
}

impl<R: PeerProvider> DatagramSession for DatagramRedirectSession<R> {
    fn poll_recv_from(&mut self, cx: &mut Context) -> Poll<Option<(DestinationAddr, Buffer)>> {
        self.lower.as_mut().poll_recv_from(cx)
    }
    fn poll_send_ready(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        self.lower.as_mut().poll_send_ready(cx)
    }
    fn send_to(&mut self, _remote_peer: DestinationAddr, buf: Buffer) {
        let future = self.remote_peer.get_peer();
        let dest = futures::executor::block_on(future);
        self.lower.as_mut().send_to(dest, buf)
    }
    fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        self.lower.as_mut().poll_shutdown(cx)
    }
}

impl<R: PeerProvider> DatagramSessionHandler for DatagramSessionRedirectHandler<R> {
    fn on_session(&self, session: Box<dyn DatagramSession>, mut context: Box<FlowContext>) {
        let next = match self.next.upgrade() {
            Some(n) => n,
            None => return,
        };

        let remote_peer = self.remote_peer.clone();
        tokio::spawn(async move {
            context.remote_peer = remote_peer.get_peer().await;
            next.on_session(
                Box::new(DatagramRedirectSession {
                    remote_peer: remote_peer,
                    lower: session,
                }),
                context,
            );
        });
    }
}

#[async_trait]
impl<R: PeerProvider> DatagramSessionFactory for DatagramSessionRedirectFactory<R> {
    async fn bind(&self, mut context: Box<FlowContext>) -> FlowResult<Box<dyn DatagramSession>> {
        let next = match self.next.upgrade() {
            Some(n) => n,
            None => return Err(FlowError::NoOutbound),
        };
        context.remote_peer = self.remote_peer.get_peer().await;
        Ok(Box::new(DatagramRedirectSession {
            remote_peer: self.remote_peer.clone(),
            lower: next.bind(context).await?,
        }))
    }
}
