use log::{debug, error, info};
use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::task::{Context, Poll};

use futures::{future::poll_fn, ready};
use tokio::time::timeout;

use super::StatHandle;
use crate::flow::*;
//use crate::ChainedOutboundFactory;
#[derive(Debug)]
enum ForwardState {
    AwatingSizeHint,
    PollingTxBuf(SizeHint),
    PollingRxBuf,
    Closing,
    Done,
}

struct StatGuard(StatHandle);

struct StreamForward<'l, 'r> {
    stream_local: &'l mut dyn Stream,
    stream_remote: &'r mut dyn Stream,

    uplink_state: ForwardState,
    downlink_state: ForwardState,
    stat: StatGuard,
}

impl Drop for StatGuard {
    fn drop(&mut self) {
        self.0
            .inner
            .tcp_connection_count
            .fetch_sub(1, Ordering::Relaxed);
    }
}

fn poll_forward_oneway(
    cx: &mut Context<'_>,
    rx: &mut dyn Stream,
    tx: &mut dyn Stream,
    state: &mut ForwardState,
    counter: &AtomicU64,
) -> Poll<FlowResult<()>> {
    info!("客户端开始调用 poll_forward_oneway");
    loop {
        //println!("当前状态: {:?}", state);
        *state = match state {
            ForwardState::AwatingSizeHint => {
                //println!("等待大小提示");
                match rx.poll_request_size(cx) {
                    Poll::Pending => {
                        //println!("大小提示等待中");
                        if let p @ Poll::Ready(Err(_)) = tx.poll_flush_tx(cx) {
                            info!("刷新发送缓冲区时发生错误");
                            return p;
                        }
                        return Poll::Pending;
                    }
                    Poll::Ready(r) => {
                        info!("客户端收到大小提示: {:?}", r);
                        ForwardState::PollingTxBuf(r?)
                    }
                }
            }

            ForwardState::PollingTxBuf(size_hint) => {
                //println!("轮询发送缓冲区, 大小提示: {:?}", size_hint);
                let buf = ready!(
                    tx.poll_tx_buffer(cx, size_hint.with_min_content(4096).try_into().unwrap())
                )?;

                if let Err((buf, e)) = rx.commit_rx_buffer(buf) {
                    println!("🍓客户端提交接收缓冲区时发生错误: {:?}", e);
                    let _ = tx.commit_tx_buffer(buf);
                    return Poll::Ready(Err(e));
                }
                ForwardState::PollingRxBuf
            }
            ForwardState::PollingRxBuf => {
                //println!("轮询接收缓冲区");
                match ready!(rx.poll_rx_buffer(cx)) {
                    Ok(buf) => {
                        let len = buf.len();
                       // println!("🌹tcp客户端接收到来自服务端的数据长度: {},数据是{:0X?}", len, &buf[0..20.min(len)]);
                        tx.commit_tx_buffer(buf)?;
                       ready!(tx.poll_flush_tx(cx))?;
                        counter.fetch_add(len as u64, Ordering::Relaxed);
                        ForwardState::AwatingSizeHint
                    }
                    Err((buf, FlowError::Eof)) => {
                        info!("接收到 EOF");
                        let len = buf.len();
                        tx.commit_tx_buffer(buf)?;
                       ready!(tx.poll_flush_tx(cx))?;
                        counter.fetch_add(len as u64, Ordering::Relaxed);
                        ForwardState::Closing
                    }
                    Err((buf, e)) => {
                        info!("客户端接收数据时发生错误: {:?}", e);
                        let _ = tx.commit_tx_buffer(buf);
                        return Poll::Ready(Err(e));
                    }
                }
            }
            ForwardState::Closing => {
                info!("客户端关闭连接");
                ready!(tx.poll_close_tx(cx))?;
                ForwardState::Done
            }
            ForwardState::Done => {
                info!("客户端转发完成");
                return Poll::Ready(Ok(()));
            }
        }
    }
}

impl<'l, 'r> Future for StreamForward<'l, 'r> {
    type Output = FlowResult<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let Self {
            stream_local,
            stream_remote,
            uplink_state,
            downlink_state,
            stat,
        } = &mut *self;
        match (
            poll_forward_oneway(
                cx,
                *stream_remote,
                *stream_local,
                downlink_state,
                &stat.0.inner.downlink_written,
            ),
            poll_forward_oneway(
                cx,
                *stream_local,
                *stream_remote,
                uplink_state,
                &stat.0.inner.uplink_written,
            ),
        ) {
            (Poll::Ready(Ok(())), Poll::Ready(Ok(()))) => Poll::Ready(Ok(())),
            (Poll::Ready(Err(e)), _) | (_, Poll::Ready(Err(e))) => Poll::Ready(Err(e)),
            _ => Poll::Pending,
        }
    }
}

#[derive(Clone)]
pub struct StreamForwardHandler {
    pub request_timeout: u64,
    pub outbound: Weak<dyn StreamOutboundFactory>,
    pub stat: StatHandle,
}
impl StreamForwardHandler {
    async fn handle_stream(
        outbound_factory: Arc<dyn StreamOutboundFactory>,
        mut lower: Box<dyn Stream>,
        request_timeout: u64,
        initial_data: Vec<u8>,
        stat: StatGuard,
        mut context: Box<FlowContext>,
    ) -> FlowResult<()> {
        println!("开始调用forward handlerstream");
        println!("数据长度为{}", initial_data.len());

        let mut initial_uplink_state = ForwardState::AwatingSizeHint;
        let initial_data = if !initial_data.is_empty() {
            println!("initial_dat存在");
            Some(initial_data)
        } else if request_timeout == 0 {
            println!("超时了");

            None
        } else {
            println!("尝试重新读取");
            timeout(tokio::time::Duration::from_millis(request_timeout), async {
                let size = crate::get_request_size_boxed!(lower)?;
                initial_uplink_state = ForwardState::PollingTxBuf(size);
                let buf = Vec::with_capacity(size.with_min_content(4096));
                println!("让下一级出站工厂进行发送数据的操作");

                lower.as_mut().commit_rx_buffer(buf).map_err(|(_, e)| e)?;
                //获取一个rx_buf接受缓冲区
                let initial_data = crate::get_rx_buffer_boxed!(lower).map_err(|(_, e)| e);
                initial_uplink_state = ForwardState::AwatingSizeHint;
                /*println!(
                    "入站数据长度: {}, 数据为: {:0X?}",
                    initial_data.as_ref().map(|data| data.len()).unwrap_or(0),
                    initial_data.as_ref().map(|data| data
                        .iter()
                        .map(|&b| format!("{:0x}", b))
                        .collect::<Vec<String>>()
                        .join(" "))
                );*/
                initial_data
            })
            .await
            .ok()
            .transpose()?
        };

        // TODO: outbound handshake timeout
        let initial_data_ref = initial_data.as_deref().unwrap_or(&[]);
        println!("转发入站流量到出战工厂进行处理");

        let outbound = outbound_factory
            .create_outbound(&mut context, initial_data_ref)
            .await;
        stat.0
            .inner
            .uplink_written
            .fetch_add(initial_data_ref.len() as u64, Ordering::Relaxed);
        drop(initial_data);
        let (mut outbound, initial_res) = match outbound {
            Ok(outbound) => outbound,
            Err(e) => {
                // TODO: log error
                // Shutdown inbound normally since it is the outbound that faults.
                // Be careful not to trigger drainage etc. for the inbound in this case.
                println!("没有获得响应的数据");
                return crate::close_tx_boxed!(lower).and_then(|()| Err(e))?;
            }
        };
        println!(
            "中转器获得响应数据{:0X?}\n{}",
            initial_res,
            initial_res.len()
        );
        if let Ok(initial_res_len) = NonZeroUsize::try_from(initial_res.len()) {
            println!("将流量转发给入站端");
            let mut buf = crate::get_tx_buffer_boxed!(lower, initial_res_len)?;
            buf.extend_from_slice(&initial_res);
            println!("中转器接收到的响应数据为数据为\n{:0X?}", buf);

            lower.as_mut().commit_tx_buffer(buf)?;
            stat.0
                .inner
                .downlink_written
                .fetch_add(initial_res_len.get() as u64, Ordering::Relaxed);
        }

        let mut initial_downlink_state = ForwardState::AwatingSizeHint;

        if let ForwardState::PollingTxBuf(_) = initial_uplink_state {
            // If lower failed to fill initial data, try to extract the temporary
            // buffer out, and forward downlink at the same time.
            poll_fn(|cx| {
                match lower.as_mut().poll_rx_buffer(cx) {
                    Poll::Ready(Ok(_)) => return Poll::Ready(Ok(())),
                    Poll::Ready(Err((_, e))) => return Poll::Ready(Err(e)),
                    _ => {}
                }
                if let r @ Poll::Ready(Err(_)) = poll_forward_oneway(
                    cx,
                    outbound.as_mut(),
                    lower.as_mut(),
                    &mut initial_downlink_state,
                    &stat.0.inner.downlink_written,
                ) {
                    return r;
                };
                Poll::Pending
            })
            .await?;
        }

        // Drop earlier to prevent StreamForward outliving outbound
        StreamForward {
            stream_local: lower.as_mut(),
            stream_remote: outbound.as_mut(),
            downlink_state: initial_downlink_state,
            uplink_state: initial_uplink_state,
            stat,
        }
        .await?;

        Ok(())
    }
}

impl StreamHandler for StreamForwardHandler {
    fn on_stream(&self, lower: Box<dyn Stream>, initial_data: Buffer, context: Box<FlowContext>) {
        println!("🌹tcp客户端开始调用StreamForwardHandler");
        if let Some(outbound) = self.outbound.upgrade() {
            let stat = StatGuard(self.stat.clone());
            stat.0
                .inner
                .tcp_connection_count
                .fetch_add(1, Ordering::Relaxed);
            tokio::spawn(Self::handle_stream(
                outbound,
                lower,
                self.request_timeout,
                initial_data,
                stat,
                context,
            ));
        }
    }
}
