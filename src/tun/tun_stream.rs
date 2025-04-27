use std::io;
use std::net::SocketAddr;
use std::sync::Weak;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::mem::MaybeUninit;
use log::info;

use async_trait::async_trait;
use futures::ready;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::flow::{Buffer, FlowContext, FlowError, FlowResult, SizeHint, Stream, StreamHandler, DestinationAddr};

// Stream Handler for TunTcpStream
pub struct TunStreamHandler {
    next: Weak<dyn StreamHandler>,
}

impl TunStreamHandler {
    pub fn new(next: Weak<dyn StreamHandler>) -> Self {
        Self { next }
    }
}

impl StreamHandler for TunStreamHandler {
    fn on_stream(
        &self,
        lower: Box<dyn Stream>,
        initial_data: Buffer,
        context: Box<FlowContext>,
    ) {
        let next = match self.next.upgrade() {
            Some(next) => next,
            None => {
                info!("Next handler is not available");
                return;
            }
        };
        
        // Just pass along to the next handler in the chain
        info!("TunStreamHandler passing stream to next handler");
        next.on_stream(lower, initial_data, context);
    }
}

// 添加安全的TunCompatFlow实现，替代CompatFlow
pub struct TunCompatFlow<S> {
    inner: S,
    rx_buf: Option<Buffer>,
    tx_buf: Option<(Buffer, usize)>,
}

impl<S: AsyncRead + AsyncWrite + Send + 'static> TunCompatFlow<S> {
    pub fn new(inner: S, tx_buf_size: usize) -> Self {
        Self {
            inner,
            rx_buf: None,
            tx_buf: Some((Vec::with_capacity(tx_buf_size), 0)),
        }
    }
}

fn convert_error(err: io::Error) -> FlowError {
    FlowError::Io(err)
}

impl<S: AsyncRead + AsyncWrite + Send + Unpin + 'static> Stream for TunCompatFlow<S> {
    // Read
    fn poll_request_size(&mut self, _cx: &mut Context<'_>) -> Poll<FlowResult<SizeHint>> {
        Poll::Ready(Ok(SizeHint::Unknown { overhead: 0 }))
    }
    
    fn commit_rx_buffer(&mut self, buffer: Buffer) -> Result<(), (Buffer, FlowError)> {
        self.rx_buf = Some(buffer);
        Ok(())
    }
    
    fn poll_rx_buffer(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Buffer, (Buffer, FlowError)>> {
        let Self {
            inner,
            rx_buf: rx_buf_opt,
            ..
        } = &mut *self;

        // Ensure buffer exists and has capacity
        if rx_buf_opt.is_none() {
            *rx_buf_opt = Some(Vec::with_capacity(8192));
        }
        
        let filled_len;
        let poll_result;
        
        {
            // Limit the scope of rx_buf and read_buf
            let rx_buf = rx_buf_opt.as_mut().unwrap();

            // Ensure there is space to read into
            if rx_buf.capacity() == rx_buf.len() {
                rx_buf.reserve(8192); // Reserve more space if full
            }

            let current_len = rx_buf.len();
            let capacity = rx_buf.capacity();
            
            let mut read_buf;
            // Use a block to manage the lifetime of the mutable borrow for ReadBuf
            {
                // Temporarily set length to capacity to create ReadBuf
                unsafe {
                    rx_buf.set_len(capacity);
                }
                // Create ReadBuf pointing to the newly initialized part
                read_buf = ReadBuf::new(&mut rx_buf[current_len..]);
                
                // Call poll_read on the inner stream
                poll_result = Pin::new(inner).poll_read(cx, &mut read_buf);
                
                // Get filled length *before* restoring original length
                filled_len = read_buf.filled().len();
                
                // Restore the original length *before* read_buf goes out of scope
                unsafe {
                    rx_buf.set_len(current_len); 
                }
            } // read_buf goes out of scope here, mutable borrow ends
        }

        // Now it's safe to take ownership of rx_buf
        match poll_result {
            Poll::Ready(Ok(())) => {
                let mut final_rx_buf = rx_buf_opt.take().unwrap(); // Take ownership
                if filled_len == 0 {
                     // Treat 0 bytes read as EOF if poll_read returned Ok(()) 
                    Poll::Ready(Err((final_rx_buf, FlowError::Eof)))
                } else {
                    // Update the length correctly after reading
                    let current_len = final_rx_buf.len(); // Get current length again after take()
                    let new_len = current_len + filled_len;
                    unsafe {
                        final_rx_buf.set_len(new_len);
                    }
                    Poll::Ready(Ok(final_rx_buf))
                }
            }
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err((rx_buf_opt.take().unwrap(), e.into())))
            }
            Poll::Pending => Poll::Pending,
        }
    }


    // Write
    fn poll_tx_buffer(
        &mut self,
        cx: &mut Context<'_>,
        size: NonZeroUsize,
    ) -> Poll<FlowResult<Buffer>> {
        ready!(self.poll_flush_tx(cx))?;
        let (mut tx_buf, _) = self.tx_buf.take().unwrap();
        tx_buf.clear();
        tx_buf.reserve(size.get());
        Poll::Ready(Ok(tx_buf))
    }
    
    fn commit_tx_buffer(&mut self, buffer: Buffer) -> FlowResult<()> {
        self.tx_buf = Some((buffer, 0));
        Ok(())
    }
    
    fn poll_flush_tx(&mut self, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        let Self { tx_buf, inner, .. } = self;
        let (tx_buf, offset) = tx_buf
            .as_mut()
            .expect("Polling TunCompatFlow without previous buffer committed");
        while *offset < tx_buf.len() {
            let written = ready!(Pin::new(&mut *inner).poll_write(cx, &tx_buf[*offset..]))
                .map_err(convert_error)?;
            *offset += written;
        }
        ready!(Pin::new(&mut *inner).poll_flush(cx))
            .map_err(convert_error)?;
        Poll::Ready(Ok(()))
    }

    fn poll_close_tx(&mut self, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        ready!(self.poll_flush_tx(cx))?;
        ready!(Pin::new(&mut self.inner).poll_shutdown(cx))
            .map_err(convert_error)?;
        Poll::Ready(Ok(()))
    }
}