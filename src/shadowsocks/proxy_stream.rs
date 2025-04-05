use super::crypto::*;
use crate::flow::*;
use futures::ready;
use std::convert::TryInto;
use std::num::NonZeroUsize;
use std::task::{Context, Poll};

pub enum RxCryptoState<C: ShadowCrypto>
where
    [(); C::KEY_LEN]:,
{
    ReadingIv { key: [u8; C::KEY_LEN] },
    Ready(C),
}

pub struct ShadowsocksStream<C: ShadowCrypto>
where
    [(); C::KEY_LEN]:,
{
    pub reader: StreamReader,
    pub rx_buf: Option<Vec<u8>>,
    pub rx_chunk_size: NonZeroUsize,
    pub rx_crypto: RxCryptoState<C>,
    pub tx_crypto: C,
    pub tx_offset: usize,
    pub lower: Box<dyn Stream>,
}

impl<C: ShadowCrypto + Unpin> Stream for ShadowsocksStream<C>
where
    [(); C::KEY_LEN]:,
    [(); C::IV_LEN]:,
    [(); C::PRE_CHUNK_OVERHEAD]:,
    [(); C::POST_CHUNK_OVERHEAD]:,
{
    fn poll_request_size(&mut self, cx: &mut Context<'_>) -> Poll<FlowResult<SizeHint>> {
        let Self {
            lower,
            rx_crypto: crypto,
            rx_chunk_size,
            reader,
            ..
        } = &mut *self;
        loop {
            match crypto {
                RxCryptoState::ReadingIv { key } => {
                    let mut iv = [0; C::IV_LEN];
                    ready!(
                        reader.poll_read_exact(cx, lower.as_mut(), C::IV_LEN, |buf| iv
                            .copy_from_slice(buf))
                    )?;
                    *crypto = RxCryptoState::Ready(C::create_crypto(key, &iv));
                }
                RxCryptoState::Ready(_) if C::PRE_CHUNK_OVERHEAD == 0 => {
                    return Poll::Ready(Ok(SizeHint::Unknown { overhead: 0 }));
                }
                RxCryptoState::Ready(crypto) => {
                    // Retrieve size of next chunk (AEAD only)
                    let size = ready!(reader.poll_read_exact(
                        cx,
                        lower.as_mut(),
                        C::PRE_CHUNK_OVERHEAD,
                        |buf| crypto.decrypt_size(buf.try_into().unwrap())
                    ))?
                    .ok_or(FlowError::UnexpectedData)?;
                    *rx_chunk_size = size;
                    return Poll::Ready(Ok(SizeHint::AtLeast(size.get() + C::POST_CHUNK_OVERHEAD)));
                }
            }
        }
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
            lower,
            rx_buf: rx_buf_opt,
            rx_chunk_size,
            rx_crypto: crypto,
            reader,
            ..
        } = &mut *self;
        let crypto = match crypto {
            RxCryptoState::ReadingIv { .. } => panic!("Polling rx buffer when IV not ready"),
            RxCryptoState::Ready(c) => c,
        };
        let rx_buf = match rx_buf_opt.as_mut() {
            Some(buf) => buf,
            None => panic!("Polling rx buffer without committing"),
        };
        let res = if C::POST_CHUNK_OVERHEAD == 0 {
            // Stream cipher
            let res = ready!(reader.poll_peek_at_least(cx, lower.as_mut(), 1, |buf| {
                let to_write = buf.len().min(rx_buf.capacity() - rx_buf.len());
                let buf = &mut buf[..to_write];
                let _ = crypto.decrypt(buf, &[0; C::POST_CHUNK_OVERHEAD]);
                rx_buf.extend_from_slice(buf);
                to_write
            }));
            if let Ok(written) = &res {
                reader.advance(*written);
            }
            res.map(|_| ())
        } else {
            // AEAD cipher
            let chunk_size = rx_chunk_size.get();
            let res = ready!(reader.poll_read_exact(
                cx,
                lower.as_mut(),
                chunk_size + C::POST_CHUNK_OVERHEAD,
                |buf| {
                    let (buf, post_overhead) = buf.split_at_mut(chunk_size);
                    if !crypto.decrypt(buf, (&*post_overhead).try_into().unwrap()) {
                        return false;
                    }
                    rx_buf.extend_from_slice(buf);
                    true
                }
            ));
            res.and_then(|dec_success| dec_success.then_some(()).ok_or(FlowError::UnexpectedData))
        };
        let buf = rx_buf_opt.take().unwrap();
        Poll::Ready(match res {
            Ok(()) => Ok(buf),
            Err(e) => Err((buf, e)),
        })
    }

    fn poll_tx_buffer(
        &mut self,
        cx: &mut Context<'_>,
        size: NonZeroUsize,
    ) -> Poll<FlowResult<Buffer>> {
        // For server, we don't need to add encryption overhead when polling for tx buffer
        self.lower.as_mut().poll_tx_buffer(cx, size)
    }

    fn commit_tx_buffer(&mut self, mut buffer: Buffer) -> FlowResult<()> {
        let Self {
            lower,
            tx_crypto: crypto,
            ..
        } = &mut *self;

        // For server, we need to encrypt the outgoing data
        let mut encrypted_buffer =
            Vec::with_capacity(buffer.len() + C::PRE_CHUNK_OVERHEAD + C::POST_CHUNK_OVERHEAD);
        encrypted_buffer.extend_from_slice(&[0; C::PRE_CHUNK_OVERHEAD]);
        encrypted_buffer.extend_from_slice(&buffer);
        encrypted_buffer.extend_from_slice(&[0; C::POST_CHUNK_OVERHEAD]);

        let (pre_overhead, remaining) = encrypted_buffer.split_at_mut(C::PRE_CHUNK_OVERHEAD);
        let (chunk, post_overhead) = remaining.split_at_mut(buffer.len());

        crypto.encrypt(
            pre_overhead.try_into().unwrap(),
            chunk,
            post_overhead.try_into().unwrap(),
        );

        lower.commit_tx_buffer(encrypted_buffer.into())
    }

    fn poll_flush_tx(&mut self, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        self.lower.poll_flush_tx(cx)
    }

    fn poll_close_tx(&mut self, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        self.lower.as_mut().poll_close_tx(cx)
    }
}
