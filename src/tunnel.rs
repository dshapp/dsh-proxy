//! One mux stream that carries plaintext HTTP/1.1 inside Noise_IK.
//!
//! The proxy runs the IK handshake itself (see `noise::ik_initiate`) and then
//! wraps the stream in this: every write is sealed into one `[u16 len][sealed]`
//! transport message, every read opens one. It mirrors what a phone's
//! `NoiseInputStream`/`NoiseOutputStream` do, on the other end of the same
//! tunnel, so the bridge sees an ordinary encrypted phone connection.

use std::io::{Error, ErrorKind, Result};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use snow::StatelessTransportState;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::wire::{MAX_NOISE_MSG, TAG_LEN};

/// Largest plaintext that fits one transport message.
const MAX_PLAIN: usize = MAX_NOISE_MSG - TAG_LEN;

fn other(error: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Other, error.to_string())
}

/// A byte stream sealed with a finished Noise transport.
pub struct NoiseStream<S> {
    inner: S,
    transport: Arc<StatelessTransportState>,
    /// Sending nonce; one writer, so no lock.
    out_nonce: u64,
    /// Receiving nonce; one reader, so no lock.
    in_nonce: u64,
    /// Plaintext opened from the wire, waiting for the reader.
    plain: BytesMut,
    /// Ciphertext for the next message that is not fully in yet.
    incoming: BytesMut,
    /// Sealed bytes still to hand to the socket.
    outgoing: BytesMut,
}

impl<S> NoiseStream<S> {
    /// Wrap a stream whose handshake has just completed.
    pub fn new(inner: S, transport: StatelessTransportState) -> Self {
        Self {
            inner,
            transport: Arc::new(transport),
            out_nonce: 0,
            in_nonce: 0,
            plain: BytesMut::new(),
            incoming: BytesMut::new(),
            outgoing: BytesMut::new(),
        }
    }

    /// Seal `data` into `outgoing` as one length-prefixed transport message.
    fn seal_into(&mut self, data: &[u8]) {
        let sealed = data.len() + TAG_LEN;
        self.outgoing.reserve(2 + sealed);
        self.outgoing.put_u16(sealed as u16);
        let start = self.outgoing.len();
        self.outgoing.resize(start + sealed, 0);
        let n = self
            .transport
            .write_message(self.out_nonce, data, &mut self.outgoing[start..])
            .expect("the transport accepts a bounded plaintext");
        self.outgoing.truncate(start + n);
        self.out_nonce += 1;
    }

    /// Open one complete message from `incoming` into `plain`, if present.
    fn open_ready(&mut self) -> Result<bool> {
        if self.incoming.len() < 2 {
            return Ok(false);
        }
        let len = u16::from_be_bytes([self.incoming[0], self.incoming[1]]) as usize;
        if len < TAG_LEN {
            return Err(other("short noise message"));
        }
        if self.incoming.len() < 2 + len {
            return Ok(false);
        }
        self.incoming.advance(2);
        let sealed = self.incoming.split_to(len);
        let start = self.plain.len();
        self.plain.resize(start + len - TAG_LEN, 0);
        let n = self
            .transport
            .read_message(self.in_nonce, &sealed, &mut self.plain[start..])
            .map_err(other)?;
        self.in_nonce += 1;
        self.plain.truncate(start + n);
        Ok(true)
    }
}

impl<S: AsyncRead + Unpin + Send> AsyncRead for NoiseStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        loop {
            if !self.plain.is_empty() {
                let take = self.plain.len().min(buf.remaining());
                buf.put_slice(&self.plain[..take]);
                self.plain.advance(take);
                return Poll::Ready(Ok(()));
            }
            // A message may already be complete in the buffer — the socket can
            // go quiet on a message boundary (hyper writes head and body in one
            // call, so the boundary lands mid-stream). Drain that before asking
            // for more ciphertext, or the reader stalls with data in hand.
            if self.open_ready()? {
                continue;
            }
            // Pull more ciphertext until at least one message is complete.
            let mut scratch = [0u8; 16 * 1024];
            let mut read = ReadBuf::new(&mut scratch);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read) {
                Poll::Ready(Ok(())) => {
                    let filled = read.filled().len();
                    if filled == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    self.incoming.extend_from_slice(&scratch[..filled]);
                    if self.open_ready()? {
                        continue;
                    }
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncWrite + Unpin + Send> AsyncWrite for NoiseStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<Result<usize>> {
        // Drain anything still buffered before accepting more plaintext.
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        let take = data.len().min(MAX_PLAIN);
        self.seal_into(&data[..take]);
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(take)),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Ready(Ok(take)),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        loop {
            let this = self.as_mut().get_mut();
            if this.outgoing.is_empty() {
                return Pin::new(&mut this.inner).poll_flush(cx);
            }
            // Two disjoint fields: the writer borrows the socket, the buffer
            // borrows the staged bytes.
            let written = match Pin::new(&mut this.inner).poll_write(cx, &this.outgoing) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(other("tunnel closed"))),
                Poll::Ready(Ok(n)) => n,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            };
            this.outgoing.advance(written);
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

/// Read the next `[u16 len][data]` frame from a plain stream, handshake only.
pub async fn read_frame<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Bytes> {
    let mut len = [0u8; 2];
    stream.read_exact(&mut len).await?;
    let len = u16::from_be_bytes(len) as usize;
    if len > MAX_PLAIN + TAG_LEN {
        return Err(other("handshake message too large"));
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;
    Ok(Bytes::from(body))
}

/// Write one `[u16 len][data]` frame. Handshake only.
pub async fn write_frame<S: AsyncWrite + Unpin>(stream: &mut S, body: &[u8]) -> Result<()> {
    let mut out = Vec::with_capacity(body.len() + 2);
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    stream.write_all(&out).await
}
