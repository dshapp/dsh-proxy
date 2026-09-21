//! The client's half of the WebSocket, as a byte stream.
//!
//! `src/ws.rs` is the server's half; this is its mirror, and it lives in the
//! tests because the proxy has no reason to contain a WebSocket client. It is
//! what lets the identical Noise stack run over either carrier, which is the
//! only way the two eras can be compared honestly: the same phone code, the
//! same bridge, and nothing different but what moves the bytes.

#![allow(dead_code)]

use std::io::{Error, ErrorKind, Result};
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const MAX_FRAME: usize = 4 * 1024 * 1024;
const MAX_SEND: usize = 64 * 1024;

fn bad(message: &str) -> Error {
    Error::new(ErrorKind::InvalidData, message.to_string())
}

/// One upgraded WebSocket, presented as the byte stream it carries.
pub struct WsClientStream<S> {
    inner: S,
    incoming: BytesMut,
    plain: BytesMut,
    outgoing: BytesMut,
    closed: bool,
    /// Rotated per frame, as RFC 6455 asks of a client.
    mask_seed: u32,
}

impl<S> WsClientStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            incoming: BytesMut::new(),
            plain: BytesMut::new(),
            outgoing: BytesMut::new(),
            closed: false,
            mask_seed: 0x9e37_79b9,
        }
    }

    /// Stage one masked client frame.
    fn frame(&mut self, opcode: u8, payload: &[u8]) {
        self.mask_seed = self.mask_seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let mask = self.mask_seed.to_be_bytes();
        self.outgoing.reserve(payload.len() + 14);
        self.outgoing.put_u8(0x80 | opcode);
        if payload.len() < 126 {
            self.outgoing.put_u8(0x80 | payload.len() as u8);
        } else if payload.len() <= u16::MAX as usize {
            self.outgoing.put_u8(0x80 | 126);
            self.outgoing.put_u16(payload.len() as u16);
        } else {
            self.outgoing.put_u8(0x80 | 127);
            self.outgoing.put_u64(payload.len() as u64);
        }
        self.outgoing.extend_from_slice(&mask);
        let start = self.outgoing.len();
        self.outgoing.extend_from_slice(payload);
        for (index, byte) in self.outgoing[start..].iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
    }

    /// Take one complete server frame out of `incoming`.
    fn decode(&mut self) -> Result<bool> {
        if self.incoming.len() < 2 {
            return Ok(false);
        }
        let opcode = self.incoming[0] & 0x0f;
        let second = self.incoming[1];
        if second & 0x80 != 0 {
            return Err(bad("a server frame must not be masked"));
        }
        let (length, offset) = match second & 0x7f {
            126 => {
                if self.incoming.len() < 4 {
                    return Ok(false);
                }
                (u16::from_be_bytes([self.incoming[2], self.incoming[3]]) as usize, 4)
            }
            127 => {
                if self.incoming.len() < 10 {
                    return Ok(false);
                }
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&self.incoming[2..10]);
                (u64::from_be_bytes(bytes) as usize, 10)
            }
            other => (other as usize, 2),
        };
        if length > MAX_FRAME {
            return Err(bad("server frame is too large"));
        }
        if self.incoming.len() < offset + length {
            return Ok(false);
        }
        self.incoming.advance(offset);
        let payload = self.incoming.split_to(length);
        match opcode {
            0x0 | 0x1 | 0x2 => self.plain.unsplit(payload),
            0x8 => self.closed = true,
            0x9 => self.frame(0xa, &payload),
            0xa => {}
            _ => return Err(bad("unknown websocket opcode")),
        }
        Ok(true)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> WsClientStream<S> {
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        while !self.outgoing.is_empty() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.outgoing) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(bad("websocket closed"))),
                Poll::Ready(Ok(n)) => self.outgoing.advance(n),
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncRead for WsClientStream<S> {
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
            // Drain a buffered frame before asking for more: the socket can
            // fall quiet exactly on a boundary.
            if self.decode()? {
                let _ = self.as_mut().drain(cx);
                continue;
            }
            if self.closed {
                return Poll::Ready(Ok(()));
            }
            let mut scratch = [0u8; 16 * 1024];
            let mut read = ReadBuf::new(&mut scratch);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read) {
                Poll::Ready(Ok(())) => {
                    let filled = read.filled().len();
                    if filled == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    self.incoming.extend_from_slice(&scratch[..filled]);
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncWrite for WsClientStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<Result<usize>> {
        match self.as_mut().drain(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        let take = data.len().min(MAX_SEND);
        self.frame(0x2, &data[..take]);
        match self.as_mut().drain(cx) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            _ => Poll::Ready(Ok(take)),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        match self.as_mut().drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        match self.as_mut().drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
            other => other,
        }
    }
}
