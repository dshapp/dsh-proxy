//! A WebSocket server, cut down to exactly what a byte pipe needs.
//!
//! The phone's whole stack - Noise_IK, the mux, HTTP/1.1 - already runs over a
//! byte stream. All that changed is what carries those bytes: `wss://` instead
//! of a bare TCP socket, because that is the only thing a WeChat mini-program
//! may open. So this is not a WebSocket library: message boundaries carry no
//! meaning here, and every data frame's payload is simply appended to the
//! stream. Control frames are the only ones that mean anything.
//!
//! The proxy still cannot read any of it. The bytes inside these frames are
//! the client's Noise_IK session with the Mac.

use std::io::{Error, ErrorKind, Result};
use std::pin::Pin;
use std::task::{Context, Poll};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use bytes::{Buf, BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The constant RFC 6455 makes every server mix into the accept key.
const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// A frame larger than this is not a client of ours; it is a memory attack.
const MAX_FRAME: usize = 16 * 1024 * 1024;
/// Outgoing payload per frame. Bigger frames save header bytes and cost
/// latency; the mux already hands us work in chunks well under this.
const MAX_SEND: usize = 64 * 1024;

const OP_CONTINUATION: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xa;

fn bad(message: &str) -> Error {
    Error::new(ErrorKind::InvalidData, message.to_string())
}

/// The `Sec-WebSocket-Accept` answer to a client's `Sec-WebSocket-Key`.
pub fn accept_key(client_key: &str) -> String {
    let mut input = String::with_capacity(client_key.len() + GUID.len());
    input.push_str(client_key);
    input.push_str(GUID);
    // SHA-1 is not a security choice here: RFC 6455 fixes it, and the value
    // proves only that a WebSocket server answered.
    let digest = ring::digest::digest(
        &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
        input.as_bytes(),
    );
    B64.encode(digest.as_ref())
}

/// One WebSocket connection, presented as the byte stream it carries.
pub struct WsStream<S> {
    inner: S,
    /// Bytes read from the socket that are not yet a whole frame.
    incoming: BytesMut,
    /// Payload bytes waiting for the reader.
    plain: BytesMut,
    /// Frames waiting for the socket: our data, plus any pong we owe.
    outgoing: BytesMut,
    /// A close frame arrived; the stream ends once `plain` is drained.
    closed: bool,
}

impl<S> WsStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            incoming: BytesMut::new(),
            plain: BytesMut::new(),
            outgoing: BytesMut::new(),
            closed: false,
        }
    }

    /// Stage one server frame. Server frames are never masked.
    fn frame(&mut self, opcode: u8, payload: &[u8]) {
        self.outgoing.reserve(payload.len() + 10);
        self.outgoing.put_u8(0x80 | opcode);
        if payload.len() < 126 {
            self.outgoing.put_u8(payload.len() as u8);
        } else if payload.len() <= u16::MAX as usize {
            self.outgoing.put_u8(126);
            self.outgoing.put_u16(payload.len() as u16);
        } else {
            self.outgoing.put_u8(127);
            self.outgoing.put_u64(payload.len() as u64);
        }
        self.outgoing.extend_from_slice(payload);
    }

    /// Take one complete frame out of `incoming`.
    ///
    /// @returns whether a frame was consumed; payload lands in `plain`.
    fn decode(&mut self) -> Result<bool> {
        if self.incoming.len() < 2 {
            return Ok(false);
        }
        let first = self.incoming[0];
        let second = self.incoming[1];
        let opcode = first & 0x0f;
        let masked = second & 0x80 != 0;
        let short = (second & 0x7f) as usize;
        let (length, mut offset) = match short {
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
            other => (other, 2),
        };
        if length > MAX_FRAME {
            return Err(bad("websocket frame is too large"));
        }
        // RFC 6455: a client must mask. An unmasked client frame is either a
        // broken implementation or someone hand-rolling traffic at us.
        if !masked {
            return Err(bad("client frame is not masked"));
        }
        if self.incoming.len() < offset + 4 {
            return Ok(false);
        }
        let mask = [
            self.incoming[offset],
            self.incoming[offset + 1],
            self.incoming[offset + 2],
            self.incoming[offset + 3],
        ];
        offset += 4;
        if self.incoming.len() < offset + length {
            return Ok(false);
        }
        self.incoming.advance(offset);
        let mut payload = self.incoming.split_to(length);
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
        match opcode {
            // A pipe cares about bytes, not messages, so a fragment is just
            // more stream and FIN means nothing.
            OP_CONTINUATION | OP_TEXT | OP_BINARY => self.plain.unsplit(payload),
            OP_CLOSE => self.closed = true,
            OP_PING => self.frame(OP_PONG, &payload),
            OP_PONG => {}
            _ => return Err(bad("unknown websocket opcode")),
        }
        Ok(true)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> WsStream<S> {
    /// Push staged frames at the socket, without blocking the caller.
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

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncRead for WsStream<S> {
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
            // Drain what is already buffered before asking for more: the
            // socket can fall quiet exactly on a frame boundary, and a reader
            // that waits for more bytes with a whole frame in hand hangs.
            if self.decode()? {
                // A control frame may have queued a pong; get it moving, but
                // never block the read on it.
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

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncWrite for WsStream<S> {
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
        self.frame(OP_BINARY, &data[..take]);
        match self.as_mut().drain(cx) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            // Staged either way: a partial flush finishes on the next poll.
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
        if !self.closed {
            self.frame(OP_CLOSE, &[]);
            self.closed = true;
        }
        match self.as_mut().drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
            other => other,
        }
    }
}
