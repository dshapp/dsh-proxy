//! Shared test scaffolding: a proxy, and a client that speaks the real
//! contract to it.
//!
//! The client here is deliberately hand-rolled rather than taken from a
//! WebSocket crate, so the tests are an independent implementation of what a
//! phone does: masked frames, its own fragmentation, and nothing above the
//! byte stream.

#![allow(dead_code)]
pub mod phone;
pub mod wsio;

use std::net::SocketAddr;
use std::sync::Arc;

use dsh_proxy::edge::Edge;
use dsh_proxy::tls;
use rustls::pki_types::CertificateDer;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// The 37-byte plaintext preamble every connection starts with.
pub fn preamble(magic: &[u8; 4], version: u8, key: &[u8]) -> Vec<u8> {
    let mut head = Vec::with_capacity(37);
    head.extend_from_slice(magic);
    head.push(version);
    head.extend_from_slice(key);
    head
}

/// Start a proxy with a self-signed certificate; returns its address and leaf.
pub async fn start_proxy_with(limits: dsh_proxy::Limits) -> (SocketAddr, CertificateDer<'static>) {
    let identity = tls::self_signed(&["localhost"]).unwrap();
    let cert = identity.cert_chain[0].clone();
    let server = tls::server_config(identity).unwrap();
    let table = Arc::new(dashmap::DashMap::new());
    let edge = Arc::new(Edge { tls: server, table });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let private = dsh_proxy::noise::generate_keypair().unwrap().0;
    tokio::spawn(async move {
        let _ = dsh_proxy::run_edge(listener, Arc::new(private), limits, edge).await;
    });
    (addr, cert)
}

pub async fn start_proxy() -> (SocketAddr, CertificateDer<'static>) {
    start_proxy_with(dsh_proxy::Limits::default()).await
}

/// Frame `payload` the way a browser or `wx.connectSocket` would: masked.
pub fn client_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 14);
    out.push(0x80 | opcode);
    let mask_bit = 0x80u8;
    if payload.len() < 126 {
        out.push(mask_bit | payload.len() as u8);
    } else if payload.len() <= u16::MAX as usize {
        out.push(mask_bit | 126);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        out.push(mask_bit | 127);
        out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    let mask = [0x37u8, 0xfa, 0x21, 0x3d];
    out.extend_from_slice(&mask);
    for (index, byte) in payload.iter().enumerate() {
        out.push(byte ^ mask[index % 4]);
    }
    out
}

/// A client-side WebSocket that presents itself as a byte stream.
pub struct WsClient<S> {
    pub inner: S,
    plain: Vec<u8>,
    /// Payload bytes per outgoing frame, so fragmentation can be exercised.
    pub chunk: usize,
}

impl<S> WsClient<S> {
    pub fn new(inner: S, chunk: usize) -> Self {
        Self { inner, plain: Vec::new(), chunk }
    }
}

// Read and write are separate impls so a pipe can be split and driven from
// two tasks: a transfer larger than one window deadlocks otherwise.
impl<S: AsyncWrite + Unpin> WsClient<S> {
    pub async fn send(&mut self, data: &[u8]) -> std::io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        for piece in data.chunks(self.chunk) {
            self.inner.write_all(&client_frame(0x2, piece)).await?;
        }
        self.inner.flush().await
    }

    pub async fn ping(&mut self, payload: &[u8]) -> std::io::Result<()> {
        self.inner.write_all(&client_frame(0x9, payload)).await?;
        self.inner.flush().await
    }

}

impl<S: AsyncRead + Unpin> WsClient<S> {
    /// Read until `want` payload bytes have arrived, unframing as we go.
    pub async fn recv(&mut self, want: usize) -> std::io::Result<Vec<u8>> {
        while self.plain.len() < want {
            let mut head = [0u8; 2];
            self.inner.read_exact(&mut head).await?;
            let opcode = head[0] & 0x0f;
            assert_eq!(head[1] & 0x80, 0, "a server frame must not be masked");
            let length = match head[1] & 0x7f {
                126 => {
                    let mut bytes = [0u8; 2];
                    self.inner.read_exact(&mut bytes).await?;
                    u16::from_be_bytes(bytes) as usize
                }
                127 => {
                    let mut bytes = [0u8; 8];
                    self.inner.read_exact(&mut bytes).await?;
                    u64::from_be_bytes(bytes) as usize
                }
                other => other as usize,
            };
            let mut payload = vec![0u8; length];
            self.inner.read_exact(&mut payload).await?;
            match opcode {
                0x0 | 0x1 | 0x2 => self.plain.extend_from_slice(&payload),
                0xa => {}
                0x8 => return Err(std::io::Error::other("server closed")),
                other => panic!("unexpected opcode {other}"),
            }
        }
        Ok(self.plain.drain(..want).collect())
    }

    /// Read one control frame, returning its opcode and payload.
    pub async fn recv_control(&mut self) -> std::io::Result<(u8, Vec<u8>)> {
        let mut head = [0u8; 2];
        self.inner.read_exact(&mut head).await?;
        let length = (head[1] & 0x7f) as usize;
        let mut payload = vec![0u8; length];
        self.inner.read_exact(&mut payload).await?;
        Ok((head[0] & 0x0f, payload))
    }
}

pub type Pipe = WsClient<tokio_rustls::client::TlsStream<TcpStream>>;

/// Open the pipe: TLS, then the upgrade, leaving a byte stream behind.
pub async fn open_pipe(
    addr: SocketAddr,
    cert: &CertificateDer<'static>,
    chunk: usize,
) -> std::io::Result<Pipe> {
    let connector = tokio_rustls::TlsConnector::from(tls::client_config_trusting(cert.clone()));
    let socket = TcpStream::connect(addr).await?;
    socket.set_nodelay(true)?;
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls = connector.connect(name, socket).await?;
    let request = "GET /tunnel HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\n\
                   Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\
                   Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
    tls.write_all(request.as_bytes()).await?;
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        tls.read_exact(&mut byte).await?;
        head.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&head);
    assert!(text.starts_with("HTTP/1.1 101"), "no 101: {text}");
    // RFC 6455's accept value for the fixed key above.
    assert!(
        text.to_ascii_lowercase().contains("s3pplmbitxaq9kygzzhzrbk+xoo="),
        "wrong Sec-WebSocket-Accept: {text}"
    );
    Ok(WsClient { inner: tls, plain: Vec::new(), chunk })
}
