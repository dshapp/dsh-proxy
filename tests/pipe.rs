//! The one client contract: a WebSocket carrying the phone's own byte stream.
//!
//! The test plays a real mini-program: TLS to the proxy, a WebSocket upgrade,
//! then masked frames carrying the 37-byte preamble and a Noise_IK session
//! with the bridge. Nothing inside is readable by the proxy, which is the
//! point - it is the same end-to-end session a bare TCP socket used to carry.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::{FramedRead, FramedWrite};

use dsh_proxy::edge::Edge;
use dsh_proxy::mux::{MuxSession, MuxStreamIo};
use dsh_proxy::noise;
use dsh_proxy::phone::Pool;
use dsh_proxy::state::Registry;
use dsh_proxy::tls;
use dsh_proxy::tunnel::NoiseStream;
use dsh_proxy::wire::{HEAD_LEN, MAGIC_BRIDGE, MAGIC_CLIENT, VERSION};

fn preamble(magic: &[u8; 4], key: &[u8; 32]) -> Vec<u8> {
    let mut head = Vec::with_capacity(HEAD_LEN);
    head.extend_from_slice(magic);
    head.push(VERSION);
    head.extend_from_slice(key);
    head
}

// ------------------------------------------------------- a minimal WS client

/// Frame `payload` the way a browser or `wx.connectSocket` would: masked.
fn client_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
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
struct WsClient<S> {
    inner: S,
    plain: Vec<u8>,
    /// Payload bytes per outgoing frame, so fragmentation can be exercised.
    chunk: usize,
}

impl<S: AsyncRead + AsyncWrite + Unpin> WsClient<S> {
    async fn send(&mut self, data: &[u8]) -> std::io::Result<()> {
        for piece in data.chunks(self.chunk) {
            self.inner.write_all(&client_frame(0x2, piece)).await?;
        }
        self.inner.flush().await
    }

    async fn ping(&mut self, payload: &[u8]) -> std::io::Result<()> {
        self.inner.write_all(&client_frame(0x9, payload)).await?;
        self.inner.flush().await
    }

    /// Read until `want` payload bytes have arrived, unframing as we go.
    async fn recv(&mut self, want: usize) -> std::io::Result<Vec<u8>> {
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
    async fn recv_control(&mut self) -> std::io::Result<(u8, Vec<u8>)> {
        let mut head = [0u8; 2];
        self.inner.read_exact(&mut head).await?;
        let length = (head[1] & 0x7f) as usize;
        let mut payload = vec![0u8; length];
        self.inner.read_exact(&mut payload).await?;
        Ok((head[0] & 0x0f, payload))
    }
}

// ------------------------------------------------------------- the two ends

async fn start_proxy() -> (std::net::SocketAddr, rustls::pki_types::CertificateDer<'static>) {
    let identity = tls::self_signed(&["localhost"]).unwrap();
    let cert = identity.cert_chain[0].clone();
    let server = tls::server_config(identity).unwrap();
    let table = Arc::new(dashmap::DashMap::new());
    let registry = Arc::new(Registry::open(None).unwrap());
    let pool = Arc::new(Pool::new(table.clone(), 8));
    let edge = Arc::new(Edge { pool, registry, tls: server, table });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let private = noise::generate_keypair().unwrap().0;
    tokio::spawn(async move {
        let _ = dsh_proxy::run_edge(
            listener,
            Arc::new(private),
            dsh_proxy::Limits::default(),
            edge,
        )
        .await;
    });
    (addr, cert)
}

async fn write_lp(socket: &mut TcpStream, body: &[u8]) {
    let mut out = Vec::with_capacity(body.len() + 2);
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    socket.write_all(&out).await.unwrap();
}

async fn read_lp(socket: &mut TcpStream) -> Vec<u8> {
    let mut len = [0u8; 2];
    socket.read_exact(&mut len).await.unwrap();
    let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
    socket.read_exact(&mut body).await.unwrap();
    body
}

/// A bridge that answers Noise_IK and echoes HTTP, exactly as the Mac does.
async fn attach(addr: std::net::SocketAddr) -> [u8; 32] {
    let (private, public) = noise::generate_keypair().unwrap();
    let mut socket = TcpStream::connect(addr).await.unwrap();
    socket.set_nodelay(true).unwrap();
    let head = preamble(&MAGIC_BRIDGE, &[0u8; 32]);
    socket.write_all(&head).await.unwrap();
    let mut handshake = snow::Builder::new(dsh_proxy::wire::NOISE_XX.parse().unwrap())
        .local_private_key(&private)
        .prologue(&head)
        .build_initiator()
        .unwrap();
    let mut buf = vec![0u8; 65535];
    let n = handshake.write_message(&[], &mut buf).unwrap();
    write_lp(&mut socket, &buf[..n]).await;
    let msg2 = read_lp(&mut socket).await;
    handshake.read_message(&msg2, &mut buf).unwrap();
    let n = handshake.write_message(&[], &mut buf).unwrap();
    write_lp(&mut socket, &buf[..n]).await;
    let transport = handshake.into_stateless_transport_mode().unwrap();

    let (decoder, encoder) = noise::codecs(transport);
    let (reader, writer) = socket.into_split();
    let (session, _done) = MuxSession::start(
        FramedRead::new(reader, decoder),
        FramedWrite::new(writer, encoder),
        64,
    );
    let bridge_private = private.clone();
    session.on_open(move |tx, rx| {
        let private = bridge_private.clone();
        tokio::spawn(async move {
            let mut io = MuxStreamIo::new(tx, rx);
            let mut head = [0u8; HEAD_LEN];
            if io.read_exact(&mut head).await.is_err() || head[..4] != MAGIC_CLIENT {
                return;
            }
            let Ok((_device, _token, transport)) =
                noise::ik_respond(&mut io, &private, &head).await
            else {
                return;
            };
            let stream = NoiseStream::new(io, transport);
            async fn echo(
                req: Request<Incoming>,
            ) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
                let bytes = req.into_body().collect().await.unwrap().to_bytes();
                Ok(Response::new(Full::new(bytes)))
            }
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service_fn(echo))
                .await;
        });
    });
    Box::leak(Box::new(session));
    tokio::time::sleep(Duration::from_millis(150)).await;
    public.try_into().unwrap()
}

/// Open the pipe: TLS, then the upgrade, leaving a byte stream behind.
async fn open_pipe(
    addr: std::net::SocketAddr,
    cert: &rustls::pki_types::CertificateDer<'static>,
    chunk: usize,
) -> WsClient<tokio_rustls::client::TlsStream<TcpStream>> {
    let connector = tokio_rustls::TlsConnector::from(tls::client_config_trusting(cert.clone()));
    let socket = TcpStream::connect(addr).await.unwrap();
    socket.set_nodelay(true).unwrap();
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls = connector.connect(name, socket).await.unwrap();
    let request = "GET /tunnel HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\n\
                   Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\
                   Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
    tls.write_all(request.as_bytes()).await.unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        tls.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&head);
    assert!(text.starts_with("HTTP/1.1 101"), "no 101: {text}");
    // RFC 6455's accept value for the fixed key above.
    assert!(
        text.to_ascii_lowercase().contains("s3pplmbitxaq9kygzzhzrbk+xoo="),
        "wrong Sec-WebSocket-Accept: {text}"
    );
    WsClient { inner: tls, plain: Vec::new(), chunk }
}

/// Drive one HTTP request through Noise, inside the pipe.
async fn call(
    pipe: &mut WsClient<tokio_rustls::client::TlsStream<TcpStream>>,
    transport: &snow::StatelessTransportState,
    nonce: &mut u64,
    in_nonce: &mut u64,
    body: &[u8],
) -> Vec<u8> {
    let request = format!(
        "POST /api/session/echo HTTP/1.1\r\nhost: mobile.dsh\r\n\
         content-type: application/octet-stream\r\ncontent-length: {}\r\n\r\n",
        body.len()
    );
    let mut plain = request.into_bytes();
    plain.extend_from_slice(body);
    // One Noise message, length-prefixed, exactly as NoiseStream frames it.
    let mut sealed = vec![0u8; plain.len() + 16];
    let n = transport.write_message(*nonce, &plain, &mut sealed).unwrap();
    *nonce += 1;
    let mut framed = Vec::with_capacity(n + 2);
    framed.extend_from_slice(&(n as u16).to_be_bytes());
    framed.extend_from_slice(&sealed[..n]);
    pipe.send(&framed).await.unwrap();

    let length = pipe.recv(2).await.unwrap();
    let length = u16::from_be_bytes([length[0], length[1]]) as usize;
    let ciphertext = pipe.recv(length).await.unwrap();
    let mut opened = vec![0u8; length];
    let n = transport
        .read_message(*in_nonce, &ciphertext, &mut opened)
        .unwrap();
    *in_nonce += 1;
    opened.truncate(n);
    opened
}

/// The whole contract in one path: WSS in, Noise_IK end to end, HTTP inside.
#[tokio::test]
async fn a_websocket_carries_an_end_to_end_noise_session() {
    let (addr, cert) = start_proxy().await;
    let bridge_key = attach(addr).await;
    let mut pipe = open_pipe(addr, &cert, 64 * 1024).await;

    let head = preamble(&MAGIC_CLIENT, &bridge_key);
    pipe.send(&head).await.unwrap();

    let (device_private, _) = noise::generate_keypair().unwrap();
    let mut handshake = snow::Builder::new(dsh_proxy::wire::NOISE_IK.parse().unwrap())
        .local_private_key(&device_private)
        .remote_public_key(&bridge_key)
        .prologue(&head)
        .build_initiator()
        .unwrap();
    let mut buf = vec![0u8; 1024];
    let n = handshake.write_message(&[], &mut buf).unwrap();
    let mut framed = Vec::new();
    framed.extend_from_slice(&(n as u16).to_be_bytes());
    framed.extend_from_slice(&buf[..n]);
    pipe.send(&framed).await.unwrap();

    let length = pipe.recv(2).await.unwrap();
    let length = u16::from_be_bytes([length[0], length[1]]) as usize;
    let msg2 = pipe.recv(length).await.unwrap();
    handshake.read_message(&msg2, &mut buf).unwrap();
    let transport = handshake.into_stateless_transport_mode().unwrap();

    let mut out_nonce = 0u64;
    let mut in_nonce = 0u64;
    let response = call(&mut pipe, &transport, &mut out_nonce, &mut in_nonce, b"hello").await;
    let text = String::from_utf8_lossy(&response);
    assert!(text.starts_with("HTTP/1.1 200"), "unexpected reply: {text}");
    assert!(text.ends_with("hello"), "body not echoed: {text}");
}

/// A mini-program sends small frames; the pipe must reassemble a stream from
/// them without caring where the boundaries fell.
#[tokio::test]
async fn a_preamble_split_across_frames_still_routes() {
    let (addr, cert) = start_proxy().await;
    let bridge_key = attach(addr).await;
    // Seven bytes per frame: the 37-byte preamble spans six of them.
    let mut pipe = open_pipe(addr, &cert, 7).await;

    let head = preamble(&MAGIC_CLIENT, &bridge_key);
    pipe.send(&head).await.unwrap();

    let (device_private, _) = noise::generate_keypair().unwrap();
    let mut handshake = snow::Builder::new(dsh_proxy::wire::NOISE_IK.parse().unwrap())
        .local_private_key(&device_private)
        .remote_public_key(&bridge_key)
        .prologue(&head)
        .build_initiator()
        .unwrap();
    let mut buf = vec![0u8; 1024];
    let n = handshake.write_message(&[], &mut buf).unwrap();
    let mut framed = Vec::new();
    framed.extend_from_slice(&(n as u16).to_be_bytes());
    framed.extend_from_slice(&buf[..n]);
    pipe.send(&framed).await.unwrap();

    let length = pipe.recv(2).await.unwrap();
    let length = u16::from_be_bytes([length[0], length[1]]) as usize;
    let msg2 = pipe.recv(length).await.unwrap();
    handshake.read_message(&msg2, &mut buf).unwrap();
    let transport = handshake.into_stateless_transport_mode().unwrap();

    let mut out_nonce = 0u64;
    let mut in_nonce = 0u64;
    let response = call(&mut pipe, &transport, &mut out_nonce, &mut in_nonce, b"split").await;
    assert!(String::from_utf8_lossy(&response).ends_with("split"));
}

/// Keepalive must be answered, or a mini-program's socket dies quietly.
#[tokio::test]
async fn a_ping_is_answered_with_a_pong() {
    let (addr, cert) = start_proxy().await;
    let _ = attach(addr).await;
    let mut pipe = open_pipe(addr, &cert, 4096).await;
    pipe.ping(b"alive").await.unwrap();
    let (opcode, payload) = tokio::time::timeout(Duration::from_secs(5), pipe.recv_control())
        .await
        .expect("no pong")
        .unwrap();
    assert_eq!(opcode, 0xa, "expected a pong");
    assert_eq!(payload, b"alive");
}

/// An unknown bridge key is dropped without a word, as it always was.
#[tokio::test]
async fn an_unknown_bridge_key_is_dropped() {
    let (addr, cert) = start_proxy().await;
    let _ = attach(addr).await;
    let mut pipe = open_pipe(addr, &cert, 4096).await;
    pipe.send(&preamble(&MAGIC_CLIENT, &[9u8; 32])).await.unwrap();
    pipe.send(b"anything").await.unwrap();
    let outcome = tokio::time::timeout(Duration::from_secs(3), pipe.recv(1)).await;
    match outcome {
        Err(_) => {}
        Ok(result) => assert!(result.is_err(), "an unknown key must get nothing back"),
    }
}
