//! End-to-end tests for the unified TLS edge.
//!
//! Each test plays both ends: a bridge speaking the existing bridge protocol
//! (Noise_XX to register, one Noise_IK per client stream, then plain HTTP) and
//! a client speaking the new contract (TLS, bearer token, /api).

use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
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

/// A proxy with a self-signed certificate; returns its address and the leaf,
/// which the client trusts directly.
async fn start_edge() -> (std::net::SocketAddr, rustls::pki_types::CertificateDer<'static>) {
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

/// What the fake bridge does with one client stream.
#[derive(Clone, Copy)]
enum Behaviour {
    Echo,
    Upgrade,
}

struct Bridge {
    key: [u8; 32],
    accepted: Arc<tokio::sync::Mutex<Vec<Vec<u8>>>>,
}

impl Bridge {
    async fn accepted(&self) -> usize {
        self.accepted.lock().await.len()
    }
}

/// Attach a bridge to the proxy; returns its routing key.
async fn attach(addr: std::net::SocketAddr, behaviour: Behaviour) -> Bridge {
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
    let accepted: Arc<tokio::sync::Mutex<Vec<Vec<u8>>>> =
        Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let seen = accepted.clone();
    let bridge_private = private.clone();
    session.on_open(move |tx, rx| {
        let private = bridge_private.clone();
        let seen = seen.clone();
        let upgrade = matches!(behaviour, Behaviour::Upgrade);
        tokio::spawn(async move {
            let mut io = MuxStreamIo::new(tx, rx);
            let mut head = [0u8; HEAD_LEN];
            if io.read_exact(&mut head).await.is_err() || head[..4] != MAGIC_CLIENT {
                return;
            }
            let Ok((device, _token, transport)) =
                noise::ik_respond(&mut io, &private, &head).await
            else {
                return;
            };
            seen.lock().await.push(device.to_vec());
            let stream = NoiseStream::new(io, transport);
            if upgrade {
                serve_upgrade(stream).await;
            } else {
                serve_echo(stream).await;
            }
        });
    });
    // Keep the session alive for the test's lifetime.
    Box::leak(Box::new(session));
    let key: [u8; 32] = public.try_into().unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;
    Bridge { key, accepted }
}

/// Plain HTTP echo, for /api calls.
async fn serve_echo<IO>(io: IO)
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    async fn inner(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
        let bytes = req.into_body().collect().await.unwrap().to_bytes();
        Ok(Response::new(Full::new(bytes)))
    }
    let _ = hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(io), service_fn(inner))
        .await;
}

/// Answer the upgrade with 101, then echo raw bytes over the spliced stream.
async fn serve_upgrade<IO>(io: IO)
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    async fn inner(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
        let upgraded = hyper::upgrade::on(req);
        tokio::spawn(async move {
            if let Ok(upgraded) = upgraded.await {
                let mut stream = TokioIo::new(upgraded);
                let mut buffer = [0u8; 4096];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            // The tunnel buffers until flushed, exactly as a
                            // real bridge's socket would not.
                            if stream.write_all(&buffer[..n]).await.is_err() {
                                break;
                            }
                            if stream.flush().await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        });
        Ok(Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header("connection", "Upgrade")
            .header("upgrade", "websocket")
            .body(Full::new(Bytes::new()))
            .unwrap())
    }
    let _ = hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(io), service_fn(inner))
        .with_upgrades()
        .await;
}

/// One HTTPS client connection to the proxy.
async fn connect_client(
    addr: std::net::SocketAddr,
    cert: &rustls::pki_types::CertificateDer<'static>,
) -> hyper::client::conn::http1::SendRequest<Full<Bytes>> {
    let connector = tokio_rustls::TlsConnector::from(tls::client_config_trusting(cert.clone()));
    let socket = TcpStream::connect(addr).await.unwrap();
    socket.set_nodelay(true).unwrap();
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let tls = connector.connect(name, socket).await.unwrap();
    let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    sender
}

/// Pair one installation over TLS and return the bearer token.
async fn pair(
    addr: std::net::SocketAddr,
    cert: &rustls::pki_types::CertificateDer<'static>,
    key: [u8; 32],
) -> String {
    let mut sender = connect_client(addr, cert).await;
    let body = format!(
        "{{\"bridgeKey\":\"{}\",\"pairingToken\":\"{}\",\"name\":\"test\"}}",
        B64.encode(key),
        B64.encode([7u8; 32]),
    );
    let request = Request::builder()
        .method(Method::POST)
        .uri("/pair")
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK, "pairing failed");
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    parsed["token"].as_str().unwrap().to_string()
}

fn api(path: &str, token: &str, body: Bytes) -> Request<Full<Bytes>> {
    Request::builder()
        .method(Method::POST)
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/octet-stream")
        .body(Full::new(body))
        .unwrap()
}

#[tokio::test]
async fn pairing_mints_a_token_that_reaches_the_bridge() {
    let (addr, cert) = start_edge().await;
    let bridge = attach(addr, Behaviour::Echo).await;
    let token = pair(addr, &cert, bridge.key).await;
    assert!(!token.is_empty());
    assert_eq!(bridge.accepted().await, 1);
}

#[tokio::test]
async fn unknown_token_is_refused() {
    let (addr, cert) = start_edge().await;
    let bridge = attach(addr, Behaviour::Echo).await;
    let _ = bridge;
    let mut sender = connect_client(addr, &cert).await;
    let response = sender
        .send_request(api("/api/echo", "not-a-real-token", Bytes::from_static(b"x")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn api_call_round_trips_over_the_tunnel() {
    let (addr, cert) = start_edge().await;
    let bridge = attach(addr, Behaviour::Echo).await;
    let token = pair(addr, &cert, bridge.key).await;
    let mut sender = connect_client(addr, &cert).await;
    let response = sender
        .send_request(api("/api/echo", &token, Bytes::from_static(b"hello tunnel")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&bytes[..], b"hello tunnel");
}

/// A body larger than one 256 KiB window only completes if the edge returns
/// receive credit; without it the transfer stalls after the first window.
#[tokio::test]
async fn bulk_beyond_one_window_completes() {
    let (addr, cert) = start_edge().await;
    let bridge = attach(addr, Behaviour::Echo).await;
    let token = pair(addr, &cert, bridge.key).await;
    let mut sender = connect_client(addr, &cert).await;
    let payload: Vec<u8> = (0..768 * 1024).map(|i| (i % 251) as u8).collect();
    let response = sender
        .send_request(api("/api/session.uploadFileBinary", &token, Bytes::from(payload.clone())))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(bytes.len(), payload.len());
    assert_eq!(&bytes[..], &payload[..]);
}

/// The upgrade is spliced, not parsed: after 101 the proxy copies bytes.
#[tokio::test]
async fn websocket_upgrade_is_spliced_to_the_bridge() {
    let (addr, cert) = start_edge().await;
    let bridge = attach(addr, Behaviour::Upgrade).await;
    let token = pair(addr, &cert, bridge.key).await;

    let connector = tokio_rustls::TlsConnector::from(tls::client_config_trusting(cert.clone()));
    let socket = TcpStream::connect(addr).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls = connector.connect(name, socket).await.unwrap();
    let request = format!(
        "GET /api/remote.mux HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\n\
         Upgrade: websocket\r\nAuthorization: Bearer {token}\r\n\
         Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
    );
    tls.write_all(request.as_bytes()).await.unwrap();

    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        tls.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&head);
    assert!(text.starts_with("HTTP/1.1 101"), "no 101: {text}");

    tls.write_all(b"spliced bytes").await.unwrap();
    let mut echoed = [0u8; 13];
    tokio::time::timeout(Duration::from_secs(10), tls.read_exact(&mut echoed))
        .await
        .expect("splice timed out")
        .unwrap();
    assert_eq!(&echoed, b"spliced bytes");
}

/// The proxy knows no socket route names: any /api upgrade is spliced, so the
/// bridge can add a socket (the RPC pipe) without a proxy change.
#[tokio::test]
async fn any_api_upgrade_is_spliced_not_just_the_known_one() {
    let (addr, cert) = start_edge().await;
    let bridge = attach(addr, Behaviour::Upgrade).await;
    let token = pair(addr, &cert, bridge.key).await;

    let connector = tokio_rustls::TlsConnector::from(tls::client_config_trusting(cert.clone()));
    let socket = TcpStream::connect(addr).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls = connector.connect(name, socket).await.unwrap();
    // A route the proxy has never heard of.
    let request = format!(
        "GET /api/rpc.mux HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\n\
         Upgrade: websocket\r\nAuthorization: Bearer {token}\r\n\
         Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
    );
    tls.write_all(request.as_bytes()).await.unwrap();

    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        tls.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&head);
    assert!(text.starts_with("HTTP/1.1 101"), "no 101: {text}");

    tls.write_all(b"rpc frame").await.unwrap();
    let mut echoed = [0u8; 9];
    tokio::time::timeout(Duration::from_secs(10), tls.read_exact(&mut echoed))
        .await
        .expect("splice timed out")
        .unwrap();
    assert_eq!(&echoed, b"rpc frame");
}

/// An RPC call parks its tunnel for reuse; a bulk route does not, so a file
/// transfer never leaves a large-buffered tunnel sitting in the idle pool.
///
/// Counting tunnels the bridge accepted is the probe, and the telling step is
/// the last one: an RPC after a bulk call has to build a tunnel, because the
/// bulk call closed the one it borrowed instead of parking it.
#[tokio::test]
async fn bulk_routes_do_not_park_their_tunnel() {
    let (addr, cert) = start_edge().await;
    let bridge = attach(addr, Behaviour::Echo).await;
    let token = pair(addr, &cert, bridge.key).await;
    let mut sender = connect_client(addr, &cert).await;

    async fn call(
        sender: &mut hyper::client::conn::http1::SendRequest<Full<Bytes>>,
        token: &str,
        path: &str,
    ) {
        let response = sender
            .send_request(api(path, token, Bytes::from_static(b"x")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        let _ = response.into_body().collect().await.unwrap();
        // The lease returns when the response body is dropped, one task hop
        // after `collect` resolves.
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    call(&mut sender, &token, "/api/session/echo").await;
    let after_first = bridge.accepted().await;

    call(&mut sender, &token, "/api/session/echo").await;
    assert_eq!(
        bridge.accepted().await,
        after_first,
        "a second RPC must reuse the parked tunnel"
    );

    call(&mut sender, &token, "/api/session/uploadFileBinary").await;
    assert_eq!(
        bridge.accepted().await,
        after_first,
        "a bulk call may borrow a parked tunnel"
    );

    call(&mut sender, &token, "/api/session/echo").await;
    assert_eq!(
        bridge.accepted().await,
        after_first + 1,
        "the bulk call must have closed the tunnel rather than parking it"
    );
}

/// Regression: a transport message that arrives complete in one burst and then
/// leaves the socket quiet must still be readable.
///
/// hyper writes head and body in a single `write`, so a near-64 KiB request
/// lands as one maximum-size Noise message followed by a small one. If the
/// reader asks for more ciphertext while a complete message already sits in
/// `incoming`, the request hangs until the deadline.
#[tokio::test]
async fn a_complete_buffered_message_is_read_without_more_ciphertext() {
    use dsh_proxy::wire::{MAX_NOISE_MSG, TAG_LEN};

    let max_plain = MAX_NOISE_MSG - TAG_LEN;
    let (client_private, _) = noise::generate_keypair().unwrap();
    let (bridge_private, bridge_public) = noise::generate_keypair().unwrap();
    let prologue = preamble(&MAGIC_CLIENT, &[3u8; 32]);

    let (client_socket, server_socket) = tokio::io::duplex(64 * 1024);
    let payload: Vec<u8> = (0..max_plain + 64).map(|i| (i % 251) as u8).collect();
    let expected = payload.clone();
    let prologue_for_bridge = prologue.clone();
    let bridge = tokio::spawn(async move {
        let mut socket = server_socket;
        let (_, first, transport) =
            noise::ik_respond(&mut socket, &bridge_private, &prologue_for_bridge)
                .await
                .unwrap();
        assert!(first.is_empty());
        let mut stream = NoiseStream::new(socket, transport);
        let mut got = vec![0u8; expected.len()];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(got, expected);
        stream.write_all(b"ok").await.unwrap();
        stream.flush().await.unwrap();
    });

    let mut socket = client_socket;
    let transport = noise::ik_initiate(
        &mut socket,
        &client_private,
        &bridge_public,
        &prologue,
        &[],
    )
    .await
    .unwrap();
    let mut stream = NoiseStream::new(socket, transport);
    // One write larger than one message: exactly the shape hyper produces.
    stream.write_all(&payload).await.unwrap();
    stream.flush().await.unwrap();
    let mut ack = [0u8; 2];
    stream.read_exact(&mut ack).await.unwrap();
    assert_eq!(&ack, b"ok");
    bridge.await.unwrap();
}

