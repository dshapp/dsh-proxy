//! Old era against new, on one loopback, with only the carrier different.
//!
//! Both columns run the same bridge, the same Noise_IK stack and the same
//! payloads. What differs is what carries the bytes: a bare TCP socket into
//! the 38c1eab proxy, or a WebSocket over TLS into this one. So the delta is
//! the carrier and the proxy that terminates it, and nothing else.
//!
//! Not a unit test - driven by env vars and run on demand:
//!   BENCH_MODE=old BENCH_PROXY=127.0.0.1:9000 cargo test --release --test bench -- --ignored --nocapture

use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::codec::{FramedRead, FramedWrite};

use dsh_proxy::mux::{MuxSession, MuxStreamIo};
use dsh_proxy::noise;
use dsh_proxy::wire::{HEAD_LEN, MAGIC_BRIDGE, MAGIC_CLIENT};

mod common;
use common::phone::{ik_initiate, ik_respond, NoiseStream};
use common::{preamble, wsio::WsClientStream};

fn env(name: &str, fallback: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| fallback.to_string())
}

fn number(name: &str, fallback: usize) -> usize {
    env(name, "").parse().unwrap_or(fallback)
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

/// The bridge, identical in both eras: Noise_XX to register, one Noise_IK per
/// stream, then a length-prefixed echo.
async fn attach_bridge(proxy: &str) -> [u8; 32] {
    let (private, public) = noise::generate_keypair().unwrap();
    let mut socket = TcpStream::connect(proxy).await.unwrap();
    socket.set_nodelay(true).unwrap();
    let head = preamble(&MAGIC_BRIDGE, 1, &[0u8; 32]);
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
        4096,
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
                ik_respond(&mut io, &private, &head).await
            else {
                return;
            };
            let mut stream = NoiseStream::new(io, transport);
            let mut length = [0u8; 4];
            loop {
                if stream.read_exact(&mut length).await.is_err() {
                    return;
                }
                let mut body = vec![0u8; u32::from_be_bytes(length) as usize];
                if stream.read_exact(&mut body).await.is_err() {
                    return;
                }
                let mut out = Vec::with_capacity(4 + body.len());
                out.extend_from_slice(&length);
                out.extend_from_slice(&body);
                if stream.write_all(&out).await.is_err() || stream.flush().await.is_err() {
                    return;
                }
            }
        });
    });
    Box::leak(Box::new(session));
    tokio::time::sleep(Duration::from_millis(250)).await;
    public.try_into().unwrap()
}

/// Accepts the development certificate; production verifies it normally.
#[derive(Debug)]
struct TrustAny(std::sync::Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for TrustAny {
    fn verify_server_cert(
        &self,
        _end: &rustls::pki_types::CertificateDer<'_>,
        _chain: &[rustls::pki_types::CertificateDer<'_>],
        _name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn tls_config() -> std::sync::Arc<rustls::ClientConfig> {
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(TrustAny(provider)))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    std::sync::Arc::new(config)
}

/// Whatever carries the phone's bytes this era.
enum Carrier {
    Tcp(NoiseStream<TcpStream>),
    Wss(NoiseStream<WsClientStream<tokio_rustls::client::TlsStream<TcpStream>>>),
}

impl Carrier {
    async fn round_trip(&mut self, payload: &[u8]) -> std::io::Result<usize> {
        match self {
            Carrier::Tcp(stream) => exchange(stream, payload).await,
            Carrier::Wss(stream) => exchange(stream, payload).await,
        }
    }
}

async fn exchange<S>(stream: &mut S, payload: &[u8]) -> std::io::Result<usize>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    stream.write_all(&out).await?;
    stream.flush().await?;
    let mut length = [0u8; 4];
    stream.read_exact(&mut length).await?;
    let mut body = vec![0u8; u32::from_be_bytes(length) as usize];
    stream.read_exact(&mut body).await?;
    Ok(body.len())
}

/// The old era: a bare TCP socket straight into the proxy.
async fn dial_old(proxy: &str, key: [u8; 32]) -> Carrier {
    let (private, _) = noise::generate_keypair().unwrap();
    let mut socket = TcpStream::connect(proxy).await.unwrap();
    socket.set_nodelay(true).unwrap();
    let head = preamble(&MAGIC_CLIENT, 1, &key);
    socket.write_all(&head).await.unwrap();
    let transport = ik_initiate(&mut socket, &private, &key, &head, &[]).await.unwrap();
    Carrier::Tcp(NoiseStream::new(socket, transport))
}

/// The new era: TLS, one upgrade, then the same bytes.
async fn dial_new(proxy: &str, key: [u8; 32]) -> Carrier {
    let connector = tokio_rustls::TlsConnector::from(tls_config());
    let socket = TcpStream::connect(proxy).await.unwrap();
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
    assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 101"));

    let mut stream = WsClientStream::new(tls);
    let (private, _) = noise::generate_keypair().unwrap();
    let preamble_bytes = preamble(&MAGIC_CLIENT, 1, &key);
    stream.write_all(&preamble_bytes).await.unwrap();
    stream.flush().await.unwrap();
    let transport = ik_initiate(&mut stream, &private, &key, &preamble_bytes, &[])
        .await
        .unwrap();
    Carrier::Wss(NoiseStream::new(stream, transport))
}

async fn dial(mode: &str, proxy: &str, key: [u8; 32]) -> Carrier {
    if mode == "old" { dial_old(proxy, key).await } else { dial_new(proxy, key).await }
}

fn report(mode: &str, scenario: &str, size: usize, lanes: usize, total: usize, elapsed: Duration, mut latencies: Vec<Duration>) {
    latencies.sort();
    let pick = |p: f64| -> f64 {
        let index = ((latencies.len() as f64 - 1.0) * p).round() as usize;
        latencies[index].as_secs_f64() * 1000.0
    };
    let seconds = elapsed.as_secs_f64();
    println!(
        "{}",
        serde_json::json!({
            "mode": mode,
            "scenario": scenario,
            "size": size,
            "concurrency": lanes,
            "requests": total,
            "elapsed_ms": (seconds * 1000.0).round(),
            "rps": (total as f64 / seconds).round(),
            "p50_ms": (pick(0.50) * 1000.0).round() / 1000.0,
            "p99_ms": (pick(0.99) * 1000.0).round() / 1000.0,
            "mb_per_s": (((size * total) as f64 / seconds / (1024.0 * 1024.0)) * 100.0).round() / 100.0,
        })
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn bench() {
    let mode = env("BENCH_MODE", "new");
    let proxy = env("BENCH_PROXY", "127.0.0.1:9000");
    let scenario = env("BENCH_SCENARIO", "latency");
    let requests = number("BENCH_REQUESTS", 2000);
    let size = number("BENCH_SIZE", 4);
    let lanes = number("BENCH_CONCURRENCY", 1).max(1);

    let key = attach_bridge(&proxy).await;

    if scenario == "connect" {
        let started = Instant::now();
        let mut latencies = Vec::with_capacity(requests);
        let mut held = Vec::new();
        for _ in 0..requests {
            let at = Instant::now();
            let mut carrier = dial(&mode, &proxy, key).await;
            // A tunnel is only real once a byte has been through it.
            carrier.round_trip(b"ping").await.unwrap();
            latencies.push(at.elapsed());
            held.push(carrier);
            if held.len() > 32 { held.remove(0); }
        }
        report(&mode, "connect", 0, 1, requests, started.elapsed(), latencies);
        return;
    }

    let per_lane = requests.div_ceil(lanes);
    let payload = vec![0x5au8; size.max(1)];

    let mut carriers = Vec::with_capacity(lanes);
    for _ in 0..lanes {
        let mut carrier = dial(&mode, &proxy, key).await;
        // One untimed exchange, so handshakes and first allocations are not
        // folded into the numbers.
        carrier.round_trip(&payload).await.unwrap();
        carriers.push(carrier);
    }

    let started = Instant::now();
    let mut tasks = Vec::with_capacity(lanes);
    for mut carrier in carriers {
        let payload = payload.clone();
        tasks.push(tokio::spawn(async move {
            let mut latencies = Vec::with_capacity(per_lane);
            for _ in 0..per_lane {
                let at = Instant::now();
                let echoed = carrier.round_trip(&payload).await.unwrap();
                assert_eq!(echoed, payload.len());
                latencies.push(at.elapsed());
            }
            latencies
        }));
    }
    let mut latencies = Vec::new();
    for task in tasks {
        latencies.extend(task.await.unwrap());
    }
    report(&mode, &scenario, size, lanes, per_lane * lanes, started.elapsed(), latencies);
}
