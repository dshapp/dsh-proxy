//! Loopback benchmark harness: one real bridge and one real client per run.
//!
//! The bridge always speaks the *existing* protocol (Noise_XX to register,
//! then one Noise_IK per client stream, then plain HTTP), because that is the
//! point of the change: the bridge does not move, only the client edge does.
//!
//!   old  client: raw TCP + DSHC preamble + Noise_IK   (the phone did crypto)
//!   new  client: TLS + bearer token, proxy does Noise_IK on its behalf
//!
//! Run against a proxy that is already listening:
//!
//!   harness --mode old --proxy 127.0.0.1:9443 --scenario latency
//!   harness --mode new --proxy 127.0.0.1:9443 --scenario throughput --size 262144

use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::codec::{FramedRead, FramedWrite};

use dsh_proxy::mux::{MuxSession, MuxStreamIo};
use dsh_proxy::noise;
use dsh_proxy::tunnel::NoiseStream;
use dsh_proxy::wire::{HEAD_LEN, MAGIC_BRIDGE, MAGIC_CLIENT, VERSION};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type Sender = hyper::client::conn::http1::SendRequest<Full<Bytes>>;

fn fail(message: impl std::fmt::Display) -> BoxError {
    Box::new(std::io::Error::new(std::io::ErrorKind::Other, message.to_string()))
}

fn preamble(magic: &[u8; 4], key: &[u8; 32]) -> Vec<u8> {
    let mut head = Vec::with_capacity(HEAD_LEN);
    head.extend_from_slice(magic);
    head.push(VERSION);
    head.extend_from_slice(key);
    head
}

/// The one bridge endpoint every scenario calls: echo the body back.
async fn echo(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, BoxError> {
    let bytes = req.into_body().collect().await?.to_bytes();
    Ok(Response::new(Full::new(bytes)))
}

/// The same endpoint reached the other way: answer 101 and then echo
/// `[u32 len][payload]` frames on the raw upgraded stream. This is what a
/// client gets when it opens one WSS pipe instead of one HTTP call per RPC.
async fn bridge_service(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, BoxError> {
    if req.headers().get(hyper::header::UPGRADE).is_none() {
        return echo(req).await;
    }
    let upgraded = hyper::upgrade::on(req);
    tokio::spawn(async move {
        let Ok(upgraded) = upgraded.await else { return };
        let mut stream = TokioIo::new(upgraded);
        let mut head = [0u8; 4];
        loop {
            if stream.read_exact(&mut head).await.is_err() {
                return;
            }
            let mut body = vec![0u8; u32::from_be_bytes(head) as usize];
            if stream.read_exact(&mut body).await.is_err() {
                return;
            }
            let mut out = Vec::with_capacity(4 + body.len());
            out.extend_from_slice(&head);
            out.extend_from_slice(&body);
            if stream.write_all(&out).await.is_err() || stream.flush().await.is_err() {
                return;
            }
        }
    });
    Ok(Response::builder()
        .status(101)
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .body(Full::new(Bytes::new()))?)
}

async fn serve_http<IO>(io: IO)
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if let Err(error) = hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(io), service_fn(bridge_service))
        .with_upgrades()
        .await
    {
        eprintln!("bridge: serve_connection ended: {error}");
    }
}

/// Attach a bridge to the proxy and return its routing key.
async fn attach_bridge(proxy: &str) -> Result<[u8; 32], BoxError> {
    let (private, public) = noise::generate_keypair()?;
    let mut socket = TcpStream::connect(proxy).await?;
    socket.set_nodelay(true)?;
    let head = preamble(&MAGIC_BRIDGE, &[0u8; 32]);
    socket.write_all(&head).await?;

    let mut handshake = snow::Builder::new(dsh_proxy::wire::NOISE_XX.parse()?)
        .local_private_key(&private)
        .prologue(&head)
        .build_initiator()?;
    let mut buf = vec![0u8; 65535];
    let n = handshake.write_message(&[], &mut buf)?;
    write_lp(&mut socket, &buf[..n]).await?;
    let msg2 = read_lp(&mut socket).await?;
    handshake.read_message(&msg2, &mut buf)?;
    let n = handshake.write_message(&[], &mut buf)?;
    write_lp(&mut socket, &buf[..n]).await?;
    let transport = handshake.into_stateless_transport_mode()?;

    let (decoder, encoder) = noise::codecs(transport);
    let (reader, writer) = socket.into_split();
    let (session, _done) = MuxSession::start(
        FramedRead::new(reader, decoder),
        FramedWrite::new(writer, encoder),
        2048,
    );
    // Every stream the proxy opens is one client: read its preamble, answer
    // IK as the device would see it, then serve plain HTTP on the sealed
    // stream. This is the bridge's real code path, not a shortcut.
    session.on_open(move |tx, rx| {
        let private = private.clone();
        tokio::spawn(async move {
            let mut io = MuxStreamIo::new(tx, rx);
            let mut head = [0u8; HEAD_LEN];
            if let Err(error) = io.read_exact(&mut head).await {
                eprintln!("bridge: preamble read failed: {error}");
                return;
            }
            if head[..4] != MAGIC_CLIENT {
                eprintln!("bridge: bad preamble magic");
                return;
            }
            // EXPERIMENT: with the inner layer removed the bridge trusts the
            // Noise_XX link it already authenticated, and reads HTTP directly.
            if dsh_proxy::phone::plain_tunnels() {
                serve_http(io).await;
                return;
            }
            let (_device, _token, transport) = match noise::ik_respond(&mut io, &private, &head).await {
                Ok(result) => result,
                Err(error) => {
                    eprintln!("bridge: ik_respond failed: {error}");
                    return;
                }
            };
            serve_http(NoiseStream::new(io, transport)).await;
        });
    });

    let key: [u8; 32] = public.try_into().map_err(|_| fail("bad bridge key"))?;
    Ok(key)
}

async fn write_lp(socket: &mut TcpStream, body: &[u8]) -> Result<(), BoxError> {
    let mut out = Vec::with_capacity(body.len() + 2);
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    socket.write_all(&out).await?;
    Ok(())
}

async fn read_lp(socket: &mut TcpStream) -> Result<Vec<u8>, BoxError> {
    let mut len = [0u8; 2];
    socket.read_exact(&mut len).await?;
    let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
    socket.read_exact(&mut body).await?;
    Ok(body)
}

// ------------------------------------------------------------- old-era client

async fn old_connect(proxy: &str, key: [u8; 32]) -> Result<Sender, BoxError> {
    let (private, _) = noise::generate_keypair()?;
    let mut socket = TcpStream::connect(proxy).await?;
    socket.set_nodelay(true)?;
    let head = preamble(&MAGIC_CLIENT, &key);
    socket.write_all(&head).await?;
    let transport = noise::ik_initiate(&mut socket, &private, &key, &head, &[]).await?;
    let (sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(NoiseStream::new(socket, transport)))
            .await?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            eprintln!("client: connection ended: {error}");
        }
    });
    Ok(sender)
}

// ------------------------------------------------------------- new-era client

/// Accepts the development certificate; production verifies it normally.
#[derive(Debug)]
struct TrustAny(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for TrustAny {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("ring supports the defaults")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TrustAny(provider)))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

/// Open one TLS connection. The token rides each request, not the socket.
async fn new_connect(proxy: &str, _token: &str) -> Result<Sender, BoxError> {
    let connector = tokio_rustls::TlsConnector::from(tls_config());
    let socket = TcpStream::connect(proxy).await?;
    socket.set_nodelay(true)?;
    let name = rustls::pki_types::ServerName::try_from("localhost")?;
    let tls = connector.connect(name, socket).await?;
    let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            eprintln!("client: connection ended: {error}");
        }
    });
    Ok(sender)
}

/// Pair once and return the bearer token the client uses thereafter.
async fn pair(proxy: &str, key: [u8; 32]) -> Result<String, BoxError> {
    let mut sender = new_connect(proxy, "").await?;
    let body = format!(
        "{{\"bridgeKey\":\"{}\",\"name\":\"bench\"}}",
        B64.encode(key)
    );
    let request = Request::builder()
        .method(Method::POST)
        .uri("/pair")
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))?;
    let response = sender.send_request(request).await?;
    let status = response.status();
    let bytes = response.into_body().collect().await?.to_bytes();
    if !status.is_success() {
        return Err(fail(format!(
            "pair failed {status}: {}",
            String::from_utf8_lossy(&bytes)
        )));
    }
    let parsed: serde_json::Value = serde_json::from_slice(&bytes)?;
    Ok(parsed["token"]
        .as_str()
        .ok_or_else(|| fail("pair returned no token"))?
        .to_string())
}

// ------------------------------------------------- new-era client, one WSS pipe

/// One upgraded TLS connection, used as a byte pipe.
type Spliced = tokio_rustls::client::TlsStream<TcpStream>;

/// Open the WSS pipe: TLS, then one upgrade handshake, then raw bytes.
///
/// After the 101 the proxy stops parsing anything: it copies bytes between
/// this socket and the bridge's mux stream. Every RPC afterwards costs the
/// proxy one copy, not one HTTP request cycle.
async fn spliced_connect(proxy: &str, token: &str) -> Result<Spliced, BoxError> {
    let connector = tokio_rustls::TlsConnector::from(tls_config());
    let socket = TcpStream::connect(proxy).await?;
    socket.set_nodelay(true)?;
    let name = rustls::pki_types::ServerName::try_from("localhost")?;
    let mut tls = connector.connect(name, socket).await?;
    let request = format!(
        "GET /api/remote.mux HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\n\
         Upgrade: websocket\r\nAuthorization: Bearer {token}\r\n\
         Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
    );
    tls.write_all(request.as_bytes()).await?;
    tls.flush().await?;
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        tls.read_exact(&mut byte).await?;
        head.push(byte[0]);
    }
    if !head.starts_with(b"HTTP/1.1 101") {
        return Err(fail(format!(
            "upgrade refused: {}",
            String::from_utf8_lossy(&head).lines().next().unwrap_or("")
        )));
    }
    Ok(tls)
}

/// One request/response over the pipe, framed by the client itself.
async fn pipe_round_trip(lane: &mut Spliced, payload: &[u8]) -> Result<usize, BoxError> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    lane.write_all(&out).await?;
    lane.flush().await?;
    let mut head = [0u8; 4];
    lane.read_exact(&mut head).await?;
    let mut body = vec![0u8; u32::from_be_bytes(head) as usize];
    lane.read_exact(&mut body).await?;
    Ok(body.len())
}

/// Same shape as `measure`, but every lane is a spliced WSS pipe.
async fn measure_spliced(proxy: &str, token: &str, scenario: &Scenario) -> Result<(), BoxError> {
    let lane_count = scenario.concurrency.max(1);
    let per_lane = scenario.requests.div_ceil(lane_count);
    let payload = vec![0x5au8; scenario.size.max(1)];

    let mut lanes = Vec::with_capacity(lane_count);
    for _ in 0..lane_count {
        lanes.push(spliced_connect(proxy, token).await?);
    }
    for lane in lanes.iter_mut() {
        pipe_round_trip(lane, b"warm").await?;
    }

    let started = Instant::now();
    let mut tasks = Vec::with_capacity(lane_count);
    for mut lane in lanes {
        let payload = payload.clone();
        tasks.push(tokio::spawn(async move {
            let mut latencies = Vec::with_capacity(per_lane);
            for _ in 0..per_lane {
                let at = Instant::now();
                let echoed = pipe_round_trip(&mut lane, &payload).await?;
                if echoed != payload.len() {
                    return Err(fail(format!("short echo {echoed}")));
                }
                latencies.push(at.elapsed());
            }
            Ok::<_, BoxError>(latencies)
        }));
    }
    let mut latencies = Vec::new();
    for task in tasks {
        latencies.extend(task.await??);
    }
    let elapsed = started.elapsed();
    latencies.sort();
    let pick = |p: f64| -> f64 {
        let index = ((latencies.len() as f64 - 1.0) * p).round() as usize;
        latencies[index].as_secs_f64() * 1000.0
    };
    let total = per_lane * lane_count;
    let mb_per_s = (scenario.size * total) as f64 / elapsed.as_secs_f64() / (1024.0 * 1024.0);
    println!(
        "{}",
        serde_json::json!({
            "mode": "spliced",
            "scenario": scenario.scenario,
            "requests": total,
            "size": scenario.size,
            "concurrency": lane_count,
            "elapsed_ms": (elapsed.as_secs_f64() * 1000.0).round(),
            "rps": (total as f64 / elapsed.as_secs_f64()).round(),
            "p50_ms": (pick(0.50) * 1000.0).round() / 1000.0,
            "p99_ms": (pick(0.99) * 1000.0).round() / 1000.0,
            "mb_per_s": (mb_per_s * 100.0).round() / 100.0,
        })
    );
    Ok(())
}

// -------------------------------------------------------------------- driver

struct Scenario {
    scenario: String,
    requests: usize,
    size: usize,
    /// Sockets driven at once. Each is its own connection, so this measures
    /// the per-connection cost the new edge adds.
    concurrency: usize,
}

/// Time `requests` round trips spread over `concurrency` connections.
async fn measure(
    label: &str,
    mut senders: Vec<Sender>,
    token: Option<&str>,
    scenario: &Scenario,
) -> Result<(), BoxError> {
    let payload = Bytes::from(vec![0x5au8; scenario.size.max(1)]);
    let path = if scenario.scenario == "throughput" {
        "/api/session.uploadFileBinary"
    } else {
        "/api/echo"
    };
    let build = |body: Bytes| -> Result<Request<Full<Bytes>>, BoxError> {
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header("content-type", "application/octet-stream");
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        Ok(builder.body(Full::new(body))?)
    };

    let lane_count = scenario.concurrency.max(1);
    let per_lane = scenario.requests.div_ceil(lane_count);
    let token = token.map(|value| value.to_string());
    let throughput = scenario.scenario == "throughput";

    // One untimed request per connection, so the TLS and Noise handshakes and
    // the first allocations are not folded into the numbers.
    for sender in senders.iter_mut() {
        let warm = sender.send_request(build(Bytes::from_static(b"warm"))?).await?;
        let _ = warm.into_body().collect().await?;
    }

    // Each lane is an independent connection, driven on its own task so the
    // proxy sees real concurrency rather than interleaved awaits on one flow.
    let started = Instant::now();
    let mut tasks = Vec::with_capacity(lane_count);
    for mut sender in senders {
        let payload = payload.clone();
        let token = token.clone();
        tasks.push(tokio::spawn(async move {
            let mut latencies = Vec::with_capacity(per_lane);
            for _ in 0..per_lane {
                let at = Instant::now();
                let body = if throughput { payload.clone() } else { Bytes::from_static(b"ping") };
                let mut builder = Request::builder()
                    .method(Method::POST)
                    .uri(if throughput { "/api/session.uploadFileBinary" } else { "/api/echo" })
                    .header("content-type", "application/octet-stream");
                if let Some(token) = &token {
                    builder = builder.header("authorization", format!("Bearer {token}"));
                }
                let response = sender.send_request(builder.body(Full::new(body))?).await?;
                let status = response.status();
                let bytes = response.into_body().collect().await?.to_bytes();
                if !status.is_success() {
                    return Err(fail(format!("request failed {status}")));
                }
                if !throughput && bytes.len() != 4 {
                    return Err(fail(format!("unexpected echo length {}", bytes.len())));
                }
                latencies.push(at.elapsed());
            }
            Ok::<_, BoxError>(latencies)
        }));
    }
    let mut latencies = Vec::new();
    for task in tasks {
        latencies.extend(task.await??);
    }
    let elapsed = started.elapsed();
    latencies.sort();
    let pick = |p: f64| -> f64 {
        let index = ((latencies.len() as f64 - 1.0) * p).round() as usize;
        latencies[index].as_secs_f64() * 1000.0
    };
    let total = per_lane * lane_count;
    let mb_per_s = if scenario.scenario == "throughput" {
        (scenario.size * total) as f64 / elapsed.as_secs_f64() / (1024.0 * 1024.0)
    } else {
        0.0
    };
    println!(
        "{}",
        serde_json::json!({
            "mode": label,
            "scenario": scenario.scenario,
            "requests": total,
            "size": scenario.size,
            "concurrency": lane_count,
            "elapsed_ms": (elapsed.as_secs_f64() * 1000.0).round(),
            "rps": (total as f64 / elapsed.as_secs_f64()).round(),
            "p50_ms": (pick(0.50) * 1000.0).round() / 1000.0,
            "p99_ms": (pick(0.99) * 1000.0).round() / 1000.0,
            "mb_per_s": (mb_per_s * 100.0).round() / 100.0,
            "concurrency_note": "mb_per_s counts echoed payload; uplink equals it",
        })
    );
    Ok(())
}

/// Time connection establishment alone: the new edge adds a TLS handshake
/// the old raw-TCP phone path never paid.
async fn measure_connect(
    label: &str,
    proxy: &str,
    key: [u8; 32],
    token: Option<&str>,
    count: usize,
) -> Result<(), BoxError> {
    let mut latencies = Vec::with_capacity(count);
    let started = Instant::now();
    for _ in 0..count {
        let at = Instant::now();
        match token {
            Some(token) => {
                let _ = new_connect(proxy, token).await?;
            }
            None => {
                let _ = old_connect(proxy, key).await?;
            }
        }
        latencies.push(at.elapsed());
    }
    let elapsed = started.elapsed();
    latencies.sort();
    let pick = |p: f64| -> f64 {
        let index = ((latencies.len() as f64 - 1.0) * p).round() as usize;
        latencies[index].as_secs_f64() * 1000.0
    };
    println!(
        "{}",
        serde_json::json!({
            "mode": label,
            "scenario": "connect",
            "connections": count,
            "elapsed_ms": (elapsed.as_secs_f64() * 1000.0).round(),
            "conn_per_s": (count as f64 / elapsed.as_secs_f64()).round(),
            "p50_ms": (pick(0.50) * 1000.0).round() / 1000.0,
            "p99_ms": (pick(0.99) * 1000.0).round() / 1000.0,
        })
    );
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let mut mode = String::from("new");
    let mut proxy = String::from("127.0.0.1:9443");
    let mut scenario = Scenario { scenario: "latency".into(), requests: 1000, size: 4, concurrency: 1 };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--mode" => mode = args.next().unwrap_or(mode),
            "--proxy" => proxy = args.next().unwrap_or(proxy),
            "--scenario" => scenario.scenario = args.next().unwrap_or(scenario.scenario),
            "--requests" => scenario.requests = args.next().unwrap_or_default().parse().unwrap_or(1000),
            "--size" => scenario.size = args.next().unwrap_or_default().parse().unwrap_or(4),
            "--concurrency" => {
                scenario.concurrency = args.next().unwrap_or_default().parse().unwrap_or(1)
            }
            other => return Err(fail(format!("unknown argument {other}"))),
        }
    }

    // The bridge must be registered before the client's first request: the
    // proxy routes by the key the XX handshake proved.
    let key = attach_bridge(&proxy).await?;
    tokio::time::sleep(Duration::from_millis(250)).await;

    let token = match mode.as_str() {
        "new" => Some(pair(&proxy, key).await?),
        "old" => None,
        other => return Err(fail(format!("unknown mode {other}"))),
    };
    if scenario.scenario == "connect" {
        return measure_connect(&mode, &proxy, key, token.as_deref(), scenario.requests).await;
    }
    if scenario.scenario == "spliced" {
        let token = token.ok_or_else(|| fail("the spliced pipe is a new-era contract"))?;
        return measure_spliced(&proxy, &token, &scenario).await;
    }
    let mut senders = Vec::with_capacity(scenario.concurrency);
    for _ in 0..scenario.concurrency.max(1) {
        let sender = match token.as_deref() {
            Some(token) => new_connect(&proxy, token).await?,
            None => old_connect(&proxy, key).await?,
        };
        senders.push(sender);
    }
    measure(&mode, senders, token.as_deref(), &scenario).await?;
    Ok(())
}
