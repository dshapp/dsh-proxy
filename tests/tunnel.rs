//! End-to-end tests over real loopback sockets.
//!
//! The bridge here is written against PROTOCOL.md on purpose: it uses snow's
//! stateful `TransportState` and hand-rolled framing, so it is an independent
//! implementation of the peer. If the proxy's stateless nonce handling or its
//! batched window accounting ever drifted, these would fail.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const PARAMS: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
const MAX_PAYLOAD: usize = 16384;
const WINDOW: u32 = 256 * 1024;
const KIND_OPEN: u8 = 0;
const KIND_DATA: u8 = 1;
const KIND_CLOSE: u8 = 2;
const KIND_WINDOW: u8 = 3;

fn preamble(magic: &[u8; 4], version: u8, key: &[u8]) -> Vec<u8> {
    let mut head = Vec::with_capacity(37);
    head.extend_from_slice(magic);
    head.push(version);
    head.extend_from_slice(key);
    head
}

async fn start_proxy() -> SocketAddr {
    start_proxy_with(dsh_proxy::Limits::default()).await
}

/// A proxy with explicit admission limits, for the tests that need small ones.
async fn start_proxy_with(limits: dsh_proxy::Limits) -> SocketAddr {
    let (private, _) = dsh_proxy::noise::generate_keypair().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = dsh_proxy::run(listener, Arc::new(private), limits).await;
    });
    addr
}

/// A bridge that echoes every byte of every stream back to its phone.
struct EchoBridge {
    socket: TcpStream,
    transport: snow::TransportState,
    /// Credit we hold for sending, per protocol one window per stream.
    credit: u32,
    queue: VecDeque<(u32, Vec<u8>)>,
}

impl EchoBridge {
    async fn connect(addr: SocketAddr, private: &[u8]) -> Self {
        let head = preamble(b"DSHB", 1, &[0u8; 32]);
        let mut socket = TcpStream::connect(addr).await.unwrap();
        socket.write_all(&head).await.unwrap();

        let mut hs = snow::Builder::new(PARAMS.parse().unwrap())
            .local_private_key(private)
            .prologue(&head)
            .build_initiator()
            .unwrap();
        let mut buf = vec![0u8; 65535];

        let n = hs.write_message(&[], &mut buf).unwrap();
        write_lp(&mut socket, &buf[..n]).await;
        let msg2 = read_lp(&mut socket).await;
        hs.read_message(&msg2, &mut buf).unwrap();
        let n = hs.write_message(&[], &mut buf).unwrap();
        write_lp(&mut socket, &buf[..n]).await;

        let transport = hs.into_transport_mode().unwrap();
        Self { socket, transport, credit: WINDOW, queue: VecDeque::new() }
    }

    async fn send_frame(&mut self, id: u32, kind: u8, payload: &[u8]) {
        let sealed = seal_frame(&mut self.transport, id, kind, payload);
        write_lp(&mut self.socket, &sealed).await;
    }

    async fn read_frame(&mut self) -> Option<(u32, u8, Vec<u8>)> {
        let sealed = read_lp_opt(&mut self.socket).await?;
        let mut plain = vec![0u8; sealed.len()];
        let n = self.transport.read_message(&sealed, &mut plain).unwrap();
        plain.truncate(n);
        assert!(plain.len() >= 8, "short frame");
        let id = u32::from_be_bytes([plain[0], plain[1], plain[2], plain[3]]);
        let kind = plain[4];
        Some((id, kind, plain[8..].to_vec()))
    }

    /// Push queued echo bytes out while the proxy's window allows it.
    async fn drain(&mut self) {
        while let Some((id, body)) = self.queue.pop_front() {
            let take = body.len().min(MAX_PAYLOAD).min(self.credit as usize);
            if take == 0 {
                self.queue.push_front((id, body));
                return;
            }
            self.credit -= take as u32;
            self.send_frame(id, KIND_DATA, &body[..take]).await;
            if take < body.len() {
                self.queue.push_front((id, body[take..].to_vec()));
            }
        }
    }

    /// Run until the link dies.
    async fn run(mut self) {
        while let Some((id, kind, body)) = self.read_frame().await {
            match kind {
                KIND_OPEN => {}
                KIND_DATA if id == 0 => {}
                KIND_DATA => {
                    // Return receive credit immediately, then echo.
                    let len = body.len() as u32;
                    self.send_frame(id, KIND_WINDOW, &len.to_be_bytes()).await;
                    self.queue.push_back((id, body));
                    self.drain().await;
                }
                KIND_WINDOW => {
                    let grant = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                    self.credit += grant;
                    self.drain().await;
                }
                KIND_CLOSE => {
                    self.queue.retain(|(qid, _)| *qid != id);
                }
                _ => {}
            }
        }
    }
}

/// Seal one mux frame with the transport, returning the wire bytes.
fn seal_frame(transport: &mut snow::TransportState, id: u32, kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut plain = Vec::with_capacity(8 + payload.len());
    plain.extend_from_slice(&id.to_be_bytes());
    plain.push(kind);
    plain.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    plain.push(0);
    plain.extend_from_slice(payload);

    let mut sealed = vec![0u8; plain.len() + 16];
    let n = transport.write_message(&plain, &mut sealed).unwrap();
    sealed.truncate(n);
    sealed
}

/// Complete the bridge side of the XX handshake.
async fn xx_connect(addr: SocketAddr, private: &[u8]) -> (TcpStream, snow::TransportState) {
    let head = preamble(b"DSHB", 1, &[0u8; 32]);
    let mut socket = TcpStream::connect(addr).await.unwrap();
    socket.write_all(&head).await.unwrap();

    let mut hs = snow::Builder::new(PARAMS.parse().unwrap())
        .local_private_key(private)
        .prologue(&head)
        .build_initiator()
        .unwrap();
    let mut buf = vec![0u8; 65535];
    let n = hs.write_message(&[], &mut buf).unwrap();
    write_lp(&mut socket, &buf[..n]).await;
    let msg2 = read_lp(&mut socket).await;
    hs.read_message(&msg2, &mut buf).unwrap();
    let n = hs.write_message(&[], &mut buf).unwrap();
    write_lp(&mut socket, &buf[..n]).await;
    (socket, hs.into_transport_mode().unwrap())
}

async fn write_lp(socket: &mut TcpStream, body: &[u8]) {
    let mut out = Vec::with_capacity(body.len() + 2);
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    socket.write_all(&out).await.unwrap();
}

async fn read_lp(socket: &mut TcpStream) -> Vec<u8> {
    read_lp_opt(socket).await.expect("link closed")
}

/// `write_lp`, but a closed peer is reported instead of panicking.
async fn write_lp_opt(socket: &mut TcpStream, body: &[u8]) -> std::io::Result<()> {
    let mut out = Vec::with_capacity(body.len() + 2);
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    socket.write_all(&out).await
}

async fn read_lp_opt(socket: &mut TcpStream) -> Option<Vec<u8>> {
    let mut len = [0u8; 2];
    socket.read_exact(&mut len).await.ok()?;
    let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
    socket.read_exact(&mut body).await.ok()?;
    Some(body)
}

/// Bring up a proxy with an echo bridge attached; returns the address and key.
async fn proxy_with_bridge() -> (SocketAddr, Vec<u8>) {
    proxy_with_bridge_at(start_proxy().await).await
}

/// The same, on an already-started proxy.
async fn proxy_with_bridge_at(addr: SocketAddr) -> (SocketAddr, Vec<u8>) {
    let (private, public) = dsh_proxy::noise::generate_keypair().unwrap();
    let bridge = EchoBridge::connect(addr, &private).await;
    tokio::spawn(bridge.run());
    // Let the proxy register the bridge before a phone addresses it.
    tokio::time::sleep(Duration::from_millis(150)).await;
    (addr, public)
}

#[tokio::test]
async fn phone_round_trip() {
    let (addr, key) = proxy_with_bridge().await;
    let head = preamble(b"DSHC", 1, &key);

    let mut phone = TcpStream::connect(addr).await.unwrap();
    phone.write_all(&head).await.unwrap();
    phone.write_all(b"hello bridge").await.unwrap();

    // The proxy forwards the preamble into the stream first, so it comes back.
    let mut got = vec![0u8; head.len() + 12];
    phone.read_exact(&mut got).await.unwrap();
    assert_eq!(&got[..head.len()], &head[..]);
    assert_eq!(&got[head.len()..], b"hello bridge");
}

/// Exercises flow control in both directions: more than one window each way,
/// which only completes if batched WINDOW updates keep the credit flowing.
#[tokio::test]
async fn bulk_transfer_through_window() {
    let (addr, key) = proxy_with_bridge().await;
    let head = preamble(b"DSHC", 1, &key);
    let payload: Vec<u8> = (0..3 * 1024 * 1024).map(|i| (i % 251) as u8).collect();

    let phone = TcpStream::connect(addr).await.unwrap();
    let (mut reader, mut writer) = phone.into_split();

    let send = payload.clone();
    // The task returns the write half so it is NOT dropped: a phone that
    // half-closes ends the stream, since the mux has no half-close signal.
    let writing = tokio::spawn(async move {
        writer.write_all(&head).await.unwrap();
        writer.write_all(&send).await.unwrap();
        writer
    });

    let mut echoed = vec![0u8; 37 + payload.len()];
    tokio::time::timeout(Duration::from_secs(60), reader.read_exact(&mut echoed))
        .await
        .expect("bulk transfer timed out")
        .unwrap();
    drop(writing.await.unwrap());
    assert_eq!(&echoed[37..], &payload[..], "payload corrupted in the tunnel");
}

/// Many streams at once on one link: ids, windows and inboxes stay separate.
#[tokio::test]
async fn concurrent_streams_stay_separate() {
    let (addr, key) = proxy_with_bridge().await;
    let mut tasks = Vec::new();
    for i in 0..50u32 {
        let head = preamble(b"DSHC", 1, &key);
        tasks.push(tokio::spawn(async move {
            let body = format!("stream-{i:04}-payload").repeat(64);
            let mut phone = TcpStream::connect(addr).await.unwrap();
            phone.write_all(&head).await.unwrap();
            phone.write_all(body.as_bytes()).await.unwrap();
            let mut got = vec![0u8; head.len() + body.len()];
            phone.read_exact(&mut got).await.unwrap();
            assert_eq!(&got[head.len()..], body.as_bytes());
        }));
    }
    for task in tasks {
        tokio::time::timeout(Duration::from_secs(30), task).await.unwrap().unwrap();
    }
}

/// The keepalive channel must be echoed, or the bridge tears the link down.
#[tokio::test]
async fn keepalive_is_echoed() {
    let addr = start_proxy().await;
    let (private, _) = dsh_proxy::noise::generate_keypair().unwrap();
    let mut bridge = EchoBridge::connect(addr, &private).await;
    bridge.send_frame(0, KIND_DATA, &[]).await;
    let (id, kind, body) = bridge.read_frame().await.expect("no keepalive echo");
    assert_eq!((id, kind, body.len()), (0, KIND_DATA, 0));
}

#[tokio::test]
async fn unknown_bridge_key_is_dropped() {
    let addr = start_proxy().await;
    let mut phone = TcpStream::connect(addr).await.unwrap();
    phone.write_all(&preamble(b"DSHC", 1, &[9u8; 32])).await.unwrap();
    let _ = phone.write_all(b"anyone there?").await;
    let mut got = Vec::new();
    // Clean EOF or a reset both mean the proxy said nothing.
    let _ = phone.read_to_end(&mut got).await;
    assert!(got.is_empty(), "unknown key learned something");
}

#[tokio::test]
async fn wrong_version_and_magic_are_dropped() {
    let addr = start_proxy().await;
    for head in [preamble(b"DSHC", 2, &[0u8; 32]), preamble(b"XXXX", 1, &[0u8; 32])] {
        let mut sock = TcpStream::connect(addr).await.unwrap();
        sock.write_all(&head).await.unwrap();
        let mut got = Vec::new();
        sock.read_to_end(&mut got).await.unwrap();
        assert!(got.is_empty());
    }
}
/// An unauthenticated peer cannot claim more than its share of the table.
#[tokio::test]
async fn too_many_bridges_from_one_ip_are_refused() {
    let limits = dsh_proxy::Limits { max_bridges_per_ip: 2, ..Default::default() };
    let addr = start_proxy_with(limits).await;

    // Two are admitted; their links stay open.
    let mut held = Vec::new();
    for _ in 0..2 {
        let (private, public) = dsh_proxy::noise::generate_keypair().unwrap();
        let bridge = EchoBridge::connect(addr, &private).await;
        tokio::spawn(bridge.run());
        held.push(public);
    }
    tokio::time::sleep(Duration::from_millis(150)).await;

    // A third is dropped mid-handshake: the connection closes without a reply.
    let (private, _) = dsh_proxy::noise::generate_keypair().unwrap();
    let head = preamble(b"DSHB", 1, &[0u8; 32]);
    let mut socket = TcpStream::connect(addr).await.unwrap();
    socket.write_all(&head).await.unwrap();
    let mut hs = snow::Builder::new(PARAMS.parse().unwrap())
        .local_private_key(&private)
        .prologue(&head)
        .build_initiator()
        .unwrap();
    let mut buf = vec![0u8; 4096];
    let n = hs.write_message(&[], &mut buf).unwrap();
    write_lp(&mut socket, &buf[..n]).await;

    let mut reply = Vec::new();
    let closed = tokio::time::timeout(Duration::from_secs(5), socket.read_to_end(&mut reply)).await;
    assert!(closed.is_ok(), "over-limit bridge was not refused");
    assert!(reply.is_empty(), "refused bridge got a handshake reply");
}

/// A bridge that stalls mid-handshake is reaped, not held open forever.
#[tokio::test]
async fn stalled_handshake_is_timed_out() {
    let limits = dsh_proxy::Limits {
        handshake_timeout: Duration::from_millis(300),
        ..Default::default()
    };
    let addr = start_proxy_with(limits).await;

    // A valid preamble and a well-formed first message, then silence.
    let (private, _) = dsh_proxy::noise::generate_keypair().unwrap();
    let head = preamble(b"DSHB", 1, &[0u8; 32]);
    let mut socket = TcpStream::connect(addr).await.unwrap();
    socket.write_all(&head).await.unwrap();
    let mut hs = snow::Builder::new(PARAMS.parse().unwrap())
        .local_private_key(&private)
        .prologue(&head)
        .build_initiator()
        .unwrap();
    let mut buf = vec![0u8; 4096];
    let n = hs.write_message(&[], &mut buf).unwrap();
    write_lp(&mut socket, &buf[..n]).await;

    let mut rest = Vec::new();
    let ended = tokio::time::timeout(Duration::from_secs(10), socket.read_to_end(&mut rest)).await;
    assert!(ended.is_ok(), "a stalled handshake was never reaped");
}

/// The bridge stream ceiling is a reservation, so callers racing for the last
/// slot cannot overshoot it.
#[tokio::test]
async fn stream_budget_is_never_exceeded() {
    const CAP: usize = 8;
    let limits = dsh_proxy::Limits { max_streams_per_bridge: CAP, ..Default::default() };
    let addr = start_proxy_with(limits).await;
    let (addr, key) = proxy_with_bridge_at(addr).await;

    // Every phone holds its stream open, so no slot is freed mid-race.
    let mut phones = Vec::new();
    for _ in 0..CAP * 4 {
        let head = preamble(b"DSHC", 1, &key);
        phones.push(tokio::spawn(async move {
            let mut phone = TcpStream::connect(addr).await.unwrap();
            if phone.write_all(&head).await.is_err() {
                return None;
            }
            // An opened stream echoes the preamble back; a refused one is
            // closed or silent, so the read never completes.
            let mut got = vec![0u8; head.len()];
            match tokio::time::timeout(Duration::from_secs(5), phone.read_exact(&mut got)).await {
                Ok(Ok(_)) if got == head => Some(phone),
                _ => None,
            }
        }));
    }
    let mut opened = 0usize;
    let mut held = Vec::new();
    for phone in phones {
        if let Some(phone) = phone.await.unwrap() {
            opened += 1;
            held.push(phone);
        }
    }
    assert_eq!(opened, CAP, "opened {opened} streams against a budget of {CAP}");
    drop(held);
}

/// A bridge that ignores its receive credit on one stream, so the proxy's
/// per-stream inbox overflows while the phone is not reading.
///
/// Sets the oneshot once the proxy has closed the stream, which is the
/// evidence that the overflow was handled rather than tolerated.
async fn credit_ignoring_bridge(
    addr: SocketAddr,
    private: Vec<u8>,
    ready: tokio::sync::oneshot::Sender<()>,
    start: tokio::sync::oneshot::Receiver<()>,
    closed: tokio::sync::oneshot::Sender<u32>,
) {
    let (mut socket, mut transport) = xx_connect(addr, &private).await;
    let _ = ready.send(());
    let mut start = Some(start);
    let mut closed = Some(closed);
    while let Some(sealed) = read_lp_opt(&mut socket).await {
        let mut plain = vec![0u8; sealed.len()];
        let n = transport.read_message(&sealed, &mut plain).unwrap();
        plain.truncate(n);
        if plain.len() < 8 {
            continue;
        }
        let id = u32::from_be_bytes([plain[0], plain[1], plain[2], plain[3]]);
        let kind = plain[4];
        match kind {
            KIND_DATA if id != 0 => {
                // Echo the phone's preamble, then wait for the test to say the
                // phone has stopped reading, so the flood — not the echo — is
                // what wedges the downlink.
                let payload = plain[8..].to_vec();
                write_lp(&mut socket, &seal_frame(&mut transport, id, KIND_DATA, &payload)).await;
                if let Some(signal) = start.take() {
                    let _ = signal.await;
                }
                // Now write past the window we were granted, on purpose.
                let tiny = vec![b'x'; 16];
                for _ in 0..4096 {
                    // `seal_frame` returns the sealed body only; the length
                    // prefix is `write_lp`'s job, exactly as in send_frame.
                    let frame = seal_frame(&mut transport, id, KIND_DATA, &tiny);
                    if write_lp_opt(&mut socket, &frame).await.is_err() {
                        break;
                    }
                }
            }
            KIND_CLOSE => {
                if let Some(sender) = closed.take() {
                    let _ = sender.send(id);
                }
            }
            _ => {}
        }
    }
}

/// One stream that writes past its credit loses its own connection; the bridge
/// link and every other phone on it must survive.
#[tokio::test]
async fn inbox_overflow_costs_one_stream_not_the_link() {
    let limits = dsh_proxy::Limits { max_streams_per_bridge: 8, ..Default::default() };
    let addr = start_proxy_with(limits).await;
    let (private, key) = dsh_proxy::noise::generate_keypair().unwrap();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (start_tx, start_rx) = tokio::sync::oneshot::channel();
    let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(credit_ignoring_bridge(addr, private, ready_tx, start_rx, closed_tx));
    // The link must exist before a phone addresses its key, or the proxy has
    // nobody to route to and the phone is dropped as unknown.
    tokio::time::timeout(Duration::from_secs(5), ready_rx)
        .await
        .expect("the flooding bridge never registered")
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // The phone is the only client on this link. It reads the echo, then stops
    // reading, so the flood below has nowhere to drain.
    let mut victim = TcpStream::connect(addr).await.unwrap();
    victim.write_all(&preamble(b"DSHC", 1, &key)).await.unwrap();
    let mut echoed = vec![0u8; 37];
    tokio::time::timeout(Duration::from_secs(5), victim.read_exact(&mut echoed))
        .await
        .expect("victim stream never opened")
        .unwrap();
    let _ = start_tx.send(());

    let flooded = tokio::time::timeout(Duration::from_secs(20), closed_rx)
        .await
        .expect("the flooding stream was never closed")
        .expect("the flooding bridge died first");
    assert!(flooded > 0, "the keepalive channel was closed, not the stream");
    drop(victim);

    // The link itself is unharmed: a new stream still opens on it.
    let mut second = TcpStream::connect(addr).await.unwrap();
    second.write_all(&preamble(b"DSHC", 1, &key)).await.unwrap();
    let mut echoed = vec![0u8; 37];
    tokio::time::timeout(Duration::from_secs(5), second.read_exact(&mut echoed))
        .await
        .expect("the link died with one stream")
        .unwrap();
    assert_eq!(echoed, preamble(b"DSHC", 1, &key));
}
