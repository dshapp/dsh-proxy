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
    let (private, _) = dsh_proxy::noise::generate_keypair().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = dsh_proxy::run(listener, Arc::new(private)).await;
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
        let mut plain = Vec::with_capacity(8 + payload.len());
        plain.extend_from_slice(&id.to_be_bytes());
        plain.push(kind);
        plain.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        plain.push(0);
        plain.extend_from_slice(payload);

        let mut sealed = vec![0u8; plain.len() + 16];
        let n = self.transport.write_message(&plain, &mut sealed).unwrap();
        write_lp(&mut self.socket, &sealed[..n]).await;
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

async fn write_lp(socket: &mut TcpStream, body: &[u8]) {
    let mut out = Vec::with_capacity(body.len() + 2);
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    socket.write_all(&out).await.unwrap();
}

async fn read_lp(socket: &mut TcpStream) -> Vec<u8> {
    read_lp_opt(socket).await.expect("link closed")
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
    let addr = start_proxy().await;
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
