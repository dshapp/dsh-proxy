//! dsh mobile-access proxy.
//!
//! One TCP port. Every connection starts with the same 37-byte plaintext
//! preamble; the proxy reads exactly that, then either adopts a bridge link
//! (Noise_XX) or splices a mobile connection onto the addressed bridge's mux.
//! Application bytes are never parsed, never decrypted, never stored.

pub mod mux;
pub mod noise;
pub mod wire;

use std::io::Result;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_util::codec::{FramedRead, FramedWrite};

use mux::MuxSession;
use wire::{
    HEAD_LEN, MAGIC_BRIDGE, MAGIC_CLIENT, MAX_PAYLOAD, MAX_STREAMS_PER_BRIDGE, VERSION, WINDOW,
};

/// A connection that does not deliver its preamble is not a client of ours.
const PREAMBLE_TIMEOUT: Duration = Duration::from_secs(5);
/// Return receive credit once half the window is spent, instead of one
/// WINDOW frame per DATA frame. Halves the frames on the downlink path and
/// still leaves the bridge half a window to keep writing into.
const GRANT_THRESHOLD: u32 = WINDOW / 2;

/// Admission limits for bridge registrations.
///
/// Registering a bridge is deliberately unauthenticated — possession of a
/// static key is proved by the handshake itself, and there is nothing to
/// authenticate against — so the only defence against one host filling the
/// table is a ceiling. Both bounds are per-process, and per-IP exists because
/// a single origin can otherwise claim the whole table.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Most bridge links the process will hold at once.
    pub max_bridges: usize,
    /// Most bridge links one peer address may hold at once.
    pub max_bridges_per_ip: usize,
    /// Most streams one bridge will carry at once.
    pub max_streams_per_bridge: usize,
    /// Deadline for the whole Noise_XX handshake, not just the preamble.
    pub handshake_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_bridges: 1024,
            max_bridges_per_ip: 32,
            max_streams_per_bridge: MAX_STREAMS_PER_BRIDGE,
            handshake_timeout: Duration::from_secs(10),
        }
    }
}

/// Bridge links currently held per peer address.
///
/// A guard rather than a counter: every path that admits a bridge moves one of
/// these into `serve_bridge`, so the count cannot drift from reality even when
/// a task is cancelled or panics on the way out.
type BridgesPerIp = Arc<DashMap<IpAddr, usize>>;

/// Holds one per-IP bridge slot until dropped.
struct IpSlot {
    table: BridgesPerIp,
    ip: IpAddr,
}

impl IpSlot {
    /// Claim a slot for `ip`, or `None` when the peer already holds its share.
    fn claim(table: &BridgesPerIp, ip: IpAddr, max: usize) -> Option<Self> {
        let mut entry = table.entry(ip).or_insert(0);
        if *entry >= max {
            return None;
        }
        *entry += 1;
        Some(Self { table: table.clone(), ip })
    }
}

impl Drop for IpSlot {
    fn drop(&mut self) {
        if let Some(mut count) = self.table.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
        }
        // Reclaim the key once the last holder let go, so the map tracks live
        // peers rather than every address the process has ever seen. A claim
        // racing in between leaves a count above zero and is left alone.
        self.table.remove_if(&self.ip, |_, count| *count == 0);
    }
}

pub type Table = Arc<DashMap<[u8; 32], Arc<MuxSession>>>;

/// Serve until the listener fails.
pub async fn run(listener: TcpListener, private: Arc<Vec<u8>>, limits: Limits) -> Result<()> {
    let table: Table = Arc::new(DashMap::new());
    let per_ip: BridgesPerIp = Arc::new(DashMap::new());
    // A permit pool rather than a length check, so the ceiling is exact even
    // when many bridges arrive at once.
    let budget = Arc::new(Semaphore::new(limits.max_bridges));
    loop {
        let (socket, peer) = listener.accept().await?;
        let table = table.clone();
        let per_ip = per_ip.clone();
        let budget = budget.clone();
        let private = private.clone();
        tokio::spawn(async move {
            let _ = socket.set_nodelay(true);
            let _ = serve(socket, peer.ip(), table, per_ip, budget, private, limits).await;
        });
    }
}

async fn serve(
    mut socket: TcpStream,
    peer: IpAddr,
    table: Table,
    per_ip: BridgesPerIp,
    budget: Arc<Semaphore>,
    private: Arc<Vec<u8>>,
    limits: Limits,
) -> Result<()> {
    let mut head = [0u8; HEAD_LEN];
    timeout(PREAMBLE_TIMEOUT, socket.read_exact(&mut head)).await??;
    if head[4] != VERSION {
        return Ok(());
    }
    let magic: [u8; 4] = [head[0], head[1], head[2], head[3]];
    match magic {
        MAGIC_BRIDGE => serve_bridge(socket, &head, peer, table, per_ip, budget, &private, limits).await,
        MAGIC_CLIENT => serve_client(socket, &head, table).await,
        // Anything else gets nothing back: an unknown speaker learns nothing.
        _ => Ok(()),
    }
}

/// Adopt a bridge: the XX handshake is its proof of key possession, and the
/// key it proves is the routing key mobile clients address.
async fn serve_bridge(
    mut socket: TcpStream,
    head: &[u8; HEAD_LEN],
    peer: IpAddr,
    table: Table,
    per_ip: BridgesPerIp,
    budget: Arc<Semaphore>,
    private: &[u8],
    limits: Limits,
) -> Result<()> {
    // Admission before cryptography: a rejected bridge costs one packet, and
    // the global/per-IP slots are held for the whole link below.
    let Ok(_slots) = budget.try_acquire_owned() else { return Ok(()) };
    let Some(_per_ip) = IpSlot::claim(&per_ip, peer, limits.max_bridges_per_ip) else {
        return Ok(());
    };
    let (bridge_key, transport) = match timeout(
        limits.handshake_timeout,
        noise::xx_respond(&mut socket, private, head),
    )
    .await
    {
        Ok(result) => result?,
        // A peer that stalls mid-handshake is not a bridge; the whole XX flow
        // is bounded, not just the preamble read before it.
        Err(_) => return Ok(()),
    };
    let (decoder, encoder) = noise::codecs(transport);
    let (reader, writer) = socket.into_split();
    let (session, done) = MuxSession::start(
        FramedRead::new(reader, decoder),
        FramedWrite::new(writer, encoder),
        limits.max_streams_per_bridge,
    );
    // The key is a routing label, not a secret: whoever holds the QR code has
    // it, so writing it to a log only spreads it further.
    eprintln!("bridge up");
    table.insert(bridge_key, session.clone());
    let _ = done.await;
    // Only drop the entry if a later generation has not replaced it.
    table.remove_if(&bridge_key, |_, current| Arc::ptr_eq(current, &session));
    eprintln!("bridge down");
    Ok(())
}

/// Splice one mobile connection onto its bridge. From here the proxy only
/// moves bytes: the Noise_IK handshake inside belongs to the two endpoints.
async fn serve_client(socket: TcpStream, head: &[u8; HEAD_LEN], table: Table) -> Result<()> {
    let mut key = [0u8; 32];
    key.copy_from_slice(&head[5..HEAD_LEN]);
    let Some(session) = table.get(&key).map(|entry| entry.clone()) else { return Ok(()) };
    // The slot is reserved inside this call, so two clients racing for the
    // last one cannot both win.
    let Some((tx, mut rx)) = session.try_open_stream().await else { return Ok(()) };
    let tx = Arc::new(tx);
    tx.send(Bytes::copy_from_slice(head)).await?;

    let (mut reader, mut writer) = socket.into_split();
    let uplink = tokio::spawn({
        let tx = tx.clone();
        async move {
            let mut buf = BytesMut::with_capacity(MAX_PAYLOAD);
            loop {
                buf.reserve(MAX_PAYLOAD);
                match reader.read_buf(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        // split_to hands off a slice of the same allocation.
                        if tx.send(buf.split_to(n).freeze()).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
    });
    let downlink = async {
        let mut pending: u32 = 0;
        while let Some(chunk) = rx.recv().await {
            if writer.write_all(&chunk).await.is_err() {
                break;
            }
            pending += chunk.len() as u32;
            if pending >= GRANT_THRESHOLD {
                if tx.grant(pending).await.is_err() {
                    break;
                }
                pending = 0;
            }
        }
        let _ = writer.shutdown().await;
    };
    tokio::pin!(downlink);
    // Either end hanging up ends the stream: waiting only on the bridge would
    // leak one stream per phone that walked out of WiFi.
    tokio::select! {
        _ = uplink => {}
        _ = &mut downlink => {}
    }
    tx.close().await;
    Ok(())
}
