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
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_util::codec::{FramedRead, FramedWrite};

use mux::MuxSession;
use wire::{HEAD_LEN, MAGIC_BRIDGE, MAGIC_CLIENT, MAX_PAYLOAD, VERSION, WINDOW};

/// Resource guard, not authentication: one bridge cannot be made to hold
/// unbounded state by whoever knows its public key. A phone keeps a live
/// socket plus a small connection pool, so this is thousands of phones.
const MAX_STREAMS_PER_BRIDGE: usize = 2048;
/// A connection that does not deliver its preamble is not a client of ours.
const PREAMBLE_TIMEOUT: Duration = Duration::from_secs(5);
/// Return receive credit once half the window is spent, instead of one
/// WINDOW frame per DATA frame. Halves the frames on the downlink path and
/// still leaves the bridge half a window to keep writing into.
const GRANT_THRESHOLD: u32 = WINDOW / 2;

pub type Table = Arc<DashMap<[u8; 32], Arc<MuxSession>>>;

/// Serve until the listener fails.
pub async fn run(listener: TcpListener, private: Arc<Vec<u8>>) -> Result<()> {
    let table: Table = Arc::new(DashMap::new());
    loop {
        let (socket, _) = listener.accept().await?;
        let table = table.clone();
        let private = private.clone();
        tokio::spawn(async move {
            let _ = socket.set_nodelay(true);
            let _ = serve(socket, table, private).await;
        });
    }
}

async fn serve(mut socket: TcpStream, table: Table, private: Arc<Vec<u8>>) -> Result<()> {
    let mut head = [0u8; HEAD_LEN];
    timeout(PREAMBLE_TIMEOUT, socket.read_exact(&mut head)).await??;
    if head[4] != VERSION {
        return Ok(());
    }
    let magic: [u8; 4] = [head[0], head[1], head[2], head[3]];
    match magic {
        MAGIC_BRIDGE => serve_bridge(socket, &head, table, &private).await,
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
    table: Table,
    private: &[u8],
) -> Result<()> {
    let (bridge_key, transport) = noise::xx_respond(&mut socket, private, head).await?;
    let (decoder, encoder) = noise::codecs(transport);
    let (reader, writer) = socket.into_split();
    let (session, done) = MuxSession::start(
        FramedRead::new(reader, decoder),
        FramedWrite::new(writer, encoder),
    );
    eprintln!("bridge up {}", B64.encode(bridge_key));
    table.insert(bridge_key, session.clone());
    let _ = done.await;
    // Only drop the entry if a later generation has not replaced it.
    table.remove_if(&bridge_key, |_, current| Arc::ptr_eq(current, &session));
    eprintln!("bridge down {}", B64.encode(bridge_key));
    Ok(())
}

/// Splice one mobile connection onto its bridge. From here the proxy only
/// moves bytes: the Noise_IK handshake inside belongs to the two endpoints.
async fn serve_client(socket: TcpStream, head: &[u8; HEAD_LEN], table: Table) -> Result<()> {
    let mut key = [0u8; 32];
    key.copy_from_slice(&head[5..HEAD_LEN]);
    let Some(session) = table.get(&key).map(|entry| entry.clone()) else { return Ok(()) };
    if session.stream_count() >= MAX_STREAMS_PER_BRIDGE {
        return Ok(());
    }
    let (tx, mut rx) = session.open_stream().await?;
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
