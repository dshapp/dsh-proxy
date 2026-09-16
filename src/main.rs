//! dsh mobile-access proxy.
//!
//! One TCP port. Every connection starts with the same 37-byte plaintext
//! preamble; the proxy reads exactly that, then either adopts a bridge link
//! (Noise_XX) or splices a mobile connection onto the addressed bridge's mux.
//! Application bytes are never parsed, never decrypted, never stored.

mod mux;
mod noise;
mod wire;

use std::io::Result;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use mux::MuxSession;
use wire::{HEAD_LEN, MAGIC_BRIDGE, MAGIC_CLIENT, MAX_PAYLOAD, VERSION};

/// Resource guard, not authentication: one bridge cannot be made to hold
/// unbounded state by whoever knows its public key. A phone keeps a live
/// socket plus a small connection pool, so this is thousands of phones.
const MAX_STREAMS_PER_BRIDGE: usize = 2048;
/// A connection that does not deliver its preamble is not a client of ours.
const PREAMBLE_TIMEOUT: Duration = Duration::from_secs(5);

type Table = Arc<DashMap<[u8; 32], Arc<MuxSession>>>;

#[tokio::main]
async fn main() -> Result<()> {
    let mut listen = "0.0.0.0:443".to_string();
    let mut key: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => listen = args.next().unwrap_or(listen),
            "--key" => key = args.next(),
            "--help" | "-h" => {
                eprintln!("dsh-proxy [--listen HOST:PORT] [--key BASE64_X25519_PRIVATE]");
                return Ok(());
            }
            other => {
                eprintln!("dsh-proxy: unknown argument {other}");
                std::process::exit(2);
            }
        }
    }

    let private = match key {
        Some(text) => B64
            .decode(text.trim())
            .unwrap_or_else(|_| { eprintln!("dsh-proxy: --key is not base64"); std::process::exit(2) }),
        None => noise::generate_keypair()?.0,
    };
    let public = noise::public_key_of(&private)?;
    let private = Arc::new(private);

    let listener = TcpListener::bind(&listen).await?;
    eprintln!("dsh-proxy listening on {listen}");
    eprintln!("dsh-proxy public key {}", B64.encode(&public));

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
    let (session, done) = MuxSession::start(socket, transport);
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
    tx.send(head).await?;

    let (mut reader, mut writer) = socket.into_split();
    let uplink = tokio::spawn({
        let tx = tx.clone();
        async move {
            let mut buf = vec![0u8; MAX_PAYLOAD];
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if tx.send(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
    });
    let downlink = async {
        while let Some(chunk) = rx.recv().await {
            if writer.write_all(&chunk).await.is_err() {
                break;
            }
            if tx.grant(chunk.len() as u32).await.is_err() {
                break;
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
