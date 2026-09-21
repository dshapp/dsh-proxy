//! The proxy as a phone: one Noise_IK tunnel per (bridge, device), pooled.
//!
//! A tunnel is an ordinary mux stream carrying a Noise_IK handshake and then
//! plain HTTP/1.1. Pooling matters because IK costs a round trip and a few
//! DHs; a request that reuses a live tunnel costs neither.

use std::io::{Error, ErrorKind, Result};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use std::sync::Mutex;

use bytes::Bytes;
use dashmap::DashMap;
use http_body_util::combinators::BoxBody;
use hyper::client::conn::http1::{self, SendRequest};
use hyper_util::rt::TokioIo;
use tokio::task::JoinHandle;

use crate::mux::{MuxSession, MuxStreamIo};
use crate::noise;
use crate::state::DeviceHandle;
use crate::tunnel::NoiseStream;
use crate::wire::{HEAD_LEN, MAGIC_CLIENT, VERSION, WINDOW};

/// Idle tunnels are closed after this long, so a quiet proxy holds no bridge
/// stream slots.
const IDLE: Duration = Duration::from_secs(60);
/// A body buffered before the edge spills it; bounds one request's memory.
pub const MAX_BODY: usize = 64 * 1024 * 1024;

/// The body type every tunneled request uses.
pub type Body = BoxBody<Bytes, Error>;

fn other(error: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Other, error.to_string())
}

/// The 37-byte preamble a bridge expects from a phone.
///
/// It is also the Noise prologue, so it must be written and mixed in exactly
/// as one buffer.
pub fn preamble(bridge_key: &[u8; 32]) -> Vec<u8> {
    let mut head = Vec::with_capacity(HEAD_LEN);
    head.extend_from_slice(&MAGIC_CLIENT);
    head.push(VERSION);
    head.extend_from_slice(bridge_key);
    head
}

/// One tunnel to the bridge, with or without the inner Noise_IK layer.
pub enum Tunnel {
    /// The shipped shape: HTTP inside Noise_IK inside the Noise_XX mux link.
    Sealed(NoiseStream<MuxStreamIo>),
    /// Experimental: HTTP straight on the mux stream, sealed only by the
    /// bridge link's own Noise_XX.
    Plain(MuxStreamIo),
}

/// Whether to drop the inner Noise_IK layer (experiment only).
pub fn plain_tunnels() -> bool {
    std::env::var("DSH_TUNNEL_PLAIN").is_ok_and(|value| value == "1")
}

impl tokio::io::AsyncRead for Tunnel {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<Result<()>> {
        match self.get_mut() {
            Tunnel::Sealed(inner) => std::pin::Pin::new(inner).poll_read(cx, buf),
            Tunnel::Plain(inner) => std::pin::Pin::new(inner).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for Tunnel {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<Result<usize>> {
        match self.get_mut() {
            Tunnel::Sealed(inner) => std::pin::Pin::new(inner).poll_write(cx, data),
            Tunnel::Plain(inner) => std::pin::Pin::new(inner).poll_write(cx, data),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<()>> {
        match self.get_mut() {
            Tunnel::Sealed(inner) => std::pin::Pin::new(inner).poll_flush(cx),
            Tunnel::Plain(inner) => std::pin::Pin::new(inner).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<()>> {
        match self.get_mut() {
            Tunnel::Sealed(inner) => std::pin::Pin::new(inner).poll_shutdown(cx),
            Tunnel::Plain(inner) => std::pin::Pin::new(inner).poll_shutdown(cx),
        }
    }
}

/// One keep-alive HTTP/1.1 connection riding a Noise tunnel.
struct Conn {
    sender: SendRequest<Body>,
    created: Instant,
}

/// Tunnels keyed by bridge+device, each with a small idle pool.
pub struct Pool {
    table: Arc<DashMap<[u8; 32], Arc<MuxSession>>>,
    pools: DashMap<[u8; 64], Arc<Mutex<Vec<Conn>>>>,
    /// Ceiling on tunnels held for one installation.
    per_device: usize,
    /// Live tunnels, process-wide, for /status.
    live: Arc<AtomicUsize>,
}

/// A tunnel checked out of the pool.
///
/// The lease carries everything it needs to put itself back, and does so in
/// `Drop`: a request body and a response body both end by dropping the lease,
/// whether that happens after the last byte or when a client hangs up early.
pub struct Lease {
    sender: Option<SendRequest<Body>>,
    /// The idle list this lease came from, so `Drop` needs no lookup.
    slot: Arc<Mutex<Vec<Conn>>>,
    cap: usize,
    live: Arc<AtomicUsize>,
    /// Whether this tunnel may be parked for reuse when the lease ends.
    reusable: bool,
}

impl Pool {
    pub fn new(table: Arc<DashMap<[u8; 32], Arc<MuxSession>>>, per_device: usize) -> Self {
        Self {
            table,
            pools: DashMap::new(),
            per_device: per_device.max(1),
            live: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Live tunnels, for /status.
    pub fn live(&self) -> usize {
        self.live.load(Ordering::Relaxed)
    }

    /// A stable pool key for one installation on one bridge.
    fn key(route: &DeviceHandle) -> [u8; 64] {
        let mut key = [0u8; 64];
        key[..32].copy_from_slice(&route.bridge_key);
        key[32..].copy_from_slice(&route.device_id);
        key
    }

    /// Open one fresh Noise tunnel to the route's bridge.
    ///
    /// The pairing token rides the first message on first contact and is empty
    /// on every re-open; the bridge consumes it exactly once.
    pub async fn open_tunnel(
        &self,
        route: &DeviceHandle,
        first_payload: &[u8],
    ) -> Result<Tunnel> {
        let session = self
            .table
            .get(&route.bridge_key)
            .map(|entry| entry.clone())
            .ok_or_else(|| other("bridge is not connected"))?;
        let (tx, rx) = session
            .try_open_stream()
            .await
            .ok_or_else(|| other("bridge is at its stream limit"))?;
        let head = preamble(&route.bridge_key);
        tx.send(Bytes::copy_from_slice(&head)).await?;

        let mut io = MuxStreamIo::new(tx, rx);
        // EXPERIMENT (DSH_TUNNEL_PLAIN=1): skip the inner Noise_IK. The mux
        // link is already Noise_XX between these same two processes, so once
        // the proxy holds both keys the IK layer is a second AEAD pass over
        // every byte that protects nothing the XX link does not. Measuring it
        // is the only way to price removing it.
        if plain_tunnels() {
            return Ok(Tunnel::Plain(io));
        }
        let transport = noise::ik_initiate(
            &mut io,
            &route.private_key,
            &route.bridge_key,
            &head,
            first_payload,
        )
        .await?;
        Ok(Tunnel::Sealed(NoiseStream::new(io, transport)))
    }

    /// Borrow a pooled HTTP connection, or build one.
    pub async fn acquire(&self, route: &DeviceHandle) -> Result<Lease> {
        let key = Self::key(route);
        let slot = self
            .pools
            .entry(key)
            .or_insert_with(|| Arc::new(Mutex::new(Vec::new())))
            .clone();

        // Pop an idle connection. Stale ones (closed by keep-alive expiry, or
        // older than IDLE) are dropped here rather than handed out.
        let reused = {
            let mut idle = slot.lock().expect("the idle list is never poisoned");
            let mut found = None;
            while let Some(candidate) = idle.pop() {
                if candidate.created.elapsed() < IDLE && !candidate.sender.is_closed() {
                    found = Some(candidate);
                    break;
                }
            }
            found
        };
        if let Some(conn) = reused {
            return Ok(Lease {
                sender: Some(conn.sender),
                slot,
                cap: self.per_device,
                live: self.live.clone(),
                reusable: true,
            });
        }

        let (sender, connection) = self.handshake(route, false).await?;
        let _connection: JoinHandle<()> = connection;
        Ok(Lease {
            sender: Some(sender),
            slot,
            cap: self.per_device,
            live: self.live.clone(),
            reusable: true,
        })
    }

    /// Build one tunnel and complete a client-side HTTP/1.1 handshake.
    ///
    /// When `upgrades` is true the connection is driven with upgrade support,
    /// which is what the WebSocket path needs; pooled connections skip it.
    async fn handshake(
        &self,
        route: &DeviceHandle,
        upgrades: bool,
    ) -> Result<(SendRequest<Body>, JoinHandle<()>)> {
        let stream = self.open_tunnel(route, &[]).await?;
        let io = TokioIo::new(stream);
        let (sender, connection) = http1::handshake(io).await.map_err(other)?;
        self.live.fetch_add(1, Ordering::Relaxed);
        let handle = if upgrades {
            tokio::spawn(async move {
                let _ = connection.with_upgrades().await;
            })
        } else {
            tokio::spawn(async move {
                let _ = connection.await;
            })
        };
        Ok((sender, handle))
    }

    /// A dedicated upgradable connection for one WebSocket.
    pub async fn open_upgradable(
        &self,
        route: &DeviceHandle,
    ) -> Result<(SendRequest<Body>, JoinHandle<()>)> {
        self.handshake(route, true).await
    }

}

impl Lease {
    /// The connection to send on.
    pub fn sender(&mut self) -> &mut SendRequest<Body> {
        self.sender.as_mut().expect("lease already consumed")
    }

    /// Drop the connection instead of returning it (a poisoned keep-alive).
    pub fn discard(&mut self) {
        self.sender = None;
    }

    /// Close this tunnel when the lease ends rather than parking it.
    ///
    /// A bulk transfer leaves a tunnel holding large buffers and a bridge
    /// stream slot for as long as the idle timeout. Those are worth keeping
    /// for a chatty RPC connection and not for a one-off file, so bulk routes
    /// take a tunnel and give it back to the operating system.
    pub fn close_when_done(&mut self) {
        self.reusable = false;
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        // `discard` clears the sender first, so a dropped lease means exactly
        // one thing: this tunnel is done and must not be counted live again.
        let Some(sender) = self.sender.take() else {
            self.live.fetch_sub(1, Ordering::Relaxed);
            return;
        };
        if sender.is_closed() || !self.reusable {
            self.live.fetch_sub(1, Ordering::Relaxed);
            return;
        }
        let mut idle = self.slot.lock().expect("the idle list is never poisoned");
        if idle.len() >= self.cap {
            drop(idle);
            self.live.fetch_sub(1, Ordering::Relaxed);
            return;
        }
        idle.push(Conn { sender, created: Instant::now() });
    }
}

/// The receive window is the real bound on how much a tunnel may buffer; the
/// constant is asserted here so a future tweak to WINDOW is noticed.
const _: () = assert!(WINDOW == 256 * 1024);
