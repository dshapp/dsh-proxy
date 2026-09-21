//! The client edge: one WebSocket, and nothing else.
//!
//! Every end-user client - Android, the WeChat mini-program, anything later -
//! arrives the same way: TLS, then an upgrade on `/tunnel`. What rides inside
//! is the phone's own byte stream, a 37-byte preamble and then a Noise_IK
//! session with the Mac. The proxy unwraps WebSocket frames and forwards the
//! bytes. It cannot read them and holds no key that would let it.
//!
//! There is deliberately no pairing route, no token, and no stored state here.
//! Pairing happens inside the tunnel, between the phone and the Mac, so the
//! public component keeps nothing worth stealing.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use dashmap::DashMap;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::header::{CONNECTION, UPGRADE};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use crate::mux::MuxSession;
use crate::wire::{HEAD_LEN, MAGIC_CLIENT, VERSION};
use crate::ws::{accept_key, WsStream};

/// A client that does not send its preamble is not a client of ours.
const PREAMBLE_TIMEOUT: Duration = Duration::from_secs(10);

/// Responses here are a status line and at most a few bytes of JSON.
pub type Body = Full<Bytes>;

/// Everything the edge needs to serve one connection.
pub struct Edge {
    pub tls: Arc<rustls::ServerConfig>,
    pub table: Arc<DashMap<[u8; 32], Arc<MuxSession>>>,
}

fn json(status: StatusCode, value: serde_json::Value) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(value.to_string())))
        .expect("a built response")
}

fn fail(status: StatusCode, message: &str) -> Response<Body> {
    json(status, serde_json::json!({ "error": message }))
}

impl Edge {
    /// Terminate TLS on one accepted socket and serve HTTP/1.1 on it.
    pub async fn serve(self: Arc<Self>, socket: TcpStream, slot: Arc<crate::IpSlot>) {
        let _ = socket.set_nodelay(true);
        let acceptor = TlsAcceptor::from(self.tls.clone());
        let tls = match acceptor.accept(socket).await {
            Ok(stream) => stream,
            // A failed handshake is not an incident: scanners and stale
            // clients die here and never reach a route.
            Err(_) => return,
        };
        let service = service_fn(move |request| {
            let edge = self.clone();
            let slot = slot.clone();
            async move { edge.handle(request, slot).await }
        });
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(tls), service)
            .with_upgrades()
            .await;
    }

    /// Route one request. There are exactly two.
    async fn handle(
        &self,
        req: Request<Incoming>,
        slot: Arc<crate::IpSlot>,
    ) -> Result<Response<Body>, Infallible> {
        let path = req.uri().path().to_string();
        if path == "/tunnel" && is_upgrade(&req) {
            return Ok(self.tunnel(req, slot));
        }
        if path == "/health" {
            return Ok(json(StatusCode::OK, serde_json::json!({ "ok": true })));
        }
        Ok(fail(StatusCode::NOT_FOUND, "no such route"))
    }

    /// Answer a WebSocket upgrade and splice the stream inside it.
    ///
    /// No token is checked, and none could be: the session inside is Noise_IK
    /// between the phone and the Mac, and the Mac's device allowlist is the
    /// authority. What the proxy owes this route is admission control, not
    /// authentication - see the per-IP and per-bridge ceilings.
    fn tunnel(&self, mut req: Request<Incoming>, slot: Arc<crate::IpSlot>) -> Response<Body> {
        let Some(key) = req
            .headers()
            .get("sec-websocket-key")
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_string())
        else {
            return fail(StatusCode::BAD_REQUEST, "missing Sec-WebSocket-Key");
        };
        let accept = accept_key(&key);
        let upgraded = hyper::upgrade::on(&mut req);
        let table = self.table.clone();
        tokio::spawn(async move {
            // Held for the tunnel's whole life, which is what the per-IP
            // ceiling is meant to be counting.
            let _slot = slot;
            let Ok(upgraded) = upgraded.await else { return };
            let mut stream = WsStream::new(TokioIo::new(upgraded));
            // The preamble names the bridge; it is read from the stream just
            // as the bare-TCP path used to read it from the socket.
            let mut head = [0u8; HEAD_LEN];
            let read = tokio::time::timeout(PREAMBLE_TIMEOUT, stream.read_exact(&mut head)).await;
            if !matches!(read, Ok(Ok(_))) {
                return;
            }
            if head[..4] != MAGIC_CLIENT || head[4] != VERSION {
                return;
            }
            let _ = crate::serve_client(stream, &head, table).await;
        });
        Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header(CONNECTION, "Upgrade")
            .header(UPGRADE, "websocket")
            .header("sec-websocket-accept", accept)
            .body(Full::new(Bytes::new()))
            .expect("a built response")
    }
}

/// Whether a request asks to switch protocols.
pub fn is_upgrade(req: &Request<Incoming>) -> bool {
    req.headers()
        .get(UPGRADE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
}
