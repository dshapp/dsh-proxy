//! The unified client edge: one HTTPS/WSS contract for every end user.
//!
//! Android, the WeChat mini-program and anything later all arrive here the
//! same way - TLS, then /pair, then /api/<method> and /api/remote.mux with a
//! bearer token. There is no branch on client type; the only decision is which
//! bridge the token addresses.

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use bytes::Bytes;
use dashmap::DashMap;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Body as HttpBody, Frame, Incoming};
use hyper::header::{HeaderMap, CONNECTION, UPGRADE};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use crate::mux::MuxSession;
use crate::phone::{Body, Lease, Pool, MAX_BODY};
use crate::state::{DeviceHandle, Registry};

/// Everything the edge needs to serve one connection.
pub struct Edge {
    pub pool: Arc<Pool>,
    pub registry: Arc<Registry>,
    pub tls: Arc<rustls::ServerConfig>,
    pub table: Arc<DashMap<[u8; 32], Arc<MuxSession>>>,
}

/// A full-bodied response or request.
fn boxed_full(data: impl Into<Bytes>) -> Body {
    Full::new(data.into())
        .map_err(|never: std::convert::Infallible| -> std::io::Error { match never {} })
        .boxed()
}

/// Headers a proxy must not forward verbatim.
fn strip_hop(headers: &mut HeaderMap) {
    for name in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "host",
        "authorization",
    ] {
        headers.remove(name);
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PairRequest {
    bridge_key: String,
    #[serde(default)]
    pairing_token: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

fn json(status: StatusCode, value: serde_json::Value) -> Response<Body> {
    let text = value.to_string();
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(boxed_full(text))
        .expect("a built response")
}

fn fail(status: StatusCode, message: &str) -> Response<Body> {
    json(status, serde_json::json!({ "error": message }))
}

/// A bridge response body that keeps its tunnel checked out until it ends.
///
/// The lease rides the body rather than the request path so that a response
/// dropped early (client hang-up) still returns the tunnel, and one that fails
/// mid-stream is discarded instead of offered to the next request.
struct TiedBody {
    inner: Body,
    lease: Option<Lease>,
}

impl HttpBody for TiedBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Err(error))) => {
                // A half-read response leaves the tunnel out of step with the
                // protocol; close it rather than pooling it.
                if let Some(mut lease) = this.lease.take() {
                    lease.discard();
                }
                Poll::Ready(Some(Err(error)))
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

impl Edge {
    /// Terminate TLS on one accepted socket and serve HTTP/1.1 on it.
    pub async fn serve(self: Arc<Self>, socket: TcpStream) {
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
            async move { edge.handle(request).await }
        });
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(tls), service)
            .with_upgrades()
            .await;
    }

    /// One request: authenticate, route, and either answer or forward.
    async fn handle(&self, req: Request<Incoming>) -> Result<Response<Body>, Infallible> {
        let path = req.uri().path().to_string();
        if req.method() == Method::POST && path == "/pair" {
            return Ok(self.pair(req).await);
        }
        if path == "/health" {
            return Ok(json(StatusCode::OK, serde_json::json!({ "ok": true })));
        }

        let route = match self.authenticate(&req) {
            Some(route) => route,
            None => return Ok(fail(StatusCode::UNAUTHORIZED, "missing or unknown bearer token")),
        };

        if !path.starts_with("/api/") {
            return Ok(fail(StatusCode::NOT_FOUND, "no such route"));
        }
        // Any /api upgrade is spliced, whatever it is. The proxy deliberately
        // knows no route names: the bridge's own allowlist decides which
        // sockets exist, so adding one there needs no change here.
        if is_upgrade(&req) {
            return Ok(self.upgrade(route, req).await);
        }
        Ok(self.forward(route, req).await)
    }

    /// Resolve the bearer token to a device handle, if it is valid.
    fn authenticate(&self, req: &Request<Incoming>) -> Option<DeviceHandle> {
        let header = req.headers().get("authorization")?.to_str().ok()?;
        let token = header.strip_prefix("Bearer ")?;
        self.registry.verify(token)
    }

    /// Pair one installation: prove its fresh device key to the bridge, then
    /// mint the bearer token it will use from now on.
    async fn pair(&self, req: Request<Incoming>) -> Response<Body> {
        let body = match Limited::new(req.into_body(), MAX_BODY).collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(_) => return fail(StatusCode::PAYLOAD_TOO_LARGE, "pair body too large"),
        };
        let parsed: PairRequest = match serde_json::from_slice(&body) {
            Ok(parsed) => parsed,
            Err(_) => return fail(StatusCode::BAD_REQUEST, "pair body is not the expected JSON"),
        };
        let Ok(bridge_bytes) = B64.decode(parsed.bridge_key.trim()) else {
            return fail(StatusCode::BAD_REQUEST, "bridgeKey is not base64url")
        };
        let Ok(bridge_key): Result<[u8; 32], _> = bridge_bytes.try_into() else {
            return fail(StatusCode::BAD_REQUEST, "bridgeKey is not 32 bytes")
        };
        let token = match parsed.pairing_token.as_deref() {
            Some(text) if !text.is_empty() => match B64.decode(text) {
                Ok(bytes) => bytes,
                Err(_) => return fail(StatusCode::BAD_REQUEST, "pairingToken is not base64url"),
            },
            _ => Vec::new(),
        };
        if !self.table.contains_key(&bridge_key) {
            return fail(StatusCode::SERVICE_UNAVAILABLE, "bridge is not connected");
        }
        let name = parsed.name.unwrap_or_else(|| "phone".to_string());
        let (private_key, public_key) = match crate::noise::generate_keypair() {
            Ok(pair) => pair,
            Err(_) => return fail(StatusCode::INTERNAL_SERVER_ERROR, "could not generate a device key"),
        };
        let device_id: [u8; 32] = match public_key.try_into() {
            Ok(id) => id,
            Err(_) => return fail(StatusCode::INTERNAL_SERVER_ERROR, "bad device key length"),
        };
        let route = DeviceHandle {
            bridge_key,
            device_id,
            private_key: private_key.clone(),
            name: name.clone(),
        };
        // The handshake is the acceptance test: a pairing token that the bridge
        // rejects, or a device key it will not whitelist, fails right here and
        // never becomes a token.
        if let Err(error) = self.pool.open_tunnel(&route, &token).await {
            return fail(StatusCode::UNAUTHORIZED, &format!("bridge refused pairing: {error}"));
        }
        match self.registry.issue(bridge_key, private_key, name.clone()) {
            Ok(bearer) => json(
                StatusCode::OK,
                serde_json::json!({
                    "token": bearer,
                    "name": name,
                    "deviceId": B64.encode(device_id),
                }),
            ),
            Err(error) => fail(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
        }
    }

    /// Forward one RPC or plugin route into the tunnel.
    ///
    /// Neither body is buffered. The request streams off the client and into
    /// the tunnel; the response streams back, and the pooled connection rides
    /// the response body so it returns itself to the pool exactly when that
    /// body ends, not when the last header is written.
    async fn forward(&self, route: DeviceHandle, req: Request<Incoming>) -> Response<Body> {
        let (parts, body) = req.into_parts();
        let mut headers = parts.headers.clone();
        strip_hop(&mut headers);
        let target_path = parts.uri.path().to_string();
        let target = parts
            .uri
            .path_and_query()
            .map(|value| value.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        // Bounded but streamed: hyper pulls frames while it writes the tunnel
        // request, so a 64 MiB upload never sits in this process at once.
        let streamed = Limited::new(body, MAX_BODY).map_err(std::io::Error::other).boxed();
        let upstream = match Request::builder()
            .method(parts.method.clone())
            .uri(target)
            .body(streamed)
        {
            Ok(request) => {
                let mut request = request;
                for (name, value) in headers.iter() {
                    // Only hop-by-hop headers were removed above; everything
                    // else is the client's own and is replayed as-is.
                    request.headers_mut().insert(name, value.clone());
                }
                request
            }
            Err(_) => return fail(StatusCode::BAD_REQUEST, "bad upstream request"),
        };

        let mut lease = match self.pool.acquire(&route).await {
            Ok(lease) => lease,
            Err(error) => return fail(StatusCode::BAD_GATEWAY, &error.to_string()),
        };
        if is_bulk(&target_path) {
            lease.close_when_done();
        }
        let upstream = match lease.sender().send_request(upstream).await {
            Ok(response) => response,
            Err(error) => {
                lease.discard();
                return fail(StatusCode::BAD_GATEWAY, &error.to_string());
            }
        };
        let (parts, body) = upstream.into_parts();
        // A bridge that says `close` has already ended this connection; drop
        // the lease rather than offering a corpse to the next request.
        if parts.headers.get(CONNECTION).is_some_and(|value| value.as_bytes() == b"close") {
            lease.discard();
        }
        let mut response = Response::builder().status(parts.status);
        for (name, value) in parts.headers.iter() {
            let lower = name.as_str();
            if matches!(lower, "connection" | "transfer-encoding" | "keep-alive") {
                continue;
            }
            response = response.header(name, value);
        }
        let streamed = TiedBody {
            inner: body.map_err(std::io::Error::other).boxed(),
            lease: Some(lease),
        };
        response.body(streamed.boxed()).expect("a built response")
    }

    /// Splice a WebSocket upgrade onto a dedicated tunnel.
    ///
    /// The proxy never parses a WebSocket frame: once both sides answer 101,
    /// the two upgraded streams are joined byte for byte.
    async fn upgrade(&self, route: DeviceHandle, req: Request<Incoming>) -> Response<Body> {
        let mut headers = req.headers().clone();
        let target = req
            .uri()
            .path_and_query()
            .map(|value| value.as_str().to_string())
            .unwrap_or_else(|| "/api/remote.mux".to_string());
        let mut client_req = req;
        let client_upgrade = hyper::upgrade::on(&mut client_req);
        strip_hop_ws(&mut headers);
        let upstream = match Request::builder()
            .method(Method::GET)
            .uri(target)
            .body(boxed_full(Bytes::new()))
        {
            Ok(request) => {
                let mut request = request;
                for (name, value) in headers.iter() {
                    request.headers_mut().insert(name, value.clone());
                }
                request
            }
            Err(_) => return fail(StatusCode::BAD_REQUEST, "bad upgrade request"),
        };
        let (mut sender, _driver) = match self.pool.open_upgradable(&route).await {
            Ok(pair) => pair,
            Err(error) => return fail(StatusCode::BAD_GATEWAY, &error.to_string()),
        };
        let mut upstream = match sender.send_request(upstream).await {
            Ok(response) => response,
            Err(error) => return fail(StatusCode::BAD_GATEWAY, &error.to_string()),
        };
        if upstream.status() != StatusCode::SWITCHING_PROTOCOLS {
            return fail(StatusCode::BAD_GATEWAY, "bridge did not accept the upgrade");
        }
        let upstream_upgrade = hyper::upgrade::on(&mut upstream);
        let parts = upstream.into_parts().0;
        tokio::spawn(async move {
            if let (Ok(from_bridge), Ok(from_client)) =
                tokio::join!(upstream_upgrade, client_upgrade)
            {
                let mut to_bridge = TokioIo::new(from_bridge);
                let mut to_client = TokioIo::new(from_client);
                // A tear-down in either direction ends the splice; each side
                // carries its own flush, so a buffered tunnel still delivers.
                let _ = copy_bidirectional(&mut to_bridge, &mut to_client).await;
            }
        });
        let mut response = Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);
        for (name, value) in parts.headers.iter() {
            response = response.header(name, value);
        }
        response.body(boxed_full(Bytes::new())).expect("a built response")
    }
}

/// Strip only what must not be replayed, keeping the WebSocket handshake.
fn strip_hop_ws(headers: &mut HeaderMap) {
    for name in ["host", "authorization"] {
        headers.remove(name);
    }
    headers.insert(CONNECTION, hyper::header::HeaderValue::from_static("Upgrade"));
    headers.insert(UPGRADE, hyper::header::HeaderValue::from_static("websocket"));
}

/// Routes whose bodies are files rather than arguments.
///
/// These are the bridge's own streaming routes. They are named here only to
/// decide tunnel lifetime — the proxy does not treat their contents
/// differently, and a route missing from this list still works, it just parks
/// its tunnel for reuse like an RPC call.
fn is_bulk(path: &str) -> bool {
    matches!(path, "/api/file" | "/api/session/uploadFileBinary")
}

/// Whether a request asks to switch protocols.
pub fn is_upgrade(req: &Request<Incoming>) -> bool {
    req.headers()
        .get(UPGRADE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
        || req
            .headers()
            .get(CONNECTION)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.to_ascii_lowercase().contains("upgrade"))
}
