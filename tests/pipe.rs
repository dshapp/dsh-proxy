//! The one client contract: a WebSocket carrying the phone's own byte stream.
//!
//! The test plays a real mini-program: TLS to the proxy, a WebSocket upgrade,
//! then masked frames carrying the 37-byte preamble and a Noise_IK session
//! with the bridge. Nothing inside is readable by the proxy, which is the
//! point - it is the same end-to-end session a bare TCP socket used to carry.

use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::codec::{FramedRead, FramedWrite};

use dsh_proxy::mux::{MuxSession, MuxStreamIo};
use dsh_proxy::noise;
use common::phone::{ik_respond, NoiseStream};
use dsh_proxy::wire::{HEAD_LEN, MAGIC_BRIDGE, MAGIC_CLIENT};

mod common;
use common::{open_pipe, preamble, start_proxy, Pipe};


// ------------------------------------------------------------- the two ends


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

/// A bridge that answers Noise_IK and echoes HTTP, exactly as the Mac does.
async fn attach(addr: std::net::SocketAddr) -> [u8; 32] {
    let (private, public) = noise::generate_keypair().unwrap();
    let mut socket = TcpStream::connect(addr).await.unwrap();
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
        64,
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
            let stream = NoiseStream::new(io, transport);
            async fn echo(
                req: Request<Incoming>,
            ) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
                let bytes = req.into_body().collect().await.unwrap().to_bytes();
                Ok(Response::new(Full::new(bytes)))
            }
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service_fn(echo))
                .await;
        });
    });
    Box::leak(Box::new(session));
    tokio::time::sleep(Duration::from_millis(150)).await;
    public.try_into().unwrap()
}


/// Drive one HTTP request through Noise, inside the pipe.
async fn call(
    pipe: &mut Pipe,
    transport: &snow::StatelessTransportState,
    nonce: &mut u64,
    in_nonce: &mut u64,
    body: &[u8],
) -> Vec<u8> {
    let request = format!(
        "POST /api/session/echo HTTP/1.1\r\nhost: mobile.dsh\r\n\
         content-type: application/octet-stream\r\ncontent-length: {}\r\n\r\n",
        body.len()
    );
    let mut plain = request.into_bytes();
    plain.extend_from_slice(body);
    // One Noise message, length-prefixed, exactly as NoiseStream frames it.
    let mut sealed = vec![0u8; plain.len() + 16];
    let n = transport.write_message(*nonce, &plain, &mut sealed).unwrap();
    *nonce += 1;
    let mut framed = Vec::with_capacity(n + 2);
    framed.extend_from_slice(&(n as u16).to_be_bytes());
    framed.extend_from_slice(&sealed[..n]);
    pipe.send(&framed).await.unwrap();

    let length = pipe.recv(2).await.unwrap();
    let length = u16::from_be_bytes([length[0], length[1]]) as usize;
    let ciphertext = pipe.recv(length).await.unwrap();
    let mut opened = vec![0u8; length];
    let n = transport
        .read_message(*in_nonce, &ciphertext, &mut opened)
        .unwrap();
    *in_nonce += 1;
    opened.truncate(n);
    opened
}

/// The whole contract in one path: WSS in, Noise_IK end to end, HTTP inside.
#[tokio::test]
async fn a_websocket_carries_an_end_to_end_noise_session() {
    let (addr, cert) = start_proxy().await;
    let bridge_key = attach(addr).await;
    let mut pipe = open_pipe(addr, &cert, 64 * 1024).await.unwrap();

    let head = preamble(&MAGIC_CLIENT, 1, &bridge_key);
    pipe.send(&head).await.unwrap();

    let (device_private, _) = noise::generate_keypair().unwrap();
    let mut handshake = snow::Builder::new(dsh_proxy::wire::NOISE_IK.parse().unwrap())
        .local_private_key(&device_private)
        .remote_public_key(&bridge_key)
        .prologue(&head)
        .build_initiator()
        .unwrap();
    let mut buf = vec![0u8; 1024];
    let n = handshake.write_message(&[], &mut buf).unwrap();
    let mut framed = Vec::new();
    framed.extend_from_slice(&(n as u16).to_be_bytes());
    framed.extend_from_slice(&buf[..n]);
    pipe.send(&framed).await.unwrap();

    let length = pipe.recv(2).await.unwrap();
    let length = u16::from_be_bytes([length[0], length[1]]) as usize;
    let msg2 = pipe.recv(length).await.unwrap();
    handshake.read_message(&msg2, &mut buf).unwrap();
    let transport = handshake.into_stateless_transport_mode().unwrap();

    let mut out_nonce = 0u64;
    let mut in_nonce = 0u64;
    let response = call(&mut pipe, &transport, &mut out_nonce, &mut in_nonce, b"hello").await;
    let text = String::from_utf8_lossy(&response);
    assert!(text.starts_with("HTTP/1.1 200"), "unexpected reply: {text}");
    assert!(text.ends_with("hello"), "body not echoed: {text}");
}

/// A mini-program sends small frames; the pipe must reassemble a stream from
/// them without caring where the boundaries fell.
#[tokio::test]
async fn a_preamble_split_across_frames_still_routes() {
    let (addr, cert) = start_proxy().await;
    let bridge_key = attach(addr).await;
    // Seven bytes per frame: the 37-byte preamble spans six of them.
    let mut pipe = open_pipe(addr, &cert, 7).await.unwrap();

    let head = preamble(&MAGIC_CLIENT, 1, &bridge_key);
    pipe.send(&head).await.unwrap();

    let (device_private, _) = noise::generate_keypair().unwrap();
    let mut handshake = snow::Builder::new(dsh_proxy::wire::NOISE_IK.parse().unwrap())
        .local_private_key(&device_private)
        .remote_public_key(&bridge_key)
        .prologue(&head)
        .build_initiator()
        .unwrap();
    let mut buf = vec![0u8; 1024];
    let n = handshake.write_message(&[], &mut buf).unwrap();
    let mut framed = Vec::new();
    framed.extend_from_slice(&(n as u16).to_be_bytes());
    framed.extend_from_slice(&buf[..n]);
    pipe.send(&framed).await.unwrap();

    let length = pipe.recv(2).await.unwrap();
    let length = u16::from_be_bytes([length[0], length[1]]) as usize;
    let msg2 = pipe.recv(length).await.unwrap();
    handshake.read_message(&msg2, &mut buf).unwrap();
    let transport = handshake.into_stateless_transport_mode().unwrap();

    let mut out_nonce = 0u64;
    let mut in_nonce = 0u64;
    let response = call(&mut pipe, &transport, &mut out_nonce, &mut in_nonce, b"split").await;
    assert!(String::from_utf8_lossy(&response).ends_with("split"));
}

/// Keepalive must be answered, or a mini-program's socket dies quietly.
#[tokio::test]
async fn a_ping_is_answered_with_a_pong() {
    let (addr, cert) = start_proxy().await;
    let _ = attach(addr).await;
    let mut pipe = open_pipe(addr, &cert, 4096).await.unwrap();
    pipe.ping(b"alive").await.unwrap();
    let (opcode, payload) = tokio::time::timeout(Duration::from_secs(5), pipe.recv_control())
        .await
        .expect("no pong")
        .unwrap();
    assert_eq!(opcode, 0xa, "expected a pong");
    assert_eq!(payload, b"alive");
}

/// An unknown bridge key is dropped without a word, as it always was.
#[tokio::test]
async fn an_unknown_bridge_key_is_dropped() {
    let (addr, cert) = start_proxy().await;
    let _ = attach(addr).await;
    let mut pipe = open_pipe(addr, &cert, 4096).await.unwrap();
    pipe.send(&preamble(&MAGIC_CLIENT, 1, &[9u8; 32])).await.unwrap();
    pipe.send(b"anything").await.unwrap();
    let outcome = tokio::time::timeout(Duration::from_secs(3), pipe.recv(1)).await;
    match outcome {
        Err(_) => {}
        Ok(result) => assert!(result.is_err(), "an unknown key must get nothing back"),
    }
}
