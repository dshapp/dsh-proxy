//! Noise_XX responder, and the codec that carries mux frames over it.
//!
//! The proxy never decrypts application traffic: this is only the bridge link,
//! whose handshake is also the bridge's proof of holding its static key.
//!
//! Transport state is `snow::StatelessTransportState`, whose seal/open take
//! `&self` and an explicit nonce. Each direction is owned by one task with its
//! own counter, so the two directions never share a lock and never contend.

use std::io::{Error, ErrorKind, Result};
use std::sync::Arc;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use snow::StatelessTransportState;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::codec::{Decoder, Encoder};

use crate::mux::Frame;
use crate::wire::{
    FRAME_HEAD, MAX_HANDSHAKE_MSG, MAX_NOISE_MSG, MAX_PAYLOAD, NOISE_IK, NOISE_XX, TAG_LEN,
};

fn bad(error: impl ToString) -> Error {
    Error::new(ErrorKind::InvalidData, error.to_string())
}

/// Seals mux frames onto the bridge link. Owns the sending nonce.
pub struct NoiseEncoder {
    transport: Arc<StatelessTransportState>,
    nonce: u64,
    /// Reused plaintext staging buffer: no allocation per frame.
    scratch: Vec<u8>,
}

/// Opens mux frames arriving from the bridge. Owns the receiving nonce.
pub struct NoiseDecoder {
    transport: Arc<StatelessTransportState>,
    nonce: u64,
}

/// Split one finished handshake into the two halves of the link.
pub fn codecs(transport: StatelessTransportState) -> (NoiseDecoder, NoiseEncoder) {
    let transport = Arc::new(transport);
    (
        NoiseDecoder { transport: transport.clone(), nonce: 0 },
        NoiseEncoder {
            transport,
            nonce: 0,
            scratch: Vec::with_capacity(FRAME_HEAD + MAX_PAYLOAD),
        },
    )
}

impl Encoder<Frame> for NoiseEncoder {
    type Error = Error;

    /// Encode and seal straight into the `Framed` write buffer: the frame
    /// header, the AEAD output and the length prefix all land in one buffer,
    /// so a frame costs no allocation of its own.
    fn encode(&mut self, frame: Frame, dst: &mut BytesMut) -> Result<()> {
        self.scratch.clear();
        self.scratch.put_u32(frame.id);
        self.scratch.put_u8(frame.kind);
        self.scratch.put_u16(frame.payload.len() as u16);
        self.scratch.put_u8(0);
        self.scratch.extend_from_slice(&frame.payload);

        let sealed = self.scratch.len() + TAG_LEN;
        if sealed > MAX_NOISE_MSG {
            return Err(bad("noise message too large"));
        }
        dst.reserve(2 + sealed);
        dst.put_u16(sealed as u16);
        let start = dst.len();
        dst.resize(start + sealed, 0);
        let n = self
            .transport
            .write_message(self.nonce, &self.scratch, &mut dst[start..])
            .map_err(bad)?;
        dst.truncate(start + n);
        self.nonce += 1;
        Ok(())
    }
}

impl Decoder for NoiseDecoder {
    type Item = Bytes;
    type Error = Error;

    /// `Framed` hands us a buffer it filled with large reads, so a frame no
    /// longer costs its own pair of syscalls.
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Bytes>> {
        if src.len() < 2 {
            src.reserve(2);
            return Ok(None);
        }
        let len = u16::from_be_bytes([src[0], src[1]]) as usize;
        if len < TAG_LEN {
            return Err(bad("short noise message"));
        }
        if src.len() < 2 + len {
            src.reserve(2 + len - src.len());
            return Ok(None);
        }
        src.advance(2);
        let sealed = src.split_to(len);

        let mut plain = BytesMut::zeroed(len - TAG_LEN);
        let n = self
            .transport
            .read_message(self.nonce, &sealed, &mut plain)
            .map_err(bad)?;
        self.nonce += 1;
        plain.truncate(n);
        Ok(Some(plain.freeze()))
    }
}

/// Read one `[u16 len][data]` frame. Handshake only — three messages, before
/// the link is framed, so it reads exactly and buffers nothing.
///
/// The length is attacker-controlled, so it is checked against the handshake
/// ceiling *before* allocating: an unauthenticated peer must not be able to
/// name a 64 KiB buffer per connection.
async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut len = [0u8; 2];
    reader.read_exact(&mut len).await?;
    let len = u16::from_be_bytes(len) as usize;
    if len > MAX_HANDSHAKE_MSG {
        return Err(bad("handshake message too large"));
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).await?;
    Ok(body)
}

/// Write one `[u16 len][data]` frame. Handshake only.
///
/// The explicit flush matters: a handshake frame is a few hundred bytes, while
/// a buffering transport (the proxy's mux stream) only emits on flush or once
/// its buffer fills. Without it the handshake would sit in the buffer, the two
/// ends would wait on each other, and the tunnel would never come up.
async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, body: &[u8]) -> Result<()> {
    if body.len() > MAX_HANDSHAKE_MSG {
        return Err(bad("handshake message too large"));
    }
    let mut out = Vec::with_capacity(body.len() + 2);
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    writer.write_all(&out).await?;
    writer.flush().await
}

/// Respond to a bridge's Noise_XX handshake.
///
/// XX carries the initiator's static key in message 3, authenticated by the
/// handshake itself, so the returned key is proof of possession — no challenge,
/// no signature, no registration step.
pub async fn xx_respond<S: AsyncRead + AsyncWrite + Unpin>(
    socket: &mut S,
    private_key: &[u8],
    prologue: &[u8],
) -> Result<([u8; 32], StatelessTransportState)> {
    let params = NOISE_XX.parse().map_err(bad)?;
    let mut handshake = snow::Builder::new(params)
        .local_private_key(private_key)
        .prologue(prologue)
        .build_responder()
        .map_err(bad)?;

    // XX's three messages are a few hundred bytes at most; the transport
    // ceiling is for the mux that follows, not for this.
    let mut buf = vec![0u8; MAX_HANDSHAKE_MSG];
    let msg1 = read_frame(socket).await?;
    handshake.read_message(&msg1, &mut buf).map_err(bad)?;
    let n = handshake.write_message(&[], &mut buf).map_err(bad)?;
    write_frame(socket, &buf[..n]).await?;
    let msg3 = read_frame(socket).await?;
    handshake.read_message(&msg3, &mut buf).map_err(bad)?;

    let remote = handshake
        .get_remote_static()
        .ok_or_else(|| bad("bridge sent no static key"))?;
    let key: [u8; 32] = remote.try_into().map_err(|_| bad("bad static key length"))?;
    let transport = handshake.into_stateless_transport_mode().map_err(bad)?;
    Ok((key, transport))
}

/// Drive the *phone* side of a Noise_IK handshake with a bridge.
///
/// This is the proxy standing in for a paired device: it presents a device
/// static key the bridge has whitelisted (or a one-shot pairing token, in the
/// first message's payload), and verifies the bridge's static key against the
/// routing key in the preamble. Nothing else changes on the bridge — it sees
/// an ordinary phone and runs its existing IK responder unchanged.
///
/// @param device_private - the device's 32-byte X25519 static private key.
/// @param bridge_public - the bridge's 32-byte static public key (bridgeKey).
/// @param prologue - the exact 37-byte preamble that was written to the wire.
/// @param first_payload - pairing token on first contact, empty afterwards.
pub async fn ik_initiate<S: AsyncRead + AsyncWrite + Unpin>(
    socket: &mut S,
    device_private: &[u8],
    bridge_public: &[u8],
    prologue: &[u8],
    first_payload: &[u8],
) -> Result<StatelessTransportState> {
    let params = NOISE_IK.parse().map_err(bad)?;
    let mut handshake = snow::Builder::new(params)
        .local_private_key(device_private)
        .remote_public_key(bridge_public)
        .prologue(prologue)
        .build_initiator()
        .map_err(bad)?;

    let mut buf = vec![0u8; MAX_HANDSHAKE_MSG];
    let n = handshake.write_message(first_payload, &mut buf).map_err(bad)?;
    write_frame(socket, &buf[..n]).await?;
    let msg2 = read_frame(socket).await?;
    handshake.read_message(&msg2, &mut buf).map_err(bad)?;

    // IK already proves the responder to us, but assert the identity anyway:
    // a bridge that answered with the wrong static key is not our bridge.
    match handshake.get_remote_static() {
        Some(remote) if remote == bridge_public => {}
        Some(_) => return Err(bad("bridge proved an unexpected static key")),
        None => return Err(bad("bridge sent no static key")),
    }
    handshake.into_stateless_transport_mode().map_err(bad)
}

/// Respond to a device's Noise_IK handshake — the bridge's side of the same
/// protocol the proxy initiates above.
///
/// This is what a real bridge runs; it lives here so the loopback harness is an
/// independent implementation of the peer rather than a second copy of the
/// proxy's own code.
///
/// @returns the device's static public key, the first message's payload (the
/// pairing token on first contact) and the finished transport.
pub async fn ik_respond<S: AsyncRead + AsyncWrite + Unpin>(
    socket: &mut S,
    bridge_private: &[u8],
    prologue: &[u8],
) -> Result<([u8; 32], Vec<u8>, StatelessTransportState)> {
    let params = NOISE_IK.parse().map_err(bad)?;
    let mut handshake = snow::Builder::new(params)
        .local_private_key(bridge_private)
        .prologue(prologue)
        .build_responder()
        .map_err(bad)?;

    // IK's first message carries the initiator's static key and its payload;
    // the second is the responder's only flight.
    let mut buf = vec![0u8; MAX_HANDSHAKE_MSG];
    let msg1 = read_frame(socket).await?;
    let mut payload = vec![0u8; MAX_HANDSHAKE_MSG];
    let n = handshake
        .read_message(&msg1, &mut payload)
        .map_err(bad)?;
    payload.truncate(n);

    let remote = handshake
        .get_remote_static()
        .ok_or_else(|| bad("device sent no static key"))?;
    let key: [u8; 32] = remote.try_into().map_err(|_| bad("bad static key length"))?;

    let n = handshake.write_message(&[], &mut buf).map_err(bad)?;
    write_frame(socket, &buf[..n]).await?;

    let transport = handshake.into_stateless_transport_mode().map_err(bad)?;
    Ok((key, payload, transport))
}

/// Generate an X25519 static key pair.
pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    let params = NOISE_XX.parse().map_err(bad)?;
    let pair = snow::Builder::new(params).generate_keypair().map_err(bad)?;
    Ok((pair.private, pair.public))
}

/// Derive the public key of a stored private key.
pub fn public_key_of(private_key: &[u8]) -> Result<[u8; 32]> {
    let bytes: [u8; 32] = private_key
        .try_into()
        .map_err(|_| bad("private key must be 32 bytes"))?;
    let secret = x25519_dalek::StaticSecret::from(bytes);
    Ok(x25519_dalek::PublicKey::from(&secret).to_bytes())
}

#[cfg(test)]
mod tests {
    /// snow and x25519-dalek must agree, or a bridge would pin a key the proxy
    /// never proves.
    #[test]
    fn public_key_matches_snow() {
        for _ in 0..16 {
            let (private, public) = super::generate_keypair().unwrap();
            assert_eq!(super::public_key_of(&private).unwrap().to_vec(), public);
        }
    }
}
