//! Noise_XX responder and the length-prefixed transport used with bridges.
//!
//! The proxy never decrypts application traffic: this is only the bridge link,
//! whose handshake is also the bridge's proof of holding its static key.

use std::io::{Error, ErrorKind, Result};
use std::sync::Mutex;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::wire::{MAX_NOISE_MSG, NOISE_XX};

fn bad(error: impl ToString) -> Error {
    Error::new(ErrorKind::InvalidData, error.to_string())
}

/// Sendable Noise transport: the socket halves stay outside the lock, so the
/// mutex is held only for the microseconds of one AEAD operation.
pub struct NoiseTransport {
    inner: Mutex<snow::TransportState>,
}

impl NoiseTransport {
    /// Seal one plaintext message.
    pub fn encrypt(&self, plain: &[u8]) -> Result<Vec<u8>> {
        let mut out = vec![0u8; plain.len() + 16];
        let mut state = self.inner.lock().map_err(bad)?;
        let n = state.write_message(plain, &mut out).map_err(bad)?;
        out.truncate(n);
        Ok(out)
    }

    /// Open one ciphertext message.
    pub fn decrypt(&self, cipher: &[u8]) -> Result<Vec<u8>> {
        let mut out = vec![0u8; cipher.len()];
        let mut state = self.inner.lock().map_err(bad)?;
        let n = state.read_message(cipher, &mut out).map_err(bad)?;
        out.truncate(n);
        Ok(out)
    }
}

/// Read one `[u16 len][data]` frame.
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut len = [0u8; 2];
    reader.read_exact(&mut len).await?;
    let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
    reader.read_exact(&mut body).await?;
    Ok(body)
}

/// Write one `[u16 len][data]` frame.
pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, body: &[u8]) -> Result<()> {
    if body.len() > MAX_NOISE_MSG {
        return Err(bad("noise message too large"));
    }
    let mut out = Vec::with_capacity(body.len() + 2);
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    writer.write_all(&out).await
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
) -> Result<([u8; 32], NoiseTransport)> {
    let params = NOISE_XX.parse().map_err(bad)?;
    let mut handshake = snow::Builder::new(params)
        .local_private_key(private_key)
        .prologue(prologue)
        .build_responder()
        .map_err(bad)?;

    let mut buf = vec![0u8; MAX_NOISE_MSG];
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
    let transport = handshake.into_transport_mode().map_err(bad)?;
    Ok((key, NoiseTransport { inner: Mutex::new(transport) }))
}

/// Generate an X25519 static key pair.
pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    let params = NOISE_XX.parse().map_err(bad)?;
    let pair = snow::Builder::new(params).generate_keypair().map_err(bad)?;
    Ok((pair.private, pair.public))
}

/// Derive the public key of a stored private key.
pub fn public_key_of(private_key: &[u8]) -> Result<Vec<u8>> {
    use snow::params::DHChoice;
    use snow::resolvers::{CryptoResolver, DefaultResolver};
    let mut dh = DefaultResolver
        .resolve_dh(&DHChoice::Curve25519)
        .ok_or_else(|| bad("no x25519 backend"))?;
    dh.set(private_key);
    Ok(dh.pubkey().to_vec())
}
