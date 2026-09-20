//! Paired-device registry and bearer tokens.
//!
//! With TLS terminating here, the proxy holds one X25519 device key per paired
//! installation: the key is what a bridge whitelists, so the bridge's existing
//! device list, 180-day expiry and revocation keep working unchanged. A client
//! never holds that key - it holds a bearer token, and only the token's hash is
//! stored, so a leaked state file is not a set of usable credentials.
//!
//! The file is optional: with no --state the registry is memory-only and a
//! restart asks every client to pair again.

use std::io;
use std::path::PathBuf;
use std::sync::RwLock;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use ring::digest;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

/// Everything one request needs to address and authenticate a bridge.
#[derive(Clone)]
pub struct DeviceHandle {
    /// Routing key, and the bridge's static public key.
    pub bridge_key: [u8; 32],
    /// The device's static public key; the bridge's whitelist entry.
    pub device_id: [u8; 32],
    /// The device's static private key, held only by the proxy.
    pub private_key: Vec<u8>,
    /// Label shown on the Mac's device list.
    pub name: String,
}

/// One persisted pairing.
#[derive(Serialize, Deserialize)]
struct Record {
    bridge_key: String,
    device_id: String,
    private_key: String,
    /// SHA-256 of the bearer token, base64url. The token itself is not stored.
    token_hash: String,
    name: String,
    created_at: u64,
}

/// The set of paired installations.
pub struct Registry {
    records: RwLock<Vec<Record>>,
    path: Option<PathBuf>,
}

fn other(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::Other, error.to_string())
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Hash a token. Tokens are 256-bit, so a plain hash needs no salt or stretch.
fn hash_token(token: &str) -> [u8; 32] {
    let digest = digest::digest(&digest::SHA256, token.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

fn random_token() -> io::Result<String> {
    let mut buf = [0u8; 32];
    SystemRandom::new()
        .fill(&mut buf)
        .map_err(|_| other("system randomness unavailable"))?;
    Ok(B64.encode(buf))
}

/// Compare two short byte strings without leaking where they differ.
///
/// ring's own helper moved to an internal module, so this is the two-line
/// accumulator it always was: fixed work, no early exit.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in a.iter().zip(b.iter()) {
        difference |= left ^ right;
    }
    difference == 0
}

fn decode32(text: &str) -> io::Result<[u8; 32]> {
    let bytes = B64.decode(text).map_err(other)?;
    bytes.try_into().map_err(|_| other("expected a 32-byte key"))
}

impl Registry {
    /// Open the registry, loading the path when one is configured.
    pub fn open(path: Option<String>) -> io::Result<Self> {
        let path = path.map(PathBuf::from);
        let records = match &path {
            Some(file) if file.exists() => {
                let text = std::fs::read_to_string(file)?;
                serde_json::from_str(&text).map_err(other)?
            }
            _ => Vec::new(),
        };
        Ok(Self { records: RwLock::new(records), path })
    }

    /// Admit a freshly handshaken device and mint its bearer token.
    ///
    /// Called only after the bridge itself accepted the device key, so the
    /// registry never vouches for a key the bridge has not whitelisted.
    pub fn issue(
        &self,
        bridge_key: [u8; 32],
        private_key: Vec<u8>,
        name: String,
    ) -> io::Result<String> {
        let device_id = crate::noise::public_key_of(&private_key)?;
        let token = random_token()?;
        let record = Record {
            bridge_key: B64.encode(bridge_key),
            device_id: B64.encode(device_id),
            private_key: B64.encode(&private_key),
            token_hash: B64.encode(hash_token(&token)),
            name,
            created_at: now(),
        };
        // Re-pairing the same installation replaces its old token rather than
        // leaving a second live credential behind.
        {
            let mut records = self.records.write().expect("registry lock");
            records.retain(|existing| {
                !(existing.bridge_key == record.bridge_key && existing.device_id == record.device_id)
            });
            records.push(record);
        }
        self.save()?;
        Ok(token)
    }

    /// Resolve a presented bearer token, or None when it is unknown.
    pub fn verify(&self, token: &str) -> Option<DeviceHandle> {
        let presented = hash_token(token);
        let records = self.records.read().expect("registry lock");
        for record in records.iter() {
            let stored = B64.decode(&record.token_hash).ok()?;
            // Linear and constant-time: the set is tiny, and the comparison
            // says nothing through its timing.
            if constant_time_eq(&stored, &presented) {
                return Some(DeviceHandle {
                    bridge_key: decode32(&record.bridge_key).ok()?,
                    device_id: decode32(&record.device_id).ok()?,
                    private_key: B64.decode(&record.private_key).ok()?,
                    name: record.name.clone(),
                });
            }
        }
        None
    }

    /// Number of paired installations, for /status.
    pub fn len(&self) -> usize {
        self.records.read().expect("registry lock").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Persist, when a path is configured. Written to a sibling then renamed,
    /// so a crash never leaves a half file behind.
    fn save(&self) -> io::Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        let text = {
            let records = self.records.read().expect("registry lock");
            serde_json::to_string_pretty(&*records).map_err(other)?
        };
        let temporary = path.with_extension("tmp");
        std::fs::write(&temporary, text)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&temporary, path)
    }
}
