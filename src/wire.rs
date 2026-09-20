//! Wire constants shared by both connection kinds. See PROTOCOL.md.

/// Preamble magic of a mobile client connection.
pub const MAGIC_CLIENT: [u8; 4] = *b"DSHC";
/// Preamble magic of a bridge connection.
pub const MAGIC_BRIDGE: [u8; 4] = *b"DSHB";
/// Protocol version carried by the preamble.
pub const VERSION: u8 = 1;
/// magic(4) + ver(1) + key(32)
pub const HEAD_LEN: usize = 37;

/// Noise suite spoken by bridges.
pub const NOISE_XX: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
/// Noise suite spoken by phones. The proxy now terminates TLS for every phone
/// and speaks IK on its behalf, so this direction lives here too.
pub const NOISE_IK: &str = "Noise_IK_25519_ChaChaPoly_SHA256";

/// Largest Noise message on the wire (length prefix is u16).
pub const MAX_NOISE_MSG: usize = 65535;
/// Largest message allowed during the handshake, before a peer is trusted.
/// The three XX messages are a few hundred bytes; 64 KiB is not.
pub const MAX_HANDSHAKE_MSG: usize = 1024;
/// ChaChaPoly authentication tag.
pub const TAG_LEN: usize = 16;

/// mux frame kinds.
pub const KIND_OPEN: u8 = 0;
pub const KIND_DATA: u8 = 1;
pub const KIND_CLOSE: u8 = 2;
pub const KIND_WINDOW: u8 = 3;

/// mux frame header: streamId(u32) + kind(u8) + len(u16) + rsv(u8).
pub const FRAME_HEAD: usize = 8;
/// Largest mux payload; keeps one frame inside one Noise message with room to spare.
pub const MAX_PAYLOAD: usize = 16384;
/// Per-stream receive window.
pub const WINDOW: u32 = 256 * 1024;

/// Resource guard, not authentication: one bridge cannot be made to hold
/// unbounded state by whoever knows its public key. A phone keeps a live
/// socket plus a small connection pool, so this is thousands of phones.
pub const MAX_STREAMS_PER_BRIDGE: usize = 2048;
