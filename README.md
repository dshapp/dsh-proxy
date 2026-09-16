# dsh-proxy

The only public component of dsh mobile access. One TCP port, no TLS, no
certificate, no configuration file, no disk, no state to restore.

```
iPhone ──bare TCP──┐
                   ├─> dsh-proxy ──one long connection──> Mac (dsh-mobile-bridge)
Mac bridge ────────┘
```

Every connection starts with the same 37-byte plaintext preamble. The proxy
reads exactly that:

- `DSHB` — a bridge. A Noise_XX handshake follows; the static key it proves
  becomes the routing key. A minimal mux then rides that link.
- `DSHC` — a phone. The 32-byte key addresses a bridge; the proxy opens one mux
  stream, forwards the preamble, and copies bytes. Unknown key: silent drop.

The phone's Noise_IK session terminates on the Mac, so the proxy cannot decrypt
anything it carries. Its whole state is `DashMap<[u8; 32], MuxSession>` in
memory — restart it and every bridge is back within seconds.

See [../dsh-mobile-bridge/PROTOCOL.md](../dsh-mobile-bridge/PROTOCOL.md) for the
wire format.

## Run

```sh
cargo build --release
./target/release/dsh-proxy --listen 0.0.0.0:443 --key <base64 x25519 private>
```

`--listen` defaults to `0.0.0.0:443` (port 443 survives restrictive networks).
Without `--key` a key pair is generated at startup; the public half is printed
so a bridge can pin it. Local development:

```sh
./target/release/dsh-proxy --listen 127.0.0.1:8787
```

`cargo test` runs the suite in `tests/tunnel.rs`, which drives a real proxy
over loopback with an independent bridge written against PROTOCOL.md: round
trip, 3 MiB bulk transfer through the window, 50 concurrent streams,
keepalive echo, and the silent drops for unknown key, version and magic.

## Measured

One M-series Mac running proxy, bridge and load generator together (so these
are floors, not ceilings), against 100–300 simulated phones:

| | result |
|---|---|
| Noise_IK handshakes | 1374/s, p50 33 ms, 0 failures over 1000 |
| `/api` calls through the tunnel | ~2000 rps, p50 ~40 ms, p99 ~100 ms, 0 failures over 10000 |
| same calls straight at loopback | ~3000–9000 rps — the tunnel costs roughly one local round trip |
| live Remote-stream sockets | 300 concurrent, all still open, upgrade p50 220 ms |
| bulk transfer | 36 MiB/s down (paged transcripts), 141 MiB/s up |
| proxy memory | ~5 MB RSS with 400 streams, flat across runs |

Per-bridge stream ceiling is `MAX_STREAMS_PER_BRIDGE` (2048); over it, new
phone connections are dropped without touching the bridge link.
