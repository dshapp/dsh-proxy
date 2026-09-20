# dsh-proxy

The only public component of dsh mobile access. **One TCP port**, one contract
for every client — Android, the WeChat mini-program, and anything later.

```
Android ─┐
         ├─ HTTPS/1.1 + WSS, Bearer token ─> dsh-proxy ──Noise_IK──> Mac (dsh-mobile-bridge)
Mini-prog┘                                      │
                                            TLS 1.3 + implicit HTTP/1.1
```

The proxy reads one byte to decide what a connection is:

- `0x16` — a TLS ClientHello. Terminate it, then serve HTTPS/WSS. This is the
  **only** end-user contract.
- anything else — the historical 37-byte preamble (`DSHB` bridge, `DSHC`
  phone). Kept so existing bridges register unchanged; the raw-phone path is
  legacy and no longer the documented contract.

So end users reach the proxy exactly like any HTTPS API: `POST /pair`, then
`POST /api/<method>` or `GET /api/remote.mux` with `Authorization: Bearer
<token>`. There is no branch on client type anywhere in the request path — the
only decision is which bridge the token addresses.

## Authentication

Four layers, each independent of the others:

| layer | what it proves | where |
|---|---|---|
| L0 TLS 1.3 | the client reached the real proxy (certificates, ALPN `http/1.1`) | this proxy |
| L1 Bearer token | this installation is paired, and to which bridge | this proxy |
| L2 Noise_IK | the proxy may speak for a whitelisted device to the bridge | proxy ↔ Mac |
| L3 bridge allowlist | the device key was authorized during pairing | Mac |

Tokens are random 32-byte values stored **hashed** (SHA-256) and compared in
constant time; the registry file is written `0o600`. A client never chooses or
sees a bridge key or device key — the proxy generates the device keypair at
pairing time and the token is the only handle the client holds. A stolen token
therefore buys exactly one installation's access, and revoking it is deleting
one registry row.

### Pairing

```
dshm://<host>/<bridgeKey>#<pairingToken>
        │                    │
        │                    └─ one-shot, consumed by the bridge's allowlist
        └─ which Mac to reach
```

`POST /pair {bridgeKey, pairingToken, name}` makes the proxy generate an
X25519 device key, run Noise_IK to that bridge with the pairing token as the
first payload, and — only if the bridge's `DeviceRegistry` accepts the key —
mint and return the Bearer token. A rejected pairing never becomes a token.

## Routes

| route | behaviour |
|---|---|
| `POST /pair` | proxy-local; validates against the bridge, returns a token |
| `GET /health` | liveness, no auth |
| `POST/GET /api/<method>` | authenticated, forwarded into a Noise_IK tunnel |
| `GET /api/remote.mux` + `Upgrade` | authenticated; both sides answer 101 and the streams are spliced byte for byte |

The proxy never parses a WebSocket frame: the upgrade is a byte splice. That is
what a mini-program needs, since it can only use WSS, never raw TCP.

## Run

```sh
cargo build --release
./target/release/dsh-proxy --listen 0.0.0.0:443 \
    --key <base64 x25519 private> \
    --tls-cert /etc/dsh/fullchain.pem --tls-key /etc/dsh/privkey.pem \
    --state /var/lib/dsh/proxy-state.json
```

| flag | default | meaning |
|---|---|---|
| `--listen` | `0.0.0.0:443` | the single public port |
| `--key` | generated | bridge-link static key; printed at startup |
| `--tls-cert` / `--tls-key` | — | PEM certificate and key; required for real clients |
| `--tls-self-signed` | off | mint a throwaway certificate (local development only) |
| `--state` | none | registry file; without it tokens are lost on restart |
| `--max-tunnels-per-device` | 8 | pooled tunnels held per installation |

Plus the original admission limits (`--max-bridges`, `--max-bridges-per-ip`,
`--max-streams-per-bridge`, `--handshake-timeout-ms`), unchanged.

### State

The old proxy promised *no disk, no state*. The unified edge needs both: a
Bearer token must survive a restart or every client must re-pair. `--state`
names one JSON file written atomically and `0o600`; omit it and the proxy still
runs, but every restart invalidates every token. Bridge links are still pure
memory — a restarted proxy repopulates them as bridges reconnect.

## TLS

rustls with the `ring` provider, explicit rather than process-global. ALPN
advertises **only `http/1.1`**: no h2 (a mini-program's WSS is HTTP/1.1), and
no RFC 8441 extended CONNECT. A certificate and key are loaded once at startup;
a reload needs a restart.

## Tests

`cargo test` runs two suites:

- `tests/tunnel.rs` (11) — the bridge link and mux: round trip, 3 MiB bulk
  through the receive window, 50 concurrent streams, keepalive echo, silent
  drops for unknown key / version / magic, per-IP refusal, stalled-handshake
  reaping, the exact stream budget under a race, one stream's flood costing
  only that stream, duplicate registration.
- `tests/edge.rs` (6) — the whole public contract over real TLS with an
  independent bridge: pairing mints a working token, an unknown token is
  refused, `/api` round trip, a 768 KiB body (beyond one 256 KiB window), the
  WSS upgrade spliced, and the buffered-message regression below.

### One bug worth remembering

At 65 504 bytes a request arrives as one maximum-size Noise message plus a
small one, and the socket goes quiet on that boundary. `poll_read` used to ask
for more ciphertext while a complete message already sat in its buffer, so the
read hung. It now drains buffered messages first. The regression test is
`a_complete_buffered_message_is_read_without_more_ciphertext`.

## Measured

`scripts/bench.sh` runs the old (commit `38c1eab`) and new edges through the
same bridge and the same harness. Headline: **1.96× rps at one connection, 3
964 vs 2 894 connections/s, bulk unchanged at scale (548 vs 556 MB/s)**, with
4.3× the CPU at 32 concurrent connections — the per-request authentication the
old byte-relay never did. Full numbers, method and caveats:
[BENCHMARKS.md](BENCHMARKS.md).

## Security delta

The old proxy could not decrypt application traffic: Noise_IK ran phone to Mac.
The unified edge terminates TLS and runs Noise_IK itself, so the proxy is now
inside the trust boundary and can see plaintext. That is the deliberate price
of one uniform contract a mini-program can speak. Layer L0–L1 guard the
outside, L2–L3 still guard the bridge.
