# dsh-proxy

[中文](README.zh.md)

The public relay behind [DSH App](https://dshapp.github.io/en/) mobile access.
The Android app, the WeChat mini program and your Mac's
[`dsh-mobile-bridge`](https://github.com/dshapp/dsh-mobile-bridge) all dial
**out** to it, so the Mac never opens a port. It is one static binary on one
TCP port; it carries only ciphertext and keeps nothing on disk.

```
Android / mini program ──wss://host/tunnel──┐
                                            ├─> dsh-proxy ──one long link──> Mac (dsh-mobile-bridge) ──> dsh
Mac bridge ─────────────DSHB preamble───────┘
          Noise_IK, end to end between the phone and the Mac
```

## What you get

- **One port, TLS only.** Phones and bridges share a single listening port.
  There is no unencrypted mode.
- **Ciphertext only.** The session inside each tunnel is Noise_IK between the
  phone and the Mac. The proxy holds no key that could read it.
- **Nothing worth stealing.** No pairing route, no token store, no state file.
  A restart costs only the seconds a bridge takes to reconnect.
- **One contract for every client.** A WeChat mini program cannot open a raw
  socket, but it can open a WebSocket, so `wss://host/tunnel` serves both
  clients unchanged.
- **Cheap admission control.** Per-IP and per-bridge ceilings, enforced
  without decrypting or looking anything up.
- **Ships as one file.** CI builds a statically linked Linux binary: copy it
  over and run it.

> **Do you need to run this?** Only to self-host. `dsh-mobile-bridge` ships
> pointed at a public instance (`dshproxy.wuhaolin.cn:8787`, key pinned), so
> mobile access works without one of your own.

## Requirements

- A host reachable from the internet with one open TCP port (443 by default).
- A TLS certificate for the hostname the phones will dial, such as Let's
  Encrypt `fullchain.pem` / `privkey.pem`. Phones verify it.
- Rust stable, only if you build from source.

## Install

**Prebuilt (Linux x86_64).** Every push to `main` runs
[build.yml](.github/workflows/build.yml), which tests, builds a static musl
binary, checks that it starts, and uploads it as the `dsh-proxy-linux-x86_64`
artifact together with its SHA-256. Download the artifact from the run page,
then:

```sh
unzip dsh-proxy-linux-x86_64.zip
sha256sum -c dsh-proxy.sha256
install -m 755 target/x86_64-unknown-linux-musl/release/dsh-proxy /usr/local/bin/
```

**From source.**

```sh
cargo build --release --locked             # -> target/release/dsh-proxy
# a static Linux binary, as CI builds it (needs musl-tools):
rustup target add x86_64-unknown-linux-musl
cargo build --release --locked --target x86_64-unknown-linux-musl
```

## Run

**1. Create a bridge-link key once, and keep it.** Any 32 random bytes are a
valid X25519 private key:

```sh
umask 077 && openssl rand -base64 32 > /etc/dsh/proxy.key
```

**2. Start the proxy.**

```sh
dsh-proxy --listen 0.0.0.0:443 --key "$(cat /etc/dsh/proxy.key)" \
    --tls-cert /etc/dsh/fullchain.pem --tls-key /etc/dsh/privkey.pem
```

It prints the public half of the key, which bridges pin:

```
dsh-proxy listening on 0.0.0.0:443
dsh-proxy public key I7bowv/d8y5NTR6N1ntxMm//NoElvLJbN6NDvZi3HTU=
```

**3. Check it.**

```sh
curl https://proxy.example.com/health      # {"ok":true}
```

**4. Point the Mac's bridge at it**, in the profile's `cordis.patch.yml`:

```yaml
- id: mobile-bridge
  config:
    proxyHost: proxy.example.com
    proxyPort: 443
    proxyPublicKey: I7bowv/d8y5NTR6N1ntxMm//NoElvLJbN6NDvZi3HTU=   # the line printed above
```

Phones need no configuration: the pairing code the bridge shows
(`dshm://host:port/…`) already names the proxy.

Without `--key`, every start generates a new key, and a bridge that pins
`proxyPublicKey` refuses the proxy until you update its config. Note that
`--key` is an argument, so other users on the same host can read it from the
process list; run the proxy on a machine you control.

For local development, `--tls-self-signed` mints a throwaway certificate for
`localhost`; clients have to trust it or skip verification.

### As a systemd service

```ini
# /etc/systemd/system/dsh-proxy.service
[Unit]
Description=dsh-proxy
Wants=network-online.target
After=network-online.target

[Service]
User=dsh
ExecStart=/bin/sh -c 'exec /usr/local/bin/dsh-proxy --listen 0.0.0.0:443 --key "$(cat /etc/dsh/proxy.key)" --tls-cert /etc/dsh/fullchain.pem --tls-key /etc/dsh/privkey.pem'
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
Restart=always

[Install]
WantedBy=multi-user.target
```

The `dsh` user must be able to read the key and both PEM files. The
certificate is read once at startup, so restart the service after each renewal
(for example from a certbot deploy hook). A restart only makes bridges
reconnect.

## Configuration

Everything is a command-line flag. `--help` prints the usage; a bad
argument exits with status 2.

| flag | default | meaning |
|---|---|---|
| `--listen HOST:PORT` | `0.0.0.0:443` | the one port phones and bridges share |
| `--key BASE64` | generated at each start | 32-byte X25519 private key for the bridge link |
| `--tls-cert PEM` / `--tls-key PEM` | — | certificate chain and private key; both required unless self-signed |
| `--tls-self-signed` | off | throwaway `localhost` certificate, for development |
| `--max-clients-per-ip N` | 64 | TLS clients one peer address may hold, claimed before the handshake |
| `--max-bridges N` | 1024 | bridge links held at once, process-wide |
| `--max-bridges-per-ip N` | 32 | bridge links held by one peer address |
| `--max-streams-per-bridge N` | 2048 | phone streams one bridge carries at once |
| `--handshake-timeout-ms N` | 10000 | deadline for a bridge's whole Noise_XX handshake |

## How it works

The proxy reads the first byte to decide what a connection is:

- `0x16`, a TLS ClientHello. Terminate TLS and serve HTTP/1.1. Only two
  routes exist: `GET /tunnel` with a WebSocket `Upgrade`, and `GET /health`.
  Everything else is `404`.
- `DSHB`, a bridge dialling out. A Noise_XX handshake follows. The static
  key it proves becomes the routing key, and a minimal mux
  (`OPEN` / `DATA` / `CLOSE` / `WINDOW`, 256 KiB window per stream) runs
  over that link.

Anything else gets nothing back.

**The client contract.** One WebSocket. Inside it are the bytes a phone used to
put on a bare TCP socket: the 37-byte `DSHC` preamble
(`magic(4) + version(1) + bridge key(32)`) naming a bridge, then a **Noise_IK
session with the Mac**. The proxy unwraps WebSocket frames and forwards the
bytes. It holds no key that would let it read them, and it does not try.

Message boundaries carry no meaning: a client may send the preamble in six
frames or in one. Control frames are the only ones the proxy interprets. A
ping is answered, because a mini program's socket dies quietly without it.

Neither client had to change above the carrier. Both already ran their Noise
stack on a byte-stream seam, and `wx.connectSocket` is a byte pipe like any
other.

## Security

| layer | proves | where |
|---|---|---|
| TLS 1.3 | the client reached the real proxy | here |
| Noise_IK | the device holds a paired static key | phone ↔ Mac |
| device allowlist | that key was approved during pairing | Mac |

`/tunnel` checks no token, and none could be checked: the session inside is
end to end, and the Mac is the authority. What the proxy owes this route is
**admission control**, not authentication. That is the `--max-*` and
`--handshake-timeout-ms` flags above, and it is cheap on purpose: no
decryption, no lookup. A phone naming an unknown bridge, or a bridge with an
unknown version or magic, is dropped without a reply.

Pairing happens inside the tunnel, between the phone and the Mac. So the
public component holds **nothing worth stealing**.

What the proxy *can* see: peer IP addresses, the bridge routing key (an
identifier, not a secret; it is printed in the pairing QR code), and the size
and timing of traffic.

## Performance

Measured against the previous bare-TCP proxy with the same bridge, the same
phone stack and the same payloads. Only the carrier differs:

| | old | new |
|---|---:|---:|
| 4 B echo, 32 connections | 108 799 rps | **107 647 rps**, same CPU |
| 1 MiB bulk, 8 lanes | 743.9 MB/s | 603.3 MB/s, +33 % CPU |
| connection setup | 2 094/s | 1 384/s |

The RPC-shaped traffic costs nothing extra. TLS and WebSocket framing are paid
per byte and per connection: about a fifth of bulk throughput and a third of
the connection rate. On a link that tops out around 0.5 MB/s, neither one is
the limit. Method, caveats and a correction to an earlier unfair comparison
are in [BENCHMARKS.md](BENCHMARKS.md) (Chinese).

## Troubleshooting

| symptom | cause and fix |
|---|---|
| `provide --tls-cert and --tls-key, or --tls-self-signed` | There is no plaintext mode. Pass both PEM files, or `--tls-self-signed` for development. |
| `--key is not base64` / `private key must be 32 bytes` | The key must be base64 of exactly 32 bytes. Generate it with `openssl rand -base64 32`. |
| `Permission denied` binding `:443` | Ports below 1024 need `CAP_NET_BIND_SERVICE` (see the systemd unit). Or listen on a high port and set the bridge's `proxyPort` to match. |
| The bridge never connects after a proxy restart | The proxy ran without `--key` and now has a new public key, so the bridge's pin no longer matches. Start it with `--key`, or update `proxyPublicKey`. |
| A phone's tunnel opens and then closes, with nothing logged | The Mac it names has no live link to this proxy. Unknown bridges are dropped silently by design. Check that the bridge reports `connected`. |
| Phones behind one NAT are refused | That address reached `--max-clients-per-ip` (64). Raise it. |
| Phones reject the certificate after a renewal | The certificate is loaded only at startup. Restart the proxy. |

## Development

```sh
cargo test --locked                                   # what CI runs
cargo clippy --all-targets --locked -- -D warnings
```

`cargo test` runs 18 tests. 17 of them run over real loopback sockets, against
a bridge and a phone written as independent implementations of the peers. The
phone's Noise_IK and transport framing live in `tests/common/phone.rs`, not in
the proxy, which is what makes these evidence rather than a mirror.

- `tests/pipe.rs`: the client contract. An end-to-end Noise session over WSS,
  a preamble split across seven-byte frames, ping answered with pong, an
  oversized ping refused, the per-IP tunnel ceiling, and an unknown bridge
  key told nothing.
- `tests/tunnel.rs`: the bridge link and mux. Round trip, 3 MiB through the
  receive window, 50 concurrent streams, keepalive, the silent drops for
  unknown key / version / magic, per-IP refusal, stalled-handshake reaping,
  the exact stream budget under a race, one stream's flood costing only that
  stream, and duplicate registration.
- `src/noise.rs`: a unit test that `snow` and `x25519-dalek` derive the same
  public key, or a bridge would pin a key the proxy never proves.

`tests/bench.rs` is the benchmark. It is `#[ignore]`d and driven by
`scripts/bench.sh <PORT_BASE>`, which needs the old proxy built from
`38c1eab` (`OLD_BIN`).

| file | role |
|---|---|
| `src/main.rs` | flags, key and certificate loading, bind |
| `src/lib.rs` | first-byte demux, bridge admission, splicing a client onto a bridge |
| `src/edge.rs` | TLS edge and its two HTTP routes |
| `src/ws.rs` | a WebSocket server cut down to a byte pipe |
| `src/noise.rs` | Noise_XX responder for the bridge link |
| `src/mux.rs` | the stream mux carried by one bridge link |
| `src/tls.rs` | PEM loading and self-signed certificates |
| `src/wire.rs` | wire constants shared by both connection kinds |

## License

MIT, as declared in [Cargo.toml](Cargo.toml).

<!-- dsh-family:start -->
## The DSH App family

**DSH App** is a family of clients and plugins built for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (`dsh`). Every piece plugs into the **same** dsh on your computer, so sessions, models and plugins are shared everywhere — combine the ones you need. Downloads and docs: **[dshapp.github.io](https://dshapp.github.io/en/)**.

```mermaid
flowchart LR
  subgraph pc["Your computer"]
    mac["macOS App"] --> dsh(["dsh"])
    cc["dsh-chrome-control"] --- dsh
    mb["dsh-mobile-bridge"] --- dsh
    cu["dsh-kimi-computer-use"] --- dsh
    cs["dsh-claude-subscription"] --- dsh
    ext["Chrome extension"] <--> cc
  end
  android["Android App"] --> proxy["dsh-proxy"]
  mini["WeChat mini program"] --> proxy
  proxy <--> mb
  style proxy fill:#0A84FF,stroke:#0A84FF,color:#fff
```

| | Project | What it does | Links |
| --- | --- | --- | --- |
| Clients | **macOS App**<br>`dsh-macapp` | Native SwiftUI client that hosts your local dsh and switches on every extension | [Overview](https://dshapp.github.io/en/products/macos/) · source coming soon |
|  | **Android App**<br>`dsh-androidapp` | DSH in your pocket: approvals, questions and notifications, end-to-end encrypted | [Overview](https://dshapp.github.io/en/products/android/) · source coming soon |
|  | **DSH Remote (WeChat)**<br>`dsh-miniapp` | No install: take over DSH from WeChat on iPhone or Android | [Overview](https://dshapp.github.io/en/products/miniapp/) · source coming soon |
|  | **Chrome extension**<br>`dsh-chrome-extension` | DSH in the browser side panel, and the executing half of browser control | [Overview](https://dshapp.github.io/en/products/chrome/) · source coming soon |
| dsh plugins | **Browser control**<br>`dsh-chrome-control` | Hands your signed-in Chrome to the agent as `mcp__chrome__*` tools | [Overview](https://dshapp.github.io/en/products/chrome/) · [Source](https://github.com/dshapp/dsh-chrome-control) |
|  | **Mobile bridge**<br>`dsh-mobile-bridge` | Serves dsh to paired phones over a Noise tunnel, without opening a port | [Overview](https://dshapp.github.io/en/products/android/) · [Source](https://github.com/dshapp/dsh-mobile-bridge) |
|  | **Computer use**<br>`dsh-kimi-computer-use` | Lets the agent operate Mac apps that have no API, in the background | [Overview](https://dshapp.github.io/en/products/cu/) · [Source](https://github.com/dshapp/dsh-kimi-computer-use) |
|  | **Claude subscription**<br>`dsh-claude-subscription` | Runs Claude models in DSH on your Claude Code subscription, no API key | [Source](https://github.com/dshapp/dsh-claude-subscription) |
| Infrastructure | **Relay** ← you are here<br>`dsh-proxy` | The only public piece of mobile access: one port, ciphertext only, no state | [Overview](https://dshapp.github.io/en/docs/crypto/) |
|  | **Website**<br>`dshapp.github.io` | Downloads, docs and release notes | [Overview](https://dshapp.github.io/en/) · [Source](https://github.com/dshapp/dshapp.github.io) |
<!-- dsh-family:end -->
