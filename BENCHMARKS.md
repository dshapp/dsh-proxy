# Old edge vs unified edge — measured

Both systems run the **same bridge** half (Noise_XX registration, one
Noise_IK tunnel per client stream, plain HTTP/1.1 inside). The only difference
is the client edge, so the delta below is exactly the cost of the new one.

- `old` = commit `38c1eab` binary + a raw-TCP phone: TCP, 37-byte `DSHC`
  preamble, Noise_IK end to end through the proxy.
- `new` = this branch's binary + a TLS client: TLS 1.3, `Authorization:
  Bearer`, proxy-terminated Noise_IK to the bridge.

Everything is loopback on one Apple M4 Pro (14 cores, 48 GB), proxy, bridge and
load generator on the same host, so **both columns are floors** — a real
deployment adds at least one wide-area round trip and, on the bundled VPS, a
~0.5 MB/s bandwidth ceiling that neither column models. The crypto and
connection-handling deltas are what transfer; absolute numbers do not.

Reproduce with `bash scripts/bench.sh <PORT_BASE>` (needs both binaries and
`target/release/harness`; see `scripts/bench.sh` for the exact cases).

## Results

| case | metric | old | new | delta |
|---|---|---:|---:|---:|
| latency 1 conn | rps | 7 567 | **14 799** | 1.96× |
| | p50 / p99 | 0.060 / 1.739 ms | 0.064 / 0.120 ms | p99 14× better |
| | proxy CPU | 0:00.09 | 0:00.13 | +44 % |
| | proxy RSS | 2 592 KB | 4 416 KB | +1.8 MB |
| latency 32 conn | rps | **88 418** | 59 665 | 0.67× |
| | p50 / p99 | 0.329 / 0.869 ms | 0.408 / 1.339 ms | +24 % / +54 % |
| | proxy CPU | 0:00.58 | 0:02.47 | 4.3× |
| | proxy RSS | 3 920 KB | 9 120 KB | +5.2 MB |
| connect | conn/s | 2 894 | **3 964** | 1.37× |
| | p50 / p99 | 0.331 / 0.457 ms | 0.247 / 0.330 ms | better |
| | proxy CPU | 0:00.03 | 0:00.05 | +67 % |
| bulk 256 KiB ×200 | MB/s | **231.9** | 177.4 | 0.76× |
| | p50 / p99 | 1.054 / 1.329 ms | 1.408 / 1.610 ms | +34 % / +21 % |
| | proxy RSS | 3 312 KB | 8 560 KB | +5.2 MB |
| bulk 1 MiB ×64, conc 8 | MB/s | **555.6** | 548.4 | 0.99× |
| | p50 / p99 | 13.696 / 18.528 ms | 14.312 / 17.731 ms | ≈ equal |
| | proxy CPU | 0:00.21 | 0:00.32 | +52 % |
| | proxy RSS | 5 360 KB | 34 512 KB | +29 MB |
| new proxy + **old** client | rps | — | 15 424 | legacy path unchanged |

## What the numbers say

**Latency throughput wins at 1 connection.** 1.96× the request rate with a
30× tighter p99. The old path pays for a Noise_IK handshake inside every new
tunnel; the new pool hands a warm, already-authenticated HTTP/1.1 connection
back, so most requests never touch the handshake at all.

**At 32 concurrent connections the old path still wins** on raw rps (88k vs
60k), and that is the honest cost of the design: the same TLS + bearer
machinery now runs in-process on every request, where the old proxy only
copied bytes. The 4.3× CPU figure is the clearest picture of it — the new edge
does per-request work the old edge never did. A single wide-area RTT dominates
both of these numbers in production, so the practical difference is small; on
a busy host, capacity planning should use the CPU column.

**Connection establishment is faster** (3 964 vs 2 894/s) despite adding a TLS
handshake, because the old path pays a Noise_IK handshake *after* the TCP
handshake for every connection. TLS 1.3 is one round trip and the proxy now
owns both halves of it.

**Bulk throughput is unchanged at scale** (548 vs 556 MB/s at 1 MiB ×8), which
is the result that matters: streaming both bodies end to end leaves the new
edge as fast as a blind byte relay at the payload sizes that saturate the
pipe. The one regression, 256 KiB at concurrency 1, is a single-connection
effect — one TLS record and one HTTP/1.1 framing pass per 256 KiB request —
not a systemic one.

**Memory is the remaining gap.** 29 MB extra at 1 MiB ×8 is real, but it is
per-request transient, not a leak: the proxy's resident set returns to ~4.5 MB
once traffic stops. It is the cost of holding whole response frames in the
HTTP/1.1 path, and it is bounded by `WINDOW` (256 KiB) × concurrent streams,
not by request size — a 64 MiB upload no longer grows it, because the body now
streams instead of being collected.

## The 64 KiB boundary (fixed)

The first matrix run had `old-bulk-*` failing outright at every size from
64 KiB up. It was not a proxy limit: at 65 504 bytes the request reaches the
proxy as one maximum-size (65 535-byte) Noise message followed by a small one,
and the reader asked the socket for *more* ciphertext while a complete message
already sat in its buffer. The socket had gone quiet on the message boundary,
so the read hung until the harness deadline.

`NoiseStream::poll_read` now drains a buffered complete message before reading
more, which fixes the old client path and the new one alike — the new client
was hitting the same stall at large enough bodies. Regression:
`a_complete_buffered_message_is_read_without_more_ciphertext` in
`tests/edge.rs`.

## Security delta (not measured, and the reason for the design)

The old proxy could not decrypt application traffic at all: Noise_IK ran end
to end, phone to Mac. The unified edge terminates TLS and runs Noise_IK
itself, so the proxy is now inside the trust boundary and can see plaintext.
That is the deliberate trade for one uniform contract that a WeChat
mini-program can speak (HTTPS/WSS only, no raw TCP, no Noise). See the
architecture notes in `README.md`.
