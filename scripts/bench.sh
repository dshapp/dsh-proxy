#!/usr/bin/env bash
# Old era against new, same bridge, same payloads, same machine.
#
#   old = the 38c1eab proxy + a bare TCP phone
#   new = this worktree's proxy + a phone over TLS and a WebSocket
#
# Both carry the identical Noise_IK stack and echo the same length-prefixed
# frames, so the delta is the carrier and the proxy that terminates it.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
OLD_BIN=${OLD_BIN:-/tmp/dsh-proxy-old/target/release/dsh-proxy}
NEW_BIN=$HERE/target/release/dsh-proxy
PORT_BASE=${1:-28000}
TMP=${TMPDIR:-/tmp}

run_case() {
  local label=$1 mode=$2 scenario=$3 requests=$4 size=$5 conc=$6 port=$7
  local bin flags
  if [ "$mode" = old ]; then bin=$OLD_BIN; flags=""; else bin=$NEW_BIN; flags="--tls-self-signed"; fi

  # shellcheck disable=SC2086
  $bin --listen 127.0.0.1:"$port" $flags >"$TMP/bench-$label.log" 2>&1 &
  local proxy=$!
  sleep 0.8

  local rss_file=$TMP/bench-rss-$label
  echo 0 > "$rss_file"
  (
    peak=0
    while kill -0 "$proxy" 2>/dev/null; do
      rss=$(ps -o rss= -p "$proxy" 2>/dev/null | tr -d ' ')
      if [ -n "$rss" ] && [ "$rss" -gt "$peak" ]; then peak=$rss; echo "$peak" > "$rss_file"; fi
      sleep 0.05
    done
  ) &
  local sampler=$!

  local out
  out=$(cd "$HERE" && BENCH_MODE=$mode BENCH_PROXY=127.0.0.1:$port \
      BENCH_SCENARIO=$scenario BENCH_REQUESTS=$requests BENCH_SIZE=$size BENCH_CONCURRENCY=$conc \
      cargo test --release --test bench -- --ignored --nocapture 2>/dev/null | grep '^{')
  local cpu
  cpu=$(ps -o time= -p "$proxy" 2>/dev/null | tr -d ' ')
  kill "$proxy" 2>/dev/null
  wait "$proxy" 2>/dev/null
  wait "$sampler" 2>/dev/null

  printf '%-18s cpu=%-9s rss_kb=%-7s %s\n' "$label" "$cpu" "$(cat "$rss_file")" "${out:-NO RESULT}"
}

echo "# old: $OLD_BIN"
echo "# new: $NEW_BIN"
echo "# host: $(hostname -s)"

run_case old-echo-1    old latency    20000 4       1  $((PORT_BASE+1))
run_case new-echo-1    new latency    20000 4       1  $((PORT_BASE+2))
run_case old-echo-32   old latency    40000 4       32 $((PORT_BASE+3))
run_case new-echo-32   new latency    40000 4       32 $((PORT_BASE+4))
run_case old-connect   old connect    300   0       1  $((PORT_BASE+5))
run_case new-connect   new connect    300   0       1  $((PORT_BASE+6))
run_case old-bulk-64k  old throughput 2000  65536   1  $((PORT_BASE+7))
run_case new-bulk-64k  new throughput 2000  65536   1  $((PORT_BASE+8))
run_case old-bulk-1m-8 old throughput 400   1048576 8  $((PORT_BASE+9))
run_case new-bulk-1m-8 new throughput 400   1048576 8  $((PORT_BASE+10))
