#!/usr/bin/env bash
# Measure the old and new edges on the same loopback, with the same harness.
#
#   old system = the 38c1eab proxy binary + a raw-TCP Noise_IK phone
#   new system = this worktree's proxy + a TLS/bearer client
#
# The bridge half is identical in both, so the delta is the client edge only.
set -u

HERE=$(cd "$(dirname "$0")/.." && pwd)
NEW_BIN=$HERE/target/release/dsh-proxy
OLD_BIN=${OLD_BIN:-/tmp/dsh-proxy-old/target/release/dsh-proxy}
HARNESS=$HERE/target/release/harness
TMP=${TMPDIR:-/tmp}

usage() { echo "usage: $0 [PORT_BASE]" >&2; exit 2; }
PORT_BASE=${1:-21000}

# One measured case: start a proxy, run one harness scenario, report the
# proxy's peak RSS and CPU alongside the harness numbers.
run_case() {
  local label=$1 bin=$2 flags=$3 mode=$4 scenario=$5 requests=$6 size=$7 conc=$8 port=$9
  local state="$TMP/bench-state-$port.json"
  # Each case gets its own registry file: a fresh proxy must not inherit
  # another case's pairing tokens.
  local resolved=${flags//@STATE@/$state}
  rm -f "$state"
  # shellcheck disable=SC2086
  $bin --listen 127.0.0.1:"$port" $resolved >"$TMP/px-$label.log" 2>&1 &
  local proxy=$!
  sleep 0.7
  local rss_file="$TMP/rss-$label"
  : > "$rss_file"
  (
    local peak=0
    while kill -0 "$proxy" 2>/dev/null; do
      local rss
      rss=$(ps -o rss= -p "$proxy" 2>/dev/null | tr -d ' ')
      if [ -n "$rss" ] && [ "$rss" -gt "$peak" ]; then peak=$rss; echo "$peak" > "$rss_file"; fi
      sleep 0.05
    done
  ) &
  local sampler=$!
  local started
  started=$(date +%s.%N)
  local result
  result=$("$HARNESS" --mode "$mode" --proxy 127.0.0.1:"$port" \
      --scenario "$scenario" --requests "$requests" --size "$size" --concurrency "$conc" 2>"$TMP/h-$label.err")
  local status=$?
  local ended
  ended=$(date +%s.%N)
  local cpu
  cpu=$(ps -o time= -p "$proxy" 2>/dev/null | tr -d ' ')
  kill "$proxy" 2>/dev/null
  wait "$proxy" 2>/dev/null
  wait "$sampler" 2>/dev/null
  local peak
  peak=$(cat "$rss_file" 2>/dev/null || echo 0)
  local wall
  wall=$(echo "$ended - $started" | bc)
  local metrics
  if [ $status -ne 0 ]; then
    metrics="{\"error\":\"harness exited $status\",\"stderr\":\"$(head -c 300 "$TMP/h-$label.err" | tr '\n' ' ')\"}"
  else
    metrics=$result
  fi
  printf '%s host=%s proxy_cpu=%s proxy_rss_kb=%s wall_s=%s %s\n' \
    "$label" "$(hostname -s)" "$cpu" "$peak" "$wall" "$metrics"
}

echo "# old binary: $OLD_BIN"
echo "# new binary: $NEW_BIN"

run_case old-latency-1      "$OLD_BIN" ""       old latency    3000 4      1     $((PORT_BASE+1))
run_case old-latency-32     "$OLD_BIN" ""       old latency    32000 4     32    $((PORT_BASE+2))
run_case old-connect        "$OLD_BIN" ""       old connect    300  4      1     $((PORT_BASE+3))
run_case old-bulk-256k-1    "$OLD_BIN" ""       old throughput 200  262144 1     $((PORT_BASE+4))
run_case old-bulk-1m-8      "$OLD_BIN" ""       old throughput 64   1048576 8    $((PORT_BASE+5))

NEW_FLAGS="--tls-self-signed --state @STATE@"
run_case new-latency-1      "$NEW_BIN" "$NEW_FLAGS"       new latency    3000 4      1     $((PORT_BASE+11))
run_case new-latency-32     "$NEW_BIN" "$NEW_FLAGS"       new latency    32000 4     32    $((PORT_BASE+12))
run_case new-connect        "$NEW_BIN" "$NEW_FLAGS"       new connect    300  4      1     $((PORT_BASE+13))
run_case new-bulk-256k-1    "$NEW_BIN" "$NEW_FLAGS"       new throughput 200  262144 1     $((PORT_BASE+14))
run_case new-bulk-1m-8      "$NEW_BIN" "$NEW_FLAGS"       new throughput 64   1048576 8    $((PORT_BASE+15))
run_case new-proxy-old-client "$NEW_BIN" "$NEW_FLAGS"     old latency    3000 4      1     $((PORT_BASE+16))