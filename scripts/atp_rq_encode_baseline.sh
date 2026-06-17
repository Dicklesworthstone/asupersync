#!/usr/bin/env bash
# atp_rq_encode_baseline.sh — RaptorQ encode-cost baseline + before/after gate for F3
# (parallel per-block encode, bead 317hxr.4). The large-file weakness vs rsync is the
# single-threaded RaptorQ encode (the sender pins one core). This measures, per payload
# size, the loopback rq send wall-clock + sender CPU% + peak RSS (encode-dominated for
# large files) and verifies every transfer bit-for-bit. Run it BEFORE and AFTER F3 lands;
# the encode wall should drop and CPU% should rise well above 100% (multi-core) with the
# received sha UNCHANGED (isomorphism: symbols are deterministic per SBN+ESI).
#
# Usage: ATP_BIN=/path/to/atp ./scripts/atp_rq_encode_baseline.sh
#        SIZES="10M:10485760 100M:104857600" WORKERS=4 ./scripts/atp_rq_encode_baseline.sh
set -uo pipefail

ATP_BIN="${ATP_BIN:-}"
SIZES="${SIZES:-10M:10485760 50M:52428800}"
WORKERS="${WORKERS:-4}"
PORT="${PORT_BASE:-19850}"
TS="$(date +%Y%m%d_%H%M%S)"; OUT="${OUT:-/tmp/atp_rq_encode_baseline_$TS}"
mkdir -p "$OUT/src"; RESULTS="$OUT/results.jsonl"; : > "$RESULTS"; ALL_PIDS=()
log(){ printf '%s | %s\n' "$(date '+%H:%M:%S')" "$*"; }

if [ -z "$ATP_BIN" ]; then for c in /data/tmp/cargo-target/release/atp ./target/release/atp; do [ -x "$c" ] && ATP_BIN="$c" && break; done; fi
[ -n "$ATP_BIN" ] && [ -x "$ATP_BIN" ] || { log "FATAL: atp binary not found (set ATP_BIN)"; exit 2; }
command -v /usr/bin/time >/dev/null 2>&1 || { log "FATAL: /usr/bin/time required"; exit 2; }
cleanup(){ local p; for p in ${ALL_PIDS[@]+"${ALL_PIDS[@]}"}; do kill -9 "$p" 2>/dev/null; done; }
trap cleanup EXIT INT TERM
log "atp: $ATP_BIN   cores: $(nproc 2>/dev/null || echo '?')"
KEY="$("$ATP_BIN" rq-keygen 2>/dev/null | grep -oE '[0-9a-f]{64}' | head -1)"; [ -n "$KEY" ] || KEY="$(openssl rand -hex 32)"

run(){
  local label="$1"; local bytes="$2"; local dst="$OUT/dst_$label"; rm -rf "$dst"; mkdir -p "$dst"
  head -c "$bytes" /dev/urandom > "$OUT/src/$label.bin"
  local src_sha; src_sha="$(sha256sum "$OUT/src/$label.bin" | cut -d' ' -f1)"
  PORT=$((PORT+1))
  "$ATP_BIN" recv "$dst" --listen "127.0.0.1:$PORT" --transport rq --once --rq-auth-key-hex "$KEY" --workers "$WORKERS" --max-bytes 2147483648 > "$OUT/recv_$label.log" 2>&1 &
  local rpid=$!; ALL_PIDS+=("$rpid")
  local r=0; for _ in $(seq 1 40); do grep -qi listening "$OUT/recv_$label.log" 2>/dev/null && { r=1; break; }; sleep 0.25; done
  [ "$r" = 1 ] || { log "  $label receiver not ready"; kill "$rpid" 2>/dev/null; return; }
  /usr/bin/time -v "$ATP_BIN" send "$OUT/src/$label.bin" "127.0.0.1:$PORT" --transport rq --rq-auth-key-hex "$KEY" --workers "$WORKERS" --max-bytes 2147483648 > "$OUT/send_$label.log" 2> "$OUT/time_$label.txt"
  local rc=$?; wait "$rpid" 2>/dev/null
  local dst_sha; dst_sha="$(sha256sum "$dst/$label.bin" 2>/dev/null | cut -d' ' -f1)"
  local wall cpu maxrss symbols
  wall="$(grep -oE 'wall clock.*' "$OUT/time_$label.txt" | grep -oE '[0-9:.]+$')"
  cpu="$(grep -oE 'Percent of CPU[^:]*: [0-9]+%' "$OUT/time_$label.txt" | grep -oE '[0-9]+')"
  maxrss="$(grep -oE 'Maximum resident set size[^:]*: [0-9]+' "$OUT/time_$label.txt" | grep -oE '[0-9]+$')"
  symbols="$(grep -oE '"symbols_sent":[0-9]+' "$OUT/send_$label.log" | grep -oE '[0-9]+')"
  local sha_ok; [ "$src_sha" = "${dst_sha:-x}" ] && sha_ok=true || sha_ok=false
  log "  $label rc=$rc wall=${wall:-?} cpu=${cpu:-?}% maxrss=${maxrss:-?}KB symbols=${symbols:-?} sha_ok=$sha_ok"
  printf '{"size":"%s","rc":%s,"wall":"%s","cpu_pct":%s,"maxrss_kb":%s,"symbols_sent":%s,"sha_ok":%s}\n' \
    "$label" "$rc" "${wall:-?}" "${cpu:-0}" "${maxrss:-0}" "${symbols:-0}" "$sha_ok" >> "$RESULTS"
  rm -rf "$dst" 2>/dev/null || true
}

log "=== rq encode baseline ($TS) sizes=[$SIZES] workers=$WORKERS ==="
for sz in $SIZES; do run "${sz%%:*}" "${sz##*:}"; done
log "results: $RESULTS"
[ -s "$RESULTS" ] && grep -q '"sha_ok":false' "$RESULTS" && { log "==== BASELINE: a transfer FAILED sha ===="; exit 1; } || log "==== BASELINE: all sha OK ===="
