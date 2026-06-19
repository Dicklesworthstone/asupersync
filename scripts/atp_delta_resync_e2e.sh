#!/usr/bin/env bash
# atp_delta_resync_e2e.sh — incremental re-sync correctness gate (bead bzkxa5 / B-8.8b AC5).
#
# Proves the delta path the CLI wiring (bzkxa5) added is BYTE-IDENTICAL and actually
# incremental: do a full sync to a dest, then mutate the source (append / insert / rename /
# 1% in-place) and re-sync. After each re-sync the received tree must be SHA-256 identical to
# the (mutated) source, AND the sender must have chosen the DELTA path (shipped only changed
# chunks) rather than silently falling back to a full transfer. A re-sync that is byte-correct
# but secretly full-object would pass a naive check yet defeat the entire B-8 thesis — so this
# gate asserts BOTH. It is THE prerequisite for the B-8.7 (0kh4jm) re-sync benchmark: without a
# proven delta path there is nothing to measure.
#
# Loopback-only, hermetic, no rm -rf of shared paths (everything under a unique $OUT). The atp
# binary must be built with --features atp-cli (delta rides the TCP transport).
#
# Usage:
#   ATP_BIN=/path/to/atp ./scripts/atp_delta_resync_e2e.sh
#   MUTATIONS="append insert rename onepct" ./scripts/atp_delta_resync_e2e.sh
set -uo pipefail

ATP_BIN="${ATP_BIN:-}"
TRANSPORT="${TRANSPORT:-tcp}"        # delta is wired on the TCP data path (tcp_config delta flag)
MUTATIONS="${MUTATIONS:-append insert rename onepct}"
PORT_BASE="${PORT_BASE:-19600}"
TS="$(date +%Y%m%d_%H%M%S)"
OUT="${OUT:-/tmp/atp_delta_resync_e2e_$TS}"
SRC="$OUT/src"
DEST="$OUT/dest"
LOGS="$OUT/logs"
SUMMARY="$OUT/summary.json"
DELTA_STATE_DIR=".asupersync-atp-delta-v1"
DELTA_PKG_PREFIX=".asupersync-atp-delta-package-"
mkdir -p "$SRC" "$DEST" "$LOGS"
PASS=0; FAIL=0; PORT="$PORT_BASE"

log() { printf '%s | %s\n' "$(date '+%H:%M:%S')" "$*" >&2; }
fail() { log "FAIL: $*"; FAIL=$((FAIL + 1)); }
ok() { log "ok: $*"; PASS=$((PASS + 1)); }

# ---- locate atp binary ----
if [ -z "$ATP_BIN" ]; then
  for c in /data/tmp/cargo-target/release/atp /data/tmp/rch_target_atp_release2/release/atp ./target/release/atp; do
    [ -x "$c" ] && ATP_BIN="$c" && break
  done
fi
[ -n "$ATP_BIN" ] && [ -x "$ATP_BIN" ] || { log "FATAL: atp binary not found; set ATP_BIN= (build: cargo build --release --bin atp --features atp-cli)"; exit 2; }
log "atp binary: $ATP_BIN"

# Path-independent content-set digest: sha256 over the SORTED per-file content sha256, EXCLUDING
# the delta bookkeeping dirs the receiver writes (.asupersync-atp-delta-v1 / -package-*) so they
# never perturb the src==dst comparison.
content_set() {
  find "$1" -type f \
    -not -path "*/${DELTA_STATE_DIR}/*" \
    -not -path "*/${DELTA_PKG_PREFIX}*/*" \
    -print0 2>/dev/null \
    | xargs -0 -r sha256sum 2>/dev/null | awk '{ print $1 }' \
    | LC_ALL=C sort | sha256sum | awk '{ print $1 }'
}

logical_bytes() {
  find "$1" -type f \
    -not -path "*/${DELTA_STATE_DIR}/*" \
    -not -path "*/${DELTA_PKG_PREFIX}*/*" \
    -printf '%s\n' 2>/dev/null \
    | awk '{ total += $1 } END { print total + 0 }'
}

# Run one send -> recv over loopback; echo the sender-stderr log path. The receiver persists its
# delta state under $DEST so the NEXT send is planned incrementally against it.
sync_once() {
  local label="$1"
  local port=$((PORT)); PORT=$((PORT + 1))
  local recv_log="$LOGS/${label}_recv.log" send_log="$LOGS/${label}_send.log"
  timeout 120 "$ATP_BIN" recv "$DEST" --listen "127.0.0.1:${port}" --once \
    --transport "$TRANSPORT" --rq-allow-unauthenticated-lab >"$recv_log" 2>&1 &
  local recv_pid=$!
  sleep 0.75
  timeout 120 "$ATP_BIN" send "$SRC" "127.0.0.1:${port}" \
    --transport "$TRANSPORT" --rq-allow-unauthenticated-lab >"$send_log" 2>&1
  local send_rc=$?
  wait "$recv_pid" 2>/dev/null || true
  if [ "$send_rc" -ne 0 ]; then
    log "  sender exit=$send_rc (see $send_log)"
  fi
  printf '%s' "$send_log"
}

send_bytes() {
  sed -nE 's/.*"bytes_sent"[[:space:]]*:[[:space:]]*([0-9]+).*/\1/p' "$1" 2>/dev/null | tail -n 1
}

# Did the sender choose the incremental delta path (vs a full-object transfer/fallback)?
delta_engaged() {
  local log_path="$1" current_logical_bytes="${2:-0}" sent
  if grep -qE "delta planner: sending [0-9]+ chunk" "$log_path" 2>/dev/null; then
    return 0
  fi
  sent="$(send_bytes "$log_path")"
  [ -n "$sent" ] \
    && [ "$current_logical_bytes" -gt 0 ] \
    && [ "$sent" -lt "$current_logical_bytes" ] \
    && ! delta_full_fallback "$log_path"
}
delta_full_fallback() {
  grep -qE "full-object fallback|no receiver state|not delta-packable|using full-object transfer" "$1" 2>/dev/null
}

# ---- build the initial source tree (heterogeneous, a few MB, incompressible) ----
build_tree() {
  : >"$SRC/.gitkeep"
  mkdir -p "$SRC/a" "$SRC/b/c"
  head -c 1500000 /dev/urandom >"$SRC/a/big1.bin"
  head -c 800000 /dev/urandom >"$SRC/a/big2.bin"
  head -c 64000 /dev/urandom >"$SRC/b/mid.bin"
  for i in 0 1 2 3 4; do head -c 9000 /dev/urandom >"$SRC/b/c/small_$i.bin"; done
}

mutate() {
  case "$1" in
    append)  head -c 40000 /dev/urandom >>"$SRC/a/big1.bin" ;;                  # grow one file
    insert)  head -c 120000 /dev/urandom >"$SRC/a/inserted.bin" ;;              # brand-new file
    rename)  mv "$SRC/a/big2.bin" "$SRC/a/big2_renamed.bin" ;;                   # pure rename
    onepct)  dd if=/dev/urandom of="$SRC/a/big1.bin" bs=1 seek=700000 count=15000 conv=notrunc status=none ;; # in-place 1% edit
    *) log "unknown mutation: $1"; return 1 ;;
  esac
}

banner() { printf '\n========== %s ==========\n' "$*" >&2; }

# ---- full baseline sync ----
banner "BUILD + FULL BASELINE SYNC"
build_tree
src0="$(content_set "$SRC")"
base_log="$(sync_once baseline)"
dst0="$(content_set "$DEST")"
if [ "$src0" = "$dst0" ]; then ok "baseline full sync byte-identical (set=${src0:0:16})"; else fail "baseline sync mismatch: src=${src0:0:16} dst=${dst0:0:16}"; fi

# ---- incremental re-syncs across mutations ----
for m in $MUTATIONS; do
  banner "MUTATION: $m"
  mutate "$m" || { fail "$m: mutate failed"; continue; }
  src="$(content_set "$SRC")"
  src_bytes="$(logical_bytes "$SRC")"
  slog="$(sync_once "resync_$m")"
  dst="$(content_set "$DEST")"

  # (1) THE correctness gate: received tree byte-identical to the mutated source.
  if [ "$src" = "$dst" ]; then ok "$m: re-sync byte-identical (set=${src:0:16})"; else fail "$m: re-sync MISMATCH src=${src:0:16} dst=${dst:0:16}"; fi

  # (2) the thesis gate: it must be INCREMENTAL, not a silent full transfer. A correct-but-full
  #     re-sync defeats B-8; the rename case especially must delta the moved bytes, not re-send.
  if delta_engaged "$slog" "$src_bytes"; then
    ok "$m: delta path engaged (shipped only changed chunks)"
  elif delta_full_fallback "$slog"; then
    fail "$m: fell back to FULL-OBJECT transfer (not incremental — defeats B-8)"
  else
    log "  $m: could not classify delta mode from sender log $slog (review)"
    fail "$m: delta mode unclassified"
  fi
done

# ---- summary ----
status="passed"; [ "$FAIL" -eq 0 ] || status="failed"
cat >"$SUMMARY" <<EOF_SUM
{
  "schema_version": "atp-delta-resync-e2e-v1",
  "bead": "asupersync-bzkxa5",
  "transport": "${TRANSPORT}",
  "mutations": "${MUTATIONS}",
  "pass": ${PASS},
  "fail": ${FAIL},
  "status": "${status}",
  "artifacts": "${OUT}",
  "repro_command": "ATP_BIN=${ATP_BIN} bash scripts/atp_delta_resync_e2e.sh"
}
EOF_SUM

banner "RESULT"
log "PASS=$PASS FAIL=$FAIL  summary=$SUMMARY"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
