#!/usr/bin/env bash
# atp_e2e_lossy.sh — ATP convergence-under-loss e2e (bead G4.2 / 317hxr.15.2).
#
# Proves the value proposition of RaptorQ-over-QUIC: a transfer still converges
# (bit-for-bit) across a lossy link, repairing dropped datagrams via fountain
# coding + NeedMore feedback rounds instead of stalling. For each packet-loss
# epsilon in EPS_SWEEP it runs a real QUIC send -> recv through a userspace lossy
# UDP relay (scripts/lossy_udp_relay.py) that drops a controlled fraction of
# datagrams, then asserts: sender exits 0, receiver commits, dst sha256 == src
# sha256. It records the relay's forward/drop counts (the repair-cost proxy:
# more loss => more symbols forwarded to converge) and wall time per epsilon.
#
# Why a relay and not `tc netem`: tc qdisc on `lo` needs root AND globally
# degrades loopback for every other agent on the box. The relay is pure
# userspace, unprivileged, per-transfer, and reproducible (seeded PRNG).
#
# Loss is DATA-direction only by default (sender->receiver symbols); the control
# direction (feedback/Proof) is kept lossless so this isolates "does erasure
# coding repair DATA loss" from "does the control plane survive loss" (the F6
# concern — exercise that separately with CTRL_LOSS>0). Single-file payloads are
# used on purpose so this does not also trip the multi-entry proof bug (G9 .20).
#
# rq (RaptorQ over plain UDP + a TCP control channel) is NOT run here: a UDP
# relay cannot carry rq's TCP control stream. rq convergence-under-loss is proven
# over the real internet by the cross-machine gauntlet (G4.3 .15.3).
#
# Usage: ATP_BIN=/path/to/atp ./scripts/atp_e2e_lossy.sh
#        SIZE=4M:4194304 EPS_SWEEP="0 0.05 0.1 0.2" CTRL_LOSS=0.0 ./scripts/atp_e2e_lossy.sh
set -uo pipefail

ATP_BIN="${ATP_BIN:-}"
SIZE="${SIZE:-2M:2097152}"                 # single-file payload (label:bytes)
EPS_SWEEP="${EPS_SWEEP:-0 0.01 0.05 0.10 0.20}"  # data-direction packet-loss fractions
CTRL_LOSS="${CTRL_LOSS:-0.0}"              # control-direction loss (0 = isolate erasure repair)
TRANSFER_TIMEOUT="${TRANSFER_TIMEOUT:-60}" # per-epsilon bound; a non-converging case fails here
WORKERS="${WORKERS:-4}"
SEED="${SEED:-1}"
PORT="${PORT_BASE:-19700}"
RELAY="${RELAY:-$(dirname "$0")/lossy_udp_relay.py}"
# Tracked known gaps (transport:eps => bead/reason): a FAIL whose key matches is recorded as XFAIL.
# The F1 receiver work now makes the ordinary data-loss floor real: eps=0.01/0.05/0.10 must pass and
# may no longer be hidden behind default XFAILs. Keep only the extreme eps=0.20 case as a bounded
# follow-up until the reliable-control/F6 path proves it inside the same 60s budget.
KNOWN_GAPS="${KNOWN_GAPS:-quic:0.20=G4.2/F6:extreme-loss-control-recovery-budget}"
TS="$(date +%Y%m%d_%H%M%S)"; OUT="${OUT:-/tmp/atp_e2e_lossy_$TS}"; W="$OUT/work"
mkdir -p "$W/src" "$OUT/logs"; RESULTS="$OUT/results.jsonl"; : > "$RESULTS"; PASS=0; FAIL=0; XFAIL=0; ALL_PIDS=()
log(){ printf '%s | %s\n' "$(date '+%H:%M:%S')" "$*"; }
banner(){ printf '\n========== %s ==========\n' "$*"; }

if [ -z "$ATP_BIN" ]; then for c in /data/tmp/cargo-target/release/atp ./target/release/atp; do [ -x "$c" ] && ATP_BIN="$c" && break; done; fi
[ -n "$ATP_BIN" ] && [ -x "$ATP_BIN" ] || { log "FATAL: atp binary not found (set ATP_BIN)"; exit 2; }
command -v python3 >/dev/null 2>&1 || { log "FATAL: python3 required for the lossy relay"; exit 2; }
[ -f "$RELAY" ] || { log "FATAL: relay script not found: $RELAY"; exit 2; }
log "atp: $ATP_BIN"; log "relay: $RELAY"
# kill ONLY the procs this script spawned (receiver + relay; sender runs foreground under timeout) —
# never a broad pkill -f atp that would hit other agents' concurrent runs.
cleanup(){ local p; for p in ${ALL_PIDS[@]+"${ALL_PIDS[@]}"}; do kill -9 "$p" 2>/dev/null; done; }
trap cleanup EXIT INT TERM

KEY="$("$ATP_BIN" rq-keygen 2>/dev/null | grep -oE '[0-9a-f]{64}' | head -1)"; [ -n "$KEY" ] || KEY="$(openssl rand -hex 32)"
gen_certs(){ local d="$OUT/certs"; mkdir -p "$d"; ( cd "$d"
  openssl ecparam -name prime256v1 -genkey -noout -out ca.key 2>/dev/null
  openssl req -x509 -new -key ca.key -days 3650 -subj "/CN=atp-lossy-ca" -out ca.pem 2>/dev/null
  openssl ecparam -name prime256v1 -genkey -noout -out leaf.key 2>/dev/null
  openssl req -new -key leaf.key -subj "/CN=atp-lossy" -out leaf.csr 2>/dev/null
  printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n' > leaf.ext
  openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 3650 -extfile leaf.ext -out leaf.pem 2>/dev/null ); }

label="${SIZE%%:*}"; bytes="${SIZE##*:}"
head -c "$bytes" /dev/urandom > "$W/src/file.bin"
SRC_SHA="$(sha256sum "$W/src/file.bin" | awk '{print $1}')"
gen_certs

jnum(){ python3 -c "import json,sys;print(json.load(open(sys.argv[1])).get(sys.argv[2],'?'))" "$1" "$2" 2>/dev/null || echo '?'; }

run_lossy(){ # eps
  local eps="$1"; PORT=$((PORT+2)); local rport=$PORT lport=$((PORT+1))
  local tag="quic_eps${eps}"; local dst="$W/dst_$tag"; rm -rf "$dst" 2>/dev/null; mkdir -p "$dst"
  local rlog="$OUT/logs/recv_$tag.log" slog="$OUT/logs/send_$tag.log"
  local relaylog="$OUT/logs/relay_$tag.log" relaystats="$OUT/logs/relay_$tag.stats" ready="$OUT/logs/relay_$tag.ready"
  banner "LOSSY quic  eps=$eps  (recv:$rport relay:$lport->$rport)"
  # 1) receiver on the real port
  "$ATP_BIN" recv "$dst" --listen "127.0.0.1:$rport" --transport quic --once \
    --server-cert "$OUT/certs/leaf.pem" --server-key "$OUT/certs/leaf.key" \
    --rq-auth-key-hex "$KEY" --workers "$WORKERS" --max-bytes 2147483648 > "$rlog" 2>&1 &
  local rpid=$!; ALL_PIDS+=("$rpid")
  local r=0; for _ in $(seq 1 60); do grep -qi "quic listening" "$rlog" 2>/dev/null && { r=1; break; }; sleep 0.25; done
  [ "$r" = 1 ] || { log "  receiver not ready"; kill "$rpid" 2>/dev/null; printf '{"transport":"quic","eps":%s,"result":"FAIL","reason":"recv_not_ready"}\n' "$eps" >>"$RESULTS"; FAIL=$((FAIL+1)); return; }
  # 2) lossy relay (sender targets lport; relay forwards to rport, dropping eps of DATA datagrams)
  python3 "$RELAY" --listen "127.0.0.1:$lport" --target "127.0.0.1:$rport" \
    --loss "$eps" --loss-ctrl "$CTRL_LOSS" --seed "$SEED" --ready-file "$ready" --stats-file "$relaystats" \
    > "$relaylog" 2>&1 &
  local gpid=$!; ALL_PIDS+=("$gpid")
  for _ in $(seq 1 40); do [ -f "$ready" ] && break; sleep 0.1; done
  # 3) send THROUGH the relay, bounded
  local t0 t1 elapsed
  t0=$(date +%s)
  timeout "$TRANSFER_TIMEOUT" "$ATP_BIN" send "$W/src/file.bin" "127.0.0.1:$lport" --transport quic \
    --ca "$OUT/certs/ca.pem" --server-name 127.0.0.1 \
    --rq-auth-key-hex "$KEY" --workers "$WORKERS" --max-bytes 2147483648 > "$slog" 2>&1
  local send_rc=$?
  t1=$(date +%s); elapsed=$((t1-t0))
  sleep 1; kill "$rpid" "$gpid" 2>/dev/null; wait "$rpid" "$gpid" 2>/dev/null
  # 4) verify convergence
  local dst_sha; dst_sha="$(sha256sum "$dst/file.bin" 2>/dev/null | awk '{print $1}')"
  local committed; committed="$(grep -o '"committed":true' "$rlog" 2>/dev/null | head -1)"
  local dfwd ddrop aloss
  dfwd="$(jnum "$relaystats" data_fwd)"; ddrop="$(jnum "$relaystats" data_drop)"; aloss="$(jnum "$relaystats" data_actual_loss)"
  local verdict="PASS" reason=""
  if [ "$send_rc" = 124 ]; then verdict="FAIL"; reason="transfer_timeout_${TRANSFER_TIMEOUT}s_no_convergence"
  elif [ "$send_rc" != 0 ]; then verdict="FAIL"; reason="send_rc=$send_rc"
  elif [ -z "$committed" ]; then verdict="FAIL"; reason="receiver_not_committed"
  elif [ "$dst_sha" != "$SRC_SHA" ]; then verdict="FAIL"; reason="sha_mismatch(dst=${dst_sha:-MISSING})"
  fi
  # downgrade a FAIL to tracked XFAIL when this transport:eps is a known, beaded convergence gap
  local gap=""; case " $KNOWN_GAPS " in *" quic:$eps="*) gap="${KNOWN_GAPS##*"quic:$eps="}"; gap="${gap%% *}";; esac
  [ "$verdict" = FAIL ] && [ -n "$gap" ] && { verdict="XFAIL"; reason="${reason} [known-gap:$gap]"; }
  log "  eps=$eps send_rc=$send_rc committed=${committed:+yes} dst_sha_ok=$([ "$dst_sha" = "$SRC_SHA" ] && echo 1 || echo 0) data_fwd=$dfwd data_drop=$ddrop actual_loss=$aloss wall=${elapsed}s => $verdict${reason:+ ($reason)}"
  case "$verdict" in
    PASS)  PASS=$((PASS+1));;
    XFAIL) XFAIL=$((XFAIL+1));;
    *)     FAIL=$((FAIL+1)); log "  --- send log tail ---"; tail -3 "$slog" | sed 's/^/    s| /'; log "  --- recv log tail ---"; tail -3 "$rlog" | sed 's/^/    r| /';;
  esac
  printf '{"transport":"quic","eps":%s,"result":"%s","send_rc":%s,"sha_ok":%s,"data_fwd":"%s","data_drop":"%s","actual_loss":"%s","wall_s":%s,"reason":"%s"}\n' \
    "$eps" "$verdict" "$send_rc" "$([ "$dst_sha" = "$SRC_SHA" ] && echo true || echo false)" "$dfwd" "$ddrop" "$aloss" "$elapsed" "$reason" >> "$RESULTS"
  rm -rf "$dst" 2>/dev/null || true
}

banner "ATP CONVERGENCE-UNDER-LOSS E2E ($TS)  size=$label  eps=[$EPS_SWEEP]  ctrl_loss=$CTRL_LOSS  timeout=${TRANSFER_TIMEOUT}s"
log "src sha256=$SRC_SHA"
for eps in $EPS_SWEEP; do run_lossy "$eps"; done
banner "SUMMARY"
log "PASS=$PASS XFAIL=$XFAIL FAIL=$FAIL   results: $RESULTS"
if command -v jq >/dev/null 2>&1; then jq -rs '.[] | "  \(.result)\tquic eps=\(.eps)  sha_ok=\(.sha_ok) fwd=\(.data_fwd) drop=\(.data_drop) actual_loss=\(.actual_loss) wall=\(.wall_s)s\(if .reason != "" then "  \(.reason)" else "" end)"' "$RESULTS"; else cat "$RESULTS"; fi
printf '{"ts":"%s","size":"%s","pass":%s,"xfail":%s,"fail":%s}\n' "$TS" "$label" "$PASS" "$XFAIL" "$FAIL" > "$OUT/summary.json"
log "artifacts: $OUT"
[ "$FAIL" -eq 0 ] && { log "==== LOSSY E2E: PASS (xfail=$XFAIL) ===="; exit 0; } || { log "==== LOSSY E2E: FAIL ($FAIL) ===="; exit 1; }
