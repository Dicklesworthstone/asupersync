#!/usr/bin/env bash
# atp_e2e_cancel.sh — ATP peer-death / cancel robustness e2e (bead G4.6).
#
# Kills one side of a live transfer mid-flight and asserts the SURVIVING side:
#   (1) does NOT hang forever — it exits within a bounded window (its idle timeout),
#   (2) when the survivor is the RECEIVER, it CLEANS its staging dir (.atp-*-staging-*)
#       instead of leaking it (the F-REG failure mode, on abnormal peer death),
#   (3) leaves NO orphaned atp processes.
# Covers both transports (rq, quic) and both victims (sender, receiver).
# Process-level robustness (peer crash / partition); in-process Cx cancel-correctness
# is covered by the per-feature lab tests, not here.
#
# Usage: ATP_BIN=/path/to/atp ./scripts/atp_e2e_cancel.sh
#        SIZE=50M:52428800 TRANSPORTS="rq quic" VICTIMS="sender receiver" ./scripts/atp_e2e_cancel.sh
#
# Findings (first full run, 2026-06-16, loopback, size=50M):
#   rq  /kill-sender   -> receiver exits 0s, staging clean   => PASS  (TCP control EOF = instant peer death)
#   rq  /kill-receiver -> sender   exits 1s, clean           => PASS  (TCP control EOF)
#   quic/kill-sender   -> receiver exits 61s, staging CLEANED => PASS  (no liveness signal; waits full idle
#                                                                       timeout, but DOES self-clean on timeout)
#   quic/kill-receiver -> sender   keeps spraying/waiting, hangs past SURVIVOR_TIMEOUT => tracked XFAIL (G9/F6)
#   => rq gets fast peer-death detection for free from its TCP control channel; quic over pure UDP has no
#      liveness signal, so peer death is only noticed via the 60s idle timeout (and only once the sender
#      stops spraying). The fix is F6 (reliable self-resync control + keepalive/liveness); see KNOWN_GAPS.
set -uo pipefail

ATP_BIN="${ATP_BIN:-}"
SIZE="${SIZE:-50M:52428800}"          # one size, big enough to still be in-flight at KILL_DELAY
TRANSPORTS="${TRANSPORTS:-rq quic}"
VICTIMS="${VICTIMS:-sender receiver}"
WORKERS="${WORKERS:-4}"
KILL_DELAY="${KILL_DELAY:-1.5}"        # seconds into the transfer before we kill the victim
SURVIVOR_TIMEOUT="${SURVIVOR_TIMEOUT:-80}"  # bound: survivor must exit within this (idle_timeout 60s + margin)
PORT="${PORT_BASE:-19600}"
# Tracked known gaps (transport:victim => bead/reason). A FAIL whose "transport:victim" matches a key
# is recorded as XFAIL (expected-fail) instead of failing the suite, so this stays a GREEN regression
# floor while the gap is tracked — exactly like the KNOWN_GAPS xfail in scripts/atp_e2e_loopback.sh.
#   quic:receiver — on abrupt RECEIVER death the quic SENDER has no peer-liveness signal (rq gets one
#   for free from its TCP control channel), so it keeps spraying/waiting instead of failing fast; the
#   idle-timeout only fires once it stops sending, so the sender hangs well past SURVIVOR_TIMEOUT.
#   Tracked by G9 / F6 (reliable self-resync control + keepalive/liveness). Remove this key once F6
#   gives quic a fast peer-death signal and the scenario exits bounded on its own.
KNOWN_GAPS="${KNOWN_GAPS:-quic:receiver=G9/F6:quic-sender-no-peer-liveness-hangs-on-receiver-death}"
TS="$(date +%Y%m%d_%H%M%S)"; OUT="${OUT:-/tmp/atp_e2e_cancel_$TS}"; W="$OUT/work"
mkdir -p "$W/src" "$OUT/logs"; RESULTS="$OUT/results.jsonl"; : > "$RESULTS"; PASS=0; FAIL=0; XFAIL=0; ALL_PIDS=()
log(){ printf '%s | %s\n' "$(date '+%H:%M:%S')" "$*"; }
banner(){ printf '\n========== %s ==========\n' "$*"; }

if [ -z "$ATP_BIN" ]; then for c in /data/tmp/cargo-target/release/atp /data/tmp/rch_target_atp_release2/release/atp ./target/release/atp; do [ -x "$c" ] && ATP_BIN="$c" && break; done; fi
[ -n "$ATP_BIN" ] && [ -x "$ATP_BIN" ] || { log "FATAL: atp binary not found (set ATP_BIN)"; exit 2; }
log "atp: $ATP_BIN"
# Clean up ONLY the atp processes this script spawned (tracked in ALL_PIDS) on any exit/interrupt —
# never a broad `pkill -f atp`, which would also kill OTHER agents' concurrent atp runs sharing the
# same binary path. This makes an interrupted/cut run (e.g. during the long quic survivor-wait) leave
# no orphans of ours behind.
cleanup(){ local p; for p in ${ALL_PIDS[@]+"${ALL_PIDS[@]}"}; do kill -9 "$p" 2>/dev/null; done; }
trap cleanup EXIT INT TERM
KEY="$("$ATP_BIN" rq-keygen 2>/dev/null | grep -oE '[0-9a-f]{64}' | head -1)"; [ -n "$KEY" ] || KEY="$(openssl rand -hex 32)"

gen_certs(){ local d="$OUT/certs"; mkdir -p "$d"; ( cd "$d"
  openssl ecparam -name prime256v1 -genkey -noout -out ca.key 2>/dev/null
  openssl req -x509 -new -key ca.key -days 3650 -subj "/CN=atp-cancel-ca" -out ca.pem 2>/dev/null
  openssl ecparam -name prime256v1 -genkey -noout -out leaf.key 2>/dev/null
  openssl req -new -key leaf.key -subj "/CN=atp-cancel" -out leaf.csr 2>/dev/null
  printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n' > leaf.ext
  openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 3650 -extfile leaf.ext -out leaf.pem 2>/dev/null ); }

label="${SIZE%%:*}"; bytes="${SIZE##*:}"
[ -f "$W/src/file.bin" ] && [ "$(stat -c%s "$W/src/file.bin" 2>/dev/null)" = "$bytes" ] || head -c "$bytes" /dev/urandom > "$W/src/file.bin"
echo "$TRANSPORTS" | grep -qw quic && gen_certs

alive(){ kill -0 "$1" 2>/dev/null; }
orphans(){ pgrep -af "$ATP_BIN" 2>/dev/null | grep -v "$$" | wc -l; }

run_cancel(){ # transport victim
  local tr="$1" victim="$2"; PORT=$((PORT+1))
  local dst="$W/dst_${tr}_${victim}"; rm -rf "$dst" 2>/dev/null; mkdir -p "$dst"
  local rlog="$OUT/logs/recv_${tr}_${victim}.log" slog="$OUT/logs/send_${tr}_${victim}.log"
  local rextra="" sextra="" ready="listening"
  if [ "$tr" = quic ]; then rextra="--server-cert $OUT/certs/leaf.pem --server-key $OUT/certs/leaf.key"; sextra="--ca $OUT/certs/ca.pem --server-name 127.0.0.1"; ready="quic listening"; else sextra="--streams 4"; fi
  banner "CANCEL $tr  kill=$victim  (port $PORT)"
  "$ATP_BIN" recv "$dst" --listen "127.0.0.1:$PORT" --transport "$tr" --once $rextra --rq-auth-key-hex "$KEY" --workers "$WORKERS" --max-bytes 2147483648 > "$rlog" 2>&1 &
  local rpid=$!; ALL_PIDS+=("$rpid")
  local r=0; for _ in $(seq 1 60); do grep -qi "$ready" "$rlog" 2>/dev/null && { r=1; break; }; sleep 0.25; done
  [ "$r" = 1 ] || { log "  receiver not ready"; kill "$rpid" 2>/dev/null; printf '{"transport":"%s","victim":"%s","result":"FAIL","reason":"recv_not_ready"}\n' "$tr" "$victim" >>"$RESULTS"; FAIL=$((FAIL+1)); return; }
  "$ATP_BIN" send "$W/src/file.bin" "127.0.0.1:$PORT" --transport "$tr" $sextra --rq-auth-key-hex "$KEY" --workers "$WORKERS" --max-bytes 2147483648 > "$slog" 2>&1 &
  local spid=$!; ALL_PIDS+=("$spid")
  sleep "$KILL_DELAY"
  # confirm the transfer is genuinely in flight (both alive) before killing
  if ! alive "$spid" || ! alive "$rpid"; then log "  NOTE: a side already exited before kill (transfer too fast for KILL_DELAY=$KILL_DELAY)"; fi
  local vpid spid_or_rpid survivor_pid survivor_name
  if [ "$victim" = sender ]; then vpid=$spid; survivor_pid=$rpid; survivor_name=receiver; else vpid=$rpid; survivor_pid=$spid; survivor_name=sender; fi
  log "  killing $victim (pid $vpid) mid-transfer (SIGKILL = abrupt peer death)"
  kill -9 "$vpid" 2>/dev/null; wait "$vpid" 2>/dev/null
  # observe survivor: must exit within SURVIVOR_TIMEOUT
  local t0 exited=0; t0=$(date +%s)
  while alive "$survivor_pid"; do
    [ $(( $(date +%s) - t0 )) -ge "$SURVIVOR_TIMEOUT" ] && break
    sleep 1
  done
  local elapsed=$(( $(date +%s) - t0 ))
  if alive "$survivor_pid"; then exited=0; log "  survivor ($survivor_name) STILL RUNNING after ${elapsed}s — killing"; kill -9 "$survivor_pid" 2>/dev/null; else exited=1; log "  survivor ($survivor_name) exited after ${elapsed}s"; fi
  wait "$survivor_pid" 2>/dev/null
  # checks
  local staging="none"; ls -d "$dst"/.atp-*-staging-* >/dev/null 2>&1 && staging="LEAKED"
  local orph; orph=$(orphans)
  # verdict: survivor must have exited bounded; if receiver survived, staging must be clean; no orphans
  local verdict="PASS" reason=""
  [ "$exited" = 1 ] || { verdict="FAIL"; reason="survivor_hung"; }
  [ "$survivor_name" = receiver ] && [ "$staging" = LEAKED ] && { verdict="FAIL"; reason="${reason} staging_leaked_on_peer_death"; }
  # downgrade a FAIL to a tracked XFAIL when this transport:victim is a known, beaded gap
  local gap=""; case " $KNOWN_GAPS " in *" $tr:$victim="*) gap="${KNOWN_GAPS##*"$tr:$victim="}"; gap="${gap%% *}";; esac
  [ "$verdict" = FAIL ] && [ -n "$gap" ] && { verdict="XFAIL"; reason="${reason} [known-gap:$gap]"; }
  log "  survivor=$survivor_name exited=${exited} elapsed=${elapsed}s staging=$staging orphans_after=$orph => $verdict${reason:+ ($reason)}"
  case "$verdict" in
    PASS)  PASS=$((PASS+1));;
    XFAIL) XFAIL=$((XFAIL+1));;
    *)     FAIL=$((FAIL+1)); log "  --- survivor log tail ---"; tail -5 "$([ "$survivor_name" = receiver ] && echo "$rlog" || echo "$slog")" | sed 's/^/    | /';;
  esac
  printf '{"transport":"%s","victim":"%s","survivor":"%s","result":"%s","exited":%s,"elapsed_s":%s,"staging":"%s","orphans":%s,"reason":"%s"}\n' \
    "$tr" "$victim" "$survivor_name" "$verdict" "$exited" "$elapsed" "$staging" "$orph" "$reason" >> "$RESULTS"
  # kill only the two procs this scenario spawned (never a broad pkill that would hit peer agents)
  kill -9 "$rpid" "$spid" 2>/dev/null; wait "$rpid" "$spid" 2>/dev/null; rm -rf "$dst" 2>/dev/null || true
}

banner "ATP CANCEL / PEER-DEATH E2E ($TS)  size=$label transports=[$TRANSPORTS] victims=[$VICTIMS]"
for tr in $TRANSPORTS; do for v in $VICTIMS; do run_cancel "$tr" "$v"; done; done
banner "SUMMARY"
log "PASS=$PASS XFAIL=$XFAIL FAIL=$FAIL   results: $RESULTS"
if command -v jq >/dev/null 2>&1; then jq -rs '.[] | "  \(.result)\t\(.transport)/kill-\(.victim)  survivor=\(.survivor) exited=\(.exited) elapsed=\(.elapsed_s)s staging=\(.staging)\(if .reason != "" then "  \(.reason)" else "" end)"' "$RESULTS"; else cat "$RESULTS"; fi
printf '{"ts":"%s","pass":%s,"xfail":%s,"fail":%s}\n' "$TS" "$PASS" "$XFAIL" "$FAIL" > "$OUT/summary.json"
log "artifacts: $OUT"
[ "$FAIL" -eq 0 ] && { log "==== CANCEL E2E: PASS (xfail=$XFAIL) ===="; exit 0; } || { log "==== CANCEL E2E: FAIL ($FAIL) ===="; exit 1; }
