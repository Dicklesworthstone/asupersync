#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# resync_bench.sh — the incremental RE-SYNC benchmark (B-8.7, asupersync-0kh4jm):
# a fail-closed functional gate for authenticated in-session re-sync control.
# It records BYTES-ON-WIRE for diagnostics, but does not make a throughput win
# claim against the plaintext rsyncd comparison lane.
#
# Per (size x regime x change-mode):
#   1. gen a base payload; do an INITIAL full sync to seed the receiver's prior
#      state (atp into one dest, rsync into another) — UNMEASURED setup;
#   2. MUTATE the source (0% / 1% / 10% byte flips / append / insert / rename);
#   3. RE-SYNC (measured): ATP with delta control default-on and tuned rsync
#      delta mode each into their pre-seeded dest. Measure bytes-on-wire (netns
#      veth tx+rx byte counters, tool-agnostic), wall, peak RSS;
#   4. VERIFY byte-identical (tree_digest src == dst). For 0pct, additionally
#      require the exact zero-payload sender/receiver JSON tuple, a naturally
#      closing receiver, unchanged destination-file identity, and bounded
#      nonzero authenticated-control wire bytes. FAIL-CLOSED: a mismatch is
#      recorded status!=ok and can never score as a win.
# Emits one JSONL row per (size, regime, change-mode, method). Requires root
# (netns/tc). Changed-source modes currently expose authenticated full-object
# fallback and are never labeled or scored as missing-chunk delta.
#
#   sudo env BIN=/tmp/atp_bench/atp bash scripts/atp_bench/resync_bench.sh
#   # resync.jsonl is functional evidence, not a headline score_matrix input.
#
# atp delta is default-on; --no-delta forces a full send (the fallback baseline).
# The default RQ lane uses one strict per-run key over protected stdin. Delta
# negotiation stays on the real framed control connection: there is no port+1
# state listener or cached-state shortcut. The 0pct cell is a fail-closed live
# zero-payload gate; changed cells honestly expose full fallback until the
# authenticated missing-chunk data path is enabled. QUIC needs a separate TLS +
# protected-control-key acceptance profile; this RQ-only harness does not claim
# that profile exists or admit QUIC evidence.
# ─────────────────────────────────────────────────────────────────────────────

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GEN_TREE="${GEN_TREE:-$HERE/gen_tree.py}"
BIN="${BIN:-/tmp/atp_bench/atp}"
OUT_DIR="${OUT_DIR:-/tmp/atp_resync_bench}"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
RUN_DIR="${RUN_DIR:-${OUT_DIR}/${RUN_ID}}"
RESULTS="${RESULTS:-${RUN_DIR}/resync.jsonl}"

# label:bytes for single-file workloads; trees handled via CHANGE=rename.
SIZES="${SIZES:-5M:5242880 100M:104857600 500M:524288000}"
REGIMES="${REGIMES:-perfect good bad}"
# 0pct/1pct/10pct/append/insert mutate a file; rename mutates a tree.
CHANGES="${CHANGES:-0pct}"

WORKERS="${WORKERS:-4}"
ATP_TRANSPORT="${ATP_TRANSPORT:-rq}"
STREAMS="${STREAMS:-1}"
SYMBOL_SIZE="${SYMBOL_SIZE:-1200}"
MAX_BYTES="${MAX_BYTES:-6442450944}"
if [ -z "${HOST_IP+x}" ] && [ -z "${NS_IP+x}" ]; then
    # Pick a per-run subnet by default so concurrent netns benches do not
    # collide on the old fixed 10.99.0.0/24 route.
    NETNS_SUBNET="${NETNS_SUBNET:-$(printf '%s' "$RUN_ID" | cksum | awk '{printf "10.%d.%d", 64 + ($1 % 128), 1 + (int($1 / 128) % 254)}')}"
    HOST_IP="${NETNS_SUBNET}.1"
    NS_IP="${NETNS_SUBNET}.2"
else
    HOST_IP="${HOST_IP:-10.99.0.1}"
    NS_IP="${NS_IP:-10.99.0.2}"
fi
CIDR="${CIDR:-24}"
PORT_BASE="${PORT_BASE:-41000}"
TIMEOUT_S="${TIMEOUT_S:-300}"
ATP_RECV_LISTEN_TIMEOUT_MS="${ATP_RECV_LISTEN_TIMEOUT_MS:-30000}"
ATP_RECV_ACCEPT_TIMEOUT_SECS="${ATP_RECV_ACCEPT_TIMEOUT_SECS:-$(((ATP_RECV_LISTEN_TIMEOUT_MS + 999) / 1000))}"
RECEIVER_READY_SLEEP="${RECEIVER_READY_SLEEP:-0.75}"
RSS_SAMPLE_INTERVAL="${RSS_SAMPLE_INTERVAL:-0.2}"
TREE_PRESET="${TREE_PRESET:-tree_small}"
GIT_HEAD="$(git -C "$HERE" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"

NS=""; IF_HOST=""; IF_NS=""; RSYNCD_PID=""

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }
die() { echo "resync_bench.sh: $*" >&2; exit 2; }

[ "$ATP_TRANSPORT" = "rq" ] \
    || die "ATP_TRANSPORT must be rq; QUIC is not admitted by this RQ-only gate"
[[ -z "${ATP_RQ_AUTH_KEY_HEX:-}" ]] || die "ATP_RQ_AUTH_KEY_HEX is forbidden; this harness generates a protected per-run key"
[[ -z "${RQ_AUTH_KEY_HEX:-}" ]] || die "RQ_AUTH_KEY_HEX is forbidden; this harness generates a protected per-run key"
[[ -z "${RQ_AUTH_SECRET:-}" ]] || die "RQ_AUTH_SECRET is forbidden; this harness generates a protected per-run key"
unset RQ_AUTH_SECRET
RQ_AUTH_SECRET=""
[ "$(id -u)" = "0" ] || die "needs root (netns/tc)"
[ -x "$BIN" ] || die "BIN not executable: $BIN"
[ -f "$GEN_TREE" ] || die "gen_tree.py missing: $GEN_TREE"
for c in awk dd ip tc rsync sha256sum python3 pgrep timeout /usr/bin/time; do
    command -v "$c" >/dev/null 2>&1 || die "missing command: $c"
done

mkdir -p "$RUN_DIR"

now_s() { date +%s.%N; }
elapsed_s() { awk -v a="$1" -v b="$2" 'BEGIN { printf "%.6f", b - a }'; }
sha256_file() { if [ -f "$1" ]; then sha256sum "$1" | awk '{print $1}'; else printf 'missing'; fi; }
max_rss_kb_from_time() {
    local value=""
    if [ -f "$1" ]; then
        value="$(awk -F: '/Maximum resident set size/ { gsub(/^[ \t]+/,"",$2); print $2 }' "$1" | tail -n1)"
    fi
    printf '%s' "${value:-0}"
}

tree_digest() {
    local root="$1"; [ -d "$root" ] || { printf 'missing'; return; }
    ( cd "$root" && find . -type f ! -name 'SHA256SUMS' ! -name '*.manifest.jsonl' \
        ! -path './.asupersync-atp-delta-v1/*' -print0 | sort -z \
        | while IFS= read -r -d '' f; do printf '%s:%s\n' "${f#./}" "$(sha256sum "$f" | awk '{print $1}')"; done ) \
        | sha256sum | awk '{print $1}'
}
tree_size_bytes() {
    python3 - "$1" <<'PY'
import json, sys
total = 0
with open(sys.argv[1], encoding="utf-8") as fh:
    for line in fh:
        if line.strip():
            total += int(json.loads(line).get("size", 0))
print(total)
PY
}
change_requested() {
    local needle="$1" change
    for change in $CHANGES; do
        [ "$change" = "$needle" ] && return 0
    done
    return 1
}

clear_rq_auth_secret() {
    set +x
    if [[ -n "${RQ_AUTH_SECRET:-}" ]]; then
        RQ_AUTH_SECRET=0000000000000000000000000000000000000000000000000000000000000000
    fi
    unset RQ_AUTH_SECRET
}
ensure_rq_auth_secret() {
    if [[ -z "${RQ_AUTH_SECRET:-}" ]]; then
        set +x
        RQ_AUTH_SECRET=$(env -u ATP_RQ_AUTH_KEY_HEX -u RQ_AUTH_KEY_HEX "$BIN" rq-keygen)
    fi
    [[ "$RQ_AUTH_SECRET" =~ ^[0-9A-Fa-f]{64}$ ]] \
        || die "generated ATP RQ auth key is not 64 hex characters"
}
send_rq_auth_secret() {
    set +x
    [[ ${#RQ_AUTH_SECRET} -eq 64 ]] || die "ATP RQ auth key is not initialized"
    builtin printf '%s\n' "$RQ_AUTH_SECRET"
}

# bytes-on-wire = sender (netns) veth tx+rx delta around the measured transfer.
ns_wire_bytes() {
    local tx rx
    tx="$(ip netns exec "$NS" cat "/sys/class/net/${IF_NS}/statistics/tx_bytes" 2>/dev/null || echo 0)"
    rx="$(ip netns exec "$NS" cat "/sys/class/net/${IF_NS}/statistics/rx_bytes" 2>/dev/null || echo 0)"
    printf '%s' "$((tx + rx))"
}

regime_netem() {
    case "$1" in
        perfect) printf 'delay 2ms rate 1gbit' ;;
        good)    printf 'delay 25ms loss 0.1%% rate 200mbit' ;;
        bad)     printf 'delay 80ms 20ms loss 2%% rate 50mbit' ;;
        worse)   printf 'delay 80ms 20ms loss 5%% rate 50mbit' ;;
        terrible) printf 'delay 120ms 30ms loss 10%% rate 20mbit' ;;
        highbdp) printf 'delay 200ms 10ms loss 0.1%% rate 1gbit' ;;
        *) die "unknown regime: $1" ;;
    esac
}
apply_regime() {
    local netem; netem="$(regime_netem "$1")"
    # shellcheck disable=SC2086
    tc qdisc replace dev "$IF_HOST" root netem $netem
    # shellcheck disable=SC2086
    ip netns exec "$NS" tc qdisc replace dev "$IF_NS" root netem $netem
}

setup_netns() {
    local sfx; sfx="$(printf '%s' "$RUN_ID" | cksum | awk '{print substr($1,1,6)}')"
    NS="atprs${sfx}"; IF_HOST="vrh${sfx}"; IF_NS="vrn${sfx}"
    ip netns add "$NS"
    ip link add "$IF_HOST" type veth peer name "$IF_NS"
    ip link set "$IF_NS" netns "$NS"
    ip addr add "${HOST_IP}/${CIDR}" dev "$IF_HOST"; ip link set "$IF_HOST" up
    ip netns exec "$NS" ip addr add "${NS_IP}/${CIDR}" dev "$IF_NS"
    ip netns exec "$NS" ip link set lo up
    ip netns exec "$NS" ip link set "$IF_NS" up
    log "netns $NS host=$HOST_IP ns=$NS_IP/$CIDR"
}
start_rsyncd() {
    local root="$1" conf="$2"
    cat >"$conf" <<EOF
use chroot = no
max connections = 0
reverse lookup = no
[bench]
    path = ${root}
    read only = false
    uid = root
    gid = root
EOF
    rsync --daemon --no-detach --address="$HOST_IP" --port=1873 --config="$conf" >"${conf}.log" 2>&1 &
    RSYNCD_PID=$!
    sleep 0.5
    kill -0 "$RSYNCD_PID" 2>/dev/null || die "rsyncd failed: $(cat "${conf}.log" 2>/dev/null)"
}
stop_rsyncd() {
    if [ -n "$RSYNCD_PID" ]; then
        kill "$RSYNCD_PID" 2>/dev/null || true
        RSYNCD_PID=""
    fi
    true
}

cleanup() {
    clear_rq_auth_secret
    stop_rsyncd
    if [ -n "$NS" ]; then
        ip netns del "$NS" >/dev/null 2>&1 || true
    fi
    if [ -n "$IF_HOST" ]; then
        ip link del "$IF_HOST" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

# ── payload + mutation ───────────────────────────────────────────────────────
gen_file() {
    local path="$1" bytes="$2" mb=$(( $2 / 1048576 )) rem=$(( $2 % 1048576 ))
    if [ "$mb" -gt 0 ]; then
        dd if=/dev/urandom of="$path" bs=1M count="$mb" status=none
    else
        : >"$path"
    fi
    if [ "$rem" -gt 0 ]; then
        dd if=/dev/urandom bs=1 count="$rem" status=none >>"$path"
    fi
}
# Apply a change mode to a FILE in place (operates on a copy passed as $1).
mutate_file() {
    local path="$1" mode="$2" size; size="$(stat -c%s "$path")"
    case "$mode" in
        0pct) : ;; # no change — re-sync should be ~0 bytes (AlreadyInSync)
        1pct)  python3 - "$path" "$size" 0.01 <<'PY'
import os, random, sys
p, size, frac = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
rng = random.Random(1234)
n = max(1, int(size * frac))
with open(p, "r+b") as f:
    for _ in range(n):
        f.seek(rng.randrange(size)); f.write(bytes([rng.randrange(256)]))
PY
            ;;
        10pct) python3 - "$path" "$size" 0.10 <<'PY'
import os, random, sys
p, size, frac = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
rng = random.Random(5678)
n = max(1, int(size * frac))
with open(p, "r+b") as f:
    for _ in range(n):
        f.seek(rng.randrange(size)); f.write(bytes([rng.randrange(256)]))
PY
            ;;
        append) dd if=/dev/urandom bs=64K count=1 status=none >>"$path" ;;
        insert) python3 - "$path" <<'PY'
import os, sys
p = sys.argv[1]
with open(p, "rb") as f: data = f.read()
mid = len(data)//2
ins = os.urandom(65536)
with open(p, "wb") as f: f.write(data[:mid] + ins + data[mid:])
PY
            ;;
        *) die "unknown file change mode: $mode" ;;
    esac
}
mutate_tree_rename() {
    local root="$1" first target
    first="$(python3 - "$root" <<'PY'
from pathlib import Path
import sys
root = Path(sys.argv[1])
files = sorted(path for path in root.rglob("*") if path.is_file())
print(files[0] if files else "")
PY
)"
    [ -n "$first" ] || die "tree rename requested but no files found under $root"
    target="${first}.renamed"
    [ ! -e "$target" ] || die "tree rename target already exists: $target"
    mv "$first" "$target"
}

sample_peak_rss() {
    local pattern="$1" stop="$2" out="$3" peak=0
    while [ ! -e "$stop" ]; do
        local total=0 pid rss
        for pid in $(pgrep -f "$pattern" 2>/dev/null || true); do
            rss="$(awk '/^VmRSS:/ {print $2}' "/proc/$pid/status" 2>/dev/null || true)"
            [ -n "$rss" ] && total=$((total + rss))
        done
        [ "$total" -gt "$peak" ] && peak="$total"
        sleep "$RSS_SAMPLE_INTERVAL"
    done
    printf '%s' "$peak" >"$out"
}

payload_identity_stamp() {
    stat -c '%d:%i:%s:%f:%u:%g:%y' "$1"
}

seed_atp_rq() {
    local src="$1" dest_dir="$2" port="$3" case_dir="$4" tag="$5"
    local recv_log="$case_dir/atp_init_recv.log" send_log="$case_dir/atp_init_send.log"
    local -a recv_cmd=(
        timeout "$TIMEOUT_S" env -u ATP_RQ_AUTH_KEY_HEX -u RQ_AUTH_KEY_HEX
        "$BIN" recv "$dest_dir" --listen "0.0.0.0:${port}" --transport rq --once
        --peer-id "init-${tag}-recv-${port}" --workers "$WORKERS" --max-bytes "$MAX_BYTES"
        --symbol-size "$SYMBOL_SIZE" --listen-timeout-ms "$ATP_RECV_LISTEN_TIMEOUT_MS"
        --accept-timeout-secs "$ATP_RECV_ACCEPT_TIMEOUT_SECS" --rq-auth-key-stdin --no-delta
    )
    local -a send_cmd=(
        ip netns exec "$NS" timeout "$TIMEOUT_S"
        env -u ATP_RQ_AUTH_KEY_HEX -u RQ_AUTH_KEY_HEX "$BIN" send "$src" "${HOST_IP}:${port}"
        --transport rq --streams "$STREAMS" --symbol-size "$SYMBOL_SIZE"
        --peer-id "init-${tag}-send-${port}" --max-bytes "$MAX_BYTES"
        --rq-auth-key-stdin --no-delta
    )

    set +e
    send_rq_auth_secret | "${recv_cmd[@]}" >"$recv_log" 2>&1 &
    local recv_pid=$!
    sleep "$RECEIVER_READY_SLEEP"
    send_rq_auth_secret | "${send_cmd[@]}" >"$send_log" 2>&1
    local send_status=$?
    if [ "$send_status" != "0" ]; then
        kill -0 "$recv_pid" 2>/dev/null && kill "$recv_pid" 2>/dev/null
    fi
    wait "$recv_pid" 2>/dev/null
    local recv_status=$?
    set -e

    if [ "$send_status" != "0" ] || [ "$recv_status" != "0" ]; then
        log "ATP seed sync failed (send=$send_status recv=$recv_status)"
        return 1
    fi
}

verify_rq_authenticated_noop() {
    local sender_log="$1" receiver_log="$2" source_bytes="$3" wire_bytes="$4"
    local before_stamp="$5" after_stamp="$6"
    python3 - "$sender_log" "$receiver_log" "$source_bytes" "$wire_bytes" \
        "$before_stamp" "$after_stamp" <<'PY'
import json
import sys

sender_path, receiver_path = sys.argv[1:3]
source_bytes, wire_bytes = map(int, sys.argv[3:5])
before_stamp, after_stamp = sys.argv[5:7]

def report(path, event):
    matches = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            try:
                candidate = json.loads(line)
            except json.JSONDecodeError:
                continue
            if candidate.get("event") == event:
                matches.append(candidate)
    if len(matches) != 1:
        raise SystemExit(f"expected exactly one {event} JSON report in {path}, got {len(matches)}")
    return matches[0]

sender = report(sender_path, "atp_send")
receiver = report(receiver_path, "atp_receive")

expected_sender = {
    "transport": "rq",
    "committed": True,
    "files": 1,
    "sha_ok": True,
    "merkle_ok": True,
    "bytes_sent": 0,
    "symbols_sent": 0,
    "feedback_rounds": 0,
}
expected_receiver = {
    "transport": "rq",
    "committed": True,
    "files": 1,
    "bytes_received": 0,
    "symbols_accepted": 0,
    "feedback_rounds": 0,
}
for key, expected in expected_sender.items():
    if sender.get(key) != expected:
        raise SystemExit(f"sender {key}: expected {expected!r}, got {sender.get(key)!r}")
for key, expected in expected_receiver.items():
    if receiver.get(key) != expected:
        raise SystemExit(f"receiver {key}: expected {expected!r}, got {receiver.get(key)!r}")

sender_transfer = sender.get("transfer_id")
if not sender_transfer or receiver.get("transfer_id") != sender_transfer:
    raise SystemExit("sender/receiver transfer_id is empty or mismatched")

for key in ("bytes", "symbols_sent", "symbols_accepted", "feedback_rounds"):
    if sender.get("metrics", {}).get(key) != 0:
        raise SystemExit(f"sender metrics.{key} is not zero")
for key in ("bytes", "symbols_accepted", "feedback_rounds"):
    if receiver.get("metrics", {}).get(key) != 0:
        raise SystemExit(f"receiver metrics.{key} is not zero")

if before_stamp != after_stamp:
    raise SystemExit("destination payload identity or metadata changed during authenticated no-op")
if not 0 < wire_bytes < source_bytes:
    raise SystemExit(
        f"authenticated control wire bytes must satisfy 0 < wire < source size; "
        f"wire={wire_bytes} source={source_bytes}"
    )
PY
}

run_cell_strict() {
    local cell_label="$1"
    shift
    set +e
    (
        # Keep the parent netns alive between cells, but always reap a cell-local
        # rsync daemon. Re-enable errexit inside this untested subshell so a
        # setup/mutation/copy failure cannot silently become a successful row.
        trap 'stop_rsyncd' EXIT
        set -e
        "$@"
    )
    local cell_status=$?
    set -e
    if [ "$cell_status" != "0" ]; then
        log "[FAIL] cell ${cell_label} aborted with status ${cell_status}"
        CELL_FAILURES=$((CELL_FAILURES + 1))
    fi
}

# ── measured re-sync for one method ──────────────────────────────────────────
# echoes: WIRE_BYTES WALL PEAK_RSS_KB STATUS_CODE
resync_atp() {
    local src="$1" dest_dir="$2" port="$3" case_dir="$4"
    local rl="$case_dir/atp_recv.log" sl="$case_dir/atp_send.log" rt="$case_dir/atp_recv.time" st="$case_dir/atp_send.time"
    local s_tag="atprs-send-${port}" r_tag="atprs-recv-${port}"
    local s_stop="$case_dir/atp_s_stop" s_out="$case_dir/atp_s_rss"
    local recv_args=(--transport rq --symbol-size "$SYMBOL_SIZE" --rq-auth-key-stdin)
    local send_args=(--transport rq --streams "$STREAMS" --symbol-size "$SYMBOL_SIZE" --rq-auth-key-stdin)
    set +e
    local -a recv_cmd=(
        timeout "$TIMEOUT_S" /usr/bin/time -v env -u ATP_RQ_AUTH_KEY_HEX -u RQ_AUTH_KEY_HEX
        "$BIN" recv "$dest_dir" --listen "0.0.0.0:${port}" "${recv_args[@]}"
        --once --peer-id "$r_tag" --workers "$WORKERS" --max-bytes "$MAX_BYTES"
        --listen-timeout-ms "$ATP_RECV_LISTEN_TIMEOUT_MS"
        --accept-timeout-secs "$ATP_RECV_ACCEPT_TIMEOUT_SECS"
    )
    send_rq_auth_secret | "${recv_cmd[@]}" >"$rl" 2>"$rt" &
    local recv_pid=$!
    sample_peak_rss "$s_tag" "$s_stop" "$s_out" & local samp=$!
    sleep "$RECEIVER_READY_SLEEP"
    local before after start finish ss rs
    before="$(ns_wire_bytes)"; start="$(now_s)"
    local -a send_cmd=(
        ip netns exec "$NS" timeout "$TIMEOUT_S" /usr/bin/time -v
        env -u ATP_RQ_AUTH_KEY_HEX -u RQ_AUTH_KEY_HEX "$BIN" send "$src" "${HOST_IP}:${port}"
        "${send_args[@]}" --peer-id "$s_tag" --max-bytes "$MAX_BYTES"
    )
    send_rq_auth_secret | "${send_cmd[@]}" >"$sl" 2>"$st"
    ss=$?
    finish="$(now_s)"; after="$(ns_wire_bytes)"
    if [ "$ss" != "0" ]; then
        kill -0 "$recv_pid" 2>/dev/null && kill "$recv_pid" 2>/dev/null
    fi
    wait "$recv_pid"; rs=$?
    touch "$s_stop"; wait "$samp" 2>/dev/null
    set -e
    # Default the RSS field to 0 when /usr/bin/time produced no "Maximum resident
    # set size" line (e.g. the process was killed): an empty field collapses under
    # word-splitting at the call site and shifts $4 (a_sc) out of range -> unbound.
    local rss_kb; rss_kb="$(max_rss_kb_from_time "$st")"; rss_kb="${rss_kb:-0}"
    printf '%s %s %s %s' "$((after - before))" "$(elapsed_s "$start" "$finish")" \
        "$rss_kb" "$((ss + rs))"
}

resync_rsync() {
    local src="$1" case_dir="$2" is_dir="$3"
    local st="$case_dir/rsync.time" sl="$case_dir/rsync.log"
    local s_stop="$case_dir/rs_s_stop" s_out="$case_dir/rs_s_rss"
    local delete_args=()
    [ "$is_dir" = "1" ] && delete_args+=(--delete)
    set +e
    sample_peak_rss "rsync " "$s_stop" "$s_out" & local samp=$!
    local before after start finish status
    before="$(ns_wire_bytes)"; start="$(now_s)"
    # MEASURED re-sync: rsync MUST use its delta algorithm for a fair/tough baseline.
    # (-W=--whole-file would disable delta and send the whole file -> false atp "win".)
    # --no-whole-file enables the rolling+strong-checksum delta; --checksum forces
    # content-based change detection (robust vs in-place same-size edits). Matches the
    # canonical loopback baseline (ledger E-RESYNC-3/4). BUG-A fix (SapphireHill).
    ip netns exec "$NS" timeout "$TIMEOUT_S" /usr/bin/time -v rsync -a --no-whole-file --checksum --inplace --no-compress "${delete_args[@]}" \
        "$src" "rsync://${HOST_IP}:1873/bench/" >"$sl" 2>"$st"
    status=$?
    finish="$(now_s)"; after="$(ns_wire_bytes)"
    touch "$s_stop"; wait "$samp" 2>/dev/null
    set -e
    printf '%s %s %s %s' "$((after - before))" "$(elapsed_s "$start" "$finish")" \
        "$(max_rss_kb_from_time "$st")" "$status"
}

emit_row() {
    # workload size_bytes regime change method wire wall rss src_sha dst_sha status_code delta_mode delta_acceptance
    ROW_RUN="$RUN_ID" ROW_GIT="$GIT_HEAD" ROW_WL="$1" ROW_SIZE="$2" ROW_REGIME="$3" \
    ROW_CHANGE="$4" ROW_METHOD="$5" ROW_WIRE="$6" ROW_WALL="$7" ROW_RSS="$8" \
    ROW_SRC="$9" ROW_DST="${10}" ROW_SC="${11}" ROW_DELTA_MODE="${12}" \
    ROW_DELTA_ACCEPTANCE="${13}" \
    python3 - >>"$RESULTS" <<'PY'
import json, os
e = os.environ.get
def num(n, d=0):
    try:
        f = float(e(n) or "")
        return int(f) if f.is_integer() else f
    except ValueError:
        return d
sha_ok = e("ROW_SRC", "") == e("ROW_DST", "x") and e("ROW_SRC", "") not in ("", "missing")
status = "ok" if (sha_ok and e("ROW_SC", "1") == "0") else ("error" if e("ROW_SC","1") != "0" else "sha_mismatch")
acceptance_raw = e("ROW_DELTA_ACCEPTANCE", "not_applicable")
delta_acceptance = {"true": True, "false": False}.get(acceptance_raw)
is_atp = e("ROW_METHOD", "").startswith("atp-")
delta_mode = e("ROW_DELTA_MODE", "")
if is_atp and delta_mode == "full_object_ineligible":
    auth_posture = "rq-symbol-hmac-only-delta-ineligible"
elif is_atp:
    auth_posture = "rq-framed-control-hmac-sha256-v1"
else:
    auth_posture = "none"
row = {
    "schema": "atp-bench-resync-result-v1", "run_id": e("ROW_RUN","adhoc"), "git_head": e("ROW_GIT","?"),
    "phase": "resync", "workload": e("ROW_WL",""), "size_bytes": num("ROW_SIZE"),
    "regime": e("ROW_REGIME",""), "crypto_tier": "auth" if is_atp else "nocrypto",
    "change_mode": e("ROW_CHANGE",""),
    "method": e("ROW_METHOD",""), "rep": 1, "bytes_on_wire": num("ROW_WIRE"),
    "wall_s": num("ROW_WALL"), "peak_rss_kb": num("ROW_RSS"), "avg_rss_kb": num("ROW_RSS"),
    "source_sha": e("ROW_SRC",""), "dest_sha": e("ROW_DST",""),
    "sha_ok": sha_ok, "status_code": num("ROW_SC", 1), "status": status,
    "delta_mode_observed": delta_mode,
    "delta_control_auth_posture": auth_posture,
    "delta_acceptance_ok": delta_acceptance,
    "performance_claim": False,
}
print(json.dumps(row, sort_keys=True, separators=(",", ":")))
PY
}

# ── per-cell flow: initial sync -> mutate -> measured re-sync -> verify ──────
run_file_cell() {
    local label="$1" bytes="$2" regime="$3" change="$4" port="$5"
    local case_dir="$RUN_DIR/file_${label}/${regime}/${change}"; mkdir -p "$case_dir"
    apply_regime "$regime"
    local base="$case_dir/base.bin"; gen_file "$base" "$bytes"

    # ── atp: initial full sync (seed receiver prior state), then mutate+resync ─
    local atp_dest="$case_dir/atp_dest"; mkdir -p "$atp_dest"
    local atp_src="$case_dir/atp_src.bin"; cp "$base" "$atp_src"
    log "[$label/$regime/$change] atp initial sync"
    seed_atp_rq "$atp_src" "$atp_dest" "$port" "$case_dir" "file" || return 1
    local atp_payload
    atp_payload="$atp_dest/$(basename "$atp_src")"
    [ "$(sha256_file "$atp_src")" = "$(sha256_file "$atp_payload")" ] \
        || { log "[$label/$regime/$change] ATP seed SHA mismatch"; return 1; }
    mutate_file "$atp_src" "$change"
    local before_stamp="not_applicable"
    [ "$change" != "0pct" ] || before_stamp="$(payload_identity_stamp "$atp_payload")"
    # Seed and measured control listeners use distinct ports; no sidecar exists.
    local fields; fields="$(resync_atp "$atp_src" "$atp_dest" "$((port+1))" "$case_dir")"
    # shellcheck disable=SC2086
    set -- $fields; local a_wire="${1:-0}" a_wall="${2:-0}" a_rss="${3:-0}" a_sc="${4:-1}"
    local a_src_sha a_dst_sha; a_src_sha="$(sha256_file "$atp_src")"; a_dst_sha="$(sha256_file "$atp_payload")"
    local delta_mode="unverified" delta_acceptance="not_applicable"
    if [ "$change" = "0pct" ]; then
        local after_stamp verify_status
        after_stamp="$(payload_identity_stamp "$atp_payload")"
        set +e
        verify_rq_authenticated_noop "$case_dir/atp_send.log" "$case_dir/atp_recv.log" \
            "$(stat -c%s "$atp_src")" "$a_wire" "$before_stamp" "$after_stamp"
        verify_status=$?
        set -e
        if [ "$verify_status" = "0" ] && [ "$a_sc" = "0" ]; then
            delta_mode="already_in_sync"
            delta_acceptance="true"
        else
            delta_mode="unverified"
            delta_acceptance="false"
            a_sc=$((a_sc + verify_status + 1))
        fi
    elif [ "$a_sc" = "0" ]; then
        delta_mode="full_object_fallback"
    fi
    emit_row "file_${label}" "$bytes" "$regime" "$change" "atp-rq-authenticated-transfer" \
        "$a_wire" "$a_wall" "$a_rss" "$a_src_sha" "$a_dst_sha" "$a_sc" \
        "$delta_mode" "$delta_acceptance"

    # ── rsync: initial sync into the daemon root, then mutate+resync ──────────
    local rroot="$case_dir/rsync_root"; mkdir -p "$rroot"
    local rsrc="$case_dir/rsync_src.bin"; cp "$base" "$rsrc"
    start_rsyncd "$rroot" "$case_dir/rsyncd.conf"
    ip netns exec "$NS" timeout "$TIMEOUT_S" rsync -aW --inplace --no-compress "$rsrc" \
        "rsync://${HOST_IP}:1873/bench/" >"$case_dir/rsync_init.log" 2>&1
    mutate_file "$rsrc" "$change"
    fields="$(resync_rsync "$rsrc" "$case_dir" 0)"
    # shellcheck disable=SC2086
    set -- $fields; local r_wire="${1:-0}" r_wall="${2:-0}" r_rss="${3:-0}" r_sc="${4:-1}"
    stop_rsyncd
    local r_src_sha r_dst_sha; r_src_sha="$(sha256_file "$rsrc")"; r_dst_sha="$(sha256_file "$rroot/$(basename "$rsrc")")"
    emit_row "file_${label}" "$bytes" "$regime" "$change" "rsyncd-delta" \
        "$r_wire" "$r_wall" "$r_rss" "$r_src_sha" "$r_dst_sha" "$r_sc" \
        "rsync_delta" "not_applicable"

    log "[$label/$regime/$change] atp wire=${a_wire}B rsync wire=${r_wire}B (diagnostic only)"
    if [ "$a_sc" != "0" ] || [ "$r_sc" != "0" ] \
        || [ "$a_src_sha" != "$a_dst_sha" ] || [ "$r_src_sha" != "$r_dst_sha" ]; then
        return 1
    fi
    if [ "$change" = "0pct" ] && [ "$delta_acceptance" != "true" ]; then
        return 1
    fi
}

run_tree_rename_cell() {
    local preset="$1" regime="$2" port="$3"
    local change="rename"
    local case_dir="$RUN_DIR/${preset}/${regime}/${change}"; mkdir -p "$case_dir"
    apply_regime "$regime"
    local base="$case_dir/base_tree" manifest="$case_dir/base_tree.manifest.jsonl"
    python3 "$GEN_TREE" --root "$base" --kind "$preset" --manifest "$manifest" >"$case_dir/gen_tree.log"
    local bytes; bytes="$(tree_size_bytes "$manifest")"

    # ── atp: initial full sync (seed receiver prior state), then tree rename ──
    local atp_dest="$case_dir/atp_dest"; mkdir -p "$atp_dest"
    local atp_src="$case_dir/atp_tree_src"; cp -a "$base" "$atp_src"
    log "[$preset/$regime/$change] atp initial sync"
    seed_atp_rq "$atp_src" "$atp_dest" "$port" "$case_dir" "tree" || return 1
    [ "$(tree_digest "$atp_src")" = "$(tree_digest "$atp_dest/$(basename "$atp_src")")" ] \
        || { log "[$preset/$regime/$change] ATP seed tree digest mismatch"; return 1; }
    mutate_tree_rename "$atp_src"
    local fields; fields="$(resync_atp "$atp_src" "$atp_dest" "$((port+1))" "$case_dir")"
    # shellcheck disable=SC2086
    set -- $fields; local a_wire="${1:-0}" a_wall="${2:-0}" a_rss="${3:-0}" a_sc="${4:-1}"
    local a_src_sha a_dst_sha; a_src_sha="$(tree_digest "$atp_src")"; a_dst_sha="$(tree_digest "$atp_dest/$(basename "$atp_src")")"
    local tree_delta_mode="unverified"
    [ "$a_sc" != "0" ] || tree_delta_mode="full_object_ineligible"
    emit_row "$preset" "$bytes" "$regime" "$change" "atp-rq-authenticated-transfer" \
        "$a_wire" "$a_wall" "$a_rss" "$a_src_sha" "$a_dst_sha" "$a_sc" \
        "$tree_delta_mode" "not_applicable"

    # ── rsync: initial sync into the daemon root, then rename+resync ──────────
    local rroot="$case_dir/rsync_root"; mkdir -p "$rroot"
    local rsrc="$case_dir/rsync_tree_src"; cp -a "$base" "$rsrc"
    start_rsyncd "$rroot" "$case_dir/rsyncd.conf"
    ip netns exec "$NS" timeout "$TIMEOUT_S" rsync -aW --inplace --no-compress "$rsrc" \
        "rsync://${HOST_IP}:1873/bench/" >"$case_dir/rsync_init.log" 2>&1
    mutate_tree_rename "$rsrc"
    fields="$(resync_rsync "$rsrc" "$case_dir" 1)"
    # shellcheck disable=SC2086
    set -- $fields; local r_wire="${1:-0}" r_wall="${2:-0}" r_rss="${3:-0}" r_sc="${4:-1}"
    stop_rsyncd
    local r_src_sha r_dst_sha; r_src_sha="$(tree_digest "$rsrc")"; r_dst_sha="$(tree_digest "$rroot/$(basename "$rsrc")")"
    emit_row "$preset" "$bytes" "$regime" "$change" "rsyncd-delta" \
        "$r_wire" "$r_wall" "$r_rss" "$r_src_sha" "$r_dst_sha" "$r_sc" \
        "rsync_delta" "not_applicable"

    log "[$preset/$regime/$change] atp wire=${a_wire}B rsync wire=${r_wire}B (diagnostic only)"
    if [ "$a_sc" != "0" ] || [ "$r_sc" != "0" ] \
        || [ "$a_src_sha" != "$a_dst_sha" ] || [ "$r_src_sha" != "$r_dst_sha" ]; then
        return 1
    fi
}

main() {
    log "resync_bench start -> $RESULTS (git $GIT_HEAD)"
    log "timeouts: process=${TIMEOUT_S}s atp-recv-listen=${ATP_RECV_LISTEN_TIMEOUT_MS}ms"
    log "scope: authenticated RQ framed-control functional evidence; no performance claim"
    ensure_rq_auth_secret
    setup_netns
    local port_off=0 planned_rows=0 initial_rows=0
    CELL_FAILURES=0
    if [ -f "$RESULTS" ]; then
        initial_rows="$(wc -l <"$RESULTS")"
    fi
    for spec in $SIZES; do
        local label="${spec%%:*}" bytes="${spec##*:}"
        for regime in $REGIMES; do
            for change in $CHANGES; do
                [ "$change" = "rename" ] && continue  # rename is a tree case (see TREE note)
                local port=$((PORT_BASE + port_off)); port_off=$((port_off + 4))
                planned_rows=$((planned_rows + 2))
                run_cell_strict "${label}/${regime}/${change}" \
                    run_file_cell "$label" "$bytes" "$regime" "$change" "$port"
            done
        done
    done
    if change_requested rename; then
        for regime in $REGIMES; do
            local port=$((PORT_BASE + port_off)); port_off=$((port_off + 4))
            planned_rows=$((planned_rows + 2))
            run_cell_strict "${TREE_PRESET}/${regime}/rename" \
                run_tree_rename_cell "$TREE_PRESET" "$regime" "$port"
        done
    fi
    local final_rows emitted_rows
    final_rows="$(wc -l <"$RESULTS")"
    emitted_rows=$((final_rows - initial_rows))
    if [ "$CELL_FAILURES" != "0" ] || [ "$emitted_rows" != "$planned_rows" ]; then
        die "fail-closed cell gate failed: cell_failures=${CELL_FAILURES} emitted_rows=${emitted_rows} planned_rows=${planned_rows}"
    fi
    log "resync_bench complete. ATP wire bytes are diagnostic functional evidence only."
    log "Rename tree re-sync rows use TREE_PRESET=${TREE_PRESET}."
    log "results: $RESULTS"
    # Diagnostic summary only. Authentication postures differ, so ratios are
    # deliberately not performance evidence.
    python3 - "$RESULTS" <<'PY'
import json, sys, collections
cells = collections.defaultdict(dict)
for line in open(sys.argv[1]):
    line = line.strip()
    if not line: continue
    r = json.loads(line)
    cells[(r["workload"], r["regime"], r["change_mode"])][r["method"]] = r
print("\n# re-sync functional diagnostics (no performance claim)\n")
print("| workload | regime | change | atp wire | rsync wire | atp delta mode | atp acceptance | atp sha |")
print("|---|---|---|--:|--:|---|---|---|")
for k in sorted(cells):
    a = cells[k].get("atp-rq-authenticated-transfer"); s = cells[k].get("rsyncd-delta")
    aw = a["bytes_on_wire"] if a else None
    sw = s["bytes_on_wire"] if s else None
    print("| {} | {} | {} | {} | {} | {} | {} | {} |".format(
        k[0], k[1], k[2], aw if aw is not None else "—", sw if sw is not None else "—",
        a.get("delta_mode_observed", "—") if a else "—",
        a.get("delta_acceptance_ok", "—") if a else "—",
        "ok" if (a and a["sha_ok"]) else "FAIL"))
PY
}

main "$@"
