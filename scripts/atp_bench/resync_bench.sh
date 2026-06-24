#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# resync_bench.sh — the incremental RE-SYNC benchmark (B-8.7, asupersync-0kh4jm):
# the evidence gate for the rsync-killer claim. The headline metric is
# BYTES-ON-WIRE for a re-sync after an edit — atp-delta should be ~proportional
# to the change, beating rsync's delta algorithm; for a tiny edit atp must send
# ~O(change), not O(file).
#
# Per (size x regime x change-mode):
#   1. gen a base payload; do an INITIAL full sync to seed the receiver's prior
#      state (atp into one dest, rsync into another) — UNMEASURED setup;
#   2. MUTATE the source (0% / 1% / 10% byte flips / append / insert / rename);
#   3. RE-SYNC (measured): atp-delta (default-on) and tuned rsync delta mode
#      each into their pre-seeded dest. Measure bytes-on-wire (netns veth tx+rx
#      byte counters, tool-agnostic), wall, peak RSS;
#   4. VERIFY byte-identical (tree_digest src == dst). FAIL-CLOSED: a mismatch is
#      recorded status!=ok + sha_ok=false and can never score as a win.
# Emits one JSONL row per (size, regime, change-mode, method) + a summary table
# of the atp/rsync bytes-on-wire ratio (the headline). Requires root (netns/tc).
#
#   sudo env BIN=/tmp/atp_bench/atp bash scripts/atp_bench/resync_bench.sh
#   python3 scripts/atp_bench/score_matrix.py <RUN_DIR>/resync.jsonl   # reuses the scorer
#
# atp delta is default-on; --no-delta forces a full send (the fallback baseline).
# This harness is transport-rq (nocrypto lab) vs rsyncd by default, so it
# exercises changed-chunk negotiation on the RaptorQ path that previously sent
# the full object. Set ATP_TRANSPORT=tcp to compare the streaming TCP delta path.
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
CHANGES="${CHANGES:-0pct 1pct 10pct append insert rename}"

WORKERS="${WORKERS:-4}"
ATP_TRANSPORT="${ATP_TRANSPORT:-rq}"
STREAMS="${STREAMS:-8}"
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
TIMEOUT_S="${TIMEOUT_S:-3600}"
RECEIVER_READY_SLEEP="${RECEIVER_READY_SLEEP:-0.75}"
RSS_SAMPLE_INTERVAL="${RSS_SAMPLE_INTERVAL:-0.2}"
RQ_AUTH_LAB="${RQ_AUTH_LAB:---rq-allow-unauthenticated-lab}"
TREE_PRESET="${TREE_PRESET:-tree_small}"
ATP_DELTA_STATE_DIR="${ATP_DELTA_STATE_DIR:-.asupersync-atp-delta-v1}"
ATP_DELTA_STATE_FILE="${ATP_DELTA_STATE_FILE:-state.json}"
GIT_HEAD="$(git -C "$HERE" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"

NS=""; IF_HOST=""; IF_NS=""; RSYNCD_PID=""

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }
die() { echo "resync_bench.sh: $*" >&2; exit 2; }

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

atp_delta_state_path() {
    printf '%s/%s/%s' "$1" "$ATP_DELTA_STATE_DIR" "$ATP_DELTA_STATE_FILE"
}
require_atp_delta_state() {
    local state_path; state_path="$(atp_delta_state_path "$1")"
    if [ ! -s "$state_path" ]; then
        log "ATP seed sync did not persist receiver delta state: $state_path"
        return 1
    fi
    python3 - "$state_path" <<'PY'
import json, sys
state_path = sys.argv[1]
with open(state_path, "rb") as fh:
    state = json.load(fh)
# Accept the legacy per-chunk-signature array OR the compact manifest format
# (kogbnc/d1833a063 shrank the eager 17.7KB/chunk chunk_signatures array down to a
# manifest_hex + chunk_count, ~160x smaller — the delta-negotiation bytes win).
if not (state.get("chunk_signatures") or (state.get("manifest_hex") and state.get("chunk_count"))):
    raise SystemExit(f"ATP receiver delta state has no chunk manifest/signatures: {state_path}")
PY
}
probe_atp_delta_sidecar() {
    local host="$1" port="$2" out="$3"
    ip netns exec "$NS" python3 - "$host" "$port" "$out" <<'PY'
import json, socket, sys
host, port, out = sys.argv[1], int(sys.argv[2]), sys.argv[3]
with socket.create_connection((host, port), timeout=5.0) as sock:
    sock.settimeout(5.0)
    chunks = []
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        chunks.append(chunk)
payload = b"".join(chunks).strip()
if not payload:
    raise SystemExit("ATP delta sidecar returned empty state")
state = json.loads(payload.decode("utf-8"))
if not (state.get("chunk_signatures") or (state.get("manifest_hex") and state.get("chunk_count"))):
    raise SystemExit("ATP delta sidecar state has no chunk manifest/signatures")
with open(out, "wb") as fh:
    fh.write(payload + b"\n")
PY
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
    stop_rsyncd
    [ -n "$NS" ] && ip netns del "$NS" >/dev/null 2>&1 || true
    [ -n "$IF_HOST" ] && ip link del "$IF_HOST" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ── payload + mutation ───────────────────────────────────────────────────────
gen_file() {
    local path="$1" bytes="$2" mb=$(( $2 / 1048576 )) rem=$(( $2 % 1048576 ))
    [ "$mb" -gt 0 ] && dd if=/dev/urandom of="$path" bs=1M count="$mb" status=none || : >"$path"
    [ "$rem" -gt 0 ] && dd if=/dev/urandom bs=1 count="$rem" status=none >>"$path" || :
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

# ── measured re-sync for one method ──────────────────────────────────────────
# echoes: WIRE_BYTES WALL PEAK_RSS_KB STATUS_CODE
resync_atp() {
    local src="$1" dest_dir="$2" port="$3" case_dir="$4"
    local rl="$case_dir/atp_recv.log" sl="$case_dir/atp_send.log" rt="$case_dir/atp_recv.time" st="$case_dir/atp_send.time"
    local s_tag="atprs-send-${port}" r_tag="atprs-recv-${port}"
    local s_stop="$case_dir/atp_s_stop" s_out="$case_dir/atp_s_rss"
    local recv_args=(--transport "$ATP_TRANSPORT")
    local send_args=(--transport "$ATP_TRANSPORT")
    case "$ATP_TRANSPORT" in
        tcp) ;;
        rq)
            recv_args+=(--symbol-size "$SYMBOL_SIZE")
            send_args+=(--streams "$STREAMS" --symbol-size "$SYMBOL_SIZE")
            # shellcheck disable=SC2206
            [ -n "$RQ_AUTH_LAB" ] && recv_args+=($RQ_AUTH_LAB)
            # shellcheck disable=SC2206
            [ -n "$RQ_AUTH_LAB" ] && send_args+=($RQ_AUTH_LAB)
            ;;
        *) die "unsupported ATP_TRANSPORT for resync benchmark: $ATP_TRANSPORT" ;;
    esac
    set +e
    timeout "$TIMEOUT_S" /usr/bin/time -v "$BIN" recv "$dest_dir" \
        --listen "0.0.0.0:${port}" "${recv_args[@]}" --once --peer-id "$r_tag" \
        --workers "$WORKERS" --max-bytes "$MAX_BYTES" \
        >"$rl" 2>"$rt" &
    local recv_pid=$!
    sample_peak_rss "$s_tag" "$s_stop" "$s_out" & local samp=$!
    sleep "$RECEIVER_READY_SLEEP"
    local sidecar_port=$((port + 1)) probe_status=0
    probe_atp_delta_sidecar "$HOST_IP" "$sidecar_port" "$case_dir/atp_delta_sidecar_state.json"
    probe_status=$?
    if [ "$probe_status" != "0" ]; then
        log "ATP delta sidecar ${HOST_IP}:${sidecar_port} unavailable or empty; aborting measured ATP re-sync"
        kill "$recv_pid" 2>/dev/null || true
        wait "$recv_pid" 2>/dev/null || true
        touch "$s_stop"; wait "$samp" 2>/dev/null
        set -e
        printf '0 0 0 %s' "$probe_status"
        return 0
    fi
    local before after start finish ss rs
    before="$(ns_wire_bytes)"; start="$(now_s)"
    ip netns exec "$NS" timeout "$TIMEOUT_S" /usr/bin/time -v "$BIN" send "$src" "${HOST_IP}:${port}" \
        "${send_args[@]}" --peer-id "$s_tag" --max-bytes "$MAX_BYTES" >"$sl" 2>"$st"
    ss=$?
    finish="$(now_s)"; after="$(ns_wire_bytes)"
    if [ "$ss" = "0" ] && grep -Eq "using full-object transfer|full-object fallback" "$st"; then
        log "ATP sender used graceful full-object transfer after delta planner rejected package; scoring by sha and wire bytes"
    fi
    if [ "$ss" != "0" ]; then
        # Delta-package RQ sends can fail at the sender after the receiver has
        # decoded and started post-receive application. Give the receiver a
        # bounded grace window to emit its real status before forcing cleanup.
        local grace=0
        while kill -0 "$recv_pid" 2>/dev/null && [ "$grace" -lt 40 ]; do
            sleep 0.25
            grace=$((grace + 1))
        done
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
    local src="$1" rsync_root="$2" case_dir="$3" is_dir="$4"
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
    # workload size_bytes regime change method wire wall rss src_sha dst_sha status_code
    ROW_RUN="$RUN_ID" ROW_GIT="$GIT_HEAD" ROW_WL="$1" ROW_SIZE="$2" ROW_REGIME="$3" \
    ROW_CHANGE="$4" ROW_METHOD="$5" ROW_WIRE="$6" ROW_WALL="$7" ROW_RSS="$8" \
    ROW_SRC="$9" ROW_DST="${10}" ROW_SC="${11}" \
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
row = {
    "schema": "atp-bench-resync-result-v1", "run_id": e("ROW_RUN","adhoc"), "git_head": e("ROW_GIT","?"),
    "phase": "resync", "workload": e("ROW_WL",""), "size_bytes": num("ROW_SIZE"),
    "regime": e("ROW_REGIME",""), "crypto_tier": "nocrypto", "change_mode": e("ROW_CHANGE",""),
    "method": e("ROW_METHOD",""), "rep": 1, "bytes_on_wire": num("ROW_WIRE"),
    "wall_s": num("ROW_WALL"), "peak_rss_kb": num("ROW_RSS"), "avg_rss_kb": num("ROW_RSS"),
    "source_sha": e("ROW_SRC",""), "dest_sha": e("ROW_DST",""),
    "sha_ok": sha_ok, "status_code": num("ROW_SC", 1), "status": status,
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
    set +e
    timeout "$TIMEOUT_S" "$BIN" recv "$atp_dest" --listen "0.0.0.0:${port}" --transport rq --once \
        --peer-id "init-recv-${port}" --workers "$WORKERS" --max-bytes "$MAX_BYTES" \
        --symbol-size "$SYMBOL_SIZE" $RQ_AUTH_LAB >"$case_dir/atp_init_recv.log" 2>&1 &
    local ip_pid=$!; sleep "$RECEIVER_READY_SLEEP"
    local init_send_status init_recv_status
    ip netns exec "$NS" timeout "$TIMEOUT_S" "$BIN" send "$atp_src" "${HOST_IP}:${port}" --transport rq \
        --streams "$STREAMS" --symbol-size "$SYMBOL_SIZE" --peer-id "init-send-${port}" \
        --max-bytes "$MAX_BYTES" $RQ_AUTH_LAB >"$case_dir/atp_init_send.log" 2>&1
    init_send_status=$?
    wait "$ip_pid" 2>/dev/null
    init_recv_status=$?
    set -e
    if [ "$init_send_status" != "0" ] || [ "$init_recv_status" != "0" ]; then
        log "[$label/$regime/$change] atp initial sync failed (send=$init_send_status recv=$init_recv_status)"
        return 1
    fi
    require_atp_delta_state "$atp_dest"
    mutate_file "$atp_src" "$change"
    local fields; fields="$(resync_atp "$atp_src" "$atp_dest" "$((port+1))" "$case_dir")"
    # shellcheck disable=SC2086
    set -- $fields; local a_wire="${1:-0}" a_wall="${2:-0}" a_rss="${3:-0}" a_sc="${4:-1}"
    local a_src_sha a_dst_sha; a_src_sha="$(sha256_file "$atp_src")"; a_dst_sha="$(sha256_file "$atp_dest/$(basename "$atp_src")")"
    emit_row "file_${label}" "$bytes" "$regime" "$change" "atp-rq-delta" "$a_wire" "$a_wall" "$a_rss" "$a_src_sha" "$a_dst_sha" "$a_sc"

    # ── rsync: initial sync into the daemon root, then mutate+resync ──────────
    local rroot="$case_dir/rsync_root"; mkdir -p "$rroot"
    local rsrc="$case_dir/rsync_src.bin"; cp "$base" "$rsrc"
    start_rsyncd "$rroot" "$case_dir/rsyncd.conf"
    ip netns exec "$NS" timeout "$TIMEOUT_S" rsync -aW --inplace --no-compress "$rsrc" \
        "rsync://${HOST_IP}:1873/bench/" >"$case_dir/rsync_init.log" 2>&1
    mutate_file "$rsrc" "$change"
    fields="$(resync_rsync "$rsrc" "$rroot" "$case_dir" 0)"
    # shellcheck disable=SC2086
    set -- $fields; local r_wire="${1:-0}" r_wall="${2:-0}" r_rss="${3:-0}" r_sc="${4:-1}"
    stop_rsyncd
    local r_src_sha r_dst_sha; r_src_sha="$(sha256_file "$rsrc")"; r_dst_sha="$(sha256_file "$rroot/$(basename "$rsrc")")"
    emit_row "file_${label}" "$bytes" "$regime" "$change" "rsyncd-delta" "$r_wire" "$r_wall" "$r_rss" "$r_src_sha" "$r_dst_sha" "$r_sc"

    log "[$label/$regime/$change] atp wire=${a_wire}B rsync wire=${r_wire}B (re-sync bytes-on-wire)"
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
    set +e
    timeout "$TIMEOUT_S" "$BIN" recv "$atp_dest" --listen "0.0.0.0:${port}" --transport rq --once \
        --peer-id "init-tree-recv-${port}" --workers "$WORKERS" --max-bytes "$MAX_BYTES" \
        --symbol-size "$SYMBOL_SIZE" $RQ_AUTH_LAB >"$case_dir/atp_init_recv.log" 2>&1 &
    local ip_pid=$!; sleep "$RECEIVER_READY_SLEEP"
    local init_send_status init_recv_status
    ip netns exec "$NS" timeout "$TIMEOUT_S" "$BIN" send "$atp_src" "${HOST_IP}:${port}" --transport rq \
        --streams "$STREAMS" --symbol-size "$SYMBOL_SIZE" --peer-id "init-tree-send-${port}" \
        --max-bytes "$MAX_BYTES" $RQ_AUTH_LAB >"$case_dir/atp_init_send.log" 2>&1
    init_send_status=$?
    wait "$ip_pid" 2>/dev/null
    init_recv_status=$?
    set -e
    if [ "$init_send_status" != "0" ] || [ "$init_recv_status" != "0" ]; then
        log "[$preset/$regime/$change] atp initial sync failed (send=$init_send_status recv=$init_recv_status)"
        return 1
    fi
    require_atp_delta_state "$atp_dest"
    mutate_tree_rename "$atp_src"
    local fields; fields="$(resync_atp "$atp_src" "$atp_dest" "$((port+1))" "$case_dir")"
    # shellcheck disable=SC2086
    set -- $fields; local a_wire="${1:-0}" a_wall="${2:-0}" a_rss="${3:-0}" a_sc="${4:-1}"
    local a_src_sha a_dst_sha; a_src_sha="$(tree_digest "$atp_src")"; a_dst_sha="$(tree_digest "$atp_dest/$(basename "$atp_src")")"
    emit_row "$preset" "$bytes" "$regime" "$change" "atp-rq-delta" "$a_wire" "$a_wall" "$a_rss" "$a_src_sha" "$a_dst_sha" "$a_sc"

    # ── rsync: initial sync into the daemon root, then rename+resync ──────────
    local rroot="$case_dir/rsync_root"; mkdir -p "$rroot"
    local rsrc="$case_dir/rsync_tree_src"; cp -a "$base" "$rsrc"
    start_rsyncd "$rroot" "$case_dir/rsyncd.conf"
    ip netns exec "$NS" timeout "$TIMEOUT_S" rsync -aW --inplace --no-compress "$rsrc" \
        "rsync://${HOST_IP}:1873/bench/" >"$case_dir/rsync_init.log" 2>&1
    mutate_tree_rename "$rsrc"
    fields="$(resync_rsync "$rsrc" "$rroot" "$case_dir" 1)"
    # shellcheck disable=SC2086
    set -- $fields; local r_wire="${1:-0}" r_wall="${2:-0}" r_rss="${3:-0}" r_sc="${4:-1}"
    stop_rsyncd
    local r_src_sha r_dst_sha; r_src_sha="$(tree_digest "$rsrc")"; r_dst_sha="$(tree_digest "$rroot/$(basename "$rsrc")")"
    emit_row "$preset" "$bytes" "$regime" "$change" "rsyncd-delta" "$r_wire" "$r_wall" "$r_rss" "$r_src_sha" "$r_dst_sha" "$r_sc"

    log "[$preset/$regime/$change] atp wire=${a_wire}B rsync wire=${r_wire}B (tree re-sync bytes-on-wire)"
}

main() {
    log "resync_bench start -> $RESULTS (git $GIT_HEAD)"
    setup_netns
    local port_off=0
    for spec in $SIZES; do
        local label="${spec%%:*}" bytes="${spec##*:}"
        for regime in $REGIMES; do
            for change in $CHANGES; do
                [ "$change" = "rename" ] && continue  # rename is a tree case (see TREE note)
                local port=$((PORT_BASE + port_off)); port_off=$((port_off + 4))
                # Isolate each cell: under `set -e` a lossy-regime (good/bad) timeout
                # or non-convergence inside run_file_cell would otherwise abort the
                # WHOLE matrix at the first failing cell. Catch it, stop any cell-
                # local rsyncd, and continue so every regime/size/change cell still
                # produces a comparison row (the loss regimes are exactly where atp
                # RaptorQ FEC should beat rsync TCP-delta retransmit stalls).
                run_file_cell "$label" "$bytes" "$regime" "$change" "$port" \
                    || { log "[WARN] cell ${label}/${regime}/${change} aborted (continuing matrix)"; stop_rsyncd 2>/dev/null || true; }
            done
        done
    done
    if change_requested rename; then
        for regime in $REGIMES; do
            local port=$((PORT_BASE + port_off)); port_off=$((port_off + 4))
            run_tree_rename_cell "$TREE_PRESET" "$regime" "$port" \
                || { log "[WARN] cell ${TREE_PRESET}/${regime}/rename aborted (continuing matrix)"; stop_rsyncd 2>/dev/null || true; }
        done
    fi
    log "resync_bench complete. Headline = atp-rq-delta vs rsyncd-delta bytes_on_wire per cell."
    log "Rename tree re-sync rows use TREE_PRESET=${TREE_PRESET}."
    log "results: $RESULTS"
    # Quick headline summary (atp/rsync wire-byte ratio per cell).
    python3 - "$RESULTS" <<'PY'
import json, sys, collections
cells = collections.defaultdict(dict)
for line in open(sys.argv[1]):
    line = line.strip()
    if not line: continue
    r = json.loads(line)
    cells[(r["workload"], r["regime"], r["change_mode"])][r["method"]] = r
print("\n# re-sync bytes-on-wire (atp-rq-delta vs rsyncd-delta)\n")
print("| workload | regime | change | atp wire | rsync wire | ratio atp/rsync | atp sha |")
print("|---|---|---|--:|--:|--:|---|")
for k in sorted(cells):
    a = cells[k].get("atp-rq-delta"); s = cells[k].get("rsyncd-delta")
    aw = a["bytes_on_wire"] if a else None
    sw = s["bytes_on_wire"] if s else None
    ratio = (aw / sw) if (aw is not None and sw) else None
    print("| {} | {} | {} | {} | {} | {} | {} |".format(
        k[0], k[1], k[2], aw if aw is not None else "—", sw if sw is not None else "—",
        ("%.2f" % ratio) if ratio is not None else "—",
        "ok" if (a and a["sha_ok"]) else "FAIL"))
PY
}

main "$@"
