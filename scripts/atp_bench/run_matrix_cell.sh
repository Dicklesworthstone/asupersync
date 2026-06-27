#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# run_matrix_cell.sh — the per-cell runner for matrix_bench.sh (cc_1 lane).
#
# matrix_bench.sh is a planner/resume layer: for every (workload, regime, tier,
# method, rep) it sets up the cell environment and shells out to a per-cell
# command (--run-cell-command). This is that command. It does the actual
# "run + measure + verify" the spec calls for, hermetically per cell:
#
#   1. stand up a fresh netns + veth pair, apply the regime's netem (rate-capped,
#      symmetric on BOTH ends) from $ATP_MATRIX_NETEM_JSON;
#   2. run ONE transfer for the cell's method (atp-rq lab/auth, atp-quic, rsyncd,
#      rsync-over-ssh) — receiver on the host, sender in the netns so traffic
#      crosses the shaped link;
#   3. measure wall, peak RSS (/usr/bin/time -v, both ends) + avg RSS (200 ms
#      /proc VmRSS sampler, both ends), CPU%, feedback_rounds;
#   4. SHA-256 verify every transfer (file: digest; tree: sorted per-file set vs
#      the gen_tree manifest) — FAIL-CLOSED: a mismatch/timeout/error is recorded
#      with status!="ok" + sha_ok=false so it can never be scored as a win;
#   5. append one JSONL row to $ATP_MATRIX_RESULTS using the field names the
#      scorer (score_matrix.py) reads: workload, regime, crypto_tier, method,
#      rep, wall_s, peak_rss_kb, avg_rss_kb, sha_ok, status (+ extras).
#
# Requires root (netns/tc). Wire it in via:
#   sudo env BIN=/tmp/atp_bench/atp bash scripts/atp_bench/matrix_bench.sh \
#     --execute --generate-workloads \
#     --run-cell-command 'bash scripts/atp_bench/run_matrix_cell.sh'
#
# Inputs (exported by matrix_bench.sh's run_cell):
#   ATP_MATRIX_WORKLOAD ATP_MATRIX_WORKLOAD_PATH ATP_MATRIX_REGIME
#   ATP_MATRIX_TIER ATP_MATRIX_METHOD ATP_MATRIX_REP ATP_MATRIX_STREAMS ATP_MATRIX_RESULTS
#   ATP_MATRIX_NETEM_JSON ATP_MATRIX_RUN_ID ATP_MATRIX_GIT_HEAD
# Tunables (env): BIN, WORKERS, STREAMS, SYMBOL_SIZE, MAX_BLOCK_SIZE, MAX_BYTES,
#   RQ_AUTH_KEY_HEX, HOST_IP, NS_IP, CIDR, ATP_MATRIX_TIMEOUT,
#   RSS_SAMPLE_INTERVAL, REMOTE_USER, SSH_KEY, RECEIVER_READY_SLEEP, CELL_TMP.
# ─────────────────────────────────────────────────────────────────────────────

: "${ATP_MATRIX_WORKLOAD:?run via matrix_bench.sh --run-cell-command}"
: "${ATP_MATRIX_WORKLOAD_PATH:?missing ATP_MATRIX_WORKLOAD_PATH}"
: "${ATP_MATRIX_REGIME:?missing ATP_MATRIX_REGIME}"
: "${ATP_MATRIX_TIER:?missing ATP_MATRIX_TIER}"
: "${ATP_MATRIX_METHOD:?missing ATP_MATRIX_METHOD}"
: "${ATP_MATRIX_REP:?missing ATP_MATRIX_REP}"
: "${ATP_MATRIX_RESULTS:?missing ATP_MATRIX_RESULTS}"
: "${ATP_MATRIX_NETEM_JSON:?missing ATP_MATRIX_NETEM_JSON}"

WORKLOAD="$ATP_MATRIX_WORKLOAD"
WL_PATH="$ATP_MATRIX_WORKLOAD_PATH"
REGIME="$ATP_MATRIX_REGIME"
TIER="$ATP_MATRIX_TIER"
METHOD="$ATP_MATRIX_METHOD"
REP="$ATP_MATRIX_REP"
RESULTS="$ATP_MATRIX_RESULTS"
NETEM_JSON="$ATP_MATRIX_NETEM_JSON"
RUN_ID="${ATP_MATRIX_RUN_ID:-adhoc}"
GIT_HEAD="${ATP_MATRIX_GIT_HEAD:-unknown}"

BIN="${BIN:-/tmp/atp_bench/atp}"
WORKERS="${WORKERS:-4}"
STREAMS="${STREAMS:-1}"
STREAMS="${ATP_MATRIX_STREAMS:-$STREAMS}"
SYMBOL_SIZE="${SYMBOL_SIZE:-1200}"
MAX_BLOCK_SIZE="${ATP_MATRIX_MAX_BLOCK_SIZE:-${MAX_BLOCK_SIZE:-auto}}"
MAX_BYTES="${MAX_BYTES:-6442450944}"
RQ_AUTH_KEY_HEX="${RQ_AUTH_KEY_HEX:-00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff}"
HOST_IP="${HOST_IP:-10.99.0.1}"
NS_IP="${NS_IP:-10.99.0.2}"
CIDR="${CIDR:-24}"
RSS_SAMPLE_INTERVAL="${RSS_SAMPLE_INTERVAL:-0.2}"
RECEIVER_READY_SLEEP="${RECEIVER_READY_SLEEP:-0.75}"
REMOTE_USER="${REMOTE_USER:-root}"
SSH_KEY="${SSH_KEY:-/root/.ssh/atp_matrix_bench}"
CELL_TMP="${CELL_TMP:-$(dirname "$RESULTS")/cells}"

# Generous, size-aware timeout (the transfer only; gen/teardown are untimed).
if [ -n "${ATP_MATRIX_TIMEOUT:-}" ]; then
    TIMEOUT_S="$ATP_MATRIX_TIMEOUT"
elif [ "$WORKLOAD" = "5G" ]; then
    TIMEOUT_S=7200
else
    TIMEOUT_S=1800
fi

log() { printf '%s [cell %s/%s/%s/%s rep=%s] %s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$WORKLOAD" "$REGIME" "$TIER" "$METHOD" "$REP" "$*" >&2; }

[ "$(id -u)" = "0" ] || { echo "run_matrix_cell.sh needs root (netns/tc)" >&2; exit 1; }
[ -x "$BIN" ] || { echo "BIN not executable: $BIN" >&2; exit 1; }

SUFFIX="$(printf '%s-%s-%s' "$RUN_ID" "$METHOD" "$REP" | cksum | awk '{ print substr($1,1,6) }')"
NS="atpc${SUFFIX}"
IF_HOST="vch${SUFFIX}"
IF_NS="vcn${SUFFIX}"
PORT=$(( 40000 + ($(printf '%s' "$SUFFIX" | cksum | awk '{print $1}') % 20000) ))
CASE_DIR="${CELL_TMP}/${WORKLOAD}/${REGIME}/${TIER}/${METHOD}/rep${REP}"
RSYNCD_PID=""

cleanup() {
    [ -n "$RSYNCD_PID" ] && kill "$RSYNCD_PID" 2>/dev/null || true
    ip netns del "$NS" >/dev/null 2>&1 || true
    ip link del "$IF_HOST" >/dev/null 2>&1 || true
}
trap cleanup EXIT

mkdir -p "$CASE_DIR"

# ── helpers ──────────────────────────────────────────────────────────────────
now_s() { date +%s.%N; }
elapsed_s() { awk -v a="$1" -v b="$2" 'BEGIN { printf "%.6f", b - a }'; }
max_rss_kb_from_time() {
    [ -f "$1" ] || { printf ''; return; }
    awk -F: '/Maximum resident set size/ { gsub(/^[ \t]+/, "", $2); print $2 }' "$1" | tail -n 1
}
cpu_pct_from_time() {
    [ -f "$1" ] || { printf ''; return; }
    awk -F: '/Percent of CPU this job got/ { gsub(/[^0-9]/, "", $2); print $2 }' "$1" | tail -n 1
}
# Sum of voluntary + involuntary context switches from a /usr/bin/time -v file.
# Cheap proxy for syscall/scheduler pressure: the per-symbol sendto spray on a
# clean fast link shows up here, so Phase-2 can quantify why atp's per-packet
# overhead loses on the "perfect" cell (vs rsync's few large TCP writes).
# Both "Voluntary..." and "Involuntary..." lines contain "voluntary context
# switches", so the case-insensitive match sums both.
ctx_switches_from_time() {
    [ -f "$1" ] || { printf ''; return; }
    awk -F: 'tolower($0) ~ /voluntary context switches/ { gsub(/[^0-9]/, "", $2); s += $2 } END { print s + 0 }' "$1"
}
extract_metric() {
    local key="$1"; shift
    grep -h -E "\"?${key}\"?[[:space:]]*[:=]" "$@" 2>/dev/null | tail -n 1 \
        | sed -E "s/.*\"?${key}\"?[[:space:]]*[:=][[:space:]]*([0-9]+).*/\\1/" \
        | grep -E '^[0-9]+$' || true
}
sha256_file() { if [ -f "$1" ]; then sha256sum "$1" | awk '{print $1}'; else printf 'missing'; fi; }

# Canonical tree digest: sha256 over sorted "relpath:perfilesha" set.
tree_digest() {
    local root="$1"
    [ -d "$root" ] || { printf 'missing'; return; }
    ( cd "$root" && find . -type f ! -name 'SHA256SUMS' ! -name '*.manifest.jsonl' -print0 \
        | sort -z \
        | while IFS= read -r -d '' f; do
            printf '%s:%s\n' "${f#./}" "$(sha256sum "$f" | awk '{print $1}')"
          done ) | sha256sum | awk '{print $1}'
}

# Source tree digest from gen_tree manifest (path + sha256 per line), same shape.
manifest_tree_digest() {
    local manifest="$1"
    [ -f "$manifest" ] || { printf 'missing'; return; }
    python3 - "$manifest" <<'PY'
import hashlib, json, sys
rows = []
with open(sys.argv[1], encoding="utf-8") as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        if "path" in r and r.get("sha256"):
            rows.append(f"{r['path']}:{r['sha256']}")
rows.sort()
print(hashlib.sha256("\n".join(rows).encode()).hexdigest())
PY
}

netem_loss_pct() {
    python3 - "$NETEM_JSON" <<'PY'
import json, math, sys
try:
    value = float((json.loads(sys.argv[1]) or {}).get("loss_pct", 0) or 0)
except Exception:
    value = 0.0
if not math.isfinite(value) or value < 0:
    value = 0.0
print(value)
PY
}

# peak avg (kB) over a cmdline pattern, sampled every RSS_SAMPLE_INTERVAL.
sample_rss() {
    local pattern="$1" stop_file="$2" out_file="$3"
    local peak=0 sum=0 count=0
    while [ ! -e "$stop_file" ]; do
        local total=0 pid rss pids
        pids="$(pgrep -f "$pattern" 2>/dev/null || true)"
        for pid in $pids; do
            rss="$(awk '/^VmRSS:/ { print $2 }' "/proc/$pid/status" 2>/dev/null || true)"
            [ -n "$rss" ] && total=$((total + rss))
        done
        if [ "$total" -gt 0 ]; then
            [ "$total" -gt "$peak" ] && peak="$total"
            sum=$((sum + total)); count=$((count + 1))
        fi
        sleep "$RSS_SAMPLE_INTERVAL"
    done
    local avg=0; [ "$count" -gt 0 ] && avg=$((sum / count))
    printf '%s %s\n' "$peak" "$avg" >"$out_file"
}

# max of two possibly-empty integers
imax() { local a="${1:-0}" b="${2:-0}"; [ -z "$a" ] && a=0; [ -z "$b" ] && b=0; if [ "$a" -ge "$b" ]; then printf '%s' "$a"; else printf '%s' "$b"; fi; }

netem_args() {  # turn ATP_MATRIX_NETEM_JSON into a tc netem argument string
    python3 - "$NETEM_JSON" <<'PY'
import json, sys
c = json.loads(sys.argv[1])
parts = ["delay", f"{c.get('delay_ms',0)}ms"]
jit = c.get("jitter_ms", 0) or 0
if jit:
    parts.append(f"{jit}ms")
loss = c.get("loss_pct", 0) or 0
if loss:
    parts += ["loss", f"{loss}%"]
reorder = c.get("reorder_pct", 0) or 0
if reorder:
    parts += ["reorder", f"{reorder}%", "50%"]
dup = c.get("duplicate_pct", c.get("dup_pct", 0)) or 0
if dup:
    parts += ["duplicate", f"{dup}%"]
rate = c.get("rate")
if rate:
    parts += ["rate", rate]
# Optional explicit queue limit (packets). High-BDP links (e.g. 1gbit @ 200ms,
# BDP ~33k pkts) need a limit well above the netem default of 1000, or the queue
# tail-drops and silently throttles BOTH transports far below line rate. Only
# regimes that set "limit" get one; others keep the default for stable baselines.
limit = c.get("limit", 0) or 0
if limit:
    parts += ["limit", str(int(limit))]
print(" ".join(parts))
PY
}

setup_link() {
    ip netns add "$NS"
    ip link add "$IF_HOST" type veth peer name "$IF_NS"
    ip link set "$IF_NS" netns "$NS"
    ip addr add "${HOST_IP}/${CIDR}" dev "$IF_HOST"
    ip link set "$IF_HOST" up
    ip netns exec "$NS" ip addr add "${NS_IP}/${CIDR}" dev "$IF_NS"
    ip netns exec "$NS" ip link set lo up
    ip netns exec "$NS" ip link set "$IF_NS" up
    local netem; netem="$(netem_args)"
    # shellcheck disable=SC2086
    tc qdisc replace dev "$IF_HOST" root netem $netem
    # shellcheck disable=SC2086
    ip netns exec "$NS" tc qdisc replace dev "$IF_NS" root netem $netem
    log "link up (netem both ends): $netem  port=$PORT"
}

ensure_ssh_key() {
    mkdir -p "$(dirname "$SSH_KEY")"
    [ -f "$SSH_KEY" ] || ssh-keygen -q -t ed25519 -N '' -f "$SSH_KEY"
    chmod 700 "$(dirname "$SSH_KEY")"; chmod 600 "$SSH_KEY"
    local home; home="$(getent passwd "$REMOTE_USER" | awk -F: '{print $6}')"
    [ -n "$home" ] || { echo "no home for $REMOTE_USER" >&2; exit 1; }
    mkdir -p "${home}/.ssh"; chmod 700 "${home}/.ssh"
    touch "${home}/.ssh/authorized_keys"; chmod 600 "${home}/.ssh/authorized_keys"
    grep -qxF "$(cat "${SSH_KEY}.pub")" "${home}/.ssh/authorized_keys" \
        || cat "${SSH_KEY}.pub" >>"${home}/.ssh/authorized_keys"
}
ssh_opts() { printf '%s' "-i ${SSH_KEY} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -c aes128-gcm@openssh.com"; }

# ── transfer kinds ───────────────────────────────────────────────────────────
# Each populates: WALL S_PEAK R_PEAK S_AVG R_AVG CPU ROUNDS STATUS_CODE TIMED_OUT
run_atp() {  # $1=auth-mode: lab|key   $2=transport: rq|quic
    local mode="$1" transport="$2"
    local recv_dir="$CASE_DIR/recv"; mkdir -p "$recv_dir"
    local rl="$CASE_DIR/recv.log" sl="$CASE_DIR/send.log" rt="$CASE_DIR/recv.time" st="$CASE_DIR/send.time"
    local r_tag="atprecv-${SUFFIX}" s_tag="atpsend-${SUFFIX}"
    local r_stop="$CASE_DIR/r_stop" r_out="$CASE_DIR/r_rss" s_stop="$CASE_DIR/s_stop" s_out="$CASE_DIR/s_rss"
    local -a auth_recv=() auth_send=() block_args=() delta_args=() tls_recv=() tls_send=() rq_loss_args=()
    local sym="$SYMBOL_SIZE"
    # "auto" means let atp pick its built-in (auto-bound) block size — the CLI
    # flag parses strictly as a number, so omit it rather than passing "auto"
    # (passing the literal "auto" makes atp reject the arg and instant-fail).
    if [ "$MAX_BLOCK_SIZE" != "auto" ]; then
        block_args=(--max-block-size "$MAX_BLOCK_SIZE")
    fi
    # Matrix cells are whole-object scorecard transfers, not re-sync delta cells.
    # Disable the receiver-state sidecar probe so netns route issues cannot add
    # fallback noise to wall-time or obscure the transport under test.
    delta_args=(--no-delta)
    if [ "$mode" = "lab" ]; then
        auth_recv=(--rq-allow-unauthenticated-lab); auth_send=(--rq-allow-unauthenticated-lab)
    else
        auth_recv=(--rq-auth-key-hex "$RQ_AUTH_KEY_HEX"); auth_send=(--rq-auth-key-hex "$RQ_AUTH_KEY_HEX")
    fi
    if [ "$transport" = "quic" ]; then
        local cert="$CASE_DIR/cert.pem" key="$CASE_DIR/key.pem"
        # Keep the encrypted matrix on the same P-256 leaf shape used by the
        # checked QUIC/TLS fixtures. Fall back to RSA-2048 only where the EC
        # OpenSSL path is unavailable.
        # rustls-webpki's server-cert verifier requires the leaf to carry
        # extendedKeyUsage=serverAuth (a bare -x509 cert omits it → the client
        # rejects the server cert and the QUIC/TLS handshake dies with a fatal
        # alert). Add EKU serverAuth + keyUsage so the self-signed leaf validates.
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
            -keyout "$key" -out "$cert" -days 3 \
            -subj "/CN=${HOST_IP}" -addext "subjectAltName=IP:${HOST_IP}" \
            -addext "keyUsage=critical,digitalSignature" \
            -addext "extendedKeyUsage=serverAuth" >/dev/null 2>&1 || \
        openssl req -x509 -newkey rsa:2048 -nodes -keyout "$key" -out "$cert" -days 3 \
            -subj "/CN=${HOST_IP}" -addext "subjectAltName=IP:${HOST_IP}" \
            -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
            -addext "extendedKeyUsage=serverAuth" >/dev/null 2>&1
        tls_recv=(--server-cert "$cert" --server-key "$key"); tls_send=(--ca "$cert" --server-name "$HOST_IP")
        # QUIC carries each RaptorQ symbol in one DATAGRAM whose max_datagram_size
        # is 1200; the 56-byte authenticated envelope header must also fit, so the
        # symbol payload is capped at 1200-56=1144 (the rq tier keeps the full
        # SYMBOL_SIZE). atp rejects the transfer fail-closed otherwise. This is an
        # atp-internal framing detail and does not affect the rsync-ssh comparison,
        # so the encrypted tier stays apples-to-apples. (z0v7ri encrypted-tier fix.)
        if [ "$sym" -gt 1141 ]; then sym=1141; fi
        # quic adds TLS identity ON TOP of the per-symbol auth posture; keep the
        # key/lab flags so the encrypted tier stays crypto-symmetric vs rsync-ssh
        # and the receiver does not fail closed for missing symbol auth.
    fi

    local extra_send=()
    if [ "$transport" = "rq" ]; then
        extra_send=(--streams "$STREAMS")
        rq_loss_args=(--rq-round0-loss-pct "$(netem_loss_pct)")
    fi
    # Optional sender bandwidth cap (bytes/sec). Set ATP_SEND_BWLIMIT to pace the
    # sender at/below the link rate — diagnostic for round-0 overrun on rate-capped
    # links (MATRIX-123). Applies to all transports (quic/auto honor --bwlimit).
    if [ -n "${ATP_SEND_BWLIMIT:-}" ]; then
        extra_send+=(--bwlimit "$ATP_SEND_BWLIMIT")
    fi

    set +e
    timeout "$TIMEOUT_S" /usr/bin/time -v "$BIN" recv "$recv_dir" \
        --listen "0.0.0.0:${PORT}" --transport "$transport" --once --peer-id "$r_tag" \
        --workers "$WORKERS" --max-bytes "$MAX_BYTES" --symbol-size "$sym" \
        "${block_args[@]}" "${delta_args[@]}" "${rq_loss_args[@]}" "${auth_recv[@]}" "${tls_recv[@]}" >"$rl" 2>"$rt" &
    local recv_pid=$!
    sample_rss "$r_tag" "$r_stop" "$r_out" & local r_samp=$!
    sleep "$RECEIVER_READY_SLEEP"
    sample_rss "$s_tag" "$s_stop" "$s_out" & local s_samp=$!
    local start finish ss rs; TIMED_OUT=false
    start="$(now_s)"
    ip netns exec "$NS" timeout "$TIMEOUT_S" /usr/bin/time -v "$BIN" send "$WL_PATH" "${HOST_IP}:${PORT}" \
        --transport "$transport" --symbol-size "$sym" --peer-id "$s_tag" --max-bytes "$MAX_BYTES" \
        "${block_args[@]}" "${delta_args[@]}" "${rq_loss_args[@]}" "${extra_send[@]}" "${auth_send[@]}" "${tls_send[@]}" >"$sl" 2>"$st"
    ss=$?; [ "$ss" = "124" ] && TIMED_OUT=true
    if [ "$ss" != "0" ] && kill -0 "$recv_pid" 2>/dev/null; then kill "$recv_pid" 2>/dev/null || true; fi
    wait "$recv_pid"; rs=$?; [ "$rs" = "124" ] && TIMED_OUT=true
    finish="$(now_s)"
    touch "$r_stop" "$s_stop"; wait "$r_samp" "$s_samp" 2>/dev/null || true
    set -e

    WALL="$(elapsed_s "$start" "$finish")"
    S_PEAK="$(max_rss_kb_from_time "$st")"; R_PEAK="$(max_rss_kb_from_time "$rt")"
    S_AVG="$(awk '{print $2}' "$s_out" 2>/dev/null)"; R_AVG="$(awk '{print $2}' "$r_out" 2>/dev/null)"
    CPU="$(cpu_pct_from_time "$st")"
    S_CTX="$(ctx_switches_from_time "$st")"
    ROUNDS="$(extract_metric feedback_rounds "$sl" "$rl" "$st" "$rt")"
    STATUS_CODE=$((ss + rs))
    DEST="$recv_dir/$(basename "$WL_PATH")"
}

run_rsync() {  # $1=transport: daemon|ssh
    local kind="$1" base; base="$(basename "$WL_PATH")"
    local sl="$CASE_DIR/rsync.log" st="$CASE_DIR/rsync.time"
    local r_stop="$CASE_DIR/r_stop" r_out="$CASE_DIR/r_rss" s_stop="$CASE_DIR/s_stop" s_out="$CASE_DIR/s_rss"
    local start finish status; TIMED_OUT=false
    set +e
    sample_rss "rsync " "$r_stop" "$r_out" & local r_samp=$!
    sample_rss "rsync " "$s_stop" "$s_out" & local s_samp=$!
    start="$(now_s)"
    if [ "$kind" = "daemon" ]; then
        local root="$CASE_DIR/rsyncd_root"; mkdir -p "$root"
        local conf="$CASE_DIR/rsyncd.conf"
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
        rsync --daemon --no-detach --address="$HOST_IP" --port=1873 --config="$conf" \
            >"$CASE_DIR/rsyncd.log" 2>&1 &
        RSYNCD_PID=$!
        sleep 0.5
        ip netns exec "$NS" timeout "$TIMEOUT_S" /usr/bin/time -v rsync -aW --inplace --no-compress \
            "$WL_PATH" "rsync://${HOST_IP}:1873/bench/" >"$sl" 2>"$st"
        status=$?
        DEST="$root/$base"
    else
        ensure_ssh_key
        local recv_dir="$CASE_DIR/recv"; mkdir -p "$recv_dir"
        ip netns exec "$NS" timeout "$TIMEOUT_S" /usr/bin/time -v rsync -aW --inplace --no-compress \
            -e "ssh $(ssh_opts)" "$WL_PATH" "${REMOTE_USER}@${HOST_IP}:${recv_dir}/" >"$sl" 2>"$st"
        status=$?
        DEST="$recv_dir/$base"
    fi
    [ "$status" = "124" ] && TIMED_OUT=true
    finish="$(now_s)"
    touch "$r_stop" "$s_stop"; wait "$r_samp" "$s_samp" 2>/dev/null || true
    [ -n "$RSYNCD_PID" ] && { kill "$RSYNCD_PID" 2>/dev/null || true; RSYNCD_PID=""; }
    set -e

    WALL="$(elapsed_s "$start" "$finish")"
    S_PEAK="$(max_rss_kb_from_time "$st")"; CPU="$(cpu_pct_from_time "$st")"
    S_CTX="$(ctx_switches_from_time "$st")"
    R_PEAK="$(awk '{print $1}' "$r_out" 2>/dev/null)"; R_AVG="$(awk '{print $2}' "$r_out" 2>/dev/null)"
    S_AVG="$(awk '{print $2}' "$s_out" 2>/dev/null)"
    ROUNDS=""
    STATUS_CODE="$status"
}

# ── run + verify + emit ──────────────────────────────────────────────────────
setup_link

DEST=""
WALL=""; S_PEAK=""; R_PEAK=""; S_AVG=""; R_AVG=""; CPU=""; S_CTX=""; ROUNDS=""; STATUS_CODE=1; TIMED_OUT=false
case "$METHOD" in
    atp-rq-lab)             run_atp lab rq ;;
    atp-rq-auth)            run_atp key rq ;;
    atp-quic-tls13)         run_atp key quic ;;
    rsyncd)                 run_rsync daemon ;;
    rsync-ssh-aes128gcm)    run_rsync ssh ;;
    *) log "unknown method '$METHOD' — recording as error"; STATUS_CODE=2 ;;
esac

# Determine workload kind + source digest, then verify the destination.
SRC_SHA=""; DST_SHA=""; SHA_OK=false
if [ -d "$WL_PATH" ]; then
    KIND="tree"
    # SRC and DST must be computed by the SAME function so identical trees hash identically.
    # The manifest digest used a different byte layout (no trailing newline + Python codepoint
    # sort vs bash locale `sort`), so it never matched tree_digest's output even for a perfect
    # transfer -> every tree cell (atp AND rsync) was scored sha_mismatch. Compare the actual
    # source tree to the actual destination tree via tree_digest on both sides instead.
    SRC_SHA="$(tree_digest "$WL_PATH")"
    DST_SHA="$(tree_digest "$DEST")"
else
    KIND="file"
    SRC_SHA="$(sha256_file "$WL_PATH")"
    DST_SHA="$(sha256_file "$DEST")"
fi
[ -n "$SRC_SHA" ] && [ "$SRC_SHA" = "$DST_SHA" ] && SHA_OK=true

# Fail-closed status. SHA_OK (tree_digest src==dst) is the source of truth for
# DELIVERY: it proves the WHOLE object arrived byte-identical, so a partial or
# corrupt transfer can never pass it. A non-zero EXIT after a verified delivery is
# a clean-exit robustness bug, NOT a data failure — atp 50M single-file @ 10% loss
# delivers correctly but the process exits 144 (bead nsbub4). Crediting it as "ok"
# (with status_code preserving the dirty exit in the row) keeps atp's real
# lossy-link delivery from being discarded as a failure, while staying fail-closed:
# a timeout, or any non-zero exit WITHOUT verified data, is still not "ok".
STATUS="ok"
if [ "$TIMED_OUT" = "true" ]; then STATUS="timeout"
elif [ "$SHA_OK" != "true" ]; then
    if [ "${STATUS_CODE:-1}" != "0" ]; then STATUS="error"; else STATUS="sha_mismatch"; fi
fi

SIZE_BYTES=0
if [ "$KIND" = "file" ] && [ -f "$WL_PATH" ]; then SIZE_BYTES="$(wc -c <"$WL_PATH" | tr -d ' ')"; fi
if [ "$KIND" = "tree" ] && [ -f "${WL_PATH}.manifest.jsonl" ]; then
    SIZE_BYTES="$(python3 -c 'import json,sys; print(sum(json.loads(l).get("size",0) for l in open(sys.argv[1]) if l.strip()))' "${WL_PATH}.manifest.jsonl")"
fi

# Per-packet floor: the minimal one-sendto-per-symbol datagram count for the atp
# methods (ceil(size / symbol_size)). Combined with wall_s this exposes atp's
# per-packet syscall overhead on rate-capped low-latency links — the "perfect"
# cell where atp loses to rsync's few large TCP writes. 0 for rsync (big writes).
EST_DGRAMS=0
case "$METHOD" in
    atp-*)
        if [ "${SIZE_BYTES:-0}" -gt 0 ] && [ "${SYMBOL_SIZE:-0}" -gt 0 ]; then
            EST_DGRAMS=$(( (SIZE_BYTES + SYMBOL_SIZE - 1) / SYMBOL_SIZE ))
        fi
        ;;
esac

PEAK_RSS_KB="$(imax "$S_PEAK" "$R_PEAK")"
AVG_RSS_KB="$(imax "$S_AVG" "$R_AVG")"

# Emit one JSONL row (field names match score_matrix.py + matrix_bench.sh).
# Values are passed via env (not shell-interpolated into the script) so quoting
# and empty/odd values cannot corrupt the JSON.
ROW_RUN_ID="$RUN_ID" ROW_GIT="$GIT_HEAD" ROW_WL="$WORKLOAD" ROW_KIND="$KIND" \
ROW_SIZE="${SIZE_BYTES:-0}" ROW_REGIME="$REGIME" ROW_TIER="$TIER" ROW_METHOD="$METHOD" \
ROW_REP="$REP" ROW_NETEM="$NETEM_JSON" ROW_WALL="${WALL:-0}" ROW_PEAK="${PEAK_RSS_KB:-0}" \
ROW_AVG="${AVG_RSS_KB:-0}" ROW_SP="${S_PEAK:-0}" ROW_RP="${R_PEAK:-0}" ROW_SA="${S_AVG:-0}" \
ROW_RA="${R_AVG:-0}" ROW_CPU="${CPU:-0}" ROW_ROUNDS="${ROUNDS:-0}" ROW_SRC="$SRC_SHA" \
ROW_DST="$DST_SHA" ROW_SHA_OK="$SHA_OK" ROW_TO="$TIMED_OUT" ROW_SC="${STATUS_CODE:-1}" \
ROW_STATUS="$STATUS" ROW_CASE="$CASE_DIR" ROW_CTX="${S_CTX:-0}" ROW_ESTPKT="${EST_DGRAMS:-0}" \
ROW_STREAMS="${STREAMS:-0}" \
python3 - >>"$RESULTS" <<'PY'
import json, os


def num(name, default=0.0):
    raw = (os.environ.get(name) or "").strip()
    if raw == "":
        return default
    try:
        f = float(raw)
        return int(f) if f.is_integer() else f
    except ValueError:
        return default


def jobj(name, default):
    try:
        return json.loads(os.environ.get(name) or "")
    except ValueError:
        return default


e = os.environ.get
row = {
    "schema": "atp-bench-matrix-result-v1",
    "run_id": e("ROW_RUN_ID", "adhoc"),
    "git_head": e("ROW_GIT", "unknown"),
    "workload": e("ROW_WL", ""),
    "workload_kind": e("ROW_KIND", ""),
    "size_bytes": num("ROW_SIZE"),
    "regime": e("ROW_REGIME", ""),
    "crypto_tier": e("ROW_TIER", ""),
    "method": e("ROW_METHOD", ""),
    "rep": num("ROW_REP"),
    "netem": jobj("ROW_NETEM", {}),
    "wall_s": num("ROW_WALL"),
    "peak_rss_kb": num("ROW_PEAK"),
    "avg_rss_kb": num("ROW_AVG"),
    "sender_peak_rss_kb": num("ROW_SP"),
    "receiver_peak_rss_kb": num("ROW_RP"),
    "sender_avg_rss_kb": num("ROW_SA"),
    "receiver_avg_rss_kb": num("ROW_RA"),
    "sender_cpu_pct": num("ROW_CPU"),
    "sender_ctx_switches": num("ROW_CTX"),
    "est_min_datagrams": num("ROW_ESTPKT"),
    "feedback_rounds": num("ROW_ROUNDS"),
    "source_sha": e("ROW_SRC", ""),
    "dest_sha": e("ROW_DST", ""),
    "sha_ok": e("ROW_SHA_OK", "false") == "true",
    "timed_out": e("ROW_TO", "false") == "true",
    "status_code": num("ROW_SC", 1),
    "status": e("ROW_STATUS", "error"),
    "case_dir": e("ROW_CASE", ""),
}
if row["method"].startswith("atp-rq-"):
    row["atp_rq_streams"] = num("ROW_STREAMS", 0)
    row["stream_count"] = row["atp_rq_streams"]
print(json.dumps(row, sort_keys=True, separators=(",", ":")))
PY

log "DONE wall=${WALL:-?}s status=${STATUS} sha_ok=${SHA_OK} rounds=${ROUNDS:-?} peak_rss_kb=${PEAK_RSS_KB:-?} streams=${STREAMS:-n/a}"
