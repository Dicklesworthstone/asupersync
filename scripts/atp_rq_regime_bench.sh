#!/usr/bin/env bash
set -euo pipefail

# Honest ATP-RQ vs tuned rsync scoreboard harness.
#
# Runs both tools inside a netns/veth/netem link so Contabo can act as an
# isolated 100M-ish testbed without borrowing the shared host interface. Output
# artifacts are kept under a unique run directory; this script does not remove
# prior benchmark data.
#
# Typical smoke:
#   sudo env BIN=/tmp/atp_bench/atp_f3 SIZES=1M:1048576 REGIMES=clean \
#     bash scripts/atp_rq_regime_bench.sh
#
# Full scoreboard:
#   sudo env BIN=/tmp/atp_bench/atp_f3 bash scripts/atp_rq_regime_bench.sh

BIN="${BIN:-/tmp/atp_bench/atp_f3}"
OUT_DIR="${OUT_DIR:-/tmp/atp_rq_regime_bench}"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
RUN_DIR="${OUT_DIR}/${RUN_ID}"

SIZES="${SIZES:-10M:10485760 100M:104857600 1G:1073741824}"
REGIMES="${REGIMES:-clean lossy1 lossy3 lossy10 spotty highbdp50 highbdp100}"
METHODS="${METHODS:-atp-rq rsync}"

RATE="${RATE:-100mbit}"
HOST_IP="${HOST_IP:-10.99.0.1}"
NS_IP="${NS_IP:-10.99.0.2}"
CIDR="${CIDR:-24}"
PORT_BASE="${PORT_BASE:-49152}"
WORKERS="${WORKERS:-4}"
STREAMS="${STREAMS:-8}"
SYMBOL_SIZE="${SYMBOL_SIZE:-1200}"
MAX_BYTES="${MAX_BYTES:-2147483648}"
ATP_TIMEOUT="${ATP_TIMEOUT:-2400}"
RSYNC_TIMEOUT="${RSYNC_TIMEOUT:-2400}"
RECEIVER_READY_SLEEP="${RECEIVER_READY_SLEEP:-0.75}"
RSS_SAMPLE_INTERVAL="${RSS_SAMPLE_INTERVAL:-0.05}"
SPOTTY_PHASE_SECONDS="${SPOTTY_PHASE_SECONDS:-8}"
REMOTE_USER="${REMOTE_USER:-root}"
SSH_KEY="${SSH_KEY:-/root/.ssh/atp_rq_regime_local}"
RQ_AUTH_KEY_HEX="${RQ_AUTH_KEY_HEX:-00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff}"

RESULTS_JSONL="${RUN_DIR}/results.jsonl"
RESULTS_TSV="${RUN_DIR}/results.tsv"
RUN_META="${RUN_DIR}/run_meta.txt"
REGIME_MUTATOR_PID=""

require_root() {
    if [ "$(id -u)" != "0" ]; then
        echo "atp_rq_regime_bench.sh must run as root for netns/tc" >&2
        exit 1
    fi
}

require_cmds() {
    local missing=0
    for cmd in awk basename cat chmod cksum date dd getent grep ip mkdir pgrep ps rsync sed sha256sum sleep ssh ssh-keygen tc timeout touch; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo "missing required command: $cmd" >&2
            missing=1
        fi
    done
    if [ "$missing" != "0" ]; then
        exit 1
    fi
    if [ ! -x "$BIN" ]; then
        echo "BIN is not executable: $BIN" >&2
        exit 1
    fi
    if ! command -v /usr/bin/time >/dev/null 2>&1; then
        echo "missing required command: /usr/bin/time" >&2
        exit 1
    fi
}

json_escape() {
    sed 's/\\/\\\\/g; s/"/\\"/g' <<<"$1"
}

num_or_null() {
    local value="${1:-}"
    if [ -n "$value" ] && [[ "$value" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
        printf '%s' "$value"
    else
        printf 'null'
    fi
}

now_s() {
    date +%s.%N
}

elapsed_s() {
    awk -v start="$1" -v finish="$2" 'BEGIN { printf "%.6f", finish - start }'
}

max_rss_kb_from_time() {
    awk -F: '/Maximum resident set size/ { gsub(/^[ \t]+/, "", $2); print $2 }' "$1" | tail -n 1
}

extract_metric() {
    local key="$1"
    shift
    grep -h -E "\"?${key}\"?[[:space:]]*[:=]" "$@" 2>/dev/null \
        | tail -n 1 \
        | sed -E "s/.*\"?${key}\"?[[:space:]]*[:=][[:space:]]*([0-9]+).*/\\1/" \
        | grep -E '^[0-9]+$' \
        || true
}

sha256_file() {
    local path="$1"
    if [ -f "$path" ]; then
        sha256sum "$path" | awk '{ print $1 }'
    else
        printf 'missing'
    fi
}

sample_peak_rss_kb() {
    local pattern="$1"
    local stop_file="$2"
    local out_file="$3"
    local peak=0

    while [ ! -e "$stop_file" ]; do
        local total=0
        local pids=""
        pids="$(pgrep -f "$pattern" 2>/dev/null || true)"
        for pid in $pids; do
            local rss=""
            rss="$(ps -o rss= -p "$pid" 2>/dev/null | awk '{ print $1 }' || true)"
            if [ -n "$rss" ]; then
                total=$((total + rss))
            fi
        done
        if [ "$total" -gt "$peak" ]; then
            peak="$total"
        fi
        sleep "$RSS_SAMPLE_INTERVAL"
    done

    printf '%s\n' "$peak" >"$out_file"
}

emit_result() {
    local regime="$1"
    local size_label="$2"
    local size_bytes="$3"
    local method="$4"
    local wall="$5"
    local sender_rss="$6"
    local receiver_rss="$7"
    local feedback_rounds="$8"
    local source_sha="$9"
    local dest_sha="${10}"
    local sha_ok="${11}"
    local status="${12}"
    local case_dir="${13}"
    local note="${14}"

    local note_json
    note_json="$(json_escape "$note")"
    local case_dir_json
    case_dir_json="$(json_escape "$case_dir")"

    printf '{"run_id":"%s","regime":"%s","size_label":"%s","size_bytes":%s,"method":"%s","wall_seconds":%s,"sender_peak_rss_kb":%s,"receiver_peak_rss_kb":%s,"feedback_rounds":%s,"source_sha":"%s","dest_sha":"%s","sha_ok":%s,"status":%s,"case_dir":"%s","note":"%s"}\n' \
        "$(json_escape "$RUN_ID")" \
        "$(json_escape "$regime")" \
        "$(json_escape "$size_label")" \
        "$(num_or_null "$size_bytes")" \
        "$(json_escape "$method")" \
        "$(num_or_null "$wall")" \
        "$(num_or_null "$sender_rss")" \
        "$(num_or_null "$receiver_rss")" \
        "$(num_or_null "$feedback_rounds")" \
        "$(json_escape "$source_sha")" \
        "$(json_escape "$dest_sha")" \
        "$sha_ok" \
        "$(num_or_null "$status")" \
        "$case_dir_json" \
        "$note_json" \
        >>"$RESULTS_JSONL"

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$regime" "$size_label" "$method" "$wall" "$sender_rss" "$receiver_rss" \
        "$feedback_rounds" "$sha_ok" "$status" "$dest_sha" "$note" >>"$RESULTS_TSV"
}

ensure_ssh_key() {
    mkdir -p "$(dirname "$SSH_KEY")"
    if [ ! -f "$SSH_KEY" ]; then
        ssh-keygen -q -t ed25519 -N '' -f "$SSH_KEY"
    fi
    chmod 700 "$(dirname "$SSH_KEY")"
    chmod 600 "$SSH_KEY"

    local home_dir
    home_dir="$(getent passwd "$REMOTE_USER" | awk -F: '{ print $6 }')"
    if [ -z "$home_dir" ]; then
        echo "cannot determine home directory for ${REMOTE_USER}" >&2
        exit 1
    fi
    mkdir -p "${home_dir}/.ssh"
    chmod 700 "${home_dir}/.ssh"
    local pub
    pub="$(cat "${SSH_KEY}.pub")"
    touch "${home_dir}/.ssh/authorized_keys"
    chmod 600 "${home_dir}/.ssh/authorized_keys"
    if ! grep -qxF "$pub" "${home_dir}/.ssh/authorized_keys"; then
        printf '%s\n' "$pub" >>"${home_dir}/.ssh/authorized_keys"
    fi
}

netem_with_rate() {
    if [ "$RATE" = "none" ]; then
        printf '%s' "$*"
    elif [ "$#" -eq 0 ]; then
        printf 'rate %s' "$RATE"
    else
        printf '%s rate %s' "$*" "$RATE"
    fi
}

apply_netem() {
    local args
    args="$(netem_with_rate "$@")"
    # shellcheck disable=SC2086
    tc qdisc replace dev "$IF_HOST" root netem $args
    # shellcheck disable=SC2086
    ip netns exec "$NS" tc qdisc replace dev "$IF_NS" root netem $args
}

start_spotty_mutator() {
    local stop_file="$1"
    local log_file="$2"
    (
        local phase=0
        while [ ! -e "$stop_file" ]; do
            case $((phase % 4)) in
                0) apply_netem loss 0.5% delay 10ms ;;
                1) apply_netem loss 8% 35% delay 45ms 15ms ;;
                2) apply_netem loss 2% delay 25ms 8ms ;;
                3) apply_netem loss 10% 50% delay 60ms 25ms ;;
            esac
            printf '%s phase=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$phase"
            phase=$((phase + 1))
            sleep "$SPOTTY_PHASE_SECONDS"
        done
    ) >"$log_file" 2>&1 &
    printf '%s' "$!"
}

begin_regime() {
    local regime="$1"
    local case_dir="$2"
    local stop_file="$case_dir/spotty_stop"
    local mutator_log="$case_dir/spotty_netem.log"
    REGIME_MUTATOR_PID=""

    case "$regime" in
        clean)
            apply_netem
            ;;
        lossy1)
            apply_netem loss 1% delay 10ms
            ;;
        lossy3)
            apply_netem loss 3% delay 10ms
            ;;
        lossy10)
            apply_netem loss 10% delay 10ms
            ;;
        highbdp50)
            apply_netem delay 25ms
            ;;
        highbdp100)
            apply_netem delay 50ms
            ;;
        spotty)
            apply_netem loss 0.5% delay 10ms
            REGIME_MUTATOR_PID="$(start_spotty_mutator "$stop_file" "$mutator_log")"
            ;;
        *)
            echo "unknown regime: $regime" >&2
            exit 1
            ;;
    esac
}

end_regime() {
    local case_dir="$1"
    local mutator_pid="${2:-}"
    if [ -n "$mutator_pid" ]; then
        touch "$case_dir/spotty_stop"
        wait "$mutator_pid" 2>/dev/null || true
    fi
}

create_payload() {
    local path="$1"
    local bytes="$2"
    local full_mb=$((bytes / 1048576))
    local rem=$((bytes % 1048576))

    if [ "$full_mb" -gt 0 ]; then
        dd if=/dev/urandom of="$path" bs=1M count="$full_mb" status=none
    else
        : >"$path"
    fi
    if [ "$rem" -gt 0 ]; then
        dd if=/dev/urandom bs=1 count="$rem" status=none >>"$path"
    fi
}

setup_netns() {
    local suffix
    suffix="$(printf '%s' "$RUN_ID" | cksum | awk '{ print substr($1, 1, 6) }')"
    NS="${NS:-atprq${suffix}}"
    IF_HOST="${IF_HOST:-vh${suffix}}"
    IF_NS="${IF_NS:-vn${suffix}}"

    ip netns add "$NS"
    ip link add "$IF_HOST" type veth peer name "$IF_NS"
    ip link set "$IF_NS" netns "$NS"
    ip addr add "${HOST_IP}/${CIDR}" dev "$IF_HOST"
    ip link set "$IF_HOST" up
    ip netns exec "$NS" ip addr add "${NS_IP}/${CIDR}" dev "$IF_NS"
    ip netns exec "$NS" ip link set lo up
    ip netns exec "$NS" ip link set "$IF_NS" up
    apply_netem
}

teardown_netns() {
    ip netns del "$NS" >/dev/null 2>&1 || true
    ip link del "$IF_HOST" >/dev/null 2>&1 || true
}

ssh_opts() {
    printf '%s' "-i ${SSH_KEY} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -c aes128-gcm@openssh.com"
}

run_atp() {
    local regime="$1"
    local size_label="$2"
    local size_bytes="$3"
    local src="$4"
    local source_sha="$5"
    local case_dir="$6"
    local port="$7"

    local atp_dir="$case_dir/atp_recv"
    mkdir -p "$atp_dir"
    local recv_log="$case_dir/atp_recv.log"
    local send_log="$case_dir/atp_send.log"
    local recv_time="$case_dir/atp_recv.time"
    local send_time="$case_dir/atp_send.time"
    begin_regime "$regime" "$case_dir/atp"
    local mutator_pid="$REGIME_MUTATOR_PID"

    set +e
    timeout "$ATP_TIMEOUT" /usr/bin/time -v "$BIN" recv "$atp_dir" \
        --listen "0.0.0.0:${port}" \
        --transport rq \
        --once \
        --rq-auth-key-hex "$RQ_AUTH_KEY_HEX" \
        --workers "$WORKERS" \
        --max-bytes "$MAX_BYTES" \
        >"$recv_log" 2>"$recv_time" &
    local recv_pid=$!
    sleep "$RECEIVER_READY_SLEEP"

    local start finish sender_status recv_status
    start="$(now_s)"
    ip netns exec "$NS" timeout "$ATP_TIMEOUT" /usr/bin/time -v "$BIN" send "$src" "${HOST_IP}:${port}" \
        --transport rq \
        --streams "$STREAMS" \
        --symbol-size "$SYMBOL_SIZE" \
        --rq-auth-key-hex "$RQ_AUTH_KEY_HEX" \
        >"$send_log" 2>"$send_time"
    sender_status=$?
    if [ "$sender_status" != "0" ] && kill -0 "$recv_pid" 2>/dev/null; then
        kill "$recv_pid" 2>/dev/null || true
    fi
    wait "$recv_pid"
    recv_status=$?
    finish="$(now_s)"
    set -e

    end_regime "$case_dir/atp" "$mutator_pid"

    local wall sender_rss receiver_rss feedback_rounds dest dest_sha sha_ok note status
    wall="$(elapsed_s "$start" "$finish")"
    sender_rss="$(max_rss_kb_from_time "$send_time")"
    receiver_rss="$(max_rss_kb_from_time "$recv_time")"
    feedback_rounds="$(extract_metric feedback_rounds "$send_log" "$recv_log" "$send_time" "$recv_time")"
    dest="${atp_dir}/$(basename "$src")"
    dest_sha="$(sha256_file "$dest")"
    sha_ok=false
    if [ "$dest_sha" = "$source_sha" ]; then
        sha_ok=true
    fi
    status=$((sender_status + recv_status))
    note="sender_status=${sender_status};receiver_status=${recv_status}"

    emit_result "$regime" "$size_label" "$size_bytes" "atp-rq" "$wall" "$sender_rss" "$receiver_rss" \
        "$feedback_rounds" "$source_sha" "$dest_sha" "$sha_ok" "$status" "$case_dir/atp" "$note"
}

run_rsync() {
    local regime="$1"
    local size_label="$2"
    local size_bytes="$3"
    local src="$4"
    local source_sha="$5"
    local case_dir="$6"

    local rsync_dir="$case_dir/rsync_recv"
    mkdir -p "$rsync_dir"
    local log="$case_dir/rsync.log"
    local time_log="$case_dir/rsync.time"
    local sampler_stop="$case_dir/rsync_receiver_sampler_stop"
    local sampler_out="$case_dir/rsync_receiver_peak_rss_kb.txt"
    begin_regime "$regime" "$case_dir/rsync"
    local mutator_pid="$REGIME_MUTATOR_PID"
    local sampler_pid
    sample_peak_rss_kb "rsync --server" "$sampler_stop" "$sampler_out" &
    sampler_pid=$!

    set +e
    local start finish status
    start="$(now_s)"
    ip netns exec "$NS" timeout "$RSYNC_TIMEOUT" /usr/bin/time -v rsync -a \
        --whole-file \
        --inplace \
        --no-compress \
        -e "ssh $(ssh_opts)" \
        "$src" "${REMOTE_USER}@${HOST_IP}:${rsync_dir}/" \
        >"$log" 2>"$time_log"
    status=$?
    finish="$(now_s)"
    touch "$sampler_stop"
    wait "$sampler_pid" 2>/dev/null || true
    set -e

    end_regime "$case_dir/rsync" "$mutator_pid"

    local wall sender_rss receiver_rss dest dest_sha sha_ok
    wall="$(elapsed_s "$start" "$finish")"
    sender_rss="$(max_rss_kb_from_time "$time_log")"
    receiver_rss="$(cat "$sampler_out" 2>/dev/null || true)"
    dest="${rsync_dir}/$(basename "$src")"
    dest_sha="$(sha256_file "$dest")"
    sha_ok=false
    if [ "$dest_sha" = "$source_sha" ]; then
        sha_ok=true
    fi

    emit_result "$regime" "$size_label" "$size_bytes" "rsync" "$wall" "$sender_rss" "$receiver_rss" \
        "" "$source_sha" "$dest_sha" "$sha_ok" "$status" "$case_dir/rsync" "status=${status}"
}

main() {
    require_root
    require_cmds
    mkdir -p "$RUN_DIR"
    printf 'regime\tsize\tmethod\twall_seconds\tsender_peak_rss_kb\treceiver_peak_rss_kb\tfeedback_rounds\tsha_ok\tstatus\tdest_sha\tnote\n' >"$RESULTS_TSV"
    {
        printf 'run_id=%s\n' "$RUN_ID"
        printf 'bin=%s\n' "$BIN"
        printf 'rate=%s\n' "$RATE"
        printf 'sizes=%s\n' "$SIZES"
        printf 'regimes=%s\n' "$REGIMES"
        printf 'methods=%s\n' "$METHODS"
        printf 'host_ip=%s\n' "$HOST_IP"
        printf 'ns_ip=%s\n' "$NS_IP"
    } >"$RUN_META"

    ensure_ssh_key
    setup_netns
    trap teardown_netns EXIT
    ip netns exec "$NS" ssh $(ssh_opts) "${REMOTE_USER}@${HOST_IP}" true

    local port_offset=0
    for size_spec in $SIZES; do
        local size_label="${size_spec%%:*}"
        local size_bytes="${size_spec##*:}"
        local src="${RUN_DIR}/src_${size_label}.bin"
        create_payload "$src" "$size_bytes"
        local source_sha
        source_sha="$(sha256_file "$src")"

        for regime in $REGIMES; do
            local case_dir="${RUN_DIR}/${regime}_${size_label}"
            mkdir -p "$case_dir/atp" "$case_dir/rsync"
            local port=$((PORT_BASE + port_offset))
            port_offset=$((port_offset + 1))

            if [[ " ${METHODS} " == *" atp-rq "* ]]; then
                run_atp "$regime" "$size_label" "$size_bytes" "$src" "$source_sha" "$case_dir" "$port"
            fi
            if [[ " ${METHODS} " == *" rsync "* ]]; then
                run_rsync "$regime" "$size_label" "$size_bytes" "$src" "$source_sha" "$case_dir"
            fi
        done
    done

    printf 'results_jsonl=%s\n' "$RESULTS_JSONL"
    printf 'results_tsv=%s\n' "$RESULTS_TSV"
    printf 'run_meta=%s\n' "$RUN_META"
}

main "$@"
