#!/usr/bin/env bash
# ATP vs rsync benchmark orchestrator (br-asupersync-iiz6jk).
# Run from the dev box; drives a sender and a receiver fleet machine over the
# open internet. Every transfer is SHA-256-verified on the receiver.
#
# See README.md in this directory for methodology.
set -euo pipefail

SENDER="" SENDER_KEY="" RECEIVER="" RECEIVER_KEY=""
ATP_BINARY="target/release/atp"
PAYLOADS="512k,1m,10m,100m,1g,tree"
TOOLS="atp-quic,atp-rq,atp-tcp,rsync-ssh,rsyncd"
RUNS=3
OUT="artifacts/atp_bench/$(date +%Y-%m-%d)"
ATP_PORT=8472
RSYNCD_PORT=8730
BASE=/root/atp-bench
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ATP_RQ_STREAMS=8
ATP_RQ_SYMBOL_SIZE=1024
ATP_RQ_MAX_BLOCK_SIZE=auto
ATP_RQ_REPAIR_OVERHEAD=1.001
ATP_RQ_TAIL_DRAIN_MS=2
ATP_RQ_AUTH_KEY_HEX=""
ATP_QUIC_SERVER_NAME=""
ATP_QUIC_HANDSHAKE_TIMEOUT_MS=30000
MAX_LOAD_PER_CORE=1.5
MAX_SENDER_RSS_MB=0
MAX_RECEIVER_RSS_MB=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --sender) SENDER="$2"; shift 2;;
        --sender-key) SENDER_KEY="$2"; shift 2;;
        --receiver) RECEIVER="$2"; shift 2;;
        --receiver-key) RECEIVER_KEY="$2"; shift 2;;
        --atp-binary) ATP_BINARY="$2"; shift 2;;
        --payloads) PAYLOADS="$2"; shift 2;;
        --tools) TOOLS="$2"; shift 2;;
        --runs) RUNS="$2"; shift 2;;
        --out) OUT="$2"; shift 2;;
        --base) BASE="$2"; shift 2;;
        --run-id) RUN_ID="$2"; shift 2;;
        --atp-rq-streams) ATP_RQ_STREAMS="$2"; shift 2;;
        --atp-rq-symbol-size) ATP_RQ_SYMBOL_SIZE="$2"; shift 2;;
        --atp-rq-max-block-size) ATP_RQ_MAX_BLOCK_SIZE="$2"; shift 2;;
        --atp-rq-repair-overhead) ATP_RQ_REPAIR_OVERHEAD="$2"; shift 2;;
        --atp-rq-tail-drain-ms) ATP_RQ_TAIL_DRAIN_MS="$2"; shift 2;;
        --atp-rq-auth-key-hex) ATP_RQ_AUTH_KEY_HEX="$2"; shift 2;;
        --atp-quic-server-name) ATP_QUIC_SERVER_NAME="$2"; shift 2;;
        --atp-quic-handshake-timeout-ms) ATP_QUIC_HANDSHAKE_TIMEOUT_MS="$2"; shift 2;;
        --max-load-per-core) MAX_LOAD_PER_CORE="$2"; shift 2;;
        --max-sender-rss-mb) MAX_SENDER_RSS_MB="$2"; shift 2;;
        --max-receiver-rss-mb) MAX_RECEIVER_RSS_MB="$2"; shift 2;;
        *) echo "unknown arg: $1" >&2; exit 2;;
    esac
done
[[ -n "$SENDER" && -n "$RECEIVER" ]] || { echo "need --sender and --receiver" >&2; exit 2; }
case "$RUN_ID" in
    *[!A-Za-z0-9._-]*) echo "invalid --run-id; use only A-Za-z0-9._-" >&2; exit 2;;
esac

SSH_S=(ssh -i "$SENDER_KEY" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 "$SENDER")
SSH_R=(ssh -i "$RECEIVER_KEY" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 "$RECEIVER")
SCP_S=(scp -i "$SENDER_KEY" -o StrictHostKeyChecking=accept-new)
SCP_R=(scp -i "$RECEIVER_KEY" -o StrictHostKeyChecking=accept-new)
ssh_hostname() {
    ssh -G "$1" 2>/dev/null | awk '$1 == "hostname" { print $2; exit }'
}
RECEIVER_IP=$(ssh_hostname "$RECEIVER")
RECEIVER_IP="${RECEIVER_IP:-${RECEIVER##*@}}"
ATP_QUIC_SERVER_NAME="${ATP_QUIC_SERVER_NAME:-$RECEIVER_IP}"
QUIC_TLS_DIR="$BASE/runs/$RUN_ID/quic_tls"
QUIC_CERT="$QUIC_TLS_DIR/server.pem"
QUIC_KEY="$QUIC_TLS_DIR/server.key"

mkdir -p "$OUT"
RESULTS="$OUT/results.jsonl"
note() { echo "[bench] $(date +%H:%M:%S) $*" >&2; }

# ─── Preflight: deploy ───────────────────────────────────────────────────────
note "deploying scripts + binary"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
"${SSH_S[@]}" "mkdir -p $BASE/recv/$RUN_ID $BASE/runs/$RUN_ID $BASE/manifests"
"${SSH_R[@]}" "mkdir -p $BASE/recv/$RUN_ID $BASE/runs/$RUN_ID $BASE/manifests"
"${SCP_S[@]}" "$SCRIPT_DIR/gen_payloads.sh" "$SCRIPT_DIR/collect_metrics.sh" "$SCRIPT_DIR/run_one.sh" "$SENDER:$BASE/"
"${SCP_R[@]}" "$SCRIPT_DIR/collect_metrics.sh" "$RECEIVER:$BASE/"
"${SCP_S[@]}" "$ATP_BINARY" "$SENDER:$BASE/atp"
"${SCP_R[@]}" "$ATP_BINARY" "$RECEIVER:$BASE/atp"
"${SSH_S[@]}" "chmod +x $BASE/atp $BASE/*.sh"
"${SSH_R[@]}" "chmod +x $BASE/atp $BASE/*.sh"

if [[ ",$TOOLS," == *",atp-rq,"* || ",$TOOLS," == *",atp-quic,"* ]]; then
    if [[ -z "$ATP_RQ_AUTH_KEY_HEX" ]]; then
        note "generating per-run ATP RQ/QUIC symbol-auth key"
        ATP_RQ_AUTH_KEY_HEX=$("${SSH_S[@]}" "$BASE/atp rq-keygen")
    fi
    [[ "$ATP_RQ_AUTH_KEY_HEX" =~ ^[0-9A-Fa-f]{64}$ ]] \
        || { echo "ATP RQ auth key must be 64 hex characters" >&2; exit 2; }
fi

if [[ ",$TOOLS," == *",atp-quic,"* ]]; then
    note "generating per-run ATP QUIC TLS certificate"
    "${SSH_R[@]}" "mkdir -p $QUIC_TLS_DIR
san_type=DNS
case '$ATP_QUIC_SERVER_NAME' in *:*) san_type=IP;; *[!0-9.]*) san_type=DNS;; *) san_type=IP;; esac
openssl req -x509 -newkey ed25519 -nodes -keyout $QUIC_KEY -out $QUIC_CERT -days 3 -subj '/CN=$ATP_QUIC_SERVER_NAME' -addext \"subjectAltName=\${san_type}:$ATP_QUIC_SERVER_NAME\" >/dev/null 2>&1 || \
openssl req -x509 -newkey rsa:2048 -nodes -keyout $QUIC_KEY -out $QUIC_CERT -days 3 -subj '/CN=$ATP_QUIC_SERVER_NAME' -addext \"subjectAltName=\${san_type}:$ATP_QUIC_SERVER_NAME\" >/dev/null 2>&1
test -s $QUIC_CERT && test -s $QUIC_KEY" \
        || { echo "failed to generate QUIC TLS certificate on receiver" >&2; exit 1; }
    "${SSH_R[@]}" "cat $QUIC_CERT" | "${SSH_S[@]}" "mkdir -p $QUIC_TLS_DIR && cat > $QUIC_CERT"
fi

# Sender→receiver ssh trust for rsync-ssh (sender's root key onto receiver).
note "ensuring sender→receiver ssh trust"
SENDER_PUB=$("${SSH_S[@]}" "mkdir -p ~/.ssh && chmod 700 ~/.ssh && test -f ~/.ssh/id_ed25519 || ssh-keygen -t ed25519 -N '' -f ~/.ssh/id_ed25519 -q; cat ~/.ssh/id_ed25519.pub")
"${SSH_R[@]}" "grep -qF '$SENDER_PUB' /root/.ssh/authorized_keys 2>/dev/null || echo '$SENDER_PUB' >> /root/.ssh/authorized_keys"
"${SSH_S[@]}" "ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 root@$RECEIVER_IP true" \
    || { echo "sender cannot ssh to receiver" >&2; exit 1; }

note "generating payloads on sender (1g + tree take a while on first run)"
"${SSH_S[@]}" "bash $BASE/gen_payloads.sh $BASE"
note "copying manifests to receiver"
"${SSH_S[@]}" "tar -C $BASE -cf - manifests" | "${SSH_R[@]}" "tar -C $BASE -xf -"

# Network conditions snapshot.
note "recording network conditions"
RTT=$("${SSH_S[@]}" "ping -c 10 -q $RECEIVER_IP 2>/dev/null | tail -1" || echo "ping unavailable")
SENDER_CORES=$("${SSH_S[@]}" nproc)
RECEIVER_CORES=$("${SSH_R[@]}" nproc)
cat > "$OUT/conditions.json" <<EOF
{"date":"$(date -u +%FT%TZ)","run_id":"$RUN_ID","sender":"$SENDER","receiver":"$RECEIVER","rtt":"$RTT","sender_cores":$SENDER_CORES,"receiver_cores":$RECEIVER_CORES,"tools":"$TOOLS","payloads":"$PAYLOADS","runs":$RUNS,"atp_rq_streams":$ATP_RQ_STREAMS,"atp_rq_symbol_size":$ATP_RQ_SYMBOL_SIZE,"atp_rq_max_block_size":"$ATP_RQ_MAX_BLOCK_SIZE","atp_rq_repair_overhead":$ATP_RQ_REPAIR_OVERHEAD,"atp_rq_tail_drain_ms":$ATP_RQ_TAIL_DRAIN_MS,"atp_rq_auth":"per-run-env-key","atp_quic_tls":"per-run-self-signed","atp_quic_server_name":"$ATP_QUIC_SERVER_NAME","atp_quic_handshake_timeout_ms":$ATP_QUIC_HANDSHAKE_TIMEOUT_MS,"max_load_per_core":$MAX_LOAD_PER_CORE,"max_sender_rss_mb":$MAX_SENDER_RSS_MB,"max_receiver_rss_mb":$MAX_RECEIVER_RSS_MB}
EOF
note "RTT: $RTT"

payload_path() { # payload name -> path under payloads/
    case "$1" in
        512k) echo "single_512k.bin";; 1m) echo "single_1m.bin";;
        10m) echo "single_10m.bin";; 100m) echo "single_100m.bin";;
        1g) echo "single_1g.bin";; tree) echo "tree";;
        *) echo "unknown payload $1" >&2; exit 2;;
    esac
}
manifest_name() { case "$1" in tree) echo tree;; *) echo "single_$1";; esac; }

payload_bytes() {
    "${SSH_S[@]}" "du -sb $BASE/payloads/$(payload_path "$1") | cut -f1"
}

# ─── rsyncd lifecycle on receiver ────────────────────────────────────────────
# NOTE: do not `pkill -f 'rsync --daemon'` — the remote shell's own command line
# contains that string, so pkill -f would kill the launching ssh session
# (exit 255). Kill by pid file instead. `uid = root`/`gid = root` are required
# so the module can write into the root-owned dest; `setsid </dev/null` fully
# detaches the daemon so it survives the ssh session closing.
start_rsyncd() {
    "${SSH_R[@]}" "test -f $BASE/rsyncd.pid && kill \$(cat $BASE/rsyncd.pid) 2>/dev/null; sleep 0.5
printf 'port = %s\nuse chroot = false\nuid = root\ngid = root\nmax connections = 32\npid file = %s/rsyncd.pid\n[bench]\n    path = %s/recv\n    read only = false\n' '$RSYNCD_PORT' '$BASE' '$BASE' | tee $BASE/rsyncd.conf >/dev/null
setsid rsync --daemon --config=$BASE/rsyncd.conf </dev/null >/dev/null 2>&1
sleep 0.6
ss -tlnp 2>/dev/null | grep -q ':$RSYNCD_PORT ' && echo rsyncd-listening"
}
stop_rsyncd() {
    "${SSH_R[@]}" "test -f $BASE/rsyncd.pid && kill \$(cat $BASE/rsyncd.pid) 2>/dev/null || true"
}

# ─── One run ─────────────────────────────────────────────────────────────────
run_transfer() { # tool payload run_idx -> appends one JSON line to RESULTS
    local tool="$1" payload="$2" run_idx="$3"
    local ppath bytes mname label run_rel run_dest run_dir
    ppath=$(payload_path "$payload")
    bytes=$(payload_bytes "$payload")
    mname=$(manifest_name "$payload")
    label="${tool}_${payload}_r${run_idx}"
    run_rel="$RUN_ID/$tool/$payload/r$run_idx"
    run_dest="$BASE/recv/$run_rel"
    run_dir="$BASE/runs/$run_rel"
    "${SSH_R[@]}" "mkdir -p $run_dest $run_dir"

    # Receiver-side sampler + (for atp) the one-shot receiver under time -v.
    local recv_pid_file="$run_dir/recv_run.pid"
    case "$tool" in
        atp-rq)
            "${SSH_R[@]}" "nohup $BASE/collect_metrics.sh '$BASE/atp recv' $run_dir/sampler.jsonl >/dev/null 2>&1 & echo \$! > $run_dir/sampler.pid
nohup /usr/bin/time -v -o $run_dir/recv_time.txt env ATP_RQ_AUTH_KEY_HEX='$ATP_RQ_AUTH_KEY_HEX' $BASE/atp recv $run_dest --listen 0.0.0.0:$ATP_PORT --once --transport rq --symbol-size $ATP_RQ_SYMBOL_SIZE --max-block-size '$ATP_RQ_MAX_BLOCK_SIZE' --repair-overhead $ATP_RQ_REPAIR_OVERHEAD --rq-tail-drain-ms $ATP_RQ_TAIL_DRAIN_MS > $run_dir/recv_out.txt 2>&1 & echo \$! > $recv_pid_file"
            sleep 1 ;;
        atp-quic)
            "${SSH_R[@]}" "nohup $BASE/collect_metrics.sh '$BASE/atp recv' $run_dir/sampler.jsonl >/dev/null 2>&1 & echo \$! > $run_dir/sampler.pid
nohup /usr/bin/time -v -o $run_dir/recv_time.txt env ATP_RQ_AUTH_KEY_HEX='$ATP_RQ_AUTH_KEY_HEX' $BASE/atp recv $run_dest --listen 0.0.0.0:$ATP_PORT --once --transport quic --symbol-size $ATP_RQ_SYMBOL_SIZE --max-block-size '$ATP_RQ_MAX_BLOCK_SIZE' --repair-overhead $ATP_RQ_REPAIR_OVERHEAD --rq-tail-drain-ms $ATP_RQ_TAIL_DRAIN_MS --server-cert $QUIC_CERT --server-key $QUIC_KEY --quic-handshake-timeout-ms $ATP_QUIC_HANDSHAKE_TIMEOUT_MS > $run_dir/recv_out.txt 2>&1 & echo \$! > $recv_pid_file"
            sleep 1 ;;
        atp-tcp)
            "${SSH_R[@]}" "nohup $BASE/collect_metrics.sh '$BASE/atp recv' $run_dir/sampler.jsonl >/dev/null 2>&1 & echo \$! > $run_dir/sampler.pid
nohup /usr/bin/time -v -o $run_dir/recv_time.txt $BASE/atp recv $run_dest --listen 0.0.0.0:$ATP_PORT --once --transport tcp > $run_dir/recv_out.txt 2>&1 & echo \$! > $recv_pid_file"
            sleep 1 ;;
        rsync-ssh)
            "${SSH_R[@]}" "nohup $BASE/collect_metrics.sh 'rsync' $run_dir/sampler.jsonl >/dev/null 2>&1 & echo \$! > $run_dir/sampler.pid" ;;
        rsyncd)
            "${SSH_R[@]}" "nohup $BASE/collect_metrics.sh 'rsync' $run_dir/sampler.jsonl >/dev/null 2>&1 & echo \$! > $run_dir/sampler.pid" ;;
        *)
            echo "unknown tool: $tool" >&2; exit 2 ;;
    esac

    # Sender command.
    local sender_json
    case "$tool" in
        atp-rq)
            sender_json=$("${SSH_S[@]}" "bash $BASE/run_one.sh $label $bytes -- env ATP_RQ_AUTH_KEY_HEX='$ATP_RQ_AUTH_KEY_HEX' $BASE/atp send $BASE/payloads/$ppath $RECEIVER_IP:$ATP_PORT --transport rq --streams $ATP_RQ_STREAMS --symbol-size $ATP_RQ_SYMBOL_SIZE --max-block-size '$ATP_RQ_MAX_BLOCK_SIZE' --repair-overhead $ATP_RQ_REPAIR_OVERHEAD --rq-tail-drain-ms $ATP_RQ_TAIL_DRAIN_MS") ;;
        atp-quic)
            sender_json=$("${SSH_S[@]}" "bash $BASE/run_one.sh $label $bytes -- env ATP_RQ_AUTH_KEY_HEX='$ATP_RQ_AUTH_KEY_HEX' $BASE/atp send $BASE/payloads/$ppath $RECEIVER_IP:$ATP_PORT --transport quic --symbol-size $ATP_RQ_SYMBOL_SIZE --max-block-size '$ATP_RQ_MAX_BLOCK_SIZE' --repair-overhead $ATP_RQ_REPAIR_OVERHEAD --rq-tail-drain-ms $ATP_RQ_TAIL_DRAIN_MS --ca $QUIC_CERT --server-name '$ATP_QUIC_SERVER_NAME' --quic-handshake-timeout-ms $ATP_QUIC_HANDSHAKE_TIMEOUT_MS") ;;
        atp-tcp)
            sender_json=$("${SSH_S[@]}" "bash $BASE/run_one.sh $label $bytes -- $BASE/atp send $BASE/payloads/$ppath $RECEIVER_IP:$ATP_PORT --transport tcp") ;;
        rsync-ssh)
            sender_json=$("${SSH_S[@]}" "bash $BASE/run_one.sh $label $bytes -- rsync -aW --inplace -e 'ssh -T -x -o Compression=no -o StrictHostKeyChecking=accept-new -c aes128-gcm@openssh.com' $BASE/payloads/$ppath root@$RECEIVER_IP:$run_dest/") ;;
        rsyncd)
            sender_json=$("${SSH_S[@]}" "bash $BASE/run_one.sh $label $bytes -- rsync -aW --inplace --port $RSYNCD_PORT $BASE/payloads/$ppath rsync://$RECEIVER_IP/bench/$run_rel/") ;;
        *)
            echo "unknown tool: $tool" >&2; exit 2 ;;
    esac

    # Wait for the atp receiver to finish committing (it exits on --once).
    if [[ "$tool" == atp-* ]]; then
        "${SSH_R[@]}" "for i in \$(seq 1 120); do kill -0 \$(cat $recv_pid_file) 2>/dev/null || exit 0; sleep 0.5; done; exit 1" \
            || note "WARN: atp receiver still alive after 60s"
    fi

    # Stop sampler, fetch receiver metrics.
    "${SSH_R[@]}" "kill \$(cat $run_dir/sampler.pid) 2>/dev/null || true"
    local recv_sampler recv_time_json=null
    recv_sampler=$("${SSH_R[@]}" "python3 - <<'PY'
import json
peak_rss=avg_rss=peak_cpu=avg_cpu=peak_load=0.0; n=0
try:
    for line in open('$run_dir/sampler.jsonl'):
        s=json.loads(line); n+=1
        peak_rss=max(peak_rss,s['rss_kb']); avg_rss+=s['rss_kb']
        peak_cpu=max(peak_cpu,s['cpu_pct']); avg_cpu+=s['cpu_pct']
        peak_load=max(peak_load,s['load1'])
except FileNotFoundError: pass
if n: avg_rss/=n; avg_cpu/=n
print(json.dumps({'samples':n,'peak_rss_kb':peak_rss,'avg_rss_kb':round(avg_rss,1),'peak_cpu_pct':peak_cpu,'avg_cpu_pct':round(avg_cpu,1),'peak_load1':peak_load}))
PY")
    if [[ "$tool" == atp-* ]]; then
        recv_time_json=$("${SSH_R[@]}" "python3 - <<'PY'
import json,re
d={}
try:
    t=open('$run_dir/recv_time.txt').read()
    m=re.search(r'Maximum resident set size.*: (\d+)',t)
    if m: d['max_rss_kb']=int(m.group(1))
    m=re.search(r'Elapsed \(wall clock\).*: ([\d:.]+)',t)
    if m:
        p=[float(x) for x in m.group(1).split(':')]
        d['wall_s']=p[0]*3600+p[1]*60+p[2] if len(p)==3 else p[0]*60+p[1] if len(p)==2 else p[0]
except FileNotFoundError: pass
print(json.dumps(d) if d else 'null')
PY")
    fi

    local resource_guard
    resource_guard=$(SENDER_JSON="$sender_json" RECEIVER_SAMPLER_JSON="$recv_sampler" RECEIVER_TIME_JSON="$recv_time_json" \
        MAX_LOAD_PER_CORE="$MAX_LOAD_PER_CORE" MAX_SENDER_RSS_MB="$MAX_SENDER_RSS_MB" MAX_RECEIVER_RSS_MB="$MAX_RECEIVER_RSS_MB" \
        SENDER_CORES="$SENDER_CORES" RECEIVER_CORES="$RECEIVER_CORES" python3 - <<'PY'
import json
import os


def number(value, default=0.0):
    if value is None:
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


sender = json.loads(os.environ["SENDER_JSON"])
sampler = json.loads(os.environ["RECEIVER_SAMPLER_JSON"])
receiver_time_raw = os.environ["RECEIVER_TIME_JSON"]
receiver_time = {} if receiver_time_raw == "null" else json.loads(receiver_time_raw)

max_load_per_core = number(os.environ["MAX_LOAD_PER_CORE"])
max_sender_rss_mb = number(os.environ["MAX_SENDER_RSS_MB"])
max_receiver_rss_mb = number(os.environ["MAX_RECEIVER_RSS_MB"])
sender_cores = max(1.0, number(os.environ["SENDER_CORES"], 1.0))
receiver_cores = max(1.0, number(os.environ["RECEIVER_CORES"], 1.0))

checks = []


def add_check(name, observed, limit, unit):
    checks.append(
        {
            "name": name,
            "observed": round(observed, 3),
            "limit": round(limit, 3),
            "unit": unit,
            "passed": observed <= limit,
        }
    )


if max_load_per_core > 0:
    sender_load_limit = sender_cores * max_load_per_core
    receiver_load_limit = receiver_cores * max_load_per_core
    sender_load = max(number(sender.get("load1_start")), number(sender.get("load1_end")))
    receiver_load = number(sampler.get("peak_load1"))
    add_check("sender_load1", sender_load, sender_load_limit, "loadavg")
    add_check("receiver_load1", receiver_load, receiver_load_limit, "loadavg")

if max_sender_rss_mb > 0:
    add_check("sender_peak_rss", number(sender.get("max_rss_kb")) / 1024.0, max_sender_rss_mb, "MiB")

if max_receiver_rss_mb > 0:
    receiver_rss_kb = max(number(receiver_time.get("max_rss_kb")), number(sampler.get("peak_rss_kb")))
    add_check("receiver_peak_rss", receiver_rss_kb / 1024.0, max_receiver_rss_mb, "MiB")

print(
    json.dumps(
        {
            "schema_version": "atp-bench-resource-guard-v1",
            "ok": all(check["passed"] for check in checks),
            "checks": checks,
            "configured": {
                "max_load_per_core": max_load_per_core,
                "max_sender_rss_mb": max_sender_rss_mb,
                "max_receiver_rss_mb": max_receiver_rss_mb,
            },
        },
        separators=(",", ":"),
    )
)
PY
    )

    # Bit-for-bit verification against the manifest. Always recorded.
    local verify_ok=false
    if "${SSH_R[@]}" "cd $run_dest && sha256sum --status -c $BASE/manifests/$mname.sha256"; then
        verify_ok=true
    fi

    echo "{\"tool\":\"$tool\",\"payload\":\"$payload\",\"run\":$run_idx,\"run_id\":\"$RUN_ID\",\"receiver_dest\":\"$run_dest\",\"receiver_run_dir\":\"$run_dir\",\"verify_ok\":$verify_ok,\"sender\":$sender_json,\"receiver_sampler\":$recv_sampler,\"receiver_time\":$recv_time_json,\"resource_guard\":$resource_guard}" >> "$RESULTS"
    local wall
    wall=$(echo "$sender_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["wall_s"])')
    note "$label: wall=${wall}s verify_ok=$verify_ok"
    [[ "$verify_ok" == true ]] || note "!!! VERIFY FAILED for $label"
    if [[ "$(echo "$resource_guard" | python3 -c 'import json,sys; print(str(json.load(sys.stdin)["ok"]).lower())')" != true ]]; then
        note "!!! RESOURCE GUARD FAILED for $label: $resource_guard"
        exit 1
    fi
}

# ─── Main loop ───────────────────────────────────────────────────────────────
IFS=',' read -ra TOOL_LIST <<< "$TOOLS"
IFS=',' read -ra PAYLOAD_LIST <<< "$PAYLOADS"

for tool in "${TOOL_LIST[@]}"; do
    [[ "$tool" == rsyncd ]] && start_rsyncd
    for payload in "${PAYLOAD_LIST[@]}"; do
        # Responsiveness guard before each series.
        for host_cmd in SSH_S SSH_R; do
            declare -n ssh_ref=$host_cmd
            load=$("${ssh_ref[@]}" "cut -d' ' -f1 /proc/loadavg")
            cores=$("${ssh_ref[@]}" nproc)
            if python3 -c "exit(0 if float('$load') < float('$MAX_LOAD_PER_CORE')*$cores else 1)"; then :; else
                note "ABORT series: $host_cmd loadavg $load exceeds ${MAX_LOAD_PER_CORE}x$cores cores"; exit 1
            fi
        done
        run_transfer "$tool" "$payload" 0   # warmup
        for r in $(seq 1 "$RUNS"); do run_transfer "$tool" "$payload" "$r"; done
    done
    [[ "$tool" == rsyncd ]] && stop_rsyncd
done

note "done: $RESULTS"
note "generate the report with: python3 $SCRIPT_DIR/report.py $RESULTS > $OUT/report.md"
