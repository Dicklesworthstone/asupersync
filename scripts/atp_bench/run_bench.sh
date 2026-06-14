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
TOOLS="atp-rq,atp-tcp,rsync-ssh,rsyncd"
RUNS=3
OUT="artifacts/atp_bench/$(date +%Y-%m-%d)"
ATP_PORT=8472
RSYNCD_PORT=8730
BASE=/root/atp-bench
ATP_RQ_STREAMS=8
ATP_RQ_SYMBOL_SIZE=1024
ATP_RQ_REPAIR_OVERHEAD=1.15
ATP_RQ_TAIL_DRAIN_MS=2

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
        --atp-rq-streams) ATP_RQ_STREAMS="$2"; shift 2;;
        --atp-rq-symbol-size) ATP_RQ_SYMBOL_SIZE="$2"; shift 2;;
        --atp-rq-repair-overhead) ATP_RQ_REPAIR_OVERHEAD="$2"; shift 2;;
        --atp-rq-tail-drain-ms) ATP_RQ_TAIL_DRAIN_MS="$2"; shift 2;;
        *) echo "unknown arg: $1" >&2; exit 2;;
    esac
done
[[ -n "$SENDER" && -n "$RECEIVER" ]] || { echo "need --sender and --receiver" >&2; exit 2; }

SSH_S=(ssh -i "$SENDER_KEY" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 "$SENDER")
SSH_R=(ssh -i "$RECEIVER_KEY" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 "$RECEIVER")
SCP_S=(scp -i "$SENDER_KEY" -o StrictHostKeyChecking=accept-new)
SCP_R=(scp -i "$RECEIVER_KEY" -o StrictHostKeyChecking=accept-new)
RECEIVER_IP="${RECEIVER##*@}"

mkdir -p "$OUT"
RESULTS="$OUT/results.jsonl"
note() { echo "[bench] $(date +%H:%M:%S) $*" >&2; }

# ─── Preflight: deploy ───────────────────────────────────────────────────────
note "deploying scripts + binary"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
"${SSH_S[@]}" "mkdir -p $BASE/recv $BASE/manifests"
"${SSH_R[@]}" "mkdir -p $BASE/recv $BASE/manifests"
"${SCP_S[@]}" "$SCRIPT_DIR/gen_payloads.sh" "$SCRIPT_DIR/collect_metrics.sh" "$SCRIPT_DIR/run_one.sh" "$SENDER:$BASE/"
"${SCP_R[@]}" "$SCRIPT_DIR/collect_metrics.sh" "$RECEIVER:$BASE/"
"${SCP_S[@]}" "$ATP_BINARY" "$SENDER:$BASE/atp"
"${SCP_R[@]}" "$ATP_BINARY" "$RECEIVER:$BASE/atp"
"${SSH_S[@]}" "chmod +x $BASE/atp $BASE/*.sh"
"${SSH_R[@]}" "chmod +x $BASE/atp $BASE/*.sh"

# Sender→receiver ssh trust for rsync-ssh (sender's root key onto receiver).
note "ensuring sender→receiver ssh trust"
SENDER_PUB=$("${SSH_S[@]}" "test -f /root/.ssh/id_ed25519 || ssh-keygen -t ed25519 -N '' -f /root/.ssh/id_ed25519 -q; cat /root/.ssh/id_ed25519.pub")
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
{"date":"$(date -u +%FT%TZ)","sender":"$SENDER","receiver":"$RECEIVER","rtt":"$RTT","sender_cores":$SENDER_CORES,"receiver_cores":$RECEIVER_CORES,"tools":"$TOOLS","payloads":"$PAYLOADS","runs":$RUNS,"atp_rq_streams":$ATP_RQ_STREAMS,"atp_rq_symbol_size":$ATP_RQ_SYMBOL_SIZE,"atp_rq_repair_overhead":$ATP_RQ_REPAIR_OVERHEAD,"atp_rq_tail_drain_ms":$ATP_RQ_TAIL_DRAIN_MS}
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
    local ppath bytes mname
    ppath=$(payload_path "$payload")
    bytes=$(payload_bytes "$payload")
    mname=$(manifest_name "$payload")

    # Clean receiver dest (scoped, guarded path).
    "${SSH_R[@]}" "find $BASE/recv -mindepth 1 -delete"

    # Receiver-side sampler + (for atp) the one-shot receiver under time -v.
    local recv_pid_file="$BASE/recv_run.pid"
    case "$tool" in
        atp-rq)
            "${SSH_R[@]}" "rm -f $BASE/recv_time.txt; nohup $BASE/collect_metrics.sh '$BASE/atp recv' $BASE/sampler.jsonl >/dev/null 2>&1 & echo \$! > $BASE/sampler.pid
nohup /usr/bin/time -v -o $BASE/recv_time.txt $BASE/atp recv $BASE/recv --listen 0.0.0.0:$ATP_PORT --once --transport rq --symbol-size $ATP_RQ_SYMBOL_SIZE --repair-overhead $ATP_RQ_REPAIR_OVERHEAD --rq-tail-drain-ms $ATP_RQ_TAIL_DRAIN_MS > $BASE/recv_out.txt 2>&1 & echo \$! > $recv_pid_file"
            sleep 1 ;;
        atp-tcp)
            "${SSH_R[@]}" "rm -f $BASE/recv_time.txt; nohup $BASE/collect_metrics.sh '$BASE/atp recv' $BASE/sampler.jsonl >/dev/null 2>&1 & echo \$! > $BASE/sampler.pid
nohup /usr/bin/time -v -o $BASE/recv_time.txt $BASE/atp recv $BASE/recv --listen 0.0.0.0:$ATP_PORT --once --transport tcp > $BASE/recv_out.txt 2>&1 & echo \$! > $recv_pid_file"
            sleep 1 ;;
        rsync-ssh)
            "${SSH_R[@]}" "nohup $BASE/collect_metrics.sh 'rsync' $BASE/sampler.jsonl >/dev/null 2>&1 & echo \$! > $BASE/sampler.pid" ;;
        rsyncd)
            "${SSH_R[@]}" "nohup $BASE/collect_metrics.sh 'rsync' $BASE/sampler.jsonl >/dev/null 2>&1 & echo \$! > $BASE/sampler.pid" ;;
        *)
            echo "unknown tool: $tool" >&2; exit 2 ;;
    esac

    # Sender command.
    local label="${tool}_${payload}_r${run_idx}"
    local sender_json
    case "$tool" in
        atp-rq)
            sender_json=$("${SSH_S[@]}" "bash $BASE/run_one.sh $label $bytes -- $BASE/atp send $BASE/payloads/$ppath $RECEIVER_IP:$ATP_PORT --transport rq --streams $ATP_RQ_STREAMS --symbol-size $ATP_RQ_SYMBOL_SIZE --repair-overhead $ATP_RQ_REPAIR_OVERHEAD --rq-tail-drain-ms $ATP_RQ_TAIL_DRAIN_MS") ;;
        atp-tcp)
            sender_json=$("${SSH_S[@]}" "bash $BASE/run_one.sh $label $bytes -- $BASE/atp send $BASE/payloads/$ppath $RECEIVER_IP:$ATP_PORT --transport tcp") ;;
        rsync-ssh)
            sender_json=$("${SSH_S[@]}" "bash $BASE/run_one.sh $label $bytes -- rsync -aW --inplace -e 'ssh -T -x -o Compression=no -o StrictHostKeyChecking=accept-new -c aes128-gcm@openssh.com' $BASE/payloads/$ppath root@$RECEIVER_IP:$BASE/recv/") ;;
        rsyncd)
            sender_json=$("${SSH_S[@]}" "bash $BASE/run_one.sh $label $bytes -- rsync -aW --inplace --port $RSYNCD_PORT $BASE/payloads/$ppath rsync://$RECEIVER_IP/bench/") ;;
        *)
            echo "unknown tool: $tool" >&2; exit 2 ;;
    esac

    # Wait for the atp receiver to finish committing (it exits on --once).
    if [[ "$tool" == atp-* ]]; then
        "${SSH_R[@]}" "for i in \$(seq 1 120); do kill -0 \$(cat $recv_pid_file) 2>/dev/null || exit 0; sleep 0.5; done; exit 1" \
            || note "WARN: atp receiver still alive after 60s"
    fi

    # Stop sampler, fetch receiver metrics.
    "${SSH_R[@]}" "kill \$(cat $BASE/sampler.pid) 2>/dev/null || true"
    local recv_sampler recv_time_json=null
    recv_sampler=$("${SSH_R[@]}" "python3 - <<'PY'
import json
peak_rss=avg_rss=peak_cpu=avg_cpu=peak_load=0.0; n=0
try:
    for line in open('$BASE/sampler.jsonl'):
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
    t=open('$BASE/recv_time.txt').read()
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

    # Bit-for-bit verification against the manifest. Always recorded.
    local verify_ok=false
    if "${SSH_R[@]}" "cd $BASE/recv && sha256sum --status -c $BASE/manifests/$mname.sha256"; then
        verify_ok=true
    fi

    echo "{\"tool\":\"$tool\",\"payload\":\"$payload\",\"run\":$run_idx,\"verify_ok\":$verify_ok,\"sender\":$sender_json,\"receiver_sampler\":$recv_sampler,\"receiver_time\":$recv_time_json}" >> "$RESULTS"
    local wall verify_str
    wall=$(echo "$sender_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["wall_s"])')
    note "$label: wall=${wall}s verify_ok=$verify_ok"
    [[ "$verify_ok" == true ]] || note "!!! VERIFY FAILED for $label"
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
            if python3 -c "exit(0 if float('$load') < 1.5*$cores else 1)"; then :; else
                note "ABORT series: $host_cmd loadavg $load exceeds 1.5x$cores cores"; exit 1
            fi
        done
        run_transfer "$tool" "$payload" 0   # warmup
        for r in $(seq 1 "$RUNS"); do run_transfer "$tool" "$payload" "$r"; done
    done
    [[ "$tool" == rsyncd ]] && stop_rsyncd
done

note "done: $RESULTS"
note "generate the report with: python3 $SCRIPT_DIR/report.py $RESULTS > $OUT/report.md"
