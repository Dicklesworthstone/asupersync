#!/usr/bin/env bash
# atp_quic_vs_rsync_benchmark.sh
#
# Benchmark asupersync ATP (QUIC + RaptorQ over real UDP, TLS-1.3, per-symbol
# HMAC) against tuned rsync, pushing payloads from a SENDER host to a RECEIVER
# host over the open internet. Measures wall-clock, peak RSS, and CPU% on the
# sender, and verifies every transfer bit-for-bit via SHA-256.
#
# rsync is given its fastest realistic configuration so the comparison is tough
# for atp:
#   * --whole-file        (skip the delta algorithm; pure overhead to an empty dest)
#   * --no-compress       (raw throughput; no CPU spent compressing)
#   * fast SSH cipher     (aes128-gcm, Compression=no) -- still encrypted, like atp
#
# Usage:  SENDER=fmd RECEIVER=vmi1149989 RECEIVER_IP=212.90.121.76 \
#         ATP_BIN_LOCAL=/path/to/atp ./benchmark.sh all
# Stages: deploy | certs | payloads | run | report | all
set -euo pipefail

SENDER="${SENDER:-fmd}"
RECEIVER="${RECEIVER:-vmi1149989}"
RECEIVER_IP="${RECEIVER_IP:-212.90.121.76}"
ATP_BIN_LOCAL="${ATP_BIN_LOCAL:-/data/tmp/rch_target_atp_release/release/atp}"
PORT="${PORT:-8472}"
WORKERS="${WORKERS:-4}"
# label:bytes pairs.  512K 1M 10M 100M 1G.
SIZES="${SIZES:-512K:524288 1M:1048576 10M:10485760 100M:104857600 1G:1073741824}"
WR="${WR:-/tmp/atp_bench}"                 # remote work dir on both hosts
LOCAL="${LOCAL:-/data/tmp/atp_bench_work}" # local control dir
OUTDIR="${OUTDIR:-$LOCAL/results_$(date +%Y%m%d_%H%M%S)}"
SSH_OPTS="-o ConnectTimeout=20 -o StrictHostKeyChecking=accept-new -o BatchMode=yes"
GEN_CERTS="$(dirname "$0")/atp_bench_gen_certs.sh"

mkdir -p "$OUTDIR"
log() { printf '[bench %s] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
snd() { ssh $SSH_OPTS "$SENDER" "$@"; }
rcv() { ssh $SSH_OPTS "$RECEIVER" "$@"; }

deploy() {
  log "deploy atp binary -> $SENDER and $RECEIVER"
  [ -x "$ATP_BIN_LOCAL" ] || { log "FATAL: atp binary not found/executable: $ATP_BIN_LOCAL"; exit 1; }
  snd "mkdir -p $WR"; rcv "mkdir -p $WR"
  scp $SSH_OPTS "$ATP_BIN_LOCAL" "$SENDER:$WR/atp" >/dev/null
  scp $SSH_OPTS "$ATP_BIN_LOCAL" "$RECEIVER:$WR/atp" >/dev/null
  snd "chmod +x $WR/atp; $WR/atp --version" || true
  rcv "chmod +x $WR/atp; $WR/atp --version" || true
}

certs() {
  log "generate certs (leaf SAN includes $RECEIVER_IP) and distribute"
  "$GEN_CERTS" "$LOCAL/certs" "$RECEIVER_IP" >&2
  scp $SSH_OPTS "$LOCAL/certs/leaf.pem" "$LOCAL/certs/leaf.key" "$RECEIVER:$WR/" >/dev/null
  scp $SSH_OPTS "$LOCAL/certs/ca.pem" "$SENDER:$WR/" >/dev/null
  # one shared per-run symbol-auth key (validated by atp's keygen)
  "$ATP_BIN_LOCAL" rq-keygen > "$LOCAL/keygen.out" 2>/dev/null || true
  KEY="$(grep -oE '[0-9a-f]{64}' "$LOCAL/keygen.out" | head -1)"
  [ -n "$KEY" ] || KEY="$(openssl rand -hex 32)"
  echo "$KEY" > "$LOCAL/auth.key"
  log "symbol-auth key: ${KEY:0:12}..."
}

gen_payloads() {
  log "generate payloads on $SENDER under $WR/src"
  snd "set -e; mkdir -p $WR/src; cd $WR/src
    for pair in $SIZES; do
      label=\${pair%%:*}; bytes=\${pair##*:}
      [ -f file_\$label.bin ] && [ \$(stat -c%s file_\$label.bin) -eq \$bytes ] && continue
      head -c \$bytes /dev/urandom > file_\$label.bin
    done
    # heterogeneous nested tree (~13 MB): mixed sizes, depth, text+binary
    find tree -mindepth 1 -delete 2>/dev/null || true
    mkdir -p tree/a/b/c tree/a/d tree/e
    head -c 1048576  /dev/urandom > tree/a/big1.bin
    head -c 3145728  /dev/urandom > tree/a/b/big2.bin
    head -c 512000   /dev/urandom > tree/a/b/c/mid.bin
    head -c 8192000  /dev/urandom > tree/a/d/big3.bin
    head -c 4096     /dev/urandom > tree/e/small.bin
    for i in \$(seq 1 50); do echo \"line \$i of a small text file in the tree\" > tree/e/text_\$i.txt; done
    sha256sum file_*.bin > sha_files.txt
    find tree -type f | sort | xargs sha256sum > sha_tree.txt
    echo PAYLOADS_READY"
}

# parse /usr/bin/time -v output file -> 'wall_s maxrss_kb cpu_pct'
parse_time() {
  local f="$1"
  awk '
    /Elapsed \(wall clock\)/ { e=$NF }
    /Maximum resident set size/ { rss=$NF }
    /Percent of CPU/ { c=$NF; sub(/%/,"",c) }
    END {
      # e is H:MM:SS or M:SS.ss
      n=split(e,p,":"); s=0
      if(n==3) s=p[1]*3600+p[2]*60+p[3]
      else if(n==2) s=p[1]*60+p[2]
      else s=p[1]
      printf "%s %s %s", s, rss, c
    }' "$f"
}

# run_one METHOD LABEL  (METHOD in atpquic|rsync)
run_one() {
  local method="$1" label="$2"
  local src dst
  if [ "$label" = "tree" ]; then src="$WR/src/tree"; else src="$WR/src/file_$label.bin"; fi
  dst="$WR/dst_${method}_${label}_$$"
  rcv "mkdir -p $dst; find $dst -mindepth 1 -delete 2>/dev/null || true"
  local KEY; KEY="$(cat "$LOCAL/auth.key")"
  local tfile="$OUTDIR/time_${method}_${label}.txt"
  local jfile="$OUTDIR/send_${method}_${label}.json"

  case "$method" in
  atpquic|atprq)
    local transport ready_pat recvextra sendextra
    if [ "$method" = "atpquic" ]; then
      transport="quic"; ready_pat="quic listening"
      recvextra="--server-cert leaf.pem --server-key leaf.key"
      sendextra="--ca ca.pem --server-name $RECEIVER_IP"
    else
      transport="rq"; ready_pat="listening"; recvextra=""; sendextra="--streams ${STREAMS:-8}"
    fi
    # ensure a clean port (kill any straggler receiver from a prior failed run)
    rcv "pkill -f 'atp recv' 2>/dev/null; sleep 1" || true
    rcv "cd $WR; rm -f recv_${method}_${label}.log; \
         nohup ./atp recv $dst --listen 0.0.0.0:$PORT --transport $transport --once \
           $recvextra --rq-auth-key-hex $KEY --workers $WORKERS --max-bytes 2147483648 \
           > recv_${method}_${label}.log 2>&1 & echo \$!" \
      > "$OUTDIR/recvpid_${method}_${label}.txt"
    local ready=0
    for _ in $(seq 1 60); do
      if rcv "grep -qi '$ready_pat' $WR/recv_${method}_${label}.log 2>/dev/null"; then ready=1; break; fi
      sleep 0.5
    done
    [ "$ready" = 1 ] || { log "  $method receiver not ready"; rcv "cat $WR/recv_${method}_${label}.log" >&2 || true; return 1; }
    snd "cd $WR; /usr/bin/time -v ./atp send $src $RECEIVER_IP:$PORT --transport $transport \
           $sendextra --rq-auth-key-hex $KEY --workers $WORKERS --max-bytes 2147483648 \
           > send.json 2> time.txt; rc=\$?; cat send.json; echo \"SEND_RC=\$rc\"; echo '---TIME---'; cat time.txt" \
      > "$OUTDIR/raw_${method}_${label}.txt" 2>&1 || { log "  atp $transport send FAILED"; cat "$OUTDIR/raw_${method}_${label}.txt" >&2; rcv "cat $WR/recv_${method}_${label}.log" >&2 || true; return 1; }
    sed -n '1,/---TIME---/p' "$OUTDIR/raw_${method}_${label}.txt" | sed '/---TIME---/d' > "$jfile"
    sed -n '/---TIME---/,$p' "$OUTDIR/raw_${method}_${label}.txt" | sed '/---TIME---/d' > "$tfile"
    sleep 1
    ;;
  rsync)
    # rsync at its fastest: no delta algorithm, no compression (payloads are
    # random/incompressible), inplace writes, fast AEAD ssh cipher (still
    # encrypted, like atp's TLS). This is the toughest baseline for atp.
    # rsync runs ON the sender and connects sender->receiver over ssh, so it must
    # dial the receiver's real IP/user with a key present on the sender (the
    # local ssh alias does not exist there). RKEY = path to that key on the sender.
    snd "cd $WR; /usr/bin/time -v rsync -r --whole-file --inplace --no-compress \
           -e 'ssh -i ${RKEY:-/tmp/atp_bench/rkey} -c aes128-gcm@openssh.com -o Compression=no -o StrictHostKeyChecking=accept-new -o ConnectTimeout=20' \
           $src ${RECEIVER_USER:-root}@$RECEIVER_IP:$dst/ 2> time.txt; echo SEND_RC=\$?; cat time.txt" \
      > "$OUTDIR/raw_${method}_${label}.txt" 2>&1 || { log "  rsync ssh wrapper FAILED"; cat "$OUTDIR/raw_${method}_${label}.txt" >&2; return 1; }
    cp "$OUTDIR/raw_${method}_${label}.txt" "$tfile"
    ;;
  esac

  # verify sha256
  local ok="UNKNOWN"
  if [ "$label" = "tree" ]; then
    # receiver dst contains tree/...; compare set of hashes (basename-relative)
    local want got
    want="$(snd "cd $WR/src && find tree -type f | sort | xargs sha256sum | awk '{print \$1}' | sort")"
    got="$(rcv "cd $dst && find . -type f | sort | xargs sha256sum 2>/dev/null | awk '{print \$1}' | sort")"
    [ "$want" = "$got" ] && ok="OK" || ok="MISMATCH"
  else
    local want got
    want="$(snd "sha256sum $src | awk '{print \$1}'")"
    got="$(rcv "find $dst -type f -name '*.bin' | head -1 | xargs sha256sum 2>/dev/null | awk '{print \$1}'")"
    [ -n "$got" ] && [ "$want" = "$got" ] && ok="OK" || ok="MISMATCH"
  fi

  read -r wall rss cpu <<<"$(parse_time "$tfile")"
  printf '{"method":"%s","label":"%s","wall_s":%s,"max_rss_kb":%s,"cpu_pct":%s,"sha256":"%s"}\n' \
    "$method" "$label" "${wall:-null}" "${rss:-null}" "${cpu:-null}" "$ok" \
    | tee -a "$OUTDIR/results.jsonl"
  log "  $method $label: wall=${wall}s rss=${rss}KB cpu=${cpu}% sha=$ok"
  rcv "find $dst -mindepth 1 -delete 2>/dev/null; rmdir $dst 2>/dev/null || true"
}

run() {
  : > "$OUTDIR/results.jsonl"
  local labels=""
  for pair in $SIZES; do labels="$labels ${pair%%:*}"; done
  labels="$labels tree"
  for label in $labels; do
    for method in ${METHODS:-rsync atprq}; do
      log "RUN $method $label"
      run_one "$method" "$label" || log "  (continuing after failure)"
    done
  done
}

report() {
  log "report -> $OUTDIR/report.md"
  {
    echo "# ATP (QUIC+RaptorQ) vs tuned rsync"
    echo
    echo "Sender: \`$SENDER\`  Receiver: \`$RECEIVER\` ($RECEIVER_IP)  Port: $PORT  Workers: $WORKERS"
    echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo
    echo "| payload | method | wall (s) | peak RSS (MB) | CPU% | sha256 |"
    echo "|---|---|--:|--:|--:|:--:|"
    if command -v jq >/dev/null 2>&1; then
      jq -r '"| \(.label) | \(.method) | \(.wall_s) | \(.max_rss_kb/1024|floor) | \(.cpu_pct) | \(.sha256) |"' "$OUTDIR/results.jsonl"
    else
      cat "$OUTDIR/results.jsonl"
    fi
  } > "$OUTDIR/report.md"
  cat "$OUTDIR/report.md" >&2
}

case "${1:-all}" in
  deploy) deploy ;;
  certs) certs ;;
  payloads) gen_payloads ;;
  run) run ;;
  one) run_one "${2:?method}" "${3:?label}" ;;
  report) report ;;
  all) deploy; certs; gen_payloads; run; report ;;
  *) echo "stages: deploy|certs|payloads|run|report|all" >&2; exit 1 ;;
esac
