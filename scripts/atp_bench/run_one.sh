#!/usr/bin/env bash
# Run ONE sender-side transfer command under /usr/bin/time -v (+ perf stat if
# available), emitting a single JSON result line on stdout
# (br-asupersync-iiz6jk).
#
# Usage: run_one.sh <label> <payload_bytes> -- <command...>
set -euo pipefail

LABEL="$1"; BYTES="$2"; shift 2
[[ "$1" == "--" ]] && shift

TMP_ROOT="${ATP_BENCH_TMPDIR:-/tmp}"
TMP=$(mktemp -d "$TMP_ROOT/atp_bench_one.XXXXXX")
TIME_OUT="$TMP/time.txt"
PERF_OUT="$TMP/perf.txt"

# mpstat per-core sampling for the duration of the run (1s interval).
MPSTAT_PID=0
if command -v mpstat >/dev/null 2>&1; then
    LC_ALL=C mpstat -P ALL 1 </dev/null > "$TMP/mpstat.txt" 2>/dev/null &
    MPSTAT_PID=$!
fi

START_LOAD=$(cut -d' ' -f1 /proc/loadavg)
STATUS=0
if command -v perf >/dev/null 2>&1 \
   && perf stat -e task-clock true </dev/null >/dev/null 2>&1; then
    /usr/bin/time -v -o "$TIME_OUT" \
        perf stat -x, -e task-clock,cycles,instructions -o "$PERF_OUT" \
        "$@" >/dev/null 2>"$TMP/cmd.stderr" || STATUS=$?
else
    /usr/bin/time -v -o "$TIME_OUT" "$@" >/dev/null 2>"$TMP/cmd.stderr" || STATUS=$?
fi
END_LOAD=$(cut -d' ' -f1 /proc/loadavg)

if [[ $MPSTAT_PID -ne 0 ]]; then kill "$MPSTAT_PID" 2>/dev/null || true; wait "$MPSTAT_PID" 2>/dev/null || true; fi

wall_s=$(awk -F': ' '/Elapsed \(wall clock\)/ {print $2}' "$TIME_OUT" | awk -F: '
    NF==3 {print $1*3600 + $2*60 + $3}
    NF==2 {print $1*60 + $2}
    NF==1 {print $1}')
max_rss_kb=$(awk -F': ' '/Maximum resident set size/ {print $2}' "$TIME_OUT")
user_s=$(awk -F': ' '/User time \(seconds\)/ {print $2}' "$TIME_OUT")
sys_s=$(awk -F': ' '/System time \(seconds\)/ {print $2}' "$TIME_OUT")

cycles=null; instructions=null; task_clock_ms=null
if [[ -s "$PERF_OUT" ]]; then
    c=$(awk -F, '$3=="cycles" {print $1}' "$PERF_OUT" | tr -d ' ')
    i=$(awk -F, '$3=="instructions" {print $1}' "$PERF_OUT" | tr -d ' ')
    t=$(awk -F, '$3=="task-clock" {print $1}' "$PERF_OUT" | tr -d ' ')
    [[ "$c" =~ ^[0-9]+$ ]] && cycles=$c
    [[ "$i" =~ ^[0-9]+$ ]] && instructions=$i
    [[ "$t" =~ ^[0-9.]+$ ]] && task_clock_ms=$t
fi

# Average non-idle CPU across all cores while the run was active.
cores=$(nproc)
avg_core_util=null
if [[ -s "$TMP/mpstat.txt" ]]; then
    avg_core_util=$(awk '/all/ && $NF ~ /^[0-9.]+$/ {idle+=$NF; n++} END {if (n>0) printf "%.1f", 100-idle/n; else print "null"}' "$TMP/mpstat.txt")
fi

cmd_stderr=$(head -c 500 "$TMP/cmd.stderr" | tr '\n' ' ' | tr '"' "'")

cat <<EOF
{"label":"$LABEL","bytes":$BYTES,"status":$STATUS,"wall_s":${wall_s:-null},"user_s":${user_s:-null},"sys_s":${sys_s:-null},"max_rss_kb":${max_rss_kb:-null},"cycles":$cycles,"instructions":$instructions,"task_clock_ms":$task_clock_ms,"cores":$cores,"avg_core_util_pct":$avg_core_util,"load1_start":$START_LOAD,"load1_end":$END_LOAD,"tmp_dir":"$TMP","stderr_head":"$cmd_stderr"}
EOF
