#!/usr/bin/env bash
# Background process metrics collector (br-asupersync-iiz6jk).
# Samples RSS/%CPU for processes matching a pattern plus system loadavg every
# 0.5s, writing JSONL until killed. Used on both sender and receiver.
#
# Usage: collect_metrics.sh <pgrep-pattern> <out.jsonl>
set -u

PATTERN="$1"
OUT="$2"
: > "$OUT"

while true; do
    ts=$(date +%s.%N)
    load=$(cut -d' ' -f1 /proc/loadavg)
    line=$(pgrep -f "$PATTERN" 2>/dev/null | head -20 | xargs -r ps -o rss=,pcpu= -p 2>/dev/null |
        awk '{rss+=$1; cpu+=$2} END {printf "%d %.1f", rss, cpu}')
    rss=${line%% *}
    cpu=${line##* }
    [[ -z "$rss" ]] && rss=0
    [[ -z "$cpu" ]] && cpu=0
    echo "{\"ts\":$ts,\"rss_kb\":${rss:-0},\"cpu_pct\":${cpu:-0},\"load1\":$load}" >> "$OUT"
    sleep 0.5
done
