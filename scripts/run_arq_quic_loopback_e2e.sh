#!/usr/bin/env bash
# Run a retained, self-validating ARQ/QUIC loopback E2E artifact pack.
#
# Normal mode builds or uses the standalone `atp` binary, runs a real
# `atp recv --transport quic --once` plus `atp send --transport quic` over
# loopback UDP, and writes:
#   - events.ndjson: ordered script-stage events
#   - summary.json: machine-readable transfer summary
#   - sender.json / receiver.json: raw atp JSON reports
#   - sender.time.txt: /usr/bin/time -v sender metrics
#   - receiver.time.txt: /usr/bin/time -v receiver metrics
#
# Offline mode (`--from-output DIR`) validates a retained output directory
# without rerunning the transfer. This is the negative-test hook for corrupted
# artifacts.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUTPUT_DIR="${ARQ_QUIC_OUTPUT_DIR:-$PROJECT_ROOT/artifacts/arq_quic_e2e/$TIMESTAMP}"
ATP_BIN="${ATP_BIN:-}"
AUTH_KEY_HEX="${ARQ_QUIC_AUTH_KEY_HEX:-000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f}"
PAYLOAD_BYTES="${ARQ_QUIC_PAYLOAD_BYTES:-8192}"
SERVER_NAME="${ARQ_QUIC_SERVER_NAME:-localhost}"
FROM_OUTPUT=""

usage() {
    cat >&2 <<USAGE
Usage:
  $0 [--output-dir DIR]
  $0 --from-output DIR

Environment:
  ATP_BIN                  Existing atp binary. If unset, cargo builds one.
  CARGO_TARGET_DIR         Target dir for the optional cargo build.
  ARQ_QUIC_OUTPUT_DIR      Artifact output dir (default artifacts/arq_quic_e2e/<UTC timestamp>).
  ARQ_QUIC_PAYLOAD_BYTES   Deterministic payload size (default 8192).
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-dir)
            OUTPUT_DIR="${2:?--output-dir requires a path}"
            shift 2
            ;;
        --from-output)
            FROM_OUTPUT="${2:?--from-output requires a path}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage
            exit 2
            ;;
    esac
done

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "missing required command: $1" >&2
        exit 127
    }
}

require_cmd jq
require_cmd python3
require_cmd openssl
require_cmd sha256sum
require_cmd awk
require_cmd grep
require_cmd sed

emit_event() {
    local stage="$1"
    local status="$2"
    local message="$3"
    local details="${4:-{}}"
    mkdir -p "$OUTPUT_DIR"
    jq -cn \
        --arg schema_version "arq-quic-e2e-event-v1" \
        --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --arg stage "$stage" \
        --arg status "$status" \
        --arg message "$message" \
        --arg details "$details" \
        '($details | fromjson? // {}) as $details_obj |
        {
          schema_version:$schema_version,
          ts:$ts,
          stage:$stage,
          status:$status,
          message:$message
        } + (if $details_obj == {} then {} else {details:$details_obj} end)' \
        >> "$OUTPUT_DIR/events.ndjson"
}

emit_summary_event() {
    mkdir -p "$OUTPUT_DIR"
    jq -c \
        --arg schema_version "arq-quic-e2e-event-v1" \
        --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        '{
          schema_version:$schema_version,
          ts:$ts,
          stage:"summary",
          status:"passed",
          message:"captured final transfer metrics and counter availability",
          details:{
            bytes_sent:.bytes_sent,
            bytes_received:.bytes_received,
            sha256_match:.sha256_match,
            metrics:.metrics,
            transport_counters:.transport_counters
          }
        }' "$OUTPUT_DIR/summary.json" \
        >> "$OUTPUT_DIR/events.ndjson"
}

extract_max_rss_kb() {
    local time_file="$1"
    local value
    value="$(
        awk -F: '/Maximum resident set size/ { gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2 }' "$time_file" \
            | tail -n1
    )"
    if [[ "$value" =~ ^[0-9]+$ ]]; then
        printf '%s\n' "$value"
    else
        printf '0\n'
    fi
}

extract_elapsed_raw() {
    local time_file="$1"
    sed -n 's/^[[:space:]]*Elapsed (wall clock) time (h:mm:ss or m:ss):[[:space:]]*//p' "$time_file" \
        | tail -n1
}

elapsed_to_seconds() {
    local raw="$1"
    python3 - "$raw" <<'PY'
import sys

raw = sys.argv[1].strip()
if not raw:
    print("0")
    raise SystemExit

parts = raw.split(":")
try:
    if len(parts) == 3:
        seconds = int(parts[0]) * 3600 + int(parts[1]) * 60 + float(parts[2])
    elif len(parts) == 2:
        seconds = int(parts[0]) * 60 + float(parts[1])
    else:
        seconds = float(parts[0])
except ValueError:
    seconds = 0.0

if seconds < 0:
    seconds = 0.0
print(f"{seconds:.6f}")
PY
}

validate_output() {
    local dir="$1"
    local summary="$dir/summary.json"
    local events="$dir/events.ndjson"

    [[ -s "$summary" ]] || { echo "missing summary.json in $dir" >&2; return 1; }
    [[ -s "$events" ]] || { echo "missing events.ndjson in $dir" >&2; return 1; }

    jq -e '
      .schema_version == "arq-quic-loopback-e2e-summary-v1" and
      .status == "passed" and
      .transport == "quic" and
      .sha256_match == true and
      (.bytes_sent | type == "number") and
      (.bytes_received | type == "number") and
      .bytes_sent == .bytes_received and
      .bytes_sent > 0 and
      .sender.event == "atp_send" and
      .sender.transport == "quic" and
      .sender.committed == true and
      .receiver.event == "atp_receive" and
      .receiver.transport == "quic" and
      .receiver.committed == true and
      (.metrics.sender_max_rss_kb | type == "number") and
      (.metrics.receiver_max_rss_kb | type == "number") and
      (.metrics.peak_max_rss_kb | type == "number") and
      .metrics.peak_max_rss_kb >= .metrics.sender_max_rss_kb and
      .metrics.peak_max_rss_kb >= .metrics.receiver_max_rss_kb and
      (.metrics.sender_elapsed_seconds | type == "number" and . >= 0) and
      (.metrics.receiver_elapsed_seconds | type == "number" and . >= 0) and
      (.metrics.transfer_elapsed_seconds | type == "number" and . >= 0) and
      (.metrics.goodput_bytes_per_second | type == "number" and . >= 0) and
      (.metrics.goodput_bits_per_second | type == "number" and . >= 0) and
      (.metrics.symbol_loss_rate | type == "number" and . >= 0 and . <= 1) and
      (.metrics.feedback_rounds_total | type == "number" and . >= 0) and
      (.metrics.decode_time_per_block_micros | type == "number" and . >= 0) and
      .transport_counters.symbols_sent_available == true and
      (.transport_counters.symbols_sent | type == "number" and . > 0) and
      .transport_counters.symbols_accepted_available == true and
      (.transport_counters.symbols_accepted | type == "number" and . > 0) and
      .transport_counters.feedback_rounds_available == true and
      (.transport_counters.feedback_rounds_sender | type == "number" and . >= 0) and
      (.transport_counters.feedback_rounds_receiver | type == "number" and . >= 0) and
      .transport_counters.decode_count_available == true and
      (.transport_counters.decode_count | type == "number" and . >= 0) and
      .transport_counters.decode_micros_available == true and
      (.transport_counters.decode_micros | type == "number" and . >= 0) and
      (.transport_counters.no_claim | type == "string") and
      (.artifacts.events_ndjson | type == "string")
    ' "$summary" >/dev/null

    jq -e -s '
      length >= 5 and
      all(.[]; .schema_version == "arq-quic-e2e-event-v1" and
        (.stage | type == "string" and length > 0) and
        (.status as $s | ["started","passed","failed"] | index($s) != null)) and
      any(.[]; .stage == "receiver_ready" and .status == "passed") and
      any(.[]; .stage == "sender_transfer" and .status == "passed") and
      any(.[]; .stage == "sha256_verify" and .status == "passed") and
      any(.[]; .stage == "summary" and .status == "passed" and (.details.transport_counters.no_claim | type == "string"))
    ' "$events" >/dev/null
}

if [[ -n "$FROM_OUTPUT" ]]; then
    validate_output "$FROM_OUTPUT"
    echo "validated ARQ/QUIC loopback output: $FROM_OUTPUT"
    exit 0
fi

mkdir -p "$OUTPUT_DIR/source" "$OUTPUT_DIR/dest" "$OUTPUT_DIR/tls"
: > "$OUTPUT_DIR/events.ndjson"
emit_event "setup" "started" "preparing retained loopback artifacts"

if [[ -z "$ATP_BIN" ]]; then
    emit_event "build_atp" "started" "building standalone atp binary with atp-cli,tls"
    CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PROJECT_ROOT/target}"
    export CARGO_TARGET_DIR
    (
        cd "$PROJECT_ROOT"
        cargo build -p asupersync --bin atp --features atp-cli,tls
    )
    ATP_BIN="$CARGO_TARGET_DIR/debug/atp"
fi
[[ -x "$ATP_BIN" ]] || { emit_event "build_atp" "failed" "atp binary missing or not executable"; echo "atp binary missing: $ATP_BIN" >&2; exit 1; }
emit_event "build_atp" "passed" "using atp binary $ATP_BIN"

"$SCRIPT_DIR/atp_bench_gen_certs.sh" "$OUTPUT_DIR/tls" 127.0.0.1 > "$OUTPUT_DIR/certs.log" 2>&1

PAYLOAD="$OUTPUT_DIR/source/payload.bin"
python3 - "$PAYLOAD" "$PAYLOAD_BYTES" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
size = int(sys.argv[2])
path.parent.mkdir(parents=True, exist_ok=True)
path.write_bytes(bytes((i * 17) % 251 for i in range(size)))
PY
emit_event "payload" "passed" "wrote deterministic payload"

RECEIVER_JSON="$OUTPUT_DIR/receiver.json"
RECEIVER_STDERR="$OUTPUT_DIR/receiver.stderr"
RECEIVER_TIME="$OUTPUT_DIR/receiver.time.txt"
SENDER_JSON="$OUTPUT_DIR/sender.json"
SENDER_STDERR="$OUTPUT_DIR/sender.stderr"
SENDER_TIME="$OUTPUT_DIR/sender.time.txt"

/usr/bin/time -v -o "$RECEIVER_TIME" "$ATP_BIN" recv "$OUTPUT_DIR/dest" \
    --listen 127.0.0.1:0 \
    --transport quic \
    --once \
    --server-cert "$OUTPUT_DIR/tls/leaf.pem" \
    --server-key "$OUTPUT_DIR/tls/leaf.key" \
    --rq-auth-key-hex "$AUTH_KEY_HEX" \
    > "$RECEIVER_JSON" 2> "$RECEIVER_STDERR" &
RECEIVER_PID=$!

LISTEN_ADDR=""
for _ in $(seq 1 100); do
    if ! kill -0 "$RECEIVER_PID" 2>/dev/null; then
        emit_event "receiver_ready" "failed" "receiver exited before readiness"
        cat "$RECEIVER_STDERR" >&2 || true
        exit 1
    fi
    if grep -q "atp: quic listening on " "$RECEIVER_STDERR" 2>/dev/null; then
        LISTEN_ADDR="$(
            sed -n 's/^atp: quic listening on \([^,]*\), dest .*/\1/p' "$RECEIVER_STDERR" \
                | tail -n1
        )"
        break
    fi
    sleep 0.1
done
[[ -n "$LISTEN_ADDR" ]] || { emit_event "receiver_ready" "failed" "receiver did not print readiness"; cat "$RECEIVER_STDERR" >&2 || true; exit 1; }
emit_event "receiver_ready" "passed" "receiver listening on $LISTEN_ADDR"

emit_event "sender_transfer" "started" "running atp send --transport quic"
if /usr/bin/time -v -o "$SENDER_TIME" "$ATP_BIN" send "$PAYLOAD" "$LISTEN_ADDR" \
    --transport quic \
    --ca "$OUTPUT_DIR/tls/ca.pem" \
    --server-name "$SERVER_NAME" \
    --rq-auth-key-hex "$AUTH_KEY_HEX" \
    > "$SENDER_JSON" 2> "$SENDER_STDERR"; then
    emit_event "sender_transfer" "passed" "sender completed"
else
    emit_event "sender_transfer" "failed" "sender failed"
    cat "$SENDER_STDERR" >&2 || true
    kill "$RECEIVER_PID" 2>/dev/null || true
    wait "$RECEIVER_PID" 2>/dev/null || true
    exit 1
fi

wait "$RECEIVER_PID"
emit_event "receiver_transfer" "passed" "receiver exited after one transfer"

SOURCE_SHA="$(sha256sum "$PAYLOAD" | awk '{print $1}')"
RECEIVED="$OUTPUT_DIR/dest/payload.bin"
[[ -f "$RECEIVED" ]] || { emit_event "sha256_verify" "failed" "received payload missing"; exit 1; }
RECEIVED_SHA="$(sha256sum "$RECEIVED" | awk '{print $1}')"
if [[ "$SOURCE_SHA" != "$RECEIVED_SHA" ]]; then
    emit_event "sha256_verify" "failed" "source and received sha256 differ"
    exit 1
fi
emit_event "sha256_verify" "passed" "source and received sha256 match" "$(jq -cn \
    --arg source_sha "$SOURCE_SHA" \
    --arg received_sha "$RECEIVED_SHA" \
    '{source_sha256:$source_sha,received_sha256:$received_sha,match:true}')"

SENDER_MAX_RSS_KB="$(extract_max_rss_kb "$SENDER_TIME")"
RECEIVER_MAX_RSS_KB="$(extract_max_rss_kb "$RECEIVER_TIME")"
if (( SENDER_MAX_RSS_KB >= RECEIVER_MAX_RSS_KB )); then
    PEAK_MAX_RSS_KB="$SENDER_MAX_RSS_KB"
else
    PEAK_MAX_RSS_KB="$RECEIVER_MAX_RSS_KB"
fi
SENDER_ELAPSED_RAW="$(extract_elapsed_raw "$SENDER_TIME")"
RECEIVER_ELAPSED_RAW="$(extract_elapsed_raw "$RECEIVER_TIME")"
SENDER_ELAPSED_SECONDS="$(elapsed_to_seconds "$SENDER_ELAPSED_RAW")"
RECEIVER_ELAPSED_SECONDS="$(elapsed_to_seconds "$RECEIVER_ELAPSED_RAW")"

jq -n \
    --slurpfile sender "$SENDER_JSON" \
    --slurpfile receiver "$RECEIVER_JSON" \
    --arg output_dir "$OUTPUT_DIR" \
    --arg payload "$PAYLOAD" \
    --arg received "$RECEIVED" \
    --arg source_sha "$SOURCE_SHA" \
    --arg received_sha "$RECEIVED_SHA" \
    --arg events "$OUTPUT_DIR/events.ndjson" \
    --arg sender_json "$SENDER_JSON" \
    --arg receiver_json "$RECEIVER_JSON" \
    --arg sender_stderr "$SENDER_STDERR" \
    --arg receiver_stderr "$RECEIVER_STDERR" \
    --arg sender_time "$SENDER_TIME" \
    --arg receiver_time "$RECEIVER_TIME" \
    --arg sender_elapsed_raw "$SENDER_ELAPSED_RAW" \
    --arg receiver_elapsed_raw "$RECEIVER_ELAPSED_RAW" \
    --argjson sender_elapsed_seconds "$SENDER_ELAPSED_SECONDS" \
    --argjson receiver_elapsed_seconds "$RECEIVER_ELAPSED_SECONDS" \
    --argjson sender_max_rss_kb "$SENDER_MAX_RSS_KB" \
    --argjson receiver_max_rss_kb "$RECEIVER_MAX_RSS_KB" \
    --argjson peak_max_rss_kb "$PEAK_MAX_RSS_KB" \
    '($sender[0].symbols_sent // null) as $symbols_sent |
    ($receiver[0].symbols_accepted // null) as $symbols_accepted |
    ($sender[0].feedback_rounds // null) as $feedback_rounds_sender |
    ($receiver[0].feedback_rounds // null) as $feedback_rounds_receiver |
    ($receiver[0].decode_count // null) as $decode_count |
    ($receiver[0].decode_micros // null) as $decode_micros |
    ($receiver[0].bytes_received // 0) as $bytes_received |
    (if $sender_elapsed_seconds > 0 then $sender_elapsed_seconds else $receiver_elapsed_seconds end) as $transfer_elapsed_seconds |
    {
      schema_version: "arq-quic-loopback-e2e-summary-v1",
      status: "passed",
      transport: "quic",
      output_dir: $output_dir,
      payload_path: $payload,
      received_path: $received,
      bytes_sent: ($sender[0].bytes_sent // 0),
      bytes_received: ($receiver[0].bytes_received // 0),
      sender: $sender[0],
      receiver: $receiver[0],
      sha256: {source: $source_sha, received: $received_sha, match: ($source_sha == $received_sha)},
      sha256_match: ($source_sha == $received_sha),
      metrics: {
        sender_max_rss_kb: $sender_max_rss_kb,
        receiver_max_rss_kb: $receiver_max_rss_kb,
        peak_max_rss_kb: $peak_max_rss_kb,
        sender_elapsed_raw: $sender_elapsed_raw,
        receiver_elapsed_raw: $receiver_elapsed_raw,
        sender_elapsed_seconds: $sender_elapsed_seconds,
        receiver_elapsed_seconds: $receiver_elapsed_seconds,
        transfer_elapsed_seconds: $transfer_elapsed_seconds,
        goodput_bytes_per_second: (if $transfer_elapsed_seconds > 0 then ($bytes_received / $transfer_elapsed_seconds) else 0 end),
        goodput_bits_per_second: (if $transfer_elapsed_seconds > 0 then (($bytes_received * 8) / $transfer_elapsed_seconds) else 0 end),
        symbol_loss_rate: (
          if (($symbols_sent | type) == "number" and $symbols_sent > 0 and (($symbols_accepted | type) == "number"))
          then (([($symbols_sent - $symbols_accepted), 0] | max) / $symbols_sent)
          else 0
          end
        ),
        feedback_rounds_total: (
          (if (($feedback_rounds_sender | type) == "number") then $feedback_rounds_sender else 0 end) +
          (if (($feedback_rounds_receiver | type) == "number") then $feedback_rounds_receiver else 0 end)
        ),
        decode_time_per_block_micros: (
          if (($decode_count | type) == "number" and $decode_count > 0 and (($decode_micros | type) == "number"))
          then ($decode_micros / $decode_count)
          else 0
          end
        )
      },
      transport_counters: {
        source: "atp-cli-json",
        symbols_sent: $symbols_sent,
        symbols_accepted: $symbols_accepted,
        feedback_rounds_sender: $feedback_rounds_sender,
        feedback_rounds_receiver: $feedback_rounds_receiver,
        decode_count: $decode_count,
        decode_micros: $decode_micros,
        symbols_sent_available: (($symbols_sent | type) == "number"),
        symbols_accepted_available: (($symbols_accepted | type) == "number"),
        feedback_rounds_available: ((($feedback_rounds_sender | type) == "number") and (($feedback_rounds_receiver | type) == "number")),
        decode_count_available: (($decode_count | type) == "number"),
        decode_micros_available: (($decode_micros | type) == "number"),
        no_claim: "Loopback summary derives goodput and symbol-loss headline metrics from retained time/CLI artifacts, and exposes sender/receiver peak RSS plus receiver decode block count/time. The loss rate is a loopback artifact metric, not a fleet/network-loss proof. H2 still does not claim metrics-provider emission, fanout/per-path stats, avg RSS, optional-metrics off-overhead, or fleet proof."
      },
      artifacts: {
        events_ndjson: $events,
        sender_json: $sender_json,
        receiver_json: $receiver_json,
        sender_stderr: $sender_stderr,
        receiver_stderr: $receiver_stderr,
        sender_time: $sender_time,
        receiver_time: $receiver_time
      }
    }' > "$OUTPUT_DIR/summary.json"

emit_summary_event
if ! VALIDATION_ERROR="$(validate_output "$OUTPUT_DIR" 2>&1)"; then
    emit_event "offline_validation" "failed" "summary and events failed validation" "$(
        jq -cn --arg error "$VALIDATION_ERROR" '{error:$error}'
    )"
    printf '%s\n' "$VALIDATION_ERROR" >&2
    exit 1
fi
emit_event "offline_validation" "passed" "summary and events validate"

echo "ARQ/QUIC loopback E2E artifacts: $OUTPUT_DIR"
