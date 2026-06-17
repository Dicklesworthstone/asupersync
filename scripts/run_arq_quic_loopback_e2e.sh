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
      .transport_counters.symbols_sent_available == true and
      (.transport_counters.symbols_sent | type == "number" and . >= 0) and
      .transport_counters.symbols_accepted_available == true and
      (.transport_counters.symbols_accepted | type == "number" and . >= 0) and
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
SENDER_JSON="$OUTPUT_DIR/sender.json"
SENDER_STDERR="$OUTPUT_DIR/sender.stderr"
SENDER_TIME="$OUTPUT_DIR/sender.time.txt"

"$ATP_BIN" recv "$OUTPUT_DIR/dest" \
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

MAX_RSS_KB="$(
    awk -F: '/Maximum resident set size/ { gsub(/^[ \t]+/, "", $2); print $2 }' "$SENDER_TIME" \
        | tail -n1
)"
MAX_RSS_KB="${MAX_RSS_KB:-0}"
ELAPSED_RAW="$(
    sed -n 's/^[[:space:]]*Elapsed (wall clock) time (h:mm:ss or m:ss):[[:space:]]*//p' "$SENDER_TIME" \
        | tail -n1
)"

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
    --arg elapsed_raw "$ELAPSED_RAW" \
    --argjson sender_max_rss_kb "$MAX_RSS_KB" \
    '{
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
      metrics: {sender_max_rss_kb: $sender_max_rss_kb, sender_elapsed_raw: $elapsed_raw},
      transport_counters: {
        source: "atp-cli-json",
        symbols_sent: ($sender[0].symbols_sent // null),
        symbols_accepted: ($receiver[0].symbols_accepted // null),
        feedback_rounds_sender: ($sender[0].feedback_rounds // null),
        feedback_rounds_receiver: ($receiver[0].feedback_rounds // null),
        decode_count: ($receiver[0].decode_count // null),
        decode_micros: ($receiver[0].decode_micros // null),
        symbols_sent_available: (($sender[0].symbols_sent // null | type) == "number"),
        symbols_accepted_available: (($receiver[0].symbols_accepted // null | type) == "number"),
        feedback_rounds_available: ((($sender[0].feedback_rounds // null | type) == "number") and (($receiver[0].feedback_rounds // null | type) == "number")),
        decode_count_available: (($receiver[0].decode_count // null | type) == "number"),
        decode_micros_available: (($receiver[0].decode_micros // null | type) == "number"),
        no_claim: "Loopback summary exposes receiver decode block count and decode completion time from atp CLI JSON. H2 still does not claim goodput, loss, fanout, RSS provider metrics, off-overhead, or fleet proof."
      },
      artifacts: {
        events_ndjson: $events,
        sender_json: $sender_json,
        receiver_json: $receiver_json,
        sender_stderr: $sender_stderr,
        receiver_stderr: $receiver_stderr,
        sender_time: $sender_time
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
