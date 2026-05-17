#!/usr/bin/env bash
# Deterministic Kafka broker parity proof runner.
#
# Usage:
#   bash scripts/kafka_broker_parity_proof_runner.sh [output-dir]
#
# Default output:
#   target/kafka-broker-parity-proof/$ASUPERSYNC_KAFKA_BROKER_PARITY_BEAD_ID/{run.log,scenario_rows.jsonl,run_report.json}

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BEAD_ID="${ASUPERSYNC_KAFKA_BROKER_PARITY_BEAD_ID:-asupersync-0xbecl}"
OUT_DIR="${1:-$PROJECT_DIR/target/kafka-broker-parity-proof/$BEAD_ID}"
LOG_FILE="$OUT_DIR/run.log"
ROWS_FILE="$OUT_DIR/scenario_rows.jsonl"
REPORT_FILE="$OUT_DIR/run_report.json"
RCH_BIN="${RCH_BIN:-rch}"
CARGO_BIN="${CARGO_BIN:-cargo}"

INCLUDE_OFFSET_ACK_PROOF=false
case "${ASUPERSYNC_KAFKA_BROKER_PARITY_INCLUDE_OFFSET_ACK_PROOF:-}" in
  1 | true | TRUE | yes | YES | on | ON)
    INCLUDE_OFFSET_ACK_PROOF=true
    ;;
esac
if [ "$BEAD_ID" = "asupersync-0xbecl.2" ]; then
  INCLUDE_OFFSET_ACK_PROOF=true
fi
INCLUDE_RESILIENCE_PROOF=false
case "${ASUPERSYNC_KAFKA_BROKER_PARITY_INCLUDE_RESILIENCE_PROOF:-}" in
  1 | true | TRUE | yes | YES | on | ON)
    INCLUDE_RESILIENCE_PROOF=true
    ;;
esac
if [ "$BEAD_ID" = "asupersync-0xbecl.3" ]; then
  INCLUDE_RESILIENCE_PROOF=true
fi

EXPECTED_SCENARIOS=(
  "kafka-default-feature-gate"
  "kafka-producer-consumer-roundtrip"
)
if [ "$INCLUDE_OFFSET_ACK_PROOF" = true ]; then
  EXPECTED_SCENARIOS+=("kafka-producer-consumer-offset-ack-redaction")
fi
if [ "$INCLUDE_RESILIENCE_PROOF" = true ]; then
  EXPECTED_SCENARIOS+=("kafka-reconnect-cancellation-error-taxonomy")
fi

REQUIRED_FIELDS=(
  "bead_id"
  "broker_kind"
  "broker_version"
  "scenario_id"
  "feature_flags"
  "connection_uri_redacted"
  "auth_mode"
  "topic_or_stream"
  "message_count"
  "ack_count"
  "consumer_lag"
  "partition"
  "offset"
  "delivery_status"
  "payload_sha256"
  "expected_ordering_scope"
  "reconnect_count"
  "cancellation_point"
  "expected_result"
  "actual_result"
  "artifact_path"
  "unsupported_reason"
  "verdict"
  "first_failure"
)

mkdir -p "$OUT_DIR"
: > "$LOG_FILE"
: > "$ROWS_FILE"

cd "$PROJECT_DIR"

log() {
  printf '%s\n' "$*" | tee -a "$LOG_FILE"
}

reject_rch_local_fallback_file() {
  local lane_name="$1"
  local log_path="$2"

  if grep -Eq '^\[RCH\] local \(|falling back to local' "$log_path" 2>/dev/null; then
    log "lane=$lane_name rch_local_fallback=true"
    echo "rch local fallback detected in $lane_name; refusing local cargo execution" > "$OUT_DIR/rch_local_fallback.txt"
    exit 86
  fi
}

run_lane() {
  local lane_name="$1"
  shift
  local lane_log="$OUT_DIR/${lane_name}.log"
  local lane_timeout="${RCH_LANE_TIMEOUT_SECS:-900}"

  log "lane=$lane_name"
  log "command=$(printf '%q ' "$@")"
  set +e
  : > "$lane_log"
  timeout "$lane_timeout" "$@" > "$lane_log" 2>&1 &
  local lane_pid="$!"
  while kill -0 "$lane_pid" 2>/dev/null; do
    if grep -q 'Remote command finished: exit=0' "$lane_log"; then
      sleep 1
      kill "$lane_pid" 2>/dev/null || true
      break
    fi
    sleep 1
  done
  wait "$lane_pid"
  local status="$?"
  set -e
  tee -a "$LOG_FILE" < "$lane_log"
  reject_rch_local_fallback_file "$lane_name" "$lane_log"
  if [ "$status" -ne 0 ] \
    && grep -q 'Remote command finished: exit=0' "$lane_log"; then
    log "lane=$lane_name remote_exit=0 local_status=$status artifact_retrieval_timeout=true"
    status=0
  fi
  log "lane=$lane_name status=$status"
  return "$status"
}

RUN_STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
GIT_SHA="$(git rev-parse --short HEAD 2>/dev/null || printf 'unknown')"
DEFAULT_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_asupersync_kafka_broker_parity_default"
KAFKA_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_asupersync_kafka_broker_parity_kafka"
OFFSET_ACK_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_asupersync_kafka_broker_parity_offset_ack"
RESILIENCE_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_asupersync_kafka_broker_parity_resilience"

if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
  echo "FATAL: rch is required and was not found/executable at: ${RCH_BIN}" >&2
  exit 1
fi

DEFAULT_CMD=(
  env
  RCH_FORCE_REMOTE=1
  RCH_QUEUE_WHEN_BUSY=1
  RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900
  RCH_DAEMON_RESPONSE_TIMEOUT_SECS=900
  "$RCH_BIN" exec --
  env
  "CARGO_TARGET_DIR=$DEFAULT_TARGET_DIR"
  CARGO_INCREMENTAL=0
  CARGO_PROFILE_TEST_DEBUG=0
  "RUSTFLAGS=-C debuginfo=0"
  "ASUPERSYNC_KAFKA_BROKER_PARITY_PROOF_DIR=$OUT_DIR"
  "ASUPERSYNC_KAFKA_BROKER_PARITY_BEAD_ID=$BEAD_ID"
  "$CARGO_BIN" test -p asupersync
  --test kafka_real_broker
  --features test-internals
  kafka_broker_parity_default_feature_gate_logs_required_fields
  --
  --nocapture
  --test-threads=1
)

KAFKA_CMD=(
  env
  RCH_FORCE_REMOTE=1
  RCH_QUEUE_WHEN_BUSY=1
  RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900
  RCH_DAEMON_RESPONSE_TIMEOUT_SECS=900
  "$RCH_BIN" exec --
  env
  "CARGO_TARGET_DIR=$KAFKA_TARGET_DIR"
  CARGO_INCREMENTAL=0
  CARGO_PROFILE_TEST_DEBUG=0
  "RUSTFLAGS=-C debuginfo=0"
  "ASUPERSYNC_KAFKA_BROKER_PARITY_PROOF_DIR=$OUT_DIR"
  "ASUPERSYNC_KAFKA_BROKER_PARITY_BEAD_ID=$BEAD_ID"
  "$CARGO_BIN" test -p asupersync
  --test kafka_real_broker
  --features "test-internals,kafka"
  kafka_broker_parity_real_broker_proof_row
  --
  --nocapture
  --test-threads=1
)

OFFSET_ACK_CMD=(
  env
  RCH_FORCE_REMOTE=1
  RCH_QUEUE_WHEN_BUSY=1
  RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900
  RCH_DAEMON_RESPONSE_TIMEOUT_SECS=900
  "$RCH_BIN" exec --
  env
  "CARGO_TARGET_DIR=$OFFSET_ACK_TARGET_DIR"
  CARGO_INCREMENTAL=0
  CARGO_PROFILE_TEST_DEBUG=0
  "RUSTFLAGS=-C debuginfo=0"
  "ASUPERSYNC_KAFKA_BROKER_PARITY_PROOF_DIR=$OUT_DIR"
  "ASUPERSYNC_KAFKA_BROKER_PARITY_BEAD_ID=$BEAD_ID"
  "$CARGO_BIN" test -p asupersync
  --test kafka_real_broker
  --features "test-internals,kafka"
  kafka_broker_parity_offset_ack_redaction_row
  --
  --nocapture
  --test-threads=1
)

RESILIENCE_CMD=(
  env
  RCH_FORCE_REMOTE=1
  RCH_QUEUE_WHEN_BUSY=1
  RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900
  RCH_DAEMON_RESPONSE_TIMEOUT_SECS=900
  "$RCH_BIN" exec --
  env
  "CARGO_TARGET_DIR=$RESILIENCE_TARGET_DIR"
  CARGO_INCREMENTAL=0
  CARGO_PROFILE_TEST_DEBUG=0
  "RUSTFLAGS=-C debuginfo=0"
  "ASUPERSYNC_KAFKA_BROKER_PARITY_PROOF_DIR=$OUT_DIR"
  "ASUPERSYNC_KAFKA_BROKER_PARITY_BEAD_ID=$BEAD_ID"
  "$CARGO_BIN" test -p asupersync
  --test kafka_real_broker
  --features "test-internals,kafka"
  kafka_broker_parity_resilience_taxonomy_row
  --
  --nocapture
  --test-threads=1
)

log "bead_id=$BEAD_ID"
log "output_dir=$OUT_DIR"
log "git_sha=$GIT_SHA"
log "rch_bin=$RCH_BIN"
log "cargo_bin=$CARGO_BIN"
log "default_target_dir=$DEFAULT_TARGET_DIR"
log "kafka_target_dir=$KAFKA_TARGET_DIR"
log "offset_ack_target_dir=$OFFSET_ACK_TARGET_DIR"
log "resilience_target_dir=$RESILIENCE_TARGET_DIR"
log "include_offset_ack_proof=$INCLUDE_OFFSET_ACK_PROOF"
log "include_resilience_proof=$INCLUDE_RESILIENCE_PROOF"

TEST_STATUS=0
run_lane default-feature-gate "${DEFAULT_CMD[@]}" || TEST_STATUS=1
run_lane kafka-broker-proof "${KAFKA_CMD[@]}" || TEST_STATUS=1
if [ "$INCLUDE_OFFSET_ACK_PROOF" = true ]; then
  run_lane kafka-offset-ack-redaction-proof "${OFFSET_ACK_CMD[@]}" || TEST_STATUS=1
fi
if [ "$INCLUDE_RESILIENCE_PROOF" = true ]; then
  run_lane kafka-resilience-proof "${RESILIENCE_CMD[@]}" || TEST_STATUS=1
fi

jq -Rr --arg bead_id "$BEAD_ID" '
  def event_object:
    . as $line
    | (try ($line | fromjson) catch null) as $direct
    | if $direct != null then
        $direct
      else
        (try ($line | capture("(?<json>\\{.*\\})").json | fromjson) catch empty)
      end;
  event_object
  | objects
  | select(.bead_id? == $bead_id)
  | @json
' "$LOG_FILE" > "$ROWS_FILE" || true

MISSING_SCENARIOS=()
for scenario in "${EXPECTED_SCENARIOS[@]}"; do
  if ! jq -e --arg scenario "$scenario" \
    'select(.scenario_id == $scenario)' "$ROWS_FILE" >/dev/null 2>&1; then
    MISSING_SCENARIOS+=("$scenario")
  fi
done

EXPECTED_JSON="$(printf '%s\n' "${EXPECTED_SCENARIOS[@]}" | jq -R . | jq -s .)"
REQUIRED_FIELDS_JSON="$(printf '%s\n' "${REQUIRED_FIELDS[@]}" | jq -R . | jq -s .)"
if [ "${#MISSING_SCENARIOS[@]}" -eq 0 ]; then
  MISSING_JSON="[]"
else
  MISSING_JSON="$(printf '%s\n' "${MISSING_SCENARIOS[@]}" | jq -R . | jq -s .)"
fi
if [ -s "$ROWS_FILE" ]; then
  ROWS_JSON="$(jq -s . "$ROWS_FILE")"
  DRIFTS_JSON="$(jq -s '[.[] | select(.verdict == "fail")]' "$ROWS_FILE")"
  SKIPS_JSON="$(jq -s '[.[] | select(.verdict == "skip")]' "$ROWS_FILE")"
  MISSING_FIELDS_JSON="$(jq -s --argjson required_fields "$REQUIRED_FIELDS_JSON" '
    [
      .[] as $row
      | $required_fields[] as $field
      | select(($row | has($field)) | not)
      | "\($row.scenario_id // "<unknown>"):\($field)"
    ]
  ' "$ROWS_FILE")"
  INVALID_OFFSET_ACK_ROWS_JSON="$(jq -s '
    [
      .[]
      | select(.scenario_id == "kafka-producer-consumer-offset-ack-redaction")
      | select(
          (
            .verdict == "pass"
            and (
              (.partition | type) != "number"
              or (.offset | type) != "number"
              or .delivery_status != "offset-committed"
              or ((.payload_sha256 | type) != "string")
              or ((.payload_sha256 | test("^[0-9a-f]{64}$")) | not)
              or ((.expected_ordering_scope | type) != "string")
              or .expected_ordering_scope == ""
            )
          )
          or (
            .verdict == "skip"
            and (
              (.unsupported_reason | type) != "string"
              or .unsupported_reason == ""
              or .delivery_status != "not-attempted"
              or .payload_sha256 != ""
            )
          )
          or (.verdict != "pass" and .verdict != "skip")
        )
    ]
  ' "$ROWS_FILE")"
  INVALID_RESILIENCE_ROWS_JSON="$(jq -s '
    [
      .[]
      | select(.scenario_id == "kafka-reconnect-cancellation-error-taxonomy")
      | select(
          (
            .verdict == "pass"
            and (
              .delivery_status != "recovered-after-unavailable-bootstrap-and-cancelled-send-poll"
              or .cancellation_point != "unavailable-bootstrap-send-before-commit-and-consumer-poll"
              or (.reconnect_count | type) != "number"
              or .reconnect_count < 1
              or .message_count < 1
              or .ack_count < 1
              or .consumer_lag != 0
              or .unsupported_reason != ""
              or .first_failure != ""
            )
          )
          or (
            .verdict == "skip"
            and (
              .delivery_status != "cancelled-before-send-commit-and-poll"
              or .cancellation_point != "unavailable-bootstrap-send-before-commit-and-consumer-poll"
              or (.reconnect_count | type) != "number"
              or .reconnect_count != 0
              or .message_count != 0
              or .ack_count != 0
              or .consumer_lag != 0
              or (.unsupported_reason | type) != "string"
              or .unsupported_reason == ""
              or .first_failure != ""
            )
          )
          or (.verdict != "pass" and .verdict != "skip")
        )
    ]
  ' "$ROWS_FILE")"
else
  ROWS_JSON="[]"
  DRIFTS_JSON="[]"
  SKIPS_JSON="[]"
  MISSING_FIELDS_JSON="[]"
  INVALID_OFFSET_ACK_ROWS_JSON="[]"
  INVALID_RESILIENCE_ROWS_JSON="[]"
fi

ROW_COUNT="$(wc -l < "$ROWS_FILE" | tr -d ' ')"
VALIDATION_PASSED=false
if [ "$TEST_STATUS" -eq 0 ] \
  && [ "${#MISSING_SCENARIOS[@]}" -eq 0 ] \
  && [ "$(jq 'length' <<<"$DRIFTS_JSON")" -eq 0 ] \
  && [ "$(jq 'length' <<<"$MISSING_FIELDS_JSON")" -eq 0 ] \
  && [ "$(jq 'length' <<<"$INVALID_OFFSET_ACK_ROWS_JSON")" -eq 0 ] \
  && [ "$(jq 'length' <<<"$INVALID_RESILIENCE_ROWS_JSON")" -eq 0 ] \
  && [ "$ROW_COUNT" -eq "${#EXPECTED_SCENARIOS[@]}" ]; then
  VALIDATION_PASSED=true
fi

RUN_FINISHED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

jq -n \
  --arg bead_id "$BEAD_ID" \
  --arg run_started_at "$RUN_STARTED_AT" \
  --arg run_finished_at "$RUN_FINISHED_AT" \
  --arg git_sha "$GIT_SHA" \
  --arg output_dir "$OUT_DIR" \
  --arg log_path "$LOG_FILE" \
  --arg rows_path "$ROWS_FILE" \
  --argjson test_status "$TEST_STATUS" \
  --argjson row_count "$ROW_COUNT" \
  --argjson expected_scenarios "$EXPECTED_JSON" \
  --argjson required_fields "$REQUIRED_FIELDS_JSON" \
  --argjson missing_scenarios "$MISSING_JSON" \
  --argjson missing_fields "$MISSING_FIELDS_JSON" \
  --argjson invalid_offset_ack_rows "$INVALID_OFFSET_ACK_ROWS_JSON" \
  --argjson invalid_resilience_rows "$INVALID_RESILIENCE_ROWS_JSON" \
  --argjson rows "$ROWS_JSON" \
  --argjson drifts "$DRIFTS_JSON" \
  --argjson skips "$SKIPS_JSON" \
  --argjson validation_passed "$VALIDATION_PASSED" \
  '{
    bead_id: $bead_id,
    run_started_at: $run_started_at,
    run_finished_at: $run_finished_at,
    git_sha: $git_sha,
    output_dir: $output_dir,
    run_log: $log_path,
    scenario_rows: $rows_path,
    test_status: $test_status,
    row_count: $row_count,
    validation_passed: $validation_passed,
    expected_scenarios: $expected_scenarios,
    required_fields: $required_fields,
    missing_scenarios: $missing_scenarios,
    missing_fields: $missing_fields,
    invalid_offset_ack_rows: $invalid_offset_ack_rows,
    invalid_resilience_rows: $invalid_resilience_rows,
    drifts: $drifts,
    skips: $skips,
    rows: $rows
  }' > "$REPORT_FILE"

log "run_report=$REPORT_FILE"
log "validation_passed=$VALIDATION_PASSED"

if [ "$VALIDATION_PASSED" != true ]; then
  exit 1
fi
