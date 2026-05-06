#!/usr/bin/env bash
# Deterministic Kafka broker parity proof runner.
#
# Usage:
#   bash scripts/kafka_broker_parity_proof_runner.sh [output-dir]
#
# Default output:
#   target/kafka-broker-parity-proof/asupersync-0xbecl/{run.log,scenario_rows.jsonl,run_report.json}

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="${1:-$PROJECT_DIR/target/kafka-broker-parity-proof/asupersync-0xbecl}"
LOG_FILE="$OUT_DIR/run.log"
ROWS_FILE="$OUT_DIR/scenario_rows.jsonl"
REPORT_FILE="$OUT_DIR/run_report.json"
BEAD_ID="asupersync-0xbecl"

EXPECTED_SCENARIOS=(
  "kafka-default-feature-gate"
  "kafka-producer-consumer-roundtrip"
)

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

run_lane() {
  local lane_name="$1"
  shift
  local lane_log="$OUT_DIR/${lane_name}.log"
  local lane_timeout="${RCH_LANE_TIMEOUT_SECS:-300}"

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
  cat "$lane_log" | tee -a "$LOG_FILE"
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

DEFAULT_CMD=(
  env
  -u
  CARGO_TARGET_DIR
  RCH_FORCE_REMOTE=1
  RCH_QUEUE_WHEN_BUSY=1
  RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900
  RCH_DAEMON_RESPONSE_TIMEOUT_SECS=900
  rch exec --
  env
  CARGO_INCREMENTAL=0
  CARGO_PROFILE_TEST_DEBUG=0
  "RUSTFLAGS=-C debuginfo=0"
  "ASUPERSYNC_KAFKA_BROKER_PARITY_PROOF_DIR=$OUT_DIR"
  cargo test -p asupersync
  --target-dir "$DEFAULT_TARGET_DIR"
  --test kafka_real_broker
  --features test-internals
  kafka_broker_parity_default_feature_gate_logs_required_fields
  --
  --nocapture
  --test-threads=1
)

KAFKA_CMD=(
  env
  -u
  CARGO_TARGET_DIR
  RCH_FORCE_REMOTE=1
  RCH_QUEUE_WHEN_BUSY=1
  RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900
  RCH_DAEMON_RESPONSE_TIMEOUT_SECS=900
  rch exec --
  env
  CARGO_INCREMENTAL=0
  CARGO_PROFILE_TEST_DEBUG=0
  "RUSTFLAGS=-C debuginfo=0"
  "ASUPERSYNC_KAFKA_BROKER_PARITY_PROOF_DIR=$OUT_DIR"
  cargo test -p asupersync
  --target-dir "$KAFKA_TARGET_DIR"
  --test kafka_real_broker
  --features test-internals,kafka
  kafka_broker_parity_real_broker_proof_row
  --
  --nocapture
  --test-threads=1
)

log "bead_id=$BEAD_ID"
log "output_dir=$OUT_DIR"
log "git_sha=$GIT_SHA"

TEST_STATUS=0
run_lane default-feature-gate "${DEFAULT_CMD[@]}" || TEST_STATUS=1
run_lane kafka-broker-proof "${KAFKA_CMD[@]}" || TEST_STATUS=1

sed -n 's/^.*\({.*"bead_id":"asupersync-0xbecl".*}\).*$/\1/p' "$LOG_FILE" > "$ROWS_FILE" || true

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
else
  ROWS_JSON="[]"
  DRIFTS_JSON="[]"
  SKIPS_JSON="[]"
  MISSING_FIELDS_JSON="[]"
fi

ROW_COUNT="$(wc -l < "$ROWS_FILE" | tr -d ' ')"
VALIDATION_PASSED=false
if [ "$TEST_STATUS" -eq 0 ] \
  && [ "${#MISSING_SCENARIOS[@]}" -eq 0 ] \
  && [ "$(jq 'length' <<<"$DRIFTS_JSON")" -eq 0 ] \
  && [ "$(jq 'length' <<<"$MISSING_FIELDS_JSON")" -eq 0 ] \
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
    drifts: $drifts,
    skips: $skips,
    rows: $rows
  }' > "$REPORT_FILE"

log "run_report=$REPORT_FILE"
log "validation_passed=$VALIDATION_PASSED"

if [ "$VALIDATION_PASSED" != true ]; then
  exit 1
fi
