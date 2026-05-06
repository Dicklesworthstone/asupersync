#!/usr/bin/env bash
# Deterministic NATS / JetStream broker parity proof runner.
#
# Usage:
#   bash scripts/nats_jetstream_broker_parity_proof_runner.sh [output-dir]
#
# Default output:
#   target/messaging-broker-proof/asupersync-6xjxd7/{run.log,scenario_rows.jsonl,run_report.json}

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="${1:-$PROJECT_DIR/target/messaging-broker-proof/asupersync-6xjxd7}"
LOG_FILE="$OUT_DIR/run.log"
ROWS_FILE="$OUT_DIR/scenario_rows.jsonl"
REPORT_FILE="$OUT_DIR/run_report.json"
BEAD_ID="asupersync-6xjxd7"

EXPECTED_SCENARIOS=(
  "nats-pub-sub-roundtrip"
  "nats-request-reply-roundtrip"
  "nats-queue-group-single-delivery"
  "jetstream-create-consumer-pull-ack"
  "jetstream-durable-redelivery-after-reconnect"
  "jetstream-deliver-by-start-sequence-reference"
  "jetstream-deliver-by-start-time-reference"
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

redact_uri() {
  local uri="${1:-nats://127.0.0.1:4222}"
  sed -E 's#(://)[^/@]+@#\1<redacted>@#' <<<"$uri"
}

auth_mode() {
  local uri="${1:-}"
  if [[ -n "${NATS_AUTH_MODE:-}" ]]; then
    printf '%s' "$NATS_AUTH_MODE"
  elif [[ "$uri" == *"://"*"@"* ]]; then
    printf 'user-info-redacted'
  else
    printf 'none-or-tokenless'
  fi
}

broker_version() {
  if [[ -n "${NATS_BROKER_VERSION:-}" ]]; then
    printf '%s' "$NATS_BROKER_VERSION"
    return
  fi

  local bin="${NATS_SERVER_BIN:-nats-server}"
  if command -v "$bin" >/dev/null 2>&1; then
    "$bin" --version 2>/dev/null | head -n 1 || printf 'unknown'
  else
    printf 'unavailable'
  fi
}

run_cargo_test() {
  local label="$1"
  local target="$2"
  local cmd_log="$OUT_DIR/${label}.log"
  : > "$cmd_log"

  local cmd=(
    env
    -u
    CARGO_TARGET_DIR
    RCH_FORCE_REMOTE=1
    RCH_QUEUE_WHEN_BUSY=1
    RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900
    rch exec --
    env
    CARGO_INCREMENTAL=0
    CARGO_PROFILE_TEST_DEBUG=0
    "CARGO_TARGET_DIR=/tmp/rch_target_${BEAD_ID}_${label}"
    "RUSTFLAGS=-C debuginfo=0"
    cargo test -p asupersync
    --test "$target"
    --features test-internals
    --
    --nocapture
    --test-threads=1
  )

  log "target=$target"
  log "command[$label]=$(printf '%q ' "${cmd[@]}")"

  set +e
  timeout "${RCH_COMMAND_TIMEOUT_SECS:-300}" "${cmd[@]}" 2>&1 | tee -a "$LOG_FILE" "$cmd_log"
  local status="${PIPESTATUS[0]}"
  set -e

  if grep -Eq '^\[RCH\] local \(|falling back to local' "$cmd_log"; then
    log "rch_local_fallback_detected[$label]=true"
    return 125
  fi

  if [[ "$status" -eq 124 ]] && grep -q 'test result: ok\.' "$cmd_log"; then
    log "rch_artifact_retrieval_timeout_after_pass[$label]=true"
    return 0
  fi

  return "$status"
}

test_result_for() {
  local test_name="$1"
  local suite="$2"
  local skip_reason

  skip_reason="$(jq -Rr --arg test "$test_name" '
    fromjson? | objects
    | select(.event == "test_skipped" and .test == $test)
    | .reason
  ' "$LOG_FILE" | tail -n 1)"

  if [[ -n "$skip_reason" ]]; then
    printf 'skip\t%s' "$skip_reason"
    return
  fi

  if jq -Rr --arg suite "$suite" --arg test "$test_name" '
    fromjson? | objects
    | select(.suite == $suite and .test == $test and .event == "test_end" and .result == "pass")
    | .result
  ' "$LOG_FILE" | grep -qx 'pass'; then
    printf 'pass\t'
    return
  fi

  printf 'fail\tmissing pass or skip marker for %s' "$test_name"
}

emit_row() {
  local scenario_id="$1"
  local test_name="$2"
  local suite="$3"
  local broker_kind="$4"
  local topic_or_stream="$5"
  local expected_message_count="$6"
  local expected_ack_count="$7"
  local expected_lag="$8"
  local reconnect_count="$9"
  local cancellation_point="${10}"

  local result_line verdict unsupported_reason actual_result first_failure message_count ack_count
  result_line="$(test_result_for "$test_name" "$suite")"
  verdict="${result_line%%$'\t'*}"
  unsupported_reason="${result_line#*$'\t'}"

  case "$verdict" in
    pass)
      actual_result="broker proof passed"
      first_failure=""
      message_count="$expected_message_count"
      ack_count="$expected_ack_count"
      unsupported_reason=""
      ;;
    skip)
      actual_result="broker unavailable or disabled"
      first_failure=""
      message_count=0
      ack_count=0
      ;;
    *)
      actual_result="missing passing broker proof"
      first_failure="$unsupported_reason"
      message_count=0
      ack_count=0
      unsupported_reason=""
      ;;
  esac

  jq -cn \
    --arg bead_id "$BEAD_ID" \
    --arg broker_kind "$broker_kind" \
    --arg broker_version "$BROKER_VERSION" \
    --arg scenario_id "$scenario_id" \
    --arg feature_flags "test-internals" \
    --arg connection_uri_redacted "$CONNECTION_URI_REDACTED" \
    --arg auth_mode "$AUTH_MODE" \
    --arg topic_or_stream "$topic_or_stream" \
    --argjson message_count "$message_count" \
    --argjson ack_count "$ack_count" \
    --argjson consumer_lag "$expected_lag" \
    --argjson reconnect_count "$reconnect_count" \
    --arg cancellation_point "$cancellation_point" \
    --arg expected_result "real broker pass or explicit unavailable-broker skip" \
    --arg actual_result "$actual_result" \
    --arg artifact_path "$REPORT_FILE" \
    --arg unsupported_reason "$unsupported_reason" \
    --arg verdict "$verdict" \
    --arg first_failure "$first_failure" \
    '{
      bead_id: $bead_id,
      broker_kind: $broker_kind,
      broker_version: $broker_version,
      scenario_id: $scenario_id,
      feature_flags: $feature_flags,
      connection_uri_redacted: $connection_uri_redacted,
      auth_mode: $auth_mode,
      topic_or_stream: $topic_or_stream,
      message_count: $message_count,
      ack_count: $ack_count,
      consumer_lag: $consumer_lag,
      reconnect_count: $reconnect_count,
      cancellation_point: $cancellation_point,
      expected_result: $expected_result,
      actual_result: $actual_result,
      artifact_path: $artifact_path,
      unsupported_reason: $unsupported_reason,
      verdict: $verdict,
      first_failure: $first_failure
    }' >> "$ROWS_FILE"
}

RUN_STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
GIT_SHA="$(git rev-parse --short HEAD 2>/dev/null || printf 'unknown')"
CONNECTION_URI_REDACTED="$(redact_uri "${NATS_URL:-nats://127.0.0.1:4222}")"
AUTH_MODE="$(auth_mode "${NATS_URL:-}")"
BROKER_VERSION="$(broker_version)"

log "bead_id=$BEAD_ID"
log "output_dir=$OUT_DIR"
log "git_sha=$GIT_SHA"
log "real_nats_tests=${REAL_NATS_TESTS:-false}"
log "connection_uri_redacted=$CONNECTION_URI_REDACTED"
log "broker_version=$BROKER_VERSION"

NATS_STATUS=0
JETSTREAM_STATUS=0
run_cargo_test "nats" "nats_real_server" || NATS_STATUS="$?"
run_cargo_test "jetstream" "jetstream_real_server" || JETSTREAM_STATUS="$?"

emit_row "nats-pub-sub-roundtrip" "nats_real_pub_sub_roundtrip" "nats_real" "nats" "asupersync.pubsub.<unique>" 1 0 0 0 "none"
emit_row "nats-request-reply-roundtrip" "nats_real_request_reply_roundtrip" "nats_real" "nats" "asupersync.request.<unique>" 1 1 0 0 "none"
emit_row "nats-queue-group-single-delivery" "nats_real_queue_group_single_delivery" "nats_real" "nats" "asupersync.queue.<unique>" 1 0 0 0 "worker-timeout"
emit_row "jetstream-create-consumer-pull-ack" "jetstream_real_create_consumer_pull_ack_roundtrip" "jetstream_real" "jetstream" "jetstream_stream.<unique>" 1 1 0 0 "none"
emit_row "jetstream-durable-redelivery-after-reconnect" "jetstream_real_durable_consumer_redelivers_after_reconnect_without_ack" "jetstream_real" "jetstream" "jetstream_redelivery.<unique>" 1 1 0 1 "drop-before-ack"
emit_row "jetstream-deliver-by-start-sequence-reference" "jetstream_real_deliver_by_start_sequence_matches_raw_nats_first_delivery_tick135" "jetstream_real" "jetstream" "jetstream_start_sequence.<unique>" 3 2 0 0 "none"
emit_row "jetstream-deliver-by-start-time-reference" "jetstream_real_deliver_by_start_time_matches_raw_nats_first_delivery_tick137" "jetstream_real" "jetstream" "jetstream_start_time.<unique>" 3 2 0 0 "none"

EXPECTED_JSON="$(printf '%s\n' "${EXPECTED_SCENARIOS[@]}" | jq -R . | jq -s .)"
REQUIRED_FIELDS_JSON="$(printf '%s\n' "${REQUIRED_FIELDS[@]}" | jq -R . | jq -s .)"
ROWS_JSON="$(jq -s . "$ROWS_FILE")"
ROW_COUNT="$(wc -l < "$ROWS_FILE" | tr -d ' ')"
DRIFTS_JSON="$(jq -s '[.[] | select(.verdict == "fail")]' "$ROWS_FILE")"
SKIPS_JSON="$(jq -s '[.[] | select(.verdict == "skip")]' "$ROWS_FILE")"
PASSES_JSON="$(jq -s '[.[] | select(.verdict == "pass")]' "$ROWS_FILE")"

MISSING_SCENARIOS_JSON="$(jq -n \
  --argjson expected "$EXPECTED_JSON" \
  --slurpfile rows "$ROWS_FILE" \
  '$expected - ($rows | map(.scenario_id))')"

MISSING_FIELDS_JSON="$(jq -s --argjson required_fields "$REQUIRED_FIELDS_JSON" '
  [
    .[] as $row
    | $required_fields[] as $field
    | select(($row | has($field)) | not)
    | "\($row.scenario_id // "<unknown>"):\($field)"
  ]
' "$ROWS_FILE")"

VALIDATION_PASSED=false
if [[ "$NATS_STATUS" -eq 0 ]] \
  && [[ "$JETSTREAM_STATUS" -eq 0 ]] \
  && [[ "$ROW_COUNT" -eq "${#EXPECTED_SCENARIOS[@]}" ]] \
  && [[ "$(jq 'length' <<<"$MISSING_SCENARIOS_JSON")" -eq 0 ]] \
  && [[ "$(jq 'length' <<<"$MISSING_FIELDS_JSON")" -eq 0 ]] \
  && [[ "$(jq 'length' <<<"$DRIFTS_JSON")" -eq 0 ]]; then
  VALIDATION_PASSED=true
fi

RUN_FINISHED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# shellcheck disable=SC2094
jq -n \
  --arg bead_id "$BEAD_ID" \
  --arg run_started_at "$RUN_STARTED_AT" \
  --arg run_finished_at "$RUN_FINISHED_AT" \
  --arg git_sha "$GIT_SHA" \
  --arg output_dir "$OUT_DIR" \
  --arg log_path "$LOG_FILE" \
  --arg rows_path "$ROWS_FILE" \
  --arg report_path "$REPORT_FILE" \
  --arg connection_uri_redacted "$CONNECTION_URI_REDACTED" \
  --arg broker_version "$BROKER_VERSION" \
  --arg real_nats_tests "${REAL_NATS_TESTS:-false}" \
  --argjson nats_status "$NATS_STATUS" \
  --argjson jetstream_status "$JETSTREAM_STATUS" \
  --argjson row_count "$ROW_COUNT" \
  --argjson expected_scenarios "$EXPECTED_JSON" \
  --argjson required_fields "$REQUIRED_FIELDS_JSON" \
  --argjson missing_scenarios "$MISSING_SCENARIOS_JSON" \
  --argjson missing_fields "$MISSING_FIELDS_JSON" \
  --argjson rows "$ROWS_JSON" \
  --argjson drifts "$DRIFTS_JSON" \
  --argjson skips "$SKIPS_JSON" \
  --argjson passes "$PASSES_JSON" \
  --argjson validation_passed "$VALIDATION_PASSED" \
  '{
    bead_id: $bead_id,
    run_started_at: $run_started_at,
    run_finished_at: $run_finished_at,
    git_sha: $git_sha,
    output_dir: $output_dir,
    run_log: $log_path,
    scenario_rows: $rows_path,
    report_path: $report_path,
    connection_uri_redacted: $connection_uri_redacted,
    broker_version: $broker_version,
    real_nats_tests: $real_nats_tests,
    nats_status: $nats_status,
    jetstream_status: $jetstream_status,
    row_count: $row_count,
    pass_count: ($passes | length),
    skip_count: ($skips | length),
    fail_count: ($drifts | length),
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

if [[ "$VALIDATION_PASSED" != true ]]; then
  exit 1
fi
