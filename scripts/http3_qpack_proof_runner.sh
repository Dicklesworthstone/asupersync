#!/usr/bin/env bash
# Deterministic HTTP/3 QPACK instruction-stream proof runner.
#
# Usage:
#   bash scripts/http3_qpack_proof_runner.sh [output-dir]
#
# Default output:
#   target/http3-qpack-instruction-proof/asupersync-1xxmyo/{run.log,run_report.json}

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="${1:-$PROJECT_DIR/target/http3-qpack-instruction-proof/asupersync-1xxmyo}"
LOG_FILE="$OUT_DIR/run.log"
ROWS_FILE="$OUT_DIR/scenario_rows.jsonl"
REPORT_FILE="$OUT_DIR/run_report.json"
BEAD_ID="asupersync-1xxmyo"

EXPECTED_SCENARIOS=(
  "static-only-rejection"
  "encoder-instruction-roundtrip"
  "decoder-feedback-roundtrip"
  "blocked-then-unblocked-stream"
  "cancellation-while-blocked"
  "capacity-exceeded"
  "malformed-instruction"
  "wrong-stream-instruction"
)

mkdir -p "$OUT_DIR"
: > "$LOG_FILE"
: > "$ROWS_FILE"

cd "$PROJECT_DIR"

log() {
  printf '%s\n' "$*" | tee -a "$LOG_FILE"
}

RUN_STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
GIT_SHA="$(git rev-parse --short HEAD 2>/dev/null || printf 'unknown')"

CMD=(
  env
  -u
  CARGO_TARGET_DIR
  rch exec --
  env
  CARGO_INCREMENTAL=0
  CARGO_PROFILE_TEST_DEBUG=0
  "RUSTFLAGS=-C debuginfo=0"
  cargo test -p asupersync
  --lib
  --features test-internals,http3
  qpack_instruction_stream
  --
  --nocapture
)

log "bead_id=$BEAD_ID"
log "scenario_filter=qpack_instruction_stream"
log "output_dir=$OUT_DIR"
log "git_sha=$GIT_SHA"
log "command=$(printf '%q ' "${CMD[@]}")"

set +e
"${CMD[@]}" 2>&1 | tee -a "$LOG_FILE"
TEST_STATUS="${PIPESTATUS[0]}"
set -e

grep -E '^\{.*"bead_id":"asupersync-1xxmyo".*\}$' "$LOG_FILE" > "$ROWS_FILE" || true

MISSING_SCENARIOS=()
for scenario in "${EXPECTED_SCENARIOS[@]}"; do
  if ! jq -e --arg scenario "$scenario" \
    'select(.scenario_id == $scenario)' "$ROWS_FILE" >/dev/null 2>&1; then
    MISSING_SCENARIOS+=("$scenario")
  fi
done

EXPECTED_JSON="$(printf '%s\n' "${EXPECTED_SCENARIOS[@]}" | jq -R . | jq -s .)"
if [ "${#MISSING_SCENARIOS[@]}" -eq 0 ]; then
  MISSING_JSON="[]"
else
  MISSING_JSON="$(printf '%s\n' "${MISSING_SCENARIOS[@]}" | jq -R . | jq -s .)"
fi
if [ -s "$ROWS_FILE" ]; then
  ROWS_JSON="$(jq -s . "$ROWS_FILE")"
  DRIFTS_JSON="$(jq -s '[.[] | select(.verdict != "pass")]' "$ROWS_FILE")"
else
  ROWS_JSON="[]"
  DRIFTS_JSON="[]"
fi

ROW_COUNT="$(wc -l < "$ROWS_FILE" | tr -d ' ')"
VALIDATION_PASSED=false
if [ "$TEST_STATUS" -eq 0 ] \
  && [ "${#MISSING_SCENARIOS[@]}" -eq 0 ] \
  && [ "$(jq 'length' <<<"$DRIFTS_JSON")" -eq 0 ] \
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
  --arg command "$(printf '%q ' "${CMD[@]}")" \
  --argjson test_status "$TEST_STATUS" \
  --argjson expected_scenarios "$EXPECTED_JSON" \
  --argjson missing_scenarios "$MISSING_JSON" \
  --argjson rows "$ROWS_JSON" \
  --argjson drifts "$DRIFTS_JSON" \
  --argjson validation_passed "$VALIDATION_PASSED" \
  '{
    bead_id: $bead_id,
    run_started_at: $run_started_at,
    run_finished_at: $run_finished_at,
    git_sha: $git_sha,
    output_dir: $output_dir,
    run_log: $log_path,
    scenario_rows: $rows_path,
    command: $command,
    test_status: $test_status,
    validation_passed: $validation_passed,
    expected_scenarios: $expected_scenarios,
    missing_scenarios: $missing_scenarios,
    drifts: $drifts,
    rows: $rows
  }' > "$REPORT_FILE"

log "run_report=$REPORT_FILE"
log "validation_passed=$VALIDATION_PASSED"

if [ "$VALIDATION_PASSED" != true ]; then
  exit 1
fi
