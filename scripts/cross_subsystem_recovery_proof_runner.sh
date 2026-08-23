#!/usr/bin/env bash
# Focused proof runner for the maintained dormant cross-subsystem recovery lane.
#
# Usage:
#   bash scripts/cross_subsystem_recovery_proof_runner.sh [output-dir]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BEAD_ID="${ASUPERSYNC_CROSS_SUBSYSTEM_BEAD_ID:-asupersync-d24mms.12.3}"
OUT_DIR="${1:-$PROJECT_DIR/target/cross-subsystem-recovery-proof/$BEAD_ID}"
LOG_FILE="$OUT_DIR/run.log"
ROWS_FILE="$OUT_DIR/scenario_rows.jsonl"
REPORT_FILE="$OUT_DIR/run_report.json"
RCH_BIN="${RCH_BIN:-rch}"
CARGO_BIN="${CARGO_BIN:-cargo}"
CARGO_JOBS="${ASUPERSYNC_CROSS_SUBSYSTEM_JOBS:-2}"
FEATURES="cross-subsystem-recovery-e2e"
RCH_LOCAL_FALLBACK_PATTERN='^\[RCH\] local \(|falling back to local|local fallback|fallback to local|executing locally'

EXPECTED_SCENARIOS=(
  DORMANT-INT-001
  DORMANT-INT-002
  DORMANT-INT-003
  DORMANT-INT-004
  DORMANT-INT-005
  DORMANT-INT-006
  DORMANT-INT-007
  DORMANT-INT-008
  DORMANT-INT-009
  DORMANT-INT-010
  DORMANT-INT-011
  DORMANT-INT-012
  DORMANT-INT-013
  DORMANT-INT-014
  DORMANT-INT-015
  DORMANT-INT-016
  DORMANT-INT-017
)

REQUIRED_ROW_FIELDS=(
  bead_id
  scenario_id
  capability_ids
  subsystem
  feature_flags
  operation
  deterministic_seed
  expected
  actual
  cancellation_point
  cleanup_status
  unsupported_reason
  verdict
  first_failure
  replay_command
)

mkdir -p "$OUT_DIR"
: > "$LOG_FILE"
: > "$ROWS_FILE"
cd "$PROJECT_DIR"

log() {
  printf '%s\n' "$*" | tee -a "$LOG_FILE"
}

reject_local_fallback() {
  if grep -Eiq "$RCH_LOCAL_FALLBACK_PATTERN" "$LOG_FILE" 2>/dev/null; then
    log "rch_local_fallback=true"
    printf '%s\n' "RCH local fallback detected; no Cargo proof admitted" \
      > "$OUT_DIR/rch_local_fallback.txt"
    exit 86
  fi
}

RUN_STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
GIT_SHA="$(git rev-parse HEAD 2>/dev/null || printf 'unknown')"
SAFE_BEAD="${BEAD_ID//[^[:alnum:]_]/_}"
RCH_TARGET_DIR="${ASUPERSYNC_CROSS_SUBSYSTEM_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_cross_subsystem_${SAFE_BEAD}}"

CMD=(
  "$RCH_BIN" exec
  --base HEAD
  --clean-overlay
  --overlay-path Cargo.toml
  --overlay-path src/lib.rs
  --overlay-path src/real_cross_subsystem_recovery_e2e_tests.rs
  --
  env
  "CARGO_TARGET_DIR=$RCH_TARGET_DIR"
  CARGO_INCREMENTAL=0
  CARGO_PROFILE_TEST_DEBUG=0
  "RUSTFLAGS=-D warnings -C debuginfo=0"
  "ASUPERSYNC_CROSS_SUBSYSTEM_BEAD_ID=$BEAD_ID"
  "$CARGO_BIN" test -j "$CARGO_JOBS" -p asupersync --lib
  --no-default-features
  --features "$FEATURES"
  dormant_cross_subsystem_recovery_emits_required_scenarios
  --
  --nocapture
  --test-threads=1
)

log "bead_id=$BEAD_ID"
log "scenario_filter=dormant_cross_subsystem_recovery_emits_required_scenarios"
log "features=$FEATURES"
log "output_dir=$OUT_DIR"
log "git_sha=$GIT_SHA"
log "rch_target_dir=$RCH_TARGET_DIR"
log "command=RCH_REQUIRE_REMOTE=1 $(printf '%q ' "${CMD[@]}")"

set +e
RCH_REQUIRE_REMOTE=1 "${CMD[@]}" 2>&1 | tee -a "$LOG_FILE"
TEST_STATUS="${PIPESTATUS[0]}"
set -e
reject_local_fallback

grep -F "\"bead_id\":\"${BEAD_ID}\"" "$LOG_FILE" \
  | sed 's/^[^{]*//' \
  > "$ROWS_FILE" || true

EXPECTED_JSON="$(printf '%s\n' "${EXPECTED_SCENARIOS[@]}" | jq -R . | jq -s .)"
REQUIRED_FIELDS_JSON="$(printf '%s\n' "${REQUIRED_ROW_FIELDS[@]}" | jq -R . | jq -s .)"
ROWS_JSON="$(if [ -s "$ROWS_FILE" ]; then jq -s . "$ROWS_FILE"; else printf '[]'; fi)"
ROW_COUNT="$(jq 'length' <<<"$ROWS_JSON")"
PASS_COUNT="$(jq '[.[] | select(.verdict == "pass")] | length' <<<"$ROWS_JSON")"
SKIP_COUNT="$(jq '[.[] | select(.verdict == "skip")] | length' <<<"$ROWS_JSON")"
FAIL_COUNT="$(jq '[.[] | select(.verdict == "fail")] | length' <<<"$ROWS_JSON")"
MISSING_SCENARIOS="$(jq -n --argjson expected "$EXPECTED_JSON" --argjson rows "$ROWS_JSON" \
  '$expected - [$rows[].scenario_id]')"
DUPLICATE_SCENARIOS="$(jq -n --argjson rows "$ROWS_JSON" \
  '$rows | group_by(.scenario_id) | map(select(length != 1) | {scenario_id: .[0].scenario_id, count: length})')"
MISSING_FIELDS="$(jq -n --argjson rows "$ROWS_JSON" --argjson fields "$REQUIRED_FIELDS_JSON" \
  '[$rows[] as $row | $fields[] as $field | select(($row | has($field)) | not) | {scenario_id: ($row.scenario_id // "<missing>"), field: $field}]')"
DRIFTS="$(jq -n --argjson rows "$ROWS_JSON" '
  [$rows[] |
    select(
      (.verdict == "fail") or
      (.verdict == "pass" and .expected != .actual) or
      (.verdict == "skip" and (
        .scenario_id != "DORMANT-INT-005" or
        .unsupported_reason != "PLACEHOLDER_NOT_EVIDENCE"
      )) or
      (.verdict != "pass" and .verdict != "skip")
    )
  ]')"

VALIDATION_PASSED=false
if [ "$TEST_STATUS" -eq 0 ] \
  && [ "$ROW_COUNT" -eq "${#EXPECTED_SCENARIOS[@]}" ] \
  && [ "$PASS_COUNT" -eq 16 ] \
  && [ "$SKIP_COUNT" -eq 1 ] \
  && [ "$FAIL_COUNT" -eq 0 ] \
  && [ "$(jq 'length' <<<"$MISSING_SCENARIOS")" -eq 0 ] \
  && [ "$(jq 'length' <<<"$DUPLICATE_SCENARIOS")" -eq 0 ] \
  && [ "$(jq 'length' <<<"$MISSING_FIELDS")" -eq 0 ] \
  && [ "$(jq 'length' <<<"$DRIFTS")" -eq 0 ]; then
  VALIDATION_PASSED=true
fi

RUN_FINISHED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
jq -n \
  --arg bead_id "$BEAD_ID" \
  --arg run_started_at "$RUN_STARTED_AT" \
  --arg run_finished_at "$RUN_FINISHED_AT" \
  --arg git_sha "$GIT_SHA" \
  --arg output_dir "$OUT_DIR" \
  --arg run_log "$LOG_FILE" \
  --arg scenario_rows "$ROWS_FILE" \
  --arg features "$FEATURES" \
  --arg rch_target_dir "$RCH_TARGET_DIR" \
  --arg command "RCH_REQUIRE_REMOTE=1 $(printf '%q ' "${CMD[@]}")" \
  --argjson test_status "$TEST_STATUS" \
  --argjson row_count "$ROW_COUNT" \
  --argjson pass_count "$PASS_COUNT" \
  --argjson skip_count "$SKIP_COUNT" \
  --argjson fail_count "$FAIL_COUNT" \
  --argjson expected_scenarios "$EXPECTED_JSON" \
  --argjson required_row_fields "$REQUIRED_FIELDS_JSON" \
  --argjson missing_scenarios "$MISSING_SCENARIOS" \
  --argjson duplicate_scenarios "$DUPLICATE_SCENARIOS" \
  --argjson missing_fields "$MISSING_FIELDS" \
  --argjson drifts "$DRIFTS" \
  --argjson rows "$ROWS_JSON" \
  --argjson validation_passed "$VALIDATION_PASSED" \
  '{
    bead_id: $bead_id,
    run_started_at: $run_started_at,
    run_finished_at: $run_finished_at,
    git_sha: $git_sha,
    output_dir: $output_dir,
    run_log: $run_log,
    scenario_rows: $scenario_rows,
    command: $command,
    features: $features,
    rch_target_dir: $rch_target_dir,
    test_status: $test_status,
    row_count: $row_count,
    pass_count: $pass_count,
    skip_count: $skip_count,
    fail_count: $fail_count,
    validation_passed: $validation_passed,
    expected_scenarios: $expected_scenarios,
    required_row_fields: $required_row_fields,
    missing_scenarios: $missing_scenarios,
    duplicate_scenarios: $duplicate_scenarios,
    missing_fields: $missing_fields,
    drifts: $drifts,
    rows: $rows
  }' > "$REPORT_FILE"

log "test_status=$TEST_STATUS"
log "row_count=$ROW_COUNT"
log "pass_count=$PASS_COUNT"
log "skip_count=$SKIP_COUNT"
log "fail_count=$FAIL_COUNT"
log "validation_passed=$VALIDATION_PASSED"
log "report=$REPORT_FILE"

if [ "$VALIDATION_PASSED" != true ]; then
  exit 1
fi
