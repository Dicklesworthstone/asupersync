#!/usr/bin/env bash
# Focused proof runner for the maintained dormant distributed recovery lane.
#
# Usage:
#   bash scripts/distributed_hash_snapshot_recovery_proof_runner.sh [output-dir]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BEAD_ID="${ASUPERSYNC_DISTRIBUTED_RECOVERY_BEAD_ID:-asupersync-d24mms.12.4}"
OUT_DIR="${1:-$PROJECT_DIR/target/distributed-hash-snapshot-recovery-proof/$BEAD_ID}"
LOG_FILE="$OUT_DIR/run.log"
ROWS_FILE="$OUT_DIR/scenario_rows.jsonl"
REPORT_FILE="$OUT_DIR/run_report.json"
RCH_BIN="${RCH_BIN:-rch}"
CARGO_BIN="${CARGO_BIN:-cargo}"
CARGO_JOBS="${ASUPERSYNC_DISTRIBUTED_RECOVERY_JOBS:-2}"
RUN_TIMEOUT_SECONDS="${ASUPERSYNC_DISTRIBUTED_RECOVERY_TIMEOUT_SECONDS:-1800}"
FEATURES="distributed-hash-snapshot-recovery-e2e"
RCH_LOCAL_FALLBACK_PATTERN='^\[RCH\] local \(|falling back to local|local fallback|fallback to local|executing locally'
RCH_BLOCKER_PATTERN='no admissible remote worker|no remote workers|remote execution required|exit 103|admission refused|active_project_exclusion'

EXPECTED_SCENARIOS=(
  DORMANT-DIST-001
  DORMANT-DIST-002
  DORMANT-DIST-003
  DORMANT-DIST-004
  DORMANT-DIST-005
)

REQUIRED_ROW_FIELDS=(
  bead_id
  scenario_id
  capability_ids
  feature_flags
  operation
  deterministic_seed
  expected
  actual
  lifecycle
  cleanup_status
  infrastructure_blocker
  verdict
  first_failure
  replay_command
  details
)

mkdir -p "$OUT_DIR"
: > "$LOG_FILE"
: > "$ROWS_FILE"
cd "$PROJECT_DIR"

log() {
  printf '%s\n' "$*" | tee -a "$LOG_FILE"
}

RUN_STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
GIT_SHA="$(git rev-parse HEAD 2>/dev/null || printf 'unknown')"
SAFE_BEAD="${BEAD_ID//[^[:alnum:]_]/_}"
RCH_TARGET_DIR="${ASUPERSYNC_DISTRIBUTED_RECOVERY_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_distributed_recovery_${SAFE_BEAD}}"

CMD=(
  "$RCH_BIN" exec
  --base HEAD
  --clean-overlay
  --overlay-path Cargo.toml
  --overlay-path tests/distributed_hash_snapshot_recovery_e2e.rs
  --
  env
  "CARGO_TARGET_DIR=$RCH_TARGET_DIR"
  CARGO_INCREMENTAL=0
  CARGO_PROFILE_TEST_DEBUG=0
  "RUSTFLAGS=-D warnings -C debuginfo=0"
  "ASUPERSYNC_DISTRIBUTED_RECOVERY_BEAD_ID=$BEAD_ID"
  "$CARGO_BIN" test -j "$CARGO_JOBS" -p asupersync
  --test distributed_hash_snapshot_recovery_e2e
  --no-default-features
  --features "$FEATURES"
  dormant_distributed_hash_snapshot_recovery_emits_required_scenarios
  --
  --nocapture
  --test-threads=1
)

log "bead_id=$BEAD_ID"
log "scenario_filter=dormant_distributed_hash_snapshot_recovery_emits_required_scenarios"
log "features=$FEATURES"
log "output_dir=$OUT_DIR"
log "git_sha=$GIT_SHA"
log "rch_target_dir=$RCH_TARGET_DIR"
log "timeout_seconds=$RUN_TIMEOUT_SECONDS"
log "command=timeout --foreground ${RUN_TIMEOUT_SECONDS}s env RCH_REQUIRE_REMOTE=1 $(printf '%q ' "${CMD[@]}")"

set +e
timeout --foreground "${RUN_TIMEOUT_SECONDS}s" env RCH_REQUIRE_REMOTE=1 "${CMD[@]}" \
  2>&1 | tee -a "$LOG_FILE"
TEST_STATUS="${PIPESTATUS[0]}"
set -e

LOCAL_FALLBACK=false
if grep -Eiq "$RCH_LOCAL_FALLBACK_PATTERN" "$LOG_FILE" 2>/dev/null; then
  LOCAL_FALLBACK=true
  TEST_STATUS=86
  log "rch_local_fallback=true"
fi

INFRASTRUCTURE_BLOCKER=""
if [ "$TEST_STATUS" -eq 124 ]; then
  INFRASTRUCTURE_BLOCKER="runner_timeout"
elif grep -Eiq "$RCH_BLOCKER_PATTERN" "$LOG_FILE" 2>/dev/null; then
  INFRASTRUCTURE_BLOCKER="rch_remote_admission_or_fleet_blocker"
elif [ "$LOCAL_FALLBACK" = true ]; then
  INFRASTRUCTURE_BLOCKER="rch_local_fallback_rejected"
fi

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
      (.verdict != "pass") or
      (.expected != .actual) or
      (.infrastructure_blocker != null) or
      (.first_failure != null)
    )
  ]')"

FIRST_FAILURE="$(jq -n \
  --argjson test_status "$TEST_STATUS" \
  --argjson rows "$ROWS_JSON" \
  --argjson missing "$MISSING_SCENARIOS" '
  if ($rows | map(select(.first_failure != null or .verdict != "pass")) | length) > 0 then
    ($rows | map(select(.first_failure != null or .verdict != "pass"))[0])
  elif $test_status != 0 then
    {kind: "cargo_or_admission_failure", test_status: $test_status, missing_scenarios: $missing}
  elif ($missing | length) > 0 then
    {kind: "missing_scenario_receipt", missing_scenarios: $missing}
  else null end')"

VALIDATION_PASSED=false
if [ "$TEST_STATUS" -eq 0 ] \
  && [ "$LOCAL_FALLBACK" = false ] \
  && [ -z "$INFRASTRUCTURE_BLOCKER" ] \
  && [ "$ROW_COUNT" -eq "${#EXPECTED_SCENARIOS[@]}" ] \
  && [ "$PASS_COUNT" -eq 5 ] \
  && [ "$SKIP_COUNT" -eq 0 ] \
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
  --arg command "timeout --foreground ${RUN_TIMEOUT_SECONDS}s env RCH_REQUIRE_REMOTE=1 $(printf '%q ' "${CMD[@]}")" \
  --arg infrastructure_blocker "$INFRASTRUCTURE_BLOCKER" \
  --argjson test_status "$TEST_STATUS" \
  --argjson local_fallback "$LOCAL_FALLBACK" \
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
  --argjson first_failure "$FIRST_FAILURE" \
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
    local_fallback: $local_fallback,
    infrastructure_blocker: (if $infrastructure_blocker == "" then null else $infrastructure_blocker end),
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
    first_failure: $first_failure,
    rows: $rows
  }' > "$REPORT_FILE"

log "test_status=$TEST_STATUS"
log "row_count=$ROW_COUNT"
log "pass_count=$PASS_COUNT"
log "skip_count=$SKIP_COUNT"
log "fail_count=$FAIL_COUNT"
log "infrastructure_blocker=${INFRASTRUCTURE_BLOCKER:-none}"
log "validation_passed=$VALIDATION_PASSED"
log "report=$REPORT_FILE"

if [ "$VALIDATION_PASSED" != true ]; then
  exit 1
fi
