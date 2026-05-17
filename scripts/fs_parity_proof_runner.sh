#!/usr/bin/env bash
# Deterministic filesystem parity proof runner.
#
# Usage:
#   bash scripts/fs_parity_proof_runner.sh [output-dir]
#
# Default output:
#   target/fs-parity-proof/asupersync-oc0ybw/{run.log,scenario_rows.jsonl,run_report.json}

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="${1:-$PROJECT_DIR/target/fs-parity-proof/asupersync-oc0ybw}"
LOG_FILE="$OUT_DIR/run.log"
ROWS_FILE="$OUT_DIR/scenario_rows.jsonl"
REPORT_FILE="$OUT_DIR/run_report.json"
BEAD_ID="asupersync-oc0ybw"
RCH_BIN="${RCH_BIN:-rch}"
CARGO_BIN="${CARGO_BIN:-cargo}"
RCH_LOCAL_FALLBACK_PATTERN='^\[RCH\] local \(|falling back to local|local fallback|fallback to local|executing locally'

EXPECTED_SCENARIOS=(
  "open-options-seek-sync"
  "open-options-append-truncate"
  "file-create-new-exclusive"
  "file-clone-position-rewind"
  "file-set-len-permissions"
  "read-dir-metadata-disposition"
  "buffered-lines-boundaries"
  "buf-writer-flush-visibility"
  "write-atomic-replace-cleanup"
  "dir-create-remove-boundaries"
  "unix-vfs-equivalence"
  "error-kind-remove-missing"
  "error-kind-invalid-utf8-read-to-string"
  "error-kind-create-dir-existing-file"
  "error-kind-read-dir-non-directory"
  "try-exists-lifecycle"
  "path-ops-copy-hardlink-rename"
  "unix-symlink-metadata-readlink"
  "io-uring-cancellation-support-boundary"
  "io-uring-unknown-completion-attribution"
  "read-dir-drop-cancellation"
)

REQUIRED_ROW_FIELDS=(
  "bead_id"
  "scenario_id"
  "api"
  "backend"
  "platform"
  "feature_flags"
  "temp_root"
  "operation"
  "bytes_expected"
  "bytes_actual"
  "metadata_expected"
  "metadata_actual"
  "cancellation_point"
  "cleanup_status"
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

reject_rch_local_fallback_log() {
  if grep -Eiq "$RCH_LOCAL_FALLBACK_PATTERN" "$LOG_FILE" 2>/dev/null; then
    log "rch_local_fallback=true"
    echo "rch local fallback detected; refusing local cargo execution" > "$OUT_DIR/rch_local_fallback.txt"
    exit 86
  fi
}

RUN_STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
GIT_SHA="$(git rev-parse --short HEAD 2>/dev/null || printf 'unknown')"
FEATURES="${ASUPERSYNC_FS_PARITY_FEATURES:-test-internals}"
TARGET_DIR_SAFE_BEAD="${BEAD_ID//[^[:alnum:]_]/_}"
TARGET_DIR_SAFE_FEATURES="${FEATURES//[^[:alnum:]_]/_}"
RCH_TARGET_DIR="${ASUPERSYNC_FS_PARITY_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_fs_parity_${TARGET_DIR_SAFE_BEAD}_${TARGET_DIR_SAFE_FEATURES}}"

CMD=(
  "$RCH_BIN" exec --
  env
  "CARGO_TARGET_DIR=$RCH_TARGET_DIR"
  CARGO_INCREMENTAL=0
  CARGO_PROFILE_TEST_DEBUG=0
  "RUSTFLAGS=-C debuginfo=0"
  "ASUPERSYNC_FS_PARITY_PROOF_DIR=$OUT_DIR"
  "ASUPERSYNC_FS_PARITY_BEAD_ID=$BEAD_ID"
  "$CARGO_BIN" test -p asupersync
  --test e2e_fs
  --features "$FEATURES"
  fs_parity_wave2_proof_runner_logs_required_scenarios
  --
  --nocapture
)

log "bead_id=$BEAD_ID"
log "scenario_filter=fs_parity_wave2_proof_runner_logs_required_scenarios"
log "output_dir=$OUT_DIR"
log "git_sha=$GIT_SHA"
log "features=$FEATURES"
log "rch_target_dir=$RCH_TARGET_DIR"
log "command=$(printf '%q ' "${CMD[@]}")"

set +e
"${CMD[@]}" 2>&1 | tee -a "$LOG_FILE"
TEST_STATUS="${PIPESTATUS[0]}"
set -e
reject_rch_local_fallback_log

grep -E '^\{.*"bead_id":"asupersync-oc0ybw".*\}$' "$LOG_FILE" > "$ROWS_FILE" || true

MISSING_SCENARIOS=()
for scenario in "${EXPECTED_SCENARIOS[@]}"; do
  if ! jq -e --arg scenario "$scenario" \
    'select(.scenario_id == $scenario)' "$ROWS_FILE" >/dev/null 2>&1; then
    MISSING_SCENARIOS+=("$scenario")
  fi
done

EXPECTED_JSON="$(printf '%s\n' "${EXPECTED_SCENARIOS[@]}" | jq -R . | jq -s .)"
REQUIRED_FIELDS_JSON="$(printf '%s\n' "${REQUIRED_ROW_FIELDS[@]}" | jq -R . | jq -s .)"
if [ "${#MISSING_SCENARIOS[@]}" -eq 0 ]; then
  MISSING_JSON="[]"
else
  MISSING_JSON="$(printf '%s\n' "${MISSING_SCENARIOS[@]}" | jq -R . | jq -s .)"
fi
if [ -s "$ROWS_FILE" ]; then
  ROWS_JSON="$(jq -s . "$ROWS_FILE")"
  DRIFTS_JSON="$(jq -s '[.[] | select((.verdict == "fail") or (.verdict == "skip" and ((.unsupported_reason // "") == "")) or (.verdict != "pass" and .verdict != "skip"))]' "$ROWS_FILE")"
  MISSING_FIELDS_JSON="$(jq -s --argjson fields "$REQUIRED_FIELDS_JSON" '[.[] as $row | $fields[] as $field | select(($row | has($field)) | not) | {scenario_id: ($row.scenario_id // "<missing>"), field: $field}]' "$ROWS_FILE")"
else
  ROWS_JSON="[]"
  DRIFTS_JSON="[]"
  MISSING_FIELDS_JSON="[]"
fi

ROW_COUNT="$(wc -l < "$ROWS_FILE" | tr -d ' ')"
PASS_COUNT="$(jq -s '[.[] | select(.verdict == "pass")] | length' "$ROWS_FILE")"
SKIP_COUNT="$(jq -s '[.[] | select(.verdict == "skip")] | length' "$ROWS_FILE")"
FAIL_COUNT="$(jq -s '[.[] | select(.verdict == "fail")] | length' "$ROWS_FILE")"
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
  --arg command "$(printf '%q ' "${CMD[@]}")" \
  --arg features "$FEATURES" \
  --arg rch_target_dir "$RCH_TARGET_DIR" \
  --argjson test_status "$TEST_STATUS" \
  --argjson row_count "$ROW_COUNT" \
  --argjson pass_count "$PASS_COUNT" \
  --argjson skip_count "$SKIP_COUNT" \
  --argjson fail_count "$FAIL_COUNT" \
  --argjson expected_scenarios "$EXPECTED_JSON" \
  --argjson required_row_fields "$REQUIRED_FIELDS_JSON" \
  --argjson missing_scenarios "$MISSING_JSON" \
  --argjson missing_fields "$MISSING_FIELDS_JSON" \
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
    missing_fields: $missing_fields,
    drifts: $drifts,
    rows: $rows
  }' > "$REPORT_FILE"

log "run_report=$REPORT_FILE"
log "validation_passed=$VALIDATION_PASSED"

if [ "$VALIDATION_PASSED" != true ]; then
  exit 1
fi
