#!/usr/bin/env bash
set -euo pipefail

RUN_ID="${RUN_ID:-atp-relay-$(date -u +%Y%m%dT%H%M%SZ)}"
OUTPUT_ROOT="${OUTPUT_ROOT:-target/atp-relay-e2e/${RUN_ID}}"
LOG_FILE="${OUTPUT_ROOT}/events.ndjson"
TEST_LOG="${OUTPUT_ROOT}/cargo-test.log"
TARGET_DIR="${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_atp_relay_e2e}"
RCH_BIN="${RCH_BIN:-rch}"
CARGO_BIN="${CARGO_BIN:-cargo}"

export RCH_REQUIRE_REMOTE="${RCH_REQUIRE_REMOTE:-1}"

mkdir -p "${OUTPUT_ROOT}"

json_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  printf '%s' "${value}"
}

log_event() {
  local status="$1"
  local stage="$2"
  local detail="$3"
  printf '{"run_id":"%s","status":"%s","stage":"%s","detail":"%s","target_dir":"%s"}\n' \
    "$(json_escape "${RUN_ID}")" \
    "$(json_escape "${status}")" \
    "$(json_escape "${stage}")" \
    "$(json_escape "${detail}")" \
    "$(json_escape "${TARGET_DIR}")" | tee -a "${LOG_FILE}"
}

record_failure_patterns() {
  local pattern_count=0
  for pattern in \
    "panicked at" \
    "test result: FAILED" \
    "assertion failed" \
    "Task leak detected" \
    "obligation[ _-]*leak[ _-]*(detected|found)" \
    "local fallback" \
    "falling back to local" \
    "\\[RCH\\] local"; do
    if grep -Eiq "${pattern}" "${TEST_LOG}" 2>/dev/null; then
      log_event "fail" "pattern-scan" "matched ${pattern}"
      grep -Ein "${pattern}" "${TEST_LOG}" | head -20 > "${OUTPUT_ROOT}/pattern_${pattern//[^A-Za-z0-9]/_}.txt" || true
      pattern_count=$((pattern_count + 1))
    fi
  done

  if [[ "${pattern_count}" -ne 0 ]]; then
    return 1
  fi
}

run_cargo_test_stage() {
  local stage="$1"
  local log_path="$2"
  shift 2
  log_event "start" "${stage}" "$*"
  set +e
  "$@" 2>&1 | tee "${log_path}"
  stage_status=${PIPESTATUS[0]}
  set -e
  if [[ "${stage_status}" -ne 0 ]]; then
    log_event "fail" "${stage}" "cargo status ${stage_status}; see ${log_path}"
    exit "${stage_status}"
  fi
  log_event "pass" "${stage}" "see ${log_path}"
}

if ! command -v "${RCH_BIN}" >/dev/null 2>&1; then
  log_event "blocked" "preflight" "rch not found"
  exit 127
fi

log_event "start" "preflight" "ATP relay e2e runner"

log_event "start" "compile-atp-relay-e2e" \
  "covered by cargo test --test atp_relay_e2e compile phase"

if [[ "${ATP_RELAY_RUN_LIB_UNIT:-0}" == "1" ]]; then
  run_cargo_test_stage "unit-relay-model" "${OUTPUT_ROOT}/cargo-unit.log" \
    "${RCH_BIN}" exec -- env "CARGO_TARGET_DIR=${TARGET_DIR}" "${CARGO_BIN}" test \
      -p asupersync --lib net::atp::relay::tests:: -- --nocapture
else
  log_event "skip" "unit-relay-model" \
    "set ATP_RELAY_RUN_LIB_UNIT=1; default skips unrelated lib-harness blockers"
fi

run_cargo_test_stage "integration-atp-relay-e2e" "${TEST_LOG}" \
  "${RCH_BIN}" exec -- env "CARGO_TARGET_DIR=${TARGET_DIR}" "${CARGO_BIN}" test \
    -p asupersync --test atp_relay_e2e -- --nocapture --test-threads=1

log_event "pass" "compile-atp-relay-e2e" \
  "cargo test --test atp_relay_e2e compiled successfully"
log_event "start" "failure-pattern-scan" "scan ${TEST_LOG}"
record_failure_patterns
log_event "pass" "failure-pattern-scan" "scan ${TEST_LOG}"

log_event "pass" "summary" "ATP relay e2e completed"
