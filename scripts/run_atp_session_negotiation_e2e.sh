#!/usr/bin/env bash
set -euo pipefail

RUN_ID="${RUN_ID:-atp-session-$(date -u +%Y%m%dT%H%M%SZ)}"
OUTPUT_ROOT="${OUTPUT_ROOT:-target/atp-session-negotiation-e2e/${RUN_ID}}"
LOG_FILE="${OUTPUT_ROOT}/events.ndjson"
TARGET_DIR="${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_atp_session_negotiation_e2e}"

mkdir -p "${OUTPUT_ROOT}"

log_event() {
  local status="$1"
  local stage="$2"
  local detail="$3"
  printf '{"run_id":"%s","status":"%s","stage":"%s","detail":"%s","target_dir":"%s"}\n' \
    "${RUN_ID}" "${status}" "${stage}" "${detail}" "${TARGET_DIR}" | tee -a "${LOG_FILE}"
}

run_stage() {
  local stage="$1"
  shift
  log_event "start" "${stage}" "$*"
  "$@"
  log_event "pass" "${stage}" "$*"
}

if ! command -v rch >/dev/null 2>&1; then
  log_event "blocked" "preflight" "rch not found"
  exit 127
fi

log_event "start" "preflight" "ATP session negotiation e2e"

if [[ "${ATP_SESSION_RUN_LIB_UNIT:-0}" == "1" ]]; then
  run_stage "unit-session-state-machine" \
    rch exec -- env CARGO_TARGET_DIR="${TARGET_DIR}" cargo test -p asupersync \
      --lib net::atp::protocol::session::tests -- --nocapture
else
  log_event "skip" "unit-session-state-machine" \
    "set ATP_SESSION_RUN_LIB_UNIT=1; default skips unrelated lib-harness blockers"
fi

run_stage "integration-session-e2e" \
  rch exec -- env CARGO_TARGET_DIR="${TARGET_DIR}" cargo test -p asupersync \
    --test atp_session_negotiation -- --nocapture

log_event "pass" "summary" "ATP session negotiation e2e complete"
