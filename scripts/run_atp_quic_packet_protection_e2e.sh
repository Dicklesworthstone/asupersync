#!/usr/bin/env bash
set -euo pipefail

RUN_ID="${RUN_ID:-atp-quic-protection-$(date -u +%Y%m%dT%H%M%SZ)}"
OUTPUT_ROOT="${OUTPUT_ROOT:-target/atp-quic-packet-protection-e2e/${RUN_ID}}"
LOG_FILE="${OUTPUT_ROOT}/events.ndjson"
TARGET_DIR="${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_atp_quic_packet_protection_e2e}"

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

log_event "start" "preflight" "ATP native QUIC packet-protection provider boundary"

run_stage "deterministic-provider-contract" \
  rch exec -- env CARGO_TARGET_DIR="${TARGET_DIR}" cargo test -p asupersync \
    --test atp_quic_packet_protection -- --nocapture

if [[ "${ATP_QUIC_RUN_TLS_REAL_PROVIDER:-1}" == "1" ]]; then
  run_stage "tls-feature-provider-frontier" \
    rch exec -- env CARGO_TARGET_DIR="${TARGET_DIR}" cargo test -p asupersync \
      --features tls --test atp_quic_packet_protection -- --nocapture
else
  log_event "skip" "tls-feature-provider-frontier" \
    "ATP_QUIC_RUN_TLS_REAL_PROVIDER=0 requested deterministic-only mode; tls feature provider frontier was intentionally skipped"
fi

log_event "pass" "summary" "ATP packet-protection provider e2e complete"
