#!/usr/bin/env bash
set -euo pipefail

RUN_ID="${RUN_ID:-atp-session-$(date -u +%Y%m%dT%H%M%SZ)}"
OUTPUT_ROOT="${OUTPUT_ROOT:-target/atp-session-negotiation-e2e/${RUN_ID}}"
LOG_FILE="${OUTPUT_ROOT}/events.ndjson"
TARGET_DIR="${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_atp_session_negotiation_e2e}"
SESSION_CARGO_HOME="${ATP_SESSION_CARGO_HOME:-/tmp/rch_cargo_home_asupersync_reality}"
# Keep child logs outside RCH's disposable per-command source root. The test
# appends a unique process/time directory and never deletes previous artifacts.
SESSION_ARTIFACT_ROOT="${ATP_SESSION_ARTIFACT_ROOT:-/tmp/asupersync-atp-session-negotiation-artifacts}"
export RCH_REQUIRE_REMOTE=1
export RCH_VISIBILITY="${RCH_VISIBILITY:-verbose}"

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
  local status=0
  "$@" 2>&1 | tee "${OUTPUT_ROOT}/${stage}.log" || status=$?
  if [[ "${status}" != "0" ]]; then
    log_event "fail" "${stage}" "terminal_exit=${status}; first output retained"
    return "${status}"
  fi
  log_event "pass" "${stage}" "$*"
}

if ! command -v rch >/dev/null 2>&1; then
  log_event "blocked" "preflight" "rch not found"
  exit 127
fi

log_event "start" "preflight" "ATP session negotiation e2e"

# Capture installed capability evidence; example/prose mentions do not count
# as option declarations. Unsupported clients stop before any Cargo command.
run_stage "rch-version" rch --version
run_stage "rch-exec-help" rch exec --help
if ! grep -q '[^[:space:]]' "${OUTPUT_ROOT}/rch-version.log"; then
  log_event "blocked" "clean-overlay-capability" "empty installed version identity; no proof command emitted"
  exit 2
fi
for flag in --base --clean-overlay --overlay-path --no-overlay; do
  if ! awk -v flag="${flag}" '
    /^Options:/ { options = 1; next }
    /^[^[:space:]]/ { options = 0 }
    options && /^[[:space:]]+(-[[:alnum:]], )?--/ {
      for (i = 1; i <= NF; i++) if ($i == flag) found = 1
    }
    END { exit !found }
  ' "${OUTPUT_ROOT}/rch-exec-help.log"; then
    log_event "blocked" "clean-overlay-capability" "missing option declaration: ${flag}; no proof command emitted"
    exit 2
  fi
done
if [[ "$(git branch --show-current)" != "main" || -n "$(git rev-parse --show-prefix)" ]]; then
  log_event "blocked" "source" "run from project root on main"
  exit 2
fi
BASE_COMMIT="$(git rev-parse --verify "${RCH_BASE:-HEAD}^{commit}")"
# These three paths are the entire lane. Coordinate their Agent Mail
# reservations before running on dirty main; unrelated peer dirt is excluded.
RCH_COMMAND=(rch exec --base "${BASE_COMMIT}" --clean-overlay
  --overlay-path src/net/atp/protocol/session.rs
  --overlay-path tests/atp_session_negotiation.rs
  --overlay-path scripts/run_atp_session_negotiation_e2e.sh)
log_event "pass" "clean-overlay-capability" "base=${BASE_COMMIT}; exact three owned paths selected; remote required"

if [[ "${ATP_SESSION_RUN_LIB_UNIT:-1}" == "1" ]]; then
  run_stage "unit-session-state-machine" \
    "${RCH_COMMAND[@]}" -- env CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_HOME="${SESSION_CARGO_HOME}" \
      CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' \
      cargo test -p asupersync --locked \
      --lib net::atp::protocol::session::tests -- --nocapture
else
  log_event "skip" "unit-session-state-machine" \
    "explicit integration-only run; required unit proof omitted"
fi

run_stage "integration-session-e2e" \
  "${RCH_COMMAND[@]}" -- env CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_HOME="${SESSION_CARGO_HOME}" \
    CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' \
    ASUPERSYNC_TEST_ARTIFACTS_DIR="${SESSION_ARTIFACT_ROOT}" cargo test -p asupersync \
    --locked --features tls --test atp_session_negotiation -- --nocapture

# A missing TLS feature or accidentally filtered/empty test suite must not
# manufacture process proof. This receipt is emitted only after the parent
# checks both child-process pairs, received frames, refusals and transcripts.
if ! grep -F '"scenario_id":"native_two_process_extension_exchange"' \
    "${OUTPUT_ROOT}/integration-session-e2e.log" \
    | grep -F '"child_processes":4' | grep -F '"negotiated_sessions":2' \
    | grep -F '"result":"pass"' >/dev/null; then
  log_event "fail" "native-extension-process-proof" "required nonzero process result absent"
  exit 1
fi

log_event "pass" "summary" "ATP session negotiation stages complete; unit_mode=${ATP_SESSION_RUN_LIB_UNIT:-1}"
