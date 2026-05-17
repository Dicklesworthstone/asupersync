#!/usr/bin/env bash
# Redis E2E Test Runner (bd-9vfn, enriched bd-26l3)
#
# Starts a local Redis container, runs the Redis E2E integration tests, and
# saves structured artifacts under target/e2e-results/.
#
# Usage:
#   ./scripts/test_redis_e2e.sh [--dry-run]
#
# Environment Variables:
#   REDIS_IMAGE    - Docker image (default: redis:7)
#   REDIS_PORT     - Host port to bind (default: 6379)
#   TEST_LOG_LEVEL - error|warn|info|debug|trace (default: trace)
#   RUST_LOG       - tracing filter (default: asupersync=debug)
#   RUST_BACKTRACE - 1 to enable backtraces (default: 1)
#   TEST_SEED      - deterministic seed override (default: 0xDEADBEEF)
#   RCH_BIN        - remote compilation helper executable (default: rch)
#   CARGO_BIN      - Cargo executable routed through rch (default: cargo)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="${PROJECT_ROOT}/target/e2e-results/redis"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LOG_FILE="${OUTPUT_DIR}/redis_e2e_${TIMESTAMP}.log"
ARTIFACT_DIR="${OUTPUT_DIR}/artifacts_${TIMESTAMP}"
RCH_BIN="${RCH_BIN:-rch}"
CARGO_BIN="${CARGO_BIN:-cargo}"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_redis_e2e}"
DRY_RUN=0
LOCAL_FALLBACKS=0

if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=1
    shift
fi

if [[ "$#" -gt 0 ]]; then
    echo "usage: $0 [--dry-run]" >&2
    exit 2
fi

export REDIS_IMAGE="${REDIS_IMAGE:-redis:7}"
export REDIS_PORT="${REDIS_PORT:-6379}"

export TEST_LOG_LEVEL="${TEST_LOG_LEVEL:-trace}"
export RUST_LOG="${RUST_LOG:-asupersync=debug}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export TEST_SEED="${TEST_SEED:-0xDEADBEEF}"

CONTAINER_NAME="asupersync_redis_e2e"

mkdir -p "$OUTPUT_DIR" "$ARTIFACT_DIR"

format_command() {
    local rendered
    printf -v rendered "%q " "$@"
    printf '%s' "${rendered% }"
}

json_escape() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//$'\n'/\\n}"
    printf '%s' "${value}"
}

local_fallback_pattern='^\[RCH\] local \(|local fallback|fallback to local|falling back to local|executing locally'

record_local_fallbacks() {
    local log_path="$1"
    local label="$2"
    local artifact_path="${ARTIFACT_DIR}/${label// /_}.txt"

    if grep -Eiq "$local_fallback_pattern" "$log_path" 2>/dev/null; then
        echo "  ERROR: rch local fallback detected in ${label}"
        grep -Ein "$local_fallback_pattern" "$log_path" | head -5 > "$artifact_path" 2>/dev/null || true
        ((LOCAL_FALLBACKS++)) || true
    fi
}

run_or_print() {
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        format_command "$@"
        printf '\n'
        return 0
    fi
    "$@"
}

echo "==================================================================="
echo "                   Asupersync Redis E2E Tests                      "
echo "==================================================================="
echo ""
echo "Config:"
echo "  REDIS_IMAGE:     ${REDIS_IMAGE}"
echo "  REDIS_PORT:      ${REDIS_PORT}"
echo "  TEST_LOG_LEVEL:  ${TEST_LOG_LEVEL}"
echo "  RUST_LOG:        ${RUST_LOG}"
echo "  TEST_SEED:       ${TEST_SEED}"
echo "  Output:          ${LOG_FILE}"
echo "  Artifacts:       ${ARTIFACT_DIR}"
echo "  Runner:          ${RCH_BIN} exec"
echo "  Target dir:      ${CARGO_TARGET_DIR}"
if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "  Mode:            dry-run"
fi
echo ""

cleanup() {
  echo ""
  echo ">>> Cleaning up docker container..."
  docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
}
if [[ "${DRY_RUN}" -eq 0 ]]; then
  trap cleanup EXIT
fi

# --- [1/4] Pre-flight: compilation check ---
echo ">>> [1/4] Pre-flight: checking compilation..."
CHECK_COMMAND=(
    "${RCH_BIN}"
    exec
    --
    env
    "CARGO_TARGET_DIR=${CARGO_TARGET_DIR}"
    "RUST_LOG=${RUST_LOG}"
    "RUST_BACKTRACE=${RUST_BACKTRACE}"
    "TEST_SEED=${TEST_SEED}"
    "${CARGO_BIN}"
    check
    --test
    e2e_redis
    --all-features
)
if ! run_or_print "${CHECK_COMMAND[@]}" 2>"${ARTIFACT_DIR}/compile_errors.log"; then
    echo "  FATAL: compilation failed — see ${ARTIFACT_DIR}/compile_errors.log"
    exit 1
fi
record_local_fallbacks "${ARTIFACT_DIR}/compile_errors.log" "compile local fallback"
if [[ "$LOCAL_FALLBACKS" -ne 0 ]]; then
    echo "  FATAL: rch local fallback detected during pre-flight; refusing local cargo execution"
    exit 86
fi
echo "  OK"

# --- [2/4] Start Redis and run tests ---
echo ""
echo ">>> [2/4] Starting Redis container..."

pick_free_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

start_redis() {
  local port="$1"
  docker run -d --name "${CONTAINER_NAME}" -p "127.0.0.1:${port}:6379" "${REDIS_IMAGE}" >/dev/null
}

if [[ "${DRY_RUN}" -eq 1 ]]; then
  echo ">>> Dry-run: skipping Redis container startup."
else
  docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true

  if ! start_redis "${REDIS_PORT}"; then
    echo ">>> Failed to bind ${REDIS_PORT}; retrying with a free port..."
    REDIS_PORT="$(pick_free_port)"
    docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
    start_redis "${REDIS_PORT}"
  fi
fi

echo ">>> Redis listening on 127.0.0.1:${REDIS_PORT}"

echo ">>> Waiting for Redis to become ready..."
READY=0
if [[ "${DRY_RUN}" -eq 1 ]]; then
  READY=1
else
  for i in $(seq 1 50); do
    if docker exec "${CONTAINER_NAME}" redis-cli ping >/dev/null 2>&1; then
      READY=1
      break
    fi
    sleep 0.1
  done

  if [[ "${READY}" -ne 1 ]]; then
    echo "ERROR: Redis did not become ready in time"
    docker logs "${CONTAINER_NAME}" || true
    exit 1
  fi
fi

export REDIS_URL="redis://127.0.0.1:${REDIS_PORT}"

echo ""
echo ">>> Running Redis E2E tests..."
TEST_RESULT=0
TEST_COMMAND=(
    "${RCH_BIN}"
    exec
    --
    env
    "CARGO_TARGET_DIR=${CARGO_TARGET_DIR}"
    "REDIS_URL=${REDIS_URL}"
    "TEST_LOG_LEVEL=${TEST_LOG_LEVEL}"
    "RUST_LOG=${RUST_LOG}"
    "RUST_BACKTRACE=${RUST_BACKTRACE}"
    "TEST_SEED=${TEST_SEED}"
    "${CARGO_BIN}"
    test
    --test
    e2e_redis
    --all-features
    --
    --nocapture
    --test-threads=1
)
if [[ "${DRY_RUN}" -eq 1 ]]; then
  format_command "${TEST_COMMAND[@]}" | tee "$LOG_FILE"
  TEST_RESULT=0
elif timeout 180 "${TEST_COMMAND[@]}" 2>&1 | tee "$LOG_FILE"; then
  TEST_RESULT=0
else
  TEST_RESULT=$?
fi

# --- [3/4] Failure pattern analysis ---
echo ""
echo ">>> [3/4] Checking output for failure patterns..."

PATTERN_FAILURES=0

check_pattern() {
    local pattern="$1"
    local label="$2"
    if grep -q "$pattern" "$LOG_FILE" 2>/dev/null; then
        echo "  ERROR: ${label}"
        grep -n "$pattern" "$LOG_FILE" | head -5 > "${ARTIFACT_DIR}/${label// /_}.txt" 2>/dev/null || true
        ((PATTERN_FAILURES++)) || true
    fi
}

check_pattern "test result: FAILED" "cargo reported failures"
check_pattern "deadlock"           "potential deadlock"
check_pattern "hung"               "potential hang"
check_pattern "timed out"          "timeout detected"
check_pattern "panicked at"        "panic detected"
record_local_fallbacks "$LOG_FILE" "test local fallback"

if [ "$PATTERN_FAILURES" -eq 0 ] && [ "$LOCAL_FALLBACKS" -eq 0 ]; then
    echo "  No failure patterns found"
fi

# --- [4/4] Artifact collection ---
echo ""
echo ">>> [4/4] Collecting artifacts..."

PASSED=$({ grep -c "^test .* ok$" "$LOG_FILE" 2>/dev/null || true; } | awk '{s+=$1} END {print s+0}')
FAILED=$({ grep -c "^test .* FAILED$" "$LOG_FILE" 2>/dev/null || true; } | awk '{s+=$1} END {print s+0}')
SUITE_ID="redis_e2e"
SCENARIO_ID="E2E-SUITE-REDIS"
SUMMARY_FILE="${ARTIFACT_DIR}/summary.json"
REPRO_COMMAND="REDIS_IMAGE=${REDIS_IMAGE} REDIS_PORT=${REDIS_PORT} TEST_LOG_LEVEL=${TEST_LOG_LEVEL} RUST_LOG=${RUST_LOG} TEST_SEED=${TEST_SEED} RCH_BIN=${RCH_BIN} CARGO_TARGET_DIR=${CARGO_TARGET_DIR} bash ${SCRIPT_DIR}/$(basename "$0")"
RUN_ENDED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SUITE_STATUS="failed"
if [[ "$TEST_RESULT" -eq 0 && "$PATTERN_FAILURES" -eq 0 && "$LOCAL_FALLBACKS" -eq 0 ]]; then
  SUITE_STATUS="passed"
fi
if [[ "${DRY_RUN}" -eq 1 ]]; then
  SUITE_STATUS="planned"
fi
DRY_RUN_JSON=false
if [[ "${DRY_RUN}" -eq 1 ]]; then
  DRY_RUN_JSON=true
fi
FAILURE_CLASS="test_or_pattern_failure"
if [[ "$SUITE_STATUS" == "passed" || "$SUITE_STATUS" == "planned" ]]; then
  FAILURE_CLASS="none"
elif [[ "$LOCAL_FALLBACKS" -ne 0 ]]; then
  FAILURE_CLASS="rch_local_fallback"
fi
RCH_ROUTED_JSON=true
if [[ "$LOCAL_FALLBACKS" -ne 0 ]]; then
  RCH_ROUTED_JSON=false
fi

cat > "${SUMMARY_FILE}" << ENDJSON
{
  "schema_version": "e2e-suite-summary-v3",
  "suite_id": "${SUITE_ID}",
  "scenario_id": "${SCENARIO_ID}",
  "seed": "${TEST_SEED}",
  "started_ts": "${RUN_STARTED_TS}",
  "ended_ts": "${RUN_ENDED_TS}",
  "status": "${SUITE_STATUS}",
  "failure_class": "${FAILURE_CLASS}",
  "dry_run": ${DRY_RUN_JSON},
  "runner": "rch exec",
  "all_rch_routed": ${RCH_ROUTED_JSON},
  "rch_local_fallbacks": ${LOCAL_FALLBACKS},
  "repro_command": "$(json_escape "${REPRO_COMMAND}")",
  "artifact_path": "$(json_escape "${SUMMARY_FILE}")",
  "suite": "${SUITE_ID}",
  "timestamp": "${TIMESTAMP}",
  "test_log_level": "$(json_escape "${TEST_LOG_LEVEL}")",
  "redis_image": "$(json_escape "${REDIS_IMAGE}")",
  "redis_port": ${REDIS_PORT},
  "tests_passed": ${PASSED},
  "tests_failed": ${FAILED},
  "exit_code": ${TEST_RESULT},
  "pattern_failures": ${PATTERN_FAILURES},
  "log_file": "$(json_escape "${LOG_FILE}")",
  "artifact_dir": "$(json_escape "${ARTIFACT_DIR}")"
}
ENDJSON

grep -oE "seed[= ]+0x[0-9a-fA-F]+" "$LOG_FILE" > "${ARTIFACT_DIR}/seeds.txt" 2>/dev/null || true
grep -oE "trace_fingerprint[= ]+[a-f0-9]+" "$LOG_FILE" > "${ARTIFACT_DIR}/traces.txt" 2>/dev/null || true

echo "127.0.0.1:${REDIS_PORT}" > "${ARTIFACT_DIR}/endpoints.txt"

echo "  Summary: ${SUMMARY_FILE}"

# --- Summary ---
echo ""
echo "==================================================================="
echo "                           SUMMARY                                 "
echo "==================================================================="
if [[ "${DRY_RUN}" -eq 1 ]]; then
  echo "Status: PLANNED"
  echo "Docker and Cargo were not executed."
elif [[ "$TEST_RESULT" -eq 0 && "$PATTERN_FAILURES" -eq 0 && "$LOCAL_FALLBACKS" -eq 0 ]]; then
  echo "Status: PASSED"
else
  echo "Status: FAILED"
  echo "See: ${LOG_FILE}"
  echo "Artifacts: ${ARTIFACT_DIR}"
fi
echo "==================================================================="

echo "Diagnostic artifacts are retained for auditability, including empty files."

if [[ "$TEST_RESULT" -ne 0 || "$PATTERN_FAILURES" -ne 0 || "$LOCAL_FALLBACKS" -ne 0 ]]; then
  exit 1
fi
