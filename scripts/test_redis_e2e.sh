#!/usr/bin/env bash
# Redis E2E Test Runner (bd-9vfn, enriched bd-26l3)
#
# Starts a local Redis container, runs the Redis E2E integration tests, and
# saves structured artifacts under target/e2e-results/.
#
# Usage:
#   ./scripts/test_redis_e2e.sh
#
# Environment Variables:
#   REDIS_IMAGE    - Docker image (default: redis:7)
#   REDIS_PORT     - Host port to bind (default: 6379)
#   TEST_LOG_LEVEL - error|warn|info|debug|trace (default: trace)
#   RUST_LOG       - tracing filter (default: asupersync=debug)
#   RUST_BACKTRACE - 1 to enable backtraces (default: 1)
#   TEST_SEED      - deterministic seed override (default: 0xDEADBEEF)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="${PROJECT_ROOT}/target/e2e-results/redis"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
LOG_FILE="${OUTPUT_DIR}/redis_e2e_${TIMESTAMP}.log"
ARTIFACT_DIR="${OUTPUT_DIR}/artifacts_${TIMESTAMP}"

export REDIS_IMAGE="${REDIS_IMAGE:-redis:7}"
export REDIS_PORT="${REDIS_PORT:-6379}"

export TEST_LOG_LEVEL="${TEST_LOG_LEVEL:-trace}"
export RUST_LOG="${RUST_LOG:-asupersync=debug}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export TEST_SEED="${TEST_SEED:-0xDEADBEEF}"

CONTAINER_NAME="asupersync_redis_e2e"

mkdir -p "$OUTPUT_DIR" "$ARTIFACT_DIR"

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
echo ""

cleanup() {
  echo ""
  echo ">>> Cleaning up docker container..."
  docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# --- [1/4] Pre-flight: compilation check ---
echo ">>> [1/4] Pre-flight: checking compilation..."
if ! cargo check --test e2e_redis --all-features 2>"${ARTIFACT_DIR}/compile_errors.log"; then
    echo "  FATAL: compilation failed — see ${ARTIFACT_DIR}/compile_errors.log"
    exit 1
fi
echo "  OK"

# --- [2/4] Start Redis and run tests ---
echo ""
echo ">>> [2/4] Starting Redis container..."

docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true

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

if ! start_redis "${REDIS_PORT}"; then
  echo ">>> Failed to bind ${REDIS_PORT}; retrying with a free port..."
  REDIS_PORT="$(pick_free_port)"
  docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
  start_redis "${REDIS_PORT}"
fi

echo ">>> Redis listening on 127.0.0.1:${REDIS_PORT}"

echo ">>> Waiting for Redis to become ready..."
READY=0
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

export REDIS_URL="redis://127.0.0.1:${REDIS_PORT}"

echo ""
echo ">>> Running Redis E2E tests..."
TEST_RESULT=0
if timeout 180 cargo test --test e2e_redis --all-features -- --nocapture --test-threads=1 2>&1 | tee "$LOG_FILE"; then
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

if [ "$PATTERN_FAILURES" -eq 0 ]; then
    echo "  No failure patterns found"
fi

# --- [4/4] Artifact collection ---
echo ""
echo ">>> [4/4] Collecting artifacts..."

PASSED=$(grep -c "^test .* ok$" "$LOG_FILE" 2>/dev/null || echo "0")
FAILED=$(grep -c "^test .* FAILED$" "$LOG_FILE" 2>/dev/null || echo "0")

cat > "${ARTIFACT_DIR}/summary.json" << ENDJSON
{
  "suite": "redis_e2e",
  "timestamp": "${TIMESTAMP}",
  "seed": "${TEST_SEED}",
  "test_log_level": "${TEST_LOG_LEVEL}",
  "redis_image": "${REDIS_IMAGE}",
  "redis_port": ${REDIS_PORT},
  "tests_passed": ${PASSED},
  "tests_failed": ${FAILED},
  "exit_code": ${TEST_RESULT},
  "pattern_failures": ${PATTERN_FAILURES},
  "log_file": "${LOG_FILE}",
  "artifact_dir": "${ARTIFACT_DIR}"
}
ENDJSON

grep -oE "seed[= ]+0x[0-9a-fA-F]+" "$LOG_FILE" > "${ARTIFACT_DIR}/seeds.txt" 2>/dev/null || true
grep -oE "trace_fingerprint[= ]+[a-f0-9]+" "$LOG_FILE" > "${ARTIFACT_DIR}/traces.txt" 2>/dev/null || true

echo "127.0.0.1:${REDIS_PORT}" > "${ARTIFACT_DIR}/endpoints.txt"

echo "  Summary: ${ARTIFACT_DIR}/summary.json"

# --- Summary ---
echo ""
echo "==================================================================="
echo "                           SUMMARY                                 "
echo "==================================================================="
if [[ "$TEST_RESULT" -eq 0 && "$PATTERN_FAILURES" -eq 0 ]]; then
  echo "Status: PASSED"
else
  echo "Status: FAILED"
  echo "See: ${LOG_FILE}"
  echo "Artifacts: ${ARTIFACT_DIR}"
fi
echo "==================================================================="

find "$ARTIFACT_DIR" -name "*.txt" -empty -delete 2>/dev/null || true

if [[ "$TEST_RESULT" -ne 0 || "$PATTERN_FAILURES" -ne 0 ]]; then
  exit 1
fi
