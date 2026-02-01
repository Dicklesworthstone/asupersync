#!/usr/bin/env bash
# Redis E2E Test Runner (bd-9vfn)
#
# Starts a local Redis container, runs the Redis E2E integration tests, and
# saves logs under target/e2e-results/.
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

set -euo pipefail

OUTPUT_DIR="target/e2e-results"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
LOG_FILE="${OUTPUT_DIR}/redis_e2e_${TIMESTAMP}.log"

export REDIS_IMAGE="${REDIS_IMAGE:-redis:7}"
export REDIS_PORT="${REDIS_PORT:-6379}"

export TEST_LOG_LEVEL="${TEST_LOG_LEVEL:-trace}"
export RUST_LOG="${RUST_LOG:-asupersync=debug}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"

CONTAINER_NAME="asupersync_redis_e2e"

mkdir -p "$OUTPUT_DIR"

echo "==================================================================="
echo "                   Asupersync Redis E2E Tests                      "
echo "==================================================================="
echo ""
echo "Config:"
echo "  REDIS_IMAGE:     ${REDIS_IMAGE}"
echo "  REDIS_PORT:      ${REDIS_PORT}"
echo "  TEST_LOG_LEVEL:  ${TEST_LOG_LEVEL}"
echo "  RUST_LOG:        ${RUST_LOG}"
echo "  Output:          ${LOG_FILE}"
echo ""

cleanup() {
  echo ""
  echo ">>> Cleaning up docker container..."
  docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo ">>> Starting Redis container..."
docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true

pick_free_port() {
  # Uses Python because it is widely available and avoids platform-specific `lsof`/`ss` parsing.
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

run_tests() {
  echo ">>> Running: cargo test --test e2e_redis ..."
  if timeout 180 cargo test --test e2e_redis -- --nocapture --test-threads=1 2>&1 | tee "$LOG_FILE"; then
    return 0
  fi
  return 1
}

check_failure_patterns() {
  local failures=0

  echo ""
  echo ">>> Checking output for suspicious patterns..."

  if grep -q "test result: FAILED" "$LOG_FILE" 2>/dev/null; then
    echo "  ERROR: cargo reported failures"
    ((failures++))
  fi

  if grep -qiE "(deadlock|hung|timed out|timeout)" "$LOG_FILE" 2>/dev/null; then
    echo "  WARNING: potential hang/timeout text detected"
    grep -iE "(deadlock|hung|timed out|timeout)" "$LOG_FILE" | head -n 10 || true
    ((failures++))
  fi

  return $failures
}

TEST_RESULT=0
run_tests || TEST_RESULT=$?

PATTERN_RESULT=0
check_failure_patterns || PATTERN_RESULT=$?

echo ""
echo "==================================================================="
echo "                           SUMMARY                                 "
echo "==================================================================="
if [[ "$TEST_RESULT" -eq 0 && "$PATTERN_RESULT" -eq 0 ]]; then
  echo "Status: PASSED"
else
  echo "Status: FAILED"
  echo "See: ${LOG_FILE}"
fi
echo "==================================================================="

if [[ "$TEST_RESULT" -ne 0 || "$PATTERN_RESULT" -ne 0 ]]; then
  exit 1
fi
