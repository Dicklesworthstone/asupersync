#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

GIT_REV="$(git rev-parse --short HEAD)"
RCH_BIN="${RCH_BIN:-rch}"
REDIS_PUSH_TARGET_DIR="${REDIS_PUSH_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_redis_resp3_push_buffering}"
OUTPUT_ROOT="${REDIS_PUSH_OUTPUT_ROOT:-${PROJECT_ROOT}/target/e2e-results/redis_resp3_push_buffering}"
RUN_ID="${REDIS_PUSH_RUN_ID:-$(date -u +%Y%m%d_%H%M%S)}"
LOG_DIR="${OUTPUT_ROOT}/run_${RUN_ID}/logs"

if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
  echo "FATAL: rch is required and was not found at: ${RCH_BIN}" >&2
  exit 1
fi

mkdir -p "$LOG_DIR"

reject_rch_local_fallback_log() {
  local label="$1"
  local log_file="$2"
  local safe_label="${label//[^A-Za-z0-9_]/_}"

  if grep -Eq '^\[RCH\] local \(|falling back to local' "$log_file" 2>/dev/null; then
    echo "FATAL: rch local fallback detected in ${label}; refusing local cargo execution" >&2
    echo "rch local fallback detected in ${label}; refusing local cargo execution" > "${LOG_DIR}/${safe_label}.rch_local_fallback.txt"
    cat "$log_file"
    exit 86
  fi
}

run_step() {
  local label="$1"
  local feature_flags="$2"
  local test_filter="$3"
  shift 3
  local -a command_args=("$@")
  local command
  local log_file
  local safe_label="${label//[^A-Za-z0-9_]/_}"
  log_file="${LOG_DIR}/${safe_label}.log"
  : >"$log_file"
  local started_ms
  started_ms="$(date +%s%3N)"
  printf -v command '%q ' "${command_args[@]}"
  command="${command% }"

  printf 'START label="%s" git_rev="%s" feature_flags="%s" test_filter="%s" command="%s"\n' \
    "$label" "$GIT_REV" "$feature_flags" "$test_filter" "$command"

  if "${command_args[@]}" >"$log_file" 2>&1; then
    reject_rch_local_fallback_log "$label" "$log_file"
    local ended_ms elapsed_ms
    ended_ms="$(date +%s%3N)"
    elapsed_ms="$((ended_ms - started_ms))"
    printf 'PASS label="%s" git_rev="%s" feature_flags="%s" test_filter="%s" elapsed_ms="%s" log_file="%s" command="%s"\n' \
      "$label" "$GIT_REV" "$feature_flags" "$test_filter" "$elapsed_ms" "$log_file" "$command"
    return 0
  fi

  local ended_ms elapsed_ms first_failure
  reject_rch_local_fallback_log "$label" "$log_file"
  ended_ms="$(date +%s%3N)"
  elapsed_ms="$((ended_ms - started_ms))"
  first_failure="$(
    grep -n -m1 -E 'error\[|error:|FAILED|panicked at|test result: FAILED' "$log_file" \
      || sed -n '1p' "$log_file"
  )"
  printf 'FAIL label="%s" git_rev="%s" feature_flags="%s" test_filter="%s" elapsed_ms="%s" log_file="%s" first_failure="%s" command="%s"\n' \
    "$label" "$GIT_REV" "$feature_flags" "$test_filter" "$elapsed_ms" "$log_file" "${first_failure//\"/\\\"}" "$command"
  cat "$log_file"
  return 1
}

run_step \
  "rustfmt-check" \
  "-" \
  "src/messaging/redis.rs tests/redis_resp3_push_buffering.rs" \
  "$RCH_BIN" exec -- \
  rustfmt --edition 2024 --check src/messaging/redis.rs tests/redis_resp3_push_buffering.rs

run_step \
  "unit-redis-resp3-push" \
  "test-internals" \
  "redis_resp3_push" \
  "$RCH_BIN" exec -- \
  env \
  CARGO_INCREMENTAL=0 \
  CARGO_PROFILE_TEST_DEBUG=0 \
  "RUSTFLAGS=-D warnings -C debuginfo=0" \
  "CARGO_TARGET_DIR=${REDIS_PUSH_TARGET_DIR}" \
  cargo test -p asupersync --lib redis_resp3_push --features test-internals -- --nocapture --test-threads=1

run_step \
  "integration-redis-resp3-push-buffering" \
  "test-internals" \
  "redis_resp3_push_buffering" \
  "$RCH_BIN" exec -- \
  env \
  CARGO_INCREMENTAL=0 \
  CARGO_PROFILE_TEST_DEBUG=0 \
  "RUSTFLAGS=-D warnings -C debuginfo=0" \
  "CARGO_TARGET_DIR=${REDIS_PUSH_TARGET_DIR}" \
  cargo test -p asupersync --test redis_resp3_push_buffering --features test-internals -- --nocapture --test-threads=1
