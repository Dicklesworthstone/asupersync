#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

GIT_REV="$(git rev-parse --short HEAD)"

run_step() {
  local label="$1"
  local feature_flags="$2"
  local test_filter="$3"
  local command="$4"
  local log_file
  log_file="$(mktemp)"
  local started_ms
  started_ms="$(date +%s%3N)"

  printf 'START label="%s" git_rev="%s" feature_flags="%s" test_filter="%s" command="%s"\n' \
    "$label" "$GIT_REV" "$feature_flags" "$test_filter" "$command"

  if bash -lc "$command" >"$log_file" 2>&1; then
    local ended_ms elapsed_ms
    ended_ms="$(date +%s%3N)"
    elapsed_ms="$((ended_ms - started_ms))"
    printf 'PASS label="%s" git_rev="%s" feature_flags="%s" test_filter="%s" elapsed_ms="%s" command="%s"\n' \
      "$label" "$GIT_REV" "$feature_flags" "$test_filter" "$elapsed_ms" "$command"
    rm -f "$log_file"
    return 0
  fi

  local ended_ms elapsed_ms first_failure
  ended_ms="$(date +%s%3N)"
  elapsed_ms="$((ended_ms - started_ms))"
  first_failure="$(
    grep -n -m1 -E 'error\\[|error:|FAILED|panicked at|test result: FAILED' "$log_file" \
      || sed -n '1p' "$log_file"
  )"
  printf 'FAIL label="%s" git_rev="%s" feature_flags="%s" test_filter="%s" elapsed_ms="%s" first_failure="%s" command="%s"\n' \
    "$label" "$GIT_REV" "$feature_flags" "$test_filter" "$elapsed_ms" "${first_failure//\"/\\\"}" "$command"
  cat "$log_file"
  rm -f "$log_file"
  return 1
}

run_step \
  "rustfmt-check" \
  "-" \
  "src/messaging/redis.rs tests/redis_resp3_push_buffering.rs" \
  "rch exec -- rustfmt --edition 2024 --check src/messaging/redis.rs tests/redis_resp3_push_buffering.rs"

run_step \
  "unit-redis-resp3-push" \
  "test-internals" \
  "redis_resp3_push" \
  "rch exec -- cargo test -p asupersync --lib redis_resp3_push --features test-internals -- --nocapture"

run_step \
  "integration-redis-resp3-push-buffering" \
  "test-internals" \
  "redis_resp3_push_buffering" \
  "rch exec -- cargo test -p asupersync --test redis_resp3_push_buffering --features test-internals -- --nocapture"
