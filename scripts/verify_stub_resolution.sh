#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ARTIFACT_ROOT="${STUB_RESOLUTION_ARTIFACT_ROOT:-${PROJECT_ROOT}/artifacts/stub_resolution}"
SCAN_ARTIFACT_ROOT="${STUB_SCAN_ARTIFACT_ROOT:-${ARTIFACT_ROOT}}"
POINTER_SCHEMA="stub-resolution-suite-pointer-v1"
LATEST_POINTER="${ARTIFACT_ROOT}/latest.json"
LATEST_SUCCESS_POINTER="${ARTIFACT_ROOT}/latest_success.json"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${ARTIFACT_ROOT}/${RUN_ID}"

mkdir -p "$RUN_DIR"

STUB_SCAN_ARTIFACT_ROOT="$RUN_DIR" bash "$SCRIPT_DIR/scan_stubs.sh"

SUMMARY_PATH="${RUN_DIR}/stub_resolution_scan_summary.json"
EVENTS_PATH="${RUN_DIR}/stub_resolution_scan_events.ndjson"

verdict="$(
    jq -r '.verdict // "unknown"' "$SUMMARY_PATH"
)"

jq -nc \
    --arg schema_version "$POINTER_SCHEMA" \
    --arg run_id "$RUN_ID" \
    --arg summary_path "$SUMMARY_PATH" \
    --arg events_path "$EVENTS_PATH" \
    --arg verdict "$verdict" \
    '{
      schema_version: $schema_version,
      run_id: $run_id,
      summary_path: $summary_path,
      events_path: $events_path,
      verdict: $verdict
    }' >"$LATEST_POINTER"

if [[ "$verdict" == "passed" ]]; then
    cp "$LATEST_POINTER" "$LATEST_SUCCESS_POINTER"
fi

if [[ "$verdict" != "passed" ]]; then
    exit 1
fi
