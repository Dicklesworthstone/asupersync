#!/usr/bin/env bash
set -euo pipefail

log() {
  printf '[audit-index-append-e2e] %s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HELPER="${ROOT_DIR}/scripts/audit_index_append.py"
ARTIFACT_DIR="${TMPDIR:-/tmp}/audit_index_append_e2e_$$_$(date -u +%Y%m%dT%H%M%SZ)"
TARGET="${ARTIFACT_DIR}/audit_index.copy.jsonl"
ORIGINAL_COPY="${ARTIFACT_DIR}/audit_index.original.jsonl"
PARALLEL_TARGET="${ARTIFACT_DIR}/audit_index.parallel.jsonl"
BAD_TARGET="${ARTIFACT_DIR}/missing-newline.jsonl"
DRY_RUN_OUT="${ARTIFACT_DIR}/dry-run-row.json"
PARALLEL_ONE_OUT="${ARTIFACT_DIR}/parallel-one.out"
PARALLEL_TWO_OUT="${ARTIFACT_DIR}/parallel-two.out"
BAD_ERR="${ARTIFACT_DIR}/bad-row.stderr"

log "repo=${ROOT_DIR}"
log "artifact_dir=${ARTIFACT_DIR}"
mkdir -p "${ARTIFACT_DIR}"

if [[ -f "${ROOT_DIR}/audit_index.jsonl" ]]; then
  cp "${ROOT_DIR}/audit_index.jsonl" "${TARGET}"
else
  : > "${TARGET}"
fi
cp "${TARGET}" "${ORIGINAL_COPY}"

ORIGINAL_BYTES="$(wc -c < "${TARGET}" | tr -d ' ')"
ORIGINAL_LINES="$(wc -l < "${TARGET}" | tr -d ' ')"
log "copied audit_index bytes=${ORIGINAL_BYTES} lines=${ORIGINAL_LINES}"

python3 "${HELPER}" --self-test --self-test-dir "${ARTIFACT_DIR}/helper-self-test"

python3 "${HELPER}" --index "${TARGET}" --dry-run \
  --file src/example_lock_light_one.rs \
  --lines 11 \
  --batch asupersync-67t6xn-e2e-a \
  --date 2026-05-22 \
  --agent E2EAgentOne \
  --verdict SOUND \
  --bugs 0 \
  --notes "first disjoint append row" > "${DRY_RUN_OUT}"
log "dry_run_row=$(cat "${DRY_RUN_OUT}")"

python3 "${HELPER}" --index "${TARGET}" \
  --file src/example_lock_light_one.rs \
  --lines 11 \
  --batch asupersync-67t6xn-e2e-a \
  --date 2026-05-22 \
  --agent E2EAgentOne \
  --verdict SOUND \
  --bugs 0 \
  --notes "first disjoint append row" >/dev/null

python3 "${HELPER}" --index "${TARGET}" \
  --file src/example_lock_light_two.rs \
  --lines 22 \
  --batch asupersync-67t6xn-e2e-b \
  --date 2026-05-22 \
  --agent E2EAgentTwo \
  --verdict FIXED \
  --bugs 1 \
  --notes "second disjoint append row" >/dev/null

POST_LINES="$(wc -l < "${TARGET}" | tr -d ' ')"
EXPECTED_LINES="$((ORIGINAL_LINES + 2))"
log "post_append_lines=${POST_LINES} expected=${EXPECTED_LINES}"
if [[ "${POST_LINES}" != "${EXPECTED_LINES}" ]]; then
  log "line count invariant failed"
  exit 1
fi

python3 - "${TARGET}" "${ORIGINAL_COPY}" "${ORIGINAL_BYTES}" <<'PY'
import json
import sys
from pathlib import Path

target = Path(sys.argv[1])
original = Path(sys.argv[2])
original_bytes = int(sys.argv[3])
data = target.read_bytes()
expected_prefix = original.read_bytes()
if len(expected_prefix) != original_bytes:
    raise SystemExit("original byte-count invariant failed")
if data[:original_bytes] != expected_prefix:
    raise SystemExit("append changed existing prefix bytes")
lines = target.read_text(encoding="utf-8").splitlines()
tail = [json.loads(line) for line in lines[-2:]]
if [row["file"] for row in tail] != [
    "src/example_lock_light_one.rs",
    "src/example_lock_light_two.rs",
]:
    raise SystemExit(f"unexpected tail rows: {tail!r}")
if tail[0]["verdict"] != "SOUND" or tail[1]["verdict"] != "FIXED":
    raise SystemExit(f"unexpected verdicts: {tail!r}")
print("tail rows validated")
PY

if python3 "${HELPER}" --index "${TARGET}" \
  --file src/bad.rs \
  --lines 1 \
  --batch asupersync-67t6xn-e2e-bad \
  --date 2026-05-22 \
  --agent E2EAgentBad \
  --verdict SOUND \
  --bugs 1 \
  --notes "this row must fail" 2> "${BAD_ERR}"; then
  log "invalid SOUND/bugs row unexpectedly passed"
  exit 1
fi
log "invalid_row_error=$(cat "${BAD_ERR}")"

cp "${ORIGINAL_COPY}" "${PARALLEL_TARGET}"
log "starting two concurrent append helper processes"
python3 "${HELPER}" --index "${PARALLEL_TARGET}" \
  --file src/example_parallel_one.rs \
  --lines 33 \
  --batch asupersync-67t6xn-e2e-parallel-a \
  --date 2026-05-22 \
  --agent E2EParallelOne \
  --verdict SOUND \
  --bugs 0 \
  --notes "parallel append row one" > "${PARALLEL_ONE_OUT}" &
PID_ONE="$!"
python3 "${HELPER}" --index "${PARALLEL_TARGET}" \
  --file src/example_parallel_two.rs \
  --lines 44 \
  --batch asupersync-67t6xn-e2e-parallel-b \
  --date 2026-05-22 \
  --agent E2EParallelTwo \
  --verdict SOUND \
  --bugs 0 \
  --notes "parallel append row two" > "${PARALLEL_TWO_OUT}" &
PID_TWO="$!"
wait "${PID_ONE}"
wait "${PID_TWO}"
log "parallel_one_row=$(cat "${PARALLEL_ONE_OUT}")"
log "parallel_two_row=$(cat "${PARALLEL_TWO_OUT}")"

PARALLEL_LINES="$(wc -l < "${PARALLEL_TARGET}" | tr -d ' ')"
if [[ "${PARALLEL_LINES}" != "${EXPECTED_LINES}" ]]; then
  log "parallel line count invariant failed: actual=${PARALLEL_LINES} expected=${EXPECTED_LINES}"
  exit 1
fi

python3 - "${PARALLEL_TARGET}" "${ORIGINAL_COPY}" "${ORIGINAL_BYTES}" <<'PY'
import json
import sys
from pathlib import Path

target = Path(sys.argv[1])
original = Path(sys.argv[2])
original_bytes = int(sys.argv[3])
data = target.read_bytes()
expected_prefix = original.read_bytes()
if len(expected_prefix) != original_bytes:
    raise SystemExit("parallel original byte-count invariant failed")
if data[:original_bytes] != expected_prefix:
    raise SystemExit("parallel append changed existing prefix bytes")
lines = target.read_text(encoding="utf-8").splitlines()
tail = [json.loads(line) for line in lines[-2:]]
files = sorted(row["file"] for row in tail)
if files != ["src/example_parallel_one.rs", "src/example_parallel_two.rs"]:
    raise SystemExit(f"unexpected parallel tail rows: {tail!r}")
print("parallel tail rows validated")
PY

printf '{"legacy":true}' > "${BAD_TARGET}"
if python3 "${HELPER}" --index "${BAD_TARGET}" \
  --file src/no_newline.rs \
  --lines 1 \
  --batch asupersync-67t6xn-e2e-newline \
  --date 2026-05-22 \
  --agent E2EAgentNewline \
  --verdict SOUND \
  --bugs 0 \
  --notes "this target must fail" 2>> "${BAD_ERR}"; then
  log "missing-newline target unexpectedly passed"
  exit 1
fi

log "append-only helper e2e passed"
log "artifacts retained at ${ARTIFACT_DIR}"
