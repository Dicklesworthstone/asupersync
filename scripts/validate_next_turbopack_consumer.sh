#!/usr/bin/env bash
set -euo pipefail

# bead: asupersync-3qv04.6.3

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
FIXTURE_DIR="${REPO_ROOT}/tests/fixtures/next-turbopack-consumer"
RESULT_ROOT="${REPO_ROOT}/target/e2e-results/next_turbopack_consumer"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${RESULT_ROOT}/${TIMESTAMP}"
LOG_FILE="${RUN_DIR}/consumer_build.log"
SUMMARY_FILE="${RUN_DIR}/summary.json"

mkdir -p "${RUN_DIR}"

require_cmd() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "FATAL: required command not found: ${cmd}" >&2
    exit 1
  fi
}

require_cmd nodejs
require_cmd npm
require_cmd python3

if [[ ! -d "${FIXTURE_DIR}" ]]; then
  echo "FATAL: fixture missing: ${FIXTURE_DIR}" >&2
  exit 1
fi

MISSING_ARTIFACTS=0
for required in \
  "packages/browser-core/asupersync.js" \
  "packages/browser-core/asupersync_bg.wasm" \
  "packages/browser-core/abi-metadata.json" \
  "packages/browser/dist/index.js" \
  "packages/browser/dist/index.d.ts" \
  "packages/next/dist/index.js" \
  "packages/next/dist/index.d.ts"
do
  if [[ ! -f "${REPO_ROOT}/${required}" ]]; then
    echo "MISSING: ${required}" >&2
    MISSING_ARTIFACTS=$((MISSING_ARTIFACTS + 1))
  fi
done

if [[ "${MISSING_ARTIFACTS}" -gt 0 ]]; then
  cat >&2 <<'MISSING_EOF'
FATAL: required packaged Browser Edition artifacts are missing.

Build and stage package artifacts first, then rerun:
  PATH=/usr/bin:$PATH corepack pnpm run build

This consumer validation intentionally runs only against built package outputs.
MISSING_EOF
  exit 1
fi

WORK_DIR="$(mktemp -d "${RUN_DIR}/work.XXXXXX")"
CONSUMER_DIR="${WORK_DIR}/consumer"
PKG_DIR="${WORK_DIR}/packages"

mkdir -p "${CONSUMER_DIR}" "${PKG_DIR}"
cp -R "${FIXTURE_DIR}/." "${CONSUMER_DIR}/"
cp -R "${REPO_ROOT}/packages/browser-core" "${PKG_DIR}/browser-core"
cp -R "${REPO_ROOT}/packages/browser" "${PKG_DIR}/browser"
cp -R "${REPO_ROOT}/packages/next" "${PKG_DIR}/next"

# Consumer installs from local package copies; rewrite workspace protocol so npm can resolve.
python3 - "${CONSUMER_DIR}/package.json" "${PKG_DIR}/browser/package.json" "${PKG_DIR}/next/package.json" <<'PY'
import json
import pathlib
import sys

consumer_path = pathlib.Path(sys.argv[1])
browser_path = pathlib.Path(sys.argv[2])
next_path = pathlib.Path(sys.argv[3])

consumer_data = json.loads(consumer_path.read_text())
consumer_deps = consumer_data.setdefault("dependencies", {})
consumer_deps["@asupersync/next"] = "file:../packages/next"
consumer_deps["@asupersync/browser"] = "file:../packages/browser"
consumer_deps["@asupersync/browser-core"] = "file:../packages/browser-core"
consumer_path.write_text(json.dumps(consumer_data, indent=2) + "\n")

browser_data = json.loads(browser_path.read_text())
browser_deps = browser_data.setdefault("dependencies", {})
browser_deps["@asupersync/browser-core"] = "file:../browser-core"
browser_path.write_text(json.dumps(browser_data, indent=2) + "\n")

next_data = json.loads(next_path.read_text())
next_deps = next_data.setdefault("dependencies", {})
next_deps["@asupersync/browser"] = "file:../browser"
next_path.write_text(json.dumps(next_data, indent=2) + "\n")
PY

(
  cd "${CONSUMER_DIR}"
  PATH="/usr/bin:${PATH}" npm install --no-audit --no-fund
  PATH="/usr/bin:${PATH}" npm run build
  PATH="/usr/bin:${PATH}" npm run check:bundle
) | tee "${LOG_FILE}"

python3 - "${CONSUMER_DIR}" "${SUMMARY_FILE}" "${TIMESTAMP}" <<'PY'
import json
import pathlib
import sys

consumer = pathlib.Path(sys.argv[1])
summary_path = pathlib.Path(sys.argv[2])
timestamp = sys.argv[3]
next_dir = consumer / ".next"
build_id = next_dir / "BUILD_ID"
summary = {
    "scenario_id": "L6-BUNDLER-NEXT-TURBOPACK",
    "timestamp": timestamp,
    "fixture": "tests/fixtures/next-turbopack-consumer",
    "status": "pass",
    "checks": {
        "next_dir_exists": next_dir.exists(),
        "build_id_exists": build_id.exists(),
        "standalone_dir_exists": (next_dir / "standalone").exists(),
    },
}
summary_path.write_text(json.dumps(summary, indent=2) + "\n")
PY

cat <<EOF2
Next/Turbopack consumer validation passed.
Artifacts:
  log: ${LOG_FILE}
  summary: ${SUMMARY_FILE}
EOF2
