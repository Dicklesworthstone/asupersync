#!/usr/bin/env bash
set -euo pipefail

# bead: asupersync-3qv04.9.3.2

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
FIXTURE_DIR="${REPO_ROOT}/tests/fixtures/react-consumer"
RESULT_ROOT="${REPO_ROOT}/target/e2e-results/react_consumer"
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
  "packages/react/dist/index.js" \
  "packages/react/dist/index.d.ts"
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
cp -R "${REPO_ROOT}/packages/react" "${PKG_DIR}/react"

# Consumer installs from local package copies; rewrite workspace protocol so npm can resolve.
python3 - "${CONSUMER_DIR}/package.json" "${PKG_DIR}/browser/package.json" "${PKG_DIR}/react/package.json" <<'PY'
import json
import pathlib
import sys

consumer_pkg = pathlib.Path(sys.argv[1])
browser_pkg = pathlib.Path(sys.argv[2])
react_pkg = pathlib.Path(sys.argv[3])

consumer_data = json.loads(consumer_pkg.read_text())
consumer_deps = consumer_data.setdefault("dependencies", {})
consumer_deps["@asupersync/react"] = "file:../packages/react"
consumer_deps["@asupersync/browser"] = "file:../packages/browser"
consumer_deps["@asupersync/browser-core"] = "file:../packages/browser-core"
consumer_pkg.write_text(json.dumps(consumer_data, indent=2) + "\n")

browser_data = json.loads(browser_pkg.read_text())
browser_deps = browser_data.setdefault("dependencies", {})
browser_deps["@asupersync/browser-core"] = "file:../browser-core"
browser_pkg.write_text(json.dumps(browser_data, indent=2) + "\n")

react_data = json.loads(react_pkg.read_text())
react_deps = react_data.setdefault("dependencies", {})
react_deps["@asupersync/browser"] = "file:../browser"
react_pkg.write_text(json.dumps(react_data, indent=2) + "\n")
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
dist = consumer / "dist"
assets = dist / "assets"
summary = {
    "scenario_id": "L9-EXAMPLE-REACT",
    "timestamp": timestamp,
    "fixture": "tests/fixtures/react-consumer",
    "status": "pass",
    "checks": {
        "dist_exists": dist.exists(),
        "index_html_exists": (dist / "index.html").exists(),
        "asset_js_count": len(
            [p for p in assets.glob("*") if p.suffix in {".js", ".mjs"}]
        )
        if assets.exists()
        else 0,
    },
}
summary_path.write_text(json.dumps(summary, indent=2) + "\n")
PY

cat <<EOF2
React consumer validation passed.
Artifacts:
  log: ${LOG_FILE}
  summary: ${SUMMARY_FILE}
EOF2
