#!/usr/bin/env bash
set -euo pipefail

# bead: asupersync-n6kwt.6.2

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
FIXTURE_DIR="${REPO_ROOT}/tests/fixtures/shared-worker-consumer"
RESULT_ROOT="${REPO_ROOT}/target/e2e-results/shared_worker_consumer"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${RESULT_ROOT}/${TIMESTAMP}"
LOG_FILE="${RUN_DIR}/consumer_build.log"
SUMMARY_FILE="${RUN_DIR}/summary.json"
BROWSER_RUN_FILE="${RUN_DIR}/browser-run.json"

mkdir -p "${RUN_DIR}"

require_cmd() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "FATAL: required command not found: ${cmd}" >&2
    exit 1
  fi
}

require_cmd node
require_cmd npm
require_cmd npx
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
  "packages/browser/dist/index.d.ts"
do
  if [[ ! -f "${REPO_ROOT}/${required}" ]]; then
    echo "MISSING: ${required}" >&2
    MISSING_ARTIFACTS=$((MISSING_ARTIFACTS + 1))
  fi
done

if [[ "${MISSING_ARTIFACTS}" -gt 0 ]]; then
  cat >&2 <<'EOF'
FATAL: required packaged Browser Edition artifacts are missing.

Build and stage package artifacts first, then rerun:
  PATH=/usr/bin:$PATH corepack pnpm run build

This SharedWorker validation intentionally runs only against built package outputs.
EOF
  exit 1
fi

WORK_DIR="$(mktemp -d "/tmp/asupersync-shared-worker.XXXXXX")"
CONSUMER_DIR="${WORK_DIR}/consumer"
PKG_DIR="${WORK_DIR}/packages"

mkdir -p "${CONSUMER_DIR}" "${PKG_DIR}"
cp -R "${FIXTURE_DIR}/." "${CONSUMER_DIR}/"
cp -R "${REPO_ROOT}/packages/browser-core" "${PKG_DIR}/browser-core"
cp -R "${REPO_ROOT}/packages/browser" "${PKG_DIR}/browser"

python3 - "${CONSUMER_DIR}/package.json" "${PKG_DIR}/browser/package.json" <<'PY'
import json
import pathlib
import sys

consumer_pkg = pathlib.Path(sys.argv[1])
browser_pkg = pathlib.Path(sys.argv[2])

consumer_data = json.loads(consumer_pkg.read_text())
consumer_deps = consumer_data.setdefault("dependencies", {})
consumer_deps["@asupersync/browser"] = "file:../packages/browser"
consumer_deps["@asupersync/browser-core"] = "file:../packages/browser-core"
consumer_pkg.write_text(json.dumps(consumer_data, indent=2) + "\n")

browser_data = json.loads(browser_pkg.read_text())
browser_deps = browser_data.setdefault("dependencies", {})
browser_deps["@asupersync/browser-core"] = "file:../browser-core"
browser_pkg.write_text(json.dumps(browser_data, indent=2) + "\n")
PY

(
  cd "${CONSUMER_DIR}"
  PATH="/usr/bin:${PATH}" npm install --no-audit --no-fund
  PATH="/usr/bin:${PATH}" npm run build
  PATH="/usr/bin:${PATH}" npm run check:bundle
  PATH="/usr/bin:${PATH}" npm run check:browser -- "${BROWSER_RUN_FILE}"
) | tee "${LOG_FILE}"

python3 - "${CONSUMER_DIR}" "${SUMMARY_FILE}" "${TIMESTAMP}" "${BROWSER_RUN_FILE}" <<'PY'
import json
import pathlib
import sys

consumer = pathlib.Path(sys.argv[1])
summary_path = pathlib.Path(sys.argv[2])
timestamp = sys.argv[3]
browser_run_path = pathlib.Path(sys.argv[4])
dist = consumer / "dist"
browser_run = json.loads(browser_run_path.read_text())

js_assets = sorted(
    path
    for path in dist.rglob("*")
    if path.is_file() and path.suffix in {".js", ".mjs", ".ts"}
)

markers = {
    "baseline_marker": False,
    "reuse_marker": False,
    "protocol_mismatch_marker": False,
    "crash_fallback_marker": False,
    "client_churn_marker": False,
    "crash_recovery_marker": False,
    "attach_marker": False,
    "topology_marker": False,
    "coordinator_protocol_mismatch_marker": False,
    "coordinator_crash_marker": False,
    "coordinator_detach_marker": False,
}

for asset in js_assets:
    content = asset.read_text(encoding="utf-8", errors="replace")
    markers["baseline_marker"] |= "shared-worker-selection-baseline" in content
    markers["reuse_marker"] |= "shared-worker-selection-reuse" in content
    markers["protocol_mismatch_marker"] |= (
        "shared-worker-selection-protocol-mismatch" in content
    )
    markers["crash_fallback_marker"] |= (
        "shared-worker-selection-crash-fallback" in content
    )
    markers["client_churn_marker"] |= (
        "shared-worker-selection-client-churn" in content
    )
    markers["crash_recovery_marker"] |= (
        "shared-worker-selection-crash-recovery" in content
    )
    markers["attach_marker"] |= "shared-worker-coordinator-attach" in content
    markers["topology_marker"] |= (
        "shared-worker-coordinator-topology-snapshot" in content
    )
    markers["coordinator_protocol_mismatch_marker"] |= (
        "shared-worker-coordinator-protocol-mismatch" in content
    )
    markers["coordinator_crash_marker"] |= (
        "shared-worker-coordinator-crash-before-handshake" in content
    )
    markers["coordinator_detach_marker"] |= (
        "shared-worker-coordinator-detach" in content
    )

summary = {
    "scenario_id": "L6-SHARED-WORKER-COORDINATOR",
    "timestamp": timestamp,
    "fixture": "tests/fixtures/shared-worker-consumer",
    "status": "pass",
    "checks": {
        "dist_exists": dist.exists(),
        "index_html_exists": (dist / "index.html").exists(),
        "asset_js_count": len(js_assets),
        "real_browser_run_ok": browser_run["status"] == "ok",
        "browser_scenario_id": browser_run["scenario_id"],
        "reuse_page_one_mode": browser_run["reuse_page_one_mode"],
        "reuse_page_two_mode": browser_run["reuse_page_two_mode"],
        "reuse_page_one_client_count": browser_run["reuse_page_one_client_count"],
        "reuse_page_two_client_count": browser_run["reuse_page_two_client_count"],
        "reuse_attach_count": browser_run["reuse_page_one_attach_count"],
        "reuse_worker_name": browser_run["reuse_worker_name"],
        "reuse_client_ids": browser_run["reuse_client_ids"],
        "reuse_page_one_direct_execution_reason_code": browser_run["reuse_page_one_direct_execution_reason_code"],
        "reuse_page_two_direct_execution_reason_code": browser_run["reuse_page_two_direct_execution_reason_code"],
        "mismatch_mode": browser_run["mismatch_mode"],
        "mismatch_reason": browser_run["mismatch_reason"],
        "mismatch_fallback_lane_id": browser_run["mismatch_fallback_lane_id"],
        "mismatch_direct_execution_reason_code": browser_run["mismatch_direct_execution_reason_code"],
        "crash_mode": browser_run["crash_mode"],
        "crash_reason": browser_run["crash_reason"],
        "crash_fallback_lane_id": browser_run["crash_fallback_lane_id"],
        "crash_direct_execution_reason_code": browser_run["crash_direct_execution_reason_code"],
        "churn_mode": browser_run["churn_mode"],
        "churn_worker_name": browser_run["churn_worker_name"],
        "churn_client_ids": browser_run["churn_client_ids"],
        "churn_attach_count": browser_run["churn_attach_count"],
        "churn_direct_execution_reason_code": browser_run["churn_direct_execution_reason_code"],
        "recovery_mode": browser_run["recovery_mode"],
        "recovery_worker_name": browser_run["recovery_worker_name"],
        "recovery_client_ids": browser_run["recovery_client_ids"],
        "recovery_attach_count": browser_run["recovery_attach_count"],
        "recovery_direct_execution_reason_code": browser_run["recovery_direct_execution_reason_code"],
        "close_lifecycle_states": browser_run["close_lifecycle_states"],
        "churn_close_lifecycle_state": browser_run["churn_close_lifecycle_state"],
        "recovery_close_lifecycle_state": browser_run["recovery_close_lifecycle_state"],
        **markers,
    },
    "scenario_inventory": browser_run["scenario_inventory"],
}
summary_path.write_text(json.dumps(summary, indent=2) + "\n")
PY

cat <<EOF
Shared-worker coordinator consumer validation passed.
Artifacts:
  log: ${LOG_FILE}
  browser run: ${BROWSER_RUN_FILE}
  summary: ${SUMMARY_FILE}
EOF
