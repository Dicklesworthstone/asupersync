#!/usr/bin/env bash
set -euo pipefail

# bead: asupersync-n6kwt.7.2

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
FIXTURE_DIR="${REPO_ROOT}/tests/fixtures/service-worker-broker-consumer"
RESULT_ROOT="${REPO_ROOT}/target/e2e-results/service_worker_broker_consumer"
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

This service-worker broker validation intentionally runs only against built
package outputs.
EOF
  exit 1
fi

WORK_DIR="$(mktemp -d "/tmp/asupersync-service-worker-broker.XXXXXX")"
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

js_assets = sorted(
    path
    for path in dist.rglob("*")
    if path.is_file() and path.suffix in {".js", ".mjs"}
)
browser_run = json.loads(browser_run_path.read_text())

markers = {
    "bootstrap_marker": False,
    "registration_marker": False,
    "work_marker": False,
    "handoff_marker": False,
    "reopen_marker": False,
    "mismatch_marker": False,
    "cleanup_marker": False,
    "direct_runtime_reason_marker": False,
}
for asset in js_assets:
    content = asset.read_text(encoding="utf-8", errors="replace")
    markers["bootstrap_marker"] |= "service-worker-broker-bootstrap" in content
    markers["registration_marker"] |= "service-worker-broker-registration" in content
    markers["work_marker"] |= "service-worker-broker-work" in content
    markers["handoff_marker"] |= "service-worker-broker-handoff" in content
    markers["reopen_marker"] |= "service-worker-broker-reopen" in content
    markers["mismatch_marker"] |= "service-worker-broker-mismatch" in content
    markers["cleanup_marker"] |= "service-worker-broker-cleanup" in content
    markers["direct_runtime_reason_marker"] |= (
        "service_worker_direct_runtime_not_shipped" in content
    )

summary = {
    "scenario_id": "L6-SERVICE-WORKER-BROKER",
    "timestamp": timestamp,
    "fixture": "tests/fixtures/service-worker-broker-consumer",
    "status": "pass",
    "checks": {
        "dist_exists": dist.exists(),
        "index_html_exists": (dist / "index.html").exists(),
        "service_worker_bundle_exists": (dist / "service-worker.js").exists(),
        "asset_js_count": len(js_assets),
        "real_browser_run_ok": browser_run["status"] == "ok",
        "browser_scenario_id": browser_run["scenario_id"],
        "browser_final_phase_is_cleanup_complete": (
            browser_run["final_phase"] == "cleanup_complete"
        ),
        "browser_controller_ready": browser_run["controller_ready"] is True,
        "browser_broker_supported": browser_run["broker_supported"] is True,
        "browser_broker_reason": browser_run["broker_reason"],
        "browser_broker_runtime_context": browser_run["broker_runtime_context"],
        "browser_direct_execution_reason": browser_run["direct_execution_reason_code"],
        "browser_registration_requested_lane": browser_run["registration_requested_lane"],
        "browser_registration_fallback_lane_id": browser_run["registration_fallback_lane_id"],
        "browser_registration_lifecycle_state": browser_run["registration_lifecycle_state"],
        "browser_pending_work_count": browser_run["pending_work_count"],
        "browser_reopened_pending_work_count": browser_run["reopened_pending_work_count"],
        "browser_handoff_count": browser_run["handoff_count"],
        "browser_reopened_handoff_count": browser_run["reopened_handoff_count"],
        "browser_handoff_target_lane_id": browser_run["handoff_target_lane_id"],
        "browser_handoff_reason": browser_run["handoff_reason"],
        "browser_mismatch_supported": browser_run["mismatch_supported"],
        "browser_mismatch_reason": browser_run["mismatch_reason"],
        "browser_cleared_count": browser_run["cleared_count"],
        "browser_post_cleanup_registration_missing": (
            browser_run["post_cleanup_registration_missing"] is True
        ),
        "browser_post_cleanup_pending_work_count": browser_run["post_cleanup_pending_work_count"],
        "browser_post_cleanup_handoff_count": browser_run["post_cleanup_handoff_count"],
        **markers,
    },
}
summary_path.write_text(json.dumps(summary, indent=2) + "\n")
PY

cat <<EOF
Service-worker broker consumer validation passed.
Artifacts:
  log: ${LOG_FILE}
  browser run: ${BROWSER_RUN_FILE}
  summary: ${SUMMARY_FILE}
EOF
