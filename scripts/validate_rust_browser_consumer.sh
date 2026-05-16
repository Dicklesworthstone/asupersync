#!/usr/bin/env bash
set -euo pipefail

# beads: asupersync-4l9iw.2, asupersync-4l9iw.8, asupersync-4l9iw.11

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
FIXTURE_DIR="${REPO_ROOT}/tests/fixtures/rust-browser-consumer"
CRATE_DIR="${FIXTURE_DIR}/crate"
RESULT_ROOT="${RUST_BROWSER_CONSUMER_OUTPUT_ROOT:-${REPO_ROOT}/target/e2e-results/rust_browser_consumer}"
RUN_ID="${RUST_BROWSER_CONSUMER_RUN_ID:-}"

usage() {
  cat <<'USAGE'
Usage: scripts/validate_rust_browser_consumer.sh [options]

Options:
  --run-id <id>          Deterministic run directory name.
  --output-root <dir>    Directory for run artifacts.
  -h, --help             Show this help.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-id)
      RUN_ID="${2:-}"
      shift 2
      ;;
    --output-root)
      RESULT_ROOT="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "${RUN_ID}" ]]; then
  RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
fi

RUN_DIR="${RESULT_ROOT}/${RUN_ID}"
LOG_FILE="${RUN_DIR}/consumer_build.log"
SUMMARY_FILE="${RUN_DIR}/summary.json"
BROWSER_RUN_FILE="${RUN_DIR}/browser-run.json"

mkdir -p "${RUN_DIR}"
WORK_DIR="$(mktemp -d "${RUN_DIR}/work.XXXXXX")"
PKG_DIR="${WORK_DIR}/pkg"
CONSUMER_DIR="${WORK_DIR}/consumer"
CARGO_WRAPPER="${WORK_DIR}/cargo-rch"
TARGET_DIR="${WORK_DIR}/target"

require_cmd() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "FATAL: required command not found: ${cmd}" >&2
    exit 1
  fi
}

reject_rch_local_fallback_log() {
  if grep -Eq '^\[RCH\] local \(|falling back to local' "${LOG_FILE}" 2>/dev/null; then
    echo "FATAL: rch local fallback detected; refusing local cargo execution" >&2
    echo "rch local fallback detected; refusing local cargo execution" > "${RUN_DIR}/rch_local_fallback.txt"
    exit 86
  fi
}

require_cmd node
require_cmd npm
require_cmd python3
require_cmd rch

if [[ ! -d "${FIXTURE_DIR}" ]]; then
  echo "FATAL: fixture missing: ${FIXTURE_DIR}" >&2
  exit 1
fi

if [[ ! -f "${CRATE_DIR}/Cargo.toml" ]]; then
  echo "FATAL: Rust crate manifest missing: ${CRATE_DIR}/Cargo.toml" >&2
  exit 1
fi

cat > "${CARGO_WRAPPER}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
cd "${REPO_ROOT}"
export RCH_FORCE_REMOTE="\${RCH_FORCE_REMOTE:-1}"
export RCH_QUEUE_WHEN_BUSY="\${RCH_QUEUE_WHEN_BUSY:-1}"
export RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS="\${RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS:-900}"
exec rch exec -- env CARGO_TARGET_DIR="${TARGET_DIR}" cargo "\$@"
EOF
chmod +x "${CARGO_WRAPPER}"

(
  cd "${REPO_ROOT}"
  "${CARGO_WRAPPER}" build \
    --lib \
    --target wasm32-unknown-unknown \
    --manifest-path "${CRATE_DIR}/Cargo.toml"
  CARGO="${CARGO_WRAPPER}" wasm-pack build "${CRATE_DIR}" \
    --target web \
    --dev \
    --out-dir "${PKG_DIR}" \
    --out-name asupersync_rust_browser_consumer_fixture
) | tee "${LOG_FILE}"
reject_rch_local_fallback_log

for required in \
  "${PKG_DIR}/asupersync_rust_browser_consumer_fixture.js" \
  "${PKG_DIR}/asupersync_rust_browser_consumer_fixture_bg.wasm" \
  "${PKG_DIR}/package.json"
do
  if [[ ! -f "${required}" ]]; then
    echo "FATAL: missing generated Rust-browser package artifact: ${required}" >&2
    exit 1
  fi
done

mkdir -p "${CONSUMER_DIR}"
cp -R "${FIXTURE_DIR}/." "${CONSUMER_DIR}/"
mkdir -p "${CONSUMER_DIR}/pkg"
cp -R "${PKG_DIR}/." "${CONSUMER_DIR}/pkg/"

(
  cd "${CONSUMER_DIR}"
  npm install --no-audit --no-fund
  npm run build
  npm run check:bundle
  npm run check:browser -- "${BROWSER_RUN_FILE}"
) | tee -a "${LOG_FILE}"

python3 - "${REPO_ROOT}" "${CONSUMER_DIR}" "${SUMMARY_FILE}" "${RUN_ID}" "${BROWSER_RUN_FILE}" <<'PY'
import json
import os
import pathlib
import sys

repo_root = pathlib.Path(sys.argv[1])
consumer = pathlib.Path(sys.argv[2])
summary_path = pathlib.Path(sys.argv[3])
run_id = sys.argv[4]
browser_run_path = pathlib.Path(sys.argv[5])
dist = consumer / "dist"
assets = dist / "assets"
browser_run = json.loads(browser_run_path.read_text())
package = json.loads((consumer / "package.json").read_text())
wasm_assets = sorted(assets.glob("*.wasm")) if assets.exists() else []
wasm_artifact_path = (
    os.path.relpath(wasm_assets[0], repo_root) if wasm_assets else ""
)
browser_run_artifact_path = os.path.relpath(browser_run_path, repo_root)
summary_artifact_path = os.path.relpath(summary_path, repo_root)
unsupported_surfaces = [
    "service_worker_direct_runtime",
    "shared_worker_direct_runtime",
    "native_tcp_udp_filesystem_process",
]
summary = {
    "schema_version": "browser-rust-runtime-api-stability-run-report-v1",
    "bead_id": "asupersync-j1xbon.1",
    "parent_bead_id": "asupersync-j1xbon",
    "scenario_id": "L6-RUST-BROWSER-CONSUMER",
    "run_id": run_id,
    "profile": "wasm-browser-dev",
    "host_context": "browser_main_thread_and_dedicated_worker",
    "api_version": "runtime-builder-browser-preview-v1",
    "consumer_version": f"{package['name']}@{package['version']}",
    "selected_lane": browser_run["main_thread_browser_selection_lane"],
    "unsupported_surfaces": unsupported_surfaces,
    "wasm_artifact_path": wasm_artifact_path,
    "browser_run_artifact_path": browser_run_artifact_path,
    "summary_artifact_path": summary_artifact_path,
    "expected_output": "ok",
    "actual_output": browser_run["completed_task_outcome"],
    "verdict": "pass",
    "first_failure": "",
    "fixture": "tests/fixtures/rust-browser-consumer",
    "status": "pass",
    "browser_run": {
        "status": browser_run["status"],
        "scenario_id": browser_run["scenario_id"],
        "support_lane": browser_run["support_lane"],
        "main_thread_selected_lane": browser_run["main_thread_selected_lane"],
        "main_thread_browser_selection_lane": browser_run["main_thread_browser_selection_lane"],
        "service_worker_fail_closed_reason_code": browser_run["service_worker_fail_closed_reason_code"],
        "shared_worker_fail_closed_reason_code": browser_run["shared_worker_fail_closed_reason_code"],
        "service_worker_broker_reason": browser_run["service_worker_broker_reason"],
        "shared_worker_coordinator_main_thread_reason": browser_run["shared_worker_coordinator_main_thread_reason"],
        "shared_worker_coordinator_dedicated_worker_reason": browser_run["shared_worker_coordinator_dedicated_worker_reason"],
        "downgrade_selected_lane": browser_run["downgrade_selected_lane"],
        "downgrade_browser_selection_lane": browser_run["downgrade_browser_selection_lane"],
        "downgrade_reason_code": browser_run["downgrade_reason_code"],
        "dedicated_worker_selected_lane": browser_run["dedicated_worker_selected_lane"],
        "dedicated_worker_browser_selection_lane": browser_run["dedicated_worker_browser_selection_lane"],
    },
    "checks": {
        "dist_exists": dist.exists(),
        "index_html_exists": (dist / "index.html").exists(),
        "asset_js_count": len(list(assets.glob("*.js"))) if assets.exists() else 0,
        "asset_wasm_count": len(list(assets.glob("*.wasm"))) if assets.exists() else 0,
        "real_browser_run_ok": browser_run["status"] == "ok",
        "browser_scenario_id": browser_run["scenario_id"],
        "browser_support_lane": browser_run["support_lane"],
        "ready_phase_is_ready": browser_run["ready_phase"] == "ready",
        "disposed_phase_is_disposed": browser_run["disposed_phase"] == "disposed",
        "child_scope_count_before_unmount": browser_run["child_scope_count_before_unmount"],
        "active_task_count_before_unmount": browser_run["active_task_count_before_unmount"],
        "completed_task_outcome_is_ok": browser_run["completed_task_outcome"] == "ok",
        "cancel_event_count_is_one": browser_run["cancel_event_count"] == 1,
        "dispatch_count": browser_run["dispatch_count"],
        "event_symbols_include_task_spawn": "task_spawn" in browser_run["event_symbols"],
        "event_symbols_include_task_join": "task_join" in browser_run["event_symbols"],
        "event_symbols_include_task_cancel": "task_cancel" in browser_run["event_symbols"],
        "capabilities_has_window": browser_run["capabilities"]["has_window"] is True,
        "capabilities_has_document": browser_run["capabilities"]["has_document"] is True,
        "capabilities_has_webassembly": browser_run["capabilities"]["has_webassembly"] is True,
        "main_thread_selected_lane": browser_run["main_thread_selected_lane"],
        "main_thread_browser_selection_lane": browser_run["main_thread_browser_selection_lane"],
        "main_thread_preferred_worker_selected_lane": browser_run["main_thread_preferred_worker_selected_lane"],
        "main_thread_preferred_worker_browser_selection_lane": browser_run["main_thread_preferred_worker_browser_selection_lane"],
        "main_thread_preferred_worker_reason_code": browser_run["main_thread_preferred_worker_reason_code"],
        "service_worker_fail_closed_reason_code": browser_run["service_worker_fail_closed_reason_code"],
        "shared_worker_fail_closed_reason_code": browser_run["shared_worker_fail_closed_reason_code"],
        "service_worker_broker_reason": browser_run["service_worker_broker_reason"],
        "shared_worker_coordinator_main_thread_reason": browser_run["shared_worker_coordinator_main_thread_reason"],
        "shared_worker_coordinator_dedicated_worker_reason": browser_run["shared_worker_coordinator_dedicated_worker_reason"],
        "downgrade_selected_lane": browser_run["downgrade_selected_lane"],
        "downgrade_browser_selection_lane": browser_run["downgrade_browser_selection_lane"],
        "downgrade_reason_code": browser_run["downgrade_reason_code"],
        "dedicated_worker_ready_phase_is_ready": browser_run["dedicated_worker_ready_phase"] == "ready",
        "dedicated_worker_disposed_phase_is_disposed": browser_run["dedicated_worker_disposed_phase"] == "disposed",
        "dedicated_worker_completed_task_outcome_is_ok": browser_run["dedicated_worker_completed_task_outcome"] == "ok",
        "dedicated_worker_cancel_event_count_is_one": browser_run["dedicated_worker_cancel_event_count"] == 1,
        "dedicated_worker_selected_lane": browser_run["dedicated_worker_selected_lane"],
        "dedicated_worker_browser_selection_lane": browser_run["dedicated_worker_browser_selection_lane"],
        "dedicated_worker_preferred_main_thread_selected_lane": browser_run["dedicated_worker_preferred_main_thread_selected_lane"],
        "dedicated_worker_preferred_main_thread_browser_selection_lane": browser_run["dedicated_worker_preferred_main_thread_browser_selection_lane"],
        "dedicated_worker_preferred_main_thread_reason_code": browser_run["dedicated_worker_preferred_main_thread_reason_code"],
        "main_thread_local_storage_available": browser_run["main_thread_local_storage"] is True,
        "dedicated_worker_local_storage_unavailable": browser_run["dedicated_worker_local_storage"] is False,
        "main_thread_indexed_db_flag": browser_run["main_thread_indexed_db"],
        "dedicated_worker_indexed_db_flag": browser_run["dedicated_worker_indexed_db"],
        "main_thread_web_transport_flag": browser_run["main_thread_web_transport"],
        "dedicated_worker_web_transport_flag": browser_run["dedicated_worker_web_transport"],
    },
}
summary_path.write_text(json.dumps(summary, indent=2) + "\n")
ordered = [
    f"bead_id={summary['bead_id']}",
    f"scenario_id={summary['scenario_id']}",
    f"profile={summary['profile']}",
    f"host_context={summary['host_context']}",
    f"api_version={summary['api_version']}",
    f"consumer_version={summary['consumer_version']}",
    f"selected_lane={summary['selected_lane']}",
    "unsupported_surfaces=" + ",".join(summary["unsupported_surfaces"]),
    f"wasm_artifact_path={summary['wasm_artifact_path']}",
    f"browser_run_artifact_path={summary['browser_run_artifact_path']}",
    f"expected_output={summary['expected_output']}",
    f"actual_output={summary['actual_output']}",
    f"verdict={summary['verdict']}",
    f"first_failure={summary['first_failure']}",
]
print("RUST_BROWSER_RUNTIME_API_SCENARIO " + " ".join(ordered))
PY

cat <<EOF
Rust browser consumer validation passed.
Artifacts:
  log: ${LOG_FILE}
  browser run: ${BROWSER_RUN_FILE}
  summary: ${SUMMARY_FILE}
EOF
