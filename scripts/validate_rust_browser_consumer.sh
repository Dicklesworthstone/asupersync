#!/usr/bin/env bash
set -euo pipefail

# beads: asupersync-4l9iw.2, asupersync-4l9iw.8, asupersync-4l9iw.11

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
FIXTURE_DIR="${REPO_ROOT}/tests/fixtures/rust-browser-consumer"
CRATE_DIR="${FIXTURE_DIR}/crate"
RESULT_ROOT="${REPO_ROOT}/target/e2e-results/rust_browser_consumer"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${RESULT_ROOT}/${TIMESTAMP}"
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
exec rch exec -- env CARGO_TARGET_DIR="${TARGET_DIR}" cargo "\$@"
EOF
chmod +x "${CARGO_WRAPPER}"

(
  cd "${REPO_ROOT}"
  CARGO="${CARGO_WRAPPER}" wasm-pack build "${CRATE_DIR}" \
    --target web \
    --dev \
    --out-dir "${PKG_DIR}" \
    --out-name asupersync_rust_browser_consumer_fixture
) | tee "${LOG_FILE}"

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

python3 - "${CONSUMER_DIR}" "${SUMMARY_FILE}" "${TIMESTAMP}" "${BROWSER_RUN_FILE}" <<'PY'
import json
import pathlib
import sys

consumer = pathlib.Path(sys.argv[1])
summary_path = pathlib.Path(sys.argv[2])
timestamp = sys.argv[3]
browser_run_path = pathlib.Path(sys.argv[4])
dist = consumer / "dist"
assets = dist / "assets"
browser_run = json.loads(browser_run_path.read_text())
summary = {
    "scenario_id": "L6-RUST-BROWSER-CONSUMER",
    "timestamp": timestamp,
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
PY

cat <<EOF
Rust browser consumer validation passed.
Artifacts:
  log: ${LOG_FILE}
  browser run: ${BROWSER_RUN_FILE}
  summary: ${SUMMARY_FILE}
EOF
