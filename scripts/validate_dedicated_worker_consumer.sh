#!/usr/bin/env bash
set -euo pipefail

# bead: asupersync-18tbo.4

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
FIXTURE_DIR="${REPO_ROOT}/tests/fixtures/dedicated-worker-consumer"
RESULT_ROOT="${REPO_ROOT}/target/e2e-results/dedicated_worker_consumer"
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

This worker validation intentionally runs only against built package outputs.
EOF
  exit 1
fi

WORK_DIR="$(mktemp -d "/tmp/asupersync-dedicated-worker.XXXXXX")"
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

python3 - "${CONSUMER_DIR}" "${SUMMARY_FILE}" "${TIMESTAMP}" "${BROWSER_RUN_FILE}" "${LOG_FILE}" "${REPO_ROOT}" <<'PY'
import json
import pathlib
import sys

consumer = pathlib.Path(sys.argv[1])
summary_path = pathlib.Path(sys.argv[2])
timestamp = sys.argv[3]
browser_run_path = pathlib.Path(sys.argv[4])
log_path = pathlib.Path(sys.argv[5])
repo_root = pathlib.Path(sys.argv[6])
dist = consumer / "dist"
assets = dist / "assets"
asset_files = (
    sorted(
        asset
        for asset in assets.iterdir()
        if asset.is_file() and asset.suffix in {".js", ".mjs"}
    )
    if assets.exists()
    else []
)
browser_run = json.loads(browser_run_path.read_text())


def repo_relative(path: pathlib.Path) -> str:
    try:
        return str(path.relative_to(repo_root))
    except ValueError:
        return str(path)

markers = {
    "worker_bootstrap_marker": False,
    "worker_shutdown_marker": False,
    "worker_runtime_selection_baseline_marker": False,
    "worker_scope_selection_baseline_marker": False,
    "worker_scope_selection_preferred_main_thread_marker": False,
    "worker_lane_health_retrying_marker": False,
    "worker_execution_ladder_retrying_marker": False,
    "worker_lane_health_demotion_marker": False,
    "worker_runtime_selection_demoted_marker": False,
    "worker_runtime_selection_prerequisite_loss_marker": False,
    "worker_lane_health_reset_marker": False,
    "worker_runtime_selection_recovered_marker": False,
    "worker_storage_support_marker": False,
    "worker_storage_roundtrip_marker": False,
    "storage_artifact_marker": False,
    "download_unsupported_marker": False,
    "worker_artifact_export_marker": False,
    "worker_artifact_download_guard_marker": False,
    "worker_artifact_quota_guard_marker": False,
    "worker_artifact_cleanup_marker": False,
}
for asset in asset_files:
    content = asset.read_text(encoding="utf-8", errors="replace")
    markers["worker_bootstrap_marker"] |= "worker-bootstrap" in content
    markers["worker_shutdown_marker"] |= "worker-shutdown-complete" in content
    markers["worker_runtime_selection_baseline_marker"] |= "worker-runtime-selection-baseline" in content
    markers["worker_scope_selection_baseline_marker"] |= "worker-scope-selection-baseline" in content
    markers["worker_scope_selection_preferred_main_thread_marker"] |= (
        "worker-scope-selection-preferred-main-thread" in content
    )
    markers["worker_lane_health_retrying_marker"] |= "worker-lane-health-retrying" in content
    markers["worker_execution_ladder_retrying_marker"] |= (
        "worker-execution-ladder-retrying" in content
    )
    markers["worker_lane_health_demotion_marker"] |= "worker-lane-health-demotion" in content
    markers["worker_runtime_selection_demoted_marker"] |= "worker-runtime-selection-demoted" in content
    markers["worker_runtime_selection_prerequisite_loss_marker"] |= (
        "worker-runtime-selection-prerequisite-loss" in content
    )
    markers["worker_lane_health_reset_marker"] |= "worker-lane-health-reset" in content
    markers["worker_runtime_selection_recovered_marker"] |= "worker-runtime-selection-recovered" in content
    markers["worker_storage_support_marker"] |= "worker-storage-support" in content
    markers["worker_storage_roundtrip_marker"] |= "worker-storage-roundtrip" in content
    markers["storage_artifact_marker"] |= "worker-storage-artifact-export-handoff" in content
    markers["download_unsupported_marker"] |= (
        "ASUPERSYNC_BROWSER_ARTIFACT_DOWNLOAD_UNSUPPORTED" in content
    )
    markers["worker_artifact_export_marker"] |= "worker-artifact-archive" in content
    markers["worker_artifact_download_guard_marker"] |= "worker-artifact-download-unavailable" in content
    markers["worker_artifact_quota_guard_marker"] |= "worker-artifact-quota-guard" in content
    markers["worker_artifact_cleanup_marker"] |= "worker-artifact-cleanup" in content

CANONICAL_SCENARIO_INVENTORY = [
    {
        "scenario_id": "worker_bootstrap_baseline",
        "failure_family": "baseline",
        "expected_outcome": "dedicated worker direct runtime stays selected on the no-throw path",
        "artifact_keys": ["browser_run", "log"],
    },
    {
        "scenario_id": "preferred_lane_mismatch_truthful_worker_selection",
        "failure_family": "preferred_lane_mismatch",
        "expected_outcome": "requested main-thread preference stays truthful to the worker lane",
        "artifact_keys": ["browser_run", "log"],
    },
    {
        "scenario_id": "worker_loss_retry_window",
        "failure_family": "worker_loss",
        "expected_outcome": "first worker loss consumes retry budget without silent downgrade",
        "artifact_keys": ["browser_run", "log"],
    },
    {
        "scenario_id": "worker_loss_fail_closed_demotion",
        "failure_family": "worker_loss",
        "expected_outcome": "exhausted retry budget demotes fail-closed instead of silently falling through",
        "artifact_keys": ["browser_run", "log"],
    },
    {
        "scenario_id": "prerequisite_drift_reason_precedence",
        "failure_family": "prerequisite_drift",
        "expected_outcome": "current prerequisite loss outranks stale demotion state",
        "artifact_keys": ["browser_run", "log"],
    },
    {
        "scenario_id": "lane_health_recovery",
        "failure_family": "recovery",
        "expected_outcome": "health reset restores the dedicated worker lane",
        "artifact_keys": ["browser_run", "log"],
    },
    {
        "scenario_id": "graceful_shutdown_handoff",
        "failure_family": "shutdown",
        "expected_outcome": "fixture reaches shutdown_complete after worker handoff",
        "artifact_keys": ["browser_run", "log"],
    },
]


def normalize_artifact_keys(raw_keys: object) -> list[str]:
    artifact_keys: list[str] = []
    if isinstance(raw_keys, list):
        for key in raw_keys:
            if isinstance(key, str) and key not in artifact_keys:
                artifact_keys.append(key)
    for required_key in ["browser_run", "log"]:
        if required_key not in artifact_keys:
            artifact_keys.append(required_key)
    return artifact_keys


def normalize_scenario_inventory(browser_run: dict[str, object]) -> list[dict[str, object]]:
    canonical_scenarios = [
        {**entry, "artifact_keys": normalize_artifact_keys(entry.get("artifact_keys"))}
        for entry in CANONICAL_SCENARIO_INVENTORY
    ]
    canonical_by_id = {
        entry["scenario_id"]: entry
        for entry in canonical_scenarios
        if isinstance(entry.get("scenario_id"), str)
    }
    extras: list[dict[str, object]] = []
    raw_inventory = browser_run.get("scenario_inventory")
    if not isinstance(raw_inventory, list):
        return canonical_scenarios

    for raw_entry in raw_inventory:
        if not isinstance(raw_entry, dict):
            continue
        scenario_id = raw_entry.get("scenario_id")
        if not isinstance(scenario_id, str):
            continue
        normalized_artifact_keys = normalize_artifact_keys(raw_entry.get("artifact_keys"))
        observed = raw_entry.get("observed")
        failure_family = raw_entry.get("failure_family")
        expected_outcome = raw_entry.get("expected_outcome")

        if scenario_id in canonical_by_id:
            entry = canonical_by_id[scenario_id]
            if isinstance(failure_family, str):
                entry["failure_family"] = failure_family
            if isinstance(expected_outcome, str):
                entry["expected_outcome"] = expected_outcome
            entry["artifact_keys"] = normalized_artifact_keys
            if isinstance(observed, dict):
                entry["observed"] = observed
            continue

        extra_entry = {
            "scenario_id": scenario_id,
            "artifact_keys": normalized_artifact_keys,
        }
        if isinstance(failure_family, str):
            extra_entry["failure_family"] = failure_family
        if isinstance(expected_outcome, str):
            extra_entry["expected_outcome"] = expected_outcome
        if isinstance(observed, dict):
            extra_entry["observed"] = observed
        extras.append(extra_entry)

    return canonical_scenarios + extras


scenario_inventory = normalize_scenario_inventory(browser_run)

artifacts = {
    "summary": repo_relative(summary_path),
    "browser_run": repo_relative(browser_run_path),
    "log": repo_relative(log_path),
    "fixture": "tests/fixtures/dedicated-worker-consumer",
}

replay_commands = [
    "PATH=/usr/bin:$PATH bash scripts/validate_dedicated_worker_consumer.sh",
    "cd tests/fixtures/dedicated-worker-consumer && PATH=/usr/bin:$PATH npm run check:bundle",
]

summary = {
    "scenario_id": "L6-BUNDLER-DEDICATED-WORKER",
    "timestamp": timestamp,
    "fixture": "tests/fixtures/dedicated-worker-consumer",
    "status": "pass",
    "scenario_inventory": scenario_inventory,
    "artifacts": artifacts,
    "replay_commands": replay_commands,
    "checks": {
        "dist_exists": dist.exists(),
        "index_html_exists": (dist / "index.html").exists(),
        "asset_script_count": len(asset_files),
        "asset_js_count": sum(1 for asset in asset_files if asset.suffix == ".js"),
        "asset_mjs_count": sum(1 for asset in asset_files if asset.suffix == ".mjs"),
        "real_browser_run_ok": browser_run["status"] == "ok",
        "browser_scenario_id": browser_run["scenario_id"],
        "browser_final_phase_is_shutdown_complete": browser_run["final_phase"] == "shutdown_complete",
        "browser_shutdown_reason": browser_run["shutdown_reason"],
        "browser_shutdown_reason_is_fixture_handoff_complete": browser_run["shutdown_reason"] == "fixture-handoff-complete",
        "browser_support_runtime_context": browser_run["support_runtime_context"],
        "browser_baseline_selected_lane": browser_run["baseline_selected_lane"],
        "browser_baseline_scope_outcome_is_ok": browser_run["baseline_scope_outcome"] == "ok",
        "browser_preferred_scope_selected_lane": browser_run["preferred_scope_selected_lane"],
        "browser_preferred_scope_outcome_is_ok": browser_run["preferred_scope_outcome"] == "ok",
        "browser_retrying_status": browser_run["retrying_status"],
        "browser_retrying_selected_lane": browser_run["retrying_selected_lane"],
        "browser_retrying_last_trigger": browser_run["retrying_last_trigger"],
        "browser_retrying_retry_budget_remaining": browser_run["retrying_retry_budget_remaining"],
        "browser_demotion_status": browser_run["demotion_status"],
        "browser_demotion_failure_count": browser_run["demotion_failure_count"],
        "browser_demotion_retry_budget_remaining": browser_run["demotion_retry_budget_remaining"],
        "browser_demotion_cooldown_until_ms": browser_run["demotion_cooldown_until_ms"],
        "browser_demotion_last_trigger": browser_run["demotion_last_trigger"],
        "browser_demotion_demoted_to_lane_id": browser_run["demotion_demoted_to_lane_id"],
        "browser_demoted_selected_lane": browser_run["demoted_selected_lane"],
        "browser_demoted_reason_code": browser_run["demoted_reason_code"],
        "browser_demoted_outcome_is_null": browser_run["demoted_outcome"] is None,
        "browser_demoted_health_last_trigger": browser_run["demoted_health_last_trigger"],
        "browser_demoted_health_demoted_to_lane_id": browser_run["demoted_health_demoted_to_lane_id"],
        "browser_demoted_worker_candidate_reason": browser_run["demoted_worker_candidate_reason"],
        "browser_prerequisite_loss_simulated": browser_run["prerequisite_loss_simulated"],
        "browser_prerequisite_loss_skipped_reason": browser_run["prerequisite_loss_skipped_reason"],
        "browser_prerequisite_loss_selected_lane": browser_run["prerequisite_loss_selected_lane"],
        "browser_prerequisite_loss_reason_code": browser_run["prerequisite_loss_reason_code"],
        "browser_prerequisite_loss_health_status": browser_run["prerequisite_loss_health_status"],
        "browser_prerequisite_loss_health_last_trigger": browser_run["prerequisite_loss_health_last_trigger"],
        "browser_prerequisite_loss_health_demoted_to_lane_id": browser_run["prerequisite_loss_health_demoted_to_lane_id"],
        "browser_prerequisite_loss_worker_candidate_reason": browser_run["prerequisite_loss_worker_candidate_reason"],
        "browser_recovered_status": browser_run["recovered_status"],
        "browser_recovered_selected_lane": browser_run["recovered_selected_lane"],
        "browser_recovered_outcome_is_ok": browser_run["recovered_outcome"] == "ok",
        "browser_storage_backend": browser_run["storage_backend"],
        "browser_artifact_download_failure_code": browser_run["artifact_download_failure_code"],
        "browser_quota_failure_reason": browser_run["quota_failure_reason"],
        **markers,
    },
}
summary_path.write_text(json.dumps(summary, indent=2) + "\n")
PY

cat <<EOF
Dedicated worker consumer validation passed.
Artifacts:
  log: ${LOG_FILE}
  browser run: ${BROWSER_RUN_FILE}
  summary: ${SUMMARY_FILE}
EOF
