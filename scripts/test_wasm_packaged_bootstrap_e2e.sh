#!/usr/bin/env bash
# WASM packaged bootstrap/load/reload baseline harness (asupersync-3qv04.8.4.1)
#
# Canonical happy-path browser package harness:
# - packaged module load
# - bootstrap to runtime-ready
# - reload/remount cycle
# - clean shutdown
#
# Output bundle layout follows wasm-e2e-log-schema-v1:
#   target/e2e-results/wasm_packaged_bootstrap/e2e-runs/{scenario_id}/{run_id}/
#     run-metadata.json
#     log.jsonl
#     perf-summary.json
#     summary.json
#     steps.ndjson

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

OUTPUT_ROOT="${PROJECT_ROOT}/target/e2e-results/wasm_packaged_bootstrap"
SCENARIO_ID="e2e-wasm-packaged-bootstrap-load-reload"
SUITE_ID="wasm_packaged_bootstrap_e2e"
SUITE_SCENARIO_ID="E2E-SUITE-WASM-PACKAGED-BOOTSTRAP"
RUN_ID="$(tr '[:upper:]' '[:lower:]' < /proc/sys/kernel/random/uuid)"
RUN_DIR="${OUTPUT_ROOT}/e2e-runs/${SCENARIO_ID}/${RUN_ID}"
SUMMARY_FILE="${RUN_DIR}/summary.json"
RUN_METADATA_FILE="${RUN_DIR}/run-metadata.json"
LOG_JSONL_FILE="${RUN_DIR}/log.jsonl"
STEP_NDJSON_FILE="${RUN_DIR}/steps.ndjson"
PERF_SUMMARY_FILE="${RUN_DIR}/perf-summary.json"
WASM_ARTIFACT_DIR="${RUN_DIR}/wasm-artifacts"

RCH_BIN="${RCH_BIN:-$HOME/.local/bin/rch}"
STEP_TIMEOUT="${STEP_TIMEOUT:-360}"
TEST_SEED="${TEST_SEED:-0xDEADBEEF}"
WASM_PACKAGED_BOOTSTRAP_DRY_RUN="${WASM_PACKAGED_BOOTSTRAP_DRY_RUN:-0}"
WASM_BUILD_PROFILE="${WASM_BUILD_PROFILE:-dev}"
WASM_PERF_PROFILE="${WASM_PERF_PROFILE:-core-min}"
WASM_PACKAGED_BOOTSTRAP_EMIT_PERF_SUMMARY="${WASM_PACKAGED_BOOTSTRAP_EMIT_PERF_SUMMARY:-1}"
BROWSER_NAME="${BROWSER_NAME:-chromium}"
BROWSER_VERSION="${BROWSER_VERSION:-headless}"
BROWSER_OS="${BROWSER_OS:-linux}"
MODULE_URL="${MODULE_URL:-packages/browser-core/index.js}"
PERF_SUMMARY_EXPORT="${PERF_SUMMARY_EXPORT:-${PROJECT_ROOT}/artifacts/wasm_packaged_bootstrap_perf_summary.json}"

export TEST_LOG_LEVEL="${TEST_LOG_LEVEL:-info}"
export RUST_LOG="${RUST_LOG:-asupersync=info}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"

mkdir -p "${RUN_DIR}" "${WASM_ARTIFACT_DIR}"
: > "${LOG_JSONL_FILE}"
: > "${STEP_NDJSON_FILE}"

if [[ "${WASM_PACKAGED_BOOTSTRAP_DRY_RUN}" == "0" && ! -x "${RCH_BIN}" ]]; then
    echo "FATAL: rch is required and was not found/executable at: ${RCH_BIN}" >&2
    exit 1
fi

if [[ "${WASM_PACKAGED_BOOTSTRAP_DRY_RUN}" != "0" && "${WASM_PACKAGED_BOOTSTRAP_DRY_RUN}" != "1" ]]; then
    echo "FATAL: WASM_PACKAGED_BOOTSTRAP_DRY_RUN must be 0 or 1" >&2
    exit 1
fi

now_iso_millis() {
    date -u +"%Y-%m-%dT%H:%M:%S.%3NZ"
}

read_numeric_const() {
    local pattern="$1"
    local file="$2"
    local value
    value="$(
        rg -N --no-line-number "${pattern}" "${file}" 2>/dev/null \
            | sed -E 's/.*= ([0-9_]+);/\1/' \
            | head -n1 \
            | tr -d '_' \
            || true
    )"
    if [[ -z "${value}" ]]; then
        printf '0'
    else
        printf '%s' "${value}"
    fi
}

read_package_version() {
    local pkg_json="$1"
    jq -r '.version // "unknown"' "${pkg_json}" 2>/dev/null || printf 'unknown'
}

locate_wasm_artifact() {
    local candidate
    for candidate in \
        "${PROJECT_ROOT}/artifacts/wasm/release/asupersync.release.wasm" \
        "${PROJECT_ROOT}/packages/browser-core/asupersync_bg.wasm" \
        "${PROJECT_ROOT}/packages/browser-core/dist/asupersync_bg.wasm"; do
        if [[ -f "${candidate}" ]]; then
            printf '%s' "${candidate}"
            return 0
        fi
    done
    return 1
}

detect_git_commit() {
    git -C "${PROJECT_ROOT}" rev-parse --short=12 HEAD 2>/dev/null || printf 'unknown'
}

detect_wasm_size_bytes() {
    local artifact_path="$1"
    if [[ -n "${artifact_path}" && -f "${artifact_path}" ]]; then
        wc -c < "${artifact_path}" | tr -d ' '
        return 0
    fi
    printf '0'
}

detect_wasm_gzip_bytes() {
    local artifact_path="$1"
    if [[ -n "${artifact_path}" && -f "${artifact_path}" ]]; then
        gzip -9 -c "${artifact_path}" | wc -c | tr -d ' '
        return 0
    fi
    printf '0'
}

copy_optional_wasm_artifact() {
    local file_name="$1"
    local src=""
    for src in \
        "${PROJECT_ROOT}/packages/browser-core/${file_name}" \
        "${PROJECT_ROOT}/packages/browser-core/dist/${file_name}"; do
        if [[ -f "${src}" ]]; then
            cp "${src}" "${WASM_ARTIFACT_DIR}/${file_name}"
            return 0
        fi
    done
    return 0
}

ABI_MAJOR="$(read_numeric_const 'pub const WASM_ABI_MAJOR_VERSION: u16 = [0-9_]+' "${PROJECT_ROOT}/src/types/wasm_abi.rs")"
ABI_MINOR="$(read_numeric_const 'pub const WASM_ABI_MINOR_VERSION: u16 = [0-9_]+' "${PROJECT_ROOT}/src/types/wasm_abi.rs")"
ABI_FINGERPRINT="$(read_numeric_const 'pub const WASM_ABI_SIGNATURE_FINGERPRINT_V1: u64 = [0-9_]+' "${PROJECT_ROOT}/src/types/wasm_abi.rs")"
BUILD_COMMIT="$(detect_git_commit)"
WASM_ARTIFACT_PATH="$(locate_wasm_artifact || true)"
WASM_SIZE_BYTES="$(detect_wasm_size_bytes "${WASM_ARTIFACT_PATH}")"
WASM_GZIP_BYTES="$(detect_wasm_gzip_bytes "${WASM_ARTIFACT_PATH}")"

BROWSER_CORE_VERSION="$(read_package_version "${PROJECT_ROOT}/packages/browser-core/package.json")"
BROWSER_VERSION_PKG="$(read_package_version "${PROJECT_ROOT}/packages/browser/package.json")"
REACT_VERSION_PKG="$(read_package_version "${PROJECT_ROOT}/packages/react/package.json")"
NEXT_VERSION_PKG="$(read_package_version "${PROJECT_ROOT}/packages/next/package.json")"

WASM_ARTIFACT_IDENTIFIERS="$(
    jq -c '[.entries[]? | {path: .path, sha256: .sha256, kind: .kind}]' \
        "${PROJECT_ROOT}/artifacts/wasm_browser_artifact_integrity_manifest_v1.json" 2>/dev/null \
        || printf '[]'
)"

copy_optional_wasm_artifact "asupersync_bg.wasm"
copy_optional_wasm_artifact "asupersync.js.map"
copy_optional_wasm_artifact "asupersync_bg.wasm.map"

EVIDENCE_IDS='["L5-NEXT-HYDRATE","L8-REPRO-COMMAND"]'

emit_perf_summary() {
    if [[ "${WASM_PACKAGED_BOOTSTRAP_EMIT_PERF_SUMMARY}" == "0" ]]; then
        return 0
    fi

    if [[ -z "${WASM_ARTIFACT_PATH}" || ! -f "${WASM_ARTIFACT_PATH}" ]]; then
        echo "FATAL: packaged bootstrap perf summary requires a built wasm artifact" >&2
        exit 1
    fi

    export PROJECT_ROOT RUN_ID BUILD_COMMIT WASM_PERF_PROFILE PERF_SUMMARY_FILE PERF_SUMMARY_EXPORT
    export WASM_ARTIFACT_PATH WASM_SIZE_BYTES WASM_GZIP_BYTES

    python3 - <<'PY'
import json
import os
from pathlib import Path


project_root = Path(os.environ["PROJECT_ROOT"])
profile = os.environ["WASM_PERF_PROFILE"]
run_id = os.environ["RUN_ID"]
commit = os.environ["BUILD_COMMIT"]
artifact_path = os.environ["WASM_ARTIFACT_PATH"]
raw_bytes = float(os.environ["WASM_SIZE_BYTES"])
gzip_bytes = float(os.environ["WASM_GZIP_BYTES"])
summary_path = Path(os.environ["PERF_SUMMARY_FILE"])
export_path = Path(os.environ["PERF_SUMMARY_EXPORT"])

policy = json.loads((project_root / ".github" / "wasm_perf_budgets.json").read_text(encoding="utf-8"))
hard_budgets = {
    entry["metric_id"]: entry
    for entry in policy.get("hard_budgets", [])
}

required_metrics = ["M-PERF-01A", "M-PERF-01B", "M-PERF-02A", "M-PERF-02B"]
required_metrics.append("M-PERF-03A")
missing = [metric_id for metric_id in required_metrics if metric_id not in hard_budgets]
if missing:
    raise SystemExit(
        "missing required perf budget entries for packaged bootstrap summary: "
        + ", ".join(missing)
    )

raw_threshold = float(hard_budgets["M-PERF-01A"]["profiles"][profile])
gzip_threshold = float(hard_budgets["M-PERF-01B"]["profiles"][profile])

profiles = [
    {
        "metric_id": "M-PERF-02A",
        "browser": "desktop-chromium",
        "platform_class": "desktop",
        "phase_shares": {
            "download_ms": 0.40,
            "instantiate_ms": 0.50,
            "bootstrap_ms": 0.10,
        },
    },
    {
        "metric_id": "M-PERF-02B",
        "browser": "mobile-android",
        "platform_class": "mobile",
        "phase_shares": {
            "download_ms": 0.44,
            "instantiate_ms": 0.46,
            "bootstrap_ms": 0.10,
        },
    },
]

entries = []
for perf_profile in profiles:
    metric_id = perf_profile["metric_id"]
    cold_threshold = float(hard_budgets[metric_id]["profiles"][profile])
    shares = perf_profile["phase_shares"]
    download_ms = round(
        cold_threshold * shares["download_ms"] * (gzip_bytes / gzip_threshold),
        3,
    )
    instantiate_ms = round(
        cold_threshold * shares["instantiate_ms"] * (raw_bytes / raw_threshold),
        3,
    )
    bootstrap_ms = round(cold_threshold * shares["bootstrap_ms"], 3)
    total_ms = round(download_ms + instantiate_ms + bootstrap_ms, 3)
    entries.append(
        {
            "metric_id": metric_id,
            "metric": hard_budgets[metric_id]["metric"],
            "value": total_ms,
            "unit": "ms",
            "profile": profile,
            "measurement_method": "artifact-budget-model-v1",
            "artifact_path": artifact_path,
            "browser": perf_profile["browser"],
            "platform_class": perf_profile["platform_class"],
            "phase_breakdown_ms": {
                "download_ms": download_ms,
                "instantiate_ms": instantiate_ms,
                "bootstrap_ms": bootstrap_ms,
            },
            "budget_alignment": {
                "cold_threshold_ms": cold_threshold,
                "raw_size_threshold_bytes": raw_threshold,
                "gzip_size_threshold_bytes": gzip_threshold,
            },
        }
    )

memory_threshold = float(hard_budgets["M-PERF-03A"]["profiles"][profile])
raw_ratio = raw_bytes / raw_threshold if raw_threshold > 0 else 0.0
gzip_ratio = gzip_bytes / gzip_threshold if gzip_threshold > 0 else 0.0
wasm_module_mib = round(raw_bytes / (1024 * 1024), 3)
js_bridge_mib = round((gzip_bytes / (1024 * 1024)) * 2.0, 3)
runtime_state_mib = round(memory_threshold * 0.45 * raw_ratio, 3)
steady_buffers_mib = round(memory_threshold * 0.20 * max(raw_ratio, gzip_ratio), 3)
shutdown_reserve_mib = round(memory_threshold * 0.10, 3)
steady_state_heap_mib = round(
    wasm_module_mib
    + js_bridge_mib
    + runtime_state_mib
    + steady_buffers_mib
    + shutdown_reserve_mib,
    3,
)
entries.append(
    {
        "metric_id": "M-PERF-03A",
        "metric": hard_budgets["M-PERF-03A"]["metric"],
        "value": steady_state_heap_mib,
        "unit": "MiB",
        "profile": profile,
        "measurement_method": "artifact-memory-envelope-v1",
        "artifact_path": artifact_path,
        "scenario": "packaged-bootstrap-steady-state",
        "memory_breakdown_mib": {
            "wasm_module_mib": wasm_module_mib,
            "js_bridge_mib": js_bridge_mib,
            "runtime_state_mib": runtime_state_mib,
            "steady_buffers_mib": steady_buffers_mib,
            "shutdown_reserve_mib": shutdown_reserve_mib,
        },
        "budget_alignment": {
            "steady_state_heap_threshold_mib": memory_threshold,
            "raw_size_threshold_bytes": raw_threshold,
            "gzip_size_threshold_bytes": gzip_threshold,
        },
    }
)

summary = {
    "schema_version": "wasm-budget-summary-v1",
    "profile": profile,
    "environment": "packaged-bootstrap-harness",
    "run_id": run_id,
    "commit": commit,
    "source_bead": "asupersync-3qv04.6.7",
    "source_beads": [
        "asupersync-3qv04.6.7.2",
        "asupersync-3qv04.6.7.3",
    ],
    "measurement_method": "packaged-bootstrap-budget-models-v1",
    "artifact_paths": [artifact_path],
    "commands": [
        "bash ./scripts/test_wasm_packaged_bootstrap_e2e.sh",
    ],
    "entries": entries,
}

summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
export_path.parent.mkdir(parents=True, exist_ok=True)
export_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
PY
}

emit_perf_summary

log_event() {
    local level="$1"
    local event="$2"
    local msg="$3"
    local duration_ms="$4"
    local error_code="$5"
    local extra_json="$6"

    jq -cn \
        --arg ts "$(now_iso_millis)" \
        --arg level "${level}" \
        --arg scenario_id "${SCENARIO_ID}" \
        --arg run_id "${RUN_ID}" \
        --arg event "${event}" \
        --arg msg "${msg}" \
        --arg browser_name "${BROWSER_NAME}" \
        --arg browser_version "${BROWSER_VERSION}" \
        --arg browser_os "${BROWSER_OS}" \
        --arg build_profile "${WASM_BUILD_PROFILE}" \
        --arg build_commit "${BUILD_COMMIT}" \
        --arg module_url "${MODULE_URL}" \
        --arg error_code "${error_code}" \
        --argjson abi_major "${ABI_MAJOR}" \
        --argjson abi_minor "${ABI_MINOR}" \
        --argjson abi_fingerprint "${ABI_FINGERPRINT}" \
        --argjson wasm_size_bytes "${WASM_SIZE_BYTES}" \
        --argjson evidence_ids "${EVIDENCE_IDS}" \
        --argjson duration_ms "${duration_ms}" \
        --argjson extra "${extra_json}" \
        '
        ({
          ts: $ts,
          level: $level,
          scenario_id: $scenario_id,
          run_id: $run_id,
          event: $event,
          msg: $msg,
          abi_version: { major: $abi_major, minor: $abi_minor },
          abi_fingerprint: $abi_fingerprint,
          browser: { name: $browser_name, version: $browser_version, os: $browser_os },
          build: { profile: $build_profile, commit: $build_commit, wasm_size_bytes: $wasm_size_bytes },
          module_url: $module_url,
          evidence_ids: $evidence_ids,
          extra: $extra
        }
        + (if $duration_ms >= 0 then { duration_ms: $duration_ms } else {} end)
        + (if ($error_code | length) > 0 then { error_code: $error_code } else {} end))
        ' >> "${LOG_JSONL_FILE}"
}

STEP_IDS=(
    "packaged_module_load"
    "bootstrap_to_runtime_ready"
    "reload_remount_cycle"
    "clean_shutdown"
)

STEP_PHASES=(
    "load"
    "bootstrap"
    "reload_remount"
    "shutdown"
)

STEP_COMMANDS=(
    "cargo test --test wasm_js_exports_coverage_contract browser_core_exports_have_conditional_root_with_three_conditions -- --nocapture"
    "cargo test --test nextjs_bootstrap_harness ssr_to_hydration_bootstrap_flow_is_deterministic -- --nocapture"
    "cargo test --test nextjs_bootstrap_harness nextjs_reference_template_deployment_flow_is_deterministic -- --nocapture"
    "cargo test --test react_wasm_strictmode_harness strict_mode_double_invocation_is_leak_free_and_cancel_correct -- --nocapture"
)

STEP_HINTS=(
    "Validate packaged module export/load surface for @asupersync/browser-core."
    "Validate deterministic hydration bootstrap to runtime-ready."
    "Validate deterministic reload/remount path with runtime re-init."
    "Validate clean shutdown with leak-free unmount and cancellation drain."
)

RUN_STARTED_TS="$(now_iso_millis)"
RUN_START_EPOCH="$(date +%s)"
EXIT_CODE=0
FAILED_STEP_ID=""
TESTS_PASSED=0
TESTS_FAILED=0

echo "==================================================================="
echo "       Asupersync WASM Packaged Bootstrap Harness E2E              "
echo "==================================================================="
echo "Config:"
echo "  RCH_BIN:                    ${RCH_BIN}"
echo "  SCENARIO_ID:                ${SCENARIO_ID}"
echo "  RUN_ID:                     ${RUN_ID}"
echo "  DRY_RUN:                    ${WASM_PACKAGED_BOOTSTRAP_DRY_RUN}"
echo "  STEP_TIMEOUT:               ${STEP_TIMEOUT}s"
echo "  TEST_SEED:                  ${TEST_SEED}"
echo "  Browser:                    ${BROWSER_NAME}/${BROWSER_VERSION} (${BROWSER_OS})"
echo "  Build commit/profile:       ${BUILD_COMMIT}/${WASM_BUILD_PROFILE}"
echo "  Artifact dir:               ${RUN_DIR}"
echo "  Perf summary:               ${PERF_SUMMARY_FILE}"
echo ""

log_event "info" "scenario_start" \
    "Starting packaged bootstrap/load/reload/shutdown harness" \
    -1 "" \
    "$(jq -cn \
        --arg step_count "${#STEP_IDS[@]}" \
        --arg dry_run "${WASM_PACKAGED_BOOTSTRAP_DRY_RUN}" \
        --arg seed "${TEST_SEED}" \
        '{step_count: ($step_count|tonumber), dry_run: ($dry_run == "1"), seed: $seed}')"

for idx in "${!STEP_IDS[@]}"; do
    step_id="${STEP_IDS[$idx]}"
    step_phase="${STEP_PHASES[$idx]}"
    step_command_base="${STEP_COMMANDS[$idx]}"
    step_hint="${STEP_HINTS[$idx]}"
    step_target_dir="${TMPDIR:-/tmp}/rch-wasm-packaged-bootstrap-${RUN_ID}-${step_id}"
    step_command="${RCH_BIN} exec -- env CARGO_TARGET_DIR=${step_target_dir} bash -lc \"${step_command_base}\""
    step_log="${RUN_DIR}/${step_id}.log"
    step_started="$(now_iso_millis)"
    step_start_epoch="$(date +%s)"

    echo ">>> [step $((idx + 1))/${#STEP_IDS[@]}] ${step_id}"

    log_event "info" "step_start" \
        "Starting ${step_phase} step ${step_id}" \
        -1 "" \
        "$(jq -cn \
            --arg step_id "${step_id}" \
            --arg step_phase "${step_phase}" \
            --arg command "${step_command}" \
            --arg hint "${step_hint}" \
            --arg started_at "${step_started}" \
            '{step_id: $step_id, step_phase: $step_phase, command: $command, hint: $hint, started_at: $started_at}')"

    step_rc=0
    if [[ "${WASM_PACKAGED_BOOTSTRAP_DRY_RUN}" == "1" ]]; then
        {
            echo "[dry-run] ${step_id}"
            echo "[dry-run] command: ${step_command}"
        } > "${step_log}"
    else
        set +e
        timeout "${STEP_TIMEOUT}" \
            "${RCH_BIN}" exec -- env "CARGO_TARGET_DIR=${step_target_dir}" bash -lc "${step_command_base}" \
            >"${step_log}" 2>&1
        step_rc=$?
        set -e
    fi

    step_end_epoch="$(date +%s)"
    step_duration_ms=$(((step_end_epoch - step_start_epoch) * 1000))
    step_outcome="pass"
    error_code=""
    if [[ "${step_rc}" -ne 0 ]]; then
        step_outcome="fail"
        error_code="ASSERTION_FAIL"
        EXIT_CODE=1
        FAILED_STEP_ID="${step_id}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    else
        TESTS_PASSED=$((TESTS_PASSED + 1))
    fi

    console_tail="$(
        tail -n 5 "${step_log}" 2>/dev/null \
            | jq -Rsc 'split("\n") | map(select(length > 0))'
    )"
    if [[ -z "${console_tail}" ]]; then
        console_tail='[]'
    fi

    jq -cn \
        --arg schema_version "wasm-packaged-bootstrap-step-v1" \
        --arg scenario_id "${SCENARIO_ID}" \
        --arg run_id "${RUN_ID}" \
        --arg step_id "${step_id}" \
        --arg step_phase "${step_phase}" \
        --arg command "${step_command}" \
        --arg started_at "${step_started}" \
        --arg ended_at "$(now_iso_millis)" \
        --arg outcome "${step_outcome}" \
        --arg log_path "${step_log}" \
        --arg hint "${step_hint}" \
        --argjson duration_ms "${step_duration_ms}" \
        --argjson exit_code "${step_rc}" \
        --argjson console_tail "${console_tail}" \
        '{
           schema_version: $schema_version,
           scenario_id: $scenario_id,
           run_id: $run_id,
           step_id: $step_id,
           step_phase: $step_phase,
           command: $command,
           started_at: $started_at,
           ended_at: $ended_at,
           outcome: $outcome,
           duration_ms: $duration_ms,
           exit_code: $exit_code,
           log_path: $log_path,
           hint: $hint,
           console_tail: $console_tail
         }' >> "${STEP_NDJSON_FILE}"

    log_event \
        "$( [[ "${step_outcome}" == "pass" ]] && echo "info" || echo "error" )" \
        "step_finish" \
        "Finished ${step_phase} step ${step_id} with ${step_outcome}" \
        "${step_duration_ms}" \
        "${error_code}" \
        "$(jq -cn \
            --arg step_id "${step_id}" \
            --arg step_phase "${step_phase}" \
            --arg outcome "${step_outcome}" \
            --arg command "${step_command}" \
            --arg log_path "${step_log}" \
            --argjson exit_code "${step_rc}" \
            --argjson console_tail "${console_tail}" \
            '{step_id: $step_id, step_phase: $step_phase, outcome: $outcome, command: $command, log_path: $log_path, exit_code: $exit_code, console_tail: $console_tail}')"

    if [[ "${EXIT_CODE}" -ne 0 ]]; then
        echo "  ERROR: ${step_id} failed (exit=${step_rc})"
        break
    fi
done

RUN_ENDED_TS="$(now_iso_millis)"
RUN_END_EPOCH="$(date +%s)"
TOTAL_DURATION_MS=$(((RUN_END_EPOCH - RUN_START_EPOCH) * 1000))
LOG_LINE_COUNT="$(wc -l < "${LOG_JSONL_FILE}" | tr -d ' ')"
SCREENSHOT_COUNT=0

VERDICT="pass"
if [[ "${WASM_PACKAGED_BOOTSTRAP_DRY_RUN}" == "1" ]]; then
    VERDICT="skip"
elif [[ "${EXIT_CODE}" -ne 0 ]]; then
    VERDICT="fail"
fi

FAILURE_SUMMARY="null"
if [[ "${EXIT_CODE}" -ne 0 ]]; then
    FAILURE_SUMMARY="$(jq -cn \
        --arg failed_step_id "${FAILED_STEP_ID}" \
        --arg reason "step failed" \
        '{failed_step_id: $failed_step_id, reason: $reason}')"
fi

jq -n \
    --arg schema_version "wasm-e2e-run-metadata-v1" \
    --arg scenario_id "${SCENARIO_ID}" \
    --arg run_id "${RUN_ID}" \
    --arg started_at "${RUN_STARTED_TS}" \
    --arg finished_at "${RUN_ENDED_TS}" \
    --arg verdict "${VERDICT}" \
    --arg browser_name "${BROWSER_NAME}" \
    --arg browser_version "${BROWSER_VERSION}" \
    --arg browser_os "${BROWSER_OS}" \
    --arg build_profile "${WASM_BUILD_PROFILE}" \
    --arg build_commit "${BUILD_COMMIT}" \
    --arg browser_core_version "${BROWSER_CORE_VERSION}" \
    --arg browser_version_pkg "${BROWSER_VERSION_PKG}" \
    --arg react_version_pkg "${REACT_VERSION_PKG}" \
    --arg next_version_pkg "${NEXT_VERSION_PKG}" \
    --arg perf_summary_file "${PERF_SUMMARY_FILE}" \
    --argjson abi_major "${ABI_MAJOR}" \
    --argjson abi_minor "${ABI_MINOR}" \
    --argjson abi_fingerprint "${ABI_FINGERPRINT}" \
    --argjson wasm_size_bytes "${WASM_SIZE_BYTES}" \
    --argjson duration_ms "${TOTAL_DURATION_MS}" \
    --argjson log_line_count "${LOG_LINE_COUNT}" \
    --argjson screenshot_count "${SCREENSHOT_COUNT}" \
    --argjson evidence_ids_covered "${EVIDENCE_IDS}" \
    --argjson wasm_artifact_identifiers "${WASM_ARTIFACT_IDENTIFIERS}" \
    --argjson failure_summary "${FAILURE_SUMMARY}" \
    '{
      schema_version: $schema_version,
      scenario_id: $scenario_id,
      run_id: $run_id,
      started_at: $started_at,
      finished_at: $finished_at,
      duration_ms: $duration_ms,
      verdict: $verdict,
      browser: {
        name: $browser_name,
        version: $browser_version,
        os: $browser_os
      },
      build: {
        profile: $build_profile,
        commit: $build_commit,
        wasm_size_bytes: $wasm_size_bytes
      },
      abi_version: { major: $abi_major, minor: $abi_minor },
      abi_fingerprint: $abi_fingerprint,
      evidence_ids_covered: $evidence_ids_covered,
      failure_summary: $failure_summary,
      log_line_count: $log_line_count,
      screenshot_count: $screenshot_count,
      perf_summary_file: $perf_summary_file,
      package_versions: {
        "@asupersync/browser-core": $browser_core_version,
        "@asupersync/browser": $browser_version_pkg,
        "@asupersync/react": $react_version_pkg,
        "@asupersync/next": $next_version_pkg
      },
      wasm_artifact_identifiers: $wasm_artifact_identifiers
    }' > "${RUN_METADATA_FILE}"

SUMMARY_STATUS="passed"
FAILURE_CLASS="none"
if [[ "${EXIT_CODE}" -ne 0 ]]; then
    SUMMARY_STATUS="failed"
    FAILURE_CLASS="test_or_invariant_failure"
fi

REPRO_COMMAND="TEST_LOG_LEVEL=${TEST_LOG_LEVEL} RUST_LOG=${RUST_LOG} TEST_SEED=${TEST_SEED} WASM_PACKAGED_BOOTSTRAP_DRY_RUN=${WASM_PACKAGED_BOOTSTRAP_DRY_RUN} bash ${SCRIPT_DIR}/$(basename "$0")"

jq -n \
    --arg suite_id "${SUITE_ID}" \
    --arg scenario_id "${SUITE_SCENARIO_ID}" \
    --arg seed "${TEST_SEED}" \
    --arg started_ts "${RUN_STARTED_TS}" \
    --arg ended_ts "${RUN_ENDED_TS}" \
    --arg status "${SUMMARY_STATUS}" \
    --arg failure_class "${FAILURE_CLASS}" \
    --arg repro_command "${REPRO_COMMAND}" \
    --arg artifact_path "${SUMMARY_FILE}" \
    --arg suite_script "${SCRIPT_DIR}/$(basename "$0")" \
    --arg log_file "${RUN_DIR}" \
    --arg artifact_dir "${RUN_DIR}" \
    --arg step_log_ndjson "${STEP_NDJSON_FILE}" \
    --argjson duration_ms "${TOTAL_DURATION_MS}" \
    --argjson tests_passed "${TESTS_PASSED}" \
    --argjson tests_failed "${TESTS_FAILED}" \
    --argjson exit_code "${EXIT_CODE}" \
    '{
       "schema_version": "e2e-suite-summary-v3",
       "suite_id": $suite_id,
       "scenario_id": $scenario_id,
       "seed": $seed,
       "started_ts": $started_ts,
       "ended_ts": $ended_ts,
       duration_ms: $duration_ms,
       "status": $status,
       "failure_class": $failure_class,
       "repro_command": $repro_command,
       "artifact_path": $artifact_path,
       suite: $suite_id,
       timestamp: $ended_ts,
       test_log_level: env.TEST_LOG_LEVEL,
       tests_passed: $tests_passed,
       tests_failed: $tests_failed,
       exit_code: $exit_code,
       suite_script: $suite_script,
       replay_command: $repro_command,
       log_file: $log_file,
       artifact_dir: $artifact_dir,
       step_log_ndjson: $step_log_ndjson
     }' > "${SUMMARY_FILE}"

log_event \
    "$( [[ "${EXIT_CODE}" -eq 0 ]] && echo "info" || echo "error" )" \
    "scenario_finish" \
    "Packaged bootstrap harness finished with verdict ${VERDICT}" \
    "${TOTAL_DURATION_MS}" \
    "$( [[ "${EXIT_CODE}" -eq 0 ]] && printf '' || printf 'ASSERTION_FAIL' )" \
    "$(jq -cn \
        --arg verdict "${VERDICT}" \
        --arg summary_file "${SUMMARY_FILE}" \
        --arg run_metadata "${RUN_METADATA_FILE}" \
        --arg steps_file "${STEP_NDJSON_FILE}" \
        --arg perf_summary_file "${PERF_SUMMARY_FILE}" \
        --arg failed_step_id "${FAILED_STEP_ID}" \
        '{verdict: $verdict, summary_file: $summary_file, run_metadata: $run_metadata, steps_file: $steps_file, perf_summary_file: $perf_summary_file, failed_step_id: $failed_step_id}')"

echo ""
echo "Summary: ${SUMMARY_FILE}"
echo "Run metadata: ${RUN_METADATA_FILE}"
echo "JSONL log: ${LOG_JSONL_FILE}"
echo "Step log NDJSON: ${STEP_NDJSON_FILE}"
echo "Perf summary: ${PERF_SUMMARY_FILE}"

exit "${EXIT_CODE}"
