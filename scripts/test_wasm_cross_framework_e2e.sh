#!/usr/bin/env bash
# Cross-framework browser E2E runner (asupersync-umelq.18.3)
#
# Extended packaged bootstrap/load/reload harness coverage for:
#   asupersync-3qv04.8.4.1
# Extended host-bridge scenario harness coverage for:
#   asupersync-3qv04.8.4.3
#
# The script emits:
# - schema-style JSONL: target/e2e-runs/<scenario_id>/<run_id>/log.jsonl
# - run metadata: target/e2e-runs/<scenario_id>/<run_id>/run-metadata.json
# - step detail rows: target/e2e-runs/<scenario_id>/<run_id>/steps.ndjson
# - legacy summary copy under target/e2e-results/... for compatibility

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
RUN_STARTED_EPOCH="$(date +%s)"

RCH_BIN="${RCH_BIN:-$HOME/.local/bin/rch}"
SUITE_TIMEOUT="${SUITE_TIMEOUT:-1200}"
STEP_TIMEOUT="${STEP_TIMEOUT:-360}"
RCH_SCAN_TIMEOUT="${RCH_SCAN_TIMEOUT:-420}"
HARNESS_PROFILE="${HARNESS_PROFILE:-full}"
FAULT_MATRIX_MODE="${FAULT_MATRIX_MODE:-reduced}"
BROWSER_NAME="${BROWSER_NAME:-chromium-headless}"
BROWSER_VERSION="${BROWSER_VERSION:-unknown}"
HARNESS_DRY_RUN="${HARNESS_DRY_RUN:-0}"

export TEST_LOG_LEVEL="${TEST_LOG_LEVEL:-info}"
export RUST_LOG="${RUST_LOG:-asupersync=info}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export TEST_SEED="${TEST_SEED:-0xDEADBEEF}"

case "${HARNESS_PROFILE}" in
    full|packaged_bootstrap|host_bridge)
        ;;
    *)
        echo "FATAL: HARNESS_PROFILE must be one of: full, packaged_bootstrap, host_bridge" >&2
        exit 1
        ;;
esac

case "${FAULT_MATRIX_MODE}" in
    reduced|full)
        ;;
    *)
        echo "FATAL: FAULT_MATRIX_MODE must be one of: reduced, full" >&2
        exit 1
        ;;
esac

if [[ "${HARNESS_PROFILE}" == "packaged_bootstrap" ]]; then
    SUITE_ID="wasm_packaged_bootstrap_e2e"
    SCENARIO_ID="e2e-wasm-packaged-bootstrap-load-reload"
    LEGACY_OUTPUT_DIR="${PROJECT_ROOT}/target/e2e-results/wasm_packaged_bootstrap"
elif [[ "${HARNESS_PROFILE}" == "host_bridge" ]]; then
    SUITE_ID="wasm_host_bridge_e2e"
    SCENARIO_ID="e2e-wasm-host-bridge-suite"
    LEGACY_OUTPUT_DIR="${PROJECT_ROOT}/target/e2e-results/wasm_host_bridge"
else
    SUITE_ID="wasm_cross_framework_e2e"
    SCENARIO_ID="e2e-wasm-cross-framework-suite"
    LEGACY_OUTPUT_DIR="${PROJECT_ROOT}/target/e2e-results/wasm_cross_framework"
fi

if [[ ! -x "${RCH_BIN}" ]]; then
    echo "FATAL: rch is required and was not found/executable at: ${RCH_BIN}" >&2
    exit 1
fi

generate_run_id() {
    if command -v uuidgen >/dev/null 2>&1; then
        uuidgen | tr '[:upper:]' '[:lower:]'
        return
    fi
    if [[ -f /proc/sys/kernel/random/uuid ]]; then
        cat /proc/sys/kernel/random/uuid
        return
    fi
    printf '00000000-0000-4000-8000-%012d\n' "$((RANDOM * RANDOM + 1))"
}

sha256_file() {
    local path="$1"
    if [[ ! -f "$path" ]]; then
        printf '%s' "missing"
        return
    fi
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$path" | awk '{print $1}'
        return
    fi
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$path" | awk '{print $1}'
        return
    fi
    printf '%s' "unavailable"
}

RUN_ID="$(generate_run_id)"
ARTIFACT_ROOT="${PROJECT_ROOT}/target/e2e-runs"
ARTIFACT_DIR="${ARTIFACT_ROOT}/${SCENARIO_ID}/${RUN_ID}"
LEGACY_ARTIFACT_DIR="${LEGACY_OUTPUT_DIR}/artifacts_${TIMESTAMP}"

RUN_METADATA_FILE="${ARTIFACT_DIR}/run-metadata.json"
LOG_JSONL="${ARTIFACT_DIR}/log.jsonl"
STEP_NDJSON="${ARTIFACT_DIR}/steps.ndjson"
SUMMARY_FILE="${ARTIFACT_DIR}/summary.json"

mkdir -p "${ARTIFACT_DIR}" "${LEGACY_ARTIFACT_DIR}" "${ARTIFACT_DIR}/screenshots" "${ARTIFACT_DIR}/traces" "${ARTIFACT_DIR}/wasm-artifacts"

BROWSER_CORE_PACKAGE_JSON="${PROJECT_ROOT}/packages/browser-core/package.json"
BROWSER_PACKAGE_JSON="${PROJECT_ROOT}/packages/browser/package.json"
BROWSER_CORE_VERSION="$(jq -r '.version // "unknown"' "${BROWSER_CORE_PACKAGE_JSON}" 2>/dev/null || echo unknown)"
BROWSER_SDK_VERSION="$(jq -r '.version // "unknown"' "${BROWSER_PACKAGE_JSON}" 2>/dev/null || echo unknown)"
COMMIT_HASH="$(git -C "${PROJECT_ROOT}" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
OS_NAME="$(uname -s | tr '[:upper:]' '[:lower:]')"

ABI_METADATA_PATH="${PROJECT_ROOT}/packages/browser-core/abi-metadata.json"
if [[ -f "${ABI_METADATA_PATH}" ]]; then
    ABI_MAJOR="$(jq -r '.abi_version.major // 0' "${ABI_METADATA_PATH}" 2>/dev/null || echo 0)"
    ABI_MINOR="$(jq -r '.abi_version.minor // 0' "${ABI_METADATA_PATH}" 2>/dev/null || echo 0)"
    ABI_FINGERPRINT="$(jq -r '.abi_fingerprint // 0' "${ABI_METADATA_PATH}" 2>/dev/null || echo 0)"
else
    ABI_MAJOR=0
    ABI_MINOR=0
    ABI_FINGERPRINT=0
fi

WASM_MODULE_SOURCE=""
for candidate in \
    "${PROJECT_ROOT}/packages/browser-core/asupersync_bg.wasm" \
    "${PROJECT_ROOT}/pkg/asupersync_bg.wasm"
do
    if [[ -f "${candidate}" ]]; then
        WASM_MODULE_SOURCE="${candidate}"
        break
    fi
done

MODULE_RELATIVE_PATH=""
WASM_SIZE_BYTES=0
if [[ -n "${WASM_MODULE_SOURCE}" ]]; then
    cp "${WASM_MODULE_SOURCE}" "${ARTIFACT_DIR}/wasm-artifacts/asupersync_bg.wasm"
    MODULE_RELATIVE_PATH="wasm-artifacts/asupersync_bg.wasm"
    WASM_SIZE_BYTES="$(wc -c < "${WASM_MODULE_SOURCE}" | tr -d ' ')"
fi
MODULE_FINGERPRINT="$(sha256_file "${WASM_MODULE_SOURCE:-/dev/null}")"

for optional in asupersync.js.map asupersync_bg.wasm.map; do
    for source in "${PROJECT_ROOT}/packages/browser-core/${optional}" "${PROJECT_ROOT}/pkg/${optional}"; do
        if [[ -f "${source}" ]]; then
            cp "${source}" "${ARTIFACT_DIR}/wasm-artifacts/${optional}"
            break
        fi
    done
done

echo "==================================================================="
echo "         Asupersync WASM Cross-Framework Browser E2E               "
echo "==================================================================="
echo "Config:"
echo "  SUITE_ID:         ${SUITE_ID}"
echo "  SCENARIO_ID:      ${SCENARIO_ID}"
echo "  HARNESS_PROFILE:  ${HARNESS_PROFILE}"
echo "  RUN_ID:           ${RUN_ID}"
echo "  RCH_BIN:          ${RCH_BIN}"
echo "  TEST_LOG_LEVEL:   ${TEST_LOG_LEVEL}"
echo "  RUST_LOG:         ${RUST_LOG}"
echo "  TEST_SEED:        ${TEST_SEED}"
echo "  FAULT_MATRIX_MODE:${FAULT_MATRIX_MODE}"
echo "  SUITE_TIMEOUT:    ${SUITE_TIMEOUT}s"
echo "  STEP_TIMEOUT:     ${STEP_TIMEOUT}s"
echo "  HARNESS_DRY_RUN:  ${HARNESS_DRY_RUN}"
echo "  Artifacts:        ${ARTIFACT_DIR}"
echo ""

STEP_IDS=()
STEP_FRAMEWORK=()
STEP_CATEGORY=()
STEP_HINTS=()
STEP_COMMANDS=()
STEP_FAULT_PROFILE=()
STEP_EVIDENCE_IDS=()

add_step() {
    local step_id="$1"
    local framework="$2"
    local category="$3"
    local hint="$4"
    local command="$5"
    local fault_profile="$6"
    local evidence_ids_csv="$7"

    STEP_IDS+=("$step_id")
    STEP_FRAMEWORK+=("$framework")
    STEP_CATEGORY+=("$category")
    STEP_HINTS+=("$hint")
    STEP_COMMANDS+=("$command")
    STEP_FAULT_PROFILE+=("$fault_profile")
    STEP_EVIDENCE_IDS+=("$evidence_ids_csv")
}

if [[ "${HARNESS_PROFILE}" == "packaged_bootstrap" ]]; then
    add_step \
        "next.packaged_bootstrap.load_ssr_to_hydration" \
        "next" \
        "bootstrap_flow" \
        "Validate deterministic client hydration bootstrap path." \
        "cargo test --test nextjs_bootstrap_harness ssr_to_hydration_bootstrap_flow_is_deterministic -- --nocapture" \
        "none" \
        "L5-NEXT-HYDRATE,L8-WASM-VERSION"

    add_step \
        "next.packaged_bootstrap.reload_reference_template" \
        "next" \
        "reload_flow" \
        "Validate deterministic reload/remount behavior for the Next reference template." \
        "cargo test --test nextjs_bootstrap_harness nextjs_reference_template_deployment_flow_is_deterministic -- --nocapture" \
        "none" \
        "L5-NEXT-HYDRATE,L8-REPRO-COMMAND"

    add_step \
        "next.packaged_bootstrap.structured_log_metadata" \
        "next" \
        "metadata_logging" \
        "Validate replay-oriented structured metadata emitted by bootstrap logs." \
        "cargo test --test nextjs_bootstrap_harness nextjs_reference_template_structured_logs_include_replay_metadata -- --nocapture" \
        "none" \
        "L8-CONSOLE-CAPTURE,L8-REPRO-COMMAND"

    add_step \
        "next.packaged_bootstrap.cancel_retry_recovery" \
        "next" \
        "recovery_flow" \
        "Validate cancellation and retry recovery in bootstrap lifecycle." \
        "cargo test --test nextjs_bootstrap_harness cancelled_bootstrap_supports_retryable_recovery_path -- --nocapture" \
        "none" \
        "L5-NEXT-HYDRATE,L8-REPRO-COMMAND"

    add_step \
        "next.packaged_bootstrap.clean_shutdown" \
        "next" \
        "shutdown_flow" \
        "Validate hydration mismatch recovery flow completes without orphaned runtime state." \
        "cargo test --test nextjs_bootstrap_harness hydration_mismatch_recovers_via_rehydrate_path -- --nocapture" \
        "none" \
        "L5-NEXT-HYDRATE,L8-REPRO-COMMAND"
elif [[ "${HARNESS_PROFILE}" == "host_bridge" ]]; then
    add_step \
        "wasm.host_bridge.fetch_request_contract" \
        "vanilla" \
        "host_bridge_fetch" \
        "Validate fetch bridge contract mapping at the wasm ABI boundary." \
        "cargo test --test wasm_abi_contract wasm_abi_signature_matrix_matches_v1_contract -- --nocapture" \
        "none" \
        "L4-FETCH-BASIC,L8-REPRO-COMMAND"

    add_step \
        "wasm.host_bridge.readable_stream_flow" \
        "vanilla" \
        "host_bridge_stream" \
        "Validate browser readable stream bridge flow mapping." \
        "cargo test --lib readable_stream_reads_from_source -- --nocapture" \
        "none" \
        "L4-STREAM-FLOW,L8-REPRO-COMMAND"

    add_step \
        "wasm.host_bridge.writable_stream_backpressure" \
        "vanilla" \
        "host_bridge_stream" \
        "Validate browser writable stream backpressure mapping." \
        "cargo test --lib writable_stream_backpressure_detection -- --nocapture" \
        "none" \
        "L4-STREAM-FLOW,L8-REPRO-COMMAND"

    add_step \
        "wasm.host_bridge.websocket_lifecycle" \
        "vanilla" \
        "host_bridge_websocket" \
        "Validate websocket bridge handshake and lifecycle semantics." \
        "cargo test --test e2e_websocket ws_server_handshake_accepts_and_selects_protocol -- --nocapture" \
        "none" \
        "L4-WS-LIFECYCLE,L8-REPRO-COMMAND"

    add_step \
        "wasm.host_bridge.storage_roundtrip" \
        "vanilla" \
        "host_bridge_storage" \
        "Validate browser storage bridge deterministic round-trip behavior." \
        "cargo test --lib adapter_round_trip_set_get_delete_is_deterministic -- --nocapture" \
        "none" \
        "L4-STORAGE-ROUNDTRIP,L8-REPRO-COMMAND"

    add_step \
        "wasm.host_bridge.abort_signal_propagation" \
        "vanilla" \
        "host_bridge_abort" \
        "Validate abort/cancellation signal mapping at the stream boundary." \
        "cargo test --lib readable_stream_cancel_produces_error -- --nocapture" \
        "none" \
        "L4-ABORT,L8-REPRO-COMMAND"
else
    add_step "vanilla.scheduler_ready_handoff_limit" "vanilla" "initialization_orchestration" "Inspect browser scheduler handoff controls in src/runtime/scheduler/three_lane.rs." "cargo test --test scheduler_browser_determinism browser_ready_handoff_limit_bounds_burst_size -- --nocapture" "none" "L8-REPRO-COMMAND"
    add_step "vanilla.cancel_preempts_ready_burst" "vanilla" "cancellation_race" "Inspect cancel-lane preemption ordering in scheduler browser path." "cargo test --test scheduler_browser_determinism browser_cancel_preempts_ready_burst -- --nocapture" "none" "L8-REPRO-COMMAND"
    add_step "react.strict_mode_double_invocation" "react" "strict_mode_cleanup" "Inspect React provider strict-mode lifecycle accounting in tests/react_wasm_strictmode_harness.rs." "cargo test --test react_wasm_strictmode_harness strict_mode_double_invocation_is_leak_free_and_cancel_correct -- --nocapture" "none" "L5-REACT-STRICT"
    add_step "react.concurrent_restart_loser_drain" "react" "loser_drain" "Inspect loser-drain + cancellation transitions for concurrent render restart." "cargo test --test react_wasm_strictmode_harness concurrent_render_restart_pattern_cancels_and_drains_losers -- --nocapture" "none" "L5-REACT-MOUNT"
    add_step "next.bootstrap_ssr_to_hydration" "next" "bootstrap_flow" "Inspect Next bootstrap state transitions in src/web/nextjs_bootstrap.rs." "cargo test --test nextjs_bootstrap_harness ssr_to_hydration_bootstrap_flow_is_deterministic -- --nocapture" "none" "L5-NEXT-HYDRATE"
    add_step "next.negative_cache_revalidation_rejected" "next" "negative_path" "Inspect invalid-command guardrails in Next bootstrap command handling." "cargo test --test nextjs_bootstrap_harness cache_revalidation_before_hydration_is_rejected -- --nocapture" "none" "L5-NEXT-HYDRATE"
    add_step "next.recovery_cancelled_bootstrap_retry" "next" "recovery_path" "Inspect retry recovery flow for cancelled bootstrap transitions." "cargo test --test nextjs_bootstrap_harness cancelled_bootstrap_supports_retryable_recovery_path -- --nocapture" "none" "L5-NEXT-HYDRATE"
    add_step "next.recovery_hydration_mismatch_rehydrate" "next" "recovery_path" "Inspect hydration mismatch recovery/reset semantics." "cargo test --test nextjs_bootstrap_harness hydration_mismatch_recovers_via_rehydrate_path -- --nocapture" "none" "L5-NEXT-HYDRATE"
    add_step "wasm.host_interruption_tab_suspension" "vanilla" "hostile_timing" "Inspect obligation ledger behavior under tab-suspension style timing gaps." "cargo test --test obligation_wasm_parity wasm_host_interruption_tab_suspension_multi_obligation -- --nocapture" "none" "L8-REPRO-COMMAND"
    add_step "wasm.host_interruption_cancel_drain" "vanilla" "hostile_timing" "Inspect cancellation drain invariants under host interruption timing." "cargo test --test obligation_wasm_parity wasm_host_interruption_during_cancel_drain -- --nocapture" "none" "L8-REPRO-COMMAND"
    add_step "vanilla.browser_replay_report_artifact" "vanilla" "replay_artifact" "Inspect browser replay artifact/report generation pipeline in tests/replay_e2e_suite.rs." "cargo test --test replay_e2e_suite browser_replay_report_artifact_e2e -- --nocapture" "none" "L8-REPRO-COMMAND"
    add_step "vanilla.browser_replay_schedule_fuzz_corpus" "vanilla" "replay_artifact" "Inspect schedule-permutation fuzz corpus artifact generation (schedule_permutation_fuzz_corpus.json) in tests/replay_e2e_suite.rs." "cargo test --test replay_e2e_suite schedule_permutation_fuzz_regression_corpus_artifact -- --nocapture" "none" "L8-REPRO-COMMAND"
    add_step "vanilla.browser_replay_delta_drift_bundle" "vanilla" "replay_artifact" "Inspect golden replay-delta drift triage bundle generation (golden_trace_replay_delta_triage_bundle.json) in tests/replay_e2e_suite.rs." "cargo test --test replay_e2e_suite golden_trace_replay_delta_report_flags_fixture_drift -- --nocapture" "none" "L8-REPRO-COMMAND"

    add_step "network.fault_latency_spike_websocket_recovery" "vanilla" "network_fault_injection" "Validate websocket path resilience under deterministic latency spike profile with structured fault metadata." "ASUPERSYNC_TEST_FAULT_PROFILE=latency_spike ASUPERSYNC_TEST_FAULT_SEED=${TEST_SEED} cargo test --test e2e_websocket -- --nocapture" "latency_spike" "L8-REPRO-COMMAND"
    add_step "network.fault_packet_loss_transport_recovery" "vanilla" "network_fault_injection" "Validate transport path resilience under deterministic packet-loss profile with structured fault metadata." "ASUPERSYNC_TEST_FAULT_PROFILE=packet_loss_05pct ASUPERSYNC_TEST_FAULT_SEED=${TEST_SEED} cargo test --test e2e_transport -- --nocapture" "packet_loss_05pct" "L8-REPRO-COMMAND"

    if [[ "${FAULT_MATRIX_MODE}" == "full" ]]; then
        add_step "network.fault_disconnect_reconnect_websocket" "react" "network_fault_injection" "Validate reconnect behavior under deterministic disconnect/reconnect fault profile." "ASUPERSYNC_TEST_FAULT_PROFILE=disconnect_reconnect ASUPERSYNC_TEST_FAULT_SEED=${TEST_SEED} cargo test --test e2e_websocket -- --nocapture" "disconnect_reconnect" "L8-REPRO-COMMAND"
        add_step "network.fault_timeout_race_signal_path" "next" "network_fault_injection" "Validate timeout-race behavior under deterministic timeout profile and replay-ready logs." "ASUPERSYNC_TEST_FAULT_PROFILE=timeout_race ASUPERSYNC_TEST_FAULT_SEED=${TEST_SEED} cargo test --test e2e_signal -- --nocapture" "timeout_race" "L8-REPRO-COMMAND"
        add_step "network.fault_partial_io_transport_path" "next" "network_fault_injection" "Validate partial read/write path under deterministic partial-io profile." "ASUPERSYNC_TEST_FAULT_PROFILE=partial_io ASUPERSYNC_TEST_FAULT_SEED=${TEST_SEED} cargo test --test e2e_transport -- --nocapture" "partial_io" "L8-REPRO-COMMAND"
    fi
fi

collect_trace_pointers() {
    local log_path="$1"
    local pointers
    pointers="$(
        grep -Eo 'artifacts/[A-Za-z0-9._/\-]+' "$log_path" 2>/dev/null \
            | sort -u \
            | head -n 12 \
            || true
    )"
    if [[ -z "${pointers}" ]]; then
        printf '%s' '[]'
    else
        printf '%s\n' "${pointers}" | jq -Rsc 'split("\n") | map(select(length>0))'
    fi
}

ts_now() {
    date -u +"%Y-%m-%dT%H:%M:%S.%3NZ"
}

emit_log_entry() {
    local level="$1"
    local event="$2"
    local msg="$3"
    local duration_ms="$4"
    local evidence_ids_json="$5"
    local error_code="$6"
    local extra_json="$7"

    jq -cn \
        --arg ts "$(ts_now)" \
        --arg level "${level}" \
        --arg scenario_id "${SCENARIO_ID}" \
        --arg run_id "${RUN_ID}" \
        --arg event "${event}" \
        --arg msg "${msg}" \
        --arg browser_name "${BROWSER_NAME}" \
        --arg browser_version "${BROWSER_VERSION}" \
        --arg os_name "${OS_NAME}" \
        --arg profile "${HARNESS_PROFILE}" \
        --arg commit "${COMMIT_HASH}" \
        --arg module_url "${MODULE_RELATIVE_PATH}" \
        --argjson wasm_size_bytes "${WASM_SIZE_BYTES}" \
        --argjson abi_major "${ABI_MAJOR}" \
        --argjson abi_minor "${ABI_MINOR}" \
        --argjson abi_fingerprint "${ABI_FINGERPRINT}" \
        --argjson duration_ms "${duration_ms}" \
        --argjson evidence_ids "${evidence_ids_json}" \
        --arg error_code "${error_code}" \
        --argjson extra "${extra_json}" \
        '({
            ts: $ts,
            level: $level,
            scenario_id: $scenario_id,
            run_id: $run_id,
            event: $event,
            msg: $msg,
            abi_version: {major: $abi_major, minor: $abi_minor},
            abi_fingerprint: $abi_fingerprint,
            browser: {name: $browser_name, version: $browser_version, os: $os_name},
            build: {profile: $profile, commit: $commit, wasm_size_bytes: $wasm_size_bytes},
            evidence_ids: $evidence_ids,
            extra: $extra
          }
          + (if ($module_url | length) > 0 then {module_url: $module_url} else {} end)
          + (if $duration_ms >= 0 then {duration_ms: $duration_ms} else {} end)
          + (if ($error_code | length) > 0 then {error_code: $error_code} else {} end)
         )' >> "${LOG_JSONL}"
}

append_step_row() {
    local row_json="$1"
    printf '%s\n' "$row_json" >> "${STEP_NDJSON}"
}

EXIT_CODE=0
FAILED_STEP_IDS=()
FRAMEWORKS_COVERED=()
FAULT_PROFILES_EXECUTED=()
EVIDENCE_IDS_COLLECTED=()
: > "${STEP_NDJSON}"
: > "${LOG_JSONL}"

for idx in "${!STEP_IDS[@]}"; do
    step_id="${STEP_IDS[$idx]}"
    framework="${STEP_FRAMEWORK[$idx]}"
    category="${STEP_CATEGORY[$idx]}"
    hint="${STEP_HINTS[$idx]}"
    command_base="${STEP_COMMANDS[$idx]}"
    fault_profile="${STEP_FAULT_PROFILE[$idx]:-none}"
    evidence_ids_csv="${STEP_EVIDENCE_IDS[$idx]:-L8-REPRO-COMMAND}"

    target_dir_step="${step_id//[^a-zA-Z0-9]/_}"
    target_dir="/tmp/rch-wasm-cross-${TIMESTAMP}-${target_dir_step}"
    command="${RCH_BIN} exec -- env CARGO_TARGET_DIR=${target_dir} ${command_base}"
    step_log="${ARTIFACT_DIR}/${step_id}.log"

    FRAMEWORKS_COVERED+=("${framework}")
    if [[ "${fault_profile}" != "none" ]]; then
        FAULT_PROFILES_EXECUTED+=("${fault_profile}")
    fi

    IFS=',' read -r -a evidence_ids_arr <<< "${evidence_ids_csv}"
    for eid in "${evidence_ids_arr[@]}"; do
        if [[ -n "${eid}" ]]; then
            EVIDENCE_IDS_COLLECTED+=("${eid}")
        fi
    done
    evidence_ids_json="$(printf '%s\n' "${evidence_ids_arr[@]}" | jq -Rsc 'split("\n") | map(select(length>0))')"

    started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    step_start_epoch="$(date +%s)"

    start_extra="$(jq -cn \
        --arg suite_id "${SUITE_ID}" \
        --arg step_id "${step_id}" \
        --arg framework "${framework}" \
        --arg category "${category}" \
        --arg command "${command}" \
        --arg fault_profile "${fault_profile}" \
        --arg hint "${hint}" \
        --arg started_at "${started_at}" \
        --arg suite_started_at "${RUN_STARTED_TS}" \
        --arg core_version "${BROWSER_CORE_VERSION}" \
        --arg browser_version_pkg "${BROWSER_SDK_VERSION}" \
        --arg module_fingerprint "${MODULE_FINGERPRINT}" \
        '{
            suite_id: $suite_id,
            step_id: $step_id,
            framework: $framework,
            category: $category,
            command: $command,
            fault_profile: $fault_profile,
            remediation_hint: $hint,
            package_versions: {
              browser_core: $core_version,
              browser: $browser_version_pkg
            },
            wasm_artifact: {
              fingerprint: $module_fingerprint,
              module_path: "wasm-artifacts/asupersync_bg.wasm",
              present: ($module_fingerprint != "missing")
            },
            timing_markers: {
              suite_started_at: $suite_started_at,
              step_started_at: $started_at
            }
        }')"

    emit_log_entry "info" "step_start" "Starting ${step_id}" -1 "${evidence_ids_json}" "" "${start_extra}"

    echo ">>> [step $((idx + 1))/${#STEP_IDS[@]}] ${step_id}"

    set +e
    if [[ "${HARNESS_DRY_RUN}" == "1" ]]; then
        printf '[dry-run] %s\n' "${command}" >"${step_log}"
        step_rc=0
    else
        timeout "${STEP_TIMEOUT}" bash -lc "${command}" >"${step_log}" 2>&1
        step_rc=$?
    fi
    set -e

    step_end_epoch="$(date +%s)"
    ended_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    duration_ms=$(((step_end_epoch - step_start_epoch) * 1000))

    outcome="pass"
    level="info"
    error_code=""
    if [[ "${step_rc}" -ne 0 ]]; then
        if [[ "${step_rc}" -eq 124 ]]; then
            outcome="timeout"
            error_code="BRIDGE_TIMEOUT"
        else
            outcome="fail"
            error_code="ASSERTION_FAIL"
        fi
        level="error"
        EXIT_CODE=1
        FAILED_STEP_IDS+=("${step_id}")
    fi

    trace_pointer_json="$(collect_trace_pointers "${step_log}")"
    if [[ -z "${trace_pointer_json}" || "${trace_pointer_json}" == "null" ]]; then
        trace_pointer_json='[]'
    fi

    finish_extra="$(jq -cn \
        --arg suite_id "${SUITE_ID}" \
        --arg step_id "${step_id}" \
        --arg framework "${framework}" \
        --arg category "${category}" \
        --arg command "${command}" \
        --arg fault_profile "${fault_profile}" \
        --arg hint "${hint}" \
        --arg started_at "${started_at}" \
        --arg ended_at "${ended_at}" \
        --arg log_path "${step_log}" \
        --arg core_version "${BROWSER_CORE_VERSION}" \
        --arg browser_version_pkg "${BROWSER_SDK_VERSION}" \
        --arg module_fingerprint "${MODULE_FINGERPRINT}" \
        --argjson trace_artifacts "${trace_pointer_json}" \
        --arg scenario_id "${SCENARIO_ID}" \
        --arg run_id "${RUN_ID}" \
        --arg suite_started_at "${RUN_STARTED_TS}" \
        --arg harness_profile "${HARNESS_PROFILE}" \
        --arg fault_matrix_mode_arg "${FAULT_MATRIX_MODE}" \
        '{
            suite_id: $suite_id,
            step_id: $step_id,
            framework: $framework,
            category: $category,
            command: $command,
            fault_profile: $fault_profile,
            remediation_hint: $hint,
            step_log_path: $log_path,
            trace_artifacts: $trace_artifacts,
            package_versions: {
              browser_core: $core_version,
              browser: $browser_version_pkg
            },
            wasm_artifact: {
              fingerprint: $module_fingerprint,
              module_path: "wasm-artifacts/asupersync_bg.wasm",
              present: ($module_fingerprint != "missing")
            },
            console_output: {
              captured: true,
              path: $log_path
            },
            scenario_metadata: {
              scenario_id: $scenario_id,
              run_id: $run_id,
              harness_profile: $harness_profile,
              fault_matrix_mode: $fault_matrix_mode_arg
            },
            timing_markers: {
              suite_started_at: $suite_started_at,
              step_started_at: $started_at,
              step_ended_at: $ended_at
            }
        }')"

    emit_log_entry "${level}" "step_finish" "Finished ${step_id} (${outcome})" "${duration_ms}" "${evidence_ids_json}" "${error_code}" "${finish_extra}"

    step_row="$(jq -cn \
        --arg schema_version "wasm-cross-framework-step-v2" \
        --arg suite_id "${SUITE_ID}" \
        --arg scenario_id "${SCENARIO_ID}" \
        --arg step_id "${step_id}" \
        --arg framework "${framework}" \
        --arg category "${category}" \
        --arg command "${command}" \
        --arg repro_command "${command}" \
        --arg started_at "${started_at}" \
        --arg ended_at "${ended_at}" \
        --arg outcome "${outcome}" \
        --arg log_path "${step_log}" \
        --arg remediation_hint "${hint}" \
        --arg fault_profile "${fault_profile}" \
        --arg fault_matrix_mode "${FAULT_MATRIX_MODE}" \
        --arg fault_seed "${TEST_SEED}" \
        --argjson exit_code "${step_rc}" \
        --argjson duration_ms "${duration_ms}" \
        --argjson trace_artifacts "${trace_pointer_json}" \
        --argjson evidence_ids "${evidence_ids_json}" \
        '{
           schema_version: $schema_version,
           suite_id: $suite_id,
           scenario_id: $scenario_id,
           step_id: $step_id,
           framework: $framework,
           category: $category,
           command: $command,
           repro_command: $repro_command,
           started_at: $started_at,
           ended_at: $ended_at,
           duration_ms: $duration_ms,
           exit_code: $exit_code,
           outcome: $outcome,
           log_path: $log_path,
           trace_artifacts: $trace_artifacts,
           remediation_hint: $remediation_hint,
           fault_profile: $fault_profile,
           fault_matrix_mode: $fault_matrix_mode,
           fault_seed: $fault_seed,
           evidence_ids: $evidence_ids
         }')"
    append_step_row "${step_row}"

    if [[ "${EXIT_CODE}" -ne 0 ]]; then
        echo "  ERROR: ${step_id} failed (exit=${step_rc})"
        break
    fi
done

RUN_ENDED_EPOCH="$(date +%s)"
RUN_ENDED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
TOTAL_DURATION_MS=$(((RUN_ENDED_EPOCH - RUN_STARTED_EPOCH) * 1000))

frameworks_json="$(printf '%s\n' "${FRAMEWORKS_COVERED[@]-}" | sort -u | jq -Rsc 'split("\n") | map(select(length>0))')"
failed_steps_json="$(printf '%s\n' "${FAILED_STEP_IDS[@]-}" | jq -Rsc 'split("\n") | map(select(length>0))')"
fault_profiles_json="$(printf '%s\n' "${FAULT_PROFILES_EXECUTED[@]-}" | sort -u | jq -Rsc 'split("\n") | map(select(length>0))')"
evidence_ids_json="$(printf '%s\n' "${EVIDENCE_IDS_COLLECTED[@]-}" | sort -u | jq -Rsc 'split("\n") | map(select(length>0))')"
steps_recorded="$(wc -l < "${STEP_NDJSON}" | tr -d ' ')"
log_line_count="$(wc -l < "${LOG_JSONL}" | tr -d ' ')"

verdict="pass"
status="passed"
if [[ "${EXIT_CODE}" -ne 0 ]]; then
    verdict="fail"
    status="failed"
fi

failure_summary_json='null'
if [[ "${EXIT_CODE}" -ne 0 && "${#FAILED_STEP_IDS[@]}" -gt 0 ]]; then
    failure_summary_json="$(jq -cn --arg first_step "${FAILED_STEP_IDS[0]}" --arg reason "step_failure" '{first_failed_step: $first_step, reason: $reason}')"
fi

jq -n \
    --arg schema_version "wasm-e2e-run-metadata-v1" \
    --arg scenario_id "${SCENARIO_ID}" \
    --arg run_id "${RUN_ID}" \
    --arg started_at "${RUN_STARTED_TS}" \
    --arg finished_at "${RUN_ENDED_TS}" \
    --arg verdict "${verdict}" \
    --arg browser_name "${BROWSER_NAME}" \
    --arg browser_version "${BROWSER_VERSION}" \
    --arg os_name "${OS_NAME}" \
    --arg profile "${HARNESS_PROFILE}" \
    --arg commit "${COMMIT_HASH}" \
    --argjson wasm_size_bytes "${WASM_SIZE_BYTES}" \
    --argjson abi_major "${ABI_MAJOR}" \
    --argjson abi_minor "${ABI_MINOR}" \
    --argjson abi_fingerprint "${ABI_FINGERPRINT}" \
    --argjson duration_ms "${TOTAL_DURATION_MS}" \
    --argjson evidence_ids_covered "${evidence_ids_json}" \
    --argjson log_line_count "${log_line_count}" \
    --argjson screenshot_count 0 \
    --argjson failure_summary "${failure_summary_json}" \
    '{
       schema_version: $schema_version,
       scenario_id: $scenario_id,
       run_id: $run_id,
       started_at: $started_at,
       finished_at: $finished_at,
       duration_ms: $duration_ms,
       verdict: $verdict,
       browser: {name: $browser_name, version: $browser_version, os: $os_name},
       build: {profile: $profile, commit: $commit, wasm_size_bytes: $wasm_size_bytes},
       abi_version: {major: $abi_major, minor: $abi_minor},
       abi_fingerprint: $abi_fingerprint,
       evidence_ids_covered: $evidence_ids_covered,
       failure_summary: $failure_summary,
       log_line_count: $log_line_count,
       screenshot_count: $screenshot_count
     }' > "${RUN_METADATA_FILE}"

REPRO_COMMAND="HARNESS_PROFILE=${HARNESS_PROFILE} TEST_LOG_LEVEL=${TEST_LOG_LEVEL} RUST_LOG=${RUST_LOG} TEST_SEED=${TEST_SEED} bash ${SCRIPT_DIR}/$(basename "$0")"

jq -n \
    --arg schema_version "e2e-suite-summary-v3" \
    --arg suite_id "${SUITE_ID}" \
    --arg scenario_id "${SCENARIO_ID}" \
    --arg run_id "${RUN_ID}" \
    --arg seed "${TEST_SEED}" \
    --arg started_ts "${RUN_STARTED_TS}" \
    --arg ended_ts "${RUN_ENDED_TS}" \
    --arg status "${status}" \
    --arg repro_command "${REPRO_COMMAND}" \
    --arg run_metadata_path "${RUN_METADATA_FILE}" \
    --arg artifact_dir "${ARTIFACT_DIR}" \
    --arg log_jsonl "${LOG_JSONL}" \
    --arg step_log_ndjson "${STEP_NDJSON}" \
    --arg fault_matrix_mode "${FAULT_MATRIX_MODE}" \
    --arg harness_profile "${HARNESS_PROFILE}" \
    --arg module_fingerprint "${MODULE_FINGERPRINT}" \
    --argjson duration_ms "${TOTAL_DURATION_MS}" \
    --argjson tests_passed "$((steps_recorded - ${#FAILED_STEP_IDS[@]}))" \
    --argjson tests_failed "${#FAILED_STEP_IDS[@]}" \
    --argjson exit_code "${EXIT_CODE}" \
    --argjson frameworks "${frameworks_json}" \
    --argjson fault_profiles "${fault_profiles_json}" \
    --argjson failed_steps "${failed_steps_json}" \
    --argjson evidence_ids "${evidence_ids_json}" \
    --argjson step_count "${steps_recorded}" \
    '{
       schema_version: $schema_version,
       suite_id: $suite_id,
       scenario_id: $scenario_id,
       run_id: $run_id,
       seed: $seed,
       started_ts: $started_ts,
       ended_ts: $ended_ts,
       duration_ms: $duration_ms,
       status: $status,
       repro_command: $repro_command,
       run_metadata_path: $run_metadata_path,
       artifact_dir: $artifact_dir,
       log_jsonl: $log_jsonl,
       step_log_ndjson: $step_log_ndjson,
       fault_matrix_mode: $fault_matrix_mode,
       harness_profile: $harness_profile,
       module_fingerprint: $module_fingerprint,
       tests_passed: $tests_passed,
       tests_failed: $tests_failed,
       exit_code: $exit_code,
       frameworks_covered: $frameworks,
       fault_profiles: $fault_profiles,
       failed_steps: $failed_steps,
       evidence_ids: $evidence_ids,
       step_count: $step_count
     }' > "${SUMMARY_FILE}"

cp "${SUMMARY_FILE}" "${LEGACY_ARTIFACT_DIR}/summary.json"
cp "${STEP_NDJSON}" "${LEGACY_ARTIFACT_DIR}/steps.ndjson"
cp "${LOG_JSONL}" "${LEGACY_ARTIFACT_DIR}/log.jsonl"
cp "${RUN_METADATA_FILE}" "${LEGACY_ARTIFACT_DIR}/run-metadata.json"

echo ""
echo "Run Metadata: ${RUN_METADATA_FILE}"
echo "Schema Log JSONL: ${LOG_JSONL}"
echo "Step NDJSON: ${STEP_NDJSON}"
echo "Summary: ${SUMMARY_FILE}"
echo "Legacy copy: ${LEGACY_ARTIFACT_DIR}"

if [[ "${EXIT_CODE}" -ne 0 ]]; then
    exit 1
fi

exit 0
