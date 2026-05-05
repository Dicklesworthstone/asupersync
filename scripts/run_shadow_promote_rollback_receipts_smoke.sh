#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT="${PROJECT_ROOT}/artifacts/shadow_promote_rollback_receipts_smoke_contract_v1.json"
OUTPUT_ROOT="${SHADOW_PROMOTE_ROLLBACK_OUTPUT_ROOT:-${PROJECT_ROOT}/target/shadow-promote-rollback-receipts-smoke}"
SCENARIO="AA-SHADOW-PROMOTE-ROLLBACK-RECEIPT-64C-256G"
RUN_ID="${SHADOW_PROMOTE_ROLLBACK_RUN_ID:-manual}"
MODE="dry-run"
RCH_WRAPPER_TIMEOUT="${RCH_WRAPPER_TIMEOUT:-900}"

usage() {
    cat <<'USAGE'
Usage: bash scripts/run_shadow_promote_rollback_receipts_smoke.sh [options]

Options:
  --list                  List smoke scenarios and exit.
  --dry-run               Emit command and run report without executing rch (default).
  --execute               Execute the focused rch-backed smoke proof.
  --scenario <id>         Select scenario id.
  --output-root <path>    Override output root.
  --run-id <id>           Override run id.
USAGE
}

require_jq() {
    if ! command -v jq >/dev/null 2>&1; then
        echo "FATAL: jq is required for shadow promote/rollback smoke runner" >&2
        exit 2
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --list)
            require_jq
            jq -r '.smoke_scenarios[] | "  \(.scenario_id): \(.expected_decision)"' "$ARTIFACT"
            exit 0
            ;;
        --dry-run)
            MODE="dry-run"
            shift
            ;;
        --execute)
            MODE="execute"
            shift
            ;;
        --scenario)
            SCENARIO="${2:?missing scenario id}"
            shift 2
            ;;
        --output-root)
            OUTPUT_ROOT="${2:?missing output root}"
            shift 2
            ;;
        --run-id)
            RUN_ID="${2:?missing run id}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "FATAL: unknown argument $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

require_jq

if ! jq -e --arg scenario "$SCENARIO" '.smoke_scenarios[] | select(.scenario_id == $scenario)' "$ARTIFACT" >/dev/null; then
    echo "FATAL: scenario ${SCENARIO} not found in ${ARTIFACT}" >&2
    exit 2
fi

RUN_DIR="${OUTPUT_ROOT}/run_${RUN_ID}/${SCENARIO}"
REPORT_PATH="${RUN_DIR}/shadow_promote_rollback_receipt.json"
RUN_LOG_PATH="${RUN_DIR}/run.log"
RUN_REPORT_PATH="${RUN_DIR}/run_report.json"
REPORT_JSON_MARKER="ASUPERSYNC_SHADOW_PROMOTE_ROLLBACK_RECEIPT_JSON="
mkdir -p "$RUN_DIR"

COMMAND="timeout ${RCH_WRAPPER_TIMEOUT} rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' CARGO_TARGET_DIR=\${TMPDIR:-/tmp}/rch_target_shadow_promote_rollback_receipts ASUPERSYNC_SHADOW_PROMOTE_ROLLBACK_RECEIPT_PATH=${REPORT_PATH} cargo test -p asupersync --test shadow_promote_rollback_receipts_contract shadow_promote_rollback_receipt_smoke_emits_report --features test-internals -- --nocapture"
COMMAND_STATUS=0
REMOTE_TEST_PASSED=false
REPORT_SOURCE="not_run"

{
    printf 'SHADOW_PROMOTE_ROLLBACK scenario_id=%s mode=%s report_path=%s\n' "$SCENARIO" "$MODE" "$REPORT_PATH"
    printf 'SHADOW_PROMOTE_ROLLBACK command=%s\n' "$COMMAND"
} >"$RUN_LOG_PATH"

if [[ "$MODE" == "execute" ]]; then
    set +e
    (
        cd "$PROJECT_ROOT"
        eval "$COMMAND"
    ) >>"$RUN_LOG_PATH" 2>&1
    COMMAND_STATUS=$?
    set -e

    if grep -q 'test result: ok. 1 passed' "$RUN_LOG_PATH"; then
        REMOTE_TEST_PASSED=true
    fi

    if [[ -s "$REPORT_PATH" ]]; then
        REPORT_SOURCE="retrieved"
    else
        REPORT_JSON_LINE="$(grep -a "^${REPORT_JSON_MARKER}" "$RUN_LOG_PATH" | tail -n 1 || true)"
        if [[ -n "$REPORT_JSON_LINE" ]]; then
            printf '%s\n' "${REPORT_JSON_LINE#"$REPORT_JSON_MARKER"}" >"$REPORT_PATH"
            REPORT_SOURCE="reconstructed_from_log"
        else
            REPORT_SOURCE="missing"
        fi
    fi

    if [[ "$COMMAND_STATUS" -ne 0 && "$REMOTE_TEST_PASSED" != "true" ]]; then
        echo "FATAL: shadow promote/rollback command failed with status ${COMMAND_STATUS}" >>"$RUN_LOG_PATH"
        exit "$COMMAND_STATUS"
    fi
    if [[ ! -s "$REPORT_PATH" ]]; then
        echo "FATAL: shadow promote/rollback report missing after ${REPORT_SOURCE}" >>"$RUN_LOG_PATH"
        exit 1
    fi

    jq -e --arg scenario "$SCENARIO" '
        .schema_version == "shadow-promote-rollback-receipt-v1"
        and .scenario_id == $scenario
        and .decision == "promote"
        and .accepted == true
        and .no_win == false
        and .fallback_decision == "promote_candidate_bundle"
        and .shadow_run_decision == "promote"
        and .p99_delta_ns <= 0
        and .p999_delta_ns <= 0
        and .regret_margin_basis_points >= 250
        and (.refusal_reasons | length == 0)
        and (.dirty_artifacts | length == 0)
        and (.capacity_certificate_id | contains("capacity_envelope"))
        and (.latency_certificate_id | contains("latency_budget"))
        and (.rollback_receipt_path | endswith(".json"))
        and (.replay_command | contains("rch exec"))
    ' "$REPORT_PATH" >/dev/null
fi

REPORT_PROJECTION='{}'
if [[ -s "$REPORT_PATH" ]]; then
    REPORT_PROJECTION="$(jq -c '{
        decision,
        baseline_bundle_digest_sha256,
        candidate_bundle_digest_sha256,
        baseline_evidence_hash_sha256,
        candidate_evidence_hash_sha256,
        capacity_certificate_id,
        latency_certificate_id,
        shadow_run_decision,
        regret_margin_basis_points,
        p99_delta_ns,
        p999_delta_ns,
        detected_refusals: .refusal_reasons,
        rollback_receipt_path,
        artifact_path: $report_path,
        replay_command
    }' --arg report_path "$REPORT_PATH" "$REPORT_PATH")"
fi

jq -n \
    --arg schema_version "shadow-promote-rollback-run-report-v1" \
    --arg scenario_id "$SCENARIO" \
    --arg mode "$MODE" \
    --arg status "$(if [[ "$MODE" == "execute" ]]; then echo passed; else echo dry_run; fi)" \
    --arg command "$COMMAND" \
    --arg command_status "$COMMAND_STATUS" \
    --arg remote_test_passed "$REMOTE_TEST_PASSED" \
    --arg report_source "$REPORT_SOURCE" \
    --arg run_log_path "$RUN_LOG_PATH" \
    --arg report_path "$REPORT_PATH" \
    --argjson report_projection "$REPORT_PROJECTION" \
    '{
        schema_version: $schema_version,
        scenario_id: $scenario_id,
        mode: $mode,
        status: $status,
        command: $command,
        command_status: ($command_status | tonumber),
        remote_test_passed: ($remote_test_passed == "true"),
        report_source: $report_source,
        run_log_path: $run_log_path,
        report_path: $report_path
    } + $report_projection' >"$RUN_REPORT_PATH"

printf 'SHADOW_PROMOTE_ROLLBACK_RUN scenario_id=%s status=%s report=%s run_report=%s\n' \
    "$SCENARIO" "$(jq -r '.status' "$RUN_REPORT_PATH")" "$REPORT_PATH" "$RUN_REPORT_PATH"
