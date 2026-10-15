#!/usr/bin/env bash
# WASM Pilot Observability E2E (asupersync-umelq.17.2)
#
# Verifies deterministic pilot telemetry/SLO gates:
# - pass scenario (no threshold/parity breach)
# - failure-injection scenario (threshold + parity breaches)
# - actionable alert payloads with replay + owner routing context

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "${SCRIPT_DIR}")"
OUTPUT_DIR="${PROJECT_ROOT}/target/e2e-results/wasm_pilot_observability"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ARTIFACT_DIR="${OUTPUT_DIR}/artifacts_${TIMESTAMP}"
WORK_DIR="/tmp/asupersync_wasm_pilot_observability_${TIMESTAMP}_$$"
PASS_INPUT="${WORK_DIR}/telemetry_pass_input.json"
FAIL_INPUT="${WORK_DIR}/telemetry_fail_input.json"
PASS_SUMMARY="${ARTIFACT_DIR}/pilot_observability_pass_summary.json"
FAIL_SUMMARY="${ARTIFACT_DIR}/pilot_observability_fail_summary.json"
PASS_ALERTS="${ARTIFACT_DIR}/pilot_observability_pass_alerts.ndjson"
FAIL_ALERTS="${ARTIFACT_DIR}/pilot_observability_fail_alerts.ndjson"
E2E_SUMMARY="${ARTIFACT_DIR}/summary.json"
SUITE_ID="wasm_pilot_observability_e2e"
E2E_SCENARIO_ID="E2E-SUITE-WASM-PILOT-OBSERVABILITY"

if ! command -v jq >/dev/null 2>&1; then
    echo "FATAL: jq is required for schema checks" >&2
    exit 1
fi

mkdir -p "${OUTPUT_DIR}" "${ARTIFACT_DIR}" "${WORK_DIR}"

cat > "${PASS_INPUT}" <<'EOF'
{
  "seed": 4242,
  "parity_tolerance_pct_default": 5.0,
  "events": [
    {
      "scenario_id": "pilot-pass-react",
      "framework": "react",
      "profile_family": "wasm",
      "signal_name": "incident_mtta_minutes",
      "signal_source": "pilot_drill",
      "signal_value": 8.0,
      "threshold_kind": "max",
      "threshold_value": 15.0,
      "capability_surface": "wasm.replay",
      "owner_route": "oncall:wasm-runtime",
      "replay_command": "asupersync lab replay examples/scenarios/smoke_happy_path.yaml --seed 4242",
      "trace_pointer": "artifacts/replay/pilot-pass-react-wasm.json",
      "remediation_pointer": "docs/wasm_pilot_observability_contract.md#alerting-and-owner-routing-rules"
    },
    {
      "scenario_id": "pilot-pass-react",
      "framework": "react",
      "profile_family": "native",
      "signal_name": "incident_mtta_minutes",
      "signal_source": "pilot_drill",
      "signal_value": 8.2,
      "threshold_kind": "max",
      "threshold_value": 15.0,
      "capability_surface": "native.replay",
      "owner_route": "oncall:wasm-runtime",
      "replay_command": "asupersync lab replay examples/scenarios/smoke_happy_path.yaml --seed 4242",
      "trace_pointer": "artifacts/replay/pilot-pass-react-native.json",
      "remediation_pointer": "docs/wasm_pilot_observability_contract.md#alerting-and-owner-routing-rules"
    },
    {
      "scenario_id": "pilot-pass-vanilla",
      "framework": "vanilla",
      "profile_family": "wasm",
      "signal_name": "replay_success_rate_pct",
      "signal_source": "pilot_drill",
      "signal_value": 99.5,
      "threshold_kind": "min",
      "threshold_value": 98.0,
      "capability_surface": "wasm.replay",
      "owner_route": "oncall:wasm-runtime",
      "replay_command": "asupersync lab replay examples/scenarios/smoke_happy_path.yaml --seed 4242",
      "trace_pointer": "artifacts/replay/pilot-pass-vanilla-wasm.json",
      "remediation_pointer": "docs/wasm_pilot_observability_contract.md#incident-drill-linkage-requirement"
    },
    {
      "scenario_id": "pilot-pass-vanilla",
      "framework": "vanilla",
      "profile_family": "native",
      "signal_name": "replay_success_rate_pct",
      "signal_source": "pilot_drill",
      "signal_value": 99.2,
      "threshold_kind": "min",
      "threshold_value": 98.0,
      "capability_surface": "native.replay",
      "owner_route": "oncall:wasm-runtime",
      "replay_command": "asupersync lab replay examples/scenarios/smoke_happy_path.yaml --seed 4242",
      "trace_pointer": "artifacts/replay/pilot-pass-vanilla-native.json",
      "remediation_pointer": "docs/wasm_pilot_observability_contract.md#incident-drill-linkage-requirement"
    },
    {
      "scenario_id": "pilot-pass-next",
      "framework": "next",
      "profile_family": "wasm",
      "signal_name": "error_budget_burn_pct",
      "signal_source": "pilot_drill",
      "signal_value": 2.08,
      "threshold_kind": "max",
      "threshold_value": 5.0,
      "capability_surface": "wasm.runtime",
      "owner_route": "oncall:pilot-sre",
      "replay_command": "asupersync lab replay examples/scenarios/smoke_happy_path.yaml --seed 4242",
      "trace_pointer": "artifacts/replay/pilot-pass-next-wasm.json",
      "remediation_pointer": "docs/wasm_pilot_observability_contract.md#ci-parity-contract"
    },
    {
      "scenario_id": "pilot-pass-next",
      "framework": "next",
      "profile_family": "native",
      "signal_name": "error_budget_burn_pct",
      "signal_source": "pilot_drill",
      "signal_value": 2.0,
      "threshold_kind": "max",
      "threshold_value": 5.0,
      "capability_surface": "native.runtime",
      "owner_route": "oncall:pilot-sre",
      "replay_command": "asupersync lab replay examples/scenarios/smoke_happy_path.yaml --seed 4242",
      "trace_pointer": "artifacts/replay/pilot-pass-next-native.json",
      "remediation_pointer": "docs/wasm_pilot_observability_contract.md#ci-parity-contract"
    }
  ]
}
EOF

cat > "${FAIL_INPUT}" <<'EOF'
{
  "seed": 4242,
  "parity_tolerance_pct_default": 3.0,
  "events": [
    {
      "scenario_id": "pilot-fail-next",
      "framework": "next",
      "profile_family": "wasm",
      "signal_name": "error_budget_burn_pct",
      "signal_source": "pilot_failure_injection",
      "signal_value": 11.0,
      "threshold_kind": "max",
      "threshold_value": 5.0,
      "capability_surface": "wasm.runtime",
      "owner_route": "oncall:pilot-sre",
      "replay_command": "asupersync lab replay examples/scenarios/smoke_happy_path.yaml --seed 4242 --window-start 1 --window-events 10",
      "trace_pointer": "artifacts/replay/pilot-fail-next-wasm.json",
      "remediation_pointer": "docs/wasm_pilot_observability_contract.md#alerting-and-owner-routing-rules"
    },
    {
      "scenario_id": "pilot-fail-next",
      "framework": "next",
      "profile_family": "native",
      "signal_name": "error_budget_burn_pct",
      "signal_source": "pilot_failure_injection",
      "signal_value": 4.0,
      "threshold_kind": "max",
      "threshold_value": 5.0,
      "capability_surface": "native.runtime",
      "owner_route": "oncall:pilot-sre",
      "replay_command": "asupersync lab replay examples/scenarios/smoke_happy_path.yaml --seed 4242 --window-start 1 --window-events 10",
      "trace_pointer": "artifacts/replay/pilot-fail-next-native.json",
      "remediation_pointer": "docs/wasm_pilot_observability_contract.md#alerting-and-owner-routing-rules"
    },
    {
      "scenario_id": "pilot-fail-react",
      "framework": "react",
      "profile_family": "wasm",
      "signal_name": "replay_success_rate_pct",
      "signal_source": "pilot_failure_injection",
      "signal_value": 90.0,
      "threshold_kind": "min",
      "threshold_value": 89.0,
      "parity_tolerance_pct": 3.0,
      "capability_surface": "wasm.replay",
      "owner_route": "oncall:wasm-runtime",
      "replay_command": "asupersync lab replay examples/scenarios/smoke_happy_path.yaml --seed 4242 --window-start 1 --window-events 10",
      "trace_pointer": "artifacts/replay/pilot-fail-react-wasm.json",
      "remediation_pointer": "docs/wasm_pilot_observability_contract.md#ci-parity-contract"
    },
    {
      "scenario_id": "pilot-fail-react",
      "framework": "react",
      "profile_family": "native",
      "signal_name": "replay_success_rate_pct",
      "signal_source": "pilot_failure_injection",
      "signal_value": 100.0,
      "threshold_kind": "min",
      "threshold_value": 89.0,
      "parity_tolerance_pct": 3.0,
      "capability_surface": "native.replay",
      "owner_route": "oncall:wasm-runtime",
      "replay_command": "asupersync lab replay examples/scenarios/smoke_happy_path.yaml --seed 4242 --window-start 1 --window-events 10",
      "trace_pointer": "artifacts/replay/pilot-fail-react-native.json",
      "remediation_pointer": "docs/wasm_pilot_observability_contract.md#ci-parity-contract"
    }
  ]
}
EOF

CHECKS_PASSED=0
CHECK_FAILURES=0
EXIT_CODE=0

if ASUPERSYNC_EVAL_TS="2026-03-03T00:00:00Z" \
    python3 "${PROJECT_ROOT}/scripts/evaluate_wasm_pilot_cohort.py" \
        --telemetry-input "${PASS_INPUT}" \
        --telemetry-output "${PASS_SUMMARY}" \
        --telemetry-log-output "${PASS_ALERTS}"; then
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
else
    CHECK_FAILURES=$((CHECK_FAILURES + 1))
    EXIT_CODE=1
fi

if ASUPERSYNC_EVAL_TS="2026-03-03T00:00:00Z" \
    python3 "${PROJECT_ROOT}/scripts/evaluate_wasm_pilot_cohort.py" \
        --telemetry-input "${FAIL_INPUT}" \
        --telemetry-output "${FAIL_SUMMARY}" \
        --telemetry-log-output "${FAIL_ALERTS}"; then
    CHECK_FAILURES=$((CHECK_FAILURES + 1))
    EXIT_CODE=1
else
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
fi

if jq -e '.schema_version == "asupersync-pilot-observability-v1" and .status == "pass" and .alerts_count == 0 and .ci_parity_ok == true' "${PASS_SUMMARY}" >/dev/null; then
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
else
    CHECK_FAILURES=$((CHECK_FAILURES + 1))
    EXIT_CODE=1
fi

if jq -e '.schema_version == "asupersync-pilot-observability-v1" and .status == "fail" and .alerts_count >= 1 and .ci_parity_ok == false' "${FAIL_SUMMARY}" >/dev/null; then
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
else
    CHECK_FAILURES=$((CHECK_FAILURES + 1))
    EXIT_CODE=1
fi

if jq -e '.alerts | length > 0 and all(.[]; has("owner_route") and has("replay_command") and has("trace_pointer") and has("remediation_pointer") and has("capability_surface") and has("signal_source"))' "${FAIL_SUMMARY}" >/dev/null; then
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
else
    CHECK_FAILURES=$((CHECK_FAILURES + 1))
    EXIT_CODE=1
fi

if jq -e 'select(.event == "pilot_slo_alert") | has("owner_route") and has("replay_command") and has("trace_pointer")' "${FAIL_ALERTS}" >/dev/null; then
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
else
    CHECK_FAILURES=$((CHECK_FAILURES + 1))
    EXIT_CODE=1
fi

jq -n \
    --arg schema "wasm-pilot-observability-e2e-v1" \
    --arg suite_id "${SUITE_ID}" \
    --arg scenario_id "${E2E_SCENARIO_ID}" \
    --arg started_at "${RUN_STARTED_TS}" \
    --arg finished_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg pass_summary "${PASS_SUMMARY}" \
    --arg fail_summary "${FAIL_SUMMARY}" \
    --arg pass_alerts "${PASS_ALERTS}" \
    --arg fail_alerts "${FAIL_ALERTS}" \
    --arg replay_command "ASUPERSYNC_EVAL_TS=2026-03-03T00:00:00Z python3 scripts/evaluate_wasm_pilot_cohort.py --telemetry-input ${FAIL_INPUT} --telemetry-output ${FAIL_SUMMARY} --telemetry-log-output ${FAIL_ALERTS}" \
    --argjson checks_passed "${CHECKS_PASSED}" \
    --argjson checks_failed "${CHECK_FAILURES}" \
    --argjson exit_code "${EXIT_CODE}" \
    '{
        schema_version: $schema,
        suite_id: $suite_id,
        scenario_id: $scenario_id,
        started_at_utc: $started_at,
        finished_at_utc: $finished_at,
        status: (if $exit_code == 0 then "pass" else "fail" end),
        checks_passed: $checks_passed,
        checks_failed: $checks_failed,
        exit_code: $exit_code,
        artifacts: {
          pass_summary: $pass_summary,
          fail_summary: $fail_summary,
          pass_alerts: $pass_alerts,
          fail_alerts: $fail_alerts
        },
        replay_command: $replay_command
    }' > "${E2E_SUMMARY}"

cat "${E2E_SUMMARY}"

if [[ ${EXIT_CODE} -ne 0 ]]; then
    echo "FAILED: pilot observability e2e checks failed (${CHECK_FAILURES} failure(s))" >&2
fi

exit ${EXIT_CODE}
