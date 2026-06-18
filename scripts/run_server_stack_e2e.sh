#!/usr/bin/env bash
# Full-lifecycle server-stack E2E runner (asupersync-server-stack-hardening-eeexl1.8).
#
# Drives the production_service fixture (examples/production_service.rs — router +
# default trace middleware + in-memory SQLite handler + request-aware graceful
# drain) through the epic's chaos scenarios. The structured fixture log IS the
# test interface: assertions read its lines, proving log quality at the same time.
#
# All Cargo work is routed through RCH (remote build/run); this script never
# builds locally. The orchestrator's central batch-verify runs it on a healthy
# fleet — write/syntax-check/commit here, run there.
#
# Scenarios (per the bead): S1 baseline, S2 disconnect-storm, S3 deadline-cascade,
# S4 SIGTERM drain, S5 deterministic chaos. The current fixture is self-driving
# (boot -> self-probe /health,/users,/missing -> graceful drain -> exit), which
# fully exercises S1 (baseline traffic + assertions) and S4 (graceful drain). The
# attack scenarios (S2/S3/S5) require a long-running fixture "serve mode" plus
# fault toggles that examples/production_service.rs does not yet expose; they are
# recorded as SKIPPED with the exact missing capability — never silently dropped —
# so the suite lights them up as the fixture grows (stage-gated, per the AC).
#
# Usage:
#   scripts/run_server_stack_e2e.sh                 # run the suite
#   scripts/run_server_stack_e2e.sh --list-stages   # list scenarios
#   scripts/run_server_stack_e2e.sh --dry-run       # plan only, no fixture run
#
# Environment:
#   SERVER_STACK_RUN_ID         Run id under target/e2e-results/server_stack.
#   SERVER_STACK_OUTPUT_ROOT    Output root for summary.json + events.ndjson.
#   SERVER_STACK_CARGO_TARGET_DIR  Shared Cargo target dir for the RCH worker.
#   RCH_BIN                     RCH executable (default: rch).
#   RCH_REQUIRE_REMOTE          Remote-only RCH policy (default: 1).
#   TEST_SEED                   Deterministic seed (default: 0xDEADBEEF).
#   FIXTURE_TIMEOUT_SECS        Per-fixture-run wall cap (default: 120).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
RUN_ID="${SERVER_STACK_RUN_ID:-${TIMESTAMP}}"
OUTPUT_ROOT="${SERVER_STACK_OUTPUT_ROOT:-${PROJECT_ROOT}/target/e2e-results/server_stack}"
OUTPUT_DIR="${OUTPUT_ROOT}/${RUN_ID}"
EVENTS_NDJSON="${OUTPUT_DIR}/events.ndjson"
SUMMARY_JSON="${OUTPUT_DIR}/summary.json"
RCH_BIN="${RCH_BIN:-rch}"
RCH_REQUIRE_REMOTE="${RCH_REQUIRE_REMOTE:-1}"
SERVER_STACK_TARGET_DIR="${SERVER_STACK_CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_asupersync_server_stack}"
TEST_SEED="${TEST_SEED:-0xDEADBEEF}"
FIXTURE_TIMEOUT_SECS="${FIXTURE_TIMEOUT_SECS:-120}"
DRY_RUN=0

# scenario_id | description | state (run|skip) | skip_reason
SCENARIOS=(
    "S1-baseline|steady self-probe traffic through router+middleware+SQLite, statuses asserted from logs|run|"
    "S2-disconnect-storm|client-disconnect storm -> 499 + DB cancel + zero leaks asserted from logs|skip|needs fixture serve-mode (long-running listener) + an external connect/abort driver"
    "S3-deadline-cascade|request deadline cascade -> budget-expiry path observed|skip|needs fixture serve-mode + a per-request deadline injection toggle"
    "S4-sigterm-drain|graceful request-aware drain to quiescence, clean exit asserted from logs|run|"
    "S5-chaos|deterministic fault injection (resets/slow-DB/endpoint-death) two runs identical|skip|needs fixture serve-mode + lab/chaos fault toggles wired into the fixture"
)

usage() {
    cat <<'USAGE'
Usage:
  scripts/run_server_stack_e2e.sh
  scripts/run_server_stack_e2e.sh --list-stages
  scripts/run_server_stack_e2e.sh --dry-run

Drives examples/production_service.rs through the server-stack chaos scenarios.
S1/S4 run against the current self-driving fixture; S2/S3/S5 are skipped with the
exact missing fixture capability until a long-running serve-mode lands.
USAGE
}

case "${1:-}" in
    --help | -h)
        usage
        exit 0
        ;;
    --list-stages)
        for entry in "${SCENARIOS[@]}"; do
            IFS='|' read -r sid desc state reason <<<"$entry"
            printf '%s\t%s\t%s\n' "$sid" "$state" "$desc"
        done
        exit 0
        ;;
    --dry-run)
        DRY_RUN=1
        shift
        ;;
    "") ;;
    *)
        echo "Unknown argument: $1" >&2
        usage >&2
        exit 2
        ;;
esac

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

utc_now() {
    date -u +%Y-%m-%dT%H:%M:%SZ
}

command_string() {
    local rendered="" part
    for part in "$@"; do
        if [[ -n "$rendered" ]]; then
            rendered+=" "
        fi
        rendered+="$(printf '%q' "$part")"
    done
    printf '%s' "$rendered"
}

emit_event() {
    local scenario_id="$1" event="$2" status="$3" detail="$4"
    printf '{"schema_version":"server-stack-event-v1","run_id":"%s","scenario_id":"%s","event":"%s","status":"%s","detail":"%s","emitted_at":"%s"}\n' \
        "$(json_escape "$RUN_ID")" \
        "$(json_escape "$scenario_id")" \
        "$(json_escape "$event")" \
        "$(json_escape "$status")" \
        "$(json_escape "$detail")" \
        "$(json_escape "$(utc_now)")" \
        >>"$EVENTS_NDJSON"
}

# Run the self-driving fixture once via RCH; capture combined output to a log and
# return the fixture exit code. The fixture boots, self-probes, drains, exits.
FIXTURE_LOG=""
run_fixture() {
    FIXTURE_LOG="${OUTPUT_DIR}/fixture_lifecycle.log"
    local -a cmd=(
        env
        "RCH_REQUIRE_REMOTE=${RCH_REQUIRE_REMOTE}"
        "$RCH_BIN"
        exec
        --
        env
        "CARGO_TARGET_DIR=${SERVER_STACK_TARGET_DIR}"
        "CARGO_INCREMENTAL=0"
        "TEST_SEED=${TEST_SEED}"
        timeout "${FIXTURE_TIMEOUT_SECS}"
        cargo run --quiet --example production_service --features sqlite
    )
    local rendered
    rendered="$(command_string "${cmd[@]}")"
    echo "command: ${rendered}" >"$FIXTURE_LOG"
    emit_event "fixture" "run" "running" "$rendered"
    set +e
    "${cmd[@]}" >>"$FIXTURE_LOG" 2>&1
    local rc=$?
    set -e
    emit_event "fixture" "run" "exit:${rc}" "$FIXTURE_LOG"
    return "$rc"
}

# Assert a marker line is present in the fixture log; echo a pass/fail token.
assert_log() {
    local pattern="$1"
    if grep -qE "$pattern" "$FIXTURE_LOG" 2>/dev/null; then
        return 0
    fi
    return 1
}

# ── Scenario implementations ─────────────────────────────────────────────────
# Both runnable scenarios read the SAME self-driving fixture run: one boot
# exercises baseline traffic (S1) then graceful drain (S4).
declare -A SCENARIO_STATUS=()
declare -A SCENARIO_DETAIL=()

scenario_s1_baseline() {
    local fails=0 msg=""
    assert_log "production_service listening on http://" || { fails=1; msg+="no-listen;"; }
    assert_log "self-probe GET /health -> HTTP/1\\.1 200" || { fails=1; msg+="health!=200;"; }
    assert_log "self-probe GET /users -> HTTP/1\\.1 200" || { fails=1; msg+="users!=200(sqlite-path);"; }
    assert_log "self-probe GET /missing -> HTTP/1\\.1 404" || { fails=1; msg+="missing!=404;"; }
    if [[ "$fails" -eq 0 ]]; then
        SCENARIO_STATUS[S1-baseline]="passed"
        SCENARIO_DETAIL[S1-baseline]="router+trace-middleware+sqlite handler served /health,/users(200) and /missing(404) through the full path"
    else
        SCENARIO_STATUS[S1-baseline]="failed"
        SCENARIO_DETAIL[S1-baseline]="$msg"
    fi
}

scenario_s4_drain() {
    local fails=0 msg=""
    assert_log "production_service drained cleanly" || { fails=1; msg+="no-clean-drain;"; }
    [[ "${FIXTURE_RC:-1}" -eq 0 ]] || { fails=1; msg+="fixture-exit=${FIXTURE_RC};"; }
    if [[ "$fails" -eq 0 ]]; then
        SCENARIO_STATUS[S4-sigterm-drain]="passed"
        SCENARIO_DETAIL[S4-sigterm-drain]="request-aware graceful drain reached quiescence and the process exited 0 (drain-certificate phase assertions pending richer fixture drain logging)"
    else
        SCENARIO_STATUS[S4-sigterm-drain]="failed"
        SCENARIO_DETAIL[S4-sigterm-drain]="$msg"
    fi
}

# ── Drive ────────────────────────────────────────────────────────────────────
mkdir -p "$OUTPUT_DIR"
: >"$EVENTS_NDJSON"

if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[dry-run] server-stack e2e plan (run_id=${RUN_ID}):"
    for entry in "${SCENARIOS[@]}"; do
        IFS='|' read -r sid desc state reason <<<"$entry"
        if [[ "$state" == "skip" ]]; then
            printf '  %-22s SKIP  (%s)\n' "$sid" "$reason"
        else
            printf '  %-22s RUN   %s\n' "$sid" "$desc"
        fi
    done
    echo "[dry-run] fixture: cargo run --example production_service --features sqlite (via ${RCH_BIN})"
    exit 0
fi

overall_status="passed"
failed_scenario=""

# Record skipped scenarios up front (no silent omission).
for entry in "${SCENARIOS[@]}"; do
    IFS='|' read -r sid desc state reason <<<"$entry"
    if [[ "$state" == "skip" ]]; then
        SCENARIO_STATUS[$sid]="skipped"
        SCENARIO_DETAIL[$sid]="$reason"
        emit_event "$sid" "scenario" "skipped" "$reason"
    fi
done

# One self-driving fixture run powers S1 (baseline) and S4 (drain).
emit_event "S1-baseline" "scenario" "start" "shared lifecycle fixture run"
emit_event "S4-sigterm-drain" "scenario" "start" "shared lifecycle fixture run"
set +e
run_fixture
FIXTURE_RC=$?
set -e

scenario_s1_baseline
scenario_s4_drain

for sid in S1-baseline S4-sigterm-drain; do
    emit_event "$sid" "scenario" "${SCENARIO_STATUS[$sid]}" "${SCENARIO_DETAIL[$sid]}"
    if [[ "${SCENARIO_STATUS[$sid]}" == "failed" ]]; then
        overall_status="failed"
        [[ -n "$failed_scenario" ]] || failed_scenario="$sid"
    fi
done

ended_at="$(utc_now)"

# Build the scenarios JSON array for the summary.
scenarios_json=""
for entry in "${SCENARIOS[@]}"; do
    IFS='|' read -r sid desc state reason <<<"$entry"
    local_status="${SCENARIO_STATUS[$sid]:-unknown}"
    local_detail="${SCENARIO_DETAIL[$sid]:-}"
    [[ -n "$scenarios_json" ]] && scenarios_json+=","
    scenarios_json+=$(printf '{"scenario_id":"%s","status":"%s","detail":"%s"}' \
        "$(json_escape "$sid")" "$(json_escape "$local_status")" "$(json_escape "$local_detail")")
done

cat >"$SUMMARY_JSON" <<EOF_SUMMARY
{
  "schema_version": "e2e-suite-summary-v3",
  "suite_id": "server_stack_e2e",
  "scenario_id": "E2E-SUITE-SERVER-STACK",
  "seed": "${TEST_SEED}",
  "started_ts": "${GENERATED_AT}",
  "ended_ts": "${ended_at}",
  "status": "${overall_status}",
  "repro_command": "bash scripts/run_server_stack_e2e.sh",
  "artifact_path": "${OUTPUT_DIR}",
  "run_id": "${RUN_ID}",
  "target_dir": "${SERVER_STACK_TARGET_DIR}",
  "fixture": "examples/production_service.rs",
  "failed_scenario": "${failed_scenario}",
  "events_ndjson": "${EVENTS_NDJSON}",
  "scenarios": [${scenarios_json}]
}
EOF_SUMMARY

echo "Summary: ${SUMMARY_JSON}"
echo "Artifacts: ${OUTPUT_DIR}"
for entry in "${SCENARIOS[@]}"; do
    IFS='|' read -r sid desc state reason <<<"$entry"
    printf '  %-22s %s\n' "$sid" "${SCENARIO_STATUS[$sid]:-unknown}"
done

[[ "$overall_status" == "passed" ]] || exit 1
exit 0
