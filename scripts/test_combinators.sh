#!/bin/bash
# Combinator E2E Test Suite
#
# This script runs the full combinator test suite with structured logging,
# focusing on cancel-correctness and obligation safety verification.
#
# Usage:
#   ./scripts/test_combinators.sh
#   ./scripts/test_combinators.sh --executing --base FULL_COMMIT_SHA \
#     --overlay-path src/owned.rs [--overlay-path ...]
#   Select --no-overlay for a committed executing-combinator candidate.
#   Executing mode requires strict remote source selection and runs the full
#   native audit, both real engine unit suites and the public stream journeys.
#
# Environment Variables:
#   RUST_LOG - Log level (default: info)
#   RUST_BACKTRACE - Enable backtraces (default: 1)
#   RCH_BIN - Remote compilation helper executable (default: rch)
#   CARGO_BIN - Cargo executable routed through rch (default: cargo)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

run_executing_mode() {
    local base='' no_overlay=0 option path resolved
    local jobs="${EXECUTING_COMBINATOR_BUILD_JOBS:-8}"
    local cargo_home="${EXECUTING_COMBINATOR_CARGO_HOME:-${CARGO_HOME:-}}"
    local worker="${RCH_WORKER:-}" fingerprint=''
    local output="${EXECUTING_COMBINATOR_ARTIFACT_DIR:-${TMPDIR:-/tmp}/asupersync-executing-combinators-$(date -u +%Y%m%dT%H%M%S)-$$}"
    local target="${CARGO_TARGET_DIR_BASE:-${TMPDIR:-/tmp}/rch_target_executing_combinators}"
    local rch_bin
    local -a overlays=() source_args=() cargo_env=() command=()
    shift
    while (( $# )); do
        case "$1" in
            --base|--overlay-path)
                option="$1"
                (( $# >= 2 )) || { echo "Missing value for $1" >&2; return 86; }
                if [[ "$option" == --base ]]; then base="$2"; else overlays+=("$2"); fi
                shift 2 ;;
            --no-overlay) no_overlay=1; shift ;;
            *) echo "Unknown executing mode option: $1" >&2; return 86 ;;
        esac
    done
    [[ "$base" =~ ^[0-9a-f]{40}$ && "$jobs" =~ ^[1-9][0-9]*$ ]] || {
        echo "A full --base commit and positive EXECUTING_COMBINATOR_BUILD_JOBS are required" >&2; return 86;
    }
    if (( (no_overlay && ${#overlays[@]}) || (!no_overlay && !${#overlays[@]}) )); then
        echo "Select --no-overlay or explicit --overlay-path files" >&2; return 86
    fi
    cd "$PROJECT_ROOT"
    [[ "$(git branch --show-current)" == main && "$(git rev-parse --verify "$base^{commit}")" == "$base" ]] || return 86
    for option in python3 rg realpath timeout; do command -v "$option" >/dev/null || return 86; done
    for path in "${overlays[@]}"; do
        [[ "$path" != /* && "$path" != *$'\n'* && "$path" != *$'\r'* && "$path" != *$'\t'* && "/$path/" != */../* && "/$path/" != */./* ]] || return 86
        resolved=$(realpath --relative-to="$PROJECT_ROOT" -- "$path") || return 86
        [[ "$resolved" == "$path" && -f "$path" && ! -L "$path" ]] || return 86
    done
    rch_bin=$(command -v "${RCH_BIN:-rch}") || return 86
    [[ "$(basename "$rch_bin")" == rch && "$(realpath "$rch_bin")" != "$PROJECT_ROOT/scripts/rch_ci_fallback.sh" ]] || return 86
    [[ ! -e "$output" && ! -L "$output" ]] || { echo "Preserving existing evidence: $output" >&2; return 86; }
    mkdir -p "$(dirname "$output")"
    mkdir "$output"
    "$rch_bin" exec --help > "$output/rch-capabilities.txt"
    for option in --base --clean-overlay --overlay-path --no-overlay; do
        rg -q -- "$option" "$output/rch-capabilities.txt" || { echo "Installed RCH lacks $option" >&2; return 86; }
    done
    source_args=(--base "$base" --clean-overlay)
    if (( no_overlay )); then source_args+=(--no-overlay); else
        for path in "${overlays[@]}"; do source_args+=(--overlay-path "$path"); done
    fi
    [[ -z "$cargo_home" ]] || cargo_env+=("CARGO_HOME=$cargo_home")
    python3 - "$base" "${overlays[@]}" > "$output/source.json" <<'PY'
import hashlib, json, pathlib, sys
print(json.dumps(dict(base=sys.argv[1], features="tls,test-internals", overlays=[
    dict(path=p,sha256=hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest(),
         mode=pathlib.Path(p).stat().st_mode) for p in sys.argv[2:]
]), sort_keys=True))
PY
    local stage status receipt
    for stage in native units journeys; do
        case "$stage" in
            native) command=(test --test runtime_abort_vs_cancel_semantics_audit) ;;
            units) command=(test --lib) ;;
            journeys) command=(test --test e2e_stream_pipeline) ;;
        esac
        command+=(--jobs "$jobs" -p asupersync --locked --features 'tls,test-internals' --)
        if [[ "$stage" == units ]]; then command+=(combinator::map_reduce:: combinator::pipeline::); fi
        command+=(--nocapture --test-threads=1)
        printf 'Executing stage %s command:' "$stage"
        printf ' %q' "$rch_bin" exec "${source_args[@]}" -- env "${cargo_env[@]}" "CARGO_TARGET_DIR=$target/$stage" cargo "${command[@]}"
        printf '\n'
        python3 - "$output/source.json" <<'PY'
import hashlib, json, pathlib, sys
for row in json.loads(pathlib.Path(sys.argv[1]).read_text())["overlays"]:
    path=pathlib.Path(row["path"])
    assert not path.is_symlink() and path.stat().st_mode==row["mode"]
    assert hashlib.sha256(path.read_bytes()).hexdigest()==row["sha256"], row["path"]
PY
        status=0
        RCH_REQUIRE_REMOTE=1 RCH_DISABLE_TARGET_REUSE=1 RCH_VISIBILITY=verbose \
            RCH_WORKER="$worker" RCH_WORKERS='' NO_COLOR=1 \
            timeout "${EXECUTING_COMBINATOR_STAGE_TIMEOUT:-1800}" "$rch_bin" --no-color exec "${source_args[@]}" -- \
            env "${cargo_env[@]}" CARGO_TARGET_DIR="$target/$stage" CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
            RUSTFLAGS='-D warnings -C debuginfo=0' cargo "${command[@]}" \
            2>&1 | tee "$output/$stage.log" || status=$?
        printf '%s terminal_exit=%s\n' "$stage" "$status" | tee -a "$output/stages.txt"
        (( status == 0 )) || return "$status"
        receipt=$(python3 - "$output/$stage.log" "$output/source.json" "$stage" "$worker" "$fingerprint" <<'PY'
import hashlib, json, pathlib, re, sys
log_path,source_path,stage,worker,fingerprint=sys.argv[1:]
log=re.sub(r"\x1b\[[0-9;]*m", "", pathlib.Path(log_path).read_text())
source=json.loads(pathlib.Path(source_path).read_text())
for row in source["overlays"]:
    path=pathlib.Path(row["path"])
    assert not path.is_symlink() and path.stat().st_mode==row["mode"]
    assert hashlib.sha256(path.read_bytes()).hexdigest()==row["sha256"], row["path"]
selected=re.findall(r"Selected worker: ([A-Za-z0-9_.-]+) at ",log)
terminal=re.findall(r"^\[RCH\] remote ([A-Za-z0-9_.-]+) \([^\n]+\)$",log,re.M)
assert len(selected)==1 and terminal==selected and (not worker or selected==[worker])
assert not re.search(r"^\[RCH\] local \(|falling back to local|local fallback|executing locally",log,re.M)
receipts=re.findall(r"^\[RCH\] clean-overlay receipt: base=([0-9a-f]{40}) overlay-fingerprint=([0-9a-f]{64})$",log,re.M)
assert len(receipts)==1 and receipts[0][0]==source["base"]
assert not fingerprint or receipts[0][1]==fingerprint
counts=re.findall(r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;",log,re.M)
assert len(counts)==1 and int(counts[0][0])>0 and counts[0][1:4]==("0","0","0"), counts
assert stage=="units" or counts[0][4]=="0", counts
if stage=="units":
    for name in ("executing_map_held_first_input_keeps_completed_results_in_retained_window",
                 "executing_pipeline_heterogeneous_sink_ack_bounds_all_work"):
        # With one libtest thread and --nocapture, scenario output can appear
        # between this test-start prefix and its final `ok`. The aggregate
        # above requires every selected test to pass, with no ignored tests.
        assert re.search(r"^test [^\n]*::"+name+r" \.\.\.",log,re.M), name
if stage=="journeys":
    for name in ("public_executing_combinators_seeded_lab_delivery_and_backpressure",
                 "public_executing_combinators_native_delivery_and_backpressure"):
        assert re.search(r"^test [^\n]*::"+name+r" \.\.\.",log,re.M), name
    rows=[json.loads(line.split("ASUPERSYNC_EXECUTING_COMBINATORS ",1)[1]) for line in log.splitlines() if "ASUPERSYNC_EXECUTING_COMBINATORS " in line]
    assert len(rows)==5 and sorted(row["seed"] for row in rows if row["backend"]=="lab")==[0x3301,0x3302,0x3303]
    assert sorted(row["backend"] for row in rows if row["backend"]!="lab")==["native_current_thread","native_two_worker_sharded"]
    for row in rows:
        assert row["live_tasks"]==row["leaks"]==0 and len(row["journeys"])==3
        if row["backend"]=="lab": assert row["pending_obligations"]==0 and row["original_region_closed"]
        else: assert row["shutdown_completed"]
        mapped,positive,negative=row["journeys"]
        assert mapped["admitted"]==mapped["joined"]==mapped["reduced"]==24
        assert mapped["max_active"]<=2 and mapped["max_retained"]==mapped["held_prefix_pulled"]==3
        assert mapped["held_prefix_later_tasks_completed"]==2 and mapped["noncommutative_order_matches"]
        for result in (positive,negative):
            assert result["stages"]==2 and result["edge_capacity"]==1 and result["max_in_flight"]==result["held_sink_pulled"]==3
            assert result["admitted"]==result["acknowledged"]==result["expected_outputs"]==24 and result["held_sink_published"]==0
        assert positive["observed_outputs"]==24 and positive["delivery_refusal"] is None
        assert negative["observed_outputs"]==23 and negative["delivery_refusal"]=="delivery_mismatch"
print(selected[0],receipts[0][1])
PY
        ) || return 87
        read -r worker fingerprint <<< "$receipt"
    done
    printf 'Executed native audit, engine units and 15 public journeys; logs: %s\n' "$output"
}

if [[ "${1:-}" == --executing ]]; then
    run_executing_mode "$@"
    exit $?
fi

LOG_DIR="$PROJECT_ROOT/test_logs/combinators_$(date +%Y%m%d_%H%M%S)"
RUN_STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
RCH_BIN="${RCH_BIN:-rch}"
CARGO_BIN="${CARGO_BIN:-cargo}"
CARGO_TARGET_DIR_BASE="${CARGO_TARGET_DIR_BASE:-${TMPDIR:-/tmp}/rch_target_combinators_e2e}"
DRY_RUN=0

if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=1
    shift
fi

if [[ "$#" -ne 0 ]]; then
    echo "usage: $0 [--dry-run]" >&2
    exit 2
fi

mkdir -p "$LOG_DIR"

# Default log level
export RUST_LOG="${RUST_LOG:-info}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export TEST_SEED="${TEST_SEED:-0xDEADBEEF}"

format_command() {
    local rendered
    printf -v rendered "%q " "$@"
    printf '%s' "${rendered% }"
}

json_escape() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//$'\n'/\\n}"
    printf '%s' "${value}"
}

run_cargo() {
    local lane="$1"
    shift
    local target_dir="${CARGO_TARGET_DIR_BASE}/${lane}"
    local command=(
        "${RCH_BIN}"
        exec
        --
        env
        "CARGO_TARGET_DIR=${target_dir}"
        "RUST_LOG=${RUST_LOG}"
        "RUST_BACKTRACE=${RUST_BACKTRACE}"
        "TEST_SEED=${TEST_SEED}"
        "${CARGO_BIN}"
        "$@"
    )

    if [[ "${DRY_RUN}" -eq 1 ]]; then
        format_command "${command[@]}"
        printf '\n'
        return 0
    fi

    "${command[@]}"
}

echo "=== Combinator E2E Test Suite ==="
echo "Log directory: $LOG_DIR"
echo "Start time: $(date -Iseconds)"
echo "RUST_LOG: $RUST_LOG"
echo "Runner: ${RCH_BIN} exec"
echo "Target base: ${CARGO_TARGET_DIR_BASE}"
if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "Mode: dry-run"
fi
echo ""

# Track test results
UNIT_EXIT=0
CANCEL_EXIT=0
ASYNC_EXIT=0
OVERALL_EXIT=0
LOCAL_FALLBACKS=0

# Run combinator unit tests
echo "[1/3] Running combinator unit tests..."
if run_cargo unit test -p asupersync --test e2e_combinator e2e::combinator::unit -- --nocapture 2>&1 | tee "$LOG_DIR/unit_tests.log"; then
    UNIT_EXIT=0
    echo "    -> PASS"
else
    UNIT_EXIT=1
    echo "    -> FAIL"
fi

# Run cancel-correctness tests (CRITICAL)
echo ""
echo "[2/3] Running cancel-correctness tests (CRITICAL)..."
if run_cargo cancel test -p asupersync --test e2e_combinator e2e::combinator::cancel_correctness -- --nocapture 2>&1 | tee "$LOG_DIR/cancel_tests.log"; then
    CANCEL_EXIT=0
    echo "    -> PASS"
else
    CANCEL_EXIT=1
    echo "    -> FAIL"
fi

# Run async loser drain tests
echo ""
echo "[3/3] Running async loser drain tests..."
if run_cargo async test -p asupersync --test e2e_combinator async_loser_drain -- --nocapture 2>&1 | tee "$LOG_DIR/async_tests.log"; then
    ASYNC_EXIT=0
    echo "    -> PASS"
else
    ASYNC_EXIT=1
    echo "    -> FAIL"
fi

# Check for critical oracle violations
echo ""
echo "[Analysis] Checking for oracle violations..."
if grep -qE "(LoserDrainViolation|ObligationLeakViolation)" "$LOG_DIR"/*.log 2>/dev/null; then
    echo "    -> WARNING: Oracle violations detected!"
    grep -hE "(LoserDrainViolation|ObligationLeakViolation)" "$LOG_DIR"/*.log | head -10
    OVERALL_EXIT=1
else
    echo "    -> No oracle violations"
fi

# Check for panics
if grep -qE "(panicked|FAILED)" "$LOG_DIR"/*.log 2>/dev/null; then
    echo ""
    echo "[Analysis] Test failures detected:"
    grep -hE "(panicked|FAILED)" "$LOG_DIR"/*.log | head -20
fi

# Reject proof transcripts that came from a local rch fallback.
echo ""
echo "[Analysis] Checking for rch local fallback..."
if grep -qE '^\[RCH\] local \(|local fallback|fallback to local|executing locally' "$LOG_DIR"/*.log 2>/dev/null; then
    echo "    -> FATAL: rch local fallback detected; refusing local cargo execution"
    grep -hE '^\[RCH\] local \(|local fallback|fallback to local|executing locally' "$LOG_DIR"/*.log | head -10
    LOCAL_FALLBACKS=1
    OVERALL_EXIT=86
else
    echo "    -> No local fallback markers"
fi

# Generate summary
echo ""
echo "=== Test Summary ==="
PASSED_TESTS=$({ grep -h -c "^test .* ok$" "$LOG_DIR"/*.log 2>/dev/null || true; } | awk '{s+=$1} END {print s+0}')
FAILED_TESTS=$({ grep -h -c "^test .* FAILED$" "$LOG_DIR"/*.log 2>/dev/null || true; } | awk '{s+=$1} END {print s+0}')
LOSER_DRAIN_VIOLATIONS=$({ grep -h -c "LoserDrainViolation" "$LOG_DIR"/*.log 2>/dev/null || true; } | awk '{s+=$1} END {print s+0}')
OBLIGATION_LEAK_VIOLATIONS=$({ grep -h -c "ObligationLeakViolation" "$LOG_DIR"/*.log 2>/dev/null || true; } | awk '{s+=$1} END {print s+0}')
SUITE_ID="combinators_e2e"
SCENARIO_ID="E2E-SUITE-COMBINATORS"
SUMMARY_FILE="$LOG_DIR/summary.json"
REPRO_COMMAND="TEST_SEED=${TEST_SEED} RUST_LOG=${RUST_LOG} RCH_BIN=${RCH_BIN} CARGO_TARGET_DIR_BASE=${CARGO_TARGET_DIR_BASE} bash ${SCRIPT_DIR}/$(basename "$0")"
RUN_ENDED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SUITE_STATUS="failed"
if [ $UNIT_EXIT -eq 0 ] && [ $CANCEL_EXIT -eq 0 ] && [ $ASYNC_EXIT -eq 0 ] && [ $OVERALL_EXIT -eq 0 ]; then
    SUITE_STATUS="passed"
fi
if [[ "${DRY_RUN}" -eq 1 ]]; then
    SUITE_STATUS="planned"
fi
DRY_RUN_JSON=false
if [[ "${DRY_RUN}" -eq 1 ]]; then
    DRY_RUN_JSON=true
fi
RCH_ROUTED_JSON=true
if [[ "${LOCAL_FALLBACKS}" -ne 0 ]]; then
    RCH_ROUTED_JSON=false
fi

cat > "$SUMMARY_FILE" << ENDJSON
{
  "schema_version": "e2e-suite-summary-v3",
  "suite_id": "${SUITE_ID}",
  "scenario_id": "${SCENARIO_ID}",
  "seed": "${TEST_SEED}",
  "started_ts": "${RUN_STARTED_TS}",
  "ended_ts": "${RUN_ENDED_TS}",
  "status": "${SUITE_STATUS}",
  "dry_run": ${DRY_RUN_JSON},
  "runner": "rch exec",
  "all_rch_routed": ${RCH_ROUTED_JSON},
  "rch_local_fallbacks": ${LOCAL_FALLBACKS},
  "repro_command": "$(json_escape "${REPRO_COMMAND}")",
  "artifact_path": "$(json_escape "${SUMMARY_FILE}")",
  "suite": "${SUITE_ID}",
  "tests_passed": ${PASSED_TESTS},
  "tests_failed": ${FAILED_TESTS},
  "unit_exit": ${UNIT_EXIT},
  "cancel_exit": ${CANCEL_EXIT},
  "async_exit": ${ASYNC_EXIT},
  "oracle_exit": ${OVERALL_EXIT},
  "loser_drain_violations": ${LOSER_DRAIN_VIOLATIONS},
  "obligation_leak_violations": ${OBLIGATION_LEAK_VIOLATIONS},
  "log_dir": "$(json_escape "${LOG_DIR}")"
}
ENDJSON

echo "Summary: $SUMMARY_FILE"

echo ""
echo "End time: $(date -Iseconds)"
echo "Logs saved to: $LOG_DIR"
echo "=== Test Complete ==="

# Exit with overall status
if [ $UNIT_EXIT -ne 0 ] || [ $CANCEL_EXIT -ne 0 ] || [ $ASYNC_EXIT -ne 0 ] || [ $OVERALL_EXIT -ne 0 ]; then
    exit 1
fi
exit 0
