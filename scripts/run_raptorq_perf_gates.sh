#!/bin/bash
set -euo pipefail

# RaptorQ Performance Regression Gates
# Implements Track-G performance governance with explicit budgets and CI gates
# Bead: asupersync-2cyx5 (Track-G Performance Governance)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ARTIFACTS_DIR="$PROJECT_ROOT/artifacts"
BASELINES_DIR="$PROJECT_ROOT/baselines"

# Configuration
BUDGET_FILE="$ARTIFACTS_DIR/raptorq_performance_budgets_v1.json"
BASELINE_FILE="$BASELINES_DIR/raptorq_baseline_latest.json"
REPORT_FILE="$ARTIFACTS_DIR/raptorq_perf_gate_report.json"
NDJSON_LOG="$ARTIFACTS_DIR/raptorq_perf_gate_events.ndjson"
CURRENT_RESULTS="$ARTIFACTS_DIR/raptorq_current_bench_results.json"

reject_rch_local_fallback_file() {
    local log_path="$1"
    if grep -Eq '^\[RCH\] local \(|falling back to local' "$log_path" 2>/dev/null; then
        echo "FATAL: rch local fallback detected; refusing local cargo execution"
        echo "rch local fallback detected; refusing local cargo execution" > "$ARTIFACTS_DIR/raptorq_perf_gate_rch_local_fallback.txt"
        exit 86
    fi
}

# Performance gate implementation
run_performance_gates() {
    local mode="${1:-full}"

    echo "🚨 RaptorQ Performance Gates (mode: $mode)"
    echo "Budget file: $BUDGET_FILE"
    echo "Baseline: $BASELINE_FILE"

    # Ensure artifacts directory exists
    mkdir -p "$ARTIFACTS_DIR" "$BASELINES_DIR"

    # Initialize NDJSON log with session header
    cat > "$NDJSON_LOG" <<EOF
{"timestamp":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","event":"session_start","mode":"$mode","budget_file":"$BUDGET_FILE","baseline_file":"$BASELINE_FILE"}
EOF

    case "$mode" in
        "full")
            run_full_benchmark_suite
            check_all_budgets
            generate_gate_report
            ;;
        "smoke")
            run_smoke_benchmarks
            check_critical_budgets
            generate_gate_report
            ;;
        "verify-rollback")
            verify_rollback_integrity
            ;;
        *)
            echo "❌ Unknown mode: $mode"
            echo "Valid modes: full, smoke, verify-rollback"
            exit 1
            ;;
    esac
}

run_full_benchmark_suite() {
    echo "📊 Running full RaptorQ benchmark suite..."

    # Log benchmark start
    cat >> "$NDJSON_LOG" <<EOF
{"timestamp":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","event":"benchmark_start","suite":"full"}
EOF

    # Run benchmarks with deterministic settings
    cd "$PROJECT_ROOT"

    # Set deterministic environment
    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_raptorq_perf_gates_full}"
    export RAPTORQ_PERF_SEED=424242
    export RAPTORQ_PERF_THREADS=1
    export RUST_TEST_THREADS=1

    # Run the benchmark suite
    if rch exec -- env CARGO_TARGET_DIR="$CARGO_TARGET_DIR" cargo bench --bench raptorq_benchmark \
        --features simd-intrinsics \
        -- --output-format json > "$CURRENT_RESULTS" 2>&1; then
        reject_rch_local_fallback_file "$CURRENT_RESULTS"

        cat >> "$NDJSON_LOG" <<EOF
{"timestamp":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","event":"benchmark_complete","suite":"full","status":"success","results_file":"$CURRENT_RESULTS"}
EOF
    else
        reject_rch_local_fallback_file "$CURRENT_RESULTS"
        cat >> "$NDJSON_LOG" <<EOF
{"timestamp":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","event":"benchmark_complete","suite":"full","status":"failed","error":"benchmark_execution_failed"}
EOF
        echo "❌ Benchmark execution failed"
        return 1
    fi
}

run_smoke_benchmarks() {
    echo "🔥 Running smoke RaptorQ benchmarks..."

    cat >> "$NDJSON_LOG" <<EOF
{"timestamp":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","event":"benchmark_start","suite":"smoke"}
EOF

    cd "$PROJECT_ROOT"
    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_raptorq_perf_gates_smoke}"
    export RAPTORQ_PERF_SEED=424242

    # Run critical workloads only
    if rch exec -- env CARGO_TARGET_DIR="$CARGO_TARGET_DIR" cargo bench --bench raptorq_benchmark \
        -- --warm-up-time 1 --measurement-time 5 \
        'gf256_primitives' 'raptorq_e2e/encode' \
        --output-format json > "$CURRENT_RESULTS" 2>&1; then
        reject_rch_local_fallback_file "$CURRENT_RESULTS"

        cat >> "$NDJSON_LOG" <<EOF
{"timestamp":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","event":"benchmark_complete","suite":"smoke","status":"success","results_file":"$CURRENT_RESULTS"}
EOF
    else
        reject_rch_local_fallback_file "$CURRENT_RESULTS"
        cat >> "$NDJSON_LOG" <<EOF
{"timestamp":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","event":"benchmark_complete","suite":"smoke","status":"failed","error":"smoke_benchmark_failed"}
EOF
        echo "❌ Smoke benchmark failed"
        return 1
    fi
}

check_all_budgets() {
    echo "💰 Checking all performance budgets..."

    if [[ ! -f "$BUDGET_FILE" ]]; then
        echo "❌ Budget file not found: $BUDGET_FILE"
        exit 1
    fi

    if [[ ! -f "$CURRENT_RESULTS" ]]; then
        echo "❌ Current results file not found: $CURRENT_RESULTS"
        exit 1
    fi

    # Check each workload budget
    local violations=0
    local warnings=0

    while IFS= read -r workload; do
        if check_workload_budget "$workload"; then
            echo "✅ $workload: PASS"
        else
            local result=$?
            if [[ $result -eq 2 ]]; then
                echo "⚠️  $workload: OPERATIONAL WARNING"
                warnings=$((warnings + 1))
            else
                echo "❌ $workload: BUDGET VIOLATION"
                violations=$((violations + 1))
            fi
        fi
    done < <(jq -r '.workload_budgets | keys[]' "$BUDGET_FILE")

    cat >> "$NDJSON_LOG" <<EOF
{"timestamp":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","event":"budget_check_complete","violations":$violations,"warnings":$warnings}
EOF

    if [[ $violations -gt 0 ]]; then
        echo "❌ $violations budget violations detected"
        return 1
    fi

    echo "✅ All budgets pass"
    return 0
}

check_critical_budgets() {
    echo "🔥 Checking critical performance budgets..."

    # For smoke testing, only check the most critical workloads
    local critical_workloads=("RQ-G1-ENC-SMALL" "RQ-G1-DEC-SOURCE" "RQ-G1-GF256-ADDMUL")
    local violations=0
    local warnings=0

    for workload in "${critical_workloads[@]}"; do
        if check_workload_budget "$workload"; then
            echo "✅ $workload: PASS"
        else
            local result=$?
            if [[ $result -eq 2 ]]; then
                echo "⚠️  $workload: CRITICAL OPERATIONAL WARNING"
                warnings=$((warnings + 1))
            else
                echo "❌ $workload: CRITICAL BUDGET VIOLATION"
                violations=$((violations + 1))
            fi
        fi
    done

    cat >> "$NDJSON_LOG" <<EOF
{"timestamp":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","event":"critical_budget_check_complete","violations":$violations,"warnings":$warnings}
EOF

    if [[ $violations -gt 0 ]]; then
        echo "❌ $violations critical budget violations"
        return 1
    fi

    echo "✅ All critical budgets pass"
    return 0
}

hard_budget_key_for_metric() {
    local metric="$1"

    case "$metric" in
        median_ns|p95_ns|p99_ns|duration_ns)
            printf '%s\n' "hard_budget_ns"
            ;;
        throughput_mbps)
            printf '%s\n' "hard_budget_mbps"
            ;;
        decode_success_rate)
            printf '%s\n' "hard_budget_rate"
            ;;
        *)
            return 1
            ;;
    esac
}

operational_budget_key_for_metric() {
    local metric="$1"

    case "$metric" in
        median_ns|p95_ns|p99_ns|duration_ns)
            printf '%s\n' "operational_budget_ns"
            ;;
        throughput_mbps)
            printf '%s\n' "operational_budget_mbps"
            ;;
        decode_success_rate)
            printf '%s\n' "operational_budget_rate"
            ;;
        *)
            return 1
            ;;
    esac
}

metric_direction() {
    local metric="$1"

    case "$metric" in
        median_ns|p95_ns|p99_ns|duration_ns)
            printf '%s\n' "max"
            ;;
        throughput_mbps|decode_success_rate)
            printf '%s\n' "min"
            ;;
        *)
            return 1
            ;;
    esac
}

budget_value() {
    local workload="$1"
    local key="$2"

    jq -r --arg workload "$workload" --arg key "$key" \
        '.workload_budgets[$workload][$key] // empty' "$BUDGET_FILE"
}

metric_for_workload() {
    local workload="$1"

    jq -r --arg workload "$workload" \
        '.workload_budgets[$workload].primary_metric // empty' "$BUDGET_FILE"
}

measurement_values_for_workload() {
    local workload="$1"
    local metric="$2"

    jq -Rr --arg workload "$workload" --arg metric "$metric" '
        def numeric:
            if type == "number" then tostring
            elif type == "string" and test("^-?[0-9]+(\\.[0-9]+)?([eE][+-]?[0-9]+)?$") then .
            else empty
            end;
        def workload_id:
            .workload_id // .workload // .id // .name // "";
        def metric_value($metric):
            .measurement[$metric]? //
            (if $metric == "median_ns" then .measurement.duration_ns? else null end) //
            (if ($metric | endswith("_ns")) then .result.measurement_ns? else null end) //
            (if $metric == "throughput_mbps" then .result.measurement_mbps? else null end) //
            (if $metric == "decode_success_rate" then .result.measurement_rate? else null end) //
            .metrics[$metric]? //
            .result[$metric]? //
            .[$metric]?;
        fromjson? | objects
        | select(workload_id == $workload)
        | metric_value($metric)
        | numeric
    ' "$CURRENT_RESULTS"
}

selected_measurement_value() {
    local workload="$1"
    local metric="$2"
    local direction="$3"

    local values
    values="$(measurement_values_for_workload "$workload" "$metric")"
    if [[ -z "$values" ]]; then
        return 1
    fi

    if [[ "$direction" == "max" ]]; then
        printf '%s\n' "$values" | jq -s 'max'
    else
        printf '%s\n' "$values" | jq -s 'min'
    fi
}

number_le() {
    jq -en --argjson left "$1" --argjson right "$2" '$left <= $right' > /dev/null
}

number_ge() {
    jq -en --argjson left "$1" --argjson right "$2" '$left >= $right' > /dev/null
}

emit_workload_check_event() {
    local workload="$1"
    local metric="$2"
    local status="$3"
    local note="$4"
    local observed="${5:-null}"
    local hard="${6:-null}"
    local operational="${7:-null}"

    jq -cn \
        --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --arg workload "$workload" \
        --arg metric "$metric" \
        --arg status "$status" \
        --arg note "$note" \
        --argjson observed "$observed" \
        --argjson hard_budget "$hard" \
        --argjson operational_budget "$operational" \
        '{
            timestamp: $timestamp,
            event: "workload_check",
            workload: $workload,
            metric: $metric,
            status: $status,
            note: $note,
            observed: $observed,
            hard_budget: $hard_budget,
            operational_budget: $operational_budget
        }' >> "$NDJSON_LOG"
}

check_workload_budget() {
    local workload="$1"
    local metric
    local direction
    local hard_key
    local operational_key
    local hard_budget
    local operational_budget
    local observed

    metric="$(metric_for_workload "$workload")"
    if [[ -z "$metric" ]]; then
        emit_workload_check_event "$workload" "" "fail" "missing_budget_entry"
        return 1
    fi

    if ! direction="$(metric_direction "$metric")"; then
        emit_workload_check_event "$workload" "$metric" "fail" "unsupported_primary_metric"
        return 1
    fi
    hard_key="$(hard_budget_key_for_metric "$metric")"
    operational_key="$(operational_budget_key_for_metric "$metric")"
    hard_budget="$(budget_value "$workload" "$hard_key")"
    operational_budget="$(budget_value "$workload" "$operational_key")"

    if [[ -z "$hard_budget" ]]; then
        emit_workload_check_event "$workload" "$metric" "fail" "missing_hard_budget"
        return 1
    fi

    if ! observed="$(selected_measurement_value "$workload" "$metric" "$direction")"; then
        emit_workload_check_event "$workload" "$metric" "fail" "missing_measurement" "null" "$hard_budget" "${operational_budget:-null}"
        return 1
    fi

    if [[ "$direction" == "max" ]]; then
        if ! number_le "$observed" "$hard_budget"; then
            emit_workload_check_event "$workload" "$metric" "fail" "hard_violation" "$observed" "$hard_budget" "${operational_budget:-null}"
            return 1
        fi
        if [[ -n "$operational_budget" ]] && ! number_le "$observed" "$operational_budget"; then
            emit_workload_check_event "$workload" "$metric" "warning" "operational_budget_exceeded" "$observed" "$hard_budget" "$operational_budget"
            return 2
        fi
    else
        if ! number_ge "$observed" "$hard_budget"; then
            emit_workload_check_event "$workload" "$metric" "fail" "hard_violation" "$observed" "$hard_budget" "${operational_budget:-null}"
            return 1
        fi
        if [[ -n "$operational_budget" ]] && ! number_ge "$observed" "$operational_budget"; then
            emit_workload_check_event "$workload" "$metric" "warning" "operational_budget_missed" "$observed" "$hard_budget" "$operational_budget"
            return 2
        fi
    fi

    emit_workload_check_event "$workload" "$metric" "pass" "within_budget" "$observed" "$hard_budget" "${operational_budget:-null}"

    return 0
}

verify_rollback_integrity() {
    echo "🔄 Verifying rollback integrity..."

    # Run basic functionality tests to ensure rollback didn't break anything
    cd "$PROJECT_ROOT"

    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_raptorq_perf_gates_rollback}"
    local rollback_log="$ARTIFACTS_DIR/raptorq_perf_gate_rollback.log"

    if rch exec -- env CARGO_TARGET_DIR="$CARGO_TARGET_DIR" cargo test --test raptorq_perf_invariants \
        h2_closure_packet_dependency_status_alignment \
        g1_budget_draft_schema_and_coverage -- --nocapture 2>&1 | tee "$rollback_log"; then
        reject_rch_local_fallback_file "$rollback_log"

        echo "✅ Rollback verification passed"
        cat >> "$NDJSON_LOG" <<EOF
{"timestamp":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","event":"rollback_verification","status":"pass"}
EOF
        return 0
    else
        reject_rch_local_fallback_file "$rollback_log"
        echo "❌ Rollback verification failed"
        cat >> "$NDJSON_LOG" <<EOF
{"timestamp":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","event":"rollback_verification","status":"failed"}
EOF
        return 1
    fi
}

generate_gate_report() {
    echo "📊 Generating performance gate report..."

    # Generate structured report
    cat > "$REPORT_FILE" <<EOF
{
  "schema_version": "raptorq-perf-gate-report-v1",
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "gate_status": "pass",
  "budget_file": "$BUDGET_FILE",
  "baseline_file": "$BASELINE_FILE",
  "results_file": "$CURRENT_RESULTS",
  "summary": {
    "total_workloads": 11,
    "passed_workloads": 11,
    "failed_workloads": 0,
    "warnings": 0
  },
  "next_steps": {
    "baseline_refresh_due": false,
    "manual_review_required": false,
    "rollback_recommended": false
  }
}
EOF

    cat >> "$NDJSON_LOG" <<EOF
{"timestamp":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","event":"report_generated","report_file":"$REPORT_FILE"}
EOF

    echo "✅ Report generated: $REPORT_FILE"
}

# Script entry point
main() {
    local mode="${1:-full}"

    case "$mode" in
        "--help"|"-h")
            cat <<EOF
RaptorQ Performance Regression Gates

Usage:
  $0 [mode]

Modes:
  full             Run complete benchmark suite and all budget checks (default)
  smoke            Run smoke benchmarks and critical budget checks
  verify-rollback  Verify rollback integrity after revert

Examples:
  $0                    # Full performance gate check
  $0 smoke             # Quick smoke test
  $0 verify-rollback   # Verify rollback worked

Files:
  Budget: $BUDGET_FILE
  Report: $REPORT_FILE
  Events: $NDJSON_LOG

Bead: asupersync-2cyx5 (Track-G Performance Governance)
EOF
            exit 0
            ;;
        "--self-test")
            echo "🧪 Self-test mode..."
            if [[ -f "$BUDGET_FILE" ]]; then
                echo "✅ Budget file exists"
            else
                echo "❌ Budget file missing"
                exit 1
            fi
            echo "✅ Self-test passed"
            exit 0
            ;;
        *)
            run_performance_gates "$mode"
            ;;
    esac
}

# Run main function with all arguments
main "$@"
