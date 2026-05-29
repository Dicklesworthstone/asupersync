#!/bin/bash
# ATP Enhanced Release Gates - Complete ATP Release Qualification
# Integrates with existing release gates and adds ATP-specific validation

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
GATE_LOG="${PROJECT_ROOT}/artifacts/atp_release_gates_$(date +%Y%m%d_%H%M%S).log"
SESSION_ID="atp_gate_$(date +%Y%m%d_%H%M%S)_$$"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Gate tracking
CRITICAL_GATES_PASSED=0
CRITICAL_GATES_FAILED=0
HIGH_GATES_PASSED=0
HIGH_GATES_FAILED=0
MEDIUM_GATES_PASSED=0
MEDIUM_GATES_FAILED=0
GATES_SKIPPED=0

log_gate() {
    local status="$1"
    local priority="$2"
    local gate="$3"
    local message="$4"

    local timestamp=$(date -u '+%Y-%m-%d %H:%M:%S UTC')

    case "$status" in
        PASS)
            echo -e "${GREEN}[PASS]${NC} [$priority] $gate: $message" | tee -a "$GATE_LOG"
            case "$priority" in
                CRITICAL) ((CRITICAL_GATES_PASSED++)) ;;
                HIGH) ((HIGH_GATES_PASSED++)) ;;
                MEDIUM) ((MEDIUM_GATES_PASSED++)) ;;
            esac
            ;;
        FAIL)
            echo -e "${RED}[FAIL]${NC} [$priority] $gate: $message" | tee -a "$GATE_LOG"
            case "$priority" in
                CRITICAL) ((CRITICAL_GATES_FAILED++)) ;;
                HIGH) ((HIGH_GATES_FAILED++)) ;;
                MEDIUM) ((MEDIUM_GATES_FAILED++)) ;;
            esac
            ;;
        SKIP)
            echo -e "${YELLOW}[SKIP]${NC} [$priority] $gate: $message" | tee -a "$GATE_LOG"
            ((GATES_SKIPPED++))
            ;;
        INFO)
            echo -e "${BLUE}[INFO]${NC} $gate: $message" | tee -a "$GATE_LOG"
            ;;
    esac

    # Structured log entry
    printf '{"timestamp":"%s","status":"%s","priority":"%s","gate":"%s","message":"%s","session_id":"%s"}\n' \
        "$timestamp" "$status" "$priority" "$gate" "$message" "$SESSION_ID" >> "$GATE_LOG.jsonl"
}

print_banner() {
    echo -e "${CYAN}"
    echo "=========================================="
    echo "   ATP ENHANCED RELEASE GATES v2.0"
    echo "=========================================="
    echo -e "${NC}"
    echo "Session ID: $SESSION_ID"
    echo "Log file: $GATE_LOG"
    echo "Time: $(date)"
    echo ""
}

usage() {
    cat << 'USAGE'
Usage: scripts/atp_enhanced_release_gates.sh [OPTIONS]

Enhanced ATP release gate validation with comprehensive proof lane coverage.

Options:
  --critical-only       Run only CRITICAL priority gates (fast commit gates)
  --high-priority       Run CRITICAL + HIGH priority gates (daily gates)
  --full               Run all gates (release candidate validation)
  --proof-lanes-only   Execute proof lane matrix only
  --dependency-only    Run dependency audit gates only
  --performance-only   Run performance validation only
  --documentation-only Run documentation sync validation only
  --dry-run           Show planned operations without execution
  --parallel          Run independent gates in parallel (faster)
  --timeout <seconds> Set global timeout for gate execution
  --verbose           Enable detailed gate execution logging
  --help              Show this help

Gate Priority Levels:
  CRITICAL: Must pass for any commit (P1-P3, S1, S3)
  HIGH:     Must pass for daily builds (All core + integration)
  MEDIUM:   Must pass for release candidates (Performance, stress)

Examples:
  # Fast commit validation (< 10 min)
  scripts/atp_enhanced_release_gates.sh --critical-only

  # Daily build validation (< 30 min)
  scripts/atp_enhanced_release_gates.sh --high-priority

  # Full release candidate validation (< 60 min)
  scripts/atp_enhanced_release_gates.sh --full

  # Check specific areas
  scripts/atp_enhanced_release_gates.sh --proof-lanes-only
  scripts/atp_enhanced_release_gates.sh --dependency-only
USAGE
}

# Parse command line arguments
CRITICAL_ONLY=false
HIGH_PRIORITY=false
FULL_VALIDATION=false
PROOF_LANES_ONLY=false
DEPENDENCY_ONLY=false
PERFORMANCE_ONLY=false
DOCUMENTATION_ONLY=false
DRY_RUN=false
PARALLEL_EXECUTION=false
TIMEOUT_SECONDS=3600
VERBOSE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --critical-only)
            CRITICAL_ONLY=true
            shift
            ;;
        --high-priority)
            HIGH_PRIORITY=true
            shift
            ;;
        --full)
            FULL_VALIDATION=true
            shift
            ;;
        --proof-lanes-only)
            PROOF_LANES_ONLY=true
            shift
            ;;
        --dependency-only)
            DEPENDENCY_ONLY=true
            shift
            ;;
        --performance-only)
            PERFORMANCE_ONLY=true
            shift
            ;;
        --documentation-only)
            DOCUMENTATION_ONLY=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --parallel)
            PARALLEL_EXECUTION=true
            shift
            ;;
        --timeout)
            TIMEOUT_SECONDS="$2"
            shift 2
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

# Validate mutually exclusive options
exclusive_count=0
[[ "$CRITICAL_ONLY" == true ]] && ((exclusive_count++))
[[ "$HIGH_PRIORITY" == true ]] && ((exclusive_count++))
[[ "$FULL_VALIDATION" == true ]] && ((exclusive_count++))
[[ "$PROOF_LANES_ONLY" == true ]] && ((exclusive_count++))
[[ "$DEPENDENCY_ONLY" == true ]] && ((exclusive_count++))
[[ "$PERFORMANCE_ONLY" == true ]] && ((exclusive_count++))
[[ "$DOCUMENTATION_ONLY" == true ]] && ((exclusive_count++))

if [[ $exclusive_count -eq 0 ]]; then
    # Default to high-priority for daily builds
    HIGH_PRIORITY=true
elif [[ $exclusive_count -gt 1 ]]; then
    echo "Error: Only one mode can be specified" >&2
    exit 2
fi

# Utility functions
execute_with_timeout() {
    local timeout_secs="$1"
    local description="$2"
    shift 2
    local command=("$@")

    if [[ "$DRY_RUN" == true ]]; then
        echo "DRY RUN: Would execute: ${command[*]}"
        return 0
    fi

    if [[ "$VERBOSE" == true ]]; then
        log_gate "INFO" "" "execute" "Running: ${command[*]}"
    fi

    timeout "${timeout_secs}" "${command[@]}"
}

run_proof_lane() {
    local lane_id="$1"
    local priority="$2"
    local description="$3"
    local command="$4"
    local timeout_secs="${5:-300}"

    log_gate "INFO" "" "$lane_id" "Starting $description"

    local start_time=$(date +%s)
    if execute_with_timeout "$timeout_secs" "$description" bash -c "$command"; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        log_gate "PASS" "$priority" "$lane_id" "$description completed in ${duration}s"
        return 0
    else
        local exit_code=$?
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        log_gate "FAIL" "$priority" "$lane_id" "$description failed in ${duration}s (exit code: $exit_code)"
        return $exit_code
    fi
}

# Critical Gates (Must pass for any commit)
run_critical_gates() {
    log_gate "INFO" "" "critical_gates" "Starting CRITICAL priority gates"

    # P1: Native QUIC Conformance (no external deps)
    run_proof_lane "P1" "CRITICAL" "Native QUIC Conformance" \
        'rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_p1" cargo test --lib net::quic_native --features test-internals' \
        600

    # P2: ATP Protocol Codec
    run_proof_lane "P2" "CRITICAL" "ATP Protocol Codec" \
        'rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_p2" cargo test --lib cli::atp_command_tree' \
        300

    # P3: Manifest Integrity
    run_proof_lane "P3" "CRITICAL" "Manifest Integrity" \
        'rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_p3" cargo test --lib atp::manifest' \
        300

    # S1: Dependency Audit (Zero External Dependencies)
    run_proof_lane "S1" "CRITICAL" "Dependency Audit" \
        'scripts/dependency_audit.sh --atp-core-only' \
        120

    # S3: Capability Security
    run_proof_lane "S3" "CRITICAL" "Capability Security" \
        'rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_s3" cargo test --lib cx::capability --features test-internals' \
        300

    log_gate "INFO" "" "critical_gates" "CRITICAL gates completed"
}

# High Priority Gates (Daily builds)
run_high_priority_gates() {
    log_gate "INFO" "" "high_gates" "Starting HIGH priority gates"

    # P4: Crash Safety
    run_proof_lane "P4" "HIGH" "Crash Safety" \
        'rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_p4" cargo test --lib atp::journal --features test-internals' \
        600

    # P5: Resume Capability
    run_proof_lane "P5" "HIGH" "Resume Capability" \
        'rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_p5" cargo test --lib atp::transfer --features test-internals' \
        600

    # P6: Dogfooding Validation
    run_proof_lane "P6" "HIGH" "Dogfooding Validation" \
        'scripts/atp_dogfood_coordinator.sh full --dry-run && cargo test --test atp_dogfood_integration' \
        900

    # P7: Relay Protocol
    run_proof_lane "P7" "HIGH" "Relay Protocol" \
        'rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_p7" cargo test --lib atp::relay --features test-internals' \
        600

    # P8: RaptorQ Repair
    run_proof_lane "P8" "HIGH" "RaptorQ Repair" \
        'rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_p8" cargo test --lib raptorq --features test-internals' \
        600

    # A1: CLI Command Completeness
    run_proof_lane "A1" "HIGH" "CLI Command Completeness" \
        'rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_a1" cargo test --lib cli::atp_command_tree' \
        300

    # A2: Workflow Coordinator
    run_proof_lane "A2" "HIGH" "Workflow Coordinator" \
        'rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_a2" cargo test --lib cli::atp_workflows' \
        300

    # S2: Cryptographic Verification
    run_proof_lane "S2" "HIGH" "Cryptographic Verification" \
        'rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_s2" cargo test --lib atp::crypto --features test-internals' \
        300

    log_gate "INFO" "" "high_gates" "HIGH priority gates completed"
}

# Medium Priority Gates (Release candidates)
run_medium_priority_gates() {
    log_gate "INFO" "" "medium_gates" "Starting MEDIUM priority gates"

    # P9: Swarm Coordination
    run_proof_lane "P9" "MEDIUM" "Swarm Coordination" \
        'rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_p9" cargo test --lib atp::swarm --features test-internals' \
        900

    # P10: Cache Management
    run_proof_lane "P10" "MEDIUM" "Cache Management" \
        'rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_p10" cargo test --lib atp::cache --features test-internals' \
        600

    # A3: ATPD Daemon
    run_proof_lane "A3" "MEDIUM" "ATPD Daemon Service" \
        'scripts/run_atp_atpd_appspec_e2e.sh' \
        900

    # A4: Cross-Platform Compatibility
    run_proof_lane "A4" "MEDIUM" "Cross-Platform Compatibility" \
        'scripts/cross_platform_test.sh --atp-focus' \
        1200

    # R1: Performance Benchmarks
    run_proof_lane "R1" "MEDIUM" "Performance Benchmarks" \
        'rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_r1" cargo bench --features criterion-benches --bench atp_j5_workflows_bench' \
        1800

    # R2: Stress Testing
    run_proof_lane "R2" "MEDIUM" "Stress Testing" \
        'scripts/atp_stress_test.sh --resource-limits' \
        1200

    # R3: Deterministic Replay
    run_proof_lane "R3" "MEDIUM" "Deterministic Replay" \
        'rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_r3" cargo test --test atp_deterministic_replay' \
        600

    log_gate "INFO" "" "medium_gates" "MEDIUM priority gates completed"
}

# Documentation Gates
run_documentation_gates() {
    log_gate "INFO" "" "doc_gates" "Starting documentation gates"

    # D1: Architecture Documentation Sync
    run_proof_lane "D1" "HIGH" "Architecture Documentation Sync" \
        'scripts/validate_dod.sh --check-architecture-sync' \
        300

    # D2: Proof Lane Coverage
    run_proof_lane "D2" "HIGH" "Proof Lane Coverage" \
        'scripts/validate_proof_lane_coverage.sh' \
        300

    # D3: DOD Checklist Compliance
    run_proof_lane "D3" "HIGH" "DOD Checklist Compliance" \
        'scripts/validate_dod.sh --atp-components' \
        300

    log_gate "INFO" "" "doc_gates" "Documentation gates completed"
}

# Generate final report
generate_final_report() {
    echo ""
    echo -e "${CYAN}=========================================="
    echo "       ATP RELEASE GATES SUMMARY"
    echo "==========================================${NC}"
    echo "Session: $SESSION_ID"
    echo "Execution: $(date)"
    echo ""

    echo "Gate Results:"
    echo "  CRITICAL: $CRITICAL_GATES_PASSED passed, $CRITICAL_GATES_FAILED failed"
    echo "  HIGH:     $HIGH_GATES_PASSED passed, $HIGH_GATES_FAILED failed"
    echo "  MEDIUM:   $MEDIUM_GATES_PASSED passed, $MEDIUM_GATES_FAILED failed"
    echo "  SKIPPED:  $GATES_SKIPPED"
    echo ""

    # Generate structured report
    local report_file="${PROJECT_ROOT}/artifacts/atp_release_gate_report_${SESSION_ID}.json"
    cat > "$report_file" << EOF
{
  "session_id": "$SESSION_ID",
  "timestamp": "$(date -u --iso-8601=seconds)",
  "execution_mode": "$(get_execution_mode)",
  "results": {
    "critical": {
      "passed": $CRITICAL_GATES_PASSED,
      "failed": $CRITICAL_GATES_FAILED
    },
    "high": {
      "passed": $HIGH_GATES_PASSED,
      "failed": $HIGH_GATES_FAILED
    },
    "medium": {
      "passed": $MEDIUM_GATES_PASSED,
      "failed": $MEDIUM_GATES_FAILED
    },
    "skipped": $GATES_SKIPPED
  },
  "artifacts": {
    "main_log": "$GATE_LOG",
    "structured_log": "$GATE_LOG.jsonl"
  }
}
EOF

    echo "Report generated: $report_file"
    echo ""

    # Determine overall result
    local overall_result="PASS"
    local exit_code=0

    if [[ $CRITICAL_GATES_FAILED -gt 0 ]]; then
        overall_result="FAIL"
        exit_code=1
        echo -e "${RED}❌ CRITICAL gates failed - Release BLOCKED${NC}"
    elif [[ "$FULL_VALIDATION" == true && ($HIGH_GATES_FAILED -gt 0 || $MEDIUM_GATES_FAILED -gt 0) ]]; then
        overall_result="FAIL"
        exit_code=1
        echo -e "${RED}❌ Release candidate validation failed${NC}"
    elif [[ "$HIGH_PRIORITY" == true && $HIGH_GATES_FAILED -gt 0 ]]; then
        overall_result="FAIL"
        exit_code=1
        echo -e "${RED}❌ Daily build validation failed${NC}"
    else
        echo -e "${GREEN}✅ All required gates passed - Release APPROVED${NC}"
    fi

    echo "Overall result: $overall_result"

    # Create bead for failures if any occurred
    if [[ $exit_code -ne 0 && "$DRY_RUN" == false ]]; then
        create_failure_bead
    fi

    exit $exit_code
}

get_execution_mode() {
    if [[ "$CRITICAL_ONLY" == true ]]; then
        echo "critical-only"
    elif [[ "$HIGH_PRIORITY" == true ]]; then
        echo "high-priority"
    elif [[ "$FULL_VALIDATION" == true ]]; then
        echo "full"
    elif [[ "$PROOF_LANES_ONLY" == true ]]; then
        echo "proof-lanes-only"
    elif [[ "$DEPENDENCY_ONLY" == true ]]; then
        echo "dependency-only"
    elif [[ "$PERFORMANCE_ONLY" == true ]]; then
        echo "performance-only"
    elif [[ "$DOCUMENTATION_ONLY" == true ]]; then
        echo "documentation-only"
    else
        echo "unknown"
    fi
}

create_failure_bead() {
    local total_failures=$((CRITICAL_GATES_FAILED + HIGH_GATES_FAILED + MEDIUM_GATES_FAILED))

    if command -v br >/dev/null 2>&1; then
        local bead_id
        if bead_id=$(br create \
            --title "ATP Release Gate Failures: $total_failures gates failed" \
            --type bug \
            --priority 1 \
            --labels "atp-dml,release-gates,ci" \
            --assignee ubuntu 2>/dev/null); then

            cat > "/tmp/atp_gate_failure_${SESSION_ID}.md" <<EOF
# ATP Release Gate Failure Report

## Failure Summary
- **Session ID**: $SESSION_ID
- **Execution Mode**: $(get_execution_mode)
- **Total Failures**: $total_failures
- **Critical Failures**: $CRITICAL_GATES_FAILED
- **High Priority Failures**: $HIGH_GATES_FAILED
- **Medium Priority Failures**: $MEDIUM_GATES_FAILED

## Investigation Artifacts
- **Main Log**: $GATE_LOG
- **Structured Log**: $GATE_LOG.jsonl
- **Report File**: artifacts/atp_release_gate_report_${SESSION_ID}.json

## Failed Gates Analysis
\`\`\`bash
# Extract failed gates from structured log
jq -r 'select(.status == "FAIL")' $GATE_LOG.jsonl

# Review specific gate failures
grep "\\[FAIL\\]" $GATE_LOG
\`\`\`

## Next Steps
1. Review gate failure logs for specific error details
2. Run individual failing gates for detailed debugging
3. Fix underlying issues before retry
4. Update proof lanes if legitimate implementation changes

## Rerun Commands
\`\`\`bash
# Rerun specific priority level
scripts/atp_enhanced_release_gates.sh --$(get_execution_mode)

# Debug individual gates that failed
# (Extract specific commands from structured log)
\`\`\`
EOF

            br update "$bead_id" --description "$(cat /tmp/atp_gate_failure_${SESSION_ID}.md)"
            rm -f "/tmp/atp_gate_failure_${SESSION_ID}.md"

            log_gate "INFO" "" "bead" "Created failure bead: $bead_id"
        fi
    fi
}

# Main execution
print_banner

if [[ "$DRY_RUN" == true ]]; then
    log_gate "INFO" "" "main" "DRY RUN MODE - showing planned execution"
    echo "Mode: $(get_execution_mode)"
    echo "Timeout: ${TIMEOUT_SECONDS}s"
    echo "Parallel: $PARALLEL_EXECUTION"
fi

# Execute based on selected mode
if [[ "$CRITICAL_ONLY" == true ]]; then
    run_critical_gates
elif [[ "$HIGH_PRIORITY" == true ]]; then
    run_critical_gates
    run_high_priority_gates
    run_documentation_gates
elif [[ "$FULL_VALIDATION" == true ]]; then
    run_critical_gates
    run_high_priority_gates
    run_medium_priority_gates
    run_documentation_gates
elif [[ "$PROOF_LANES_ONLY" == true ]]; then
    run_critical_gates
    run_high_priority_gates
    run_medium_priority_gates
elif [[ "$DEPENDENCY_ONLY" == true ]]; then
    run_proof_lane "S1" "CRITICAL" "Dependency Audit" \
        'scripts/dependency_audit.sh --atp-core-only'
elif [[ "$PERFORMANCE_ONLY" == true ]]; then
    run_proof_lane "R1" "MEDIUM" "Performance Benchmarks" \
        'rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_r1" cargo bench --features criterion-benches --bench atp_j5_workflows_bench' \
        1800
    run_proof_lane "R2" "MEDIUM" "Stress Testing" \
        'scripts/atp_stress_test.sh --resource-limits' \
        1200
elif [[ "$DOCUMENTATION_ONLY" == true ]]; then
    run_documentation_gates
fi

generate_final_report
