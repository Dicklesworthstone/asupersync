#!/bin/bash
# ATP Release Gates - Master Release Qualification Script
# Orchestrates all release gates and proof lane validation

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
GATE_LOG="${PROJECT_ROOT}/artifacts/release_gates_$(date +%Y%m%d_%H%M%S).log"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Gate tracking
GATES_PASSED=0
GATES_FAILED=0
GATES_SKIPPED=0

log_gate() {
    local status="$1"
    local gate="$2"
    local message="$3"

    case "$status" in
        PASS)
            echo -e "${GREEN}[PASS]${NC} $gate: $message" | tee -a "$GATE_LOG"
            ((GATES_PASSED++))
            ;;
        FAIL)
            echo -e "${RED}[FAIL]${NC} $gate: $message" | tee -a "$GATE_LOG"
            ((GATES_FAILED++))
            ;;
        SKIP)
            echo -e "${YELLOW}[SKIP]${NC} $gate: $message" | tee -a "$GATE_LOG"
            ((GATES_SKIPPED++))
            ;;
        INFO)
            echo -e "${BLUE}[INFO]${NC} $gate: $message" | tee -a "$GATE_LOG"
            ;;
    esac
}

print_banner() {
    echo -e "${CYAN}"
    echo "=========================================="
    echo "   ATP RELEASE GATES VALIDATION"
    echo "=========================================="
    echo -e "${NC}"
}

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Validate ATP release gates and proof lane requirements."
    echo ""
    echo "Options:"
    echo "  --proof-lanes-only    Run only proof lane validation"
    echo "  --dependency-only     Run only dependency audit"
    echo "  --platform-only       Run only cross-platform tests"
    echo "  --quick              Skip long-running tests"
    echo "  --verbose            Enable verbose output"
    echo "  --help               Show this help message"
    echo ""
    echo "Gate Categories:"
    echo "  1. Dependency Audit   - Validate no forbidden dependencies"
    echo "  2. Cross-Platform     - Verify platform compatibility"
    echo "  3. Proof Lanes        - Execute complete proof lane matrix"
    echo "  4. Security           - Security validation checks"
    echo "  5. Documentation      - Documentation completeness"
    echo "  6. Performance        - Performance regression checks"
}

# Parse command line options
PROOF_LANES_ONLY=false
DEPENDENCY_ONLY=false
PLATFORM_ONLY=false
QUICK_MODE=false
VERBOSE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --proof-lanes-only)
            PROOF_LANES_ONLY=true
            shift
            ;;
        --dependency-only)
            DEPENDENCY_ONLY=true
            shift
            ;;
        --platform-only)
            PLATFORM_ONLY=true
            shift
            ;;
        --quick)
            QUICK_MODE=true
            shift
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
            exit 1
            ;;
    esac
done

# Initialize gate log
mkdir -p "${PROJECT_ROOT}/artifacts"
{
    echo "ATP Release Gates Validation"
    echo "Started: $(date)"
    echo "Working Directory: $PROJECT_ROOT"
    echo "Git Commit: $(git rev-parse HEAD 2>/dev/null || echo 'N/A')"
    echo "=========================================="
} > "$GATE_LOG"

run_dependency_audit() {
    log_gate INFO "DEPENDENCY-AUDIT" "Starting dependency audit..."

    if [[ -x "$SCRIPT_DIR/dependency_audit.sh" ]]; then
        if "$SCRIPT_DIR/dependency_audit.sh" >>"$GATE_LOG" 2>&1; then
            log_gate PASS "DEPENDENCY-AUDIT" "All dependency checks passed"
        else
            log_gate FAIL "DEPENDENCY-AUDIT" "Dependency violations found - check audit log"
        fi
    else
        log_gate FAIL "DEPENDENCY-AUDIT" "dependency_audit.sh script not found or not executable"
    fi
}

run_cross_platform_tests() {
    log_gate INFO "CROSS-PLATFORM" "Starting cross-platform compatibility tests..."

    if [[ -x "$SCRIPT_DIR/cross_platform_test.sh" ]]; then
        if "$SCRIPT_DIR/cross_platform_test.sh" >>"$GATE_LOG" 2>&1; then
            log_gate PASS "CROSS-PLATFORM" "Platform compatibility validated"
        else
            log_gate FAIL "CROSS-PLATFORM" "Platform compatibility issues found"
        fi
    else
        log_gate FAIL "CROSS-PLATFORM" "cross_platform_test.sh script not found or not executable"
    fi
}

run_proof_lanes() {
    log_gate INFO "PROOF-LANES" "Starting proof lane matrix execution..."

    cd "$PROJECT_ROOT"

    local proof_lanes=(
        "quic_conformance:QUIC Conformance"
        "atp_protocol_codec:ATP Protocol Codec"
        "manifest_merkle:Manifest/Merkle Integrity"
        "crash_safety:Disk Crash Safety"
        "resume_transfer:Resume Capability"
        "path_graph:Path Graph Verification"
        "relay_forwarding:Relay Forwarding"
        "raptorq_repair:RaptorQ Repair"
        "lab_scenarios:Lab Scenarios"
        "deterministic_replay:Deterministic Replay"
        "cli_ux:CLI User Experience"
        "daemon_shutdown:Daemon Shutdown"
        "benchmarks:Performance Benchmarks"
        "security_validation:Security Validation"
    )

    local lane_failures=0

    for lane_spec in "${proof_lanes[@]}"; do
        local lane_name="${lane_spec%%:*}"
        local lane_desc="${lane_spec#*:}"

        log_gate INFO "PROOF-LANE-$lane_name" "Executing $lane_desc..."

        # Check if specific test exists, otherwise skip
        local test_command=""
        case "$lane_name" in
            quic_conformance)
                test_command="cargo test --test quic_conformance"
                ;;
            atp_protocol_codec)
                test_command="cargo test --test atp_protocol_codec"
                ;;
            manifest_merkle)
                test_command="cargo test --test manifest_merkle"
                ;;
            crash_safety)
                test_command="cargo test --test crash_safety"
                ;;
            resume_transfer)
                test_command="cargo test --test resume_transfer"
                ;;
            cli_ux)
                test_command="cargo test --test cli_ux"
                ;;
            benchmarks)
                if [[ "$QUICK_MODE" == "true" ]]; then
                    log_gate SKIP "PROOF-LANE-$lane_name" "Skipped in quick mode"
                    continue
                fi
                test_command="cargo test --test benchmarks"
                ;;
            *)
                # For now, use general test pattern
                test_command="cargo test --lib $(echo "$lane_name" | tr '_' '-')"
                ;;
        esac

        if [[ -n "$test_command" ]]; then
            if timeout 1800 $test_command >>"$GATE_LOG" 2>&1; then
                log_gate PASS "PROOF-LANE-$lane_name" "$lane_desc completed successfully"
            else
                log_gate FAIL "PROOF-LANE-$lane_name" "$lane_desc failed - generating replay artifacts"

                # Generate replay artifacts for failed proof lanes
                if [[ -x "$SCRIPT_DIR/generate_replay_artifacts.sh" ]]; then
                    "$SCRIPT_DIR/generate_replay_artifacts.sh" -t "proof_lane_${lane_name}" proof-lane "$test_command" >>"$GATE_LOG" 2>&1 || true
                fi

                ((lane_failures++))
            fi
        else
            log_gate SKIP "PROOF-LANE-$lane_name" "Test command not defined"
        fi
    done

    if [[ $lane_failures -eq 0 ]]; then
        log_gate PASS "PROOF-LANES" "All proof lanes passed"
    else
        log_gate FAIL "PROOF-LANES" "$lane_failures proof lanes failed"
    fi
}

run_security_checks() {
    log_gate INFO "SECURITY" "Starting security validation..."

    cd "$PROJECT_ROOT"

    # Check for unsafe code that needs review
    local unsafe_count
    unsafe_count=$(find src/ -name "*.rs" -exec grep -c "unsafe" {} \; 2>/dev/null | awk '{sum += $1} END {print sum+0}')

    if [[ $unsafe_count -gt 0 ]]; then
        log_gate INFO "SECURITY" "Found $unsafe_count unsafe blocks - ensure all have proper justification"
    fi

    # Run cargo audit if available
    if command -v cargo-audit >/dev/null; then
        if cargo audit >>"$GATE_LOG" 2>&1; then
            log_gate PASS "SECURITY" "No known vulnerabilities in dependencies"
        else
            log_gate FAIL "SECURITY" "Security vulnerabilities found in dependencies"
        fi
    else
        log_gate SKIP "SECURITY" "cargo-audit not available"
    fi

    log_gate PASS "SECURITY" "Security validation completed"
}

run_documentation_checks() {
    log_gate INFO "DOCUMENTATION" "Validating documentation completeness..."

    cd "$PROJECT_ROOT"

    # Check for required documentation files
    local required_docs=(
        "README.md"
        "CONTRIBUTING.md"
        "artifacts/ATP_PROOF_LANE_MANIFEST.md"
        "artifacts/ATP_GOVERNANCE.md"
    )

    local missing_docs=0
    for doc in "${required_docs[@]}"; do
        if [[ -f "$doc" ]]; then
            log_gate PASS "DOCUMENTATION" "Found required document: $doc"
        else
            log_gate FAIL "DOCUMENTATION" "Missing required document: $doc"
            ((missing_docs++))
        fi
    done

    # Check documentation tests
    if cargo test --doc >>"$GATE_LOG" 2>&1; then
        log_gate PASS "DOCUMENTATION" "All documentation tests passed"
    else
        log_gate FAIL "DOCUMENTATION" "Documentation tests failed"
        ((missing_docs++))
    fi

    if [[ $missing_docs -eq 0 ]]; then
        log_gate PASS "DOCUMENTATION" "Documentation validation completed"
    else
        log_gate FAIL "DOCUMENTATION" "$missing_docs documentation issues found"
    fi
}

run_performance_checks() {
    if [[ "$QUICK_MODE" == "true" ]]; then
        log_gate SKIP "PERFORMANCE" "Skipped in quick mode"
        return
    fi

    log_gate INFO "PERFORMANCE" "Running performance regression checks..."

    cd "$PROJECT_ROOT"

    # Basic performance smoke test
    if cargo test --release --test benchmarks >>"$GATE_LOG" 2>&1; then
        log_gate PASS "PERFORMANCE" "Performance tests passed"
    else
        log_gate FAIL "PERFORMANCE" "Performance regression detected"
    fi
}

# Main execution logic
main() {
    print_banner

    log_gate INFO "RELEASE-GATES" "Starting ATP release gate validation"

    if [[ "$DEPENDENCY_ONLY" == "true" ]]; then
        run_dependency_audit
    elif [[ "$PLATFORM_ONLY" == "true" ]]; then
        run_cross_platform_tests
    elif [[ "$PROOF_LANES_ONLY" == "true" ]]; then
        run_proof_lanes
    else
        # Run all gates in order
        run_dependency_audit
        run_cross_platform_tests
        run_security_checks
        run_documentation_checks
        run_performance_checks
        run_proof_lanes
    fi

    # Generate final summary
    echo "" | tee -a "$GATE_LOG"
    echo "==========================================" | tee -a "$GATE_LOG"
    echo "RELEASE GATES SUMMARY" | tee -a "$GATE_LOG"
    echo "==========================================" | tee -a "$GATE_LOG"
    echo "Passed: $GATES_PASSED" | tee -a "$GATE_LOG"
    echo "Failed: $GATES_FAILED" | tee -a "$GATE_LOG"
    echo "Skipped: $GATES_SKIPPED" | tee -a "$GATE_LOG"
    echo "Completed: $(date)" | tee -a "$GATE_LOG"
    echo "" | tee -a "$GATE_LOG"

    if [[ $GATES_FAILED -eq 0 ]]; then
        echo -e "${GREEN}🎉 ATP RELEASE GATES: ALL PASSED${NC}"
        echo -e "${GREEN}ATP is ready for release${NC}"
        echo -e "${BLUE}Full gate log: $GATE_LOG${NC}"
        exit 0
    else
        echo -e "${RED}❌ ATP RELEASE GATES: $GATES_FAILED FAILURES${NC}"
        echo -e "${RED}ATP is NOT ready for release${NC}"
        echo -e "${BLUE}Full gate log: $GATE_LOG${NC}"
        echo ""
        echo "Fix all failing gates before proceeding with release."
        exit 1
    fi
}

# Execute main function
main "$@"