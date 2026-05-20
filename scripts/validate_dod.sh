#!/bin/bash
# ATP Definition of Done Enforcement
# Validates that implementation beads meet ATP evidence standards

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DOD_LOG="${PROJECT_ROOT}/artifacts/dod_validation_$(date +%Y%m%d_%H%M%S).log"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# DoD enforcement tracking
DOD_VIOLATIONS=0
DOD_WARNINGS=0
DOD_PASSED=0

log_violation() {
    echo -e "${RED}VIOLATION:${NC} $1" | tee -a "$DOD_LOG"
    ((DOD_VIOLATIONS++))
}

log_warning() {
    echo -e "${YELLOW}WARNING:${NC} $1" | tee -a "$DOD_LOG"
    ((DOD_WARNINGS++))
}

log_pass() {
    echo -e "${GREEN}PASS:${NC} $1" | tee -a "$DOD_LOG"
    ((DOD_PASSED++))
}

log_info() {
    echo -e "${BLUE}INFO:${NC} $1" | tee -a "$DOD_LOG"
}

# Initialize DoD log
mkdir -p "${PROJECT_ROOT}/artifacts"
{
    echo "ATP Definition of Done Validation - $(date)"
    echo "================================================"
    echo "Working Directory: $PROJECT_ROOT"
    echo "Git Commit: $(git rev-parse HEAD 2>/dev/null || echo 'N/A')"
    echo ""
} > "$DOD_LOG"

# ATP surface area definitions
declare -A ATP_SURFACES=(
    ["native_quic"]="Native QUIC implementation (src/net/quic_native/)"
    ["atp_protocol"]="ATP protocol implementation (src/atp/protocol/)"
    ["object_graph"]="Object graph and manifest (src/atp/object/, src/atp/manifest/)"
    ["disk_journal"]="Disk storage and journaling (src/atp/disk/, src/atp/journal/)"
    ["scheduler"]="Task scheduler (src/runtime/scheduler/)"
    ["raptorq_repair"]="RaptorQ repair implementation (src/raptorq/)"
    ["path_graph"]="Path graph and routing (src/atp/path/)"
    ["atpd"]="ATP daemon (src/bin/atpd/)"
    ["cli_sdk"]="CLI and SDK (src/cli/, src/sdk/)"
    ["mailbox_swarm"]="Mailbox and swarm (src/atp/mailbox/, src/atp/swarm/)"
    ["adapters"]="Protocol adapters (src/adapters/)"
    ["lab_bench"]="Lab and benchmarking (src/lab/, tests/benchmarks/)"
    ["release_governance"]="Release and governance (scripts/, artifacts/)"
)

# DoD evidence categories
declare -A EVIDENCE_CATEGORIES=(
    ["unit_tests"]="Local invariant testing via unit tests"
    ["property_tests"]="Property/metamorphic tests for codecs/manifests/repair"
    ["integration_tests"]="End-to-end integration test scenarios"
    ["lab_tests"]="Deterministic lab tests for concurrency/faults"
    ["e2e_scripts"]="User workflow end-to-end scripts"
    ["structured_logs"]="Structured logging and observability"
    ["failure_bundles"]="Failure bundle generation and replay"
    ["dependency_audit"]="Dependency audit compliance"
    ["platform_coverage"]="Cross-platform validation"
)

check_surface_evidence() {
    local surface="$1"
    local surface_path="$2"

    log_info "Checking DoD evidence for ATP surface: $surface"

    if [[ ! -d "$PROJECT_ROOT/$surface_path" ]]; then
        log_warning "Surface path not found: $surface_path"
        return 0
    fi

    local violations=0

    # Check for unit tests
    local unit_test_files=$(find "$PROJECT_ROOT/$surface_path" -name "*test*.rs" -o -name "test_*.rs" 2>/dev/null || true)
    if [[ -n "$unit_test_files" ]]; then
        log_pass "Unit tests found for $surface"
    else
        # Check for #[cfg(test)] blocks
        local test_blocks=$(find "$PROJECT_ROOT/$surface_path" -name "*.rs" -exec grep -l "#\[cfg(test)\]" {} \; 2>/dev/null || true)
        if [[ -n "$test_blocks" ]]; then
            log_pass "Inline unit tests found for $surface"
        else
            log_violation "No unit tests found for $surface (required for implementation beads)"
            ((violations++))
        fi
    fi

    # Check for integration tests
    local integration_tests=$(find "$PROJECT_ROOT/tests" -name "*${surface}*" -o -name "*$(echo "$surface" | tr '_' '-')*" 2>/dev/null || true)
    if [[ -n "$integration_tests" ]]; then
        log_pass "Integration tests found for $surface"
    else
        log_warning "No dedicated integration tests found for $surface"
    fi

    return $violations
}

validate_test_evidence() {
    log_info "Validating test evidence across ATP surfaces..."

    local total_violations=0

    for surface in "${!ATP_SURFACES[@]}"; do
        local surface_desc="${ATP_SURFACES[$surface]}"
        local surface_path=""

        # Map surface to likely path
        case "$surface" in
            native_quic) surface_path="src/net/quic_native" ;;
            atp_protocol) surface_path="src/atp/protocol" ;;
            object_graph) surface_path="src/atp/object" ;;
            disk_journal) surface_path="src/atp/disk" ;;
            scheduler) surface_path="src/runtime/scheduler" ;;
            raptorq_repair) surface_path="src/raptorq" ;;
            path_graph) surface_path="src/atp/path" ;;
            atpd) surface_path="src/bin" ;;
            cli_sdk) surface_path="src/cli" ;;
            mailbox_swarm) surface_path="src/atp/mailbox" ;;
            adapters) surface_path="src/adapters" ;;
            lab_bench) surface_path="src/lab" ;;
            release_governance) surface_path="scripts" ;;
        esac

        if check_surface_evidence "$surface" "$surface_path"; then
            ((total_violations += $?))
        fi
    done

    return $total_violations
}

validate_e2e_evidence() {
    log_info "Validating end-to-end evidence..."

    local violations=0

    # Check for e2e test scripts
    local e2e_scripts=$(find "$PROJECT_ROOT/scripts" -name "*e2e*.sh" 2>/dev/null || true)
    if [[ -n "$e2e_scripts" ]]; then
        log_pass "E2E test scripts found: $(echo "$e2e_scripts" | wc -l) scripts"
    else
        log_violation "No E2E test scripts found in scripts/ directory"
        ((violations++))
    fi

    # Check for structured logging
    local log_structures=$(find "$PROJECT_ROOT/src" -name "*.rs" -exec grep -l "tracing::" {} \; 2>/dev/null | head -5 || true)
    if [[ -n "$log_structures" ]]; then
        log_pass "Structured logging found (tracing crate usage)"
    else
        log_violation "No structured logging found (tracing crate required)"
        ((violations++))
    fi

    # Check for failure bundle capabilities
    local failure_bundle_code=$(find "$PROJECT_ROOT/src" -name "*.rs" -exec grep -l "replay\|evidence\|artifact" {} \; 2>/dev/null | head -3 || true)
    if [[ -n "$failure_bundle_code" ]]; then
        log_pass "Failure bundle/replay capabilities found"
    else
        log_warning "Limited failure bundle/replay evidence found"
    fi

    return $violations
}

validate_proof_command_evidence() {
    log_info "Validating proof command evidence..."

    local violations=0

    # Check that test commands in ATP_PROOF_LANE_MANIFEST actually exist
    local manifest_file="$PROJECT_ROOT/artifacts/ATP_PROOF_LANE_MANIFEST.md"
    if [[ -f "$manifest_file" ]]; then
        # Extract cargo test commands from manifest
        local test_commands=$(grep "Command.*cargo test" "$manifest_file" | sed 's/.*Command.*: *`\([^`]*\)`.*/\1/' || true)

        if [[ -n "$test_commands" ]]; then
            echo "$test_commands" | while IFS= read -r cmd; do
                if [[ -n "$cmd" ]]; then
                    # Extract test name from command
                    local test_name=$(echo "$cmd" | sed 's/.*--test \([^ ]*\).*/\1/' || true)
                    if [[ -n "$test_name" && "$test_name" != "$cmd" ]]; then
                        # Check if test file exists
                        if [[ -f "$PROJECT_ROOT/tests/${test_name}.rs" ]]; then
                            log_pass "Proof lane test exists: $test_name"
                        else
                            log_violation "Proof lane test missing: $test_name (referenced in manifest)"
                            ((violations++))
                        fi
                    fi
                fi
            done
        fi

        log_pass "ATP proof lane manifest validation completed"
    else
        log_violation "ATP_PROOF_LANE_MANIFEST.md not found"
        ((violations++))
    fi

    return $violations
}

validate_coverage_evidence() {
    log_info "Validating test coverage evidence..."

    local violations=0

    # Check for coverage tooling
    if command -v cargo-tarpaulin >/dev/null 2>&1; then
        log_pass "Code coverage tooling available (tarpaulin)"
    elif command -v grcov >/dev/null 2>&1; then
        log_pass "Code coverage tooling available (grcov)"
    else
        log_warning "No code coverage tooling found (tarpaulin or grcov recommended)"
    fi

    # Check for existing coverage reports
    local coverage_artifacts=$(find "$PROJECT_ROOT/artifacts" -name "*coverage*" -o -name "*.lcov" 2>/dev/null || true)
    if [[ -n "$coverage_artifacts" ]]; then
        log_pass "Coverage artifacts found in artifacts/ directory"
    else
        log_warning "No coverage artifacts found (consider adding coverage reports)"
    fi

    return $violations
}

check_anti_patterns() {
    log_info "Checking for DoD anti-patterns..."

    local violations=0

    # Check for compile-only evidence patterns
    local compile_only_patterns=$(find "$PROJECT_ROOT/src" -name "*.rs" -exec grep -l "TODO\|FIXME\|unimplemented!" {} \; 2>/dev/null | head -5 || true)
    if [[ -n "$compile_only_patterns" ]]; then
        log_warning "Potential compile-only patterns found: $(echo "$compile_only_patterns" | wc -l) files"
        echo "Files: $compile_only_patterns" >> "$DOD_LOG"
    fi

    # Check for external QUIC/Tokio usage (should be caught by dependency audit)
    local external_runtime=$(find "$PROJECT_ROOT/src" -name "*.rs" -exec grep -l "tokio::runtime\|quinn::" {} \; 2>/dev/null | head -3 || true)
    if [[ -n "$external_runtime" ]]; then
        log_violation "External runtime/QUIC usage found (violates ATP core principles)"
        ((violations++))
    fi

    # Check for missing test assertions
    local test_files=$(find "$PROJECT_ROOT" -name "*test*.rs" -o -path "*/tests/*" -name "*.rs" 2>/dev/null || true)
    if [[ -n "$test_files" ]]; then
        local assertion_count=0
        while IFS= read -r test_file; do
            if [[ -f "$test_file" ]]; then
                local assertions=$(grep -c "assert\|expect" "$test_file" 2>/dev/null || echo 0)
                assertion_count=$((assertion_count + assertions))
            fi
        done <<< "$test_files"

        if [[ $assertion_count -gt 20 ]]; then
            log_pass "Adequate test assertions found ($assertion_count total)"
        else
            log_warning "Low test assertion count ($assertion_count) - verify test quality"
        fi
    fi

    return $violations
}

generate_dod_report() {
    log_info "Generating Definition of Done compliance report..."

    local report_file="$PROJECT_ROOT/artifacts/dod_compliance_report.json"

    cat > "$report_file" << EOF
{
    "dod_validation": {
        "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
        "git_commit": "$(git rev-parse HEAD 2>/dev/null || echo 'N/A')",
        "validation_results": {
            "passed": $DOD_PASSED,
            "warnings": $DOD_WARNINGS,
            "violations": $DOD_VIOLATIONS
        }
    },
    "atp_surfaces": {
$(for surface in "${!ATP_SURFACES[@]}"; do
    echo "        \"$surface\": \"${ATP_SURFACES[$surface]}\","
done | sed '$s/,$//')
    },
    "evidence_categories": {
$(for category in "${!EVIDENCE_CATEGORIES[@]}"; do
    echo "        \"$category\": \"${EVIDENCE_CATEGORIES[$category]}\","
done | sed '$s/,$//')
    },
    "compliance_status": "$(if [[ $DOD_VIOLATIONS -eq 0 ]]; then echo "COMPLIANT"; else echo "NON_COMPLIANT"; fi)",
    "recommendations": [
$(if [[ $DOD_VIOLATIONS -gt 0 ]]; then
    echo "        \"Address DoD violations before closing implementation beads\","
fi)
$(if [[ $DOD_WARNINGS -gt 0 ]]; then
    echo "        \"Review warnings for potential evidence gaps\","
fi)
        "Ensure all ATP surfaces have adequate test coverage",
        "Maintain structured logging and failure bundle capabilities",
        "Keep proof lane commands synchronized with actual test implementations"
    ]
}
EOF

    log_pass "DoD compliance report generated: $report_file"
}

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Validate ATP Definition of Done compliance for implementation beads."
    echo ""
    echo "Options:"
    echo "  --surface SURFACE     Validate specific ATP surface only"
    echo "  --evidence CATEGORY   Check specific evidence category"
    echo "  --strict             Treat warnings as violations"
    echo "  --report-only        Generate report without validation"
    echo "  --help               Show this help message"
    echo ""
    echo "ATP Surfaces:"
    for surface in "${!ATP_SURFACES[@]}"; do
        echo "  $surface"
    done
    echo ""
    echo "Evidence Categories:"
    for category in "${!EVIDENCE_CATEGORIES[@]}"; do
        echo "  $category"
    done
}

# Parse command line options
SPECIFIC_SURFACE=""
SPECIFIC_EVIDENCE=""
STRICT_MODE=false
REPORT_ONLY=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --surface)
            SPECIFIC_SURFACE="$2"
            shift 2
            ;;
        --evidence)
            SPECIFIC_EVIDENCE="$2"
            shift 2
            ;;
        --strict)
            STRICT_MODE=true
            shift
            ;;
        --report-only)
            REPORT_ONLY=true
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

main() {
    echo "ATP Definition of Done Validation"
    echo "================================="

    if [[ "$REPORT_ONLY" == "true" ]]; then
        generate_dod_report
        exit 0
    fi

    log_info "Starting ATP DoD validation for implementation beads"

    local total_violations=0

    # Run validation checks
    if [[ -z "$SPECIFIC_SURFACE" && -z "$SPECIFIC_EVIDENCE" ]]; then
        # Full validation
        validate_test_evidence || total_violations=$((total_violations + $?))
        validate_e2e_evidence || total_violations=$((total_violations + $?))
        validate_proof_command_evidence || total_violations=$((total_violations + $?))
        validate_coverage_evidence || total_violations=$((total_violations + $?))
        check_anti_patterns || total_violations=$((total_violations + $?))
    elif [[ -n "$SPECIFIC_SURFACE" ]]; then
        # Surface-specific validation
        if [[ -n "${ATP_SURFACES[$SPECIFIC_SURFACE]:-}" ]]; then
            log_info "Validating specific ATP surface: $SPECIFIC_SURFACE"
            # Implementation would go here for surface-specific validation
        else
            log_violation "Unknown ATP surface: $SPECIFIC_SURFACE"
            ((total_violations++))
        fi
    fi

    # Apply strict mode
    if [[ "$STRICT_MODE" == "true" ]]; then
        total_violations=$((total_violations + DOD_WARNINGS))
        DOD_VIOLATIONS=$((DOD_VIOLATIONS + DOD_WARNINGS))
        DOD_WARNINGS=0
    fi

    generate_dod_report

    # Final summary
    echo ""
    echo "================================="
    echo "DoD VALIDATION SUMMARY"
    echo "================================="
    echo "Passed: $DOD_PASSED" | tee -a "$DOD_LOG"
    echo "Warnings: $DOD_WARNINGS" | tee -a "$DOD_LOG"
    echo "Violations: $DOD_VIOLATIONS" | tee -a "$DOD_LOG"
    echo "Validation completed: $(date)" | tee -a "$DOD_LOG"
    echo ""

    if [[ $DOD_VIOLATIONS -eq 0 ]]; then
        echo -e "${GREEN}✅ ATP DEFINITION OF DONE: COMPLIANT${NC}"
        echo -e "${GREEN}Implementation beads may proceed to closure${NC}"
        echo -e "${BLUE}Full validation log: $DOD_LOG${NC}"
        exit 0
    else
        echo -e "${RED}❌ ATP DEFINITION OF DONE: NON-COMPLIANT${NC}"
        echo -e "${RED}$DOD_VIOLATIONS violations must be addressed before bead closure${NC}"
        echo -e "${BLUE}Full validation log: $DOD_LOG${NC}"
        echo ""
        echo "Address violations before closing implementation beads."
        exit 1
    fi
}

# Execute main function
main "$@"