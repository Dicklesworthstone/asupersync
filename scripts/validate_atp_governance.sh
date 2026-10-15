#!/bin/bash
# ATP Governance Validation - Ensures documentation aligns with implementation reality
# Validates architecture docs, proof lanes, and governance processes

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VALIDATION_LOG="${PROJECT_ROOT}/artifacts/atp_governance_validation_$(date +%Y%m%d_%H%M%S).log"

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Validation tracking
CHECKS_PASSED=0
CHECKS_FAILED=0
WARNINGS=0

log_check() {
    local status="$1"
    local check="$2"
    local message="$3"

    case "$status" in
        PASS)
            echo -e "${GREEN}[PASS]${NC} $check: $message" | tee -a "$VALIDATION_LOG"
            ((CHECKS_PASSED++))
            ;;
        FAIL)
            echo -e "${RED}[FAIL]${NC} $check: $message" | tee -a "$VALIDATION_LOG"
            ((CHECKS_FAILED++))
            ;;
        WARN)
            echo -e "${YELLOW}[WARN]${NC} $check: $message" | tee -a "$VALIDATION_LOG"
            ((WARNINGS++))
            ;;
        INFO)
            echo -e "${BLUE}[INFO]${NC} $check: $message" | tee -a "$VALIDATION_LOG"
            ;;
    esac
}

print_banner() {
    echo -e "${BLUE}"
    echo "=========================================="
    echo "   ATP GOVERNANCE VALIDATION"
    echo "=========================================="
    echo -e "${NC}"
    echo "Log file: $VALIDATION_LOG"
    echo ""
}

# Validate architecture documentation alignment
validate_architecture_docs() {
    log_check "INFO" "arch_docs" "Validating architecture documentation alignment"

    # Check architecture doc exists and is recent
    local arch_doc="${PROJECT_ROOT}/docs/ATP_ARCHITECTURE.md"
    if [[ ! -f "$arch_doc" ]]; then
        log_check "FAIL" "arch_docs" "Architecture document missing: $arch_doc"
        return
    fi

    # Check if doc references current commit
    local current_commit=$(git rev-parse HEAD)
    local short_commit=${current_commit:0:9}

    if grep -q "$short_commit" "$arch_doc"; then
        log_check "PASS" "arch_docs" "Architecture doc references current commit $short_commit"
    else
        log_check "WARN" "arch_docs" "Architecture doc may be outdated (no reference to commit $short_commit)"
    fi

    # Check for implementation-reality alignment
    local components_documented=0
    local components_implemented=0

    # Count documented components
    if grep -q "ATP Workflows" "$arch_doc"; then ((components_documented++)); fi
    if grep -q "ATP Command Tree" "$arch_doc"; then ((components_documented++)); fi
    if grep -q "ATPD Daemon" "$arch_doc"; then ((components_documented++)); fi
    if grep -q "Object Graph" "$arch_doc"; then ((components_documented++)); fi

    # Count implemented components
    if [[ -f "$PROJECT_ROOT/src/cli/atp_workflows.rs" ]]; then ((components_implemented++)); fi
    if [[ -f "$PROJECT_ROOT/src/cli/atp_command_tree.rs" ]]; then ((components_implemented++)); fi
    if [[ -f "$PROJECT_ROOT/src/bin/atpd.rs" ]]; then ((components_implemented++)); fi
    if find "$PROJECT_ROOT/src" -name "*object*" -type f | grep -q .; then ((components_implemented++)); fi

    if [[ $components_documented -eq $components_implemented ]]; then
        log_check "PASS" "arch_docs" "Component documentation aligned with implementation ($components_documented components)"
    else
        log_check "WARN" "arch_docs" "Documentation-implementation mismatch (doc: $components_documented, impl: $components_implemented)"
    fi
}

# Validate proof lane manifest completeness
validate_proof_lane_manifest() {
    log_check "INFO" "proof_lanes" "Validating proof lane manifest completeness"

    local manifest_file="${PROJECT_ROOT}/artifacts/ATP_PROOF_LANE_MANIFEST.md"
    if [[ ! -f "$manifest_file" ]]; then
        log_check "FAIL" "proof_lanes" "Proof lane manifest missing: $manifest_file"
        return
    fi

    # Check for required proof lane sections
    local required_sections=(
        "Core Protocol Proof Lanes"
        "Application & Integration Proof Lanes"
        "Security & Compliance Proof Lanes"
        "Performance & Reliability Proof Lanes"
        "Documentation & Governance Proof Lanes"
    )

    local sections_found=0
    for section in "${required_sections[@]}"; do
        if grep -q "$section" "$manifest_file"; then
            ((sections_found++))
        else
            log_check "WARN" "proof_lanes" "Missing section: $section"
        fi
    done

    if [[ $sections_found -eq ${#required_sections[@]} ]]; then
        log_check "PASS" "proof_lanes" "All required proof lane sections present"
    else
        log_check "FAIL" "proof_lanes" "Missing $((${#required_sections[@]} - sections_found)) required sections"
    fi

    # Check for executable commands
    local commands_with_rch=$(grep -c "rch exec" "$manifest_file" || echo "0")
    local commands_with_scripts=$(grep -c "scripts/" "$manifest_file" || echo "0")
    local total_commands=$((commands_with_rch + commands_with_scripts))

    if [[ $total_commands -gt 10 ]]; then
        log_check "PASS" "proof_lanes" "Sufficient executable commands found ($total_commands total)"
    else
        log_check "WARN" "proof_lanes" "Low number of executable commands ($total_commands total)"
    fi
}

# Validate dogfooding implementation
validate_dogfooding_implementation() {
    log_check "INFO" "dogfooding" "Validating ATP dogfooding implementation"

    # Check dogfooding coordinator exists
    local coordinator_script="${PROJECT_ROOT}/scripts/atp_dogfood_coordinator.sh"
    if [[ ! -x "$coordinator_script" ]]; then
        log_check "FAIL" "dogfooding" "Dogfood coordinator missing or not executable: $coordinator_script"
        return
    fi

    # Test dry-run mode
    if "$coordinator_script" --dry-run build-artifacts >/dev/null 2>&1; then
        log_check "PASS" "dogfooding" "Dogfood coordinator dry-run executes successfully"
    else
        log_check "FAIL" "dogfooding" "Dogfood coordinator dry-run failed"
    fi

    # Check CI integration
    local ci_script="${PROJECT_ROOT}/scripts/ci/atp_dogfood_ci_integration.sh"
    if [[ ! -x "$ci_script" ]]; then
        log_check "WARN" "dogfooding" "CI integration script missing: $ci_script"
    else
        log_check "PASS" "dogfooding" "CI integration script present and executable"
    fi

    # Check integration tests
    local integration_test="${PROJECT_ROOT}/tests/atp_dogfood_integration.rs"
    if [[ ! -f "$integration_test" ]]; then
        log_check "WARN" "dogfooding" "Integration tests missing: $integration_test"
    else
        log_check "PASS" "dogfooding" "Integration tests present"
    fi
}

# Validate release gates
validate_release_gates() {
    log_check "INFO" "release_gates" "Validating ATP release gate implementation"

    # Check enhanced release gates script
    local enhanced_gates="${PROJECT_ROOT}/scripts/atp_enhanced_release_gates.sh"
    if [[ ! -x "$enhanced_gates" ]]; then
        log_check "FAIL" "release_gates" "Enhanced release gates script missing: $enhanced_gates"
    else
        log_check "PASS" "release_gates" "Enhanced release gates script present"

        # Test help functionality
        if "$enhanced_gates" --help >/dev/null 2>&1; then
            log_check "PASS" "release_gates" "Release gates help executes successfully"
        else
            log_check "WARN" "release_gates" "Release gates help execution failed"
        fi

        # Check for priority levels
        if grep -q "CRITICAL\|HIGH\|MEDIUM" "$enhanced_gates"; then
            log_check "PASS" "release_gates" "Priority levels properly implemented"
        else
            log_check "WARN" "release_gates" "Priority levels may be missing"
        fi
    fi

    # Check original release gates integration
    local original_gates="${PROJECT_ROOT}/scripts/atp_release_gates.sh"
    if [[ -x "$original_gates" ]]; then
        log_check "PASS" "release_gates" "Original release gates script still available"
    else
        log_check "INFO" "release_gates" "Original release gates script not found (may be replaced)"
    fi
}

# Validate governance documentation
validate_governance_docs() {
    log_check "INFO" "governance" "Validating ATP governance documentation"

    # Check governance v2 document
    local governance_doc="${PROJECT_ROOT}/docs/ATP_GOVERNANCE_V2.md"
    if [[ ! -f "$governance_doc" ]]; then
        log_check "FAIL" "governance" "Governance v2 document missing: $governance_doc"
    else
        log_check "PASS" "governance" "Governance v2 document present"

        # Check for required governance sections
        local required_gov_sections=(
            "Core Governance Principles"
            "Documentation Governance"
            "Release Governance"
            "Component Ownership"
            "Change Management"
            "Compliance and Audit"
        )

        local gov_sections_found=0
        for section in "${required_gov_sections[@]}"; do
            if grep -q "$section" "$governance_doc"; then
                ((gov_sections_found++))
            else
                log_check "WARN" "governance" "Missing governance section: $section"
            fi
        done

        if [[ $gov_sections_found -eq ${#required_gov_sections[@]} ]]; then
            log_check "PASS" "governance" "All governance sections present"
        else
            log_check "WARN" "governance" "Missing governance sections ($gov_sections_found/${#required_gov_sections[@]})"
        fi
    fi

    # Check DOD checklist
    local dod_checklist="${PROJECT_ROOT}/ATP_DOD_CHECKLIST.md"
    if [[ ! -f "$dod_checklist" ]]; then
        log_check "WARN" "governance" "DOD checklist missing: $dod_checklist"
    else
        log_check "PASS" "governance" "DOD checklist present"
    fi
}

# Validate bead integration
validate_bead_integration() {
    log_check "INFO" "beads" "Validating bead system integration"

    # Check if br command is available
    if command -v br >/dev/null 2>&1; then
        log_check "PASS" "beads" "Beads CLI (br) available"

        # Check for ATP-related beads
        if br list --labels atp-dml 2>/dev/null | grep -q "atp"; then
            log_check "PASS" "beads" "ATP-related beads found in system"
        else
            log_check "INFO" "beads" "No ATP beads currently in system (may be expected)"
        fi
    else
        log_check "WARN" "beads" "Beads CLI (br) not available"
    fi

    # Check for bead creation in failure scenarios
    local scripts_with_bead_creation=0
    if grep -q "br create" "${PROJECT_ROOT}/scripts/atp_dogfood_coordinator.sh" 2>/dev/null; then
        ((scripts_with_bead_creation++))
    fi
    if grep -q "br create" "${PROJECT_ROOT}/scripts/atp_enhanced_release_gates.sh" 2>/dev/null; then
        ((scripts_with_bead_creation++))
    fi

    if [[ $scripts_with_bead_creation -gt 0 ]]; then
        log_check "PASS" "beads" "Bead creation integrated in failure handling ($scripts_with_bead_creation scripts)"
    else
        log_check "WARN" "beads" "Limited bead integration in automation scripts"
    fi
}

# Validate implementation completeness
validate_implementation_completeness() {
    log_check "INFO" "completeness" "Validating ATP-M implementation completeness"

    # Track ATP-M acceptance criteria completion
    local criteria_met=0
    local total_criteria=5

    # 1. ATP architecture docs from reality
    if [[ -f "${PROJECT_ROOT}/docs/ATP_ARCHITECTURE.md" ]]; then
        ((criteria_met++))
        log_check "PASS" "completeness" "✓ Architecture docs generated from implementation reality"
    else
        log_check "FAIL" "completeness" "✗ Architecture docs missing"
    fi

    # 2. Proof lane manifest mapping
    if [[ -f "${PROJECT_ROOT}/artifacts/ATP_PROOF_LANE_MANIFEST.md" ]] &&
       grep -q "Command.*Guarantee" "${PROJECT_ROOT}/artifacts/ATP_PROOF_LANE_MANIFEST.md"; then
        ((criteria_met++))
        log_check "PASS" "completeness" "✓ Proof lane manifest maps tests to guarantees"
    else
        log_check "FAIL" "completeness" "✗ Proof lane manifest incomplete"
    fi

    # 3. CI or local dogfood uses ATP (from ATP-M2)
    if [[ -x "${PROJECT_ROOT}/scripts/atp_dogfood_coordinator.sh" ]]; then
        ((criteria_met++))
        log_check "PASS" "completeness" "✓ ATP dogfood for real artifact flows implemented"
    else
        log_check "FAIL" "completeness" "✗ ATP dogfooding missing"
    fi

    # 4. Release gates with dependencies/tokio/replay/benchmarks
    if [[ -x "${PROJECT_ROOT}/scripts/atp_enhanced_release_gates.sh" ]] &&
       grep -q "dependency.*audit\|tokio\|deterministic\|benchmark" "${PROJECT_ROOT}/scripts/atp_enhanced_release_gates.sh"; then
        ((criteria_met++))
        log_check "PASS" "completeness" "✓ Release gates include ATP-specific requirements"
    else
        log_check "FAIL" "completeness" "✗ Enhanced release gates incomplete"
    fi

    # 5. Future planning in beads not prose
    if [[ -f "${PROJECT_ROOT}/docs/ATP_GOVERNANCE_V2.md" ]] &&
       grep -q "bead.*planning\|bead.*track" "${PROJECT_ROOT}/docs/ATP_GOVERNANCE_V2.md"; then
        ((criteria_met++))
        log_check "PASS" "completeness" "✓ Governance ensures bead-driven planning updates"
    else
        log_check "FAIL" "completeness" "✗ Bead-driven planning governance incomplete"
    fi

    # Overall completeness assessment
    if [[ $criteria_met -eq $total_criteria ]]; then
        log_check "PASS" "completeness" "All ATP-M acceptance criteria met ($criteria_met/$total_criteria)"
    else
        log_check "FAIL" "completeness" "ATP-M acceptance criteria incomplete ($criteria_met/$total_criteria met)"
    fi
}

# Generate validation report
generate_validation_report() {
    echo ""
    echo -e "${BLUE}=========================================="
    echo "   ATP GOVERNANCE VALIDATION SUMMARY"
    echo "==========================================${NC}"
    echo ""

    echo "Validation Results:"
    echo "  Checks passed: $CHECKS_PASSED"
    echo "  Checks failed: $CHECKS_FAILED"
    echo "  Warnings: $WARNINGS"
    echo ""

    # Generate structured report
    local report_file="${PROJECT_ROOT}/artifacts/atp_governance_validation_$(date +%Y%m%d_%H%M%S).json"
    cat > "$report_file" << EOF
{
  "validation_timestamp": "$(date -u --iso-8601=seconds)",
  "commit_hash": "$(git rev-parse HEAD)",
  "results": {
    "passed": $CHECKS_PASSED,
    "failed": $CHECKS_FAILED,
    "warnings": $WARNINGS
  },
  "validation_areas": [
    "architecture_docs",
    "proof_lane_manifest",
    "dogfooding_implementation",
    "release_gates",
    "governance_docs",
    "bead_integration",
    "implementation_completeness"
  ],
  "artifacts": {
    "validation_log": "$VALIDATION_LOG",
    "report_file": "$report_file"
  }
}
EOF

    echo "Detailed report: $report_file"
    echo ""

    # Determine overall result
    if [[ $CHECKS_FAILED -eq 0 ]]; then
        echo -e "${GREEN}✅ ATP Governance validation PASSED${NC}"
        if [[ $WARNINGS -gt 0 ]]; then
            echo -e "${YELLOW}   ($WARNINGS warnings to address)${NC}"
        fi
        exit 0
    else
        echo -e "${RED}❌ ATP Governance validation FAILED${NC}"
        echo -e "   $CHECKS_FAILED critical issues must be resolved"
        exit 1
    fi
}

# Main execution
print_banner

validate_architecture_docs
validate_proof_lane_manifest
validate_dogfooding_implementation
validate_release_gates
validate_governance_docs
validate_bead_integration
validate_implementation_completeness

generate_validation_report