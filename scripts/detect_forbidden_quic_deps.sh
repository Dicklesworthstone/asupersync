#!/bin/bash
# ATP Dependency Audit Gate: Detect forbidden external QUIC stacks and Tokio runtime paths
# Part of asupersync-jaghjr: ATP-M5 dependency audit gates

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Exit codes
EXIT_SUCCESS=0
EXIT_FORBIDDEN_DEPS=1
EXIT_AUDIT_FAILURE=2

# Forbidden external QUIC stack crates
FORBIDDEN_QUIC_CRATES=(
    "quinn"
    "quinn-proto"
    "quinn-udp"
    "quiche"
    "s2n-quic"
    "s2n-quic-core"
    "s2n-quic-transport"
    "h3-quinn"
    "h3-quiche"
    "msquic"
    "msquic-sys"
    "cloudflare-quic"
    "neqo-transport"
    "neqo-http3"
    "lsquic"
    "lsquic-sys"
)

# Forbidden Tokio runtime paths (for production profiles)
FORBIDDEN_TOKIO_CRATES=(
    "tokio"
    "tokio-util"
    "tokio-stream"
    "tokio-tungstenite"
    "hyper"
    "reqwest"
    "axum"
    "tower-http"
    "async-std"
    "smol"
)

# Function to check dependencies in cargo tree output
check_dependency_tree() {
    local profile="$1"
    local feature_args="$2"
    local temp_dir="${TMPDIR:-/tmp}/rch_target_quic_audit_${profile//-/_}"

    echo "Checking dependency tree for profile: $profile"
    echo "Feature args: $feature_args"

    # Get the dependency tree
    local tree_output
    if ! tree_output=$(rch exec -- env CARGO_TARGET_DIR="$temp_dir" cargo tree -e normal -p asupersync $feature_args 2>&1); then
        echo -e "${RED}ERROR: Failed to generate cargo tree for $profile${NC}" >&2
        return $EXIT_AUDIT_FAILURE
    fi

    local violations=0

    # Check for forbidden QUIC crates
    echo "  Checking for forbidden QUIC stacks..."
    for crate in "${FORBIDDEN_QUIC_CRATES[@]}"; do
        if echo "$tree_output" | grep -q "^[├└│ ]*$crate "; then
            echo -e "${RED}VIOLATION: Forbidden QUIC crate detected: $crate${NC}" >&2
            echo "  Profile: $profile" >&2
            echo "  Feature args: $feature_args" >&2
            violations=$((violations + 1))
        fi
    done

    # Check for Tokio dependencies (only for production profiles)
    if [[ "$profile" == "default-production" || "$profile" == "metrics-production" ]]; then
        echo "  Checking for forbidden Tokio runtime paths..."
        for crate in "${FORBIDDEN_TOKIO_CRATES[@]}"; do
            if echo "$tree_output" | grep -q "^[├└│ ]*$crate "; then
                echo -e "${RED}VIOLATION: Forbidden Tokio crate in production profile: $crate${NC}" >&2
                echo "  Profile: $profile" >&2
                echo "  Feature args: $feature_args" >&2
                violations=$((violations + 1))
            fi
        done
    fi

    if [[ $violations -eq 0 ]]; then
        echo -e "${GREEN}  ✓ No violations found for $profile${NC}"
    fi

    return $violations
}

# Function to audit ATP native core specifically
audit_atp_native_core() {
    echo "=== ATP Native Core Dependency Audit ==="

    local violations=0

    # Check default production (core runtime)
    check_dependency_tree "default-production" "" || violations=$((violations + $?))

    # Check metrics production
    check_dependency_tree "metrics-production" "--features metrics" || violations=$((violations + $?))

    # Check quic feature (should only use native implementation)
    check_dependency_tree "quic-native" "--features quic" || violations=$((violations + $?))

    # Check http3 feature (should only use native implementation)
    check_dependency_tree "http3-native" "--features http3" || violations=$((violations + $?))

    return $violations
}

# Function to generate audit report
generate_audit_report() {
    local violations="$1"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    cat > "artifacts/atp_quic_dependency_audit_$(date +%Y%m%d_%H%M%S).json" <<EOF
{
  "audit_version": "atp-quic-dependency-audit-v1",
  "bead_id": "asupersync-jaghjr",
  "timestamp": "$timestamp",
  "violations_found": $violations,
  "forbidden_quic_crates": [
$(printf '    "%s",\n' "${FORBIDDEN_QUIC_CRATES[@]}" | sed '$s/,$//')
  ],
  "forbidden_tokio_crates": [
$(printf '    "%s",\n' "${FORBIDDEN_TOKIO_CRATES[@]}" | sed '$s/,$//')
  ],
  "audit_status": $([ $violations -eq 0 ] && echo '"PASS"' || echo '"FAIL"'),
  "enforcement_policy": "ATP native core must not depend on external QUIC stacks or Tokio runtime in production profiles",
  "documentation": {
    "bead": "asupersync-jaghjr",
    "contract": "artifacts/atp_native_quic_endpoint_contract_v1.json",
    "proof_manifest": "artifacts/proof_lane_manifest_v1.json"
  }
}
EOF
}

# Main execution
main() {
    echo "ATP-M5: Dependency Audit Gate for External QUIC Stacks and Tokio Runtime Paths"
    echo "=================================================================="

    # Ensure we're in the right directory
    if [[ ! -f "Cargo.toml" || ! -f "artifacts/proof_lane_manifest_v1.json" ]]; then
        echo -e "${RED}ERROR: Must be run from asupersync project root${NC}" >&2
        exit $EXIT_AUDIT_FAILURE
    fi

    # Run ATP native core audit
    local total_violations=0
    audit_atp_native_core || total_violations=$?

    # Generate audit report
    generate_audit_report "$total_violations"

    # Final result
    echo "=================================================================="
    if [[ $total_violations -eq 0 ]]; then
        echo -e "${GREEN}✓ ATP Dependency Audit PASSED${NC}"
        echo "  No forbidden QUIC stacks or Tokio runtime paths detected"
        exit $EXIT_SUCCESS
    else
        echo -e "${RED}✗ ATP Dependency Audit FAILED${NC}"
        echo "  Found $total_violations dependency violations"
        echo "  ATP native core must remain self-contained"
        exit $EXIT_FORBIDDEN_DEPS
    fi
}

# Help function
show_help() {
    cat <<EOF
ATP Dependency Audit Gate - Detect forbidden external QUIC stacks and Tokio runtime paths

USAGE:
    $0 [OPTIONS]

OPTIONS:
    -h, --help          Show this help message
    --audit-only        Run audit without generating report files
    --verbose           Enable verbose output

DESCRIPTION:
    This script enforces ATP's requirement to be internally self-contained
    and not rely on external QUIC crates or Tokio runtime in production profiles.

    Forbidden QUIC stacks: quinn, quiche, s2n-quic, h3-quinn, msquic, etc.
    Forbidden Tokio paths: tokio, hyper, reqwest, axum (production only)

    The script validates the dependency tree for ATP native core profiles:
    - default-production (no features)
    - metrics-production (metrics feature)
    - quic-native (quic feature)
    - http3-native (http3 feature)

EXIT CODES:
    0 - Audit passed, no violations found
    1 - Audit failed, forbidden dependencies detected
    2 - Audit could not be completed due to errors

EXAMPLES:
    $0                  # Run full audit with report generation
    $0 --audit-only     # Run audit without generating reports
    $0 --verbose        # Run with detailed output

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        --audit-only)
            AUDIT_ONLY=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        *)
            echo -e "${RED}ERROR: Unknown option: $1${NC}" >&2
            echo "Use --help for usage information" >&2
            exit $EXIT_AUDIT_FAILURE
            ;;
    esac
done

# Run main function
main "$@"