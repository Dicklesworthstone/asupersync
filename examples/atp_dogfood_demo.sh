#!/bin/bash
# ATP-M2: Dogfooding Demo Script
#
# This script demonstrates ATP dogfooding for real Asupersync artifacts.
# It shows a complete workflow from build to archival using ATP.

set -euo pipefail

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$DEMO_DIR")"
DEMO_SESSION="demo_$(date +%Y%m%d_%H%M%S)"

# Color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_demo() {
    echo -e "${CYAN}[DEMO]${NC} $1"
}

print_banner() {
    echo -e "${CYAN}"
    echo "=========================================="
    echo "    ATP Dogfooding Demo"
    echo "=========================================="
    echo -e "${NC}"
    echo "This demo shows how ATP can be used for"
    echo "real Asupersync artifact management."
    echo ""
    echo "Demo session: $DEMO_SESSION"
    echo ""
}

# Check if ATP dogfooding is set up
check_demo_prerequisites() {
    log_demo "Checking demo prerequisites..."

    if [[ ! -x "${PROJECT_ROOT}/scripts/atp_dogfood_coordinator.sh" ]]; then
        echo "❌ ATP dogfood coordinator not found"
        echo "   Expected: ${PROJECT_ROOT}/scripts/atp_dogfood_coordinator.sh"
        exit 1
    fi

    if [[ ! -x "${PROJECT_ROOT}/scripts/ci/atp_dogfood_ci_integration.sh" ]]; then
        echo "❌ CI integration script not found"
        exit 1
    fi

    echo "✅ ATP dogfooding scripts are available"
    echo ""
}

# Demo 1: Basic dogfooding workflow
demo_basic_workflow() {
    log_demo "Demo 1: Basic dogfooding workflow"
    echo ""

    echo -e "${YELLOW}This demo shows the dogfood coordinator in dry-run mode:${NC}"
    echo ""

    # Show dry run for each workflow type
    for workflow in build-artifacts test-results fuzz-corpora proof-bundles; do
        echo -e "${BLUE}➤ $workflow workflow:${NC}"
        "${PROJECT_ROOT}/scripts/atp_dogfood_coordinator.sh" \
            --dry-run \
            --peer-id "demo-peer" \
            --relay "demo.example.com:8080" \
            "$workflow" | head -5
        echo ""
    done
}

# Demo 2: CI integration workflow
demo_ci_integration() {
    log_demo "Demo 2: CI integration workflow"
    echo ""

    echo -e "${YELLOW}This demo shows how CI systems can use ATP:${NC}"
    echo ""

    # Show CI integration check
    echo -e "${BLUE}➤ Checking ATP availability for CI:${NC}"
    export ATP_DOGFOOD_ENABLED=false
    "${PROJECT_ROOT}/scripts/ci/atp_dogfood_ci_integration.sh" check || true
    echo ""

    # Show what CI would do if ATP was enabled
    echo -e "${BLUE}➤ CI workflow with ATP enabled:${NC}"
    export ATP_DOGFOOD_ENABLED=true
    export ATP_DOGFOOD_CI_MODE=optional
    export CI_RUN_ID="demo_ci_${DEMO_SESSION}"

    echo "Environment configured:"
    echo "  ATP_DOGFOOD_ENABLED=$ATP_DOGFOOD_ENABLED"
    echo "  ATP_DOGFOOD_CI_MODE=$ATP_DOGFOOD_CI_MODE"
    echo "  CI_RUN_ID=$CI_RUN_ID"
    echo ""

    echo "CI commands that would use ATP:"
    echo "  post-build   - Transfer build artifacts via ATP"
    echo "  post-test    - Transfer test results via ATP"
    echo "  post-coverage - Transfer coverage reports via ATP"
    echo "  post-fuzz    - Synchronize fuzz corpora via ATP"
    echo ""
}

# Demo 3: Show generated artifacts structure
demo_artifacts_structure() {
    log_demo "Demo 3: Generated artifacts and proof structure"
    echo ""

    echo -e "${YELLOW}When ATP dogfooding runs, it generates:${NC}"
    echo ""

    echo -e "${BLUE}➤ Session logs:${NC}"
    echo "  artifacts/atp_dogfood_YYYYMMDD_HHMMSS.log      (human-readable)"
    echo "  artifacts/atp_dogfood_YYYYMMDD_HHMMSS.log.jsonl (structured)"
    echo ""

    echo -e "${BLUE}➤ Proof artifacts:${NC}"
    echo "  artifacts/build_transfer_proof_SESSION_ID.json"
    echo "  artifacts/test_transfer_proof_SESSION_ID.json"
    echo "  artifacts/fuzz_sync_proof_SESSION_ID.json"
    echo "  artifacts/proof_archive_SESSION_ID.json"
    echo ""

    echo -e "${BLUE}➤ Replay artifacts:${NC}"
    echo "  artifacts/build_replay_SESSION_ID.jsonl"
    echo "  artifacts/test_replay_SESSION_ID.jsonl"
    echo ""

    echo -e "${BLUE}➤ Example proof structure:${NC}"
    cat << 'EOF'
{
  "proof_version": "1.0",
  "session_id": "20260525_143022_hostname_12345",
  "timestamp": "2026-05-25T14:30:22Z",
  "component": "build-artifacts",
  "transfer_manifest": {
    "total_size": 15728640,
    "chunks": 15,
    "compression_ratio": 0.73
  },
  "integrity_verification": {
    "hash_algorithm": "blake3",
    "content_hash": "blake3:abc123...",
    "verification_status": "verified"
  },
  "performance_metrics": {
    "transfer_duration_ms": 2340,
    "throughput_mbps": 53.7
  }
}
EOF
    echo ""
}

# Demo 4: Show failure handling
demo_failure_handling() {
    log_demo "Demo 4: Failure handling and bead creation"
    echo ""

    echo -e "${YELLOW}When ATP transfers fail, dogfooding:${NC}"
    echo ""

    echo -e "${BLUE}➤ Creates detailed failure beads:${NC}"
    cat << 'EOF'
Title: ATP Dogfood Failure: ATP transfer failed
Type: bug
Priority: 2
Labels: atp-dml,dogfood,build-artifacts

# Failure Summary
- Component: build-artifacts
- Session ID: 20260525_143022_hostname_12345
- Details: Exit code: 1, Duration: 45s, Bundle size: 15728640 bytes

# Proof Context
- Log file: artifacts/atp_dogfood_20260525_143022.log
- Session artifacts: artifacts/*_20260525_143022_hostname_12345.*

# Investigation Steps
1. Check ATP daemon status
2. Verify network connectivity
3. Review proof artifacts
EOF
    echo ""

    echo -e "${BLUE}➤ Provides structured failure logs:${NC}"
    cat << 'EOF'
{"timestamp":"2026-05-25T14:30:22Z","level":"FAILURE","component":"build","message":"ATP transfer failed after 45s (exit code: 1)"}
{"timestamp":"2026-05-25T14:30:22Z","level":"INFO","component":"bead","message":"Created bead asupersync-abc123 for build failure"}
EOF
    echo ""
}

# Demo 5: Real usage patterns
demo_usage_patterns() {
    log_demo "Demo 5: Real-world usage patterns"
    echo ""

    echo -e "${YELLOW}How developers would use ATP dogfooding:${NC}"
    echo ""

    echo -e "${BLUE}➤ Local development:${NC}"
    echo "  # Test dogfooding before committing"
    echo "  scripts/atp_dogfood_coordinator.sh --dry-run build-artifacts"
    echo "  scripts/atp_dogfood_coordinator.sh build-artifacts"
    echo ""

    echo -e "${BLUE}➤ CI/CD integration:${NC}"
    echo "  # In GitHub Actions / CI system"
    echo "  export ATP_DOGFOOD_ENABLED=true"
    echo "  export ATP_DOGFOOD_CI_MODE=optional"
    echo "  scripts/ci/atp_dogfood_ci_integration.sh post-build"
    echo ""

    echo -e "${BLUE}➤ Release workflows:${NC}"
    echo "  # Full dogfood validation before release"
    echo "  scripts/atp_dogfood_coordinator.sh full"
    echo "  scripts/atp_dogfood_coordinator.sh status"
    echo ""

    echo -e "${BLUE}➤ Debugging failed transfers:${NC}"
    echo "  # Investigate transfer failures"
    echo "  grep 'SESSION_ID' artifacts/atp_dogfood_*.log"
    echo "  jq '.level == \"FAILURE\"' artifacts/*.log.jsonl"
    echo ""
}

# Demo 6: Show help and options
demo_help_and_options() {
    log_demo "Demo 6: Available commands and options"
    echo ""

    echo -e "${BLUE}➤ Dogfood coordinator help:${NC}"
    "${PROJECT_ROOT}/scripts/atp_dogfood_coordinator.sh" --help | head -15
    echo "  ... (use --help for full options)"
    echo ""

    echo -e "${BLUE}➤ CI integration help:${NC}"
    "${PROJECT_ROOT}/scripts/ci/atp_dogfood_ci_integration.sh" help | head -10
    echo "  ... (use 'help' for full commands)"
    echo ""
}

# Main demo flow
main() {
    print_banner
    check_demo_prerequisites

    demo_basic_workflow
    read -p "Press Enter to continue to CI integration demo..."
    echo ""

    demo_ci_integration
    read -p "Press Enter to continue to artifacts structure demo..."
    echo ""

    demo_artifacts_structure
    read -p "Press Enter to continue to failure handling demo..."
    echo ""

    demo_failure_handling
    read -p "Press Enter to continue to usage patterns demo..."
    echo ""

    demo_usage_patterns
    read -p "Press Enter to see help and options..."
    echo ""

    demo_help_and_options

    echo ""
    log_demo "Demo complete! 🎉"
    echo ""
    echo -e "${GREEN}Next steps:${NC}"
    echo "1. Read docs/ATP_DOGFOODING.md for full documentation"
    echo "2. Try: scripts/atp_dogfood_coordinator.sh --dry-run build-artifacts"
    echo "3. Enable in CI: export ATP_DOGFOOD_ENABLED=true"
    echo "4. Run integration tests: cargo test atp_dogfood_integration"
    echo ""
}

# Handle script arguments
case "${1:-run}" in
    --help|-h|help)
        cat << 'HELP'
ATP Dogfooding Demo Script

Usage: examples/atp_dogfood_demo.sh [command]

Commands:
  run       Run the full interactive demo (default)
  quick     Run a non-interactive quick demo
  help      Show this help

This script demonstrates ATP dogfooding capabilities without
actually executing transfers (uses dry-run mode).
HELP
        ;;
    quick)
        print_banner
        check_demo_prerequisites
        demo_basic_workflow
        echo ""
        log_demo "Quick demo complete! Use 'run' for the full interactive demo."
        ;;
    run|*)
        main
        ;;
esac