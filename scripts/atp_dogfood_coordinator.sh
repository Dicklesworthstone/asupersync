#!/bin/bash
# ATP-M2: Dogfood ATP for Asupersync artifacts and workflows
#
# This script coordinates ATP dogfooding by using ATP to transfer real
# Asupersync artifacts instead of traditional file movement. Generates
# proof and replay artifacts for all transfers.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DOGFOOD_LOG="${PROJECT_ROOT}/artifacts/atp_dogfood_$(date +%Y%m%d_%H%M%S).log"
DOGFOOD_SESSION_ID="$(date +%Y%m%d_%H%M%S)_$(hostname)_$$"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Dogfood tracking
TRANSFERS_ATTEMPTED=0
TRANSFERS_SUCCESSFUL=0
TRANSFERS_FAILED=0
BEADS_CREATED=0

# Configuration
TARGET_DIR="${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_atp_dogfood}"
ATP_PEER_ID="${ATP_DOGFOOD_PEER_ID:-dogfood-$(hostname)}"
ATP_RELAY_ENDPOINT="${ATP_DOGFOOD_RELAY:-127.0.0.1:8080}"
ATP_PROOF_LEVEL="${ATP_DOGFOOD_PROOF_LEVEL:-full}"
ENABLE_BEAD_CREATION="${ATP_DOGFOOD_CREATE_BEADS:-true}"

usage() {
    cat <<'USAGE'
Usage: scripts/atp_dogfood_coordinator.sh [options] <mode>

Modes:
  build-artifacts     Transfer build outputs using ATP
  test-results       Transfer test results and coverage reports
  fuzz-corpora       Synchronize fuzz corpora via ATP
  proof-bundles      Archive proof bundles through ATP
  release-assets     Distribute release assets with ATP
  full               Run all dogfood workflows
  status             Check dogfood transfer status

Options:
  --target-dir <dir>     Cargo target directory
  --peer-id <id>         ATP peer identifier
  --relay <endpoint>     ATP relay endpoint
  --proof-level <level>  Proof level: minimal, standard, full
  --no-beads            Don't create beads for failures
  --dry-run             Show planned operations without executing
  -h, --help            Show this help

Environment Variables:
  ATP_DOGFOOD_PEER_ID       Default peer ID
  ATP_DOGFOOD_RELAY         Default relay endpoint
  ATP_DOGFOOD_PROOF_LEVEL   Default proof level
  ATP_DOGFOOD_CREATE_BEADS  Create beads for failures (true/false)
USAGE
}

log_dogfood() {
    local level="$1"
    local component="$2"
    local message="$3"

    local timestamp=$(date -u '+%Y-%m-%d %H:%M:%S UTC')

    case "$level" in
        SUCCESS)
            echo -e "${GREEN}[SUCCESS]${NC} $component: $message" | tee -a "$DOGFOOD_LOG"
            ;;
        FAILURE)
            echo -e "${RED}[FAILURE]${NC} $component: $message" | tee -a "$DOGFOOD_LOG"
            ;;
        WARNING)
            echo -e "${YELLOW}[WARNING]${NC} $component: $message" | tee -a "$DOGFOOD_LOG"
            ;;
        INFO)
            echo -e "${BLUE}[INFO]${NC} $component: $message" | tee -a "$DOGFOOD_LOG"
            ;;
    esac

    # Structured log entry
    printf '{"timestamp":"%s","level":"%s","component":"%s","message":"%s","session_id":"%s"}\n' \
        "$timestamp" "$level" "$component" "$message" "$DOGFOOD_SESSION_ID" >> "$DOGFOOD_LOG.jsonl"
}

print_banner() {
    echo -e "${CYAN}"
    echo "=========================================="
    echo "    ATP-M2 Dogfood Coordinator"
    echo "=========================================="
    echo -e "${NC}"
    echo "Session ID: $DOGFOOD_SESSION_ID"
    echo "Log file: $DOGFOOD_LOG"
    echo "Peer ID: $ATP_PEER_ID"
    echo "Relay: $ATP_RELAY_ENDPOINT"
    echo "Proof level: $ATP_PROOF_LEVEL"
    echo ""
}

# Check prerequisites for ATP dogfooding
check_prerequisites() {
    log_dogfood "INFO" "prereq" "Checking ATP dogfood prerequisites"

    # Check ATP CLI is available
    if ! command -v atp >/dev/null 2>&1; then
        log_dogfood "FAILURE" "prereq" "ATP CLI not found in PATH"
        return 1
    fi

    # Check atpd daemon if using daemon mode
    if ! pgrep -f atpd >/dev/null 2>&1; then
        log_dogfood "WARNING" "prereq" "atpd daemon not running - transfers will use direct mode"
    fi

    # Check artifacts directory exists
    if [[ ! -d "$PROJECT_ROOT/artifacts" ]]; then
        log_dogfood "FAILURE" "prereq" "Artifacts directory not found"
        return 1
    fi

    # Check rch is available for builds
    if ! command -v rch >/dev/null 2>&1; then
        log_dogfood "WARNING" "prereq" "RCH not found - falling back to local builds"
    fi

    log_dogfood "SUCCESS" "prereq" "Prerequisites check passed"
    return 0
}

# Transfer build artifacts using ATP
dogfood_build_artifacts() {
    log_dogfood "INFO" "build" "Starting build artifacts dogfood transfer"
    ((TRANSFERS_ATTEMPTED++))

    # Build project to generate artifacts
    local build_start=$(date +%s)
    if ! rch exec -- env "CARGO_TARGET_DIR=${TARGET_DIR}" cargo build --release --all-targets 2>/dev/null; then
        log_dogfood "FAILURE" "build" "Failed to build project for artifact generation"
        ((TRANSFERS_FAILED++))
        return 1
    fi
    local build_end=$(date +%s)
    local build_duration=$((build_end - build_start))

    # Package build artifacts
    local artifact_bundle="${PROJECT_ROOT}/artifacts/build_artifacts_${DOGFOOD_SESSION_ID}.tar.gz"
    tar -czf "$artifact_bundle" \
        -C "$TARGET_DIR" \
        --exclude="incremental" \
        --exclude=".fingerprint" \
        release/

    local bundle_size=$(stat -f%z "$artifact_bundle" 2>/dev/null || stat -c%s "$artifact_bundle")
    log_dogfood "INFO" "build" "Created artifact bundle: $(basename $artifact_bundle) (${bundle_size} bytes)"

    # Transfer via ATP with proof generation
    local transfer_start=$(date +%s)
    local atp_result
    if atp send "$artifact_bundle" \
        --peer "$ATP_PEER_ID" \
        --relay "$ATP_RELAY_ENDPOINT" \
        --proof-level "$ATP_PROOF_LEVEL" \
        --metadata "source=build_artifacts,session=$DOGFOOD_SESSION_ID,build_duration=$build_duration" \
        --tags "dogfood,build-artifacts,release" \
        --output-format json > "${PROJECT_ROOT}/artifacts/build_transfer_proof_${DOGFOOD_SESSION_ID}.json"; then

        local transfer_end=$(date +%s)
        local transfer_duration=$((transfer_end - transfer_start))

        log_dogfood "SUCCESS" "build" "ATP transfer completed in ${transfer_duration}s with proof"
        ((TRANSFERS_SUCCESSFUL++))

        # Generate replay artifacts
        atp replay "${PROJECT_ROOT}/artifacts/build_transfer_proof_${DOGFOOD_SESSION_ID}.json" \
            --output "${PROJECT_ROOT}/artifacts/build_replay_${DOGFOOD_SESSION_ID}.jsonl" \
            --format structured

        return 0
    else
        atp_result=$?
        local transfer_end=$(date +%s)
        local transfer_duration=$((transfer_end - transfer_start))

        log_dogfood "FAILURE" "build" "ATP transfer failed after ${transfer_duration}s (exit code: $atp_result)"
        ((TRANSFERS_FAILED++))

        # Create bead for failure if enabled
        if [[ "$ENABLE_BEAD_CREATION" == "true" ]]; then
            create_failure_bead "build-artifacts" "ATP transfer failed" \
                "Exit code: $atp_result, Duration: ${transfer_duration}s, Bundle size: ${bundle_size} bytes"
        fi

        return 1
    fi
}

# Transfer test results using ATP
dogfood_test_results() {
    log_dogfood "INFO" "test" "Starting test results dogfood transfer"
    ((TRANSFERS_ATTEMPTED++))

    # Run tests to generate results
    local test_start=$(date +%s)
    local test_output_dir="${PROJECT_ROOT}/target/test_results_${DOGFOOD_SESSION_ID}"
    mkdir -p "$test_output_dir"

    if ! rch exec -- env "CARGO_TARGET_DIR=${TARGET_DIR}" \
        cargo test --all-targets -- --format=json > "${test_output_dir}/test_results.json" 2>&1; then
        log_dogfood "FAILURE" "test" "Test execution failed"
        ((TRANSFERS_FAILED++))
        return 1
    fi
    local test_end=$(date +%s)
    local test_duration=$((test_end - test_start))

    # Package test results
    local results_bundle="${PROJECT_ROOT}/artifacts/test_results_${DOGFOOD_SESSION_ID}.tar.gz"
    tar -czf "$results_bundle" -C "$(dirname $test_output_dir)" "$(basename $test_output_dir)"

    local bundle_size=$(stat -f%z "$results_bundle" 2>/dev/null || stat -c%s "$results_bundle")

    # Transfer via ATP
    if atp send "$results_bundle" \
        --peer "$ATP_PEER_ID" \
        --relay "$ATP_RELAY_ENDPOINT" \
        --proof-level "$ATP_PROOF_LEVEL" \
        --metadata "source=test_results,session=$DOGFOOD_SESSION_ID,test_duration=$test_duration" \
        --tags "dogfood,test-results,ci" \
        --output-format json > "${PROJECT_ROOT}/artifacts/test_transfer_proof_${DOGFOOD_SESSION_ID}.json"; then

        log_dogfood "SUCCESS" "test" "Test results transferred via ATP with proof"
        ((TRANSFERS_SUCCESSFUL++))
        return 0
    else
        log_dogfood "FAILURE" "test" "ATP transfer of test results failed"
        ((TRANSFERS_FAILED++))

        if [[ "$ENABLE_BEAD_CREATION" == "true" ]]; then
            create_failure_bead "test-results" "ATP test results transfer failed" \
                "Test duration: ${test_duration}s, Bundle size: ${bundle_size} bytes"
        fi

        return 1
    fi
}

# Synchronize fuzz corpora using ATP
dogfood_fuzz_corpora() {
    log_dogfood "INFO" "fuzz" "Starting fuzz corpora dogfood sync"
    ((TRANSFERS_ATTEMPTED++))

    local fuzz_dir="${PROJECT_ROOT}/fuzz"
    if [[ ! -d "$fuzz_dir" ]]; then
        log_dogfood "WARNING" "fuzz" "No fuzz directory found, skipping"
        return 0
    fi

    # Find fuzz corpora
    local corpus_dirs=()
    while IFS= read -r -d '' dir; do
        corpus_dirs+=("$dir")
    done < <(find "$fuzz_dir" -name "corpus" -type d -print0)

    if [[ ${#corpus_dirs[@]} -eq 0 ]]; then
        log_dogfood "WARNING" "fuzz" "No fuzz corpora found"
        return 0
    fi

    # Package corpora
    local corpus_bundle="${PROJECT_ROOT}/artifacts/fuzz_corpora_${DOGFOOD_SESSION_ID}.tar.gz"
    tar -czf "$corpus_bundle" -C "$PROJECT_ROOT" "${corpus_dirs[@]#$PROJECT_ROOT/}"

    local bundle_size=$(stat -f%z "$corpus_bundle" 2>/dev/null || stat -c%s "$corpus_bundle")
    local corpus_count=${#corpus_dirs[@]}

    # Sync via ATP fuzz workflow
    if atp fuzz sync "$corpus_bundle" \
        --target "asupersync-dogfood" \
        --strategy "bidirectional" \
        --metadata "session=$DOGFOOD_SESSION_ID,corpus_count=$corpus_count" \
        --output-format json > "${PROJECT_ROOT}/artifacts/fuzz_sync_proof_${DOGFOOD_SESSION_ID}.json"; then

        log_dogfood "SUCCESS" "fuzz" "Fuzz corpora synced via ATP ($corpus_count corpora)"
        ((TRANSFERS_SUCCESSFUL++))
        return 0
    else
        log_dogfood "FAILURE" "fuzz" "ATP fuzz sync failed"
        ((TRANSFERS_FAILED++))

        if [[ "$ENABLE_BEAD_CREATION" == "true" ]]; then
            create_failure_bead "fuzz-corpora" "ATP fuzz corpus sync failed" \
                "Corpus count: $corpus_count, Bundle size: ${bundle_size} bytes"
        fi

        return 1
    fi
}

# Archive proof bundles using ATP
dogfood_proof_bundles() {
    log_dogfood "INFO" "proof" "Starting proof bundle dogfood archival"
    ((TRANSFERS_ATTEMPTED++))

    # Find existing proof artifacts
    local proof_files=()
    while IFS= read -r -d '' file; do
        proof_files+=("$file")
    done < <(find "$PROJECT_ROOT/artifacts" -name "*proof*" -name "*.json" -print0)

    if [[ ${#proof_files[@]} -eq 0 ]]; then
        log_dogfood "WARNING" "proof" "No proof artifacts found"
        return 0
    fi

    # Package proof bundles
    local proof_bundle="${PROJECT_ROOT}/artifacts/proof_bundle_${DOGFOOD_SESSION_ID}.tar.gz"
    tar -czf "$proof_bundle" "${proof_files[@]}"

    local bundle_size=$(stat -f%z "$proof_bundle" 2>/dev/null || stat -c%s "$proof_bundle")
    local proof_count=${#proof_files[@]}

    # Archive via ATP
    if atp archive store "$proof_bundle" \
        --compression-level 9 \
        --retention "30d" \
        --metadata "session=$DOGFOOD_SESSION_ID,proof_count=$proof_count" \
        --tags "dogfood,proof-bundles,archive" \
        --verify \
        --output-format json > "${PROJECT_ROOT}/artifacts/proof_archive_${DOGFOOD_SESSION_ID}.json"; then

        log_dogfood "SUCCESS" "proof" "Proof bundles archived via ATP ($proof_count files)"
        ((TRANSFERS_SUCCESSFUL++))
        return 0
    else
        log_dogfood "FAILURE" "proof" "ATP proof bundle archival failed"
        ((TRANSFERS_FAILED++))

        if [[ "$ENABLE_BEAD_CREATION" == "true" ]]; then
            create_failure_bead "proof-bundles" "ATP proof bundle archival failed" \
                "Proof count: $proof_count, Bundle size: ${bundle_size} bytes"
        fi

        return 1
    fi
}

# Create bead for dogfood failure with exact proof context
create_failure_bead() {
    local component="$1"
    local title="$2"
    local details="$3"

    local bead_id
    if bead_id=$(br create \
        --title "ATP Dogfood Failure: $title" \
        --type bug \
        --priority 2 \
        --labels "atp-dml,dogfood,$component" \
        --assignee ubuntu 2>/dev/null); then

        # Add detailed description with proof context
        cat > "/tmp/dogfood_failure_${DOGFOOD_SESSION_ID}.md" <<EOF
# ATP Dogfood Failure Report

## Failure Summary
- **Component**: $component
- **Session ID**: $DOGFOOD_SESSION_ID
- **Timestamp**: $(date -u '+%Y-%m-%d %H:%M:%S UTC')
- **Details**: $details

## Proof Context
- **Log file**: $DOGFOOD_LOG
- **Structured log**: $DOGFOOD_LOG.jsonl
- **Session artifacts**: artifacts/*_${DOGFOOD_SESSION_ID}.*

## Environment
- **ATP Peer ID**: $ATP_PEER_ID
- **ATP Relay**: $ATP_RELAY_ENDPOINT
- **Proof Level**: $ATP_PROOF_LEVEL
- **Target Dir**: $TARGET_DIR

## Reproduction
\`\`\`bash
# Run specific dogfood component
scripts/atp_dogfood_coordinator.sh $component

# Check logs for this session
grep "$DOGFOOD_SESSION_ID" $DOGFOOD_LOG
\`\`\`

## Investigation Steps
1. Check ATP daemon status: \`systemctl status atpd\`
2. Verify network connectivity to relay
3. Check disk space and permissions
4. Review proof artifacts for this session
EOF

        br update "$bead_id" --description "$(cat /tmp/dogfood_failure_${DOGFOOD_SESSION_ID}.md)"
        rm -f "/tmp/dogfood_failure_${DOGFOOD_SESSION_ID}.md"

        log_dogfood "INFO" "bead" "Created bead $bead_id for $component failure"
        ((BEADS_CREATED++))
    else
        log_dogfood "WARNING" "bead" "Failed to create bead for $component failure"
    fi
}

# Print final status report
print_status_report() {
    echo ""
    echo -e "${CYAN}=========================================="
    echo "       Dogfood Session Summary"
    echo "==========================================${NC}"
    echo "Session ID: $DOGFOOD_SESSION_ID"
    echo ""
    echo "Transfer Statistics:"
    echo "  Attempted: $TRANSFERS_ATTEMPTED"
    echo "  Successful: $TRANSFERS_SUCCESSFUL"
    echo "  Failed: $TRANSFERS_FAILED"
    echo ""
    echo "Issue Tracking:"
    echo "  Beads created: $BEADS_CREATED"
    echo ""
    echo "Artifacts Generated:"
    find "$PROJECT_ROOT/artifacts" -name "*_${DOGFOOD_SESSION_ID}.*" -type f | while read -r file; do
        local size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file")
        echo "  $(basename "$file") (${size} bytes)"
    done
    echo ""
    echo "Log Files:"
    echo "  Main log: $DOGFOOD_LOG"
    echo "  Structured log: $DOGFOOD_LOG.jsonl"

    # Determine exit code
    if [[ $TRANSFERS_FAILED -eq 0 ]]; then
        echo -e "${GREEN}✓ All dogfood transfers successful${NC}"
        exit 0
    else
        echo -e "${RED}✗ $TRANSFERS_FAILED dogfood transfer(s) failed${NC}"
        exit 1
    fi
}

# Parse command line arguments
DRY_RUN=false
MODE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target-dir)
            TARGET_DIR="$2"
            shift 2
            ;;
        --peer-id)
            ATP_PEER_ID="$2"
            shift 2
            ;;
        --relay)
            ATP_RELAY_ENDPOINT="$2"
            shift 2
            ;;
        --proof-level)
            ATP_PROOF_LEVEL="$2"
            shift 2
            ;;
        --no-beads)
            ENABLE_BEAD_CREATION=false
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
        *)
            if [[ -z "$MODE" ]]; then
                MODE="$1"
            else
                echo "Too many arguments" >&2
                usage >&2
                exit 2
            fi
            shift
            ;;
    esac
done

if [[ -z "$MODE" ]]; then
    echo "Mode required" >&2
    usage >&2
    exit 2
fi

# Main execution
print_banner

if [[ "$DRY_RUN" == true ]]; then
    log_dogfood "INFO" "main" "DRY RUN MODE - no actual transfers will be performed"
    echo "Would run dogfood mode: $MODE"
    echo "Configuration: peer=$ATP_PEER_ID, relay=$ATP_RELAY_ENDPOINT, proof=$ATP_PROOF_LEVEL"
    exit 0
fi

# Check prerequisites
if ! check_prerequisites; then
    log_dogfood "FAILURE" "main" "Prerequisites check failed"
    exit 1
fi

# Execute dogfood workflows based on mode
case "$MODE" in
    build-artifacts)
        dogfood_build_artifacts
        ;;
    test-results)
        dogfood_test_results
        ;;
    fuzz-corpora)
        dogfood_fuzz_corpora
        ;;
    proof-bundles)
        dogfood_proof_bundles
        ;;
    release-assets)
        log_dogfood "INFO" "release" "Release assets dogfood not yet implemented"
        ;;
    full)
        dogfood_build_artifacts || true
        dogfood_test_results || true
        dogfood_fuzz_corpora || true
        dogfood_proof_bundles || true
        ;;
    status)
        echo "Checking dogfood transfer status..."
        # Implementation would check ATP status and recent transfers
        atp status --peer "$ATP_PEER_ID" --format json || true
        ;;
    *)
        echo "Invalid mode: $MODE" >&2
        usage >&2
        exit 2
        ;;
esac

# Print final report
print_status_report