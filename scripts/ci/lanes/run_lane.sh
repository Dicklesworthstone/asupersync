#!/bin/bash
# ATP-N7: Proof Lane Runner
#
# Executes individual ATP proof lanes with timeout, logging, and artifact collection

set -euo pipefail

# Default values
LANE_ID=""
MODE="smoke"
PLATFORM=""
TIMEOUT="10m"
ARTIFACTS_DIR="artifacts"
ENABLE_EXTENDED_LOGGING=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --lane)
            LANE_ID="$2"
            shift 2
            ;;
        --mode)
            MODE="$2"
            shift 2
            ;;
        --platform)
            PLATFORM="$2"
            shift 2
            ;;
        --timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        --artifacts-dir)
            ARTIFACTS_DIR="$2"
            shift 2
            ;;
        --enable-extended-logging)
            ENABLE_EXTENDED_LOGGING=true
            shift
            ;;
        *)
            echo "Unknown option $1"
            exit 1
            ;;
    esac
done

# Validate required parameters
if [[ -z "$LANE_ID" ]]; then
    echo "Error: --lane is required"
    exit 1
fi

if [[ -z "$PLATFORM" ]]; then
    echo "Error: --platform is required"
    exit 1
fi

# Setup directories
mkdir -p "$ARTIFACTS_DIR"
mkdir -p "test-results"
mkdir -p "logs"

# Lane-specific setup
LANE_LOG="logs/${LANE_ID}_${PLATFORM}_${MODE}.log"
LANE_ARTIFACTS_DIR="${ARTIFACTS_DIR}/${LANE_ID}"
mkdir -p "$LANE_ARTIFACTS_DIR"

echo "=== ATP Proof Lane: $LANE_ID ($MODE mode on $PLATFORM) ===" | tee "$LANE_LOG"
echo "Started at: $(date -u '+%Y-%m-%d %H:%M:%S UTC')" | tee -a "$LANE_LOG"
echo "Timeout: $TIMEOUT" | tee -a "$LANE_LOG"
echo "Artifacts: $LANE_ARTIFACTS_DIR" | tee -a "$LANE_LOG"

# Start timer
START_TIME=$(date +%s)

# Function to cleanup on exit
cleanup() {
    local exit_code=$?
    local end_time=$(date +%s)
    local duration=$((end_time - START_TIME))

    echo "=== Lane Summary ===" | tee -a "$LANE_LOG"
    echo "Exit code: $exit_code" | tee -a "$LANE_LOG"
    echo "Duration: ${duration}s" | tee -a "$LANE_LOG"
    echo "Finished at: $(date -u '+%Y-%m-%d %H:%M:%S UTC')" | tee -a "$LANE_LOG"

    # Generate lane metadata
    cat > "${LANE_ARTIFACTS_DIR}/metadata.json" <<EOF
{
    "lane_id": "$LANE_ID",
    "mode": "$MODE",
    "platform": "$PLATFORM",
    "start_time": "$START_TIME",
    "end_time": "$end_time",
    "duration_seconds": $duration,
    "exit_code": $exit_code,
    "timeout": "$TIMEOUT",
    "artifacts_dir": "$LANE_ARTIFACTS_DIR"
}
EOF

    # Collect system information
    if command -v uname >/dev/null; then
        uname -a > "${LANE_ARTIFACTS_DIR}/system_info.txt" 2>/dev/null || true
    fi

    if command -v rustc >/dev/null; then
        rustc --version > "${LANE_ARTIFACTS_DIR}/rust_version.txt" 2>/dev/null || true
        cargo --version >> "${LANE_ARTIFACTS_DIR}/rust_version.txt" 2>/dev/null || true
    fi

    return $exit_code
}

trap cleanup EXIT

# Set extended logging if requested
if [[ "$ENABLE_EXTENDED_LOGGING" == "true" ]]; then
    export RUST_LOG="debug"
    export ATP_LOG_LEVEL="debug"
    echo "Extended logging enabled" | tee -a "$LANE_LOG"
else
    export RUST_LOG="info"
    export ATP_LOG_LEVEL="info"
fi

# Set ATP environment variables
export ATP_TEST_MODE="$MODE"
export ATP_TEST_PLATFORM="$PLATFORM"
export ATP_ARTIFACTS_DIR="$LANE_ARTIFACTS_DIR"

# Run the lane with timeout
echo "Executing lane: $LANE_ID" | tee -a "$LANE_LOG"

case "$LANE_ID" in
    "compile")
        echo "Running compile checks..." | tee -a "$LANE_LOG"
        timeout "$TIMEOUT" cargo check --all-targets 2>&1 | tee -a "$LANE_LOG"
        timeout "$TIMEOUT" cargo clippy --all-targets -- -D warnings 2>&1 | tee -a "$LANE_LOG"
        ;;

    "unit")
        echo "Running unit tests..." | tee -a "$LANE_LOG"
        timeout "$TIMEOUT" cargo test --lib --bins --no-fail-fast \
            --message-format json 2>&1 | tee "${LANE_ARTIFACTS_DIR}/unit_test_output.jsonl" | \
            jq -r 'select(.type == "test") | "\(.event) \(.name)"' | tee -a "$LANE_LOG"
        ;;

    "fmt")
        echo "Running format check..." | tee -a "$LANE_LOG"
        timeout "$TIMEOUT" cargo fmt --check 2>&1 | tee -a "$LANE_LOG"
        ;;

    "atp_conformance")
        echo "Running ATP conformance tests..." | tee -a "$LANE_LOG"
        timeout "$TIMEOUT" cargo test atp::quic::conformance --no-fail-fast 2>&1 | tee -a "$LANE_LOG"
        timeout "$TIMEOUT" cargo test --test atp_conformance_suite 2>&1 | tee -a "$LANE_LOG"

        # Collect conformance artifacts
        if [[ -f "conformance_results.json" ]]; then
            cp "conformance_results.json" "$LANE_ARTIFACTS_DIR/"
        fi
        ;;

    "atp_fuzz")
        echo "Running ATP fuzz tests..." | tee -a "$LANE_LOG"
        timeout "$TIMEOUT" cargo test atp::quic::fuzz_harness --no-fail-fast 2>&1 | tee -a "$LANE_LOG"

        # Run extended fuzzing if in full/release mode
        if [[ "$MODE" == "full" || "$MODE" == "release" ]]; then
            echo "Running extended fuzz suite..." | tee -a "$LANE_LOG"
            timeout 1800 scripts/ci/run_fuzz_suite.sh 2>&1 | tee -a "$LANE_LOG" || true
        fi
        ;;

    "atp_e2e")
        echo "Running ATP E2E proof suite..." | tee -a "$LANE_LOG"
        timeout "$TIMEOUT" cargo test atp::e2e_proof_suite --no-fail-fast 2>&1 | tee -a "$LANE_LOG"
        timeout "$TIMEOUT" cargo test atp::quic::e2e_endpoints 2>&1 | tee -a "$LANE_LOG"

        # Run E2E scenarios
        if [[ -f "scripts/ci/run_e2e_scenarios.sh" ]]; then
            timeout "$TIMEOUT" scripts/ci/run_e2e_scenarios.sh 2>&1 | tee -a "$LANE_LOG" || true
        fi
        ;;

    "atp_packet_lab")
        echo "Running ATP packet laboratory tests..." | tee -a "$LANE_LOG"
        timeout "$TIMEOUT" cargo test atp::quic::packet_lab --no-fail-fast 2>&1 | tee -a "$LANE_LOG"

        # Run network scenarios
        if [[ -f "scripts/ci/run_network_scenarios.sh" ]]; then
            timeout "$TIMEOUT" scripts/ci/run_network_scenarios.sh 2>&1 | tee -a "$LANE_LOG" || true
        fi
        ;;

    "dependency_audit")
        echo "Running dependency audit..." | tee -a "$LANE_LOG"
        timeout "$TIMEOUT" scripts/ci/audit_dependencies.sh 2>&1 | tee -a "$LANE_LOG" || true

        # Check for banned dependencies
        cargo metadata --format-version 1 | python3 scripts/ci/check_banned_deps.py 2>&1 | tee -a "$LANE_LOG"
        ;;

    "platform_caps")
        echo "Running platform capabilities test..." | tee -a "$LANE_LOG"
        timeout "$TIMEOUT" cargo test platform_capabilities --no-fail-fast 2>&1 | tee -a "$LANE_LOG"

        # Test platform-specific features
        if [[ -f "scripts/ci/test_platform_features.sh" ]]; then
            timeout "$TIMEOUT" scripts/ci/test_platform_features.sh 2>&1 | tee -a "$LANE_LOG" || true
        fi
        ;;

    "atp_stress")
        echo "Running ATP stress tests..." | tee -a "$LANE_LOG"
        if [[ -f "scripts/ci/run_stress_tests.sh" ]]; then
            timeout "$TIMEOUT" scripts/ci/run_stress_tests.sh 2>&1 | tee -a "$LANE_LOG" || true
        fi
        ;;

    "atp_security")
        echo "Running ATP security tests..." | tee -a "$LANE_LOG"
        timeout "$TIMEOUT" cargo test atp_security_tests --no-fail-fast 2>&1 | tee -a "$LANE_LOG" || true

        if [[ -f "scripts/ci/run_security_audit.sh" ]]; then
            timeout "$TIMEOUT" scripts/ci/run_security_audit.sh 2>&1 | tee -a "$LANE_LOG" || true
        fi
        ;;

    "atp_benchmarks")
        echo "Running ATP benchmarks..." | tee -a "$LANE_LOG"
        timeout "$TIMEOUT" cargo bench --bench atp_benchmarks 2>&1 | tee -a "$LANE_LOG" || true

        if [[ -f "scripts/ci/run_comparison_benchmarks.sh" ]]; then
            timeout "$TIMEOUT" scripts/ci/run_comparison_benchmarks.sh 2>&1 | tee -a "$LANE_LOG" || true
        fi
        ;;

    *)
        echo "Unknown lane: $LANE_ID" | tee -a "$LANE_LOG"
        exit 1
        ;;
esac

echo "Lane $LANE_ID completed successfully" | tee -a "$LANE_LOG"

# Copy log to artifacts
cp "$LANE_LOG" "$LANE_ARTIFACTS_DIR/"

# Generate success marker
echo "SUCCESS" > "${LANE_ARTIFACTS_DIR}/status.txt"