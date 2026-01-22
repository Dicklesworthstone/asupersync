#!/usr/bin/env bash
# E2E Test Script Template for Asupersync
#
# This script provides a template for running comprehensive E2E tests
# with detailed logging and failure detection.
#
# Usage:
#   ./scripts/e2e_test_template.sh [test_pattern]
#
# Environment Variables:
#   TEST_LOG_LEVEL - Logging verbosity (error, warn, info, debug, trace)
#   RUST_LOG - Standard Rust logging level
#   RUST_BACKTRACE - Enable backtraces (1 = enabled)

set -euo pipefail

# Configuration
TEST_PATTERN="${1:-e2e_}"
OUTPUT_DIR="target/e2e-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$OUTPUT_DIR/e2e_${TIMESTAMP}.log"

# Set default environment
export TEST_LOG_LEVEL="${TEST_LOG_LEVEL:-trace}"
export RUST_LOG="${RUST_LOG:-debug}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo "==================================================================="
echo "             Asupersync E2E Test Suite                            "
echo "==================================================================="
echo ""
echo "Configuration:"
echo "  Test pattern:    $TEST_PATTERN"
echo "  Log level:       $TEST_LOG_LEVEL"
echo "  Output:          $LOG_FILE"
echo ""

# Run tests with timeout and capture output
run_e2e_tests() {
    echo ">>> Starting E2E tests..."

    if timeout 300 cargo test "$TEST_PATTERN" \
        --features test-internals \
        -- --nocapture --test-threads=1 2>&1 | tee "$LOG_FILE"; then
        return 0
    else
        return 1
    fi
}

# Check for common failure patterns
check_failure_patterns() {
    local log_file="$1"
    local failures=0

    echo ""
    echo ">>> Checking for failure patterns..."

    # Check for busy loops
    if grep -q "Busy loop detected" "$log_file" 2>/dev/null; then
        echo "  ERROR: Busy loops detected!"
        ((failures++))
    fi

    # Check for leaked tasks
    if grep -q "Task leak detected" "$log_file" 2>/dev/null; then
        echo "  ERROR: Leaked tasks detected!"
        ((failures++))
    fi

    # Check for leaked registrations
    if grep -q "leaked registration" "$log_file" 2>/dev/null; then
        echo "  ERROR: Leaked I/O registrations detected!"
        ((failures++))
    fi

    # Check for panics
    if grep -q "panicked at" "$log_file" 2>/dev/null; then
        echo "  ERROR: Panics detected!"
        ((failures++))
    fi

    # Check for assertion failures
    if grep -q "assertion failed" "$log_file" 2>/dev/null; then
        echo "  ERROR: Assertion failures detected!"
        ((failures++))
    fi

    return $failures
}

# Print test summary
print_summary() {
    local test_result=$1
    local pattern_result=$2

    echo ""
    echo "==================================================================="
    echo "                       E2E TEST SUMMARY                           "
    echo "==================================================================="

    if [ "$test_result" -eq 0 ] && [ "$pattern_result" -eq 0 ]; then
        echo "  Status: PASSED"
        echo ""
        echo "  All E2E tests completed successfully!"
    else
        echo "  Status: FAILED"
        echo ""
        if [ "$test_result" -ne 0 ]; then
            echo "  - Test execution failed"
        fi
        if [ "$pattern_result" -ne 0 ]; then
            echo "  - Failure patterns detected in output"
        fi
        echo ""
        echo "  See $LOG_FILE for details"
    fi

    echo "==================================================================="
}

# Main execution
TEST_RESULT=0
run_e2e_tests || TEST_RESULT=$?

PATTERN_RESULT=0
check_failure_patterns "$LOG_FILE" || PATTERN_RESULT=$?

print_summary $TEST_RESULT $PATTERN_RESULT

# Exit with appropriate code
if [ "$TEST_RESULT" -ne 0 ] || [ "$PATTERN_RESULT" -ne 0 ]; then
    exit 1
fi

echo ""
echo "All E2E tests passed!"
