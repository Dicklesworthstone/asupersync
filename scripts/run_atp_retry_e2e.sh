#!/bin/bash
#
# ATP-B3 E2E test script for retry scenarios
# Tests idempotency, duplicate detection, and retry bounds
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[ATP-RETRY-E2E]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[ATP-RETRY-E2E]${NC} $1"
}

error() {
    echo -e "${RED}[ATP-RETRY-E2E]${NC} $1"
}

# Test scenarios
SCENARIOS=(
    "disconnect_retry"
    "duplicate_delivery"
    "cancelled_transfer"
    "daemon_restart"
    "relay_retry"
    "mailbox_retry"
    "conflicting_commits"
)

# Default configuration
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/atp_retry_e2e}"
TEST_TIMEOUT="${TEST_TIMEOUT:-60}"
VERBOSE="${VERBOSE:-0}"

usage() {
    cat <<EOF
Usage: $0 [OPTIONS] [SCENARIO...]

Run ATP retry scenario E2E tests for idempotency and duplicate detection.

OPTIONS:
    -h, --help          Show this help
    -v, --verbose       Verbose output
    -t, --timeout SEC   Test timeout in seconds (default: 60)
    --list              List available test scenarios

SCENARIOS:
    disconnect_retry    Test retry after connection loss
    duplicate_delivery  Test duplicate message handling
    cancelled_transfer  Test retry after cancellation
    daemon_restart      Test retry after daemon restart
    relay_retry         Test relay failure retry
    mailbox_retry       Test mailbox storage retry
    conflicting_commits Test conflict resolution
    all                 Run all scenarios (default)

EXAMPLES:
    $0                              # Run all scenarios
    $0 disconnect_retry             # Run specific scenario
    $0 -v duplicate_delivery        # Run with verbose output
    $0 --list                       # List available scenarios

ENVIRONMENT:
    CARGO_TARGET_DIR    Cargo target directory
    TEST_TIMEOUT        Test timeout in seconds
    VERBOSE             Verbose output (0/1)
EOF
}

list_scenarios() {
    log "Available test scenarios:"
    for scenario in "${SCENARIOS[@]}"; do
        echo "  $scenario"
    done
}

run_scenario_test() {
    local scenario="$1"
    local test_name="atp_retry_${scenario}_e2e"

    log "Running scenario: $scenario"

    local cargo_cmd="rch exec -- env CARGO_TARGET_DIR=$CARGO_TARGET_DIR cargo test --test $test_name"

    if [[ "$VERBOSE" == "1" ]]; then
        cargo_cmd="$cargo_cmd -- --nocapture"
    fi

    if timeout "$TEST_TIMEOUT" bash -c "$cargo_cmd"; then
        log "✅ Scenario '$scenario' passed"
        return 0
    else
        local exit_code=$?
        if [[ $exit_code == 124 ]]; then
            error "❌ Scenario '$scenario' timed out after ${TEST_TIMEOUT}s"
        else
            error "❌ Scenario '$scenario' failed with exit code $exit_code"
        fi
        return 1
    fi
}

run_unit_tests() {
    log "Running ATP outcome unit tests"

    local cargo_cmd="rch exec -- env CARGO_TARGET_DIR=$CARGO_TARGET_DIR cargo test --lib net::atp::protocol::outcome"

    if [[ "$VERBOSE" == "1" ]]; then
        cargo_cmd="$cargo_cmd -- --nocapture"
    fi

    if timeout "$TEST_TIMEOUT" bash -c "$cargo_cmd"; then
        log "✅ Unit tests passed"
        return 0
    else
        local exit_code=$?
        if [[ $exit_code == 124 ]]; then
            error "❌ Unit tests timed out after ${TEST_TIMEOUT}s"
        else
            error "❌ Unit tests failed with exit code $exit_code"
        fi
        return 1
    fi
}

run_property_tests() {
    log "Running ATP idempotency property tests"

    local cargo_cmd="rch exec -- env CARGO_TARGET_DIR=$CARGO_TARGET_DIR cargo test --lib net::atp::protocol::outcome::proptest"

    if [[ "$VERBOSE" == "1" ]]; then
        cargo_cmd="$cargo_cmd -- --nocapture"
    fi

    if timeout "$TEST_TIMEOUT" bash -c "$cargo_cmd"; then
        log "✅ Property tests passed"
        return 0
    else
        local exit_code=$?
        if [[ $exit_code == 124 ]]; then
            error "❌ Property tests timed out after ${TEST_TIMEOUT}s"
        else
            error "❌ Property tests failed with exit code $exit_code"
        fi
        return 1
    fi
}

main() {
    local scenarios_to_run=()

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            -v|--verbose)
                VERBOSE=1
                shift
                ;;
            -t|--timeout)
                TEST_TIMEOUT="$2"
                shift 2
                ;;
            --list)
                list_scenarios
                exit 0
                ;;
            all)
                scenarios_to_run=("${SCENARIOS[@]}")
                shift
                ;;
            *)
                # Check if it's a valid scenario
                local valid=0
                for scenario in "${SCENARIOS[@]}"; do
                    if [[ "$1" == "$scenario" ]]; then
                        scenarios_to_run+=("$1")
                        valid=1
                        break
                    fi
                done

                if [[ $valid == 0 ]]; then
                    error "Unknown scenario: $1"
                    echo "Run '$0 --list' to see available scenarios"
                    exit 1
                fi
                shift
                ;;
        esac
    done

    # Default to all scenarios if none specified
    if [[ ${#scenarios_to_run[@]} == 0 ]]; then
        scenarios_to_run=("${SCENARIOS[@]}")
    fi

    log "Starting ATP retry scenario E2E tests"
    log "Target directory: $CARGO_TARGET_DIR"
    log "Test timeout: ${TEST_TIMEOUT}s"

    local failed_tests=()

    # Run unit tests first
    if ! run_unit_tests; then
        failed_tests+=("unit_tests")
    fi

    # Run property tests
    if ! run_property_tests; then
        failed_tests+=("property_tests")
    fi

    # Run scenario tests
    for scenario in "${scenarios_to_run[@]}"; do
        if ! run_scenario_test "$scenario"; then
            failed_tests+=("$scenario")
        fi
    done

    # Summary
    echo
    log "Test Summary"
    log "============"

    local total_tests=$((2 + ${#scenarios_to_run[@]}))  # unit + property + scenarios
    local failed_count=${#failed_tests[@]}
    local passed_count=$((total_tests - failed_count))

    log "Total tests: $total_tests"
    log "Passed: $passed_count"

    if [[ $failed_count == 0 ]]; then
        log "✅ All tests passed!"
        exit 0
    else
        log "❌ Failed: $failed_count"
        for test in "${failed_tests[@]}"; do
            error "  - $test"
        done
        exit 1
    fi
}

main "$@"