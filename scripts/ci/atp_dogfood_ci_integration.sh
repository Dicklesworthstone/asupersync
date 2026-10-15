#!/bin/bash
# ATP-M2: CI Integration for ATP Dogfooding
#
# This script demonstrates how CI/release pipelines can optionally use ATP
# for artifact distribution when ATP dogfooding is enabled.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# CI integration configuration
ATP_DOGFOOD_ENABLED="${ATP_DOGFOOD_ENABLED:-false}"
ATP_DOGFOOD_CI_MODE="${ATP_DOGFOOD_CI_MODE:-optional}"  # optional, required, disabled
CI_ARTIFACTS_DIR="${CI_ARTIFACTS_DIR:-${PROJECT_ROOT}/target/ci-artifacts}"
CI_RUN_ID="${CI_RUN_ID:-ci_$(date +%Y%m%d_%H%M%S)}"

# Color codes for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_ci() {
    local level="$1"
    local message="$2"
    echo -e "${level}[CI-ATP]${NC} $message"
}

# Check if ATP dogfooding is available and configured
check_atp_dogfood_availability() {
    # Check if ATP CLI is available
    if ! command -v atp >/dev/null 2>&1; then
        log_ci "$YELLOW" "ATP CLI not available - falling back to traditional artifact handling"
        return 1
    fi

    # Check if dogfood coordinator is available
    if [[ ! -x "${PROJECT_ROOT}/scripts/atp_dogfood_coordinator.sh" ]]; then
        log_ci "$YELLOW" "ATP dogfood coordinator not available"
        return 1
    fi

    # Check configuration
    if [[ "$ATP_DOGFOOD_ENABLED" != "true" ]]; then
        log_ci "$YELLOW" "ATP dogfooding disabled via ATP_DOGFOOD_ENABLED"
        return 1
    fi

    return 0
}

# Traditional artifact handling (fallback)
handle_artifacts_traditional() {
    local artifact_type="$1"
    local source_dir="$2"
    local dest_dir="$3"

    log_ci "$YELLOW" "Using traditional artifact handling for $artifact_type"

    mkdir -p "$dest_dir"

    case "$artifact_type" in
        build)
            # Copy build artifacts
            if [[ -d "$source_dir" ]]; then
                cp -r "$source_dir"/* "$dest_dir/" || true
            fi
            ;;
        test)
            # Copy test results
            find "$source_dir" -name "*.xml" -o -name "*.json" -o -name "*.html" | \
                xargs -I {} cp {} "$dest_dir/" || true
            ;;
        coverage)
            # Copy coverage reports
            find "$source_dir" -name "*.lcov" -o -name "*.html" | \
                xargs -I {} cp {} "$dest_dir/" || true
            ;;
    esac

    log_ci "$GREEN" "Traditional artifact handling completed for $artifact_type"
}

# ATP-powered artifact handling
handle_artifacts_atp() {
    local artifact_type="$1"
    local source_dir="$2"
    local dest_identifier="$3"

    log_ci "$GREEN" "Using ATP for artifact handling: $artifact_type"

    # Map artifact types to dogfood coordinator modes
    local dogfood_mode
    case "$artifact_type" in
        build)
            dogfood_mode="build-artifacts"
            ;;
        test)
            dogfood_mode="test-results"
            ;;
        coverage)
            # For now, treat coverage like test results
            dogfood_mode="test-results"
            ;;
        fuzz)
            dogfood_mode="fuzz-corpora"
            ;;
        *)
            log_ci "$YELLOW" "Unknown artifact type for ATP: $artifact_type, using generic"
            dogfood_mode="build-artifacts"
            ;;
    esac

    # Run dogfood coordinator
    if "${PROJECT_ROOT}/scripts/atp_dogfood_coordinator.sh" \
        --peer-id "ci-${CI_RUN_ID}" \
        --metadata "ci_run=$CI_RUN_ID,artifact_type=$artifact_type" \
        "$dogfood_mode"; then

        log_ci "$GREEN" "ATP artifact handling completed successfully for $artifact_type"
        return 0
    else
        log_ci "$RED" "ATP artifact handling failed for $artifact_type"

        # Decide how to handle failure based on CI mode
        case "$ATP_DOGFOOD_CI_MODE" in
            required)
                log_ci "$RED" "ATP dogfooding is required but failed - failing CI"
                return 1
                ;;
            optional)
                log_ci "$YELLOW" "ATP dogfooding failed but is optional - falling back"
                handle_artifacts_traditional "$artifact_type" "$source_dir" "$CI_ARTIFACTS_DIR/$artifact_type"
                return 0
                ;;
            *)
                log_ci "$YELLOW" "Unknown CI mode: $ATP_DOGFOOD_CI_MODE"
                return 1
                ;;
        esac
    fi
}

# Main artifact distribution function
distribute_ci_artifacts() {
    local artifact_type="${1:-build}"
    local source_dir="${2:-target}"
    local dest="${3:-${CI_ARTIFACTS_DIR}/$artifact_type}"

    log_ci "$GREEN" "Distributing CI artifacts: $artifact_type"
    log_ci "$GREEN" "Source: $source_dir"
    log_ci "$GREEN" "Destination/Identifier: $dest"

    # Check if we should use ATP dogfooding
    if check_atp_dogfood_availability; then
        handle_artifacts_atp "$artifact_type" "$source_dir" "$dest"
    else
        handle_artifacts_traditional "$artifact_type" "$source_dir" "$dest"
    fi
}

# CI workflow integration points
ci_post_build() {
    log_ci "$GREEN" "CI post-build artifact distribution"
    distribute_ci_artifacts "build" "target/release" "ci-build-${CI_RUN_ID}"
}

ci_post_test() {
    log_ci "$GREEN" "CI post-test artifact distribution"
    distribute_ci_artifacts "test" "target/test-results" "ci-test-${CI_RUN_ID}"
}

ci_post_coverage() {
    log_ci "$GREEN" "CI post-coverage artifact distribution"
    distribute_ci_artifacts "coverage" "target/coverage" "ci-coverage-${CI_RUN_ID}"
}

ci_post_fuzz() {
    log_ci "$GREEN" "CI post-fuzz artifact distribution"
    distribute_ci_artifacts "fuzz" "fuzz" "ci-fuzz-${CI_RUN_ID}"
}

# Main command handler
main() {
    case "${1:-help}" in
        post-build)
            ci_post_build
            ;;
        post-test)
            ci_post_test
            ;;
        post-coverage)
            ci_post_coverage
            ;;
        post-fuzz)
            ci_post_fuzz
            ;;
        check)
            if check_atp_dogfood_availability; then
                log_ci "$GREEN" "ATP dogfooding is available and enabled"
                exit 0
            else
                log_ci "$YELLOW" "ATP dogfooding is not available"
                exit 1
            fi
            ;;
        help|--help|-h)
            cat <<'HELP'
Usage: scripts/ci/atp_dogfood_ci_integration.sh <command>

Commands:
  post-build      Distribute build artifacts
  post-test       Distribute test results
  post-coverage   Distribute coverage reports
  post-fuzz       Distribute fuzz corpora
  check           Check ATP dogfooding availability

Environment Variables:
  ATP_DOGFOOD_ENABLED     Enable ATP dogfooding (true/false)
  ATP_DOGFOOD_CI_MODE     CI mode: optional, required, disabled
  CI_ARTIFACTS_DIR        Directory for traditional artifact storage
  CI_RUN_ID              CI run identifier

Examples:
  # Enable ATP dogfooding in CI
  export ATP_DOGFOOD_ENABLED=true
  export ATP_DOGFOOD_CI_MODE=optional
  scripts/ci/atp_dogfood_ci_integration.sh post-build

  # Check if ATP dogfooding is available
  scripts/ci/atp_dogfood_ci_integration.sh check
HELP
            ;;
        *)
            echo "Unknown command: $1" >&2
            echo "Use 'help' for usage information" >&2
            exit 2
            ;;
    esac
}

main "$@"