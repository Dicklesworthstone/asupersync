#!/bin/bash
# ATP Module Compilation Checker
#
# Quick script to verify ATP modules compile correctly.
# Useful for rapid feedback during ATP development.

set -euo pipefail

echo "🧪 Checking ATP module compilation..."

# Check if we're in the right directory
if [[ ! -f Cargo.toml ]]; then
    echo "❌ Error: Must run from asupersync project root"
    exit 1
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to run a check
run_check() {
    local name="$1"
    local command="$2"

    echo -n "  $name... "
    if eval "$command" > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
        return 0
    else
        echo -e "${RED}✗${NC}"
        return 1
    fi
}

# Function to run a check with output
run_check_verbose() {
    local name="$1"
    local command="$2"

    echo "  $name..."
    if eval "$command"; then
        echo -e "  ${GREEN}✓ $name passed${NC}"
        return 0
    else
        echo -e "  ${RED}✗ $name failed${NC}"
        return 1
    fi
}

echo "📋 Running ATP compilation checks:"

# Basic compilation check
run_check "Basic ATP compilation" \
    "rch exec -- env CARGO_TARGET_DIR=\"\${TMPDIR:-/tmp}/rch_target_atp_check\" cargo check --lib"

# Test compilation check
run_check "ATP test compilation" \
    "rch exec -- env CARGO_TARGET_DIR=\"\${TMPDIR:-/tmp}/rch_target_atp_test\" cargo test --lib --no-run"

# Infrastructure test
run_check "ATP infrastructure test" \
    "rch exec -- env CARGO_TARGET_DIR=\"\${TMPDIR:-/tmp}/rch_target_atp_infra\" cargo test atp_infrastructure_test --no-run"

# Clippy check (warnings only)
echo "  Clippy analysis (warnings allowed)..."
if rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_atp_clippy" cargo clippy --lib -- -D clippy::correctness > /dev/null 2>&1; then
    echo -e "  ${GREEN}✓ No correctness issues${NC}"
else
    echo -e "  ${YELLOW}⚠ Some clippy warnings (not blocking)${NC}"
fi

# Format check
run_check "Format check" \
    "rch exec -- cargo fmt --check"

echo ""
echo "🎯 ATP Compilation Summary:"
echo "  All basic compilation checks completed."
echo "  Use 'cargo test atp_infrastructure_test' to run the full infrastructure test."
echo "  Use 'cargo test --lib atp' to run all ATP tests."
echo ""
echo -e "${GREEN}✨ ATP modules ready for development!${NC}"