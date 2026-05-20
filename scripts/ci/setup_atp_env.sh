#!/bin/bash
# ATP-N7: ATP Test Environment Setup

set -euo pipefail

echo "=== Setting up ATP test environment ==="

# Set ATP-specific environment variables
export ATP_TEST_MODE="${ATP_TEST_MODE:-smoke}"
export ATP_LOG_LEVEL="${ATP_LOG_LEVEL:-info}"
export RUST_LOG="${RUST_LOG:-info}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"

# Create directories for test artifacts
mkdir -p artifacts/{smoke,full,release}
mkdir -p test-results
mkdir -p logs
mkdir -p coverage

echo "Environment variables:"
echo "  ATP_TEST_MODE=$ATP_TEST_MODE"
echo "  ATP_LOG_LEVEL=$ATP_LOG_LEVEL"
echo "  RUST_LOG=$RUST_LOG"

# Setup Rust environment
echo "Configuring Rust environment..."

# Ensure we have the required components
rustup component add rustfmt clippy 2>/dev/null || true

# Configure cargo for testing
export CARGO_INCREMENTAL=0
export RUSTFLAGS="-D warnings"

# Set test timeout
export RUST_TEST_TIMEOUT=300  # 5 minutes

echo "✓ ATP test environment ready"