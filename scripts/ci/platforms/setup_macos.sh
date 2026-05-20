#!/bin/bash
# ATP-N7: macOS Platform Setup for ATP Testing

set -euo pipefail

echo "=== Setting up macOS platform for ATP testing ==="

# Install system dependencies via Homebrew
if ! command -v brew &> /dev/null; then
    echo "Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

# Update Homebrew
brew update

# Install essential tools
echo "Installing system dependencies..."
brew install \
    curl \
    jq \
    python3 \
    git \
    wget \
    openssl@3

# Install network testing tools
brew install \
    netcat \
    iperf3

# Install development tools if not present
if ! xcode-select -p &> /dev/null; then
    echo "Installing Xcode command line tools..."
    xcode-select --install || true
fi

# Install Rust-specific tools
echo "Installing Rust testing tools..."
cargo install --locked cargo-nextest || true
cargo install --locked cargo-llvm-cov || true
cargo install --locked cargo-audit || true

# Setup ATP test environment
echo "Setting up ATP test environment..."

# Create test directories
mkdir -p /tmp/atp-test/{artifacts,logs,data}

# Set ATP-specific environment variables
export ATP_PLATFORM="macos"
export ATP_IO_BACKEND="kqueue"
export ATP_NETWORK_BACKEND="kqueue"

# Setup OpenSSL paths for macOS
export OPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"
export PKG_CONFIG_PATH="$OPENSSL_ROOT_DIR/lib/pkgconfig:${PKG_CONFIG_PATH:-}"

# Create test certificate for TLS testing
echo "Setting up test certificates..."
mkdir -p /tmp/atp-test/certs
openssl req -x509 -newkey rsa:4096 -keyout /tmp/atp-test/certs/key.pem \
    -out /tmp/atp-test/certs/cert.pem -sha256 -days 365 -nodes \
    -subj "/C=US/ST=Test/L=Test/O=ATP/OU=Test/CN=localhost" 2>/dev/null || true

# Setup resource limits for testing
echo "Setting resource limits for testing..."
ulimit -n 10240 || true  # File descriptors (macOS default is lower)

echo "macOS platform setup completed"
echo "Platform: $(uname -a)"
echo "Xcode: $(xcode-select -p 2>/dev/null || echo 'Not installed')"
echo "Rust: $(rustc --version)"
echo "Cargo: $(cargo --version)"
echo "OpenSSL: $(openssl version)"