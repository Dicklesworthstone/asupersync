#!/bin/bash
# ATP-N7: Linux Platform Setup for ATP Testing

set -euo pipefail

echo "=== Setting up Linux platform for ATP testing ==="

# Update package lists
sudo apt-get update

# Install system dependencies
sudo apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    curl \
    jq \
    python3 \
    python3-pip \
    git \
    wget \
    unzip

# Install Linux-specific dependencies for ATP
echo "Installing Linux-specific dependencies..."

# Install io_uring development headers (for async I/O)
sudo apt-get install -y liburing-dev

# Install network testing tools
sudo apt-get install -y \
    net-tools \
    iproute2 \
    netcat-openbsd \
    tcpdump \
    iperf3

# Install performance profiling tools
sudo apt-get install -y \
    perf \
    valgrind \
    strace

# Install Rust-specific tools
echo "Installing Rust testing tools..."
cargo install --locked cargo-nextest || true
cargo install --locked cargo-llvm-cov || true
cargo install --locked cargo-audit || true

# Setup network capabilities for testing (if needed)
echo "Setting up network test capabilities..."

# Create test network namespace (optional, for isolation)
if [[ "$EUID" -eq 0 ]]; then
    echo "Running as root, setting up network test namespace"
    ip netns add atp-test || true
    ip netns exec atp-test ip link set lo up || true
fi

# Setup ATP test environment
echo "Setting up ATP test environment..."

# Create test directories
mkdir -p /tmp/atp-test/{artifacts,logs,data}

# Set ATP-specific environment variables
export ATP_PLATFORM="linux"
export ATP_IO_BACKEND="io_uring"
export ATP_NETWORK_BACKEND="epoll"

# Install test vectors and conformance data (if available)
echo "Setting up test data..."

# Create test certificate for TLS testing
if command -v openssl >/dev/null; then
    mkdir -p /tmp/atp-test/certs
    openssl req -x509 -newkey rsa:4096 -keyout /tmp/atp-test/certs/key.pem \
        -out /tmp/atp-test/certs/cert.pem -sha256 -days 365 -nodes \
        -subj "/C=US/ST=Test/L=Test/O=ATP/OU=Test/CN=localhost" 2>/dev/null || true
fi

# Setup ulimits for testing
echo "Setting resource limits for testing..."
ulimit -n 65536 || true  # File descriptors
ulimit -c unlimited || true  # Core dumps

echo "Linux platform setup completed"
echo "Platform: $(uname -a)"
echo "Rust: $(rustc --version)"
echo "Cargo: $(cargo --version)"