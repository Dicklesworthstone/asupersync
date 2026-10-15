#!/bin/bash
# ATP-N7: Windows Platform Setup for ATP Testing
# Note: This runs in Git Bash/WSL environment on Windows runners

set -euo pipefail

echo "=== Setting up Windows platform for ATP testing ==="

# Check if we're in WSL or Git Bash
if [[ -n "${WSL_DISTRO_NAME:-}" ]]; then
    echo "Running in WSL: $WSL_DISTRO_NAME"
    WINDOWS_ENV="wsl"
elif [[ "$OSTYPE" == "msys" ]]; then
    echo "Running in Git Bash/MSYS2"
    WINDOWS_ENV="msys"
else
    echo "Unknown Windows environment: $OSTYPE"
    WINDOWS_ENV="unknown"
fi

# Install system dependencies based on environment
if [[ "$WINDOWS_ENV" == "wsl" ]]; then
    echo "Setting up WSL environment..."

    # Update package lists
    sudo apt-get update

    # Install essential tools
    sudo apt-get install -y \
        curl \
        jq \
        python3 \
        python3-pip \
        git \
        wget \
        unzip \
        pkg-config \
        libssl-dev

elif [[ "$WINDOWS_ENV" == "msys" ]]; then
    echo "Setting up MSYS2/Git Bash environment..."

    # Install tools via pacman if available
    if command -v pacman &> /dev/null; then
        pacman -S --noconfirm \
            curl \
            jq \
            python \
            git \
            wget \
            unzip || true
    fi
fi

# Install Rust-specific tools
echo "Installing Rust testing tools..."
cargo install --locked cargo-nextest || true
cargo install --locked cargo-llvm-cov || true
cargo install --locked cargo-audit || true

# Setup ATP test environment
echo "Setting up ATP test environment..."

# Create test directories (Windows-compatible paths)
TEST_DIR="/tmp/atp-test"
if [[ "$WINDOWS_ENV" == "msys" ]]; then
    TEST_DIR="/c/temp/atp-test"
fi

mkdir -p "${TEST_DIR}"/{artifacts,logs,data}

# Set ATP-specific environment variables
export ATP_PLATFORM="windows"
export ATP_IO_BACKEND="iocp"
export ATP_NETWORK_BACKEND="winsock"

# Create test certificate for TLS testing
echo "Setting up test certificates..."
CERT_DIR="${TEST_DIR}/certs"
mkdir -p "$CERT_DIR"

if command -v openssl >/dev/null; then
    openssl req -x509 -newkey rsa:4096 -keyout "${CERT_DIR}/key.pem" \
        -out "${CERT_DIR}/cert.pem" -sha256 -days 365 -nodes \
        -subj "/C=US/ST=Test/L=Test/O=ATP/OU=Test/CN=localhost" 2>/dev/null || true
fi

# Windows-specific setup
echo "Configuring Windows-specific settings..."

# Enable long paths in Git (if in Git Bash)
if command -v git >/dev/null; then
    git config --global core.longpaths true || true
fi

# Set Windows-specific Cargo configuration
CARGO_CONFIG_DIR="${HOME}/.cargo"
mkdir -p "$CARGO_CONFIG_DIR"

cat > "${CARGO_CONFIG_DIR}/config.toml" <<EOF
[build]
# Windows-specific build configuration
target-dir = "target"

[target.'cfg(windows)']
rustflags = [
    "-C", "link-arg=/STACK:8388608",  # 8MB stack size
]

[env]
# Windows-specific environment
ATP_PLATFORM = "windows"
ATP_IO_BACKEND = "iocp"
EOF

# Setup Windows Defender exclusions (if running as admin)
echo "Setting up Windows Defender exclusions for build performance..."
EXCLUSION_PATHS=(
    "$(pwd)/target"
    "$TEST_DIR"
    "${HOME}/.cargo"
    "${HOME}/.rustup"
)

for path in "${EXCLUSION_PATHS[@]}"; do
    # Convert to Windows path format
    WIN_PATH=$(cygpath -w "$path" 2>/dev/null || echo "$path")

    # Try to add exclusion (will fail if not admin, that's OK)
    powershell.exe -Command "Add-MpPreference -ExclusionPath \"$WIN_PATH\"" 2>/dev/null || true
done

echo "Windows platform setup completed"
echo "Platform: $(uname -a)"
echo "Environment: $WINDOWS_ENV"
echo "Rust: $(rustc --version)"
echo "Cargo: $(cargo --version)"

# Print Windows-specific info
if command -v powershell.exe >/dev/null; then
    echo "PowerShell: $(powershell.exe -Command '$PSVersionTable.PSVersion' 2>/dev/null || echo 'Unknown')"
fi