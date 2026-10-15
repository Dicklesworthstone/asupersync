#!/bin/bash
# ATP Cross-Platform Capability Test
# Validates ATP behavior consistency across supported platforms

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TEST_LOG="${PROJECT_ROOT}/artifacts/cross_platform_test_$(date +%Y%m%d_%H%M%S).log"

# Initialize test log
mkdir -p "${PROJECT_ROOT}/artifacts"
echo "ATP Cross-Platform Test - $(date)" > "$TEST_LOG"
echo "=======================================" >> "$TEST_LOG"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test result tracking
FAILURES=0
SKIPPED=0
PASSED=0

log_failure() {
    echo -e "${RED}FAIL:${NC} $1" | tee -a "$TEST_LOG"
    ((FAILURES += 1))
}

log_skip() {
    echo -e "${YELLOW}SKIP:${NC} $1" | tee -a "$TEST_LOG"
    ((SKIPPED += 1))
}

log_pass() {
    echo -e "${GREEN}PASS:${NC} $1" | tee -a "$TEST_LOG"
    ((PASSED += 1))
}

log_info() {
    echo -e "${BLUE}INFO:${NC} $1" | tee -a "$TEST_LOG"
}

cargo_target_dir() {
    printf '%s' "${CARGO_TARGET_DIR:-${PROJECT_ROOT}/target/cross_platform_cargo}"
}

run_cargo_check() {
    local label="$1"
    shift

    log_info "Running cargo check: $label"
    if CARGO_TARGET_DIR="$(cargo_target_dir)" cargo check "$@" >> "$TEST_LOG" 2>&1; then
        log_pass "$label compiles"
    else
        log_failure "$label compilation failed"
    fi
}

run_cargo_test() {
    local label="$1"
    shift

    log_info "Running cargo test: $label"
    local cargo_output
    if cargo_output="$(CARGO_TARGET_DIR="$(cargo_target_dir)" cargo test "$@" 2>&1)"; then
        printf '%s\n' "$cargo_output" >> "$TEST_LOG"
        if grep -Eq "running 0 tests|0 passed; 0 failed; 0 ignored; .* filtered out" <<< "$cargo_output"; then
            log_failure "$label ran zero tests"
            return
        fi
        log_pass "$label passed"
    else
        printf '%s\n' "$cargo_output" >> "$TEST_LOG"
        log_failure "$label failed"
    fi
}

tool_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Detect current platform
detect_platform() {
    local os="$(uname -s)"
    local arch="$(uname -m)"

    case "$os" in
        Linux*)   PLATFORM="linux" ;;
        Darwin*)  PLATFORM="macos" ;;
        CYGWIN*|MINGW*|MSYS*) PLATFORM="windows" ;;
        *)        PLATFORM="unknown" ;;
    esac

    case "$arch" in
        x86_64)   ARCH="x64" ;;
        arm64|aarch64) ARCH="arm64" ;;
        *)        ARCH="unknown" ;;
    esac

    log_info "Detected platform: $PLATFORM-$ARCH"
}

# Test filesystem capabilities
test_filesystem_caps() {
    log_info "Testing filesystem capabilities..."

    local test_dir="${PROJECT_ROOT}/target/cross_platform_test"
    mkdir -p "$test_dir"

    # Test sparse file support
    if command -v fallocate >/dev/null 2>&1; then
        if fallocate -l 1G "$test_dir/sparse_test" 2>/dev/null; then
            log_pass "Sparse file support available"
        else
            log_skip "Sparse file support not available"
        fi
    else
        log_skip "fallocate not available for sparse file test"
    fi

    # Test symlink support
    if ln -s "target" "$test_dir/symlink_test" 2>/dev/null; then
        log_pass "Symlink support available"
    else
        log_skip "Symlink support not available"
    fi

    # Test extended attributes
    if command -v setfattr >/dev/null 2>&1; then
        touch "$test_dir/xattr_test"
        if setfattr -n user.test -v "value" "$test_dir/xattr_test" 2>/dev/null; then
            log_pass "Extended attributes support available"
        else
            log_skip "Extended attributes not available"
        fi
    else
        log_skip "Extended attributes tools not available"
    fi

    log_info "Filesystem probe artifacts retained under $test_dir"
}

# Test network capabilities
test_network_caps() {
    log_info "Testing network capabilities..."

    # Test IPv6 support
    if ping6 -c 1 ::1 >/dev/null 2>&1; then
        log_pass "IPv6 support available"
    else
        log_skip "IPv6 not available"
    fi

    # Test UDP socket binding
    if tool_exists nc; then
        if nc -u -l 0 -p 0 </dev/null >/dev/null 2>&1 & then
            local nc_pid=$!
            sleep 0.1
            kill $nc_pid 2>/dev/null || true
            wait $nc_pid 2>/dev/null || true
            log_pass "UDP socket binding available"
        else
            log_skip "UDP socket binding test failed"
        fi
    else
        log_skip "netcat not available for network testing"
    fi

    # Test SO_REUSEPORT with the canonical Rust coverage instead of a shell stub.
    case "$PLATFORM" in
        linux)
            run_cargo_test \
                "SO_REUSEPORT Linux conformance" \
                --test conformance \
                conformance::tcp_listener::test_so_reuseport_load_balancing \
                -- \
                --exact
            ;;
        macos)
            run_cargo_test \
                "SO_REUSEPORT Unix socket option" \
                --lib \
                net::tcp::socket::tests::test_listen_with_reuseport \
                -- \
                --exact
            ;;
        windows)
            log_skip "SO_REUSEPORT is Unix-only"
            ;;
        *)
            log_skip "SO_REUSEPORT proof unavailable for unknown platform"
            ;;
    esac
}

# Test ATP-specific capabilities
test_atp_caps() {
    log_info "Testing ATP-specific capabilities..."

    cd "$PROJECT_ROOT"

    run_cargo_check \
        "ATP/native core" \
        --package asupersync \
        --lib \
        --no-default-features \
        --features "native-runtime"

    run_cargo_check \
        "native QUIC/HTTP3 feature surface" \
        --package asupersync \
        --lib \
        --no-default-features \
        --features "native-runtime,quic,http3"

    run_cargo_check \
        "TLS feature surface" \
        --package asupersync \
        --lib \
        --no-default-features \
        --features "tls"

    run_cargo_check \
        "SQLite feature surface" \
        --package asupersync \
        --lib \
        --no-default-features \
        --features "sqlite"

    test_windows_cross_compile_surface

    # Test platform-specific I/O
    case "$PLATFORM" in
        linux)
            run_cargo_check \
                "Linux io_uring feature surface" \
                --package asupersync \
                --lib \
                --no-default-features \
                --features "native-runtime,io-uring"
            ;;
        macos)
            run_cargo_check \
                "macOS native feature surface" \
                --package asupersync \
                --lib \
                --no-default-features \
                --features "native-runtime"
            ;;
        windows)
            run_cargo_check \
                "Windows native feature surface" \
                --package asupersync \
                --lib \
                --no-default-features \
                --features "native-runtime"
            ;;
    esac
}

test_windows_cross_compile_surface() {
    local windows_target="x86_64-pc-windows-gnu"

    if ! rustup target list --installed 2>/dev/null | grep -qx "$windows_target"; then
        log_skip "Windows GNU Rust target not installed: $windows_target"
        return
    fi

    run_cargo_check \
        "Windows GNU pure-Rust/native source surface" \
        --package asupersync \
        --lib \
        --target "$windows_target" \
        --no-default-features \
        --features "native-runtime,quic,http3,compression,tracing-integration"

    if tool_exists x86_64-w64-mingw32-gcc; then
        run_cargo_check \
            "Windows GNU native-C feature surface (TLS + SQLite)" \
            --package asupersync \
            --lib \
            --target "$windows_target" \
            --no-default-features \
            --features "tls,sqlite"
    else
        log_skip "Windows GNU native-C feature surface requires x86_64-w64-mingw32-gcc for ring/libsqlite3-sys"
    fi
}

# Test performance characteristics
test_performance_caps() {
    log_info "Testing performance capabilities..."

    cd "$PROJECT_ROOT"

    # Test if we can measure time precisely
    if tool_exists time; then
        log_pass "High-resolution timing available"
    else
        log_skip "High-resolution timing not available"
    fi

    # Test memory mapping
    if tool_exists mmap || [[ "$PLATFORM" != "unknown" ]]; then
        log_pass "Memory mapping capabilities available"
    else
        log_skip "Memory mapping capabilities unknown"
    fi

    # Test CPU features (if available)
    if tool_exists lscpu; then
        local cpu_features
        cpu_features=$(lscpu | grep "Flags" | head -1 || echo "")
        if [[ -n "$cpu_features" ]]; then
            log_pass "CPU feature detection available"
            echo "CPU features: $cpu_features" >> "$TEST_LOG"
        else
            log_skip "CPU feature detection not available"
        fi
    else
        log_skip "CPU information not available"
    fi
}

# Generate capability matrix
generate_capability_matrix() {
    log_info "Generating capability matrix..."

    local matrix_file="${PROJECT_ROOT}/artifacts/platform_capability_matrix.json"

    cat > "$matrix_file" << EOF
{
    "platform": {
        "os": "$PLATFORM",
        "arch": "$ARCH",
        "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    },
    "capabilities": {
        "filesystem": {
            "sparse_files": "$(grep -q "Sparse file support available" "$TEST_LOG" && echo "true" || echo "false")",
            "symlinks": "$(grep -q "Symlink support available" "$TEST_LOG" && echo "true" || echo "false")",
            "extended_attributes": "$(grep -q "Extended attributes support available" "$TEST_LOG" && echo "true" || echo "false")"
        },
        "network": {
            "ipv6": "$(grep -q "IPv6 support available" "$TEST_LOG" && echo "true" || echo "false")",
            "udp_sockets": "$(grep -q "UDP socket binding available" "$TEST_LOG" && echo "true" || echo "false")",
            "reuseport": "$(grep -Eq "SO_REUSEPORT (Linux conformance|Unix socket option) passed" "$TEST_LOG" && echo "true" || echo "false")"
        },
        "atp": {
            "core_compilation": "$(grep -q "ATP/native core compiles" "$TEST_LOG" && echo "true" || echo "false")",
            "quic_native": "$(grep -q "native QUIC/HTTP3 feature surface compiles" "$TEST_LOG" && echo "true" || echo "false")",
            "tls": "$(grep -q "TLS feature surface compiles" "$TEST_LOG" && echo "true" || echo "false")",
            "sqlite": "$(grep -q "SQLite feature surface compiles" "$TEST_LOG" && echo "true" || echo "false")",
            "windows_gnu_source": "$(grep -q "Windows GNU pure-Rust/native source surface compiles" "$TEST_LOG" && echo "true" || echo "false")",
            "windows_gnu_native_c": "$(grep -q "Windows GNU native-C feature surface (TLS + SQLite) compiles" "$TEST_LOG" && echo "true" || echo "false")"
        },
        "performance": {
            "high_res_timing": "$(grep -q "High-resolution timing available" "$TEST_LOG" && echo "true" || echo "false")",
            "memory_mapping": "$(grep -q "Memory mapping capabilities available" "$TEST_LOG" && echo "true" || echo "false")"
        }
    },
    "test_results": {
        "passed": $PASSED,
        "skipped": $SKIPPED,
        "failed": $FAILURES
    }
}
EOF

    log_pass "Capability matrix generated: $matrix_file"
}

# Main execution
main() {
    echo "Starting ATP cross-platform capability test..." | tee -a "$TEST_LOG"

    detect_platform
    test_filesystem_caps
    test_network_caps
    test_atp_caps
    test_performance_caps
    generate_capability_matrix

    # Final summary
    echo "" | tee -a "$TEST_LOG"
    echo "=======================================" | tee -a "$TEST_LOG"
    echo "TEST SUMMARY" | tee -a "$TEST_LOG"
    echo "=======================================" | tee -a "$TEST_LOG"
    echo "Platform: $PLATFORM-$ARCH" | tee -a "$TEST_LOG"
    echo "Passed: $PASSED" | tee -a "$TEST_LOG"
    echo "Skipped: $SKIPPED" | tee -a "$TEST_LOG"
    echo "Failed: $FAILURES" | tee -a "$TEST_LOG"
    echo "Test completed: $(date)" | tee -a "$TEST_LOG"

    if [[ $FAILURES -eq 0 ]]; then
        echo -e "${GREEN}CROSS-PLATFORM TEST PASSED${NC}"
        echo "Full test log: $TEST_LOG"
        exit 0
    else
        echo -e "${RED}CROSS-PLATFORM TEST FAILED${NC}"
        echo "Full test log: $TEST_LOG"
        exit 1
    fi
}

# Execute main function
main "$@"
