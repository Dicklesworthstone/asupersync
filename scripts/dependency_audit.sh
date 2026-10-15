#!/bin/bash
# ATP Dependency Audit - Release Gate Implementation
# Ensures no unauthorized external dependencies in ATP/native core

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
AUDIT_LOG="${PROJECT_ROOT}/artifacts/dependency_audit_$(date +%Y%m%d_%H%M%S).log"

# Initialize audit log
mkdir -p "${PROJECT_ROOT}/artifacts"
echo "ATP Dependency Audit - $(date)" > "$AUDIT_LOG"
echo "=======================================" >> "$AUDIT_LOG"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Audit result tracking
VIOLATIONS=0
WARNINGS=0

log_violation() {
    echo -e "${RED}VIOLATION:${NC} $1" | tee -a "$AUDIT_LOG"
    ((VIOLATIONS++))
}

log_warning() {
    echo -e "${YELLOW}WARNING:${NC} $1" | tee -a "$AUDIT_LOG"
    ((WARNINGS++))
}

log_success() {
    echo -e "${GREEN}PASS:${NC} $1" | tee -a "$AUDIT_LOG"
}

echo "Starting ATP dependency audit..." | tee -a "$AUDIT_LOG"

# Check for forbidden external QUIC crates
echo "\n1. Checking for external QUIC crates..." | tee -a "$AUDIT_LOG"

FORBIDDEN_QUIC_CRATES=(
    "quinn"
    "quiche"
    "quinn-proto"
    "quinn-udp"
    "h3"
    "h3-quinn"
    "s2n-quic"
    "msquic"
    "neqo"
)

cd "$PROJECT_ROOT"

# Check Cargo.toml files
for crate_name in "${FORBIDDEN_QUIC_CRATES[@]}"; do
    if grep -r "^$crate_name\s*=" Cargo.toml Cargo.lock 2>/dev/null; then
        log_violation "Found forbidden external QUIC crate: $crate_name"
    fi
done

# Check source code for forbidden imports
QUIC_IMPORTS=$(find src/ -name "*.rs" -exec grep -l "use.*\(quinn\|quiche\|h3\|s2n_quic\|msquic\|neqo\)" {} \; 2>/dev/null || true)
if [[ -n "$QUIC_IMPORTS" ]]; then
    log_violation "Found external QUIC imports in: $QUIC_IMPORTS"
else
    log_success "No external QUIC crate dependencies found"
fi

# Check for forbidden Tokio runtime paths in ATP/native core
echo "\n2. Checking for Tokio runtime dependencies..." | tee -a "$AUDIT_LOG"

ATP_CORE_DIRS=(
    "src/net/atp/"
    "src/atp/"
    "src/native/"
)

TOKIO_VIOLATIONS=""
for dir in "${ATP_CORE_DIRS[@]}"; do
    if [[ -d "$dir" ]]; then
        # Check for direct tokio runtime usage
        TOKIO_USAGE=$(find "$dir" -name "*.rs" -exec grep -l "tokio::runtime\|Runtime::new\|Handle::current" {} \; 2>/dev/null || true)
        if [[ -n "$TOKIO_USAGE" ]]; then
            TOKIO_VIOLATIONS="$TOKIO_VIOLATIONS $TOKIO_USAGE"
        fi

        # Check for tokio feature flags that enable runtime
        RUNTIME_FEATURES=$(find "$dir" -name "Cargo.toml" -exec grep -l 'tokio.*=.*"rt\|rt-multi-thread"' {} \; 2>/dev/null || true)
        if [[ -n "$RUNTIME_FEATURES" ]]; then
            TOKIO_VIOLATIONS="$TOKIO_VIOLATIONS $RUNTIME_FEATURES"
        fi
    fi
done

if [[ -n "$TOKIO_VIOLATIONS" ]]; then
    log_violation "Found Tokio runtime usage in ATP core: $TOKIO_VIOLATIONS"
else
    log_success "No Tokio runtime dependencies in ATP core"
fi

# Check for approved vs forbidden dependencies
echo "\n3. Validating dependency whitelist..." | tee -a "$AUDIT_LOG"

# ATP core should only use these approved crates
APPROVED_DEPS=(
    "serde"
    "sha2"
    "blake3"
    "hex"
    "bytes"
    "futures"
    "pin-project"
    "thiserror"
    "tracing"
    "uuid"
    "smallvec"
    "hashbrown"
    "parking_lot"
)

# Extract actual dependencies from Cargo.lock
if [[ -f "Cargo.lock" ]]; then
    ACTUAL_DEPS=$(grep "^name = " Cargo.lock | sed 's/name = "\(.*\)"/\1/' | sort -u)

    # Check for unexpected dependencies
    while IFS= read -r dep; do
        # Skip internal crates and approved deps
        if [[ "$dep" == "asupersync"* ]] || [[ " ${APPROVED_DEPS[*]} " =~ " ${dep} " ]]; then
            continue
        fi

        # Flag potentially problematic dependencies
        case "$dep" in
            tokio|async-std|smol|futures-executor)
                log_warning "Runtime dependency detected: $dep (verify usage is appropriate)"
                ;;
            openssl|rustls|native-tls)
                log_warning "TLS dependency detected: $dep (verify not bypassing ATP crypto)"
                ;;
            *)
                # Let other deps pass but log them
                echo "INFO: External dependency: $dep" >> "$AUDIT_LOG"
                ;;
        esac
    done <<< "$ACTUAL_DEPS"
else
    log_warning "Cargo.lock not found - cannot validate dependency list"
fi

# Check cross-platform capability requirements
echo "\n4. Checking cross-platform capabilities..." | tee -a "$AUDIT_LOG"

PLATFORM_FEATURES=(
    "cfg(unix)"
    "cfg(windows)"
    "cfg(target_os"
)

PLATFORM_CODE=""
for feature in "${PLATFORM_FEATURES[@]}"; do
    FEATURE_USAGE=$(find src/ -name "*.rs" -exec grep -l "$feature" {} \; 2>/dev/null || true)
    if [[ -n "$FEATURE_USAGE" ]]; then
        PLATFORM_CODE="$PLATFORM_CODE $FEATURE_USAGE"
    fi
done

if [[ -n "$PLATFORM_CODE" ]]; then
    log_success "Platform-specific code found (requires cross-platform testing)"
    echo "Platform-specific files: $PLATFORM_CODE" >> "$AUDIT_LOG"
else
    log_success "No platform-specific code detected"
fi

# Check for security-sensitive code
echo "\n5. Security audit..." | tee -a "$AUDIT_LOG"

SECURITY_PATTERNS=(
    "unsafe"
    "transmute"
    "from_raw"
    "uninitialized"
)

SECURITY_ISSUES=""
for pattern in "${SECURITY_PATTERNS[@]}"; do
    PATTERN_USAGE=$(find src/ -name "*.rs" -exec grep -l "\b$pattern\b" {} \; 2>/dev/null || true)
    if [[ -n "$PATTERN_USAGE" ]]; then
        SECURITY_ISSUES="$SECURITY_ISSUES $pattern:($PATTERN_USAGE)"
    fi
done

if [[ -n "$SECURITY_ISSUES" ]]; then
    log_warning "Security-sensitive code found: $SECURITY_ISSUES"
    echo "Verify all unsafe code has proper justification and review" >> "$AUDIT_LOG"
else
    log_success "No security-sensitive patterns detected"
fi

# Generate audit summary
echo "\n=======================================" >> "$AUDIT_LOG"
echo "AUDIT SUMMARY" >> "$AUDIT_LOG"
echo "=======================================" >> "$AUDIT_LOG"
echo "Violations: $VIOLATIONS" >> "$AUDIT_LOG"
echo "Warnings: $WARNINGS" >> "$AUDIT_LOG"
echo "Audit completed: $(date)" >> "$AUDIT_LOG"

# Final result
echo ""
echo "======================================="
if [[ $VIOLATIONS -eq 0 ]]; then
    echo -e "${GREEN}DEPENDENCY AUDIT PASSED${NC}"
    echo "Warnings: $WARNINGS"
    echo "Full audit log: $AUDIT_LOG"
    exit 0
else
    echo -e "${RED}DEPENDENCY AUDIT FAILED${NC}"
    echo "Violations: $VIOLATIONS"
    echo "Warnings: $WARNINGS"
    echo "Full audit log: $AUDIT_LOG"
    exit 1
fi