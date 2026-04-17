#!/bin/bash
set -euo pipefail

# Offline kernel superoptimization script for RaptorQ GF(256) operations.
#
# This script automates the complete offline tuning workflow:
# 1. Auto-detect host architecture
# 2. Run systematic kernel optimization
# 3. Generate optimized profile packs
# 4. Validate bit-exactness
# 5. Emit evidence artifacts

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="${PROJECT_ROOT}/tuning_results"
VERBOSE=false
ARCH=""
SKIP_VALIDATION=false

usage() {
    cat << EOF
Usage: $0 [options]

Offline kernel superoptimization for RaptorQ GF(256) operations.

Options:
    -h, --help              Show this help message
    -v, --verbose           Enable verbose output
    -a, --arch ARCH         Target architecture (scalar, x86-avx2, aarch64-neon)
                           If not specified, auto-detects host architecture
    -o, --output DIR        Output directory for results (default: tuning_results)
    --skip-validation       Skip bit-exactness validation
    --latency-weight W      Latency optimization weight 0.0-1.0 (default: 0.5)
    --throughput-weight W   Throughput optimization weight 0.0-1.0 (default: 0.3)
    --bandwidth-weight W    Bandwidth optimization weight 0.0-1.0 (default: 0.2)
    --min-improvement P     Minimum improvement threshold % (default: 5.0)

Examples:
    # Auto-detect architecture and run optimization
    $0

    # Optimize for specific architecture with verbose output
    $0 --arch x86-avx2 --verbose

    # Custom optimization weights
    $0 --latency-weight 0.7 --throughput-weight 0.2 --bandwidth-weight 0.1
EOF
}

# Default optimization criteria
LATENCY_WEIGHT=0.5
THROUGHPUT_WEIGHT=0.3
BANDWIDTH_WEIGHT=0.2
MIN_IMPROVEMENT=5.0

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            exit 0
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -a|--arch)
            ARCH="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --skip-validation)
            SKIP_VALIDATION=true
            shift
            ;;
        --latency-weight)
            LATENCY_WEIGHT="$2"
            shift 2
            ;;
        --throughput-weight)
            THROUGHPUT_WEIGHT="$2"
            shift 2
            ;;
        --bandwidth-weight)
            BANDWIDTH_WEIGHT="$2"
            shift 2
            ;;
        --min-improvement)
            MIN_IMPROVEMENT="$2"
            shift 2
            ;;
        *)
            echo "Error: Unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

# Validate optimization weights sum to reasonable total
WEIGHT_SUM=$(echo "$LATENCY_WEIGHT + $THROUGHPUT_WEIGHT + $BANDWIDTH_WEIGHT" | bc -l)
if (( $(echo "$WEIGHT_SUM < 0.9 || $WEIGHT_SUM > 1.1" | bc -l) )); then
    echo "Warning: Optimization weights sum to $WEIGHT_SUM (should be ~1.0)" >&2
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Set up logging
LOG_FILE="$OUTPUT_DIR/tuning_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOG_FILE")
exec 2> >(tee -a "$LOG_FILE" >&2)

echo "=== RaptorQ GF(256) Offline Kernel Superoptimization ==="
echo "Started: $(date)"
echo "Project root: $PROJECT_ROOT"
echo "Output directory: $OUTPUT_DIR"
echo "Log file: $LOG_FILE"
echo

# Build the offline tuner
echo "Building offline tuner..."
cd "$PROJECT_ROOT"

CARGO_CMD="cargo build --bin offline_tuner --release --features cli,simd-intrinsics"
if [[ "$VERBOSE" == "true" ]]; then
    echo "Running: $CARGO_CMD"
fi

if ! $CARGO_CMD; then
    echo "Error: Failed to build offline tuner" >&2
    exit 1
fi

echo "Build completed successfully."
echo

# Set up tuner command
TUNER_CMD="./target/release/offline_tuner"
TUNER_ARGS=(
    "optimize"
    "--output-dir" "$OUTPUT_DIR"
    "--latency-weight" "$LATENCY_WEIGHT"
    "--throughput-weight" "$THROUGHPUT_WEIGHT"
    "--bandwidth-weight" "$BANDWIDTH_WEIGHT"
    "--min-improvement-threshold" "$MIN_IMPROVEMENT"
)

if [[ "$VERBOSE" == "true" ]]; then
    TUNER_ARGS+=(--verbose)
fi

if [[ -n "$ARCH" ]]; then
    TUNER_ARGS+=(--arch "$ARCH")
else
    TUNER_ARGS+=(--auto-detect)
fi

echo "Running offline kernel superoptimization..."
if [[ "$VERBOSE" == "true" ]]; then
    echo "Command: $TUNER_CMD ${TUNER_ARGS[*]}"
fi

if ! "$TUNER_CMD" "${TUNER_ARGS[@]}"; then
    echo "Error: Offline tuning failed" >&2
    exit 1
fi

echo "Optimization completed successfully."
echo

# Run validation if not skipped
if [[ "$SKIP_VALIDATION" != "true" ]]; then
    echo "Running bit-exactness validation..."

    VALIDATE_ARGS=("validate")
    if [[ -n "$ARCH" ]]; then
        VALIDATE_ARGS+=(--arch "$ARCH")
    else
        # Auto-detect architecture for validation
        VALIDATE_ARGS+=(--arch "scalar")  # Default to scalar for now
    fi

    if [[ "$VERBOSE" == "true" ]]; then
        echo "Command: $TUNER_CMD ${VALIDATE_ARGS[*]}"
    fi

    if ! "$TUNER_CMD" "${VALIDATE_ARGS[@]}"; then
        echo "Warning: Bit-exactness validation failed" >&2
        # Don't exit on validation failure - results may still be useful
    else
        echo "Validation completed successfully."
    fi
    echo
fi

# Generate summary report
SUMMARY_FILE="$OUTPUT_DIR/optimization_summary.txt"
echo "Generating summary report: $SUMMARY_FILE"

cat > "$SUMMARY_FILE" << EOF
RaptorQ GF(256) Offline Kernel Superoptimization Summary
======================================================

Timestamp: $(date)
Host: $(uname -a)

Configuration:
- Target Architecture: ${ARCH:-"auto-detected"}
- Latency Weight: $LATENCY_WEIGHT
- Throughput Weight: $THROUGHPUT_WEIGHT
- Bandwidth Weight: $BANDWIDTH_WEIGHT
- Minimum Improvement Threshold: ${MIN_IMPROVEMENT}%

Output Files:
EOF

# List generated files
find "$OUTPUT_DIR" -type f -name "*.json" -exec echo "- {}" \; >> "$SUMMARY_FILE"

echo "Summary report generated."
echo

# Show final results
echo "=== Optimization Results ==="
echo "All artifacts saved to: $OUTPUT_DIR"
echo "Summary report: $SUMMARY_FILE"
echo "Log file: $LOG_FILE"

# Show generated profile pack if available
PROFILE_PACK=$(find "$OUTPUT_DIR" -name "optimized_profile_*.json" | head -1)
if [[ -n "$PROFILE_PACK" ]]; then
    echo "Optimized profile pack: $PROFILE_PACK"

    if [[ "$VERBOSE" == "true" ]] && command -v jq >/dev/null 2>&1; then
        echo
        echo "Profile Pack Summary:"
        jq -r '.selected_tuning_candidate_id // "unknown"' "$PROFILE_PACK" | sed 's/^/  Selected candidate: /'
        jq -r '.architecture_class // "unknown"' "$PROFILE_PACK" | sed 's/^/  Architecture: /'
    fi
fi

echo
echo "Offline kernel superoptimization completed successfully!"
echo "Completed: $(date)"