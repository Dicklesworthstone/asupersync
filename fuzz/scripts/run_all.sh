#!/bin/bash
# Run all fuzz targets for a short duration.
# Usage: ./scripts/run_all.sh [duration_seconds]

set -euo pipefail

DURATION="${1:-60}"
FUZZ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RCH_CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_fuzz_run_all}"

cd "$FUZZ_DIR"

TARGETS=(
    fuzz_http1_request
    fuzz_http1_response
    fuzz_hpack_decode
    fuzz_http2_frame
    fuzz_interest_flags
)

echo "Running ${#TARGETS[@]} fuzz targets for ${DURATION}s each..."
echo

for target in "${TARGETS[@]}"; do
    echo "=== Fuzzing: $target ==="
    rch exec -- env CARGO_TARGET_DIR="$RCH_CARGO_TARGET_DIR" cargo +nightly fuzz run "$target" -- -max_total_time="$DURATION" || {
        echo "CRASH FOUND in $target"
        exit 1
    }
    echo
done

echo "All fuzz targets completed successfully!"
