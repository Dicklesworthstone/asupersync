#!/bin/bash
# Replay a specific seed/crash file through a fuzz target.
# Usage: ./scripts/replay_seed.sh <target> <seed_file>
#
# This is useful for:
# - Reproducing crashes from CI
# - Verifying a bug is fixed
# - Debugging with additional logging

set -euo pipefail

if [ $# -lt 2 ]; then
    echo "Usage: $0 <target> <seed_file>"
    echo ""
    echo "Example:"
    echo "  $0 fuzz_http2_frame artifacts/fuzz_http2_frame/crash-abc123"
    exit 1
fi

TARGET="$1"
SEED_FILE="$2"
FUZZ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RCH_CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_fuzz_replay_seed}"

cd "$FUZZ_DIR"

if [ ! -f "$SEED_FILE" ]; then
    echo "Error: Seed file not found: $SEED_FILE"
    exit 1
fi

echo "Replaying seed through $TARGET..."
echo "Seed file: $SEED_FILE"
echo "Seed size: $(wc -c < "$SEED_FILE") bytes"
echo "Seed hex (first 64 bytes):"
xxd -l 64 "$SEED_FILE" 2>/dev/null || hexdump -C -n 64 "$SEED_FILE" 2>/dev/null || true
echo ""

# Build with debug symbols
rch exec -- env CARGO_TARGET_DIR="$RCH_CARGO_TARGET_DIR" cargo +nightly fuzz run "$TARGET" -- "$SEED_FILE" -runs=1

echo "Replay completed successfully."
