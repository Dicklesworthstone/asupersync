#!/usr/bin/env bash
# Bounded model-checking runner for asupersync state machines (bd-11g3i).
#
# Usage:
#   scripts/run_model_check.sh [--ci]
#
# Prerequisites:
#   - Java 11+ (for TLC)
#   - TLA+ tools: either `tlc` on PATH or TLA_TOOLS_JAR env var
#
# Options:
#   --ci    CI smoke mode: shorter bounds, structured JSON output
#
# Outputs:
#   formal/tla/output/            Model check artifacts
#   formal/tla/output/result.json Structured result (CI mode)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TLA_DIR="$PROJECT_DIR/formal/tla"
OUTPUT_DIR="$TLA_DIR/output"
SPEC="$TLA_DIR/Asupersync.tla"
CONFIG="$TLA_DIR/Asupersync_MC.cfg"

CI_MODE=false
if [[ "${1:-}" == "--ci" ]]; then
    CI_MODE=true
fi

# Find TLC
find_tlc() {
    if command -v tlc &>/dev/null; then
        echo "tlc"
        return
    fi
    if [[ -n "${TLA_TOOLS_JAR:-}" ]] && [[ -f "$TLA_TOOLS_JAR" ]]; then
        echo "java -jar $TLA_TOOLS_JAR"
        return
    fi
    # Try common locations
    for jar in \
        "$HOME/.tla/tla2tools.jar" \
        "/opt/tla/tla2tools.jar" \
        "/usr/local/lib/tla2tools.jar"; do
        if [[ -f "$jar" ]]; then
            echo "java -jar $jar"
            return
        fi
    done
    return 1
}

mkdir -p "$OUTPUT_DIR"

echo "=== Asupersync Bounded Model Check (bd-11g3i) ==="
echo "Spec:   $SPEC"
echo "Config: $CONFIG"
echo "Output: $OUTPUT_DIR"
echo ""

TLC_CMD=""
if TLC_CMD=$(find_tlc); then
    echo "TLC found: $TLC_CMD"
else
    echo "WARNING: TLC not found. Install TLA+ tools or set TLA_TOOLS_JAR."
    echo ""
    echo "To install:"
    echo "  1. Download tla2tools.jar from https://github.com/tlaplus/tlaplus/releases"
    echo "  2. Set TLA_TOOLS_JAR=/path/to/tla2tools.jar"
    echo "  3. Or: mkdir -p ~/.tla && mv tla2tools.jar ~/.tla/"
    echo ""

    # In CI mode, emit a structured skip result
    if $CI_MODE; then
        cat > "$OUTPUT_DIR/result.json" <<ENDJSON
{
    "status": "skipped",
    "reason": "TLC not installed",
    "spec": "formal/tla/Asupersync.tla",
    "config": "formal/tla/Asupersync_MC.cfg",
    "bead": "bd-11g3i",
    "invariants_checked": [
        "TypeInvariant",
        "WellFormedInvariant",
        "NoOrphanTasks",
        "NoLeakedObligations",
        "CloseImpliesQuiescent"
    ]
}
ENDJSON
        echo "CI result written to $OUTPUT_DIR/result.json"
    fi
    exit 0
fi

# Run TLC
WORKERS="${TLC_WORKERS:-auto}"
DEPTH="${TLC_DEPTH:-100}"

echo "Workers: $WORKERS"
echo "Depth:   $DEPTH"
echo ""

LOGFILE="$OUTPUT_DIR/tlc_$(date +%Y%m%d_%H%M%S).log"

set +e
$TLC_CMD \
    -config "$CONFIG" \
    -workers "$WORKERS" \
    -depth "$DEPTH" \
    -deadlock \
    -terse \
    -cleanup \
    "$SPEC" 2>&1 | tee "$LOGFILE"
TLC_EXIT=$?
set -e

echo ""
echo "TLC exit code: $TLC_EXIT"
echo "Log: $LOGFILE"

# Parse results for CI
if $CI_MODE; then
    STATUS="pass"
    STATES=""
    VIOLATIONS=""

    if [[ $TLC_EXIT -ne 0 ]]; then
        STATUS="fail"
    fi

    # Extract state count from log
    STATES=$(grep -oP '\d+ distinct states found' "$LOGFILE" | grep -oP '\d+' || echo "unknown")
    VIOLATIONS=$(grep -c 'Error:' "$LOGFILE" || echo "0")

    cat > "$OUTPUT_DIR/result.json" <<ENDJSON
{
    "status": "$STATUS",
    "exit_code": $TLC_EXIT,
    "distinct_states": "$STATES",
    "violations": $VIOLATIONS,
    "spec": "formal/tla/Asupersync.tla",
    "config": "formal/tla/Asupersync_MC.cfg",
    "log": "$(basename "$LOGFILE")",
    "bead": "bd-11g3i",
    "invariants_checked": [
        "TypeInvariant",
        "WellFormedInvariant",
        "NoOrphanTasks",
        "NoLeakedObligations",
        "CloseImpliesQuiescent"
    ]
}
ENDJSON
    echo "CI result written to $OUTPUT_DIR/result.json"
fi

exit $TLC_EXIT
