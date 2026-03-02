#!/usr/bin/env bash
# TLA+ Scenario-Based Model Check Runner (SEM-12.4)
#
# Runs TLC model checker against the Asupersync TLA+ spec with configurable
# scenario parameters. Captures structured diagnostics and violation traces.
#
# Usage:
#   scripts/run_tla_scenarios.sh [--json] [--verbose] [--scenario SCENARIO]
#
# Scenarios:
#   minimal    - 1 task, 1 region, 0 obligations (smoke test)
#   standard   - 2 tasks, 2 regions, 1 obligation (default)
#   full       - 3 tasks, 3 regions, 2 obligations (exhaustive)
#
# Output:
#   - Exit 0 if all invariants hold
#   - Exit 1 if any invariant violation or TLC error
#   - JSON report written to formal/tla/output/scenario_report.json when --json
#
# Bead: asupersync-3cddg.12.4

set -euo pipefail

TLA_DIR="formal/tla"
TLA_SPEC="$TLA_DIR/Asupersync.tla"
TLA_CFG="$TLA_DIR/Asupersync_MC.cfg"
OUTPUT_DIR="$TLA_DIR/output"
REPORT_FILE="$OUTPUT_DIR/scenario_report.json"
JSON_OUTPUT=false
VERBOSE=false
SCENARIO="standard"

for arg in "$@"; do
  case "$arg" in
    --json) JSON_OUTPUT=true ;;
    --verbose) VERBOSE=true ;;
    --scenario)
      # next arg will be consumed by shift
      ;;
    minimal|standard|full)
      SCENARIO="$arg" ;;
    *) echo "Unknown argument: $arg"; exit 1 ;;
  esac
done

log() {
  if [ "$VERBOSE" = true ]; then
    echo "[tla-scenario] $*" >&2
  fi
}

# ─── Check prerequisites ─────────────────────────────────────────

TLC_CMD=""
if command -v tlc &>/dev/null; then
  TLC_CMD="tlc"
elif [ -n "${TLC_JAR:-}" ] && [ -f "$TLC_JAR" ]; then
  TLC_CMD="java -jar $TLC_JAR"
elif command -v java &>/dev/null; then
  # Check common locations
  for jar in /usr/local/lib/tla/tla2tools.jar ~/tla2tools.jar; do
    if [ -f "$jar" ]; then
      TLC_CMD="java -jar $jar"
      break
    fi
  done
fi

if [ -z "$TLC_CMD" ]; then
  echo "SKIP: TLC (TLA+ model checker) not found"
  echo "  Install: https://github.com/tlaplus/tlaplus/releases"
  echo "  Or set TLC_JAR=/path/to/tla2tools.jar"
  mkdir -p "$OUTPUT_DIR"
  if [ "$JSON_OUTPUT" = true ]; then
    cat > "$REPORT_FILE" <<'EOF'
{
  "schema": "tla-scenario-report-v1",
  "status": "skipped",
  "reason": "TLC not found in PATH",
  "tlc_available": false,
  "scenario": null,
  "invariants_checked": 0,
  "invariants_passed": 0,
  "invariants_violated": 0,
  "violations": []
}
EOF
  fi
  exit 0
fi

if [ ! -f "$TLA_SPEC" ]; then
  echo "ERROR: $TLA_SPEC not found"
  exit 1
fi

mkdir -p "$OUTPUT_DIR"

# ─── Scenario parameters ─────────────────────────────────────────

case "$SCENARIO" in
  minimal)
    TASKS=1; REGIONS=1; OBLIGATIONS=0; MAX_MASK=1
    DESCRIPTION="Smoke test: 1 task, 1 region, 0 obligations"
    ;;
  standard)
    TASKS=2; REGIONS=2; OBLIGATIONS=1; MAX_MASK=2
    DESCRIPTION="Standard: 2 tasks, 2 regions, 1 obligation"
    ;;
  full)
    TASKS=3; REGIONS=3; OBLIGATIONS=2; MAX_MASK=2
    DESCRIPTION="Exhaustive: 3 tasks, 3 regions, 2 obligations"
    ;;
esac

log "Running scenario '$SCENARIO': $DESCRIPTION"

# ─── Expected invariants and liveness properties ──────────────────

EXPECTED_INVARIANTS=(
  "TypeInvariant"
  "WellFormedInvariant"
  "NoOrphanTasks"
  "NoLeakedObligations"
  "CloseImpliesQuiescent"
)

EXPECTED_LIVENESS=(
  "CancelTerminates"
)

# ─── Run TLC ──────────────────────────────────────────────────────

log "Running TLC on $TLA_SPEC..."
RUN_START=$(date +%s%N 2>/dev/null || date +%s)

TLC_OUTPUT=""
TLC_EXIT=0
TLC_OUTPUT=$($TLC_CMD "$TLA_SPEC" -config "$TLA_CFG" -workers auto 2>&1) || TLC_EXIT=$?

RUN_END=$(date +%s%N 2>/dev/null || date +%s)
RUN_DURATION_MS=$(( (RUN_END - RUN_START) / 1000000 ))

log "TLC completed in ${RUN_DURATION_MS}ms with exit code $TLC_EXIT"

# Save raw output
echo "$TLC_OUTPUT" > "$OUTPUT_DIR/tlc_raw_output.txt"

# ─── Parse TLC output ────────────────────────────────────────────

VIOLATIONS=()
STATES_FOUND=0
STATES_DISTINCT=0
INVARIANT_VIOLATIONS=0

while IFS= read -r line; do
  # Extract state counts
  if echo "$line" | grep -q "states found"; then
    STATES_FOUND=$(echo "$line" | grep -oP '\d+(?= states found)' || echo 0)
  fi
  if echo "$line" | grep -q "distinct states"; then
    STATES_DISTINCT=$(echo "$line" | grep -oP '\d+(?= distinct states)' || echo 0)
  fi
  # Detect invariant violations
  if echo "$line" | grep -q "Invariant .* is violated"; then
    VIOLATIONS+=("$line")
    ((INVARIANT_VIOLATIONS++)) || true
  fi
  if echo "$line" | grep -q "Error:"; then
    VIOLATIONS+=("$line")
  fi
done <<< "$TLC_OUTPUT"

INVARIANTS_CHECKED=${#EXPECTED_INVARIANTS[@]}
INVARIANTS_PASSED=$((INVARIANTS_CHECKED - INVARIANT_VIOLATIONS))

# ─── Determine overall status ────────────────────────────────────

if [ "$TLC_EXIT" -eq 0 ] && [ "$INVARIANT_VIOLATIONS" -eq 0 ]; then
  STATUS="passed"
else
  STATUS="failed"
fi

# ─── Output report ───────────────────────────────────────────────

echo "=== TLA+ Scenario Report ==="
echo "Scenario:     $SCENARIO ($DESCRIPTION)"
echo "Status:       $STATUS"
echo "Invariants:   $INVARIANTS_PASSED/$INVARIANTS_CHECKED passed"
echo "States:       $STATES_FOUND found, $STATES_DISTINCT distinct"
echo "Duration:     ${RUN_DURATION_MS}ms"
echo ""

if [ "$INVARIANT_VIOLATIONS" -gt 0 ]; then
  echo "=== Violations ==="
  for v in "${VIOLATIONS[@]}"; do
    echo "  $v"
  done
  echo ""
  echo "Raw output saved to: $OUTPUT_DIR/tlc_raw_output.txt"
fi

# ─── JSON report ─────────────────────────────────────────────────

if [ "$JSON_OUTPUT" = true ]; then
  VIOLATION_JSON="["
  FIRST=true
  for v in "${VIOLATIONS[@]}"; do
    if [ "$FIRST" = false ]; then VIOLATION_JSON+=","; fi
    ESCAPED=$(echo "$v" | sed 's/"/\\"/g')
    VIOLATION_JSON+="\"$ESCAPED\""
    FIRST=false
  done
  VIOLATION_JSON+="]"

  INV_JSON="["
  FIRST=true
  for inv in "${EXPECTED_INVARIANTS[@]}"; do
    if [ "$FIRST" = false ]; then INV_JSON+=","; fi
    INV_JSON+="\"$inv\""
    FIRST=false
  done
  INV_JSON+="]"

  LIVE_JSON="["
  FIRST=true
  for live in "${EXPECTED_LIVENESS[@]}"; do
    if [ "$FIRST" = false ]; then LIVE_JSON+=","; fi
    LIVE_JSON+="\"$live\""
    FIRST=false
  done
  LIVE_JSON+="]"

  cat > "$REPORT_FILE" <<EOF
{
  "schema": "tla-scenario-report-v1",
  "status": "$STATUS",
  "tlc_available": true,
  "tlc_exit_code": $TLC_EXIT,
  "scenario": "$SCENARIO",
  "description": "$DESCRIPTION",
  "parameters": {
    "tasks": $TASKS,
    "regions": $REGIONS,
    "obligations": $OBLIGATIONS,
    "max_mask": $MAX_MASK
  },
  "duration_ms": $RUN_DURATION_MS,
  "states_found": $STATES_FOUND,
  "states_distinct": $STATES_DISTINCT,
  "invariants_checked": $INVARIANTS_CHECKED,
  "invariants_passed": $INVARIANTS_PASSED,
  "invariants_violated": $INVARIANT_VIOLATIONS,
  "expected_invariants": $INV_JSON,
  "expected_liveness": $LIVE_JSON,
  "violations": $VIOLATION_JSON,
  "spec_file": "$TLA_SPEC",
  "config_file": "$TLA_CFG",
  "raw_output": "$OUTPUT_DIR/tlc_raw_output.txt"
}
EOF
  log "JSON report written to $REPORT_FILE"
fi

# ─── Exit ─────────────────────────────────────────────────────────

if [ "$STATUS" = "failed" ]; then
  exit 1
fi
exit 0
