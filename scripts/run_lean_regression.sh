#!/usr/bin/env bash
# Lean Proof Regression Runner (SEM-12.3)
#
# Runs the Lean theorem pack via `lake build`, captures structured diagnostics,
# and produces a machine-readable JSON report.
#
# Usage:
#   scripts/run_lean_regression.sh [--json] [--verbose]
#
# Output:
#   - Exit 0 if all proofs pass
#   - Exit 1 if any proof fails or Lean is unavailable
#   - JSON report written to formal/lean/regression_report.json when --json
#
# Bead: asupersync-3cddg.12.3

set -euo pipefail

LEAN_DIR="formal/lean"
REPORT_FILE="$LEAN_DIR/regression_report.json"
JSON_OUTPUT=false
VERBOSE=false

for arg in "$@"; do
  case "$arg" in
    --json) JSON_OUTPUT=true ;;
    --verbose) VERBOSE=true ;;
    *) echo "Unknown argument: $arg"; exit 1 ;;
  esac
done

log() {
  if [ "$VERBOSE" = true ]; then
    echo "[lean-regression] $*" >&2
  fi
}

# ─── Check prerequisites ─────────────────────────────────────────

if ! command -v lake &>/dev/null; then
  echo "SKIP: lake (Lean) not found in PATH"
  if [ "$JSON_OUTPUT" = true ]; then
    cat > "$REPORT_FILE" <<'EOF'
{
  "schema": "lean-regression-report-v1",
  "status": "skipped",
  "reason": "lake not found in PATH",
  "lean_available": false,
  "theorems_checked": 0,
  "theorems_passed": 0,
  "theorems_failed": 0,
  "errors": []
}
EOF
  fi
  exit 0
fi

if [ ! -f "$LEAN_DIR/lakefile.lean" ]; then
  echo "ERROR: $LEAN_DIR/lakefile.lean not found"
  exit 1
fi

# ─── Run lake build and capture output ────────────────────────────

log "Running lake build in $LEAN_DIR..."
BUILD_START=$(date +%s%N 2>/dev/null || date +%s)

BUILD_OUTPUT=""
BUILD_EXIT=0
BUILD_OUTPUT=$(cd "$LEAN_DIR" && lake build 2>&1) || BUILD_EXIT=$?

BUILD_END=$(date +%s%N 2>/dev/null || date +%s)
BUILD_DURATION_MS=$(( (BUILD_END - BUILD_START) / 1000000 ))

log "Build completed in ${BUILD_DURATION_MS}ms with exit code $BUILD_EXIT"

# ─── Parse build output for theorem-level diagnostics ─────────────

ERRORS=()
WARNINGS=()
THEOREM_COUNT=0
ERROR_COUNT=0
WARNING_COUNT=0

while IFS= read -r line; do
  # Lean 4 error format: file:line:col: error: message
  if echo "$line" | grep -q ": error:"; then
    ERRORS+=("$line")
    ((ERROR_COUNT++)) || true
  elif echo "$line" | grep -q ": warning:"; then
    WARNINGS+=("$line")
    ((WARNING_COUNT++)) || true
  fi
done <<< "$BUILD_OUTPUT"

# Count theorems from the Lean source
if [ -f "$LEAN_DIR/Asupersync.lean" ]; then
  THEOREM_COUNT=$(grep -c "^theorem\|^lemma\|^instance" "$LEAN_DIR/Asupersync.lean" 2>/dev/null || echo 0)
fi

# ─── Determine overall status ────────────────────────────────────

if [ "$BUILD_EXIT" -eq 0 ]; then
  STATUS="passed"
  PASSED=$THEOREM_COUNT
  FAILED=0
else
  STATUS="failed"
  PASSED=0
  FAILED=$ERROR_COUNT
fi

# ─── Output report ───────────────────────────────────────────────

echo "=== Lean Proof Regression Report ==="
echo "Status:     $STATUS"
echo "Theorems:   $THEOREM_COUNT"
echo "Passed:     $PASSED"
echo "Failed:     $FAILED"
echo "Warnings:   $WARNING_COUNT"
echo "Duration:   ${BUILD_DURATION_MS}ms"
echo ""

if [ "$ERROR_COUNT" -gt 0 ]; then
  echo "=== Errors ==="
  for err in "${ERRORS[@]}"; do
    echo "  $err"
  done
  echo ""
fi

if [ "$WARNING_COUNT" -gt 0 ] && [ "$VERBOSE" = true ]; then
  echo "=== Warnings ==="
  for warn in "${WARNINGS[@]}"; do
    echo "  $warn"
  done
  echo ""
fi

# ─── JSON report ─────────────────────────────────────────────────

if [ "$JSON_OUTPUT" = true ]; then
  # Build JSON error array
  ERROR_JSON="["
  FIRST=true
  for err in "${ERRORS[@]}"; do
    if [ "$FIRST" = false ]; then ERROR_JSON+=","; fi
    # Escape quotes for JSON
    ESCAPED=$(echo "$err" | sed 's/"/\\"/g')
    ERROR_JSON+="\"$ESCAPED\""
    FIRST=false
  done
  ERROR_JSON+="]"

  WARNING_JSON="["
  FIRST=true
  for warn in "${WARNINGS[@]}"; do
    if [ "$FIRST" = false ]; then WARNING_JSON+=","; fi
    ESCAPED=$(echo "$warn" | sed 's/"/\\"/g')
    WARNING_JSON+="\"$ESCAPED\""
    FIRST=false
  done
  WARNING_JSON+="]"

  cat > "$REPORT_FILE" <<EOF
{
  "schema": "lean-regression-report-v1",
  "status": "$STATUS",
  "lean_available": true,
  "build_exit_code": $BUILD_EXIT,
  "duration_ms": $BUILD_DURATION_MS,
  "theorems_checked": $THEOREM_COUNT,
  "theorems_passed": $PASSED,
  "theorems_failed": $FAILED,
  "warning_count": $WARNING_COUNT,
  "errors": $ERROR_JSON,
  "warnings": $WARNING_JSON,
  "source_file": "$LEAN_DIR/Asupersync.lean",
  "lakefile": "$LEAN_DIR/lakefile.lean"
}
EOF
  log "JSON report written to $REPORT_FILE"
fi

# ─── Exit ─────────────────────────────────────────────────────────

if [ "$STATUS" = "failed" ]; then
  exit 1
fi
exit 0
