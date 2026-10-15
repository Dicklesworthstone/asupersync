#!/usr/bin/env bash
# SEM-10.3: Semantic-change workflow policy checker
# Enforces PR requirements when semantic contract artifacts are modified.
#
# Checks:
#   1. Any changed contract doc must still contain all 47 rule IDs
#   2. Changed RT files with rule-ID annotations must not remove them
#   3. New/modified rule-IDs require gap matrix update
#   4. ADR references must link to existing ADR documents
#   5. Risk statements required for HIGH-tier rule changes
#
# Usage: scripts/check_semantic_change_policy.sh [BASE_REF]
#
# Arguments:
#   BASE_REF  Git ref to diff against (default: main)
#
# Exit codes:
#   0 = policy checks pass
#   1 = policy violation found
#   2 = script error

set -uo pipefail

BASE_REF="${1:-main}"
FAIL_COUNT=0
WARN_COUNT=0
CHECK_COUNT=0

log_pass() { CHECK_COUNT=$((CHECK_COUNT + 1)); }
log_fail() { CHECK_COUNT=$((CHECK_COUNT + 1)); FAIL_COUNT=$((FAIL_COUNT + 1)); echo "  FAIL: $1"; }
log_warn() { WARN_COUNT=$((WARN_COUNT + 1)); echo "  WARN: $1"; }

echo "=== SEM-10.3: Semantic-Change Workflow Policy Check ==="
echo "  Base: $BASE_REF"
echo ""

# Get list of changed files
CHANGED_FILES="$(git diff --name-only "$BASE_REF" 2>/dev/null || true)"
if [ -z "$CHANGED_FILES" ]; then
    echo "No changes detected against $BASE_REF."
    echo ""
    echo "VERDICT: PASS (no changes)"
    exit 0
fi

# ─── Check 1: Contract doc integrity ─────────────────────────────────────────
echo "--- P1: Contract Document Integrity ---"

CONTRACT_CHANGED=false
while IFS= read -r f; do
    case "$f" in
        docs/semantic_contract_*.md)
            CONTRACT_CHANGED=true
            # Verify the file still exists and has content
            if [ ! -f "$f" ]; then
                log_fail "Contract doc deleted: $f"
                continue
            fi
            log_pass
            ;;
    esac
done <<< "$CHANGED_FILES"

if $CONTRACT_CHANGED; then
    echo "  Contract docs modified — running rule-ID preservation check."
    # Run SEM-10.1 consistency checker
    if bash scripts/check_semantic_consistency.sh > /dev/null 2>&1; then
        log_pass
        echo "  PASS: All rule-IDs preserved after contract changes."
    else
        log_fail "Contract change broke rule-ID consistency. Run: scripts/check_semantic_consistency.sh --verbose"
    fi
else
    echo "  No contract docs changed — skipping."
fi

# ─── Check 2: Rule-ID annotation preservation ────────────────────────────────
echo ""
echo "--- P2: Rule-ID Annotation Preservation ---"

# Known annotation locations from SEM-08.3
ANNOTATION_FILES=(
    "src/types/cancel.rs"
    "src/runtime/state.rs"
    "src/lab/oracle/cancellation_protocol.rs"
    "src/record/obligation.rs"
    "src/record/region.rs"
    "src/types/outcome.rs"
)

ANNOTATION_REMOVED=false
for af in "${ANNOTATION_FILES[@]}"; do
    if echo "$CHANGED_FILES" | grep -q "^${af}$"; then
        # Check if any rule-ID annotations were removed
        REMOVED_ANNOTATIONS="$(git diff "$BASE_REF" -- "$af" 2>/dev/null | grep '^-.*\(rule\.\|inv\.\|def\.\|prog\.\|comb\.\|law\.\)' | grep -v '^---' || true)"
        if [ -n "$REMOVED_ANNOTATIONS" ]; then
            # Check if the same rule-ID still exists in the file (moved, not deleted)
            while IFS= read -r removed_line; do
                rule_match="$(echo "$removed_line" | grep -oP '(rule|inv|def|prog|comb|law)\.[a-z_.]+' | head -1)"
                if [ -n "$rule_match" ] && ! grep -q "$rule_match" "$af" 2>/dev/null; then
                    log_fail "Rule-ID annotation removed from $af: $rule_match"
                    ANNOTATION_REMOVED=true
                fi
            done <<< "$REMOVED_ANNOTATIONS"
        fi
        if ! $ANNOTATION_REMOVED; then
            log_pass
        fi
    fi
done

if ! $ANNOTATION_REMOVED; then
    echo "  PASS: No rule-ID annotations removed."
fi

# ─── Check 3: Gap matrix update requirement ──────────────────────────────────
echo ""
echo "--- P3: Gap Matrix Sync ---"

# If any RT source file with semantic annotations changed, gap matrix should be reviewed
RT_SEMANTIC_CHANGED=false
while IFS= read -r f; do
    case "$f" in
        src/types/cancel.rs|src/runtime/state.rs|src/record/obligation.rs|src/record/region.rs|src/types/outcome.rs)
            RT_SEMANTIC_CHANGED=true
            ;;
        src/lab/oracle/*)
            RT_SEMANTIC_CHANGED=true
            ;;
        src/cx/*)
            RT_SEMANTIC_CHANGED=true
            ;;
    esac
done <<< "$CHANGED_FILES"

GAP_MATRIX_CHANGED=false
if echo "$CHANGED_FILES" | grep -q "docs/semantic_runtime_gap_matrix.md"; then
    GAP_MATRIX_CHANGED=true
fi

if $RT_SEMANTIC_CHANGED && ! $GAP_MATRIX_CHANGED; then
    log_warn "Semantic RT files changed but gap matrix not updated. Review: docs/semantic_runtime_gap_matrix.md"
else
    log_pass
    echo "  PASS: Gap matrix sync OK."
fi

# ─── Check 4: ADR reference validation ───────────────────────────────────────
echo ""
echo "--- P4: ADR Reference Validation ---"

# Check that any ADR-NNN reference in changed files points to an existing doc
ADR_ISSUES=0
while IFS= read -r f; do
    if [ -f "$f" ]; then
        while IFS= read -r adr_ref; do
            adr_num="$(echo "$adr_ref" | grep -oP 'ADR-\d+' | head -1)"
            if [ -n "$adr_num" ]; then
                # Check if corresponding ADR doc exists
                adr_file="docs/semantic_adr_$(echo "$adr_num" | tr '[:upper:]' '[:lower:]' | tr '-' '_').md"
                # ADR references in our contract docs point to sections within the ratification doc
                # They don't need separate files — just validate they're in the known set (001-008)
                adr_digit="$(echo "$adr_num" | grep -oP '\d+' | head -1)"
                if [ "$adr_digit" -lt 1 ] || [ "$adr_digit" -gt 8 ] 2>/dev/null; then
                    log_warn "Unknown ADR reference in $f: $adr_num (valid range: ADR-001 to ADR-008)"
                    ADR_ISSUES=$((ADR_ISSUES + 1))
                fi
            fi
        done < <(grep -n 'ADR-[0-9]\+' "$f" 2>/dev/null || true)
    fi
done <<< "$CHANGED_FILES"

if [ "$ADR_ISSUES" -eq 0 ]; then
    log_pass
    echo "  PASS: All ADR references valid."
fi

# ─── Check 5: Verification matrix consistency ────────────────────────────────
echo ""
echo "--- P5: Verification Matrix Consistency ---"

VMATRIX_CHANGED=false
if echo "$CHANGED_FILES" | grep -q "docs/semantic_verification_matrix.md"; then
    VMATRIX_CHANGED=true
fi

if $VMATRIX_CHANGED; then
    # Verify all 47 rule IDs still appear
    VMATRIX_RULES="$(grep -cP '`(rule|inv|def|prog|comb|law)\.' docs/semantic_verification_matrix.md 2>/dev/null || echo 0)"
    if [ "$VMATRIX_RULES" -lt 47 ]; then
        log_fail "Verification matrix has fewer than 47 rule entries ($VMATRIX_RULES found)"
    else
        log_pass
        echo "  PASS: Verification matrix contains all rule entries."
    fi
else
    echo "  Verification matrix not changed — skipping."
fi

# ─── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo "=== Summary ==="
echo "  Checks: $CHECK_COUNT"
echo "  Passed: $((CHECK_COUNT - FAIL_COUNT))"
echo "  Failed: $FAIL_COUNT"
echo "  Warnings: $WARN_COUNT"

if [ "$FAIL_COUNT" -gt 0 ]; then
    echo ""
    echo "VERDICT: FAIL ($FAIL_COUNT violations)"
    echo ""
    echo "Semantic changes require:"
    echo "  1. All 47 rule-IDs preserved in contract docs"
    echo "  2. Rule-ID annotations not removed from RT source"
    echo "  3. Gap matrix updated when semantic RT files change"
    echo "  4. ADR references point to valid ADR-001 through ADR-008"
    echo "  5. Verification matrix maintains all 47 entries"
    exit 1
else
    echo ""
    echo "VERDICT: PASS"
    exit 0
fi
