#!/usr/bin/env bash
# SEM-10.1: Contract-projection consistency CI checker
# Verifies that semantic contract rule-ID citations are consistent across layers.
#
# Usage: scripts/check_semantic_consistency.sh [--verbose]
#
# Exit codes:
#   0 = all checks pass
#   1 = consistency violation found
#   2 = script error

set -uo pipefail

VERBOSE="${1:-}"
FAIL_COUNT=0
WARN_COUNT=0
CHECK_COUNT=0

log_pass() { CHECK_COUNT=$((CHECK_COUNT + 1)); [ "$VERBOSE" = "--verbose" ] && echo "  PASS: $1" || true; }
log_fail() { CHECK_COUNT=$((CHECK_COUNT + 1)); FAIL_COUNT=$((FAIL_COUNT + 1)); echo "  FAIL: $1"; }
log_warn() { WARN_COUNT=$((WARN_COUNT + 1)); echo "  WARN: $1"; }

echo "=== SEM-10.1: Semantic Contract Consistency Check ==="
echo ""

# ─── Check 1: Contract docs exist ───────────────────────────────────────────
echo "--- G1: Contract Document Completeness ---"

CONTRACT_FILES=(
    "docs/semantic_contract_schema.md"
    "docs/semantic_contract_glossary.md"
    "docs/semantic_contract_transitions.md"
    "docs/semantic_contract_invariants.md"
    "docs/semantic_contract_versioning.md"
)

for f in "${CONTRACT_FILES[@]}"; do
    if [ -f "$f" ]; then
        log_pass "$f exists"
    else
        log_fail "$f missing"
    fi
done

# ─── Check 2: Rule-ID coverage in contract ──────────────────────────────────
echo ""
echo "--- G1: Rule-ID Coverage ---"

# Check that all 47 rule IDs appear somewhere in the contract docs
RULE_IDS=(
    "rule.cancel.request" "rule.cancel.acknowledge" "rule.cancel.drain"
    "rule.cancel.finalize" "inv.cancel.idempotence" "inv.cancel.propagates_down"
    "def.cancel.reason_kinds" "def.cancel.severity_ordering" "prog.cancel.drains"
    "rule.cancel.checkpoint_masked" "inv.cancel.mask_bounded" "inv.cancel.mask_monotone"
    "rule.obligation.reserve" "rule.obligation.commit" "rule.obligation.abort"
    "rule.obligation.leak" "inv.obligation.no_leak" "inv.obligation.linear"
    "inv.obligation.bounded" "inv.obligation.ledger_empty_on_close" "prog.obligation.resolves"
    "rule.region.close_begin" "rule.region.close_cancel_children"
    "rule.region.close_children_done" "rule.region.close_run_finalizer"
    "rule.region.close_complete" "inv.region.quiescence" "prog.region.close_terminates"
    "def.outcome.four_valued" "def.outcome.severity_lattice"
    "def.outcome.join_semantics" "def.cancel.reason_ordering"
    "inv.ownership.single_owner" "inv.ownership.task_owned"
    "def.ownership.region_tree" "rule.ownership.spawn"
    "comb.join" "comb.race" "comb.timeout"
    "inv.combinator.loser_drained" "law.race.never_abandon"
    "law.join.assoc" "law.race.comm"
    "inv.capability.no_ambient" "def.capability.cx_scope"
    "inv.determinism.replayable" "def.determinism.seed_equivalence"
)

MISSING_RULES=0
for rule_id in "${RULE_IDS[@]}"; do
    if grep -rql "$rule_id" docs/semantic_contract_*.md > /dev/null 2>&1; then
        log_pass "Rule $rule_id found in contract docs"
    else
        log_fail "Rule $rule_id MISSING from contract docs"
        MISSING_RULES=$((MISSING_RULES + 1))
    fi
done

echo "  Rule coverage: $((${#RULE_IDS[@]} - MISSING_RULES))/${#RULE_IDS[@]}"

# ─── Check 3: Capability audit (ADR-006) ────────────────────────────────────
echo ""
echo "--- G6: Capability Audit (ADR-006) ---"

UNSAFE_IN_CX="$(grep -rn '#\[allow(unsafe_code)\]' src/cx/ 2>/dev/null | wc -l | tr -d '[:space:]' || true)"
UNSAFE_IN_CX="${UNSAFE_IN_CX:-0}"
if [ "$UNSAFE_IN_CX" -eq 0 ]; then
    log_pass "No #[allow(unsafe_code)] in src/cx/ (inv.capability.no_ambient)"
else
    log_fail "$UNSAFE_IN_CX instances of #[allow(unsafe_code)] in src/cx/"
fi

# ─── Check 4: Rule-ID annotations in RT (SEM-08.3) ──────────────────────────
echo ""
echo "--- G4: Rule-ID Annotations in Runtime ---"

ANNOTATION_CHECKS=(
    "src/types/cancel.rs:inv.cancel.idempotence"
    "src/runtime/state.rs:inv.cancel.propagates_down"
    "src/lab/oracle/cancellation_protocol.rs:rule.cancel.checkpoint_masked"
    "src/record/obligation.rs:inv.obligation.linear"
    "src/record/region.rs:rule.region.close_run_finalizer"
    "src/types/outcome.rs:def.outcome.join_semantics"
)

for check in "${ANNOTATION_CHECKS[@]}"; do
    file="${check%%:*}"
    rule="${check##*:}"
    if grep -q "$rule" "$file" 2>/dev/null; then
        log_pass "$rule annotation in $file"
    else
        log_fail "$rule annotation MISSING from $file"
    fi
done

# ─── Check 5: Contract version field ────────────────────────────────────────
echo ""
echo "--- G1: Contract Version ---"

if grep -q 'schema_version.*1\.' docs/semantic_contract_schema.md 2>/dev/null; then
    log_pass "Contract schema version present"
else
    log_fail "Contract schema version missing"
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
    exit 1
else
    echo ""
    echo "VERDICT: PASS"
    exit 0
fi
