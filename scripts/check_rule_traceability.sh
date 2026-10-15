#!/usr/bin/env bash
# SEM-10.2: Rule-traceability completeness checker
# Verifies that every canonical rule-ID has required artifact links across layers.
#
# For each of the 47 rule IDs, checks:
#   1. CONTRACT: Present in docs/semantic_contract_*.md
#   2. GAP-MATRIX: Present in docs/semantic_runtime_gap_matrix.md
#   3. RT-SOURCE: Present in src/**/*.rs (annotation or implementation reference)
#   4. TESTS: Present in tests/**/*.rs or src/**/test*.rs
#
# Rules classified SCOPE-OUT in the gap matrix are exempt from RT-SOURCE and TESTS.
#
# Usage: scripts/check_rule_traceability.sh [--verbose] [--strict]
#
# Flags:
#   --verbose   Show PASS results in addition to failures
#   --strict    Treat warnings as failures (for CI enforcement)
#
# Exit codes:
#   0 = all checks pass
#   1 = traceability violation found
#   2 = script error

set -uo pipefail

VERBOSE=false
STRICT=false
for arg in "$@"; do
    case "$arg" in
        --verbose) VERBOSE=true ;;
        --strict) STRICT=true ;;
    esac
done

FAIL_COUNT=0
WARN_COUNT=0
PASS_COUNT=0
RULE_FAIL_COUNT=0
TOTAL_RULES=0

log_pass() { PASS_COUNT=$((PASS_COUNT + 1)); $VERBOSE && echo "    PASS: $1" || true; }
log_fail() { FAIL_COUNT=$((FAIL_COUNT + 1)); echo "    FAIL: $1"; }
log_warn() { WARN_COUNT=$((WARN_COUNT + 1)); echo "    WARN: $1"; }

echo "=== SEM-10.2: Rule-Traceability Completeness Check ==="
echo ""

# ─── Canonical rule registry ─────────────────────────────────────────────────
# Format: "RULE_ID:EXPECTED_GAP_CLASS"
# Gap classes: ALIGNED, DOC-GAP, TEST-GAP, SCOPE-OUT
# SCOPE-OUT rules are exempt from RT-SOURCE and TESTS checks.
RULES=(
    "rule.cancel.request:ALIGNED"
    "rule.cancel.acknowledge:ALIGNED"
    "rule.cancel.drain:ALIGNED"
    "rule.cancel.finalize:ALIGNED"
    "inv.cancel.idempotence:ALIGNED"
    "inv.cancel.propagates_down:ALIGNED"
    "def.cancel.reason_kinds:ALIGNED"
    "def.cancel.severity_ordering:ALIGNED"
    "prog.cancel.drains:ALIGNED"
    "rule.cancel.checkpoint_masked:ALIGNED"
    "inv.cancel.mask_bounded:ALIGNED"
    "inv.cancel.mask_monotone:ALIGNED"
    "rule.obligation.reserve:ALIGNED"
    "rule.obligation.commit:ALIGNED"
    "rule.obligation.abort:ALIGNED"
    "rule.obligation.leak:ALIGNED"
    "inv.obligation.no_leak:ALIGNED"
    "inv.obligation.linear:ALIGNED"
    "inv.obligation.bounded:ALIGNED"
    "inv.obligation.ledger_empty_on_close:ALIGNED"
    "prog.obligation.resolves:ALIGNED"
    "rule.region.close_begin:ALIGNED"
    "rule.region.close_cancel_children:ALIGNED"
    "rule.region.close_children_done:ALIGNED"
    "rule.region.close_run_finalizer:ALIGNED"
    "rule.region.close_complete:ALIGNED"
    "inv.region.quiescence:ALIGNED"
    "prog.region.close_terminates:ALIGNED"
    "def.outcome.four_valued:ALIGNED"
    "def.outcome.severity_lattice:ALIGNED"
    "def.outcome.join_semantics:ALIGNED"
    "def.cancel.reason_ordering:ALIGNED"
    "inv.ownership.single_owner:ALIGNED"
    "inv.ownership.task_owned:ALIGNED"
    "def.ownership.region_tree:ALIGNED"
    "rule.ownership.spawn:ALIGNED"
    "comb.join:ALIGNED"
    "comb.race:ALIGNED"
    "comb.timeout:ALIGNED"
    "inv.combinator.loser_drained:ALIGNED"
    "law.race.never_abandon:ALIGNED"
    "law.join.assoc:ALIGNED"
    "law.race.comm:ALIGNED"
    "inv.capability.no_ambient:SCOPE-OUT"
    "def.capability.cx_scope:SCOPE-OUT"
    "inv.determinism.replayable:ALIGNED"
    "def.determinism.seed_equivalence:ALIGNED"
)

# ─── Per-rule traceability check ──────────────────────────────────────────────
echo "--- Per-Rule Artifact Traceability ---"
echo ""

for entry in "${RULES[@]}"; do
    rule_id="${entry%%:*}"
    gap_class="${entry##*:}"
    TOTAL_RULES=$((TOTAL_RULES + 1))
    missing_links=()

    # 1. CONTRACT: present in semantic contract docs?
    if grep -rql "$rule_id" docs/semantic_contract_*.md > /dev/null 2>&1; then
        log_pass "$rule_id → CONTRACT"
    else
        missing_links+=("CONTRACT")
    fi

    # 2. GAP-MATRIX: present in gap matrix?
    if grep -q "$rule_id" docs/semantic_runtime_gap_matrix.md 2>/dev/null; then
        log_pass "$rule_id → GAP-MATRIX"
    else
        missing_links+=("GAP-MATRIX")
    fi

    # 3. RT-SOURCE: present in src/**/*.rs? (skip for SCOPE-OUT)
    if [ "$gap_class" = "SCOPE-OUT" ]; then
        log_pass "$rule_id → RT-SOURCE (SCOPE-OUT exempt)"
    elif grep -rql "$rule_id" src/ --include='*.rs' > /dev/null 2>&1; then
        log_pass "$rule_id → RT-SOURCE"
    else
        # RT source annotation is desirable but only a warning for rules that
        # are implementation-implicit (e.g. structural invariants enforced by types)
        missing_links+=("RT-SOURCE")
    fi

    # 4. TESTS: present in tests/**/*.rs? (skip for SCOPE-OUT)
    if [ "$gap_class" = "SCOPE-OUT" ]; then
        log_pass "$rule_id → TESTS (SCOPE-OUT exempt)"
    elif grep -rql "$rule_id" tests/ --include='*.rs' > /dev/null 2>&1; then
        log_pass "$rule_id → TESTS"
    elif grep -rql "$rule_id" src/ --include='*test*.rs' > /dev/null 2>&1; then
        log_pass "$rule_id → TESTS (inline)"
    else
        missing_links+=("TESTS")
    fi

    # Report per-rule result
    if [ ${#missing_links[@]} -eq 0 ]; then
        $VERBOSE && echo "  [OK] $rule_id ($gap_class): all links present" || true
    else
        link_list=""
        for ml in "${missing_links[@]}"; do
            link_list="${link_list:+$link_list, }$ml"
        done

        # CONTRACT and GAP-MATRIX missing = hard fail
        # RT-SOURCE and TESTS missing = warn (unless --strict)
        has_hard_fail=false
        for ml in "${missing_links[@]}"; do
            if [ "$ml" = "CONTRACT" ] || [ "$ml" = "GAP-MATRIX" ]; then
                has_hard_fail=true
                break
            fi
        done

        if $has_hard_fail; then
            echo "  [FAIL] $rule_id ($gap_class): missing → $link_list"
            RULE_FAIL_COUNT=$((RULE_FAIL_COUNT + 1))
            for ml in "${missing_links[@]}"; do
                log_fail "$rule_id missing $ml link"
            done
        elif $STRICT; then
            echo "  [FAIL] $rule_id ($gap_class): missing → $link_list (strict mode)"
            RULE_FAIL_COUNT=$((RULE_FAIL_COUNT + 1))
            for ml in "${missing_links[@]}"; do
                log_fail "$rule_id missing $ml link"
            done
        else
            echo "  [WARN] $rule_id ($gap_class): missing → $link_list"
            for ml in "${missing_links[@]}"; do
                log_warn "$rule_id missing $ml link"
            done
        fi
    fi
done

# ─── Cross-check: orphaned rule-IDs in RT not in registry ────────────────────
echo ""
echo "--- Orphan Detection: RT Rule-IDs Not in Registry ---"

# Extract rule-ID-like patterns from src/ and check they're in our registry
KNOWN_RULES=""
for entry in "${RULES[@]}"; do
    KNOWN_RULES="$KNOWN_RULES ${entry%%:*}"
done

ORPHAN_COUNT=0
# Only match patterns in the semantic contract namespace domains
SEM_DOMAINS="cancel|obligation|region|outcome|ownership|combinator|capability|determinism"
while IFS= read -r line; do
    rule_match="$(echo "$line" | grep -oP "(rule|inv|def|prog)\\.($SEM_DOMAINS)\\.[a-z_]+" | head -1)"
    if [ -n "$rule_match" ]; then
        if ! echo "$KNOWN_RULES" | grep -qw "$rule_match"; then
            log_warn "Potential orphan rule-ID in RT: $rule_match (in $(echo "$line" | cut -d: -f1))"
            ORPHAN_COUNT=$((ORPHAN_COUNT + 1))
        fi
    fi
done < <(grep -rn "\\(rule\\|inv\\|def\\|prog\\)\\.\\(cancel\\|obligation\\|region\\|outcome\\|ownership\\|combinator\\|capability\\|determinism\\)\\." src/ --include='*.rs' 2>/dev/null || true)

if [ "$ORPHAN_COUNT" -eq 0 ]; then
    log_pass "No orphaned rule-IDs in RT source"
else
    echo "  Found $ORPHAN_COUNT potential orphan rule-ID(s)"
fi

# ─── Traceability coverage summary ───────────────────────────────────────────
echo ""
echo "--- Traceability Coverage Summary ---"

# Count per-link-type coverage
CONTRACT_HIT=0; GAP_HIT=0; RT_HIT=0; TEST_HIT=0
for entry in "${RULES[@]}"; do
    rule_id="${entry%%:*}"
    gap_class="${entry##*:}"

    grep -rql "$rule_id" docs/semantic_contract_*.md > /dev/null 2>&1 && CONTRACT_HIT=$((CONTRACT_HIT + 1))
    grep -q "$rule_id" docs/semantic_runtime_gap_matrix.md 2>/dev/null && GAP_HIT=$((GAP_HIT + 1))

    if [ "$gap_class" = "SCOPE-OUT" ]; then
        RT_HIT=$((RT_HIT + 1))
        TEST_HIT=$((TEST_HIT + 1))
    else
        grep -rql "$rule_id" src/ --include='*.rs' > /dev/null 2>&1 && RT_HIT=$((RT_HIT + 1))
        if grep -rql "$rule_id" tests/ --include='*.rs' > /dev/null 2>&1; then
            TEST_HIT=$((TEST_HIT + 1))
        elif grep -rql "$rule_id" src/ --include='*test*.rs' > /dev/null 2>&1; then
            TEST_HIT=$((TEST_HIT + 1))
        fi
    fi
done

echo "  CONTRACT:   $CONTRACT_HIT/$TOTAL_RULES"
echo "  GAP-MATRIX: $GAP_HIT/$TOTAL_RULES"
echo "  RT-SOURCE:  $RT_HIT/$TOTAL_RULES"
echo "  TESTS:      $TEST_HIT/$TOTAL_RULES"

# ─── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo "=== Summary ==="
echo "  Rules checked: $TOTAL_RULES"
echo "  Rules with complete traceability: $((TOTAL_RULES - RULE_FAIL_COUNT))"
echo "  Rules with broken links: $RULE_FAIL_COUNT"
echo "  Individual link checks: $((PASS_COUNT + FAIL_COUNT))"
echo "  Passed: $PASS_COUNT"
echo "  Failed: $FAIL_COUNT"
echo "  Warnings: $WARN_COUNT"

EFFECTIVE_FAIL=$FAIL_COUNT
if $STRICT; then
    EFFECTIVE_FAIL=$((FAIL_COUNT + WARN_COUNT))
fi

if [ "$EFFECTIVE_FAIL" -gt 0 ]; then
    echo ""
    echo "VERDICT: FAIL ($EFFECTIVE_FAIL violations)"
    echo ""
    echo "To fix: add missing rule-ID references to the indicated artifact layers."
    echo "  CONTRACT → docs/semantic_contract_*.md"
    echo "  GAP-MATRIX → docs/semantic_runtime_gap_matrix.md"
    echo "  RT-SOURCE → src/**/*.rs (add rule-ID in doc comment)"
    echo "  TESTS → tests/**/*.rs (add rule-ID in test doc comment)"
    exit 1
else
    echo ""
    echo "VERDICT: PASS"
    exit 0
fi
