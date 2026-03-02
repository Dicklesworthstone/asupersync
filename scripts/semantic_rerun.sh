#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────
# semantic_rerun.sh — SEM-12.12
#
# One-command rerun shortcuts for semantic verification failure classes.
# Preserves deterministic seeds, correlation IDs, and full logging context.
#
# Usage:
#   scripts/semantic_rerun.sh <suite>  [--seed N] [--verbose] [--json]
#
# Suites:
#   all        Run all verification suites (full profile)
#   docs       Documentation alignment tests
#   golden     Golden fixture validation
#   lean       Lean proof regression tests
#   tla        TLA+ scenario validation
#   logging    Logging schema + witness replay
#   coverage   Coverage gate enforcement
#   runtime    Runtime conformance (golden + gap matrix)
#   laws       Property/law algebraic tests
#   e2e        Cross-artifact E2E (witness + adversarial)
#   forensics  Full forensics profile with diagnostics
#
# Options:
#   --seed N     Set deterministic seed for reproducible runs
#   --verbose    Show full test output (--nocapture)
#   --json       Emit structured JSON output
#   --summary    Also generate verification summary after run
#
# Exit codes:
#   0 — all tests passed
#   1 — test failures
#   2 — usage/configuration error
#
# Bead: asupersync-3cddg.12.12
# ──────────────────────────────────────────────────────────────────────
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

SUITE=""
SEED=""
VERBOSE=false
JSON_OUTPUT=false
GENERATE_SUMMARY=false
NOCAPTURE=""

# ─── Argument parsing ────────────────────────────────────────────────
if [[ $# -lt 1 ]]; then
    echo "Usage: scripts/semantic_rerun.sh <suite> [--seed N] [--verbose] [--json] [--summary]" >&2
    echo "" >&2
    echo "Suites: all docs golden lean tla logging coverage runtime laws e2e forensics" >&2
    exit 2
fi

SUITE="$1"
shift

while [[ $# -gt 0 ]]; do
    case "$1" in
        --seed)     SEED="$2";            shift 2 ;;
        --verbose)  VERBOSE=true;         shift ;;
        --json)     JSON_OUTPUT=true;     shift ;;
        --summary)  GENERATE_SUMMARY=true; shift ;;
        *)
            echo "Unknown flag: $1" >&2
            exit 2
            ;;
    esac
done

if [[ "$VERBOSE" == "true" ]]; then
    NOCAPTURE="-- --nocapture"
fi

# Export seed if provided
if [[ -n "$SEED" ]]; then
    export SEED
fi

log() { echo "[semantic-rerun] $(date -u '+%H:%M:%S') $*"; }

TIMESTAMP=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
RUN_ID="srr-$(printf '%016x' "${SEED:-$$}")-$(date +%s%N | tail -c 17 | head -c 16)"
EXIT_CODE=0

log "Starting rerun: suite=$SUITE seed=${SEED:-random} run_id=$RUN_ID"

# ─── Suite dispatch ──────────────────────────────────────────────────
run_tests() {
    local label="$1"
    shift
    log "Running: $label"
    if ! "$@"; then
        log "FAILED: $label"
        EXIT_CODE=1
    else
        log "PASSED: $label"
    fi
}

case "$SUITE" in
    docs)
        run_tests "semantic_docs_lint" \
            cargo test --test semantic_docs_lint --test semantic_docs_rule_mapping_lint $NOCAPTURE
        ;;

    golden)
        run_tests "semantic_golden_fixture_validation" \
            cargo test --test semantic_golden_fixture_validation $NOCAPTURE
        ;;

    lean)
        run_tests "semantic_lean_regression" \
            cargo test --test semantic_lean_regression $NOCAPTURE
        ;;

    tla)
        run_tests "semantic_tla_scenarios" \
            cargo test --test semantic_tla_scenarios $NOCAPTURE
        ;;

    logging)
        run_tests "semantic_log_schema_validation + witness_replay" \
            cargo test --test semantic_log_schema_validation --test semantic_witness_replay_e2e $NOCAPTURE
        ;;

    coverage)
        run_tests "coverage_gate (full profile)" \
            scripts/run_semantic_verification.sh --profile full --json
        ;;

    runtime)
        run_tests "golden_fixture_validation" \
            cargo test --test semantic_golden_fixture_validation $NOCAPTURE
        run_tests "evidence_bundle_g4" \
            scripts/assemble_evidence_bundle.sh --json --skip-runner --phase 1
        ;;

    laws)
        run_tests "law_tests" \
            cargo test law_join_assoc law_race_comm law_timeout_min metamorphic_drain law_race_abandon $NOCAPTURE
        ;;

    e2e)
        run_tests "witness_replay + adversarial" \
            cargo test --test semantic_witness_replay_e2e --test adversarial_witness_corpus $NOCAPTURE
        ;;

    all)
        run_tests "docs" \
            cargo test --test semantic_docs_lint --test semantic_docs_rule_mapping_lint $NOCAPTURE
        run_tests "golden" \
            cargo test --test semantic_golden_fixture_validation $NOCAPTURE
        run_tests "lean" \
            cargo test --test semantic_lean_regression $NOCAPTURE
        run_tests "tla" \
            cargo test --test semantic_tla_scenarios $NOCAPTURE
        run_tests "logging" \
            cargo test --test semantic_log_schema_validation --test semantic_witness_replay_e2e $NOCAPTURE
        ;;

    forensics)
        log "Running full forensics profile"
        run_tests "forensics" \
            scripts/run_semantic_verification.sh --profile forensics --json
        GENERATE_SUMMARY=true
        ;;

    *)
        echo "Unknown suite: $SUITE" >&2
        echo "Valid suites: all docs golden lean tla logging coverage runtime laws e2e forensics" >&2
        exit 2
        ;;
esac

# ─── Optional summary generation ────────────────────────────────────
if [[ "$GENERATE_SUMMARY" == "true" ]]; then
    log "Generating verification summary..."
    SUMMARY_FLAGS=""
    if [[ "$JSON_OUTPUT" == "true" ]]; then
        SUMMARY_FLAGS="--json"
    fi
    if [[ "$VERBOSE" == "true" ]]; then
        SUMMARY_FLAGS="$SUMMARY_FLAGS --verbose"
    fi
    scripts/generate_verification_summary.sh $SUMMARY_FLAGS || true
fi

# ─── JSON output ────────────────────────────────────────────────────
if [[ "$JSON_OUTPUT" == "true" ]]; then
    python3 -c "
import json, sys
result = {
    'schema': 'semantic-rerun-v1',
    'run_id': '${RUN_ID}',
    'suite': '${SUITE}',
    'seed': '${SEED:-null}',
    'timestamp': '${TIMESTAMP}',
    'exit_code': ${EXIT_CODE},
    'status': 'passed' if ${EXIT_CODE} == 0 else 'failed',
    'rerun_command': 'scripts/semantic_rerun.sh ${SUITE}' + (' --seed ${SEED}' if '${SEED}' else '') + ' --json',
}
json.dump(result, sys.stdout, indent=2)
print()
" 2>/dev/null || true
fi

# ─── Summary ────────────────────────────────────────────────────────
echo ""
if [[ $EXIT_CODE -eq 0 ]]; then
    log "All tests passed for suite: $SUITE"
else
    log "FAILURES detected in suite: $SUITE"
    echo ""
    echo "  Next steps:"
    echo "    1. Review test output above for specific assertion failures"
    echo "    2. Consult: docs/semantic_failure_replay_cookbook.md §2"
    echo "    3. Re-run with --verbose for full output"
    echo "    4. Generate triage: scripts/generate_verification_summary.sh --json --verbose"
fi

if [[ $EXIT_CODE -eq 0 ]]; then
    exit 0
else
    exit 1
fi
