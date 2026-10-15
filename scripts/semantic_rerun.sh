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
NOCAPTURE_ARGS=()
RCH_BIN="${RCH_BIN:-rch}"
RCH_CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_semantic_rerun}"

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
    NOCAPTURE_ARGS=(-- --nocapture)
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

# shellcheck disable=SC2317 # Invoked indirectly through run_tests dispatch.
run_cargo() {
    local output=""
    local status=0

    set +e
    output=$("$RCH_BIN" exec -- env CARGO_TARGET_DIR="$RCH_CARGO_TARGET_DIR" cargo "$@" 2>&1)
    status=$?
    set -e

    printf '%s\n' "$output"
    if printf '%s\n' "$output" | grep -Eq '^\[RCH\] local \(|falling back to local'; then
        printf '%s\n' "FATAL: rch local fallback detected; refusing local cargo execution" >&2
        return 86
    fi
    return "$status"
}

case "$SUITE" in
    docs)
        run_tests "semantic_docs_lint" \
            run_cargo test --test semantic_docs_lint --test semantic_docs_rule_mapping_lint "${NOCAPTURE_ARGS[@]}"
        ;;

    golden)
        run_tests "semantic_golden_fixture_validation" \
            run_cargo test --test semantic_golden_fixture_validation "${NOCAPTURE_ARGS[@]}"
        ;;

    lean)
        run_tests "semantic_lean_regression" \
            run_cargo test --test semantic_lean_regression "${NOCAPTURE_ARGS[@]}"
        ;;

    tla)
        run_tests "semantic_tla_scenarios" \
            run_cargo test --test semantic_tla_scenarios "${NOCAPTURE_ARGS[@]}"
        ;;

    logging)
        run_tests "semantic_log_schema_validation + witness_replay" \
            run_cargo test --test semantic_log_schema_validation --test semantic_witness_replay_e2e "${NOCAPTURE_ARGS[@]}"
        ;;

    coverage)
        run_tests "coverage_gate (full profile)" \
            scripts/run_semantic_verification.sh --profile full --json
        ;;

    runtime)
        run_tests "golden_fixture_validation" \
            run_cargo test --test semantic_golden_fixture_validation "${NOCAPTURE_ARGS[@]}"
        run_tests "evidence_bundle_g4" \
            scripts/assemble_evidence_bundle.sh --json --skip-runner --phase 1
        ;;

    laws)
        run_tests "law_tests" \
            run_cargo test law_join_assoc law_race_comm law_timeout_min metamorphic_drain law_race_abandon "${NOCAPTURE_ARGS[@]}"
        ;;

    e2e)
        run_tests "witness_replay + adversarial" \
            run_cargo test --test semantic_witness_replay_e2e --test adversarial_witness_corpus "${NOCAPTURE_ARGS[@]}"
        ;;

    all)
        run_tests "docs" \
            run_cargo test --test semantic_docs_lint --test semantic_docs_rule_mapping_lint "${NOCAPTURE_ARGS[@]}"
        run_tests "golden" \
            run_cargo test --test semantic_golden_fixture_validation "${NOCAPTURE_ARGS[@]}"
        run_tests "lean" \
            run_cargo test --test semantic_lean_regression "${NOCAPTURE_ARGS[@]}"
        run_tests "tla" \
            run_cargo test --test semantic_tla_scenarios "${NOCAPTURE_ARGS[@]}"
        run_tests "logging" \
            run_cargo test --test semantic_log_schema_validation --test semantic_witness_replay_e2e "${NOCAPTURE_ARGS[@]}"
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
    SUMMARY_FLAGS=()
    if [[ "$JSON_OUTPUT" == "true" ]]; then
        SUMMARY_FLAGS+=(--json)
    fi
    if [[ "$VERBOSE" == "true" ]]; then
        SUMMARY_FLAGS+=(--verbose)
    fi
    scripts/generate_verification_summary.sh "${SUMMARY_FLAGS[@]}" || true
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
