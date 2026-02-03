#!/usr/bin/env bash
# Run formal proof verification checks locally.
# Mirrors the proof-checks CI job in .github/workflows/ci.yml
#
# Usage: ./scripts/run_proof_checks.sh
# Exit 0 = all checks passed, non-zero = at least one failed.

set -euo pipefail

FAILED=0

run_check() {
    local name="$1"
    shift
    echo "=== $name ==="
    if "$@"; then
        echo "  PASS"
    else
        echo "  FAIL"
        FAILED=1
    fi
    echo
}

run_check "Certificate verification" \
    cargo test --lib plan::certificate --all-features -- --nocapture

run_check "Obligation formal checks" \
    cargo test --lib obligation --all-features -- --nocapture

run_check "Lab oracle invariant checks" \
    cargo test --lib lab::oracle --all-features -- --nocapture

run_check "Cancellation protocol tests" \
    cargo test --lib types::cancel --all-features -- --nocapture

run_check "Combinator algebraic laws" \
    cargo test --lib combinator::laws --all-features -- --nocapture

run_check "TLA+ export smoke test" \
    cargo test --lib trace::tla_export --all-features -- --nocapture

run_check "Trace canonicalization" \
    cargo test --lib trace::canonicalize --all-features -- --nocapture

run_check "DPOR exploration" \
    cargo test --test dpor_exploration --all-features -- --nocapture || true

if [ "$FAILED" -eq 0 ]; then
    echo "All proof checks passed."
else
    echo "Some proof checks FAILED."
fi

exit $FAILED
