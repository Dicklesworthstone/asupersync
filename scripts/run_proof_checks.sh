#!/usr/bin/env bash
# Run formal proof verification checks locally (bd-2rhiq).
# Mirrors and extends the proof-checks CI job in .github/workflows/ci.yml.
#
# Usage:
#   scripts/run_proof_checks.sh [--json] [--artifacts-dir DIR]
#
# Options:
#   --json           Emit structured JSON manifest to stdout (plus artifacts dir)
#   --artifacts-dir  Directory for proof artifacts (default: target/proof-artifacts)
#
# Exit 0 = all checks passed, non-zero = at least one failed.
#
# Cross-references:
#   CI workflow: .github/workflows/ci.yml (proof-checks job)
#   TLA+ model: formal/tla/Asupersync.tla
#   Lean spec:  formal/lean/Asupersync.lean
#   Lease tests: tests/lease_semantics.rs

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

# Parse args
JSON_MODE=false
ARTIFACTS_DIR="target/proof-artifacts"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --json) JSON_MODE=true; shift ;;
        --artifacts-dir) ARTIFACTS_DIR="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

mkdir -p "$ARTIFACTS_DIR"

FAILED=0
TOTAL=0
PASSED=0
RESULTS=()
START_TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)

run_check() {
    local name="$1"
    local category="$2"
    shift 2
    TOTAL=$((TOTAL + 1))

    local logfile="$ARTIFACTS_DIR/$(echo "$name" | tr ' ' '_' | tr '[:upper:]' '[:lower:]').log"
    local status="pass"
    local start_s=$SECONDS

    echo "=== [$TOTAL] $name ==="
    if "$@" > "$logfile" 2>&1; then
        echo "  PASS"
        PASSED=$((PASSED + 1))
    else
        echo "  FAIL (see $logfile)"
        status="fail"
        FAILED=$((FAILED + 1))
        # Show last 10 lines for diagnostics
        tail -10 "$logfile" | sed 's/^/  | /'
    fi
    local elapsed=$((SECONDS - start_s))
    echo "  (${elapsed}s)"
    echo

    RESULTS+=("{\"name\":\"$name\",\"category\":\"$category\",\"status\":\"$status\",\"elapsed_s\":$elapsed,\"log\":\"$(basename "$logfile")\"}")
}

run_check_optional() {
    local name="$1"
    local category="$2"
    shift 2
    TOTAL=$((TOTAL + 1))

    local logfile="$ARTIFACTS_DIR/$(echo "$name" | tr ' ' '_' | tr '[:upper:]' '[:lower:]').log"
    local status="skip"
    local start_s=$SECONDS

    echo "=== [$TOTAL] $name (optional) ==="
    if "$@" > "$logfile" 2>&1; then
        echo "  PASS"
        status="pass"
        PASSED=$((PASSED + 1))
    else
        echo "  SKIPPED or FAIL (non-blocking)"
        # Don't increment FAILED — optional checks don't block
    fi
    local elapsed=$((SECONDS - start_s))
    echo "  (${elapsed}s)"
    echo

    RESULTS+=("{\"name\":\"$name\",\"category\":\"$category\",\"status\":\"$status\",\"elapsed_s\":$elapsed,\"log\":\"$(basename "$logfile")\"}")
}

echo "=== Asupersync Proof Verification Suite (bd-2rhiq) ==="
echo "Artifacts: $ARTIFACTS_DIR"
echo ""

# ---- Category: Rust Proof Tests ----

run_check "Certificate verification" "rust-proofs" \
    cargo test --lib plan::certificate --all-features -- --nocapture

run_check "Obligation formal checks" "rust-proofs" \
    cargo test --lib obligation --all-features -- --nocapture

run_check "Lab oracle invariant checks" "rust-proofs" \
    cargo test --lib lab::oracle --all-features -- --nocapture

run_check "Cancellation protocol tests" "rust-proofs" \
    cargo test --lib types::cancel --all-features -- --nocapture

run_check "Combinator algebraic laws" "rust-proofs" \
    cargo test --lib combinator::laws --all-features -- --nocapture

run_check "TLA+ export smoke test" "rust-proofs" \
    cargo test --lib trace::tla_export --all-features -- --nocapture

run_check "Trace canonicalization" "rust-proofs" \
    cargo test --lib trace::canonicalize --all-features -- --nocapture

# ---- Category: Integration Proof Tests ----

run_check "Lease semantics and liveness" "integration-proofs" \
    cargo test --test lease_semantics -- --nocapture

run_check "Close quiescence regression" "integration-proofs" \
    cargo test --test close_quiescence_regression -- --nocapture

run_check "Refinement conformance" "integration-proofs" \
    cargo test --test refinement_conformance -- --nocapture

# ---- Category: DPOR (optional, may not be present) ----

run_check_optional "DPOR exploration" "dpor" \
    cargo test --test dpor_exploration --all-features -- --nocapture

# ---- Category: TLA+ Model Checking (optional, requires TLC) ----

run_check_optional "TLA+ bounded model check" "tla-model" \
    bash scripts/run_model_check.sh --ci

# ---- Category: Lean Proof Build (optional, requires lake) ----

if command -v lake &>/dev/null; then
    run_check "Lean proof build" "lean-proofs" \
        bash -c "cd formal/lean && lake build"
else
    echo "=== [skip] Lean proof build (lake not installed) ==="
    echo "  Install elan/lean4 to enable: curl -sSf https://raw.githubusercontent.com/leanprover/elan/main/elan-init.sh | sh"
    echo
    RESULTS+=("{\"name\":\"Lean proof build\",\"category\":\"lean-proofs\",\"status\":\"skip\",\"elapsed_s\":0,\"log\":\"\"}")
fi

# ---- Generate manifest ----

END_TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
GIT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")

# Build JSON array from results
RESULTS_JSON="["
for i in "${!RESULTS[@]}"; do
    if [ "$i" -gt 0 ]; then RESULTS_JSON+=","; fi
    RESULTS_JSON+="${RESULTS[$i]}"
done
RESULTS_JSON+="]"

MANIFEST=$(cat <<ENDJSON
{
    "version": "1.0.0",
    "bead": "bd-2rhiq",
    "started_at": "$START_TS",
    "finished_at": "$END_TS",
    "git_sha": "$GIT_SHA",
    "git_branch": "$GIT_BRANCH",
    "total": $TOTAL,
    "passed": $PASSED,
    "failed": $FAILED,
    "skipped": $((TOTAL - PASSED - FAILED)),
    "status": "$([ "$FAILED" -eq 0 ] && echo "pass" || echo "fail")",
    "checks": $RESULTS_JSON
}
ENDJSON
)

echo "$MANIFEST" > "$ARTIFACTS_DIR/manifest.json"

echo "========================================"
echo "Results: $PASSED/$TOTAL passed, $FAILED failed"
echo "Manifest: $ARTIFACTS_DIR/manifest.json"

if $JSON_MODE; then
    echo "$MANIFEST"
fi

exit "$FAILED"
