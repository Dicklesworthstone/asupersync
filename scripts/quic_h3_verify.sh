#!/usr/bin/env bash
# One-command QUIC/H3 full verification runner.
#
# Usage:
#   ./scripts/quic_h3_verify.sh          # fast mode (unit + smoke E2E)
#   ./scripts/quic_h3_verify.sh --full   # full mode (all unit + all E2E + coverage + artifacts)
#   ./scripts/quic_h3_verify.sh --dry-run
#
# Requires: rch, python3

set -euo pipefail

MODE="fast"
DRY_RUN=0
PASS=0
FAIL=0
START_TIME=$(date +%s)
RCH_BIN="${RCH_BIN:-$HOME/.local/bin/rch}"
RCH_TIMEOUT_SEC="${RCH_TIMEOUT_SEC:-900}"
LAST_RCH_OUTPUT=""

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

usage() {
    cat <<'USAGE'
Usage: scripts/quic_h3_verify.sh [--full] [--dry-run]

Options:
  --full      Run the full QUIC/H3 E2E and coverage gates.
  --dry-run   Print planned proof commands without executing them.
  -h, --help  Show this help.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --full)
            MODE="--full"
            shift
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

step() {
    echo -e "\n${BOLD}[$(date +%H:%M:%S)] $1${NC}"
}

pass() {
    echo -e "  ${GREEN}PASS${NC} $1"
    PASS=$((PASS + 1))
}

fail() {
    echo -e "  ${RED}FAIL${NC} $1"
    FAIL=$((FAIL + 1))
}

skip() {
    echo -e "  ${YELLOW}SKIP${NC} $1"
}

print_command() {
    printf '%q ' "$@"
    printf '\n'
}

run_local_gate() {
    local label="$1"
    shift

    if [[ "${DRY_RUN}" -eq 1 ]]; then
        printf '  DRY-RUN %s: ' "${label}"
        print_command "$@"
        return 0
    fi

    "$@" > /dev/null 2>&1
}

run_rch_capture() {
    local label="$1"
    shift
    local -a command=("${RCH_BIN}" exec -- "$@")
    local output=""
    local status=0

    if [[ "${DRY_RUN}" -eq 1 ]]; then
        printf '  DRY-RUN %s: ' "${label}"
        print_command "${command[@]}"
        LAST_RCH_OUTPUT="dry-run"
        return 0
    fi

    set +e
    output="$(timeout "${RCH_TIMEOUT_SEC}s" "${command[@]}" 2>&1)"
    status=$?
    set -e

    LAST_RCH_OUTPUT="${output}"

    if grep -Eq '^\[RCH\] local \(|falling back to local' <<<"${output}"; then
        printf '%s\n' "${output}" | tail -40
        return 86
    fi

    return "${status}"
}

run_cargo_test_gate() {
    local label="$1"
    shift

    if run_rch_capture "${label}" "$@"; then
        if [[ "${DRY_RUN}" -eq 1 ]] || grep -q '^test result: ok' <<<"${LAST_RCH_OUTPUT}"; then
            pass "${label}"
            return 0
        fi
    fi

    printf '%s\n' "${LAST_RCH_OUTPUT}" | tail -40
    fail "${label}"
    return 1
}

if [[ "${DRY_RUN}" -eq 0 && ! -x "${RCH_BIN}" ]]; then
    echo "FATAL: rch is required and was not found/executable at: ${RCH_BIN}" >&2
    exit 1
fi

# ─── Gate 1: No-mock policy ─────────────────────────────────────────────
step "Gate 1: No-mock policy enforcement"
if run_local_gate "No-mock policy" python3 scripts/check_no_mock_policy.py --policy .github/no_mock_policy.json; then
    pass "No-mock policy"
else
    fail "No-mock policy"
fi

# ─── Gate 2: Replay catalog integrity ───────────────────────────────────
step "Gate 2: Replay catalog integrity"
if run_local_gate "Replay catalog self-test" python3 scripts/quic_h3_triage.py --self-test; then
    pass "Replay catalog self-test"
else
    fail "Replay catalog self-test"
fi

# ─── Gate 3: Unit tests ─────────────────────────────────────────────────
step "Gate 3: QUIC/H3 unit tests"
for target in quic_core quic_native h3_native forensic_log; do
    run_cargo_test_gate "$target" \
        env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 "RUSTFLAGS=-C debuginfo=0" \
        "CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_quic_h3_verify_unit_${target}" \
        cargo test -p asupersync "$target" --all-features || true
done

# ─── Gate 4: E2E tests ──────────────────────────────────────────────────
if [ "$MODE" = "--full" ]; then
    E2E_CRATES="quic_h3_e2e quic_h3_e2e_loss quic_h3_e2e_h3 quic_h3_e2e_cancel quic_h3_e2e_violations"
else
    # Fast mode: run the main harness only (24 tests covering all categories)
    E2E_CRATES="quic_h3_e2e"
fi

step "Gate 4: E2E integration tests (${MODE})"
for crate in $E2E_CRATES; do
    run_cargo_test_gate "$crate" \
        env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 "RUSTFLAGS=-C debuginfo=0" \
        "CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_quic_h3_verify_e2e_${crate}" \
        cargo test --test "$crate" --all-features || true
done

# ─── Gate 5: Coverage ratchet (full mode only) ──────────────────────────
if [ "$MODE" = "--full" ]; then
    step "Gate 5: Coverage ratchet check"
    if run_rch_capture "coverage ratchet" \
        env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 "RUSTFLAGS=-C debuginfo=0" \
        "CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_quic_h3_verify_coverage" \
        cargo llvm-cov test -p asupersync --all-features --summary-only; then
        if [[ "${DRY_RUN}" -eq 1 ]] || grep -q "TOTAL" <<<"${LAST_RCH_OUTPUT}"; then
            pass "Coverage report generated"
        else
            printf '%s\n' "${LAST_RCH_OUTPUT}" | tail -40
            fail "Coverage report"
        fi
    elif grep -Eq 'no such command: `llvm-cov`|cargo-llvm-cov: command not found' <<<"${LAST_RCH_OUTPUT}"; then
        skip "cargo-llvm-cov not installed on rch worker"
    else
        printf '%s\n' "${LAST_RCH_OUTPUT}" | tail -40
        fail "Coverage report"
    fi
fi

# ─── Summary ────────────────────────────────────────────────────────────
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  QUIC/H3 Verification Summary (${MODE})${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo -e "  ${GREEN}Planned:${NC} ${PASS}"
else
    echo -e "  ${GREEN}Passed:${NC} ${PASS}"
fi
echo -e "  ${RED}Failed:${NC} ${FAIL}"
echo -e "  Duration: ${ELAPSED}s"
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"

if [ "$FAIL" -gt 0 ]; then
    echo -e "\n${RED}VERIFICATION FAILED${NC}"
    echo "Run individual tests with --nocapture for details:"
    echo "  RCH_BIN=${RCH_BIN} ${RCH_BIN} exec -- cargo test --test quic_h3_e2e -- --nocapture"
    echo "  python3 scripts/quic_h3_triage.py --catalog --verbose"
    exit 1
else
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        echo -e "\n${GREEN}DRY RUN COMPLETE${NC}"
    else
        echo -e "\n${GREEN}ALL GATES PASSED${NC}"
    fi
    exit 0
fi
