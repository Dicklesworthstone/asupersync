#!/usr/bin/env bash
# shellcheck disable=SC2317 # run_check invokes named function callbacks indirectly.
# Run formal proof verification checks through required remote Cargo lanes
# (bd-2rhiq). Non-Cargo model/proof tools still run on the invoking host.
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
RCH_BIN="${RCH_BIN:-rch}"
RCH_CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_proof_checks}"
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

validate_remote_rch_binary() {
    local resolved_rch=""
    local resolved_fallback=""

    resolved_rch=$(command -v -- "$RCH_BIN") || {
        printf '%s\n' "FATAL: canonical rch executable not found: $RCH_BIN" >&2
        return 86
    }
    if [[ $(basename -- "$resolved_rch") != "rch" ]]; then
        printf '%s\n' \
            "FATAL: RCH_BIN must resolve to an executable named rch for remote proof: $resolved_rch" >&2
        return 86
    fi
    resolved_rch=$(realpath -- "$resolved_rch") || return 86
    resolved_fallback=$(realpath -- "$PROJECT_DIR/scripts/rch_ci_fallback.sh") || return 86
    if [[ $resolved_rch == "$resolved_fallback" ]]; then
        printf '%s\n' \
            "FATAL: scripts/rch_ci_fallback.sh can execute Cargo locally and is forbidden for remote proof" >&2
        return 86
    fi
}

run_check() {
    local name="$1"
    local category="$2"
    shift 2
    TOTAL=$((TOTAL + 1))

    local logfile
    logfile="$ARTIFACTS_DIR/$(echo "$name" | tr ' ' '_' | tr '[:upper:]' '[:lower:]').log"
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

    local logfile
    logfile="$ARTIFACTS_DIR/$(echo "$name" | tr ' ' '_' | tr '[:upper:]' '[:lower:]').log"
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

run_cargo() {
    local output=""
    local status=0

    validate_remote_rch_binary || return $?

    set +e
    output=$(RCH_REQUIRE_REMOTE=1 "$RCH_BIN" exec -- env CARGO_TARGET_DIR="$RCH_CARGO_TARGET_DIR" cargo "$@" 2>&1)
    status=$?
    set -e

    printf '%s\n' "$output"
    if grep -Eq '^\[RCH\] local \(|falling back to local|^\[rch-ci-fallback\] executing locally:' <<<"$output"; then
        printf '%s\n' "FATAL: rch local fallback detected; refusing local cargo execution" >&2
        return 86
    fi
    return "$status"
}

run_native_parked_task_cancellation() {
    local output=""
    local status=0

    validate_remote_rch_binary || return $?

    set +e
    output=$(RCH_REQUIRE_REMOTE=1 "$RCH_BIN" exec -- env \
        CARGO_TARGET_DIR="$RCH_CARGO_TARGET_DIR" \
        CARGO_INCREMENTAL=0 \
        CARGO_PROFILE_TEST_DEBUG=0 \
        RUSTFLAGS='-D warnings -C debuginfo=0' \
        cargo test -p asupersync --locked --test runtime_abort_vs_cancel_semantics_audit -- --nocapture 2>&1)
    status=$?
    set -e

    printf '%s\n' "$output"
    if [[ $status -ne 0 ]]; then
        return "$status"
    fi
    if grep -Eq '^\[RCH\] local \(|falling back to local|^\[rch-ci-fallback\] executing locally:' <<<"$output"; then
        printf '%s\n' \
            "FATAL: native parked-task cancellation proof used local fallback while RCH is required" >&2
        return 86
    fi
    if ! grep -Eq \
        'test result: ok\. [1-9][0-9]* passed; 0 failed; 0 ignored; 0 measured; 0 filtered out' \
        <<<"$output"; then
        printf '%s\n' \
            "FATAL: native parked-task cancellation proof must run a nonzero, completely unfiltered test matrix" >&2
        return 87
    fi
    for required_test in \
        run_test_preserves_typed_cancellation_from_a_parked_spawn \
        abort_repolls_a_mutex_parked_operation_to_graceful_cancellation \
        abort_repolls_an_explicit_cx_websocket_close_write_to_typed_cancellation \
        abort_repolls_a_capacity_parked_send_to_graceful_cancellation \
        abort_repolls_a_semaphore_parked_acquire_to_graceful_cancellation \
        local_spawn_abort_preserves_mutex_cancellation_and_waiter_cleanup \
        cross_thread_abort_on_multi_worker_runtime_preserves_mutex_cancellation_and_waiter_cleanup \
        cross_thread_cx_cancel_wakes_a_timer_parked_native_task \
        abort_and_join_complete_promptly_for_a_timer_parked_native_child \
        abort_before_first_poll_keeps_task_level_cancellation_attribution \
        cancellation_published_at_the_end_of_pending_repolls_user_code \
        acknowledged_cancellation_can_finish_async_cleanup_before_join_completes \
        ordinary_spawn_keeps_cancellation_dominant_for_cancellation_blind_late_values \
        read_only_cancellation_observation_does_not_reclassify_a_late_value \
        spawn_blocking_discards_a_late_value_after_wrapper_cancellation \
        spawn_blocking_in_discards_a_late_value_after_wrapper_cancellation \
        legacy_state_task_panic_after_abort_remains_panicked \
        legacy_state_task_keeps_cancellation_dominant_result_attribution \
        terminal_publication_boundary_preserves_panics_as_join_errors \
        panic_during_cancel_cleanup_outranks_task_cancellation \
        mailbox_and_scope_spawn_paths_classify_before_terminal_publication \
        sibling_terminal_handle_publishers_are_cx_independent \
        task_handle_abort_publishes_via_same_stable_envelope_as_cancel \
        task_handle_abort_strengthens_existing_cancel_reason \
        task_handle_abort_defers_panic_isolated_wakers_to_runtime_publication \
        task_handle_abort_default_reason_is_user_kind_not_force_kill \
        cx_cancel_with_publishes_via_same_stable_envelope_as_abort \
        cx_cancel_fast_uses_same_publish_mechanism_minimal_attribution \
        no_unsafe_thread_termination_in_abort_or_cancel_paths \
        abort_path_uses_weak_handle_to_avoid_keeping_task_alive \
        cancel_handlers_run_on_both_abort_and_cancel_via_same_checkpoint_path \
        abort_does_not_have_separate_force_kill_method \
        abort_with_reason_does_not_call_drop_guard_bypass_machinery \
        cross_reference_to_prior_audits
    do
        if ! grep -Fq "test ${required_test} ... ok" <<<"$output"; then
            printf '%s\n' \
                "FATAL: native parked-task cancellation proof did not pass required sentinel ${required_test}" >&2
            return 88
        fi
    done
}

run_v044_downstream_cancel_compatibility() {
    local output=""
    local status=0

    validate_remote_rch_binary || return $?

    set +e
    output=$(RCH_REQUIRE_REMOTE=1 "$RCH_BIN" exec -- env \
        CARGO_TARGET_DIR="$RCH_CARGO_TARGET_DIR" \
        CARGO_INCREMENTAL=0 \
        CARGO_PROFILE_DEV_DEBUG=0 \
        RUSTFLAGS='-D warnings -C debuginfo=0' \
        cargo run --manifest-path \
        tests/fixtures/downstream-consumer-proof/Cargo.toml \
        --bin v044_cancel_compat_consumer 2>&1)
    status=$?
    set -e

    printf '%s\n' "$output"
    if [[ $status -ne 0 ]]; then
        return "$status"
    fi
    if grep -Eq '^\[RCH\] local \(|falling back to local|^\[rch-ci-fallback\] executing locally:' <<<"$output"; then
        printf '%s\n' \
            "FATAL: published v0.4.4 cancellation canary used local fallback while RCH is required" >&2
        return 86
    fi
    for required_signal in \
        V044_CANCEL_COMPAT_NEGATIVE_RED \
        V044_CANCEL_COMPAT_POSITIVE_GREEN \
        V044_CANCEL_COMPAT_CASES=3
    do
        if ! grep -Fq "$required_signal" <<<"$output"; then
            printf '%s\n' \
                "FATAL: published v0.4.4 cancellation canary did not emit ${required_signal}" >&2
            return 88
        fi
    done
    if grep -Eq '(^|[^0-9])0 passed|filtered out|ignored|skipped' <<<"$output"; then
        printf '%s\n' \
            "FATAL: published v0.4.4 cancellation canary emitted a zero, filtered, ignored, or skipped result" >&2
        return 87
    fi
}

echo "=== Asupersync Proof Verification Suite (bd-2rhiq) ==="
echo "Artifacts: $ARTIFACTS_DIR"
echo ""

# ---- Category: Escaped-Defect Release Blockers ----

run_check "Native parked-task cancellation boundary" "integration-proofs" \
    run_native_parked_task_cancellation

run_check "Published v0.4.4 downstream cancellation compatibility" "integration-proofs" \
    run_v044_downstream_cancel_compatibility

# ---- Category: Rust Proof Tests ----

run_check "Certificate verification" "rust-proofs" \
    run_cargo test --lib plan::certificate --all-features -- --nocapture

run_check "Obligation formal checks" "rust-proofs" \
    run_cargo test --lib obligation --all-features -- --nocapture

run_check "Lab oracle invariant checks" "rust-proofs" \
    run_cargo test --lib lab::oracle --all-features -- --nocapture

run_check "Cancellation protocol tests" "rust-proofs" \
    run_cargo test --lib types::cancel --all-features -- --nocapture

run_check "Combinator algebraic laws" "rust-proofs" \
    run_cargo test --lib combinator::laws --all-features -- --nocapture

run_check "TLA+ export smoke test" "rust-proofs" \
    run_cargo test --lib trace::tla_export --all-features -- --nocapture

run_check "Trace canonicalization" "rust-proofs" \
    run_cargo test --lib trace::canonicalize --all-features -- --nocapture

# ---- Category: Integration Proof Tests ----

run_check "Lease semantics and liveness" "integration-proofs" \
    run_cargo test --test lease_semantics -- --nocapture

run_check "Close quiescence regression" "integration-proofs" \
    run_cargo test --test close_quiescence_regression -- --nocapture

run_check "Refinement conformance" "integration-proofs" \
    run_cargo test --test refinement_conformance -- --nocapture

# ---- Category: DPOR (optional, may not be present) ----

run_check_optional "DPOR exploration" "dpor" \
    run_cargo test --test dpor_exploration --all-features -- --nocapture

# ---- Category: TLA+ Model Checking (optional, requires TLC) ----

run_check_optional "TLA+ bounded model check" "tla-model" \
    bash scripts/run_model_check.sh --ci

# ---- Category: Lean Proof Build (optional, requires lake) ----

if command -v lake &>/dev/null; then
    run_check "Lean proof build" "lean-proofs" \
        lake --dir formal/lean build
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
