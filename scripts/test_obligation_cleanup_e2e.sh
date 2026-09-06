#!/usr/bin/env bash
# Obligation cleanup no-mock E2E runner for asupersync-9u057b.5.
#
# Runs the focused client-disconnect forced-cancel obligation cleanup harness
# with deterministic single-threaded Rust test execution, structured log capture,
# and preserved artifacts for failure triage.
#
# Usage:
#   bash scripts/test_obligation_cleanup_e2e.sh [test_filter]
#   bash scripts/test_obligation_cleanup_e2e.sh --checked-admission \
#     --base FULL_COMMIT_SHA --overlay-path src/owned.rs [--overlay-path ...]
#   Use --no-overlay instead of overlay paths for a committed candidate.
#   Optional --features CSV defaults to test-internals,channel-mpsc-select-e2e.
#   CHECKED_ADMISSION_BUILD_JOBS defaults to 8. CHECKED_ADMISSION_CARGO_HOME
#   (or CARGO_HOME) is forwarded to each remote Cargo command when supplied.
#   Checked mode preserves the legacy cleanup routes below and runs native,
#   lifecycle and public-channel stages against one explicitly selected source.
#   --managed-supervision uses the same source selection and remote execution
#   with native, supervisor/finalizer unit, and public supervision stages.
#   It defaults to tls,test-internals and uses MANAGED_SUPERVISION_ARTIFACT_DIR.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

checked_selection_json() {
    local files='[]' path digest mode
    for path in "${CHECKED_OVERLAYS[@]}"; do
        [[ -f "$PROJECT_ROOT/$path" && ! -L "$PROJECT_ROOT/$path" ]] || return 86
        digest=$(sha256sum -- "$PROJECT_ROOT/$path") || return 86
        digest="${digest%% *}"
        mode=$(stat -c '%a' -- "$PROJECT_ROOT/$path") || return 86
        files=$(jq -cn --argjson files "$files" --arg path "$path" \
            --arg sha256 "$digest" --arg mode "$mode" \
            '$files + [{path:$path,sha256:$sha256,mode:$mode}]') || return 86
    done
    jq -cnS --arg base "$CHECKED_BASE" --arg features "$CHECKED_FEATURES" \
        --arg build_jobs "$CHECKED_BUILD_JOBS" --arg cargo_home "$CHECKED_CARGO_HOME" \
        --argjson files "$files" \
        '{base:$base,features:$features,build_jobs:$build_jobs,cargo_home:$cargo_home,
          overlays:($files|sort_by(.path))}'
}

checked_finish_summary() {
    local status=$?
    trap - EXIT
    jq -n --arg status "$CHECKED_STATUS" --arg phase "$CHECKED_PHASE" \
        --arg schema "$CHECKED_SCHEMA" --arg bead "$CHECKED_BEAD" \
        --argjson exit_code "$status" --arg started "$CHECKED_STARTED" \
        --arg ended "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --slurpfile source "$CHECKED_DIR/source-selection.json" \
        --slurpfile stages "$CHECKED_DIR/stages.ndjson" \
        '{schema_version:$schema,
          bead_id:$bead,status:$status,phase:$phase,
          exit_code:$exit_code,started:$started,ended:$ended,
          source:$source[0],stages:$stages,
          source_evidence:"clean-overlay-admission-and-local-selected-file-hashes",
          worker_content_manifest_verified:false}' > "$CHECKED_DIR/summary.json" || {
        printf 'FATAL: checked admission summary could not be preserved\n' >&2
        (( status != 0 )) && exit "$status"
        exit 86
    }
    printf '%s summary: %s\n' "$CHECKED_MODE" "$CHECKED_DIR/summary.json"
    exit "$status"
}

checked_verify_source() {
    local stage="$1"
    checked_selection_json > "$CHECKED_DIR/$stage.selection.json" || return 86
    if ! cmp -s "$CHECKED_DIR/source-selection.json" "$CHECKED_DIR/$stage.selection.json"; then
        printf 'FATAL: selected source changed at %s\n' "$stage" >&2
        return 86
    fi
}

checked_verify_receipt() {
    local stage="$1" log="$2" selected terminal source fingerprint
    selected=$(sed -nE 's/.*Selected worker: ([A-Za-z0-9_.-]+) at .*/\1/p' "$log")
    terminal=$(sed -nE 's/^\[RCH\] remote ([A-Za-z0-9_.-]+) \([^)]*\)$/\1/p' "$log")
    [[ "$selected" =~ ^[A-Za-z0-9_.-]+$ && "$terminal" == "$selected" ]] || {
        printf 'FATAL: %s requires one selected worker and its actual remote terminal\n' "$stage" >&2
        return 86
    }
    if [[ -n "$CHECKED_WORKER" && "$selected" != "$CHECKED_WORKER" ]]; then
        printf 'FATAL: %s selected a different worker\n' "$stage" >&2
        return 86
    fi
    source=$(sed -nE 's/^\[RCH\] clean-overlay receipt: base=([0-9a-f]{40}) overlay-fingerprint=([0-9a-f]{64})$/\1 \2/p' "$log")
    [[ "$source" =~ ^[0-9a-f]{40}\ [0-9a-f]{64}$ && "${source%% *}" == "$CHECKED_BASE" ]] || {
        printf 'FATAL: %s lacks one admitted receipt for the requested base\n' "$stage" >&2
        return 86
    }
    fingerprint="${source##* }"
    if [[ -n "$CHECKED_OVERLAY_FINGERPRINT" && "$fingerprint" != "$CHECKED_OVERLAY_FINGERPRINT" ]]; then
        printf 'FATAL: %s overlay fingerprint differs from the native baseline\n' "$stage" >&2
        return 86
    fi
    CHECKED_WORKER="$selected"
    CHECKED_OVERLAY_FINGERPRINT="$fingerprint"
    # Installed RCH refuses combining clean-overlay and source-content-receipt.
    # This joins actual admission/terminal evidence and local selected hashes;
    # it does not claim an independently hashed worker content manifest.
    jq -cn --arg worker "$selected" --arg base "$CHECKED_BASE" \
        --arg fingerprint "$fingerprint" \
        '{worker:$worker,base:$base,overlay_fingerprint:$fingerprint,
          worker_content_manifest_verified:false}' > "$CHECKED_DIR/$stage.source-receipt.json" || return 86
}

checked_stage() {
    local stage="$1" status=0 log
    shift
    CHECKED_PHASE="$stage"
    log="$CHECKED_DIR/$stage.log"
    checked_verify_source "$stage.before" || return $?
    # RCH creates the final rsync destination, but its parent must already
    # exist locally. Test-only stages may return no binary artifacts and
    # therefore never create this parent before the public cargo-run stage.
    mkdir -p "$CHECKED_TARGET" || return $?
    printf 'Checked stage %s command:' "$stage"
    printf ' %q' "$CHECKED_RCH" exec "${CHECKED_SOURCE_ARGS[@]}" -- env "${CHECKED_REMOTE_CARGO_ENV[@]}" \
        CARGO_TARGET_DIR="$CHECKED_TARGET/$stage" CARGO_INCREMENTAL=0 \
        CARGO_PROFILE_TEST_DEBUG=0 CARGO_PROFILE_DEV_DEBUG=0 \
        'RUSTFLAGS=-D warnings -C debuginfo=0' cargo "$@"
    printf '\n'
    if RCH_REQUIRE_REMOTE=1 RCH_DISABLE_TARGET_REUSE=1 RCH_VISIBILITY=verbose \
        RCH_WORKER="$CHECKED_WORKER" RCH_WORKERS='' NO_COLOR=1 \
        timeout "${CHECKED_STAGE_TIMEOUT:-1800}" "$CHECKED_RCH" --no-color exec \
        "${CHECKED_SOURCE_ARGS[@]}" -- env "${CHECKED_REMOTE_CARGO_ENV[@]}" \
        CARGO_TARGET_DIR="$CHECKED_TARGET/$stage" CARGO_INCREMENTAL=0 \
        CARGO_PROFILE_TEST_DEBUG=0 CARGO_PROFILE_DEV_DEBUG=0 \
        RUSTFLAGS='-D warnings -C debuginfo=0' cargo "$@" 2>&1 | tee "$log"; then
        status=0
    else
        status=$?
    fi
    jq -cn --arg stage "$stage" --arg log "$log" --argjson exit_code "$status" \
        '{stage:$stage,log:$log,cargo_exit_code:$exit_code,
          target_reuse_disabled:true}' >> "$CHECKED_DIR/stages.ndjson" || return 86
    [[ "$status" -eq 0 ]] || return "$status"
    if rg -q '^\[RCH\] local \(|falling back to local|local fallback|\[rch-ci-fallback\] executing locally:' "$log"; then
        printf 'FATAL: %s used local fallback\n' "$stage" >&2
        return 86
    fi
    checked_verify_source "$stage.after" || return $?
    checked_verify_receipt "$stage" "$log" || return $?
    if [[ "$CHECKED_MODE" == managed-supervision && "$stage" == units ]]; then
        # This deliberately selects affected modules from the large lib suite.
        # Public journeys and the native prerequisite remain unfiltered.
        python3 - "$log" <<'PY' || return 87
import pathlib, re, sys
log = pathlib.Path(sys.argv[1]).read_text()
counts = re.findall(r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;", log, re.M)
assert len(counts) == 1 and int(counts[0][0]) > 0 and counts[0][1:4] == ("0", "0", "0"), counts
PY
    elif [[ "$stage" != public ]]; then
        rg -q '^test result: ok\. [1-9][0-9]* passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;' "$log" || {
            printf 'FATAL: %s must execute a nonzero, unfiltered, unignored test suite\n' "$stage" >&2
            return 87
        }
        if rg -q '^test result: (FAILED|ok\. 0 passed)|^test result:.*[1-9][0-9]* (failed|ignored|filtered out)' "$log"; then
            printf 'FATAL: %s includes an unsuccessful or incomplete test result\n' "$stage" >&2
            return 87
        fi
    fi
}

run_checked_admission_mode() {
    CHECKED_MODE="${1#--}"
    CHECKED_SCHEMA='asupersync.checked_obligation_runner.v1'
    CHECKED_BEAD='asupersync-bi2462.29'
    CHECKED_BASE=''
    CHECKED_FEATURES='test-internals,channel-mpsc-select-e2e'
    if [[ "$CHECKED_MODE" == managed-supervision ]]; then
        CHECKED_SCHEMA='asupersync.managed_supervision_runner.v1'
        CHECKED_BEAD='asupersync-bi2462.35'
        CHECKED_FEATURES='tls,test-internals'
    fi
    CHECKED_OVERLAYS=()
    CHECKED_BUILD_JOBS="${CHECKED_ADMISSION_BUILD_JOBS:-8}"
    CHECKED_CARGO_HOME="${CHECKED_ADMISSION_CARGO_HOME:-${CARGO_HOME:-}}"
    CHECKED_WORKER="${RCH_WORKER:-}"
    [[ "$CHECKED_BUILD_JOBS" =~ ^[1-9][0-9]*$ ]] || {
        printf 'CHECKED_ADMISSION_BUILD_JOBS must be a positive integer\n' >&2; return 86;
    }
    CHECKED_REMOTE_CARGO_ENV=()
    if [[ -n "$CHECKED_CARGO_HOME" ]]; then
        CHECKED_REMOTE_CARGO_ENV+=("CARGO_HOME=$CHECKED_CARGO_HOME")
    fi
    local no_overlay=0 path resolved option
    shift
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --base|--overlay-path|--features)
                option="$1"
                [[ $# -ge 2 ]] || { printf 'Missing value for %s\n' "$1" >&2; return 86; }
                case "$option" in
                    --base) CHECKED_BASE="$2" ;;
                    --features) CHECKED_FEATURES="$2" ;;
                    --overlay-path) CHECKED_OVERLAYS+=("$2") ;;
                esac
                shift 2 ;;
            --no-overlay) no_overlay=1; shift ;;
            *) printf 'Unknown checked admission option: %s\n' "$1" >&2; return 86 ;;
        esac
    done
    [[ "$CHECKED_BASE" =~ ^[0-9a-f]{40}$ ]] || { printf 'A full explicit --base commit is required\n' >&2; return 86; }
    [[ "$CHECKED_FEATURES" =~ ^[a-zA-Z0-9_,-]+$ ]] || return 86
    if [[ "$CHECKED_MODE" == managed-supervision ]]; then
        [[ "$CHECKED_FEATURES" == 'tls,test-internals' ]] || {
            printf 'Managed supervision requires --features tls,test-internals\n' >&2; return 86;
        }
    else
        [[ ",$CHECKED_FEATURES," == *,test-internals,* && ",$CHECKED_FEATURES," == *,channel-mpsc-select-e2e,* ]] || {
            printf 'Checked mode requires test-internals and channel-mpsc-select-e2e in --features\n' >&2; return 86;
        }
    fi
    if (( (no_overlay == 1 && ${#CHECKED_OVERLAYS[@]} != 0) || (no_overlay == 0 && ${#CHECKED_OVERLAYS[@]} == 0) )); then
        printf 'Select either --no-overlay or explicit --overlay-path files\n' >&2; return 86
    fi
    cd "$PROJECT_ROOT"
    [[ "$(git rev-parse --verify "$CHECKED_BASE^{commit}")" == "$CHECKED_BASE" ]] || return 86
    [[ "$(git branch --show-current)" == main ]] || return 86
    for option in jq rg sha256sum stat realpath timeout python3; do command -v "$option" >/dev/null || return 86; done
    for path in "${CHECKED_OVERLAYS[@]}"; do
        [[ "$path" != /* && "$path" != *$'\n'* && "$path" != *$'\r'* && "$path" != *$'\t'* && "/$path/" != */../* && "/$path/" != */./* ]] || return 86
        resolved=$(realpath --relative-to="$PROJECT_ROOT" -- "$path") || return 86
        [[ "$resolved" == "$path" && -f "$path" && ! -L "$path" ]] || {
            printf 'Overlay must name one canonical regular repository file: %s\n' "$path" >&2; return 86;
        }
    done
    CHECKED_RCH=$(command -v "${RCH_BIN:-rch}") || return 86
    [[ "$(basename "$CHECKED_RCH")" == rch ]] || return 86
    [[ "$(realpath "$CHECKED_RCH")" != "$PROJECT_ROOT/scripts/rch_ci_fallback.sh" ]] || return 86
    CHECKED_DIR="${CHECKED_ADMISSION_ARTIFACT_DIR:-$PROJECT_ROOT/target/e2e-results/obligation-cleanup/checked-$(date -u +%Y%m%dT%H%M%S)-$$}"
    CHECKED_TARGET="${RCH_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_checked_obligation_journey}"
    if [[ "$CHECKED_MODE" == managed-supervision ]]; then
        CHECKED_DIR="${MANAGED_SUPERVISION_ARTIFACT_DIR:-${TMPDIR:-/tmp}/asupersync-managed-supervision-$(date -u +%Y%m%dT%H%M%S)-$$}"
        CHECKED_TARGET="${RCH_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_managed_supervision}"
    fi
    if [[ -e "$CHECKED_DIR" || -L "$CHECKED_DIR" ]]; then
        printf 'FATAL: evidence directory already exists; preserving %s\n' "$CHECKED_DIR" >&2
        return 86
    fi
    mkdir -p "$(dirname "$CHECKED_DIR")"
    mkdir "$CHECKED_DIR" || return 86
    "$CHECKED_RCH" exec --help > "$CHECKED_DIR/rch-capabilities.txt"
    for option in --base --clean-overlay --overlay-path --no-overlay; do
        rg -q -- "$option" "$CHECKED_DIR/rch-capabilities.txt" || { printf 'Installed RCH lacks %s\n' "$option" >&2; return 86; }
    done
    CHECKED_SOURCE_ARGS=(--base "$CHECKED_BASE" --clean-overlay)
    if (( no_overlay )); then
        CHECKED_SOURCE_ARGS+=(--no-overlay)
    else
        for path in "${CHECKED_OVERLAYS[@]}"; do CHECKED_SOURCE_ARGS+=(--overlay-path "$path"); done
    fi
    checked_selection_json > "$CHECKED_DIR/source-selection.json"
    : > "$CHECKED_DIR/stages.ndjson"
    CHECKED_STATUS=failed
    CHECKED_PHASE=admitted
    CHECKED_STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    CHECKED_OVERLAY_FINGERPRINT=''
    trap checked_finish_summary EXIT
    # Keep every stage on a fresh target: source-inspection tests can otherwise
    # reuse a stale CARGO_MANIFEST_DIR baked into a pooled-target binary.
    checked_stage native test --jobs "$CHECKED_BUILD_JOBS" -p asupersync --locked --features "$CHECKED_FEATURES" \
        --test runtime_abort_vs_cancel_semantics_audit -- --nocapture --test-threads=1 || return $?
    if [[ "$CHECKED_MODE" == managed-supervision ]]; then
        run_managed_supervision_stages || return $?
        CHECKED_PHASE=complete
        CHECKED_STATUS=passed
        return 0
    fi
    for option in \
        abort_repolls_a_mutex_parked_operation_to_graceful_cancellation \
        abort_repolls_a_capacity_parked_send_to_graceful_cancellation \
        abort_repolls_a_semaphore_parked_acquire_to_graceful_cancellation \
        checked_zero_quota_refuses_before_publication_on_native_current_thread \
        checked_zero_quota_refuses_before_publication_on_native_sharded_workers \
        checked_owned_permit_cancellation_and_same_poll_reuse_on_native_current_thread \
        checked_owned_permit_cancellation_and_same_poll_reuse_on_native_sharded_workers \
        checked_other_primitives_refuse_cancel_and_reuse_on_native_current_thread \
        checked_other_primitives_refuse_cancel_and_reuse_on_native_sharded_workers; do
        # In single-threaded --nocapture output, scenario logging can split
        # the test-start prefix from its final ok. checked_stage has already
        # required an unfiltered suite with zero failures and ignored tests.
        [[ "$(rg -c "^test $option \\.\\.\\. " "$CHECKED_DIR/native.log")" == 1 ]] || { printf 'Missing or duplicate native sentinel %s\n' "$option" >&2; return 88; }
    done
    checked_stage lifecycle test --jobs "$CHECKED_BUILD_JOBS" -p asupersync --locked --features "$CHECKED_FEATURES" \
        --test obligation_lifecycle_e2e -- --nocapture --test-threads=1 || return $?
    [[ "$(rg -c '^test checked_public_primitives_share_lab_region_quota \.\.\. ' "$CHECKED_DIR/lifecycle.log")" == 1 ]] || return 88
    checked_stage public run --jobs "$CHECKED_BUILD_JOBS" -p asupersync --locked --features "$CHECKED_FEATURES" \
        --bin channel_mpsc_select_e2e || return $?
    sed -n 's/^ASUPERSYNC_CHECKED_OBLIGATION_JOURNEY //p' "$CHECKED_DIR/public.log" > "$CHECKED_DIR/public-journey.json"
    jq -es 'length == 1 and (.[0] |
        .schema_version == "asupersync.checked_obligation_journey.v1" and
        .delivered_bytes > 0 and .disconnect_preserved_bytes > 0 and
        .reserved == 5 and .committed == 2 and .aborted == 3 and
        .refused == 0 and .leaked == 0 and .pending == 0 and .open_tickets == 0 and
        .posted == .applied and .finalizers_started == 1 and .finalizers_finished == 1 and
        .physical_reserved == 0 and .queued_messages == 0 and .send_waiters == 0 and .recv_waiters == 0 and
        .same_channel_reused_after_close == true and .report.quiescent == true and
        .report.refinement_firewall.rule_id == null and
        .report.refinement_firewall.skipped_due_to_trace_truncation == false)
    ' "$CHECKED_DIR/public-journey.json" >/dev/null || return 89
    CHECKED_PHASE=complete
    CHECKED_STATUS=passed
}

run_managed_supervision_stages() {
    checked_stage units test --jobs "$CHECKED_BUILD_JOBS" -p asupersync --locked \
        --features "$CHECKED_FEATURES" --lib -- \
        supervision:: record::finalizer:: record::region:: cx::child_region:: runtime::state:: \
        native_current_thread_shutdown_budget_runs_and_retires_real_finalizers \
        native_sharded_shutdown_budget_runs_and_retires_real_finalizers \
        external_only_finalizer_budget_activation_wakes_and_retires_actual_cleanup \
        managed_supervisor_runtime_signal_source \
        --nocapture --test-threads=1 || return $?
    local name
    for name in \
        managed_real_generations_cover_all_restart_modes_and_outcomes \
        managed_three_strategies_drain_actual_finalizers_before_replacement \
        managed_parent_cancel_during_root_finalizer_precedes_success_publication \
        managed_shutdown_enforces_actual_finalizers_and_retains_reclaimed_receipts \
        managed_close_distinguishes_cancelled_body_from_descendant_cleanup_failure \
        explicit_finalizer_actual_lab_task_deadline_wakes_through_cancel_mask \
        native_current_thread_shutdown_budget_runs_and_retires_real_finalizers \
        native_sharded_shutdown_budget_runs_and_retires_real_finalizers \
        external_only_finalizer_budget_activation_wakes_and_retires_actual_cleanup \
        managed_supervisor_runtime_signal_source; do
        [[ "$(rg -c "^test .*::$name \\.\\.\\. " "$CHECKED_DIR/units.log")" == 1 ]] || {
            printf 'Missing or duplicate supervisor unit sentinel %s\n' "$name" >&2; return 88;
        }
    done
    checked_stage supervision test --jobs "$CHECKED_BUILD_JOBS" -p asupersync --locked \
        --features "$CHECKED_FEATURES" --test supervision_regression -- \
        --nocapture --test-threads=1 || return $?
    python3 - "$CHECKED_DIR/supervision.log" > "$CHECKED_DIR/supervision-journeys.json" <<'PY' || return 89
import json, pathlib, re, sys
log = pathlib.Path(sys.argv[1]).read_text()
for name in ("public_managed_supervisor_seeded_lab_work_and_cleanup",
             "public_managed_supervisor_native_work_and_cleanup",
             "public_managed_supervisor_owned_sigterm_shutdown"):
    assert len(re.findall(r"^test managed_public::" + name + r" \.\.\. ", log, re.M)) == 1, name
def rows(marker):
    return [json.loads(line.split(marker, 1)[1]) for line in log.splitlines() if marker in line]
journeys = rows("ASUPERSYNC_MANAGED_SUPERVISOR ")
assert len(journeys) == 5
assert sorted(row["seed"] for row in journeys if row["backend"] == "lab") == [0x3501, 0x3502, 0x3503]
native = ["native_current_thread", "native_two_worker_sharded"]
assert sorted(row["backend"] for row in journeys if row["backend"] != "lab") == native
for row in journeys:
    assert row["live_tasks"] == row["leaks"] == 0
    if row["backend"] == "lab":
        assert row["pending_obligations"] == 0
    else:
        assert row["shutdown_completed"]
    cases = row["journeys"]
    assert len(cases) == 18
    modes = [case for case in cases if case["scenario"] == "public_restart_mode"]
    assert {(case["mode"], case["terminal"]) for case in modes} == {
        (mode, terminal) for mode in ("Permanent", "Transient", "Temporary") for terminal in range(3)}
    for case in modes:
        restarts = int(case["mode"] == "Permanent" or (case["mode"] == "Transient" and case["terminal"] != 0))
        assert case["started"] == case["joined"] == 1 + restarts and case["restart_batches"] == restarts
    sets = [case for case in cases if case["scenario"] == "public_restart_sets"]
    assert len(sets) == 6 and sorted(case["policy"] for case in sets) == sorted(["OneForOne", "OneForAll", "RestForOne"] * 2)
    for case in cases:
        if case["scenario"] == "public_cancel_during_factory":
            assert case["started"] == case["joined"] == 1 and case["never_started_child"] == "b" and case["cleanup_crossed_pending"]
        if case["scenario"] == "public_cancel_during_actual_backoff":
            assert case["started"] == case["joined"] == 1 and case["restart_batches"] == 0 and case["actual_sleep_witness"]
        if case["scenario"] == "public_shared_intensity_actual_parent_escalation":
            assert case["started"] == case["joined"] == 3 and case["restart_batches"] == case["escalations"] == 1
signals = rows("ASUPERSYNC_SUPERVISOR_SIGTERM_COMPLETE ")
assert len(signals) == 2 and sorted(row["backend"] for row in signals) == native
for row in signals:
    assert row["runtime_shutdown"] and row["live_tasks"] == row["leaks"] == 0
    case = row["journey"]
    assert case["signal"] == "actual_process_SIGTERM"
    assert case["selected"] == case["started"] == case["joined"] == 4 and case["restart_batches"] == 0
    assert case["payloads"] == [700, 701, 702, 703]
    assert case["negative_controls"] == ["zero_selected_generations", "premature_generation_completion"]
print(json.dumps(dict(journeys=journeys, native_signal_shutdown=signals), sort_keys=True))
PY
}

if [[ "${1:-}" == --checked-admission || "${1:-}" == --managed-supervision ]]; then
    run_checked_admission_mode "$@"
    exit $?
fi

OUTPUT_DIR="${PROJECT_ROOT}/target/e2e-results/obligation-cleanup"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LOG_FILE="${OUTPUT_DIR}/obligation_cleanup_e2e_${TIMESTAMP}.log"
ARTIFACT_DIR="${OUTPUT_DIR}/artifacts_${TIMESTAMP}"
SUMMARY_FILE="${ARTIFACT_DIR}/summary.json"
TEST_FILTER="${1:-test_client_disconnect_forced_cancel_cleans_pending_obligations}"

case "$TEST_FILTER" in
    *supervisor_restart_pending_ack*)
        SCENARIO_ID="supervisor_restart_pending_ack_cleanup"
        EXPECTED_CHAOS_CANCELLATIONS=12
        WORKLOAD_ID="${WORKLOAD_ID:-asupersync-9u057b.9}"
        RUNTIME_PROFILE="${RUNTIME_PROFILE:-real-service-obligation-chaos-supervisor-restart}"
        WORKLOAD_CONFIG_REF="${WORKLOAD_CONFIG_REF:-scripts/test_obligation_cleanup_e2e.sh::supervisor_restart_pending_ack}"
        ;;
    *)
        SCENARIO_ID="client_disconnect_forced_cancel_cleanup"
        EXPECTED_CHAOS_CANCELLATIONS=16
        WORKLOAD_ID="${WORKLOAD_ID:-asupersync-9u057b.5}"
        RUNTIME_PROFILE="${RUNTIME_PROFILE:-real-service-obligation-chaos}"
        WORKLOAD_CONFIG_REF="${WORKLOAD_CONFIG_REF:-scripts/test_obligation_cleanup_e2e.sh::client_disconnect_forced_cancel}"
        ;;
esac

RCH_BIN="${RCH_BIN:-rch}"
RCH_TARGET_DIR="${RCH_TARGET_DIR:-${TMPDIR:-/tmp}/rch-target-obligation-cleanup-e2e-${USER:-unknown}-${TIMESTAMP}-$$}"
RCH_REQUIRE_REMOTE="${RCH_REQUIRE_REMOTE:-1}"
RCH_QUEUE_WHEN_BUSY="${RCH_QUEUE_WHEN_BUSY:-1}"
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS="${RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS:-300}"

export TEST_LOG_LEVEL="${TEST_LOG_LEVEL:-trace}"
export RUST_LOG="${RUST_LOG:-asupersync=debug}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export TEST_SEED="${TEST_SEED:-0x90057B5}"
export OBLIGATION_E2E_TESTS="${OBLIGATION_E2E_TESTS:-true}"
export ASUPERSYNC_TEST_ARTIFACTS_DIR="${ASUPERSYNC_TEST_ARTIFACTS_DIR:-${ARTIFACT_DIR}/test-artifacts}"
TEST_ARTIFACT_SCENARIO_DIR="${ASUPERSYNC_TEST_ARTIFACTS_DIR}/${SCENARIO_ID}"

if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
    echo "FATAL: rch is required and was not found/executable at: ${RCH_BIN}" >&2
    exit 1
fi

mkdir -p "$OUTPUT_DIR" "$ARTIFACT_DIR" "$ASUPERSYNC_TEST_ARTIFACTS_DIR"

run_timeout_cargo() {
    local timeout_sec="$1"
    shift
    RCH_REQUIRE_REMOTE="$RCH_REQUIRE_REMOTE" \
    RCH_QUEUE_WHEN_BUSY="$RCH_QUEUE_WHEN_BUSY" \
    RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS="$RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS" \
    timeout "$timeout_sec" "$RCH_BIN" exec -- env \
        CARGO_TARGET_DIR="$RCH_TARGET_DIR" \
        TEST_LOG_LEVEL="$TEST_LOG_LEVEL" \
        RUST_LOG="$RUST_LOG" \
        RUST_BACKTRACE="$RUST_BACKTRACE" \
        TEST_SEED="$TEST_SEED" \
        OBLIGATION_E2E_TESTS="$OBLIGATION_E2E_TESTS" \
        ASUPERSYNC_TEST_ARTIFACTS_DIR="$ASUPERSYNC_TEST_ARTIFACTS_DIR" \
        cargo "$@"
}

reject_rch_local_fallback_log() {
    local log_path="$1"
    if grep -Eq '^\[RCH\] local \(|falling back to local|local fallback' "$log_path" 2>/dev/null; then
        echo "  FATAL: rch local fallback detected; refusing local cargo execution"
        echo "rch local fallback detected; refusing local cargo execution" > "${ARTIFACT_DIR}/rch_local_fallback.txt"
        return 86
    fi
}

echo "==================================================================="
echo "          Asupersync Obligation Cleanup No-Mock E2E"
echo "==================================================================="
echo "  Test filter:      ${TEST_FILTER}"
echo "  Output:           ${LOG_FILE}"
echo "  Artifacts:        ${ARTIFACT_DIR}"
echo "  Test artifacts:   ${ASUPERSYNC_TEST_ARTIFACTS_DIR}"
echo "  RCH target dir:   ${RCH_TARGET_DIR}"
echo "  RCH remote only:  ${RCH_REQUIRE_REMOTE}"
echo ""

TEST_RESULT=0
pushd "$PROJECT_ROOT" >/dev/null
if run_timeout_cargo 900 test -p asupersync --no-default-features --features obligation-cleanup-e2e --test obligation_cleanup_e2e --message-format=short "${TEST_FILTER}" -- --nocapture --test-threads=1 2>&1 | tee "$LOG_FILE"; then
    TEST_RESULT=0
else
    TEST_RESULT=$?
fi
popd >/dev/null

if ! reject_rch_local_fallback_log "$LOG_FILE"; then
    TEST_RESULT=86
fi

materialize_test_artifacts_from_log() {
    mkdir -p "$TEST_ARTIFACT_SCENARIO_DIR"

    awk '
        /ASUPERSYNC_OBLIGATION_CLEANUP_EVENTS_BEGIN / { capture = 1; next }
        /ASUPERSYNC_OBLIGATION_CLEANUP_EVENTS_END / { capture = 0; next }
        capture { print }
    ' "$LOG_FILE" > "${TEST_ARTIFACT_SCENARIO_DIR}/events.ndjson"

    sed -n 's/^ASUPERSYNC_OBLIGATION_CLEANUP_SUMMARY_JSON //p' "$LOG_FILE" \
        | tail -1 > "${TEST_ARTIFACT_SCENARIO_DIR}/summary.json"
}

materialize_test_artifacts_from_log

PATTERN_FAILURES=0
check_pattern() {
    local pattern="$1"
    local label="$2"
    if grep -Eq "$pattern" "$LOG_FILE" 2>/dev/null; then
        echo "  ERROR: ${label}"
        grep -En "$pattern" "$LOG_FILE" | head -5 > "${ARTIFACT_DIR}/${label// /_}.txt" 2>/dev/null || true
        ((PATTERN_FAILURES++)) || true
    fi
}

check_pattern "panicked at" "panic detected"
check_pattern "assertion failed" "assertion failure"
check_pattern "test result: FAILED" "cargo reported failures"
check_pattern "Task leak detected" "task leak detected"
check_pattern 'Leak detected: [1-9][0-9]* obligations leaked|obligation leak detected|"zero_leaks":[[:space:]]*false|"leaked_after":[[:space:]]*[1-9]' "obligation leak"

if [ "$TEST_RESULT" -eq 0 ]; then
    require_pattern() {
        local pattern="$1"
        local label="$2"
        if ! grep -Eq "$pattern" "$LOG_FILE" 2>/dev/null; then
            echo "  ERROR: missing ${label}"
            echo "missing ${label}: ${pattern}" > "${ARTIFACT_DIR}/${label// /_}.txt"
            ((PATTERN_FAILURES++)) || true
        fi
    }

    require_pattern '"schema_version":"asupersync\.atp\.log\.event\.v1"' "ATP structured log schema"
    require_pattern '"event_type":"seed_selected"' "ATP seed-selected event"
    require_pattern '"event_type":"oracle_checked"' "ATP oracle-checked event"
    require_pattern '"event_type":"test_completed"' "ATP test-completed event"
    require_pattern "\"chaos_cancellations\"[[:space:]]*:[[:space:]]*${EXPECTED_CHAOS_CANCELLATIONS}" "forced-cancel chaos decisions"

    if [ ! -s "${TEST_ARTIFACT_SCENARIO_DIR}/events.ndjson" ] || [ ! -s "${TEST_ARTIFACT_SCENARIO_DIR}/summary.json" ]; then
        echo "  ERROR: test artifact materialization failed"
        ((PATTERN_FAILURES++)) || true
    fi
fi

PASSED=$(grep -c "^test .* ok$" "$LOG_FILE" 2>/dev/null || true)
FAILED=$(grep -c "^test .* FAILED$" "$LOG_FILE" 2>/dev/null || true)
RUN_ENDED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SUITE_STATUS="failed"
if [ "$TEST_RESULT" -eq 0 ] && [ "$PATTERN_FAILURES" -eq 0 ]; then
    SUITE_STATUS="passed"
fi

cat > "$SUMMARY_FILE" << ENDJSON
{
  "schema_version": "obligation-cleanup-e2e-runner-summary-v1",
  "suite_id": "obligation_cleanup_e2e",
  "scenario_id": "${SCENARIO_ID}",
  "workload_id": "${WORKLOAD_ID}",
  "runtime_profile": "${RUNTIME_PROFILE}",
  "workload_config_ref": "${WORKLOAD_CONFIG_REF}",
  "seed": "${TEST_SEED}",
  "started_ts": "${RUN_STARTED_TS}",
  "ended_ts": "${RUN_ENDED_TS}",
  "status": "${SUITE_STATUS}",
  "test_filter": "${TEST_FILTER}",
  "rch_bin": "${RCH_BIN}",
  "rch_target_dir": "${RCH_TARGET_DIR}",
  "rch_require_remote": "${RCH_REQUIRE_REMOTE}",
  "tests_passed": ${PASSED},
  "tests_failed": ${FAILED},
  "exit_code": ${TEST_RESULT},
  "pattern_failures": ${PATTERN_FAILURES},
  "log_file": "${LOG_FILE}",
  "artifact_dir": "${ARTIFACT_DIR}",
  "test_artifact_dir": "${ASUPERSYNC_TEST_ARTIFACTS_DIR}",
  "repro_command": "RCH_REQUIRE_REMOTE=1 RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=300 RCH_TARGET_DIR='${RCH_TARGET_DIR}' ASUPERSYNC_TEST_ARTIFACTS_DIR='${ASUPERSYNC_TEST_ARTIFACTS_DIR}' bash scripts/test_obligation_cleanup_e2e.sh ${TEST_FILTER}"
}
ENDJSON

echo ""
echo "Summary: ${SUMMARY_FILE}"
echo "Status: ${SUITE_STATUS}"

if [ "$TEST_RESULT" -ne 0 ] || [ "$PATTERN_FAILURES" -ne 0 ]; then
    exit 1
fi
