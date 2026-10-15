#!/usr/bin/env bash
set -euo pipefail

# Runtime/sync proof runner for asupersync-a5d34a.
#
# Emits mock-code-finder evidence JSONL validated by the shared
# scripts/validate_mock_code_finder_evidence.py contract. Rust execution is
# routed through rch by default; use --self-test and --list for cheap checks.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CONTRACT="${PROJECT_ROOT}/artifacts/mock_code_finder_verification_contract_v1.json"
VALIDATOR="${PROJECT_ROOT}/scripts/validate_mock_code_finder_evidence.py"
RCH_BIN="${RCH_BIN:-rch}"
CARGO_BIN="${CARGO_BIN:-cargo}"
RCH_WRAPPER_TIMEOUT="${RCH_WRAPPER_TIMEOUT:-240s}"
RUN_ID="${RUN_ID:-current}"
ARTIFACT_ROOT="${ARTIFACT_ROOT:-${PROJECT_ROOT}/artifacts/mock-code-finder/asupersync-a5d34a}"
MODE="execute"
USE_RCH=1
SCENARIO_FILTER=""
ALLOW_LOCAL_CARGO="${ALLOW_LOCAL_CARGO:-0}"

SCHEMA_VERSION="mock-code-finder-evidence-jsonl-schema-v1"
BEAD_ID="asupersync-a5d34a"
SUBSYSTEM="runtime-sync"
TARGET_DIR_EXPR="\${TMPDIR:-/tmp}/rch_target_asupersync_a5d34a_runtime_sync"

declare -a SCENARIOS=(
    "RUNTIME-SCHEDULER-SHUTDOWN-BOUNDARY-LIVE"
    "RUNTIME-FINALIZER-QUIESCENCE-LIVE"
    "RUNTIME-FINALIZER-DRAIN-SOURCE-LIVE"
    "RUNTIME-OBLIGATION-CANCEL-DRAIN-FINALIZE-LIVE"
    "SYNC-RWLOCK-UPGRADE-CANCEL-LIVE"
    "SYNC-RWLOCK-WRITER-FAIRNESS-LIVE"
    "CHANNEL-ONESHOT-TRIPWIRE-SCAN-LIVE"
)

usage() {
    cat <<'USAGE'
Usage: bash scripts/run_runtime_sync_invariant_evidence.sh [options]

Options:
  --execute                 Run selected runtime/sync proof scenarios (default)
  --dry-run                 List commands and artifact paths without running cargo
  --self-test               Validate script fixtures and shared negative cases without cargo
  --list                    List scenarios and aggregate-runner registration metadata
  --scenario <SCENARIO_ID>  Run or dry-run one scenario
  --artifact-root <PATH>    Override output root (default: artifacts/mock-code-finder/asupersync-a5d34a)
  --run-id <RUN_ID>         Stable run directory name (default: current)
  RCH_WRAPPER_TIMEOUT       rch wrapper timeout env var (default: 240s)
  --local                   Run cargo locally only with ALLOW_LOCAL_CARGO=1 (not for agent validation)
  -h, --help                Show this help
USAGE
}

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

repo_relative() {
    local path="$1"
    case "$path" in
        "$PROJECT_ROOT"/*) printf '%s' "${path#"$PROJECT_ROOT"/}" ;;
        *) printf '%s' "$path" ;;
    esac
}

has_scenario() {
    local candidate="$1"
    local scenario
    for scenario in "${SCENARIOS[@]}"; do
        if [[ "$scenario" == "$candidate" ]]; then
            return 0
        fi
    done
    return 1
}

git_state() {
    local sha
    sha="$(git -C "$PROJECT_ROOT" rev-parse --short HEAD)"
    if [[ -n "$(git -C "$PROJECT_ROOT" status --porcelain)" ]]; then
        printf 'main@%s-dirty' "$sha"
    else
        printf 'main@%s' "$sha"
    fi
}

cargo_env_prefix() {
    printf 'env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" CARGO_TARGET_DIR=%s' "$TARGET_DIR_EXPR"
}

scenario_command() {
    local scenario_id="$1"
    case "$scenario_id" in
        RUNTIME-SCHEDULER-SHUTDOWN-BOUNDARY-LIVE)
            printf '%s %s test -p asupersync --lib scheduler_shutdown -- --nocapture\n' "$(cargo_env_prefix)" "$CARGO_BIN"
            ;;
        RUNTIME-FINALIZER-QUIESCENCE-LIVE)
            printf '%s %s test -p asupersync --lib cancel_drain_finalize_nested_regions -- --nocapture\n' "$(cargo_env_prefix)" "$CARGO_BIN"
            ;;
        RUNTIME-FINALIZER-DRAIN-SOURCE-LIVE)
            printf '%s %s test -p asupersync --lib drain_ready_async_finalizers_runs_async_cleanup_even_with_zero_task_limit -- --nocapture\n' "$(cargo_env_prefix)" "$CARGO_BIN"
            ;;
        RUNTIME-OBLIGATION-CANCEL-DRAIN-FINALIZE-LIVE)
            printf '%s %s test -p asupersync --lib multiple_tasks_obligations_cancel_drain_finalize -- --nocapture\n' "$(cargo_env_prefix)" "$CARGO_BIN"
            ;;
        SYNC-RWLOCK-UPGRADE-CANCEL-LIVE)
            printf '%s %s test -p asupersync --lib audit_rwlock_no_read_to_write_upgrade -- --nocapture\n' "$(cargo_env_prefix)" "$CARGO_BIN"
            ;;
        SYNC-RWLOCK-WRITER-FAIRNESS-LIVE)
            printf '%s %s test -p asupersync --lib audit_rwlock_writer_starvation_prevention -- --nocapture\n' "$(cargo_env_prefix)" "$CARGO_BIN"
            ;;
        CHANNEL-ONESHOT-TRIPWIRE-SCAN-LIVE)
            printf 'bash scripts/run_runtime_sync_invariant_evidence.sh --internal-oneshot-scan\n'
            ;;
        *)
            echo "unknown scenario: $scenario_id" >&2
            return 1
            ;;
    esac
}

scenario_test_filter() {
    case "$1" in
        RUNTIME-SCHEDULER-SHUTDOWN-BOUNDARY-LIVE) printf 'scheduler_shutdown\n' ;;
        RUNTIME-FINALIZER-QUIESCENCE-LIVE) printf 'cancel_drain_finalize_nested_regions\n' ;;
        RUNTIME-FINALIZER-DRAIN-SOURCE-LIVE) printf 'drain_ready_async_finalizers_runs_async_cleanup_even_with_zero_task_limit\n' ;;
        RUNTIME-OBLIGATION-CANCEL-DRAIN-FINALIZE-LIVE) printf 'multiple_tasks_obligations_cancel_drain_finalize\n' ;;
        SYNC-RWLOCK-UPGRADE-CANCEL-LIVE) printf 'audit_rwlock_no_read_to_write_upgrade\n' ;;
        SYNC-RWLOCK-WRITER-FAIRNESS-LIVE) printf 'audit_rwlock_writer_starvation_prevention\n' ;;
        CHANNEL-ONESHOT-TRIPWIRE-SCAN-LIVE) printf 'src/channel/oneshot.rs no-unimplemented scan\n' ;;
        *) return 1 ;;
    esac
}

scenario_expected_behavior() {
    case "$1" in
        RUNTIME-SCHEDULER-SHUTDOWN-BOUNDARY-LIVE)
            printf 'Scheduler shutdown remains an idempotent worker-stop signal, wakes workers, and does not grow fake shutdown_now or shutdown_timeout APIs.\n'
            ;;
        RUNTIME-FINALIZER-QUIESCENCE-LIVE)
            printf 'Nested cancellation propagates from root to child, drains child work first, closes the child, then closes the root after all live tasks and children are gone.\n'
            ;;
        RUNTIME-FINALIZER-DRAIN-SOURCE-LIVE)
            printf 'Ready async finalizers are scheduled even when normal task admission is closed, keep the region uncloseable while running, then record cleanup execution and close history.\n'
            ;;
        RUNTIME-OBLIGATION-CANCEL-DRAIN-FINALIZE-LIVE)
            printf 'Cancel-drain-finalize resolves mixed obligations by preserving committed permits, auto-aborting orphaned obligations, closing the region, and emitting reserve/commit/abort trace events.\n'
            ;;
        SYNC-RWLOCK-UPGRADE-CANCEL-LIVE)
            printf 'RwLock explicitly rejects in-place read-to-write upgrade, queues writers behind readers, and cancellation removes queued writer state without leaks.\n'
            ;;
        SYNC-RWLOCK-WRITER-FAIRNESS-LIVE)
            printf 'Waiting writers block late readers, acquire after active readers release, and queued readers resume after the writer turn completes.\n'
            ;;
        CHANNEL-ONESHOT-TRIPWIRE-SCAN-LIVE)
            printf 'Production oneshot source contains no unimplemented/todo panic tripwire and documents the cancelled reservation path.\n'
            ;;
        *) return 1 ;;
    esac
}

scenario_source_files() {
    case "$1" in
        RUNTIME-SCHEDULER-SHUTDOWN-BOUNDARY-LIVE)
            printf '["src/runtime/scheduler/shutdown_behavior_audit_test.rs","src/runtime/scheduler/three_lane.rs","src/runtime/state.rs"]\n'
            ;;
        RUNTIME-FINALIZER-QUIESCENCE-LIVE)
            printf '["src/runtime/state.rs","src/record/region.rs","src/record/task.rs"]\n'
            ;;
        RUNTIME-FINALIZER-DRAIN-SOURCE-LIVE)
            printf '["src/runtime/state.rs","src/record/region.rs","src/record/task.rs"]\n'
            ;;
        RUNTIME-OBLIGATION-CANCEL-DRAIN-FINALIZE-LIVE)
            printf '["src/runtime/state.rs","src/record/obligation.rs","src/record/region.rs"]\n'
            ;;
        SYNC-RWLOCK-UPGRADE-CANCEL-LIVE|SYNC-RWLOCK-WRITER-FAIRNESS-LIVE)
            printf '["src/sync/rwlock.rs"]\n'
            ;;
        CHANNEL-ONESHOT-TRIPWIRE-SCAN-LIVE)
            printf '["src/channel/oneshot.rs"]\n'
            ;;
        *) return 1 ;;
    esac
}

run_oneshot_scan() {
    cd "$PROJECT_ROOT"
    local matches=""
    matches="$(rg -n 'unimplemented!\(|todo!\(|panic!\("TODO' src/channel/oneshot.rs || true)"
    if [[ -n "$matches" ]]; then
        printf 'oneshot tripwire scan failed:\n%s\n' "$matches"
        return 1
    fi
    rg -n 'Cancelled\(T\)|pre-commit phase|reserve\(&cx\)' src/channel/oneshot.rs
    printf 'oneshot tripwire scan passed: no unimplemented/todo panic remains in src/channel/oneshot.rs\n'
}

validate_cargo_output() {
    local combined_path="$1"
    local scenario_id="$2"
    local test_count

    if ! grep -Fq "test result: ok" "$combined_path"; then
        printf '%s did not emit a successful cargo test summary' "$scenario_id"
        return 1
    fi
    test_count="$(grep -Eo 'test result: ok\. [0-9]+ passed' "$combined_path" | tail -n1 | awk '{print $4}' || true)"
    if [[ -z "$test_count" || "$test_count" -le 0 ]]; then
        printf '%s cargo summary did not report any passed tests' "$scenario_id"
        return 1
    fi
    if grep -Eiq 'test result: FAILED|panicked at|error\[|error:' "$combined_path"; then
        printf '%s output contains failure markers despite summary' "$scenario_id"
        return 1
    fi
    printf 'cargo test summary ok; passed_tests=%s' "$test_count"
}

validate_scan_output() {
    local combined_path="$1"
    if ! grep -Fq 'oneshot tripwire scan passed' "$combined_path"; then
        printf 'oneshot scan did not emit pass marker'
        return 1
    fi
    if grep -Eq 'unimplemented!\(|todo!\(|panic!\("TODO' "$combined_path"; then
        printf 'oneshot scan output contains forbidden tripwire marker'
        return 1
    fi
    printf 'oneshot source scan has no unimplemented/todo panic tripwire'
}

write_evidence_record() {
    local jsonl_path="$1"
    local scenario_id="$2"
    local command="$3"
    local rch_command="$4"
    local test_filter="$5"
    local input_artifact="$6"
    local output_artifact="$7"
    local expected_behavior="$8"
    local actual_behavior="$9"
    local verdict="${10}"
    local first_failure_line="${11}"
    local duration_ms="${12}"
    local source_files_json="${13}"

    cat >> "$jsonl_path" <<EOF
{"schema_version":"${SCHEMA_VERSION}","bead_id":"${BEAD_ID}","scenario_id":"$(json_escape "$scenario_id")","subsystem":"${SUBSYSTEM}","support_class":"production_live","source_files_inspected":${source_files_json},"command":"$(json_escape "$command")","rch_command_if_used":"$(json_escape "$rch_command")","cargo_features":["test-internals"],"test_filter":"$(json_escape "$test_filter")","env_keys_required":["ARTIFACT_ROOT","RUN_ID","RCH_BIN","CARGO_BIN","RCH_WRAPPER_TIMEOUT"],"deterministic_seed_or_fixture_id":"runtime-sync-a5d34a-fixed-filters","input_artifact":"$(json_escape "$input_artifact")","output_artifact":"$(json_escape "$output_artifact")","expected_behavior":"$(json_escape "$expected_behavior")","actual_behavior":"$(json_escape "$actual_behavior")","verdict":"${verdict}","first_failure_line":"$(json_escape "$first_failure_line")","duration_ms":${duration_ms},"git_sha_or_tree_state":"$(git_state)","blocker_bead_id":"","evidence_quality":"live"}
EOF
}

first_failure_line_from() {
    local path="$1"
    grep -m1 -E 'error:|FAILED|FAIL|panicked at|blocked|unsupported|tripwire scan failed' "$path" 2>/dev/null || true
}

reject_rch_local_fallback_capture() {
    local scenario_id="$1"
    local combined_path="$2"
    local marker_path
    marker_path="$(dirname "$combined_path")/${scenario_id}.rch_local_fallback"

    if grep -Eq '^\[RCH\] local \(|falling back to local' "$combined_path" 2>/dev/null; then
        echo "FATAL: rch local fallback detected in ${scenario_id}; refusing local cargo execution" >&2
        echo "rch local fallback detected in ${scenario_id}; refusing local cargo execution" > "$marker_path"
        exit 86
    fi
}

run_rch_command_capture() {
    local scenario_id="$1"
    local stdout_path="$2"
    local stderr_path="$3"
    local target_dir="${TMPDIR:-/tmp}/rch_target_asupersync_a5d34a_runtime_sync"

    case "$scenario_id" in
        RUNTIME-SCHEDULER-SHUTDOWN-BOUNDARY-LIVE)
            timeout "$RCH_WRAPPER_TIMEOUT" "$RCH_BIN" exec -- \
                env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="$target_dir" \
                "$CARGO_BIN" test -p asupersync --lib scheduler_shutdown -- --nocapture \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        RUNTIME-FINALIZER-QUIESCENCE-LIVE)
            timeout "$RCH_WRAPPER_TIMEOUT" "$RCH_BIN" exec -- \
                env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="$target_dir" \
                "$CARGO_BIN" test -p asupersync --lib cancel_drain_finalize_nested_regions -- --nocapture \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        RUNTIME-FINALIZER-DRAIN-SOURCE-LIVE)
            timeout "$RCH_WRAPPER_TIMEOUT" "$RCH_BIN" exec -- \
                env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="$target_dir" \
                "$CARGO_BIN" test -p asupersync --lib \
                drain_ready_async_finalizers_runs_async_cleanup_even_with_zero_task_limit -- --nocapture \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        RUNTIME-OBLIGATION-CANCEL-DRAIN-FINALIZE-LIVE)
            timeout "$RCH_WRAPPER_TIMEOUT" "$RCH_BIN" exec -- \
                env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="$target_dir" \
                "$CARGO_BIN" test -p asupersync --lib \
                multiple_tasks_obligations_cancel_drain_finalize -- --nocapture \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        SYNC-RWLOCK-UPGRADE-CANCEL-LIVE)
            timeout "$RCH_WRAPPER_TIMEOUT" "$RCH_BIN" exec -- \
                env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="$target_dir" \
                "$CARGO_BIN" test -p asupersync --lib audit_rwlock_no_read_to_write_upgrade -- --nocapture \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        SYNC-RWLOCK-WRITER-FAIRNESS-LIVE)
            timeout "$RCH_WRAPPER_TIMEOUT" "$RCH_BIN" exec -- \
                env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="$target_dir" \
                "$CARGO_BIN" test -p asupersync --lib audit_rwlock_writer_starvation_prevention -- --nocapture \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        *)
            echo "unknown rch scenario: $scenario_id" >&2
            return 1
            ;;
    esac
}

run_local_command_capture() {
    local scenario_id="$1"
    local stdout_path="$2"
    local stderr_path="$3"
    local target_dir="${TMPDIR:-/tmp}/rch_target_asupersync_a5d34a_runtime_sync"

    case "$scenario_id" in
        RUNTIME-SCHEDULER-SHUTDOWN-BOUNDARY-LIVE)
            env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="$target_dir" \
                "$CARGO_BIN" test -p asupersync --lib scheduler_shutdown -- --nocapture \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        RUNTIME-FINALIZER-QUIESCENCE-LIVE)
            env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="$target_dir" \
                "$CARGO_BIN" test -p asupersync --lib cancel_drain_finalize_nested_regions -- --nocapture \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        RUNTIME-FINALIZER-DRAIN-SOURCE-LIVE)
            env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="$target_dir" \
                "$CARGO_BIN" test -p asupersync --lib \
                drain_ready_async_finalizers_runs_async_cleanup_even_with_zero_task_limit -- --nocapture \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        RUNTIME-OBLIGATION-CANCEL-DRAIN-FINALIZE-LIVE)
            env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="$target_dir" \
                "$CARGO_BIN" test -p asupersync --lib \
                multiple_tasks_obligations_cancel_drain_finalize -- --nocapture \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        SYNC-RWLOCK-UPGRADE-CANCEL-LIVE)
            env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="$target_dir" \
                "$CARGO_BIN" test -p asupersync --lib audit_rwlock_no_read_to_write_upgrade -- --nocapture \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        SYNC-RWLOCK-WRITER-FAIRNESS-LIVE)
            env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="$target_dir" \
                "$CARGO_BIN" test -p asupersync --lib audit_rwlock_writer_starvation_prevention -- --nocapture \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        *)
            echo "unknown local scenario: $scenario_id" >&2
            return 1
            ;;
    esac
}

run_command_capture() {
    local scenario_id="$1"
    local stdout_path="$2"
    local stderr_path="$3"
    local command

    command="$(scenario_command "$scenario_id")"
    if [[ "$scenario_id" == "CHANNEL-ONESHOT-TRIPWIRE-SCAN-LIVE" ]]; then
        bash "$0" --internal-oneshot-scan > "$stdout_path" 2> "$stderr_path"
    elif [[ "$USE_RCH" -eq 1 ]]; then
        run_rch_command_capture "$scenario_id" "$stdout_path" "$stderr_path"
    else
        run_local_command_capture "$scenario_id" "$stdout_path" "$stderr_path"
    fi
}

run_scenario() {
    local scenario_id="$1"
    local run_dir="$2"
    local jsonl_path="$3"
    local command rch_command test_filter expected source_files_json stdout_path stderr_path combined_path
    local start_ms end_ms duration_ms rc verdict actual validation_result first_failure output_artifact input_artifact

    command="$(scenario_command "$scenario_id")"
    if [[ "$USE_RCH" -eq 1 && "$scenario_id" != "CHANNEL-ONESHOT-TRIPWIRE-SCAN-LIVE" ]]; then
        rch_command="rch exec -- ${command}"
    else
        rch_command=""
    fi
    test_filter="$(scenario_test_filter "$scenario_id")"
    expected="$(scenario_expected_behavior "$scenario_id")"
    source_files_json="$(scenario_source_files "$scenario_id")"
    stdout_path="${run_dir}/${scenario_id}.stdout"
    stderr_path="${run_dir}/${scenario_id}.stderr"
    combined_path="${run_dir}/${scenario_id}.combined"
    output_artifact="$(repo_relative "$combined_path")"
    input_artifact="asupersync-a5d34a:${test_filter}"

    if [[ "$MODE" == "dry-run" ]]; then
        if [[ -n "$rch_command" ]]; then
            printf '[dry-run] %s\n' "$rch_command"
        else
            printf '[dry-run] %s\n' "$command"
        fi
        return 0
    fi

    start_ms="$(date +%s%3N)"
    set +e
    run_command_capture "$scenario_id" "$stdout_path" "$stderr_path"
    rc=$?
    set -e
    end_ms="$(date +%s%3N)"
    duration_ms=$((end_ms - start_ms))
    cat "$stdout_path" "$stderr_path" > "$combined_path"
    reject_rch_local_fallback_capture "$scenario_id" "$combined_path"

    verdict="pass"
    first_failure=""
    if [[ "$scenario_id" == "CHANNEL-ONESHOT-TRIPWIRE-SCAN-LIVE" ]]; then
        if validation_result="$(validate_scan_output "$combined_path")"; then
            actual="$validation_result"
        else
            verdict="fail"
            actual="$validation_result"
            first_failure="$validation_result"
        fi
    else
        if validation_result="$(validate_cargo_output "$combined_path" "$scenario_id")"; then
            actual="$validation_result"
        else
            verdict="fail"
            actual="$validation_result"
            first_failure="$validation_result"
        fi
    fi

    if [[ "$verdict" == "pass" && "$rc" -ne 0 && "$USE_RCH" -eq 1 && "$scenario_id" != "CHANNEL-ONESHOT-TRIPWIRE-SCAN-LIVE" ]]; then
        actual="${actual}; rch wrapper exited ${rc} after emitting valid proof output"
    elif [[ "$verdict" == "pass" && "$rc" -ne 0 ]]; then
        verdict="fail"
        actual="command exited ${rc}; ${actual}"
        first_failure="$(first_failure_line_from "$combined_path")"
    elif [[ "$verdict" == "fail" && "$rc" -ne 0 && -z "$first_failure" ]]; then
        first_failure="$(first_failure_line_from "$combined_path")"
    fi

    write_evidence_record \
        "$jsonl_path" \
        "$scenario_id" \
        "$command" \
        "$rch_command" \
        "$test_filter" \
        "$input_artifact" \
        "$output_artifact" \
        "$expected" \
        "$actual" \
        "$verdict" \
        "$first_failure" \
        "$duration_ms" \
        "$source_files_json"

    if [[ "$verdict" != "pass" ]]; then
        return 1
    fi
}

write_self_test_fixture_jsonl() {
    local path="$1"
    cat > "$path" <<EOF
{"schema_version":"${SCHEMA_VERSION}","bead_id":"${BEAD_ID}","scenario_id":"runtime-sync-self-test-live-pass","subsystem":"${SUBSYSTEM}","support_class":"production_live","source_files_inspected":["src/runtime/scheduler/shutdown_behavior_audit_test.rs"],"command":"bash scripts/run_runtime_sync_invariant_evidence.sh --self-test","rch_command_if_used":"","cargo_features":["test-internals"],"test_filter":"self-test-pass","env_keys_required":["ARTIFACT_ROOT"],"deterministic_seed_or_fixture_id":"self-test-v1","input_artifact":"scripts/run_runtime_sync_invariant_evidence.sh","output_artifact":"$(repo_relative "$path")","expected_behavior":"Fixture live-pass record validates successfully.","actual_behavior":"Fixture record is schema-valid and redacted.","verdict":"pass","first_failure_line":"","duration_ms":1,"git_sha_or_tree_state":"$(git_state)","blocker_bead_id":"","evidence_quality":"live"}
{"schema_version":"${SCHEMA_VERSION}","bead_id":"${BEAD_ID}","scenario_id":"runtime-sync-self-test-live-fail","subsystem":"${SUBSYSTEM}","support_class":"production_live","source_files_inspected":["src/sync/rwlock.rs"],"command":"bash scripts/run_runtime_sync_invariant_evidence.sh --self-test --fixture live-fail","rch_command_if_used":"","cargo_features":["test-internals"],"test_filter":"self-test-fail","env_keys_required":[],"deterministic_seed_or_fixture_id":"self-test-v1","input_artifact":"src/sync/rwlock.rs","output_artifact":"","expected_behavior":"A fabricated failing production check remains represented as fail, not pass.","actual_behavior":"Fixture record intentionally records a live fail outcome.","verdict":"fail","first_failure_line":"fixture:runtime-sync-live-fail","duration_ms":1,"git_sha_or_tree_state":"$(git_state)","blocker_bead_id":"","evidence_quality":"live"}
{"schema_version":"${SCHEMA_VERSION}","bead_id":"${BEAD_ID}","scenario_id":"runtime-sync-self-test-blocked","subsystem":"${SUBSYSTEM}","support_class":"blocked_external","source_files_inspected":["tests/runtime_e2e.rs"],"command":"bash scripts/run_runtime_sync_invariant_evidence.sh --self-test --fixture blocked","rch_command_if_used":"","cargo_features":["test-internals"],"test_filter":"self-test-blocked","env_keys_required":["RCH_BIN"],"deterministic_seed_or_fixture_id":"self-test-v1","input_artifact":"tests/runtime_e2e.rs","output_artifact":"","expected_behavior":"Blocked records carry blocker context and are not counted as production passes.","actual_behavior":"Fixture record uses blocked evidence with blocker bead context.","verdict":"blocked","first_failure_line":"fixture:blocked-before-rust-validation","duration_ms":1,"git_sha_or_tree_state":"$(git_state)","blocker_bead_id":"${BEAD_ID}","evidence_quality":"blocked"}
{"schema_version":"${SCHEMA_VERSION}","bead_id":"${BEAD_ID}","scenario_id":"runtime-sync-self-test-unsupported","subsystem":"${SUBSYSTEM}","support_class":"explicitly_unsupported","source_files_inspected":["src/sync/rwlock.rs"],"command":"bash scripts/run_runtime_sync_invariant_evidence.sh --self-test --fixture unsupported","rch_command_if_used":"","cargo_features":["test-internals"],"test_filter":"self-test-unsupported","env_keys_required":[],"deterministic_seed_or_fixture_id":"self-test-v1","input_artifact":"src/sync/rwlock.rs","output_artifact":"","expected_behavior":"Unsupported runtime/sync evidence is explicit and cannot become a production pass.","actual_behavior":"Fixture record validates as unsupported evidence.","verdict":"unsupported","first_failure_line":"","duration_ms":1,"git_sha_or_tree_state":"$(git_state)","blocker_bead_id":"","evidence_quality":"unsupported"}
{"schema_version":"${SCHEMA_VERSION}","bead_id":"${BEAD_ID}","scenario_id":"runtime-sync-self-test-expected-fail","subsystem":"${SUBSYSTEM}","support_class":"production_live","source_files_inspected":["src/runtime/scheduler/three_lane.rs"],"command":"bash scripts/run_runtime_sync_invariant_evidence.sh --self-test --fixture expected-fail","rch_command_if_used":"","cargo_features":["test-internals"],"test_filter":"self-test-expected-fail","env_keys_required":[],"deterministic_seed_or_fixture_id":"self-test-v1","input_artifact":"src/runtime/scheduler/three_lane.rs","output_artifact":"","expected_behavior":"Expected-fail records remain separated from production passes.","actual_behavior":"Fixture record validates as expected_fail evidence.","verdict":"expected_fail","first_failure_line":"fixture:known-follow-up","duration_ms":1,"git_sha_or_tree_state":"$(git_state)","blocker_bead_id":"${BEAD_ID}","evidence_quality":"expected_fail"}
{"schema_version":"${SCHEMA_VERSION}","bead_id":"${BEAD_ID}","scenario_id":"runtime-sync-self-test-fixture-only","subsystem":"${SUBSYSTEM}","support_class":"fixture_reference","source_files_inspected":["scripts/run_runtime_sync_invariant_evidence.sh"],"command":"bash scripts/run_runtime_sync_invariant_evidence.sh --self-test --fixture fixture-only","rch_command_if_used":"","cargo_features":[],"test_filter":"self-test-fixture-only","env_keys_required":[],"deterministic_seed_or_fixture_id":"runtime-sync-fixture","input_artifact":"scripts/run_runtime_sync_invariant_evidence.sh","output_artifact":"","expected_behavior":"Fixture-only records are accepted for context but never counted as production conformance.","actual_behavior":"Fixture record validates as fixture_only evidence.","verdict":"fixture_only","first_failure_line":"","duration_ms":1,"git_sha_or_tree_state":"$(git_state)","blocker_bead_id":"","evidence_quality":"fixture_only"}
EOF
}

run_self_test() {
    local root="$ARTIFACT_ROOT/self-test"
    local fixture_jsonl="$root/runtime-sync-self-test.jsonl"
    local summary_json="$root/runtime-sync-self-test.summary.json"
    mkdir -p "$root"
    write_self_test_fixture_jsonl "$fixture_jsonl"
    python3 "$VALIDATOR" --contract "$CONTRACT" --self-test >/dev/null
    python3 "$VALIDATOR" --contract "$CONTRACT" --jsonl "$fixture_jsonl" --summary-output "$summary_json"
    echo "runtime/sync evidence runner self-test: pass"
    echo "Evidence JSONL: $(repo_relative "$fixture_jsonl")"
    echo "Summary: $(repo_relative "$summary_json")"
}

list_scenarios() {
    echo "Runtime/sync invariant proof scenarios:"
    local scenario
    for scenario in "${SCENARIOS[@]}"; do
        echo "  ${scenario} :: $(scenario_command "$scenario")"
    done
    echo "aggregate_runner_bead=asupersync-oelvq2"
    echo "aggregate_child_bead=${BEAD_ID}"
    echo "validator=$(repo_relative "$VALIDATOR")"
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --execute)
                MODE="execute"
                shift
                ;;
            --dry-run)
                MODE="dry-run"
                shift
                ;;
            --self-test)
                MODE="self-test"
                shift
                ;;
            --list)
                MODE="list"
                shift
                ;;
            --scenario)
                if [[ -z "${2:-}" ]]; then
                    echo "missing scenario after --scenario" >&2
                    exit 1
                fi
                SCENARIO_FILTER="$2"
                shift 2
                ;;
            --artifact-root)
                if [[ -z "${2:-}" ]]; then
                    echo "missing path after --artifact-root" >&2
                    exit 1
                fi
                ARTIFACT_ROOT="$2"
                shift 2
                ;;
            --run-id)
                if [[ -z "${2:-}" ]]; then
                    echo "missing run id after --run-id" >&2
                    exit 1
                fi
                RUN_ID="$2"
                shift 2
                ;;
            --local)
                if [[ "$ALLOW_LOCAL_CARGO" != "1" ]]; then
                    echo "FATAL: --local requires ALLOW_LOCAL_CARGO=1; use the default rch path for proof runs." >&2
                    exit 2
                fi
                USE_RCH=0
                shift
                ;;
            --internal-oneshot-scan)
                run_oneshot_scan
                exit $?
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                echo "unknown argument: $1" >&2
                usage >&2
                exit 1
                ;;
        esac
    done
}

main() {
    parse_args "$@"

    if [[ -n "$SCENARIO_FILTER" ]] && ! has_scenario "$SCENARIO_FILTER"; then
        echo "unknown scenario: $SCENARIO_FILTER" >&2
        list_scenarios >&2
        exit 1
    fi

    case "$MODE" in
        list)
            list_scenarios
            ;;
        self-test)
            run_self_test
            ;;
        dry-run|execute)
            local run_dir jsonl_path summary_path scenario failures=0 executed=0
            run_dir="${ARTIFACT_ROOT}/${RUN_ID}"
            jsonl_path="${run_dir}/runtime-sync-invariant-evidence.jsonl"
            summary_path="${run_dir}/runtime-sync-invariant-evidence.summary.json"
            mkdir -p "$run_dir"
            : > "$jsonl_path"

            for scenario in "${SCENARIOS[@]}"; do
                if [[ -n "$SCENARIO_FILTER" && "$scenario" != "$SCENARIO_FILTER" ]]; then
                    continue
                fi
                executed=$((executed + 1))
                if ! run_scenario "$scenario" "$run_dir" "$jsonl_path"; then
                    failures=$((failures + 1))
                fi
            done

            if [[ "$executed" -eq 0 ]]; then
                echo "zero scenarios selected" >&2
                exit 1
            fi

            if [[ "$MODE" == "dry-run" ]]; then
                echo "Dry-run artifact root: $(repo_relative "$run_dir")"
                exit 0
            fi

            python3 "$VALIDATOR" --contract "$CONTRACT" --jsonl "$jsonl_path" --summary-output "$summary_path"
            echo "runtime/sync invariant evidence: $([[ "$failures" -eq 0 ]] && echo pass || echo fail)"
            echo "Scenarios: ${executed}"
            echo "Evidence JSONL: $(repo_relative "$jsonl_path")"
            echo "Summary: $(repo_relative "$summary_path")"
            if [[ "$failures" -ne 0 ]]; then
                exit 1
            fi
            ;;
        *)
            echo "internal error: unknown mode $MODE" >&2
            exit 1
            ;;
    esac
}

main "$@"
