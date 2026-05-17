#!/usr/bin/env bash
set -euo pipefail

# HTTP/2 conformance proof runner for asupersync-hxi1ga.
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
RCH_WRAPPER_TIMEOUT="${RCH_WRAPPER_TIMEOUT:-600s}"
RUN_ID="${RUN_ID:-current}"
ARTIFACT_ROOT="${ARTIFACT_ROOT:-${PROJECT_ROOT}/artifacts/mock-code-finder/asupersync-hxi1ga}"
MODE="execute"
USE_RCH=1
SCENARIO_FILTER=""
ALLOW_LOCAL_CARGO="${ALLOW_LOCAL_CARGO:-0}"

SCHEMA_VERSION="mock-code-finder-evidence-jsonl-schema-v1"
BEAD_ID="asupersync-hxi1ga"
SUBSYSTEM="http2-conformance"
TARGET_DIR_EXPR="\${TMPDIR:-/tmp}/rch_target_asupersync_hxi1ga_h2"

declare -a SCENARIOS=(
    "H2-LIVE-ADAPTER-INTEGRATION-LIVE"
    "H2-GOAWAY-STATE-MACHINE-LIVE"
    "H2-PING-ACK-LIVE"
    "H2-DATA-END-STREAM-LIVE"
    "H2-PRIORITY-STATE-LIVE"
    "H2-ENABLE-PUSH-LIVE"
    "H2-SIMULATE-HELPER-SCAN-LIVE"
)

usage() {
    cat <<'USAGE'
Usage: bash scripts/run_h2_conformance_evidence.sh [options]

Options:
  --execute                 Run selected HTTP/2 proof scenarios (default)
  --dry-run                 List commands and artifact paths without running cargo
  --self-test               Validate script fixtures and shared negative cases without cargo
  --list                    List scenarios and aggregate-runner registration metadata
  --scenario <SCENARIO_ID>  Run or dry-run one scenario
  --artifact-root <PATH>    Override output root (default: artifacts/mock-code-finder/asupersync-hxi1ga)
  --run-id <RUN_ID>         Stable run directory name (default: current)
  RCH_WRAPPER_TIMEOUT       rch wrapper timeout env var (default: 600s)
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
        H2-LIVE-ADAPTER-INTEGRATION-LIVE)
            printf '%s %s test -p asupersync --test conformance test_h2_conformance_integration --features test-internals -- --nocapture\n' "$(cargo_env_prefix)" "$CARGO_BIN"
            ;;
        H2-GOAWAY-STATE-MACHINE-LIVE)
            printf '%s %s run -p asupersync-conformance --bin h2_goaway_conformance -- --format summary --timeout 30\n' "$(cargo_env_prefix)" "$CARGO_BIN"
            ;;
        H2-PING-ACK-LIVE)
            printf '%s %s run -p asupersync-conformance --bin h2_ping_conformance -- --format summary --timeout 30\n' "$(cargo_env_prefix)" "$CARGO_BIN"
            ;;
        H2-DATA-END-STREAM-LIVE)
            printf '%s %s run -p asupersync-conformance --bin h2_data_end_stream_conformance -- --format summary --timeout 30\n' "$(cargo_env_prefix)" "$CARGO_BIN"
            ;;
        H2-PRIORITY-STATE-LIVE)
            printf '%s %s run -p asupersync-conformance --bin h2_priority_conformance -- --format summary --timeout 30\n' "$(cargo_env_prefix)" "$CARGO_BIN"
            ;;
        H2-ENABLE-PUSH-LIVE)
            printf '%s %s run -p asupersync-conformance --bin h2_enable_push_conformance -- --format summary --timeout 30\n' "$(cargo_env_prefix)" "$CARGO_BIN"
            ;;
        H2-SIMULATE-HELPER-SCAN-LIVE)
            printf 'bash scripts/run_h2_conformance_evidence.sh --internal-simulate-scan\n'
            ;;
        *)
            echo "unknown scenario: $scenario_id" >&2
            return 1
            ;;
    esac
}

scenario_test_filter() {
    case "$1" in
        H2-LIVE-ADAPTER-INTEGRATION-LIVE) printf 'test_h2_conformance_integration\n' ;;
        H2-GOAWAY-STATE-MACHINE-LIVE) printf 'h2_goaway_conformance\n' ;;
        H2-PING-ACK-LIVE) printf 'h2_ping_conformance\n' ;;
        H2-DATA-END-STREAM-LIVE) printf 'h2_data_end_stream_conformance\n' ;;
        H2-PRIORITY-STATE-LIVE) printf 'h2_priority_conformance\n' ;;
        H2-ENABLE-PUSH-LIVE) printf 'h2_enable_push_conformance\n' ;;
        H2-SIMULATE-HELPER-SCAN-LIVE) printf 'h2 simulate helper scan\n' ;;
        *) return 1 ;;
    esac
}

scenario_expected_behavior() {
    case "$1" in
        H2-LIVE-ADAPTER-INTEGRATION-LIVE)
            printf 'The shared HTTP/2 conformance integration uses the live adapter and includes frame, stream, connection, settings, priority, and error-handling requirements.\n'
            ;;
        H2-GOAWAY-STATE-MACHINE-LIVE)
            printf 'Real Connection::process_frame and Connection::goaway assertions cover received GOAWAY, emitted GOAWAY, last_stream_id narrowing, debug data, post-GOAWAY refusal, and repeated GOAWAY behavior.\n'
            ;;
        H2-PING-ACK-LIVE)
            printf 'Real PING processing queues exactly one ACK with identical opaque data, preserves pending frame order, and never re-ACKs ACK PING frames.\n'
            ;;
        H2-DATA-END-STREAM-LIVE)
            printf 'Real DATA and HEADERS stream-state assertions cover END_STREAM closure, zero/final data behavior, and rejection after closed states.\n'
            ;;
        H2-PRIORITY-STATE-LIVE)
            printf 'Real PRIORITY parsing and stream-priority tests cover valid payloads, stream-id-zero rejection, dependency, exclusive, weight, and unsupported scheduling semantics without fake state extraction.\n'
            ;;
        H2-ENABLE-PUSH-LIVE)
            printf 'Real SETTINGS_ENABLE_PUSH and PUSH_PROMISE assertions cover accepted disabled push, invalid values, role-correct rejection, and explicit unsupported server-push behavior.\n'
            ;;
        H2-SIMULATE-HELPER-SCAN-LIVE)
            printf 'Targeted HTTP/2 conformance files contain no simulate_* helpers, hard-coded success paths, or fake-pass text claiming repaired frame/state-machine conformance.\n'
            ;;
        *) return 1 ;;
    esac
}

scenario_source_files() {
    case "$1" in
        H2-LIVE-ADAPTER-INTEGRATION-LIVE)
            printf '["tests/conformance/mod.rs","tests/conformance/h2_live_adapter.rs","tests/conformance/h2_rfc7540/mod.rs"]\n'
            ;;
        H2-GOAWAY-STATE-MACHINE-LIVE)
            printf '["src/http/h2/connection.rs","src/http/h2/frame.rs","conformance/src/h2_goaway_conformance.rs","conformance/src/bin/h2_goaway_conformance.rs","tests/conformance/h2_rfc7540/connection_tests.rs"]\n'
            ;;
        H2-PING-ACK-LIVE)
            printf '["src/http/h2/connection.rs","src/http/h2/frame.rs","conformance/src/h2_ping_conformance.rs","conformance/src/bin/h2_ping_conformance.rs"]\n'
            ;;
        H2-DATA-END-STREAM-LIVE)
            printf '["src/http/h2/connection.rs","src/http/h2/stream.rs","conformance/src/h2_data_end_stream_conformance.rs","conformance/src/bin/h2_data_end_stream_conformance.rs"]\n'
            ;;
        H2-PRIORITY-STATE-LIVE)
            printf '["src/http/h2/frame.rs","src/http/h2/stream.rs","conformance/src/h2_priority_conformance.rs","conformance/src/bin/h2_priority_conformance.rs","tests/conformance/h2_priority.rs","tests/conformance/h2_rfc7540/priority_tests.rs"]\n'
            ;;
        H2-ENABLE-PUSH-LIVE)
            printf '["src/http/h2/settings.rs","src/http/h2/connection.rs","conformance/src/h2_enable_push_conformance.rs","conformance/src/bin/h2_enable_push_conformance.rs"]\n'
            ;;
        H2-SIMULATE-HELPER-SCAN-LIVE)
            printf '["tests/conformance/h2_live_adapter.rs","tests/conformance/h2_rfc7540/connection_tests.rs","tests/conformance/h2_rfc7540/stream_tests.rs","tests/conformance/h2_rfc7540/priority_tests.rs","conformance/src/h2_ping_conformance.rs","conformance/src/h2_goaway_conformance.rs","conformance/src/h2_data_end_stream_conformance.rs","conformance/src/h2_priority_conformance.rs","conformance/src/h2_enable_push_conformance.rs"]\n'
            ;;
        *) return 1 ;;
    esac
}

scenario_input_artifact() {
    case "$1" in
        H2-LIVE-ADAPTER-INTEGRATION-LIVE) printf 'tests/conformance/mod.rs:test_h2_conformance_integration\n' ;;
        H2-GOAWAY-STATE-MACHINE-LIVE) printf 'conformance/src/bin/h2_goaway_conformance.rs\n' ;;
        H2-PING-ACK-LIVE) printf 'conformance/src/bin/h2_ping_conformance.rs\n' ;;
        H2-DATA-END-STREAM-LIVE) printf 'conformance/src/bin/h2_data_end_stream_conformance.rs\n' ;;
        H2-PRIORITY-STATE-LIVE) printf 'conformance/src/bin/h2_priority_conformance.rs\n' ;;
        H2-ENABLE-PUSH-LIVE) printf 'conformance/src/bin/h2_enable_push_conformance.rs\n' ;;
        H2-SIMULATE-HELPER-SCAN-LIVE) printf 'targeted HTTP/2 conformance source scan\n' ;;
        *) return 1 ;;
    esac
}

write_evidence_record() {
    local jsonl_path="$1"
    local scenario_id="$2"
    local support_class="$3"
    local command="$4"
    local rch_command="$5"
    local test_filter="$6"
    local input_artifact="$7"
    local output_artifact="$8"
    local expected_behavior="$9"
    local actual_behavior="${10}"
    local verdict="${11}"
    local first_failure_line="${12}"
    local duration_ms="${13}"
    local source_files_json="${14}"
    local blocker_bead_id="${15}"
    local evidence_quality="${16}"

    cat >> "$jsonl_path" <<EOF
{"schema_version":"${SCHEMA_VERSION}","bead_id":"${BEAD_ID}","scenario_id":"$(json_escape "$scenario_id")","subsystem":"${SUBSYSTEM}","support_class":"${support_class}","source_files_inspected":${source_files_json},"command":"$(json_escape "$command")","rch_command_if_used":"$(json_escape "$rch_command")","cargo_features":["test-internals"],"test_filter":"$(json_escape "$test_filter")","env_keys_required":["ARTIFACT_ROOT","RUN_ID","RCH_BIN","RCH_WRAPPER_TIMEOUT"],"deterministic_seed_or_fixture_id":"h2-conformance-hxi1ga-fixed-filters","input_artifact":"$(json_escape "$input_artifact")","output_artifact":"$(json_escape "$output_artifact")","expected_behavior":"$(json_escape "$expected_behavior")","actual_behavior":"$(json_escape "$actual_behavior")","verdict":"${verdict}","first_failure_line":"$(json_escape "$first_failure_line")","duration_ms":${duration_ms},"git_sha_or_tree_state":"$(git_state)","blocker_bead_id":"$(json_escape "$blocker_bead_id")","evidence_quality":"${evidence_quality}"}
EOF
}

first_failure_line_from() {
    local path="$1"
    grep -m1 -E 'error:|FAILED|FAIL|panicked at|blocked|unsupported|fake pass|simulate_|expected H2|expected HTTP/2' "$path" 2>/dev/null || true
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

run_simulate_scan() {
    cd "$PROJECT_ROOT"
    local scan_files=(
        "tests/conformance/h2_live_adapter.rs"
        "tests/conformance/h2_rfc7540/connection_tests.rs"
        "tests/conformance/h2_rfc7540/stream_tests.rs"
        "tests/conformance/h2_rfc7540/priority_tests.rs"
        "conformance/src/h2_ping_conformance.rs"
        "conformance/src/h2_goaway_conformance.rs"
        "conformance/src/h2_data_end_stream_conformance.rs"
        "conformance/src/h2_priority_conformance.rs"
        "conformance/src/h2_enable_push_conformance.rs"
    )
    local forbidden=""
    forbidden="$(rg -n 'simulate_[[:alnum:]_]+|hard-coded success|fake pass' "${scan_files[@]}" || true)"
    if [[ -n "$forbidden" ]]; then
        printf 'h2 simulate helper scan failed:\n%s\n' "$forbidden"
        return 1
    fi
    rg -n 'process_frame|Frame::GoAway|PingFrame|DataFrame|PriorityFrame|SETTINGS_ENABLE_PUSH|PUSH_PROMISE|h2_live_adapter|H2_REFERENCE_UNIMPLEMENTED' "${scan_files[@]}"
    printf 'h2 simulate helper scan passed: no targeted simulate_* helper or fake-pass text remains in repaired HTTP/2 conformance surfaces\n'
}

validate_cargo_output() {
    local combined_path="$1"
    local scenario_id="$2"
    local test_count
    local case_count

    if grep -Fq "ALL TESTS PASSED" "$combined_path"; then
        case_count="$(grep -Eo 'Passed: *[0-9]+' "$combined_path" | tail -n1 | awk '{print $2}' || true)"
        if [[ -z "$case_count" || "$case_count" -le 0 ]]; then
            printf '%s conformance runner did not report any passed cases' "$scenario_id"
            return 1
        fi
        if grep -Eiq 'TESTS FAILED|panicked at|error\[|Tests timed out|not found' "$combined_path"; then
            printf '%s conformance runner output contains failure markers despite pass summary' "$scenario_id"
            return 1
        fi
        printf 'conformance runner summary ok; passed_cases=%s' "$case_count"
        return 0
    fi

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
    if grep -Fq 'h2 simulate helper scan failed' "$combined_path"; then
        printf 'H2 simulate helper scan found forbidden helper text: %s' "$(first_failure_line_from "$combined_path")"
        return 1
    fi
    if ! grep -Fq 'h2 simulate helper scan passed' "$combined_path"; then
        printf 'H2 simulate helper scan did not emit its pass marker'
        return 1
    fi
    printf 'targeted H2 simulate-helper scan passed'
}

run_rch_command_capture() {
    local scenario_id="$1"
    local stdout_path="$2"
    local stderr_path="$3"
    local target_dir="${TMPDIR:-/tmp}/rch_target_asupersync_hxi1ga_h2"

    case "$scenario_id" in
        H2-LIVE-ADAPTER-INTEGRATION-LIVE)
            timeout "$RCH_WRAPPER_TIMEOUT" "$RCH_BIN" exec -- \
                env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="$target_dir" \
                "$CARGO_BIN" test -p asupersync --test conformance \
                test_h2_conformance_integration \
                --features test-internals -- --nocapture \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        H2-GOAWAY-STATE-MACHINE-LIVE)
            timeout "$RCH_WRAPPER_TIMEOUT" "$RCH_BIN" exec -- \
                env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="$target_dir" \
                "$CARGO_BIN" run -p asupersync-conformance --bin h2_goaway_conformance -- \
                --format summary --timeout 30 \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        H2-PING-ACK-LIVE)
            timeout "$RCH_WRAPPER_TIMEOUT" "$RCH_BIN" exec -- \
                env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="$target_dir" \
                "$CARGO_BIN" run -p asupersync-conformance --bin h2_ping_conformance -- \
                --format summary --timeout 30 \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        H2-DATA-END-STREAM-LIVE)
            timeout "$RCH_WRAPPER_TIMEOUT" "$RCH_BIN" exec -- \
                env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="$target_dir" \
                "$CARGO_BIN" run -p asupersync-conformance --bin h2_data_end_stream_conformance -- \
                --format summary --timeout 30 \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        H2-PRIORITY-STATE-LIVE)
            timeout "$RCH_WRAPPER_TIMEOUT" "$RCH_BIN" exec -- \
                env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="$target_dir" \
                "$CARGO_BIN" run -p asupersync-conformance --bin h2_priority_conformance -- \
                --format summary --timeout 30 \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        H2-ENABLE-PUSH-LIVE)
            timeout "$RCH_WRAPPER_TIMEOUT" "$RCH_BIN" exec -- \
                env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="$target_dir" \
                "$CARGO_BIN" run -p asupersync-conformance --bin h2_enable_push_conformance -- \
                --format summary --timeout 30 \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        *)
            echo "unknown rch scenario: $scenario_id" >&2
            return 1
            ;;
    esac
}

run_command_capture() {
    local scenario_id="$1"
    local stdout_path="$2"
    local stderr_path="$3"

    if [[ "$scenario_id" == "H2-SIMULATE-HELPER-SCAN-LIVE" ]]; then
        run_simulate_scan > "$stdout_path" 2> "$stderr_path"
        return
    fi

    if [[ "$USE_RCH" -eq 1 ]]; then
        run_rch_command_capture "$scenario_id" "$stdout_path" "$stderr_path"
        return
    fi

    case "$scenario_id" in
        H2-LIVE-ADAPTER-INTEGRATION-LIVE)
            env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_asupersync_hxi1ga_h2" \
                "$CARGO_BIN" test -p asupersync --test conformance \
                test_h2_conformance_integration \
                --features test-internals -- --nocapture \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        H2-GOAWAY-STATE-MACHINE-LIVE)
            env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_asupersync_hxi1ga_h2" \
                "$CARGO_BIN" run -p asupersync-conformance --bin h2_goaway_conformance -- \
                --format summary --timeout 30 \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        H2-PING-ACK-LIVE)
            env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_asupersync_hxi1ga_h2" \
                "$CARGO_BIN" run -p asupersync-conformance --bin h2_ping_conformance -- \
                --format summary --timeout 30 \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        H2-DATA-END-STREAM-LIVE)
            env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_asupersync_hxi1ga_h2" \
                "$CARGO_BIN" run -p asupersync-conformance --bin h2_data_end_stream_conformance -- \
                --format summary --timeout 30 \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        H2-PRIORITY-STATE-LIVE)
            env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_asupersync_hxi1ga_h2" \
                "$CARGO_BIN" run -p asupersync-conformance --bin h2_priority_conformance -- \
                --format summary --timeout 30 \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        H2-ENABLE-PUSH-LIVE)
            env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_asupersync_hxi1ga_h2" \
                "$CARGO_BIN" run -p asupersync-conformance --bin h2_enable_push_conformance -- \
                --format summary --timeout 30 \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        *)
            echo "unknown local scenario: $scenario_id" >&2
            return 1
            ;;
    esac
}

run_scenario() {
    local scenario_id="$1"
    local run_dir="$2"
    local jsonl_path="$3"
    local command rch_command test_filter expected source_files_json stdout_path stderr_path combined_path
    local start_ms end_ms duration_ms rc verdict actual validation_result first_failure output_artifact input_artifact
    local support_class evidence_quality blocker_bead_id

    command="$(scenario_command "$scenario_id")"
    if [[ "$USE_RCH" -eq 1 && "$scenario_id" != "H2-SIMULATE-HELPER-SCAN-LIVE" ]]; then
        rch_command="rch exec -- ${command}"
    else
        rch_command=""
    fi
    test_filter="$(scenario_test_filter "$scenario_id")"
    expected="$(scenario_expected_behavior "$scenario_id")"
    source_files_json="$(scenario_source_files "$scenario_id")"
    input_artifact="$(scenario_input_artifact "$scenario_id")"
    stdout_path="${run_dir}/${scenario_id}.stdout"
    stderr_path="${run_dir}/${scenario_id}.stderr"
    combined_path="${run_dir}/${scenario_id}.combined"
    output_artifact="$(repo_relative "$combined_path")"

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
    support_class="production_live"
    evidence_quality="live"
    blocker_bead_id=""
    first_failure=""
    if [[ "$scenario_id" == "H2-SIMULATE-HELPER-SCAN-LIVE" ]]; then
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

    if [[ "$verdict" == "pass" && "$rc" -ne 0 && "$USE_RCH" -eq 1 ]]; then
        actual="${actual}; rch wrapper exited ${rc} after emitting valid proof output"
    elif [[ "$verdict" == "pass" && "$rc" -ne 0 ]]; then
        verdict="fail"
        actual="command exited ${rc}; ${actual}"
        first_failure="$(first_failure_line_from "$combined_path")"
    elif [[ "$verdict" == "fail" && "$rc" -ne 0 && -z "$first_failure" ]]; then
        first_failure="$(first_failure_line_from "$combined_path")"
    fi
    if [[ "$verdict" == "fail" ]] \
        && [[ "$rc" -ne 0 ]] \
        && grep -Fq 'Blocking waiting for file lock on artifact directory' "$combined_path"
    then
        verdict="blocked"
        support_class="blocked_external"
        evidence_quality="blocked"
        blocker_bead_id="$BEAD_ID"
        actual="rch artifact-directory lock prevented ${scenario_id} from reaching cargo test before the wrapper timeout; no production verdict was claimed."
        first_failure="rch artifact directory file lock before cargo summary"
    fi
    if [[ "$verdict" == "fail" && "$rc" -eq 124 ]]; then
        verdict="blocked"
        support_class="blocked_external"
        evidence_quality="blocked"
        blocker_bead_id="$BEAD_ID"
        actual="rch wrapper timed out before ${scenario_id} emitted a cargo test summary; no production verdict was claimed."
        first_failure="rch wrapper timeout before cargo summary"
    fi

    write_evidence_record \
        "$jsonl_path" \
        "$scenario_id" \
        "$support_class" \
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
        "$source_files_json" \
        "$blocker_bead_id" \
        "$evidence_quality"

    if [[ "$verdict" != "pass" ]]; then
        return 1
    fi
}

write_self_test_fixture_jsonl() {
    local path="$1"
    cat > "$path" <<EOF
{"schema_version":"${SCHEMA_VERSION}","bead_id":"${BEAD_ID}","scenario_id":"h2-self-test-live-pass","subsystem":"${SUBSYSTEM}","support_class":"production_live","source_files_inspected":["scripts/run_h2_conformance_evidence.sh","src/http/h2/connection.rs"],"command":"bash scripts/run_h2_conformance_evidence.sh --self-test","rch_command_if_used":"","cargo_features":["test-internals"],"test_filter":"self-test-pass","env_keys_required":["ARTIFACT_ROOT"],"deterministic_seed_or_fixture_id":"self-test-v1","input_artifact":"src/http/h2/connection.rs","output_artifact":"$(repo_relative "$path")","expected_behavior":"Fixture live-pass record validates successfully.","actual_behavior":"Fixture record is schema-valid and redacted.","verdict":"pass","first_failure_line":"","duration_ms":1,"git_sha_or_tree_state":"$(git_state)","blocker_bead_id":"","evidence_quality":"live"}
{"schema_version":"${SCHEMA_VERSION}","bead_id":"${BEAD_ID}","scenario_id":"h2-self-test-live-fail","subsystem":"${SUBSYSTEM}","support_class":"production_live","source_files_inspected":["tests/conformance/h2_live_adapter.rs"],"command":"bash scripts/run_h2_conformance_evidence.sh --self-test --fixture live-fail","rch_command_if_used":"","cargo_features":["test-internals"],"test_filter":"self-test-fail","env_keys_required":[],"deterministic_seed_or_fixture_id":"self-test-v1","input_artifact":"tests/conformance/h2_live_adapter.rs","output_artifact":"","expected_behavior":"A fabricated failing H2 check remains represented as fail, not pass.","actual_behavior":"Fixture record intentionally records a live fail outcome.","verdict":"fail","first_failure_line":"fixture:h2-live-fail","duration_ms":1,"git_sha_or_tree_state":"$(git_state)","blocker_bead_id":"","evidence_quality":"live"}
{"schema_version":"${SCHEMA_VERSION}","bead_id":"${BEAD_ID}","scenario_id":"h2-self-test-blocked","subsystem":"${SUBSYSTEM}","support_class":"blocked_external","source_files_inspected":["src/http/h2/connection.rs"],"command":"bash scripts/run_h2_conformance_evidence.sh --scenario H2-GOAWAY-STATE-MACHINE-LIVE","rch_command_if_used":"","cargo_features":["test-internals"],"test_filter":"self-test-blocked","env_keys_required":["RCH_BIN"],"deterministic_seed_or_fixture_id":"self-test-v1","input_artifact":"src/http/h2/connection.rs","output_artifact":"","expected_behavior":"Blocked records carry blocker context and are not counted as production passes.","actual_behavior":"Fixture record uses blocked evidence with blocker bead context.","verdict":"blocked","first_failure_line":"fixture:blocked-before-rust-validation","duration_ms":1,"git_sha_or_tree_state":"$(git_state)","blocker_bead_id":"${BEAD_ID}","evidence_quality":"blocked"}
{"schema_version":"${SCHEMA_VERSION}","bead_id":"${BEAD_ID}","scenario_id":"h2-self-test-unsupported","subsystem":"${SUBSYSTEM}","support_class":"explicitly_unsupported","source_files_inspected":["conformance/src/h2_enable_push_conformance.rs"],"command":"bash scripts/run_h2_conformance_evidence.sh --self-test --fixture unsupported","rch_command_if_used":"","cargo_features":["test-internals"],"test_filter":"self-test-unsupported","env_keys_required":[],"deterministic_seed_or_fixture_id":"self-test-v1","input_artifact":"conformance/src/h2_enable_push_conformance.rs","output_artifact":"","expected_behavior":"Unsupported H2 server-push evidence is explicit and cannot become a production pass.","actual_behavior":"Fixture record validates as unsupported evidence.","verdict":"unsupported","first_failure_line":"","duration_ms":1,"git_sha_or_tree_state":"$(git_state)","blocker_bead_id":"","evidence_quality":"unsupported"}
{"schema_version":"${SCHEMA_VERSION}","bead_id":"${BEAD_ID}","scenario_id":"h2-self-test-expected-fail","subsystem":"${SUBSYSTEM}","support_class":"production_live","source_files_inspected":["conformance/src/h2_ping_conformance.rs"],"command":"bash scripts/run_h2_conformance_evidence.sh --self-test --fixture expected-fail","rch_command_if_used":"","cargo_features":["test-internals"],"test_filter":"self-test-expected-fail","env_keys_required":[],"deterministic_seed_or_fixture_id":"self-test-v1","input_artifact":"conformance/src/h2_ping_conformance.rs","output_artifact":"","expected_behavior":"Expected-fail records remain separated from production passes.","actual_behavior":"Fixture record validates as expected_fail evidence.","verdict":"expected_fail","first_failure_line":"fixture:known-follow-up","duration_ms":1,"git_sha_or_tree_state":"$(git_state)","blocker_bead_id":"${BEAD_ID}","evidence_quality":"expected_fail"}
{"schema_version":"${SCHEMA_VERSION}","bead_id":"${BEAD_ID}","scenario_id":"h2-self-test-fixture-only","subsystem":"${SUBSYSTEM}","support_class":"fixture_reference","source_files_inspected":["tests/conformance/h2_rfc7540/connection_tests.rs"],"command":"bash scripts/run_h2_conformance_evidence.sh --self-test --fixture fixture-only","rch_command_if_used":"","cargo_features":[],"test_filter":"self-test-fixture-only","env_keys_required":[],"deterministic_seed_or_fixture_id":"h2-fixture","input_artifact":"tests/conformance/h2_rfc7540/connection_tests.rs","output_artifact":"","expected_behavior":"Fixture-only records are accepted for context but never counted as production conformance.","actual_behavior":"Fixture record validates as fixture_only evidence.","verdict":"fixture_only","first_failure_line":"","duration_ms":1,"git_sha_or_tree_state":"$(git_state)","blocker_bead_id":"","evidence_quality":"fixture_only"}
EOF
}

run_self_test() {
    local root="$ARTIFACT_ROOT/self-test"
    local fixture_jsonl="$root/h2-conformance-self-test.jsonl"
    local summary_json="$root/h2-conformance-self-test.summary.json"
    local cargo_output="$root/h2-cargo-summary.fixture"
    local runner_output="$root/h2-runner-summary.fixture"
    local failing_output="$root/h2-failing-summary.fixture"
    mkdir -p "$root"
    write_self_test_fixture_jsonl "$fixture_jsonl"
    python3 "$VALIDATOR" --contract "$CONTRACT" --self-test >/dev/null
    python3 "$VALIDATOR" --contract "$CONTRACT" --jsonl "$fixture_jsonl" --summary-output "$summary_json"
    cat > "$cargo_output" <<'EOF'
running 2 tests
test h2_fixture_one ... ok
test h2_fixture_two ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
EOF
    validate_cargo_output "$cargo_output" "h2-self-test-cargo-summary" >/dev/null
    cat > "$runner_output" <<'EOF'
HTTP/2 CONFORMANCE RESULTS
ALL TESTS PASSED
Passed: 3
Failed: 0
EOF
    validate_cargo_output "$runner_output" "h2-self-test-runner-summary" >/dev/null
    cat > "$failing_output" <<'EOF'
HTTP/2 CONFORMANCE RESULTS
1 TESTS FAILED
Passed: 2
Failed: 1
EOF
    if validate_cargo_output "$failing_output" "h2-self-test-failing-summary" >/dev/null; then
        echo "self-test failure fixture unexpectedly validated" >&2
        exit 1
    fi
    echo "HTTP/2 conformance evidence runner self-test: pass"
    echo "Evidence JSONL: $(repo_relative "$fixture_jsonl")"
    echo "Summary: $(repo_relative "$summary_json")"
}

list_scenarios() {
    echo "HTTP/2 conformance proof scenarios:"
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
            --internal-simulate-scan)
                MODE="internal-simulate-scan"
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
        internal-simulate-scan)
            run_simulate_scan
            ;;
        dry-run|execute)
            local run_dir jsonl_path summary_path scenario failures=0 executed=0
            run_dir="${ARTIFACT_ROOT}/${RUN_ID}"
            jsonl_path="${run_dir}/h2-conformance-evidence.jsonl"
            summary_path="${run_dir}/h2-conformance-evidence.summary.json"
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
            echo "HTTP/2 conformance evidence: $([[ "$failures" -eq 0 ]] && echo pass || echo fail)"
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
