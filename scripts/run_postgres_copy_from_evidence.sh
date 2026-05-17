#!/usr/bin/env bash
set -euo pipefail

# PostgreSQL COPY FROM proof runner for asupersync-zftrj9.
#
# Emits mock-code-finder evidence JSONL validated by the shared
# scripts/validate_mock_code_finder_evidence.py contract. Rust execution is
# routed through rch by default; when no real PostgreSQL service is configured,
# the real-server lane is recorded as blocked and deterministic wire-level
# proof scenarios still run.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CONTRACT="${PROJECT_ROOT}/artifacts/mock_code_finder_verification_contract_v1.json"
VALIDATOR="${PROJECT_ROOT}/scripts/validate_mock_code_finder_evidence.py"
RCH_BIN="${RCH_BIN:-rch}"
CARGO_BIN="${CARGO_BIN:-cargo}"
RCH_WRAPPER_TIMEOUT="${RCH_WRAPPER_TIMEOUT:-600s}"
RUN_ID="${RUN_ID:-current}"
ARTIFACT_ROOT="${ARTIFACT_ROOT:-${PROJECT_ROOT}/artifacts/mock-code-finder/asupersync-zftrj9}"
MODE="execute"
USE_RCH=1
SCENARIO_FILTER=""
ALLOW_LOCAL_CARGO="${ALLOW_LOCAL_CARGO:-0}"

SCHEMA_VERSION="mock-code-finder-evidence-jsonl-schema-v1"
BEAD_ID="asupersync-zftrj9"
SUBSYSTEM="database-postgres-copy-from"
TARGET_DIR_EXPR="\${TMPDIR:-/tmp}/rch_target_asupersync_zftrj9_postgres_copy"

declare -a SCENARIOS=(
    "POSTGRES-COPY-REAL-SERVER-LIVE"
    "POSTGRES-COPY-WIRE-API-LIVE"
    "POSTGRES-COPY-AUDIT-DIAGNOSTICS-LIVE"
    "POSTGRES-COPY-CONFORMANCE-PARSER-LIVE"
)

usage() {
    cat <<'USAGE'
Usage: bash scripts/run_postgres_copy_from_evidence.sh [options]

Options:
  --execute                 Run selected PostgreSQL COPY proof scenarios (default)
  --dry-run                 List commands and artifact paths without running cargo
  --self-test               Validate script fixtures and shared negative cases without cargo
  --list                    List scenarios and aggregate-runner registration metadata
  --scenario <SCENARIO_ID>  Run or dry-run one scenario
  --artifact-root <PATH>    Override output root (default: artifacts/mock-code-finder/asupersync-zftrj9)
  --run-id <RUN_ID>         Stable run directory name (default: current)
  RCH_WRAPPER_TIMEOUT       rch wrapper timeout env var (default: 600s)
  --local                   Run cargo locally only with ALLOW_LOCAL_CARGO=1 (not for agent validation)
  -h, --help                Show this help

Real PostgreSQL execution:
  Set REAL_POSTGRES_TESTS=true and POSTGRES_URL to run the live-server
  COPY FROM scenario. POSTGRES_URL values are never written to evidence.
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

real_postgres_configured() {
    [[ "${REAL_POSTGRES_TESTS:-}" == "true" ]]
}

scenario_command() {
    local scenario_id="$1"
    case "$scenario_id" in
        POSTGRES-COPY-REAL-SERVER-LIVE)
            printf '%s REAL_POSTGRES_TESTS=true POSTGRES_URL=<redacted> %s test -p asupersync --test postgres_real_server pg_real_copy_from_chunks_streams_and_recovers --features postgres,test-internals -- --nocapture\n' "$(cargo_env_prefix)" "$CARGO_BIN"
            ;;
        POSTGRES-COPY-WIRE-API-LIVE)
            printf '%s %s test -p asupersync --lib copy_from_chunks --features test-internals,postgres -- --nocapture\n' "$(cargo_env_prefix)" "$CARGO_BIN"
            ;;
        POSTGRES-COPY-AUDIT-DIAGNOSTICS-LIVE)
            printf '%s %s test -p asupersync --lib postgres_copy_from_error_audit --features test-internals,postgres -- --nocapture\n' "$(cargo_env_prefix)" "$CARGO_BIN"
            ;;
        POSTGRES-COPY-CONFORMANCE-PARSER-LIVE)
            printf '%s %s test -p asupersync --test conformance test_postgres_copy_conformance_integration --features test-internals,postgres -- --nocapture\n' "$(cargo_env_prefix)" "$CARGO_BIN"
            ;;
        *)
            echo "unknown scenario: $scenario_id" >&2
            return 1
            ;;
    esac
}

scenario_test_filter() {
    case "$1" in
        POSTGRES-COPY-REAL-SERVER-LIVE) printf 'pg_real_copy_from_chunks_streams_and_recovers\n' ;;
        POSTGRES-COPY-WIRE-API-LIVE) printf 'copy_from_chunks\n' ;;
        POSTGRES-COPY-AUDIT-DIAGNOSTICS-LIVE) printf 'postgres_copy_from_error_audit\n' ;;
        POSTGRES-COPY-CONFORMANCE-PARSER-LIVE) printf 'test_postgres_copy_conformance_integration\n' ;;
        *) return 1 ;;
    esac
}

scenario_expected_behavior() {
    case "$1" in
        POSTGRES-COPY-REAL-SERVER-LIVE)
            printf 'When REAL_POSTGRES_TESTS is enabled, the public PgConnection COPY FROM API streams rows into a real PostgreSQL temp table, sends CopyFail on caller abort, preserves backend COPY errors, rolls back partial COPY rows, and reuses the connection after success and failure.\n'
            ;;
        POSTGRES-COPY-WIRE-API-LIVE)
            printf 'The public PgConnection COPY FROM API streams bounded CopyData chunks, sends CopyDone for success and empty input, sends CopyFail on source error/cancellation, preserves backend errors, and resynchronizes the connection.\n'
            ;;
        POSTGRES-COPY-AUDIT-DIAGNOSTICS-LIVE)
            printf 'Former panic-only COPY FROM audit checks now exercise production PgConnection::copy_from_chunks and preserve structured backend diagnostics including row position, detail, hint, and SQLSTATE.\n'
            ;;
        POSTGRES-COPY-CONFORMANCE-PARSER-LIVE)
            printf 'The active PostgreSQL COPY conformance harness validates CopyDone and CopyFail sequences with the production fuzz_parse_copy_in_sequence parser instead of a local fake model.\n'
            ;;
        *) return 1 ;;
    esac
}

scenario_source_files() {
    case "$1" in
        POSTGRES-COPY-REAL-SERVER-LIVE)
            printf '["tests/postgres_real_server.rs","src/database/postgres.rs"]\n'
            ;;
        POSTGRES-COPY-WIRE-API-LIVE)
            printf '["src/database/postgres.rs"]\n'
            ;;
        POSTGRES-COPY-AUDIT-DIAGNOSTICS-LIVE)
            printf '["src/database/postgres_copy_from_error_audit.rs","src/database/postgres.rs"]\n'
            ;;
        POSTGRES-COPY-CONFORMANCE-PARSER-LIVE)
            printf '["tests/conformance/postgres_copy.rs","src/database/postgres.rs"]\n'
            ;;
        *) return 1 ;;
    esac
}

scenario_cargo_features() {
    printf '["test-internals","postgres"]\n'
}

scenario_input_artifact() {
    case "$1" in
        POSTGRES-COPY-REAL-SERVER-LIVE) printf 'POSTGRES_URL=<redacted>\n' ;;
        POSTGRES-COPY-WIRE-API-LIVE) printf 'src/database/postgres.rs:copy_from_chunks\n' ;;
        POSTGRES-COPY-AUDIT-DIAGNOSTICS-LIVE) printf 'src/database/postgres_copy_from_error_audit.rs\n' ;;
        POSTGRES-COPY-CONFORMANCE-PARSER-LIVE) printf 'tests/conformance/postgres_copy.rs\n' ;;
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
    local cargo_features_json="${15}"
    local blocker_bead_id="${16}"
    local evidence_quality="${17}"

    cat >> "$jsonl_path" <<EOF
{"schema_version":"${SCHEMA_VERSION}","bead_id":"${BEAD_ID}","scenario_id":"$(json_escape "$scenario_id")","subsystem":"${SUBSYSTEM}","support_class":"${support_class}","source_files_inspected":${source_files_json},"command":"$(json_escape "$command")","rch_command_if_used":"$(json_escape "$rch_command")","cargo_features":${cargo_features_json},"test_filter":"$(json_escape "$test_filter")","env_keys_required":["REAL_POSTGRES_TESTS","POSTGRES_URL","ALLOW_NON_LOCALHOST_POSTGRES","ARTIFACT_ROOT","RUN_ID","RCH_BIN","RCH_WRAPPER_TIMEOUT"],"deterministic_seed_or_fixture_id":"postgres-copy-zftrj9-fixed-filters","input_artifact":"$(json_escape "$input_artifact")","output_artifact":"$(json_escape "$output_artifact")","expected_behavior":"$(json_escape "$expected_behavior")","actual_behavior":"$(json_escape "$actual_behavior")","verdict":"${verdict}","first_failure_line":"$(json_escape "$first_failure_line")","duration_ms":${duration_ms},"git_sha_or_tree_state":"$(git_state)","blocker_bead_id":"$(json_escape "$blocker_bead_id")","evidence_quality":"${evidence_quality}"}
EOF
}

first_failure_line_from() {
    local path="$1"
    grep -m1 -E 'error:|FAILED|FAIL|panicked at|test_skipped|blocked|unsupported|expected SQLSTATE|expected COPY' "$path" 2>/dev/null || true
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

validate_real_server_output() {
    local combined_path="$1"
    local base
    if ! base="$(validate_cargo_output "$combined_path" "POSTGRES-COPY-REAL-SERVER-LIVE")"; then
        printf '%s' "$base"
        return 1
    fi
    if grep -Fq '"event":"test_skipped"' "$combined_path"; then
        printf 'real PostgreSQL COPY test skipped after REAL_POSTGRES_TESTS was requested'
        return 1
    fi
    for marker in copy_success copy_source_abort copy_malformed_backend_error query_after_failure; do
        if ! grep -Fq "$marker" "$combined_path"; then
            printf 'real PostgreSQL COPY output missing phase marker: %s' "$marker"
            return 1
        fi
    done
    printf '%s; live PostgreSQL COPY phases observed' "$base"
}

run_rch_command_capture() {
    local scenario_id="$1"
    local stdout_path="$2"
    local stderr_path="$3"
    local target_dir="${TMPDIR:-/tmp}/rch_target_asupersync_zftrj9_postgres_copy"

    case "$scenario_id" in
        POSTGRES-COPY-REAL-SERVER-LIVE)
            timeout "$RCH_WRAPPER_TIMEOUT" "$RCH_BIN" exec -- \
                env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="$target_dir" REAL_POSTGRES_TESTS=true POSTGRES_URL="${POSTGRES_URL:-}" \
                ALLOW_NON_LOCALHOST_POSTGRES="${ALLOW_NON_LOCALHOST_POSTGRES:-}" \
                "$CARGO_BIN" test -p asupersync --test postgres_real_server \
                pg_real_copy_from_chunks_streams_and_recovers \
                --features postgres,test-internals -- --nocapture \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        POSTGRES-COPY-WIRE-API-LIVE)
            timeout "$RCH_WRAPPER_TIMEOUT" "$RCH_BIN" exec -- \
                env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="$target_dir" \
                "$CARGO_BIN" test -p asupersync --lib copy_from_chunks \
                --features test-internals,postgres -- --nocapture \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        POSTGRES-COPY-AUDIT-DIAGNOSTICS-LIVE)
            timeout "$RCH_WRAPPER_TIMEOUT" "$RCH_BIN" exec -- \
                env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="$target_dir" \
                "$CARGO_BIN" test -p asupersync --lib postgres_copy_from_error_audit \
                --features test-internals,postgres -- --nocapture \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        POSTGRES-COPY-CONFORMANCE-PARSER-LIVE)
            timeout "$RCH_WRAPPER_TIMEOUT" "$RCH_BIN" exec -- \
                env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="$target_dir" \
                "$CARGO_BIN" test -p asupersync --test conformance \
                test_postgres_copy_conformance_integration \
                --features test-internals,postgres -- --nocapture \
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

    if [[ "$USE_RCH" -eq 1 ]]; then
        run_rch_command_capture "$scenario_id" "$stdout_path" "$stderr_path"
        return
    fi

    case "$scenario_id" in
        POSTGRES-COPY-REAL-SERVER-LIVE)
            env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_asupersync_zftrj9_postgres_copy" \
                REAL_POSTGRES_TESTS=true POSTGRES_URL="${POSTGRES_URL:-}" \
                ALLOW_NON_LOCALHOST_POSTGRES="${ALLOW_NON_LOCALHOST_POSTGRES:-}" \
                "$CARGO_BIN" test -p asupersync --test postgres_real_server \
                pg_real_copy_from_chunks_streams_and_recovers \
                --features postgres,test-internals -- --nocapture \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        POSTGRES-COPY-WIRE-API-LIVE)
            env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_asupersync_zftrj9_postgres_copy" \
                "$CARGO_BIN" test -p asupersync --lib copy_from_chunks \
                --features test-internals,postgres -- --nocapture \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        POSTGRES-COPY-AUDIT-DIAGNOSTICS-LIVE)
            env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_asupersync_zftrj9_postgres_copy" \
                "$CARGO_BIN" test -p asupersync --lib postgres_copy_from_error_audit \
                --features test-internals,postgres -- --nocapture \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        POSTGRES-COPY-CONFORMANCE-PARSER-LIVE)
            env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_asupersync_zftrj9_postgres_copy" \
                "$CARGO_BIN" test -p asupersync --test conformance \
                test_postgres_copy_conformance_integration \
                --features test-internals,postgres -- --nocapture \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        *)
            echo "unknown local scenario: $scenario_id" >&2
            return 1
            ;;
    esac
}

write_real_server_blocked_record() {
    local jsonl_path="$1"
    local run_dir="$2"
    local scenario_id="POSTGRES-COPY-REAL-SERVER-LIVE"
    local blocked_path="${run_dir}/${scenario_id}.blocked"
    local command rch_command test_filter expected source_files_json input_artifact actual

    command="$(scenario_command "$scenario_id")"
    rch_command=""
    if [[ "$USE_RCH" -eq 1 ]]; then
        rch_command="rch exec -- ${command}"
    fi
    test_filter="$(scenario_test_filter "$scenario_id")"
    expected="$(scenario_expected_behavior "$scenario_id")"
    source_files_json="$(scenario_source_files "$scenario_id")"
    input_artifact="$(scenario_input_artifact "$scenario_id")"
    actual="REAL_POSTGRES_TESTS was not true; live PostgreSQL service proof not attempted. POSTGRES_URL, if present, was treated as secret and redacted; deterministic wire-level COPY FROM scenarios remain required in this run."
    printf '%s\n' "$actual" > "$blocked_path"
    write_evidence_record \
        "$jsonl_path" \
        "$scenario_id" \
        "blocked_external" \
        "$command" \
        "$rch_command" \
        "$test_filter" \
        "$input_artifact" \
        "$(repo_relative "$blocked_path")" \
        "$expected" \
        "$actual" \
        "blocked" \
        "REAL_POSTGRES_TESTS not set to true" \
        0 \
        "$source_files_json" \
        "$(scenario_cargo_features)" \
        "$BEAD_ID" \
        "blocked"
}

run_scenario() {
    local scenario_id="$1"
    local run_dir="$2"
    local jsonl_path="$3"
    local command rch_command test_filter expected source_files_json stdout_path stderr_path combined_path
    local start_ms end_ms duration_ms rc verdict actual validation_result first_failure output_artifact input_artifact
    local support_class evidence_quality blocker_bead_id

    if [[ "$scenario_id" == "POSTGRES-COPY-REAL-SERVER-LIVE" ]] && ! real_postgres_configured; then
        if [[ "$MODE" == "dry-run" ]]; then
            printf '[dry-run] real-server blocked unless REAL_POSTGRES_TESTS=true; %s\n' "$(scenario_command "$scenario_id")"
            return 0
        fi
        write_real_server_blocked_record "$jsonl_path" "$run_dir"
        return 0
    fi

    command="$(scenario_command "$scenario_id")"
    if [[ "$USE_RCH" -eq 1 ]]; then
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

    verdict="pass"
    support_class="production_live"
    evidence_quality="live"
    blocker_bead_id=""
    first_failure=""
    if [[ "$USE_RCH" -eq 1 ]] && grep -Eq '^\[RCH\] local \(|falling back to local' "$combined_path" 2>/dev/null; then
        verdict="fail"
        rc=86
        actual="rch local fallback detected; refusing local cargo execution"
        first_failure="$actual"
        printf '%s\n' "$actual" > "${run_dir}/${scenario_id}.rch_local_fallback.txt"
    elif [[ "$scenario_id" == "POSTGRES-COPY-REAL-SERVER-LIVE" ]]; then
        if validation_result="$(validate_real_server_output "$combined_path")"; then
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
    if [[ "$verdict" == "fail" ]] && [[ "$rc" -eq 124 ]]; then
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
        "$(scenario_cargo_features)" \
        "$blocker_bead_id" \
        "$evidence_quality"

    if [[ "$verdict" != "pass" ]]; then
        return 1
    fi
}

write_self_test_fixture_jsonl() {
    local path="$1"
    cat > "$path" <<EOF
{"schema_version":"${SCHEMA_VERSION}","bead_id":"${BEAD_ID}","scenario_id":"postgres-copy-self-test-live-pass","subsystem":"${SUBSYSTEM}","support_class":"production_live","source_files_inspected":["scripts/run_postgres_copy_from_evidence.sh","src/database/postgres.rs"],"command":"bash scripts/run_postgres_copy_from_evidence.sh --self-test","rch_command_if_used":"","cargo_features":["test-internals","postgres"],"test_filter":"self-test-pass","env_keys_required":["ARTIFACT_ROOT"],"deterministic_seed_or_fixture_id":"self-test-v1","input_artifact":"src/database/postgres.rs:copy_from_chunks","output_artifact":"$(repo_relative "$path")","expected_behavior":"Fixture live-pass record validates successfully.","actual_behavior":"Fixture record is schema-valid and redacted.","verdict":"pass","first_failure_line":"","duration_ms":1,"git_sha_or_tree_state":"$(git_state)","blocker_bead_id":"","evidence_quality":"live"}
{"schema_version":"${SCHEMA_VERSION}","bead_id":"${BEAD_ID}","scenario_id":"postgres-copy-self-test-live-fail","subsystem":"${SUBSYSTEM}","support_class":"production_live","source_files_inspected":["src/database/postgres.rs"],"command":"bash scripts/run_postgres_copy_from_evidence.sh --self-test --fixture live-fail","rch_command_if_used":"","cargo_features":["test-internals","postgres"],"test_filter":"self-test-fail","env_keys_required":[],"deterministic_seed_or_fixture_id":"self-test-v1","input_artifact":"src/database/postgres.rs:copy_from_chunks","output_artifact":"","expected_behavior":"A fabricated failing COPY FROM check remains represented as fail, not pass.","actual_behavior":"Fixture record intentionally records a live fail outcome.","verdict":"fail","first_failure_line":"fixture:postgres-copy-live-fail","duration_ms":1,"git_sha_or_tree_state":"$(git_state)","blocker_bead_id":"","evidence_quality":"live"}
{"schema_version":"${SCHEMA_VERSION}","bead_id":"${BEAD_ID}","scenario_id":"postgres-copy-self-test-blocked","subsystem":"${SUBSYSTEM}","support_class":"blocked_external","source_files_inspected":["tests/postgres_real_server.rs"],"command":"bash scripts/run_postgres_copy_from_evidence.sh --scenario POSTGRES-COPY-REAL-SERVER-LIVE","rch_command_if_used":"","cargo_features":["test-internals","postgres"],"test_filter":"self-test-blocked","env_keys_required":["REAL_POSTGRES_TESTS","POSTGRES_URL"],"deterministic_seed_or_fixture_id":"self-test-v1","input_artifact":"POSTGRES_URL=<redacted>","output_artifact":"","expected_behavior":"Blocked real-server records carry blocker context and are not counted as production passes.","actual_behavior":"Fixture record uses blocked evidence with missing-service context and redacted environment handling.","verdict":"blocked","first_failure_line":"fixture:REAL_POSTGRES_TESTS not set to true","duration_ms":1,"git_sha_or_tree_state":"$(git_state)","blocker_bead_id":"${BEAD_ID}","evidence_quality":"blocked"}
{"schema_version":"${SCHEMA_VERSION}","bead_id":"${BEAD_ID}","scenario_id":"postgres-copy-self-test-unsupported","subsystem":"${SUBSYSTEM}","support_class":"explicitly_unsupported","source_files_inspected":["scripts/run_postgres_copy_from_evidence.sh"],"command":"bash scripts/run_postgres_copy_from_evidence.sh --self-test --fixture unsupported","rch_command_if_used":"","cargo_features":["test-internals","postgres"],"test_filter":"self-test-unsupported","env_keys_required":[],"deterministic_seed_or_fixture_id":"self-test-v1","input_artifact":"scripts/run_postgres_copy_from_evidence.sh","output_artifact":"","expected_behavior":"Unsupported COPY FROM evidence is explicit and cannot become a production pass.","actual_behavior":"Fixture record validates as unsupported evidence.","verdict":"unsupported","first_failure_line":"","duration_ms":1,"git_sha_or_tree_state":"$(git_state)","blocker_bead_id":"","evidence_quality":"unsupported"}
{"schema_version":"${SCHEMA_VERSION}","bead_id":"${BEAD_ID}","scenario_id":"postgres-copy-self-test-expected-fail","subsystem":"${SUBSYSTEM}","support_class":"production_live","source_files_inspected":["tests/conformance/postgres_copy.rs"],"command":"bash scripts/run_postgres_copy_from_evidence.sh --self-test --fixture expected-fail","rch_command_if_used":"","cargo_features":["test-internals","postgres"],"test_filter":"self-test-expected-fail","env_keys_required":[],"deterministic_seed_or_fixture_id":"self-test-v1","input_artifact":"tests/conformance/postgres_copy.rs","output_artifact":"","expected_behavior":"Expected-fail records remain separated from production passes.","actual_behavior":"Fixture record validates as expected_fail evidence.","verdict":"expected_fail","first_failure_line":"fixture:known-follow-up","duration_ms":1,"git_sha_or_tree_state":"$(git_state)","blocker_bead_id":"${BEAD_ID}","evidence_quality":"expected_fail"}
{"schema_version":"${SCHEMA_VERSION}","bead_id":"${BEAD_ID}","scenario_id":"postgres-copy-self-test-fixture-only","subsystem":"${SUBSYSTEM}","support_class":"fixture_reference","source_files_inspected":["tests/conformance/postgres_copy.rs"],"command":"bash scripts/run_postgres_copy_from_evidence.sh --self-test --fixture fixture-only","rch_command_if_used":"","cargo_features":[],"test_filter":"self-test-fixture-only","env_keys_required":[],"deterministic_seed_or_fixture_id":"postgres-copy-fixture","input_artifact":"tests/conformance/postgres_copy.rs","output_artifact":"","expected_behavior":"Fixture-only records are accepted for context but never counted as production conformance.","actual_behavior":"Fixture record validates as fixture_only evidence.","verdict":"fixture_only","first_failure_line":"","duration_ms":1,"git_sha_or_tree_state":"$(git_state)","blocker_bead_id":"","evidence_quality":"fixture_only"}
EOF
}

run_self_test() {
    local root="$ARTIFACT_ROOT/self-test"
    local fixture_jsonl="$root/postgres-copy-self-test.jsonl"
    local summary_json="$root/postgres-copy-self-test.summary.json"
    mkdir -p "$root"
    write_self_test_fixture_jsonl "$fixture_jsonl"
    python3 "$VALIDATOR" --contract "$CONTRACT" --self-test >/dev/null
    python3 "$VALIDATOR" --contract "$CONTRACT" --jsonl "$fixture_jsonl" --summary-output "$summary_json"
    echo "PostgreSQL COPY FROM evidence runner self-test: pass"
    echo "Evidence JSONL: $(repo_relative "$fixture_jsonl")"
    echo "Summary: $(repo_relative "$summary_json")"
}

list_scenarios() {
    echo "PostgreSQL COPY FROM proof scenarios:"
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
            jsonl_path="${run_dir}/postgres-copy-from-evidence.jsonl"
            summary_path="${run_dir}/postgres-copy-from-evidence.summary.json"
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
            echo "PostgreSQL COPY FROM evidence: $([[ "$failures" -eq 0 ]] && echo pass || echo fail)"
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
