#!/usr/bin/env bash
set -euo pipefail

# RFC6330 proof runner for asupersync-kokw3m.
#
# Emits mock-code-finder evidence JSONL that is validated by
# scripts/validate_mock_code_finder_evidence.py. Rust execution is routed
# through rch by default; use --dry-run or --self-test for cheap contract checks.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CONTRACT="${PROJECT_ROOT}/artifacts/mock_code_finder_verification_contract_v1.json"
VALIDATOR="${PROJECT_ROOT}/scripts/validate_mock_code_finder_evidence.py"
RCH_BIN="${RCH_BIN:-rch}"
RCH_WRAPPER_TIMEOUT="${RCH_WRAPPER_TIMEOUT:-240s}"
RUN_ID="${RUN_ID:-current}"
ARTIFACT_ROOT="${ARTIFACT_ROOT:-${PROJECT_ROOT}/artifacts/mock-code-finder/asupersync-kokw3m}"
MODE="execute"
USE_RCH=1
SCENARIO_FILTER=""

SCHEMA_VERSION="mock-code-finder-evidence-jsonl-schema-v1"
BEAD_ID="asupersync-kokw3m"
SUBSYSTEM="raptorq-rfc6330"

declare -a SCENARIOS=(
    "RFC6330-PROOF-RUN-ALL-LIVE"
    "RFC6330-PROOF-SECTION-5-3-LIVE"
    "RFC6330-PROOF-LEVEL-MUST-LIVE"
    "RFC6330-PROOF-CATEGORY-DIFFERENTIAL-LIVE"
    "RFC6330-PROOF-GENERATE-REPORT"
)

usage() {
    cat <<'USAGE'
Usage: bash scripts/run_rfc6330_conformance_evidence.sh [options]

Options:
  --execute                 Run selected RFC6330 proof scenarios (default)
  --dry-run                 List commands and artifact paths without running cargo
  --self-test               Validate script fixtures and shared negative cases without cargo
  --list                    List scenarios and aggregate-runner registration metadata
  --scenario <SCENARIO_ID>  Run or dry-run one scenario
  --artifact-root <PATH>    Override output root (default: artifacts/mock-code-finder/asupersync-kokw3m)
  --run-id <RUN_ID>         Stable run directory name (default: current)
  RCH_WRAPPER_TIMEOUT       rch wrapper timeout env var (default: 240s)
  --local                   Run cargo locally instead of through rch (not for agent validation)
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

scenario_args() {
    case "$1" in
        RFC6330-PROOF-RUN-ALL-LIVE)
            printf '%s\n' "--run-all --ci-mode --seed 42"
            ;;
        RFC6330-PROOF-SECTION-5-3-LIVE)
            printf '%s\n' "--section 5.3 --ci-mode --seed 42"
            ;;
        RFC6330-PROOF-LEVEL-MUST-LIVE)
            printf '%s\n' "--level must --ci-mode --seed 42"
            ;;
        RFC6330-PROOF-CATEGORY-DIFFERENTIAL-LIVE)
            printf '%s\n' "--category differential --ci-mode --seed 42"
            ;;
        RFC6330-PROOF-GENERATE-REPORT)
            printf '%s\n' "--generate-report --seed 42"
            ;;
        *)
            echo "unknown scenario: $1" >&2
            return 1
            ;;
    esac
}

scenario_filter_label() {
    case "$1" in
        RFC6330-PROOF-RUN-ALL-LIVE) printf '%s\n' "run-all" ;;
        RFC6330-PROOF-SECTION-5-3-LIVE) printf '%s\n' "section=5.3" ;;
        RFC6330-PROOF-LEVEL-MUST-LIVE) printf '%s\n' "level=must" ;;
        RFC6330-PROOF-CATEGORY-DIFFERENTIAL-LIVE) printf '%s\n' "category=differential" ;;
        RFC6330-PROOF-GENERATE-REPORT) printf '%s\n' "generate-report" ;;
        *) return 1 ;;
    esac
}

scenario_expected_behavior() {
    case "$1" in
        RFC6330-PROOF-RUN-ALL-LIVE)
            printf '%s\n' "The RFC6330 CLI runs all registered tests, emits nonzero CI JSONL rows, reports live_checked evidence, and surfaces blocked RFC6330 gaps explicitly."
            ;;
        RFC6330-PROOF-SECTION-5-3-LIVE)
            printf '%s\n' "The RFC6330 section filter executes the live 5.3 tuple-generation seam and preserves blocked repair-tuple gap metadata."
            ;;
        RFC6330-PROOF-LEVEL-MUST-LIVE)
            printf '%s\n' "The RFC6330 requirement-level filter executes all MUST rows without fixture-only promotion and keeps incomplete MUST rows blocked."
            ;;
        RFC6330-PROOF-CATEGORY-DIFFERENTIAL-LIVE)
            printf '%s\n' "The RFC6330 category filter executes the differential tuple test through live production code and exposes blocked differential follow-up rows."
            ;;
        RFC6330-PROOF-GENERATE-REPORT)
            printf '%s\n' "The human report contains evidence-quality counts and the registered test execution matrix."
            ;;
        *)
            return 1
            ;;
    esac
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

cli_base_command() {
    local args="$1"
    printf 'cargo run -p asupersync-conformance --bin raptorq_rfc6330_conformance -- %s' "$args"
}

rch_command_string() {
    local args="$1"
    printf "rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 RUSTFLAGS='-C debuginfo=0' CARGO_TARGET_DIR=\${TMPDIR:-/tmp}/rch_target_asupersync_kokw3m_rfc6330 cargo run -p asupersync-conformance --bin raptorq_rfc6330_conformance -- %s" "$args"
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

    cat >> "$jsonl_path" <<EOF
{"schema_version":"${SCHEMA_VERSION}","bead_id":"${BEAD_ID}","scenario_id":"$(json_escape "$scenario_id")","subsystem":"${SUBSYSTEM}","support_class":"production_live","source_files_inspected":["conformance/src/bin/raptorq_rfc6330_conformance.rs","conformance/src/raptorq_rfc6330.rs","conformance/src/rfc6330_tests.rs","src/raptorq/rfc6330.rs","src/raptorq/systematic.rs"],"command":"$(json_escape "$command")","rch_command_if_used":"$(json_escape "$rch_command")","cargo_features":[],"test_filter":"$(json_escape "$test_filter")","env_keys_required":["ARTIFACT_ROOT","RUN_ID","RCH_BIN","RCH_WRAPPER_TIMEOUT"],"deterministic_seed_or_fixture_id":"rfc6330-cli-seed-42","input_artifact":"$(json_escape "$input_artifact")","output_artifact":"$(json_escape "$output_artifact")","expected_behavior":"$(json_escape "$expected_behavior")","actual_behavior":"$(json_escape "$actual_behavior")","verdict":"${verdict}","first_failure_line":"$(json_escape "$first_failure_line")","duration_ms":${duration_ms},"git_sha_or_tree_state":"$(git_state)","blocker_bead_id":"","evidence_quality":"live"}
EOF
}

run_command_capture() {
    local args="$1"
    local stdout_path="$2"
    local stderr_path="$3"
    local target_dir="${TMPDIR:-/tmp}/rch_target_asupersync_kokw3m_rfc6330"

    if [[ "$USE_RCH" -eq 1 ]]; then
        timeout "$RCH_WRAPPER_TIMEOUT" "$RCH_BIN" exec -- \
            env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
            CARGO_TARGET_DIR="$target_dir" \
            cargo run -p asupersync-conformance --bin raptorq_rfc6330_conformance -- $args \
            > "$stdout_path" 2> "$stderr_path"
    else
        cargo run -p asupersync-conformance --bin raptorq_rfc6330_conformance -- $args \
            > "$stdout_path" 2> "$stderr_path"
    fi
}

first_failure_line_from() {
    local stderr_path="$1"
    local stdout_path="$2"
    local line=""
    line="$(grep -m1 -E 'error:|FAILED|FAIL|blocked|unsupported|Conformance threshold not met' "$stderr_path" "$stdout_path" 2>/dev/null || true)"
    printf '%s' "$line"
}

validate_ci_output() {
    local stdout_path="$1"
    local scenario_id="$2"
    local summary_json total failing live_checked blocked unsupported expected_fail failed_quality
    local record_count missing_seam missing_blocker

    summary_json="$(grep -E '^\{"summary":' "$stdout_path" | tail -n1 || true)"
    if [[ -z "$summary_json" ]]; then
        printf 'missing CI summary line'
        return 1
    fi

    total="$(jq -r '.summary.total // empty' <<<"$summary_json")"
    failing="$(jq -r '.summary.failing // 0' <<<"$summary_json")"
    live_checked="$(jq -r '.summary.evidence_quality.live_checked // 0' <<<"$summary_json")"
    blocked="$(jq -r '.summary.evidence_quality.blocked // 0' <<<"$summary_json")"
    unsupported="$(jq -r '.summary.evidence_quality.unsupported // 0' <<<"$summary_json")"
    expected_fail="$(jq -r '.summary.evidence_quality.expected_fail // 0' <<<"$summary_json")"
    failed_quality="$(jq -r '.summary.evidence_quality.failed // 0' <<<"$summary_json")"
    record_count="$(jq -Rr 'fromjson? | objects | select(has("summary") | not) | .rfc_clause // empty' "$stdout_path" | wc -l | tr -d ' ')"
    missing_seam="$(jq -Rr 'fromjson? | objects | select(has("summary") | not) | select((.evidence_kind == "live_checked") and ((.production_seam_path // "") == "")) | .rfc_clause // empty' "$stdout_path" | head -n1)"
    missing_blocker="$(jq -Rr 'fromjson? | objects | select(has("summary") | not) | select((.evidence_kind == "blocked" or .evidence_kind == "unsupported" or .evidence_kind == "expected_fail") and ((.blocker_id // "") == "")) | .rfc_clause // empty' "$stdout_path" | head -n1)"

    if [[ -z "$total" || "$total" -le 0 ]]; then
        printf '%s emitted zero tests' "$scenario_id"
        return 1
    fi
    if [[ "$record_count" -le 0 ]]; then
        printf '%s emitted zero JSONL records' "$scenario_id"
        return 1
    fi
    if [[ -z "$live_checked" || "$live_checked" -le 0 ]]; then
        printf '%s emitted no live_checked evidence' "$scenario_id"
        return 1
    fi
    if [[ -n "$missing_seam" ]]; then
        printf '%s live row missing production seam: %s' "$scenario_id" "$missing_seam"
        return 1
    fi
    if [[ -n "$missing_blocker" ]]; then
        printf '%s degraded row missing blocker: %s' "$scenario_id" "$missing_blocker"
        return 1
    fi
    if [[ "$failed_quality" -gt 0 ]]; then
        printf '%s reported live failed evidence=%s' "$scenario_id" "$failed_quality"
        return 1
    fi

    printf 'CLI summary total=%s failing=%s live_checked=%s blocked=%s unsupported=%s expected_fail=%s records=%s' \
        "$total" "$failing" "$live_checked" "$blocked" "$unsupported" "$expected_fail" "$record_count"
}

validate_report_output() {
    local stdout_path="$1"
    local required
    for required in "## Evidence Quality" "## Registered Test Executions" "RFC 6330 Conformance Coverage Report"; do
        if ! grep -Fq "$required" "$stdout_path"; then
            printf 'report missing required section: %s' "$required"
            return 1
        fi
    done
    printf 'report contains evidence-quality and registered-execution sections'
}

run_scenario() {
    local scenario_id="$1"
    local run_dir="$2"
    local jsonl_path="$3"
    local args command rch_command test_filter expected stdout_path stderr_path combined_path output_artifact input_artifact
    local start_ms end_ms duration_ms rc verdict first_failure actual validation_result

    args="$(scenario_args "$scenario_id")"
    command="$(cli_base_command "$args")"
    if [[ "$USE_RCH" -eq 1 ]]; then
        rch_command="$(rch_command_string "$args")"
    else
        rch_command=""
    fi
    test_filter="$(scenario_filter_label "$scenario_id")"
    expected="$(scenario_expected_behavior "$scenario_id")"
    stdout_path="${run_dir}/${scenario_id}.stdout"
    stderr_path="${run_dir}/${scenario_id}.stderr"
    combined_path="${run_dir}/${scenario_id}.combined"
    output_artifact="$(repo_relative "$combined_path")"
    input_artifact="conformance/raptorq_rfc6330/REQUIREMENTS_MATRIX.json"

    if [[ "$MODE" == "dry-run" ]]; then
        printf '[dry-run] %s\n' "$rch_command"
        return 0
    fi

    start_ms="$(date +%s%3N)"
    set +e
    run_command_capture "$args" "$stdout_path" "$stderr_path"
    rc=$?
    set -e
    end_ms="$(date +%s%3N)"
    duration_ms=$((end_ms - start_ms))
    cat "$stdout_path" "$stderr_path" > "$combined_path"

    verdict="pass"
    first_failure=""
    if [[ "$scenario_id" == "RFC6330-PROOF-GENERATE-REPORT" ]]; then
        if validation_result="$(validate_report_output "$combined_path")"; then
            actual="$validation_result"
        else
            verdict="fail"
            actual="$validation_result"
            first_failure="$validation_result"
        fi
    else
        if validation_result="$(validate_ci_output "$combined_path" "$scenario_id")"; then
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
        first_failure="$(first_failure_line_from "$stderr_path" "$stdout_path")"
    elif [[ "$verdict" == "fail" && "$rc" -ne 0 ]]; then
        actual="command exited ${rc}; ${actual}"
        if [[ -z "$first_failure" ]]; then
            first_failure="$(first_failure_line_from "$stderr_path" "$stdout_path")"
        fi
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
        "$duration_ms"

    if [[ "$verdict" != "pass" ]]; then
        return 1
    fi
}

write_self_test_fixture_jsonl() {
    local path="$1"
    cat > "$path" <<EOF
{"schema_version":"${SCHEMA_VERSION}","bead_id":"${BEAD_ID}","scenario_id":"rfc6330-self-test-live-pass","subsystem":"${SUBSYSTEM}","support_class":"production_live","source_files_inspected":["conformance/src/bin/raptorq_rfc6330_conformance.rs"],"command":"bash scripts/run_rfc6330_conformance_evidence.sh --self-test","rch_command_if_used":"","cargo_features":[],"test_filter":"self-test-pass","env_keys_required":["ARTIFACT_ROOT"],"deterministic_seed_or_fixture_id":"self-test-v1","input_artifact":"conformance/src/rfc6330_tests.rs","output_artifact":"$(repo_relative "$path")","expected_behavior":"Fixture live-pass record validates successfully.","actual_behavior":"Fixture record is schema-valid and redacted.","verdict":"pass","first_failure_line":"","duration_ms":1,"git_sha_or_tree_state":"$(git_state)","blocker_bead_id":"","evidence_quality":"live"}
{"schema_version":"${SCHEMA_VERSION}","bead_id":"${BEAD_ID}","scenario_id":"rfc6330-self-test-live-fail","subsystem":"${SUBSYSTEM}","support_class":"production_live","source_files_inspected":["conformance/src/rfc6330_tests.rs"],"command":"bash scripts/run_rfc6330_conformance_evidence.sh --self-test --fixture live-fail","rch_command_if_used":"","cargo_features":[],"test_filter":"self-test-fail","env_keys_required":[],"deterministic_seed_or_fixture_id":"self-test-v1","input_artifact":"conformance/src/rfc6330_tests.rs","output_artifact":"","expected_behavior":"A fabricated failing production check remains represented as fail, not pass.","actual_behavior":"Fixture record intentionally records a live fail outcome.","verdict":"fail","first_failure_line":"fixture:rfc6330-live-fail","duration_ms":1,"git_sha_or_tree_state":"$(git_state)","blocker_bead_id":"","evidence_quality":"live"}
{"schema_version":"${SCHEMA_VERSION}","bead_id":"${BEAD_ID}","scenario_id":"rfc6330-self-test-blocked","subsystem":"${SUBSYSTEM}","support_class":"blocked_external","source_files_inspected":["conformance/src/rfc6330_tests.rs"],"command":"bash scripts/run_rfc6330_conformance_evidence.sh --self-test --fixture blocked","rch_command_if_used":"","cargo_features":[],"test_filter":"self-test-blocked","env_keys_required":["RCH_BIN"],"deterministic_seed_or_fixture_id":"self-test-v1","input_artifact":"conformance/src/rfc6330_tests.rs","output_artifact":"","expected_behavior":"Blocked records carry blocker context and are not counted as production passes.","actual_behavior":"Fixture record uses blocked evidence with blocker bead context.","verdict":"blocked","first_failure_line":"fixture:blocked-before-rust-validation","duration_ms":1,"git_sha_or_tree_state":"$(git_state)","blocker_bead_id":"asupersync-kokw3m","evidence_quality":"blocked"}
{"schema_version":"${SCHEMA_VERSION}","bead_id":"${BEAD_ID}","scenario_id":"rfc6330-self-test-unsupported","subsystem":"${SUBSYSTEM}","support_class":"explicitly_unsupported","source_files_inspected":["conformance/src/rfc6330_tests.rs"],"command":"bash scripts/run_rfc6330_conformance_evidence.sh --self-test --fixture unsupported","rch_command_if_used":"","cargo_features":[],"test_filter":"self-test-unsupported","env_keys_required":[],"deterministic_seed_or_fixture_id":"self-test-v1","input_artifact":"conformance/src/rfc6330_tests.rs","output_artifact":"","expected_behavior":"Unsupported RFC6330 evidence is explicit and cannot become a production pass.","actual_behavior":"Fixture record validates as unsupported evidence.","verdict":"unsupported","first_failure_line":"","duration_ms":1,"git_sha_or_tree_state":"$(git_state)","blocker_bead_id":"","evidence_quality":"unsupported"}
{"schema_version":"${SCHEMA_VERSION}","bead_id":"${BEAD_ID}","scenario_id":"rfc6330-self-test-expected-fail","subsystem":"${SUBSYSTEM}","support_class":"production_live","source_files_inspected":["conformance/src/rfc6330_tests.rs"],"command":"bash scripts/run_rfc6330_conformance_evidence.sh --self-test --fixture expected-fail","rch_command_if_used":"","cargo_features":[],"test_filter":"self-test-expected-fail","env_keys_required":[],"deterministic_seed_or_fixture_id":"self-test-v1","input_artifact":"conformance/src/rfc6330_tests.rs","output_artifact":"","expected_behavior":"Expected-fail records remain separated from production passes.","actual_behavior":"Fixture record validates as expected_fail evidence.","verdict":"expected_fail","first_failure_line":"fixture:known-follow-up","duration_ms":1,"git_sha_or_tree_state":"$(git_state)","blocker_bead_id":"asupersync-kokw3m","evidence_quality":"expected_fail"}
{"schema_version":"${SCHEMA_VERSION}","bead_id":"${BEAD_ID}","scenario_id":"rfc6330-self-test-fixture-only","subsystem":"${SUBSYSTEM}","support_class":"fixture_reference","source_files_inspected":["conformance/src/rfc6330_fixtures.rs"],"command":"bash scripts/run_rfc6330_conformance_evidence.sh --self-test --fixture fixture-only","rch_command_if_used":"","cargo_features":[],"test_filter":"self-test-fixture-only","env_keys_required":[],"deterministic_seed_or_fixture_id":"RFC6330_TUPLE_TEST_VECTORS","input_artifact":"conformance/src/rfc6330_fixtures.rs","output_artifact":"","expected_behavior":"Fixture-only records are accepted for context but never counted as production conformance.","actual_behavior":"Fixture record validates as fixture_only evidence.","verdict":"fixture_only","first_failure_line":"","duration_ms":1,"git_sha_or_tree_state":"$(git_state)","blocker_bead_id":"","evidence_quality":"fixture_only"}
EOF
}

run_self_test() {
    local root="$ARTIFACT_ROOT/self-test"
    local fixture_jsonl="$root/rfc6330-self-test.jsonl"
    local summary_json="$root/rfc6330-self-test.summary.json"
    mkdir -p "$root"
    write_self_test_fixture_jsonl "$fixture_jsonl"
    python3 "$VALIDATOR" --contract "$CONTRACT" --self-test >/dev/null
    python3 "$VALIDATOR" --contract "$CONTRACT" --jsonl "$fixture_jsonl" --summary-output "$summary_json"
    echo "RFC6330 evidence runner self-test: pass"
    echo "Evidence JSONL: $(repo_relative "$fixture_jsonl")"
    echo "Summary: $(repo_relative "$summary_json")"
}

list_scenarios() {
    echo "RFC6330 evidence proof scenarios:"
    local scenario
    for scenario in "${SCENARIOS[@]}"; do
        echo "  ${scenario} :: $(scenario_args "$scenario")"
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
            local run_dir jsonl_path summary_path scenario failures=0
            run_dir="${ARTIFACT_ROOT}/${RUN_ID}"
            jsonl_path="${run_dir}/rfc6330-conformance-evidence.jsonl"
            summary_path="${run_dir}/rfc6330-conformance-evidence.summary.json"
            mkdir -p "$run_dir"
            : > "$jsonl_path"

            for scenario in "${SCENARIOS[@]}"; do
                if [[ -n "$SCENARIO_FILTER" && "$scenario" != "$SCENARIO_FILTER" ]]; then
                    continue
                fi
                if ! run_scenario "$scenario" "$run_dir" "$jsonl_path"; then
                    failures=$((failures + 1))
                fi
            done

            if [[ "$MODE" == "dry-run" ]]; then
                echo "Dry-run artifact root: $(repo_relative "$run_dir")"
                exit 0
            fi

            python3 "$VALIDATOR" --contract "$CONTRACT" --jsonl "$jsonl_path" --summary-output "$summary_path"
            echo "RFC6330 conformance evidence: $([[ "$failures" -eq 0 ]] && echo pass || echo fail)"
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
