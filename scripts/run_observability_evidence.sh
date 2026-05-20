#!/usr/bin/env bash
set -euo pipefail

# Observability proof runner for asupersync-uw9zg9.
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
ARTIFACT_ROOT="${ARTIFACT_ROOT:-${PROJECT_ROOT}/artifacts/mock-code-finder/asupersync-uw9zg9}"
MODE="execute"
USE_RCH=1
SCENARIO_FILTER=""
ALLOW_LOCAL_CARGO="${ALLOW_LOCAL_CARGO:-0}"

SCHEMA_VERSION="mock-code-finder-evidence-jsonl-schema-v1"
BEAD_ID="asupersync-uw9zg9"
SUBSYSTEM="observability-otel-w3c"
TARGET_DIR_EXPR="\${TMPDIR:-/tmp}/rch_target_asupersync_uw9zg9_observability"

declare -a SCENARIOS=(
    "OTEL-HISTOGRAM-AGGREGATOR-LIVE"
    "OTEL-HISTOGRAM-RECORD-LIVE"
    "OTEL-RESOURCE-DETECTION-MERGE-LIVE"
    "OTEL-LOG-SEVERITY-LIVE"
    "OTEL-TRACE-ID-RANDOMNESS-LIVE"
    "OTEL-SPAN-ID-RANDOMNESS-LIVE"
    "OTEL-METRIC-BATCHING-LIVE"
    "OTEL-TRACE-CONTEXT-PROPAGATION-LIVE"
    "OTEL-W3C-BAGGAGE-PRODUCTION-LIVE"
    "OTEL-TAIL-SAMPLING-UNSUPPORTED"
    "OTEL-EVIDENCE-REDACTION-SELF-TEST-LIVE"
)

usage() {
    cat <<'USAGE'
Usage: bash scripts/run_observability_evidence.sh [options]

Options:
  --execute                 Run selected OTel/W3C proof scenarios (default)
  --dry-run                 List commands and artifact paths without running cargo
  --self-test               Validate script fixtures and shared negative cases without cargo
  --list                    List scenarios and aggregate-runner registration metadata
  --scenario <SCENARIO_ID>  Run or dry-run one scenario
  --artifact-root <PATH>    Override output root (default: artifacts/mock-code-finder/asupersync-uw9zg9)
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
        OTEL-HISTOGRAM-AGGREGATOR-LIVE)
            printf '%s %s run -p asupersync-conformance --bin otel_histogram_aggregator_conformance\n' "$(cargo_env_prefix)" "$CARGO_BIN"
            ;;
        OTEL-HISTOGRAM-RECORD-LIVE)
            printf '%s %s run -p asupersync-conformance --bin otel_histogram_record_conformance\n' "$(cargo_env_prefix)" "$CARGO_BIN"
            ;;
        OTEL-RESOURCE-DETECTION-MERGE-LIVE)
            printf '%s %s run -p asupersync-conformance --bin otel_resource_detection_conformance\n' "$(cargo_env_prefix)" "$CARGO_BIN"
            ;;
        OTEL-LOG-SEVERITY-LIVE)
            printf '%s %s run -p asupersync-conformance --bin otel_logs_severity_range_conformance\n' "$(cargo_env_prefix)" "$CARGO_BIN"
            ;;
        OTEL-TRACE-ID-RANDOMNESS-LIVE)
            printf '%s %s run -p asupersync-conformance --bin otel_trace_id_randomness_conformance\n' "$(cargo_env_prefix)" "$CARGO_BIN"
            ;;
        OTEL-SPAN-ID-RANDOMNESS-LIVE)
            printf '%s %s run -p asupersync-conformance --bin otel_span_id_randomness_conformance\n' "$(cargo_env_prefix)" "$CARGO_BIN"
            ;;
        OTEL-METRIC-BATCHING-LIVE)
            printf '%s %s run -p asupersync-conformance --bin otel_metric_exporter_batching_conformance\n' "$(cargo_env_prefix)" "$CARGO_BIN"
            ;;
        OTEL-TRACE-CONTEXT-PROPAGATION-LIVE)
            printf '%s %s run -p asupersync-conformance --bin otel_trace_context_propagation_conformance -- all\n' "$(cargo_env_prefix)" "$CARGO_BIN"
            ;;
        OTEL-W3C-BAGGAGE-PRODUCTION-LIVE)
            printf '%s %s test -p asupersync --lib baggage_ --features test-internals,tracing-integration -- --nocapture\n' "$(cargo_env_prefix)" "$CARGO_BIN"
            ;;
        OTEL-TAIL-SAMPLING-UNSUPPORTED)
            printf '%s %s test -p asupersync --lib tail_based_sampling_scope --features metrics,tracing-integration,test-internals -- --nocapture\n' "$(cargo_env_prefix)" "$CARGO_BIN"
            ;;
        OTEL-EVIDENCE-REDACTION-SELF-TEST-LIVE)
            printf 'python3 scripts/validate_mock_code_finder_evidence.py --contract artifacts/mock_code_finder_verification_contract_v1.json --self-test\n'
            ;;
        *)
            echo "unknown scenario: $scenario_id" >&2
            return 1
            ;;
    esac
}

scenario_test_filter() {
    case "$1" in
        OTEL-HISTOGRAM-AGGREGATOR-LIVE) printf 'otel_histogram_aggregator_conformance\n' ;;
        OTEL-HISTOGRAM-RECORD-LIVE) printf 'otel_histogram_record_conformance\n' ;;
        OTEL-RESOURCE-DETECTION-MERGE-LIVE) printf 'otel_resource_detection_conformance\n' ;;
        OTEL-LOG-SEVERITY-LIVE) printf 'otel_logs_severity_range_conformance\n' ;;
        OTEL-TRACE-ID-RANDOMNESS-LIVE) printf 'otel_trace_id_randomness_conformance\n' ;;
        OTEL-SPAN-ID-RANDOMNESS-LIVE) printf 'otel_span_id_randomness_conformance\n' ;;
        OTEL-METRIC-BATCHING-LIVE) printf 'otel_metric_exporter_batching_conformance\n' ;;
        OTEL-TRACE-CONTEXT-PROPAGATION-LIVE) printf 'otel_trace_context_propagation_conformance all\n' ;;
        OTEL-W3C-BAGGAGE-PRODUCTION-LIVE) printf 'baggage_\n' ;;
        OTEL-TAIL-SAMPLING-UNSUPPORTED) printf 'tail_based_sampling_scope\n' ;;
        OTEL-EVIDENCE-REDACTION-SELF-TEST-LIVE) printf 'validator self-test redaction negative cases\n' ;;
        *) return 1 ;;
    esac
}

scenario_expected_behavior() {
    case "$1" in
        OTEL-HISTOGRAM-AGGREGATOR-LIVE)
            printf 'Live asupersync histogram snapshots match deterministic explicit-boundary bucket, count, and sum expectations.\n'
            ;;
        OTEL-HISTOGRAM-RECORD-LIVE)
            printf 'Histogram record operations update live asupersync snapshot buckets, counts, and sums for boundary and edge observations.\n'
            ;;
        OTEL-RESOURCE-DETECTION-MERGE-LIVE)
            printf 'OTEL_RESOURCE_ATTRIBUTES parsing and merge behavior is checked through the live OtlpResourceBuilder seam against opentelemetry-sdk reference output.\n'
            ;;
        OTEL-LOG-SEVERITY-LIVE)
            printf 'Representative log levels map to OTLP severity numbers/text, boundary ranges are covered, and unsupported fatal range is explicit.\n'
            ;;
        OTEL-TRACE-ID-RANDOMNESS-LIVE)
            printf 'Trace IDs generated through the live observability surface are nonzero, correctly formatted, unique within the sample, and entropy checked.\n'
            ;;
        OTEL-SPAN-ID-RANDOMNESS-LIVE)
            printf 'Span IDs generated through the live observability surface are nonzero, correctly formatted, unique within the sample, and entropy checked.\n'
            ;;
        OTEL-METRIC-BATCHING-LIVE)
            printf 'Metric exporter batching records live flush, drain, threshold, timeout, and drop accounting behavior against the batching contract.\n'
            ;;
        OTEL-TRACE-CONTEXT-PROPAGATION-LIVE)
            printf 'Trace context extraction/injection preserves traceparent/tracestate identity and handles invalid propagation cases through the conformance runner.\n'
            ;;
        OTEL-W3C-BAGGAGE-PRODUCTION-LIVE)
            printf 'Production W3CBaggage extraction does not require traceparent, injection is deterministic, invalid members are rejected, and security bounds are enforced.\n'
            ;;
        OTEL-TAIL-SAMPLING-UNSUPPORTED)
            printf 'Tail-based sampling support stance is encoded as explicitly unsupported with missing production surfaces and mock-code-finder evidence fields, not as a pass.\n'
            ;;
        OTEL-EVIDENCE-REDACTION-SELF-TEST-LIVE)
            printf 'Shared proof validator rejects malformed JSONL, zero-scenario output, missing fields, dishonest audit-only passes, and unredacted secret-looking values.\n'
            ;;
        *) return 1 ;;
    esac
}

scenario_source_files() {
    case "$1" in
        OTEL-HISTOGRAM-AGGREGATOR-LIVE)
            printf '["conformance/src/bin/otel_histogram_aggregator_conformance.rs","src/observability/metrics.rs"]\n'
            ;;
        OTEL-HISTOGRAM-RECORD-LIVE)
            printf '["conformance/src/bin/otel_histogram_record_conformance.rs","src/observability/metrics.rs"]\n'
            ;;
        OTEL-RESOURCE-DETECTION-MERGE-LIVE)
            printf '["conformance/src/bin/otel_resource_detection_conformance.rs","src/observability/otel.rs"]\n'
            ;;
        OTEL-LOG-SEVERITY-LIVE)
            printf '["conformance/src/bin/otel_logs_severity_range_conformance.rs","src/observability/level.rs","src/observability/otel.rs"]\n'
            ;;
        OTEL-TRACE-ID-RANDOMNESS-LIVE)
            printf '["conformance/src/bin/otel_trace_id_randomness_conformance.rs","src/observability/w3c_trace_context.rs","src/observability/otel.rs"]\n'
            ;;
        OTEL-SPAN-ID-RANDOMNESS-LIVE)
            printf '["conformance/src/bin/otel_span_id_randomness_conformance.rs","src/observability/w3c_trace_context.rs","src/observability/otel.rs"]\n'
            ;;
        OTEL-METRIC-BATCHING-LIVE)
            printf '["conformance/src/bin/otel_metric_exporter_batching_conformance.rs","src/observability/otel.rs"]\n'
            ;;
        OTEL-TRACE-CONTEXT-PROPAGATION-LIVE)
            printf '["conformance/src/bin/otel_trace_context_propagation_conformance.rs","src/observability/w3c_trace_context.rs"]\n'
            ;;
        OTEL-W3C-BAGGAGE-PRODUCTION-LIVE)
            printf '["src/observability/w3c_trace_context.rs"]\n'
            ;;
        OTEL-TAIL-SAMPLING-UNSUPPORTED)
            printf '["src/observability/otlp_trace_exporter.rs","src/observability/otlp_tail_based_sampling_audit_test.rs"]\n'
            ;;
        OTEL-EVIDENCE-REDACTION-SELF-TEST-LIVE)
            printf '["scripts/validate_mock_code_finder_evidence.py","artifacts/mock_code_finder_verification_contract_v1.json","scripts/run_observability_evidence.sh"]\n'
            ;;
        *) return 1 ;;
    esac
}

scenario_input_artifact() {
    case "$1" in
        OTEL-HISTOGRAM-AGGREGATOR-LIVE) printf 'conformance/src/bin/otel_histogram_aggregator_conformance.rs:main\n' ;;
        OTEL-HISTOGRAM-RECORD-LIVE) printf 'conformance/src/bin/otel_histogram_record_conformance.rs:main\n' ;;
        OTEL-RESOURCE-DETECTION-MERGE-LIVE) printf 'conformance/src/bin/otel_resource_detection_conformance.rs:main\n' ;;
        OTEL-LOG-SEVERITY-LIVE) printf 'conformance/src/bin/otel_logs_severity_range_conformance.rs:main\n' ;;
        OTEL-TRACE-ID-RANDOMNESS-LIVE) printf 'conformance/src/bin/otel_trace_id_randomness_conformance.rs:main\n' ;;
        OTEL-SPAN-ID-RANDOMNESS-LIVE) printf 'conformance/src/bin/otel_span_id_randomness_conformance.rs:main\n' ;;
        OTEL-METRIC-BATCHING-LIVE) printf 'conformance/src/bin/otel_metric_exporter_batching_conformance.rs:main\n' ;;
        OTEL-TRACE-CONTEXT-PROPAGATION-LIVE) printf 'conformance/src/bin/otel_trace_context_propagation_conformance.rs:all\n' ;;
        OTEL-W3C-BAGGAGE-PRODUCTION-LIVE) printf 'src/observability/w3c_trace_context.rs:baggage tests\n' ;;
        OTEL-TAIL-SAMPLING-UNSUPPORTED) printf 'src/observability/otlp_trace_exporter.rs:otlp_tail_based_sampling_scope\n' ;;
        OTEL-EVIDENCE-REDACTION-SELF-TEST-LIVE) printf 'scripts/validate_mock_code_finder_evidence.py:run_self_test\n' ;;
        *) return 1 ;;
    esac
}

scenario_expected_verdict() {
    case "$1" in
        OTEL-TAIL-SAMPLING-UNSUPPORTED) printf 'unsupported\n' ;;
        *) printf 'pass\n' ;;
    esac
}

rch_invocation() {
    local scenario_id="$1"
    case "$scenario_id" in
        OTEL-HISTOGRAM-AGGREGATOR-LIVE)
            printf '%s %s run -p asupersync-conformance --bin otel_histogram_aggregator_conformance\n' \
                "rch exec -- $(cargo_env_prefix)" "$CARGO_BIN"
            ;;
        OTEL-HISTOGRAM-RECORD-LIVE)
            printf '%s %s run -p asupersync-conformance --bin otel_histogram_record_conformance\n' \
                "rch exec -- $(cargo_env_prefix)" "$CARGO_BIN"
            ;;
        OTEL-RESOURCE-DETECTION-MERGE-LIVE)
            printf '%s %s run -p asupersync-conformance --bin otel_resource_detection_conformance\n' \
                "rch exec -- $(cargo_env_prefix)" "$CARGO_BIN"
            ;;
        OTEL-LOG-SEVERITY-LIVE)
            printf '%s %s run -p asupersync-conformance --bin otel_logs_severity_range_conformance\n' \
                "rch exec -- $(cargo_env_prefix)" "$CARGO_BIN"
            ;;
        OTEL-TRACE-ID-RANDOMNESS-LIVE)
            printf '%s %s run -p asupersync-conformance --bin otel_trace_id_randomness_conformance\n' \
                "rch exec -- $(cargo_env_prefix)" "$CARGO_BIN"
            ;;
        OTEL-SPAN-ID-RANDOMNESS-LIVE)
            printf '%s %s run -p asupersync-conformance --bin otel_span_id_randomness_conformance\n' \
                "rch exec -- $(cargo_env_prefix)" "$CARGO_BIN"
            ;;
        OTEL-METRIC-BATCHING-LIVE)
            printf '%s %s run -p asupersync-conformance --bin otel_metric_exporter_batching_conformance\n' \
                "rch exec -- $(cargo_env_prefix)" "$CARGO_BIN"
            ;;
        OTEL-TRACE-CONTEXT-PROPAGATION-LIVE)
            printf '%s %s run -p asupersync-conformance --bin otel_trace_context_propagation_conformance -- all\n' \
                "rch exec -- $(cargo_env_prefix)" "$CARGO_BIN"
            ;;
        OTEL-W3C-BAGGAGE-PRODUCTION-LIVE)
            printf '%s %s test -p asupersync --lib baggage_ --features test-internals,tracing-integration -- --nocapture\n' \
                "rch exec -- $(cargo_env_prefix)" "$CARGO_BIN"
            ;;
        OTEL-TAIL-SAMPLING-UNSUPPORTED)
            printf '%s %s test -p asupersync --lib tail_based_sampling_scope --features metrics,tracing-integration,test-internals -- --nocapture\n' \
                "rch exec -- $(cargo_env_prefix)" "$CARGO_BIN"
            ;;
        *)
            echo "unknown rch scenario: $scenario_id" >&2
            return 1
            ;;
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
{"schema_version":"${SCHEMA_VERSION}","bead_id":"${BEAD_ID}","scenario_id":"$(json_escape "$scenario_id")","subsystem":"${SUBSYSTEM}","support_class":"${support_class}","source_files_inspected":${source_files_json},"command":"$(json_escape "$command")","rch_command_if_used":"$(json_escape "$rch_command")","cargo_features":["metrics","test-internals","tracing-integration"],"test_filter":"$(json_escape "$test_filter")","env_keys_required":["ARTIFACT_ROOT","RUN_ID","RCH_BIN","CARGO_BIN","RCH_WRAPPER_TIMEOUT"],"deterministic_seed_or_fixture_id":"otel-w3c-uw9zg9-fixed-scenarios","input_artifact":"$(json_escape "$input_artifact")","output_artifact":"$(json_escape "$output_artifact")","expected_behavior":"$(json_escape "$expected_behavior")","actual_behavior":"$(json_escape "$actual_behavior")","verdict":"${verdict}","first_failure_line":"$(json_escape "$first_failure_line")","duration_ms":${duration_ms},"git_sha_or_tree_state":"$(git_state)","blocker_bead_id":"$(json_escape "$blocker_bead_id")","evidence_quality":"${evidence_quality}"}
EOF
}

first_failure_line_from() {
    local path="$1"
    grep -m1 -E 'error:|FAILED|FAIL|panicked at|blocked|unsupported|unredacted|invalid JSON|missing required|zero scenario' "$path" 2>/dev/null || true
}

run_rch_command_capture() {
    local scenario_id="$1"
    local stdout_path="$2"
    local stderr_path="$3"
    local target_dir="${TMPDIR:-/tmp}/rch_target_asupersync_uw9zg9_observability"

    case "$scenario_id" in
        OTEL-HISTOGRAM-AGGREGATOR-LIVE)
            timeout "$RCH_WRAPPER_TIMEOUT" "$RCH_BIN" exec -- env CARGO_INCREMENTAL=0 \
                CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" CARGO_TARGET_DIR="$target_dir" \
                "$CARGO_BIN" run -p asupersync-conformance --bin otel_histogram_aggregator_conformance \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        OTEL-HISTOGRAM-RECORD-LIVE)
            timeout "$RCH_WRAPPER_TIMEOUT" "$RCH_BIN" exec -- env CARGO_INCREMENTAL=0 \
                CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" CARGO_TARGET_DIR="$target_dir" \
                "$CARGO_BIN" run -p asupersync-conformance --bin otel_histogram_record_conformance \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        OTEL-RESOURCE-DETECTION-MERGE-LIVE)
            timeout "$RCH_WRAPPER_TIMEOUT" "$RCH_BIN" exec -- env CARGO_INCREMENTAL=0 \
                CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" CARGO_TARGET_DIR="$target_dir" \
                "$CARGO_BIN" run -p asupersync-conformance --bin otel_resource_detection_conformance \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        OTEL-LOG-SEVERITY-LIVE)
            timeout "$RCH_WRAPPER_TIMEOUT" "$RCH_BIN" exec -- env CARGO_INCREMENTAL=0 \
                CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" CARGO_TARGET_DIR="$target_dir" \
                "$CARGO_BIN" run -p asupersync-conformance --bin otel_logs_severity_range_conformance \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        OTEL-TRACE-ID-RANDOMNESS-LIVE)
            timeout "$RCH_WRAPPER_TIMEOUT" "$RCH_BIN" exec -- env CARGO_INCREMENTAL=0 \
                CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" CARGO_TARGET_DIR="$target_dir" \
                "$CARGO_BIN" run -p asupersync-conformance --bin otel_trace_id_randomness_conformance \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        OTEL-SPAN-ID-RANDOMNESS-LIVE)
            timeout "$RCH_WRAPPER_TIMEOUT" "$RCH_BIN" exec -- env CARGO_INCREMENTAL=0 \
                CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" CARGO_TARGET_DIR="$target_dir" \
                "$CARGO_BIN" run -p asupersync-conformance --bin otel_span_id_randomness_conformance \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        OTEL-METRIC-BATCHING-LIVE)
            timeout "$RCH_WRAPPER_TIMEOUT" "$RCH_BIN" exec -- env CARGO_INCREMENTAL=0 \
                CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" CARGO_TARGET_DIR="$target_dir" \
                "$CARGO_BIN" run -p asupersync-conformance --bin otel_metric_exporter_batching_conformance \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        OTEL-TRACE-CONTEXT-PROPAGATION-LIVE)
            timeout "$RCH_WRAPPER_TIMEOUT" "$RCH_BIN" exec -- env CARGO_INCREMENTAL=0 \
                CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" CARGO_TARGET_DIR="$target_dir" \
                "$CARGO_BIN" run -p asupersync-conformance --bin otel_trace_context_propagation_conformance -- all \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        OTEL-W3C-BAGGAGE-PRODUCTION-LIVE)
            timeout "$RCH_WRAPPER_TIMEOUT" "$RCH_BIN" exec -- env CARGO_INCREMENTAL=0 \
                CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" CARGO_TARGET_DIR="$target_dir" \
                "$CARGO_BIN" test -p asupersync --lib baggage_ --features test-internals,tracing-integration -- --nocapture \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        OTEL-TAIL-SAMPLING-UNSUPPORTED)
            timeout "$RCH_WRAPPER_TIMEOUT" "$RCH_BIN" exec -- env CARGO_INCREMENTAL=0 \
                CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" CARGO_TARGET_DIR="$target_dir" \
                "$CARGO_BIN" test -p asupersync --lib tail_based_sampling_scope --features metrics,tracing-integration,test-internals -- --nocapture \
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
    local target_dir="${TMPDIR:-/tmp}/rch_target_asupersync_uw9zg9_observability"

    case "$scenario_id" in
        OTEL-HISTOGRAM-AGGREGATOR-LIVE)
            env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="$target_dir" \
                "$CARGO_BIN" run -p asupersync-conformance --bin otel_histogram_aggregator_conformance \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        OTEL-HISTOGRAM-RECORD-LIVE)
            env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="$target_dir" \
                "$CARGO_BIN" run -p asupersync-conformance --bin otel_histogram_record_conformance \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        OTEL-RESOURCE-DETECTION-MERGE-LIVE)
            env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="$target_dir" \
                "$CARGO_BIN" run -p asupersync-conformance --bin otel_resource_detection_conformance \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        OTEL-LOG-SEVERITY-LIVE)
            env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="$target_dir" \
                "$CARGO_BIN" run -p asupersync-conformance --bin otel_logs_severity_range_conformance \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        OTEL-TRACE-ID-RANDOMNESS-LIVE)
            env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="$target_dir" \
                "$CARGO_BIN" run -p asupersync-conformance --bin otel_trace_id_randomness_conformance \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        OTEL-SPAN-ID-RANDOMNESS-LIVE)
            env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="$target_dir" \
                "$CARGO_BIN" run -p asupersync-conformance --bin otel_span_id_randomness_conformance \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        OTEL-METRIC-BATCHING-LIVE)
            env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="$target_dir" \
                "$CARGO_BIN" run -p asupersync-conformance --bin otel_metric_exporter_batching_conformance \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        OTEL-TRACE-CONTEXT-PROPAGATION-LIVE)
            env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="$target_dir" \
                "$CARGO_BIN" run -p asupersync-conformance --bin otel_trace_context_propagation_conformance -- all \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        OTEL-W3C-BAGGAGE-PRODUCTION-LIVE)
            env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="$target_dir" \
                "$CARGO_BIN" test -p asupersync --lib baggage_ --features test-internals,tracing-integration -- --nocapture \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        OTEL-TAIL-SAMPLING-UNSUPPORTED)
            env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0" \
                CARGO_TARGET_DIR="$target_dir" \
                "$CARGO_BIN" test -p asupersync --lib tail_based_sampling_scope --features metrics,tracing-integration,test-internals -- --nocapture \
                > "$stdout_path" 2> "$stderr_path"
            ;;
        OTEL-EVIDENCE-REDACTION-SELF-TEST-LIVE)
            python3 "$VALIDATOR" --contract "$CONTRACT" --self-test \
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

    if [[ "$scenario_id" == "OTEL-EVIDENCE-REDACTION-SELF-TEST-LIVE" ]]; then
        cd "$PROJECT_ROOT"
        run_local_command_capture "$scenario_id" "$stdout_path" "$stderr_path"
    elif [[ "$USE_RCH" -eq 1 ]]; then
        run_rch_command_capture "$scenario_id" "$stdout_path" "$stderr_path"
    else
        cd "$PROJECT_ROOT"
        run_local_command_capture "$scenario_id" "$stdout_path" "$stderr_path"
    fi
}

validate_command_output() {
    local combined_path="$1"
    local scenario_id="$2"
    local expected_verdict="$3"

    if [[ "$expected_verdict" == "unsupported" ]]; then
        if grep -Fq "test result: ok" "$combined_path"; then
            printf 'tail-sampling support boundary is explicitly unsupported and contract tests passed'
            return 0
        fi
        printf '%s did not emit successful unsupported-scope cargo tests' "$scenario_id"
        return 1
    fi

    case "$scenario_id" in
        OTEL-W3C-BAGGAGE-PRODUCTION-LIVE)
            if grep -Fq "test result: ok" "$combined_path"; then
                printf 'production W3C baggage tests passed'
                return 0
            fi
            printf '%s did not emit a successful cargo test summary' "$scenario_id"
            return 1
            ;;
        OTEL-EVIDENCE-REDACTION-SELF-TEST-LIVE)
            if grep -Fq '"self_test"' "$combined_path" && grep -Fq '"verdict": "pass"' "$combined_path"; then
                printf 'shared validator self-test passed including redaction negative case'
                return 0
            fi
            printf '%s did not emit validator self-test pass summary' "$scenario_id"
            return 1
            ;;
        *)
            if grep -Fq "ALL TESTS PASSED" "$combined_path"; then
                printf 'conformance binary emitted ALL TESTS PASSED'
                return 0
            fi
            printf '%s did not emit ALL TESTS PASSED' "$scenario_id"
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
    local support_class evidence_quality blocker_bead_id expected_verdict rch_local_fallback

    command="$(scenario_command "$scenario_id")"
    if [[ "$USE_RCH" -eq 1 && "$scenario_id" != "OTEL-EVIDENCE-REDACTION-SELF-TEST-LIVE" ]]; then
        rch_command="$(rch_invocation "$scenario_id")"
    else
        rch_command=""
    fi
    test_filter="$(scenario_test_filter "$scenario_id")"
    expected="$(scenario_expected_behavior "$scenario_id")"
    source_files_json="$(scenario_source_files "$scenario_id")"
    input_artifact="$(scenario_input_artifact "$scenario_id")"
    expected_verdict="$(scenario_expected_verdict "$scenario_id")"
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

    rch_local_fallback=0
    if [[ "$USE_RCH" -eq 1 && "$scenario_id" != "OTEL-EVIDENCE-REDACTION-SELF-TEST-LIVE" ]] \
        && grep -Eq '^\[RCH\] local \(|falling back to local' "$combined_path" 2>/dev/null; then
        rch_local_fallback=1
        printf 'rch local fallback detected; refusing local cargo execution\n' > "${run_dir}/${scenario_id}.rch_local_fallback.txt"
        rc=86
    fi

    verdict="$expected_verdict"
    support_class="production_live"
    evidence_quality="live"
    blocker_bead_id=""
    first_failure=""
    if [[ "$expected_verdict" == "unsupported" ]]; then
        support_class="explicitly_unsupported"
        evidence_quality="unsupported"
    fi

    if [[ "$rch_local_fallback" -eq 1 ]]; then
        verdict="fail"
        support_class="production_live"
        evidence_quality="live"
        actual="rch local fallback detected; refusing local cargo execution"
        first_failure="$actual"
    elif validation_result="$(validate_command_output "$combined_path" "$scenario_id" "$expected_verdict")"; then
        actual="$validation_result"
    else
        verdict="fail"
        support_class="production_live"
        evidence_quality="live"
        actual="$validation_result"
        first_failure="$validation_result"
    fi

    if [[ "$verdict" != "fail" && "$rc" -ne 0 && "$USE_RCH" -eq 1 && "$scenario_id" != "OTEL-EVIDENCE-REDACTION-SELF-TEST-LIVE" ]]; then
        actual="${actual}; rch wrapper exited ${rc} after emitting valid proof output"
    elif [[ "$verdict" != "fail" && "$rc" -ne 0 ]]; then
        verdict="fail"
        support_class="production_live"
        evidence_quality="live"
        actual="command exited ${rc}; ${actual}"
        first_failure="$(first_failure_line_from "$combined_path")"
    elif [[ "$verdict" == "fail" && "$rc" -ne 0 && -z "$first_failure" ]]; then
        first_failure="$(first_failure_line_from "$combined_path")"
    fi
    if [[ "$verdict" == "fail" && "$rc" -eq 124 ]]; then
        verdict="blocked"
        support_class="blocked_external"
        evidence_quality="blocked"
        blocker_bead_id="$BEAD_ID"
        actual="rch wrapper timed out before ${scenario_id} emitted required proof output; no production verdict was claimed."
        first_failure="rch wrapper timeout before proof summary"
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

    if [[ "$verdict" == "fail" || "$verdict" == "blocked" ]]; then
        return 1
    fi
}

write_self_test_fixture_jsonl() {
    local path="$1"
    cat > "$path" <<EOF
{"schema_version":"${SCHEMA_VERSION}","bead_id":"${BEAD_ID}","scenario_id":"observability-self-test-live-pass","subsystem":"${SUBSYSTEM}","support_class":"production_live","source_files_inspected":["scripts/run_observability_evidence.sh","src/observability/otel.rs"],"command":"bash scripts/run_observability_evidence.sh --self-test","rch_command_if_used":"","cargo_features":["metrics","test-internals","tracing-integration"],"test_filter":"self-test-pass","env_keys_required":["ARTIFACT_ROOT"],"deterministic_seed_or_fixture_id":"self-test-v1","input_artifact":"scripts/run_observability_evidence.sh","output_artifact":"$(repo_relative "$path")","expected_behavior":"Fixture live-pass record validates successfully.","actual_behavior":"Fixture record is schema-valid and redacted.","verdict":"pass","first_failure_line":"","duration_ms":1,"git_sha_or_tree_state":"$(git_state)","blocker_bead_id":"","evidence_quality":"live"}
{"schema_version":"${SCHEMA_VERSION}","bead_id":"${BEAD_ID}","scenario_id":"observability-self-test-live-fail","subsystem":"${SUBSYSTEM}","support_class":"production_live","source_files_inspected":["conformance/src/bin/otel_metric_exporter_batching_conformance.rs"],"command":"bash scripts/run_observability_evidence.sh --self-test --fixture live-fail","rch_command_if_used":"","cargo_features":["metrics"],"test_filter":"self-test-fail","env_keys_required":[],"deterministic_seed_or_fixture_id":"self-test-v1","input_artifact":"conformance/src/bin/otel_metric_exporter_batching_conformance.rs","output_artifact":"","expected_behavior":"A fabricated failing OTel check remains represented as fail, not pass.","actual_behavior":"Fixture record intentionally records a live fail outcome.","verdict":"fail","first_failure_line":"fixture:observability-live-fail","duration_ms":1,"git_sha_or_tree_state":"$(git_state)","blocker_bead_id":"","evidence_quality":"live"}
{"schema_version":"${SCHEMA_VERSION}","bead_id":"${BEAD_ID}","scenario_id":"observability-self-test-blocked","subsystem":"${SUBSYSTEM}","support_class":"blocked_external","source_files_inspected":["conformance/src/bin/otel_resource_detection_conformance.rs"],"command":"bash scripts/run_observability_evidence.sh --scenario OTEL-RESOURCE-DETECTION-MERGE-LIVE","rch_command_if_used":"","cargo_features":["metrics"],"test_filter":"self-test-blocked","env_keys_required":["RCH_BIN"],"deterministic_seed_or_fixture_id":"self-test-v1","input_artifact":"conformance/src/bin/otel_resource_detection_conformance.rs","output_artifact":"","expected_behavior":"Blocked records carry blocker context and are not counted as production passes.","actual_behavior":"Fixture record uses blocked evidence with blocker bead context.","verdict":"blocked","first_failure_line":"fixture:blocked-before-rust-validation","duration_ms":1,"git_sha_or_tree_state":"$(git_state)","blocker_bead_id":"${BEAD_ID}","evidence_quality":"blocked"}
{"schema_version":"${SCHEMA_VERSION}","bead_id":"${BEAD_ID}","scenario_id":"observability-self-test-unsupported","subsystem":"${SUBSYSTEM}","support_class":"explicitly_unsupported","source_files_inspected":["src/observability/otlp_trace_exporter.rs"],"command":"bash scripts/run_observability_evidence.sh --scenario OTEL-TAIL-SAMPLING-UNSUPPORTED","rch_command_if_used":"","cargo_features":["metrics"],"test_filter":"self-test-unsupported","env_keys_required":[],"deterministic_seed_or_fixture_id":"self-test-v1","input_artifact":"src/observability/otlp_trace_exporter.rs","output_artifact":"","expected_behavior":"Unsupported tail-sampling evidence is explicit and cannot become a production pass.","actual_behavior":"Fixture record validates as unsupported evidence.","verdict":"unsupported","first_failure_line":"","duration_ms":1,"git_sha_or_tree_state":"$(git_state)","blocker_bead_id":"","evidence_quality":"unsupported"}
{"schema_version":"${SCHEMA_VERSION}","bead_id":"${BEAD_ID}","scenario_id":"observability-self-test-expected-fail","subsystem":"${SUBSYSTEM}","support_class":"production_live","source_files_inspected":["conformance/src/bin/otel_baggage_propagation_conformance.rs"],"command":"bash scripts/run_observability_evidence.sh --self-test --fixture expected-fail","rch_command_if_used":"","cargo_features":["metrics"],"test_filter":"self-test-expected-fail","env_keys_required":[],"deterministic_seed_or_fixture_id":"self-test-v1","input_artifact":"conformance/src/bin/otel_baggage_propagation_conformance.rs","output_artifact":"","expected_behavior":"Expected-fail records remain separated from production passes.","actual_behavior":"Fixture record validates as expected_fail evidence.","verdict":"expected_fail","first_failure_line":"fixture:known-follow-up","duration_ms":1,"git_sha_or_tree_state":"$(git_state)","blocker_bead_id":"${BEAD_ID}","evidence_quality":"expected_fail"}
{"schema_version":"${SCHEMA_VERSION}","bead_id":"${BEAD_ID}","scenario_id":"observability-self-test-fixture-only","subsystem":"${SUBSYSTEM}","support_class":"fixture_reference","source_files_inspected":["scripts/run_observability_evidence.sh"],"command":"bash scripts/run_observability_evidence.sh --self-test --fixture fixture-only","rch_command_if_used":"","cargo_features":[],"test_filter":"self-test-fixture-only","env_keys_required":[],"deterministic_seed_or_fixture_id":"observability-fixture","input_artifact":"scripts/run_observability_evidence.sh","output_artifact":"","expected_behavior":"Fixture-only records are accepted for context but never counted as production conformance.","actual_behavior":"Fixture record validates as fixture_only evidence.","verdict":"fixture_only","first_failure_line":"","duration_ms":1,"git_sha_or_tree_state":"$(git_state)","blocker_bead_id":"","evidence_quality":"fixture_only"}
EOF
}

run_self_test() {
    local root="$ARTIFACT_ROOT/self-test"
    local fixture_jsonl="$root/observability-self-test.jsonl"
    local summary_json="$root/observability-self-test.summary.json"
    local nonzero_root="$root/nonzero-child"
    local nonzero_log="$root/nonzero-child.log"
    local nonzero_summary="$nonzero_root/child/observability-evidence.summary.json"
    local child_rc
    mkdir -p "$root"
    write_self_test_fixture_jsonl "$fixture_jsonl"
    python3 "$VALIDATOR" --contract "$CONTRACT" --self-test >/dev/null
    python3 "$VALIDATOR" --contract "$CONTRACT" --jsonl "$fixture_jsonl" --summary-output "$summary_json"

    set +e
    RCH_BIN=false RCH_WRAPPER_TIMEOUT=5s bash "$0" \
        --execute \
        --scenario OTEL-HISTOGRAM-AGGREGATOR-LIVE \
        --artifact-root "$nonzero_root" \
        --run-id child \
        > "$nonzero_log" 2>&1
    child_rc=$?
    set -e
    if [[ "$child_rc" -eq 0 ]]; then
        echo "self-test expected child proof runner to exit nonzero when child validation cannot run" >&2
        exit 1
    fi
    python3 - "$nonzero_summary" <<'PY'
import json
import sys
from pathlib import Path

summary_path = Path(sys.argv[1])
summary = json.loads(summary_path.read_text(encoding="utf-8"))
records = next(iter(summary.values()))
if records.get("records") != 1 or records.get("verdicts", {}).get("fail") != 1:
    raise SystemExit(f"{summary_path}: expected exactly one fail record, got {records!r}")
PY

    echo "observability evidence runner self-test: pass"
    echo "Evidence JSONL: $(repo_relative "$fixture_jsonl")"
    echo "Summary: $(repo_relative "$summary_json")"
    echo "Nonzero child-run log: $(repo_relative "$nonzero_log")"
}

list_scenarios() {
    echo "Observability OTel/W3C proof scenarios:"
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
            local run_dir jsonl_path summary_path scenario failures=0 executed=0 non_pass=0
            run_dir="${ARTIFACT_ROOT}/${RUN_ID}"
            jsonl_path="${run_dir}/observability-evidence.jsonl"
            summary_path="${run_dir}/observability-evidence.summary.json"
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
                if [[ "$(scenario_expected_verdict "$scenario")" != "pass" ]]; then
                    non_pass=$((non_pass + 1))
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
            echo "observability evidence: $([[ "$failures" -eq 0 ]] && echo pass || echo fail)"
            echo "Scenarios: ${executed}"
            echo "Explicit non-pass evidence records: ${non_pass}"
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
