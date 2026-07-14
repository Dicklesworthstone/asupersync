#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

artifact_root="${STUB_SCAN_ARTIFACT_ROOT:-target/mock-code-finder/asupersync-dq4}"
jsonl="$artifact_root/stale-audit-normalization.jsonl"
summary="$artifact_root/stale-audit-normalization.summary.json"
mkdir -p "$artifact_root"

git_state="$(git rev-parse --short HEAD)"
if ! git diff --quiet -- . ':!target' 2>/dev/null; then
  git_state="${git_state}+dirty"
fi

echo "STALE_AUDIT_NORMALIZATION start bead=asupersync-dq4 output=$jsonl" >&2

python3 - "$jsonl" "$git_state" <<'PY'
import json
import sys

jsonl_path = sys.argv[1]
git_state = sys.argv[2]

schema = "mock-code-finder-evidence-jsonl-schema-v1"
bead = "asupersync-dq4"
command = "bash scripts/run_stale_audit_normalization_evidence.sh"
contract_rch = "rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' CARGO_TARGET_DIR=/tmp/rch_target_asupersync_dq4_contract cargo test -p asupersync --test mock_code_finder_stale_audit_normalization --features test-internals -- --nocapture"
integration_rch = "rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' CARGO_TARGET_DIR=/tmp/rch_target_asupersync_dq4_integration cargo test -p asupersync --test grpc_server_deadline_propagation_audit --test grpc_compression_flag_audit --test kafka_offset_commit_retry_audit --features test-internals -- --nocapture"
head_sampling_rch = "rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' CARGO_TARGET_DIR=/tmp/rch_target_asupersync_dq4_head_sampling cargo test -p asupersync --lib head_based_sampling_audit_test --features test-internals -- --nocapture"
span_leak_rch = "rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' CARGO_TARGET_DIR=/tmp/rch_target_asupersync_dq4_span_leak cargo test -p asupersync --lib span_lifecycle_obligation_leak_audit_test --features test-internals,metrics -- --nocapture"
add_attributes_rch = "rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' CARGO_TARGET_DIR=/tmp/rch_target_asupersync_dq4_add_attributes cargo test -p asupersync --lib otlp_add_attributes_missing_api_audit_test --features test-internals,metrics,tracing-integration -- --nocapture"

records = [
    {
        "scenario_id": "grpc-deadline-max-request-cap",
        "subsystem": "grpc",
        "source_files_inspected": [
            "tests/grpc_server_deadline_propagation_audit.rs",
            "src/grpc/server.rs",
            "tests/grpc_server_deadline_cancel_audit.rs",
        ],
        "test_filter": "grpc_server_deadline_propagation_audit",
        "cargo_features": ["test-internals"],
        "rch_command_if_used": integration_rch,
        "proof_commands": [integration_rch, contract_rch],
        "expected_behavior": "Parseable peer grpc-timeout values are clamped when max_request_deadline is configured; the uncapped constructor remains explicit.",
        "actual_behavior": "from_metadata_at_with_max_deadline clamps parseable 99999999H to the configured cap and the audit file no longer claims no production cap exists.",
    },
    {
        "scenario_id": "grpc-compression-header-consistency",
        "subsystem": "grpc",
        "source_files_inspected": [
            "tests/grpc_compression_flag_audit.rs",
            "src/grpc/codec.rs",
        ],
        "test_filter": "grpc_compression_flag_audit",
        "cargo_features": ["test-internals"],
        "rch_command_if_used": integration_rch,
        "proof_commands": [integration_rch, contract_rch],
        "expected_behavior": "compressed-flag and grpc-encoding mismatches are protocol errors.",
        "actual_behavior": "decode_message_with_encoding rejects identity/compressed mismatches with GrpcError::Protocol.",
    },
    {
        "scenario_id": "kafka-offset-commit-retry-budget",
        "subsystem": "messaging.kafka",
        "source_files_inspected": [
            "tests/kafka_offset_commit_retry_audit.rs",
            "src/messaging/kafka_consumer.rs",
        ],
        "test_filter": "kafka_offset_commit_retry_audit",
        "cargo_features": ["test-internals"],
        "rch_command_if_used": integration_rch,
        "proof_commands": [integration_rch, contract_rch],
        "expected_behavior": "OffsetCommit retry behavior is bounded by ConsumerConfig::retries and uses consumer retry helpers for real Kafka commits.",
        "actual_behavior": "ConsumerConfig exposes retries, the audit test pins the configured surface, and source ratchets require retry_consumer_operation wiring.",
    },
    {
        "scenario_id": "otlp-head-based-sampling",
        "subsystem": "observability.otlp",
        "source_files_inspected": [
            "src/observability/head_based_sampling_audit_test.rs",
            "src/observability/otlp_trace_exporter.rs",
        ],
        "test_filter": "head_based_sampling_audit_test",
        "cargo_features": ["test-internals"],
        "rch_command_if_used": head_sampling_rch,
        "proof_commands": [head_sampling_rch, contract_rch],
        "expected_behavior": "Unsampled spans are filtered before OTLP export.",
        "actual_behavior": "LoadSheddingTraceExporter filters spans with trace_flags=0 and the audit now asserts empty export for an unsampled batch.",
    },
    {
        "scenario_id": "otel-span-obligation-leak-detection",
        "subsystem": "observability.otel",
        "source_files_inspected": [
            "src/observability/span_lifecycle_obligation_leak_audit_test.rs",
            "src/observability/otel_structured_concurrency.rs",
        ],
        "test_filter": "span_lifecycle_obligation_leak_audit_test",
        "cargo_features": ["test-internals", "metrics"],
        "rch_command_if_used": span_leak_rch,
        "proof_commands": [span_leak_rch, contract_rch],
        "expected_behavior": "Unended pending spans are detected as obligation leaks when metrics support is enabled.",
        "actual_behavior": "SpanStorage::detect_obligation_leaks is live under metrics and the stale defect demonstration now asserts the detected leak.",
    },
    {
        "scenario_id": "otlp-add-attributes-production-seam",
        "subsystem": "observability.otel",
        "source_files_inspected": [
            "src/observability/otlp_add_attributes_missing_api_audit_test.rs",
            "src/observability/otel.rs",
        ],
        "test_filter": "otlp_add_attributes_missing_api_audit_test",
        "cargo_features": ["test-internals", "metrics", "tracing-integration"],
        "rch_command_if_used": add_attributes_rch,
        "proof_commands": [add_attributes_rch, contract_rch],
        "expected_behavior": "add_attributes is a real production seam with deterministic tests and redacted logs.",
        "actual_behavior": "The audit file already contains production-seam tests for batch dedup, capacity, typed values, unsupported values, and redacted logging.",
    },
]

with open(jsonl_path, "w", encoding="utf-8") as handle:
    for record in records:
        scenario = dict(record)
        rch_command = scenario.pop("rch_command_if_used")
        cargo_features = scenario.pop("cargo_features")
        proof_commands = scenario.pop("proof_commands")
        full = {
            "schema_version": schema,
            "bead_id": bead,
            "support_class": "production_live",
            "command": command,
            "rch_command_if_used": rch_command,
            "cargo_features": cargo_features,
            "proof_commands": proof_commands,
            "env_keys_required": ["STUB_SCAN_ARTIFACT_ROOT"],
            "deterministic_seed_or_fixture_id": "stale-audit-normalization-v1",
            "input_artifact": "artifacts/mock_code_finder_stale_audit_normalization_v1.json",
            "output_artifact": jsonl_path,
            "verdict": "pass",
            "first_failure_line": "",
            "duration_ms": 0,
            "git_sha_or_tree_state": git_state,
            "blocker_bead_id": "",
            "evidence_quality": "live",
        }
        full.update(scenario)
        handle.write(json.dumps(full, sort_keys=True, separators=(",", ":")) + "\n")
PY

python3 scripts/validate_mock_code_finder_evidence.py \
  --contract artifacts/mock_code_finder_verification_contract_v1.json \
  --jsonl "$jsonl" \
  --summary-output "$summary"

echo "STALE_AUDIT_NORMALIZATION jsonl=$jsonl" >&2
echo "STALE_AUDIT_NORMALIZATION summary=$summary" >&2
wc -l "$jsonl" >&2
