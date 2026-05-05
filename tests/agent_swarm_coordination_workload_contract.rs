#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};

const DOC_PATH: &str = "docs/agent_swarm_coordination_workload_contract.md";
const ARTIFACT_PATH: &str = "artifacts/agent_swarm_coordination_workload_contract_v1.json";
const RUNTIME_CORPUS_PATH: &str = "artifacts/runtime_workload_corpus_v1.json";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn load_doc() -> String {
    std::fs::read_to_string(repo_path(DOC_PATH)).expect("read coordination workload contract doc")
}

fn load_json(relative: &str) -> Value {
    let raw = std::fs::read_to_string(repo_path(relative)).expect("read json artifact");
    serde_json::from_str(&raw).expect("parse json artifact")
}

fn contract() -> Value {
    load_json(ARTIFACT_PATH)
}

fn string_array<'a>(value: &'a Value, key: &str) -> Vec<&'a str> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
        })
        .collect()
}

fn event_sort_tuple(event: &Value, sort_key: &[&str]) -> Vec<String> {
    sort_key
        .iter()
        .map(|field| {
            event
                .get(*field)
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("sort field {field} must be string"))
                .to_string()
        })
        .collect()
}

#[test]
fn doc_references_bead_artifact_test_and_runtime_corpus() {
    let doc = load_doc();
    for expected in [
        "asupersync-qn8i0p.1",
        ARTIFACT_PATH,
        "tests/agent_swarm_coordination_workload_contract.rs",
        "docs/runtime_workload_corpus_contract.md",
        RUNTIME_CORPUS_PATH,
        "src/runtime/scheduler/swarm_evidence.rs",
    ] {
        assert!(doc.contains(expected), "doc must reference {expected}");
    }

    for section in [
        "Purpose",
        "Contract Artifact",
        "Required Event Fields",
        "Deterministic Ordering",
        "Redaction And Refusal",
        "Runtime Workload Corpus Compatibility",
        "Validation",
        "Cross-References",
    ] {
        assert!(doc.contains(section), "doc missing section {section}");
    }

    assert!(
        doc.contains("rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_agent_swarm_coordination_contract cargo test -p asupersync --test agent_swarm_coordination_workload_contract -- --nocapture"),
        "doc must publish the focused rch validation command"
    );
}

#[test]
fn artifact_versions_and_dependency_boundary_are_stable() {
    let contract = contract();
    assert_eq!(
        contract.get("contract_version").and_then(Value::as_str),
        Some("agent-swarm-coordination-workload-contract-v1")
    );
    assert_eq!(
        contract.get("schema_version").and_then(Value::as_str),
        Some("agent-swarm-coordination-workload-bundle-v1")
    );
    assert_eq!(
        contract.get("event_schema_version").and_then(Value::as_str),
        Some("agent-swarm-coordination-event-v1")
    );
    assert_eq!(
        contract.get("bead_id").and_then(Value::as_str),
        Some("asupersync-qn8i0p.1")
    );

    let forbidden: BTreeSet<_> = string_array(
        &contract["core_runtime_dependency_policy"],
        "forbidden_core_runtime_dependencies",
    )
    .into_iter()
    .collect();
    for dependency in ["mcp_agent_mail", "agent-mail", "beads", "br", "bv", "rch"] {
        assert!(
            forbidden.contains(dependency),
            "core runtime dependency policy must forbid {dependency}"
        );
    }
}

#[test]
fn event_required_fields_match_bead_contract() {
    let contract = contract();
    let required: BTreeSet<_> = string_array(&contract["record_layout"], "event_required_fields")
        .into_iter()
        .collect();
    let expected: BTreeSet<_> = [
        "schema_version",
        "run_id",
        "source_kind",
        "source_agent",
        "source_thread_or_bead",
        "event_ts",
        "stable_sequence",
        "event_kind",
        "correlation_id",
        "command_class",
        "workload_family",
        "queue_depth_or_lock_state",
        "file_frontier",
        "artifact_refs",
        "redaction_verdict",
        "source_hash",
        "refusal_reason",
    ]
    .into_iter()
    .collect();
    assert_eq!(required, expected);
    assert_eq!(
        required.len(),
        string_array(&contract["record_layout"], "event_required_fields").len(),
        "required fields must be duplicate-free"
    );
}

#[test]
fn allowed_taxonomies_cover_sources_families_redaction_and_refusals() {
    let contract = contract();
    let allowed = &contract["allowed_values"];

    let source_kinds: BTreeSet<_> = string_array(allowed, "source_kind").into_iter().collect();
    assert_eq!(
        source_kinds,
        BTreeSet::from([
            "agent_mail",
            "artifact_store",
            "beads",
            "bv",
            "git_dirty_frontier",
            "rch",
            "unknown",
        ])
    );

    let families: BTreeSet<_> = string_array(allowed, "workload_family")
        .into_iter()
        .collect();
    assert_eq!(
        families,
        BTreeSet::from([
            "artifact_retrieval_tail",
            "concurrent_rch_proofs",
            "coordination_latency_burst",
            "fail_closed_dirty_frontier",
            "proof_runner_fanout",
            "stale_in_progress_reclaim",
            "tracker_lock_contention",
        ])
    );

    let redaction: BTreeSet<_> = string_array(allowed, "redaction_verdict")
        .into_iter()
        .collect();
    assert_eq!(
        redaction,
        BTreeSet::from(["metadata_only", "pseudonymized", "redacted", "refused"])
    );

    let refusals: BTreeSet<_> = string_array(allowed, "refusal_reason")
        .into_iter()
        .collect();
    for refusal in [
        "",
        "duplicate_event",
        "missing_required_field",
        "nondeterministic_order",
        "stale_source",
        "unknown_schema_version",
        "unredacted_secret",
        "unsupported_source_kind",
    ] {
        assert!(refusals.contains(refusal), "missing refusal {refusal}");
    }
}

#[test]
fn sample_bundles_have_required_fields_and_valid_refusal_semantics() {
    let contract = contract();
    let required = string_array(&contract["record_layout"], "event_required_fields");
    let allowed = &contract["allowed_values"];
    let allowed_sources: BTreeSet<_> = string_array(allowed, "source_kind").into_iter().collect();
    let allowed_events: BTreeSet<_> = string_array(allowed, "event_kind").into_iter().collect();
    let allowed_commands: BTreeSet<_> =
        string_array(allowed, "command_class").into_iter().collect();
    let allowed_families: BTreeSet<_> = string_array(allowed, "workload_family")
        .into_iter()
        .collect();
    let allowed_redaction: BTreeSet<_> = string_array(allowed, "redaction_verdict")
        .into_iter()
        .collect();
    let allowed_refusals: BTreeSet<_> = string_array(allowed, "refusal_reason")
        .into_iter()
        .collect();

    let mut saw_accepted = false;
    let mut saw_refused = false;
    let mut refusal_reasons = BTreeSet::new();

    for bundle in contract["sample_bundles"]
        .as_array()
        .expect("sample_bundles must be array")
    {
        for field in string_array(&contract["record_layout"], "bundle_required_fields") {
            assert!(bundle.get(field).is_some(), "sample bundle missing {field}");
        }

        let events = bundle["events"].as_array().expect("events must be array");
        assert!(
            !events.is_empty(),
            "sample bundle must carry at least one event"
        );

        for event in events {
            for field in &required {
                assert!(event.get(*field).is_some(), "sample event missing {field}");
            }

            let source_kind = event["source_kind"].as_str().expect("source_kind string");
            let event_kind = event["event_kind"].as_str().expect("event_kind string");
            let command_class = event["command_class"]
                .as_str()
                .expect("command_class string");
            let workload_family = event["workload_family"].as_str().expect("family string");
            let redaction_verdict = event["redaction_verdict"]
                .as_str()
                .expect("redaction verdict string");
            let refusal_reason = event["refusal_reason"]
                .as_str()
                .expect("refusal reason string");

            assert!(allowed_sources.contains(source_kind), "unknown source kind");
            assert!(allowed_events.contains(event_kind), "unknown event kind");
            assert!(
                allowed_commands.contains(command_class),
                "unknown command class"
            );
            assert!(
                allowed_families.contains(workload_family),
                "unknown workload family"
            );
            assert!(
                allowed_redaction.contains(redaction_verdict),
                "unknown redaction verdict"
            );
            assert!(
                allowed_refusals.contains(refusal_reason),
                "unknown refusal reason"
            );

            if refusal_reason.is_empty() {
                saw_accepted = true;
                assert_ne!(
                    redaction_verdict, "refused",
                    "accepted events cannot use refused redaction verdict"
                );
                assert_ne!(
                    source_kind, "unknown",
                    "unknown source kind is valid only for refused events"
                );
            } else {
                saw_refused = true;
                refusal_reasons.insert(refusal_reason.to_string());
                assert_eq!(
                    redaction_verdict, "refused",
                    "refused events must use refused redaction verdict"
                );
            }
        }
    }

    assert!(saw_accepted, "samples must include an accepted bundle");
    assert!(saw_refused, "samples must include refused bundles");
    assert!(refusal_reasons.contains("unsupported_source_kind"));
    assert!(refusal_reasons.contains("stale_source"));
    assert!(refusal_reasons.contains("unknown_schema_version"));
}

#[test]
fn sample_events_are_sorted_and_duplicate_policy_is_deterministic() {
    let contract = contract();
    let sort_key = string_array(&contract["record_layout"], "deterministic_sort_key");
    let dedupe_key = string_array(&contract["duplicate_policy"], "dedupe_key");
    assert_eq!(
        contract
            .pointer("/duplicate_policy/action")
            .and_then(Value::as_str),
        Some("dedupe_then_sort")
    );

    for bundle in contract["sample_bundles"]
        .as_array()
        .expect("sample_bundles must be array")
    {
        let events = bundle["events"].as_array().expect("events array");
        let tuples: Vec<Vec<String>> = events
            .iter()
            .map(|event| event_sort_tuple(event, &sort_key))
            .collect();
        let mut sorted = tuples.clone();
        sorted.sort();
        assert_eq!(
            tuples, sorted,
            "sample events must already be canonicalized"
        );

        let mut seen = HashSet::new();
        for event in events {
            let key = dedupe_key
                .iter()
                .map(|field| {
                    event
                        .get(*field)
                        .and_then(Value::as_str)
                        .unwrap_or_else(|| panic!("dedupe field {field} must be string"))
                })
                .collect::<Vec<_>>()
                .join("|");
            assert!(seen.insert(key), "sample bundle contains duplicate event");
        }
    }
}

#[test]
fn runtime_workload_corpus_compatibility_stays_optional_and_fail_closed() {
    let contract = contract();
    let runtime_corpus = load_json(RUNTIME_CORPUS_PATH);

    assert_eq!(
        contract
            .get("runtime_workload_corpus_contract")
            .and_then(Value::as_str),
        runtime_corpus
            .get("contract_version")
            .and_then(Value::as_str)
    );

    let expansion = &contract["runtime_workload_expansion_pack"];
    assert_eq!(
        expansion
            .get("baseline_denominator")
            .and_then(Value::as_bool),
        Some(false),
        "coordination packs must not change the core denominator"
    );
    assert_eq!(
        expansion.get("compatible_runner").and_then(Value::as_str),
        runtime_corpus.get("runner_script").and_then(Value::as_str)
    );

    let fail_closed: BTreeSet<_> = string_array(expansion, "fail_closed_refusal_reasons")
        .into_iter()
        .collect();
    for refusal in [
        "missing_required_field",
        "stale_source",
        "unredacted_secret",
        "unknown_schema_version",
        "unsupported_source_kind",
    ] {
        assert!(
            fail_closed.contains(refusal),
            "missing fail-closed refusal {refusal}"
        );
    }

    let runtime_core_count = runtime_corpus["default_core_set"]
        .as_array()
        .expect("runtime default_core_set")
        .len();
    assert_eq!(
        runtime_core_count, 7,
        "this contract must not mutate runtime corpus core set"
    );
}

#[test]
fn redaction_report_and_stale_policy_cover_trust_boundary_requirements() {
    let contract = contract();
    let redaction = &contract["redaction"];
    for key in [
        "forbid_message_body_retention_by_default",
        "forbid_raw_env_values",
        "forbid_raw_home_paths",
        "forbid_raw_hostnames",
        "forbid_raw_worker_names",
    ] {
        assert_eq!(
            redaction.get(key).and_then(Value::as_bool),
            Some(true),
            "redaction policy must enforce {key}"
        );
    }

    let report_required: BTreeSet<_> = string_array(redaction, "report_required_fields")
        .into_iter()
        .collect();
    for field in [
        "redacted_field_count",
        "pseudonymized_field_count",
        "metadata_only_field_count",
        "refused_event_count",
        "retained_field_summary",
    ] {
        assert!(
            report_required.contains(field),
            "missing redaction report field {field}"
        );
    }

    assert_eq!(
        contract
            .pointer("/stale_source_policy/refusal_reason")
            .and_then(Value::as_str),
        Some("stale_source")
    );
    assert_eq!(
        contract
            .pointer("/stale_source_policy/max_source_age_seconds")
            .and_then(Value::as_u64),
        Some(86_400)
    );
}
