#![allow(clippy::all)]
//! Hindsight logging and minimal nondeterminism capture contract invariants (AA-06.1).

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const DOC_PATH: &str = "docs/hindsight_logging_nondeterminism_capture_contract.md";
const ARTIFACT_PATH: &str = "artifacts/hindsight_logging_nondeterminism_capture_v1.json";
const RUNNER_SCRIPT_PATH: &str = "scripts/run_hindsight_logging_smoke.sh";
const REPLAY_MODULE_PATH: &str = "src/trace/replay.rs";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_doc() -> String {
    std::fs::read_to_string(repo_root().join(DOC_PATH))
        .expect("failed to load hindsight logging doc")
}

fn load_artifact() -> Value {
    let raw = std::fs::read_to_string(repo_root().join(ARTIFACT_PATH))
        .expect("failed to load hindsight logging artifact");
    serde_json::from_str(&raw).expect("failed to parse hindsight logging artifact")
}

fn load_replay_source() -> String {
    std::fs::read_to_string(repo_root().join(REPLAY_MODULE_PATH))
        .expect("failed to load replay module source")
}

fn source_ids(artifact: &Value) -> BTreeSet<String> {
    artifact["required_nondeterminism_sources"]
        .as_array()
        .expect("required_nondeterminism_sources must be array")
        .iter()
        .map(|s| {
            s["source_id"]
                .as_str()
                .expect("source_id must be string")
                .to_string()
        })
        .collect()
}

fn replay_event_variants(artifact: &Value) -> BTreeSet<String> {
    artifact["required_nondeterminism_sources"]
        .as_array()
        .expect("required_nondeterminism_sources must be array")
        .iter()
        .map(|s| {
            s["replay_event_variant"]
                .as_str()
                .expect("replay_event_variant must be string")
                .to_string()
        })
        .collect()
}

fn excluded_fields(artifact: &Value) -> BTreeSet<String> {
    artifact["excluded_derived_state"]
        .as_array()
        .expect("excluded_derived_state must be array")
        .iter()
        .map(|e| {
            e["field"]
                .as_str()
                .expect("field must be string")
                .to_string()
        })
        .collect()
}

// ── Doc existence and structure ──────────────────────────────────────

#[test]
fn doc_exists() {
    assert!(
        Path::new(DOC_PATH).exists(),
        "hindsight logging doc must exist"
    );
}

#[test]
fn doc_references_bead() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-1508v.6.4"),
        "doc must reference bead id"
    );
}

#[test]
fn doc_has_required_sections() {
    let doc = load_doc();
    let sections = [
        "Purpose",
        "Contract Artifacts",
        "Required Nondeterminism Sources",
        "Excluded Derived State",
        "Replay Artifact Format",
        "Structured Logging Contract",
        "Comparator-Smoke Runner",
        "Validation",
        "Cross-References",
    ];
    let mut missing = Vec::new();
    for section in sections {
        if !doc.contains(section) {
            missing.push(section);
        }
    }
    assert!(
        missing.is_empty(),
        "doc missing sections:\n{}",
        missing
            .iter()
            .map(|s| format!("  - {s}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn doc_references_artifact_runner_and_test() {
    let doc = load_doc();
    for reference in [
        "artifacts/hindsight_logging_nondeterminism_capture_v1.json",
        "scripts/run_hindsight_logging_smoke.sh",
        "tests/hindsight_logging_nondeterminism_capture_contract.rs",
        "src/trace/replay.rs",
    ] {
        assert!(doc.contains(reference), "doc must reference {reference}");
    }
}

#[test]
fn doc_reproduction_command_uses_rch() {
    let doc = load_doc();
    assert!(
        doc.contains(
            "rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa061 cargo test --test hindsight_logging_nondeterminism_capture_contract -- --nocapture"
        ),
        "doc must route heavy validation through rch"
    );
}

// ── Artifact schema and version stability ────────────────────────────

#[test]
fn artifact_versions_are_stable() {
    let artifact = load_artifact();
    assert_eq!(
        artifact["contract_version"].as_str(),
        Some("hindsight-logging-nondeterminism-capture-v1")
    );
    assert_eq!(
        artifact["runner_bundle_schema_version"].as_str(),
        Some("hindsight-logging-smoke-bundle-v1")
    );
    assert_eq!(
        artifact["runner_report_schema_version"].as_str(),
        Some("hindsight-logging-smoke-run-report-v1")
    );
    assert_eq!(
        artifact["runner_script"].as_str(),
        Some("scripts/run_hindsight_logging_smoke.sh")
    );
}

#[test]
fn replay_schema_version_matches_source() {
    let artifact = load_artifact();
    let version = artifact["replay_schema_version"]
        .as_u64()
        .expect("replay_schema_version must be integer");
    // Must match REPLAY_SCHEMA_VERSION in src/trace/replay.rs
    assert_eq!(version, 1, "replay schema version must be 1");
}

// ── Nondeterminism source catalog completeness ───────────────────────

#[test]
fn nondeterminism_source_ids_are_unique() {
    let artifact = load_artifact();
    let ids = source_ids(&artifact);
    let sources = artifact["required_nondeterminism_sources"]
        .as_array()
        .unwrap();
    assert_eq!(
        ids.len(),
        sources.len(),
        "source IDs must be unique (got {} unique out of {})",
        ids.len(),
        sources.len()
    );
}

#[test]
fn nondeterminism_source_catalog_has_expected_ids() {
    let artifact = load_artifact();
    let actual = source_ids(&artifact);
    let expected: BTreeSet<String> = [
        "ND-SCHED-TASK-SCHEDULED",
        "ND-SCHED-TASK-YIELDED",
        "ND-SCHED-TASK-COMPLETED",
        "ND-SCHED-TASK-SPAWNED",
        "ND-TIME-ADVANCED",
        "ND-TIME-TIMER-CREATED",
        "ND-TIME-TIMER-FIRED",
        "ND-TIME-TIMER-CANCELLED",
        "ND-IO-READY",
        "ND-IO-RESULT",
        "ND-IO-ERROR",
        "ND-RNG-SEED",
        "ND-RNG-VALUE",
        "ND-CHAOS-INJECTION",
        "ND-REGION-CREATED",
        "ND-REGION-CLOSED",
        "ND-REGION-CANCELLED",
        "ND-WAKER-WAKE",
        "ND-WAKER-BATCH-WAKE",
        "ND-CHECKPOINT",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();
    assert_eq!(
        actual, expected,
        "nondeterminism source catalog must remain stable"
    );
}

#[test]
fn replay_event_variants_cover_all_replay_enum_variants() {
    let artifact = load_artifact();
    let variants = replay_event_variants(&artifact);
    let source = load_replay_source();

    // Every variant referenced in the artifact must exist in the source
    for variant in &variants {
        assert!(
            source.contains(variant),
            "replay source must contain variant: {variant}"
        );
    }
}

#[test]
fn nondeterminism_categories_are_complete() {
    let artifact = load_artifact();
    let categories: BTreeSet<String> = artifact["nondeterminism_categories"]
        .as_array()
        .expect("nondeterminism_categories must be array")
        .iter()
        .map(|c| c.as_str().expect("category must be string").to_string())
        .collect();

    let expected: BTreeSet<String> = [
        "scheduling",
        "time",
        "io",
        "entropy",
        "fault_injection",
        "region_lifecycle",
        "waker_delivery",
        "checkpoint",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();

    assert_eq!(
        categories, expected,
        "nondeterminism categories must be stable"
    );
}

#[test]
fn every_source_has_a_valid_category() {
    let artifact = load_artifact();
    let categories: BTreeSet<String> = artifact["nondeterminism_categories"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_string())
        .collect();

    for source in artifact["required_nondeterminism_sources"]
        .as_array()
        .unwrap()
    {
        let sid = source["source_id"].as_str().unwrap();
        let cat = source["category"]
            .as_str()
            .expect("category must be string");
        assert!(
            categories.contains(cat),
            "source {sid} has unknown category: {cat}"
        );
    }
}

#[test]
fn every_source_has_required_fields() {
    let artifact = load_artifact();
    let required = [
        "source_id",
        "category",
        "replay_event_variant",
        "description",
        "owner_file",
        "compact_size_bytes",
        "capture_point",
    ];
    for source in artifact["required_nondeterminism_sources"]
        .as_array()
        .unwrap()
    {
        let sid = source["source_id"].as_str().unwrap_or("<missing>");
        for field in &required {
            assert!(
                source.get(*field).is_some(),
                "source {sid} missing required field: {field}"
            );
        }
    }
}

#[test]
fn owner_files_exist() {
    let artifact = load_artifact();
    let root = repo_root();
    for source in artifact["required_nondeterminism_sources"]
        .as_array()
        .unwrap()
    {
        let sid = source["source_id"].as_str().unwrap();
        let owner_file = source["owner_file"]
            .as_str()
            .expect("owner_file must be string");
        assert!(
            root.join(owner_file).exists(),
            "owner file for {sid} must exist: {owner_file}"
        );
    }
}

// ── Excluded derived state ───────────────────────────────────────────

#[test]
fn excluded_derived_state_has_expected_fields() {
    let artifact = load_artifact();
    let actual = excluded_fields(&artifact);
    let expected: BTreeSet<String> = [
        "ready_queue_len",
        "cancel_lane_len",
        "finalize_lane_len",
        "total_tasks",
        "active_regions",
        "cancel_streak_current",
        "outstanding_obligations",
        "obligation_leak_count",
        "governor_state",
        "worker_park_state",
        "blocking_pool_state",
        "timer_heap_structure",
        "calibration_scores",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();
    assert_eq!(
        actual, expected,
        "excluded derived state catalog must remain stable"
    );
}

#[test]
fn excluded_fields_have_derivation_source() {
    let artifact = load_artifact();
    for entry in artifact["excluded_derived_state"].as_array().unwrap() {
        let field = entry["field"].as_str().unwrap();
        let derivation = entry["derivation_source"]
            .as_str()
            .expect("derivation_source must be string");
        assert!(
            !derivation.is_empty(),
            "excluded field {field} must have non-empty derivation_source"
        );
        let reason = entry["reason"].as_str().expect("reason must be string");
        assert!(
            !reason.is_empty(),
            "excluded field {field} must have non-empty reason"
        );
    }
}

// ── Size budget ──────────────────────────────────────────────────────

#[test]
fn size_budget_is_reasonable() {
    let artifact = load_artifact();
    let budget = &artifact["size_budget"];
    let max = budget["max_event_bytes"]
        .as_u64()
        .expect("max_event_bytes must be integer");
    let typical = budget["typical_event_bytes"]
        .as_u64()
        .expect("typical_event_bytes must be integer");
    let overhead = budget["overhead_budget_fraction"]
        .as_f64()
        .expect("overhead_budget_fraction must be number");

    assert!(max <= 64, "max event bytes must be <= 64; got {max}");
    assert!(typical <= max, "typical must be <= max");
    assert!(
        (0.0..=1.0).contains(&overhead),
        "overhead fraction must be in [0,1]; got {overhead}"
    );
}

#[test]
fn all_source_sizes_are_within_budget() {
    let artifact = load_artifact();
    let max_bytes = artifact["size_budget"]["max_event_bytes"].as_u64().unwrap();

    for source in artifact["required_nondeterminism_sources"]
        .as_array()
        .unwrap()
    {
        let sid = source["source_id"].as_str().unwrap();
        let size = source["compact_size_bytes"]
            .as_u64()
            .expect("compact_size_bytes must be integer");
        assert!(
            size <= max_bytes,
            "source {sid} size {size} exceeds budget {max_bytes}"
        );
    }
}

// ── Replay format ────────────────────────────────────────────────────

#[test]
fn replay_format_roundtrips() {
    use asupersync::trace::replay::{ReplayEvent, ReplayTrace, TraceMetadata};

    let metadata = TraceMetadata::new(42).with_config_hash(0xDEAD);
    let mut trace = ReplayTrace::new(metadata);
    trace.push(ReplayEvent::RngSeed { seed: 42 });
    trace.push(ReplayEvent::TaskScheduled {
        task: asupersync::types::TaskId::testing_default().into(),
        at_tick: 0,
    });
    trace.push(ReplayEvent::Checkpoint {
        sequence: 1,
        time_nanos: 100,
        active_tasks: 1,
        active_regions: 1,
    });

    let bytes = trace.to_bytes().expect("serialize replay trace");
    let loaded = ReplayTrace::from_bytes(&bytes).expect("deserialize replay trace");
    assert_eq!(loaded.metadata.seed, 42);
    assert_eq!(loaded.metadata.config_hash, 0xDEAD);
    assert_eq!(loaded.events.len(), 3);
}

#[test]
fn replay_metadata_compatibility_check() {
    use asupersync::trace::replay::TraceMetadata;

    let meta = TraceMetadata::new(0);
    assert!(meta.is_compatible(), "current version must be compatible");
}

// ── Structured logging fields ────────────────────────────────────────

#[test]
fn structured_log_fields_are_unique_and_nonempty() {
    let artifact = load_artifact();
    let fields = artifact["structured_log_fields_required"]
        .as_array()
        .expect("structured_log_fields_required must be array");

    assert!(
        !fields.is_empty(),
        "structured_log_fields_required must not be empty"
    );

    let mut set = BTreeSet::new();
    for field in fields {
        let field = field
            .as_str()
            .expect("structured log field must be string")
            .to_string();
        assert!(!field.is_empty(), "structured log field must not be empty");
        assert!(
            set.insert(field.clone()),
            "duplicate structured log field: {field}"
        );
    }
}

#[test]
fn replay_status_values_are_stable() {
    let artifact = load_artifact();
    let statuses: BTreeSet<String> = artifact["replay_status_values"]
        .as_array()
        .expect("replay_status_values must be array")
        .iter()
        .map(|s| s.as_str().expect("status must be string").to_string())
        .collect();

    let expected: BTreeSet<String> = ["success", "diverged", "incomplete", "schema_mismatch"]
        .into_iter()
        .map(ToOwned::to_owned)
        .collect();

    assert_eq!(statuses, expected, "replay status values must be stable");
}

// ── Smoke runner and scenarios ───────────────────────────────────────

#[test]
fn smoke_scenarios_are_rch_routed() {
    let artifact = load_artifact();
    let scenarios = artifact["smoke_scenarios"]
        .as_array()
        .expect("smoke_scenarios must be array");
    assert!(
        !scenarios.is_empty(),
        "contract must define at least one smoke scenario"
    );

    for scenario in scenarios {
        let sid = scenario["scenario_id"]
            .as_str()
            .expect("scenario_id must be string");
        let command = scenario["command"]
            .as_str()
            .expect("scenario command must be string");
        assert!(
            command.contains("rch exec --"),
            "scenario {sid} command must use rch: {command}"
        );
    }
}

#[test]
fn runner_script_exists_and_declares_modes() {
    let root = repo_root();
    let script_path = root.join(RUNNER_SCRIPT_PATH);
    assert!(
        script_path.exists(),
        "runner script must exist: {}",
        script_path.display()
    );

    let script = std::fs::read_to_string(&script_path)
        .expect("failed to read hindsight logging smoke runner script");
    for token in [
        "--list",
        "--scenario",
        "--dry-run",
        "--execute",
        "hindsight-logging-smoke-bundle-v1",
        "hindsight-logging-smoke-run-report-v1",
    ] {
        assert!(
            script.contains(token),
            "runner script missing token: {token}"
        );
    }
}

// ── Downstream bead references ───────────────────────────────────────

#[test]
fn downstream_beads_stay_in_aa_track_namespace() {
    let artifact = load_artifact();
    for bead in artifact["downstream_beads"]
        .as_array()
        .expect("downstream_beads must be array")
    {
        let bead = bead.as_str().expect("downstream bead must be string");
        assert!(
            bead.starts_with("asupersync-1508v."),
            "downstream bead must stay in AA namespace: {bead}"
        );
    }
}
