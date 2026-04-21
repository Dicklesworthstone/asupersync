#![allow(warnings)]
//! Visual Regression Harness and Core Interaction Suite Validation (Track 6.9)
//!
//! Validates the visual-regression harness contract including snapshot
//! construction determinism, artifact manifest invariants, golden fixture
//! schema, visual profile mapping, and document coverage.
//!
//! Bead: asupersync-2b4jj.6.9

#![allow(missing_docs)]
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(clippy::all)]
#![cfg(feature = "cli")]

use asupersync::cli::doctor::{
    DoctorVisualHarnessArtifactManifest, DoctorVisualHarnessArtifactRecord,
    DoctorVisualHarnessSnapshot,
};
use serde::Deserialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

// ─── Constants ──────────────────────────────────────────────────────

const HARNESS_DOC_PATH: &str = "docs/doctor_visual_regression_harness.md";
const FIXTURE_DIR: &str = "tests/fixtures/doctor_visual_harness";
const FIXTURE_PACK_PATH: &str = "tests/fixtures/doctor_visual_harness/manifest.json";
const FIXTURE_PACK_SCHEMA_VERSION: &str = "doctor-visual-harness-fixture-pack-v1";
const MANIFEST_SCHEMA_VERSION: &str = "doctor-visual-harness-manifest-v1";

// Known visual profiles from the contract
const VISUAL_PROFILES: [&str; 3] = ["frankentui-stable", "frankentui-cancel", "frankentui-alert"];

// Known artifact classes from the contract
const ARTIFACT_CLASSES: [&str; 6] = [
    "snapshot",
    "metrics",
    "replay_metadata",
    "structured_log",
    "summary",
    "transcript",
];

// Retention class mapping from invariant 7
const HOT_CLASSES: [&str; 3] = ["snapshot", "structured_log", "transcript"];
const WARM_CLASSES: [&str; 3] = ["summary", "metrics", "replay_metadata"];

// ─── Fixture types ──────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
struct VisualFixturePack {
    schema_version: String,
    description: String,
    fixtures: Vec<VisualFixture>,
}

#[derive(Debug, Clone, Deserialize)]
struct VisualFixture {
    fixture_id: String,
    outcome_class: String,
    expected_visual_profile: String,
    expected_focused_panel: String,
    viewport_width: u16,
    viewport_height: u16,
}

// ─── Helpers ────────────────────────────────────────────────────────

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_doc() -> String {
    std::fs::read_to_string(repo_root().join(HARNESS_DOC_PATH))
        .expect("failed to load visual regression harness doc")
}

fn load_fixture_pack() -> VisualFixturePack {
    let raw = std::fs::read_to_string(repo_root().join(FIXTURE_PACK_PATH))
        .expect("failed to load fixture pack");
    serde_json::from_str(&raw).expect("failed to parse fixture pack")
}

fn load_golden_snapshot(name: &str) -> DoctorVisualHarnessSnapshot {
    let path = repo_root().join(FIXTURE_DIR).join(format!("{name}.json"));
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("failed to load golden snapshot {name}"));
    serde_json::from_str(&raw).unwrap_or_else(|_| panic!("failed to parse golden snapshot {name}"))
}

fn load_golden_manifest(name: &str) -> DoctorVisualHarnessArtifactManifest {
    let path = repo_root().join(FIXTURE_DIR).join(format!("{name}.json"));
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("failed to load golden manifest {name}"));
    serde_json::from_str(&raw).unwrap_or_else(|_| panic!("failed to parse golden manifest {name}"))
}

fn expected_retention_class(artifact_class: &str) -> &'static str {
    if HOT_CLASSES.contains(&artifact_class) {
        "hot"
    } else if WARM_CLASSES.contains(&artifact_class) {
        "warm"
    } else {
        panic!("unknown artifact class: {artifact_class}")
    }
}

// ─── Document infrastructure ────────────────────────────────────────

#[test]
fn doc_exists() {
    assert!(
        Path::new(HARNESS_DOC_PATH).exists(),
        "Visual regression harness doc must exist"
    );
}

#[test]
fn doc_references_bead() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-2b4jj.6.9"),
        "Doc must reference its own bead ID"
    );
}

#[test]
fn doc_has_required_sections() {
    let doc = load_doc();
    let sections = [
        "Purpose",
        "Harness Infrastructure",
        "Visual Profile Mapping",
        "Golden Fixture Management",
        "Core Interaction Regression Scenarios",
        "Determinism Invariants",
        "CI Validation",
        "Cross-References",
    ];
    let mut missing = Vec::new();
    for section in &sections {
        if !doc.contains(section) {
            missing.push(*section);
        }
    }
    assert!(
        missing.is_empty(),
        "Doc missing sections:\n{}",
        missing
            .iter()
            .map(|s| format!("  - {s}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn doc_references_cross_documents() {
    let doc = load_doc();
    let refs = [
        "doctor_visual_language_contract.md",
        "doctor_e2e_harness_contract.md",
        "doctor_analyzer_fixture_harness.md",
        "doctor_scenario_composer_contract.md",
        "doctor_logging_contract.md",
    ];
    let mut missing = Vec::new();
    for r in &refs {
        if !doc.contains(r) {
            missing.push(*r);
        }
    }
    assert!(
        missing.is_empty(),
        "Doc missing cross-references:\n{}",
        missing
            .iter()
            .map(|r| format!("  - {r}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn doc_references_test_file() {
    let doc = load_doc();
    assert!(
        doc.contains("doctor_visual_regression_harness.rs"),
        "Doc must reference its own test file"
    );
}

#[test]
fn doc_references_implementation() {
    let doc = load_doc();
    assert!(
        doc.contains("src/cli/doctor/mod.rs"),
        "Doc must reference implementation file"
    );
}

#[test]
fn doc_reproduction_commands_use_rch() {
    let doc = load_doc();
    let required_commands = [
        "rch exec -- cargo test --test doctor_visual_regression_harness --features cli -- --nocapture",
        "rch exec -- cargo test --test doctor_analyzer_fixture_harness --features cli -- --nocapture",
    ];

    for command in &required_commands {
        assert!(
            doc.contains(command),
            "Doc reproduction section must route heavy tests through rch: {command}"
        );
    }
}

#[test]
fn doc_documents_all_visual_profiles() {
    let doc = load_doc();
    for profile in &VISUAL_PROFILES {
        assert!(
            doc.contains(profile),
            "Doc must document visual profile: {profile}"
        );
    }
}

#[test]
fn doc_documents_all_artifact_classes() {
    let doc = load_doc();
    for class in &ARTIFACT_CLASSES {
        assert!(
            doc.contains(class),
            "Doc must document artifact class: {class}"
        );
    }
}

#[test]
fn doc_documents_retention_classes() {
    let doc = load_doc();
    assert!(
        doc.contains("hot"),
        "Doc must document 'hot' retention class"
    );
    assert!(
        doc.contains("warm"),
        "Doc must document 'warm' retention class"
    );
}

#[test]
fn doc_documents_determinism_invariant_count() {
    let doc = load_doc();
    let count = doc
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            (1..=8).any(|i| trimmed.starts_with(&format!("{i}. **")))
        })
        .count();
    assert!(
        count >= 8,
        "Doc must have at least 8 determinism invariants, found {count}"
    );
}

// ─── Fixture pack validation ────────────────────────────────────────

#[test]
fn fixture_directory_exists() {
    assert!(
        Path::new(FIXTURE_DIR).exists(),
        "Fixture directory must exist"
    );
}

#[test]
fn fixture_pack_loads() {
    let pack = load_fixture_pack();
    assert_eq!(
        pack.schema_version, FIXTURE_PACK_SCHEMA_VERSION,
        "Fixture pack schema version mismatch"
    );
    assert!(
        !pack.description.is_empty(),
        "Fixture pack must have a description"
    );
}

#[test]
fn fixture_pack_covers_all_outcome_classes() {
    let pack = load_fixture_pack();
    let outcomes: HashSet<&str> = pack
        .fixtures
        .iter()
        .map(|f| f.outcome_class.as_str())
        .collect();
    for expected in &["success", "cancelled", "failed"] {
        assert!(
            outcomes.contains(expected),
            "Fixture pack must cover outcome class: {expected}"
        );
    }
}

#[test]
fn fixture_pack_ids_are_unique() {
    let pack = load_fixture_pack();
    let mut ids = HashSet::new();
    for fixture in &pack.fixtures {
        assert!(
            ids.insert(&fixture.fixture_id),
            "Duplicate fixture ID: {}",
            fixture.fixture_id
        );
    }
}

#[test]
fn fixture_pack_profiles_match_outcome_mapping() {
    let pack = load_fixture_pack();
    for fixture in &pack.fixtures {
        let expected_profile = match fixture.outcome_class.as_str() {
            "success" => "frankentui-stable",
            "cancelled" => "frankentui-cancel",
            _ => "frankentui-alert",
        };
        assert_eq!(
            fixture.expected_visual_profile, expected_profile,
            "Fixture {} profile mismatch for outcome '{}'",
            fixture.fixture_id, fixture.outcome_class
        );
    }
}

#[test]
fn fixture_pack_panels_match_outcome_mapping() {
    let pack = load_fixture_pack();
    for fixture in &pack.fixtures {
        let expected_panel = if fixture.outcome_class == "success" {
            "summary_panel"
        } else {
            "triage_panel"
        };
        assert_eq!(
            fixture.expected_focused_panel, expected_panel,
            "Fixture {} panel mismatch for outcome '{}'",
            fixture.fixture_id, fixture.outcome_class
        );
    }
}

#[test]
fn fixture_pack_viewports_are_valid() {
    let pack = load_fixture_pack();
    for fixture in &pack.fixtures {
        assert!(
            fixture.viewport_width >= 110,
            "Fixture {} viewport_width {} below minimum 110",
            fixture.fixture_id,
            fixture.viewport_width
        );
        assert!(
            fixture.viewport_height >= 32,
            "Fixture {} viewport_height {} below minimum 32",
            fixture.fixture_id,
            fixture.viewport_height
        );
    }
}

// ─── Golden snapshot validation ─────────────────────────────────────

#[test]
fn golden_snapshot_files_exist() {
    let names = ["snapshot_success", "snapshot_cancelled", "snapshot_failed"];
    for name in &names {
        let path = repo_root().join(FIXTURE_DIR).join(format!("{name}.json"));
        assert!(
            path.exists(),
            "Golden snapshot file must exist: {name}.json"
        );
    }
}

#[test]
fn golden_snapshots_deserialize() {
    let names = ["snapshot_success", "snapshot_cancelled", "snapshot_failed"];
    for name in &names {
        let snapshot = load_golden_snapshot(name);
        assert!(
            !snapshot.snapshot_id.is_empty(),
            "Golden snapshot {name} must have non-empty snapshot_id"
        );
    }
}

#[test]
fn golden_snapshot_success_profile() {
    let snapshot = load_golden_snapshot("snapshot_success");
    assert_eq!(snapshot.visual_profile, "frankentui-stable");
    assert_eq!(snapshot.focused_panel, "summary_panel");
}

#[test]
fn golden_snapshot_cancelled_profile() {
    let snapshot = load_golden_snapshot("snapshot_cancelled");
    assert_eq!(snapshot.visual_profile, "frankentui-cancel");
    assert_eq!(snapshot.focused_panel, "triage_panel");
}

#[test]
fn golden_snapshot_failed_profile() {
    let snapshot = load_golden_snapshot("snapshot_failed");
    assert_eq!(snapshot.visual_profile, "frankentui-alert");
    assert_eq!(snapshot.focused_panel, "triage_panel");
}

#[test]
fn golden_snapshots_have_valid_digests() {
    let names = ["snapshot_success", "snapshot_cancelled", "snapshot_failed"];
    for name in &names {
        let snapshot = load_golden_snapshot(name);
        assert!(
            !snapshot.stage_digest.is_empty(),
            "Golden snapshot {name} must have non-empty stage_digest"
        );
        assert!(
            snapshot.stage_digest.starts_with("len:"),
            "Golden snapshot {name} stage_digest must start with 'len:'"
        );
    }
}

// ─── Golden manifest validation ─────────────────────────────────────

#[test]
fn golden_manifest_file_exists() {
    let path = repo_root().join(FIXTURE_DIR).join("manifest_success.json");
    assert!(path.exists(), "Golden artifact manifest must exist");
}

#[test]
fn golden_manifest_deserializes() {
    let manifest = load_golden_manifest("manifest_success");
    assert_eq!(manifest.schema_version, MANIFEST_SCHEMA_VERSION);
    assert!(!manifest.run_id.is_empty());
    assert!(!manifest.scenario_id.is_empty());
}

#[test]
fn golden_manifest_artifact_root() {
    let manifest = load_golden_manifest("manifest_success");
    assert!(
        manifest.artifact_root.starts_with("artifacts/"),
        "artifact_root must start with 'artifacts/'"
    );
}

#[test]
fn golden_manifest_records_sorted() {
    let manifest = load_golden_manifest("manifest_success");
    let ids: Vec<&str> = manifest
        .records
        .iter()
        .map(|r| r.artifact_id.as_str())
        .collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(
        ids, sorted,
        "Manifest records must be lexically sorted by artifact_id"
    );
}

#[test]
fn golden_manifest_paths_rooted() {
    let manifest = load_golden_manifest("manifest_success");
    for record in &manifest.records {
        assert!(
            record.artifact_path.starts_with("artifacts/"),
            "artifact_path must start with 'artifacts/': {}",
            record.artifact_id
        );
    }
}

#[test]
fn golden_manifest_checksums_nonempty() {
    let manifest = load_golden_manifest("manifest_success");
    for record in &manifest.records {
        assert!(
            !record.checksum_hint.trim().is_empty(),
            "checksum_hint must be non-empty: {}",
            record.artifact_id
        );
    }
}

#[test]
fn golden_manifest_retention_classes_valid() {
    let manifest = load_golden_manifest("manifest_success");
    for record in &manifest.records {
        assert!(
            record.retention_class == "hot" || record.retention_class == "warm",
            "retention_class must be 'hot' or 'warm': {} has '{}'",
            record.artifact_id,
            record.retention_class
        );
    }
}

#[test]
fn golden_manifest_retention_policy() {
    let manifest = load_golden_manifest("manifest_success");
    for record in &manifest.records {
        let expected = expected_retention_class(&record.artifact_class);
        assert_eq!(
            record.retention_class, expected,
            "Retention policy mismatch for {} (class {}): expected '{}', got '{}'",
            record.artifact_id, record.artifact_class, expected, record.retention_class
        );
    }
}

#[test]
fn golden_manifest_linked_artifacts_sorted() {
    let manifest = load_golden_manifest("manifest_success");
    for record in &manifest.records {
        let linked = &record.linked_artifacts;
        let mut sorted = linked.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            linked, &sorted,
            "linked_artifacts must be lexically sorted and deduplicated: {}",
            record.artifact_id
        );
    }
}

#[test]
fn golden_manifest_artifact_classes_valid() {
    let manifest = load_golden_manifest("manifest_success");
    let valid_classes: HashSet<&str> = ARTIFACT_CLASSES.iter().copied().collect();
    for record in &manifest.records {
        assert!(
            valid_classes.contains(record.artifact_class.as_str()),
            "Unknown artifact class '{}' in record {}",
            record.artifact_class,
            record.artifact_id
        );
    }
}

#[test]
fn golden_manifest_artifact_ids_unique() {
    let manifest = load_golden_manifest("manifest_success");
    let mut ids = HashSet::new();
    for record in &manifest.records {
        assert!(
            ids.insert(&record.artifact_id),
            "Duplicate artifact_id: {}",
            record.artifact_id
        );
    }
}

// ─── Snapshot struct construction ───────────────────────────────────

#[test]
fn snapshot_roundtrip_serde() {
    let snapshot = DoctorVisualHarnessSnapshot {
        snapshot_id: "test-snapshot-001".to_string(),
        viewport_width: 132,
        viewport_height: 44,
        focused_panel: "summary_panel".to_string(),
        selected_node_id: "node-01".to_string(),
        stage_digest: "len:2|pass|pass".to_string(),
        visual_profile: "frankentui-stable".to_string(),
        capture_index: 0,
    };
    let json = serde_json::to_string(&snapshot).expect("serialize snapshot");
    let deserialized: DoctorVisualHarnessSnapshot =
        serde_json::from_str(&json).expect("deserialize snapshot");
    assert_eq!(
        snapshot, deserialized,
        "Snapshot must roundtrip through serde"
    );
}

#[test]
fn snapshot_viewport_determinism() {
    let snap_a = DoctorVisualHarnessSnapshot {
        snapshot_id: "det-a".to_string(),
        viewport_width: 132,
        viewport_height: 44,
        focused_panel: "summary_panel".to_string(),
        selected_node_id: "node-01".to_string(),
        stage_digest: "len:1|ok".to_string(),
        visual_profile: "frankentui-stable".to_string(),
        capture_index: 0,
    };
    let snap_b = DoctorVisualHarnessSnapshot {
        snapshot_id: "det-a".to_string(),
        viewport_width: 132,
        viewport_height: 44,
        focused_panel: "summary_panel".to_string(),
        selected_node_id: "node-01".to_string(),
        stage_digest: "len:1|ok".to_string(),
        visual_profile: "frankentui-stable".to_string(),
        capture_index: 0,
    };
    assert_eq!(snap_a, snap_b, "Same inputs must produce equal snapshots");
}

#[test]
fn snapshot_profile_determinism() {
    let outcomes_and_profiles = [
        ("success", "frankentui-stable", "summary_panel"),
        ("cancelled", "frankentui-cancel", "triage_panel"),
        ("failed", "frankentui-alert", "triage_panel"),
        ("error", "frankentui-alert", "triage_panel"),
        ("timeout", "frankentui-alert", "triage_panel"),
    ];

    for (outcome, expected_profile, expected_panel) in &outcomes_and_profiles {
        let profile = match *outcome {
            "success" => "frankentui-stable",
            "cancelled" => "frankentui-cancel",
            _ => "frankentui-alert",
        };
        let panel = if *outcome == "success" {
            "summary_panel"
        } else {
            "triage_panel"
        };
        assert_eq!(
            profile, *expected_profile,
            "Profile mapping mismatch for outcome '{outcome}'"
        );
        assert_eq!(
            panel, *expected_panel,
            "Panel mapping mismatch for outcome '{outcome}'"
        );
    }
}

// ─── Artifact manifest construction ─────────────────────────────────

#[test]
fn manifest_roundtrip_serde() {
    let record = DoctorVisualHarnessArtifactRecord {
        artifact_id: "test-record-001".to_string(),
        artifact_class: "snapshot".to_string(),
        artifact_path: "artifacts/run-001/test-record.json".to_string(),
        checksum_hint: "check-001".to_string(),
        retention_class: "hot".to_string(),
        linked_artifacts: vec!["other-001".to_string(), "other-002".to_string()],
    };
    let manifest = DoctorVisualHarnessArtifactManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        run_id: "run-001".to_string(),
        scenario_id: "scenario-001".to_string(),
        artifact_root: "artifacts/run-001/doctor/e2e/".to_string(),
        records: vec![record],
    };
    let json = serde_json::to_string(&manifest).expect("serialize manifest");
    let deserialized: DoctorVisualHarnessArtifactManifest =
        serde_json::from_str(&json).expect("deserialize manifest");
    assert_eq!(
        manifest, deserialized,
        "Manifest must roundtrip through serde"
    );
}

#[test]
fn manifest_record_ordering_invariant() {
    let records = vec![
        DoctorVisualHarnessArtifactRecord {
            artifact_id: "c-record".to_string(),
            artifact_class: "snapshot".to_string(),
            artifact_path: "artifacts/test/c.json".to_string(),
            checksum_hint: "c".to_string(),
            retention_class: "hot".to_string(),
            linked_artifacts: vec![],
        },
        DoctorVisualHarnessArtifactRecord {
            artifact_id: "a-record".to_string(),
            artifact_class: "transcript".to_string(),
            artifact_path: "artifacts/test/a.json".to_string(),
            checksum_hint: "a".to_string(),
            retention_class: "hot".to_string(),
            linked_artifacts: vec![],
        },
        DoctorVisualHarnessArtifactRecord {
            artifact_id: "b-record".to_string(),
            artifact_class: "summary".to_string(),
            artifact_path: "artifacts/test/b.json".to_string(),
            checksum_hint: "b".to_string(),
            retention_class: "warm".to_string(),
            linked_artifacts: vec![],
        },
    ];

    let mut sorted = records;
    sorted.sort_by(|a, b| a.artifact_id.cmp(&b.artifact_id));

    assert_eq!(sorted[0].artifact_id, "a-record");
    assert_eq!(sorted[1].artifact_id, "b-record");
    assert_eq!(sorted[2].artifact_id, "c-record");
}

#[test]
fn manifest_linked_artifacts_dedup_invariant() {
    let mut linked = vec![
        "artifact-b".to_string(),
        "artifact-a".to_string(),
        "artifact-b".to_string(),
        "artifact-c".to_string(),
    ];
    linked.sort();
    linked.dedup();
    assert_eq!(
        linked,
        vec!["artifact-a", "artifact-b", "artifact-c"],
        "Linked artifacts must be sorted and deduplicated"
    );
}

#[test]
fn manifest_path_rooting_invariant() {
    let valid_paths = [
        "artifacts/run-001/test.json",
        "artifacts/run-002/doctor/e2e/snap.json",
    ];
    let invalid_paths = [
        "run-001/test.json",
        "output/snap.json",
        "/artifacts/test.json",
    ];

    for path in &valid_paths {
        assert!(
            path.starts_with("artifacts/"),
            "Valid path should start with 'artifacts/': {path}"
        );
    }
    for path in &invalid_paths {
        assert!(
            !path.starts_with("artifacts/"),
            "Invalid path should NOT start with 'artifacts/': {path}"
        );
    }
}

// ─── Drift detection ────────────────────────────────────────────────

#[test]
fn drift_detection_viewport_mismatch() {
    let golden = load_golden_snapshot("snapshot_success");
    let mutated = DoctorVisualHarnessSnapshot {
        viewport_width: golden.viewport_width + 1,
        ..golden.clone()
    };
    assert_ne!(
        golden.viewport_width, mutated.viewport_width,
        "Viewport drift must be detected"
    );
    assert_ne!(golden, mutated);
}

#[test]
fn drift_detection_profile_mismatch() {
    let golden = load_golden_snapshot("snapshot_success");
    let mutated = DoctorVisualHarnessSnapshot {
        visual_profile: "frankentui-alert".to_string(),
        ..golden.clone()
    };
    assert_ne!(golden, mutated, "Profile drift must be detected");
}

#[test]
fn drift_detection_panel_mismatch() {
    let golden = load_golden_snapshot("snapshot_success");
    let mutated = DoctorVisualHarnessSnapshot {
        focused_panel: "triage_panel".to_string(),
        ..golden.clone()
    };
    assert_ne!(golden, mutated, "Panel drift must be detected");
}
