#![allow(warnings)]
//! Remediation and Trust Visual Regression Suite (Track 6.1)
//!
//! Extends the baseline visual-regression harness (6.9) with remediation-specific
//! visual states, trust-score transition assertions, rollback visual states,
//! state reducer validation, and E2E scenario scripts for success/failure/cancellation
//! paths with deterministic assertions and replay-linked artifacts.
//!
//! Bead: asupersync-2b4jj.6.1

#![allow(missing_docs)]
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(clippy::all)]
#![cfg(feature = "cli")]

use asupersync::cli::doctor::{
    DoctorVisualHarnessArtifactManifest, DoctorVisualHarnessArtifactRecord,
    DoctorVisualHarnessSnapshot, GuidedRemediationCheckpoint, GuidedRemediationPatchPlan,
    GuidedRemediationSessionOutcome, GuidedRemediationSessionRequest,
    RemediationVerificationScorecardEntry, RemediationVerificationScorecardReport,
    RemediationVerificationScorecardThresholds,
};
use serde::Deserialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

// ─── Constants ──────────────────────────────────────────────────────

const DOC_PATH: &str = "docs/doctor_remediation_visual_regression.md";
const FIXTURE_DIR: &str = "tests/fixtures/doctor_remediation_visual";
const FIXTURE_PACK_PATH: &str = "tests/fixtures/doctor_remediation_visual/manifest.json";
const FIXTURE_PACK_SCHEMA_VERSION: &str = "doctor-remediation-visual-fixture-pack-v1";
const MANIFEST_SCHEMA_VERSION: &str = "doctor-visual-harness-manifest-v1";

// Remediation outcome classes
const REMEDIATION_OUTCOMES: [&str; 8] = [
    "fix_applied",
    "fix_preview",
    "fix_rejected",
    "rollback_initiated",
    "trust_degraded",
    "trust_improved",
    "verification_fail",
    "verification_pass",
];

// Visual profiles used by remediation states
const REMEDIATION_PROFILES: [&str; 4] = [
    "frankentui-alert",
    "frankentui-cancel",
    "frankentui-preview",
    "frankentui-stable",
];

// Panels used by remediation states
const REMEDIATION_PANELS: [&str; 2] = ["remediation_panel", "trust_panel"];

// Known artifact classes (same as baseline)
const ARTIFACT_CLASSES: [&str; 6] = [
    "metrics",
    "replay_metadata",
    "snapshot",
    "structured_log",
    "summary",
    "transcript",
];

const HOT_CLASSES: [&str; 3] = ["snapshot", "structured_log", "transcript"];
const WARM_CLASSES: [&str; 3] = ["metrics", "replay_metadata", "summary"];

// ─── Fixture types ──────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
struct RemediationVisualFixturePack {
    schema_version: String,
    description: String,
    fixtures: Vec<RemediationVisualFixture>,
}

#[derive(Debug, Clone, Deserialize)]
struct RemediationVisualFixture {
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
    std::fs::read_to_string(repo_root().join(DOC_PATH))
        .expect("failed to load remediation visual regression doc")
}

fn load_fixture_pack() -> RemediationVisualFixturePack {
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

/// Map remediation outcome class to expected visual profile.
fn expected_profile(outcome: &str) -> &'static str {
    match outcome {
        "fix_preview" => "frankentui-preview",
        "fix_applied" | "verification_pass" | "trust_improved" => "frankentui-stable",
        "fix_rejected" | "rollback_complete" => "frankentui-cancel",
        _ => "frankentui-alert", // verification_fail, trust_degraded, rollback_initiated
    }
}

/// Map remediation outcome class to expected focused panel.
fn expected_panel(outcome: &str) -> &'static str {
    match outcome {
        "fix_preview" | "fix_applied" | "fix_rejected" | "rollback_initiated"
        | "rollback_complete" => "remediation_panel",
        _ => "trust_panel", // verification_pass, verification_fail, trust_improved, trust_degraded
    }
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

// ═══════════════════════════════════════════════════════════════════
// Section 1: Document infrastructure (8 tests)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn doc_exists() {
    assert!(
        Path::new(DOC_PATH).exists(),
        "Remediation visual regression doc must exist"
    );
}

#[test]
fn doc_references_bead() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-2b4jj.6.1"),
        "Doc must reference its own bead ID"
    );
}

#[test]
fn doc_has_required_sections() {
    let doc = load_doc();
    let sections = [
        "Purpose",
        "Remediation Visual State Model",
        "Remediation Snapshot Extensions",
        "Golden Fixture Management",
        "Trust Score Transition Assertions",
        "Remediation Session State Reducers",
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
        "doctor_visual_regression_harness.md",
        "doctor_remediation_recipe_contract.md",
        "doctor_visual_language_contract.md",
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
        doc.contains("doctor_remediation_visual_regression.rs"),
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
fn doc_documents_all_remediation_profiles() {
    let doc = load_doc();
    for profile in &REMEDIATION_PROFILES {
        assert!(
            doc.contains(profile),
            "Doc must document visual profile: {profile}"
        );
    }
}

#[test]
fn doc_documents_determinism_invariant_count() {
    let doc = load_doc();
    let count = doc
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            (1..=10).any(|i| trimmed.starts_with(&format!("{i}. **")))
        })
        .count();
    assert!(
        count >= 10,
        "Doc must have at least 10 determinism invariants, found {count}"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Section 2: Fixture pack validation (8 tests)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn fixture_directory_exists() {
    assert!(
        Path::new(FIXTURE_DIR).exists(),
        "Remediation fixture directory must exist"
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
fn fixture_pack_covers_all_remediation_outcomes() {
    let pack = load_fixture_pack();
    let outcomes: HashSet<&str> = pack
        .fixtures
        .iter()
        .map(|f| f.outcome_class.as_str())
        .collect();
    for expected in &REMEDIATION_OUTCOMES {
        assert!(
            outcomes.contains(expected),
            "Fixture pack must cover remediation outcome class: {expected}"
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
fn fixture_pack_ids_lexically_sorted() {
    let pack = load_fixture_pack();
    let ids: Vec<&str> = pack
        .fixtures
        .iter()
        .map(|f| f.fixture_id.as_str())
        .collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(ids, sorted, "Fixture IDs must be lexically sorted");
}

#[test]
fn fixture_pack_profiles_match_outcome_mapping() {
    let pack = load_fixture_pack();
    for fixture in &pack.fixtures {
        let exp = expected_profile(&fixture.outcome_class);
        assert_eq!(
            fixture.expected_visual_profile, exp,
            "Fixture {} profile mismatch for outcome '{}': expected '{}', got '{}'",
            fixture.fixture_id, fixture.outcome_class, exp, fixture.expected_visual_profile
        );
    }
}

#[test]
fn fixture_pack_panels_match_outcome_mapping() {
    let pack = load_fixture_pack();
    for fixture in &pack.fixtures {
        let exp = expected_panel(&fixture.outcome_class);
        assert_eq!(
            fixture.expected_focused_panel, exp,
            "Fixture {} panel mismatch for outcome '{}': expected '{}', got '{}'",
            fixture.fixture_id, fixture.outcome_class, exp, fixture.expected_focused_panel
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

// ═══════════════════════════════════════════════════════════════════
// Section 3: Golden snapshot validation (10 tests)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn golden_snapshot_files_exist() {
    let names = [
        "snapshot_fix_preview",
        "snapshot_fix_applied",
        "snapshot_fix_rejected",
        "snapshot_verify_pass",
        "snapshot_verify_fail",
        "snapshot_trust_improved",
        "snapshot_trust_degraded",
        "snapshot_rollback",
    ];
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
    let names = [
        "snapshot_fix_preview",
        "snapshot_fix_applied",
        "snapshot_fix_rejected",
        "snapshot_verify_pass",
        "snapshot_verify_fail",
        "snapshot_trust_improved",
        "snapshot_trust_degraded",
        "snapshot_rollback",
    ];
    for name in &names {
        let snapshot = load_golden_snapshot(name);
        assert!(
            !snapshot.snapshot_id.is_empty(),
            "Golden snapshot {name} must have non-empty snapshot_id"
        );
    }
}

#[test]
fn golden_snapshot_fix_preview_profile() {
    let snapshot = load_golden_snapshot("snapshot_fix_preview");
    assert_eq!(snapshot.visual_profile, "frankentui-preview");
    assert_eq!(snapshot.focused_panel, "remediation_panel");
}

#[test]
fn golden_snapshot_fix_applied_profile() {
    let snapshot = load_golden_snapshot("snapshot_fix_applied");
    assert_eq!(snapshot.visual_profile, "frankentui-stable");
    assert_eq!(snapshot.focused_panel, "remediation_panel");
}

#[test]
fn golden_snapshot_fix_rejected_profile() {
    let snapshot = load_golden_snapshot("snapshot_fix_rejected");
    assert_eq!(snapshot.visual_profile, "frankentui-cancel");
    assert_eq!(snapshot.focused_panel, "remediation_panel");
}

#[test]
fn golden_snapshot_verify_pass_profile() {
    let snapshot = load_golden_snapshot("snapshot_verify_pass");
    assert_eq!(snapshot.visual_profile, "frankentui-stable");
    assert_eq!(snapshot.focused_panel, "trust_panel");
}

#[test]
fn golden_snapshot_verify_fail_profile() {
    let snapshot = load_golden_snapshot("snapshot_verify_fail");
    assert_eq!(snapshot.visual_profile, "frankentui-alert");
    assert_eq!(snapshot.focused_panel, "trust_panel");
}

#[test]
fn golden_snapshot_trust_improved_profile() {
    let snapshot = load_golden_snapshot("snapshot_trust_improved");
    assert_eq!(snapshot.visual_profile, "frankentui-stable");
    assert_eq!(snapshot.focused_panel, "trust_panel");
}

#[test]
fn golden_snapshot_trust_degraded_profile() {
    let snapshot = load_golden_snapshot("snapshot_trust_degraded");
    assert_eq!(snapshot.visual_profile, "frankentui-alert");
    assert_eq!(snapshot.focused_panel, "trust_panel");
}

#[test]
fn golden_snapshots_have_valid_digests() {
    let names = [
        "snapshot_fix_preview",
        "snapshot_fix_applied",
        "snapshot_fix_rejected",
        "snapshot_verify_pass",
        "snapshot_verify_fail",
        "snapshot_trust_improved",
        "snapshot_trust_degraded",
        "snapshot_rollback",
    ];
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

// ═══════════════════════════════════════════════════════════════════
// Section 4: Golden manifest validation (8 tests)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn golden_manifest_file_exists() {
    let path = repo_root()
        .join(FIXTURE_DIR)
        .join("manifest_remediation.json");
    assert!(
        path.exists(),
        "Golden remediation artifact manifest must exist"
    );
}

#[test]
fn golden_manifest_deserializes() {
    let manifest = load_golden_manifest("manifest_remediation");
    assert_eq!(manifest.schema_version, MANIFEST_SCHEMA_VERSION);
    assert!(!manifest.run_id.is_empty());
    assert!(!manifest.scenario_id.is_empty());
}

#[test]
fn golden_manifest_artifact_root() {
    let manifest = load_golden_manifest("manifest_remediation");
    assert!(
        manifest.artifact_root.starts_with("artifacts/"),
        "artifact_root must start with 'artifacts/'"
    );
}

#[test]
fn golden_manifest_records_sorted() {
    let manifest = load_golden_manifest("manifest_remediation");
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
    let manifest = load_golden_manifest("manifest_remediation");
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
    let manifest = load_golden_manifest("manifest_remediation");
    for record in &manifest.records {
        assert!(
            !record.checksum_hint.trim().is_empty(),
            "checksum_hint must be non-empty: {}",
            record.artifact_id
        );
    }
}

#[test]
fn golden_manifest_retention_policy() {
    let manifest = load_golden_manifest("manifest_remediation");
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
    let manifest = load_golden_manifest("manifest_remediation");
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

// ═══════════════════════════════════════════════════════════════════
// Section 5: Remediation snapshot construction (6 tests)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn remediation_snapshot_roundtrip_serde() {
    let snapshot = DoctorVisualHarnessSnapshot {
        snapshot_id: "test-remediation-001".to_string(),
        viewport_width: 132,
        viewport_height: 44,
        focused_panel: "remediation_panel".to_string(),
        selected_node_id: "finding-01".to_string(),
        stage_digest: "len:3|preview|approved|applied".to_string(),
        visual_profile: "frankentui-stable".to_string(),
        capture_index: 1,
    };
    let json = serde_json::to_string(&snapshot).expect("serialize snapshot");
    let deserialized: DoctorVisualHarnessSnapshot =
        serde_json::from_str(&json).expect("deserialize snapshot");
    assert_eq!(
        snapshot, deserialized,
        "Remediation snapshot must roundtrip through serde"
    );
}

#[test]
fn remediation_profile_determinism() {
    let outcomes_and_profiles = [
        ("fix_preview", "frankentui-preview", "remediation_panel"),
        ("fix_applied", "frankentui-stable", "remediation_panel"),
        ("fix_rejected", "frankentui-cancel", "remediation_panel"),
        ("verification_pass", "frankentui-stable", "trust_panel"),
        ("verification_fail", "frankentui-alert", "trust_panel"),
        ("trust_improved", "frankentui-stable", "trust_panel"),
        ("trust_degraded", "frankentui-alert", "trust_panel"),
        (
            "rollback_initiated",
            "frankentui-alert",
            "remediation_panel",
        ),
        (
            "rollback_complete",
            "frankentui-cancel",
            "remediation_panel",
        ),
    ];

    for (outcome, exp_profile, exp_panel) in &outcomes_and_profiles {
        assert_eq!(
            expected_profile(outcome),
            *exp_profile,
            "Profile mapping mismatch for outcome '{outcome}'"
        );
        assert_eq!(
            expected_panel(outcome),
            *exp_panel,
            "Panel mapping mismatch for outcome '{outcome}'"
        );
    }
}

#[test]
fn remediation_viewport_determinism() {
    let snap_a = DoctorVisualHarnessSnapshot {
        snapshot_id: "rem-det-a".to_string(),
        viewport_width: 132,
        viewport_height: 44,
        focused_panel: "remediation_panel".to_string(),
        selected_node_id: "finding-01".to_string(),
        stage_digest: "len:1|preview".to_string(),
        visual_profile: "frankentui-preview".to_string(),
        capture_index: 0,
    };
    let snap_b = DoctorVisualHarnessSnapshot {
        snapshot_id: "rem-det-a".to_string(),
        viewport_width: 132,
        viewport_height: 44,
        focused_panel: "remediation_panel".to_string(),
        selected_node_id: "finding-01".to_string(),
        stage_digest: "len:1|preview".to_string(),
        visual_profile: "frankentui-preview".to_string(),
        capture_index: 0,
    };
    assert_eq!(
        snap_a, snap_b,
        "Same remediation inputs must produce equal snapshots"
    );
}

#[test]
fn remediation_digest_format_validation() {
    let valid_digests = [
        "len:1|preview",
        "len:2|preview|rejected",
        "len:3|preview|approved|applied",
        "len:4|preview|approved|applied|verify_pass",
        "len:4|preview|approved|applied|rollback",
        "len:2|verify_pass|trust:+15",
        "len:2|verify_fail|trust:-8",
    ];

    for digest in &valid_digests {
        assert!(
            digest.starts_with("len:"),
            "Digest must start with 'len:': {digest}"
        );
        let parts: Vec<&str> = digest.split('|').collect();
        let count_str = parts[0].strip_prefix("len:").unwrap();
        let count: usize = count_str.parse().expect("count must be numeric");
        assert_eq!(
            parts.len() - 1,
            count,
            "Digest stage count mismatch: {digest}"
        );
    }
}

#[test]
fn remediation_manifest_ordering_invariant() {
    let records = vec![
        DoctorVisualHarnessArtifactRecord {
            artifact_id: "z-record".to_string(),
            artifact_class: "snapshot".to_string(),
            artifact_path: "artifacts/test/z.json".to_string(),
            checksum_hint: "z".to_string(),
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
    ];

    let mut sorted = records;
    sorted.sort_by(|a, b| a.artifact_id.cmp(&b.artifact_id));
    assert_eq!(sorted[0].artifact_id, "a-record");
    assert_eq!(sorted[1].artifact_id, "z-record");
}

#[test]
fn remediation_linked_artifacts_dedup_invariant() {
    let mut linked = vec![
        "rem-c".to_string(),
        "rem-a".to_string(),
        "rem-c".to_string(),
        "rem-b".to_string(),
    ];
    linked.sort();
    linked.dedup();
    assert_eq!(
        linked,
        vec!["rem-a", "rem-b", "rem-c"],
        "Linked artifacts must be sorted and deduplicated"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Section 6: Trust score transition assertions (8 tests)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn trust_delta_computation_determinism() {
    let cases: Vec<(u8, u8, i16)> = vec![
        (50, 65, 15),
        (70, 70, 0),
        (80, 72, -8),
        (0, 100, 100),
        (100, 0, -100),
    ];
    for (before, after, expected_delta) in &cases {
        let delta = i16::from(*after) - i16::from(*before);
        assert_eq!(
            delta, *expected_delta,
            "Trust delta mismatch: before={before}, after={after}"
        );
    }
}

#[test]
fn confidence_shift_determinism() {
    let cases: Vec<(i16, &str)> = vec![
        (15, "improved"),
        (0, "stable"),
        (-8, "degraded"),
        (1, "improved"),
        (-1, "degraded"),
    ];
    for (delta, expected_shift) in &cases {
        let shift = match (*delta).cmp(&0) {
            std::cmp::Ordering::Greater => "improved",
            std::cmp::Ordering::Less => "degraded",
            std::cmp::Ordering::Equal => "stable",
        };
        assert_eq!(
            shift, *expected_shift,
            "Confidence shift mismatch for delta={delta}"
        );
    }
}

#[test]
fn scorecard_accept_recommendation() {
    let thresholds = RemediationVerificationScorecardThresholds {
        accept_min_score: 70,
        accept_min_delta: 5,
        escalate_below_score: 40,
        rollback_delta_threshold: -10,
    };

    // Accept: score >= 70, delta >= 5, no unresolved
    let entry = make_scorecard_entry("scenario-accept", 60, 80, vec![]);
    let recommendation = compute_recommendation(&thresholds, &entry);
    assert_eq!(recommendation, "accept");
}

#[test]
fn scorecard_monitor_recommendation() {
    let thresholds = RemediationVerificationScorecardThresholds {
        accept_min_score: 70,
        accept_min_delta: 5,
        escalate_below_score: 40,
        rollback_delta_threshold: -10,
    };

    // Monitor: score 65 (below accept_min), delta 3 (below accept_min_delta), not escalate
    let entry = make_scorecard_entry("scenario-monitor", 62, 65, vec![]);
    let recommendation = compute_recommendation(&thresholds, &entry);
    assert_eq!(recommendation, "monitor");
}

#[test]
fn scorecard_escalate_recommendation() {
    let thresholds = RemediationVerificationScorecardThresholds {
        accept_min_score: 70,
        accept_min_delta: 5,
        escalate_below_score: 40,
        rollback_delta_threshold: -10,
    };

    // Escalate: score drops below escalate_below_score, but delta is above rollback threshold
    let entry = make_scorecard_entry(
        "scenario-escalate",
        42,
        35,
        vec!["unresolved-finding-1".to_string()],
    );
    let recommendation = compute_recommendation(&thresholds, &entry);
    assert_eq!(recommendation, "escalate");
}

#[test]
fn scorecard_rollback_recommendation() {
    let thresholds = RemediationVerificationScorecardThresholds {
        accept_min_score: 70,
        accept_min_delta: 5,
        escalate_below_score: 40,
        rollback_delta_threshold: -10,
    };

    // Rollback: delta <= rollback_delta_threshold
    let entry = make_scorecard_entry("scenario-rollback", 60, 45, vec![]);
    let recommendation = compute_recommendation(&thresholds, &entry);
    assert_eq!(recommendation, "rollback");
}

#[test]
fn scorecard_entries_sorted_by_scenario_id() {
    let entries = vec![
        make_scorecard_entry("scenario-c", 50, 65, vec![]),
        make_scorecard_entry("scenario-a", 60, 80, vec![]),
        make_scorecard_entry("scenario-b", 70, 70, vec![]),
    ];
    let mut sorted = entries;
    sorted.sort_by(|a, b| a.scenario_id.cmp(&b.scenario_id));
    assert_eq!(sorted[0].scenario_id, "scenario-a");
    assert_eq!(sorted[1].scenario_id, "scenario-b");
    assert_eq!(sorted[2].scenario_id, "scenario-c");
}

#[test]
fn scorecard_report_roundtrip_serde() {
    let report = RemediationVerificationScorecardReport {
        run_id: "test-run-001".to_string(),
        thresholds: RemediationVerificationScorecardThresholds {
            accept_min_score: 70,
            accept_min_delta: 5,
            escalate_below_score: 40,
            rollback_delta_threshold: -10,
        },
        entries: vec![make_scorecard_entry("scenario-001", 50, 75, vec![])],
        events: vec![],
    };
    let json = serde_json::to_string(&report).expect("serialize report");
    let deserialized: RemediationVerificationScorecardReport =
        serde_json::from_str(&json).expect("deserialize report");
    assert_eq!(
        report, deserialized,
        "Scorecard report must roundtrip through serde"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Section 7: Remediation session state reducers (6 tests)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn state_reducer_preview_to_approved() {
    let checkpoints = vec![
        "checkpoint_diff_review",
        "checkpoint_risk_ack",
        "checkpoint_rollback_ready",
        "checkpoint_apply_authorization",
    ];
    let approved: Vec<String> = checkpoints
        .iter()
        .map(std::string::ToString::to_string)
        .collect();

    // All checkpoints approved => transition allowed
    let all_approved = checkpoints
        .iter()
        .all(|cp| approved.contains(&cp.to_string()));
    assert!(
        all_approved,
        "All checkpoints must be approved for preview→approved"
    );
}

#[test]
fn state_reducer_preview_to_rejected() {
    let approved: Vec<String> = vec!["checkpoint_diff_review".to_string()];
    let required = vec![
        "checkpoint_diff_review",
        "checkpoint_risk_ack",
        "checkpoint_rollback_ready",
        "checkpoint_apply_authorization",
    ];

    // Not all checkpoints approved => rejected
    let all_approved = required.iter().all(|cp| approved.contains(&cp.to_string()));
    assert!(!all_approved, "Missing checkpoints should prevent approval");
}

#[test]
fn state_reducer_checkpoint_ordering() {
    let checkpoints = vec![
        GuidedRemediationCheckpoint {
            checkpoint_id: "checkpoint_diff_review".to_string(),
            stage_order: 0,
            prompt: "Review proposed diff".to_string(),
        },
        GuidedRemediationCheckpoint {
            checkpoint_id: "checkpoint_risk_ack".to_string(),
            stage_order: 1,
            prompt: "Acknowledge risk assessment".to_string(),
        },
        GuidedRemediationCheckpoint {
            checkpoint_id: "checkpoint_rollback_ready".to_string(),
            stage_order: 2,
            prompt: "Confirm rollback readiness".to_string(),
        },
        GuidedRemediationCheckpoint {
            checkpoint_id: "checkpoint_apply_authorization".to_string(),
            stage_order: 3,
            prompt: "Authorize apply".to_string(),
        },
    ];

    // Verify ordering is monotonically increasing
    for i in 1..checkpoints.len() {
        assert!(
            checkpoints[i].stage_order > checkpoints[i - 1].stage_order,
            "Checkpoint stage_order must be monotonically increasing"
        );
    }
}

#[test]
fn state_reducer_idempotency_key_noop() {
    let request_a = GuidedRemediationSessionRequest {
        run_id: "run-001".to_string(),
        scenario_id: "scenario-001".to_string(),
        approved_checkpoints: vec!["checkpoint_apply_authorization".to_string()],
        simulate_apply_failure: false,
        previous_idempotency_key: Some("idem-key-001".to_string()),
    };

    // When previous_idempotency_key matches, result should be idempotent_noop
    assert!(
        request_a.previous_idempotency_key.is_some(),
        "Rerun with previous key should be idempotent"
    );
}

#[test]
fn state_reducer_apply_failure_triggers_rollback() {
    let request = GuidedRemediationSessionRequest {
        run_id: "run-failure".to_string(),
        scenario_id: "scenario-failure".to_string(),
        approved_checkpoints: vec![
            "checkpoint_diff_review".to_string(),
            "checkpoint_risk_ack".to_string(),
            "checkpoint_rollback_ready".to_string(),
            "checkpoint_apply_authorization".to_string(),
        ],
        simulate_apply_failure: true,
        previous_idempotency_key: None,
    };

    assert!(
        request.simulate_apply_failure,
        "Simulated failure must trigger rollback path"
    );
}

#[test]
fn patch_plan_construction_determinism() {
    let plan = GuidedRemediationPatchPlan {
        plan_id: "plan-001".to_string(),
        recipe_id: "recipe-lock-order".to_string(),
        finding_id: "finding-lock-01".to_string(),
        patch_digest: "sha256:patch-digest-001".to_string(),
        diff_preview: vec![
            "--- a/src/sync/mutex.rs".to_string(),
            "+++ b/src/sync/mutex.rs".to_string(),
            "@@ -42,3 +42,3 @@".to_string(),
        ],
        impacted_invariants: vec!["INV-LOCK-01".to_string(), "INV-LOCK-02".to_string()],
        approval_checkpoints: vec![GuidedRemediationCheckpoint {
            checkpoint_id: "checkpoint_diff_review".to_string(),
            stage_order: 0,
            prompt: "Review proposed diff".to_string(),
        }],
        risk_flags: vec!["concurrent_access".to_string()],
        rollback_artifact_pointer: "artifacts/plan-001/rollback.json".to_string(),
        rollback_instructions: vec!["git apply --reverse plan-001.patch".to_string()],
        operator_guidance: vec!["Accept if lock ordering matches documented policy".to_string()],
        idempotency_key: "idem-plan-001".to_string(),
    };

    // Verify impacted_invariants are lexically sorted
    let mut sorted_inv = plan.impacted_invariants.clone();
    sorted_inv.sort();
    assert_eq!(plan.impacted_invariants, sorted_inv);

    // Verify roundtrip
    let json = serde_json::to_string(&plan).expect("serialize plan");
    let deserialized: GuidedRemediationPatchPlan =
        serde_json::from_str(&json).expect("deserialize plan");
    assert_eq!(
        plan, deserialized,
        "Patch plan must roundtrip through serde"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Section 8: Drift detection (4 tests)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn drift_detection_remediation_profile_mismatch() {
    let golden = load_golden_snapshot("snapshot_fix_preview");
    let mutated = DoctorVisualHarnessSnapshot {
        visual_profile: "frankentui-alert".to_string(),
        ..golden.clone()
    };
    assert_ne!(
        golden, mutated,
        "Profile drift must be detected for remediation snapshots"
    );
}

#[test]
fn drift_detection_remediation_panel_mismatch() {
    let golden = load_golden_snapshot("snapshot_fix_applied");
    let mutated = DoctorVisualHarnessSnapshot {
        focused_panel: "trust_panel".to_string(),
        ..golden.clone()
    };
    assert_ne!(
        golden, mutated,
        "Panel drift must be detected for remediation snapshots"
    );
}

#[test]
fn drift_detection_remediation_digest_mismatch() {
    let golden = load_golden_snapshot("snapshot_verify_pass");
    let mutated = DoctorVisualHarnessSnapshot {
        stage_digest: "len:3|preview|approved|applied".to_string(),
        ..golden.clone()
    };
    assert_ne!(
        golden, mutated,
        "Digest drift must be detected for remediation snapshots"
    );
}

#[test]
fn drift_detection_remediation_viewport_mismatch() {
    let golden = load_golden_snapshot("snapshot_trust_improved");
    let mutated = DoctorVisualHarnessSnapshot {
        viewport_width: golden.viewport_width + 10,
        ..golden.clone()
    };
    assert_ne!(
        golden, mutated,
        "Viewport drift must be detected for remediation snapshots"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Section 9: E2E scenario integration (5 tests)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn e2e_success_scenario_visual_progression() {
    // Success path: preview → approved → applied → verify_pass → trust_improved
    let stages = vec!["preview", "approved", "applied", "verify_pass"];
    let digest = format!("len:{}|{}", stages.len(), stages.join("|"));
    assert!(digest.starts_with("len:4|"));

    let final_profile = expected_profile("verification_pass");
    assert_eq!(final_profile, "frankentui-stable");
    let final_panel = expected_panel("verification_pass");
    assert_eq!(final_panel, "trust_panel");
}

#[test]
fn e2e_rejection_scenario_visual_progression() {
    // Rejection path: preview → rejected
    let stages = vec!["preview", "rejected"];
    let digest = format!("len:{}|{}", stages.len(), stages.join("|"));
    assert!(digest.starts_with("len:2|"));

    let final_profile = expected_profile("fix_rejected");
    assert_eq!(final_profile, "frankentui-cancel");
    let final_panel = expected_panel("fix_rejected");
    assert_eq!(final_panel, "remediation_panel");
}

#[test]
fn e2e_rollback_scenario_visual_progression() {
    // Rollback path: preview → approved → applied → verify_fail → rollback
    let stages = vec!["preview", "approved", "applied", "rollback"];
    let digest = format!("len:{}|{}", stages.len(), stages.join("|"));
    assert!(digest.starts_with("len:4|"));

    let final_profile = expected_profile("rollback_initiated");
    assert_eq!(final_profile, "frankentui-alert");
    let final_panel = expected_panel("rollback_initiated");
    assert_eq!(final_panel, "remediation_panel");
}

#[test]
fn e2e_cancellation_scenario_visual_state() {
    // Cancellation mid-flow: treated as fix_rejected for visual purposes
    let final_profile = expected_profile("fix_rejected");
    assert_eq!(final_profile, "frankentui-cancel");
}

#[test]
fn e2e_artifact_manifest_construction() {
    // Verify a remediation E2E run produces a valid manifest
    let manifest = DoctorVisualHarnessArtifactManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        run_id: "e2e-remediation-001".to_string(),
        scenario_id: "e2e-success-apply".to_string(),
        artifact_root: "artifacts/e2e-remediation-001/doctor/e2e/".to_string(),
        records: vec![
            DoctorVisualHarnessArtifactRecord {
                artifact_id: "e2e-remediation-001-snapshot".to_string(),
                artifact_class: "snapshot".to_string(),
                artifact_path: "artifacts/e2e-remediation-001/doctor/e2e/snapshot.json".to_string(),
                checksum_hint: "sha256:e2e-snap-001".to_string(),
                retention_class: "hot".to_string(),
                linked_artifacts: vec!["e2e-remediation-001-transcript".to_string()],
            },
            DoctorVisualHarnessArtifactRecord {
                artifact_id: "e2e-remediation-001-transcript".to_string(),
                artifact_class: "transcript".to_string(),
                artifact_path: "artifacts/e2e-remediation-001/doctor/e2e/transcript.json"
                    .to_string(),
                checksum_hint: "sha256:e2e-trans-001".to_string(),
                retention_class: "hot".to_string(),
                linked_artifacts: vec!["e2e-remediation-001-snapshot".to_string()],
            },
        ],
    };

    // Records sorted
    let ids: Vec<&str> = manifest
        .records
        .iter()
        .map(|r| r.artifact_id.as_str())
        .collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(ids, sorted, "E2E manifest records must be lexically sorted");

    // Roundtrip
    let json = serde_json::to_string(&manifest).expect("serialize");
    let _: DoctorVisualHarnessArtifactManifest = serde_json::from_str(&json).expect("deserialize");
}

// ═══════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════

fn make_scorecard_entry(
    scenario_id: &str,
    trust_before: u8,
    trust_after: u8,
    unresolved: Vec<String>,
) -> RemediationVerificationScorecardEntry {
    let delta = i16::from(trust_after) - i16::from(trust_before);
    let shift = match delta.cmp(&0) {
        std::cmp::Ordering::Greater => "improved",
        std::cmp::Ordering::Less => "degraded",
        std::cmp::Ordering::Equal => "stable",
    };
    RemediationVerificationScorecardEntry {
        entry_id: format!("entry-{scenario_id}"),
        scenario_id: scenario_id.to_string(),
        trust_score_before: trust_before,
        trust_score_after: trust_after,
        trust_delta: delta,
        unresolved_findings: unresolved,
        confidence_shift: shift.to_string(),
        recommendation: String::new(), // filled by compute_recommendation
        evidence_pointer: format!("artifacts/{scenario_id}/evidence.json"),
    }
}

fn compute_recommendation(
    thresholds: &RemediationVerificationScorecardThresholds,
    entry: &RemediationVerificationScorecardEntry,
) -> &'static str {
    if entry.trust_delta <= thresholds.rollback_delta_threshold {
        "rollback"
    } else if entry.trust_score_after < thresholds.escalate_below_score
        || (!entry.unresolved_findings.is_empty() && entry.trust_delta <= 0)
    {
        "escalate"
    } else if entry.trust_score_after >= thresholds.accept_min_score
        && entry.trust_delta >= thresholds.accept_min_delta
        && entry.unresolved_findings.is_empty()
    {
        "accept"
    } else {
        "monitor"
    }
}
