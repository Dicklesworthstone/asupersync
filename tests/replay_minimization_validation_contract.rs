#![allow(clippy::all)]
//! Replay minimization and counterexample quality validation contract (AA-06.3).

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const DOC_PATH: &str = "docs/replay_minimization_validation_contract.md";
const ARTIFACT_PATH: &str = "artifacts/replay_minimization_validation_contract_v1.json";
const RUNNER_SCRIPT_PATH: &str = "scripts/run_replay_minimization_validation_smoke.sh";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_doc() -> String {
    std::fs::read_to_string(repo_root().join(DOC_PATH))
        .expect("failed to load replay minimization validation doc")
}

fn load_artifact() -> Value {
    let raw = std::fs::read_to_string(repo_root().join(ARTIFACT_PATH))
        .expect("failed to load replay minimization validation artifact");
    serde_json::from_str(&raw).expect("failed to parse artifact")
}

// ── Doc existence and structure ──────────────────────────────────────

#[test]
fn doc_exists() {
    assert!(
        Path::new(DOC_PATH).exists(),
        "replay minimization validation doc must exist"
    );
}

#[test]
fn doc_references_bead() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-1508v.6.6"),
        "doc must reference bead id"
    );
}

#[test]
fn doc_has_required_sections() {
    let doc = load_doc();
    let sections = [
        "Purpose",
        "Contract Artifacts",
        "Validation Dimensions",
        "Equivalence Invariants",
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
        "artifacts/replay_minimization_validation_contract_v1.json",
        "scripts/run_replay_minimization_validation_smoke.sh",
        "tests/replay_minimization_validation_contract.rs",
        "src/trace/canonicalize.rs",
        "src/trace/delta_debug.rs",
        "src/trace/geodesic.rs",
        "src/trace/dpor.rs",
        "src/trace/crashpack.rs",
        "src/trace/divergence.rs",
    ] {
        assert!(doc.contains(reference), "doc must reference {reference}");
    }
}

#[test]
fn doc_reproduction_command_uses_rch() {
    let doc = load_doc();
    assert!(
        doc.contains(
            "rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa063 cargo test --test replay_minimization_validation_contract -- --nocapture"
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
        Some("replay-minimization-validation-contract-v1")
    );
    assert_eq!(
        artifact["runner_bundle_schema_version"].as_str(),
        Some("replay-minimization-validation-smoke-bundle-v1")
    );
    assert_eq!(
        artifact["runner_report_schema_version"].as_str(),
        Some("replay-minimization-validation-smoke-run-report-v1")
    );
    assert_eq!(
        artifact["runner_script"].as_str(),
        Some("scripts/run_replay_minimization_validation_smoke.sh")
    );
}

// ── Validation dimension catalog ─────────────────────────────────────

#[test]
fn validation_dimension_catalog_has_expected_ids() {
    let artifact = load_artifact();
    let actual: BTreeSet<String> = artifact["validation_dimensions"]
        .as_array()
        .expect("validation_dimensions must be array")
        .iter()
        .map(|d| {
            d["dimension_id"]
                .as_str()
                .expect("dimension_id must be string")
                .to_string()
        })
        .collect();
    let expected: BTreeSet<String> = [
        "canonicalization-equivalence",
        "minimization-quality",
        "geodesic-correctness",
        "race-detection-soundness",
        "crashpack-integrity",
        "divergence-diagnostics",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();
    assert_eq!(
        actual, expected,
        "validation dimension catalog must remain stable"
    );
}

#[test]
fn each_dimension_has_required_fields() {
    let artifact = load_artifact();
    let required = ["dimension_id", "description", "owner_files", "invariants"];
    for dim in artifact["validation_dimensions"].as_array().unwrap() {
        let did = dim["dimension_id"].as_str().unwrap_or("<missing>");
        for field in &required {
            assert!(
                dim.get(*field).is_some(),
                "dimension {did} missing field: {field}"
            );
        }
    }
}

#[test]
fn dimension_owner_files_exist() {
    let artifact = load_artifact();
    let root = repo_root();
    for dim in artifact["validation_dimensions"].as_array().unwrap() {
        let did = dim["dimension_id"].as_str().unwrap();
        for owner in dim["owner_files"].as_array().unwrap() {
            let owner_file = owner.as_str().expect("owner_file must be string");
            assert!(
                root.join(owner_file).exists(),
                "owner file for {did} must exist: {owner_file}"
            );
        }
    }
}

// ── Structured log fields ────────────────────────────────────────────

#[test]
fn structured_log_fields_are_unique_and_nonempty() {
    let artifact = load_artifact();
    let fields = artifact["structured_log_fields_required"]
        .as_array()
        .expect("structured_log_fields_required must be array");

    assert!(!fields.is_empty());

    let mut set = BTreeSet::new();
    for field in fields {
        let field = field.as_str().expect("field must be string").to_string();
        assert!(!field.is_empty());
        assert!(
            set.insert(field.clone()),
            "duplicate structured log field: {field}"
        );
    }
}

// ── Smoke runner and scenarios ───────────────────────────────────────

#[test]
fn smoke_scenarios_are_rch_routed() {
    let artifact = load_artifact();
    let scenarios = artifact["smoke_scenarios"]
        .as_array()
        .expect("smoke_scenarios must be array");
    assert!(!scenarios.is_empty());

    for scenario in scenarios {
        let sid = scenario["scenario_id"]
            .as_str()
            .expect("scenario_id must be string");
        let command = scenario["command"]
            .as_str()
            .expect("command must be string");
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
    assert!(script_path.exists(), "runner script must exist");

    let script = std::fs::read_to_string(&script_path).expect("failed to read runner script");
    for token in [
        "--list",
        "--scenario",
        "--dry-run",
        "--execute",
        "replay-minimization-validation-smoke-bundle-v1",
        "replay-minimization-validation-smoke-run-report-v1",
    ] {
        assert!(
            script.contains(token),
            "runner script missing token: {token}"
        );
    }
}

// ── Downstream beads ─────────────────────────────────────────────────

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

// ── Canonicalization equivalence (functional) ────────────────────────

#[test]
fn canonicalization_preserves_event_set() {
    use asupersync::trace::canonicalize::{FoataTrace, canonicalize};
    use asupersync::trace::event::TraceEvent;
    use asupersync::types::{RegionId, TaskId, Time};

    let events = vec![
        TraceEvent::spawn(
            1,
            Time::ZERO,
            TaskId::new_for_test(1, 0),
            RegionId::new_for_test(1, 0),
        ),
        TraceEvent::spawn(
            2,
            Time::ZERO,
            TaskId::new_for_test(2, 0),
            RegionId::new_for_test(2, 0),
        ),
        TraceEvent::complete(
            3,
            Time::ZERO,
            TaskId::new_for_test(1, 0),
            RegionId::new_for_test(1, 0),
        ),
        TraceEvent::complete(
            4,
            Time::ZERO,
            TaskId::new_for_test(2, 0),
            RegionId::new_for_test(2, 0),
        ),
    ];

    let foata: FoataTrace = canonicalize(&events);
    let total_events: usize = foata.layers().iter().map(Vec::len).sum();
    assert_eq!(
        total_events,
        events.len(),
        "canonicalization must preserve event count"
    );
}

#[test]
fn canonicalization_fingerprint_deterministic() {
    use asupersync::trace::canonicalize::trace_fingerprint;
    use asupersync::trace::event::TraceEvent;
    use asupersync::types::{RegionId, TaskId, Time};

    let events = vec![
        TraceEvent::spawn(
            1,
            Time::ZERO,
            TaskId::new_for_test(1, 0),
            RegionId::new_for_test(1, 0),
        ),
        TraceEvent::spawn(
            2,
            Time::ZERO,
            TaskId::new_for_test(2, 0),
            RegionId::new_for_test(2, 0),
        ),
        TraceEvent::complete(
            3,
            Time::ZERO,
            TaskId::new_for_test(1, 0),
            RegionId::new_for_test(1, 0),
        ),
    ];

    let fp1 = trace_fingerprint(&events);
    let fp2 = trace_fingerprint(&events);
    assert_eq!(fp1, fp2, "fingerprint must be deterministic");
    assert_ne!(fp1, 0, "fingerprint should be non-zero for non-empty trace");
}

// ── Normalization correctness (functional) ───────────────────────────

#[test]
fn normalization_reduces_switch_cost() {
    use asupersync::trace::event::TraceEvent;
    use asupersync::trace::geodesic::GeodesicConfig;
    use asupersync::trace::{normalize_trace, trace_switch_cost};
    use asupersync::types::{RegionId, TaskId, Time};

    // Interleaved: A, B, A, B => 3 switches
    let events = vec![
        TraceEvent::spawn(
            1,
            Time::ZERO,
            TaskId::new_for_test(1, 0),
            RegionId::new_for_test(1, 0),
        ),
        TraceEvent::spawn(
            2,
            Time::ZERO,
            TaskId::new_for_test(2, 0),
            RegionId::new_for_test(2, 0),
        ),
        TraceEvent::complete(
            3,
            Time::ZERO,
            TaskId::new_for_test(1, 0),
            RegionId::new_for_test(1, 0),
        ),
        TraceEvent::complete(
            4,
            Time::ZERO,
            TaskId::new_for_test(2, 0),
            RegionId::new_for_test(2, 0),
        ),
    ];

    let original_cost = trace_switch_cost(&events);
    let config = GeodesicConfig::default();
    let (normalized, result) = normalize_trace(&events, &config);

    assert_eq!(
        normalized.len(),
        events.len(),
        "normalization must preserve event count"
    );
    assert!(
        result.switch_count <= original_cost,
        "normalized switch count ({}) must be <= original ({})",
        result.switch_count,
        original_cost
    );
}

#[test]
fn normalization_greedy_fallback_is_valid() {
    use asupersync::trace::event::TraceEvent;
    use asupersync::trace::geodesic::{GeodesicAlgorithm, GeodesicConfig};
    use asupersync::trace::normalize_trace;
    use asupersync::types::{RegionId, TaskId, Time};

    let events = vec![
        TraceEvent::spawn(
            1,
            Time::ZERO,
            TaskId::new_for_test(1, 0),
            RegionId::new_for_test(1, 0),
        ),
        TraceEvent::spawn(
            2,
            Time::ZERO,
            TaskId::new_for_test(2, 0),
            RegionId::new_for_test(2, 0),
        ),
    ];

    let config = GeodesicConfig::greedy_only();
    let (normalized, result) = normalize_trace(&events, &config);
    assert_eq!(normalized.len(), events.len());
    assert_eq!(result.algorithm, GeodesicAlgorithm::Greedy);
}

// ── Race detection soundness (functional) ────────────────────────────

#[test]
fn race_detection_independent_events_no_races() {
    use asupersync::trace::dpor::detect_races;
    use asupersync::trace::event::TraceEvent;
    use asupersync::types::{RegionId, TaskId, Time};

    // Two independent spawns in different regions
    let events = vec![
        TraceEvent::spawn(
            1,
            Time::ZERO,
            TaskId::new_for_test(1, 0),
            RegionId::new_for_test(1, 0),
        ),
        TraceEvent::spawn(
            2,
            Time::ZERO,
            TaskId::new_for_test(2, 0),
            RegionId::new_for_test(2, 0),
        ),
    ];

    let analysis = detect_races(&events);
    assert!(analysis.is_race_free(), "independent events must not race");
}

#[test]
fn race_detection_empty_trace_is_race_free() {
    use asupersync::trace::dpor::detect_races;
    use asupersync::trace::event::TraceEvent;

    let events: Vec<TraceEvent> = vec![];
    let analysis = detect_races(&events);
    assert!(analysis.is_race_free(), "empty trace must be race-free");
}

// ── Crash pack integrity (functional) ────────────────────────────────

#[test]
fn crashpack_schema_version_stable() {
    use asupersync::trace::crashpack::CRASHPACK_SCHEMA_VERSION;
    assert_eq!(CRASHPACK_SCHEMA_VERSION, 1, "schema version must be stable");
}

#[test]
fn crashpack_builder_fingerprint_matches_trace() {
    use asupersync::trace::canonicalize::trace_fingerprint;
    use asupersync::trace::crashpack::{CrashPack, CrashPackConfig, FailureInfo, FailureOutcome};
    use asupersync::trace::event::TraceEvent;
    use asupersync::types::{RegionId, TaskId, Time};

    let events = vec![
        TraceEvent::spawn(
            1,
            Time::ZERO,
            TaskId::new_for_test(1, 0),
            RegionId::new_for_test(1, 0),
        ),
        TraceEvent::spawn(
            2,
            Time::ZERO,
            TaskId::new_for_test(2, 0),
            RegionId::new_for_test(2, 0),
        ),
    ];

    let expected_fp = trace_fingerprint(&events);

    let pack = CrashPack::builder(CrashPackConfig {
        seed: 42,
        config_hash: 0xDEAD,
        ..Default::default()
    })
    .from_trace(&events)
    .failure(FailureInfo {
        task: TaskId::new_for_test(1, 0),
        region: RegionId::new_for_test(1, 0),
        outcome: FailureOutcome::Panicked {
            message: "test".to_string(),
        },
        virtual_time: Time::ZERO,
    })
    .build()
    .expect("contract test crash pack should include failure metadata");

    assert_eq!(
        pack.fingerprint(),
        expected_fp,
        "crash pack fingerprint must match trace_fingerprint"
    );
    assert_eq!(pack.seed(), 42);
}

#[test]
fn crashpack_deterministic_equality() {
    use asupersync::trace::crashpack::{CrashPack, CrashPackConfig, FailureInfo, FailureOutcome};
    use asupersync::trace::event::TraceEvent;
    use asupersync::types::{RegionId, TaskId, Time};

    let events = vec![TraceEvent::spawn(
        1,
        Time::ZERO,
        TaskId::new_for_test(1, 0),
        RegionId::new_for_test(1, 0),
    )];

    let failure = FailureInfo {
        task: TaskId::new_for_test(1, 0),
        region: RegionId::new_for_test(1, 0),
        outcome: FailureOutcome::Err,
        virtual_time: Time::ZERO,
    };

    let pack1 = CrashPack::builder(CrashPackConfig {
        seed: 99,
        config_hash: 0xBEEF,
        ..Default::default()
    })
    .from_trace(&events)
    .failure(failure.clone())
    .build()
    .expect("contract test crash pack should include failure metadata");

    let pack2 = CrashPack::builder(CrashPackConfig {
        seed: 99,
        config_hash: 0xBEEF,
        ..Default::default()
    })
    .from_trace(&events)
    .failure(failure)
    .build()
    .expect("contract test crash pack should include failure metadata");

    assert_eq!(pack1, pack2, "crash packs with same inputs must be equal");
}

#[test]
fn crashpack_replay_command_well_formed() {
    use asupersync::trace::crashpack::{CrashPack, CrashPackConfig, FailureInfo, FailureOutcome};
    use asupersync::types::{RegionId, TaskId, Time};

    let pack = CrashPack::builder(CrashPackConfig {
        seed: 42,
        config_hash: 0xCAFE,
        ..Default::default()
    })
    .failure(FailureInfo {
        task: TaskId::new_for_test(1, 0),
        region: RegionId::new_for_test(1, 0),
        outcome: FailureOutcome::Err,
        virtual_time: Time::ZERO,
    })
    .build()
    .expect("contract test crash pack should include failure metadata");

    let cmd = pack.replay_command(Some("crashpack.bin"));
    assert!(
        !cmd.command_line.is_empty(),
        "replay command must be non-empty"
    );
}

// ── Divergence diagnostics (functional) ──────────────────────────────

#[test]
fn divergence_report_has_correct_structure() {
    use asupersync::trace::divergence::{
        DiagnosticConfig, DivergenceCategory, diagnose_divergence,
    };
    use asupersync::trace::replay::{CompactTaskId, ReplayEvent, ReplayTrace, TraceMetadata};
    use asupersync::trace::replayer::DivergenceError;

    let trace = ReplayTrace {
        metadata: TraceMetadata {
            version: 1,
            seed: 42,
            recorded_at: 0,
            config_hash: 0,
            description: None,
        },
        events: vec![
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(2),
                at_tick: 1,
            },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(3),
                at_tick: 2,
            },
        ],
        cursor: 0,
    };

    let error = DivergenceError {
        index: 1,
        expected: Some(ReplayEvent::TaskScheduled {
            task: CompactTaskId(2),
            at_tick: 1,
        }),
        actual: ReplayEvent::TaskScheduled {
            task: CompactTaskId(99),
            at_tick: 1,
        },
        context: "test divergence".to_string(),
    };

    let config = DiagnosticConfig::default();
    let report = diagnose_divergence(&trace, &error, &config);

    assert_eq!(report.divergence_index, 1);
    assert_eq!(report.trace_length, 3);
    assert_eq!(report.seed, 42);
    assert_eq!(report.category, DivergenceCategory::SchedulingOrder);
    assert!(report.replay_progress_pct > 0.0);
    assert!(report.replay_progress_pct < 100.0);
}

#[test]
fn divergence_report_json_serializable() {
    use asupersync::trace::divergence::{DiagnosticConfig, diagnose_divergence};
    use asupersync::trace::replay::{CompactTaskId, ReplayEvent, ReplayTrace, TraceMetadata};
    use asupersync::trace::replayer::DivergenceError;

    let trace = ReplayTrace {
        metadata: TraceMetadata {
            version: 1,
            seed: 0,
            recorded_at: 0,
            config_hash: 0,
            description: None,
        },
        events: vec![ReplayEvent::TaskScheduled {
            task: CompactTaskId(1),
            at_tick: 0,
        }],
        cursor: 0,
    };

    let error = DivergenceError {
        index: 0,
        expected: Some(ReplayEvent::TaskScheduled {
            task: CompactTaskId(1),
            at_tick: 0,
        }),
        actual: ReplayEvent::TaskScheduled {
            task: CompactTaskId(2),
            at_tick: 0,
        },
        context: String::new(),
    };

    let report = diagnose_divergence(&trace, &error, &DiagnosticConfig::default());
    let json = report.to_json().expect("must serialize to JSON");
    assert!(json.contains("divergence_index"));
    assert!(json.contains("category"));
    assert!(json.contains("explanation"));
}

#[test]
fn divergence_minimal_prefix_correct_length() {
    use asupersync::trace::divergence::minimal_divergent_prefix;
    use asupersync::trace::replay::{CompactTaskId, ReplayEvent, ReplayTrace, TraceMetadata};

    let trace = ReplayTrace {
        metadata: TraceMetadata {
            version: 1,
            seed: 0,
            recorded_at: 0,
            config_hash: 0,
            description: None,
        },
        events: vec![
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(2),
                at_tick: 1,
            },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(3),
                at_tick: 2,
            },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(4),
                at_tick: 3,
            },
        ],
        cursor: 0,
    };

    // Divergence at index 2 => prefix is events[0..3] (indices 0, 1, 2)
    let prefix = minimal_divergent_prefix(&trace, 2);
    assert_eq!(prefix.events.len(), 3);
    assert_eq!(prefix.metadata.seed, trace.metadata.seed);
}
