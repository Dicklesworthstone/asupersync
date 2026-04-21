#![allow(clippy::all)]
//! Digital twin contract invariants (AA-03.1).

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const DOC_PATH: &str = "docs/digital_twin_contract.md";
const ARTIFACT_PATH: &str = "artifacts/digital_twin_v1.json";
const RUNNER_SCRIPT_PATH: &str = "scripts/run_digital_twin_smoke.sh";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_doc() -> String {
    std::fs::read_to_string(repo_root().join(DOC_PATH)).expect("failed to load digital twin doc")
}

fn load_artifact() -> Value {
    let raw = std::fs::read_to_string(repo_root().join(ARTIFACT_PATH))
        .expect("failed to load digital twin artifact");
    serde_json::from_str(&raw).expect("failed to parse artifact")
}

// ── Doc existence and structure ─────────────────────────────────────

#[test]
fn doc_exists() {
    assert!(Path::new(DOC_PATH).exists(), "doc must exist");
}

#[test]
fn doc_references_bead() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-1508v.3.4"),
        "doc must reference bead id"
    );
}

#[test]
fn doc_has_required_sections() {
    let doc = load_doc();
    let sections = [
        "Purpose",
        "Contract Artifacts",
        "Queue Stage Model",
        "Service Curve Types",
        "Snapshot Field Mapping",
        "Error Budget",
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
        "artifacts/digital_twin_v1.json",
        "scripts/run_digital_twin_smoke.sh",
        "tests/digital_twin_contract.rs",
        "src/runtime/kernel.rs",
    ] {
        assert!(doc.contains(reference), "doc must reference {reference}");
    }
}

#[test]
fn doc_reproduction_command_uses_rch() {
    let doc = load_doc();
    assert!(
        doc.contains(
            "rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa031 cargo test --test digital_twin_contract -- --nocapture"
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
        Some("digital-twin-v1")
    );
    assert_eq!(
        artifact["runner_bundle_schema_version"].as_str(),
        Some("digital-twin-smoke-bundle-v1")
    );
    assert_eq!(
        artifact["runner_report_schema_version"].as_str(),
        Some("digital-twin-smoke-run-report-v1")
    );
    assert_eq!(
        artifact["runner_script"].as_str(),
        Some("scripts/run_digital_twin_smoke.sh")
    );
}

#[test]
fn model_version_is_stable() {
    let artifact = load_artifact();
    assert_eq!(
        artifact["model_version"]["major"].as_u64(),
        Some(1),
        "model major version must be 1"
    );
    assert_eq!(
        artifact["model_version"]["minor"].as_u64(),
        Some(0),
        "model minor version must be 0"
    );
}

// ── Queue stage catalog ──────────────────────────────────────────────

#[test]
fn stage_ids_are_complete() {
    let artifact = load_artifact();
    let actual: BTreeSet<String> = artifact["queue_stages"]
        .as_array()
        .expect("queue_stages must be array")
        .iter()
        .map(|s| s["stage_id"].as_str().unwrap().to_string())
        .collect();
    let expected: BTreeSet<String> = [
        "DT-READY-QUEUE",
        "DT-CANCEL-LANE",
        "DT-FINALIZE-LANE",
        "DT-OBLIGATION-SETTLE",
        "DT-IO-REACTOR",
        "DT-ADMISSION-GATE",
        "DT-RETRY-BACKOFF",
        "DT-STEAL-PATH",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();
    assert_eq!(actual, expected, "queue stage IDs must remain stable");
}

#[test]
fn each_stage_has_required_fields() {
    let artifact = load_artifact();
    for stage in artifact["queue_stages"].as_array().unwrap() {
        let sid = stage["stage_id"].as_str().unwrap_or("<missing>");
        for field in [
            "stage_id",
            "name",
            "description",
            "parameter_sources",
            "seam_ids",
            "service_curve_type",
        ] {
            assert!(
                stage.get(field).is_some(),
                "stage {sid} missing field: {field}"
            );
        }
    }
}

#[test]
fn stage_service_curve_types_are_valid() {
    let artifact = load_artifact();
    let valid_types: BTreeSet<String> = artifact["service_curve_types"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["type_id"].as_str().unwrap().to_string())
        .collect();

    for stage in artifact["queue_stages"].as_array().unwrap() {
        let sid = stage["stage_id"].as_str().unwrap();
        let curve_type = stage["service_curve_type"].as_str().unwrap();
        assert!(
            valid_types.contains(curve_type),
            "stage {sid} has invalid service_curve_type: {curve_type}"
        );
    }
}

// ── Service curve types ──────────────────────────────────────────────

#[test]
fn service_curve_types_are_stable() {
    let artifact = load_artifact();
    let actual: BTreeSet<String> = artifact["service_curve_types"]
        .as_array()
        .expect("service_curve_types must be array")
        .iter()
        .map(|t| t["type_id"].as_str().unwrap().to_string())
        .collect();
    let expected: BTreeSet<String> = ["rate-latency", "token-bucket", "leaky-bucket", "batch"]
        .into_iter()
        .map(ToOwned::to_owned)
        .collect();
    assert_eq!(actual, expected, "service curve types must remain stable");
}

#[test]
fn each_service_curve_type_has_parameters() {
    let artifact = load_artifact();
    for curve in artifact["service_curve_types"].as_array().unwrap() {
        let tid = curve["type_id"].as_str().unwrap();
        let params = curve["parameters"]
            .as_array()
            .expect("parameters must be array");
        assert!(
            !params.is_empty(),
            "service curve type {tid} must have parameters"
        );
    }
}

// ── Snapshot field mapping ───────────────────────────────────────────

#[test]
fn mapping_references_valid_stages() {
    let artifact = load_artifact();
    let stage_ids: BTreeSet<String> = artifact["queue_stages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["stage_id"].as_str().unwrap().to_string())
        .collect();

    for mapping in artifact["snapshot_field_mapping"]["mappings"]
        .as_array()
        .unwrap()
    {
        let field = mapping["snapshot_field"].as_str().unwrap();
        let stage = mapping["stage_id"].as_str().unwrap();
        assert!(
            stage_ids.contains(stage),
            "mapping for {field} references unknown stage: {stage}"
        );
    }
}

#[test]
fn mapping_covers_known_snapshot_fields() {
    let artifact = load_artifact();
    let mapped_fields: BTreeSet<String> = artifact["snapshot_field_mapping"]["mappings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["snapshot_field"].as_str().unwrap().to_string())
        .collect();

    // Must map at least these critical fields
    for field in [
        "ready_queue_len",
        "worker_count",
        "cancel_lane_len",
        "outstanding_obligations",
        "pending_io_registrations",
        "total_tasks",
    ] {
        assert!(
            mapped_fields.contains(field),
            "critical snapshot field must be mapped: {field}"
        );
    }
}

#[test]
fn mapping_entries_have_required_fields() {
    let artifact = load_artifact();
    for mapping in artifact["snapshot_field_mapping"]["mappings"]
        .as_array()
        .unwrap()
    {
        for field in ["snapshot_field", "stage_id", "role"] {
            assert!(
                mapping.get(field).is_some(),
                "mapping entry missing field: {field}"
            );
        }
    }
}

#[test]
fn mapping_stage_coverage_includes_major_paths() {
    let artifact = load_artifact();
    let mapped_stages: BTreeSet<String> = artifact["snapshot_field_mapping"]["mappings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["stage_id"].as_str().unwrap().to_string())
        .collect();

    for stage in [
        "DT-READY-QUEUE",
        "DT-CANCEL-LANE",
        "DT-OBLIGATION-SETTLE",
        "DT-IO-REACTOR",
        "DT-ADMISSION-GATE",
    ] {
        assert!(
            mapped_stages.contains(stage),
            "major path stage must have snapshot mapping: {stage}"
        );
    }
}

// ── Error budget ─────────────────────────────────────────────────────

#[test]
fn error_budget_metrics_are_stable() {
    let artifact = load_artifact();
    let actual: BTreeSet<String> = artifact["error_budget"]["metrics"]
        .as_array()
        .expect("error_budget.metrics must be array")
        .iter()
        .map(|m| m["metric_id"].as_str().unwrap().to_string())
        .collect();
    let expected: BTreeSet<String> = ["DT-ERR-P50", "DT-ERR-P99", "DT-ERR-THROUGHPUT"]
        .into_iter()
        .map(ToOwned::to_owned)
        .collect();
    assert_eq!(actual, expected, "error budget metrics must remain stable");
}

#[test]
fn error_budget_bounds_are_positive() {
    let artifact = load_artifact();
    for metric in artifact["error_budget"]["metrics"].as_array().unwrap() {
        let mid = metric["metric_id"].as_str().unwrap();
        let bound = metric["max_relative_error"]
            .as_f64()
            .expect("max_relative_error must be float");
        assert!(
            bound > 0.0 && bound <= 1.0,
            "error budget for {mid} must be in (0, 1], got {bound}"
        );
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
        let f = field.as_str().expect("field must be string").to_string();
        assert!(!f.is_empty());
        assert!(set.insert(f.clone()), "duplicate field: {f}");
    }
}

// ── Smoke runner ─────────────────────────────────────────────────────

#[test]
fn smoke_scenarios_are_rch_routed() {
    let artifact = load_artifact();
    let scenarios = artifact["smoke_scenarios"].as_array().expect("array");
    assert!(!scenarios.is_empty());
    for scenario in scenarios {
        let sid = scenario["scenario_id"].as_str().unwrap();
        let cmd = scenario["command"].as_str().unwrap();
        assert!(cmd.contains("rch exec --"), "scenario {sid} must use rch");
    }
}

#[test]
fn runner_script_exists_and_declares_modes() {
    let root = repo_root();
    let script_path = root.join(RUNNER_SCRIPT_PATH);
    assert!(script_path.exists(), "runner script must exist");
    let script = std::fs::read_to_string(&script_path).unwrap();
    for token in [
        "--list",
        "--scenario",
        "--dry-run",
        "--execute",
        "digital-twin-smoke-bundle-v1",
        "digital-twin-smoke-run-report-v1",
    ] {
        assert!(script.contains(token), "runner missing token: {token}");
    }
}

// ── Downstream beads ─────────────────────────────────────────────────

#[test]
fn downstream_beads_are_in_aa_namespace() {
    let artifact = load_artifact();
    for bead in artifact["downstream_beads"].as_array().unwrap() {
        let bead = bead.as_str().unwrap();
        assert!(
            bead.starts_with("asupersync-1508v."),
            "must be AA namespace: {bead}"
        );
    }
}

// ── Functional: Service curve math ───────────────────────────────────

/// Rate-latency service curve: beta(t) = R * max(0, t - T)
fn rate_latency(rate: f64, latency: f64, t: f64) -> f64 {
    rate * (t - latency).max(0.0)
}

/// Token-bucket arrival curve: alpha(t) = min(P*t, B + r*t)
fn token_bucket(peak: f64, burst: f64, sustained: f64, t: f64) -> f64 {
    (peak * t).min(sustained.mul_add(t, burst))
}

/// Leaky-bucket arrival curve: alpha(t) = r*t + b
fn leaky_bucket(rate: f64, burst: f64, t: f64) -> f64 {
    rate.mul_add(t, burst)
}

#[test]
fn stage_rate_latency_curve_composition() {
    // Ready queue: 4 workers, 10us service latency
    let rate = 4.0; // tasks/us
    let latency = 10.0; // us

    // At t < latency, no service
    assert!((rate_latency(rate, latency, 5.0)).abs() < f64::EPSILON);
    // At t = latency, service begins
    assert!((rate_latency(rate, latency, 10.0)).abs() < f64::EPSILON);
    // At t > latency, linear service
    assert!((rate_latency(rate, latency, 20.0) - 40.0).abs() < 1e-9);
}

#[test]
fn stage_token_bucket_burst_and_sustained() {
    let peak = 10.0;
    let burst = 5.0;
    let sustained = 2.0;

    // At t=0, alpha = min(0, 5) = 0
    assert!((token_bucket(peak, burst, sustained, 0.0)).abs() < f64::EPSILON);
    // Small t: peak dominates
    assert!((token_bucket(peak, burst, sustained, 0.1) - 1.0).abs() < 1e-9);
    // Large t: sustained + burst dominates
    let t = 100.0;
    let expected = (peak * t).min(burst + sustained * t);
    assert!((token_bucket(peak, burst, sustained, t) - expected).abs() < 1e-9);
}

#[test]
fn stage_leaky_bucket_admission_control() {
    let rate = 100.0; // tasks/sec
    let burst = 10.0;

    assert!((leaky_bucket(rate, burst, 0.0) - 10.0).abs() < 1e-9);
    assert!((leaky_bucket(rate, burst, 1.0) - 110.0).abs() < 1e-9);
}

#[test]
fn stage_network_calculus_backlog_bound() {
    // Backlog bound: sup{alpha(t) - beta(t)} for t >= 0
    // With token-bucket arrival and rate-latency service
    let peak = 8.0;
    let burst = 16.0;
    let sustained = 3.0;
    let service_rate = 4.0;
    let service_latency = 5.0;

    let mut max_backlog = 0.0f64;
    for i in 0..1000_i32 {
        let t = f64::from(i) * 0.1;
        let arrival = token_bucket(peak, burst, sustained, t);
        let service = rate_latency(service_rate, service_latency, t);
        max_backlog = max_backlog.max(arrival - service);
    }

    // Backlog must be finite and positive for these parameters
    assert!(max_backlog > 0.0, "backlog bound must be positive");
    assert!(
        max_backlog < 1000.0,
        "backlog bound must be finite, got {max_backlog}"
    );
}

#[test]
fn stage_delay_bound_from_curves() {
    // Delay bound: horizontal distance between alpha and beta
    // For rate-latency service with rate R and latency T,
    // and leaky-bucket arrival with rate r < R and burst b:
    // delay <= T + b/R
    let service_rate = 4.0;
    let service_latency = 10.0;
    let arrival_rate = 2.0;
    let arrival_burst = 8.0;

    assert!(
        arrival_rate < service_rate,
        "stability: arrival rate must be < service rate"
    );

    let theoretical_delay_bound = service_latency + arrival_burst / service_rate;
    assert!(theoretical_delay_bound > 0.0);

    // Verify by simulation
    let mut max_delay = 0.0f64;
    for i in 0..1000_i32 {
        let t = f64::from(i) * 0.1;
        let arrival = leaky_bucket(arrival_rate, arrival_burst, t);
        // Find time when service reaches this level
        // beta(t') = arrival => t' = arrival/R + T
        let service_time = arrival / service_rate + service_latency;
        let delay = service_time - t;
        max_delay = max_delay.max(delay);
    }

    assert!(
        max_delay <= theoretical_delay_bound + 0.1,
        "simulated delay {max_delay} must be <= theoretical bound {theoretical_delay_bound}"
    );
}

#[test]
fn stage_error_budget_relative_error_calculation() {
    let predicted = 150.0_f64;
    let observed = 170.0_f64;
    let relative_error = (predicted - observed).abs() / observed;

    assert!(
        (relative_error - (20.0 / 170.0)).abs() < 1e-9,
        "relative error calculation must be correct"
    );

    // Within 15% budget?
    assert!(
        relative_error < 0.15,
        "this example should be within p50 budget"
    );
}

#[test]
fn stage_error_budget_violation_detected() {
    let predicted = 100.0_f64;
    let observed = 200.0_f64;
    let relative_error = (predicted - observed).abs() / observed;

    assert!(relative_error > 0.30, "50% error must exceed p99 budget");
}

#[test]
fn stage_parameter_source_snapshot_field_consistency() {
    // Verify that all parameter_sources in queue_stages reference fields
    // that exist in the snapshot_field_mapping
    let artifact = load_artifact();
    let mapped_fields: BTreeSet<String> = artifact["snapshot_field_mapping"]["mappings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["snapshot_field"].as_str().unwrap().to_string())
        .collect();

    let mut unlinked = Vec::new();
    for stage in artifact["queue_stages"].as_array().unwrap() {
        let sid = stage["stage_id"].as_str().unwrap();
        for source in stage["parameter_sources"].as_array().unwrap() {
            let field = source.as_str().unwrap();
            if !mapped_fields.contains(field) {
                unlinked.push(format!("{sid}:{field}"));
            }
        }
    }
    assert!(
        unlinked.is_empty(),
        "parameter sources must map to snapshot fields: {unlinked:?}"
    );
}

#[test]
fn stage_seam_ids_reference_known_seams() {
    // Verify seam IDs in queue_stages follow the AA01-SEAM-* naming pattern
    let artifact = load_artifact();
    for stage in artifact["queue_stages"].as_array().unwrap() {
        let sid = stage["stage_id"].as_str().unwrap();
        for seam in stage["seam_ids"].as_array().unwrap() {
            let seam_id = seam.as_str().unwrap();
            assert!(
                seam_id.starts_with("AA01-SEAM-"),
                "stage {sid} seam must follow AA01-SEAM-* pattern: {seam_id}"
            );
        }
    }
}

#[test]
fn stage_twin_serialization_roundtrip() {
    // Build a minimal twin state from artifact and verify JSON roundtrip
    let artifact = load_artifact();
    let stages: Vec<String> = artifact["queue_stages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["stage_id"].as_str().unwrap().to_string())
        .collect();

    let twin_state: BTreeMap<String, f64> = stages
        .iter()
        .enumerate()
        .map(|(i, sid)| {
            #[allow(clippy::cast_precision_loss)]
            let val = i as f64 * 10.0;
            (sid.clone(), val)
        })
        .collect();

    let json = serde_json::to_string(&twin_state).unwrap();
    let deser: BTreeMap<String, f64> = serde_json::from_str(&json).unwrap();
    assert_eq!(twin_state, deser, "twin state must round-trip through JSON");
}
