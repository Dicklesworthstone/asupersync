#![allow(clippy::all)]
//! Kernel fast path prototype contract invariants (AA-04.2).

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const DOC_PATH: &str = "docs/kernel_fast_path_prototype_contract.md";
const ARTIFACT_PATH: &str = "artifacts/kernel_fast_path_prototype_v1.json";
const RUNNER_SCRIPT_PATH: &str = "scripts/run_kernel_fast_path_prototype_smoke.sh";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_doc() -> String {
    std::fs::read_to_string(repo_root().join(DOC_PATH))
        .expect("failed to load kernel fast path prototype doc")
}

fn load_artifact() -> Value {
    let raw = std::fs::read_to_string(repo_root().join(ARTIFACT_PATH))
        .expect("failed to load kernel fast path prototype artifact");
    serde_json::from_str(&raw).expect("failed to parse artifact")
}

// -- Doc existence and structure --

#[test]
fn doc_exists() {
    assert!(Path::new(DOC_PATH).exists(), "doc must exist");
}

#[test]
fn doc_references_bead() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-1508v.4.5"),
        "doc must reference bead id"
    );
}

#[test]
fn doc_has_required_sections() {
    let doc = load_doc();
    let sections = [
        "Purpose",
        "Contract Artifacts",
        "Prototype Surfaces",
        "Fallback Seam Contract",
        "Benchmark Dimensions",
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
        "artifacts/kernel_fast_path_prototype_v1.json",
        "scripts/run_kernel_fast_path_prototype_smoke.sh",
        "tests/kernel_fast_path_prototype_contract.rs",
        "src/runtime/scheduler/local_queue.rs",
        "src/runtime/scheduler/stealing.rs",
        "src/runtime/waker.rs",
    ] {
        assert!(doc.contains(reference), "doc must reference {reference}");
    }
}

#[test]
fn doc_reproduction_command_uses_rch() {
    let doc = load_doc();
    assert!(
        doc.contains(
            "rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa042 cargo test --test kernel_fast_path_prototype_contract -- --nocapture"
        ),
        "doc must route heavy validation through rch"
    );
}

// -- Artifact schema and version stability --

#[test]
fn artifact_versions_are_stable() {
    let artifact = load_artifact();
    assert_eq!(
        artifact["contract_version"].as_str(),
        Some("kernel-fast-path-prototype-v1")
    );
    assert_eq!(
        artifact["runner_bundle_schema_version"].as_str(),
        Some("kernel-fast-path-prototype-smoke-bundle-v1")
    );
    assert_eq!(
        artifact["runner_report_schema_version"].as_str(),
        Some("kernel-fast-path-prototype-smoke-run-report-v1")
    );
    assert_eq!(
        artifact["runner_script"].as_str(),
        Some("scripts/run_kernel_fast_path_prototype_smoke.sh")
    );
}

// -- Prototype surface catalog --

#[test]
fn prototype_surface_has_expected_ids() {
    let artifact = load_artifact();
    let actual: BTreeSet<String> = artifact["prototype_surfaces"]
        .as_array()
        .expect("prototype_surfaces must be array")
        .iter()
        .map(|s| s["surface_id"].as_str().unwrap().to_string())
        .collect();
    let expected: BTreeSet<String> = ["shard-local-dispatch", "wake-coalescing", "adaptive-steal"]
        .into_iter()
        .map(ToOwned::to_owned)
        .collect();
    assert_eq!(actual, expected, "prototype surfaces must remain stable");
}

#[test]
fn prototype_surface_owner_files_exist() {
    let artifact = load_artifact();
    let root = repo_root();
    for surface in artifact["prototype_surfaces"].as_array().unwrap() {
        let sid = surface["surface_id"].as_str().unwrap();
        let owner_file = surface["owner_file"]
            .as_str()
            .expect("owner_file must be string");
        assert!(
            root.join(owner_file).exists(),
            "owner file for {sid} must exist: {owner_file}"
        );
    }
}

#[test]
fn each_prototype_surface_has_required_fields() {
    let artifact = load_artifact();
    let required = [
        "surface_id",
        "description",
        "owner_file",
        "incumbent_mechanism",
        "prototype_mechanism",
        "fallback_flag",
    ];
    for surface in artifact["prototype_surfaces"].as_array().unwrap() {
        let sid = surface["surface_id"].as_str().unwrap_or("<missing>");
        for field in &required {
            assert!(
                surface.get(*field).is_some(),
                "prototype surface {sid} missing field: {field}"
            );
        }
    }
}

// -- Fallback seam --

#[test]
fn fallback_seam_defaults_to_incumbent() {
    let artifact = load_artifact();
    let seam = &artifact["fallback_seam"];
    assert_eq!(
        seam["defaults_to_incumbent"].as_bool(),
        Some(true),
        "fallback seam must default to incumbent"
    );
}

#[test]
fn fallback_seam_flags_match_surfaces() {
    let artifact = load_artifact();
    let surface_flags: BTreeSet<String> = artifact["prototype_surfaces"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["fallback_flag"].as_str().unwrap().to_string())
        .collect();
    let seam_flags: BTreeSet<String> = artifact["fallback_seam"]["flags"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f.as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        surface_flags, seam_flags,
        "fallback seam flags must match prototype surface flags"
    );
}

// -- Benchmark dimensions --

#[test]
fn benchmark_dimensions_have_expected_ids() {
    let artifact = load_artifact();
    let actual: BTreeSet<String> = artifact["benchmark_dimensions"]
        .as_array()
        .expect("benchmark_dimensions must be array")
        .iter()
        .map(|d| d["dimension_id"].as_str().unwrap().to_string())
        .collect();
    let expected: BTreeSet<String> = [
        "owner-push-pop-throughput",
        "wake-dedup-throughput",
        "steal-latency",
        "e2e-task-throughput",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();
    assert_eq!(actual, expected, "benchmark dimensions must remain stable");
}

#[test]
fn each_benchmark_dimension_has_metrics() {
    let artifact = load_artifact();
    for dim in artifact["benchmark_dimensions"].as_array().unwrap() {
        let did = dim["dimension_id"].as_str().unwrap();
        let metrics = dim["metrics"].as_array().expect("metrics must be array");
        assert!(!metrics.is_empty(), "dimension {did} must have metrics");
    }
}

// -- Structured log fields --

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

// -- Smoke runner and scenarios --

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
        "kernel-fast-path-prototype-smoke-bundle-v1",
        "kernel-fast-path-prototype-smoke-run-report-v1",
    ] {
        assert!(script.contains(token), "runner missing token: {token}");
    }
}

// -- Downstream beads --

#[test]
fn downstream_beads_stay_in_aa_track_namespace() {
    let artifact = load_artifact();
    for bead in artifact["downstream_beads"].as_array().unwrap() {
        let bead = bead.as_str().unwrap();
        assert!(
            bead.starts_with("asupersync-1508v."),
            "must be AA namespace: {bead}"
        );
    }
}

// -- Functional: Local queue push/pop/steal --

#[test]
#[cfg(feature = "test-internals")]
fn functional_local_queue_push_pop_round_trip() {
    use asupersync::runtime::scheduler::local_queue::LocalQueue;
    use asupersync::types::TaskId;

    let queue = LocalQueue::new_for_test(7);

    // Push tasks 0..4
    for i in 0..4u32 {
        queue.push(TaskId::new_for_test(i, 0));
    }

    // Pop should return tasks (LIFO order from owner)
    let mut popped = Vec::new();
    while let Some(tid) = queue.pop() {
        popped.push(tid);
    }
    assert_eq!(popped.len(), 4, "must pop all pushed tasks");
}

#[test]
#[cfg(feature = "test-internals")]
fn functional_local_queue_steal_returns_tasks() {
    use asupersync::runtime::scheduler::local_queue::LocalQueue;
    use asupersync::types::TaskId;

    let queue = LocalQueue::new_for_test(7);
    let stealer = queue.stealer();

    for i in 0..4u32 {
        queue.push(TaskId::new_for_test(i, 0));
    }

    // Steal should return tasks (FIFO order from thief)
    let stolen = stealer.steal();
    assert!(stolen.is_some(), "stealer must be able to steal a task");
}

#[test]
#[cfg(feature = "test-internals")]
fn functional_waker_dedup_coalesces_duplicates() {
    use asupersync::runtime::waker::WakerState;
    use asupersync::types::TaskId;
    use std::sync::Arc;

    let state = Arc::new(WakerState::new());
    let tid = TaskId::new_for_test(1, 0);

    // Wake 10 times
    let waker = state.waker_for(tid);
    for _ in 0..10 {
        waker.wake_by_ref();
    }

    // Should coalesce to exactly 1
    let woken = state.drain_woken();
    assert_eq!(woken.len(), 1, "10 duplicate wakes must coalesce to 1");
    assert_eq!(woken[0], tid);
}

#[test]
#[cfg(feature = "test-internals")]
fn functional_steal_task_power_of_two_choices() {
    use asupersync::runtime::scheduler::local_queue::LocalQueue;
    use asupersync::runtime::scheduler::stealing::steal_task;
    use asupersync::types::TaskId;
    use asupersync::util::DetRng;

    // Create 3 queues sharing the same backing state, load only q1
    let state = LocalQueue::test_state(15);
    let q0 = LocalQueue::new(state.clone());
    let q1 = LocalQueue::new(state.clone());
    let q2 = LocalQueue::new(state);

    for i in 0..8u32 {
        q1.push(TaskId::new_for_test(i, 0));
    }

    let stealers = vec![q0.stealer(), q1.stealer(), q2.stealer()];
    let mut rng = DetRng::new(42);

    // Steal should find work in q1
    let stolen = steal_task(&stealers, &mut rng);
    assert!(
        stolen.is_some(),
        "steal_task must find work in loaded queue"
    );
}
