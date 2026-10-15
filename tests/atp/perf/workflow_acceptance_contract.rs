use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

const SCRIPT_PATH: &str = "scripts/atp_perf/workflow_acceptance_smoke.py";
const CONTRACT_VERSION: &str = "atp-n9-workflow-acceptance-v1";
const REPORT_SCHEMA_VERSION: &str = "atp-n9-workflow-report-v1";
const EVENT_SCHEMA_VERSION: &str = "atp-n9-workflow-event-v1";
const SCHEDULER_PROFILE_SCHEMA_VERSION: &str = "atp-e5-scheduler-workload-profile-v1";
const SCHEDULER_GATE_SCHEMA_VERSION: &str = "atp-e5-scheduler-benchmark-gate-v1";
const BENCHMARK_REPORT_SCHEMA_VERSION: &str = "atp-l3-public-regression-report-v1";
static RUN_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn repo_path(path: &str) -> PathBuf {
    repo_root().join(path)
}

fn read_script() -> String {
    std::fs::read_to_string(repo_path(SCRIPT_PATH)).expect("ATP-N9 runner script must exist")
}

fn run_contract_smoke() -> Value {
    let output_root = repo_path("target/atp_perf_acceptance_contract");
    let run_id = format!(
        "atp-n9-contract-{}-{}",
        std::process::id(),
        RUN_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let output = Command::new("python3")
        .arg(repo_path(SCRIPT_PATH))
        .args([
            "--contract-only",
            "--run-id",
            &run_id,
            "--output-root",
            output_root
                .to_str()
                .expect("output root path must be valid UTF-8"),
        ])
        .current_dir(repo_root())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run ATP-N9 workflow acceptance smoke contract");

    assert!(
        output.status.success(),
        "ATP-N9 runner failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("runner stdout must be JSON")
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|item| item.as_str().expect("entry must be string").to_string())
        .collect()
}

fn artifact_path(report: &Value, key: &str) -> PathBuf {
    let raw = report["artifacts"][key]
        .as_str()
        .unwrap_or_else(|| panic!("artifact path {key} must be string"));
    let path = Path::new(raw);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        repo_path(raw)
    }
}

#[test]
fn runner_declares_fast_regression_and_manual_modes() {
    let script = read_script();
    for required in [
        "--list",
        "--mode",
        "--workflow",
        "--output-root",
        "--run-id",
        "--contract-only",
        "--require-external-tools",
        "smoke",
        "regression",
        "manual",
    ] {
        assert!(script.contains(required), "runner must declare {required}");
    }
}

#[test]
fn workflow_catalog_covers_real_user_acceptance_surfaces() {
    let report = run_contract_smoke();
    assert_eq!(report["contract_version"].as_str(), Some(CONTRACT_VERSION));
    assert_eq!(
        report["schema_version"].as_str(),
        Some(REPORT_SCHEMA_VERSION)
    );
    assert_eq!(report["bead_id"].as_str(), Some("asupersync-m7hmrq"));

    let workflow_classes = array(&report, "workflow_catalog")
        .iter()
        .map(|workflow| {
            workflow["workflow_class"]
                .as_str()
                .expect("workflow_class must be string")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    for required_class in [
        "huge_file",
        "many_small_files",
        "sync_tree_small_edits",
        "sparse_image",
        "model_bundle",
        "dataset",
        "relay_only",
        "mailbox",
        "first_pairing",
        "interrupted_resume",
        "cache_swarm",
    ] {
        assert!(
            workflow_classes.contains(required_class),
            "workflow catalog must cover {required_class}"
        );
    }

    let selected = string_set(&report, "selected_workflow_ids");
    for required_smoke in [
        "one_huge_file",
        "relay_only_transfer",
        "mailbox_transfer",
        "first_pairing_transfer",
        "interrupted_resume_transfer",
        "cache_swarm_get",
    ] {
        assert!(
            selected.contains(required_smoke),
            "smoke mode must include {required_smoke}"
        );
    }
}

#[test]
fn metric_budgets_and_bottleneck_classes_are_stable() {
    let report = run_contract_smoke();
    let metrics = array(&report, "metric_budgets")
        .iter()
        .map(|metric| {
            metric["metric"]
                .as_str()
                .expect("metric name must be string")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    for required_metric in [
        "time_to_first_verified_file_ms",
        "time_to_usable_prefix_ms",
        "whole_object_commit_ms",
        "resume_after_interruption_ms",
        "bytes_wasted",
        "cpu_ms_per_gib",
        "memory_peak_bytes",
        "operator_action_count",
        "failure_explanation_clarity_score",
    ] {
        assert!(
            metrics.contains(required_metric),
            "metric budget must include {required_metric}"
        );
    }

    let classes = string_set(&report, "failure_bottleneck_classes");
    for required_class in [
        "path",
        "disk",
        "cpu",
        "repair",
        "relay",
        "permission",
        "protocol",
        "user_policy",
    ] {
        assert!(
            classes.contains(required_class),
            "failure bottleneck catalog must include {required_class}"
        );
    }
}

#[test]
fn scheduler_workload_profiles_cover_atp_e5_gate_surfaces() {
    let report = run_contract_smoke();
    assert_eq!(
        report["scheduler_profile_schema_version"].as_str(),
        Some(SCHEDULER_PROFILE_SCHEMA_VERSION)
    );
    assert_eq!(
        report["scheduler_benchmark_gate"]["schema_version"].as_str(),
        Some(SCHEDULER_GATE_SCHEMA_VERSION)
    );
    assert_eq!(
        report["scheduler_benchmark_gate"]["bead_id"].as_str(),
        Some("asupersync-nva98g")
    );

    let profile_classes = array(&report, "scheduler_workload_profiles")
        .iter()
        .map(|profile| {
            profile["workload_class"]
                .as_str()
                .expect("workload_class must be string")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    for required_class in [
        "bulk_file",
        "sync_tree",
        "media",
        "sparse_image",
        "artifact",
        "stream",
        "relay_only",
        "lossy",
        "high_bdp",
        "mobile_unstable",
    ] {
        assert!(
            profile_classes.contains(required_class),
            "scheduler workload catalog must cover {required_class}"
        );
    }

    let scheduler_metrics = array(&report, "scheduler_metric_budgets")
        .iter()
        .map(|metric| {
            metric["metric"]
                .as_str()
                .expect("scheduler metric name must be string")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    for required_metric in [
        "wall_clock_ms",
        "verified_completion",
        "time_to_first_usable_file_ms",
        "bytes_wasted",
        "cpu_ms_per_gib",
        "memory_peak_bytes",
        "disk_amplification_ratio",
        "queueing_pressure_score",
        "repair_roi_score",
    ] {
        assert!(
            scheduler_metrics.contains(required_metric),
            "scheduler metric budget must include {required_metric}"
        );
    }

    let signals = string_set(
        &report["scheduler_benchmark_gate"],
        "required_scheduler_signals",
    );
    for required_signal in [
        "chunk_priorities",
        "stream_priorities",
        "hedging",
        "pressure_feedback",
        "repair_decision",
    ] {
        assert!(
            signals.contains(required_signal),
            "scheduler benchmark gate must require {required_signal}"
        );
    }
}

#[test]
fn benchmark_cartel_public_report_covers_regression_surfaces() {
    let report = run_contract_smoke();
    assert_eq!(
        report["benchmark_report_schema_version"].as_str(),
        Some(BENCHMARK_REPORT_SCHEMA_VERSION)
    );

    let benchmark_report_path = artifact_path(&report, "benchmark_report");
    let benchmark_report: Value = serde_json::from_str(
        &std::fs::read_to_string(&benchmark_report_path)
            .expect("benchmark report artifact must be readable"),
    )
    .expect("benchmark report must be JSON");
    assert_eq!(
        benchmark_report["schema_version"].as_str(),
        Some(BENCHMARK_REPORT_SCHEMA_VERSION)
    );
    assert_eq!(
        benchmark_report["bead_id"].as_str(),
        Some("asupersync-2e1wev")
    );
    assert_eq!(benchmark_report["status"].as_str(), Some("pass"));

    for required_field in [
        "workflow_count",
        "required_lane_count",
        "optional_lane_count",
        "skipped_count",
        "failed_count",
    ] {
        assert!(
            !benchmark_report["public_dashboard"][required_field].is_null(),
            "public dashboard must include {required_field}"
        );
    }

    let required_profiles = string_set(&benchmark_report, "required_profile_classes");
    for required_profile in ["bulk_file", "sync_tree", "lossy", "relay_only"] {
        assert!(
            required_profiles.contains(required_profile),
            "benchmark cartel must require {required_profile}"
        );
    }
    let manual_profiles = string_set(&benchmark_report, "manual_or_release_only_profile_classes");
    for manual_profile in ["high_bdp", "mobile_unstable"] {
        assert!(
            manual_profiles.contains(manual_profile),
            "report must distinguish manual/release-only {manual_profile}"
        );
    }

    let rows = array(&benchmark_report, "rows");
    let row_profile_classes = rows
        .iter()
        .map(|row| {
            row["profile_class"]
                .as_str()
                .expect("row profile_class must be string")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    for required_profile in ["bulk_file", "sync_tree", "lossy", "relay_only"] {
        assert!(
            row_profile_classes.contains(required_profile),
            "smoke benchmark rows must include {required_profile}"
        );
    }

    let row_workflows = rows
        .iter()
        .map(|row| {
            row["workflow_id"]
                .as_str()
                .expect("row workflow_id must be string")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    for required_workflow in [
        "one_huge_file",
        "sync_tree_small_edits",
        "interrupted_resume_transfer",
        "relay_only_transfer",
    ] {
        assert!(
            row_workflows.contains(required_workflow),
            "local reduced-size e2e report must include {required_workflow}"
        );
    }

    for row in rows {
        for required_field in [
            "command_line",
            "path_summary",
            "scheduler_decisions",
            "repair_decision",
            "disk_metrics",
            "benchmark_metrics",
            "baseline_normalization",
            "threshold_comparison",
            "skip_classification",
            "proof_root",
            "replay_pointer",
        ] {
            assert!(
                !row[required_field].is_null(),
                "{} must include benchmark row field {required_field}",
                row["workflow_id"].as_str().unwrap_or("<unknown>")
            );
        }
        for required_metric in [
            "verified_completion_time_ms",
            "resume_time_after_crash_ms",
            "bytes_on_wire",
            "cpu_ms_per_gib",
            "memory_peak_bytes",
            "disk_amplification_ratio",
            "time_to_first_usable_file_ms",
            "failure_reproducibility",
        ] {
            assert!(
                !row["benchmark_metrics"][required_metric].is_null(),
                "{} must include benchmark metric {required_metric}",
                row["workflow_id"].as_str().unwrap_or("<unknown>")
            );
        }
        let comparisons = row["threshold_comparison"]
            .as_array()
            .expect("threshold comparison must be array");
        assert!(
            comparisons
                .iter()
                .any(
                    |comparison| comparison["metric"].as_str() == Some("wall_clock_ms")
                        && comparison["passed"].is_boolean()
                ),
            "threshold comparison must include wall_clock_ms pass/fail"
        );
    }
}

#[test]
fn emitted_artifacts_have_required_schema_and_replay_fields() {
    let report = run_contract_smoke();
    assert_eq!(report["status"].as_str(), Some("pass"));

    for key in [
        "summary",
        "run_report",
        "structured_events",
        "benchmark_report",
        "fixture_manifest",
        "replay_pointer",
    ] {
        let path = artifact_path(&report, key);
        assert!(path.exists(), "artifact {key} must exist at {path:?}");
    }

    let summary = std::fs::read_to_string(artifact_path(&report, "summary"))
        .expect("summary artifact must be readable");
    assert!(
        summary.lines().count() <= 12,
        "human summary must stay concise"
    );
    assert!(summary.contains("ATP-N9 workflow acceptance summary"));

    let events_raw = std::fs::read_to_string(artifact_path(&report, "structured_events"))
        .expect("events artifact must be readable");
    let events = events_raw
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event line must be JSON"))
        .collect::<Vec<_>>();
    assert!(!events.is_empty(), "runner must emit at least one event");

    for event in events {
        assert_eq!(event["schema_version"].as_str(), Some(EVENT_SCHEMA_VERSION));
        for required in [
            "command_line",
            "profile",
            "transfer_id",
            "path_summary",
            "manifest_root",
            "proof_root",
            "metrics",
            "thresholds",
            "scheduler_profile",
            "scheduler_decisions",
            "regression_thresholds",
            "bottleneck_classification",
            "failure_explanation",
            "replay_pointer",
        ] {
            assert!(
                !event[required].is_null(),
                "{} must include required event field {required}",
                event["workflow_id"].as_str().unwrap_or("<unknown>")
            );
        }
        assert!(
            event["replay_pointer"]["command"]
                .as_str()
                .expect("replay command must be string")
                .contains(SCRIPT_PATH),
            "replay pointer must name the ATP-N9 runner"
        );
        assert!(
            event["path_summary"]["path_modes"]
                .as_array()
                .expect("path_modes must be array")
                .iter()
                .all(Value::is_string),
            "path summary must expose path mode strings"
        );
        assert_eq!(
            event["scheduler_decisions"]["schema_version"].as_str(),
            Some(SCHEDULER_PROFILE_SCHEMA_VERSION)
        );
        for required_signal in [
            "chunk_priorities",
            "stream_priorities",
            "hedging",
            "pressure_feedback",
            "repair_decision",
        ] {
            assert!(
                !event["scheduler_decisions"][required_signal].is_null(),
                "{} must include scheduler signal {required_signal}",
                event["workflow_id"].as_str().unwrap_or("<unknown>")
            );
        }
        for required_metric in [
            "wall_clock_ms",
            "verified_completion",
            "time_to_first_usable_file_ms",
            "disk_amplification_ratio",
            "queueing_pressure_score",
            "repair_roi_score",
        ] {
            assert!(
                !event["metrics"][required_metric].is_null(),
                "{} must include ATP-E5 metric {required_metric}",
                event["workflow_id"].as_str().unwrap_or("<unknown>")
            );
        }
    }
}
