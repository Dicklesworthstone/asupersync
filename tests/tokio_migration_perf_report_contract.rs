#![allow(dead_code, missing_docs)]

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;

const CONTRACT_PATH: &str = "artifacts/tokio_migration_perf_report_contract_v1.json";
const SHADOW_CONTRACT_PATH: &str = "artifacts/tokio_migration_shadow_workload_contract_v1.json";

#[derive(Debug, Deserialize, Serialize)]
struct PerfReportContract {
    contract_version: String,
    schema_version: String,
    generated_for_bead: String,
    shadow_runner: String,
    source_workload_contract: String,
    evidence_freshness_policy: EvidenceFreshnessPolicy,
    percentile_policy: PercentilePolicy,
    required_report_fields: Vec<String>,
    required_log_fields: Vec<String>,
    validation_commands: Vec<String>,
    report_cards: Vec<ReportCard>,
    real_host_templates: Vec<RealHostTemplate>,
    refusal_cases: Vec<RefusalCase>,
}

#[derive(Debug, Deserialize, Serialize)]
struct EvidenceFreshnessPolicy {
    missing_evidence: String,
    stale_evidence: String,
    max_age_seconds: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct PercentilePolicy {
    algorithm: String,
    small_sample_p999_policy: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct ReportCard {
    report_id: String,
    source_shadow_scenario_id: String,
    scale_mode: String,
    host_fingerprint: HostFingerprint,
    workload_seed: String,
    sample_count: usize,
    measurement_window_nanos: u64,
    completed_operations: u64,
    latency_samples_micros: Vec<u64>,
    percentiles_micros: Percentiles,
    throughput_ops_per_sec: u64,
    queue_depth_samples: Vec<u64>,
    queue_depth_summary: QueueDepthSummary,
    cancellation_debt_units: CancellationDebtUnits,
    memory_pressure: MemoryPressure,
    verdict: String,
    classification: String,
    operator_override_text: String,
    artifact_paths: ArtifactPaths,
    exact_command: String,
    projection_hash: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct HostFingerprint {
    kind: String,
    hostname: String,
    cpu_threads: u64,
    memory_gib: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct Percentiles {
    p50: u64,
    p95: u64,
    p99: u64,
    p999: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct QueueDepthSummary {
    max: u64,
    mean_milli: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct CancellationDebtUnits {
    tokio_reference: i64,
    asupersync: i64,
    delta: i64,
}

#[derive(Debug, Deserialize, Serialize)]
struct MemoryPressure {
    peak_bytes: u64,
    steady_bytes: u64,
    verdict: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct ArtifactPaths {
    report_jsonl: String,
    summary_json: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct RealHostTemplate {
    template_id: String,
    scale_mode: String,
    min_cpu_cores: u64,
    min_memory_gib: u64,
    required_fields: Vec<String>,
    operator_verdict: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct RefusalCase {
    case_id: String,
    source_shadow_scenario_id: String,
    reason: String,
    max_age_seconds: Option<u64>,
    verdict: String,
    operator_next_step: String,
}

fn repo_path(path: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn load_contract() -> PerfReportContract {
    let text = std::fs::read_to_string(repo_path(CONTRACT_PATH))
        .expect("perf report contract should exist");
    serde_json::from_str(&text).expect("perf report contract should parse")
}

fn load_shadow_scenario_ids() -> BTreeSet<String> {
    let text = std::fs::read_to_string(repo_path(SHADOW_CONTRACT_PATH))
        .expect("shadow workload contract should exist");
    let value: Value = serde_json::from_str(&text).expect("shadow workload contract should parse");
    value["scenarios"]
        .as_array()
        .expect("shadow scenarios should be an array")
        .iter()
        .map(|scenario| {
            scenario["scenario_id"]
                .as_str()
                .expect("shadow scenario id should be a string")
                .to_string()
        })
        .collect()
}

fn nearest_rank(sorted: &[u64], numerator: usize, denominator: usize) -> u64 {
    assert!(!sorted.is_empty(), "percentiles require samples");
    let rank = (sorted.len() * numerator)
        .div_ceil(denominator)
        .clamp(1, sorted.len());
    sorted[rank - 1]
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn projection_text(card: &ReportCard) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        card.report_id,
        card.source_shadow_scenario_id,
        card.scale_mode,
        card.sample_count,
        card.percentiles_micros.p50,
        card.percentiles_micros.p95,
        card.percentiles_micros.p99,
        card.percentiles_micros.p999,
        card.throughput_ops_per_sec,
        card.queue_depth_summary.max,
        card.queue_depth_summary.mean_milli,
        card.cancellation_debt_units.delta,
        card.memory_pressure.verdict,
        card.verdict,
        card.classification
    )
}

fn projection_hash(card: &ReportCard) -> u64 {
    fnv1a64(projection_text(card).as_bytes())
}

#[test]
fn contract_declares_stable_version_and_fail_closed_evidence_policy() {
    let contract = load_contract();

    assert_eq!(contract.contract_version, "tokio-migration-perf-report-v1");
    assert_eq!(
        contract.schema_version,
        "tokio-migration-perf-report-schema-v1"
    );
    assert_eq!(contract.generated_for_bead, "asupersync-miglat");
    assert_eq!(
        contract.shadow_runner,
        "scripts/run_tokio_migration_shadow_workload_smoke.sh"
    );
    assert_eq!(
        contract.source_workload_contract,
        "artifacts/tokio_migration_shadow_workload_contract_v1.json"
    );
    assert_eq!(
        contract.evidence_freshness_policy.missing_evidence,
        "refuse"
    );
    assert_eq!(contract.evidence_freshness_policy.stale_evidence, "refuse");
    assert_eq!(
        contract.percentile_policy.algorithm,
        "nearest_rank_sorted_samples"
    );
    assert_eq!(
        contract.percentile_policy.small_sample_p999_policy,
        "max_sample"
    );
}

#[test]
fn report_cards_link_to_shadow_workloads_and_include_required_fields() {
    let contract = load_contract();
    let shadow_ids = load_shadow_scenario_ids();
    let required_fields: BTreeSet<_> = contract.required_report_fields.iter().cloned().collect();

    for card in &contract.report_cards {
        assert!(
            shadow_ids.contains(&card.source_shadow_scenario_id),
            "missing shadow scenario for {}",
            card.report_id
        );
        let row = serde_json::to_value(card).expect("report card should serialize");
        for field in &required_fields {
            assert!(row.get(field).is_some(), "missing field {field}: {row}");
        }
        assert!(card.artifact_paths.report_jsonl.ends_with(".jsonl"));
        assert!(card.artifact_paths.summary_json.ends_with(".json"));
        assert!(card.exact_command.contains(&card.source_shadow_scenario_id));
    }
}

#[test]
fn percentiles_are_sorted_nearest_rank_values() {
    let contract = load_contract();

    for card in &contract.report_cards {
        assert_eq!(card.sample_count, card.latency_samples_micros.len());
        let mut sorted = card.latency_samples_micros.clone();
        sorted.sort_unstable();

        assert_eq!(card.percentiles_micros.p50, nearest_rank(&sorted, 50, 100));
        assert_eq!(card.percentiles_micros.p95, nearest_rank(&sorted, 95, 100));
        assert_eq!(card.percentiles_micros.p99, nearest_rank(&sorted, 99, 100));
        assert_eq!(
            card.percentiles_micros.p999,
            nearest_rank(&sorted, 999, 1000)
        );
        if card.sample_count < 1000 {
            assert_eq!(
                card.percentiles_micros.p999,
                *sorted.last().expect("samples exist"),
                "small-sample p999 should fail closed to max sample"
            );
        }
    }
}

#[test]
fn throughput_and_queue_depth_summaries_are_stable() {
    let contract = load_contract();

    for card in &contract.report_cards {
        assert!(card.measurement_window_nanos > 0);
        let expected_throughput =
            card.completed_operations * 1_000_000_000 / card.measurement_window_nanos;
        assert_eq!(card.throughput_ops_per_sec, expected_throughput);

        let max_depth = card.queue_depth_samples.iter().copied().max().unwrap_or(0);
        let mean_milli = card.queue_depth_samples.iter().sum::<u64>() * 1000
            / card.queue_depth_samples.len() as u64;
        assert_eq!(card.queue_depth_summary.max, max_depth);
        assert_eq!(card.queue_depth_summary.mean_milli, mean_milli);
    }
}

#[test]
fn cancellation_debt_memory_pressure_and_no_win_verdicts_are_explicit() {
    let contract = load_contract();

    for card in &contract.report_cards {
        assert_eq!(
            card.cancellation_debt_units.delta,
            card.cancellation_debt_units.tokio_reference - card.cancellation_debt_units.asupersync
        );
        assert!(card.memory_pressure.peak_bytes >= card.memory_pressure.steady_bytes);
        assert!(!card.operator_override_text.is_empty());
        assert!(
            !card
                .operator_override_text
                .to_ascii_lowercase()
                .contains("secret"),
            "operator text must stay redacted"
        );
    }

    assert!(
        contract
            .report_cards
            .iter()
            .any(|card| card.classification == "no_win"
                && card.verdict == "hold_conservative_no_win"),
        "contract must preserve a no-win hold row"
    );
}

#[test]
fn projection_hashes_are_stable() {
    let contract = load_contract();

    for card in &contract.report_cards {
        assert_eq!(
            projection_hash(card),
            card.projection_hash,
            "projection hash drifted for {}",
            card.report_id
        );
    }
}

#[test]
fn refusal_cases_and_real_host_templates_fail_closed() {
    let contract = load_contract();
    let shadow_ids = load_shadow_scenario_ids();

    let reasons: BTreeSet<_> = contract
        .refusal_cases
        .iter()
        .map(|case| case.reason.as_str())
        .collect();
    assert!(reasons.contains("missing_performance_evidence"));
    assert!(reasons.contains("stale_performance_evidence"));

    for case in &contract.refusal_cases {
        assert!(shadow_ids.contains(&case.source_shadow_scenario_id));
        assert!(case.verdict.starts_with("refuse_"));
        assert!(!case.operator_next_step.is_empty());
        if case.reason == "stale_performance_evidence" {
            assert_eq!(
                case.max_age_seconds,
                Some(contract.evidence_freshness_policy.max_age_seconds)
            );
        }
    }

    let template = contract
        .real_host_templates
        .iter()
        .find(|template| template.template_id == "TM-PERF-REALHOST-64C-256G")
        .expect("64-core template should exist");
    assert_eq!(template.scale_mode, "real-host-template");
    assert!(template.min_cpu_cores >= 64);
    assert!(template.min_memory_gib >= 256);
    assert_eq!(template.operator_verdict, "template_only_not_ci_evidence");
    for field in ["p99_micros", "p999_micros", "artifact_paths"] {
        assert!(
            template
                .required_fields
                .iter()
                .any(|required| required == field),
            "template missing required field {field}"
        );
    }
}

#[test]
fn validation_commands_use_rch_and_shadow_runner_execution() {
    let contract = load_contract();
    let joined = contract.validation_commands.join("\n");

    assert!(joined.contains("rch exec -- rustfmt"));
    assert!(joined.contains("rch exec -- env CARGO_INCREMENTAL=0"));
    assert!(
        joined.contains("cargo test -p asupersync --test tokio_migration_perf_report_contract")
    );
    assert!(joined.contains("scripts/run_tokio_migration_shadow_workload_smoke.sh"));
    assert!(joined.contains("--dry-run"));
    assert!(joined.contains("--execute"));

    for required in [
        "exact_command",
        "scale_mode",
        "host_fingerprint",
        "cpu_threads",
        "memory_gib",
        "p99_micros",
        "p999_micros",
        "throughput_ops_per_sec",
        "cancellation_debt_delta",
        "memory_pressure_peak_bytes",
    ] {
        assert!(
            contract
                .required_log_fields
                .iter()
                .any(|field| field == required),
            "missing required log field {required}"
        );
    }
}
