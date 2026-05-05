//! Runtime latency-budget certificate contract invariants (asupersync-d87ytw.2).

#![allow(missing_docs)]

use asupersync::observability::{
    TAIL_LATENCY_BUDGET_CERTIFICATE_SCHEMA_VERSION, TAIL_LATENCY_COMPACT_EVENT_SCHEMA_VERSION,
    TAIL_LATENCY_TAXONOMY_CONTRACT_VERSION, TailLatencyBudgetCertificate,
    TailLatencyBudgetEvidence, TailLatencyBudgetGate, TailLatencyBudgetQuantiles,
    TailLatencyBudgetUncertainty, TailLatencyBudgetVerdict, TailLatencyCompactEvent,
    TailLatencyCompactSample, TailLatencyEmitterConfig, emit_tail_latency_compact_event,
    tail_latency_taxonomy_contract, verify_tail_latency_budget_certificate,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const DOC_PATH: &str = "docs/runtime_latency_budget_certificate_contract.md";
const ARTIFACT_PATH: &str = "artifacts/runtime_latency_budget_certificate_v1.json";
const RUNNER_PATH: &str = "scripts/run_latency_budget_certificate_smoke.sh";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_doc() -> String {
    std::fs::read_to_string(repo_root().join(DOC_PATH))
        .expect("failed to load latency-budget certificate doc")
}

fn load_artifact() -> Value {
    let raw = std::fs::read_to_string(repo_root().join(ARTIFACT_PATH))
        .expect("failed to load latency-budget certificate artifact");
    serde_json::from_str(&raw).expect("failed to parse latency-budget artifact")
}

fn load_runner() -> String {
    std::fs::read_to_string(repo_root().join(RUNNER_PATH))
        .expect("failed to load latency-budget certificate runner")
}

fn complete_event(scenario_id: &str, event_id: &str) -> TailLatencyCompactEvent {
    emit_tail_latency_compact_event(
        TailLatencyEmitterConfig::enabled_core(),
        scenario_id,
        event_id,
        TailLatencyCompactSample::new(18_000)
            .with_ready_queue_depth(18)
            .with_poll_count(7)
            .with_events_received(4)
            .with_retries_total_delay_ns(2_000)
            .with_synchronization_lock_wait_ns(1_000)
            .with_allocator_live_allocations(22),
    )
    .expect("complete tail event should emit")
    .expect("enabled emitter should return an event")
}

fn certificate_gate() -> TailLatencyBudgetGate {
    TailLatencyBudgetGate::new(20_000, 64, 20_000, 9_000, 10, 500)
}

fn base_evidence(
    certificate_id: &str,
    scenario_id: &str,
    event: TailLatencyCompactEvent,
) -> TailLatencyBudgetEvidence {
    TailLatencyBudgetEvidence::new(
        certificate_id,
        scenario_id,
        "candidate-balanced",
        "conservative-baseline",
        format!("bash {RUNNER_PATH} --execute --scenario {scenario_id}"),
        certificate_gate(),
    )
    .with_sample_window(256, 7)
    .with_quantiles(TailLatencyBudgetQuantiles::new(
        9_000, 13_000, 16_000, 17_000,
    ))
    .with_uncertainty(TailLatencyBudgetUncertainty::new(250, 750))
    .with_regression_window(17_500, 17_000)
    .with_tail_events(vec![event])
}

fn certificate_report_row(certificate: &TailLatencyBudgetCertificate) -> Value {
    json!({
        "certificate_id": certificate.certificate_id,
        "certificate_hash": certificate.certificate_hash,
        "scenario_id": certificate.scenario_id,
        "candidate_id": certificate.candidate_id,
        "fallback_profile": certificate.fallback_profile,
        "taxonomy_version": certificate.taxonomy_version,
        "verdict": certificate.verdict.as_str(),
        "p50_latency_ns": certificate.p50_latency_ns,
        "p95_latency_ns": certificate.p95_latency_ns,
        "p99_latency_ns": certificate.p99_latency_ns,
        "p999_latency_ns": certificate.p999_latency_ns,
        "budget_p999_latency_ns": certificate.budget_p999_latency_ns,
        "term_breakdown": certificate.term_breakdown,
        "uncertainty_interval": {
            "lower_bound_ns": certificate.uncertainty_lower_bound_ns,
            "upper_bound_ns": certificate.uncertainty_upper_bound_ns,
        },
        "sample_count": certificate.sample_count,
        "unknown_residual_ns": certificate.unknown_residual_ns,
        "unknown_residual_basis_points": certificate.unknown_residual_basis_points,
        "fallback_reason": certificate.fallback_reason,
        "reason_codes": certificate.reason_codes,
        "replay_command": certificate.replay_command,
    })
}

#[test]
fn doc_exists_and_references_contract_surface() {
    assert!(Path::new(DOC_PATH).exists(), "doc must exist");
    let doc = load_doc();
    for required in [
        "asupersync-d87ytw.2",
        "Purpose",
        "Verifier Inputs",
        "Verdicts",
        "Fail-Closed Rules",
        "No-Win Rules",
        "Smoke Runner",
        "Validation",
        "Cross-References",
        ARTIFACT_PATH,
        RUNNER_PATH,
        "src/observability/diagnostics.rs",
    ] {
        assert!(doc.contains(required), "doc must mention {required}");
    }
}

#[test]
fn artifact_versions_match_code_and_taxonomy() {
    let artifact = load_artifact();
    assert_eq!(
        artifact["contract_version"].as_str(),
        Some(TAIL_LATENCY_BUDGET_CERTIFICATE_SCHEMA_VERSION)
    );
    assert_eq!(
        artifact["tail_taxonomy_contract_version"].as_str(),
        Some(TAIL_LATENCY_TAXONOMY_CONTRACT_VERSION)
    );
    assert_eq!(
        artifact["compact_event_schema_version"].as_str(),
        Some(TAIL_LATENCY_COMPACT_EVENT_SCHEMA_VERSION)
    );
    assert_eq!(artifact["bead_id"].as_str(), Some("asupersync-d87ytw.2"));
    assert_eq!(artifact["runner_script"].as_str(), Some(RUNNER_PATH));
}

#[test]
fn artifact_covers_all_taxonomy_terms_and_report_fields() {
    let artifact = load_artifact();
    let contract = tail_latency_taxonomy_contract();
    let expected_terms: BTreeSet<String> = contract
        .terms
        .iter()
        .map(|term| term.term_id.clone())
        .collect();
    let actual_terms: BTreeSet<String> = artifact["term_breakdown_terms"]
        .as_array()
        .expect("term_breakdown_terms must be array")
        .iter()
        .map(|term| term.as_str().expect("term must be string").to_string())
        .collect();
    assert_eq!(actual_terms, expected_terms);

    let report_fields: BTreeSet<&str> = artifact["required_report_fields"]
        .as_array()
        .expect("required_report_fields must be array")
        .iter()
        .map(|field| field.as_str().expect("field must be string"))
        .collect();
    for required in [
        "certificate_id",
        "certificate_hash",
        "scenario_id",
        "candidate_id",
        "fallback_profile",
        "taxonomy_version",
        "p50_latency_ns",
        "p95_latency_ns",
        "p99_latency_ns",
        "p999_latency_ns",
        "budget_p999_latency_ns",
        "term_breakdown",
        "uncertainty_interval",
        "sample_count",
        "unknown_residual_ns",
        "unknown_residual_basis_points",
        "fallback_reason",
        "reason_codes",
        "replay_command",
    ] {
        assert!(
            report_fields.contains(required),
            "report field missing {required}"
        );
    }
}

#[test]
fn runner_exists_and_routes_execute_through_rch() {
    assert!(Path::new(RUNNER_PATH).exists(), "runner must exist");
    let runner = load_runner();
    for required in [
        "--list",
        "--dry-run",
        "--execute",
        "rch exec -- env CARGO_INCREMENTAL=0",
        "ASUPERSYNC_LATENCY_BUDGET_CERTIFICATE_REPORT_PATH",
        "LATENCY_BUDGET_CERTIFICATE_REPORT_JSON_BEGIN",
        "certificate_hash",
        "fallback_reason",
    ] {
        assert!(runner.contains(required), "runner must contain {required}");
    }
}

#[test]
fn verifier_accepts_pass_no_win_and_fail_closed_rows() {
    let pass = verify_tail_latency_budget_certificate(base_evidence(
        "latency-budget-cert-pass",
        "LATENCY-BUDGET-PASS",
        complete_event("LATENCY-BUDGET-PASS", "event-pass"),
    ));
    assert_eq!(pass.verdict, TailLatencyBudgetVerdict::Pass);
    assert!(pass.reason_codes.is_empty());

    let no_win = verify_tail_latency_budget_certificate(
        base_evidence(
            "latency-budget-cert-no-win",
            "LATENCY-BUDGET-NO-WIN",
            complete_event("LATENCY-BUDGET-NO-WIN", "event-no-win"),
        )
        .with_quantiles(TailLatencyBudgetQuantiles::new(
            9_000, 18_000, 20_000, 22_000,
        ))
        .with_uncertainty(TailLatencyBudgetUncertainty::new(500, 1_000))
        .with_regression_window(17_500, 21_000),
    );
    assert_eq!(no_win.verdict, TailLatencyBudgetVerdict::NoWin);
    assert!(
        no_win
            .reason_codes
            .contains(&"p999_budget_exceeded".to_string())
    );

    let fail_closed = verify_tail_latency_budget_certificate(
        TailLatencyBudgetEvidence::new(
            "latency-budget-cert-fail-closed",
            "LATENCY-BUDGET-FAIL-CLOSED",
            "candidate-mean-only",
            "conservative-baseline",
            format!("bash {RUNNER_PATH} --execute --scenario LATENCY-BUDGET-FAIL-CLOSED"),
            certificate_gate(),
        )
        .with_sample_window(16, 11)
        .with_uncertainty(TailLatencyBudgetUncertainty::new(0, 10))
        .with_regression_window(1_000, 900)
        .with_tail_events(vec![complete_event(
            "LATENCY-BUDGET-FAIL-CLOSED",
            "event-fail-closed",
        )]),
    );
    assert_eq!(fail_closed.verdict, TailLatencyBudgetVerdict::FailClosed);
    assert!(
        fail_closed
            .reason_codes
            .contains(&"missing_quantiles_mean_only_evidence".to_string())
    );
    assert!(
        fail_closed
            .reason_codes
            .contains(&"stale_calibration".to_string())
    );

    let missing_identity = verify_tail_latency_budget_certificate(
        TailLatencyBudgetEvidence::new(
            "latency-budget-cert-missing-identity",
            "LATENCY-BUDGET-MISSING-IDENTITY",
            " ",
            " ",
            format!("bash {RUNNER_PATH} --execute --scenario LATENCY-BUDGET-MISSING-IDENTITY"),
            certificate_gate(),
        )
        .with_sample_window(256, 7)
        .with_quantiles(TailLatencyBudgetQuantiles::new(
            9_000, 13_000, 16_000, 17_000,
        ))
        .with_uncertainty(TailLatencyBudgetUncertainty::new(250, 750))
        .with_regression_window(17_500, 17_000)
        .with_tail_events(vec![complete_event(
            "LATENCY-BUDGET-MISSING-IDENTITY",
            "event-missing-identity",
        )]),
    );
    assert_eq!(
        missing_identity.verdict,
        TailLatencyBudgetVerdict::FailClosed
    );
    assert!(
        missing_identity
            .reason_codes
            .contains(&"empty_candidate_id".to_string())
    );
    assert!(
        missing_identity
            .reason_codes
            .contains(&"empty_fallback_profile".to_string())
    );
}

#[test]
fn latency_budget_certificate_smoke_emits_report() {
    let report_path = std::env::var("ASUPERSYNC_LATENCY_BUDGET_CERTIFICATE_REPORT_PATH")
        .unwrap_or_else(|_| "target/latency-budget-certificate-smoke/report.json".to_string());
    let replay_command = format!(
        "bash {RUNNER_PATH} --execute --output-root target/latency-budget-certificate-smoke"
    );

    let pass = verify_tail_latency_budget_certificate(base_evidence(
        "latency-budget-cert-pass",
        "LATENCY-BUDGET-PASS",
        complete_event("LATENCY-BUDGET-PASS", "event-pass"),
    ));
    let no_win = verify_tail_latency_budget_certificate(
        base_evidence(
            "latency-budget-cert-no-win",
            "LATENCY-BUDGET-NO-WIN",
            complete_event("LATENCY-BUDGET-NO-WIN", "event-no-win"),
        )
        .with_quantiles(TailLatencyBudgetQuantiles::new(
            9_000, 18_000, 20_000, 22_000,
        ))
        .with_uncertainty(TailLatencyBudgetUncertainty::new(500, 1_000))
        .with_regression_window(17_500, 21_000),
    );
    let fail_closed = verify_tail_latency_budget_certificate(
        TailLatencyBudgetEvidence::new(
            "latency-budget-cert-fail-closed",
            "LATENCY-BUDGET-FAIL-CLOSED",
            "candidate-mean-only",
            "conservative-baseline",
            format!("bash {RUNNER_PATH} --execute --scenario LATENCY-BUDGET-FAIL-CLOSED"),
            certificate_gate(),
        )
        .with_sample_window(16, 11)
        .with_uncertainty(TailLatencyBudgetUncertainty::new(0, 10))
        .with_regression_window(1_000, 900)
        .with_tail_events(vec![complete_event(
            "LATENCY-BUDGET-FAIL-CLOSED",
            "event-fail-closed",
        )]),
    );

    let report = json!({
        "schema_version": "latency-budget-certificate-smoke-report-v1",
        "contract_version": TAIL_LATENCY_BUDGET_CERTIFICATE_SCHEMA_VERSION,
        "bead_id": "asupersync-d87ytw.2",
        "status": "passed",
        "artifact_path": report_path,
        "replay_command": replay_command,
        "rows": [
            certificate_report_row(&pass),
            certificate_report_row(&no_win),
            certificate_report_row(&fail_closed),
        ],
    });

    println!("LATENCY_BUDGET_CERTIFICATE_REPORT_JSON_BEGIN");
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("serialize smoke report")
    );
    println!("LATENCY_BUDGET_CERTIFICATE_REPORT_JSON_END");

    let report_path = PathBuf::from(
        report["artifact_path"]
            .as_str()
            .expect("artifact path must be string"),
    );
    if let Some(parent) = report_path.parent() {
        std::fs::create_dir_all(parent).expect("create report parent");
    }
    std::fs::write(
        &report_path,
        serde_json::to_vec_pretty(&report).expect("serialize report file"),
    )
    .expect("write smoke report");
}
