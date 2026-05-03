#![allow(missing_docs)]

use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::time::{Duration, Instant};

use asupersync::observability::otlp_trace_exporter::{
    LoadSheddingTraceExporter, MockOtlpHttpExporter, OtlpBrownoutAction, OtlpSpan, SpanBatch,
    TraceExporter,
};
use asupersync::runtime::resource_monitor::{
    DegradationLevel, OverloadBrownoutEvidence, OverloadBrownoutLedger, OverloadBrownoutPhase,
    OverloadBrownoutProfile, OverloadBrownoutReason, TailRiskAdmissionDecision,
};
use asupersync::runtime::scheduler::swarm_evidence::SchedulerEvidenceMetrics;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const OTLP_BROWNOUT_CONTRACT_PATH_ENV: &str = "ASUPERSYNC_OTLP_BROWNOUT_CONTRACT_PATH";
const OTLP_BROWNOUT_SCENARIO_ENV: &str = "ASUPERSYNC_OTLP_BROWNOUT_SCENARIO";
const OTLP_BROWNOUT_REPORT_PATH_ENV: &str = "ASUPERSYNC_OTLP_BROWNOUT_REPORT_PATH";
const OTLP_BROWNOUT_REPORT_SCHEMA_VERSION: &str = "otlp-brownout-shedding-report-v1";
const OTLP_BROWNOUT_PROJECTION_SCHEMA_VERSION: &str = "otlp-brownout-shedding-projection-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OtlpBrownoutSmokeContract {
    contract_version: String,
    smoke_scenarios: Vec<OtlpBrownoutScenario>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OtlpBrownoutScenario {
    scenario_id: String,
    description: String,
    workload_class: String,
    output_root: String,
    execution_policy: String,
    workload_seed: u64,
    safe_fallback_profile: String,
    expected_winner_profile: String,
    brownout_profile: OverloadBrownoutProfile,
    fixture: OtlpBrownoutFixture,
    expected_report_projection: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OtlpBrownoutFixture {
    windows: Vec<OtlpBrownoutWindow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OtlpBrownoutWindow {
    window_id: String,
    use_shared_brownout: bool,
    previous_phase: OverloadBrownoutPhase,
    wake_to_run_p99_ns: u64,
    queue_residency_p99_ns: u64,
    ready_backlog_p99: usize,
    cancel_debt_p99: usize,
    memory_pressure_bps: Option<u16>,
    degradation_level: DegradationLevel,
    outer_tail_risk_decision: TailRiskAdmissionDecision,
    priorities: Vec<String>,
}

fn default_brownout_profile() -> OverloadBrownoutProfile {
    OverloadBrownoutProfile::default()
}

fn expected_projection_brownout_priority_gate() -> Value {
    json!({
        "schema_version": OTLP_BROWNOUT_PROJECTION_SCHEMA_VERSION,
        "scenario_id": "AA-OTLP-BROWNOUT-PRIORITY-GATE",
        "workload_class": "brownout-priority-gate",
        "workload_seed": 404404,
        "window_count": 2,
        "phase_sequence": ["degrade", "shed_optional"],
        "action_sequence": ["drop_low_priority", "retain_summary_only"],
        "fallback_windows": [],
        "fallback_activation_count": 0,
        "dropped_low_priority_spans": 2,
        "retained_summary_spans": 4,
        "queue_dropped_spans": 0,
        "exported_high_priority_spans": 3,
        "exported_low_priority_spans": 0,
        "final_shared_phase": "shed_optional",
        "final_shared_reason_codes": [
            "preserve_critical_surfaces",
            "observe_pressure",
            "degrade_pressure",
            "shed_optional_pressure",
            "tail_risk_outer_shed"
        ],
        "winner_profile": "brownout",
        "no_win_trigger": false
    })
}

fn expected_projection_standalone_fallback() -> Value {
    json!({
        "schema_version": OTLP_BROWNOUT_PROJECTION_SCHEMA_VERSION,
        "scenario_id": "AA-OTLP-BROWNOUT-STANDALONE-FALLBACK",
        "workload_class": "standalone-fallback",
        "workload_seed": 505505,
        "window_count": 1,
        "phase_sequence": ["normal"],
        "action_sequence": ["export_all"],
        "fallback_windows": ["fallback_export_all"],
        "fallback_activation_count": 1,
        "dropped_low_priority_spans": 0,
        "retained_summary_spans": 0,
        "queue_dropped_spans": 0,
        "exported_high_priority_spans": 2,
        "exported_low_priority_spans": 2,
        "final_shared_phase": "normal",
        "final_shared_reason_codes": [],
        "winner_profile": "standalone_fallback",
        "no_win_trigger": true
    })
}

fn default_otlp_brownout_contract() -> OtlpBrownoutSmokeContract {
    OtlpBrownoutSmokeContract {
        contract_version: "otlp-brownout-shedding-smoke-contract-v1".to_string(),
        smoke_scenarios: vec![
            OtlpBrownoutScenario {
                scenario_id: "AA-OTLP-BROWNOUT-PRIORITY-GATE".to_string(),
                description: "Shared brownout replay that drops low-priority OTLP spans in degrade mode and retains summary-only evidence in shed-optional mode.".to_string(),
                workload_class: "brownout-priority-gate".to_string(),
                output_root: "target/otlp-brownout-shedding-smoke".to_string(),
                execution_policy: "execute_or_dry_run".to_string(),
                workload_seed: 404404,
                safe_fallback_profile: "standalone_fallback".to_string(),
                expected_winner_profile: "brownout".to_string(),
                brownout_profile: default_brownout_profile(),
                fixture: OtlpBrownoutFixture {
                    windows: vec![
                        OtlpBrownoutWindow {
                            window_id: "degrade_drop_low_priority".to_string(),
                            use_shared_brownout: true,
                            previous_phase: OverloadBrownoutPhase::Observe,
                            wake_to_run_p99_ns: 228_000,
                            queue_residency_p99_ns: 246_000,
                            ready_backlog_p99: 208,
                            cancel_debt_p99: 56,
                            memory_pressure_bps: Some(8_820),
                            degradation_level: DegradationLevel::Moderate,
                            outer_tail_risk_decision: TailRiskAdmissionDecision::Defer,
                            priorities: vec![
                                "low".to_string(),
                                "high".to_string(),
                                "low".to_string(),
                                "high".to_string(),
                                "high".to_string(),
                            ],
                        },
                        OtlpBrownoutWindow {
                            window_id: "shed_summary_only".to_string(),
                            use_shared_brownout: true,
                            previous_phase: OverloadBrownoutPhase::Degrade,
                            wake_to_run_p99_ns: 308_000,
                            queue_residency_p99_ns: 322_000,
                            ready_backlog_p99: 264,
                            cancel_debt_p99: 72,
                            memory_pressure_bps: Some(9_450),
                            degradation_level: DegradationLevel::Heavy,
                            outer_tail_risk_decision: TailRiskAdmissionDecision::Shed,
                            priorities: vec![
                                "high".to_string(),
                                "low".to_string(),
                                "high".to_string(),
                                "low".to_string(),
                            ],
                        },
                    ],
                },
                expected_report_projection: expected_projection_brownout_priority_gate(),
            },
            OtlpBrownoutScenario {
                scenario_id: "AA-OTLP-BROWNOUT-STANDALONE-FALLBACK".to_string(),
                description: "Missing brownout evidence replay that keeps the OTLP exporter on standalone export-all behavior with an explicit fallback verdict.".to_string(),
                workload_class: "standalone-fallback".to_string(),
                output_root: "target/otlp-brownout-shedding-smoke".to_string(),
                execution_policy: "execute_or_dry_run".to_string(),
                workload_seed: 505505,
                safe_fallback_profile: "standalone_fallback".to_string(),
                expected_winner_profile: "standalone_fallback".to_string(),
                brownout_profile: default_brownout_profile(),
                fixture: OtlpBrownoutFixture {
                    windows: vec![OtlpBrownoutWindow {
                        window_id: "fallback_export_all".to_string(),
                        use_shared_brownout: false,
                        previous_phase: OverloadBrownoutPhase::Normal,
                        wake_to_run_p99_ns: 118_000,
                        queue_residency_p99_ns: 120_000,
                        ready_backlog_p99: 96,
                        cancel_debt_p99: 20,
                        memory_pressure_bps: Some(7_100),
                        degradation_level: DegradationLevel::None,
                        outer_tail_risk_decision: TailRiskAdmissionDecision::Admit,
                        priorities: vec![
                            "low".to_string(),
                            "high".to_string(),
                            "low".to_string(),
                            "high".to_string(),
                        ],
                    }],
                },
                expected_report_projection: expected_projection_standalone_fallback(),
            },
        ],
    }
}

fn load_otlp_brownout_contract() -> OtlpBrownoutSmokeContract {
    if let Ok(path) = std::env::var(OTLP_BROWNOUT_CONTRACT_PATH_ENV) {
        return serde_json::from_str(
            &fs::read_to_string(&path).expect("read OTLP brownout smoke contract"),
        )
        .expect("deserialize OTLP brownout smoke contract");
    }
    default_otlp_brownout_contract()
}

fn selected_otlp_brownout_scenario() -> String {
    std::env::var(OTLP_BROWNOUT_SCENARIO_ENV)
        .unwrap_or_else(|_| "AA-OTLP-BROWNOUT-PRIORITY-GATE".to_string())
}

fn maybe_write_otlp_brownout_report(path: &str, report: &Value) {
    let report_path = Path::new(path);
    if let Some(parent) = report_path.parent() {
        fs::create_dir_all(parent).expect("create OTLP brownout report directory");
    }
    fs::write(
        report_path,
        serde_json::to_string_pretty(report).expect("serialize OTLP brownout report"),
    )
    .expect("write OTLP brownout report");
}

fn hash_json_value(value: &Value) -> u64 {
    let mut hasher = DefaultHasher::new();
    serde_json::to_string(value)
        .expect("serialize OTLP brownout projection")
        .hash(&mut hasher);
    hasher.finish()
}

fn action_label(action: OtlpBrownoutAction) -> &'static str {
    match action {
        OtlpBrownoutAction::ExportAll => "export_all",
        OtlpBrownoutAction::DropLowPriority => "drop_low_priority",
        OtlpBrownoutAction::RetainSummaryOnly => "retain_summary_only",
    }
}

fn phase_label(phase: OverloadBrownoutPhase) -> &'static str {
    match phase {
        OverloadBrownoutPhase::Normal => "normal",
        OverloadBrownoutPhase::Observe => "observe",
        OverloadBrownoutPhase::Degrade => "degrade",
        OverloadBrownoutPhase::ShedOptional => "shed_optional",
        OverloadBrownoutPhase::Recovery => "recovery",
    }
}

fn reason_label(reason: OverloadBrownoutReason) -> &'static str {
    match reason {
        OverloadBrownoutReason::Disabled => "disabled",
        OverloadBrownoutReason::MissingEvidenceFallback => "missing_evidence_fallback",
        OverloadBrownoutReason::ObservePressure => "observe_pressure",
        OverloadBrownoutReason::DegradePressure => "degrade_pressure",
        OverloadBrownoutReason::ShedOptionalPressure => "shed_optional_pressure",
        OverloadBrownoutReason::TailRiskOuterDefer => "tail_risk_outer_defer",
        OverloadBrownoutReason::TailRiskOuterShed => "tail_risk_outer_shed",
        OverloadBrownoutReason::RecoveryHysteresis => "recovery_hysteresis",
        OverloadBrownoutReason::PreserveCriticalSurfaces => "preserve_critical_surfaces",
        OverloadBrownoutReason::OptionalSurfaceAlreadyShedding => {
            "optional_surface_already_shedding"
        }
        OverloadBrownoutReason::ConservativeBaseline => "conservative_baseline",
    }
}

fn create_priority_batch(batch_id: u64, priorities: &[String]) -> SpanBatch {
    let spans = priorities
        .iter()
        .enumerate()
        .map(|(index, priority)| OtlpSpan {
            span_id: format!("span-{}-{}", batch_id, index),
            name: "otlp_brownout_test".to_string(),
            start_time_unix_nano: 1_000_000_000,
            end_time_unix_nano: 1_000_001_000,
            attributes: vec![
                ("service".to_string(), "test".to_string()),
                ("otlp.priority".to_string(), priority.clone()),
            ],
            trace_flags: Some(0x01),
        })
        .collect();

    SpanBatch {
        batch_id,
        spans,
        created_at: Instant::now(),
    }
}

fn priority_label(span: &OtlpSpan) -> &'static str {
    span.attributes
        .iter()
        .find_map(|(key, value)| {
            if key == "otlp.priority" {
                Some(match value.as_str() {
                    "low" => "low",
                    _ => "high",
                })
            } else {
                None
            }
        })
        .unwrap_or("high")
}

fn build_scheduler_metrics(window: &OtlpBrownoutWindow) -> SchedulerEvidenceMetrics {
    SchedulerEvidenceMetrics {
        wake_to_run_p50_ns: window.wake_to_run_p99_ns.saturating_div(6),
        wake_to_run_p95_ns: window.wake_to_run_p99_ns.saturating_mul(85) / 100,
        wake_to_run_p99_ns: window.wake_to_run_p99_ns,
        queue_residency_p50_ns: window.queue_residency_p99_ns.saturating_div(6),
        queue_residency_p95_ns: window.queue_residency_p99_ns.saturating_mul(82) / 100,
        queue_residency_p99_ns: window.queue_residency_p99_ns,
        ready_backlog_p95: window.ready_backlog_p99.saturating_mul(4) / 5,
        ready_backlog_p99: window.ready_backlog_p99,
        cancel_debt_p95: window.cancel_debt_p99.saturating_mul(3) / 4,
        cancel_debt_p99: window.cancel_debt_p99,
        remote_steal_ratio_pct: Some(((window.ready_backlog_p99 as u64 / 8).min(50)) as u8),
        cross_cohort_wake_p99_ns: Some(window.wake_to_run_p99_ns.saturating_add(24_000)),
    }
}

fn build_shared_brownout(
    window: &OtlpBrownoutWindow,
    profile: &OverloadBrownoutProfile,
) -> Option<OverloadBrownoutLedger> {
    if !window.use_shared_brownout {
        return None;
    }
    Some(OverloadBrownoutLedger::evaluate(
        &OverloadBrownoutEvidence {
            scheduler: Some(build_scheduler_metrics(window)),
            memory_pressure_bps: window.memory_pressure_bps,
            degradation_level: window.degradation_level,
            outer_tail_risk_decision: window.outer_tail_risk_decision,
            previous_phase: window.previous_phase,
            recovery_streak_windows: 0,
            already_shed_surfaces: Vec::new(),
        },
        profile,
    ))
}

fn build_otlp_brownout_report(scenario: &OtlpBrownoutScenario, include_hash_probe: bool) -> Value {
    let mock_exporter = MockOtlpHttpExporter::new(Duration::from_millis(0));
    let exporter =
        LoadSheddingTraceExporter::new(Box::new(mock_exporter.clone()), 8, Duration::from_secs(1));

    let mut phase_sequence = Vec::new();
    let mut action_sequence = Vec::new();
    let mut fallback_windows = Vec::new();
    let mut window_reports = Vec::new();
    let mut exported_high_priority_spans = 0u64;
    let mut exported_low_priority_spans = 0u64;
    let mut final_shared_reason_codes = Vec::new();
    let mut final_shared_phase = "normal".to_string();

    for (index, window) in scenario.fixture.windows.iter().enumerate() {
        let brownout = build_shared_brownout(window, &scenario.brownout_profile);
        let snapshot = exporter.update_brownout_policy(brownout.as_ref());
        let before_brownout_drop = exporter.brownout_dropped_spans_count();
        let before_retained_summary = exporter.retained_summary_spans_count();
        let before_queue_drop = exporter.dropped_spans_count();
        let before_exported_batches = mock_exporter.exported_batches().len();

        let batch = create_priority_batch(index as u64 + 1, &window.priorities);
        exporter
            .export(&batch)
            .expect("OTLP brownout contract export should succeed");
        exporter
            .process_queue()
            .expect("OTLP brownout contract queue drain should succeed");

        let exported_batches = mock_exporter.exported_batches();
        for exported_batch in exported_batches.iter().skip(before_exported_batches) {
            for span in &exported_batch.spans {
                match priority_label(span) {
                    "low" => exported_low_priority_spans += 1,
                    _ => exported_high_priority_spans += 1,
                }
            }
        }

        let brownout_dropped_delta = exporter
            .brownout_dropped_spans_count()
            .saturating_sub(before_brownout_drop);
        let retained_summary_delta = exporter
            .retained_summary_spans_count()
            .saturating_sub(before_retained_summary);
        let queue_dropped_delta = exporter
            .dropped_spans_count()
            .saturating_sub(before_queue_drop);

        phase_sequence.push(phase_label(snapshot.shared_phase).to_string());
        action_sequence.push(action_label(snapshot.action).to_string());
        if snapshot.fallback_used {
            fallback_windows.push(window.window_id.clone());
        }
        final_shared_phase = phase_label(snapshot.shared_phase).to_string();
        final_shared_reason_codes = snapshot
            .shared_reason_codes
            .iter()
            .map(|reason| reason_label(*reason).to_string())
            .collect();

        window_reports.push(json!({
            "window_id": window.window_id,
            "shared_phase": phase_label(snapshot.shared_phase),
            "exporter_action": action_label(snapshot.action),
            "fallback_used": snapshot.fallback_used,
            "shared_reason_codes": snapshot.shared_reason_codes.iter().map(|reason| reason_label(*reason)).collect::<Vec<_>>(),
            "brownout_dropped_spans": brownout_dropped_delta,
            "retained_summary_spans": retained_summary_delta,
            "queue_dropped_spans": queue_dropped_delta
        }));
    }

    let final_stats = exporter.load_shedding_stats();
    let winner_profile =
        if final_stats.brownout_dropped_spans > 0 || final_stats.retained_summary_spans > 0 {
            "brownout"
        } else {
            scenario.safe_fallback_profile.as_str()
        };
    let no_win_trigger = winner_profile == scenario.safe_fallback_profile;
    let fallback_activation_count = fallback_windows.len() as u64;

    let report_projection = json!({
        "schema_version": OTLP_BROWNOUT_PROJECTION_SCHEMA_VERSION,
        "scenario_id": scenario.scenario_id,
        "workload_class": scenario.workload_class,
        "workload_seed": scenario.workload_seed,
        "window_count": scenario.fixture.windows.len(),
        "phase_sequence": phase_sequence,
        "action_sequence": action_sequence,
        "fallback_windows": fallback_windows,
        "fallback_activation_count": fallback_activation_count,
        "dropped_low_priority_spans": final_stats.brownout_dropped_spans,
        "retained_summary_spans": final_stats.retained_summary_spans,
        "queue_dropped_spans": exporter.dropped_spans_count(),
        "exported_high_priority_spans": exported_high_priority_spans,
        "exported_low_priority_spans": exported_low_priority_spans,
        "final_shared_phase": final_shared_phase,
        "final_shared_reason_codes": final_shared_reason_codes,
        "winner_profile": winner_profile,
        "no_win_trigger": no_win_trigger
    });
    let repeated_run_hash_match = if include_hash_probe {
        let probe = build_otlp_brownout_report(scenario, false);
        hash_json_value(&probe["report_projection"]) == hash_json_value(&report_projection)
    } else {
        true
    };

    json!({
        "schema_version": OTLP_BROWNOUT_REPORT_SCHEMA_VERSION,
        "scenario_id": scenario.scenario_id,
        "description": scenario.description,
        "workload_class": scenario.workload_class,
        "workload_seed": scenario.workload_seed,
        "safe_fallback_profile": scenario.safe_fallback_profile,
        "expected_winner_profile": scenario.expected_winner_profile,
        "report_projection": report_projection,
        "repeated_run_hash_match": repeated_run_hash_match,
        "window_reports": window_reports,
        "operator_verdict": {
            "winner_profile": winner_profile,
            "safe_fallback_profile": scenario.safe_fallback_profile,
            "no_win_trigger": no_win_trigger,
            "pass": winner_profile == scenario.expected_winner_profile,
        },
        "expected_report_projection": scenario.expected_report_projection
    })
}

#[test]
fn otlp_brownout_shedding_smoke_contract_emits_report() {
    let contract = load_otlp_brownout_contract();
    let scenario_id = selected_otlp_brownout_scenario();
    let scenario = contract
        .smoke_scenarios
        .iter()
        .find(|candidate| candidate.scenario_id == scenario_id)
        .expect("selected OTLP brownout scenario must exist");
    let report = build_otlp_brownout_report(scenario, true);

    if !scenario.expected_report_projection.is_null() {
        assert_eq!(
            report["report_projection"], scenario.expected_report_projection,
            "OTLP brownout smoke contract projection must stay stable"
        );
    }
    assert_eq!(
        report["repeated_run_hash_match"].as_bool(),
        Some(true),
        "repeated OTLP brownout report generation must stay deterministic"
    );
    assert_eq!(
        report["operator_verdict"]["pass"].as_bool(),
        Some(true),
        "operator verdict must agree with the expected OTLP winner profile"
    );

    if let Ok(path) = std::env::var(OTLP_BROWNOUT_REPORT_PATH_ENV) {
        maybe_write_otlp_brownout_report(&path, &report);
    }

    println!("OTLP_BROWNOUT_SHEDDING_REPORT_JSON_BEGIN");
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("serialize OTLP brownout report")
    );
    println!("OTLP_BROWNOUT_SHEDDING_REPORT_JSON_END");
}
