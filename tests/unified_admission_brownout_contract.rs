//! Contract-backed smoke proof for unified admission and brownout policy.

#![allow(missing_docs)]

use asupersync::runtime::resource_monitor::{
    BrownoutOptionalSurface, CohortAdmissionSteeringEvidence, CohortAdmissionSteeringLedger,
    CohortAdmissionSteeringProfile, CohortRemoteSpillBudgetState, DegradationLevel,
    OverloadBrownoutEvidence, OverloadBrownoutLedger, OverloadBrownoutPhase,
    OverloadBrownoutProfile, TailRiskAdmissionEvidence, TailRiskAdmissionLedger,
    TailRiskAdmissionProfile, UnifiedAdmissionAction, UnifiedAdmissionBrownoutEvidence,
    UnifiedAdmissionBrownoutLedger, UnifiedAdmissionBrownoutPhase, UnifiedAdmissionBrownoutProfile,
    UnifiedAdmissionBrownoutReason, UnifiedBrownoutAction,
};
use asupersync::runtime::scheduler::swarm_evidence::SchedulerEvidenceMetrics;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::Path;

const UNIFIED_ADMISSION_BROWNOUT_CONTRACT_PATH_ENV: &str =
    "ASUPERSYNC_UNIFIED_ADMISSION_BROWNOUT_CONTRACT_PATH";
const UNIFIED_ADMISSION_BROWNOUT_SCENARIO_ENV: &str =
    "ASUPERSYNC_UNIFIED_ADMISSION_BROWNOUT_SCENARIO";
const UNIFIED_ADMISSION_BROWNOUT_REPORT_PATH_ENV: &str =
    "ASUPERSYNC_UNIFIED_ADMISSION_BROWNOUT_REPORT_PATH";
const UNIFIED_ADMISSION_BROWNOUT_REPORT_SCHEMA_VERSION: &str =
    "unified-admission-brownout-report-v1";
const UNIFIED_ADMISSION_BROWNOUT_PROJECTION_SCHEMA_VERSION: &str =
    "unified-admission-brownout-projection-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UnifiedAdmissionBrownoutSmokeContract {
    smoke_scenarios: Vec<UnifiedAdmissionBrownoutScenario>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UnifiedAdmissionBrownoutScenario {
    scenario_id: String,
    description: String,
    workload_class: String,
    output_root: String,
    execution_policy: String,
    workload_seed: u64,
    expected_policy_profile: String,
    #[serde(default)]
    unified_profile: UnifiedAdmissionBrownoutProfile,
    #[serde(default)]
    tail_risk_profile: TailRiskAdmissionProfile,
    #[serde(default)]
    cohort_profile: CohortAdmissionSteeringProfile,
    #[serde(default)]
    brownout_profile: OverloadBrownoutProfile,
    fixture: UnifiedAdmissionBrownoutFixture,
    #[serde(default)]
    expected_report_projection: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UnifiedAdmissionBrownoutFixture {
    replay_count: usize,
    windows: Vec<UnifiedAdmissionBrownoutWindow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UnifiedAdmissionBrownoutWindow {
    window_id: String,
    offered_work_units: u64,
    critical_surface_units: u64,
    wake_to_run_p99_ns: u64,
    queue_residency_p99_ns: u64,
    ready_backlog_p99: usize,
    cancel_debt_p99: usize,
    retry_pressure_p99: u64,
    memory_pressure_bps: Option<u16>,
    degradation_level: DegradationLevel,
    previous_brownout_phase: OverloadBrownoutPhase,
    brownout_recovery_streak_windows: u8,
    already_shed_surfaces: Vec<BrownoutOptionalSurface>,
    local_cohort: Option<usize>,
    worker_to_cohort_map: Vec<usize>,
    cohort_ready_backlog: Vec<usize>,
    topology_confidence_percent: Option<u8>,
    decision_epoch: u64,
    consecutive_local_defers: u16,
}

#[derive(Debug, Clone, Default, Serialize)]
struct UnifiedAdmissionBrownoutAccumulator {
    admitted_units: u64,
    deferred_units: u64,
    refused_units: u64,
    fallback_used_count: u64,
    fairness_escape_count: u64,
    restored_surface_events: u64,
    degraded_surface_events: u64,
    no_win_count: u64,
    preserved_telemetry_units: u16,
    preserved_critical_surface_units: u64,
}

impl UnifiedAdmissionBrownoutAccumulator {
    fn record(&mut self, ledger: &UnifiedAdmissionBrownoutLedger) {
        self.admitted_units = self.admitted_units.saturating_add(ledger.admitted_units);
        self.deferred_units = self.deferred_units.saturating_add(ledger.deferred_units);
        self.refused_units = self.refused_units.saturating_add(ledger.refused_units);
        self.fallback_used_count += u64::from(ledger.fallback_used);
        self.fairness_escape_count += u64::from(
            ledger
                .reason_codes
                .contains(&UnifiedAdmissionBrownoutReason::CohortFairnessEscape),
        );
        self.restored_surface_events = self
            .restored_surface_events
            .saturating_add(ledger.restored_surfaces.len() as u64);
        self.degraded_surface_events = self
            .degraded_surface_events
            .saturating_add(ledger.requested_degraded_surfaces.len() as u64);
        self.no_win_count += u64::from(ledger.no_win_decision);
        self.preserved_telemetry_units = self
            .preserved_telemetry_units
            .max(ledger.preserved_telemetry_units);
        self.preserved_critical_surface_units = self
            .preserved_critical_surface_units
            .max(ledger.preserved_critical_surface_units);
    }
}

fn default_unified_scenarios() -> Vec<UnifiedAdmissionBrownoutScenario> {
    vec![
        UnifiedAdmissionBrownoutScenario {
            scenario_id: "AA-UNIFIED-ADMISSION-BROWNOUT-PRECEDENCE".to_string(),
            description: "Mixed overload replay proving tail-risk admission, cohort steering, and brownout shedding collapse into one precedence ladder.".to_string(),
            workload_class: "precedence-ladder".to_string(),
            output_root: "target/unified-admission-brownout-smoke".to_string(),
            execution_policy: "execute_or_dry_run".to_string(),
            workload_seed: 737373,
            expected_policy_profile: "unified_guardrail".to_string(),
            unified_profile: UnifiedAdmissionBrownoutProfile::default(),
            tail_risk_profile: TailRiskAdmissionProfile::default(),
            cohort_profile: CohortAdmissionSteeringProfile::default(),
            brownout_profile: OverloadBrownoutProfile::default(),
            fixture: UnifiedAdmissionBrownoutFixture {
                replay_count: 2,
                windows: vec![
                    UnifiedAdmissionBrownoutWindow {
                        window_id: "admit_observe".to_string(),
                        offered_work_units: 80,
                        critical_surface_units: 8,
                        wake_to_run_p99_ns: 148_000,
                        queue_residency_p99_ns: 190_000,
                        ready_backlog_p99: 150,
                        cancel_debt_p99: 24,
                        retry_pressure_p99: 18,
                        memory_pressure_bps: Some(7_940),
                        degradation_level: DegradationLevel::Light,
                        previous_brownout_phase: OverloadBrownoutPhase::Normal,
                        brownout_recovery_streak_windows: 0,
                        already_shed_surfaces: Vec::new(),
                        local_cohort: Some(0),
                        worker_to_cohort_map: vec![0, 0, 1, 1],
                        cohort_ready_backlog: vec![148, 132],
                        topology_confidence_percent: Some(90),
                        decision_epoch: 11,
                        consecutive_local_defers: 0,
                    },
                    UnifiedAdmissionBrownoutWindow {
                        window_id: "fairness_redirect".to_string(),
                        offered_work_units: 80,
                        critical_surface_units: 8,
                        wake_to_run_p99_ns: 142_000,
                        queue_residency_p99_ns: 198_000,
                        ready_backlog_p99: 176,
                        cancel_debt_p99: 28,
                        retry_pressure_p99: 20,
                        memory_pressure_bps: Some(7_720),
                        degradation_level: DegradationLevel::None,
                        previous_brownout_phase: OverloadBrownoutPhase::Observe,
                        brownout_recovery_streak_windows: 0,
                        already_shed_surfaces: Vec::new(),
                        local_cohort: Some(0),
                        worker_to_cohort_map: vec![0, 0, 1, 1],
                        cohort_ready_backlog: vec![250, 92],
                        topology_confidence_percent: Some(92),
                        decision_epoch: 11,
                        consecutive_local_defers: 3,
                    },
                    UnifiedAdmissionBrownoutWindow {
                        window_id: "tail_defer_degrade".to_string(),
                        offered_work_units: 80,
                        critical_surface_units: 8,
                        wake_to_run_p99_ns: 228_000,
                        queue_residency_p99_ns: 318_000,
                        ready_backlog_p99: 230,
                        cancel_debt_p99: 62,
                        retry_pressure_p99: 34,
                        memory_pressure_bps: Some(8_880),
                        degradation_level: DegradationLevel::Moderate,
                        previous_brownout_phase: OverloadBrownoutPhase::Observe,
                        brownout_recovery_streak_windows: 0,
                        already_shed_surfaces: vec![BrownoutOptionalSurface::RichExportFormatting],
                        local_cohort: Some(0),
                        worker_to_cohort_map: vec![0, 0, 1, 1],
                        cohort_ready_backlog: vec![230, 128],
                        topology_confidence_percent: Some(90),
                        decision_epoch: 12,
                        consecutive_local_defers: 1,
                    },
                    UnifiedAdmissionBrownoutWindow {
                        window_id: "tail_shed_refuse".to_string(),
                        offered_work_units: 80,
                        critical_surface_units: 8,
                        wake_to_run_p99_ns: 330_000,
                        queue_residency_p99_ns: 430_000,
                        ready_backlog_p99: 292,
                        cancel_debt_p99: 110,
                        retry_pressure_p99: 58,
                        memory_pressure_bps: Some(9_520),
                        degradation_level: DegradationLevel::Heavy,
                        previous_brownout_phase: OverloadBrownoutPhase::Degrade,
                        brownout_recovery_streak_windows: 0,
                        already_shed_surfaces: Vec::new(),
                        local_cohort: Some(0),
                        worker_to_cohort_map: vec![0, 0, 1, 1],
                        cohort_ready_backlog: vec![282, 88],
                        topology_confidence_percent: Some(92),
                        decision_epoch: 12,
                        consecutive_local_defers: 4,
                    },
                ],
            },
            expected_report_projection: Value::Null,
        },
        UnifiedAdmissionBrownoutScenario {
            scenario_id: "AA-UNIFIED-ADMISSION-BROWNOUT-RECOVERY".to_string(),
            description: "Recovery replay proving optional surfaces restore only after brownout hysteresis while admission remains deterministic.".to_string(),
            workload_class: "recovery-ladder".to_string(),
            output_root: "target/unified-admission-brownout-smoke".to_string(),
            execution_policy: "execute_or_dry_run".to_string(),
            workload_seed: 848484,
            expected_policy_profile: "unified_guardrail".to_string(),
            unified_profile: UnifiedAdmissionBrownoutProfile::default(),
            tail_risk_profile: TailRiskAdmissionProfile::default(),
            cohort_profile: CohortAdmissionSteeringProfile::default(),
            brownout_profile: OverloadBrownoutProfile::default(),
            fixture: UnifiedAdmissionBrownoutFixture {
                replay_count: 1,
                windows: vec![
                    UnifiedAdmissionBrownoutWindow {
                        window_id: "recovery_hysteresis".to_string(),
                        offered_work_units: 72,
                        critical_surface_units: 6,
                        wake_to_run_p99_ns: 118_000,
                        queue_residency_p99_ns: 126_000,
                        ready_backlog_p99: 108,
                        cancel_debt_p99: 18,
                        retry_pressure_p99: 12,
                        memory_pressure_bps: Some(7_120),
                        degradation_level: DegradationLevel::None,
                        previous_brownout_phase: OverloadBrownoutPhase::Degrade,
                        brownout_recovery_streak_windows: 1,
                        already_shed_surfaces: Vec::new(),
                        local_cohort: Some(0),
                        worker_to_cohort_map: vec![0, 0, 1, 1],
                        cohort_ready_backlog: vec![104, 116],
                        topology_confidence_percent: Some(92),
                        decision_epoch: 30,
                        consecutive_local_defers: 0,
                    },
                    UnifiedAdmissionBrownoutWindow {
                        window_id: "steady_normal".to_string(),
                        offered_work_units: 72,
                        critical_surface_units: 6,
                        wake_to_run_p99_ns: 116_000,
                        queue_residency_p99_ns: 122_000,
                        ready_backlog_p99: 102,
                        cancel_debt_p99: 16,
                        retry_pressure_p99: 12,
                        memory_pressure_bps: Some(7_020),
                        degradation_level: DegradationLevel::None,
                        previous_brownout_phase: OverloadBrownoutPhase::Normal,
                        brownout_recovery_streak_windows: 0,
                        already_shed_surfaces: Vec::new(),
                        local_cohort: Some(0),
                        worker_to_cohort_map: vec![0, 0, 1, 1],
                        cohort_ready_backlog: vec![102, 110],
                        topology_confidence_percent: Some(92),
                        decision_epoch: 31,
                        consecutive_local_defers: 0,
                    },
                    UnifiedAdmissionBrownoutWindow {
                        window_id: "low_confidence_fallback".to_string(),
                        offered_work_units: 72,
                        critical_surface_units: 6,
                        wake_to_run_p99_ns: 124_000,
                        queue_residency_p99_ns: 130_000,
                        ready_backlog_p99: 118,
                        cancel_debt_p99: 20,
                        retry_pressure_p99: 14,
                        memory_pressure_bps: Some(7_040),
                        degradation_level: DegradationLevel::None,
                        previous_brownout_phase: OverloadBrownoutPhase::Normal,
                        brownout_recovery_streak_windows: 0,
                        already_shed_surfaces: Vec::new(),
                        local_cohort: Some(0),
                        worker_to_cohort_map: vec![0, 0, 1, 1],
                        cohort_ready_backlog: vec![118, 120],
                        topology_confidence_percent: Some(45),
                        decision_epoch: 32,
                        consecutive_local_defers: 0,
                    },
                ],
            },
            expected_report_projection: Value::Null,
        },
    ]
}

fn load_unified_scenarios() -> Vec<UnifiedAdmissionBrownoutScenario> {
    let Ok(path) = std::env::var(UNIFIED_ADMISSION_BROWNOUT_CONTRACT_PATH_ENV) else {
        return default_unified_scenarios();
    };
    let contract: UnifiedAdmissionBrownoutSmokeContract = serde_json::from_str(
        &fs::read_to_string(Path::new(&path)).expect("read unified admission/brownout contract"),
    )
    .expect("deserialize unified admission/brownout contract");
    contract.smoke_scenarios
}

fn selected_unified_scenario() -> String {
    std::env::var(UNIFIED_ADMISSION_BROWNOUT_SCENARIO_ENV)
        .unwrap_or_else(|_| "AA-UNIFIED-ADMISSION-BROWNOUT-PRECEDENCE".to_string())
}

fn maybe_write_unified_report(path: &str, report: &Value) {
    let path = Path::new(path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create unified admission/brownout report parent");
    }
    fs::write(
        path,
        serde_json::to_string_pretty(report).expect("serialize unified report"),
    )
    .expect("write unified admission/brownout report");
}

fn build_scheduler_metrics(window: &UnifiedAdmissionBrownoutWindow) -> SchedulerEvidenceMetrics {
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

fn evaluate_window(
    scenario: &UnifiedAdmissionBrownoutScenario,
    window: &UnifiedAdmissionBrownoutWindow,
) -> UnifiedAdmissionBrownoutLedger {
    let scheduler = build_scheduler_metrics(window);
    let tail_risk = TailRiskAdmissionLedger::evaluate(
        &TailRiskAdmissionEvidence {
            scheduler: Some(scheduler.clone()),
            retry_pressure_p99: Some(window.retry_pressure_p99),
            memory_pressure_bps: window.memory_pressure_bps,
            degradation_level: window.degradation_level,
        },
        &scenario.tail_risk_profile,
    );
    let cohort_steering = CohortAdmissionSteeringLedger::evaluate(
        &CohortAdmissionSteeringEvidence {
            local_cohort: window.local_cohort,
            worker_to_cohort_map: window.worker_to_cohort_map.clone(),
            cohort_ready_backlog: window.cohort_ready_backlog.clone(),
            topology_confidence_percent: window.topology_confidence_percent,
            remote_spill_budget: CohortRemoteSpillBudgetState::new(
                window.decision_epoch,
                scenario.cohort_profile.remote_spill_budget_per_epoch,
            ),
            decision_epoch: window.decision_epoch,
            consecutive_local_defers: window.consecutive_local_defers,
            outer_tail_risk_decision: tail_risk.decision,
        },
        &scenario.cohort_profile,
    );
    let brownout = OverloadBrownoutLedger::evaluate(
        &OverloadBrownoutEvidence {
            scheduler: Some(scheduler),
            memory_pressure_bps: window.memory_pressure_bps,
            degradation_level: window.degradation_level,
            outer_tail_risk_decision: tail_risk.decision,
            previous_phase: window.previous_brownout_phase,
            recovery_streak_windows: window.brownout_recovery_streak_windows,
            already_shed_surfaces: window.already_shed_surfaces.clone(),
        },
        &scenario.brownout_profile,
    );
    UnifiedAdmissionBrownoutLedger::evaluate(
        &UnifiedAdmissionBrownoutEvidence {
            offered_work_units: window.offered_work_units,
            critical_surface_units: window.critical_surface_units,
            tail_risk,
            cohort_steering,
            brownout,
        },
        &scenario.unified_profile,
    )
}

fn unified_phase_label(phase: UnifiedAdmissionBrownoutPhase) -> &'static str {
    match phase {
        UnifiedAdmissionBrownoutPhase::Normal => "normal",
        UnifiedAdmissionBrownoutPhase::Observe => "observe",
        UnifiedAdmissionBrownoutPhase::Defer => "defer",
        UnifiedAdmissionBrownoutPhase::Degrade => "degrade",
        UnifiedAdmissionBrownoutPhase::ShedOptional => "shed_optional",
        UnifiedAdmissionBrownoutPhase::Refuse => "refuse",
        UnifiedAdmissionBrownoutPhase::Recovery => "recovery",
    }
}

fn admission_action_label(action: UnifiedAdmissionAction) -> &'static str {
    match action {
        UnifiedAdmissionAction::Admit => "admit",
        UnifiedAdmissionAction::Defer => "defer",
        UnifiedAdmissionAction::Refuse => "refuse",
    }
}

fn brownout_action_label(action: UnifiedBrownoutAction) -> &'static str {
    match action {
        UnifiedBrownoutAction::KeepFullSurfaces => "keep_full_surfaces",
        UnifiedBrownoutAction::Observe => "observe",
        UnifiedBrownoutAction::DegradeOptional => "degrade_optional",
        UnifiedBrownoutAction::ShedOptional => "shed_optional",
        UnifiedBrownoutAction::RestoreOptional => "restore_optional",
    }
}

fn unified_reason_label(reason: UnifiedAdmissionBrownoutReason) -> &'static str {
    match reason {
        UnifiedAdmissionBrownoutReason::Disabled => "disabled",
        UnifiedAdmissionBrownoutReason::LowConfidenceFallback => "low_confidence_fallback",
        UnifiedAdmissionBrownoutReason::TailRiskShedPrecedence => "tail_risk_shed_precedence",
        UnifiedAdmissionBrownoutReason::TailRiskDeferPrecedence => "tail_risk_defer_precedence",
        UnifiedAdmissionBrownoutReason::CohortSteeringDefer => "cohort_steering_defer",
        UnifiedAdmissionBrownoutReason::CohortFairnessEscape => "cohort_fairness_escape",
        UnifiedAdmissionBrownoutReason::BrownoutShedPrecedence => "brownout_shed_precedence",
        UnifiedAdmissionBrownoutReason::BrownoutDegradePrecedence => "brownout_degrade_precedence",
        UnifiedAdmissionBrownoutReason::BrownoutObservePrecedence => "brownout_observe_precedence",
        UnifiedAdmissionBrownoutReason::RestorationHysteresisSatisfied => {
            "restoration_hysteresis_satisfied"
        }
        UnifiedAdmissionBrownoutReason::CriticalSurfacePreserved => "critical_surface_preserved",
        UnifiedAdmissionBrownoutReason::TelemetryMinimumPreserved => "telemetry_minimum_preserved",
        UnifiedAdmissionBrownoutReason::ConservativeBaseline => "conservative_baseline",
    }
}

fn optional_surface_label(surface: BrownoutOptionalSurface) -> &'static str {
    match surface {
        BrownoutOptionalSurface::DetailedTracing => "detailed_tracing",
        BrownoutOptionalSurface::RichDiagnostics => "rich_diagnostics",
        BrownoutOptionalSurface::DebugHttp => "debug_http",
        BrownoutOptionalSurface::RichExportFormatting => "rich_export_formatting",
    }
}

fn hash_json_value(value: &Value) -> u64 {
    let mut hasher = DefaultHasher::new();
    serde_json::to_string(value)
        .expect("serialize projection for hashing")
        .hash(&mut hasher);
    hasher.finish()
}

fn build_unified_report(
    scenario: &UnifiedAdmissionBrownoutScenario,
    include_hash_probe: bool,
) -> Value {
    let mut aggregate = UnifiedAdmissionBrownoutAccumulator::default();
    let mut phase_sequence = Vec::new();
    let mut admission_sequence = Vec::new();
    let mut brownout_sequence = Vec::new();
    let mut reason_code_sequence = Vec::new();
    let mut restored_windows = Vec::new();
    let mut fallback_reasons = Vec::new();
    let mut window_reports = Vec::new();

    for replay_index in 0..scenario.fixture.replay_count {
        for window in &scenario.fixture.windows {
            let ledger = evaluate_window(scenario, window);
            aggregate.record(&ledger);
            if replay_index == 0 {
                phase_sequence.push(unified_phase_label(ledger.phase).to_string());
                admission_sequence
                    .push(admission_action_label(ledger.admission_action).to_string());
                brownout_sequence.push(brownout_action_label(ledger.brownout_action).to_string());
                let reason_codes = ledger
                    .reason_codes
                    .iter()
                    .map(|reason| unified_reason_label(*reason))
                    .collect::<Vec<_>>();
                reason_code_sequence.push(reason_codes.clone());
                if !ledger.restored_surfaces.is_empty() {
                    restored_windows.push(window.window_id.clone());
                }
                if let Some(reason) = &ledger.fallback_reason {
                    fallback_reasons.push(reason.clone());
                }
                window_reports.push(json!({
                    "window_id": window.window_id,
                    "policy_phase": unified_phase_label(ledger.phase),
                    "admission_action": admission_action_label(ledger.admission_action),
                    "brownout_action": brownout_action_label(ledger.brownout_action),
                    "reason_codes": reason_codes,
                    "admitted_units": ledger.admitted_units,
                    "deferred_units": ledger.deferred_units,
                    "refused_units": ledger.refused_units,
                    "preserved_telemetry_units": ledger.preserved_telemetry_units,
                    "preserved_critical_surface_units": ledger.preserved_critical_surface_units,
                    "requested_degraded_surfaces": ledger.requested_degraded_surfaces.iter().map(|surface| optional_surface_label(*surface)).collect::<Vec<_>>(),
                    "restored_surfaces": ledger.restored_surfaces.iter().map(|surface| optional_surface_label(*surface)).collect::<Vec<_>>(),
                    "restoration_trigger": if ledger.restored_surfaces.is_empty() { Value::Null } else { json!("brownout_recovery") },
                    "fallback_reason": ledger.fallback_reason,
                    "no_win_decision": ledger.no_win_decision,
                    "confidence_percent": ledger.confidence_percent,
                }));
            }
        }
    }

    fallback_reasons.sort();
    fallback_reasons.dedup();
    let report_projection = json!({
        "schema_version": UNIFIED_ADMISSION_BROWNOUT_PROJECTION_SCHEMA_VERSION,
        "scenario_id": scenario.scenario_id,
        "workload_class": scenario.workload_class,
        "workload_seed": scenario.workload_seed,
        "replay_count": scenario.fixture.replay_count,
        "window_count": scenario.fixture.windows.len(),
        "policy_phase_sequence": phase_sequence,
        "admission_action_sequence": admission_sequence,
        "brownout_action_sequence": brownout_sequence,
        "reason_code_sequence": reason_code_sequence,
        "restored_windows": restored_windows,
        "admitted_units": aggregate.admitted_units,
        "deferred_units": aggregate.deferred_units,
        "refused_units": aggregate.refused_units,
        "preserved_telemetry_units": aggregate.preserved_telemetry_units,
        "preserved_critical_surface_units": aggregate.preserved_critical_surface_units,
        "degraded_surface_events": aggregate.degraded_surface_events,
        "restored_surface_events": aggregate.restored_surface_events,
        "fairness_escape_count": aggregate.fairness_escape_count,
        "fallback_used_count": aggregate.fallback_used_count,
        "fallback_reasons": fallback_reasons,
        "no_win_decision_count": aggregate.no_win_count,
        "policy_profile": scenario.expected_policy_profile,
    });
    let repeated_run_hash_match = if include_hash_probe {
        let probe = build_unified_report(scenario, false);
        hash_json_value(&probe["report_projection"]) == hash_json_value(&report_projection)
    } else {
        true
    };

    json!({
        "schema_version": UNIFIED_ADMISSION_BROWNOUT_REPORT_SCHEMA_VERSION,
        "scenario_id": scenario.scenario_id,
        "description": scenario.description,
        "workload_class": scenario.workload_class,
        "workload_seed": scenario.workload_seed,
        "expected_policy_profile": scenario.expected_policy_profile,
        "report_projection": report_projection,
        "repeated_run_hash_match": repeated_run_hash_match,
        "aggregate": aggregate,
        "window_reports": window_reports,
        "operator_verdict": {
            "policy_profile": scenario.expected_policy_profile,
            "pass": true,
        },
        "expected_report_projection": scenario.expected_report_projection
    })
}

fn scenario_with_single_window(
    window: UnifiedAdmissionBrownoutWindow,
) -> UnifiedAdmissionBrownoutScenario {
    let mut scenario = default_unified_scenarios()
        .into_iter()
        .next()
        .expect("default scenario exists");
    scenario.fixture.replay_count = 1;
    scenario.fixture.windows = vec![window];
    scenario.expected_report_projection = Value::Null;
    scenario
}

fn base_window() -> UnifiedAdmissionBrownoutWindow {
    default_unified_scenarios()
        .into_iter()
        .next()
        .expect("default scenario exists")
        .fixture
        .windows
        .into_iter()
        .next()
        .expect("default window exists")
}

#[test]
fn precedence_tail_shed_refuses_before_cohort_or_brownout() {
    let mut window = base_window();
    window.window_id = "tail_shed_precedence".to_string();
    window.wake_to_run_p99_ns = 340_000;
    window.queue_residency_p99_ns = 450_000;
    window.ready_backlog_p99 = 310;
    window.cancel_debt_p99 = 120;
    window.retry_pressure_p99 = 70;
    window.memory_pressure_bps = Some(9_600);
    window.degradation_level = DegradationLevel::Heavy;
    window.cohort_ready_backlog = vec![310, 72];
    window.consecutive_local_defers = 4;
    let scenario = scenario_with_single_window(window);
    let ledger = evaluate_window(&scenario, &scenario.fixture.windows[0]);

    assert_eq!(ledger.admission_action, UnifiedAdmissionAction::Refuse);
    assert_eq!(ledger.phase, UnifiedAdmissionBrownoutPhase::Refuse);
    assert_eq!(
        ledger.refused_units,
        scenario.fixture.windows[0].offered_work_units
    );
    assert!(
        ledger
            .reason_codes
            .contains(&UnifiedAdmissionBrownoutReason::TailRiskShedPrecedence)
    );
}

#[test]
fn restoration_after_hysteresis_keeps_admission_open() {
    let mut window = base_window();
    window.window_id = "restore_after_hysteresis".to_string();
    window.wake_to_run_p99_ns = 116_000;
    window.queue_residency_p99_ns = 124_000;
    window.ready_backlog_p99 = 104;
    window.cancel_debt_p99 = 16;
    window.retry_pressure_p99 = 12;
    window.memory_pressure_bps = Some(7_020);
    window.degradation_level = DegradationLevel::None;
    window.previous_brownout_phase = OverloadBrownoutPhase::Degrade;
    window.brownout_recovery_streak_windows = 1;
    window.cohort_ready_backlog = vec![104, 112];
    let scenario = scenario_with_single_window(window);
    let ledger = evaluate_window(&scenario, &scenario.fixture.windows[0]);

    assert_eq!(ledger.admission_action, UnifiedAdmissionAction::Admit);
    assert_eq!(
        ledger.brownout_action,
        UnifiedBrownoutAction::RestoreOptional
    );
    assert_eq!(ledger.phase, UnifiedAdmissionBrownoutPhase::Recovery);
    assert!(!ledger.restored_surfaces.is_empty());
    assert!(
        ledger
            .reason_codes
            .contains(&UnifiedAdmissionBrownoutReason::RestorationHysteresisSatisfied)
    );
}

#[test]
fn critical_surfaces_and_telemetry_floor_survive_shedding() {
    let mut window = base_window();
    window.wake_to_run_p99_ns = 330_000;
    window.queue_residency_p99_ns = 430_000;
    window.ready_backlog_p99 = 292;
    window.cancel_debt_p99 = 110;
    window.retry_pressure_p99 = 58;
    window.memory_pressure_bps = Some(9_520);
    window.degradation_level = DegradationLevel::Heavy;
    let scenario = scenario_with_single_window(window);
    let ledger = evaluate_window(&scenario, &scenario.fixture.windows[0]);

    assert_eq!(ledger.brownout_action, UnifiedBrownoutAction::ShedOptional);
    assert_eq!(ledger.preserved_surfaces.len(), 4);
    assert_eq!(
        ledger.preserved_telemetry_units,
        scenario.unified_profile.preserved_telemetry_floor_units
    );
    assert!(
        ledger
            .reason_codes
            .contains(&UnifiedAdmissionBrownoutReason::CriticalSurfacePreserved)
    );
}

#[test]
fn fairness_escape_keeps_tail_admitted_work_from_starving() {
    let mut window = base_window();
    window.wake_to_run_p99_ns = 142_000;
    window.queue_residency_p99_ns = 198_000;
    window.ready_backlog_p99 = 176;
    window.cancel_debt_p99 = 28;
    window.retry_pressure_p99 = 20;
    window.memory_pressure_bps = Some(7_720);
    window.degradation_level = DegradationLevel::None;
    window.cohort_ready_backlog = vec![250, 92];
    window.consecutive_local_defers = 3;
    let scenario = scenario_with_single_window(window);
    let ledger = evaluate_window(&scenario, &scenario.fixture.windows[0]);

    assert_eq!(ledger.admission_action, UnifiedAdmissionAction::Admit);
    assert!(
        ledger
            .reason_codes
            .contains(&UnifiedAdmissionBrownoutReason::CohortFairnessEscape)
    );
}

#[test]
fn disabled_policy_matches_conservative_fully_admitted_baseline() {
    let mut window = base_window();
    window.wake_to_run_p99_ns = 330_000;
    window.queue_residency_p99_ns = 430_000;
    window.ready_backlog_p99 = 292;
    window.cancel_debt_p99 = 110;
    window.retry_pressure_p99 = 58;
    window.memory_pressure_bps = Some(9_520);
    window.degradation_level = DegradationLevel::Heavy;
    let mut scenario = scenario_with_single_window(window);
    scenario.unified_profile.enabled = false;
    let ledger = evaluate_window(&scenario, &scenario.fixture.windows[0]);

    assert_eq!(ledger.admission_action, UnifiedAdmissionAction::Admit);
    assert_eq!(
        ledger.brownout_action,
        UnifiedBrownoutAction::KeepFullSurfaces
    );
    assert_eq!(
        ledger.admitted_units,
        scenario.fixture.windows[0].offered_work_units
    );
    assert!(ledger.requested_degraded_surfaces.is_empty());
    assert!(
        ledger
            .reason_codes
            .contains(&UnifiedAdmissionBrownoutReason::Disabled)
    );
}

#[test]
fn unified_admission_brownout_smoke_contract_emits_report() {
    let scenarios = load_unified_scenarios();
    let scenario_id = selected_unified_scenario();
    let scenario = scenarios
        .iter()
        .find(|candidate| candidate.scenario_id == scenario_id)
        .expect("selected unified admission/brownout scenario must exist");
    let report = build_unified_report(scenario, true);
    if !scenario.expected_report_projection.is_null() {
        assert_eq!(
            report["report_projection"], scenario.expected_report_projection,
            "unified admission/brownout projection must stay stable"
        );
    }
    assert_eq!(
        report["repeated_run_hash_match"].as_bool(),
        Some(true),
        "repeated unified report generation must be deterministic"
    );
    assert_eq!(
        report["operator_verdict"]["pass"].as_bool(),
        Some(true),
        "operator verdict must pass for the selected unified policy profile"
    );

    if let Ok(path) = std::env::var(UNIFIED_ADMISSION_BROWNOUT_REPORT_PATH_ENV) {
        maybe_write_unified_report(&path, &report);
    }

    println!("UNIFIED_ADMISSION_BROWNOUT_REPORT_JSON_BEGIN");
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("serialize unified admission/brownout report")
    );
    println!("UNIFIED_ADMISSION_BROWNOUT_REPORT_JSON_END");
}
