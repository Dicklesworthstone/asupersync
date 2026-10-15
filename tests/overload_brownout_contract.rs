//! Contract-backed smoke proof for overload brownout of optional runtime surfaces.

use asupersync::runtime::resource_monitor::{
    BrownoutOptionalSurface, BrownoutProtectedSurface, DegradationLevel, OverloadBrownoutEvidence,
    OverloadBrownoutLedger, OverloadBrownoutPhase, OverloadBrownoutProfile, OverloadBrownoutReason,
    TailRiskAdmissionDecision,
};
use asupersync::runtime::scheduler::swarm_evidence::SchedulerEvidenceMetrics;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::Path;

const OVERLOAD_BROWNOUT_CONTRACT_PATH_ENV: &str = "ASUPERSYNC_OVERLOAD_BROWNOUT_CONTRACT_PATH";
const OVERLOAD_BROWNOUT_SCENARIO_ENV: &str = "ASUPERSYNC_OVERLOAD_BROWNOUT_SCENARIO";
const OVERLOAD_BROWNOUT_REPORT_PATH_ENV: &str = "ASUPERSYNC_OVERLOAD_BROWNOUT_REPORT_PATH";
const OVERLOAD_BROWNOUT_REPORT_SCHEMA_VERSION: &str = "overload-brownout-report-v1";
const OVERLOAD_BROWNOUT_PROJECTION_SCHEMA_VERSION: &str = "overload-brownout-projection-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OverloadBrownoutSmokeContract {
    smoke_scenarios: Vec<OverloadBrownoutScenario>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OverloadBrownoutScenario {
    scenario_id: String,
    description: String,
    workload_class: String,
    output_root: String,
    execution_policy: String,
    workload_seed: u64,
    safe_fallback_profile: String,
    expected_winner_profile: String,
    brownout_profile: OverloadBrownoutProfile,
    fixture: OverloadBrownoutFixture,
    expected_report_projection: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OverloadBrownoutFixture {
    initial_phase: OverloadBrownoutPhase,
    replay_count: usize,
    windows: Vec<OverloadBrownoutWindow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OverloadBrownoutWindow {
    window_id: String,
    wake_to_run_p99_ns: u64,
    queue_residency_p99_ns: u64,
    ready_backlog_p99: usize,
    cancel_debt_p99: usize,
    memory_pressure_bps: Option<u16>,
    degradation_level: DegradationLevel,
    outer_tail_risk_decision: TailRiskAdmissionDecision,
    already_shed_surfaces: Vec<BrownoutOptionalSurface>,
    offered_core_units: u64,
    base_cancel_p99_ns: u64,
}

#[derive(Debug, Clone)]
struct BrownoutWindowOutcome {
    core_units_preserved: u64,
    cancel_latency_samples: Vec<u64>,
    active_optional_surface_count: usize,
}

#[derive(Debug, Clone, Default)]
struct BrownoutAccumulator {
    observe_count: u64,
    degrade_count: u64,
    shed_optional_count: u64,
    recovery_count: u64,
    fallback_used_count: u64,
    core_units_preserved: u64,
    cancel_latencies: Vec<u64>,
    optional_surface_reduction_events: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
struct BrownoutSummary {
    observe_count: u64,
    degrade_count: u64,
    shed_optional_count: u64,
    recovery_count: u64,
    fallback_used_count: u64,
    core_units_preserved: u64,
    cancel_p50_ns: u64,
    cancel_p95_ns: u64,
    cancel_p99_ns: u64,
    throughput_ratio: f64,
    optional_surface_reduction_events: u64,
}

impl BrownoutAccumulator {
    fn record(
        &mut self,
        phase: OverloadBrownoutPhase,
        fallback_used: bool,
        requested_degraded_surfaces: usize,
        outcome: &BrownoutWindowOutcome,
    ) {
        match phase {
            OverloadBrownoutPhase::Normal => {}
            OverloadBrownoutPhase::Observe => self.observe_count += 1,
            OverloadBrownoutPhase::Degrade => self.degrade_count += 1,
            OverloadBrownoutPhase::ShedOptional => self.shed_optional_count += 1,
            OverloadBrownoutPhase::Recovery => self.recovery_count += 1,
        }
        self.fallback_used_count += u64::from(fallback_used);
        self.optional_surface_reduction_events += requested_degraded_surfaces as u64;
        self.core_units_preserved += outcome.core_units_preserved;
        self.cancel_latencies
            .extend_from_slice(&outcome.cancel_latency_samples);
    }

    fn summary(&self, total_offered_units: u64) -> BrownoutSummary {
        BrownoutSummary {
            observe_count: self.observe_count,
            degrade_count: self.degrade_count,
            shed_optional_count: self.shed_optional_count,
            recovery_count: self.recovery_count,
            fallback_used_count: self.fallback_used_count,
            core_units_preserved: self.core_units_preserved,
            cancel_p50_ns: percentile_slice_u64(&self.cancel_latencies, 50, 100),
            cancel_p95_ns: percentile_slice_u64(&self.cancel_latencies, 95, 100),
            cancel_p99_ns: percentile_slice_u64(&self.cancel_latencies, 99, 100),
            throughput_ratio: if total_offered_units == 0 {
                0.0
            } else {
                round4(self.core_units_preserved as f64 / total_offered_units as f64)
            },
            optional_surface_reduction_events: self.optional_surface_reduction_events,
        }
    }
}

fn round4(value: f64) -> f64 {
    (value * 10_000.0).round() / 10_000.0
}

fn percentile_slice_u64(samples: &[u64], numerator: usize, denominator: usize) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let index = ((sorted.len() - 1) * numerator) / denominator;
    sorted[index]
}

fn hash_json_value(value: &Value) -> u64 {
    let mut hasher = DefaultHasher::new();
    serde_json::to_string(value)
        .expect("serialize projection for hashing")
        .hash(&mut hasher);
    hasher.finish()
}

fn default_overload_brownout_scenarios() -> Vec<OverloadBrownoutScenario> {
    vec![
        OverloadBrownoutScenario {
            scenario_id: "AA-OVERLOAD-BROWNOUT-OPTIONAL-FIRST".to_string(),
            description: "Staged overload replay proving optional runtime surfaces brown out before core throughput and cancellation latency collapse.".to_string(),
            workload_class: "optional-first".to_string(),
            output_root: "target/overload-brownout-smoke".to_string(),
            execution_policy: "execute_or_dry_run".to_string(),
            workload_seed: 808080,
            safe_fallback_profile: "full_surfaces".to_string(),
            expected_winner_profile: "brownout".to_string(),
            brownout_profile: OverloadBrownoutProfile::default(),
            fixture: OverloadBrownoutFixture {
                initial_phase: OverloadBrownoutPhase::Normal,
                replay_count: 2,
                windows: vec![
                    OverloadBrownoutWindow {
                        window_id: "observe_export_formatting".to_string(),
                        wake_to_run_p99_ns: 162_000,
                        queue_residency_p99_ns: 188_000,
                        ready_backlog_p99: 144,
                        cancel_debt_p99: 24,
                        memory_pressure_bps: Some(7_940),
                        degradation_level: DegradationLevel::Light,
                        outer_tail_risk_decision: TailRiskAdmissionDecision::Admit,
                        already_shed_surfaces: Vec::new(),
                        offered_core_units: 96,
                        base_cancel_p99_ns: 158_000,
                    },
                    OverloadBrownoutWindow {
                        window_id: "degrade_diagnostics".to_string(),
                        wake_to_run_p99_ns: 228_000,
                        queue_residency_p99_ns: 246_000,
                        ready_backlog_p99: 208,
                        cancel_debt_p99: 56,
                        memory_pressure_bps: Some(8_820),
                        degradation_level: DegradationLevel::Moderate,
                        outer_tail_risk_decision: TailRiskAdmissionDecision::Defer,
                        already_shed_surfaces: vec![BrownoutOptionalSurface::RichDiagnostics],
                        offered_core_units: 96,
                        base_cancel_p99_ns: 176_000,
                    },
                    OverloadBrownoutWindow {
                        window_id: "shed_optional".to_string(),
                        wake_to_run_p99_ns: 308_000,
                        queue_residency_p99_ns: 322_000,
                        ready_backlog_p99: 264,
                        cancel_debt_p99: 72,
                        memory_pressure_bps: Some(9_420),
                        degradation_level: DegradationLevel::Heavy,
                        outer_tail_risk_decision: TailRiskAdmissionDecision::Shed,
                        already_shed_surfaces: Vec::new(),
                        offered_core_units: 96,
                        base_cancel_p99_ns: 214_000,
                    },
                    OverloadBrownoutWindow {
                        window_id: "recovery_restore".to_string(),
                        wake_to_run_p99_ns: 118_000,
                        queue_residency_p99_ns: 126_000,
                        ready_backlog_p99: 108,
                        cancel_debt_p99: 18,
                        memory_pressure_bps: Some(7_120),
                        degradation_level: DegradationLevel::None,
                        outer_tail_risk_decision: TailRiskAdmissionDecision::Admit,
                        already_shed_surfaces: Vec::new(),
                        offered_core_units: 96,
                        base_cancel_p99_ns: 132_000,
                    },
                ],
            },
            expected_report_projection: Value::Null,
        },
        OverloadBrownoutScenario {
            scenario_id: "AA-OVERLOAD-BROWNOUT-KEEP-FULL-SURFACES".to_string(),
            description: "Low-pressure recovery replay where the operator should keep full optional surfaces pinned because brownout does not win decisively.".to_string(),
            workload_class: "keep-full".to_string(),
            output_root: "target/overload-brownout-smoke".to_string(),
            execution_policy: "execute_or_dry_run".to_string(),
            workload_seed: 919191,
            safe_fallback_profile: "full_surfaces".to_string(),
            expected_winner_profile: "full_surfaces".to_string(),
            brownout_profile: OverloadBrownoutProfile::default(),
            fixture: OverloadBrownoutFixture {
                initial_phase: OverloadBrownoutPhase::Degrade,
                replay_count: 1,
                windows: vec![
                    OverloadBrownoutWindow {
                        window_id: "recovery_hysteresis".to_string(),
                        wake_to_run_p99_ns: 119_000,
                        queue_residency_p99_ns: 122_000,
                        ready_backlog_p99: 112,
                        cancel_debt_p99: 18,
                        memory_pressure_bps: Some(7_180),
                        degradation_level: DegradationLevel::None,
                        outer_tail_risk_decision: TailRiskAdmissionDecision::Admit,
                        already_shed_surfaces: Vec::new(),
                        offered_core_units: 96,
                        base_cancel_p99_ns: 128_000,
                    },
                    OverloadBrownoutWindow {
                        window_id: "restored_normal".to_string(),
                        wake_to_run_p99_ns: 114_000,
                        queue_residency_p99_ns: 118_000,
                        ready_backlog_p99: 104,
                        cancel_debt_p99: 16,
                        memory_pressure_bps: Some(7_040),
                        degradation_level: DegradationLevel::None,
                        outer_tail_risk_decision: TailRiskAdmissionDecision::Admit,
                        already_shed_surfaces: Vec::new(),
                        offered_core_units: 96,
                        base_cancel_p99_ns: 126_000,
                    },
                    OverloadBrownoutWindow {
                        window_id: "steady_state".to_string(),
                        wake_to_run_p99_ns: 112_000,
                        queue_residency_p99_ns: 116_000,
                        ready_backlog_p99: 98,
                        cancel_debt_p99: 16,
                        memory_pressure_bps: Some(7_020),
                        degradation_level: DegradationLevel::None,
                        outer_tail_risk_decision: TailRiskAdmissionDecision::Admit,
                        already_shed_surfaces: Vec::new(),
                        offered_core_units: 96,
                        base_cancel_p99_ns: 124_000,
                    },
                ],
            },
            expected_report_projection: Value::Null,
        },
    ]
}

fn load_overload_brownout_scenarios() -> Vec<OverloadBrownoutScenario> {
    let Ok(path) = std::env::var(OVERLOAD_BROWNOUT_CONTRACT_PATH_ENV) else {
        return default_overload_brownout_scenarios();
    };
    let contract: OverloadBrownoutSmokeContract = serde_json::from_str(
        &fs::read_to_string(Path::new(&path)).expect("read brownout contract"),
    )
    .expect("deserialize brownout contract");
    contract.smoke_scenarios
}

fn selected_overload_brownout_scenario() -> String {
    std::env::var(OVERLOAD_BROWNOUT_SCENARIO_ENV)
        .unwrap_or_else(|_| "AA-OVERLOAD-BROWNOUT-OPTIONAL-FIRST".to_string())
}

fn maybe_write_overload_brownout_report(path: &str, report: &Value) {
    let path = Path::new(path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create overload brownout report parent directory");
    }
    fs::write(
        path,
        serde_json::to_string_pretty(report).expect("serialize overload brownout report"),
    )
    .expect("write overload brownout report");
}

fn build_scheduler_metrics(window: &OverloadBrownoutWindow) -> SchedulerEvidenceMetrics {
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

fn sample_brownout_evidence() -> OverloadBrownoutEvidence {
    OverloadBrownoutEvidence {
        scheduler: Some(SchedulerEvidenceMetrics {
            wake_to_run_p50_ns: 12_000,
            wake_to_run_p95_ns: 162_000,
            wake_to_run_p99_ns: 228_000,
            queue_residency_p50_ns: 18_000,
            queue_residency_p95_ns: 196_000,
            queue_residency_p99_ns: 246_000,
            ready_backlog_p95: 166,
            ready_backlog_p99: 208,
            cancel_debt_p95: 42,
            cancel_debt_p99: 56,
            remote_steal_ratio_pct: Some(22),
            cross_cohort_wake_p99_ns: Some(252_000),
        }),
        memory_pressure_bps: Some(8_820),
        degradation_level: DegradationLevel::Moderate,
        outer_tail_risk_decision: TailRiskAdmissionDecision::Defer,
        previous_phase: OverloadBrownoutPhase::Observe,
        recovery_streak_windows: 0,
        already_shed_surfaces: Vec::new(),
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

fn brownout_phase_label(phase: OverloadBrownoutPhase) -> &'static str {
    match phase {
        OverloadBrownoutPhase::Normal => "normal",
        OverloadBrownoutPhase::Observe => "observe",
        OverloadBrownoutPhase::Degrade => "degrade",
        OverloadBrownoutPhase::ShedOptional => "shed_optional",
        OverloadBrownoutPhase::Recovery => "recovery",
    }
}

fn brownout_reason_label(reason: OverloadBrownoutReason) -> &'static str {
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

fn surface_cost(surface: BrownoutOptionalSurface) -> (u64, u64) {
    match surface {
        BrownoutOptionalSurface::DetailedTracing => (7, 24_000),
        BrownoutOptionalSurface::RichDiagnostics => (6, 18_000),
        BrownoutOptionalSurface::DebugHttp => (4, 12_000),
        BrownoutOptionalSurface::RichExportFormatting => (3, 9_000),
    }
}

fn simulate_window_outcome(
    effective_optional_surfaces: &[BrownoutOptionalSurface],
    requested_degraded_surfaces: &[BrownoutOptionalSurface],
    window: &OverloadBrownoutWindow,
    replay_index: usize,
) -> BrownoutWindowOutcome {
    let enabled_surfaces = effective_optional_surfaces
        .iter()
        .copied()
        .filter(|surface| !requested_degraded_surfaces.contains(surface))
        .collect::<Vec<_>>();
    let enabled_count = enabled_surfaces.len();
    let (surface_penalty_units, surface_cancel_penalty_ns) = enabled_surfaces
        .iter()
        .copied()
        .map(surface_cost)
        .fold((0u64, 0u64), |(units_acc, cancel_acc), (units, cancel)| {
            (units_acc + units, cancel_acc + cancel)
        });
    let memory_penalty_units = window
        .memory_pressure_bps
        .unwrap_or(0)
        .saturating_sub(7_000)
        .saturating_div(130) as u64;
    let backlog_penalty_units = (window.ready_backlog_p99 as u64).saturating_div(28);
    let outer_penalty_units = match window.outer_tail_risk_decision {
        TailRiskAdmissionDecision::Admit => 0,
        TailRiskAdmissionDecision::Defer => 6,
        TailRiskAdmissionDecision::Shed => 14,
    };
    let total_penalty_units = surface_penalty_units
        .saturating_add(memory_penalty_units)
        .saturating_add(backlog_penalty_units)
        .saturating_add(outer_penalty_units)
        .min(window.offered_core_units / 2);
    let core_units_preserved = window
        .offered_core_units
        .saturating_sub(total_penalty_units);

    let memory_cancel_penalty = window
        .memory_pressure_bps
        .unwrap_or(0)
        .saturating_sub(7_000) as u64
        * 20;
    let queue_cancel_penalty = window.queue_residency_p99_ns.saturating_div(4);
    let tail_cancel_penalty = window.wake_to_run_p99_ns.saturating_div(3);
    let cancel_base = window
        .base_cancel_p99_ns
        .saturating_add(surface_cancel_penalty_ns)
        .saturating_add(memory_cancel_penalty)
        .saturating_add(queue_cancel_penalty)
        .saturating_add(tail_cancel_penalty)
        .saturating_add((enabled_count as u64).saturating_mul(3_500));
    let mut cancel_latency_samples = Vec::with_capacity(core_units_preserved as usize);
    for sample_idx in 0..core_units_preserved {
        let jitter = ((replay_index as u64 * 19) + (sample_idx % 11) * 7).saturating_mul(173);
        cancel_latency_samples.push(cancel_base.saturating_add(jitter));
    }

    BrownoutWindowOutcome {
        core_units_preserved,
        cancel_latency_samples,
        active_optional_surface_count: enabled_count,
    }
}

fn build_overload_brownout_report(
    scenario: &OverloadBrownoutScenario,
    include_hash_probe: bool,
) -> Value {
    let effective_optional_surfaces = scenario.brownout_profile.effective_optional_surfaces();
    let total_offered_units = scenario
        .fixture
        .windows
        .iter()
        .map(|window| window.offered_core_units)
        .sum::<u64>()
        .saturating_mul(scenario.fixture.replay_count as u64);

    let mut brownout = BrownoutAccumulator::default();
    let mut full_surfaces = BrownoutAccumulator::default();
    let mut window_reports = Vec::new();
    let mut phase_sequence = Vec::new();
    let mut fallback_windows = Vec::new();
    let mut restored_windows = Vec::new();
    let mut already_shedding_windows = Vec::new();

    for replay_index in 0..scenario.fixture.replay_count {
        let mut previous_phase = scenario.fixture.initial_phase;
        let mut recovery_streak = 0u8;
        for window in &scenario.fixture.windows {
            let evidence = OverloadBrownoutEvidence {
                scheduler: Some(build_scheduler_metrics(window)),
                memory_pressure_bps: window.memory_pressure_bps,
                degradation_level: window.degradation_level,
                outer_tail_risk_decision: window.outer_tail_risk_decision,
                previous_phase,
                recovery_streak_windows: recovery_streak,
                already_shed_surfaces: window.already_shed_surfaces.clone(),
            };
            let ledger = OverloadBrownoutLedger::evaluate(&evidence, &scenario.brownout_profile);
            let brownout_outcome = simulate_window_outcome(
                &effective_optional_surfaces,
                &ledger.requested_degraded_surfaces,
                window,
                replay_index,
            );
            let full_outcome =
                simulate_window_outcome(&effective_optional_surfaces, &[], window, replay_index);

            brownout.record(
                ledger.phase,
                ledger.fallback_used,
                ledger.requested_degraded_surfaces.len(),
                &brownout_outcome,
            );
            full_surfaces.record(OverloadBrownoutPhase::Normal, false, 0, &full_outcome);

            if replay_index == 0 {
                phase_sequence.push(brownout_phase_label(ledger.phase).to_string());
                if ledger.fallback_used {
                    fallback_windows.push(window.window_id.clone());
                }
                if !ledger.restored_surfaces.is_empty() {
                    restored_windows.push(window.window_id.clone());
                }
                if !ledger.already_shed_surfaces.is_empty() {
                    already_shedding_windows.push(window.window_id.clone());
                }
                window_reports.push(json!({
                    "window_id": window.window_id,
                    "memory_pressure_bps": window.memory_pressure_bps,
                    "degradation_level": format!("{:?}", window.degradation_level).to_lowercase(),
                    "outer_tail_risk_decision": format!("{:?}", window.outer_tail_risk_decision).to_lowercase(),
                    "brownout": {
                        "phase": brownout_phase_label(ledger.phase),
                        "fallback_used": ledger.fallback_used,
                        "reason_codes": ledger.reason_codes.iter().map(|reason| brownout_reason_label(*reason)).collect::<Vec<_>>(),
                        "requested_degraded_surfaces": ledger.requested_degraded_surfaces.iter().map(|surface| optional_surface_label(*surface)).collect::<Vec<_>>(),
                        "newly_degraded_surfaces": ledger.newly_degraded_surfaces.iter().map(|surface| optional_surface_label(*surface)).collect::<Vec<_>>(),
                        "already_shed_surfaces": ledger.already_shed_surfaces.iter().map(|surface| optional_surface_label(*surface)).collect::<Vec<_>>(),
                        "restored_surfaces": ledger.restored_surfaces.iter().map(|surface| optional_surface_label(*surface)).collect::<Vec<_>>(),
                        "preserved_surfaces": ledger.preserved_surfaces,
                        "recovery_streak_after": ledger.recovery_streak_after,
                        "core_units_preserved": brownout_outcome.core_units_preserved,
                        "cancel_p99_ns": percentile_slice_u64(&brownout_outcome.cancel_latency_samples, 99, 100),
                        "active_optional_surface_count": brownout_outcome.active_optional_surface_count,
                    },
                    "full_surfaces": {
                        "core_units_preserved": full_outcome.core_units_preserved,
                        "cancel_p99_ns": percentile_slice_u64(&full_outcome.cancel_latency_samples, 99, 100),
                        "active_optional_surface_count": full_outcome.active_optional_surface_count,
                    }
                }));
            }

            previous_phase = ledger.phase;
            recovery_streak = ledger.recovery_streak_after;
        }
    }

    let brownout_summary = brownout.summary(total_offered_units);
    let full_summary = full_surfaces.summary(total_offered_units);
    let cancel_p95_improvement_ns = full_summary
        .cancel_p95_ns
        .saturating_sub(brownout_summary.cancel_p95_ns);
    let cancel_p99_improvement_ns = full_summary
        .cancel_p99_ns
        .saturating_sub(brownout_summary.cancel_p99_ns);
    let brownout_core_units = i64::try_from(brownout_summary.core_units_preserved)
        .expect("brownout preserved units fit report delta");
    let full_core_units = i64::try_from(full_summary.core_units_preserved)
        .expect("full-surface preserved units fit report delta");
    let core_units_delta = brownout_core_units - full_core_units;
    let winner_profile = if cancel_p99_improvement_ns >= 40_000 || core_units_delta >= 8 {
        "brownout"
    } else {
        scenario.safe_fallback_profile.as_str()
    };
    let no_win_trigger = winner_profile == scenario.safe_fallback_profile;
    let report_projection = json!({
        "schema_version": OVERLOAD_BROWNOUT_PROJECTION_SCHEMA_VERSION,
        "scenario_id": scenario.scenario_id,
        "workload_class": scenario.workload_class,
        "workload_seed": scenario.workload_seed,
        "replay_count": scenario.fixture.replay_count,
        "window_count": scenario.fixture.windows.len(),
        "phase_sequence": phase_sequence,
        "fallback_windows": fallback_windows,
        "restored_windows": restored_windows,
        "already_shedding_windows": already_shedding_windows,
        "brownout": {
            "observe_count": brownout_summary.observe_count,
            "degrade_count": brownout_summary.degrade_count,
            "shed_optional_count": brownout_summary.shed_optional_count,
            "recovery_count": brownout_summary.recovery_count,
            "fallback_used_count": brownout_summary.fallback_used_count,
            "core_units_preserved": brownout_summary.core_units_preserved,
            "cancel_p95_ns": brownout_summary.cancel_p95_ns,
            "cancel_p99_ns": brownout_summary.cancel_p99_ns,
            "throughput_ratio": brownout_summary.throughput_ratio,
            "optional_surface_reduction_events": brownout_summary.optional_surface_reduction_events,
        },
        "full_surfaces": {
            "core_units_preserved": full_summary.core_units_preserved,
            "cancel_p95_ns": full_summary.cancel_p95_ns,
            "cancel_p99_ns": full_summary.cancel_p99_ns,
            "throughput_ratio": full_summary.throughput_ratio,
        },
        "comparison": {
            "cancel_p95_improvement_ns": cancel_p95_improvement_ns,
            "cancel_p99_improvement_ns": cancel_p99_improvement_ns,
            "core_units_delta": core_units_delta,
            "winner_profile": winner_profile,
            "no_win_trigger": no_win_trigger,
        }
    });
    let repeated_run_hash_match = if include_hash_probe {
        let probe = build_overload_brownout_report(scenario, false);
        hash_json_value(&probe["report_projection"]) == hash_json_value(&report_projection)
    } else {
        true
    };

    json!({
        "schema_version": OVERLOAD_BROWNOUT_REPORT_SCHEMA_VERSION,
        "scenario_id": scenario.scenario_id,
        "description": scenario.description,
        "workload_class": scenario.workload_class,
        "workload_seed": scenario.workload_seed,
        "safe_fallback_profile": scenario.safe_fallback_profile,
        "expected_winner_profile": scenario.expected_winner_profile,
        "brownout_profile": scenario.brownout_profile,
        "report_projection": report_projection,
        "repeated_run_hash_match": repeated_run_hash_match,
        "brownout_summary": brownout_summary,
        "full_surfaces_summary": full_summary,
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
fn overload_brownout_runner_rejects_full_rch_fallback_marker_set() {
    let script = fs::read_to_string("scripts/run_overload_brownout_smoke.sh")
        .expect("overload brownout smoke runner should load");

    assert!(
        script
            .matches(r#"grep -Eiq "$RCH_LOCAL_FALLBACK_PATTERN""#)
            .count()
            >= 1,
        "runner must use the shared local fallback matcher at its rch gate"
    );

    for token in [
        "RCH_LOCAL_FALLBACK_PATTERN=",
        "[RCH\\] local",
        "falling back to local",
        "local fallback",
        "fallback to local",
        "executing locally",
    ] {
        assert!(
            script.contains(token),
            "runner missing local fallback marker: {token}"
        );
    }
}

#[test]
fn overload_brownout_smoke_contract_emits_report() {
    let scenarios = load_overload_brownout_scenarios();
    let scenario_id = selected_overload_brownout_scenario();
    let scenario = scenarios
        .iter()
        .find(|candidate| candidate.scenario_id == scenario_id)
        .expect("selected overload brownout scenario must exist");
    let report = build_overload_brownout_report(scenario, true);
    if !scenario.expected_report_projection.is_null() {
        assert_eq!(
            report["report_projection"], scenario.expected_report_projection,
            "brownout smoke contract projection must stay stable"
        );
    }
    assert_eq!(
        report["repeated_run_hash_match"].as_bool(),
        Some(true),
        "repeated brownout report generation must be deterministic"
    );
    assert_eq!(
        report["operator_verdict"]["pass"].as_bool(),
        Some(true),
        "operator verdict must agree with the expected winner profile"
    );

    if let Ok(path) = std::env::var(OVERLOAD_BROWNOUT_REPORT_PATH_ENV) {
        maybe_write_overload_brownout_report(&path, &report);
    }

    println!("OVERLOAD_BROWNOUT_REPORT_JSON_BEGIN");
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("serialize overload brownout report")
    );
    println!("OVERLOAD_BROWNOUT_REPORT_JSON_END");
}

#[test]
fn overload_brownout_unit_coverage_filters_denied_surfaces() {
    let profile = OverloadBrownoutProfile {
        allowed_optional_surfaces: vec![
            BrownoutOptionalSurface::DetailedTracing,
            BrownoutOptionalSurface::RichDiagnostics,
            BrownoutOptionalSurface::DetailedTracing,
            BrownoutOptionalSurface::RichExportFormatting,
        ],
        denied_optional_surfaces: vec![BrownoutOptionalSurface::RichDiagnostics],
        ..OverloadBrownoutProfile::default()
    };

    assert_eq!(
        profile.effective_optional_surfaces(),
        vec![
            BrownoutOptionalSurface::DetailedTracing,
            BrownoutOptionalSurface::RichExportFormatting,
        ]
    );
}

#[test]
fn overload_brownout_unit_coverage_disabled_mode_matches_normal() {
    let profile = OverloadBrownoutProfile {
        enabled: false,
        ..OverloadBrownoutProfile::default()
    };
    let ledger = OverloadBrownoutLedger::evaluate(&sample_brownout_evidence(), &profile);

    assert!(ledger.fallback_used);
    assert_eq!(ledger.phase, OverloadBrownoutPhase::Normal);
    assert!(ledger.requested_degraded_surfaces.is_empty());
    assert!(
        ledger
            .reason_codes
            .contains(&OverloadBrownoutReason::Disabled)
    );
}

#[test]
fn overload_brownout_unit_coverage_missing_evidence_falls_back_conservatively() {
    let ledger = OverloadBrownoutLedger::evaluate(
        &OverloadBrownoutEvidence {
            scheduler: None,
            memory_pressure_bps: Some(7_900),
            degradation_level: DegradationLevel::Light,
            outer_tail_risk_decision: TailRiskAdmissionDecision::Admit,
            previous_phase: OverloadBrownoutPhase::Normal,
            recovery_streak_windows: 0,
            already_shed_surfaces: Vec::new(),
        },
        &OverloadBrownoutProfile::default(),
    );

    assert!(ledger.fallback_used);
    assert_eq!(ledger.phase, OverloadBrownoutPhase::Observe);
    assert_eq!(
        ledger.missing_evidence_fields,
        vec!["scheduler_metrics".to_string()]
    );
    assert!(
        ledger
            .reason_codes
            .contains(&OverloadBrownoutReason::MissingEvidenceFallback)
    );
}

#[test]
fn overload_brownout_unit_coverage_sheds_optional_under_severe_pressure() {
    let ledger = OverloadBrownoutLedger::evaluate(
        &OverloadBrownoutEvidence {
            memory_pressure_bps: Some(9_450),
            outer_tail_risk_decision: TailRiskAdmissionDecision::Shed,
            degradation_level: DegradationLevel::Heavy,
            ..sample_brownout_evidence()
        },
        &OverloadBrownoutProfile::default(),
    );

    assert_eq!(ledger.phase, OverloadBrownoutPhase::ShedOptional);
    assert!(
        ledger
            .requested_degraded_surfaces
            .contains(&BrownoutOptionalSurface::DetailedTracing)
    );
    assert!(
        ledger
            .reason_codes
            .contains(&OverloadBrownoutReason::TailRiskOuterShed)
    );
}

#[test]
fn overload_brownout_unit_coverage_restores_surfaces_with_recovery_hysteresis() {
    let ledger = OverloadBrownoutLedger::evaluate(
        &OverloadBrownoutEvidence {
            scheduler: Some(SchedulerEvidenceMetrics {
                wake_to_run_p50_ns: 7_500,
                wake_to_run_p95_ns: 74_000,
                wake_to_run_p99_ns: 118_000,
                queue_residency_p50_ns: 12_000,
                queue_residency_p95_ns: 88_000,
                queue_residency_p99_ns: 120_000,
                ready_backlog_p95: 96,
                ready_backlog_p99: 128,
                cancel_debt_p95: 12,
                cancel_debt_p99: 20,
                remote_steal_ratio_pct: Some(10),
                cross_cohort_wake_p99_ns: Some(92_000),
            }),
            memory_pressure_bps: Some(7_100),
            degradation_level: DegradationLevel::None,
            outer_tail_risk_decision: TailRiskAdmissionDecision::Admit,
            previous_phase: OverloadBrownoutPhase::ShedOptional,
            recovery_streak_windows: 0,
            already_shed_surfaces: Vec::new(),
        },
        &OverloadBrownoutProfile::default(),
    );

    assert_eq!(ledger.phase, OverloadBrownoutPhase::Recovery);
    assert_eq!(ledger.recovery_streak_after, 1);
    assert!(
        ledger
            .restored_surfaces
            .contains(&BrownoutOptionalSurface::DetailedTracing)
    );
    assert!(
        ledger
            .reason_codes
            .contains(&OverloadBrownoutReason::RecoveryHysteresis)
    );
}

#[test]
fn overload_brownout_unit_coverage_avoids_duplicate_self_shedding_accounting() {
    let ledger = OverloadBrownoutLedger::evaluate(
        &OverloadBrownoutEvidence {
            already_shed_surfaces: vec![BrownoutOptionalSurface::RichDiagnostics],
            ..sample_brownout_evidence()
        },
        &OverloadBrownoutProfile::default(),
    );

    assert_eq!(ledger.phase, OverloadBrownoutPhase::Degrade);
    assert!(
        ledger
            .already_shed_surfaces
            .contains(&BrownoutOptionalSurface::RichDiagnostics)
    );
    assert!(
        !ledger
            .newly_degraded_surfaces
            .contains(&BrownoutOptionalSurface::RichDiagnostics)
    );
    assert!(
        ledger
            .reason_codes
            .contains(&OverloadBrownoutReason::OptionalSurfaceAlreadyShedding)
    );
}

#[test]
fn overload_brownout_unit_coverage_preserves_critical_surfaces() {
    let ledger = OverloadBrownoutLedger::evaluate(
        &sample_brownout_evidence(),
        &OverloadBrownoutProfile::default(),
    );

    assert_eq!(ledger.phase, OverloadBrownoutPhase::Degrade);
    assert_eq!(
        ledger.preserved_surfaces,
        vec![
            BrownoutProtectedSurface::CoreScheduling,
            BrownoutProtectedSurface::CancellationDrain,
            BrownoutProtectedSurface::RegionQuiescence,
            BrownoutProtectedSurface::ObligationCleanup,
        ]
    );
}

#[test]
fn overload_brownout_unit_coverage_is_idempotent_for_same_inputs() {
    let evidence = sample_brownout_evidence();
    let profile = OverloadBrownoutProfile::default();
    let first = OverloadBrownoutLedger::evaluate(&evidence, &profile);
    let second = OverloadBrownoutLedger::evaluate(&evidence, &profile);

    assert_eq!(first, second);
}

#[test]
fn overload_brownout_unit_coverage_ledger_round_trips_through_json() {
    let ledger = OverloadBrownoutLedger::evaluate(
        &sample_brownout_evidence(),
        &OverloadBrownoutProfile::default(),
    );
    let json = serde_json::to_string_pretty(&ledger).expect("serialize overload brownout");
    let reparsed: OverloadBrownoutLedger =
        serde_json::from_str(&json).expect("deserialize overload brownout");

    assert_eq!(reparsed, ledger);
}
