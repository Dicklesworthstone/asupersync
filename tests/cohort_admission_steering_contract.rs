//! Contract-backed smoke proof for cohort-aware admission steering.

use asupersync::runtime::resource_monitor::{
    CohortAdmissionSteeringDecision, CohortAdmissionSteeringEvidence,
    CohortAdmissionSteeringLedger, CohortAdmissionSteeringProfile, CohortAdmissionSteeringReason,
    CohortRemoteSpillBudgetState, TailRiskAdmissionDecision,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::Path;

const COHORT_ADMISSION_STEERING_CONTRACT_PATH_ENV: &str =
    "ASUPERSYNC_COHORT_ADMISSION_STEERING_CONTRACT_PATH";
const COHORT_ADMISSION_STEERING_SCENARIO_ENV: &str =
    "ASUPERSYNC_COHORT_ADMISSION_STEERING_SCENARIO";
const COHORT_ADMISSION_STEERING_REPORT_PATH_ENV: &str =
    "ASUPERSYNC_COHORT_ADMISSION_STEERING_REPORT_PATH";
const COHORT_ADMISSION_STEERING_REPORT_SCHEMA_VERSION: &str = "cohort-admission-steering-report-v1";
const COHORT_ADMISSION_STEERING_PROJECTION_SCHEMA_VERSION: &str =
    "cohort-admission-steering-projection-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CohortAdmissionSteeringSmokeContract {
    smoke_scenarios: Vec<CohortAdmissionSteeringScenario>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CohortAdmissionSteeringScenario {
    scenario_id: String,
    description: String,
    workload_class: String,
    output_root: String,
    execution_policy: String,
    workload_seed: u64,
    safe_fallback_profile: String,
    expected_winner_profile: String,
    steering_profile: CohortAdmissionSteeringProfile,
    fixture: CohortAdmissionSteeringFixture,
    expected_report_projection: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CohortAdmissionSteeringFixture {
    replay_count: usize,
    windows: Vec<CohortAdmissionSteeringWindow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CohortAdmissionSteeringWindow {
    window_id: String,
    local_cohort: Option<usize>,
    worker_to_cohort_map: Vec<usize>,
    cohort_ready_backlog: Vec<usize>,
    topology_confidence_percent: Option<u8>,
    decision_epoch: u64,
    consecutive_local_defers: u16,
    outer_tail_risk_decision: TailRiskAdmissionDecision,
    offered_work_units: u64,
    local_wake_to_run_p99_ns: u64,
    remote_wake_to_run_p99_ns: u64,
}

#[derive(Debug, Clone)]
struct CohortPlacementWindowOutcome {
    admitted_units: u64,
    deferred_units: u64,
    remote_spill_count: u64,
    latency_samples: Vec<u64>,
}

#[derive(Debug, Clone, Default, Serialize)]
struct CohortSteeringAccumulator {
    admit_local_count: u64,
    redirect_remote_count: u64,
    defer_count: u64,
    fallback_used_count: u64,
    budget_exhausted_count: u64,
    fairness_escape_count: u64,
    admitted_units: u64,
    deferred_units: u64,
    remote_spill_count: u64,
    latencies: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
struct CohortSteeringSummary {
    admit_local_count: u64,
    redirect_remote_count: u64,
    defer_count: u64,
    fallback_used_count: u64,
    budget_exhausted_count: u64,
    fairness_escape_count: u64,
    admitted_units: u64,
    deferred_units: u64,
    remote_spill_count: u64,
    p50_latency_ns: u64,
    p95_latency_ns: u64,
    p99_latency_ns: u64,
    max_latency_ns: u64,
    throughput_ratio: f64,
}

impl CohortSteeringAccumulator {
    fn record(
        &mut self,
        decision: CohortAdmissionSteeringDecision,
        fallback_used: bool,
        budget_exhausted: bool,
        fairness_escape: bool,
        outcome: &CohortPlacementWindowOutcome,
    ) {
        match decision {
            CohortAdmissionSteeringDecision::AdmitLocal => self.admit_local_count += 1,
            CohortAdmissionSteeringDecision::RedirectRemote => self.redirect_remote_count += 1,
            CohortAdmissionSteeringDecision::Defer => self.defer_count += 1,
        }
        self.fallback_used_count += u64::from(fallback_used);
        self.budget_exhausted_count += u64::from(budget_exhausted);
        self.fairness_escape_count += u64::from(fairness_escape);
        self.admitted_units += outcome.admitted_units;
        self.deferred_units += outcome.deferred_units;
        self.remote_spill_count += outcome.remote_spill_count;
        self.latencies.extend_from_slice(&outcome.latency_samples);
    }

    fn summary(&self, total_offered_units: u64) -> CohortSteeringSummary {
        let max_latency_ns = self.latencies.iter().copied().max().unwrap_or(0);
        let throughput_ratio = if total_offered_units == 0 {
            0.0
        } else {
            round4(self.admitted_units as f64 / total_offered_units as f64)
        };
        CohortSteeringSummary {
            admit_local_count: self.admit_local_count,
            redirect_remote_count: self.redirect_remote_count,
            defer_count: self.defer_count,
            fallback_used_count: self.fallback_used_count,
            budget_exhausted_count: self.budget_exhausted_count,
            fairness_escape_count: self.fairness_escape_count,
            admitted_units: self.admitted_units,
            deferred_units: self.deferred_units,
            remote_spill_count: self.remote_spill_count,
            p50_latency_ns: percentile_slice_u64(&self.latencies, 50, 100),
            p95_latency_ns: percentile_slice_u64(&self.latencies, 95, 100),
            p99_latency_ns: percentile_slice_u64(&self.latencies, 99, 100),
            max_latency_ns,
            throughput_ratio,
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

fn u64_count_delta(lhs: u64, rhs: u64) -> i64 {
    let lhs = i64::try_from(lhs).expect("cohort steering count fits i64");
    let rhs = i64::try_from(rhs).expect("cohort steering count fits i64");
    lhs - rhs
}

fn default_cohort_admission_steering_scenarios() -> Vec<CohortAdmissionSteeringScenario> {
    vec![
        CohortAdmissionSteeringScenario {
            scenario_id: "AA-COHORT-ADMISSION-STEERING-LOCALITY-WIN-2C".to_string(),
            description: "High-confidence two-cohort replay where bounded redirect tokens cut wake-to-run tails and remote spill pressure versus conservative global routing.".to_string(),
            workload_class: "locality-win".to_string(),
            output_root: "target/cohort-admission-steering-smoke".to_string(),
            execution_policy: "execute_or_dry_run".to_string(),
            workload_seed: 424242,
            safe_fallback_profile: "conservative_global".to_string(),
            expected_winner_profile: "cohort_steered".to_string(),
            steering_profile: CohortAdmissionSteeringProfile::default(),
            fixture: CohortAdmissionSteeringFixture {
                replay_count: 2,
                windows: vec![
                    CohortAdmissionSteeringWindow {
                        window_id: "local_balanced".to_string(),
                        local_cohort: Some(0),
                        worker_to_cohort_map: vec![0, 0, 1, 1],
                        cohort_ready_backlog: vec![148, 128],
                        topology_confidence_percent: Some(90),
                        decision_epoch: 10,
                        consecutive_local_defers: 0,
                        outer_tail_risk_decision: TailRiskAdmissionDecision::Admit,
                        offered_work_units: 48,
                        local_wake_to_run_p99_ns: 148_000,
                        remote_wake_to_run_p99_ns: 142_000,
                    },
                    CohortAdmissionSteeringWindow {
                        window_id: "local_saturated".to_string(),
                        local_cohort: Some(0),
                        worker_to_cohort_map: vec![0, 0, 1, 1],
                        cohort_ready_backlog: vec![260, 84],
                        topology_confidence_percent: Some(92),
                        decision_epoch: 10,
                        consecutive_local_defers: 1,
                        outer_tail_risk_decision: TailRiskAdmissionDecision::Admit,
                        offered_work_units: 48,
                        local_wake_to_run_p99_ns: 236_000,
                        remote_wake_to_run_p99_ns: 146_000,
                    },
                    CohortAdmissionSteeringWindow {
                        window_id: "fairness_escape".to_string(),
                        local_cohort: Some(0),
                        worker_to_cohort_map: vec![0, 0, 1, 1],
                        cohort_ready_backlog: vec![244, 96],
                        topology_confidence_percent: Some(90),
                        decision_epoch: 10,
                        consecutive_local_defers: 3,
                        outer_tail_risk_decision: TailRiskAdmissionDecision::Admit,
                        offered_work_units: 48,
                        local_wake_to_run_p99_ns: 228_000,
                        remote_wake_to_run_p99_ns: 154_000,
                    },
                ],
            },
            expected_report_projection: Value::Null,
        },
        CohortAdmissionSteeringScenario {
            scenario_id: "AA-COHORT-ADMISSION-STEERING-KEEP-GLOBAL-2C".to_string(),
            description: "Low-confidence and no-win replay that keeps the conservative global routing path pinned and records an explicit safe fallback verdict.".to_string(),
            workload_class: "keep-global".to_string(),
            output_root: "target/cohort-admission-steering-smoke".to_string(),
            execution_policy: "execute_or_dry_run".to_string(),
            workload_seed: 515151,
            safe_fallback_profile: "conservative_global".to_string(),
            expected_winner_profile: "conservative_global".to_string(),
            steering_profile: CohortAdmissionSteeringProfile::default(),
            fixture: CohortAdmissionSteeringFixture {
                replay_count: 1,
                windows: vec![
                    CohortAdmissionSteeringWindow {
                        window_id: "low_confidence".to_string(),
                        local_cohort: Some(0),
                        worker_to_cohort_map: vec![0, 0, 1, 1],
                        cohort_ready_backlog: vec![208, 198],
                        topology_confidence_percent: Some(48),
                        decision_epoch: 22,
                        consecutive_local_defers: 0,
                        outer_tail_risk_decision: TailRiskAdmissionDecision::Admit,
                        offered_work_units: 48,
                        local_wake_to_run_p99_ns: 204_000,
                        remote_wake_to_run_p99_ns: 201_000,
                    },
                    CohortAdmissionSteeringWindow {
                        window_id: "thin_remote_gain".to_string(),
                        local_cohort: Some(0),
                        worker_to_cohort_map: vec![0, 0, 1, 1],
                        cohort_ready_backlog: vec![214, 196],
                        topology_confidence_percent: Some(88),
                        decision_epoch: 23,
                        consecutive_local_defers: 1,
                        outer_tail_risk_decision: TailRiskAdmissionDecision::Admit,
                        offered_work_units: 48,
                        local_wake_to_run_p99_ns: 211_000,
                        remote_wake_to_run_p99_ns: 208_000,
                    },
                    CohortAdmissionSteeringWindow {
                        window_id: "tail_risk_outer_cap".to_string(),
                        local_cohort: Some(0),
                        worker_to_cohort_map: vec![0, 0, 1, 1],
                        cohort_ready_backlog: vec![228, 150],
                        topology_confidence_percent: Some(90),
                        decision_epoch: 24,
                        consecutive_local_defers: 4,
                        outer_tail_risk_decision: TailRiskAdmissionDecision::Defer,
                        offered_work_units: 48,
                        local_wake_to_run_p99_ns: 224_000,
                        remote_wake_to_run_p99_ns: 176_000,
                    },
                ],
            },
            expected_report_projection: Value::Null,
        },
    ]
}

fn load_cohort_admission_steering_scenarios() -> Vec<CohortAdmissionSteeringScenario> {
    let Ok(path) = std::env::var(COHORT_ADMISSION_STEERING_CONTRACT_PATH_ENV) else {
        return default_cohort_admission_steering_scenarios();
    };
    let contract: CohortAdmissionSteeringSmokeContract = serde_json::from_str(
        &fs::read_to_string(Path::new(&path)).expect("read cohort admission steering contract"),
    )
    .expect("deserialize cohort admission steering contract");
    contract.smoke_scenarios
}

fn selected_cohort_admission_steering_scenario() -> String {
    std::env::var(COHORT_ADMISSION_STEERING_SCENARIO_ENV)
        .unwrap_or_else(|_| "AA-COHORT-ADMISSION-STEERING-LOCALITY-WIN-2C".to_string())
}

fn maybe_write_cohort_admission_steering_report(path: &str, report: &Value) {
    let path = Path::new(path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create cohort report parent directory");
    }
    fs::write(
        path,
        serde_json::to_string_pretty(report).expect("serialize cohort admission steering report"),
    )
    .expect("write cohort admission steering report");
}

fn conservative_global_decision(
    window: &CohortAdmissionSteeringWindow,
) -> CohortAdmissionSteeringDecision {
    if window.outer_tail_risk_decision == TailRiskAdmissionDecision::Admit {
        CohortAdmissionSteeringDecision::AdmitLocal
    } else {
        CohortAdmissionSteeringDecision::Defer
    }
}

fn simulate_cohort_window_outcome(
    decision: CohortAdmissionSteeringDecision,
    target_cohort: Option<usize>,
    window: &CohortAdmissionSteeringWindow,
    replay_index: usize,
) -> CohortPlacementWindowOutcome {
    let offered = window.offered_work_units;
    let local_cohort = window.local_cohort.unwrap_or(0);
    let local_backlog_usize = window
        .cohort_ready_backlog
        .get(local_cohort)
        .copied()
        .unwrap_or(0);
    let local_backlog = local_backlog_usize as u64;
    let best_remote_backlog = window
        .cohort_ready_backlog
        .iter()
        .enumerate()
        .filter(|(cohort, _)| *cohort != local_cohort)
        .map(|(_, backlog)| *backlog)
        .min()
        .unwrap_or(local_backlog_usize) as u64;
    let remote_backlog = target_cohort
        .and_then(|cohort| window.cohort_ready_backlog.get(cohort).copied())
        .unwrap_or(best_remote_backlog as usize) as u64;
    let backlog_gap = local_backlog.saturating_sub(best_remote_backlog);

    let (
        admitted_units,
        deferred_units,
        remote_spill_count,
        p99_base,
        overload_multiplier,
        decision_penalty,
    ) = match decision {
        CohortAdmissionSteeringDecision::AdmitLocal => (
            offered,
            0,
            backlog_gap.saturating_div(40),
            window.local_wake_to_run_p99_ns,
            1_350,
            21_000 + backlog_gap.saturating_mul(320),
        ),
        CohortAdmissionSteeringDecision::RedirectRemote => (
            offered,
            0,
            1,
            window.remote_wake_to_run_p99_ns,
            780,
            13_500 + remote_backlog.saturating_mul(110),
        ),
        CohortAdmissionSteeringDecision::Defer => (
            offered.saturating_mul(82).saturating_div(100),
            offered.saturating_sub(offered.saturating_mul(82).saturating_div(100)),
            0,
            window.local_wake_to_run_p99_ns.saturating_sub(18_000),
            620,
            9_500,
        ),
    };

    let backlog_source = match decision {
        CohortAdmissionSteeringDecision::RedirectRemote => remote_backlog,
        CohortAdmissionSteeringDecision::AdmitLocal | CohortAdmissionSteeringDecision::Defer => {
            local_backlog
        }
    };

    let base_latency = p99_base
        .saturating_div(2)
        .saturating_add(backlog_source.saturating_mul(overload_multiplier))
        .saturating_add(decision_penalty);
    let mut latency_samples = Vec::with_capacity(admitted_units as usize);
    for sample_idx in 0..admitted_units {
        let jitter = ((replay_index as u64 * 23) + (sample_idx % 17) * 11).saturating_mul(131);
        latency_samples.push(base_latency.saturating_add(jitter));
    }

    CohortPlacementWindowOutcome {
        admitted_units,
        deferred_units,
        remote_spill_count,
        latency_samples,
    }
}

fn cohort_steering_reason_label(reason: CohortAdmissionSteeringReason) -> &'static str {
    match reason {
        CohortAdmissionSteeringReason::Disabled => "disabled",
        CohortAdmissionSteeringReason::MissingTopology => "missing_topology",
        CohortAdmissionSteeringReason::LowConfidenceFallback => "low_confidence_fallback",
        CohortAdmissionSteeringReason::TailRiskOuterCap => "tail_risk_outer_cap",
        CohortAdmissionSteeringReason::LocalCapacityAvailable => "local_capacity_available",
        CohortAdmissionSteeringReason::LocalBacklogPressure => "local_backlog_pressure",
        CohortAdmissionSteeringReason::RemoteSpillBudgetSpent => "remote_spill_budget_spent",
        CohortAdmissionSteeringReason::RemoteSpillBudgetExhausted => {
            "remote_spill_budget_exhausted"
        }
        CohortAdmissionSteeringReason::FairnessEscapeHatch => "fairness_escape_hatch",
        CohortAdmissionSteeringReason::ConservativeGlobalBaseline => "conservative_global_baseline",
    }
}

fn build_cohort_admission_steering_report(
    scenario: &CohortAdmissionSteeringScenario,
    include_hash_probe: bool,
) -> Value {
    let total_offered_units = scenario
        .fixture
        .windows
        .iter()
        .map(|window| window.offered_work_units)
        .sum::<u64>()
        .saturating_mul(scenario.fixture.replay_count as u64);

    let mut steered = CohortSteeringAccumulator::default();
    let mut conservative_global = CohortSteeringAccumulator::default();
    let mut window_reports = Vec::new();
    let mut decision_sequence = Vec::new();
    let mut conservative_sequence = Vec::new();
    let mut fallback_windows = Vec::new();
    let mut fairness_windows = Vec::new();
    let mut budget_start_sequence = Vec::new();
    let mut budget_remaining_sequence = Vec::new();

    let mut budget_state = CohortRemoteSpillBudgetState::new(
        scenario
            .fixture
            .windows
            .first()
            .map_or(0, |window| window.decision_epoch),
        scenario.steering_profile.remote_spill_budget_per_epoch,
    );

    for replay_index in 0..scenario.fixture.replay_count {
        let mut replay_budget = budget_state;
        for window in &scenario.fixture.windows {
            let evidence = CohortAdmissionSteeringEvidence {
                local_cohort: window.local_cohort,
                worker_to_cohort_map: window.worker_to_cohort_map.clone(),
                cohort_ready_backlog: window.cohort_ready_backlog.clone(),
                topology_confidence_percent: window.topology_confidence_percent,
                remote_spill_budget: replay_budget,
                decision_epoch: window.decision_epoch,
                consecutive_local_defers: window.consecutive_local_defers,
                outer_tail_risk_decision: window.outer_tail_risk_decision,
            };
            let ledger =
                CohortAdmissionSteeringLedger::evaluate(&evidence, &scenario.steering_profile);
            replay_budget = CohortRemoteSpillBudgetState::new(
                ledger.evidence.remote_spill_budget_epoch,
                ledger.remote_spill_budget_remaining,
            );

            let global_decision = conservative_global_decision(window);
            let steered_outcome = simulate_cohort_window_outcome(
                ledger.decision,
                ledger.target_cohort,
                window,
                replay_index,
            );
            let global_outcome =
                simulate_cohort_window_outcome(global_decision, None, window, replay_index);

            steered.record(
                ledger.decision,
                ledger.fallback_used,
                ledger
                    .reason_codes
                    .contains(&CohortAdmissionSteeringReason::RemoteSpillBudgetExhausted)
                    || ledger.remote_spill_budget_remaining == 0,
                ledger
                    .reason_codes
                    .contains(&CohortAdmissionSteeringReason::FairnessEscapeHatch),
                &steered_outcome,
            );
            conservative_global.record(global_decision, false, false, false, &global_outcome);

            if replay_index == 0 {
                decision_sequence.push(format!("{:?}", ledger.decision).to_lowercase());
                conservative_sequence.push(format!("{:?}", global_decision).to_lowercase());
                budget_start_sequence.push(ledger.remote_spill_budget_start);
                budget_remaining_sequence.push(ledger.remote_spill_budget_remaining);
                if ledger.fallback_used {
                    fallback_windows.push(window.window_id.clone());
                }
                if ledger
                    .reason_codes
                    .contains(&CohortAdmissionSteeringReason::FairnessEscapeHatch)
                {
                    fairness_windows.push(window.window_id.clone());
                }
                window_reports.push(json!({
                    "window_id": window.window_id,
                    "worker_to_cohort_map": window.worker_to_cohort_map,
                    "cohort_ready_backlog": window.cohort_ready_backlog,
                    "topology_confidence_percent": window.topology_confidence_percent,
                    "outer_tail_risk_decision": format!("{:?}", window.outer_tail_risk_decision).to_lowercase(),
                    "steered": {
                        "decision": format!("{:?}", ledger.decision).to_lowercase(),
                        "target_cohort": ledger.target_cohort,
                        "fallback_used": ledger.fallback_used,
                        "confidence_percent": ledger.confidence_percent,
                        "reason_codes": ledger.reason_codes.iter().map(|reason| cohort_steering_reason_label(*reason)).collect::<Vec<_>>(),
                        "missing_evidence_fields": ledger.missing_evidence_fields,
                        "remote_spill_budget_start": ledger.remote_spill_budget_start,
                        "remote_spill_budget_remaining": ledger.remote_spill_budget_remaining,
                        "remote_spill_budget_exhausted": ledger.remote_spill_budget_exhausted,
                        "admitted_units": steered_outcome.admitted_units,
                        "deferred_units": steered_outcome.deferred_units,
                        "remote_spill_count": steered_outcome.remote_spill_count,
                        "window_p99_ns": percentile_slice_u64(&steered_outcome.latency_samples, 99, 100),
                    },
                    "conservative_global": {
                        "decision": format!("{:?}", global_decision).to_lowercase(),
                        "admitted_units": global_outcome.admitted_units,
                        "deferred_units": global_outcome.deferred_units,
                        "remote_spill_count": global_outcome.remote_spill_count,
                        "window_p99_ns": percentile_slice_u64(&global_outcome.latency_samples, 99, 100),
                    }
                }));
            }
        }
        budget_state = replay_budget;
    }

    let steered_summary = steered.summary(total_offered_units);
    let conservative_summary = conservative_global.summary(total_offered_units);
    let winner_profile = if steered_summary.p99_latency_ns < conservative_summary.p99_latency_ns
        || (steered_summary.p99_latency_ns == conservative_summary.p99_latency_ns
            && steered_summary.remote_spill_count < conservative_summary.remote_spill_count)
    {
        "cohort_steered"
    } else {
        scenario.safe_fallback_profile.as_str()
    };
    let no_win_trigger = winner_profile == scenario.safe_fallback_profile;
    let report_projection = json!({
        "schema_version": COHORT_ADMISSION_STEERING_PROJECTION_SCHEMA_VERSION,
        "scenario_id": scenario.scenario_id,
        "workload_class": scenario.workload_class,
        "workload_seed": scenario.workload_seed,
        "replay_count": scenario.fixture.replay_count,
        "window_count": scenario.fixture.windows.len(),
        "decision_sequence": decision_sequence,
        "conservative_global_sequence": conservative_sequence,
        "budget_start_sequence": budget_start_sequence,
        "budget_remaining_sequence": budget_remaining_sequence,
        "fallback_windows": fallback_windows,
        "fairness_windows": fairness_windows,
        "steered": {
            "admit_local_count": steered_summary.admit_local_count,
            "redirect_remote_count": steered_summary.redirect_remote_count,
            "defer_count": steered_summary.defer_count,
            "fallback_used_count": steered_summary.fallback_used_count,
            "budget_exhausted_count": steered_summary.budget_exhausted_count,
            "fairness_escape_count": steered_summary.fairness_escape_count,
            "admitted_units": steered_summary.admitted_units,
            "deferred_units": steered_summary.deferred_units,
            "remote_spill_count": steered_summary.remote_spill_count,
            "p95_latency_ns": steered_summary.p95_latency_ns,
            "p99_latency_ns": steered_summary.p99_latency_ns,
            "throughput_ratio": steered_summary.throughput_ratio
        },
        "conservative_global": {
            "admit_local_count": conservative_summary.admit_local_count,
            "redirect_remote_count": conservative_summary.redirect_remote_count,
            "defer_count": conservative_summary.defer_count,
            "admitted_units": conservative_summary.admitted_units,
            "deferred_units": conservative_summary.deferred_units,
            "remote_spill_count": conservative_summary.remote_spill_count,
            "p95_latency_ns": conservative_summary.p95_latency_ns,
            "p99_latency_ns": conservative_summary.p99_latency_ns,
            "throughput_ratio": conservative_summary.throughput_ratio
        },
        "comparison": {
            "p95_latency_improvement_ns": conservative_summary.p95_latency_ns.saturating_sub(steered_summary.p95_latency_ns),
            "p99_latency_improvement_ns": conservative_summary.p99_latency_ns.saturating_sub(steered_summary.p99_latency_ns),
            "remote_spill_reduction": u64_count_delta(
                conservative_summary.remote_spill_count,
                steered_summary.remote_spill_count,
            ),
            "throughput_delta_units": u64_count_delta(
                steered_summary.admitted_units,
                conservative_summary.admitted_units,
            ),
            "winner_profile": winner_profile,
            "no_win_trigger": no_win_trigger,
        }
    });
    let repeated_run_hash_match = if include_hash_probe {
        let probe = build_cohort_admission_steering_report(scenario, false);
        hash_json_value(&probe["report_projection"]) == hash_json_value(&report_projection)
    } else {
        true
    };

    json!({
        "schema_version": COHORT_ADMISSION_STEERING_REPORT_SCHEMA_VERSION,
        "scenario_id": scenario.scenario_id,
        "description": scenario.description,
        "workload_class": scenario.workload_class,
        "workload_seed": scenario.workload_seed,
        "safe_fallback_profile": scenario.safe_fallback_profile,
        "expected_winner_profile": scenario.expected_winner_profile,
        "steering_profile": scenario.steering_profile,
        "report_projection": report_projection,
        "repeated_run_hash_match": repeated_run_hash_match,
        "steered_summary": steered_summary,
        "conservative_global_summary": conservative_summary,
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
fn cohort_admission_steering_smoke_contract_emits_report() {
    let scenarios = load_cohort_admission_steering_scenarios();
    let scenario_id = selected_cohort_admission_steering_scenario();
    let scenario = scenarios
        .iter()
        .find(|candidate| candidate.scenario_id == scenario_id)
        .expect("selected cohort admission steering scenario must exist");
    let report = build_cohort_admission_steering_report(scenario, true);
    if !scenario.expected_report_projection.is_null() {
        assert_eq!(
            report["report_projection"], scenario.expected_report_projection,
            "cohort steering smoke contract projection must stay stable"
        );
    }
    assert_eq!(
        report["repeated_run_hash_match"].as_bool(),
        Some(true),
        "repeated cohort steering report generation must be deterministic"
    );
    assert_eq!(
        report["operator_verdict"]["pass"].as_bool(),
        Some(true),
        "operator verdict must agree with the expected winner profile"
    );

    if let Ok(path) = std::env::var(COHORT_ADMISSION_STEERING_REPORT_PATH_ENV) {
        maybe_write_cohort_admission_steering_report(&path, &report);
    }

    println!("COHORT_ADMISSION_STEERING_REPORT_JSON_BEGIN");
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("serialize cohort admission steering report")
    );
    println!("COHORT_ADMISSION_STEERING_REPORT_JSON_END");
}
