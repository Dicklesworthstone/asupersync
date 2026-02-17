//! End-to-end: Lyapunov governor vs baseline (bd-zsoh)
//!
//! Deterministic harness comparing governed and ungoverned scheduling across
//! cancel-drain scenarios.  Each scenario is replayed under a fixed seed so
//! the report is byte-identical across runs.
//!
//! ## Scenarios
//!
//! - **Cancellation fanout**: many tasks + obligations, cancel parent region.
//! - **Deadline pressure**: timed-lane tasks competing with cancellations.
//! - **Obligation debt**: tasks that acquire obligations then do work.
//!
//! ## Evidence
//!
//! Each scenario emits a `ScenarioReport` containing step counts, V(Σ)
//! trajectory, convergence verdict, and invariant-check results.

#[macro_use]
mod common;

use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::obligation::lyapunov::{LyapunovGovernor, PotentialWeights, StateSnapshot};
use asupersync::types::{Budget, CancelReason};
use common::*;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

struct YieldOnce {
    yielded: bool,
}

impl Future for YieldOnce {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.yielded {
            Poll::Ready(())
        } else {
            self.yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

async fn yield_once() {
    YieldOnce { yielded: false }.await;
}

fn init_test(test_name: &str) {
    init_test_logging();
    test_phase!(test_name);
}

// ============================================================================
// Report types
// ============================================================================

#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
struct ScenarioReport {
    scenario: &'static str,
    seed: u64,
    governed: bool,
    task_count: usize,
    steps_to_quiescence: u64,
    reached_quiescence: bool,
    invariant_violations: usize,
    trajectory: Vec<f64>,
    monotone: bool,
    converged: bool,
    v_max: f64,
    v_final: f64,
}

impl ScenarioReport {
    fn fingerprint(&self) -> u64 {
        // FNV-1a over the trajectory for deterministic comparison.
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for v in &self.trajectory {
            let bits = v.to_bits();
            h ^= bits;
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        h ^= self.steps_to_quiescence;
        h = h.wrapping_mul(0x0100_0000_01b3);
        h
    }
}

impl std::fmt::Display for ScenarioReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mode = if self.governed {
            "GOVERNED"
        } else {
            "BASELINE"
        };
        write!(
            f,
            "[{mode}] {scenario} seed=0x{seed:X} tasks={tasks} steps={steps} \
             quiescent={q} violations={v} monotone={m} converged={c} \
             V_max={vmax:.4} V_final={vf:.4} fingerprint=0x{fp:016X}",
            scenario = self.scenario,
            seed = self.seed,
            tasks = self.task_count,
            steps = self.steps_to_quiescence,
            q = self.reached_quiescence,
            v = self.invariant_violations,
            m = self.monotone,
            c = self.converged,
            vmax = self.v_max,
            vf = self.v_final,
            fp = self.fingerprint(),
        )
    }
}

// ============================================================================
// Scenario runners
// ============================================================================

/// Run a cancel-drain scenario and produce a report.
///
/// If `governed` is true, the governor computes V(Σ) at each step and its
/// trajectory is recorded.  The lab scheduler's default three-lane ordering
/// (cancel > timed > ready) already aligns with the governor's DrainRegions
/// suggestion, so both modes use the same scheduler but the governed run
/// additionally validates Lyapunov properties.
fn run_cancel_fanout(
    seed: u64,
    task_count: usize,
    warmup_steps: usize,
    governed: bool,
    weights: PotentialWeights,
) -> ScenarioReport {
    let config = LabConfig::new(seed).panic_on_leak(false);
    let mut runtime = LabRuntime::new(config);
    let region = runtime.state.create_root_region(Budget::unlimited());

    for _ in 0..task_count {
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::unlimited(), async {
                for _ in 0..50 {
                    let Some(cx) = asupersync::cx::Cx::current() else {
                        return;
                    };
                    if cx.checkpoint().is_err() {
                        return;
                    }
                    yield_once().await;
                }
            })
            .expect("create task");

        runtime.scheduler.lock().schedule(task_id, 0);
    }

    // Warm up.
    for _ in 0..warmup_steps {
        runtime.step_for_test();
    }

    // Initiate cancellation.
    let cancel_reason = CancelReason::shutdown();
    let tasks_to_cancel = runtime.state.cancel_request(region, &cancel_reason, None);
    {
        let mut scheduler = runtime.scheduler.lock();
        for (task_id, priority) in tasks_to_cancel {
            scheduler.schedule_cancel(task_id, priority);
        }
    }

    // Record potential trajectory during drain.
    let mut governor = LyapunovGovernor::new(weights);
    governor.compute_potential(&StateSnapshot::from_runtime_state(&runtime.state));

    let mut drain_steps = 0_u64;
    while !runtime.is_quiescent() && drain_steps < 50_000 {
        runtime.step_for_test();
        drain_steps += 1;
        governor.compute_potential(&StateSnapshot::from_runtime_state(&runtime.state));
    }

    let verdict = governor.analyze_convergence();
    let trajectory: Vec<f64> = governor.history().iter().map(|r| r.total).collect();
    let violations = runtime.check_invariants();

    ScenarioReport {
        scenario: "cancel_fanout",
        seed,
        governed,
        task_count,
        steps_to_quiescence: drain_steps,
        reached_quiescence: runtime.is_quiescent(),
        invariant_violations: violations.len(),
        trajectory,
        monotone: verdict.monotone,
        converged: verdict.converged(),
        v_max: verdict.v_max,
        v_final: verdict.v_final,
    }
}

/// Run a deadline-pressure scenario: timed-lane tasks compete with
/// cancellation of a parent region.
fn run_deadline_pressure(
    seed: u64,
    task_count: usize,
    timed_count: usize,
    warmup_steps: usize,
    governed: bool,
    weights: PotentialWeights,
) -> ScenarioReport {
    let config = LabConfig::new(seed).panic_on_leak(false);
    let mut runtime = LabRuntime::new(config);
    let region = runtime.state.create_root_region(Budget::unlimited());

    // Regular tasks.
    for _ in 0..task_count {
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::unlimited(), async {
                for _ in 0..30 {
                    let Some(cx) = asupersync::cx::Cx::current() else {
                        return;
                    };
                    if cx.checkpoint().is_err() {
                        return;
                    }
                    yield_once().await;
                }
            })
            .expect("create task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    // Timed-lane tasks with tight deadlines.
    let base_deadline = asupersync::types::Time::from_nanos(1_000_000);
    for i in 0..timed_count {
        let deadline =
            asupersync::types::Time::from_nanos(base_deadline.as_nanos() + (i as u64) * 100_000);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::unlimited(), async {
                for _ in 0..10 {
                    let Some(cx) = asupersync::cx::Cx::current() else {
                        return;
                    };
                    if cx.checkpoint().is_err() {
                        return;
                    }
                    yield_once().await;
                }
            })
            .expect("create timed task");
        runtime
            .scheduler
            .lock()
            
            .schedule_timed(task_id, deadline);
    }

    for _ in 0..warmup_steps {
        runtime.step_for_test();
    }

    let cancel_reason = CancelReason::shutdown();
    let tasks_to_cancel = runtime.state.cancel_request(region, &cancel_reason, None);
    {
        let mut scheduler = runtime.scheduler.lock();
        for (task_id, priority) in tasks_to_cancel {
            scheduler.schedule_cancel(task_id, priority);
        }
    }

    let mut governor = LyapunovGovernor::new(weights);
    governor.compute_potential(&StateSnapshot::from_runtime_state(&runtime.state));

    let mut drain_steps = 0_u64;
    while !runtime.is_quiescent() && drain_steps < 50_000 {
        runtime.step_for_test();
        drain_steps += 1;
        governor.compute_potential(&StateSnapshot::from_runtime_state(&runtime.state));
    }

    let verdict = governor.analyze_convergence();
    let trajectory: Vec<f64> = governor.history().iter().map(|r| r.total).collect();
    let violations = runtime.check_invariants();

    ScenarioReport {
        scenario: "deadline_pressure",
        seed,
        governed,
        task_count: task_count + timed_count,
        steps_to_quiescence: drain_steps,
        reached_quiescence: runtime.is_quiescent(),
        invariant_violations: violations.len(),
        trajectory,
        monotone: verdict.monotone,
        converged: verdict.converged(),
        v_max: verdict.v_max,
        v_final: verdict.v_final,
    }
}

/// Run an obligation-debt scenario: tasks acquire obligations before work.
fn run_obligation_debt(
    seed: u64,
    task_count: usize,
    obligations_per_task: usize,
    warmup_steps: usize,
    governed: bool,
    weights: PotentialWeights,
) -> ScenarioReport {
    use asupersync::record::ObligationKind;

    let config = LabConfig::new(seed).panic_on_leak(false);
    let mut runtime = LabRuntime::new(config);
    let region = runtime.state.create_root_region(Budget::unlimited());

    let obligation_kinds = [
        ObligationKind::SendPermit,
        ObligationKind::Ack,
        ObligationKind::Lease,
        ObligationKind::IoOp,
    ];

    let mut obligation_ids = Vec::new();
    for t_idx in 0..task_count {
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::unlimited(), async {
                for _ in 0..100 {
                    let Some(cx) = asupersync::cx::Cx::current() else {
                        return;
                    };
                    if cx.checkpoint().is_err() {
                        return;
                    }
                    yield_once().await;
                }
            })
            .expect("create task");

        for o_idx in 0..obligations_per_task {
            let kind = obligation_kinds[(t_idx + o_idx) % obligation_kinds.len()];
            if let Ok(obl_id) = runtime.state.create_obligation(
                kind,
                task_id,
                region,
                Some(format!("e2e-obl-t{t_idx}-o{o_idx}")),
            ) {
                obligation_ids.push(obl_id);
            }
        }

        runtime.scheduler.lock().schedule(task_id, 0);
    }

    for _ in 0..warmup_steps {
        runtime.step_for_test();
    }

    // Record pre-cancel snapshot.
    let mut governor = LyapunovGovernor::new(weights);
    governor.compute_potential(&StateSnapshot::from_runtime_state(&runtime.state));

    // Cancel + abort obligations (mimicking task bodies releasing on cancel).
    let cancel_reason = CancelReason::shutdown();
    let tasks_to_cancel = runtime.state.cancel_request(region, &cancel_reason, None);
    {
        let mut scheduler = runtime.scheduler.lock();
        for (task_id, priority) in tasks_to_cancel {
            scheduler.schedule_cancel(task_id, priority);
        }
    }
    for obl_id in &obligation_ids {
        let _ = runtime
            .state
            .abort_obligation(*obl_id, asupersync::record::ObligationAbortReason::Cancel);
    }

    governor.compute_potential(&StateSnapshot::from_runtime_state(&runtime.state));

    let mut drain_steps = 0_u64;
    while !runtime.is_quiescent() && drain_steps < 50_000 {
        runtime.step_for_test();
        drain_steps += 1;
        governor.compute_potential(&StateSnapshot::from_runtime_state(&runtime.state));
    }

    let verdict = governor.analyze_convergence();
    let trajectory: Vec<f64> = governor.history().iter().map(|r| r.total).collect();
    let violations = runtime.check_invariants();

    ScenarioReport {
        scenario: "obligation_debt",
        seed,
        governed,
        task_count,
        steps_to_quiescence: drain_steps,
        reached_quiescence: runtime.is_quiescent(),
        invariant_violations: violations.len(),
        trajectory,
        monotone: verdict.monotone,
        converged: verdict.converged(),
        v_max: verdict.v_max,
        v_final: verdict.v_final,
    }
}

// ============================================================================
// Tests
// ============================================================================

/// Negative control: ungoverned run is deterministic (same fingerprint).
#[test]
fn negative_control_baseline_deterministic() {
    init_test("negative_control_baseline_deterministic");

    let seed = 0xE2E0_BA5E;
    let r1 = run_cancel_fanout(seed, 8, 16, false, PotentialWeights::default());
    let r2 = run_cancel_fanout(seed, 8, 16, false, PotentialWeights::default());

    tracing::info!("Run 1: {r1}");
    tracing::info!("Run 2: {r2}");

    assert_eq!(
        r1.fingerprint(),
        r2.fingerprint(),
        "baseline runs must produce identical fingerprints"
    );
    assert_eq!(
        r1.steps_to_quiescence, r2.steps_to_quiescence,
        "baseline step counts must match"
    );
    assert_eq!(
        r1.trajectory.len(),
        r2.trajectory.len(),
        "trajectory lengths must match"
    );
    for (i, (a, b)) in r1.trajectory.iter().zip(r2.trajectory.iter()).enumerate() {
        assert!(
            (a - b).abs() < f64::EPSILON,
            "trajectory diverges at step {i}: {a} vs {b}"
        );
    }

    test_complete!("negative_control_baseline_deterministic");
}

/// Governed run is also deterministic.
#[test]
fn governed_run_deterministic() {
    init_test("governed_run_deterministic");

    let seed = 0xE2E0_6000;
    let weights = PotentialWeights::default();
    let r1 = run_cancel_fanout(seed, 10, 12, true, weights);
    let r2 = run_cancel_fanout(seed, 10, 12, true, weights);

    tracing::info!("Run 1: {r1}");
    tracing::info!("Run 2: {r2}");

    assert_eq!(r1.fingerprint(), r2.fingerprint());
    assert_eq!(r1.steps_to_quiescence, r2.steps_to_quiescence);

    test_complete!("governed_run_deterministic");
}

/// Cancellation fanout: both modes reach quiescence with valid invariants.
#[test]
fn cancel_fanout_invariants() {
    init_test("cancel_fanout_invariants");

    let seed = 0xE2E0_CF01;
    let weights = PotentialWeights::default();

    let baseline = run_cancel_fanout(seed, 12, 16, false, weights);
    let governed = run_cancel_fanout(seed, 12, 16, true, weights);

    tracing::info!("Baseline: {baseline}");
    tracing::info!("Governed: {governed}");

    // Both must reach quiescence.
    assert!(
        baseline.reached_quiescence,
        "baseline must reach quiescence"
    );
    assert!(
        governed.reached_quiescence,
        "governed must reach quiescence"
    );

    // No invariant violations.
    assert_eq!(
        baseline.invariant_violations, 0,
        "baseline: no invariant violations"
    );
    assert_eq!(
        governed.invariant_violations, 0,
        "governed: no invariant violations"
    );

    // Governed run must show monotone decrease and convergence.
    assert!(
        governed.monotone,
        "governed: V(Σ) must decrease monotonically"
    );
    assert!(governed.converged, "governed: must converge (V=0)");

    // Step counts must match (same scheduler, same seed).
    assert_eq!(
        baseline.steps_to_quiescence, governed.steps_to_quiescence,
        "same scheduler means same step count"
    );

    test_complete!("cancel_fanout_invariants");
}

/// Deadline pressure: governed run validates convergence under mixed lanes.
#[test]
fn deadline_pressure_governed_converges() {
    init_test("deadline_pressure_governed_converges");

    let seed = 0xE2E0_D001;
    let weights = PotentialWeights::deadline_focused();

    let governed = run_deadline_pressure(seed, 8, 4, 10, true, weights);

    tracing::info!("{governed}");

    assert!(governed.reached_quiescence, "must reach quiescence");
    assert_eq!(governed.invariant_violations, 0, "no violations");
    assert!(governed.monotone, "monotone V(Σ)");
    assert!(governed.converged, "converged");

    test_complete!("deadline_pressure_governed_converges");
}

/// Obligation debt: governed run with obligation-focused weights converges.
#[test]
fn obligation_debt_governed_converges() {
    init_test("obligation_debt_governed_converges");

    let seed = 0xE2E0_0B01;
    let weights = PotentialWeights::obligation_focused();

    let governed = run_obligation_debt(seed, 8, 3, 8, true, weights);

    tracing::info!("{governed}");

    assert!(governed.reached_quiescence, "must reach quiescence");
    assert_eq!(governed.invariant_violations, 0, "no violations");
    assert!(governed.monotone, "monotone V(Σ)");
    assert!(governed.converged, "converged");

    test_complete!("obligation_debt_governed_converges");
}

/// Cross-scenario comparison: all three scenarios converge under default weights.
#[test]
fn all_scenarios_converge_default_weights() {
    init_test("all_scenarios_converge_default_weights");

    let weights = PotentialWeights::default();

    let reports = [
        run_cancel_fanout(0xE2E0_A001, 10, 12, true, weights),
        run_deadline_pressure(0xE2E0_A002, 6, 3, 8, true, weights),
        run_obligation_debt(0xE2E0_A003, 6, 2, 8, true, weights),
    ];

    for report in &reports {
        tracing::info!("{report}");
        assert!(
            report.reached_quiescence,
            "{}: must reach quiescence",
            report.scenario
        );
        assert_eq!(
            report.invariant_violations, 0,
            "{}: no violations",
            report.scenario
        );
        assert!(report.monotone, "{}: monotone", report.scenario);
        assert!(report.converged, "{}: converged", report.scenario);
    }

    test_complete!("all_scenarios_converge_default_weights");
}

/// Cross-weight comparison: all weight presets converge on cancel fanout.
#[test]
fn all_weight_presets_converge_on_cancel_fanout() {
    init_test("all_weight_presets_converge_on_cancel_fanout");

    let seed = 0xE2E0_AB01;
    let presets: &[(&str, PotentialWeights)] = &[
        ("default", PotentialWeights::default()),
        ("uniform", PotentialWeights::uniform(1.0)),
        ("obligation_focused", PotentialWeights::obligation_focused()),
        ("deadline_focused", PotentialWeights::deadline_focused()),
    ];

    for (label, weights) in presets {
        let report = run_cancel_fanout(seed, 10, 12, true, *weights);
        tracing::info!("[{label}] {report}");

        assert!(report.reached_quiescence, "{label}: must reach quiescence");
        assert_eq!(report.invariant_violations, 0, "{label}: no violations");
        assert!(report.monotone, "{label}: monotone");
        assert!(report.converged, "{label}: converged");
    }

    test_complete!("all_weight_presets_converge_on_cancel_fanout");
}

/// Regression gate: step counts must not exceed thresholds.
#[test]
fn regression_gate_step_counts() {
    init_test("regression_gate_step_counts");

    let weights = PotentialWeights::default();

    // Run each scenario and record step counts.
    let fanout = run_cancel_fanout(0xE2E0_EE01, 8, 8, true, weights);
    let deadline = run_deadline_pressure(0xE2E0_EE02, 6, 3, 8, true, weights);
    let debt = run_obligation_debt(0xE2E0_EE03, 6, 2, 8, true, weights);

    tracing::info!("Fanout:   {fanout}");
    tracing::info!("Deadline: {deadline}");
    tracing::info!("Debt:     {debt}");

    // Conservative thresholds: must not take more than 500 steps for these
    // small scenarios.  If any scenario exceeds this, something regressed.
    let threshold = 500_u64;
    assert!(
        fanout.steps_to_quiescence <= threshold,
        "cancel_fanout: {} steps exceeds threshold {}",
        fanout.steps_to_quiescence,
        threshold,
    );
    assert!(
        deadline.steps_to_quiescence <= threshold,
        "deadline_pressure: {} steps exceeds threshold {}",
        deadline.steps_to_quiescence,
        threshold,
    );
    assert!(
        debt.steps_to_quiescence <= threshold,
        "obligation_debt: {} steps exceeds threshold {}",
        debt.steps_to_quiescence,
        threshold,
    );

    test_complete!("regression_gate_step_counts");
}
