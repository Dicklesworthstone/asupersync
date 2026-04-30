//! Conformance harness: replay a fixed-seed scheduler trace and pin its
//! decision order against a known-good baseline.
//!
//! The in-tree `cfg(test)` test
//! `three_lane_scheduler_decision_trace_fixed_seed` already snapshots a
//! decision trace for the bare `ThreeLaneScheduler`, but it lives in
//! the lib's unit-test binary, which is currently blocked from running
//! by unrelated `cfg(test)` modules in `src/`. The existing
//! `tests/lab_determinism.rs` covers run-to-run determinism (same seed
//! → same result, different seed → different result) but does NOT pin
//! the actual decision trace bytes. A regression in lab-runtime
//! scheduling that happens to remain self-consistent (still
//! deterministic, just *differently* deterministic) would slip past
//! today's checks.
//!
//! This harness fills that gap: it captures the full execution order
//! produced by `LabRuntime` for a fixed seed and locks it as a `.snap`
//! golden, so any future change that perturbs the lab-scheduler's
//! decision policy surfaces as a snapshot diff. The harness also
//! re-asserts run-to-run determinism in the same test, so the snapshot
//! cannot drift under us.
//!
//! Lives under `tests/` so it compiles into its own integration-test
//! binary against the public crate surface.

use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::runtime::yield_now;
use asupersync::types::Budget;
use asupersync::util::DetRng;
use std::sync::Arc;
use std::sync::Mutex;

/// Schedule `task_count` cooperative-yield tasks at the given seed and
/// return their completion order. The seed drives both the lab
/// scheduler's internal RNG and the up-front task-id shuffle, so two
/// invocations at the same seed must produce byte-identical Vec<usize>.
fn run_replay(seed: u64, task_count: usize, yields_per_task: usize) -> Vec<usize> {
    let mut runtime = LabRuntime::new(LabConfig::new(seed));
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let completion_order = Arc::new(Mutex::new(Vec::new()));
    let mut task_ids = Vec::new();
    for i in 0..task_count {
        let order = Arc::clone(&completion_order);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                for _ in 0..yields_per_task {
                    yield_now().await;
                }
                order.lock().expect("completion-order mutex").push(i);
            })
            .expect("create task");
        task_ids.push(task_id);
    }

    // Deterministic up-front shuffle so different seeds touch different
    // initial scheduler queues. Same seed → same shuffle.
    let mut rng = DetRng::new(seed);
    for i in (1..task_ids.len()).rev() {
        let j = (rng.next_u32() as usize) % (i + 1);
        task_ids.swap(i, j);
    }

    for task_id in task_ids {
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    runtime.run_until_quiescent();

    Arc::try_unwrap(completion_order)
        .expect("only one Arc holder")
        .into_inner()
        .expect("mutex not poisoned")
}

#[test]
fn lab_runtime_decision_trace_known_good_seed_replays_to_golden() {
    // Seed and shape are deliberately picked so the trace exercises a
    // non-trivial interleaving (>= 8 tasks, >= 4 yields per task).
    const SEED: u64 = 0xC0DE_CAFE_BEEF_0191;
    const TASK_COUNT: usize = 12;
    const YIELDS_PER_TASK: usize = 5;

    let trace_run_a = run_replay(SEED, TASK_COUNT, YIELDS_PER_TASK);
    let trace_run_b = run_replay(SEED, TASK_COUNT, YIELDS_PER_TASK);

    // Determinism conformance: the same seed must reproduce the same
    // trace byte-for-byte. This is what makes the snapshot below
    // meaningful — without it, the snapshot would be pinning whichever
    // schedule a particular machine happened to produce first.
    assert_eq!(
        trace_run_a, trace_run_b,
        "same-seed lab-runtime replay must produce byte-identical decision traces; \
         a divergence here means the lab scheduler is no longer deterministic for \
         seed {SEED:#018X} and the snapshot below is meaningless until that is fixed",
    );

    // Sanity: every task we spawned must complete (no scheduler stall).
    assert_eq!(
        trace_run_a.len(),
        TASK_COUNT,
        "expected all {TASK_COUNT} tasks to complete; got {}",
        trace_run_a.len(),
    );

    // Known-good golden: any change to the lab scheduler's decision
    // policy that perturbs this order surfaces here.
    insta::assert_json_snapshot!("lab_runtime_decision_trace_seed_0191", &trace_run_a,);
}

#[test]
fn lab_runtime_decision_trace_different_seeds_diverge() {
    // The conformance snapshot above is only meaningful if the seed
    // actually selects between distinguishable schedules. Pick two
    // seeds whose expected traces are guaranteed to differ.
    const SEED_A: u64 = 0xC0DE_CAFE_BEEF_0191;
    const SEED_B: u64 = 0xC0DE_CAFE_BEEF_0192;

    let trace_a = run_replay(SEED_A, 12, 5);
    let trace_b = run_replay(SEED_B, 12, 5);

    assert_ne!(
        trace_a, trace_b,
        "different seeds must produce distinguishable decision traces; \
         identical output across seeds {SEED_A:#018X} and {SEED_B:#018X} means \
         the lab scheduler has lost its seed-dependence and the conformance \
         snapshot is no longer informative",
    );
}
