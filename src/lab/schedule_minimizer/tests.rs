use super::*;
use crate::lab::LabConfig;
use crate::types::Budget;
use std::cell::Cell;
use std::future::poll_fn;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;

const FAILURE: FailureKey = FailureKey([7; 32]);

// The consumer's pre-publication polls have no required effects. They can be
// deleted, unlike either task's terminal poll. Keep both handles in the fixture.
fn workload(seed: u64) -> (LabRuntime, (Arc<AtomicBool>, impl Sized)) {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(100));
    let root = runtime.state.create_root_region(Budget::INFINITE);
    let published = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&published);
    let (consumer, consumer_handle) = runtime
        .state
        .create_task(root, Budget::INFINITE, poll_fn(move |cx| {
            if observed.load(Ordering::SeqCst) {
                Poll::Ready(())
            } else {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }))
        .expect("create consumer");
    let target = Arc::clone(&published);
    let (producer, producer_handle) = runtime
        .state
        .create_task(root, Budget::INFINITE, async move {
            target.store(true, Ordering::SeqCst);
        })
        .expect("create producer");
    runtime.scheduler.lock().schedule(consumer, Budget::INFINITE.priority);
    runtime.scheduler.lock().schedule(producer, Budget::INFINITE.priority);
    (runtime, (published, (consumer_handle, producer_handle)))
}

fn source() -> (ForcedSchedule, u64) {
    // Find a source with at least one removable pending poll without baking in
    // the RNG implementation's exact seed-to-choice mapping.
    for seed in 1..=64 {
        let (mut runtime, _fixture) = workload(seed);
        runtime.start_forced_schedule_recording(100).unwrap();
        runtime.run_until_quiescent();
        let source = runtime.finish_forced_schedule_recording().unwrap();
        if source.terminal_quiescent() && source.dispatches().len() > 2 {
            return (source, seed);
        }
    }
    panic!("bounded seed sweep must include a consumer-first source");
}

fn limits() -> ScheduleMinimizerLimits {
    ScheduleMinimizerLimits {
        max_source_dispatches: 100,
        max_attempts: 100,
        max_work_per_attempt: 300,
        max_total_work: 30_000,
        confirmations: 2,
    }
}

#[test]
fn actual_replay_reduces_pending_polls_and_preserves_original_source_indices() {
    let (source, seed) = source();
    let before = source.to_canonical_bytes().unwrap();
    let report = minimize_schedule(&source, limits(), || workload(seed), |_, fixture, lab| {
        assert!(lab.quiescent);
        fixture.0.load(Ordering::SeqCst).then_some(FAILURE)
    }).unwrap();
    assert_eq!(report.stop(), ScheduleMinimizerStop::SingleDeletionPassComplete);
    assert_eq!(report.retained_source_indices().len(), 2);
    assert!(report.stats().reductions > 0);
    assert!(report.stats().incomplete + report.stats().rejected > 0);
    assert_eq!(source.to_canonical_bytes().unwrap(), before);
    for (index, dispatch) in report.retained_source_indices().iter().zip(report.candidate().dispatches()) {
        assert_eq!(*index, dispatch.source_index());
        assert_eq!(source.dispatches()[*index].task(), dispatch.task());
    }
    let (mut replay, fixture) = workload(seed);
    let replayed = replay.run_forced_schedule_candidate(report.candidate(), candidate_limits(limits(), 300)).unwrap();
    assert_eq!(replayed.termination, ForcedScheduleCandidateTermination::Quiescent);
    assert!(fixture.0.load(Ordering::SeqCst));
    assert_eq!(report.confirmations(), 2);
}

#[test]
fn incomplete_or_rejected_candidates_never_reach_even_an_always_matching_classifier() {
    let (source, seed) = source();
    let calls = Cell::new(0);
    let result = minimize_schedule(&source, limits(), || workload(seed), |_, _, lab| {
        calls.set(calls.get() + 1);
        assert!(lab.quiescent, "partial execution must not be offered as a reproduction");
        Some(FAILURE)
    }).unwrap();
    assert_eq!(result.retained_source_indices().len(), 2);
    assert!(result.stats().incomplete + result.stats().rejected > 0);
    assert!(calls.get() < result.stats().attempts);
}

#[test]
fn a_successful_source_without_a_failure_is_not_a_minimization_baseline() {
    let (source, seed) = source();
    let factories = Cell::new(0);
    let result = minimize_schedule(&source, limits(), || {
        factories.set(factories.get() + 1);
        workload(seed)
    }, |_, _, _| None);
    assert!(matches!(result, Err(ScheduleMinimizerError::NoBaselineFailure)));
    assert_eq!(factories.get(), 1);
}

#[test]
fn strict_source_replay_refuses_a_different_runtime_before_classification() {
    let (source, seed) = source();
    let calls = Cell::new(0);
    let result = minimize_schedule(&source, limits(), || workload(seed + 1), |_, _, _| {
        calls.set(calls.get() + 1);
        Some(FAILURE)
    });
    assert!(matches!(result, Err(ScheduleMinimizerError::BaselineReplay(_))));
    assert_eq!(calls.get(), 0);
}

#[test]
fn source_count_and_baseline_budget_are_admitted_before_any_factory() {
    let (source, seed) = source();
    let factories = Cell::new(0);
    let mut too_many = limits();
    too_many.max_source_dispatches = source.dispatches().len() - 1;
    let mut too_little = limits();
    too_little.max_total_work = 1;
    for bounds in [too_many, too_little] {
        let result = minimize_schedule(&source, bounds, || {
            factories.set(factories.get() + 1);
            workload(seed)
        }, |_, _, _| Some(FAILURE));
        assert!(result.is_err());
    }
    assert_eq!(factories.get(), 0);
}

#[test]
fn zero_limits_do_not_construct_workloads() {
    let (source, seed) = source();
    for field in 0..5 {
        let mut bounds = limits();
        match field {
            0 => bounds.max_source_dispatches = 0,
            1 => bounds.max_attempts = 0,
            2 => bounds.max_work_per_attempt = 0,
            3 => bounds.max_total_work = 0,
            _ => bounds.confirmations = 0,
        }
        let factories = Cell::new(0);
        let result = minimize_schedule(&source, bounds, || {
            factories.set(factories.get() + 1);
            workload(seed)
        }, |_, _, _| Some(FAILURE));
        assert!(matches!(result, Err(ScheduleMinimizerError::InvalidLimit(_))));
        assert_eq!(factories.get(), 0);
    }
}

#[test]
fn attempt_limit_returns_only_the_fully_confirmed_original_candidate() {
    let (source, seed) = source();
    let mut bounds = limits();
    bounds.max_attempts = bounds.confirmations + 1;
    let factories = Cell::new(0);
    let report = minimize_schedule(&source, bounds, || {
        factories.set(factories.get() + 1);
        workload(seed)
    }, |_, _, _| Some(FAILURE)).unwrap();
    assert_eq!(report.stop(), ScheduleMinimizerStop::AttemptLimit);
    assert_eq!(report.retained_source_indices().len(), source.dispatches().len());
    assert_eq!(report.stats().reductions, 0);
    assert_eq!(report.stats().attempts, bounds.max_attempts);
    assert_eq!(factories.get(), bounds.max_attempts);
}

#[test]
fn changing_failure_identity_during_baseline_is_refused() {
    let (source, seed) = source();
    let calls = Cell::new(0);
    let result = minimize_schedule(&source, limits(), || workload(seed), |_, _, _| {
        let previous = calls.get();
        calls.set(previous + 1);
        Some(if previous == 0 { FAILURE } else { FailureKey([8; 32]) })
    });
    assert!(matches!(result, Err(ScheduleMinimizerError::UnstableBaseline)));
    assert_eq!(calls.get(), 2);
}

#[test]
fn a_different_failure_never_replaces_the_original_failure() {
    let (source, seed) = source();
    let calls = Cell::new(0);
    let report = minimize_schedule(&source, limits(), || workload(seed), |_, _, _| {
        let previous = calls.get();
        calls.set(previous + 1);
        Some(if previous < 3 { FAILURE } else { FailureKey([8; 32]) })
    }).unwrap();
    assert_eq!(report.failure(), FAILURE);
    assert_eq!(report.retained_source_indices().len(), source.dispatches().len());
    assert!(report.stats().nonmatching > 0);
    assert_eq!(report.stats().reductions, 0);
}

#[test]
fn a_candidate_that_loses_its_failure_on_confirmation_is_not_retained() {
    let (source, seed) = source();
    let calls = Cell::new(0);
    let report = minimize_schedule(&source, limits(), || workload(seed), |_, _, _| {
        let previous = calls.get();
        calls.set(previous + 1);
        // Strict source + two baseline candidates + one reduction confirmation.
        (previous < 4).then_some(FAILURE)
    }).unwrap();
    assert_eq!(report.stop(), ScheduleMinimizerStop::UnstableReproduction);
    assert_eq!(report.stats().reductions, 0);
    assert_eq!(report.retained_source_indices().len(), source.dispatches().len());
}

#[test]
fn aggregate_grants_account_for_errors_and_never_admit_unbounded_zero_cost_trials() {
    let mut stats = ScheduleMinimizerStats::default();
    let mut bounds = limits();
    bounds.max_total_work = 7;
    bounds.max_work_per_attempt = 5;
    assert_eq!(admit_attempt(bounds, &mut stats), Ok(5));
    assert_eq!(admit_attempt(bounds, &mut stats), Ok(2));
    assert_eq!(admit_attempt(bounds, &mut stats), Err(ScheduleMinimizerStop::TotalWorkLimit));
    assert_eq!(stats.attempts, 2);
    assert_eq!(stats.charged_work, 7);
    let mut stats = ScheduleMinimizerStats::default();
    bounds.max_attempts = 2;
    for _ in 0..2 {
        let grant = admit_attempt(bounds, &mut stats).unwrap();
        stats.charged_work -= grant; // A successful zero-work candidate.
    }
    assert_eq!(admit_attempt(bounds, &mut stats), Err(ScheduleMinimizerStop::AttemptLimit));
}

#[test]
fn classifier_panics_propagate_instead_of_becoming_the_target_failure() {
    let (source, seed) = source();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = minimize_schedule(&source, limits(), || workload(seed), |_, _, _| {
            panic!("classifier bug, not an application failure");
        });
    }));
    assert!(result.is_err());
}
