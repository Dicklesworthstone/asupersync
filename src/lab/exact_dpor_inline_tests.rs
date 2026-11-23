#![allow(clippy::pedantic, clippy::nursery, clippy::future_not_send)]

use super::*;
use crate::lab::exact_explorer::ExactScheduleExplorer;
use crate::lab::runtime::ForcedScheduleLimits;
use crate::record::ObligationKind;
use crate::trace::distributed::LogicalClockMode;
use crate::types::{Budget, Time};
use parking_lot::Mutex;
use std::cell::{Cell, RefCell};
use std::sync::Arc;
use std::task::{Poll, Waker};

fn limits() -> ExactDporLimits {
    ExactDporLimits::new(
        ExactScheduleLimits::new(32, 256, 64, 256, 512),
        2048,
        2_000_000,
        4096,
        16_384,
    )
}

// A deliberately instrumented model effect: ChaosInjection's existing
// footprint writes GlobalState and carries the executing task identity. This
// fixture does not claim that the runtime detects arbitrary Rust memory races.
// Its schedule-dependent failure below is a real unresolved runtime obligation.
fn model_shared_write(cx: &crate::Cx) {
    let task = cx.task_id();
    let clock = cx.logical_tick();
    cx.trace_buffer().unwrap().record_event(|seq| {
        TraceEvent::new(
            seq,
            Time::ZERO,
            TraceEventKind::ChaosInjection,
            TraceData::Chaos {
                kind: "model_shared_write".to_owned(),
                task: Some(task),
                detail: "instrumented shared-state effect".to_owned(),
            },
        )
        .with_logical_time(clock)
    });
}

fn install_writers(
    runtime: &mut LabRuntime,
    count: u8,
    output: Arc<Mutex<Vec<u8>>>,
    leak_if_one_is_first: bool,
) {
    let region = runtime.state.create_root_region(Budget::INFINITE);
    for label in 0..count {
        let output = Arc::clone(&output);
        let (task, _join) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let cx = crate::Cx::current().unwrap();
                model_shared_write(&cx);
                let first = output.lock().is_empty();
                output.lock().push(label);
                if leak_if_one_is_first && label == 1 && first {
                    let token = cx
                        .try_register_obligation_checked(ObligationKind::Lease, cx.task_id())
                        .unwrap()
                        .unwrap();
                    drop(token);
                }
            })
            .unwrap();
        runtime.scheduler.lock().schedule(task, 0);
    }
}

fn writers(runtime: &mut LabRuntime) {
    install_writers(runtime, 2, Arc::new(Mutex::new(Vec::new())), false);
}

// Two real checked-credit callers compete for one region quota slot. A holds
// its credit until B attempts admission. B's refusal path is correct, but its
// accepted path deliberately leaks. The initial A-first run passes; an exact
// B-first alternative exposes that bug without synthetic conflict events.
fn install_quota_competitors(runtime: &mut LabRuntime, output: Arc<Mutex<Vec<u8>>>) {
    use crate::record::ObligationAbortReason;
    use crate::runtime::obligation_mailbox::{ObligationAdmissionError, ObligationToken};

    let region = runtime.state.create_root_region(Budget::INFINITE);
    let record = runtime.state.region(region).unwrap();
    let mut quota = record.limits();
    quota.max_obligations = Some(1);
    record.set_limits(quota);
    let attempted = Arc::new(Mutex::new((false, None::<Waker>)));
    let source_attempted = Arc::clone(&attempted);
    let source_output = Arc::clone(&output);
    let mut held = None::<ObligationToken>;
    let (source, _source_join) = runtime
        .state
        .create_task(
            region,
            Budget::INFINITE,
            std::future::poll_fn(move |task_cx| {
                if held.is_none() {
                    source_output.lock().push(0);
                    let cx = crate::Cx::current().unwrap();
                    held = cx
                        .try_register_obligation_checked(ObligationKind::Lease, cx.task_id())
                        .unwrap();
                    assert!(held.is_some());
                }
                let mut attempted = source_attempted.lock();
                if attempted.0 {
                    drop(attempted);
                    assert!(held.take().unwrap().abort(ObligationAbortReason::Explicit));
                    Poll::Ready(())
                } else {
                    attempted.1 = Some(task_cx.waker().clone());
                    Poll::Pending
                }
            }),
        )
        .unwrap();
    let (competitor, _competitor_join) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            output.lock().push(1);
            let cx = crate::Cx::current().unwrap();
            match cx.try_register_obligation_checked(ObligationKind::Lease, cx.task_id()) {
                Ok(Some(token)) => drop(token), // Deliberately broken accepted path.
                Err(ObligationAdmissionError::LimitReached { limit: 1, live: 1 }) => {}
                result => panic!("unexpected admission result: {result:?}"),
            }
            let wake = {
                let mut attempted = attempted.lock();
                attempted.0 = true;
                attempted.1.take()
            };
            if let Some(wake) = wake {
                wake.wake();
            }
        })
        .unwrap();
    runtime.scheduler.lock().schedule(source, 0);
    runtime.scheduler.lock().schedule(competitor, 0);
}

#[test]
fn real_quota_guidance_finds_and_replays_a_failure_seed_samples_miss() {
    // A finite seed sample can revisit the same order. It is not an absence-of-
    // bugs certificate: exact guidance must execute the other witnessed choice.
    for seed in [2, 4, 6, 8] {
        let mut runtime =
            LabRuntime::new_with_task_causality(LabConfig::new(seed).panic_on_leak(false));
        let output = Arc::new(Mutex::new(Vec::new()));
        install_quota_competitors(&mut runtime, Arc::clone(&output));
        assert!(runtime.run_until_quiescent_with_report().lab_test_passed());
        assert_eq!(*output.lock(), vec![0, 1]);
    }

    let config = LabConfig::new(2).panic_on_leak(false);
    let observations = RefCell::new(Vec::new());
    let report = ExactDporExplorer::new(config.clone(), limits())
        .explore_until_failure(|runtime| {
            let output = Arc::new(Mutex::new(Vec::new()));
            install_quota_competitors(runtime, Arc::clone(&output));
            observations.borrow_mut().push(output);
        })
        .unwrap();
    assert_eq!(report.termination, ExactDporTermination::Stopped);
    assert_eq!(report.runs.len(), 2);
    assert!(report.runs[0].execution.lab.lab_test_passed());
    let failing = &report.runs[1];
    assert_eq!(failing.analysis, ExactDporAnalysis::Analyzed);
    assert_eq!(
        failing.execution.termination,
        ExactScheduleTermination::Quiescent
    );
    assert!(!failing.execution.lab.lab_test_passed());
    assert!(
        !failing
            .execution
            .lab
            .oracle_report
            .entry("obligation_leak")
            .unwrap()
            .passed
    );
    let source = failing.backtrack.as_ref().unwrap();
    assert_eq!(source.source_run, 0);
    assert_eq!(source.earlier_decision, 0);
    assert_eq!(source.later_decision, 1);
    assert_eq!(source.intervening_later_task_polls, 0);
    assert_eq!(
        failing.execution.execution.decisions()[0].selected().task,
        source.later_task.into()
    );
    assert_ne!(
        report.runs[0].execution.execution.decisions()[0]
            .selected()
            .task,
        failing.execution.execution.decisions()[0].selected().task
    );
    assert_eq!(*observations.borrow()[0].lock(), vec![0, 1]);
    assert_eq!(*observations.borrow()[1].lock(), vec![1, 0]);

    let mut replay = LabRuntime::new_with_task_causality(config);
    let output = Arc::new(Mutex::new(Vec::new()));
    install_quota_competitors(&mut replay, Arc::clone(&output));
    let receipt = failing.execution.schedule.as_ref().unwrap();
    let replayed = replay
        .run_forced_schedule(receipt, ForcedScheduleLimits::new(64, 256))
        .unwrap();
    assert_eq!(replayed.schedule_hash, receipt.terminal_schedule_hash());
    assert_eq!(*output.lock(), vec![1, 0]);
    assert!(!replay.report().lab_test_passed());
}

#[test]
fn exact_prefix_dedup_terminates_without_discarding_a_distinct_dispatch_order() {
    let output = RefCell::new(Vec::new());
    let report = ExactDporExplorer::new(LabConfig::new(2), limits())
        .explore(|runtime| {
            let observed = Arc::new(Mutex::new(Vec::new()));
            install_writers(runtime, 2, Arc::clone(&observed), false);
            output.borrow_mut().push(observed);
        })
        .unwrap();
    assert_eq!(report.termination, ExactDporTermination::GuidanceQueueEmpty);
    assert_eq!(report.runs.len(), 2);
    assert_eq!(report.statistics.queued, 1);
    assert!(report.statistics.duplicates > 0);
    assert_eq!(*output.borrow()[0].lock(), vec![0, 1]);
    assert_eq!(*output.borrow()[1].lock(), vec![1, 0]);
    assert!(report.pending_prefixes.is_empty());
}

#[test]
fn independent_tasks_do_not_generate_scheduler_only_guidance() {
    let report = ExactDporExplorer::new(LabConfig::new(2), limits())
        .explore(|runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            for _ in 0..3 {
                let (task, _join) = runtime
                    .state
                    .create_task(region, Budget::INFINITE, async {})
                    .unwrap();
                runtime.scheduler.lock().schedule(task, 0);
            }
        })
        .unwrap();
    assert_eq!(report.termination, ExactDporTermination::GuidanceQueueEmpty);
    assert_eq!(report.runs.len(), 1);
    assert_eq!(report.runs[0].analysis, ExactDporAnalysis::Analyzed);
    assert_eq!(report.statistics.queued, 0);
}

#[test]
fn run_and_aggregate_frontier_limits_retain_honest_replayable_work() {
    let config = LabConfig::new(2);
    let mut bounded = limits();
    bounded.execution.max_runs = 1;
    let report = ExactDporExplorer::new(config.clone(), bounded)
        .explore(writers)
        .unwrap();
    assert_eq!(report.termination, ExactDporTermination::RunLimit);
    assert_eq!(report.pending_prefixes.len(), 1);
    let resumed = ExactScheduleExplorer::new(config.clone(), limits().execution)
        .replay(&report.pending_prefixes[0], writers)
        .unwrap();
    assert_eq!(resumed.termination, ExactScheduleTermination::Quiescent);
    assert_ne!(
        resumed.execution.decisions()[0].selected().task,
        report.runs[0].execution.execution.decisions()[0]
            .selected()
            .task
    );

    // Count alone would admit this prefix; its two enabled choices exceed the
    // retained-witness budget. Omission must never look like queue exhaustion.
    bounded = limits();
    bounded.max_pending_choices = 1;
    let report = ExactDporExplorer::new(config.clone(), bounded)
        .explore(writers)
        .unwrap();
    assert_eq!(report.termination, ExactDporTermination::FrontierLimit);
    assert!(report.statistics.omitted > 0);
    assert_eq!(report.statistics.queued, 0);
    assert_eq!(report.runs.len(), 1);

    bounded = limits();
    bounded.max_pending_decisions = 1;
    let report = ExactDporExplorer::new(config, bounded)
        .explore(|runtime| {
            install_writers(runtime, 3, Arc::new(Mutex::new(Vec::new())), false);
        })
        .unwrap();
    assert_eq!(report.termination, ExactDporTermination::FrontierLimit);
    assert!(report.statistics.omitted > 0);
}

#[test]
fn trace_eviction_and_analysis_limits_refuse_partial_guidance() {
    let config = LabConfig::new(2);
    let mut trace_bound = limits();
    trace_bound.max_trace_events = 1;
    let mut pair_bound = limits();
    pair_bound.max_event_pairs = 1;
    for (bound, expected) in [
        (trace_bound, ExactDporAnalysis::TraceLimit),
        (pair_bound, ExactDporAnalysis::PairLimit),
    ] {
        let report = ExactDporExplorer::new(config.clone(), bound)
            .explore(writers)
            .unwrap();
        assert_eq!(report.termination, ExactDporTermination::Incomplete);
        assert_eq!(report.runs[0].analysis, expected);
        assert_eq!(report.statistics.queued, 0);
        assert!(report.pending_prefixes.is_empty());
    }

    let report = ExactDporExplorer::new(config.trace_capacity(1), limits())
        .explore(writers)
        .unwrap();
    assert_eq!(report.termination, ExactDporTermination::Incomplete);
    assert!(matches!(
        report.runs[0].analysis,
        ExactDporAnalysis::TraceTruncated { recorded, retained: 1 } if recorded > 1
    ));
    assert_eq!(report.statistics.queued, 0);
}

#[test]
fn replacing_runtime_clock_or_capture_is_refused_before_polling() {
    for replacement in 0..3 {
        let config = LabConfig::new(2);
        let output = Arc::new(Mutex::new(Vec::new()));
        let report = ExactDporExplorer::new(config.clone(), limits())
            .explore(|runtime| {
                match replacement {
                    0 => *runtime = LabRuntime::new_with_task_causality(config.clone()),
                    1 => runtime.state.set_logical_clock_mode(LogicalClockMode::Lamport),
                    _ => runtime.state.trace = crate::trace::TraceBufferHandle::new(4096),
                }
                install_writers(runtime, 2, Arc::clone(&output), false);
            })
            .unwrap();
        assert_eq!(report.termination, ExactDporTermination::Incomplete);
        assert_eq!(report.runs[0].analysis, ExactDporAnalysis::CaptureReplaced);
        assert!(report.runs[0].execution.schedule.is_none());
        assert!(output.lock().is_empty());
        assert_eq!(report.statistics.queued, 0);
    }
}

#[test]
fn changed_factory_enabled_set_diverges_before_executing_the_requested_choice() {
    let calls = Cell::new(0);
    let observations = RefCell::new(Vec::new());
    let report = ExactDporExplorer::new(LabConfig::new(2), limits())
        .explore(|runtime| {
            let call = calls.get();
            calls.set(call + 1);
            let output = Arc::new(Mutex::new(Vec::new()));
            install_writers(
                runtime,
                if call == 0 { 2 } else { 3 },
                Arc::clone(&output),
                false,
            );
            observations.borrow_mut().push(output);
        })
        .unwrap();
    assert_eq!(report.termination, ExactDporTermination::Incomplete);
    assert_eq!(report.runs.len(), 2);
    assert_eq!(
        report.runs[1].execution.termination,
        ExactScheduleTermination::PrefixDiverged { decision: 0 }
    );
    assert_eq!(
        report.runs[1].analysis,
        ExactDporAnalysis::IncompleteExecution
    );
    assert!(observations.borrow()[1].lock().is_empty());
    assert!(report.runs[1].execution.schedule.is_none());
}

#[test]
fn moving_a_tasks_next_poll_does_not_claim_to_reverse_its_later_effect() {
    let observations = RefCell::new(Vec::new());
    let report = ExactDporExplorer::new(LabConfig::new(2), limits())
        .explore(|runtime| {
            let output = Arc::new(Mutex::new(Vec::new()));
            let region = runtime.state.create_root_region(Budget::INFINITE);
            for label in 0..2 {
                let output = Arc::clone(&output);
                let mut yielded = label == 0;
                let (task, _join) = runtime
                    .state
                    .create_task(
                        region,
                        Budget::INFINITE,
                        std::future::poll_fn(move |task_cx| {
                            if !yielded {
                                yielded = true;
                                task_cx.waker().wake_by_ref();
                                return Poll::Pending;
                            }
                            model_shared_write(&crate::Cx::current().unwrap());
                            output.lock().push(label);
                            Poll::Ready(())
                        }),
                    )
                    .unwrap();
                runtime.scheduler.lock().schedule(task, 0);
            }
            observations.borrow_mut().push(output);
        })
        .unwrap();
    assert_eq!(report.runs.len(), 3);
    let guided = &report.runs[1];
    let witness = guided.backtrack.as_ref().unwrap();
    assert_eq!(witness.earlier_decision, 0);
    assert_eq!(witness.later_decision, 2);
    assert_eq!(witness.intervening_later_task_polls, 1);
    assert_eq!(
        guided.execution.execution.decisions()[0].selected().task,
        witness.later_task.into()
    );
    // Its next poll merely yields; A's effect still precedes B's effect.
    assert_eq!(*observations.borrow()[0].lock(), vec![0, 1]);
    assert_eq!(*observations.borrow()[1].lock(), vec![0, 1]);
    // A later candidate can move B's second poll too; only that run reverses
    // the effects. Its retained witness identifies the intervening source run.
    assert_eq!(*observations.borrow()[2].lock(), vec![1, 0]);
    assert_eq!(report.runs[2].backtrack.as_ref().unwrap().source_run, 1);
    assert_eq!(report.termination, ExactDporTermination::GuidanceQueueEmpty);
}

#[test]
fn incomplete_cancellation_cleanup_never_generates_guidance() {
    let mut bounded = limits();
    bounded.execution.max_dispatches_per_run = 3;
    for wakes in [false, true] {
        let report = ExactDporExplorer::new(LabConfig::new(2), bounded)
            .explore(|runtime| {
                let region = runtime.state.create_root_region(Budget::INFINITE);
                let (task, handle) = runtime
                    .state
                    .create_task(
                        region,
                        Budget::INFINITE,
                        std::future::poll_fn(move |task_cx| {
                            assert!(crate::Cx::current().unwrap().checkpoint().is_err());
                            if wakes {
                                task_cx.waker().wake_by_ref();
                            }
                            Poll::<()>::Pending
                        }),
                    )
                    .unwrap();
                runtime.scheduler.lock().schedule(task, 0);
                handle.abort();
            })
            .unwrap();
        assert_eq!(report.termination, ExactDporTermination::Incomplete);
        assert_eq!(report.runs.len(), 1);
        assert_eq!(
            report.runs[0].analysis,
            ExactDporAnalysis::IncompleteExecution
        );
        assert!(report.runs[0].execution.schedule.is_none());
        assert_eq!(report.statistics.queued, 0);
        assert!(matches!(
            report.runs[0].execution.termination,
            ExactScheduleTermination::Stalled | ExactScheduleTermination::DispatchLimit
        ));
    }
}

#[test]
fn opt_in_cursor_capture_does_not_change_events_or_schedule_receipts() {
    let config = LabConfig::new(2);
    let mut ordinary = LabRuntime::new_with_task_causality(config.clone());
    writers(&mut ordinary);
    let prefix = ordinary.exact_schedule_empty_prefix();
    let plain = ordinary.run_exact_schedule_prefix(&prefix, limits().execution);

    let mut captured = LabRuntime::new_with_task_causality(config);
    writers(&mut captured);
    let (with_ranges, ranges) =
        captured.run_exact_schedule_prefix_with_trace(&prefix, limits().execution, true);
    assert_eq!(plain.execution, with_ranges.execution);
    assert_eq!(ordinary.trace().snapshot(), captured.trace().snapshot());
    assert_eq!(
        plain.schedule.unwrap().terminal_schedule_hash(),
        with_ranges.schedule.unwrap().terminal_schedule_hash()
    );
    assert_eq!(ranges.len(), 2);
    assert!(ranges.iter().all(|range| !range.is_empty()));
}

#[test]
fn admission_rejects_zero_bounds_and_counter_overflow_before_the_factory() {
    let config = LabConfig::new(2);
    let mut bad = limits();
    bad.max_trace_events = 0;
    assert_eq!(
        ExactDporExplorer::new(config.clone(), bad)
            .explore(|_| panic!("factory called"))
            .unwrap_err(),
        ExactDporConfigError::ZeroLimit
    );
    bad = limits();
    bad.execution.max_runs = usize::MAX;
    assert_eq!(
        ExactDporExplorer::new(config.clone(), bad)
            .explore(|_| panic!("factory called"))
            .unwrap_err(),
        ExactDporConfigError::CounterOverflow
    );
    assert_eq!(
        ExactDporExplorer::new(config.worker_count(2), limits())
            .explore(|_| panic!("factory called"))
            .unwrap_err(),
        ExactDporConfigError::Execution(ExactScheduleConfigError::MultipleWorkers)
    );
}
