use super::*;
use crate::lab::LabConfig;
use crate::runtime::task_handle::TaskHandle;
use crate::trace::TraceEvent;
use crate::trace::replay::ProjectionOptions;
use crate::types::{Budget, RegionId, TaskId, Time};
use crate::util::ArenaIndex;
use std::future::poll_fn;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;

fn limits() -> StrictProductionReplayLimits {
    StrictProductionReplayLimits::new(128, 16, 64, 64, 8)
}

fn source_task(ordinal: usize) -> TaskId {
    TaskId::from_arena(ArenaIndex::new(u32::try_from(ordinal + 40).unwrap(), 7))
}

fn source_events(spawns: usize, order: &[usize]) -> Vec<TraceEvent> {
    let region = RegionId::from_arena(ArenaIndex::new(31, 2));
    let mut events = Vec::new();
    for ordinal in 0..spawns {
        events.push(TraceEvent::spawn(
            u64::try_from(events.len()).unwrap(),
            Time::ZERO,
            source_task(ordinal),
            region,
        ));
    }
    for &ordinal in order {
        events.push(TraceEvent::poll(
            u64::try_from(events.len()).unwrap(),
            Time::ZERO,
            source_task(ordinal),
            region,
        ));
    }
    events
}

fn source(spawns: usize, order: &[usize]) -> ProductionSchedule {
    ProductionSchedule::from_runtime_trace(&source_events(spawns, order)).unwrap()
}

struct DropProbe(Arc<AtomicUsize>);

impl Drop for DropProbe {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

struct Fixture {
    runtime: LabRuntime,
    handles: Vec<TaskHandle<()>>,
    polls: Vec<Arc<AtomicUsize>>,
    drops: Vec<Arc<AtomicUsize>>,
}

impl Fixture {
    fn new(required_polls: &[usize], config: LabConfig) -> Self {
        let mut runtime = LabRuntime::new(config);
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let mut handles = Vec::new();
        let mut polls = Vec::new();
        let mut drops = Vec::new();
        for &required in required_polls {
            assert!(required > 0);
            let count = Arc::new(AtomicUsize::new(0));
            let dropped = Arc::new(AtomicUsize::new(0));
            let counter = Arc::clone(&count);
            let probe = DropProbe(Arc::clone(&dropped));
            let (task, handle) = runtime
                .state
                .create_task(root, Budget::INFINITE, async move {
                    let _keep_alive = probe;
                    poll_fn(move |cx| {
                        if counter.fetch_add(1, Ordering::SeqCst) + 1 == required {
                            Poll::Ready(())
                        } else {
                            cx.waker().wake_by_ref();
                            Poll::Pending
                        }
                    })
                    .await;
                })
                .unwrap();
            runtime.scheduler.lock().schedule(task, 0);
            handles.push(handle);
            polls.push(count);
            drops.push(dropped);
        }
        Self {
            runtime,
            handles,
            polls,
            drops,
        }
    }

    fn counts(&self) -> Vec<usize> {
        self.polls
            .iter()
            .map(|counter| counter.load(Ordering::SeqCst))
            .collect()
    }

    fn drop_counts(&self) -> Vec<usize> {
        self.drops
            .iter()
            .map(|counter| counter.load(Ordering::SeqCst))
            .collect()
    }

    fn drain(&mut self) {
        eprintln!(
            "{}",
            serde_json::json!({
                "bead": "asupersync-bi2462.96",
                "phase": "before_explicit_cleanup",
                "steps": self.runtime.steps(),
                "polls": self.counts(),
                "drops": self.drop_counts(),
                "boundary": format!("{:?}", self.runtime.production_replay_boundary()),
            })
        );
        let _ = self.runtime.discard_production_replay();
        // Explicit cleanup, not replay. step_for_test also lets the fixture
        // clean up after deliberately testing a configured one-step limit.
        for _ in 0..128 {
            if self.runtime.is_quiescent() {
                break;
            }
            self.runtime.step_for_test();
        }
        assert!(
            self.runtime.is_quiescent(),
            "fixture must not abandon live work"
        );
        assert!(self.handles.iter().all(TaskHandle::is_finished));
        assert!(self.drop_counts().iter().all(|count| *count == 1));
    }
}

fn fixture(polls: &[usize]) -> Fixture {
    Fixture::new(polls, LabConfig::new(71).max_steps(128))
}

#[test]
fn complete_source_requires_exact_consumption_and_quiescence() {
    let mut fx = fixture(&[2, 1]);
    let report = fx
        .runtime
        .run_production_schedule_strict(&source(2, &[0, 1, 0]), limits())
        .unwrap();
    assert_eq!(
        report.termination,
        StrictProductionReplayTermination::Matched
    );
    assert_eq!(report.replay.steps_matched, 3);
    assert_eq!(report.replay.steps_total, 3);
    assert_eq!(report.observed_spawns, 2);
    assert_eq!(report.work_units, 3);
    assert!(report.replay.stopped);
    assert!(report.lab.quiescent);
    assert!(report.passed());
    assert_eq!(fx.counts(), [2, 1]);
    fx.drain();
}

#[test]
fn exhausted_source_never_polls_unrecorded_tail_and_retains_captures() {
    let mut fx = fixture(&[1, 1]);
    let report = fx
        .runtime
        .run_production_schedule_strict(&source(2, &[0]), limits())
        .unwrap();
    assert_eq!(
        report.termination,
        StrictProductionReplayTermination::SourceExhausted
    );
    assert_eq!(report.replay.steps_matched, report.replay.steps_total);
    assert!(!report.passed());
    assert!(!report.lab.quiescent);
    assert_eq!(fx.counts(), [1, 0]);
    assert_eq!(fx.drop_counts(), [1, 0], "unpolled future remains owned");
    // Even an accidental normal-driver call must not silently execute the tail.
    fx.runtime.run_until_quiescent();
    fx.runtime.step_for_test();
    assert_eq!(fx.counts(), [1, 0]);
    assert_eq!(fx.drop_counts(), [1, 0]);
    fx.drain();
    assert_eq!(fx.counts(), [1, 1]);
}

#[test]
fn explicit_prefix_replay_continues_and_reports_its_limited_authority() {
    let mut fx = fixture(&[1, 1]);
    fx.runtime
        .replay_production_schedule_prefix(&source(2, &[0]), ProductionReplayOptions::default())
        .unwrap();
    fx.runtime.run_until_quiescent();
    assert_eq!(fx.counts(), [1, 1]);
    assert!(!fx.runtime.replay_report().unwrap().stopped);
    let boundary = fx.runtime.production_replay_boundary().unwrap();
    assert_eq!(boundary.mode, ProductionReplayMode::Prefix);
    assert_eq!(boundary.termination, None);
    assert_eq!(boundary.replay.steps_matched, 1);
    fx.drain();
}

#[test]
fn default_replay_rejects_truncated_tail_without_polling_it() {
    let mut fx = fixture(&[1, 1]);
    fx.runtime
        .replay_production_schedule(&source(2, &[0]), ProductionReplayOptions::default())
        .unwrap();
    let report = fx.runtime.run_until_quiescent_with_report();
    assert_eq!(fx.counts(), [1, 0], "an unrecorded task must remain owned");
    assert!(!report.lab_test_passed());
    let boundary = fx.runtime.production_replay_boundary().unwrap();
    assert_eq!(boundary.mode, ProductionReplayMode::Strict);
    assert_eq!(
        boundary.termination,
        Some(StrictProductionReplayTermination::SourceExhausted)
    );
    assert!(boundary.replay.stopped);
    assert_eq!(boundary.replay.steps_matched, 1);
    let steps = fx.runtime.steps();
    let now = fx.runtime.now();
    let auto = fx.runtime.run_with_auto_advance();
    assert_eq!(auto.steps, 0);
    assert_eq!(auto.auto_advances, 0);
    assert_eq!(fx.runtime.steps(), steps);
    assert_eq!(fx.runtime.now(), now);
    assert_eq!(fx.counts(), [1, 0]);
    fx.drain();
}

#[test]
fn default_replay_rejects_unconsumed_source_even_after_workload_quiesces() {
    let mut fx = fixture(&[1]);
    fx.runtime
        .replay_production_schedule(&source(1, &[0, 0]), ProductionReplayOptions::default())
        .unwrap();
    let report = fx.runtime.run_until_quiescent_with_report();
    assert!(report.quiescent);
    assert!(!report.lab_test_passed());
    assert_eq!(
        fx.runtime.production_replay_boundary().unwrap().termination,
        Some(StrictProductionReplayTermination::SourceRemaining)
    );
    assert!(
        report
            .invariant_violations
            .iter()
            .any(|value| value.starts_with("production_replay:incomplete:SourceRemaining"))
    );
    fx.drain();
}

#[test]
fn quiescence_does_not_accept_an_unconsumed_source_suffix() {
    let mut fx = fixture(&[1]);
    let report = fx
        .runtime
        .run_production_schedule_strict(&source(1, &[0, 0]), limits())
        .unwrap();
    assert_eq!(
        report.termination,
        StrictProductionReplayTermination::SourceRemaining
    );
    assert!(report.lab.quiescent);
    assert_eq!(report.replay.steps_matched, 1);
    assert_eq!(report.replay.steps_total, 2);
    assert!(!report.passed());
    assert_eq!(fx.counts(), [1]);
    fx.drain();
}

#[test]
fn missing_recorded_task_reports_divergence_without_polling_another_task() {
    let mut fx = fixture(&[1]);
    let report = fx
        .runtime
        .run_production_schedule_strict(&source(2, &[1]), limits())
        .unwrap();
    assert_eq!(
        report.termination,
        StrictProductionReplayTermination::Diverged
    );
    assert_eq!(report.replay.steps_matched, 0);
    assert_eq!(report.replay.divergence.unwrap().expected_ordinal, 1);
    assert_eq!(fx.counts(), [0]);
    assert_eq!(fx.drop_counts(), [0]);
    fx.drain();
}

#[test]
fn driver_budget_stops_between_recorded_polls_and_preserves_work() {
    let mut fx = fixture(&[2]);
    let report = fx
        .runtime
        .run_production_schedule_strict(
            &source(1, &[0, 0]),
            StrictProductionReplayLimits {
                max_work_units: 1,
                ..limits()
            },
        )
        .unwrap();
    assert_eq!(
        report.termination,
        StrictProductionReplayTermination::WorkLimit
    );
    assert_eq!(report.work_units, 1);
    assert_eq!(report.replay.steps_matched, 1);
    assert_eq!(fx.counts(), [1]);
    assert_eq!(fx.drop_counts(), [0]);
    fx.runtime.step_for_test();
    assert_eq!(fx.counts(), [1]);
    fx.drain();
}

#[test]
fn zero_work_budget_admits_but_does_not_poll() {
    let mut fx = fixture(&[1]);
    let report = fx
        .runtime
        .run_production_schedule_strict(
            &source(1, &[0]),
            StrictProductionReplayLimits {
                max_work_units: 0,
                ..limits()
            },
        )
        .unwrap();
    assert_eq!(
        report.termination,
        StrictProductionReplayTermination::WorkLimit
    );
    assert_eq!(report.work_units, 0);
    assert_eq!(fx.runtime.steps(), 0);
    assert_eq!(fx.counts(), [0]);
    assert!(report.replay.stopped);
    fx.drain();
}

#[test]
fn configured_step_limit_is_not_overridden_by_larger_driver_budget() {
    let mut fx = Fixture::new(&[2], LabConfig::new(71).max_steps(1));
    let report = fx
        .runtime
        .run_production_schedule_strict(&source(1, &[0, 0]), limits())
        .unwrap();
    assert_eq!(
        report.termination,
        StrictProductionReplayTermination::ConfiguredStepLimit
    );
    assert_eq!(report.work_units, 1);
    assert_eq!(fx.counts(), [1]);
    fx.drain();
}

#[test]
fn all_source_limits_refuse_before_installation_or_task_side_effects() {
    let schedule = source(2, &[0, 1]);
    let cases = [
        (
            "events",
            StrictProductionReplayLimits {
                max_events: schedule.trace().events.len() - 1,
                ..limits()
            },
        ),
        (
            "spawns",
            StrictProductionReplayLimits {
                max_spawns: 1,
                ..limits()
            },
        ),
        (
            "dispatches",
            StrictProductionReplayLimits {
                max_dispatches: 1,
                ..limits()
            },
        ),
    ];
    for (resource, bound) in cases {
        let mut fx = fixture(&[1, 1]);
        let error = fx
            .runtime
            .run_production_schedule_strict(&schedule, bound)
            .unwrap_err();
        assert!(matches!(
            error,
            StrictProductionReplayError::SourceLimit { resource: found, .. } if found == resource
        ));
        assert!(fx.runtime.replay_report().is_none());
        assert_eq!(fx.runtime.steps(), 0);
        assert_eq!(fx.counts(), [0, 0]);
        fx.drain();
    }
}

#[test]
fn no_poll_projection_and_orphan_projection_cannot_pass_admission() {
    let events = source_events(1, &[]);
    let no_steps = ProductionSchedule::from_runtime_trace(&events).unwrap();
    assert!(matches!(
        prepare_source(&no_steps, limits()),
        Err(StrictProductionReplayError::NoDispatches)
    ));

    let region = RegionId::from_arena(ArenaIndex::new(31, 2));
    let orphan = ProductionSchedule::from_runtime_trace_with(
        &[TraceEvent::poll(1, Time::ZERO, source_task(0), region)],
        ProjectionOptions {
            allow_orphans: true,
        },
    )
    .unwrap();
    assert!(matches!(
        prepare_source(&orphan, limits()),
        Err(StrictProductionReplayError::OrphanSpawns { count: 1 })
    ));

    let enqueue_only = ProductionSchedule::from_runtime_trace(&[
        TraceEvent::spawn(0, Time::ZERO, source_task(0), region),
        TraceEvent::schedule(1, Time::ZERO, source_task(0), region),
    ])
    .unwrap();
    assert!(matches!(
        prepare_source(&enqueue_only, limits()),
        Err(StrictProductionReplayError::NonPollSource)
    ));
}

#[test]
fn repeated_or_reversed_poll_sequence_is_rejected_before_execution() {
    for second in [1, 2] {
        let mut events = source_events(1, &[0, 0]);
        events[1].seq = 2;
        events[2].seq = second;
        let schedule = ProductionSchedule::from_runtime_trace(&events).unwrap();
        assert!(matches!(
            prepare_source(&schedule, limits()),
            Err(StrictProductionReplayError::SourceOrder { .. })
        ));
    }
}

#[test]
fn source_order_rejection_includes_unprojected_observations() {
    let region = RegionId::from_arena(ArenaIndex::new(31, 2));
    for next in [1, 0] {
        let mut events = source_events(1, &[0]);
        // Schedule is ignored when Poll observations exist, but its ordering
        // still belongs to the source and must not disappear during projection.
        events.push(TraceEvent::schedule(
            next,
            Time::ZERO,
            source_task(0),
            region,
        ));
        let schedule = ProductionSchedule::from_runtime_trace(&events).unwrap();
        assert_eq!(schedule.summary().skipped, 1);
        assert!(matches!(
            prepare_source(&schedule, limits()),
            Err(StrictProductionReplayError::SourceOrder { previous: 1, next: observed }) if observed == next
        ));
        let mut fx = fixture(&[1]);
        fx.runtime
            .replay_production_schedule(&schedule, ProductionReplayOptions::default())
            .unwrap();
        fx.runtime.run_until_quiescent();
        assert_eq!(fx.counts(), [0]);
        assert!(matches!(
            fx.runtime
                .production_replay_boundary()
                .unwrap()
                .source_error,
            Some(StrictProductionReplayError::SourceOrder { .. })
        ));
        fx.drain();
    }
}

#[test]
fn legitimate_unused_sequence_numbers_do_not_reject_complete_work() {
    let mut events = source_events(1, &[0]);
    events[0].seq = 7;
    events[1].seq = 19;
    let schedule = ProductionSchedule::from_runtime_trace(&events).unwrap();
    let mut fx = fixture(&[1]);
    let report = fx
        .runtime
        .run_production_schedule_strict(&schedule, limits())
        .unwrap();
    assert_eq!(
        report.termination,
        StrictProductionReplayTermination::Matched
    );
    assert!(report.passed());
    assert_eq!(fx.counts(), [1]);
    fx.drain();
}

#[test]
fn default_replay_cannot_pass_quiescence_with_a_stale_wake_and_unconsumed_source() {
    let mut runtime = LabRuntime::new(LabConfig::new(71).max_steps(128));
    let root = runtime.state.create_root_region(Budget::INFINITE);
    let saved = Arc::new(parking_lot::Mutex::new(None::<std::task::Waker>));
    let first_saved = Arc::clone(&saved);
    let (first, first_handle) = runtime
        .state
        .create_task(root, Budget::INFINITE, async move {
            poll_fn(|cx| {
                *first_saved.lock() = Some(cx.waker().clone());
                Poll::Ready(())
            })
            .await;
        })
        .unwrap();
    let (second, second_handle) = runtime
        .state
        .create_task(root, Budget::INFINITE, async move {
            saved
                .lock()
                .take()
                .expect("first task captured its waker")
                .wake();
        })
        .unwrap();
    runtime.scheduler.lock().schedule(first, 0);
    runtime.scheduler.lock().schedule(second, 0);
    runtime
        .replay_production_schedule(&source(2, &[0, 1, 0]), ProductionReplayOptions::default())
        .unwrap();

    // The legacy run loop stops on task-state quiescence before it considers
    // the stale scheduler entry. That is not complete replay consumption.
    let report = runtime.run_until_quiescent_with_report();
    let boundary = runtime.production_replay_boundary().unwrap();
    assert!(report.quiescent);
    assert!(first_handle.is_finished());
    assert!(second_handle.is_finished());
    assert!(!runtime.scheduler.lock().is_empty());
    assert_eq!(boundary.replay.steps_matched, 2);
    assert_eq!(boundary.replay.steps_total, 3);
    assert_eq!(boundary.termination, None);
    assert!(report.oracle_report.all_passed());
    assert!(
        report
            .invariant_violations
            .iter()
            .all(|violation| { violation.starts_with("production_replay:incomplete:Pending:") })
    );
    assert!(!report.lab_test_passed());
    eprintln!(
        "{}",
        serde_json::json!({
            "bead": "asupersync-bi2462.96",
            "case": "default_quiescent_stale_wake",
            "matched": boundary.replay.steps_matched,
            "total": boundary.replay.steps_total,
            "quiescent": report.quiescent,
            "invariant_violations": report.invariant_violations,
        })
    );

    let _ = runtime.discard_production_replay();
    runtime.step_for_test();
    assert!(runtime.scheduler.lock().is_empty());
    assert!(runtime.is_quiescent());
}

#[test]
fn stale_wake_cannot_count_a_retired_future_as_a_matched_poll() {
    let mut runtime = LabRuntime::new(LabConfig::new(71).max_steps(128));
    let root = runtime.state.create_root_region(Budget::INFINITE);
    let saved = Arc::new(parking_lot::Mutex::new(None::<std::task::Waker>));
    let first_saved = Arc::clone(&saved);
    let (first, first_handle) = runtime
        .state
        .create_task(root, Budget::INFINITE, async move {
            poll_fn(|cx| {
                *first_saved.lock() = Some(cx.waker().clone());
                Poll::Ready(())
            })
            .await;
        })
        .unwrap();
    let (second, second_handle) = runtime
        .state
        .create_task(root, Budget::INFINITE, async move {
            saved
                .lock()
                .take()
                .expect("first task captured its waker")
                .wake();
        })
        .unwrap();
    runtime.scheduler.lock().schedule(first, 0);
    runtime.scheduler.lock().schedule(second, 0);
    let report = runtime
        .run_production_schedule_strict(&source(2, &[0, 1, 0]), limits())
        .unwrap();
    eprintln!(
        "{}",
        serde_json::json!({"bead": "asupersync-bi2462.96", "case": "stale_wake", "receipt": format!("{report:?}")})
    );
    assert_eq!(
        report.termination,
        StrictProductionReplayTermination::Diverged
    );
    assert_eq!(report.replay.steps_matched, 2);
    assert_eq!(report.replay.steps_total, 3);
    assert_eq!(
        report.replay.divergence.unwrap().reason,
        crate::lab::runtime::ReplayDivergenceReason::SchedulerInvariant
    );
    assert!(first_handle.is_finished());
    assert!(second_handle.is_finished());
    let _ = runtime.discard_production_replay();
    runtime.run_until_quiescent();
    assert!(runtime.is_quiescent());
}

#[test]
fn missing_interior_poll_cannot_skip_a_dependency() {
    use std::sync::atomic::AtomicBool;
    let mut runtime = LabRuntime::new(LabConfig::new(71).max_steps(128));
    let root = runtime.state.create_root_region(Budget::INFINITE);
    let ready = Arc::new(AtomicBool::new(false));
    let waiter = Arc::new(parking_lot::Mutex::new(None::<std::task::Waker>));
    let producer_ready = Arc::clone(&ready);
    let producer_waiter = Arc::clone(&waiter);
    let (producer, producer_handle) = runtime
        .state
        .create_task(root, Budget::INFINITE, async move {
            futures_lite::future::yield_now().await;
            producer_ready.store(true, Ordering::SeqCst);
            if let Some(waker) = producer_waiter.lock().take() {
                waker.wake();
            }
        })
        .unwrap();
    let (consumer, consumer_handle) = runtime
        .state
        .create_task(root, Budget::INFINITE, async move {
            poll_fn(|cx| {
                if ready.load(Ordering::SeqCst) {
                    Poll::Ready(())
                } else {
                    *waiter.lock() = Some(cx.waker().clone());
                    Poll::Pending
                }
            })
            .await;
        })
        .unwrap();
    runtime.scheduler.lock().schedule(producer, 0);
    runtime.scheduler.lock().schedule(consumer, 0);
    // The complete source is producer, consumer, producer, consumer. Remove
    // the interior producer poll while retaining the final consumer choice.
    let report = runtime
        .run_production_schedule_strict(&source(2, &[0, 1, 1]), limits())
        .unwrap();
    eprintln!(
        "{}",
        serde_json::json!({"bead": "asupersync-bi2462.96", "case": "missing_dependency_poll", "receipt": format!("{report:?}")})
    );
    assert_eq!(
        report.termination,
        StrictProductionReplayTermination::Diverged
    );
    assert_eq!(report.replay.steps_matched, 2);
    assert!(matches!(
        report.replay.divergence.unwrap().reason,
        crate::lab::runtime::ReplayDivergenceReason::TaskNotRunnable { .. }
    ));
    assert!(!producer_handle.is_finished());
    assert!(!consumer_handle.is_finished());
    let _ = runtime.discard_production_replay();
    runtime.run_until_quiescent();
    assert!(producer_handle.is_finished());
    assert!(consumer_handle.is_finished());
    assert!(runtime.is_quiescent());
}

#[test]
fn spawn_count_receipt_does_not_hide_missing_or_additional_tasks() {
    let mut missing = fixture(&[1]);
    let report = missing
        .runtime
        .run_production_schedule_strict(&source(2, &[0]), limits())
        .unwrap();
    assert_eq!(
        report.termination,
        StrictProductionReplayTermination::SpawnCountMismatch {
            expected: 2,
            observed: 1,
        }
    );
    assert_eq!(report.observed_spawns, 1);
    assert!(!report.passed());
    missing.drain();

    let mut extra = fixture(&[1, 1]);
    let report = extra
        .runtime
        .run_production_schedule_strict(&source(1, &[0]), limits())
        .unwrap();
    assert_eq!(
        report.termination,
        StrictProductionReplayTermination::SpawnCountMismatch {
            expected: 1,
            observed: 2,
        }
    );
    assert_eq!(report.observed_spawns, 2);
    assert_eq!(
        report.replay.spawns_bound, 1,
        "legacy count is clamped; strict count must not be"
    );
    assert_eq!(extra.counts(), [0, 0]);
    extra.drain();
}

#[test]
fn existing_replay_and_exact_recorder_are_not_overwritten() {
    let schedule = source(1, &[0]);
    let mut fx = fixture(&[1]);
    fx.runtime
        .replay_production_schedule(&schedule, ProductionReplayOptions::default())
        .unwrap();
    let before = fx.runtime.replay_report();
    assert!(matches!(
        fx.runtime
            .run_production_schedule_strict(&schedule, limits()),
        Err(StrictProductionReplayError::ReplayAlreadyConfigured)
    ));
    assert_eq!(fx.runtime.replay_report(), before);
    let _ = fx.runtime.discard_production_replay();
    fx.runtime.start_forced_schedule_recording(64).unwrap();
    assert!(matches!(
        fx.runtime
            .run_production_schedule_strict(&schedule, limits()),
        Err(StrictProductionReplayError::RecordingActive)
    ));
    assert!(fx.runtime.forced_schedule_recorder.is_some());
    assert_eq!(fx.counts(), [0]);
    let _ = fx.runtime.finish_forced_schedule_recording().unwrap();
    fx.drain();
}

#[test]
fn started_runtime_is_refused_without_rewinding_or_pausing_existing_work() {
    let mut fx = fixture(&[2]);
    fx.runtime.step_for_test();
    let steps = fx.runtime.steps();
    assert!(matches!(
        fx.runtime
            .run_production_schedule_strict(&source(1, &[0]), limits()),
        Err(StrictProductionReplayError::AlreadyStarted { .. })
    ));
    assert_eq!(fx.runtime.steps(), steps);
    assert!(fx.runtime.replay_report().is_none());
    assert_eq!(fx.counts(), [1]);
    fx.drain();
}

#[test]
fn pause_guard_survives_unwind_without_dropping_runtime_custody() {
    let mut fx = fixture(&[1]);
    fx.runtime.production_replay = Some(prepare_source(&source(1, &[0]), limits()).unwrap());
    let panic: Result<(), _> = catch_unwind(AssertUnwindSafe(|| {
        let _pause = PauseOnExit {
            runtime: &mut fx.runtime,
        };
        panic!("driver sentinel");
    }));
    assert_eq!(
        panic.unwrap_err().downcast_ref::<&str>(),
        Some(&"driver sentinel")
    );
    assert!(fx.runtime.replay_report().unwrap().stopped);
    assert_eq!(fx.drop_counts(), [0]);
    fx.runtime.step_for_test();
    assert_eq!(fx.counts(), [0]);
    fx.drain();
}

#[test]
fn final_spawn_admission_pumps_do_not_poll_an_unrecorded_child() {
    let mut runtime = LabRuntime::new(LabConfig::new(71).max_steps(128));
    let root = runtime.state.create_root_region(Budget::INFINITE);
    let child_polls = Arc::new(AtomicUsize::new(0));
    let child_counter = Arc::clone(&child_polls);
    let (parent, handle) = runtime
        .state
        .create_task(root, Budget::INFINITE, async move {
            let cx = crate::Cx::current().expect("runtime installs a context");
            let mut child = cx
                .spawn(move |_| async move {
                    child_counter.fetch_add(1, Ordering::SeqCst);
                })
                .expect("child spawn admitted to mailbox");
            child
                .join(&cx)
                .await
                .expect("child completes during explicit cleanup");
        })
        .unwrap();
    runtime.scheduler.lock().schedule(parent, 0);
    let report = runtime
        .run_production_schedule_strict(&source(2, &[0]), limits())
        .unwrap();
    assert_eq!(
        report.termination,
        StrictProductionReplayTermination::SourceExhausted
    );
    assert_eq!(report.replay.steps_matched, 1);
    assert_eq!(
        report.observed_spawns, 2,
        "terminal pump admits queued child"
    );
    assert!(
        report.work_units > 1,
        "system-only admission consumes driver budget"
    );
    assert_eq!(child_polls.load(Ordering::SeqCst), 0);
    assert!(!handle.is_finished());
    let _ = runtime.discard_production_replay();
    runtime.run_until_quiescent();
    assert!(runtime.is_quiescent());
    assert!(handle.is_finished());
    assert_eq!(child_polls.load(Ordering::SeqCst), 1);
}

#[test]
fn extra_spawn_admitted_during_a_step_retains_its_typed_rejection() {
    let mut runtime = LabRuntime::new(LabConfig::new(71).max_steps(128));
    let root = runtime.state.create_root_region(Budget::INFINITE);
    let child_polls = Arc::new(AtomicUsize::new(0));
    let child_counter = Arc::clone(&child_polls);
    let (parent, handle) = runtime
        .state
        .create_task(root, Budget::INFINITE, async move {
            let cx = crate::Cx::current().expect("runtime installs a context");
            let mut child = cx
                .spawn(move |_| async move {
                    child_counter.fetch_add(1, Ordering::SeqCst);
                })
                .expect("child admitted to mailbox");
            child
                .join(&cx)
                .await
                .expect("explicit cleanup completes child");
        })
        .unwrap();
    runtime.scheduler.lock().schedule(parent, 0);
    // Only the parent exists before execution. Its first poll admits the
    // unexpected child, which becomes visible inside the second step.
    let report = runtime
        .run_production_schedule_strict(&source(1, &[0, 0]), limits())
        .unwrap();
    eprintln!(
        "{}",
        serde_json::json!({
            "bead": "asupersync-bi2462.96",
            "case": "spawn_during_dispatch_admission",
            "receipt": format!("{report:?}"),
            "child_polls": child_polls.load(Ordering::SeqCst),
        })
    );
    assert_eq!(
        report.termination,
        StrictProductionReplayTermination::SpawnCountMismatch {
            expected: 1,
            observed: 2,
        }
    );
    assert_eq!(report.replay.steps_matched, 1);
    assert_eq!(child_polls.load(Ordering::SeqCst), 0);
    assert_eq!(
        runtime.production_replay_boundary().unwrap().termination,
        Some(report.termination)
    );
    let _ = runtime.discard_production_replay();
    runtime.run_until_quiescent();
    assert!(handle.is_finished());
    assert!(runtime.is_quiescent());
    assert_eq!(child_polls.load(Ordering::SeqCst), 1);
}

#[test]
fn timer_waits_charge_work_without_claiming_an_extra_matched_poll() {
    let mut runtime = LabRuntime::new(LabConfig::new(71).max_steps(128));
    let root = runtime.state.create_root_region(Budget::INFINITE);
    let finished = Arc::new(AtomicUsize::new(0));
    let completed = Arc::clone(&finished);
    let deadline = Time::from_millis(25);
    let (task, handle) = runtime
        .state
        .create_task(root, Budget::INFINITE, async move {
            crate::time::Sleep::new(deadline).await;
            completed.fetch_add(1, Ordering::SeqCst);
        })
        .unwrap();
    runtime.scheduler.lock().schedule(task, 0);
    let report = runtime
        .run_production_schedule_strict(
            &source(1, &[0, 0]),
            StrictProductionReplayLimits {
                max_work_units: 2,
                ..limits()
            },
        )
        .unwrap();
    assert_eq!(
        report.termination,
        StrictProductionReplayTermination::WorkLimit
    );
    assert_eq!(report.replay.steps_matched, 1);
    assert_eq!(report.work_units, 2);
    assert!(runtime.now() >= deadline);
    assert_eq!(
        finished.load(Ordering::SeqCst),
        0,
        "wait must not secretly poll"
    );
    let frozen_time = runtime.now();
    let frozen_steps = runtime.steps();
    let paused = runtime.run_with_auto_advance();
    assert_eq!(paused.steps, 0);
    assert_eq!(paused.auto_advances, 0);
    assert_eq!(runtime.now(), frozen_time);
    assert_eq!(runtime.steps(), frozen_steps);
    let _ = runtime.discard_production_replay();
    let _ = runtime.run_with_auto_advance();
    assert!(runtime.is_quiescent());
    assert!(handle.is_finished());
    assert_eq!(finished.load(Ordering::SeqCst), 1);
}

#[test]
fn zero_wait_policy_refuses_timer_wait_without_advancing_virtual_time() {
    let mut runtime = LabRuntime::new(LabConfig::new(71).max_steps(128));
    let root = runtime.state.create_root_region(Budget::INFINITE);
    let (task, handle) = runtime
        .state
        .create_task(root, Budget::INFINITE, async {
            crate::time::Sleep::new(Time::from_millis(25)).await;
        })
        .unwrap();
    runtime.scheduler.lock().schedule(task, 0);
    let report = runtime
        .run_production_schedule_strict(
            &source(1, &[0, 0]),
            StrictProductionReplayLimits {
                max_wait_steps: 0,
                ..limits()
            },
        )
        .unwrap();
    assert_eq!(
        report.termination,
        StrictProductionReplayTermination::Diverged
    );
    assert_eq!(report.replay.steps_matched, 1);
    assert_eq!(runtime.now(), Time::ZERO);
    let _ = runtime.discard_production_replay();
    let _ = runtime.run_with_auto_advance();
    assert!(handle.is_finished());
    assert!(runtime.is_quiescent());
}

#[test]
fn chaos_cannot_make_selected_but_unpolled_work_look_replayed() {
    let mut runtime = LabRuntime::new(LabConfig::new(71).with_light_chaos());
    assert!(runtime.has_chaos());
    assert!(matches!(
        runtime.run_production_schedule_strict(&source(1, &[0]), limits()),
        Err(StrictProductionReplayError::ChaosActive)
    ));
    assert_eq!(runtime.steps(), 0);
    assert!(runtime.replay_report().is_none());
    assert!(runtime.is_quiescent());
}
