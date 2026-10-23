#![allow(clippy::pedantic, clippy::nursery, clippy::future_not_send)]

use super::*;
use crate::lab::runtime::ForcedScheduleLimits;
use crate::types::{Budget, Time};
use parking_lot::Mutex;
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::task::{Poll, Waker};
use std::time::Duration;

fn limits() -> ExactScheduleLimits {
    ExactScheduleLimits::new(32, 256, 64, 256, 512)
}

fn one_poll_tasks(runtime: &mut LabRuntime, count: u8, observations: Arc<Mutex<Vec<u8>>>) {
    let region = runtime.state.create_root_region(Budget::INFINITE);
    for label in 0..count {
        let observations = Arc::clone(&observations);
        let (task, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                observations.lock().push(label);
            })
            .expect("create task");
        runtime.scheduler.lock().schedule(task, 0);
    }
}

#[test]
fn exact_explorer_executes_all_six_orders_and_replays_each_receipt() {
    let config = LabConfig::new(42);
    let explorer = ExactScheduleExplorer::new(config.clone(), limits());
    let observed = RefCell::new(Vec::new());
    let report = explorer
        .explore(|runtime| {
            let output = Arc::new(Mutex::new(Vec::new()));
            one_poll_tasks(runtime, 3, Arc::clone(&output));
            observed.borrow_mut().push(output);
        })
        .expect("supported configuration");

    assert_eq!(report.termination, ExactScheduleSearchTermination::SearchExhausted);
    assert_eq!(report.completed_schedules(), 6);
    assert!(report.pending_prefixes.is_empty());
    assert_eq!(report.omitted_prefixes, 0);
    let actual: BTreeSet<_> = observed
        .borrow()
        .iter()
        .map(|output| output.lock().clone())
        .collect();
    let expected = BTreeSet::from([
        vec![0, 1, 2],
        vec![0, 2, 1],
        vec![1, 0, 2],
        vec![1, 2, 0],
        vec![2, 0, 1],
        vec![2, 1, 0],
    ]);
    assert_eq!(actual, expected);

    for (run, original) in report.runs.iter().zip(observed.borrow().iter()) {
        assert!(run.lab.quiescent);
        let output = Arc::new(Mutex::new(Vec::new()));
        let mut runtime = LabRuntime::new_with_task_causality(config.clone());
        one_poll_tasks(&mut runtime, 3, Arc::clone(&output));
        let schedule = run.schedule.as_ref().expect("complete receipt");
        let replay = runtime
            .run_forced_schedule(schedule, ForcedScheduleLimits::new(64, 256))
            .expect("exact receipt must replay on a fresh workload");
        assert!(replay.quiescent);
        assert_eq!(replay.schedule_hash, schedule.terminal_schedule_hash());
        assert_eq!(*output.lock(), *original.lock());
    }
}

#[test]
fn exact_explorer_exposes_lost_updates_across_real_poll_boundaries() {
    let explorer = ExactScheduleExplorer::new(LabConfig::new(77), limits());
    let outcomes = RefCell::new(Vec::new());
    let report = explorer
        .explore(|runtime| {
            let counter = Arc::new(Mutex::new(0usize));
            outcomes.borrow_mut().push(Arc::clone(&counter));
            let region = runtime.state.create_root_region(Budget::INFINITE);
            for _ in 0..2 {
                let counter = Arc::clone(&counter);
                let mut read = None;
                let future = std::future::poll_fn(move |cx| {
                    if let Some(value) = read {
                        *counter.lock() = value + 1;
                        Poll::Ready(())
                    } else {
                        read = Some(*counter.lock());
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                });
                let (task, _handle) = runtime
                    .state
                    .create_task(region, Budget::INFINITE, future)
                    .expect("create split read/write task");
                runtime.scheduler.lock().schedule(task, 0);
            }
        })
        .expect("supported configuration");

    // The six linear extensions of A-read < A-write and B-read < B-write
    // include both serial increments and the planted lost-update defect.
    assert_eq!(report.termination, ExactScheduleSearchTermination::SearchExhausted);
    assert_eq!(report.completed_schedules(), 6);
    let actual: BTreeSet<_> = outcomes.borrow().iter().map(|value| *value.lock()).collect();
    assert_eq!(actual, BTreeSet::from([1, 2]));
}

#[test]
fn exact_prefix_replays_the_same_choices_and_rejects_changed_enabled_sets() {
    let explorer = ExactScheduleExplorer::new(LabConfig::new(42), limits());
    let report = explorer
        .explore(|runtime| one_poll_tasks(runtime, 3, Arc::new(Mutex::new(Vec::new()))))
        .unwrap();
    let original = &report.runs[1];
    let replay = explorer
        .replay(&original.execution, |runtime| {
            one_poll_tasks(runtime, 3, Arc::new(Mutex::new(Vec::new())));
        })
        .unwrap();
    assert_eq!(replay.termination, ExactScheduleTermination::Quiescent);
    assert_eq!(replay.execution, original.execution);
    assert_eq!(
        replay.schedule.unwrap().terminal_schedule_hash(),
        original.schedule.as_ref().unwrap().terminal_schedule_hash()
    );

    for change_time in [false, true] {
        let polled = Arc::new(Mutex::new(Vec::new()));
        let divergent = explorer
            .replay(&original.execution, |runtime| {
                one_poll_tasks(runtime, if change_time { 3 } else { 2 }, Arc::clone(&polled));
                if change_time {
                    runtime.advance_time(1);
                }
            })
            .unwrap();
        assert_eq!(
            divergent.termination,
            ExactScheduleTermination::PrefixDiverged { decision: 0 }
        );
        assert!(polled.lock().is_empty(), "mismatched choice was not polled");
        assert!(divergent.schedule.is_none());
        assert!(divergent.execution.decisions().is_empty());
    }

    let too_short = explorer.replay(&original.execution, |_| {}).unwrap();
    assert_eq!(
        too_short.termination,
        ExactScheduleTermination::PrefixDiverged { decision: 0 }
    );
    assert!(too_short.schedule.is_none());
}

#[test]
fn exact_explorer_reports_each_exhaustion_without_claiming_completion() {
    let setup = |runtime: &mut LabRuntime| {
        one_poll_tasks(runtime, 3, Arc::new(Mutex::new(Vec::new())));
    };
    let mut bounded = limits();
    bounded.max_runs = 1;
    let run_limited = ExactScheduleExplorer::new(LabConfig::new(42), bounded)
        .explore(setup)
        .unwrap();
    assert_eq!(run_limited.termination, ExactScheduleSearchTermination::RunLimit);
    assert_eq!(run_limited.completed_schedules(), 1);
    assert!(!run_limited.pending_prefixes.is_empty());

    bounded = limits();
    bounded.max_pending_prefixes = 1;
    let queue_limited = ExactScheduleExplorer::new(LabConfig::new(42), bounded)
        .explore(setup)
        .unwrap();
    assert_eq!(
        queue_limited.termination,
        ExactScheduleSearchTermination::PrefixQueueLimit
    );
    assert!(queue_limited.omitted_prefixes > 0);

    for dispatch_limit in [false, true] {
        bounded = limits();
        if dispatch_limit {
            bounded.max_dispatches_per_run = 1;
        } else {
            bounded.max_work_per_run = 1;
        }
        let report = ExactScheduleExplorer::new(LabConfig::new(42), bounded)
            .explore(setup)
            .unwrap();
        assert_eq!(report.termination, ExactScheduleSearchTermination::IncompleteRun);
        assert_eq!(report.completed_schedules(), 0);
        let expected = if dispatch_limit {
            ExactScheduleTermination::DispatchLimit
        } else {
            ExactScheduleTermination::WorkLimit
        };
        assert!(report.runs.iter().all(|run| run.termination == expected));
        assert!(report.runs.iter().all(|run| run.schedule.is_none()));
    }
}

fn sleeping_task(runtime: &mut LabRuntime, observed: Arc<Mutex<Vec<Time>>>) {
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let (task, _handle) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            let cx = crate::Cx::current().expect("lab task context");
            crate::time::sleep(cx.now(), Duration::from_millis(2)).await;
            observed.lock().push(cx.now());
        })
        .expect("create sleeping task");
    runtime.scheduler.lock().schedule(task, 0);
}

#[test]
fn exact_explorer_timer_completion_has_a_strictly_replayable_receipt() {
    let config = LabConfig::new(43);
    let observed = Arc::new(Mutex::new(Vec::new()));
    let report = ExactScheduleExplorer::new(config.clone(), limits())
        .explore(|runtime| sleeping_task(runtime, Arc::clone(&observed)))
        .unwrap();
    assert_eq!(report.termination, ExactScheduleSearchTermination::SearchExhausted);
    assert_eq!(report.completed_schedules(), 1);
    assert_eq!(*observed.lock(), vec![Time::from_millis(2)]);

    let mut replay = LabRuntime::new_with_task_causality(config);
    let replayed = Arc::new(Mutex::new(Vec::new()));
    sleeping_task(&mut replay, Arc::clone(&replayed));
    let schedule = report.runs[0].schedule.as_ref().unwrap();
    let receipt = replay
        .run_forced_schedule(schedule, ForcedScheduleLimits::new(64, 256))
        .expect("timer receipt replays");
    assert!(receipt.quiescent);
    assert_eq!(receipt.terminal_nanos, Time::from_millis(2).as_nanos());
    assert_eq!(*replayed.lock(), *observed.lock());
}

#[test]
fn parked_work_and_silent_timer_hops_are_explicitly_incomplete() {
    for silent_timer in [false, true] {
        let report = ExactScheduleExplorer::new(LabConfig::new(42), limits())
            .explore(|runtime| {
                let region = runtime.state.create_root_region(Budget::INFINITE);
                let (task, _handle) = runtime
                    .state
                    .create_task(region, Budget::INFINITE, std::future::pending::<()>())
                    .expect("create parked task");
                runtime.scheduler.lock().schedule(task, 0);
                if silent_timer {
                    let timer = runtime.state.timer_driver_handle().unwrap();
                    let _ = timer.register(Time::from_millis(1), Waker::noop().clone());
                }
            })
            .unwrap();
        assert_eq!(report.termination, ExactScheduleSearchTermination::IncompleteRun);
        assert_eq!(report.completed_schedules(), 0);
        let run = &report.runs[0];
        assert!(!run.lab.quiescent);
        assert!(run.schedule.is_none());
        if silent_timer {
            assert!(matches!(run.termination, ExactScheduleTermination::Unsupported { .. }));
        } else {
            assert_eq!(run.termination, ExactScheduleTermination::Stalled);
        }
    }
}

#[test]
fn exact_explorer_rejects_invalid_configuration_before_factory() {
    let forbidden = |_: &mut LabRuntime| panic!("invalid configuration invoked the factory");
    let multiple = ExactScheduleExplorer::new(LabConfig::new(42).worker_count(2), limits());
    assert!(matches!(
        multiple.explore(forbidden),
        Err(ExactScheduleConfigError::MultipleWorkers)
    ));
    let chaos = ExactScheduleExplorer::new(LabConfig::new(42).with_light_chaos(), limits());
    assert!(matches!(
        chaos.explore(forbidden),
        Err(ExactScheduleConfigError::ChaosEnabled)
    ));
    let mut zero = limits();
    zero.max_inventory_entries = 0;
    assert!(matches!(
        ExactScheduleExplorer::new(LabConfig::new(42), zero).explore(forbidden),
        Err(ExactScheduleConfigError::ZeroLimit)
    ));
}

#[test]
fn exact_explorer_rechecks_factory_state_and_inventory_bounds() {
    let explorer = ExactScheduleExplorer::new(LabConfig::new(42), limits());
    let started = explorer
        .explore(|runtime| {
            one_poll_tasks(runtime, 2, Arc::new(Mutex::new(Vec::new())));
            runtime.step_for_test();
        })
        .unwrap();
    assert!(matches!(
        started.runs[0].termination,
        ExactScheduleTermination::ReplayRejected(ForcedScheduleError::RuntimeAlreadyStarted { .. })
    ));
    assert!(started.runs[0].schedule.is_none());

    let paused = explorer
        .explore(|runtime| {
            one_poll_tasks(runtime, 1, Arc::new(Mutex::new(Vec::new())));
            runtime.pause_clock();
        })
        .unwrap();
    assert!(matches!(
        paused.runs[0].termination,
        ExactScheduleTermination::Unsupported { .. }
    ));
    assert!(paused.runs[0].execution.decisions().is_empty());

    let mut bounded = limits();
    bounded.max_inventory_entries = 1;
    let inventory = ExactScheduleExplorer::new(LabConfig::new(42), bounded)
        .explore(|runtime| one_poll_tasks(runtime, 2, Arc::new(Mutex::new(Vec::new()))))
        .unwrap();
    assert!(matches!(
        inventory.runs[0].termination,
        ExactScheduleTermination::Unsupported { .. }
    ));
    assert!(inventory.runs[0].execution.decisions().is_empty());
    assert_eq!(inventory.termination, ExactScheduleSearchTermination::IncompleteRun);
}

#[test]
fn exact_explorer_rejects_production_replay_installed_by_factory() {
    let config = LabConfig::new(42).with_default_replay_recording();
    let mut source = LabRuntime::new_with_task_causality(config.clone());
    one_poll_tasks(&mut source, 1, Arc::new(Mutex::new(Vec::new())));
    source.run_until_quiescent();
    let schedule = source.recorded_production_schedule().expect("source schedule");
    let polled = Arc::new(Mutex::new(Vec::new()));
    let report = ExactScheduleExplorer::new(config, limits())
        .explore(|runtime| {
            one_poll_tasks(runtime, 1, Arc::clone(&polled));
            runtime
                .replay_production_schedule_prefix(
                    &schedule,
                    crate::lab::runtime::ProductionReplayOptions::default(),
                )
                .expect("install conflicting replay before any poll");
        })
        .unwrap();
    assert_eq!(report.termination, ExactScheduleSearchTermination::IncompleteRun);
    assert!(matches!(
        report.runs[0].termination,
        ExactScheduleTermination::Unsupported { .. }
    ));
    assert!(polled.lock().is_empty());
    assert!(report.runs[0].execution.decisions().is_empty());
    assert!(report.runs[0].schedule.is_none());
}

#[test]
fn exact_explorer_pending_obligation_posts_preserve_strict_timer_receipts() {
    struct ScheduleTask {
        task: crate::types::TaskId,
        scheduler: Arc<Mutex<crate::lab::runtime::LabScheduler>>,
    }

    impl std::task::Wake for ScheduleTask {
        fn wake(self: Arc<Self>) {
            self.scheduler.lock().schedule(self.task, 0);
        }
    }

    fn setup(runtime: &mut LabRuntime, observed: Arc<Mutex<Vec<Time>>>) {
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let (task, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                observed.lock().push(crate::Cx::current().unwrap().now());
            })
            .expect("create timer-scheduled task");
        let cx = runtime.state.task(task).unwrap().cx.as_ref().unwrap().clone();
        let (sender, _receiver) = crate::channel::oneshot::channel::<()>();
        drop(sender.reserve_checked(&cx).expect("checked reservation"));
        assert!(runtime.state.has_pending_obligation_posts());
        assert!(runtime.scheduler.lock().is_empty());
        let wake = Waker::from(Arc::new(ScheduleTask {
            task,
            scheduler: Arc::clone(&runtime.scheduler),
        }));
        let timer = runtime.state.timer_driver_handle().unwrap();
        let _ = timer.register(Time::from_millis(2), wake);
    }

    let config = LabConfig::new(43);
    let observed = Arc::new(Mutex::new(Vec::new()));
    let report = ExactScheduleExplorer::new(config.clone(), limits())
        .explore(|runtime| setup(runtime, Arc::clone(&observed)))
        .unwrap();
    assert_eq!(report.termination, ExactScheduleSearchTermination::SearchExhausted);
    assert_eq!(report.completed_schedules(), 1);
    let run = &report.runs[0];
    assert_eq!(run.execution.decisions().len(), 1);
    assert_eq!(run.execution.decisions()[0].selected().at_step(), 1);
    assert_eq!(*observed.lock(), vec![Time::from_millis(2)]);
    let schedule = run.schedule.as_ref().expect("complete receipt");

    let replayed = Arc::new(Mutex::new(Vec::new()));
    let mut runtime = LabRuntime::new_with_task_causality(config);
    setup(&mut runtime, Arc::clone(&replayed));
    let replay = runtime
        .run_forced_schedule(schedule, ForcedScheduleLimits::new(64, 256))
        .expect("pending posts retain the existing strict replay chronology");
    assert!(replay.quiescent);
    assert_eq!(replay.schedule_hash, schedule.terminal_schedule_hash());
    assert_eq!(*replayed.lock(), *observed.lock());
}
