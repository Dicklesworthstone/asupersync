//! Real native parked-task capture, checked projection, and strict Lab replay.
#![cfg(not(target_arch = "wasm32"))]

use asupersync::Cx;
use asupersync::channel::oneshot;
use asupersync::lab::runtime::production_strict::{
    StrictProductionReplayLimits, StrictProductionReplayTermination,
};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::trace::{ScheduleCaptureError, ScheduleCaptureSnapshot, TraceData, TraceEventKind};
use asupersync::types::{Budget, CancelKind, TaskId};
use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

const WATCHDOG: Duration = Duration::from_secs(10);

fn join_native<F: Future>(runtime: &Runtime, future: F) -> F::Output {
    runtime.block_on(async {
        let cx = Cx::current().expect("caller watchdog has runtime drivers");
        asupersync::time::timeout(cx.now(), WATCHDOG, future)
            .await
            .expect("native capture workload completed before watchdog")
    })
}

fn completed_capture(runtime: &Runtime) -> ScheduleCaptureSnapshot {
    let deadline = Instant::now() + WATCHDOG;
    loop {
        let snapshot = runtime
            .schedule_capture_snapshot()
            .expect("capture enabled");
        match snapshot.production_schedule() {
            Ok(_) => return snapshot,
            Err(ScheduleCaptureError::UnfinishedTasks { .. }) if Instant::now() < deadline => {
                // Join publication can precede the worker's Complete event.
                std::thread::yield_now();
            }
            Err(error) => panic!("capture did not reach a complete boundary: {error:?}"),
        }
    }
}

async fn receive_input(
    mut receiver: oneshot::Receiver<u32>,
    parked: Option<mpsc::Sender<TaskId>>,
    replay_input: Option<(oneshot::Sender<u32>, u32)>,
) -> u32 {
    let cx = Cx::current().expect("actual admitted task context");
    let mut parked = parked;
    let mut replay_input = replay_input;
    let mut receive = std::pin::pin!(receiver.recv(&cx));
    poll_fn(|task| {
        let result = receive.as_mut().poll(task);
        if result.is_pending() {
            if let Some(parked) = parked.take() {
                parked
                    .send(cx.task_id())
                    .expect("publish real Pending witness");
            }
            // The Lab reconstructs the externally supplied input at the first
            // witnessed receive registration. Strict replay still controls
            // when this now-runnable task may be polled again.
            if let Some((sender, value)) = replay_input.take() {
                sender.send_blocking(value).expect("inject captured input");
            }
        }
        result
    })
    .await
    .expect("external input received")
}

#[test]
fn native_parked_wakes_replay_with_identical_terminal_values() {
    for workers in [1, 2] {
        for sharded in [false, true] {
            let runtime = RuntimeBuilder::new()
                .worker_threads(workers)
                .with_sharded_state(sharded)
                .capture_schedules(true)
                .build()
                .unwrap();
            let (parked_tx, parked_rx) = mpsc::channel();
            let values = [17, 29];
            let mut joins = Vec::new();
            let mut inputs = Vec::new();
            for value in values {
                let (sender, receiver) = oneshot::channel();
                inputs.push((sender, value));
                joins.push(runtime.handle().spawn(receive_input(
                    receiver,
                    Some(parked_tx.clone()),
                    None,
                )));
            }
            drop(parked_tx);
            // Both tasks genuinely park before any sender supplies a value.
            let first = parked_rx.recv_timeout(WATCHDOG).expect("first task parked");
            let second = parked_rx
                .recv_timeout(WATCHDOG)
                .expect("second task parked");
            assert_ne!(first, second);
            for (sender, value) in inputs {
                sender.send_blocking(value).unwrap();
            }
            let native: Vec<_> = joins
                .into_iter()
                .map(|join| join_native(&runtime, join))
                .collect();
            assert_eq!(native, values);
            let snapshot = completed_capture(&runtime);
            assert_eq!(snapshot.dropped_events(), 0);
            assert_eq!(snapshot.worker_count(), workers);
            let schedule = snapshot.production_schedule().unwrap();
            assert_eq!(schedule.summary().spawned, 2);
            assert!(schedule.summary().steps >= 4);
            let mut polls = BTreeMap::new();
            for event in snapshot.events() {
                if event.kind == TraceEventKind::Poll
                    && let TraceData::Task { task, .. } = &event.data
                {
                    *polls.entry(*task).or_insert(0usize) += 1;
                    let context = snapshot
                        .contexts()
                        .iter()
                        .find(|context| context.event_sequence == event.seq)
                        .unwrap();
                    assert!(context.worker_id.is_some_and(|worker| worker < workers));
                }
            }
            assert!(polls.get(&first).is_some_and(|count| *count >= 2));
            assert!(polls.get(&second).is_some_and(|count| *count >= 2));
            for task in [first, second] {
                assert!(snapshot.events().iter().any(|event| {
                    event.kind == TraceEventKind::Wake
                        && matches!(event.data, TraceData::Task { task: observed, .. } if observed == task)
                }));
            }

            let mut lab = LabRuntime::new(LabConfig::new(95).max_steps(128));
            let region = lab.state.create_root_region(Budget::INFINITE);
            let observed = Arc::new(Mutex::new(vec![None; values.len()]));
            let mut lab_joins = Vec::new();
            for (index, value) in values.into_iter().enumerate() {
                let (sender, receiver) = oneshot::channel();
                let observed = Arc::clone(&observed);
                let (task, join) = lab
                    .state
                    .create_task(region, Budget::INFINITE, async move {
                        let value = receive_input(receiver, None, Some((sender, value))).await;
                        observed.lock().unwrap()[index] = Some(value);
                    })
                    .unwrap();
                lab.scheduler.lock().schedule(task, 0);
                lab_joins.push(join);
            }
            let report = lab
                .run_production_schedule_strict(
                    &schedule,
                    StrictProductionReplayLimits::new(512, 8, 128, 128, 8),
                )
                .unwrap();
            eprintln!(
                "{}",
                serde_json::json!({
                    "bead": "asupersync-bi2462.95",
                    "workers": workers,
                    "sharded": sharded,
                    "native_polls": format!("{polls:?}"),
                    "events": snapshot.total_events(),
                    "dropped_events": snapshot.dropped_events(),
                    "replay": format!("{report:?}"),
                    "native_values": native,
                    "lab_values": *observed.lock().unwrap(),
                })
            );
            assert_eq!(
                report.termination,
                StrictProductionReplayTermination::Matched
            );
            assert!(report.passed());
            assert_eq!(*observed.lock().unwrap(), [Some(17), Some(29)]);
            assert!(
                lab_joins
                    .iter()
                    .all(asupersync::runtime::TaskHandle::is_finished)
            );
            assert!(runtime.shutdown_timeout(WATCHDOG));
        }
    }
}

#[test]
fn native_cancellation_capture_contains_ack_before_completion() {
    for workers in [1, 2] {
        for sharded in [false, true] {
            let runtime = RuntimeBuilder::new()
                .worker_threads(workers)
                .with_sharded_state(sharded)
                .capture_schedules(true)
                .build()
                .unwrap();
            let (sender, mut receiver) = oneshot::channel::<()>();
            let (parked_tx, parked_rx) = mpsc::channel();
            let join = runtime.handle().spawn(async move {
                let cx = Cx::current().unwrap();
                let mut parked = Some(parked_tx);
                let mut receive = std::pin::pin!(receiver.recv(&cx));
                let result = poll_fn(|task| {
                    let result = receive.as_mut().poll(task);
                    if result.is_pending()
                        && let Some(parked) = parked.take()
                    {
                        parked.send(cx.clone()).unwrap();
                    }
                    result
                })
                .await;
                assert!(result.is_err());
                assert!(cx.checkpoint().is_err());
                cx.cancel_reason().expect("actual task cancellation")
            });
            let owner = parked_rx
                .recv_timeout(WATCHDOG)
                .expect("task parked on live oneshot");
            owner.cancel_with(CancelKind::User, Some("capture cancellation"));
            let reason = join_native(&runtime, join);
            assert_eq!(reason.kind, CancelKind::User);
            let snapshot = completed_capture(&runtime);
            let ack = snapshot
                .events()
                .iter()
                .find(|event| {
                    event.kind == TraceEventKind::CancelAck
                        && matches!(&event.data, TraceData::Cancel { task, reason: observed, .. }
                        if *task == owner.task_id() && observed == &reason)
                })
                .expect("actual checkpoint receipt captured");
            let complete = snapshot.events().iter().find(|event| {
                event.kind == TraceEventKind::Complete
                    && matches!(event.data, TraceData::Task { task, .. } if task == owner.task_id())
            }).unwrap();
            assert!(ack.seq < complete.seq);
            assert!(snapshot.contexts().iter().any(|context| context.event_sequence == ack.seq && context.worker_id.is_some()));
            eprintln!(
                "{}",
                serde_json::json!({"bead": "asupersync-bi2462.95", "case": "cancel_ack", "workers": workers, "sharded": sharded, "task": format!("{:?}", owner.task_id()), "ack": ack.seq, "complete": complete.seq})
            );
            drop(sender);
            drop(owner);
            assert!(runtime.shutdown_timeout(WATCHDOG));
        }
    }
}

#[test]
fn disabled_capture_emits_no_scheduler_observations() {
    let runtime = RuntimeBuilder::new().worker_threads(2).build().unwrap();
    join_native(
        &runtime,
        runtime.handle().spawn(async {
            asupersync::runtime::yield_now().await;
        }),
    );
    assert!(runtime.schedule_capture_snapshot().is_none());
    assert!(!runtime.trace_snapshot().iter().any(|event| matches!(
        event.kind,
        TraceEventKind::Schedule
            | TraceEventKind::Poll
            | TraceEventKind::Wake
            | TraceEventKind::Yield
            | TraceEventKind::CancelAck
    )));
    assert!(runtime.shutdown_timeout(WATCHDOG));
}

#[test]
fn native_capture_overflow_is_bounded_and_rejected() {
    let runtime = RuntimeBuilder::new()
        .worker_threads(1)
        .capture_schedules(true)
        .build()
        .unwrap();
    join_native(
        &runtime,
        runtime.handle().spawn(async {
            for _ in 0..2_048 {
                asupersync::runtime::yield_now().await;
            }
        }),
    );
    let snapshot = runtime.schedule_capture_snapshot().unwrap();
    assert!(snapshot.dropped_events() > 0);
    assert!(snapshot.events().len() <= snapshot.capacity());
    assert!(snapshot.contexts().len() <= snapshot.capacity());
    assert!(matches!(
        snapshot.production_schedule(),
        Err(ScheduleCaptureError::Truncated { .. })
    ));
    eprintln!(
        "{}",
        serde_json::json!({"bead": "asupersync-bi2462.95", "case": "overflow", "total": snapshot.total_events(), "dropped": snapshot.dropped_events(), "capacity": snapshot.capacity()})
    );
    assert!(runtime.shutdown_timeout(WATCHDOG));
}
