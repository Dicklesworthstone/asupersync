//! Real native parked-task capture, checked projection, and strict Lab replay.
#![cfg(not(target_arch = "wasm32"))]

use asupersync::Cx;
use asupersync::channel::mpsc as ring;
use asupersync::channel::oneshot;
use asupersync::lab::runtime::ReplayDivergenceReason;
use asupersync::lab::runtime::production_strict::{
    StrictProductionReplayError, StrictProductionReplayLimits, StrictProductionReplayReport,
    StrictProductionReplayTermination,
};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::trace::{
    CompactTaskId, ProductionSchedule, ProjectionError, ProjectionOptions, ScheduleCaptureError,
    ScheduleCaptureSnapshot, TraceData, TraceEvent, TraceEventKind,
};
use asupersync::types::{Budget, CancelKind, Severity, TaskId};
use std::collections::{BTreeMap, BTreeSet};
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

/// Each `join_native` call runs one `block_on`, whose caller-polled root is
/// registered as a task. The capture must report exactly those tasks, none of
/// which a worker ever polled, and leave them out of the projection.
fn assert_caller_tasks_left_out(snapshot: &ScheduleCaptureSnapshot, block_on_calls: usize) {
    let callers = snapshot.caller_tasks();
    assert_eq!(
        callers.len(),
        block_on_calls,
        "one caller task per block_on"
    );
    for caller in callers {
        let spawned = snapshot.events().iter().any(|event| {
            event.kind == TraceEventKind::Spawn
                && matches!(event.data, TraceData::Task { task, .. } if task == *caller)
        });
        let polled = snapshot.events().iter().any(|event| {
            event.kind == TraceEventKind::Poll
                && matches!(event.data, TraceData::Task { task, .. } if task == *caller)
        });
        assert!(
            spawned,
            "caller task {caller:?} has its Spawn in the capture"
        );
        assert!(!polled, "no worker polled caller task {caller:?}");
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
            assert_caller_tasks_left_out(&snapshot, values.len());
            assert_eq!(
                snapshot.terminal_outcomes(),
                &[
                    (first.min(second), Severity::Ok),
                    (first.max(second), Severity::Ok)
                ]
            );
            let schedule = snapshot.production_schedule().unwrap();
            assert!(schedule.carries_outcomes());
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

/// br-asupersync-bi2462.8: the capture keeps each task's terminal outcome, and
/// a strict replay in which a task ends differently is refused. Natively both
/// tasks return their input. In the Lab reconstruction the second task panics
/// on it, which a state task records as Panicked. Task order, spawn count and
/// quiescence all still match, so only the outcome comparison can catch it.
#[test]
fn native_capture_outcomes_refuse_terminal_outcome_drift() {
    let runtime = RuntimeBuilder::new()
        .worker_threads(1)
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
        joins.push(
            runtime
                .handle()
                .spawn(receive_input(receiver, Some(parked_tx.clone()), None)),
        );
    }
    drop(parked_tx);
    parked_rx.recv_timeout(WATCHDOG).expect("first task parked");
    parked_rx
        .recv_timeout(WATCHDOG)
        .expect("second task parked");
    for (sender, value) in inputs {
        sender.send_blocking(value).unwrap();
    }
    let native: Vec<_> = joins
        .into_iter()
        .map(|join| join_native(&runtime, join))
        .collect();
    assert_eq!(native, values);

    let snapshot = completed_capture(&runtime);
    let outcomes: Vec<_> = snapshot
        .terminal_outcomes()
        .iter()
        .map(|(_, outcome)| *outcome)
        .collect();
    assert_eq!(outcomes, [Severity::Ok, Severity::Ok]);
    let schedule = snapshot.production_schedule().unwrap();
    assert!(schedule.carries_outcomes());
    let by_ordinal: Vec<_> = schedule
        .spawn_order()
        .iter()
        .map(|task| schedule.captured_outcome(*task))
        .collect();
    assert_eq!(by_ordinal, [Some(Severity::Ok), Some(Severity::Ok)]);

    let mut lab = LabRuntime::new(LabConfig::new(95).max_steps(128));
    let region = lab.state.create_root_region(Budget::INFINITE);
    let mut lab_joins = Vec::new();
    for value in values {
        let (sender, receiver) = oneshot::channel();
        let (task, join) = lab
            .state
            .create_task(region, Budget::INFINITE, async move {
                let received = receive_input(receiver, None, Some((sender, value))).await;
                assert_ne!(received, 29, "the reconstructed task fails on its input");
                received
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
            "bead": "asupersync-bi2462.8",
            "case": "terminal_outcome_drift",
            "captured": format!("{by_ordinal:?}"),
            "replay": format!("{report:?}"),
        })
    );
    assert_eq!(report.replay.steps_matched, report.replay.steps_total);
    assert_eq!(
        report.termination,
        StrictProductionReplayTermination::OutcomeMismatch {
            ordinal: 1,
            expected: Severity::Ok,
            observed: Some(Severity::Panicked),
        }
    );
    assert!(!report.passed());
    assert!(
        lab_joins
            .iter()
            .all(asupersync::runtime::TaskHandle::is_finished)
    );
    assert!(runtime.shutdown_timeout(WATCHDOG));
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

const PANIC_WITNESS: &str = "6hewgp handle-spawned panic";

fn panic_on_purpose() -> u32 {
    panic!("{PANIC_WITNESS}")
}

/// Resolves to `Err(payload)` when awaiting `join` re-raises its task's panic.
async fn catch_join<F: Future>(join: F) -> std::thread::Result<F::Output> {
    let mut join = std::pin::pin!(join);
    poll_fn(|cx| {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| join.as_mut().poll(cx))) {
            Ok(poll) => poll.map(Ok),
            Err(payload) => std::task::Poll::Ready(Err(payload)),
        }
    })
    .await
}

/// asupersync-6hewgp: a task spawned through `RuntimeHandle` whose future
/// panics re-raises the payload on its join handle and is recorded Panicked,
/// as `Cx::spawn` and state tasks are. The record used to say Ok, so metrics,
/// the root region's close outcome and this capture all reported a success.
/// Covers both spawn admission modes and the owner-thread local lane.
#[test]
fn native_handle_spawned_panic_is_recorded_panicked() {
    use asupersync::runtime::JoinError;
    use asupersync::runtime::config::SpawnAdmissionMode;
    // Every variant is observed before one comparison, so a failure names
    // each spawn path that still records the wrong outcome.
    let mut observed = Vec::new();
    for mode in [SpawnAdmissionMode::Direct, SpawnAdmissionMode::Mailbox] {
        let runtime = RuntimeBuilder::new()
            .worker_threads(2)
            .spawn_admission(mode)
            .capture_schedules(true)
            .build()
            .unwrap();
        let ok = runtime.handle().spawn_checked(async {
            asupersync::runtime::yield_now().await;
            7_u32
        });
        let panicking = runtime.handle().spawn_checked(async {
            asupersync::runtime::yield_now().await;
            panic_on_purpose()
        });
        assert_eq!(join_native(&runtime, ok).ok(), Some(7), "{mode:?}");
        match join_native(&runtime, panicking) {
            Err(JoinError::Panicked(payload)) => {
                assert_eq!(payload.message(), PANIC_WITNESS, "{mode:?}");
            }
            other => panic!("{mode:?}: the panicking task joined as {other:?}"),
        }
        let snapshot = completed_capture(&runtime);
        let mut outcomes: Vec<_> = snapshot
            .terminal_outcomes()
            .iter()
            .map(|(_, outcome)| *outcome)
            .collect();
        outcomes.sort();
        observed.push((format!("{mode:?}"), outcomes));
        assert!(runtime.shutdown_timeout(WATCHDOG));
    }

    let runtime = RuntimeBuilder::current_thread()
        .capture_schedules(true)
        .build()
        .unwrap();
    let handle = runtime.handle();
    let joined = runtime.block_on(async move {
        let join = handle.spawn_local(async {
            asupersync::runtime::yield_now().await;
            panic_on_purpose()
        });
        catch_join(join).await
    });
    let payload = joined.expect_err("the local join re-raises its task's panic");
    assert_eq!(
        payload.downcast_ref::<String>().map(String::as_str),
        Some(PANIC_WITNESS)
    );
    let snapshot = completed_capture(&runtime);
    // The current-thread capture also lists an Ok task besides the local
    // one, so only the panicking task's outcome is compared here.
    let outcomes: Vec<_> = snapshot
        .terminal_outcomes()
        .iter()
        .map(|(_, outcome)| *outcome)
        .filter(|outcome| *outcome != Severity::Ok)
        .collect();
    observed.push(("local lane".to_string(), outcomes));
    assert!(runtime.shutdown_timeout(WATCHDOG));

    let expected = [
        ("Direct", vec![Severity::Ok, Severity::Panicked]),
        ("Mailbox", vec![Severity::Ok, Severity::Panicked]),
        ("local lane", vec![Severity::Panicked]),
    ]
    .map(|(label, outcomes)| (label.to_string(), outcomes));
    assert_eq!(observed, expected);
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

/// Stages in the token ring, the hops its single token travels, and the
/// external value that starts it.
const RING_STAGES: usize = 4;
const RING_HOPS: u64 = 12;
const RING_KICK: u32 = 7;

/// A ring token: (hop, payload).
type Token = (u64, u64);

/// What each ring stage received in the Lab, indexed by spawn order.
type RingValues = Vec<Option<Vec<Token>>>;

/// Receives the next ring token, publishing `parked` the first time the
/// receive returns Pending: a real parked-state witness, not a sleep.
async fn next_token(
    cx: &Cx,
    inbox: &mut ring::Receiver<Token>,
    parked: &mut Option<mpsc::Sender<TaskId>>,
) -> Option<Token> {
    let mut receive = std::pin::pin!(inbox.recv(cx));
    poll_fn(|task| {
        let result = receive.as_mut().poll(task);
        if result.is_pending()
            && let Some(parked) = parked.take()
        {
            parked
                .send(cx.task_id())
                .expect("publish real Pending witness");
        }
        result
    })
    .await
    .ok()
}

/// One stage of the token ring. Stage 0 takes the first token from an
/// external oneshot kick. Every stage records each token it receives, yields
/// once, and forwards the next token until the final hop; then it drops its
/// sender, so the other stages see the ring close one after another. Only
/// the token holder is runnable, so the poll order depends on the data, and
/// no two polls can race on the same channel, even on two workers.
async fn ring_stage(
    stage: u64,
    kick: Option<(oneshot::Receiver<u32>, Option<(oneshot::Sender<u32>, u32)>)>,
    mut inbox: ring::Receiver<Token>,
    next: ring::Sender<Token>,
    parked: Option<mpsc::Sender<TaskId>>,
) -> Vec<Token> {
    let cx = Cx::current().expect("actual admitted task context");
    let mut parked = parked;
    let mut token = match kick {
        Some((receiver, replay_input)) => Some((
            0,
            u64::from(receive_input(receiver, parked.take(), replay_input).await),
        )),
        None => next_token(&cx, &mut inbox, &mut parked).await,
    };
    let mut seen = Vec::new();
    while let Some((hop, payload)) = token {
        seen.push((hop, payload));
        if hop == RING_HOPS {
            break;
        }
        asupersync::runtime::yield_now().await;
        next.send(&cx, (hop + 1, payload.wrapping_mul(31).wrapping_add(stage)))
            .await
            .expect("ring successor is parked on its inbox");
        token = next_token(&cx, &mut inbox, &mut parked).await;
    }
    drop(next);
    seen
}

/// One capacity-1 channel per stage: stage `i` reads inbox `i` and forwards
/// into inbox `i + 1`, wrapping around.
fn ring_links() -> Vec<(ring::Receiver<Token>, ring::Sender<Token>)> {
    let (mut senders, receivers): (Vec<_>, Vec<_>) =
        (0..RING_STAGES).map(|_| ring::channel::<Token>(1)).unzip();
    senders.rotate_left(1);
    receivers.into_iter().zip(senders).collect()
}

/// The tokens each stage must receive, computed without any runtime.
fn expected_ring_tokens(kick: u32) -> Vec<Vec<Token>> {
    let mut seen = vec![Vec::new(); RING_STAGES];
    let mut payload = u64::from(kick);
    for (hop, stage) in (0..=RING_HOPS).zip((0..RING_STAGES).cycle()) {
        seen[stage].push((hop, payload));
        payload = payload.wrapping_mul(31).wrapping_add(stage as u64);
    }
    seen
}

/// Runs the ring on a native runtime with schedule capture on. Every stage
/// genuinely parks before the main thread sends the kick.
fn capture_ring(workers: usize, sharded: bool) -> (ScheduleCaptureSnapshot, Vec<Vec<Token>>) {
    let runtime = RuntimeBuilder::new()
        .worker_threads(workers)
        .with_sharded_state(sharded)
        .capture_schedules(true)
        .build()
        .unwrap();
    let (parked_tx, parked_rx) = mpsc::channel();
    let (kick_tx, kick_rx) = oneshot::channel();
    let mut kick_rx = Some(kick_rx);
    let joins: Vec<_> = ring_links()
        .into_iter()
        .enumerate()
        .map(|(stage, (inbox, next))| {
            let kick = (stage == 0).then(|| (kick_rx.take().expect("one kick receiver"), None));
            runtime.handle().spawn(ring_stage(
                stage as u64,
                kick,
                inbox,
                next,
                Some(parked_tx.clone()),
            ))
        })
        .collect();
    drop(parked_tx);
    let parked: BTreeSet<_> = (0..RING_STAGES)
        .map(|_| {
            parked_rx
                .recv_timeout(WATCHDOG)
                .expect("ring stage parked before the kick")
        })
        .collect();
    assert_eq!(parked.len(), RING_STAGES);
    kick_tx.send_blocking(RING_KICK).expect("kick the ring");
    let native: Vec<_> = joins
        .into_iter()
        .map(|join| join_native(&runtime, join))
        .collect();
    let snapshot = completed_capture(&runtime);
    assert_caller_tasks_left_out(&snapshot, RING_STAGES);
    assert!(runtime.shutdown_timeout(WATCHDOG));
    (snapshot, native)
}

/// Rebuilds the ring in a fresh Lab, with the same stage bodies in the same
/// spawn order, and drives it strictly by `schedule`. Stage 0 injects the
/// kick when it first parks, as the native main thread did once every stage
/// had parked. The schedule still decides when stage 0 runs again.
/// `extra_task` admits one task that the capture never saw, after the ring.
fn replay_ring(
    schedule: &ProductionSchedule,
    kick: u32,
    extra_task: bool,
) -> (
    Result<StrictProductionReplayReport, StrictProductionReplayError>,
    RingValues,
    Vec<bool>,
) {
    let mut lab = LabRuntime::new(LabConfig::new(0x80B3).max_steps(4_096));
    let region = lab.state.create_root_region(Budget::INFINITE);
    let observed = Arc::new(Mutex::new(vec![None; RING_STAGES]));
    let (kick_tx, kick_rx) = oneshot::channel();
    let mut kick_input = Some((kick_rx, Some((kick_tx, kick))));
    let mut joins = Vec::new();
    for (stage, (inbox, next)) in ring_links().into_iter().enumerate() {
        let stage_kick = if stage == 0 { kick_input.take() } else { None };
        let observed = Arc::clone(&observed);
        let (task, join) = lab
            .state
            .create_task(region, Budget::INFINITE, async move {
                let seen = ring_stage(stage as u64, stage_kick, inbox, next, None).await;
                observed.lock().unwrap()[stage] = Some(seen);
            })
            .unwrap();
        lab.scheduler.lock().schedule(task, 0);
        joins.push(join);
    }
    if extra_task {
        let (task, join) = lab
            .state
            .create_task(region, Budget::INFINITE, async {})
            .unwrap();
        lab.scheduler.lock().schedule(task, 0);
        joins.push(join);
    }
    let report = lab.run_production_schedule_strict(
        schedule,
        StrictProductionReplayLimits::new(4_096, 8, 1_024, 4_096, 8),
    );
    let finished = joins
        .iter()
        .map(asupersync::runtime::TaskHandle::is_finished)
        .collect();
    let values = observed.lock().unwrap().clone();
    // The observations above are the replay boundary. Then leave replay mode
    // and let ordinary scheduling finish what the replay retained, so no case
    // abandons live work.
    let _ = lab.discard_production_replay();
    lab.run_until_quiescent();
    assert!(
        lab.is_quiescent(),
        "the Lab drains what the replay retained"
    );
    (report, values, finished)
}

fn spawned_tasks(events: &[TraceEvent]) -> Vec<TaskId> {
    events
        .iter()
        .filter_map(|event| match (&event.kind, &event.data) {
            (TraceEventKind::Spawn, TraceData::Task { task, .. }) => Some(*task),
            _ => None,
        })
        .collect()
}

fn poll_positions(events: &[TraceEvent], task: Option<TaskId>) -> Vec<usize> {
    events
        .iter()
        .enumerate()
        .filter(|(_, event)| {
            event.kind == TraceEventKind::Poll
                && matches!(event.data, TraceData::Task { task: polled, .. }
                    if task.is_none_or(|task| task == polled))
        })
        .map(|(position, _)| position)
        .collect()
}

/// Asserts that a refused or stopped replay ran no stage to completion.
fn assert_no_stage_completed(case: &str, values: &RingValues, finished: &[bool]) {
    assert!(
        values.iter().all(Option::is_none),
        "{case}: no stage may complete, got {values:?}"
    );
    assert!(
        finished.iter().all(|done| !*done),
        "{case}: no task may finish, got {finished:?}"
    );
}

/// br-asupersync-bi2462.8: a real multi-task capture from the production
/// scheduler replays in the Lab with the recorded poll order, the same
/// channel values in every task, and every task finished. Four stages pass
/// one token around a ring of capacity-1 channels, so each stage's polls
/// depend on its neighbours' progress. Runs on one and two workers, with
/// and without sharded state.
#[test]
fn native_ring_capture_replays_poll_order_and_channel_values() {
    let expected = expected_ring_tokens(RING_KICK);
    for workers in [1, 2] {
        for sharded in [false, true] {
            let (snapshot, native) = capture_ring(workers, sharded);
            assert_eq!(native, expected, "native stages received the ring tokens");
            assert_eq!(snapshot.dropped_events(), 0);
            assert_eq!(snapshot.worker_count(), workers);
            let schedule = snapshot.production_schedule().unwrap();
            assert_eq!(schedule.summary().spawned, RING_STAGES);
            // Every stage parks once before the kick, and each forwarded hop
            // takes two polls: receive then yield, forward then park.
            assert!(schedule.summary().steps >= RING_STAGES + 2 * RING_HOPS as usize);
            let (report, lab, finished) = replay_ring(&schedule, RING_KICK, false);
            let report = report.expect("the real capture is admitted");
            eprintln!(
                "{}",
                serde_json::json!({
                    "bead": "asupersync-bi2462.8",
                    "case": "ring_replay",
                    "workers": workers,
                    "sharded": sharded,
                    "events": snapshot.total_events(),
                    "steps": schedule.summary().steps,
                    "replay": format!("{report:?}"),
                    "native": format!("{native:?}"),
                    "lab": format!("{lab:?}"),
                })
            );
            assert_eq!(
                report.termination,
                StrictProductionReplayTermination::Matched
            );
            assert!(report.passed());
            assert_eq!(report.observed_spawns, RING_STAGES);
            assert_eq!(report.replay.steps_matched, schedule.summary().steps);
            assert!(finished.iter().all(|done| *done), "every Lab task finished");
            let lab: Vec<_> = lab
                .into_iter()
                .map(|seen| seen.expect("Lab stage completed"))
                .collect();
            assert_eq!(lab, native, "Lab replay reproduces every stage's values");
        }
    }
}

/// br-asupersync-bi2462.8: copies of a real capture, each with one defect,
/// are refused before the Lab runs work the capture did not record. Only
/// the lost-interior-poll copy runs any recorded polls, and it stops at the
/// first recorded choice it cannot honour.
#[test]
fn real_ring_capture_copies_with_defects_are_refused() {
    let (snapshot, native) = capture_ring(1, false);
    // The scheduled observations, as production_schedule() projects them:
    // the block_on callers' own events are left out.
    let callers = snapshot.caller_tasks();
    let events: Vec<TraceEvent> = snapshot
        .events()
        .iter()
        .filter(
            |event| !matches!(event.data, TraceData::Task { task, .. } if callers.contains(&task)),
        )
        .cloned()
        .collect();
    let spawns = spawned_tasks(&events);
    assert_eq!(spawns.len(), RING_STAGES);
    let log = |case: &str, detail: String| {
        eprintln!(
            "{}",
            serde_json::json!({"bead": "asupersync-bi2462.8", "case": case, "detail": detail})
        );
    };

    // Control: the unmodified copy replays completely.
    let schedule = ProductionSchedule::from_runtime_trace(&events).unwrap();
    let (report, values, finished) = replay_ring(&schedule, RING_KICK, false);
    let report = report.expect("the unmodified copy is admitted");
    log("unmodified", format!("{report:?}"));
    assert!(report.passed());
    assert!(finished.iter().all(|done| *done));
    assert_eq!(
        values.into_iter().map(Option::unwrap).collect::<Vec<_>>(),
        native
    );

    // Stage 2's first poll after it parked: the one that takes its first token.
    let stage2_polls = poll_positions(&events, Some(spawns[2]));
    let taking = stage2_polls[1];

    // Missing birth: stage 0's spawn is gone. Strict projection refuses it;
    // admitted as an orphan, the strict driver still refuses it.
    let mut unborn = events.clone();
    let birth = unborn
        .iter()
        .position(|event| event.kind == TraceEventKind::Spawn)
        .unwrap();
    unborn.remove(birth);
    let projected = ProductionSchedule::from_runtime_trace(&unborn);
    log("missing_birth", format!("{:?}", projected.as_ref().err()));
    assert!(matches!(
        projected,
        Err(ProjectionError::MissingSpawn { task, .. }) if task == CompactTaskId::from(spawns[0])
    ));
    let orphaned = ProductionSchedule::from_runtime_trace_with(
        &unborn,
        ProjectionOptions {
            allow_orphans: true,
        },
    )
    .unwrap();
    let (report, values, finished) = replay_ring(&orphaned, RING_KICK, false);
    log("orphan_birth", format!("{report:?}"));
    assert!(matches!(
        report,
        Err(StrictProductionReplayError::OrphanSpawns { count: 1 })
    ));
    assert_no_stage_completed("orphan_birth", &values, &finished);

    // Altered generation: one poll names a task identity that was never born.
    let mut altered = events.clone();
    if let TraceData::Task { task, .. } = &mut altered[taking].data {
        let mut id = serde_json::to_value(*task).unwrap();
        id["generation"] = serde_json::json!(id["generation"].as_u64().unwrap() + 1);
        *task = serde_json::from_value(id).unwrap();
    }
    let projected = ProductionSchedule::from_runtime_trace(&altered);
    log(
        "altered_generation",
        format!("{:?}", projected.as_ref().err()),
    );
    assert!(matches!(
        projected,
        Err(ProjectionError::MissingSpawn { seq, kind: TraceEventKind::Poll, .. })
            if seq == events[taking].seq
    ));

    // Duplicated observation: the same poll recorded twice.
    let mut duplicated = events.clone();
    duplicated.insert(taking + 1, events[taking].clone());
    let (report, values, finished) = replay_ring(
        &ProductionSchedule::from_runtime_trace(&duplicated).unwrap(),
        RING_KICK,
        false,
    );
    log("duplicated_poll", format!("{report:?}"));
    let seq = events[taking].seq;
    assert!(matches!(
        report,
        Err(StrictProductionReplayError::SourceOrder { previous, next })
            if previous == seq && next == seq
    ));
    assert_no_stage_completed("duplicated_poll", &values, &finished);

    // Reordered observations: that poll swapped with the event after it.
    let mut reordered = events.clone();
    reordered.swap(taking, taking + 1);
    let (report, values, finished) = replay_ring(
        &ProductionSchedule::from_runtime_trace(&reordered).unwrap(),
        RING_KICK,
        false,
    );
    log("reordered_events", format!("{report:?}"));
    assert!(matches!(
        report,
        Err(StrictProductionReplayError::SourceOrder { previous, next })
            if previous == events[taking + 1].seq && next == seq
    ));
    assert_no_stage_completed("reordered_events", &values, &finished);

    // Interior poll loss: that poll is missing. The Lab spends stage 2's next
    // recorded poll on the receive, and then stage 3, the recorded next
    // task, cannot run without an unrecorded poll of stage 2. The replay
    // stops there.
    let mut lost = events.clone();
    lost.remove(taking);
    let (report, values, finished) = replay_ring(
        &ProductionSchedule::from_runtime_trace(&lost).unwrap(),
        RING_KICK,
        false,
    );
    let report = report.expect("a copy with a lost poll is admitted");
    log("interior_poll_loss", format!("{report:?}"));
    assert_eq!(
        report.termination,
        StrictProductionReplayTermination::Diverged
    );
    let divergence = report
        .replay
        .divergence
        .as_ref()
        .expect("the divergence is named");
    assert_eq!(divergence.expected_ordinal, 3);
    assert!(matches!(
        divergence.reason,
        ReplayDivergenceReason::TaskNotRunnable { .. }
    ));
    assert!(!report.passed());
    assert_no_stage_completed("interior_poll_loss", &values, &finished);

    // Suffix loss after every birth: the copy ends halfway through the polls.
    // The Lab consumes exactly the retained choices and reports the live
    // remainder instead of scheduling it.
    let all_polls = poll_positions(&events, None);
    let suffix_lost = events[..all_polls[all_polls.len() / 2]].to_vec();
    assert_eq!(spawned_tasks(&suffix_lost).len(), RING_STAGES);
    let truncated = ProductionSchedule::from_runtime_trace(&suffix_lost).unwrap();
    let (report, values, finished) = replay_ring(&truncated, RING_KICK, false);
    let report = report.expect("a truncated copy is admitted");
    log("suffix_loss", format!("{report:?}"));
    assert_eq!(
        report.termination,
        StrictProductionReplayTermination::SourceExhausted
    );
    assert_eq!(report.replay.steps_matched, truncated.summary().steps);
    assert!(report.replay.divergence.is_none());
    assert!(!report.passed());
    assert_no_stage_completed("suffix_loss", &values, &finished);

    // Extra replay work: the Lab admits a task that the capture never saw.
    // The strict driver refuses it before its first step.
    let (report, values, finished) = replay_ring(&schedule, RING_KICK, true);
    let report = report.expect("the schedule is admitted");
    log("extra_task", format!("{report:?}"));
    assert_eq!(
        report.termination,
        StrictProductionReplayTermination::SpawnCountMismatch {
            expected: RING_STAGES,
            observed: RING_STAGES + 1,
        }
    );
    assert_eq!(report.work_units, 0);
    assert_no_stage_completed("extra_task", &values, &finished);

    // Value drift is outside the strict receipt. The projection records task
    // order and terminal outcomes, not the values tasks return. The same
    // schedule drives a ring kicked with a different value to a Matched
    // receipt, because every stage still ends Ok, so comparing the values,
    // as the tests above do, is the harness's oracle for values. Outcome
    // drift is refused by the driver itself; see
    // native_capture_outcomes_refuse_terminal_outcome_drift.
    let (report, values, _) = replay_ring(&schedule, RING_KICK + 1, false);
    let report = report.expect("the schedule is admitted");
    log("outcome_drift", format!("{report:?}"));
    assert!(report.passed());
    let drifted: Vec<_> = values.into_iter().map(Option::unwrap).collect();
    assert_ne!(drifted, native);
    assert_eq!(drifted, expected_ring_tokens(RING_KICK + 1));
}
