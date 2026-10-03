//! Behavioral proof that the stock permits are runtime-visible obligations
//! (br-asupersync-gap-permits-as-obligations-cv5sqe).
//!
//! The README promises that a reserved `mpsc` / `oneshot` / `broadcast`
//! permit and a `Semaphore` permit are tracked obligations: the lab's
//! obligation-leak oracle names a leaked permit by kind, and futurelock
//! detection fires for a task that stops being polled while holding one.
//! Every scenario below goes through the public reserve/acquire API from
//! inside a real lab task, so the mailbox admission, the runtime's
//! completion-time leak sweep, and the oracle report are all exercised on
//! the same path user code takes. Nothing is created by hand with
//! `RuntimeState::create_obligation`.
//!
//! Leak scenarios `mem::forget` the permit: that is the one way a permit can
//! outlive its holder without resolving. Ordinary drop is a supported abort
//! path (asserted by the controls), not a leak.
//!
//! The `native_*` tests repeat the core claims on the production runtime,
//! current-thread and two workers, through `Runtime::diagnostics()`. A
//! reserved permit is a live obligation of its kind, held by the reserving
//! task in its region. Send or drop resolves it. A forgotten permit becomes
//! a confirmed leak once its holder finishes. A task cancelled while it
//! holds a permit, or ended by its region's close, aborts the permit
//! instead of leaking it.
//!
//! No-claim: `Mutex` / `RwLock` guards are not obligations and are not
//! covered here. Futurelock detection is a lab facility and is proved only
//! on the lab.

use std::future::Future;
use std::sync::{Arc, Mutex};

use asupersync::Cx;
use asupersync::channel::{broadcast, mpsc, oneshot};
use asupersync::cx::ChildRegionSpec;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::observability::{Diagnostics, ObligationLeak};
use asupersync::record::ObligationKind;
use asupersync::runtime::config::ObligationLeakResponse;
use asupersync::runtime::{Runtime, RuntimeBuilder, yield_now};
use asupersync::sync::Semaphore;
use asupersync::trace::{TraceData, TraceEvent, TraceEventKind};
use asupersync::types::{Budget, CancelReason, TaskId};

fn lab(seed: u64) -> LabRuntime {
    LabRuntime::new(LabConfig::new(seed).max_steps(10_000).panic_on_leak(false))
}

/// Spawn `body` as a real lab task under a fresh root region and run the lab
/// to quiescence. The join handle is kept alive until the run finishes so the
/// task cannot be torn down early.
fn run_task<F>(lab: &mut LabRuntime, body: F) -> TaskId
where
    F: Future<Output = ()> + Send + 'static,
{
    let root = lab.state.create_root_region(Budget::INFINITE);
    let (task, handle) = lab
        .state
        .create_task(root, Budget::INFINITE, body)
        .expect("create lab task");
    lab.scheduler.lock().schedule(task, 0);
    lab.run_until_quiescent();
    drop(handle);
    task
}

fn mailbox_stats(
    lab: &LabRuntime,
) -> asupersync::runtime::obligation_mailbox::ObligationMailboxStats {
    lab.state
        .obligation_gateway()
        .expect("lab runtime installs an obligation gateway")
        .mailbox()
        .stats()
}

fn leak_events(lab: &LabRuntime) -> Vec<TraceEvent> {
    lab.trace()
        .snapshot()
        .into_iter()
        .filter(|event| event.kind == TraceEventKind::ObligationLeak)
        .collect()
}

fn futurelock_events(lab: &LabRuntime) -> Vec<TraceEvent> {
    lab.trace()
        .snapshot()
        .into_iter()
        .filter(|event| event.kind == TraceEventKind::FuturelockDetected)
        .collect()
}

/// Shared assertions for "one permit of `kind` was forgotten by `holder`".
fn assert_single_leak(lab: &mut LabRuntime, holder: TaskId, kind: ObligationKind) {
    let stats = mailbox_stats(lab);
    assert_eq!(stats.reserved, 1, "one reservation was posted: {stats:?}");
    assert_eq!(stats.committed, 0, "{stats:?}");
    assert_eq!(stats.aborted, 0, "{stats:?}");
    assert_eq!(
        stats.leaked, 0,
        "the token was forgotten, never dropped, so the mailbox saw no Leak post: {stats:?}"
    );

    assert_eq!(
        lab.state.leak_count(),
        1,
        "the runtime's completion-time sweep diagnosed the forgotten permit"
    );
    assert_eq!(
        lab.state.pending_obligation_count(),
        0,
        "a diagnosed leak is no longer pending"
    );

    let events = leak_events(lab);
    assert_eq!(
        events.len(),
        1,
        "exactly one ObligationLeak event: {events:?}"
    );
    match &events[0].data {
        TraceData::Obligation {
            task,
            kind: leaked_kind,
            ..
        } => {
            assert_eq!(*task, holder, "the leak names the forgetting task");
            assert_eq!(*leaked_kind, kind, "the leak names the permit kind");
        }
        other => panic!("ObligationLeak carries obligation data, got {other:?}"),
    }

    let report = lab.report();
    let entry = report
        .oracle_report
        .entry("obligation_leak")
        .expect("obligation leak oracle is registered");
    assert!(
        !entry.passed,
        "the obligation-leak oracle must report the forgotten permit: {entry:?}"
    );
    let violation = entry
        .violation
        .as_deref()
        .expect("a failed oracle entry carries its violation text");
    let expected_kind = format!("{kind:?}");
    assert!(
        violation.contains(&expected_kind),
        "the oracle names the permit kind {expected_kind}: {violation}"
    );
    assert!(
        report
            .invariant_violations
            .iter()
            .any(|line| line == "oracle:obligation_leak"),
        "the aggregate report mirrors the failed oracle: {:?}",
        report.invariant_violations
    );
}

/// Shared assertions for "every permit was sent, aborted or dropped".
fn assert_clean(lab: &mut LabRuntime, reserved: u64, committed: u64, aborted: u64) {
    let stats = mailbox_stats(lab);
    assert_eq!(stats.reserved, reserved, "{stats:?}");
    assert_eq!(stats.committed, committed, "{stats:?}");
    assert_eq!(stats.aborted, aborted, "{stats:?}");
    assert_eq!(stats.leaked, 0, "{stats:?}");
    assert_eq!(stats.refused, 0, "{stats:?}");
    assert_eq!(lab.state.leak_count(), 0);
    assert_eq!(lab.state.pending_obligation_count(), 0);
    assert!(leak_events(lab).is_empty());
    assert!(lab.is_quiescent());

    let report = lab.report();
    let entry = report
        .oracle_report
        .entry("obligation_leak")
        .expect("obligation leak oracle is registered");
    assert!(entry.passed, "no leak may be reported: {entry:?}");
}

// ---------------------------------------------------------------------------
// mpsc
// ---------------------------------------------------------------------------

#[test]
fn mpsc_permit_forgotten_at_task_completion_is_a_send_permit_leak() {
    let mut lab = lab(0xC5_0001);
    let holder = run_task(&mut lab, async {
        let cx = Cx::current().expect("lab task installs a current Cx");
        let (tx, _rx) = mpsc::channel::<u8>(1);
        let permit = tx.reserve(&cx).await.expect("reserve capacity");
        // The leak: the permit escapes without send() or abort().
        std::mem::forget(permit);
    });
    assert_single_leak(&mut lab, holder, ObligationKind::SendPermit);
}

#[test]
fn mpsc_permit_sent_or_dropped_is_resolved_not_leaked() {
    let mut lab = lab(0xC5_0002);
    run_task(&mut lab, async {
        let cx = Cx::current().expect("lab task installs a current Cx");
        let (tx, mut rx) = mpsc::channel::<u8>(2);

        // Commit path.
        let permit = tx.reserve(&cx).await.expect("reserve capacity");
        permit.try_send(7).expect("receiver is live");
        assert_eq!(rx.recv(&cx).await.expect("receive"), 7);

        // Explicit abort path.
        let permit = tx.reserve(&cx).await.expect("reserve capacity");
        permit.abort();

        // Implicit abort path: an unsent permit is dropped.
        {
            let _permit = tx.reserve(&cx).await.expect("reserve capacity");
        }
    });
    assert_clean(&mut lab, 3, 1, 2);
}

/// The one-call `Sender::send` commits its internal permit in the same poll
/// that reserves it, so it posts no obligation at all; an explicit
/// `reserve` still posts its reservation and commit. Both paths deliver
/// (br-asupersync-issue65-criticisms-kpmoy5.1.16).
#[test]
fn mpsc_one_call_send_posts_no_transient_obligation_but_reserve_still_does() {
    let mut lab = lab(0xC5_0010);
    run_task(&mut lab, async {
        let cx = Cx::current().expect("lab task installs a current Cx");
        let (tx, mut rx) = mpsc::channel::<u8>(4);

        tx.send(&cx, 1).await.expect("one-call send");
        tx.send(&cx, 2).await.expect("one-call send");
        let permit = tx.reserve(&cx).await.expect("reserve capacity");
        permit.try_send(3).expect("receiver is live");

        for expected in 1..=3 {
            assert_eq!(rx.recv(&cx).await.expect("receive"), expected);
        }
    });
    assert_clean(&mut lab, 1, 1, 0);
}

// ---------------------------------------------------------------------------
// oneshot
// ---------------------------------------------------------------------------

#[test]
fn oneshot_permit_forgotten_at_task_completion_is_a_send_permit_leak() {
    let mut lab = lab(0xC5_0003);
    let holder = run_task(&mut lab, async {
        let cx = Cx::current().expect("lab task installs a current Cx");
        let (tx, _rx) = oneshot::channel::<u8>();
        let permit = tx.reserve(&cx).expect("reserve oneshot");
        std::mem::forget(permit);
    });
    assert_single_leak(&mut lab, holder, ObligationKind::SendPermit);
}

#[test]
fn oneshot_permit_sent_or_dropped_is_resolved_not_leaked() {
    let mut lab = lab(0xC5_0004);
    run_task(&mut lab, async {
        let cx = Cx::current().expect("lab task installs a current Cx");

        let (tx, mut rx) = oneshot::channel::<u8>();
        let permit = tx.reserve(&cx).expect("reserve oneshot");
        permit.send(9).expect("receiver is live");
        assert_eq!(rx.try_recv().ok(), Some(9));

        let (tx, _rx) = oneshot::channel::<u8>();
        let permit = tx.reserve(&cx).expect("reserve oneshot");
        permit.abort();

        let (tx, _rx) = oneshot::channel::<u8>();
        {
            let _permit = tx.reserve(&cx).expect("reserve oneshot");
        }
    });
    assert_clean(&mut lab, 3, 1, 2);
}

// ---------------------------------------------------------------------------
// broadcast
// ---------------------------------------------------------------------------

#[test]
fn broadcast_permit_forgotten_at_task_completion_is_a_send_permit_leak() {
    let mut lab = lab(0xC5_0005);
    let holder = run_task(&mut lab, async {
        let cx = Cx::current().expect("lab task installs a current Cx");
        let (tx, _rx) = broadcast::channel::<u8>(4);
        let permit = tx.reserve(&cx).expect("reserve broadcast");
        std::mem::forget(permit);
    });
    assert_single_leak(&mut lab, holder, ObligationKind::SendPermit);
}

#[test]
fn broadcast_permit_sent_or_dropped_is_resolved_not_leaked() {
    let mut lab = lab(0xC5_0006);
    run_task(&mut lab, async {
        let cx = Cx::current().expect("lab task installs a current Cx");
        let (tx, mut rx) = broadcast::channel::<u8>(4);

        let permit = tx.reserve(&cx).expect("reserve broadcast");
        assert_eq!(permit.send(3), 1, "one live receiver");
        assert_eq!(rx.try_recv().ok(), Some(3));

        {
            let _permit = tx.reserve(&cx).expect("reserve broadcast");
        }
    });
    assert_clean(&mut lab, 2, 1, 1);
}

// ---------------------------------------------------------------------------
// semaphore
// ---------------------------------------------------------------------------

#[test]
fn semaphore_permit_forgotten_at_task_completion_is_a_semaphore_permit_leak() {
    let mut lab = lab(0xC5_0007);
    let holder = run_task(&mut lab, async {
        let cx = Cx::current().expect("lab task installs a current Cx");
        let sem = Semaphore::new(1);
        let permit = sem.acquire(&cx, 1).await.expect("acquire permit");
        std::mem::forget(permit);
    });
    assert_single_leak(&mut lab, holder, ObligationKind::SemaphorePermit);
}

/// Drive a task that acquires one semaphore permit, optionally releases it,
/// then parks forever. Returns the task id and the futurelock events the lab
/// emitted after `steps` further steps.
fn park_holding_semaphore(
    seed: u64,
    release_before_parking: bool,
    steps: usize,
) -> (TaskId, Vec<TraceEvent>) {
    let mut lab = LabRuntime::new(
        LabConfig::new(seed)
            .max_steps(10_000)
            .panic_on_leak(false)
            .futurelock_max_idle_steps(3)
            .panic_on_futurelock(false),
    );
    let root = lab.state.create_root_region(Budget::INFINITE);
    let (task, _handle) = lab
        .state
        .create_task(root, Budget::INFINITE, async move {
            let cx = Cx::current().expect("lab task installs a current Cx");
            let sem = Semaphore::new(1);
            let permit = sem.acquire(&cx, 1).await.expect("acquire permit");
            if release_before_parking {
                drop(permit);
                std::future::pending::<()>().await;
            } else {
                // Hold the permit while never being polled again.
                std::future::pending::<()>().await;
                drop(permit);
            }
        })
        .expect("create lab task");
    lab.scheduler.lock().schedule(task, 0);
    for _ in 0..steps {
        lab.step_for_test();
    }
    let events = futurelock_events(&lab);
    (task, events)
}

#[test]
fn semaphore_permit_held_by_an_unpolled_task_triggers_futurelock() {
    let (task, events) = park_holding_semaphore(0xC5_0008, false, 8);
    let event = events
        .first()
        .expect("a parked task holding a semaphore permit is a futurelock");
    match &event.data {
        TraceData::Futurelock {
            task: reported,
            idle_steps,
            held,
            ..
        } => {
            assert_eq!(*reported, task, "the futurelock names the holder");
            assert!(
                *idle_steps > 3,
                "idle for longer than the threshold: {idle_steps}"
            );
            assert!(
                held.iter()
                    .any(|(_, kind)| *kind == ObligationKind::SemaphorePermit),
                "the futurelock names the semaphore permit: {held:?}"
            );
        }
        other => panic!("FuturelockDetected carries futurelock data, got {other:?}"),
    }
}

#[test]
fn semaphore_permit_released_before_parking_is_not_a_futurelock() {
    let (_task, events) = park_holding_semaphore(0xC5_0009, true, 8);
    assert!(
        events.is_empty(),
        "a parked task holding nothing is not a futurelock: {events:?}"
    );
}

// ---------------------------------------------------------------------------
// Native runtime: the same obligations on the production runtime
// ---------------------------------------------------------------------------

const MAX_YIELDS: usize = 10_000;

/// The production runtime in both shapes. A leak is logged rather than
/// panicking, so the leak scenarios can observe it.
fn native_runtimes() -> Vec<(&'static str, Runtime)> {
    [
        ("current-thread", RuntimeBuilder::current_thread()),
        (
            "two-workers",
            RuntimeBuilder::multi_thread().worker_threads(2),
        ),
    ]
    .into_iter()
    .map(|(flavor, builder)| {
        let runtime = builder
            .obligation_leak_response(ObligationLeakResponse::Log)
            .build()
            .expect("build native runtime");
        (flavor, runtime)
    })
    .collect()
}

/// Yield to the runtime until `probe` holds; the mailbox resolves
/// obligations asynchronously, so a state change needs a few polls to show.
async fn yield_until(mut probe: impl FnMut() -> bool) -> bool {
    for _ in 0..MAX_YIELDS {
        if probe() {
            return true;
        }
        yield_now().await;
    }
    probe()
}

/// Live (reserved, holder still running) obligations of `kind` held by `holder`.
fn live(diagnostics: &Diagnostics, holder: TaskId, kind: ObligationKind) -> Vec<ObligationLeak> {
    let kind = format!("{kind:?}");
    diagnostics
        .find_leaked_obligations()
        .into_iter()
        .filter(|record| record.holder_task == Some(holder) && record.obligation_type == kind)
        .collect()
}

/// Confirmed leaks of `kind` held by `holder`.
fn confirmed(
    diagnostics: &Diagnostics,
    holder: TaskId,
    kind: ObligationKind,
) -> Vec<ObligationLeak> {
    let kind = format!("{kind:?}");
    diagnostics
        .find_confirmed_obligation_leaks()
        .into_iter()
        .filter(|record| record.holder_task == Some(holder) && record.obligation_type == kind)
        .collect()
}

#[test]
fn native_permits_are_live_obligations_until_sent_or_dropped() {
    for (flavor, runtime) in native_runtimes() {
        let diagnostics = runtime.diagnostics();
        runtime.block_on(async {
            let cx = Cx::current().expect("block_on installs a root Cx");
            let holder = cx.task_id();
            let (tx, mut rx) = mpsc::channel::<u8>(2);

            // mpsc: reserve, observe the live SendPermit, then commit it.
            let permit = tx.reserve(&cx).await.expect("reserve capacity");
            assert!(
                yield_until(|| live(&diagnostics, holder, ObligationKind::SendPermit).len() == 1)
                    .await,
                "{flavor}: a reserved permit is one live SendPermit obligation"
            );
            let record = live(&diagnostics, holder, ObligationKind::SendPermit)
                .pop()
                .expect("live SendPermit record");
            assert_eq!(record.region_id, cx.region_id(), "{flavor}: held in the holder's region");
            permit.try_send(7).expect("receiver is live");
            assert_eq!(rx.recv(&cx).await.expect("receive"), 7);
            assert!(
                yield_until(|| live(&diagnostics, holder, ObligationKind::SendPermit).is_empty())
                    .await,
                "{flavor}: a sent permit resolves its obligation"
            );

            // mpsc: an unsent permit dropped aborts its obligation.
            let permit = tx.reserve(&cx).await.expect("reserve capacity");
            assert!(
                yield_until(|| live(&diagnostics, holder, ObligationKind::SendPermit).len() == 1)
                    .await,
                "{flavor}: the second reservation is live"
            );
            drop(permit);
            assert!(
                yield_until(|| live(&diagnostics, holder, ObligationKind::SendPermit).is_empty())
                    .await,
                "{flavor}: a dropped permit aborts its obligation"
            );

            // Semaphore: an acquired permit is live until released.
            let semaphore = Semaphore::new(1);
            let permit = semaphore.acquire(&cx, 1).await.expect("acquire permit");
            assert!(
                yield_until(|| {
                    live(&diagnostics, holder, ObligationKind::SemaphorePermit).len() == 1
                })
                .await,
                "{flavor}: an acquired permit is one live SemaphorePermit obligation"
            );
            drop(permit);
            assert!(
                yield_until(|| {
                    live(&diagnostics, holder, ObligationKind::SemaphorePermit).is_empty()
                })
                .await,
                "{flavor}: a released permit discharges its obligation"
            );

            assert!(
                confirmed(&diagnostics, holder, ObligationKind::SendPermit).is_empty()
                    && confirmed(&diagnostics, holder, ObligationKind::SemaphorePermit).is_empty(),
                "{flavor}: resolved permits are never confirmed leaks"
            );
        });
    }
}

#[test]
fn native_permits_forgotten_by_a_finished_task_are_confirmed_leaks_of_their_kind() {
    for (flavor, runtime) in native_runtimes() {
        let diagnostics = runtime.diagnostics();
        runtime.block_on(async {
            let cx = Cx::current().expect("block_on installs a root Cx");
            let mut handle = cx
                .spawn(|task_cx| async move {
                    let (tx, _rx) = mpsc::channel::<u8>(1);
                    let permit = tx.reserve(&task_cx).await.expect("reserve capacity");
                    let semaphore = Semaphore::new(1);
                    let held = semaphore.acquire(&task_cx, 1).await.expect("acquire permit");
                    // The leaks: both permits escape without being resolved.
                    std::mem::forget(permit);
                    std::mem::forget(held);
                    (task_cx.task_id(), task_cx.region_id())
                })
                .expect("spawn leaking task");
            let (holder, region) = handle.join(&cx).await.expect("join leaking task");

            assert!(
                yield_until(|| {
                    confirmed(&diagnostics, holder, ObligationKind::SendPermit).len() == 1
                        && confirmed(&diagnostics, holder, ObligationKind::SemaphorePermit).len()
                            == 1
                })
                .await,
                "{flavor}: each forgotten permit is one confirmed leak of its kind; confirmed = {:?}",
                diagnostics.find_confirmed_obligation_leaks()
            );
            for kind in [ObligationKind::SendPermit, ObligationKind::SemaphorePermit] {
                let leak = confirmed(&diagnostics, holder, kind)
                    .pop()
                    .expect("confirmed leak record");
                assert_eq!(leak.region_id, region, "{flavor}: {kind:?} leak names the holder's region");
            }
        });
    }
}

#[test]
fn native_task_cancelled_while_holding_a_permit_aborts_it_without_a_leak() {
    for (flavor, runtime) in native_runtimes() {
        let diagnostics = runtime.diagnostics();
        runtime.block_on(async {
            let cx = Cx::current().expect("block_on installs a root Cx");
            let holder_slot = Arc::new(Mutex::new(None));
            let slot = Arc::clone(&holder_slot);
            let handle = cx
                .spawn(move |task_cx| async move {
                    let (tx, _rx) = mpsc::channel::<u8>(1);
                    let _permit = tx.reserve(&task_cx).await.expect("reserve capacity");
                    *slot.lock().expect("holder slot") = Some(task_cx.task_id());
                    // Hold the permit until cancellation is observed; returning
                    // then drops it on the cancellation path.
                    while task_cx.checkpoint().is_ok() {
                        yield_now().await;
                    }
                })
                .expect("spawn holding task");

            assert!(
                yield_until(|| holder_slot.lock().expect("holder slot").is_some()).await,
                "{flavor}: the task reserved its permit"
            );
            let holder = holder_slot.lock().expect("holder slot").expect("holder id");
            assert!(
                yield_until(|| live(&diagnostics, holder, ObligationKind::SendPermit).len() == 1)
                    .await,
                "{flavor}: the permit is live before cancellation (state witness)"
            );

            handle.abort_with_reason(CancelReason::user("cv5sqe native cancel"));
            assert!(
                yield_until(|| live(&diagnostics, holder, ObligationKind::SendPermit).is_empty())
                    .await,
                "{flavor}: cancellation aborts the held permit's obligation"
            );
            assert!(
                confirmed(&diagnostics, holder, ObligationKind::SendPermit).is_empty(),
                "{flavor}: a permit dropped on the cancellation path is not a leak; confirmed = {:?}",
                diagnostics.find_confirmed_obligation_leaks()
            );
        });
    }
}

#[test]
fn native_region_close_aborts_a_permit_held_by_a_task_inside_it() {
    for (flavor, runtime) in native_runtimes() {
        let diagnostics = runtime.diagnostics();
        runtime.block_on(async {
            let cx = Cx::current().expect("block_on installs a root Cx");
            let child = cx
                .open_child_region(ChildRegionSpec::inherit())
                .await
                .expect("open a child region");
            let child_region = child.region_id();
            let holder_slot = Arc::new(Mutex::new(None));
            let slot = Arc::clone(&holder_slot);
            // The task waits on a cancel-aware receive that nothing will
            // satisfy, so only the region's close can end it. The sender stays
            // alive until after the close.
            let (_gate_tx, mut gate_rx) = mpsc::channel::<u8>(1);
            let _handle = child
                .cx()
                .spawn(move |task_cx| async move {
                    let (tx, _rx) = mpsc::channel::<u8>(1);
                    let _permit = tx.reserve(&task_cx).await.expect("reserve capacity");
                    *slot.lock().expect("holder slot") = Some(task_cx.task_id());
                    let _ = gate_rx.recv(&task_cx).await;
                })
                .expect("spawn inside the child region");

            assert!(
                yield_until(|| holder_slot.lock().expect("holder slot").is_some()).await,
                "{flavor}: the task reserved its permit"
            );
            let holder = holder_slot.lock().expect("holder slot").expect("holder id");
            assert!(
                yield_until(|| live(&diagnostics, holder, ObligationKind::SendPermit).len() == 1)
                    .await,
                "{flavor}: the permit is live before the close (state witness)"
            );
            let record = live(&diagnostics, holder, ObligationKind::SendPermit)
                .pop()
                .expect("live SendPermit record");
            assert_eq!(
                record.region_id, child_region,
                "{flavor}: the permit is held in the child region"
            );

            child.close().await.expect("close the child region");
            assert!(
                yield_until(|| live(&diagnostics, holder, ObligationKind::SendPermit).is_empty())
                    .await,
                "{flavor}: closing the region aborts the held permit's obligation"
            );
            assert!(
                confirmed(&diagnostics, holder, ObligationKind::SendPermit).is_empty(),
                "{flavor}: a permit dropped when its region closes is not a leak; confirmed = {:?}",
                diagnostics.find_confirmed_obligation_leaks()
            );
        });
    }
}
