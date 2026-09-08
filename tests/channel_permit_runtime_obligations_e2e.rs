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
//! No-claim: `Mutex` / `RwLock` guards are not obligations and are not
//! covered here; neither is the production three-lane scheduler (the
//! completion sweep is shared, but this file runs the deterministic lab).

use std::future::Future;

use asupersync::Cx;
use asupersync::channel::{broadcast, mpsc, oneshot};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::record::ObligationKind;
use asupersync::sync::Semaphore;
use asupersync::trace::{TraceData, TraceEvent, TraceEventKind};
use asupersync::types::{Budget, TaskId};

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
