//! The API-v2 on-ramp, exercised as one lane.
//!
//! Beads: asupersync-dx-core-api-v2-u1z5hn.11 and .12
//!
//! The individual v2 pieces have their own unit tests. What was missing is a
//! lane that runs the surface a *new user* actually touches, in the same
//! combination the on-ramp examples put it in: the entry attribute macros, a
//! `Cx` handed to the body, `Cx::spawn` plus `join`, `JoinSet` fan-out, and the
//! deterministic lab test. `scripts/run_api_v2_e2e.sh` runs this lane after it
//! runs the example programs, so a break in the journey is attributable to
//! either the examples or this surface rather than to "something in the epic".
//!
//! The on-ramp tests assert that the macro supplies a working `Cx`, spawned
//! work is joinable, and fan-out aggregates. The lifecycle tests additionally
//! inspect admission accounting and terminal runtime invariants.
//!
//! The lifecycle matrix below adds nine lab and nine native cells:
//! before/during/after close x root/child/grandchild. Native cells use actual
//! workers and an observed parked task to hold the close protocol open. Lab
//! cells use `RuntimeState::cancel_request`, never a hand-placed region state.
//! Admission denial must resolve the returned handle as `ParentCancelled`
//! without invoking the factory; both executors must finish with no work or
//! obligations left.
//! Replay: `RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync
//! --test api_v2_integration --features test-internals -- --nocapture`.
//!
//! API-v2 symbol coverage (review alongside changes to the epic's surface):
//! - `Cx::spawn`, `spawn_in`, `TaskHandle::{join,try_join,abort}`, mailbox
//!   counters, child region identity/close: lifecycle cells and property test.
//! - `spawn_local`, `spawn_local_in`, `spawn_blocking`, `spawn_blocking_in`,
//!   `spawn_registered_in`: local/blocking ownership and budget test.
//! - `JoinSet::{new,in_cx,spawn,spawn_local,len,is_empty,try_join_next,join_next,
//!   join_all,cancel_all,summary}`: fan-out, pending-join, budget and local tests.
//!   Explicit-reason cancellation and abort-on-drop also have the dedicated
//!   `join_set_cancel_drain_lab_proof` lane.
//! - `main`, `test`, `lab_test`, `scope!`, `join!`, `join_all!`, `race!`, `select!`
//!   and the prelude: entry and composed-macro tests.
//! - `PureCaps`, `WebCaps`, `restrict`, ambient restriction: runtime test here
//!   and both errors in `compile_fail/spawn_without_capability.rs`; child
//!   region and spawned-task derivation must retain the parent's mask.
//!   `set_current`, `set_current_restricted`, `current`, and `with_current`
//!   retain restrictions across reinstallation, factories, and resumed polls.
//! - Bounded/unbounded MPSC send/recv/recv_many, bulk semaphore acquisition,
//!   `for_each_concurrent`, `try_for_each_concurrent`, `partition`,
//!   `try_buffered`, `collect_into`, stream telemetry: channel/stream journey.
//! - `Cx::{budget_for_timeout,remaining_budget}`, absolute/relative Budget
//!   constructors: local/blocking test; all `SpawnError` codes remain covered
//!   by the runtime/state unit tests and `error_code_registry_contract` lane.
//! Design names that were not shipped (`JoinSet::in_child_region`,
//! `Budget::for_timeout`, `fold_into`) are not invented aliases here; current
//! public equivalents are child `Cx` + `in_cx`, `budget_for_timeout`, and
//! `collect_into`. This suite does not close the whole API-v2 product epic.

#![allow(missing_docs)]
#![allow(clippy::unused_async)]

use asupersync::lab::LabRuntime;
use asupersync::lab_test;
use asupersync::prelude::*;

#[cfg(feature = "test-internals")]
mod lifecycle {
    use asupersync::cx::{ChildRegion, ChildRegionSpec, Cx};
    use asupersync::lab::{LabConfig, LabRuntime};
    use asupersync::record::region::RegionState;
    use asupersync::runtime::{JoinError, RootDrainOutcome, Runtime, RuntimeBuilder, TaskHandle};
    use asupersync::types::{Budget, CancelKind, CancelReason, RegionId};
    use std::future::Future;
    use std::pin::{Pin, pin};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};
    use std::time::{Duration, Instant};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Phase {
        Before,
        During,
        After,
    }

    fn drive_native<F: Future>(future: F) -> F::Output {
        let mut future = pin!(future);
        let mut context = Context::from_waker(Waker::noop());
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
                return value;
            }
            assert!(
                Instant::now() < deadline,
                "native lifecycle operation stalled"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn assert_denied<T: std::fmt::Debug>(result: Result<T, JoinError>) {
        match result {
            Err(JoinError::Cancelled(reason)) => {
                assert_eq!(reason.kind, CancelKind::ParentCancelled)
            }
            other => panic!("closed-region admission must be ParentCancelled: {other:?}"),
        }
    }

    #[derive(Default)]
    struct Gate {
        released: bool,
        parked: bool,
        waker: Option<Waker>,
    }

    struct ParkedTask {
        cx: Cx,
        gate: Arc<Mutex<Gate>>,
    }

    struct HeldTask {
        handle: TaskHandle<Option<CancelKind>>,
        gate: Arc<Mutex<Gate>>,
    }

    impl Future for ParkedTask {
        type Output = Option<CancelKind>;

        fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
            // Acknowledge cancellation but keep cleanup parked until the
            // controller releases it. Close cannot finish by dropping us.
            let _ = self.cx.checkpoint();
            let mut gate = self.gate.lock().unwrap();
            gate.parked = true;
            gate.waker = Some(context.waker().clone());
            if gate.released {
                Poll::Ready(self.cx.cancel_reason().map(|reason| reason.kind))
            } else {
                Poll::Pending
            }
        }
    }

    fn release(gate: &Mutex<Gate>) {
        let waker = {
            let mut gate = gate.lock().unwrap();
            gate.released = true;
            gate.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn native_cell(depth: usize, phase: Phase) {
        let runtime = RuntimeBuilder::new().worker_threads(2).build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let observer = Cx::for_testing();
        let mut cx = root.clone();
        let mut children: Vec<ChildRegion> = Vec::new();
        for _ in 0..depth {
            let child = drive_native(cx.open_child_region(ChildRegionSpec::inherit())).unwrap();
            assert_ne!(child.region_id(), cx.region_id());
            cx = child.cx().clone();
            children.push(child);
        }
        let region = cx.region_id();
        assert_eq!(
            native_region_state(&runtime, region),
            Some(RegionState::Open)
        );
        let mut held =
            (phase != Phase::Before).then(|| hold_native_close(&runtime, &cx, children.last()));
        if phase == Phase::After {
            finish_native_close(&runtime, &observer, &mut held, &mut children);
            assert!(matches!(
                native_region_state(&runtime, region),
                None | Some(RegionState::Closed)
            ));
        }

        let factories = Arc::new(AtomicUsize::new(0));
        let called = Arc::clone(&factories);
        let mut handle = cx
            .spawn(move |child| {
                called.fetch_add(1, Ordering::SeqCst);
                async move { (child.region_id(), 42_u32) }
            })
            .expect("live gateway returns a handle even when admission is denied");
        let result = drive_native(handle.join(&observer));
        if phase == Phase::Before {
            assert_eq!(result.unwrap(), (region, 42));
            assert_eq!(factories.load(Ordering::SeqCst), 1);
        } else {
            assert_denied(result);
            assert_eq!(
                factories.load(Ordering::SeqCst),
                0,
                "denied factory must never run"
            );
        }
        assert_eq!(
            Arc::strong_count(&factories),
            1,
            "factory captures released"
        );
        finish_native_close(&runtime, &observer, &mut held, &mut children);
        assert!(
            runtime.is_quiescent(),
            "native cell depth={depth} phase={phase:?}"
        );
        assert!(
            runtime
                .task_inspector(Default::default())
                .list_active_tasks()
                .is_empty()
        );
        assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    }

    fn native_region_state(runtime: &Runtime, region: RegionId) -> Option<RegionState> {
        runtime
            .diagnostics()
            .explain_region_open(region)
            .region_state
    }

    fn hold_native_close(runtime: &Runtime, cx: &Cx, child: Option<&ChildRegion>) -> HeldTask {
        let gate = Arc::new(Mutex::new(Gate::default()));
        let child_gate = Arc::clone(&gate);
        let handle = cx
            .spawn(move |cx| ParkedTask {
                cx,
                gate: child_gate,
            })
            .unwrap();
        drive_native(std::future::poll_fn(|_| {
            if gate.lock().unwrap().parked {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }));
        assert!(!runtime.is_quiescent(), "parked task is owned before close");
        if let Some(child) = child {
            child
                .cancel(CancelReason::user("api-v2 lifecycle close"))
                .unwrap();
        } else {
            assert_eq!(
                runtime.drain_root_region(Duration::ZERO),
                RootDrainOutcome::TimedOut
            );
        }
        drive_native(std::future::poll_fn(|_| {
            match native_region_state(runtime, cx.region_id()) {
                Some(RegionState::Closing | RegionState::Draining) => Poll::Ready(()),
                other => {
                    assert_eq!(
                        other,
                        Some(RegionState::Open),
                        "cleanup must hold the region open"
                    );
                    Poll::Pending
                }
            }
        }));
        HeldTask { handle, gate }
    }

    fn finish_native_close(
        runtime: &Runtime,
        observer: &Cx,
        held: &mut Option<HeldTask>,
        children: &mut Vec<ChildRegion>,
    ) {
        if let Some(HeldTask { mut handle, gate }) = held.take() {
            release(&gate);
            let reason =
                drive_native(handle.join(observer)).expect("acknowledged cleanup result retained");
            let expected = if children.is_empty() {
                CancelKind::Shutdown
            } else {
                CancelKind::User
            };
            assert_eq!(reason, Some(expected));
        }
        while let Some(child) = children.pop() {
            drive_native(child.close()).unwrap();
        }
        assert_eq!(
            runtime.drain_root_region(Duration::from_secs(5)),
            RootDrainOutcome::Quiescent
        );
    }

    fn lab_with_cx(depth: usize, seed: u64) -> (LabRuntime, Cx, Vec<RegionId>) {
        let mut lab = LabRuntime::new(LabConfig::new(seed));
        let mut regions = vec![lab.state.create_root_region(Budget::INFINITE)];
        for _ in 0..depth {
            let child = lab
                .state
                .create_child_region(*regions.last().unwrap(), Budget::INFINITE)
                .unwrap();
            regions.push(child);
        }
        let region = *regions.last().unwrap();
        let (task, mut boot) = lab
            .state
            .create_task(region, Budget::INFINITE, async {})
            .unwrap();
        let cx = lab.state.task(task).unwrap().cx.as_ref().unwrap().clone();
        lab.scheduler
            .lock()
            .schedule(task, Budget::INFINITE.priority);
        lab.run_until_quiescent();
        assert_eq!(boot.try_join().unwrap(), Some(()));
        (lab, cx, regions)
    }

    fn assert_lab_clean(lab: &mut LabRuntime, regions: &[RegionId]) {
        for region in regions.iter().rev() {
            lab_begin_close(lab, *region);
            lab.state.advance_region_state(*region);
        }
        let report = lab.run_until_quiescent_with_report();
        assert!(report.quiescent, "{report:?}");
        assert!(
            report.oracle_report.all_passed(),
            "{:?}",
            report.oracle_report
        );
        assert!(
            report.invariant_violations.is_empty(),
            "{:?}",
            report.invariant_violations
        );
        assert_eq!(lab.state.live_task_count(), 0);
        assert_eq!(lab.state.pending_obligation_count(), 0);
        assert_eq!(lab.state.leak_count(), 0);
        assert!(lab.spawn_mailbox().is_empty());
        assert!(
            regions
                .iter()
                .all(|region| lab.state.region_was_closed(*region))
        );
    }

    fn lab_begin_close(lab: &mut LabRuntime, region: RegionId) {
        if lab.state.region(region).is_none() {
            return;
        }
        let reason = CancelReason::new(CancelKind::ParentCancelled);
        let effects = lab.state.cancel_request(region, &reason, None);
        let (tasks, wakes) = effects.into_parts();
        for (task, priority) in tasks {
            lab.scheduler.lock().schedule_cancel(task, priority);
        }
        wakes.dispatch();
    }

    fn lab_cell(depth: usize, phase: Phase) {
        let (mut lab, cx, regions) = lab_with_cx(depth, 0xA211);
        let region = cx.region_id();
        // A pending publication is real work: its credit must prevent close
        // from completing until admission (or producer drop) resolves it.
        let close_hold = (phase == Phase::During)
            .then(|| lab.state.region(region).unwrap().reserve_pending_spawn());
        if phase != Phase::Before {
            lab_begin_close(&mut lab, region);
        }
        if phase == Phase::During {
            assert!(matches!(
                lab.state.region(region).unwrap().state(),
                RegionState::Closing | RegionState::Draining
            ));
        }
        if phase == Phase::After {
            lab.state.advance_region_state(region);
            assert!(lab.state.region_was_closed(region));
        }
        let factories = Arc::new(AtomicUsize::new(0));
        let called = Arc::clone(&factories);
        let mailbox = lab.spawn_mailbox();
        let enqueued = mailbox.total_enqueued();
        let mut handle = cx
            .spawn(move |child| {
                called.fetch_add(1, Ordering::SeqCst);
                async move { (child.region_id(), 42_u32) }
            })
            .unwrap();
        assert_eq!(mailbox.total_enqueued(), enqueued + 1);
        assert_eq!(
            mailbox.len(),
            1,
            "the real mailbox contains the pending spawn"
        );
        drop(close_hold);
        lab.run_until_quiescent();
        let result = handle.try_join();
        if phase == Phase::Before {
            assert_eq!(result.unwrap(), Some((region, 42)));
            assert_eq!(factories.load(Ordering::SeqCst), 1);
        } else {
            assert_denied(result);
            assert_eq!(factories.load(Ordering::SeqCst), 0);
        }
        assert_eq!(mailbox.total_dequeued(), mailbox.total_enqueued());
        assert_eq!(
            Arc::strong_count(&factories),
            1,
            "factory captures released"
        );
        assert_lab_clean(&mut lab, &regions);
    }

    struct CapturedDrop(Arc<AtomicUsize>);

    impl Drop for CapturedDrop {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn mailbox_spawn_cancel_close_interleavings_256_cases() {
        use proptest::prelude::*;
        use proptest::test_runner::{Config, RngSeed, TestRunner};

        const SEED: u64 = 0x0A21_1256;
        let config = Config {
            cases: 256,
            rng_seed: RngSeed::Fixed(SEED),
            source_file: Some(file!()),
            test_name: Some("mailbox_spawn_cancel_close_interleavings_256_cases"),
            ..Config::default()
        };
        let mut runner = TestRunner::new(config);
        let result = runner.run(
            &(
                0_usize..3,
                any::<u64>(),
                proptest::collection::vec(0_u8..5, 1..40),
            ),
            |(depth, lab_seed, operations)| {
                let (mut lab, cx, regions) = lab_with_cx(depth, lab_seed);
                let dropped = Arc::new(AtomicUsize::new(0));
                let mut handles = Vec::new();
                for operation in std::iter::once(0).chain(operations) {
                    match operation {
                        0 | 1 => {
                            let id = handles.len();
                            let captured = CapturedDrop(Arc::clone(&dropped));
                            handles.push(
                                cx.spawn(move |child| async move {
                                    let _captured = captured;
                                    asupersync::runtime::yield_now().await;
                                    match child.checkpoint() {
                                        Ok(()) => Ok(id),
                                        Err(_) => Err(child.cancel_reason().unwrap().kind),
                                    }
                                })
                                .unwrap(),
                            );
                        }
                        2 => lab.step_for_test(),
                        3 => {
                            if let Some(handle) = handles.last() {
                                handle.abort();
                            }
                        }
                        4 => {
                            lab_begin_close(&mut lab, cx.region_id());
                        }
                        _ => unreachable!(),
                    }
                }
                lab.run_until_quiescent();
                for (id, handle) in handles.iter_mut().enumerate() {
                    match handle.try_join() {
                        Ok(Some(Ok(value))) => prop_assert_eq!(value, id),
                        Ok(Some(Err(kind))) => prop_assert!(matches!(
                            kind,
                            CancelKind::User | CancelKind::ParentCancelled
                        )),
                        Err(JoinError::Cancelled(reason)) => {
                            prop_assert!(matches!(
                                reason.kind,
                                CancelKind::User | CancelKind::ParentCancelled
                            ));
                        }
                        other => prop_assert!(
                            false,
                            "seed={} id={} unresolved/unexpected: {:?}",
                            lab_seed,
                            id,
                            other
                        ),
                    }
                }
                prop_assert_eq!(dropped.load(Ordering::SeqCst), handles.len());
                assert_lab_clean(&mut lab, &regions);
                Ok(())
            },
        );
        assert!(
            result.is_ok(),
            "seed={SEED}; RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --test api_v2_integration --features test-internals mailbox_spawn_cancel_close_interleavings_256_cases -- --nocapture; shrunk failure={result:?}"
        );
    }

    #[test]
    fn legacy_scope_spawn_preserves_ambient_capabilities() {
        use asupersync::cx::cap::CapSet;
        use asupersync::runtime::SpawnError;

        let (mut lab, full, regions) = lab_with_cx(0, 0xA21A);
        let restricted = {
            let _guard = full
                .restrict::<CapSet<true, false, false, false, false>>()
                .set_current_restricted();
            Cx::current().unwrap()
        };
        let expected = restricted.capabilities();
        let scope = restricted.scope();
        let mut handle = scope
            .spawn_registered(&mut lab.state, &restricted, |child| {
                let factory = Cx::current().unwrap().capabilities();
                async move {
                    asupersync::runtime::yield_now().await;
                    (
                        child.capabilities(),
                        factory,
                        Cx::current().unwrap().capabilities(),
                    )
                }
            })
            .unwrap();
        lab.scheduler
            .lock()
            .schedule(handle.task_id(), Budget::INFINITE.priority);
        lab.run_until_quiescent();
        assert_eq!(
            handle.try_join().unwrap(),
            Some((expected, expected, expected))
        );

        let pure = {
            let _guard = full
                .restrict::<asupersync::cx::wrappers::PureCaps>()
                .set_current_restricted();
            Cx::current().unwrap()
        };
        assert!(matches!(
            scope.spawn_registered(&mut lab.state, &pure, |_| async { 1 }),
            Err(SpawnError::RuntimeUnavailable)
        ));
        assert_lab_clean(&mut lab, &regions);
    }

    macro_rules! cells {
        ($runner:ident; $($name:ident => ($depth:literal, $phase:ident)),+ $(,)?) => {
            $(#[test] fn $name() { $runner($depth, Phase::$phase); })+
        };
    }

    cells!(lab_cell;
        lab_root_before_close => (0, Before), lab_root_during_close => (0, During), lab_root_after_close => (0, After),
        lab_child_before_close => (1, Before), lab_child_during_close => (1, During), lab_child_after_close => (1, After),
        lab_grandchild_before_close => (2, Before), lab_grandchild_during_close => (2, During), lab_grandchild_after_close => (2, After),
    );
    cells!(native_cell;
        native_root_before_close => (0, Before), native_root_during_close => (0, During), native_root_after_close => (0, After),
        native_child_before_close => (1, Before), native_child_during_close => (1, During), native_child_after_close => (1, After),
        native_grandchild_before_close => (2, Before), native_grandchild_during_close => (2, During), native_grandchild_after_close => (2, After),
    );
}

/// The `hello.rs` shape: the attribute macro alone must produce a usable
/// runtime, with no explicit builder and no ambient-state threading.
#[asupersync::test]
async fn entry_macro_without_cx_runs_on_the_production_runtime() {
    assert!(
        Cx::current().is_some(),
        "the entry macro must install an ambient Cx even when the body does \
         not ask for one"
    );
}

/// The `Cx`-taking form: the macro must hand the body a context whose
/// capabilities actually work, which is what every on-ramp snippet assumes.
#[asupersync::test]
async fn entry_macro_supplies_a_working_cx() -> Result<(), asupersync::Error> {
    let cx = Cx::current().expect("entry macro installs an ambient Cx");
    cx.checkpoint()?;
    assert_eq!(
        cx.region_id(),
        Cx::current().expect("ambient Cx").region_id(),
        "the injected Cx and the ambient Cx must be the same region"
    );
    Ok(())
}

/// `Cx::spawn` + `TaskHandle::join` is the two-line concurrency on-ramp: no
/// `&mut RuntimeState`, no detached handle, and the child's value comes back.
#[asupersync::test]
async fn cx_spawn_joins_a_child_and_returns_its_value() {
    let cx = Cx::current().expect("entry macro installs an ambient Cx");
    let mut handle = cx
        .spawn(|task_cx| async move {
            task_cx.checkpoint().expect("child checkpoint");
            41_u32 + 1
        })
        .expect("spawn child");
    let joined = handle.join(&cx).await.expect("child joins");
    assert_eq!(
        joined, 42,
        "the spawned child's value must reach the parent"
    );
}

/// The `spawn_fanout.rs` shape: dynamic fan-out collected through `JoinSet`,
/// with every member's outcome observed rather than dropped.
#[asupersync::test]
async fn join_set_fans_out_and_aggregates_every_member() {
    let cx = Cx::current().expect("entry macro installs an ambient Cx");
    let mut set = JoinSet::in_cx(&cx);
    for i in 0..10_u32 {
        set.spawn(&cx, move |_| async move { Ok::<_, ()>(i) })
            .expect("spawn member");
    }
    let outcomes = set.join_all(&cx).await;
    assert_eq!(outcomes.len(), 10, "every spawned member must be collected");
    let total: u32 = outcomes
        .into_iter()
        .map(|outcome| outcome.expect("member ok"))
        .sum();
    assert_eq!(total, 45, "0..10 sums to 45");
}

/// The `deterministic_test.rs` shape, in its native habitat: `#[lab_test]`
/// gives a seeded `LabRuntime` with no harness boilerplate.
#[lab_test]
fn lab_test_macro_supplies_a_seeded_runtime(lab: &mut LabRuntime) {
    assert_eq!(
        lab.config().seed,
        0,
        "the bare form must use the documented default seed"
    );
}

/// Same-seed replay is the property the on-ramp advertises, so the lane asserts
/// it directly rather than trusting the example's own assertion.
#[test]
fn same_seed_replays_the_same_execution() {
    fn run(seed: u64) -> u32 {
        let (total, report) = asupersync::lab::run_async_under_lab(seed, |cx| async move {
            let mut set = JoinSet::in_cx(&cx);
            for i in 0..8_u32 {
                set.spawn(&cx, move |_| async move { Ok::<_, ()>(i) })
                    .expect("spawn member");
            }
            set.join_all(&cx)
                .await
                .into_iter()
                .fold(0, |sum, outcome| sum + outcome.expect("member ok"))
        });
        assert!(report.quiescent, "lab run must reach quiescence");
        assert!(
            report.invariant_violations.is_empty(),
            "no invariant may be violated: {:?}",
            report.invariant_violations
        );
        total
    }

    let first = run(7);
    assert_eq!(first, run(7), "same seed must produce the same result");
    assert_eq!(first, 28, "0..8 sums to 28");
}

#[asupersync::test]
async fn pure_and_web_caps_preserve_identity_and_refuse_ambient_spawn() {
    use asupersync::cx::wrappers::{PureCaps, WebCaps};
    use asupersync::runtime::{SpawnError, TaskHandle};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn denied<T>(result: Result<TaskHandle<T>, SpawnError>) {
        assert!(matches!(result, Err(SpawnError::RuntimeUnavailable)));
    }

    fn assert_spawn_family_denied(cx: &Cx) {
        use asupersync::cx::{ChildRegionError, ChildRegionSpec};
        use std::future::Future;
        use std::task::{Context, Poll, Waker};

        let calls = Arc::new(AtomicUsize::new(0));
        let factory = || {
            let calls = Arc::clone(&calls);
            move |_| {
                calls.fetch_add(1, Ordering::SeqCst);
                std::future::ready(1)
            }
        };
        let blocking = || {
            let calls = Arc::clone(&calls);
            move |_| calls.fetch_add(1, Ordering::SeqCst)
        };
        assert!(!cx.capabilities().spawn);
        let scope = cx.scope();
        denied(cx.spawn(factory()));
        denied(cx.spawn_in(&scope, factory()));
        denied(cx.spawn_registered_in(&scope, factory()));
        denied(cx.spawn_local(factory()));
        denied(cx.spawn_local_in(&scope, factory()));
        denied(cx.spawn_blocking(blocking()));
        denied(cx.spawn_blocking_in(&scope, blocking()));
        let mut set = JoinSet::<u32, (), _>::in_cx(cx);
        assert!(matches!(
            set.spawn(cx, |_| async { Ok(1) }),
            Err(SpawnError::RuntimeUnavailable)
        ));
        assert!(matches!(
            set.spawn_local(cx, |_| async { Ok(1) }),
            Err(SpawnError::RuntimeUnavailable)
        ));
        assert!(set.is_empty());
        for restricted_install in [false, true] {
            let _guard = if restricted_install {
                cx.clone().set_current_restricted()
            } else {
                Cx::set_current(Some(cx.clone()))
            };
            let installed = Cx::current().unwrap();
            assert_eq!(installed.capabilities(), cx.capabilities());
            assert_eq!(
                Cx::with_current(Cx::capabilities).unwrap(),
                cx.capabilities()
            );
            denied(installed.spawn(factory()));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(Arc::strong_count(&calls), 1);
        let mut opening = std::pin::pin!(cx.open_child_region(ChildRegionSpec::inherit()));
        assert!(matches!(
            opening
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(ChildRegionError::RuntimeUnavailable))
        ));
    }

    let full = Cx::current().unwrap();
    let pure = full.restrict::<PureCaps>();
    let web = full.restrict::<WebCaps>();
    assert_eq!(pure.region_id(), full.region_id());
    assert_eq!(web.task_id(), full.task_id());
    pure.checkpoint().unwrap();
    web.checkpoint().unwrap();
    {
        let _guard = pure.set_current_restricted();
        assert_spawn_family_denied(&Cx::current().unwrap());
    }
    {
        let _guard = web.set_current_restricted();
        assert_spawn_family_denied(&Cx::current().unwrap());
    }
    let mut handle = full.spawn(|_| async { 3 }).unwrap();
    assert_eq!(handle.join(&full).await.unwrap(), 3);
    assert!(matches!(
        Cx::detached_cancel_context()
            .open_child_region(asupersync::cx::ChildRegionSpec::inherit())
            .await,
        Err(asupersync::cx::ChildRegionError::NoRuntimeGateway)
    ));
}

#[asupersync::test]
async fn child_region_preserves_parent_ambient_capabilities() {
    use asupersync::cx::cap::CapSet;
    use asupersync::cx::{CapabilitySnapshot, ChildRegionSpec};
    use std::sync::{Arc, Mutex};

    struct RecordDrop {
        label: &'static str,
        snapshots: Arc<Mutex<Vec<(&'static str, CapabilitySnapshot)>>>,
    }

    impl Drop for RecordDrop {
        fn drop(&mut self) {
            self.snapshots
                .lock()
                .unwrap()
                .push((self.label, Cx::current().unwrap().capabilities()));
        }
    }

    struct PanickingFuture(RecordDrop);

    impl std::future::Future for PanickingFuture {
        type Output = ();

        fn poll(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<()> {
            std::panic::panic_any(RecordDrop {
                label: "panic payload",
                snapshots: Arc::clone(&self.0.snapshots),
            });
        }
    }

    let full = Cx::current().unwrap();
    let restricted = {
        let _guard = full
            .restrict::<CapSet<true, false, false, false, false>>()
            .set_current_restricted();
        Cx::current().unwrap()
    };
    let expected = restricted.capabilities();
    assert!(expected.spawn);
    assert!(!expected.io && !expected.time && !expected.entropy && !expected.remote);
    let child = restricted
        .open_child_region(ChildRegionSpec::inherit())
        .await
        .unwrap();
    let grandchild = child
        .cx()
        .open_child_region(ChildRegionSpec::inherit())
        .await
        .unwrap();
    let mut task = grandchild
        .cx()
        .spawn(|cx| {
            let factory = Cx::current().unwrap().capabilities();
            async move {
                let first_poll = Cx::current().unwrap().capabilities();
                asupersync::runtime::yield_now().await;
                (
                    cx.capabilities(),
                    factory,
                    first_poll,
                    Cx::current().unwrap().capabilities(),
                )
            }
        })
        .unwrap();
    assert_eq!(child.cx().capabilities(), expected);
    assert_eq!(grandchild.cx().capabilities(), expected);
    assert_eq!(
        task.join(&full).await.unwrap(),
        (expected, expected, expected, expected)
    );
    assert!(child.cx().io().is_none());
    assert!(child.cx().timer_driver().is_none());
    let drops = Arc::new(Mutex::new(Vec::new()));
    let snapshots = Arc::clone(&drops);
    let mut panicking = grandchild
        .cx()
        .spawn(move |_| {
            PanickingFuture(RecordDrop {
                label: "future",
                snapshots,
            })
        })
        .unwrap();
    assert!(matches!(
        panicking.join(&full).await,
        Err(asupersync::runtime::JoinError::Panicked(_))
    ));
    let observed = drops.lock().unwrap().clone();
    assert_eq!(
        observed.len(),
        2,
        "future and panic payload must be dropped"
    );
    for (label, snapshot) in observed {
        assert_eq!(snapshot, expected, "{label} destructor restored authority");
    }
    grandchild.close().await.unwrap();
    child.close().await.unwrap();
    assert!(full.capabilities().io && full.capabilities().time);
}

#[test]
fn dropping_pending_join_next_then_cancel_all_drains_the_same_members() {
    use asupersync::types::CancelKind;
    use std::future::Future;
    use std::task::{Context, Waker};

    let (outcomes, report) = asupersync::lab::run_async_under_lab(0xA212, |cx| async move {
        let mut set = JoinSet::in_cx(&cx);
        for _ in 0..4 {
            set.spawn(&cx, |child| async move {
                while child.checkpoint().is_ok() {
                    asupersync::runtime::yield_now().await;
                }
                Err::<u32, _>("cancelled")
            })
            .unwrap();
        }
        {
            let mut next = std::pin::pin!(set.join_next(&cx));
            assert!(
                next.as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
        }
        assert_eq!(
            set.len(),
            4,
            "dropping the pending collection future keeps ownership"
        );
        assert!(set.try_join_next().is_none());
        set.cancel_all(&cx).await
    });
    assert_eq!(outcomes.len(), 4);
    for outcome in outcomes {
        assert!(matches!(outcome, Outcome::Cancelled(reason) if reason.kind == CancelKind::User));
    }
    assert!(report.quiescent && report.oracle_report.all_passed());
    assert!(report.invariant_violations.is_empty());
}

#[test]
fn join_set_poll_budget_exhaustion_mid_fanout_drains_every_member() {
    use asupersync::types::CancelKind;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let ((outcomes, checkpoints), report) =
        asupersync::lab::run_async_under_lab(0xA213, |cx| async move {
            let scope = cx.scope_with_budget(Budget::INFINITE.with_poll_quota(3));
            let mut set = JoinSet::new(&scope);
            let checkpoints = Arc::new(AtomicUsize::new(0));
            for _ in 0..4 {
                let checkpoints = Arc::clone(&checkpoints);
                set.spawn(&cx, move |child| async move {
                    loop {
                        if child.checkpoint().is_err() {
                            return Err::<u32, _>(child.cancel_reason().unwrap().kind);
                        }
                        checkpoints.fetch_add(1, Ordering::SeqCst);
                        asupersync::runtime::yield_now().await;
                    }
                })
                .unwrap();
            }
            let outcomes = set.join_all(&cx).await;
            (outcomes, checkpoints.load(Ordering::SeqCst))
        });
    assert!(
        checkpoints > 0,
        "members must run before exhausting their budget"
    );
    assert_eq!(outcomes.len(), 4);
    for outcome in outcomes {
        assert!(
            matches!(outcome, Outcome::Cancelled(reason) if reason.kind == CancelKind::PollQuota)
        );
    }
    assert!(report.quiescent && report.oracle_report.all_passed());
    assert!(report.invariant_violations.is_empty());
}

mod macro_entry {
    #[asupersync::main]
    pub async fn main() {
        let (value, report) = asupersync::lab::run_async_under_lab(0xA214, |cx| async move {
            asupersync::scope!(cx, {
                let mut handle = cx.spawn_in(&scope, |_| async { 10_u32 }).unwrap();
                let (a, b) = asupersync::join!(handle.join(&cx), async { 20_u32 });
                assert_eq!((a.unwrap(), b), (10, 20));
                let pair = asupersync::join_all!(async { 10_u32 }, async { 20_u32 });
                assert_eq!(pair, [10, 20]);
                let winner = asupersync::race!(cx, { async { 30_u32 }, async { 30_u32 } }).unwrap();
                asupersync::select!(cx, {
                    value = async move { winner + 12 } => value,
                    value = async { 42_u32 } => value,
                })
                .unwrap()
            })
        });
        assert_eq!(value, 42);
        assert!(report.quiescent && report.oracle_report.all_passed());
        assert!(report.invariant_violations.is_empty());
    }
}

#[test]
fn entry_scope_join_race_and_select_compose_under_lab() {
    macro_entry::main();
}

#[test]
fn mailbox_race_participants_keep_identity_and_run_loser_cleanup() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    for arity in [2, 3] {
        let ((winner, cleaned), report) =
            asupersync::lab::run_async_under_lab(0xA216 + arity as u64, move |cx| async move {
                let scope = cx.scope();
                let parked = Arc::new(AtomicUsize::new(0));
                let cleaned = Arc::new(AtomicUsize::new(0));
                let mut handles = Vec::new();
                for index in 0..arity {
                    let parked = Arc::clone(&parked);
                    let cleaned = Arc::clone(&cleaned);
                    handles.push(
                        cx.spawn_in(&scope, move |child| async move {
                            if index == 0 {
                                while parked.load(Ordering::SeqCst) != arity - 1 {
                                    asupersync::runtime::yield_now().await;
                                }
                                7
                            } else {
                                parked.fetch_add(1, Ordering::SeqCst);
                                while child.checkpoint().is_ok() {
                                    asupersync::runtime::yield_now().await;
                                }
                                // This code must run after cancellation; merely
                                // dropping the losing future cannot increment it.
                                cleaned.fetch_add(1, Ordering::SeqCst);
                                0
                            }
                        })
                        .unwrap(),
                    );
                }
                // No task has been admitted yet. The oracle must join the
                // provisional start identities with the completion records.
                let winner = if arity == 2 {
                    let second = handles.pop().unwrap();
                    scope
                        .race(&cx, handles.pop().unwrap(), second)
                        .await
                        .unwrap()
                } else {
                    scope.race_all(&cx, handles).await.unwrap().0
                };
                (winner, cleaned.load(Ordering::SeqCst))
            });
        assert_eq!(winner, 7);
        assert_eq!(cleaned, arity - 1);
        assert!(report.quiescent && report.oracle_report.all_passed());
        assert!(report.invariant_violations.is_empty());
    }
}

#[test]
fn mailbox_quorum_participants_keep_identity_and_run_loser_cleanup() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let ((values, cleaned), report) =
        asupersync::lab::run_async_under_lab(0xA219, |cx| async move {
            let parked = Arc::new(AtomicUsize::new(0));
            let cleaned = Arc::new(AtomicUsize::new(0));
            let branches = (0..3).map(|index| {
                let parked = Arc::clone(&parked);
                let cleaned = Arc::clone(&cleaned);
                move |child: Cx| async move {
                    if index == 0 {
                        while parked.load(Ordering::SeqCst) != 2 {
                            asupersync::runtime::yield_now().await;
                        }
                        Ok(7)
                    } else {
                        parked.fetch_add(1, Ordering::SeqCst);
                        while child.checkpoint().is_ok() {
                            asupersync::runtime::yield_now().await;
                        }
                        cleaned.fetch_add(1, Ordering::SeqCst);
                        Err(())
                    }
                }
            });
            let values = cx.scope().quorum(&cx, 1, branches).await.unwrap();
            (values, cleaned.load(Ordering::SeqCst))
        });
    assert_eq!(values, vec![7]);
    assert_eq!(cleaned, 2);
    assert!(report.quiescent && report.oracle_report.all_passed());
    assert!(report.invariant_violations.is_empty());
}

#[test]
fn channel_stream_and_bulk_permit_journey_releases_every_obligation() {
    use asupersync::channel::mpsc;
    use asupersync::stream::{StreamExt, for_each_concurrent, iter, try_for_each_concurrent};
    use asupersync::sync::Semaphore;

    let (values, report) = asupersync::lab::run_async_under_lab(0xA215, |cx| async move {
        let semaphore = Semaphore::new(3);
        let permits = semaphore.acquire_many(&cx, 3).await.unwrap();
        assert_eq!(semaphore.available_permits(), 0);
        assert!(semaphore.try_acquire_many(1).is_err());
        drop(permits);
        assert_eq!(semaphore.available_permits(), 3);

        let (tx, mut rx) = mpsc::channel(2);
        let producer = for_each_concurrent(&cx, iter(0_u32..6), 2, move |child, value| {
            let tx = tx.clone();
            async move { tx.send(&child, value).await.unwrap() }
        });
        let consume = async {
            let mut values = Vec::new();
            loop {
                match rx.recv(&cx).await {
                    Ok(value) => values.push(value),
                    Err(mpsc::RecvError::Disconnected) => break,
                    Err(other) => panic!("channel journey failed: {other:?}"),
                }
            }
            values
        };
        let (produced, mut values) = asupersync::join!(producer, consume);
        assert!(matches!(produced, Outcome::Ok(())));
        values.sort_unstable();
        assert_eq!(values, vec![0, 1, 2, 3, 4, 5]);

        let (tx, mut rx) = mpsc::unbounded_channel();
        for value in &values {
            tx.send(*value).unwrap();
        }
        drop(tx);
        let mut received = Vec::new();
        assert_eq!(rx.recv_many(&cx, &mut received, 6).await.unwrap(), 6);
        assert_eq!(received, values);
        assert_eq!(rx.try_recv(), Err(mpsc::RecvError::Disconnected));

        let (even, odd) = iter(values).partition(|value| value % 2 == 0, 2);
        let (even, odd) = asupersync::join!(even.collect::<Vec<_>>(), odd.collect::<Vec<_>>());
        assert_eq!(even, vec![0, 2, 4]);
        assert_eq!(odd, vec![1, 3, 5]);
        let mut buffered = iter(odd)
            .map(|value| {
                Box::pin(async move {
                    asupersync::runtime::yield_now().await;
                    Ok::<_, ()>(value * 2)
                })
            })
            .try_buffered(2);
        let fresh = buffered.telemetry_snapshot(215);
        assert_eq!((fresh.limit, fresh.in_flight, fresh.available), (2, 0, 2));
        let mut results = Vec::new();
        while let Some(value) = buffered.next().await {
            results.push(value);
        }
        assert_eq!(results, vec![Ok(2), Ok(6), Ok(10)]);
        let terminal = buffered.telemetry_snapshot(215);
        assert!(terminal.closed);
        assert_eq!(terminal.in_flight, 0);
        let stopped = try_for_each_concurrent(&cx, iter(0..6), 2, |_, value| async move {
            if value == 2 {
                Err("stop at two")
            } else {
                Ok(())
            }
        })
        .await;
        assert_eq!(stopped, Outcome::Err("stop at two"));
        iter(even).collect_into(vec![99]).await
    });
    assert_eq!(values, vec![99, 0, 2, 4]);
    assert!(report.quiescent && report.oracle_report.all_passed());
    assert!(report.invariant_violations.is_empty());
}

#[test]
fn local_and_blocking_spawns_keep_region_and_scope_budgets() {
    use asupersync::cx::cap::CapSet;
    use asupersync::runtime::{RootDrainOutcome, RuntimeBuilder};
    use std::rc::Rc;
    use std::time::Duration;

    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let scope = cx.scope_with_budget(Budget::INFINITE.with_cost_quota(37));
        let region = scope.region_id();
        let value = Rc::new(7);
        let local_value = Rc::clone(&value);
        let mut local = cx
            .spawn_local(move |child| async move { (child.region_id(), *local_value) })
            .unwrap();
        assert_eq!(local.join(&cx).await.unwrap(), (region, 7));
        let local_value = Rc::clone(&value);
        let mut scoped = cx
            .spawn_local_in(&scope, move |child| async move {
                (
                    child.region_id(),
                    child.remaining_budget().cost,
                    *local_value,
                )
            })
            .unwrap();
        assert_eq!(scoped.join(&cx).await.unwrap(), (region, Some(37), 7));
        let mut blocking = cx.spawn_blocking(|child| child.region_id()).unwrap();
        assert_eq!(blocking.join(&cx).await.unwrap(), region);
        let mut blocking = cx
            .spawn_blocking_in(&scope, |child| {
                (child.region_id(), child.remaining_budget().cost)
            })
            .unwrap();
        assert_eq!(blocking.join(&cx).await.unwrap(), (region, Some(37)));
        let mut registered = cx
            .spawn_registered_in(&scope, |child| async move { child.remaining_budget().cost })
            .unwrap();
        assert_eq!(registered.join(&cx).await.unwrap(), Some(37));

        let mut set = JoinSet::new(&scope);
        set.spawn_local(&cx, move |_| async move { Ok::<_, ()>(*value) })
            .unwrap();
        assert!(!set.is_empty());
        assert_eq!(set.join_next(&cx).await, Some(Outcome::Ok(7)));
        assert!(set.is_empty());
        assert!(set.join_next(&cx).await.is_none());
        assert_eq!(set.summary().completed(), 1);
        assert_eq!(set.summary().worst(), asupersync::types::Severity::Ok);

        let restricted = {
            let _guard = cx
                .restrict::<CapSet<true, false, false, false, false>>()
                .set_current_restricted();
            Cx::current().unwrap()
        };
        let expected = restricted.capabilities();
        assert!(expected.spawn && !expected.io && !expected.time);
        let local_value = Rc::new(11);
        let mut local = restricted
            .spawn_local(move |child| {
                let factory = Cx::current().unwrap().capabilities();
                async move {
                    let first_poll = Cx::current().unwrap().capabilities();
                    asupersync::runtime::yield_now().await;
                    (
                        *local_value,
                        child.capabilities(),
                        factory,
                        first_poll,
                        Cx::current().unwrap().capabilities(),
                    )
                }
            })
            .unwrap();
        assert_eq!(
            local.join(&cx).await.unwrap(),
            (11, expected, expected, expected, expected)
        );
        let mut blocking = restricted
            .spawn_blocking(|child| child.capabilities())
            .unwrap();
        assert_eq!(blocking.join(&cx).await.unwrap(), expected);

        let before = cx.now();
        let budget = cx.budget_for_timeout(Duration::from_secs(2));
        let after = cx.now();
        let deadline = budget.deadline.unwrap();
        assert!(deadline >= before + Duration::from_secs(2));
        assert!(deadline <= after + Duration::from_secs(2));
        assert_eq!(
            Budget::with_deadline_at_secs(2),
            Budget::with_deadline_at_ns(2_000_000_000)
        );
    });
    assert_eq!(
        runtime.drain_root_region(Duration::from_secs(5)),
        RootDrainOutcome::Quiescent
    );
    assert!(runtime.is_quiescent());
}
