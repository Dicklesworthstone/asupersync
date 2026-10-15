//! Native root-close regressions for br-asupersync-bi2462.92.

use super::*;
use crate::cx::Cx;
use crate::record::{ObligationAbortReason, ObligationKind};
use crate::types::{
    CancelKind, CapabilityBudget, CapabilityBudgetDimension, CapabilityBudgetRefusal,
    CapabilityBudgetRequirements, Outcome, TaskId,
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

fn runtime_for(case: u8) -> Runtime {
    match case {
        0 => RuntimeBuilder::current_thread(),
        1 => RuntimeBuilder::new().worker_threads(1),
        2 => RuntimeBuilder::new().worker_threads(2),
        _ => RuntimeBuilder::new()
            .worker_threads(2)
            .with_sharded_state(true),
    }
    .build()
    .expect("build native root-drain runtime")
}

fn wait_until(mut predicate: impl FnMut() -> bool, message: &str) {
    let started = Instant::now();
    while !predicate() {
        assert!(started.elapsed() < Duration::from_secs(3), "{message}");
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn wait_parked(runtime: &Runtime, task: TaskId) {
    wait_until(
        || {
            if let Some(table) = runtime.inner.scheduler.dispatch_task_table() {
                let mut table = table
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                table.get_stored_future(task).is_some()
                    && table
                        .task(task)
                        .is_some_and(|record| !record.wake_state.is_notified())
            } else {
                let mut state = runtime
                    .inner
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state.get_stored_future(task).is_some()
                    && state
                        .task(task)
                        .is_some_and(|record| !record.wake_state.is_notified())
            }
        },
        "finalizer/child must return Pending to native dispatch with no pending wake",
    );
}

#[derive(Default)]
struct ReleaseGate {
    released: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

impl ReleaseGate {
    fn release(&self) {
        self.released.store(true, Ordering::Release);
        let waker = self.waker.lock().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

struct RootFinalizer {
    gate: Arc<ReleaseGate>,
    parked: Option<std::sync::mpsc::Sender<TaskId>>,
    completed: Arc<AtomicBool>,
    drops: Arc<AtomicUsize>,
}

impl Future for RootFinalizer {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<()> {
        let cx = Cx::current().expect("native finalizer context");
        assert!(
            cx.inner.read().mask_depth > 0,
            "root finalizer executes masked"
        );
        assert!(cx.checkpoint().is_ok());
        *self.gate.waker.lock() = Some(task.waker().clone());
        if self.gate.released.load(Ordering::Acquire) {
            self.completed.store(true, Ordering::Release);
            return Poll::Ready(());
        }
        if let Some(parked) = self.parked.take() {
            parked
                .send(cx.task_id())
                .expect("publish pending finalizer");
        }
        // Only the external release owns a wake. The drain must not mistake
        // this real parked finalizer for completed work.
        Poll::Pending
    }
}

impl Drop for RootFinalizer {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::AcqRel);
    }
}

#[test]
fn finalizer_only_root_closes_after_pending_async_and_sync_cleanup() {
    for case in 0..4 {
        let runtime = runtime_for(case);
        let root = runtime.inner.root_region;
        let gate = Arc::new(ReleaseGate::default());
        let asynchronous = Arc::new(AtomicBool::new(false));
        let synchronous = Arc::new(AtomicBool::new(false));
        let drops = Arc::new(AtomicUsize::new(0));
        let returned = Arc::new(AtomicBool::new(false));
        let (parked_tx, parked_rx) = std::sync::mpsc::channel();
        {
            let mut state = runtime
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let sync_flag = Arc::clone(&synchronous);
            let async_flag = Arc::clone(&asynchronous);
            assert!(state.register_sync_finalizer(root, move || {
                assert!(
                    async_flag.load(Ordering::Acquire),
                    "LIFO async cleanup completed first"
                );
                sync_flag.store(true, Ordering::Release);
            }));
            assert!(state.register_async_finalizer(
                root,
                RootFinalizer {
                    gate: Arc::clone(&gate),
                    parked: Some(parked_tx),
                    completed: Arc::clone(&asynchronous),
                    drops: Arc::clone(&drops),
                }
            ));
            assert_eq!(state.live_task_count(), 0);
            assert_eq!(state.pending_obligation_count(), 0);
        }
        let observer_runtime = runtime.clone();
        let observer_returned = Arc::clone(&returned);
        let release = std::thread::spawn(move || {
            let task = parked_rx
                .recv_timeout(Duration::from_secs(3))
                .expect("empty root started its finalizer");
            wait_parked(&observer_runtime, task);
            assert!(
                !observer_returned.load(Ordering::Acquire),
                "drain returned before finalizer receipt"
            );
            std::thread::sleep(Duration::from_millis(20));
            assert!(!observer_returned.load(Ordering::Acquire));
            gate.release();
        });
        let outcome = runtime.drain_root_region(Duration::from_secs(2));
        returned.store(true, Ordering::Release);
        release.join().expect("release pending root finalizer");
        assert_eq!(outcome, RootDrainOutcome::Quiescent);
        assert!(asynchronous.load(Ordering::Acquire));
        assert!(synchronous.load(Ordering::Acquire));
        assert_eq!(drops.load(Ordering::Acquire), 1);
        let state = runtime
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            state.region(root).is_none(),
            "Quiescent requires actual root removal"
        );
        assert_eq!(state.live_region_count(), 0);
        eprintln!(
            "{{\"bead\":\"asupersync-bi2462.92\",\"case\":{case},\"scenario\":\"finalizer-only-root\",\"outcome\":\"Quiescent\",\"async_done\":true,\"sync_done\":true,\"root_removed\":true}}"
        );
    }
}

#[test]
fn root_drain_timeout_retains_pending_finalizer_until_a_later_drain() {
    for case in 0..4 {
        let runtime = runtime_for(case);
        let root = runtime.inner.root_region;
        let gate = Arc::new(ReleaseGate::default());
        let completed = Arc::new(AtomicBool::new(false));
        let drops = Arc::new(AtomicUsize::new(0));
        let (parked_tx, parked_rx) = std::sync::mpsc::channel();
        assert!(
            runtime
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .register_async_finalizer(
                    root,
                    RootFinalizer {
                        gate: Arc::clone(&gate),
                        parked: Some(parked_tx),
                        completed: Arc::clone(&completed),
                        drops: Arc::clone(&drops),
                    }
                )
        );
        let report = runtime.shutdown_drained(Duration::from_millis(100));
        assert!(
            report.elapsed < Duration::from_secs(1),
            "bounded wait: {report:?}"
        );
        let task = parked_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("root finalizer was polled");
        wait_parked(&runtime, task);
        assert_eq!(report.outcome, RootDrainOutcome::TimedOut);
        assert_eq!(report.live_tasks, 1);
        assert_eq!(report.live_regions, 1);
        assert_eq!(report.queued_finalizers, 0);
        assert!(!completed.load(Ordering::Acquire));
        assert_eq!(
            drops.load(Ordering::Acquire),
            0,
            "timeout preserves pending cleanup ownership"
        );
        gate.release();
        let finished = runtime.shutdown_drained(Duration::from_secs(2));
        assert_eq!(finished.outcome, RootDrainOutcome::Quiescent);
        assert_eq!(finished.live_tasks, 0);
        assert_eq!(finished.live_regions, 0);
        assert!(completed.load(Ordering::Acquire));
        assert_eq!(drops.load(Ordering::Acquire), 1);
        eprintln!(
            "{{\"bead\":\"asupersync-bi2462.92\",\"case\":{case},\"scenario\":\"pending-finalizer-timeout\",\"timed_out\":\"{report:?}\",\"later\":\"{finished:?}\"}}"
        );
    }
}

#[test]
fn handle_drain_of_an_already_closed_root_preserves_bounded_teardown() {
    for case in 0..4 {
        let runtime = runtime_for(case);
        let handle = runtime.handle();
        assert_eq!(
            runtime.shutdown_drained(Duration::ZERO).outcome,
            RootDrainOutcome::Quiescent
        );
        let repeated = handle
            .shutdown_drained(Duration::ZERO)
            .expect("live handle drains closed root");
        assert_eq!(repeated.outcome, RootDrainOutcome::Quiescent);
        assert_eq!(repeated.live_tasks, 0);
        assert_eq!(repeated.live_regions, 0);
        assert_eq!(
            runtime
                .trace_snapshot()
                .iter()
                .filter(|event| event.kind == crate::trace::TraceEventKind::RegionCloseBegin)
                .count(),
            1,
            "repeat drain must not invent another root close"
        );
        drop(handle);
        assert!(
            runtime.shutdown_timeout(Duration::from_secs(2)),
            "borrowed root drain must preserve teardown-reaper ownership"
        );
    }
}

#[test]
fn shutdown_drained_cancels_parked_child_settles_obligation_and_runs_finalizer() {
    for case in 0..4 {
        let runtime = runtime_for(case);
        let root = runtime.inner.root_region;
        let (parked_tx, parked_rx) = std::sync::mpsc::channel();
        let settled = Arc::new(AtomicBool::new(false));
        let child_settled = Arc::clone(&settled);
        let mut child = runtime.block_on(async {
            let cx = Cx::current().unwrap();
            cx.spawn(move |child| async move {
                let obligation = child
                    .try_register_obligation_checked(ObligationKind::Lease, child.task_id())
                    .expect("admit native obligation")
                    .expect("runtime obligation token");
                let mut cancelled = std::pin::pin!(child.cancelled());
                let mut parked = Some(parked_tx);
                std::future::poll_fn(|task| {
                    let result = cancelled.as_mut().poll(task);
                    if result.is_pending()
                        && let Some(parked) = parked.take()
                    {
                        parked.send(child.task_id()).expect("publish parked child");
                    }
                    result
                })
                .await;
                child.checkpoint().expect_err("child acknowledges shutdown");
                let reason = child
                    .cancel_reason()
                    .expect("the shutdown drain records its cancel reason");
                assert_eq!(reason.kind, CancelKind::Shutdown);
                assert!(obligation.abort(ObligationAbortReason::Cancel));
                child_settled.store(true, Ordering::Release);
                Outcome::<(), ()>::Cancelled(reason)
            })
            .expect("spawn parked root child")
        });
        let task = parked_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("child actually polled");
        wait_parked(&runtime, task);
        wait_until(
            || {
                runtime
                    .root_drain_snapshot(Duration::ZERO)
                    .pending_obligations
                    == 1
            },
            "obligation publication must materialize before shutdown",
        );
        let finalized = Arc::new(AtomicBool::new(false));
        let finalizer_flag = Arc::clone(&finalized);
        assert!(
            runtime
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .register_async_finalizer(root, async move {
                    assert!(
                        settled.load(Ordering::Acquire),
                        "child settled before root finalization"
                    );
                    finalizer_flag.store(true, Ordering::Release);
                })
        );
        let report = runtime.shutdown_drained(Duration::from_secs(2));
        assert_eq!(report.outcome, RootDrainOutcome::Quiescent);
        assert_eq!(report.live_tasks, 0);
        assert_eq!(report.pending_obligations, 0);
        assert_eq!(report.live_regions, 0);
        assert_eq!(report.queued_finalizers, 0);
        assert_eq!(report.pending_spawns, 0);
        assert!(!report.has_pending_obligation_posts);
        assert!(finalized.load(Ordering::Acquire));
        let Some(Outcome::Cancelled(reason)) = child
            .try_join()
            .expect("typed child result survives shutdown")
        else {
            panic!("expected a completed domain cancellation");
        };
        assert_eq!(reason.kind, CancelKind::Shutdown);
        let events = runtime.trace_snapshot();
        assert!(events.iter().any(
            |event| matches!(&event.data, crate::trace::TraceData::Message(message)
            if message.starts_with("root_drain outcome=drain_completed"))
        ));
        eprintln!(
            "{{\"bead\":\"asupersync-bi2462.92\",\"case\":{case},\"scenario\":\"child-obligation-finalizer\",\"task\":\"{task:?}\",\"report\":\"{report:?}\"}}"
        );
    }
}

fn immediate_scope_region<T>(future: impl Future<Output = T>) -> T {
    // The legacy region surface borrows RuntimeState. These fixtures create
    // only empty regions with ready bodies, so no state lock may cross a
    // Pending boundary or block native admission/completion.
    let mut future = std::pin::pin!(future);
    match future.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("empty scope region must close in its first poll"),
    }
}

fn assert_scope_root_drained(runtime: &Runtime, workers: u8) {
    let report = runtime.shutdown_drained(Duration::from_secs(3));
    assert_eq!(report.outcome, RootDrainOutcome::Quiescent);
    assert_eq!(report.live_tasks, 0);
    assert_eq!(report.pending_obligations, 0);
    assert_eq!(report.live_regions, 0);
    assert_eq!(report.queued_finalizers, 0);
    assert_eq!(report.pending_spawns, 0);
    assert!(!report.has_pending_obligation_posts);
    eprintln!("SCOPE_ADMISSION bead=asupersync-bi2462.46 workers={workers} report={report:?}");
}

#[test]
fn scope_region_admission_preserves_context_only_constraints_on_native_workers() {
    use crate::runtime::resource_monitor::RegionPriority;
    use crate::types::policy::FailFast;

    for workers in [1, 2] {
        let runtime = runtime_for(workers);
        let state = Arc::downgrade(&runtime.inner.state);
        let caller_thread = std::thread::current().id();
        runtime.block_on(async {
            let owner = Cx::current().expect("native block_on context");
            let mut task = owner
                .spawn(move |cx| async move {
                    assert_ne!(std::thread::current().id(), caller_thread);
                    let now = cx.now();
                    let budget = Budget::new()
                        .with_timeout(now, Duration::from_secs(60))
                        .with_poll_quota(41)
                        .with_cost_quota(73)
                        .with_priority(211);
                    let capabilities = CapabilityBudget::new()
                        .with_memory_bytes(4_096)
                        .with_cpu_units(32)
                        .with_io_bytes(8_192)
                        .with_artifact_bytes(512)
                        .with_cleanup_budget(
                            Budget::new()
                                .with_timeout(now, Duration::from_secs(90))
                                .with_poll_quota(7)
                                .with_cost_quota(19)
                                .with_priority(213),
                        );
                    let plain_scope = cx.scope_with_budget(budget);
                    assert_eq!(plain_scope.budget(), budget);
                    let scope = cx
                        .scope_with_budget_and_capability_budget(
                            budget,
                            capabilities,
                            CapabilityBudgetRequirements::NONE,
                        )
                        .expect("context-only envelopes are admitted");
                    let state = state.upgrade().expect("live native state");
                    let mut state = state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let parent = state.region(cx.region_id()).expect("native owner region");
                    assert_eq!(parent.budget(), Budget::INFINITE);
                    assert_eq!(parent.capability_budget(), CapabilityBudget::UNSPECIFIED);
                    let mut observed_regions = Vec::new();

                    let outcome = immediate_scope_region(plain_scope.region_with_budget(
                        &mut state,
                        &cx,
                        Budget::INFINITE,
                        FailFast,
                        |child, _state| std::future::ready(Outcome::Ok(child.budget())),
                    ))
                    .expect("plain scope opens an empty child");
                    assert!(matches!(outcome, Outcome::Ok(actual) if actual == budget));
                    let exhausted_scope = cx.scope_with_budget(Budget::ZERO);
                    let outcome = immediate_scope_region(exhausted_scope.region_with_budget(
                        &mut state,
                        &cx,
                        Budget::INFINITE,
                        FailFast,
                        |child, _state| std::future::ready(Outcome::Ok(child.budget())),
                    ))
                    .expect("legacy admission represents exhausted scheduler constraints");
                    assert!(matches!(outcome, Outcome::Ok(actual) if actual == Budget::ZERO));

                    for entry in 0..5 {
                        let inspect = |child: crate::cx::Scope<'_>, state: &mut RuntimeState| {
                            let child_id = child.region_id();
                            assert_eq!(child.budget(), budget, "entry={entry}");
                            assert_eq!(child.capability_budget(), capabilities, "entry={entry}");
                            let nested = immediate_scope_region(
                                child.region_with_budget_and_capability_budget(
                                    state,
                                    &cx,
                                    Budget::INFINITE,
                                    CapabilityBudget::UNSPECIFIED,
                                    CapabilityBudgetRequirements::NONE,
                                    FailFast,
                                    |leaf, state| {
                                        let record = state.region(leaf.region_id()).expect("leaf");
                                        assert_eq!(record.budget(), budget);
                                        assert_eq!(record.capability_budget(), capabilities);
                                        assert_eq!(leaf.budget(), budget);
                                        assert_eq!(leaf.capability_budget(), capabilities);
                                        std::future::ready(Outcome::Ok(leaf.region_id()))
                                    },
                                ),
                            )
                            .expect("nested child inherits every constraint");
                            let Outcome::Ok(leaf_id) = nested else {
                                panic!("empty nested region must close successfully");
                            };
                            assert!(state.region(leaf_id).is_none());
                            std::future::ready(Outcome::Ok((child_id, leaf_id)))
                        };
                        let outcome = match entry {
                            0 => immediate_scope_region(
                                scope.region(&mut state, &cx, FailFast, inspect),
                            ),
                            1 => immediate_scope_region(scope.region_with_priority(
                                &mut state,
                                &cx,
                                RegionPriority::Low,
                                FailFast,
                                inspect,
                            )),
                            2 => immediate_scope_region(scope.region_with_budget(
                                &mut state,
                                &cx,
                                Budget::INFINITE,
                                FailFast,
                                inspect,
                            )),
                            3 => immediate_scope_region(scope.region_with_budget_and_priority(
                                &mut state,
                                &cx,
                                Budget::INFINITE,
                                RegionPriority::Low,
                                FailFast,
                                inspect,
                            )),
                            _ => immediate_scope_region(
                                scope.region_with_budget_and_capability_budget(
                                    &mut state,
                                    &cx,
                                    Budget::INFINITE,
                                    CapabilityBudget::UNSPECIFIED,
                                    CapabilityBudgetRequirements::NONE,
                                    FailFast,
                                    inspect,
                                ),
                            ),
                        }
                        .expect("scope entry point admits an empty child");
                        let Outcome::Ok((child_id, leaf_id)) = outcome else {
                            panic!("empty scope region must close successfully");
                        };
                        assert!(state.region(child_id).is_none());
                        assert!(
                            state
                                .region(cx.region_id())
                                .expect("parent")
                                .child_ids()
                                .is_empty()
                        );
                        observed_regions.push((entry, child_id, leaf_id));
                    }
                    drop(state);
                    eprintln!(
                        "SCOPE_ADMISSION workers={workers} task={:?} regions={observed_regions:?} budget={budget:?} capabilities={capabilities:?}",
                        cx.task_id()
                    );
                })
                .expect("spawn native scope owner");
            crate::time::timeout(owner.now(), Duration::from_secs(10), task.join(&owner))
                .await
                .expect("native scope owner completes within bound")
                .expect("native scope owner retains its successful result");
        });
        assert_scope_root_drained(&runtime, workers);
    }
}

#[test]
fn scope_region_admission_cannot_replenish_exhausted_native_capabilities() {
    use crate::types::policy::FailFast;

    for workers in [1, 2] {
        let runtime = runtime_for(workers);
        let state = Arc::downgrade(&runtime.inner.state);
        runtime.block_on(async {
            let owner = Cx::current().expect("native block_on context");
            let mut task = owner
                .spawn(move |cx| async move {
                    let cases = [
                        (
                            CapabilityBudget::new().with_memory_bytes(0),
                            CapabilityBudgetRequirements::new().require_memory_bytes(),
                            CapabilityBudgetDimension::MemoryBytes,
                        ),
                        (
                            CapabilityBudget::new().with_cpu_units(0),
                            CapabilityBudgetRequirements::new().require_cpu_units(),
                            CapabilityBudgetDimension::CpuUnits,
                        ),
                        (
                            CapabilityBudget::new().with_io_bytes(0),
                            CapabilityBudgetRequirements::new().require_io_bytes(),
                            CapabilityBudgetDimension::IoBytes,
                        ),
                        (
                            CapabilityBudget::new().with_artifact_bytes(0),
                            CapabilityBudgetRequirements::new().require_artifact_bytes(),
                            CapabilityBudgetDimension::ArtifactBytes,
                        ),
                        (
                            CapabilityBudget::new()
                                .with_cleanup_budget(Budget::new().with_poll_quota(0)),
                            CapabilityBudgetRequirements::new().require_cleanup(),
                            CapabilityBudgetDimension::Cleanup,
                        ),
                        (
                            CapabilityBudget::new()
                                .with_cleanup_budget(Budget::new().with_cost_quota(0)),
                            CapabilityBudgetRequirements::new().require_cleanup(),
                            CapabilityBudgetDimension::Cleanup,
                        ),
                    ];
                    let replenishment = CapabilityBudget::new()
                        .with_memory_bytes(1_024)
                        .with_cpu_units(16)
                        .with_io_bytes(1_024)
                        .with_artifact_bytes(64)
                        .with_cleanup_budget(Budget::INFINITE);
                    for (exhausted, requirements, dimension) in cases {
                        let scope = cx
                            .scope_with_budget_and_capability_budget(
                                Budget::INFINITE,
                                exhausted,
                                CapabilityBudgetRequirements::NONE,
                            )
                            .expect("non-required exhausted envelope can be represented");
                        let state = state.upgrade().expect("live native state");
                        let mut state = state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        let before = state.live_region_count();
                        let mut factory_called = false;
                        let error = immediate_scope_region(
                            scope.region_with_budget_and_capability_budget(
                                &mut state,
                                &cx,
                                Budget::INFINITE,
                                replenishment,
                                requirements,
                                FailFast,
                                |_child, _state| {
                                    factory_called = true;
                                    std::future::ready(Outcome::Ok(()))
                                },
                            ),
                        )
                        .expect_err("new child cannot replenish a context-only exhausted envelope");
                        assert!(matches!(
                            error,
                            crate::runtime::RegionCreateError::CapabilityBudgetRefused {
                                parent,
                                reason: CapabilityBudgetRefusal::Exhausted(actual),
                            } if parent == cx.region_id() && actual == dimension
                        ));
                        assert!(!factory_called, "refusal must precede factory side effects");
                        assert_eq!(state.live_region_count(), before);
                        assert!(
                            state
                                .region(cx.region_id())
                                .expect("parent")
                                .child_ids()
                                .is_empty()
                        );
                        drop(state);
                        eprintln!(
                            "SCOPE_ADMISSION workers={workers} task={:?} refused={dimension:?} exhausted={exhausted:?} live_regions={before}",
                            cx.task_id()
                        );
                    }
                })
                .expect("spawn native refusal owner");
            crate::time::timeout(owner.now(), Duration::from_secs(10), task.join(&owner))
                .await
                .expect("native capability refusals complete within bound")
                .expect("native capability refusal owner completes successfully");
        });
        assert_scope_root_drained(&runtime, workers);
    }
}
