//! Native completion effects must survive leak-policy unwind and record recycling.
//!
//! The target is admitted through Cx::spawn, so its public TaskHandle really is
//! gated by the record-backed retirement barrier. No open direct-state target
//! handle or manually scheduled dependent can hide a lost completion effect.

use super::*;
use crate::cx::Cx;
use crate::runtime::TaskTable;
use crate::runtime::spawn_mailbox::{SpawnGateway, SpawnMailbox, is_spawn_mailbox_id};
use crate::runtime::state::{
    AdmissionRegionTarget, AdmissionTaskTarget,
    close_wake_test_support::{ClosePanic, CloseProbe},
};
use crate::types::{Budget, RegionId};
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Weak, mpsc as probe};
use std::task::{Context, Poll, Wake, Waker};

#[derive(Clone, Copy)]
enum LeakStage {
    OwnTask,
    ParentAfterRetirement,
    OwnTaskAndParent,
}

/// Foreign Wake/Drop callbacks only try locks. A broken completion path fails
/// its counters instead of deadlocking the native worker or panicking in Drop.
struct DeliveryProbe {
    state: Weak<ContendedMutex<RuntimeState>>,
    tasks: Option<Weak<ContendedMutex<TaskTable>>>,
    task: TaskId,
    owner: RegionId,
    cx: Option<Cx>,
    wakes: AtomicUsize,
    drops: AtomicUsize,
    state_unlocked: AtomicUsize,
    tasks_unlocked: AtomicUsize,
    cx_unlocked: AtomicUsize,
    retired: AtomicUsize,
    closed: AtomicUsize,
}

impl DeliveryProbe {
    fn new(
        state: &Arc<ContendedMutex<RuntimeState>>,
        tasks: Option<&Arc<ContendedMutex<TaskTable>>>,
        task: TaskId,
        owner: RegionId,
        cx: Option<Cx>,
    ) -> Arc<Self> {
        Arc::new(Self {
            state: Arc::downgrade(state),
            tasks: tasks.map(Arc::downgrade),
            task,
            owner,
            cx,
            wakes: AtomicUsize::new(0),
            drops: AtomicUsize::new(0),
            state_unlocked: AtomicUsize::new(0),
            tasks_unlocked: AtomicUsize::new(0),
            cx_unlocked: AtomicUsize::new(0),
            retired: AtomicUsize::new(0),
            closed: AtomicUsize::new(0),
        })
    }

    fn waker(self: &Arc<Self>) -> Waker {
        Waker::from(Arc::new(DeliveryWake(Arc::clone(self))))
    }

    fn observe(&self, waking: bool) {
        if waking {
            self.wakes.fetch_add(1, Ordering::SeqCst);
        } else {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
        if self
            .cx
            .as_ref()
            .is_none_or(|cx| cx.inner.try_write().is_some())
        {
            self.cx_unlocked.fetch_add(1, Ordering::SeqCst);
        }
        let Some(state) = self.state.upgrade() else {
            return;
        };
        let state = match state.try_lock() {
            Ok(state) => state,
            Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return,
        };
        self.state_unlocked.fetch_add(1, Ordering::SeqCst);
        let retired = if let Some(tasks) = self.tasks.as_ref() {
            let Some(tasks) = tasks.upgrade() else {
                return;
            };
            let tasks = match tasks.try_lock() {
                Ok(tasks) => tasks,
                Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) => return,
            };
            self.tasks_unlocked.fetch_add(1, Ordering::SeqCst);
            tasks.task(self.task).is_none()
        } else {
            self.tasks_unlocked.fetch_add(1, Ordering::SeqCst);
            state.task(self.task).is_none()
        };
        if retired {
            self.retired.fetch_add(1, Ordering::SeqCst);
        }
        if state.region(self.owner).is_none() && state.region_was_closed(self.owner) {
            self.closed.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn assert_pending(&self) {
        assert_eq!(self.wakes.load(Ordering::SeqCst), 0);
        assert_eq!(self.drops.load(Ordering::SeqCst), 0);
    }

    fn assert_delivered(&self, wakes: usize) {
        assert_eq!(self.wakes.load(Ordering::SeqCst), wakes);
        assert_eq!(
            self.drops.load(Ordering::SeqCst),
            1,
            "last Waker retires once"
        );
        let callbacks = wakes + 1;
        assert_eq!(self.state_unlocked.load(Ordering::SeqCst), callbacks);
        assert_eq!(self.tasks_unlocked.load(Ordering::SeqCst), callbacks);
        assert_eq!(self.cx_unlocked.load(Ordering::SeqCst), callbacks);
        assert_eq!(self.retired.load(Ordering::SeqCst), callbacks);
        assert_eq!(self.closed.load(Ordering::SeqCst), callbacks);
    }
}

struct DeliveryWake(Arc<DeliveryProbe>);

impl Wake for DeliveryWake {
    fn wake(self: Arc<Self>) {
        self.0.observe(true);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.observe(true);
    }
}

impl Drop for DeliveryWake {
    fn drop(&mut self) {
        self.0.observe(false);
    }
}

fn run_completion_retention(sharded: bool, stage: LeakStage) {
    let mut runtime = RuntimeState::new();
    runtime.set_obligation_leak_response(crate::runtime::config::ObligationLeakResponse::Panic);
    let root = runtime.create_root_region(Budget::INFINITE);
    let parent = runtime.create_child_region(root, Budget::INFINITE).unwrap();
    let child = runtime
        .create_child_region(parent, Budget::INFINITE)
        .unwrap();
    let state = Arc::new(ContendedMutex::new("runtime_state", runtime));
    let shards = sharded.then(|| {
        let mut runtime = state.lock().unwrap();
        let shards = Arc::new(crate::runtime::ShardedState::new(
            runtime.trace_handle(),
            runtime.metrics_provider(),
            runtime.sharded_construction_config(),
        ));
        runtime.install_shard_tables(Arc::clone(&shards));
        shards
    });
    let task_table = shards.as_ref().map(|shards| shards.task_shard_handle());
    let mut scheduler = match &shards {
        Some(shards) => ThreeLaneScheduler::new_with_sharded_state(
            1,
            &state,
            shards,
            DEFAULT_CANCEL_STREAK_LIMIT,
            false,
            32,
        ),
        None => {
            ThreeLaneScheduler::new_with_options(1, &state, DEFAULT_CANCEL_STREAK_LIMIT, false, 32)
        }
    };
    let mailbox = Arc::new(SpawnMailbox::new());
    scheduler.attach_spawn_mailbox(Arc::clone(&mailbox));
    let liveness = Arc::new(());
    let gateway = Arc::new(SpawnGateway::new(
        Arc::clone(&mailbox),
        scheduler.spawn_enqueued_notifier(),
        None,
        Arc::downgrade(&liveness),
    ));
    state
        .lock()
        .unwrap()
        .set_spawn_gateway(Arc::clone(&gateway));

    let dependent_runs = Arc::new(AtomicUsize::new(0));
    let dependent_counter = Arc::clone(&dependent_runs);
    let (dependent, mut dependent_handle, watcher_cx, producer_cx, effects) = {
        let mut runtime = state.lock().unwrap();
        let mut tasks = task_table
            .as_ref()
            .map_or(AdmissionTaskTarget::Embedded, |table| {
                AdmissionTaskTarget::External(table.lock().unwrap())
            });
        let (dependent, handle, effects) = runtime
            .create_task_with_deferred_spawn_effects_in(
                root,
                Budget::INFINITE,
                async move {
                    dependent_counter.fetch_add(1, Ordering::SeqCst);
                    19_u8
                },
                &mut tasks,
                &AdmissionRegionTarget::Embedded,
            )
            .unwrap();
        let watcher = match &mut tasks {
            AdmissionTaskTarget::Embedded => runtime.task(dependent).unwrap(),
            AdmissionTaskTarget::External(table) => table.task(dependent).unwrap(),
        }
        .cx
        .as_ref()
        .unwrap()
        .clone();
        // A principal borrows the real root task's identity, but targets the
        // child and its actual admission counter. It is not a child-owned task
        // that could prevent the completion-driven close below.
        let producer: Cx = Cx::new(child, dependent, Budget::INFINITE)
            .with_spawn_gateway(Some(Arc::clone(&gateway)))
            .with_pending_spawn_counter(Some(
                runtime.region(child).unwrap().pending_spawn_handle(),
            ));
        (dependent, handle, watcher, producer, effects)
    };
    effects.dispatch();

    let target_runs = Arc::new(AtomicUsize::new(0));
    let target_counter = Arc::clone(&target_runs);
    let mut handle = producer_cx
        .spawn(move |_| async move {
            target_counter.fetch_add(1, Ordering::SeqCst);
            73_u8
        })
        .unwrap();
    assert!(is_spawn_mailbox_id(handle.task_id()));
    assert_eq!(handle.try_join().unwrap(), None);
    let mut noop = Context::from_waker(Waker::noop());
    assert!(handle.poll_join(&mut noop).is_pending());

    let mut worker = scheduler.take_workers().pop().unwrap();
    assert_eq!(worker.drain_spawn_admissions(), 1);
    assert!(!is_spawn_mailbox_id(handle.task_id()));
    let task = handle.task_id();
    let (target_cx, barrier) = {
        let mut runtime = state.lock().unwrap();
        let mut tasks = task_table
            .as_ref()
            .map_or(AdmissionTaskTarget::Embedded, |table| {
                AdmissionTaskTarget::External(table.lock().unwrap())
            });
        let record = match &mut tasks {
            AdmissionTaskTarget::Embedded => runtime.task_mut(task).unwrap(),
            AdmissionTaskTarget::External(table) => table.task_mut(task).unwrap(),
        };
        assert_eq!(record.owner, child);
        record.add_waiter(dependent);
        let cx = record.cx.as_ref().unwrap().clone();
        let barrier = record
            .cx_inner
            .as_ref()
            .unwrap()
            .read()
            .retirement_barrier
            .clone()
            .expect("real mailbox retirement barrier");
        (cx, barrier)
    };
    assert!(!barrier.is_open());
    assert_eq!(handle.try_join().unwrap(), None);

    let join_probe = DeliveryProbe::new(&state, task_table.as_ref(), task, child, None);
    {
        let waker = join_probe.waker();
        let mut task_cx = Context::from_waker(&waker);
        assert!(handle.poll_join(&mut task_cx).is_pending());
    }
    join_probe.assert_pending();

    let cancel_probe = DeliveryProbe::new(
        &state,
        task_table.as_ref(),
        task,
        child,
        Some(target_cx.clone()),
    );
    {
        let waker = cancel_probe.waker();
        target_cx.register_cancel_waker(&waker);
    }
    cancel_probe.assert_pending();

    let mut opening = Box::pin(watcher_cx.monitor(&handle));
    assert!(opening.as_mut().poll(&mut noop).is_pending());
    assert_eq!(worker.drain_region_commands(), 1);
    let Poll::Ready(Ok(monitor)) = opening.as_mut().poll(&mut noop) else {
        panic!("native monitor must be established before completion");
    };
    drop(opening);
    let down_probe = DeliveryProbe::new(&state, task_table.as_ref(), task, child, None);
    let mut down = Box::pin(monitor.down(&watcher_cx));
    {
        let waker = down_probe.waker();
        let mut task_cx = Context::from_waker(&waker);
        assert!(down.as_mut().poll(&mut task_cx).is_pending());
    }
    down_probe.assert_pending();

    {
        let mut runtime = state.lock().unwrap();
        if matches!(stage, LeakStage::OwnTask | LeakStage::OwnTaskAndParent) {
            runtime
                .create_obligation(crate::record::ObligationKind::SendPermit, task, child, None)
                .unwrap();
        }
        if matches!(
            stage,
            LeakStage::ParentAfterRetirement | LeakStage::OwnTaskAndParent
        ) {
            let mut tasks = task_table
                .as_ref()
                .map_or(AdmissionTaskTarget::Embedded, |table| {
                    AdmissionTaskTarget::External(table.lock().unwrap())
                });
            let (orphan, orphan_handle, orphan_cx, orphan_sender, orphan_effects) = runtime
                .create_task_infrastructure_in::<()>(
                    &watcher_cx,
                    parent,
                    Budget::INFINITE,
                    false,
                    &mut tasks,
                    &AdmissionRegionTarget::Embedded,
                )
                .unwrap();
            drop(tasks);
            runtime
                .create_obligation(
                    crate::record::ObligationKind::SendPermit,
                    orphan,
                    parent,
                    None,
                )
                .unwrap();
            // Inject the missing-holder invariant failure after creating a
            // real tracked credit. This is audited only when child close
            // cascades into the parent, after the target record is retired.
            let orphan_record = match task_table.as_ref() {
                Some(table) => table.lock().unwrap().remove_task(orphan),
                None => runtime.tasks.remove_task(orphan),
            };
            runtime.region(parent).unwrap().remove_task(orphan);
            drop(runtime);
            drop((orphan_record, orphan_handle, orphan_cx, orphan_sender));
            orphan_effects.dispatch();
        }
    }
    let child_close = CloseProbe::install(&state, task_table.as_ref(), child, ClosePanic::None);
    let parent_close = CloseProbe::install(&state, task_table.as_ref(), parent, ClosePanic::None);
    {
        let runtime = state.lock().unwrap();
        assert!(runtime.region(child).unwrap().begin_close(None));
        assert!(runtime.region(parent).unwrap().begin_close(None));
    }
    child_close.assert_pending();
    parent_close.assert_pending();

    let (done, observed) = probe::channel();
    std::thread::scope(|scope| {
        scope.spawn(move || {
            assert_eq!(
                worker.next_task(),
                Some(task),
                "only mailbox admission schedules the target"
            );
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                worker.execute(task);
            }));
            assert!(
                result.is_err(),
                "the configured leak-policy panic must occur"
            );
            if let Err(payload) = result {
                std::mem::forget(payload);
            }
            assert_eq!(
                worker.next_task(),
                Some(dependent),
                "only the retained TaskId waiter can schedule this dependent"
            );
            worker.execute(dependent);
            assert!(
                worker.next_task().is_none(),
                "completion does not enqueue duplicate effects"
            );
            done.send(()).unwrap();
        });
        observed.recv_timeout(Duration::from_secs(2)).unwrap();
    });

    assert_eq!(target_runs.load(Ordering::SeqCst), 1);
    assert_eq!(dependent_runs.load(Ordering::SeqCst), 1);
    assert!(barrier.is_open());
    assert_eq!(handle.try_join().unwrap(), Some(73));
    assert_eq!(dependent_handle.try_join().unwrap(), Some(19));
    join_probe.assert_delivered(1);
    down_probe.assert_delivered(1);
    cancel_probe.assert_delivered(0);
    assert!(target_cx.inner.read().cancel_waker_registry_closed);
    let Poll::Ready(Ok(notification)) = down.as_mut().poll(&mut noop) else {
        panic!("retained DOWN must resolve without waiting for another runtime event");
    };
    assert_eq!(notification.monitored, task);
    assert_eq!(notification.monitor_ref, monitor.monitor_ref());
    assert!(
        notification.reason.is_normal(),
        "the task's original Ok outcome is preserved"
    );
    child_close.assert_delivered();
    parent_close.assert_delivered();
    let runtime = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert!(runtime.region_was_closed(child));
    assert!(runtime.region_was_closed(parent));
    assert!(runtime.region(root).unwrap().task_ids().is_empty());
    assert_eq!(runtime.region(root).unwrap().pending_spawn_count(), 0);
    assert_eq!(runtime.pending_obligation_count(), 0);
    assert_eq!(
        runtime
            .down_history()
            .filter(|(watcher, target, _)| { *watcher == dependent && *target == task })
            .count(),
        1,
        "completion retries resolve the monitor exactly once"
    );
}

#[test]
fn native_own_leak_panic_retains_real_pending_join_and_completion_effects() {
    for sharded in [false, true] {
        run_completion_retention(sharded, LeakStage::OwnTask);
    }
}

#[test]
fn native_parent_leak_after_recycling_retains_real_pending_join_and_completion_effects() {
    for sharded in [false, true] {
        run_completion_retention(sharded, LeakStage::ParentAfterRetirement);
    }
}

#[test]
fn native_combined_leaks_retain_completion_effects_through_cleanup() {
    for sharded in [false, true] {
        run_completion_retention(sharded, LeakStage::OwnTaskAndParent);
    }
}
