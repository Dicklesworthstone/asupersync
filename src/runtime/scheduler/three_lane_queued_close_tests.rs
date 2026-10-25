//! Native queued region and obligation closes notify waiters after unlock.
use super::*;
use crate::cx::{ChildRegion, ChildRegionSpec, Cx};
use crate::record::{ObligationAbortReason, ObligationKind};
use crate::runtime::config::ObligationLeakResponse;
use crate::runtime::obligation_mailbox::{ObligationGateway, ObligationMailbox, ObligationToken};
use crate::runtime::spawn_mailbox::{SpawnGateway, SpawnMailbox};
use crate::runtime::state::{
    AdmissionRegionTarget, AdmissionTaskTarget,
    close_wake_test_support::{ClosePanic, CloseProbe},
};
use crate::runtime::{TaskHandle, TaskTable};
use crate::types::{Budget, CancelReason, RegionId};
use std::future::Future;
use std::task::{Context, Poll, Waker};

#[derive(Clone, Copy)]
enum TableLayout {
    Embedded,
    Sharded,
    ExternalOnly,
}

#[derive(Clone, Copy)]
enum CloseCommand {
    Close,
    Cancel,
    CancelWithBudget,
}

#[derive(Clone, Copy)]
enum ObligationTerminal {
    Commit,
    Abort,
    Leak,
}

impl ObligationTerminal {
    fn post(self, token: ObligationToken) {
        match self {
            Self::Commit => assert!(token.commit()),
            Self::Abort => assert!(token.abort(ObligationAbortReason::Explicit)),
            Self::Leak => drop(token),
        }
    }
}

#[derive(Clone, Copy)]
enum ObligationDrain {
    Dispatch,
    Completion,
}

type CompletionPost = Arc<parking_lot::Mutex<Option<(ObligationToken, ObligationTerminal)>>>;

struct Fixture {
    state: Arc<ContendedMutex<RuntimeState>>,
    table: Option<Arc<ContendedMutex<TaskTable>>>,
    worker: ThreeLaneWorker,
    principal: Cx,
    root: RegionId,
    healthy: TaskId,
    healthy_handle: TaskHandle<u8>,
    obligations: Arc<ObligationMailbox>,
    completion_post: CompletionPost,
    retired_holders: Vec<TaskId>,
    _scheduler: ThreeLaneScheduler,
    _liveness: Arc<()>,
}

impl Fixture {
    fn new(layout: TableLayout) -> Self {
        let mut runtime = RuntimeState::new();
        let root = runtime.create_root_region(Budget::INFINITE);
        let state = Arc::new(ContendedMutex::new("runtime_state", runtime));
        let shards = matches!(layout, TableLayout::Sharded).then(|| {
            let mut runtime = state.lock().unwrap();
            let shards = Arc::new(crate::runtime::ShardedState::new(
                runtime.trace_handle(),
                runtime.metrics_provider(),
                runtime.sharded_construction_config(),
            ));
            runtime.install_shard_tables(Arc::clone(&shards));
            shards
        });
        let table = match layout {
            TableLayout::Embedded => None,
            TableLayout::Sharded => Some(shards.as_ref().unwrap().task_shard_handle()),
            TableLayout::ExternalOnly => Some(Arc::new(ContendedMutex::new(
                "task_table",
                TaskTable::new(),
            ))),
        };
        let mut scheduler = if let Some(shards) = shards.as_ref() {
            ThreeLaneScheduler::new_with_sharded_state(
                1,
                &state,
                shards,
                DEFAULT_CANCEL_STREAK_LIMIT,
                false,
                32,
            )
        } else {
            ThreeLaneScheduler::new_with_options_and_task_table(
                1,
                &state,
                table.clone(),
                DEFAULT_CANCEL_STREAK_LIMIT,
                false,
                32,
            )
        };
        let mailbox = Arc::new(SpawnMailbox::new());
        scheduler.attach_spawn_mailbox(Arc::clone(&mailbox));
        let liveness = Arc::new(());
        let gateway = Arc::new(SpawnGateway::new(
            mailbox,
            scheduler.spawn_enqueued_notifier(),
            None,
            Arc::downgrade(&liveness),
        ));
        state.lock().unwrap().set_spawn_gateway(gateway);
        let obligations = Arc::new(ObligationMailbox::new());
        scheduler.attach_obligation_mailbox(&obligations);
        state.lock().unwrap().set_obligation_gateway(Arc::new(
            ObligationGateway::new(
                Arc::clone(&obligations),
                scheduler.obligation_posted_notifier(),
                Arc::downgrade(&liveness),
            ),
        ));
        let completion_post = CompletionPost::default();
        let poll_post = Arc::clone(&completion_post);
        let (healthy, healthy_handle, principal, effects) = {
            let mut runtime = state.lock().unwrap();
            let mut target = table.as_ref().map_or(AdmissionTaskTarget::Embedded, |table| {
                AdmissionTaskTarget::External(table.lock().unwrap())
            });
            let (task, handle, effects) = runtime
                .create_task_with_deferred_spawn_effects_in(
                    root,
                    Budget::INFINITE,
                    async move {
                        // Publish inside a real native poll: the worker must
                        // apply this post in its pre-completion drain.
                        let post = poll_post.lock().take();
                        if let Some((token, terminal)) = post {
                            terminal.post(token);
                        }
                        19_u8
                    },
                    &mut target,
                    &AdmissionRegionTarget::Embedded,
                )
                .unwrap();
            let principal = match &target {
                AdmissionTaskTarget::Embedded => runtime.task(task).unwrap(),
                AdmissionTaskTarget::External(table) => table.task(task).unwrap(),
            }
            .cx
            .as_ref()
            .unwrap()
            .clone();
            (task, handle, principal, effects)
        };
        effects.dispatch();
        scheduler.inject_ready(healthy, 50);
        let worker = scheduler.take_workers().pop().unwrap();
        Self {
            state,
            table,
            worker,
            principal,
            root,
            healthy,
            healthy_handle,
            obligations,
            completion_post,
            retired_holders: Vec::new(),
            _scheduler: scheduler,
            _liveness: liveness,
        }
    }

    fn open_child(&mut self) -> ChildRegion {
        open_child(&mut self.worker, &self.principal)
    }

    fn admit_obligation(
        &mut self,
        region: RegionId,
        checked: bool,
    ) -> (TaskId, Cx, ObligationToken) {
        let (holder, handle, cx, sender, effects) = {
            let mut state = self.state.lock().unwrap();
            let mut target = self.table.as_ref().map_or(AdmissionTaskTarget::Embedded, |table| {
                AdmissionTaskTarget::External(table.lock().unwrap())
            });
            state
                .create_task_infrastructure_in::<()>(
                    &self.principal,
                    region,
                    Budget::INFINITE,
                    false,
                    &mut target,
                    &AdmissionRegionTarget::Embedded,
                )
                .unwrap()
        };
        effects.dispatch();
        drop((handle, sender));
        let token = if checked {
            cx.try_register_obligation_checked(ObligationKind::SendPermit, holder)
                .unwrap()
                .unwrap()
        } else {
            cx.try_register_obligation(ObligationKind::SendPermit, holder)
                .unwrap()
        };
        assert_eq!(self.worker.drain_spawn_admissions(), 0);
        assert_eq!(self.obligations.open_tickets(), 1);
        (holder, cx, token)
    }

    fn unlink_holder(&mut self, holder: TaskId, region: RegionId, cx: &Cx) {
        // Isolate obligation settlement as the last close barrier. Ordinary
        // task completion would settle the obligation itself. Allocate and
        // unlink a real holder only after the queued close has begun, without
        // inventing an ID or calling the synchronous completion wrapper.
        cx.revoke_obligation_admission();
        let record = {
            let mut state = self.state.lock().unwrap();
            let record = match self.table.as_ref() {
                Some(table) => table.lock().unwrap().remove_task(holder),
                None => state.tasks.remove_task(holder),
            };
            assert!(record.is_some());
            state.region(region).unwrap().remove_task(holder);
            record
        };
        drop(record);
        self.retired_holders.push(holder);
    }

    fn finish_healthy(&mut self) {
        let mut completed = false;
        // A queued close can have published cancellation for an explicitly
        // unlinked fixture holder. Consume only those known stale identities.
        for _ in 0..=self.retired_holders.len() {
            let task = self.worker.next_task().expect("the ready task survived");
            assert!(task == self.healthy || self.retired_holders.contains(&task));
            self.worker.execute(task);
            if task == self.healthy {
                completed = true;
                break;
            }
        }
        assert!(completed, "the native worker must still complete unrelated work");
        assert_eq!(self.healthy_handle.try_join().unwrap(), Some(19));
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(state.region(self.root).unwrap().task_ids().is_empty());
        assert_eq!(state.pending_obligation_count(), 0);
    }
}

fn open_child(worker: &mut ThreeLaneWorker, cx: &Cx) -> ChildRegion {
    let mut opening = std::pin::pin!(cx.open_child_region(ChildRegionSpec::inherit()));
    let mut poll = Context::from_waker(Waker::noop());
    assert!(opening.as_mut().poll(&mut poll).is_pending());
    assert_eq!(worker.drain_region_commands(), 1);
    match opening.as_mut().poll(&mut poll) {
        Poll::Ready(Ok(child)) => child,
        result => panic!("native mailbox did not admit child: {result:?}"),
    }
}

fn run_queued_close(layout: TableLayout, command: CloseCommand, panic: ClosePanic) {
    let mut fixture = Fixture::new(layout);
    let child = fixture.open_child();
    let child_id = child.region_id();
    let probe = CloseProbe::install(
        &fixture.state,
        fixture.table.as_ref(),
        child_id,
        panic,
    );
    let expected_commands = match command {
        CloseCommand::Close => 1,
        CloseCommand::Cancel => {
            child.cancel(CancelReason::user("queued cancellation")).unwrap();
            2
        }
        CloseCommand::CancelWithBudget => {
            child
                .cancel_with_budget(
                    CancelReason::user("queued bounded cancellation"),
                    Budget::INFINITE.with_poll_quota(17),
                )
                .unwrap();
            2
        }
    };
    let mut close = std::pin::pin!(child.close_with_outcome());
    let mut poll = Context::from_waker(Waker::noop());
    assert!(close.as_mut().poll(&mut poll).is_pending());
    probe.assert_pending();
    assert_eq!(fixture.worker.drain_region_commands(), expected_commands);
    probe.assert_delivered();
    let receipt = match close.as_mut().poll(&mut poll) {
        Poll::Ready(Ok(receipt)) => receipt,
        result => panic!("queued close did not publish its receipt: {result:?}"),
    };
    assert!(matches!(receipt.outcome, crate::types::Outcome::Cancelled(_)));
    assert!(receipt.cleanup_outcome.is_none());
    {
        let state = fixture.state.lock().unwrap();
        assert!(state.region_was_closed(child_id));
        assert!(state.region(child_id).is_none());
        assert_eq!(state.region(fixture.root).unwrap().child_count(), 0);
    }
    fixture.finish_healthy();
}

#[test]
fn queued_native_close_and_cancel_wakers_run_after_all_runtime_locks() {
    for layout in [
        TableLayout::Embedded,
        TableLayout::Sharded,
        TableLayout::ExternalOnly,
    ] {
        for command in [
            CloseCommand::Close,
            CloseCommand::Cancel,
            CloseCommand::CancelWithBudget,
        ] {
            for panic in [ClosePanic::None, ClosePanic::Wake, ClosePanic::Drop] {
                run_queued_close(layout, command, panic);
            }
        }
    }
}

#[test]
fn queued_child_close_keeps_earlier_notifications_when_a_parent_leak_panics() {
    for layout in [TableLayout::Embedded, TableLayout::Sharded] {
        let mut fixture = Fixture::new(layout);
        let parent = fixture.open_child();
        let parent_id = parent.region_id();
        let child = open_child(&mut fixture.worker, parent.cx());
        let child_id = child.region_id();

        {
            let mut state = fixture.state.lock().unwrap();
            state.set_obligation_leak_response(
                crate::runtime::config::ObligationLeakResponse::Panic,
            );
            // Admit a real obligation before planting a missing holder.
            // Its task is minted and removed from the authoritative table;
            // no task or obligation identity is fabricated.
            let orphan_table = fixture.table.as_ref();
            let mut target = orphan_table.map_or(AdmissionTaskTarget::Embedded, |table| {
                AdmissionTaskTarget::External(table.lock().unwrap())
            });
            let (orphan, handle, cx, sender, effects) = state
                .create_task_infrastructure_in::<()>(
                    &fixture.principal,
                    parent_id,
                    Budget::INFINITE,
                    false,
                    &mut target,
                    &AdmissionRegionTarget::Embedded,
                )
                .unwrap();
            drop(target);
            state
                .create_obligation(
                    crate::record::ObligationKind::SendPermit,
                    orphan,
                    parent_id,
                    None,
                )
                .unwrap();
            let record = match orphan_table {
                Some(table) => table.lock().unwrap().remove_task(orphan),
                None => state.tasks.remove_task(orphan),
            };
            assert!(record.is_some());
            state.region(parent_id).unwrap().remove_task(orphan);
            assert!(state.region(parent_id).unwrap().begin_close(None));
            drop(state);
            drop((record, handle, cx, sender));
            effects.dispatch();
        }

        // The configured leak panic poisons the shard mutex while releasing
        // it. CloseProbe's task-table probe treats poison as failure, so this
        // unwind test probes RuntimeState directly; the ordinary matrix above
        // independently checks callbacks against every external table lock.
        let probe = CloseProbe::install(&fixture.state, None, child_id, ClosePanic::None);
        let mut close = std::pin::pin!(child.close_with_outcome());
        let mut poll = Context::from_waker(Waker::noop());
        assert!(close.as_mut().poll(&mut poll).is_pending());
        let applied = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            fixture.worker.drain_region_commands();
        }));
        let payload = applied.expect_err("the parent leak must exercise the unwind path");
        std::mem::forget(payload);
        probe.assert_delivered();
        assert!(matches!(
            close.as_mut().poll(&mut poll),
            Poll::Ready(Ok(_))
        ));
        {
            let state = fixture
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(state.region_was_closed(child_id));
            assert!(state.region_was_closed(parent_id));
            assert_eq!(state.leak_count(), 1);
            assert_eq!(state.pending_obligation_count(), 0);
        }
        drop(parent);
        fixture.finish_healthy();
    }
}

fn run_obligation_close(
    layout: TableLayout,
    checked: bool,
    terminal: ObligationTerminal,
    drain: ObligationDrain,
    panic: ClosePanic,
) {
    let mut fixture = Fixture::new(layout);
    fixture
        .state
        .lock()
        .unwrap()
        .set_obligation_leak_response(ObligationLeakResponse::Recover);
    let child = fixture.open_child();
    let child_id = child.region_id();
    let (holder, cx, token) = fixture.admit_obligation(child_id, checked);
    let probe = CloseProbe::install(&fixture.state, fixture.table.as_ref(), child_id, panic);
    let mut close = std::pin::pin!(child.close_with_outcome());
    let mut poll = Context::from_waker(Waker::noop());
    assert!(close.as_mut().poll(&mut poll).is_pending());
    assert_eq!(fixture.worker.drain_region_commands(), 1);
    probe.assert_pending();
    fixture.unlink_holder(holder, child_id, &cx);

    match drain {
        ObligationDrain::Dispatch => {
            terminal.post(token);
            assert_eq!(fixture.worker.drain_spawn_admissions(), 0);
        }
        ObligationDrain::Completion => {
            *fixture.completion_post.lock() = Some((token, terminal));
            fixture.finish_healthy();
        }
    }
    probe.assert_delivered();
    let receipt = match close.as_mut().poll(&mut poll) {
        Poll::Ready(Ok(receipt)) => receipt,
        result => panic!("obligation settlement did not publish close: {result:?}"),
    };
    assert!(matches!(receipt.outcome, crate::types::Outcome::Cancelled(_)));
    assert!(receipt.cleanup_outcome.is_none());
    {
        let state = fixture.state.lock().unwrap();
        assert!(state.region_was_closed(child_id));
        assert!(state.region(child_id).is_none());
        assert_eq!(state.region(fixture.root).unwrap().child_count(), 0);
        assert_eq!(state.pending_obligation_count(), 0);
        assert_eq!(state.leak_count(), u64::from(matches!(terminal, ObligationTerminal::Leak)));
    }
    let stats = fixture.obligations.stats();
    assert_eq!(stats.posted, 2);
    assert_eq!(stats.applied, stats.posted);
    assert_eq!(stats.reserved, 1);
    assert_eq!(stats.committed, u64::from(matches!(terminal, ObligationTerminal::Commit)));
    assert_eq!(stats.aborted, u64::from(matches!(terminal, ObligationTerminal::Abort)));
    assert_eq!(stats.leaked, u64::from(matches!(terminal, ObligationTerminal::Leak)));
    assert_eq!(stats.refused, 0);
    assert_eq!(fixture.obligations.open_tickets(), 0);
    if matches!(drain, ObligationDrain::Dispatch) {
        fixture.finish_healthy();
    }
}

#[test]
fn native_obligation_terminal_closes_notify_after_dispatch_and_completion_unlock() {
    for layout in [TableLayout::Embedded, TableLayout::Sharded, TableLayout::ExternalOnly] {
        for checked in [false, true] {
            for terminal in [
                ObligationTerminal::Commit,
                ObligationTerminal::Abort,
                ObligationTerminal::Leak,
            ] {
                for drain in [ObligationDrain::Dispatch, ObligationDrain::Completion] {
                    for panic in [ClosePanic::None, ClosePanic::Wake, ClosePanic::Drop] {
                        run_obligation_close(layout, checked, terminal, drain, panic);
                    }
                }
            }
        }
    }
}

#[test]
fn native_obligation_drain_delivers_closed_region_before_resuming_a_later_leak_panic() {
    for layout in [TableLayout::Embedded, TableLayout::Sharded, TableLayout::ExternalOnly] {
        let mut fixture = Fixture::new(layout);
        let child = fixture.open_child();
        let child_id = child.region_id();
        let (holder, cx, token) = fixture.admit_obligation(child_id, true);
        let leaked = fixture
            .principal
            .try_register_obligation_checked(ObligationKind::SendPermit, fixture.healthy)
            .unwrap()
            .unwrap();
        assert_eq!(fixture.worker.drain_spawn_admissions(), 0);
        fixture
            .state
            .lock()
            .unwrap()
            .set_obligation_leak_response(ObligationLeakResponse::Panic);
        // A leak poisons the external table guard. The ordinary matrix probes
        // that lock; this unwind witness uses the poison-aware state probe.
        let probe = CloseProbe::install(&fixture.state, None, child_id, ClosePanic::None);
        let mut close = std::pin::pin!(child.close_with_outcome());
        let mut poll = Context::from_waker(Waker::noop());
        assert!(close.as_mut().poll(&mut poll).is_pending());
        assert_eq!(fixture.worker.drain_region_commands(), 1);
        probe.assert_pending();
        fixture.unlink_holder(holder, child_id, &cx);
        assert!(token.commit());
        drop(leaked);

        let applied = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            fixture.worker.drain_spawn_admissions();
        }));
        let payload = applied.expect_err("the later leak must retain fail-fast behavior");
        assert!(payload.downcast_ref::<String>().is_some_and(|message| message.contains("obligation")));
        std::mem::forget(payload);
        probe.assert_delivered();
        assert!(matches!(close.as_mut().poll(&mut poll), Poll::Ready(Ok(_))));
        {
            let state = fixture.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(state.region_was_closed(child_id));
            assert!(state.region(child_id).is_none());
            assert_eq!(state.leak_count(), 1);
            assert_eq!(state.pending_obligation_count(), 0);
        }
        let stats = fixture.obligations.stats();
        assert_eq!(stats.posted, 4);
        assert_eq!(stats.applied, stats.posted);
        assert_eq!(stats.committed, 1);
        assert_eq!(stats.refused, 0);
        assert_eq!(fixture.obligations.open_tickets(), 0);
        fixture.finish_healthy();
    }
}

#[test]
fn native_obligation_close_keeps_notifications_when_its_parent_walk_panics() {
    for layout in [TableLayout::Embedded, TableLayout::Sharded] {
        let mut fixture = Fixture::new(layout);
        let parent = fixture.open_child();
        let parent_id = parent.region_id();
        let child = open_child(&mut fixture.worker, parent.cx());
        let child_id = child.region_id();
        let (holder, cx, token) = fixture.admit_obligation(child_id, true);
        {
            let mut state = fixture.state.lock().unwrap();
            state.set_obligation_leak_response(ObligationLeakResponse::Panic);
            let mut target = fixture.table.as_ref().map_or(AdmissionTaskTarget::Embedded, |table| {
                AdmissionTaskTarget::External(table.lock().unwrap())
            });
            let (orphan, handle, orphan_cx, sender, effects) = state
                .create_task_infrastructure_in::<()>(
                    &fixture.principal,
                    parent_id,
                    Budget::INFINITE,
                    false,
                    &mut target,
                    &AdmissionRegionTarget::Embedded,
                )
                .unwrap();
            drop(target);
            state
                .create_obligation(ObligationKind::SendPermit, orphan, parent_id, None)
                .unwrap();
            let record = match fixture.table.as_ref() {
                Some(table) => table.lock().unwrap().remove_task(orphan),
                None => state.tasks.remove_task(orphan),
            };
            assert!(record.is_some());
            state.region(parent_id).unwrap().remove_task(orphan);
            assert!(state.region(parent_id).unwrap().begin_close(None));
            drop(state);
            drop((record, handle, orphan_cx, sender));
            effects.dispatch();
        }
        let probe = CloseProbe::install(&fixture.state, None, child_id, ClosePanic::None);
        let mut close = std::pin::pin!(child.close_with_outcome());
        let mut poll = Context::from_waker(Waker::noop());
        assert!(close.as_mut().poll(&mut poll).is_pending());
        assert_eq!(fixture.worker.drain_region_commands(), 1);
        probe.assert_pending();
        fixture.unlink_holder(holder, child_id, &cx);
        assert!(token.commit());

        // This single post closes the child and enters the parent's leak
        // audit before per-post application returns. Its close token must
        // already belong to the caller's post-lock delivery guard.
        let applied = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            fixture.worker.drain_spawn_admissions();
        }));
        let payload = applied.expect_err("the same post must reach the parent leak panic");
        assert!(payload.downcast_ref::<String>().is_some_and(|message| message.contains("obligation")));
        std::mem::forget(payload);
        probe.assert_delivered();
        assert!(matches!(close.as_mut().poll(&mut poll), Poll::Ready(Ok(_))));
        {
            let state = fixture.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(state.region_was_closed(child_id));
            assert!(state.region_was_closed(parent_id));
            assert_eq!(state.leak_count(), 1);
            assert_eq!(state.pending_obligation_count(), 0);
        }
        assert_eq!(fixture.obligations.stats().applied, 2);
        assert_eq!(fixture.obligations.open_tickets(), 0);
        drop(parent);
        fixture.finish_healthy();
    }
}


#[test]
fn native_async_finalizer_checked_permits_obey_quota_and_retirement() {
    use crate::runtime::obligation_mailbox::ObligationAdmissionError;
    use crate::sync::{CheckedAcquireError, OwnedSemaphorePermit, Semaphore};

    for layout in [TableLayout::Embedded, TableLayout::Sharded, TableLayout::ExternalOnly] {
        for limit in [0_usize, 1, 3] {
            let mut fixture = Fixture::new(layout);
            let child = fixture.open_child();
            let child_id = child.region_id();
            let semaphore = Arc::new(Semaphore::new(limit + 1));
            let cleanup_semaphore = Arc::clone(&semaphore);
            let retained = Arc::new(parking_lot::Mutex::new(None::<Cx>));
            let cleanup_retained = Arc::clone(&retained);
            let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let cleanup_started = Arc::clone(&started);
            let (release, mut released) = crate::channel::oneshot::channel::<()>();
            {
                let mut state = fixture.state.lock().unwrap();
                let region = state.region(child_id).unwrap();
                let mut limits = region.limits();
                limits.max_obligations = Some(limit);
                region.set_limits(limits);
                assert!(state.register_async_finalizer(child_id, async move {
                    let cx = Cx::current().expect("real native finalizer context");
                    *cleanup_retained.lock() = Some(cx.clone());
                    // Zero units never consume quota, including a zero quota.
                    drop(OwnedSemaphorePermit::acquire_checked(
                        Arc::clone(&cleanup_semaphore), &cx, 0,
                    ).await.unwrap());
                    let mut permits = Vec::new();
                    for _ in 0..limit {
                        permits.push(OwnedSemaphorePermit::acquire_checked(
                            Arc::clone(&cleanup_semaphore), &cx, 1,
                        ).await.expect("live cleanup admits tracked resources"));
                    }
                    assert!(matches!(
                        cleanup_semaphore.try_acquire_checked(&cx, 1),
                        Err(CheckedAcquireError::Admission(
                            ObligationAdmissionError::LimitReached {
                                limit: observed,
                                live,
                            }
                        )) if observed == limit && live == limit
                    ));
                    assert_eq!(cleanup_semaphore.available_permits(), 1);
                    cleanup_started.store(true, std::sync::atomic::Ordering::SeqCst);
                    released.recv_uninterruptible().await.unwrap();
                    drop(permits);
                }));
            }
            let probe = CloseProbe::install(
                &fixture.state, fixture.table.as_ref(), child_id, ClosePanic::None,
            );
            let mut close = std::pin::pin!(child.close_with_outcome());
            let mut poll = Context::from_waker(Waker::noop());
            assert!(close.as_mut().poll(&mut poll).is_pending());
            assert_eq!(fixture.worker.drain_region_commands(), 1);
            // Native completion discovers and publishes the real finalizer.
            fixture.finish_healthy();
            let finalizer = fixture.worker.next_task().expect("finalizer is runnable");
            fixture.worker.execute(finalizer);
            assert!(started.load(std::sync::atomic::Ordering::SeqCst));
            let cleanup_cx = retained.lock().as_ref().unwrap().clone();
            assert_eq!(cleanup_cx.task_id(), finalizer);
            assert_eq!(cleanup_cx.region_id(), child_id);
            assert_eq!(fixture.worker.drain_spawn_admissions(), 0);
            probe.assert_pending();
            {
                let mut state = fixture.state.lock().unwrap();
                let region = state.region(child_id).unwrap();
                assert_eq!(region.state(), crate::record::region::RegionState::Finalizing);
                assert_eq!(region.pending_obligations(), limit);
                assert_eq!(region.unapplied_obligation_count(), limit);
                assert!(matches!(
                    region.add_task(finalizer),
                    Err(crate::record::AdmissionError::Closed)
                ));
                assert!(!state.can_region_complete_close(child_id));
                assert!(state.create_child_region(child_id, Budget::INFINITE).is_err());
            }
            // Cleanup checked credits do not widen the direct-ID contract.
            assert!(matches!(
                cleanup_cx.reserve_direct_obligation(finalizer, child_id),
                Some(Err(ObligationAdmissionError::RegionClosed))
            ));
            assert!(close.as_mut().poll(&mut poll).is_pending());
            release.send_blocking(()).unwrap();
            assert_eq!(fixture.worker.next_task(), Some(finalizer));
            fixture.worker.execute(finalizer);
            probe.assert_delivered();
            let receipt = match close.as_mut().poll(&mut poll) {
                Poll::Ready(Ok(receipt)) => receipt,
                result => panic!("checked cleanup failed to retire: {result:?}"),
            };
            assert!(matches!(receipt.cleanup_outcome, Some(crate::types::Outcome::Ok(()))));
            assert_eq!(semaphore.available_permits(), limit + 1);
            assert!(matches!(
                cleanup_cx.try_register_obligation_checked(
                    ObligationKind::SemaphorePermit, finalizer,
                ),
                Err(ObligationAdmissionError::RegionClosed)
            ));
            let stats = fixture.obligations.stats();
            assert_eq!(stats.reserved, limit as u64);
            assert_eq!(stats.committed, limit as u64);
            assert_eq!(stats.posted, 2 * limit as u64);
            assert_eq!(stats.applied, stats.posted);
            assert_eq!(stats.refused, 0);
            assert_eq!(stats.leaked, 0);
            assert_eq!(fixture.obligations.open_tickets(), 0);
            let state = fixture.state.lock().unwrap();
            assert!(state.region_was_closed(child_id));
            assert_eq!(state.pending_obligation_count(), 0);
            assert_eq!(state.leak_count(), 0);
        }
    }
}


fn spawn_native_cleanup_probe(
    fixture: &mut Fixture,
    future: impl Future<Output = u8> + Send + 'static,
) -> (TaskId, TaskHandle<u8>) {
    let (task, handle, effects) = {
        let mut state = fixture.state.lock().unwrap();
        let mut target = fixture.table.as_ref().map_or(AdmissionTaskTarget::Embedded, |table| {
            AdmissionTaskTarget::External(table.lock().unwrap())
        });
        state.create_task_with_deferred_spawn_effects_in(
            fixture.root, Budget::INFINITE, future, &mut target,
            &AdmissionRegionTarget::Embedded,
        ).unwrap()
    };
    effects.dispatch();
    fixture._scheduler.inject_ready(task, 50);
    (task, handle)
}

#[test]
fn native_async_finalizer_handoff_preserves_identity_and_rejects_retired_destination() {
    use crate::runtime::obligation_mailbox::{
        ObligationAdmissionError, ObligationTransferError,
    };

    for layout in [TableLayout::Embedded, TableLayout::Sharded, TableLayout::ExternalOnly] {
        let mut fixture = Fixture::new(layout);
        let child = fixture.open_child();
        let child_id = child.region_id();
        let retained = Arc::new(parking_lot::Mutex::new(None::<Cx>));
        let cleanup_retained = Arc::clone(&retained);
        let received = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cleanup_received = Arc::clone(&received);
        let (transfer, mut transferred) = crate::channel::oneshot::channel::<ObligationToken>();
        let (finish, mut finished) = crate::channel::oneshot::channel::<()>();
        {
            let mut state = fixture.state.lock().unwrap();
            let region = state.region(child_id).unwrap();
            let mut limits = region.limits();
            limits.max_obligations = Some(1);
            region.set_limits(limits);
            assert!(state.register_async_finalizer(child_id, async move {
                let cx = Cx::current().expect("real native finalizer context");
                *cleanup_retained.lock() = Some(cx.clone());
                let token = transferred.recv_uninterruptible().await.unwrap();
                assert_eq!(token.holder(), cx.task_id());
                assert_eq!(token.region(), cx.region_id());
                assert!(matches!(
                    cx.try_register_obligation_checked(ObligationKind::Lease, cx.task_id()),
                    Err(ObligationAdmissionError::LimitReached { limit: 1, live: 1 })
                ));
                cleanup_received.store(true, std::sync::atomic::Ordering::SeqCst);
                finished.recv_uninterruptible().await.unwrap();
                assert!(token.commit());
            }));
        }
        let probe = CloseProbe::install(
            &fixture.state, fixture.table.as_ref(), child_id, ClosePanic::None,
        );
        let mut close = std::pin::pin!(child.close_with_outcome());
        let mut poll = Context::from_waker(Waker::noop());
        assert!(close.as_mut().poll(&mut poll).is_pending());
        assert_eq!(fixture.worker.drain_region_commands(), 1);
        fixture.finish_healthy();
        let finalizer = fixture.worker.next_task().expect("finalizer is runnable");
        fixture.worker.execute(finalizer);
        let cleanup_cx = retained.lock().as_ref().unwrap().clone();
        assert_eq!(cleanup_cx.task_id(), finalizer);
        assert_eq!(
            fixture.state.lock().unwrap().region(child_id).unwrap().state(),
            crate::record::region::RegionState::Finalizing,
        );
        probe.assert_pending();

        let (published, mut publication) = crate::channel::oneshot::channel::<ObligationToken>();
        let (release_source, mut source_released) = crate::channel::oneshot::channel::<()>();
        let (source, mut source_handle) = spawn_native_cleanup_probe(&mut fixture, async move {
            let cx = Cx::current().expect("real native source context");
            let token = cx.try_register_obligation_checked(
                ObligationKind::Lease, cx.task_id(),
            ).unwrap().unwrap();
            published.send_blocking(token).unwrap();
            source_released.recv_uninterruptible().await.unwrap();
            41_u8
        });
        assert_eq!(fixture.worker.next_task(), Some(source));
        fixture.worker.execute(source);
        let token = publication.try_recv().unwrap();
        let original_ticket = token.ticket();
        assert_eq!(fixture.worker.drain_spawn_admissions(), 0);
        let original_id = fixture.obligations.ticket_binding(original_ticket).unwrap();
        let moved = token.try_transfer(&cleanup_cx).expect("live cleanup receives ownership");
        let destination_ticket = moved.ticket();
        assert_eq!(fixture.worker.drain_spawn_admissions(), 0);
        assert_eq!(fixture.obligations.ticket_binding(original_ticket), None);
        assert_eq!(fixture.obligations.ticket_binding(destination_ticket), Some(original_id));
        {
            let state = fixture.state.lock().unwrap();
            assert_eq!(state.region(fixture.root).unwrap().pending_obligations(), 0);
            assert_eq!(state.region(child_id).unwrap().pending_obligations(), 1);
            assert_eq!(state.region(child_id).unwrap().unapplied_obligation_count(), 1);
        }

        // The original native owner can retire without leaking the obligation
        // now owned by the still-running finalizer.
        release_source.send_blocking(()).unwrap();
        assert_eq!(fixture.worker.next_task(), Some(source));
        fixture.worker.execute(source);
        assert_eq!(source_handle.try_join().unwrap(), Some(41));
        transfer.send_blocking(moved).unwrap();
        assert_eq!(fixture.worker.next_task(), Some(finalizer));
        fixture.worker.execute(finalizer);
        assert!(received.load(std::sync::atomic::Ordering::SeqCst));
        probe.assert_pending();
        finish.send_blocking(()).unwrap();
        assert_eq!(fixture.worker.next_task(), Some(finalizer));
        fixture.worker.execute(finalizer);
        probe.assert_delivered();
        let receipt = match close.as_mut().poll(&mut poll) {
            Poll::Ready(Ok(receipt)) => receipt,
            result => panic!("transferred cleanup failed to retire: {result:?}"),
        };
        assert!(matches!(receipt.cleanup_outcome, Some(crate::types::Outcome::Ok(()))));

        // Reuse the actual scheduler/task arena after cleanup retirement. A
        // retained cleanup context must not admit into the retired generation;
        // a refused transfer returns the original live owner's token intact.
        let (replacement, mut replacement_handle) =
            spawn_native_cleanup_probe(&mut fixture, async move {
                let cx = Cx::current().expect("replacement native source context");
                assert_ne!(cx.task_id(), cleanup_cx.task_id());
                let token = cx.try_register_obligation_checked(
                    ObligationKind::Lease, cx.task_id(),
                ).unwrap().unwrap();
                let ticket = token.ticket();
                let failure = token.try_transfer(&cleanup_cx).unwrap_err();
                assert_eq!(
                    failure.reason(),
                    ObligationTransferError::Destination(ObligationAdmissionError::RegionClosed),
                );
                let (_, token) = failure.into_parts();
                assert_eq!(token.ticket(), ticket);
                assert_eq!(token.holder(), cx.task_id());
                assert!(token.commit());
                43_u8
            });
        assert_eq!(fixture.worker.next_task(), Some(replacement));
        fixture.worker.execute(replacement);
        assert_eq!(replacement_handle.try_join().unwrap(), Some(43));
        let stats = fixture.obligations.stats();
        assert_eq!(stats.reserved, 2);
        assert_eq!(stats.committed, 2);
        assert_eq!(stats.posted, 5);
        assert_eq!(stats.applied, stats.posted);
        assert_eq!(stats.refused, 0);
        assert_eq!(fixture.obligations.open_tickets(), 0);
        let state = fixture.state.lock().unwrap();
        assert!(state.region_was_closed(child_id));
        assert_eq!(state.pending_obligation_count(), 0);
        assert_eq!(state.leak_count(), 0);
        assert!(state.region(fixture.root).unwrap().task_ids().is_empty());
    }
}

