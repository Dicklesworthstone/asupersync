//! Native queued region closes publish functional notifications after unlock.
use super::*;
use crate::cx::{ChildRegion, ChildRegionSpec, Cx};
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

struct Fixture {
    state: Arc<ContendedMutex<RuntimeState>>,
    table: Option<Arc<ContendedMutex<TaskTable>>>,
    worker: ThreeLaneWorker,
    principal: Cx,
    root: RegionId,
    healthy: TaskId,
    healthy_handle: TaskHandle<u8>,
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
        let (healthy, healthy_handle, principal, effects) = {
            let mut runtime = state.lock().unwrap();
            let mut target = table.as_ref().map_or(AdmissionTaskTarget::Embedded, |table| {
                AdmissionTaskTarget::External(table.lock().unwrap())
            });
            let (task, handle, effects) = runtime
                .create_task_with_deferred_spawn_effects_in(
                    root,
                    Budget::INFINITE,
                    async { 19_u8 },
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
            _scheduler: scheduler,
            _liveness: liveness,
        }
    }

    fn open_child(&mut self) -> ChildRegion {
        open_child(&mut self.worker, &self.principal)
    }

    fn finish_healthy(&mut self) {
        let task = self.worker.next_task().expect("the ready task survived");
        assert_eq!(task, self.healthy);
        self.worker.execute(task);
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
