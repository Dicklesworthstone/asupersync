//! Completion-driven region close delivery on native embedded and sharded workers.
use super::*;
use crate::runtime::state::{
    AdmissionRegionTarget, AdmissionTaskTarget,
    close_wake_test_support::{ClosePanic, CloseProbe, RetirementProbe, close_work},
};
use crate::types::Budget;
use std::sync::mpsc as probe;

fn run_close_wakes(
    sharded: bool,
    parked: bool,
    panic_task: bool,
    close_panic: ClosePanic,
    retirement_panic: ClosePanic,
) {
    let mut runtime = RuntimeState::new();
    let root = runtime.create_root_region(Budget::INFINITE);
    let child = runtime.create_child_region(root, Budget::INFINITE).unwrap();
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
    let (release, receive) = crate::channel::oneshot::channel::<()>();
    let (task, mut handle, healthy, mut healthy_handle, barrier, effects, healthy_effects) = {
        let mut runtime = state.lock().unwrap();
        let mut target = task_table
            .as_ref()
            .map_or(AdmissionTaskTarget::Embedded, |table| {
                AdmissionTaskTarget::External(table.lock().unwrap())
            });
        let (task, handle, effects) = runtime
            .create_task_with_deferred_spawn_effects_in(
                child,
                Budget::INFINITE,
                close_work(parked.then_some(receive), panic_task),
                &mut target,
                &AdmissionRegionTarget::Embedded,
            )
            .unwrap();
        let (healthy, healthy_handle, healthy_effects) = runtime
            .create_task_with_deferred_spawn_effects_in(
                root,
                Budget::INFINITE,
                async { 19_u8 },
                &mut target,
                &AdmissionRegionTarget::Embedded,
            )
            .unwrap();
        let record = match &mut target {
            AdmissionTaskTarget::Embedded => runtime.task_mut(task).unwrap(),
            AdmissionTaskTarget::External(table) => table.task_mut(task).unwrap(),
        };
        record.add_waiter(healthy);
        // The direct state-task API exposes an already-open handle. Install
        // the same pending Cx barrier used by mailbox admission so this worker
        // fixture also exercises its real post-lock retirement-wake boundary.
        let barrier = crate::runtime::task_handle::RetirementBarrier::pending();
        record
            .cx
            .as_ref()
            .unwrap()
            .install_retirement_barrier(Arc::clone(&barrier));
        (
            task,
            handle,
            healthy,
            healthy_handle,
            barrier,
            effects,
            healthy_effects,
        )
    };
    effects.dispatch();
    healthy_effects.dispatch();
    let close_probe = CloseProbe::install(&state, task_table.as_ref(), child, close_panic);
    let retirement_probe = RetirementProbe::arm(&barrier, retirement_panic);
    assert!(
        state
            .lock()
            .unwrap()
            .region(child)
            .unwrap()
            .begin_close(None)
    );
    let mut scheduler = match &shards {
        Some(shards) => ThreeLaneScheduler::new_with_sharded_state(
            2,
            &state,
            shards,
            DEFAULT_CANCEL_STREAK_LIMIT,
            false,
            32,
        ),
        None => {
            ThreeLaneScheduler::new_with_options(2, &state, DEFAULT_CANCEL_STREAK_LIMIT, false, 32)
        }
    };
    scheduler.inject_ready(task, 50);
    std::thread::scope(|scope| {
        let (done, observed) = probe::channel();
        let mut controls = Vec::new();
        for mut worker in scheduler.take_workers() {
            let (control, commands) = probe::channel::<bool>();
            controls.push(control);
            let done = done.clone();
            scope.spawn(move || {
                while commands.recv().unwrap_or(false) {
                    let task = worker.next_task().expect("witnessed ready task");
                    worker.execute(task);
                    done.send(task).unwrap();
                }
            });
        }
        controls[0].send(true).unwrap();
        assert_eq!(observed.recv_timeout(Duration::from_secs(2)).unwrap(), task);
        let completing_worker = usize::from(parked);
        if parked {
            close_probe.assert_pending();
            release.send_blocking(()).unwrap();
            controls[completing_worker].send(true).unwrap();
            assert_eq!(observed.recv_timeout(Duration::from_secs(2)).unwrap(), task);
        }
        controls[completing_worker].send(true).unwrap();
        assert_eq!(
            observed.recv_timeout(Duration::from_secs(2)).unwrap(),
            healthy,
            "hostile callbacks cannot lose the dependent or kill its worker"
        );
        for control in controls {
            control.send(false).unwrap();
        }
    });
    close_probe.assert_delivered();
    retirement_probe.assert_delivered();
    assert!(barrier.is_open());
    let cx = crate::cx::Cx::for_testing();
    let result = futures_lite::future::block_on(handle.join(&cx));
    if panic_task {
        assert!(result.is_err());
    } else {
        assert_eq!(result.unwrap(), 73);
    }
    assert_eq!(
        futures_lite::future::block_on(healthy_handle.join(&cx)).unwrap(),
        19
    );
    let runtime = state.lock().unwrap();
    assert!(runtime.region_was_closed(child));
    assert_eq!(runtime.pending_obligation_count(), 0);
    assert!(runtime.region(root).unwrap().task_ids().is_empty());
}

#[test]
fn native_close_wakers_reenter_after_retirement_and_survive_callback_panics() {
    for sharded in [false, true] {
        for panic_task in [false, true] {
            for close_panic in [ClosePanic::None, ClosePanic::Wake, ClosePanic::Drop] {
                run_close_wakes(sharded, true, panic_task, close_panic, ClosePanic::None);
            }
        }
    }
}

#[test]
fn native_retirement_waker_panics_cannot_discard_later_region_close_notifications() {
    for sharded in [false, true] {
        for panic_task in [false, true] {
            for retirement_panic in [ClosePanic::Wake, ClosePanic::Drop] {
                run_close_wakes(
                    sharded,
                    false,
                    panic_task,
                    ClosePanic::None,
                    retirement_panic,
                );
            }
        }
    }
}

#[test]
fn close_wakes_captured_before_a_parent_leak_panic_survive_native_unwind() {
    for sharded in [false, true] {
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
        let (task, mut handle, healthy, mut healthy_handle) = {
            let mut runtime = state.lock().unwrap();
            let mut target = task_table
                .as_ref()
                .map_or(AdmissionTaskTarget::Embedded, |table| {
                    AdmissionTaskTarget::External(table.lock().unwrap())
                });
            let (task, handle, effects) = runtime
                .create_task_with_deferred_spawn_effects_in(
                    child,
                    Budget::INFINITE,
                    async { 73_u8 },
                    &mut target,
                    &AdmissionRegionTarget::Embedded,
                )
                .unwrap();
            let (healthy, healthy_handle, healthy_effects) = runtime
                .create_task_with_deferred_spawn_effects_in(
                    root,
                    Budget::INFINITE,
                    async { 19_u8 },
                    &mut target,
                    &AdmissionRegionTarget::Embedded,
                )
                .unwrap();
            // Construct an actual admitted obligation, then inject the
            // missing-holder invariant failure that region leak recovery is
            // designed to diagnose. The child's completion must first close
            // the child, then encounter this orphan while advancing its parent.
            let (orphan, orphan_handle, orphan_cx, orphan_sender, orphan_effects) = runtime
                .create_task_infrastructure_in::<()>(
                    &crate::cx::Cx::for_testing(),
                    parent,
                    Budget::INFINITE,
                    false,
                    &mut target,
                    &AdmissionRegionTarget::Embedded,
                )
                .unwrap();
            drop(target);
            runtime
                .create_obligation(
                    crate::record::ObligationKind::SendPermit,
                    orphan,
                    parent,
                    None,
                )
                .unwrap();
            let orphan_record = match task_table.as_ref() {
                Some(table) => table.lock().unwrap().remove_task(orphan),
                None => runtime.tasks.remove_task(orphan),
            };
            runtime.region(parent).unwrap().remove_task(orphan);
            drop(runtime);
            drop((orphan_record, orphan_handle, orphan_cx, orphan_sender));
            effects.dispatch();
            healthy_effects.dispatch();
            orphan_effects.dispatch();
            (task, handle, healthy, healthy_handle)
        };
        let close_probe = CloseProbe::install(&state, task_table.as_ref(), child, ClosePanic::None);
        {
            let runtime = state.lock().unwrap();
            assert!(runtime.region(child).unwrap().begin_close(None));
            assert!(runtime.region(parent).unwrap().begin_close(None));
        }
        let mut scheduler = match &shards {
            Some(shards) => ThreeLaneScheduler::new_with_sharded_state(
                1,
                &state,
                shards,
                DEFAULT_CANCEL_STREAK_LIMIT,
                false,
                32,
            ),
            None => ThreeLaneScheduler::new_with_options(
                1,
                &state,
                DEFAULT_CANCEL_STREAK_LIMIT,
                false,
                32,
            ),
        };
        let mut worker = scheduler.take_workers().pop().unwrap();
        let (done, observed) = probe::channel();
        std::thread::scope(|scope| {
            scope.spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    worker.execute(task);
                }));
                assert!(
                    result.is_err(),
                    "the configured parent leak panic is exercised"
                );
                if let Err(payload) = result {
                    std::mem::forget(payload);
                }
                worker.execute(healthy);
                done.send(()).unwrap();
            });
            observed.recv_timeout(Duration::from_secs(2)).unwrap();
        });
        close_probe.assert_delivered();
        let cx = crate::cx::Cx::for_testing();
        assert_eq!(
            futures_lite::future::block_on(handle.join(&cx)).unwrap(),
            73
        );
        assert_eq!(
            futures_lite::future::block_on(healthy_handle.join(&cx)).unwrap(),
            19
        );
        let runtime = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(runtime.region_was_closed(child));
        assert!(runtime.region_was_closed(parent));
        assert_eq!(runtime.pending_obligation_count(), 0);
    }
}
