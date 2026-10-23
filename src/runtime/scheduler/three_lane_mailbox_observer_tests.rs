//! Native unified/sharded mailbox observer regressions.
use super::*;
use crate::runtime::state::{
    AdmissionRegionTarget, AdmissionTaskTarget,
    mailbox_observer_test_support::{assert_settled, mailbox_runtime, post_work},
};
use crate::types::Budget;
use std::sync::mpsc as probe;

fn run_mailbox_observers(worker_count: usize, sharded: bool, parked: bool, panic_task: bool) {
    let (mut runtime, metrics, mailbox, _liveness) = mailbox_runtime(true);
    let root = runtime.create_root_region(Budget::INFINITE);
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
    // Mint directly into the dispatching table. Moving an existing record
    // would revoke its checked holder admission and test a different path.
    let (task, mut handle, healthy, mut healthy_handle, first_effects, second_effects) = {
        let mut runtime = state.lock().unwrap();
        let mut target = task_table
            .as_ref()
            .map_or(AdmissionTaskTarget::Embedded, |table| {
                AdmissionTaskTarget::External(table.lock().unwrap())
            });
        let (task, handle, first_effects) = runtime
            .create_task_with_deferred_spawn_effects_in(
                root,
                Budget::INFINITE,
                post_work(parked.then_some(receive), panic_task),
                &mut target,
                &AdmissionRegionTarget::Embedded,
            )
            .unwrap();
        let (healthy, healthy_handle, second_effects) = runtime
            .create_task_with_deferred_spawn_effects_in(
                root,
                Budget::INFINITE,
                async { 19_u8 },
                &mut target,
                &AdmissionRegionTarget::Embedded,
            )
            .unwrap();
        match &mut target {
            AdmissionTaskTarget::Embedded => runtime.task_mut(task).unwrap().add_waiter(healthy),
            AdmissionTaskTarget::External(table) => {
                table.task_mut(task).unwrap().add_waiter(healthy)
            }
        }
        (
            task,
            handle,
            healthy,
            healthy_handle,
            first_effects,
            second_effects,
        )
    };
    first_effects.dispatch();
    second_effects.dispatch();
    metrics.arm(&state, &mailbox);
    let mut scheduler = match &shards {
        Some(shards) => ThreeLaneScheduler::new_with_sharded_state(
            worker_count,
            &state,
            shards,
            DEFAULT_CANCEL_STREAK_LIMIT,
            false,
            32,
        ),
        None => ThreeLaneScheduler::new_with_options(
            worker_count,
            &state,
            DEFAULT_CANCEL_STREAK_LIMIT,
            false,
            32,
        ),
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
                    // The normal worker loop drains posts between polls.
                    // Exercise that bounded production seam after Pending too.
                    worker.drain_spawn_admissions();
                    done.send(task).unwrap();
                }
            });
        }
        controls[0].send(true).unwrap();
        assert_eq!(observed.recv_timeout(Duration::from_secs(2)).unwrap(), task);
        let completing_worker = if parked { worker_count - 1 } else { 0 };
        if parked {
            metrics.assert_observed(&["created", "discharged", "created"]);
            assert_eq!(state.lock().unwrap().pending_obligation_count(), 1);
            release.send_blocking(()).unwrap();
            controls[completing_worker].send(true).unwrap();
            assert_eq!(observed.recv_timeout(Duration::from_secs(2)).unwrap(), task);
        }
        controls[completing_worker].send(true).unwrap();
        assert_eq!(
            observed.recv_timeout(Duration::from_secs(2)).unwrap(),
            healthy,
            "observer panics cannot suppress the waiter or kill its worker"
        );
        for control in controls {
            control.send(false).unwrap();
        }
    });
    let cx = crate::cx::Cx::for_testing();
    let result = futures_lite::future::block_on(handle.join(&cx));
    if panic_task {
        assert!(result.is_err(), "task panic remains observable");
    } else {
        assert_eq!(result.unwrap(), 73);
    }
    assert_eq!(
        futures_lite::future::block_on(healthy_handle.join(&cx)).unwrap(),
        19
    );
    metrics.assert_observed(&["created", "discharged", "created", "discharged"]);
    assert_settled(&mailbox);
    let runtime = state.lock().unwrap();
    assert_eq!(runtime.pending_obligation_count(), 0);
    assert!(runtime.region(root).unwrap().task_ids().is_empty());
}

#[test]
fn native_mailbox_observers_reenter_after_receipts_and_preserve_worker_liveness() {
    // Only one worker is commanded at a time, so a failed probe try-lock
    // witnesses delivery under its own lock rather than unrelated contention.
    for workers in [1, 2] {
        for sharded in [false, true] {
            for parked in [false, true] {
                for panic_task in [false, true] {
                    run_mailbox_observers(workers, sharded, parked, panic_task);
                }
            }
        }
    }
}
