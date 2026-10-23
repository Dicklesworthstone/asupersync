//! Native legacy-worker mailbox observer regressions.
use super::*;
use crate::runtime::state::mailbox_observer_test_support::{
    assert_settled, mailbox_runtime, post_work,
};
use crate::sync::ContendedMutex;
use crate::types::Budget;
use std::sync::mpsc as probe;

#[test]
fn legacy_mailbox_observers_reenter_after_receipts_and_survive_panics() {
    for parked in [false, true] {
        for panic_task in [false, true] {
            for panic_callbacks in [false, true] {
                let (mut runtime, metrics, mailbox, _liveness) = mailbox_runtime(panic_callbacks);
                let root = runtime.create_root_region(Budget::INFINITE);
                let (release, receive) = crate::channel::oneshot::channel::<()>();
                let (task, mut handle) = runtime
                    .create_task(
                        root,
                        Budget::INFINITE,
                        post_work(parked.then_some(receive), panic_task),
                    )
                    .unwrap();
                let (healthy, mut healthy_handle) = runtime
                    .create_task(root, Budget::INFINITE, async { 19_u8 })
                    .unwrap();
                runtime.task_mut(task).unwrap().add_waiter(healthy);
                let state = Arc::new(ContendedMutex::new("runtime_state", runtime));
                metrics.arm(&state, &mailbox);
                let global = Arc::new(GlobalQueue::new());
                let worker = Worker::new(
                    0,
                    Vec::new(),
                    Arc::clone(&global),
                    Arc::clone(&state),
                    Arc::new(AtomicBool::new(false)),
                );
                std::thread::scope(|scope| {
                    let (done, observed) = probe::channel();
                    let (drive, commands) = probe::channel();
                    scope.spawn(move || {
                        worker.execute(task);
                        done.send(task).unwrap();
                        commands.recv().unwrap();
                        if parked {
                            assert_eq!(global.pop(), Some(task), "real oneshot wake");
                            worker.execute(task);
                        }
                        assert_eq!(global.pop(), Some(healthy), "published completion waiter");
                        worker.execute(healthy);
                        done.send(healthy).unwrap();
                    });
                    assert_eq!(observed.recv_timeout(Duration::from_secs(2)).unwrap(), task);
                    if parked {
                        metrics.assert_observed(&["created", "discharged", "created"]);
                        assert_eq!(state.lock().unwrap().pending_obligation_count(), 1);
                        release.send_blocking(()).unwrap();
                    }
                    drive.send(()).unwrap();
                    assert_eq!(
                        observed.recv_timeout(Duration::from_secs(2)).unwrap(),
                        healthy
                    );
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
        }
    }
}
