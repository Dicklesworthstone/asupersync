//! Close notification liveness at the legacy native worker boundary.
use super::*;
use crate::runtime::state::close_wake_test_support::{ClosePanic, CloseProbe, close_work};
use crate::sync::ContendedMutex;
use crate::types::Budget;
use std::sync::mpsc as probe;

#[test]
fn legacy_completion_defers_close_wake_and_drop_callbacks_until_unlock() {
    for panic_task in [false, true] {
        for close_panic in [ClosePanic::None, ClosePanic::Wake, ClosePanic::Drop] {
            let mut runtime = RuntimeState::new();
            let root = runtime.create_root_region(Budget::INFINITE);
            let child = runtime.create_child_region(root, Budget::INFINITE).unwrap();
            let (release, receive) = crate::channel::oneshot::channel::<()>();
            let (task, mut handle) = runtime
                .create_task(
                    child,
                    Budget::INFINITE,
                    close_work(Some(receive), panic_task),
                )
                .unwrap();
            let (healthy, mut healthy_handle) = runtime
                .create_task(root, Budget::INFINITE, async { 19_u8 })
                .unwrap();
            runtime.task_mut(task).unwrap().add_waiter(healthy);
            let state = Arc::new(ContendedMutex::new("runtime_state", runtime));
            let close_probe = CloseProbe::install(&state, None, child, close_panic);
            assert!(
                state
                    .lock()
                    .unwrap()
                    .region(child)
                    .unwrap()
                    .begin_close(None)
            );
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
                    assert_eq!(global.pop(), Some(task), "oneshot wake");
                    worker.execute(task);
                    assert_eq!(global.pop(), Some(healthy), "completion waiter");
                    worker.execute(healthy);
                    done.send(healthy).unwrap();
                });
                assert_eq!(observed.recv_timeout(Duration::from_secs(2)).unwrap(), task);
                close_probe.assert_pending();
                release.send_blocking(()).unwrap();
                drive.send(()).unwrap();
                assert_eq!(
                    observed.recv_timeout(Duration::from_secs(2)).unwrap(),
                    healthy
                );
            });
            close_probe.assert_delivered();
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
            assert!(state.lock().unwrap().region_was_closed(child));
        }
    }
}
