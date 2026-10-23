//! Current-thread caller retirement delivers functional close notifications.
use super::*;
use crate::runtime::state::close_wake_test_support::{ClosePanic, CloseProbe};

#[test]
fn caller_retirement_close_callbacks_reenter_current_thread_runtime_after_unlock() {
    for sharded in [false, true] {
        for close_panic in [ClosePanic::None, ClosePanic::Wake, ClosePanic::Drop] {
            let runtime = RuntimeBuilder::current_thread()
                .with_sharded_state(sharded)
                .build()
                .unwrap();
            // The outer drive owns the current-thread worker loan. A background
            // driver cannot race these deterministic reentry probes.
            runtime.block_on(async {
                let root = runtime.request_cx_with_budget(Budget::INFINITE);
                let child = runtime
                    .inner
                    .state
                    .lock()
                    .unwrap()
                    .create_child_region(root.region_id(), Budget::INFINITE)
                    .unwrap();
                let parent = crate::cx::Cx::new(child, root.task_id(), Budget::INFINITE);
                let registration = CallerTaskRegistration::new(&runtime.inner, &parent).unwrap();
                let table = runtime.inner.scheduler.dispatch_task_table();
                let close_probe =
                    CloseProbe::install(&runtime.inner.state, table.as_ref(), child, close_panic);
                assert!(
                    runtime
                        .inner
                        .state
                        .lock()
                        .unwrap()
                        .region(child)
                        .unwrap()
                        .begin_close(None)
                );
                drop(registration);
                close_probe.assert_delivered();
            });
            assert_eq!(
                runtime.block_on(async { 19_u8 }),
                19,
                "the current-thread worker remains usable after hostile close callbacks"
            );
        }
    }
}
