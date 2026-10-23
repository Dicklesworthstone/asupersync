//! Current-thread and caller-polled retirement observer boundaries.
use super::*;
use crate::runtime::state::mailbox_observer_test_support::{
    MailboxLifecycleMetrics, assert_settled, post_work,
};

#[test]
fn block_on_and_caller_retirement_deliver_mailbox_observers_after_unlock() {
    for sharded in [false, true] {
        for caller_polled in [false, true] {
            for panic_callbacks in [false, true] {
                let metrics = MailboxLifecycleMetrics::new(panic_callbacks);
                let mut builder = RuntimeBuilder::current_thread().with_sharded_state(sharded);
                builder.config.metrics_provider = metrics.clone();
                let runtime = builder.build().unwrap();
                let mailbox = runtime
                    .inner
                    .state
                    .lock()
                    .unwrap()
                    .obligation_gateway()
                    .unwrap()
                    .mailbox()
                    .clone();
                metrics.arm(&runtime.inner.state, &mailbox);
                if caller_polled {
                    // Hold the worker loan in the outer drive so the
                    // background worker cannot drain the mailbox before this
                    // actual caller-polled registration/retirement guard.
                    runtime.block_on(async {
                        let parent = runtime.request_cx_with_budget(Budget::INFINITE);
                        let registration =
                            CallerTaskRegistration::new(&runtime.inner, &parent).unwrap();
                        {
                            let _cx = crate::cx::Cx::set_current(Some(registration.cx.clone()));
                            assert_eq!(futures_lite::future::block_on(post_work(None, false)), 73);
                        }
                        drop(registration);
                    });
                } else {
                    assert_eq!(runtime.block_on(post_work(None, false)), 73);
                }
                metrics.assert_observed(&["created", "discharged", "created", "discharged"]);
                assert_settled(&mailbox);
                assert_eq!(
                    runtime
                        .inner
                        .state
                        .lock()
                        .unwrap()
                        .pending_obligation_count(),
                    0
                );
                assert_eq!(runtime.block_on(async { 19_u8 }), 19);
            }
        }
    }
}
