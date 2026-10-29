//! Downstream compiler coverage for GH #86.
//!
//! Deliberately no recursion_limit attribute, HTTP imports, test-internals,
//! unsafe auto-trait implementations, or boxing before the Send obligation.
//! Cargo compiles this as a separate crate, not as part of asupersync's lib.
#![forbid(unsafe_code)]

use asupersync::Cx;
use asupersync::runtime::spawn_mailbox::SpawnRequest;
use std::future::{Future, pending};

fn require_send<T: Send>() {}
fn require_send_sync<T: Send + Sync>() {}
fn require_send_closure<F: FnOnce() + Send + 'static>(_: F) {}

/// Exercise the reported long auto-trait path, not just Cx in isolation.
pub fn assert_runtime_send_contracts() {
    require_send::<SpawnRequest>();
    require_send_sync::<Cx>();
}

/// Keep the whole context alive across suspension. Moving only one of its
/// fields into the future would not test the context's structural type graph.
pub fn cx_capturing_future(cx: Cx) -> impl Future<Output = ()> + Send + 'static {
    async move {
        pending::<()>().await;
        drop(cx);
    }
}

/// Also reach Cx indirectly through the spawn/admission/mailbox graph that
/// exposed the extra rustls depth in the reporter's compiler notes.
pub fn spawn_request_capturing_future(
    request: SpawnRequest,
) -> impl Future<Output = ()> + Send + 'static {
    async move {
        pending::<()>().await;
        drop(request);
    }
}

/// A blocking-pool-style closure must be Send before any runtime type erasure.
/// This is a compile contract; the deliberately pending futures are not run.
pub fn assert_capturing_closure_is_send(cx: Cx, request: SpawnRequest) {
    require_send_closure(move || {
        drop(cx_capturing_future(cx));
        drop(spawn_request_capturing_future(request));
    });
}

#[test]
fn public_runtime_types_are_send() {
    assert_runtime_send_contracts();
}

#[test]
fn cx_capturing_future_runs_on_attached_blocking_pool() {
    use asupersync::runtime::RuntimeBuilder;
    use std::future::poll_fn;
    use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
    use std::sync::{Arc, mpsc};
    use std::task::{Context, Poll, Waker};
    use std::thread;
    use std::time::Duration;

    const BOUND: Duration = Duration::from_secs(10);
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(1, 1)
        .build()
        .expect("runtime with a real blocking worker");
    // Always exercise bounded teardown, including when a worker or assertion
    // fails. The worker itself never waits for the runtime to make progress.
    let result = catch_unwind(AssertUnwindSafe(|| {
        runtime.block_on(async {
            let cx = Cx::current().expect("runtime-owned context");
            let expected = (cx.region_id(), cx.task_id());
            let pool = cx.blocking_pool_handle().expect("attached blocking pool");
            let caller = thread::current().id();
            let witness = Arc::new(());
            let released = Arc::downgrade(&witness);
            let (sender, receiver) = mpsc::channel();

            // Construct the concrete future here, before the pool imposes its
            // Send obligation. Retain the whole Cx across a real Pending poll;
            // do not route through a helper already returning impl Send.
            let future = async move {
                let mut suspended = false;
                poll_fn(|task| {
                    if suspended {
                        Poll::Ready(())
                    } else {
                        suspended = true;
                        task.waker().wake_by_ref();
                        Poll::Pending
                    }
                })
                .await;
                let observed = (cx.region_id(), cx.task_id());
                drop(cx);
                drop(witness);
                observed
            };
            let task = pool.spawn(move || {
                let mut future = std::pin::pin!(future);
                let mut context = Context::from_waker(Waker::noop());
                assert!(future.as_mut().poll(&mut context).is_pending());
                let Poll::Ready(observed) = future.as_mut().poll(&mut context) else {
                    panic!("the second poll must complete");
                };
                sender
                    .send((thread::current().id(), observed))
                    .expect("send worker observation");
            });
            assert!(task.wait_timeout(BOUND), "blocking task completes in time");
            let (worker, observed) = receiver
                .recv_timeout(BOUND)
                .expect("worker completes both polls without panicking");
            assert_ne!(worker, caller, "the real pool executes the future");
            assert_eq!(observed, expected, "the captured Cx retains its identity");
            assert!(released.upgrade().is_none(), "future captures are released");
            assert_eq!(pool.pending_count(), 0);
            assert_eq!(pool.busy_threads(), 0);
        });
        assert!(runtime.is_quiescent(), "runtime has no remaining live work");
    }));
    let shutdown = runtime.shutdown_timeout(BOUND);
    if let Err(panic) = result {
        resume_unwind(panic);
    }
    assert!(shutdown, "blocking worker exits within the shutdown bound");
}
