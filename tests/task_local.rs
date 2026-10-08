//! `task_local!`: values bound to one future while it runs, on the
//! multi-worker runtime. Each task sees only its own value across awaits and
//! worker migrations; scopes nest and restore; spawned tasks do not inherit;
//! an abandoned future is dropped inside its scope; panics restore the outer
//! value.

use asupersync::runtime::task_local::AccessError;
use asupersync::runtime::{RuntimeBuilder, yield_now};
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

asupersync::task_local! {
    static REQUEST_ID: u64;
    /// A non-`Clone` value, read by reference.
    pub static TENANT: Vec<String>;
}

async fn current_id() -> u64 {
    yield_now().await;
    REQUEST_ID.get()
}

#[test]
fn each_task_sees_its_own_value_across_awaits_and_workers() {
    let runtime = RuntimeBuilder::new()
        .worker_threads(4)
        .build()
        .expect("runtime");
    let handle = runtime.handle();
    let seen = runtime.block_on(async move {
        let mut tasks = Vec::new();
        for id in 0..64_u64 {
            tasks.push(handle.spawn(REQUEST_ID.scope(id, async move {
                let mut observed = Vec::new();
                for _ in 0..20 {
                    observed.push(current_id().await);
                }
                (id, observed)
            })));
        }
        let mut seen = Vec::new();
        for task in tasks {
            seen.push(task.await);
        }
        seen
    });
    for (id, observed) in seen {
        assert!(
            observed.iter().all(|value| *value == id),
            "{id}: {observed:?}"
        );
    }
    assert!(REQUEST_ID.try_get().is_err());
}

#[test]
fn scopes_nest_and_restore_and_spawned_tasks_do_not_inherit() {
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("runtime");
    let handle = runtime.handle();
    runtime.block_on(REQUEST_ID.scope(1, async move {
        assert_eq!(current_id().await, 1);
        let inner = REQUEST_ID
            .scope(2, async {
                let inner = current_id().await;
                TENANT
                    .scope(vec!["acme".to_owned()], async {
                        yield_now().await;
                        TENANT.with(|tenant| assert_eq!(tenant, &["acme"]));
                    })
                    .await;
                inner
            })
            .await;
        assert_eq!(inner, 2);
        assert_eq!(current_id().await, 1, "the outer value is back");
        assert!(TENANT.try_with(|_| ()).is_err());

        // A spawned task runs its own future, outside this scope.
        let child = handle.spawn(async { REQUEST_ID.try_get().ok() }).await;
        assert_eq!(child, None);
        // Passing the value on is explicit.
        let child = handle
            .spawn(REQUEST_ID.scope(REQUEST_ID.get(), current_id()))
            .await;
        assert_eq!(child, 1);
    }));
}

#[test]
fn an_abandoned_future_is_dropped_inside_its_scope() {
    struct ReadsOnDrop(Arc<AtomicU64>);
    impl Drop for ReadsOnDrop {
        fn drop(&mut self) {
            self.0
                .store(REQUEST_ID.try_get().unwrap_or(u64::MAX), Ordering::SeqCst);
        }
    }

    let dropped_with = Arc::new(AtomicU64::new(0));
    let guard = ReadsOnDrop(Arc::clone(&dropped_with));
    let scoped = REQUEST_ID.scope(42, async move {
        let _guard = guard;
        std::future::pending::<()>().await;
    });
    let mut scoped = Box::pin(scoped);
    // Poll once so the guard lives inside the future's state, then abandon it.
    let waker = std::task::Waker::noop();
    let mut context = std::task::Context::from_waker(waker);
    assert!(scoped.as_mut().poll(&mut context).is_pending());
    drop(scoped);
    assert_eq!(dropped_with.load(Ordering::SeqCst), 42);
    assert!(REQUEST_ID.try_get().is_err());
}

#[test]
fn sync_scope_take_value_and_panics() {
    let outer = REQUEST_ID.sync_scope(5, || {
        let unwound = catch_unwind(AssertUnwindSafe(|| {
            REQUEST_ID.sync_scope(6, || {
                assert_eq!(REQUEST_ID.get(), 6);
                panic!("inside the inner scope");
            })
        }));
        assert!(unwound.is_err());
        REQUEST_ID.get()
    });
    assert_eq!(outer, 5, "the panic restored the outer value");

    // Entering a scope of a key while its value is borrowed is refused.
    let refused = catch_unwind(|| {
        REQUEST_ID.sync_scope(7, || REQUEST_ID.with(|_| REQUEST_ID.sync_scope(8, || ())));
    });
    assert!(refused.is_err());
    assert!(REQUEST_ID.try_get().is_err());

    let mut scoped = Box::pin(REQUEST_ID.scope(9, async { REQUEST_ID.try_get().ok() }));
    assert_eq!(scoped.as_mut().take_value(), Some(9));
    assert_eq!(scoped.as_mut().take_value(), None);
    let runtime = RuntimeBuilder::current_thread().build().expect("runtime");
    assert_eq!(
        runtime.block_on(scoped),
        None,
        "taken before the future ran"
    );

    assert!(
        catch_unwind(|| REQUEST_ID.get()).is_err(),
        "get outside a scope panics"
    );
    let error: AccessError = REQUEST_ID.try_get().expect_err("unset");
    assert_eq!(error.to_string(), "task-local value not set");
}
