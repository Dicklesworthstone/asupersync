//! Minimal tests to verify SharedLabHandle behavior.

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use asupersync::runtime::TaskHandle;
use asupersync::types::Budget;
use parking_lot::Mutex;

// -- LabYieldOnce (copied from fixtures) --

struct LabYieldOnce {
    yielded: bool,
}

impl Future for LabYieldOnce {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.yielded {
            Poll::Ready(())
        } else {
            self.yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

fn lab_yield_once() -> LabYieldOnce {
    LabYieldOnce { yielded: false }
}

// -- SharedLabHandle --

#[allow(dead_code)]
enum LabJoinState {
    Empty,
    InFlight,
    Ready(BTreeSet<String>),
}

struct SharedLabInner {
    handle: TaskHandle<BTreeSet<String>>,
    state: Mutex<LabJoinState>,
}

#[derive(Clone)]
struct SharedLabHandle {
    inner: std::sync::Arc<SharedLabInner>,
}

impl SharedLabHandle {
    fn new(handle: TaskHandle<BTreeSet<String>>) -> Self {
        Self {
            inner: std::sync::Arc::new(SharedLabInner {
                handle,
                state: Mutex::new(LabJoinState::Empty),
            }),
        }
    }

    fn try_join_probe(&self) -> Option<BTreeSet<String>> {
        let mut state = self.inner.state.lock();
        match &*state {
            LabJoinState::Ready(result) => {
                let out = result.clone();
                drop(state);
                Some(out)
            }
            LabJoinState::InFlight => None,
            LabJoinState::Empty => match self.inner.handle.try_join() {
                Ok(Some(result)) => {
                    let output = result.clone();
                    *state = LabJoinState::Ready(result);
                    drop(state);
                    Some(output)
                }
                Ok(None) => None,
                Err(_) => {
                    *state = LabJoinState::Ready(BTreeSet::new());
                    drop(state);
                    Some(BTreeSet::new())
                }
            },
        }
    }
}

#[test]
fn shared_handle_finds_completed_value() {
    asupersync::test_utils::init_test_logging();

    asupersync::lab::runtime::test(42, |runtime| {
        let region = runtime.state.create_root_region(Budget::INFINITE);

        let (tid, raw_handle) = {
            let future = async move {
                lab_yield_once().await;
                let mut set = BTreeSet::new();
                set.insert("hello".to_string());
                set
            };
            runtime
                .state
                .create_task(region, Budget::INFINITE, future)
                .expect("spawn leaf")
        };

        let shared = SharedLabHandle::new(raw_handle);

        assert!(
            shared.try_join_probe().is_none(),
            "should be None before run"
        );

        {
            let mut sched = runtime.scheduler.lock();
            sched.schedule(tid, 0);
        }
        runtime.run_until_quiescent();

        let result = shared.try_join_probe();
        assert!(result.is_some(), "should find value after quiescence");
        assert!(result.unwrap().contains("hello"));
    });
}

/// Simulate the race driver pattern: a parent task polls children via
/// try_join_probe in a loop, yielding between iterations.
#[test]
fn shared_handle_polling_from_task() {
    asupersync::test_utils::init_test_logging();

    asupersync::lab::runtime::test(42, |runtime| {
        let region = runtime.state.create_root_region(Budget::INFINITE);

        // Create leaf task.
        let (leaf_tid, leaf_handle) = {
            let future = async move {
                lab_yield_once().await;
                let mut set = BTreeSet::new();
                set.insert("leaf".to_string());
                set
            };
            runtime
                .state
                .create_task(region, Budget::INFINITE, future)
                .expect("spawn leaf")
        };

        let shared = SharedLabHandle::new(leaf_handle);

        // Create a "race driver" task that polls the shared handle.
        let (driver_tid, driver_handle) = {
            let future = async move {
                let mut iters = 0u32;
                loop {
                    iters += 1;
                    assert!(iters <= 100, "polling loop stuck after {iters} iters");
                    if let Some(result) = shared.try_join_probe() {
                        return result;
                    }
                    lab_yield_once().await;
                }
            };
            runtime
                .state
                .create_task(region, Budget::INFINITE, future)
                .expect("spawn driver")
        };

        // Schedule both tasks.
        {
            let mut sched = runtime.scheduler.lock();
            sched.schedule(leaf_tid, 0);
            sched.schedule(driver_tid, 0);
        }

        runtime.run_until_quiescent();
        assert!(runtime.is_quiescent(), "must be quiescent");

        let result = driver_handle
            .try_join()
            .expect("try_join ok")
            .expect("should be ready");
        assert!(result.contains("leaf"));
    });
}
