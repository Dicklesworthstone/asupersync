//! Browser host driver. No Rust task future is owned by the host callback: the
//! scope-owned executor retains them and the driver holds only a weak reference.
use super::{DriveState, Executor, fail_all, poll_executor};
use std::cell::RefCell;
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::rc::{Rc, Weak};
use std::sync::Arc;
use std::task::{Context, Poll};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

pub(super) fn ensure_driver(executor: &Rc<RefCell<Executor>>) {
    let epoch = {
        let mut state = executor.borrow_mut();
        if state.driver_running { return; }
        let Some(epoch) = state.driver_epoch.checked_add(1) else {
            drop(state);
            fail_all(executor, "local executor driver identity exhausted");
            return;
        };
        state.driver_epoch = epoch;
        state.driver_running = true;
        epoch
    };
    wasm_bindgen_futures::spawn_local(Driver {
        executor: Rc::downgrade(executor), epoch, yielding: None,
    });
}

struct Driver {
    executor: Weak<RefCell<Executor>>,
    epoch: u64,
    yielding: Option<Pin<Box<JsFuture>>>,
}

// A microtask-only self-wake loop can starve network/UI callbacks. Promise
// settlement is scheduled by the host's task queue after each busy quantum.
// The callback captures neither the executor nor any user future.
fn next_host_turn() -> JsFuture {
    let promise = js_sys::Promise::new(&mut |resolve, reject| {
        let global = js_sys::global();
        let result = js_sys::Reflect::get(&global, &JsValue::from_str("setTimeout"))
            .and_then(|value| value.dyn_into::<js_sys::Function>())
            .and_then(|timer| timer.call2(&global, resolve.as_ref(), &JsValue::from_f64(0.0)));
        if let Err(error) = result {
            let _ = reject.call1(&JsValue::UNDEFINED, &error);
        }
    });
    JsFuture::from(promise)
}

fn stop(executor: &Rc<RefCell<Executor>>, epoch: u64) {
    let signal = {
        let mut state = executor.borrow_mut();
        if state.driver_epoch != epoch { return; }
        state.driver_running = false;
        Arc::clone(&state.signal)
    };
    // If dropping the old waker spawns work, admission can now start a NEW
    // driver. The epoch prevents this retiring driver from clearing that one.
    signal.clear();
}

impl Driver {
    fn poll_driver(&mut self, executor: &Rc<RefCell<Executor>>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self;
        if executor.borrow().driver_epoch != this.epoch { return Poll::Ready(()); }
        if executor.borrow().tasks.is_empty() {
            stop(executor, this.epoch);
            return Poll::Ready(());
        }
        if let Some(yielding) = this.yielding.as_mut() {
            match yielding.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(_)) => this.yielding = None,
                Poll::Ready(Err(_)) => {
                    fail_all(executor, "browser task-queue scheduling failed");
                    stop(executor, this.epoch);
                    return Poll::Ready(());
                }
            }
        }
        match poll_executor(executor, cx) {
            DriveState::Empty => {
                stop(executor, this.epoch);
                Poll::Ready(())
            }
            DriveState::Parked => Poll::Pending,
            DriveState::Runnable => {
                this.yielding = Some(Box::pin(next_host_turn()));
                // Schedule one continuation to register on the promise.
                // Inner-future wakeups cannot bypass the host-turn gate, and
                // an already-settled JsFuture is consumed exactly once.
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
}

impl Future for Driver {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        let Some(executor) = this.executor.upgrade() else {
            return Poll::Ready(());
        };
        match catch_unwind(AssertUnwindSafe(|| this.poll_driver(&executor, cx))) {
            Ok(result) => result,
            Err(payload) => {
                // User poll/destructor panics already become task outcomes.
                // A remaining scheduler/waker panic must not leave the realm
                // marked as driven while its only driver is unwinding.
                let cleanup = catch_unwind(AssertUnwindSafe(|| {
                    fail_all(&executor, "browser local driver callback panicked");
                }));
                stop(&executor, this.epoch);
                drop(cleanup);
                std::panic::resume_unwind(payload);
            }
        }
    }
}
