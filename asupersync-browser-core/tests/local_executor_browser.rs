//! Actual browser-host tests for the canonical Rust-future executor.
//! These exercise real Promise settlement and the host task queue; native
//! ledger tests cannot establish those properties.
#![cfg(target_arch = "wasm32")]

use asupersync::types::{
    WasmAbiOutcomeEnvelope, WasmAbiValue, WasmHandleRef, WasmScopeEnterRequest,
    WasmTaskSpawnRequest,
};
use asupersync_browser_core::local::{LocalExecutorConfig, spawn_local_future};
use asupersync_browser_core::{runtime_close, runtime_create, scope_close, scope_enter, task_join};
use std::cell::Cell;
use std::future::poll_fn;
use std::rc::Rc;
use std::task::Poll;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

fn ok(value: u64) -> WasmAbiOutcomeEnvelope {
    WasmAbiOutcomeEnvelope::Ok {
        value: WasmAbiValue::U64(value),
    }
}

struct Owners {
    runtime: WasmHandleRef,
    scope: WasmHandleRef,
}

impl Owners {
    fn new() -> Self {
        let runtime = serde_json::from_str(&runtime_create(None).unwrap()).unwrap();
        let scope = serde_json::from_str(
            &scope_enter(
                serde_json::to_string(&WasmScopeEnterRequest {
                    parent: runtime,
                    label: Some("real-rust-browser-futures".into()),
                })
                .unwrap(),
                None,
            )
            .unwrap(),
        )
        .unwrap();
        Self { runtime, scope }
    }

    fn request(&self) -> WasmTaskSpawnRequest {
        WasmTaskSpawnRequest {
            scope: self.scope,
            label: None,
            cancel_kind: None,
        }
    }
}

impl Drop for Owners {
    fn drop(&mut self) {
        runtime_close(serde_json::to_string(&self.runtime).unwrap(), None).unwrap();
    }
}

fn next_host_task() -> JsFuture {
    JsFuture::from(js_sys::Promise::new(&mut |resolve, reject| {
        let global = js_sys::global();
        let result = js_sys::Reflect::get(&global, &JsValue::from_str("setTimeout"))
            .and_then(|timer| timer.dyn_into::<js_sys::Function>())
            .and_then(|timer| timer.call2(&global, resolve.as_ref(), &JsValue::from_f64(0.0)));
        if let Err(error) = result {
            let _ = reject.call1(&JsValue::UNDEFINED, &error);
        }
    }))
}

#[wasm_bindgen_test]
async fn real_js_promise_resumes_a_non_send_rust_future_and_returns_its_value() {
    let owners = Owners::new();
    let entered = Rc::new(Cell::new(false));
    let observed = Rc::clone(&entered);
    let task = spawn_local_future(
        owners.request(),
        async move {
            observed.set(true);
            next_host_task().await.expect("actual timer-backed Promise");
            ok(37)
        },
        None,
    )
    .unwrap();
    assert!(!entered.get(), "admission must not poll inline");
    assert!(task_join(
        serde_json::to_string(&task.handle()).unwrap(),
        serde_json::to_string(&ok(999)).unwrap(),
        None,
    )
    .is_err());
    let result = task.await;
    assert!(entered.get());
    assert_eq!(result.outcome, ok(37));
    assert!(result.publication_error.is_none());
}

#[wasm_bindgen_test]
async fn scope_close_destroys_a_real_parked_js_future_without_another_poll() {
    struct DropProbe(Rc<Cell<usize>>);
    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let owners = Owners::new();
    let drops = Rc::new(Cell::new(0));
    let entered = Rc::new(Cell::new(false));
    let observed = Rc::clone(&entered);
    let probe = DropProbe(Rc::clone(&drops));
    let never_settled = js_sys::Promise::new(&mut |_resolve, _reject| {});
    let task = spawn_local_future(
        owners.request(),
        async move {
            let _probe = probe;
            observed.set(true);
            let _ = JsFuture::from(never_settled).await;
            ok(999)
        },
        None,
    )
    .unwrap();
    next_host_task().await.unwrap();
    assert!(entered.get(), "the actual Rust future must have reached its Promise await");
    assert_eq!(drops.get(), 0);
    scope_close(serde_json::to_string(&owners.scope).unwrap(), None).unwrap();
    assert_eq!(drops.get(), 1, "close must retire the pinned future synchronously");
    let result = task.await;
    assert!(matches!(result.outcome, WasmAbiOutcomeEnvelope::Cancelled { .. }));
    assert!(result.publication_error.is_none());
}

#[wasm_bindgen_test]
async fn a_self_waking_future_cannot_starve_a_real_host_task_callback() {
    let owners = Owners::new();
    let host_ran = Rc::new(Cell::new(false));
    let timer_seen = Rc::clone(&host_ran);
    // Queue a real host task before the busy executor starts. Merely making
    // another microtask runnable is not a valid fairness positive control.
    let timer = next_host_task();
    wasm_bindgen_futures::spawn_local(async move {
        timer.await.expect("host timer callback");
        timer_seen.set(true);
    });
    let polled = Rc::new(Cell::new(0));
    let count = Rc::clone(&polled);
    let host_seen = Rc::clone(&host_ran);
    let ceiling = LocalExecutorConfig::default().polls_per_turn * 8;
    let task = spawn_local_future(
        owners.request(),
        poll_fn(move |cx| {
            count.set(count.get() + 1);
            if host_seen.get() {
                Poll::Ready(ok(1))
            } else if count.get() >= ceiling {
                // A broken microtask-only driver finishes this negative path
                // instead of making the test hang forever.
                Poll::Ready(ok(0))
            } else {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }),
        None,
    )
    .unwrap();
    let result = task.await;
    assert_eq!(result.outcome, ok(1), "host callback was starved by Rust polling");
    assert!(host_ran.get());
    assert!(polled.get() < ceiling);
    assert!(result.publication_error.is_none());
}
