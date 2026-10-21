//! Real browser-network admission and retirement across body ownership.
use crate::fetch::{FetchBytesError, FetchBytesLimits};
use asupersync::types::{WasmFetchRequest, WasmHandleRef, WasmScopeEnterRequest};
use std::future::Future;
use std::task::{Context, Poll, Waker};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_test::*;

struct Owners { runtime: WasmHandleRef, scope: WasmHandleRef, url: String }
impl Owners {
    fn new() -> Self {
        let location = js_sys::Reflect::get(&js_sys::global(), &JsValue::from_str("location")).unwrap();
        let href = js_sys::Reflect::get(&location, &JsValue::from_str("href")).unwrap().as_string().unwrap();
        let (url, origin) = crate::canonicalize_browser_http_url(&href).unwrap();
        let runtime = serde_json::from_str(&crate::runtime_create_impl(Some(serde_json::json!({
            "fetchAuthority": { "allowedOrigins": [origin], "allowedMethods": ["GET"] }
        }).to_string())).unwrap()).unwrap();
        let scope = crate::with_dispatcher(|d| d.scope_enter(&WasmScopeEnterRequest {
            parent: runtime, label: None,
        }, None)).unwrap();
        Self { runtime, scope, url }
    }
    fn request(&self) -> WasmFetchRequest {
        WasmFetchRequest { scope: self.scope, url: self.url.clone(), method: "GET".into(), credentials: false, body: None }
    }
}
impl Drop for Owners {
    fn drop(&mut self) {
        if crate::dispatcher_handle_is_live(&self.runtime) {
            crate::runtime_close_impl(serde_json::to_string(&self.runtime).unwrap(), None).unwrap();
        }
    }
}

#[wasm_bindgen_test]
async fn client_stream_headers_hold_shared_credit_and_eof_returns_it() {
    let owners = Owners::new();
    let client = crate::fetch::FetchBytesClient::new(FetchBytesLimits::new(0, 4_194_304, 4096), 1);
    let clone = client.clone();
    let mut body = client.stream(owners.request(), 4_194_304, None).await.unwrap();
    assert_eq!(clone.in_flight(), 1);
    assert!(matches!(clone.fetch(owners.request(), None).await,
        Err(FetchBytesError::InFlightLimit { limit: 1 })));
    assert!(matches!(clone.stream(owners.request(), 4_194_304, None).await,
        Err(FetchBytesError::InFlightLimit { limit: 1 })));
    let mut received = 0;
    while let Some(chunk) = body.next_chunk().await.unwrap() { received += chunk.len(); }
    assert!(received > 0);
    assert_eq!(body.received_bytes(), received);
    assert_eq!(client.in_flight(), 0, "completed body remains retained");
    assert_eq!(body.next_chunk().await.unwrap(), None);
    let replacement = clone.stream(owners.request(), 4_194_304, None).await.unwrap();
    assert_eq!(client.in_flight(), 1);
    drop(replacement);
    assert_eq!(client.in_flight(), 0);
}

#[wasm_bindgen_test]
async fn dropping_client_body_keeps_credit_during_reentrant_abort_listener() {
    let owners = Owners::new();
    let client = crate::fetch::FetchBytesClient::new(FetchBytesLimits::new(0, 4_194_304, 4096), 1);
    let before = crate::INFLIGHT_FETCHES.with(|f| f.borrow().keys().copied().collect::<std::collections::HashSet<_>>());
    let body = client.stream(owners.request(), 4_194_304, None).await.unwrap();
    let (handle, controller) = crate::INFLIGHT_FETCHES.with(|f| f.borrow().iter()
        .find(|(h, _)| !before.contains(*h)).map(|(h, c)| (*h, c.clone())).unwrap());
    let observed = std::rc::Rc::new(std::cell::Cell::new(false));
    let seen = std::rc::Rc::clone(&observed);
    let clone = client.clone();
    let request = owners.request();
    let callback = wasm_bindgen::closure::Closure::wrap(Box::new(move |_event: web_sys::Event| {
        assert_eq!(clone.in_flight(), 1);
        let mut replacement = Box::pin(clone.stream(request.clone(), 4_194_304, None));
        assert!(matches!(replacement.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(FetchBytesError::InFlightLimit { limit: 1 }))));
        seen.set(true);
    }) as Box<dyn FnMut(web_sys::Event)>);
    controller.signal().set_onabort(Some(callback.as_ref().unchecked_ref()));
    drop(body);
    controller.signal().set_onabort(None);
    assert!(observed.get());
    assert!(controller.signal().aborted());
    assert!(!crate::dispatcher_handle_is_live(&handle));
    assert_eq!(client.in_flight(), 0);
}

#[wasm_bindgen_test]
async fn client_stream_chunk_failure_returns_capacity_before_body_drop() {
    let owners = Owners::new();
    let client = crate::fetch::FetchBytesClient::new(FetchBytesLimits::new(0, 4_194_304, 4096), 1);
    let mut body = client.stream(owners.request(), 0, None).await.unwrap();
    let error = loop {
        match body.next_chunk().await {
            Ok(Some(chunk)) => assert!(chunk.is_empty()),
            Ok(None) => panic!("the real runner page must contain a body"),
            Err(error) => break error,
        }
    };
    assert_eq!(error, FetchBytesError::ChunkLimit { limit: 0 });
    assert_eq!(client.in_flight(), 0);
    assert_eq!(body.next_chunk().await, Err(error));
}

#[wasm_bindgen_test]
fn dropping_client_stream_during_actual_pending_headers_aborts_and_returns_credit() {
    let owners = Owners::new();
    let client = crate::fetch::FetchBytesClient::new(FetchBytesLimits::new(0, 4_194_304, 4096), 1);
    let before = crate::INFLIGHT_FETCHES.with(|f| f.borrow().keys().copied().collect::<std::collections::HashSet<_>>());
    let mut opening = Box::pin(client.stream(owners.request(), 4_194_304, None));
    assert!(opening.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
    let (handle, controller) = crate::INFLIGHT_FETCHES.with(|f| f.borrow().iter()
        .find(|(h, _)| !before.contains(*h)).map(|(h, c)| (*h, c.clone())).unwrap());
    assert_eq!(client.in_flight(), 1);
    drop(opening);
    assert!(controller.signal().aborted());
    assert!(!crate::dispatcher_handle_is_live(&handle));
    assert_eq!(client.in_flight(), 0);
}
