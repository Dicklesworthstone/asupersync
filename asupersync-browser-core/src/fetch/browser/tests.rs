//! Real browser fetch journeys plus real ReadableStream body-decoder fixtures.
//! Constructed response fixtures do not claim network interoperability.
use super::*;
use crate::fetch::{fetch_bytes as public_fetch_bytes, FetchBytesResponse};
use asupersync::types::{WasmScopeEnterRequest, WasmTaskCancelRequest, WasmTaskSpawnRequest};
use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::future::{Future, poll_fn};
use std::rc::Rc;
use std::task::{Context, Waker};
use wasm_bindgen::closure::Closure;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen::prelude::wasm_bindgen(inline_js = r#"
export function streamResponse(chunks, status) {
    return new Response(new ReadableStream({
        start(controller) {
            for (const chunk of chunks) controller.enqueue(chunk);
            controller.close();
        }
    }), {status});
}
export function emptyChunkResponse() {
    return new Response(new ReadableStream({
        pull(controller) { controller.enqueue(new Uint8Array()); }
    }));
}
export function parkedResponse() {
    return new Response(new ReadableStream());
}
export function erroredResponse() {
    return new Response(new ReadableStream({
        start(controller) { controller.error('private rejection payload'); }
    }));
}
"#)]
extern "C" {
    #[wasm_bindgen(js_name = streamResponse)]
    fn stream_response(chunks: &js_sys::Array, status: u16) -> Response;
    #[wasm_bindgen(js_name = emptyChunkResponse)]
    fn empty_chunk_response() -> Response;
    #[wasm_bindgen(js_name = parkedResponse)]
    fn parked_response() -> Response;
    #[wasm_bindgen(js_name = erroredResponse)]
    fn errored_response() -> Response;
}

fn limits() -> FetchBytesLimits { FetchBytesLimits::new(64, 2 * 1024 * 1024, 4096) }
fn current_url() -> String {
    let location = js_sys::Reflect::get(&js_sys::global(), &JsValue::from_str("location")).unwrap();
    js_sys::Reflect::get(&location, &JsValue::from_str("href")).unwrap().as_string().unwrap()
}
struct Owners { runtime: WasmHandleRef, scope: WasmHandleRef, url: String }
impl Owners {
    fn new() -> Self {
        let (url, origin) = crate::canonicalize_browser_http_url(&current_url()).unwrap();
        let runtime = serde_json::from_str(&crate::runtime_create_impl(Some(serde_json::json!({
            "fetchAuthority": { "allowedOrigins": [origin], "allowedMethods": ["GET", "POST"] }
        }).to_string())).unwrap()).unwrap();
        let scope = crate::with_dispatcher(|d| d.scope_enter(&WasmScopeEnterRequest {
            parent: runtime, label: Some("bounded-browser-fetch".into()),
        }, None)).unwrap();
        Self { runtime, scope, url }
    }
    fn request(&self) -> WasmFetchRequest {
        WasmFetchRequest { scope: self.scope, url: self.url.clone(), method: "GET".into(), credentials: false, body: None }
    }
    fn operation(&self) -> HostFetch {
        let (_, lease) = prepare(self.request(), limits(), None).unwrap();
        HostFetch::new(lease).unwrap()
    }
}
impl Drop for Owners {
    fn drop(&mut self) {
        if crate::dispatcher_handle_is_live(&self.runtime) {
            crate::runtime_close_impl(serde_json::to_string(&self.runtime).unwrap(), None).unwrap();
        }
    }
}
fn registrations() -> HashSet<WasmHandleRef> {
    crate::INFLIGHT_FETCHES.with(|fetches| fetches.borrow().keys().copied().collect())
}
fn new_registration(before: &HashSet<WasmHandleRef>) -> (WasmHandleRef, AbortController) {
    let entries = crate::INFLIGHT_FETCHES.with(|fetches| {
        fetches.borrow().iter().filter(|(handle, _)| !before.contains(*handle))
            .map(|(handle, controller)| (*handle, controller.clone())).collect::<Vec<_>>()
    });
    assert_eq!(entries.len(), 1, "one real fetch must have been admitted in this poll");
    entries.into_iter().next().unwrap()
}

#[wasm_bindgen_test]
async fn real_same_origin_fetch_returns_the_actual_body_not_only_headers() {
    let owners = Owners::new();
    // Fetch the runner's actual served page; no invented fixture endpoint and
    // no overridden global fetch. Whole-buffer reads are reference-oracle only.
    let init = RequestInit::new();
    init.set_credentials(RequestCredentials::Omit);
    init.set_redirect(RequestRedirect::Error);
    let reference = JsFuture::from(crate::host_fetch_with_str_and_init(&owners.url, &init).unwrap())
        .await.unwrap().dyn_into::<Response>().unwrap();
    let status = reference.status();
    let expected = js_sys::Uint8Array::new(&JsFuture::from(reference.array_buffer().unwrap()).await.unwrap()).to_vec();
    assert!(!expected.is_empty(), "the HTTP runner must actually serve a document");
    let response = public_fetch_bytes(owners.request(), limits(), None).await.unwrap();
    assert_eq!(response.status, status);
    assert_eq!(response.body, expected);
}

#[wasm_bindgen_test]
fn dropping_a_real_pending_fetch_aborts_its_signal_and_releases_its_handle() {
    let owners = Owners::new();
    let before = registrations();
    let mut pending = Box::pin(public_fetch_bytes(owners.request(), limits(), None));
    assert!(pending.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
    let (handle, controller) = new_registration(&before);
    assert!(!controller.signal().aborted());
    drop(pending);
    assert!(controller.signal().aborted());
    assert!(!registrations().contains(&handle));
    assert!(!crate::dispatcher_handle_is_live(&handle));
}

#[wasm_bindgen_test]
async fn closing_scope_aborts_a_real_pending_fetch_and_cannot_return_stale_success() {
    let owners = Owners::new();
    let before = registrations();
    let mut pending = Box::pin(public_fetch_bytes(owners.request(), limits(), None));
    assert!(pending.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
    let (handle, controller) = new_registration(&before);
    crate::scope_close_impl(serde_json::to_string(&owners.scope).unwrap(), None).unwrap();
    assert!(controller.signal().aborted());
    assert!(!crate::dispatcher_handle_is_live(&handle));
    assert_eq!(pending.await, Err(FetchBytesError::Cancelled));
    assert!(!registrations().contains(&handle));
}

#[wasm_bindgen_test]
async fn local_task_cancel_during_the_real_fetch_pending_poll_retires_host_io() {
    let owners = Owners::new();
    let request = owners.request();
    let handle_slot = Rc::new(Cell::new(None));
    let target = Rc::clone(&handle_slot);
    let captured = Rc::new(RefCell::new(None));
    let observed = Rc::clone(&captured);
    let task = crate::local::spawn_local_future(WasmTaskSpawnRequest {
        scope: owners.scope, label: None, cancel_kind: None,
    }, async move {
        let before = registrations();
        let mut fetch = Box::pin(public_fetch_bytes(request, limits(), None));
        let _unexpected = poll_fn(|cx| {
            let result = fetch.as_mut().poll(cx);
            if result.is_pending() && observed.borrow().is_none() {
                *observed.borrow_mut() = Some(new_registration(&before));
                crate::task_cancel_impl(serde_json::to_string(&WasmTaskCancelRequest {
                    task: target.get().unwrap(), kind: "pending_fetch_cancel".into(), message: None,
                }).unwrap(), None).unwrap();
            }
            result
        }).await.expect("the executor must retire this future before it returns");
        WasmAbiOutcomeEnvelope::Ok { value: WasmAbiValue::Unit }
    }, None).unwrap();
    handle_slot.set(Some(task.handle()));
    let completion = task.await;
    assert!(matches!(completion.outcome, WasmAbiOutcomeEnvelope::Cancelled { .. }));
    assert!(completion.publication_error.is_none());
    let (handle, controller) = captured.borrow_mut().take().expect("actual fetch returned Pending");
    assert!(controller.signal().aborted());
    assert!(!registrations().contains(&handle));
    assert!(!crate::dispatcher_handle_is_live(&handle));
}

#[wasm_bindgen_test]
async fn real_network_body_exceeding_zero_limit_is_not_returned_partially() {
    let owners = Owners::new();
    assert_eq!(public_fetch_bytes(owners.request(), FetchBytesLimits::new(0, 0, 4096), None).await,
        Err(FetchBytesError::ResponseLimit { limit: 0 }));
}

#[wasm_bindgen_test]
async fn streamed_body_fixture_preserves_binary_chunks_http_errors_and_exact_eof_budget() {
    let owners = Owners::new();
    let chunks = js_sys::Array::new();
    chunks.push(&js_sys::Uint8Array::from([0_u8, 255].as_slice()));
    chunks.push(&js_sys::Uint8Array::new_with_length(0));
    chunks.push(&js_sys::Uint8Array::from([1_u8, 2, 3].as_slice()));
    let response = stream_response(&chunks, 503);
    let stream = response.body().unwrap();
    let mut operation = owners.operation();
    let signal = operation.signal.clone();
    let handle = operation.handle;
    let result = operation.read_response(response, FetchBytesLimits::new(0, 5, 4)).await;
    assert_eq!(operation.finish(result).unwrap(), FetchBytesResponse { status: 503, body: vec![0, 255, 1, 2, 3] });
    assert!(!signal.aborted(), "a complete body is not a cancelled request");
    assert!(!stream.locked());
    assert!(!crate::dispatcher_handle_is_live(&handle));
    let mut operation = owners.operation();
    let result = operation.read_response(stream_response(&chunks, 503), FetchBytesLimits::new(0, 5, 3)).await;
    assert_eq!(operation.finish(result), Err(FetchBytesError::ReadLimit { limit: 3 }),
        "receiving every byte does not prove EOF without the final read");
}

#[wasm_bindgen_test]
async fn streamed_body_fixture_limit_failure_aborts_and_releases_the_reader() {
    let owners = Owners::new();
    let response = Response::new_with_opt_str(Some("too large")).unwrap();
    let stream = response.body().unwrap();
    let mut operation = owners.operation();
    let signal = operation.signal.clone();
    let result = operation.read_response(response, FetchBytesLimits::new(0, 2, 8)).await;
    assert_eq!(operation.finish(result), Err(FetchBytesError::ResponseLimit { limit: 2 }));
    assert!(signal.aborted());
    assert!(!stream.locked());
}

#[wasm_bindgen_test]
async fn an_endless_empty_chunk_fixture_cannot_escape_the_read_work_limit() {
    let owners = Owners::new();
    let response = empty_chunk_response();
    let stream = response.body().unwrap();
    let mut operation = owners.operation();
    let result = operation.read_response(response, FetchBytesLimits::new(0, 0, 3)).await;
    assert_eq!(operation.finish(result), Err(FetchBytesError::ReadLimit { limit: 3 }));
    assert!(!stream.locked());
    // The constructed stream is a decoder fixture, not a Fetch stream attached
    // to our AbortSignal; explicitly retire its independent source after testing.
    JsFuture::from(stream.cancel()).await.unwrap();
}

#[wasm_bindgen_test]
async fn null_body_needs_no_reads_and_invalid_chunk_or_opaque_response_is_not_success() {
    let owners = Owners::new();
    let mut operation = owners.operation();
    let result = operation.read_response(Response::new().unwrap(), FetchBytesLimits::new(0, 0, 0)).await;
    assert_eq!(operation.finish(result).unwrap(), FetchBytesResponse { status: 200, body: Vec::new() });
    let mut operation = owners.operation();
    let result = operation.read_response(Response::error(), limits()).await;
    assert_eq!(operation.finish(result), Err(FetchBytesError::InvalidResponse));
    let chunks = js_sys::Array::new();
    chunks.push(&JsValue::from_str("not a byte chunk"));
    let mut operation = owners.operation();
    let result = operation.read_response(stream_response(&chunks, 200), limits()).await;
    assert_eq!(operation.finish(result), Err(FetchBytesError::InvalidResponse));
}

#[wasm_bindgen_test]
async fn body_stream_rejection_is_not_eof_and_does_not_expose_its_payload() {
    let owners = Owners::new();
    let mut operation = owners.operation();
    let result = operation.read_response(errored_response(), limits()).await;
    let error = operation.finish(result).unwrap_err();
    assert_eq!(error, FetchBytesError::Host { stage: FetchBytesStage::Read });
    assert!(!format!("{error:?}").contains("private rejection"));
}

#[wasm_bindgen_test]
fn scope_abort_listener_can_reenter_and_admit_unrelated_fetch_without_registry_borrow() {
    let owners = Owners::new();
    let unrelated = Owners::new();
    let operation = owners.operation();
    let replacement = Rc::new(RefCell::new(None));
    let captured = Rc::clone(&replacement);
    let request = unrelated.request();
    let invoked = Rc::new(Cell::new(false));
    let seen = Rc::clone(&invoked);
    let on_abort = Closure::wrap(Box::new(move |_event: web_sys::Event| {
        // Both nested cleanup and a new registry insertion must be legal.
        crate::browser_operator_snapshot_impl().unwrap();
        let (_, lease) = prepare(request.clone(), limits(), None).unwrap();
        *captured.borrow_mut() = Some(HostFetch::new(lease).unwrap());
        seen.set(true);
    }) as Box<dyn FnMut(web_sys::Event)>);
    operation.signal.set_onabort(Some(on_abort.as_ref().unchecked_ref()));
    crate::scope_close_impl(serde_json::to_string(&owners.scope).unwrap(), None).unwrap();
    assert!(invoked.get());
    assert!(operation.signal.aborted());
    assert!(replacement.borrow().as_ref().unwrap().check_active().is_ok());
    operation.signal.set_onabort(None);
    drop(operation);
    drop(replacement.borrow_mut().take());
}

#[wasm_bindgen_test]
fn request_policy_disables_redirects_and_does_not_enable_credentials_implicitly() {
    let owners = Owners::new();
    let operation = owners.operation();
    let init = operation.request_init(&owners.request());
    assert_eq!(js_sys::Reflect::get(&init, &JsValue::from_str("redirect")).unwrap().as_string().as_deref(), Some("error"));
    assert_eq!(js_sys::Reflect::get(&init, &JsValue::from_str("credentials")).unwrap().as_string().as_deref(), Some("omit"));
}

#[wasm_bindgen_test]
async fn dropping_during_a_pending_body_read_releases_the_real_reader_lock() {
    let owners = Owners::new();
    let response = parked_response();
    let stream = response.body().unwrap();
    let mut operation = owners.operation();
    let handle = operation.handle;
    let signal = operation.signal.clone();
    let mut reading = Box::pin(operation.read_response(response, limits()));
    assert!(reading.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
    assert!(stream.locked());
    drop(reading);
    drop(operation);
    assert!(signal.aborted());
    assert!(!stream.locked());
    assert!(!crate::dispatcher_handle_is_live(&handle));
    // This is a constructed stream fixture, not a network-backed Fetch stream.
    JsFuture::from(stream.cancel()).await.unwrap();
}

#[wasm_bindgen_test]
async fn client_clones_share_real_network_admission_and_dropped_fetch_returns_capacity() {
    let owners = Owners::new();
    let client = crate::fetch::FetchBytesClient::new(limits(), 1);
    let clone = client.clone();
    let before = registrations();
    let mut first = Box::pin(client.fetch(owners.request(), None));
    assert_eq!(client.in_flight(), 0, "construction is lazy");
    assert!(first.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
    let (handle, controller) = new_registration(&before);
    assert_eq!(clone.in_flight(), 1);
    let mut refused = Box::pin(clone.fetch(owners.request(), None));
    assert_eq!(refused.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        std::task::Poll::Ready(Err(FetchBytesError::InFlightLimit { limit: 1 })));
    assert_eq!(new_registration(&before).0, handle, "refusal cannot admit another request");
    drop(first);
    assert!(controller.signal().aborted());
    assert_eq!(client.in_flight(), 0);
    assert!(!crate::dispatcher_handle_is_live(&handle));
    let response = clone.fetch(owners.request(), None).await.unwrap();
    assert!(!response.body.is_empty());
    assert_eq!(client.in_flight(), 0);
}
