//! Actual fetch journeys and real browser ReadableStream decoder fixtures.
//! Fixtures exercise stream semantics, not network interoperability.
use super::*;
use asupersync::types::WasmScopeEnterRequest;
use std::future::poll_fn;
use std::task::Waker;
use wasm_bindgen_test::*;

#[wasm_bindgen::prelude::wasm_bindgen(inline_js = r#"
export function pullBody(status) {
    let controller;
    let pulls = 0;
    const stream = new ReadableStream({
        start(c) { controller = c; },
        pull() { pulls++; }
    }, {highWaterMark: 0});
    return {response: new Response(stream, {status}), controller, count: () => pulls};
}
export function bodyResponse(body) { return body.response; }
export function bodyPush(body, bytes) { body.controller.enqueue(bytes); }
export function bodyClose(body) { body.controller.close(); }
export function bodyError(body) { body.controller.error('secret-rejection'); }
export function bodyPulls(body) { return body.count(); }
export function bodyMalformed(body) { body.controller.enqueue('not-bytes'); }
"#)]
extern "C" {
    #[wasm_bindgen(js_name = pullBody)]
    fn pull_body(status: u16) -> JsValue;
    #[wasm_bindgen(js_name = bodyResponse)]
    fn body_response(body: &JsValue) -> Response;
    #[wasm_bindgen(js_name = bodyPush)]
    fn body_push(body: &JsValue, bytes: &[u8]);
    #[wasm_bindgen(js_name = bodyClose)]
    fn body_close(body: &JsValue);
    #[wasm_bindgen(js_name = bodyError)]
    fn body_error(body: &JsValue);
    #[wasm_bindgen(js_name = bodyPulls)]
    fn body_pulls(body: &JsValue) -> u32;
    #[wasm_bindgen(js_name = bodyMalformed)]
    fn body_malformed(body: &JsValue);
}

fn limits(bytes: usize, chunk: usize, reads: usize) -> FetchStreamLimits {
    FetchStreamLimits::new(FetchBytesLimits::new(0, bytes, reads), chunk)
}

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
    fn body(&self, response: Response, limits: FetchStreamLimits)
        -> (FetchStream, AbortSignal, WasmHandleRef)
    {
        let (_, lease) = prepare(self.request(), limits.transfer, None).unwrap();
        let operation = HostFetch::new(lease).unwrap();
        let signal = operation.signal.clone();
        let handle = operation.handle;
        let body = HostBody::from_response(operation, response, limits).unwrap();
        (FetchStream { status: body.status, body, _local: std::marker::PhantomData }, signal, handle)
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
async fn real_network_stream_matches_complete_reference_bytes() {
    let owners = Owners::new();
    let init = RequestInit::new();
    init.set_credentials(RequestCredentials::Omit);
    init.set_redirect(RequestRedirect::Error);
    let response = JsFuture::from(crate::host_fetch_with_str_and_init(&owners.url, &init).unwrap())
        .await.unwrap().dyn_into::<Response>().unwrap();
    let expected_status = response.status();
    let expected = js_sys::Uint8Array::new(&JsFuture::from(response.array_buffer().unwrap()).await.unwrap()).to_vec();
    assert!(!expected.is_empty());
    let mut stream = crate::fetch::fetch_stream(owners.request(), limits(4_194_304, 4_194_304, 4096), None).await.unwrap();
    assert_eq!(stream.status(), expected_status);
    assert_eq!(stream.received_bytes(), 0);
    let mut actual = Vec::new();
    while let Some(chunk) = stream.next_chunk().await.unwrap() { actual.extend_from_slice(&chunk); }
    assert_eq!(actual, expected);
    assert_eq!(stream.received_bytes(), actual.len());
    assert_eq!(stream.next_chunk().await.unwrap(), None);
}

#[wasm_bindgen_test]
async fn dropped_next_chunk_wait_preserves_the_original_pending_read() {
    let owners = Owners::new();
    let fixture = pull_body(200);
    let (mut body, signal, handle) = owners.body(body_response(&fixture), limits(4, 4, 2));
    let mut wait = Box::pin(body.next_chunk());
    assert!(wait.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
    drop(wait);
    assert!(!signal.aborted());
    assert!(crate::dispatcher_handle_is_live(&handle));
    body_push(&fixture, &[1, 2, 3, 4]);
    body_close(&fixture);
    assert_eq!(body.next_chunk().await.unwrap(), Some(vec![1, 2, 3, 4]));
    assert_eq!(body.next_chunk().await.unwrap(), None, "dropped wait charged only one read");
    assert!(!signal.aborted());
    assert!(!crate::dispatcher_handle_is_live(&handle));
}

#[wasm_bindgen_test]
async fn body_does_not_prefetch_when_the_consumer_stops_reading() {
    let owners = Owners::new();
    let fixture = pull_body(200);
    let (mut body, _, _) = owners.body(body_response(&fixture), limits(8, 4, 3));
    JsFuture::from(js_sys::Promise::resolve(&JsValue::UNDEFINED)).await.unwrap();
    assert_eq!(body_pulls(&fixture), 0, "returning headers must not read a body");
    let mut wait = Box::pin(body.next_chunk());
    assert!(wait.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
    JsFuture::from(js_sys::Promise::resolve(&JsValue::UNDEFINED)).await.unwrap();
    assert_eq!(body_pulls(&fixture), 1);
    body_push(&fixture, &[9]);
    assert_eq!(wait.await.unwrap(), Some(vec![9]));
    JsFuture::from(js_sys::Promise::resolve(&JsValue::UNDEFINED)).await.unwrap();
    assert_eq!(body_pulls(&fixture), 1, "no next read until the consumer requests it");
    body_close(&fixture);
    assert_eq!(body.next_chunk().await.unwrap(), None);
}

#[wasm_bindgen_test]
async fn stream_preserves_empty_chunks_binary_data_and_http_error_status() {
    let owners = Owners::new();
    let fixture = pull_body(503);
    body_push(&fixture, &[]);
    body_push(&fixture, &[0, 255, 1]);
    body_close(&fixture);
    let (mut body, signal, handle) = owners.body(body_response(&fixture), limits(3, 3, 3));
    assert_eq!(body.status(), 503);
    assert_eq!(body.next_chunk().await.unwrap(), Some(Vec::new()));
    assert_eq!(body.next_chunk().await.unwrap(), Some(vec![0, 255, 1]));
    assert_eq!(body.next_chunk().await.unwrap(), None);
    assert!(!signal.aborted());
    assert!(!crate::dispatcher_handle_is_live(&handle));
}

#[wasm_bindgen_test]
async fn total_limit_is_not_reset_when_a_chunk_is_delivered() {
    let owners = Owners::new();
    let fixture = pull_body(200);
    body_push(&fixture, &[1, 2]);
    body_push(&fixture, &[3, 4]);
    body_close(&fixture);
    let response = body_response(&fixture);
    let underlying = response.body().unwrap();
    let (mut body, signal, handle) = owners.body(response, limits(3, 2, 3));
    assert_eq!(body.next_chunk().await.unwrap(), Some(vec![1, 2]));
    let error = Err(FetchBytesError::ResponseLimit { limit: 3 });
    assert_eq!(body.next_chunk().await, error);
    assert_eq!(body.next_chunk().await, error, "failure is sticky, not EOF");
    assert_eq!(body.received_bytes(), 2);
    assert!(signal.aborted());
    assert!(!underlying.locked());
    assert!(!crate::dispatcher_handle_is_live(&handle));
}

#[wasm_bindgen_test]
async fn oversized_chunk_is_refused_even_with_room_in_total_budget() {
    let owners = Owners::new();
    let fixture = pull_body(200);
    body_push(&fixture, &[1, 2, 3]);
    body_close(&fixture);
    let (mut body, signal, _) = owners.body(body_response(&fixture), limits(100, 2, 3));
    assert_eq!(body.next_chunk().await, Err(FetchBytesError::ChunkLimit { limit: 2 }));
    assert_eq!(body.received_bytes(), 0);
    assert!(signal.aborted());
}

#[wasm_bindgen_test]
async fn delivered_bytes_do_not_manufacture_eof_without_a_read_credit() {
    let owners = Owners::new();
    let fixture = pull_body(200);
    body_push(&fixture, &[7]);
    body_close(&fixture);
    let (mut body, signal, _) = owners.body(body_response(&fixture), limits(1, 1, 1));
    assert_eq!(body.next_chunk().await.unwrap(), Some(vec![7]));
    assert_eq!(body.next_chunk().await, Err(FetchBytesError::ReadLimit { limit: 1 }));
    assert!(signal.aborted());
}

#[wasm_bindgen_test]
async fn closing_scope_discards_an_already_queued_chunk() {
    let owners = Owners::new();
    let fixture = pull_body(200);
    body_push(&fixture, &[7]);
    body_close(&fixture);
    let (mut body, signal, _) = owners.body(body_response(&fixture), limits(1, 1, 2));
    crate::scope_close_impl(serde_json::to_string(&owners.scope).unwrap(), None).unwrap();
    assert!(signal.aborted());
    assert_eq!(body.next_chunk().await, Err(FetchBytesError::Cancelled));
    assert_eq!(body.received_bytes(), 0);
}

#[wasm_bindgen_test]
async fn dropping_body_aborts_pending_read_and_releases_reader_and_handle() {
    let owners = Owners::new();
    let fixture = pull_body(200);
    let response = body_response(&fixture);
    let underlying = response.body().unwrap();
    let (mut body, signal, handle) = owners.body(response, limits(8, 8, 2));
    assert!(Pin::new(&mut body).poll_chunk(&mut Context::from_waker(Waker::noop())).is_pending());
    assert!(underlying.locked());
    drop(body);
    assert!(signal.aborted());
    assert!(!underlying.locked());
    assert!(!crate::dispatcher_handle_is_live(&handle));
    // The constructed source is not a real fetch attached to AbortSignal.
    JsFuture::from(underlying.cancel()).await.unwrap();
}

#[wasm_bindgen_test]
async fn errored_or_malformed_stream_is_never_successful_eof() {
    let owners = Owners::new();
    for malformed in [false, true] {
        let fixture = pull_body(200);
        if malformed { body_malformed(&fixture); } else { body_error(&fixture); }
        let (mut body, signal, _) = owners.body(body_response(&fixture), limits(8, 8, 2));
        let error = body.next_chunk().await.unwrap_err();
        assert_eq!(error, if malformed { FetchBytesError::InvalidResponse }
            else { FetchBytesError::Host { stage: FetchBytesStage::Read } });
        assert!(!format!("{error:?}").contains("secret-rejection"));
        assert_eq!(body.next_chunk().await, Err(error));
        assert!(signal.aborted());
        if malformed { body_close(&fixture); }
    }
}

#[wasm_bindgen_test]
async fn null_body_finishes_with_zero_budgets_and_no_abort() {
    let owners = Owners::new();
    let (mut body, signal, handle) = owners.body(Response::new().unwrap(), limits(0, 0, 0));
    assert_eq!(body.next_chunk().await.unwrap(), None);
    assert!(!signal.aborted());
    assert!(!crate::dispatcher_handle_is_live(&handle));
    assert_eq!(body.next_chunk().await.unwrap(), None);
}

#[wasm_bindgen_test]
async fn repeated_polls_do_not_charge_a_pending_read_more_than_once() {
    let owners = Owners::new();
    let fixture = pull_body(200);
    let (mut body, _, _) = owners.body(body_response(&fixture), limits(0, 0, 1));
    for _ in 0..100 {
        assert!(Pin::new(&mut body).poll_chunk(&mut Context::from_waker(Waker::noop())).is_pending());
    }
    body_close(&fixture);
    assert_eq!(poll_fn(|cx| Pin::new(&mut body).poll_chunk(cx)).await.unwrap(), None);
}
