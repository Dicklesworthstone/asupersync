#![deny(unsafe_code)]
#![allow(clippy::missing_errors_doc)]
// wasm-bindgen requires String at the JS boundary; impl functions mirror those signatures.
#![allow(clippy::needless_pass_by_value)]

pub mod error;
pub mod types;

use crate::error::dispatch_error_json;
use crate::types::{decode_json_payload, decode_optional_consumer_version, encode_json_payload};
use asupersync::types::{
    WASM_ABI_MAJOR_VERSION, WASM_ABI_MINOR_VERSION, WASM_ABI_SIGNATURE_FINGERPRINT_V1,
    WasmAbiCancellation, WasmAbiErrorCode, WasmAbiFailure, WasmAbiOutcomeEnvelope,
    WasmAbiRecoverability, WasmAbiValue, WasmAbiVersion, WasmDispatchError, WasmExportDispatcher,
    WasmFetchRequest, WasmHandleRef, WasmScopeEnterRequest, WasmTaskCancelRequest,
    WasmTaskSpawnRequest,
};
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
#[cfg(target_arch = "wasm32")]
use std::rc::Rc;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::closure::Closure;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::{JsCast, JsValue, prelude::wasm_bindgen};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_futures::{JsFuture, spawn_local};
#[cfg(target_arch = "wasm32")]
use web_sys::{
    AbortController, BinaryType, CloseEvent, Event, MessageEvent, RequestInit, Response, WebSocket,
};

thread_local! {
    static DISPATCHER: RefCell<WasmExportDispatcher> = RefCell::new(WasmExportDispatcher::new());
}
#[cfg(target_arch = "wasm32")]
thread_local! {
    static INFLIGHT_FETCHES: RefCell<HashMap<WasmHandleRef, AbortController>> = RefCell::new(HashMap::new());
}
thread_local! {
    static INFLIGHT_WEBSOCKETS: RefCell<HashMap<WasmHandleRef, BrowserWebSocketHostState>> = RefCell::new(HashMap::new());
}

#[derive(Debug, Clone, serde::Deserialize)]
struct BrowserWebSocketOpenRequest {
    scope: WasmHandleRef,
    url: String,
    protocols: Option<Vec<String>>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct BrowserWebSocketSendRequest {
    socket: WasmHandleRef,
    value: WasmAbiValue,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct BrowserWebSocketRecvRequest {
    socket: WasmHandleRef,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct BrowserWebSocketCloseRequest {
    socket: WasmHandleRef,
    reason: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct BrowserWebSocketCancelRequest {
    socket: WasmHandleRef,
    kind: String,
    message: Option<String>,
}

#[cfg(target_arch = "wasm32")]
struct BrowserWebSocketHostState {
    socket: WebSocket,
    inbox: Rc<RefCell<VecDeque<WasmAbiOutcomeEnvelope>>>,
    _on_message: Closure<dyn FnMut(MessageEvent)>,
    _on_close: Closure<dyn FnMut(CloseEvent)>,
    _on_error: Closure<dyn FnMut(Event)>,
}

#[cfg(not(target_arch = "wasm32"))]
struct BrowserWebSocketHostState {
    inbox: VecDeque<WasmAbiOutcomeEnvelope>,
    closed: bool,
}

fn parse_json<T: serde::de::DeserializeOwned>(raw: &str, field: &str) -> Result<T, String> {
    decode_json_payload(raw, field)
}

fn encode_json<T: serde::Serialize>(value: &T, field: &str) -> Result<String, String> {
    encode_json_payload(value, field)
}

fn parse_consumer_version(raw: Option<String>) -> Result<Option<WasmAbiVersion>, String> {
    decode_optional_consumer_version(raw)
}

fn to_error_string(err: WasmDispatchError) -> String {
    dispatch_error_json(&err)
}

fn with_dispatcher<R>(
    f: impl FnOnce(&mut WasmExportDispatcher) -> Result<R, WasmDispatchError>,
) -> Result<R, String> {
    DISPATCHER.with(|dispatcher| {
        let mut dispatcher = dispatcher.borrow_mut();
        f(&mut dispatcher).map_err(to_error_string)
    })
}

fn normalize_fetch_method(method: &str) -> Result<String, String> {
    let normalized = method.trim().to_ascii_uppercase();
    if normalized.is_empty() {
        return Err("fetch method must not be empty".to_string());
    }
    match normalized.as_str() {
        "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" => Ok(normalized),
        _ => Err(format!("unsupported fetch method: {normalized}")),
    }
}

fn normalize_fetch_request(request: WasmFetchRequest) -> Result<WasmFetchRequest, String> {
    let method = normalize_fetch_method(&request.method)?;
    if matches!(method.as_str(), "GET" | "HEAD") && request.body.is_some() {
        return Err(format!(
            "fetch method {method} does not permit a request body"
        ));
    }
    Ok(WasmFetchRequest { method, ..request })
}

const fn fetch_pending_outcome(handle: WasmHandleRef) -> WasmAbiOutcomeEnvelope {
    WasmAbiOutcomeEnvelope::Ok {
        value: WasmAbiValue::Handle(handle),
    }
}

#[allow(clippy::missing_const_for_fn)]
fn fetch_error_outcome(
    message: String,
    recoverability: WasmAbiRecoverability,
) -> WasmAbiOutcomeEnvelope {
    WasmAbiOutcomeEnvelope::Err {
        failure: WasmAbiFailure {
            code: WasmAbiErrorCode::InternalFailure,
            recoverability,
            message,
        },
    }
}

fn cancelled_outcome(
    kind: &str,
    phase: &str,
    message: Option<String>,
    origin_task: Option<String>,
) -> WasmAbiOutcomeEnvelope {
    WasmAbiOutcomeEnvelope::Cancelled {
        cancellation: WasmAbiCancellation {
            kind: kind.to_string(),
            phase: phase.to_string(),
            origin_region: "browser".to_string(),
            origin_task,
            timestamp_nanos: 0,
            message,
            truncated: false,
        },
    }
}

#[cfg(target_arch = "wasm32")]
fn take_inflight_fetch(handle: &WasmHandleRef) -> Option<AbortController> {
    INFLIGHT_FETCHES.with(|inflight| inflight.borrow_mut().remove(handle))
}

#[cfg(target_arch = "wasm32")]
fn register_inflight_fetch(handle: WasmHandleRef, controller: AbortController) {
    INFLIGHT_FETCHES.with(|inflight| {
        inflight.borrow_mut().insert(handle, controller);
    });
}

#[cfg(target_arch = "wasm32")]
fn js_value_message(value: &JsValue) -> String {
    value
        .as_string()
        .or_else(|| {
            js_sys::JSON::stringify(value)
                .ok()
                .and_then(|json| json.as_string())
        })
        .unwrap_or_else(|| "non-string JS error".to_string())
}

#[cfg(target_arch = "wasm32")]
fn js_error_name(value: &JsValue) -> Option<String> {
    js_sys::Reflect::get(value, &JsValue::from_str("name"))
        .ok()
        .and_then(|name| name.as_string())
}

#[cfg(target_arch = "wasm32")]
fn abort_cancelled_outcome(message: String) -> WasmAbiOutcomeEnvelope {
    cancelled_outcome("abort_signal", "cancelling", Some(message), None)
}

fn normalize_websocket_url(url: &str) -> Result<String, String> {
    let normalized = url.trim();
    if normalized.is_empty() {
        return Err("websocket URL must not be empty".to_string());
    }
    if !(normalized.starts_with("ws://") || normalized.starts_with("wss://")) {
        return Err(format!(
            "websocket URL must start with ws:// or wss://: {normalized}"
        ));
    }
    Ok(normalized.to_string())
}

const fn websocket_pending_outcome(handle: WasmHandleRef) -> WasmAbiOutcomeEnvelope {
    WasmAbiOutcomeEnvelope::Ok {
        value: WasmAbiValue::Handle(handle),
    }
}

const fn websocket_idle_outcome() -> WasmAbiOutcomeEnvelope {
    WasmAbiOutcomeEnvelope::Ok {
        value: WasmAbiValue::Unit,
    }
}

const fn websocket_send_outcome() -> WasmAbiOutcomeEnvelope {
    WasmAbiOutcomeEnvelope::Ok {
        value: WasmAbiValue::Unit,
    }
}

fn spawn_websocket_handle(
    scope: WasmHandleRef,
    consumer_version: Option<WasmAbiVersion>,
) -> Result<WasmHandleRef, String> {
    let spawn = WasmTaskSpawnRequest {
        scope,
        label: Some("browser-websocket".to_string()),
        cancel_kind: Some("abort_signal".to_string()),
    };
    with_dispatcher(|dispatcher| dispatcher.task_spawn(&spawn, consumer_version))
}

fn finalize_websocket_handle(
    handle: &WasmHandleRef,
    outcome: WasmAbiOutcomeEnvelope,
    consumer_version: Option<WasmAbiVersion>,
) -> Result<WasmAbiOutcomeEnvelope, String> {
    with_dispatcher(|dispatcher| dispatcher.task_join(handle, outcome, consumer_version))
}

fn cancel_websocket_handle(
    request: &WasmTaskCancelRequest,
    consumer_version: Option<WasmAbiVersion>,
) -> Result<WasmAbiOutcomeEnvelope, String> {
    with_dispatcher(|dispatcher| dispatcher.task_cancel(request, consumer_version))
}

fn with_websocket_state_mut<R>(
    handle: &WasmHandleRef,
    f: impl FnOnce(&mut BrowserWebSocketHostState) -> Result<R, String>,
) -> Result<R, String> {
    INFLIGHT_WEBSOCKETS.with(|sockets| {
        let mut sockets = sockets.borrow_mut();
        let state = sockets
            .get_mut(handle)
            .ok_or_else(|| format!("unknown websocket handle: {handle:?}"))?;
        f(state)
    })
}

fn take_websocket_state(handle: &WasmHandleRef) -> Option<BrowserWebSocketHostState> {
    INFLIGHT_WEBSOCKETS.with(|sockets| sockets.borrow_mut().remove(handle))
}

#[cfg(target_arch = "wasm32")]
fn finalize_fetch_outcome(handle: WasmHandleRef, outcome: WasmAbiOutcomeEnvelope) {
    if take_inflight_fetch(&handle).is_none() {
        return;
    }
    if matches!(outcome, WasmAbiOutcomeEnvelope::Cancelled { .. }) {
        let _ = with_dispatcher(|dispatcher| dispatcher.apply_abort(&handle));
    }
    let _ = with_dispatcher(|dispatcher| dispatcher.fetch_complete(&handle, outcome));
}

#[cfg(target_arch = "wasm32")]
async fn run_browser_fetch(
    request: WasmFetchRequest,
    signal: web_sys::AbortSignal,
) -> WasmAbiOutcomeEnvelope {
    let Some(window) = web_sys::window() else {
        return fetch_error_outcome(
            "window is not available in this host context".to_string(),
            WasmAbiRecoverability::Permanent,
        );
    };

    let mut init = RequestInit::new();
    init.method(&request.method);
    init.signal(Some(&signal));
    if let Some(body) = request.body {
        let body = js_sys::Uint8Array::from(body.as_slice());
        init.body(Some(&body.into()));
    }

    let fetch_promise = window.fetch_with_str_and_init(&request.url, &init);
    match JsFuture::from(fetch_promise).await {
        Ok(response_value) => {
            let status = response_value
                .dyn_into::<Response>()
                .ok()
                .map(|response| u64::from(response.status()));
            let value = status.map_or(WasmAbiValue::Unit, WasmAbiValue::U64);
            WasmAbiOutcomeEnvelope::Ok { value }
        }
        Err(error) => {
            let message = js_value_message(&error);
            if js_error_name(&error).as_deref() == Some("AbortError") {
                abort_cancelled_outcome(format!("fetch aborted by AbortSignal: {message}"))
            } else {
                fetch_error_outcome(
                    format!("browser fetch rejected: {message}"),
                    WasmAbiRecoverability::Transient,
                )
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn spawn_browser_fetch(handle: WasmHandleRef, request: WasmFetchRequest) -> Result<(), String> {
    let controller = AbortController::new().map_err(|err| {
        format!(
            "failed to create AbortController for fetch handle {:?}: {}",
            handle,
            js_value_message(&err)
        )
    })?;
    let signal = controller.signal();
    register_inflight_fetch(handle, controller);
    spawn_local(async move {
        let outcome = run_browser_fetch(request, signal).await;
        finalize_fetch_outcome(handle, outcome);
    });
    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn websocket_outcome_from_message_event(event: MessageEvent) -> WasmAbiOutcomeEnvelope {
    let payload = event.data();
    if let Some(text) = payload.as_string() {
        return WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::String(text),
        };
    }
    if let Ok(buffer) = payload.dyn_into::<js_sys::ArrayBuffer>() {
        let bytes = js_sys::Uint8Array::new(&buffer).to_vec();
        return WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::Bytes(bytes),
        };
    }
    fetch_error_outcome(
        "websocket message payload type is unsupported".to_string(),
        WasmAbiRecoverability::Unknown,
    )
}

#[cfg(target_arch = "wasm32")]
fn setup_browser_websocket(
    handle: WasmHandleRef,
    request: &BrowserWebSocketOpenRequest,
) -> Result<(), String> {
    let socket = if let Some(protocols) = request.protocols.as_ref() {
        if protocols.is_empty() {
            WebSocket::new(&request.url)
        } else {
            let js_protocols = js_sys::Array::new();
            for protocol in protocols {
                js_protocols.push(&JsValue::from_str(protocol));
            }
            WebSocket::new_with_str_sequence(&request.url, &js_protocols)
        }
    } else {
        WebSocket::new(&request.url)
    }
    .map_err(|err| {
        format!(
            "failed to construct browser WebSocket: {}",
            js_value_message(&err)
        )
    })?;
    socket.set_binary_type(BinaryType::Arraybuffer);

    let inbox = Rc::new(RefCell::new(VecDeque::new()));
    let inbox_for_message = Rc::clone(&inbox);
    let on_message = Closure::wrap(Box::new(move |event: MessageEvent| {
        inbox_for_message
            .borrow_mut()
            .push_back(websocket_outcome_from_message_event(event));
    }) as Box<dyn FnMut(MessageEvent)>);

    let inbox_for_close = Rc::clone(&inbox);
    let on_close = Closure::wrap(Box::new(move |event: CloseEvent| {
        let message = if event.reason().is_empty() {
            format!("websocket closed with code {}", event.code())
        } else {
            format!(
                "websocket closed with code {} ({})",
                event.code(),
                event.reason()
            )
        };
        inbox_for_close.borrow_mut().push_back(cancelled_outcome(
            "websocket_close",
            "draining",
            Some(message),
            None,
        ));
    }) as Box<dyn FnMut(CloseEvent)>);

    let inbox_for_error = Rc::clone(&inbox);
    let on_error = Closure::wrap(Box::new(move |_event: Event| {
        inbox_for_error.borrow_mut().push_back(fetch_error_outcome(
            "browser websocket error event".to_string(),
            WasmAbiRecoverability::Transient,
        ));
    }) as Box<dyn FnMut(Event)>);

    socket.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    socket.set_onclose(Some(on_close.as_ref().unchecked_ref()));
    socket.set_onerror(Some(on_error.as_ref().unchecked_ref()));

    INFLIGHT_WEBSOCKETS.with(|sockets| {
        sockets.borrow_mut().insert(
            handle,
            BrowserWebSocketHostState {
                socket,
                inbox,
                _on_message: on_message,
                _on_close: on_close,
                _on_error: on_error,
            },
        );
    });

    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
#[allow(clippy::unnecessary_wraps)]
fn setup_browser_websocket(
    handle: WasmHandleRef,
    request: &BrowserWebSocketOpenRequest,
) -> Result<(), String> {
    let _requested_protocols = request.protocols.as_ref().map(std::vec::Vec::len);
    INFLIGHT_WEBSOCKETS.with(|sockets| {
        sockets.borrow_mut().insert(
            handle,
            BrowserWebSocketHostState {
                inbox: VecDeque::new(),
                closed: false,
            },
        );
    });
    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn send_browser_websocket_message(
    handle: &WasmHandleRef,
    value: WasmAbiValue,
) -> Result<(), String> {
    with_websocket_state_mut(handle, |state| match value {
        WasmAbiValue::String(text) => state.socket.send_with_str(&text).map_err(|err| {
            format!(
                "websocket send_with_str failed for {:?}: {}",
                handle,
                js_value_message(&err)
            )
        }),
        WasmAbiValue::Bytes(bytes) => state.socket.send_with_u8_array(&bytes).map_err(|err| {
            format!(
                "websocket send_with_u8_array failed for {:?}: {}",
                handle,
                js_value_message(&err)
            )
        }),
        other => Err(format!(
            "websocket send requires string/bytes payload, got {other:?}"
        )),
    })
}

#[cfg(not(target_arch = "wasm32"))]
fn send_browser_websocket_message(
    handle: &WasmHandleRef,
    value: WasmAbiValue,
) -> Result<(), String> {
    with_websocket_state_mut(handle, |state| {
        if state.closed {
            return Err(format!("websocket handle {handle:?} is already closed"));
        }
        match value {
            WasmAbiValue::String(text) => state.inbox.push_back(WasmAbiOutcomeEnvelope::Ok {
                value: WasmAbiValue::String(text),
            }),
            WasmAbiValue::Bytes(bytes) => state.inbox.push_back(WasmAbiOutcomeEnvelope::Ok {
                value: WasmAbiValue::Bytes(bytes),
            }),
            other => {
                return Err(format!(
                    "websocket send requires string/bytes payload, got {other:?}"
                ));
            }
        }
        Ok(())
    })
}

#[cfg(target_arch = "wasm32")]
fn recv_browser_websocket_message(
    handle: &WasmHandleRef,
) -> Result<WasmAbiOutcomeEnvelope, String> {
    with_websocket_state_mut(handle, |state| {
        Ok(state
            .inbox
            .borrow_mut()
            .pop_front()
            .unwrap_or_else(websocket_idle_outcome))
    })
}

#[cfg(not(target_arch = "wasm32"))]
fn recv_browser_websocket_message(
    handle: &WasmHandleRef,
) -> Result<WasmAbiOutcomeEnvelope, String> {
    with_websocket_state_mut(handle, |state| {
        Ok(state
            .inbox
            .pop_front()
            .unwrap_or_else(websocket_idle_outcome))
    })
}

#[cfg(target_arch = "wasm32")]
fn close_browser_websocket_socket(
    state: BrowserWebSocketHostState,
    reason: Option<String>,
) -> Result<(), String> {
    if let Some(reason) = reason {
        state
            .socket
            .close_with_code_and_reason(1000, &reason)
            .map_err(|err| format!("websocket close failed: {}", js_value_message(&err)))?;
    } else {
        state
            .socket
            .close()
            .map_err(|err| format!("websocket close failed: {}", js_value_message(&err)))?;
    }
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
#[allow(clippy::unnecessary_wraps)]
fn close_browser_websocket_socket(
    mut state: BrowserWebSocketHostState,
    reason: Option<String>,
) -> Result<(), String> {
    state.closed = true;
    if let Some(reason) = reason {
        state.inbox.push_back(cancelled_outcome(
            "websocket_close",
            "draining",
            Some(reason),
            None,
        ));
    }
    Ok(())
}

/// Reset helper for host-side deterministic tests.
#[cfg(not(target_arch = "wasm32"))]
pub fn reset_dispatcher_for_tests() {
    DISPATCHER.with(|dispatcher| {
        *dispatcher.borrow_mut() = WasmExportDispatcher::new();
    });
    INFLIGHT_WEBSOCKETS.with(|sockets| {
        sockets.borrow_mut().clear();
    });
}

fn runtime_create_impl(consumer_version_json: Option<String>) -> Result<String, String> {
    let consumer_version = parse_consumer_version(consumer_version_json)?;
    let handle = with_dispatcher(|dispatcher| dispatcher.runtime_create(consumer_version))?;
    encode_json(&handle, "runtime_create.response")
}

fn runtime_close_impl(
    handle_json: String,
    consumer_version_json: Option<String>,
) -> Result<String, String> {
    let handle: WasmHandleRef = parse_json(&handle_json, "runtime_close.request")?;
    let consumer_version = parse_consumer_version(consumer_version_json)?;
    let outcome =
        with_dispatcher(|dispatcher| dispatcher.runtime_close(&handle, consumer_version))?;
    encode_json(&outcome, "runtime_close.response")
}

fn scope_enter_impl(
    request_json: String,
    consumer_version_json: Option<String>,
) -> Result<String, String> {
    let request: WasmScopeEnterRequest = parse_json(&request_json, "scope_enter.request")?;
    let consumer_version = parse_consumer_version(consumer_version_json)?;
    let handle = with_dispatcher(|dispatcher| dispatcher.scope_enter(&request, consumer_version))?;
    encode_json(&handle, "scope_enter.response")
}

fn scope_close_impl(
    handle_json: String,
    consumer_version_json: Option<String>,
) -> Result<String, String> {
    let handle: WasmHandleRef = parse_json(&handle_json, "scope_close.request")?;
    let consumer_version = parse_consumer_version(consumer_version_json)?;
    let outcome = with_dispatcher(|dispatcher| dispatcher.scope_close(&handle, consumer_version))?;
    encode_json(&outcome, "scope_close.response")
}

fn task_spawn_impl(
    request_json: String,
    consumer_version_json: Option<String>,
) -> Result<String, String> {
    let request: WasmTaskSpawnRequest = parse_json(&request_json, "task_spawn.request")?;
    let consumer_version = parse_consumer_version(consumer_version_json)?;
    let handle = with_dispatcher(|dispatcher| dispatcher.task_spawn(&request, consumer_version))?;
    encode_json(&handle, "task_spawn.response")
}

fn task_join_impl(
    handle_json: String,
    outcome_json: String,
    consumer_version_json: Option<String>,
) -> Result<String, String> {
    let handle: WasmHandleRef = parse_json(&handle_json, "task_join.request.handle")?;
    let outcome: WasmAbiOutcomeEnvelope = parse_json(&outcome_json, "task_join.request.outcome")?;
    let consumer_version = parse_consumer_version(consumer_version_json)?;
    let joined =
        with_dispatcher(|dispatcher| dispatcher.task_join(&handle, outcome, consumer_version))?;
    encode_json(&joined, "task_join.response")
}

fn task_cancel_impl(
    request_json: String,
    consumer_version_json: Option<String>,
) -> Result<String, String> {
    let request: WasmTaskCancelRequest = parse_json(&request_json, "task_cancel.request")?;
    let consumer_version = parse_consumer_version(consumer_version_json)?;
    let outcome = with_dispatcher(|dispatcher| dispatcher.task_cancel(&request, consumer_version))?;
    encode_json(&outcome, "task_cancel.response")
}

fn fetch_request_impl(
    request_json: String,
    consumer_version_json: Option<String>,
) -> Result<String, String> {
    let request: WasmFetchRequest = parse_json(&request_json, "fetch_request.request")?;
    let request = normalize_fetch_request(request)?;
    let consumer_version = parse_consumer_version(consumer_version_json)?;
    let handle =
        with_dispatcher(|dispatcher| dispatcher.fetch_request(&request, consumer_version))?;
    #[cfg(target_arch = "wasm32")]
    if let Err(setup_err) = spawn_browser_fetch(handle, request.clone()) {
        let setup_outcome = fetch_error_outcome(
            format!("failed to start browser fetch: {setup_err}"),
            WasmAbiRecoverability::Permanent,
        );
        let _ =
            with_dispatcher(|dispatcher| dispatcher.fetch_complete(&handle, setup_outcome.clone()));
        return encode_json(&setup_outcome, "fetch_request.response");
    }
    encode_json(&fetch_pending_outcome(handle), "fetch_request.response")
}

fn websocket_open_impl(
    request_json: String,
    consumer_version_json: Option<String>,
) -> Result<String, String> {
    let request: BrowserWebSocketOpenRequest = parse_json(&request_json, "websocket_open.request")?;
    let url = normalize_websocket_url(&request.url)?;
    let request = BrowserWebSocketOpenRequest { url, ..request };
    let consumer_version = parse_consumer_version(consumer_version_json)?;
    let handle = spawn_websocket_handle(request.scope, consumer_version)?;
    if let Err(setup_err) = setup_browser_websocket(handle, &request) {
        let setup_outcome = fetch_error_outcome(
            format!("failed to start browser websocket: {setup_err}"),
            WasmAbiRecoverability::Permanent,
        );
        let _ = finalize_websocket_handle(&handle, setup_outcome.clone(), consumer_version);
        return encode_json(&setup_outcome, "websocket_open.response");
    }
    encode_json(
        &websocket_pending_outcome(handle),
        "websocket_open.response",
    )
}

fn websocket_send_impl(
    request_json: String,
    _consumer_version_json: Option<String>,
) -> Result<String, String> {
    let request: BrowserWebSocketSendRequest = parse_json(&request_json, "websocket_send.request")?;
    send_browser_websocket_message(&request.socket, request.value)?;
    encode_json(&websocket_send_outcome(), "websocket_send.response")
}

fn websocket_recv_impl(
    request_json: String,
    _consumer_version_json: Option<String>,
) -> Result<String, String> {
    let request: BrowserWebSocketRecvRequest = parse_json(&request_json, "websocket_recv.request")?;
    let outcome = recv_browser_websocket_message(&request.socket)?;
    encode_json(&outcome, "websocket_recv.response")
}

fn websocket_close_impl(
    request_json: String,
    consumer_version_json: Option<String>,
) -> Result<String, String> {
    let request: BrowserWebSocketCloseRequest =
        parse_json(&request_json, "websocket_close.request")?;
    let consumer_version = parse_consumer_version(consumer_version_json)?;
    let state = take_websocket_state(&request.socket)
        .ok_or_else(|| format!("unknown websocket handle: {:?}", request.socket))?;
    close_browser_websocket_socket(state, request.reason.clone())?;
    let outcome = if let Some(reason) = request.reason {
        cancelled_outcome(
            "websocket_close",
            "draining",
            Some(reason),
            Some(format!("{:?}", request.socket)),
        )
    } else {
        websocket_send_outcome()
    };
    let closed = finalize_websocket_handle(&request.socket, outcome, consumer_version)?;
    encode_json(&closed, "websocket_close.response")
}

fn websocket_cancel_impl(
    request_json: String,
    consumer_version_json: Option<String>,
) -> Result<String, String> {
    let request: BrowserWebSocketCancelRequest =
        parse_json(&request_json, "websocket_cancel.request")?;
    let consumer_version = parse_consumer_version(consumer_version_json)?;
    let cancel = WasmTaskCancelRequest {
        task: request.socket,
        kind: request.kind.clone(),
        message: request.message.clone(),
    };
    let _ = cancel_websocket_handle(&cancel, consumer_version)?;
    if let Some(state) = take_websocket_state(&request.socket) {
        close_browser_websocket_socket(state, request.message.clone())?;
    }
    let cancelled = cancelled_outcome(
        &request.kind,
        "cancelling",
        request.message,
        Some(format!("{:?}", request.socket)),
    );
    let joined = finalize_websocket_handle(&request.socket, cancelled, consumer_version)?;
    encode_json(&joined, "websocket_cancel.response")
}

fn abi_version_impl() -> Result<String, String> {
    let version = WasmAbiVersion {
        major: WASM_ABI_MAJOR_VERSION,
        minor: WASM_ABI_MINOR_VERSION,
    };
    encode_json(&version, "abi_version.response")
}

const fn abi_fingerprint_impl() -> u64 {
    WASM_ABI_SIGNATURE_FINGERPRINT_V1
}

#[cfg(target_arch = "wasm32")]
fn into_js_error(err: String) -> JsValue {
    JsValue::from_str(&err)
}

/// `runtime_create` ABI symbol.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = runtime_create))]
#[cfg(target_arch = "wasm32")]
pub fn runtime_create(consumer_version_json: Option<String>) -> Result<String, JsValue> {
    runtime_create_impl(consumer_version_json).map_err(into_js_error)
}

/// Host adapter for `runtime_create`.
#[cfg(not(target_arch = "wasm32"))]
pub fn runtime_create(consumer_version_json: Option<String>) -> Result<String, String> {
    runtime_create_impl(consumer_version_json)
}

/// `runtime_close` ABI symbol.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = runtime_close))]
#[cfg(target_arch = "wasm32")]
pub fn runtime_close(
    handle_json: String,
    consumer_version_json: Option<String>,
) -> Result<String, JsValue> {
    runtime_close_impl(handle_json, consumer_version_json).map_err(into_js_error)
}

/// Host adapter for `runtime_close`.
#[cfg(not(target_arch = "wasm32"))]
pub fn runtime_close(
    handle_json: String,
    consumer_version_json: Option<String>,
) -> Result<String, String> {
    runtime_close_impl(handle_json, consumer_version_json)
}

/// `scope_enter` ABI symbol.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = scope_enter))]
#[cfg(target_arch = "wasm32")]
pub fn scope_enter(
    request_json: String,
    consumer_version_json: Option<String>,
) -> Result<String, JsValue> {
    scope_enter_impl(request_json, consumer_version_json).map_err(into_js_error)
}

/// Host adapter for `scope_enter`.
#[cfg(not(target_arch = "wasm32"))]
pub fn scope_enter(
    request_json: String,
    consumer_version_json: Option<String>,
) -> Result<String, String> {
    scope_enter_impl(request_json, consumer_version_json)
}

/// `scope_close` ABI symbol.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = scope_close))]
#[cfg(target_arch = "wasm32")]
pub fn scope_close(
    handle_json: String,
    consumer_version_json: Option<String>,
) -> Result<String, JsValue> {
    scope_close_impl(handle_json, consumer_version_json).map_err(into_js_error)
}

/// Host adapter for `scope_close`.
#[cfg(not(target_arch = "wasm32"))]
pub fn scope_close(
    handle_json: String,
    consumer_version_json: Option<String>,
) -> Result<String, String> {
    scope_close_impl(handle_json, consumer_version_json)
}

/// `task_spawn` ABI symbol.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = task_spawn))]
#[cfg(target_arch = "wasm32")]
pub fn task_spawn(
    request_json: String,
    consumer_version_json: Option<String>,
) -> Result<String, JsValue> {
    task_spawn_impl(request_json, consumer_version_json).map_err(into_js_error)
}

/// Host adapter for `task_spawn`.
#[cfg(not(target_arch = "wasm32"))]
pub fn task_spawn(
    request_json: String,
    consumer_version_json: Option<String>,
) -> Result<String, String> {
    task_spawn_impl(request_json, consumer_version_json)
}

/// `task_join` ABI symbol.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = task_join))]
#[cfg(target_arch = "wasm32")]
pub fn task_join(
    handle_json: String,
    outcome_json: String,
    consumer_version_json: Option<String>,
) -> Result<String, JsValue> {
    task_join_impl(handle_json, outcome_json, consumer_version_json).map_err(into_js_error)
}

/// Host adapter for `task_join`.
#[cfg(not(target_arch = "wasm32"))]
pub fn task_join(
    handle_json: String,
    outcome_json: String,
    consumer_version_json: Option<String>,
) -> Result<String, String> {
    task_join_impl(handle_json, outcome_json, consumer_version_json)
}

/// `task_cancel` ABI symbol.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = task_cancel))]
#[cfg(target_arch = "wasm32")]
pub fn task_cancel(
    request_json: String,
    consumer_version_json: Option<String>,
) -> Result<String, JsValue> {
    task_cancel_impl(request_json, consumer_version_json).map_err(into_js_error)
}

/// Host adapter for `task_cancel`.
#[cfg(not(target_arch = "wasm32"))]
pub fn task_cancel(
    request_json: String,
    consumer_version_json: Option<String>,
) -> Result<String, String> {
    task_cancel_impl(request_json, consumer_version_json)
}

/// `fetch_request` ABI symbol.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = fetch_request))]
#[cfg(target_arch = "wasm32")]
pub fn fetch_request(
    request_json: String,
    consumer_version_json: Option<String>,
) -> Result<String, JsValue> {
    fetch_request_impl(request_json, consumer_version_json).map_err(into_js_error)
}

/// Host adapter for `fetch_request`.
#[cfg(not(target_arch = "wasm32"))]
pub fn fetch_request(
    request_json: String,
    consumer_version_json: Option<String>,
) -> Result<String, String> {
    fetch_request_impl(request_json, consumer_version_json)
}

/// `websocket_open` bridge symbol.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = websocket_open))]
#[cfg(target_arch = "wasm32")]
pub fn websocket_open(
    request_json: String,
    consumer_version_json: Option<String>,
) -> Result<String, JsValue> {
    websocket_open_impl(request_json, consumer_version_json).map_err(into_js_error)
}

/// Host adapter for `websocket_open`.
#[cfg(not(target_arch = "wasm32"))]
pub fn websocket_open(
    request_json: String,
    consumer_version_json: Option<String>,
) -> Result<String, String> {
    websocket_open_impl(request_json, consumer_version_json)
}

/// `websocket_send` bridge symbol.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = websocket_send))]
#[cfg(target_arch = "wasm32")]
pub fn websocket_send(
    request_json: String,
    consumer_version_json: Option<String>,
) -> Result<String, JsValue> {
    websocket_send_impl(request_json, consumer_version_json).map_err(into_js_error)
}

/// Host adapter for `websocket_send`.
#[cfg(not(target_arch = "wasm32"))]
pub fn websocket_send(
    request_json: String,
    consumer_version_json: Option<String>,
) -> Result<String, String> {
    websocket_send_impl(request_json, consumer_version_json)
}

/// `websocket_recv` bridge symbol.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = websocket_recv))]
#[cfg(target_arch = "wasm32")]
pub fn websocket_recv(
    request_json: String,
    consumer_version_json: Option<String>,
) -> Result<String, JsValue> {
    websocket_recv_impl(request_json, consumer_version_json).map_err(into_js_error)
}

/// Host adapter for `websocket_recv`.
#[cfg(not(target_arch = "wasm32"))]
pub fn websocket_recv(
    request_json: String,
    consumer_version_json: Option<String>,
) -> Result<String, String> {
    websocket_recv_impl(request_json, consumer_version_json)
}

/// `websocket_close` bridge symbol.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = websocket_close))]
#[cfg(target_arch = "wasm32")]
pub fn websocket_close(
    request_json: String,
    consumer_version_json: Option<String>,
) -> Result<String, JsValue> {
    websocket_close_impl(request_json, consumer_version_json).map_err(into_js_error)
}

/// Host adapter for `websocket_close`.
#[cfg(not(target_arch = "wasm32"))]
pub fn websocket_close(
    request_json: String,
    consumer_version_json: Option<String>,
) -> Result<String, String> {
    websocket_close_impl(request_json, consumer_version_json)
}

/// `websocket_cancel` bridge symbol.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = websocket_cancel))]
#[cfg(target_arch = "wasm32")]
pub fn websocket_cancel(
    request_json: String,
    consumer_version_json: Option<String>,
) -> Result<String, JsValue> {
    websocket_cancel_impl(request_json, consumer_version_json).map_err(into_js_error)
}

/// Host adapter for `websocket_cancel`.
#[cfg(not(target_arch = "wasm32"))]
pub fn websocket_cancel(
    request_json: String,
    consumer_version_json: Option<String>,
) -> Result<String, String> {
    websocket_cancel_impl(request_json, consumer_version_json)
}

/// `abi_version` ABI symbol.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = abi_version))]
#[cfg(target_arch = "wasm32")]
pub fn abi_version() -> Result<String, JsValue> {
    abi_version_impl().map_err(into_js_error)
}

/// Host adapter for `abi_version`.
#[cfg(not(target_arch = "wasm32"))]
pub fn abi_version() -> Result<String, String> {
    abi_version_impl()
}

/// `abi_fingerprint` ABI symbol.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = abi_fingerprint))]
#[cfg(target_arch = "wasm32")]
#[must_use]
pub const fn abi_fingerprint() -> u64 {
    abi_fingerprint_impl()
}

/// Host adapter for `abi_fingerprint`.
#[cfg(not(target_arch = "wasm32"))]
#[must_use]
pub const fn abi_fingerprint() -> u64 {
    abi_fingerprint_impl()
}
