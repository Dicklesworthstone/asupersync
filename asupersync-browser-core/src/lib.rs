//! Canonical Rust-side wasm-bindgen boundary for the shipped Browser Edition.
//!
//! `asupersync-browser-core` is the sole workspace crate that owns the live
//! v1 ABI/export surface consumed by `@asupersync/browser-core` and the
//! higher-level JS/TS packages.
//!
//! The sibling `asupersync-wasm` crate is retained as a non-canonical scaffold
//! for future or alternative binding strategies. It is not the current owner of
//! the shipped JS/WASM boundary.
//!
#![deny(unsafe_code)]
#![allow(clippy::missing_errors_doc)]
// wasm-bindgen requires String at the JS boundary; impl functions mirror those signatures.
#![allow(clippy::needless_pass_by_value)]

pub mod error;
mod exports;
pub mod types;

pub use exports::{
    abi_fingerprint, abi_version, browser_operator_snapshot, fetch_request, runtime_close,
    runtime_create, scope_close, scope_enter, task_cancel, task_join, task_spawn, websocket_cancel,
    websocket_close, websocket_open, websocket_recv, websocket_send,
};

use crate::error::dispatch_error_json;
use crate::types::{
    BrowserOperatorConsoleSnapshot, decode_json_payload, decode_optional_consumer_version,
    encode_json_payload,
};
use asupersync::io::{FetchAuthority, FetchMethod};
use asupersync::types::WasmDispatcherDiagnostics;
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
use wasm_bindgen::{JsCast, JsValue};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_futures::{JsFuture, spawn_local};
#[cfg(target_arch = "wasm32")]
use web_sys::{
    AbortController, BinaryType, CloseEvent, Event, MessageEvent, RequestCredentials, RequestInit,
    Response, Url, WebSocket, WorkerGlobalScope,
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

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowserFetchAuthorityConfig {
    #[serde(default)]
    allowed_origins: Vec<String>,
    #[serde(default)]
    allowed_methods: Vec<String>,
    #[serde(default)]
    allow_credentials: bool,
    #[serde(default)]
    max_header_count: usize,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowserRuntimeCreateRequest {
    #[serde(default)]
    fetch_authority: BrowserFetchAuthorityConfig,
    #[serde(default)]
    consumer_version: Option<WasmAbiVersion>,
}

#[cfg(target_arch = "wasm32")]
struct BrowserWebSocketHostState {
    socket: WebSocket,
    inbox: Rc<RefCell<VecDeque<WasmAbiOutcomeEnvelope>>>,
    _on_message: Closure<dyn FnMut(MessageEvent)>,
    _on_close: Closure<dyn FnMut(CloseEvent)>,
    _on_error: Closure<dyn FnMut(Event)>,
}

#[cfg(target_arch = "wasm32")]
impl Drop for BrowserWebSocketHostState {
    fn drop(&mut self) {
        self.socket.set_onmessage(None);
        self.socket.set_onclose(None);
        self.socket.set_onerror(None);
        let _ = self.socket.close();
    }
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

fn dispatcher_handle_is_live(handle: &WasmHandleRef) -> bool {
    DISPATCHER.with(|dispatcher| dispatcher.borrow().handles().get(handle).is_ok())
}

#[cfg(target_arch = "wasm32")]
fn cleanup_released_fetches() {
    INFLIGHT_FETCHES.with(|inflight| {
        inflight
            .borrow_mut()
            .retain(|handle, _| dispatcher_handle_is_live(handle));
    });
}

#[cfg(not(target_arch = "wasm32"))]
const fn cleanup_released_fetches() {}

fn cleanup_released_websockets() {
    INFLIGHT_WEBSOCKETS.with(|sockets| {
        sockets
            .borrow_mut()
            .retain(|handle, _| dispatcher_handle_is_live(handle));
    });
}

fn cleanup_released_host_state() {
    cleanup_released_fetches();
    cleanup_released_websockets();
}

#[cfg(target_arch = "wasm32")]
fn canonicalize_browser_http_url(raw: &str) -> Result<(String, String), String> {
    let url = Url::new(raw).map_err(|error| {
        format!(
            "fetch URL is not a valid absolute browser URL: {}",
            js_value_message(&error)
        )
    })?;
    if !matches!(url.protocol().as_str(), "http:" | "https:") {
        return Err(format!(
            "fetch URL must use http or https, got {}",
            url.protocol()
        ));
    }
    if !url.username().is_empty() || !url.password().is_empty() {
        return Err("fetch URL must not contain embedded credentials".to_string());
    }
    let origin = url.origin();
    if origin == "null" {
        return Err("fetch URL must have a tuple origin".to_string());
    }
    Ok((url.href(), origin))
}

#[cfg(not(target_arch = "wasm32"))]
fn canonicalize_browser_http_url(raw: &str) -> Result<(String, String), String> {
    let trimmed = raw.trim();
    let scheme_end = trimmed
        .find("://")
        .ok_or_else(|| "fetch URL must be absolute".to_string())?;
    let scheme = trimmed[..scheme_end].to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https") {
        return Err(format!("fetch URL must use http or https, got {scheme}"));
    }

    let rest = trimmed[scheme_end + 3..].replace('\\', "/");
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() {
        return Err("fetch URL must include a host".to_string());
    }
    if authority.contains('@') {
        return Err("fetch URL must not contain embedded credentials".to_string());
    }

    let (host, port) = if let Some(ipv6) = authority.strip_prefix('[') {
        let closing = ipv6
            .find(']')
            .ok_or_else(|| "fetch URL contains an unterminated IPv6 host".to_string())?;
        let host = format!("[{}]", ipv6[..closing].to_ascii_lowercase());
        let suffix = &ipv6[closing + 1..];
        let port = if suffix.is_empty() {
            None
        } else {
            Some(
                suffix
                    .strip_prefix(':')
                    .ok_or_else(|| "fetch URL has an invalid IPv6 authority".to_string())?,
            )
        };
        (host, port)
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        (host.to_ascii_lowercase(), Some(port))
    } else {
        (authority.to_ascii_lowercase(), None)
    };
    if host.is_empty() {
        return Err("fetch URL must include a host".to_string());
    }

    let port = port
        .map(|value| {
            value
                .parse::<u16>()
                .map_err(|_| "fetch URL has an invalid port".to_string())
        })
        .transpose()?;
    let include_port =
        port.filter(|value| !matches!((scheme.as_str(), value), ("http", 80) | ("https", 443)));
    let canonical_authority =
        include_port.map_or_else(|| host.clone(), |value| format!("{host}:{value}"));
    let suffix = &rest[authority_end..];
    let canonical_suffix = if suffix.is_empty() {
        "/".to_string()
    } else if suffix.starts_with(['?', '#']) {
        format!("/{suffix}")
    } else {
        suffix.to_string()
    };
    let origin = format!("{scheme}://{canonical_authority}");
    Ok((format!("{origin}{canonical_suffix}"), origin))
}

fn normalize_fetch_method(method: &str) -> Result<String, String> {
    let normalized = method.trim().to_ascii_uppercase();
    if normalized.is_empty() {
        return Err("fetch method must not be empty".to_string());
    }
    if FetchMethod::from_http_token(&normalized).is_some() {
        Ok(normalized)
    } else {
        Err(format!("unsupported fetch method: {normalized}"))
    }
}

fn normalize_fetch_request(request: WasmFetchRequest) -> Result<WasmFetchRequest, String> {
    if request.url.trim().is_empty() {
        return Err("fetch URL must not be empty".to_string());
    }
    let method = normalize_fetch_method(&request.method)?;
    let (url, _) = canonicalize_browser_http_url(&request.url)?;
    if matches!(method.as_str(), "GET" | "HEAD") && request.body.is_some() {
        return Err(format!(
            "fetch method {method} does not permit a request body"
        ));
    }
    Ok(WasmFetchRequest {
        method,
        url,
        ..request
    })
}

fn canonicalize_fetch_authority(
    config: BrowserFetchAuthorityConfig,
) -> Result<FetchAuthority, String> {
    let mut authority = FetchAuthority::deny_all().with_max_header_count(config.max_header_count);
    for origin in config.allowed_origins {
        let canonical_origin = if origin == "*" {
            origin
        } else {
            canonicalize_browser_http_url(&origin)?.1
        };
        authority = authority.grant_origin(canonical_origin);
    }
    for method in config.allowed_methods {
        let normalized = normalize_fetch_method(&method)?;
        let method = FetchMethod::from_http_token(&normalized)
            .ok_or_else(|| format!("unsupported fetch authority method: {normalized}"))?;
        authority = authority.grant_method(method);
    }
    if config.allow_credentials {
        authority = authority.with_credentials_allowed();
    }
    Ok(authority)
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
    let (scheme, rest) = normalized
        .split_once("://")
        .ok_or_else(|| format!("websocket URL must start with ws:// or wss://: {normalized}"))?;
    if !(scheme.eq_ignore_ascii_case("ws") || scheme.eq_ignore_ascii_case("wss")) {
        return Err(format!(
            "websocket URL must start with ws:// or wss://: {normalized}"
        ));
    }
    Ok(format!("{}://{rest}", scheme.to_ascii_lowercase()))
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

fn insert_websocket_state(handle: WasmHandleRef, state: BrowserWebSocketHostState) {
    INFLIGHT_WEBSOCKETS.with(|sockets| {
        sockets.borrow_mut().insert(handle, state);
    });
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
fn host_fetch_with_str_and_init(url: &str, init: &RequestInit) -> Result<js_sys::Promise, String> {
    if let Some(window) = web_sys::window() {
        return Ok(window.fetch_with_str_and_init(url, init));
    }

    if let Ok(worker) = js_sys::global().dyn_into::<WorkerGlobalScope>() {
        return Ok(worker.fetch_with_str_and_init(url, init));
    }

    Err("window or WorkerGlobalScope fetch host is not available in this host context".to_string())
}

#[cfg(target_arch = "wasm32")]
async fn run_browser_fetch(
    request: WasmFetchRequest,
    signal: web_sys::AbortSignal,
) -> WasmAbiOutcomeEnvelope {
    let init = RequestInit::new();
    init.set_method(&request.method);
    init.set_signal(Some(&signal));
    init.set_credentials(if request.credentials {
        RequestCredentials::Include
    } else {
        RequestCredentials::Omit
    });
    if let Some(body) = request.body {
        let body = js_sys::Uint8Array::from(body.as_slice());
        init.set_body(&body.into());
    }

    let fetch_promise = match host_fetch_with_str_and_init(&request.url, &init) {
        Ok(fetch_promise) => fetch_promise,
        Err(message) => {
            return fetch_error_outcome(message, WasmAbiRecoverability::Permanent);
        }
    };
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
            "completed",
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

fn recv_browser_websocket_message(
    handle: &WasmHandleRef,
) -> Result<WasmAbiOutcomeEnvelope, String> {
    with_websocket_state_mut(handle, |state| {
        #[cfg(target_arch = "wasm32")]
        let next = state.inbox.borrow_mut().pop_front();
        #[cfg(not(target_arch = "wasm32"))]
        let next = state.inbox.pop_front();

        Ok(next.unwrap_or_else(websocket_idle_outcome))
    })
}

const MAX_WEBSOCKET_CLOSE_REASON_BYTES: usize = 123;

fn validate_websocket_close_reason(reason: &str) -> Result<(), String> {
    if reason.len() > MAX_WEBSOCKET_CLOSE_REASON_BYTES {
        return Err(format!(
            "websocket close reason exceeds {MAX_WEBSOCKET_CLOSE_REASON_BYTES} bytes"
        ));
    }
    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn close_browser_websocket_socket(
    state: &mut BrowserWebSocketHostState,
    reason: Option<&str>,
) -> Result<(), String> {
    if let Some(reason) = reason {
        validate_websocket_close_reason(reason)?;
        state
            .socket
            .close_with_code_and_reason(1000, reason)
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
    state: &mut BrowserWebSocketHostState,
    reason: Option<&str>,
) -> Result<(), String> {
    if let Some(reason) = reason {
        validate_websocket_close_reason(reason)?;
        state.inbox.push_back(cancelled_outcome(
            "websocket_close",
            "completed",
            Some(reason.to_string()),
            None,
        ));
    }
    state.closed = true;
    Ok(())
}

/// Reset helper for host-side deterministic tests.
pub fn reset_dispatcher_for_tests() {
    DISPATCHER.with(|dispatcher| {
        *dispatcher.borrow_mut() = WasmExportDispatcher::new();
    });
    #[cfg(target_arch = "wasm32")]
    INFLIGHT_FETCHES.with(|fetches| {
        fetches.borrow_mut().clear();
    });
    INFLIGHT_WEBSOCKETS.with(|sockets| {
        sockets.borrow_mut().clear();
    });
}

/// Host-side diagnostics helper for export-boundary tests.
#[must_use]
pub fn dispatcher_diagnostics_for_tests() -> WasmDispatcherDiagnostics {
    DISPATCHER.with(|dispatcher| dispatcher.borrow().diagnostic_snapshot())
}

fn runtime_create_impl(request_json: Option<String>) -> Result<String, String> {
    let request: BrowserRuntimeCreateRequest = request_json.map_or_else(
        || Ok(BrowserRuntimeCreateRequest::default()),
        |request_json| parse_json(&request_json, "runtime_create.request"),
    )?;
    let fetch_authority = canonicalize_fetch_authority(request.fetch_authority)?;
    let consumer_version = request.consumer_version;
    let handle = with_dispatcher(|dispatcher| {
        let handle = dispatcher.runtime_create(consumer_version)?;
        if let Err(error) = dispatcher.register_runtime_fetch_authority(&handle, fetch_authority) {
            let _ = dispatcher.runtime_close(&handle, consumer_version);
            return Err(error);
        }
        Ok(handle)
    })?;
    encode_json(&handle, "runtime_create.response")
}

fn browser_operator_snapshot_impl() -> Result<String, String> {
    cleanup_released_host_state();
    let snapshot = DISPATCHER.with(|dispatcher| {
        let diagnostics = dispatcher.borrow().diagnostic_snapshot();
        BrowserOperatorConsoleSnapshot::from_dispatcher_diagnostics(&diagnostics)
    });
    encode_json(&snapshot, "browser_operator_snapshot.response")
}

fn runtime_close_impl(
    handle_json: String,
    consumer_version_json: Option<String>,
) -> Result<String, String> {
    let handle: WasmHandleRef = parse_json(&handle_json, "runtime_close.request")?;
    let consumer_version = parse_consumer_version(consumer_version_json)?;
    let outcome =
        with_dispatcher(|dispatcher| dispatcher.runtime_close(&handle, consumer_version))?;
    cleanup_released_host_state();
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
    cleanup_released_host_state();
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

    #[cfg(target_arch = "wasm32")]
    if let Some(controller) = take_inflight_fetch(&request.task) {
        controller.abort();
    }

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
    let close_reason = request.reason.clone();
    let mut state = take_websocket_state(&request.socket)
        .ok_or_else(|| format!("unknown websocket handle: {:?}", request.socket))?;
    if let Err(err) = close_browser_websocket_socket(&mut state, close_reason.as_deref()) {
        insert_websocket_state(request.socket, state);
        return Err(err);
    }
    let outcome = if let Some(reason) = close_reason {
        cancelled_outcome(
            "websocket_close",
            "completed",
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
    let cancel_message = request.message.clone();
    let cancel = WasmTaskCancelRequest {
        task: request.socket,
        kind: request.kind.clone(),
        message: cancel_message.clone(),
    };
    let _ = cancel_websocket_handle(&cancel, consumer_version)?;
    if let Some(mut state) = take_websocket_state(&request.socket)
        && let Err(err) = close_browser_websocket_socket(&mut state, cancel_message.as_deref())
    {
        insert_websocket_state(request.socket, state);
        return Err(err);
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

#[cfg(test)]
mod tests {
    use super::{
        BrowserFetchAuthorityConfig, canonicalize_browser_http_url, canonicalize_fetch_authority,
    };
    use asupersync::io::FetchMethod;

    #[test]
    fn fetch_url_canonicalization_matches_browser_special_url_boundaries() {
        let (url, origin) =
            canonicalize_browser_http_url(r"HTTPS://API.EXAMPLE.COM:443\records?limit=1")
                .expect("special URL must canonicalize");
        assert_eq!(url, "https://api.example.com/records?limit=1");
        assert_eq!(origin, "https://api.example.com");

        let error = canonicalize_browser_http_url("https://user:secret@api.example.com/data")
            .expect_err("embedded credentials must fail closed");
        assert!(error.contains("embedded credentials"));
    }

    #[test]
    fn fetch_authority_origins_and_methods_are_canonicalized_once() {
        let authority = canonicalize_fetch_authority(BrowserFetchAuthorityConfig {
            allowed_origins: vec!["HTTPS://API.EXAMPLE.COM:443/base".to_string()],
            allowed_methods: vec![" get ".to_string()],
            allow_credentials: false,
            max_header_count: 0,
        })
        .expect("authority must canonicalize");

        assert_eq!(
            authority.allowed_origins,
            vec!["https://api.example.com".to_string()]
        );
        assert_eq!(authority.allowed_methods, vec![FetchMethod::Get]);
        assert!(!authority.allow_credentials);
    }
}

#[cfg(target_arch = "wasm32")]
fn into_js_error(err: String) -> JsValue {
    JsValue::from_str(&err)
}
