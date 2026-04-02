//! Concrete ABI export wrappers re-exported at the crate root.
//!
//! The dispatcher and host/browser bridge state live in [`crate::lib`]. This
//! module owns the public v1 export surface so the implementation matches the
//! documented boundary instead of leaving a stale placeholder module behind.

#[cfg(target_arch = "wasm32")]
use super::into_js_error;
use super::{
    abi_fingerprint_impl, abi_version_impl, fetch_request_impl, runtime_close_impl,
    runtime_create_impl, scope_close_impl, scope_enter_impl, task_cancel_impl, task_join_impl,
    task_spawn_impl, websocket_cancel_impl, websocket_close_impl, websocket_open_impl,
    websocket_recv_impl, websocket_send_impl,
};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::{JsValue, prelude::wasm_bindgen};

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
pub fn abi_fingerprint() -> u64 {
    abi_fingerprint_impl()
}

/// Host adapter for `abi_fingerprint`.
#[cfg(not(target_arch = "wasm32"))]
#[must_use]
pub const fn abi_fingerprint() -> u64 {
    abi_fingerprint_impl()
}
