//! Concrete `#[wasm_bindgen]` export functions wrapping [`WasmExportDispatcher`].
//!
//! Each function in this module corresponds to a v1 ABI symbol. The dispatcher
//! owns all boundary state (handle table, lifecycle, event logging). These
//! wrappers handle only JS <-> Rust type conversion.
//!
//! Implementation deferred to bead `asupersync-3qv04.2.2`.

// Placeholder: concrete #[wasm_bindgen] exports will be implemented in
// asupersync-3qv04.2.2 once this strategy bead is accepted.
//
// The export surface will include:
//   - runtime_create() -> u64
//   - runtime_close(handle: u64) -> JsValue
//   - scope_enter(parent: u64, label: Option<String>) -> u64
//   - scope_close(handle: u64) -> JsValue
//   - task_spawn(scope: u64, label: Option<String>) -> u64
//   - task_join(handle: u64) -> JsValue
//   - task_cancel(handle: u64, kind: Option<String>) -> JsValue
//   - fetch_request(scope: u64, url: String, ...) -> JsValue
//   - abi_version() -> JsValue
//   - abi_fingerprint() -> u64
