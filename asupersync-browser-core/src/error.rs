//! JS error conversions for the WASM boundary.
//!
//! Maps `WasmAbiFailure` and Rust panics to structured JS errors with
//! deterministic codes and diagnostic metadata.
//!
//! This module focuses on deterministic boundary-error marshalling for
//! bead `asupersync-3qv04.2.3`.

use asupersync::types::WasmDispatchError;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsValue;

/// Encode a dispatch error into the canonical JSON failure payload.
#[must_use]
pub fn dispatch_error_json(err: &WasmDispatchError) -> String {
    let failure = err.to_failure();
    serde_json::to_string(&failure).unwrap_or_else(|_| err.to_string())
}

/// Encode a dispatch error as `JsValue` for wasm-bindgen function boundaries.
#[cfg(target_arch = "wasm32")]
#[must_use]
pub fn dispatch_error_js(err: &WasmDispatchError) -> JsValue {
    JsValue::from_str(&dispatch_error_json(err))
}

#[cfg(test)]
mod tests {
    use super::dispatch_error_json;
    use asupersync::types::wasm_abi::WasmHandleError;
    use asupersync::types::{
        WasmAbiErrorCode, WasmAbiFailure, WasmAbiRecoverability, WasmDispatchError,
    };

    #[test]
    fn invalid_request_maps_to_decode_failure_payload() {
        let err = WasmDispatchError::InvalidRequest {
            reason: "malformed payload".to_string(),
        };
        let encoded = dispatch_error_json(&err);
        let decoded: WasmAbiFailure = serde_json::from_str(&encoded).expect("decode failure json");

        assert_eq!(decoded.code, WasmAbiErrorCode::DecodeFailure);
        assert_eq!(decoded.recoverability, WasmAbiRecoverability::Permanent);
        assert!(decoded.message.contains("invalid request"));
    }

    #[test]
    fn handle_errors_map_to_invalid_handle_payload() {
        let err = WasmDispatchError::Handle(WasmHandleError::SlotOutOfRange {
            slot: 11,
            table_size: 10,
        });
        let encoded = dispatch_error_json(&err);
        let decoded: WasmAbiFailure = serde_json::from_str(&encoded).expect("decode failure json");

        assert_eq!(decoded.code, WasmAbiErrorCode::InvalidHandle);
        assert_eq!(decoded.recoverability, WasmAbiRecoverability::Permanent);
        assert!(decoded.message.contains("handle error"));
    }
}
