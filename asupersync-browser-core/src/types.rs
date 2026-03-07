//! JS-visible type wrappers and serialization helpers.
//!
//! Bridges between core ABI types (`WasmAbiOutcomeEnvelope`, `WasmHandleRef`,
//! etc.) and `JsValue` representations using `serde-wasm-bindgen`.
//!
//! This module focuses on deterministic payload marshalling for bead
//! `asupersync-3qv04.2.3`.

use asupersync::types::WasmAbiVersion;
use serde::Serialize;
use serde::de::DeserializeOwned;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsValue;

/// Decode a JSON payload string into a typed ABI value.
pub fn decode_json_payload<T: DeserializeOwned>(raw: &str, field: &str) -> Result<T, String> {
    serde_json::from_str(raw)
        .map_err(|err| format!("failed to decode {field} JSON payload: {err}; payload={raw}"))
}

/// Encode a typed ABI value into a JSON payload string.
pub fn encode_json_payload<T: Serialize>(value: &T, field: &str) -> Result<String, String> {
    serde_json::to_string(value)
        .map_err(|err| format!("failed to encode {field} JSON payload: {err}"))
}

/// Decode optional consumer ABI version from an optional JSON payload.
pub fn decode_optional_consumer_version(
    raw: Option<String>,
) -> Result<Option<WasmAbiVersion>, String> {
    match raw {
        None => Ok(None),
        Some(version) if version.trim().is_empty() => Ok(None),
        Some(version) => decode_json_payload(&version, "consumer_version").map(Some),
    }
}

/// Decode a `JsValue` payload into a typed ABI value on wasm targets.
#[cfg(target_arch = "wasm32")]
pub fn decode_js_payload<T: DeserializeOwned>(value: JsValue, field: &str) -> Result<T, String> {
    serde_wasm_bindgen::from_value(value)
        .map_err(|err| format!("failed to decode {field} JsValue payload: {err}"))
}

/// Encode a typed ABI value into `JsValue` on wasm targets.
#[cfg(target_arch = "wasm32")]
pub fn encode_js_payload<T: Serialize>(value: &T, field: &str) -> Result<JsValue, String> {
    serde_wasm_bindgen::to_value(value)
        .map_err(|err| format!("failed to encode {field} JsValue payload: {err}"))
}

#[cfg(test)]
mod tests {
    use super::{decode_json_payload, decode_optional_consumer_version, encode_json_payload};
    use asupersync::types::{
        WasmAbiOutcomeEnvelope, WasmAbiValue, WasmAbiVersion, WasmHandleKind, WasmHandleRef,
    };

    #[test]
    fn handle_ref_json_round_trip_holds() {
        let handle = WasmHandleRef {
            kind: WasmHandleKind::Task,
            slot: 7,
            generation: 3,
        };

        let encoded = encode_json_payload(&handle, "handle").expect("encode handle");
        let decoded: WasmHandleRef =
            decode_json_payload(&encoded, "handle").expect("decode handle");
        assert_eq!(decoded, handle);
    }

    #[test]
    fn outcome_envelope_json_round_trip_holds() {
        let outcome = WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::String("ready".to_string()),
        };

        let encoded = encode_json_payload(&outcome, "outcome").expect("encode outcome");
        let decoded: WasmAbiOutcomeEnvelope =
            decode_json_payload(&encoded, "outcome").expect("decode outcome");
        assert_eq!(decoded, outcome);
    }

    #[test]
    fn consumer_version_decoding_handles_none_and_blank() {
        assert_eq!(decode_optional_consumer_version(None).expect("none"), None);
        assert_eq!(
            decode_optional_consumer_version(Some(String::new())).expect("blank"),
            None
        );
        assert_eq!(
            decode_optional_consumer_version(Some("   ".to_string())).expect("whitespace"),
            None
        );
    }

    #[test]
    fn consumer_version_decoding_parses_valid_json() {
        let version_json = r#"{"major":1,"minor":2}"#.to_string();
        let parsed = decode_optional_consumer_version(Some(version_json)).expect("parse version");
        assert_eq!(parsed, Some(WasmAbiVersion { major: 1, minor: 2 }));
    }
}
