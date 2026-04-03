//! Non-canonical error-conversion scaffold for a future alternative binding lane.
//!
//! The shipped Browser Edition error boundary lives in
//! `asupersync-browser-core`; this module remains intentionally non-canonical
//! so `asupersync-wasm` does not masquerade as a second supported owner.
//!
//! Instead of pretending to own the JS/WASM boundary, this crate fails closed
//! and returns explicit metadata pointing callers at the canonical owner.

use crate::types::{CANONICAL_JS_PACKAGE, CANONICAL_RUST_CRATE, RETAINED_ROLE};
use serde::{Deserialize, Serialize};

/// Machine-readable code for requests routed to the non-canonical scaffold.
pub const NON_CANONICAL_BOUNDARY_ERROR_CODE: &str = "non_canonical_boundary";

/// Explicit error returned when callers try to use this crate as the live boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetainedBoundaryError {
    pub code: String,
    pub requested_symbol: String,
    pub role: String,
    pub canonical_rust_crate: String,
    pub canonical_js_package: String,
    pub message: String,
}

/// Build a deterministic error directing callers to the canonical boundary crate.
#[must_use]
pub fn non_canonical_boundary_error(requested_symbol: &str) -> RetainedBoundaryError {
    RetainedBoundaryError {
        code: NON_CANONICAL_BOUNDARY_ERROR_CODE.to_string(),
        requested_symbol: requested_symbol.to_string(),
        role: RETAINED_ROLE.to_string(),
        canonical_rust_crate: CANONICAL_RUST_CRATE.to_string(),
        canonical_js_package: CANONICAL_JS_PACKAGE.to_string(),
        message: format!(
            "`{requested_symbol}` is not available from `asupersync-wasm`; use `{CANONICAL_RUST_CRATE}` / `{CANONICAL_JS_PACKAGE}` for the shipped JS/WASM boundary"
        ),
    }
}

/// Encode the retained-scaffold error as JSON for deterministic callers/tests.
#[must_use]
pub fn non_canonical_boundary_error_json(requested_symbol: &str) -> String {
    serde_json::to_string(&non_canonical_boundary_error(requested_symbol)).unwrap_or_else(|_| {
        format!(
            "{{\"code\":\"{NON_CANONICAL_BOUNDARY_ERROR_CODE}\",\"requested_symbol\":\"{requested_symbol}\",\"message\":\"non-canonical boundary\"}}"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::{
        NON_CANONICAL_BOUNDARY_ERROR_CODE, RetainedBoundaryError, non_canonical_boundary_error,
        non_canonical_boundary_error_json,
    };

    #[test]
    fn error_names_canonical_boundary_owner() {
        let err = non_canonical_boundary_error("runtime_create");

        assert_eq!(err.code, NON_CANONICAL_BOUNDARY_ERROR_CODE);
        assert_eq!(err.requested_symbol, "runtime_create");
        assert_eq!(err.role, "retained-scaffold");
        assert!(err.message.contains("asupersync-browser-core"));
        assert!(err.message.contains("@asupersync/browser-core"));
    }

    #[test]
    fn error_json_round_trips() {
        let encoded = non_canonical_boundary_error_json("abi_version");
        let decoded: RetainedBoundaryError =
            serde_json::from_str(&encoded).expect("decode retained boundary error");

        assert_eq!(decoded.code, NON_CANONICAL_BOUNDARY_ERROR_CODE);
        assert_eq!(decoded.requested_symbol, "abi_version");
    }
}
