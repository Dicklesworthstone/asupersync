//! Non-canonical export scaffold for future binding experiments.
//!
//! The shipped v1 ABI exports live in `asupersync-browser-core`. This module is
//! intentionally retained as a non-live scaffold so the repository does not
//! claim a second live JS/WASM boundary.
//!
//! Instead of exporting a second live boundary, the scaffold exposes explicit
//! status helpers plus a deterministic fail-closed path for mistaken callers.

use crate::error::{
    RetainedBoundaryError, non_canonical_boundary_error, non_canonical_boundary_error_json,
};
use crate::types::{RetainedBoundaryStatus, retained_boundary_status};

/// Return the truthful status of this retained scaffold.
#[must_use]
pub fn canonical_boundary_status() -> RetainedBoundaryStatus {
    retained_boundary_status()
}

/// Encode the truthful status as JSON for tooling and docs tests.
#[must_use]
pub fn canonical_boundary_status_json() -> String {
    serde_json::to_string(&canonical_boundary_status())
        .unwrap_or_else(|_| "{\"role\":\"retained-scaffold\"}".to_string())
}

/// Fail closed when a caller asks this crate to serve a live ABI symbol.
pub fn fail_closed_symbol(symbol: &str) -> Result<(), RetainedBoundaryError> {
    Err(non_canonical_boundary_error(symbol))
}

/// JSON-encoded fail-closed response for deterministic host-side checks.
pub fn fail_closed_symbol_json(symbol: &str) -> Result<String, String> {
    Err(non_canonical_boundary_error_json(symbol))
}

#[cfg(test)]
mod tests {
    use super::{
        RetainedBoundaryStatus, canonical_boundary_status, canonical_boundary_status_json,
        fail_closed_symbol, fail_closed_symbol_json,
    };

    #[test]
    fn status_json_round_trips() {
        let encoded = canonical_boundary_status_json();
        let decoded: RetainedBoundaryStatus =
            serde_json::from_str(&encoded).expect("decode retained scaffold status");

        assert_eq!(decoded, canonical_boundary_status());
    }

    #[test]
    fn fail_closed_symbol_returns_structured_error() {
        let err = fail_closed_symbol("task_spawn").expect_err("scaffold must fail closed");
        assert_eq!(err.requested_symbol, "task_spawn");

        let err_json =
            fail_closed_symbol_json("task_spawn").expect_err("scaffold json path must fail");
        assert!(err_json.contains("task_spawn"));
        assert!(err_json.contains("asupersync-browser-core"));
    }
}
