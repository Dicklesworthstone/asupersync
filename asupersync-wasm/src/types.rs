//! Non-canonical JS-type scaffold for a future alternative binding lane.
//!
//! The live JS-visible ABI type bridge is implemented in
//! `asupersync-browser-core`; this module remains intentionally non-canonical
//! so the workspace keeps one truthful shipped owner.
//!
//! Instead of mirroring the live ABI types, this crate exposes explicit
//! metadata describing its retained-scaffold role and the canonical owner.

use serde::{Deserialize, Serialize};

pub const CANONICAL_RUST_CRATE: &str = "asupersync-browser-core";
pub const CANONICAL_JS_PACKAGE: &str = "@asupersync/browser-core";
pub const RETAINED_ROLE: &str = "retained-scaffold";

/// Explicit status for the non-canonical scaffold crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetainedBoundaryStatus {
    pub role: String,
    pub canonical_rust_crate: String,
    pub canonical_js_package: String,
    pub message: String,
}

impl RetainedBoundaryStatus {
    /// Return the current truthful role of the crate.
    #[must_use]
    pub fn current() -> Self {
        Self {
            role: RETAINED_ROLE.to_string(),
            canonical_rust_crate: CANONICAL_RUST_CRATE.to_string(),
            canonical_js_package: CANONICAL_JS_PACKAGE.to_string(),
            message: format!(
                "`asupersync-wasm` is a retained scaffold; the shipped JS/WASM boundary lives in `{CANONICAL_RUST_CRATE}` / `{CANONICAL_JS_PACKAGE}`"
            ),
        }
    }
}

/// Return the current retained-scaffold status.
#[must_use]
pub fn retained_boundary_status() -> RetainedBoundaryStatus {
    RetainedBoundaryStatus::current()
}

#[cfg(test)]
mod tests {
    use super::{
        CANONICAL_JS_PACKAGE, CANONICAL_RUST_CRATE, RETAINED_ROLE, retained_boundary_status,
    };

    #[test]
    fn retained_status_names_canonical_owner() {
        let status = retained_boundary_status();

        assert_eq!(status.role, RETAINED_ROLE);
        assert_eq!(status.canonical_rust_crate, CANONICAL_RUST_CRATE);
        assert_eq!(status.canonical_js_package, CANONICAL_JS_PACKAGE);
        assert!(status.message.contains("retained scaffold"));
    }
}
