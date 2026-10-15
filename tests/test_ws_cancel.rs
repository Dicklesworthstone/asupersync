//! Tombstone guard for WebSocket cancellation coverage.
//!
//! The executable cancellation cases live under the canonical
//! `e2e_websocket` integration target. Keep this legacy target as a guard so it
//! fails if the moved coverage is disconnected.

const E2E_WEBSOCKET_TARGET: &str = include_str!("e2e_websocket.rs");
const WEBSOCKET_E2E_MODULE: &str = include_str!("e2e/websocket/mod.rs");
const CANCEL_CORRECTNESS_MODULE: &str = include_str!("e2e/websocket/cancel_correctness/mod.rs");

#[test]
fn moved_websocket_cancel_coverage_still_exists() {
    assert!(
        E2E_WEBSOCKET_TARGET.contains("mod websocket_e2e;"),
        "e2e_websocket.rs no longer includes the websocket E2E module"
    );
    assert!(
        WEBSOCKET_E2E_MODULE.contains("pub mod cancel_correctness;"),
        "websocket E2E module no longer exposes cancel-correctness coverage"
    );
    assert!(
        CANCEL_CORRECTNESS_MODULE.contains("mod client_cancel;")
            && CANCEL_CORRECTNESS_MODULE.contains("mod server_cancel;"),
        "websocket cancel-correctness module no longer includes both client and server cases"
    );
}
