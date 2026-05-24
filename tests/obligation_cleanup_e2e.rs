//! Focused obligation cleanup E2E runner.
//!
//! The runner lives in `asupersync::real_obligation_leak_check_e2e_tests`,
//! which is itself gated by the `real-service-e2e` or `obligation-cleanup-e2e`
//! features. Gate this integration test the same way so it compiles cleanly
//! in the default test build instead of failing closed with an unresolved
//! import.
#![cfg(any(feature = "real-service-e2e", feature = "obligation-cleanup-e2e"))]

#[test]
fn test_client_disconnect_forced_cancel_cleans_pending_obligations() {
    asupersync::real_obligation_leak_check_e2e_tests::run_client_disconnect_forced_cancel_cleanup_e2e();
}
