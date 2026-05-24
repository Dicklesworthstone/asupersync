//! Focused obligation cleanup E2E runner.

#[test]
fn test_client_disconnect_forced_cancel_cleans_pending_obligations() {
    asupersync::real_obligation_leak_check_e2e_tests::run_client_disconnect_forced_cancel_cleanup_e2e();
}
