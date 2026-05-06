//! Common utilities and fixtures for console E2E tests.

use asupersync::runtime::RuntimeState;
use std::sync::Arc;

/// Create a minimal runtime state for diagnostics testing.
#[must_use]
#[allow(clippy::arc_with_non_send_sync)]
pub fn create_test_runtime_state() -> Arc<RuntimeState> {
    Arc::new(RuntimeState::new())
}
