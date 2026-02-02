//! Actor E2E test suite entry point.
//!
//! This file provides the entry point for the actor E2E test suite,
//! including unit tests, integration tests, lab runtime tests, and E2E scenarios.
//!
//! Run with: `cargo test --test e2e_actor`

#![allow(unused_imports)]

mod common {
    pub fn init_test_logging() {
        // Initialize tracing for tests if not already done
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_test_writer()
            .try_init();
    }
}

/// Phase tracking macro for structured test logging.
#[macro_export]
macro_rules! test_phase {
    ($name:expr) => {
        tracing::info!(test = $name, "=== TEST START ===");
    };
}

/// Assertion with logging for better test output.
#[macro_export]
macro_rules! assert_with_log {
    ($cond:expr, $msg:expr, $expected:expr, $actual:expr) => {
        if !$cond {
            tracing::error!(
                message = $msg,
                expected = ?$expected,
                actual = ?$actual,
                "Assertion failed"
            );
        }
        assert!($cond, "{}: expected {:?}, got {:?}", $msg, $expected, $actual);
    };
}

// Re-export the actor test module as actor_e2e for internal use
#[path = "e2e/actor/mod.rs"]
pub mod actor_e2e;
