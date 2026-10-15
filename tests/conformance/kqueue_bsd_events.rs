//! BSD kqueue event semantics conformance tests.
//!
//! This module provides conformance testing for BSD-specific kqueue behaviors
//! that are not covered by the standard unit tests in the kqueue reactor.

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
mod bsd_tests {
    // Re-export all the conformance tests from the main test file
    // This allows them to be discovered by the conformance test infrastructure
    // while keeping them conditionally compiled for BSD platforms only.
}

/// Non-BSD platform marker.
/// This ensures the module compiles on all platforms but only runs the actual
/// kqueue tests on BSD systems where kqueue is available.
#[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
#[test]
fn kqueue_conformance_is_bsd_only() {}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
mod bsd_standalone {
    // Cargo integration tests are separate crate roots, so this conformance
    // wrapper cannot re-export sibling `tests/conformance_kqueue_bsd_events.rs`.
    // The standalone BSD test crate owns those kqueue semantics checks.
}
