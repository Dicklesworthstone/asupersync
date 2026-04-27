#![allow(warnings)]
#![allow(clippy::all)]
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

/// Placeholder test for non-BSD platforms
/// This ensures the module compiles on all platforms but only runs the actual
/// kqueue tests on BSD systems where kqueue is available.
#[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
#[test]
#[allow(dead_code)]
fn kqueue_conformance_requires_bsd_platform() {
    // This test serves as documentation that kqueue conformance tests
    // are only available on macOS and FreeBSD platforms.
    println!("kqueue conformance tests require macOS or FreeBSD");
    assert!(true, "Placeholder test for non-BSD platforms");
}

// The actual BSD kqueue conformance tests live in the standalone integration
// test crate `tests/conformance_kqueue_bsd_events.rs` and run via:
//     cargo test --test conformance_kqueue_bsd_events
// They CANNOT be re-exported here — each top-level `tests/*.rs` is its own
// crate root in cargo's integration-test model, so `super::super::<sibling>`
// does not resolve. Previous attempt at `pub use super::super::
// conformance_kqueue_bsd_events::*;` was removed for that reason.
