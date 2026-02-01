//! WebSocket end-to-end (E2E) test suite.
//!
//! This mirrors `bd-35ld` and intentionally mixes:
//! - protocol-level conformance checks (wire bytes)
//! - cancel-correctness scenarios
//! - real TCP integration tests
//! - deterministic lab tests (virtual TCP + LabRuntime)

pub mod cancel_correctness;
pub mod conformance;
pub mod integration;
pub mod lab;
pub mod util;
