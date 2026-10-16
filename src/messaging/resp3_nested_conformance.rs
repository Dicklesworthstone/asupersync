//! RESP3 nested Map/Set conformance tests.
//!
//! This module implements value-model conformance tests for RESP3 nested Map/Set
//! encoding/decoding. Tests focus on round-trip fidelity and wire format compatibility
//! with known good golden vectors matching the redis-rs value model.

#[cfg(test)]
#[path = "resp3_nested_conformance_inline_tests.rs"]
mod tests;
