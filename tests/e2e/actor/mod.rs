//! Actor end-to-end (E2E) test suite.
//!
//! This suite tests actor functionality across:
//! - Unit tests for core actor primitives
//! - Integration tests for actor + lab runtime determinism
//! - E2E tests for realistic actor scenarios
//! - Lab tests for deterministic scheduling verification

pub mod e2e;
pub mod integration;
pub mod lab;
pub mod unit;
pub mod util;
