#![allow(warnings)]
#![allow(clippy::all)]
//! RaptorQ RFC 6330 Golden File Testing and Round-Trip Validation
//!
//! Implements Pattern 2 (Golden File Testing) and Pattern 3 (Round-Trip Conformance)
//! for comprehensive RaptorQ conformance testing.

pub mod golden_file_manager;
pub mod golden_file_manager_simple;
pub mod round_trip_harness;
pub mod fixture_generator_simple;

// Re-export main types
pub use golden_file_manager::GoldenFileManager;
pub use round_trip_harness::{RoundTripHarness, RoundTripConfig, RoundTripSummary};
pub use fixture_generator_simple::{FixtureGenerator, SimpleParameterFixture};