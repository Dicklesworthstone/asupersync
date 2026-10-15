#![allow(warnings)]
#![allow(clippy::all)]
//! Simple Fixture Generator for RaptorQ Golden File Testing

use serde::{Deserialize, Serialize};

/// Basic fixture generator for RaptorQ conformance testing
#[derive(Debug)]
#[allow(dead_code)]
pub struct FixtureGenerator {
    seed: u64,
}

#[allow(dead_code)]

impl FixtureGenerator {
    #[allow(dead_code)]
    pub fn new(seed: u64) -> Self {
        Self { seed }
    }

    /// Generate test data for fixtures
    #[allow(dead_code)]
    pub fn generate_test_data(&self, size: usize, pattern: u8) -> Vec<u8> {
        vec![pattern; size]
    }
}

/// Simple parameter derivation fixture
#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct SimpleParameterFixture {
    pub object_size: u64,
    pub symbol_size: u16,
    pub k_derived: u32,
}

#[allow(dead_code)]

impl SimpleParameterFixture {
    #[allow(dead_code)]
    pub fn compute(object_size: u64, symbol_size: u16) -> Self {
        let k_derived = ((object_size + symbol_size as u64 - 1) / symbol_size as u64) as u32;
        Self { object_size, symbol_size, k_derived }
    }
}