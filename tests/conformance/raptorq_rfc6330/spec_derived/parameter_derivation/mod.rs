//! Parameter derivation tests for RFC 6330 sections 5.1-5.2.
//!
//! Tests systematic index calculation, K derivation, K' calculation,
//! and parameter derivation algorithms (J, P1, P, H, W).

pub mod k_calculation_tests;
pub mod systematic_index_tests;
pub mod tuple_generation_tests;

use super::{Rfc6330ConformanceCase, Rfc6330ConformanceSuite};

/// Register all parameter derivation tests.
#[allow(dead_code)]
pub fn register_tests(suite: &mut Rfc6330ConformanceSuite) {
    k_calculation_tests::register_tests(suite);
    systematic_index_tests::register_tests(suite);
    tuple_generation_tests::register_tests(suite);
}