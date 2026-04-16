//! Encoding process tests for RFC 6330 Section 4.2.
//!
//! Tests systematic symbol generation, repair symbol generation,
//! and Encoding Symbol ID (ESI) validation.

pub mod systematic_encoding_tests;
pub mod repair_symbol_tests;
pub mod esi_validation_tests;

use super::{Rfc6330ConformanceCase, Rfc6330ConformanceSuite};

/// Register all encoding process tests.
pub fn register_tests(suite: &mut Rfc6330ConformanceSuite) {
    systematic_encoding_tests::register_tests(suite);
    repair_symbol_tests::register_tests(suite);
    esi_validation_tests::register_tests(suite);
}