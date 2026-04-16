//! Integration tests for multi-section RFC 6330 conformance.

pub mod end_to_end_conformance;
pub mod edge_case_matrix;

use super::{Rfc6330ConformanceCase, Rfc6330ConformanceSuite};

/// Register all integration tests.
pub fn register_tests(suite: &mut Rfc6330ConformanceSuite) {
    end_to_end_conformance::register_tests(suite);
    edge_case_matrix::register_tests(suite);
}