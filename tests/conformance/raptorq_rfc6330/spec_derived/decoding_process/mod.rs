#![allow(warnings)]
#![allow(clippy::all)]
//! Decoding process tests for RFC 6330 Section 4.3.

pub mod constraint_matrix_tests;
pub mod gaussian_elimination_tests;
pub mod reconstruction_tests;

use super::{Rfc6330ConformanceCase, Rfc6330ConformanceSuite};

/// Register all decoding process tests.
#[allow(dead_code)]
pub fn register_tests(suite: &mut Rfc6330ConformanceSuite) {
    constraint_matrix_tests::register_tests(suite);
    gaussian_elimination_tests::register_tests(suite);
    reconstruction_tests::register_tests(suite);
}