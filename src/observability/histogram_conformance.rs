//! Conformance tests for histogram metrics implementation.
//!
//! Tests critical properties that must hold for histogram correctness:
//! 1. Bucket boundaries honored with <1ulp drift
//! 2. Σ(bucket_counts) == total_count conservation invariant
//! 3. sum/mean/p99 statistical invariants
//! 4. concurrent recorders don't double-count (thread safety)
//! 5. histogram reset atomicity
//!
//! These golden tests verify that histogram implementations conform to
//! mathematical properties required for accurate metrics collection.

#[cfg(feature = "metrics")]
#[cfg(test)]
#[path = "histogram_conformance_conformance_tests_inline_tests.rs"]
mod conformance_tests;
