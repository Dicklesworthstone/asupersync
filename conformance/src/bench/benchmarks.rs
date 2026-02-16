//! Default benchmark definitions.

use crate::bench::Benchmark;
use crate::RuntimeInterface;

/// Default benchmark set for conformance runtime comparisons.
pub fn default_benchmarks<R: RuntimeInterface>() -> Vec<Benchmark<R>> {
    vec![]
}
