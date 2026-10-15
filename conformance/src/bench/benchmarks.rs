//! Default benchmark definitions.

use crate::RuntimeInterface;
use crate::bench::Benchmark;

/// Default benchmark set for conformance runtime comparisons.
pub fn default_benchmarks<R: RuntimeInterface>() -> Vec<Benchmark<R>> {
    vec![]
}
