//! Benchmark framework for conformance and performance comparisons.

use crate::RuntimeInterface;
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub mod benchmarks;
pub mod report;
pub mod runner;
pub mod stats;

pub use benchmarks::default_benchmarks;
pub use report::{
    render_console_summary, write_html_comparison_report, write_html_report, write_json_report,
};
pub use runner::{
    BenchAllocSnapshot, BenchAllocStats, BenchComparisonResult, BenchComparisonSummary,
    BenchConfig, BenchOutput, BenchRunResult, BenchRunSummary, BenchRunner, BenchThresholds,
    RegressionCheck, RegressionConfig, RegressionMetric, run_benchmark_comparison,
};
pub use stats::{Comparison, ComparisonConfidence, Stats, StatsError};

/// Benchmark category for grouping and filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BenchCategory {
    /// Task creation overhead.
    TaskSpawn,
    /// Context switch latency.
    TaskSwitch,
    /// Channel throughput (messages/sec).
    ChannelThroughput,
    /// Channel latency (round-trip time).
    ChannelLatency,
    /// Mutex contention behavior.
    MutexContention,
    /// Timer accuracy.
    TimerAccuracy,
    /// I/O throughput.
    IoThroughput,
    /// I/O latency.
    IoLatency,
}

/// Definition of a benchmark for a runtime implementation.
pub struct Benchmark<R: RuntimeInterface> {
    /// Unique identifier.
    pub id: &'static str,
    /// Human-readable name.
    pub name: &'static str,
    /// Description of what this benchmark measures.
    pub description: &'static str,
    /// Category for grouping.
    pub category: BenchCategory,
    /// Number of warmup iterations.
    pub warmup: u32,
    /// Number of measurement iterations.
    pub iterations: u32,
    /// The benchmark function.
    pub bench_fn: Box<dyn Fn(&R) -> Duration + Send + Sync>,
}

impl<R: RuntimeInterface> Benchmark<R> {
    /// Create a new benchmark definition.
    pub fn new(
        id: &'static str,
        name: &'static str,
        description: &'static str,
        category: BenchCategory,
        warmup: u32,
        iterations: u32,
        bench_fn: impl Fn(&R) -> Duration + Send + Sync + 'static,
    ) -> Self {
        Self {
            id,
            name,
            description,
            category,
            warmup,
            iterations,
            bench_fn: Box::new(bench_fn),
        }
    }
}

/// Macro for defining benchmarks.
#[macro_export]
macro_rules! benchmark {
    (
        id: $id:literal,
        name: $name:literal,
        description: $desc:literal,
        category: $cat:expr,
        warmup: $warmup:expr,
        iterations: $iters:expr,
        bench: |$rt:ident| $body:expr
    ) => {
        $crate::bench::Benchmark::new($id, $name, $desc, $cat, $warmup, $iters, |$rt| $body)
    };
}
