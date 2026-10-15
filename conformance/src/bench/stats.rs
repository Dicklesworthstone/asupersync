//! Statistics and comparison helpers for benchmarks.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;

/// Errors that can occur while computing statistics.
#[derive(Debug, Clone)]
pub enum StatsError {
    /// No samples were provided.
    EmptySamples,
}

impl fmt::Display for StatsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StatsError::EmptySamples => write!(f, "no samples provided"),
        }
    }
}

impl std::error::Error for StatsError {}

/// Statistical summary of benchmark results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stats {
    pub min: Duration,
    pub max: Duration,
    pub mean: Duration,
    pub median: Duration,
    pub std_dev: Duration,
    pub p50: Duration,
    pub p75: Duration,
    pub p90: Duration,
    pub p95: Duration,
    pub p99: Duration,
    pub p999: Duration,
    pub sample_count: usize,
}

impl Stats {
    /// Compute statistics from samples.
    pub fn from_samples(samples: &[Duration]) -> Result<Self, StatsError> {
        if samples.is_empty() {
            return Err(StatsError::EmptySamples);
        }

        let mut sorted: Vec<u128> = samples.iter().map(|d| d.as_nanos()).collect();
        sorted.sort_unstable();

        let n = sorted.len();
        let sum_nanos: u128 = sorted.iter().copied().sum();
        let mean_nanos = sum_nanos / n as u128;

        let mean_f64 = mean_nanos as f64;
        let variance = sorted
            .iter()
            .map(|value| {
                let diff = *value as f64 - mean_f64;
                diff * diff
            })
            .sum::<f64>()
            / n as f64;
        let std_dev_nanos = variance.sqrt();

        Ok(Self {
            min: nanos_to_duration(*sorted.first().unwrap()),
            max: nanos_to_duration(*sorted.last().unwrap()),
            mean: nanos_to_duration(mean_nanos),
            median: nanos_to_duration(percentile(&sorted, 1, 2)),
            std_dev: Duration::from_nanos(f64_to_u64_saturating(std_dev_nanos)),
            p50: nanos_to_duration(percentile(&sorted, 50, 100)),
            p75: nanos_to_duration(percentile(&sorted, 75, 100)),
            p90: nanos_to_duration(percentile(&sorted, 90, 100)),
            p95: nanos_to_duration(percentile(&sorted, 95, 100)),
            p99: nanos_to_duration(percentile(&sorted, 99, 100)),
            p999: nanos_to_duration(percentile(&sorted, 999, 1000)),
            sample_count: n,
        })
    }

    /// Coefficient of variation (std_dev / mean).
    pub fn cv(&self) -> f64 {
        let mean = self.mean.as_nanos() as f64;
        if mean == 0.0 {
            return 0.0;
        }
        self.std_dev.as_nanos() as f64 / mean
    }
}

/// Comparison between two implementations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Comparison {
    pub a: Stats,
    pub b: Stats,
    pub speedup: f64,
    pub confidence: ComparisonConfidence,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ComparisonConfidence {
    /// Clear winner, low variance.
    High,
    /// Likely winner, some variance.
    Medium,
    /// Too close to call.
    Low,
    /// High variance, unreliable.
    Uncertain,
}

impl Comparison {
    /// Compute a comparison summary between two stats.
    pub fn compute(a: &Stats, b: &Stats) -> Self {
        let a_mean = a.mean.as_nanos() as f64;
        let b_mean = b.mean.as_nanos() as f64;
        let speedup = if a_mean == 0.0 {
            f64::INFINITY
        } else {
            b_mean / a_mean
        };

        let avg_cv = (a.cv() + b.cv()) / 2.0;
        let diff_pct = (speedup - 1.0).abs();

        let confidence = if avg_cv > 0.5 {
            ComparisonConfidence::Uncertain
        } else if diff_pct < 0.05 {
            ComparisonConfidence::Low
        } else if avg_cv > 0.2 {
            ComparisonConfidence::Medium
        } else {
            ComparisonConfidence::High
        };

        Self {
            a: a.clone(),
            b: b.clone(),
            speedup,
            confidence,
        }
    }
}

fn percentile(sorted: &[u128], numerator: usize, denominator: usize) -> u128 {
    let n = sorted.len();
    let idx = (n.saturating_sub(1) * numerator) / denominator;
    sorted[idx]
}

fn nanos_to_duration(nanos: u128) -> Duration {
    Duration::from_nanos(u128_to_u64_saturating(nanos))
}

fn u128_to_u64_saturating(value: u128) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn f64_to_u64_saturating(value: f64) -> u64 {
    if !value.is_finite() || value <= 0.0 {
        return 0;
    }
    if value >= u64::MAX as f64 {
        return u64::MAX;
    }
    value.round() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_basic() {
        let samples = [
            Duration::from_micros(10),
            Duration::from_micros(20),
            Duration::from_micros(30),
            Duration::from_micros(40),
        ];
        let stats = Stats::from_samples(&samples).expect("stats computed");

        assert_eq!(stats.sample_count, 4);
        assert_eq!(stats.min, Duration::from_micros(10));
        assert_eq!(stats.max, Duration::from_micros(40));
        assert_eq!(stats.p50, Duration::from_micros(20));
    }
}
