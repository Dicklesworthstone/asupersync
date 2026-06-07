//! High-precision timing side-channel detection for ATP security conformance.
//!
//! This module provides enhanced timing measurement and analysis capabilities
//! to detect subtle timing side-channels in ATP cryptographic operations.
//! Replaces Duration-based approach with hardware performance counters and
//! statistical analysis for improved detection precision.
//!
//! # Features
//!
//! - Hardware TSC (Time Stamp Counter) access for nanosecond precision
//! - Statistical analysis of timing distributions
//! - Baseline calibration to distinguish signal from noise
//! - Automated side-channel vulnerability detection
//!
//! # Security Model
//!
//! This module assumes an attacker with:
//! - High-resolution timing measurement capability
//! - Ability to trigger cryptographic operations with chosen inputs
//! - Statistical analysis tools to detect timing patterns
//!
//! The goal is to detect timing variations that could leak cryptographic
//! secrets through statistical timing analysis.

use std::collections::VecDeque;
use std::time::Instant;

/// Configuration for timing side-channel detection.
#[derive(Debug, Clone)]
pub struct TimingDetectorConfig {
    /// Number of timing samples to collect for baseline calibration.
    pub baseline_samples: usize,
    /// Statistical significance threshold for detecting timing differences.
    /// Lower values increase sensitivity but may cause false positives.
    pub significance_threshold: f64,
    /// Minimum timing difference (in nanoseconds) to consider suspicious.
    pub min_suspicious_delta_ns: u64,
    /// Maximum coefficient of variation allowed for baseline measurements.
    pub max_baseline_cv: f64,
    /// Number of warmup iterations to skip (for JIT/cache warmup).
    pub warmup_iterations: usize,
}

impl Default for TimingDetectorConfig {
    fn default() -> Self {
        Self {
            baseline_samples: 10000,
            significance_threshold: 0.01, // p < 0.01 for statistical significance
            min_suspicious_delta_ns: 100, // 100ns minimum detectable difference
            max_baseline_cv: 0.1,         // 10% coefficient of variation max
            warmup_iterations: 1000,
        }
    }
}

/// High-precision timing measurement using hardware performance counters.
#[derive(Debug, Clone)]
pub struct PrecisionTimer {
    source: PrecisionTimingSource,
    origin: Instant,
}

#[derive(Debug, Clone, Copy)]
enum PrecisionTimingSource {
    InvariantTsc { ticks_per_second: u64 },
    MonotonicClock,
}

impl PrecisionTimer {
    /// Create a new precision timer, detecting available timing sources.
    pub fn new() -> Self {
        Self {
            source: Self::detect_tsc_source().unwrap_or(PrecisionTimingSource::MonotonicClock),
            origin: Instant::now(),
        }
    }

    /// Detect if TSC (Time Stamp Counter) is available, invariant, and has
    /// a discoverable conversion rate.
    fn detect_tsc_source() -> Option<PrecisionTimingSource> {
        detect_invariant_tsc_frequency_hz()
            .map(|ticks_per_second| PrecisionTimingSource::InvariantTsc { ticks_per_second })
    }

    /// Take a high-precision timing measurement.
    /// Returns time in nanoseconds since an arbitrary epoch.
    pub fn now_ns(&self) -> u64 {
        match self.source {
            PrecisionTimingSource::InvariantTsc { ticks_per_second } => {
                ticks_to_nanos(read_tsc_ordered(), ticks_per_second)
            }
            PrecisionTimingSource::MonotonicClock => {
                u64::try_from(self.origin.elapsed().as_nanos()).unwrap_or(u64::MAX)
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn detect_invariant_tsc_frequency_hz() -> Option<u64> {
    let max_basic_leaf = cpuid(0).eax;
    if max_basic_leaf < 1 {
        return None;
    }

    let feature_leaf = cpuid(1);
    let has_tsc = feature_leaf.edx & (1 << 4) != 0;
    if !has_tsc {
        return None;
    }

    let max_extended_leaf = cpuid(0x8000_0000).eax;
    let has_invariant_tsc =
        max_extended_leaf >= 0x8000_0007 && (cpuid(0x8000_0007).edx & (1 << 8) != 0);
    if !has_invariant_tsc {
        return None;
    }

    cpuid_tsc_frequency_hz(max_basic_leaf)
}

#[cfg(not(target_arch = "x86_64"))]
fn detect_invariant_tsc_frequency_hz() -> Option<u64> {
    None
}

#[cfg(target_arch = "x86_64")]
fn cpuid_tsc_frequency_hz(max_basic_leaf: u32) -> Option<u64> {
    if max_basic_leaf >= 0x15 {
        let leaf = cpuid(0x15);
        let denominator = leaf.eax;
        let numerator = leaf.ebx;
        let crystal_hz = leaf.ecx;
        if denominator != 0 && numerator != 0 && crystal_hz != 0 {
            let hz = u128::from(crystal_hz) * u128::from(numerator) / u128::from(denominator);
            return u64::try_from(hz).ok().filter(|hz| *hz > 0);
        }
    }

    if max_basic_leaf >= 0x16 {
        let base_mhz = cpuid(0x16).eax;
        if base_mhz != 0 {
            return Some(u64::from(base_mhz) * 1_000_000);
        }
    }

    None
}

#[cfg(target_arch = "x86_64")]
fn cpuid(leaf: u32) -> core::arch::x86_64::CpuidResult {
    core::arch::x86_64::__cpuid(leaf)
}

#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
fn read_tsc_ordered() -> u64 {
    // SAFETY: LFENCE serializes the local core before/after the timestamp read;
    // RDTSC only reads the processor counter and does not dereference memory.
    unsafe {
        core::arch::x86_64::_mm_lfence();
        let ticks = core::arch::x86_64::_rdtsc();
        core::arch::x86_64::_mm_lfence();
        ticks
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn read_tsc_ordered() -> u64 {
    0
}

fn ticks_to_nanos(ticks: u64, ticks_per_second: u64) -> u64 {
    let nanos = u128::from(ticks).saturating_mul(1_000_000_000) / u128::from(ticks_per_second);
    u64::try_from(nanos).unwrap_or(u64::MAX)
}

/// Statistical analysis results for timing measurements.
#[derive(Debug, Clone)]
pub struct TimingStatistics {
    pub mean: f64,
    pub std_dev: f64,
    pub variance: f64,
    pub coefficient_of_variation: f64,
    pub min: u64,
    pub max: u64,
    pub sample_count: usize,
}

impl TimingStatistics {
    /// Calculate statistics from timing samples.
    pub fn from_samples(samples: &[u64]) -> Self {
        if samples.is_empty() {
            return Self {
                mean: 0.0,
                std_dev: 0.0,
                variance: 0.0,
                coefficient_of_variation: 0.0,
                min: 0,
                max: 0,
                sample_count: 0,
            };
        }

        let mean = samples.iter().map(|&x| x as f64).sum::<f64>() / samples.len() as f64;

        let variance = samples
            .iter()
            .map(|&x| {
                let diff = x as f64 - mean;
                diff * diff
            })
            .sum::<f64>()
            / samples.len() as f64;

        let std_dev = variance.sqrt();
        let coefficient_of_variation = if mean > 0.0 { std_dev / mean } else { 0.0 };

        Self {
            mean,
            std_dev,
            variance,
            coefficient_of_variation,
            min: *samples.iter().min().unwrap_or(&0),
            max: *samples.iter().max().unwrap_or(&0),
            sample_count: samples.len(),
        }
    }

    /// Perform Welch's t-test to compare two timing distributions.
    /// Returns p-value for the null hypothesis that the means are equal.
    pub fn welch_t_test(&self, other: &Self) -> f64 {
        if self.sample_count == 0 || other.sample_count == 0 {
            return 1.0; // Cannot reject null hypothesis with no data
        }

        // Welch's t-test for unequal variances
        let mean_diff = (self.mean - other.mean).abs();
        let se_diff = ((self.variance / self.sample_count as f64)
            + (other.variance / other.sample_count as f64))
            .sqrt();

        if se_diff == 0.0 {
            return 1.0; // No variance means no detectable difference
        }

        let t_stat = mean_diff / se_diff;

        // Simplified p-value approximation for demonstration
        // Real implementation would use proper statistical tables
        let df = ((self.variance / self.sample_count as f64)
            + (other.variance / other.sample_count as f64))
            .powi(2)
            / ((self.variance / self.sample_count as f64).powi(2) / (self.sample_count - 1) as f64
                + (other.variance / other.sample_count as f64).powi(2)
                    / (other.sample_count - 1) as f64);

        // Very rough approximation: convert t-statistic to p-value
        // For df > 30, t-distribution approximates normal distribution
        if df > 30.0 {
            // Normal approximation: p ≈ 2 * (1 - Φ(|t|))
            2.0 * (1.0 - self.normal_cdf(t_stat))
        } else {
            // Conservative estimate for small df
            if t_stat > 2.0 { 0.05 } else { 0.5 }
        }
    }

    /// Simplified normal CDF approximation for p-value calculation.
    fn normal_cdf(&self, x: f64) -> f64 {
        // Abramowitz and Stegun approximation
        let a1 = 0.254829592;
        let a2 = -0.284496736;
        let a3 = 1.421413741;
        let a4 = -1.453152027;
        let a5 = 1.061405429;
        let p = 0.3275911;

        let sign = if x < 0.0 { -1.0 } else { 1.0 };
        let x = x.abs();

        let t = 1.0 / (1.0 + p * x);
        let y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * (-x * x / 2.0).exp();

        f64::midpoint(1.0, sign * y)
    }
}

/// Timing side-channel detection result.
#[derive(Debug, Clone)]
pub struct SideChannelDetectionResult {
    /// Whether a potential side-channel was detected.
    pub detected: bool,
    /// Statistical significance of the timing difference.
    pub p_value: f64,
    /// Baseline timing statistics.
    pub baseline_stats: TimingStatistics,
    /// Test case timing statistics.
    pub test_stats: TimingStatistics,
    /// Human-readable description of the finding.
    pub description: String,
}

/// High-precision timing side-channel detector for ATP security conformance.
pub struct TimingSideChannelDetector {
    config: TimingDetectorConfig,
    timer: PrecisionTimer,
    baseline_samples: VecDeque<u64>,
}

impl TimingSideChannelDetector {
    /// Create a new timing side-channel detector.
    pub fn new(config: TimingDetectorConfig) -> Self {
        Self {
            config,
            timer: PrecisionTimer::new(),
            baseline_samples: VecDeque::new(),
        }
    }

    /// Perform baseline calibration by measuring timing of a reference operation.
    pub fn calibrate_baseline<F>(&mut self, mut reference_operation: F) -> Result<(), String>
    where
        F: FnMut(),
    {
        self.baseline_samples.clear();

        // Warmup iterations to stabilize JIT compilation and caches
        for _ in 0..self.config.warmup_iterations {
            reference_operation();
        }

        // Collect baseline timing samples
        for _ in 0..self.config.baseline_samples {
            let start = self.timer.now_ns();
            reference_operation();
            let elapsed = self.timer.now_ns().saturating_sub(start);
            self.baseline_samples.push_back(elapsed);
        }

        // Validate baseline stability
        let baseline_stats = TimingStatistics::from_samples(
            &self.baseline_samples.iter().copied().collect::<Vec<_>>(),
        );

        if baseline_stats.coefficient_of_variation > self.config.max_baseline_cv {
            return Err(format!(
                "Baseline timing too unstable: CV={:.3} > {:.3}",
                baseline_stats.coefficient_of_variation, self.config.max_baseline_cv
            ));
        }

        Ok(())
    }

    /// Test an operation for timing side-channels compared to baseline.
    pub fn test_operation<F>(
        &self,
        mut test_operation: F,
        iterations: usize,
    ) -> SideChannelDetectionResult
    where
        F: FnMut(),
    {
        if self.baseline_samples.is_empty() {
            return SideChannelDetectionResult {
                detected: false,
                p_value: 1.0,
                baseline_stats: TimingStatistics::from_samples(&[]),
                test_stats: TimingStatistics::from_samples(&[]),
                description: "No baseline calibration performed".to_string(),
            };
        }

        let mut test_samples = Vec::with_capacity(iterations);

        // Warmup iterations
        for _ in 0..self.config.warmup_iterations {
            test_operation();
        }

        // Collect test timing samples
        for _ in 0..iterations {
            let start = self.timer.now_ns();
            test_operation();
            let elapsed = self.timer.now_ns().saturating_sub(start);
            test_samples.push(elapsed);
        }

        let baseline_stats = TimingStatistics::from_samples(
            &self.baseline_samples.iter().copied().collect::<Vec<_>>(),
        );
        let test_stats = TimingStatistics::from_samples(&test_samples);

        // Perform statistical significance test
        let p_value = baseline_stats.welch_t_test(&test_stats);
        let mean_diff = (baseline_stats.mean - test_stats.mean).abs();

        // Check for detection criteria
        let statistically_significant = p_value < self.config.significance_threshold;
        let practically_significant = mean_diff >= self.config.min_suspicious_delta_ns as f64;
        let detected = statistically_significant && practically_significant;

        let description = if detected {
            format!(
                "Potential timing side-channel detected: {:.1}ns mean difference, p={:.6}",
                mean_diff, p_value
            )
        } else if statistically_significant {
            format!(
                "Statistically significant but small timing difference: {:.1}ns, p={:.6}",
                mean_diff, p_value
            )
        } else {
            format!(
                "No significant timing difference detected: {:.1}ns, p={:.6}",
                mean_diff, p_value
            )
        };

        SideChannelDetectionResult {
            detected,
            p_value,
            baseline_stats,
            test_stats,
            description,
        }
    }

    /// Convenience method to test constant-time implementation.
    /// Compares timing between different inputs that should take equal time.
    pub fn test_constant_time<F>(
        &self,
        mut operation: F,
        input_a: &[u8],
        input_b: &[u8],
        iterations: usize,
    ) -> SideChannelDetectionResult
    where
        F: FnMut(&[u8]),
    {
        let mut samples_a = Vec::with_capacity(iterations);
        let mut samples_b = Vec::with_capacity(iterations);

        // Warmup with both inputs
        for _ in 0..self.config.warmup_iterations / 2 {
            operation(input_a);
            operation(input_b);
        }

        // Interleaved timing measurements to reduce systematic bias
        for _ in 0..iterations {
            // Measure input A
            let start = self.timer.now_ns();
            operation(input_a);
            let elapsed_a = self.timer.now_ns().saturating_sub(start);
            samples_a.push(elapsed_a);

            // Measure input B
            let start = self.timer.now_ns();
            operation(input_b);
            let elapsed_b = self.timer.now_ns().saturating_sub(start);
            samples_b.push(elapsed_b);
        }

        let stats_a = TimingStatistics::from_samples(&samples_a);
        let stats_b = TimingStatistics::from_samples(&samples_b);

        let p_value = stats_a.welch_t_test(&stats_b);
        let mean_diff = (stats_a.mean - stats_b.mean).abs();

        let statistically_significant = p_value < self.config.significance_threshold;
        let practically_significant = mean_diff >= self.config.min_suspicious_delta_ns as f64;
        let detected = statistically_significant && practically_significant;

        let description = if detected {
            format!(
                "Timing side-channel in constant-time operation: {:.1}ns difference, p={:.6}",
                mean_diff, p_value
            )
        } else {
            format!(
                "Constant-time operation verified: {:.1}ns difference, p={:.6}",
                mean_diff, p_value
            )
        };

        SideChannelDetectionResult {
            detected,
            p_value,
            baseline_stats: stats_a,
            test_stats: stats_b,
            description,
        }
    }
}

impl Default for TimingSideChannelDetector {
    fn default() -> Self {
        Self::new(TimingDetectorConfig::default())
    }
}

#[cfg(all(test, feature = "legacy-internal-test-harnesses"))]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_precision_timer() {
        let timer = PrecisionTimer::new();
        let start = timer.now_ns();
        thread::sleep(Duration::from_millis(1));
        let elapsed = timer.now_ns().saturating_sub(start);

        // Should have elapsed at least 1ms (1_000_000 ns)
        assert!(
            elapsed >= 1_000_000,
            "Timer precision insufficient: {}ns",
            elapsed
        );
    }

    #[test]
    fn test_timing_statistics() {
        let samples = vec![100, 110, 105, 95, 120, 90, 115, 100, 105, 110];
        let stats = TimingStatistics::from_samples(&samples);

        assert_eq!(stats.sample_count, 10);
        assert_eq!(stats.min, 90);
        assert_eq!(stats.max, 120);
        assert!((stats.mean - 105.0).abs() < 0.1);
    }

    #[test]
    fn test_side_channel_detector_calibration() {
        let mut detector = TimingSideChannelDetector::default();

        // Calibrate with a simple operation
        let result = detector.calibrate_baseline(|| {
            // Simple operation that should have consistent timing
            let _sum: u64 = (0..100).sum();
        });

        assert!(result.is_ok(), "Baseline calibration failed: {:?}", result);
    }

    #[test]
    fn test_constant_time_detection() {
        let detector = TimingSideChannelDetector::default();

        // Test with inputs that should have similar timing
        let input_a = vec![0u8; 32];
        let input_b = vec![1u8; 32];

        let result = detector.test_constant_time(
            |data| {
                // Simple constant-time operation (XOR)
                let mut result = 0u8;
                for &byte in data {
                    result ^= byte;
                }
            },
            &input_a,
            &input_b,
            1000,
        );

        // Should not detect timing differences for simple XOR
        assert!(
            !result.detected,
            "False positive timing detection: {}",
            result.description
        );
    }

    #[test]
    fn test_intentional_timing_difference() {
        let detector = TimingSideChannelDetector::default();

        // Test with operations that have intentional timing differences
        let fast_input = vec![0u8; 10];
        let slow_input = vec![1u8; 100];

        let result = detector.test_constant_time(
            |data| {
                // Operation with data-dependent timing
                for &byte in data {
                    if byte != 0 {
                        // Extra work for non-zero bytes
                        let _: u64 = (0..10).map(|x| x * byte as u64).sum();
                    }
                }
            },
            &fast_input,
            &slow_input,
            1000,
        );

        // Should detect timing differences
        assert!(
            result.detected,
            "Failed to detect intentional timing difference: {}",
            result.description
        );
    }
}
