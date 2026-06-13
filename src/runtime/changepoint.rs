//! Deterministic online change-point detectors for runtime metric series.
//!
//! This module is the pure detector substrate for the adaptive control plane.
//! It intentionally has no scheduler hooks, background sampling, locks, or
//! ambient state: callers feed fixed-point samples and receive optional
//! detection receipts. Runtime integration can then decide whether a detection
//! should emit trace evidence, reset a controller, or remain observe-only.

/// Fixed-point runtime metric sample.
///
/// Values are stored in integer micro-units so replay and lab runs do not depend
/// on platform floating-point behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MetricSample(i64);

impl MetricSample {
    /// Scale factor used by [`Self::from_units`] and [`Self::as_units`].
    pub const SCALE: i64 = 1_000_000;

    /// Build a sample from raw fixed-point micro-units.
    #[must_use]
    pub const fn from_micro_units(value: i64) -> Self {
        Self(value)
    }

    /// Build a sample from whole runtime metric units.
    #[must_use]
    pub const fn from_units(value: i64) -> Self {
        Self(value.saturating_mul(Self::SCALE))
    }

    /// Return the raw fixed-point micro-units.
    #[must_use]
    pub const fn as_micro_units(self) -> i64 {
        self.0
    }

    /// Return the whole-unit component rounded toward zero.
    #[must_use]
    pub const fn as_units(self) -> i64 {
        self.0 / Self::SCALE
    }
}

impl From<i64> for MetricSample {
    fn from(value: i64) -> Self {
        Self::from_units(value)
    }
}

/// Runtime metric series monitored for regime shifts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RuntimeMetricSeries {
    /// Ready-queue depth sampled at the scheduler epoch boundary.
    ReadyQueueDepth,
    /// Wake-to-run latency in microseconds.
    WakeToRunLatencyMicros,
    /// Cancel-streak reward or loss signal.
    CancelStreakReward,
    /// Region drain-rate signal.
    DrainRate,
    /// Caller-defined series with a deterministic local identifier.
    Custom(u16),
}

impl RuntimeMetricSeries {
    /// Stable label for trace evidence and operator diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadyQueueDepth => "ready_queue_depth",
            Self::WakeToRunLatencyMicros => "wake_to_run_latency_micros",
            Self::CancelStreakReward => "cancel_streak_reward",
            Self::DrainRate => "drain_rate",
            Self::Custom(_) => "custom",
        }
    }
}

/// Detector algorithm that produced a change-point receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChangePointDetectorKind {
    /// Page-Hinkley cumulative mean-shift detector.
    PageHinkley,
    /// One-sided cumulative-sum detector.
    Cusum,
}

/// Direction of the detected shift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChangeDirection {
    /// Samples rose above the prior regime.
    Increase,
    /// Samples fell below the prior regime.
    Decrease,
}

/// Deterministic receipt emitted when a detector crosses its threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChangePointDetection {
    /// Runtime series that was sampled.
    pub series: RuntimeMetricSeries,
    /// Detector that produced this receipt.
    pub detector: ChangePointDetectorKind,
    /// Direction of the detected shift.
    pub direction: ChangeDirection,
    /// One-based sample index at which the threshold crossed.
    pub sample_index: u64,
    /// Sample that crossed the threshold.
    pub sample: MetricSample,
    /// Detector statistic at the crossing point.
    pub statistic: i64,
    /// Configured threshold for the detector statistic.
    pub threshold: i64,
}

/// Stable snapshot of a detector's internal state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChangePointSnapshot {
    /// Runtime series being monitored.
    pub series: RuntimeMetricSeries,
    /// Detector represented by this snapshot.
    pub detector: ChangePointDetectorKind,
    /// Number of samples consumed.
    pub sample_count: u64,
    /// Current mean estimate in fixed-point micro-units.
    pub mean: MetricSample,
    /// Current detector statistic.
    pub statistic: i64,
    /// Configured threshold for the statistic.
    pub threshold: i64,
}

/// Page-Hinkley detector configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageHinkleyConfig {
    /// Small tolerated drift before cumulative evidence grows.
    pub tolerance: MetricSample,
    /// Detection threshold in fixed-point micro-units.
    pub threshold: i64,
    /// Whether to reset cumulative state after emitting a detection.
    pub reset_after_detection: bool,
}

impl PageHinkleyConfig {
    /// Conservative default for integer scheduler signals.
    #[must_use]
    pub const fn conservative() -> Self {
        Self {
            tolerance: MetricSample::from_micro_units(50_000),
            threshold: 3 * MetricSample::SCALE,
            reset_after_detection: true,
        }
    }
}

/// Page-Hinkley cumulative mean-shift detector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageHinkleyDetector {
    series: RuntimeMetricSeries,
    config: PageHinkleyConfig,
    sample_count: u64,
    mean_micro_units: i64,
    cumulative: i64,
    min_cumulative: i64,
}

impl PageHinkleyDetector {
    /// Build a detector for `series`.
    #[must_use]
    pub const fn new(series: RuntimeMetricSeries, config: PageHinkleyConfig) -> Self {
        Self {
            series,
            config,
            sample_count: 0,
            mean_micro_units: 0,
            cumulative: 0,
            min_cumulative: 0,
        }
    }

    /// Consume one sample and return a detection receipt if the threshold crosses.
    pub fn update(&mut self, sample: MetricSample) -> Option<ChangePointDetection> {
        self.sample_count = self.sample_count.saturating_add(1);
        let sample_micro_units = sample.as_micro_units();
        self.mean_micro_units =
            update_running_mean(self.mean_micro_units, sample_micro_units, self.sample_count);
        let centered = sample_micro_units
            .saturating_sub(self.mean_micro_units)
            .saturating_sub(self.config.tolerance.as_micro_units());
        self.cumulative = self.cumulative.saturating_add(centered);
        self.min_cumulative = self.min_cumulative.min(self.cumulative);
        let statistic = self.cumulative.saturating_sub(self.min_cumulative);

        if statistic >= self.config.threshold {
            let detection = ChangePointDetection {
                series: self.series,
                detector: ChangePointDetectorKind::PageHinkley,
                direction: ChangeDirection::Increase,
                sample_index: self.sample_count,
                sample,
                statistic,
                threshold: self.config.threshold,
            };
            if self.config.reset_after_detection {
                self.reset_at(sample);
            }
            Some(detection)
        } else {
            None
        }
    }

    /// Return a deterministic state snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> ChangePointSnapshot {
        ChangePointSnapshot {
            series: self.series,
            detector: ChangePointDetectorKind::PageHinkley,
            sample_count: self.sample_count,
            mean: MetricSample::from_micro_units(self.mean_micro_units),
            statistic: self.cumulative.saturating_sub(self.min_cumulative),
            threshold: self.config.threshold,
        }
    }

    fn reset_at(&mut self, sample: MetricSample) {
        self.mean_micro_units = sample.as_micro_units();
        self.cumulative = 0;
        self.min_cumulative = 0;
    }
}

/// One-sided CUSUM detector configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CusumConfig {
    /// Baseline mean to compare samples against.
    pub baseline: MetricSample,
    /// Slack value subtracted from each residual.
    pub drift: MetricSample,
    /// Detection threshold in fixed-point micro-units.
    pub threshold: i64,
    /// Direction monitored by this CUSUM instance.
    pub direction: ChangeDirection,
    /// Whether to reset cumulative state after emitting a detection.
    pub reset_after_detection: bool,
}

impl CusumConfig {
    /// Build a conservative upward-shift detector around `baseline`.
    #[must_use]
    pub const fn upward(baseline: MetricSample, threshold: i64) -> Self {
        Self {
            baseline,
            drift: MetricSample::from_micro_units(50_000),
            threshold,
            direction: ChangeDirection::Increase,
            reset_after_detection: true,
        }
    }

    /// Build a conservative downward-shift detector around `baseline`.
    #[must_use]
    pub const fn downward(baseline: MetricSample, threshold: i64) -> Self {
        Self {
            baseline,
            drift: MetricSample::from_micro_units(50_000),
            threshold,
            direction: ChangeDirection::Decrease,
            reset_after_detection: true,
        }
    }
}

/// One-sided deterministic cumulative-sum detector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CusumDetector {
    series: RuntimeMetricSeries,
    config: CusumConfig,
    sample_count: u64,
    statistic: i64,
}

impl CusumDetector {
    /// Build a detector for `series`.
    #[must_use]
    pub const fn new(series: RuntimeMetricSeries, config: CusumConfig) -> Self {
        Self {
            series,
            config,
            sample_count: 0,
            statistic: 0,
        }
    }

    /// Consume one sample and return a detection receipt if the threshold crosses.
    pub fn update(&mut self, sample: MetricSample) -> Option<ChangePointDetection> {
        self.sample_count = self.sample_count.saturating_add(1);
        let residual = match self.config.direction {
            ChangeDirection::Increase => sample
                .as_micro_units()
                .saturating_sub(self.config.baseline.as_micro_units())
                .saturating_sub(self.config.drift.as_micro_units()),
            ChangeDirection::Decrease => self
                .config
                .baseline
                .as_micro_units()
                .saturating_sub(sample.as_micro_units())
                .saturating_sub(self.config.drift.as_micro_units()),
        };
        self.statistic = 0.max(self.statistic.saturating_add(residual));

        if self.statistic >= self.config.threshold {
            let detection = ChangePointDetection {
                series: self.series,
                detector: ChangePointDetectorKind::Cusum,
                direction: self.config.direction,
                sample_index: self.sample_count,
                sample,
                statistic: self.statistic,
                threshold: self.config.threshold,
            };
            if self.config.reset_after_detection {
                self.statistic = 0;
            }
            Some(detection)
        } else {
            None
        }
    }

    /// Return a deterministic state snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> ChangePointSnapshot {
        ChangePointSnapshot {
            series: self.series,
            detector: ChangePointDetectorKind::Cusum,
            sample_count: self.sample_count,
            mean: self.config.baseline,
            statistic: self.statistic,
            threshold: self.config.threshold,
        }
    }
}

fn update_running_mean(current: i64, sample: i64, sample_count: u64) -> i64 {
    if sample_count == 1 {
        return sample;
    }
    let delta = i128::from(sample) - i128::from(current);
    let next = i128::from(current) + delta / i128::from(sample_count);
    next.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed_page_hinkley(
        detector: &mut PageHinkleyDetector,
        samples: &[i64],
    ) -> Option<ChangePointDetection> {
        samples
            .iter()
            .copied()
            .find_map(|sample| detector.update(MetricSample::from_units(sample)))
    }

    fn feed_cusum(detector: &mut CusumDetector, samples: &[i64]) -> Option<ChangePointDetection> {
        samples
            .iter()
            .copied()
            .find_map(|sample| detector.update(MetricSample::from_units(sample)))
    }

    #[test]
    fn metric_sample_uses_deterministic_micro_units() {
        let sample = MetricSample::from_units(42);

        assert_eq!(sample.as_micro_units(), 42 * MetricSample::SCALE);
        assert_eq!(sample.as_units(), 42);
        assert_eq!(MetricSample::from_micro_units(1_500_000).as_units(), 1);
    }

    #[test]
    fn page_hinkley_detects_step_increase_after_stable_prefix() {
        let mut detector = PageHinkleyDetector::new(
            RuntimeMetricSeries::ReadyQueueDepth,
            PageHinkleyConfig {
                tolerance: MetricSample::from_micro_units(0),
                threshold: 10 * MetricSample::SCALE,
                reset_after_detection: false,
            },
        );
        let detection = feed_page_hinkley(&mut detector, &[10, 10, 10, 10, 10, 18, 18, 18, 18, 18])
            .expect("step increase should cross threshold");

        assert_eq!(detection.series, RuntimeMetricSeries::ReadyQueueDepth);
        assert_eq!(detection.detector, ChangePointDetectorKind::PageHinkley);
        assert_eq!(detection.direction, ChangeDirection::Increase);
        assert_eq!(detection.sample_index, 7);
        assert!(detection.statistic >= detection.threshold);
    }

    #[test]
    fn page_hinkley_stays_quiet_for_steady_series() {
        let mut detector = PageHinkleyDetector::new(
            RuntimeMetricSeries::WakeToRunLatencyMicros,
            PageHinkleyConfig::conservative(),
        );
        let detection = feed_page_hinkley(&mut detector, &[40, 40, 41, 40, 41, 40, 41, 40]);

        assert!(detection.is_none());
        assert_eq!(detector.snapshot().sample_count, 8);
    }

    #[test]
    fn cusum_detects_known_upward_shift() {
        let mut detector = CusumDetector::new(
            RuntimeMetricSeries::CancelStreakReward,
            CusumConfig::upward(MetricSample::from_units(10), 6 * MetricSample::SCALE),
        );
        let detection = feed_cusum(&mut detector, &[10, 10, 11, 14, 14, 14])
            .expect("upward shift should cross threshold");

        assert_eq!(detection.detector, ChangePointDetectorKind::Cusum);
        assert_eq!(detection.direction, ChangeDirection::Increase);
        assert_eq!(detection.sample_index, 5);
        assert!(detection.statistic >= detection.threshold);
        assert_eq!(detector.snapshot().statistic, 0);
    }

    #[test]
    fn cusum_detects_known_downward_shift() {
        let mut detector = CusumDetector::new(
            RuntimeMetricSeries::DrainRate,
            CusumConfig::downward(MetricSample::from_units(20), 8 * MetricSample::SCALE),
        );
        let detection = feed_cusum(&mut detector, &[20, 19, 18, 15, 15, 15])
            .expect("downward shift should cross threshold");

        assert_eq!(detection.series, RuntimeMetricSeries::DrainRate);
        assert_eq!(detection.direction, ChangeDirection::Decrease);
        assert_eq!(detection.sample_index, 5);
    }

    #[test]
    fn detector_snapshots_are_byte_identical_for_same_series() {
        let samples = [3, 3, 4, 9, 9, 10, 10];
        let mut left = PageHinkleyDetector::new(
            RuntimeMetricSeries::Custom(7),
            PageHinkleyConfig::conservative(),
        );
        let mut right = PageHinkleyDetector::new(
            RuntimeMetricSeries::Custom(7),
            PageHinkleyConfig::conservative(),
        );

        for sample in samples {
            let left_detection = left.update(MetricSample::from_units(sample));
            let right_detection = right.update(MetricSample::from_units(sample));
            assert_eq!(left_detection, right_detection);
            assert_eq!(left.snapshot(), right.snapshot());
        }
    }
}
