//! Deterministic online change-point detectors for runtime metric series.
//!
//! This module is the pure detector substrate for the adaptive control plane.
//! It intentionally has no scheduler hooks, background sampling, locks, or
//! ambient state: callers feed fixed-point samples and receive optional
//! detection receipts. Runtime integration can then decide whether a detection
//! should emit trace evidence, reset a controller, or remain observe-only.
//!
//! # Why change-point detection
//!
//! The EXP3 cancel-preemption controller and the Lyapunov governor adapt
//! *within* a regime. Neither notices that the regime itself shifted (a
//! workload phase change, a deploy, a traffic-pattern flip) — the classic
//! failure mode of adaptive control is confidently optimizing for yesterday.
//! CUSUM and Page-Hinkley are the buried-standard online detectors: `O(1)`
//! per-sample updates with provable average-run-length (ARL) trade-offs. They
//! are the missing complement, not a competitor: on detection the bounded,
//! conservative response is to *forget* stale learning (reset a controller to
//! its priors), never to take aggressive scheduling action directly.
//!
//! # Configuration profile
//!
//! [`ChangePointMonitorConfig`] is intentionally a pure profile object: it
//! describes which detectors would be installed, whether the monitor is enabled,
//! and how to build a [`ChangePointMonitor`]. The conservative scheduler profile
//! registers the expected runtime series but still starts disabled. That keeps
//! "off by default" verifiable at construction time, not just as an operator
//! convention.
//!
//! # Determinism
//!
//! Every accumulator is an `i64` in micro-units ([`MetricSample::SCALE`]).
//! Running means use an `i128` intermediate and clamp back to `i64`; no step
//! touches floating point. Two detectors fed the same sample sequence from a
//! fresh state therefore produce byte-identical receipts and snapshots, so
//! replay and lab runs reproduce exactly.
//!
//! # Galaxy-brain card — Page-Hinkley ([`PageHinkleyDetector`])
//!
//! Tracks cumulative deviation of each sample from the running mean, minus a
//! tolerated drift `δ`, and alarms when the run-up above the running minimum of
//! that cumulative sum exceeds a threshold `λ`:
//!
//! ```text
//! x̄_T  = running mean of x_1..x_T
//! m_T  = Σ_{t≤T} (x_t − x̄_t − δ)          (cumulative above-tolerance evidence)
//! M_T  = min_{t≤T} m_t                      (running floor)
//! PH_T = m_T − M_T                          (run-up since the floor)
//! alarm ⇔ PH_T ≥ λ
//! ```
//!
//! When reset-on-detection is enabled, the alarm sample seeds a fresh mean
//! epoch while the public receipt index remains lifetime-wide.
//!
//! Substituted defaults ([`PageHinkleyConfig::conservative`]): `δ = 0.05` units
//! (`50_000` micro-units), `λ = 3.0` units. ARL intuition: the false-alarm ARL
//! grows roughly exponentially in `λ` relative to the noise scale, so a larger
//! `λ` buys a longer quiet run at the cost of slower detection; `δ` is the
//! magnitude of drift deemed acceptable and trades detection delay against
//! sensitivity. With unit-scale scheduler noise, `λ = 3` means ~3 units of
//! accumulated above-tolerance evidence must pile up before an alarm fires.
//!
//! # Galaxy-brain card — CUSUM ([`CusumDetector`])
//!
//! One-sided cumulative sum of residuals against a fixed baseline `μ₀`, with a
//! slack `k` (half the shift magnitude you want to catch) and threshold `h`:
//!
//! ```text
//! upward:   S_0 = 0,  S_t = max(0, S_{t−1} + (x_t − μ₀ − k)),   alarm ⇔ S_t ≥ h
//! downward: S_0 = 0,  S_t = max(0, S_{t−1} + (μ₀ − x_t − k)),   alarm ⇔ S_t ≥ h
//! ```
//!
//! Substituted defaults ([`CusumConfig::upward`]/[`CusumConfig::downward`]):
//! `k = 0.05` units (`50_000` micro-units), `h` caller-supplied. ARL intuition:
//! picking `k = (μ₁ − μ₀) / 2` is SPRT-optimal for detecting a shift to `μ₁`;
//! the false-alarm ARL increases with `h`, while the detection delay is roughly
//! `h / (shift − k)` once the true mean exceeds the baseline by more than `k`.

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
    /// Lifetime count used for public sample indexes and snapshots.
    sample_count: u64,
    /// Samples incorporated into the running mean since the latest reset.
    mean_sample_count: u64,
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
            mean_sample_count: 0,
            mean_micro_units: 0,
            cumulative: 0,
            min_cumulative: 0,
        }
    }

    /// Runtime series this detector monitors.
    #[must_use]
    pub const fn series(&self) -> RuntimeMetricSeries {
        self.series
    }

    /// Consume one sample and return a detection receipt if the threshold crosses.
    pub fn update(&mut self, sample: MetricSample) -> Option<ChangePointDetection> {
        self.sample_count = self.sample_count.saturating_add(1);
        self.mean_sample_count = self.mean_sample_count.saturating_add(1);
        let sample_micro_units = sample.as_micro_units();
        self.mean_micro_units = update_running_mean(
            self.mean_micro_units,
            sample_micro_units,
            self.mean_sample_count,
        );
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
        self.mean_sample_count = 1;
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

    /// Runtime series this detector monitors.
    #[must_use]
    pub const fn series(&self) -> RuntimeMetricSeries {
        self.series
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

/// Pluggable detector backing one monitored series inside a [`ChangePointMonitor`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeriesDetector {
    /// Page-Hinkley cumulative mean-shift detector.
    PageHinkley(PageHinkleyDetector),
    /// One-sided cumulative-sum detector.
    Cusum(CusumDetector),
}

impl SeriesDetector {
    /// Runtime series this detector monitors.
    #[must_use]
    pub const fn series(&self) -> RuntimeMetricSeries {
        match self {
            Self::PageHinkley(detector) => detector.series(),
            Self::Cusum(detector) => detector.series(),
        }
    }

    /// Detector algorithm represented by this slot.
    #[must_use]
    pub const fn kind(&self) -> ChangePointDetectorKind {
        match self {
            Self::PageHinkley(_) => ChangePointDetectorKind::PageHinkley,
            Self::Cusum(_) => ChangePointDetectorKind::Cusum,
        }
    }

    /// Consume one sample and return a detection receipt if the threshold crosses.
    pub fn update(&mut self, sample: MetricSample) -> Option<ChangePointDetection> {
        match self {
            Self::PageHinkley(detector) => detector.update(sample),
            Self::Cusum(detector) => detector.update(sample),
        }
    }

    /// Deterministic state snapshot for this detector.
    #[must_use]
    pub const fn snapshot(&self) -> ChangePointSnapshot {
        match self {
            Self::PageHinkley(detector) => detector.snapshot(),
            Self::Cusum(detector) => detector.snapshot(),
        }
    }
}

impl From<PageHinkleyDetector> for SeriesDetector {
    fn from(detector: PageHinkleyDetector) -> Self {
        Self::PageHinkley(detector)
    }
}

impl From<CusumDetector> for SeriesDetector {
    fn from(detector: CusumDetector) -> Self {
        Self::Cusum(detector)
    }
}

/// Declarative detector entry for a [`ChangePointMonitorConfig`].
///
/// This is a copyable profile row, not live detector state. Calling
/// [`Self::build_detector`] creates a fresh detector with zero samples.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangePointSeriesConfig {
    /// Page-Hinkley detector for one runtime series.
    PageHinkley {
        /// Series sampled by the detector.
        series: RuntimeMetricSeries,
        /// Detector parameters.
        config: PageHinkleyConfig,
    },
    /// One-sided CUSUM detector for one runtime series.
    Cusum {
        /// Series sampled by the detector.
        series: RuntimeMetricSeries,
        /// Detector parameters.
        config: CusumConfig,
    },
}

impl ChangePointSeriesConfig {
    /// Build a Page-Hinkley profile row.
    #[must_use]
    pub const fn page_hinkley(series: RuntimeMetricSeries, config: PageHinkleyConfig) -> Self {
        Self::PageHinkley { series, config }
    }

    /// Build a CUSUM profile row.
    #[must_use]
    pub const fn cusum(series: RuntimeMetricSeries, config: CusumConfig) -> Self {
        Self::Cusum { series, config }
    }

    /// Runtime series this profile row monitors.
    #[must_use]
    pub const fn series(self) -> RuntimeMetricSeries {
        match self {
            Self::PageHinkley { series, .. } | Self::Cusum { series, .. } => series,
        }
    }

    /// Detector kind represented by this profile row.
    #[must_use]
    pub const fn kind(self) -> ChangePointDetectorKind {
        match self {
            Self::PageHinkley { .. } => ChangePointDetectorKind::PageHinkley,
            Self::Cusum { .. } => ChangePointDetectorKind::Cusum,
        }
    }

    /// Build a fresh live detector from this profile row.
    #[must_use]
    pub const fn build_detector(self) -> SeriesDetector {
        match self {
            Self::PageHinkley { series, config } => {
                SeriesDetector::PageHinkley(PageHinkleyDetector::new(series, config))
            }
            Self::Cusum { series, config } => {
                SeriesDetector::Cusum(CusumDetector::new(series, config))
            }
        }
    }
}

impl From<ChangePointSeriesConfig> for SeriesDetector {
    fn from(config: ChangePointSeriesConfig) -> Self {
        config.build_detector()
    }
}

/// Pure, off-by-default configuration for a [`ChangePointMonitor`].
///
/// The profile is detached from runtime sampling. Building it never starts a
/// background task or mutates scheduler state; callers must explicitly feed
/// samples to the returned monitor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangePointMonitorConfig {
    /// Whether the built monitor should emit detections.
    pub enabled: bool,
    /// Detector profile rows installed in deterministic registration order.
    pub series: Vec<ChangePointSeriesConfig>,
}

impl ChangePointMonitorConfig {
    /// Empty disabled profile.
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            enabled: false,
            series: Vec::new(),
        }
    }

    /// Conservative scheduler-facing detector profile.
    ///
    /// The profile includes the runtime series named in the adaptive-control
    /// design notes, but remains disabled. Operators or future runtime-builder
    /// wiring must opt in by calling [`Self::enable`].
    #[must_use]
    pub fn conservative_scheduler_defaults() -> Self {
        Self {
            enabled: false,
            series: vec![
                ChangePointSeriesConfig::page_hinkley(
                    RuntimeMetricSeries::ReadyQueueDepth,
                    PageHinkleyConfig::conservative(),
                ),
                ChangePointSeriesConfig::page_hinkley(
                    RuntimeMetricSeries::WakeToRunLatencyMicros,
                    PageHinkleyConfig::conservative(),
                ),
                ChangePointSeriesConfig::page_hinkley(
                    RuntimeMetricSeries::CancelStreakReward,
                    PageHinkleyConfig::conservative(),
                ),
                ChangePointSeriesConfig::page_hinkley(
                    RuntimeMetricSeries::DrainRate,
                    PageHinkleyConfig::conservative(),
                ),
            ],
        }
    }

    /// Append one detector profile row.
    #[must_use]
    pub fn with_series(mut self, series: ChangePointSeriesConfig) -> Self {
        self.series.push(series);
        self
    }

    /// Enable the built monitor.
    #[must_use]
    pub fn enable(mut self) -> Self {
        self.enabled = true;
        self
    }

    /// Disable the built monitor.
    #[must_use]
    pub fn disable(mut self) -> Self {
        self.enabled = false;
        self
    }

    /// Number of configured detector rows.
    #[must_use]
    pub fn len(&self) -> usize {
        self.series.len()
    }

    /// Whether no detector rows are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.series.is_empty()
    }

    /// Build a fresh monitor from this profile.
    #[must_use]
    pub fn build_monitor(&self) -> ChangePointMonitor {
        let mut monitor = ChangePointMonitor::new();
        for series in &self.series {
            monitor.register(series.build_detector());
        }
        monitor.set_enabled(self.enabled);
        monitor
    }
}

impl Default for ChangePointMonitorConfig {
    fn default() -> Self {
        Self::disabled()
    }
}

/// Deterministic, off-by-default monitor over a fixed set of runtime series.
///
/// The monitor owns one or more [`SeriesDetector`]s and routes each observed
/// sample to every detector registered for that series, in registration order.
/// It performs no sampling, locking, or background work of its own — the
/// scheduler snapshot path feeds it and decides what to do with a receipt.
///
/// Detection is gated on [`Self::is_enabled`]: a freshly built monitor is
/// **disabled**, so [`Self::observe`] returns `None` until a caller opts in.
/// This makes "off by default" a structural property rather than a convention.
///
/// # Examples
///
/// ```
/// use asupersync::runtime::changepoint::{
///     ChangePointMonitor, MetricSample, PageHinkleyConfig, PageHinkleyDetector,
///     RuntimeMetricSeries,
/// };
///
/// let detector = PageHinkleyDetector::new(
///     RuntimeMetricSeries::ReadyQueueDepth,
///     PageHinkleyConfig {
///         tolerance: MetricSample::from_micro_units(0),
///         threshold: 10 * MetricSample::SCALE,
///         reset_after_detection: false,
///     },
/// );
/// let mut monitor = ChangePointMonitor::new().with_detector(detector).enable();
///
/// let mut fired = None;
/// for value in [10, 10, 10, 10, 10, 18, 18, 18, 18, 18] {
///     if let Some(detection) =
///         monitor.observe(RuntimeMetricSeries::ReadyQueueDepth, MetricSample::from_units(value))
///     {
///         fired = Some(detection);
///         break;
///     }
/// }
/// assert!(fired.is_some());
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangePointMonitor {
    enabled: bool,
    detectors: Vec<SeriesDetector>,
}

impl ChangePointMonitor {
    /// Build an empty, disabled monitor.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            enabled: false,
            detectors: Vec::new(),
        }
    }

    /// Register a detector, returning the monitor for chaining.
    #[must_use]
    pub fn with_detector(mut self, detector: impl Into<SeriesDetector>) -> Self {
        self.detectors.push(detector.into());
        self
    }

    /// Mark the monitor enabled, returning it for chaining.
    #[must_use]
    pub fn enable(mut self) -> Self {
        self.enabled = true;
        self
    }

    /// Register an additional detector in place.
    pub fn register(&mut self, detector: impl Into<SeriesDetector>) {
        self.detectors.push(detector.into());
    }

    /// Enable or disable detection.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Whether detection is currently enabled.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Number of registered detectors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.detectors.len()
    }

    /// Whether no detectors are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.detectors.is_empty()
    }

    /// Feed `sample` to every detector registered for `series`.
    ///
    /// Returns the first detection in registration order, or `None` when the
    /// monitor is disabled, no detector is registered for `series`, or no
    /// threshold crossed. All matching detectors advance their state regardless
    /// of which one produced the returned receipt, so later observations
    /// reflect every sample seen.
    pub fn observe(
        &mut self,
        series: RuntimeMetricSeries,
        sample: MetricSample,
    ) -> Option<ChangePointDetection> {
        if !self.enabled {
            return None;
        }
        let mut first: Option<ChangePointDetection> = None;
        for detector in &mut self.detectors {
            if detector.series() != series {
                continue;
            }
            // Advance every matching detector; keep the earliest receipt.
            first = first.or(detector.update(sample));
        }
        first
    }

    /// Deterministic snapshots of every registered detector, in registration order.
    #[must_use]
    pub fn snapshots(&self) -> Vec<ChangePointSnapshot> {
        self.detectors
            .iter()
            .map(SeriesDetector::snapshot)
            .collect()
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
#[path = "changepoint_inline_tests.rs"]
mod tests;
