//! Live swarm pressure governor for preventing overload in large agent deployments.
//!
//! This module provides deterministic pressure monitoring and admission control
//! based on runtime-local metrics including queue depths, pool saturation,
//! channel backlogs, and memory budget signals.

use crate::cx::Cx;
use crate::error::Error;
use crate::observability::metrics::{Counter, Gauge, Metrics, Summary};
use crate::runtime::Runtime;
use crate::runtime::resource_monitor::ResourceType;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Configuration for the pressure governor.
#[derive(Debug, Clone)]
pub struct PressureGovernorConfig {
    /// Enable pressure monitoring (observe-only mode when admission control disabled).
    pub enabled: bool,
    /// Enable admission control decisions (requires enabled=true).
    pub admission_control: bool,
    /// Sample interval for metrics collection.
    pub sample_interval: Duration,
    /// Thresholds for pressure signals (0.0-1.0, where 1.0 is maximum capacity).
    pub thresholds: PressureThresholds,
}

/// Pressure signal thresholds for admission decisions.
#[derive(Debug, Clone)]
pub struct PressureThresholds {
    /// Runnable queue depth threshold (as fraction of worker count).
    pub runnable_queue: f64,
    /// Blocking pool saturation threshold (active/capacity).
    pub blocking_pool: f64,
    /// Channel backlog threshold (pending/buffer_size across all channels).
    pub channel_backlog: f64,
    /// Cleanup debt threshold (pending cleanup tasks/capacity).
    pub cleanup_debt: f64,
    /// Memory budget threshold (used/allocated).
    pub memory_budget: f64,
}

/// Current pressure readings from the runtime.
#[derive(Debug, Clone)]
pub struct PressureSnapshot {
    /// Timestamp of this snapshot.
    pub timestamp: Instant,
    /// Runnable queue depth pressure (0.0-1.0+).
    pub runnable_queue_pressure: f64,
    /// Blocking pool saturation (0.0-1.0).
    pub blocking_pool_pressure: f64,
    /// Channel backlog pressure (0.0-1.0+).
    pub channel_backlog_pressure: f64,
    /// Cleanup debt pressure (0.0-1.0+).
    pub cleanup_debt_pressure: f64,
    /// Memory budget pressure (0.0-1.0+).
    pub memory_budget_pressure: f64,
    /// Overall pressure level (max of all signals).
    pub overall_pressure: f64,
    /// Which runtime-local pressure signals were live for this sample.
    pub signal_availability: PressureSignalAvailability,
    /// Conservative fallback verdict for unavailable signal surfaces.
    pub fallback_verdict: PressureFallbackVerdict,
}

/// Runtime-local pressure signal availability for a snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PressureSignalAvailability {
    /// Scheduler runnable-queue signal is live.
    pub runnable_queue: bool,
    /// Blocking-pool saturation signal is live.
    pub blocking_pool: bool,
    /// Channel-backlog signal is live.
    pub channel_backlog: bool,
    /// Cleanup-debt signal is live.
    pub cleanup_debt: bool,
    /// Memory-budget signal is live.
    pub memory_budget: bool,
}

impl PressureSignalAvailability {
    const RUNNABLE_QUEUE: u64 = 1 << 0;
    const BLOCKING_POOL: u64 = 1 << 1;
    const CHANNEL_BACKLOG: u64 = 1 << 2;
    const CLEANUP_DEBT: u64 = 1 << 3;
    const MEMORY_BUDGET: u64 = 1 << 4;

    /// No runtime-local signals are live.
    pub const NONE: Self = Self {
        runnable_queue: false,
        blocking_pool: false,
        channel_backlog: false,
        cleanup_debt: false,
        memory_budget: false,
    };

    /// All runtime-local signals are live.
    pub const ALL: Self = Self {
        runnable_queue: true,
        blocking_pool: true,
        channel_backlog: true,
        cleanup_debt: true,
        memory_budget: true,
    };

    #[must_use]
    fn from_mask(mask: u64) -> Self {
        Self {
            runnable_queue: mask & Self::RUNNABLE_QUEUE != 0,
            blocking_pool: mask & Self::BLOCKING_POOL != 0,
            channel_backlog: mask & Self::CHANNEL_BACKLOG != 0,
            cleanup_debt: mask & Self::CLEANUP_DEBT != 0,
            memory_budget: mask & Self::MEMORY_BUDGET != 0,
        }
    }

    #[must_use]
    fn mask(self) -> u64 {
        let mut mask = 0;
        if self.runnable_queue {
            mask |= Self::RUNNABLE_QUEUE;
        }
        if self.blocking_pool {
            mask |= Self::BLOCKING_POOL;
        }
        if self.channel_backlog {
            mask |= Self::CHANNEL_BACKLOG;
        }
        if self.cleanup_debt {
            mask |= Self::CLEANUP_DEBT;
        }
        if self.memory_budget {
            mask |= Self::MEMORY_BUDGET;
        }
        mask
    }

    /// Returns true if at least one runtime-local signal is live.
    #[must_use]
    pub fn any_live(self) -> bool {
        self.mask() != 0
    }

    /// Returns true if all runtime-local signals are live.
    #[must_use]
    pub fn all_live(self) -> bool {
        self == Self::ALL
    }
}

/// Conservative fallback state for missing pressure signals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PressureFallbackVerdict {
    /// Every pressure signal required by the governor was sampled live.
    Complete,
    /// No runtime-local pressure signal is available; admission must be conservative.
    NoWinNoLiveSignals,
    /// At least one signal is available, but the snapshot is still incomplete.
    PartialSignalsUnavailable,
}

impl PressureFallbackVerdict {
    /// Classifies a snapshot from the availability of its runtime-local signals.
    #[must_use]
    pub fn from_availability(availability: PressureSignalAvailability) -> Self {
        if availability.all_live() {
            Self::Complete
        } else if availability.any_live() {
            Self::PartialSignalsUnavailable
        } else {
            Self::NoWinNoLiveSignals
        }
    }

    /// Returns the stable integer encoding used by governor metrics.
    #[must_use]
    pub const fn as_metric_value(self) -> i64 {
        match self {
            Self::Complete => 0,
            Self::PartialSignalsUnavailable => 1,
            Self::NoWinNoLiveSignals => 2,
        }
    }
}

/// Admission decision for new regions or task groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionDecision {
    /// Allow the operation to proceed.
    Admit,
    /// Deny the operation due to high pressure.
    Reject,
    /// Allow but suggest backpressure to caller.
    AdmitWithBackpressure,
}

/// Live swarm pressure governor.
pub struct PressureGovernor {
    config: PressureGovernorConfig,
    #[allow(dead_code)] // TODO: Used for accessing actual runtime metrics in full implementation
    runtime: Arc<Runtime>,
    #[allow(dead_code)] // TODO: Used for additional metrics management in full implementation
    metrics: Arc<Metrics>,

    // Metrics for pressure signals
    runnable_queue_gauge: Arc<Gauge>,
    blocking_pool_gauge: Arc<Gauge>,
    channel_backlog_gauge: Arc<Gauge>,
    cleanup_debt_gauge: Arc<Gauge>,
    memory_budget_gauge: Arc<Gauge>,
    overall_pressure_gauge: Arc<Gauge>,

    // Admission control metrics
    admissions_total: Arc<Counter>,
    rejections_total: Arc<Counter>,
    backpressure_total: Arc<Counter>,
    partial_fallback_total: Arc<Counter>,
    no_win_fallback_total: Arc<Counter>,

    // Internal state
    started_at: Instant,
    last_sample: AtomicU64, // Nanoseconds elapsed since started_at
    last_signal_availability_mask: AtomicU64,
    sample_count: AtomicU64,
    decision_latency_summary: Arc<Summary>,
    decision_latency_p95_gauge: Arc<Gauge>,
    decision_latency_p999_gauge: Arc<Gauge>,
    fallback_verdict_gauge: Arc<Gauge>,
}

impl PressureGovernor {
    /// Create a new pressure governor with the given configuration.
    pub fn new(
        config: PressureGovernorConfig,
        runtime: Arc<Runtime>,
        mut metrics: Metrics,
    ) -> Result<Self, Error> {
        // Register pressure signal gauges
        // Note: Gauges store i64 values, so we'll scale f64 pressure values by 10000 for storage
        let runnable_queue_gauge = metrics.gauge("pressure_runnable_queue_scaled");

        let blocking_pool_gauge = metrics.gauge("pressure_blocking_pool_scaled");

        let channel_backlog_gauge = metrics.gauge("pressure_channel_backlog_scaled");

        let cleanup_debt_gauge = metrics.gauge("pressure_cleanup_debt_scaled");

        let memory_budget_gauge = metrics.gauge("pressure_memory_budget_scaled");

        let overall_pressure_gauge = metrics.gauge("pressure_overall_scaled");

        // Register admission control counters
        let admissions_total = metrics.counter("pressure_governor_admissions_total");

        let rejections_total = metrics.counter("pressure_governor_rejections_total");

        let backpressure_total = metrics.counter("pressure_governor_backpressure_total");
        let partial_fallback_total =
            metrics.counter("pressure_governor_partial_signal_fallback_total");
        let no_win_fallback_total = metrics.counter("pressure_governor_no_win_fallback_total");
        let decision_latency_summary = metrics.summary("pressure_governor_decision_latency_ns");
        let decision_latency_p95_gauge = metrics.gauge("pressure_governor_decision_latency_p95_ns");
        let decision_latency_p999_gauge =
            metrics.gauge("pressure_governor_decision_latency_p999_ns");
        let fallback_verdict_gauge = metrics.gauge("pressure_governor_fallback_verdict");
        let started_at = Instant::now();

        Ok(Self {
            config,
            runtime,
            metrics: Arc::new(metrics),
            runnable_queue_gauge,
            blocking_pool_gauge,
            channel_backlog_gauge,
            cleanup_debt_gauge,
            memory_budget_gauge,
            overall_pressure_gauge,
            admissions_total,
            rejections_total,
            backpressure_total,
            partial_fallback_total,
            no_win_fallback_total,
            started_at,
            last_sample: AtomicU64::new(0),
            last_signal_availability_mask: AtomicU64::new(PressureSignalAvailability::NONE.mask()),
            sample_count: AtomicU64::new(0),
            decision_latency_summary,
            decision_latency_p95_gauge,
            decision_latency_p999_gauge,
            fallback_verdict_gauge,
        })
    }

    /// Sample current pressure signals from the runtime.
    pub fn sample_pressure(&self, cx: &Cx) -> Result<PressureSnapshot, Error> {
        let now = Instant::now();

        // Check if we should sample (respecting sample_interval)
        let now_nanos = nanos_since(self.started_at, now);
        let last_sample_nanos = self.last_sample.load(Ordering::Acquire);
        if last_sample_nanos != 0
            && now_nanos.saturating_sub(last_sample_nanos)
                < duration_nanos_u64(self.config.sample_interval)
        {
            // Too soon, return cached values from gauges
            return Ok(self.snapshot_from_gauges(now));
        }

        // Sample fresh pressure signals
        let snapshot = self.collect_pressure_signals(cx, now)?;

        // Update metrics (scale f64 pressure to i64 by multiplying by 10000)
        const PRESSURE_SCALE: f64 = 10000.0;
        self.runnable_queue_gauge
            .set((snapshot.runnable_queue_pressure * PRESSURE_SCALE) as i64);
        self.blocking_pool_gauge
            .set((snapshot.blocking_pool_pressure * PRESSURE_SCALE) as i64);
        self.channel_backlog_gauge
            .set((snapshot.channel_backlog_pressure * PRESSURE_SCALE) as i64);
        self.cleanup_debt_gauge
            .set((snapshot.cleanup_debt_pressure * PRESSURE_SCALE) as i64);
        self.memory_budget_gauge
            .set((snapshot.memory_budget_pressure * PRESSURE_SCALE) as i64);
        self.overall_pressure_gauge
            .set((snapshot.overall_pressure * PRESSURE_SCALE) as i64);
        self.fallback_verdict_gauge
            .set(snapshot.fallback_verdict.as_metric_value());

        // Update sampling state
        self.last_sample.store(now_nanos, Ordering::Release);
        self.last_signal_availability_mask
            .store(snapshot.signal_availability.mask(), Ordering::Release);
        self.sample_count.fetch_add(1, Ordering::Relaxed);

        Ok(snapshot)
    }

    /// Make an admission decision for a new region or task group.
    pub fn check_admission(&self, cx: &Cx) -> Result<AdmissionDecision, Error> {
        let decision_started_at = Instant::now();
        if !self.config.enabled {
            // Governor disabled, always admit
            self.admissions_total.increment();
            self.record_decision_latency(decision_started_at);
            return Ok(AdmissionDecision::Admit);
        }

        let snapshot = match self.sample_pressure(cx) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                self.record_decision_latency(decision_started_at);
                return Err(error);
            }
        };
        self.record_fallback_verdict(snapshot.fallback_verdict);

        if !self.config.admission_control {
            // Observe-only mode, always admit but record pressure
            self.admissions_total.increment();
            self.record_decision_latency(decision_started_at);
            return Ok(AdmissionDecision::Admit);
        }

        // Check pressure against thresholds
        let decision = self.evaluate_admission(&snapshot);

        match decision {
            AdmissionDecision::Admit => {
                self.admissions_total.increment();
            }
            AdmissionDecision::Reject => {
                self.rejections_total.increment();
            }
            AdmissionDecision::AdmitWithBackpressure => {
                self.admissions_total.increment();
                self.backpressure_total.increment();
            }
        }

        self.record_decision_latency(decision_started_at);
        Ok(decision)
    }

    /// Get the current configuration.
    pub fn config(&self) -> &PressureGovernorConfig {
        &self.config
    }

    /// Get total samples collected.
    pub fn sample_count(&self) -> u64 {
        self.sample_count.load(Ordering::Relaxed)
    }

    /// Returns the latest fallback verdict metric value.
    #[must_use]
    pub fn fallback_verdict_metric(&self) -> i64 {
        self.fallback_verdict_gauge.get()
    }

    /// Returns the current exact p95 decision latency, rounded down to nanoseconds.
    #[must_use]
    pub fn decision_latency_p95_ns(&self) -> Option<u64> {
        self.decision_latency_summary
            .quantile(0.95)
            .map(f64_to_u64_saturating)
    }

    /// Returns the current exact p999 decision latency, rounded down to nanoseconds.
    #[must_use]
    pub fn decision_latency_p999_ns(&self) -> Option<u64> {
        self.decision_latency_summary
            .quantile(0.999)
            .map(f64_to_u64_saturating)
    }

    /// Returns the latest published p95 decision latency gauge value.
    #[must_use]
    pub fn decision_latency_p95_metric_ns(&self) -> i64 {
        self.decision_latency_p95_gauge.get()
    }

    /// Returns the latest published p999 decision latency gauge value.
    #[must_use]
    pub fn decision_latency_p999_metric_ns(&self) -> i64 {
        self.decision_latency_p999_gauge.get()
    }

    // Private helper methods

    fn collect_pressure_signals(
        &self,
        _cx: &Cx,
        timestamp: Instant,
    ) -> Result<PressureSnapshot, Error> {
        // Collect actual metrics from runtime components

        let runnable_queue = self.sample_runnable_queue_pressure();

        let blocking_pool = self.sample_blocking_pool_pressure();

        // Channel backlog pressure: sum of pending items across all channels
        // TODO: Implement channel monitoring when channel registry is available
        let channel_backlog = self.sample_channel_backlog_pressure();

        // Cleanup debt pressure: pending cleanup work / region capacity.
        let cleanup_debt = self.sample_cleanup_debt_pressure();

        // Memory budget pressure: runtime resource-monitor memory usage / max limit.
        let memory_budget = self.sample_memory_budget_pressure();

        let signal_availability = PressureSignalAvailability {
            runnable_queue: runnable_queue.available,
            blocking_pool: blocking_pool.available,
            channel_backlog: channel_backlog.available,
            cleanup_debt: cleanup_debt.available,
            memory_budget: memory_budget.available,
        };
        let fallback_verdict = PressureFallbackVerdict::from_availability(signal_availability);

        // Overall pressure is the maximum of all signals
        let overall_pressure = runnable_queue
            .pressure
            .max(blocking_pool.pressure)
            .max(channel_backlog.pressure)
            .max(cleanup_debt.pressure)
            .max(memory_budget.pressure);

        Ok(PressureSnapshot {
            timestamp,
            runnable_queue_pressure: runnable_queue.pressure,
            blocking_pool_pressure: blocking_pool.pressure,
            channel_backlog_pressure: channel_backlog.pressure,
            cleanup_debt_pressure: cleanup_debt.pressure,
            memory_budget_pressure: memory_budget.pressure,
            overall_pressure,
            signal_availability,
            fallback_verdict,
        })
    }

    fn snapshot_from_gauges(&self, timestamp: Instant) -> PressureSnapshot {
        // Convert scaled i64 values back to f64 pressure values
        const PRESSURE_SCALE: f64 = 10000.0;
        let runnable_queue_pressure = self.runnable_queue_gauge.get() as f64 / PRESSURE_SCALE;
        let blocking_pool_pressure = self.blocking_pool_gauge.get() as f64 / PRESSURE_SCALE;
        let channel_backlog_pressure = self.channel_backlog_gauge.get() as f64 / PRESSURE_SCALE;
        let cleanup_debt_pressure = self.cleanup_debt_gauge.get() as f64 / PRESSURE_SCALE;
        let memory_budget_pressure = self.memory_budget_gauge.get() as f64 / PRESSURE_SCALE;
        let overall_pressure = self.overall_pressure_gauge.get() as f64 / PRESSURE_SCALE;
        let signal_availability = PressureSignalAvailability::from_mask(
            self.last_signal_availability_mask.load(Ordering::Acquire),
        );
        let fallback_verdict = PressureFallbackVerdict::from_availability(signal_availability);

        PressureSnapshot {
            timestamp,
            runnable_queue_pressure,
            blocking_pool_pressure,
            channel_backlog_pressure,
            cleanup_debt_pressure,
            memory_budget_pressure,
            overall_pressure,
            signal_availability,
            fallback_verdict,
        }
    }

    fn evaluate_admission(&self, snapshot: &PressureSnapshot) -> AdmissionDecision {
        let thresholds = &self.config.thresholds;

        // With no live pressure signals, avoid treating an empty sample as proof
        // of low pressure. Backpressure is the least destructive conservative path.
        if snapshot.fallback_verdict == PressureFallbackVerdict::NoWinNoLiveSignals {
            return AdmissionDecision::AdmitWithBackpressure;
        }

        // Check for hard rejection conditions
        if snapshot.runnable_queue_pressure > thresholds.runnable_queue * 1.2
            || snapshot.blocking_pool_pressure > thresholds.blocking_pool * 1.2
            || snapshot.channel_backlog_pressure > thresholds.channel_backlog * 1.2
            || snapshot.cleanup_debt_pressure > thresholds.cleanup_debt * 1.2
            || snapshot.memory_budget_pressure > thresholds.memory_budget * 1.2
        {
            return AdmissionDecision::Reject;
        }

        // Check for backpressure conditions
        if snapshot.runnable_queue_pressure > thresholds.runnable_queue
            || snapshot.blocking_pool_pressure > thresholds.blocking_pool
            || snapshot.channel_backlog_pressure > thresholds.channel_backlog
            || snapshot.cleanup_debt_pressure > thresholds.cleanup_debt
            || snapshot.memory_budget_pressure > thresholds.memory_budget
        {
            return AdmissionDecision::AdmitWithBackpressure;
        }

        AdmissionDecision::Admit
    }

    // Runtime metric collection implementations

    fn sample_runnable_queue_pressure(&self) -> PressureSignalSample {
        let capacity = self.runtime.config().global_queue_limit;
        if capacity == 0 {
            return PressureSignalSample::unavailable();
        }

        let ready_depth = self.runtime.scheduler_global_ready_depth();
        PressureSignalSample::available(ready_depth as f64 / capacity as f64)
    }

    fn sample_blocking_pool_pressure(&self) -> PressureSignalSample {
        let max_threads = self.runtime.config().blocking.max_threads;
        if max_threads == 0 {
            return PressureSignalSample::unavailable();
        }

        let Some(blocking_pool) = self.runtime.blocking_handle() else {
            return PressureSignalSample::unavailable();
        };

        let busy = blocking_pool.busy_threads();
        let pending = blocking_pool.pending_count();
        let load = busy.saturating_add(pending);
        PressureSignalSample::available(load as f64 / max_threads as f64)
    }

    fn sample_channel_backlog_pressure(&self) -> PressureSignalSample {
        // TODO: Access channel registry from runtime for global channel monitoring
        // In a full implementation, we would:
        // 1. Iterate through all active mpsc/broadcast/oneshot channels
        // 2. Sum pending message counts across all channels
        // 3. Calculate pressure relative to total buffer capacity

        // This requires a channel registry that doesn't exist yet
        PressureSignalSample::unavailable()
    }

    fn sample_cleanup_debt_pressure(&self) -> PressureSignalSample {
        let capacity = self
            .runtime
            .config()
            .resolved_capacity_hints()
            .region_capacity;
        if capacity == 0 {
            return PressureSignalSample::unavailable();
        }

        let draining_regions = self.runtime.draining_region_count();
        PressureSignalSample::available(draining_regions as f64 / capacity as f64)
    }

    fn sample_memory_budget_pressure(&self) -> PressureSignalSample {
        let resource_monitor = self.runtime.resource_monitor();
        let resource_pressure = resource_monitor.pressure();
        let Some(measurement) = resource_pressure.get_measurement(&ResourceType::Memory) else {
            return PressureSignalSample::unavailable();
        };
        if measurement.max_limit == 0 {
            return PressureSignalSample::unavailable();
        }

        PressureSignalSample::available(measurement.usage_ratio())
    }

    fn record_fallback_verdict(&self, verdict: PressureFallbackVerdict) {
        self.fallback_verdict_gauge.set(verdict.as_metric_value());
        match verdict {
            PressureFallbackVerdict::Complete => {}
            PressureFallbackVerdict::PartialSignalsUnavailable => {
                self.partial_fallback_total.increment();
            }
            PressureFallbackVerdict::NoWinNoLiveSignals => {
                self.no_win_fallback_total.increment();
            }
        }
    }

    fn record_decision_latency(&self, started_at: Instant) {
        let elapsed_ns = duration_nanos_u64(Instant::now().saturating_duration_since(started_at));
        self.decision_latency_summary.observe(elapsed_ns as f64);
        if let Some(p95) = self.decision_latency_p95_ns() {
            self.decision_latency_p95_gauge
                .set(u64_to_i64_saturating(p95));
        }
        if let Some(p999) = self.decision_latency_p999_ns() {
            self.decision_latency_p999_gauge
                .set(u64_to_i64_saturating(p999));
        }
    }
}

struct PressureSignalSample {
    pressure: f64,
    available: bool,
}

impl PressureSignalSample {
    const fn unavailable() -> Self {
        Self {
            pressure: 0.0,
            available: false,
        }
    }

    const fn available(pressure: f64) -> Self {
        Self {
            pressure,
            available: true,
        }
    }
}

fn nanos_since(started_at: Instant, now: Instant) -> u64 {
    duration_nanos_u64(now.saturating_duration_since(started_at))
}

fn duration_nanos_u64(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

fn f64_to_u64_saturating(value: f64) -> u64 {
    if !value.is_finite() || value <= 0.0 {
        0
    } else if value >= u64::MAX as f64 {
        u64::MAX
    } else {
        value as u64
    }
}

fn u64_to_i64_saturating(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

impl Default for PressureGovernorConfig {
    fn default() -> Self {
        Self {
            enabled: false,           // Conservative default
            admission_control: false, // Start in observe-only mode
            sample_interval: Duration::from_secs(1),
            thresholds: PressureThresholds::default(),
        }
    }
}

impl Default for PressureThresholds {
    fn default() -> Self {
        Self {
            runnable_queue: 0.8,  // 80% of queue capacity
            blocking_pool: 0.9,   // 90% of thread pool
            channel_backlog: 0.7, // 70% of buffer capacity
            cleanup_debt: 0.8,    // 80% of cleanup capacity
            memory_budget: 0.9,   // 90% of memory budget
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observability::metrics::Metrics;
    use crate::runtime::RuntimeBuilder;
    use crate::types::Budget;
    use std::time::Duration;

    #[test]
    fn test_pressure_governor_config_defaults() {
        let config = PressureGovernorConfig::default();
        assert!(!config.enabled);
        assert!(!config.admission_control);
        assert_eq!(config.sample_interval, Duration::from_secs(1));

        let thresholds = config.thresholds;
        assert_eq!(thresholds.runnable_queue, 0.8);
        assert_eq!(thresholds.blocking_pool, 0.9);
        assert_eq!(thresholds.channel_backlog, 0.7);
        assert_eq!(thresholds.cleanup_debt, 0.8);
        assert_eq!(thresholds.memory_budget, 0.9);
    }

    #[test]
    fn test_pressure_thresholds_evaluation() {
        let config = PressureGovernorConfig {
            enabled: true,
            admission_control: true,
            thresholds: PressureThresholds {
                runnable_queue: 0.8,
                blocking_pool: 0.9,
                channel_backlog: 0.7,
                cleanup_debt: 0.8,
                memory_budget: 0.9,
            },
            ..Default::default()
        };

        use std::sync::Arc;

        let runtime = Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let metrics = Metrics::new();
        let governor = PressureGovernor::new(config, runtime, metrics).unwrap();

        // Test low pressure - should admit
        let low_pressure = PressureSnapshot {
            timestamp: Instant::now(),
            runnable_queue_pressure: 0.5,
            blocking_pool_pressure: 0.5,
            channel_backlog_pressure: 0.5,
            cleanup_debt_pressure: 0.5,
            memory_budget_pressure: 0.5,
            overall_pressure: 0.5,
            signal_availability: PressureSignalAvailability::ALL,
            fallback_verdict: PressureFallbackVerdict::Complete,
        };

        let decision = governor.evaluate_admission(&low_pressure);
        assert_eq!(decision, AdmissionDecision::Admit);

        // Test moderate pressure - should admit with backpressure
        let moderate_pressure = PressureSnapshot {
            timestamp: Instant::now(),
            runnable_queue_pressure: 0.85, // Above threshold (0.8)
            blocking_pool_pressure: 0.5,
            channel_backlog_pressure: 0.5,
            cleanup_debt_pressure: 0.5,
            memory_budget_pressure: 0.5,
            overall_pressure: 0.85,
            signal_availability: PressureSignalAvailability::ALL,
            fallback_verdict: PressureFallbackVerdict::Complete,
        };

        let decision = governor.evaluate_admission(&moderate_pressure);
        assert_eq!(decision, AdmissionDecision::AdmitWithBackpressure);

        // Test high pressure - should reject
        let high_pressure = PressureSnapshot {
            timestamp: Instant::now(),
            runnable_queue_pressure: 1.0, // Above rejection threshold (0.8 * 1.2 = 0.96)
            blocking_pool_pressure: 0.5,
            channel_backlog_pressure: 0.5,
            cleanup_debt_pressure: 0.5,
            memory_budget_pressure: 0.5,
            overall_pressure: 1.0,
            signal_availability: PressureSignalAvailability::ALL,
            fallback_verdict: PressureFallbackVerdict::Complete,
        };

        let decision = governor.evaluate_admission(&high_pressure);
        assert_eq!(decision, AdmissionDecision::Reject);
    }

    fn pressure_snapshot_from_values(values: [f64; 5]) -> PressureSnapshot {
        let overall_pressure = values.iter().copied().fold(0.0, f64::max);
        PressureSnapshot {
            timestamp: Instant::now(),
            runnable_queue_pressure: values[0],
            blocking_pool_pressure: values[1],
            channel_backlog_pressure: values[2],
            cleanup_debt_pressure: values[3],
            memory_budget_pressure: values[4],
            overall_pressure,
            signal_availability: PressureSignalAvailability::ALL,
            fallback_verdict: PressureFallbackVerdict::Complete,
        }
    }

    #[test]
    fn pressure_governor_no_win_fallback_uses_backpressure() {
        let config = PressureGovernorConfig {
            enabled: true,
            admission_control: true,
            ..Default::default()
        };
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let metrics = Metrics::new();
        let governor = PressureGovernor::new(config, runtime, metrics)
            .expect("pressure governor should initialize");

        let no_win_pressure = PressureSnapshot {
            timestamp: Instant::now(),
            runnable_queue_pressure: 0.0,
            blocking_pool_pressure: 0.0,
            channel_backlog_pressure: 0.0,
            cleanup_debt_pressure: 0.0,
            memory_budget_pressure: 0.0,
            overall_pressure: 0.0,
            signal_availability: PressureSignalAvailability::NONE,
            fallback_verdict: PressureFallbackVerdict::NoWinNoLiveSignals,
        };
        assert_eq!(
            governor.evaluate_admission(&no_win_pressure),
            AdmissionDecision::AdmitWithBackpressure
        );

        let complete_low_pressure = PressureSnapshot {
            signal_availability: PressureSignalAvailability::ALL,
            fallback_verdict: PressureFallbackVerdict::Complete,
            ..no_win_pressure
        };
        assert_eq!(
            governor.evaluate_admission(&complete_low_pressure),
            AdmissionDecision::Admit
        );
    }

    #[test]
    fn pressure_threshold_boundaries_apply_to_every_signal() {
        let thresholds = PressureThresholds {
            runnable_queue: 0.8,
            blocking_pool: 0.9,
            channel_backlog: 0.7,
            cleanup_debt: 0.8,
            memory_budget: 0.9,
        };
        let config = PressureGovernorConfig {
            enabled: true,
            admission_control: true,
            thresholds: thresholds.clone(),
            ..Default::default()
        };
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let metrics = Metrics::new();
        let governor = PressureGovernor::new(config, runtime, metrics).unwrap();
        let cases = [
            ("runnable_queue", 0, thresholds.runnable_queue),
            ("blocking_pool", 1, thresholds.blocking_pool),
            ("channel_backlog", 2, thresholds.channel_backlog),
            ("cleanup_debt", 3, thresholds.cleanup_debt),
            ("memory_budget", 4, thresholds.memory_budget),
        ];

        for (name, index, threshold) in cases {
            let hard_reject_threshold = threshold * 1.2;

            let mut at_threshold = [0.0; 5];
            at_threshold[index] = threshold;
            assert_eq!(
                governor.evaluate_admission(&pressure_snapshot_from_values(at_threshold)),
                AdmissionDecision::Admit,
                "{name} pressure equal to threshold should still admit"
            );

            let mut above_threshold = [0.0; 5];
            above_threshold[index] = threshold + 0.0001;
            assert_eq!(
                governor.evaluate_admission(&pressure_snapshot_from_values(above_threshold)),
                AdmissionDecision::AdmitWithBackpressure,
                "{name} pressure just above threshold should apply backpressure"
            );

            let mut at_hard_reject_threshold = [0.0; 5];
            at_hard_reject_threshold[index] = hard_reject_threshold;
            assert_eq!(
                governor
                    .evaluate_admission(&pressure_snapshot_from_values(at_hard_reject_threshold,)),
                AdmissionDecision::AdmitWithBackpressure,
                "{name} pressure equal to hard reject threshold should not reject"
            );

            let mut above_hard_reject_threshold = [0.0; 5];
            above_hard_reject_threshold[index] = hard_reject_threshold + 0.0001;
            assert_eq!(
                governor.evaluate_admission(&pressure_snapshot_from_values(
                    above_hard_reject_threshold,
                )),
                AdmissionDecision::Reject,
                "{name} pressure above hard reject threshold should reject"
            );
        }
    }

    #[test]
    fn test_pressure_governor_disabled_always_admits() {
        let config = PressureGovernorConfig {
            enabled: false, // Disabled
            admission_control: false,
            ..Default::default()
        };

        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let metrics = Metrics::new();

        let result = PressureGovernor::new(config, runtime, metrics);
        assert!(result.is_ok());

        let governor = result.unwrap();

        // Even with very high simulated pressure, disabled governor should not reject
        assert!(!governor.config().enabled);
    }

    #[test]
    fn test_pressure_governor_observe_only_mode() {
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .blocking_threads(0, 1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let first = runtime
            .spawn_blocking(move || {
                started_tx
                    .send(())
                    .expect("test should observe first blocking task start");
                release_rx
                    .recv()
                    .expect("test should release first blocking task");
            })
            .expect("runtime should expose a blocking pool");
        if let Err(error) = started_rx.recv_timeout(Duration::from_secs(2)) {
            let _ = release_tx.send(());
            panic!("first blocking task should start: {error}");
        }

        let (queued_tx, queued_rx) = std::sync::mpsc::channel();
        let second = runtime
            .spawn_blocking(move || {
                queued_tx
                    .send(())
                    .expect("test should observe queued blocking task run");
            })
            .expect("runtime should accept a queued blocking task");

        let config = PressureGovernorConfig {
            enabled: true,
            admission_control: false,
            sample_interval: Duration::ZERO,
            thresholds: PressureThresholds {
                blocking_pool: 0.5,
                ..Default::default()
            },
        };
        let metrics = Metrics::new();
        let governor =
            PressureGovernor::new(config, std::sync::Arc::clone(&runtime), metrics).unwrap();
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let decision = governor.check_admission(&cx);

        release_tx
            .send(())
            .expect("test should release first blocking task");
        assert!(
            first.wait_timeout(Duration::from_secs(2)),
            "first blocking task should finish"
        );
        assert!(
            second.wait_timeout(Duration::from_secs(2)),
            "queued blocking task should finish"
        );
        queued_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("queued blocking task should execute after release");

        let decision = decision.expect("observe-only admission should not fail");

        assert!(governor.config().enabled);
        assert!(!governor.config().admission_control);
        assert_eq!(decision, AdmissionDecision::Admit);
        assert_eq!(
            governor.fallback_verdict_metric(),
            PressureFallbackVerdict::PartialSignalsUnavailable.as_metric_value()
        );
        assert_eq!(governor.partial_fallback_total.get(), 1);
        assert_eq!(governor.no_win_fallback_total.get(), 0);
    }

    #[test]
    fn test_pressure_snapshot_overall_pressure_calculation() {
        let snapshot = PressureSnapshot {
            timestamp: Instant::now(),
            runnable_queue_pressure: 0.6,
            blocking_pool_pressure: 0.8, // Highest
            channel_backlog_pressure: 0.4,
            cleanup_debt_pressure: 0.5,
            memory_budget_pressure: 0.7,
            overall_pressure: 0.8, // Should be max of all signals
            signal_availability: PressureSignalAvailability::ALL,
            fallback_verdict: PressureFallbackVerdict::Complete,
        };

        // Verify overall pressure matches the highest signal
        assert_eq!(snapshot.overall_pressure, 0.8);
        assert!(snapshot.overall_pressure >= snapshot.runnable_queue_pressure);
        assert!(snapshot.overall_pressure >= snapshot.blocking_pool_pressure);
        assert!(snapshot.overall_pressure >= snapshot.channel_backlog_pressure);
        assert!(snapshot.overall_pressure >= snapshot.cleanup_debt_pressure);
        assert!(snapshot.overall_pressure >= snapshot.memory_budget_pressure);
    }

    #[test]
    fn pressure_signal_availability_reports_no_win_fallback() {
        let none = PressureSignalAvailability::NONE;
        assert!(!none.any_live());
        assert!(!none.all_live());
        assert_eq!(
            PressureFallbackVerdict::from_availability(none),
            PressureFallbackVerdict::NoWinNoLiveSignals
        );

        let partial = PressureSignalAvailability {
            runnable_queue: true,
            ..PressureSignalAvailability::NONE
        };
        assert!(partial.any_live());
        assert!(!partial.all_live());
        assert_eq!(
            PressureFallbackVerdict::from_availability(partial),
            PressureFallbackVerdict::PartialSignalsUnavailable
        );

        let round_trip = PressureSignalAvailability::from_mask(partial.mask());
        assert_eq!(round_trip, partial);
    }

    #[test]
    fn pressure_governor_records_fallback_counters_by_verdict() {
        let config = PressureGovernorConfig {
            enabled: true,
            admission_control: true,
            ..Default::default()
        };
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create fallback-counter runtime"),
        );
        let metrics = Metrics::new();
        let governor = PressureGovernor::new(config, runtime, metrics)
            .expect("pressure governor should initialize");

        governor.record_fallback_verdict(PressureFallbackVerdict::Complete);
        assert_eq!(governor.partial_fallback_total.get(), 0);
        assert_eq!(governor.no_win_fallback_total.get(), 0);

        governor.record_fallback_verdict(PressureFallbackVerdict::PartialSignalsUnavailable);
        assert_eq!(governor.partial_fallback_total.get(), 1);
        assert_eq!(governor.no_win_fallback_total.get(), 0);
        assert_eq!(
            governor.fallback_verdict_metric(),
            PressureFallbackVerdict::PartialSignalsUnavailable.as_metric_value()
        );

        governor.record_fallback_verdict(PressureFallbackVerdict::NoWinNoLiveSignals);
        assert_eq!(governor.partial_fallback_total.get(), 1);
        assert_eq!(governor.no_win_fallback_total.get(), 1);
        assert_eq!(
            governor.fallback_verdict_metric(),
            PressureFallbackVerdict::NoWinNoLiveSignals.as_metric_value()
        );
    }

    #[test]
    fn pressure_governor_records_partial_fallback_and_decision_latency() {
        let config = PressureGovernorConfig {
            enabled: true,
            admission_control: true,
            ..Default::default()
        };
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let metrics = Metrics::new();
        let governor = PressureGovernor::new(config, std::sync::Arc::clone(&runtime), metrics)
            .expect("pressure governor should initialize");
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let sampled = governor
            .sample_pressure(&cx)
            .expect("direct pressure sample should not fail");
        assert_eq!(
            sampled.fallback_verdict,
            PressureFallbackVerdict::PartialSignalsUnavailable
        );
        assert_eq!(
            governor.fallback_verdict_metric(),
            PressureFallbackVerdict::PartialSignalsUnavailable.as_metric_value()
        );
        assert_eq!(
            governor.partial_fallback_total.get(),
            0,
            "direct sampling updates the verdict gauge without counting an admission fallback"
        );
        assert_eq!(governor.no_win_fallback_total.get(), 0);

        let decision = governor
            .check_admission(&cx)
            .expect("pressure admission should not fail");

        assert_eq!(decision, AdmissionDecision::Admit);
        assert_eq!(
            governor.fallback_verdict_metric(),
            PressureFallbackVerdict::PartialSignalsUnavailable.as_metric_value()
        );
        assert_eq!(governor.partial_fallback_total.get(), 1);
        assert_eq!(governor.no_win_fallback_total.get(), 0);
        assert_eq!(governor.sample_count(), 1);
        let p95 = governor
            .decision_latency_p95_ns()
            .expect("p95 decision latency should be recorded");
        let p999 = governor
            .decision_latency_p999_ns()
            .expect("p999 decision latency should be recorded");
        assert_eq!(
            governor.decision_latency_p95_metric_ns(),
            u64_to_i64_saturating(p95)
        );
        assert_eq!(
            governor.decision_latency_p999_metric_ns(),
            u64_to_i64_saturating(p999)
        );

        let cached = governor
            .sample_pressure(&cx)
            .expect("cached pressure snapshot should not fail");
        assert_eq!(
            cached.fallback_verdict,
            PressureFallbackVerdict::PartialSignalsUnavailable
        );
        assert!(!cached.signal_availability.runnable_queue);
        assert!(!cached.signal_availability.blocking_pool);
        assert!(!cached.signal_availability.channel_backlog);
        assert!(cached.signal_availability.cleanup_debt);
        assert!(!cached.signal_availability.memory_budget);
    }

    #[test]
    fn pressure_governor_samples_blocking_pool_pressure_when_runtime_exposes_pool() {
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .blocking_threads(0, 1)
                .build()
                .expect("Failed to create blocking-pool runtime"),
        );
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let first = runtime
            .spawn_blocking(move || {
                started_tx
                    .send(())
                    .expect("test should observe first task start");
                release_rx
                    .recv()
                    .expect("test should release first blocking task");
            })
            .expect("runtime should expose a blocking pool");
        started_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("first blocking task should start");

        let (queued_tx, queued_rx) = std::sync::mpsc::channel();
        let second = runtime
            .spawn_blocking(move || {
                let _ = queued_tx.send(());
            })
            .expect("runtime should accept a queued blocking task");

        let config = PressureGovernorConfig {
            enabled: true,
            admission_control: true,
            sample_interval: Duration::ZERO,
            ..Default::default()
        };
        let metrics = Metrics::new();
        let governor = PressureGovernor::new(config, std::sync::Arc::clone(&runtime), metrics)
            .expect("pressure governor should initialize");
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let snapshot = governor
            .sample_pressure(&cx)
            .expect("blocking-pool pressure snapshot should not fail");
        assert!(snapshot.signal_availability.blocking_pool);
        assert!(!snapshot.signal_availability.runnable_queue);
        assert_eq!(
            snapshot.fallback_verdict,
            PressureFallbackVerdict::PartialSignalsUnavailable
        );
        assert!(
            snapshot.blocking_pool_pressure >= 1.0,
            "one busy blocking thread should produce saturation, got {}",
            snapshot.blocking_pool_pressure
        );
        assert_eq!(snapshot.overall_pressure, snapshot.blocking_pool_pressure);

        let decision = governor
            .check_admission(&cx)
            .expect("blocking-pool pressure decision should not fail");
        assert!(
            matches!(
                decision,
                AdmissionDecision::AdmitWithBackpressure | AdmissionDecision::Reject
            ),
            "blocking-pool pressure should influence admission, got {decision:?}"
        );
        assert_eq!(
            governor.fallback_verdict_metric(),
            PressureFallbackVerdict::PartialSignalsUnavailable.as_metric_value()
        );

        release_tx
            .send(())
            .expect("test should release first blocking task");
        assert!(
            first.wait_timeout(Duration::from_secs(2)),
            "first blocking task should finish"
        );
        assert!(
            second.wait_timeout(Duration::from_secs(2)),
            "queued blocking task should finish"
        );
        queued_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("queued blocking task should execute after release");
    }

    #[test]
    fn pressure_governor_leaves_runnable_queue_unavailable_without_capacity() {
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let config = PressureGovernorConfig {
            enabled: true,
            admission_control: true,
            sample_interval: Duration::ZERO,
            ..Default::default()
        };
        let metrics = Metrics::new();
        let governor = PressureGovernor::new(config, std::sync::Arc::clone(&runtime), metrics)
            .expect("pressure governor should initialize");
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let snapshot = governor
            .sample_pressure(&cx)
            .expect("pressure snapshot should not fail");

        assert!(!snapshot.signal_availability.runnable_queue);
        assert_eq!(snapshot.runnable_queue_pressure, 0.0);
    }

    #[test]
    fn pressure_governor_samples_runnable_queue_when_capacity_is_configured() {
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .global_queue_limit(4)
                .build()
                .expect("Failed to create global-queue-limited runtime"),
        );
        let config = PressureGovernorConfig {
            enabled: true,
            admission_control: true,
            sample_interval: Duration::ZERO,
            ..Default::default()
        };
        let metrics = Metrics::new();
        let governor = PressureGovernor::new(config, std::sync::Arc::clone(&runtime), metrics)
            .expect("pressure governor should initialize");
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let snapshot = governor
            .sample_pressure(&cx)
            .expect("pressure snapshot should not fail");

        assert_eq!(runtime.scheduler_global_ready_depth(), 0);
        assert!(snapshot.signal_availability.runnable_queue);
        assert_eq!(snapshot.runnable_queue_pressure, 0.0);
        assert_eq!(
            snapshot.fallback_verdict,
            PressureFallbackVerdict::PartialSignalsUnavailable
        );
    }

    #[test]
    fn pressure_governor_samples_cleanup_debt_from_runtime_draining_regions() {
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create cleanup-debt runtime"),
        );
        let config = PressureGovernorConfig {
            enabled: true,
            admission_control: true,
            sample_interval: Duration::ZERO,
            ..Default::default()
        };
        let metrics = Metrics::new();
        let governor = PressureGovernor::new(config, std::sync::Arc::clone(&runtime), metrics)
            .expect("pressure governor should initialize");
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let snapshot = governor
            .sample_pressure(&cx)
            .expect("pressure snapshot should not fail");

        assert_eq!(runtime.draining_region_count(), 0);
        assert!(snapshot.signal_availability.cleanup_debt);
        assert_eq!(snapshot.cleanup_debt_pressure, 0.0);
        assert_eq!(
            snapshot.fallback_verdict,
            PressureFallbackVerdict::PartialSignalsUnavailable
        );
    }

    #[test]
    fn pressure_governor_samples_memory_budget_from_resource_monitor() {
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create memory-pressure runtime"),
        );
        runtime.resource_monitor().pressure().update_measurement(
            ResourceType::Memory,
            crate::runtime::resource_monitor::ResourceMeasurement::new(768, 800, 950, 1024),
        );

        let config = PressureGovernorConfig {
            enabled: true,
            admission_control: true,
            sample_interval: Duration::ZERO,
            ..Default::default()
        };
        let metrics = Metrics::new();
        let governor = PressureGovernor::new(config, std::sync::Arc::clone(&runtime), metrics)
            .expect("pressure governor should initialize");
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let snapshot = governor
            .sample_pressure(&cx)
            .expect("pressure snapshot should not fail");

        assert!(snapshot.signal_availability.memory_budget);
        assert_eq!(snapshot.memory_budget_pressure, 0.75);
        assert_eq!(snapshot.overall_pressure, snapshot.memory_budget_pressure);
        assert_eq!(
            snapshot.fallback_verdict,
            PressureFallbackVerdict::PartialSignalsUnavailable
        );
    }

    #[test]
    fn test_pressure_thresholds_defaults() {
        let thresholds = PressureThresholds::default();

        // Verify reasonable defaults
        assert_eq!(thresholds.runnable_queue, 0.8);
        assert_eq!(thresholds.blocking_pool, 0.9);
        assert_eq!(thresholds.channel_backlog, 0.7);
        assert_eq!(thresholds.cleanup_debt, 0.8);
        assert_eq!(thresholds.memory_budget, 0.9);

        // Verify all thresholds are in reasonable range
        assert!(thresholds.runnable_queue > 0.0 && thresholds.runnable_queue < 1.0);
        assert!(thresholds.blocking_pool > 0.0 && thresholds.blocking_pool < 1.0);
        assert!(thresholds.channel_backlog > 0.0 && thresholds.channel_backlog < 1.0);
        assert!(thresholds.cleanup_debt > 0.0 && thresholds.cleanup_debt < 1.0);
        assert!(thresholds.memory_budget > 0.0 && thresholds.memory_budget < 1.0);
    }

    /// Integration test demonstrating the pressure governor against live runtime signals.
    #[cfg(feature = "test-internals")]
    #[test]
    fn test_pressure_governor_integration_scenario() {
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .global_queue_limit(4)
                .blocking_threads(0, 1)
                .build()
                .expect("Failed to create runtime for pressure integration scenario"),
        );

        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let first = runtime
            .spawn_blocking(move || {
                started_tx
                    .send(())
                    .expect("test should observe first blocking task start");
                release_rx
                    .recv()
                    .expect("test should release first blocking task");
            })
            .expect("runtime should expose a blocking pool");
        started_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("first blocking task should start");

        let (queued_tx, queued_rx) = std::sync::mpsc::channel();
        let second = runtime
            .spawn_blocking(move || {
                queued_tx
                    .send(())
                    .expect("test should observe queued blocking task run");
            })
            .expect("runtime should accept a queued blocking task");

        let config = PressureGovernorConfig {
            enabled: true,
            admission_control: true,
            sample_interval: Duration::ZERO,
            thresholds: PressureThresholds {
                runnable_queue: 0.5,
                blocking_pool: 0.5,
                channel_backlog: 0.6,
                cleanup_debt: 0.7,
                memory_budget: 0.8,
            },
        };
        let metrics = Metrics::new();
        let governor = PressureGovernor::new(config, std::sync::Arc::clone(&runtime), metrics)
            .expect("pressure governor should initialize");
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let saturated = governor.sample_pressure(&cx);
        let decision = governor.check_admission(&cx);

        release_tx
            .send(())
            .expect("test should release first blocking task");
        assert!(
            first.wait_timeout(Duration::from_secs(2)),
            "first blocking task should finish"
        );
        assert!(
            second.wait_timeout(Duration::from_secs(2)),
            "queued blocking task should finish"
        );
        queued_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("queued blocking task should execute after release");

        let drained = governor
            .sample_pressure(&cx)
            .expect("drained pressure snapshot should not fail");

        let saturated = saturated.expect("pressure snapshot should not fail");
        assert!(saturated.signal_availability.runnable_queue);
        assert!(saturated.signal_availability.blocking_pool);
        assert!(!saturated.signal_availability.channel_backlog);
        assert!(saturated.signal_availability.cleanup_debt);
        assert_eq!(
            saturated.fallback_verdict,
            PressureFallbackVerdict::PartialSignalsUnavailable
        );
        assert_eq!(saturated.runnable_queue_pressure, 0.0);
        assert_eq!(saturated.cleanup_debt_pressure, 0.0);
        assert!(
            saturated.blocking_pool_pressure >= 1.0,
            "busy plus queued blocking work should saturate the pool, got {}",
            saturated.blocking_pool_pressure
        );
        assert_eq!(saturated.overall_pressure, saturated.blocking_pool_pressure);

        let decision = decision.expect("admission decision should not fail");
        assert_eq!(decision, AdmissionDecision::Reject);
        assert_eq!(
            governor.fallback_verdict_metric(),
            PressureFallbackVerdict::PartialSignalsUnavailable.as_metric_value()
        );
        assert_eq!(governor.partial_fallback_total.get(), 1);
        assert_eq!(governor.no_win_fallback_total.get(), 0);

        assert!(drained.signal_availability.runnable_queue);
        assert!(drained.signal_availability.blocking_pool);
        assert!(drained.signal_availability.cleanup_debt);
        assert_eq!(drained.runnable_queue_pressure, 0.0);
        assert_eq!(drained.blocking_pool_pressure, 0.0);
        assert_eq!(drained.cleanup_debt_pressure, 0.0);
        assert_eq!(drained.overall_pressure, 0.0);
        assert!(
            runtime.is_quiescent(),
            "runtime should be quiescent after pressure scenario drains"
        );
    }
}
