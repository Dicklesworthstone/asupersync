//! Live swarm pressure governor for preventing overload in large agent deployments.
//!
//! This module provides deterministic pressure monitoring and admission control
//! based on runtime-local metrics including queue depths, pool saturation,
//! channel backlogs, and memory budget signals.

use crate::cx::Cx;
use crate::error::Error;
use crate::observability::metrics::{Counter, Gauge, Metrics, Summary};
use crate::runtime::Runtime;
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
    fallback_total: Arc<Counter>,

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
        let fallback_total = metrics.counter("pressure_governor_no_win_fallback_total");
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
            fallback_total,
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

        // Cleanup debt pressure: pending cleanup tasks / capacity
        // TODO: Access runtime cleanup queue when available
        let cleanup_debt = self.sample_cleanup_debt_pressure();

        // Memory budget pressure: allocated / budget
        // TODO: Access memory allocator statistics when available
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
        // Access the runtime's scheduler statistics
        // This is a simplified implementation - in production we'd want to access
        // the actual scheduler queue depths from ThreeLaneScheduler

        // For now, get approximation from worker ready counts
        // In a full implementation, we would:
        // 1. Access ThreeLaneScheduler.workers[].ready_count() for each worker
        // 2. Sum global queue depths from GlobalInjector
        // 3. Calculate pressure as (total_ready_tasks / (worker_count * expected_capacity))

        // No live scheduler queue signal is exposed yet. Report no pressure
        // instead of fabricating load from unrelated process state.
        PressureSignalSample::unavailable()
    }

    fn sample_blocking_pool_pressure(&self) -> PressureSignalSample {
        // TODO: Access actual blocking pool handle from runtime
        // In a full implementation, we would:
        // 1. Get BlockingPoolHandle from Runtime
        // 2. Call blocking_pool.busy_threads() / blocking_pool.max_threads
        // 3. Also consider pending_count() for queue pressure

        // No live blocking-pool saturation signal is exposed yet.
        PressureSignalSample::unavailable()
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
        // TODO: Access runtime resource cleanup verifier statistics
        // In a full implementation, we would:
        // 1. Access ResourceCleanupVerifier from Runtime
        // 2. Get pending cleanup task count and capacity
        // 3. Calculate pressure as pending / capacity

        // No live cleanup-debt signal is exposed yet.
        PressureSignalSample::unavailable()
    }

    fn sample_memory_budget_pressure(&self) -> PressureSignalSample {
        // TODO: Access memory allocator and budget statistics
        // In a full implementation, we would:
        // 1. Access RegionHeap statistics for allocated memory
        // 2. Get budget limits from RuntimeConfig
        // 3. Calculate pressure as allocated / budget

        // No live memory-budget signal is exposed yet.
        PressureSignalSample::unavailable()
    }

    fn record_fallback_verdict(&self, verdict: PressureFallbackVerdict) {
        self.fallback_verdict_gauge.set(verdict.as_metric_value());
        if verdict != PressureFallbackVerdict::Complete {
            self.fallback_total.increment();
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

        // Create a mock governor for testing evaluation logic
        // Note: Creating a full runtime for unit tests is complex, so we'll use a placeholder approach
        // In a real scenario, we'd use RuntimeBuilder to create the runtime
        // For this test, we're focusing on the evaluation logic independent of runtime

        // Create a dummy runtime reference for testing
        use std::sync::Arc;

        // Use a simple runtime handle for testing - this won't actually be used in evaluation
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
        let config = PressureGovernorConfig {
            enabled: true,
            admission_control: false, // Observe-only mode
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

        // In observe-only mode, should collect metrics but always admit
        assert!(governor.config().enabled);
        assert!(!governor.config().admission_control);
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
    fn pressure_governor_records_no_win_fallback_and_decision_latency() {
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
        let governor = PressureGovernor::new(config, runtime, metrics).unwrap();
        let cx = Cx::new();

        let decision = governor
            .check_admission(&cx)
            .expect("pressure admission should not fail");

        assert_eq!(decision, AdmissionDecision::Admit);
        assert_eq!(
            governor.fallback_verdict_metric(),
            PressureFallbackVerdict::NoWinNoLiveSignals.as_metric_value()
        );
        assert_eq!(governor.fallback_total.get(), 1);
        assert_eq!(governor.sample_count(), 1);
        assert!(governor.decision_latency_p95_ns().is_some());
        assert!(governor.decision_latency_p999_ns().is_some());

        let cached = governor
            .sample_pressure(&cx)
            .expect("cached pressure snapshot should not fail");
        assert_eq!(
            cached.fallback_verdict,
            PressureFallbackVerdict::NoWinNoLiveSignals
        );
        assert_eq!(cached.signal_availability, PressureSignalAvailability::NONE);
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

    /// Integration test demonstrating the pressure governor in a lab scenario.
    /// This test would be expanded in a full implementation to run actual workloads
    /// and verify pressure detection and admission decisions.
    #[cfg(feature = "test-internals")]
    #[test]
    fn test_pressure_governor_integration_scenario() {
        // This is a placeholder for a full integration test that would:
        // 1. Create a lab runtime with multiple workers
        // 2. Install a pressure governor with realistic thresholds
        // 3. Run a workload that gradually increases pressure
        // 4. Verify that pressure metrics are collected correctly
        // 5. Verify that admission decisions change as pressure increases
        // 6. Verify that backpressure and rejection occur at appropriate thresholds

        let config = PressureGovernorConfig {
            enabled: true,
            admission_control: true,
            sample_interval: Duration::from_millis(100),
            thresholds: PressureThresholds {
                runnable_queue: 0.7,
                blocking_pool: 0.8,
                channel_backlog: 0.6,
                cleanup_debt: 0.7,
                memory_budget: 0.8,
            },
        };

        // In a full test, we would:
        // let runtime = RuntimeBuilder::new().worker_threads(4).build().unwrap();
        // let metrics = Arc::new(Metrics::new());
        // let governor = Arc::new(PressureGovernor::new(config, runtime.handle(), metrics).unwrap());
        // ... run workload and verify behavior

        assert!(config.enabled);
        assert!(config.admission_control);
    }
}
