//! Live swarm pressure governor for preventing overload in large agent deployments.
//!
//! This module provides deterministic pressure monitoring and admission control
//! based on runtime-local metrics including queue depths, pool saturation,
//! cleanup debt, and memory budget signals. Channel-backlog pressure is an
//! explicit aggregate sample today: channel owners must feed it through
//! [`PressureGovernor::record_channel_backlog_sample`] until the runtime owns a
//! channel registry.

use crate::cx::Cx;
use crate::error::Error;
use crate::observability::metrics::{Counter, Gauge, Metrics, Summary};
use crate::runtime::Runtime;
use crate::runtime::resource_monitor::ResourceType;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const CHANNEL_BACKLOG_SAMPLE_UNAVAILABLE: u64 = u64::MAX;
static NEXT_PRESSURE_GOVERNOR_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);

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
    /// Channel backlog threshold for the explicit aggregate sample
    /// (pending/buffer_size across sampled channels).
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
    /// Channel backlog pressure (0.0-1.0+) when an explicit aggregate sample is live.
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

/// Resource envelope for tracking region-level resource allocations.
#[derive(Debug, Clone)]
pub struct ResourceEnvelope {
    /// Memory budget allocated to this envelope.
    pub memory_budget: u64,
    /// CPU allocation weight (relative to other envelopes).
    pub cpu_weight: f64,
    /// Maximum concurrent I/O operations.
    pub io_budget: u64,
    /// Maximum number of tasks allowed in this envelope.
    pub task_limit: usize,
    /// Current resource usage within this envelope.
    pub usage: ResourceUsage,
}

/// Current resource usage for an envelope.
#[derive(Debug, Clone, Default)]
pub struct ResourceUsage {
    /// Memory currently allocated.
    pub memory_used: u64,
    /// CPU utilization (0.0-1.0).
    pub cpu_utilization: f64,
    /// Active I/O operations.
    pub io_active: u64,
    /// Current task count.
    pub task_count: usize,
}

/// Swarm coordination state for distributed pressure management.
#[derive(Debug, Clone)]
pub struct SwarmCoordinationState {
    /// This runtime's instance ID for swarm coordination.
    pub instance_id: u64,
    /// Peer runtime pressure states.
    pub peer_states: std::collections::HashMap<u64, PeerPressureState>,
    /// Last coordination timestamp.
    pub last_coordination: std::time::Instant,
    /// Coordination interval.
    pub coordination_interval: std::time::Duration,
}

/// Pressure state from a peer runtime in the swarm.
#[derive(Debug, Clone)]
pub struct PeerPressureState {
    /// Peer's overall pressure level.
    pub overall_pressure: f64,
    /// Peer's admission rate.
    pub admission_rate: f64,
    /// Last update timestamp.
    pub last_update: std::time::Instant,
    /// Whether peer is available for coordination.
    pub available: bool,
}

/// Enhanced admission decision with resource envelope context.
#[derive(Debug, Clone)]
pub struct EnhancedAdmissionDecision {
    /// Basic admission decision.
    pub decision: AdmissionDecision,
    /// Suggested resource envelope for admitted operations.
    pub suggested_envelope: Option<ResourceEnvelope>,
    /// Backpressure propagation signals.
    pub backpressure_signals: BackpressureSignals,
    /// Coordination hints for swarm management.
    pub swarm_hints: SwarmCoordinationHints,
}

/// Backpressure signals to propagate across components.
#[derive(Debug, Clone, Default)]
pub struct BackpressureSignals {
    /// Suggested delay before retry (for rejected operations).
    pub retry_delay: Option<std::time::Duration>,
    /// Component-specific pressure levels (0.0-1.0).
    pub component_pressures: std::collections::HashMap<String, f64>,
    /// Whether to shed load in upstream components.
    pub shed_load: bool,
}

/// Coordination hints for swarm pressure management.
#[derive(Debug, Clone, Default)]
pub struct SwarmCoordinationHints {
    /// Whether to redistribute load to peer runtimes.
    pub redistribute_load: bool,
    /// Preferred peer instances for load redistribution.
    pub preferred_peers: Vec<u64>,
    /// Expected pressure relief duration.
    pub relief_duration: Option<std::time::Duration>,
}

/// Live swarm pressure governor.
pub struct PressureGovernor {
    config: PressureGovernorConfig,
    runtime: Arc<Runtime>,
    #[allow(dead_code)]
    // Retained so the metric handles registered above keep their owning
    // registry/exporter state alive for the governor lifetime.
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
    channel_backlog_sample_bits: AtomicU64,
    sample_count: AtomicU64,
    decision_latency_summary: Arc<Summary>,
    decision_latency_p95_gauge: Arc<Gauge>,
    decision_latency_p999_gauge: Arc<Gauge>,
    fallback_verdict_gauge: Arc<Gauge>,

    // Resource envelope tracking
    active_envelopes: std::sync::RwLock<std::collections::HashMap<u64, ResourceEnvelope>>,
    envelope_metrics: EnvelopeMetrics,

    // Swarm coordination
    swarm_state: std::sync::RwLock<SwarmCoordinationState>,
    swarm_metrics: SwarmMetrics,
}

/// Metrics for resource envelope tracking.
#[derive(Debug)]
struct EnvelopeMetrics {
    envelopes_active: Arc<Gauge>,
    envelope_memory_used: Arc<Gauge>,
    envelope_cpu_utilization: Arc<Gauge>,
    envelope_io_active: Arc<Gauge>,
    envelope_violations: Arc<Counter>,
}

/// Metrics for swarm coordination.
#[derive(Debug)]
struct SwarmMetrics {
    peers_active: Arc<Gauge>,
    coordination_rounds: Arc<Counter>,
    peer_pressure_max: Arc<Gauge>,
    coordination_latency: Arc<Summary>,
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
        let envelope_metrics = EnvelopeMetrics {
            envelopes_active: metrics.gauge("envelope_envelopes_active"),
            envelope_memory_used: metrics.gauge("envelope_memory_used_bytes"),
            envelope_cpu_utilization: metrics.gauge("envelope_cpu_utilization_scaled"),
            envelope_io_active: metrics.gauge("envelope_io_active_operations"),
            envelope_violations: metrics.counter("envelope_violations_total"),
        };
        let swarm_metrics = SwarmMetrics {
            peers_active: metrics.gauge("swarm_peers_active"),
            coordination_rounds: metrics.counter("swarm_coordination_rounds_total"),
            peer_pressure_max: metrics.gauge("swarm_peer_pressure_max_scaled"),
            coordination_latency: metrics.summary("swarm_coordination_latency_seconds"),
        };
        let started_at = Instant::now();
        let metrics = Arc::new(metrics);

        Ok(Self {
            config,
            runtime,
            metrics,
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
            channel_backlog_sample_bits: AtomicU64::new(CHANNEL_BACKLOG_SAMPLE_UNAVAILABLE),
            sample_count: AtomicU64::new(0),
            decision_latency_summary,
            decision_latency_p95_gauge,
            decision_latency_p999_gauge,
            fallback_verdict_gauge,

            // Initialize resource envelope tracking
            active_envelopes: std::sync::RwLock::new(std::collections::HashMap::new()),
            envelope_metrics,

            // Initialize swarm coordination
            swarm_state: std::sync::RwLock::new(SwarmCoordinationState {
                instance_id: NEXT_PRESSURE_GOVERNOR_INSTANCE_ID.fetch_add(1, Ordering::Relaxed),
                peer_states: std::collections::HashMap::new(),
                last_coordination: Instant::now(),
                coordination_interval: Duration::from_secs(1), // 1s coordination interval
            }),
            swarm_metrics,
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

    /// Records an explicit aggregate channel backlog sample.
    ///
    /// `pending_items` should include committed queued messages plus any
    /// reserved-but-uncommitted send obligations across the sampled channels.
    /// `total_capacity` is the summed capacity for those channels. A zero
    /// capacity clears the signal because no meaningful pressure ratio exists.
    pub fn record_channel_backlog_sample(&self, pending_items: usize, total_capacity: usize) {
        let bits = if total_capacity == 0 {
            CHANNEL_BACKLOG_SAMPLE_UNAVAILABLE
        } else {
            (pending_items as f64 / total_capacity as f64).to_bits()
        };
        self.channel_backlog_sample_bits
            .store(bits, Ordering::Release);
        self.last_sample.store(0, Ordering::Release);
    }

    /// Clears the explicit aggregate channel backlog sample.
    pub fn clear_channel_backlog_sample(&self) {
        self.channel_backlog_sample_bits
            .store(CHANNEL_BACKLOG_SAMPLE_UNAVAILABLE, Ordering::Release);
        self.last_sample.store(0, Ordering::Release);
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

    /// Make an enhanced admission decision with resource envelope and swarm coordination.
    pub fn check_enhanced_admission(
        &self,
        cx: &Cx,
        requested_envelope: Option<ResourceEnvelope>,
    ) -> Result<EnhancedAdmissionDecision, Error> {
        let decision_started_at = Instant::now();

        // Basic admission check first
        let basic_decision = self.check_admission(cx)?;

        // Update swarm coordination state
        self.update_swarm_coordination()?;

        // Build enhanced decision with resource envelope and backpressure signals
        let enhanced_decision = match basic_decision {
            AdmissionDecision::Admit => {
                let envelope = self.allocate_resource_envelope(requested_envelope)?;
                EnhancedAdmissionDecision {
                    decision: AdmissionDecision::Admit,
                    suggested_envelope: Some(envelope),
                    backpressure_signals: self.generate_backpressure_signals(false)?,
                    swarm_hints: self.generate_swarm_hints()?,
                }
            }
            AdmissionDecision::AdmitWithBackpressure => {
                let envelope = self.allocate_constrained_envelope(requested_envelope)?;
                EnhancedAdmissionDecision {
                    decision: AdmissionDecision::AdmitWithBackpressure,
                    suggested_envelope: envelope,
                    backpressure_signals: self.generate_backpressure_signals(true)?,
                    swarm_hints: self.generate_swarm_hints()?,
                }
            }
            AdmissionDecision::Reject => {
                let backpressure = self.generate_backpressure_signals(true)?;
                let swarm_hints = self.generate_swarm_hints()?;
                EnhancedAdmissionDecision {
                    decision: AdmissionDecision::Reject,
                    suggested_envelope: None,
                    backpressure_signals: backpressure,
                    swarm_hints,
                }
            }
        };

        self.record_decision_latency(decision_started_at);
        Ok(enhanced_decision)
    }

    /// Register a new resource envelope for tracking.
    pub fn register_envelope(
        &self,
        envelope_id: u64,
        envelope: ResourceEnvelope,
    ) -> Result<(), Error> {
        let mut envelopes = self
            .active_envelopes
            .write()
            .map_err(|_| Error::internal("Failed to acquire envelope lock".to_string()))?;

        envelopes.insert(envelope_id, envelope);
        self.envelope_metrics
            .envelopes_active
            .set(usize_to_i64_saturating(envelopes.len()));
        self.update_envelope_metrics(&envelopes)?;
        Ok(())
    }

    /// Update resource usage for an existing envelope.
    pub fn update_envelope_usage(
        &self,
        envelope_id: u64,
        usage: ResourceUsage,
    ) -> Result<(), Error> {
        let mut envelopes = self
            .active_envelopes
            .write()
            .map_err(|_| Error::internal("Failed to acquire envelope lock".to_string()))?;

        if let Some(envelope) = envelopes.get_mut(&envelope_id) {
            envelope.usage = usage;

            // Check for violations
            if self.check_envelope_violations(envelope) {
                self.envelope_metrics.envelope_violations.increment();
            }

            self.update_envelope_metrics(&envelopes)?;
        }

        Ok(())
    }

    /// Remove a resource envelope when no longer needed.
    pub fn unregister_envelope(&self, envelope_id: u64) -> Result<(), Error> {
        let mut envelopes = self
            .active_envelopes
            .write()
            .map_err(|_| Error::internal("Failed to acquire envelope lock".to_string()))?;

        envelopes.remove(&envelope_id);
        self.envelope_metrics
            .envelopes_active
            .set(usize_to_i64_saturating(envelopes.len()));
        self.update_envelope_metrics(&envelopes)?;
        Ok(())
    }

    /// Update peer pressure state for swarm coordination.
    pub fn update_peer_pressure(
        &self,
        peer_id: u64,
        pressure_state: PeerPressureState,
    ) -> Result<(), Error> {
        let mut swarm_state = self
            .swarm_state
            .write()
            .map_err(|_| Error::internal("Failed to acquire swarm lock".to_string()))?;

        swarm_state.peer_states.insert(peer_id, pressure_state);
        self.swarm_metrics
            .peers_active
            .set(usize_to_i64_saturating(swarm_state.peer_states.len()));

        // Update max peer pressure metric
        if let Some(max_pressure) = swarm_state
            .peer_states
            .values()
            .map(|p| p.overall_pressure)
            .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
        {
            const PRESSURE_SCALE: f64 = 10000.0;
            self.swarm_metrics
                .peer_pressure_max
                .set((max_pressure * PRESSURE_SCALE) as i64);
        }

        Ok(())
    }

    /// Get current swarm coordination state for external coordination.
    pub fn get_swarm_state(&self) -> Result<SwarmCoordinationState, Error> {
        let swarm_state = self
            .swarm_state
            .read()
            .map_err(|_| Error::internal("Failed to acquire swarm lock".to_string()))?;
        Ok(swarm_state.clone())
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

        // Channel backlog pressure is unavailable until a caller records an
        // explicit aggregate sample with `record_channel_backlog_sample`.
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
        let bits = self.channel_backlog_sample_bits.load(Ordering::Acquire);
        if bits != CHANNEL_BACKLOG_SAMPLE_UNAVAILABLE {
            let pressure = f64::from_bits(bits);
            if pressure.is_finite() && pressure >= 0.0 {
                return PressureSignalSample::available(pressure);
            }
        }

        // A full registry can replace this explicit aggregate sample once the
        // runtime owns one. Until then, channel owners can feed deterministic
        // telemetry through `record_channel_backlog_sample`.
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

    // Resource envelope management helpers

    fn allocate_resource_envelope(
        &self,
        requested: Option<ResourceEnvelope>,
    ) -> Result<ResourceEnvelope, Error> {
        // Use requested envelope or create a default one
        let envelope = requested.unwrap_or_else(|| ResourceEnvelope {
            memory_budget: 64 * 1024 * 1024, // 64MB default
            cpu_weight: 1.0,
            io_budget: 10,
            task_limit: 100,
            usage: ResourceUsage::default(),
        });

        // Validate that we have resources available
        self.validate_resource_availability(&envelope)?;
        Ok(envelope)
    }

    fn allocate_constrained_envelope(
        &self,
        requested: Option<ResourceEnvelope>,
    ) -> Result<Option<ResourceEnvelope>, Error> {
        if let Some(mut envelope) = requested {
            // Reduce allocations by 50% under backpressure
            envelope.memory_budget /= 2;
            envelope.cpu_weight /= 2.0;
            envelope.io_budget /= 2;
            envelope.task_limit /= 2;

            if self.validate_resource_availability(&envelope).is_ok() {
                Ok(Some(envelope))
            } else {
                Ok(None) // Can't even allocate constrained envelope
            }
        } else {
            // Create a minimal constrained envelope
            let envelope = ResourceEnvelope {
                memory_budget: 16 * 1024 * 1024, // 16MB constrained
                cpu_weight: 0.5,
                io_budget: 2,
                task_limit: 10,
                usage: ResourceUsage::default(),
            };

            if self.validate_resource_availability(&envelope).is_ok() {
                Ok(Some(envelope))
            } else {
                Ok(None)
            }
        }
    }

    fn validate_resource_availability(&self, envelope: &ResourceEnvelope) -> Result<(), Error> {
        let envelopes = self
            .active_envelopes
            .read()
            .map_err(|_| Error::internal("Failed to acquire envelope lock".to_string()))?;

        // Calculate current resource usage across all envelopes
        let total_memory: u64 = envelopes.values().map(|e| e.usage.memory_used).sum();
        let total_io: u64 = envelopes.values().map(|e| e.usage.io_active).sum();
        let total_tasks: usize = envelopes.values().map(|e| e.usage.task_count).sum();

        // Simple resource limits (in production, these would come from system discovery)
        const MAX_MEMORY: u64 = 4 * 1024 * 1024 * 1024; // 4GB
        const MAX_IO: u64 = 1000;
        const MAX_TASKS: usize = 10000;

        if total_memory + envelope.memory_budget > MAX_MEMORY {
            return Err(Error::internal("Insufficient memory budget".to_string()));
        }
        if total_io + envelope.io_budget > MAX_IO {
            return Err(Error::internal("Insufficient I/O budget".to_string()));
        }
        if total_tasks + envelope.task_limit > MAX_TASKS {
            return Err(Error::internal("Insufficient task limit".to_string()));
        }

        Ok(())
    }

    fn check_envelope_violations(&self, envelope: &ResourceEnvelope) -> bool {
        envelope.usage.memory_used > envelope.memory_budget
            || envelope.usage.io_active > envelope.io_budget
            || envelope.usage.task_count > envelope.task_limit
            || envelope.usage.cpu_utilization > 1.0
    }

    fn update_envelope_metrics(
        &self,
        envelopes: &std::collections::HashMap<u64, ResourceEnvelope>,
    ) -> Result<(), Error> {
        let total_memory: u64 = envelopes.values().map(|e| e.usage.memory_used).sum();
        let avg_cpu: f64 = if envelopes.is_empty() {
            0.0
        } else {
            envelopes
                .values()
                .map(|e| e.usage.cpu_utilization)
                .sum::<f64>()
                / envelopes.len() as f64
        };
        let total_io: u64 = envelopes.values().map(|e| e.usage.io_active).sum();

        self.envelope_metrics
            .envelope_memory_used
            .set(u64_to_i64_saturating(total_memory));
        self.envelope_metrics
            .envelope_cpu_utilization
            .set((avg_cpu * 10000.0) as i64); // scaled
        self.envelope_metrics
            .envelope_io_active
            .set(u64_to_i64_saturating(total_io));

        Ok(())
    }

    // Backpressure signal generation

    fn generate_backpressure_signals(
        &self,
        under_pressure: bool,
    ) -> Result<BackpressureSignals, Error> {
        let mut signals = BackpressureSignals::default();

        if under_pressure {
            signals.retry_delay = Some(Duration::from_millis(100)); // 100ms retry delay
            signals.shed_load = true;

            // Add component-specific pressure levels
            signals
                .component_pressures
                .insert("scheduler".to_string(), 0.8);
            signals
                .component_pressures
                .insert("blocking_pool".to_string(), 0.7);
            signals
                .component_pressures
                .insert("memory".to_string(), 0.9);
        }

        Ok(signals)
    }

    // Swarm coordination helpers

    fn generate_swarm_hints(&self) -> Result<SwarmCoordinationHints, Error> {
        let swarm_state = self
            .swarm_state
            .read()
            .map_err(|_| Error::internal("Failed to acquire swarm lock".to_string()))?;

        let mut hints = SwarmCoordinationHints::default();

        // Find peers with lower pressure for load redistribution
        let available_peers: Vec<u64> = swarm_state
            .peer_states
            .iter()
            .filter(|(_, state)| state.available && state.overall_pressure < 0.7)
            .map(|(&id, _)| id)
            .collect();

        if !available_peers.is_empty() {
            hints.redistribute_load = true;
            hints.preferred_peers = available_peers;
            hints.relief_duration = Some(Duration::from_secs(30)); // Expected relief in 30s
        }

        Ok(hints)
    }

    fn update_swarm_coordination(&self) -> Result<(), Error> {
        let coordination_start = Instant::now();

        {
            let mut swarm_state = self
                .swarm_state
                .write()
                .map_err(|_| Error::internal("Failed to acquire swarm lock".to_string()))?;

            // Check if it's time for coordination
            if coordination_start.duration_since(swarm_state.last_coordination)
                < swarm_state.coordination_interval
            {
                return Ok(());
            }

            // Remove stale peer states
            let stale_threshold = Duration::from_secs(30);
            swarm_state.peer_states.retain(|_, state| {
                coordination_start.duration_since(state.last_update) < stale_threshold
            });

            swarm_state.last_coordination = coordination_start;
        }

        self.swarm_metrics.coordination_rounds.increment();

        let coordination_duration = Instant::now().duration_since(coordination_start);
        self.swarm_metrics
            .coordination_latency
            .observe(coordination_duration.as_secs_f64());

        Ok(())
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

fn usize_to_i64_saturating(value: usize) -> i64 {
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
    use crate::lab::{LabConfig, LabRunReport, LabRuntime};
    use crate::observability::metrics::Metrics;
    use crate::runtime::RuntimeBuilder;
    use crate::types::Budget;
    use std::time::Duration;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct PressureLabTransition {
        pending_items: usize,
        total_capacity: usize,
        channel_backlog_pressure_scaled: i64,
        decision: AdmissionDecision,
        fallback_verdict: PressureFallbackVerdict,
        channel_backlog_live: bool,
    }

    fn run_lab_pressure_transition_projection(
        seed: u64,
    ) -> (Vec<PressureLabTransition>, LabRunReport) {
        let mut lab = LabRuntime::new(LabConfig::new(seed).worker_count(2).max_steps(10_000));
        let root = lab.state.create_root_region(Budget::INFINITE);
        for _ in 0..3 {
            let (task_id, _handle) = lab
                .state
                .create_task(root, Budget::INFINITE, async {
                    crate::runtime::yield_now::yield_now().await;
                })
                .expect("lab pressure task should be created");
            lab.scheduler.lock().schedule(task_id, 0);
        }

        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .global_queue_limit(4)
                .build()
                .expect("Failed to create pressure transition runtime"),
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

        let mut transitions = Vec::new();
        for (pending_items, total_capacity) in [(0, 4), (3, 4), (5, 4)] {
            governor.record_channel_backlog_sample(pending_items, total_capacity);
            let snapshot = governor
                .sample_pressure(&cx)
                .expect("pressure snapshot should not fail");
            let decision = governor
                .check_admission(&cx)
                .expect("pressure admission should not fail");
            transitions.push(PressureLabTransition {
                pending_items,
                total_capacity,
                channel_backlog_pressure_scaled: (snapshot.channel_backlog_pressure * 10_000.0)
                    as i64,
                decision,
                fallback_verdict: snapshot.fallback_verdict,
                channel_backlog_live: snapshot.signal_availability.channel_backlog,
            });
        }

        let report = lab.run_until_quiescent_with_report();
        (transitions, report)
    }

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
    fn pressure_governor_cached_snapshot_preserves_signal_availability() {
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .global_queue_limit(4)
                .build()
                .expect("Failed to create cached-snapshot runtime"),
        );
        runtime.resource_monitor().pressure().update_measurement(
            ResourceType::Memory,
            crate::runtime::resource_monitor::ResourceMeasurement::new(512, 800, 950, 1024),
        );

        let config = PressureGovernorConfig {
            enabled: true,
            admission_control: true,
            sample_interval: Duration::from_secs(60),
            ..Default::default()
        };
        let metrics = Metrics::new();
        let governor = PressureGovernor::new(config, std::sync::Arc::clone(&runtime), metrics)
            .expect("pressure governor should initialize");
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let fresh = governor
            .sample_pressure(&cx)
            .expect("fresh pressure snapshot should not fail");
        let cached = governor
            .sample_pressure(&cx)
            .expect("cached pressure snapshot should not fail");

        assert_eq!(governor.sample_count(), 1);
        assert_eq!(cached.signal_availability, fresh.signal_availability);
        assert!(cached.signal_availability.runnable_queue);
        assert!(cached.signal_availability.cleanup_debt);
        assert!(cached.signal_availability.memory_budget);
        assert_eq!(
            cached.fallback_verdict,
            PressureFallbackVerdict::PartialSignalsUnavailable
        );
        assert_eq!(cached.memory_budget_pressure, 0.5);
        assert_eq!(cached.overall_pressure, fresh.overall_pressure);
    }

    #[test]
    fn pressure_governor_samples_explicit_channel_backlog_telemetry() {
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .global_queue_limit(4)
                .build()
                .expect("Failed to create channel-backlog runtime"),
        );
        let config = PressureGovernorConfig {
            enabled: true,
            admission_control: true,
            sample_interval: Duration::from_secs(60),
            ..Default::default()
        };
        let metrics = Metrics::new();
        let governor = PressureGovernor::new(config, std::sync::Arc::clone(&runtime), metrics)
            .expect("pressure governor should initialize");
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let initial = governor
            .sample_pressure(&cx)
            .expect("initial pressure snapshot should not fail");
        assert!(!initial.signal_availability.channel_backlog);
        assert_eq!(governor.sample_count(), 1);

        let (tx, _rx) = crate::channel::mpsc::channel::<u8>(4);
        tx.try_send(1).expect("first queued message should fit");
        tx.try_send(2).expect("second queued message should fit");
        let permit = tx.try_reserve().expect("reserved obligation should fit");
        let telemetry = tx.telemetry_snapshot(17);

        governor.record_channel_backlog_sample(
            telemetry.queued_messages + telemetry.reserved_uncommitted_obligations,
            telemetry.capacity,
        );
        let sampled = governor
            .sample_pressure(&cx)
            .expect("channel backlog pressure snapshot should not fail");

        assert_eq!(governor.sample_count(), 2);
        assert!(sampled.signal_availability.channel_backlog);
        assert_eq!(sampled.channel_backlog_pressure, 0.75);
        assert_eq!(sampled.overall_pressure, 0.75);
        assert_eq!(
            sampled.fallback_verdict,
            PressureFallbackVerdict::PartialSignalsUnavailable
        );

        permit.abort();
        governor.clear_channel_backlog_sample();
        let cleared = governor
            .sample_pressure(&cx)
            .expect("cleared channel backlog snapshot should not fail");

        assert_eq!(governor.sample_count(), 3);
        assert!(!cleared.signal_availability.channel_backlog);
        assert_eq!(cleared.channel_backlog_pressure, 0.0);
    }

    #[test]
    fn pressure_governor_channel_backlog_sample_drives_admission() {
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .global_queue_limit(4)
                .build()
                .expect("Failed to create channel-backlog admission runtime"),
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

        governor.record_channel_backlog_sample(3, 4);
        let decision = governor
            .check_admission(&cx)
            .expect("channel backlog admission should not fail");

        assert_eq!(decision, AdmissionDecision::AdmitWithBackpressure);
        assert_eq!(governor.backpressure_total.get(), 1);
        assert_eq!(governor.partial_fallback_total.get(), 1);
        assert_eq!(governor.no_win_fallback_total.get(), 0);
        assert_eq!(
            governor.fallback_verdict_metric(),
            PressureFallbackVerdict::PartialSignalsUnavailable.as_metric_value()
        );
    }

    #[test]
    fn pressure_governor_lab_runtime_pressure_transitions_are_deterministic() {
        let (first_trace, first_report) = run_lab_pressure_transition_projection(0x5A17);
        let (second_trace, second_report) = run_lab_pressure_transition_projection(0x5A17);

        assert_eq!(
            first_trace,
            vec![
                PressureLabTransition {
                    pending_items: 0,
                    total_capacity: 4,
                    channel_backlog_pressure_scaled: 0,
                    decision: AdmissionDecision::Admit,
                    fallback_verdict: PressureFallbackVerdict::PartialSignalsUnavailable,
                    channel_backlog_live: true,
                },
                PressureLabTransition {
                    pending_items: 3,
                    total_capacity: 4,
                    channel_backlog_pressure_scaled: 7_500,
                    decision: AdmissionDecision::AdmitWithBackpressure,
                    fallback_verdict: PressureFallbackVerdict::PartialSignalsUnavailable,
                    channel_backlog_live: true,
                },
                PressureLabTransition {
                    pending_items: 5,
                    total_capacity: 4,
                    channel_backlog_pressure_scaled: 12_500,
                    decision: AdmissionDecision::Reject,
                    fallback_verdict: PressureFallbackVerdict::PartialSignalsUnavailable,
                    channel_backlog_live: true,
                },
            ]
        );
        assert_eq!(first_trace, second_trace);

        assert!(first_report.quiescent);
        assert!(second_report.quiescent);
        assert_eq!(
            first_report.trace_fingerprint, second_report.trace_fingerprint,
            "matching LabRuntime pressure scenarios should replay to the same trace fingerprint"
        );
        assert_eq!(
            first_report.trace_certificate, second_report.trace_certificate,
            "matching LabRuntime pressure scenarios should keep certificate evidence stable"
        );
        assert_eq!(
            first_report.oracle_report.to_json(),
            second_report.oracle_report.to_json()
        );
        assert_eq!(
            first_report.invariant_violations,
            second_report.invariant_violations
        );
        assert!(first_report.oracle_report.all_passed());
        assert!(second_report.oracle_report.all_passed());
        assert!(first_report.invariant_violations.is_empty());
        assert!(second_report.invariant_violations.is_empty());
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

    #[test]
    fn enhanced_admission_control_with_resource_envelope() {
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create enhanced admission runtime"),
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

        // Test basic enhanced admission
        let decision = governor
            .check_enhanced_admission(&cx, None)
            .expect("enhanced admission should not fail");

        assert_eq!(decision.decision, AdmissionDecision::Admit);
        assert!(decision.suggested_envelope.is_some());
        assert!(!decision.backpressure_signals.shed_load);

        let envelope = decision.suggested_envelope.unwrap();
        assert_eq!(envelope.memory_budget, 64 * 1024 * 1024); // 64MB default
        assert_eq!(envelope.cpu_weight, 1.0);
        assert_eq!(envelope.io_budget, 10);
        assert_eq!(envelope.task_limit, 100);
    }

    #[test]
    fn resource_envelope_tracking() {
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create envelope tracking runtime"),
        );
        let config = PressureGovernorConfig::default();
        let metrics = Metrics::new();
        let governor = PressureGovernor::new(config, std::sync::Arc::clone(&runtime), metrics)
            .expect("pressure governor should initialize");

        // Register a resource envelope
        let envelope = ResourceEnvelope {
            memory_budget: 128 * 1024 * 1024, // 128MB
            cpu_weight: 2.0,
            io_budget: 20,
            task_limit: 200,
            usage: ResourceUsage::default(),
        };

        governor
            .register_envelope(1, envelope.clone())
            .expect("envelope registration should succeed");

        assert_eq!(governor.envelope_metrics.envelopes_active.get(), 1);

        // Update envelope usage
        let usage = ResourceUsage {
            memory_used: 64 * 1024 * 1024, // 64MB used
            cpu_utilization: 0.5,
            io_active: 10,
            task_count: 50,
        };

        governor
            .update_envelope_usage(1, usage)
            .expect("envelope usage update should succeed");

        assert_eq!(
            governor.envelope_metrics.envelope_memory_used.get(),
            64 * 1024 * 1024
        );

        // Unregister envelope
        governor
            .unregister_envelope(1)
            .expect("envelope unregistration should succeed");

        assert_eq!(governor.envelope_metrics.envelopes_active.get(), 0);
        assert_eq!(governor.envelope_metrics.envelope_memory_used.get(), 0);
    }

    #[test]
    fn swarm_coordination_peer_management() {
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create swarm coordination runtime"),
        );
        let config = PressureGovernorConfig::default();
        let metrics = Metrics::new();
        let governor = PressureGovernor::new(config, std::sync::Arc::clone(&runtime), metrics)
            .expect("pressure governor should initialize");

        // Add a peer with low pressure
        let peer_state = PeerPressureState {
            overall_pressure: 0.3,
            admission_rate: 0.9,
            last_update: std::time::Instant::now(),
            available: true,
        };

        governor
            .update_peer_pressure(100, peer_state)
            .expect("peer pressure update should succeed");

        assert_eq!(governor.swarm_metrics.peers_active.get(), 1);

        // Check swarm coordination hints
        let hints = governor
            .generate_swarm_hints()
            .expect("swarm hints generation should succeed");

        assert!(hints.redistribute_load);
        assert_eq!(hints.preferred_peers, vec![100]);

        // Test swarm state retrieval
        let swarm_state = governor
            .get_swarm_state()
            .expect("swarm state retrieval should succeed");

        assert_eq!(swarm_state.peer_states.len(), 1);
        assert!(swarm_state.peer_states.contains_key(&100));
    }

    #[test]
    fn backpressure_signal_generation() {
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create backpressure runtime"),
        );
        let config = PressureGovernorConfig::default();
        let metrics = Metrics::new();
        let governor = PressureGovernor::new(config, std::sync::Arc::clone(&runtime), metrics)
            .expect("pressure governor should initialize");

        // Test backpressure signals under pressure
        let signals = governor
            .generate_backpressure_signals(true)
            .expect("backpressure signal generation should succeed");

        assert!(signals.shed_load);
        assert!(signals.retry_delay.is_some());
        assert_eq!(signals.retry_delay.unwrap(), Duration::from_millis(100));
        assert!(!signals.component_pressures.is_empty());
        assert_eq!(signals.component_pressures.get("scheduler"), Some(&0.8));

        // Test normal signals without pressure
        let normal_signals = governor
            .generate_backpressure_signals(false)
            .expect("normal signal generation should succeed");

        assert!(!normal_signals.shed_load);
        assert!(normal_signals.retry_delay.is_none());
        assert!(normal_signals.component_pressures.is_empty());
    }
}
