//! Swarm-aware admission control and resource envelope management.
//!
//! This module implements production-ready swarm pressure governance by combining
//! the existing pressure governor with resource monitoring and cross-runtime
//! coordination. It provides:
//!
//! - **Admission Control**: Enforced region creation throttling
//! - **Resource Envelopes**: Budget tracking and enforcement
//! - **Backpressure Propagation**: Cross-component pressure signaling
//! - **Swarm Coordination**: Multi-runtime pressure awareness
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
//! │ Region Creation │───▶│ SwarmPressure    │───▶│ ResourceEnvelope│
//! │ Request         │    │ Governor         │    │ Enforcement     │
//! └─────────────────┘    └──────────────────┘    └─────────────────┘
//!                               │
//!                               ▼
//!                        ┌──────────────────┐
//!                        │ Admission        │
//!                        │ Decision         │
//!                        └──────────────────┘
//! ```
//!
//! # Integration
//!
//! Integrates with existing runtime components:
//! - Builds on `PressureGovernor` for internal runtime pressure
//! - Uses `ResourceMonitor` for system-level resource tracking
//! - Enforces decisions in `RuntimeState::create_child_region()`
//! - Propagates pressure signals across swarm instances

use crate::cx::Cx;
use crate::error::Error;
use crate::observability::pressure_governor::{
    AdmissionDecision, PressureGovernor, PressureGovernorConfig, PressureSnapshot,
};
use crate::runtime::resource_monitor::{DegradationLevel, RegionPriority, ResourceMonitor};
use crate::types::{RegionId, id::next_bootstrap_region_id};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use thiserror::Error;

/// Errors specific to swarm pressure governance.
#[derive(Debug, Error)]
pub enum SwarmPressureError {
    /// Resource envelope budget exceeded.
    #[error("resource envelope budget exceeded: {resource} usage {current} exceeds limit {limit}")]
    EnvelopeBudgetExceeded {
        /// Budget class that exceeded its envelope.
        resource: String,
        /// Usage after applying the attempted reservation.
        current: u64,
        /// Configured maximum for the resource envelope.
        limit: u64,
    },

    /// Swarm coordination failed.
    #[error("swarm coordination error: {reason}")]
    SwarmCoordinationFailed {
        /// Coordination failure detail.
        reason: String,
    },

    /// Admission rejected due to pressure.
    #[error("admission rejected: {reason}")]
    AdmissionRejected {
        /// Human-readable rejection reason.
        reason: String,
    },

    /// Underlying pressure governor error.
    #[error("pressure governor error: {0}")]
    PressureGovernor(#[from] Error),
}

/// Resource envelope tracking for a region.
#[derive(Debug, Clone)]
pub struct ResourceEnvelope {
    /// Region this envelope tracks.
    pub region_id: RegionId,
    /// Memory budget in bytes.
    pub memory_budget: u64,
    /// Current memory usage in bytes.
    pub memory_used: Arc<AtomicU64>,
    /// CPU budget in nanoseconds per second.
    pub cpu_budget_ns_per_sec: u64,
    /// Current CPU usage tracking.
    pub cpu_used_ns: Arc<AtomicU64>,
    /// IO budget in operations per second.
    pub io_budget_ops_per_sec: u64,
    /// Current IO operations count.
    pub io_ops_used: Arc<AtomicU64>,
    /// Envelope creation timestamp.
    pub created_at: Instant,
}

impl ResourceEnvelope {
    /// Creates a new resource envelope for the given region.
    pub fn new(
        region_id: RegionId,
        memory_budget: u64,
        cpu_budget_ns_per_sec: u64,
        io_budget_ops_per_sec: u64,
    ) -> Self {
        Self {
            region_id,
            memory_budget,
            memory_used: Arc::new(AtomicU64::new(0)),
            cpu_budget_ns_per_sec,
            cpu_used_ns: Arc::new(AtomicU64::new(0)),
            io_budget_ops_per_sec,
            io_ops_used: Arc::new(AtomicU64::new(0)),
            created_at: Instant::now(),
        }
    }

    /// Checks if the envelope has sufficient budget for the requested allocation.
    pub fn check_memory_budget(&self, requested: u64) -> Result<(), SwarmPressureError> {
        check_envelope_budget(
            "memory",
            self.memory_used.load(Ordering::Relaxed),
            requested,
            self.memory_budget,
        )
    }

    /// Reserves memory from the envelope budget.
    pub fn reserve_memory(&self, amount: u64) -> Result<(), SwarmPressureError> {
        self.check_memory_budget(amount)?;
        self.memory_used.fetch_add(amount, Ordering::Relaxed);
        Ok(())
    }

    /// Releases memory back to the envelope budget.
    pub fn release_memory(&self, amount: u64) {
        let current = self.memory_used.load(Ordering::Relaxed);
        let new_value = current.saturating_sub(amount);
        self.memory_used.store(new_value, Ordering::Relaxed);
    }

    /// Returns current memory utilization as a ratio (0.0 to 1.0+).
    pub fn memory_utilization(&self) -> f64 {
        if self.memory_budget == 0 {
            return 0.0;
        }
        let used = self.memory_used.load(Ordering::Relaxed);
        used as f64 / self.memory_budget as f64
    }

    /// Checks if the envelope has sufficient CPU budget for the requested nanoseconds.
    pub fn check_cpu_budget(&self, requested_ns: u64) -> Result<(), SwarmPressureError> {
        check_envelope_budget(
            "cpu",
            self.cpu_used_ns.load(Ordering::Relaxed),
            requested_ns,
            self.cpu_budget_ns_per_sec,
        )
    }

    /// Reserves CPU nanoseconds from this envelope's per-second budget.
    pub fn reserve_cpu(&self, amount_ns: u64) -> Result<(), SwarmPressureError> {
        self.check_cpu_budget(amount_ns)?;
        self.cpu_used_ns.fetch_add(amount_ns, Ordering::Relaxed);
        Ok(())
    }

    /// Releases CPU nanoseconds back to the envelope budget.
    pub fn release_cpu(&self, amount_ns: u64) {
        let current = self.cpu_used_ns.load(Ordering::Relaxed);
        self.cpu_used_ns
            .store(current.saturating_sub(amount_ns), Ordering::Relaxed);
    }

    /// Returns current CPU utilization as a ratio (0.0 to 1.0+).
    pub fn cpu_utilization(&self) -> f64 {
        if self.cpu_budget_ns_per_sec == 0 {
            return 0.0;
        }
        let used = self.cpu_used_ns.load(Ordering::Relaxed);
        used as f64 / self.cpu_budget_ns_per_sec as f64
    }

    /// Checks if the envelope has sufficient IO budget for the requested operations.
    pub fn check_io_budget(&self, requested_ops: u64) -> Result<(), SwarmPressureError> {
        check_envelope_budget(
            "io",
            self.io_ops_used.load(Ordering::Relaxed),
            requested_ops,
            self.io_budget_ops_per_sec,
        )
    }

    /// Reserves IO operations from this envelope's per-second budget.
    pub fn reserve_io(&self, amount_ops: u64) -> Result<(), SwarmPressureError> {
        self.check_io_budget(amount_ops)?;
        self.io_ops_used.fetch_add(amount_ops, Ordering::Relaxed);
        Ok(())
    }

    /// Releases IO operations back to the envelope budget.
    pub fn release_io(&self, amount_ops: u64) {
        let current = self.io_ops_used.load(Ordering::Relaxed);
        self.io_ops_used
            .store(current.saturating_sub(amount_ops), Ordering::Relaxed);
    }

    /// Returns current IO utilization as a ratio (0.0 to 1.0+).
    pub fn io_utilization(&self) -> f64 {
        if self.io_budget_ops_per_sec == 0 {
            return 0.0;
        }
        let used = self.io_ops_used.load(Ordering::Relaxed);
        used as f64 / self.io_budget_ops_per_sec as f64
    }
}

fn check_envelope_budget(
    resource: &str,
    current: u64,
    requested: u64,
    limit: u64,
) -> Result<(), SwarmPressureError> {
    let next = current.saturating_add(requested);
    if next > limit {
        return Err(SwarmPressureError::EnvelopeBudgetExceeded {
            resource: resource.to_string(),
            current: next,
            limit,
        });
    }
    Ok(())
}

/// Configuration for swarm pressure governance.
#[derive(Debug, Clone)]
pub struct SwarmPressureGovernorConfig {
    /// Enable swarm pressure governance.
    pub enabled: bool,
    /// Underlying pressure governor configuration.
    pub pressure_config: PressureGovernorConfig,
    /// Maximum regions per swarm instance.
    pub max_regions_per_instance: usize,
    /// Default memory budget per region in bytes.
    pub default_memory_budget_bytes: u64,
    /// Default CPU budget per region in nanoseconds per second.
    pub default_cpu_budget_ns_per_sec: u64,
    /// Default IO budget per region in operations per second.
    pub default_io_budget_ops_per_sec: u64,
    /// Envelope budget enforcement enabled.
    pub envelope_enforcement_enabled: bool,
    /// Swarm coordination timeout.
    pub swarm_coordination_timeout: Duration,
}

impl Default for SwarmPressureGovernorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            pressure_config: PressureGovernorConfig::default(),
            max_regions_per_instance: 1000,
            default_memory_budget_bytes: 100 * 1024 * 1024, // 100MB per region
            default_cpu_budget_ns_per_sec: 100_000_000,     // 100ms per second
            default_io_budget_ops_per_sec: 1000,            // 1000 ops per second
            envelope_enforcement_enabled: true,
            swarm_coordination_timeout: Duration::from_millis(50),
        }
    }
}

/// Enhanced admission decision with resource envelope information.
#[derive(Debug, Clone)]
pub struct SwarmAdmissionDecision {
    /// Core admission decision.
    pub decision: AdmissionDecision,
    /// Resource envelope for the admitted region (if approved).
    pub envelope: Option<ResourceEnvelope>,
    /// Pressure snapshot at decision time.
    pub pressure_snapshot: PressureSnapshot,
    /// System degradation level at decision time.
    pub degradation_level: DegradationLevel,
    /// Decision latency in nanoseconds.
    pub decision_latency_ns: u64,
    /// Reason for the decision.
    pub reason: String,
}

/// Swarm-aware pressure governor with resource envelope management.
pub struct SwarmPressureGovernor {
    config: SwarmPressureGovernorConfig,
    pressure_governor: PressureGovernor,
    resource_monitor: Arc<ResourceMonitor>,

    // Metrics
    total_admission_checks: AtomicU64,
    regions_admitted: AtomicU64,
    regions_rejected: AtomicU64,
    envelope_budget_violations: AtomicU64,

    // Resource envelope tracking
    active_regions: std::sync::Mutex<std::collections::HashMap<RegionId, ResourceEnvelope>>,
}

impl SwarmPressureGovernor {
    /// Creates a new swarm pressure governor.
    pub fn new(
        config: SwarmPressureGovernorConfig,
        resource_monitor: Arc<ResourceMonitor>,
        pressure_governor: PressureGovernor,
    ) -> Self {
        Self {
            config,
            pressure_governor,
            resource_monitor,
            total_admission_checks: AtomicU64::new(0),
            regions_admitted: AtomicU64::new(0),
            regions_rejected: AtomicU64::new(0),
            envelope_budget_violations: AtomicU64::new(0),
            active_regions: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Make a comprehensive admission decision for a new region.
    pub fn check_region_admission(
        &self,
        cx: &Cx,
        priority: RegionPriority,
        requested_memory: Option<u64>,
    ) -> Result<SwarmAdmissionDecision, SwarmPressureError> {
        let decision_start = Instant::now();
        self.total_admission_checks.fetch_add(1, Ordering::Relaxed);

        if !self.config.enabled {
            // Swarm governance disabled, always admit with default envelope
            let envelope = self.create_default_envelope(next_bootstrap_region_id())?;
            return Ok(SwarmAdmissionDecision {
                decision: AdmissionDecision::Admit,
                envelope: Some(envelope),
                pressure_snapshot: self.get_default_pressure_snapshot(),
                degradation_level: DegradationLevel::None,
                decision_latency_ns: decision_start.elapsed().as_nanos() as u64,
                reason: "Swarm governance disabled".to_string(),
            });
        }

        // Check system-level resource pressure
        let degradation_level = self
            .resource_monitor
            .pressure()
            .composite_degradation_level();

        // Check runtime-internal pressure via pressure governor
        let pressure_snapshot = self.pressure_governor.sample_pressure(cx)?;
        let pressure_decision = self.pressure_governor.check_admission(cx)?;

        if let Some(requested_memory) = requested_memory
            && self.config.envelope_enforcement_enabled
            && requested_memory > self.config.default_memory_budget_bytes
        {
            self.regions_rejected.fetch_add(1, Ordering::Relaxed);
            self.envelope_budget_violations
                .fetch_add(1, Ordering::Relaxed);
            return Ok(SwarmAdmissionDecision {
                decision: AdmissionDecision::Reject,
                envelope: None,
                pressure_snapshot,
                degradation_level,
                decision_latency_ns: decision_start.elapsed().as_nanos() as u64,
                reason: format!(
                    "Requested memory {requested_memory} exceeds region envelope budget {}",
                    self.config.default_memory_budget_bytes
                ),
            });
        }

        // Apply swarm-specific logic
        let swarm_decision = self.evaluate_swarm_admission(
            priority,
            &pressure_decision,
            degradation_level,
            requested_memory,
        )?;

        // Create resource envelope if admitted
        let envelope = if matches!(
            swarm_decision.decision,
            AdmissionDecision::Admit | AdmissionDecision::AdmitWithBackpressure
        ) {
            let region_id = next_bootstrap_region_id(); // Will be filled in by caller
            Some(self.create_envelope_for_region(region_id, requested_memory)?)
        } else {
            None
        };

        // Update metrics
        match swarm_decision.decision {
            AdmissionDecision::Admit => {
                self.regions_admitted.fetch_add(1, Ordering::Relaxed);
            }
            AdmissionDecision::Reject => {
                self.regions_rejected.fetch_add(1, Ordering::Relaxed);
            }
            AdmissionDecision::AdmitWithBackpressure => {
                self.regions_admitted.fetch_add(1, Ordering::Relaxed);
            }
        }

        Ok(SwarmAdmissionDecision {
            decision: swarm_decision.decision,
            envelope,
            pressure_snapshot,
            degradation_level,
            decision_latency_ns: decision_start.elapsed().as_nanos() as u64,
            reason: swarm_decision.reason,
        })
    }

    /// Register a resource envelope for an active region.
    pub fn register_region_envelope(&self, region_id: RegionId, envelope: ResourceEnvelope) {
        let mut envelopes = self.active_regions.lock().unwrap();
        envelopes.insert(region_id, envelope);
    }

    /// Remove a region's resource envelope when the region closes.
    pub fn unregister_region_envelope(&self, region_id: RegionId) -> Option<ResourceEnvelope> {
        let mut envelopes = self.active_regions.lock().unwrap();
        envelopes.remove(&region_id)
    }

    /// Get resource envelope for a region.
    pub fn get_region_envelope(&self, region_id: RegionId) -> Option<ResourceEnvelope> {
        let envelopes = self.active_regions.lock().unwrap();
        envelopes.get(&region_id).cloned()
    }

    /// Returns current swarm governance metrics.
    pub fn metrics(&self) -> SwarmPressureMetrics {
        let envelopes = self.active_regions.lock().unwrap();
        SwarmPressureMetrics {
            total_admission_checks: self.total_admission_checks.load(Ordering::Relaxed),
            regions_admitted: self.regions_admitted.load(Ordering::Relaxed),
            regions_rejected: self.regions_rejected.load(Ordering::Relaxed),
            envelope_budget_violations: self.envelope_budget_violations.load(Ordering::Relaxed),
            active_region_count: envelopes.len() as u64,
        }
    }

    // Private helper methods

    fn evaluate_swarm_admission(
        &self,
        priority: RegionPriority,
        pressure_decision: &AdmissionDecision,
        degradation_level: DegradationLevel,
        _requested_memory: Option<u64>,
    ) -> Result<SwarmAdmissionDecisionInternal, SwarmPressureError> {
        // Check region count limits
        let active_count = {
            let envelopes = self.active_regions.lock().unwrap();
            envelopes.len()
        };

        if active_count >= self.config.max_regions_per_instance {
            return Ok(SwarmAdmissionDecisionInternal {
                decision: AdmissionDecision::Reject,
                reason: format!(
                    "Region limit exceeded: {} >= {}",
                    active_count, self.config.max_regions_per_instance
                ),
            });
        }

        // Combine pressure governor decision with system degradation
        let decision = match (pressure_decision, degradation_level, priority) {
            // Always admit critical regions regardless of pressure
            (_, _, RegionPriority::Critical) => AdmissionDecision::Admit,

            // Reject if pressure governor rejected and system is under stress
            (
                AdmissionDecision::Reject,
                DegradationLevel::Heavy | DegradationLevel::Emergency,
                _,
            ) => AdmissionDecision::Reject,

            // Apply backpressure for moderate system stress
            (_, DegradationLevel::Moderate | DegradationLevel::Heavy, RegionPriority::Normal) => {
                AdmissionDecision::AdmitWithBackpressure
            }

            // Reject low-priority regions under any stress
            (
                _,
                DegradationLevel::Moderate | DegradationLevel::Heavy | DegradationLevel::Emergency,
                RegionPriority::Low | RegionPriority::BestEffort,
            ) => AdmissionDecision::Reject,

            // Otherwise follow pressure governor decision
            (decision, _, _) => *decision,
        };

        let reason = match decision {
            AdmissionDecision::Admit => "Admission approved".to_string(),
            AdmissionDecision::Reject => format!(
                "Rejected due to pressure: {:?} degradation, {:?} priority",
                degradation_level, priority
            ),
            AdmissionDecision::AdmitWithBackpressure => format!(
                "Admitted with backpressure: {:?} degradation",
                degradation_level
            ),
        };

        Ok(SwarmAdmissionDecisionInternal { decision, reason })
    }

    fn create_envelope_for_region(
        &self,
        region_id: RegionId,
        requested_memory: Option<u64>,
    ) -> Result<ResourceEnvelope, SwarmPressureError> {
        let memory_budget = if self.config.envelope_enforcement_enabled {
            self.config.default_memory_budget_bytes
        } else {
            requested_memory.unwrap_or(self.config.default_memory_budget_bytes)
        };

        Ok(ResourceEnvelope::new(
            region_id,
            memory_budget,
            self.config.default_cpu_budget_ns_per_sec,
            self.config.default_io_budget_ops_per_sec,
        ))
    }

    fn create_default_envelope(
        &self,
        region_id: RegionId,
    ) -> Result<ResourceEnvelope, SwarmPressureError> {
        self.create_envelope_for_region(region_id, None)
    }

    fn get_default_pressure_snapshot(&self) -> PressureSnapshot {
        // Create a default snapshot when pressure governance is disabled
        PressureSnapshot {
            timestamp: Instant::now(),
            runnable_queue_pressure: 0.0,
            blocking_pool_pressure: 0.0,
            channel_backlog_pressure: 0.0,
            cleanup_debt_pressure: 0.0,
            memory_budget_pressure: 0.0,
            overall_pressure: 0.0,
            signal_availability:
                crate::observability::pressure_governor::PressureSignalAvailability::NONE,
            fallback_verdict:
                crate::observability::pressure_governor::PressureFallbackVerdict::Complete,
        }
    }
}

#[derive(Debug)]
struct SwarmAdmissionDecisionInternal {
    decision: AdmissionDecision,
    reason: String,
}

/// Metrics for swarm pressure governance.
#[derive(Debug, Clone)]
pub struct SwarmPressureMetrics {
    /// Total admission checks performed.
    pub total_admission_checks: u64,
    /// Total regions admitted.
    pub regions_admitted: u64,
    /// Total regions rejected.
    pub regions_rejected: u64,
    /// Total envelope budget violations.
    pub envelope_budget_violations: u64,
    /// Number of active regions with envelopes.
    pub active_region_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observability::metrics::Metrics;
    use crate::runtime::RuntimeBuilder;
    use crate::types::Budget;

    fn create_test_swarm_governor() -> SwarmPressureGovernor {
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );

        let config = SwarmPressureGovernorConfig::default();
        let resource_monitor = runtime.resource_monitor();
        let pressure_governor = PressureGovernor::new(
            config.pressure_config.clone(),
            std::sync::Arc::clone(&runtime),
            Metrics::new(),
        )
        .expect("Failed to create pressure governor");

        SwarmPressureGovernor::new(config, resource_monitor, pressure_governor)
    }

    #[test]
    fn test_resource_envelope_budget_enforcement() {
        let envelope = ResourceEnvelope::new(RegionId::new_for_test(1, 1), 1000, 1000000, 100);

        // Should allow allocation within budget
        assert!(envelope.reserve_memory(500).is_ok());
        assert_eq!(envelope.memory_utilization(), 0.5);

        // Should reject allocation exceeding budget
        assert!(envelope.reserve_memory(600).is_err());

        // Should allow allocation after release
        envelope.release_memory(200);
        assert!(envelope.reserve_memory(400).is_ok());
        assert_eq!(envelope.memory_utilization(), 0.7);
    }

    #[test]
    fn test_resource_envelope_cpu_and_io_budget_enforcement() {
        let envelope = ResourceEnvelope::new(RegionId::new_for_test(1, 2), 1000, 100, 10);

        assert!(envelope.reserve_cpu(60).is_ok());
        assert_eq!(envelope.cpu_utilization(), 0.6);
        assert!(matches!(
            envelope.reserve_cpu(50),
            Err(SwarmPressureError::EnvelopeBudgetExceeded { resource, .. }) if resource == "cpu"
        ));
        envelope.release_cpu(25);
        assert!(envelope.reserve_cpu(40).is_ok());
        assert_eq!(envelope.cpu_utilization(), 0.75);

        assert!(envelope.reserve_io(7).is_ok());
        assert_eq!(envelope.io_utilization(), 0.7);
        assert!(matches!(
            envelope.reserve_io(4),
            Err(SwarmPressureError::EnvelopeBudgetExceeded { resource, .. }) if resource == "io"
        ));
        envelope.release_io(3);
        assert!(envelope.reserve_io(2).is_ok());
        assert_eq!(envelope.io_utilization(), 0.6);
    }

    #[test]
    fn test_swarm_governor_region_limits() {
        let mut config = SwarmPressureGovernorConfig::default();
        config.max_regions_per_instance = 2;

        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );

        let pressure_governor = PressureGovernor::new(
            config.pressure_config.clone(),
            std::sync::Arc::clone(&runtime),
            Metrics::new(),
        )
        .expect("Failed to create pressure governor");

        let governor =
            SwarmPressureGovernor::new(config, runtime.resource_monitor(), pressure_governor);

        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        // First two admissions should succeed
        let decision1 = governor
            .check_region_admission(&cx, RegionPriority::Normal, None)
            .expect("First admission should succeed");
        assert!(matches!(decision1.decision, AdmissionDecision::Admit));

        let decision2 = governor
            .check_region_admission(&cx, RegionPriority::Normal, None)
            .expect("Second admission should succeed");
        assert!(matches!(decision2.decision, AdmissionDecision::Admit));

        // Add envelopes to simulate active regions
        governor
            .register_region_envelope(RegionId::new_for_test(1, 1), decision1.envelope.unwrap());
        governor
            .register_region_envelope(RegionId::new_for_test(2, 1), decision2.envelope.unwrap());

        // Third admission should be rejected
        let decision3 = governor
            .check_region_admission(&cx, RegionPriority::Normal, None)
            .expect("Third admission check should succeed");
        assert!(matches!(decision3.decision, AdmissionDecision::Reject));
        assert!(decision3.reason.contains("Region limit exceeded"));
    }

    #[test]
    fn test_backpressure_admission_still_gets_resource_envelope() {
        let governor = create_test_swarm_governor();
        governor
            .resource_monitor
            .pressure()
            .update_degradation_level(
                crate::runtime::resource_monitor::ResourceType::Memory,
                DegradationLevel::Moderate,
            );

        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let decision = governor
            .check_region_admission(&cx, RegionPriority::Normal, Some(1024))
            .expect("Backpressure admission should produce a decision");

        assert!(matches!(
            decision.decision,
            AdmissionDecision::AdmitWithBackpressure
        ));
        let envelope = decision
            .envelope
            .expect("backpressure admission still admits work and must return an envelope");
        assert_eq!(
            envelope.memory_budget,
            governor.config.default_memory_budget_bytes
        );

        governor.register_region_envelope(envelope.region_id, envelope);
        assert_eq!(governor.metrics().active_region_count, 1);
    }

    #[test]
    fn test_requested_memory_over_envelope_budget_rejects_admission() {
        let mut config = SwarmPressureGovernorConfig::default();
        config.default_memory_budget_bytes = 1024;

        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let pressure_governor = PressureGovernor::new(
            config.pressure_config.clone(),
            std::sync::Arc::clone(&runtime),
            Metrics::new(),
        )
        .expect("Failed to create pressure governor");
        let governor =
            SwarmPressureGovernor::new(config, runtime.resource_monitor(), pressure_governor);
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let decision = governor
            .check_region_admission(&cx, RegionPriority::Normal, Some(1025))
            .expect("Oversized request should be represented as an admission rejection");

        assert!(matches!(decision.decision, AdmissionDecision::Reject));
        assert!(decision.envelope.is_none());
        assert!(decision.reason.contains("exceeds region envelope budget"));
        let metrics = governor.metrics();
        assert_eq!(metrics.regions_rejected, 1);
        assert_eq!(metrics.envelope_budget_violations, 1);
    }

    #[test]
    fn test_critical_priority_always_admitted() {
        let governor = create_test_swarm_governor();
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let decision = governor
            .check_region_admission(&cx, RegionPriority::Critical, None)
            .expect("Critical admission should succeed");

        assert!(matches!(decision.decision, AdmissionDecision::Admit));
        assert_eq!(decision.reason, "Admission approved");
    }
}
