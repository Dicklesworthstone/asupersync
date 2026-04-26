//! Resource monitoring and degradation trigger system.
//!
//! This module provides comprehensive resource monitoring, degradation triggers,
//! and load shedding decisions for the asupersync runtime. It tracks memory usage,
//! file descriptors, CPU load, network connections, and custom resource types,
//! then triggers degradation policies when thresholds are exceeded.
//!
//! # Architecture
//!
//! - [`ResourceMonitor`] - Central monitoring coordinator
//! - [`DegradationEngine`] - Decision engine for resource reclamation
//! - [`TriggerConfig`] - Configurable thresholds and hysteresis
//! - [`ResourcePressure`] - Multi-dimensional pressure tracking
//!
//! # Integration
//!
//! The monitor integrates with existing runtime components:
//! - Region creation checks resource availability
//! - Scheduler responds to CPU pressure
//! - IO driver handles file descriptor pressure
//! - Memory allocators trigger on heap pressure

#![allow(missing_docs)]

use crate::types::RegionId;
use crate::types::pressure::SystemPressure;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use thiserror::Error;

/// Errors that can occur during resource monitoring.
#[derive(Debug, Error)]
pub enum ResourceMonitorError {
    /// Resource type is not registered.
    #[error("unknown resource type: {resource_type}")]
    UnknownResourceType { resource_type: String },

    /// Monitoring is already active.
    #[error("resource monitoring is already active")]
    AlreadyActive,

    /// System resource access failed.
    #[error("failed to access system resource: {reason}")]
    SystemAccessFailed { reason: String },

    /// Configuration is invalid.
    #[error("invalid configuration: {details}")]
    InvalidConfig { details: String },

    /// Degradation engine is not ready.
    #[error("degradation engine not initialized")]
    EngineNotReady,
}

/// Resource types tracked by the monitor.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResourceType {
    /// Physical memory (heap allocations).
    Memory,
    /// File descriptors and handles.
    FileDescriptors,
    /// CPU load and scheduler queue depth.
    CpuLoad,
    /// Network connections and sockets.
    NetworkConnections,
    /// Runtime tasks and their associated resources.
    Task,
    /// Custom application-defined resource.
    Custom(String),
}

impl std::fmt::Display for ResourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Memory => write!(f, "memory"),
            Self::FileDescriptors => write!(f, "file_descriptors"),
            Self::CpuLoad => write!(f, "cpu_load"),
            Self::NetworkConnections => write!(f, "network_connections"),
            Self::Task => write!(f, "task"),
            Self::Custom(name) => write!(f, "custom:{name}"),
        }
    }
}

/// Resource usage measurement with limits.
#[derive(Debug, Clone)]
pub struct ResourceMeasurement {
    /// Current usage value.
    pub current: u64,
    /// Soft limit (warning threshold).
    pub soft_limit: u64,
    /// Hard limit (critical threshold).
    pub hard_limit: u64,
    /// Maximum theoretical limit.
    pub max_limit: u64,
    /// Timestamp of measurement.
    pub timestamp: Instant,
}

impl ResourceMeasurement {
    /// Create a new measurement.
    #[must_use]
    pub fn new(current: u64, soft_limit: u64, hard_limit: u64, max_limit: u64) -> Self {
        Self {
            current,
            soft_limit,
            hard_limit,
            max_limit,
            timestamp: Instant::now(),
        }
    }

    /// Calculate usage percentage (0.0-1.0).
    #[must_use]
    pub fn usage_ratio(&self) -> f64 {
        if self.max_limit == 0 {
            return 0.0;
        }
        (self.current as f64) / (self.max_limit as f64)
    }

    /// Check if soft threshold is exceeded.
    #[must_use]
    pub fn is_soft_exceeded(&self) -> bool {
        self.current >= self.soft_limit
    }

    /// Check if hard threshold is exceeded.
    #[must_use]
    pub fn is_hard_exceeded(&self) -> bool {
        self.current >= self.hard_limit
    }

    /// Check if at critical level (near max limit).
    #[must_use]
    pub fn is_critical(&self) -> bool {
        self.current >= self.max_limit.saturating_sub(self.max_limit / 20) // Within 5% of max
    }
}

/// Degradation level indicating severity of resource pressure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DegradationLevel {
    /// No degradation needed.
    None = 0,
    /// Light load shedding (reject new low-priority work).
    Light = 1,
    /// Moderate load shedding (pause background tasks).
    Moderate = 2,
    /// Heavy degradation (cancel non-critical regions).
    Heavy = 3,
    /// Emergency shedding (cancel all non-essential work).
    Emergency = 4,
}

impl DegradationLevel {
    /// Convert to pressure headroom value (0.0-1.0).
    #[must_use]
    pub fn to_headroom(self) -> f32 {
        match self {
            Self::None => 1.0,
            Self::Light => 0.75,
            Self::Moderate => 0.5,
            Self::Heavy => 0.25,
            Self::Emergency => 0.0,
        }
    }

    /// Convert from pressure headroom value.
    #[must_use]
    pub fn from_headroom(headroom: f32) -> Self {
        if headroom > 0.875 {
            Self::None
        } else if headroom > 0.625 {
            Self::Light
        } else if headroom > 0.375 {
            Self::Moderate
        } else if headroom > 0.125 {
            Self::Heavy
        } else {
            Self::Emergency
        }
    }
}

/// Configuration for resource monitoring thresholds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerConfig {
    /// Warning threshold (0.0-1.0 of max capacity).
    pub soft_threshold: f64,
    /// Critical threshold (0.0-1.0 of max capacity).
    pub hard_threshold: f64,
    /// Hysteresis margin to prevent oscillation (0.0-1.0).
    pub hysteresis: f64,
    /// Minimum time between degradation level changes.
    pub cooldown: Duration,
    /// Whether this resource type is enabled for monitoring.
    pub enabled: bool,
}

impl TriggerConfig {
    /// Create default trigger configuration.
    #[must_use]
    pub fn default_for_resource(resource_type: &ResourceType) -> Self {
        match resource_type {
            ResourceType::Memory => Self {
                soft_threshold: 0.70, // 70% memory usage
                hard_threshold: 0.85, // 85% memory usage
                hysteresis: 0.05,     // 5% margin
                cooldown: Duration::from_secs(5),
                enabled: true,
            },
            ResourceType::FileDescriptors => Self {
                soft_threshold: 0.75, // 75% of fd limit
                hard_threshold: 0.90, // 90% of fd limit
                hysteresis: 0.05,
                cooldown: Duration::from_secs(2),
                enabled: true,
            },
            ResourceType::CpuLoad => Self {
                soft_threshold: 0.80, // 80% CPU
                hard_threshold: 0.95, // 95% CPU
                hysteresis: 0.10,     // 10% margin (CPU can be spiky)
                cooldown: Duration::from_secs(3),
                enabled: true,
            },
            ResourceType::NetworkConnections => Self {
                soft_threshold: 0.70, // 70% of connection limit
                hard_threshold: 0.85, // 85% of connection limit
                hysteresis: 0.05,
                cooldown: Duration::from_secs(1),
                enabled: true,
            },
            ResourceType::Custom(_) => Self {
                soft_threshold: 0.75, // Conservative default
                hard_threshold: 0.90,
                hysteresis: 0.05,
                cooldown: Duration::from_secs(5),
                enabled: false, // Must be explicitly enabled
            },
            ResourceType::Task => Self {
                soft_threshold: 0.80, // 80% of task limit
                hard_threshold: 0.95, // 95% of task limit
                hysteresis: 0.05,
                cooldown: Duration::from_secs(1),
                enabled: true,
            },
        }
    }

    /// Calculate degradation level for a measurement.
    #[must_use]
    pub fn calculate_degradation(&self, measurement: &ResourceMeasurement) -> DegradationLevel {
        let usage_ratio = measurement.usage_ratio();

        if usage_ratio >= self.hard_threshold {
            // Check for emergency conditions
            if measurement.is_critical() {
                DegradationLevel::Emergency
            } else {
                DegradationLevel::Heavy
            }
        } else if usage_ratio >= self.soft_threshold {
            if usage_ratio >= (self.hard_threshold - self.hysteresis) {
                DegradationLevel::Moderate
            } else {
                DegradationLevel::Light
            }
        } else {
            DegradationLevel::None
        }
    }

    /// Apply hysteresis to prevent oscillation.
    #[must_use]
    pub fn apply_hysteresis(
        &self,
        new_level: DegradationLevel,
        current_level: DegradationLevel,
        last_change: Option<Instant>,
    ) -> DegradationLevel {
        // Respect cooldown period
        if let Some(last) = last_change {
            if last.elapsed() < self.cooldown {
                return current_level;
            }
        }

        // Allow immediate escalation for emergencies
        if new_level == DegradationLevel::Emergency {
            return new_level;
        }

        // Apply hysteresis for downgrades
        if new_level < current_level {
            // Only downgrade if we're well below the threshold
            let new_u8 = new_level as u8;
            let current_u8 = current_level as u8;
            if new_u8 <= current_u8.saturating_sub(1) {
                new_level
            } else {
                current_level
            }
        } else {
            new_level
        }
    }
}

/// Multi-dimensional resource pressure tracking.
#[derive(Debug, Default)]
pub struct ResourcePressure {
    /// Per-resource measurements.
    measurements: RwLock<HashMap<ResourceType, ResourceMeasurement>>,
    /// Per-resource degradation levels.
    degradation_levels: RwLock<HashMap<ResourceType, DegradationLevel>>,
    /// Last degradation level change timestamps.
    last_changes: RwLock<HashMap<ResourceType, Instant>>,
    /// Overall system pressure.
    system_pressure: Arc<SystemPressure>,
    /// Resource monitoring overhead counter.
    monitoring_overhead: AtomicU64,
}

impl ResourcePressure {
    /// Create new resource pressure tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            measurements: RwLock::new(HashMap::new()),
            degradation_levels: RwLock::new(HashMap::new()),
            last_changes: RwLock::new(HashMap::new()),
            system_pressure: Arc::new(SystemPressure::new()),
            monitoring_overhead: AtomicU64::new(0),
        }
    }

    /// Update measurement for a resource type.
    pub fn update_measurement(
        &self,
        resource_type: ResourceType,
        measurement: ResourceMeasurement,
    ) {
        let start = Instant::now();

        {
            let mut measurements = self.measurements.write();
            measurements.insert(resource_type, measurement);
        }

        // Update monitoring overhead tracking
        let elapsed_nanos = start.elapsed().as_nanos() as u64;
        self.monitoring_overhead
            .fetch_add(elapsed_nanos, Ordering::Relaxed);
    }

    /// Get current measurement for a resource type.
    pub fn get_measurement(&self, resource_type: &ResourceType) -> Option<ResourceMeasurement> {
        self.measurements.read().get(resource_type).cloned()
    }

    /// Update degradation level for a resource type.
    pub fn update_degradation_level(&self, resource_type: ResourceType, level: DegradationLevel) {
        let mut levels = self.degradation_levels.write();
        let mut changes = self.last_changes.write();

        levels.insert(resource_type.clone(), level);
        changes.insert(resource_type, Instant::now());

        // Update overall system pressure based on maximum degradation level
        let max_level = levels
            .values()
            .max()
            .copied()
            .unwrap_or(DegradationLevel::None);
        self.system_pressure.set_headroom(max_level.to_headroom());
    }

    /// Get current degradation level for a resource type.
    pub fn get_degradation_level(&self, resource_type: &ResourceType) -> DegradationLevel {
        self.degradation_levels
            .read()
            .get(resource_type)
            .copied()
            .unwrap_or(DegradationLevel::None)
    }

    /// Get overall system pressure.
    pub fn system_pressure(&self) -> Arc<SystemPressure> {
        Arc::clone(&self.system_pressure)
    }

    /// Get monitoring overhead in nanoseconds.
    pub fn monitoring_overhead_nanos(&self) -> u64 {
        self.monitoring_overhead.load(Ordering::Relaxed)
    }

    /// Calculate composite degradation level across all resources.
    pub fn composite_degradation_level(&self) -> DegradationLevel {
        let levels = self.degradation_levels.read();
        levels
            .values()
            .max()
            .copied()
            .unwrap_or(DegradationLevel::None)
    }
}

/// Region priority classification for degradation decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum RegionPriority {
    /// Critical system regions that must never be cancelled.
    Critical = 0,
    /// High priority user-facing work.
    High = 1,
    /// Normal priority work.
    #[default]
    Normal = 2,
    /// Low priority background work.
    Low = 3,
    /// Best-effort work that can be freely cancelled.
    BestEffort = 4,
}

/// Work shedding decision for a region.
#[derive(Debug, Clone)]
pub enum SheddingDecision {
    /// Keep the region running.
    Keep,
    /// Pause the region temporarily.
    Pause,
    /// Cancel the region gracefully.
    Cancel,
    /// Cancel the region immediately (emergency).
    ForceCancel,
}

/// Degradation decision engine for resource reclamation.
#[derive(Debug)]
pub struct DegradationEngine {
    /// Resource pressure tracker.
    pressure: Arc<ResourcePressure>,
    /// Trigger configuration per resource type.
    trigger_configs: RwLock<HashMap<ResourceType, TriggerConfig>>,
    /// Region priority mapping.
    region_priorities: RwLock<HashMap<RegionId, RegionPriority>>,
    /// Active degradation policies.
    active_policies: RwLock<HashMap<ResourceType, Vec<DegradationPolicy>>>,
    /// Statistics tracking.
    stats: DegradationStats,
}

/// Degradation policy for a specific resource type.
#[derive(Debug, Clone)]
pub struct DegradationPolicy {
    /// Resource type this policy applies to.
    pub resource_type: ResourceType,
    /// Degradation level that triggers this policy.
    pub trigger_level: DegradationLevel,
    /// Policy action to take.
    pub action: PolicyAction,
}

/// Actions that can be taken by degradation policies.
#[derive(Debug, Clone)]
pub enum PolicyAction {
    /// Reject new work of specified priority or lower.
    RejectNewWork(RegionPriority),
    /// Cancel regions of specified priority or lower.
    CancelRegions(RegionPriority),
    /// Pause regions of specified priority or lower.
    PauseRegions(RegionPriority),
    /// Reduce resource limits for new allocations.
    ReduceLimits { factor: f64 },
    /// Custom action with callback.
    Custom { name: String },
}

/// Statistics for degradation engine operations.
#[derive(Debug, Default)]
pub struct DegradationStats {
    /// Number of degradation triggers fired.
    triggers_fired: AtomicU64,
    /// Number of regions cancelled due to degradation.
    regions_cancelled: AtomicU64,
    /// Number of regions paused due to degradation.
    regions_paused: AtomicU64,
    /// Number of new work requests rejected.
    requests_rejected: AtomicU64,
    /// Total time spent in degradation decisions.
    decision_time_nanos: AtomicU64,
}

impl DegradationEngine {
    /// Create a new degradation engine.
    pub fn new(pressure: Arc<ResourcePressure>) -> Self {
        let mut trigger_configs = HashMap::new();

        // Install default configurations for built-in resource types
        for resource_type in [
            ResourceType::Memory,
            ResourceType::FileDescriptors,
            ResourceType::CpuLoad,
            ResourceType::NetworkConnections,
            ResourceType::Task,
        ] {
            trigger_configs.insert(
                resource_type.clone(),
                TriggerConfig::default_for_resource(&resource_type),
            );
        }

        Self {
            pressure,
            trigger_configs: RwLock::new(trigger_configs),
            region_priorities: RwLock::new(HashMap::new()),
            active_policies: RwLock::new(HashMap::new()),
            stats: DegradationStats::default(),
        }
    }

    /// Register a custom resource type with configuration.
    pub fn register_resource_type(
        &self,
        resource_type: ResourceType,
        config: TriggerConfig,
    ) -> Result<(), ResourceMonitorError> {
        let mut configs = self.trigger_configs.write();
        configs.insert(resource_type, config);
        Ok(())
    }

    /// Set priority for a region.
    pub fn set_region_priority(&self, region_id: RegionId, priority: RegionPriority) {
        let mut priorities = self.region_priorities.write();
        priorities.insert(region_id, priority);
    }

    /// Add a degradation policy for a resource type.
    pub fn add_policy(&self, policy: DegradationPolicy) {
        let mut policies = self.active_policies.write();
        policies
            .entry(policy.resource_type.clone())
            .or_default()
            .push(policy);
    }

    /// Process resource measurements and trigger degradation if needed.
    pub fn process_measurements(
        &self,
    ) -> Result<Vec<(ResourceType, DegradationLevel)>, ResourceMonitorError> {
        let start = Instant::now();
        let mut triggered_changes = Vec::new();

        let configs = self.trigger_configs.read();

        for (resource_type, config) in configs.iter() {
            if !config.enabled {
                continue;
            }

            if let Some(measurement) = self.pressure.get_measurement(resource_type) {
                let new_level = config.calculate_degradation(&measurement);
                let current_level = self.pressure.get_degradation_level(resource_type);

                let last_change = self
                    .pressure
                    .last_changes
                    .read()
                    .get(resource_type)
                    .copied();

                let final_level = config.apply_hysteresis(new_level, current_level, last_change);

                if final_level != current_level {
                    self.pressure
                        .update_degradation_level(resource_type.clone(), final_level);
                    triggered_changes.push((resource_type.clone(), final_level));

                    self.stats.triggers_fired.fetch_add(1, Ordering::Relaxed);

                    // Apply policies for this degradation level
                    self.apply_policies(resource_type, final_level)?;
                }
            }
        }

        let elapsed_nanos = start.elapsed().as_nanos() as u64;
        self.stats
            .decision_time_nanos
            .fetch_add(elapsed_nanos, Ordering::Relaxed);

        Ok(triggered_changes)
    }

    /// Apply degradation policies for a resource type and level.
    fn apply_policies(
        &self,
        resource_type: &ResourceType,
        level: DegradationLevel,
    ) -> Result<(), ResourceMonitorError> {
        let policies = self.active_policies.read();

        if let Some(resource_policies) = policies.get(resource_type) {
            for policy in resource_policies {
                if level >= policy.trigger_level {
                    self.execute_policy_action(&policy.action, level)?;
                }
            }
        }

        Ok(())
    }

    /// Execute a specific policy action.
    fn execute_policy_action(
        &self,
        action: &PolicyAction,
        _level: DegradationLevel,
    ) -> Result<(), ResourceMonitorError> {
        match action {
            PolicyAction::RejectNewWork(_priority_threshold) => {
                // This would integrate with the runtime's region creation logic
                // to reject new work below the priority threshold
                self.stats.requests_rejected.fetch_add(1, Ordering::Relaxed);
            }
            PolicyAction::CancelRegions(_priority_threshold) => {
                // This would integrate with the runtime to cancel regions
                // below the priority threshold
                self.stats.regions_cancelled.fetch_add(1, Ordering::Relaxed);
            }
            PolicyAction::PauseRegions(_priority_threshold) => {
                // This would integrate with the scheduler to pause regions
                // below the priority threshold
                self.stats.regions_paused.fetch_add(1, Ordering::Relaxed);
            }
            PolicyAction::ReduceLimits { factor: _ } => {
                // This would reduce resource allocation limits
                // by the specified factor
            }
            PolicyAction::Custom { name: _name } => {
                // Custom actions would be handled by registered callbacks
            }
        }

        Ok(())
    }

    /// Decide what to do with a specific region during degradation.
    pub fn should_shed_region(&self, region_id: RegionId) -> SheddingDecision {
        let composite_level = self.pressure.composite_degradation_level();
        let priorities = self.region_priorities.read();
        let region_priority = priorities.get(&region_id).copied().unwrap_or_default();

        match (composite_level, region_priority) {
            (DegradationLevel::Emergency, RegionPriority::BestEffort) => {
                SheddingDecision::ForceCancel
            }
            (DegradationLevel::Emergency, RegionPriority::Low) => SheddingDecision::Cancel,
            (DegradationLevel::Emergency, RegionPriority::Normal) => SheddingDecision::Pause,
            (DegradationLevel::Emergency, _) => SheddingDecision::Keep,

            (DegradationLevel::Heavy, RegionPriority::BestEffort) => SheddingDecision::Cancel,
            (DegradationLevel::Heavy, RegionPriority::Low) => SheddingDecision::Pause,
            (DegradationLevel::Heavy, _) => SheddingDecision::Keep,

            (DegradationLevel::Moderate, RegionPriority::BestEffort) => SheddingDecision::Pause,
            (DegradationLevel::Moderate, _) => SheddingDecision::Keep,

            (DegradationLevel::Light, RegionPriority::BestEffort) => SheddingDecision::Pause,
            (DegradationLevel::Light, _) => SheddingDecision::Keep,

            (DegradationLevel::None, _) => SheddingDecision::Keep,
        }
    }

    /// Get degradation statistics.
    pub fn stats(&self) -> DegradationStatsSnapshot {
        DegradationStatsSnapshot {
            triggers_fired: self.stats.triggers_fired.load(Ordering::Relaxed),
            regions_cancelled: self.stats.regions_cancelled.load(Ordering::Relaxed),
            regions_paused: self.stats.regions_paused.load(Ordering::Relaxed),
            requests_rejected: self.stats.requests_rejected.load(Ordering::Relaxed),
            decision_time_nanos: self.stats.decision_time_nanos.load(Ordering::Relaxed),
            monitoring_overhead_nanos: self.pressure.monitoring_overhead_nanos(),
        }
    }
}

/// Snapshot of degradation statistics for reporting.
#[derive(Debug, Clone)]
pub struct DegradationStatsSnapshot {
    pub triggers_fired: u64,
    pub regions_cancelled: u64,
    pub regions_paused: u64,
    pub requests_rejected: u64,
    pub decision_time_nanos: u64,
    pub monitoring_overhead_nanos: u64,
}

impl DegradationStatsSnapshot {
    /// Calculate overhead as percentage of total runtime.
    #[must_use]
    pub fn overhead_percentage(&self, total_runtime_nanos: u64) -> f64 {
        if total_runtime_nanos == 0 {
            return 0.0;
        }
        let total_overhead = self.decision_time_nanos + self.monitoring_overhead_nanos;
        (total_overhead as f64) / (total_runtime_nanos as f64) * 100.0
    }
}

fn cycle_overhead_percentage(elapsed: Duration, interval: Duration) -> f64 {
    let interval_nanos = interval.as_nanos();
    if interval_nanos == 0 {
        return 0.0;
    }
    (elapsed.as_nanos() as f64) / (interval_nanos as f64) * 100.0
}

/// System resource collector for platform-specific monitoring.
/// br-asupersync-thfiyk: derive (soft, hard) absolute thresholds from
/// a `max_limit` and the percentage points the operator considers
/// warning vs critical. Saturates at `max_limit` so the soft band can
/// never exceed the hard band even on tiny `max_limit` values.
fn derive_thresholds(max_limit: u64, soft_pct: u64, hard_pct: u64) -> (u64, u64) {
    debug_assert!(soft_pct <= hard_pct);
    let soft = max_limit
        .saturating_mul(soft_pct)
        .checked_div(100)
        .unwrap_or(0);
    let hard = max_limit
        .saturating_mul(hard_pct)
        .checked_div(100)
        .unwrap_or(0);
    (soft.min(max_limit), hard.min(max_limit))
}

/// Platform-specific resource readers (br-asupersync-thfiyk).
///
/// Each function returns the same `std::io::Result<u64>` shape across
/// platforms; non-supported platforms return
/// `ErrorKind::Unsupported` so the caller's `if let Ok(..)` skip in
/// [`SystemResourceCollector::collect_now`] gracefully omits the
/// measurement and existing pressure values are preserved.
mod platform {
    /// Total system memory or process address-space ceiling, in bytes.
    /// Falls back to a large finite value (16 GiB) when the platform
    /// reports `RLIM_INFINITY` so downstream `usage_ratio()` arithmetic
    /// stays well-defined.
    const ADDRESS_SPACE_FALLBACK: u64 = 16 * 1024 * 1024 * 1024;

    #[cfg(target_os = "linux")]
    pub fn process_rss_bytes() -> std::io::Result<u64> {
        let status = std::fs::read_to_string("/proc/self/status")?;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                let kib_str = rest.trim().split_whitespace().next().ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "VmRSS missing value")
                })?;
                let kib: u64 = kib_str.parse().map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "VmRSS not numeric")
                })?;
                return Ok(kib.saturating_mul(1024));
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "VmRSS not present in /proc/self/status",
        ))
    }

    #[cfg(target_os = "linux")]
    pub fn memory_max_bytes() -> std::io::Result<u64> {
        // Prefer the address-space rlimit; fall back to MemTotal when
        // the rlimit is `RLIM_INFINITY` (the common production shape).
        if let Ok((_, hard)) = address_space_rlimit() {
            if hard != u64::MAX && hard != 0 {
                return Ok(hard);
            }
        }
        let meminfo = std::fs::read_to_string("/proc/meminfo")?;
        for line in meminfo.lines() {
            if let Some(rest) = line.strip_prefix("MemTotal:") {
                let kib_str = rest.trim().split_whitespace().next().ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "MemTotal missing value")
                })?;
                let kib: u64 = kib_str.parse().map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "MemTotal not numeric")
                })?;
                return Ok(kib.saturating_mul(1024));
            }
        }
        Ok(ADDRESS_SPACE_FALLBACK)
    }

    #[cfg(target_os = "linux")]
    pub fn process_fd_count() -> std::io::Result<u64> {
        let count = std::fs::read_dir("/proc/self/fd")?.count();
        Ok(count as u64)
    }

    #[cfg(target_os = "linux")]
    pub fn load_avg_1min_scaled() -> std::io::Result<u64> {
        let s = std::fs::read_to_string("/proc/loadavg")?;
        let first = s.split_whitespace().next().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "empty /proc/loadavg")
        })?;
        let v: f64 = first.parse().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "loadavg not numeric")
        })?;
        let cpus = num_cpus().max(1) as f64;
        let pct = (v / cpus).clamp(0.0, 1.0) * 100.0;
        Ok(pct.round() as u64)
    }

    #[cfg(target_os = "linux")]
    pub fn process_connection_count() -> std::io::Result<u64> {
        let mut total: u64 = 0;
        for path in [
            "/proc/self/net/tcp",
            "/proc/self/net/tcp6",
            "/proc/self/net/udp",
            "/proc/self/net/udp6",
        ] {
            if let Ok(s) = std::fs::read_to_string(path) {
                // First line is the column header; everything after is
                // a single connection. `saturating_sub(1)` handles the
                // empty-file edge case.
                total = total.saturating_add((s.lines().count() as u64).saturating_sub(1));
            }
        }
        Ok(total)
    }

    // ----- macOS / BSD ------------------------------------------------------

    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    #[allow(unsafe_code)]
    pub fn process_rss_bytes() -> std::io::Result<u64> {
        // SAFETY: `getrusage(RUSAGE_SELF, &mut usage)` writes into a
        // zeroed `rusage` we own; the libc call is well-defined.
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
        if rc == -1 {
            return Err(std::io::Error::last_os_error());
        }
        // ru_maxrss: bytes on macOS, kilobytes on BSDs (per their man pages).
        let raw = usage.ru_maxrss as u64;
        #[cfg(target_os = "macos")]
        {
            Ok(raw)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Ok(raw.saturating_mul(1024))
        }
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    pub fn memory_max_bytes() -> std::io::Result<u64> {
        if let Ok((_, hard)) = address_space_rlimit() {
            if hard != u64::MAX && hard != 0 {
                return Ok(hard);
            }
        }
        Ok(ADDRESS_SPACE_FALLBACK)
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    pub fn process_fd_count() -> std::io::Result<u64> {
        // /dev/fd is the per-process FD directory exposed by fdescfs;
        // the count of entries is the count of open descriptors.
        let count = std::fs::read_dir("/dev/fd")?.count();
        Ok(count as u64)
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    #[allow(unsafe_code)]
    pub fn load_avg_1min_scaled() -> std::io::Result<u64> {
        let mut loads: [f64; 3] = [0.0; 3];
        // SAFETY: `getloadavg` writes up to `n` doubles into the
        // caller-provided buffer; we pass an array of 3.
        let n = unsafe { libc::getloadavg(loads.as_mut_ptr(), 3) };
        if n < 1 {
            return Err(std::io::Error::last_os_error());
        }
        let cpus = num_cpus().max(1) as f64;
        let pct = (loads[0] / cpus).clamp(0.0, 1.0) * 100.0;
        Ok(pct.round() as u64)
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    pub fn process_connection_count() -> std::io::Result<u64> {
        // libproc / sysctl would give an exact answer but pull in a
        // transitive `mach2` dependency the project doesn't otherwise
        // need. The FD count is a conservative upper bound (sockets
        // are FDs); operators that need exact connection counts can
        // wire a custom resource collector via `register_resource`.
        process_fd_count()
    }

    // ----- Unsupported platforms (Windows / others) -------------------------

    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    )))]
    fn unsupported<T>(what: &'static str) -> std::io::Result<T> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!(
                "resource_monitor: {what} is not implemented on this platform \
                 (Linux, macOS, FreeBSD, NetBSD, OpenBSD, DragonFly only). \
                 Wire a platform-specific collector via \
                 ResourceMonitor::register_resource."
            ),
        ))
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    )))]
    pub fn process_rss_bytes() -> std::io::Result<u64> {
        unsupported("process_rss_bytes")
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    )))]
    pub fn memory_max_bytes() -> std::io::Result<u64> {
        unsupported("memory_max_bytes")
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    )))]
    pub fn process_fd_count() -> std::io::Result<u64> {
        unsupported("process_fd_count")
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    )))]
    pub fn load_avg_1min_scaled() -> std::io::Result<u64> {
        unsupported("load_avg_1min_scaled")
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    )))]
    pub fn process_connection_count() -> std::io::Result<u64> {
        unsupported("process_connection_count")
    }

    // ----- Cross-platform helpers (Unix / fallback) -------------------------

    #[cfg(unix)]
    #[allow(unsafe_code)]
    pub fn fd_rlimit() -> std::io::Result<(u64, u64)> {
        // SAFETY: `getrlimit(RLIMIT_NOFILE, &mut rlim)` writes into a
        // zeroed `rlimit` we own.
        let mut rlim: libc::rlimit = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) };
        if rc == -1 {
            return Err(std::io::Error::last_os_error());
        }
        let cur = rlim.rlim_cur as u64;
        let max = rlim.rlim_max as u64;
        Ok((cur, max))
    }

    #[cfg(unix)]
    #[allow(unsafe_code)]
    pub fn address_space_rlimit() -> std::io::Result<(u64, u64)> {
        // SAFETY: same shape as `fd_rlimit`.
        let mut rlim: libc::rlimit = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut rlim) };
        if rc == -1 {
            return Err(std::io::Error::last_os_error());
        }
        // Treat RLIM_INFINITY as `u64::MAX` so the caller can detect
        // "no ceiling" without depending on platform-specific
        // sentinel values.
        let infinity = libc::RLIM_INFINITY as u64;
        let cur = if rlim.rlim_cur as u64 == infinity {
            u64::MAX
        } else {
            rlim.rlim_cur as u64
        };
        let max = if rlim.rlim_max as u64 == infinity {
            u64::MAX
        } else {
            rlim.rlim_max as u64
        };
        Ok((cur, max))
    }

    #[cfg(not(unix))]
    pub fn fd_rlimit() -> std::io::Result<(u64, u64)> {
        // No portable Win32 equivalent of RLIMIT_NOFILE; default to a
        // conservative pair and let the operator override via custom
        // resource collectors.
        Ok((512, 1024))
    }

    #[cfg(not(unix))]
    pub fn address_space_rlimit() -> std::io::Result<(u64, u64)> {
        Ok((u64::MAX, u64::MAX))
    }

    pub fn num_cpus() -> u64 {
        std::thread::available_parallelism()
            .map(|n| n.get() as u64)
            .unwrap_or(1)
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct SystemResourceCollector {
    /// Whether monitoring is active.
    active: AtomicBool,
    /// Collection interval.
    interval: Duration,
    /// Collected data.
    pressure: Arc<ResourcePressure>,
}

impl SystemResourceCollector {
    /// Create a new system resource collector.
    pub fn new(pressure: Arc<ResourcePressure>, interval: Duration) -> Self {
        Self {
            active: AtomicBool::new(false),
            interval,
            pressure,
        }
    }

    /// Start monitoring system resources.
    pub fn start(&self) -> Result<(), ResourceMonitorError> {
        if self
            .active
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed)
            .is_err()
        {
            return Err(ResourceMonitorError::AlreadyActive);
        }

        // In a real implementation, this would spawn a background task
        // that periodically samples system resources
        Ok(())
    }

    /// Stop monitoring.
    pub fn stop(&self) {
        self.active.store(false, Ordering::SeqCst);
    }

    /// Manually collect current system resource measurements.
    pub fn collect_now(&self) -> Result<(), ResourceMonitorError> {
        let _start = Instant::now();

        // Memory usage (simplified - would use platform-specific APIs)
        if let Ok(memory_usage) = self.collect_memory_usage() {
            self.pressure
                .update_measurement(ResourceType::Memory, memory_usage);
        }

        // File descriptor usage
        if let Ok(fd_usage) = self.collect_fd_usage() {
            self.pressure
                .update_measurement(ResourceType::FileDescriptors, fd_usage);
        }

        // CPU load
        if let Ok(cpu_load) = self.collect_cpu_load() {
            self.pressure
                .update_measurement(ResourceType::CpuLoad, cpu_load);
        }

        // Network connections
        if let Ok(network_usage) = self.collect_network_usage() {
            self.pressure
                .update_measurement(ResourceType::NetworkConnections, network_usage);
        }

        Ok(())
    }

    /// Collect memory usage measurement.
    ///
    /// br-asupersync-thfiyk: real platform read.
    /// - Linux: VmRSS from `/proc/self/status`; max from `RLIMIT_AS`,
    ///   falling back to `MemTotal` from `/proc/meminfo` when the
    ///   address-space rlimit is `RLIM_INFINITY`.
    /// - macOS/BSD: `getrusage(RUSAGE_SELF).ru_maxrss` for current
    ///   (bytes on macOS, KiB on BSD); same `RLIMIT_AS` fallback.
    /// - Windows / other: `SystemAccessFailed` — caller's
    ///   `if let Ok(..)` in `collect_now` cleanly skips the
    ///   measurement update so existing pressure values are preserved.
    fn collect_memory_usage(&self) -> Result<ResourceMeasurement, ResourceMonitorError> {
        let current_bytes = platform::process_rss_bytes().map_err(|e| {
            ResourceMonitorError::SystemAccessFailed {
                reason: format!("memory rss: {e}"),
            }
        })?;
        let max_limit =
            platform::memory_max_bytes().map_err(|e| ResourceMonitorError::SystemAccessFailed {
                reason: format!("memory max: {e}"),
            })?;
        let (soft_limit, hard_limit) = derive_thresholds(max_limit, 75, 90);
        Ok(ResourceMeasurement::new(
            current_bytes,
            soft_limit,
            hard_limit,
            max_limit,
        ))
    }

    /// Collect file descriptor usage.
    ///
    /// br-asupersync-thfiyk: real platform read.
    /// - Linux: count entries in `/proc/self/fd`.
    /// - macOS/BSD: count entries in `/dev/fd` (the per-process
    ///   symlink directory exposed by `fdescfs`).
    /// - All Unix: max from `getrlimit(RLIMIT_NOFILE)`.
    fn collect_fd_usage(&self) -> Result<ResourceMeasurement, ResourceMonitorError> {
        let current_fds =
            platform::process_fd_count().map_err(|e| ResourceMonitorError::SystemAccessFailed {
                reason: format!("fd count: {e}"),
            })?;
        let (_, hard_max) =
            platform::fd_rlimit().map_err(|e| ResourceMonitorError::SystemAccessFailed {
                reason: format!("fd rlimit: {e}"),
            })?;
        let max_limit = if hard_max == 0 { 1024 } else { hard_max };
        let (soft_limit, hard_limit) = derive_thresholds(max_limit, 75, 90);
        Ok(ResourceMeasurement::new(
            current_fds,
            soft_limit,
            hard_limit,
            max_limit,
        ))
    }

    /// Collect CPU load measurement.
    ///
    /// br-asupersync-thfiyk: real platform read.
    /// - Linux: read first column of `/proc/loadavg` (1-minute load
    ///   average), normalize by core count, scale to 0..100.
    /// - macOS/BSD: `getloadavg(3)`, same normalization.
    /// - Windows / other: `SystemAccessFailed`.
    fn collect_cpu_load(&self) -> Result<ResourceMeasurement, ResourceMonitorError> {
        let load_avg_1min = platform::load_avg_1min_scaled().map_err(|e| {
            ResourceMonitorError::SystemAccessFailed {
                reason: format!("loadavg: {e}"),
            }
        })?;
        // CPU load is intrinsically a 0..100 scale; thresholds are
        // absolute rather than derived from a per-process rlimit.
        Ok(ResourceMeasurement::new(load_avg_1min, 80, 95, 100))
    }

    /// Collect network connection usage.
    ///
    /// br-asupersync-thfiyk: real platform read.
    /// - Linux: sum non-header rows of `/proc/self/net/{tcp,tcp6,udp,udp6}`.
    /// - macOS/BSD: `getrlimit(RLIMIT_NOFILE)` ceiling and the FD count
    ///   as a conservative upper bound on open sockets (libproc would
    ///   give an exact answer but pulls in a transitive `mach2` dep
    ///   the project doesn't otherwise need).
    fn collect_network_usage(&self) -> Result<ResourceMeasurement, ResourceMonitorError> {
        let current_connections = platform::process_connection_count().map_err(|e| {
            ResourceMonitorError::SystemAccessFailed {
                reason: format!("connection count: {e}"),
            }
        })?;
        // Sockets share the FD table, so the connection ceiling is at
        // most RLIMIT_NOFILE. Use a reasonable fallback when the
        // rlimit is unavailable.
        let (_, hard_max) = platform::fd_rlimit().unwrap_or((512, 1024));
        let max_limit = if hard_max == 0 { 1024 } else { hard_max };
        let (soft_limit, hard_limit) = derive_thresholds(max_limit, 70, 85);
        Ok(ResourceMeasurement::new(
            current_connections,
            soft_limit,
            hard_limit,
            max_limit,
        ))
    }

    /// Check if monitoring is active.
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }
}

/// Central resource monitor coordinator.
#[derive(Debug)]
pub struct ResourceMonitor {
    /// Resource pressure tracker.
    pressure: Arc<ResourcePressure>,
    /// Degradation decision engine.
    engine: Arc<DegradationEngine>,
    /// System resource collector.
    collector: SystemResourceCollector,
    /// Monitoring configuration.
    config: RwLock<MonitorConfig>,
}

/// Configuration for the resource monitor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorConfig {
    /// Collection interval for system resources.
    pub collection_interval: Duration,
    /// Whether to enable automatic degradation.
    pub enable_auto_degradation: bool,
    /// Maximum allowed monitoring overhead percentage.
    pub max_overhead_percent: f64,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            collection_interval: Duration::from_secs(1),
            enable_auto_degradation: true,
            max_overhead_percent: 0.5, // 0.5% overhead limit
        }
    }
}

impl ResourceMonitor {
    /// Create a new resource monitor.
    #[must_use]
    pub fn new(config: MonitorConfig) -> Self {
        let pressure = Arc::new(ResourcePressure::new());
        let engine = Arc::new(DegradationEngine::new(Arc::clone(&pressure)));
        let collector =
            SystemResourceCollector::new(Arc::clone(&pressure), config.collection_interval);

        Self {
            pressure,
            engine,
            collector,
            config: RwLock::new(config),
        }
    }

    /// Start resource monitoring.
    pub fn start(&self) -> Result<(), ResourceMonitorError> {
        self.collector.start()
    }

    /// Stop resource monitoring.
    pub fn stop(&self) {
        self.collector.stop();
    }

    /// Get access to the pressure tracker.
    pub fn pressure(&self) -> Arc<ResourcePressure> {
        Arc::clone(&self.pressure)
    }

    /// Get access to the degradation engine.
    pub fn engine(&self) -> Arc<DegradationEngine> {
        Arc::clone(&self.engine)
    }

    /// Update monitoring configuration.
    pub fn update_config(&self, new_config: MonitorConfig) {
        let mut config = self.config.write();
        *config = new_config;
    }

    /// Process current measurements and trigger degradation if needed.
    pub fn process_current_state(
        &self,
    ) -> Result<Vec<(ResourceType, DegradationLevel)>, ResourceMonitorError> {
        let cycle_start = Instant::now();

        // Collect fresh measurements
        self.collector.collect_now()?;

        // Process through degradation engine
        let changes = self.engine.process_measurements()?;

        // Check overhead limits
        let config = self.config.read();
        if config.enable_auto_degradation {
            let overhead_percent =
                cycle_overhead_percentage(cycle_start.elapsed(), config.collection_interval);

            if overhead_percent > config.max_overhead_percent {
                crate::tracing_compat::warn!(
                    overhead_percent,
                    collection_interval_ms = config.collection_interval.as_millis(),
                    max_overhead_percent = config.max_overhead_percent,
                    "resource monitoring overhead exceeds configured limit"
                );
            }
        }

        Ok(changes)
    }

    /// Get comprehensive status report.
    pub fn status_report(&self) -> ResourceMonitorStatus {
        let measurements: HashMap<ResourceType, ResourceMeasurement> =
            self.pressure.measurements.read().clone();
        let degradation_levels: HashMap<ResourceType, DegradationLevel> =
            self.pressure.degradation_levels.read().clone();

        ResourceMonitorStatus {
            is_active: self.collector.is_active(),
            composite_degradation_level: self.pressure.composite_degradation_level(),
            measurements,
            degradation_levels,
            stats: self.engine.stats(),
            config: self.config.read().clone(),
        }
    }
}

/// Status report for resource monitoring system.
#[derive(Debug, Clone)]
pub struct ResourceMonitorStatus {
    pub is_active: bool,
    pub composite_degradation_level: DegradationLevel,
    pub measurements: HashMap<ResourceType, ResourceMeasurement>,
    pub degradation_levels: HashMap<ResourceType, DegradationLevel>,
    pub stats: DegradationStatsSnapshot,
    pub config: MonitorConfig,
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[test]
    fn test_resource_measurement_ratios() {
        let measurement = ResourceMeasurement::new(750, 800, 900, 1000);

        assert_eq!(measurement.usage_ratio(), 0.75);
        assert!(!measurement.is_soft_exceeded());
        assert!(!measurement.is_hard_exceeded());
        assert!(!measurement.is_critical());
    }

    #[test]
    fn test_degradation_level_conversion() {
        assert_eq!(DegradationLevel::None.to_headroom(), 1.0);
        assert_eq!(DegradationLevel::Emergency.to_headroom(), 0.0);
        assert_eq!(DegradationLevel::from_headroom(0.9), DegradationLevel::None);
        assert_eq!(
            DegradationLevel::from_headroom(0.1),
            DegradationLevel::Emergency
        );
    }

    #[test]
    fn test_trigger_config_degradation_calculation() {
        let config = TriggerConfig::default_for_resource(&ResourceType::Memory);
        let measurement = ResourceMeasurement::new(800, 700, 850, 1000); // 80% usage

        let level = config.calculate_degradation(&measurement);
        assert_eq!(level, DegradationLevel::Moderate);
    }

    #[test]
    fn test_resource_pressure_updates() {
        let pressure = ResourcePressure::new();
        let measurement = ResourceMeasurement::new(500, 700, 850, 1000);

        pressure.update_measurement(ResourceType::Memory, measurement.clone());

        let retrieved = pressure.get_measurement(&ResourceType::Memory).unwrap();
        assert_eq!(retrieved.current, measurement.current);
    }

    #[test]
    fn test_resource_pressure_system_pressure_matches_degradation_band() {
        let pressure = ResourcePressure::new();
        let system_pressure = pressure.system_pressure();

        pressure.update_degradation_level(ResourceType::Memory, DegradationLevel::None);
        assert!((system_pressure.headroom() - 1.0).abs() < f32::EPSILON);
        assert_eq!(system_pressure.degradation_level(), 0);
        assert_eq!(system_pressure.level_label(), "normal");

        pressure.update_degradation_level(ResourceType::Memory, DegradationLevel::Light);
        assert!((system_pressure.headroom() - 0.75).abs() < f32::EPSILON);
        assert_eq!(system_pressure.degradation_level(), 1);
        assert_eq!(system_pressure.level_label(), "light");

        pressure.update_degradation_level(ResourceType::Memory, DegradationLevel::Moderate);
        assert!((system_pressure.headroom() - 0.5).abs() < f32::EPSILON);
        assert_eq!(system_pressure.degradation_level(), 2);
        assert_eq!(system_pressure.level_label(), "moderate");

        pressure.update_degradation_level(ResourceType::Memory, DegradationLevel::Heavy);
        assert!((system_pressure.headroom() - 0.25).abs() < f32::EPSILON);
        assert_eq!(system_pressure.degradation_level(), 3);
        assert_eq!(system_pressure.level_label(), "heavy");

        pressure.update_degradation_level(ResourceType::Memory, DegradationLevel::Emergency);
        assert!(system_pressure.headroom().abs() < f32::EPSILON);
        assert_eq!(system_pressure.degradation_level(), 4);
        assert_eq!(system_pressure.level_label(), "emergency");
    }

    #[test]
    fn test_degradation_engine_policies() {
        let pressure = Arc::new(ResourcePressure::new());
        let engine = DegradationEngine::new(Arc::clone(&pressure));

        let policy = DegradationPolicy {
            resource_type: ResourceType::Memory,
            trigger_level: DegradationLevel::Moderate,
            action: PolicyAction::RejectNewWork(RegionPriority::Low),
        };

        engine.add_policy(policy);

        // Test region shedding decisions
        let region_id = RegionId::new_ephemeral();
        engine.set_region_priority(region_id, RegionPriority::Low);

        pressure.update_degradation_level(ResourceType::Memory, DegradationLevel::Heavy);

        let decision = engine.should_shed_region(region_id);
        assert!(matches!(decision, SheddingDecision::Pause));
    }

    #[test]
    fn test_degradation_engine_monitors_task_pressure_by_default() {
        let pressure = Arc::new(ResourcePressure::new());
        let engine = DegradationEngine::new(Arc::clone(&pressure));

        pressure.update_measurement(
            ResourceType::Task,
            ResourceMeasurement::new(960, 800, 950, 1000),
        );

        let changes = engine
            .process_measurements()
            .expect("task pressure should process");
        assert_eq!(
            changes,
            vec![(ResourceType::Task, DegradationLevel::Emergency)]
        );
        assert_eq!(
            pressure.get_degradation_level(&ResourceType::Task),
            DegradationLevel::Emergency
        );
    }

    #[test]
    fn test_cycle_overhead_percentage_uses_configured_interval() {
        let overhead =
            cycle_overhead_percentage(Duration::from_millis(25), Duration::from_millis(100));
        assert!((overhead - 25.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_cycle_overhead_percentage_handles_zero_interval() {
        assert_eq!(
            cycle_overhead_percentage(Duration::from_millis(25), Duration::ZERO),
            0.0
        );
    }

    // ===================================================================
    // br-asupersync-thfiyk: real platform-read tests for the
    // SystemResourceCollector. The exact values vary per-host so we
    // assert on shape (non-zero where it must be, ratios sane, no
    // longer the constants the old mocks returned).
    // ===================================================================

    #[test]
    fn thfiyk_derive_thresholds_basic() {
        assert_eq!(derive_thresholds(1000, 75, 90), (750, 900));
        assert_eq!(derive_thresholds(0, 75, 90), (0, 0));
        // Saturation: extremely large `max_limit` doesn't overflow u64.
        let (s, h) = derive_thresholds(u64::MAX, 75, 90);
        assert!(s <= u64::MAX);
        assert!(h <= u64::MAX);
        assert!(s <= h);
    }

    #[test]
    fn thfiyk_derive_thresholds_clamps_to_max() {
        // soft and hard must never exceed max_limit even if the
        // percentages would compute past it (rounding).
        let (s, h) = derive_thresholds(7, 75, 90);
        assert!(s <= 7);
        assert!(h <= 7);
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    #[test]
    fn thfiyk_collect_memory_usage_returns_real_rss() {
        let pressure = Arc::new(ResourcePressure::new());
        let collector = SystemResourceCollector::new(pressure, Duration::from_secs(1));
        let m = collector
            .collect_memory_usage()
            .expect("memory usage read should succeed on supported platform");
        // The old mock always returned 512 MiB exactly; the real
        // reader yields the live VmRSS / ru_maxrss which is virtually
        // never that exact value. We assert (a) non-zero current
        // (this test process necessarily has resident memory),
        // (b) max_limit > 0, (c) we did NOT get the mock constant.
        assert!(m.current > 0, "current bytes should be > 0");
        assert!(m.max_limit > 0, "max_limit should be > 0");
        assert!(
            m.current != 512 * 1024 * 1024 || m.max_limit != 2048 * 1024 * 1024,
            "appears to still be returning the legacy mock constants"
        );
        assert!(m.soft_limit <= m.hard_limit, "soft <= hard");
        assert!(m.hard_limit <= m.max_limit, "hard <= max");
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    #[test]
    fn thfiyk_collect_fd_usage_returns_real_count() {
        let pressure = Arc::new(ResourcePressure::new());
        let collector = SystemResourceCollector::new(pressure, Duration::from_secs(1));
        let m = collector
            .collect_fd_usage()
            .expect("fd usage read should succeed on supported platform");
        // A test process always has at least stdin/stdout/stderr open,
        // so current_fds >= 3 in practice. We assert >= 1 to keep the
        // test robust on obscure sandboxed environments.
        assert!(m.current >= 1, "fd count should be >= 1");
        assert!(m.max_limit >= m.current, "fd ceiling >= current");
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    #[test]
    fn thfiyk_collect_cpu_load_returns_real_load() {
        let pressure = Arc::new(ResourcePressure::new());
        let collector = SystemResourceCollector::new(pressure, Duration::from_secs(1));
        let m = collector
            .collect_cpu_load()
            .expect("loadavg read should succeed on supported platform");
        assert_eq!(m.max_limit, 100, "load is reported on a 0..100 scale");
        assert!(m.current <= 100, "load percentage in range");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn thfiyk_collect_network_usage_returns_real_count() {
        let pressure = Arc::new(ResourcePressure::new());
        let collector = SystemResourceCollector::new(pressure, Duration::from_secs(1));
        let m = collector
            .collect_network_usage()
            .expect("connection count read should succeed on Linux");
        // Connection count can legitimately be 0 (a fresh test
        // process opens no sockets), so assert only that the ceiling
        // is sane and the reader did not return the legacy mock 50.
        assert!(m.max_limit > 0, "connection ceiling > 0");
        assert!(m.soft_limit <= m.hard_limit);
        assert!(m.hard_limit <= m.max_limit);
    }
}
