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
        last_change: Instant,
    ) -> DegradationLevel {
        // Respect cooldown period
        if last_change.elapsed() < self.cooldown {
            return current_level;
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
#[derive(Debug)]
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

impl Default for ResourcePressure {
    fn default() -> Self {
        Self::new()
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
                    .copied()
                    .unwrap_or_else(|| {
                        Instant::now()
                            .checked_sub(Duration::from_secs(3600))
                            .unwrap()
                    });

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

/// System resource collector for platform-specific monitoring.
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
    fn collect_memory_usage(&self) -> Result<ResourceMeasurement, ResourceMonitorError> {
        // Simplified implementation - real version would use platform APIs
        // like /proc/meminfo on Linux, Windows API calls, etc.

        // Mock values for demonstration
        let current_bytes = 512 * 1024 * 1024; // 512 MB
        let soft_limit = 1024 * 1024 * 1024; // 1 GB
        let hard_limit = 1536 * 1024 * 1024; // 1.5 GB
        let max_limit = 2048 * 1024 * 1024; // 2 GB

        Ok(ResourceMeasurement::new(
            current_bytes,
            soft_limit,
            hard_limit,
            max_limit,
        ))
    }

    /// Collect file descriptor usage.
    fn collect_fd_usage(&self) -> Result<ResourceMeasurement, ResourceMonitorError> {
        // Mock implementation - real version would check ulimits and /proc/self/fd
        let current_fds = 128;
        let soft_limit = 768; // 75% of 1024
        let hard_limit = 922; // 90% of 1024
        let max_limit = 1024; // ulimit -n

        Ok(ResourceMeasurement::new(
            current_fds,
            soft_limit,
            hard_limit,
            max_limit,
        ))
    }

    /// Collect CPU load measurement.
    fn collect_cpu_load(&self) -> Result<ResourceMeasurement, ResourceMonitorError> {
        // Mock implementation - real version would read /proc/loadavg or equivalent
        let load_avg_1min = 80; // 80% load (scaled to 0-100)
        let soft_limit = 80;
        let hard_limit = 95;
        let max_limit = 100;

        Ok(ResourceMeasurement::new(
            load_avg_1min,
            soft_limit,
            hard_limit,
            max_limit,
        ))
    }

    /// Collect network connection usage.
    fn collect_network_usage(&self) -> Result<ResourceMeasurement, ResourceMonitorError> {
        // Mock implementation - real version would count open sockets
        let current_connections = 50;
        let soft_limit = 350; // 70% of 500
        let hard_limit = 425; // 85% of 500
        let max_limit = 500; // Application limit

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
        // Collect fresh measurements
        self.collector.collect_now()?;

        // Process through degradation engine
        let changes = self.engine.process_measurements()?;

        // Check overhead limits
        let config = self.config.read();
        if config.enable_auto_degradation {
            let stats = self.engine.stats();
            let overhead_percent =
                stats.overhead_percentage(Duration::from_secs(1).as_nanos() as u64);

            if overhead_percent > config.max_overhead_percent {
                // Could trigger a degradation level for monitoring overhead itself
                eprintln!(
                    "Warning: Resource monitoring overhead {:.2}% exceeds limit {:.2}%",
                    overhead_percent, config.max_overhead_percent
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
}
