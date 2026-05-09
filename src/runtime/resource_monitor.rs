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

use crate::runtime::scheduler::SchedulerEvidenceMetrics;
use crate::types::RegionId;
use crate::types::pressure::SystemPressure;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use thiserror::Error;

/// Stable schema for operator-facing platform probe reports.
pub const RESOURCE_MONITOR_PLATFORM_GAP_REPORT_SCHEMA_VERSION: &str =
    "asupersync.resource-monitor-platform-gaps.v1";

const RESOURCE_PROBE_WARNING_THROTTLE_EVERY: u64 = 8;

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

/// Built-in platform probes used by the system resource collector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceProbe {
    ProcessRssBytes,
    MemoryMaxBytes,
    ProcessFdCount,
    FileDescriptorLimit,
    #[serde(rename = "load_avg_1min_scaled")]
    LoadAvg1MinScaled,
    ProcessConnectionCount,
    NetworkConnectionLimit,
}

impl ResourceProbe {
    #[must_use]
    pub fn resource_type(self) -> ResourceType {
        match self {
            Self::ProcessRssBytes | Self::MemoryMaxBytes => ResourceType::Memory,
            Self::ProcessFdCount | Self::FileDescriptorLimit => ResourceType::FileDescriptors,
            Self::LoadAvg1MinScaled => ResourceType::CpuLoad,
            Self::ProcessConnectionCount | Self::NetworkConnectionLimit => {
                ResourceType::NetworkConnections
            }
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProcessRssBytes => "process_rss_bytes",
            Self::MemoryMaxBytes => "memory_max_bytes",
            Self::ProcessFdCount => "process_fd_count",
            Self::FileDescriptorLimit => "file_descriptor_limit",
            Self::LoadAvg1MinScaled => "load_avg_1min_scaled",
            Self::ProcessConnectionCount => "process_connection_count",
            Self::NetworkConnectionLimit => "network_connection_limit",
        }
    }
}

impl std::fmt::Display for ResourceProbe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Availability state for a platform resource probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceProbeStatus {
    Supported,
    Unavailable,
    Fallback,
    Disabled,
}

/// Operator-safe fallback semantics for a failed or disabled probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceProbeFallback {
    None,
    OmitMeasurement,
    ConservativeDefault,
    CustomCollectorRequired,
    MonitorDisabled,
}

impl std::fmt::Display for ResourceProbeFallback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::None => "none",
            Self::OmitMeasurement => "omit_measurement",
            Self::ConservativeDefault => "conservative_default",
            Self::CustomCollectorRequired => "custom_collector_required",
            Self::MonitorDisabled => "monitor_disabled",
        };
        f.write_str(label)
    }
}

/// Aggregate verdict for operator-facing platform probe reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceProbeOperatorVerdict {
    Complete,
    DegradedWithUnavailableProbes,
    DegradedWithFallbacks,
    Disabled,
}

/// Serializable snapshot for one platform resource probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceProbeSnapshot {
    pub platform: String,
    pub resource_type: ResourceType,
    pub probe: ResourceProbe,
    pub status: ResourceProbeStatus,
    pub fallback: ResourceProbeFallback,
    pub sampled_value: Option<u64>,
    pub error_message: Option<String>,
    pub warning_count: u64,
    pub warning_suppressed_count: u64,
}

/// Serializable platform probe inventory for the resource monitor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourcePlatformProbeReport {
    pub schema_version: String,
    pub platform: String,
    pub probes: Vec<ResourceProbeSnapshot>,
    pub supported_count: u64,
    pub unavailable_count: u64,
    pub fallback_count: u64,
    pub disabled_count: u64,
    pub warning_emitted_count: u64,
    pub warning_suppressed_count: u64,
    pub operator_verdict: ResourceProbeOperatorVerdict,
}

impl ResourcePlatformProbeReport {
    fn from_snapshots(platform: String, mut probes: Vec<ResourceProbeSnapshot>) -> Self {
        probes.sort_by_key(|snapshot| snapshot.probe);

        let supported_count = probes
            .iter()
            .filter(|snapshot| snapshot.status == ResourceProbeStatus::Supported)
            .count() as u64;
        let unavailable_count = probes
            .iter()
            .filter(|snapshot| snapshot.status == ResourceProbeStatus::Unavailable)
            .count() as u64;
        let fallback_count = probes
            .iter()
            .filter(|snapshot| snapshot.status == ResourceProbeStatus::Fallback)
            .count() as u64;
        let disabled_count = probes
            .iter()
            .filter(|snapshot| snapshot.status == ResourceProbeStatus::Disabled)
            .count() as u64;
        let warning_suppressed_count = probes
            .iter()
            .map(|snapshot| snapshot.warning_suppressed_count)
            .sum();
        let warning_emitted_count = probes
            .iter()
            .map(|snapshot| snapshot.warning_count - snapshot.warning_suppressed_count)
            .sum();

        let operator_verdict = if !probes.is_empty() && disabled_count == probes.len() as u64 {
            ResourceProbeOperatorVerdict::Disabled
        } else if unavailable_count > 0 {
            ResourceProbeOperatorVerdict::DegradedWithUnavailableProbes
        } else if fallback_count > 0 {
            ResourceProbeOperatorVerdict::DegradedWithFallbacks
        } else {
            ResourceProbeOperatorVerdict::Complete
        };

        Self {
            schema_version: RESOURCE_MONITOR_PLATFORM_GAP_REPORT_SCHEMA_VERSION.to_string(),
            platform,
            probes,
            supported_count,
            unavailable_count,
            fallback_count,
            disabled_count,
            warning_emitted_count,
            warning_suppressed_count,
            operator_verdict,
        }
    }
}

#[derive(Debug)]
struct ResourceProbeState {
    platform: String,
    probes: RwLock<HashMap<ResourceProbe, ResourceProbeSnapshot>>,
    warning_counts: RwLock<HashMap<ResourceProbe, u64>>,
}

impl ResourceProbeState {
    fn new(platform: impl Into<String>) -> Self {
        Self {
            platform: platform.into(),
            probes: RwLock::new(HashMap::new()),
            warning_counts: RwLock::new(HashMap::new()),
        }
    }

    fn report(&self) -> ResourcePlatformProbeReport {
        ResourcePlatformProbeReport::from_snapshots(
            self.platform.clone(),
            self.probes.read().values().cloned().collect(),
        )
    }

    fn record_supported(&self, probe: ResourceProbe, sampled_value: Option<u64>) {
        self.probes.write().insert(
            probe,
            self.snapshot(
                probe,
                ResourceProbeStatus::Supported,
                ResourceProbeFallback::None,
                sampled_value,
                None,
                0,
                0,
            ),
        );
    }

    fn record_probe_failure(
        &self,
        probe: ResourceProbe,
        requested_fallback: ResourceProbeFallback,
        error: &std::io::Error,
    ) {
        let fallback = if error.kind() == std::io::ErrorKind::Unsupported {
            ResourceProbeFallback::CustomCollectorRequired
        } else {
            requested_fallback
        };
        let status = if fallback == ResourceProbeFallback::ConservativeDefault {
            ResourceProbeStatus::Fallback
        } else {
            ResourceProbeStatus::Unavailable
        };

        let warning_count = {
            let mut counts = self.warning_counts.write();
            let count = counts.entry(probe).or_insert(0);
            *count += 1;
            *count
        };
        let should_emit_warning = should_emit_probe_warning(warning_count);
        let warning_suppressed_count = warning_count - probe_warning_emitted_count(warning_count);

        if should_emit_warning {
            crate::tracing_compat::warn!(
                platform = self.platform.as_str(),
                probe = probe.as_str(),
                resource_type = probe.resource_type().to_string(),
                fallback = fallback.to_string(),
                error = error.to_string(),
                "resource monitor platform probe unavailable"
            );
        }

        self.probes.write().insert(
            probe,
            self.snapshot(
                probe,
                status,
                fallback,
                None,
                Some(error.to_string()),
                warning_count,
                warning_suppressed_count,
            ),
        );
    }

    #[cfg(test)]
    fn record_disabled(&self, probe: ResourceProbe) {
        self.probes.write().insert(
            probe,
            self.snapshot(
                probe,
                ResourceProbeStatus::Disabled,
                ResourceProbeFallback::MonitorDisabled,
                None,
                None,
                0,
                0,
            ),
        );
    }

    fn snapshot(
        &self,
        probe: ResourceProbe,
        status: ResourceProbeStatus,
        fallback: ResourceProbeFallback,
        sampled_value: Option<u64>,
        error_message: Option<String>,
        warning_count: u64,
        warning_suppressed_count: u64,
    ) -> ResourceProbeSnapshot {
        ResourceProbeSnapshot {
            platform: self.platform.clone(),
            resource_type: probe.resource_type(),
            probe,
            status,
            fallback,
            sampled_value,
            error_message,
            warning_count,
            warning_suppressed_count,
        }
    }
}

fn should_emit_probe_warning(warning_count: u64) -> bool {
    warning_count == 1 || warning_count.is_multiple_of(RESOURCE_PROBE_WARNING_THROTTLE_EVERY)
}

fn probe_warning_emitted_count(warning_count: u64) -> u64 {
    if warning_count == 0 {
        0
    } else {
        1 + warning_count / RESOURCE_PROBE_WARNING_THROTTLE_EVERY
    }
}

fn current_platform_fingerprint() -> String {
    format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH)
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

    /// Evaluate a deterministic overload-admission decision using the current pressure band
    /// plus first-party scheduler evidence.
    #[must_use]
    pub fn evaluate_tail_risk_admission(
        &self,
        scheduler: Option<&SchedulerEvidenceMetrics>,
        retry_pressure_p99: Option<u64>,
        memory_pressure_bps: Option<u16>,
        profile: &TailRiskAdmissionProfile,
    ) -> TailRiskAdmissionLedger {
        let evidence = TailRiskAdmissionEvidence {
            scheduler: scheduler.cloned(),
            retry_pressure_p99,
            memory_pressure_bps,
            degradation_level: self.pressure.composite_degradation_level(),
        };
        TailRiskAdmissionLedger::evaluate(&evidence, profile)
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

/// Stable version identifier for tail-risk admission ledgers.
pub const TAIL_RISK_ADMISSION_LEDGER_SCHEMA_VERSION: &str = "asupersync.tail-risk-admission.v1";

/// Admission outcome for overload-sensitive work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TailRiskAdmissionDecision {
    Admit,
    Defer,
    Shed,
}

/// Explicit reason codes for a tail-risk admission verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TailRiskAdmissionReason {
    WakeToRunTail,
    QueueResidencyTail,
    BacklogPressure,
    CancelDebtPressure,
    RetryPressure,
    MemoryPressure,
    ExistingDegradation,
    ConservativeFallback,
    BalancedBaseline,
}

/// Bounded operator-tunable thresholds for overload admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailRiskAdmissionProfile {
    pub wake_to_run_p99_ns_limit: u64,
    pub queue_residency_p99_ns_limit: u64,
    pub ready_backlog_p99_limit: usize,
    pub cancel_debt_p99_limit: usize,
    pub retry_pressure_p99_limit: u64,
    pub memory_pressure_soft_bps: u16,
    pub memory_pressure_hard_bps: u16,
    pub defer_expected_loss_score: u8,
    pub shed_expected_loss_score: u8,
}

impl Default for TailRiskAdmissionProfile {
    fn default() -> Self {
        Self {
            wake_to_run_p99_ns_limit: 150_000,
            queue_residency_p99_ns_limit: 400_000,
            ready_backlog_p99_limit: 256,
            cancel_debt_p99_limit: 96,
            retry_pressure_p99_limit: 32,
            memory_pressure_soft_bps: 8_000,
            memory_pressure_hard_bps: 9_200,
            defer_expected_loss_score: 35,
            shed_expected_loss_score: 65,
        }
    }
}

/// Evidence vector consumed by the tail-risk admission rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailRiskAdmissionEvidence {
    pub scheduler: Option<SchedulerEvidenceMetrics>,
    pub retry_pressure_p99: Option<u64>,
    /// Memory pressure in basis points, where `10_000` represents 100%.
    pub memory_pressure_bps: Option<u16>,
    pub degradation_level: DegradationLevel,
}

impl TailRiskAdmissionEvidence {
    fn missing_fields(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if self.scheduler.is_none() {
            missing.push("scheduler_metrics");
        }
        if self.retry_pressure_p99.is_none() {
            missing.push("retry_pressure_p99");
        }
        match self.memory_pressure_bps {
            Some(value) if value <= 10_000 => {}
            Some(_) | None => missing.push("memory_pressure_bps"),
        }
        missing
    }
}

/// Flattened evidence snapshot stored in the decision ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailRiskAdmissionEvidenceSnapshot {
    pub wake_to_run_p99_ns: Option<u64>,
    pub queue_residency_p99_ns: Option<u64>,
    pub ready_backlog_p99: Option<usize>,
    pub cancel_debt_p99: Option<usize>,
    pub retry_pressure_p99: Option<u64>,
    pub memory_pressure_bps: Option<u16>,
}

/// Deterministic decision ledger for overload admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailRiskAdmissionLedger {
    pub schema_version: String,
    pub decision: TailRiskAdmissionDecision,
    pub fallback_used: bool,
    pub expected_loss_score: u8,
    pub confidence_percent: u8,
    pub reason_codes: Vec<TailRiskAdmissionReason>,
    pub missing_evidence_fields: Vec<String>,
    pub profile: TailRiskAdmissionProfile,
    pub degradation_level: DegradationLevel,
    pub evidence: TailRiskAdmissionEvidenceSnapshot,
    pub explanation: Vec<String>,
}

impl TailRiskAdmissionLedger {
    /// Evaluate one overload-admission decision against the supplied evidence and profile.
    #[must_use]
    pub fn evaluate(
        evidence: &TailRiskAdmissionEvidence,
        profile: &TailRiskAdmissionProfile,
    ) -> Self {
        let snapshot = TailRiskAdmissionEvidenceSnapshot {
            wake_to_run_p99_ns: evidence
                .scheduler
                .as_ref()
                .map(|metrics| metrics.wake_to_run_p99_ns),
            queue_residency_p99_ns: evidence
                .scheduler
                .as_ref()
                .map(|metrics| metrics.queue_residency_p99_ns),
            ready_backlog_p99: evidence
                .scheduler
                .as_ref()
                .map(|metrics| metrics.ready_backlog_p99),
            cancel_debt_p99: evidence
                .scheduler
                .as_ref()
                .map(|metrics| metrics.cancel_debt_p99),
            retry_pressure_p99: evidence.retry_pressure_p99,
            memory_pressure_bps: evidence.memory_pressure_bps,
        };
        let missing_fields = evidence
            .missing_fields()
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();

        if !missing_fields.is_empty() {
            return Self::conservative_fallback(evidence, profile, snapshot, missing_fields);
        }

        let scheduler = evidence.scheduler.as_ref().expect("checked above");
        let retry_pressure = evidence.retry_pressure_p99.expect("checked above");
        let memory_pressure = evidence.memory_pressure_bps.expect("checked above");

        let mut expected_loss_score = 0u8;
        let mut reason_codes = Vec::new();
        let mut explanation = Vec::new();

        if scheduler.wake_to_run_p99_ns >= profile.wake_to_run_p99_ns_limit {
            expected_loss_score = expected_loss_score.saturating_add(18);
            reason_codes.push(TailRiskAdmissionReason::WakeToRunTail);
            explanation.push(format!(
                "wake_to_run p99={}ns exceeded the configured limit {}ns",
                scheduler.wake_to_run_p99_ns, profile.wake_to_run_p99_ns_limit
            ));
        }

        if scheduler.queue_residency_p99_ns >= profile.queue_residency_p99_ns_limit {
            expected_loss_score = expected_loss_score.saturating_add(22);
            reason_codes.push(TailRiskAdmissionReason::QueueResidencyTail);
            explanation.push(format!(
                "queue_residency p99={}ns exceeded the configured limit {}ns",
                scheduler.queue_residency_p99_ns, profile.queue_residency_p99_ns_limit
            ));
        }

        if scheduler.ready_backlog_p99 >= profile.ready_backlog_p99_limit {
            expected_loss_score = expected_loss_score.saturating_add(15);
            reason_codes.push(TailRiskAdmissionReason::BacklogPressure);
            explanation.push(format!(
                "ready_backlog p99={} exceeded the configured limit {}",
                scheduler.ready_backlog_p99, profile.ready_backlog_p99_limit
            ));
        }

        if scheduler.cancel_debt_p99 >= profile.cancel_debt_p99_limit {
            expected_loss_score = expected_loss_score.saturating_add(10);
            reason_codes.push(TailRiskAdmissionReason::CancelDebtPressure);
            explanation.push(format!(
                "cancel_debt p99={} exceeded the configured limit {}",
                scheduler.cancel_debt_p99, profile.cancel_debt_p99_limit
            ));
        }

        if retry_pressure >= profile.retry_pressure_p99_limit {
            expected_loss_score = expected_loss_score.saturating_add(15);
            reason_codes.push(TailRiskAdmissionReason::RetryPressure);
            explanation.push(format!(
                "retry_pressure p99={} exceeded the configured limit {}",
                retry_pressure, profile.retry_pressure_p99_limit
            ));
        }

        if memory_pressure >= profile.memory_pressure_soft_bps {
            let increment = if memory_pressure >= profile.memory_pressure_hard_bps {
                25
            } else {
                12
            };
            expected_loss_score = expected_loss_score.saturating_add(increment);
            reason_codes.push(TailRiskAdmissionReason::MemoryPressure);
            explanation.push(format!(
                "memory pressure {}bps exceeded the soft limit {}bps",
                memory_pressure, profile.memory_pressure_soft_bps
            ));
        }

        if evidence.degradation_level >= DegradationLevel::Moderate {
            expected_loss_score = expected_loss_score.saturating_add(10);
            reason_codes.push(TailRiskAdmissionReason::ExistingDegradation);
            explanation.push(format!(
                "existing degradation level {:?} tightened the admission envelope",
                evidence.degradation_level
            ));
        }

        if reason_codes.is_empty() {
            reason_codes.push(TailRiskAdmissionReason::BalancedBaseline);
            explanation.push(
                "tail, backlog, retry, and memory evidence stayed inside the configured envelope"
                    .to_string(),
            );
        }

        let decision = if memory_pressure >= profile.memory_pressure_hard_bps
            || evidence.degradation_level == DegradationLevel::Emergency
            || expected_loss_score >= profile.shed_expected_loss_score
        {
            TailRiskAdmissionDecision::Shed
        } else if evidence.degradation_level >= DegradationLevel::Moderate
            || expected_loss_score >= profile.defer_expected_loss_score
        {
            TailRiskAdmissionDecision::Defer
        } else {
            TailRiskAdmissionDecision::Admit
        };

        let confidence_percent = 65u8
            .saturating_add((reason_codes.len() as u8).saturating_mul(5))
            .min(90);

        Self {
            schema_version: TAIL_RISK_ADMISSION_LEDGER_SCHEMA_VERSION.to_string(),
            decision,
            fallback_used: false,
            expected_loss_score,
            confidence_percent,
            reason_codes,
            missing_evidence_fields: Vec::new(),
            profile: profile.clone(),
            degradation_level: evidence.degradation_level,
            evidence: snapshot,
            explanation,
        }
    }

    fn conservative_fallback(
        evidence: &TailRiskAdmissionEvidence,
        profile: &TailRiskAdmissionProfile,
        snapshot: TailRiskAdmissionEvidenceSnapshot,
        missing_evidence_fields: Vec<String>,
    ) -> Self {
        let decision = match evidence.degradation_level {
            DegradationLevel::Emergency | DegradationLevel::Heavy => {
                TailRiskAdmissionDecision::Shed
            }
            DegradationLevel::Moderate => TailRiskAdmissionDecision::Defer,
            DegradationLevel::Light | DegradationLevel::None => TailRiskAdmissionDecision::Admit,
        };

        Self {
            schema_version: TAIL_RISK_ADMISSION_LEDGER_SCHEMA_VERSION.to_string(),
            decision,
            fallback_used: true,
            expected_loss_score: 0,
            confidence_percent: 100,
            reason_codes: vec![TailRiskAdmissionReason::ConservativeFallback],
            missing_evidence_fields,
            profile: profile.clone(),
            degradation_level: evidence.degradation_level,
            evidence: snapshot,
            explanation: vec![
                "Incomplete evidence preserved the conservative degradation-band comparator."
                    .to_string(),
            ],
        }
    }
}

/// Stable version identifier for cohort-aware admission steering ledgers.
pub const COHORT_ADMISSION_STEERING_LEDGER_SCHEMA_VERSION: &str =
    "asupersync.cohort-admission-steering.v1";

/// Placement outcome for cohort-aware admission steering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortAdmissionSteeringDecision {
    AdmitLocal,
    RedirectRemote,
    Defer,
}

/// Explicit reason codes for cohort-aware admission steering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortAdmissionSteeringReason {
    Disabled,
    MissingTopology,
    LowConfidenceFallback,
    TailRiskOuterCap,
    LocalCapacityAvailable,
    LocalBacklogPressure,
    RemoteSpillBudgetSpent,
    RemoteSpillBudgetExhausted,
    FairnessEscapeHatch,
    ConservativeGlobalBaseline,
}

/// Bounded knobs for cohort-aware admission steering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CohortAdmissionSteeringProfile {
    pub enabled: bool,
    pub local_ready_backlog_soft_limit: usize,
    pub local_ready_backlog_hard_limit: usize,
    pub remote_ready_backlog_limit: usize,
    pub remote_redirect_delta_min: usize,
    pub remote_spill_budget_per_epoch: u16,
    pub min_topology_confidence_percent: u8,
    pub fairness_escape_after_consecutive_defers: u16,
}

impl Default for CohortAdmissionSteeringProfile {
    fn default() -> Self {
        Self {
            enabled: true,
            local_ready_backlog_soft_limit: 192,
            local_ready_backlog_hard_limit: 256,
            remote_ready_backlog_limit: 160,
            remote_redirect_delta_min: 24,
            remote_spill_budget_per_epoch: 2,
            min_topology_confidence_percent: 70,
            fairness_escape_after_consecutive_defers: 3,
        }
    }
}

/// Deterministic budget state for bounded remote spill steering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CohortRemoteSpillBudgetState {
    pub epoch: u64,
    pub remaining_tokens: u16,
}

impl CohortRemoteSpillBudgetState {
    #[must_use]
    pub fn new(epoch: u64, remaining_tokens: u16) -> Self {
        Self {
            epoch,
            remaining_tokens,
        }
    }

    #[must_use]
    pub fn normalized_for_epoch(
        self,
        profile: &CohortAdmissionSteeringProfile,
        decision_epoch: u64,
    ) -> Self {
        if self.epoch == decision_epoch {
            Self {
                epoch: self.epoch,
                remaining_tokens: self
                    .remaining_tokens
                    .min(profile.remote_spill_budget_per_epoch),
            }
        } else {
            Self {
                epoch: decision_epoch,
                remaining_tokens: profile.remote_spill_budget_per_epoch,
            }
        }
    }

    #[must_use]
    pub fn spend_one(self) -> Self {
        Self {
            epoch: self.epoch,
            remaining_tokens: self.remaining_tokens.saturating_sub(1),
        }
    }
}

/// Cohort-local evidence vector for admission steering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CohortAdmissionSteeringEvidence {
    pub local_cohort: Option<usize>,
    pub worker_to_cohort_map: Vec<usize>,
    pub cohort_ready_backlog: Vec<usize>,
    pub topology_confidence_percent: Option<u8>,
    pub remote_spill_budget: CohortRemoteSpillBudgetState,
    pub decision_epoch: u64,
    pub consecutive_local_defers: u16,
    pub outer_tail_risk_decision: TailRiskAdmissionDecision,
}

impl CohortAdmissionSteeringEvidence {
    fn missing_fields(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if self.local_cohort.is_none() {
            missing.push("local_cohort");
        }
        if self.worker_to_cohort_map.is_empty() {
            missing.push("worker_to_cohort_map");
        }
        if self.cohort_ready_backlog.is_empty() {
            missing.push("cohort_ready_backlog");
        }
        if let Some(local) = self.local_cohort {
            if local >= self.cohort_ready_backlog.len() {
                missing.push("local_cohort");
            }
        }
        if !self.worker_to_cohort_map.is_empty()
            && !self.cohort_ready_backlog.is_empty()
            && self
                .worker_to_cohort_map
                .iter()
                .any(|cohort| *cohort >= self.cohort_ready_backlog.len())
        {
            missing.push("worker_to_cohort_map");
        }
        missing.sort_unstable();
        missing.dedup();
        missing
    }

    fn remote_target(&self) -> Option<(usize, usize)> {
        let local = self.local_cohort?;
        self.cohort_ready_backlog
            .iter()
            .enumerate()
            .filter(|(cohort, _)| *cohort != local)
            .min_by_key(|(cohort, backlog)| (**backlog, *cohort))
            .map(|(cohort, backlog)| (cohort, *backlog))
    }
}

/// Flattened evidence snapshot stored in the cohort steering ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CohortAdmissionSteeringEvidenceSnapshot {
    pub local_cohort: Option<usize>,
    pub cohort_count: usize,
    pub worker_to_cohort_map: Vec<usize>,
    pub cohort_ready_backlog: Vec<usize>,
    pub topology_confidence_percent: Option<u8>,
    pub decision_epoch: u64,
    pub remote_spill_budget_epoch: u64,
    pub remote_spill_budget_remaining_before: u16,
    pub remote_spill_budget_remaining_after: u16,
    pub consecutive_local_defers: u16,
    pub outer_tail_risk_decision: TailRiskAdmissionDecision,
}

/// Deterministic decision ledger for cohort-aware admission steering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CohortAdmissionSteeringLedger {
    pub schema_version: String,
    pub decision: CohortAdmissionSteeringDecision,
    pub target_cohort: Option<usize>,
    pub fallback_used: bool,
    pub confidence_percent: u8,
    pub reason_codes: Vec<CohortAdmissionSteeringReason>,
    pub missing_evidence_fields: Vec<String>,
    pub profile: CohortAdmissionSteeringProfile,
    pub evidence: CohortAdmissionSteeringEvidenceSnapshot,
    pub remote_spill_budget_start: u16,
    pub remote_spill_budget_remaining: u16,
    pub remote_spill_budget_exhausted: bool,
    pub explanation: Vec<String>,
}

impl CohortAdmissionSteeringLedger {
    /// Evaluate one cohort-aware placement decision.
    #[must_use]
    pub fn evaluate(
        evidence: &CohortAdmissionSteeringEvidence,
        profile: &CohortAdmissionSteeringProfile,
    ) -> Self {
        let normalized_budget = evidence
            .remote_spill_budget
            .normalized_for_epoch(profile, evidence.decision_epoch);
        let budget_start = normalized_budget.remaining_tokens;
        let mut budget_after = budget_start;
        let snapshot = CohortAdmissionSteeringEvidenceSnapshot {
            local_cohort: evidence.local_cohort,
            cohort_count: evidence.cohort_ready_backlog.len(),
            worker_to_cohort_map: evidence.worker_to_cohort_map.clone(),
            cohort_ready_backlog: evidence.cohort_ready_backlog.clone(),
            topology_confidence_percent: evidence.topology_confidence_percent,
            decision_epoch: evidence.decision_epoch,
            remote_spill_budget_epoch: normalized_budget.epoch,
            remote_spill_budget_remaining_before: budget_start,
            remote_spill_budget_remaining_after: budget_start,
            consecutive_local_defers: evidence.consecutive_local_defers,
            outer_tail_risk_decision: evidence.outer_tail_risk_decision,
        };

        if evidence.outer_tail_risk_decision != TailRiskAdmissionDecision::Admit {
            return Self::finish(
                profile,
                snapshot,
                CohortAdmissionSteeringDecision::Defer,
                None,
                false,
                evidence.topology_confidence_percent.unwrap_or(100),
                vec![CohortAdmissionSteeringReason::TailRiskOuterCap],
                Vec::new(),
                budget_start,
                budget_after,
                vec![format!(
                    "tail-risk outer decision {:?} kept cohort steering from admitting new work",
                    evidence.outer_tail_risk_decision
                )],
            );
        }

        if !profile.enabled {
            return Self::finish(
                profile,
                snapshot,
                CohortAdmissionSteeringDecision::AdmitLocal,
                evidence.local_cohort,
                true,
                evidence.topology_confidence_percent.unwrap_or(100),
                vec![
                    CohortAdmissionSteeringReason::Disabled,
                    CohortAdmissionSteeringReason::ConservativeGlobalBaseline,
                ],
                Vec::new(),
                budget_start,
                budget_after,
                vec![
                    "cohort steering is disabled, so the conservative global routing path stayed pinned"
                        .to_string(),
                ],
            );
        }

        let missing_fields = evidence
            .missing_fields()
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        if !missing_fields.is_empty() {
            return Self::finish(
                profile,
                snapshot,
                CohortAdmissionSteeringDecision::AdmitLocal,
                evidence.local_cohort,
                true,
                evidence.topology_confidence_percent.unwrap_or(100),
                vec![
                    CohortAdmissionSteeringReason::MissingTopology,
                    CohortAdmissionSteeringReason::ConservativeGlobalBaseline,
                ],
                missing_fields,
                budget_start,
                budget_after,
                vec![
                    "missing or invalid worker/cohort topology kept the conservative global routing path pinned"
                        .to_string(),
                ],
            );
        }

        let topology_confidence = evidence.topology_confidence_percent.unwrap_or(0).min(100);
        if topology_confidence < profile.min_topology_confidence_percent {
            return Self::finish(
                profile,
                snapshot,
                CohortAdmissionSteeringDecision::AdmitLocal,
                evidence.local_cohort,
                true,
                topology_confidence,
                vec![
                    CohortAdmissionSteeringReason::LowConfidenceFallback,
                    CohortAdmissionSteeringReason::ConservativeGlobalBaseline,
                ],
                Vec::new(),
                budget_start,
                budget_after,
                vec![format!(
                    "topology confidence {}% stayed below the configured minimum {}%",
                    topology_confidence, profile.min_topology_confidence_percent
                )],
            );
        }

        let local_cohort = evidence.local_cohort.expect("validated above");
        let local_backlog = evidence.cohort_ready_backlog[local_cohort];
        let fairness_triggered =
            evidence.consecutive_local_defers >= profile.fairness_escape_after_consecutive_defers;

        if local_backlog <= profile.local_ready_backlog_soft_limit {
            return Self::finish(
                profile,
                snapshot,
                CohortAdmissionSteeringDecision::AdmitLocal,
                Some(local_cohort),
                false,
                topology_confidence,
                vec![CohortAdmissionSteeringReason::LocalCapacityAvailable],
                Vec::new(),
                budget_start,
                budget_after,
                vec![format!(
                    "local cohort {} backlog {} stayed inside the soft limit {}",
                    local_cohort, local_backlog, profile.local_ready_backlog_soft_limit
                )],
            );
        }

        let Some((remote_target, remote_backlog)) = evidence.remote_target() else {
            return Self::finish(
                profile,
                snapshot,
                CohortAdmissionSteeringDecision::AdmitLocal,
                Some(local_cohort),
                false,
                topology_confidence,
                vec![CohortAdmissionSteeringReason::ConservativeGlobalBaseline],
                Vec::new(),
                budget_start,
                budget_after,
                vec![
                    "no remote cohort candidate existed, so the conservative local placement stayed pinned"
                        .to_string(),
                ],
            );
        };

        let remote_gain = local_backlog.saturating_sub(remote_backlog);
        let remote_viable = remote_backlog <= profile.remote_ready_backlog_limit
            && remote_gain >= profile.remote_redirect_delta_min;

        if remote_viable && budget_start > 0 {
            budget_after = normalized_budget.spend_one().remaining_tokens;
            let mut reasons = vec![
                CohortAdmissionSteeringReason::LocalBacklogPressure,
                CohortAdmissionSteeringReason::RemoteSpillBudgetSpent,
            ];
            let mut explanation = vec![format!(
                "redirected from local cohort {} backlog {} to remote cohort {} backlog {} with remote gain {}",
                local_cohort, local_backlog, remote_target, remote_backlog, remote_gain
            )];
            if fairness_triggered {
                reasons.push(CohortAdmissionSteeringReason::FairnessEscapeHatch);
                explanation.push(format!(
                    "fairness escape hatch fired after {} consecutive local defers",
                    evidence.consecutive_local_defers
                ));
            }
            return Self::finish(
                profile,
                snapshot,
                CohortAdmissionSteeringDecision::RedirectRemote,
                Some(remote_target),
                false,
                topology_confidence,
                reasons,
                Vec::new(),
                budget_start,
                budget_after,
                explanation,
            );
        }

        if remote_viable && budget_start == 0 {
            let mut reasons = vec![CohortAdmissionSteeringReason::RemoteSpillBudgetExhausted];
            let mut explanation = vec![format!(
                "remote cohort {} backlog {} was viable but the epoch budget was exhausted",
                remote_target, remote_backlog
            )];
            if fairness_triggered {
                reasons.push(CohortAdmissionSteeringReason::FairnessEscapeHatch);
                explanation.push(format!(
                    "fairness pressure was present after {} consecutive local defers",
                    evidence.consecutive_local_defers
                ));
            }
            return Self::finish(
                profile,
                snapshot,
                CohortAdmissionSteeringDecision::Defer,
                None,
                false,
                topology_confidence,
                reasons,
                Vec::new(),
                budget_start,
                budget_after,
                explanation,
            );
        }

        Self::finish(
            profile,
            snapshot,
            CohortAdmissionSteeringDecision::AdmitLocal,
            Some(local_cohort),
            false,
            topology_confidence,
            vec![CohortAdmissionSteeringReason::ConservativeGlobalBaseline],
            Vec::new(),
            budget_start,
            budget_after,
            vec![format!(
                "remote cohort {} backlog {} did not beat the local cohort {} backlog {} by the configured delta {}",
                remote_target,
                remote_backlog,
                local_cohort,
                local_backlog,
                profile.remote_redirect_delta_min
            )],
        )
    }

    fn finish(
        profile: &CohortAdmissionSteeringProfile,
        mut snapshot: CohortAdmissionSteeringEvidenceSnapshot,
        decision: CohortAdmissionSteeringDecision,
        target_cohort: Option<usize>,
        fallback_used: bool,
        confidence_percent: u8,
        reason_codes: Vec<CohortAdmissionSteeringReason>,
        missing_evidence_fields: Vec<String>,
        remote_spill_budget_start: u16,
        remote_spill_budget_remaining: u16,
        explanation: Vec<String>,
    ) -> Self {
        snapshot.remote_spill_budget_remaining_after = remote_spill_budget_remaining;
        Self {
            schema_version: COHORT_ADMISSION_STEERING_LEDGER_SCHEMA_VERSION.to_string(),
            decision,
            target_cohort,
            fallback_used,
            confidence_percent,
            reason_codes,
            missing_evidence_fields,
            profile: profile.clone(),
            evidence: snapshot,
            remote_spill_budget_start,
            remote_spill_budget_remaining,
            remote_spill_budget_exhausted: remote_spill_budget_remaining == 0,
            explanation,
        }
    }
}

/// Stable version identifier for overload brownout ledgers.
pub const OVERLOAD_BROWNOUT_LEDGER_SCHEMA_VERSION: &str = "asupersync.overload-brownout.v1";

/// Optional runtime surfaces that may be degraded during overload brownout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrownoutOptionalSurface {
    DetailedTracing,
    RichDiagnostics,
    DebugHttp,
    RichExportFormatting,
}

/// Critical runtime surfaces that brownout must never disable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrownoutProtectedSurface {
    CoreScheduling,
    CancellationDrain,
    RegionQuiescence,
    ObligationCleanup,
}

/// Brownout phase for optional runtime surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverloadBrownoutPhase {
    Normal,
    Observe,
    Degrade,
    ShedOptional,
    Recovery,
}

impl OverloadBrownoutPhase {
    #[must_use]
    fn severity_rank(self) -> u8 {
        match self {
            Self::Normal => 0,
            Self::Observe | Self::Recovery => 1,
            Self::Degrade => 2,
            Self::ShedOptional => 3,
        }
    }
}

/// Explicit reason codes for overload brownout decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverloadBrownoutReason {
    Disabled,
    MissingEvidenceFallback,
    ObservePressure,
    DegradePressure,
    ShedOptionalPressure,
    TailRiskOuterDefer,
    TailRiskOuterShed,
    RecoveryHysteresis,
    PreserveCriticalSurfaces,
    OptionalSurfaceAlreadyShedding,
    ConservativeBaseline,
}

/// Bounded operator-tunable profile for overload brownout decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverloadBrownoutProfile {
    pub enabled: bool,
    pub observe_memory_pressure_bps: u16,
    pub degrade_memory_pressure_bps: u16,
    pub shed_optional_memory_pressure_bps: u16,
    pub observe_wake_to_run_p99_ns: u64,
    pub degrade_wake_to_run_p99_ns: u64,
    pub shed_optional_wake_to_run_p99_ns: u64,
    pub recovery_window_threshold: u8,
    pub allowed_optional_surfaces: Vec<BrownoutOptionalSurface>,
    pub denied_optional_surfaces: Vec<BrownoutOptionalSurface>,
}

impl Default for OverloadBrownoutProfile {
    fn default() -> Self {
        Self {
            enabled: true,
            observe_memory_pressure_bps: 7_800,
            degrade_memory_pressure_bps: 8_600,
            shed_optional_memory_pressure_bps: 9_300,
            observe_wake_to_run_p99_ns: 145_000,
            degrade_wake_to_run_p99_ns: 210_000,
            shed_optional_wake_to_run_p99_ns: 285_000,
            recovery_window_threshold: 2,
            allowed_optional_surfaces: vec![
                BrownoutOptionalSurface::DetailedTracing,
                BrownoutOptionalSurface::RichDiagnostics,
                BrownoutOptionalSurface::DebugHttp,
                BrownoutOptionalSurface::RichExportFormatting,
            ],
            denied_optional_surfaces: Vec::new(),
        }
    }
}

impl OverloadBrownoutProfile {
    /// Return the deduplicated, denylist-filtered optional surfaces.
    #[must_use]
    pub fn effective_optional_surfaces(&self) -> Vec<BrownoutOptionalSurface> {
        let mut effective = Vec::new();
        for surface in &self.allowed_optional_surfaces {
            if self.denied_optional_surfaces.contains(surface) || effective.contains(surface) {
                continue;
            }
            effective.push(*surface);
        }
        effective
    }

    fn surfaces_for_phase(&self, phase: OverloadBrownoutPhase) -> Vec<BrownoutOptionalSurface> {
        let effective = self.effective_optional_surfaces();
        let wanted = match phase {
            OverloadBrownoutPhase::Normal => Vec::new(),
            OverloadBrownoutPhase::Observe | OverloadBrownoutPhase::Recovery => {
                vec![BrownoutOptionalSurface::RichExportFormatting]
            }
            OverloadBrownoutPhase::Degrade => vec![
                BrownoutOptionalSurface::RichExportFormatting,
                BrownoutOptionalSurface::RichDiagnostics,
            ],
            OverloadBrownoutPhase::ShedOptional => effective.clone(),
        };
        wanted
            .into_iter()
            .filter(|surface| effective.contains(surface))
            .collect()
    }
}

/// Evidence vector for overload brownout decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverloadBrownoutEvidence {
    pub scheduler: Option<SchedulerEvidenceMetrics>,
    /// Memory pressure in basis points, where `10_000` represents 100%.
    pub memory_pressure_bps: Option<u16>,
    pub degradation_level: DegradationLevel,
    pub outer_tail_risk_decision: TailRiskAdmissionDecision,
    pub previous_phase: OverloadBrownoutPhase,
    pub recovery_streak_windows: u8,
    pub already_shed_surfaces: Vec<BrownoutOptionalSurface>,
}

impl OverloadBrownoutEvidence {
    fn missing_fields(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if self.scheduler.is_none() {
            missing.push("scheduler_metrics");
        }
        match self.memory_pressure_bps {
            Some(value) if value <= 10_000 => {}
            Some(_) | None => missing.push("memory_pressure_bps"),
        }
        missing
    }
}

/// Flattened evidence snapshot stored in the overload brownout ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverloadBrownoutEvidenceSnapshot {
    pub wake_to_run_p99_ns: Option<u64>,
    pub queue_residency_p99_ns: Option<u64>,
    pub ready_backlog_p99: Option<usize>,
    pub cancel_debt_p99: Option<usize>,
    pub memory_pressure_bps: Option<u16>,
    pub degradation_level: DegradationLevel,
    pub outer_tail_risk_decision: TailRiskAdmissionDecision,
    pub previous_phase: OverloadBrownoutPhase,
    pub recovery_streak_before: u8,
    pub already_shed_surfaces: Vec<BrownoutOptionalSurface>,
}

/// Deterministic decision ledger for overload brownout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverloadBrownoutLedger {
    pub schema_version: String,
    pub phase: OverloadBrownoutPhase,
    pub fallback_used: bool,
    pub reason_codes: Vec<OverloadBrownoutReason>,
    pub missing_evidence_fields: Vec<String>,
    pub profile: OverloadBrownoutProfile,
    pub evidence: OverloadBrownoutEvidenceSnapshot,
    pub requested_degraded_surfaces: Vec<BrownoutOptionalSurface>,
    pub newly_degraded_surfaces: Vec<BrownoutOptionalSurface>,
    pub already_shed_surfaces: Vec<BrownoutOptionalSurface>,
    pub restored_surfaces: Vec<BrownoutOptionalSurface>,
    pub preserved_surfaces: Vec<BrownoutProtectedSurface>,
    pub recovery_streak_after: u8,
    pub explanation: Vec<String>,
}

impl OverloadBrownoutLedger {
    /// Evaluate one overload brownout decision.
    #[must_use]
    pub fn evaluate(
        evidence: &OverloadBrownoutEvidence,
        profile: &OverloadBrownoutProfile,
    ) -> Self {
        let snapshot = OverloadBrownoutEvidenceSnapshot {
            wake_to_run_p99_ns: evidence
                .scheduler
                .as_ref()
                .map(|metrics| metrics.wake_to_run_p99_ns),
            queue_residency_p99_ns: evidence
                .scheduler
                .as_ref()
                .map(|metrics| metrics.queue_residency_p99_ns),
            ready_backlog_p99: evidence
                .scheduler
                .as_ref()
                .map(|metrics| metrics.ready_backlog_p99),
            cancel_debt_p99: evidence
                .scheduler
                .as_ref()
                .map(|metrics| metrics.cancel_debt_p99),
            memory_pressure_bps: evidence.memory_pressure_bps,
            degradation_level: evidence.degradation_level,
            outer_tail_risk_decision: evidence.outer_tail_risk_decision,
            previous_phase: evidence.previous_phase,
            recovery_streak_before: evidence.recovery_streak_windows,
            already_shed_surfaces: evidence.already_shed_surfaces.clone(),
        };

        if !profile.enabled {
            return Self::finish(
                profile,
                snapshot,
                OverloadBrownoutPhase::Normal,
                true,
                vec![
                    OverloadBrownoutReason::Disabled,
                    OverloadBrownoutReason::ConservativeBaseline,
                ],
                Vec::new(),
                Vec::new(),
                0,
                vec!["brownout is disabled, so optional surfaces stayed fully enabled".to_string()],
            );
        }

        let missing_fields = evidence
            .missing_fields()
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        if !missing_fields.is_empty() {
            let conservative_phase = Self::conservative_phase(evidence);
            return Self::finish(
                profile,
                snapshot,
                conservative_phase,
                true,
                vec![
                    OverloadBrownoutReason::MissingEvidenceFallback,
                    OverloadBrownoutReason::PreserveCriticalSurfaces,
                ],
                missing_fields,
                Vec::new(),
                evidence.recovery_streak_windows,
                vec![
                    "incomplete evidence kept brownout on a conservative degradation-band comparator"
                        .to_string(),
                ],
            );
        }

        let scheduler = evidence.scheduler.as_ref().expect("validated above");
        let memory_pressure = evidence.memory_pressure_bps.expect("validated above");
        let mut raw_phase = OverloadBrownoutPhase::Normal;
        let mut reason_codes = vec![OverloadBrownoutReason::PreserveCriticalSurfaces];
        let mut explanation = vec![
            "core scheduling, cancellation drain, region quiescence, and obligation cleanup stay preserved in every brownout phase".to_string(),
        ];

        if memory_pressure >= profile.observe_memory_pressure_bps
            || scheduler.wake_to_run_p99_ns >= profile.observe_wake_to_run_p99_ns
            || evidence.degradation_level >= DegradationLevel::Light
        {
            raw_phase = OverloadBrownoutPhase::Observe;
            reason_codes.push(OverloadBrownoutReason::ObservePressure);
            explanation.push(format!(
                "observe threshold crossed: wake_to_run p99={}ns, memory={}bps",
                scheduler.wake_to_run_p99_ns, memory_pressure
            ));
        }

        if memory_pressure >= profile.degrade_memory_pressure_bps
            || scheduler.wake_to_run_p99_ns >= profile.degrade_wake_to_run_p99_ns
            || evidence.degradation_level >= DegradationLevel::Moderate
            || evidence.outer_tail_risk_decision == TailRiskAdmissionDecision::Defer
        {
            raw_phase = OverloadBrownoutPhase::Degrade;
            reason_codes.push(OverloadBrownoutReason::DegradePressure);
            explanation.push(format!(
                "degrade threshold crossed: wake_to_run p99={}ns, memory={}bps, outer={:?}",
                scheduler.wake_to_run_p99_ns, memory_pressure, evidence.outer_tail_risk_decision
            ));
        }

        if memory_pressure >= profile.shed_optional_memory_pressure_bps
            || scheduler.wake_to_run_p99_ns >= profile.shed_optional_wake_to_run_p99_ns
            || evidence.degradation_level >= DegradationLevel::Heavy
            || evidence.outer_tail_risk_decision == TailRiskAdmissionDecision::Shed
        {
            raw_phase = OverloadBrownoutPhase::ShedOptional;
            reason_codes.push(OverloadBrownoutReason::ShedOptionalPressure);
            explanation.push(format!(
                "optional-shed threshold crossed: wake_to_run p99={}ns, memory={}bps, outer={:?}",
                scheduler.wake_to_run_p99_ns, memory_pressure, evidence.outer_tail_risk_decision
            ));
        }

        if evidence.outer_tail_risk_decision == TailRiskAdmissionDecision::Defer {
            reason_codes.push(OverloadBrownoutReason::TailRiskOuterDefer);
        }
        if evidence.outer_tail_risk_decision == TailRiskAdmissionDecision::Shed {
            reason_codes.push(OverloadBrownoutReason::TailRiskOuterShed);
        }

        let mut phase = raw_phase;
        let mut recovery_streak_after = 0;
        if raw_phase.severity_rank() < evidence.previous_phase.severity_rank()
            && evidence.previous_phase != OverloadBrownoutPhase::Normal
        {
            recovery_streak_after = evidence.recovery_streak_windows.saturating_add(1);
            if recovery_streak_after < profile.recovery_window_threshold {
                phase = OverloadBrownoutPhase::Recovery;
                reason_codes.push(OverloadBrownoutReason::RecoveryHysteresis);
                explanation.push(format!(
                    "recovery hysteresis kept one brownout window active ({}/{})",
                    recovery_streak_after, profile.recovery_window_threshold
                ));
            } else {
                recovery_streak_after = 0;
                explanation.push(format!(
                    "recovery hysteresis satisfied after {} windows",
                    profile.recovery_window_threshold
                ));
            }
        }

        let previous_requested = profile.surfaces_for_phase(evidence.previous_phase);
        let requested = profile.surfaces_for_phase(phase);
        let already_shed = requested
            .iter()
            .copied()
            .filter(|surface| evidence.already_shed_surfaces.contains(surface))
            .collect::<Vec<_>>();
        let newly_degraded = requested
            .iter()
            .copied()
            .filter(|surface| !evidence.already_shed_surfaces.contains(surface))
            .collect::<Vec<_>>();
        if !already_shed.is_empty() {
            reason_codes.push(OverloadBrownoutReason::OptionalSurfaceAlreadyShedding);
            explanation.push(format!(
                "{} optional surface(s) were already shedding locally and were not double-counted",
                already_shed.len()
            ));
        }
        let restored = previous_requested
            .iter()
            .copied()
            .filter(|surface| !requested.contains(surface))
            .collect::<Vec<_>>();

        Self {
            schema_version: OVERLOAD_BROWNOUT_LEDGER_SCHEMA_VERSION.to_string(),
            phase,
            fallback_used: false,
            reason_codes,
            missing_evidence_fields: Vec::new(),
            profile: profile.clone(),
            evidence: snapshot,
            requested_degraded_surfaces: requested,
            newly_degraded_surfaces: newly_degraded,
            already_shed_surfaces: already_shed,
            restored_surfaces: restored,
            preserved_surfaces: vec![
                BrownoutProtectedSurface::CoreScheduling,
                BrownoutProtectedSurface::CancellationDrain,
                BrownoutProtectedSurface::RegionQuiescence,
                BrownoutProtectedSurface::ObligationCleanup,
            ],
            recovery_streak_after,
            explanation,
        }
    }

    fn conservative_phase(evidence: &OverloadBrownoutEvidence) -> OverloadBrownoutPhase {
        match evidence.outer_tail_risk_decision {
            TailRiskAdmissionDecision::Shed => OverloadBrownoutPhase::ShedOptional,
            TailRiskAdmissionDecision::Defer => OverloadBrownoutPhase::Degrade,
            TailRiskAdmissionDecision::Admit => match evidence.degradation_level {
                DegradationLevel::Emergency | DegradationLevel::Heavy => {
                    OverloadBrownoutPhase::ShedOptional
                }
                DegradationLevel::Moderate => OverloadBrownoutPhase::Degrade,
                DegradationLevel::Light => OverloadBrownoutPhase::Observe,
                DegradationLevel::None => OverloadBrownoutPhase::Normal,
            },
        }
    }

    fn finish(
        profile: &OverloadBrownoutProfile,
        snapshot: OverloadBrownoutEvidenceSnapshot,
        phase: OverloadBrownoutPhase,
        fallback_used: bool,
        reason_codes: Vec<OverloadBrownoutReason>,
        missing_evidence_fields: Vec<String>,
        restored_surfaces: Vec<BrownoutOptionalSurface>,
        recovery_streak_after: u8,
        explanation: Vec<String>,
    ) -> Self {
        let requested = profile.surfaces_for_phase(phase);
        Self {
            schema_version: OVERLOAD_BROWNOUT_LEDGER_SCHEMA_VERSION.to_string(),
            phase,
            fallback_used,
            reason_codes,
            missing_evidence_fields,
            profile: profile.clone(),
            evidence: snapshot,
            requested_degraded_surfaces: requested.clone(),
            newly_degraded_surfaces: requested,
            already_shed_surfaces: Vec::new(),
            restored_surfaces,
            preserved_surfaces: vec![
                BrownoutProtectedSurface::CoreScheduling,
                BrownoutProtectedSurface::CancellationDrain,
                BrownoutProtectedSurface::RegionQuiescence,
                BrownoutProtectedSurface::ObligationCleanup,
            ],
            recovery_streak_after,
            explanation,
        }
    }
}

/// Stable version identifier for unified admission and brownout policy ledgers.
pub const UNIFIED_ADMISSION_BROWNOUT_LEDGER_SCHEMA_VERSION: &str =
    "asupersync.unified-admission-brownout.v1";

/// Top-level phase emitted by the unified overload policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnifiedAdmissionBrownoutPhase {
    Normal,
    Observe,
    Defer,
    Degrade,
    ShedOptional,
    Refuse,
    Recovery,
}

/// Work-admission action selected after all overload controllers are composed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnifiedAdmissionAction {
    Admit,
    Defer,
    Refuse,
}

/// Optional-surface action selected by the unified policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnifiedBrownoutAction {
    KeepFullSurfaces,
    Observe,
    DegradeOptional,
    ShedOptional,
    RestoreOptional,
}

/// Explicit reason codes for the unified admission/brownout verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnifiedAdmissionBrownoutReason {
    Disabled,
    LowConfidenceFallback,
    TailRiskShedPrecedence,
    TailRiskDeferPrecedence,
    CohortSteeringDefer,
    CohortFairnessEscape,
    BrownoutShedPrecedence,
    BrownoutDegradePrecedence,
    BrownoutObservePrecedence,
    RestorationHysteresisSatisfied,
    CriticalSurfacePreserved,
    TelemetryMinimumPreserved,
    ConservativeBaseline,
}

/// Operator-tunable guardrails for the unified admission and brownout contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnifiedAdmissionBrownoutProfile {
    pub enabled: bool,
    pub min_confidence_percent: u8,
    pub defer_admit_basis_points: u16,
    pub preserved_telemetry_floor_units: u16,
    pub critical_surface_floor_units: u64,
}

impl Default for UnifiedAdmissionBrownoutProfile {
    fn default() -> Self {
        Self {
            enabled: true,
            min_confidence_percent: 60,
            defer_admit_basis_points: 8_000,
            preserved_telemetry_floor_units: 4,
            critical_surface_floor_units: 1,
        }
    }
}

/// Inputs for composing admission, cohort steering, and brownout ledgers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnifiedAdmissionBrownoutEvidence {
    pub offered_work_units: u64,
    pub critical_surface_units: u64,
    pub tail_risk: TailRiskAdmissionLedger,
    pub cohort_steering: CohortAdmissionSteeringLedger,
    pub brownout: OverloadBrownoutLedger,
}

/// Deterministic operator-facing policy ledger that composes all overload controls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnifiedAdmissionBrownoutLedger {
    pub schema_version: String,
    pub phase: UnifiedAdmissionBrownoutPhase,
    pub admission_action: UnifiedAdmissionAction,
    pub brownout_action: UnifiedBrownoutAction,
    pub fallback_used: bool,
    pub confidence_percent: u8,
    pub reason_codes: Vec<UnifiedAdmissionBrownoutReason>,
    pub admitted_units: u64,
    pub deferred_units: u64,
    pub refused_units: u64,
    pub preserved_telemetry_units: u16,
    pub preserved_critical_surface_units: u64,
    pub requested_degraded_surfaces: Vec<BrownoutOptionalSurface>,
    pub restored_surfaces: Vec<BrownoutOptionalSurface>,
    pub preserved_surfaces: Vec<BrownoutProtectedSurface>,
    pub no_win_decision: bool,
    pub fallback_reason: Option<String>,
    pub profile: UnifiedAdmissionBrownoutProfile,
    pub explanation: Vec<String>,
}

impl UnifiedAdmissionBrownoutLedger {
    /// Compose the first-party overload controllers into one deterministic policy verdict.
    #[must_use]
    pub fn evaluate(
        evidence: &UnifiedAdmissionBrownoutEvidence,
        profile: &UnifiedAdmissionBrownoutProfile,
    ) -> Self {
        let preserved_critical_surface_units = evidence
            .critical_surface_units
            .max(profile.critical_surface_floor_units);
        let preserved_telemetry_units = profile.preserved_telemetry_floor_units;
        let mut reason_codes = vec![
            UnifiedAdmissionBrownoutReason::CriticalSurfacePreserved,
            UnifiedAdmissionBrownoutReason::TelemetryMinimumPreserved,
        ];
        let mut explanation = vec![
            "critical scheduling, cancellation drain, region quiescence, obligation cleanup, and minimum telemetry stay preserved before optional shedding is considered"
                .to_string(),
        ];
        let input_fallback_used = evidence.tail_risk.fallback_used
            || evidence.cohort_steering.fallback_used
            || evidence.brownout.fallback_used;
        let confidence_percent = evidence
            .tail_risk
            .confidence_percent
            .min(evidence.cohort_steering.confidence_percent)
            .min(100);

        if !profile.enabled {
            reason_codes.push(UnifiedAdmissionBrownoutReason::Disabled);
            reason_codes.push(UnifiedAdmissionBrownoutReason::ConservativeBaseline);
            explanation.push(
                "unified policy is disabled, so the conservative fully-admitted baseline stayed pinned"
                    .to_string(),
            );
            return Self::finish(
                profile,
                UnifiedAdmissionBrownoutPhase::Normal,
                UnifiedAdmissionAction::Admit,
                UnifiedBrownoutAction::KeepFullSurfaces,
                true,
                confidence_percent,
                reason_codes,
                evidence.offered_work_units,
                preserved_telemetry_units,
                preserved_critical_surface_units,
                Vec::new(),
                Vec::new(),
                evidence.brownout.preserved_surfaces.clone(),
                false,
                None,
                explanation,
            );
        }

        let low_confidence = confidence_percent < profile.min_confidence_percent;
        if low_confidence {
            reason_codes.push(UnifiedAdmissionBrownoutReason::LowConfidenceFallback);
            explanation.push(format!(
                "minimum controller confidence {}% stayed below the unified policy floor {}%",
                confidence_percent, profile.min_confidence_percent
            ));
        }

        let fairness_escape = evidence
            .cohort_steering
            .reason_codes
            .contains(&CohortAdmissionSteeringReason::FairnessEscapeHatch);
        if fairness_escape {
            reason_codes.push(UnifiedAdmissionBrownoutReason::CohortFairnessEscape);
            explanation.push(
                "cohort steering recorded a fairness escape hatch, so tail-admitted work keeps an admission path"
                    .to_string(),
            );
        }

        let mut admission_action = match evidence.tail_risk.decision {
            TailRiskAdmissionDecision::Shed => {
                reason_codes.push(UnifiedAdmissionBrownoutReason::TailRiskShedPrecedence);
                explanation
                    .push("tail-risk shed takes precedence over cohort placement".to_string());
                UnifiedAdmissionAction::Refuse
            }
            TailRiskAdmissionDecision::Defer => {
                reason_codes.push(UnifiedAdmissionBrownoutReason::TailRiskDeferPrecedence);
                explanation
                    .push("tail-risk defer takes precedence over cohort placement".to_string());
                UnifiedAdmissionAction::Defer
            }
            TailRiskAdmissionDecision::Admit => match evidence.cohort_steering.decision {
                CohortAdmissionSteeringDecision::Defer if !fairness_escape => {
                    reason_codes.push(UnifiedAdmissionBrownoutReason::CohortSteeringDefer);
                    explanation.push(
                        "cohort steering deferred after tail-risk admission because no safe placement was available"
                            .to_string(),
                    );
                    UnifiedAdmissionAction::Defer
                }
                CohortAdmissionSteeringDecision::AdmitLocal
                | CohortAdmissionSteeringDecision::RedirectRemote
                | CohortAdmissionSteeringDecision::Defer => UnifiedAdmissionAction::Admit,
            },
        };

        if low_confidence && admission_action == UnifiedAdmissionAction::Admit {
            admission_action = UnifiedAdmissionAction::Defer;
        }

        let brownout_action = match evidence.brownout.phase {
            OverloadBrownoutPhase::Normal if evidence.brownout.restored_surfaces.is_empty() => {
                UnifiedBrownoutAction::KeepFullSurfaces
            }
            OverloadBrownoutPhase::Normal | OverloadBrownoutPhase::Recovery => {
                reason_codes.push(UnifiedAdmissionBrownoutReason::RestorationHysteresisSatisfied);
                explanation.push("brownout recovery restored optional surfaces".to_string());
                UnifiedBrownoutAction::RestoreOptional
            }
            OverloadBrownoutPhase::Observe => {
                reason_codes.push(UnifiedAdmissionBrownoutReason::BrownoutObservePrecedence);
                UnifiedBrownoutAction::Observe
            }
            OverloadBrownoutPhase::Degrade => {
                reason_codes.push(UnifiedAdmissionBrownoutReason::BrownoutDegradePrecedence);
                UnifiedBrownoutAction::DegradeOptional
            }
            OverloadBrownoutPhase::ShedOptional => {
                reason_codes.push(UnifiedAdmissionBrownoutReason::BrownoutShedPrecedence);
                UnifiedBrownoutAction::ShedOptional
            }
        };

        let phase = match (admission_action, brownout_action) {
            (UnifiedAdmissionAction::Refuse, _) => UnifiedAdmissionBrownoutPhase::Refuse,
            (_, UnifiedBrownoutAction::ShedOptional) => UnifiedAdmissionBrownoutPhase::ShedOptional,
            (UnifiedAdmissionAction::Defer, _) => UnifiedAdmissionBrownoutPhase::Defer,
            (_, UnifiedBrownoutAction::DegradeOptional) => UnifiedAdmissionBrownoutPhase::Degrade,
            (_, UnifiedBrownoutAction::RestoreOptional) => UnifiedAdmissionBrownoutPhase::Recovery,
            (_, UnifiedBrownoutAction::Observe) => UnifiedAdmissionBrownoutPhase::Observe,
            (UnifiedAdmissionAction::Admit, UnifiedBrownoutAction::KeepFullSurfaces) => {
                UnifiedAdmissionBrownoutPhase::Normal
            }
        };

        let no_win_decision = low_confidence
            || (input_fallback_used && admission_action != UnifiedAdmissionAction::Admit);
        let fallback_reason = no_win_decision.then(|| {
            if low_confidence {
                "low_confidence_fallback".to_string()
            } else {
                "controller_fallback_used".to_string()
            }
        });

        Self::finish(
            profile,
            phase,
            admission_action,
            brownout_action,
            input_fallback_used || low_confidence,
            confidence_percent,
            reason_codes,
            evidence.offered_work_units,
            preserved_telemetry_units,
            preserved_critical_surface_units,
            evidence.brownout.requested_degraded_surfaces.clone(),
            evidence.brownout.restored_surfaces.clone(),
            evidence.brownout.preserved_surfaces.clone(),
            no_win_decision,
            fallback_reason,
            explanation,
        )
    }

    fn finish(
        profile: &UnifiedAdmissionBrownoutProfile,
        phase: UnifiedAdmissionBrownoutPhase,
        admission_action: UnifiedAdmissionAction,
        brownout_action: UnifiedBrownoutAction,
        fallback_used: bool,
        confidence_percent: u8,
        reason_codes: Vec<UnifiedAdmissionBrownoutReason>,
        offered_work_units: u64,
        preserved_telemetry_units: u16,
        preserved_critical_surface_units: u64,
        requested_degraded_surfaces: Vec<BrownoutOptionalSurface>,
        restored_surfaces: Vec<BrownoutOptionalSurface>,
        preserved_surfaces: Vec<BrownoutProtectedSurface>,
        no_win_decision: bool,
        fallback_reason: Option<String>,
        explanation: Vec<String>,
    ) -> Self {
        let (admitted_units, deferred_units, refused_units) =
            unified_admission_counts(offered_work_units, admission_action, profile);
        Self {
            schema_version: UNIFIED_ADMISSION_BROWNOUT_LEDGER_SCHEMA_VERSION.to_string(),
            phase,
            admission_action,
            brownout_action,
            fallback_used,
            confidence_percent,
            reason_codes,
            admitted_units,
            deferred_units,
            refused_units,
            preserved_telemetry_units,
            preserved_critical_surface_units,
            requested_degraded_surfaces,
            restored_surfaces,
            preserved_surfaces,
            no_win_decision,
            fallback_reason,
            profile: profile.clone(),
            explanation,
        }
    }
}

fn unified_admission_counts(
    offered_work_units: u64,
    admission_action: UnifiedAdmissionAction,
    profile: &UnifiedAdmissionBrownoutProfile,
) -> (u64, u64, u64) {
    match admission_action {
        UnifiedAdmissionAction::Admit => (offered_work_units, 0, 0),
        UnifiedAdmissionAction::Defer => {
            let admitted = offered_work_units
                .saturating_mul(u64::from(profile.defer_admit_basis_points.min(10_000)))
                / 10_000;
            (admitted, offered_work_units.saturating_sub(admitted), 0)
        }
        UnifiedAdmissionAction::Refuse => (0, 0, offered_work_units),
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
    let max = u128::from(max_limit);
    let soft = (max * u128::from(soft_pct)) / 100;
    let hard = (max * u128::from(hard_pct)) / 100;
    (soft.min(max) as u64, hard.min(max) as u64)
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
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    const ADDRESS_SPACE_FALLBACK: u64 = 16 * 1024 * 1024 * 1024;

    #[cfg(target_os = "linux")]
    pub fn process_rss_bytes() -> std::io::Result<u64> {
        let status = std::fs::read_to_string("/proc/self/status")?;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                let kib_str = rest.split_whitespace().next().ok_or_else(|| {
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
                let kib_str = rest.split_whitespace().next().ok_or_else(|| {
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
        let infinity = libc::RLIM_INFINITY;
        let cur = if rlim.rlim_cur == infinity {
            u64::MAX
        } else {
            rlim.rlim_cur as u64
        };
        let max = if rlim.rlim_max == infinity {
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
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub fn address_space_rlimit() -> std::io::Result<(u64, u64)> {
        Ok((u64::MAX, u64::MAX))
    }

    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub fn num_cpus() -> u64 {
        std::thread::available_parallelism().map_or(1, |n| n.get() as u64)
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct SystemResourceCollector {
    /// Whether monitoring is active.
    ///
    /// This is a lifecycle gate for start/stop/status observers, not a
    /// publication point for sampled resource data, so acquire/release
    /// ordering is enough and avoids a global `SeqCst` fence here.
    active: AtomicBool,
    /// Collection interval.
    interval: Duration,
    /// Collected data.
    pressure: Arc<ResourcePressure>,
    /// Operator-facing platform probe state.
    probe_state: Arc<ResourceProbeState>,
}

impl SystemResourceCollector {
    /// Create a new system resource collector.
    pub fn new(pressure: Arc<ResourcePressure>, interval: Duration) -> Self {
        Self {
            active: AtomicBool::new(false),
            interval,
            pressure,
            probe_state: Arc::new(ResourceProbeState::new(current_platform_fingerprint())),
        }
    }

    /// Start monitoring system resources.
    pub fn start(&self) -> Result<(), ResourceMonitorError> {
        if self
            .active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
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
        self.active.store(false, Ordering::Release);
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

    /// Report platform probe availability and fallback state for operators.
    pub fn platform_probe_report(&self) -> ResourcePlatformProbeReport {
        self.probe_state.report()
    }

    fn observe_probe<T>(
        &self,
        probe: ResourceProbe,
        fallback: ResourceProbeFallback,
        result: std::io::Result<T>,
        sampled_value: impl FnOnce(&T) -> Option<u64>,
    ) -> std::io::Result<T> {
        match result {
            Ok(value) => {
                self.probe_state
                    .record_supported(probe, sampled_value(&value));
                Ok(value)
            }
            Err(error) => {
                self.probe_state
                    .record_probe_failure(probe, fallback, &error);
                Err(error)
            }
        }
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
        let current_bytes_result = self.observe_probe(
            ResourceProbe::ProcessRssBytes,
            ResourceProbeFallback::OmitMeasurement,
            platform::process_rss_bytes(),
            |value| Some(*value),
        );
        let max_limit_result = self.observe_probe(
            ResourceProbe::MemoryMaxBytes,
            ResourceProbeFallback::OmitMeasurement,
            platform::memory_max_bytes(),
            |value| Some(*value),
        );

        let current_bytes =
            current_bytes_result.map_err(|e| ResourceMonitorError::SystemAccessFailed {
                reason: format!("memory rss: {e}"),
            })?;
        let max_limit = max_limit_result.map_err(|e| ResourceMonitorError::SystemAccessFailed {
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
        let current_fds_result = self.observe_probe(
            ResourceProbe::ProcessFdCount,
            ResourceProbeFallback::OmitMeasurement,
            platform::process_fd_count(),
            |value| Some(*value),
        );
        let fd_limit_result = self.observe_probe(
            ResourceProbe::FileDescriptorLimit,
            ResourceProbeFallback::OmitMeasurement,
            platform::fd_rlimit(),
            |(_, hard)| Some(*hard),
        );

        let current_fds =
            current_fds_result.map_err(|e| ResourceMonitorError::SystemAccessFailed {
                reason: format!("fd count: {e}"),
            })?;
        let (_, hard_max) =
            fd_limit_result.map_err(|e| ResourceMonitorError::SystemAccessFailed {
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
        let load_avg_1min = self
            .observe_probe(
                ResourceProbe::LoadAvg1MinScaled,
                ResourceProbeFallback::OmitMeasurement,
                platform::load_avg_1min_scaled(),
                |value| Some(*value),
            )
            .map_err(|e| ResourceMonitorError::SystemAccessFailed {
                reason: format!("loadavg: {e}"),
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
        let current_connections_result = self.observe_probe(
            ResourceProbe::ProcessConnectionCount,
            ResourceProbeFallback::OmitMeasurement,
            platform::process_connection_count(),
            |value| Some(*value),
        );
        let fd_limit_result = self.observe_probe(
            ResourceProbe::NetworkConnectionLimit,
            ResourceProbeFallback::ConservativeDefault,
            platform::fd_rlimit(),
            |(_, hard)| Some(*hard),
        );

        let current_connections =
            current_connections_result.map_err(|e| ResourceMonitorError::SystemAccessFailed {
                reason: format!("connection count: {e}"),
            })?;
        // Sockets share the FD table, so the connection ceiling is at
        // most RLIMIT_NOFILE. Use a reasonable fallback when the
        // rlimit is unavailable.
        let (_, hard_max) = fd_limit_result.unwrap_or((512, 1024));
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
        self.active.load(Ordering::Acquire)
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
            platform_probe_report: self.collector.platform_probe_report(),
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
    pub platform_probe_report: ResourcePlatformProbeReport,
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
    use serde_json::{Value, json};
    use std::collections::hash_map::DefaultHasher;
    use std::fs;
    use std::hash::{Hash, Hasher};
    use std::path::Path;

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

    #[test]
    fn m4oxsk_supported_probe_reporting_records_sampled_value() {
        let state = ResourceProbeState::new("fake-linux/x86_64");

        state.record_supported(ResourceProbe::ProcessRssBytes, Some(4096));

        let report = state.report();
        assert_eq!(report.supported_count, 1);
        assert_eq!(report.unavailable_count, 0);
        assert_eq!(report.fallback_count, 0);
        assert_eq!(
            report.operator_verdict,
            ResourceProbeOperatorVerdict::Complete
        );
        assert_eq!(report.probes[0].sampled_value, Some(4096));
        assert_eq!(report.probes[0].resource_type, ResourceType::Memory);
    }

    #[test]
    fn m4oxsk_unsupported_probe_reporting_is_typed() {
        let state = ResourceProbeState::new("fake-unsupported/wasm32");
        let error = std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "not implemented on fake platform",
        );

        state.record_probe_failure(
            ResourceProbe::ProcessFdCount,
            ResourceProbeFallback::OmitMeasurement,
            &error,
        );

        let report = state.report();
        let probe = &report.probes[0];
        assert_eq!(report.unavailable_count, 1);
        assert_eq!(report.warning_emitted_count, 1);
        assert_eq!(
            report.operator_verdict,
            ResourceProbeOperatorVerdict::DegradedWithUnavailableProbes
        );
        assert_eq!(probe.status, ResourceProbeStatus::Unavailable);
        assert_eq!(
            probe.fallback,
            ResourceProbeFallback::CustomCollectorRequired
        );
        assert_eq!(probe.probe, ResourceProbe::ProcessFdCount);
        assert!(probe.error_message.as_deref().unwrap().contains("fake"));
    }

    #[test]
    fn m4oxsk_fallback_aggregation_preserves_operator_semantics() {
        let state = ResourceProbeState::new("fake-bsd/aarch64");
        let error = std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "fd rlimit inaccessible",
        );

        state.record_probe_failure(
            ResourceProbe::NetworkConnectionLimit,
            ResourceProbeFallback::ConservativeDefault,
            &error,
        );

        let report = state.report();
        assert_eq!(report.fallback_count, 1);
        assert_eq!(report.unavailable_count, 0);
        assert_eq!(
            report.operator_verdict,
            ResourceProbeOperatorVerdict::DegradedWithFallbacks
        );
        assert_eq!(report.probes[0].status, ResourceProbeStatus::Fallback);
        assert_eq!(
            report.probes[0].fallback,
            ResourceProbeFallback::ConservativeDefault
        );
    }

    #[test]
    fn m4oxsk_warning_throttling_suppresses_repeated_probe_failures() {
        let state = ResourceProbeState::new("fake-linux/x86_64");

        for attempt in 0..9 {
            let error = std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("transient probe failure {attempt}"),
            );
            state.record_probe_failure(
                ResourceProbe::LoadAvg1MinScaled,
                ResourceProbeFallback::OmitMeasurement,
                &error,
            );
        }

        let report = state.report();
        assert_eq!(report.warning_emitted_count, 2);
        assert_eq!(report.warning_suppressed_count, 7);
        assert_eq!(report.probes[0].warning_count, 9);
        assert_eq!(report.probes[0].warning_suppressed_count, 7);
    }

    #[test]
    fn m4oxsk_unavailable_probe_report_serializes_operator_fields() {
        let state = ResourceProbeState::new("fake-windows/x86_64");
        let error =
            std::io::Error::new(std::io::ErrorKind::Unsupported, "load average unavailable");

        state.record_probe_failure(
            ResourceProbe::LoadAvg1MinScaled,
            ResourceProbeFallback::OmitMeasurement,
            &error,
        );

        let report = state.report();
        let json = serde_json::to_string_pretty(&report).expect("serialize report");
        let value: Value = serde_json::from_str(&json).expect("parse report json");

        assert_eq!(
            value["schema_version"],
            RESOURCE_MONITOR_PLATFORM_GAP_REPORT_SCHEMA_VERSION
        );
        assert_eq!(value["probes"][0]["probe"], "load_avg_1min_scaled");
        assert_eq!(value["probes"][0]["status"], "unavailable");
        assert_eq!(value["probes"][0]["fallback"], "custom_collector_required");
        assert_eq!(
            value["operator_verdict"],
            "degraded_with_unavailable_probes"
        );
    }

    #[test]
    fn m4oxsk_disabled_monitor_probe_report_is_explicit() {
        let state = ResourceProbeState::new("fake-disabled/noarch");

        state.record_disabled(ResourceProbe::ProcessRssBytes);
        state.record_disabled(ResourceProbe::LoadAvg1MinScaled);

        let report = state.report();
        assert_eq!(report.disabled_count, 2);
        assert_eq!(report.warning_emitted_count, 0);
        assert_eq!(report.warning_suppressed_count, 0);
        assert_eq!(
            report.operator_verdict,
            ResourceProbeOperatorVerdict::Disabled
        );
        assert!(report.probes.iter().all(|probe| {
            probe.status == ResourceProbeStatus::Disabled
                && probe.fallback == ResourceProbeFallback::MonitorDisabled
        }));
    }

    #[test]
    fn m4oxsk_status_report_carries_platform_probe_inventory() {
        let monitor = ResourceMonitor::new(MonitorConfig::default());

        let status = monitor.status_report();

        assert!(!status.is_active);
        assert_eq!(
            status.platform_probe_report.schema_version,
            RESOURCE_MONITOR_PLATFORM_GAP_REPORT_SCHEMA_VERSION
        );
        assert_eq!(
            status.platform_probe_report.platform,
            current_platform_fingerprint()
        );
    }

    #[test]
    fn rz7cpt_system_resource_collector_active_flag_tracks_lifecycle() {
        let pressure = Arc::new(ResourcePressure::new());
        let collector = SystemResourceCollector::new(pressure, Duration::from_millis(50));

        assert!(!collector.is_active());
        collector.start().expect("collector should start once");
        assert!(collector.is_active());
        assert!(matches!(
            collector.start(),
            Err(ResourceMonitorError::AlreadyActive)
        ));
        assert!(collector.is_active());

        collector.stop();
        assert!(!collector.is_active());
        collector
            .start()
            .expect("collector should restart after stop");
        assert!(collector.is_active());
        collector.stop();
    }

    #[test]
    fn m4oxsk_resource_monitor_platform_gap_smoke_emits_operator_report() {
        let state = ResourceProbeState::new("host-template/linux-or-fallback");
        let unsupported = std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "template host lacks process fd probe",
        );
        let fallback = std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "template host hides connection limit",
        );

        state.record_supported(ResourceProbe::ProcessRssBytes, Some(12_288));
        state.record_probe_failure(
            ResourceProbe::ProcessFdCount,
            ResourceProbeFallback::OmitMeasurement,
            &unsupported,
        );
        state.record_probe_failure(
            ResourceProbe::NetworkConnectionLimit,
            ResourceProbeFallback::ConservativeDefault,
            &fallback,
        );
        state.record_disabled(ResourceProbe::MemoryMaxBytes);

        let report = state.report();
        let probe_list: Vec<Value> = report
            .probes
            .iter()
            .map(|probe| {
                json!({
                    "probe": probe.probe,
                    "resource_type": probe.resource_type,
                    "status": probe.status,
                    "fallback": probe.fallback,
                    "sampled_value": probe.sampled_value,
                    "error_message": probe.error_message,
                })
            })
            .collect();
        let smoke_report = json!({
            "schema_version": report.schema_version,
            "platform_fingerprint": report.platform,
            "probe_list": probe_list,
            "supported_count": report.supported_count,
            "unavailable_count": report.unavailable_count,
            "fallback_count": report.fallback_count,
            "disabled_count": report.disabled_count,
            "warning_emitted_count": report.warning_emitted_count,
            "warning_suppressed_count": report.warning_suppressed_count,
            "sampled_values": report.probes.iter().filter_map(|probe| {
                probe.sampled_value.map(|value| json!({
                    "probe": probe.probe,
                    "value": value,
                }))
            }).collect::<Vec<_>>(),
            "error_messages": report.probes.iter().filter_map(|probe| {
                probe.error_message.as_ref().map(|message| json!({
                    "probe": probe.probe,
                    "message": message,
                    "fallback": probe.fallback,
                }))
            }).collect::<Vec<_>>(),
            "final_operator_verdict": report.operator_verdict,
        });

        assert_eq!(smoke_report["supported_count"], 1);
        assert_eq!(smoke_report["unavailable_count"], 1);
        assert_eq!(smoke_report["fallback_count"], 1);
        assert_eq!(smoke_report["disabled_count"], 1);
        assert_eq!(
            smoke_report["final_operator_verdict"],
            "degraded_with_unavailable_probes"
        );

        if std::env::var_os("ASUPERSYNC_RESOURCE_MONITOR_PLATFORM_GAP_REPORT").is_some() {
            println!("RESOURCE_MONITOR_PLATFORM_GAP_REPORT_JSON_BEGIN");
            println!(
                "{}",
                serde_json::to_string_pretty(&smoke_report).expect("serialize smoke report")
            );
            println!("RESOURCE_MONITOR_PLATFORM_GAP_REPORT_JSON_END");
        }
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
        assert_eq!(s, ((u128::from(u64::MAX) * 75) / 100) as u64);
        assert_eq!(h, ((u128::from(u64::MAX) * 90) / 100) as u64);
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

    fn sample_scheduler_metrics() -> SchedulerEvidenceMetrics {
        SchedulerEvidenceMetrics {
            wake_to_run_p50_ns: 8_000,
            wake_to_run_p95_ns: 90_000,
            wake_to_run_p99_ns: 220_000,
            queue_residency_p50_ns: 16_000,
            queue_residency_p95_ns: 200_000,
            queue_residency_p99_ns: 520_000,
            ready_backlog_p95: 192,
            ready_backlog_p99: 320,
            cancel_debt_p95: 48,
            cancel_debt_p99: 128,
            remote_steal_ratio_pct: Some(42),
            cross_cohort_wake_p99_ns: Some(180_000),
        }
    }

    #[test]
    fn tail_risk_admission_falls_back_when_evidence_is_missing() {
        let ledger = TailRiskAdmissionLedger::evaluate(
            &TailRiskAdmissionEvidence {
                scheduler: None,
                retry_pressure_p99: Some(12),
                memory_pressure_bps: Some(7_200),
                degradation_level: DegradationLevel::Moderate,
            },
            &TailRiskAdmissionProfile::default(),
        );
        assert!(
            ledger.fallback_used,
            "missing evidence must trigger fallback"
        );
        assert_eq!(ledger.decision, TailRiskAdmissionDecision::Defer);
        assert_eq!(
            ledger.reason_codes,
            vec![TailRiskAdmissionReason::ConservativeFallback]
        );
        assert_eq!(
            ledger.missing_evidence_fields,
            vec!["scheduler_metrics".to_string()]
        );
    }

    #[test]
    fn tail_risk_admission_is_deterministic_for_fixed_inputs() {
        let evidence = TailRiskAdmissionEvidence {
            scheduler: Some(sample_scheduler_metrics()),
            retry_pressure_p99: Some(40),
            memory_pressure_bps: Some(8_700),
            degradation_level: DegradationLevel::Moderate,
        };
        let profile = TailRiskAdmissionProfile::default();
        let first = TailRiskAdmissionLedger::evaluate(&evidence, &profile);
        for _ in 0..8 {
            let next = TailRiskAdmissionLedger::evaluate(&evidence, &profile);
            assert_eq!(first, next, "fixed evidence must stay deterministic");
        }
    }

    #[test]
    fn tail_risk_admission_transitions_across_overload_bands() {
        let profile = TailRiskAdmissionProfile::default();
        let mild = TailRiskAdmissionLedger::evaluate(
            &TailRiskAdmissionEvidence {
                scheduler: Some(SchedulerEvidenceMetrics {
                    wake_to_run_p50_ns: 6_000,
                    wake_to_run_p95_ns: 50_000,
                    wake_to_run_p99_ns: 80_000,
                    queue_residency_p50_ns: 10_000,
                    queue_residency_p95_ns: 90_000,
                    queue_residency_p99_ns: 140_000,
                    ready_backlog_p95: 96,
                    ready_backlog_p99: 120,
                    cancel_debt_p95: 24,
                    cancel_debt_p99: 40,
                    remote_steal_ratio_pct: Some(18),
                    cross_cohort_wake_p99_ns: Some(80_000),
                }),
                retry_pressure_p99: Some(6),
                memory_pressure_bps: Some(6_800),
                degradation_level: DegradationLevel::None,
            },
            &profile,
        );
        let medium = TailRiskAdmissionLedger::evaluate(
            &TailRiskAdmissionEvidence {
                scheduler: Some(SchedulerEvidenceMetrics {
                    wake_to_run_p50_ns: 8_000,
                    wake_to_run_p95_ns: 90_000,
                    wake_to_run_p99_ns: 170_000,
                    queue_residency_p50_ns: 16_000,
                    queue_residency_p95_ns: 220_000,
                    queue_residency_p99_ns: 420_000,
                    ready_backlog_p95: 188,
                    ready_backlog_p99: 220,
                    cancel_debt_p95: 42,
                    cancel_debt_p99: 78,
                    remote_steal_ratio_pct: Some(34),
                    cross_cohort_wake_p99_ns: Some(140_000),
                }),
                retry_pressure_p99: Some(36),
                memory_pressure_bps: Some(7_900),
                degradation_level: DegradationLevel::Light,
            },
            &profile,
        );
        let severe = TailRiskAdmissionLedger::evaluate(
            &TailRiskAdmissionEvidence {
                scheduler: Some(sample_scheduler_metrics()),
                retry_pressure_p99: Some(52),
                memory_pressure_bps: Some(9_450),
                degradation_level: DegradationLevel::Heavy,
            },
            &profile,
        );
        assert_eq!(mild.decision, TailRiskAdmissionDecision::Admit);
        assert_eq!(medium.decision, TailRiskAdmissionDecision::Defer);
        assert_eq!(severe.decision, TailRiskAdmissionDecision::Shed);
    }

    #[test]
    fn tail_risk_admission_ledger_round_trips_through_json() {
        let ledger = TailRiskAdmissionLedger::evaluate(
            &TailRiskAdmissionEvidence {
                scheduler: Some(sample_scheduler_metrics()),
                retry_pressure_p99: Some(40),
                memory_pressure_bps: Some(8_700),
                degradation_level: DegradationLevel::Moderate,
            },
            &TailRiskAdmissionProfile::default(),
        );
        let json = serde_json::to_string_pretty(&ledger).expect("serialize ledger");
        let reparsed: TailRiskAdmissionLedger =
            serde_json::from_str(&json).expect("deserialize ledger");
        assert_eq!(reparsed, ledger);
    }

    #[test]
    fn tail_risk_admission_sheds_on_tail_and_memory_storm() {
        let ledger = TailRiskAdmissionLedger::evaluate(
            &TailRiskAdmissionEvidence {
                scheduler: Some(sample_scheduler_metrics()),
                retry_pressure_p99: Some(48),
                memory_pressure_bps: Some(9_400),
                degradation_level: DegradationLevel::Heavy,
            },
            &TailRiskAdmissionProfile::default(),
        );
        assert_eq!(ledger.decision, TailRiskAdmissionDecision::Shed);
        assert!(!ledger.fallback_used);
        assert!(
            ledger
                .reason_codes
                .contains(&TailRiskAdmissionReason::MemoryPressure)
        );
        assert!(
            ledger
                .reason_codes
                .contains(&TailRiskAdmissionReason::QueueResidencyTail)
        );
    }

    #[test]
    fn degradation_engine_evaluates_tail_risk_admission_from_pressure_band() {
        let pressure = Arc::new(ResourcePressure::new());
        let engine = DegradationEngine::new(Arc::clone(&pressure));
        pressure.update_degradation_level(ResourceType::Memory, DegradationLevel::Moderate);
        let ledger = engine.evaluate_tail_risk_admission(
            Some(&sample_scheduler_metrics()),
            Some(40),
            Some(8_300),
            &TailRiskAdmissionProfile::default(),
        );
        assert_eq!(ledger.degradation_level, DegradationLevel::Moderate);
        assert_eq!(ledger.decision, TailRiskAdmissionDecision::Shed);
        assert!(
            ledger
                .reason_codes
                .contains(&TailRiskAdmissionReason::ExistingDegradation)
        );
    }

    const TAIL_RISK_ADMISSION_CONTRACT_PATH_ENV: &str =
        "ASUPERSYNC_TAIL_RISK_ADMISSION_CONTRACT_PATH";
    const TAIL_RISK_ADMISSION_SCENARIO_ENV: &str = "ASUPERSYNC_TAIL_RISK_ADMISSION_SCENARIO";
    const TAIL_RISK_ADMISSION_REPORT_PATH_ENV: &str = "ASUPERSYNC_TAIL_RISK_ADMISSION_REPORT_PATH";
    const TAIL_RISK_ADMISSION_REPORT_SCHEMA_VERSION: &str = "tail-risk-admission-report-v1";
    const TAIL_RISK_ADMISSION_PROJECTION_SCHEMA_VERSION: &str = "tail-risk-admission-projection-v1";
    const TAIL_RISK_ADMISSION_MIXED_SCENARIO_ID: &str = "AA-TAIL-RISK-ADMISSION-MIXED-OVERLOAD";
    const TAIL_RISK_ADMISSION_FALLBACK_SCENARIO_ID: &str =
        "AA-TAIL-RISK-ADMISSION-CONSERVATIVE-FALLBACK";

    #[derive(Debug, Clone, Deserialize)]
    struct TailRiskAdmissionSmokeContract {
        smoke_scenarios: Vec<TailRiskAdmissionScenario>,
    }

    #[derive(Debug, Clone, Deserialize)]
    struct TailRiskAdmissionScenario {
        scenario_id: String,
        description: String,
        workload_class: String,
        tail_risk_profile: TailRiskAdmissionProfile,
        fixed_threshold_profile: FixedThresholdAdmissionProfile,
        fixture: TailRiskAdmissionFixture,
        expected_report_projection: Value,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct FixedThresholdAdmissionProfile {
        ready_backlog_soft_limit: usize,
        ready_backlog_hard_limit: usize,
        memory_pressure_soft_bps: u16,
        memory_pressure_hard_bps: u16,
        moderate_degradation_sheds: bool,
    }

    #[derive(Debug, Clone, Deserialize)]
    struct TailRiskAdmissionFixture {
        base_service_ns: u64,
        replay_count: usize,
        windows: Vec<TailRiskAdmissionWindow>,
    }

    #[derive(Debug, Clone, Deserialize)]
    struct TailRiskAdmissionWindow {
        window_id: String,
        wake_to_run_p99_ns: Option<u64>,
        queue_residency_p99_ns: Option<u64>,
        ready_backlog_p99: Option<usize>,
        cancel_debt_p99: Option<usize>,
        retry_pressure_p99: Option<u64>,
        memory_pressure_bps: Option<u16>,
        degradation_level: DegradationLevel,
        offered_work_units: u64,
    }

    #[derive(Debug, Clone, Serialize)]
    struct PolicySummary {
        decision_counts: Value,
        admitted_units: u64,
        deferred_units: u64,
        shed_units: u64,
        fallback_used_count: u64,
        mean_expected_loss_score: f64,
        p50_latency_ns: u64,
        p95_latency_ns: u64,
        p99_latency_ns: u64,
        max_latency_ns: u64,
        throughput_ratio: f64,
    }

    #[derive(Debug, Clone)]
    struct PolicyAccumulator {
        admit_count: u64,
        defer_count: u64,
        shed_count: u64,
        admitted_units: u64,
        deferred_units: u64,
        shed_units: u64,
        fallback_used_count: u64,
        loss_score_sum: u64,
        loss_score_count: u64,
        latencies: Vec<u64>,
    }

    impl PolicyAccumulator {
        fn record(
            &mut self,
            decision: TailRiskAdmissionDecision,
            fallback_used: bool,
            expected_loss_score: u8,
            outcome: &WindowOutcome,
        ) {
            match decision {
                TailRiskAdmissionDecision::Admit => self.admit_count += 1,
                TailRiskAdmissionDecision::Defer => self.defer_count += 1,
                TailRiskAdmissionDecision::Shed => self.shed_count += 1,
            }
            self.admitted_units = self.admitted_units.saturating_add(outcome.admitted_units);
            self.deferred_units = self.deferred_units.saturating_add(outcome.deferred_units);
            self.shed_units = self.shed_units.saturating_add(outcome.shed_units);
            if fallback_used {
                self.fallback_used_count += 1;
            }
            self.loss_score_sum = self
                .loss_score_sum
                .saturating_add(u64::from(expected_loss_score));
            self.loss_score_count += 1;
            self.latencies.extend_from_slice(&outcome.latency_samples);
        }

        fn summary(&self, total_offered_units: u64) -> PolicySummary {
            PolicySummary {
                decision_counts: json!({
                    "admit": self.admit_count,
                    "defer": self.defer_count,
                    "shed": self.shed_count,
                }),
                admitted_units: self.admitted_units,
                deferred_units: self.deferred_units,
                shed_units: self.shed_units,
                fallback_used_count: self.fallback_used_count,
                mean_expected_loss_score: ratio_u64(self.loss_score_sum, self.loss_score_count),
                p50_latency_ns: percentile_slice_u64(&self.latencies, 50, 100),
                p95_latency_ns: percentile_slice_u64(&self.latencies, 95, 100),
                p99_latency_ns: percentile_slice_u64(&self.latencies, 99, 100),
                max_latency_ns: self.latencies.iter().copied().max().unwrap_or(0),
                throughput_ratio: ratio_u64(self.admitted_units, total_offered_units),
            }
        }
    }

    #[derive(Debug, Clone)]
    struct WindowOutcome {
        admitted_units: u64,
        deferred_units: u64,
        shed_units: u64,
        latency_samples: Vec<u64>,
    }

    fn default_tail_risk_admission_scenarios() -> Vec<TailRiskAdmissionScenario> {
        vec![
            TailRiskAdmissionScenario {
                scenario_id: TAIL_RISK_ADMISSION_MIXED_SCENARIO_ID.to_string(),
                description: "Drive a deterministic mixed overload replay covering balanced traffic, retry storms, backlog spikes, and memory pressure while comparing the tail-risk controller against a fixed-threshold baseline.".to_string(),
                workload_class: "mixed-overload".to_string(),
                tail_risk_profile: TailRiskAdmissionProfile::default(),
                fixed_threshold_profile: FixedThresholdAdmissionProfile {
                    ready_backlog_soft_limit: 256,
                    ready_backlog_hard_limit: 320,
                    memory_pressure_soft_bps: 8_200,
                    memory_pressure_hard_bps: 9_200,
                    moderate_degradation_sheds: false,
                },
                fixture: TailRiskAdmissionFixture {
                    base_service_ns: 48_000,
                    replay_count: 2,
                    windows: vec![
                        TailRiskAdmissionWindow {
                            window_id: "steady".to_string(),
                            wake_to_run_p99_ns: Some(92_000),
                            queue_residency_p99_ns: Some(180_000),
                            ready_backlog_p99: Some(144),
                            cancel_debt_p99: Some(38),
                            retry_pressure_p99: Some(8),
                            memory_pressure_bps: Some(6_700),
                            degradation_level: DegradationLevel::None,
                            offered_work_units: 64,
                        },
                        TailRiskAdmissionWindow {
                            window_id: "retry_storm".to_string(),
                            wake_to_run_p99_ns: Some(176_000),
                            queue_residency_p99_ns: Some(430_000),
                            ready_backlog_p99: Some(224),
                            cancel_debt_p99: Some(72),
                            retry_pressure_p99: Some(41),
                            memory_pressure_bps: Some(7_800),
                            degradation_level: DegradationLevel::Light,
                            offered_work_units: 64,
                        },
                        TailRiskAdmissionWindow {
                            window_id: "backlog_and_cancel".to_string(),
                            wake_to_run_p99_ns: Some(164_000),
                            queue_residency_p99_ns: Some(360_000),
                            ready_backlog_p99: Some(248),
                            cancel_debt_p99: Some(118),
                            retry_pressure_p99: Some(22),
                            memory_pressure_bps: Some(7_950),
                            degradation_level: DegradationLevel::Moderate,
                            offered_work_units: 64,
                        },
                        TailRiskAdmissionWindow {
                            window_id: "memory_surge".to_string(),
                            wake_to_run_p99_ns: Some(236_000),
                            queue_residency_p99_ns: Some(540_000),
                            ready_backlog_p99: Some(308),
                            cancel_debt_p99: Some(132),
                            retry_pressure_p99: Some(55),
                            memory_pressure_bps: Some(9_450),
                            degradation_level: DegradationLevel::Heavy,
                            offered_work_units: 64,
                        },
                    ],
                },
                expected_report_projection: Value::Null,
            },
            TailRiskAdmissionScenario {
                scenario_id: TAIL_RISK_ADMISSION_FALLBACK_SCENARIO_ID.to_string(),
                description: "Remove key evidence fields and prove the controller falls back deterministically to the conservative degradation-band comparator with explicit missing-field explanations.".to_string(),
                workload_class: "low-confidence-fallback".to_string(),
                tail_risk_profile: TailRiskAdmissionProfile::default(),
                fixed_threshold_profile: FixedThresholdAdmissionProfile {
                    ready_backlog_soft_limit: 256,
                    ready_backlog_hard_limit: 320,
                    memory_pressure_soft_bps: 8_200,
                    memory_pressure_hard_bps: 9_200,
                    moderate_degradation_sheds: false,
                },
                fixture: TailRiskAdmissionFixture {
                    base_service_ns: 48_000,
                    replay_count: 1,
                    windows: vec![
                        TailRiskAdmissionWindow {
                            window_id: "missing_scheduler".to_string(),
                            wake_to_run_p99_ns: None,
                            queue_residency_p99_ns: None,
                            ready_backlog_p99: None,
                            cancel_debt_p99: None,
                            retry_pressure_p99: Some(18),
                            memory_pressure_bps: Some(7_500),
                            degradation_level: DegradationLevel::Moderate,
                            offered_work_units: 48,
                        },
                        TailRiskAdmissionWindow {
                            window_id: "missing_retry".to_string(),
                            wake_to_run_p99_ns: Some(128_000),
                            queue_residency_p99_ns: Some(240_000),
                            ready_backlog_p99: Some(180),
                            cancel_debt_p99: Some(52),
                            retry_pressure_p99: None,
                            memory_pressure_bps: Some(7_200),
                            degradation_level: DegradationLevel::Light,
                            offered_work_units: 48,
                        },
                        TailRiskAdmissionWindow {
                            window_id: "invalid_memory".to_string(),
                            wake_to_run_p99_ns: Some(156_000),
                            queue_residency_p99_ns: Some(280_000),
                            ready_backlog_p99: Some(196),
                            cancel_debt_p99: Some(66),
                            retry_pressure_p99: Some(20),
                            memory_pressure_bps: None,
                            degradation_level: DegradationLevel::Heavy,
                            offered_work_units: 48,
                        },
                    ],
                },
                expected_report_projection: Value::Null,
            },
        ]
    }

    fn load_tail_risk_admission_scenarios() -> Vec<TailRiskAdmissionScenario> {
        let Some(contract_path) = std::env::var(TAIL_RISK_ADMISSION_CONTRACT_PATH_ENV).ok() else {
            return default_tail_risk_admission_scenarios();
        };
        let contract: TailRiskAdmissionSmokeContract = serde_json::from_str(
            &fs::read_to_string(&contract_path).expect("read tail-risk admission contract"),
        )
        .expect("parse tail-risk admission contract");
        contract.smoke_scenarios
    }

    fn selected_tail_risk_admission_scenario() -> String {
        std::env::var(TAIL_RISK_ADMISSION_SCENARIO_ENV)
            .unwrap_or_else(|_| TAIL_RISK_ADMISSION_MIXED_SCENARIO_ID.to_string())
    }

    fn maybe_write_tail_risk_admission_report(path: &str, report: &Value) {
        let report_path = Path::new(path);
        if let Some(parent) = report_path.parent() {
            fs::create_dir_all(parent).expect("create tail-risk admission report directory");
        }
        fs::write(
            report_path,
            serde_json::to_string_pretty(report).expect("serialize tail-risk admission report"),
        )
        .expect("write tail-risk admission report");
    }

    fn ratio_u64(numerator: u64, denominator: u64) -> f64 {
        if denominator == 0 {
            return 0.0;
        }
        round4(numerator as f64 / denominator as f64)
    }

    fn round4(value: f64) -> f64 {
        (value * 10_000.0).round() / 10_000.0
    }

    fn percentile_slice_u64(samples: &[u64], numerator: usize, denominator: usize) -> u64 {
        if samples.is_empty() {
            return 0;
        }
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        let index = ((sorted.len() - 1) * numerator) / denominator;
        sorted[index]
    }

    fn sample_scheduler_metrics_from_window(
        window: &TailRiskAdmissionWindow,
        window_index: usize,
    ) -> Option<SchedulerEvidenceMetrics> {
        Some(SchedulerEvidenceMetrics {
            wake_to_run_p50_ns: window.wake_to_run_p99_ns?.saturating_div(10).max(1),
            wake_to_run_p95_ns: window
                .wake_to_run_p99_ns?
                .saturating_mul(8)
                .saturating_div(10),
            wake_to_run_p99_ns: window.wake_to_run_p99_ns?,
            queue_residency_p50_ns: window.queue_residency_p99_ns?.saturating_div(8).max(1),
            queue_residency_p95_ns: window
                .queue_residency_p99_ns?
                .saturating_mul(8)
                .saturating_div(10),
            queue_residency_p99_ns: window.queue_residency_p99_ns?,
            ready_backlog_p95: window
                .ready_backlog_p99?
                .saturating_sub(window.ready_backlog_p99?.saturating_div(6)),
            ready_backlog_p99: window.ready_backlog_p99?,
            cancel_debt_p95: window
                .cancel_debt_p99?
                .saturating_sub(window.cancel_debt_p99?.saturating_div(5)),
            cancel_debt_p99: window.cancel_debt_p99?,
            remote_steal_ratio_pct: Some((25 + window_index * 7) as u8),
            cross_cohort_wake_p99_ns: window
                .wake_to_run_p99_ns
                .map(|value| value.saturating_sub(12_000)),
        })
    }

    fn fixed_threshold_decision(
        window: &TailRiskAdmissionWindow,
        profile: &FixedThresholdAdmissionProfile,
    ) -> (TailRiskAdmissionDecision, Vec<&'static str>) {
        let mut reasons = Vec::new();
        if window.memory_pressure_bps.unwrap_or(10_001) >= profile.memory_pressure_hard_bps {
            reasons.push("memory_hard_limit");
        }
        if window.ready_backlog_p99.unwrap_or(usize::MAX) >= profile.ready_backlog_hard_limit {
            reasons.push("backlog_hard_limit");
        }
        if window.degradation_level >= DegradationLevel::Heavy
            || (profile.moderate_degradation_sheds
                && window.degradation_level >= DegradationLevel::Moderate)
        {
            reasons.push("degradation_band");
        }
        if !reasons.is_empty() {
            return (TailRiskAdmissionDecision::Shed, reasons);
        }

        if window
            .memory_pressure_bps
            .unwrap_or(profile.memory_pressure_soft_bps)
            >= profile.memory_pressure_soft_bps
        {
            reasons.push("memory_soft_limit");
        }
        if window
            .ready_backlog_p99
            .unwrap_or(profile.ready_backlog_soft_limit)
            >= profile.ready_backlog_soft_limit
        {
            reasons.push("backlog_soft_limit");
        }
        if window.degradation_level >= DegradationLevel::Moderate {
            reasons.push("moderate_degradation");
        }
        if !reasons.is_empty() {
            return (TailRiskAdmissionDecision::Defer, reasons);
        }

        (TailRiskAdmissionDecision::Admit, vec!["steady_state"])
    }

    fn simulate_window_outcome(
        decision: TailRiskAdmissionDecision,
        fixture: &TailRiskAdmissionFixture,
        window: &TailRiskAdmissionWindow,
        window_index: usize,
    ) -> WindowOutcome {
        let offered = window.offered_work_units;
        let (admitted_units, deferred_units, shed_units, overload_multiplier, decision_penalty) =
            match decision {
                TailRiskAdmissionDecision::Admit => (offered, 0, 0, 9_200, 18_000),
                TailRiskAdmissionDecision::Defer => (
                    offered.saturating_mul(78).saturating_div(100),
                    offered.saturating_sub(offered.saturating_mul(78).saturating_div(100)),
                    0,
                    6_200,
                    11_000,
                ),
                TailRiskAdmissionDecision::Shed => (
                    offered.saturating_mul(38).saturating_div(100),
                    0,
                    offered.saturating_sub(offered.saturating_mul(38).saturating_div(100)),
                    4_100,
                    7_000,
                ),
            };
        let wake = window.wake_to_run_p99_ns.unwrap_or(120_000);
        let queue = window.queue_residency_p99_ns.unwrap_or(260_000);
        let backlog = window.ready_backlog_p99.unwrap_or(180) as u64;
        let cancel_debt = window.cancel_debt_p99.unwrap_or(64) as u64;
        let retry = window.retry_pressure_p99.unwrap_or(18);
        let memory = u64::from(window.memory_pressure_bps.unwrap_or(7_500));
        let degradation = match window.degradation_level {
            DegradationLevel::None => 0,
            DegradationLevel::Light => 8,
            DegradationLevel::Moderate => 18,
            DegradationLevel::Heavy => 28,
            DegradationLevel::Emergency => 42,
        };
        let overload_score = wake.saturating_div(20_000)
            + queue.saturating_div(40_000)
            + backlog.saturating_div(14)
            + cancel_debt.saturating_div(9)
            + retry.saturating_mul(2)
            + memory.saturating_div(450)
            + degradation;
        let base_latency = fixture
            .base_service_ns
            .saturating_add(wake.saturating_div(3))
            .saturating_add(queue.saturating_div(4));

        let mut latency_samples = Vec::with_capacity(admitted_units as usize);
        for sample_idx in 0..admitted_units {
            let jitter = ((window_index as u64 * 19) + (sample_idx % 11) * 13).saturating_mul(157);
            let latency = base_latency
                .saturating_add(overload_score.saturating_mul(overload_multiplier))
                .saturating_add(decision_penalty)
                .saturating_add(jitter);
            latency_samples.push(latency);
        }

        WindowOutcome {
            admitted_units,
            deferred_units,
            shed_units,
            latency_samples,
        }
    }

    fn tail_risk_reason_label(reason: TailRiskAdmissionReason) -> &'static str {
        match reason {
            TailRiskAdmissionReason::WakeToRunTail => "wake_to_run_tail",
            TailRiskAdmissionReason::QueueResidencyTail => "queue_residency_tail",
            TailRiskAdmissionReason::BacklogPressure => "backlog_pressure",
            TailRiskAdmissionReason::CancelDebtPressure => "cancel_debt_pressure",
            TailRiskAdmissionReason::RetryPressure => "retry_pressure",
            TailRiskAdmissionReason::MemoryPressure => "memory_pressure",
            TailRiskAdmissionReason::ExistingDegradation => "existing_degradation",
            TailRiskAdmissionReason::ConservativeFallback => "conservative_fallback",
            TailRiskAdmissionReason::BalancedBaseline => "balanced_baseline",
        }
    }

    fn hash_json_value(value: &Value) -> u64 {
        let mut hasher = DefaultHasher::new();
        serde_json::to_string(value)
            .expect("serialize projection for hashing")
            .hash(&mut hasher);
        hasher.finish()
    }

    fn build_tail_risk_admission_report(
        scenario: &TailRiskAdmissionScenario,
        include_hash_probe: bool,
    ) -> Value {
        let total_offered_units = scenario
            .fixture
            .windows
            .iter()
            .map(|window| window.offered_work_units)
            .sum::<u64>()
            .saturating_mul(scenario.fixture.replay_count as u64);
        let evidence_vector_fields = json!([
            "wake_to_run_p99_ns",
            "queue_residency_p99_ns",
            "ready_backlog_p99",
            "cancel_debt_p99",
            "retry_pressure_p99",
            "memory_pressure_bps",
            "degradation_level"
        ]);

        let mut tail_risk = PolicyAccumulator {
            admit_count: 0,
            defer_count: 0,
            shed_count: 0,
            admitted_units: 0,
            deferred_units: 0,
            shed_units: 0,
            fallback_used_count: 0,
            loss_score_sum: 0,
            loss_score_count: 0,
            latencies: Vec::new(),
        };
        let mut fixed_threshold = tail_risk.clone();
        let mut window_reports = Vec::new();
        let mut fallback_windows = Vec::new();
        let mut tail_risk_decisions = Vec::new();
        let mut fixed_threshold_decisions = Vec::new();

        for replay_index in 0..scenario.fixture.replay_count {
            for (window_index, window) in scenario.fixture.windows.iter().enumerate() {
                let evidence = TailRiskAdmissionEvidence {
                    scheduler: sample_scheduler_metrics_from_window(window, window_index),
                    retry_pressure_p99: window.retry_pressure_p99,
                    memory_pressure_bps: window.memory_pressure_bps,
                    degradation_level: window.degradation_level,
                };
                let ledger =
                    TailRiskAdmissionLedger::evaluate(&evidence, &scenario.tail_risk_profile);
                let (baseline_decision, baseline_reasons) =
                    fixed_threshold_decision(window, &scenario.fixed_threshold_profile);

                let tail_outcome = simulate_window_outcome(
                    ledger.decision,
                    &scenario.fixture,
                    window,
                    window_index,
                );
                let baseline_outcome = simulate_window_outcome(
                    baseline_decision,
                    &scenario.fixture,
                    window,
                    window_index,
                );

                tail_risk.record(
                    ledger.decision,
                    ledger.fallback_used,
                    ledger.expected_loss_score,
                    &tail_outcome,
                );
                fixed_threshold.record(baseline_decision, false, 0, &baseline_outcome);

                if replay_index == 0 {
                    tail_risk_decisions.push(format!("{:?}", ledger.decision).to_lowercase());
                    fixed_threshold_decisions
                        .push(format!("{:?}", baseline_decision).to_lowercase());
                    if ledger.fallback_used {
                        fallback_windows.push(window.window_id.clone());
                    }
                    window_reports.push(json!({
                        "window_id": window.window_id,
                        "evidence_vector": {
                            "wake_to_run_p99_ns": window.wake_to_run_p99_ns,
                            "queue_residency_p99_ns": window.queue_residency_p99_ns,
                            "ready_backlog_p99": window.ready_backlog_p99,
                            "cancel_debt_p99": window.cancel_debt_p99,
                            "retry_pressure_p99": window.retry_pressure_p99,
                            "memory_pressure_bps": window.memory_pressure_bps,
                            "degradation_level": format!("{:?}", window.degradation_level).to_lowercase(),
                        },
                        "tail_risk": {
                            "decision": format!("{:?}", ledger.decision).to_lowercase(),
                            "fallback_used": ledger.fallback_used,
                            "expected_loss_score": ledger.expected_loss_score,
                            "confidence_percent": ledger.confidence_percent,
                            "reason_codes": ledger.reason_codes.iter().map(|reason| tail_risk_reason_label(*reason)).collect::<Vec<_>>(),
                            "missing_evidence_fields": ledger.missing_evidence_fields,
                            "admitted_units": tail_outcome.admitted_units,
                            "deferred_units": tail_outcome.deferred_units,
                            "shed_units": tail_outcome.shed_units,
                            "window_p99_ns": percentile_slice_u64(&tail_outcome.latency_samples, 99, 100),
                        },
                        "fixed_threshold": {
                            "decision": format!("{:?}", baseline_decision).to_lowercase(),
                            "reason_codes": baseline_reasons,
                            "admitted_units": baseline_outcome.admitted_units,
                            "deferred_units": baseline_outcome.deferred_units,
                            "shed_units": baseline_outcome.shed_units,
                            "window_p99_ns": percentile_slice_u64(&baseline_outcome.latency_samples, 99, 100),
                        }
                    }));
                }
            }
        }

        let tail_summary = tail_risk.summary(total_offered_units);
        let fixed_summary = fixed_threshold.summary(total_offered_units);
        let report_projection = json!({
            "schema_version": TAIL_RISK_ADMISSION_PROJECTION_SCHEMA_VERSION,
            "scenario_id": scenario.scenario_id,
            "workload_class": scenario.workload_class,
            "replay_count": scenario.fixture.replay_count,
            "window_count": scenario.fixture.windows.len(),
            "tail_risk_decision_sequence": tail_risk_decisions,
            "fixed_threshold_decision_sequence": fixed_threshold_decisions,
            "tail_risk": {
                "admitted_units": tail_summary.admitted_units,
                "deferred_units": tail_summary.deferred_units,
                "shed_units": tail_summary.shed_units,
                "fallback_used_count": tail_summary.fallback_used_count,
                "p95_latency_ns": tail_summary.p95_latency_ns,
                "p99_latency_ns": tail_summary.p99_latency_ns,
                "throughput_ratio": tail_summary.throughput_ratio
            },
            "fixed_threshold": {
                "admitted_units": fixed_summary.admitted_units,
                "deferred_units": fixed_summary.deferred_units,
                "shed_units": fixed_summary.shed_units,
                "p95_latency_ns": fixed_summary.p95_latency_ns,
                "p99_latency_ns": fixed_summary.p99_latency_ns,
                "throughput_ratio": fixed_summary.throughput_ratio
            },
            "comparison": {
                "p95_latency_improvement_ns": fixed_summary.p95_latency_ns.saturating_sub(tail_summary.p95_latency_ns),
                "p99_latency_improvement_ns": fixed_summary.p99_latency_ns.saturating_sub(tail_summary.p99_latency_ns),
                "max_latency_improvement_ns": fixed_summary.max_latency_ns.saturating_sub(tail_summary.max_latency_ns),
                "throughput_delta_units": tail_summary.admitted_units as i64 - fixed_summary.admitted_units as i64,
                "tail_risk_better_than_fixed": tail_summary.p99_latency_ns < fixed_summary.p99_latency_ns,
            },
            "fallback_windows": fallback_windows,
            "evidence_vector_fields": evidence_vector_fields
        });
        let repeated_run_hash_match = if include_hash_probe {
            let probe = build_tail_risk_admission_report(scenario, false);
            hash_json_value(&probe["report_projection"]) == hash_json_value(&report_projection)
        } else {
            true
        };

        json!({
            "schema_version": TAIL_RISK_ADMISSION_REPORT_SCHEMA_VERSION,
            "scenario_id": scenario.scenario_id,
            "description": scenario.description,
            "workload_class": scenario.workload_class,
            "tail_risk_profile": scenario.tail_risk_profile,
            "fixed_threshold_profile": scenario.fixed_threshold_profile,
            "report_projection": report_projection,
            "repeated_run_hash_match": repeated_run_hash_match,
            "tail_risk_summary": tail_summary,
            "fixed_threshold_summary": fixed_summary,
            "window_reports": window_reports,
            "expected_report_projection": scenario.expected_report_projection
        })
    }

    #[test]
    fn tail_risk_admission_smoke_contract_emits_report() {
        let scenarios = load_tail_risk_admission_scenarios();
        let scenario_id = selected_tail_risk_admission_scenario();
        let scenario = scenarios
            .iter()
            .find(|candidate| candidate.scenario_id == scenario_id)
            .expect("selected tail-risk admission scenario must exist");
        let report = build_tail_risk_admission_report(scenario, true);
        if !scenario.expected_report_projection.is_null() {
            assert_eq!(
                report["report_projection"], scenario.expected_report_projection,
                "smoke contract projection must stay stable"
            );
        }
        assert_eq!(
            report["repeated_run_hash_match"].as_bool(),
            Some(true),
            "repeated report generation must be deterministic"
        );

        if let Ok(path) = std::env::var(TAIL_RISK_ADMISSION_REPORT_PATH_ENV) {
            maybe_write_tail_risk_admission_report(&path, &report);
        }

        println!("TAIL_RISK_ADMISSION_REPORT_JSON_BEGIN");
        println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("serialize tail-risk report")
        );
        println!("TAIL_RISK_ADMISSION_REPORT_JSON_END");
        crate::test_complete!("tail_risk_admission_smoke_contract_emits_report");
    }

    fn sample_cohort_steering_evidence() -> CohortAdmissionSteeringEvidence {
        CohortAdmissionSteeringEvidence {
            local_cohort: Some(0),
            worker_to_cohort_map: vec![0, 0, 1, 1],
            cohort_ready_backlog: vec![228, 96],
            topology_confidence_percent: Some(88),
            remote_spill_budget: CohortRemoteSpillBudgetState::new(7, 2),
            decision_epoch: 7,
            consecutive_local_defers: 1,
            outer_tail_risk_decision: TailRiskAdmissionDecision::Admit,
        }
    }

    #[test]
    fn cohort_remote_spill_budget_resets_by_epoch_and_saturates() {
        let profile = CohortAdmissionSteeringProfile {
            remote_spill_budget_per_epoch: 2,
            ..CohortAdmissionSteeringProfile::default()
        };
        let same_epoch = CohortRemoteSpillBudgetState::new(4, 9).normalized_for_epoch(&profile, 4);
        assert_eq!(same_epoch.remaining_tokens, 2);
        let next_epoch = same_epoch.normalized_for_epoch(&profile, 5);
        assert_eq!(next_epoch.epoch, 5);
        assert_eq!(next_epoch.remaining_tokens, 2);
        assert_eq!(next_epoch.spend_one().remaining_tokens, 1);
        assert_eq!(
            CohortRemoteSpillBudgetState::new(5, 0)
                .spend_one()
                .remaining_tokens,
            0
        );
    }

    #[test]
    fn cohort_admission_steering_falls_back_when_topology_is_missing() {
        let ledger = CohortAdmissionSteeringLedger::evaluate(
            &CohortAdmissionSteeringEvidence {
                local_cohort: None,
                worker_to_cohort_map: Vec::new(),
                cohort_ready_backlog: Vec::new(),
                topology_confidence_percent: Some(90),
                remote_spill_budget: CohortRemoteSpillBudgetState::new(3, 2),
                decision_epoch: 3,
                consecutive_local_defers: 0,
                outer_tail_risk_decision: TailRiskAdmissionDecision::Admit,
            },
            &CohortAdmissionSteeringProfile::default(),
        );
        assert!(ledger.fallback_used);
        assert_eq!(ledger.decision, CohortAdmissionSteeringDecision::AdmitLocal);
        assert!(
            ledger
                .reason_codes
                .contains(&CohortAdmissionSteeringReason::MissingTopology)
        );
        assert_eq!(
            ledger.missing_evidence_fields,
            vec![
                "cohort_ready_backlog".to_string(),
                "local_cohort".to_string(),
                "worker_to_cohort_map".to_string()
            ]
        );
    }

    #[test]
    fn cohort_admission_steering_validates_worker_to_cohort_map() {
        let ledger = CohortAdmissionSteeringLedger::evaluate(
            &CohortAdmissionSteeringEvidence {
                worker_to_cohort_map: vec![0, 2],
                cohort_ready_backlog: vec![144, 96],
                ..sample_cohort_steering_evidence()
            },
            &CohortAdmissionSteeringProfile::default(),
        );
        assert!(ledger.fallback_used);
        assert_eq!(ledger.decision, CohortAdmissionSteeringDecision::AdmitLocal);
        assert_eq!(
            ledger.missing_evidence_fields,
            vec!["worker_to_cohort_map".to_string()]
        );
    }

    #[test]
    fn cohort_admission_steering_falls_back_when_confidence_is_low() {
        let ledger = CohortAdmissionSteeringLedger::evaluate(
            &CohortAdmissionSteeringEvidence {
                topology_confidence_percent: Some(42),
                ..sample_cohort_steering_evidence()
            },
            &CohortAdmissionSteeringProfile::default(),
        );
        assert!(ledger.fallback_used);
        assert_eq!(ledger.decision, CohortAdmissionSteeringDecision::AdmitLocal);
        assert!(
            ledger
                .reason_codes
                .contains(&CohortAdmissionSteeringReason::LowConfidenceFallback)
        );
    }

    #[test]
    fn cohort_admission_steering_respects_outer_tail_risk_cap() {
        let ledger = CohortAdmissionSteeringLedger::evaluate(
            &CohortAdmissionSteeringEvidence {
                outer_tail_risk_decision: TailRiskAdmissionDecision::Defer,
                ..sample_cohort_steering_evidence()
            },
            &CohortAdmissionSteeringProfile::default(),
        );
        assert_eq!(ledger.decision, CohortAdmissionSteeringDecision::Defer);
        assert!(!ledger.fallback_used);
        assert_eq!(
            ledger.reason_codes,
            vec![CohortAdmissionSteeringReason::TailRiskOuterCap]
        );
        assert_eq!(ledger.remote_spill_budget_remaining, 2);
    }

    #[test]
    fn cohort_admission_steering_redirects_remote_and_spends_budget() {
        let ledger = CohortAdmissionSteeringLedger::evaluate(
            &sample_cohort_steering_evidence(),
            &CohortAdmissionSteeringProfile::default(),
        );
        assert_eq!(
            ledger.decision,
            CohortAdmissionSteeringDecision::RedirectRemote
        );
        assert_eq!(ledger.target_cohort, Some(1));
        assert_eq!(ledger.remote_spill_budget_start, 2);
        assert_eq!(ledger.remote_spill_budget_remaining, 1);
        assert!(
            ledger
                .reason_codes
                .contains(&CohortAdmissionSteeringReason::RemoteSpillBudgetSpent)
        );
    }

    #[test]
    fn cohort_admission_steering_triggers_fairness_escape_hatch() {
        let profile = CohortAdmissionSteeringProfile {
            fairness_escape_after_consecutive_defers: 2,
            ..CohortAdmissionSteeringProfile::default()
        };
        let ledger = CohortAdmissionSteeringLedger::evaluate(
            &CohortAdmissionSteeringEvidence {
                consecutive_local_defers: 2,
                ..sample_cohort_steering_evidence()
            },
            &profile,
        );
        assert_eq!(
            ledger.decision,
            CohortAdmissionSteeringDecision::RedirectRemote
        );
        assert!(
            ledger
                .reason_codes
                .contains(&CohortAdmissionSteeringReason::FairnessEscapeHatch)
        );
    }

    #[test]
    fn cohort_admission_steering_defers_when_budget_is_exhausted() {
        let ledger = CohortAdmissionSteeringLedger::evaluate(
            &CohortAdmissionSteeringEvidence {
                remote_spill_budget: CohortRemoteSpillBudgetState::new(7, 0),
                consecutive_local_defers: 4,
                ..sample_cohort_steering_evidence()
            },
            &CohortAdmissionSteeringProfile::default(),
        );
        assert_eq!(ledger.decision, CohortAdmissionSteeringDecision::Defer);
        assert!(ledger.remote_spill_budget_exhausted);
        assert!(
            ledger
                .reason_codes
                .contains(&CohortAdmissionSteeringReason::RemoteSpillBudgetExhausted)
        );
    }

    #[test]
    fn cohort_admission_steering_disabled_mode_matches_conservative_global() {
        let profile = CohortAdmissionSteeringProfile {
            enabled: false,
            ..CohortAdmissionSteeringProfile::default()
        };
        let ledger =
            CohortAdmissionSteeringLedger::evaluate(&sample_cohort_steering_evidence(), &profile);
        assert!(ledger.fallback_used);
        assert_eq!(ledger.decision, CohortAdmissionSteeringDecision::AdmitLocal);
        assert_eq!(ledger.target_cohort, Some(0));
        assert!(
            ledger
                .reason_codes
                .contains(&CohortAdmissionSteeringReason::Disabled)
        );
    }

    #[test]
    fn cohort_admission_steering_ledger_round_trips_through_json() {
        let ledger = CohortAdmissionSteeringLedger::evaluate(
            &sample_cohort_steering_evidence(),
            &CohortAdmissionSteeringProfile::default(),
        );
        let json = serde_json::to_string_pretty(&ledger).expect("serialize cohort ledger");
        let reparsed: CohortAdmissionSteeringLedger =
            serde_json::from_str(&json).expect("deserialize cohort ledger");
        assert_eq!(reparsed, ledger);
    }

    fn sample_brownout_evidence() -> OverloadBrownoutEvidence {
        OverloadBrownoutEvidence {
            scheduler: Some(SchedulerEvidenceMetrics {
                wake_to_run_p50_ns: 8_000,
                wake_to_run_p95_ns: 120_000,
                wake_to_run_p99_ns: 236_000,
                queue_residency_p50_ns: 18_000,
                queue_residency_p95_ns: 180_000,
                queue_residency_p99_ns: 310_000,
                ready_backlog_p95: 164,
                ready_backlog_p99: 224,
                cancel_debt_p95: 28,
                cancel_debt_p99: 44,
                remote_steal_ratio_pct: Some(18),
                cross_cohort_wake_p99_ns: Some(148_000),
            }),
            memory_pressure_bps: Some(8_820),
            degradation_level: DegradationLevel::Moderate,
            outer_tail_risk_decision: TailRiskAdmissionDecision::Defer,
            previous_phase: OverloadBrownoutPhase::Observe,
            recovery_streak_windows: 0,
            already_shed_surfaces: Vec::new(),
        }
    }

    #[test]
    fn overload_brownout_effective_optional_surfaces_dedupes_and_filters_denied() {
        let profile = OverloadBrownoutProfile {
            allowed_optional_surfaces: vec![
                BrownoutOptionalSurface::DetailedTracing,
                BrownoutOptionalSurface::RichDiagnostics,
                BrownoutOptionalSurface::DetailedTracing,
                BrownoutOptionalSurface::RichExportFormatting,
            ],
            denied_optional_surfaces: vec![BrownoutOptionalSurface::RichDiagnostics],
            ..OverloadBrownoutProfile::default()
        };
        assert_eq!(
            profile.effective_optional_surfaces(),
            vec![
                BrownoutOptionalSurface::DetailedTracing,
                BrownoutOptionalSurface::RichExportFormatting,
            ]
        );
    }

    #[test]
    fn overload_brownout_disabled_mode_matches_normal() {
        let profile = OverloadBrownoutProfile {
            enabled: false,
            ..OverloadBrownoutProfile::default()
        };
        let ledger = OverloadBrownoutLedger::evaluate(&sample_brownout_evidence(), &profile);
        assert!(ledger.fallback_used);
        assert_eq!(ledger.phase, OverloadBrownoutPhase::Normal);
        assert!(ledger.requested_degraded_surfaces.is_empty());
        assert!(
            ledger
                .reason_codes
                .contains(&OverloadBrownoutReason::Disabled)
        );
    }

    #[test]
    fn overload_brownout_falls_back_when_evidence_is_missing() {
        let ledger = OverloadBrownoutLedger::evaluate(
            &OverloadBrownoutEvidence {
                scheduler: None,
                memory_pressure_bps: Some(7_900),
                degradation_level: DegradationLevel::Light,
                outer_tail_risk_decision: TailRiskAdmissionDecision::Admit,
                previous_phase: OverloadBrownoutPhase::Normal,
                recovery_streak_windows: 0,
                already_shed_surfaces: Vec::new(),
            },
            &OverloadBrownoutProfile::default(),
        );
        assert!(ledger.fallback_used);
        assert_eq!(ledger.phase, OverloadBrownoutPhase::Observe);
        assert_eq!(
            ledger.missing_evidence_fields,
            vec!["scheduler_metrics".to_string()]
        );
    }

    #[test]
    fn overload_brownout_escalates_to_shed_optional_under_severe_pressure() {
        let ledger = OverloadBrownoutLedger::evaluate(
            &OverloadBrownoutEvidence {
                memory_pressure_bps: Some(9_450),
                outer_tail_risk_decision: TailRiskAdmissionDecision::Shed,
                degradation_level: DegradationLevel::Heavy,
                ..sample_brownout_evidence()
            },
            &OverloadBrownoutProfile::default(),
        );
        assert_eq!(ledger.phase, OverloadBrownoutPhase::ShedOptional);
        assert!(
            ledger
                .requested_degraded_surfaces
                .contains(&BrownoutOptionalSurface::DetailedTracing)
        );
        assert!(
            ledger
                .reason_codes
                .contains(&OverloadBrownoutReason::TailRiskOuterShed)
        );
    }

    #[test]
    fn overload_brownout_respects_recovery_hysteresis_and_restores_surfaces() {
        let profile = OverloadBrownoutProfile::default();
        let ledger = OverloadBrownoutLedger::evaluate(
            &OverloadBrownoutEvidence {
                scheduler: Some(SchedulerEvidenceMetrics {
                    wake_to_run_p50_ns: 7_500,
                    wake_to_run_p95_ns: 74_000,
                    wake_to_run_p99_ns: 118_000,
                    queue_residency_p50_ns: 12_000,
                    queue_residency_p95_ns: 88_000,
                    queue_residency_p99_ns: 120_000,
                    ready_backlog_p95: 96,
                    ready_backlog_p99: 128,
                    cancel_debt_p95: 12,
                    cancel_debt_p99: 20,
                    remote_steal_ratio_pct: Some(10),
                    cross_cohort_wake_p99_ns: Some(92_000),
                }),
                memory_pressure_bps: Some(7_100),
                degradation_level: DegradationLevel::None,
                outer_tail_risk_decision: TailRiskAdmissionDecision::Admit,
                previous_phase: OverloadBrownoutPhase::ShedOptional,
                recovery_streak_windows: 0,
                already_shed_surfaces: Vec::new(),
            },
            &profile,
        );
        assert_eq!(ledger.phase, OverloadBrownoutPhase::Recovery);
        assert_eq!(ledger.recovery_streak_after, 1);
        assert!(
            ledger
                .restored_surfaces
                .contains(&BrownoutOptionalSurface::DetailedTracing)
        );
        assert!(
            ledger
                .reason_codes
                .contains(&OverloadBrownoutReason::RecoveryHysteresis)
        );
    }

    #[test]
    fn overload_brownout_avoids_duplicate_accounting_for_self_shedding_surfaces() {
        let ledger = OverloadBrownoutLedger::evaluate(
            &OverloadBrownoutEvidence {
                already_shed_surfaces: vec![BrownoutOptionalSurface::RichDiagnostics],
                ..sample_brownout_evidence()
            },
            &OverloadBrownoutProfile::default(),
        );
        assert_eq!(ledger.phase, OverloadBrownoutPhase::Degrade);
        assert!(
            ledger
                .already_shed_surfaces
                .contains(&BrownoutOptionalSurface::RichDiagnostics)
        );
        assert!(
            !ledger
                .newly_degraded_surfaces
                .contains(&BrownoutOptionalSurface::RichDiagnostics)
        );
        assert!(
            ledger
                .reason_codes
                .contains(&OverloadBrownoutReason::OptionalSurfaceAlreadyShedding)
        );
    }

    #[test]
    fn overload_brownout_preserves_critical_surfaces() {
        let ledger = OverloadBrownoutLedger::evaluate(
            &sample_brownout_evidence(),
            &OverloadBrownoutProfile::default(),
        );
        assert_eq!(ledger.phase, OverloadBrownoutPhase::Degrade);
        assert_eq!(
            ledger.preserved_surfaces,
            vec![
                BrownoutProtectedSurface::CoreScheduling,
                BrownoutProtectedSurface::CancellationDrain,
                BrownoutProtectedSurface::RegionQuiescence,
                BrownoutProtectedSurface::ObligationCleanup,
            ]
        );
    }

    #[test]
    fn overload_brownout_ledger_round_trips_through_json() {
        let ledger = OverloadBrownoutLedger::evaluate(
            &sample_brownout_evidence(),
            &OverloadBrownoutProfile::default(),
        );
        let json = serde_json::to_string_pretty(&ledger).expect("serialize overload brownout");
        let reparsed: OverloadBrownoutLedger =
            serde_json::from_str(&json).expect("deserialize overload brownout");
        assert_eq!(reparsed, ledger);
    }

    const COHORT_ADMISSION_STEERING_CONTRACT_PATH_ENV: &str =
        "ASUPERSYNC_COHORT_ADMISSION_STEERING_CONTRACT_PATH";
    const COHORT_ADMISSION_STEERING_SCENARIO_ENV: &str =
        "ASUPERSYNC_COHORT_ADMISSION_STEERING_SCENARIO";
    const COHORT_ADMISSION_STEERING_REPORT_PATH_ENV: &str =
        "ASUPERSYNC_COHORT_ADMISSION_STEERING_REPORT_PATH";
    const COHORT_ADMISSION_STEERING_REPORT_SCHEMA_VERSION: &str =
        "cohort-admission-steering-report-v1";
    const COHORT_ADMISSION_STEERING_PROJECTION_SCHEMA_VERSION: &str =
        "cohort-admission-steering-projection-v1";

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct CohortAdmissionSteeringSmokeContract {
        smoke_scenarios: Vec<CohortAdmissionSteeringScenario>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct CohortAdmissionSteeringScenario {
        scenario_id: String,
        description: String,
        workload_class: String,
        output_root: String,
        execution_policy: String,
        workload_seed: u64,
        safe_fallback_profile: String,
        expected_winner_profile: String,
        steering_profile: CohortAdmissionSteeringProfile,
        fixture: CohortAdmissionSteeringFixture,
        expected_report_projection: Value,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct CohortAdmissionSteeringFixture {
        replay_count: usize,
        windows: Vec<CohortAdmissionSteeringWindow>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct CohortAdmissionSteeringWindow {
        window_id: String,
        local_cohort: Option<usize>,
        worker_to_cohort_map: Vec<usize>,
        cohort_ready_backlog: Vec<usize>,
        topology_confidence_percent: Option<u8>,
        decision_epoch: u64,
        consecutive_local_defers: u16,
        outer_tail_risk_decision: TailRiskAdmissionDecision,
        offered_work_units: u64,
        local_wake_to_run_p99_ns: u64,
        remote_wake_to_run_p99_ns: u64,
    }

    #[derive(Debug, Clone)]
    struct CohortPlacementWindowOutcome {
        admitted_units: u64,
        deferred_units: u64,
        remote_spill_count: u64,
        latency_samples: Vec<u64>,
    }

    #[derive(Debug, Clone, Default, Serialize)]
    struct CohortSteeringAccumulator {
        admit_local_count: u64,
        redirect_remote_count: u64,
        defer_count: u64,
        fallback_used_count: u64,
        budget_exhausted_count: u64,
        fairness_escape_count: u64,
        admitted_units: u64,
        deferred_units: u64,
        remote_spill_count: u64,
        latencies: Vec<u64>,
    }

    #[derive(Debug, Clone, PartialEq, Serialize)]
    struct CohortSteeringSummary {
        admit_local_count: u64,
        redirect_remote_count: u64,
        defer_count: u64,
        fallback_used_count: u64,
        budget_exhausted_count: u64,
        fairness_escape_count: u64,
        admitted_units: u64,
        deferred_units: u64,
        remote_spill_count: u64,
        p50_latency_ns: u64,
        p95_latency_ns: u64,
        p99_latency_ns: u64,
        max_latency_ns: u64,
        throughput_ratio: f64,
    }

    impl CohortSteeringAccumulator {
        fn record(
            &mut self,
            decision: CohortAdmissionSteeringDecision,
            fallback_used: bool,
            budget_exhausted: bool,
            fairness_escape: bool,
            outcome: &CohortPlacementWindowOutcome,
        ) {
            match decision {
                CohortAdmissionSteeringDecision::AdmitLocal => self.admit_local_count += 1,
                CohortAdmissionSteeringDecision::RedirectRemote => self.redirect_remote_count += 1,
                CohortAdmissionSteeringDecision::Defer => self.defer_count += 1,
            }
            self.fallback_used_count += u64::from(fallback_used);
            self.budget_exhausted_count += u64::from(budget_exhausted);
            self.fairness_escape_count += u64::from(fairness_escape);
            self.admitted_units += outcome.admitted_units;
            self.deferred_units += outcome.deferred_units;
            self.remote_spill_count += outcome.remote_spill_count;
            self.latencies.extend_from_slice(&outcome.latency_samples);
        }

        fn summary(&self, total_offered_units: u64) -> CohortSteeringSummary {
            let max_latency_ns = self.latencies.iter().copied().max().unwrap_or(0);
            let throughput_ratio = if total_offered_units == 0 {
                0.0
            } else {
                round4(self.admitted_units as f64 / total_offered_units as f64)
            };
            CohortSteeringSummary {
                admit_local_count: self.admit_local_count,
                redirect_remote_count: self.redirect_remote_count,
                defer_count: self.defer_count,
                fallback_used_count: self.fallback_used_count,
                budget_exhausted_count: self.budget_exhausted_count,
                fairness_escape_count: self.fairness_escape_count,
                admitted_units: self.admitted_units,
                deferred_units: self.deferred_units,
                remote_spill_count: self.remote_spill_count,
                p50_latency_ns: percentile_slice_u64(&self.latencies, 50, 100),
                p95_latency_ns: percentile_slice_u64(&self.latencies, 95, 100),
                p99_latency_ns: percentile_slice_u64(&self.latencies, 99, 100),
                max_latency_ns,
                throughput_ratio,
            }
        }
    }

    fn default_cohort_admission_steering_scenarios() -> Vec<CohortAdmissionSteeringScenario> {
        vec![
            CohortAdmissionSteeringScenario {
                scenario_id: "AA-COHORT-ADMISSION-STEERING-LOCALITY-WIN-2C".to_string(),
                description: "High-confidence two-cohort replay where the local cohort saturates, the remote cohort stays cool, and bounded redirect tokens cut wake-to-run tails versus the conservative global path.".to_string(),
                workload_class: "locality-win".to_string(),
                output_root: "target/cohort-admission-steering-smoke".to_string(),
                execution_policy: "execute_or_dry_run".to_string(),
                workload_seed: 424242,
                safe_fallback_profile: "conservative_global".to_string(),
                expected_winner_profile: "cohort_steered".to_string(),
                steering_profile: CohortAdmissionSteeringProfile::default(),
                fixture: CohortAdmissionSteeringFixture {
                    replay_count: 2,
                    windows: vec![
                        CohortAdmissionSteeringWindow {
                            window_id: "local_balanced".to_string(),
                            local_cohort: Some(0),
                            worker_to_cohort_map: vec![0, 0, 1, 1],
                            cohort_ready_backlog: vec![148, 128],
                            topology_confidence_percent: Some(90),
                            decision_epoch: 10,
                            consecutive_local_defers: 0,
                            outer_tail_risk_decision: TailRiskAdmissionDecision::Admit,
                            offered_work_units: 48,
                            local_wake_to_run_p99_ns: 148_000,
                            remote_wake_to_run_p99_ns: 142_000,
                        },
                        CohortAdmissionSteeringWindow {
                            window_id: "local_saturated".to_string(),
                            local_cohort: Some(0),
                            worker_to_cohort_map: vec![0, 0, 1, 1],
                            cohort_ready_backlog: vec![260, 84],
                            topology_confidence_percent: Some(92),
                            decision_epoch: 10,
                            consecutive_local_defers: 1,
                            outer_tail_risk_decision: TailRiskAdmissionDecision::Admit,
                            offered_work_units: 48,
                            local_wake_to_run_p99_ns: 236_000,
                            remote_wake_to_run_p99_ns: 146_000,
                        },
                        CohortAdmissionSteeringWindow {
                            window_id: "fairness_escape".to_string(),
                            local_cohort: Some(0),
                            worker_to_cohort_map: vec![0, 0, 1, 1],
                            cohort_ready_backlog: vec![244, 96],
                            topology_confidence_percent: Some(90),
                            decision_epoch: 10,
                            consecutive_local_defers: 3,
                            outer_tail_risk_decision: TailRiskAdmissionDecision::Admit,
                            offered_work_units: 48,
                            local_wake_to_run_p99_ns: 228_000,
                            remote_wake_to_run_p99_ns: 154_000,
                        },
                    ],
                },
                expected_report_projection: Value::Null,
            },
            CohortAdmissionSteeringScenario {
                scenario_id: "AA-COHORT-ADMISSION-STEERING-KEEP-GLOBAL-2C".to_string(),
                description: "Low-confidence and no-win replay that proves the controller keeps the conservative global path pinned and records an explicit safe fallback verdict.".to_string(),
                workload_class: "keep-global".to_string(),
                output_root: "target/cohort-admission-steering-smoke".to_string(),
                execution_policy: "execute_or_dry_run".to_string(),
                workload_seed: 515151,
                safe_fallback_profile: "conservative_global".to_string(),
                expected_winner_profile: "conservative_global".to_string(),
                steering_profile: CohortAdmissionSteeringProfile::default(),
                fixture: CohortAdmissionSteeringFixture {
                    replay_count: 1,
                    windows: vec![
                        CohortAdmissionSteeringWindow {
                            window_id: "low_confidence".to_string(),
                            local_cohort: Some(0),
                            worker_to_cohort_map: vec![0, 0, 1, 1],
                            cohort_ready_backlog: vec![208, 198],
                            topology_confidence_percent: Some(48),
                            decision_epoch: 22,
                            consecutive_local_defers: 0,
                            outer_tail_risk_decision: TailRiskAdmissionDecision::Admit,
                            offered_work_units: 48,
                            local_wake_to_run_p99_ns: 204_000,
                            remote_wake_to_run_p99_ns: 201_000,
                        },
                        CohortAdmissionSteeringWindow {
                            window_id: "thin_remote_gain".to_string(),
                            local_cohort: Some(0),
                            worker_to_cohort_map: vec![0, 0, 1, 1],
                            cohort_ready_backlog: vec![214, 196],
                            topology_confidence_percent: Some(88),
                            decision_epoch: 23,
                            consecutive_local_defers: 1,
                            outer_tail_risk_decision: TailRiskAdmissionDecision::Admit,
                            offered_work_units: 48,
                            local_wake_to_run_p99_ns: 211_000,
                            remote_wake_to_run_p99_ns: 208_000,
                        },
                        CohortAdmissionSteeringWindow {
                            window_id: "tail_risk_outer_cap".to_string(),
                            local_cohort: Some(0),
                            worker_to_cohort_map: vec![0, 0, 1, 1],
                            cohort_ready_backlog: vec![228, 150],
                            topology_confidence_percent: Some(90),
                            decision_epoch: 24,
                            consecutive_local_defers: 4,
                            outer_tail_risk_decision: TailRiskAdmissionDecision::Defer,
                            offered_work_units: 48,
                            local_wake_to_run_p99_ns: 224_000,
                            remote_wake_to_run_p99_ns: 176_000,
                        },
                    ],
                },
                expected_report_projection: Value::Null,
            },
        ]
    }

    fn load_cohort_admission_steering_scenarios() -> Vec<CohortAdmissionSteeringScenario> {
        let Ok(path) = std::env::var(COHORT_ADMISSION_STEERING_CONTRACT_PATH_ENV) else {
            return default_cohort_admission_steering_scenarios();
        };
        let contract: CohortAdmissionSteeringSmokeContract = serde_json::from_str(
            &fs::read_to_string(Path::new(&path)).expect("read cohort admission steering contract"),
        )
        .expect("deserialize cohort admission steering contract");
        contract.smoke_scenarios
    }

    fn selected_cohort_admission_steering_scenario() -> String {
        std::env::var(COHORT_ADMISSION_STEERING_SCENARIO_ENV)
            .unwrap_or_else(|_| "AA-COHORT-ADMISSION-STEERING-LOCALITY-WIN-2C".to_string())
    }

    fn maybe_write_cohort_admission_steering_report(path: &str, report: &Value) {
        let path = Path::new(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create cohort report parent directory");
        }
        fs::write(
            path,
            serde_json::to_string_pretty(report)
                .expect("serialize cohort admission steering report"),
        )
        .expect("write cohort admission steering report");
    }

    fn conservative_global_decision(
        window: &CohortAdmissionSteeringWindow,
    ) -> CohortAdmissionSteeringDecision {
        if window.outer_tail_risk_decision == TailRiskAdmissionDecision::Admit {
            CohortAdmissionSteeringDecision::AdmitLocal
        } else {
            CohortAdmissionSteeringDecision::Defer
        }
    }

    fn simulate_cohort_window_outcome(
        decision: CohortAdmissionSteeringDecision,
        target_cohort: Option<usize>,
        window: &CohortAdmissionSteeringWindow,
        replay_index: usize,
    ) -> CohortPlacementWindowOutcome {
        let offered = window.offered_work_units;
        let local_cohort = window.local_cohort.unwrap_or(0);
        let local_backlog_usize = window
            .cohort_ready_backlog
            .get(local_cohort)
            .copied()
            .unwrap_or(0);
        let local_backlog = local_backlog_usize as u64;
        let best_remote_backlog = window
            .cohort_ready_backlog
            .iter()
            .enumerate()
            .filter(|(cohort, _)| *cohort != local_cohort)
            .map(|(_, backlog)| *backlog)
            .min()
            .unwrap_or(local_backlog_usize) as u64;
        let remote_backlog = target_cohort
            .and_then(|cohort| window.cohort_ready_backlog.get(cohort).copied())
            .unwrap_or(best_remote_backlog as usize) as u64;
        let backlog_gap = local_backlog.saturating_sub(best_remote_backlog);

        let (
            admitted_units,
            deferred_units,
            remote_spill_count,
            p99_base,
            overload_multiplier,
            decision_penalty,
        ) = match decision {
            CohortAdmissionSteeringDecision::AdmitLocal => (
                offered,
                0,
                backlog_gap.saturating_div(40),
                window.local_wake_to_run_p99_ns,
                1_350,
                21_000 + backlog_gap.saturating_mul(320),
            ),
            CohortAdmissionSteeringDecision::RedirectRemote => (
                offered,
                0,
                1,
                window.remote_wake_to_run_p99_ns,
                780,
                13_500 + remote_backlog.saturating_mul(110),
            ),
            CohortAdmissionSteeringDecision::Defer => (
                offered.saturating_mul(82).saturating_div(100),
                offered.saturating_sub(offered.saturating_mul(82).saturating_div(100)),
                0,
                window.local_wake_to_run_p99_ns.saturating_sub(18_000),
                620,
                9_500,
            ),
        };

        let backlog_source = match decision {
            CohortAdmissionSteeringDecision::RedirectRemote => remote_backlog,
            CohortAdmissionSteeringDecision::AdmitLocal
            | CohortAdmissionSteeringDecision::Defer => local_backlog,
        };

        let base_latency = p99_base
            .saturating_div(2)
            .saturating_add(backlog_source.saturating_mul(overload_multiplier))
            .saturating_add(decision_penalty);
        let mut latency_samples = Vec::with_capacity(admitted_units as usize);
        for sample_idx in 0..admitted_units {
            let jitter = ((replay_index as u64 * 23) + (sample_idx % 17) * 11).saturating_mul(131);
            latency_samples.push(base_latency.saturating_add(jitter));
        }

        CohortPlacementWindowOutcome {
            admitted_units,
            deferred_units,
            remote_spill_count,
            latency_samples,
        }
    }

    fn cohort_steering_reason_label(reason: CohortAdmissionSteeringReason) -> &'static str {
        match reason {
            CohortAdmissionSteeringReason::Disabled => "disabled",
            CohortAdmissionSteeringReason::MissingTopology => "missing_topology",
            CohortAdmissionSteeringReason::LowConfidenceFallback => "low_confidence_fallback",
            CohortAdmissionSteeringReason::TailRiskOuterCap => "tail_risk_outer_cap",
            CohortAdmissionSteeringReason::LocalCapacityAvailable => "local_capacity_available",
            CohortAdmissionSteeringReason::LocalBacklogPressure => "local_backlog_pressure",
            CohortAdmissionSteeringReason::RemoteSpillBudgetSpent => "remote_spill_budget_spent",
            CohortAdmissionSteeringReason::RemoteSpillBudgetExhausted => {
                "remote_spill_budget_exhausted"
            }
            CohortAdmissionSteeringReason::FairnessEscapeHatch => "fairness_escape_hatch",
            CohortAdmissionSteeringReason::ConservativeGlobalBaseline => {
                "conservative_global_baseline"
            }
        }
    }

    fn build_cohort_admission_steering_report(
        scenario: &CohortAdmissionSteeringScenario,
        include_hash_probe: bool,
    ) -> Value {
        let total_offered_units = scenario
            .fixture
            .windows
            .iter()
            .map(|window| window.offered_work_units)
            .sum::<u64>()
            .saturating_mul(scenario.fixture.replay_count as u64);

        let mut steered = CohortSteeringAccumulator::default();
        let mut conservative_global = CohortSteeringAccumulator::default();
        let mut window_reports = Vec::new();
        let mut decision_sequence = Vec::new();
        let mut conservative_sequence = Vec::new();
        let mut fallback_windows = Vec::new();
        let mut fairness_windows = Vec::new();
        let mut budget_start_sequence = Vec::new();
        let mut budget_remaining_sequence = Vec::new();

        let mut budget_state = CohortRemoteSpillBudgetState::new(
            scenario
                .fixture
                .windows
                .first()
                .map_or(0, |window| window.decision_epoch),
            scenario.steering_profile.remote_spill_budget_per_epoch,
        );

        for replay_index in 0..scenario.fixture.replay_count {
            let mut replay_budget = budget_state;
            for window in &scenario.fixture.windows {
                let evidence = CohortAdmissionSteeringEvidence {
                    local_cohort: window.local_cohort,
                    worker_to_cohort_map: window.worker_to_cohort_map.clone(),
                    cohort_ready_backlog: window.cohort_ready_backlog.clone(),
                    topology_confidence_percent: window.topology_confidence_percent,
                    remote_spill_budget: replay_budget,
                    decision_epoch: window.decision_epoch,
                    consecutive_local_defers: window.consecutive_local_defers,
                    outer_tail_risk_decision: window.outer_tail_risk_decision,
                };
                let ledger =
                    CohortAdmissionSteeringLedger::evaluate(&evidence, &scenario.steering_profile);
                replay_budget = CohortRemoteSpillBudgetState::new(
                    ledger.evidence.remote_spill_budget_epoch,
                    ledger.remote_spill_budget_remaining,
                );

                let global_decision = conservative_global_decision(window);
                let steered_outcome = simulate_cohort_window_outcome(
                    ledger.decision,
                    ledger.target_cohort,
                    window,
                    replay_index,
                );
                let global_outcome =
                    simulate_cohort_window_outcome(global_decision, None, window, replay_index);

                steered.record(
                    ledger.decision,
                    ledger.fallback_used,
                    ledger
                        .reason_codes
                        .contains(&CohortAdmissionSteeringReason::RemoteSpillBudgetExhausted),
                    ledger
                        .reason_codes
                        .contains(&CohortAdmissionSteeringReason::FairnessEscapeHatch),
                    &steered_outcome,
                );
                conservative_global.record(global_decision, false, false, false, &global_outcome);

                if replay_index == 0 {
                    decision_sequence.push(format!("{:?}", ledger.decision).to_lowercase());
                    conservative_sequence.push(format!("{:?}", global_decision).to_lowercase());
                    budget_start_sequence.push(ledger.remote_spill_budget_start);
                    budget_remaining_sequence.push(ledger.remote_spill_budget_remaining);
                    if ledger.fallback_used {
                        fallback_windows.push(window.window_id.clone());
                    }
                    if ledger
                        .reason_codes
                        .contains(&CohortAdmissionSteeringReason::FairnessEscapeHatch)
                    {
                        fairness_windows.push(window.window_id.clone());
                    }
                    window_reports.push(json!({
                        "window_id": window.window_id,
                        "worker_to_cohort_map": window.worker_to_cohort_map,
                        "cohort_ready_backlog": window.cohort_ready_backlog,
                        "topology_confidence_percent": window.topology_confidence_percent,
                        "outer_tail_risk_decision": format!("{:?}", window.outer_tail_risk_decision).to_lowercase(),
                        "steered": {
                            "decision": format!("{:?}", ledger.decision).to_lowercase(),
                            "target_cohort": ledger.target_cohort,
                            "fallback_used": ledger.fallback_used,
                            "confidence_percent": ledger.confidence_percent,
                            "reason_codes": ledger.reason_codes.iter().map(|reason| cohort_steering_reason_label(*reason)).collect::<Vec<_>>(),
                            "missing_evidence_fields": ledger.missing_evidence_fields,
                            "remote_spill_budget_start": ledger.remote_spill_budget_start,
                            "remote_spill_budget_remaining": ledger.remote_spill_budget_remaining,
                            "remote_spill_budget_exhausted": ledger.remote_spill_budget_exhausted,
                            "admitted_units": steered_outcome.admitted_units,
                            "deferred_units": steered_outcome.deferred_units,
                            "remote_spill_count": steered_outcome.remote_spill_count,
                            "window_p99_ns": percentile_slice_u64(&steered_outcome.latency_samples, 99, 100),
                        },
                        "conservative_global": {
                            "decision": format!("{:?}", global_decision).to_lowercase(),
                            "admitted_units": global_outcome.admitted_units,
                            "deferred_units": global_outcome.deferred_units,
                            "remote_spill_count": global_outcome.remote_spill_count,
                            "window_p99_ns": percentile_slice_u64(&global_outcome.latency_samples, 99, 100),
                        }
                    }));
                }
            }
            budget_state = replay_budget;
        }

        let steered_summary = steered.summary(total_offered_units);
        let conservative_summary = conservative_global.summary(total_offered_units);
        let winner_profile = if steered_summary.p99_latency_ns < conservative_summary.p99_latency_ns
            || (steered_summary.p99_latency_ns == conservative_summary.p99_latency_ns
                && steered_summary.remote_spill_count < conservative_summary.remote_spill_count)
        {
            "cohort_steered"
        } else {
            scenario.safe_fallback_profile.as_str()
        };
        let no_win_trigger = winner_profile == scenario.safe_fallback_profile;
        let report_projection = json!({
            "schema_version": COHORT_ADMISSION_STEERING_PROJECTION_SCHEMA_VERSION,
            "scenario_id": scenario.scenario_id,
            "workload_class": scenario.workload_class,
            "workload_seed": scenario.workload_seed,
            "replay_count": scenario.fixture.replay_count,
            "window_count": scenario.fixture.windows.len(),
            "decision_sequence": decision_sequence,
            "conservative_global_sequence": conservative_sequence,
            "budget_start_sequence": budget_start_sequence,
            "budget_remaining_sequence": budget_remaining_sequence,
            "fallback_windows": fallback_windows,
            "fairness_windows": fairness_windows,
            "steered": {
                "admit_local_count": steered_summary.admit_local_count,
                "redirect_remote_count": steered_summary.redirect_remote_count,
                "defer_count": steered_summary.defer_count,
                "fallback_used_count": steered_summary.fallback_used_count,
                "budget_exhausted_count": steered_summary.budget_exhausted_count,
                "fairness_escape_count": steered_summary.fairness_escape_count,
                "admitted_units": steered_summary.admitted_units,
                "deferred_units": steered_summary.deferred_units,
                "remote_spill_count": steered_summary.remote_spill_count,
                "p95_latency_ns": steered_summary.p95_latency_ns,
                "p99_latency_ns": steered_summary.p99_latency_ns,
                "throughput_ratio": steered_summary.throughput_ratio
            },
            "conservative_global": {
                "admit_local_count": conservative_summary.admit_local_count,
                "redirect_remote_count": conservative_summary.redirect_remote_count,
                "defer_count": conservative_summary.defer_count,
                "admitted_units": conservative_summary.admitted_units,
                "deferred_units": conservative_summary.deferred_units,
                "remote_spill_count": conservative_summary.remote_spill_count,
                "p95_latency_ns": conservative_summary.p95_latency_ns,
                "p99_latency_ns": conservative_summary.p99_latency_ns,
                "throughput_ratio": conservative_summary.throughput_ratio
            },
            "comparison": {
                "p95_latency_improvement_ns": conservative_summary.p95_latency_ns.saturating_sub(steered_summary.p95_latency_ns),
                "p99_latency_improvement_ns": conservative_summary.p99_latency_ns.saturating_sub(steered_summary.p99_latency_ns),
                "remote_spill_reduction": conservative_summary.remote_spill_count as i64 - steered_summary.remote_spill_count as i64,
                "throughput_delta_units": steered_summary.admitted_units as i64 - conservative_summary.admitted_units as i64,
                "winner_profile": winner_profile,
                "no_win_trigger": no_win_trigger,
            }
        });
        let repeated_run_hash_match = if include_hash_probe {
            let probe = build_cohort_admission_steering_report(scenario, false);
            hash_json_value(&probe["report_projection"]) == hash_json_value(&report_projection)
        } else {
            true
        };

        json!({
            "schema_version": COHORT_ADMISSION_STEERING_REPORT_SCHEMA_VERSION,
            "scenario_id": scenario.scenario_id,
            "description": scenario.description,
            "workload_class": scenario.workload_class,
            "workload_seed": scenario.workload_seed,
            "safe_fallback_profile": scenario.safe_fallback_profile,
            "expected_winner_profile": scenario.expected_winner_profile,
            "steering_profile": scenario.steering_profile,
            "report_projection": report_projection,
            "repeated_run_hash_match": repeated_run_hash_match,
            "steered_summary": steered_summary,
            "conservative_global_summary": conservative_summary,
            "window_reports": window_reports,
            "operator_verdict": {
                "winner_profile": winner_profile,
                "safe_fallback_profile": scenario.safe_fallback_profile,
                "no_win_trigger": no_win_trigger,
                "pass": winner_profile == scenario.expected_winner_profile,
            },
            "expected_report_projection": scenario.expected_report_projection
        })
    }

    #[test]
    fn cohort_admission_steering_smoke_contract_emits_report() {
        let scenarios = load_cohort_admission_steering_scenarios();
        let scenario_id = selected_cohort_admission_steering_scenario();
        let scenario = scenarios
            .iter()
            .find(|candidate| candidate.scenario_id == scenario_id)
            .expect("selected cohort admission steering scenario must exist");
        let report = build_cohort_admission_steering_report(scenario, true);
        if !scenario.expected_report_projection.is_null() {
            assert_eq!(
                report["report_projection"], scenario.expected_report_projection,
                "cohort steering smoke contract projection must stay stable"
            );
        }
        assert_eq!(
            report["repeated_run_hash_match"].as_bool(),
            Some(true),
            "repeated cohort steering report generation must be deterministic"
        );
        assert_eq!(
            report["operator_verdict"]["pass"].as_bool(),
            Some(true),
            "operator verdict must agree with the expected winner profile"
        );

        if let Ok(path) = std::env::var(COHORT_ADMISSION_STEERING_REPORT_PATH_ENV) {
            maybe_write_cohort_admission_steering_report(&path, &report);
        }

        println!("COHORT_ADMISSION_STEERING_REPORT_JSON_BEGIN");
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .expect("serialize cohort admission steering report")
        );
        println!("COHORT_ADMISSION_STEERING_REPORT_JSON_END");
        crate::test_complete!("cohort_admission_steering_smoke_contract_emits_report");
    }
}
