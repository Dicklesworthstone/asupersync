//! Runtime Resource Cleanup Verification Engine
//!
//! Provides comprehensive tracking and verification that all runtime resources
//! (file handles, memory, network connections, I/O operations) are properly
//! cleaned up during region close and cancellation scenarios.
//!
//! # Core Invariant: "Region Close = Quiescence + Resource Cleanup"
//!
//! The asupersync runtime's fundamental invariant states that when a region closes,
//! it reaches complete quiescence. This verification engine extends that invariant
//! to ensure quiescence includes proper cleanup of ALL associated resources.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────┐    track    ┌───────────────────┐
//! │ Resource         │ ──────────▶ │ Cleanup           │
//! │ Allocation       │             │ Verifier          │
//! │ Points           │             │                   │
//! └──────────────────┘             └─────────┬─────────┘
//!                                            │ verify
//!                                            ▼
//! ┌──────────────────┐              ┌───────────────────┐
//! │ Region Close     │ ◀──────────  │ Resource          │
//! │ Hook             │   verify     │ Attribution       │
//! │                  │   cleanup    │ Database          │
//! └──────────────────┘              └───────────────────┘
//! ```
//!
//! # Resource Categories Tracked
//!
//! 1. **File Descriptors** - Files, sockets, pipes, epoll/kqueue descriptors
//! 2. **Memory Allocations** - Heap allocations tracked by region ownership
//! 3. **Network Connections** - TCP/UDP sockets, TLS sessions
//! 4. **I/O Operations** - Pending async I/O operations and their buffers
//! 5. **System Resources** - Timers, signal handlers, thread-local storage
//!
//! # Integration Points
//!
//! The verifier hooks into existing runtime infrastructure:
//! - **Resource Monitor** - Leverages existing resource tracking
//! - **State Verifier** - Integrates with state transition validation
//! - **Region Table** - Hooks region close events
//! - **Observability** - Reports violations through structured logging

use crate::types::{RegionId, TaskId};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::SystemTime;
use thiserror::Error;

/// Errors that can occur during resource cleanup verification.
#[derive(Debug, Error)]
pub enum ResourceCleanupError {
    /// Resource leak detected during region close.
    #[error(
        "resource leak detected in region {region_id:?}: {leak_count} resources not cleaned up"
    )]
    ResourceLeak {
        region_id: RegionId,
        leak_count: usize,
        resource_types: Vec<ResourceType>,
    },

    /// Resource attribution failed - cannot determine owner.
    #[error("cannot attribute resource {resource_id:?} to any region")]
    AttributionFailed { resource_id: ResourceId },

    /// Resource tracking is not enabled.
    #[error("resource cleanup verification is not enabled")]
    NotEnabled,

    /// Invalid resource state transition.
    #[error("invalid resource state transition: {resource_id:?} from {from:?} to {to:?}")]
    InvalidTransition {
        resource_id: ResourceId,
        from: ResourceState,
        to: ResourceState,
    },

    /// Resource cleanup is still in progress and must be rechecked before close.
    #[error(
        "resource cleanup still pending in region {region_id:?}: {pending_count} resources not yet cleaned"
    )]
    CleanupPending {
        region_id: RegionId,
        pending_count: usize,
        resource_types: Vec<ResourceType>,
    },
}

/// Unique identifier for tracked resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResourceId(u64);

impl ResourceId {
    /// Generate a new unique resource ID.
    pub fn new() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        Self(NEXT_ID.fetch_add(1, Ordering::Relaxed))
    }
}

/// Categories of tracked resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResourceType {
    /// File descriptor (file, socket, pipe).
    FileDescriptor,
    /// Heap memory allocation.
    HeapAllocation,
    /// Network connection (TCP/UDP socket).
    NetworkConnection,
    /// Async I/O operation in flight.
    IoOperation,
    /// Timer or deadline registration.
    Timer,
    /// Thread-local resource.
    ThreadLocal,
    /// Custom resource type.
    Custom(u32),
}

impl ResourceType {
    /// Check if this resource type requires immediate cleanup on region close.
    pub fn requires_immediate_cleanup(self) -> bool {
        matches!(
            self,
            Self::FileDescriptor | Self::NetworkConnection | Self::IoOperation
        )
    }

    /// Check if this resource type can be deferred for cleanup.
    pub fn allows_deferred_cleanup(self) -> bool {
        matches!(self, Self::HeapAllocation | Self::ThreadLocal)
    }
}

/// State of a tracked resource throughout its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResourceState {
    /// Resource has been allocated but not yet attached to a region.
    Allocated,
    /// Resource is owned by a specific region and in active use.
    Active,
    /// Resource is being cleaned up (region is closing).
    Cleaning,
    /// Resource cleanup has completed successfully.
    Cleaned,
    /// Resource was abandoned without proper cleanup (leak detected).
    Leaked,
}

impl ResourceState {
    /// Check if this is a valid state transition.
    pub fn can_transition_to(self, target: Self) -> bool {
        use ResourceState::*;
        match (self, target) {
            (Allocated, Active) => true,
            (Allocated, Cleaned) => true,
            (Active, Cleaning) => true,
            (Active, Cleaned) => true,
            (Cleaning, Cleaned) => true,
            (Cleaned, Cleaned) => true,
            (Active, Leaked) => true,
            (Allocated, Leaked) => true,
            (Cleaning, Leaked) => true,
            _ => false,
        }
    }
}

/// Details of a tracked resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceRecord {
    /// Unique identifier for this resource.
    pub id: ResourceId,
    /// Category of resource.
    pub resource_type: ResourceType,
    /// Current state in cleanup lifecycle.
    pub state: ResourceState,
    /// Region that owns this resource (if any).
    pub owner_region: Option<RegionId>,
    /// Task that allocated this resource (if any).
    pub allocating_task: Option<TaskId>,
    /// Timestamp when resource was allocated.
    pub allocated_at: SystemTime,
    /// Timestamp when resource state last changed.
    pub last_updated: SystemTime,
    /// Optional description for debugging.
    pub description: Option<String>,
    /// File descriptor number (for FileDescriptor resources).
    pub file_descriptor: Option<i32>,
    /// Size in bytes (for HeapAllocation resources).
    pub size_bytes: Option<usize>,
}

impl ResourceRecord {
    /// Create a new resource record.
    pub fn new(
        resource_type: ResourceType,
        owner_region: Option<RegionId>,
        allocating_task: Option<TaskId>,
    ) -> Self {
        let now = SystemTime::now();
        Self {
            id: ResourceId::new(),
            resource_type,
            state: ResourceState::Allocated,
            owner_region,
            allocating_task,
            allocated_at: now,
            last_updated: now,
            description: None,
            file_descriptor: None,
            size_bytes: None,
        }
    }

    /// Transition resource to a new state.
    pub fn transition_to(&mut self, new_state: ResourceState) -> Result<(), ResourceCleanupError> {
        if !self.state.can_transition_to(new_state) {
            return Err(ResourceCleanupError::InvalidTransition {
                resource_id: self.id,
                from: self.state,
                to: new_state,
            });
        }

        self.state = new_state;
        self.last_updated = SystemTime::now();
        Ok(())
    }

    /// Mark this resource as being actively used by a region.
    pub fn activate(&mut self, region_id: RegionId) -> Result<(), ResourceCleanupError> {
        self.owner_region = Some(region_id);
        self.transition_to(ResourceState::Active)
    }

    /// Begin cleanup process for this resource.
    pub fn begin_cleanup(&mut self) -> Result<(), ResourceCleanupError> {
        self.transition_to(ResourceState::Cleaning)
    }

    /// Mark cleanup as completed.
    pub fn complete_cleanup(&mut self) -> Result<(), ResourceCleanupError> {
        self.transition_to(ResourceState::Cleaned)
    }

    /// Mark resource as leaked (cleanup failed).
    pub fn mark_leaked(&mut self) -> Result<(), ResourceCleanupError> {
        self.transition_to(ResourceState::Leaked)
    }
}

/// Configuration for resource cleanup verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceCleanupConfig {
    /// Enable resource cleanup verification.
    pub enable_verification: bool,
    /// Enable detailed resource tracking (higher memory overhead).
    pub enable_detailed_tracking: bool,
    /// Enable stack trace capture for resource allocations.
    pub enable_allocation_traces: bool,
    /// Maximum number of resources to track before evicting oldest.
    pub max_tracked_resources: usize,
    /// Grace period for resource cleanup after region close.
    pub cleanup_grace_period_ms: u64,
    /// Whether to panic on detected resource leaks.
    pub panic_on_leaks: bool,
    /// Resource types to track (empty = track all).
    pub tracked_resource_types: HashSet<ResourceType>,
}

impl Default for ResourceCleanupConfig {
    fn default() -> Self {
        Self {
            enable_verification: true,
            enable_detailed_tracking: cfg!(debug_assertions),
            enable_allocation_traces: false,
            max_tracked_resources: 10_000,
            cleanup_grace_period_ms: 1000, // 1 second
            panic_on_leaks: cfg!(debug_assertions),
            tracked_resource_types: HashSet::new(), // Track all by default
        }
    }
}

/// Statistics about resource cleanup verification.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceCleanupStats {
    /// Total number of resources allocated.
    pub total_allocated: u64,
    /// Total number of resources cleaned up successfully.
    pub total_cleaned: u64,
    /// Total number of resource leaks detected.
    pub total_leaked: u64,
    /// Current number of actively tracked resources.
    pub currently_tracked: u64,
    /// Peak number of simultaneously tracked resources.
    pub peak_tracked: u64,
    /// Number of regions that closed with clean resource states.
    pub clean_region_closes: u64,
    /// Number of regions that closed with resource leaks.
    pub leaked_region_closes: u64,
}

/// Runtime Resource Cleanup Verification Engine.
///
/// This is the main component that tracks resource allocation, ownership,
/// and cleanup to verify the "region close = quiescence" invariant includes
/// proper resource cleanup.
pub struct ResourceCleanupVerifier {
    /// Configuration for verification behavior.
    config: ResourceCleanupConfig,
    /// Database of currently tracked resources.
    resources: RwLock<HashMap<ResourceId, ResourceRecord>>,
    /// Mapping from region ID to owned resource IDs.
    region_resources: RwLock<HashMap<RegionId, HashSet<ResourceId>>>,
    /// Statistics about verification activity.
    stats: RwLock<ResourceCleanupStats>,
    /// Whether verification is currently active.
    is_active: AtomicBool,
    /// Unique verifier instance ID for debugging.
}

impl ResourceCleanupVerifier {
    /// Create a new resource cleanup verifier.
    pub fn new(config: ResourceCleanupConfig) -> Self {
        static NEXT_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);
        let instance_id = NEXT_INSTANCE_ID.fetch_add(1, Ordering::Relaxed);

        Self {
            config,
            resources: RwLock::new(HashMap::new()),
            region_resources: RwLock::new(HashMap::new()),
            stats: RwLock::new(ResourceCleanupStats::default()),
            is_active: AtomicBool::new(false),
            instance_id,
        }
    }

    /// Start resource cleanup verification.
    pub fn start(&self) -> Result<(), ResourceCleanupError> {
        if !self.config.enable_verification {
            return Err(ResourceCleanupError::NotEnabled);
        }

        self.is_active.store(true, Ordering::Release);
        crate::tracing_compat::debug!(
            "Started resource cleanup verifier instance {}",
            self.instance_id
        );
        Ok(())
    }

    /// Stop resource cleanup verification.
    pub fn stop(&self) {
        self.is_active.store(false, Ordering::Release);
        crate::tracing_compat::debug!(
            "Stopped resource cleanup verifier instance {}",
            self.instance_id
        );
    }

    /// Check if verification is currently active.
    pub fn is_active(&self) -> bool {
        self.is_active.load(Ordering::Acquire)
    }

    /// Track allocation of a new resource.
    pub fn track_allocation(
        &self,
        resource_type: ResourceType,
        owner_region: Option<RegionId>,
        allocating_task: Option<TaskId>,
    ) -> Result<ResourceId, ResourceCleanupError> {
        if !self.is_active() {
            return Err(ResourceCleanupError::NotEnabled);
        }

        // Check if we should track this resource type
        if !self.config.tracked_resource_types.is_empty()
            && !self.config.tracked_resource_types.contains(&resource_type)
        {
            // Return a dummy ID for resources we're not tracking
            return Ok(ResourceId::new());
        }

        let mut record = ResourceRecord::new(resource_type, owner_region, allocating_task);
        let resource_id = record.id;

        // Update resource to active state if it has an owner region
        if let Some(region_id) = owner_region {
            record.activate(region_id)?;
        }

        // Insert into tracking database
        {
            let mut resources = self.resources.write();
            resources.insert(resource_id, record);

            // Evict oldest resources if we're over the limit
            if resources.len() > self.config.max_tracked_resources {
                // Find the oldest resource in Cleaned state to evict
                let oldest_cleaned = resources
                    .iter()
                    .filter(|(_, record)| record.state == ResourceState::Cleaned)
                    .min_by_key(|(_, record)| record.last_updated)
                    .map(|(id, _)| *id);

                if let Some(id_to_evict) = oldest_cleaned {
                    resources.remove(&id_to_evict);
                }
            }
        }

        // Track region ownership if applicable
        if let Some(region_id) = owner_region {
            let mut region_resources = self.region_resources.write();
            region_resources
                .entry(region_id)
                .or_insert_with(HashSet::new)
                .insert(resource_id);
        }

        // Update statistics
        {
            let mut stats = self.stats.write();
            stats.total_allocated += 1;
            stats.currently_tracked += 1;
            if stats.currently_tracked > stats.peak_tracked {
                stats.peak_tracked = stats.currently_tracked;
            }
        }

        crate::tracing_compat::trace!(
            "Tracked allocation: resource_id={:?} type={:?} region={:?}",
            resource_id,
            resource_type,
            owner_region
        );

        Ok(resource_id)
    }

    /// Mark a resource as cleaned up.
    pub fn track_cleanup(&self, resource_id: ResourceId) -> Result<(), ResourceCleanupError> {
        if !self.is_active() {
            return Err(ResourceCleanupError::NotEnabled);
        }

        let mut resources = self.resources.write();
        if let Some(record) = resources.get_mut(&resource_id) {
            record.complete_cleanup()?;

            // Update statistics
            drop(resources);
            let mut stats = self.stats.write();
            stats.total_cleaned += 1;
            stats.currently_tracked = stats.currently_tracked.saturating_sub(1);

            crate::tracing_compat::trace!("Tracked cleanup: resource_id={:?}", resource_id);
            Ok(())
        } else {
            Err(ResourceCleanupError::AttributionFailed { resource_id })
        }
    }

    /// Verify that all resources owned by a region are properly cleaned up.
    ///
    /// This is called during region close to enforce the "region close = quiescence"
    /// invariant includes proper resource cleanup.
    pub fn verify_region_cleanup(&self, region_id: RegionId) -> Result<(), ResourceCleanupError> {
        if !self.is_active() {
            return Ok(()); // Skip verification if disabled
        }

        // Get all resources owned by this region
        let owned_resources = {
            let region_resources = self.region_resources.read();
            region_resources
                .get(&region_id)
                .cloned()
                .unwrap_or_default()
        };

        if owned_resources.is_empty() {
            // No resources to clean up - perfect!
            let mut stats = self.stats.write();
            stats.clean_region_closes += 1;
            return Ok(());
        }

        // Check each owned resource for proper cleanup. Region close may only
        // succeed once every tracked resource is already Cleaned.
        let mut leaked_resources = Vec::new();
        let mut leaked_types = HashSet::new();
        let mut pending_resources = Vec::new();
        let mut pending_types = HashSet::new();

        {
            let mut resources = self.resources.write();
            for resource_id in &owned_resources {
                if let Some(record) = resources.get_mut(resource_id) {
                    match record.state {
                        ResourceState::Active => {
                            // Active at region close means cleanup did not run.
                            record.mark_leaked().ok();
                            leaked_resources.push(*resource_id);
                            leaked_types.insert(record.resource_type);
                        }
                        ResourceState::Cleaning => {
                            // Cleanup is in progress. Keep the region mapping
                            // until a later check either observes Cleaned or
                            // the grace period expires.
                            let grace_period = std::time::Duration::from_millis(
                                self.config.cleanup_grace_period_ms,
                            );
                            if record.last_updated.elapsed().unwrap_or(grace_period) >= grace_period
                            {
                                record.mark_leaked().ok();
                                leaked_resources.push(*resource_id);
                                leaked_types.insert(record.resource_type);
                            } else {
                                pending_resources.push(*resource_id);
                                pending_types.insert(record.resource_type);
                            }
                        }
                        ResourceState::Leaked => {
                            // Already marked as leaked
                            leaked_resources.push(*resource_id);
                            leaked_types.insert(record.resource_type);
                        }
                        ResourceState::Cleaned => {
                            // Resource properly cleaned up - no action needed
                        }
                        ResourceState::Allocated => {
                            // Resource never became active - mark as leaked
                            record.mark_leaked().ok();
                            leaked_resources.push(*resource_id);
                            leaked_types.insert(record.resource_type);
                        }
                    }
                }
            }
        }

        // Update statistics and clean up region mapping
        {
            let mut stats = self.stats.write();
            if leaked_resources.is_empty() && pending_resources.is_empty() {
                stats.clean_region_closes += 1;
            } else if !leaked_resources.is_empty() {
                stats.leaked_region_closes += 1;
                stats.total_leaked += leaked_resources.len() as u64;
                stats.currently_tracked = stats
                    .currently_tracked
                    .saturating_sub(leaked_resources.len() as u64);
            }
        }

        if !pending_resources.is_empty() && leaked_resources.is_empty() {
            let error = ResourceCleanupError::CleanupPending {
                region_id,
                pending_count: pending_resources.len(),
                resource_types: pending_types.into_iter().collect(),
            };

            crate::tracing_compat::debug!("Resource cleanup verification pending: {}", error);
            return Err(error);
        }

        if pending_resources.is_empty() || !leaked_resources.is_empty() {
            let mut region_resources = self.region_resources.write();
            region_resources.remove(&region_id);
        }

        // Report any leaks found
        if !leaked_resources.is_empty() {
            let error = ResourceCleanupError::ResourceLeak {
                region_id,
                leak_count: leaked_resources.len(),
                resource_types: leaked_types.into_iter().collect(),
            };

            crate::tracing_compat::error!("Resource cleanup verification failed: {}", error);

            // Log details of each leaked resource
            let resources = self.resources.read();
            for resource_id in &leaked_resources {
                if let Some(record) = resources.get(resource_id) {
                    crate::tracing_compat::warn!(
                        "Leaked resource: {:?} (type={:?}, allocated_at={:?})",
                        resource_id,
                        record.resource_type,
                        record.allocated_at
                    );
                }
            }

            if self.config.panic_on_leaks {
                panic!("Resource cleanup verification failed: {}", error);
            }

            return Err(error);
        }

        crate::tracing_compat::debug!(
            "Region cleanup verified successfully: region_id={:?} resources_cleaned={}",
            region_id,
            owned_resources.len()
        );

        Ok(())
    }

    /// Get current verification statistics.
    pub fn get_stats(&self) -> ResourceCleanupStats {
        self.stats.read().clone()
    }

    /// Get details of all currently tracked resources.
    pub fn get_tracked_resources(&self) -> HashMap<ResourceId, ResourceRecord> {
        self.resources.read().clone()
    }

    /// Get all resources owned by a specific region.
    pub fn get_region_resources(&self, region_id: RegionId) -> Vec<ResourceRecord> {
        let region_resources = self.region_resources.read();
        let resource_ids = region_resources
            .get(&region_id)
            .cloned()
            .unwrap_or_default();

        let resources = self.resources.read();
        resource_ids
            .into_iter()
            .filter_map(|id| resources.get(&id).cloned())
            .collect()
    }

    /// Force cleanup verification for all tracked resources.
    /// This is primarily for testing and debugging.
    pub fn force_global_cleanup_check(&self) -> Vec<ResourceCleanupError> {
        let mut errors = Vec::new();

        // Get all unique region IDs that own resources
        let region_ids: HashSet<RegionId> = {
            let region_resources = self.region_resources.read();
            region_resources.keys().copied().collect()
        };

        // Verify cleanup for each region
        for region_id in region_ids {
            if let Err(error) = self.verify_region_cleanup(region_id) {
                errors.push(error);
            }
        }

        errors
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_state_transitions() {
        use ResourceState::*;

        // Valid transitions
        assert!(Allocated.can_transition_to(Active));
        assert!(Allocated.can_transition_to(Cleaned));
        assert!(Active.can_transition_to(Cleaning));
        assert!(Active.can_transition_to(Cleaned));
        assert!(Cleaning.can_transition_to(Cleaned));
        assert!(Cleaned.can_transition_to(Cleaned));
        assert!(Active.can_transition_to(Leaked));
        assert!(Allocated.can_transition_to(Leaked));
        assert!(Cleaning.can_transition_to(Leaked));

        // Invalid transitions
        assert!(!Cleaned.can_transition_to(Active));
        assert!(!Leaked.can_transition_to(Cleaned));
        assert!(!Allocated.can_transition_to(Cleaning));
    }

    #[test]
    fn test_resource_record_lifecycle() {
        let region_id = RegionId::new_ephemeral();
        let task_id = TaskId::new_ephemeral();

        let mut record =
            ResourceRecord::new(ResourceType::FileDescriptor, Some(region_id), Some(task_id));

        assert_eq!(record.state, ResourceState::Allocated);

        // Activate resource
        record.activate(region_id).unwrap();
        assert_eq!(record.state, ResourceState::Active);
        assert_eq!(record.owner_region, Some(region_id));

        // Begin cleanup
        record.begin_cleanup().unwrap();
        assert_eq!(record.state, ResourceState::Cleaning);

        // Complete cleanup
        record.complete_cleanup().unwrap();
        assert_eq!(record.state, ResourceState::Cleaned);
    }

    #[test]
    fn test_resource_cleanup_verifier() {
        let config = ResourceCleanupConfig::default();
        let verifier = ResourceCleanupVerifier::new(config);

        // Start verification
        verifier.start().unwrap();
        assert!(verifier.is_active());

        let region_id = RegionId::new_ephemeral();

        // Track resource allocation
        let resource_id = verifier
            .track_allocation(ResourceType::FileDescriptor, Some(region_id), None)
            .unwrap();

        // Verify region has the resource
        let region_resources = verifier.get_region_resources(region_id);
        assert_eq!(region_resources.len(), 1);
        assert_eq!(region_resources[0].id, resource_id);

        // Clean up the resource
        verifier.track_cleanup(resource_id).unwrap();

        // Verify region cleanup
        verifier.verify_region_cleanup(region_id).unwrap();

        let stats = verifier.get_stats();
        assert_eq!(stats.total_allocated, 1);
        assert_eq!(stats.total_cleaned, 1);
        assert_eq!(stats.total_leaked, 0);
        assert_eq!(stats.clean_region_closes, 1);
    }

    #[test]
    fn test_resource_leak_detection() {
        let config = ResourceCleanupConfig {
            panic_on_leaks: false, // Don't panic in tests
            ..Default::default()
        };
        let verifier = ResourceCleanupVerifier::new(config);

        verifier.start().unwrap();

        let region_id = RegionId::new_ephemeral();

        // Allocate resource but don't clean it up
        let _resource_id = verifier
            .track_allocation(ResourceType::FileDescriptor, Some(region_id), None)
            .unwrap();

        // Try to close region without cleaning up resource
        let result = verifier.verify_region_cleanup(region_id);
        assert!(result.is_err());

        if let Err(ResourceCleanupError::ResourceLeak {
            region_id: leaked_region,
            leak_count,
            resource_types,
        }) = result
        {
            assert_eq!(leaked_region, region_id);
            assert_eq!(leak_count, 1);
            assert!(resource_types.contains(&ResourceType::FileDescriptor));
        } else {
            panic!("Expected ResourceLeak error");
        }

        let stats = verifier.get_stats();
        assert_eq!(stats.total_leaked, 1);
        assert_eq!(stats.leaked_region_closes, 1);
    }

    #[test]
    fn test_pending_cleanup_does_not_close_region_mapping() {
        let config = ResourceCleanupConfig {
            panic_on_leaks: false,
            cleanup_grace_period_ms: 60_000,
            ..Default::default()
        };
        let verifier = ResourceCleanupVerifier::new(config);
        verifier.start().unwrap();

        let region_id = RegionId::new_ephemeral();
        let resource_id = verifier
            .track_allocation(ResourceType::NetworkConnection, Some(region_id), None)
            .unwrap();

        {
            let mut resources = verifier.resources.write();
            resources
                .get_mut(&resource_id)
                .expect("tracked resource")
                .begin_cleanup()
                .expect("active resource can enter cleanup");
        }

        let result = verifier.verify_region_cleanup(region_id);
        assert!(matches!(
            result,
            Err(ResourceCleanupError::CleanupPending {
                pending_count: 1,
                ..
            })
        ));

        assert_eq!(
            verifier.get_region_resources(region_id).len(),
            1,
            "pending cleanup must remain attributed for a later recheck"
        );

        verifier.track_cleanup(resource_id).unwrap();
        verifier.verify_region_cleanup(region_id).unwrap();
        assert!(verifier.get_region_resources(region_id).is_empty());
    }
}
