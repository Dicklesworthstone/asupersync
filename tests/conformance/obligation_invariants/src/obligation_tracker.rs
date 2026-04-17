//! Obligation invariant tracking and validation infrastructure.
//!
//! This module provides comprehensive tracking of obligation lifecycles to validate
//! structured concurrency invariants in the asupersync runtime.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, Weak};
use std::time::Instant;

use asupersync::types::{ObligationId, RegionId};

/// Tracks obligations and validates structured concurrency invariants.
#[derive(Debug, Clone)]
pub struct ObligationTracker {
    inner: Arc<Mutex<ObligationTrackerInner>>,
}

#[derive(Debug)]
struct ObligationTrackerInner {
    /// Active obligations with their metadata
    active_obligations: HashMap<ObligationId, ObligationMetadata>,
    /// Region hierarchy tracking
    region_hierarchy: RegionTree,
    /// Resource tracking for leak detection
    resource_tracker: ResourceTracker,
    /// Detected invariant violations
    invariant_violations: Vec<InvariantViolation>,
    /// Tracking start time for metrics
    start_time: Instant,
}

/// Metadata tracked for each obligation
#[derive(Debug, Clone)]
pub struct ObligationMetadata {
    pub obligation_id: ObligationId,
    pub parent_region: RegionId,
    pub creation_time: Instant,
    pub state: ObligationState,
    pub children: HashSet<ObligationId>,
    pub resources: HashSet<ResourceHandle>,
    pub cancel_token: Option<CancelToken>,
}

/// Current state of an obligation
#[derive(Debug, Clone, PartialEq)]
pub enum ObligationState {
    Active,
    Resolving,
    Resolved,
    Cancelled,
    Aborted,
}

/// Tracks region hierarchy for quiescence validation
#[derive(Debug, Default)]
pub struct RegionTree {
    regions: HashMap<RegionId, RegionMetadata>,
    parent_child_map: HashMap<RegionId, HashSet<RegionId>>,
    child_parent_map: HashMap<RegionId, RegionId>,
}

/// Metadata for each region
#[derive(Debug, Clone)]
pub struct RegionMetadata {
    pub region_id: RegionId,
    pub creation_time: Instant,
    pub state: RegionState,
    pub obligations: HashSet<ObligationId>,
    pub close_initiated: Option<Instant>,
}

/// Current state of a region
#[derive(Debug, Clone, PartialEq)]
pub enum RegionState {
    Active,
    Closing,
    Closed,
}

/// Resource tracking for leak detection
#[derive(Debug, Default)]
pub struct ResourceTracker {
    /// File descriptors allocated by obligations
    file_descriptors: HashMap<ObligationId, HashSet<i32>>,
    /// Memory allocations tracked by obligations
    memory_allocations: HashMap<ObligationId, HashSet<usize>>,
    /// Waker registrations by obligation
    waker_registrations: HashMap<ObligationId, HashSet<WakerHandle>>,
    /// Network connections by obligation
    network_connections: HashMap<ObligationId, HashSet<ConnectionHandle>>,
}

/// Handle to a tracked resource
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ResourceHandle {
    FileDescriptor(i32),
    MemoryAllocation(usize),
    WakerRegistration(WakerHandle),
    NetworkConnection(ConnectionHandle),
}

/// Handle to a waker registration
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WakerHandle {
    pub id: u64,
    pub registration_time: u64, // timestamp as u64 for hash
}

/// Handle to a network connection
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionHandle {
    pub id: u64,
    pub local_addr: String,
    pub remote_addr: String,
}

/// Cancel token for obligation cancellation
#[derive(Debug, Clone)]
pub struct CancelToken {
    pub token_id: u64,
    pub is_cancelled: Arc<std::sync::atomic::AtomicBool>,
}

/// Detected invariant violation
#[derive(Debug, Clone)]
pub struct InvariantViolation {
    pub violation_type: InvariantViolationType,
    pub obligation_id: Option<ObligationId>,
    pub region_id: Option<RegionId>,
    pub detection_time: Instant,
    pub description: String,
    pub stack_trace: Option<String>,
}

/// Types of invariant violations
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum InvariantViolationType {
    /// Obligation leak - obligation not properly resolved
    ObligationLeak,
    /// Region quiescence violation - region closed with active obligations
    RegionQuiescenceViolation,
    /// Cancel propagation failure - cancel signal not propagated
    CancelPropagationFailure,
    /// Resource leak - resources not cleaned up on obligation completion
    ResourceLeak,
    /// Temporal safety violation - obligation outlived parent region
    TemporalSafetyViolation,
}

impl ObligationTracker {
    /// Create a new obligation tracker
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(ObligationTrackerInner {
                active_obligations: HashMap::new(),
                region_hierarchy: RegionTree::default(),
                resource_tracker: ResourceTracker::default(),
                invariant_violations: Vec::new(),
                start_time: Instant::now(),
            })),
        }
    }

    /// Track creation of a new obligation
    pub fn track_obligation_creation(&self, obligation_id: ObligationId, parent_region: RegionId) {
        let mut inner = self.inner.lock().unwrap();

        let metadata = ObligationMetadata {
            obligation_id,
            parent_region,
            creation_time: Instant::now(),
            state: ObligationState::Active,
            children: HashSet::new(),
            resources: HashSet::new(),
            cancel_token: None,
        };

        inner.active_obligations.insert(obligation_id, metadata);

        // Add to parent region
        if let Some(region) = inner.region_hierarchy.regions.get_mut(&parent_region) {
            region.obligations.insert(obligation_id);
        }
    }

    /// Track resolution of an obligation
    pub fn track_obligation_resolution(&self, obligation_id: ObligationId) {
        let mut inner = self.inner.lock().unwrap();

        if let Some(metadata) = inner.active_obligations.get_mut(&obligation_id) {
            metadata.state = ObligationState::Resolved;

            // Validate resource cleanup
            if !metadata.resources.is_empty() {
                let violation = InvariantViolation {
                    violation_type: InvariantViolationType::ResourceLeak,
                    obligation_id: Some(obligation_id),
                    region_id: Some(metadata.parent_region),
                    detection_time: Instant::now(),
                    description: format!(
                        "Obligation {} resolved with {} uncleaned resources",
                        obligation_id.0,
                        metadata.resources.len()
                    ),
                    stack_trace: None,
                };
                inner.invariant_violations.push(violation);
            }

            // Remove from active tracking
            inner.active_obligations.remove(&obligation_id);

            // Remove from parent region
            if let Some(region) = inner
                .region_hierarchy
                .regions
                .get_mut(&metadata.parent_region)
            {
                region.obligations.remove(&obligation_id);
            }
        }
    }

    /// Track cancellation of an obligation
    pub fn track_obligation_cancellation(&self, obligation_id: ObligationId) {
        let mut inner = self.inner.lock().unwrap();

        if let Some(metadata) = inner.active_obligations.get_mut(&obligation_id) {
            metadata.state = ObligationState::Cancelled;

            // Mark cancel token as cancelled
            if let Some(ref token) = metadata.cancel_token {
                token
                    .is_cancelled
                    .store(true, std::sync::atomic::Ordering::SeqCst);
            }

            // Propagate cancellation to children
            let children: Vec<_> = metadata.children.iter().copied().collect();
            drop(inner); // Release lock before recursive calls

            for child_id in children {
                self.track_obligation_cancellation(child_id);
            }
        }
    }

    /// Track creation of a region
    pub fn track_region_creation(&self, region_id: RegionId, parent_region: Option<RegionId>) {
        let mut inner = self.inner.lock().unwrap();

        let metadata = RegionMetadata {
            region_id,
            creation_time: Instant::now(),
            state: RegionState::Active,
            obligations: HashSet::new(),
            close_initiated: None,
        };

        inner.region_hierarchy.regions.insert(region_id, metadata);

        // Update parent-child relationships
        if let Some(parent) = parent_region {
            inner
                .region_hierarchy
                .parent_child_map
                .entry(parent)
                .or_default()
                .insert(region_id);
            inner
                .region_hierarchy
                .child_parent_map
                .insert(region_id, parent);
        }
    }

    /// Track initiation of region closure
    pub fn track_region_close_initiation(&self, region_id: RegionId) {
        let mut inner = self.inner.lock().unwrap();

        if let Some(region) = inner.region_hierarchy.regions.get_mut(&region_id) {
            region.state = RegionState::Closing;
            region.close_initiated = Some(Instant::now());

            // Validate quiescence - region should have no active obligations
            if !region.obligations.is_empty() {
                let active_count = region.obligations.len();
                let violation = InvariantViolation {
                    violation_type: InvariantViolationType::RegionQuiescenceViolation,
                    obligation_id: None,
                    region_id: Some(region_id),
                    detection_time: Instant::now(),
                    description: format!(
                        "Region {} close initiated with {} active obligations",
                        region_id.0, active_count
                    ),
                    stack_trace: None,
                };
                inner.invariant_violations.push(violation);
            }
        }
    }

    /// Track completion of region closure
    pub fn track_region_close_completion(&self, region_id: RegionId) {
        let mut inner = self.inner.lock().unwrap();

        if let Some(region) = inner.region_hierarchy.regions.get_mut(&region_id) {
            region.state = RegionState::Closed;

            // Final quiescence validation
            if !region.obligations.is_empty() {
                let violation = InvariantViolation {
                    violation_type: InvariantViolationType::RegionQuiescenceViolation,
                    obligation_id: None,
                    region_id: Some(region_id),
                    detection_time: Instant::now(),
                    description: format!(
                        "Region {} closed with {} unresolved obligations",
                        region_id.0,
                        region.obligations.len()
                    ),
                    stack_trace: None,
                };
                inner.invariant_violations.push(violation);
            }
        }
    }

    /// Track resource allocation for an obligation
    pub fn track_resource_allocation(&self, obligation_id: ObligationId, resource: ResourceHandle) {
        let mut inner = self.inner.lock().unwrap();

        if let Some(metadata) = inner.active_obligations.get_mut(&obligation_id) {
            metadata.resources.insert(resource.clone());
        }

        // Update resource tracker
        match resource {
            ResourceHandle::FileDescriptor(fd) => {
                inner
                    .resource_tracker
                    .file_descriptors
                    .entry(obligation_id)
                    .or_default()
                    .insert(fd);
            }
            ResourceHandle::MemoryAllocation(ptr) => {
                inner
                    .resource_tracker
                    .memory_allocations
                    .entry(obligation_id)
                    .or_default()
                    .insert(ptr);
            }
            ResourceHandle::WakerRegistration(handle) => {
                inner
                    .resource_tracker
                    .waker_registrations
                    .entry(obligation_id)
                    .or_default()
                    .insert(handle);
            }
            ResourceHandle::NetworkConnection(handle) => {
                inner
                    .resource_tracker
                    .network_connections
                    .entry(obligation_id)
                    .or_default()
                    .insert(handle);
            }
        }
    }

    /// Track resource deallocation for an obligation
    pub fn track_resource_deallocation(
        &self,
        obligation_id: ObligationId,
        resource: ResourceHandle,
    ) {
        let mut inner = self.inner.lock().unwrap();

        if let Some(metadata) = inner.active_obligations.get_mut(&obligation_id) {
            metadata.resources.remove(&resource);
        }

        // Update resource tracker
        match resource {
            ResourceHandle::FileDescriptor(fd) => {
                if let Some(fds) = inner
                    .resource_tracker
                    .file_descriptors
                    .get_mut(&obligation_id)
                {
                    let _: bool = fds.remove(&fd);
                }
            }
            ResourceHandle::MemoryAllocation(ptr) => {
                if let Some(ptrs) = inner
                    .resource_tracker
                    .memory_allocations
                    .get_mut(&obligation_id)
                {
                    let _: bool = ptrs.remove(&ptr);
                }
            }
            ResourceHandle::WakerRegistration(handle) => {
                if let Some(wakers) = inner
                    .resource_tracker
                    .waker_registrations
                    .get_mut(&obligation_id)
                {
                    let _: bool = wakers.remove(&handle);
                }
            }
            ResourceHandle::NetworkConnection(handle) => {
                if let Some(conns) = inner
                    .resource_tracker
                    .network_connections
                    .get_mut(&obligation_id)
                {
                    let _: bool = conns.remove(&handle);
                }
            }
        }
    }

    /// Check if there are any active obligations
    pub fn has_active_obligations(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        !inner.active_obligations.is_empty()
    }

    /// Check if a region is quiescent (no active obligations)
    pub fn is_region_quiescent(&self, region_id: RegionId) -> bool {
        let inner = self.inner.lock().unwrap();
        if let Some(region) = inner.region_hierarchy.regions.get(&region_id) {
            region.obligations.is_empty()
        } else {
            true // Non-existent region is considered quiescent
        }
    }

    /// Get count of active obligations
    pub fn active_obligation_count(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.active_obligations.len()
    }

    /// Get all detected invariant violations
    pub fn get_invariant_violations(&self) -> Vec<InvariantViolation> {
        let inner = self.inner.lock().unwrap();
        inner.invariant_violations.clone()
    }

    /// Clear all tracked data (for test cleanup)
    pub fn reset(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.active_obligations.clear();
        inner.region_hierarchy = RegionTree::default();
        inner.resource_tracker = ResourceTracker::default();
        inner.invariant_violations.clear();
        inner.start_time = Instant::now();
    }

    /// Validate all invariants and return violations
    pub fn validate_invariants(&self) -> Vec<InvariantViolation> {
        let mut inner = self.inner.lock().unwrap();
        let mut violations = Vec::new();

        // Check for obligation leaks
        for (obligation_id, metadata) in &inner.active_obligations {
            if matches!(
                metadata.state,
                ObligationState::Active | ObligationState::Resolving
            ) {
                let age = metadata.creation_time.elapsed();
                if age > std::time::Duration::from_secs(30) {
                    // Configurable timeout
                    violations.push(InvariantViolation {
                        violation_type: InvariantViolationType::ObligationLeak,
                        obligation_id: Some(*obligation_id),
                        region_id: Some(metadata.parent_region),
                        detection_time: Instant::now(),
                        description: format!(
                            "Obligation {} active for {:?}, potential leak",
                            obligation_id.0, age
                        ),
                        stack_trace: None,
                    });
                }
            }
        }

        // Check for resource leaks
        for (obligation_id, metadata) in &inner.active_obligations {
            if matches!(
                metadata.state,
                ObligationState::Resolved | ObligationState::Cancelled
            ) && !metadata.resources.is_empty()
            {
                violations.push(InvariantViolation {
                    violation_type: InvariantViolationType::ResourceLeak,
                    obligation_id: Some(*obligation_id),
                    region_id: Some(metadata.parent_region),
                    detection_time: Instant::now(),
                    description: format!(
                        "Obligation {} has {} leaked resources after completion",
                        obligation_id.0,
                        metadata.resources.len()
                    ),
                    stack_trace: None,
                });
            }
        }

        inner.invariant_violations.extend(violations.clone());
        violations
    }
}

impl Default for ObligationTracker {
    fn default() -> Self {
        Self::new()
    }
}
