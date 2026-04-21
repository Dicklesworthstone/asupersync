#![allow(warnings)]
#![allow(clippy::all)]
//! Resource leak detection infrastructure for cancellation testing.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::time::Instant;

/// Tracks resource usage to detect leaks during cancellation testing.
#[derive(Debug)]
#[allow(dead_code)]
pub struct ResourceTracker {
    /// Current number of waker registrations.
    waker_count: AtomicUsize,
    /// Baseline waker count at test start.
    baseline_waker_count: AtomicUsize,
    /// Current estimated memory usage in bytes.
    memory_usage: AtomicUsize,
    /// Baseline memory usage at test start.
    baseline_memory_usage: AtomicUsize,
    /// Maximum allowed resource growth.
    max_allowed_leak: usize,
    /// Detailed tracking per resource type.
    detailed_tracking: Arc<Mutex<HashMap<String, ResourceMetrics>>>,
    /// Whether tracking is currently enabled.
    tracking_enabled: AtomicUsize, // 0 = disabled, 1 = enabled
}

#[allow(dead_code)]

impl ResourceTracker {
    /// Create a new resource tracker.
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            waker_count: AtomicUsize::new(0),
            baseline_waker_count: AtomicUsize::new(0),
            memory_usage: AtomicUsize::new(0),
            baseline_memory_usage: AtomicUsize::new(0),
            max_allowed_leak: 1024, // 1KB tolerance
            detailed_tracking: Arc::new(Mutex::new(HashMap::new())),
            tracking_enabled: AtomicUsize::new(1),
        }
    }

    /// Reset all tracking to current baseline.
    #[allow(dead_code)]
    pub fn reset(&self) {
        let current_wakers = self.waker_count.load(Ordering::Acquire);
        let current_memory = self.memory_usage.load(Ordering::Acquire);

        self.baseline_waker_count.store(current_wakers, Ordering::Release);
        self.baseline_memory_usage.store(current_memory, Ordering::Release);

        if let Ok(mut tracking) = self.detailed_tracking.lock() {
            tracking.clear();
        }
    }

    /// Enable or disable tracking.
    #[allow(dead_code)]
    pub fn set_tracking_enabled(&self, enabled: bool) {
        self.tracking_enabled.store(enabled as usize, Ordering::Release);
    }

    /// Check if tracking is enabled.
    #[allow(dead_code)]
    pub fn is_tracking_enabled(&self) -> bool {
        self.tracking_enabled.load(Ordering::Acquire) != 0
    }

    /// Register a waker allocation.
    #[allow(dead_code)]
    pub fn track_waker_allocation(&self) {
        if self.is_tracking_enabled() {
            self.waker_count.fetch_add(1, Ordering::Release);
            self.track_resource("wakers", 1, ResourceOperation::Allocate);
        }
    }

    /// Register a waker deallocation.
    #[allow(dead_code)]
    pub fn track_waker_deallocation(&self) {
        if self.is_tracking_enabled() {
            self.waker_count.fetch_sub(1, Ordering::Release);
            self.track_resource("wakers", 1, ResourceOperation::Deallocate);
        }
    }

    /// Register memory allocation.
    #[allow(dead_code)]
    pub fn track_memory_allocation(&self, size: usize) {
        if self.is_tracking_enabled() {
            self.memory_usage.fetch_add(size, Ordering::Release);
            self.track_resource("memory", size, ResourceOperation::Allocate);
        }
    }

    /// Register memory deallocation.
    #[allow(dead_code)]
    pub fn track_memory_deallocation(&self, size: usize) {
        if self.is_tracking_enabled() {
            self.memory_usage.fetch_sub(size, Ordering::Release);
            self.track_resource("memory", size, ResourceOperation::Deallocate);
        }
    }

    /// Get current waker count.
    #[allow(dead_code)]
    pub fn current_waker_count(&self) -> usize {
        self.waker_count.load(Ordering::Acquire)
    }

    /// Get current memory usage.
    #[allow(dead_code)]
    pub fn current_memory_usage(&self) -> usize {
        self.memory_usage.load(Ordering::Acquire)
    }

    /// Get waker count delta from baseline.
    #[allow(dead_code)]
    pub fn waker_count_delta(&self) -> isize {
        let current = self.waker_count.load(Ordering::Acquire) as isize;
        let baseline = self.baseline_waker_count.load(Ordering::Acquire) as isize;
        current - baseline
    }

    /// Get memory usage delta from baseline.
    #[allow(dead_code)]
    pub fn memory_usage_delta(&self) -> isize {
        let current = self.memory_usage.load(Ordering::Acquire) as isize;
        let baseline = self.baseline_memory_usage.load(Ordering::Acquire) as isize;
        current - baseline
    }

    /// Assert that no resource leaks have occurred.
    #[allow(dead_code)]
    pub fn assert_no_leaks(&self) -> Result<(), ResourceLeakError> {
        let waker_delta = self.waker_count_delta();
        let memory_delta = self.memory_usage_delta();

        let mut leaks = Vec::new();

        // Check for waker leaks
        if waker_delta > 0 {
            leaks.push(ResourceLeak {
                resource_type: "wakers".to_string(),
                leaked_count: waker_delta as usize,
                baseline_count: self.baseline_waker_count.load(Ordering::Acquire),
                current_count: self.waker_count.load(Ordering::Acquire),
            });
        }

        // Check for memory leaks (with tolerance)
        if memory_delta > self.max_allowed_leak as isize {
            leaks.push(ResourceLeak {
                resource_type: "memory".to_string(),
                leaked_count: memory_delta as usize,
                baseline_count: self.baseline_memory_usage.load(Ordering::Acquire),
                current_count: self.memory_usage.load(Ordering::Acquire),
            });
        }

        if leaks.is_empty() {
            Ok(())
        } else {
            Err(ResourceLeakError { leaks })
        }
    }

    /// Get detailed resource metrics.
    #[allow(dead_code)]
    pub fn get_detailed_metrics(&self) -> HashMap<String, ResourceMetrics> {
        self.detailed_tracking
            .lock()
            .map(|tracking| tracking.clone())
            .unwrap_or_default()
    }

    /// Track a specific resource operation.
    #[allow(dead_code)]
    fn track_resource(&self, resource_type: &str, amount: usize, operation: ResourceOperation) {
        if let Ok(mut tracking) = self.detailed_tracking.lock() {
            let metrics = tracking.entry(resource_type.to_string()).or_insert_with(ResourceMetrics::new);

            match operation {
                ResourceOperation::Allocate => {
                    metrics.allocations += 1;
                    metrics.total_allocated += amount;
                    metrics.current_usage += amount;
                    metrics.peak_usage = metrics.peak_usage.max(metrics.current_usage);
                }
                ResourceOperation::Deallocate => {
                    metrics.deallocations += 1;
                    metrics.total_deallocated += amount;
                    metrics.current_usage = metrics.current_usage.saturating_sub(amount);
                }
            }

            metrics.last_operation = Some((operation, Instant::now()));
        }
    }
}

impl Default for ResourceTracker {
    #[allow(dead_code)]
    fn default() -> Self {
        Self::new()
    }
}

/// Detailed metrics for a specific resource type.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ResourceMetrics {
    /// Number of allocation operations.
    pub allocations: usize,
    /// Number of deallocation operations.
    pub deallocations: usize,
    /// Total amount allocated.
    pub total_allocated: usize,
    /// Total amount deallocated.
    pub total_deallocated: usize,
    /// Current usage amount.
    pub current_usage: usize,
    /// Peak usage observed.
    pub peak_usage: usize,
    /// Last operation performed.
    pub last_operation: Option<(ResourceOperation, Instant)>,
}

#[allow(dead_code)]

impl ResourceMetrics {
    /// Create new empty metrics.
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            allocations: 0,
            deallocations: 0,
            total_allocated: 0,
            total_deallocated: 0,
            current_usage: 0,
            peak_usage: 0,
            last_operation: None,
        }
    }

    /// Check if this resource type is leaking.
    #[allow(dead_code)]
    pub fn is_leaking(&self) -> bool {
        self.current_usage > 0
    }

    /// Get the leak amount.
    #[allow(dead_code)]
    pub fn leak_amount(&self) -> usize {
        self.current_usage
    }
}

impl Default for ResourceMetrics {
    #[allow(dead_code)]
    fn default() -> Self {
        Self::new()
    }
}

/// Type of resource operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ResourceOperation {
    Allocate,
    Deallocate,
}

/// Represents a detected resource leak.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ResourceLeak {
    /// Type of resource that leaked.
    pub resource_type: String,
    /// Number of units leaked.
    pub leaked_count: usize,
    /// Baseline count at test start.
    pub baseline_count: usize,
    /// Current count.
    pub current_count: usize,
}

impl std::fmt::Display for ResourceLeak {
    #[allow(dead_code)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} leak: {} units (baseline: {}, current: {})",
               self.resource_type, self.leaked_count, self.baseline_count, self.current_count)
    }
}

/// Error indicating resource leaks were detected.
#[derive(Debug)]
#[allow(dead_code)]
pub struct ResourceLeakError {
    /// List of detected leaks.
    pub leaks: Vec<ResourceLeak>,
}

impl std::fmt::Display for ResourceLeakError {
    #[allow(dead_code)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Resource leaks detected: ")?;
        for (i, leak) in self.leaks.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", leak)?;
        }
        Ok(())
    }
}

impl std::error::Error for ResourceLeakError {}

/// RAII guard for tracking resource usage within a scope.
#[allow(dead_code)]
pub struct ResourceTrackingScope<'a> {
    tracker: &'a ResourceTracker,
    initial_wakers: usize,
    initial_memory: usize,
}

impl<'a> ResourceTrackingScope<'a> {
    /// Create a new tracking scope.
    #[allow(dead_code)]
    pub fn new(tracker: &'a ResourceTracker) -> Self {
        let initial_wakers = tracker.current_waker_count();
        let initial_memory = tracker.current_memory_usage();

        Self {
            tracker,
            initial_wakers,
            initial_memory,
        }
    }

    /// Get the resource delta since scope creation.
    #[allow(dead_code)]
    pub fn get_delta(&self) -> (isize, isize) {
        let current_wakers = self.tracker.current_waker_count() as isize;
        let current_memory = self.tracker.current_memory_usage() as isize;

        let waker_delta = current_wakers - self.initial_wakers as isize;
        let memory_delta = current_memory - self.initial_memory as isize;

        (waker_delta, memory_delta)
    }

    /// Assert no leaks occurred in this scope.
    #[allow(dead_code)]
    pub fn assert_no_leaks_in_scope(&self) -> Result<(), ResourceLeakError> {
        let (waker_delta, memory_delta) = self.get_delta();
        let mut leaks = Vec::new();

        if waker_delta > 0 {
            leaks.push(ResourceLeak {
                resource_type: "wakers".to_string(),
                leaked_count: waker_delta as usize,
                baseline_count: self.initial_wakers,
                current_count: self.tracker.current_waker_count(),
            });
        }

        if memory_delta > 1024 { // 1KB tolerance
            leaks.push(ResourceLeak {
                resource_type: "memory".to_string(),
                leaked_count: memory_delta as usize,
                baseline_count: self.initial_memory,
                current_count: self.tracker.current_memory_usage(),
            });
        }

        if leaks.is_empty() {
            Ok(())
        } else {
            Err(ResourceLeakError { leaks })
        }
    }
}

/// Global resource tracker instance for convenience.
static GLOBAL_TRACKER: std::sync::OnceLock<ResourceTracker> = std::sync::OnceLock::new();

/// Get the global resource tracker instance.
#[allow(dead_code)]
pub fn global_tracker() -> &'static ResourceTracker {
    GLOBAL_TRACKER.get_or_init(ResourceTracker::new)
}

/// Convenience function to track waker allocation globally.
#[allow(dead_code)]
pub fn track_waker_allocation() {
    global_tracker().track_waker_allocation();
}

/// Convenience function to track waker deallocation globally.
#[allow(dead_code)]
pub fn track_waker_deallocation() {
    global_tracker().track_waker_deallocation();
}

/// Convenience function to track memory allocation globally.
#[allow(dead_code)]
pub fn track_memory_allocation(size: usize) {
    global_tracker().track_memory_allocation(size);
}

/// Convenience function to track memory deallocation globally.
#[allow(dead_code)]
pub fn track_memory_deallocation(size: usize) {
    global_tracker().track_memory_deallocation(size);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    #[allow(dead_code)]
    fn test_resource_tracker_basic() {
        let tracker = ResourceTracker::new();
        tracker.reset();

        // Track some allocations
        tracker.track_waker_allocation();
        tracker.track_waker_allocation();
        tracker.track_memory_allocation(100);

        assert_eq!(tracker.waker_count_delta(), 2);
        assert_eq!(tracker.memory_usage_delta(), 100);

        // Should detect leaks
        assert!(tracker.assert_no_leaks().is_err());

        // Clean up
        tracker.track_waker_deallocation();
        tracker.track_waker_deallocation();
        tracker.track_memory_deallocation(100);

        // Should be clean now
        assert!(tracker.assert_no_leaks().is_ok());
    }

    #[test]
    #[allow(dead_code)]
    fn test_resource_tracking_scope() {
        let tracker = ResourceTracker::new();
        tracker.reset();

        let scope = ResourceTrackingScope::new(&tracker);

        // Allocate resources
        tracker.track_waker_allocation();
        tracker.track_memory_allocation(50);

        // Should detect leaks in scope
        assert!(scope.assert_no_leaks_in_scope().is_err());

        // Clean up
        tracker.track_waker_deallocation();
        tracker.track_memory_deallocation(50);

        // Should be clean now
        assert!(scope.assert_no_leaks_in_scope().is_ok());
    }

    #[test]
    #[allow(dead_code)]
    fn test_detailed_metrics() {
        let tracker = ResourceTracker::new();
        tracker.reset();

        // Track some operations
        tracker.track_waker_allocation();
        tracker.track_waker_allocation();
        tracker.track_waker_deallocation();
        tracker.track_memory_allocation(200);

        let metrics = tracker.get_detailed_metrics();

        assert!(metrics.contains_key("wakers"));
        assert!(metrics.contains_key("memory"));

        let waker_metrics = &metrics["wakers"];
        assert_eq!(waker_metrics.allocations, 2);
        assert_eq!(waker_metrics.deallocations, 1);
        assert_eq!(waker_metrics.current_usage, 1);

        let memory_metrics = &metrics["memory"];
        assert_eq!(memory_metrics.allocations, 1);
        assert_eq!(memory_metrics.total_allocated, 200);
        assert_eq!(memory_metrics.current_usage, 200);
    }
}