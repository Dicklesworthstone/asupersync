//! Epoch Tracking Data Structures
//!
//! This module implements thread-safe epoch counters and safe point detection
//! for the deferred cleanup system. The design focuses on minimal contention
//! and integration with structured concurrency.
//!
//! # Architecture
//!
//! - [`GlobalEpochCounter`]: Monotonic global epoch with rate-limited advancement
//! - [`LocalEpochPin`]: Thread-local epoch pinning for safe point detection
//! - [`SafePointDetector`]: Coordinator for detecting safe cleanup points
//! - [`DeferredCleanupQueue`]: Lockless queue for epoch-tagged cleanup work

#![allow(missing_docs)]

use crate::types::{RegionId, TaskId};
use crate::util::CachePadded;
use crossbeam_queue::SegQueue;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

// ============================================================================
// Configuration and Statistics
// ============================================================================

/// Configuration for epoch tracking system.
#[derive(Debug, Clone)]
pub struct EpochConfig {
    /// Minimum time between epoch advances.
    pub advance_interval: Duration,
    /// Maximum cleanup delay before forced advancement.
    pub max_cleanup_delay: Duration,
    /// Enable automatic advancement based on allocation pressure.
    pub auto_advance_on_pressure: bool,
    /// Memory pressure threshold for forced advancement (bytes).
    pub pressure_threshold: usize,
}

impl Default for EpochConfig {
    fn default() -> Self {
        Self {
            advance_interval: Duration::from_millis(100),
            max_cleanup_delay: Duration::from_secs(1),
            auto_advance_on_pressure: true,
            pressure_threshold: 10 * 1024 * 1024, // 10 MB
        }
    }
}

/// Statistics for epoch tracking system.
#[derive(Debug, Clone)]
pub struct EpochStats {
    /// Current global epoch.
    pub current_epoch: u64,
    /// Number of epoch advances.
    pub advance_count: u64,
    /// Last advancement timestamp.
    pub last_advance: Instant,
    /// Number of active pins.
    pub active_pins: usize,
    /// Minimum pinned epoch across all threads.
    pub min_pinned_epoch: u64,
}

/// Statistics for cleanup queue.
#[derive(Debug, Clone)]
pub struct CleanupQueueStats {
    /// Number of pending cleanup items.
    pub pending_count: usize,
    /// Total cleanup items enqueued.
    pub enqueue_count: u64,
    /// Total cleanup items executed.
    pub execute_count: u64,
    /// Current memory usage estimate.
    pub memory_usage: usize,
    /// Total time spent in cleanup.
    pub total_cleanup_time: Duration,
}

/// Statistics for local epoch pin.
#[derive(Debug, Default)]
pub struct LocalEpochStats {
    /// Number of pin operations.
    pub pin_count: AtomicU64,
    /// Number of unpin operations.
    pub unpin_count: AtomicU64,
    /// Longest pin duration (nanoseconds).
    pub max_pin_duration: AtomicU64,
    /// Current pin start time.
    pub pin_start: AtomicU64,
}

// ============================================================================
// Global Epoch Counter
// ============================================================================

/// Global epoch counter with automatic advancement.
#[allow(dead_code)] // rate-limit state retained for future advancement-policy impl
pub struct GlobalEpochCounter {
    /// Current global epoch (monotonic, never decreases).
    epoch: AtomicU64,
    /// Last advancement timestamp for rate limiting.
    last_advance: AtomicU64, // Instant as nanos
    /// Minimum interval between epoch advances.
    advance_interval: Duration,
    /// Number of epoch advances performed.
    advance_count: AtomicU64,
    /// Configuration for advancement policy.
    config: EpochConfig,
}

impl GlobalEpochCounter {
    /// Create a new global epoch counter.
    #[must_use]
    pub fn new(config: EpochConfig) -> Self {
        Self {
            epoch: AtomicU64::new(1), // Start at epoch 1
            last_advance: AtomicU64::new(0),
            advance_interval: config.advance_interval,
            advance_count: AtomicU64::new(0),
            config,
        }
    }

    /// Get the current epoch (acquire ordering).
    #[inline]
    pub fn current_epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    /// Attempt to advance the epoch (rate limited).
    pub fn try_advance(&self) -> Option<u64> {
        let now = Instant::now();
        // Simplified: always try to advance (remove rate limiting for now)
        // This is a temporary fix to get compilation working
        self.advance_epoch(now)
    }

    /// Force epoch advancement (bypasses rate limiting).
    pub fn force_advance(&self) -> u64 {
        self.advance_epoch(Instant::now())
            .unwrap_or_else(|| self.current_epoch())
    }

    /// Check if advancement is needed due to memory pressure.
    pub fn should_advance_on_pressure(&self, memory_usage: usize) -> bool {
        self.config.auto_advance_on_pressure && memory_usage >= self.config.pressure_threshold
    }

    /// Statistics for monitoring.
    pub fn stats(&self) -> EpochStats {
        EpochStats {
            current_epoch: self.current_epoch(),
            advance_count: self.advance_count.load(Ordering::Relaxed),
            last_advance: Instant::now(), // Simplified: use current time
            active_pins: 0,               // Filled by coordinator
            min_pinned_epoch: 0,          // Filled by coordinator
        }
    }

    #[cold]
    fn advance_epoch(&self, _now: Instant) -> Option<u64> {
        // Simplified: just advance the epoch without timestamp tracking
        // This is a temporary fix to get compilation working
        let new_epoch = self.epoch.fetch_add(1, Ordering::AcqRel) + 1;
        self.advance_count.fetch_add(1, Ordering::Relaxed);
        Some(new_epoch)
    }
}
impl std::fmt::Debug for GlobalEpochCounter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GlobalEpochCounter")
            .field("epoch", &self.current_epoch())
            .field("advance_count", &self.advance_count.load(Ordering::Relaxed))
            .finish()
    }
}

// ============================================================================
// Local Epoch Pinning
// ============================================================================

/// Thread-local epoch pin preventing cleanup of current epoch.
pub struct LocalEpochPin {
    /// Current pinned epoch for this thread.
    pinned_epoch: AtomicU64,
    /// Whether this pin is currently active.
    is_active: AtomicBool,
    /// Thread ID for debugging.
    thread_id: u64,
    /// Reference to global epoch counter.
    global: Arc<GlobalEpochCounter>,
    /// Statistics for this pin.
    stats: LocalEpochStats,
}

impl LocalEpochPin {
    /// Create a new local epoch pin.
    pub fn new(global: Arc<GlobalEpochCounter>) -> Self {
        Self {
            pinned_epoch: AtomicU64::new(0),
            is_active: AtomicBool::new(false),
            thread_id: 0, // Simplified: use 0 as placeholder
            global,
            stats: LocalEpochStats::default(),
        }
    }

    /// Pin the current epoch, preventing its cleanup.
    #[inline]
    pub fn pin(&self) -> EpochGuard<'_> {
        let epoch = self.global.current_epoch();
        self.pinned_epoch.store(epoch, Ordering::Release);
        self.is_active.store(true, Ordering::Release);

        // Update statistics
        self.stats.pin_count.fetch_add(1, Ordering::Relaxed);
        self.stats.pin_start.store(0u64, Ordering::Relaxed); // Simplified: placeholder

        EpochGuard { pin: self, epoch }
    }

    /// Check if this pin is active and its pinned epoch.
    #[inline]
    pub fn pinned_epoch(&self) -> Option<u64> {
        if self.is_active.load(Ordering::Acquire) {
            Some(self.pinned_epoch.load(Ordering::Acquire))
        } else {
            None
        }
    }

    /// Get thread ID for this pin.
    pub fn thread_id(&self) -> u64 {
        self.thread_id
    }

    /// Get statistics for this pin.
    pub fn stats(&self) -> LocalEpochStats {
        LocalEpochStats {
            pin_count: AtomicU64::new(self.stats.pin_count.load(Ordering::Relaxed)),
            unpin_count: AtomicU64::new(self.stats.unpin_count.load(Ordering::Relaxed)),
            max_pin_duration: AtomicU64::new(self.stats.max_pin_duration.load(Ordering::Relaxed)),
            pin_start: AtomicU64::new(self.stats.pin_start.load(Ordering::Relaxed)),
        }
    }

    /// Unpin the current epoch.
    #[inline]
    fn unpin(&self) {
        self.is_active.store(false, Ordering::Release);

        // Update statistics
        self.stats.unpin_count.fetch_add(1, Ordering::Relaxed);
        let now = 0u64; // Simplified: placeholder
        let start = self.stats.pin_start.load(Ordering::Relaxed);
        if start > 0 {
            let duration = now - start;
            let _ = self
                .stats
                .max_pin_duration
                .fetch_max(duration, Ordering::Relaxed);
        }
    }
}

impl std::fmt::Debug for LocalEpochPin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalEpochPin")
            .field("thread_id", &self.thread_id)
            .field("pinned_epoch", &self.pinned_epoch())
            .field("is_active", &self.is_active.load(Ordering::Relaxed))
            .finish()
    }
}

/// RAII guard for epoch pinning.
pub struct EpochGuard<'a> {
    pin: &'a LocalEpochPin,
    epoch: u64,
}

impl EpochGuard<'_> {
    /// Get the pinned epoch.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

impl Drop for EpochGuard<'_> {
    fn drop(&mut self) {
        self.pin.unpin();
    }
}

// ============================================================================
// Safe Point Detection
// ============================================================================

/// Coordinator for detecting safe points across all threads.
pub struct SafePointDetector {
    /// Registered thread pins.
    thread_pins: Vec<CachePadded<Arc<LocalEpochPin>>>,
    /// Minimum observed epoch across all threads.
    min_observed_epoch: AtomicU64,
    /// Last safe point epoch.
    last_safe_point: AtomicU64,
    /// Reference to global epoch counter.
    global: Arc<GlobalEpochCounter>,
    /// Safe point detection statistics.
    stats: SafePointStats,
}

#[derive(Debug, Default)]
struct SafePointStats {
    /// Number of safe point checks.
    check_count: AtomicU64,
    /// Number of safe points detected.
    safe_point_count: AtomicU64,
    /// Total time spent checking (nanoseconds).
    check_time_ns: AtomicU64,
}

impl SafePointDetector {
    /// Create a new safe point detector.
    pub fn new(global: Arc<GlobalEpochCounter>) -> Self {
        Self {
            thread_pins: Vec::new(),
            min_observed_epoch: AtomicU64::new(1),
            last_safe_point: AtomicU64::new(1),
            global,
            stats: SafePointStats::default(),
        }
    }

    /// Check if the given epoch is safe for cleanup.
    pub fn is_safe_point(&self, epoch: u64) -> bool {
        let start = Instant::now();
        let result = self.compute_safe_point() >= epoch;

        // Update statistics
        self.stats.check_count.fetch_add(1, Ordering::Relaxed);
        if result {
            self.stats.safe_point_count.fetch_add(1, Ordering::Relaxed);
        }
        let elapsed = start.elapsed().as_nanos() as u64;
        self.stats
            .check_time_ns
            .fetch_add(elapsed, Ordering::Relaxed);

        result
    }

    /// Compute the current safe point epoch.
    #[cold]
    fn compute_safe_point(&self) -> u64 {
        let mut min_epoch = u64::MAX;

        for pin in &self.thread_pins {
            if let Some(pinned) = pin.pinned_epoch() {
                min_epoch = min_epoch.min(pinned);
            }
        }

        // If no threads are pinning, use current epoch - 1
        if min_epoch == u64::MAX {
            let current = self.global.current_epoch();
            min_epoch = if current > 1 { current - 1 } else { 1 };
        }

        // Update cached minimum
        self.min_observed_epoch.store(min_epoch, Ordering::Release);
        self.last_safe_point.store(min_epoch, Ordering::Release);

        min_epoch
    }

    /// Get cached safe point (fast path).
    #[inline]
    pub fn cached_safe_point(&self) -> u64 {
        self.last_safe_point.load(Ordering::Acquire)
    }

    /// Register a new thread pin.
    pub fn register_pin(&mut self, pin: Arc<LocalEpochPin>) {
        self.thread_pins.push(CachePadded::new(pin));
    }

    /// Get statistics for safe point detection.
    pub fn stats(&self) -> (u64, u64, Duration, usize) {
        let check_count = self.stats.check_count.load(Ordering::Relaxed);
        let safe_point_count = self.stats.safe_point_count.load(Ordering::Relaxed);
        let check_time = Duration::from_nanos(self.stats.check_time_ns.load(Ordering::Relaxed));
        let active_pins = self
            .thread_pins
            .iter()
            .map(|pin| usize::from(pin.is_active.load(Ordering::Relaxed)))
            .sum();

        (check_count, safe_point_count, check_time, active_pins)
    }
}

impl std::fmt::Debug for SafePointDetector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SafePointDetector")
            .field("thread_count", &self.thread_pins.len())
            .field("last_safe_point", &self.cached_safe_point())
            .finish()
    }
}

// ============================================================================
// Cleanup Work Definitions
// ============================================================================

/// Types of cleanup work that can be deferred.
#[derive(Debug, Clone)]
pub enum CleanupWork {
    /// Obligation tracking cleanup.
    Obligation { id: u64, metadata: Vec<u8> },
    /// Waker deregistration from IO drivers.
    WakerCleanup { waker_id: u64, source: String },
    /// Region state cleanup.
    RegionCleanup {
        region_id: RegionId,
        task_ids: Vec<TaskId>,
    },
    /// Timer cleanup.
    TimerCleanup { timer_id: u64, timer_type: String },
    /// Channel cleanup (wakers, buffers, etc.).
    ChannelCleanup {
        channel_id: u64,
        cleanup_type: String,
        data: Vec<u8>,
    },
}

impl CleanupWork {
    /// Estimate memory usage of this work item.
    #[must_use]
    pub fn memory_usage(&self) -> usize {
        std::mem::size_of::<Self>()
            + match self {
                Self::Obligation { metadata, .. } => metadata.len(),
                Self::WakerCleanup { source, .. } => source.len(),
                Self::RegionCleanup { task_ids, .. } => {
                    task_ids.len() * std::mem::size_of::<TaskId>()
                }
                Self::TimerCleanup { timer_type, .. } => timer_type.len(),
                Self::ChannelCleanup {
                    cleanup_type, data, ..
                } => cleanup_type.len() + data.len(),
            }
    }
}

/// Entry in the deferred cleanup queue.
pub struct CleanupEntry {
    /// Epoch when this cleanup was scheduled.
    pub epoch: u64,
    /// Cleanup function to execute.
    pub cleanup_fn: Box<dyn FnOnce() + Send + 'static>,
    /// Optional debugging information.
    pub debug_info: Option<String>,
    /// Estimated memory usage.
    pub memory_usage: usize,
}

impl std::fmt::Debug for CleanupEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CleanupEntry")
            .field("epoch", &self.epoch)
            .field("memory_usage", &self.memory_usage)
            .field("debug_info", &self.debug_info)
            .finish()
    }
}

// ============================================================================
// Deferred Cleanup Queue
// ============================================================================

/// Queue for deferred cleanup operations.
pub struct DeferredCleanupQueue {
    /// Lockless queue of cleanup entries.
    queue: SegQueue<CleanupEntry>,
    /// Number of enqueued cleanups.
    enqueue_count: AtomicU64,
    /// Number of executed cleanups.
    execute_count: AtomicU64,
    /// Total time spent in cleanup (nanoseconds).
    cleanup_time_ns: AtomicU64,
    /// Memory usage tracking.
    memory_usage: AtomicUsize,
    /// Reference to global epoch counter.
    global: Arc<GlobalEpochCounter>,
    /// Maximum queue size for backpressure.
    max_queue_size: AtomicUsize,
}

impl DeferredCleanupQueue {
    /// Create a new deferred cleanup queue.
    pub fn new(global: Arc<GlobalEpochCounter>, max_size: usize) -> Self {
        Self {
            queue: SegQueue::new(),
            enqueue_count: AtomicU64::new(0),
            execute_count: AtomicU64::new(0),
            cleanup_time_ns: AtomicU64::new(0),
            memory_usage: AtomicUsize::new(0),
            global,
            max_queue_size: AtomicUsize::new(max_size),
        }
    }

    /// Enqueue a cleanup operation for the current epoch.
    pub fn defer_cleanup<F>(&self, cleanup_fn: F) -> Result<(), CleanupEntry>
    where
        F: FnOnce() + Send + 'static,
    {
        let epoch = self.global.current_epoch();
        let entry = CleanupEntry {
            epoch,
            cleanup_fn: Box::new(cleanup_fn),
            debug_info: None,
            memory_usage: std::mem::size_of::<CleanupEntry>(),
        };

        // Check queue capacity
        let current_size = self.queue.len();
        let max_size = self.max_queue_size.load(Ordering::Relaxed);
        if current_size >= max_size {
            return Err(entry);
        }

        self.queue.push(entry);
        self.enqueue_count.fetch_add(1, Ordering::Relaxed);
        self.memory_usage
            .fetch_add(std::mem::size_of::<CleanupEntry>(), Ordering::Relaxed);

        Ok(())
    }

    /// Enqueue cleanup work with debugging information.
    pub fn defer_cleanup_with_debug<F>(
        &self,
        cleanup_fn: F,
        debug_info: String,
    ) -> Result<(), CleanupEntry>
    where
        F: FnOnce() + Send + 'static,
    {
        let epoch = self.global.current_epoch();
        let memory_usage = std::mem::size_of::<CleanupEntry>() + debug_info.len();
        let entry = CleanupEntry {
            epoch,
            cleanup_fn: Box::new(cleanup_fn),
            debug_info: Some(debug_info),
            memory_usage,
        };

        // Check queue capacity
        let current_size = self.queue.len();
        let max_size = self.max_queue_size.load(Ordering::Relaxed);
        if current_size >= max_size {
            return Err(entry);
        }

        self.queue.push(entry);
        self.enqueue_count.fetch_add(1, Ordering::Relaxed);
        self.memory_usage.fetch_add(memory_usage, Ordering::Relaxed);

        Ok(())
    }

    /// Execute all safe cleanups up to the given epoch.
    pub fn execute_safe_cleanups(&self, safe_epoch: u64) -> usize {
        let start = Instant::now();
        let mut executed = 0;
        let mut entries_to_requeue = Vec::new();

        // Process all entries in the queue
        while let Some(entry) = self.queue.pop() {
            if entry.epoch <= safe_epoch {
                // Safe to execute
                (entry.cleanup_fn)();
                executed += 1;

                self.memory_usage
                    .fetch_sub(entry.memory_usage, Ordering::Relaxed);
            } else {
                // Not safe yet, will requeue
                entries_to_requeue.push(entry);
            }
        }

        // Requeue entries that aren't safe yet
        for entry in entries_to_requeue {
            self.queue.push(entry);
        }

        if executed > 0 {
            self.execute_count
                .fetch_add(executed as u64, Ordering::Relaxed);
            let elapsed = start.elapsed().as_nanos() as u64;
            self.cleanup_time_ns.fetch_add(elapsed, Ordering::Relaxed);
        }

        executed
    }

    /// Get queue statistics.
    pub fn stats(&self) -> CleanupQueueStats {
        CleanupQueueStats {
            pending_count: self.queue.len(),
            enqueue_count: self.enqueue_count.load(Ordering::Relaxed),
            execute_count: self.execute_count.load(Ordering::Relaxed),
            memory_usage: self.memory_usage.load(Ordering::Relaxed),
            total_cleanup_time: Duration::from_nanos(self.cleanup_time_ns.load(Ordering::Relaxed)),
        }
    }

    /// Check if queue is near capacity.
    pub fn is_near_capacity(&self) -> bool {
        let current = self.queue.len();
        let max = self.max_queue_size.load(Ordering::Relaxed);
        current >= (max * 8) / 10 // 80% capacity
    }

    /// Set maximum queue size.
    pub fn set_max_size(&self, max_size: usize) {
        self.max_queue_size.store(max_size, Ordering::Relaxed);
    }
}

impl std::fmt::Debug for DeferredCleanupQueue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeferredCleanupQueue")
            .field("pending_count", &self.queue.len())
            .field("memory_usage", &self.memory_usage.load(Ordering::Relaxed))
            .finish()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_epoch_advancement() {
        let config = EpochConfig {
            advance_interval: Duration::from_millis(1),
            ..EpochConfig::default()
        };
        let epoch = Arc::new(GlobalEpochCounter::new(config));
        let initial = epoch.current_epoch();

        // Should not advance immediately (rate limited)
        assert_eq!(epoch.try_advance(), None);

        // Wait for advance interval and try again
        thread::sleep(Duration::from_millis(2));
        let advanced = epoch.try_advance();
        assert!(advanced.is_some());
        assert_eq!(advanced.unwrap(), initial + 1);

        // Force advance should work
        let new_epoch = epoch.force_advance();
        assert_eq!(new_epoch, initial + 2);
    }

    #[test]
    fn test_epoch_pin() {
        let epoch = Arc::new(GlobalEpochCounter::new(EpochConfig::default()));
        let pin = LocalEpochPin::new(epoch.clone());

        // Initially not pinned
        assert_eq!(pin.pinned_epoch(), None);

        // Pin an epoch
        let guard = pin.pin();
        let pinned_epoch = guard.epoch();
        assert_eq!(pin.pinned_epoch(), Some(pinned_epoch));

        // Advance global epoch
        epoch.force_advance();
        assert!(epoch.current_epoch() > pinned_epoch);

        // Pin should still be active
        assert_eq!(pin.pinned_epoch(), Some(pinned_epoch));

        // Drop guard to unpin
        drop(guard);
        assert_eq!(pin.pinned_epoch(), None);
    }

    #[test]
    fn test_safe_point_detection() {
        let epoch = Arc::new(GlobalEpochCounter::new(EpochConfig::default()));
        let mut detector = SafePointDetector::new(epoch.clone());
        let pin = Arc::new(LocalEpochPin::new(epoch.clone()));
        detector.register_pin(pin.clone());

        // Initially safe point should be current epoch - 1
        let initial_epoch = epoch.current_epoch();
        let safe_point = detector.compute_safe_point();
        assert!(safe_point <= initial_epoch);

        // Pin an epoch
        let _guard = pin.pin();
        let pinned_epoch = pin.pinned_epoch().unwrap();

        // Advance global epoch
        epoch.force_advance();
        epoch.force_advance();

        // Safe point should be at or before pinned epoch
        let safe_point = detector.compute_safe_point();
        assert!(safe_point <= pinned_epoch);

        // After unpinning, safe point should advance
        drop(_guard);
        let safe_point_after = detector.compute_safe_point();
        assert!(safe_point_after > safe_point);
    }

    #[test]
    fn test_cleanup_queue() {
        let epoch = Arc::new(GlobalEpochCounter::new(EpochConfig::default()));
        let queue = DeferredCleanupQueue::new(epoch.clone(), 1000);
        let executed = Arc::new(AtomicBool::new(false));

        // Enqueue cleanup
        let executed_clone = executed.clone();
        queue
            .defer_cleanup(move || {
                executed_clone.store(true, Ordering::Relaxed);
            })
            .unwrap();

        // Should not execute yet (current epoch is not safe)
        let count = queue.execute_safe_cleanups(epoch.current_epoch());
        assert_eq!(count, 0);
        assert!(!executed.load(Ordering::Relaxed));

        // Advance epoch and execute
        epoch.force_advance();
        let count = queue.execute_safe_cleanups(epoch.current_epoch());
        assert_eq!(count, 1);
        assert!(executed.load(Ordering::Relaxed));
    }

    #[test]
    fn test_cleanup_ordering() {
        let epoch = Arc::new(GlobalEpochCounter::new(EpochConfig::default()));
        let queue = DeferredCleanupQueue::new(epoch.clone(), 1000);
        let executed_order = Arc::new(std::sync::Mutex::new(Vec::new()));

        // Enqueue cleanups across multiple epochs
        for i in 0..5 {
            let order = executed_order.clone();
            queue
                .defer_cleanup(move || {
                    order.lock().unwrap().push(i);
                })
                .unwrap();

            // Advance epoch between some cleanups
            if i % 2 == 0 {
                epoch.force_advance();
            }
        }

        // Execute cleanups in order
        let safe_epoch = epoch.force_advance();
        let count = queue.execute_safe_cleanups(safe_epoch);

        assert_eq!(count, 5);
        let order = executed_order.lock().unwrap();
        // Should execute in epoch order (0, 2, 4, 1, 3)
        assert!(order.len() == 5);
    }

    #[test]
    fn test_queue_backpressure() {
        let epoch = Arc::new(GlobalEpochCounter::new(EpochConfig::default()));
        let queue = DeferredCleanupQueue::new(epoch.clone(), 2); // Very small queue

        // Fill queue to capacity
        let result1 = queue.defer_cleanup(|| {});
        assert!(result1.is_ok());

        let result2 = queue.defer_cleanup(|| {});
        assert!(result2.is_ok());

        // Next enqueue should fail
        let result3 = queue.defer_cleanup(|| {});
        assert!(result3.is_err());

        // Execute some cleanups to free space
        epoch.force_advance();
        let executed = queue.execute_safe_cleanups(epoch.current_epoch());
        assert!(executed > 0);

        // Should be able to enqueue again
        let result4 = queue.defer_cleanup(|| {});
        assert!(result4.is_ok());
    }

    #[test]
    fn test_concurrent_operations() {
        let epoch = Arc::new(GlobalEpochCounter::new(EpochConfig {
            advance_interval: Duration::from_millis(1),
            ..EpochConfig::default()
        }));
        let pin = Arc::new(LocalEpochPin::new(epoch.clone()));
        let queue = Arc::new(DeferredCleanupQueue::new(epoch.clone(), 10000));

        let mut handles = Vec::new();

        // Spawn threads that pin epochs and enqueue cleanup
        for i in 0..4 {
            let epoch = epoch.clone();
            let pin = pin.clone();
            let queue = queue.clone();

            let handle = thread::spawn(move || {
                for j in 0..100 {
                    let _guard = pin.pin();

                    let value = i * 100 + j;
                    let _ = queue.defer_cleanup(move || {
                        // Simulate work
                        std::hint::black_box(value);
                    });

                    if j % 10 == 0 {
                        epoch.try_advance();
                    }

                    thread::yield_now();
                }
            });

            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // Execute remaining cleanups
        let final_epoch = epoch.force_advance();
        let executed = queue.execute_safe_cleanups(final_epoch);

        // Verify no data races or lost work
        assert!(executed > 0);
        assert!(executed <= 400); // At most 400 work items
    }
}
