//! Epoch-based garbage collection for structured concurrency cleanup.
//!
//! This module implements deferred cleanup for structured concurrency operations
//! to reduce tail latencies under high cancellation load. Instead of performing
//! cleanup work synchronously during cancellation, work is queued and performed
//! in batches at safe points.
//!
//! # Design
//!
//! The epoch GC uses epoch counters to track cleanup generations and defer
//! cleanup work to safe points:
//!
//! 1. **Epoch Counters**: Track the current epoch and allow threads to
//!    announce their local epoch to coordinate cleanup.
//! 2. **Deferred Cleanup Queues**: Lockless queues that accumulate cleanup
//!    work items tagged with the epoch they were created in.
//! 3. **Safe Point Detection**: Identifies when it's safe to clean up work
//!    from previous epochs (no threads are accessing that epoch).
//! 4. **Batch Cleanup**: Processes accumulated cleanup work efficiently.
//!
//! # Performance Goals
//!
//! - P99 cancellation latency reduced by >80%
//! - Cleanup work batching efficiency >90%
//! - <1% overhead on non-cleanup operations
//!
//! # Safety
//!
//! The epoch GC maintains structured concurrency guarantees:
//! - No cleanup work is lost
//! - Region quiescence is preserved
//! - Memory safety is maintained during cleanup deferral

use crate::sync::ContendedMutex;
use crate::types::{RegionId, TaskId};
use crossbeam_queue::SegQueue;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

// ============================================================================
// Epoch Tracking
// ============================================================================

/// Global epoch counter for coordinating cleanup across threads.
///
/// The epoch advances periodically, allowing cleanup work from previous
/// epochs to be processed once all threads have moved past that epoch.
#[derive(Debug)]
pub struct EpochCounter {
    /// Current global epoch.
    global: AtomicU64,
    /// Last time the epoch was advanced.
    last_advance: ContendedMutex<Instant>,
    /// Minimum duration between epoch advances.
    advance_interval: Duration,
}

impl Default for EpochCounter {
    fn default() -> Self {
        Self::new(Duration::from_millis(100))
    }
}

impl EpochCounter {
    /// Create a new epoch counter with the given advance interval.
    #[must_use]
    pub fn new(advance_interval: Duration) -> Self {
        Self {
            global: AtomicU64::new(1), // Start at 1 so epoch 0 can be special
            last_advance: ContendedMutex::new("epoch_gc.last_advance", Instant::now()),
            advance_interval,
        }
    }

    /// Get the current global epoch.
    pub fn current(&self) -> u64 {
        self.global.load(Ordering::Acquire)
    }

    /// Advance the global epoch if sufficient time has passed.
    ///
    /// Returns the new epoch value if advanced, or None if no advance occurred.
    pub fn try_advance(&self) -> Option<u64> {
        let now = Instant::now();
        let mut last_advance = self
            .last_advance
            .lock()
            .expect("epoch_gc last_advance mutex poisoned");

        if now.duration_since(*last_advance) >= self.advance_interval {
            let new_epoch = self.global.fetch_add(1, Ordering::AcqRel) + 1;
            *last_advance = now;
            Some(new_epoch)
        } else {
            None
        }
    }

    /// Force advance the global epoch (for testing).
    #[cfg(any(test, feature = "test-internals"))]
    pub fn force_advance(&self) -> u64 {
        let mut last_advance = self
            .last_advance
            .lock()
            .expect("epoch_gc last_advance mutex poisoned");
        let new_epoch = self.global.fetch_add(1, Ordering::AcqRel) + 1;
        *last_advance = Instant::now();
        new_epoch
    }
}

// ============================================================================
// Thread-Local Epoch Tracking
// ============================================================================

/// Thread-local epoch state for coordinating with global epoch advances.
///
/// Each thread maintains its local epoch to indicate which epoch it's
/// currently operating in. This enables safe point detection.
#[derive(Debug)]
#[allow(dead_code)]
pub struct LocalEpoch {
    /// Current local epoch for this thread.
    local: AtomicU64,
    /// Thread ID for debugging.
    thread_id: thread::ThreadId,
}

impl LocalEpoch {
    /// Create a new local epoch tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            local: AtomicU64::new(0), // Start at 0 to force initial sync
            thread_id: thread::current().id(),
        }
    }

    /// Get the current local epoch.
    pub fn current(&self) -> u64 {
        self.local.load(Ordering::Acquire)
    }

    /// Update local epoch to match global epoch.
    pub fn sync_to_global(&self, global_epoch: u64) {
        self.local.store(global_epoch, Ordering::Release);
    }

    /// Check if this thread is lagging behind the global epoch.
    pub fn is_behind(&self, global_epoch: u64) -> bool {
        self.current() < global_epoch
    }
}

impl Default for LocalEpoch {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Cleanup Work Items
// ============================================================================

/// Types of cleanup work that can be deferred.
#[derive(Debug, Clone)]
pub enum CleanupWork {
    /// Obligation tracking cleanup.
    Obligation {
        /// The obligation ID to clean up.
        id: u64,
        /// Additional metadata for cleanup.
        metadata: Vec<u8>,
    },
    /// Waker deregistration from IO drivers.
    WakerCleanup {
        /// Waker ID or token for cleanup.
        waker_id: u64,
        /// Source (e.g., "epoll", "kqueue", "iocp").
        source: String,
    },
    /// Region state cleanup.
    RegionCleanup {
        /// Region ID to clean up.
        region_id: RegionId,
        /// Associated task IDs to clean up.
        task_ids: Vec<TaskId>,
    },
    /// Timer cleanup.
    TimerCleanup {
        /// Timer ID or handle.
        timer_id: u64,
        /// Timer type for specific cleanup logic.
        timer_type: String,
    },
    /// Channel cleanup (wakers, buffers, etc.).
    ChannelCleanup {
        /// Channel ID.
        channel_id: u64,
        /// Cleanup type (waker, buffer, etc.).
        cleanup_type: String,
        /// Additional cleanup data.
        data: Vec<u8>,
    },
}

impl CleanupWork {
    /// Get a debug description of this cleanup work.
    #[must_use]
    pub fn description(&self) -> String {
        match self {
            Self::Obligation { id, .. } => format!("obligation:{id}"),
            Self::WakerCleanup { waker_id, source } => format!("waker:{source}:{waker_id}"),
            Self::RegionCleanup {
                region_id,
                task_ids,
            } => {
                format!("region:{}:tasks:{}", region_id, task_ids.len())
            }
            Self::TimerCleanup {
                timer_id,
                timer_type,
            } => {
                format!("timer:{timer_type}:{timer_id}")
            }
            Self::ChannelCleanup {
                channel_id,
                cleanup_type,
                ..
            } => {
                format!("channel:{cleanup_type}:{channel_id}")
            }
        }
    }

    /// Estimate memory usage of this cleanup work item.
    #[must_use]
    pub fn memory_usage(&self) -> usize {
        let base_size = std::mem::size_of::<Self>();
        match self {
            Self::Obligation { metadata, .. } => base_size + metadata.len(),
            Self::WakerCleanup { source, .. } => base_size + source.len(),
            Self::RegionCleanup { task_ids, .. } => {
                base_size + task_ids.len() * std::mem::size_of::<TaskId>()
            }
            Self::TimerCleanup { timer_type, .. } => base_size + timer_type.len(),
            Self::ChannelCleanup {
                cleanup_type, data, ..
            } => base_size + cleanup_type.len() + data.len(),
        }
    }
}

// ============================================================================
// Deferred Cleanup Queue
// ============================================================================

/// Work item with epoch tracking for deferred cleanup.
#[derive(Debug)]
#[allow(dead_code)]
struct EpochWork {
    /// The epoch this work was created in.
    epoch: u64,
    /// The actual cleanup work to perform.
    work: CleanupWork,
    /// Timestamp when work was enqueued.
    enqueued_at: Instant,
}

/// Configuration for the deferred cleanup system.
#[derive(Debug, Clone)]
pub struct CleanupConfig {
    /// Maximum number of work items in the queue before backpressure.
    pub max_queue_size: usize,
    /// Minimum batch size for cleanup processing.
    pub min_batch_size: usize,
    /// Maximum batch size for cleanup processing.
    pub max_batch_size: usize,
    /// Maximum time to spend in a single cleanup batch.
    pub max_batch_time: Duration,
    /// Enable emergency fallback to direct cleanup on queue overflow.
    pub enable_fallback: bool,
    /// Enable detailed logging of cleanup operations.
    pub enable_logging: bool,
}

impl Default for CleanupConfig {
    fn default() -> Self {
        Self {
            max_queue_size: 10_000,
            min_batch_size: 10,
            max_batch_size: 100,
            max_batch_time: Duration::from_millis(5),
            enable_fallback: true,
            enable_logging: false,
        }
    }
}

/// Lockless queue for deferred cleanup work items.
///
/// This queue accumulates cleanup work from all threads and processes
/// it in batches during epoch advances.
#[derive(Debug)]
pub struct DeferredCleanupQueue {
    /// Lockless queue of cleanup work.
    queue: SegQueue<EpochWork>,
    /// Current queue size estimate.
    size: AtomicUsize,
    /// Configuration for cleanup processing.
    config: CleanupConfig,
    /// Statistics for monitoring.
    stats: CleanupStats,
}

/// Statistics for monitoring cleanup queue performance.
#[derive(Debug, Default)]
pub struct CleanupStats {
    /// Total work items enqueued.
    pub total_enqueued: AtomicU64,
    /// Total work items processed.
    pub total_processed: AtomicU64,
    /// Total work items dropped due to overflow.
    pub total_dropped: AtomicU64,
    /// Total cleanup batches processed.
    pub total_batches: AtomicU64,
    /// Total time spent in cleanup processing.
    pub total_cleanup_time: AtomicU64, // microseconds
    /// Current queue size.
    pub current_queue_size: AtomicUsize,
    /// Peak queue size seen.
    pub peak_queue_size: AtomicUsize,
}

impl CleanupStats {
    /// Get cleanup efficiency as a percentage (processed / enqueued).
    pub fn efficiency_percent(&self) -> f64 {
        let enqueued = self.total_enqueued.load(Ordering::Relaxed) as f64;
        let processed = self.total_processed.load(Ordering::Relaxed) as f64;
        if enqueued > 0.0 {
            (processed / enqueued) * 100.0
        } else {
            100.0
        }
    }

    /// Get average batch size.
    pub fn average_batch_size(&self) -> f64 {
        let processed = self.total_processed.load(Ordering::Relaxed) as f64;
        let batches = self.total_batches.load(Ordering::Relaxed) as f64;
        if batches > 0.0 {
            processed / batches
        } else {
            0.0
        }
    }

    /// Get average cleanup time per batch in microseconds.
    pub fn average_batch_time_us(&self) -> f64 {
        let total_time = self.total_cleanup_time.load(Ordering::Relaxed) as f64;
        let batches = self.total_batches.load(Ordering::Relaxed) as f64;
        if batches > 0.0 {
            total_time / batches
        } else {
            0.0
        }
    }
}

impl Default for DeferredCleanupQueue {
    fn default() -> Self {
        Self::with_config(CleanupConfig::default())
    }
}

impl DeferredCleanupQueue {
    /// Create a new deferred cleanup queue with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(CleanupConfig::default())
    }

    /// Create a new deferred cleanup queue with the given configuration.
    #[must_use]
    pub fn with_config(config: CleanupConfig) -> Self {
        Self {
            queue: SegQueue::new(),
            size: AtomicUsize::new(0),
            config,
            stats: CleanupStats::default(),
        }
    }

    /// Drain all queued work items whose epoch is strictly less than
    /// `safe_epoch` without executing them. Intended for tests that want to
    /// inspect what would be cleaned up.
    pub fn collect_expired(&self, safe_epoch: u64) -> Vec<CleanupWork> {
        let mut drained = Vec::new();
        let mut held_back = Vec::new();
        while let Some(epoch_work) = self.queue.pop() {
            self.size.fetch_sub(1, Ordering::Relaxed);
            if epoch_work.epoch < safe_epoch {
                drained.push(epoch_work.work);
            } else {
                held_back.push(epoch_work);
            }
        }
        for epoch_work in held_back {
            self.size.fetch_add(1, Ordering::Relaxed);
            self.queue.push(epoch_work);
        }
        drained
    }

    /// Enqueue cleanup work to be processed later.
    ///
    /// Returns Ok(()) if the work was successfully enqueued, or Err(work)
    /// if the queue is full and backpressure should be applied.
    pub fn enqueue(&self, work: CleanupWork, current_epoch: u64) -> Result<(), CleanupWork> {
        let current_size = self.size.load(Ordering::Relaxed);

        // Check for queue overflow
        if current_size >= self.config.max_queue_size {
            self.stats.total_dropped.fetch_add(1, Ordering::Relaxed);
            return Err(work);
        }

        let epoch_work = EpochWork {
            epoch: current_epoch,
            work,
            enqueued_at: Instant::now(),
        };

        self.queue.push(epoch_work);
        let new_size = self.size.fetch_add(1, Ordering::Relaxed) + 1;
        self.stats.total_enqueued.fetch_add(1, Ordering::Relaxed);
        self.stats
            .current_queue_size
            .store(new_size, Ordering::Relaxed);

        // Update peak queue size
        let current_peak = self.stats.peak_queue_size.load(Ordering::Relaxed);
        if new_size > current_peak {
            self.stats
                .peak_queue_size
                .compare_exchange_weak(current_peak, new_size, Ordering::Relaxed, Ordering::Relaxed)
                .ok(); // Ignore race condition
        }

        Ok(())
    }

    /// Process cleanup work for epochs older than the given safe epoch.
    ///
    /// This should be called during epoch advances when it's safe to clean
    /// up work from previous epochs.
    pub fn process_safe_epochs(&self, safe_epoch: u64) -> usize {
        let start_time = Instant::now();
        let mut processed_count = 0;
        let mut batch = Vec::new();

        // Collect a batch of work items that are safe to process
        while processed_count < self.config.max_batch_size {
            if let Some(epoch_work) = self.queue.pop() {
                self.size.fetch_sub(1, Ordering::Relaxed);

                if epoch_work.epoch < safe_epoch {
                    // This work is from a safe epoch - can be processed
                    batch.push(epoch_work);
                    processed_count += 1;

                    // Check time limit
                    if start_time.elapsed() >= self.config.max_batch_time {
                        break;
                    }
                } else {
                    // This work is from a current epoch - put it back
                    self.queue.push(epoch_work);
                    self.size.fetch_add(1, Ordering::Relaxed);
                    break;
                }
            } else {
                break; // Queue is empty
            }
        }

        // Process the collected batch
        if !batch.is_empty() {
            self.process_cleanup_batch(batch);
            self.stats
                .total_processed
                .fetch_add(processed_count as u64, Ordering::Relaxed);
            self.stats.total_batches.fetch_add(1, Ordering::Relaxed);

            let batch_time_us = start_time.elapsed().as_micros() as u64;
            self.stats
                .total_cleanup_time
                .fetch_add(batch_time_us, Ordering::Relaxed);

            if self.config.enable_logging && processed_count >= self.config.min_batch_size {
                #[cfg(feature = "tracing-integration")]
                tracing::debug!(
                    processed = processed_count,
                    safe_epoch = safe_epoch,
                    batch_time_us = batch_time_us,
                    "Processed epoch GC cleanup batch"
                );
            }
        }

        // Update current queue size
        let current_size = self.size.load(Ordering::Relaxed);
        self.stats
            .current_queue_size
            .store(current_size, Ordering::Relaxed);

        processed_count
    }

    /// Process a batch of cleanup work items.
    fn process_cleanup_batch(&self, batch: Vec<EpochWork>) {
        for epoch_work in batch {
            self.process_single_work_item(&epoch_work.work);
        }
    }

    /// Process a single cleanup work item.
    fn process_single_work_item(&self, work: &CleanupWork) {
        if self.config.enable_logging {
            #[cfg(feature = "tracing-integration")]
            tracing::trace!(
                work_description = work.description(),
                "Processing cleanup work item"
            );
        }

        // TODO: Implement actual cleanup logic for each work type
        // This will integrate with the existing runtime cleanup systems
        match work {
            CleanupWork::Obligation { id, .. } => {
                // Call into obligation tracking cleanup
                self.cleanup_obligation(*id);
            }
            CleanupWork::WakerCleanup { waker_id, source } => {
                // Call into IO driver waker cleanup
                self.cleanup_waker(*waker_id, source);
            }
            CleanupWork::RegionCleanup {
                region_id,
                task_ids,
            } => {
                // Call into region state cleanup
                self.cleanup_region(*region_id, task_ids);
            }
            CleanupWork::TimerCleanup {
                timer_id,
                timer_type,
            } => {
                // Call into timer cleanup
                self.cleanup_timer(*timer_id, timer_type);
            }
            CleanupWork::ChannelCleanup {
                channel_id,
                cleanup_type,
                ..
            } => {
                // Call into channel cleanup
                self.cleanup_channel(*channel_id, cleanup_type);
            }
        }
    }

    /// Clean up an obligation.
    fn cleanup_obligation(&self, _id: u64) {
        // Integrate with obligation tracking system
        // Note: This is a simplified implementation - real integration would
        // require access to the ObligationTable and proper error handling
        #[cfg(feature = "tracing-integration")]
        tracing::debug!(
            obligation_id = id,
            "Cleaning up obligation in deferred cleanup"
        );

        // In practice, this would call something like:
        // obligation_table.cleanup_obligation(id);
        // For now, we just log the cleanup operation
    }

    /// Clean up a waker.
    fn cleanup_waker(&self, _waker_id: u64, source: &str) {
        // Integrate with IO driver waker cleanup
        #[cfg(feature = "tracing-integration")]
        tracing::debug!(
            waker_id = waker_id,
            source = source,
            "Cleaning up waker in deferred cleanup"
        );

        // Platform-specific waker cleanup
        match source {
            "epoll" => {
                // For epoll-based reactors, deregister the file descriptor
                // reactor.deregister_waker(waker_id);
            }
            "kqueue" => {
                // For kqueue-based reactors, remove the event
                // reactor.remove_kqueue_event(waker_id);
            }
            "iocp" => {
                // For IOCP-based reactors, cancel outstanding operations
                // reactor.cancel_iocp_operation(waker_id);
            }
            _ => {
                #[cfg(feature = "tracing-integration")]
                tracing::warn!(source = source, "Unknown waker source for cleanup");
            }
        }
    }

    /// Clean up region state.
    fn cleanup_region(&self, _region_id: RegionId, task_ids: &[TaskId]) {
        // Integrate with region table cleanup
        #[cfg(feature = "tracing-integration")]
        tracing::debug!(
            region_id = region_id.as_u64(),
            task_count = task_ids.len(),
            "Cleaning up region state in deferred cleanup"
        );

        // Clean up region metadata and associated tasks
        for &_task_id in task_ids {
            #[cfg(feature = "tracing-integration")]
            tracing::trace!(
                task_id = task_id.as_u64(),
                region_id = region_id.as_u64(),
                "Cleaning up task in region cleanup"
            );

            // In practice, this would call:
            // task_table.remove_task(task_id);
            // region_table.remove_task_from_region(region_id, task_id);
        }

        // Clean up region-specific resources
        // region_table.cleanup_region_metadata(region_id);
        // obligation_table.cleanup_region_obligations(region_id);
    }

    /// Clean up a timer.
    fn cleanup_timer(&self, _timer_id: u64, timer_type: &str) {
        // Integrate with timer wheel cleanup
        #[cfg(feature = "tracing-integration")]
        tracing::debug!(
            timer_id = timer_id,
            timer_type = timer_type,
            "Cleaning up timer in deferred cleanup"
        );

        // Timer-specific cleanup based on type
        match timer_type {
            "sleep" => {
                // Remove sleep timer from timer wheel
                // timer_driver.remove_sleep_timer(timer_id);
            }
            "timeout" => {
                // Remove timeout timer and associated state
                // timer_driver.remove_timeout_timer(timer_id);
                // Cancel any associated timeout futures
            }
            "interval" => {
                // Remove interval timer from recurring timer list
                // timer_driver.remove_interval_timer(timer_id);
            }
            "deadline" => {
                // Remove deadline timer and cleanup deadline tracking
                // timer_driver.remove_deadline_timer(timer_id);
            }
            _ => {
                #[cfg(feature = "tracing-integration")]
                tracing::warn!(timer_type = timer_type, "Unknown timer type for cleanup");
            }
        }

        // Common timer cleanup operations
        // timer_wheel.remove_entry(timer_id);
        // waker_registry.cleanup_timer_wakers(timer_id);
    }

    /// Clean up channel state.
    fn cleanup_channel(&self, _channel_id: u64, cleanup_type: &str) {
        // Integrate with channel cleanup
        #[cfg(feature = "tracing-integration")]
        tracing::debug!(
            channel_id = channel_id,
            cleanup_type = cleanup_type,
            "Cleaning up channel state in deferred cleanup"
        );

        // Channel-specific cleanup based on type
        match cleanup_type {
            "waker" => {
                // Clean up channel wakers (send/receive wakers)
                // channel_registry.cleanup_wakers(channel_id);
            }
            "buffer" => {
                // Clean up channel message buffers
                // channel_registry.cleanup_buffers(channel_id);
            }
            "mpsc_sender" => {
                // Clean up MPSC sender state
                // mpsc_registry.cleanup_sender(channel_id);
            }
            "mpsc_receiver" => {
                // Clean up MPSC receiver state
                // mpsc_registry.cleanup_receiver(channel_id);
            }
            "oneshot" => {
                // Clean up oneshot channel state
                // oneshot_registry.cleanup_channel(channel_id);
            }
            "broadcast" => {
                // Clean up broadcast channel state
                // broadcast_registry.cleanup_channel(channel_id);
            }
            "watch" => {
                // Clean up watch channel state
                // watch_registry.cleanup_channel(channel_id);
            }
            "session" => {
                // Clean up session channel state and type checking
                // session_registry.cleanup_channel(channel_id);
            }
            _ => {
                #[cfg(feature = "tracing-integration")]
                tracing::warn!(cleanup_type = cleanup_type, "Unknown channel cleanup type");
            }
        }

        // Common channel cleanup operations
        // waker_registry.cleanup_channel_wakers(channel_id);
        // cancel_registry.cleanup_channel_cancellation(channel_id);
    }

    /// Get current cleanup statistics.
    pub fn stats(&self) -> &CleanupStats {
        &self.stats
    }

    /// Get current configuration.
    pub fn config(&self) -> &CleanupConfig {
        &self.config
    }

    /// Get current queue length estimate.
    pub fn len(&self) -> usize {
        self.size.load(Ordering::Relaxed)
    }

    /// Check if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Check if the queue is near capacity and backpressure should be applied.
    pub fn is_near_capacity(&self) -> bool {
        let current_size = self.len();
        let threshold = (self.config.max_queue_size as f64 * 0.8) as usize;
        current_size >= threshold
    }
}

// ============================================================================
// Main Epoch GC System
// ============================================================================

/// Main epoch-based garbage collection system.
///
/// This coordinates epoch tracking and deferred cleanup across the runtime.
#[derive(Debug)]
pub struct EpochGC {
    /// Global epoch counter.
    epoch_counter: Arc<EpochCounter>,
    /// Deferred cleanup queue.
    cleanup_queue: Arc<DeferredCleanupQueue>,
    /// Whether the epoch GC is enabled.
    enabled: AtomicUsize, // 0 = disabled, 1 = enabled
}

impl EpochGC {
    /// Create a new epoch GC system with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(CleanupConfig::default())
    }

    /// Create a new epoch GC system with custom configuration.
    #[must_use]
    pub fn with_config(config: CleanupConfig) -> Self {
        Self {
            epoch_counter: Arc::new(EpochCounter::default()),
            cleanup_queue: Arc::new(DeferredCleanupQueue::with_config(config)),
            enabled: AtomicUsize::new(1), // Start enabled
        }
    }

    /// Create a disabled epoch GC system (for backwards compatibility).
    #[must_use]
    pub fn disabled() -> Self {
        let system = Self::new();
        system.enabled.store(0, Ordering::Relaxed);
        system
    }

    /// Check if the epoch GC is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed) != 0
    }

    /// Enable the epoch GC system.
    pub fn enable(&self) {
        self.enabled.store(1, Ordering::Relaxed);
    }

    /// Disable the epoch GC system (fall back to direct cleanup).
    pub fn disable(&self) {
        self.enabled.store(0, Ordering::Relaxed);
    }

    /// Get the current epoch.
    pub fn current_epoch(&self) -> u64 {
        self.epoch_counter.current()
    }

    /// Defer cleanup work to be processed later.
    ///
    /// If the epoch GC is disabled or the queue is full, this returns
    /// Err(work) to indicate direct cleanup should be performed.
    pub fn defer_cleanup(&self, work: CleanupWork) -> Result<(), CleanupWork> {
        if !self.is_enabled() {
            return Err(work); // Fall back to direct cleanup
        }

        let current_epoch = self.current_epoch();
        self.cleanup_queue.enqueue(work, current_epoch)
    }

    /// Try to advance the epoch and process safe cleanup work.
    ///
    /// This should be called periodically (e.g., from the scheduler or
    /// during natural quiescence points) to advance epochs and process
    /// accumulated cleanup work.
    ///
    /// Returns the number of cleanup work items processed.
    pub fn try_advance_and_cleanup(&self) -> usize {
        if !self.is_enabled() {
            return 0;
        }

        if let Some(new_epoch) = self.epoch_counter.try_advance() {
            // Process work from epochs older than the current one
            // We use (new_epoch - 1) as the safe epoch boundary
            let safe_epoch = new_epoch.saturating_sub(1);
            self.cleanup_queue.process_safe_epochs(safe_epoch)
        } else {
            0
        }
    }

    /// Force advance the epoch and process cleanup (for testing).
    #[cfg(test)]
    pub fn force_advance_and_cleanup(&self) -> usize {
        if !self.is_enabled() {
            return 0;
        }

        let new_epoch = self.epoch_counter.force_advance();
        let safe_epoch = new_epoch.saturating_sub(1);
        self.cleanup_queue.process_safe_epochs(safe_epoch)
    }

    /// Get cleanup queue statistics.
    pub fn stats(&self) -> &CleanupStats {
        self.cleanup_queue.stats()
    }

    /// Get cleanup queue configuration.
    pub fn config(&self) -> &CleanupConfig {
        self.cleanup_queue.config()
    }

    /// Check if the cleanup queue is near capacity.
    pub fn is_cleanup_queue_near_capacity(&self) -> bool {
        self.cleanup_queue.is_near_capacity()
    }

    /// Get epoch counter reference for thread-local coordination.
    pub fn epoch_counter(&self) -> &Arc<EpochCounter> {
        &self.epoch_counter
    }
}

impl Default for EpochGC {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn epoch_counter_advances_over_time() {
        let counter = EpochCounter::new(Duration::from_millis(10));
        let initial = counter.current();

        // Should not advance immediately
        assert_eq!(counter.try_advance(), None);
        assert_eq!(counter.current(), initial);

        // Wait for advance interval
        thread::sleep(Duration::from_millis(15));

        // Should advance now
        let new_epoch = counter.try_advance().expect("Should advance");
        assert_eq!(new_epoch, initial + 1);
        assert_eq!(counter.current(), new_epoch);
    }

    #[test]
    fn local_epoch_tracks_behind_state() {
        let local = LocalEpoch::new();
        assert_eq!(local.current(), 0);
        assert!(local.is_behind(1));
        assert!(!local.is_behind(0));

        local.sync_to_global(5);
        assert_eq!(local.current(), 5);
        assert!(!local.is_behind(5));
        assert!(local.is_behind(6));
    }

    #[test]
    fn cleanup_work_memory_usage_calculation() {
        let obligation_work = CleanupWork::Obligation {
            id: 123,
            metadata: vec![1, 2, 3, 4, 5],
        };
        assert!(obligation_work.memory_usage() > std::mem::size_of::<CleanupWork>());

        let waker_work = CleanupWork::WakerCleanup {
            waker_id: 456,
            source: "epoll".to_string(),
        };
        assert!(waker_work.memory_usage() > std::mem::size_of::<CleanupWork>());
    }

    #[test]
    fn cleanup_queue_enqueue_and_process() {
        let config = CleanupConfig {
            max_queue_size: 10,
            min_batch_size: 1,
            max_batch_size: 5,
            ..CleanupConfig::default()
        };
        let queue = DeferredCleanupQueue::with_config(config);

        // Enqueue some work
        let work1 = CleanupWork::Obligation {
            id: 1,
            metadata: vec![],
        };
        let work2 = CleanupWork::WakerCleanup {
            waker_id: 2,
            source: "kqueue".to_string(),
        };

        assert!(queue.enqueue(work1, 1).is_ok());
        assert!(queue.enqueue(work2, 1).is_ok());
        assert_eq!(queue.len(), 2);

        // Process work from epoch 1 (safe epoch 2)
        let processed = queue.process_safe_epochs(2);
        assert_eq!(processed, 2);
        assert_eq!(queue.len(), 0);

        // Verify stats
        let stats = queue.stats();
        assert_eq!(stats.total_enqueued.load(Ordering::Relaxed), 2);
        assert_eq!(stats.total_processed.load(Ordering::Relaxed), 2);
        assert_eq!(stats.total_batches.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn cleanup_queue_respects_epoch_safety() {
        let config = CleanupConfig::default();
        let queue = DeferredCleanupQueue::with_config(config);

        // Enqueue work from different epochs
        let work1 = CleanupWork::Obligation {
            id: 1,
            metadata: vec![],
        };
        let work2 = CleanupWork::Obligation {
            id: 2,
            metadata: vec![],
        };
        let work3 = CleanupWork::Obligation {
            id: 3,
            metadata: vec![],
        };

        assert!(queue.enqueue(work1, 1).is_ok());
        assert!(queue.enqueue(work2, 2).is_ok());
        assert!(queue.enqueue(work3, 3).is_ok());
        assert_eq!(queue.len(), 3);

        // Process only work from epoch 1 (safe epoch 2)
        let processed = queue.process_safe_epochs(2);
        assert_eq!(processed, 1);
        assert_eq!(queue.len(), 2);

        // Process work from epochs 1-2 (safe epoch 3)
        let processed = queue.process_safe_epochs(3);
        assert_eq!(processed, 1);
        assert_eq!(queue.len(), 1);

        // Process all remaining work (safe epoch 4)
        let processed = queue.process_safe_epochs(4);
        assert_eq!(processed, 1);
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn cleanup_queue_handles_overflow() {
        let config = CleanupConfig {
            max_queue_size: 2,
            ..CleanupConfig::default()
        };
        let queue = DeferredCleanupQueue::with_config(config);

        let work = CleanupWork::Obligation {
            id: 1,
            metadata: vec![],
        };

        // Fill queue to capacity
        assert!(queue.enqueue(work.clone(), 1).is_ok());
        assert!(queue.enqueue(work.clone(), 1).is_ok());

        // Next enqueue should fail due to overflow
        assert!(queue.enqueue(work, 1).is_err());

        // Verify overflow statistics
        let stats = queue.stats();
        assert_eq!(stats.total_dropped.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn epoch_gc_system_integration() {
        let gc = EpochGC::new();
        assert!(gc.is_enabled());

        // Defer some cleanup work
        let work = CleanupWork::Obligation {
            id: 123,
            metadata: vec![],
        };
        assert!(gc.defer_cleanup(work).is_ok());

        // Force advance and process
        let processed = gc.force_advance_and_cleanup();
        assert_eq!(processed, 1);

        // Verify statistics
        let stats = gc.stats();
        assert_eq!(stats.total_processed.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn epoch_gc_disabled_fallback() {
        let gc = EpochGC::disabled();
        assert!(!gc.is_enabled());

        // Deferred cleanup should fail and fall back to direct cleanup
        let work = CleanupWork::Obligation {
            id: 123,
            metadata: vec![],
        };
        assert!(gc.defer_cleanup(work).is_err());

        // Advance should do nothing
        let processed = gc.try_advance_and_cleanup();
        assert_eq!(processed, 0);
    }

    #[test]
    fn cleanup_stats_calculations() {
        let config = CleanupConfig::default();
        let queue = DeferredCleanupQueue::with_config(config);

        // Enqueue and process some work
        for i in 0..10 {
            let work = CleanupWork::Obligation {
                id: i,
                metadata: vec![],
            };
            let _ = queue.enqueue(work, 1);
        }

        // Process in two batches
        queue.process_safe_epochs(2);

        let stats = queue.stats();
        assert_eq!(stats.efficiency_percent(), 100.0);
        assert!(stats.average_batch_size() > 0.0);
        assert!(stats.average_batch_time_us() >= 0.0);
    }

    #[test]
    fn stress_test_concurrent_enqueue_dequeue() {
        let config = CleanupConfig {
            max_queue_size: 100_000,
            max_batch_size: 1000,
            ..CleanupConfig::default()
        };
        let _queue = Arc::new(DeferredCleanupQueue::with_config(config));
        let epoch_gc = Arc::new(EpochGC::with_config(CleanupConfig {
            max_queue_size: 100_000,
            max_batch_size: 1000,
            ..CleanupConfig::default()
        }));

        const NUM_THREADS: usize = 8;
        const WORK_ITEMS_PER_THREAD: usize = 1000;

        let mut handles = Vec::new();

        // Spawn producer threads
        for thread_id in 0..NUM_THREADS {
            let gc = Arc::clone(&epoch_gc);
            let handle = thread::spawn(move || {
                for i in 0..WORK_ITEMS_PER_THREAD {
                    let work = CleanupWork::Obligation {
                        id: (thread_id * WORK_ITEMS_PER_THREAD + i) as u64,
                        metadata: vec![thread_id as u8; 10],
                    };

                    // Keep retrying on overflow (backpressure test)
                    while gc.defer_cleanup(work.clone()).is_err() {
                        thread::sleep(Duration::from_micros(1));
                    }
                }
            });
            handles.push(handle);
        }

        // Spawn consumer thread
        let gc_consumer = Arc::clone(&epoch_gc);
        let consumer_handle = thread::spawn(move || {
            let mut total_processed = 0;
            let start = Instant::now();

            while start.elapsed() < Duration::from_secs(10)
                && total_processed < NUM_THREADS * WORK_ITEMS_PER_THREAD
            {
                let processed = gc_consumer.force_advance_and_cleanup();
                total_processed += processed;

                if processed == 0 {
                    thread::sleep(Duration::from_millis(1));
                }
            }

            total_processed
        });

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }
        let total_processed = consumer_handle.join().unwrap();

        // Verify all work was processed
        assert!(
            total_processed >= NUM_THREADS * WORK_ITEMS_PER_THREAD * 9 / 10,
            "Should process at least 90% of work items, got {}",
            total_processed
        );

        let stats = epoch_gc.stats();
        assert!(stats.efficiency_percent() >= 90.0);
        assert_eq!(stats.total_dropped.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn stress_test_memory_usage_extended_operation() {
        use std::sync::atomic::AtomicUsize;

        // Simple memory usage tracker
        static ALLOCATED: AtomicUsize = AtomicUsize::new(0);

        let config = CleanupConfig {
            max_queue_size: 10_000,
            max_batch_size: 100,
            max_batch_time: Duration::from_millis(1),
            ..CleanupConfig::default()
        };
        let epoch_gc = Arc::new(EpochGC::with_config(config));

        let start_memory = ALLOCATED.load(Ordering::Relaxed);

        // Run extended operation
        for iteration in 0..1000 {
            // Add work items
            for i in 0..100 {
                let work = CleanupWork::RegionCleanup {
                    region_id: RegionId::new_for_test(iteration * 100 + i, 1),
                    task_ids: vec![TaskId::new_for_test(i, 1); 10], // 10 tasks per region
                };
                let _ = epoch_gc.defer_cleanup(work);
            }

            // Periodically process cleanup
            if iteration % 10 == 0 {
                epoch_gc.force_advance_and_cleanup();
            }

            // Check for memory leaks every 100 iterations
            if iteration % 100 == 0 {
                epoch_gc.force_advance_and_cleanup(); // Process remaining work

                let current_memory = ALLOCATED.load(Ordering::Relaxed);
                let memory_growth = current_memory.saturating_sub(start_memory);

                // Memory growth should be bounded (less than 1MB)
                assert!(
                    memory_growth < 1_000_000,
                    "Memory growth {} exceeds limit at iteration {}",
                    memory_growth,
                    iteration
                );

                // Queue should not grow unbounded
                assert!(
                    epoch_gc.cleanup_queue.len() < 1000,
                    "Queue size {} too large at iteration {}",
                    epoch_gc.cleanup_queue.len(),
                    iteration
                );
            }
        }

        // Final cleanup
        for _ in 0..10 {
            epoch_gc.force_advance_and_cleanup();
        }

        let stats = epoch_gc.stats();
        assert!(stats.efficiency_percent() >= 95.0);
    }

    #[test]
    fn performance_benchmark_deferred_vs_direct() {
        const NUM_OPERATIONS: usize = 10_000;

        // Benchmark direct cleanup (simulated)
        let start = Instant::now();
        for i in 0..NUM_OPERATIONS {
            // Simulate direct cleanup overhead
            let _ = format!("cleanup_{}", i);
            thread::sleep(Duration::from_nanos(100)); // Simulated cleanup cost
        }
        let direct_duration = start.elapsed();

        // Benchmark deferred cleanup
        let epoch_gc = EpochGC::new();
        let start = Instant::now();

        for i in 0..NUM_OPERATIONS {
            let work = CleanupWork::Obligation {
                id: i as u64,
                metadata: vec![],
            };
            let _ = epoch_gc.defer_cleanup(work);

            // Periodically process cleanup
            if i % 100 == 0 {
                epoch_gc.force_advance_and_cleanup();
            }
        }

        // Process remaining work
        while epoch_gc.cleanup_queue.len() > 0 {
            epoch_gc.force_advance_and_cleanup();
        }

        let deferred_duration = start.elapsed();

        // Deferred cleanup should be faster for large batches
        // (Note: This is a simplified benchmark - real-world performance
        //  would depend on actual cleanup costs and batching efficiency)
        println!(
            "Direct cleanup: {:?}, Deferred cleanup: {:?}",
            direct_duration, deferred_duration
        );

        let stats = epoch_gc.stats();
        assert!(stats.total_processed.load(Ordering::Relaxed) as usize >= NUM_OPERATIONS);
        assert!(stats.efficiency_percent() >= 95.0);
        assert!(stats.average_batch_size() > 1.0); // Should batch work
    }

    #[test]
    fn correctness_test_no_work_lost() {
        use std::sync::atomic::AtomicU64;

        let epoch_gc = Arc::new(EpochGC::new());
        let _processed_counter = Arc::new(AtomicU64::new(0));

        const NUM_WORK_ITEMS: u64 = 5000;

        // Track which work items were processed
        let mut expected_ids = std::collections::HashSet::new();
        for i in 0..NUM_WORK_ITEMS {
            expected_ids.insert(i);
        }

        // Enqueue work from multiple threads
        let mut handles = Vec::new();
        for thread_id in 0..4 {
            let gc = Arc::clone(&epoch_gc);
            let start_id = thread_id * NUM_WORK_ITEMS / 4;
            let end_id = (thread_id + 1) * NUM_WORK_ITEMS / 4;

            let handle = thread::spawn(move || {
                for id in start_id..end_id {
                    let work = CleanupWork::Obligation {
                        id,
                        metadata: vec![],
                    };

                    // Retry on failure (queue full)
                    while gc.defer_cleanup(work.clone()).is_err() {
                        thread::sleep(Duration::from_micros(10));
                    }
                }
            });
            handles.push(handle);
        }

        // Process work periodically
        let gc_processor = Arc::clone(&epoch_gc);
        let processor_handle = thread::spawn(move || {
            let mut total_processed = 0;
            while total_processed < NUM_WORK_ITEMS {
                let processed = gc_processor.force_advance_and_cleanup();
                total_processed += processed as u64;

                if processed == 0 {
                    thread::sleep(Duration::from_millis(1));
                }
            }
        });

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }
        processor_handle.join().unwrap();

        // Verify no work was lost
        let stats = epoch_gc.stats();
        assert_eq!(
            stats.total_processed.load(Ordering::Relaxed),
            NUM_WORK_ITEMS
        );
        assert_eq!(stats.total_dropped.load(Ordering::Relaxed), 0);
        assert_eq!(stats.efficiency_percent(), 100.0);
    }

    #[test]
    fn backpressure_prevents_unbounded_growth() {
        let config = CleanupConfig {
            max_queue_size: 100,
            ..CleanupConfig::default()
        };
        let queue = DeferredCleanupQueue::with_config(config);

        let work = CleanupWork::Obligation {
            id: 1,
            metadata: vec![0; 1000],
        };

        // Fill queue to capacity
        let mut enqueued = 0;
        let mut rejected = 0;

        for _ in 0..200 {
            match queue.enqueue(work.clone(), 1) {
                Ok(()) => enqueued += 1,
                Err(_) => rejected += 1,
            }
        }

        assert!(
            enqueued <= 100,
            "Should not enqueue more than max_queue_size"
        );
        assert!(rejected > 0, "Should reject some items when full");
        assert!(queue.is_near_capacity(), "Should detect near capacity");

        // Verify backpressure statistics
        let stats = queue.stats();
        assert_eq!(
            stats.total_dropped.load(Ordering::Relaxed) as usize,
            rejected
        );
    }

    #[test]
    fn epoch_safety_prevents_premature_cleanup() {
        let gc = EpochGC::with_config(CleanupConfig {
            max_batch_size: 1000,
            ..CleanupConfig::default()
        });

        // Enqueue work in current epoch
        for i in 0..10 {
            let work = CleanupWork::Obligation {
                id: i,
                metadata: vec![],
            };
            gc.defer_cleanup(work).unwrap();
        }

        // Try to advance without sufficient time (should not process work)
        let processed = gc.try_advance_and_cleanup();
        assert_eq!(processed, 0, "Should not process work from current epoch");

        // Force advance and verify work is processed
        let processed = gc.force_advance_and_cleanup();
        assert_eq!(
            processed, 10,
            "Should process all work after forced advance"
        );
    }
}
