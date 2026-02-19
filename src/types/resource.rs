//! Resource management primitives for symbol-heavy workloads.
//!
//! This module provides:
//! - A pooled allocator for fixed-size symbol buffers
//! - Resource limit tracking with RAII guards
//! - Backpressure observers for pressure/limit events
//!
//! These types are intentionally synchronous and deterministic; higher-level
//! async orchestration belongs in the runtime layer.

use crate::types::DEFAULT_SYMBOL_SIZE;
use core::fmt;
use parking_lot::Mutex;
use std::sync::Arc;

/// Configuration for a symbol buffer pool.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Symbol payload size in bytes.
    pub symbol_size: u16,
    /// Initial number of buffers to pre-allocate.
    pub initial_size: usize,
    /// Maximum number of buffers allowed in the pool.
    pub max_size: usize,
    /// Whether the pool may grow beyond the initial size.
    pub allow_growth: bool,
    /// Number of buffers to add when growing.
    pub growth_increment: usize,
}

impl PoolConfig {
    /// Creates a new pool configuration.
    #[must_use]
    pub const fn new(
        symbol_size: u16,
        initial_size: usize,
        max_size: usize,
        allow_growth: bool,
        growth_increment: usize,
    ) -> Self {
        Self {
            symbol_size,
            initial_size,
            max_size,
            allow_growth,
            growth_increment,
        }
    }
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            symbol_size: DEFAULT_SYMBOL_SIZE as u16,
            initial_size: 0,
            max_size: 0,
            allow_growth: false,
            growth_increment: 0,
        }
    }
}

/// Statistics for symbol pool usage.
#[derive(Debug, Clone, Default)]
pub struct PoolStats {
    /// Total allocations handed out.
    pub allocations: u64,
    /// Total deallocations returned to the pool.
    pub deallocations: u64,
    /// Allocations satisfied from the free list.
    pub pool_hits: u64,
    /// Allocation attempts that required growth or failed.
    pub pool_misses: u64,
    /// Peak number of outstanding buffers.
    pub peak_usage: usize,
    /// Current number of outstanding buffers.
    pub current_usage: usize,
    /// Number of growth events.
    pub growth_events: u64,
}

/// A fixed-size symbol buffer owned by the pool.
#[derive(Debug)]
pub struct SymbolBuffer {
    data: Box<[u8]>,
}

impl SymbolBuffer {
    /// Creates a new zero-initialized buffer of the given size.
    #[must_use]
    pub fn new(symbol_size: u16) -> Self {
        let size = usize::from(symbol_size);
        Self {
            data: vec![0_u8; size].into_boxed_slice(),
        }
    }

    /// Returns the length of the buffer in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns a shared view of the buffer.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Returns a mutable view of the buffer.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Consumes the buffer and returns the boxed slice.
    #[must_use]
    pub fn into_boxed_slice(self) -> Box<[u8]> {
        self.data
    }
}

/// Error returned when a pool cannot satisfy an allocation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolExhausted;

impl fmt::Display for PoolExhausted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("symbol pool exhausted")
    }
}

impl std::error::Error for PoolExhausted {}

/// A pool of fixed-size symbol buffers.
#[derive(Debug)]
pub struct SymbolPool {
    free_list: Vec<SymbolBuffer>,
    allocated: usize,
    config: PoolConfig,
    stats: PoolStats,
}

impl SymbolPool {
    /// Creates a new symbol pool using the provided configuration.
    #[must_use]
    pub fn new(mut config: PoolConfig) -> Self {
        if config.max_size < config.initial_size {
            config.max_size = config.initial_size;
        }

        let mut free_list = Vec::with_capacity(config.initial_size);
        for _ in 0..config.initial_size {
            free_list.push(SymbolBuffer::new(config.symbol_size));
        }

        Self {
            free_list,
            allocated: 0,
            config,
            stats: PoolStats::default(),
        }
    }

    /// Returns the current pool configuration.
    #[must_use]
    pub fn config(&self) -> &PoolConfig {
        &self.config
    }

    /// Returns pool usage statistics.
    #[must_use]
    pub fn stats(&self) -> &PoolStats {
        &self.stats
    }

    /// Returns the number of buffers currently available in the free list.
    #[must_use]
    pub fn free_count(&self) -> usize {
        self.free_list.len()
    }

    /// Resets pool statistics while keeping current usage.
    pub fn reset_stats(&mut self) {
        self.stats = PoolStats {
            allocations: 0,
            deallocations: 0,
            pool_hits: 0,
            pool_misses: 0,
            peak_usage: self.allocated,
            current_usage: self.allocated,
            growth_events: 0,
        };
    }

    /// Allocates a symbol buffer or returns `PoolExhausted`.
    pub fn allocate(&mut self) -> Result<SymbolBuffer, PoolExhausted> {
        self.try_allocate().ok_or(PoolExhausted)
    }

    /// Attempts to allocate a symbol buffer without blocking.
    pub fn try_allocate(&mut self) -> Option<SymbolBuffer> {
        if let Some(buffer) = self.free_list.pop() {
            self.record_allocation(true);
            return Some(buffer);
        }

        self.stats.pool_misses = self.stats.pool_misses.saturating_add(1);
        if self.grow() {
            if let Some(buffer) = self.free_list.pop() {
                self.record_allocation(false);
                return Some(buffer);
            }
        }

        None
    }

    /// Returns a buffer to the pool.
    pub fn deallocate(&mut self, buffer: SymbolBuffer) {
        if self.allocated > 0 {
            self.allocated -= 1;
        }
        self.stats.deallocations = self.stats.deallocations.saturating_add(1);
        self.stats.current_usage = self.allocated;
        self.free_list.push(buffer);
    }

    /// Shrinks the free list to the minimum size based on the initial pool size.
    pub fn shrink_to_fit(&mut self) {
        let min_free = self.config.initial_size.saturating_sub(self.allocated);
        if self.free_list.len() > min_free {
            self.free_list.truncate(min_free);
        }
    }

    /// Ensures the pool has at least `count` free buffers.
    pub fn warm(&mut self, count: usize) {
        let max_free = self.config.max_size.saturating_sub(self.allocated);
        let target_free = count.min(max_free);
        while self.free_list.len() < target_free {
            self.free_list
                .push(SymbolBuffer::new(self.config.symbol_size));
        }
    }

    fn grow(&mut self) -> bool {
        if !self.config.allow_growth || self.config.growth_increment == 0 {
            return false;
        }

        let total = self.allocated + self.free_list.len();
        if total >= self.config.max_size {
            return false;
        }

        let remaining = self.config.max_size - total;
        let grow_by = self.config.growth_increment.min(remaining);

        for _ in 0..grow_by {
            self.free_list
                .push(SymbolBuffer::new(self.config.symbol_size));
        }

        self.stats.growth_events = self.stats.growth_events.saturating_add(1);
        true
    }

    fn record_allocation(&mut self, from_free_list: bool) {
        self.allocated = self.allocated.saturating_add(1);
        self.stats.allocations = self.stats.allocations.saturating_add(1);
        if from_free_list {
            self.stats.pool_hits = self.stats.pool_hits.saturating_add(1);
        }
        self.stats.current_usage = self.allocated;
        self.stats.peak_usage = self.stats.peak_usage.max(self.allocated);
    }
}

/// Kinds of resource limits enforced by the tracker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceKind {
    /// Total memory used for symbol buffers.
    SymbolMemory,
    /// Concurrent encoding operations.
    EncodingOps,
    /// Concurrent decoding operations.
    DecodingOps,
    /// Symbols currently in flight.
    SymbolsInFlight,
    /// Per-object memory limit.
    PerObjectMemory,
}

/// Limits for symbol-heavy workloads.
#[derive(Debug, Clone, Default)]
pub struct ResourceLimits {
    /// Maximum total memory for symbol buffers.
    pub max_symbol_memory: usize,
    /// Maximum concurrent encoding operations.
    pub max_encoding_ops: usize,
    /// Maximum concurrent decoding operations.
    pub max_decoding_ops: usize,
    /// Maximum symbols in flight.
    pub max_symbols_in_flight: usize,
    /// Maximum memory allowed per object.
    pub max_per_object_memory: usize,
}

impl ResourceLimits {
    /// Returns true if all limits are zero.
    #[must_use]
    pub const fn is_zero(&self) -> bool {
        self.max_symbol_memory == 0
            && self.max_encoding_ops == 0
            && self.max_decoding_ops == 0
            && self.max_symbols_in_flight == 0
            && self.max_per_object_memory == 0
    }
}

/// Current resource usage counters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResourceUsage {
    /// Memory used for symbols.
    pub symbol_memory: usize,
    /// Concurrent encoding operations.
    pub encoding_ops: usize,
    /// Concurrent decoding operations.
    pub decoding_ops: usize,
    /// Symbols in flight.
    pub symbols_in_flight: usize,
}

/// Request for additional resources.
#[derive(Debug, Clone, Copy, Default)]
pub struct ResourceRequest {
    symbol_memory: usize,
    encoding_ops: usize,
    decoding_ops: usize,
    symbols_in_flight: usize,
}

impl ResourceRequest {
    /// Creates a new resource request.
    #[must_use]
    pub const fn new(
        symbol_memory: usize,
        encoding_ops: usize,
        decoding_ops: usize,
        symbols_in_flight: usize,
    ) -> Self {
        Self {
            symbol_memory,
            encoding_ops,
            decoding_ops,
            symbols_in_flight,
        }
    }

    /// Returns the requested symbol memory in bytes.
    #[must_use]
    pub const fn symbol_memory(&self) -> usize {
        self.symbol_memory
    }
}

/// Observer for resource pressure events.
pub trait ResourceObserver: Send + Sync {
    /// Called whenever pressure changes.
    fn on_pressure_change(&self, pressure: f64);
    /// Called when a resource approaches its limit.
    fn on_limit_approached(&self, resource: ResourceKind, usage_percent: f64);
    /// Called when a resource limit is exceeded.
    fn on_limit_exceeded(&self, resource: ResourceKind);
}

/// Error returned when resources cannot be acquired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceExhausted {
    /// Symbol memory limit exceeded.
    SymbolMemory,
    /// Encoding operations limit exceeded.
    EncodingOps,
    /// Decoding operations limit exceeded.
    DecodingOps,
    /// Symbols-in-flight limit exceeded.
    SymbolsInFlight,
    /// Per-object memory limit exceeded.
    PerObjectMemory,
}

impl fmt::Display for ResourceExhausted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::SymbolMemory => "symbol memory limit exceeded",
            Self::EncodingOps => "encoding operations limit exceeded",
            Self::DecodingOps => "decoding operations limit exceeded",
            Self::SymbolsInFlight => "symbols in flight limit exceeded",
            Self::PerObjectMemory => "per-object memory limit exceeded",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for ResourceExhausted {}

/// Tracks resource usage against configured limits.
pub struct ResourceTracker {
    limits: ResourceLimits,
    current: ResourceUsage,
    observers: Vec<Box<dyn ResourceObserver>>,
}

impl ResourceTracker {
    /// Creates a new tracker with the given limits.
    #[must_use]
    pub fn new(limits: ResourceLimits) -> Self {
        Self {
            limits,
            current: ResourceUsage::default(),
            observers: Vec::new(),
        }
    }

    /// Creates a shared tracker wrapped in `Arc<parking_lot::Mutex<_>>`.
    #[must_use]
    pub fn shared(limits: ResourceLimits) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self::new(limits)))
    }

    /// Returns the current resource usage.
    #[must_use]
    pub fn usage(&self) -> &ResourceUsage {
        &self.current
    }

    /// Returns the configured limits.
    #[must_use]
    pub fn limits(&self) -> &ResourceLimits {
        &self.limits
    }

    /// Checks if a request can be satisfied.
    #[must_use]
    pub fn can_acquire(&self, request: &ResourceRequest) -> bool {
        self.check_limits(request).is_ok()
    }

    /// Adds a resource observer.
    pub fn add_observer(&mut self, observer: Box<dyn ResourceObserver>) {
        observer.on_pressure_change(self.pressure());
        self.observers.push(observer);
    }

    /// Computes the current pressure (0.0 to 1.0).
    #[must_use]
    pub fn pressure(&self) -> f64 {
        let mut max_ratio: f64 = 0.0;
        max_ratio = max_ratio.max(ratio(
            self.current.symbol_memory,
            self.limits.max_symbol_memory,
        ));
        max_ratio = max_ratio.max(ratio(
            self.current.encoding_ops,
            self.limits.max_encoding_ops,
        ));
        max_ratio = max_ratio.max(ratio(
            self.current.decoding_ops,
            self.limits.max_decoding_ops,
        ));
        max_ratio = max_ratio.max(ratio(
            self.current.symbols_in_flight,
            self.limits.max_symbols_in_flight,
        ));
        max_ratio = max_ratio.max(ratio(
            self.current.symbol_memory,
            self.limits.max_per_object_memory,
        ));
        max_ratio.min(1.0)
    }

    /// Attempts to acquire resources for an encoding operation.
    pub fn try_acquire_encoding(
        tracker: &Arc<Mutex<Self>>,
        memory_needed: usize,
    ) -> Result<ResourceGuard, ResourceExhausted> {
        let request = ResourceRequest::new(memory_needed, 1, 0, 0);
        Self::try_acquire(tracker, request)
    }

    /// Attempts to acquire resources for a decoding operation.
    pub fn try_acquire_decoding(
        tracker: &Arc<Mutex<Self>>,
        memory_needed: usize,
    ) -> Result<ResourceGuard, ResourceExhausted> {
        let request = ResourceRequest::new(memory_needed, 0, 1, 0);
        Self::try_acquire(tracker, request)
    }

    /// Attempts to acquire arbitrary resources.
    pub fn try_acquire(
        tracker: &Arc<Mutex<Self>>,
        request: ResourceRequest,
    ) -> Result<ResourceGuard, ResourceExhausted> {
        let mut guard = tracker.lock();
        guard.check_limits(&request)?;
        guard.current.symbol_memory = guard
            .current
            .symbol_memory
            .saturating_add(request.symbol_memory);
        guard.current.encoding_ops = guard
            .current
            .encoding_ops
            .saturating_add(request.encoding_ops);
        guard.current.decoding_ops = guard
            .current
            .decoding_ops
            .saturating_add(request.decoding_ops);
        guard.current.symbols_in_flight = guard
            .current
            .symbols_in_flight
            .saturating_add(request.symbols_in_flight);
        guard.notify_observers();
        drop(guard);

        Ok(ResourceGuard {
            tracker: Arc::clone(tracker),
            acquired: ResourceUsage {
                symbol_memory: request.symbol_memory,
                encoding_ops: request.encoding_ops,
                decoding_ops: request.decoding_ops,
                symbols_in_flight: request.symbols_in_flight,
            },
        })
    }

    fn release_locked(&mut self, acquired: &ResourceUsage) {
        self.current.symbol_memory = self
            .current
            .symbol_memory
            .saturating_sub(acquired.symbol_memory);
        self.current.encoding_ops = self
            .current
            .encoding_ops
            .saturating_sub(acquired.encoding_ops);
        self.current.decoding_ops = self
            .current
            .decoding_ops
            .saturating_sub(acquired.decoding_ops);
        self.current.symbols_in_flight = self
            .current
            .symbols_in_flight
            .saturating_sub(acquired.symbols_in_flight);
        self.notify_observers();
    }

    fn check_limits(&self, request: &ResourceRequest) -> Result<(), ResourceExhausted> {
        if exceeds(self.limits.max_per_object_memory, request.symbol_memory) {
            return Err(ResourceExhausted::PerObjectMemory);
        }
        if exceeds_with_current(
            self.limits.max_symbol_memory,
            self.current.symbol_memory,
            request.symbol_memory,
        ) {
            return Err(ResourceExhausted::SymbolMemory);
        }
        if exceeds_with_current(
            self.limits.max_encoding_ops,
            self.current.encoding_ops,
            request.encoding_ops,
        ) {
            return Err(ResourceExhausted::EncodingOps);
        }
        if exceeds_with_current(
            self.limits.max_decoding_ops,
            self.current.decoding_ops,
            request.decoding_ops,
        ) {
            return Err(ResourceExhausted::DecodingOps);
        }
        if exceeds_with_current(
            self.limits.max_symbols_in_flight,
            self.current.symbols_in_flight,
            request.symbols_in_flight,
        ) {
            return Err(ResourceExhausted::SymbolsInFlight);
        }
        Ok(())
    }

    fn notify_observers(&self) {
        let pressure = self.pressure();
        for observer in &self.observers {
            observer.on_pressure_change(pressure);
        }

        self.notify_limit(
            ResourceKind::SymbolMemory,
            self.current.symbol_memory,
            self.limits.max_symbol_memory,
        );
        self.notify_limit(
            ResourceKind::EncodingOps,
            self.current.encoding_ops,
            self.limits.max_encoding_ops,
        );
        self.notify_limit(
            ResourceKind::DecodingOps,
            self.current.decoding_ops,
            self.limits.max_decoding_ops,
        );
        self.notify_limit(
            ResourceKind::SymbolsInFlight,
            self.current.symbols_in_flight,
            self.limits.max_symbols_in_flight,
        );
        self.notify_limit(
            ResourceKind::PerObjectMemory,
            self.current.symbol_memory,
            self.limits.max_per_object_memory,
        );
    }

    #[allow(clippy::cast_precision_loss)]
    fn notify_limit(&self, kind: ResourceKind, usage: usize, limit: usize) {
        if limit == 0 {
            if usage > 0 {
                for observer in &self.observers {
                    observer.on_limit_exceeded(kind);
                }
            }
            return;
        }

        let usage_ratio = (usage as f64) / (limit as f64);
        if usage_ratio >= 1.0 {
            for observer in &self.observers {
                observer.on_limit_exceeded(kind);
            }
        } else if usage_ratio >= 0.9 {
            for observer in &self.observers {
                observer.on_limit_approached(kind, usage_ratio);
            }
        }
    }
}

impl fmt::Debug for ResourceTracker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResourceTracker")
            .field("limits", &self.limits)
            .field("current", &self.current)
            .field("observer_count", &self.observers.len())
            .finish()
    }
}

/// RAII guard that releases resources on drop.
#[derive(Debug)]
pub struct ResourceGuard {
    tracker: Arc<Mutex<ResourceTracker>>,
    acquired: ResourceUsage,
}

impl Drop for ResourceGuard {
    fn drop(&mut self) {
        let mut tracker = self.tracker.lock();
        tracker.release_locked(&self.acquired);
    }
}

fn exceeds(limit: usize, requested: usize) -> bool {
    limit == 0 && requested > 0 || (limit > 0 && requested > limit)
}

fn exceeds_with_current(limit: usize, current: usize, requested: usize) -> bool {
    if limit == 0 {
        return requested > 0;
    }
    current.saturating_add(requested) > limit
}

#[allow(clippy::cast_precision_loss)]
fn ratio(usage: usize, limit: usize) -> f64 {
    if limit == 0 {
        if usage == 0 { 0.0 } else { 1.0 }
    } else {
        (usage as f64) / (limit as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn pool_allocate_deallocate() {
        let config = PoolConfig::new(64, 1, 1, false, 0);
        let mut pool = SymbolPool::new(config);
        let buffer = pool.allocate().expect("expected allocation");
        assert_eq!(buffer.len(), 64);
        pool.deallocate(buffer);
        assert_eq!(pool.stats().current_usage, 0);
    }

    #[test]
    fn pool_exhaustion() {
        let config = PoolConfig::new(32, 1, 1, false, 0);
        let mut pool = SymbolPool::new(config);
        let _ = pool.allocate().expect("first allocation");
        assert!(matches!(pool.allocate(), Err(PoolExhausted)));
    }

    #[test]
    fn pool_growth() {
        let config = PoolConfig::new(16, 0, 2, true, 2);
        let mut pool = SymbolPool::new(config);
        let _ = pool.allocate().expect("allocation after growth");
        assert_eq!(pool.stats().growth_events, 1);
        assert_eq!(pool.stats().pool_misses, 1);
    }

    #[test]
    fn pool_no_growth_when_disabled() {
        let config = PoolConfig::new(16, 0, 2, false, 2);
        let mut pool = SymbolPool::new(config);
        assert!(matches!(pool.allocate(), Err(PoolExhausted)));
    }

    #[test]
    fn pool_max_size_respected() {
        let config = PoolConfig::new(16, 1, 1, true, 1);
        let mut pool = SymbolPool::new(config);
        let _ = pool.allocate().expect("first allocation");
        assert!(matches!(pool.allocate(), Err(PoolExhausted)));
    }

    #[test]
    fn pool_stats_tracking() {
        let config = PoolConfig::new(8, 2, 2, false, 0);
        let mut pool = SymbolPool::new(config);
        let a = pool.allocate().expect("alloc a");
        let b = pool.allocate().expect("alloc b");
        pool.deallocate(a);
        pool.deallocate(b);
        assert_eq!(pool.stats().allocations, 2);
        assert_eq!(pool.stats().deallocations, 2);
        assert_eq!(pool.stats().pool_hits, 2);
    }

    #[test]
    fn pool_shrink_and_warm() {
        let config = PoolConfig::new(8, 1, 4, true, 1);
        let mut pool = SymbolPool::new(config);
        pool.warm(4);
        assert_eq!(pool.free_count(), 4);
        let _ = pool.allocate().expect("allocation");
        pool.shrink_to_fit();
        assert!(pool.free_count() <= 1);
    }

    #[test]
    fn resource_acquire_within_limits() {
        let limits = ResourceLimits {
            max_symbol_memory: 100,
            max_encoding_ops: 1,
            max_decoding_ops: 1,
            max_symbols_in_flight: 10,
            max_per_object_memory: 100,
        };
        let tracker = ResourceTracker::shared(limits);
        let guard =
            ResourceTracker::try_acquire_encoding(&tracker, 50).expect("expected acquisition");
        drop(guard);
        let usage = tracker.lock().usage().clone();
        assert_eq!(usage.symbol_memory, 0);
    }

    #[test]
    fn resource_acquire_exceeds_limit() {
        let limits = ResourceLimits {
            max_symbol_memory: 10,
            max_encoding_ops: 1,
            max_decoding_ops: 1,
            max_symbols_in_flight: 10,
            max_per_object_memory: 10,
        };
        let tracker = ResourceTracker::shared(limits);
        let err = ResourceTracker::try_acquire_encoding(&tracker, 20)
            .expect_err("expected limit failure");
        assert_eq!(err, ResourceExhausted::PerObjectMemory);
    }

    #[test]
    fn resource_guard_releases_on_drop() {
        let limits = ResourceLimits {
            max_symbol_memory: 100,
            max_encoding_ops: 1,
            max_decoding_ops: 1,
            max_symbols_in_flight: 1,
            max_per_object_memory: 100,
        };
        let tracker = ResourceTracker::shared(limits);
        {
            let _guard = ResourceTracker::try_acquire_encoding(&tracker, 10).expect("acquire");
        }
        let usage = tracker.lock().usage().clone();
        assert_eq!(usage.symbol_memory, 0);
        assert_eq!(usage.encoding_ops, 0);
    }

    #[test]
    fn resource_zero_limit_fails() {
        let limits = ResourceLimits {
            max_symbol_memory: 0,
            max_encoding_ops: 0,
            max_decoding_ops: 0,
            max_symbols_in_flight: 0,
            max_per_object_memory: 0,
        };
        let tracker = ResourceTracker::shared(limits);
        let err = ResourceTracker::try_acquire_encoding(&tracker, 1).expect_err("expected failure");
        assert_eq!(err, ResourceExhausted::PerObjectMemory);
    }

    struct TestObserver {
        pressure_calls: Arc<AtomicUsize>,
        limit_calls: Arc<AtomicUsize>,
    }

    impl TestObserver {
        fn new(pressure_calls: Arc<AtomicUsize>, limit_calls: Arc<AtomicUsize>) -> Self {
            Self {
                pressure_calls,
                limit_calls,
            }
        }
    }

    impl ResourceObserver for TestObserver {
        fn on_pressure_change(&self, _pressure: f64) {
            self.pressure_calls.fetch_add(1, Ordering::Relaxed);
        }

        fn on_limit_approached(&self, _resource: ResourceKind, _usage_percent: f64) {
            self.limit_calls.fetch_add(1, Ordering::Relaxed);
        }

        fn on_limit_exceeded(&self, _resource: ResourceKind) {
            self.limit_calls.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn resource_observer_notified() {
        let limits = ResourceLimits {
            max_symbol_memory: 10,
            max_encoding_ops: 1,
            max_decoding_ops: 1,
            max_symbols_in_flight: 1,
            max_per_object_memory: 10,
        };
        let tracker = ResourceTracker::shared(limits);
        let pressure_calls = Arc::new(AtomicUsize::new(0));
        let limit_calls = Arc::new(AtomicUsize::new(0));
        let observer = Box::new(TestObserver::new(
            Arc::clone(&pressure_calls),
            Arc::clone(&limit_calls),
        ));
        tracker.lock().add_observer(observer);
        let _guard = ResourceTracker::try_acquire_encoding(&tracker, 9).expect("acquire");
        assert!(pressure_calls.load(Ordering::Relaxed) > 0);
        assert!(limit_calls.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn resource_tracker_lock_survives_panicking_holder() {
        let limits = ResourceLimits {
            max_symbol_memory: 100,
            max_encoding_ops: 1,
            max_decoding_ops: 1,
            max_symbols_in_flight: 1,
            max_per_object_memory: 100,
        };
        let tracker = ResourceTracker::shared(limits);
        let tracker_clone = Arc::clone(&tracker);

        let panicked = std::thread::spawn(move || {
            let _guard = tracker_clone.lock();
            panic!("simulate panic while holding resource tracker lock");
        })
        .join();
        assert!(panicked.is_err(), "panic thread should panic");

        let guard =
            ResourceTracker::try_acquire_encoding(&tracker, 10).expect("acquire after panic");
        drop(guard);

        let usage = tracker.lock().usage().clone();
        assert_eq!(usage.symbol_memory, 0);
        assert_eq!(usage.encoding_ops, 0);
    }

    // ---- Pure data type tests ----

    #[test]
    fn pool_config_default() {
        let cfg = PoolConfig::default();
        assert_eq!(cfg.symbol_size, DEFAULT_SYMBOL_SIZE as u16);
        assert_eq!(cfg.initial_size, 0);
        assert_eq!(cfg.max_size, 0);
        assert!(!cfg.allow_growth);
        assert_eq!(cfg.growth_increment, 0);
    }

    #[test]
    fn pool_config_debug() {
        let cfg = PoolConfig::new(256, 10, 100, true, 5);
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("PoolConfig"), "{dbg}");
        assert!(dbg.contains("256"), "{dbg}");
    }

    #[test]
    fn pool_stats_default() {
        let stats = PoolStats::default();
        assert_eq!(stats.allocations, 0);
        assert_eq!(stats.deallocations, 0);
        assert_eq!(stats.pool_hits, 0);
        assert_eq!(stats.pool_misses, 0);
        assert_eq!(stats.peak_usage, 0);
        assert_eq!(stats.current_usage, 0);
        assert_eq!(stats.growth_events, 0);
    }

    #[test]
    fn pool_stats_debug() {
        let stats = PoolStats {
            allocations: 5,
            ..PoolStats::default()
        };
        let dbg = format!("{stats:?}");
        assert!(dbg.contains("PoolStats"), "{dbg}");
        assert!(dbg.contains("5"), "{dbg}");
    }

    #[test]
    fn symbol_buffer_operations() {
        let mut buf = SymbolBuffer::new(16);
        assert_eq!(buf.len(), 16);
        assert!(!buf.is_empty());
        assert_eq!(buf.as_slice().len(), 16);
        assert!(buf.as_slice().iter().all(|&b| b == 0));

        buf.as_mut_slice()[0] = 42;
        assert_eq!(buf.as_slice()[0], 42);

        let boxed = buf.into_boxed_slice();
        assert_eq!(boxed.len(), 16);
        assert_eq!(boxed[0], 42);
    }

    #[test]
    fn symbol_buffer_zero_size() {
        let buf = SymbolBuffer::new(0);
        assert_eq!(buf.len(), 0);
        assert!(buf.is_empty());
    }

    #[test]
    fn symbol_buffer_debug() {
        let buf = SymbolBuffer::new(4);
        let dbg = format!("{buf:?}");
        assert!(dbg.contains("SymbolBuffer"), "{dbg}");
    }

    #[test]
    fn pool_exhausted_display_and_error() {
        let err = PoolExhausted;
        assert_eq!(err.to_string(), "symbol pool exhausted");
        assert!(std::error::Error::source(&err).is_none());
        assert_eq!(err, PoolExhausted);
    }

    #[test]
    fn resource_exhausted_display_all_variants() {
        let cases = [
            (ResourceExhausted::SymbolMemory, "symbol memory"),
            (ResourceExhausted::EncodingOps, "encoding operations"),
            (ResourceExhausted::DecodingOps, "decoding operations"),
            (ResourceExhausted::SymbolsInFlight, "symbols in flight"),
            (ResourceExhausted::PerObjectMemory, "per-object memory"),
        ];
        for (variant, expected_substr) in cases {
            let msg = variant.to_string();
            assert!(msg.contains(expected_substr), "{msg}");
            assert!(std::error::Error::source(&variant).is_none());
        }
    }

    #[test]
    fn resource_kind_debug_all_variants() {
        let kinds = [
            ResourceKind::SymbolMemory,
            ResourceKind::EncodingOps,
            ResourceKind::DecodingOps,
            ResourceKind::SymbolsInFlight,
            ResourceKind::PerObjectMemory,
        ];
        for kind in &kinds {
            let dbg = format!("{kind:?}");
            assert!(!dbg.is_empty());
        }
    }

    #[test]
    fn resource_limits_default_is_zero() {
        let limits = ResourceLimits::default();
        assert!(limits.is_zero());
    }

    #[test]
    fn resource_limits_non_zero() {
        let limits = ResourceLimits {
            max_symbol_memory: 1,
            ..ResourceLimits::default()
        };
        assert!(!limits.is_zero());
    }

    #[test]
    fn resource_usage_default() {
        let usage = ResourceUsage::default();
        assert_eq!(usage.symbol_memory, 0);
        assert_eq!(usage.encoding_ops, 0);
        assert_eq!(usage.decoding_ops, 0);
        assert_eq!(usage.symbols_in_flight, 0);
    }

    #[test]
    fn resource_request_default_and_accessor() {
        let req = ResourceRequest::default();
        assert_eq!(req.symbol_memory(), 0);

        let req = ResourceRequest::new(1024, 2, 3, 10);
        assert_eq!(req.symbol_memory(), 1024);
    }

    #[test]
    fn resource_tracker_debug() {
        let limits = ResourceLimits::default();
        let tracker = ResourceTracker::new(limits);
        let dbg = format!("{tracker:?}");
        assert!(dbg.contains("ResourceTracker"), "{dbg}");
    }

    #[test]
    fn resource_tracker_pressure_with_zero_limits() {
        let limits = ResourceLimits::default();
        let tracker = ResourceTracker::new(limits);
        // No usage, no limits → pressure = 0
        assert_eq!(tracker.pressure(), 0.0);
    }

    #[test]
    fn resource_tracker_can_acquire_predicate() {
        let limits = ResourceLimits {
            max_symbol_memory: 100,
            max_encoding_ops: 1,
            max_decoding_ops: 1,
            max_symbols_in_flight: 10,
            max_per_object_memory: 100,
        };
        let tracker = ResourceTracker::new(limits);
        let req = ResourceRequest::new(50, 1, 0, 0);
        assert!(tracker.can_acquire(&req));

        let req = ResourceRequest::new(200, 1, 0, 0);
        assert!(!tracker.can_acquire(&req));
    }

    #[test]
    fn resource_guard_debug() {
        let limits = ResourceLimits {
            max_symbol_memory: 100,
            max_encoding_ops: 1,
            max_decoding_ops: 1,
            max_symbols_in_flight: 10,
            max_per_object_memory: 100,
        };
        let tracker = ResourceTracker::shared(limits);
        let guard = ResourceTracker::try_acquire_encoding(&tracker, 10).expect("acquire");
        let dbg = format!("{guard:?}");
        assert!(dbg.contains("ResourceGuard"), "{dbg}");
    }

    #[test]
    fn pool_reset_stats() {
        let config = PoolConfig::new(8, 2, 2, false, 0);
        let mut pool = SymbolPool::new(config);
        let buf = pool.allocate().expect("alloc");
        pool.deallocate(buf);
        assert!(pool.stats().allocations > 0);

        pool.reset_stats();
        assert_eq!(pool.stats().allocations, 0);
        assert_eq!(pool.stats().deallocations, 0);
    }

    #[test]
    fn pool_peak_usage_tracking() {
        let config = PoolConfig::new(8, 4, 4, false, 0);
        let mut pool = SymbolPool::new(config);
        let a = pool.allocate().expect("a");
        let b = pool.allocate().expect("b");
        let c = pool.allocate().expect("c");
        assert_eq!(pool.stats().peak_usage, 3);
        pool.deallocate(a);
        pool.deallocate(b);
        // Peak stays at 3 even after deallocation
        assert_eq!(pool.stats().peak_usage, 3);
        assert_eq!(pool.stats().current_usage, 1);
        pool.deallocate(c);
    }

    #[test]
    fn try_acquire_decoding() {
        let limits = ResourceLimits {
            max_symbol_memory: 100,
            max_encoding_ops: 1,
            max_decoding_ops: 1,
            max_symbols_in_flight: 10,
            max_per_object_memory: 100,
        };
        let tracker = ResourceTracker::shared(limits);
        let guard = ResourceTracker::try_acquire_decoding(&tracker, 50).expect("decode acquire");
        {
            let t = tracker.lock();
            assert_eq!(t.usage().decoding_ops, 1);
            assert_eq!(t.usage().symbol_memory, 50);
        }
        drop(guard);
        let t = tracker.lock();
        assert_eq!(t.usage().decoding_ops, 0);
    }

    #[test]
    fn pool_config_max_clamp() {
        // When max_size < initial_size, constructor clamps max_size
        let config = PoolConfig::new(8, 5, 2, false, 0);
        let pool = SymbolPool::new(config);
        assert!(pool.config().max_size >= pool.config().initial_size);
    }
}
