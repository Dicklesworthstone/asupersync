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
use std::sync::atomic::AtomicU64;

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
    #[inline]
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
    checked_out: bool,
    owner_pool_id: Option<u64>,
}

impl SymbolBuffer {
    /// Creates a new zero-initialized buffer of the given size.
    #[must_use]
    #[inline]
    pub fn new(symbol_size: u16) -> Self {
        let size = usize::from(symbol_size);
        Self {
            data: vec![0_u8; size].into_boxed_slice(),
            checked_out: false,
            owner_pool_id: None,
        }
    }

    /// Returns the length of the buffer in bytes.
    #[must_use]
    #[inline]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if the buffer is empty.
    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns a shared view of the buffer.
    #[must_use]
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Returns a mutable view of the buffer.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Consumes the buffer and returns the boxed slice.
    ///
    /// The buffer's `Drop` zeroing is bypassed for the extracted data — the
    /// caller takes ownership and is responsible for clearing it if needed.
    #[must_use]
    pub fn into_boxed_slice(mut self) -> Box<[u8]> {
        // Swap in an empty slice so Drop zeros nothing.
        std::mem::take(&mut self.data)
    }

    fn mark_checked_out(&mut self, owner_pool_id: u64) {
        self.checked_out = true;
        self.owner_pool_id = Some(owner_pool_id);
    }

    fn clear_checkout_state(&mut self) {
        self.checked_out = false;
        self.owner_pool_id = None;
    }
}

impl Drop for SymbolBuffer {
    fn drop(&mut self) {
        // Zero buffer contents to prevent stale payload leakage when a buffer
        // is dropped without being returned to the pool via `deallocate()`.
        // This is defense-in-depth: `deallocate()` also zeros, and new buffers
        // are zero-initialized, but this catches the panic/forget-to-return path.
        self.data.fill(0);
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
    pool_id: u64,
    config: PoolConfig,
    stats: PoolStats,
}

impl SymbolPool {
    /// Creates a new symbol pool using the provided configuration.
    ///
    /// br-asupersync-jpzl5a — Mints `pool_id` from a process-global
    /// counter. This is fine for accounting / back-pressure decisions
    /// where the only contract is "distinct pools have distinct ids",
    /// but it leaks ambient identity that breaks deterministic replay
    /// across separate `LabRuntime` instances. Determinism-sensitive
    /// callers should use [`Self::new_with_pool_id`] and supply an ID
    /// minted from the runtime-scoped allocator they already hold.
    #[must_use]
    #[inline]
    pub fn new(config: PoolConfig) -> Self {
        Self::new_with_pool_id(config, next_symbol_pool_id())
    }

    /// br-asupersync-jpzl5a — Creates a new symbol pool with an
    /// explicit `pool_id`. Use this from runtime-scoped factories that
    /// want pool identity tied to a deterministic allocator (e.g. a
    /// per-runtime counter or a Cx-derived hash) rather than the
    /// process-global atomic in [`Self::new`].
    #[must_use]
    #[inline]
    pub fn new_with_pool_id(mut config: PoolConfig, pool_id: u64) -> Self {
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
            pool_id,
            config,
            stats: PoolStats::default(),
        }
    }

    /// Returns the current pool configuration.
    #[must_use]
    #[inline]
    pub fn config(&self) -> &PoolConfig {
        &self.config
    }

    /// Returns pool usage statistics.
    #[must_use]
    #[inline]
    pub fn stats(&self) -> &PoolStats {
        &self.stats
    }

    /// Returns the number of buffers currently available in the free list.
    #[must_use]
    #[inline]
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
        if let Some(mut buffer) = self.free_list.pop() {
            buffer.mark_checked_out(self.pool_id);
            self.record_allocation(true);
            return Some(buffer);
        }

        self.stats.pool_misses = self.stats.pool_misses.saturating_add(1);
        if self.grow() {
            if let Some(mut buffer) = self.free_list.pop() {
                buffer.mark_checked_out(self.pool_id);
                self.record_allocation(false);
                return Some(buffer);
            }
        }

        None
    }

    /// Returns a buffer to the pool.
    ///
    /// # Panics
    ///
    /// Panics if the buffer's size does not match the pool's configured symbol size,
    /// if it was never checked out from a pool, or if it belongs to a different pool.
    pub fn deallocate(&mut self, mut buffer: SymbolBuffer) {
        assert_eq!(
            buffer.len(),
            usize::from(self.config.symbol_size),
            "Cannot deallocate buffer of size {} into pool of size {}",
            buffer.len(),
            self.config.symbol_size
        );
        assert!(
            buffer.checked_out,
            "Cannot deallocate buffer that is not currently checked out from a pool"
        );
        assert_eq!(
            buffer.owner_pool_id,
            Some(self.pool_id),
            "Cannot deallocate buffer checked out from a different pool"
        );
        if self.allocated > 0 {
            self.allocated -= 1;
        }
        self.stats.deallocations = self.stats.deallocations.saturating_add(1);
        self.stats.current_usage = self.allocated;
        buffer.as_mut_slice().fill(0);
        buffer.clear_checkout_state();
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

/// br-asupersync-jpzl5a — Process-global SymbolPool id allocator.
///
/// Used by [`SymbolPool::new`] when the caller does not supply an
/// explicit `pool_id`. Determinism-sensitive callers must instead route
/// through [`SymbolPool::new_with_pool_id`] with an ID minted from a
/// runtime-scoped allocator. The static is `pub(crate)`-equivalent —
/// only callable from within this module — but the consequence on
/// downstream observability is documented above the trait surface.
#[inline]
fn next_symbol_pool_id() -> u64 {
    static NEXT_SYMBOL_POOL_ID: AtomicU64 = AtomicU64::new(1);
    NEXT_SYMBOL_POOL_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
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
    #[inline]
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
    #[inline]
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
    #[inline]
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
    #[inline]
    pub fn new(limits: ResourceLimits) -> Self {
        Self {
            limits,
            current: ResourceUsage::default(),
            observers: Vec::new(),
        }
    }

    /// Creates a shared tracker wrapped in `Arc<parking_lot::Mutex<_>>`.
    #[must_use]
    #[inline]
    pub fn shared(limits: ResourceLimits) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self::new(limits)))
    }

    /// Returns the current resource usage.
    #[must_use]
    #[inline]
    pub fn usage(&self) -> &ResourceUsage {
        &self.current
    }

    /// Returns the configured limits.
    #[must_use]
    #[inline]
    pub fn limits(&self) -> &ResourceLimits {
        &self.limits
    }

    /// Checks if a request can be satisfied.
    #[must_use]
    #[inline]
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
    #[inline]
    pub fn pressure(&self) -> f64 {
        let mut max_ratio: f64 = 0.0;
        // Per-object limits are checked per request in `check_limits`; they
        // are not meaningful as an aggregate ratio over total current usage.
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

#[inline]
fn exceeds(limit: usize, requested: usize) -> bool {
    limit == 0 && requested > 0 || (limit > 0 && requested > limit)
}

#[inline]
fn exceeds_with_current(limit: usize, current: usize, requested: usize) -> bool {
    if limit == 0 {
        return requested > 0;
    }
    current.saturating_add(requested) > limit
}

/// br-asupersync-ksvi5z — `ratio` already guards `limit == 0`
/// explicitly; the remaining `usage as f64 / limit as f64` cannot
/// produce NaN (both operands are finite usize→f64 conversions and
/// the divisor is nonzero). The defensive `is_finite()` check below
/// is a regression guard — a future refactor that introduces a
/// non-finite path (e.g. accepting f64 directly from a deserialised
/// snapshot) will fail closed at the saturated `1.0` rather than
/// silently disabling threshold checks. NaN at any downstream
/// comparison returns false, which is precisely the bypass shape the
/// bead flagged in `pressure.rs`.
#[allow(clippy::cast_precision_loss)]
#[inline]
fn ratio(usage: usize, limit: usize) -> f64 {
    let raw = if limit == 0 {
        if usage == 0 { 0.0 } else { 1.0 }
    } else {
        (usage as f64) / (limit as f64)
    };
    if raw.is_finite() {
        raw.clamp(0.0, 1.0)
    } else {
        // Fail-safe: treat unparseable ratio as fully-saturated.
        1.0
    }
}

#[cfg(test)]
#[path = "resource_inline_tests.rs"]
mod tests;
