//! Resource limits and memory pools for symbol processing.
//!
//! This module provides two core primitives:
//! - `SymbolPool` for bounded, reusable symbol buffers
//! - `ResourceTracker` for enforcing global resource limits

use std::sync::{Arc, Mutex};

/// Configuration for a symbol buffer pool.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Symbol size in bytes.
    pub symbol_size: u16,
    /// Initial pool size (number of buffers).
    pub initial_size: usize,
    /// Maximum pool size.
    pub max_size: usize,
    /// Whether to allow dynamic growth.
    pub allow_growth: bool,
    /// Growth increment when expanding.
    pub growth_increment: usize,
}

impl PoolConfig {
    /// Returns a normalized config with `max_size >= initial_size`.
    #[must_use]
    pub fn normalized(mut self) -> Self {
        if self.max_size < self.initial_size {
            self.max_size = self.initial_size;
        }
        if self.growth_increment == 0 {
            self.growth_increment = 1;
        }
        self
    }
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            symbol_size: 1024,
            initial_size: 0,
            max_size: 1024,
            allow_growth: true,
            growth_increment: 64,
        }
    }
}

/// A pre-allocated buffer for symbol data.
#[derive(Debug)]
pub struct SymbolBuffer {
    data: Box<[u8]>,
    in_use: bool,
}

impl SymbolBuffer {
    /// Creates a new buffer with the given symbol size.
    #[must_use]
    pub fn new(symbol_size: u16) -> Self {
        let len = symbol_size as usize;
        Self {
            data: vec![0u8; len].into_boxed_slice(),
            in_use: false,
        }
    }

    /// Returns the buffer as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Returns the buffer as a mutable slice.
    #[must_use]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Returns the buffer length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Marks the buffer as in use.
    fn mark_in_use(&mut self) {
        self.in_use = true;
    }

    /// Marks the buffer as free.
    fn mark_free(&mut self) {
        self.in_use = false;
    }
}

/// Pool usage statistics.
#[derive(Debug, Clone, Default)]
pub struct PoolStats {
    /// Total number of allocations.
    pub allocations: u64,
    /// Total number of deallocations.
    pub deallocations: u64,
    /// Allocations satisfied from the free list.
    pub pool_hits: u64,
    /// Allocation attempts that could not use the free list.
    pub pool_misses: u64,
    /// Peak number of simultaneously allocated buffers.
    pub peak_usage: usize,
    /// Current number of allocated buffers.
    pub current_usage: usize,
    /// Number of times the pool grew.
    pub growth_events: u64,
}

/// Error returned when a pool cannot allocate.
#[derive(Debug, Clone, Copy)]
pub struct PoolExhausted;

impl std::fmt::Display for PoolExhausted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "symbol pool exhausted")
    }
}

impl std::error::Error for PoolExhausted {}

/// Symbol memory pool for efficient allocation.
#[derive(Debug)]
pub struct SymbolPool {
    free_list: Vec<SymbolBuffer>,
    allocated: usize,
    config: PoolConfig,
    stats: PoolStats,
}

impl SymbolPool {
    /// Creates a new pool with the given configuration.
    #[must_use]
    pub fn new(config: PoolConfig) -> Self {
        let config = config.normalized();
        let mut pool = Self {
            free_list: Vec::with_capacity(config.initial_size),
            allocated: 0,
            config,
            stats: PoolStats::default(),
        };
        pool.warm(pool.config.initial_size);
        pool
    }

    /// Pre-warms the pool to a specified size.
    pub fn warm(&mut self, count: usize) {
        let target = count.min(self.config.max_size);
        while self.free_list.len() < target {
            self.free_list
                .push(SymbolBuffer::new(self.config.symbol_size));
        }
    }

    /// Attempts to grow the pool by `growth_increment`.
    fn grow(&mut self) -> bool {
        if !self.config.allow_growth {
            return false;
        }
        if self.free_list.len() + self.allocated >= self.config.max_size {
            return false;
        }

        let available = self
            .config
            .max_size
            .saturating_sub(self.free_list.len() + self.allocated);
        let grow_by = self.config.growth_increment.min(available);

        for _ in 0..grow_by {
            self.free_list
                .push(SymbolBuffer::new(self.config.symbol_size));
        }

        if grow_by > 0 {
            self.stats.growth_events += 1;
            true
        } else {
            false
        }
    }

    /// Allocates a symbol buffer from the pool.
    pub fn allocate(&mut self) -> Result<SymbolBuffer, PoolExhausted> {
        if let Some(mut buffer) = self.free_list.pop() {
            buffer.mark_in_use();
            self.allocated += 1;
            self.stats.allocations += 1;
            self.stats.pool_hits += 1;
            self.stats.current_usage = self.allocated;
            self.stats.peak_usage = self.stats.peak_usage.max(self.allocated);
            return Ok(buffer);
        }

        if self.grow() {
            return self.allocate();
        }

        self.stats.pool_misses += 1;
        Err(PoolExhausted)
    }

    /// Tries to allocate a symbol buffer, returning `None` if exhausted.
    pub fn try_allocate(&mut self) -> Option<SymbolBuffer> {
        self.allocate().ok()
    }

    /// Returns a buffer to the pool.
    pub fn deallocate(&mut self, mut buffer: SymbolBuffer) {
        buffer.mark_free();
        self.free_list.push(buffer);
        self.allocated = self.allocated.saturating_sub(1);
        self.stats.deallocations += 1;
        self.stats.current_usage = self.allocated;
    }

    /// Returns a snapshot of pool statistics.
    #[must_use]
    pub fn stats(&self) -> &PoolStats {
        &self.stats
    }

    /// Resets pool statistics.
    pub fn reset_stats(&mut self) {
        self.stats = PoolStats::default();
    }

    /// Shrinks the pool to its initial size.
    pub fn shrink_to_fit(&mut self) {
        let target = self.config.initial_size.min(self.config.max_size);
        if self.free_list.len() > target {
            self.free_list.truncate(target);
        }
    }
}

/// Global resource limits.
#[derive(Debug, Clone)]
#[allow(clippy::struct_field_names)]
pub struct ResourceLimits {
    /// Maximum total memory for symbol buffers.
    pub max_symbol_memory: usize,
    /// Maximum concurrent encoding operations.
    pub max_encoding_ops: usize,
    /// Maximum concurrent decoding operations.
    pub max_decoding_ops: usize,
    /// Maximum symbols in flight.
    pub max_symbols_in_flight: usize,
    /// Per-object memory limit.
    pub max_per_object_memory: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_symbol_memory: usize::MAX,
            max_encoding_ops: usize::MAX,
            max_decoding_ops: usize::MAX,
            max_symbols_in_flight: usize::MAX,
            max_per_object_memory: usize::MAX,
        }
    }
}

/// Current resource usage.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResourceUsage {
    /// Bytes of symbol memory in use.
    pub symbol_memory: usize,
    /// Active encoding operations.
    pub encoding_ops: usize,
    /// Active decoding operations.
    pub decoding_ops: usize,
    /// Symbols currently in flight.
    pub symbols_in_flight: usize,
}

impl ResourceUsage {
    fn add(&mut self, other: Self) {
        self.symbol_memory = self.symbol_memory.saturating_add(other.symbol_memory);
        self.encoding_ops = self.encoding_ops.saturating_add(other.encoding_ops);
        self.decoding_ops = self.decoding_ops.saturating_add(other.decoding_ops);
        self.symbols_in_flight = self
            .symbols_in_flight
            .saturating_add(other.symbols_in_flight);
    }

    fn sub(&mut self, other: Self) {
        self.symbol_memory = self.symbol_memory.saturating_sub(other.symbol_memory);
        self.encoding_ops = self.encoding_ops.saturating_sub(other.encoding_ops);
        self.decoding_ops = self.decoding_ops.saturating_sub(other.decoding_ops);
        self.symbols_in_flight = self
            .symbols_in_flight
            .saturating_sub(other.symbols_in_flight);
    }
}

/// Resource request for acquisition checks.
#[derive(Debug, Clone, Copy, Default)]
pub struct ResourceRequest {
    /// Requested usage amounts.
    pub usage: ResourceUsage,
}

/// Observer for resource pressure events.
pub trait ResourceObserver: Send + Sync {
    /// Called when overall pressure changes.
    fn on_pressure_change(&self, pressure: f64);
    /// Called when a specific resource is approaching its limit.
    fn on_limit_approached(&self, resource: ResourceKind, usage_percent: f64);
    /// Called when a resource limit is exceeded.
    fn on_limit_exceeded(&self, resource: ResourceKind);
}

/// Resource kinds for observer callbacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceKind {
    /// Symbol buffer memory.
    SymbolMemory,
    /// Encoding operation slots.
    EncodingOps,
    /// Decoding operation slots.
    DecodingOps,
    /// In-flight symbol slots.
    SymbolsInFlight,
}

/// Error returned when resource limits are exceeded.
#[derive(Debug, Clone, Copy)]
pub struct ResourceExhausted;

impl std::fmt::Display for ResourceExhausted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "resource limits exceeded")
    }
}

impl std::error::Error for ResourceExhausted {}

struct ResourceTrackerInner {
    limits: ResourceLimits,
    current: ResourceUsage,
    observers: Vec<Box<dyn ResourceObserver>>,
    last_pressure: f64,
}

/// Resource tracker for enforcing limits.
#[derive(Clone)]
pub struct ResourceTracker {
    inner: Arc<Mutex<ResourceTrackerInner>>,
}

impl ResourceTracker {
    /// Creates a new tracker with the given limits.
    #[must_use]
    pub fn new(limits: ResourceLimits) -> Self {
        Self {
            inner: Arc::new(Mutex::new(ResourceTrackerInner {
                limits,
                current: ResourceUsage::default(),
                observers: Vec::new(),
                last_pressure: 0.0,
            })),
        }
    }

    /// Returns the current usage snapshot.
    #[must_use]
    pub fn usage(&self) -> ResourceUsage {
        self.inner.lock().expect("lock poisoned").current
    }

    /// Returns the configured limits.
    #[must_use]
    pub fn limits(&self) -> ResourceLimits {
        self.inner.lock().expect("lock poisoned").limits.clone()
    }

    /// Adds a resource observer.
    pub fn add_observer(&self, observer: Box<dyn ResourceObserver>) {
        self.inner
            .lock()
            .expect("lock poisoned")
            .observers
            .push(observer);
    }

    /// Returns the current pressure level (0.0 - 1.0).
    #[must_use]
    pub fn pressure(&self) -> f64 {
        let inner = self.inner.lock().expect("lock poisoned");
        compute_pressure(&inner.current, &inner.limits)
    }

    /// Returns whether a request can be satisfied.
    #[must_use]
    pub fn can_acquire(&self, request: &ResourceRequest) -> bool {
        let inner = self.inner.lock().expect("lock poisoned");
        let mut projected = inner.current;
        projected.add(request.usage);
        within_limits(&projected, &inner.limits)
    }

    /// Attempts to acquire resources for encoding.
    pub fn try_acquire_encoding(
        &self,
        memory_needed: usize,
    ) -> Result<ResourceGuard, ResourceExhausted> {
        self.try_acquire(ResourceUsage {
            symbol_memory: memory_needed,
            encoding_ops: 1,
            decoding_ops: 0,
            symbols_in_flight: 0,
        })
    }

    /// Attempts to acquire resources for decoding.
    pub fn try_acquire_decoding(
        &self,
        memory_needed: usize,
    ) -> Result<ResourceGuard, ResourceExhausted> {
        self.try_acquire(ResourceUsage {
            symbol_memory: memory_needed,
            encoding_ops: 0,
            decoding_ops: 1,
            symbols_in_flight: 0,
        })
    }

    /// Attempts to acquire a resource request.
    pub fn try_acquire(&self, usage: ResourceUsage) -> Result<ResourceGuard, ResourceExhausted> {
        {
            let mut inner = self.inner.lock().expect("lock poisoned");
            let mut projected = inner.current;
            projected.add(usage);

            if !within_limits(&projected, &inner.limits) {
                notify_limit_exceeded(&inner, &projected);
                drop(inner);
                return Err(ResourceExhausted);
            }

            inner.current = projected;
            notify_pressure(&mut inner);
            drop(inner);
        }

        Ok(ResourceGuard {
            inner: Arc::clone(&self.inner),
            acquired: usage,
        })
    }
}

/// RAII guard that releases resources on drop.
pub struct ResourceGuard {
    inner: Arc<Mutex<ResourceTrackerInner>>,
    acquired: ResourceUsage,
}

impl Drop for ResourceGuard {
    fn drop(&mut self) {
        let mut inner = self.inner.lock().expect("lock poisoned");
        inner.current.sub(self.acquired);
        notify_pressure(&mut inner);
        drop(inner);
    }
}

fn within_limits(usage: &ResourceUsage, limits: &ResourceLimits) -> bool {
    usage.symbol_memory <= limits.max_symbol_memory
        && usage.encoding_ops <= limits.max_encoding_ops
        && usage.decoding_ops <= limits.max_decoding_ops
        && usage.symbols_in_flight <= limits.max_symbols_in_flight
        && usage.symbol_memory <= limits.max_per_object_memory
}

fn compute_pressure(usage: &ResourceUsage, limits: &ResourceLimits) -> f64 {
    let ratios = [
        ratio(usage.symbol_memory, limits.max_symbol_memory),
        ratio(usage.encoding_ops, limits.max_encoding_ops),
        ratio(usage.decoding_ops, limits.max_decoding_ops),
        ratio(usage.symbols_in_flight, limits.max_symbols_in_flight),
    ];
    ratios.into_iter().fold(0.0_f64, f64::max).clamp(0.0, 1.0)
}

#[allow(clippy::cast_precision_loss)]
fn ratio(value: usize, limit: usize) -> f64 {
    if limit == 0 {
        if value == 0 {
            0.0
        } else {
            1.0
        }
    } else {
        (value as f64 / limit as f64).min(1.0)
    }
}

fn notify_pressure(inner: &mut ResourceTrackerInner) {
    let pressure = compute_pressure(&inner.current, &inner.limits);
    if (pressure - inner.last_pressure).abs() > f64::EPSILON {
        inner.last_pressure = pressure;
        for obs in &inner.observers {
            obs.on_pressure_change(pressure);
        }
    }

    notify_limit_approached(inner, pressure);
}

fn notify_limit_approached(inner: &ResourceTrackerInner, pressure: f64) {
    if pressure < 0.8 {
        return;
    }

    let ratios = [
        (
            ResourceKind::SymbolMemory,
            ratio(inner.current.symbol_memory, inner.limits.max_symbol_memory),
        ),
        (
            ResourceKind::EncodingOps,
            ratio(inner.current.encoding_ops, inner.limits.max_encoding_ops),
        ),
        (
            ResourceKind::DecodingOps,
            ratio(inner.current.decoding_ops, inner.limits.max_decoding_ops),
        ),
        (
            ResourceKind::SymbolsInFlight,
            ratio(
                inner.current.symbols_in_flight,
                inner.limits.max_symbols_in_flight,
            ),
        ),
    ];

    for (kind, ratio) in ratios {
        if ratio >= 0.8 {
            for obs in &inner.observers {
                obs.on_limit_approached(kind, ratio);
            }
        }
    }
}

fn notify_limit_exceeded(inner: &ResourceTrackerInner, projected: &ResourceUsage) {
    let limits = &inner.limits;
    if projected.symbol_memory > limits.max_symbol_memory {
        for obs in &inner.observers {
            obs.on_limit_exceeded(ResourceKind::SymbolMemory);
        }
    }
    if projected.encoding_ops > limits.max_encoding_ops {
        for obs in &inner.observers {
            obs.on_limit_exceeded(ResourceKind::EncodingOps);
        }
    }
    if projected.decoding_ops > limits.max_decoding_ops {
        for obs in &inner.observers {
            obs.on_limit_exceeded(ResourceKind::DecodingOps);
        }
    }
    if projected.symbols_in_flight > limits.max_symbols_in_flight {
        for obs in &inner.observers {
            obs.on_limit_exceeded(ResourceKind::SymbolsInFlight);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_allocate_deallocate() {
        let mut pool = SymbolPool::new(PoolConfig::default());
        let buf = pool.allocate().expect("should allocate");
        assert_eq!(buf.len(), 1024);
        pool.deallocate(buf);
        assert_eq!(pool.stats.allocations, 1);
        assert_eq!(pool.stats.deallocations, 1);
        assert_eq!(pool.stats.current_usage, 0);
    }

    #[test]
    fn test_pool_exhaustion() {
        let config = PoolConfig {
            initial_size: 1,
            max_size: 1,
            allow_growth: false,
            ..Default::default()
        };
        let mut pool = SymbolPool::new(config);
        let _buf1 = pool.allocate().expect("should allocate");
        assert!(pool.allocate().is_err());
        assert_eq!(pool.stats.pool_misses, 1);
    }

    #[test]
    fn test_pool_growth() {
        let config = PoolConfig {
            initial_size: 1,
            max_size: 5,
            growth_increment: 2,
            allow_growth: true,
            ..Default::default()
        };
        let mut pool = SymbolPool::new(config);
        let _buf1 = pool.allocate().expect("1");
        let _buf2 = pool.allocate().expect("2"); // triggers growth
        let _buf3 = pool.allocate().expect("3");
        assert_eq!(pool.stats.growth_events, 1);
        assert_eq!(pool.stats.current_usage, 3);
    }

    #[test]
    fn test_resource_tracker_acquire_release() {
        let limits = ResourceLimits {
            max_encoding_ops: 2,
            ..Default::default()
        };
        let tracker = ResourceTracker::new(limits);

        let g1 = tracker.try_acquire_encoding(100).expect("1");
        assert_eq!(tracker.usage().encoding_ops, 1);

        let _g2 = tracker.try_acquire_encoding(100).expect("2");
        assert_eq!(tracker.usage().encoding_ops, 2);

        assert!(tracker.try_acquire_encoding(100).is_err());

        drop(g1);
        assert_eq!(tracker.usage().encoding_ops, 1);

        let _g3 = tracker.try_acquire_encoding(100).expect("3");
    }

    #[test]
    fn test_resource_pressure() {
        let limits = ResourceLimits {
            max_symbol_memory: 100,
            ..Default::default()
        };
        let tracker = ResourceTracker::new(limits);

        assert!((tracker.pressure() - 0.0).abs() < f64::EPSILON);

        let _g1 = tracker
            .try_acquire(ResourceUsage {
                symbol_memory: 50,
                ..Default::default()
            })
            .unwrap();
        assert!((tracker.pressure() - 0.5).abs() < f64::EPSILON);

        let _g2 = tracker
            .try_acquire(ResourceUsage {
                symbol_memory: 50,
                ..Default::default()
            })
            .unwrap();
        assert!((tracker.pressure() - 1.0).abs() < f64::EPSILON);
    }
}
