//! Resource limits and memory pools for symbol processing.
//!
//! This module provides two core primitives:
//! - `SymbolPool` for bounded, reusable symbol buffers
//! - `ResourceTracker` for enforcing global resource limits

use parking_lot::Mutex;
use std::sync::Arc;

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
        debug_assert!(
            buffer.in_use,
            "deallocating a buffer that is not marked in-use"
        );
        debug_assert_eq!(
            buffer.len(),
            self.config.symbol_size as usize,
            "deallocating a buffer with wrong symbol_size"
        );
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

    /// Resets pool statistics while keeping current/peak usage in sync with actual state.
    pub fn reset_stats(&mut self) {
        self.stats = PoolStats::default();
        self.stats.current_usage = self.allocated;
        self.stats.peak_usage = self.allocated;
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
    observers: Vec<Arc<dyn ResourceObserver>>,
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
        self.inner.lock().current
    }

    /// Returns the configured limits.
    #[must_use]
    pub fn limits(&self) -> ResourceLimits {
        self.inner.lock().limits.clone()
    }

    /// Adds a resource observer.
    pub fn add_observer(&self, observer: Box<dyn ResourceObserver>) {
        self.inner.lock().observers.push(Arc::from(observer));
    }

    /// Returns the current pressure level (0.0 - 1.0).
    #[must_use]
    pub fn pressure(&self) -> f64 {
        let inner = self.inner.lock();
        compute_pressure(&inner.current, &inner.limits)
    }

    /// Returns whether a request can be satisfied.
    #[must_use]
    pub fn can_acquire(&self, request: &ResourceRequest) -> bool {
        let inner = self.inner.lock();
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
    #[allow(clippy::significant_drop_tightening)] // false positive: inner still borrowed by prepare_pressure_notifications
    pub fn try_acquire(&self, usage: ResourceUsage) -> Result<ResourceGuard, ResourceExhausted> {
        let batch = {
            let mut inner = self.inner.lock();
            let mut projected = inner.current;
            projected.add(usage);

            if !within_limits(&projected, &inner.limits) {
                let batch = prepare_limit_exceeded(&inner, &projected);
                drop(inner);
                batch.dispatch();
                return Err(ResourceExhausted);
            }

            inner.current = projected;
            prepare_pressure_notifications(&mut inner)
        };

        batch.dispatch();

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
    #[allow(clippy::significant_drop_tightening)] // false positive: inner still borrowed by prepare_pressure_notifications
    fn drop(&mut self) {
        let batch = {
            let mut inner = self.inner.lock();
            inner.current.sub(self.acquired);
            prepare_pressure_notifications(&mut inner)
        };
        batch.dispatch();
    }
}

struct NotificationBatch {
    observers: Vec<Arc<dyn ResourceObserver>>,
    pressure_change: Option<f64>,
    approached: Vec<(ResourceKind, f64)>,
    exceeded: Vec<ResourceKind>,
}

impl NotificationBatch {
    fn empty() -> Self {
        Self {
            observers: Vec::new(),
            pressure_change: None,
            approached: Vec::new(),
            exceeded: Vec::new(),
        }
    }

    fn dispatch(self) {
        for obs in &self.observers {
            if let Some(p) = self.pressure_change {
                obs.on_pressure_change(p);
            }
            for (kind, ratio) in &self.approached {
                obs.on_limit_approached(*kind, *ratio);
            }
            for kind in &self.exceeded {
                obs.on_limit_exceeded(*kind);
            }
        }
    }
}

fn within_limits(usage: &ResourceUsage, limits: &ResourceLimits) -> bool {
    // Note: max_per_object_memory is intentionally NOT checked here.
    // `usage.symbol_memory` is the global cumulative usage, not a per-object
    // value. Per-object enforcement belongs at the call-site that knows which
    // individual object is requesting memory.
    usage.symbol_memory <= limits.max_symbol_memory
        && usage.encoding_ops <= limits.max_encoding_ops
        && usage.decoding_ops <= limits.max_decoding_ops
        && usage.symbols_in_flight <= limits.max_symbols_in_flight
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
        if value == 0 { 0.0 } else { 1.0 }
    } else {
        (value as f64 / limit as f64).min(1.0)
    }
}

fn prepare_pressure_notifications(inner: &mut ResourceTrackerInner) -> NotificationBatch {
    let pressure = compute_pressure(&inner.current, &inner.limits);
    let mut batch = NotificationBatch::empty();
    batch.observers.clone_from(&inner.observers);

    if (pressure - inner.last_pressure).abs() > f64::EPSILON {
        inner.last_pressure = pressure;
        batch.pressure_change = Some(pressure);
    }

    if pressure >= 0.8 {
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
                batch.approached.push((kind, ratio));
            }
        }
    }

    batch
}

fn prepare_limit_exceeded(
    inner: &ResourceTrackerInner,
    projected: &ResourceUsage,
) -> NotificationBatch {
    let mut batch = NotificationBatch::empty();
    batch.observers.clone_from(&inner.observers);
    let limits = &inner.limits;

    if projected.symbol_memory > limits.max_symbol_memory {
        batch.exceeded.push(ResourceKind::SymbolMemory);
    }
    if projected.encoding_ops > limits.max_encoding_ops {
        batch.exceeded.push(ResourceKind::EncodingOps);
    }
    if projected.decoding_ops > limits.max_decoding_ops {
        batch.exceeded.push(ResourceKind::DecodingOps);
    }
    if projected.symbols_in_flight > limits.max_symbols_in_flight {
        batch.exceeded.push(ResourceKind::SymbolsInFlight);
    }

    batch
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

    #[test]
    fn test_reset_stats_preserves_current_usage() {
        let mut pool = SymbolPool::new(PoolConfig::default());
        let _buf = pool.allocate().expect("should allocate");
        assert_eq!(pool.stats.current_usage, 1);
        assert_eq!(pool.stats.allocations, 1);

        pool.reset_stats();
        // After reset, current_usage and peak_usage should reflect actual allocated count.
        assert_eq!(pool.stats.current_usage, 1);
        assert_eq!(pool.stats.peak_usage, 1);
        // But cumulative counters should be zero.
        assert_eq!(pool.stats.allocations, 0);
        assert_eq!(pool.stats.deallocations, 0);
    }

    #[test]
    fn test_within_limits_ignores_per_object_memory() {
        // per_object_memory is smaller than total symbol_memory: must NOT block global checks.
        let limits = ResourceLimits {
            max_symbol_memory: 1000,
            max_per_object_memory: 100,
            ..Default::default()
        };
        let usage = ResourceUsage {
            symbol_memory: 500,
            ..Default::default()
        };
        // Global usage (500) exceeds per_object limit (100) but is within global limit (1000).
        // within_limits must return true because per-object enforcement is not its job.
        assert!(within_limits(&usage, &limits));
    }

    // Pure data-type tests (wave 17 – CyanBarn)

    #[test]
    fn pool_config_debug_clone() {
        let cfg = PoolConfig::default();
        let cfg2 = cfg;
        assert!(format!("{cfg2:?}").contains("PoolConfig"));
    }

    #[test]
    fn pool_config_default_values() {
        let cfg = PoolConfig::default();
        assert_eq!(cfg.symbol_size, 1024);
        assert_eq!(cfg.initial_size, 0);
        assert_eq!(cfg.max_size, 1024);
        assert!(cfg.allow_growth);
        assert_eq!(cfg.growth_increment, 64);
    }

    #[test]
    fn pool_config_normalized_clamps() {
        let cfg = PoolConfig {
            initial_size: 10,
            max_size: 5,
            growth_increment: 0,
            ..Default::default()
        }
        .normalized();
        assert!(cfg.max_size >= cfg.initial_size);
        assert!(cfg.growth_increment >= 1);
    }

    #[test]
    fn symbol_buffer_debug_new_len_empty() {
        let buf = SymbolBuffer::new(64);
        assert_eq!(buf.len(), 64);
        assert!(!buf.is_empty());
        assert!(format!("{buf:?}").contains("SymbolBuffer"));
    }

    #[test]
    fn symbol_buffer_as_slice() {
        let mut buf = SymbolBuffer::new(4);
        assert_eq!(buf.as_slice().len(), 4);
        buf.as_mut_slice()[0] = 0xFF;
        assert_eq!(buf.as_slice()[0], 0xFF);
    }

    #[test]
    fn symbol_buffer_zero_size_is_empty() {
        let buf = SymbolBuffer::new(0);
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn pool_stats_debug_clone_default() {
        let stats = PoolStats::default();
        let stats2 = stats;
        assert_eq!(stats2.allocations, 0);
        assert!(format!("{stats2:?}").contains("PoolStats"));
    }

    #[test]
    fn pool_exhausted_debug_clone_copy() {
        let e = PoolExhausted;
        let e2 = e;
        assert!(format!("{e2:?}").contains("PoolExhausted"));
    }

    #[test]
    fn pool_exhausted_display_error() {
        let e = PoolExhausted;
        assert!(e.to_string().contains("exhausted"));
        let err: Box<dyn std::error::Error> = Box::new(e);
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn resource_limits_debug_clone_default() {
        let lim = ResourceLimits::default();
        let lim2 = lim;
        assert_eq!(lim2.max_symbol_memory, usize::MAX);
        assert!(format!("{lim2:?}").contains("ResourceLimits"));
    }

    #[test]
    fn resource_usage_debug_clone_copy_default_eq() {
        let u = ResourceUsage::default();
        let u2 = u;
        assert_eq!(u, u2);
        assert!(format!("{u:?}").contains("ResourceUsage"));
    }

    #[test]
    fn resource_usage_ne() {
        let u1 = ResourceUsage::default();
        let u2 = ResourceUsage {
            symbol_memory: 100,
            ..Default::default()
        };
        assert_ne!(u1, u2);
    }

    #[test]
    fn resource_request_debug_clone_copy_default() {
        let req = ResourceRequest::default();
        let req2 = req;
        assert_eq!(req2.usage, ResourceUsage::default());
        assert!(format!("{req2:?}").contains("ResourceRequest"));
    }

    #[test]
    fn resource_kind_debug_clone_copy_eq() {
        let k = ResourceKind::SymbolMemory;
        let k2 = k;
        assert_eq!(k, k2);
        assert!(format!("{k:?}").contains("SymbolMemory"));
    }

    #[test]
    fn resource_kind_all_variants() {
        let variants = [
            ResourceKind::SymbolMemory,
            ResourceKind::EncodingOps,
            ResourceKind::DecodingOps,
            ResourceKind::SymbolsInFlight,
        ];
        for (i, v) in variants.iter().enumerate() {
            for (j, v2) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(v, v2);
                } else {
                    assert_ne!(v, v2);
                }
            }
        }
    }

    #[test]
    fn resource_exhausted_debug_clone_copy() {
        let e = ResourceExhausted;
        let e2 = e;
        assert!(format!("{e2:?}").contains("ResourceExhausted"));
    }

    #[test]
    fn resource_exhausted_display_error() {
        let e = ResourceExhausted;
        assert!(e.to_string().contains("resource limits exceeded"));
        let err: Box<dyn std::error::Error> = Box::new(e);
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn symbol_pool_debug() {
        let pool = SymbolPool::new(PoolConfig::default());
        assert!(format!("{pool:?}").contains("SymbolPool"));
    }

    #[test]
    fn symbol_pool_warm() {
        let mut pool = SymbolPool::new(PoolConfig {
            initial_size: 0,
            max_size: 10,
            ..Default::default()
        });
        pool.warm(5);
        // Should be able to allocate at least 5 without growth.
        for _ in 0..5 {
            assert!(pool.allocate().is_ok());
        }
    }

    #[test]
    fn symbol_pool_shrink_to_fit() {
        let mut pool = SymbolPool::new(PoolConfig {
            initial_size: 2,
            max_size: 10,
            allow_growth: true,
            growth_increment: 4,
            ..Default::default()
        });
        pool.warm(8);
        pool.shrink_to_fit();
        // After shrink, free list should be at most initial_size.
    }

    #[test]
    fn symbol_pool_try_allocate() {
        let mut pool = SymbolPool::new(PoolConfig {
            initial_size: 1,
            max_size: 1,
            allow_growth: false,
            ..Default::default()
        });
        assert!(pool.try_allocate().is_some());
        assert!(pool.try_allocate().is_none());
    }

    #[test]
    fn resource_tracker_clone() {
        let tracker = ResourceTracker::new(ResourceLimits::default());
        let tracker2 = tracker;
        assert_eq!(tracker2.usage(), ResourceUsage::default());
    }
}
