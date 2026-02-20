//! Multipath symbol aggregation infrastructure.
//!
//! This module provides symbol aggregation from multiple transport paths:
//! - `TransportPath`: Represents a single transport path with characteristics
//! - `PathSet`: Manages multiple paths to a destination
//! - `SymbolDeduplicator`: Filters duplicate symbols
//! - `SymbolReorderer`: Buffers and reorders symbols
//! - `MultipathAggregator`: Main aggregation orchestrator

use crate::error::{Error, ErrorKind};
use crate::types::Time;
use crate::types::symbol::{ObjectId, Symbol, SymbolId};
use parking_lot::RwLock;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

// ============================================================================
// Path Types
// ============================================================================

/// Unique identifier for a transport path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PathId(pub u64);

impl PathId {
    /// Creates a new path ID.
    #[must_use]
    pub const fn new(id: u64) -> Self {
        Self(id)
    }
}

impl std::fmt::Display for PathId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Path({})", self.0)
    }
}

/// State of a transport path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PathState {
    /// Path is active and healthy.
    Active = 0,

    /// Path is experiencing issues but still usable.
    Degraded = 1,

    /// Path is temporarily unavailable.
    Unavailable = 2,

    /// Path has been permanently closed.
    Closed = 3,
}

impl PathState {
    /// Returns true if the path can be used for receiving.
    #[must_use]
    pub const fn is_usable(&self) -> bool {
        matches!(self, Self::Active | Self::Degraded)
    }

    /// Converts from a raw `u8` value.
    fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Active,
            1 => Self::Degraded,
            2 => Self::Unavailable,
            _ => Self::Closed,
        }
    }
}

/// Characteristics of a transport path.
#[derive(Debug, Clone)]
pub struct PathCharacteristics {
    /// Estimated latency in milliseconds.
    pub latency_ms: u32,

    /// Estimated bandwidth in bytes per second.
    pub bandwidth_bps: u64,

    /// Estimated packet loss rate (0.0 - 1.0).
    pub loss_rate: f64,

    /// Path jitter in milliseconds.
    pub jitter_ms: u32,

    /// Whether this is a primary path.
    pub is_primary: bool,

    /// Path priority (lower = higher priority).
    pub priority: u32,
}

impl Default for PathCharacteristics {
    fn default() -> Self {
        Self {
            latency_ms: 50,
            bandwidth_bps: 1_000_000, // 1 Mbps
            loss_rate: 0.01,          // 1%
            jitter_ms: 10,
            is_primary: false,
            priority: 100,
        }
    }
}

impl PathCharacteristics {
    /// Creates characteristics for a high-quality path.
    #[must_use]
    pub fn high_quality() -> Self {
        Self {
            latency_ms: 10,
            bandwidth_bps: 10_000_000, // 10 Mbps
            loss_rate: 0.001,          // 0.1%
            jitter_ms: 2,
            is_primary: true,
            priority: 10,
        }
    }

    /// Creates characteristics for a backup path.
    #[must_use]
    pub fn backup() -> Self {
        Self {
            latency_ms: 100,
            bandwidth_bps: 500_000, // 500 Kbps
            loss_rate: 0.05,        // 5%
            jitter_ms: 30,
            is_primary: false,
            priority: 200,
        }
    }

    /// Calculates an overall quality score (higher = better).
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn quality_score(&self) -> f64 {
        let latency_score = 1000.0 / (f64::from(self.latency_ms) + 1.0);
        let bandwidth_score = (self.bandwidth_bps as f64).log10();
        let loss_score = 1.0 - self.loss_rate;
        let jitter_score = 100.0 / (f64::from(self.jitter_ms) + 1.0);

        // Weighted combination
        latency_score * 0.3 + bandwidth_score * 0.3 + loss_score * 0.3 + jitter_score * 0.1
    }
}

/// A transport path for symbol transmission.
#[derive(Debug)]
pub struct TransportPath {
    /// Unique identifier.
    pub id: PathId,

    /// Human-readable name.
    pub name: String,

    /// Current state (stored as `AtomicU8` for interior mutability through `Arc`).
    state: AtomicU8,

    /// Path characteristics.
    pub characteristics: PathCharacteristics,

    /// Remote endpoint address.
    pub remote_address: String,

    /// Symbols received on this path.
    pub symbols_received: AtomicU64,

    /// Symbols lost/dropped on this path.
    pub symbols_lost: AtomicU64,

    /// Duplicate symbols received on this path.
    pub duplicates_received: AtomicU64,

    /// Last activity time (nanoseconds, atomic for lock-free updates).
    pub last_activity: AtomicU64,

    /// Creation time.
    pub created_at: Time,
}

impl TransportPath {
    /// Creates a new transport path.
    #[must_use]
    pub fn new(id: PathId, name: impl Into<String>, remote: impl Into<String>) -> Self {
        Self {
            id,
            name: name.into(),
            state: AtomicU8::new(PathState::Active as u8),
            characteristics: PathCharacteristics::default(),
            remote_address: remote.into(),
            symbols_received: AtomicU64::new(0),
            symbols_lost: AtomicU64::new(0),
            duplicates_received: AtomicU64::new(0),
            last_activity: AtomicU64::new(0),
            created_at: Time::ZERO,
        }
    }

    /// Sets path characteristics.
    #[must_use]
    pub fn with_characteristics(mut self, chars: PathCharacteristics) -> Self {
        self.characteristics = chars;
        self
    }

    /// Returns the current path state.
    #[must_use]
    pub fn state(&self) -> PathState {
        PathState::from_u8(self.state.load(Ordering::Relaxed))
    }

    /// Updates the path state.
    pub fn set_state(&self, state: PathState) {
        self.state.store(state as u8, Ordering::Relaxed);
    }

    /// Records symbol receipt.
    pub fn record_receipt(&self, now: Time) {
        self.symbols_received.fetch_add(1, Ordering::Relaxed);
        self.last_activity.store(now.as_nanos(), Ordering::Relaxed);
    }

    /// Records a duplicate.
    pub fn record_duplicate(&self) {
        self.duplicates_received.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a loss.
    pub fn record_loss(&self) {
        self.symbols_lost.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns the effective loss rate.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn effective_loss_rate(&self) -> f64 {
        let received = self.symbols_received.load(Ordering::Relaxed);
        let lost = self.symbols_lost.load(Ordering::Relaxed);
        let total = received + lost;
        if total == 0 {
            0.0
        } else {
            lost as f64 / total as f64
        }
    }

    /// Returns the duplicate rate.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn duplicate_rate(&self) -> f64 {
        let received = self.symbols_received.load(Ordering::Relaxed);
        let duplicates = self.duplicates_received.load(Ordering::Relaxed);
        if received == 0 {
            0.0
        } else {
            duplicates as f64 / received as f64
        }
    }
}

// ============================================================================
// Path Set
// ============================================================================

/// Policy for path selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PathSelectionPolicy {
    /// Use all available paths.
    #[default]
    UseAll,

    /// Use only primary paths.
    PrimaryOnly,

    /// Use paths with best quality score.
    BestQuality {
        /// Number of paths to select.
        count: usize,
    },

    /// Use paths by priority.
    ByPriority {
        /// Number of paths to select.
        count: usize,
    },

    /// Round-robin across paths.
    RoundRobin,
}

/// Manages a set of paths to a destination.
#[derive(Debug)]
pub struct PathSet {
    /// All registered paths.
    paths: RwLock<HashMap<PathId, Arc<TransportPath>>>,

    /// Selection policy.
    policy: PathSelectionPolicy,

    /// Round-robin counter.
    rr_counter: AtomicU64,

    /// Next path ID.
    next_id: AtomicU64,
}

impl PathSet {
    /// Creates a new path set.
    #[must_use]
    pub fn new(policy: PathSelectionPolicy) -> Self {
        Self {
            paths: RwLock::new(HashMap::new()),
            policy,
            rr_counter: AtomicU64::new(0),
            next_id: AtomicU64::new(0),
        }
    }

    /// Registers a new path.
    pub fn register(&self, path: TransportPath) -> PathId {
        let id = path.id;
        let arc = Arc::new(path);
        self.paths.write().insert(id, arc);
        id
    }

    /// Creates and registers a new path.
    pub fn create_path(
        &self,
        name: impl Into<String>,
        remote: impl Into<String>,
        chars: PathCharacteristics,
    ) -> PathId {
        let id = PathId(self.next_id.fetch_add(1, Ordering::Relaxed));
        let path = TransportPath::new(id, name, remote).with_characteristics(chars);
        self.register(path)
    }

    /// Gets a path by ID.
    #[must_use]
    pub fn get(&self, id: PathId) -> Option<Arc<TransportPath>> {
        self.paths.read().get(&id).cloned()
    }

    /// Removes a path.
    pub fn remove(&self, id: PathId) -> Option<Arc<TransportPath>> {
        self.paths.write().remove(&id)
    }

    /// Returns all usable paths based on the selection policy.
    #[must_use]
    pub fn select_paths(&self) -> Vec<Arc<TransportPath>> {
        let usable: Vec<_> = {
            let paths = self.paths.read();
            paths
                .values()
                .filter(|p| p.state().is_usable())
                .cloned()
                .collect()
        };

        match self.policy {
            PathSelectionPolicy::UseAll => usable,

            PathSelectionPolicy::PrimaryOnly => usable
                .into_iter()
                .filter(|p| p.characteristics.is_primary)
                .collect(),

            PathSelectionPolicy::BestQuality { count } => {
                let mut sorted = usable;
                sorted.sort_by(|a, b| {
                    b.characteristics
                        .quality_score()
                        .partial_cmp(&a.characteristics.quality_score())
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
                sorted.into_iter().take(count).collect()
            }

            PathSelectionPolicy::ByPriority { count } => {
                let mut sorted = usable;
                sorted.sort_by_key(|p| p.characteristics.priority);
                sorted.into_iter().take(count).collect()
            }

            PathSelectionPolicy::RoundRobin => {
                if usable.is_empty() {
                    return vec![];
                }
                let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize;
                vec![usable[idx % usable.len()].clone()]
            }
        }
    }

    /// Updates path state.
    pub fn set_state(&self, id: PathId, state: PathState) -> bool {
        self.paths.read().get(&id).is_some_and(|path| {
            path.set_state(state);
            true
        })
    }

    /// Returns the number of paths.
    #[must_use]
    pub fn count(&self) -> usize {
        self.paths.read().len()
    }

    /// Returns the number of usable paths.
    #[must_use]
    pub fn usable_count(&self) -> usize {
        self.paths
            .read()
            .values()
            .filter(|p| p.state().is_usable())
            .count()
    }

    /// Returns aggregate statistics.
    #[must_use]
    pub fn stats(&self) -> PathSetStats {
        let paths = self.paths.read();

        let mut total_received = 0u64;
        let mut total_lost = 0u64;
        let mut total_duplicates = 0u64;
        let mut total_bandwidth = 0u64;

        for path in paths.values() {
            total_received += path.symbols_received.load(Ordering::Relaxed);
            total_lost += path.symbols_lost.load(Ordering::Relaxed);
            total_duplicates += path.duplicates_received.load(Ordering::Relaxed);
            if path.state().is_usable() {
                total_bandwidth += path.characteristics.bandwidth_bps;
            }
        }

        PathSetStats {
            path_count: paths.len(),
            usable_count: paths.values().filter(|p| p.state().is_usable()).count(),
            total_received,
            total_lost,
            total_duplicates,
            aggregate_bandwidth_bps: total_bandwidth,
        }
    }
}

/// Statistics for a path set.
#[derive(Debug, Clone)]
pub struct PathSetStats {
    /// Total number of paths.
    pub path_count: usize,
    /// Number of usable paths.
    pub usable_count: usize,
    /// Total symbols received.
    pub total_received: u64,
    /// Total symbols lost.
    pub total_lost: u64,
    /// Total duplicates received.
    pub total_duplicates: u64,
    /// Aggregate bandwidth of usable paths.
    pub aggregate_bandwidth_bps: u64,
}

// ============================================================================
// Symbol Deduplicator
// ============================================================================

/// Configuration for deduplication.
#[derive(Debug, Clone)]
pub struct DeduplicatorConfig {
    /// Maximum symbols to track per object.
    pub max_symbols_per_object: usize,

    /// Maximum objects to track.
    pub max_objects: usize,

    /// TTL for deduplication entries.
    pub entry_ttl: Time,

    /// Whether to track receive path.
    pub track_path: bool,
}

impl Default for DeduplicatorConfig {
    fn default() -> Self {
        Self {
            max_symbols_per_object: 10_000,
            max_objects: 1_000,
            entry_ttl: Time::from_secs(300),
            track_path: true,
        }
    }
}

/// Tracks seen symbols for deduplication.
#[derive(Debug)]
struct ObjectDeduplicationState {
    /// Symbols seen for this object.
    seen: HashSet<SymbolId>,

    /// When each symbol was first seen.
    first_seen: HashMap<SymbolId, Time>,

    /// Which path each symbol arrived on first.
    first_path: HashMap<SymbolId, PathId>,

    /// When this state was created.
    #[allow(dead_code)]
    created_at: Time,

    /// Last activity time.
    last_activity: Time,
}

impl ObjectDeduplicationState {
    fn new(created_at: Time) -> Self {
        Self {
            seen: HashSet::new(),
            first_seen: HashMap::new(),
            first_path: HashMap::new(),
            created_at,
            last_activity: created_at,
        }
    }
}

/// Filters duplicate symbols across multiple paths.
#[derive(Debug)]
pub struct SymbolDeduplicator {
    /// Per-object deduplication state.
    objects: RwLock<HashMap<ObjectId, ObjectDeduplicationState>>,

    /// Configuration.
    config: DeduplicatorConfig,

    /// Total duplicates detected.
    duplicates_detected: AtomicU64,

    /// Total unique symbols processed.
    unique_symbols: AtomicU64,
}

impl SymbolDeduplicator {
    /// Creates a new deduplicator.
    #[must_use]
    pub fn new(config: DeduplicatorConfig) -> Self {
        Self {
            objects: RwLock::new(HashMap::new()),
            config,
            duplicates_detected: AtomicU64::new(0),
            unique_symbols: AtomicU64::new(0),
        }
    }

    /// Checks if a symbol is a duplicate.
    ///
    /// Returns `true` if the symbol is new (not a duplicate).
    /// Returns `false` if the symbol has been seen before.
    pub fn check_and_record(&self, symbol: &Symbol, path: PathId, now: Time) -> bool {
        let object_id = symbol.object_id();
        let symbol_id = symbol.id();

        let mut objects = self.objects.write();

        // Enforce max_objects: if at capacity and this is a new object,
        // treat the symbol as unique but skip recording to bound memory.
        if !objects.contains_key(&object_id) && objects.len() >= self.config.max_objects {
            drop(objects);
            return true;
        }

        // Get or create object state
        let state = objects
            .entry(object_id)
            .or_insert_with(|| ObjectDeduplicationState::new(now));

        // Check if already seen
        if state.seen.contains(&symbol_id) {
            drop(objects);
            self.duplicates_detected.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // Enforce max_symbols_per_object: stop recording beyond the limit.
        if state.seen.len() >= self.config.max_symbols_per_object {
            drop(objects);
            return true;
        }

        // Record new symbol
        state.seen.insert(symbol_id);
        state.first_seen.insert(symbol_id, now);
        if self.config.track_path {
            state.first_path.insert(symbol_id, path);
        }
        state.last_activity = now;

        drop(objects);
        self.unique_symbols.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Returns the path that first delivered a symbol.
    #[must_use]
    pub fn first_path(&self, object_id: ObjectId, symbol_id: SymbolId) -> Option<PathId> {
        let objects = self.objects.read();
        objects
            .get(&object_id)
            .and_then(|state| state.first_path.get(&symbol_id).copied())
    }

    /// Prunes old entries.
    pub fn prune(&self, now: Time) -> usize {
        let mut objects = self.objects.write();
        let ttl_nanos = self.config.entry_ttl.as_nanos();

        let mut pruned = 0;
        objects.retain(|_, state| {
            let age = now
                .as_nanos()
                .saturating_sub(state.last_activity.as_nanos());
            let keep = age < ttl_nanos;
            if !keep {
                pruned += 1;
            }
            keep
        });

        pruned
    }

    /// Returns statistics.
    #[must_use]
    pub fn stats(&self) -> DeduplicatorStats {
        let objects = self.objects.read();
        let total_tracked: usize = objects.values().map(|s| s.seen.len()).sum();

        DeduplicatorStats {
            objects_tracked: objects.len(),
            symbols_tracked: total_tracked,
            duplicates_detected: self.duplicates_detected.load(Ordering::Relaxed),
            unique_symbols: self.unique_symbols.load(Ordering::Relaxed),
        }
    }

    /// Clears all state for an object (e.g., after decoding completes).
    pub fn clear_object(&self, object_id: ObjectId) {
        self.objects.write().remove(&object_id);
    }
}

/// Deduplicator statistics.
#[derive(Debug, Clone)]
pub struct DeduplicatorStats {
    /// Objects being tracked.
    pub objects_tracked: usize,
    /// Symbols being tracked.
    pub symbols_tracked: usize,
    /// Total duplicates detected.
    pub duplicates_detected: u64,
    /// Total unique symbols processed.
    pub unique_symbols: u64,
}

// ============================================================================
// Symbol Reorderer
// ============================================================================

/// Configuration for reordering.
#[derive(Debug, Clone)]
pub struct ReordererConfig {
    /// Maximum out-of-order symbols to buffer per object.
    pub max_buffer_per_object: usize,

    /// Maximum time to wait for out-of-order symbols.
    pub max_wait_time: Time,

    /// Whether to deliver immediately without waiting.
    pub immediate_delivery: bool,

    /// Maximum gap in sequence before giving up.
    pub max_sequence_gap: u32,
}

impl Default for ReordererConfig {
    fn default() -> Self {
        Self {
            max_buffer_per_object: 1_000,
            max_wait_time: Time::from_millis(100),
            immediate_delivery: false,
            max_sequence_gap: 100,
        }
    }
}

/// Buffered symbol waiting for delivery.
#[derive(Debug)]
struct BufferedSymbol {
    /// The symbol.
    symbol: Symbol,
    /// When it was received.
    received_at: Time,
    /// Path it was received on.
    path: PathId,
}

/// Per-object reordering state.
#[derive(Debug)]
struct ObjectReorderState {
    /// Next expected sequence number.
    next_expected: u32,

    /// Buffered out-of-order symbols (keyed by sequence).
    buffer: BTreeMap<u32, BufferedSymbol>,

    /// Last delivery time.
    #[allow(dead_code)]
    last_delivery: Time,
}

impl ObjectReorderState {
    fn new() -> Self {
        Self {
            next_expected: 0,
            buffer: BTreeMap::new(),
            last_delivery: Time::ZERO,
        }
    }
}

/// Buffers and reorders symbols to deliver in sequence.
#[derive(Debug)]
pub struct SymbolReorderer {
    /// Per-object reordering state.
    objects: RwLock<HashMap<ObjectId, ObjectReorderState>>,

    /// Configuration.
    config: ReordererConfig,

    /// Symbols delivered in order.
    in_order_deliveries: AtomicU64,

    /// Symbols delivered out of order (after buffering).
    reordered_deliveries: AtomicU64,

    /// Symbols that timed out waiting.
    timeout_deliveries: AtomicU64,
}

impl SymbolReorderer {
    /// Creates a new reorderer.
    #[must_use]
    pub fn new(config: ReordererConfig) -> Self {
        Self {
            objects: RwLock::new(HashMap::new()),
            config,
            in_order_deliveries: AtomicU64::new(0),
            reordered_deliveries: AtomicU64::new(0),
            timeout_deliveries: AtomicU64::new(0),
        }
    }

    /// Processes an incoming symbol.
    ///
    /// Returns symbols ready for delivery (may be empty, one, or multiple).
    pub fn process(&self, symbol: Symbol, path: PathId, now: Time) -> Vec<Symbol> {
        if self.config.immediate_delivery {
            return vec![symbol];
        }

        let object_id = symbol.object_id();
        let seq = symbol.esi();

        let mut objects = self.objects.write();
        let state = objects
            .entry(object_id)
            .or_insert_with(ObjectReorderState::new);

        let mut ready = Vec::with_capacity(1);

        // Check if this is the expected symbol
        if seq == state.next_expected {
            // Deliver immediately
            ready.push(symbol);
            state.next_expected += 1;
            state.last_delivery = now;
            self.in_order_deliveries.fetch_add(1, Ordering::Relaxed);

            // Check buffer for consecutive symbols
            while let Some(buffered) = state.buffer.remove(&state.next_expected) {
                ready.push(buffered.symbol);
                state.next_expected += 1;
                self.reordered_deliveries.fetch_add(1, Ordering::Relaxed);
            }
        } else if seq > state.next_expected {
            // Out of order - buffer it
            let gap = seq - state.next_expected;
            if gap <= self.config.max_sequence_gap
                && state.buffer.len() < self.config.max_buffer_per_object
            {
                state.buffer.insert(
                    seq,
                    BufferedSymbol {
                        symbol,
                        received_at: now,
                        path,
                    },
                );
            } else if gap > self.config.max_sequence_gap {
                // Gap too large: give up waiting on missing sequence and advance.
                // Deliver all buffered symbols (in sequence order) before resetting.
                for (_, buffered) in std::mem::take(&mut state.buffer) {
                    ready.push(buffered.symbol);
                    self.timeout_deliveries.fetch_add(1, Ordering::Relaxed);
                }
                state.next_expected = seq + 1;
                state.last_delivery = now;
                self.timeout_deliveries.fetch_add(1, Ordering::Relaxed);
                ready.push(symbol);
            }
            // else: buffer full, drop the symbol
        }
        // else: seq < next_expected - this is a late duplicate, ignore

        drop(objects);
        ready
    }

    /// Flushes timed-out symbols.
    ///
    /// Returns symbols that have waited too long.
    pub fn flush_timeouts(&self, now: Time) -> Vec<Symbol> {
        let mut objects = self.objects.write();
        let max_wait_nanos = self.config.max_wait_time.as_nanos();
        let mut flushed = Vec::with_capacity(4);

        for state in objects.values_mut() {
            // Find the highest sequence number that has timed out.
            // Any symbol with seq <= max_timeout_seq must be flushed to preserve order,
            // because we are about to advance next_expected past it.
            let mut max_timeout_seq = None;

            for (&seq, buffered) in &state.buffer {
                let wait_time = now
                    .as_nanos()
                    .saturating_sub(buffered.received_at.as_nanos());
                if wait_time >= max_wait_nanos {
                    max_timeout_seq = Some(seq);
                }
            }

            if let Some(cutoff) = max_timeout_seq {
                // Drain everything up to cutoff
                // BTreeMap::split_off returns keys >= argument.
                // We want to keep keys > cutoff, so we split at cutoff + 1.
                let keep = state.buffer.split_off(&(cutoff + 1));
                let to_flush = std::mem::replace(&mut state.buffer, keep);

                for (_, buffered) in to_flush {
                    flushed.push(buffered.symbol);
                    // We treat these as timeout deliveries because they are forced out
                    // by a timeout event (either their own or a later symbol's).
                    self.timeout_deliveries.fetch_add(1, Ordering::Relaxed);
                }

                if cutoff >= state.next_expected {
                    state.next_expected = cutoff + 1;
                }
            }

            // Drain any consecutive buffered symbols that are now deliverable.
            while let Some(buffered) = state.buffer.remove(&state.next_expected) {
                flushed.push(buffered.symbol);
                state.next_expected += 1;
                self.reordered_deliveries.fetch_add(1, Ordering::Relaxed);
            }
        }

        drop(objects);
        flushed
    }

    /// Returns statistics.
    #[must_use]
    pub fn stats(&self) -> ReordererStats {
        let objects = self.objects.read();
        let total_buffered: usize = objects.values().map(|s| s.buffer.len()).sum();

        ReordererStats {
            objects_tracked: objects.len(),
            symbols_buffered: total_buffered,
            in_order_deliveries: self.in_order_deliveries.load(Ordering::Relaxed),
            reordered_deliveries: self.reordered_deliveries.load(Ordering::Relaxed),
            timeout_deliveries: self.timeout_deliveries.load(Ordering::Relaxed),
        }
    }

    /// Clears state for an object.
    pub fn clear_object(&self, object_id: ObjectId) {
        self.objects.write().remove(&object_id);
    }
}

/// Reorderer statistics.
#[derive(Debug, Clone)]
pub struct ReordererStats {
    /// Objects being tracked.
    pub objects_tracked: usize,
    /// Symbols currently buffered.
    pub symbols_buffered: usize,
    /// Symbols delivered in order.
    pub in_order_deliveries: u64,
    /// Symbols delivered after reordering.
    pub reordered_deliveries: u64,
    /// Symbols delivered after timeout.
    pub timeout_deliveries: u64,
}

// ============================================================================
// Multipath Aggregator
// ============================================================================

/// Configuration for the aggregator.
#[derive(Debug, Clone)]
pub struct AggregatorConfig {
    /// Deduplicator configuration.
    pub dedup: DeduplicatorConfig,

    /// Reorderer configuration.
    pub reorder: ReordererConfig,

    /// Path selection policy.
    pub path_policy: PathSelectionPolicy,

    /// Whether to enable reordering.
    pub enable_reordering: bool,

    /// Flush interval for timeouts.
    pub flush_interval: Time,
}

impl Default for AggregatorConfig {
    fn default() -> Self {
        Self {
            dedup: DeduplicatorConfig::default(),
            reorder: ReordererConfig::default(),
            path_policy: PathSelectionPolicy::UseAll,
            enable_reordering: true,
            flush_interval: Time::from_millis(50),
        }
    }
}

/// Result of processing a symbol.
#[derive(Debug)]
pub struct ProcessResult {
    /// Symbols ready for delivery to decoder.
    pub ready: Vec<Symbol>,

    /// Whether the symbol was a duplicate.
    pub was_duplicate: bool,

    /// Path the symbol arrived on.
    pub path: PathId,
}

/// The main multipath aggregator.
#[derive(Debug)]
pub struct MultipathAggregator {
    /// Path set.
    paths: Arc<PathSet>,

    /// Deduplicator.
    dedup: SymbolDeduplicator,

    /// Reorderer.
    reorderer: SymbolReorderer,

    /// Configuration.
    config: AggregatorConfig,

    /// Total symbols processed.
    total_processed: AtomicU64,

    /// Last flush time (nanoseconds, atomic for lock-free check).
    last_flush: AtomicU64,
}

impl MultipathAggregator {
    /// Creates a new aggregator.
    #[must_use]
    pub fn new(config: AggregatorConfig) -> Self {
        let paths = Arc::new(PathSet::new(config.path_policy));

        Self {
            paths,
            dedup: SymbolDeduplicator::new(config.dedup.clone()),
            reorderer: SymbolReorderer::new(config.reorder.clone()),
            config,
            total_processed: AtomicU64::new(0),
            last_flush: AtomicU64::new(0),
        }
    }

    /// Returns the path set for configuration.
    #[must_use]
    pub fn paths(&self) -> &Arc<PathSet> {
        &self.paths
    }

    /// Processes an incoming symbol from a path.
    pub fn process(&self, symbol: Symbol, path: PathId, now: Time) -> ProcessResult {
        self.total_processed.fetch_add(1, Ordering::Relaxed);

        // Record path activity
        if let Some(p) = self.paths.get(path) {
            p.record_receipt(now);
        }

        // Check for duplicates
        let is_unique = self.dedup.check_and_record(&symbol, path, now);

        if !is_unique {
            // Duplicate - record and discard
            if let Some(p) = self.paths.get(path) {
                p.record_duplicate();
            }
            return ProcessResult {
                ready: vec![],
                was_duplicate: true,
                path,
            };
        }

        // Process through reorderer if enabled
        let ready = if self.config.enable_reordering {
            self.reorderer.process(symbol, path, now)
        } else {
            vec![symbol]
        };

        ProcessResult {
            ready,
            was_duplicate: false,
            path,
        }
    }

    /// Flushes any timed-out symbols.
    pub fn flush(&self, now: Time) -> Vec<Symbol> {
        // Check flush interval (lock-free CAS)
        let interval_nanos = self.config.flush_interval.as_nanos();
        loop {
            let last_nanos = self.last_flush.load(Ordering::Relaxed);
            if now.as_nanos().saturating_sub(last_nanos) < interval_nanos {
                return vec![];
            }
            if self
                .last_flush
                .compare_exchange_weak(
                    last_nanos,
                    now.as_nanos(),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                break;
            }
        }

        // Flush reorderer timeouts
        let flushed = self.reorderer.flush_timeouts(now);

        // Prune deduplicator
        self.dedup.prune(now);

        flushed
    }

    /// Notifies that an object has been fully decoded.
    ///
    /// Clears all state for the object.
    pub fn object_complete(&self, object_id: ObjectId) {
        self.dedup.clear_object(object_id);
        self.reorderer.clear_object(object_id);
    }

    /// Returns aggregate statistics.
    #[must_use]
    pub fn stats(&self) -> AggregatorStats {
        AggregatorStats {
            paths: self.paths.stats(),
            dedup: self.dedup.stats(),
            reorder: self.reorderer.stats(),
            total_processed: self.total_processed.load(Ordering::Relaxed),
        }
    }
}

/// Aggregator statistics.
#[derive(Debug, Clone)]
pub struct AggregatorStats {
    /// Path set statistics.
    pub paths: PathSetStats,
    /// Deduplicator statistics.
    pub dedup: DeduplicatorStats,
    /// Reorderer statistics.
    pub reorder: ReordererStats,
    /// Total symbols processed.
    pub total_processed: u64,
}

// ============================================================================
// Error Types
// ============================================================================

/// Errors from aggregation.
#[derive(Debug, Clone)]
pub enum AggregationError {
    /// Path not found.
    PathNotFound {
        /// The path ID.
        path: PathId,
    },

    /// Path is unavailable.
    PathUnavailable {
        /// The path ID.
        path: PathId,
    },

    /// Buffer overflow.
    BufferOverflow {
        /// The object ID.
        object_id: ObjectId,
    },

    /// Invalid symbol sequence.
    InvalidSequence {
        /// The object ID.
        object_id: ObjectId,
        /// Expected sequence number.
        expected: u32,
        /// Received sequence number.
        received: u32,
    },
}

impl std::fmt::Display for AggregationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PathNotFound { path } => write!(f, "path {path} not found"),
            Self::PathUnavailable { path } => write!(f, "path {path} unavailable"),
            Self::BufferOverflow { object_id } => {
                write!(f, "buffer overflow for object {object_id:?}")
            }
            Self::InvalidSequence {
                object_id,
                expected,
                received,
            } => {
                write!(
                    f,
                    "invalid sequence for object {object_id:?}: expected {expected}, got {received}"
                )
            }
        }
    }
}

impl std::error::Error for AggregationError {}

impl From<AggregationError> for Error {
    fn from(e: AggregationError) -> Self {
        Self::new(ErrorKind::StreamEnded).with_message(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_path(id: u64) -> TransportPath {
        TransportPath::new(
            PathId(id),
            format!("path-{id}"),
            format!("10.0.0.{id}:8080"),
        )
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    // Test 1: Path state predicates
    #[test]
    fn test_path_state() {
        init_test("test_path_state");
        let active = PathState::Active.is_usable();
        crate::assert_with_log!(active, "active usable", true, active);
        let degraded = PathState::Degraded.is_usable();
        crate::assert_with_log!(degraded, "degraded usable", true, degraded);
        let unavailable = PathState::Unavailable.is_usable();
        crate::assert_with_log!(!unavailable, "unavailable not usable", false, unavailable);
        let closed = PathState::Closed.is_usable();
        crate::assert_with_log!(!closed, "closed not usable", false, closed);
        crate::test_complete!("test_path_state");
    }

    // Test 2: Path characteristics quality score
    #[test]
    fn test_quality_score() {
        init_test("test_quality_score");
        let high = PathCharacteristics::high_quality();
        let backup = PathCharacteristics::backup();

        let high_score = high.quality_score();
        let backup_score = backup.quality_score();
        let higher = high_score > backup_score;
        crate::assert_with_log!(higher, "high > backup quality", true, higher);
        crate::test_complete!("test_quality_score");
    }

    // Test 3: Path statistics
    #[test]
    fn test_path_statistics() {
        init_test("test_path_statistics");
        let path = test_path(1);

        path.record_receipt(Time::from_secs(1));
        path.record_receipt(Time::from_secs(2));
        path.record_duplicate();
        path.record_loss();

        let received = path.symbols_received.load(Ordering::Relaxed);
        crate::assert_with_log!(received == 2, "symbols_received", 2, received);
        let duplicates = path.duplicates_received.load(Ordering::Relaxed);
        crate::assert_with_log!(duplicates == 1, "duplicates_received", 1, duplicates);
        let duplicate_rate = path.duplicate_rate();
        crate::assert_with_log!(
            duplicate_rate > 0.0,
            "duplicate_rate > 0",
            true,
            duplicate_rate > 0.0
        );
        let loss_rate = path.effective_loss_rate();
        crate::assert_with_log!(
            loss_rate > 0.0,
            "effective_loss_rate > 0",
            true,
            loss_rate > 0.0
        );
        crate::test_complete!("test_path_statistics");
    }

    // Test 4: PathSet selection - UseAll
    #[test]
    fn test_path_set_use_all() {
        init_test("test_path_set_use_all");
        let set = PathSet::new(PathSelectionPolicy::UseAll);

        set.register(test_path(1));
        set.register(test_path(2));
        set.register(test_path(3));

        let selected = set.select_paths();
        let len = selected.len();
        crate::assert_with_log!(len == 3, "selected len", 3, len);
        crate::test_complete!("test_path_set_use_all");
    }

    // Test 4.1: PathSet selection skips unusable paths
    #[test]
    fn test_path_set_skips_unusable() {
        init_test("test_path_set_skips_unusable");
        let set = PathSet::new(PathSelectionPolicy::UseAll);

        let down = test_path(1);
        down.set_state(PathState::Unavailable);
        let up = test_path(2);
        up.set_state(PathState::Active);

        set.register(down);
        set.register(up);

        let selected = set.select_paths();
        let len = selected.len();
        crate::assert_with_log!(len == 1, "selected len", 1, len);
        let id = selected[0].id;
        crate::assert_with_log!(id == PathId(2), "selected path id", PathId(2), id);
        crate::test_complete!("test_path_set_skips_unusable");
    }

    // Test 5: PathSet selection - BestQuality
    #[test]
    fn test_path_set_best_quality() {
        init_test("test_path_set_best_quality");
        let set = PathSet::new(PathSelectionPolicy::BestQuality { count: 2 });

        set.register(test_path(1).with_characteristics(PathCharacteristics::high_quality()));
        set.register(test_path(2).with_characteristics(PathCharacteristics::backup()));
        set.register(test_path(3).with_characteristics(PathCharacteristics::default()));

        let selected = set.select_paths();
        let len = selected.len();
        crate::assert_with_log!(len == 2, "selected len", 2, len);
        // First should be high quality
        let first_score = selected[0].characteristics.quality_score();
        let second_score = selected[1].characteristics.quality_score();
        let ordered = first_score > second_score;
        crate::assert_with_log!(ordered, "quality order", true, ordered);
        crate::test_complete!("test_path_set_best_quality");
    }

    // Test 5.1: PathSet selection - ByPriority
    #[test]
    fn test_path_set_by_priority() {
        init_test("test_path_set_by_priority");
        let set = PathSet::new(PathSelectionPolicy::ByPriority { count: 2 });

        set.register(test_path(1).with_characteristics(PathCharacteristics {
            priority: 50,
            ..Default::default()
        }));
        set.register(test_path(2).with_characteristics(PathCharacteristics {
            priority: 10,
            ..Default::default()
        }));
        set.register(test_path(3).with_characteristics(PathCharacteristics {
            priority: 30,
            ..Default::default()
        }));

        let selected = set.select_paths();
        let mut priorities: Vec<u32> = selected
            .iter()
            .map(|p| p.characteristics.priority)
            .collect();
        priorities.sort_unstable();
        crate::assert_with_log!(
            priorities == vec![10, 30],
            "priority selection",
            vec![10, 30],
            priorities
        );
        crate::test_complete!("test_path_set_by_priority");
    }

    // Test 6: Deduplicator basic operation
    #[test]
    fn test_deduplicator_basic() {
        init_test("test_deduplicator_basic");
        let dedup = SymbolDeduplicator::new(DeduplicatorConfig::default());

        let symbol = Symbol::new_for_test(1, 0, 0, &[1, 2, 3]);
        let path = PathId(1);
        let now = Time::ZERO;

        // First time - not duplicate
        let first = dedup.check_and_record(&symbol, path, now);
        crate::assert_with_log!(first, "first record", true, first);

        // Second time - duplicate
        let second = dedup.check_and_record(&symbol, path, now);
        crate::assert_with_log!(!second, "second duplicate", false, second);

        let stats = dedup.stats();
        crate::assert_with_log!(
            stats.unique_symbols == 1,
            "unique_symbols",
            1,
            stats.unique_symbols
        );
        crate::assert_with_log!(
            stats.duplicates_detected == 1,
            "duplicates_detected",
            1,
            stats.duplicates_detected
        );
        crate::test_complete!("test_deduplicator_basic");
    }

    // Test 7: Deduplicator tracks first path
    #[test]
    fn test_deduplicator_tracks_path() {
        init_test("test_deduplicator_tracks_path");
        let config = DeduplicatorConfig {
            track_path: true,
            ..Default::default()
        };
        let dedup = SymbolDeduplicator::new(config);

        let symbol = Symbol::new_for_test(1, 0, 0, &[1, 2, 3]);
        let path1 = PathId(1);
        let path2 = PathId(2);

        dedup.check_and_record(&symbol, path1, Time::ZERO);
        dedup.check_and_record(&symbol, path2, Time::ZERO); // Duplicate

        let first = dedup.first_path(symbol.object_id(), symbol.id());
        crate::assert_with_log!(first == Some(path1), "first path", Some(path1), first);
        crate::test_complete!("test_deduplicator_tracks_path");
    }

    // Test 8: Reorderer in-order delivery
    #[test]
    fn test_reorderer_in_order() {
        init_test("test_reorderer_in_order");
        let config = ReordererConfig {
            immediate_delivery: false,
            ..Default::default()
        };
        let reorderer = SymbolReorderer::new(config);

        let path = PathId(1);
        let now = Time::ZERO;

        // Deliver symbols in order
        let s0 = Symbol::new_for_test(1, 0, 0, &[0]);
        let s1 = Symbol::new_for_test(1, 0, 1, &[1]);
        let s2 = Symbol::new_for_test(1, 0, 2, &[2]);

        let ready0 = reorderer.process(s0, path, now);
        let ready1 = reorderer.process(s1, path, now);
        let ready2 = reorderer.process(s2, path, now);

        let len0 = ready0.len();
        crate::assert_with_log!(len0 == 1, "ready0 len", 1, len0);
        let len1 = ready1.len();
        crate::assert_with_log!(len1 == 1, "ready1 len", 1, len1);
        let len2 = ready2.len();
        crate::assert_with_log!(len2 == 1, "ready2 len", 1, len2);

        let stats = reorderer.stats();
        crate::assert_with_log!(
            stats.in_order_deliveries == 3,
            "in_order_deliveries",
            3,
            stats.in_order_deliveries
        );
        crate::assert_with_log!(
            stats.reordered_deliveries == 0,
            "reordered_deliveries",
            0,
            stats.reordered_deliveries
        );
        crate::test_complete!("test_reorderer_in_order");
    }

    // Test 9: Reorderer out-of-order buffering
    #[test]
    fn test_reorderer_out_of_order() {
        init_test("test_reorderer_out_of_order");
        let config = ReordererConfig {
            immediate_delivery: false,
            ..Default::default()
        };
        let reorderer = SymbolReorderer::new(config);

        let path = PathId(1);
        let now = Time::ZERO;

        // Deliver out of order: 0, 2, 1
        let s0 = Symbol::new_for_test(1, 0, 0, &[0]);
        let s2 = Symbol::new_for_test(1, 0, 2, &[2]);
        let s1 = Symbol::new_for_test(1, 0, 1, &[1]);

        let ready0 = reorderer.process(s0, path, now);
        let len0 = ready0.len();
        crate::assert_with_log!(len0 == 1, "ready0 len", 1, len0); // s0 delivered

        let ready2 = reorderer.process(s2, path, now);
        let len2 = ready2.len();
        crate::assert_with_log!(len2 == 0, "ready2 len", 0, len2); // s2 buffered, waiting for s1

        let ready1 = reorderer.process(s1, path, now);
        let len1 = ready1.len();
        crate::assert_with_log!(len1 == 2, "ready1 len", 2, len1); // s1 and s2 delivered

        let stats = reorderer.stats();
        crate::assert_with_log!(
            stats.in_order_deliveries == 2,
            "in_order_deliveries",
            2,
            stats.in_order_deliveries
        );
        crate::assert_with_log!(
            stats.reordered_deliveries == 1,
            "reordered_deliveries",
            1,
            stats.reordered_deliveries
        );
        crate::test_complete!("test_reorderer_out_of_order");
    }

    // Test 10: Reorderer timeout flush
    #[test]
    fn test_reorderer_timeout() {
        init_test("test_reorderer_timeout");
        let config = ReordererConfig {
            immediate_delivery: false,
            max_wait_time: Time::from_millis(100),
            ..Default::default()
        };
        let reorderer = SymbolReorderer::new(config);

        let path = PathId(1);

        // Deliver out of order: 0, 2 (skip 1)
        let s0 = Symbol::new_for_test(1, 0, 0, &[0]);
        let s2 = Symbol::new_for_test(1, 0, 2, &[2]);

        reorderer.process(s0, path, Time::ZERO);
        reorderer.process(s2, path, Time::from_millis(10));

        // Before timeout
        let flushed = reorderer.flush_timeouts(Time::from_millis(50));
        let len_before = flushed.len();
        crate::assert_with_log!(len_before == 0, "flushed before len", 0, len_before);

        // After timeout
        let flushed = reorderer.flush_timeouts(Time::from_millis(200));
        let len_after = flushed.len();
        crate::assert_with_log!(len_after == 1, "flushed after len", 1, len_after); // s2 flushed
        crate::test_complete!("test_reorderer_timeout");
    }

    // Test 10.1: Reorderer gap too large gives up and advances
    #[test]
    fn test_reorderer_gap_too_large_advances() {
        init_test("test_reorderer_gap_too_large_advances");
        let config = ReordererConfig {
            immediate_delivery: false,
            max_sequence_gap: 2,
            ..Default::default()
        };
        let reorderer = SymbolReorderer::new(config);

        let path = PathId(1);
        let now = Time::ZERO;

        let s0 = Symbol::new_for_test(1, 0, 0, &[0]);
        let s5 = Symbol::new_for_test(1, 0, 5, &[5]);
        let s6 = Symbol::new_for_test(1, 0, 6, &[6]);

        let out0 = reorderer.process(s0, path, now);
        crate::assert_with_log!(out0.len() == 1, "out0 len", 1, out0.len());

        // Gap 4 > max_sequence_gap => deliver immediately and advance
        let out5 = reorderer.process(s5, path, now);
        crate::assert_with_log!(out5.len() == 1, "out5 len", 1, out5.len());

        let out6 = reorderer.process(s6, path, now);
        crate::assert_with_log!(out6.len() == 1, "out6 len", 1, out6.len());

        crate::test_complete!("test_reorderer_gap_too_large_advances");
    }

    // Test 11: MultipathAggregator basic flow
    #[test]
    fn test_aggregator_basic() {
        init_test("test_aggregator_basic");
        let config = AggregatorConfig::default();
        let aggregator = MultipathAggregator::new(config);

        let path = aggregator.paths().create_path(
            "test",
            "localhost:8080",
            PathCharacteristics::default(),
        );

        let symbol = Symbol::new_for_test(1, 0, 0, &[1, 2, 3]);

        let result = aggregator.process(symbol.clone(), path, Time::ZERO);
        crate::assert_with_log!(
            !result.was_duplicate,
            "first not duplicate",
            false,
            result.was_duplicate
        );

        // Duplicate
        let result2 = aggregator.process(symbol, path, Time::ZERO);
        crate::assert_with_log!(
            result2.was_duplicate,
            "duplicate flagged",
            true,
            result2.was_duplicate
        );
        let ready_empty = result2.ready.is_empty();
        crate::assert_with_log!(ready_empty, "ready empty", true, ready_empty);
        crate::test_complete!("test_aggregator_basic");
    }

    // Test 11.1: MultipathAggregator deduplicates across paths
    #[test]
    fn test_aggregator_multi_path_dedup() {
        init_test("test_aggregator_multi_path_dedup");
        let config = AggregatorConfig::default();
        let aggregator = MultipathAggregator::new(config);

        let p1 =
            aggregator
                .paths()
                .create_path("p1", "localhost:1", PathCharacteristics::default());
        let p2 = aggregator
            .paths()
            .create_path("p2", "localhost:2", PathCharacteristics::backup());

        let symbol = Symbol::new_for_test(1, 0, 0, &[1, 2, 3]);

        let first = aggregator.process(symbol.clone(), p1, Time::ZERO);
        crate::assert_with_log!(
            !first.was_duplicate,
            "first unique",
            false,
            first.was_duplicate
        );

        let second = aggregator.process(symbol, p2, Time::ZERO);
        crate::assert_with_log!(
            second.was_duplicate,
            "duplicate across paths",
            true,
            second.was_duplicate
        );

        let stats = aggregator.dedup.stats();
        crate::assert_with_log!(
            stats.unique_symbols == 1,
            "unique symbols",
            1,
            stats.unique_symbols
        );
        crate::assert_with_log!(
            stats.duplicates_detected == 1,
            "duplicates detected",
            1,
            stats.duplicates_detected
        );

        let path = aggregator.paths().get(p2);
        crate::assert_with_log!(path.is_some(), "path exists", true, path.is_some());
        if let Some(path) = path {
            let duplicates = path.duplicates_received.load(Ordering::Relaxed);
            crate::assert_with_log!(duplicates == 1, "path duplicates", 1, duplicates);
        }

        crate::test_complete!("test_aggregator_multi_path_dedup");
    }

    // Test 12: MultipathAggregator object completion
    #[test]
    fn test_aggregator_object_complete() {
        init_test("test_aggregator_object_complete");
        let config = AggregatorConfig::default();
        let aggregator = MultipathAggregator::new(config);

        let path = aggregator.paths().create_path(
            "test",
            "localhost:8080",
            PathCharacteristics::default(),
        );

        let symbol = Symbol::new_for_test(1, 0, 0, &[1, 2, 3]);
        let object_id = symbol.object_id();

        aggregator.process(symbol.clone(), path, Time::ZERO);

        // Clear state
        aggregator.object_complete(object_id);

        // Same symbol is now "new" again
        let result = aggregator.process(symbol, path, Time::ZERO);
        crate::assert_with_log!(
            !result.was_duplicate,
            "post-complete not duplicate",
            false,
            result.was_duplicate
        );
        crate::test_complete!("test_aggregator_object_complete");
    }

    // Test 13: PathSet aggregate stats
    #[test]
    fn test_path_set_stats() {
        init_test("test_path_set_stats");
        let set = PathSet::new(PathSelectionPolicy::UseAll);

        let p1 = set.create_path(
            "p1",
            "a",
            PathCharacteristics {
                bandwidth_bps: 1_000_000,
                ..Default::default()
            },
        );
        let p2 = set.create_path(
            "p2",
            "b",
            PathCharacteristics {
                bandwidth_bps: 2_000_000,
                ..Default::default()
            },
        );

        if let Some(path) = set.get(p1) {
            path.symbols_received.store(100, Ordering::Relaxed);
        }
        if let Some(path) = set.get(p2) {
            path.symbols_received.store(200, Ordering::Relaxed);
        }

        let stats = set.stats();
        crate::assert_with_log!(stats.path_count == 2, "path_count", 2, stats.path_count);
        crate::assert_with_log!(
            stats.total_received == 300,
            "total_received",
            300,
            stats.total_received
        );
        crate::assert_with_log!(
            stats.aggregate_bandwidth_bps == 3_000_000,
            "aggregate_bandwidth_bps",
            3_000_000,
            stats.aggregate_bandwidth_bps
        );
        crate::test_complete!("test_path_set_stats");
    }

    // Test 14: Immediate delivery mode
    #[test]
    fn test_immediate_delivery() {
        init_test("test_immediate_delivery");
        let config = ReordererConfig {
            immediate_delivery: true,
            ..Default::default()
        };
        let reorderer = SymbolReorderer::new(config);

        // Out of order should still deliver immediately
        let s5 = Symbol::new_for_test(1, 0, 5, &[5]);
        let ready = reorderer.process(s5, PathId(1), Time::ZERO);

        let len = ready.len();
        crate::assert_with_log!(len == 1, "ready len", 1, len);
        crate::test_complete!("test_immediate_delivery");
    }

    // Test 15: Aggregator stats
    #[test]
    fn test_aggregator_stats() {
        init_test("test_aggregator_stats");
        let config = AggregatorConfig::default();
        let aggregator = MultipathAggregator::new(config);

        let path = aggregator.paths().create_path(
            "test",
            "localhost:8080",
            PathCharacteristics::default(),
        );

        for i in 0..10 {
            let symbol = Symbol::new_for_test(1, 0, i, &[i as u8]);
            aggregator.process(symbol, path, Time::ZERO);
        }

        let stats = aggregator.stats();
        crate::assert_with_log!(
            stats.total_processed == 10,
            "total_processed",
            10,
            stats.total_processed
        );
        crate::assert_with_log!(
            stats.paths.path_count == 1,
            "path_count",
            1,
            stats.paths.path_count
        );
        crate::test_complete!("test_aggregator_stats");
    }

    // ========================================================================
    // Audit regression tests
    // ========================================================================

    #[test]
    fn flush_respects_interval_gating() {
        init_test("flush_respects_interval_gating");
        let config = AggregatorConfig {
            flush_interval: Time::from_millis(100),
            ..Default::default()
        };
        let aggregator = MultipathAggregator::new(config);
        let path = aggregator.paths().create_path(
            "test",
            "localhost:8080",
            PathCharacteristics::default(),
        );

        // Process a symbol with out-of-order ESI to put something in the reorderer buffer
        let s2 = Symbol::new_for_test(1, 0, 2, &[2]);
        aggregator.process(s2, path, Time::ZERO);

        // Flush too soon — should return empty
        let early = aggregator.flush(Time::from_millis(50));
        crate::assert_with_log!(
            early.is_empty(),
            "flush before interval returns empty",
            true,
            early.is_empty()
        );

        // Flush after interval — should succeed
        let later = aggregator.flush(Time::from_millis(200));
        // Symbol 2 was buffered waiting for 0,1 — if max_wait_time passed, it should flush
        // (default max_wait_time is 100ms, and symbol was received at t=0, flush at t=200)
        crate::assert_with_log!(
            later.len() == 1,
            "flush after interval returns buffered symbol",
            1,
            later.len()
        );

        crate::test_complete!("flush_respects_interval_gating");
    }

    #[test]
    fn dedup_prune_removes_expired_objects() {
        init_test("dedup_prune_removes_expired_objects");
        let config = DeduplicatorConfig {
            entry_ttl: Time::from_secs(10),
            ..Default::default()
        };
        let dedup = SymbolDeduplicator::new(config);
        let path = PathId(1);

        // Record a symbol at t=0
        let s = Symbol::new_for_test(1, 0, 0, &[1]);
        dedup.check_and_record(&s, path, Time::ZERO);

        let before = dedup.stats();
        crate::assert_with_log!(
            before.objects_tracked == 1,
            "1 object tracked before prune",
            1,
            before.objects_tracked
        );

        // Prune at t=5 (within TTL) — should keep
        let pruned_early = dedup.prune(Time::from_secs(5));
        crate::assert_with_log!(pruned_early == 0, "nothing pruned early", 0, pruned_early);

        // Prune at t=15 (past TTL) — should remove
        let pruned_late = dedup.prune(Time::from_secs(15));
        crate::assert_with_log!(pruned_late == 1, "1 object pruned", 1, pruned_late);

        let after = dedup.stats();
        crate::assert_with_log!(
            after.objects_tracked == 0,
            "0 objects after prune",
            0,
            after.objects_tracked
        );

        crate::test_complete!("dedup_prune_removes_expired_objects");
    }

    #[test]
    fn reorderer_late_duplicate_ignored() {
        init_test("reorderer_late_duplicate_ignored");
        let config = ReordererConfig {
            immediate_delivery: false,
            ..Default::default()
        };
        let reorderer = SymbolReorderer::new(config);
        let path = PathId(1);
        let now = Time::ZERO;

        // Deliver 0, 1, 2 in order
        reorderer.process(Symbol::new_for_test(1, 0, 0, &[0]), path, now);
        reorderer.process(Symbol::new_for_test(1, 0, 1, &[1]), path, now);
        reorderer.process(Symbol::new_for_test(1, 0, 2, &[2]), path, now);

        // Late duplicate: seq 0 again
        let late = reorderer.process(Symbol::new_for_test(1, 0, 0, &[0]), path, now);
        crate::assert_with_log!(
            late.is_empty(),
            "late duplicate produces no output",
            true,
            late.is_empty()
        );

        let stats = reorderer.stats();
        crate::assert_with_log!(
            stats.in_order_deliveries == 3,
            "still 3 in-order deliveries",
            3,
            stats.in_order_deliveries
        );

        crate::test_complete!("reorderer_late_duplicate_ignored");
    }

    #[test]
    fn path_set_round_robin_cycles() {
        init_test("path_set_round_robin_cycles");
        let set = PathSet::new(PathSelectionPolicy::RoundRobin);

        set.register(test_path(1));
        set.register(test_path(2));

        // RoundRobin should select one path per call, cycling through
        let mut ids = Vec::new();
        for _ in 0..4 {
            let selected = set.select_paths();
            crate::assert_with_log!(
                selected.len() == 1,
                "round robin selects 1",
                1,
                selected.len()
            );
            ids.push(selected[0].id);
        }

        // Should see both paths represented (2 paths, 4 calls)
        let unique_ids: HashSet<PathId> = ids.iter().copied().collect();
        crate::assert_with_log!(
            unique_ids.len() == 2,
            "round robin covers both paths",
            2,
            unique_ids.len()
        );

        crate::test_complete!("path_set_round_robin_cycles");
    }

    #[test]
    fn path_set_remove_path() {
        init_test("path_set_remove_path");
        let set = PathSet::new(PathSelectionPolicy::UseAll);

        let id = set.register(test_path(1));
        set.register(test_path(2));

        crate::assert_with_log!(set.count() == 2, "2 paths", 2, set.count());

        let removed = set.remove(id);
        crate::assert_with_log!(removed.is_some(), "removed path", true, removed.is_some());
        crate::assert_with_log!(set.count() == 1, "1 path after remove", 1, set.count());

        // Remove again — should return None
        let removed_again = set.remove(id);
        crate::assert_with_log!(
            removed_again.is_none(),
            "double remove returns None",
            true,
            removed_again.is_none()
        );

        crate::test_complete!("path_set_remove_path");
    }

    #[test]
    fn aggregation_error_display_variants() {
        init_test("aggregation_error_display_variants");

        let e1 = AggregationError::PathNotFound { path: PathId(42) };
        crate::assert_with_log!(
            e1.to_string().contains("42"),
            "path not found contains id",
            true,
            e1.to_string().contains("42")
        );

        let e2 = AggregationError::PathUnavailable { path: PathId(7) };
        crate::assert_with_log!(
            e2.to_string().contains("unavailable"),
            "path unavailable display",
            true,
            e2.to_string().contains("unavailable")
        );

        let e3 = AggregationError::InvalidSequence {
            object_id: ObjectId::new(0, 1),
            expected: 5,
            received: 10,
        };
        let msg = e3.to_string();
        crate::assert_with_log!(
            msg.contains("expected 5") && msg.contains("got 10"),
            "invalid sequence display",
            true,
            msg.contains("expected 5") && msg.contains("got 10")
        );

        crate::test_complete!("aggregation_error_display_variants");
    }

    // ========================================================================
    // Bug-fix regression tests
    // ========================================================================

    /// Regression: large gap reset must drain buffered symbols, not drop them.
    #[test]
    fn reorderer_large_gap_delivers_buffered_before_reset() {
        init_test("reorderer_large_gap_delivers_buffered_before_reset");
        let config = ReordererConfig {
            immediate_delivery: false,
            max_sequence_gap: 3,
            ..Default::default()
        };
        let reorderer = SymbolReorderer::new(config);
        let path = PathId(1);
        let now = Time::ZERO;

        // Deliver seq 0 in-order.
        let s0 = Symbol::new_for_test(1, 0, 0, &[0]);
        let out0 = reorderer.process(s0, path, now);
        crate::assert_with_log!(out0.len() == 1, "s0 delivered", 1, out0.len());

        // Buffer seq 2 and 3 (out-of-order, waiting for seq 1).
        let s2 = Symbol::new_for_test(1, 0, 2, &[2]);
        let s3 = Symbol::new_for_test(1, 0, 3, &[3]);
        let out2 = reorderer.process(s2, path, now);
        let out3 = reorderer.process(s3, path, now);
        crate::assert_with_log!(out2.is_empty(), "s2 buffered", 0, out2.len());
        crate::assert_with_log!(out3.is_empty(), "s3 buffered", 0, out3.len());

        // Now deliver seq 100 — gap is 99 > max_sequence_gap(3).
        // Buffered symbols 2 and 3 must be delivered, not dropped.
        let s100 = Symbol::new_for_test(1, 0, 100, &[100]);
        let out100 = reorderer.process(s100, path, now);
        crate::assert_with_log!(
            out100.len() == 3,
            "large gap delivers buffered + new",
            3,
            out100.len()
        );

        crate::test_complete!("reorderer_large_gap_delivers_buffered_before_reset");
    }

    /// Regression: dedup must enforce max_objects limit.
    #[test]
    fn dedup_enforces_max_objects() {
        init_test("dedup_enforces_max_objects");
        let config = DeduplicatorConfig {
            max_objects: 2,
            ..Default::default()
        };
        let dedup = SymbolDeduplicator::new(config);
        let path = PathId(1);

        // Record symbols for 2 different objects — both should be tracked.
        let s1 = Symbol::new_for_test(1, 0, 0, &[1]);
        let s2 = Symbol::new_for_test(2, 0, 0, &[2]);
        crate::assert_with_log!(
            dedup.check_and_record(&s1, path, Time::ZERO),
            "obj1 unique",
            true,
            true
        );
        crate::assert_with_log!(
            dedup.check_and_record(&s2, path, Time::ZERO),
            "obj2 unique",
            true,
            true
        );

        // Third object exceeds max_objects — should still return true (unique)
        // but NOT be tracked (so a duplicate won't be detected).
        let s3 = Symbol::new_for_test(3, 0, 0, &[3]);
        let result = dedup.check_and_record(&s3, path, Time::ZERO);
        crate::assert_with_log!(result, "obj3 treated as unique", true, result);

        let stats = dedup.stats();
        crate::assert_with_log!(
            stats.objects_tracked == 2,
            "only 2 objects tracked",
            2,
            stats.objects_tracked
        );

        crate::test_complete!("dedup_enforces_max_objects");
    }

    /// Regression: dedup must enforce max_symbols_per_object limit.
    #[test]
    fn dedup_enforces_max_symbols_per_object() {
        init_test("dedup_enforces_max_symbols_per_object");
        let config = DeduplicatorConfig {
            max_symbols_per_object: 3,
            ..Default::default()
        };
        let dedup = SymbolDeduplicator::new(config);
        let path = PathId(1);

        // Record 3 symbols for object 1 — all should be tracked.
        for i in 0..3 {
            let s = Symbol::new_for_test(1, 0, i, &[i as u8]);
            let unique = dedup.check_and_record(&s, path, Time::ZERO);
            crate::assert_with_log!(unique, "symbol unique", true, unique);
        }

        // 4th symbol for same object exceeds limit — treated as unique
        // but not recorded.
        let s4 = Symbol::new_for_test(1, 0, 3, &[3]);
        let result = dedup.check_and_record(&s4, path, Time::ZERO);
        crate::assert_with_log!(result, "over-limit symbol treated as unique", true, result);

        let stats = dedup.stats();
        crate::assert_with_log!(
            stats.symbols_tracked == 3,
            "only 3 symbols tracked",
            3,
            stats.symbols_tracked
        );

        crate::test_complete!("dedup_enforces_max_symbols_per_object");
    }

    /// Flush timeout advances next_expected and drains consecutive.
    #[test]
    fn flush_timeout_drains_consecutive_after_advance() {
        init_test("flush_timeout_drains_consecutive_after_advance");
        let config = ReordererConfig {
            immediate_delivery: false,
            max_wait_time: Time::from_millis(50),
            ..Default::default()
        };
        let reorderer = SymbolReorderer::new(config);
        let path = PathId(1);

        // Deliver seq 0.
        reorderer.process(Symbol::new_for_test(1, 0, 0, &[0]), path, Time::ZERO);

        // Buffer seq 2 at t=0 (will time out at t=50).
        reorderer.process(Symbol::new_for_test(1, 0, 2, &[2]), path, Time::ZERO);

        // Buffer seq 3 at t=40 (will time out at t=90).
        reorderer.process(
            Symbol::new_for_test(1, 0, 3, &[3]),
            path,
            Time::from_millis(40),
        );

        // Flush at t=60: seq 2 timed out (waited 60ms > 50ms).
        // Seq 3 has NOT timed out (waited 20ms < 50ms).
        // After flushing seq 2, next_expected advances to 3,
        // and the consecutive drain pops seq 3 from the buffer.
        let flushed = reorderer.flush_timeouts(Time::from_millis(60));
        crate::assert_with_log!(
            flushed.len() == 2,
            "seq 2 flushed + seq 3 drained",
            2,
            flushed.len()
        );

        let stats = reorderer.stats();
        crate::assert_with_log!(
            stats.symbols_buffered == 0,
            "buffer empty after drain",
            0,
            stats.symbols_buffered
        );

        crate::test_complete!("flush_timeout_drains_consecutive_after_advance");
    }

    // =========================================================================
    // Wave 29: Data-type trait coverage
    // =========================================================================

    #[test]
    fn path_id_debug_clone_copy_display() {
        let id = PathId::new(42);
        assert!(format!("{id:?}").contains("42"));
        assert_eq!(format!("{id}"), "Path(42)");
        let cloned = id;
        let copied = id; // Copy
        assert_eq!(cloned, copied);
        assert_eq!(id.0, 42);
    }

    #[test]
    fn path_id_ord_hash() {
        use std::collections::HashSet;
        let a = PathId(1);
        let b = PathId(2);
        assert!(a < b);
        assert!(b > a);
        let mut set = HashSet::new();
        set.insert(a);
        set.insert(b);
        set.insert(a); // duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn path_state_debug_clone_copy_eq() {
        let state = PathState::Active;
        assert!(format!("{state:?}").contains("Active"));
        let cloned = state;
        let copied = state; // Copy
        assert_eq!(cloned, copied);
        assert_ne!(PathState::Active, PathState::Closed);
    }

    #[test]
    fn path_state_from_u8_all_variants() {
        assert_eq!(PathState::from_u8(0), PathState::Active);
        assert_eq!(PathState::from_u8(1), PathState::Degraded);
        assert_eq!(PathState::from_u8(2), PathState::Unavailable);
        assert_eq!(PathState::from_u8(3), PathState::Closed);
        assert_eq!(PathState::from_u8(255), PathState::Closed); // fallback
    }

    #[test]
    fn path_characteristics_debug_clone_default() {
        let chars = PathCharacteristics::default();
        assert!(format!("{chars:?}").contains("PathCharacteristics"));
        assert_eq!(chars.latency_ms, 50);
        assert_eq!(chars.bandwidth_bps, 1_000_000);
        assert!((chars.loss_rate - 0.01).abs() < f64::EPSILON);
        assert_eq!(chars.jitter_ms, 10);
        assert!(!chars.is_primary);
        assert_eq!(chars.priority, 100);
        let _cloned = chars;
    }

    #[test]
    fn path_selection_policy_debug_clone_copy_default() {
        let policy = PathSelectionPolicy::default();
        assert_eq!(policy, PathSelectionPolicy::UseAll);
        assert!(format!("{policy:?}").contains("UseAll"));
        let cloned = policy;
        let copied = policy; // Copy
        assert_eq!(cloned, copied);
    }

    #[test]
    fn path_set_stats_debug_clone() {
        let stats = PathSetStats {
            path_count: 3,
            usable_count: 2,
            total_received: 100,
            total_lost: 5,
            total_duplicates: 10,
            aggregate_bandwidth_bps: 5_000_000,
        };
        assert!(format!("{stats:?}").contains("PathSetStats"));
        let stats2 = stats;
        assert_eq!(stats2.path_count, 3);
        assert_eq!(stats2.total_received, 100);
    }

    #[test]
    fn deduplicator_config_debug_clone_default() {
        let config = DeduplicatorConfig::default();
        assert!(format!("{config:?}").contains("DeduplicatorConfig"));
        assert_eq!(config.max_symbols_per_object, 10_000);
        assert_eq!(config.max_objects, 1_000);
        assert!(config.track_path);
        let _cloned = config;
    }

    #[test]
    fn deduplicator_stats_debug_clone() {
        let stats = DeduplicatorStats {
            objects_tracked: 5,
            symbols_tracked: 50,
            duplicates_detected: 3,
            unique_symbols: 47,
        };
        assert!(format!("{stats:?}").contains("DeduplicatorStats"));
        let stats2 = stats;
        assert_eq!(stats2.objects_tracked, 5);
    }

    #[test]
    fn reorderer_config_debug_clone_default() {
        let config = ReordererConfig::default();
        assert!(format!("{config:?}").contains("ReordererConfig"));
        assert_eq!(config.max_buffer_per_object, 1_000);
        assert!(!config.immediate_delivery);
        assert_eq!(config.max_sequence_gap, 100);
        let _cloned = config;
    }

    #[test]
    fn reorderer_stats_debug_clone() {
        let stats = ReordererStats {
            objects_tracked: 2,
            symbols_buffered: 10,
            in_order_deliveries: 50,
            reordered_deliveries: 5,
            timeout_deliveries: 1,
        };
        assert!(format!("{stats:?}").contains("ReordererStats"));
        let stats2 = stats;
        assert_eq!(stats2.symbols_buffered, 10);
    }

    #[test]
    fn aggregator_config_debug_clone_default() {
        let config = AggregatorConfig::default();
        assert!(format!("{config:?}").contains("AggregatorConfig"));
        assert!(config.enable_reordering);
        assert_eq!(config.path_policy, PathSelectionPolicy::UseAll);
        let _cloned = config;
    }

    #[test]
    fn aggregation_error_debug_clone() {
        let err = AggregationError::PathNotFound { path: PathId(1) };
        assert!(format!("{err:?}").contains("PathNotFound"));
        let cloned = err;
        assert!(format!("{cloned}").contains("not found"));
    }

    #[test]
    fn aggregation_error_is_std_error() {
        let err: &dyn std::error::Error = &AggregationError::PathUnavailable { path: PathId(1) };
        let _ = format!("{err}");
        assert!(err.source().is_none());
    }

    #[test]
    fn aggregation_error_into_error() {
        let err = AggregationError::BufferOverflow {
            object_id: ObjectId::new(0, 1),
        };
        let generic: Error = err.into();
        let msg = format!("{generic}");
        assert!(msg.contains("buffer overflow") || msg.contains("overflow"));
    }

    #[test]
    fn transport_path_state_transitions() {
        let path = test_path(1);
        assert_eq!(path.state(), PathState::Active);
        path.set_state(PathState::Degraded);
        assert_eq!(path.state(), PathState::Degraded);
        path.set_state(PathState::Closed);
        assert_eq!(path.state(), PathState::Closed);
    }

    #[test]
    fn transport_path_zero_stats_rates() {
        let path = test_path(1);
        assert!((path.effective_loss_rate() - 0.0).abs() < f64::EPSILON);
        assert!((path.duplicate_rate() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn process_result_debug() {
        let result = ProcessResult {
            ready: vec![],
            was_duplicate: false,
            path: PathId(1),
        };
        assert!(format!("{result:?}").contains("ProcessResult"));
    }
}
