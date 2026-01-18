//! Multipath symbol aggregation infrastructure.
//!
//! This module provides symbol aggregation from multiple transport paths:
//! - `TransportPath`: Represents a single transport path with characteristics
//! - `PathSet`: Manages multiple paths to a destination
//! - `SymbolDeduplicator`: Filters duplicate symbols
//! - `SymbolReorderer`: Buffers and reorders symbols
//! - `MultipathAggregator`: Main aggregation orchestrator

use crate::error::{Error, ErrorKind};
use crate::types::symbol::{ObjectId, Symbol, SymbolId};
use crate::types::Time;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

// ============================================================================
// Path Types
// ============================================================================

/// Unique identifier for a transport path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
pub enum PathState {
    /// Path is active and healthy.
    Active,

    /// Path is experiencing issues but still usable.
    Degraded,

    /// Path is temporarily unavailable.
    Unavailable,

    /// Path has been permanently closed.
    Closed,
}

impl PathState {
    /// Returns true if the path can be used for receiving.
    #[must_use]
    pub const fn is_usable(&self) -> bool {
        matches!(self, Self::Active | Self::Degraded)
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

    /// Current state.
    pub state: PathState,

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

    /// Last activity time.
    pub last_activity: RwLock<Time>,

    /// Creation time.
    pub created_at: Time,
}

impl TransportPath {
    /// Creates a new transport path.
    pub fn new(id: PathId, name: impl Into<String>, remote: impl Into<String>) -> Self {
        Self {
            id,
            name: name.into(),
            state: PathState::Active,
            characteristics: PathCharacteristics::default(),
            remote_address: remote.into(),
            symbols_received: AtomicU64::new(0),
            symbols_lost: AtomicU64::new(0),
            duplicates_received: AtomicU64::new(0),
            last_activity: RwLock::new(Time::ZERO),
            created_at: Time::ZERO,
        }
    }

    /// Sets path characteristics.
    #[must_use]
    pub fn with_characteristics(mut self, chars: PathCharacteristics) -> Self {
        self.characteristics = chars;
        self
    }

    /// Records symbol receipt.
    pub fn record_receipt(&self, now: Time) {
        self.symbols_received.fetch_add(1, Ordering::Relaxed);
        *self.last_activity.write().expect("lock poisoned") = now;
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathSelectionPolicy {
    /// Use all available paths.
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

impl Default for PathSelectionPolicy {
    fn default() -> Self {
        Self::UseAll
    }
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
        self.paths.write().expect("lock poisoned").insert(id, arc);
        id
    }

    /// Creates and registers a new path.
    pub fn create_path(
        &self,
        name: impl Into<String>,
        remote: impl Into<String>,
        chars: PathCharacteristics,
    ) -> PathId {
        let id = PathId(self.next_id.fetch_add(1, Ordering::SeqCst));
        let path = TransportPath::new(id, name, remote).with_characteristics(chars);
        self.register(path)
    }

    /// Gets a path by ID.
    #[must_use]
    pub fn get(&self, id: PathId) -> Option<Arc<TransportPath>> {
        self.paths.read().expect("lock poisoned").get(&id).cloned()
    }

    /// Removes a path.
    pub fn remove(&self, id: PathId) -> Option<Arc<TransportPath>> {
        self.paths.write().expect("lock poisoned").remove(&id)
    }

    /// Returns all usable paths based on the selection policy.
    #[must_use]
    pub fn select_paths(&self) -> Vec<Arc<TransportPath>> {
        let paths = self.paths.read().expect("lock poisoned");
        let usable: Vec<_> = paths
            .values()
            .filter(|p| p.state.is_usable())
            .cloned()
            .collect();

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
    pub fn set_state(&self, id: PathId, _state: PathState) -> bool {
        if let Some(_path) = self.paths.read().expect("lock poisoned").get(&id) {
            // Note: In real impl, path.state would need interior mutability
            true
        } else {
            false
        }
    }

    /// Returns the number of paths.
    #[must_use]
    pub fn count(&self) -> usize {
        self.paths.read().expect("lock poisoned").len()
    }

    /// Returns the number of usable paths.
    #[must_use]
    pub fn usable_count(&self) -> usize {
        self.paths
            .read()
            .expect("lock poisoned")
            .values()
            .filter(|p| p.state.is_usable())
            .count()
    }

    /// Returns aggregate statistics.
    #[must_use]
    pub fn stats(&self) -> PathSetStats {
        let paths = self.paths.read().expect("lock poisoned");

        let mut total_received = 0u64;
        let mut total_lost = 0u64;
        let mut total_duplicates = 0u64;
        let mut total_bandwidth = 0u64;

        for path in paths.values() {
            total_received += path.symbols_received.load(Ordering::Relaxed);
            total_lost += path.symbols_lost.load(Ordering::Relaxed);
            total_duplicates += path.duplicates_received.load(Ordering::Relaxed);
            if path.state.is_usable() {
                total_bandwidth += path.characteristics.bandwidth_bps;
            }
        }

        PathSetStats {
            path_count: paths.len(),
            usable_count: paths.values().filter(|p| p.state.is_usable()).count(),
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

        let mut objects = self.objects.write().expect("lock poisoned");

        // Get or create object state
        let state = objects
            .entry(object_id)
            .or_insert_with(|| ObjectDeduplicationState::new(now));

        // Check if already seen
        if state.seen.contains(&symbol_id) {
            self.duplicates_detected.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // Record new symbol
        state.seen.insert(symbol_id);
        state.first_seen.insert(symbol_id, now);
        if self.config.track_path {
            state.first_path.insert(symbol_id, path);
        }
        state.last_activity = now;

        self.unique_symbols.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Returns the path that first delivered a symbol.
    #[must_use]
    pub fn first_path(&self, object_id: ObjectId, symbol_id: SymbolId) -> Option<PathId> {
        let objects = self.objects.read().expect("lock poisoned");
        objects
            .get(&object_id)
            .and_then(|state| state.first_path.get(&symbol_id).copied())
    }

    /// Prunes old entries.
    pub fn prune(&self, now: Time) -> usize {
        let mut objects = self.objects.write().expect("lock poisoned");
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
        let objects = self.objects.read().expect("lock poisoned");
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
        self.objects
            .write()
            .expect("lock poisoned")
            .remove(&object_id);
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

        let mut objects = self.objects.write().expect("lock poisoned");
        let state = objects
            .entry(object_id)
            .or_insert_with(ObjectReorderState::new);

        let mut ready = Vec::new();

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
            }
            // else: gap too large or buffer full, drop the symbol
        }
        // else: seq < next_expected - this is a late duplicate, ignore

        ready
    }

    /// Flushes timed-out symbols.
    ///
    /// Returns symbols that have waited too long.
    pub fn flush_timeouts(&self, now: Time) -> Vec<Symbol> {
        let mut objects = self.objects.write().expect("lock poisoned");
        let max_wait_nanos = self.config.max_wait_time.as_nanos();
        let mut flushed = Vec::new();

        for state in objects.values_mut() {
            let mut to_remove = Vec::new();

            for (&seq, buffered) in &state.buffer {
                let wait_time = now
                    .as_nanos()
                    .saturating_sub(buffered.received_at.as_nanos());
                if wait_time >= max_wait_nanos {
                    to_remove.push(seq);
                }
            }

            for seq in to_remove {
                if let Some(buffered) = state.buffer.remove(&seq) {
                    flushed.push(buffered.symbol);
                    self.timeout_deliveries.fetch_add(1, Ordering::Relaxed);
                }
            }

            // Advance next_expected if we flushed waiting symbols
            while state.buffer.get(&state.next_expected).is_none() {
                if state.buffer.is_empty()
                    || *state.buffer.keys().next().unwrap() > state.next_expected
                {
                    // Check if we need to skip ahead
                    if let Some(&first_key) = state.buffer.keys().next() {
                        if first_key > state.next_expected + self.config.max_sequence_gap {
                            state.next_expected = first_key;
                        }
                    }
                    break;
                }
                state.next_expected += 1;
            }
        }

        flushed
    }

    /// Returns statistics.
    #[must_use]
    pub fn stats(&self) -> ReordererStats {
        let objects = self.objects.read().expect("lock poisoned");
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
        self.objects
            .write()
            .expect("lock poisoned")
            .remove(&object_id);
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

    /// Last flush time.
    last_flush: RwLock<Time>,
}

impl MultipathAggregator {
    /// Creates a new aggregator.
    pub fn new(config: AggregatorConfig) -> Self {
        let paths = Arc::new(PathSet::new(config.path_policy));

        Self {
            paths,
            dedup: SymbolDeduplicator::new(config.dedup.clone()),
            reorderer: SymbolReorderer::new(config.reorder.clone()),
            config,
            total_processed: AtomicU64::new(0),
            last_flush: RwLock::new(Time::ZERO),
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
        // Check flush interval
        {
            let last = *self.last_flush.read().expect("lock poisoned");
            let interval_nanos = self.config.flush_interval.as_nanos();
            if now.as_nanos().saturating_sub(last.as_nanos()) < interval_nanos {
                return vec![];
            }
            *self.last_flush.write().expect("lock poisoned") = now;
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
            Self::PathNotFound { path } => write!(f, "path {} not found", path),
            Self::PathUnavailable { path } => write!(f, "path {} unavailable", path),
            Self::BufferOverflow { object_id } => {
                write!(f, "buffer overflow for object {:?}", object_id)
            }
            Self::InvalidSequence {
                object_id,
                expected,
                received,
            } => {
                write!(
                    f,
                    "invalid sequence for object {:?}: expected {}, got {}",
                    object_id, expected, received
                )
            }
        }
    }
}

impl std::error::Error for AggregationError {}

impl From<AggregationError> for Error {
    fn from(e: AggregationError) -> Self {
        Error::new(ErrorKind::StreamEnded).with_message(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_path(id: u64) -> TransportPath {
        TransportPath::new(
            PathId(id),
            format!("path-{}", id),
            format!("10.0.0.{}:8080", id),
        )
    }

    // Test 1: Path state predicates
    #[test]
    fn test_path_state() {
        assert!(PathState::Active.is_usable());
        assert!(PathState::Degraded.is_usable());
        assert!(!PathState::Unavailable.is_usable());
        assert!(!PathState::Closed.is_usable());
    }

    // Test 2: Path characteristics quality score
    #[test]
    fn test_quality_score() {
        let high = PathCharacteristics::high_quality();
        let backup = PathCharacteristics::backup();

        assert!(high.quality_score() > backup.quality_score());
    }

    // Test 3: Path statistics
    #[test]
    fn test_path_statistics() {
        let path = test_path(1);

        path.record_receipt(Time::from_secs(1));
        path.record_receipt(Time::from_secs(2));
        path.record_duplicate();
        path.record_loss();

        assert_eq!(path.symbols_received.load(Ordering::Relaxed), 2);
        assert_eq!(path.duplicates_received.load(Ordering::Relaxed), 1);
        assert!(path.duplicate_rate() > 0.0);
        assert!(path.effective_loss_rate() > 0.0);
    }

    // Test 4: PathSet selection - UseAll
    #[test]
    fn test_path_set_use_all() {
        let set = PathSet::new(PathSelectionPolicy::UseAll);

        set.register(test_path(1));
        set.register(test_path(2));
        set.register(test_path(3));

        let selected = set.select_paths();
        assert_eq!(selected.len(), 3);
    }

    // Test 5: PathSet selection - BestQuality
    #[test]
    fn test_path_set_best_quality() {
        let set = PathSet::new(PathSelectionPolicy::BestQuality { count: 2 });

        set.register(test_path(1).with_characteristics(PathCharacteristics::high_quality()));
        set.register(test_path(2).with_characteristics(PathCharacteristics::backup()));
        set.register(test_path(3).with_characteristics(PathCharacteristics::default()));

        let selected = set.select_paths();
        assert_eq!(selected.len(), 2);
        // First should be high quality
        assert!(
            selected[0].characteristics.quality_score()
                > selected[1].characteristics.quality_score()
        );
    }

    // Test 6: Deduplicator basic operation
    #[test]
    fn test_deduplicator_basic() {
        let dedup = SymbolDeduplicator::new(DeduplicatorConfig::default());

        let symbol = Symbol::new_for_test(1, 0, 0, &[1, 2, 3]);
        let path = PathId(1);
        let now = Time::ZERO;

        // First time - not duplicate
        assert!(dedup.check_and_record(&symbol, path, now));

        // Second time - duplicate
        assert!(!dedup.check_and_record(&symbol, path, now));

        let stats = dedup.stats();
        assert_eq!(stats.unique_symbols, 1);
        assert_eq!(stats.duplicates_detected, 1);
    }

    // Test 7: Deduplicator tracks first path
    #[test]
    fn test_deduplicator_tracks_path() {
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
        assert_eq!(first, Some(path1));
    }

    // Test 8: Reorderer in-order delivery
    #[test]
    fn test_reorderer_in_order() {
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

        assert_eq!(ready0.len(), 1);
        assert_eq!(ready1.len(), 1);
        assert_eq!(ready2.len(), 1);

        let stats = reorderer.stats();
        assert_eq!(stats.in_order_deliveries, 3);
        assert_eq!(stats.reordered_deliveries, 0);
    }

    // Test 9: Reorderer out-of-order buffering
    #[test]
    fn test_reorderer_out_of_order() {
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
        assert_eq!(ready0.len(), 1); // s0 delivered

        let ready2 = reorderer.process(s2, path, now);
        assert_eq!(ready2.len(), 0); // s2 buffered, waiting for s1

        let ready1 = reorderer.process(s1, path, now);
        assert_eq!(ready1.len(), 2); // s1 and s2 delivered

        let stats = reorderer.stats();
        assert_eq!(stats.in_order_deliveries, 2);
        assert_eq!(stats.reordered_deliveries, 1);
    }

    // Test 10: Reorderer timeout flush
    #[test]
    fn test_reorderer_timeout() {
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
        assert_eq!(flushed.len(), 0);

        // After timeout
        let flushed = reorderer.flush_timeouts(Time::from_millis(200));
        assert_eq!(flushed.len(), 1); // s2 flushed
    }

    // Test 11: MultipathAggregator basic flow
    #[test]
    fn test_aggregator_basic() {
        let config = AggregatorConfig::default();
        let aggregator = MultipathAggregator::new(config);

        let path = aggregator.paths().create_path(
            "test",
            "localhost:8080",
            PathCharacteristics::default(),
        );

        let symbol = Symbol::new_for_test(1, 0, 0, &[1, 2, 3]);

        let result = aggregator.process(symbol.clone(), path, Time::ZERO);
        assert!(!result.was_duplicate);

        // Duplicate
        let result2 = aggregator.process(symbol, path, Time::ZERO);
        assert!(result2.was_duplicate);
        assert!(result2.ready.is_empty());
    }

    // Test 12: MultipathAggregator object completion
    #[test]
    fn test_aggregator_object_complete() {
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
        assert!(!result.was_duplicate);
    }

    // Test 13: PathSet aggregate stats
    #[test]
    fn test_path_set_stats() {
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
        assert_eq!(stats.path_count, 2);
        assert_eq!(stats.total_received, 300);
        assert_eq!(stats.aggregate_bandwidth_bps, 3_000_000);
    }

    // Test 14: Immediate delivery mode
    #[test]
    fn test_immediate_delivery() {
        let config = ReordererConfig {
            immediate_delivery: true,
            ..Default::default()
        };
        let reorderer = SymbolReorderer::new(config);

        // Out of order should still deliver immediately
        let s5 = Symbol::new_for_test(1, 0, 5, &[5]);
        let ready = reorderer.process(s5, PathId(1), Time::ZERO);

        assert_eq!(ready.len(), 1);
    }

    // Test 15: Aggregator stats
    #[test]
    fn test_aggregator_stats() {
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
        assert_eq!(stats.total_processed, 10);
        assert_eq!(stats.paths.path_count, 1);
    }
}
