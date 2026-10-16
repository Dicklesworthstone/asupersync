//! Symbol collection and threshold tracking.
//!
//! `SymbolSet` collects symbols, deduplicates by `SymbolId`, tracks per-block
//! progress, and reports when decode thresholds are reached.

use crate::types::{Symbol, SymbolId, SymbolKind};
use crate::util::DetHashMap;
use parking_lot::RwLock;

/// Estimated overhead per symbol for bookkeeping.
const SYMBOL_OVERHEAD_BYTES: usize = 32;

/// Configuration for threshold detection.
#[derive(Debug, Clone, Copy)]
pub struct ThresholdConfig {
    /// Overhead factor (e.g., 1.02 means need K * 1.02 symbols).
    pub overhead_factor: f64,
    /// Minimum extra symbols beyond K.
    pub min_overhead: usize,
    /// Maximum symbols to accept per block (0 = unlimited).
    pub max_per_block: usize,
}

impl ThresholdConfig {
    /// Creates a new threshold configuration.
    #[inline]
    #[must_use]
    pub const fn new(overhead_factor: f64, min_overhead: usize, max_per_block: usize) -> Self {
        Self {
            overhead_factor,
            min_overhead,
            max_per_block,
        }
    }
}

impl Default for ThresholdConfig {
    #[inline]
    fn default() -> Self {
        Self {
            overhead_factor: 1.02,
            min_overhead: 0,
            max_per_block: 8192,
        }
    }
}

/// Progress tracking for a single source block.
#[derive(Debug, Clone, Copy)]
pub struct BlockProgress {
    /// Source block number.
    pub sbn: u8,
    /// Count of source symbols seen.
    pub source_symbols: usize,
    /// Count of repair symbols seen.
    pub repair_symbols: usize,
    /// Number of source symbols (K) if known.
    pub k: Option<u16>,
    /// Whether threshold has been reached.
    pub threshold_reached: bool,
}

impl BlockProgress {
    /// Returns the total number of symbols for this block.
    #[inline]
    #[must_use]
    pub const fn total(&self) -> usize {
        self.source_symbols + self.repair_symbols
    }
}

/// Result of inserting a symbol.
#[derive(Debug, Clone)]
pub enum InsertResult {
    /// Symbol inserted successfully.
    Inserted {
        /// Updated progress for this block.
        block_progress: BlockProgress,
        /// Whether threshold has been reached for this block.
        threshold_reached: bool,
    },
    /// Symbol was already present.
    Duplicate,
    /// Symbol rejected due to memory limit.
    MemoryLimitReached,
    /// Symbol rejected due to per-block limit.
    BlockLimitReached {
        /// Block number that hit the limit.
        sbn: u8,
    },
}

/// A collection of symbols with threshold tracking.
///
/// br-asupersync-jg4yyx: backed by [`DetHashMap`] (project-fixed
/// SipHash seed) instead of `std::collections::HashMap` (random
/// per-process seed). Pre-fix, two `SymbolSet` instances built from
/// the same input sequence iterated in different orders across
/// replays / processes — defeating crashpack-hash determinism and
/// any oracle that snapshots the symbol set as a golden artifact.
/// Same fix-shape as the closed asupersync-q6vujm
/// (`trace/distributed/collector.rs`) and asupersync-ks0t6j
/// (`runtime/scheduler/three_lane.rs FairnessMonitor`).
#[derive(Debug, Default)]
pub struct SymbolSet {
    symbols: DetHashMap<SymbolId, Symbol>,
    block_counts: DetHashMap<u8, BlockProgress>,
    total_count: usize,
    total_bytes: usize,
    memory_budget: Option<usize>,
    memory_remaining: usize,
    threshold_config: ThresholdConfig,
}

impl SymbolSet {
    /// Creates a new SymbolSet with the default threshold configuration.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(ThresholdConfig::default())
    }

    /// Creates a new SymbolSet with the specified configuration.
    #[inline]
    #[must_use]
    pub fn with_config(config: ThresholdConfig) -> Self {
        Self {
            symbols: DetHashMap::default(),
            block_counts: DetHashMap::default(),
            total_count: 0,
            total_bytes: 0,
            memory_budget: None,
            memory_remaining: 0,
            threshold_config: config,
        }
    }

    /// Creates a new SymbolSet with a memory budget.
    #[inline]
    #[must_use]
    pub fn with_memory_budget(config: ThresholdConfig, budget_bytes: usize) -> Self {
        let mut set = Self::with_config(config);
        set.memory_budget = Some(budget_bytes);
        set.memory_remaining = budget_bytes;
        set
    }

    /// Inserts a symbol into the set.
    pub fn insert(&mut self, symbol: Symbol) -> InsertResult {
        let id = symbol.id();
        if self.symbols.contains_key(&id) {
            return InsertResult::Duplicate;
        }

        let size = Self::estimate_symbol_size(&symbol);
        if !self.try_allocate(size) {
            return InsertResult::MemoryLimitReached;
        }

        let sbn = id.sbn();
        let config = self.threshold_config;

        // Scope the mutable borrow of block_counts
        let (limit_reached, progress_copy) = {
            let progress = self.block_counts.entry(sbn).or_insert(BlockProgress {
                sbn,
                source_symbols: 0,
                repair_symbols: 0,
                k: None,
                threshold_reached: false,
            });

            if config.max_per_block != 0 && progress.total() >= config.max_per_block {
                (true, *progress)
            } else {
                match symbol.kind() {
                    SymbolKind::Source => progress.source_symbols += 1,
                    SymbolKind::Repair => progress.repair_symbols += 1,
                }

                progress.threshold_reached = Self::calculate_threshold(progress, &config);
                (false, *progress)
            }
        };

        if limit_reached {
            self.deallocate(size);
            return InsertResult::BlockLimitReached { sbn };
        }

        self.symbols.insert(id, symbol);
        self.total_count += 1;

        InsertResult::Inserted {
            block_progress: progress_copy,
            threshold_reached: progress_copy.threshold_reached,
        }
    }

    /// Inserts multiple symbols into the set.
    pub fn insert_batch(&mut self, symbols: impl Iterator<Item = Symbol>) -> Vec<InsertResult> {
        symbols.map(|symbol| self.insert(symbol)).collect()
    }

    /// Sets the source-symbol count (K) for a block.
    ///
    /// Returns true if the threshold is now reached for that block.
    pub fn set_block_k(&mut self, sbn: u8, k: u16) -> bool {
        let config = self.threshold_config;
        let progress = self.block_counts.entry(sbn).or_insert(BlockProgress {
            sbn,
            source_symbols: 0,
            repair_symbols: 0,
            k: None,
            threshold_reached: false,
        });
        progress.k = Some(k);
        progress.threshold_reached = Self::calculate_threshold(progress, &config);
        progress.threshold_reached
    }

    /// Updates the maximum number of symbols accepted per block.
    ///
    /// This is used by decoders that can derive a safer cap only after object
    /// parameters reveal the block geometry.
    pub fn set_max_per_block(&mut self, max_per_block: usize) {
        self.threshold_config.max_per_block = max_per_block;
    }

    /// The current per-block symbol-accept cap (`0` means unbounded).
    #[must_use]
    pub fn max_per_block(&self) -> usize {
        self.threshold_config.max_per_block
    }

    /// Returns true if a symbol is present.
    #[inline]
    #[must_use]
    pub fn contains(&self, id: &SymbolId) -> bool {
        self.symbols.contains_key(id)
    }

    /// Gets a symbol by ID.
    #[inline]
    #[must_use]
    pub fn get(&self, id: &SymbolId) -> Option<&Symbol> {
        self.symbols.get(id)
    }

    /// Removes a symbol by ID.
    pub fn remove(&mut self, id: &SymbolId) -> Option<Symbol> {
        let symbol = self.symbols.remove(id)?;
        self.total_count = self.total_count.saturating_sub(1);
        self.deallocate(Self::estimate_symbol_size(&symbol));

        let sbn = id.sbn();
        if let Some(progress) = self.block_counts.get_mut(&sbn) {
            match symbol.kind() {
                SymbolKind::Source => {
                    progress.source_symbols = progress.source_symbols.saturating_sub(1);
                }
                SymbolKind::Repair => {
                    progress.repair_symbols = progress.repair_symbols.saturating_sub(1);
                }
            }
            progress.threshold_reached =
                Self::calculate_threshold(progress, &self.threshold_config);
            if progress.total() == 0 && progress.k.is_none() {
                self.block_counts.remove(&sbn);
            }
        }

        Some(symbol)
    }

    /// Returns an iterator over all symbols for a block.
    pub fn symbols_for_block(&self, sbn: u8) -> impl Iterator<Item = &Symbol> {
        self.symbols
            .values()
            .filter(move |symbol| symbol.sbn() == sbn)
    }

    /// Restores a previously accepted symbol without applying per-block intake
    /// limits again.
    ///
    /// Deferred decode jobs temporarily move symbols out of the receive set so
    /// the pipeline does not keep a second payload copy while a blocking solve
    /// owns the job. If that solve is stale or fails, the same accepted symbols
    /// must be put back exactly as retained input, not treated as fresh network
    /// intake that can trip the cap.
    pub(crate) fn restore_retained(&mut self, symbol: Symbol) -> bool {
        let id = symbol.id();
        if self.symbols.contains_key(&id) {
            return false;
        }

        let size = Self::estimate_symbol_size(&symbol);
        self.total_bytes = self.total_bytes.saturating_add(size);
        if self.memory_budget.is_some() {
            self.memory_remaining = self.memory_remaining.saturating_sub(size);
        }

        let sbn = id.sbn();
        let progress = self.block_counts.entry(sbn).or_insert(BlockProgress {
            sbn,
            source_symbols: 0,
            repair_symbols: 0,
            k: None,
            threshold_reached: false,
        });
        match symbol.kind() {
            SymbolKind::Source => progress.source_symbols += 1,
            SymbolKind::Repair => progress.repair_symbols += 1,
        }
        progress.threshold_reached = Self::calculate_threshold(progress, &self.threshold_config);

        self.symbols.insert(id, symbol);
        self.total_count = self.total_count.saturating_add(1);
        true
    }

    /// Moves all currently retained symbols for a block out of the set.
    ///
    /// The block's configured `K` is preserved so new arrivals while the decode
    /// job is in flight still have correct threshold metadata.
    pub(crate) fn take_block_symbols(&mut self, sbn: u8) -> Vec<Symbol> {
        let ids: Vec<SymbolId> = self
            .symbols
            .iter()
            .filter_map(|(id, symbol)| (symbol.sbn() == sbn).then_some(*id))
            .collect();
        let mut symbols = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(symbol) = self.remove(&id) {
                symbols.push(symbol);
            }
        }
        symbols
    }

    /// Returns block progress for a given block.
    #[inline]
    #[must_use]
    pub fn block_progress(&self, sbn: u8) -> Option<&BlockProgress> {
        self.block_counts.get(&sbn)
    }

    /// Returns true if the threshold is reached for a block.
    #[inline]
    #[must_use]
    pub fn threshold_reached(&self, sbn: u8) -> bool {
        self.block_counts
            .get(&sbn)
            .is_some_and(|progress| progress.threshold_reached)
    }

    /// Returns all blocks that have reached the threshold.
    #[must_use]
    pub fn ready_blocks(&self) -> Vec<u8> {
        let mut ready: Vec<u8> = self
            .block_counts
            .iter()
            .filter_map(|(sbn, progress)| {
                if progress.threshold_reached {
                    Some(*sbn)
                } else {
                    None
                }
            })
            .collect();
        ready.sort_unstable();
        ready
    }

    /// Returns the total number of symbols stored.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.total_count
    }

    /// Returns true if no symbols are stored.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.total_count == 0
    }

    /// Returns estimated memory usage in bytes.
    #[inline]
    #[must_use]
    pub const fn memory_usage(&self) -> usize {
        self.total_bytes
    }

    /// Clears all symbols.
    pub fn clear(&mut self) {
        self.symbols.clear();
        self.block_counts.clear();
        self.total_count = 0;
        self.total_bytes = 0;
        if let Some(budget) = self.memory_budget {
            self.memory_remaining = budget;
        }
    }

    /// Iterates over all symbols in the set.
    pub fn iter(&self) -> impl Iterator<Item = (&SymbolId, &Symbol)> {
        self.symbols.iter()
    }

    /// Drains all symbols from the set.
    pub fn drain(&mut self) -> impl Iterator<Item = (SymbolId, Symbol)> {
        self.block_counts.clear();
        self.total_count = 0;
        self.total_bytes = 0;
        if let Some(budget) = self.memory_budget {
            self.memory_remaining = budget;
        }
        std::mem::take(&mut self.symbols).into_iter()
    }

    /// Clears symbols for a specific block.
    pub fn clear_block(&mut self, sbn: u8) {
        let ids: Vec<SymbolId> = self
            .symbols
            .iter()
            .filter_map(
                |(id, symbol)| {
                    if symbol.sbn() == sbn { Some(*id) } else { None }
                },
            )
            .collect();

        for id in ids {
            let _ = self.remove(&id);
        }

        if let Some(progress) = self.block_counts.get_mut(&sbn) {
            progress.source_symbols = 0;
            progress.repair_symbols = 0;
            progress.threshold_reached =
                Self::calculate_threshold(progress, &self.threshold_config);
            if progress.k.is_none() {
                self.block_counts.remove(&sbn);
            }
        }
    }

    /// Clears selected repair symbols for a block, retaining systematic source
    /// symbols, newer repair symbols, and the block's configured K.
    pub fn clear_repair_symbols_for_block(&mut self, sbn: u8, ids: &[SymbolId]) -> usize {
        let mut removed = 0usize;
        for id in ids {
            let Some(symbol) = self.symbols.get(id) else {
                continue;
            };
            if symbol.sbn() != sbn || symbol.kind() != SymbolKind::Repair {
                continue;
            }
            if self.remove(id).is_some() {
                removed = removed.saturating_add(1);
            }
        }
        removed
    }

    fn calculate_threshold(progress: &BlockProgress, config: &ThresholdConfig) -> bool {
        progress.k.is_some_and(|k| {
            if k == 0 {
                return false;
            }
            let k_usize = k as usize;
            if progress.source_symbols >= k_usize {
                return true;
            }
            let total = progress.total();
            let raw = (f64::from(k) * config.overhead_factor).ceil();
            let minimum_threshold = k_usize.saturating_add(config.min_overhead);
            if raw.is_nan() {
                return total >= minimum_threshold;
            }
            if raw.is_sign_positive() && !raw.is_finite() {
                return false;
            }
            if raw.is_sign_negative() {
                return total >= minimum_threshold;
            }
            #[allow(clippy::cast_sign_loss)]
            let factor_threshold = raw as usize;
            // `overhead_factor` is already a total-symbol target; `min_overhead`
            // is the minimum extra beyond K, so it acts as a floor instead.
            let threshold = factor_threshold.max(minimum_threshold);
            total >= threshold
        })
    }

    fn estimate_symbol_size(symbol: &Symbol) -> usize {
        std::mem::size_of::<SymbolId>() + symbol.data().len() + SYMBOL_OVERHEAD_BYTES
    }

    fn try_allocate(&mut self, size: usize) -> bool {
        if self.memory_budget.is_some() {
            if size <= self.memory_remaining {
                self.memory_remaining -= size;
            } else {
                return false;
            }
        }
        self.total_bytes = self.total_bytes.saturating_add(size);
        true
    }

    fn deallocate(&mut self, size: usize) {
        self.total_bytes = self.total_bytes.saturating_sub(size);
        if let Some(budget) = self.memory_budget {
            self.memory_remaining = self.memory_remaining.saturating_add(size).min(budget);
        }
    }
}

/// Thread-safe SymbolSet for concurrent insertion.
#[derive(Debug, Default)]
pub struct ConcurrentSymbolSet {
    inner: RwLock<SymbolSet>,
}

impl ConcurrentSymbolSet {
    /// Creates a new concurrent SymbolSet with the default config.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a symbol into the set.
    pub fn insert(&self, symbol: Symbol) -> InsertResult {
        self.inner.write().insert(symbol)
    }

    /// Sets the block K value.
    pub fn set_block_k(&self, sbn: u8, k: u16) -> bool {
        self.inner.write().set_block_k(sbn, k)
    }

    /// Returns true if a block has reached threshold.
    #[must_use]
    pub fn threshold_reached(&self, sbn: u8) -> bool {
        self.inner.read().threshold_reached(sbn)
    }
}

#[cfg(test)]
#[path = "symbol_set_inline_tests.rs"]
mod tests;
