//! Symbol collection and threshold tracking.
//!
//! `SymbolSet` collects symbols, deduplicates by `SymbolId`, tracks per-block
//! progress, and reports when decode thresholds are reached.

use crate::types::{Symbol, SymbolId, SymbolKind};
use parking_lot::RwLock;
use std::collections::HashMap;

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
    fn default() -> Self {
        Self {
            overhead_factor: 1.02,
            min_overhead: 0,
            max_per_block: 0,
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
#[derive(Debug)]
pub struct SymbolSet {
    symbols: HashMap<SymbolId, Symbol>,
    block_counts: HashMap<u8, BlockProgress>,
    total_count: usize,
    total_bytes: usize,
    memory_budget: Option<usize>,
    memory_remaining: usize,
    threshold_config: ThresholdConfig,
}

impl SymbolSet {
    /// Creates a new SymbolSet with the default threshold configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(ThresholdConfig::default())
    }

    /// Creates a new SymbolSet with the specified configuration.
    #[must_use]
    pub fn with_config(config: ThresholdConfig) -> Self {
        Self {
            symbols: HashMap::new(),
            block_counts: HashMap::new(),
            total_count: 0,
            total_bytes: 0,
            memory_budget: None,
            memory_remaining: 0,
            threshold_config: config,
        }
    }

    /// Creates a new SymbolSet with a memory budget.
    #[must_use]
    pub fn with_memory_budget(config: ThresholdConfig, budget_bytes: usize) -> Self {
        Self {
            symbols: HashMap::new(),
            block_counts: HashMap::new(),
            total_count: 0,
            total_bytes: 0,
            memory_budget: Some(budget_bytes),
            memory_remaining: budget_bytes,
            threshold_config: config,
        }
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

    /// Returns true if a symbol is present.
    #[must_use]
    pub fn contains(&self, id: &SymbolId) -> bool {
        self.symbols.contains_key(id)
    }

    /// Gets a symbol by ID.
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

    /// Returns block progress for a given block.
    #[must_use]
    pub fn block_progress(&self, sbn: u8) -> Option<&BlockProgress> {
        self.block_counts.get(&sbn)
    }

    /// Returns true if the threshold is reached for a block.
    #[must_use]
    pub fn threshold_reached(&self, sbn: u8) -> bool {
        self.block_counts
            .get(&sbn)
            .is_some_and(|progress| progress.threshold_reached)
    }

    /// Returns all blocks that have reached the threshold.
    #[must_use]
    pub fn ready_blocks(&self) -> Vec<u8> {
        self.block_counts
            .iter()
            .filter_map(|(sbn, progress)| {
                if progress.threshold_reached {
                    Some(*sbn)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Returns the total number of symbols stored.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.total_count
    }

    /// Returns true if no symbols are stored.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.total_count == 0
    }

    /// Returns estimated memory usage in bytes.
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

    fn calculate_threshold(progress: &BlockProgress, config: &ThresholdConfig) -> bool {
        progress.k.is_some_and(|k| {
            let k_usize = k as usize;
            if progress.source_symbols >= k_usize {
                return true;
            }
            let total = progress.total();
            let raw = (f64::from(k) * config.overhead_factor).ceil();
            if raw.is_sign_negative() {
                return false;
            }
            #[allow(clippy::cast_sign_loss)]
            let threshold = raw as usize + config.min_overhead;
            total >= threshold
        })
    }

    fn check_threshold(&self, progress: &BlockProgress) -> bool {
        Self::calculate_threshold(progress, &self.threshold_config)
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

impl Default for SymbolSet {
    fn default() -> Self {
        Self::new()
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
        Self {
            inner: RwLock::new(SymbolSet::new()),
        }
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
mod tests {
    use super::*;
    use crate::types::Symbol;

    fn test_symbol(sbn: u8, esi: u32, data_len: usize) -> Symbol {
        Symbol::new_for_test(1, sbn, esi, &vec![0u8; data_len])
    }

    #[test]
    fn insert_and_duplicate() {
        let mut set = SymbolSet::new();
        let symbol = test_symbol(0, 0, 4);
        assert!(matches!(
            set.insert(symbol.clone()),
            InsertResult::Inserted { .. }
        ));
        assert!(matches!(set.insert(symbol), InsertResult::Duplicate));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn threshold_tracking() {
        let config = ThresholdConfig::new(1.0, 0, 0);
        let mut set = SymbolSet::with_config(config);
        assert!(!set.threshold_reached(0));

        let _ = set.insert(test_symbol(0, 0, 4));
        assert!(!set.threshold_reached(0));

        set.set_block_k(0, 1);
        assert!(set.threshold_reached(0));
    }

    #[test]
    fn block_limit_enforced() {
        let config = ThresholdConfig::new(1.0, 0, 1);
        let mut set = SymbolSet::with_config(config);
        assert!(matches!(
            set.insert(test_symbol(1, 0, 1)),
            InsertResult::Inserted { .. }
        ));
        assert!(matches!(
            set.insert(test_symbol(1, 1, 1)),
            InsertResult::BlockLimitReached { sbn: 1 }
        ));
    }

    #[test]
    fn memory_budget_enforced() {
        let config = ThresholdConfig::new(1.0, 0, 0);
        let mut set = SymbolSet::with_memory_budget(config, 8);
        let large = test_symbol(0, 0, 128);
        assert!(matches!(
            set.insert(large),
            InsertResult::MemoryLimitReached
        ));
    }

    #[test]
    fn clear_block_removes_only_block() {
        let mut set = SymbolSet::new();
        let _ = set.insert(test_symbol(0, 0, 4));
        let _ = set.insert(test_symbol(1, 0, 4));
        assert_eq!(set.len(), 2);

        set.clear_block(0);
        assert_eq!(set.len(), 1);
        assert!(set.symbols_for_block(0).next().is_none());
        assert!(set.symbols_for_block(1).next().is_some());
    }

    #[test]
    fn iter_and_drain_symbols() {
        let mut set = SymbolSet::new();
        let _ = set.insert(test_symbol(0, 0, 4));
        let _ = set.insert(test_symbol(0, 1, 4));

        assert_eq!(set.iter().count(), 2);
        assert_eq!(set.len(), 2);

        let drained = set.drain().count();
        assert_eq!(drained, 2);
        assert!(set.is_empty());
        assert_eq!(set.memory_usage(), 0);
    }
}
