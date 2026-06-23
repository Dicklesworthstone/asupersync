//! Channel bonding Phase C2 — one receiver-side symbol set for all donors.
//!
//! Donors in a bonded transfer spray authenticated RaptorQ symbols to the same
//! receiver endpoint. Correctness depends on the receiver treating every symbol
//! as part of one fungible decoder input stream keyed only by
//! `(object_id, sbn, esi)`. The donor id is useful for observability, but it must
//! not partition the decoder state. If two donors deliver the same key, the
//! second symbol is duplicate bandwidth and is dropped before decode.

use std::collections::{BTreeMap, BTreeSet};

use crate::types::{ObjectId, Symbol, SymbolId, SymbolKind};

/// Decoder identity for one bonded RaptorQ symbol.
///
/// This intentionally omits donor id: the same `(object_id, sbn, esi)` from any
/// donor names the same decoder row and must be deduplicated globally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BondedSymbolKey {
    object_id: ObjectId,
    sbn: u8,
    esi: u32,
}

impl BondedSymbolKey {
    /// Build a bonded receiver key.
    #[must_use]
    pub const fn new(object_id: ObjectId, sbn: u8, esi: u32) -> Self {
        Self {
            object_id,
            sbn,
            esi,
        }
    }

    /// Build a key from an existing ATP/RaptorQ symbol id.
    #[must_use]
    pub const fn from_symbol_id(symbol_id: SymbolId) -> Self {
        Self {
            object_id: symbol_id.object_id(),
            sbn: symbol_id.sbn(),
            esi: symbol_id.esi(),
        }
    }

    /// Return the object id.
    #[must_use]
    pub const fn object_id(self) -> ObjectId {
        self.object_id
    }

    /// Return the source block number.
    #[must_use]
    pub const fn sbn(self) -> u8 {
        self.sbn
    }

    /// Return the encoding symbol id.
    #[must_use]
    pub const fn esi(self) -> u32 {
        self.esi
    }
}

/// Per-donor ingress counters for C2 observability.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BondedDonorIngressStats {
    /// All authenticated symbols received from this donor.
    pub symbols_received: u64,
    /// Globally novel symbols accepted into the unified receiver set.
    pub symbols_accepted: u64,
    /// Symbols dropped because another donor or retry already provided the key.
    pub duplicate_symbols: u64,
    /// Accepted source symbols.
    pub source_symbols_accepted: u64,
    /// Accepted repair/FEC symbols.
    pub repair_symbols_accepted: u64,
}

impl BondedDonorIngressStats {
    fn record_received(&mut self) {
        self.symbols_received = self.symbols_received.saturating_add(1);
    }

    fn record_duplicate(&mut self) {
        self.duplicate_symbols = self.duplicate_symbols.saturating_add(1);
    }

    fn record_accepted(&mut self, kind: SymbolKind) {
        self.symbols_accepted = self.symbols_accepted.saturating_add(1);
        if kind.is_source() {
            self.source_symbols_accepted = self.source_symbols_accepted.saturating_add(1);
        } else {
            self.repair_symbols_accepted = self.repair_symbols_accepted.saturating_add(1);
        }
    }

    /// Duplicate rate in parts-per-million.
    #[must_use]
    pub fn duplicate_rate_ppm(self) -> u64 {
        duplicate_rate_ppm(self.duplicate_symbols, self.symbols_received)
    }
}

/// Aggregate ingress counters across all donors.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BondedReceiverIngressStats {
    /// All authenticated donor symbols observed.
    pub symbols_received: u64,
    /// Globally novel symbols accepted into the unified receiver set.
    pub symbols_accepted: u64,
    /// Globally duplicate symbols dropped before decode.
    pub duplicate_symbols: u64,
    /// Accepted source symbols.
    pub source_symbols_accepted: u64,
    /// Accepted repair/FEC symbols.
    pub repair_symbols_accepted: u64,
    /// Number of donors that have contributed at least one symbol.
    pub donor_count: usize,
}

impl BondedReceiverIngressStats {
    /// Duplicate rate in parts-per-million.
    #[must_use]
    pub fn duplicate_rate_ppm(self) -> u64 {
        duplicate_rate_ppm(self.duplicate_symbols, self.symbols_received)
    }
}

/// Result of recording one bonded donor symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BondedSymbolDisposition {
    /// The key was novel and should be fed to the shared decoder set.
    Accepted(BondedSymbolKey),
    /// The key was already present and should not be decoded again.
    Duplicate(BondedSymbolKey),
}

/// Receiver coverage for one bonded RaptorQ source block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BondedBlockCoverage {
    /// RaptorQ object id shared by all bonded donors.
    pub object_id: ObjectId,
    /// Source block number within the object.
    pub sbn: u8,
    /// Accepted symbols needed before the block can stop asking for repair.
    pub target_symbols: u32,
    /// Globally novel symbols accepted for this block.
    pub accepted_symbols: u32,
    /// Additional symbols needed to reach `target_symbols`.
    pub deficit_symbols: u32,
}

impl BondedBlockCoverage {
    /// True when the block has reached or exceeded its target.
    #[must_use]
    pub const fn is_complete(self) -> bool {
        self.deficit_symbols == 0
    }
}

/// Receiver-side C2 registry for authenticated donor symbols.
#[derive(Debug, Clone, Default)]
pub struct BondedReceiverSymbolSet {
    seen: BTreeSet<BondedSymbolKey>,
    donor_stats: BTreeMap<u32, BondedDonorIngressStats>,
    aggregate: BondedReceiverIngressStats,
}

impl BondedReceiverSymbolSet {
    /// Create an empty unified symbol set.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            seen: BTreeSet::new(),
            donor_stats: BTreeMap::new(),
            aggregate: BondedReceiverIngressStats {
                symbols_received: 0,
                symbols_accepted: 0,
                duplicate_symbols: 0,
                source_symbols_accepted: 0,
                repair_symbols_accepted: 0,
                donor_count: 0,
            },
        }
    }

    /// Record an authenticated symbol from `donor_index`.
    ///
    /// The returned [`BondedSymbolDisposition::Accepted`] path is the only path
    /// that should feed decode/persistence. Duplicate symbols are counted for
    /// telemetry and then dropped.
    pub fn record_symbol(&mut self, donor_index: u32, symbol: &Symbol) -> BondedSymbolDisposition {
        self.record_symbol_id(donor_index, symbol.id(), symbol.kind())
    }

    /// Record an authenticated symbol id from `donor_index`.
    pub fn record_symbol_id(
        &mut self,
        donor_index: u32,
        symbol_id: SymbolId,
        kind: SymbolKind,
    ) -> BondedSymbolDisposition {
        self.record_key(
            donor_index,
            BondedSymbolKey::from_symbol_id(symbol_id),
            kind,
        )
    }

    /// Record an authenticated bonded key from `donor_index`.
    pub fn record_key(
        &mut self,
        donor_index: u32,
        key: BondedSymbolKey,
        kind: SymbolKind,
    ) -> BondedSymbolDisposition {
        let was_new_donor = !self.donor_stats.contains_key(&donor_index);
        let donor = self.donor_stats.entry(donor_index).or_default();
        if was_new_donor {
            self.aggregate.donor_count += 1;
        }

        donor.record_received();
        self.aggregate.symbols_received = self.aggregate.symbols_received.saturating_add(1);

        if self.seen.insert(key) {
            donor.record_accepted(kind);
            self.aggregate.symbols_accepted = self.aggregate.symbols_accepted.saturating_add(1);
            if kind.is_source() {
                self.aggregate.source_symbols_accepted =
                    self.aggregate.source_symbols_accepted.saturating_add(1);
            } else {
                self.aggregate.repair_symbols_accepted =
                    self.aggregate.repair_symbols_accepted.saturating_add(1);
            }
            BondedSymbolDisposition::Accepted(key)
        } else {
            donor.record_duplicate();
            self.aggregate.duplicate_symbols = self.aggregate.duplicate_symbols.saturating_add(1);
            BondedSymbolDisposition::Duplicate(key)
        }
    }

    /// Return true if the unified set already contains `key`.
    #[must_use]
    pub fn contains(&self, key: BondedSymbolKey) -> bool {
        self.seen.contains(&key)
    }

    /// Number of globally novel symbols accepted so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Return true when no novel symbols have been accepted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Aggregate ingress counters.
    #[must_use]
    pub const fn aggregate_stats(&self) -> BondedReceiverIngressStats {
        self.aggregate
    }

    /// Per-donor ingress counters, if that donor has sent at least one symbol.
    #[must_use]
    pub fn donor_stats(&self, donor_index: u32) -> Option<BondedDonorIngressStats> {
        self.donor_stats.get(&donor_index).copied()
    }

    /// Compute aggregate coverage for one source block.
    ///
    /// The count is global across donors and deduplicated by `(object_id, sbn,
    /// esi)`, so duplicate donor retransmits cannot hide a remaining deficit.
    #[must_use]
    pub fn block_coverage(
        &self,
        object_id: ObjectId,
        sbn: u8,
        target_symbols: u32,
    ) -> BondedBlockCoverage {
        let accepted_symbols = self
            .seen
            .iter()
            .filter(|key| key.object_id == object_id && key.sbn == sbn)
            .count()
            .min(u32::MAX as usize) as u32;
        BondedBlockCoverage {
            object_id,
            sbn,
            target_symbols,
            accepted_symbols,
            deficit_symbols: target_symbols.saturating_sub(accepted_symbols),
        }
    }

    /// Return coverage rows only for blocks that still need repair symbols.
    #[must_use]
    pub fn blocks_needing_more(
        &self,
        blocks: impl IntoIterator<Item = (ObjectId, u8, u32)>,
    ) -> Vec<BondedBlockCoverage> {
        blocks
            .into_iter()
            .map(|(object_id, sbn, target_symbols)| {
                self.block_coverage(object_id, sbn, target_symbols)
            })
            .filter(|coverage| !coverage.is_complete())
            .collect()
    }
}

fn duplicate_rate_ppm(duplicates: u64, received: u64) -> u64 {
    if received == 0 {
        return 0;
    }
    duplicates.saturating_mul(1_000_000) / received
}

#[cfg(test)]
mod tests {
    use super::*;

    fn symbol(object: u64, sbn: u8, esi: u32, kind: SymbolKind) -> Symbol {
        Symbol::new(
            SymbolId::new_for_test(object, sbn, esi),
            vec![esi as u8],
            kind,
        )
    }

    #[test]
    fn multiple_donors_feed_one_unified_symbol_set() {
        let mut set = BondedReceiverSymbolSet::new();

        for esi in [0, 2, 4] {
            assert!(matches!(
                set.record_symbol(0, &symbol(7, 0, esi, SymbolKind::Source)),
                BondedSymbolDisposition::Accepted(_)
            ));
        }
        for esi in [1, 3, 5] {
            assert!(matches!(
                set.record_symbol(1, &symbol(7, 0, esi, SymbolKind::Repair)),
                BondedSymbolDisposition::Accepted(_)
            ));
        }

        assert_eq!(set.len(), 6);
        assert!(set.contains(BondedSymbolKey::new(ObjectId::new_for_test(7), 0, 5)));

        let aggregate = set.aggregate_stats();
        assert_eq!(aggregate.donor_count, 2);
        assert_eq!(aggregate.symbols_received, 6);
        assert_eq!(aggregate.symbols_accepted, 6);
        assert_eq!(aggregate.duplicate_symbols, 0);
        assert_eq!(aggregate.source_symbols_accepted, 3);
        assert_eq!(aggregate.repair_symbols_accepted, 3);

        let donor0 = set.donor_stats(0).expect("donor 0 stats");
        let donor1 = set.donor_stats(1).expect("donor 1 stats");
        assert_eq!(donor0.symbols_accepted, 3);
        assert_eq!(donor1.symbols_accepted, 3);
    }

    #[test]
    fn cross_donor_duplicate_esi_is_dropped_before_decode() {
        let mut set = BondedReceiverSymbolSet::new();
        let first = symbol(9, 2, 42, SymbolKind::Repair);
        let duplicate = symbol(9, 2, 42, SymbolKind::Repair);

        assert_eq!(
            set.record_symbol(0, &first),
            BondedSymbolDisposition::Accepted(BondedSymbolKey::from_symbol_id(first.id()))
        );
        assert_eq!(
            set.record_symbol(1, &duplicate),
            BondedSymbolDisposition::Duplicate(BondedSymbolKey::from_symbol_id(duplicate.id()))
        );

        assert_eq!(set.len(), 1);
        let aggregate = set.aggregate_stats();
        assert_eq!(aggregate.donor_count, 2);
        assert_eq!(aggregate.symbols_received, 2);
        assert_eq!(aggregate.symbols_accepted, 1);
        assert_eq!(aggregate.duplicate_symbols, 1);
        assert_eq!(aggregate.duplicate_rate_ppm(), 500_000);

        assert_eq!(
            set.donor_stats(1).expect("donor 1 stats").duplicate_symbols,
            1
        );
    }

    #[test]
    fn duplicate_symbols_do_not_inflate_accepted_kind_counters() {
        let mut set = BondedReceiverSymbolSet::new();
        let source = symbol(11, 0, 3, SymbolKind::Source);
        let repair = symbol(11, 0, 9, SymbolKind::Repair);

        assert!(matches!(
            set.record_symbol(0, &source),
            BondedSymbolDisposition::Accepted(_)
        ));
        assert!(matches!(
            set.record_symbol(0, &repair),
            BondedSymbolDisposition::Accepted(_)
        ));
        assert!(matches!(
            set.record_symbol(1, &source),
            BondedSymbolDisposition::Duplicate(_)
        ));
        assert!(matches!(
            set.record_symbol(1, &repair),
            BondedSymbolDisposition::Duplicate(_)
        ));

        let aggregate = set.aggregate_stats();
        assert_eq!(aggregate.symbols_received, 4);
        assert_eq!(aggregate.symbols_accepted, 2);
        assert_eq!(aggregate.duplicate_symbols, 2);
        assert_eq!(aggregate.source_symbols_accepted, 1);
        assert_eq!(aggregate.repair_symbols_accepted, 1);
        assert_eq!(aggregate.duplicate_rate_ppm(), 500_000);

        let donor1 = set.donor_stats(1).expect("donor 1 stats");
        assert_eq!(donor1.symbols_received, 2);
        assert_eq!(donor1.symbols_accepted, 0);
        assert_eq!(donor1.duplicate_symbols, 2);
        assert_eq!(donor1.source_symbols_accepted, 0);
        assert_eq!(donor1.repair_symbols_accepted, 0);
    }

    #[test]
    fn block_coverage_counts_deduplicated_symbols_across_donors() {
        let mut set = BondedReceiverSymbolSet::new();
        let object_id = ObjectId::new_for_test(13);

        for (donor, esi) in [(0, 0), (1, 1), (2, 2), (3, 2)] {
            set.record_key(
                donor,
                BondedSymbolKey::new(object_id, 0, esi),
                SymbolKind::Repair,
            );
        }

        let coverage = set.block_coverage(object_id, 0, 4);

        assert_eq!(
            coverage,
            BondedBlockCoverage {
                object_id,
                sbn: 0,
                target_symbols: 4,
                accepted_symbols: 3,
                deficit_symbols: 1,
            }
        );
        assert!(!coverage.is_complete());

        set.record_key(4, BondedSymbolKey::new(object_id, 0, 3), SymbolKind::Repair);
        assert!(set.block_coverage(object_id, 0, 4).is_complete());
    }

    #[test]
    fn blocks_needing_more_reports_only_incomplete_blocks() {
        let mut set = BondedReceiverSymbolSet::new();
        let object_id = ObjectId::new_for_test(17);
        set.record_key(0, BondedSymbolKey::new(object_id, 0, 0), SymbolKind::Source);
        set.record_key(1, BondedSymbolKey::new(object_id, 1, 0), SymbolKind::Source);
        set.record_key(1, BondedSymbolKey::new(object_id, 1, 1), SymbolKind::Repair);

        let needs_more = set.blocks_needing_more([(object_id, 0, 2), (object_id, 1, 2)]);

        assert_eq!(
            needs_more,
            vec![BondedBlockCoverage {
                object_id,
                sbn: 0,
                target_symbols: 2,
                accepted_symbols: 1,
                deficit_symbols: 1,
            }]
        );
    }

    #[test]
    fn duplicate_scope_is_object_block_and_esi_not_just_esi() {
        let mut set = BondedReceiverSymbolSet::new();

        for symbol in [
            symbol(1, 0, 7, SymbolKind::Source),
            symbol(1, 1, 7, SymbolKind::Source),
            symbol(2, 0, 7, SymbolKind::Source),
        ] {
            assert!(matches!(
                set.record_symbol(0, &symbol),
                BondedSymbolDisposition::Accepted(_)
            ));
        }

        assert_eq!(set.len(), 3);
        assert_eq!(set.aggregate_stats().duplicate_symbols, 0);
    }

    #[test]
    fn empty_set_reports_zero_duplicate_rate() {
        let set = BondedReceiverSymbolSet::new();

        assert!(set.is_empty());
        assert_eq!(set.aggregate_stats().duplicate_rate_ppm(), 0);
        assert_eq!(set.donor_stats(0), None);
    }
}
