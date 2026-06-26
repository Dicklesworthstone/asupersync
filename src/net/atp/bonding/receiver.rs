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

/// Receiver-side source-fast-path holes for one bonded RaptorQ source block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BondedBlockSourceHoles {
    /// RaptorQ object id shared by all bonded donors.
    pub object_id: ObjectId,
    /// Source block number within the object.
    pub sbn: u8,
    /// Number of systematic source ESIs for this block.
    pub source_symbols: u32,
    /// Source ESIs still missing after global cross-donor deduplication.
    pub missing_source_esis: Vec<u32>,
}

impl BondedBlockSourceHoles {
    /// True when the receiver can stay on the source-only memcpy path.
    #[must_use]
    pub fn is_source_complete(&self) -> bool {
        self.missing_source_esis.is_empty()
    }

    /// Count missing systematic source symbols for this block.
    #[must_use]
    pub fn missing_source_count(&self) -> usize {
        self.missing_source_esis.len()
    }
}

/// Live receiver progress summary for a bonded transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BondedReceiverProgressSnapshot {
    /// Aggregate symbol ingress counters.
    pub aggregate: BondedReceiverIngressStats,
    /// Number of source blocks included in this snapshot.
    pub total_blocks: usize,
    /// Blocks whose accepted symbols meet their target.
    pub complete_blocks: usize,
    /// Blocks still below their target.
    pub incomplete_blocks: usize,
    /// Sum of all incomplete block deficits.
    pub total_deficit_symbols: u64,
}

impl BondedReceiverProgressSnapshot {
    /// True when every tracked block is complete.
    #[must_use]
    pub const fn is_complete(self) -> bool {
        self.incomplete_blocks == 0
    }

    /// Aggregate duplicate rate in parts-per-million.
    #[must_use]
    pub fn duplicate_rate_ppm(self) -> u64 {
        self.aggregate.duplicate_rate_ppm()
    }
}

/// Broadcast feedback computed from aggregate bonded receiver progress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BondedReceiverFeedbackPlan {
    /// Donor control connections that should receive every feedback action.
    pub donor_targets: Vec<u32>,
    /// Missing systematic/source ESIs to request before generic repair.
    pub source_first_need_more: Vec<BondedBlockSourceHoles>,
    /// Aggregate block deficits to broadcast as NeedMore.
    pub need_more: Vec<BondedBlockCoverage>,
    /// True when the receiver should broadcast ObjectComplete/Close.
    pub close: bool,
    /// Progress snapshot used to derive the plan.
    pub progress: BondedReceiverProgressSnapshot,
}

/// One control action to send to one bonded donor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BondedReceiverFeedbackAction {
    /// Ask one donor for missing systematic/source ESIs first.
    SourceFirstNeedMore {
        /// Donor control connection that should receive the request.
        donor_index: u32,
        /// Missing source symbols for one source block.
        holes: BondedBlockSourceHoles,
    },
    /// Ask one donor for generic repair symbols for one source block.
    RepairNeedMore {
        /// Donor control connection that should receive the request.
        donor_index: u32,
        /// Aggregate block deficit after cross-donor deduplication.
        coverage: BondedBlockCoverage,
    },
    /// Tell one donor to stop spraying a verified-complete transfer.
    Close {
        /// Donor control connection that should receive the close.
        donor_index: u32,
    },
}

/// Per-donor metrics exposed by the bonded receiver progress snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BondedDonorProgressMetrics {
    /// Donor these counters describe.
    pub donor_index: u32,
    /// Raw ingress counters for this donor.
    pub stats: BondedDonorIngressStats,
    /// Duplicate rate for this donor in parts-per-million.
    pub duplicate_rate_ppm: u64,
}

/// Receiver completion path for one source block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BondedBlockCompletionPath {
    /// The block still needs more symbols before decode/commit.
    Incomplete,
    /// All systematic/source symbols are present; receiver can stay memcpy-only.
    SourceMemcpy,
    /// Enough symbols are present, but repair/FEC decode is needed for source holes.
    RepairDecode,
}

/// Machine-readable per-block receiver progress row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BondedBlockProgressMetrics {
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
    /// Number of systematic/source ESIs for this block.
    pub source_symbols: u32,
    /// Source ESIs still missing after global cross-donor deduplication.
    pub missing_source_esis: Vec<u32>,
    /// Completion path implied by aggregate coverage and source holes.
    pub completion_path: BondedBlockCompletionPath,
}

impl BondedBlockProgressMetrics {
    /// Count missing systematic/source symbols for this block.
    #[must_use]
    pub fn missing_source_count(&self) -> usize {
        self.missing_source_esis.len()
    }

    /// True when this row represents a block that still needs receiver feedback.
    #[must_use]
    pub const fn needs_more_symbols(&self) -> bool {
        self.deficit_symbols > 0
    }
}

/// Machine-readable bonded receiver progress snapshot for SDK/CLI/trace consumers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BondedReceiverLiveProgressMetrics {
    /// Aggregate symbol ingress counters.
    pub aggregate: BondedReceiverIngressStats,
    /// Sorted per-donor ingress counters.
    pub donors: Vec<BondedDonorProgressMetrics>,
    /// Per-block coverage and completion-path rows.
    pub blocks: Vec<BondedBlockProgressMetrics>,
    /// Blocks that can complete through source memcpy.
    pub source_memcpy_blocks: usize,
    /// Blocks that are symbol-complete but need repair/FEC decode.
    pub repair_decode_blocks: usize,
    /// Blocks still below their accepted-symbol target.
    pub incomplete_blocks: usize,
    /// Sum of all incomplete block deficits.
    pub total_deficit_symbols: u64,
    /// Sum of all missing systematic/source ESIs.
    pub total_missing_source_symbols: u64,
    /// Per-donor feedback frames materialized by the current aggregate plan.
    pub feedback_action_count: usize,
    /// Per-donor NeedMore frames materialized by the current aggregate plan.
    pub need_more_action_count: usize,
    /// Per-donor Close frames materialized by the current aggregate plan.
    pub close_action_count: usize,
}

impl BondedReceiverFeedbackPlan {
    /// True when there is no feedback to broadcast.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        !self.should_broadcast_need_more() && !self.should_broadcast_close()
    }

    /// True when at least one donor target should receive a NeedMore frame.
    #[must_use]
    pub fn should_broadcast_need_more(&self) -> bool {
        !self.donor_targets.is_empty()
            && (!self.source_first_need_more.is_empty() || !self.need_more.is_empty())
    }

    /// True when NeedMore should ask for missing systematic/source ESIs first.
    #[must_use]
    pub fn should_broadcast_source_first_need_more(&self) -> bool {
        !self.donor_targets.is_empty() && !self.source_first_need_more.is_empty()
    }

    /// True when NeedMore should fall back to generic repair deficits.
    #[must_use]
    pub fn should_broadcast_repair_need_more(&self) -> bool {
        !self.donor_targets.is_empty() && !self.need_more.is_empty()
    }

    /// True when at least one donor target should receive ObjectComplete/Close.
    #[must_use]
    pub fn should_broadcast_close(&self) -> bool {
        self.close && !self.donor_targets.is_empty()
    }

    /// Materialize the per-donor control fan-out for this aggregate plan.
    ///
    /// Close wins over stale deficits: once the object is verified complete,
    /// every donor receives exactly one close action and no donor receives
    /// another `NeedMore`.
    #[must_use]
    pub fn broadcast_actions(&self) -> Vec<BondedReceiverFeedbackAction> {
        if self.should_broadcast_close() {
            return self
                .donor_targets
                .iter()
                .copied()
                .map(|donor_index| BondedReceiverFeedbackAction::Close { donor_index })
                .collect();
        }

        if !self.should_broadcast_need_more() {
            return Vec::new();
        }

        let mut actions = Vec::new();
        for donor_index in self.donor_targets.iter().copied() {
            actions.extend(self.source_first_need_more.iter().cloned().map(|holes| {
                BondedReceiverFeedbackAction::SourceFirstNeedMore { donor_index, holes }
            }));
            actions.extend(self.need_more.iter().copied().map(|coverage| {
                BondedReceiverFeedbackAction::RepairNeedMore {
                    donor_index,
                    coverage,
                }
            }));
        }
        actions
    }
}

/// Receiver-side C2 registry for authenticated donor symbols.
#[derive(Debug, Clone, Default)]
pub struct BondedReceiverSymbolSet {
    seen: BTreeSet<BondedSymbolKey>,
    source_seen: BTreeSet<BondedSymbolKey>,
    donor_stats: BTreeMap<u32, BondedDonorIngressStats>,
    aggregate: BondedReceiverIngressStats,
}

impl BondedReceiverSymbolSet {
    /// Create an empty unified symbol set.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            seen: BTreeSet::new(),
            source_seen: BTreeSet::new(),
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
            let source_symbol = kind.is_source();
            if source_symbol {
                self.source_seen.insert(key);
            }
            donor.record_accepted(kind);
            self.aggregate.symbols_accepted = self.aggregate.symbols_accepted.saturating_add(1);
            if source_symbol {
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

    /// Sorted donor indexes that have contributed authenticated symbols.
    #[must_use]
    pub fn donor_targets(&self) -> Vec<u32> {
        self.donor_stats.keys().copied().collect()
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

    /// Return missing systematic/source ESIs for one block.
    ///
    /// B4 source-first feedback uses this before generic repair requests: repair
    /// ESIs can make the block decodable, but only source ESIs preserve the
    /// receiver's memcpy fast path. Duplicate donor retransmits are ignored by
    /// the shared `(object_id, sbn, esi)` set before holes are computed.
    #[must_use]
    pub fn block_source_holes(
        &self,
        object_id: ObjectId,
        sbn: u8,
        source_symbols: u32,
    ) -> BondedBlockSourceHoles {
        let missing_source_esis = (0..source_symbols)
            .filter(|esi| {
                !self
                    .source_seen
                    .contains(&BondedSymbolKey::new(object_id, sbn, *esi))
            })
            .collect();

        BondedBlockSourceHoles {
            object_id,
            sbn,
            source_symbols,
            missing_source_esis,
        }
    }

    /// Return only blocks that still need systematic/source retransmits.
    #[must_use]
    pub fn blocks_with_source_holes(
        &self,
        blocks: impl IntoIterator<Item = (ObjectId, u8, u32)>,
    ) -> Vec<BondedBlockSourceHoles> {
        blocks
            .into_iter()
            .map(|(object_id, sbn, source_symbols)| {
                self.block_source_holes(object_id, sbn, source_symbols)
            })
            .filter(|holes| !holes.is_source_complete())
            .collect()
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

    /// Build a live progress snapshot over the receiver's expected blocks.
    #[must_use]
    pub fn progress_snapshot(
        &self,
        blocks: impl IntoIterator<Item = (ObjectId, u8, u32)>,
    ) -> BondedReceiverProgressSnapshot {
        let mut total_blocks = 0usize;
        let mut complete_blocks = 0usize;
        let mut total_deficit_symbols = 0u64;

        for (object_id, sbn, target_symbols) in blocks {
            total_blocks = total_blocks.saturating_add(1);
            let coverage = self.block_coverage(object_id, sbn, target_symbols);
            if coverage.is_complete() {
                complete_blocks = complete_blocks.saturating_add(1);
            } else {
                total_deficit_symbols =
                    total_deficit_symbols.saturating_add(u64::from(coverage.deficit_symbols));
            }
        }

        BondedReceiverProgressSnapshot {
            aggregate: self.aggregate,
            total_blocks,
            complete_blocks,
            incomplete_blocks: total_blocks.saturating_sub(complete_blocks),
            total_deficit_symbols,
        }
    }

    /// Build a machine-readable progress row for one source block.
    #[must_use]
    pub fn block_progress_metrics(
        &self,
        object_id: ObjectId,
        sbn: u8,
        target_symbols: u32,
    ) -> BondedBlockProgressMetrics {
        let coverage = self.block_coverage(object_id, sbn, target_symbols);
        let source_holes = self.block_source_holes(object_id, sbn, target_symbols);
        let completion_path = if !coverage.is_complete() {
            BondedBlockCompletionPath::Incomplete
        } else if source_holes.is_source_complete() {
            BondedBlockCompletionPath::SourceMemcpy
        } else {
            BondedBlockCompletionPath::RepairDecode
        };

        BondedBlockProgressMetrics {
            object_id,
            sbn,
            target_symbols: coverage.target_symbols,
            accepted_symbols: coverage.accepted_symbols,
            deficit_symbols: coverage.deficit_symbols,
            source_symbols: source_holes.source_symbols,
            missing_source_esis: source_holes.missing_source_esis,
            completion_path,
        }
    }

    /// Build the bonded receiver's live progress metrics.
    ///
    /// This is the C5 handoff for structured trace/SDK/CLI consumers: one
    /// deterministic snapshot carries sorted per-donor counters, per-block
    /// coverage/source-hole rows, source-vs-repair completion counters, and the
    /// current aggregate feedback fan-out size.
    #[must_use]
    pub fn live_progress_metrics(
        &self,
        blocks: impl IntoIterator<Item = (ObjectId, u8, u32)>,
        object_verified_complete: bool,
    ) -> BondedReceiverLiveProgressMetrics {
        let block_list: Vec<_> = blocks.into_iter().collect();
        let block_metrics: Vec<_> = block_list
            .iter()
            .copied()
            .map(|(object_id, sbn, target_symbols)| {
                self.block_progress_metrics(object_id, sbn, target_symbols)
            })
            .collect();

        let mut source_memcpy_blocks = 0usize;
        let mut repair_decode_blocks = 0usize;
        let mut incomplete_blocks = 0usize;
        let mut total_deficit_symbols = 0u64;
        let mut total_missing_source_symbols = 0u64;
        for block in &block_metrics {
            match block.completion_path {
                BondedBlockCompletionPath::Incomplete => {
                    incomplete_blocks = incomplete_blocks.saturating_add(1);
                }
                BondedBlockCompletionPath::SourceMemcpy => {
                    source_memcpy_blocks = source_memcpy_blocks.saturating_add(1);
                }
                BondedBlockCompletionPath::RepairDecode => {
                    repair_decode_blocks = repair_decode_blocks.saturating_add(1);
                }
            }
            total_deficit_symbols =
                total_deficit_symbols.saturating_add(u64::from(block.deficit_symbols));
            total_missing_source_symbols = total_missing_source_symbols
                .saturating_add(block.missing_source_count().min(u64::MAX as usize) as u64);
        }

        let feedback_actions = self
            .feedback_broadcast_plan(block_list.iter().copied(), object_verified_complete)
            .broadcast_actions();
        let mut need_more_action_count = 0usize;
        let mut close_action_count = 0usize;
        for action in &feedback_actions {
            match action {
                BondedReceiverFeedbackAction::SourceFirstNeedMore { .. }
                | BondedReceiverFeedbackAction::RepairNeedMore { .. } => {
                    need_more_action_count = need_more_action_count.saturating_add(1);
                }
                BondedReceiverFeedbackAction::Close { .. } => {
                    close_action_count = close_action_count.saturating_add(1);
                }
            }
        }

        BondedReceiverLiveProgressMetrics {
            aggregate: self.aggregate,
            donors: self
                .donor_stats
                .iter()
                .map(|(&donor_index, &stats)| BondedDonorProgressMetrics {
                    donor_index,
                    stats,
                    duplicate_rate_ppm: stats.duplicate_rate_ppm(),
                })
                .collect(),
            blocks: block_metrics,
            source_memcpy_blocks,
            repair_decode_blocks,
            incomplete_blocks,
            total_deficit_symbols,
            total_missing_source_symbols,
            feedback_action_count: feedback_actions.len(),
            need_more_action_count,
            close_action_count,
        }
    }

    /// Compute aggregate feedback that should be broadcast to every donor.
    ///
    /// `object_verified_complete` is the receiver's fail-closed byte/object
    /// verification result. Once true, Close wins over any stale per-block
    /// deficit so no donor keeps spraying into a completed transfer.
    ///
    /// Missing systematic/source ESIs are reported separately from generic
    /// repair deficits. Control-plane callers should prefer
    /// `source_first_need_more` before falling back to `need_more` so clean and
    /// near-clean bonded transfers can complete through the memcpy source path
    /// instead of spending receiver CPU on RaptorQ repair decode.
    #[must_use]
    pub fn feedback_broadcast_plan(
        &self,
        blocks: impl IntoIterator<Item = (ObjectId, u8, u32)>,
        object_verified_complete: bool,
    ) -> BondedReceiverFeedbackPlan {
        let block_list: Vec<_> = blocks.into_iter().collect();
        let progress = self.progress_snapshot(block_list.iter().copied());
        let (source_first_need_more, need_more) = if object_verified_complete {
            (Vec::new(), Vec::new())
        } else {
            (
                self.blocks_with_source_holes(block_list.iter().copied()),
                self.blocks_needing_more(block_list.iter().copied()),
            )
        };

        BondedReceiverFeedbackPlan {
            donor_targets: self.donor_targets(),
            source_first_need_more,
            need_more,
            close: object_verified_complete,
            progress,
        }
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
        set.record_key(1, BondedSymbolKey::new(object_id, 1, 2), SymbolKind::Repair);

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
    fn progress_snapshot_summarizes_block_completion_and_deficit() {
        let mut set = BondedReceiverSymbolSet::new();
        let object_id = ObjectId::new_for_test(19);
        set.record_key(0, BondedSymbolKey::new(object_id, 0, 0), SymbolKind::Source);
        set.record_key(1, BondedSymbolKey::new(object_id, 0, 2), SymbolKind::Repair);
        set.record_key(2, BondedSymbolKey::new(object_id, 1, 0), SymbolKind::Source);
        set.record_key(3, BondedSymbolKey::new(object_id, 1, 0), SymbolKind::Source);

        let snapshot = set.progress_snapshot([(object_id, 0, 2), (object_id, 1, 3)]);

        assert_eq!(snapshot.aggregate.symbols_received, 4);
        assert_eq!(snapshot.aggregate.symbols_accepted, 3);
        assert_eq!(snapshot.aggregate.duplicate_symbols, 1);
        assert_eq!(snapshot.duplicate_rate_ppm(), 250_000);
        assert_eq!(snapshot.total_blocks, 2);
        assert_eq!(snapshot.complete_blocks, 1);
        assert_eq!(snapshot.incomplete_blocks, 1);
        assert_eq!(snapshot.total_deficit_symbols, 2);
        assert!(!snapshot.is_complete());
    }

    #[test]
    fn progress_snapshot_with_no_blocks_is_complete() {
        let set = BondedReceiverSymbolSet::new();
        let snapshot = set.progress_snapshot(std::iter::empty::<(ObjectId, u8, u32)>());

        assert_eq!(snapshot.total_blocks, 0);
        assert_eq!(snapshot.complete_blocks, 0);
        assert_eq!(snapshot.incomplete_blocks, 0);
        assert_eq!(snapshot.total_deficit_symbols, 0);
        assert!(snapshot.is_complete());
    }

    #[test]
    fn live_progress_metrics_reports_donors_blocks_paths_and_feedback_counts() {
        let mut set = BondedReceiverSymbolSet::new();
        let object_id = ObjectId::new_for_test(21);

        set.record_key(0, BondedSymbolKey::new(object_id, 0, 0), SymbolKind::Source);
        set.record_key(1, BondedSymbolKey::new(object_id, 0, 1), SymbolKind::Source);
        set.record_key(2, BondedSymbolKey::new(object_id, 0, 3), SymbolKind::Repair);
        set.record_key(3, BondedSymbolKey::new(object_id, 0, 1), SymbolKind::Source);
        set.record_key(0, BondedSymbolKey::new(object_id, 1, 0), SymbolKind::Source);

        let metrics = set.live_progress_metrics([(object_id, 0, 3), (object_id, 1, 2)], false);

        assert_eq!(metrics.aggregate.symbols_received, 5);
        assert_eq!(metrics.aggregate.symbols_accepted, 4);
        assert_eq!(metrics.aggregate.duplicate_symbols, 1);
        assert_eq!(metrics.aggregate.source_symbols_accepted, 3);
        assert_eq!(metrics.aggregate.repair_symbols_accepted, 1);
        assert_eq!(
            metrics
                .donors
                .iter()
                .map(|donor| donor.donor_index)
                .collect::<Vec<_>>(),
            vec![0, 1, 2, 3]
        );
        assert_eq!(metrics.donors[3].stats.duplicate_symbols, 1);
        assert_eq!(metrics.donors[3].duplicate_rate_ppm, 1_000_000);

        assert_eq!(metrics.blocks.len(), 2);
        assert_eq!(metrics.blocks[0].accepted_symbols, 3);
        assert_eq!(metrics.blocks[0].deficit_symbols, 0);
        assert_eq!(metrics.blocks[0].missing_source_esis, vec![2]);
        assert_eq!(
            metrics.blocks[0].completion_path,
            BondedBlockCompletionPath::RepairDecode
        );
        assert_eq!(metrics.blocks[1].accepted_symbols, 1);
        assert_eq!(metrics.blocks[1].deficit_symbols, 1);
        assert_eq!(metrics.blocks[1].missing_source_esis, vec![1]);
        assert_eq!(
            metrics.blocks[1].completion_path,
            BondedBlockCompletionPath::Incomplete
        );

        assert_eq!(metrics.source_memcpy_blocks, 0);
        assert_eq!(metrics.repair_decode_blocks, 1);
        assert_eq!(metrics.incomplete_blocks, 1);
        assert_eq!(metrics.total_deficit_symbols, 1);
        assert_eq!(metrics.total_missing_source_symbols, 2);
        assert_eq!(metrics.feedback_action_count, 12);
        assert_eq!(metrics.need_more_action_count, 12);
        assert_eq!(metrics.close_action_count, 0);
    }

    #[test]
    fn feedback_plan_broadcasts_aggregate_need_more_to_all_donors() {
        let mut set = BondedReceiverSymbolSet::new();
        let object_id = ObjectId::new_for_test(23);

        set.record_key(2, BondedSymbolKey::new(object_id, 0, 0), SymbolKind::Source);
        set.record_key(0, BondedSymbolKey::new(object_id, 0, 2), SymbolKind::Repair);
        set.record_key(1, BondedSymbolKey::new(object_id, 1, 0), SymbolKind::Source);
        set.record_key(2, BondedSymbolKey::new(object_id, 1, 0), SymbolKind::Source);

        let plan = set.feedback_broadcast_plan([(object_id, 0, 2), (object_id, 1, 3)], false);

        assert_eq!(plan.donor_targets, vec![0, 1, 2]);
        assert_eq!(
            plan.source_first_need_more,
            vec![
                BondedBlockSourceHoles {
                    object_id,
                    sbn: 0,
                    source_symbols: 2,
                    missing_source_esis: vec![1],
                },
                BondedBlockSourceHoles {
                    object_id,
                    sbn: 1,
                    source_symbols: 3,
                    missing_source_esis: vec![1, 2],
                },
            ]
        );
        assert_eq!(
            plan.need_more,
            vec![BondedBlockCoverage {
                object_id,
                sbn: 1,
                target_symbols: 3,
                accepted_symbols: 1,
                deficit_symbols: 2,
            }]
        );
        assert!(!plan.close);
        assert!(plan.should_broadcast_need_more());
        assert!(plan.should_broadcast_source_first_need_more());
        assert!(plan.should_broadcast_repair_need_more());
        assert!(!plan.should_broadcast_close());
        assert_eq!(plan.progress.total_deficit_symbols, 2);
    }

    #[test]
    fn feedback_plan_materializes_need_more_actions_for_every_donor() {
        let mut set = BondedReceiverSymbolSet::new();
        let object_id = ObjectId::new_for_test(24);

        set.record_key(2, BondedSymbolKey::new(object_id, 0, 0), SymbolKind::Source);
        set.record_key(0, BondedSymbolKey::new(object_id, 0, 3), SymbolKind::Repair);

        let plan = set.feedback_broadcast_plan([(object_id, 0, 3)], false);
        let source_holes = BondedBlockSourceHoles {
            object_id,
            sbn: 0,
            source_symbols: 3,
            missing_source_esis: vec![1, 2],
        };
        let repair_deficit = BondedBlockCoverage {
            object_id,
            sbn: 0,
            target_symbols: 3,
            accepted_symbols: 2,
            deficit_symbols: 1,
        };

        assert_eq!(
            plan.broadcast_actions(),
            vec![
                BondedReceiverFeedbackAction::SourceFirstNeedMore {
                    donor_index: 0,
                    holes: source_holes.clone(),
                },
                BondedReceiverFeedbackAction::RepairNeedMore {
                    donor_index: 0,
                    coverage: repair_deficit,
                },
                BondedReceiverFeedbackAction::SourceFirstNeedMore {
                    donor_index: 2,
                    holes: source_holes,
                },
                BondedReceiverFeedbackAction::RepairNeedMore {
                    donor_index: 2,
                    coverage: repair_deficit,
                },
            ]
        );
    }

    #[test]
    fn feedback_plan_prefers_source_holes_even_when_repairs_meet_target() {
        let mut set = BondedReceiverSymbolSet::new();
        let object_id = ObjectId::new_for_test(27);

        set.record_key(0, BondedSymbolKey::new(object_id, 0, 0), SymbolKind::Source);
        set.record_key(1, BondedSymbolKey::new(object_id, 0, 3), SymbolKind::Repair);
        set.record_key(2, BondedSymbolKey::new(object_id, 0, 4), SymbolKind::Repair);

        let plan = set.feedback_broadcast_plan([(object_id, 0, 3)], false);

        assert_eq!(plan.donor_targets, vec![0, 1, 2]);
        assert_eq!(
            plan.source_first_need_more,
            vec![BondedBlockSourceHoles {
                object_id,
                sbn: 0,
                source_symbols: 3,
                missing_source_esis: vec![1, 2],
            }]
        );
        assert!(plan.need_more.is_empty());
        assert!(plan.progress.is_complete());
        assert!(plan.should_broadcast_need_more());
        assert!(plan.should_broadcast_source_first_need_more());
        assert!(!plan.should_broadcast_repair_need_more());
        assert!(!plan.is_idle());
    }

    #[test]
    fn feedback_plan_close_suppresses_stale_need_more() {
        let mut set = BondedReceiverSymbolSet::new();
        let object_id = ObjectId::new_for_test(29);

        set.record_key(1, BondedSymbolKey::new(object_id, 0, 0), SymbolKind::Source);
        set.record_key(0, BondedSymbolKey::new(object_id, 0, 4), SymbolKind::Repair);

        let plan = set.feedback_broadcast_plan([(object_id, 0, 4)], true);

        assert_eq!(plan.donor_targets, vec![0, 1]);
        assert!(plan.source_first_need_more.is_empty());
        assert!(plan.need_more.is_empty());
        assert!(plan.close);
        assert!(!plan.should_broadcast_need_more());
        assert!(!plan.should_broadcast_source_first_need_more());
        assert!(!plan.should_broadcast_repair_need_more());
        assert!(plan.should_broadcast_close());
        assert_eq!(plan.progress.total_deficit_symbols, 2);
        assert_eq!(
            plan.broadcast_actions(),
            vec![
                BondedReceiverFeedbackAction::Close { donor_index: 0 },
                BondedReceiverFeedbackAction::Close { donor_index: 1 },
            ]
        );

        let metrics = set.live_progress_metrics([(object_id, 0, 4)], true);
        assert_eq!(metrics.feedback_action_count, 2);
        assert_eq!(metrics.need_more_action_count, 0);
        assert_eq!(metrics.close_action_count, 2);
    }

    #[test]
    fn feedback_plan_without_donor_targets_is_not_broadcastable() {
        let set = BondedReceiverSymbolSet::new();
        let object_id = ObjectId::new_for_test(31);
        let plan = set.feedback_broadcast_plan([(object_id, 0, 1)], false);

        assert!(plan.donor_targets.is_empty());
        assert_eq!(plan.source_first_need_more.len(), 1);
        assert_eq!(plan.need_more.len(), 1);
        assert!(!plan.should_broadcast_need_more());
        assert!(!plan.should_broadcast_source_first_need_more());
        assert!(!plan.should_broadcast_repair_need_more());
        assert!(!plan.should_broadcast_close());
        assert_eq!(plan.progress.total_deficit_symbols, 1);
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
    fn source_holes_ignore_repair_symbols_and_duplicates() {
        let mut set = BondedReceiverSymbolSet::new();
        let object_id = ObjectId::new_for_test(37);

        set.record_key(0, BondedSymbolKey::new(object_id, 0, 0), SymbolKind::Source);
        set.record_key(1, BondedSymbolKey::new(object_id, 0, 0), SymbolKind::Source);
        set.record_key(2, BondedSymbolKey::new(object_id, 0, 3), SymbolKind::Repair);

        let holes = set.block_source_holes(object_id, 0, 3);

        assert_eq!(
            holes,
            BondedBlockSourceHoles {
                object_id,
                sbn: 0,
                source_symbols: 3,
                missing_source_esis: vec![1, 2],
            }
        );
        assert!(!holes.is_source_complete());
        assert_eq!(holes.missing_source_count(), 2);

        set.record_key(0, BondedSymbolKey::new(object_id, 0, 1), SymbolKind::Source);
        set.record_key(1, BondedSymbolKey::new(object_id, 0, 2), SymbolKind::Source);

        assert!(set.block_source_holes(object_id, 0, 3).is_source_complete());
    }

    #[test]
    fn blocks_with_source_holes_filters_complete_blocks() {
        let mut set = BondedReceiverSymbolSet::new();
        let object_id = ObjectId::new_for_test(41);

        set.record_key(0, BondedSymbolKey::new(object_id, 0, 0), SymbolKind::Source);
        set.record_key(1, BondedSymbolKey::new(object_id, 0, 1), SymbolKind::Source);
        set.record_key(0, BondedSymbolKey::new(object_id, 1, 0), SymbolKind::Source);

        let holes = set.blocks_with_source_holes([(object_id, 0, 2), (object_id, 1, 2)]);

        assert_eq!(
            holes,
            vec![BondedBlockSourceHoles {
                object_id,
                sbn: 1,
                source_symbols: 2,
                missing_source_esis: vec![1],
            }]
        );
    }

    #[test]
    fn empty_set_reports_zero_duplicate_rate() {
        let set = BondedReceiverSymbolSet::new();

        assert!(set.is_empty());
        assert_eq!(set.aggregate_stats().duplicate_rate_ppm(), 0);
        assert_eq!(set.donor_stats(0), None);
    }
}
