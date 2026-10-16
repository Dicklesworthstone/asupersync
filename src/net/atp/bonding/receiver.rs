//! Channel bonding Phase C2 — one receiver-side symbol set for all donors.
//!
//! Donors in a bonded transfer spray authenticated RaptorQ symbols to the same
//! receiver endpoint. Correctness depends on the receiver treating every symbol
//! as part of one fungible decoder input stream keyed only by
//! `(object_id, sbn, esi)`. The donor id is useful for observability, but it must
//! not partition the decoder state. If two donors deliver the same key, the
//! second symbol is duplicate bandwidth and is dropped before decode.

use std::collections::{BTreeMap, BTreeSet};

use crate::cx::Cx;
use crate::types::{ObjectId, Symbol, SymbolId, SymbolKind};

/// Environment variable that enables human-readable bonded receiver trace lines.
pub const ATP_BOND_TRACE_ENV: &str = "ATP_BOND_TRACE";

/// Structured trace event emitted for bonded receiver live progress.
pub const BONDING_RECEIVER_PROGRESS_TRACE_EVENT: &str = "atp_bond.receiver.progress";

/// Companion trace event carrying per-block outcomes and action counts.
///
/// Split from the progress event so each stays within the correlation-safe
/// field budget: `LogEntry` caps at 16 fields and prioritized
/// task/region/span ids evict the oldest fields of a full entry
/// (br-asupersync-an0t8o).
pub const BONDING_RECEIVER_OUTCOMES_TRACE_EVENT: &str = "atp_bond.receiver.outcomes";

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
    /// Novel symbols dropped by the bounded receiver-retention policy.
    pub symbols_rejected_by_retention: u64,
}

impl BondedDonorIngressStats {
    fn record_received(&mut self) {
        self.symbols_received = self.symbols_received.saturating_add(1);
    }

    fn record_duplicate(&mut self) {
        self.duplicate_symbols = self.duplicate_symbols.saturating_add(1);
    }

    fn record_retention_reject(&mut self) {
        self.symbols_rejected_by_retention = self.symbols_rejected_by_retention.saturating_add(1);
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
    /// Novel symbols dropped by the bounded receiver-retention policy.
    pub symbols_rejected_by_retention: u64,
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
    /// The key was novel but rejected before retention would exceed the policy.
    RejectedByRetention {
        /// Symbol that was dropped.
        key: BondedSymbolKey,
        /// Memory-retention limit that rejected the symbol.
        reason: BondedReceiverRetentionRejectReason,
    },
}

/// Bounded receiver-retention policy for the shared bonded symbol set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BondedReceiverRetentionPolicy {
    /// Maximum retained unique symbols for one `(object_id, sbn)` block.
    pub max_symbols_per_block: Option<u32>,
    /// Maximum retained unique symbols across the whole bonded receiver set.
    pub max_total_symbols: Option<usize>,
}

impl BondedReceiverRetentionPolicy {
    /// No retention cap; preserves the original C2 receiver behavior.
    #[must_use]
    pub const fn unbounded() -> Self {
        Self {
            max_symbols_per_block: None,
            max_total_symbols: None,
        }
    }

    /// Build a policy with both per-block and transfer-wide retention caps.
    #[must_use]
    pub const fn bounded(max_symbols_per_block: u32, max_total_symbols: usize) -> Self {
        Self {
            max_symbols_per_block: Some(max_symbols_per_block),
            max_total_symbols: Some(max_total_symbols),
        }
    }
}

/// Why a bounded receiver-retention policy rejected a novel symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BondedReceiverRetentionRejectReason {
    /// Accepting the symbol would exceed the per-block retained-symbol cap.
    BlockSymbolCap,
    /// Accepting the symbol would exceed the transfer-wide retained-symbol cap.
    TransferSymbolCap,
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

impl BondedBlockCompletionPath {
    /// Stable trace/display token for this completion path.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Incomplete => "incomplete",
            Self::SourceMemcpy => "source_memcpy",
            Self::RepairDecode => "repair_decode",
        }
    }
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

impl BondedReceiverLiveProgressMetrics {
    /// Aggregate duplicate rate in parts-per-million.
    #[must_use]
    pub fn duplicate_rate_ppm(&self) -> u64 {
        self.aggregate.duplicate_rate_ppm()
    }

    /// Emit the structured progress event and, when `ATP_BOND_TRACE` is set, a
    /// deterministic human-readable receiver timeline.
    pub fn trace_progress(&self, cx: &Cx, phase: &str) {
        let donors = self.donors.len().to_string();
        let blocks = self.blocks.len().to_string();
        let symbols_received = self.aggregate.symbols_received.to_string();
        let symbols_accepted = self.aggregate.symbols_accepted.to_string();
        let duplicate_symbols = self.aggregate.duplicate_symbols.to_string();
        let duplicate_rate_ppm = self.duplicate_rate_ppm().to_string();
        let source_symbols_accepted = self.aggregate.source_symbols_accepted.to_string();
        let repair_symbols_accepted = self.aggregate.repair_symbols_accepted.to_string();
        let retention_rejects = self.aggregate.symbols_rejected_by_retention.to_string();
        let source_memcpy_blocks = self.source_memcpy_blocks.to_string();
        let repair_decode_blocks = self.repair_decode_blocks.to_string();
        let incomplete_blocks = self.incomplete_blocks.to_string();
        let total_deficit_symbols = self.total_deficit_symbols.to_string();
        let total_missing_source_symbols = self.total_missing_source_symbols.to_string();
        let feedback_action_count = self.feedback_action_count.to_string();
        let need_more_action_count = self.need_more_action_count.to_string();
        let close_action_count = self.close_action_count.to_string();
        cx.trace_with_fields(
            BONDING_RECEIVER_PROGRESS_TRACE_EVENT,
            &[
                ("phase", phase),
                ("donors", donors.as_str()),
                ("blocks", blocks.as_str()),
                ("symbols_received", symbols_received.as_str()),
                ("symbols_accepted", symbols_accepted.as_str()),
                ("duplicate_symbols", duplicate_symbols.as_str()),
                ("duplicate_rate_ppm", duplicate_rate_ppm.as_str()),
                ("source_symbols_accepted", source_symbols_accepted.as_str()),
                ("repair_symbols_accepted", repair_symbols_accepted.as_str()),
                ("retention_rejects", retention_rejects.as_str()),
            ],
        );
        cx.trace_with_fields(
            BONDING_RECEIVER_OUTCOMES_TRACE_EVENT,
            &[
                ("phase", phase),
                ("source_memcpy_blocks", source_memcpy_blocks.as_str()),
                ("repair_decode_blocks", repair_decode_blocks.as_str()),
                ("incomplete_blocks", incomplete_blocks.as_str()),
                ("total_deficit_symbols", total_deficit_symbols.as_str()),
                (
                    "total_missing_source_symbols",
                    total_missing_source_symbols.as_str(),
                ),
                ("feedback_actions", feedback_action_count.as_str()),
                ("need_more_actions", need_more_action_count.as_str()),
                ("close_actions", close_action_count.as_str()),
            ],
        );

        if std::env::var_os(ATP_BOND_TRACE_ENV).is_some() {
            for line in self.trace_lines(phase) {
                eprintln!("[ATP_BOND_TRACE] {line}");
            }
        }
    }

    /// Deterministic human timeline rows for tests, logs, and diagnostic UIs.
    #[must_use]
    pub fn trace_lines(&self, phase: &str) -> Vec<String> {
        let mut lines = Vec::with_capacity(
            1usize
                .saturating_add(self.donors.len())
                .saturating_add(self.blocks.len()),
        );
        lines.push(format!(
            "receiver phase={phase} donors={} blocks={} accepted={}/{} duplicate_rate_ppm={} source={} repair={} retention_rejects={} source_memcpy_blocks={} repair_decode_blocks={} incomplete_blocks={} total_deficit_symbols={} missing_source_symbols={} feedback_actions={} need_more_actions={} close_actions={}",
            self.donors.len(),
            self.blocks.len(),
            self.aggregate.symbols_accepted,
            self.aggregate.symbols_received,
            self.duplicate_rate_ppm(),
            self.aggregate.source_symbols_accepted,
            self.aggregate.repair_symbols_accepted,
            self.aggregate.symbols_rejected_by_retention,
            self.source_memcpy_blocks,
            self.repair_decode_blocks,
            self.incomplete_blocks,
            self.total_deficit_symbols,
            self.total_missing_source_symbols,
            self.feedback_action_count,
            self.need_more_action_count,
            self.close_action_count,
        ));
        for donor in &self.donors {
            lines.push(format!(
                "receiver donor={} received={} accepted={} duplicates={} duplicate_rate_ppm={} source={} repair={} retention_rejects={}",
                donor.donor_index,
                donor.stats.symbols_received,
                donor.stats.symbols_accepted,
                donor.stats.duplicate_symbols,
                donor.duplicate_rate_ppm,
                donor.stats.source_symbols_accepted,
                donor.stats.repair_symbols_accepted,
                donor.stats.symbols_rejected_by_retention,
            ));
        }
        for block in &self.blocks {
            lines.push(format!(
                "receiver block object={:?} sbn={} target={} accepted={} deficit={} source_symbols={} missing_source={} completion_path={}",
                block.object_id,
                block.sbn,
                block.target_symbols,
                block.accepted_symbols,
                block.deficit_symbols,
                block.source_symbols,
                block.missing_source_count(),
                block.completion_path.as_str(),
            ));
        }
        lines
    }
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
    /// Retained unique symbols per `(object_id, sbn)`, kept in step with
    /// `seen` so the per-block retention check on every novel symbol is a
    /// lookup rather than a scan of every symbol retained so far (which made
    /// a bounded transfer quadratic in its symbol count).
    block_symbol_counts: BTreeMap<(ObjectId, u8), u32>,
    donor_stats: BTreeMap<u32, BondedDonorIngressStats>,
    auth_rejections_by_donor: BTreeMap<u32, u64>,
    aggregate: BondedReceiverIngressStats,
}

impl BondedReceiverSymbolSet {
    /// Create an empty unified symbol set.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            seen: BTreeSet::new(),
            source_seen: BTreeSet::new(),
            block_symbol_counts: BTreeMap::new(),
            donor_stats: BTreeMap::new(),
            auth_rejections_by_donor: BTreeMap::new(),
            aggregate: BondedReceiverIngressStats {
                symbols_received: 0,
                symbols_accepted: 0,
                duplicate_symbols: 0,
                source_symbols_accepted: 0,
                repair_symbols_accepted: 0,
                symbols_rejected_by_retention: 0,
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
        self.record_key_with_retention(
            donor_index,
            key,
            kind,
            BondedReceiverRetentionPolicy::unbounded(),
        )
    }

    /// Record an authenticated bonded key under a bounded retention policy.
    ///
    /// Duplicate keys are detected before retention checks, so duplicate donor
    /// retransmits never consume memory and remain observable as duplicates even
    /// when the block or transfer is at capacity. Novel over-cap symbols are
    /// rejected before they enter `seen`/`source_seen`, preserving a hard bound
    /// for callers that opt into this path.
    pub fn record_key_with_retention(
        &mut self,
        donor_index: u32,
        key: BondedSymbolKey,
        kind: SymbolKind,
        retention: BondedReceiverRetentionPolicy,
    ) -> BondedSymbolDisposition {
        let duplicate = self.seen.contains(&key);
        let retention_reject_reason = if duplicate {
            None
        } else {
            self.retention_reject_reason(key, retention)
        };

        let was_new_donor = !self.donor_stats.contains_key(&donor_index);
        let donor = self.donor_stats.entry(donor_index).or_default();
        if was_new_donor {
            self.aggregate.donor_count += 1;
        }

        donor.record_received();
        self.aggregate.symbols_received = self.aggregate.symbols_received.saturating_add(1);

        if duplicate {
            donor.record_duplicate();
            self.aggregate.duplicate_symbols = self.aggregate.duplicate_symbols.saturating_add(1);
            BondedSymbolDisposition::Duplicate(key)
        } else if let Some(reason) = retention_reject_reason {
            donor.record_retention_reject();
            self.aggregate.symbols_rejected_by_retention = self
                .aggregate
                .symbols_rejected_by_retention
                .saturating_add(1);
            BondedSymbolDisposition::RejectedByRetention { key, reason }
        } else {
            self.seen.insert(key);
            let block_count = self
                .block_symbol_counts
                .entry((key.object_id, key.sbn))
                .or_insert(0);
            *block_count = block_count.saturating_add(1);
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
        }
    }

    fn retention_reject_reason(
        &self,
        key: BondedSymbolKey,
        retention: BondedReceiverRetentionPolicy,
    ) -> Option<BondedReceiverRetentionRejectReason> {
        if retention
            .max_total_symbols
            .is_some_and(|max_total| self.seen.len() >= max_total)
        {
            return Some(BondedReceiverRetentionRejectReason::TransferSymbolCap);
        }

        if retention
            .max_symbols_per_block
            .is_some_and(|max_block| self.block_symbol_count(key.object_id, key.sbn) >= max_block)
        {
            return Some(BondedReceiverRetentionRejectReason::BlockSymbolCap);
        }

        None
    }

    fn block_symbol_count(&self, object_id: ObjectId, sbn: u8) -> u32 {
        self.block_symbol_counts
            .get(&(object_id, sbn))
            .copied()
            .unwrap_or(0)
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

    /// Record one symbol rejected before authenticated ingress.
    ///
    /// This counter is deliberately separate from `donor_stats`: a sender
    /// that has not authenticated must not become a feedback target or inflate
    /// received/duplicate/retention accounting. The donor index is the
    /// receiver-owned ESI schedule attribution, not a cryptographic identity.
    pub(in crate::net::atp) fn record_auth_rejection(&mut self, donor_index: u32) -> u64 {
        let count = self
            .auth_rejections_by_donor
            .entry(donor_index)
            .or_default();
        *count = count.saturating_add(1);
        *count
    }

    /// Number of pre-ingress auth failures attributed to one ESI schedule.
    #[must_use]
    pub(in crate::net::atp) fn auth_rejected_symbols(&self, donor_index: u32) -> u64 {
        self.auth_rejections_by_donor
            .get(&donor_index)
            .copied()
            .unwrap_or(0)
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
#[path = "receiver_inline_tests.rs"]
mod tests;
