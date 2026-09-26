//! RaptorQ encoding for region state.
//!
//! Transforms region snapshots into erasure-coded symbols for
//! distribution to replicas using the deterministic RFC-grade pipeline.

use crate::config::EncodingConfig as PipelineEncodingConfig;
use crate::encoding::EncodingPipeline;
use crate::raptorq::systematic::SystematicParams;
use crate::types::Time;
use crate::types::resource::{PoolConfig, SymbolPool};
use crate::types::symbol::{ObjectId, ObjectParams, Symbol, SymbolId, SymbolKind};
use crate::util::DetRng;
use std::cmp::min;

use super::snapshot::RegionSnapshot;

// ---------------------------------------------------------------------------
// EncodingConfig
// ---------------------------------------------------------------------------

/// Configuration for state encoding.
#[derive(Debug, Clone)]
pub struct EncodingConfig {
    /// Symbol size in bytes.
    pub symbol_size: u16,
    /// Minimum total repair symbols to generate across all source blocks.
    pub min_repair_symbols: u16,
    /// Maximum source blocks (for large objects).
    pub max_source_blocks: u16,
    /// Total symbol overhead factor (e.g., 1.2 = at least 20% overhead).
    ///
    /// Must be finite and at least `1.0`. The total repair budget is the larger
    /// of `ceil(source_count * repair_overhead) - source_count` and the
    /// (possibly adaptive) minimum, distributed across the actual source
    /// blocks. A factor of `1.0` with a zero minimum enables source-only
    /// encoding when the adaptive policy does not raise that minimum.
    pub repair_overhead: f32,
    /// Optional replayable path-quality snapshot for adaptive block layout.
    pub path_quality: Option<PathQualitySnapshot>,
}

impl Default for EncodingConfig {
    fn default() -> Self {
        Self {
            symbol_size: 1280,
            min_repair_symbols: 4,
            max_source_blocks: 1,
            repair_overhead: 1.2,
            path_quality: None,
        }
    }
}

/// Stable policy identifier for the adaptive path-quality layout table.
pub const ADAPTIVE_BLOCK_LAYOUT_POLICY_ID: &str = "adaptive-block-layout-v1";

/// Stable policy identifier for the default static layout path.
pub const STATIC_BLOCK_LAYOUT_POLICY_ID: &str = "static-block-layout-v1";

/// Replayable quality snapshot used to derive adaptive RaptorQ block layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathQualitySnapshot {
    /// Round-trip-time EWMA in milliseconds.
    pub rtt_ewma_ms: u32,
    /// Packet-loss EWMA in permille, clamped to `0..=1000`.
    pub loss_ewma_permille: u16,
    /// Observed reorder depth in symbols.
    pub reorder_depth: u16,
}

impl PathQualitySnapshot {
    /// Creates a new bounded path-quality snapshot.
    #[must_use]
    pub fn new(rtt_ewma_ms: u32, loss_ewma_permille: u16, reorder_depth: u16) -> Self {
        Self {
            rtt_ewma_ms,
            loss_ewma_permille: loss_ewma_permille.min(1000),
            reorder_depth,
        }
    }

    /// Creates a path-quality snapshot from a floating-point loss rate.
    #[must_use]
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub fn from_loss_rate(rtt_ewma_ms: u32, loss_rate: f64, reorder_depth: u16) -> Self {
        let bounded = if loss_rate.is_finite() {
            loss_rate.clamp(0.0, 1.0)
        } else {
            1.0
        };
        Self::new(
            rtt_ewma_ms,
            (bounded * 1000.0).round() as u16,
            reorder_depth,
        )
    }
}

/// Deterministic telemetry for the block-layout choice used by one encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodingLayoutDecision {
    /// Stable policy identifier.
    pub policy_id: &'static str,
    /// Stable reason identifier for the selected policy row.
    pub reason_id: &'static str,
    /// Optional path-quality input; `None` means static fallback.
    pub path_quality: Option<PathQualitySnapshot>,
    /// Maximum source blocks configured by the caller.
    pub configured_max_source_blocks: u16,
    /// Source blocks requested by the selected policy before object-size clipping.
    pub requested_source_blocks: u16,
    /// Source blocks actually used after object-size clipping.
    pub effective_source_blocks: u16,
    /// Minimum repair symbols configured by the caller.
    pub configured_min_repair_symbols: u16,
    /// Minimum repair symbols used after adaptive overhead selection.
    pub effective_min_repair_symbols: u16,
    /// Repair multiplier from the selected policy row, in permille.
    pub repair_multiplier_permille: u16,
}

impl EncodingLayoutDecision {
    /// Static-layout decision used when no path quality is available.
    #[must_use]
    pub const fn static_config(max_source_blocks: u16, min_repair_symbols: u16) -> Self {
        Self {
            policy_id: STATIC_BLOCK_LAYOUT_POLICY_ID,
            reason_id: "path-quality-unknown",
            path_quality: None,
            configured_max_source_blocks: max_source_blocks,
            requested_source_blocks: max_source_blocks,
            effective_source_blocks: max_source_blocks,
            configured_min_repair_symbols: min_repair_symbols,
            effective_min_repair_symbols: min_repair_symbols,
            repair_multiplier_permille: 1000,
        }
    }
}

impl Default for EncodingLayoutDecision {
    fn default() -> Self {
        Self::static_config(1, 0)
    }
}

// ---------------------------------------------------------------------------
// StateEncoder
// ---------------------------------------------------------------------------

/// Encodes region state into RaptorQ symbols.
///
/// The encoder serializes a [`RegionSnapshot`] to bytes and delegates to the
/// deterministic RaptorQ pipeline for source + repair symbol generation.
#[derive(Debug)]
pub struct StateEncoder {
    config: EncodingConfig,
    rng: DetRng,
}

impl StateEncoder {
    /// Creates a new encoder with the given configuration.
    #[must_use]
    pub fn new(config: EncodingConfig, rng: DetRng) -> Self {
        Self { config, rng }
    }

    /// Encodes a region snapshot into symbols.
    ///
    /// Generates a random object ID, then delegates to [`encode_with_id`](Self::encode_with_id).
    pub fn encode(
        &mut self,
        snapshot: &RegionSnapshot,
        encoded_at: Time,
    ) -> Result<EncodedState, EncodingError> {
        let object_id = ObjectId::new_random(&mut self.rng);
        self.encode_with_id(snapshot, object_id, encoded_at)
    }

    /// Encodes with a specific object ID (for deterministic testing).
    pub fn encode_with_id(
        &mut self,
        snapshot: &RegionSnapshot,
        object_id: ObjectId,
        encoded_at: Time,
    ) -> Result<EncodedState, EncodingError> {
        validate_repair_overhead(self.config.repair_overhead)?;
        let data = snapshot.to_bytes();
        if data.is_empty() {
            return Err(EncodingError::EmptyData);
        }

        let mut layout_decision = derive_layout_decision(&self.config, data.len())?;
        let layout = derive_block_layout(
            data.len(),
            self.config.symbol_size,
            layout_decision.effective_source_blocks,
        )?;
        layout_decision.effective_source_blocks = layout.source_blocks;
        let source_count = checked_source_count(data.len(), self.config.symbol_size)?;
        let repair_count = total_repair_budget(
            source_count,
            self.config.repair_overhead,
            layout_decision.effective_min_repair_symbols,
        )?;
        let params = self.calculate_params(data.len(), object_id, layout)?;
        let mut symbols =
            Vec::with_capacity(usize::from(source_count) + usize::from(repair_count));
        let repair_distribution = distribute_repairs(
            usize::from(repair_count),
            usize::from(layout.source_blocks),
        );

        for (block, &repairs) in repair_distribution
            .iter()
            .enumerate()
            .take(usize::from(layout.source_blocks))
        {
            let (block_start, block_end) = block_bounds(block, layout.max_block_size, data.len());
            for symbol in self.encode_block_symbols(
                object_id,
                block,
                &data[block_start..block_end],
                self.config.symbol_size,
                repairs,
            )? {
                symbols.push(symbol);
            }
        }

        Ok(EncodedState {
            params,
            symbols,
            source_count,
            repair_count,
            original_size: data.len(),
            encoded_at,
            layout_decision,
        })
    }

    /// Generates exactly `count` additional repair symbols for an existing encoding.
    ///
    /// Each block resumes after its highest retained repair ESI, including
    /// when earlier repairs have been removed. Append the returned symbols to
    /// the state before requesting a further, non-overlapping range. This
    /// method does not mutate the state or reapply the initial overhead budget.
    pub fn generate_repair(
        &mut self,
        state: &EncodedState,
        count: u16,
    ) -> Result<Vec<Symbol>, EncodingError> {
        if count == 0 {
            return Ok(Vec::new());
        }

        if !state.symbols.iter().any(|s| s.kind().is_source()) {
            return Err(EncodingError::NoSourceSymbols);
        }

        validate_repair_overhead(self.config.repair_overhead)?;
        let layout = derive_block_layout(
            state.original_size,
            state.params.symbol_size,
            state.params.source_blocks,
        )?;
        checked_source_count(state.original_size, state.params.symbol_size)?;
        validate_complete_source_coverage(state)?;

        let source_blocks = usize::from(layout.source_blocks);
        let additional_repairs = distribute_repairs(usize::from(count), source_blocks);
        let mut next_repair_esi = Vec::with_capacity(source_blocks);
        let mut maximum_repair_esi = Vec::with_capacity(source_blocks);
        for block in 0..source_blocks {
            let (start, end) =
                block_bounds(block, layout.max_block_size, state.original_size);
            let source_count = (end - start).div_ceil(usize::from(state.params.symbol_size));
            let systematic = SystematicParams::try_for_source_block(
                source_count,
                usize::from(state.params.symbol_size),
            )
            .map_err(|err| EncodingError::Pipeline(format!("invalid source block: {err:?}")))?;
            next_repair_esi.push(source_count as u64);
            maximum_repair_esi.push(
                u64::from(u32::MAX) - (systematic.k_prime - systematic.k) as u64,
            );
        }
        for symbol in state.repair_symbols() {
            let block = usize::from(symbol.id().sbn());
            if block >= source_blocks {
                return Err(EncodingError::Pipeline(format!(
                    "repair symbol block {block} exceeds declared source_blocks {source_blocks}"
                )));
            }
            let (start, end) =
                block_bounds(block, layout.max_block_size, state.original_size);
            let source_count = (end - start).div_ceil(usize::from(state.params.symbol_size));
            let esi = u64::from(symbol.id().esi());
            if symbol.id().object_id() != state.params.object_id
                || symbol.len() != usize::from(state.params.symbol_size)
                || esi < source_count as u64
                || esi > maximum_repair_esi[block]
            {
                return Err(EncodingError::Pipeline(format!(
                    "invalid repair symbol identity, size, or ESI in block {block}"
                )));
            }
            next_repair_esi[block] = next_repair_esi[block].max(esi + 1);
        }

        // Check every requested range before rebuilding bytes or constructing
        // any RaptorQ matrices. The RFC ESI-to-ISI padding delta also has to fit.
        for block in 0..source_blocks {
            if additional_repairs[block] == 0 {
                continue;
            }
            let last_esi = next_repair_esi[block] + additional_repairs[block] as u64 - 1;
            if last_esi > maximum_repair_esi[block] {
                return Err(EncodingError::InvalidConfig {
                    reason: format!(
                        "repair ESI range in block {block} exceeds the RFC encoding limit"
                    ),
                });
            }
        }

        let data = rebuild_source_bytes(state);
        let mut repairs = Vec::with_capacity(usize::from(count));
        for block in 0..source_blocks {
            let extra = additional_repairs[block];
            if extra == 0 {
                continue;
            }

            let (block_start, block_end) = block_bounds(block, layout.max_block_size, data.len());
            let block_bytes = &data[block_start..block_end];
            let block_source_count = block_bytes
                .len()
                .div_ceil(usize::from(state.params.symbol_size));
            let first_repair = usize::try_from(next_repair_esi[block])
                .expect("validated repair ESI fits u32 and usize")
                - block_source_count;
            repairs.extend(self.encode_block_repair_range(
                state.params.object_id,
                block,
                block_bytes,
                state.params.symbol_size,
                first_repair,
                extra,
            )?);
        }

        if repairs.len() != usize::from(count) {
            return Err(EncodingError::Pipeline(format!(
                "generated {} repair symbols, expected {}",
                repairs.len(),
                count
            )));
        }

        Ok(repairs)
    }

    fn calculate_params(
        &self,
        data_size: usize,
        object_id: ObjectId,
        layout: BlockLayout,
    ) -> Result<ObjectParams, EncodingError> {
        let object_size = u64::try_from(data_size)
            .map_err(|_| EncodingError::ObjectSizeOverflow { size: data_size })?;

        Ok(ObjectParams::new(
            object_id,
            object_size,
            self.config.symbol_size,
            layout.source_blocks,
            layout.symbols_per_block,
        ))
    }

    fn encode_block_symbols(
        &self,
        object_id: ObjectId,
        block: usize,
        block_bytes: &[u8],
        symbol_size: u16,
        repair_count: usize,
    ) -> Result<Vec<Symbol>, EncodingError> {
        let pipeline_config = PipelineEncodingConfig {
            repair_overhead: f64::from(self.config.repair_overhead),
            max_block_size: block_bytes.len(),
            symbol_size,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        };
        let pool = SymbolPool::new(PoolConfig::default());
        let mut pipeline = EncodingPipeline::new(pipeline_config, pool);
        let block_sbn = u8::try_from(block).map_err(|_| EncodingError::SymbolCountOverflow {
            field: "source_blocks",
            value: block,
            max: usize::from(u8::MAX),
        })?;
        let mut symbols = Vec::new();

        for encoded in pipeline.encode_with_repair(object_id, block_bytes, repair_count) {
            let symbol = encoded
                .map_err(|err| EncodingError::Pipeline(err.to_string()))?
                .into_symbol();
            let kind = symbol.kind();
            let esi = symbol.id().esi();
            symbols.push(Symbol::new(
                SymbolId::new(object_id, block_sbn, esi),
                symbol.into_data(),
                kind,
            ));
        }

        Ok(symbols)
    }

    fn encode_block_repair_range(
        &self,
        object_id: ObjectId,
        block: usize,
        block_bytes: &[u8],
        symbol_size: u16,
        first_repair: usize,
        repair_count: usize,
    ) -> Result<Vec<Symbol>, EncodingError> {
        let pipeline_config = PipelineEncodingConfig {
            repair_overhead: f64::from(self.config.repair_overhead),
            max_block_size: block_bytes.len(),
            symbol_size,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        };
        let mut pipeline =
            EncodingPipeline::new(pipeline_config, SymbolPool::new(PoolConfig::default()));
        let block_sbn = u8::try_from(block).expect("validated source block index fits in u8");
        // Use the same per-block pipeline seed as encode_block_symbols, then
        // restore the enclosing object's SBN. Skip all previous source/repair
        // output instead of regenerating the entire retained prefix.
        pipeline
            .encode_repair_range(object_id, block_bytes, first_repair, repair_count)
            .map(|encoded| {
                let symbol = encoded
                    .map_err(|err| EncodingError::Pipeline(err.to_string()))?
                    .into_symbol();
                Ok(Symbol::new(
                    SymbolId::new(object_id, block_sbn, symbol.id().esi()),
                    symbol.into_data(),
                    SymbolKind::Repair,
                ))
            })
            .collect()
    }
}

/// Rebuild source data bytes from an encoded state by concatenating source symbols.
fn rebuild_source_bytes(encoded: &EncodedState) -> Vec<u8> {
    let mut sources: Vec<&Symbol> = encoded.source_symbols().collect();
    sources.sort_by_key(|symbol| (symbol.id().sbn(), symbol.id().esi()));
    let mut data = Vec::with_capacity(encoded.original_size);
    for symbol in sources {
        data.extend_from_slice(symbol.data());
    }
    data.truncate(encoded.original_size);
    data
}

/// Ensure every declared source symbol is present exactly once before
/// regenerating repairs from source bytes.
fn validate_complete_source_coverage(encoded: &EncodedState) -> Result<(), EncodingError> {
    let layout = derive_block_layout(
        encoded.original_size,
        encoded.params.symbol_size,
        encoded.params.source_blocks,
    )?;
    if encoded.params.object_size
        != u64::try_from(encoded.original_size).map_err(|_| EncodingError::ObjectSizeOverflow {
            size: encoded.original_size,
        })?
        || encoded.params.source_blocks != layout.source_blocks
        || encoded.params.symbols_per_block != layout.symbols_per_block
        || encoded.source_count
            != checked_source_count(encoded.original_size, encoded.params.symbol_size)?
    {
        return Err(EncodingError::Pipeline(
            "source object parameters do not match the encoded state".to_string(),
        ));
    }
    let symbol_size = usize::from(encoded.params.symbol_size);
    let source_blocks = usize::from(layout.source_blocks);
    let mut seen_by_block = Vec::with_capacity(source_blocks);

    for block in 0..source_blocks {
        let (start, end) = block_bounds(block, layout.max_block_size, encoded.original_size);
        let expected = if start >= end {
            0
        } else {
            (end - start).div_ceil(symbol_size)
        };
        seen_by_block.push(vec![false; expected]);
    }

    for symbol in encoded.source_symbols() {
        if symbol.id().object_id() != encoded.params.object_id || symbol.len() != symbol_size {
            return Err(EncodingError::Pipeline(
                "source symbol identity or size does not match the encoded state".to_string(),
            ));
        }
        let block = usize::from(symbol.id().sbn());
        if block >= source_blocks {
            return Err(EncodingError::Pipeline(format!(
                "source symbol block {block} exceeds declared source_blocks {source_blocks}"
            )));
        }

        let esi = usize::try_from(symbol.id().esi()).map_err(|_| {
            EncodingError::Pipeline(format!(
                "source symbol esi {} exceeds usize on this platform",
                symbol.id().esi()
            ))
        })?;
        let block_seen = &mut seen_by_block[block];
        if esi >= block_seen.len() {
            return Err(EncodingError::Pipeline(format!(
                "source symbol esi {esi} exceeds expected source count {} for block {block}",
                block_seen.len()
            )));
        }
        if block_seen[esi] {
            return Err(EncodingError::Pipeline(format!(
                "duplicate source symbol esi {esi} in block {block}"
            )));
        }
        block_seen[esi] = true;
    }

    for (block, seen) in seen_by_block.iter().enumerate() {
        let actual = seen.iter().filter(|present| **present).count();
        if actual != seen.len() {
            return Err(EncodingError::IncompleteSourceCoverage {
                block: u8::try_from(block).expect("validated source block index fits in u8"),
                expected: seen.len(),
                actual,
            });
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// EncodedState
// ---------------------------------------------------------------------------

/// Result of encoding a region snapshot.
#[derive(Debug)]
pub struct EncodedState {
    /// Object parameters for this encoding.
    pub params: ObjectParams,
    /// All generated symbols (source + repair).
    pub symbols: Vec<Symbol>,
    /// Number of source symbols.
    pub source_count: u16,
    /// Number of repair symbols.
    pub repair_count: u16,
    /// Original snapshot size in bytes.
    pub original_size: usize,
    /// Encoding timestamp.
    pub encoded_at: Time,
    /// Replayable block-layout decision used for this encoding.
    pub layout_decision: EncodingLayoutDecision,
}

impl EncodedState {
    /// Returns an iterator over source symbols only.
    pub fn source_symbols(&self) -> impl Iterator<Item = &Symbol> {
        self.symbols.iter().filter(|s| s.kind().is_source())
    }

    /// Returns an iterator over repair symbols only.
    pub fn repair_symbols(&self) -> impl Iterator<Item = &Symbol> {
        self.symbols.iter().filter(|s| s.kind().is_repair())
    }

    /// Returns the minimum symbols needed for decoding.
    #[must_use]
    pub fn min_symbols_for_decode(&self) -> u16 {
        self.source_count
    }

    /// Returns total redundancy factor.
    #[must_use]
    pub fn redundancy_factor(&self) -> f32 {
        if self.source_count == 0 {
            return 0.0;
        }
        (f32::from(self.source_count) + f32::from(self.repair_count)) / f32::from(self.source_count)
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Error during state encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodingError {
    /// Snapshot serialized to empty data.
    EmptyData,
    /// Configuration is invalid or inconsistent.
    InvalidConfig {
        /// Reason for the invalid configuration.
        reason: String,
    },
    /// No source symbols available.
    NoSourceSymbols,
    /// The source symbol set is incomplete for at least one declared block.
    IncompleteSourceCoverage {
        /// Source block with missing symbols.
        block: u8,
        /// Number of source symbols expected for that block.
        expected: usize,
        /// Number of distinct source symbols actually present for that block.
        actual: usize,
    },
    /// A symbol count exceeded representable bounds.
    SymbolCountOverflow {
        /// Name of the overflowing count.
        field: &'static str,
        /// Actual value encountered.
        value: usize,
        /// Maximum representable value.
        max: usize,
    },
    /// Snapshot size could not be represented in object parameters.
    ObjectSizeOverflow {
        /// Original size in bytes.
        size: usize,
    },
    /// Error from the underlying encoding pipeline.
    Pipeline(String),
}

impl std::fmt::Display for EncodingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyData => write!(f, "snapshot serialized to empty data"),
            Self::InvalidConfig { reason } => write!(f, "invalid encoding config: {reason}"),
            Self::NoSourceSymbols => write!(f, "no source symbols available"),
            Self::IncompleteSourceCoverage {
                block,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "incomplete source coverage for block {block}: expected {expected} distinct source symbols, got {actual}"
                )
            }
            Self::SymbolCountOverflow { field, value, max } => {
                write!(f, "{field} overflow: value={value}, max={max}")
            }
            Self::ObjectSizeOverflow { size } => {
                write!(f, "object size overflow: size={size} cannot fit in u64")
            }
            Self::Pipeline(msg) => write!(f, "pipeline encoding error: {msg}"),
        }
    }
}

impl std::error::Error for EncodingError {}

#[derive(Debug, Clone, Copy)]
struct BlockLayout {
    max_block_size: usize,
    source_blocks: u16,
    symbols_per_block: u16,
}

#[derive(Debug, Clone, Copy)]
struct AdaptiveBlockLayoutPolicyRow {
    max_loss_permille: u16,
    max_rtt_ms: u32,
    max_reorder_depth: u16,
    source_block_divisor: u16,
    repair_multiplier_permille: u16,
    reason_id: &'static str,
}

const ADAPTIVE_BLOCK_LAYOUT_POLICY: [AdaptiveBlockLayoutPolicyRow; 5] = [
    AdaptiveBlockLayoutPolicyRow {
        max_loss_permille: 10,
        max_rtt_ms: 50,
        max_reorder_depth: 1,
        source_block_divisor: 1,
        repair_multiplier_permille: 1000,
        reason_id: "clean-low-rtt",
    },
    AdaptiveBlockLayoutPolicyRow {
        max_loss_permille: 10,
        max_rtt_ms: u32::MAX,
        max_reorder_depth: 2,
        source_block_divisor: 2,
        repair_multiplier_permille: 1100,
        reason_id: "clean-high-rtt",
    },
    AdaptiveBlockLayoutPolicyRow {
        max_loss_permille: 50,
        max_rtt_ms: u32::MAX,
        max_reorder_depth: 8,
        source_block_divisor: 2,
        repair_multiplier_permille: 1250,
        reason_id: "moderate-loss",
    },
    AdaptiveBlockLayoutPolicyRow {
        max_loss_permille: 150,
        max_rtt_ms: u32::MAX,
        max_reorder_depth: 16,
        source_block_divisor: 4,
        repair_multiplier_permille: 1750,
        reason_id: "lossy",
    },
    AdaptiveBlockLayoutPolicyRow {
        max_loss_permille: u16::MAX,
        max_rtt_ms: u32::MAX,
        max_reorder_depth: u16::MAX,
        source_block_divisor: 8,
        repair_multiplier_permille: 2500,
        reason_id: "severe-loss-or-reorder",
    },
];

fn derive_block_layout(
    data_size: usize,
    symbol_size: u16,
    max_source_blocks: u16,
) -> Result<BlockLayout, EncodingError> {
    let total_symbols = total_symbols_for_layout(data_size, symbol_size, max_source_blocks)?;
    let symbol_size = usize::from(symbol_size);
    let requested_blocks = usize::from(max_source_blocks).min(total_symbols.max(1));
    let symbols_per_block = total_symbols.div_ceil(requested_blocks);
    let max_block_size = symbols_per_block
        .checked_mul(symbol_size)
        .ok_or(EncodingError::ObjectSizeOverflow { size: data_size })?;
    let source_blocks = u16::try_from(data_size.div_ceil(max_block_size)).map_err(|_| {
        EncodingError::SymbolCountOverflow {
            field: "source_blocks",
            value: data_size.div_ceil(max_block_size),
            max: usize::from(u16::MAX),
        }
    })?;
    let symbols_per_block =
        u16::try_from(symbols_per_block).map_err(|_| EncodingError::SymbolCountOverflow {
            field: "symbols_per_block",
            value: symbols_per_block,
            max: usize::from(u16::MAX),
        })?;
    if usize::from(source_blocks) > crate::encoding::MAX_SOURCE_BLOCKS {
        return Err(EncodingError::SymbolCountOverflow {
            field: "source_blocks",
            value: usize::from(source_blocks),
            max: crate::encoding::MAX_SOURCE_BLOCKS,
        });
    }

    Ok(BlockLayout {
        max_block_size,
        source_blocks,
        symbols_per_block,
    })
}

fn derive_layout_decision(
    config: &EncodingConfig,
    data_size: usize,
) -> Result<EncodingLayoutDecision, EncodingError> {
    total_symbols_for_layout(data_size, config.symbol_size, config.max_source_blocks)?;

    let Some(path_quality) = config.path_quality else {
        return Ok(EncodingLayoutDecision::static_config(
            config.max_source_blocks,
            config.min_repair_symbols,
        ));
    };

    let policy = select_adaptive_layout_policy(path_quality);
    let requested_blocks = usize::from(config.max_source_blocks)
        .div_ceil(usize::from(policy.source_block_divisor))
        .max(1);
    let requested_blocks_u16 =
        u16::try_from(requested_blocks).map_err(|_| EncodingError::SymbolCountOverflow {
            field: "source_blocks",
            value: requested_blocks,
            max: usize::from(u16::MAX),
        })?;
    let effective_repairs =
        adaptive_repair_symbols(config.min_repair_symbols, policy.repair_multiplier_permille)?;

    Ok(EncodingLayoutDecision {
        policy_id: ADAPTIVE_BLOCK_LAYOUT_POLICY_ID,
        reason_id: policy.reason_id,
        path_quality: Some(path_quality),
        configured_max_source_blocks: config.max_source_blocks,
        requested_source_blocks: requested_blocks_u16,
        effective_source_blocks: requested_blocks_u16,
        configured_min_repair_symbols: config.min_repair_symbols,
        effective_min_repair_symbols: effective_repairs,
        repair_multiplier_permille: policy.repair_multiplier_permille,
    })
}

fn total_symbols_for_layout(
    data_size: usize,
    symbol_size: u16,
    max_source_blocks: u16,
) -> Result<usize, EncodingError> {
    if data_size == 0 {
        return Err(EncodingError::EmptyData);
    }
    if symbol_size == 0 {
        return Err(EncodingError::InvalidConfig {
            reason: "symbol_size must be non-zero".to_string(),
        });
    }
    if max_source_blocks == 0 {
        return Err(EncodingError::InvalidConfig {
            reason: "max_source_blocks must be non-zero".to_string(),
        });
    }

    Ok(data_size.div_ceil(usize::from(symbol_size)))
}

fn select_adaptive_layout_policy(
    path_quality: PathQualitySnapshot,
) -> AdaptiveBlockLayoutPolicyRow {
    ADAPTIVE_BLOCK_LAYOUT_POLICY
        .iter()
        .copied()
        .find(|row| {
            path_quality.loss_ewma_permille <= row.max_loss_permille
                && path_quality.rtt_ewma_ms <= row.max_rtt_ms
                && path_quality.reorder_depth <= row.max_reorder_depth
        })
        .expect("adaptive block layout policy has a catch-all row")
}

fn adaptive_repair_symbols(
    configured_min_repair_symbols: u16,
    repair_multiplier_permille: u16,
) -> Result<u16, EncodingError> {
    if repair_multiplier_permille <= 1000 {
        return Ok(configured_min_repair_symbols);
    }

    let base = usize::from(configured_min_repair_symbols).max(1);
    let adjusted = base
        .saturating_mul(usize::from(repair_multiplier_permille))
        .div_ceil(1000);
    u16::try_from(adjusted).map_err(|_| EncodingError::SymbolCountOverflow {
        field: "min_repair_symbols",
        value: adjusted,
        max: usize::from(u16::MAX),
    })
}

fn validate_repair_overhead(overhead: f32) -> Result<(), EncodingError> {
    if !overhead.is_finite() || overhead < 1.0 {
        return Err(EncodingError::InvalidConfig {
            reason: "repair_overhead must be finite and >= 1.0".to_string(),
        });
    }
    Ok(())
}

fn checked_source_count(data_size: usize, symbol_size: u16) -> Result<u16, EncodingError> {
    let count = data_size.div_ceil(usize::from(symbol_size));
    u16::try_from(count).map_err(|_| EncodingError::SymbolCountOverflow {
        field: "source_count",
        value: count,
        max: usize::from(u16::MAX),
    })
}

fn total_repair_budget(
    source_count: u16,
    overhead: f32,
    minimum: u16,
) -> Result<u16, EncodingError> {
    validate_repair_overhead(overhead)?;
    // Both operands retain their full precision in f64. Refuse oversized
    // requests before any float-to-integer cast or symbol allocation.
    let requested = (f64::from(source_count) * f64::from(overhead)).ceil()
        - f64::from(source_count);
    if requested > f64::from(u16::MAX) {
        return Err(EncodingError::InvalidConfig {
            reason: "repair_overhead requires more than 65535 repair symbols".to_string(),
        });
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let repairs = requested as u16;
    Ok(repairs.max(minimum))
}

fn distribute_repairs(total: usize, blocks: usize) -> Vec<usize> {
    if blocks == 0 {
        return Vec::new();
    }
    let base = total / blocks;
    let remainder = total % blocks;
    (0..blocks)
        .map(|block| base + usize::from(block < remainder))
        .collect()
}

fn block_bounds(block: usize, max_block_size: usize, data_len: usize) -> (usize, usize) {
    let start = block * max_block_size;
    let end = min(start + max_block_size, data_len);
    (start, end)
}

#[cfg(test)]
mod repair_budget_tests {
    use super::*;
    use crate::distributed::recovery::{RecoveryDecodingConfig, StateDecoder};
    use crate::security::{AuthKey, SecurityContext};
    use crate::types::RegionId;
    use raptorq::{ObjectTransmissionInformation, SourceBlockEncoder};
    use std::collections::BTreeSet;

    fn snapshot_with_size(size: usize) -> RegionSnapshot {
        let mut snapshot = RegionSnapshot::empty(RegionId::new_for_test(37, 0));
        let envelope_size = snapshot.to_bytes().len();
        assert!(size >= envelope_size);
        snapshot.metadata.resize(size - envelope_size, 0);
        DetRng::new(71).fill_bytes(&mut snapshot.metadata);
        assert_eq!(snapshot.to_bytes().len(), size);
        snapshot
    }

    fn config(overhead: f32) -> EncodingConfig {
        EncodingConfig {
            symbol_size: 128,
            min_repair_symbols: 0,
            max_source_blocks: 4,
            repair_overhead: overhead,
            path_quality: None,
        }
    }

    #[test]
    fn overhead_budget_is_total_and_rounded_once_for_uneven_blocks() {
        // 2065 bytes need 17 source symbols. Four actual blocks contain
        // 5, 5, 5, 2 source symbols; no per-block ceil may multiply the budget.
        let snapshot = snapshot_with_size(16 * 128 + 17);
        for (overhead, expected_repairs, per_block) in [
            (1.0, 0, [0, 0, 0, 0]),
            (1.25, 5, [2, 1, 1, 1]),
            (1.5, 9, [3, 2, 2, 2]),
            (2.0, 17, [5, 4, 4, 4]),
        ] {
            let encoded = StateEncoder::new(config(overhead), DetRng::new(42))
                .encode(&snapshot, Time::ZERO)
                .unwrap();
            assert_eq!(encoded.source_count, 17);
            assert_eq!(encoded.repair_count, expected_repairs);
            assert_eq!(encoded.params.source_blocks, 4);
            assert_eq!(encoded.symbols.len(), 17 + usize::from(expected_repairs));
            assert_eq!(rebuild_source_bytes(&encoded), snapshot.to_bytes());
            for (block, expected) in per_block.into_iter().enumerate() {
                let repairs = encoded
                    .repair_symbols()
                    .filter(|symbol| usize::from(symbol.id().sbn()) == block)
                    .map(|symbol| symbol.id().esi())
                    .collect::<Vec<_>>();
                let source_count = [5, 5, 5, 2][block];
                assert_eq!(repairs, (source_count..source_count + expected).collect::<Vec<_>>());
            }
        }
    }

    #[test]
    fn overhead_budget_preserves_minimum_and_adaptive_floors() {
        let snapshot = snapshot_with_size(16 * 128);
        let severe = Some(PathQualitySnapshot::new(400, 300, 32));
        for (overhead, minimum, quality, expected_floor, expected_repairs) in [
            (1.0, 0, None, 0, 0),
            (1.125, 3, None, 3, 3),
            (1.125, 3, severe, 8, 8),
            (2.0, 3, severe, 8, 16),
            (1.0, 0, severe, 3, 3),
        ] {
            let mut settings = config(overhead);
            settings.min_repair_symbols = minimum;
            settings.path_quality = quality;
            let encoded = StateEncoder::new(settings, DetRng::new(43))
                .encode(&snapshot, Time::ZERO)
                .unwrap();
            assert_eq!(encoded.source_count, 16);
            assert_eq!(encoded.layout_decision.effective_min_repair_symbols, expected_floor);
            assert_eq!(encoded.repair_count, expected_repairs);
            assert_eq!(encoded.repair_symbols().count(), usize::from(expected_repairs));
        }
    }

    #[test]
    fn overhead_budget_uses_the_configured_f32_value_without_rounding_down() {
        // 1.2_f32 represents a value slightly above 1.2. Five source
        // symbols therefore need two repairs to meet that exact configured
        // bound. Widening before multiplication intentionally preserves it.
        let encoded = StateEncoder::new(config(1.2), DetRng::new(44))
            .encode(&snapshot_with_size(5 * 128), Time::ZERO)
            .unwrap();
        assert!(f64::from(1.2_f32) > 1.2_f64);
        assert_eq!(encoded.source_count, 5);
        assert_eq!(encoded.repair_count, 2);
    }

    #[test]
    fn overhead_budget_rejects_invalid_and_unrepresentable_requests() {
        let snapshot = snapshot_with_size(16 * 128);
        for overhead in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, -1.0, 0.999] {
            let error = StateEncoder::new(config(overhead), DetRng::new(45))
                .encode(&snapshot, Time::ZERO)
                .unwrap_err();
            assert_eq!(error, EncodingError::InvalidConfig {
                reason: "repair_overhead must be finite and >= 1.0".to_string(),
            });
        }
        for overhead in [4097.0, f32::MAX] {
            let error = StateEncoder::new(config(overhead), DetRng::new(46))
                .encode(&snapshot, Time::ZERO)
                .unwrap_err();
            assert_eq!(error, EncodingError::InvalidConfig {
                reason: "repair_overhead requires more than 65535 repair symbols".to_string(),
            });
        }
        assert_eq!(total_repair_budget(u16::MAX, 2.0, 0), Ok(u16::MAX));
        assert_eq!(total_repair_budget(1, 1.0, u16::MAX), Ok(u16::MAX));
        assert!(total_repair_budget(u16::MAX, 2.000_001, 0).is_err());

        let error = StateEncoder::new(EncodingConfig {
            symbol_size: 1,
            max_source_blocks: 256,
            ..config(1.0)
        }, DetRng::new(47))
        .encode(&snapshot_with_size(65536), Time::ZERO)
        .unwrap_err();
        assert_eq!(error, EncodingError::SymbolCountOverflow {
            field: "source_count", value: 65536, max: 65535,
        });

        let error = StateEncoder::new(EncodingConfig {
            max_source_blocks: 257,
            ..config(1.0)
        }, DetRng::new(48))
        .encode(&snapshot_with_size(257 * 128), Time::ZERO)
        .unwrap_err();
        assert_eq!(error, EncodingError::SymbolCountOverflow {
            field: "source_blocks", value: 257, max: 256,
        });
    }

    #[test]
    fn overhead_repairs_recover_authenticated_snapshot_after_multiblock_erasure() {
        let snapshot_key = AuthKey::from_seed(75);
        let security = SecurityContext::new(AuthKey::from_seed(76));
        let snapshot = snapshot_with_size(32 * 128).signed(&snapshot_key);
        let encoded = StateEncoder::new(config(2.0), DetRng::new(49))
            .encode(&snapshot, Time::ZERO)
            .unwrap();
        assert_eq!((encoded.source_count, encoded.repair_count), (32, 32));
        assert_eq!(encoded.params.source_blocks, 4);

        let mut decoder = StateDecoder::new(RecoveryDecodingConfig {
            auth_context: Some(security.clone()),
            snapshot_auth_key: Some(snapshot_key.clone()),
            ..Default::default()
        });
        let mut source_only = StateDecoder::new(RecoveryDecodingConfig {
            auth_context: Some(security.clone()),
            snapshot_auth_key: Some(snapshot_key),
            ..Default::default()
        });
        let mut lost_by_block = [0; 4];
        for symbol in &encoded.symbols {
            if symbol.kind().is_source() && symbol.id().esi() < 2 {
                lost_by_block[usize::from(symbol.id().sbn())] += 1;
                continue;
            }
            let authenticated = security.sign_symbol(symbol);
            decoder.add_symbol(&authenticated).unwrap();
            if symbol.kind().is_source() {
                source_only.add_symbol(&authenticated).unwrap();
            }
        }
        assert_eq!(lost_by_block, [2, 2, 2, 2]);
        assert_eq!(source_only.symbols_received(), 24);
        assert!(source_only.decode_snapshot(&encoded.params).is_err());
        let recovered = decoder.decode_snapshot(&encoded.params).unwrap();
        assert_eq!(recovered.to_bytes(), snapshot.to_bytes());
    }

    #[test]
    fn repair_continuation_skips_sparse_prefix_and_matches_independent_encoder() {
        let snapshot = snapshot_with_size(16 * 128 + 17);
        let mut encoder = StateEncoder::new(config(2.0), DetRng::new(50));
        let mut encoded = encoder.encode(&snapshot, Time::ZERO).unwrap();
        let last_esi = [9, 8, 8, 5];
        encoded.symbols.retain(|symbol| symbol.kind().is_source()
            || symbol.id().esi() == last_esi[usize::from(symbol.id().sbn())]);
        encoded.repair_count = 4;
        let additional = encoder.generate_repair(&encoded, 7).unwrap();
        assert_eq!(additional.len(), 7);
        let expected_esis = [vec![10, 11], vec![9, 10], vec![9, 10], vec![6]];
        for (block, expected) in expected_esis.into_iter().enumerate() {
            let generated = additional.iter()
                .filter(|symbol| usize::from(symbol.id().sbn()) == block)
                .collect::<Vec<_>>();
            assert_eq!(generated.iter().map(|symbol| symbol.id().esi()).collect::<Vec<_>>(), expected);
            let source_bytes = encoded.source_symbols()
                .filter(|symbol| usize::from(symbol.id().sbn()) == block)
                .flat_map(|symbol| symbol.data().iter().copied())
                .collect::<Vec<_>>();
            let reference_config = ObjectTransmissionInformation::new(
                u64::try_from(source_bytes.len()).unwrap(), 128, 1, 1, 1,
            );
            let reference = SourceBlockEncoder::new(0, &reference_config, &source_bytes);
            let first = expected[0] - u32::try_from(source_bytes.len() / 128).unwrap();
            let reference_repairs = reference.repair_packets(first, u32::try_from(expected.len()).unwrap());
            for (actual, expected) in generated.into_iter().zip(reference_repairs) {
                assert_eq!(actual.id().esi(), expected.payload_id().encoding_symbol_id());
                assert_eq!(actual.data(), expected.data());
            }
        }
        encoded.symbols.extend(additional);
        encoded.repair_count += 7;
        let second = encoder.generate_repair(&encoded, 4).unwrap();
        assert_eq!(second.iter().map(|symbol| symbol.id().esi()).collect::<Vec<_>>(), [12, 11, 11, 7]);
        let mut ids = encoded.symbols.iter().map(Symbol::id).collect::<BTreeSet<_>>();
        for symbol in second {
            assert!(ids.insert(symbol.id()), "continuation must not duplicate retained ESIs");
        }
        assert!(encoder.generate_repair(&encoded, 0).unwrap().is_empty());
    }

    #[test]
    fn repair_continuation_refuses_invalid_source_shape_and_rfc_esi_exhaustion() {
        let snapshot = snapshot_with_size(5 * 128);
        let mut encoder = StateEncoder::new(EncodingConfig {
            max_source_blocks: 1, ..config(1.0)
        }, DetRng::new(51));
        for defect in 0..6 {
            let mut state = encoder.encode(&snapshot, Time::ZERO).unwrap();
            let source = state.symbols[0].clone();
            match defect {
                0 => state.params.object_size += 1,
                1 => state.symbols[0] = Symbol::new(
                    SymbolId::new(ObjectId::new_for_test(999), 0, 0),
                    source.into_data(), SymbolKind::Source,
                ),
                2 => state.symbols[0] = Symbol::new(
                    source.id(), vec![0; 127], SymbolKind::Source,
                ),
                3 => state.symbols.push(Symbol::new(
                    SymbolId::new(state.params.object_id, 0, 4),
                    vec![0; 128], SymbolKind::Repair,
                )),
                4 => state.symbols.push(Symbol::new(
                    SymbolId::new(state.params.object_id, 0, u32::MAX),
                    vec![0; 128], SymbolKind::Repair,
                )),
                5 => {
                    // K=5 maps to K'=10, so u32::MAX-5 is the last valid
                    // repair ESI. A request after it must return an error,
                    // before the lower-level encoder's panicking ESI API.
                    state.symbols.push(Symbol::new(
                        SymbolId::new(state.params.object_id, 0, u32::MAX - 5),
                        vec![0; 128], SymbolKind::Repair,
                    ));
                }
                _ => unreachable!(),
            }
            let error = encoder.generate_repair(&state, 1).unwrap_err();
            if defect == 5 {
                assert_eq!(error, EncodingError::InvalidConfig {
                    reason: "repair ESI range in block 0 exceeds the RFC encoding limit".to_string(),
                });
            } else {
                assert!(matches!(error, EncodingError::Pipeline(_)), "defect {defect}: {error}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "legacy-internal-test-harnesses"))]
#[allow(clippy::similar_names)]
mod tests {
    use super::*;
    use crate::distributed::snapshot::{BudgetSnapshot, TaskSnapshot, TaskState};
    use crate::record::region::RegionState;
    use crate::types::RegionId;

    fn create_test_snapshot() -> RegionSnapshot {
        RegionSnapshot {
            region_id: RegionId::new_for_test(1, 0),
            state: RegionState::Open,
            timestamp: Time::from_secs(100),
            sequence: 1,
            vector_clock: crate::trace::distributed::vclock::VectorClock::new(),
            origin_id: 1,
            epoch: 1,
            tasks: vec![TaskSnapshot {
                task_id: crate::types::TaskId::new_for_test(1, 0),
                state: TaskState::Running,
                priority: 5,
            }],
            children: vec![],
            finalizer_count: 2,
            budget: BudgetSnapshot {
                deadline_nanos: Some(1_000_000_000),
                polls_remaining: Some(100),
                cost_remaining: None,
            },
            cancel_reason: None,
            parent: None,
            metadata: vec![],
            auth_tag: crate::security::AuthenticationTag::zero(),
        }
    }

    fn create_extension_snapshot() -> RegionSnapshot {
        RegionSnapshot {
            region_id: RegionId::new_for_test(7, 1),
            state: RegionState::Closing,
            timestamp: Time::from_secs(321),
            sequence: 9,
            vector_clock: crate::trace::distributed::vclock::VectorClock::new(),
            origin_id: 7,
            epoch: 2,
            tasks: vec![
                TaskSnapshot {
                    task_id: crate::types::TaskId::new_for_test(3, 0),
                    state: TaskState::Running,
                    priority: 4,
                },
                TaskSnapshot {
                    task_id: crate::types::TaskId::new_for_test(4, 2),
                    state: TaskState::Cancelled,
                    priority: 8,
                },
            ],
            children: vec![RegionId::new_for_test(8, 0), RegionId::new_for_test(9, 1)],
            finalizer_count: 5,
            budget: BudgetSnapshot {
                deadline_nanos: Some(Time::from_secs(400).as_nanos()),
                polls_remaining: Some(12),
                cost_remaining: Some(34),
            },
            cancel_reason: Some("timeout: extension fields".to_string()),
            parent: Some(RegionId::new_for_test(2, 0)),
            metadata: vec![0xde, 0xad, 0xbe, 0xef, 0x10, 0x20],
            auth_tag: crate::security::AuthenticationTag::zero(),
        }
    }

    fn create_large_snapshot(min_serialized_size: usize) -> RegionSnapshot {
        let mut snapshot = create_test_snapshot();
        let initial_len = snapshot.to_bytes().len();
        if initial_len < min_serialized_size {
            snapshot
                .metadata
                .resize(min_serialized_size.saturating_sub(initial_len), 0xAB);
            while snapshot.to_bytes().len() < min_serialized_size {
                snapshot.metadata.push(0xAB);
            }
        }
        snapshot
    }

    fn rebuild_source_bytes(encoded: &EncodedState) -> Vec<u8> {
        let mut sources: Vec<&Symbol> = encoded.source_symbols().collect();
        sources.sort_by_key(|symbol| (symbol.id().sbn(), symbol.id().esi()));
        let mut data = Vec::with_capacity(encoded.original_size);
        for symbol in sources {
            data.extend_from_slice(symbol.data());
        }
        data.truncate(encoded.original_size);
        data
    }

    fn decode_roundtrip(encoded: &EncodedState) -> RegionSnapshot {
        let data = rebuild_source_bytes(encoded);
        RegionSnapshot::from_bytes(&data).expect("roundtrip decode should succeed")
    }

    fn scrub_region_snapshot_for_encoding_snapshot_test(
        snapshot: &RegionSnapshot,
    ) -> serde_json::Value {
        serde_json::json!({
            "region_id": {
                "index": snapshot.region_id.0.index(),
                "generation": snapshot.region_id.0.generation(),
            },
            "state": format!("{:?}", snapshot.state),
            "timestamp_nanos": snapshot.timestamp.as_nanos(),
            "sequence": snapshot.sequence,
            "tasks": snapshot.tasks.iter().map(|task| {
                serde_json::json!({
                    "task_id": {
                        "index": task.task_id.0.index(),
                        "generation": task.task_id.0.generation(),
                    },
                    "state": format!("{:?}", task.state),
                    "priority": task.priority,
                })
            }).collect::<Vec<_>>(),
            "children": snapshot.children.iter().map(|child| {
                serde_json::json!({
                    "index": child.0.index(),
                    "generation": child.0.generation(),
                })
            }).collect::<Vec<_>>(),
            "finalizer_count": snapshot.finalizer_count,
            "budget": {
                "deadline_nanos": snapshot.budget.deadline_nanos,
                "polls_remaining": snapshot.budget.polls_remaining,
                "cost_remaining": snapshot.budget.cost_remaining,
            },
            "cancel_reason": snapshot.cancel_reason,
            "parent": snapshot.parent.map(|parent| serde_json::json!({
                "index": parent.0.index(),
                "generation": parent.0.generation(),
            })),
            "metadata": snapshot.metadata,
        })
    }

    fn scrub_encoded_state_envelope_for_snapshot_test(
        name: &str,
        encoded: &EncodedState,
    ) -> serde_json::Value {
        let decoded = decode_roundtrip(encoded);
        serde_json::json!({
            "name": name,
            "schema_version": "encoding-envelope-v2",
            "params": {
                "object_id": format!("{:?}", encoded.params.object_id),
                "object_size": encoded.params.object_size,
                "symbol_size": encoded.params.symbol_size,
                "source_blocks": encoded.params.source_blocks,
                "symbols_per_block": encoded.params.symbols_per_block,
                "min_symbols_for_decode": encoded.params.min_symbols_for_decode(),
            },
            "envelope": {
                "source_count": encoded.source_count,
                "repair_count": encoded.repair_count,
                "original_size": encoded.original_size,
                "encoded_at_nanos": encoded.encoded_at.as_nanos(),
                "redundancy_factor": format!("{:.3}", encoded.redundancy_factor()),
            },
            "layout_decision": {
                "policy_id": encoded.layout_decision.policy_id,
                "reason_id": encoded.layout_decision.reason_id,
                "configured_max_source_blocks": encoded.layout_decision.configured_max_source_blocks,
                "requested_source_blocks": encoded.layout_decision.requested_source_blocks,
                "effective_source_blocks": encoded.layout_decision.effective_source_blocks,
                "configured_min_repair_symbols": encoded.layout_decision.configured_min_repair_symbols,
                "effective_min_repair_symbols": encoded.layout_decision.effective_min_repair_symbols,
                "repair_multiplier_permille": encoded.layout_decision.repair_multiplier_permille,
                "path_quality": encoded.layout_decision.path_quality.map(|quality| serde_json::json!({
                    "rtt_ewma_ms": quality.rtt_ewma_ms,
                    "loss_ewma_permille": quality.loss_ewma_permille,
                    "reorder_depth": quality.reorder_depth,
                })),
            },
            "symbols": encoded.symbols.iter().map(|symbol| {
                let preview_len = symbol.len().min(8);
                let preview = symbol.data()[..preview_len]
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                serde_json::json!({
                    "sbn": symbol.id().sbn(),
                    "esi": symbol.id().esi(),
                    "kind": symbol.kind().to_string(),
                    "len": symbol.len(),
                    "preview_hex": preview,
                })
            }).collect::<Vec<_>>(),
            "roundtrip_snapshot": scrub_region_snapshot_for_encoding_snapshot_test(&decoded),
        })
    }

    #[test]
    fn distribute_repairs_preserves_budget_and_front_loads_remainder() {
        for blocks in 1..=8 {
            for total in 0..=25 {
                let repairs = distribute_repairs(total, blocks);

                assert_eq!(repairs.len(), blocks);
                assert_eq!(repairs.iter().sum::<usize>(), total);

                let base = total / blocks;
                let remainder = total % blocks;
                for (block, &count) in repairs.iter().enumerate() {
                    let expected = base + usize::from(block < remainder);
                    assert_eq!(
                        count, expected,
                        "block {block} should receive the deterministic remainder distribution"
                    );
                }

                let min = repairs.iter().copied().min().unwrap_or(0);
                let max = repairs.iter().copied().max().unwrap_or(0);
                assert!(
                    max - min <= 1,
                    "repair distribution must stay balanced, got {repairs:?}"
                );
            }
        }
    }

    #[test]
    fn path_quality_from_loss_rate_clamps_and_quantizes() {
        assert_eq!(
            PathQualitySnapshot::from_loss_rate(12, 0.057, 3),
            PathQualitySnapshot::new(12, 57, 3)
        );
        assert_eq!(
            PathQualitySnapshot::from_loss_rate(12, 9.0, 3).loss_ewma_permille,
            1000
        );
        assert_eq!(
            PathQualitySnapshot::from_loss_rate(12, f64::NAN, 3).loss_ewma_permille,
            1000
        );
    }

    #[test]
    fn unknown_path_quality_keeps_static_layout_decision() {
        let config = EncodingConfig {
            symbol_size: 128,
            min_repair_symbols: 4,
            max_source_blocks: 8,
            ..Default::default()
        };
        let mut encoder = StateEncoder::new(config, DetRng::new(42));

        let encoded = encoder
            .encode(&create_large_snapshot(4_096), Time::ZERO)
            .unwrap();

        assert_eq!(
            encoded.layout_decision.policy_id,
            STATIC_BLOCK_LAYOUT_POLICY_ID
        );
        assert_eq!(encoded.layout_decision.reason_id, "path-quality-unknown");
        assert_eq!(encoded.layout_decision.effective_source_blocks, 8);
        assert_eq!(encoded.layout_decision.effective_min_repair_symbols, 4);
    }

    #[test]
    fn lossy_path_quality_uses_larger_blocks_and_more_repairs() {
        let config = EncodingConfig {
            symbol_size: 128,
            min_repair_symbols: 4,
            max_source_blocks: 8,
            path_quality: Some(PathQualitySnapshot::new(120, 150, 4)),
            ..Default::default()
        };
        let mut encoder = StateEncoder::new(config, DetRng::new(42));

        let encoded = encoder
            .encode(&create_large_snapshot(4_096), Time::ZERO)
            .unwrap();

        assert_eq!(
            encoded.layout_decision.policy_id,
            ADAPTIVE_BLOCK_LAYOUT_POLICY_ID
        );
        assert_eq!(encoded.layout_decision.reason_id, "lossy");
        assert_eq!(encoded.layout_decision.configured_max_source_blocks, 8);
        assert_eq!(encoded.layout_decision.requested_source_blocks, 2);
        assert_eq!(encoded.params.source_blocks, 2);
        assert_eq!(encoded.layout_decision.effective_min_repair_symbols, 7);
        assert_eq!(encoded.repair_count, 7);
    }

    #[test]
    fn adaptive_policy_overhead_is_monotone_with_loss() {
        let qualities = [
            PathQualitySnapshot::new(20, 0, 0),
            PathQualitySnapshot::new(20, 10, 1),
            PathQualitySnapshot::new(20, 50, 2),
            PathQualitySnapshot::new(20, 150, 4),
            PathQualitySnapshot::new(20, 250, 4),
        ];
        let mut previous_multiplier = 0;
        let mut previous_divisor = 0;

        for quality in qualities {
            let row = select_adaptive_layout_policy(quality);
            assert!(
                row.repair_multiplier_permille >= previous_multiplier,
                "lossier quality should not reduce repair overhead"
            );
            assert!(
                row.source_block_divisor >= previous_divisor,
                "lossier quality should not request smaller extended blocks"
            );
            previous_multiplier = row.repair_multiplier_permille;
            previous_divisor = row.source_block_divisor;
        }
    }

    #[test]
    fn encode_rejects_zero_sized_config_bounds() {
        let snapshot = create_test_snapshot();
        let cases = [
            (
                EncodingConfig {
                    symbol_size: 0,
                    ..Default::default()
                },
                "symbol_size must be non-zero",
                100,
            ),
            (
                EncodingConfig {
                    max_source_blocks: 0,
                    ..Default::default()
                },
                "max_source_blocks must be non-zero",
                101,
            ),
        ];

        for (config, expected_reason, seed) in cases {
            let mut encoder = StateEncoder::new(config, DetRng::new(seed));

            let err = encoder
                .encode(&snapshot, Time::ZERO)
                .expect_err("zero-sized encoding config bound must be rejected");

            assert!(
                matches!(err, EncodingError::InvalidConfig { ref reason } if reason == expected_reason),
                "unexpected error for {expected_reason}: {err}"
            );
        }
    }

    #[test]
    fn encode_creates_correct_symbol_count() {
        let config = EncodingConfig {
            symbol_size: 128,
            min_repair_symbols: 4,
            ..Default::default()
        };
        let mut encoder = StateEncoder::new(config, DetRng::new(42));

        let snapshot = create_test_snapshot();
        let encoded = encoder.encode(&snapshot, Time::ZERO).unwrap();

        assert_eq!(
            encoded.symbols.len(),
            (encoded.source_count + encoded.repair_count) as usize
        );
        // Source + repair should match
        assert_eq!(
            encoded.source_symbols().count(),
            encoded.source_count as usize
        );
        assert_eq!(
            encoded.repair_symbols().count(),
            encoded.repair_count as usize
        );
    }

    #[test]
    fn encode_deterministic_with_same_seed() {
        let config = EncodingConfig::default();
        let snapshot = create_test_snapshot();
        let object_id = ObjectId::new_for_test(123);

        let mut encoder1 = StateEncoder::new(config.clone(), DetRng::new(42));
        let mut encoder2 = StateEncoder::new(config, DetRng::new(42));

        let encoded1 = encoder1
            .encode_with_id(&snapshot, object_id, Time::ZERO)
            .unwrap();
        let encoded2 = encoder2
            .encode_with_id(&snapshot, object_id, Time::ZERO)
            .unwrap();

        assert_eq!(encoded1.symbols.len(), encoded2.symbols.len());
        for (s1, s2) in encoded1.symbols.iter().zip(encoded2.symbols.iter()) {
            assert_eq!(s1.data(), s2.data());
        }
    }

    #[test]
    fn encode_symbol_size_respected() {
        let config = EncodingConfig {
            symbol_size: 256,
            ..Default::default()
        };
        let mut encoder = StateEncoder::new(config, DetRng::new(42));

        let snapshot = create_test_snapshot();
        let encoded = encoder.encode(&snapshot, Time::ZERO).unwrap();

        for symbol in &encoded.symbols {
            assert!(
                symbol.len() <= 256,
                "symbol size {} exceeds config 256",
                symbol.len()
            );
        }
    }

    #[test]
    fn encode_redundancy_factor() {
        let config = EncodingConfig {
            min_repair_symbols: 10,
            ..Default::default()
        };
        let mut encoder = StateEncoder::new(config, DetRng::new(42));

        let snapshot = create_test_snapshot();
        let encoded = encoder.encode(&snapshot, Time::ZERO).unwrap();

        assert!(
            encoded.redundancy_factor() > 1.0,
            "redundancy {} should be > 1.0",
            encoded.redundancy_factor()
        );
    }

    #[test]
    fn generate_additional_repair() {
        let config = EncodingConfig::default();
        let mut encoder = StateEncoder::new(config, DetRng::new(42));

        let snapshot = create_test_snapshot();
        let encoded = encoder.encode(&snapshot, Time::ZERO).unwrap();

        let additional = encoder.generate_repair(&encoded, 5).unwrap();

        assert_eq!(additional.len(), 5);
        for symbol in &additional {
            assert!(symbol.kind().is_repair());
        }
    }

    #[test]
    fn encode_honors_max_source_blocks_for_large_snapshot() {
        let config = EncodingConfig {
            symbol_size: 128,
            min_repair_symbols: 0,
            max_source_blocks: 2,
            repair_overhead: 1.0,
            ..Default::default()
        };
        let mut encoder = StateEncoder::new(config, DetRng::new(17));
        let snapshot = create_large_snapshot(56_404);

        let encoded = encoder.encode(&snapshot, Time::ZERO).unwrap();

        assert_eq!(encoded.params.source_blocks, 2);
        assert!(encoded.symbols.iter().any(|symbol| symbol.id().sbn() == 1));
        assert_eq!(
            usize::from(encoded.source_count) * 128,
            encoded.original_size.next_multiple_of(128)
        );
    }

    #[test]
    fn encode_multiblock_keeps_total_repair_budget() {
        let config = EncodingConfig {
            symbol_size: 128,
            min_repair_symbols: 3,
            max_source_blocks: 2,
            repair_overhead: 1.0,
            ..Default::default()
        };
        let mut encoder = StateEncoder::new(config, DetRng::new(19));
        let snapshot = create_large_snapshot(56_404);

        let encoded = encoder.encode(&snapshot, Time::ZERO).unwrap();

        assert_eq!(encoded.params.source_blocks, 2);
        assert_eq!(encoded.repair_count, 3);
        assert_eq!(encoded.repair_symbols().count(), 3);
        assert!(
            encoded
                .repair_symbols()
                .any(|symbol| symbol.id().sbn() == 1)
        );
    }

    #[test]
    fn generate_additional_repair_preserves_multiblock_layout_and_total_count() {
        let config = EncodingConfig {
            symbol_size: 128,
            min_repair_symbols: 0,
            max_source_blocks: 2,
            repair_overhead: 1.0,
            ..Default::default()
        };
        let mut encoder = StateEncoder::new(config, DetRng::new(23));
        let snapshot = create_large_snapshot(56_404);
        let encoded = encoder.encode(&snapshot, Time::ZERO).unwrap();

        let additional = encoder.generate_repair(&encoded, 5).unwrap();

        assert_eq!(additional.len(), 5);
        assert!(additional.iter().all(|symbol| symbol.kind().is_repair()));
        assert!(additional.iter().any(|symbol| symbol.id().sbn() == 1));
    }

    #[test]
    fn generate_repair_rejects_incomplete_source_coverage() {
        let config = EncodingConfig {
            symbol_size: 128,
            min_repair_symbols: 0,
            max_source_blocks: 2,
            repair_overhead: 1.0,
            ..Default::default()
        };
        let mut encoder = StateEncoder::new(config, DetRng::new(31));
        let snapshot = create_large_snapshot(56_404);
        let encoded = encoder.encode(&snapshot, Time::ZERO).unwrap();
        let missing = encoded
            .source_symbols()
            .find(|symbol| symbol.id().sbn() == 1)
            .expect("expected a source symbol in block 1")
            .id();
        let degraded = EncodedState {
            params: encoded.params,
            symbols: encoded
                .symbols
                .iter()
                .filter(|symbol| symbol.id() != missing)
                .cloned()
                .collect(),
            source_count: encoded.source_count,
            repair_count: encoded.repair_count,
            original_size: encoded.original_size,
            encoded_at: encoded.encoded_at,
            layout_decision: Default::default(),
        };

        let err = encoder
            .generate_repair(&degraded, 1)
            .expect_err("missing source symbol must fail closed");
        assert!(matches!(
            err,
            EncodingError::IncompleteSourceCoverage {
                block: 1,
                expected,
                actual,
            } if actual + 1 == expected
        ));
    }

    #[test]
    fn generate_repair_rejects_duplicate_source_symbol() {
        let config = EncodingConfig {
            symbol_size: 128,
            min_repair_symbols: 0,
            repair_overhead: 1.0,
            ..Default::default()
        };
        let mut encoder = StateEncoder::new(config, DetRng::new(37));
        let snapshot = create_large_snapshot(8_192);
        let encoded = encoder.encode(&snapshot, Time::ZERO).unwrap();
        let duplicate = encoded
            .source_symbols()
            .next()
            .expect("expected at least one source symbol")
            .clone();
        let mut symbols = encoded.symbols.clone();
        symbols.push(duplicate);
        let malformed = EncodedState {
            params: encoded.params,
            symbols,
            source_count: encoded.source_count,
            repair_count: encoded.repair_count,
            original_size: encoded.original_size,
            encoded_at: encoded.encoded_at,
            layout_decision: Default::default(),
        };

        let err = encoder
            .generate_repair(&malformed, 1)
            .expect_err("duplicate source symbols must be rejected");
        assert!(
            matches!(err, EncodingError::Pipeline(ref message) if message.contains("duplicate source symbol")),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn encode_allows_full_256_block_boundary_via_config() {
        let config = EncodingConfig {
            symbol_size: 1,
            min_repair_symbols: 0,
            max_source_blocks: 256,
            repair_overhead: 1.0,
            ..Default::default()
        };
        let mut encoder = StateEncoder::new(config, DetRng::new(29));
        let mut snapshot = create_test_snapshot();

        while {
            let len = snapshot.to_bytes().len();
            len < 512 || !len.is_multiple_of(256)
        } {
            snapshot.metadata.push(0xAB);
        }

        let encoded = encoder.encode(&snapshot, Time::ZERO).unwrap();

        assert_eq!(encoded.params.source_blocks, 256);
        assert!(
            encoded
                .symbols
                .iter()
                .any(|symbol| symbol.id().sbn() == 255)
        );
    }

    #[test]
    fn encode_empty_snapshot() {
        let config = EncodingConfig {
            symbol_size: 128,
            ..Default::default()
        };
        let mut encoder = StateEncoder::new(config, DetRng::new(42));

        let snapshot = RegionSnapshot::empty(RegionId::new_for_test(1, 0));
        let result = encoder.encode(&snapshot, Time::ZERO);

        // Should succeed with minimal symbols.
        assert!(result.is_ok());
        assert!(result.unwrap().source_count >= 1);
    }

    #[test]
    fn encoded_state_min_symbols_for_decode() {
        let config = EncodingConfig::default();
        let mut encoder = StateEncoder::new(config, DetRng::new(42));

        let snapshot = create_test_snapshot();
        let encoded = encoder.encode(&snapshot, Time::ZERO).unwrap();

        assert_eq!(encoded.min_symbols_for_decode(), encoded.source_count);
    }

    #[test]
    fn source_and_repair_separated() {
        let config = EncodingConfig {
            symbol_size: 64,
            min_repair_symbols: 3,
            ..Default::default()
        };
        let mut encoder = StateEncoder::new(config, DetRng::new(42));

        let snapshot = create_test_snapshot();
        let encoded = encoder.encode(&snapshot, Time::ZERO).unwrap();

        let source_count = encoded.source_symbols().count();
        let repair_count = encoded.repair_symbols().count();

        assert!(source_count > 0, "should have source symbols");
        assert_eq!(repair_count, 3, "should have 3 repair symbols");
        assert_eq!(source_count + repair_count, encoded.symbols.len());
    }

    #[test]
    fn test_encode_oversized_snapshot_splits_symbols() {
        let config = EncodingConfig {
            symbol_size: 64,
            min_repair_symbols: 0,
            ..Default::default()
        };
        let mut encoder = StateEncoder::new(config, DetRng::new(101));
        let mut snapshot = create_test_snapshot();
        snapshot.metadata = vec![0xAB; 64 * 3 + 7];

        let bytes = snapshot.to_bytes();

        let encoded = encoder.encode(&snapshot, Time::ZERO).unwrap();

        assert!(
            encoded.source_count > 1,
            "expected split into multiple source symbols"
        );
        let reconstructed = rebuild_source_bytes(&encoded);
        assert_eq!(reconstructed, bytes);
    }

    #[test]
    fn test_encode_empty_snapshot_zero_budget_roundtrip() {
        let config = EncodingConfig {
            symbol_size: 128,
            min_repair_symbols: 1,
            ..Default::default()
        };
        let mut encoder = StateEncoder::new(config, DetRng::new(7));
        let snapshot = RegionSnapshot::empty(RegionId::new_for_test(9, 0));

        let encoded = encoder.encode(&snapshot, Time::ZERO).unwrap();

        let decoded = decode_roundtrip(&encoded);
        assert!(decoded.tasks.is_empty());
        assert!(decoded.children.is_empty());
        assert!(decoded.budget.deadline_nanos.is_none());
        assert!(decoded.budget.polls_remaining.is_none());
        assert!(decoded.budget.cost_remaining.is_none());
    }

    #[test]
    fn test_encode_max_nesting_depth_children_roundtrip() {
        let config = EncodingConfig {
            symbol_size: 128,
            min_repair_symbols: 2,
            ..Default::default()
        };
        let mut encoder = StateEncoder::new(config, DetRng::new(22));
        let mut snapshot = create_test_snapshot();
        snapshot.children = (0..128)
            .map(|i| RegionId::new_for_test(200 + i, 0))
            .collect();

        let encoded = encoder.encode(&snapshot, Time::ZERO).unwrap();

        let decoded = decode_roundtrip(&encoded);
        assert_eq!(decoded.children.len(), 128);
        assert_eq!(decoded.children[0], snapshot.children[0]);
        assert_eq!(decoded.children[127], snapshot.children[127]);
    }

    #[test]
    fn test_encode_zero_length_metadata_roundtrip() {
        let config = EncodingConfig {
            symbol_size: 96,
            min_repair_symbols: 1,
            ..Default::default()
        };
        let mut encoder = StateEncoder::new(config, DetRng::new(5));
        let mut snapshot = create_test_snapshot();
        snapshot.metadata = Vec::new();

        let encoded = encoder.encode(&snapshot, Time::ZERO).unwrap();

        let decoded = decode_roundtrip(&encoded);
        assert!(decoded.metadata.is_empty());
        assert_eq!(decoded.tasks.len(), snapshot.tasks.len());
    }

    #[test]
    fn test_encode_extreme_budget_values_roundtrip() {
        let config = EncodingConfig {
            symbol_size: 128,
            min_repair_symbols: 1,
            ..Default::default()
        };
        let mut encoder = StateEncoder::new(config, DetRng::new(99));
        let mut snapshot = create_test_snapshot();
        snapshot.budget.deadline_nanos = Some(0);
        snapshot.budget.polls_remaining = Some(u32::MAX);
        snapshot.budget.cost_remaining = Some(u64::MAX);

        let encoded = encoder.encode(&snapshot, Time::ZERO).unwrap();

        let decoded = decode_roundtrip(&encoded);
        assert_eq!(decoded.budget.deadline_nanos, Some(0));
        assert_eq!(decoded.budget.polls_remaining, Some(u32::MAX));
        assert_eq!(decoded.budget.cost_remaining, Some(u64::MAX));
    }

    #[test]
    fn test_encode_deterministic_fuzz_same_seed() {
        let config = EncodingConfig::default();
        let mut encoder1 = StateEncoder::new(config.clone(), DetRng::new(4242));
        let mut encoder2 = StateEncoder::new(config, DetRng::new(4242));
        let mut snapshot_rng = DetRng::new(9001);

        for i in 0..8 {
            let mut snapshot = create_test_snapshot();
            let task_count = 1 + snapshot_rng.next_usize(4);
            let child_count = snapshot_rng.next_usize(6);
            let metadata_len = snapshot_rng.next_usize(128);
            let i_u32 = u32::try_from(i).expect("iteration fits u32");
            let task_count_u32 = u32::try_from(task_count).expect("task_count fits u32");
            let child_count_u32 = u32::try_from(child_count).expect("child_count fits u32");

            snapshot.tasks = (0..task_count_u32)
                .map(|t| TaskSnapshot {
                    task_id: crate::types::TaskId::new_for_test(i_u32 * 10 + t, 0),
                    state: if snapshot_rng.next_bool() {
                        TaskState::Running
                    } else {
                        TaskState::Pending
                    },
                    priority: u8::try_from(snapshot_rng.next_usize(10))
                        .expect("priority fits u8")
                        .max(1),
                })
                .collect();
            snapshot.children = (0..child_count_u32)
                .map(|c| RegionId::new_for_test(i_u32 * 100 + c, 0))
                .collect();
            snapshot.metadata = vec![0u8; metadata_len];
            snapshot_rng.fill_bytes(&mut snapshot.metadata);

            let encoded1 = encoder1.encode(&snapshot, Time::ZERO).unwrap();
            let encoded2 = encoder2.encode(&snapshot, Time::ZERO).unwrap();

            assert_eq!(encoded1.params.object_id, encoded2.params.object_id);
            assert_eq!(encoded1.symbols.len(), encoded2.symbols.len());
            for (s1, s2) in encoded1.symbols.iter().zip(encoded2.symbols.iter()) {
                assert_eq!(s1.id(), s2.id());
                assert_eq!(s1.data(), s2.data());
            }
        }
    }

    #[test]
    fn test_encode_repair_symbols_zero_when_configured() {
        let config = EncodingConfig {
            symbol_size: 128,
            min_repair_symbols: 0,
            repair_overhead: 1.0,
            ..Default::default()
        };
        let mut encoder = StateEncoder::new(config, DetRng::new(11));
        let snapshot = create_test_snapshot();

        let encoded = encoder.encode(&snapshot, Time::ZERO).unwrap();

        assert_eq!(encoded.repair_count, 0);
        assert_eq!(encoded.repair_symbols().count(), 0);
        assert_eq!(encoded.symbols.len(), encoded.source_count as usize);
    }

    #[test]
    fn test_encode_symbol_size_boundary_exact_multiple() {
        let symbol_size = 64usize;
        let mut snapshot = create_test_snapshot();
        let base = snapshot.to_bytes().len();
        let remainder = base % symbol_size;
        let pad = if remainder == 0 {
            0
        } else {
            symbol_size - remainder
        };
        snapshot.metadata = vec![0xCD; pad];

        let bytes = snapshot.to_bytes();

        let config = EncodingConfig {
            symbol_size: u16::try_from(symbol_size).expect("symbol_size fits u16"),
            min_repair_symbols: 1,
            ..Default::default()
        };
        let mut encoder = StateEncoder::new(config, DetRng::new(3));
        let encoded = encoder.encode(&snapshot, Time::ZERO).unwrap();

        assert_eq!(encoded.original_size % symbol_size, 0);
        assert_eq!(
            usize::from(encoded.source_count) * symbol_size,
            encoded.original_size
        );
        let reconstructed = rebuild_source_bytes(&encoded);
        assert_eq!(reconstructed, bytes);
    }

    #[test]
    fn encode_rejects_symbol_count_overflow() {
        let config = EncodingConfig {
            symbol_size: 1,
            min_repair_symbols: 0,
            ..Default::default()
        };
        let mut encoder = StateEncoder::new(config, DetRng::new(99));
        let mut snapshot = create_test_snapshot();
        snapshot.metadata = vec![0_u8; usize::from(u16::MAX) + 1024];

        let err = encoder
            .encode(&snapshot, Time::ZERO)
            .expect_err("expected symbol count overflow");
        assert!(matches!(
            err,
            EncodingError::SymbolCountOverflow {
                field: "symbols_per_block",
                ..
            }
        ));
    }

    #[test]
    fn redundancy_factor_handles_large_counts_without_overflow() {
        let encoded = EncodedState {
            params: ObjectParams::new(ObjectId::new_for_test(1), 0, 1, 1, 1),
            symbols: Vec::new(),
            source_count: u16::MAX,
            repair_count: u16::MAX,
            original_size: 0,
            encoded_at: Time::ZERO,
            layout_decision: Default::default(),
        };

        let redundancy = encoded.redundancy_factor();
        assert!((redundancy - 2.0).abs() < f32::EPSILON);
    }

    #[test]
    fn encoding_envelope_v2_snapshot() {
        // Keep this wire/layout fixture's explicit one/two-repair budgets;
        // overhead-derived counts are covered independently below.
        let mut base_encoder = StateEncoder::new(
            EncodingConfig {
                symbol_size: 48,
                min_repair_symbols: 1,
                max_source_blocks: 1,
                repair_overhead: 1.0,
                ..Default::default()
            },
            DetRng::new(111),
        );
        let mut extension_encoder = StateEncoder::new(
            EncodingConfig {
                symbol_size: 24,
                min_repair_symbols: 2,
                max_source_blocks: 2,
                repair_overhead: 1.0,
                ..Default::default()
            },
            DetRng::new(222),
        );

        let base = base_encoder
            .encode_with_id(
                &create_test_snapshot(),
                ObjectId::new_for_test(0x10),
                Time::from_secs(77),
            )
            .expect("base encoding should succeed");
        let extension = extension_encoder
            .encode_with_id(
                &create_extension_snapshot(),
                ObjectId::new_for_test(0x20),
                Time::from_secs(88),
            )
            .expect("extension encoding should succeed");

        insta::with_settings!({sort_maps => true}, {
            insta::assert_json_snapshot!(
                "encoding_envelope_v2_scrubbed",
                serde_json::json!({
                    "base": scrub_encoded_state_envelope_for_snapshot_test("base", &base),
                    "extension": scrub_encoded_state_envelope_for_snapshot_test("extension", &extension),
                })
            );
        });
    }

    // --- wave 80 trait coverage ---

    #[test]
    fn encoding_config_debug_clone_default() {
        let c = EncodingConfig::default();
        assert_eq!(c.symbol_size, 1280);
        assert_eq!(c.min_repair_symbols, 4);
        assert_eq!(c.max_source_blocks, 1);
        let c2 = c.clone();
        assert_eq!(c2.symbol_size, c.symbol_size);
        let dbg = format!("{c:?}");
        assert!(dbg.contains("EncodingConfig"));
    }

    #[test]
    fn encoding_error_debug_clone_eq() {
        let e = EncodingError::EmptyData;
        let e2 = e.clone();
        assert_eq!(e, e2);
        assert_ne!(e, EncodingError::NoSourceSymbols);
        assert_ne!(e, EncodingError::Pipeline("x".into()));
        let dbg = format!("{e:?}");
        assert!(dbg.contains("EmptyData"));
    }

    #[test]
    fn encoding_error_incomplete_source_coverage_display() {
        let err = EncodingError::IncompleteSourceCoverage {
            block: 2,
            expected: 5,
            actual: 4,
        };
        let disp = format!("{err}");
        assert!(disp.contains("block 2"));
        assert!(disp.contains("expected 5"));
        assert!(disp.contains("got 4"));
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct CompletionMatrixObservation {
        scenario_id: &'static str,
        reason_id: &'static str,
        loss_ewma_permille: u16,
        rtt_ewma_ms: u32,
        reorder_depth: u16,
        static_source_blocks: u16,
        adaptive_source_blocks: u16,
        static_repair_symbols: u16,
        adaptive_repair_symbols: u16,
        static_score: u64,
        adaptive_score: u64,
    }

    fn replica_ack_completion_score(encoded: &EncodedState, quality: PathQualitySnapshot) -> u64 {
        let source_blocks = u64::from(encoded.params.source_blocks.max(1));
        let total_symbols = u64::from(encoded.source_count) + u64::from(encoded.repair_count);
        let loss_bucket = u64::from(quality.loss_ewma_permille.div_ceil(25));
        let rtt_ms = u64::from(quality.rtt_ewma_ms.max(1));
        let reorder_depth = u64::from(quality.reorder_depth);
        let symbol_work = total_symbols.saturating_mul(2);
        let block_control_cost = source_blocks
            .saturating_mul(rtt_ms)
            .saturating_mul(1 + loss_bucket);
        let reorder_cost = source_blocks
            .saturating_mul(reorder_depth)
            .saturating_mul(10);
        let raw_score = symbol_work
            .saturating_add(block_control_cost)
            .saturating_add(reorder_cost);
        let repair_margin_credit = u64::from(encoded.repair_count)
            .saturating_mul(u64::from(quality.loss_ewma_permille) + reorder_depth * 10)
            .saturating_mul(rtt_ms)
            .div_ceil(1000);

        raw_score.saturating_sub(repair_margin_credit.min(raw_score / 2))
    }

    fn adaptive_completion_matrix_observations() -> Vec<CompletionMatrixObservation> {
        let snapshot = create_large_snapshot(4_096);
        let cases = [
            (
                "clean-low-rtt",
                PathQualitySnapshot::new(20, 0, 0),
                "clean-low-rtt",
            ),
            (
                "clean-high-rtt",
                PathQualitySnapshot::new(120, 0, 0),
                "clean-high-rtt",
            ),
            (
                "loss-5pct-low-rtt",
                PathQualitySnapshot::new(20, 50, 2),
                "moderate-loss",
            ),
            (
                "loss-5pct-high-rtt",
                PathQualitySnapshot::new(120, 50, 2),
                "moderate-loss",
            ),
            (
                "loss-15pct-low-rtt",
                PathQualitySnapshot::new(20, 150, 4),
                "lossy",
            ),
            (
                "loss-15pct-high-rtt",
                PathQualitySnapshot::new(120, 150, 4),
                "lossy",
            ),
        ];

        cases
            .into_iter()
            .enumerate()
            .map(|(index, (scenario_id, quality, expected_reason))| {
                let object_id = ObjectId::new_for_test(
                    0xD0 + u64::try_from(index).expect("matrix index fits u64"),
                );
                let base_config = EncodingConfig {
                    symbol_size: 128,
                    min_repair_symbols: 4,
                    max_source_blocks: 8,
                    ..Default::default()
                };
                let static_encoded = StateEncoder::new(base_config.clone(), DetRng::new(0))
                    .encode_with_id(&snapshot, object_id, Time::ZERO)
                    .expect("static encoding should succeed");
                let adaptive_encoded = StateEncoder::new(
                    EncodingConfig {
                        path_quality: Some(quality),
                        ..base_config
                    },
                    DetRng::new(0),
                )
                .encode_with_id(&snapshot, object_id, Time::ZERO)
                .expect("adaptive encoding should succeed");

                assert_eq!(adaptive_encoded.layout_decision.reason_id, expected_reason);

                CompletionMatrixObservation {
                    scenario_id,
                    reason_id: adaptive_encoded.layout_decision.reason_id,
                    loss_ewma_permille: quality.loss_ewma_permille,
                    rtt_ewma_ms: quality.rtt_ewma_ms,
                    reorder_depth: quality.reorder_depth,
                    static_source_blocks: static_encoded.params.source_blocks,
                    adaptive_source_blocks: adaptive_encoded.params.source_blocks,
                    static_repair_symbols: static_encoded.repair_count,
                    adaptive_repair_symbols: adaptive_encoded.repair_count,
                    static_score: replica_ack_completion_score(&static_encoded, quality),
                    adaptive_score: replica_ack_completion_score(&adaptive_encoded, quality),
                }
            })
            .collect()
    }

    #[test]
    fn adaptive_completion_matrix_beats_static_on_lossy_cells_without_clean_regression() {
        let observations = adaptive_completion_matrix_observations();
        let rerun = adaptive_completion_matrix_observations();

        assert_eq!(observations, rerun, "matrix must be replay-deterministic");
        assert_eq!(observations.len(), 6);

        for observation in observations {
            if observation.loss_ewma_permille == 0 {
                assert!(
                    observation.adaptive_score <= observation.static_score,
                    "clean path must not regress: {observation:?}"
                );
            } else {
                assert!(
                    observation.adaptive_score < observation.static_score,
                    "lossy path should improve expected completion score: {observation:?}"
                );
                assert!(
                    observation.adaptive_source_blocks <= observation.static_source_blocks,
                    "lossy path should not split into more source blocks: {observation:?}"
                );
                assert!(
                    observation.adaptive_repair_symbols >= observation.static_repair_symbols,
                    "lossy path should not reduce repair margin: {observation:?}"
                );
            }
        }
    }
}
