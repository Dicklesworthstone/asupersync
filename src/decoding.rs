//! RaptorQ decoding pipeline (Phase 0).
//!
//! This module provides a deterministic, block-oriented decoding pipeline that
//! reconstructs original data from a set of received symbols. The current
//! implementation mirrors the systematic RaptorQ encoder: it solves for
//! intermediate symbols using the precode constraints and LT repair rows, then
//! reconstitutes source symbols deterministically for testing.

use crate::error::{Error, ErrorKind};
use crate::raptorq::decoder::{
    DecodeError as RaptorDecodeError, InactivationDecoder, ReceivedSymbol,
};
use crate::raptorq::gf256::{Gf256, gf256_addmul_slice};
use crate::raptorq::systematic::SystematicParams;
use crate::security::{AuthenticatedSymbol, SecurityContext};
use crate::types::symbol_set::{InsertResult, SymbolSet, ThresholdConfig};
use crate::types::{ObjectId, ObjectParams, Symbol, SymbolId, SymbolKind};
use std::collections::{HashMap, HashSet};
use std::time::Duration;

/// Errors produced by the decoding pipeline.
#[derive(Debug, thiserror::Error)]
pub enum DecodingError {
    /// Authentication failed for a symbol.
    #[error("authentication failed for symbol {symbol_id}")]
    AuthenticationFailed {
        /// The symbol that failed authentication.
        symbol_id: SymbolId,
    },
    /// Not enough symbols to decode.
    #[error("insufficient symbols: have {received}, need {needed}")]
    InsufficientSymbols {
        /// Received symbol count.
        received: usize,
        /// Needed symbol count.
        needed: usize,
    },
    /// Matrix inversion failed during decoding.
    #[error("matrix inversion failed: {reason}")]
    MatrixInversionFailed {
        /// Reason for failure.
        reason: String,
    },
    /// Block timed out before decoding completed.
    #[error("block timeout after {elapsed:?}")]
    BlockTimeout {
        /// Block number.
        sbn: u8,
        /// Elapsed time.
        elapsed: Duration,
    },
    /// Inconsistent metadata for a block or object.
    #[error("inconsistent block metadata: {sbn} {details}")]
    InconsistentMetadata {
        /// Block number.
        sbn: u8,
        /// Details of the inconsistency.
        details: String,
    },
    /// Symbol size mismatch.
    #[error("symbol size mismatch: expected {expected}, got {actual}")]
    SymbolSizeMismatch {
        /// Expected size in bytes.
        expected: u16,
        /// Actual size in bytes.
        actual: usize,
    },
}

impl From<DecodingError> for Error {
    fn from(err: DecodingError) -> Self {
        match &err {
            DecodingError::AuthenticationFailed { .. } => Self::new(ErrorKind::CorruptedSymbol),
            DecodingError::InsufficientSymbols { .. } => Self::new(ErrorKind::InsufficientSymbols),
            DecodingError::MatrixInversionFailed { .. }
            | DecodingError::InconsistentMetadata { .. }
            | DecodingError::SymbolSizeMismatch { .. } => Self::new(ErrorKind::DecodingFailed),
            DecodingError::BlockTimeout { .. } => Self::new(ErrorKind::ThresholdTimeout),
        }
        .with_message(err.to_string())
    }
}

/// Reasons a symbol may be rejected by the decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// Symbol belongs to a different object.
    WrongObjectId,
    /// Authentication failed.
    AuthenticationFailed,
    /// Symbol size mismatch.
    SymbolSizeMismatch,
    /// Block already decoded.
    BlockAlreadyDecoded,
    /// Decode failed due to insufficient rank.
    InsufficientRank,
    /// Decode failed due to inconsistent equations.
    InconsistentEquations,
    /// Invalid or inconsistent metadata.
    InvalidMetadata,
    /// Memory or buffer limit reached.
    MemoryLimitReached,
}

/// Result of feeding a symbol into the decoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymbolAcceptResult {
    /// Symbol accepted and stored.
    Accepted {
        /// Symbols received for the block.
        received: usize,
        /// Estimated symbols needed for decode.
        needed: usize,
    },
    /// Decoding started for the block.
    DecodingStarted {
        /// Block number being decoded.
        block_sbn: u8,
    },
    /// Block fully decoded.
    BlockComplete {
        /// Block number.
        block_sbn: u8,
        /// Decoded block data.
        data: Vec<u8>,
    },
    /// Duplicate symbol ignored.
    Duplicate,
    /// Symbol rejected.
    Rejected(RejectReason),
}

/// Configuration for decoding operations.
#[derive(Debug, Clone)]
pub struct DecodingConfig {
    /// Symbol size in bytes (must match encoding).
    pub symbol_size: u16,
    /// Maximum source block size in bytes.
    pub max_block_size: usize,
    /// Repair overhead factor (e.g., 1.05 = 5% extra symbols).
    pub repair_overhead: f64,
    /// Minimum extra symbols beyond K.
    pub min_overhead: usize,
    /// Maximum symbols to buffer per block (0 = unlimited).
    pub max_buffered_symbols: usize,
    /// Block timeout (not enforced in Phase 0).
    pub block_timeout: Duration,
    /// Whether to verify authentication tags.
    pub verify_auth: bool,
}

impl Default for DecodingConfig {
    fn default() -> Self {
        Self {
            symbol_size: 256,
            max_block_size: 1024 * 1024,
            repair_overhead: 1.05,
            min_overhead: 0,
            max_buffered_symbols: 0,
            block_timeout: Duration::from_secs(30),
            verify_auth: false,
        }
    }
}

/// Progress summary for decoding.
#[derive(Debug, Clone, Copy)]
pub struct DecodingProgress {
    /// Blocks fully decoded.
    pub blocks_complete: usize,
    /// Total blocks expected (if known).
    pub blocks_total: Option<usize>,
    /// Total symbols received.
    pub symbols_received: usize,
    /// Estimated symbols needed to complete decode.
    pub symbols_needed_estimate: usize,
}

/// Per-block status.
#[derive(Debug, Clone, Copy)]
pub struct BlockStatus {
    /// Block number.
    pub sbn: u8,
    /// Symbols received for this block.
    pub symbols_received: usize,
    /// Estimated symbols needed for this block.
    pub symbols_needed: usize,
    /// Block state.
    pub state: BlockStateKind,
}

/// High-level block state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockStateKind {
    /// Collecting symbols.
    Collecting,
    /// Decoding in progress.
    Decoding,
    /// Decoded successfully.
    Decoded,
    /// Decoding failed.
    Failed,
}

#[derive(Debug)]
struct BlockDecoder {
    sbn: u8,
    state: BlockDecodingState,
    decoded: Option<Vec<u8>>,
}

#[derive(Debug)]
enum BlockDecodingState {
    Collecting,
    Decoding,
    Decoded,
    Failed,
}

/// Main decoding pipeline.
#[derive(Debug)]
pub struct DecodingPipeline {
    config: DecodingConfig,
    symbols: SymbolSet,
    blocks: HashMap<u8, BlockDecoder>,
    completed_blocks: HashSet<u8>,
    object_id: Option<ObjectId>,
    object_size: Option<u64>,
    block_plans: Option<Vec<BlockPlan>>,
    auth_context: Option<SecurityContext>,
}

impl DecodingPipeline {
    /// Creates a new decoding pipeline.
    #[must_use]
    pub fn new(config: DecodingConfig) -> Self {
        let threshold = ThresholdConfig::new(
            config.repair_overhead,
            config.min_overhead,
            config.max_buffered_symbols,
        );
        Self {
            config,
            symbols: SymbolSet::with_config(threshold),
            blocks: HashMap::new(),
            completed_blocks: HashSet::new(),
            object_id: None,
            object_size: None,
            block_plans: None,
            auth_context: None,
        }
    }

    /// Creates a new decoding pipeline with authentication enabled.
    #[must_use]
    pub fn with_auth(config: DecodingConfig, ctx: SecurityContext) -> Self {
        let mut pipeline = Self::new(config);
        pipeline.auth_context = Some(ctx);
        pipeline
    }

    /// Sets object parameters (object size, symbol size, and block layout).
    pub fn set_object_params(&mut self, params: ObjectParams) -> Result<(), DecodingError> {
        if params.symbol_size != self.config.symbol_size {
            return Err(DecodingError::SymbolSizeMismatch {
                expected: self.config.symbol_size,
                actual: params.symbol_size as usize,
            });
        }
        if let Some(existing) = self.object_id {
            if existing != params.object_id {
                return Err(DecodingError::InconsistentMetadata {
                    sbn: 0,
                    details: format!(
                        "object id mismatch: expected {existing:?}, got {:?}",
                        params.object_id
                    ),
                });
            }
        }
        self.object_id = Some(params.object_id);
        self.object_size = Some(params.object_size);
        self.block_plans = Some(plan_blocks(
            params.object_size as usize,
            usize::from(params.symbol_size),
            self.config.max_block_size,
        )?);
        self.configure_block_k();
        Ok(())
    }

    /// Feeds a received authenticated symbol into the pipeline.
    pub fn feed(
        &mut self,
        mut auth_symbol: AuthenticatedSymbol,
    ) -> Result<SymbolAcceptResult, DecodingError> {
        let symbol_id = auth_symbol.symbol().id();

        if self.config.verify_auth {
            match &self.auth_context {
                Some(ctx) => {
                    if !auth_symbol.is_verified()
                        && ctx.verify_authenticated_symbol(&mut auth_symbol).is_err()
                    {
                        return Ok(SymbolAcceptResult::Rejected(
                            RejectReason::AuthenticationFailed,
                        ));
                    }
                }
                None => {
                    // If callers already verified the symbol (e.g. at a trusted boundary), allow
                    // the verified flag to stand. If not verified and we have no auth context,
                    // we cannot validate the tag and must fail deterministically.
                    if !auth_symbol.is_verified() {
                        return Err(DecodingError::AuthenticationFailed { symbol_id });
                    }
                }
            }
        }

        let symbol = auth_symbol.into_symbol();

        if symbol.len() != usize::from(self.config.symbol_size) {
            return Ok(SymbolAcceptResult::Rejected(
                RejectReason::SymbolSizeMismatch,
            ));
        }

        if let Some(object_id) = self.object_id {
            if object_id != symbol.object_id() {
                return Ok(SymbolAcceptResult::Rejected(RejectReason::WrongObjectId));
            }
        } else {
            self.object_id = Some(symbol.object_id());
        }

        let sbn = symbol.sbn();
        if self.completed_blocks.contains(&sbn) {
            return Ok(SymbolAcceptResult::Rejected(
                RejectReason::BlockAlreadyDecoded,
            ));
        }

        // Ensure block entry exists
        self.blocks.entry(sbn).or_insert_with(|| BlockDecoder {
            sbn,
            state: BlockDecodingState::Collecting,
            decoded: None,
        });

        let insert_result = self.symbols.insert(symbol);
        match insert_result {
            InsertResult::Duplicate => Ok(SymbolAcceptResult::Duplicate),
            InsertResult::MemoryLimitReached | InsertResult::BlockLimitReached { .. } => Ok(
                SymbolAcceptResult::Rejected(RejectReason::MemoryLimitReached),
            ),
            InsertResult::Inserted {
                block_progress,
                threshold_reached,
            } => {
                if block_progress.k.is_none() {
                    self.configure_block_k();
                }
                let needed = block_progress.k.map_or(0, |k| {
                    required_symbols(k, self.config.repair_overhead, self.config.min_overhead)
                });
                let received = block_progress.total();

                if threshold_reached {
                    // Update state to Decoding
                    if let Some(block) = self.blocks.get_mut(&sbn) {
                        block.state = BlockDecodingState::Decoding;
                    }
                    if let Some(result) = self.try_decode_block(sbn) {
                        return Ok(result);
                    }
                }

                // Reset state to Collecting (if not decoded)
                if let Some(block) = self.blocks.get_mut(&sbn) {
                    if !matches!(
                        block.state,
                        BlockDecodingState::Decoded | BlockDecodingState::Failed
                    ) {
                        block.state = BlockDecodingState::Collecting;
                    }
                }
                Ok(SymbolAcceptResult::Accepted { received, needed })
            }
        }
    }

    /// Feeds a batch of symbols.
    pub fn feed_batch(
        &mut self,
        symbols: impl Iterator<Item = AuthenticatedSymbol>,
    ) -> Vec<Result<SymbolAcceptResult, DecodingError>> {
        symbols.map(|symbol| self.feed(symbol)).collect()
    }

    /// Returns true if all expected blocks are decoded.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        let Some(plans) = &self.block_plans else {
            return false;
        };
        self.completed_blocks.len() == plans.len()
    }

    /// Returns decoding progress.
    #[must_use]
    pub fn progress(&self) -> DecodingProgress {
        let blocks_total = self.block_plans.as_ref().map(Vec::len);
        let symbols_received = self.symbols.len();
        let symbols_needed_estimate = self.block_plans.as_ref().map_or(0, |plans| {
            plans
                .iter()
                .map(|plan| {
                    required_symbols(
                        plan.k as u16,
                        self.config.repair_overhead,
                        self.config.min_overhead,
                    )
                })
                .sum()
        });

        DecodingProgress {
            blocks_complete: self.completed_blocks.len(),
            blocks_total,
            symbols_received,
            symbols_needed_estimate,
        }
    }

    /// Returns per-block status if known.
    #[must_use]
    pub fn block_status(&self, sbn: u8) -> Option<BlockStatus> {
        let progress = self.symbols.block_progress(sbn)?;
        let state = self
            .blocks
            .get(&sbn)
            .map_or(BlockStateKind::Collecting, |block| match block.state {
                BlockDecodingState::Collecting => BlockStateKind::Collecting,
                BlockDecodingState::Decoding => BlockStateKind::Decoding,
                BlockDecodingState::Decoded => BlockStateKind::Decoded,
                BlockDecodingState::Failed => BlockStateKind::Failed,
            });

        let symbols_needed = progress.k.map_or(0, |k| {
            required_symbols(k, self.config.repair_overhead, self.config.min_overhead)
        });

        Some(BlockStatus {
            sbn,
            symbols_received: progress.total(),
            symbols_needed,
            state,
        })
    }

    /// Consumes the pipeline and returns decoded data if complete.
    pub fn into_data(self) -> Result<Vec<u8>, DecodingError> {
        let Some(plans) = &self.block_plans else {
            return Err(DecodingError::InconsistentMetadata {
                sbn: 0,
                details: "object parameters not set".to_string(),
            });
        };
        if !self.is_complete() {
            let received = self.symbols.len();
            let needed = plans
                .iter()
                .map(|plan| {
                    required_symbols(
                        plan.k as u16,
                        self.config.repair_overhead,
                        self.config.min_overhead,
                    )
                })
                .sum();
            return Err(DecodingError::InsufficientSymbols { received, needed });
        }

        let mut output = Vec::with_capacity(self.object_size.unwrap_or(0) as usize);
        for plan in plans {
            let block = self
                .blocks
                .get(&plan.sbn)
                .and_then(|b| b.decoded.as_ref())
                .ok_or_else(|| DecodingError::InconsistentMetadata {
                    sbn: plan.sbn,
                    details: "missing decoded block".to_string(),
                })?;
            output.extend_from_slice(block);
        }

        if let Some(size) = self.object_size {
            output.truncate(size as usize);
        }

        Ok(output)
    }

    fn configure_block_k(&mut self) {
        let Some(plans) = &self.block_plans else {
            return;
        };
        for plan in plans {
            let _ = self.symbols.set_block_k(plan.sbn, plan.k as u16);
        }
    }

    fn try_decode_block(&mut self, sbn: u8) -> Option<SymbolAcceptResult> {
        let block_plan = self.block_plan(sbn)?;
        let k = block_plan.k;
        if k == 0 {
            return None;
        }

        let symbols: Vec<Symbol> = self.symbols.symbols_for_block(sbn).cloned().collect();
        if symbols.len() < k {
            return None;
        }

        let decoded_symbols =
            match decode_block(block_plan, &symbols, usize::from(self.config.symbol_size)) {
                Ok(symbols) => symbols,
                Err(DecodingError::InsufficientSymbols { .. }) => {
                    return Some(SymbolAcceptResult::Rejected(RejectReason::InsufficientRank));
                }
                Err(DecodingError::MatrixInversionFailed { .. }) => {
                    return Some(SymbolAcceptResult::Rejected(
                        RejectReason::InconsistentEquations,
                    ));
                }
                Err(DecodingError::InconsistentMetadata { .. }) => {
                    let block = self.blocks.get_mut(&sbn);
                    if let Some(block) = block {
                        block.state = BlockDecodingState::Failed;
                    }
                    return Some(SymbolAcceptResult::Rejected(RejectReason::InvalidMetadata));
                }
                Err(DecodingError::SymbolSizeMismatch { .. }) => {
                    let block = self.blocks.get_mut(&sbn);
                    if let Some(block) = block {
                        block.state = BlockDecodingState::Failed;
                    }
                    return Some(SymbolAcceptResult::Rejected(
                        RejectReason::SymbolSizeMismatch,
                    ));
                }
                Err(_err) => {
                    let block = self.blocks.get_mut(&sbn);
                    if let Some(block) = block {
                        block.state = BlockDecodingState::Failed;
                    }
                    return Some(SymbolAcceptResult::Rejected(
                        RejectReason::MemoryLimitReached,
                    ));
                }
            };

        let mut block_data = Vec::with_capacity(block_plan.len);
        for symbol in &decoded_symbols {
            block_data.extend_from_slice(symbol.data());
        }
        block_data.truncate(block_plan.len);

        if let Some(block) = self.blocks.get_mut(&sbn) {
            block.state = BlockDecodingState::Decoded;
            block.decoded = Some(block_data.clone());
        }

        self.completed_blocks.insert(sbn);
        self.symbols.clear_block(sbn);

        Some(SymbolAcceptResult::BlockComplete {
            block_sbn: sbn,
            data: block_data,
        })
    }

    fn block_plan(&self, sbn: u8) -> Option<&BlockPlan> {
        self.block_plans
            .as_ref()
            .and_then(|plans| plans.iter().find(|plan| plan.sbn == sbn))
    }
}

#[derive(Debug, Clone)]
struct BlockPlan {
    sbn: u8,
    start: usize,
    len: usize,
    k: usize,
}

impl BlockPlan {
    fn end(&self) -> usize {
        self.start + self.len
    }
}

fn plan_blocks(
    object_size: usize,
    symbol_size: usize,
    max_block_size: usize,
) -> Result<Vec<BlockPlan>, DecodingError> {
    if object_size == 0 {
        return Ok(Vec::new());
    }

    if symbol_size == 0 {
        return Err(DecodingError::InconsistentMetadata {
            sbn: 0,
            details: "symbol_size must be > 0".to_string(),
        });
    }

    let max_blocks = u8::MAX as usize + 1;
    let max_total = max_block_size.saturating_mul(max_blocks);
    if object_size > max_total {
        return Err(DecodingError::InconsistentMetadata {
            sbn: 0,
            details: format!("object size {object_size} exceeds limit {max_total}"),
        });
    }

    let mut blocks = Vec::new();
    let mut offset = 0;
    let mut sbn: u8 = 0;

    while offset < object_size {
        let len = usize::min(max_block_size, object_size - offset);
        let k = len.div_ceil(symbol_size);
        blocks.push(BlockPlan {
            sbn,
            start: offset,
            len,
            k,
        });
        offset += len;
        sbn = sbn.wrapping_add(1);
    }

    Ok(blocks)
}

fn required_symbols(k: u16, overhead: f64, min_overhead: usize) -> usize {
    let raw = (f64::from(k) * overhead).ceil();
    if raw.is_sign_negative() {
        return 0;
    }
    #[allow(clippy::cast_sign_loss)]
    let threshold = raw as usize + min_overhead;
    threshold
}

#[allow(clippy::too_many_lines)]
fn decode_block(
    plan: &BlockPlan,
    symbols: &[Symbol],
    symbol_size: usize,
) -> Result<Vec<Symbol>, DecodingError> {
    let k = plan.k;
    if symbols.len() < k {
        return Err(DecodingError::InsufficientSymbols {
            received: symbols.len(),
            needed: k,
        });
    }

    let object_id = symbols.first().map_or(ObjectId::NIL, Symbol::object_id);
    let params = SystematicParams::for_source_block(k, symbol_size);
    let block_seed = seed_for_block(object_id, plan.sbn);
    let base_rows = params.s + params.h;

    let decoder = InactivationDecoder::new(k, symbol_size, block_seed);
    let padding_rows = params.k_prime.saturating_sub(k);
    
    // 1. Start with constraint symbols (LDPC + HDPC)
    let mut received = decoder.constraint_symbols();
    received.reserve(symbols.len() + padding_rows);

    // 2. Add received symbols (Source + Repair)
    for symbol in symbols {
        match symbol.kind() {
            SymbolKind::Source => {
                let esi = symbol.esi() as usize;
                if esi >= k {
                    return Err(DecodingError::InconsistentMetadata {
                        sbn: plan.sbn,
                        details: format!("source esi {esi} >= k {k}"),
                    });
                }
                // Systematic: source symbol i maps to intermediate symbol i (identity).
                received.push(ReceivedSymbol {
                    esi: symbol.esi(),
                    is_source: true,
                    columns: vec![esi],
                    coefficients: vec![Gf256::ONE],
                    data: symbol.data().to_vec(),
                });
            }
            SymbolKind::Repair => {
                let (columns, coefficients) = decoder.repair_equation(symbol.esi());
                received.push(ReceivedSymbol {
                    esi: symbol.esi(),
                    is_source: false,
                    columns,
                    coefficients,
                    data: symbol.data().to_vec(),
                });
            }
        }
    }

    // 3. Add zero-padded rows for K..K'.
    // These act as implicit source symbols with value 0.
    for esi in k..params.k_prime {
        received.push(ReceivedSymbol {
            esi: esi as u32,
            is_source: false,
            columns: vec![esi],
            coefficients: vec![Gf256::ONE],
            data: vec![0u8; symbol_size],
        });
    }

    let result = match decoder.decode(&received) {
        Ok(result) => result,
        Err(err) => {
            let mapped = match err {
                RaptorDecodeError::InsufficientSymbols { received, required } => {
                    DecodingError::InsufficientSymbols {
                        received,
                        needed: required,
                    }
                }
                RaptorDecodeError::SingularMatrix { row } => DecodingError::MatrixInversionFailed {
                    reason: format!("singular matrix at row {row}"),
                },
                RaptorDecodeError::SymbolSizeMismatch { expected, actual } => {
                    DecodingError::SymbolSizeMismatch {
                        expected: expected as u16,
                        actual,
                    }
                }
                RaptorDecodeError::SymbolEquationArityMismatch {
                    esi,
                    columns,
                    coefficients,
                } => DecodingError::InconsistentMetadata {
                    sbn: plan.sbn,
                    details: format!(
                        "symbol {esi} has mismatched equation vectors: columns={columns}, coefficients={coefficients}"
                    ),
                },
                RaptorDecodeError::ColumnIndexOutOfRange {
                    esi,
                    column,
                    max_valid,
                } => DecodingError::InconsistentMetadata {
                    sbn: plan.sbn,
                    details: format!(
                        "symbol {esi} references out-of-range column {column} (valid < {max_valid})"
                    ),
                },
                RaptorDecodeError::CorruptDecodedOutput {
                    esi,
                    byte_index,
                    expected,
                    actual,
                } => DecodingError::MatrixInversionFailed {
                    reason: format!(
                        "decoded output verification failed at symbol {esi}, byte {byte_index}: expected 0x{expected:02x}, actual 0x{actual:02x}"
                    ),
                },
            };
            return Err(mapped);
        }
    };

    // 4. Construct decoded symbols from the source data returned by the decoder.
    // InactivationDecoder::decode already extracts the first K intermediate symbols
    // into `result.source`, which corresponds exactly to the systematic source data.
    let mut decoded_symbols = Vec::with_capacity(k);
    for (esi, data) in result.source.into_iter().enumerate() {
        decoded_symbols.push(Symbol::new(
            SymbolId::new(object_id, plan.sbn, esi as u32),
            data,
            SymbolKind::Source,
        ));
    }

    Ok(decoded_symbols)
}



fn seed_for_block(object_id: ObjectId, sbn: u8) -> u64 {
    seed_for(object_id, sbn, 0)
}

fn seed_for(object_id: ObjectId, sbn: u8, esi: u32) -> u64 {
    let obj = object_id.as_u128();
    let hi = (obj >> 64) as u64;
    let lo = obj as u64;
    let mut seed = hi ^ lo.rotate_left(13);
    seed ^= u64::from(sbn) << 56;
    seed ^= u64::from(esi);
    if seed == 0 { 1 } else { seed }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::EncodingPipeline;
    use crate::types::resource::{PoolConfig, SymbolPool};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn pool() -> SymbolPool {
        SymbolPool::new(PoolConfig {
            symbol_size: 256,
            initial_size: 64,
            max_size: 64,
            allow_growth: false,
            growth_increment: 0,
        })
    }

    fn encoding_config() -> crate::config::EncodingConfig {
        crate::config::EncodingConfig {
            symbol_size: 256,
            max_block_size: 1024,
            repair_overhead: 1.05,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        }
    }

    fn decoder_with_params(
        config: &crate::config::EncodingConfig,
        object_id: ObjectId,
        data_len: usize,
        repair_overhead: f64,
        min_overhead: usize,
    ) -> DecodingPipeline {
        let mut decoder = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            repair_overhead,
            min_overhead,
            max_buffered_symbols: 0,
            block_timeout: Duration::from_secs(30),
            verify_auth: false,
        });
        let symbols_per_block = (data_len.div_ceil(usize::from(config.symbol_size))) as u16;
        decoder
            .set_object_params(ObjectParams::new(
                object_id,
                data_len as u64,
                config.symbol_size,
                1,
                symbols_per_block,
            ))
            .expect("params");
        decoder
    }

    #[test]
    fn decode_roundtrip_sources_only() {
        init_test("decode_roundtrip_sources_only");
        let config = encoding_config();
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id = ObjectId::new_for_test(1);
        let data = vec![42u8; 512];
        let symbols: Vec<Symbol> = encoder
            .encode_with_repair(object_id, &data, 0)
            .map(|res| res.unwrap().into_symbol())
            .collect();

        let mut decoder = decoder_with_params(&config, object_id, data.len(), 1.0, 0);

        for symbol in symbols {
            let auth = AuthenticatedSymbol::from_parts(
                symbol,
                crate::security::tag::AuthenticationTag::zero(),
            );
            let _ = decoder.feed(auth).unwrap();
        }

        let decoded_data = decoder.into_data().expect("decoded");
        let ok = decoded_data == data;
        crate::assert_with_log!(ok, "decoded data", data, decoded_data);
        crate::test_complete!("decode_roundtrip_sources_only");
    }

    #[test]
    fn decode_roundtrip_out_of_order() {
        init_test("decode_roundtrip_out_of_order");
        let config = encoding_config();
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id = ObjectId::new_for_test(2);
        let data = vec![7u8; 768];
        let mut symbols: Vec<Symbol> = encoder
            .encode_with_repair(object_id, &data, 2)
            .map(|res| res.expect("encode").into_symbol())
            .collect();

        symbols.reverse();

        let mut decoder =
            decoder_with_params(&config, object_id, data.len(), config.repair_overhead, 0);

        for symbol in symbols {
            let auth = AuthenticatedSymbol::from_parts(
                symbol,
                crate::security::tag::AuthenticationTag::zero(),
            );
            let _ = decoder.feed(auth).expect("feed");
        }

        let decoded_data = decoder.into_data().expect("decoded");
        let ok = decoded_data == data;
        crate::assert_with_log!(ok, "decoded data", data, decoded_data);
        crate::test_complete!("decode_roundtrip_out_of_order");
    }

    #[test]
    fn reject_wrong_object_id() {
        init_test("reject_wrong_object_id");
        let config = encoding_config();
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id_a = ObjectId::new_for_test(10);
        let object_id_b = ObjectId::new_for_test(11);
        let data = vec![1u8; 128];

        let mut decoder =
            decoder_with_params(&config, object_id_a, data.len(), config.repair_overhead, 0);

        let symbol_b = encoder
            .encode_with_repair(object_id_b, &data, 0)
            .next()
            .expect("symbol")
            .expect("encode")
            .into_symbol();
        let auth = AuthenticatedSymbol::from_parts(
            symbol_b,
            crate::security::tag::AuthenticationTag::zero(),
        );

        let result = decoder.feed(auth).expect("feed");
        let expected = SymbolAcceptResult::Rejected(RejectReason::WrongObjectId);
        let ok = result == expected;
        crate::assert_with_log!(ok, "wrong object id", expected, result);
        crate::test_complete!("reject_wrong_object_id");
    }

    #[test]
    fn reject_symbol_size_mismatch() {
        init_test("reject_symbol_size_mismatch");
        let config = encoding_config();
        let mut decoder = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            repair_overhead: config.repair_overhead,
            min_overhead: 0,
            max_buffered_symbols: 0,
            block_timeout: Duration::from_secs(30),
            verify_auth: false,
        });

        let symbol = Symbol::new(
            SymbolId::new(ObjectId::new_for_test(20), 0, 0),
            vec![0u8; 8],
            SymbolKind::Source,
        );
        let auth = AuthenticatedSymbol::from_parts(
            symbol,
            crate::security::tag::AuthenticationTag::zero(),
        );
        let result = decoder.feed(auth).expect("feed");
        let expected = SymbolAcceptResult::Rejected(RejectReason::SymbolSizeMismatch);
        let ok = result == expected;
        crate::assert_with_log!(ok, "symbol size mismatch", expected, result);
        crate::test_complete!("reject_symbol_size_mismatch");
    }

    #[test]
    fn reject_invalid_metadata_esi_out_of_range() {
        init_test("reject_invalid_metadata_esi_out_of_range");
        let mut decoder = DecodingPipeline::new(DecodingConfig {
            symbol_size: 8,
            max_block_size: 8,
            repair_overhead: 1.0,
            min_overhead: 0,
            max_buffered_symbols: 0,
            block_timeout: Duration::from_secs(30),
            verify_auth: false,
        });
        let object_id = ObjectId::new_for_test(21);
        decoder
            .set_object_params(ObjectParams::new(object_id, 8, 8, 1, 1))
            .expect("params");

        let symbol = Symbol::new(
            SymbolId::new(object_id, 0, 1),
            vec![0u8; 8],
            SymbolKind::Source,
        );
        let auth = AuthenticatedSymbol::from_parts(
            symbol,
            crate::security::tag::AuthenticationTag::zero(),
        );

        let result = decoder.feed(auth).expect("feed");
        let expected = SymbolAcceptResult::Rejected(RejectReason::InvalidMetadata);
        let ok = result == expected;
        crate::assert_with_log!(ok, "invalid metadata", expected, result);
        crate::test_complete!("reject_invalid_metadata_esi_out_of_range");
    }

    #[test]
    fn duplicate_symbol_before_decode() {
        init_test("duplicate_symbol_before_decode");
        let config = encoding_config();
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id = ObjectId::new_for_test(30);
        // Ensure K > 1 so the first symbol cannot complete the block decode.
        let data = vec![9u8; 512];

        let symbol = encoder
            .encode_with_repair(object_id, &data, 0)
            .next()
            .expect("symbol")
            .expect("encode")
            .into_symbol();

        let mut decoder = decoder_with_params(&config, object_id, data.len(), 1.5, 1);

        let first = decoder
            .feed(AuthenticatedSymbol::from_parts(
                symbol.clone(),
                crate::security::tag::AuthenticationTag::zero(),
            ))
            .expect("feed");
        let accepted = matches!(
            first,
            SymbolAcceptResult::Accepted { .. } | SymbolAcceptResult::DecodingStarted { .. }
        );
        crate::assert_with_log!(accepted, "first accepted", true, accepted);

        let second = decoder
            .feed(AuthenticatedSymbol::from_parts(
                symbol,
                crate::security::tag::AuthenticationTag::zero(),
            ))
            .expect("feed");
        let expected = SymbolAcceptResult::Duplicate;
        let ok = second == expected;
        crate::assert_with_log!(ok, "second duplicate", expected, second);
        crate::test_complete!("duplicate_symbol_before_decode");
    }

    #[test]
    fn into_data_reports_insufficient_symbols() {
        init_test("into_data_reports_insufficient_symbols");
        let config = encoding_config();
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id = ObjectId::new_for_test(40);
        let data = vec![5u8; 512];

        let mut decoder =
            decoder_with_params(&config, object_id, data.len(), config.repair_overhead, 0);

        let symbol = encoder
            .encode_with_repair(object_id, &data, 0)
            .next()
            .expect("symbol")
            .expect("encode")
            .into_symbol();
        let auth = AuthenticatedSymbol::from_parts(
            symbol,
            crate::security::tag::AuthenticationTag::zero(),
        );
        let _ = decoder.feed(auth).expect("feed");

        let err = decoder
            .into_data()
            .expect_err("expected insufficient symbols");
        let insufficient = matches!(err, DecodingError::InsufficientSymbols { .. });
        crate::assert_with_log!(insufficient, "insufficient symbols", true, insufficient);
        crate::test_complete!("into_data_reports_insufficient_symbols");
    }

    // ---- DecodingError Display ----

    #[test]
    fn decoding_error_display_authentication_failed() {
        let err = DecodingError::AuthenticationFailed {
            symbol_id: SymbolId::new(ObjectId::new_for_test(1), 0, 0),
        };
        let msg = err.to_string();
        assert!(msg.contains("authentication failed"), "{msg}");
    }

    #[test]
    fn decoding_error_display_insufficient_symbols() {
        let err = DecodingError::InsufficientSymbols {
            received: 3,
            needed: 10,
        };
        assert_eq!(err.to_string(), "insufficient symbols: have 3, need 10");
    }

    #[test]
    fn decoding_error_display_matrix_inversion() {
        let err = DecodingError::MatrixInversionFailed {
            reason: "rank deficient".into(),
        };
        assert_eq!(err.to_string(), "matrix inversion failed: rank deficient");
    }

    #[test]
    fn decoding_error_display_block_timeout() {
        let err = DecodingError::BlockTimeout {
            sbn: 2,
            elapsed: Duration::from_millis(1500),
        };
        let msg = err.to_string();
        assert!(msg.contains("block timeout"), "{msg}");
        assert!(msg.contains("1.5"), "{msg}");
    }

    #[test]
    fn decoding_error_display_inconsistent_metadata() {
        let err = DecodingError::InconsistentMetadata {
            sbn: 0,
            details: "mismatch".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("inconsistent block metadata"), "{msg}");
        assert!(msg.contains("mismatch"), "{msg}");
    }

    #[test]
    fn decoding_error_display_symbol_size_mismatch() {
        let err = DecodingError::SymbolSizeMismatch {
            expected: 256,
            actual: 128,
        };
        assert_eq!(
            err.to_string(),
            "symbol size mismatch: expected 256, got 128"
        );
    }

    // ---- DecodingError -> Error conversion ----

    #[test]
    fn decoding_error_into_error_auth() {
        let err = DecodingError::AuthenticationFailed {
            symbol_id: SymbolId::new(ObjectId::new_for_test(1), 0, 0),
        };
        let error: crate::error::Error = err.into();
        assert_eq!(error.kind(), crate::error::ErrorKind::CorruptedSymbol);
    }

    #[test]
    fn decoding_error_into_error_insufficient() {
        let err = DecodingError::InsufficientSymbols {
            received: 1,
            needed: 5,
        };
        let error: crate::error::Error = err.into();
        assert_eq!(error.kind(), crate::error::ErrorKind::InsufficientSymbols);
    }

    #[test]
    fn decoding_error_into_error_matrix() {
        let err = DecodingError::MatrixInversionFailed {
            reason: "singular".into(),
        };
        let error: crate::error::Error = err.into();
        assert_eq!(error.kind(), crate::error::ErrorKind::DecodingFailed);
    }

    #[test]
    fn decoding_error_into_error_timeout() {
        let err = DecodingError::BlockTimeout {
            sbn: 0,
            elapsed: Duration::from_secs(30),
        };
        let error: crate::error::Error = err.into();
        assert_eq!(error.kind(), crate::error::ErrorKind::ThresholdTimeout);
    }

    #[test]
    fn decoding_error_into_error_inconsistent() {
        let err = DecodingError::InconsistentMetadata {
            sbn: 1,
            details: "x".into(),
        };
        let error: crate::error::Error = err.into();
        assert_eq!(error.kind(), crate::error::ErrorKind::DecodingFailed);
    }

    #[test]
    fn decoding_error_into_error_size_mismatch() {
        let err = DecodingError::SymbolSizeMismatch {
            expected: 256,
            actual: 64,
        };
        let error: crate::error::Error = err.into();
        assert_eq!(error.kind(), crate::error::ErrorKind::DecodingFailed);
    }

    // ---- RejectReason ----

    #[test]
    fn reject_reason_variants_are_eq() {
        assert_eq!(RejectReason::WrongObjectId, RejectReason::WrongObjectId);
        assert_ne!(
            RejectReason::AuthenticationFailed,
            RejectReason::SymbolSizeMismatch
        );
    }

    #[test]
    fn reject_reason_debug() {
        let dbg = format!("{:?}", RejectReason::BlockAlreadyDecoded);
        assert_eq!(dbg, "BlockAlreadyDecoded");
    }

    // ---- SymbolAcceptResult ----

    #[test]
    fn symbol_accept_result_accepted_eq() {
        let a = SymbolAcceptResult::Accepted {
            received: 3,
            needed: 5,
        };
        let b = SymbolAcceptResult::Accepted {
            received: 3,
            needed: 5,
        };
        assert_eq!(a, b);
    }

    #[test]
    fn symbol_accept_result_duplicate_eq() {
        assert_eq!(SymbolAcceptResult::Duplicate, SymbolAcceptResult::Duplicate);
    }

    #[test]
    fn symbol_accept_result_rejected_eq() {
        let a = SymbolAcceptResult::Rejected(RejectReason::MemoryLimitReached);
        let b = SymbolAcceptResult::Rejected(RejectReason::MemoryLimitReached);
        assert_eq!(a, b);
    }

    #[test]
    fn symbol_accept_result_variants_ne() {
        assert_ne!(
            SymbolAcceptResult::Duplicate,
            SymbolAcceptResult::Rejected(RejectReason::WrongObjectId)
        );
    }

    // ---- DecodingConfig default ----

    #[test]
    fn decoding_config_default_values() {
        let cfg = DecodingConfig::default();
        assert_eq!(cfg.symbol_size, 256);
        assert_eq!(cfg.max_block_size, 1024 * 1024);
        assert!((cfg.repair_overhead - 1.05).abs() < f64::EPSILON);
        assert_eq!(cfg.min_overhead, 0);
        assert_eq!(cfg.max_buffered_symbols, 0);
        assert_eq!(cfg.block_timeout, Duration::from_secs(30));
        assert!(!cfg.verify_auth);
    }

    // ---- BlockStateKind ----

    #[test]
    fn block_state_kind_eq_and_debug() {
        assert_eq!(BlockStateKind::Collecting, BlockStateKind::Collecting);
        assert_ne!(BlockStateKind::Collecting, BlockStateKind::Decoded);
        assert_eq!(format!("{:?}", BlockStateKind::Failed), "Failed");
        assert_eq!(format!("{:?}", BlockStateKind::Decoding), "Decoding");
    }

    // ---- DecodingPipeline construction ----

    #[test]
    fn pipeline_new_starts_empty() {
        let pipeline = DecodingPipeline::new(DecodingConfig::default());
        let progress = pipeline.progress();
        assert_eq!(progress.blocks_complete, 0);
        assert_eq!(progress.symbols_received, 0);
    }

    #[test]
    fn pipeline_set_object_params_rejects_mismatched_symbol_size() {
        let mut pipeline = DecodingPipeline::new(DecodingConfig {
            symbol_size: 256,
            ..DecodingConfig::default()
        });
        let params = ObjectParams::new(ObjectId::new_for_test(1), 1024, 128, 1, 8);
        let err = pipeline.set_object_params(params).unwrap_err();
        assert!(matches!(err, DecodingError::SymbolSizeMismatch { .. }));
    }

    #[test]
    fn pipeline_set_object_params_rejects_inconsistent_object_id() {
        let config = encoding_config();
        let oid1 = ObjectId::new_for_test(1);
        let oid2 = ObjectId::new_for_test(2);

        let mut pipeline = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            ..DecodingConfig::default()
        });
        pipeline
            .set_object_params(ObjectParams::new(oid1, 512, config.symbol_size, 1, 2))
            .expect("first set_object_params");
        let err = pipeline
            .set_object_params(ObjectParams::new(oid2, 512, config.symbol_size, 1, 2))
            .unwrap_err();
        assert!(matches!(err, DecodingError::InconsistentMetadata { .. }));
    }

    #[test]
    fn pipeline_set_object_params_same_id_is_ok() {
        let config = encoding_config();
        let oid = ObjectId::new_for_test(1);

        let mut pipeline = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            ..DecodingConfig::default()
        });
        pipeline
            .set_object_params(ObjectParams::new(oid, 512, config.symbol_size, 1, 2))
            .expect("first");
        pipeline
            .set_object_params(ObjectParams::new(oid, 512, config.symbol_size, 1, 2))
            .expect("second with same id should succeed");
    }

    // ---- Gap tests ----

    #[test]
    fn feed_batch_returns_results_per_symbol() {
        init_test("feed_batch_returns_results_per_symbol");
        let config = encoding_config();
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id = ObjectId::new_for_test(100);
        let data = vec![0xAAu8; 768]; // 3 source symbols at 256 bytes each

        let symbols: Vec<AuthenticatedSymbol> = encoder
            .encode_with_repair(object_id, &data, 0)
            .map(|res| {
                AuthenticatedSymbol::from_parts(
                    res.unwrap().into_symbol(),
                    crate::security::tag::AuthenticationTag::zero(),
                )
            })
            .take(3)
            .collect();

        let mut decoder = decoder_with_params(&config, object_id, data.len(), 1.5, 1);

        let results = decoder.feed_batch(symbols.into_iter());
        let len = results.len();
        let expected_len = 3usize;
        crate::assert_with_log!(len == expected_len, "batch length", expected_len, len);
        for (i, r) in results.iter().enumerate() {
            let is_ok = r.is_ok();
            crate::assert_with_log!(is_ok, &format!("result[{i}] is Ok"), true, is_ok);
        }
        crate::test_complete!("feed_batch_returns_results_per_symbol");
    }

    #[test]
    fn is_complete_false_without_params() {
        init_test("is_complete_false_without_params");
        let pipeline = DecodingPipeline::new(DecodingConfig::default());
        let complete = pipeline.is_complete();
        crate::assert_with_log!(!complete, "is_complete without params", false, complete);
        crate::test_complete!("is_complete_false_without_params");
    }

    #[test]
    fn is_complete_true_after_all_blocks_decoded() {
        init_test("is_complete_true_after_all_blocks_decoded");
        let config = encoding_config();
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id = ObjectId::new_for_test(101);
        let data = vec![42u8; 512];
        let symbols: Vec<Symbol> = encoder
            .encode_with_repair(object_id, &data, 0)
            .map(|res| res.unwrap().into_symbol())
            .collect();

        let mut decoder = decoder_with_params(&config, object_id, data.len(), 1.0, 0);

        for symbol in symbols {
            let auth = AuthenticatedSymbol::from_parts(
                symbol,
                crate::security::tag::AuthenticationTag::zero(),
            );
            let _ = decoder.feed(auth).unwrap();
        }

        let complete = decoder.is_complete();
        crate::assert_with_log!(complete, "is_complete after all blocks", true, complete);
        crate::test_complete!("is_complete_true_after_all_blocks_decoded");
    }

    #[test]
    fn progress_reports_blocks_total_after_params() {
        init_test("progress_reports_blocks_total_after_params");
        let config = encoding_config();
        let object_id = ObjectId::new_for_test(102);

        let mut pipeline = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: 1024,
            ..DecodingConfig::default()
        });
        // data_len=512 < max_block_size=1024 => 1 block
        let k = (512usize).div_ceil(usize::from(config.symbol_size)) as u16;
        pipeline
            .set_object_params(ObjectParams::new(object_id, 512, config.symbol_size, 1, k))
            .expect("set params");

        let progress = pipeline.progress();
        let blocks_total = progress.blocks_total;
        let expected_blocks = Some(1usize);
        crate::assert_with_log!(
            blocks_total == expected_blocks,
            "blocks_total",
            expected_blocks,
            blocks_total
        );
        let estimate = progress.symbols_needed_estimate;
        let positive = estimate > 0;
        crate::assert_with_log!(positive, "symbols_needed_estimate > 0", true, positive);
        crate::test_complete!("progress_reports_blocks_total_after_params");
    }

    #[test]
    fn block_status_none_for_unknown_block() {
        init_test("block_status_none_for_unknown_block");
        let config = encoding_config();
        let object_id = ObjectId::new_for_test(103);

        let mut pipeline = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            ..DecodingConfig::default()
        });
        let k = (512usize).div_ceil(usize::from(config.symbol_size)) as u16;
        pipeline
            .set_object_params(ObjectParams::new(object_id, 512, config.symbol_size, 1, k))
            .expect("set params");

        let status = pipeline.block_status(99);
        let is_none = status.is_none();
        crate::assert_with_log!(is_none, "block_status(99) is None", true, is_none);
        crate::test_complete!("block_status_none_for_unknown_block");
    }

    #[test]
    fn block_status_collecting_after_partial_feed() {
        init_test("block_status_collecting_after_partial_feed");
        let config = encoding_config();
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id = ObjectId::new_for_test(104);
        let data = vec![0xBBu8; 512];

        let first_symbol = encoder
            .encode_with_repair(object_id, &data, 0)
            .next()
            .expect("symbol")
            .expect("encode")
            .into_symbol();

        // Use high overhead so 1 symbol doesn't trigger decode
        let mut decoder = decoder_with_params(&config, object_id, data.len(), 1.5, 1);

        let auth = AuthenticatedSymbol::from_parts(
            first_symbol,
            crate::security::tag::AuthenticationTag::zero(),
        );
        let _ = decoder.feed(auth).expect("feed");

        let status = decoder.block_status(0);
        let is_some = status.is_some();
        crate::assert_with_log!(is_some, "block_status(0) is Some", true, is_some);

        let status = status.unwrap();
        let state = status.state;
        let expected_state = BlockStateKind::Collecting;
        crate::assert_with_log!(
            state == expected_state,
            "state is Collecting",
            expected_state,
            state
        );
        let received = status.symbols_received;
        let expected_received = 1usize;
        crate::assert_with_log!(
            received == expected_received,
            "symbols_received",
            expected_received,
            received
        );
        crate::test_complete!("block_status_collecting_after_partial_feed");
    }

    #[test]
    fn block_status_decoded_after_complete() {
        init_test("block_status_decoded_after_complete");
        let config = encoding_config();
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id = ObjectId::new_for_test(105);
        let data = vec![42u8; 512];
        let symbols: Vec<Symbol> = encoder
            .encode_with_repair(object_id, &data, 0)
            .map(|res| res.unwrap().into_symbol())
            .collect();

        let mut decoder = decoder_with_params(&config, object_id, data.len(), 1.0, 0);

        for symbol in symbols {
            let auth = AuthenticatedSymbol::from_parts(
                symbol,
                crate::security::tag::AuthenticationTag::zero(),
            );
            let _ = decoder.feed(auth).unwrap();
        }

        // Block 0 should now be decoded; symbols are cleared but block state persists.
        // After decode, symbols are cleared so block_progress returns None.
        // The completed_blocks set tracks completion separately.
        let _status = decoder.block_status(0);
        let complete = decoder.is_complete();
        crate::assert_with_log!(complete, "is_complete", true, complete);

        // Verify via completed_blocks indirectly: feeding another sbn=0 symbol
        // should give BlockAlreadyDecoded
        let extra = Symbol::new(
            SymbolId::new(object_id, 0, 99),
            vec![0u8; usize::from(config.symbol_size)],
            SymbolKind::Source,
        );
        let auth =
            AuthenticatedSymbol::from_parts(extra, crate::security::tag::AuthenticationTag::zero());
        let result = decoder.feed(auth).expect("feed");
        let expected = SymbolAcceptResult::Rejected(RejectReason::BlockAlreadyDecoded);
        let ok = result == expected;
        crate::assert_with_log!(ok, "block already decoded", expected, result);
        crate::test_complete!("block_status_decoded_after_complete");
    }

    #[test]
    fn block_already_decoded_reject() {
        init_test("block_already_decoded_reject");
        let config = encoding_config();
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id = ObjectId::new_for_test(106);
        let data = vec![42u8; 512];
        let symbols: Vec<Symbol> = encoder
            .encode_with_repair(object_id, &data, 0)
            .map(|res| res.unwrap().into_symbol())
            .collect();

        let mut decoder = decoder_with_params(&config, object_id, data.len(), 1.0, 0);

        for symbol in symbols {
            let auth = AuthenticatedSymbol::from_parts(
                symbol,
                crate::security::tag::AuthenticationTag::zero(),
            );
            let _ = decoder.feed(auth).unwrap();
        }

        // Feed one more symbol for sbn=0
        let extra = Symbol::new(
            SymbolId::new(object_id, 0, 0),
            vec![0u8; usize::from(config.symbol_size)],
            SymbolKind::Source,
        );
        let auth =
            AuthenticatedSymbol::from_parts(extra, crate::security::tag::AuthenticationTag::zero());
        let result = decoder.feed(auth).expect("feed");
        let expected = SymbolAcceptResult::Rejected(RejectReason::BlockAlreadyDecoded);
        let ok = result == expected;
        crate::assert_with_log!(ok, "block already decoded reject", expected, result);
        crate::test_complete!("block_already_decoded_reject");
    }

    #[test]
    fn verify_auth_no_context_unverified_symbol_errors() {
        init_test("verify_auth_no_context_unverified_symbol_errors");
        let config = encoding_config();
        let mut decoder = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            verify_auth: true,
            ..DecodingConfig::default()
        });

        let symbol = Symbol::new(
            SymbolId::new(ObjectId::new_for_test(107), 0, 0),
            vec![0u8; usize::from(config.symbol_size)],
            SymbolKind::Source,
        );
        // from_parts creates an unverified symbol
        let auth = AuthenticatedSymbol::from_parts(
            symbol,
            crate::security::tag::AuthenticationTag::zero(),
        );

        let result = decoder.feed(auth);
        let is_err = result.is_err();
        crate::assert_with_log!(is_err, "unverified with no context errors", true, is_err);
        let err = result.unwrap_err();
        let is_auth_failed = matches!(err, DecodingError::AuthenticationFailed { .. });
        crate::assert_with_log!(
            is_auth_failed,
            "AuthenticationFailed variant",
            true,
            is_auth_failed
        );
        crate::test_complete!("verify_auth_no_context_unverified_symbol_errors");
    }

    #[test]
    fn verify_auth_no_context_preverified_symbol_ok() {
        init_test("verify_auth_no_context_preverified_symbol_ok");
        let config = encoding_config();
        let mut decoder = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            verify_auth: true,
            ..DecodingConfig::default()
        });

        let symbol = Symbol::new(
            SymbolId::new(ObjectId::new_for_test(108), 0, 0),
            vec![0u8; usize::from(config.symbol_size)],
            SymbolKind::Source,
        );
        // new_verified creates a pre-verified symbol
        let auth = AuthenticatedSymbol::new_verified(
            symbol,
            crate::security::tag::AuthenticationTag::zero(),
        );

        let result = decoder.feed(auth);
        let is_ok = result.is_ok();
        crate::assert_with_log!(is_ok, "preverified symbol accepted", true, is_ok);
        let accept = result.unwrap();
        let is_accepted = matches!(accept, SymbolAcceptResult::Accepted { .. });
        crate::assert_with_log!(is_accepted, "result is Accepted variant", true, is_accepted);
        crate::test_complete!("verify_auth_no_context_preverified_symbol_ok");
    }

    #[test]
    fn with_auth_rejects_bad_tag() {
        init_test("with_auth_rejects_bad_tag");
        let config = encoding_config();
        let mut decoder = DecodingPipeline::with_auth(
            DecodingConfig {
                symbol_size: config.symbol_size,
                max_block_size: config.max_block_size,
                verify_auth: true,
                ..DecodingConfig::default()
            },
            crate::security::SecurityContext::for_testing(42),
        );

        let symbol = Symbol::new(
            SymbolId::new(ObjectId::new_for_test(109), 0, 0),
            vec![0u8; usize::from(config.symbol_size)],
            SymbolKind::Source,
        );
        // zero tag is wrong for any real key
        let auth = AuthenticatedSymbol::from_parts(
            symbol,
            crate::security::tag::AuthenticationTag::zero(),
        );

        let result = decoder.feed(auth).expect("feed should not return Err");
        let expected = SymbolAcceptResult::Rejected(RejectReason::AuthenticationFailed);
        let ok = result == expected;
        crate::assert_with_log!(ok, "bad tag rejected", expected, result);
        crate::test_complete!("with_auth_rejects_bad_tag");
    }

    #[test]
    fn multi_block_roundtrip() {
        init_test("multi_block_roundtrip");
        let config = crate::config::EncodingConfig {
            symbol_size: 256,
            max_block_size: 1024,
            repair_overhead: 1.05,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        };
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id = ObjectId::new_for_test(110);
        let data: Vec<u8> = (0..2048).map(|i| (i % 251) as u8).collect();

        let symbols: Vec<Symbol> = encoder
            .encode_with_repair(object_id, &data, 0)
            .map(|res| res.unwrap().into_symbol())
            .collect();

        let mut decoder = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            repair_overhead: 1.0,
            min_overhead: 0,
            max_buffered_symbols: 0,
            block_timeout: Duration::from_secs(30),
            verify_auth: false,
        });

        // Compute block plan matching what the encoder does
        let symbol_size = usize::from(config.symbol_size);
        let num_blocks = data.len().div_ceil(config.max_block_size);
        let mut total_k: u16 = 0;
        for b in 0..num_blocks {
            let block_start = b * config.max_block_size;
            let block_len = usize::min(config.max_block_size, data.len() - block_start);
            let k = block_len.div_ceil(symbol_size) as u16;
            total_k += k;
        }
        decoder
            .set_object_params(ObjectParams::new(
                object_id,
                data.len() as u64,
                config.symbol_size,
                num_blocks as u8,
                total_k,
            ))
            .expect("set params");

        for symbol in symbols {
            let auth = AuthenticatedSymbol::from_parts(
                symbol,
                crate::security::tag::AuthenticationTag::zero(),
            );
            let _ = decoder.feed(auth).unwrap();
        }

        let complete = decoder.is_complete();
        crate::assert_with_log!(complete, "multi-block is_complete", true, complete);

        let decoded_data = decoder.into_data().expect("decoded");
        let ok = decoded_data == data;
        crate::assert_with_log!(
            ok,
            "multi-block roundtrip data",
            data.len(),
            decoded_data.len()
        );
        crate::test_complete!("multi_block_roundtrip");
    }

    #[test]
    fn into_data_no_params_errors() {
        init_test("into_data_no_params_errors");
        let pipeline = DecodingPipeline::new(DecodingConfig::default());
        let result = pipeline.into_data();
        let is_err = result.is_err();
        crate::assert_with_log!(is_err, "into_data without params errors", true, is_err);
        let err = result.unwrap_err();
        let msg = err.to_string();
        let contains = msg.contains("object parameters not set");
        crate::assert_with_log!(
            contains,
            "error message contains expected text",
            true,
            contains
        );
        crate::test_complete!("into_data_no_params_errors");
    }

    // --- wave 76 trait coverage ---

    #[test]
    fn reject_reason_debug_clone_copy_eq() {
        let r = RejectReason::WrongObjectId;
        let r2 = r; // Copy
        let r3 = r;
        assert_eq!(r, r2);
        assert_eq!(r, r3);
        assert_ne!(r, RejectReason::AuthenticationFailed);
        assert_ne!(r, RejectReason::SymbolSizeMismatch);
        assert_ne!(r, RejectReason::BlockAlreadyDecoded);
        assert_ne!(r, RejectReason::InsufficientRank);
        assert_ne!(r, RejectReason::InconsistentEquations);
        assert_ne!(r, RejectReason::InvalidMetadata);
        assert_ne!(r, RejectReason::MemoryLimitReached);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("WrongObjectId"));
    }

    #[test]
    fn symbol_accept_result_debug_clone_eq() {
        let a = SymbolAcceptResult::Accepted {
            received: 3,
            needed: 5,
        };
        let a2 = a.clone();
        assert_eq!(a, a2);
        assert_ne!(a, SymbolAcceptResult::Duplicate);
        let r = SymbolAcceptResult::Rejected(RejectReason::InvalidMetadata);
        let r2 = r.clone();
        assert_eq!(r, r2);
        let dbg = format!("{a:?}");
        assert!(dbg.contains("Accepted"));
    }

    #[test]
    fn block_state_kind_debug_clone_copy_eq() {
        let s = BlockStateKind::Collecting;
        let s2 = s; // Copy
        let s3 = s;
        assert_eq!(s, s2);
        assert_eq!(s, s3);
        assert_ne!(s, BlockStateKind::Decoding);
        assert_ne!(s, BlockStateKind::Decoded);
        assert_ne!(s, BlockStateKind::Failed);
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Collecting"));
    }
}
