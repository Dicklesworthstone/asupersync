//! RaptorQ decoding pipeline (Phase 0).
//!
//! This module provides a deterministic, block-oriented decoding pipeline that
//! reconstructs original data from a set of received symbols. The current
//! implementation mirrors the systematic RaptorQ encoder: it solves for
//! intermediate symbols using the precode constraints and LT repair rows, then
//! reconstitutes source symbols deterministically for testing.

use crate::error::{Error, ErrorKind};
use crate::raptorq::gf256::{gf256_addmul_slice, Gf256};
use crate::raptorq::systematic::{ConstraintMatrix, RobustSoliton, SystematicParams};
use crate::security::{AuthenticatedSymbol, SecurityContext};
use crate::types::symbol_set::{InsertResult, SymbolSet, ThresholdConfig};
use crate::types::{ObjectId, ObjectParams, Symbol, SymbolId, SymbolKind};
use crate::util::DetRng;
use std::collections::{BTreeSet, HashMap};
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
    completed_blocks: BTreeSet<u8>,
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
            completed_blocks: BTreeSet::new(),
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
            let Some(ctx) = &self.auth_context else {
                return Err(DecodingError::AuthenticationFailed { symbol_id });
            };
            if !auth_symbol.is_verified()
                && ctx.verify_authenticated_symbol(&mut auth_symbol).is_err()
            {
                return Ok(SymbolAcceptResult::Rejected(
                    RejectReason::AuthenticationFailed,
                ));
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

        let decoded_symbols = match decode_block(
            block_plan,
            &symbols,
            usize::from(self.config.symbol_size),
        ) {
            Ok(symbols) => symbols,
            Err(
                DecodingError::MatrixInversionFailed { .. }
                | DecodingError::InsufficientSymbols { .. },
            ) => {
                return None;
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

fn decode_block(plan: &BlockPlan, symbols: &[Symbol]) -> Result<Vec<Symbol>, DecodingError> {
    let k = plan.k;
    if symbols.len() < k {
        return Err(DecodingError::InsufficientSymbols {
            received: symbols.len(),
            needed: k,
        });
    }

    let mut rows: Vec<Row> = Vec::with_capacity(symbols.len());
    for symbol in symbols {
        let coeffs = build_coeffs(plan, symbol)?;
        rows.push(Row {
            coeffs,
            data: symbol.data().to_vec(),
        });
    }

    let solved = gaussian_elimination(rows, k)?;
    let object_id = symbols.first().map_or(ObjectId::NIL, Symbol::object_id);

    let mut decoded = Vec::with_capacity(k);
    for (esi, data) in solved.into_iter().enumerate() {
        decoded.push(Symbol::new(
            SymbolId::new(object_id, plan.sbn, esi as u32),
            data,
            SymbolKind::Source,
        ));
    }

    Ok(decoded)
}

fn build_coeffs(plan: &BlockPlan, symbol: &Symbol) -> Result<Vec<u8>, DecodingError> {
    let k = plan.k;
    let mut coeffs = vec![0u8; k];
    match symbol.kind() {
        SymbolKind::Source => {
            let esi = symbol.esi() as usize;
            if esi >= k {
                return Err(DecodingError::InconsistentMetadata {
                    sbn: plan.sbn,
                    details: format!("source esi {esi} >= k {k}"),
                });
            }
            coeffs[esi] = 1;
        }
        SymbolKind::Repair => {
            let seed = seed_for(symbol.object_id(), plan.sbn, symbol.esi());
            let mut rng = DetRng::new(seed);
            let degree = 1 + rng.next_usize(k);
            for _ in 0..degree {
                let idx = rng.next_usize(k);
                coeffs[idx] ^= 1;
            }
        }
    }
    Ok(coeffs)
}

fn seed_for(object_id: ObjectId, sbn: u8, esi: u32) -> u64 {
    let obj = object_id.as_u128();
    let hi = (obj >> 64) as u64;
    let lo = obj as u64;
    let mut seed = hi ^ lo.rotate_left(13);
    seed ^= u64::from(sbn) << 56;
    seed ^= u64::from(esi);
    if seed == 0 {
        1
    } else {
        seed
    }
}

#[derive(Debug, Clone)]
struct Row {
    coeffs: Vec<u8>,
    data: Vec<u8>,
}

impl Row {
    fn xor_with(&mut self, other: &Self) {
        for (a, b) in self.coeffs.iter_mut().zip(&other.coeffs) {
            *a ^= *b;
        }
        for (a, b) in self.data.iter_mut().zip(&other.data) {
            *a ^= *b;
        }
    }

    fn pivot_col(&self) -> Option<usize> {
        self.coeffs.iter().position(|&c| c == 1)
    }

    #[allow(clippy::naive_bytecount)]
    fn ones_count(&self) -> usize {
        self.coeffs.iter().filter(|&&c| c == 1).count()
    }
}

fn gaussian_elimination(rows: Vec<Row>, k: usize) -> Result<Vec<Vec<u8>>, DecodingError> {
    let mut rows = rows;
    let mut pivot_row = 0usize;

    for col in 0..k {
        let Some(pivot) = (pivot_row..rows.len()).find(|r| rows[*r].coeffs[col] == 1) else {
            continue;
        };
        if pivot != pivot_row {
            rows.swap(pivot_row, pivot);
        }

        for r in 0..rows.len() {
            if r != pivot_row && rows[r].coeffs[col] == 1 {
                let pivot_clone = rows[pivot_row].clone();
                rows[r].xor_with(&pivot_clone);
            }
        }

        pivot_row += 1;
        if pivot_row == rows.len() {
            break;
        }
    }

    let mut solution: Vec<Option<Vec<u8>>> = vec![None; k];
    for row in rows {
        if row.ones_count() == 1 {
            if let Some(col) = row.pivot_col() {
                solution[col] = Some(row.data);
            }
        }
    }

    if solution.iter().any(Option::is_none) {
        return Err(DecodingError::MatrixInversionFailed {
            reason: "insufficient rank".to_string(),
        });
    }

    Ok(solution
        .into_iter()
        .map(Option::unwrap_or_default)
        .collect())
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
}
