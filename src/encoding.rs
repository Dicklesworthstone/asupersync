//! RaptorQ encoding pipeline (Phase 0).
//!
//! This module provides a deterministic, streaming encoder that splits input
//! bytes into source symbols and produces a configurable number of repair
//! symbols per block. Repair symbols are generated via the systematic
//! RaptorQ encoder (precode + LT) for deterministic RFC-6330-style behavior.

use crate::config::EncodingConfig;
use crate::error::{Error, ErrorKind};
use crate::raptorq::systematic::{SystematicEncoder, SystematicParamError, SystematicParams};
use crate::types::resource::{PoolExhausted, SymbolPool};
use crate::types::{ObjectId, Symbol, SymbolId, SymbolKind};
use std::cmp::min;

/// The symbol ID format caps objects at 256 source blocks.
pub(crate) const MAX_SOURCE_BLOCKS: usize = u8::MAX as usize + 1;

/// Returns the maximum object size supported by the byte-based block contract.
#[must_use]
#[inline]
pub(crate) fn max_object_size(max_block_size: usize) -> usize {
    max_block_size.saturating_mul(MAX_SOURCE_BLOCKS)
}

/// Errors produced by the encoding pipeline.
#[derive(Debug, thiserror::Error)]
pub enum EncodingError {
    /// Input data exceeds the configured maximum.
    #[error("data too large: {size} bytes exceeds limit {limit}")]
    DataTooLarge {
        /// Input size in bytes.
        size: usize,
        /// Maximum allowed size in bytes.
        limit: usize,
    },
    /// The symbol pool could not supply a buffer.
    #[error("symbol pool exhausted")]
    PoolExhausted,
    /// Configuration is invalid or inconsistent.
    #[error("invalid configuration: {reason}")]
    InvalidConfig {
        /// Reason for invalid configuration.
        reason: String,
    },
    /// The encoding computation failed.
    #[error("encoding failed: {details}")]
    ComputationFailed {
        /// Details of the failure.
        details: String,
    },
}

impl From<PoolExhausted> for EncodingError {
    #[inline]
    fn from(_: PoolExhausted) -> Self {
        Self::PoolExhausted
    }
}

impl From<EncodingError> for Error {
    fn from(err: EncodingError) -> Self {
        match &err {
            EncodingError::DataTooLarge { .. } | EncodingError::InvalidConfig { .. } => {
                Self::new(ErrorKind::InvalidEncodingParams)
            }
            EncodingError::PoolExhausted => {
                Self::new(ErrorKind::EncodingFailed).with_message("symbol pool exhausted")
            }
            EncodingError::ComputationFailed { .. } => Self::new(ErrorKind::EncodingFailed),
        }
        .with_message(err.to_string())
    }
}

/// Encoder output with metadata.
#[derive(Debug, Clone)]
pub struct EncodedSymbol {
    symbol: Symbol,
}

impl EncodedSymbol {
    /// Creates a new encoded symbol wrapper.
    #[must_use]
    #[inline]
    pub const fn new(symbol: Symbol) -> Self {
        Self { symbol }
    }

    /// Returns the underlying symbol.
    #[must_use]
    #[inline]
    pub const fn symbol(&self) -> &Symbol {
        &self.symbol
    }

    /// Consumes the wrapper and returns the symbol.
    #[must_use]
    #[inline]
    pub fn into_symbol(self) -> Symbol {
        self.symbol
    }

    /// Returns the symbol ID.
    #[must_use]
    #[inline]
    pub const fn id(&self) -> SymbolId {
        self.symbol.id()
    }

    /// Returns the symbol kind.
    #[must_use]
    #[inline]
    pub const fn kind(&self) -> SymbolKind {
        self.symbol.kind()
    }
}

/// Statistics for the most recent encoding run.
#[derive(Debug, Clone, Copy, Default)]
pub struct EncodingStats {
    /// Input bytes consumed.
    pub bytes_in: usize,
    /// Number of blocks encoded.
    pub blocks: usize,
    /// Source symbols emitted.
    pub source_symbols: usize,
    /// Repair symbols emitted.
    pub repair_symbols: usize,
}

impl EncodingStats {
    fn reset_for(&mut self, bytes_in: usize, blocks: usize) {
        *self = Self {
            bytes_in,
            blocks,
            source_symbols: 0,
            repair_symbols: 0,
        };
    }
}

/// Main encoding pipeline.
#[derive(Debug)]
pub struct EncodingPipeline {
    config: EncodingConfig,
    pool: SymbolPool,
    stats: EncodingStats,
}

impl EncodingPipeline {
    /// Creates a new encoding pipeline.
    #[must_use]
    #[inline]
    pub fn new(config: EncodingConfig, pool: SymbolPool) -> Self {
        Self {
            config,
            pool,
            stats: EncodingStats::default(),
        }
    }

    /// Returns encoding statistics for the most recent run.
    #[must_use]
    #[inline]
    pub const fn stats(&self) -> EncodingStats {
        self.stats
    }

    /// Resets internal statistics.
    #[inline]
    pub fn reset(&mut self) {
        self.stats = EncodingStats::default();
    }

    /// Encodes data using the configured repair overhead.
    pub fn encode<'a>(&'a mut self, object_id: ObjectId, data: &'a [u8]) -> EncodingIterator<'a> {
        self.encode_internal(object_id, data, None)
    }

    /// Encodes data with an explicit repair count per block.
    pub fn encode_with_repair<'a>(
        &'a mut self,
        object_id: ObjectId,
        data: &'a [u8],
        repair_count: usize,
    ) -> EncodingIterator<'a> {
        self.encode_internal(object_id, data, Some(repair_count))
    }

    /// Encodes only repair symbols for each block, starting at `first_repair`.
    ///
    /// `first_repair` is zero-based relative to the block's first repair symbol,
    /// so `first_repair == 0` emits public ESI `K`, `first_repair == 1` emits
    /// public ESI `K + 1`, and so on. This avoids emitting or copying
    /// systematic source symbols when a transport only needs fresh RaptorQ
    /// repair.
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub(crate) fn encode_repair_range<'a>(
        &'a mut self,
        object_id: ObjectId,
        data: &'a [u8],
        first_repair: usize,
        repair_count: usize,
    ) -> RepairEncodingIterator<'a> {
        let (blocks, symbol_size, plan_error) = match self.plan_blocks(data) {
            Ok((blocks, symbol_size)) => (blocks, symbol_size, None),
            Err(err) => (Vec::new(), 0, Some(err)),
        };

        self.stats.reset_for(data.len(), blocks.len());

        RepairEncodingIterator {
            pipeline: self,
            object_id,
            data,
            blocks,
            block_index: 0,
            repair_index: 0,
            first_repair,
            repair_count,
            symbol_size,
            plan_error,
            systematic_encoder: None,
            systematic_block_index: None,
        }
    }

    /// Encodes one source block with its already-assigned source block number.
    ///
    /// This is used by bounded-memory transports that read one block from disk
    /// at a time but must preserve the same object/SBN layout as
    /// [`Self::encode_with_repair`] would have produced for the whole object.
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub(crate) fn encode_single_block_with_repair<'a>(
        &'a mut self,
        object_id: ObjectId,
        sbn: u8,
        data: &'a [u8],
        repair_count: usize,
    ) -> EncodingIterator<'a> {
        self.encode_single_block_internal(object_id, sbn, data, Some(repair_count))
    }

    /// Encodes only repair symbols for one source block.
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub(crate) fn encode_single_block_repair_range<'a>(
        &'a mut self,
        object_id: ObjectId,
        sbn: u8,
        data: &'a [u8],
        first_repair: usize,
        repair_count: usize,
    ) -> RepairEncodingIterator<'a> {
        let (blocks, symbol_size, plan_error) = match self.plan_single_block(sbn, data) {
            Ok((blocks, symbol_size)) => (blocks, symbol_size, None),
            Err(err) => (Vec::new(), 0, Some(err)),
        };

        self.stats.reset_for(data.len(), blocks.len());

        RepairEncodingIterator {
            pipeline: self,
            object_id,
            data,
            blocks,
            block_index: 0,
            repair_index: 0,
            first_repair,
            repair_count,
            symbol_size,
            plan_error,
            systematic_encoder: None,
            systematic_block_index: None,
        }
    }

    fn encode_internal<'a>(
        &'a mut self,
        object_id: ObjectId,
        data: &'a [u8],
        repair_override: Option<usize>,
    ) -> EncodingIterator<'a> {
        let (blocks, symbol_size, plan_error) = match self.plan_blocks(data) {
            Ok((blocks, symbol_size)) => (blocks, symbol_size, None),
            Err(err) => (Vec::new(), 0, Some(err)),
        };

        self.stats.reset_for(data.len(), blocks.len());

        EncodingIterator {
            pipeline: self,
            object_id,
            data,
            blocks,
            block_index: 0,
            esi: 0,
            symbol_size,
            repair_override,
            plan_error,
            systematic_encoder: None,
            systematic_block_index: None,
        }
    }

    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    fn encode_single_block_internal<'a>(
        &'a mut self,
        object_id: ObjectId,
        sbn: u8,
        data: &'a [u8],
        repair_override: Option<usize>,
    ) -> EncodingIterator<'a> {
        let (blocks, symbol_size, plan_error) = match self.plan_single_block(sbn, data) {
            Ok((blocks, symbol_size)) => (blocks, symbol_size, None),
            Err(err) => (Vec::new(), 0, Some(err)),
        };

        self.stats.reset_for(data.len(), blocks.len());

        EncodingIterator {
            pipeline: self,
            object_id,
            data,
            blocks,
            block_index: 0,
            esi: 0,
            symbol_size,
            repair_override,
            plan_error,
            systematic_encoder: None,
            systematic_block_index: None,
        }
    }

    fn plan_blocks(&self, data: &[u8]) -> Result<(Vec<BlockPlan>, usize), EncodingError> {
        let symbol_size = self.validate_config()?;

        if data.is_empty() {
            return Ok((Vec::new(), symbol_size));
        }

        let max_total = max_object_size(self.config.max_block_size);
        if data.len() > max_total {
            return Err(EncodingError::DataTooLarge {
                size: data.len(),
                limit: max_total,
            });
        }

        let mut blocks = Vec::new();
        let mut offset = 0;
        let mut sbn: u8 = 0;

        while offset < data.len() {
            let len = min(self.config.max_block_size, data.len() - offset);
            let k = len.div_ceil(symbol_size);
            validate_source_block_k(len, symbol_size, k)?;
            blocks.push(BlockPlan {
                sbn,
                start: offset,
                len,
                k,
            });
            offset += len;
            sbn = sbn.wrapping_add(1);
        }

        Ok((blocks, symbol_size))
    }

    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    fn plan_single_block(
        &self,
        sbn: u8,
        data: &[u8],
    ) -> Result<(Vec<BlockPlan>, usize), EncodingError> {
        let symbol_size = self.validate_config()?;

        if data.is_empty() {
            return Ok((Vec::new(), symbol_size));
        }
        if data.len() > self.config.max_block_size {
            return Err(EncodingError::DataTooLarge {
                size: data.len(),
                limit: self.config.max_block_size,
            });
        }

        let k = data.len().div_ceil(symbol_size);
        validate_source_block_k(data.len(), symbol_size, k)?;
        Ok((
            vec![BlockPlan {
                sbn,
                start: 0,
                len: data.len(),
                k,
            }],
            symbol_size,
        ))
    }

    fn validate_config(&self) -> Result<usize, EncodingError> {
        let symbol_size = usize::from(self.config.symbol_size);
        if symbol_size == 0 {
            return Err(EncodingError::InvalidConfig {
                reason: "symbol_size must be non-zero".to_string(),
            });
        }

        if self.config.max_block_size == 0 {
            return Err(EncodingError::InvalidConfig {
                reason: "max_block_size must be non-zero".to_string(),
            });
        }

        if !self.config.repair_overhead.is_finite() || self.config.repair_overhead < 1.0 {
            return Err(EncodingError::InvalidConfig {
                reason: "repair_overhead must be finite and >= 1.0".to_string(),
            });
        }

        if self.pool_enabled() && self.pool.config().symbol_size != self.config.symbol_size {
            return Err(EncodingError::InvalidConfig {
                reason: format!(
                    "pool symbol_size {} does not match encoding symbol_size {}",
                    self.pool.config().symbol_size,
                    self.config.symbol_size
                ),
            });
        }

        Ok(symbol_size)
    }

    fn pool_enabled(&self) -> bool {
        let config = self.pool.config();
        config.max_size > 0 || config.initial_size > 0 || config.allow_growth
    }

    fn allocate_buffer(&mut self, symbol_size: usize) -> Result<Vec<u8>, EncodingError> {
        if self.pool_enabled() {
            let buffer = self.pool.allocate()?;
            if buffer.len() != symbol_size {
                return Err(EncodingError::InvalidConfig {
                    reason: format!(
                        "pool buffer size {} does not match symbol_size {}",
                        buffer.len(),
                        symbol_size
                    ),
                });
            }
            Ok(Vec::from(buffer.into_boxed_slice()))
        } else {
            Ok(vec![0_u8; symbol_size])
        }
    }
}

fn validate_source_block_k(
    block_len: usize,
    symbol_size: usize,
    k: usize,
) -> Result<(), EncodingError> {
    SystematicParams::try_for_source_block(k, symbol_size)
        .map(|_| ())
        .map_err(|err| match err {
        SystematicParamError::UnsupportedSourceBlockSize {
            requested,
            max_supported,
        } => EncodingError::InvalidConfig {
            reason: format!(
                "block of {block_len} bytes with symbol_size {symbol_size} requires unsupported source block K={requested}; supported range is 1..={max_supported}"
            ),
        },
        SystematicParamError::KPrimeExceedsU32 {
            k_prime,
            max_u32,
        } => EncodingError::InvalidConfig {
            reason: format!(
                "block of {block_len} bytes with symbol_size {symbol_size} requires K'={k_prime} which exceeds u32::MAX ({max_u32}); ESI calculations would overflow"
            ),
        },
        SystematicParamError::RfcTableInvariantViolation {
            invariant,
            details,
        } => EncodingError::InvalidConfig {
            reason: format!(
                "block of {block_len} bytes with symbol_size {symbol_size} triggers RFC 6330 table invariant violation: {invariant} - {details}"
            ),
        },
    })
}

/// Iterator over encoded symbols.
pub struct EncodingIterator<'a> {
    pipeline: &'a mut EncodingPipeline,
    object_id: ObjectId,
    data: &'a [u8],
    blocks: Vec<BlockPlan>,
    block_index: usize,
    esi: u32,
    symbol_size: usize,
    repair_override: Option<usize>,
    plan_error: Option<EncodingError>,
    systematic_encoder: Option<SystematicEncoder>,
    systematic_block_index: Option<usize>,
}

impl Iterator for EncodingIterator<'_> {
    type Item = Result<EncodedSymbol, EncodingError>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(err) = self.plan_error.take() {
            return Some(Err(err));
        }

        while self.block_index < self.blocks.len() {
            let block = self.blocks[self.block_index].clone();
            let k = u32::try_from(block.k).unwrap_or(u32::MAX);
            if k == 0 {
                self.block_index += 1;
                self.esi = 0;
                self.systematic_encoder = None;
                self.systematic_block_index = None;
                continue;
            }

            let repair = u32::try_from(self.repair_override.unwrap_or_else(|| {
                compute_repair_count(block.k, self.pipeline.config.repair_overhead)
            }))
            .unwrap_or(u32::MAX);
            let total = k.saturating_add(repair);

            if self.esi >= total {
                self.block_index += 1;
                self.esi = 0;
                self.systematic_encoder = None;
                self.systematic_block_index = None;
                continue;
            }

            let esi = self.esi;
            self.esi = self.esi.saturating_add(1);

            let result = if esi < k {
                self.emit_source(&block, esi)
            } else {
                self.emit_repair(&block, esi)
            };

            return Some(result.map(EncodedSymbol::new));
        }

        None
    }
}

impl EncodingIterator<'_> {
    fn emit_source(&mut self, block: &BlockPlan, esi: u32) -> Result<Symbol, EncodingError> {
        let mut buffer = self.pipeline.allocate_buffer(self.symbol_size)?;
        let start = block.start + (esi as usize * self.symbol_size);
        let end = min(start + self.symbol_size, block.end());
        let copy_len = end.saturating_sub(start);

        if copy_len < buffer.len() {
            buffer.fill(0);
        }

        if copy_len > 0 {
            let slice = &self.data[start..end];
            buffer[..slice.len()].copy_from_slice(slice);
        }

        self.pipeline.stats.source_symbols += 1;
        Ok(Symbol::new(
            SymbolId::new(self.object_id, block.sbn, esi),
            buffer,
            SymbolKind::Source,
        ))
    }

    fn emit_repair(&mut self, block: &BlockPlan, esi: u32) -> Result<Symbol, EncodingError> {
        let mut buffer = self.pipeline.allocate_buffer(self.symbol_size)?;
        buffer.fill(0);

        let encoder = self.systematic_encoder_for(block)?;
        let repair = encoder.repair_symbol(esi);
        if repair.len() != self.symbol_size {
            return Err(EncodingError::ComputationFailed {
                details: format!(
                    "systematic repair symbol size mismatch: expected {}, got {}",
                    self.symbol_size,
                    repair.len()
                ),
            });
        }
        buffer.copy_from_slice(&repair);

        self.pipeline.stats.repair_symbols += 1;
        Ok(Symbol::new(
            SymbolId::new(self.object_id, block.sbn, esi),
            buffer,
            SymbolKind::Repair,
        ))
    }

    fn systematic_encoder_for(
        &mut self,
        block: &BlockPlan,
    ) -> Result<&SystematicEncoder, EncodingError> {
        let needs_rebuild = self.systematic_block_index != Some(self.block_index);
        if needs_rebuild {
            let source_symbols = build_source_symbols(self.data, block, self.symbol_size);
            let seed = seed_for_block(self.object_id, block.sbn);
            let encoder = SystematicEncoder::new(&source_symbols, self.symbol_size, seed)
                .ok_or_else(|| EncodingError::ComputationFailed {
                    details: "systematic encoder failed: singular constraint matrix".to_string(),
                })?;
            self.systematic_encoder = Some(encoder);
            self.systematic_block_index = Some(self.block_index);
        }

        Ok(self
            .systematic_encoder
            .as_ref()
            .expect("systematic encoder must be initialized"))
    }
}

/// Iterator over repair-only encoded symbols.
pub struct RepairEncodingIterator<'a> {
    pipeline: &'a mut EncodingPipeline,
    object_id: ObjectId,
    data: &'a [u8],
    blocks: Vec<BlockPlan>,
    block_index: usize,
    repair_index: usize,
    first_repair: usize,
    repair_count: usize,
    symbol_size: usize,
    plan_error: Option<EncodingError>,
    systematic_encoder: Option<SystematicEncoder>,
    systematic_block_index: Option<usize>,
}

impl Iterator for RepairEncodingIterator<'_> {
    type Item = Result<EncodedSymbol, EncodingError>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(err) = self.plan_error.take() {
            return Some(Err(err));
        }
        if self.repair_count == 0 {
            return None;
        }

        while self.block_index < self.blocks.len() {
            let block = self.blocks[self.block_index].clone();
            if block.k == 0 {
                self.advance_block();
                continue;
            }
            if self.repair_index >= self.repair_count {
                self.advance_block();
                continue;
            }

            let esi = match repair_esi(block.k, self.first_repair, self.repair_index) {
                Ok(esi) => esi,
                Err(err) => return Some(Err(err)),
            };
            self.repair_index += 1;
            return Some(self.emit_repair(&block, esi).map(EncodedSymbol::new));
        }

        None
    }
}

impl RepairEncodingIterator<'_> {
    fn advance_block(&mut self) {
        self.block_index += 1;
        self.repair_index = 0;
        self.systematic_encoder = None;
        self.systematic_block_index = None;
    }

    fn emit_repair(&mut self, block: &BlockPlan, esi: u32) -> Result<Symbol, EncodingError> {
        let mut buffer = self.pipeline.allocate_buffer(self.symbol_size)?;
        buffer.fill(0);

        let encoder = self.systematic_encoder_for(block)?;
        let repair = encoder.repair_symbol(esi);
        if repair.len() != self.symbol_size {
            return Err(EncodingError::ComputationFailed {
                details: format!(
                    "systematic repair symbol size mismatch: expected {}, got {}",
                    self.symbol_size,
                    repair.len()
                ),
            });
        }
        buffer.copy_from_slice(&repair);

        self.pipeline.stats.repair_symbols += 1;
        Ok(Symbol::new(
            SymbolId::new(self.object_id, block.sbn, esi),
            buffer,
            SymbolKind::Repair,
        ))
    }

    fn systematic_encoder_for(
        &mut self,
        block: &BlockPlan,
    ) -> Result<&SystematicEncoder, EncodingError> {
        let needs_rebuild = self.systematic_block_index != Some(self.block_index);
        if needs_rebuild {
            let source_symbols = build_source_symbols(self.data, block, self.symbol_size);
            let seed = seed_for_block(self.object_id, block.sbn);
            let encoder = SystematicEncoder::new(&source_symbols, self.symbol_size, seed)
                .ok_or_else(|| EncodingError::ComputationFailed {
                    details: "systematic encoder failed: singular constraint matrix".to_string(),
                })?;
            self.systematic_encoder = Some(encoder);
            self.systematic_block_index = Some(self.block_index);
        }

        Ok(self
            .systematic_encoder
            .as_ref()
            .expect("systematic encoder must be initialized"))
    }
}

fn repair_esi(
    block_k: usize,
    first_repair: usize,
    repair_index: usize,
) -> Result<u32, EncodingError> {
    let esi = block_k
        .checked_add(first_repair)
        .and_then(|esi| esi.checked_add(repair_index))
        .ok_or_else(|| EncodingError::InvalidConfig {
            reason: "repair ESI overflow".to_string(),
        })?;
    u32::try_from(esi).map_err(|_| EncodingError::InvalidConfig {
        reason: format!("repair ESI {esi} exceeds u32::MAX"),
    })
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

#[allow(clippy::cast_precision_loss, clippy::cast_sign_loss)]
fn compute_repair_count(k: usize, overhead: f64) -> usize {
    let desired = ((k as f64) * overhead).ceil() as usize;
    desired.saturating_sub(k)
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

fn build_source_symbols(data: &[u8], block: &BlockPlan, symbol_size: usize) -> Vec<Vec<u8>> {
    let mut symbols = Vec::with_capacity(block.k);
    for idx in 0..block.k {
        let mut buffer = vec![0u8; symbol_size];
        let start = block.start + idx * symbol_size;
        let end = min(start + symbol_size, block.end());
        if start < end {
            let slice = &data[start..end];
            buffer[..slice.len()].copy_from_slice(slice);
        }
        symbols.push(buffer);
    }
    symbols
}

#[cfg(test)]
#[path = "encoding_inline_tests.rs"]
mod tests;
