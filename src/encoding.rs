//! RaptorQ encoding pipeline (Phase 0).
//!
//! This module provides a deterministic, streaming encoder that splits input
//! bytes into source symbols and produces a configurable number of repair
//! symbols per block. Repair symbols are generated via the systematic
//! RaptorQ encoder (precode + LT) for deterministic RFC-6330-style behavior.

use crate::config::EncodingConfig;
use crate::error::{Error, ErrorKind};
use crate::raptorq::systematic::SystematicEncoder;
use crate::types::resource::{PoolExhausted, SymbolPool};
use crate::types::{ObjectId, Symbol, SymbolId, SymbolKind};
use std::cmp::min;

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
    pub const fn new(symbol: Symbol) -> Self {
        Self { symbol }
    }

    /// Returns the underlying symbol.
    #[must_use]
    pub const fn symbol(&self) -> &Symbol {
        &self.symbol
    }

    /// Consumes the wrapper and returns the symbol.
    #[must_use]
    pub fn into_symbol(self) -> Symbol {
        self.symbol
    }

    /// Returns the symbol ID.
    #[must_use]
    pub const fn id(&self) -> SymbolId {
        self.symbol.id()
    }

    /// Returns the symbol kind.
    #[must_use]
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
    pub fn new(config: EncodingConfig, pool: SymbolPool) -> Self {
        Self {
            config,
            pool,
            stats: EncodingStats::default(),
        }
    }

    /// Returns encoding statistics for the most recent run.
    #[must_use]
    pub const fn stats(&self) -> EncodingStats {
        self.stats
    }

    /// Resets internal statistics.
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

    fn plan_blocks(&self, data: &[u8]) -> Result<(Vec<BlockPlan>, usize), EncodingError> {
        if data.is_empty() {
            return Ok((Vec::new(), usize::from(self.config.symbol_size)));
        }

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

        if self.config.repair_overhead < 1.0 {
            return Err(EncodingError::InvalidConfig {
                reason: "repair_overhead must be >= 1.0".to_string(),
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

        let max_blocks = u8::MAX as usize + 1;
        let max_total = self.config.max_block_size.saturating_mul(max_blocks);
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
            let k = block.k as u32;
            if k == 0 {
                self.block_index += 1;
                self.esi = 0;
                self.systematic_encoder = None;
                self.systematic_block_index = None;
                continue;
            }

            let repair = self.repair_override.unwrap_or_else(|| {
                compute_repair_count(block.k, self.pipeline.config.repair_overhead)
            }) as u32;
            let total = k + repair;

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
    let desired = (f64::from(k as u32) * overhead).ceil() as usize;
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
mod tests {
    use super::*;
    use crate::types::ObjectId;
    use crate::types::resource::PoolConfig;

    fn test_config(
        symbol_size: u16,
        max_block_size: usize,
        repair_overhead: f64,
    ) -> EncodingConfig {
        EncodingConfig {
            symbol_size,
            max_block_size,
            repair_overhead,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        }
    }

    fn pool_for(symbol_size: u16, max_size: usize) -> SymbolPool {
        SymbolPool::new(PoolConfig {
            symbol_size,
            initial_size: max_size,
            max_size,
            allow_growth: false,
            growth_increment: 0,
        })
    }

    #[test]
    fn test_encode_small_data() {
        let mut pipeline = EncodingPipeline::new(
            test_config(4, 16, 1.0),
            SymbolPool::new(PoolConfig::default()),
        );
        let data = b"hello";
        let symbols: Vec<_> = pipeline
            .encode(ObjectId::new_for_test(1), data)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(symbols.len(), 2);
        assert_eq!(symbols[0].symbol().data().len(), 4);
        assert_eq!(symbols[1].symbol().data().len(), 4);
    }

    #[test]
    fn test_encode_exact_block_size() {
        let mut pipeline = EncodingPipeline::new(
            test_config(4, 8, 1.0),
            SymbolPool::new(PoolConfig::default()),
        );
        let data = b"abcdefgh";
        let symbols: Vec<_> = pipeline
            .encode(ObjectId::new_for_test(2), data)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(symbols.len(), 2);
        assert!(symbols.iter().all(|s| s.kind() == SymbolKind::Source));
    }

    #[test]
    fn test_encode_multiple_blocks() {
        let mut pipeline = EncodingPipeline::new(
            test_config(4, 8, 1.0),
            SymbolPool::new(PoolConfig::default()),
        );
        let data = b"abcdefghijklmnop";
        let symbols: Vec<_> = pipeline
            .encode(ObjectId::new_for_test(3), data)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let sbns: Vec<u8> = symbols.iter().map(|s| s.id().sbn()).collect();
        assert!(sbns.contains(&0));
        assert!(sbns.contains(&1));
    }

    #[test]
    fn test_encode_empty_data() {
        let mut pipeline = EncodingPipeline::new(
            test_config(8, 32, 1.0),
            SymbolPool::new(PoolConfig::default()),
        );
        let symbols: Vec<_> = pipeline
            .encode(ObjectId::new_for_test(4), &[])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert!(symbols.is_empty());
    }

    #[test]
    fn test_repair_overhead_respected() {
        let mut pipeline = EncodingPipeline::new(
            test_config(4, 16, 1.5),
            SymbolPool::new(PoolConfig::default()),
        );
        let data = b"abcdefgh";
        let symbols: Vec<_> = pipeline
            .encode(ObjectId::new_for_test(5), data)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let repair_count = symbols
            .iter()
            .filter(|s| s.kind() == SymbolKind::Repair)
            .count();
        assert_eq!(repair_count, 1);
    }

    #[test]
    fn test_symbol_ids_unique() {
        let mut pipeline = EncodingPipeline::new(
            test_config(4, 16, 1.2),
            SymbolPool::new(PoolConfig::default()),
        );
        let data = b"abcdefgh";
        let symbols: Vec<_> = pipeline
            .encode(ObjectId::new_for_test(6), data)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let mut ids = symbols.iter().map(EncodedSymbol::id).collect::<Vec<_>>();
        ids.sort_by_key(|id| (id.sbn(), id.esi()));
        ids.dedup();
        assert_eq!(ids.len(), symbols.len());
    }

    #[test]
    fn test_data_too_large_error() {
        let mut pipeline = EncodingPipeline::new(
            test_config(1, 1, 1.0),
            SymbolPool::new(PoolConfig::default()),
        );
        let data = vec![0_u8; 257];
        let err = pipeline
            .encode(ObjectId::new_for_test(7), &data)
            .next()
            .unwrap()
            .unwrap_err();

        assert!(matches!(err, EncodingError::DataTooLarge { .. }));
    }

    #[test]
    fn test_pool_exhaustion_handling() {
        let mut pipeline = EncodingPipeline::new(test_config(4, 16, 1.0), pool_for(4, 1));
        let data = b"abcdefgh";
        let mut iter = pipeline.encode(ObjectId::new_for_test(8), data);

        let _ = iter.next().unwrap().unwrap();
        let err = iter.next().unwrap().unwrap_err();
        assert!(matches!(err, EncodingError::PoolExhausted));
    }

    #[test]
    fn test_source_symbol_zero_pads_with_pool() {
        let symbol_size = 4u16;
        let mut pool = pool_for(symbol_size, 1);
        let mut buffer = pool.allocate().unwrap();
        buffer.as_mut_slice().fill(0xAA);
        pool.deallocate(buffer);

        let mut pipeline = EncodingPipeline::new(test_config(symbol_size, 16, 1.0), pool);
        let data = [0x11u8];
        let symbols: Vec<_> = pipeline
            .encode(ObjectId::new_for_test(11), &data)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(symbols.len(), 1);
        let bytes = symbols[0].symbol().data();
        assert_eq!(bytes[0], 0x11);
        assert!(bytes[1..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn test_deterministic_output() {
        let data = b"deterministic";
        let object_id = ObjectId::new_for_test(9);
        let config = test_config(4, 16, 1.5);

        let mut pipeline_a =
            EncodingPipeline::new(config.clone(), SymbolPool::new(PoolConfig::default()));
        let mut pipeline_b = EncodingPipeline::new(config, SymbolPool::new(PoolConfig::default()));

        let symbols_a: Vec<_> = pipeline_a
            .encode(object_id, data)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let symbols_b: Vec<_> = pipeline_b
            .encode(object_id, data)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let bytes_a: Vec<Vec<u8>> = symbols_a
            .iter()
            .map(|s| s.symbol().data().to_vec())
            .collect();
        let bytes_b: Vec<Vec<u8>> = symbols_b
            .iter()
            .map(|s| s.symbol().data().to_vec())
            .collect();

        assert_eq!(bytes_a, bytes_b);
    }

    #[test]
    fn test_repair_symbols_match_systematic_encoder() {
        let symbol_size = 8usize;
        let max_block_size = 64usize;
        let repair_count = 3usize;
        let data: Vec<u8> = (0u8..37).map(|i| i.wrapping_mul(7)).collect();
        let object_id = ObjectId::new_for_test(10);

        let mut pipeline = EncodingPipeline::new(
            test_config(symbol_size as u16, max_block_size, 1.0),
            SymbolPool::new(PoolConfig::default()),
        );
        let symbols: Vec<_> = pipeline
            .encode_with_repair(object_id, &data, repair_count)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let k = data.len().div_ceil(symbol_size);
        let block = BlockPlan {
            sbn: 0,
            start: 0,
            len: data.len(),
            k,
        };
        let source_symbols = build_source_symbols(&data, &block, symbol_size);
        let seed = seed_for_block(object_id, block.sbn);
        let encoder = SystematicEncoder::new(&source_symbols, symbol_size, seed).expect("encoder");

        for sym in symbols.iter().filter(|s| s.kind() == SymbolKind::Repair) {
            let esi = sym.id().esi();
            let expected = encoder.repair_symbol(esi);
            assert_eq!(sym.symbol().data(), expected.as_slice());
        }
    }

    // ========================================================================
    // Pure data-type trait coverage (wave 25)
    // ========================================================================

    #[test]
    fn encoding_error_debug_display_data_too_large() {
        let err = EncodingError::DataTooLarge {
            size: 1024,
            limit: 512,
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("DataTooLarge"));
        let disp = format!("{err}");
        assert!(disp.contains("1024"));
        assert!(disp.contains("512"));
    }

    #[test]
    fn encoding_error_display_pool_exhausted() {
        let err = EncodingError::PoolExhausted;
        let disp = format!("{err}");
        assert!(disp.contains("pool") || disp.contains("exhausted"));
    }

    #[test]
    fn encoding_error_display_invalid_config() {
        let err = EncodingError::InvalidConfig {
            reason: "symbol_size must be non-zero".into(),
        };
        let disp = format!("{err}");
        assert!(disp.contains("symbol_size"));
    }

    #[test]
    fn encoding_error_display_computation_failed() {
        let err = EncodingError::ComputationFailed {
            details: "singular matrix".into(),
        };
        let disp = format!("{err}");
        assert!(disp.contains("singular matrix"));
    }

    #[test]
    fn encoding_error_is_std_error() {
        let err = EncodingError::PoolExhausted;
        let dyn_err: &dyn std::error::Error = &err;
        assert!(!dyn_err.to_string().is_empty());
    }

    #[test]
    fn encoding_error_from_pool_exhausted() {
        let pool_err = PoolExhausted;
        let encoding_err: EncodingError = pool_err.into();
        assert!(matches!(encoding_err, EncodingError::PoolExhausted));
    }

    #[test]
    fn encoding_error_into_error() {
        let err = EncodingError::DataTooLarge {
            size: 100,
            limit: 50,
        };
        let generic: Error = err.into();
        let msg = format!("{generic}");
        assert!(!msg.is_empty());

        let err2 = EncodingError::PoolExhausted;
        let generic2: Error = err2.into();
        assert!(!format!("{generic2}").is_empty());

        let err3 = EncodingError::InvalidConfig {
            reason: "bad".into(),
        };
        let generic3: Error = err3.into();
        assert!(!format!("{generic3}").is_empty());

        let err4 = EncodingError::ComputationFailed {
            details: "fail".into(),
        };
        let generic4: Error = err4.into();
        assert!(!format!("{generic4}").is_empty());
    }

    #[test]
    fn encoding_stats_debug_clone_copy_default() {
        let stats = EncodingStats::default();
        assert_eq!(stats.bytes_in, 0);
        assert_eq!(stats.blocks, 0);
        assert_eq!(stats.source_symbols, 0);
        assert_eq!(stats.repair_symbols, 0);
        let dbg = format!("{stats:?}");
        assert!(dbg.contains("EncodingStats"));
        let s2 = stats; // Copy
        assert_eq!(s2.bytes_in, stats.bytes_in);
    }

    #[test]
    fn encoding_stats_reset_for() {
        let mut stats = EncodingStats::default();
        stats.source_symbols = 10;
        stats.repair_symbols = 5;
        stats.reset_for(1024, 4);
        assert_eq!(stats.bytes_in, 1024);
        assert_eq!(stats.blocks, 4);
        assert_eq!(stats.source_symbols, 0);
        assert_eq!(stats.repair_symbols, 0);
    }

    #[test]
    fn encoded_symbol_debug_clone_accessors() {
        let sym = Symbol::new(
            SymbolId::new(ObjectId::new_for_test(1), 0, 0),
            vec![1, 2, 3, 4],
            SymbolKind::Source,
        );
        let encoded = EncodedSymbol::new(sym);
        let dbg = format!("{encoded:?}");
        assert!(dbg.contains("EncodedSymbol"));
        assert_eq!(encoded.kind(), SymbolKind::Source);

        let cloned = encoded.clone();
        assert_eq!(cloned.symbol().data(), encoded.symbol().data());

        let id = encoded.id();
        assert_eq!(id.sbn(), 0);
        assert_eq!(id.esi(), 0);

        let sym_back = encoded.into_symbol();
        assert_eq!(sym_back.data(), &[1, 2, 3, 4]);
    }

    #[test]
    fn block_plan_debug_clone_end() {
        let plan = BlockPlan {
            sbn: 0,
            start: 100,
            len: 50,
            k: 5,
        };
        let dbg = format!("{plan:?}");
        assert!(dbg.contains("BlockPlan"));
        let plan2 = plan.clone();
        assert_eq!(plan2.end(), 150);
        assert_eq!(plan2.sbn, 0);
        assert_eq!(plan2.k, 5);
    }

    #[test]
    fn compute_repair_count_cases() {
        // overhead 1.0 means 0 repair
        assert_eq!(compute_repair_count(10, 1.0), 0);
        // overhead 1.5 means ceil(10*1.5)=15, so 5 repair
        assert_eq!(compute_repair_count(10, 1.5), 5);
        // overhead 2.0 means ceil(10*2.0)=20, so 10 repair
        assert_eq!(compute_repair_count(10, 2.0), 10);
        // k=1 with overhead 1.5 means ceil(1.5)=2, so 1 repair
        assert_eq!(compute_repair_count(1, 1.5), 1);
    }

    #[test]
    fn seed_for_block_deterministic() {
        let id = ObjectId::new_for_test(42);
        let s1 = seed_for_block(id, 0);
        let s2 = seed_for_block(id, 0);
        assert_eq!(s1, s2);
        // Different blocks should (almost certainly) yield different seeds
        let s3 = seed_for_block(id, 1);
        assert_ne!(s1, s3);
    }

    #[test]
    fn encoding_pipeline_stats_and_reset() {
        let mut pipeline = EncodingPipeline::new(
            test_config(4, 16, 1.0),
            SymbolPool::new(PoolConfig::default()),
        );

        let stats = pipeline.stats();
        assert_eq!(stats.bytes_in, 0);

        let _: Vec<_> = pipeline
            .encode(ObjectId::new_for_test(99), b"test")
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let stats = pipeline.stats();
        assert!(stats.source_symbols > 0);

        pipeline.reset();
        let stats = pipeline.stats();
        assert_eq!(stats.bytes_in, 0);
        assert_eq!(stats.source_symbols, 0);
    }
}
