//! RaptorQ encoding pipeline.
//!
//! Implements the core RaptorQ fountain code encoding pipeline that transforms
//! arbitrary byte data into a stream of symbols suitable for network transmission
//! with erasure coding protection.

use crate::error::{Error, ErrorKind};
use crate::types::symbol::{ObjectId, Symbol, SymbolId, SymbolKind};
use crate::util::{SymbolBuffer, SymbolPool};
use std::sync::{Arc, Mutex};

/// Configuration for the encoding process.
#[derive(Debug, Clone)]
pub struct EncodingConfig {
    /// Symbol size in bytes (T parameter).
    pub symbol_size: u16,
    /// Maximum source block size in bytes.
    pub max_block_size: usize,
    /// Repair symbol overhead (e.g., 1.05 = 5% extra).
    pub repair_overhead: f64,
}

impl Default for EncodingConfig {
    fn default() -> Self {
        Self {
            symbol_size: 1280,
            max_block_size: 64 * 1280, // ~80KB
            repair_overhead: 1.05,
        }
    }
}

/// A source block before encoding.
#[derive(Debug)]
pub struct SourceBlock {
    /// Source Block Number.
    pub sbn: u8,
    /// Source symbols data (aligned to symbol_size).
    pub symbols: Vec<SymbolBuffer>,
    /// Number of source symbols (K).
    pub k: u16,
}

/// Generated symbol with metadata.
#[derive(Debug)]
pub struct EncodedSymbol {
    /// Symbol ID.
    pub id: SymbolId,
    /// Symbol data.
    pub data: Symbol,
    /// Symbol kind.
    pub kind: SymbolKind,
}

/// Errors specific to encoding.
#[derive(Debug, Clone)]
pub enum EncodingError {
    /// Data too large for parameters.
    DataTooLarge {
        /// Size of the data that exceeded the limit.
        size: usize,
    },
    /// Symbol pool exhausted.
    PoolExhausted,
    /// Invalid configuration.
    InvalidConfig {
        /// Reason for invalid configuration.
        reason: String,
    },
    /// Computation failed.
    ComputationFailed {
        /// Details of the failure.
        details: String,
    },
}

impl std::fmt::Display for EncodingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DataTooLarge { size } => write!(f, "data too large: {size} bytes"),
            Self::PoolExhausted => write!(f, "symbol pool exhausted"),
            Self::InvalidConfig { reason } => write!(f, "invalid config: {reason}"),
            Self::ComputationFailed { details } => write!(f, "computation failed: {details}"),
        }
    }
}

impl std::error::Error for EncodingError {}

impl From<EncodingError> for Error {
    fn from(e: EncodingError) -> Self {
        match e {
            EncodingError::DataTooLarge { .. } => {
                Self::new(ErrorKind::DataTooLarge).with_message(e.to_string())
            }
            EncodingError::PoolExhausted => {
                Self::new(ErrorKind::Internal).with_message(e.to_string())
            }
            EncodingError::InvalidConfig { .. } => {
                Self::new(ErrorKind::InvalidEncodingParams).with_message(e.to_string())
            }
            EncodingError::ComputationFailed { .. } => {
                Self::new(ErrorKind::EncodingFailed).with_message(e.to_string())
            }
        }
    }
}

/// State machine for encoding.
#[derive(Debug)]
enum EncodingState {
    Idle,
    Partitioning {
        blocks: Vec<SourceBlock>,
    },
    Computing {
        block_idx: usize,
        // In Phase 0, we compute on the fly or precompute minimal state
    },
    Generating {
        block_idx: usize,
        esi: u32,
    },
    Complete,
}

/// The main encoding pipeline.
#[derive(Debug)]
pub struct EncodingPipeline {
    config: EncodingConfig,
    pool: Arc<Mutex<SymbolPool>>,
    state: EncodingState,
    // Intermediate storage
    blocks: Vec<SourceBlock>,
}

impl EncodingPipeline {
    /// Creates a new encoding pipeline.
    pub fn new(config: EncodingConfig, pool: Arc<Mutex<SymbolPool>>) -> Self {
        Self {
            config,
            pool,
            state: EncodingState::Idle,
            blocks: Vec::new(),
        }
    }

    /// Resets the pipeline for reuse.
    pub fn reset(&mut self) {
        self.state = EncodingState::Idle;
        // Return buffers to pool
        for block in self.blocks.drain(..) {
            let mut pool = self.pool.lock().expect("lock poisoned");
            for buf in block.symbols {
                pool.deallocate(buf);
            }
        }
    }

    /// Encodes data into a stream of symbols.
    pub fn encode<'a>(
        &'a mut self,
        object_id: ObjectId,
        data: &[u8],
    ) -> Result<EncodingIterator<'a>, EncodingError> {
        self.reset();
        self.partition(data)?;

        Ok(EncodingIterator {
            pipeline: self,
            object_id,
            current_block_idx: 0,
            current_esi: 0,
            repair_remaining: 0, // Calculated per block
        })
    }

    /// Encodes data with explicit repair count.
    pub fn encode_with_repair<'a>(
        &'a mut self,
        object_id: ObjectId,
        data: &[u8],
        repair_count: usize,
    ) -> Result<EncodingIterator<'a>, EncodingError> {
        self.reset();
        self.partition(data)?;

        // This iterator will generate K + repair_count symbols per block
        // Actually, we usually want total symbols (source + repair)
        // Or repair overhead?
        // For simplicity, let's assume repair_count is PER BLOCK additional symbols.

        Ok(EncodingIterator {
            pipeline: self,
            object_id,
            current_block_idx: 0,
            current_esi: 0,
            repair_remaining: repair_count, // Hint override
        })
    }

    fn partition(&mut self, data: &[u8]) -> Result<(), EncodingError> {
        if data.is_empty() {
            return Ok(());
        }

        let symbol_size = self.config.symbol_size as usize;
        let max_block_size = self.config.max_block_size;

        if symbol_size == 0 {
            return Err(EncodingError::InvalidConfig {
                reason: "symbol size 0".into(),
            });
        }

        let mut offset = 0;
        let mut sbn = 0;

        while offset < data.len() {
            let remaining = data.len() - offset;
            let block_len = remaining.min(max_block_size);
            let block_data = &data[offset..offset + block_len];

            // Calculate K
            let k = block_len.div_ceil(symbol_size);
            if k > 65535 {
                return Err(EncodingError::DataTooLarge { size: data.len() });
            }

            let mut symbols = Vec::with_capacity(k);
            {
                let mut pool = self.pool.lock().expect("lock poisoned");

                for i in 0..k {
                    let start = i * symbol_size;
                    let end = (start + symbol_size).min(block_len);
                    let slice = &block_data[start..end];

                    let Ok(mut buf) = pool.allocate() else {
                        // Cleanup allocated so far
                        for b in symbols {
                            pool.deallocate(b);
                        }
                        drop(pool);
                        return Err(EncodingError::PoolExhausted);
                    };

                    // Copy data and pad with zeros
                    let dest = buf.as_mut_slice();
                    dest[..slice.len()].copy_from_slice(slice);
                    if slice.len() < symbol_size {
                        dest[slice.len()..symbol_size].fill(0);
                    }

                    symbols.push(buf);
                }
            }

            self.blocks.push(SourceBlock {
                sbn,
                symbols,
                k: k as u16,
            });

            offset += block_len;
            if sbn == u8::MAX {
                // Too many blocks
                return Err(EncodingError::DataTooLarge { size: data.len() });
            }
            sbn = sbn.saturating_add(1);
        }

        self.state = EncodingState::Generating {
            block_idx: 0,
            esi: 0,
        };
        Ok(())
    }

    fn generate_symbol(&self, block: &SourceBlock, esi: u32) -> Symbol {
        let k = u32::from(block.k);
        let object_id = ObjectId::NIL; // Placeholder, overridden by iterator
        let symbol_id = SymbolId::new(object_id, block.sbn, esi);

        if esi < k {
            // Source symbol
            let buf = &block.symbols[esi as usize];
            Symbol::new(symbol_id, buf.as_slice().to_vec(), SymbolKind::Source)
        } else {
            // Repair symbol (Phase 0: Simple XOR of all source symbols)
            // In real RaptorQ, this uses intermediate symbols and matrix.
            // Here we just XOR all source symbols as a placeholder for a parity symbol.
            // For ESI > K, we can rotate the XOR or use a seed.
            // Let's do: XOR of (source[(esi + i) % k])

            let mut data = vec![0u8; self.config.symbol_size as usize];
            for i in 0..k {
                // Simple mixing function
                if (esi + i).is_multiple_of(2) {
                    // Dummy logic
                    let src = block.symbols[i as usize].as_slice();
                    for (d, s) in data.iter_mut().zip(src.iter()) {
                        *d ^= *s;
                    }
                }
            }
            Symbol::new(symbol_id, data, SymbolKind::Repair)
        }
    }
}

/// Iterator yielding encoded symbols.
pub struct EncodingIterator<'a> {
    pipeline: &'a mut EncodingPipeline,
    object_id: ObjectId,
    current_block_idx: usize,
    current_esi: u32,
    repair_remaining: usize,
}

impl Iterator for EncodingIterator<'_> {
    type Item = Result<EncodedSymbol, EncodingError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_block_idx >= self.pipeline.blocks.len() {
            return None;
        }

        let block = &self.pipeline.blocks[self.current_block_idx];
        let k = u32::from(block.k);

        // Determine how many repair symbols to generate
        // Default overhead or override
        let repair_target = if self.repair_remaining > 0 {
            self.repair_remaining
        } else {
            #[allow(clippy::cast_precision_loss, clippy::cast_sign_loss)]
            {
                (f64::from(k) * (self.pipeline.config.repair_overhead - 1.0)).ceil() as usize
            }
        };

        let max_esi = k + repair_target as u32;

        if self.current_esi >= max_esi {
            // Done with this block
            self.current_block_idx += 1;
            self.current_esi = 0;
            return self.next();
        }

        // Generate symbol
        // We need to construct a Symbol with correct ID
        let generated_symbol = self.pipeline.generate_symbol(block, self.current_esi);
        // Patch object ID
        let id = SymbolId::new(self.object_id, block.sbn, self.current_esi);
        let kind = generated_symbol.kind();
        let data = generated_symbol.into_data();
        let symbol = Symbol::new(id, data, kind);

        self.current_esi += 1;

        Some(Ok(EncodedSymbol {
            id,
            data: symbol.clone(),
            kind: symbol.kind(),
        }))
    }
}

/// Statistics for encoding.
#[derive(Debug, Default)]
pub struct EncodingStats {
    /// Total number of symbols encoded.
    pub total: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::PoolConfig;

    fn test_pool(symbol_size: u16) -> Arc<Mutex<SymbolPool>> {
        let config = PoolConfig {
            symbol_size,
            ..Default::default()
        };
        Arc::new(Mutex::new(SymbolPool::new(config)))
    }

    #[test]
    fn test_encode_small_data() {
        let config = EncodingConfig::default();
        let pool = test_pool(config.symbol_size);
        let mut pipeline = EncodingPipeline::new(config, pool);

        let data = vec![1, 2, 3, 4];
        let object_id = ObjectId::new_for_test(1);

        let iter = pipeline.encode(object_id, &data).unwrap();
        let symbols: Vec<_> = iter.collect();

        // 1 source symbol + repair
        // Default symbol size 1280. 4 bytes fits in 1.
        // Repair overhead 1.05 -> ceil(1 * 0.05) = 1 repair.
        // So 2 symbols total.
        assert_eq!(symbols.len(), 2);
        assert!(symbols[0].as_ref().unwrap().kind.is_source());
        assert!(symbols[1].as_ref().unwrap().kind.is_repair());
    }

    #[test]
    fn test_encode_exact_block_size() {
        let config = EncodingConfig {
            symbol_size: 10,
            max_block_size: 20,
            repair_overhead: 1.0, // No repair
        };
        let pool = test_pool(config.symbol_size);
        let mut pipeline = EncodingPipeline::new(config, pool);

        let data = vec![0u8; 20]; // Exactly 2 symbols
        let iter = pipeline.encode(ObjectId::new_for_test(1), &data).unwrap();
        let symbols: Vec<_> = iter.collect();

        assert_eq!(symbols.len(), 2);
        assert!(symbols[0].as_ref().unwrap().kind.is_source());
        assert!(symbols[1].as_ref().unwrap().kind.is_source());
    }
}
