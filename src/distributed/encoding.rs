//! RaptorQ encoding for region state.
//!
//! Transforms region snapshots into erasure-coded symbols for
//! distribution to replicas using the deterministic RFC-grade pipeline.

use crate::config::EncodingConfig as PipelineEncodingConfig;
use crate::encoding::EncodingPipeline;
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
    /// Minimum repair symbols to generate (for redundancy).
    pub min_repair_symbols: u16,
    /// Maximum source blocks (for large objects).
    pub max_source_blocks: u16,
    /// Repair symbol overhead factor (e.g., 1.2 = 20% overhead).
    pub repair_overhead: f32,
}

impl Default for EncodingConfig {
    fn default() -> Self {
        Self {
            symbol_size: 1280,
            min_repair_symbols: 4,
            max_source_blocks: 1,
            repair_overhead: 1.2,
        }
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
        let data = snapshot.to_bytes();
        if data.is_empty() {
            return Err(EncodingError::EmptyData);
        }

        let layout = derive_block_layout(
            data.len(),
            self.config.symbol_size,
            self.config.max_source_blocks,
        )?;
        let params = self.calculate_params(data.len(), object_id, layout)?;
        let mut symbols = Vec::new();
        let mut total_source = 0usize;
        let mut total_repair = 0usize;
        let repair_distribution = distribute_repairs(
            usize::from(self.config.min_repair_symbols),
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
                match symbol.kind() {
                    SymbolKind::Source => total_source += 1,
                    SymbolKind::Repair => total_repair += 1,
                }
                symbols.push(symbol);
            }
        }

        let source_count =
            u16::try_from(total_source).map_err(|_| EncodingError::SymbolCountOverflow {
                field: "source_count",
                value: total_source,
                max: usize::from(u16::MAX),
            })?;
        let repair_count =
            u16::try_from(total_repair).map_err(|_| EncodingError::SymbolCountOverflow {
                field: "repair_count",
                value: total_repair,
                max: usize::from(u16::MAX),
            })?;

        Ok(EncodedState {
            params,
            symbols,
            source_count,
            repair_count,
            original_size: data.len(),
            encoded_at,
        })
    }

    /// Generates additional repair symbols for an existing encoding.
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
        let data = rebuild_source_bytes(state);
        let layout = derive_block_layout(
            data.len(),
            state.params.symbol_size,
            state.params.source_blocks,
        )?;
        let source_blocks = usize::from(layout.source_blocks);
        let additional_repairs = distribute_repairs(count as usize, source_blocks);
        let mut existing_repairs = vec![0usize; source_blocks];
        for symbol in state.repair_symbols() {
            let block = usize::from(symbol.id().sbn());
            if block >= source_blocks {
                return Err(EncodingError::Pipeline(format!(
                    "repair symbol block {block} exceeds declared source_blocks {source_blocks}"
                )));
            }
            existing_repairs[block] += 1;
        }

        let mut repairs = Vec::with_capacity(count as usize);
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
            let requested_repairs = existing_repairs[block] + extra;
            let first_new_repair_esi = u32::try_from(block_source_count + existing_repairs[block])
                .map_err(|_| EncodingError::SymbolCountOverflow {
                    field: "first_new_repair_esi",
                    value: block_source_count + existing_repairs[block],
                    max: u32::MAX as usize,
                })?;

            for symbol in self.encode_block_symbols(
                state.params.object_id,
                block,
                block_bytes,
                state.params.symbol_size,
                requested_repairs,
            )? {
                if symbol.kind().is_repair() && symbol.id().esi() >= first_new_repair_esi {
                    repairs.push(symbol);
                }
            }
        }

        if repairs.len() != count as usize {
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

fn derive_block_layout(
    data_size: usize,
    symbol_size: u16,
    max_source_blocks: u16,
) -> Result<BlockLayout, EncodingError> {
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

    let symbol_size = usize::from(symbol_size);
    let total_symbols = data_size.div_ceil(symbol_size);
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

    Ok(BlockLayout {
        max_block_size,
        source_blocks,
        symbols_per_block,
    })
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::similar_names)]
mod tests {
    use super::*;
    use crate::distributed::snapshot::{BudgetSnapshot, TaskSnapshot, TaskState};
    use crate::types::RegionId;

    fn create_test_snapshot() -> RegionSnapshot {
        use crate::record::region::RegionState;

        RegionSnapshot {
            region_id: RegionId::new_for_test(1, 0),
            state: RegionState::Open,
            timestamp: Time::from_secs(100),
            sequence: 1,
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
        }
    }

    fn create_large_snapshot(min_serialized_size: usize) -> RegionSnapshot {
        let mut snapshot = create_test_snapshot();
        let initial_len = snapshot.to_bytes().len();
        if initial_len < min_serialized_size {
            snapshot
                .metadata
                .resize(min_serialized_size - initial_len, 0xAB);
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
    fn encode_allows_full_256_block_boundary_via_config() {
        let config = EncodingConfig {
            symbol_size: 1,
            min_repair_symbols: 0,
            max_source_blocks: 256,
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
        };

        let redundancy = encoded.redundancy_factor();
        assert!((redundancy - 2.0).abs() < f32::EPSILON);
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
}
