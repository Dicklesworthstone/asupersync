//! RaptorQ encoding for region state.
//!
//! Transforms region snapshots into erasure-coded symbols for
//! distribution to replicas using the deterministic RFC-grade pipeline.

use crate::config::EncodingConfig as PipelineEncodingConfig;
use crate::encoding::EncodingPipeline;
use crate::types::Time;
use crate::types::resource::{PoolConfig, SymbolPool};
use crate::types::symbol::{ObjectId, ObjectParams, Symbol};
use crate::util::DetRng;

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
    pub max_source_blocks: u8,
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

        let params = self.calculate_params(data.len(), object_id);
        let pipeline_config = PipelineEncodingConfig {
            repair_overhead: f64::from(self.config.repair_overhead),
            max_block_size: data.len(),
            symbol_size: self.config.symbol_size,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        };
        let pool = SymbolPool::new(PoolConfig::default());
        let mut pipeline = EncodingPipeline::new(pipeline_config, pool);
        let repair_override = self.config.min_repair_symbols as usize;
        let mut symbols = Vec::new();

        for encoded in pipeline.encode_with_repair(object_id, &data, repair_override) {
            let symbol = encoded
                .map_err(|err| EncodingError::Pipeline(err.to_string()))?
                .into_symbol();
            symbols.push(symbol);
        }

        let stats = pipeline.stats();
        let source_count = stats.source_symbols as u16;
        let repair_count = stats.repair_symbols as u16;

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
        let total_repairs = state.repair_count as usize + count as usize;
        let pipeline_config = PipelineEncodingConfig {
            repair_overhead: f64::from(self.config.repair_overhead),
            max_block_size: data.len(),
            symbol_size: state.params.symbol_size,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        };
        let pool = SymbolPool::new(PoolConfig::default());
        let mut pipeline = EncodingPipeline::new(pipeline_config, pool);
        let mut repairs = Vec::with_capacity(count as usize);
        let skip = state.source_count as usize + state.repair_count as usize;

        for (idx, encoded) in pipeline
            .encode_with_repair(state.params.object_id, &data, total_repairs)
            .enumerate()
        {
            let symbol = encoded
                .map_err(|err| EncodingError::Pipeline(err.to_string()))?
                .into_symbol();
            if idx >= skip {
                repairs.push(symbol);
            }
        }

        Ok(repairs)
    }

    fn calculate_params(&self, data_size: usize, object_id: ObjectId) -> ObjectParams {
        let symbol_size = self.config.symbol_size as usize;
        let symbols_needed = data_size.div_ceil(symbol_size);

        ObjectParams::new(
            object_id,
            data_size as u64,
            self.config.symbol_size,
            1, // source_blocks
            symbols_needed as u16,
        )
    }
}

/// Rebuild source data bytes from an encoded state by concatenating source symbols.
fn rebuild_source_bytes(encoded: &EncodedState) -> Vec<u8> {
    let mut sources: Vec<&Symbol> = encoded.source_symbols().collect();
    sources.sort_by_key(|symbol| symbol.id().esi());
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
        f32::from(self.source_count + self.repair_count) / f32::from(self.source_count)
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
    /// No source symbols available.
    NoSourceSymbols,
    /// Error from the underlying encoding pipeline.
    Pipeline(String),
}

impl std::fmt::Display for EncodingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyData => write!(f, "snapshot serialized to empty data"),
            Self::NoSourceSymbols => write!(f, "no source symbols available"),
            Self::Pipeline(msg) => write!(f, "pipeline encoding error: {msg}"),
        }
    }
}

impl std::error::Error for EncodingError {}

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

    fn rebuild_source_bytes(encoded: &EncodedState) -> Vec<u8> {
        let mut sources: Vec<&Symbol> = encoded.source_symbols().collect();
        sources.sort_by_key(|symbol| symbol.id().esi());
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
}
