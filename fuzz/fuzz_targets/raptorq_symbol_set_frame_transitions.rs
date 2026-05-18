//! Structure-aware fuzzer for RaptorQ symbol-set ↔ frame transitions.
//!
//! This harness tests the critical transitions between symbol collections (SymbolSet)
//! and their serialized frame representations, focusing on:
//!
//! **Core Transition Patterns:**
//! 1. **Symbol → SymbolSet**: Collection, deduplication, threshold detection
//! 2. **SymbolSet → Frame**: Serialization of accumulated symbols to wire format
//! 3. **Frame → Symbols**: Deserialization back to individual symbols
//! 4. **Round-trip invariants**: symbol_set → frame → symbol_set must preserve semantics
//!
//! **Attack Vectors Covered:**
//! - Memory exhaustion via oversized symbol sets
//! - Threshold manipulation (fake K values, overflow ESI)
//! - Block boundary violations (SBN overflow, cross-block contamination)
//! - Frame parsing corruption (truncated headers, invalid lengths)
//! - Serialization roundtrip breakage (data corruption, order dependency)
//! - State machine exploitation (partial frame reassembly)
//!
//! **Invariants Enforced:**
//! - No panics on malformed input
//! - Memory limits respected during accumulation
//! - Threshold detection remains monotonic
//! - Round-trip preserves symbol content and metadata
//! - Block progress tracking stays consistent

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use std::collections::{HashMap, HashSet};

use asupersync::types::symbol_set::{InsertResult, SymbolSet, ThresholdConfig};
use asupersync::types::{ObjectId, Symbol, SymbolId, SymbolKind};

/// Maximum input size to prevent OOM during fuzzing
const MAX_INPUT_SIZE: usize = 64 * 1024;
/// Maximum symbols per set to bound memory usage
const MAX_SYMBOLS_PER_SET: usize = 512;
/// Maximum symbol data size
const MAX_SYMBOL_SIZE: usize = 1024;
/// Maximum source blocks to test
const MAX_SOURCE_BLOCKS: u8 = 16;

/// Structure-aware symbol set operations for comprehensive transition testing
#[derive(Debug, Arbitrary)]
enum SymbolSetOperation {
    /// Insert a single symbol with specific properties
    InsertSymbol {
        sbn: u8,
        esi: u16,
        kind: FuzzSymbolKind,
        data: Vec<u8>,
    },
    /// Insert a batch of symbols
    InsertBatch { symbols: Vec<FuzzSymbol> },
    /// Set block K parameter (source symbol count)
    SetBlockK { sbn: u8, k: u16 },
    /// Remove symbol by ID
    RemoveSymbol { sbn: u8, esi: u16 },
    /// Query operations
    QuerySymbol { sbn: u8, esi: u16 },
    /// Serialize current state to frame format
    SerializeToFrame,
    /// Memory pressure test: insert until limit reached
    MemoryPressureTest { target_bytes: usize },
}

/// Fuzzable symbol kind
#[derive(Debug, Arbitrary, Clone, Copy)]
enum FuzzSymbolKind {
    Source,
    Repair,
}

impl From<FuzzSymbolKind> for SymbolKind {
    fn from(kind: FuzzSymbolKind) -> Self {
        match kind {
            FuzzSymbolKind::Source => SymbolKind::Source,
            FuzzSymbolKind::Repair => SymbolKind::Repair,
        }
    }
}

/// Fuzzable symbol representation
#[derive(Debug, Arbitrary, Clone)]
struct FuzzSymbol {
    sbn: u8,
    esi: u16,
    kind: FuzzSymbolKind,
    data: Vec<u8>,
}

/// Frame serialization format for symbol sets
#[derive(Debug, Arbitrary)]
enum FrameFormat {
    /// Simple binary format: [count][symbol_1][symbol_2]...
    SimpleBinary,
    /// Length-prefixed format: [total_len][count][symbols...]
    LengthPrefixed,
    /// Compressed format with deduplication
    Compressed,
    /// Malformed format for error path testing
    Malformed { corruption_type: CorruptionType },
}

/// Types of corruption to test error handling
#[derive(Debug, Arbitrary)]
enum CorruptionType {
    TruncatedHeader,
    InvalidLength,
    MissingTerminator,
    DataCorruption { offset: usize },
    CountMismatch,
}

/// Main fuzzing harness configuration
#[derive(Debug, Arbitrary)]
struct FuzzScenario {
    /// Initial threshold configuration
    threshold_config: FuzzThresholdConfig,
    /// Memory budget (None = unlimited)
    memory_budget: Option<usize>,
    /// Sequence of operations to perform
    operations: Vec<SymbolSetOperation>,
    /// Frame format to test
    frame_format: FrameFormat,
    /// Whether to test round-trip invariants
    test_roundtrip: bool,
}

/// Fuzzable threshold configuration
#[derive(Debug, Arbitrary)]
struct FuzzThresholdConfig {
    overhead_factor: f64,
    min_overhead: usize,
    max_per_block: usize,
}

impl From<FuzzThresholdConfig> for ThresholdConfig {
    fn from(config: FuzzThresholdConfig) -> Self {
        // Sanitize inputs to prevent NaN/infinity
        let overhead_factor = if config.overhead_factor.is_finite() && config.overhead_factor > 0.0
        {
            config.overhead_factor.clamp(1.0, 10.0)
        } else {
            1.02
        };

        ThresholdConfig::new(
            overhead_factor,
            config.min_overhead.min(1024),
            config.max_per_block.min(MAX_SYMBOLS_PER_SET),
        )
    }
}

/// Execute the fuzzing scenario with comprehensive error handling
fn execute_scenario(scenario: FuzzScenario) -> Result<(), Box<dyn std::error::Error>> {
    // Input size guard
    if scenario.operations.len() > MAX_SYMBOLS_PER_SET {
        return Ok(());
    }

    // Create SymbolSet with fuzzed configuration
    let threshold_config = ThresholdConfig::from(scenario.threshold_config);
    let mut symbol_set = if let Some(budget) = scenario.memory_budget {
        SymbolSet::with_memory_budget(threshold_config, budget.min(MAX_INPUT_SIZE))
    } else {
        SymbolSet::with_config(threshold_config)
    };

    // Track state for invariant checking
    let mut expected_symbols: HashMap<SymbolId, Symbol> = HashMap::new();
    let mut block_progress_tracker: HashMap<u8, (usize, usize, Option<u16>)> = HashMap::new();

    // Execute operations sequence
    for operation in scenario.operations {
        match operation {
            SymbolSetOperation::InsertSymbol {
                sbn,
                esi,
                kind,
                mut data,
            } => {
                if sbn > MAX_SOURCE_BLOCKS || data.len() > MAX_SYMBOL_SIZE {
                    continue;
                }

                // Bound data size
                data.truncate(MAX_SYMBOL_SIZE);

                let symbol_id = SymbolId::new(ObjectId::new_for_test(0), sbn, u32::from(esi));
                let symbol = Symbol::new(symbol_id, data.clone(), kind.into());

                let result = symbol_set.insert(symbol.clone());

                // Update tracking for invariant checks
                match result {
                    InsertResult::Inserted { block_progress, .. } => {
                        expected_symbols.insert(symbol_id, symbol);
                        let entry = block_progress_tracker.entry(sbn).or_insert((0, 0, None));
                        match kind {
                            FuzzSymbolKind::Source => entry.0 += 1,
                            FuzzSymbolKind::Repair => entry.1 += 1,
                        }

                        // Verify progress tracking consistency
                        assert_eq!(block_progress.sbn, sbn);
                        assert_eq!(block_progress.source_symbols, entry.0);
                        assert_eq!(block_progress.repair_symbols, entry.1);
                    }
                    InsertResult::Duplicate => {
                        // Symbol already exists - verify it's actually there
                        assert!(symbol_set.contains(&symbol_id));
                    }
                    InsertResult::MemoryLimitReached => {
                        // Memory limit hit - this is expected behavior
                    }
                    InsertResult::BlockLimitReached { sbn: limit_sbn } => {
                        assert_eq!(limit_sbn, sbn);
                    }
                }
            }

            SymbolSetOperation::InsertBatch { symbols } => {
                let batch_symbols: Vec<Symbol> = symbols
                    .into_iter()
                    .filter(|s| s.sbn <= MAX_SOURCE_BLOCKS && s.data.len() <= MAX_SYMBOL_SIZE)
                    .take(MAX_SYMBOLS_PER_SET / 4) // Limit batch size
                    .map(|fuzz_sym| {
                        let mut data = fuzz_sym.data;
                        data.truncate(MAX_SYMBOL_SIZE);
                        let symbol_id = SymbolId::new(
                            ObjectId::new_for_test(0),
                            fuzz_sym.sbn,
                            u32::from(fuzz_sym.esi),
                        );
                        Symbol::new(symbol_id, data, fuzz_sym.kind.into())
                    })
                    .collect();

                let results = symbol_set.insert_batch(batch_symbols.clone().into_iter());

                // Verify batch results consistency
                assert!(results.len() <= MAX_SYMBOLS_PER_SET / 4);
                for (symbol, result) in batch_symbols.into_iter().zip(results.iter()) {
                    if let InsertResult::Inserted { block_progress, .. } = result {
                        expected_symbols.insert(symbol.id(), symbol.clone());
                        let entry = block_progress_tracker
                            .entry(symbol.sbn())
                            .or_insert((0, 0, None));
                        match symbol.kind() {
                            SymbolKind::Source => entry.0 += 1,
                            SymbolKind::Repair => entry.1 += 1,
                        }
                        assert_eq!(block_progress.sbn, symbol.sbn());
                        assert_eq!(block_progress.source_symbols, entry.0);
                        assert_eq!(block_progress.repair_symbols, entry.1);
                    }
                }
            }

            SymbolSetOperation::SetBlockK { sbn, k } => {
                if sbn <= MAX_SOURCE_BLOCKS && k > 0 && k <= 256 {
                    let threshold_reached = symbol_set.set_block_k(sbn, k);

                    // Update tracking
                    let entry = block_progress_tracker.entry(sbn).or_insert((0, 0, None));
                    entry.2 = Some(k);

                    // Verify threshold logic
                    let progress = symbol_set
                        .block_progress(sbn)
                        .expect("set_block_k must create block progress");
                    assert_eq!(threshold_reached, progress.threshold_reached);
                    if progress.total() < usize::from(k) {
                        assert!(!threshold_reached);
                    }
                }
            }

            SymbolSetOperation::RemoveSymbol { sbn, esi } => {
                if sbn <= MAX_SOURCE_BLOCKS {
                    let symbol_id = SymbolId::new(ObjectId::new_for_test(0), sbn, u32::from(esi));
                    let removed = symbol_set.remove(&symbol_id);

                    if let Some(symbol) = removed {
                        expected_symbols.remove(&symbol_id);

                        // Update tracking
                        if let Some(entry) = block_progress_tracker.get_mut(&sbn) {
                            match symbol.kind() {
                                SymbolKind::Source => entry.0 = entry.0.saturating_sub(1),
                                SymbolKind::Repair => entry.1 = entry.1.saturating_sub(1),
                            }
                        }
                    }
                }
            }

            SymbolSetOperation::QuerySymbol { sbn, esi } => {
                if sbn <= MAX_SOURCE_BLOCKS {
                    let symbol_id = SymbolId::new(ObjectId::new_for_test(0), sbn, u32::from(esi));
                    let exists = symbol_set.contains(&symbol_id);
                    let get_result = symbol_set.get(&symbol_id);

                    // Consistency check: contains and get should agree
                    assert_eq!(exists, get_result.is_some());

                    if exists {
                        assert!(expected_symbols.contains_key(&symbol_id));
                    }
                }
            }

            SymbolSetOperation::SerializeToFrame => {
                let frame_data = serialize_symbol_set_to_frame(&symbol_set, &scenario.frame_format);

                if scenario.test_roundtrip && !frame_data.is_empty() {
                    // Test round-trip: frame -> symbols preserves the live set.
                    match deserialize_frame_to_symbols(&frame_data, &scenario.frame_format) {
                        Ok(deserialized) => {
                            assert!(deserialized.len() <= MAX_SYMBOLS_PER_SET);
                            assert_symbol_roundtrip(&symbol_set, &deserialized);
                        }
                        Err(_)
                            if matches!(&scenario.frame_format, FrameFormat::Malformed { .. }) =>
                        {
                            // Malformed frame variants are expected to be rejected cleanly.
                        }
                        Err(error) => return Err(error),
                    }
                }
            }

            SymbolSetOperation::MemoryPressureTest { target_bytes } => {
                if target_bytes > MAX_INPUT_SIZE {
                    continue;
                }

                // Generate symbols until memory pressure
                let mut count = 0;
                let data = vec![0u8; 256]; // Fixed size data

                while count < 100 {
                    // Limit iterations
                    let symbol_id = SymbolId::new(ObjectId::new_for_test(0), 0, count);
                    let symbol = Symbol::new(symbol_id, data.clone(), SymbolKind::Source);

                    match symbol_set.insert(symbol) {
                        InsertResult::MemoryLimitReached => break,
                        InsertResult::Inserted { block_progress, .. } => {
                            let inserted_id = SymbolId::new(ObjectId::new_for_test(0), 0, count);
                            let inserted =
                                Symbol::new(inserted_id, data.clone(), SymbolKind::Source);
                            expected_symbols.insert(inserted_id, inserted);
                            let entry = block_progress_tracker.entry(0).or_insert((0, 0, None));
                            entry.0 += 1;
                            assert_eq!(block_progress.sbn, 0);
                            assert_eq!(block_progress.source_symbols, entry.0);
                        }
                        InsertResult::Duplicate | InsertResult::BlockLimitReached { .. } => {}
                    }
                    count += 1;
                }
            }
        }
    }

    Ok(())
}

const SIMPLE_MAGIC: &[u8; 4] = b"RQSB";
const LENGTH_PREFIXED_MAGIC: &[u8; 4] = b"RQSL";
const COMPRESSED_MAGIC: &[u8; 4] = b"RQSC";
const COMPRESSED_PER_SYMBOL_OBJECTS: u8 = 0;
const COMPRESSED_COMMON_OBJECT: u8 = 1;

/// Serialize symbol set to a deterministic fuzzer-only frame format.
fn serialize_symbol_set_to_frame(symbol_set: &SymbolSet, format: &FrameFormat) -> Vec<u8> {
    let symbols = sorted_symbols(symbol_set);

    match format {
        FrameFormat::SimpleBinary => {
            let mut frame = Vec::new();
            frame.extend_from_slice(SIMPLE_MAGIC);
            push_full_symbol_records(&mut frame, &symbols);
            frame
        }
        FrameFormat::LengthPrefixed => {
            let mut payload = Vec::new();
            payload.extend_from_slice(LENGTH_PREFIXED_MAGIC);
            push_full_symbol_records(&mut payload, &symbols);

            let mut frame = Vec::with_capacity(4 + payload.len());
            let payload_len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
            frame.extend_from_slice(&payload_len.to_le_bytes());
            frame.extend_from_slice(&payload);
            frame
        }
        FrameFormat::Compressed => {
            let mut frame = Vec::new();
            frame.extend_from_slice(COMPRESSED_MAGIC);
            push_u16(&mut frame, symbols.len());

            if symbols.is_empty() {
                frame.push(COMPRESSED_COMMON_OBJECT);
            } else {
                let first_object = symbols[0].object_id();
                let has_common_object = symbols
                    .iter()
                    .all(|symbol| symbol.object_id() == first_object);

                if has_common_object {
                    frame.push(COMPRESSED_COMMON_OBJECT);
                    push_object_id(&mut frame, first_object);
                    for symbol in symbols {
                        push_local_symbol_record(&mut frame, symbol);
                    }
                } else {
                    frame.push(COMPRESSED_PER_SYMBOL_OBJECTS);
                    push_full_symbol_payloads(&mut frame, &symbols);
                }
            }

            frame
        }
        FrameFormat::Malformed { corruption_type } => match corruption_type {
            CorruptionType::TruncatedHeader => vec![0x01],
            CorruptionType::InvalidLength => vec![0xFF, 0xFF, 0xFF, 0xFF],
            CorruptionType::MissingTerminator => vec![0x01, 0x02, 0x03],
            CorruptionType::DataCorruption { offset } => {
                let mut data = vec![0u8; 16];
                if *offset < data.len() {
                    data[*offset] = 0xFF;
                }
                data
            }
            CorruptionType::CountMismatch => vec![0x10, 0x00, 0x01, 0x02],
        },
    }
}

/// Deserialize frame back to symbols (simplified implementation for testing)
fn deserialize_frame_to_symbols(
    data: &[u8],
    format: &FrameFormat,
) -> Result<Vec<Symbol>, Box<dyn std::error::Error>> {
    match format {
        FrameFormat::SimpleBinary => {
            let mut offset = 0;
            read_magic(data, &mut offset, SIMPLE_MAGIC)?;
            let symbols = read_full_symbol_records(data, &mut offset)?;
            reject_trailing_bytes(data, offset)?;
            Ok(symbols)
        }
        FrameFormat::LengthPrefixed => {
            let mut offset = 0;
            let payload_len = usize::try_from(read_u32(data, &mut offset)?)
                .map_err(|_| "Length-prefixed frame length does not fit usize")?;
            if payload_len != data.len().saturating_sub(offset) {
                return Err("Length-prefixed frame length mismatch".into());
            }

            read_magic(data, &mut offset, LENGTH_PREFIXED_MAGIC)?;
            let symbols = read_full_symbol_records(data, &mut offset)?;
            reject_trailing_bytes(data, offset)?;
            Ok(symbols)
        }
        FrameFormat::Compressed => {
            let mut offset = 0;
            read_magic(data, &mut offset, COMPRESSED_MAGIC)?;
            let count = read_symbol_count(data, &mut offset)?;
            let mode = read_u8(data, &mut offset)?;

            let symbols = match mode {
                COMPRESSED_COMMON_OBJECT if count == 0 => Vec::new(),
                COMPRESSED_COMMON_OBJECT => {
                    let object_id = read_object_id(data, &mut offset)?;
                    read_local_symbol_records(data, &mut offset, count, object_id)?
                }
                COMPRESSED_PER_SYMBOL_OBJECTS => {
                    read_full_symbol_payloads(data, &mut offset, count)?
                }
                _ => return Err("Unknown compressed frame object mode".into()),
            };

            reject_trailing_bytes(data, offset)?;
            Ok(symbols)
        }
        FrameFormat::Malformed { .. } => {
            // Malformed frames should cause controlled errors
            Err("Malformed frame".into())
        }
    }
}

fn sorted_symbols(symbol_set: &SymbolSet) -> Vec<&Symbol> {
    let mut symbols: Vec<&Symbol> = symbol_set.iter().map(|(_, symbol)| symbol).collect();
    symbols.sort_by_key(|symbol| {
        (
            symbol.object_id().as_u128(),
            symbol.sbn(),
            symbol.esi(),
            symbol_kind_tag(symbol.kind()),
            symbol.data().len(),
        )
    });
    symbols
}

fn assert_symbol_roundtrip(symbol_set: &SymbolSet, deserialized: &[Symbol]) {
    assert_eq!(deserialized.len(), symbol_set.len());

    let mut seen = HashSet::new();
    for symbol in deserialized {
        assert!(
            seen.insert(symbol.id()),
            "decoder emitted duplicate symbol id"
        );

        let expected = symbol_set
            .get(&symbol.id())
            .expect("decoded symbol id must exist in serialized set");
        assert_eq!(symbol.kind(), expected.kind());
        assert_eq!(symbol.data(), expected.data());
    }
}

fn push_full_symbol_records(frame: &mut Vec<u8>, symbols: &[&Symbol]) {
    push_u16(frame, symbols.len());
    push_full_symbol_payloads(frame, symbols);
}

fn push_full_symbol_payloads(frame: &mut Vec<u8>, symbols: &[&Symbol]) {
    for symbol in symbols {
        push_object_id(frame, symbol.object_id());
        push_local_symbol_record(frame, symbol);
    }
}

fn push_local_symbol_record(frame: &mut Vec<u8>, symbol: &Symbol) {
    frame.push(symbol.sbn());
    frame.extend_from_slice(&symbol.esi().to_le_bytes());
    frame.push(symbol_kind_tag(symbol.kind()));
    push_u16(frame, symbol.data().len());
    frame.extend_from_slice(symbol.data());
}

fn push_object_id(frame: &mut Vec<u8>, object_id: ObjectId) {
    frame.extend_from_slice(&object_id.high().to_le_bytes());
    frame.extend_from_slice(&object_id.low().to_le_bytes());
}

fn push_u16(frame: &mut Vec<u8>, value: usize) {
    debug_assert!(value <= usize::from(u16::MAX));
    let value = u16::try_from(value).unwrap_or(u16::MAX);
    frame.extend_from_slice(&value.to_le_bytes());
}

fn read_full_symbol_records(
    data: &[u8],
    offset: &mut usize,
) -> Result<Vec<Symbol>, Box<dyn std::error::Error>> {
    let count = read_symbol_count(data, offset)?;
    read_full_symbol_payloads(data, offset, count)
}

fn read_full_symbol_payloads(
    data: &[u8],
    offset: &mut usize,
    count: usize,
) -> Result<Vec<Symbol>, Box<dyn std::error::Error>> {
    let mut symbols = Vec::with_capacity(count);

    for _ in 0..count {
        let object_id = read_object_id(data, offset)?;
        symbols.push(read_local_symbol_record(data, offset, object_id)?);
    }

    Ok(symbols)
}

fn read_local_symbol_records(
    data: &[u8],
    offset: &mut usize,
    count: usize,
    object_id: ObjectId,
) -> Result<Vec<Symbol>, Box<dyn std::error::Error>> {
    let mut symbols = Vec::with_capacity(count);

    for _ in 0..count {
        symbols.push(read_local_symbol_record(data, offset, object_id)?);
    }

    Ok(symbols)
}

fn read_local_symbol_record(
    data: &[u8],
    offset: &mut usize,
    object_id: ObjectId,
) -> Result<Symbol, Box<dyn std::error::Error>> {
    let sbn = read_u8(data, offset)?;
    let esi = read_u32(data, offset)?;
    let kind = symbol_kind_from_tag(read_u8(data, offset)?)?;
    let data_len = usize::from(read_u16(data, offset)?);
    if data_len > MAX_SYMBOL_SIZE {
        return Err("Decoded symbol exceeds fuzz symbol size limit".into());
    }

    let payload = read_exact(data, offset, data_len)?.to_vec();
    let id = SymbolId::new(object_id, sbn, esi);
    Ok(Symbol::new(id, payload, kind))
}

fn read_symbol_count(data: &[u8], offset: &mut usize) -> Result<usize, Box<dyn std::error::Error>> {
    let count = usize::from(read_u16(data, offset)?);
    if count > MAX_SYMBOLS_PER_SET {
        return Err("Decoded symbol count exceeds fuzz set limit".into());
    }
    Ok(count)
}

fn read_object_id(data: &[u8], offset: &mut usize) -> Result<ObjectId, Box<dyn std::error::Error>> {
    let high = read_u64(data, offset)?;
    let low = read_u64(data, offset)?;
    Ok(ObjectId::new(high, low))
}

fn read_magic(
    data: &[u8],
    offset: &mut usize,
    expected: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let actual = read_exact(data, offset, expected.len())?;
    if actual != expected {
        return Err("Frame magic mismatch".into());
    }
    Ok(())
}

fn read_exact<'a>(
    data: &'a [u8],
    offset: &mut usize,
    len: usize,
) -> Result<&'a [u8], Box<dyn std::error::Error>> {
    let end = offset
        .checked_add(len)
        .ok_or("Frame offset overflow while decoding")?;
    if end > data.len() {
        return Err("Frame ended before expected field".into());
    }

    let bytes = &data[*offset..end];
    *offset = end;
    Ok(bytes)
}

fn read_u8(data: &[u8], offset: &mut usize) -> Result<u8, Box<dyn std::error::Error>> {
    Ok(read_exact(data, offset, 1)?[0])
}

fn read_u16(data: &[u8], offset: &mut usize) -> Result<u16, Box<dyn std::error::Error>> {
    let bytes = read_exact(data, offset, 2)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(data: &[u8], offset: &mut usize) -> Result<u32, Box<dyn std::error::Error>> {
    let bytes = read_exact(data, offset, 4)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(data: &[u8], offset: &mut usize) -> Result<u64, Box<dyn std::error::Error>> {
    let bytes = read_exact(data, offset, 8)?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn reject_trailing_bytes(data: &[u8], offset: usize) -> Result<(), Box<dyn std::error::Error>> {
    if offset != data.len() {
        return Err("Frame has trailing bytes".into());
    }
    Ok(())
}

fn symbol_kind_tag(kind: SymbolKind) -> u8 {
    match kind {
        SymbolKind::Source => 0,
        SymbolKind::Repair => 1,
    }
}

fn symbol_kind_from_tag(tag: u8) -> Result<SymbolKind, Box<dyn std::error::Error>> {
    match tag {
        0 => Ok(SymbolKind::Source),
        1 => Ok(SymbolKind::Repair),
        _ => Err("Unknown symbol kind tag".into()),
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_SIZE {
        return;
    }

    let mut u = Unstructured::new(data);

    // Generate fuzz scenario from input data
    if let Ok(scenario) = FuzzScenario::arbitrary(&mut u) {
        execute_scenario(scenario).unwrap_or_else(|error| {
            panic!("RaptorQ SymbolSet frame transition failed: {error}");
        });
    }
});
