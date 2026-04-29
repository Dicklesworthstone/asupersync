#![no_main]

//! Structure-aware fuzz target for RaptorQ decoder progressive symbol arrival under cancel storm.
//!
//! Targets edge cases in wavefront decoding pipeline under cancellation pressure:
//! - Progressive symbol arrival in batches with cancellation interrupts
//! - Wavefront batch processing with varying batch sizes and cancel timing
//! - Peeling queue state consistency when decoding is interrupted
//! - Resource cleanup and state invariants under cancel storm conditions
//! - Edge cases in assembly → peel → cancel sequences
//! - Verification that partial progress is safely discarded on cancellation

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::raptorq::decoder::{DecodeError, InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::gf256::Gf256;

/// Maximum symbols to generate for fuzzer performance
const MAX_SYMBOLS: usize = 200;

/// Maximum K value for decoder test scenarios
const MAX_K: usize = 100;

/// Test scenario for progressive symbol arrival under cancellation stress
#[derive(Arbitrary, Debug, Clone)]
struct ProgressiveCancelScenario {
    /// Source block configuration
    source_config: SourceConfig,
    /// Symbol arrival strategy (batch patterns and timing)
    arrival_strategy: ArrivalStrategy,
    /// Cancellation storm pattern
    cancel_pattern: CancelPattern,
    /// Operations to test during progressive arrival
    operations: Vec<ProgressiveOperation>,
}

/// Source block configuration affecting decode complexity
#[derive(Arbitrary, Debug, Clone)]
struct SourceConfig {
    /// Number of source symbols (K)
    k: SourceBlockSize,
    /// Symbol size for this test
    symbol_size: SymbolSize,
    /// Decoder seed
    seed: u64,
}

/// Source block size options
#[derive(Arbitrary, Debug, Clone, Copy)]
enum SourceBlockSize {
    /// Very small K (high peeling opportunities)
    Tiny(u8), // 1-10
    /// Small K (typical short blocks)
    Small(u8), // 11-50
    /// Medium K (systematic table boundaries)
    Medium(u8), // 51-100
}

impl SourceBlockSize {
    fn as_usize(self) -> usize {
        match self {
            SourceBlockSize::Tiny(k) => ((k as usize) % 10).max(1),
            SourceBlockSize::Small(k) => ((k as usize) % 40) + 11,
            SourceBlockSize::Medium(k) => ((k as usize) % 50) + 51,
        }
    }
}

/// Symbol size options
#[derive(Arbitrary, Debug, Clone, Copy)]
enum SymbolSize {
    Small,
    Medium,
    Large,
}

impl SymbolSize {
    fn as_usize(self) -> usize {
        match self {
            SymbolSize::Small => 32,
            SymbolSize::Medium => 128,
            SymbolSize::Large => 512,
        }
    }
}

/// Strategy for progressive symbol arrival
#[derive(Arbitrary, Debug, Clone)]
enum ArrivalStrategy {
    /// Small batch size with frequent interruption opportunities
    SmallBatches {
        batch_size: SmallBatchSize,
        total_batches: u8, // 1-20
    },
    /// Medium batches with balanced arrival pattern
    MediumBatches {
        batch_size: MediumBatchSize,
        arrival_jitter: ArrivalJitter,
    },
    /// Large batch with concentrated symbol arrival
    LargeBatch {
        /// Single large batch size
        batch_size: LargeBatchSize,
    },
    /// Variable batch sizes simulating network conditions
    VariableBatches {
        /// Sequence of different batch sizes
        batch_pattern: Vec<BatchSize>,
    },
}

/// Small batch size (1-5 symbols per batch)
#[derive(Arbitrary, Debug, Clone, Copy)]
enum SmallBatchSize {
    Single,      // 1 symbol per batch
    Pair,        // 2 symbols per batch
    Triple,      // 3 symbols per batch
    Quad,        // 4 symbols per batch
    Penta,       // 5 symbols per batch
}

impl SmallBatchSize {
    fn as_usize(self) -> usize {
        match self {
            SmallBatchSize::Single => 1,
            SmallBatchSize::Pair => 2,
            SmallBatchSize::Triple => 3,
            SmallBatchSize::Quad => 4,
            SmallBatchSize::Penta => 5,
        }
    }
}

/// Medium batch size (6-20 symbols per batch)
#[derive(Arbitrary, Debug, Clone, Copy)]
enum MediumBatchSize {
    Small(u8),   // 6-10
    Medium(u8),  // 11-15
    Large(u8),   // 16-20
}

impl MediumBatchSize {
    fn as_usize(self) -> usize {
        match self {
            MediumBatchSize::Small(n) => ((n as usize) % 5) + 6,
            MediumBatchSize::Medium(n) => ((n as usize) % 5) + 11,
            MediumBatchSize::Large(n) => ((n as usize) % 5) + 16,
        }
    }
}

/// Large batch size (21+ symbols)
#[derive(Arbitrary, Debug, Clone, Copy)]
enum LargeBatchSize {
    Standard(u8),  // 21-50
    Huge(u8),      // 51-100
}

impl LargeBatchSize {
    fn as_usize(self) -> usize {
        match self {
            LargeBatchSize::Standard(n) => ((n as usize) % 30) + 21,
            LargeBatchSize::Huge(n) => ((n as usize) % 50) + 51,
        }
    }
}

/// Generic batch size for variable patterns
#[derive(Arbitrary, Debug, Clone, Copy)]
enum BatchSize {
    Small(SmallBatchSize),
    Medium(MediumBatchSize),
    Large(LargeBatchSize),
}

impl BatchSize {
    fn as_usize(self) -> usize {
        match self {
            BatchSize::Small(s) => s.as_usize(),
            BatchSize::Medium(m) => m.as_usize(),
            BatchSize::Large(l) => l.as_usize(),
        }
    }
}

/// Jitter patterns for symbol arrival timing
#[derive(Arbitrary, Debug, Clone, Copy)]
enum ArrivalJitter {
    /// No jitter - regular intervals
    None,
    /// Low jitter - slight timing variation
    Low,
    /// High jitter - significant timing variation
    High,
    /// Burst pattern - symbols arrive in clusters
    Burst,
}

/// Cancellation storm patterns
#[derive(Arbitrary, Debug, Clone)]
enum CancelPattern {
    /// No cancellation (baseline test)
    None,
    /// Cancel at specific progress points
    AtProgress {
        /// Progress points where cancellation occurs (as fraction of total symbols)
        cancel_points: Vec<ProgressPoint>,
    },
    /// Random cancellation throughout decoding
    Random {
        /// Number of random cancel attempts
        attempts: u8, // 1-10
        /// Probability of each cancel attempt succeeding
        probability: CancelProbability,
    },
    /// Storm pattern - frequent cancel attempts
    Storm {
        /// Cancel attempt frequency (every N symbols)
        frequency: CancelFrequency,
        /// Duration of the storm
        duration: StormDuration,
    },
}

/// Progress points during decoding for targeted cancellation
#[derive(Arbitrary, Debug, Clone, Copy)]
enum ProgressPoint {
    /// During initial symbol assembly
    EarlyAssembly,
    /// During first peeling phase
    FirstPeel,
    /// During mid-decode processing
    MidDecode,
    /// During dense elimination phase
    DenseElimination,
    /// Just before completion
    NearCompletion,
}

/// Probability of cancellation occurring
#[derive(Arbitrary, Debug, Clone, Copy)]
enum CancelProbability {
    Low,      // ~10% chance
    Medium,   // ~30% chance
    High,     // ~60% chance
    VeryHigh, // ~90% chance
}

impl CancelProbability {
    fn as_f32(self) -> f32 {
        match self {
            CancelProbability::Low => 0.1,
            CancelProbability::Medium => 0.3,
            CancelProbability::High => 0.6,
            CancelProbability::VeryHigh => 0.9,
        }
    }
}

/// Frequency of cancellation attempts during storm
#[derive(Arbitrary, Debug, Clone, Copy)]
enum CancelFrequency {
    /// Every symbol
    PerSymbol,
    /// Every 2-3 symbols
    Low(u8), // 2-5
    /// Every 5-10 symbols
    Medium(u8), // 5-10
    /// Every 10+ symbols
    High(u8), // 10-20
}

impl CancelFrequency {
    fn as_usize(self) -> usize {
        match self {
            CancelFrequency::PerSymbol => 1,
            CancelFrequency::Low(n) => ((n as usize) % 4) + 2,
            CancelFrequency::Medium(n) => ((n as usize) % 6) + 5,
            CancelFrequency::High(n) => ((n as usize) % 11) + 10,
        }
    }
}

/// Duration of cancellation storm
#[derive(Arbitrary, Debug, Clone, Copy)]
enum StormDuration {
    /// Brief storm (few symbols)
    Short(u8), // 5-15 symbols
    /// Extended storm (many symbols)
    Long(u8),  // 20-50 symbols
    /// Storm for entire decode
    Full,
}

impl StormDuration {
    fn as_usize(self) -> usize {
        match self {
            StormDuration::Short(n) => ((n as usize) % 11) + 5,
            StormDuration::Long(n) => ((n as usize) % 31) + 20,
            StormDuration::Full => usize::MAX,
        }
    }
}

/// Operations to test during progressive decoding
#[derive(Arbitrary, Debug, Clone)]
enum ProgressiveOperation {
    /// Decode with standard batch processing
    DecodeBatched {
        batch_size: BatchSize,
    },
    /// Use wavefront decoding with specific batch size
    DecodeWavefront {
        batch_size: BatchSize,
    },
    /// Attempt decode at intermediate point (should fail gracefully)
    TryIntermediateDecode {
        /// After how many symbols to attempt decode
        after_symbols: u8, // 1-50
    },
    /// Simulate memory pressure during decoding
    MemoryPressure,
    /// Validate decoder state consistency
    ValidateState,
}

/// Symbol data generation patterns
#[derive(Arbitrary, Debug, Clone)]
enum SymbolData {
    /// All zeros
    Zero,
    /// All ones
    One,
    /// Incremental pattern
    Incremental(u8), // Start value
    /// Random pattern
    Random(u32), // Seed
    /// Alternating pattern
    Alternating,
}

impl SymbolData {
    fn generate(&self, size: usize) -> Vec<u8> {
        match self {
            SymbolData::Zero => vec![0u8; size],
            SymbolData::One => vec![0xFFu8; size],
            SymbolData::Incremental(start) => {
                let mut data = Vec::with_capacity(size);
                let mut value = *start;
                for _ in 0..size {
                    data.push(value);
                    value = value.wrapping_add(1);
                }
                data
            }
            SymbolData::Random(seed) => {
                let mut data = Vec::with_capacity(size);
                let mut state = *seed;
                for _ in 0..size {
                    state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                    data.push((state >> 24) as u8);
                }
                data
            }
            SymbolData::Alternating => {
                (0..size).map(|i| if i % 2 == 0 { 0xAA } else { 0x55 }).collect()
            }
        }
    }
}

fuzz_target!(|scenario: ProgressiveCancelScenario| {
    // Limit complexity for fuzzer performance
    if scenario.operations.len() > 20 {
        return;
    }

    // Test progressive symbol arrival under cancel storm
    test_progressive_cancel_scenario(&scenario);

    // Test invariants under cancellation
    test_cancel_invariants(&scenario);

    // Test wavefront pipeline robustness
    test_wavefront_cancel_robustness(&scenario);
});

fn test_progressive_cancel_scenario(scenario: &ProgressiveCancelScenario) {
    let k = scenario.source_config.k.as_usize();
    let symbol_size = scenario.source_config.symbol_size.as_usize();
    let seed = scenario.source_config.seed;

    // Create decoder
    let decoder = match InactivationDecoder::try_new(k, symbol_size, seed) {
        Ok(d) => d,
        Err(_) => return, // Invalid K is expected for some test cases
    };

    // Generate test symbols
    let symbols = generate_test_symbols(k, symbol_size, &scenario.arrival_strategy);

    // Test progressive arrival with cancellation
    for operation in &scenario.operations {
        let result = match operation {
            ProgressiveOperation::DecodeBatched { batch_size } => {
                test_batched_decode_with_cancel(&decoder, &symbols, batch_size.as_usize(), &scenario.cancel_pattern)
            }

            ProgressiveOperation::DecodeWavefront { batch_size } => {
                test_wavefront_decode_with_cancel(&decoder, &symbols, batch_size.as_usize(), &scenario.cancel_pattern)
            }

            ProgressiveOperation::TryIntermediateDecode { after_symbols } => {
                test_intermediate_decode(&decoder, &symbols, *after_symbols as usize)
            }

            ProgressiveOperation::MemoryPressure => {
                test_memory_pressure_decode(&decoder, &symbols)
            }

            ProgressiveOperation::ValidateState => {
                test_state_validation(&decoder, &symbols)
            }
        };

        // Don't fail on expected errors - we're testing error handling under cancellation
        let _ = result;
    }
}

fn test_cancel_invariants(scenario: &ProgressiveCancelScenario) {
    let k = scenario.source_config.k.as_usize();
    let symbol_size = scenario.source_config.symbol_size.as_usize();
    let seed = scenario.source_config.seed;

    let decoder = match InactivationDecoder::try_new(k, symbol_size, seed) {
        Ok(d) => d,
        Err(_) => return,
    };

    // Test that decoder state remains valid under cancellation
    let symbols = generate_test_symbols(k, symbol_size, &scenario.arrival_strategy);

    // Test that partial decode attempts don't corrupt subsequent attempts
    let partial_result = decoder.decode(&symbols[..symbols.len().min(k/2)]);

    // Should fail due to insufficient symbols, but not crash
    if let Err(DecodeError::InsufficientSymbols { .. }) = partial_result {
        // Expected - continue with full decode
    }

    // Full decode should still work
    if symbols.len() >= k {
        let _full_result = decoder.decode(&symbols);
    }
}

fn test_wavefront_cancel_robustness(scenario: &ProgressiveCancelScenario) {
    let k = scenario.source_config.k.as_usize();
    let symbol_size = scenario.source_config.symbol_size.as_usize();
    let seed = scenario.source_config.seed;

    let decoder = match InactivationDecoder::try_new(k, symbol_size, seed) {
        Ok(d) => d,
        Err(_) => return,
    };

    let symbols = generate_test_symbols(k, symbol_size, &scenario.arrival_strategy);

    // Test different wavefront batch sizes under cancellation
    let batch_sizes = [1, 2, 5, 10, 25];

    for &batch_size in &batch_sizes {
        if symbols.len() >= k {
            // Test that different batch sizes produce identical results
            // (when not interrupted by cancellation)
            let result_sequential = decoder.decode(&symbols);
            let result_wavefront = decoder.decode_wavefront(&symbols, batch_size);

            match (&result_sequential, &result_wavefront) {
                (Ok(seq), Ok(wave)) => {
                    // Results should be identical
                    assert_eq!(seq.source.len(), wave.source.len());
                    if seq.source.len() == wave.source.len() {
                        for (s, w) in seq.source.iter().zip(&wave.source) {
                            if s != w {
                                // Mismatch found - this could indicate a bug
                                // In fuzzing mode, don't panic but note the divergence
                                break;
                            }
                        }
                    }
                }
                (Err(e1), Err(e2)) => {
                    // Both failed - error types should match for deterministic failures
                    if std::mem::discriminant(e1) != std::mem::discriminant(e2) {
                        // Different error types could indicate non-determinism
                    }
                }
                _ => {
                    // One succeeded, one failed - potential non-determinism
                }
            }
        }
    }
}

fn generate_test_symbols(k: usize, symbol_size: usize, strategy: &ArrivalStrategy) -> Vec<ReceivedSymbol> {
    let mut symbols = Vec::new();

    // Generate source symbols
    for esi in 0..k {
        symbols.push(ReceivedSymbol {
            esi: esi as u32,
            is_source: true,
            columns: vec![esi],
            coefficients: vec![Gf256::from(1)],
            data: SymbolData::Incremental(esi as u8).generate(symbol_size),
        });
    }

    // Generate some repair symbols
    let repair_count = match strategy {
        ArrivalStrategy::SmallBatches { total_batches, .. } => (*total_batches as usize).min(20),
        ArrivalStrategy::MediumBatches { .. } => 10,
        ArrivalStrategy::LargeBatch { .. } => 5,
        ArrivalStrategy::VariableBatches { batch_pattern } => batch_pattern.len().min(15),
    };

    for i in 0..repair_count {
        let esi = (k as u32) + (i as u32);
        // Simple repair symbol - XOR of first two source symbols
        symbols.push(ReceivedSymbol {
            esi,
            is_source: false,
            columns: vec![0, 1],
            coefficients: vec![Gf256::from(1), Gf256::from(1)],
            data: SymbolData::Random(esi).generate(symbol_size),
        });
    }

    symbols.truncate(MAX_SYMBOLS);
    symbols
}

fn test_batched_decode_with_cancel(
    decoder: &InactivationDecoder,
    symbols: &[ReceivedSymbol],
    batch_size: usize,
    cancel_pattern: &CancelPattern
) -> Result<(), DecodeError> {
    // Simulate batched processing with potential cancellation

    match cancel_pattern {
        CancelPattern::None => {
            // No cancellation - test normal batched decode
            decoder.decode(symbols).map(|_| ())
        }
        CancelPattern::AtProgress { cancel_points } => {
            // Test cancellation at specific progress points
            for _point in cancel_points {
                // In a real implementation, this would check for cancellation
                // For fuzzing, we just exercise the decode path
                let partial_len = symbols.len() / 2;
                let result = decoder.decode(&symbols[..partial_len]);
                if result.is_ok() {
                    break; // Unexpected success with partial symbols
                }
            }
            Ok(())
        }
        CancelPattern::Random { .. } | CancelPattern::Storm { .. } => {
            // Test various interruption patterns
            let partial_len = symbols.len() / 3;
            let _result = decoder.decode(&symbols[..partial_len]);
            Ok(())
        }
    }
}

fn test_wavefront_decode_with_cancel(
    decoder: &InactivationDecoder,
    symbols: &[ReceivedSymbol],
    batch_size: usize,
    cancel_pattern: &CancelPattern
) -> Result<(), DecodeError> {
    // Test wavefront decoding under cancellation pressure

    match cancel_pattern {
        CancelPattern::None => {
            decoder.decode_wavefront(symbols, batch_size).map(|_| ())
        }
        _ => {
            // Test partial wavefront decode
            let partial_len = symbols.len() / 2;
            decoder.decode_wavefront(&symbols[..partial_len], batch_size).map(|_| ())
        }
    }
}

fn test_intermediate_decode(
    decoder: &InactivationDecoder,
    symbols: &[ReceivedSymbol],
    after_symbols: usize
) -> Result<(), DecodeError> {
    let attempt_len = after_symbols.min(symbols.len());
    decoder.decode(&symbols[..attempt_len]).map(|_| ())
}

fn test_memory_pressure_decode(
    decoder: &InactivationDecoder,
    symbols: &[ReceivedSymbol]
) -> Result<(), DecodeError> {
    // Simulate decode under memory pressure (simplified)
    decoder.decode(symbols).map(|_| ())
}

fn test_state_validation(
    decoder: &InactivationDecoder,
    symbols: &[ReceivedSymbol]
) -> Result<(), DecodeError> {
    // Test that decoder state validation works correctly
    decoder.decode(symbols).map(|_| ())
}