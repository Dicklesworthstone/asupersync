#![no_main]

//! Structure-aware fuzz target for RaptorQ decoder under symbol corruption.
//!
//! Targets robustness of the InactivationDecoder when receiving corrupted symbols:
//! - Bit flips and data corruption in symbol payloads
//! - Corrupted coefficient matrices and column indices
//! - Mixed corruption across source and repair symbols
//! - Error detection and recovery under systematic corruption patterns
//! - Boundary cases in corruption detection and error propagation
//! - Decoder stability when corruption affects critical decode paths

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::raptorq::decoder::{DecodeError, InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::gf256::Gf256;

/// Maximum values for fuzzer performance and memory bounds
const MAX_K: usize = 100;
const MAX_SYMBOL_SIZE: usize = 512;
const MAX_SYMBOLS: usize = 200;

/// Test scenario for decoder symbol corruption fuzzing
#[derive(Arbitrary, Debug, Clone)]
struct SymbolCorruptionScenario {
    /// Source block configuration
    source_config: SourceConfig,
    /// Set of symbols to corrupt
    corruption_targets: Vec<CorruptionTarget>,
    /// Decoding attempts and validation
    decode_operations: Vec<DecodeOperation>,
}

/// Source block configuration
#[derive(Arbitrary, Debug, Clone)]
struct SourceConfig {
    /// Number of source symbols
    k: SourceBlockK,
    /// Symbol size
    symbol_size: SymbolSize,
    /// Decoder seed
    seed: u64,
}

/// Source block size options
#[derive(Arbitrary, Debug, Clone, Copy)]
enum SourceBlockK {
    Small(u8),   // 1-20 (high corruption impact)
    Medium(u8),  // 21-50 (balanced)
    Large(u8),   // 51-100 (distributed corruption)
}

impl SourceBlockK {
    fn as_usize(self) -> usize {
        match self {
            SourceBlockK::Small(k) => (k as usize % 20).max(1),
            SourceBlockK::Medium(k) => (k as usize % 30) + 21,
            SourceBlockK::Large(k) => (k as usize % 50) + 51,
        }
    }
}

/// Symbol size options
#[derive(Arbitrary, Debug, Clone, Copy)]
enum SymbolSize {
    Tiny,    // 16 bytes
    Small,   // 64 bytes
    Medium,  // 256 bytes
    Large,   // 512 bytes
}

impl SymbolSize {
    fn as_usize(self) -> usize {
        match self {
            SymbolSize::Tiny => 16,
            SymbolSize::Small => 64,
            SymbolSize::Medium => 256,
            SymbolSize::Large => 512,
        }
    }
}

/// Symbol corruption target and method
#[derive(Arbitrary, Debug, Clone)]
struct CorruptionTarget {
    /// Target symbol specification
    target: SymbolTarget,
    /// Type of corruption to apply
    corruption_type: CorruptionType,
    /// Corruption parameters
    corruption_params: CorruptionParams,
}

/// Symbol target specification
#[derive(Arbitrary, Debug, Clone)]
enum SymbolTarget {
    /// Target source symbols
    Source {
        /// ESI of source symbol to corrupt
        esi: u32,
    },
    /// Target repair symbols
    Repair {
        /// ESI of repair symbol to corrupt
        esi: u32,
    },
    /// Target systematic symbol by index
    Systematic {
        /// Index in source block
        index: u8, // 0-255
    },
    /// Target constraint symbols
    Constraint {
        /// Which constraint symbol
        constraint_index: u8,
    },
}

/// Type of corruption to apply
#[derive(Arbitrary, Debug, Clone)]
enum CorruptionType {
    /// Corrupt symbol data payload
    DataCorruption {
        corruption_pattern: DataCorruptionPattern,
    },
    /// Corrupt equation coefficients
    CoefficientCorruption {
        coefficient_pattern: CoefficientCorruptionPattern,
    },
    /// Corrupt column indices
    ColumnCorruption {
        column_pattern: ColumnCorruptionPattern,
    },
    /// Mixed corruption (multiple corruption types)
    Mixed {
        corruptions: Vec<SingleCorruption>,
    },
}

/// Single corruption operation for mixed scenarios
#[derive(Arbitrary, Debug, Clone)]
enum SingleCorruption {
    FlipBit { byte_index: u16, bit_index: u8 },
    ZeroBytes { start: u16, len: u16 },
    RandomizeBytes { start: u16, len: u16, seed: u32 },
    CorruptCoefficient { coeff_index: u8, new_value: u8 },
    CorruptColumn { column_index: u8, new_value: u32 },
}

/// Data corruption patterns
#[derive(Arbitrary, Debug, Clone)]
enum DataCorruptionPattern {
    /// Single bit flip
    BitFlip {
        byte_offset: u16,
        bit_position: u8, // 0-7
    },
    /// Burst error (consecutive corrupted bytes)
    BurstError {
        start_offset: u16,
        length: u8, // 1-32
    },
    /// Random corruption
    RandomCorruption {
        corruption_rate: CorruptionRate,
        seed: u32,
    },
    /// Zero out data
    ZeroOut {
        start_offset: u16,
        length: u16,
    },
    /// Systematic pattern corruption
    PatternCorruption {
        pattern: CorruptionPattern,
    },
}

/// Corruption rate for random corruption
#[derive(Arbitrary, Debug, Clone, Copy)]
enum CorruptionRate {
    Low,     // ~5% of bytes
    Medium,  // ~25% of bytes
    High,    // ~75% of bytes
    Complete, // 100% of bytes
}

impl CorruptionRate {
    fn as_f32(self) -> f32 {
        match self {
            CorruptionRate::Low => 0.05,
            CorruptionRate::Medium => 0.25,
            CorruptionRate::High => 0.75,
            CorruptionRate::Complete => 1.0,
        }
    }
}

/// Systematic corruption patterns
#[derive(Arbitrary, Debug, Clone, Copy)]
enum CorruptionPattern {
    Alternating,    // 0xAA pattern
    AllOnes,        // 0xFF pattern
    Incremental,    // 0x00, 0x01, 0x02, ...
    Xor(u8),       // XOR with constant
}

/// Coefficient corruption patterns
#[derive(Arbitrary, Debug, Clone)]
enum CoefficientCorruptionPattern {
    /// Corrupt single coefficient
    Single {
        index: u8,
        new_value: u8,
    },
    /// Corrupt multiple coefficients
    Multiple {
        corruptions: Vec<CoefficientCorruption>,
    },
    /// Set all coefficients to same value
    Uniform {
        value: u8,
    },
    /// Apply systematic pattern to coefficients
    Pattern {
        pattern: CorruptionPattern,
    },
}

/// Single coefficient corruption
#[derive(Arbitrary, Debug, Clone)]
struct CoefficientCorruption {
    index: u8,
    new_value: u8,
}

/// Column index corruption patterns
#[derive(Arbitrary, Debug, Clone)]
enum ColumnCorruptionPattern {
    /// Corrupt single column index
    Single {
        index: u8,
        new_value: u32,
    },
    /// Corrupt multiple column indices
    Multiple {
        corruptions: Vec<ColumnCorruption>,
    },
    /// Out-of-range column indices
    OutOfRange {
        base_value: u32, // Large base value
    },
    /// Duplicate column indices
    Duplicate {
        target_index: u32,
    },
}

/// Single column corruption
#[derive(Arbitrary, Debug, Clone)]
struct ColumnCorruption {
    index: u8,
    new_value: u32,
}

/// Corruption parameters
#[derive(Arbitrary, Debug, Clone)]
struct CorruptionParams {
    /// Timing of corruption
    timing: CorruptionTiming,
    /// Severity level
    severity: CorruptionSeverity,
}

/// When corruption is applied
#[derive(Arbitrary, Debug, Clone, Copy)]
enum CorruptionTiming {
    /// Before any decoding attempts
    PreDecode,
    /// During progressive symbol addition
    Progressive,
    /// After some symbols processed
    PostPartial,
}

/// Severity of corruption
#[derive(Arbitrary, Debug, Clone, Copy)]
enum CorruptionSeverity {
    Minimal,   // Single bit/byte errors
    Moderate,  // Small burst errors
    Severe,    // Large corruption blocks
    Catastrophic, // Complete data destruction
}

/// Decoding operations to test with corrupted symbols
#[derive(Arbitrary, Debug, Clone)]
enum DecodeOperation {
    /// Standard decode attempt
    StandardDecode,
    /// Wavefront decode with batch size
    WavefrontDecode {
        batch_size: u8, // 1-20
    },
    /// Progressive decode (add symbols incrementally)
    ProgressiveDecode {
        batch_size: u8, // 1-10
    },
    /// Decode with proof generation
    DecodeWithProof,
    /// Validate corruption detection
    ValidateCorruption,
}

fuzz_target!(|scenario: SymbolCorruptionScenario| {
    // Limit complexity for fuzzer performance
    if scenario.corruption_targets.len() > 50 {
        return;
    }
    if scenario.decode_operations.len() > 10 {
        return;
    }

    // Test decoder robustness under symbol corruption
    test_decoder_symbol_corruption(&scenario);

    // Test corruption detection accuracy
    test_corruption_detection(&scenario);

    // Test error propagation patterns
    test_error_propagation(&scenario);
});

fn test_decoder_symbol_corruption(scenario: &SymbolCorruptionScenario) {
    let k = scenario.source_config.k.as_usize();
    let symbol_size = scenario.source_config.symbol_size.as_usize();
    let seed = scenario.source_config.seed;

    // Create decoder
    let decoder = match InactivationDecoder::try_new(k, symbol_size, seed) {
        Ok(d) => d,
        Err(_) => return, // Invalid parameters
    };

    // Generate clean symbols
    let mut symbols = generate_clean_symbols(k, symbol_size, &decoder);

    // Apply corruption to targeted symbols
    apply_corruptions(&mut symbols, &scenario.corruption_targets, k, symbol_size);

    // Test decode operations with corrupted symbols
    for operation in &scenario.decode_operations {
        test_decode_operation(&decoder, &symbols, operation);
    }
}

fn test_corruption_detection(scenario: &SymbolCorruptionScenario) {
    let k = scenario.source_config.k.as_usize();
    let symbol_size = scenario.source_config.symbol_size.as_usize();
    let seed = scenario.source_config.seed;

    let decoder = match InactivationDecoder::try_new(k, symbol_size, seed) {
        Ok(d) => d,
        Err(_) => return,
    };

    // Generate symbols and apply controlled corruption
    let mut clean_symbols = generate_clean_symbols(k, symbol_size, &decoder);
    let mut corrupted_symbols = clean_symbols.clone();

    // Apply single controlled corruption
    if let Some(target) = scenario.corruption_targets.first() {
        apply_single_corruption(&mut corrupted_symbols, target, k, symbol_size);

        // Compare decode results
        let clean_result = decoder.decode(&clean_symbols);
        let corrupted_result = decoder.decode(&corrupted_symbols);

        match (&clean_result, &corrupted_result) {
            (Ok(_), Err(DecodeError::CorruptDecodedOutput { .. })) => {
                // Corruption was detected correctly
            }
            (Ok(_), Ok(_)) => {
                // Corruption was not detected or was correctable
            }
            (Ok(_), Err(_)) => {
                // Other decode error due to corruption
            }
            (Err(_), _) => {
                // Clean decode failed - invalid test case
            }
        }
    }
}

fn test_error_propagation(scenario: &SymbolCorruptionScenario) {
    let k = scenario.source_config.k.as_usize();
    let symbol_size = scenario.source_config.symbol_size.as_usize();
    let seed = scenario.source_config.seed;

    let decoder = match InactivationDecoder::try_new(k, symbol_size, seed) {
        Ok(d) => d,
        Err(_) => return,
    };

    // Test how errors propagate through different corruption patterns
    let symbols = generate_clean_symbols(k, symbol_size, &decoder);

    for target in &scenario.corruption_targets {
        let mut test_symbols = symbols.clone();
        apply_single_corruption(&mut test_symbols, target, k, symbol_size);

        // Test decode and observe error propagation
        let result = decoder.decode(&test_symbols);

        // Categorize the type of error caused by corruption
        match result {
            Ok(_) => {
                // No error or correctable corruption
            }
            Err(DecodeError::CorruptDecodedOutput { .. }) => {
                // Output corruption detected
            }
            Err(DecodeError::SingularMatrix { .. }) => {
                // Corruption caused matrix singularity
            }
            Err(DecodeError::InsufficientSymbols { .. }) => {
                // Corruption reduced effective symbol count
            }
            Err(_) => {
                // Other error types
            }
        }
    }
}

fn generate_clean_symbols(k: usize, symbol_size: usize, decoder: &InactivationDecoder) -> Vec<ReceivedSymbol> {
    let mut symbols = Vec::new();

    // Generate source symbols
    for esi in 0..k {
        let data = generate_symbol_data(esi as u32, symbol_size);
        symbols.push(ReceivedSymbol {
            esi: esi as u32,
            is_source: true,
            columns: vec![esi],
            coefficients: vec![Gf256::from(1)],
            data,
        });
    }

    // Add some repair symbols
    let repair_count = (k / 4).max(2).min(20); // 25% overhead, capped at 20
    for i in 0..repair_count {
        let esi = (k as u32) + (i as u32);

        // Get repair equation from decoder
        if let Ok((columns, coefficients)) = decoder.repair_equation(esi) {
            let data = generate_symbol_data(esi, symbol_size);
            symbols.push(ReceivedSymbol {
                esi,
                is_source: false,
                columns,
                coefficients,
                data,
            });
        }
    }

    // Add constraint symbols
    let constraint_symbols = decoder.constraint_symbols();
    symbols.extend(constraint_symbols);

    symbols
}

fn generate_symbol_data(seed: u32, size: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(size);
    let mut state = seed;

    for _ in 0..size {
        state = state.wrapping_mul(1664525).wrapping_add(1013904223);
        data.push((state >> 24) as u8);
    }

    data
}

fn apply_corruptions(
    symbols: &mut [ReceivedSymbol],
    targets: &[CorruptionTarget],
    k: usize,
    symbol_size: usize,
) {
    for target in targets {
        apply_single_corruption(symbols, target, k, symbol_size);
    }
}

fn apply_single_corruption(
    symbols: &mut [ReceivedSymbol],
    target: &CorruptionTarget,
    k: usize,
    _symbol_size: usize,
) {
    // Find target symbol
    let symbol_index = match &target.target {
        SymbolTarget::Source { esi } => {
            symbols.iter().position(|s| s.is_source && s.esi == *esi)
        }
        SymbolTarget::Repair { esi } => {
            symbols.iter().position(|s| !s.is_source && s.esi == *esi)
        }
        SymbolTarget::Systematic { index } => {
            let target_esi = (*index as usize) % k;
            symbols.iter().position(|s| s.is_source && s.esi == target_esi as u32)
        }
        SymbolTarget::Constraint { constraint_index } => {
            // Find constraint symbol (heuristic: non-source symbols beyond k+20)
            let min_constraint_esi = (k as u32) + 20;
            symbols.iter().position(|s| !s.is_source && s.esi >= min_constraint_esi)
                .map(|i| i + (*constraint_index as usize) % 5) // Approximate constraint selection
        }
    };

    if let Some(idx) = symbol_index {
        if idx < symbols.len() {
            apply_corruption_type(&mut symbols[idx], &target.corruption_type);
        }
    }
}

fn apply_corruption_type(symbol: &mut ReceivedSymbol, corruption_type: &CorruptionType) {
    match corruption_type {
        CorruptionType::DataCorruption { corruption_pattern } => {
            apply_data_corruption(&mut symbol.data, corruption_pattern);
        }
        CorruptionType::CoefficientCorruption { coefficient_pattern } => {
            apply_coefficient_corruption(&mut symbol.coefficients, coefficient_pattern);
        }
        CorruptionType::ColumnCorruption { column_pattern } => {
            apply_column_corruption(&mut symbol.columns, column_pattern);
        }
        CorruptionType::Mixed { corruptions } => {
            for corruption in corruptions {
                apply_single_corruption_op(symbol, corruption);
            }
        }
    }
}

fn apply_data_corruption(data: &mut [u8], pattern: &DataCorruptionPattern) {
    match pattern {
        DataCorruptionPattern::BitFlip { byte_offset, bit_position } => {
            let idx = (*byte_offset as usize) % data.len();
            let bit = (*bit_position) % 8;
            data[idx] ^= 1 << bit;
        }
        DataCorruptionPattern::BurstError { start_offset, length } => {
            let start = (*start_offset as usize) % data.len();
            let len = (*length as usize).min(data.len() - start);
            for i in start..start + len {
                data[i] ^= 0xFF; // Flip all bits in burst
            }
        }
        DataCorruptionPattern::RandomCorruption { corruption_rate, seed } => {
            let rate = corruption_rate.as_f32();
            let mut state = *seed;
            for byte in data.iter_mut() {
                state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                if (state as f32 / u32::MAX as f32) < rate {
                    *byte ^= ((state >> 16) & 0xFF) as u8;
                }
            }
        }
        DataCorruptionPattern::ZeroOut { start_offset, length } => {
            let start = (*start_offset as usize) % data.len();
            let len = (*length as usize).min(data.len() - start);
            for i in start..start + len {
                data[i] = 0;
            }
        }
        DataCorruptionPattern::PatternCorruption { pattern } => {
            apply_corruption_pattern_to_data(data, *pattern);
        }
    }
}

fn apply_coefficient_corruption(coefficients: &mut [Gf256], pattern: &CoefficientCorruptionPattern) {
    match pattern {
        CoefficientCorruptionPattern::Single { index, new_value } => {
            let idx = (*index as usize) % coefficients.len();
            coefficients[idx] = Gf256::from(*new_value);
        }
        CoefficientCorruptionPattern::Multiple { corruptions } => {
            for corruption in corruptions {
                let idx = (corruption.index as usize) % coefficients.len();
                coefficients[idx] = Gf256::from(corruption.new_value);
            }
        }
        CoefficientCorruptionPattern::Uniform { value } => {
            for coeff in coefficients.iter_mut() {
                *coeff = Gf256::from(*value);
            }
        }
        CoefficientCorruptionPattern::Pattern { pattern } => {
            apply_corruption_pattern_to_coefficients(coefficients, *pattern);
        }
    }
}

fn apply_column_corruption(columns: &mut [usize], pattern: &ColumnCorruptionPattern) {
    match pattern {
        ColumnCorruptionPattern::Single { index, new_value } => {
            let idx = (*index as usize) % columns.len();
            columns[idx] = *new_value as usize;
        }
        ColumnCorruptionPattern::Multiple { corruptions } => {
            for corruption in corruptions {
                let idx = (corruption.index as usize) % columns.len();
                columns[idx] = corruption.new_value as usize;
            }
        }
        ColumnCorruptionPattern::OutOfRange { base_value } => {
            for (i, column) in columns.iter_mut().enumerate() {
                *column = (*base_value as usize) + i * 1000; // Large out-of-range values
            }
        }
        ColumnCorruptionPattern::Duplicate { target_index } => {
            for column in columns.iter_mut() {
                *column = *target_index as usize; // All columns point to same index
            }
        }
    }
}

fn apply_corruption_pattern_to_data(data: &mut [u8], pattern: CorruptionPattern) {
    match pattern {
        CorruptionPattern::Alternating => {
            for (i, byte) in data.iter_mut().enumerate() {
                *byte = if i % 2 == 0 { 0xAA } else { 0x55 };
            }
        }
        CorruptionPattern::AllOnes => {
            for byte in data.iter_mut() {
                *byte = 0xFF;
            }
        }
        CorruptionPattern::Incremental => {
            for (i, byte) in data.iter_mut().enumerate() {
                *byte = (i % 256) as u8;
            }
        }
        CorruptionPattern::Xor(value) => {
            for byte in data.iter_mut() {
                *byte ^= value;
            }
        }
    }
}

fn apply_corruption_pattern_to_coefficients(coefficients: &mut [Gf256], pattern: CorruptionPattern) {
    match pattern {
        CorruptionPattern::Alternating => {
            for (i, coeff) in coefficients.iter_mut().enumerate() {
                *coeff = Gf256::from(if i % 2 == 0 { 0xAA } else { 0x55 });
            }
        }
        CorruptionPattern::AllOnes => {
            for coeff in coefficients.iter_mut() {
                *coeff = Gf256::from(0xFF);
            }
        }
        CorruptionPattern::Incremental => {
            for (i, coeff) in coefficients.iter_mut().enumerate() {
                *coeff = Gf256::from((i % 256) as u8);
            }
        }
        CorruptionPattern::Xor(value) => {
            for coeff in coefficients.iter_mut() {
                let current_val = u8::from(*coeff);
                *coeff = Gf256::from(current_val ^ value);
            }
        }
    }
}

fn apply_single_corruption_op(symbol: &mut ReceivedSymbol, corruption: &SingleCorruption) {
    match corruption {
        SingleCorruption::FlipBit { byte_index, bit_index } => {
            let idx = (*byte_index as usize) % symbol.data.len();
            let bit = (*bit_index) % 8;
            symbol.data[idx] ^= 1 << bit;
        }
        SingleCorruption::ZeroBytes { start, len } => {
            let start_idx = (*start as usize) % symbol.data.len();
            let end_idx = (start_idx + (*len as usize)).min(symbol.data.len());
            for i in start_idx..end_idx {
                symbol.data[i] = 0;
            }
        }
        SingleCorruption::RandomizeBytes { start, len, seed } => {
            let start_idx = (*start as usize) % symbol.data.len();
            let end_idx = (start_idx + (*len as usize)).min(symbol.data.len());
            let mut state = *seed;
            for i in start_idx..end_idx {
                state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                symbol.data[i] = (state >> 24) as u8;
            }
        }
        SingleCorruption::CorruptCoefficient { coeff_index, new_value } => {
            if !symbol.coefficients.is_empty() {
                let idx = (*coeff_index as usize) % symbol.coefficients.len();
                symbol.coefficients[idx] = Gf256::from(*new_value);
            }
        }
        SingleCorruption::CorruptColumn { column_index, new_value } => {
            if !symbol.columns.is_empty() {
                let idx = (*column_index as usize) % symbol.columns.len();
                symbol.columns[idx] = *new_value as usize;
            }
        }
    }
}

fn test_decode_operation(
    decoder: &InactivationDecoder,
    symbols: &[ReceivedSymbol],
    operation: &DecodeOperation,
) {
    match operation {
        DecodeOperation::StandardDecode => {
            let _result = decoder.decode(symbols);
            // Don't assert on result - corruption may cause legitimate failures
        }
        DecodeOperation::WavefrontDecode { batch_size } => {
            let batch = (*batch_size as usize).max(1).min(20);
            let _result = decoder.decode_wavefront(symbols, batch);
        }
        DecodeOperation::ProgressiveDecode { batch_size } => {
            let batch = (*batch_size as usize).max(1).min(symbols.len());
            for chunk_end in (batch..=symbols.len()).step_by(batch) {
                let _result = decoder.decode(&symbols[..chunk_end]);
            }
        }
        DecodeOperation::DecodeWithProof => {
            let _result = decoder.decode_with_proof(symbols);
        }
        DecodeOperation::ValidateCorruption => {
            // Just ensure decoder doesn't crash on corrupted input
            let _result = decoder.decode(symbols);
        }
    }
}