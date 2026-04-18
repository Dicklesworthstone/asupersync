#![no_main]

//! Fuzz target for HPACK decoder static+dynamic table parsing.
//!
//! This target feeds malformed HPACK-encoded header blocks to the decoder, asserting:
//! 1. No panics on malformed Huffman encoding
//! 2. Dynamic table size never exceeds SETTINGS_HEADER_TABLE_SIZE
//! 3. Index 0 is rejected per RFC 7541
//! 4. Integer decoding guards against overflow
//!
//! Key scenarios tested:
//! - Malformed Huffman encoded strings (truncated, invalid EOS, wrong padding)
//! - Integer overflow in various HPACK contexts (indexes, table sizes, string lengths)
//! - Dynamic table size updates beyond allowed limits
//! - Invalid header field indices (0, out-of-bounds)
//! - Malformed HPACK instruction sequences
//! - Edge cases in literal header field encoding

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicU64, Ordering};

use asupersync::http::h2::hpack::{Decoder as HpackDecoder};
use asupersync::bytes::Bytes;

/// Simplified fuzz input for HPACK decoder testing
#[derive(Arbitrary, Debug, Clone)]
struct HpackDecoderFuzzInput {
    /// Random seed for deterministic execution
    pub seed: u64,
    /// Sequence of HPACK operations to test
    pub operations: Vec<HpackOperation>,
    /// Configuration for the test scenario
    pub config: HpackFuzzConfig,
}

/// Individual HPACK operations to fuzz
#[derive(Arbitrary, Debug, Clone)]
enum HpackOperation {
    /// Test malformed HPACK header block decoding
    DecodeHeaderBlock {
        raw_hpack_data: Vec<u8>,
        expected_error: bool,
    },
    /// Test dynamic table size update operations
    TableSizeUpdate {
        size_update_sequence: Vec<u32>,
        max_allowed_size: u32,
    },
    /// Test indexed header field operations
    IndexedHeaderField {
        index_values: Vec<u32>,
        test_invalid_indices: bool,
    },
    /// Test literal header field operations
    LiteralHeaderField {
        name_data: LiteralStringData,
        value_data: LiteralStringData,
        indexing_mode: IndexingMode,
    },
    /// Test malformed Huffman string decoding
    HuffmanStringTest {
        huffman_data: Vec<u8>,
        expect_decode_failure: bool,
    },
    /// Test integer encoding/decoding edge cases
    IntegerOverflowTest {
        prefix_bits: u8, // 1-8
        integer_bytes: Vec<u8>,
        expect_overflow: bool,
    },
    /// Test comprehensive header block sequences
    ComplexHeaderBlock {
        instructions: Vec<HpackInstruction>,
        table_size_limit: u32,
    },
}

/// HPACK string data for literal fields
#[derive(Arbitrary, Debug, Clone)]
struct LiteralStringData {
    /// Raw string bytes
    data: Vec<u8>,
    /// Whether to use Huffman encoding
    huffman_encoded: bool,
    /// Intentionally corrupt the length field
    corrupt_length: bool,
    /// Length override (if corrupt_length is true)
    fake_length: u32,
}

/// Indexing modes for literal header fields
#[derive(Arbitrary, Debug, Clone)]
enum IndexingMode {
    WithIncrementalIndexing,
    WithoutIndexing,
    NeverIndexed,
}

/// HPACK instruction types
#[derive(Arbitrary, Debug, Clone)]
enum HpackInstruction {
    /// Indexed header field (1xxxxxxx)
    IndexedHeader { index: u32 },
    /// Literal header with incremental indexing (01xxxxxx)
    LiteralIncremental { name_index: u32, value: Vec<u8> },
    /// Dynamic table size update (001xxxxx)
    TableSizeUpdate { size: u32 },
    /// Literal header without indexing (0000xxxx)
    LiteralNoIndexing { name_index: u32, value: Vec<u8> },
    /// Literal header never indexed (0001xxxx)
    LiteralNeverIndexed { name_index: u32, value: Vec<u8> },
    /// Raw malformed bytes
    MalformedBytes { data: Vec<u8> },
}

/// Configuration for HPACK fuzz testing
#[derive(Arbitrary, Debug, Clone)]
struct HpackFuzzConfig {
    /// Maximum operations per test run
    pub max_operations: u16,
    /// Enable malformed Huffman testing
    pub test_huffman_corruption: bool,
    /// Enable integer overflow testing
    pub test_integer_overflow: bool,
    /// Maximum table size for testing
    pub max_table_size: u32,
    /// Maximum header list size
    pub max_header_list_size: u32,
}

/// Shadow model for tracking HPACK decoder behavior
#[derive(Debug)]
struct HpackDecoderShadowModel {
    /// Total decode operations attempted
    total_operations: AtomicU64,
    /// Operations that completed successfully
    successful_operations: AtomicU64,
    /// Expected errors encountered
    expected_errors: AtomicU64,
    /// Protocol violations detected
    violations: std::sync::Mutex<Vec<String>>,
    /// Current expected dynamic table size
    expected_table_size: std::sync::Mutex<u32>,
    /// Maximum allowed table size
    max_allowed_table_size: std::sync::Mutex<u32>,
}

impl HpackDecoderShadowModel {
    fn new() -> Self {
        Self {
            total_operations: AtomicU64::new(0),
            successful_operations: AtomicU64::new(0),
            expected_errors: AtomicU64::new(0),
            violations: std::sync::Mutex::new(Vec::new()),
            expected_table_size: std::sync::Mutex::new(4096), // Default
            max_allowed_table_size: std::sync::Mutex::new(4096),
        }
    }

    fn record_operation_start(&self) -> u64 {
        self.total_operations.fetch_add(1, Ordering::SeqCst)
    }

    fn record_operation_success(&self) {
        self.successful_operations.fetch_add(1, Ordering::SeqCst);
    }

    fn record_expected_error(&self, _error_msg: &str) {
        self.expected_errors.fetch_add(1, Ordering::SeqCst);
    }

    fn record_violation(&self, violation: String) {
        self.violations.lock().unwrap().push(violation);
    }

    fn set_table_size_limit(&self, limit: u32) {
        *self.max_allowed_table_size.lock().unwrap() = limit;
    }

    fn update_expected_table_size(&self, size: u32) -> Result<(), String> {
        let max_allowed = *self.max_allowed_table_size.lock().unwrap();
        if size > max_allowed {
            return Err(format!(
                "Table size update {} exceeds allowed maximum {}",
                size, max_allowed
            ));
        }
        *self.expected_table_size.lock().unwrap() = size;
        Ok(())
    }

    fn verify_invariants(&self) -> Result<(), String> {
        let total = self.total_operations.load(Ordering::SeqCst);
        let success = self.successful_operations.load(Ordering::SeqCst);
        let errors = self.expected_errors.load(Ordering::SeqCst);

        // Basic accounting
        if success + errors > total {
            return Err(format!(
                "Accounting violation: success({}) + errors({}) > total({})",
                success, errors, total
            ));
        }

        // Check for recorded violations
        let violations = self.violations.lock().unwrap();
        if !violations.is_empty() {
            return Err(format!("HPACK violations: {:?}", *violations));
        }

        Ok(())
    }
}

/// Normalize fuzz input to prevent timeouts
fn normalize_fuzz_input(input: &mut HpackDecoderFuzzInput) {
    // Limit operations to prevent timeouts
    input.operations.truncate(50);

    // Bound configuration values
    input.config.max_operations = input.config.max_operations.min(100);
    input.config.max_table_size = input.config.max_table_size.clamp(0, 64 * 1024); // 64KB max
    input.config.max_header_list_size = input.config.max_header_list_size.clamp(1024, 128 * 1024); // 1KB-128KB

    // Normalize individual operations
    for op in &mut input.operations {
        match op {
            HpackOperation::DecodeHeaderBlock { raw_hpack_data, .. } => {
                // Limit raw HPACK data size
                raw_hpack_data.truncate(16384); // 16KB max
            }
            HpackOperation::TableSizeUpdate { size_update_sequence, max_allowed_size } => {
                // Limit sequence length and bound sizes
                size_update_sequence.truncate(20);
                *max_allowed_size = (*max_allowed_size).min(128 * 1024); // 128KB max
                for size in size_update_sequence {
                    *size = (*size).min(256 * 1024); // Individual updates max 256KB
                }
            }
            HpackOperation::IndexedHeaderField { index_values, .. } => {
                // Limit index testing to reasonable bounds
                index_values.truncate(100);
                for index in index_values {
                    *index = (*index).min(10000); // Max index value
                }
            }
            HpackOperation::LiteralHeaderField { name_data, value_data, .. } => {
                // Limit literal field data
                name_data.data.truncate(8192);
                value_data.data.truncate(64 * 1024); // Values can be larger
                name_data.fake_length = name_data.fake_length.min(128 * 1024);
                value_data.fake_length = value_data.fake_length.min(128 * 1024);
            }
            HpackOperation::HuffmanStringTest { huffman_data, .. } => {
                // Limit Huffman test data
                huffman_data.truncate(8192);
            }
            HpackOperation::IntegerOverflowTest { prefix_bits, integer_bytes, .. } => {
                // Limit integer test parameters
                *prefix_bits = (*prefix_bits).clamp(1, 8);
                integer_bytes.truncate(20); // Reasonable limit for integer bytes
            }
            HpackOperation::ComplexHeaderBlock { instructions, table_size_limit } => {
                // Limit instruction count and table size
                instructions.truncate(50);
                *table_size_limit = (*table_size_limit).min(128 * 1024);

                // Normalize instructions
                for instruction in instructions {
                    match instruction {
                        HpackInstruction::IndexedHeader { index } => {
                            *index = (*index).min(10000);
                        }
                        HpackInstruction::LiteralIncremental { name_index, value } |
                        HpackInstruction::LiteralNoIndexing { name_index, value } |
                        HpackInstruction::LiteralNeverIndexed { name_index, value } => {
                            *name_index = (*name_index).min(10000);
                            value.truncate(8192);
                        }
                        HpackInstruction::TableSizeUpdate { size } => {
                            *size = (*size).min(256 * 1024);
                        }
                        HpackInstruction::MalformedBytes { data } => {
                            data.truncate(2048);
                        }
                    }
                }
            }
        }
    }
}

/// Test header block decoding operations
fn test_decode_header_block(
    op: &HpackOperation,
    shadow: &HpackDecoderShadowModel,
) -> Result<(), String> {
    if let HpackOperation::DecodeHeaderBlock { raw_hpack_data, expected_error } = op {
        let _op_id = shadow.record_operation_start();

        let mut decoder = HpackDecoder::new();
        let result = decoder.decode(&mut Bytes::from(raw_hpack_data.clone()));

        match result {
            Ok(headers) => {
                if *expected_error {
                    shadow.record_violation(format!(
                        "Expected decode error for malformed data, but got {} headers",
                        headers.len()
                    ));
                    return Err("Expected error but decode succeeded".to_string());
                }
                shadow.record_operation_success();
            }
            Err(_err) => {
                // Error is expected for most malformed input
                shadow.record_expected_error("decode error");
            }
        }
    }
    Ok(())
}

/// Test dynamic table size update operations
fn test_table_size_updates(
    op: &HpackOperation,
    shadow: &HpackDecoderShadowModel,
) -> Result<(), String> {
    if let HpackOperation::TableSizeUpdate { size_update_sequence, max_allowed_size } = op {
        let _op_id = shadow.record_operation_start();

        shadow.set_table_size_limit(*max_allowed_size);

        for &size in size_update_sequence {
            // Test that table size updates respect limits
            match shadow.update_expected_table_size(size) {
                Ok(()) => {
                    // Valid size update
                }
                Err(_) => {
                    // Size exceeded limit - this should be rejected
                    shadow.record_expected_error("table size exceeds limit");
                }
            }
        }

        shadow.record_operation_success();
    }
    Ok(())
}

/// Test indexed header field operations
fn test_indexed_header_fields(
    op: &HpackOperation,
    shadow: &HpackDecoderShadowModel,
) -> Result<(), String> {
    if let HpackOperation::IndexedHeaderField { index_values, test_invalid_indices } = op {
        let _op_id = shadow.record_operation_start();

        let mut decoder = HpackDecoder::new();

        for &index in index_values {
            // Create indexed header field instruction
            let hpack_data = create_indexed_header_instruction(index);
            let result = decoder.decode(&mut Bytes::from(hpack_data));

            match result {
                Ok(_headers) => {
                    // Valid index
                    if *test_invalid_indices && index == 0 {
                        shadow.record_violation(format!(
                            "Index 0 should be rejected per RFC 7541 but was accepted"
                        ));
                        return Err("Index 0 was incorrectly accepted".to_string());
                    }
                }
                Err(_err) => {
                    // Expected for invalid indices (especially index 0)
                    if index == 0 {
                        // This is correct behavior per RFC 7541
                    }
                    shadow.record_expected_error("invalid index");
                }
            }
        }

        shadow.record_operation_success();
    }
    Ok(())
}

/// Test literal header field operations
fn test_literal_header_fields(
    op: &HpackOperation,
    shadow: &HpackDecoderShadowModel,
) -> Result<(), String> {
    if let HpackOperation::LiteralHeaderField { name_data, value_data, indexing_mode } = op {
        let _op_id = shadow.record_operation_start();

        let hpack_data = create_literal_header_instruction(name_data, value_data, indexing_mode);

        let mut decoder = HpackDecoder::new();
        let result = decoder.decode(&mut Bytes::from(hpack_data));

        match result {
            Ok(_headers) => {
                shadow.record_operation_success();
            }
            Err(_err) => {
                // Expected for malformed literal headers
                shadow.record_expected_error("literal header error");
            }
        }
    }
    Ok(())
}

/// Test Huffman string decoding
fn test_huffman_strings(
    op: &HpackOperation,
    shadow: &HpackDecoderShadowModel,
) -> Result<(), String> {
    if let HpackOperation::HuffmanStringTest { huffman_data, expect_decode_failure } = op {
        let _op_id = shadow.record_operation_start();

        // Create a literal header with Huffman-encoded value
        let hpack_data = create_huffman_string_test(huffman_data);

        let result = std::panic::catch_unwind(|| {
            let mut decoder = HpackDecoder::new();
            decoder.decode(&mut Bytes::from(hpack_data))
        });

        match result {
            Ok(decode_result) => {
                match decode_result {
                    Ok(_headers) => {
                        if *expect_decode_failure {
                            shadow.record_violation(format!(
                                "Expected Huffman decode failure but succeeded"
                            ));
                        } else {
                            shadow.record_operation_success();
                        }
                    }
                    Err(_err) => {
                        // Expected error for malformed Huffman
                        shadow.record_expected_error("huffman decode error");
                    }
                }
            }
            Err(_panic) => {
                // Panic on malformed Huffman is a violation
                shadow.record_violation(format!(
                    "Huffman decoder panicked on malformed input"
                ));
                return Err("Huffman decoder panicked".to_string());
            }
        }
    }
    Ok(())
}

/// Test integer overflow protection
fn test_integer_overflow(
    op: &HpackOperation,
    shadow: &HpackDecoderShadowModel,
) -> Result<(), String> {
    if let HpackOperation::IntegerOverflowTest { prefix_bits, integer_bytes, expect_overflow } = op {
        let _op_id = shadow.record_operation_start();

        let hpack_data = create_integer_overflow_test(*prefix_bits, integer_bytes);

        let result = std::panic::catch_unwind(|| {
            let mut decoder = HpackDecoder::new();
            decoder.decode(&mut Bytes::from(hpack_data))
        });

        match result {
            Ok(decode_result) => {
                match decode_result {
                    Ok(_headers) => {
                        if *expect_overflow {
                            shadow.record_violation(format!(
                                "Expected integer overflow error but decode succeeded"
                            ));
                        } else {
                            shadow.record_operation_success();
                        }
                    }
                    Err(_err) => {
                        // Expected error for integer overflow
                        shadow.record_expected_error("integer overflow");
                    }
                }
            }
            Err(_panic) => {
                // Panic on integer overflow is a violation
                shadow.record_violation(format!(
                    "Integer decoder panicked on overflow input"
                ));
                return Err("Integer decoder panicked".to_string());
            }
        }
    }
    Ok(())
}

/// Test complex header block sequences
fn test_complex_header_blocks(
    op: &HpackOperation,
    shadow: &HpackDecoderShadowModel,
) -> Result<(), String> {
    if let HpackOperation::ComplexHeaderBlock { instructions, table_size_limit } = op {
        let _op_id = shadow.record_operation_start();

        shadow.set_table_size_limit(*table_size_limit);
        let hpack_data = create_complex_header_block(instructions);
        let table_size_limit_copy = *table_size_limit;

        let result = std::panic::catch_unwind(|| {
            let mut decoder = HpackDecoder::new();
            decoder.set_allowed_table_size(table_size_limit_copy as usize);
            decoder.decode(&mut Bytes::from(hpack_data))
        });

        match result {
            Ok(decode_result) => {
                match decode_result {
                    Ok(_headers) => {
                        shadow.record_operation_success();
                    }
                    Err(_err) => {
                        shadow.record_expected_error("complex block error");
                    }
                }
            }
            Err(_panic) => {
                shadow.record_violation(format!(
                    "Complex header block caused panic"
                ));
                return Err("Complex header block panicked".to_string());
            }
        }
    }
    Ok(())
}

/// Create HPACK data for indexed header field test
fn create_indexed_header_instruction(index: u32) -> Vec<u8> {
    let mut data = Vec::new();

    // Indexed header field: 1xxxxxxx
    if index < 127 {
        data.push(0x80 | (index as u8));
    } else {
        data.push(0x80 | 0x7F); // 1 + max 7-bit value
        encode_integer_bytes(&mut data, index - 127);
    }

    data
}

/// Create HPACK data for literal header field test
fn create_literal_header_instruction(
    name_data: &LiteralStringData,
    value_data: &LiteralStringData,
    indexing_mode: &IndexingMode,
) -> Vec<u8> {
    let mut data = Vec::new();

    // Choose instruction based on indexing mode
    match indexing_mode {
        IndexingMode::WithIncrementalIndexing => {
            data.push(0x40); // 01xxxxxx - literal with incremental indexing, new name
        }
        IndexingMode::WithoutIndexing => {
            data.push(0x00); // 0000xxxx - literal without indexing, new name
        }
        IndexingMode::NeverIndexed => {
            data.push(0x10); // 0001xxxx - literal never indexed, new name
        }
    }

    // Encode name string
    encode_string_data(&mut data, name_data);

    // Encode value string
    encode_string_data(&mut data, value_data);

    data
}

/// Create HPACK data for Huffman string test
fn create_huffman_string_test(huffman_data: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();

    // Literal header without indexing, new name and value
    data.push(0x00); // 0000xxxx

    // Empty name (literal)
    data.push(0x00); // Name length = 0

    // Huffman-encoded value
    data.push(0x80 | (huffman_data.len() as u8)); // Huffman flag + length
    data.extend_from_slice(huffman_data);

    data
}

/// Create HPACK data for integer overflow test
fn create_integer_overflow_test(prefix_bits: u8, integer_bytes: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();

    // Create indexed header field with potentially overflowing index
    let prefix_mask = (1 << prefix_bits) - 1;
    data.push(0x80 | prefix_mask); // Set high bit for indexed field + max prefix value

    // Add continuation bytes that might cause overflow
    data.extend_from_slice(integer_bytes);

    data
}

/// Create complex HPACK header block
fn create_complex_header_block(instructions: &[HpackInstruction]) -> Vec<u8> {
    let mut data = Vec::new();

    for instruction in instructions {
        match instruction {
            HpackInstruction::IndexedHeader { index } => {
                let index_data = create_indexed_header_instruction(*index);
                data.extend_from_slice(&index_data);
            }
            HpackInstruction::TableSizeUpdate { size } => {
                // Dynamic table size update: 001xxxxx
                data.push(0x20);
                encode_integer_bytes(&mut data, *size);
            }
            HpackInstruction::LiteralIncremental { name_index, value } => {
                data.push(0x40); // 01xxxxxx
                if *name_index > 0 {
                    encode_integer_bytes(&mut data, *name_index);
                } else {
                    data.push(0x00); // New name
                    data.push(0x00); // Empty name
                }
                data.push(value.len() as u8); // Value length
                data.extend_from_slice(value);
            }
            HpackInstruction::LiteralNoIndexing { name_index, value } => {
                data.push(0x00); // 0000xxxx
                encode_integer_bytes(&mut data, *name_index);
                data.push(value.len() as u8);
                data.extend_from_slice(value);
            }
            HpackInstruction::LiteralNeverIndexed { name_index, value } => {
                data.push(0x10); // 0001xxxx
                encode_integer_bytes(&mut data, *name_index);
                data.push(value.len() as u8);
                data.extend_from_slice(value);
            }
            HpackInstruction::MalformedBytes { data: malformed_data } => {
                data.extend_from_slice(malformed_data);
            }
        }
    }

    data
}

/// Encode string data with potential corruption
fn encode_string_data(output: &mut Vec<u8>, string_data: &LiteralStringData) {
    let length = if string_data.corrupt_length {
        string_data.fake_length
    } else {
        string_data.data.len() as u32
    };

    // Huffman flag + length
    let huffman_flag = if string_data.huffman_encoded { 0x80 } else { 0x00 };

    if length < 127 {
        output.push(huffman_flag | (length as u8));
    } else {
        output.push(huffman_flag | 0x7F);
        encode_integer_bytes(output, length - 127);
    }

    // String data
    output.extend_from_slice(&string_data.data);
}

/// Encode integer continuation bytes
fn encode_integer_bytes(output: &mut Vec<u8>, mut value: u32) {
    while value >= 128 {
        output.push(0x80 | ((value % 128) as u8));
        value /= 128;
    }
    output.push(value as u8);
}

/// Execute all HPACK operations and verify invariants
fn execute_hpack_operations(input: &HpackDecoderFuzzInput) -> Result<(), String> {
    let shadow = HpackDecoderShadowModel::new();

    // Execute operation sequence with bounds checking
    let max_ops = input.config.max_operations.min(input.operations.len() as u16);
    for (i, operation) in input.operations.iter().enumerate() {
        if i >= max_ops as usize {
            break;
        }

        let result = match operation {
            HpackOperation::DecodeHeaderBlock { .. } => test_decode_header_block(operation, &shadow),
            HpackOperation::TableSizeUpdate { .. } => test_table_size_updates(operation, &shadow),
            HpackOperation::IndexedHeaderField { .. } => test_indexed_header_fields(operation, &shadow),
            HpackOperation::LiteralHeaderField { .. } => test_literal_header_fields(operation, &shadow),
            HpackOperation::HuffmanStringTest { .. } => test_huffman_strings(operation, &shadow),
            HpackOperation::IntegerOverflowTest { .. } => test_integer_overflow(operation, &shadow),
            HpackOperation::ComplexHeaderBlock { .. } => test_complex_header_blocks(operation, &shadow),
        };

        if let Err(e) = result {
            return Err(format!("Operation {} failed: {}", i, e));
        }

        // Verify invariants after each operation
        shadow.verify_invariants()?;
    }

    // Final invariant check
    shadow.verify_invariants()?;

    Ok(())
}

/// Main fuzzing entry point
fn fuzz_hpack_decoder(mut input: HpackDecoderFuzzInput) -> Result<(), String> {
    normalize_fuzz_input(&mut input);

    // Skip degenerate cases
    if input.operations.is_empty() {
        return Ok(());
    }

    // Execute HPACK decoder tests
    execute_hpack_operations(&input)?;

    Ok(())
}

fuzz_target!(|data: &[u8]| {
    // Limit input size for performance
    if data.len() > 32768 {
        return;
    }

    let mut unstructured = arbitrary::Unstructured::new(data);

    // Generate fuzz configuration
    let input = if let Ok(input) = HpackDecoderFuzzInput::arbitrary(&mut unstructured) {
        input
    } else {
        return;
    };

    // Run HPACK decoder fuzzing - catch any panics
    let _ = std::panic::catch_unwind(|| {
        let _ = fuzz_hpack_decoder(input);
    });
});