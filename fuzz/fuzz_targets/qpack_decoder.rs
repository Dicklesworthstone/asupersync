#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::http::h3_native::{
    H3NativeError, H3QpackMode, QpackFieldPlan, qpack_decode_field_section,
    qpack_decode_request_field_section, qpack_decode_response_field_section,
    qpack_encode_field_section,
};

/// Fuzz input for QPACK decoder testing
#[derive(Arbitrary, Debug)]
struct QpackFuzzInput {
    /// Raw QPACK field section bytes to decode
    field_section: Vec<u8>,
    /// QPACK mode for decoder context
    qpack_mode: FuzzQpackMode,
    /// Which decoder function to test
    decoder_type: DecoderType,
    /// Specific attack scenarios to test
    attack_scenario: AttackScenario,
}

#[derive(Arbitrary, Debug, Clone)]
enum FuzzQpackMode {
    StaticOnly,
    DynamicTableAllowed,
}

impl From<FuzzQpackMode> for H3QpackMode {
    fn from(mode: FuzzQpackMode) -> Self {
        match mode {
            FuzzQpackMode::StaticOnly => H3QpackMode::StaticOnly,
            FuzzQpackMode::DynamicTableAllowed => H3QpackMode::DynamicTableAllowed,
        }
    }
}

#[derive(Arbitrary, Debug, Clone)]
enum DecoderType {
    /// Test generic field section decoder
    FieldSection,
    /// Test request-specific decoder (with pseudo-header validation)
    RequestSpecific,
    /// Test response-specific decoder (with status validation)
    ResponseSpecific,
}

#[derive(Arbitrary, Debug, Clone)]
enum AttackScenario {
    /// Valid field section (baseline)
    Valid,
    /// Invalid static table index (should be rejected gracefully)
    InvalidStaticIndex { index: u64 },
    /// Required insert count attack (test stall handling)
    RequiredInsertCount { count: u64 },
    /// Delta base manipulation
    DeltaBase { delta: u64 },
    /// Huffman string overflow attempt
    HuffmanOverflow {
        prefix_bits: u8,
        string_data: Vec<u8>,
    },
    /// Prefixed integer overflow
    IntegerOverflow {
        prefix_len: u8,
        overflow_bytes: Vec<u8>,
    },
    /// Dynamic table size changes
    DynamicTableResize { size: u64 },
    /// Malformed field patterns
    MalformedField { pattern_type: MalformedPattern },
}

#[derive(Arbitrary, Debug, Clone)]
enum MalformedPattern {
    /// Truncated field section
    Truncated { at_byte: usize },
    /// Invalid field line pattern
    InvalidPattern { pattern: u8 },
    /// String length overflow
    StringLengthOverflow { claimed_length: u64 },
    /// Invalid UTF-8 in string
    InvalidUtf8 { bytes: Vec<u8> },
}

fuzz_target!(|input: QpackFuzzInput| {
    // Property 1: No panic on any input
    test_no_panic(&input);

    // Property 2: Invalid static table index rejected gracefully
    test_invalid_static_index(&input);

    // Property 3: Dynamic table size change respected
    test_dynamic_table_size(&input);

    // Property 4: Delta base manipulation completes cleanly
    test_delta_base(&input);

    // Property 5: Huffman-encoded strings decode without overflow
    test_huffman_string_safety(&input);

    // Property 6: Prefixed integer overflows are rejected gracefully
    test_integer_overflow(&input);

    // Property 7: Required insert count stall handled cleanly
    test_required_insert_count_stall(&input);

    // Additional: Test malformed patterns
    test_malformed_patterns(&input);

    // Additional: Test realistic scenarios
    test_realistic_scenarios();
});

/// Property 1: No panic on any input - decoder should handle all malformed inputs gracefully
fn test_no_panic(input: &QpackFuzzInput) {
    let mode = input.qpack_mode.clone().into();

    // Test should never panic, only return errors
    let result = std::panic::catch_unwind(|| -> Result<(), H3NativeError> {
        match &input.decoder_type {
            DecoderType::FieldSection => {
                qpack_decode_field_section(&input.field_section, mode).map(|_| ())
            }
            DecoderType::RequestSpecific => {
                qpack_decode_request_field_section(&input.field_section, mode, None).map(|_| ())
            }
            DecoderType::ResponseSpecific => {
                qpack_decode_response_field_section(&input.field_section, mode, None).map(|_| ())
            }
        }
    });

    assert!(
        result.is_ok(),
        "QPACK {:?} decoder panicked for {} bytes",
        input.decoder_type,
        input.field_section.len()
    );
}

/// Property 2: Invalid static table index rejected gracefully
fn test_invalid_static_index(input: &QpackFuzzInput) {
    if let AttackScenario::InvalidStaticIndex { index } = &input.attack_scenario {
        // Construct QPACK field section with invalid static index
        let malicious_section = build_static_index_reference(*index);

        let mode = input.qpack_mode.clone().into();
        let result = qpack_decode_field_section(&malicious_section, mode);

        match result {
            Err(H3NativeError::InvalidFrame(msg)) => {
                // Should gracefully reject with appropriate error message
                assert!(
                    msg.contains("static") || msg.contains("index") || msg.contains("unknown"),
                    "Error message should indicate static index issue: {msg}"
                );
            }
            Err(_) => {
                // Other errors are acceptable for malformed input
            }
            Ok(_) => {
                // If successful, the index must be valid (< 99 per RFC 9204)
                if *index >= 99 {
                    panic!("Invalid static index {index} was accepted - security issue");
                }
            }
        }
    }
}

/// Property 3: Dynamic table size change respected
fn test_dynamic_table_size(input: &QpackFuzzInput) {
    if let AttackScenario::DynamicTableResize { size } = &input.attack_scenario {
        let mode = input.qpack_mode.clone().into();

        // Test that StaticOnly mode rejects dynamic table operations
        if matches!(mode, H3QpackMode::StaticOnly) {
            let dynamic_section = build_dynamic_table_reference(*size);
            let result = qpack_decode_field_section(&dynamic_section, mode);

            match result {
                Err(H3NativeError::InvalidFrame(msg)) => {
                    assert!(
                        msg.contains("dynamic") || msg.contains("table") || msg.contains("state"),
                        "Should reject dynamic table operations in static-only mode: {msg}"
                    );
                }
                Err(_) => {
                    // Other errors acceptable
                }
                Ok(_) => {
                    // Should not succeed with dynamic references in static-only mode
                    // unless the reference was actually valid static content
                }
            }
        }
    }
}

/// Property 4: Delta Base manipulation handled cleanly
fn test_delta_base(input: &QpackFuzzInput) {
    if let AttackScenario::DeltaBase { delta } = &input.attack_scenario {
        let mode = input.qpack_mode.clone().into();
        let delta_section = build_delta_base_section(*delta);
        let result = qpack_decode_field_section(&delta_section, mode);

        match result {
            Err(H3NativeError::InvalidFrame(_)) | Err(H3NativeError::UnexpectedEof) => {
                // Expected for nonsensical bases or truncated continuations.
            }
            Err(_) => {
                // Other decoder errors are acceptable for adversarial input.
            }
            Ok(plan) => {
                assert!(
                    *delta == 0 || !plan.is_empty(),
                    "non-zero Delta Base decoded as an empty field section"
                );
            }
        }
    }
}

/// Property 5: Huffman-encoded strings decode without overflow
fn test_huffman_string_safety(input: &QpackFuzzInput) {
    if let AttackScenario::HuffmanOverflow {
        prefix_bits,
        string_data,
    } = &input.attack_scenario
    {
        let mode = input.qpack_mode.clone().into();

        // Build QPACK field section with potentially malicious Huffman string
        let huffman_section = build_huffman_string_section(*prefix_bits, string_data);

        let result = qpack_decode_field_section(&huffman_section, mode);

        match result {
            Err(H3NativeError::InvalidFrame(msg)) => {
                // Expected for malformed Huffman or in static-only mode
                if matches!(mode, H3QpackMode::StaticOnly) {
                    assert!(
                        msg.contains("huffman") || msg.contains("not supported"),
                        "Should reject Huffman in static-only mode: {msg}"
                    );
                }
            }
            Err(_) => {
                // Other errors are acceptable for malformed data
            }
            Ok(_) => {
                // Success is acceptable as long as the decoder returned normally.
            }
        }
    }
}

/// Property 6: Prefixed integer overflow is rejected or completes in bounded time
fn test_integer_overflow(input: &QpackFuzzInput) {
    if let AttackScenario::IntegerOverflow {
        prefix_len,
        overflow_bytes,
    } = &input.attack_scenario
    {
        let mode = input.qpack_mode.clone().into();
        let overflow_section = build_integer_overflow_section(*prefix_len, overflow_bytes);

        let start_time = std::time::Instant::now();
        let result = qpack_decode_field_section(&overflow_section, mode);
        let elapsed = start_time.elapsed();

        assert!(
            elapsed.as_millis() < 100,
            "Decoder took too long ({elapsed:?}) on prefixed integer overflow input"
        );

        if overflow_bytes.len() >= 10 {
            assert!(
                result.is_err(),
                "oversized QPACK prefixed integer continuation was accepted"
            );
        }
    }
}

/// Property 7: Required insert count stall handled cleanly (not infinite loop)
fn test_required_insert_count_stall(input: &QpackFuzzInput) {
    if let AttackScenario::RequiredInsertCount { count } = &input.attack_scenario {
        let mode = input.qpack_mode.clone().into();

        // Build QPACK field section with specific required insert count
        let ric_section = build_required_insert_count_section(*count);

        // This test should complete in bounded time (no infinite loops)
        let start_time = std::time::Instant::now();
        let result = qpack_decode_field_section(&ric_section, mode);
        let elapsed = start_time.elapsed();

        // Decoder should respond within reasonable time (not stall indefinitely)
        assert!(
            elapsed.as_millis() < 100,
            "Decoder took too long ({elapsed:?}) - possible infinite loop with RIC {count}"
        );

        match result {
            Err(H3NativeError::InvalidFrame(_)) => {
                // Expected for invalid required insert count scenarios
            }
            Err(_) => {
                // Other errors acceptable
            }
            Ok(_) => {
                // Success is fine if the RIC was actually valid
            }
        }
    }
}

/// Build a QPACK field section with a specific Delta Base value
fn build_delta_base_section(delta: u64) -> Vec<u8> {
    let mut section = Vec::new();

    section.push(0x00); // RIC = 0
    if delta < 127 {
        section.push(delta as u8);
    } else {
        section.push(127);
        encode_varint_continuation(&mut section, delta - 127);
    }
    section.push(0b1100_0000 | 17); // :method GET

    section
}

/// Build a QPACK field section with a specific static table index reference
fn build_static_index_reference(index: u64) -> Vec<u8> {
    let mut section = Vec::new();

    // QPACK field section header: Required Insert Count = 0, Delta Base = 0
    section.push(0x00); // RIC prefix
    section.push(0x00); // Delta Base prefix

    // Static index pattern: 11XXXXXX (RFC 9204 Section 4.5.2)
    if index < 64 {
        section.push(0b1100_0000 | (index as u8));
    } else {
        // Multi-byte encoding for larger indices
        section.push(0b1100_0000 | 63);
        encode_varint_continuation(&mut section, index - 63);
    }

    section
}

/// Build a QPACK field section with dynamic table references
fn build_dynamic_table_reference(size: u64) -> Vec<u8> {
    let mut section = Vec::new();

    // Required Insert Count > 0 indicates dynamic table usage
    section.push(0x00); // RIC prefix byte
    encode_varint_continuation(&mut section, size.min(255)); // Use size as RIC
    section.push(0x00); // Delta Base

    // Dynamic index pattern: 10XXXXXX
    section.push(0b1000_0000); // Dynamic index 0

    section
}

/// Build a QPACK field section with Huffman-encoded string
fn build_huffman_string_section(prefix_bits: u8, string_data: &[u8]) -> Vec<u8> {
    let mut section = Vec::new();

    // Field section header
    section.push(0x00); // RIC = 0
    section.push(0x00); // Delta Base = 0

    // Literal field line with name reference: 01XXXXXX (RFC 9204 Section 4.5.4)
    section.push(0b0101_0000); // Static name index 0 (:method)

    // String literal with Huffman bit set: 1XXXXXXX
    let huffman_bit = 0b1000_0000;
    let claimed_inline_len = prefix_bits & 0b0111_1111;

    if claimed_inline_len < 127 {
        section.push(huffman_bit | claimed_inline_len);
    } else {
        section.push(huffman_bit | 127);
        encode_varint_continuation(&mut section, string_data.len().saturating_sub(127) as u64);
    }

    section.extend_from_slice(string_data);
    section
}

/// Build a QPACK field section with specific Required Insert Count
fn build_required_insert_count_section(count: u64) -> Vec<u8> {
    let mut section = Vec::new();

    // Encode Required Insert Count in first byte(s)
    if count < 255 {
        section.push(count as u8);
    } else {
        section.push(0xFF);
        encode_varint_continuation(&mut section, count - 255);
    }

    section.push(0x00); // Delta Base = 0

    // Add a simple static reference to make it a valid field section structure
    section.push(0b1100_0000); // Static index 0

    section
}

/// Build a QPACK field section with an oversized prefixed integer continuation
fn build_integer_overflow_section(prefix_len: u8, overflow_bytes: &[u8]) -> Vec<u8> {
    let mut section = vec![0x00, 0x00]; // RIC=0, Delta Base=0

    // Static indexed field line with the 6-bit prefix saturated, forcing
    // continuation bytes for the static index value.
    section.push(0b1100_0000 | 63);
    let max_extra = usize::from((prefix_len % 8).max(1)) + overflow_bytes.len().min(16);
    for byte in overflow_bytes.iter().take(max_extra) {
        section.push((byte & 0x7F) | 0x80);
    }
    section.push(0x7F);

    section
}

/// Encode variable-length integer continuation bytes
fn encode_varint_continuation(out: &mut Vec<u8>, mut value: u64) {
    while value >= 128 {
        out.push((value & 0x7F) as u8 | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// Test malformed patterns to ensure robust error handling
fn test_malformed_patterns(input: &QpackFuzzInput) {
    if let AttackScenario::MalformedField { pattern_type } = &input.attack_scenario {
        let mode = input.qpack_mode.clone().into();

        let malformed_section = match pattern_type {
            MalformedPattern::Truncated { at_byte } => {
                let mut section = input.field_section.clone();
                let truncate_at = (*at_byte).min(section.len());
                section.truncate(truncate_at);
                section
            }
            MalformedPattern::InvalidPattern { pattern } => {
                vec![0x00, 0x00, *pattern] // Invalid field line pattern
            }
            MalformedPattern::StringLengthOverflow { claimed_length } => {
                build_string_length_overflow(*claimed_length)
            }
            MalformedPattern::InvalidUtf8 { bytes } => build_invalid_utf8_string(bytes),
        };

        // Should handle malformed input gracefully
        let result = qpack_decode_field_section(&malformed_section, mode);

        match result {
            Err(H3NativeError::UnexpectedEof) => {
                // Expected for truncated input
            }
            Err(H3NativeError::InvalidFrame(_)) => {
                // Expected for malformed patterns
            }
            Err(_) => {
                // Other errors acceptable
            }
            Ok(_) => {
                // Unexpected success with malformed input - may indicate issue
                // but not necessarily a failure if the malformed data was accidentally valid
            }
        }
    }
}

/// Build field section with string length overflow
fn build_string_length_overflow(claimed_length: u64) -> Vec<u8> {
    let mut section = vec![0x00, 0x00]; // RIC=0, Delta Base=0

    // Literal field line with name literal: 001XXXXX
    section.push(0b0010_0000);

    // String with excessive claimed length but short actual data
    if claimed_length < 32 {
        section.push(claimed_length as u8);
    } else {
        section.push(31);
        encode_varint_continuation(&mut section, claimed_length - 31);
    }

    // Provide much shorter actual data than claimed
    section.extend_from_slice(b"short");
    section
}

/// Build field section with invalid UTF-8 string
fn build_invalid_utf8_string(invalid_bytes: &[u8]) -> Vec<u8> {
    let mut section = vec![0x00, 0x00]; // RIC=0, Delta Base=0

    // Literal field with name literal
    section.push(0b0010_0000);

    // Name string (valid)
    section.push(4); // Length
    section.extend_from_slice(b"name");

    // Value string (potentially invalid UTF-8)
    if invalid_bytes.len() < 32 {
        section.push(invalid_bytes.len() as u8);
    } else {
        section.push(31);
        encode_varint_continuation(&mut section, invalid_bytes.len() as u64 - 31);
    }
    section.extend_from_slice(invalid_bytes);

    section
}

/// Integration test: real-world QPACK scenarios
fn test_realistic_scenarios() {
    let empty_section = vec![0x00, 0x00]; // RIC=0, Delta Base=0
    let decoded_empty =
        qpack_decode_field_section(&empty_section, H3QpackMode::StaticOnly).expect("empty decode");
    assert_eq!(decoded_empty, Vec::<QpackFieldPlan>::new());

    let request_plan = vec![
        QpackFieldPlan::StaticIndex(17), // :method GET
        QpackFieldPlan::StaticIndex(23), // :scheme https
        QpackFieldPlan::StaticIndex(1),  // :path /
        QpackFieldPlan::Literal {
            name: "user-agent".to_string(),
            value: "asupersync-fuzz".to_string(),
        },
    ];
    let request_wire = qpack_encode_field_section(&request_plan).expect("request encode");
    assert_eq!(
        qpack_decode_field_section(&request_wire, H3QpackMode::StaticOnly)
            .expect("request plan decode"),
        request_plan
    );
    let request = qpack_decode_request_field_section(&request_wire, H3QpackMode::StaticOnly, None)
        .expect("request head decode");
    assert_eq!(request.pseudo.method.as_deref(), Some("GET"));
    assert_eq!(request.pseudo.scheme.as_deref(), Some("https"));
    assert_eq!(request.pseudo.path.as_deref(), Some("/"));
    assert_eq!(
        request.headers,
        vec![("user-agent".to_string(), "asupersync-fuzz".to_string())]
    );

    let response_plan = vec![
        QpackFieldPlan::StaticIndex(25), // :status 200
        QpackFieldPlan::Literal {
            name: "server".to_string(),
            value: "asupersync".to_string(),
        },
    ];
    let response_wire = qpack_encode_field_section(&response_plan).expect("response encode");
    assert_eq!(
        qpack_decode_field_section(&response_wire, H3QpackMode::StaticOnly)
            .expect("response plan decode"),
        response_plan
    );
    let response =
        qpack_decode_response_field_section(&response_wire, H3QpackMode::StaticOnly, None)
            .expect("response head decode");
    assert_eq!(response.status, 200);
    assert_eq!(
        response.headers,
        vec![("server".to_string(), "asupersync".to_string())]
    );
}
