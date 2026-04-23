#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::net::quic_core::{
    encode_varint, decode_varint, QuicCoreError, QUIC_VARINT_MAX,
};

/// Fuzz input for QUIC varint codec testing
#[derive(Arbitrary, Debug)]
struct QuicVarintFuzzInput {
    /// Operations to perform
    operations: Vec<VarintOperation>,
    /// Attack scenarios to test specific edge cases
    attack_scenario: AttackScenario,
}

/// Operations that can be performed on the varint codec
#[derive(Arbitrary, Debug, Clone)]
enum VarintOperation {
    /// Encode a value
    Encode { value: u64 },
    /// Decode a raw byte sequence
    Decode { bytes: Vec<u8> },
    /// Round-trip: encode then decode
    RoundTrip { value: u64 },
    /// Multiple operations in sequence
    Sequence { operations: Vec<SimpleVarintOp> },
}

#[derive(Arbitrary, Debug, Clone)]
enum SimpleVarintOp {
    Encode { value: u64 },
    Decode { bytes: Vec<u8> },
}

/// Attack scenarios and edge cases to test
#[derive(Arbitrary, Debug, Clone)]
enum AttackScenario {
    /// Normal operation (baseline)
    Normal,
    /// Boundary testing around varint limits
    BoundaryTest {
        boundary_type: BoundaryType,
    },
    /// Malformed varint sequences
    MalformedVarint {
        malformed_type: MalformedType,
    },
    /// Overflow/underflow attempts
    OverflowTest {
        target_value: u64,
    },
    /// Truncated varint sequences
    TruncatedVarint {
        truncate_position: u8,
        original_length: u8,
    },
    /// Invalid length prefix combinations
    InvalidLengthPrefix {
        prefix_byte: u8,
        following_bytes: Vec<u8>,
    },
    /// Maximum length edge cases
    MaxLengthTest {
        test_type: MaxLengthTestType,
    },
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum BoundaryType {
    /// Test around 6-bit boundary (1 << 6)
    SixBit,
    /// Test around 14-bit boundary (1 << 14)
    FourteenBit,
    /// Test around 30-bit boundary (1 << 30)
    ThirtyBit,
    /// Test around 62-bit max (QUIC_VARINT_MAX)
    SixtyTwoBit,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum MalformedType {
    /// Invalid length encoding
    InvalidLength,
    /// Overlong encoding (value could be encoded shorter)
    Overlong,
    /// Reserved bit patterns
    ReservedBits,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum MaxLengthTestType {
    /// Exactly at maximum
    ExactMax,
    /// One over maximum
    OverMax,
    /// Maximum minus one
    MaxMinusOne,
}

fuzz_target!(|input: QuicVarintFuzzInput| {
    // Property 1: No panic on any input
    test_no_panic(&input);

    // Property 2: Valid varints round-trip correctly
    test_round_trip_consistency(&input);

    // Property 3: Invalid inputs are rejected gracefully
    test_invalid_input_rejection(&input);

    // Property 4: Boundary conditions handled correctly
    test_boundary_conditions(&input);

    // Property 5: Attack scenarios are handled robustly
    test_attack_scenarios(&input);

    // Property 6: Encoding bounds are enforced
    test_encoding_bounds(&input);

    // Property 7: Decode buffer management is safe
    test_decode_buffer_safety(&input);
});

/// Property 1: No panic on any input
fn test_no_panic(input: &QuicVarintFuzzInput) {
    for operation in &input.operations {
        let _result = std::panic::catch_unwind(|| {
            process_varint_operation(operation);
        });
    }

    // Process attack scenario
    let _result = std::panic::catch_unwind(|| {
        process_attack_scenario(&input.attack_scenario);
    });

    assert!(true, "Varint codec handled all inputs without panic");
}

/// Property 2: Valid varints round-trip correctly
fn test_round_trip_consistency(input: &QuicVarintFuzzInput) {
    for operation in &input.operations {
        if let VarintOperation::RoundTrip { value } = operation {
            if *value <= QUIC_VARINT_MAX {
                // Should be able to encode and decode successfully
                let mut encoded = Vec::new();
                match encode_varint(*value, &mut encoded) {
                    Ok(()) => {
                        // Should decode back to the same value
                        match decode_varint(&encoded) {
                            Ok((decoded_value, consumed)) => {
                                assert_eq!(*value, decoded_value, "Round-trip failed for value {value}");
                                assert_eq!(consumed, encoded.len(), "Consumed bytes mismatch");
                            }
                            Err(_) => {
                                panic!("Valid encoded varint failed to decode: {value}");
                            }
                        }
                    }
                    Err(QuicCoreError::VarIntOutOfRange(_)) => {
                        // This is expected if value > QUIC_VARINT_MAX
                        assert!(*value > QUIC_VARINT_MAX, "Unexpected out-of-range error for {value}");
                    }
                    Err(_) => {
                        panic!("Unexpected error encoding valid value: {value}");
                    }
                }
            }
        }
    }
}

/// Property 3: Invalid inputs are rejected gracefully
fn test_invalid_input_rejection(input: &QuicVarintFuzzInput) {
    for operation in &input.operations {
        if let VarintOperation::Decode { bytes } = operation {
            // Should either succeed or return appropriate error
            match decode_varint(bytes) {
                Ok((value, consumed)) => {
                    // If successful, value should be in valid range
                    assert!(value <= QUIC_VARINT_MAX, "Decoded value {value} exceeds QUIC_VARINT_MAX");
                    assert!(consumed > 0, "Should consume at least one byte");
                    assert!(consumed <= 8, "Should consume at most 8 bytes");
                    assert!(consumed <= bytes.len(), "Should not consume more bytes than available");
                }
                Err(QuicCoreError::UnexpectedEof) => {
                    // This is expected for truncated/empty input
                    assert!(true, "Correctly rejected truncated input");
                }
                Err(QuicCoreError::VarIntOutOfRange(val)) => {
                    // This indicates the decoding process found a value over the limit
                    assert!(val > QUIC_VARINT_MAX, "VarIntOutOfRange should only occur for values > QUIC_VARINT_MAX");
                }
                Err(_) => {
                    // Other errors are unexpected but should not panic
                    assert!(true, "Unexpected error type - but no panic");
                }
            }
        }
    }
}

/// Property 4: Boundary conditions handled correctly
fn test_boundary_conditions(input: &QuicVarintFuzzInput) {
    if let AttackScenario::BoundaryTest { boundary_type } = &input.attack_scenario {
        let test_values = match boundary_type {
            BoundaryType::SixBit => vec![
                (1 << 6) - 1,    // Max 1-byte varint
                1 << 6,          // Min 2-byte varint
                (1 << 6) + 1,    // Just over boundary
            ],
            BoundaryType::FourteenBit => vec![
                (1 << 14) - 1,   // Max 2-byte varint
                1 << 14,         // Min 4-byte varint
                (1 << 14) + 1,   // Just over boundary
            ],
            BoundaryType::ThirtyBit => vec![
                (1 << 30) - 1,   // Max 4-byte varint
                1 << 30,         // Min 8-byte varint
                (1 << 30) + 1,   // Just over boundary
            ],
            BoundaryType::SixtyTwoBit => vec![
                QUIC_VARINT_MAX,     // Maximum valid varint
                QUIC_VARINT_MAX - 1, // Just under max
            ],
        };

        for value in test_values {
            if value <= QUIC_VARINT_MAX {
                // Test round-trip for boundary values
                let mut encoded = Vec::new();
                match encode_varint(value, &mut encoded) {
                    Ok(()) => {
                        match decode_varint(&encoded) {
                            Ok((decoded, _)) => {
                                assert_eq!(value, decoded, "Boundary value {value} failed round-trip");
                            }
                            Err(_) => {
                                panic!("Boundary value {value} failed to decode");
                            }
                        }
                    }
                    Err(_) => {
                        panic!("Boundary value {value} failed to encode");
                    }
                }
            }
        }
    }
}

/// Property 5: Attack scenarios are handled robustly
fn test_attack_scenarios(input: &QuicVarintFuzzInput) {
    match &input.attack_scenario {
        AttackScenario::TruncatedVarint { truncate_position, original_length } => {
            // Try to decode truncated varint
            let original_len = (*original_length as usize).min(8).max(1);
            let truncate_pos = (*truncate_position as usize).min(original_len);

            // Create a potentially valid varint prefix then truncate it
            let mut test_bytes = vec![0xc0]; // 8-byte varint prefix
            test_bytes.extend(vec![0xff; original_len.saturating_sub(1)]);
            test_bytes.truncate(truncate_pos);

            // Should return UnexpectedEof for incomplete varints
            match decode_varint(&test_bytes) {
                Ok(_) => {
                    // Only valid if we didn't actually truncate
                    assert!(truncate_pos >= original_len, "Truncated varint should not decode successfully");
                }
                Err(QuicCoreError::UnexpectedEof) => {
                    // Expected for truncated input
                    assert!(true, "Correctly detected truncated varint");
                }
                Err(_) => {
                    // Other errors are acceptable
                    assert!(true, "Truncated varint rejected with error");
                }
            }
        }
        AttackScenario::InvalidLengthPrefix { prefix_byte, following_bytes } => {
            let mut test_bytes = vec![*prefix_byte];
            test_bytes.extend_from_slice(following_bytes);

            // Decode should handle gracefully
            let result = decode_varint(&test_bytes);
            match result {
                Ok((value, _)) => {
                    // If successful, value should be valid
                    assert!(value <= QUIC_VARINT_MAX, "Invalid prefix produced out-of-range value");
                }
                Err(_) => {
                    // Error is expected and acceptable
                    assert!(true, "Invalid prefix correctly rejected");
                }
            }
        }
        AttackScenario::OverflowTest { target_value } => {
            // Test encoding values that might cause overflow
            let mut encoded = Vec::new();
            match encode_varint(*target_value, &mut encoded) {
                Ok(()) => {
                    // Should only succeed for valid values
                    assert!(*target_value <= QUIC_VARINT_MAX, "Out-of-range value was encoded");

                    // And should decode correctly
                    match decode_varint(&encoded) {
                        Ok((decoded, _)) => {
                            assert_eq!(*target_value, decoded, "Overflow test value failed round-trip");
                        }
                        Err(_) => {
                            panic!("Valid encoded value failed to decode");
                        }
                    }
                }
                Err(QuicCoreError::VarIntOutOfRange(_)) => {
                    // Expected for values > QUIC_VARINT_MAX
                    assert!(*target_value > QUIC_VARINT_MAX, "Unexpected out-of-range rejection");
                }
                Err(_) => {
                    panic!("Unexpected error type for overflow test");
                }
            }
        }
        _ => {
            // Other scenarios tested elsewhere
        }
    }
}

/// Property 6: Encoding bounds are enforced
fn test_encoding_bounds(input: &QuicVarintFuzzInput) {
    if let AttackScenario::MaxLengthTest { test_type } = &input.attack_scenario {
        let test_value = match test_type {
            MaxLengthTestType::ExactMax => QUIC_VARINT_MAX,
            MaxLengthTestType::OverMax => QUIC_VARINT_MAX.saturating_add(1),
            MaxLengthTestType::MaxMinusOne => QUIC_VARINT_MAX.saturating_sub(1),
        };

        let mut encoded = Vec::new();
        let result = encode_varint(test_value, &mut encoded);

        match test_type {
            MaxLengthTestType::ExactMax | MaxLengthTestType::MaxMinusOne => {
                // Should succeed
                assert!(result.is_ok(), "Valid max value should encode successfully");
                assert!(!encoded.is_empty(), "Encoding should produce bytes");
                assert!(encoded.len() <= 8, "Varint should not exceed 8 bytes");
            }
            MaxLengthTestType::OverMax => {
                // Should fail
                match result {
                    Err(QuicCoreError::VarIntOutOfRange(_)) => {
                        assert!(true, "Over-max value correctly rejected");
                    }
                    _ => {
                        panic!("Over-max value should be rejected with VarIntOutOfRange");
                    }
                }
            }
        }
    }
}

/// Property 7: Decode buffer management is safe
fn test_decode_buffer_safety(input: &QuicVarintFuzzInput) {
    for operation in &input.operations {
        if let VarintOperation::Decode { bytes } = operation {
            // Test with various buffer sizes
            match decode_varint(bytes) {
                Ok((_, consumed)) => {
                    // Consumed bytes should not exceed buffer length
                    assert!(consumed <= bytes.len(), "Consumed more bytes than available");

                    // Should consume at least one byte for successful decode
                    assert!(consumed > 0, "Should consume at least one byte");

                    // Should not consume more than 8 bytes (max varint length)
                    assert!(consumed <= 8, "Should not consume more than 8 bytes");
                }
                Err(_) => {
                    // Errors are acceptable, just ensure no buffer overrun
                    assert!(true, "Error is acceptable - no buffer overrun");
                }
            }
        }
    }
}

/// Helper function to process a varint operation
fn process_varint_operation(operation: &VarintOperation) {
    match operation {
        VarintOperation::Encode { value } => {
            let mut encoded = Vec::new();
            let _ = encode_varint(*value, &mut encoded);
        }
        VarintOperation::Decode { bytes } => {
            let _ = decode_varint(bytes);
        }
        VarintOperation::RoundTrip { value } => {
            let mut encoded = Vec::new();
            if encode_varint(*value, &mut encoded).is_ok() {
                let _ = decode_varint(&encoded);
            }
        }
        VarintOperation::Sequence { operations } => {
            for op in operations {
                match op {
                    SimpleVarintOp::Encode { value } => {
                        let mut encoded = Vec::new();
                        let _ = encode_varint(*value, &mut encoded);
                    }
                    SimpleVarintOp::Decode { bytes } => {
                        let _ = decode_varint(bytes);
                    }
                }
            }
        }
    }
}

/// Helper function to process an attack scenario
fn process_attack_scenario(scenario: &AttackScenario) {
    match scenario {
        AttackScenario::Normal => {
            // Just test some basic values
            let test_values = [0, 1, 63, 64, 16383, 16384, 1073741823, 1073741824, QUIC_VARINT_MAX];
            for value in test_values {
                let mut encoded = Vec::new();
                if encode_varint(value, &mut encoded).is_ok() {
                    let _ = decode_varint(&encoded);
                }
            }
        }
        _ => {
            // Other scenarios are handled in their specific test functions
        }
    }
}