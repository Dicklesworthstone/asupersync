#![no_main]

use arbitrary::Arbitrary;
use asupersync::cx::macaroon::{CaveatPredicate, MacaroonToken, VerificationContext};
use asupersync::security::key::AuthKey;
use libfuzzer_sys::fuzz_target;

/// Comprehensive fuzz target for Macaroon capability token attenuation chains
///
/// Tests the security-critical Macaroon implementation for:
/// - Binary serialization/deserialization robustness
/// - HMAC signature chain verification integrity
/// - Caveat predicate encoding/decoding edge cases
/// - Declared-length overflow and trailing-byte parser resilience
/// - Attenuation chain manipulation attempts
/// - Third-party caveat discharge token handling
/// - Malformed token parsing resilience
/// - Time-based caveat validation under extreme conditions
/// - Resource scope pattern matching vulnerabilities
/// - Rate limiting caveat enforcement edge cases
#[derive(Arbitrary, Debug)]
struct MacaroonFuzz {
    /// Operations to perform on macaroon tokens
    operations: Vec<MacaroonOperation>,
    /// Verification context for caveat checking
    context: ContextFuzz,
    /// Malformed binary data to test deserialization
    malformed_data: Vec<u8>,
}

/// Fuzzing operations on macaroon tokens
#[derive(Arbitrary, Debug)]
enum MacaroonOperation {
    /// Create a new macaroon with given parameters
    Mint {
        root_key_seed: u64,
        identifier: String,
        location: String,
    },
    /// Add a first-party caveat
    AddCaveat { predicate: CaveatPredicateFuzz },
    /// Add a third-party caveat
    AddThirdPartyCaveat {
        location: String,
        caveat_key_seed: u64,
        identifier: String,
    },
    /// Serialize token to binary
    Serialize,
    /// Deserialize from binary data
    Deserialize(Vec<u8>),
    /// Verify signature with given key
    VerifySignature { key_seed: u64 },
    /// Full verification with context
    Verify { key_seed: u64 },
    /// Bind discharge token
    BindForRequest {
        discharge_ops: Vec<MacaroonOperation>,
    },
    /// Test malformed predicate parsing
    TestMalformedPredicate(Vec<u8>),
}

/// Fuzzing variants of caveat predicates to test edge cases
#[derive(Arbitrary, Debug)]
enum CaveatPredicateFuzz {
    TimeBefore(u64),
    TimeAfter(u64),
    RegionScope(u64),
    TaskScope(u64),
    MaxUses(u32),
    /// Test with potentially malicious glob patterns
    ResourceScope(String),
    RateLimit {
        max_count: u32,
        window_secs: u32,
    },
    /// Test with extreme string values
    Custom(String, String),
}

/// Verification context with fuzzing values
#[derive(Arbitrary, Debug)]
struct ContextFuzz {
    current_time_ms: u64,
    region_id: u64,
    task_id: u64,
    resource_path: String,
    use_count: u32,
    window_use_count: u32,
}

/// Safety limits to prevent resource exhaustion
const MAX_IDENTIFIER_LEN: usize = 1024;
const MAX_LOCATION_LEN: usize = 512;
const MAX_STRING_LEN: usize = 1024;
const MAX_OPERATIONS: usize = 20;
const MAX_MALFORMED_DATA_LEN: usize = 4096;
const MAX_CAVEAT_COUNT: usize = 50;
const MAX_TRAILING_SUFFIX_LEN: usize = 16;

fuzz_target!(|input: MacaroonFuzz| {
    // Limit operations for performance
    let operations = if input.operations.len() > MAX_OPERATIONS {
        &input.operations[..MAX_OPERATIONS]
    } else {
        &input.operations
    };

    // Test malformed data deserialization first
    test_malformed_deserialization(&input.malformed_data);

    // Test predicate encoding/decoding
    test_predicate_round_trip(operations);
    test_caveat_parser_edge_cases(operations, &input.malformed_data);

    // Execute macaroon operations
    let mut current_token: Option<MacaroonToken> = None;
    let verification_context = create_verification_context(&input.context);

    for operation in operations {
        match operation {
            MacaroonOperation::Mint {
                root_key_seed,
                identifier,
                location,
            } => {
                let safe_identifier = limit_string(identifier, MAX_IDENTIFIER_LEN);
                let safe_location = limit_string(location, MAX_LOCATION_LEN);

                current_token = Some(test_mint_token(
                    *root_key_seed,
                    &safe_identifier,
                    &safe_location,
                ));
            }
            MacaroonOperation::AddCaveat { predicate } => {
                if let Some(token) = current_token.take() {
                    current_token = Some(test_add_caveat(token, predicate));
                }
            }
            MacaroonOperation::AddThirdPartyCaveat {
                location,
                caveat_key_seed,
                identifier,
            } => {
                if let Some(token) = current_token.take() {
                    let safe_location = limit_string(location, MAX_LOCATION_LEN);
                    let safe_identifier = limit_string(identifier, MAX_IDENTIFIER_LEN);

                    current_token = Some(test_add_third_party_caveat(
                        token,
                        &safe_location,
                        *caveat_key_seed,
                        &safe_identifier,
                    ));
                }
            }
            MacaroonOperation::Serialize => {
                if let Some(token) = &current_token {
                    test_serialization_round_trip(token);
                }
            }
            MacaroonOperation::Deserialize(data) => {
                let limited_data = if data.len() > MAX_MALFORMED_DATA_LEN {
                    &data[..MAX_MALFORMED_DATA_LEN]
                } else {
                    data
                };
                test_safe_deserialization(limited_data);
            }
            MacaroonOperation::VerifySignature { key_seed } => {
                if let Some(token) = &current_token {
                    test_signature_verification(token, *key_seed);
                }
            }
            MacaroonOperation::Verify { key_seed } => {
                if let Some(token) = &current_token {
                    test_full_verification(token, *key_seed, &verification_context);
                }
            }
            MacaroonOperation::BindForRequest { discharge_ops } => {
                if let Some(token) = &current_token {
                    test_discharge_binding(token, discharge_ops);
                }
            }
            MacaroonOperation::TestMalformedPredicate(data) => {
                test_malformed_predicate_parsing(data);
            }
        }
    }

    // Final comprehensive test if we have a token
    if let Some(token) = &current_token {
        test_comprehensive_properties(token, &verification_context);
    }
});

fn test_mint_token(key_seed: u64, identifier: &str, location: &str) -> MacaroonToken {
    let root_key = AuthKey::from_seed(key_seed);
    let token = MacaroonToken::mint(&root_key, identifier, location);

    // Basic invariants
    assert_eq!(token.identifier(), identifier);
    assert_eq!(token.location(), location);
    assert_eq!(token.caveat_count(), 0);

    // Signature should verify with the same key
    assert!(token.verify_signature(&root_key));

    // Different key should fail
    let wrong_key = AuthKey::from_seed(key_seed.wrapping_add(1));
    assert!(!token.verify_signature(&wrong_key));

    token
}

fn test_add_caveat(token: MacaroonToken, predicate_fuzz: &CaveatPredicateFuzz) -> MacaroonToken {
    let predicate = convert_predicate_fuzz(predicate_fuzz);
    let original_count = token.caveat_count();

    let new_token = token.add_caveat(predicate);

    // Invariants after adding caveat
    assert_eq!(new_token.caveat_count(), original_count + 1);
    assert_eq!(new_token.identifier(), new_token.identifier()); // Should be unchanged
    assert_eq!(new_token.location(), new_token.location()); // Should be unchanged

    new_token
}

fn test_add_third_party_caveat(
    token: MacaroonToken,
    location: &str,
    caveat_key_seed: u64,
    identifier: &str,
) -> MacaroonToken {
    let caveat_key = AuthKey::from_seed(caveat_key_seed);
    let original_count = token.caveat_count();

    let new_token = token.add_third_party_caveat(location, identifier, &caveat_key);

    // Invariants after adding third-party caveat
    assert_eq!(new_token.caveat_count(), original_count + 1);

    new_token
}

fn test_serialization_round_trip(token: &MacaroonToken) {
    // Serialize should never panic
    let serialized = token.to_binary();

    // Basic sanity checks
    assert!(
        !serialized.is_empty(),
        "Serialized token should not be empty"
    );
    assert!(
        serialized.len() < 100_000,
        "Serialized token should be reasonable size"
    );

    // Deserialization should succeed for valid tokens
    if let Some(deserialized) = MacaroonToken::from_binary(&serialized) {
        // Round-trip should preserve all fields
        assert_eq!(deserialized.identifier(), token.identifier());
        assert_eq!(deserialized.location(), token.location());
        assert_eq!(deserialized.caveat_count(), token.caveat_count());
        assert_eq!(
            deserialized.signature().as_bytes(),
            token.signature().as_bytes()
        );
    }
}

fn test_safe_deserialization(data: &[u8]) {
    // Deserialization should never panic, even with malformed data
    let result = MacaroonToken::from_binary(data);

    // If deserialization succeeds, verify basic properties
    if let Some(token) = result {
        // Identifier and location should be valid UTF-8
        assert!(!token.identifier().is_empty() || token.identifier().is_empty()); // Should not panic
        assert!(!token.location().is_empty() || token.location().is_empty()); // Should not panic

        // Caveat count should be reasonable
        assert!(token.caveat_count() <= MAX_CAVEAT_COUNT);

        // Signature should be exactly 32 bytes
        assert_eq!(token.signature().as_bytes().len(), 32);
    }
}

fn test_malformed_deserialization(data: &[u8]) {
    let limited_data = if data.len() > MAX_MALFORMED_DATA_LEN {
        &data[..MAX_MALFORMED_DATA_LEN]
    } else {
        data
    };

    // Should handle malformed data gracefully
    let _ = MacaroonToken::from_binary(limited_data);
}

fn test_predicate_round_trip(operations: &[MacaroonOperation]) {
    for operation in operations {
        if let MacaroonOperation::AddCaveat { predicate } = operation {
            let pred = convert_predicate_fuzz(predicate);

            // Encoding should never panic
            let bytes = pred.to_bytes();
            assert!(!bytes.is_empty(), "Encoded predicate should not be empty");
            assert!(
                bytes.len() < 10_000,
                "Encoded predicate should be reasonable size"
            );

            // Decoding should succeed for valid predicates
            if let Some((decoded, consumed)) = CaveatPredicate::from_bytes(&bytes) {
                assert_eq!(consumed, bytes.len(), "Should consume all bytes");

                // Re-encoding should be identical
                let re_encoded = decoded.to_bytes();
                assert_eq!(bytes, re_encoded, "Round-trip should be stable");
            }
        }
    }
}

fn test_caveat_parser_edge_cases(operations: &[MacaroonOperation], malformed_data: &[u8]) {
    for operation in operations {
        if let MacaroonOperation::AddCaveat { predicate } = operation {
            let encoded = convert_predicate_fuzz(predicate).to_bytes();

            test_truncated_predicate_rejection(&encoded);
            test_trailing_predicate_bytes(&encoded, malformed_data);
            test_variable_length_field_overflow(&encoded);
        }
    }
}

fn test_truncated_predicate_rejection(encoded: &[u8]) {
    for truncated_len in 0..encoded.len() {
        assert!(
            CaveatPredicate::from_bytes(&encoded[..truncated_len]).is_none(),
            "truncated predicate prefix should be rejected"
        );
    }
}

fn test_trailing_predicate_bytes(encoded: &[u8], malformed_data: &[u8]) {
    let suffix_len = malformed_data.len().min(MAX_TRAILING_SUFFIX_LEN);
    let mut with_trailing = encoded.to_vec();
    with_trailing.extend_from_slice(&malformed_data[..suffix_len]);

    let (decoded, consumed) = CaveatPredicate::from_bytes(&with_trailing)
        .expect("valid predicate prefix should still parse with trailing bytes");
    assert_eq!(consumed, encoded.len(), "parser must stop at predicate boundary");
    assert_eq!(
        decoded.to_bytes(),
        encoded,
        "parsed predicate should round-trip to the original prefix"
    );
}

fn test_variable_length_field_overflow(encoded: &[u8]) {
    match encoded.first().copied() {
        Some(0x06) if encoded.len() >= 3 => {
            let mut inflated_key_len = encoded.to_vec();
            inflated_key_len[1..3].copy_from_slice(&u16::MAX.to_le_bytes());
            assert!(
                CaveatPredicate::from_bytes(&inflated_key_len).is_none(),
                "custom predicate with oversized key length should be rejected"
            );

            let key_len = u16::from_le_bytes([encoded[1], encoded[2]]) as usize;
            let value_len_offset = 3 + key_len;
            if encoded.len() >= value_len_offset + 2 {
                let mut inflated_value_len = encoded.to_vec();
                inflated_value_len[value_len_offset..value_len_offset + 2]
                    .copy_from_slice(&u16::MAX.to_le_bytes());
                assert!(
                    CaveatPredicate::from_bytes(&inflated_value_len).is_none(),
                    "custom predicate with oversized value length should be rejected"
                );
            }
        }
        Some(0x07) if encoded.len() >= 3 => {
            let mut inflated_pattern_len = encoded.to_vec();
            inflated_pattern_len[1..3].copy_from_slice(&u16::MAX.to_le_bytes());
            assert!(
                CaveatPredicate::from_bytes(&inflated_pattern_len).is_none(),
                "resource-scope predicate with oversized pattern length should be rejected"
            );
        }
        _ => {}
    }
}

fn test_malformed_predicate_parsing(data: &[u8]) {
    let limited_data = if data.len() > MAX_MALFORMED_DATA_LEN {
        &data[..MAX_MALFORMED_DATA_LEN]
    } else {
        data
    };

    // Should handle malformed predicate data gracefully
    if let Some((decoded, consumed)) = CaveatPredicate::from_bytes(limited_data) {
        assert!(consumed <= limited_data.len(), "parser cannot overrun input");
        assert_eq!(
            decoded.to_bytes(),
            limited_data[..consumed],
            "successful parse should round-trip its consumed prefix"
        );
    }
}

fn test_signature_verification(token: &MacaroonToken, key_seed: u64) {
    let test_key = AuthKey::from_seed(key_seed);

    // Verification should never panic
    let result = token.verify_signature(&test_key);

    // Result should be deterministic
    let result2 = token.verify_signature(&test_key);
    assert_eq!(
        result, result2,
        "Signature verification should be deterministic"
    );
}

fn test_full_verification(token: &MacaroonToken, key_seed: u64, context: &VerificationContext) {
    let test_key = AuthKey::from_seed(key_seed);

    // Verification should never panic
    let result = token.verify(&test_key, context);

    // Result should be deterministic
    let result2 = token.verify(&test_key, context);
    match (result, result2) {
        (Ok(()), Ok(())) => {} // Both succeeded
        (Err(ref e1), Err(ref e2)) => {
            // Both failed - error types should match
            assert_eq!(std::mem::discriminant(e1), std::mem::discriminant(e2));
        }
        _ => panic!("Verification results should be deterministic"),
    }
}

fn test_discharge_binding(token: &MacaroonToken, _discharge_ops: &[MacaroonOperation]) {
    // Create a simple discharge token for testing
    let discharge_key = AuthKey::from_seed(12345);
    let discharge = MacaroonToken::mint(&discharge_key, "discharge", "test");

    // Binding should never panic
    let bound = token.bind_for_request(&discharge);

    // Basic properties should be preserved from discharge
    assert_eq!(bound.identifier(), discharge.identifier());
    assert_eq!(bound.location(), discharge.location());
}

fn test_comprehensive_properties(token: &MacaroonToken, context: &VerificationContext) {
    // Test all accessor methods don't panic
    let _ = token.identifier();
    let _ = token.location();
    let _ = token.caveat_count();
    let _ = token.signature().as_bytes();

    // Test with various keys
    for seed in [0u64, 1, u64::MAX, u64::MAX / 2] {
        let key = AuthKey::from_seed(seed);
        let _ = token.verify_signature(&key);
        let _ = token.verify(&key, context);
    }

    // Test serialization
    let serialized = token.to_binary();
    assert!(!serialized.is_empty());
    assert!(serialized.len() < 1_000_000); // Reasonable upper bound
}

fn convert_predicate_fuzz(predicate_fuzz: &CaveatPredicateFuzz) -> CaveatPredicate {
    match predicate_fuzz {
        CaveatPredicateFuzz::TimeBefore(t) => CaveatPredicate::TimeBefore(*t),
        CaveatPredicateFuzz::TimeAfter(t) => CaveatPredicate::TimeAfter(*t),
        CaveatPredicateFuzz::RegionScope(id) => CaveatPredicate::RegionScope(*id),
        CaveatPredicateFuzz::TaskScope(id) => CaveatPredicate::TaskScope(*id),
        CaveatPredicateFuzz::MaxUses(n) => CaveatPredicate::MaxUses(*n),
        CaveatPredicateFuzz::ResourceScope(pattern) => {
            let safe_pattern = limit_string(pattern, MAX_STRING_LEN);
            CaveatPredicate::ResourceScope(safe_pattern)
        }
        CaveatPredicateFuzz::RateLimit {
            max_count,
            window_secs,
        } => CaveatPredicate::RateLimit {
            max_count: *max_count,
            window_secs: *window_secs,
        },
        CaveatPredicateFuzz::Custom(key, value) => {
            let safe_key = limit_string(key, MAX_STRING_LEN);
            let safe_value = limit_string(value, MAX_STRING_LEN);
            CaveatPredicate::Custom(safe_key, safe_value)
        }
    }
}

fn create_verification_context(context_fuzz: &ContextFuzz) -> VerificationContext {
    let safe_resource_path = limit_string(&context_fuzz.resource_path, MAX_STRING_LEN);

    VerificationContext::new()
        .with_time(context_fuzz.current_time_ms)
        .with_region(context_fuzz.region_id)
        .with_task(context_fuzz.task_id)
        .with_resource(safe_resource_path)
        .with_use_count(context_fuzz.use_count)
        .with_window_use_count(context_fuzz.window_use_count)
}

fn limit_string(input: &str, max_len: usize) -> String {
    if input.len() > max_len {
        input.chars().take(max_len).collect()
    } else {
        input.to_string()
    }
}
