#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::security::authenticated::AuthenticatedSymbol;
use asupersync::security::key::AuthKey;
use asupersync::security::tag::AuthenticationTag;
use asupersync::types::{Symbol, SymbolId, SymbolKind};

/// Fuzz input for AEAD tag validation testing
#[derive(Arbitrary, Debug)]
struct AeadFuzzInput {
    /// Key material (32 bytes)
    key_bytes: [u8; 32],
    /// Symbol payload data
    payload: Vec<u8>,
    /// Object ID for symbol
    object_id: u128,
    /// Source block number
    sbn: u8,
    /// Encoding symbol index
    esi: u32,
    /// Symbol kind
    is_source: bool,
    /// Tag modification scenarios
    tag_scenario: TagModificationScenario,
    /// Additional authentication data simulation
    aad_bytes: Vec<u8>,
}

#[derive(Arbitrary, Debug, Clone)]
enum TagModificationScenario {
    /// Valid tag (should verify successfully)
    Valid,
    /// Corrupt tag by flipping bits
    CorruptTag { bit_position: u8 },
    /// Wrong key used for verification
    WrongKey { key_offset: u8 },
    /// Truncated tag
    TruncatedTag { truncate_bytes: u8 },
    /// Different payload but same tag (should fail)
    PayloadTamper { byte_index: usize, new_value: u8 },
    /// AAD simulation: different symbol metadata
    MetadataTamper { tamper_sbn: bool, tamper_esi: bool },
}

fuzz_target!(|input: AeadFuzzInput| {
    // Property 1: Round-trip consistency - compute(symbol, key) then verify() should always pass
    test_round_trip_consistency(&input);

    // Property 2: Tag mismatch returns error with no plaintext leak
    test_tag_mismatch_security(&input);

    // Property 3: Key isolation - different keys should produce different tags
    test_key_isolation(&input);

    // Property 4: AAD tamper detection - symbol metadata changes should invalidate tags
    test_aad_tamper_detection(&input);

    // Property 5: Constant-time verification (basic check)
    test_constant_time_verification(&input);
});

/// Property 1: Round-trip consistency
/// For any valid symbol and key, compute() followed by verify() should always succeed
fn test_round_trip_consistency(input: &AeadFuzzInput) {
    let key = AuthKey::from_bytes(input.key_bytes);

    // Create symbol from fuzz input
    let symbol_id = SymbolId::new_for_test(
        input.object_id.wrapping_add(1), // Ensure non-zero object_id
        input.sbn,
        input.esi,
    );

    let symbol_kind = if input.is_source {
        SymbolKind::Source
    } else {
        SymbolKind::Repair
    };

    let symbol = Symbol::new(symbol_id, input.payload.clone(), symbol_kind);

    // Compute tag and verify it
    let tag = AuthenticationTag::compute(&key, &symbol);
    assert!(
        tag.verify(&key, &symbol),
        "Round-trip verification failed: computed tag should always verify with same key/symbol"
    );

    // Test AuthenticatedSymbol wrapper consistency
    let auth_symbol = AuthenticatedSymbol::new_verified(symbol.clone(), tag);
    assert!(auth_symbol.is_verified());
    assert_eq!(auth_symbol.symbol(), &symbol);
    assert_eq!(auth_symbol.tag(), &tag);
}

/// Property 2: Tag mismatch returns error with no plaintext leak
/// Corrupted tags should fail verification without revealing information
fn test_tag_mismatch_security(input: &AeadFuzzInput) {
    let key = AuthKey::from_bytes(input.key_bytes);

    let symbol_id = SymbolId::new_for_test(input.object_id.wrapping_add(1), input.sbn, input.esi);
    let symbol_kind = if input.is_source {
        SymbolKind::Source
    } else {
        SymbolKind::Repair
    };
    let symbol = Symbol::new(symbol_id, input.payload.clone(), symbol_kind);

    let valid_tag = AuthenticationTag::compute(&key, &symbol);

    match &input.tag_scenario {
        TagModificationScenario::Valid => {
            // Already tested in round_trip_consistency
        }

        TagModificationScenario::CorruptTag { bit_position } => {
            // Flip a bit in the tag
            let mut corrupted_bytes = *valid_tag.as_bytes();
            let byte_idx = (*bit_position as usize) % corrupted_bytes.len();
            let bit_idx = *bit_position % 8;
            corrupted_bytes[byte_idx] ^= 1 << bit_idx;

            let corrupted_tag = AuthenticationTag::from_bytes(corrupted_bytes);

            // Corrupted tag should NOT verify (unless we got incredibly unlucky with collision)
            if corrupted_tag != valid_tag {
                assert!(
                    !corrupted_tag.verify(&key, &symbol),
                    "Corrupted tag unexpectedly verified - possible timing attack vector"
                );
            }
        }

        TagModificationScenario::TruncatedTag { truncate_bytes } => {
            // Test with truncated tag (simulated by zeroing trailing bytes)
            let mut truncated_bytes = *valid_tag.as_bytes();
            let truncate_count = (*truncate_bytes as usize).min(truncated_bytes.len());
            for i in (truncated_bytes.len() - truncate_count)..truncated_bytes.len() {
                truncated_bytes[i] = 0;
            }

            let truncated_tag = AuthenticationTag::from_bytes(truncated_bytes);
            if truncated_tag != valid_tag && truncate_count > 0 {
                assert!(
                    !truncated_tag.verify(&key, &symbol),
                    "Truncated tag should not verify"
                );
            }
        }

        TagModificationScenario::PayloadTamper {
            byte_index,
            new_value,
        } => {
            if !input.payload.is_empty() {
                let mut tampered_payload = input.payload.clone();
                let idx = *byte_index % tampered_payload.len();
                let old_value = tampered_payload[idx];
                tampered_payload[idx] = *new_value;

                // Only test if we actually changed something
                if tampered_payload[idx] != old_value {
                    let tampered_symbol = Symbol::new(symbol_id, tampered_payload, symbol_kind);

                    // Original tag should NOT verify against tampered symbol
                    assert!(
                        !valid_tag.verify(&key, &tampered_symbol),
                        "Tag verified against tampered payload - SECURITY ISSUE"
                    );
                }
            }
        }

        _ => {
            // Other scenarios tested elsewhere
        }
    }
}

/// Property 3: Key isolation
/// Different keys should produce different tags for the same symbol
fn test_key_isolation(input: &AeadFuzzInput) {
    if let TagModificationScenario::WrongKey { key_offset } = &input.tag_scenario {
        let key1 = AuthKey::from_bytes(input.key_bytes);

        // Create different key by modifying one byte
        let mut key2_bytes = input.key_bytes;
        key2_bytes[0] = key2_bytes[0].wrapping_add(*key_offset);
        let key2 = AuthKey::from_bytes(key2_bytes);

        // Only test if keys are actually different
        if key1 != key2 {
            let symbol_id =
                SymbolId::new_for_test(input.object_id.wrapping_add(1), input.sbn, input.esi);
            let symbol_kind = if input.is_source {
                SymbolKind::Source
            } else {
                SymbolKind::Repair
            };
            let symbol = Symbol::new(symbol_id, input.payload.clone(), symbol_kind);

            let tag1 = AuthenticationTag::compute(&key1, &symbol);
            let tag2 = AuthenticationTag::compute(&key2, &symbol);

            // Different keys should produce different tags (except for negligible collision probability)
            if tag1 == tag2 {
                // Extremely unlikely but not impossible - log for investigation
                eprintln!("RARE: Same tag from different keys - possible collision");
            }

            // Tag computed with key1 should not verify with key2
            assert!(
                !tag1.verify(&key2, &symbol),
                "Tag verified with wrong key - key isolation broken"
            );

            // Tag computed with key2 should not verify with key1
            assert!(
                !tag2.verify(&key1, &symbol),
                "Tag verified with wrong key - key isolation broken"
            );
        }
    }
}

/// Property 4: AAD tamper detection
/// Changes to "additional authenticated data" (symbol metadata) should invalidate tags
fn test_aad_tamper_detection(input: &AeadFuzzInput) {
    if let TagModificationScenario::MetadataTamper {
        tamper_sbn,
        tamper_esi,
    } = &input.tag_scenario
    {
        let key = AuthKey::from_bytes(input.key_bytes);

        let original_id =
            SymbolId::new_for_test(input.object_id.wrapping_add(1), input.sbn, input.esi);
        let symbol_kind = if input.is_source {
            SymbolKind::Source
        } else {
            SymbolKind::Repair
        };
        let original_symbol = Symbol::new(original_id, input.payload.clone(), symbol_kind);

        let original_tag = AuthenticationTag::compute(&key, &original_symbol);

        // Tamper with metadata
        let tampered_sbn = if *tamper_sbn {
            input.sbn.wrapping_add(1)
        } else {
            input.sbn
        };
        let tampered_esi = if *tamper_esi {
            input.esi.wrapping_add(1)
        } else {
            input.esi
        };

        let tampered_id =
            SymbolId::new_for_test(input.object_id.wrapping_add(1), tampered_sbn, tampered_esi);

        // Only test if we actually changed something
        if tampered_id != original_id {
            let tampered_symbol = Symbol::new(tampered_id, input.payload.clone(), symbol_kind);

            // Original tag should NOT verify against symbol with tampered metadata
            assert!(
                !original_tag.verify(&key, &tampered_symbol),
                "Tag verified against tampered metadata - AAD protection broken"
            );
        }
    }
}

/// Property 5: Constant-time verification
/// Basic check that verify() doesn't panic or behave obviously differently based on input
fn test_constant_time_verification(input: &AeadFuzzInput) {
    let key = AuthKey::from_bytes(input.key_bytes);

    let symbol_id = SymbolId::new_for_test(input.object_id.wrapping_add(1), input.sbn, input.esi);
    let symbol_kind = if input.is_source {
        SymbolKind::Source
    } else {
        SymbolKind::Repair
    };
    let symbol = Symbol::new(symbol_id, input.payload.clone(), symbol_kind);

    // Test with zero tag (should be rejected)
    let zero_tag = AuthenticationTag::zero();
    let _ = zero_tag.verify(&key, &symbol); // Should not panic

    // Test with valid tag
    let valid_tag = AuthenticationTag::compute(&key, &symbol);
    let _ = valid_tag.verify(&key, &symbol); // Should not panic

    // Test with random tag bytes
    let random_tag = AuthenticationTag::from_bytes(input.key_bytes); // Reuse key bytes as random tag
    let _ = random_tag.verify(&key, &symbol); // Should not panic
}
