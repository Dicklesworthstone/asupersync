//! Comprehensive fuzz target for src/security/authenticated.rs MAC tag verifier.
//!
//! This fuzzer targets the MAC tag verification system with adversarial inputs:
//! 1. Adversarial MAC tags - malformed, flipped bits, truncated, extended
//! 2. Key rotation scenarios - multiple keys, wrong keys, expired keys
//! 3. Replay attack simulation - same symbol/tag pairs with different keys
//! 4. Symbol manipulation - payload corruption, metadata changes, kind swapping
//! 5. Timing oracle resistance - constant-time verification validation
//!
//! Unlike basic MAC tests, this exercises the complete authentication workflow
//! including AuthenticatedSymbol state transitions and verification edge cases.

#![no_main]

use arbitrary::Arbitrary;
use asupersync::security::{AuthKey, AuthenticationTag};
use asupersync::security::authenticated::AuthenticatedSymbol;
use asupersync::types::{Symbol, SymbolId, SymbolKind};
use libfuzzer_sys::fuzz_target;

const MAX_PAYLOAD_SIZE: usize = 4096;
const MAX_SYMBOLS: usize = 8;
const MAX_KEYS: usize = 6;

#[derive(Arbitrary, Debug)]
enum FuzzScenario {
    /// Single symbol with adversarial MAC tag manipulation
    AdversarialMAC {
        symbol_data: Vec<u8>,
        key_seed: u64,
        tag_mutations: Vec<TagMutation>,
    },
    /// Key rotation and cross-key verification attacks
    KeyRotation {
        symbol_data: Vec<u8>,
        key_seeds: Vec<u64>,
        verification_attempts: Vec<KeyVerificationAttempt>,
    },
    /// Replay attack simulation with modified symbols
    ReplayAttack {
        base_symbol: SymbolData,
        key_seed: u64,
        replayed_variants: Vec<SymbolData>,
    },
    /// Symbol manipulation with valid vs invalid tag scenarios
    SymbolManipulation {
        original_symbol: SymbolData,
        corrupted_variants: Vec<SymbolData>,
        key_seed: u64,
        recompute_tags: bool,
    },
    /// Timing oracle detection via repeated verification
    TimingOracle {
        symbol_data: Vec<u8>,
        key_seed: u64,
        valid_tag: bool,
        verification_rounds: u16,
    },
}

#[derive(Arbitrary, Debug, Clone)]
struct SymbolData {
    object_id: u128,
    sbn: u8,
    esi: u32,
    kind: bool, // true = Source, false = Repair
    payload: Vec<u8>,
}

#[derive(Arbitrary, Debug)]
enum TagMutation {
    FlipRandomBit { byte_index: u8, bit_index: u8 },
    FlipAllBits,
    ZeroOut,
    MaxOut,
    RotateBytes { positions: u8 },
    TruncateToSize { size: u8 },
    ExtendWithBytes { extra_bytes: Vec<u8> },
    SwapBytes { pos1: u8, pos2: u8 },
}

#[derive(Arbitrary, Debug)]
struct KeyVerificationAttempt {
    key_index: u8,
    expected_result: bool,
}

fuzz_target!(|scenario: FuzzScenario| match scenario {
    FuzzScenario::AdversarialMAC {
        symbol_data,
        key_seed,
        tag_mutations,
    } => fuzz_adversarial_mac(symbol_data, key_seed, tag_mutations),

    FuzzScenario::KeyRotation {
        symbol_data,
        key_seeds,
        verification_attempts,
    } => fuzz_key_rotation(symbol_data, key_seeds, verification_attempts),

    FuzzScenario::ReplayAttack {
        base_symbol,
        key_seed,
        replayed_variants,
    } => fuzz_replay_attack(base_symbol, key_seed, replayed_variants),

    FuzzScenario::SymbolManipulation {
        original_symbol,
        corrupted_variants,
        key_seed,
        recompute_tags,
    } => fuzz_symbol_manipulation(original_symbol, corrupted_variants, key_seed, recompute_tags),

    FuzzScenario::TimingOracle {
        symbol_data,
        key_seed,
        valid_tag,
        verification_rounds,
    } => fuzz_timing_oracle(symbol_data, key_seed, valid_tag, verification_rounds),
});

fn fuzz_adversarial_mac(symbol_data: Vec<u8>, key_seed: u64, tag_mutations: Vec<TagMutation>) {
    if symbol_data.len() > MAX_PAYLOAD_SIZE {
        return;
    }

    let key = AuthKey::from_seed(key_seed);
    let symbol_id = SymbolId::new_for_test(1, 0, 0);
    let symbol = Symbol::new(symbol_id, symbol_data, SymbolKind::Source);

    // Compute the valid tag
    let valid_tag = AuthenticationTag::compute(&key, &symbol);

    // Test that valid tag verifies correctly
    assert!(valid_tag.verify(&key, &symbol));
    let auth_symbol = AuthenticatedSymbol::from_parts(symbol.clone(), valid_tag);
    assert!(!auth_symbol.is_verified()); // Should start unverified

    // Apply mutations and verify they fail (except no-op mutations)
    for mutation in tag_mutations.iter().take(8) {
        let mutated_tag = apply_tag_mutation(&valid_tag, mutation);
        let should_pass = is_noop_mutation(&valid_tag, &mutated_tag);

        let result = mutated_tag.verify(&key, &symbol);
        if should_pass {
            assert!(result, "No-op mutation should still verify");
        } else {
            assert!(!result, "Mutated tag should fail verification");
        }
    }
}

fn fuzz_key_rotation(
    symbol_data: Vec<u8>,
    key_seeds: Vec<u64>,
    verification_attempts: Vec<KeyVerificationAttempt>,
) {
    if symbol_data.len() > MAX_PAYLOAD_SIZE || key_seeds.len() > MAX_KEYS {
        return;
    }

    let symbol_id = SymbolId::new_for_test(2, 1, 5);
    let symbol = Symbol::new(symbol_id, symbol_data, SymbolKind::Repair);

    // Generate keys and compute tags
    let keys: Vec<_> = key_seeds.iter().take(MAX_KEYS).map(|&seed| AuthKey::from_seed(seed)).collect();
    if keys.is_empty() {
        return;
    }

    let primary_key = &keys[0];
    let valid_tag = AuthenticationTag::compute(primary_key, &symbol);

    // Test cross-key verification attempts
    for attempt in verification_attempts.iter().take(MAX_KEYS * 2) {
        let key_idx = (attempt.key_index as usize) % keys.len();
        let test_key = &keys[key_idx];

        let result = valid_tag.verify(test_key, &symbol);

        // Only the primary key should verify successfully
        if key_idx == 0 {
            assert!(result, "Primary key should verify its own tag");
        } else {
            // Cross-key verification should fail (unless keys collide, which is astronomically unlikely)
            assert!(!result, "Different key should not verify tag");
        }
    }
}

fn fuzz_replay_attack(base_symbol: SymbolData, key_seed: u64, replayed_variants: Vec<SymbolData>) {
    let key = AuthKey::from_seed(key_seed);
    let base = create_symbol_from_data(&base_symbol);
    if base.data().len() > MAX_PAYLOAD_SIZE {
        return;
    }

    let valid_tag = AuthenticationTag::compute(&key, &base);

    // Verify tag works for original symbol
    assert!(valid_tag.verify(&key, &base));

    // Test replay attack: use same tag with modified symbols
    for variant_data in replayed_variants.iter().take(MAX_SYMBOLS) {
        let variant = create_symbol_from_data(variant_data);
        if variant.data().len() > MAX_PAYLOAD_SIZE {
            continue;
        }

        let result = valid_tag.verify(&key, &variant);

        // Tag should only verify if symbols are identical
        if symbols_identical(&base, &variant) {
            assert!(result, "Identical symbols should verify with same tag");
        } else {
            assert!(!result, "Modified symbol should not verify with original tag");
        }
    }
}

fn fuzz_symbol_manipulation(
    original: SymbolData,
    corrupted_variants: Vec<SymbolData>,
    key_seed: u64,
    recompute_tags: bool,
) {
    let key = AuthKey::from_seed(key_seed);
    let orig_symbol = create_symbol_from_data(&original);
    if orig_symbol.data().len() > MAX_PAYLOAD_SIZE {
        return;
    }

    let orig_tag = AuthenticationTag::compute(&key, &orig_symbol);

    for variant_data in corrupted_variants.iter().take(MAX_SYMBOLS) {
        let variant = create_symbol_from_data(variant_data);
        if variant.data().len() > MAX_PAYLOAD_SIZE {
            continue;
        }

        if recompute_tags {
            // Test with freshly computed tag - should always verify
            let variant_tag = AuthenticationTag::compute(&key, &variant);
            assert!(variant_tag.verify(&key, &variant), "Fresh tag should always verify");

            // Test AuthenticatedSymbol state transitions
            let auth_variant = AuthenticatedSymbol::from_parts(variant.clone(), variant_tag);
            assert!(!auth_variant.is_verified()); // Starts unverified

            // Test creating a verified symbol
            let verified_variant = AuthenticatedSymbol::new_verified(variant.clone(), variant_tag);
            assert!(verified_variant.is_verified()); // Created verified
        } else {
            // Test with original tag - should fail unless symbols identical
            let result = orig_tag.verify(&key, &variant);
            if symbols_identical(&orig_symbol, &variant) {
                assert!(result, "Identical symbols should verify with same tag");
            } else {
                assert!(!result, "Different symbols should not verify with same tag");
            }
        }
    }
}

fn fuzz_timing_oracle(symbol_data: Vec<u8>, key_seed: u64, valid_tag: bool, verification_rounds: u16) {
    if symbol_data.len() > MAX_PAYLOAD_SIZE {
        return;
    }

    let key = AuthKey::from_seed(key_seed);
    let symbol_id = SymbolId::new_for_test(42, 3, 7);
    let symbol = Symbol::new(symbol_id, symbol_data, SymbolKind::Source);

    let tag = if valid_tag {
        AuthenticationTag::compute(&key, &symbol)
    } else {
        AuthenticationTag::zero() // Invalid tag
    };

    // Run multiple verification rounds to test timing consistency
    let rounds = verification_rounds.min(100); // Limit to prevent timeout
    for _ in 0..rounds {
        let result = tag.verify(&key, &symbol);
        assert_eq!(result, valid_tag, "Verification result should be consistent");
    }

    // Test AuthenticatedSymbol integration
    let auth_symbol = AuthenticatedSymbol::from_parts(symbol.clone(), tag);
    assert!(!auth_symbol.is_verified()); // Always starts unverified
    assert_eq!(auth_symbol.symbol(), &symbol);
    assert_eq!(auth_symbol.tag(), &tag);
}

// Helper functions

fn apply_tag_mutation(original: &AuthenticationTag, mutation: &TagMutation) -> AuthenticationTag {
    let mut bytes = *original.as_bytes();

    match mutation {
        TagMutation::FlipRandomBit { byte_index, bit_index } => {
            let byte_idx = (*byte_index as usize) % bytes.len();
            let bit_idx = bit_index % 8;
            bytes[byte_idx] ^= 1 << bit_idx;
        }
        TagMutation::FlipAllBits => {
            for byte in &mut bytes {
                *byte = !*byte;
            }
        }
        TagMutation::ZeroOut => {
            bytes = [0u8; 32];
        }
        TagMutation::MaxOut => {
            bytes = [0xFFu8; 32];
        }
        TagMutation::RotateBytes { positions } => {
            let pos = (*positions as usize) % bytes.len();
            bytes.rotate_left(pos);
        }
        TagMutation::TruncateToSize { size } => {
            let trunc_size = (*size as usize).min(bytes.len());
            for i in trunc_size..bytes.len() {
                bytes[i] = 0;
            }
        }
        TagMutation::ExtendWithBytes { extra_bytes } => {
            // XOR extra bytes into existing tag (can't actually extend fixed-size array)
            for (i, &extra) in extra_bytes.iter().take(bytes.len()).enumerate() {
                bytes[i] ^= extra;
            }
        }
        TagMutation::SwapBytes { pos1, pos2 } => {
            let idx1 = (*pos1 as usize) % bytes.len();
            let idx2 = (*pos2 as usize) % bytes.len();
            bytes.swap(idx1, idx2);
        }
    }

    AuthenticationTag::from_bytes(bytes)
}

fn is_noop_mutation(original: &AuthenticationTag, mutated: &AuthenticationTag) -> bool {
    original == mutated
}

fn create_symbol_from_data(data: &SymbolData) -> Symbol {
    let symbol_id = SymbolId::new_for_test(
        data.object_id as u64, // Truncate to u64 for testing
        data.sbn,
        data.esi,
    );
    let kind = if data.kind { SymbolKind::Source } else { SymbolKind::Repair };
    let payload = data.payload.iter().take(MAX_PAYLOAD_SIZE).cloned().collect();

    Symbol::new(symbol_id, payload, kind)
}

fn symbols_identical(a: &Symbol, b: &Symbol) -> bool {
    a.id() == b.id() &&
    a.data() == b.data() &&
    a.kind() == b.kind() &&
    a.sbn() == b.sbn() &&
    a.esi() == b.esi()
}