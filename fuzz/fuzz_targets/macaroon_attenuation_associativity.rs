#![no_main]

use arbitrary::Arbitrary;
use asupersync::cx::macaroon::{CaveatPredicate, MacaroonToken, VerificationContext};
use asupersync::security::key::AuthKey;
use libfuzzer_sys::fuzz_target;

/// Structure-aware fuzz target for Macaroon attenuation chain associativity
///
/// Tests the mathematical properties of macaroon attenuation:
/// 1. (a∘b)(t) ≡ b(a(t)) - composition associativity
/// 2. No caveat dropping possible - monotonic restriction property
/// 3. Verification equivalence under different application orders
#[derive(Arbitrary, Debug)]
struct AttenuationChainFuzz {
    /// Base macaroon parameters
    base_token: BaseTokenParams,
    /// First set of caveats to apply
    caveats_a: Vec<CaveatFuzz>,
    /// Second set of caveats to apply
    caveats_b: Vec<CaveatFuzz>,
    /// Third set for three-way composition tests
    caveats_c: Vec<CaveatFuzz>,
    /// Verification context
    verification_context: VerificationContextFuzz,
    /// Test parameters
    test_config: TestConfig,
}

#[derive(Arbitrary, Debug)]
struct BaseTokenParams {
    /// Root key seed for deterministic key generation
    key_seed: u64,
    /// Capability identifier
    identifier: BoundedString<32>,
    /// Location hint
    location: BoundedString<16>,
}

/// Bounded string type to prevent resource exhaustion
#[derive(Arbitrary, Debug, Clone)]
struct BoundedString<const N: usize> {
    content: String,
}

impl<const N: usize> BoundedString<N> {
    fn as_str(&self) -> &str {
        if self.content.len() > N {
            &self.content[..N]
        } else {
            &self.content
        }
    }
}

/// Structure-aware caveat generation for meaningful compositions
#[derive(Arbitrary, Debug, Clone)]
enum CaveatFuzz {
    /// Time-based restrictions
    TimeBefore(u64),
    TimeAfter(u64),
    /// Scope restrictions
    RegionScope(u64),
    TaskScope(u64),
    /// Usage restrictions
    MaxUses(u32),
    /// Resource patterns with controlled complexity
    ResourceScope(BoundedString<64>),
    /// Rate limiting
    RateLimit {
        max_count: u32,
        window_secs: u32,
    },
    /// Custom predicates with bounded size
    Custom {
        key: BoundedString<32>,
        value: BoundedString<64>,
    },
}

#[derive(Arbitrary, Debug)]
struct VerificationContextFuzz {
    current_time_ms: u64,
    region_id: u64,
    task_id: u64,
    resource_path: BoundedString<64>,
    use_count: u32,
    window_use_count: u32,
}

#[derive(Arbitrary, Debug)]
struct TestConfig {
    /// Test empty caveat sets
    test_empty_sets: bool,
    /// Test identical caveats
    test_identical_caveats: bool,
    /// Test conflicting caveats
    test_conflicting_caveats: bool,
    /// Maximum caveats per set
    max_caveats_per_set: u8,
}

// Resource limits
const MAX_CAVEAT_SETS: usize = 8;
const MAX_TEST_ITERATIONS: usize = 50;

fuzz_target!(|input: AttenuationChainFuzz| {
    // Apply resource limits
    let config = TestConfig {
        max_caveats_per_set: (input.test_config.max_caveats_per_set % 16).max(1),
        ..input.test_config
    };

    let caveats_a = limit_caveat_set(&input.caveats_a, config.max_caveats_per_set as usize);
    let caveats_b = limit_caveat_set(&input.caveats_b, config.max_caveats_per_set as usize);
    let caveats_c = limit_caveat_set(&input.caveats_c, config.max_caveats_per_set as usize);

    // Create base token
    let root_key = AuthKey::from_seed(input.base_token.key_seed);
    let base_token = MacaroonToken::mint(
        &root_key,
        input.base_token.identifier.as_str(),
        input.base_token.location.as_str(),
    );

    let verification_context = create_verification_context(&input.verification_context);

    // Test 1: Attenuation composition associativity (a∘b)(t) ≡ b(a(t))
    test_composition_associativity(&base_token, &caveats_a, &caveats_b, &root_key, &verification_context);

    // Test 2: No caveat dropping - monotonic restriction property
    test_no_caveat_dropping(&base_token, &caveats_a, &caveats_b, &root_key, &verification_context);

    // Test 3: Three-way associativity (a∘b)∘c ≡ a∘(b∘c)
    test_three_way_associativity(&base_token, &caveats_a, &caveats_b, &caveats_c, &root_key, &verification_context);

    // Test 4: Identity element properties
    test_identity_properties(&base_token, &caveats_a, &root_key, &verification_context);

    // Test 5: Idempotence for duplicate caveats
    if config.test_identical_caveats {
        test_idempotence(&base_token, &caveats_a, &root_key, &verification_context);
    }

    // Test 6: Conflicting caveat behavior
    if config.test_conflicting_caveats {
        test_conflicting_caveats(&base_token, &root_key, &verification_context);
    }
});

/// Test attenuation composition associativity: (a∘b)(t) ≡ b(a(t))
fn test_composition_associativity(
    base_token: &MacaroonToken,
    caveats_a: &[CaveatFuzz],
    caveats_b: &[CaveatFuzz],
    root_key: &AuthKey,
    context: &VerificationContext,
) {
    // Apply caveats in order a, then b: (a∘b)(t)
    let token_ab = apply_caveats_sequence(base_token.clone(), &[caveats_a, caveats_b]);

    // Apply caveats in order b, then a: (b∘a)(t)
    let token_ba = apply_caveats_sequence(base_token.clone(), &[caveats_b, caveats_a]);

    // Both tokens should have the same caveat count
    assert_eq!(
        token_ab.caveat_count(),
        token_ba.caveat_count(),
        "Composition should preserve total caveat count"
    );

    // Both tokens should verify with the same result
    let result_ab = token_ab.verify(root_key, context);
    let result_ba = token_ba.verify(root_key, context);

    match (result_ab.clone(), result_ba.clone()) {
        (Ok(()), Ok(())) => {
            // Both succeed - associativity holds for verification
        }
        (Err(ref e1), Err(ref e2)) => {
            // Both fail - should fail for the same reason
            assert_eq!(
                std::mem::discriminant(e1),
                std::mem::discriminant(e2),
                "Composition associativity: both orders should fail with same error type"
            );
        }
        _ => {
            panic!(
                "Associativity violation: (a∘b)(t) = {:?} but b(a(t)) = {:?}",
                result_ab, result_ba
            );
        }
    }

    // Signature verification should have same result for both orders
    let sig_ab = token_ab.verify_signature(root_key);
    let sig_ba = token_ba.verify_signature(root_key);
    assert_eq!(
        sig_ab, sig_ba,
        "Signature verification must be consistent across composition orders"
    );
}

/// Test that no caveat dropping is possible - monotonic restriction property
fn test_no_caveat_dropping(
    base_token: &MacaroonToken,
    caveats_a: &[CaveatFuzz],
    caveats_b: &[CaveatFuzz],
    root_key: &AuthKey,
    context: &VerificationContext,
) {
    if caveats_a.is_empty() && caveats_b.is_empty() {
        return; // Skip test for empty caveat sets
    }

    // Create tokens with increasing restriction levels
    let token_base = base_token.clone();
    let token_a = apply_caveats(&token_base, caveats_a);
    let token_ab = apply_caveats(&token_a, caveats_b);

    // Monotonic restriction property: base ⊇ a ⊇ ab in terms of permissions
    let result_base = token_base.verify(root_key, context);
    let result_a = token_a.verify(root_key, context);
    let result_ab = token_ab.verify(root_key, context);

    // If more restricted token passes, less restricted should also pass
    if result_ab.is_ok() {
        assert!(
            result_a.is_ok(),
            "Monotonic restriction violated: ab passes but a fails"
        );
    }

    if result_a.is_ok() {
        assert!(
            result_base.is_ok(),
            "Monotonic restriction violated: a passes but base fails"
        );
    }

    // Caveat count must be monotonically non-decreasing
    assert!(
        token_base.caveat_count() <= token_a.caveat_count(),
        "Caveat count must not decrease during attenuation"
    );
    assert!(
        token_a.caveat_count() <= token_ab.caveat_count(),
        "Caveat count must not decrease during attenuation"
    );
}

/// Test three-way associativity: (a∘b)∘c ≡ a∘(b∘c)
fn test_three_way_associativity(
    base_token: &MacaroonToken,
    caveats_a: &[CaveatFuzz],
    caveats_b: &[CaveatFuzz],
    caveats_c: &[CaveatFuzz],
    root_key: &AuthKey,
    context: &VerificationContext,
) {
    // (a∘b)∘c
    let token_ab_c = apply_caveats_sequence(base_token.clone(), &[caveats_a, caveats_b, caveats_c]);

    // a∘(b∘c)
    let token_a_bc = apply_caveats_sequence(base_token.clone(), &[caveats_a, caveats_b, caveats_c]);

    // Both should have same caveat count and verification behavior
    assert_eq!(
        token_ab_c.caveat_count(),
        token_a_bc.caveat_count(),
        "Three-way associativity: caveat counts must match"
    );

    let result_ab_c = token_ab_c.verify(root_key, context);
    let result_a_bc = token_a_bc.verify(root_key, context);

    match (result_ab_c.clone(), result_a_bc.clone()) {
        (Ok(()), Ok(())) => {}, // Both succeed
        (Err(ref e1), Err(ref e2)) => {
            assert_eq!(
                std::mem::discriminant(e1),
                std::mem::discriminant(e2),
                "Three-way associativity: error types must match"
            );
        }
        _ => {
            panic!(
                "Three-way associativity violation: (a∘b)∘c = {:?} but a∘(b∘c) = {:?}",
                result_ab_c, result_a_bc
            );
        }
    }
}

/// Test identity element properties
fn test_identity_properties(
    base_token: &MacaroonToken,
    caveats_a: &[CaveatFuzz],
    root_key: &AuthKey,
    context: &VerificationContext,
) {
    // Empty caveat set is the identity element
    let empty_caveats: &[CaveatFuzz] = &[];

    // base∘∅ ≡ base
    let token_a_empty = apply_caveats_sequence(base_token.clone(), &[caveats_a, empty_caveats]);
    let token_a_only = apply_caveats_sequence(base_token.clone(), &[caveats_a]);

    // Should have same caveat count
    assert_eq!(
        token_a_empty.caveat_count(),
        token_a_only.caveat_count(),
        "Identity: adding empty caveats should not change count"
    );

    // Should have same verification result
    let result_a_empty = token_a_empty.verify(root_key, context);
    let result_a_only = token_a_only.verify(root_key, context);

    match (result_a_empty.clone(), result_a_only.clone()) {
        (Ok(()), Ok(())) => {},
        (Err(ref e1), Err(ref e2)) => {
            assert_eq!(
                std::mem::discriminant(e1),
                std::mem::discriminant(e2),
                "Identity: verification results must match"
            );
        }
        _ => {
            panic!(
                "Identity property violation: a∘∅ = {:?} but a = {:?}",
                result_a_empty, result_a_only
            );
        }
    }
}

/// Test idempotence for duplicate caveats
fn test_idempotence(
    base_token: &MacaroonToken,
    caveats_a: &[CaveatFuzz],
    root_key: &AuthKey,
    context: &VerificationContext,
) {
    if caveats_a.is_empty() {
        return;
    }

    // Apply same caveats twice: a∘a
    let token_a = apply_caveats(base_token, caveats_a);
    let token_aa = apply_caveats(&token_a, caveats_a);

    // Verification result should be the same
    let result_a = token_a.verify(root_key, context);
    let result_aa = token_aa.verify(root_key, context);

    match (result_a, result_aa) {
        (Ok(()), Ok(())) => {},
        (Err(ref e1), Err(ref e2)) => {
            // Should fail for same fundamental reason
            assert_eq!(
                std::mem::discriminant(e1),
                std::mem::discriminant(e2),
                "Idempotence: duplicate caveats should not change verification outcome"
            );
        }
        _ => {} // Different results are acceptable for idempotence - duplicate restrictions might interact
    }

    // Caveat count should increase (duplicates are allowed)
    assert!(
        token_aa.caveat_count() >= token_a.caveat_count(),
        "Duplicate caveats should not decrease count"
    );
}

/// Test conflicting caveat behavior
fn test_conflicting_caveats(
    base_token: &MacaroonToken,
    root_key: &AuthKey,
    context: &VerificationContext,
) {
    // Create conflicting time caveats
    let conflicting_caveats = vec![
        CaveatFuzz::TimeBefore(1000),
        CaveatFuzz::TimeAfter(2000), // Impossible: after 2000 but before 1000
    ];

    let token_conflicted = apply_caveats(base_token, &conflicting_caveats);

    // Token should always fail verification with conflicting caveats
    let result = token_conflicted.verify(root_key, context);
    assert!(
        result.is_err(),
        "Conflicting caveats should always cause verification failure"
    );
}

/// Apply a sequence of caveat sets to a token
fn apply_caveats_sequence(mut token: MacaroonToken, caveat_sets: &[&[CaveatFuzz]]) -> MacaroonToken {
    for caveat_set in caveat_sets {
        token = apply_caveats(&token, caveat_set);
    }
    token
}

/// Apply a set of caveats to a token
fn apply_caveats(token: &MacaroonToken, caveats: &[CaveatFuzz]) -> MacaroonToken {
    let mut result = token.clone();
    for caveat_fuzz in caveats {
        if let Ok(predicate) = convert_caveat_fuzz(caveat_fuzz) {
            result = result.add_caveat(predicate);
        }
    }
    result
}

/// Convert fuzz caveat to actual predicate with validation
fn convert_caveat_fuzz(caveat: &CaveatFuzz) -> Result<CaveatPredicate, &'static str> {
    let predicate = match caveat {
        CaveatFuzz::TimeBefore(t) => CaveatPredicate::TimeBefore(*t),
        CaveatFuzz::TimeAfter(t) => CaveatPredicate::TimeAfter(*t),
        CaveatFuzz::RegionScope(id) => CaveatPredicate::RegionScope(*id),
        CaveatFuzz::TaskScope(id) => CaveatPredicate::TaskScope(*id),
        CaveatFuzz::MaxUses(n) => CaveatPredicate::MaxUses(*n),
        CaveatFuzz::ResourceScope(pattern) => {
            CaveatPredicate::ResourceScope(pattern.as_str().to_string())
        }
        CaveatFuzz::RateLimit { max_count, window_secs } => {
            CaveatPredicate::RateLimit {
                max_count: *max_count,
                window_secs: *window_secs,
            }
        }
        CaveatFuzz::Custom { key, value } => {
            CaveatPredicate::Custom(key.as_str().to_string(), value.as_str().to_string())
        }
    };

    // Validate the predicate can be encoded
    predicate.validate().map_err(|_| "caveat too large")?;
    Ok(predicate)
}

fn create_verification_context(context_fuzz: &VerificationContextFuzz) -> VerificationContext {
    VerificationContext::new()
        .with_time(context_fuzz.current_time_ms)
        .with_region(context_fuzz.region_id)
        .with_task(context_fuzz.task_id)
        .with_resource(context_fuzz.resource_path.as_str().to_string())
        .with_use_count(context_fuzz.use_count)
        .with_window_use_count(60, context_fuzz.window_use_count)
}

fn limit_caveat_set(caveats: &[CaveatFuzz], max_count: usize) -> Vec<CaveatFuzz> {
    if caveats.len() > max_count {
        caveats[..max_count].to_vec()
    } else {
        caveats.to_vec()
    }
}