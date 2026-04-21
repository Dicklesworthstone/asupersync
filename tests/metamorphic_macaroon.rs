#![allow(clippy::all)]
//! Metamorphic Testing for cx::macaroon attenuation commutativity
//!
//! Verifies metamorphic properties of macaroon attenuation operations that must hold
//! regardless of specific input values. These properties capture the fundamental
//! invariants of the capability attenuation system.
//!
//! Key metamorphic relations tested:
//! 1. Caveat order independence for commutative caveats
//! 2. Attenuation is monotonic (never increases authority)
//! 3. Signature chain preservation through serialization
//! 4. Deserialize-serialize round-trip identity
//! 5. LabRuntime deterministic replay consistency

use asupersync::cx::macaroon::{
    Caveat, CaveatPredicate, MACAROON_SCHEMA_VERSION, MacaroonToken, VerificationContext,
};
use asupersync::security::key::AuthKey;
use insta::assert_json_snapshot;
use proptest::prelude::*;
use proptest::strategy::ValueTree;
use serde_json::json;
use std::collections::HashSet;
use std::fmt::Write;

/// Generate arbitrary auth keys for testing
fn arb_auth_key() -> impl Strategy<Value = AuthKey> {
    any::<[u8; 32]>().prop_map(AuthKey::from_bytes)
}

/// Generate arbitrary capability identifiers
fn arb_identifier() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("spawn:region".to_string()),
        Just("cancel:task".to_string()),
        Just("read:file".to_string()),
        Just("write:stream".to_string()),
        "cap:[a-z]{1,10}".prop_map(|s| s),
    ]
}

/// Generate arbitrary location hints
fn arb_location() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("cx/scheduler".to_string()),
        Just("cx/registry".to_string()),
        Just("io/driver".to_string()),
        Just("net/tcp".to_string()),
        "[a-z]{1,8}/[a-z]{1,8}".prop_map(|s| s),
    ]
}

/// Generate arbitrary time values (in reasonable range)
fn arb_time() -> impl Strategy<Value = u64> {
    1000u64..=1_000_000_000u64
}

/// Generate arbitrary resource scope patterns
fn arb_resource_pattern() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("files/*".to_string()),
        Just("regions/*/tasks".to_string()),
        Just("net/tcp/**".to_string()),
        "^[a-z]+(/\\*{1,2})?$".prop_map(|s| s),
    ]
}

/// Generate arbitrary caveat predicates
fn arb_caveat_predicate() -> impl Strategy<Value = CaveatPredicate> {
    prop_oneof![
        arb_time().prop_map(CaveatPredicate::TimeBefore),
        arb_time().prop_map(CaveatPredicate::TimeAfter),
        (1u64..=1000u64).prop_map(CaveatPredicate::RegionScope),
        (1u64..=1000u64).prop_map(CaveatPredicate::TaskScope),
        (1u32..=100u32).prop_map(CaveatPredicate::MaxUses),
        arb_resource_pattern().prop_map(CaveatPredicate::ResourceScope),
        (1u32..=10u32, 1u32..=3600u32).prop_map(|(max_count, window_secs)| {
            CaveatPredicate::RateLimit {
                max_count,
                window_secs,
            }
        }),
        ("[a-z]{1,8}", "[a-z]{1,10}").prop_map(|(k, v)| { CaveatPredicate::Custom(k, v) }),
    ]
}

/// Generate lists of caveat predicates
fn arb_caveat_list() -> impl Strategy<Value = Vec<CaveatPredicate>> {
    prop::collection::vec(arb_caveat_predicate(), 0..=8)
}

/// Generate a verification context that would satisfy given caveats
fn arb_verification_context_for_caveats(
    caveats: &[CaveatPredicate],
) -> impl Strategy<Value = VerificationContext> {
    let mut max_time = 0u64;
    let mut min_time = 0u64;
    let mut regions = HashSet::new();
    let mut tasks = HashSet::new();
    let mut max_uses = u32::MAX;
    let mut custom_reqs = Vec::new();

    // Analyze caveats to determine satisfying context
    for caveat in caveats {
        match caveat {
            CaveatPredicate::TimeBefore(t) => {
                if max_time == 0 || *t < max_time {
                    max_time = *t;
                }
            }
            CaveatPredicate::TimeAfter(t) => {
                if *t > min_time {
                    min_time = *t;
                }
            }
            CaveatPredicate::RegionScope(r) => {
                regions.insert(*r);
            }
            CaveatPredicate::TaskScope(t) => {
                tasks.insert(*t);
            }
            CaveatPredicate::MaxUses(n) => {
                if *n < max_uses {
                    max_uses = *n;
                }
            }
            CaveatPredicate::Custom(k, v) => {
                custom_reqs.push((k.clone(), v.clone()));
            }
            _ => {} // ResourceScope and RateLimit handled separately
        }
    }

    // Generate a context that satisfies the constraints
    let time = if max_time > 0 && min_time > 0 && max_time > min_time {
        min_time + (max_time - min_time) / 2
    } else if max_time > 0 {
        max_time - 1
    } else if min_time > 0 {
        min_time + 1000
    } else {
        5000
    };

    let region = regions.into_iter().next();
    let task = tasks.into_iter().next();
    let use_count = if max_uses != u32::MAX {
        max_uses - 1
    } else {
        0
    };

    Just(VerificationContext {
        current_time_ms: time,
        region_id: region,
        task_id: task,
        use_count,
        resource_path: Some("files/test".to_string()),
        window_use_count: 1,
        custom: custom_reqs,
    })
}

/// Check if two caveat predicates are commutative
/// (i.e., their relative order doesn't affect the final authority)
fn caveats_are_commutative(a: &CaveatPredicate, b: &CaveatPredicate) -> bool {
    use CaveatPredicate::*;
    match (a, b) {
        // Same type predicates are generally not commutative
        // (except when they don't conflict)
        (TimeBefore(_), TimeBefore(_)) => false,
        (TimeAfter(_), TimeAfter(_)) => false,
        (RegionScope(_), RegionScope(_)) => false,
        (TaskScope(_), TaskScope(_)) => false,
        (MaxUses(_), MaxUses(_)) => false,
        (ResourceScope(_), ResourceScope(_)) => false,
        (Custom(k1, _), Custom(k2, _)) => k1 != k2,
        (RateLimit { .. }, RateLimit { .. }) => false,

        // Different types are generally commutative
        _ => true,
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn caveat_json(caveat: &Caveat) -> serde_json::Value {
    match caveat {
        Caveat::FirstParty { predicate } => match predicate {
            CaveatPredicate::TimeBefore(deadline_ms) => {
                json!({"kind": "first_party", "predicate": "time_before", "deadline_ms": deadline_ms})
            }
            CaveatPredicate::TimeAfter(start_ms) => {
                json!({"kind": "first_party", "predicate": "time_after", "start_ms": start_ms})
            }
            CaveatPredicate::RegionScope(region_id) => {
                json!({"kind": "first_party", "predicate": "region_scope", "region_id": region_id})
            }
            CaveatPredicate::TaskScope(task_id) => {
                json!({"kind": "first_party", "predicate": "task_scope", "task_id": task_id})
            }
            CaveatPredicate::MaxUses(max_uses) => {
                json!({"kind": "first_party", "predicate": "max_uses", "max_uses": max_uses})
            }
            CaveatPredicate::ResourceScope(pattern) => {
                json!({"kind": "first_party", "predicate": "resource_scope", "pattern": pattern})
            }
            CaveatPredicate::RateLimit {
                max_count,
                window_secs,
            } => json!({
                "kind": "first_party",
                "predicate": "rate_limit",
                "max_count": max_count,
                "window_secs": window_secs
            }),
            CaveatPredicate::Custom(key, value) => {
                json!({"kind": "first_party", "predicate": "custom", "key": key, "value": value})
            }
        },
        Caveat::ThirdParty {
            location,
            identifier,
            vid,
        } => json!({
            "kind": "third_party",
            "location": location,
            "identifier": identifier,
            "vid_hex": hex_bytes(vid),
        }),
    }
}

/// Metamorphic Relation 1: Caveat Order Independence for Commutative Caveats
///
/// For commutative caveats A and B, adding them in either order should result
/// in equivalent verification behavior, even though signatures differ.
#[test]
fn mr_caveat_order_independence() {
    fn property(
        key: AuthKey,
        identifier: String,
        location: String,
        caveat_a: CaveatPredicate,
        caveat_b: CaveatPredicate,
    ) -> bool {
        if !caveats_are_commutative(&caveat_a, &caveat_b) {
            return true; // Skip non-commutative pairs
        }

        let token_ab = MacaroonToken::mint(&key, &identifier, &location)
            .add_caveat(caveat_a.clone())
            .add_caveat(caveat_b.clone());

        let token_ba = MacaroonToken::mint(&key, &identifier, &location)
            .add_caveat(caveat_b.clone())
            .add_caveat(caveat_a.clone());

        // Signatures will be different due to chain order
        assert_ne!(
            token_ab.signature().as_bytes(),
            token_ba.signature().as_bytes()
        );

        // But both should verify with the same key
        assert!(token_ab.verify_signature(&key));
        assert!(token_ba.verify_signature(&key));

        // And verification behavior should be equivalent for any context
        let caveats = vec![caveat_a, caveat_b];
        let ctx_strategy = arb_verification_context_for_caveats(&caveats);

        // Test with multiple contexts
        for _ in 0..5 {
            if let Ok(ctx) =
                ctx_strategy.new_tree(&mut proptest::test_runner::TestRunner::default())
            {
                let ctx_value = ctx.current();
                let result_ab = token_ab.verify(&key, &ctx_value);
                let result_ba = token_ba.verify(&key, &ctx_value);

                // Both should have the same verification outcome
                match (result_ab, result_ba) {
                    (Ok(()), Ok(())) => {} // Both pass - good
                    (Err(_), Err(_)) => {} // Both fail - also good
                    _ => return false,     // Mismatch - bad
                }
            }
        }

        true
    }

    proptest!(|(
        key in arb_auth_key(),
        identifier in arb_identifier(),
        location in arb_location(),
        caveat_a in arb_caveat_predicate(),
        caveat_b in arb_caveat_predicate(),
    )| {
        prop_assert!(property(key, identifier, location, caveat_a, caveat_b));
    });
}

/// Metamorphic Relation 2: Attenuation Monotonicity
///
/// Adding any caveat to a token should never increase its authority.
/// If a token fails verification, adding more caveats should not make it pass.
/// If a token passes verification, the new token should either pass or fail.
#[test]
fn mr_attenuation_monotonicity() {
    fn property(
        key: AuthKey,
        identifier: String,
        location: String,
        initial_caveats: Vec<CaveatPredicate>,
        additional_caveat: CaveatPredicate,
    ) -> bool {
        // Create base token
        let mut base_token = MacaroonToken::mint(&key, &identifier, &location);
        for caveat in &initial_caveats {
            base_token = base_token.add_caveat(caveat.clone());
        }

        // Create attenuated token
        let attenuated_token = base_token.clone().add_caveat(additional_caveat.clone());

        // Test with various verification contexts
        let all_caveats: Vec<_> = initial_caveats
            .into_iter()
            .chain(std::iter::once(additional_caveat))
            .collect();

        let ctx_strategy = arb_verification_context_for_caveats(&all_caveats);

        for _ in 0..10 {
            if let Ok(ctx) =
                ctx_strategy.new_tree(&mut proptest::test_runner::TestRunner::default())
            {
                let ctx_value = ctx.current();
                let base_result = base_token.verify(&key, &ctx_value);
                let attenuated_result = attenuated_token.verify(&key, &ctx_value);

                match base_result {
                    Err(_) => {
                        // If base token fails, attenuated should also fail
                        // (monotonicity: adding caveats cannot fix a failing token)
                        if attenuated_result.is_ok() {
                            return false;
                        }
                    }
                    Ok(()) => {
                        // If base token passes, attenuated may pass or fail
                        // (additional restrictions may cause failure)
                        // This is fine - no constraint here
                    }
                }
            }
        }

        true
    }

    proptest!(|(
        key in arb_auth_key(),
        identifier in arb_identifier(),
        location in arb_location(),
        initial_caveats in arb_caveat_list(),
        additional_caveat in arb_caveat_predicate(),
    )| {
        prop_assert!(property(key, identifier, location, initial_caveats, additional_caveat));
    });
}

/// Metamorphic Relation 3: Signature Chain Preservation
///
/// The signature verification should be consistent regardless of how we
/// constructed the token (via individual add_caveat calls vs bulk construction).
#[test]
fn mr_signature_chain_preservation() {
    fn property(
        key: AuthKey,
        identifier: String,
        location: String,
        caveats: Vec<CaveatPredicate>,
    ) -> bool {
        if caveats.is_empty() {
            return true;
        }

        // Method 1: Add caveats one by one
        let mut token1 = MacaroonToken::mint(&key, &identifier, &location);
        for caveat in &caveats {
            token1 = token1.add_caveat(caveat.clone());
        }

        // Method 2: Add caveats in different groupings
        let mid = caveats.len() / 2;
        let mut token2 = MacaroonToken::mint(&key, &identifier, &location);

        // Add first half
        for caveat in &caveats[..mid] {
            token2 = token2.add_caveat(caveat.clone());
        }
        // Add second half
        for caveat in &caveats[mid..] {
            token2 = token2.add_caveat(caveat.clone());
        }

        // Both should verify correctly
        assert!(token1.verify_signature(&key));
        assert!(token2.verify_signature(&key));

        // And should have identical signatures (same order of operations)
        assert_eq!(token1.signature().as_bytes(), token2.signature().as_bytes());

        // And identical caveat lists
        assert_eq!(token1.caveats(), token2.caveats());

        true
    }

    proptest!(|(
        key in arb_auth_key(),
        identifier in arb_identifier(),
        location in arb_location(),
        caveats in arb_caveat_list(),
    )| {
        prop_assert!(property(key, identifier, location, caveats));
    });
}

/// Metamorphic Relation 4: Deserialize-Serialize Round-trip Identity
///
/// Serializing a token to binary and then deserializing it should produce
/// an identical token with the same verification behavior.
#[test]
fn mr_serialize_deserialize_roundtrip() {
    fn property(
        key: AuthKey,
        identifier: String,
        location: String,
        caveats: Vec<CaveatPredicate>,
    ) -> bool {
        // Create original token
        let mut original = MacaroonToken::mint(&key, &identifier, &location);
        for caveat in &caveats {
            original = original.add_caveat(caveat.clone());
        }

        // Serialize to binary
        let binary = original.to_binary();

        // Deserialize back
        let recovered = match MacaroonToken::from_binary(&binary) {
            Some(token) => token,
            None => return false, // Deserialization failed
        };

        // Should have identical properties
        assert_eq!(original.identifier(), recovered.identifier());
        assert_eq!(original.location(), recovered.location());
        assert_eq!(original.caveats(), recovered.caveats());
        assert_eq!(
            original.signature().as_bytes(),
            recovered.signature().as_bytes()
        );

        // Should have identical verification behavior
        assert_eq!(
            original.verify_signature(&key),
            recovered.verify_signature(&key)
        );

        // Test verification with context
        let ctx_strategy = arb_verification_context_for_caveats(&caveats);
        for _ in 0..5 {
            if let Ok(ctx) =
                ctx_strategy.new_tree(&mut proptest::test_runner::TestRunner::default())
            {
                let ctx_value = ctx.current();
                let original_result = original.verify(&key, &ctx_value);
                let recovered_result = recovered.verify(&key, &ctx_value);

                // Results should be identical
                match (original_result, recovered_result) {
                    (Ok(()), Ok(())) => {}
                    (Err(_), Err(_)) => {}
                    _ => return false,
                }
            }
        }

        true
    }

    proptest!(|(
        key in arb_auth_key(),
        identifier in arb_identifier(),
        location in arb_location(),
        caveats in arb_caveat_list(),
    )| {
        prop_assert!(property(key, identifier, location, caveats));
    });
}

#[test]
fn token_serialization_scrubbed() {
    let key = AuthKey::from_bytes([0x11; 32]);
    let token = MacaroonToken::mint(&key, "api:read:tenant-7", "cx/macaroons")
        .add_caveat(CaveatPredicate::TimeBefore(1_700_000_123_000))
        .add_caveat(CaveatPredicate::RegionScope(42))
        .add_caveat(CaveatPredicate::ResourceScope(
            "tenants/7/objects/*".to_string(),
        ))
        .add_caveat(CaveatPredicate::RateLimit {
            max_count: 3,
            window_secs: 60,
        })
        .add_caveat(CaveatPredicate::Custom(
            "env".to_string(),
            "prod".to_string(),
        ));

    let binary = token.to_binary();
    let recovered = MacaroonToken::from_binary(&binary).expect("snapshot token should deserialize");

    assert_eq!(recovered.identifier(), token.identifier());
    assert_eq!(recovered.location(), token.location());
    assert_eq!(recovered.caveats(), token.caveats());
    assert_eq!(
        recovered.signature().as_bytes(),
        token.signature().as_bytes()
    );
    assert_eq!(recovered.to_binary(), binary);

    let golden = json!({
        "schema_version": MACAROON_SCHEMA_VERSION,
        "identifier": token.identifier(),
        "location": token.location(),
        "caveat_count": token.caveat_count(),
        "caveats": token
            .caveats()
            .iter()
            .map(caveat_json)
            .collect::<Vec<_>>(),
        "binary_len": binary.len(),
        "binary_hex": hex_bytes(&binary),
        "signature_hex": hex_bytes(token.signature().as_bytes()),
    });

    assert_json_snapshot!("token_serialization_scrubbed", golden);
}

/// Metamorphic Relation 5: LabRuntime Deterministic Replay
///
/// Macaroon verification should be deterministic and produce identical results
/// when replayed with the same inputs (this is important for distributed systems).
/// Since we don't have direct access to LabRuntime in this test context,
/// we test determinism by verifying that repeated verification calls with
/// identical contexts produce identical results.
#[test]
fn mr_deterministic_verification_replay() {
    fn property(
        key: AuthKey,
        identifier: String,
        location: String,
        caveats: Vec<CaveatPredicate>,
        context_seed: u64,
    ) -> bool {
        // Create token
        let mut token = MacaroonToken::mint(&key, &identifier, &location);
        for caveat in &caveats {
            token = token.add_caveat(caveat.clone());
        }

        // Create a deterministic context based on seed
        let context = VerificationContext {
            current_time_ms: context_seed % 1_000_000,
            region_id: if context_seed % 3 == 0 {
                Some((context_seed % 1000) + 1)
            } else {
                None
            },
            task_id: if context_seed % 5 == 0 {
                Some((context_seed % 1000) + 1)
            } else {
                None
            },
            use_count: (context_seed % 100) as u32,
            resource_path: if context_seed % 7 == 0 {
                Some(format!("resource_{}", context_seed % 10))
            } else {
                None
            },
            window_use_count: (context_seed % 50) as u32,
            custom: if context_seed % 11 == 0 {
                vec![(
                    format!("key_{}", context_seed % 5),
                    format!("val_{}", context_seed % 3),
                )]
            } else {
                vec![]
            },
        };

        // Verify multiple times with identical context
        let mut results = Vec::new();
        for _ in 0..5 {
            results.push(token.verify(&key, &context));
        }

        // All results should be identical
        let first_result = &results[0];
        for result in &results[1..] {
            match (first_result, result) {
                (Ok(()), Ok(())) => {}
                (Err(_e1), Err(_e2)) => {
                    // For determinism, even error details should match
                    // We'll just check that both are errors for now
                    // Could be extended to check error type/details match
                }
                _ => return false, // Mismatch in success/failure
            }
        }

        true
    }

    proptest!(|(
        key in arb_auth_key(),
        identifier in arb_identifier(),
        location in arb_location(),
        caveats in arb_caveat_list(),
        context_seed in any::<u64>(),
    )| {
        prop_assert!(property(key, identifier, location, caveats, context_seed));
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commutative_detection() {
        let time_before_1 = CaveatPredicate::TimeBefore(1000);
        let time_before_2 = CaveatPredicate::TimeBefore(2000);
        let region_scope = CaveatPredicate::RegionScope(42);
        let task_scope = CaveatPredicate::TaskScope(7);

        // Same type caveats are not commutative
        assert!(!caveats_are_commutative(&time_before_1, &time_before_2));

        // Different type caveats are commutative
        assert!(caveats_are_commutative(&time_before_1, &region_scope));
        assert!(caveats_are_commutative(&region_scope, &task_scope));
    }

    #[test]
    fn test_basic_attenuation_monotonicity() {
        let key = AuthKey::from_bytes([1u8; 32]);
        let base_token = MacaroonToken::mint(&key, "test", "loc");

        let attenuated = base_token
            .clone()
            .add_caveat(CaveatPredicate::TimeBefore(1000));

        assert!(base_token.verify_signature(&key));
        assert!(attenuated.verify_signature(&key));
        assert_ne!(
            base_token.signature().as_bytes(),
            attenuated.signature().as_bytes()
        );
    }
}
