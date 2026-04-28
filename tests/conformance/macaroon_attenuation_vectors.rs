#![allow(warnings)]
#![allow(clippy::all)]
//! Conformance vectors for macaroon capability attenuation chains.
//!
//! Tests capability token attenuation invariants:
//! - Root token can be attenuated with first-party caveats without root key
//! - Third-party caveats require discharge macaroons signed with caveat key
//! - All discharges bind to the root authorizing token (not parent discharges)
//! - Verification fails if any caveat in the chain is unsatisfied
//! - Binary serialization is deterministic for identical token structures

use asupersync::cx::macaroon::{
    CaveatPredicate, MacaroonToken, VerificationContext, VerificationError,
};
use asupersync::security::key::AuthKey;

/// Test vector demonstrating basic attenuation chain:
/// Root token → TimeBefore caveat → ResourceScope caveat → Third-party discharge
#[test]
fn vector_basic_attenuation_chain() {
    let root_key = AuthKey::from_seed(1337);
    let third_party_key = AuthKey::from_seed(2448);

    // Step 1: Issuer mints root capability token
    let root_token = MacaroonToken::mint(&root_key, "data:read", "service/data-api");

    // Step 2: Holder attenuates with time-based caveat (no root key needed)
    let time_attenuated = root_token.clone().add_caveat(CaveatPredicate::TimeBefore(10_000));

    // Step 3: Further attenuation with resource scope restriction
    let resource_attenuated = time_attenuated.clone()
        .add_caveat(CaveatPredicate::ResourceScope("/api/users/*".into()));

    // Step 4: Add third-party caveat for authentication check
    let with_third_party = resource_attenuated.clone()
        .add_third_party_caveat("auth.example.com", "user:alice", &third_party_key);

    // Step 5: Third-party authority mints discharge with own restrictions
    let discharge = MacaroonToken::mint(&third_party_key, "user:alice", "auth.example.com")
        .add_caveat(CaveatPredicate::MaxUses(5));

    // Step 6: Holder binds discharge to authorizing token
    let bound_discharge = with_third_party.bind_for_request(&discharge)
        .expect("discharge binding should succeed");

    // Step 7: Verification context satisfies all caveats
    let ctx = VerificationContext::new()
        .with_time(5_000)  // Before 10,000 deadline
        .with_resource("/api/users/123")  // Matches pattern
        .with_use_count(3);  // Under 5 uses limit

    // Step 8: End-to-end verification succeeds
    let verification_result = with_third_party
        .verify_with_discharges(&root_key, &ctx, &[bound_discharge]);

    assert!(verification_result.is_ok(), "Attenuation chain should verify successfully");

    // Freeze binary representations for conformance
    insta::assert_debug_snapshot!("basic_attenuation_root", root_token.to_binary());
    insta::assert_debug_snapshot!("basic_attenuation_time", time_attenuated.to_binary());
    insta::assert_debug_snapshot!("basic_attenuation_resource", resource_attenuated.to_binary());
    insta::assert_debug_snapshot!("basic_attenuation_third_party", with_third_party.to_binary());
    insta::assert_debug_snapshot!("basic_attenuation_discharge", discharge.to_binary());
}

/// Test vector with multiple third-party caveats in sequence:
/// Root → First-party → Third-party A → Third-party B → Discharges for A & B
#[test]
fn vector_multi_third_party_sequence() {
    let root_key = AuthKey::from_seed(8899);
    let auth_key = AuthKey::from_seed(9900);
    let audit_key = AuthKey::from_seed(1011);

    // Chain: Root → RegionScope → AuthCheck → AuditCheck
    let token = MacaroonToken::mint(&root_key, "admin:deploy", "orchestrator")
        .add_caveat(CaveatPredicate::RegionScope(42))
        .add_third_party_caveat("auth.corp.com", "deploy:permissions", &auth_key)
        .add_third_party_caveat("audit.corp.com", "deploy:approval", &audit_key);

    // Auth service issues discharge with time restriction
    let auth_discharge = MacaroonToken::mint(&auth_key, "deploy:permissions", "auth.corp.com")
        .add_caveat(CaveatPredicate::TimeBefore(86_400_000));  // 24 hours

    // Audit service issues discharge with approval ID
    let audit_discharge = MacaroonToken::mint(&audit_key, "deploy:approval", "audit.corp.com")
        .add_caveat(CaveatPredicate::Custom("approval_id".into(), "DEPLOY-2024-001".into()));

    // Both discharges bind to the root token (not each other)
    let bound_auth = token.bind_for_request(&auth_discharge)
        .expect("auth discharge binding should succeed");
    let bound_audit = token.bind_for_request(&audit_discharge)
        .expect("audit discharge binding should succeed");

    // Verification context satisfies all constraints
    let ctx = VerificationContext::new()
        .with_region(42)
        .with_time(3_600_000)  // 1 hour, well before 24h deadline
        .with_custom("approval_id", "DEPLOY-2024-001");

    let verification_result = token
        .verify_with_discharges(&root_key, &ctx, &[bound_auth, bound_audit]);

    assert!(verification_result.is_ok(), "Multi third-party chain should verify");

    // Freeze conformance vectors
    insta::assert_debug_snapshot!("multi_third_party_token", token.to_binary());
    insta::assert_debug_snapshot!("multi_third_party_auth_discharge", auth_discharge.to_binary());
    insta::assert_debug_snapshot!("multi_third_party_audit_discharge", audit_discharge.to_binary());
}

/// Test vector with nested third-party discharges:
/// Root → Third-party A → A's discharge has Third-party B → B's discharge
#[test]
fn vector_nested_third_party_discharges() {
    let root_key = AuthKey::from_seed(4455);
    let gateway_key = AuthKey::from_seed(5566);
    let backend_key = AuthKey::from_seed(6677);

    // Root token delegates to gateway service
    let root_token = MacaroonToken::mint(&root_key, "api:execute", "frontend")
        .add_third_party_caveat("gateway.svc", "route:backend", &gateway_key);

    // Gateway discharge delegates further to backend service
    let gateway_discharge = MacaroonToken::mint(&gateway_key, "route:backend", "gateway.svc")
        .add_caveat(CaveatPredicate::RateLimit { max_count: 100, window_secs: 60 })
        .add_third_party_caveat("backend.svc", "exec:compute", &backend_key);

    // Backend discharge adds final constraints
    let backend_discharge = MacaroonToken::mint(&backend_key, "exec:compute", "backend.svc")
        .add_caveat(CaveatPredicate::TaskScope(12345));

    // ALL discharges bind to the root auth token (spec compliance)
    let bound_gateway = root_token.bind_for_request(&gateway_discharge)
        .expect("gateway discharge binding should succeed");
    let bound_backend = root_token.bind_for_request(&backend_discharge)
        .expect("backend discharge binding should succeed");

    // Context satisfies nested constraints
    let ctx = VerificationContext::new()
        .with_window_use_count(60, 15)  // 15 uses in 60s window, under 100 limit
        .with_task(12345);

    let verification_result = root_token
        .verify_with_discharges(&root_key, &ctx, &[bound_gateway, bound_backend]);

    assert!(verification_result.is_ok(), "Nested discharge chain should verify");

    // Conformance snapshots
    insta::assert_debug_snapshot!("nested_root_token", root_token.to_binary());
    insta::assert_debug_snapshot!("nested_gateway_discharge", gateway_discharge.to_binary());
    insta::assert_debug_snapshot!("nested_backend_discharge", backend_discharge.to_binary());
}

/// Test vector demonstrating attenuation failure modes:
/// Verification fails when caveats are not satisfied
#[test]
fn vector_attenuation_failure_modes() {
    let root_key = AuthKey::from_seed(7788);
    let service_key = AuthKey::from_seed(8899);

    let token = MacaroonToken::mint(&root_key, "file:write", "storage")
        .add_caveat(CaveatPredicate::TimeBefore(5_000))
        .add_caveat(CaveatPredicate::ResourceScope("/tmp/*".into()))
        .add_third_party_caveat("quota.svc", "space:check", &service_key);

    let quota_discharge = MacaroonToken::mint(&service_key, "space:check", "quota.svc")
        .add_caveat(CaveatPredicate::MaxUses(1));

    let bound_discharge = token.bind_for_request(&quota_discharge).unwrap();

    // Test case 1: Expired time caveat
    let expired_ctx = VerificationContext::new()
        .with_time(6_000)  // Past 5,000 deadline
        .with_resource("/tmp/file.txt")
        .with_use_count(0);

    let expired_result = token.verify_with_discharges(&root_key, &expired_ctx, &[bound_discharge.clone()]);
    assert!(matches!(expired_result, Err(VerificationError::CaveatFailed { index: 0, .. })),
            "Should fail on expired time caveat");

    // Test case 2: Resource path mismatch
    let wrong_path_ctx = VerificationContext::new()
        .with_time(4_000)
        .with_resource("/home/secret.txt")  // Outside /tmp/* pattern
        .with_use_count(0);

    let path_result = token.verify_with_discharges(&root_key, &wrong_path_ctx, &[bound_discharge.clone()]);
    assert!(matches!(path_result, Err(VerificationError::CaveatFailed { index: 1, .. })),
            "Should fail on resource scope mismatch");

    // Test case 3: Missing discharge entirely
    let no_discharge_ctx = VerificationContext::new()
        .with_time(4_000)
        .with_resource("/tmp/file.txt")
        .with_use_count(0);

    let no_discharge_result = token.verify_with_discharges(&root_key, &no_discharge_ctx, &[]);
    assert!(matches!(no_discharge_result, Err(VerificationError::MissingDischarge { index: 2, .. })),
            "Should fail when third-party discharge is missing");
}

/// Test vector for deterministic binary serialization:
/// Same logical tokens produce identical byte representations
#[test]
fn vector_deterministic_serialization() {
    let key = AuthKey::from_seed(1122);

    // Build identical tokens via different construction paths
    let token_a = MacaroonToken::mint(&key, "test:identical", "location")
        .add_caveat(CaveatPredicate::TimeBefore(9999))
        .add_caveat(CaveatPredicate::MaxUses(42));

    let token_b = MacaroonToken::mint(&key, "test:identical", "location")
        .add_caveat(CaveatPredicate::TimeBefore(9999))
        .add_caveat(CaveatPredicate::MaxUses(42));

    // Serializations must be byte-identical
    let bytes_a = token_a.to_binary();
    let bytes_b = token_b.to_binary();
    assert_eq!(bytes_a, bytes_b, "Identical tokens must produce identical binary serialization");

    // Round-trip preservation
    let deserialized = MacaroonToken::from_binary(&bytes_a)
        .expect("Well-formed binary should deserialize");

    assert_eq!(deserialized.identifier(), token_a.identifier());
    assert_eq!(deserialized.location(), token_a.location());
    assert_eq!(deserialized.caveat_count(), token_a.caveat_count());
    assert_eq!(deserialized.caveats(), token_a.caveats());
    assert_eq!(deserialized.signature().as_bytes(), token_a.signature().as_bytes());

    // Verification still works post-deserialization
    assert!(deserialized.verify_signature(&key), "Deserialized token should verify");

    insta::assert_debug_snapshot!("deterministic_binary", bytes_a);
}

/// Test vector with comprehensive predicate coverage:
/// Exercises all built-in caveat predicate types in a single chain
#[test]
fn vector_comprehensive_predicate_coverage() {
    let root_key = AuthKey::from_seed(2233);
    let service_key = AuthKey::from_seed(3344);

    // Comprehensive attenuation chain with all predicate types
    let token = MacaroonToken::mint(&root_key, "comprehensive:test", "system")
        .add_caveat(CaveatPredicate::TimeBefore(50_000))
        .add_caveat(CaveatPredicate::TimeAfter(10_000))
        .add_caveat(CaveatPredicate::RegionScope(123))
        .add_caveat(CaveatPredicate::TaskScope(456))
        .add_caveat(CaveatPredicate::MaxUses(10))
        .add_caveat(CaveatPredicate::ResourceScope("/api/v1/*".into()))
        .add_caveat(CaveatPredicate::RateLimit { max_count: 20, window_secs: 300 })
        .add_caveat(CaveatPredicate::Custom("environment".into(), "staging".into()))
        .add_third_party_caveat("validator.svc", "final:check", &service_key);

    // Service discharge adds additional custom constraint
    let service_discharge = MacaroonToken::mint(&service_key, "final:check", "validator.svc")
        .add_caveat(CaveatPredicate::Custom("build_id".into(), "build-789".into()));

    let bound_discharge = token.bind_for_request(&service_discharge).unwrap();

    // Context satisfies ALL constraints
    let ctx = VerificationContext::new()
        .with_time(30_000)  // Between 10,000 and 50,000
        .with_region(123)
        .with_task(456)
        .with_use_count(5)  // Under 10 limit
        .with_resource("/api/v1/data")  // Matches pattern
        .with_window_use_count(300, 8)  // 8 uses in 300s window, under 20 limit
        .with_custom("environment", "staging")
        .with_custom("build_id", "build-789");

    let verification_result = token
        .verify_with_discharges(&root_key, &ctx, &[bound_discharge]);

    assert!(verification_result.is_ok(), "Comprehensive predicate chain should verify");

    // Freeze comprehensive vector
    insta::assert_debug_snapshot!("comprehensive_token", token.to_binary());
    insta::assert_debug_snapshot!("comprehensive_discharge", service_discharge.to_binary());
}

/// Test vector demonstrating round-trip verification invariants:
/// Attenuation chains maintain verification across serialize/deserialize cycles
#[test]
fn vector_round_trip_verification_invariants() {
    let root_key = AuthKey::from_seed(5577);
    let auth_key = AuthKey::from_seed(6688);

    // Original attenuation chain
    let original_token = MacaroonToken::mint(&root_key, "roundtrip:test", "persistence")
        .add_caveat(CaveatPredicate::TimeBefore(15_000))
        .add_third_party_caveat("auth.test", "roundtrip:auth", &auth_key);

    let original_discharge = MacaroonToken::mint(&auth_key, "roundtrip:auth", "auth.test")
        .add_caveat(CaveatPredicate::RegionScope(999));

    let original_bound = original_token.bind_for_request(&original_discharge).unwrap();

    // Serialize all components
    let token_bytes = original_token.to_binary();
    let discharge_bytes = original_discharge.to_binary();
    let bound_bytes = original_bound.to_binary();

    // Deserialize all components
    let restored_token = MacaroonToken::from_binary(&token_bytes)
        .expect("Token should deserialize");
    let restored_discharge = MacaroonToken::from_binary(&discharge_bytes)
        .expect("Discharge should deserialize");
    let restored_bound = MacaroonToken::from_binary(&bound_bytes)
        .expect("Bound discharge should deserialize");

    // Verification context
    let ctx = VerificationContext::new()
        .with_time(12_000)
        .with_region(999);

    // Original verification
    let original_result = original_token
        .verify_with_discharges(&root_key, &ctx, &[original_bound]);
    assert!(original_result.is_ok(), "Original chain should verify");

    // Round-trip verification using restored components
    let roundtrip_result = restored_token
        .verify_with_discharges(&root_key, &ctx, &[restored_bound.clone()]);
    assert!(roundtrip_result.is_ok(), "Round-trip chain should verify identically");

    // Cross-verification: original token with restored discharge
    let cross_result = original_token
        .verify_with_discharges(&root_key, &ctx, &[restored_bound]);
    assert!(cross_result.is_ok(), "Cross-validation should succeed");

    // Structural invariants preserved
    assert_eq!(restored_token.identifier(), original_token.identifier());
    assert_eq!(restored_token.location(), original_token.location());
    assert_eq!(restored_token.caveat_count(), original_token.caveat_count());
    assert_eq!(restored_token.caveats(), original_token.caveats());
    assert_eq!(restored_token.signature().as_bytes(), original_token.signature().as_bytes());

    // Freeze round-trip vectors
    insta::assert_debug_snapshot!("roundtrip_original_token", token_bytes);
    insta::assert_debug_snapshot!("roundtrip_original_discharge", discharge_bytes);
    insta::assert_debug_snapshot!("roundtrip_bound_discharge", bound_bytes);
}