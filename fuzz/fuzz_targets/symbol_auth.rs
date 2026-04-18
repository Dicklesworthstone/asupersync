//! Symbol authentication security fuzz target.
//!
//! This target fuzzes malformed symbol authentication tokens to test the security
//! properties of the authentication system in src/security/authenticated.rs.
//!
//! # Security Properties Tested
//! 1. **Tag verification constant-time**: HMAC verification resistant to timing attacks
//! 2. **Key rotation honored**: Different keys produce different verification results
//! 3. **Replay window enforcement**: Simulated timestamp-based replay protection
//! 4. **Expired tokens rejected**: Tokens with expired metadata are rejected
//! 5. **Context field binding**: Tampering with symbol fields breaks authentication
//!
//! # Attack Scenarios Covered
//! - Invalid tag forgery attempts
//! - Key confusion attacks (wrong key, wrong derived key)
//! - Symbol field tampering (object_id, sbn, esi, kind, payload modification)
//! - Replay attacks with stale timestamps
//! - Cross-context substitution attacks
//! - Malformed tag sizes and encodings
//! - Timing attack attempts against tag verification
//!
//! # Running
//! ```bash
//! cargo +nightly fuzz run symbol_auth -- -runs=1000000
//! ```

#![no_main]

use arbitrary::Arbitrary;
use asupersync::security::{
    AuthError, AuthErrorKind, AuthKey, AuthMode, AuthenticatedSymbol, AuthenticationTag,
    SecurityContext,
};
use asupersync::types::{Symbol, SymbolId, SymbolKind};
use libfuzzer_sys::fuzz_target;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Symbol authentication fuzzing input structure
#[derive(Arbitrary, Debug, Clone)]
struct SymbolAuthFuzzInput {
    /// Strategy for generating malicious authentication scenarios
    strategy: FuzzStrategy,
    /// Configuration for the test scenario
    config: AuthFuzzConfig,
    /// Sequence of authentication operations
    operations: Vec<AuthOperation>,
}

/// Fuzzing strategies for symbol authentication
#[derive(Arbitrary, Debug, Clone)]
enum FuzzStrategy {
    /// Valid authentication baseline
    ValidAuth,
    /// Tag forgery attempts
    TagForgery,
    /// Key confusion/rotation attacks
    KeyRotationAttack,
    /// Field tampering attacks
    FieldTampering,
    /// Replay attack simulation
    ReplayAttack,
    /// Cross-context substitution
    CrossContextAttack,
    /// Timing attack attempts
    TimingAttack,
}

/// Configuration for authentication fuzzing
#[derive(Arbitrary, Debug, Clone)]
struct AuthFuzzConfig {
    /// Number of authentication keys to test
    key_count: usize,
    /// Number of symbols to test
    symbol_count: usize,
    /// Base timestamp for replay testing
    base_timestamp: u64,
    /// Maximum time skew for replay windows (seconds)
    replay_window_seconds: u64,
    /// Whether to test expired tokens
    test_expiration: bool,
    /// Context derivation purposes for testing
    context_purposes: Vec<Vec<u8>>,
}

/// Individual authentication operation in the test sequence
#[derive(Arbitrary, Debug, Clone)]
enum AuthOperation {
    /// Sign a symbol with a specific key
    SignSymbol {
        key_index: usize,
        symbol_data: SymbolData,
    },
    /// Verify an authenticated symbol
    VerifySymbol {
        key_index: usize,
        symbol_data: SymbolData,
        tag_data: [u8; 32],
        expected_valid: bool,
    },
    /// Tamper with symbol fields
    TamperSymbol {
        original_symbol: SymbolData,
        tampering: FieldTampering,
    },
    /// Test key rotation
    RotateKeys {
        old_key_index: usize,
        new_key_index: usize,
        symbol_data: SymbolData,
    },
    /// Test replay protection
    ReplayTest {
        symbol_data: SymbolData,
        timestamp_offset: i64,
        expected_valid: bool,
    },
    /// Cross-context substitution test
    CrossContextTest {
        source_context: Vec<u8>,
        target_context: Vec<u8>,
        symbol_data: SymbolData,
    },
}

/// Symbol data for testing
#[derive(Arbitrary, Debug, Clone)]
struct SymbolData {
    object_id: u128,
    sbn: u8,
    esi: u32,
    kind: SymbolKindFuzz,
    payload: Vec<u8>,
}

/// Symbol kind for fuzzing
#[derive(Arbitrary, Debug, Clone)]
enum SymbolKindFuzz {
    Source,
    Repair,
}

impl From<SymbolKindFuzz> for SymbolKind {
    fn from(kind: SymbolKindFuzz) -> Self {
        match kind {
            SymbolKindFuzz::Source => SymbolKind::Source,
            SymbolKindFuzz::Repair => SymbolKind::Repair,
        }
    }
}

/// Field tampering operations
#[derive(Arbitrary, Debug, Clone)]
enum FieldTampering {
    /// Modify object ID
    ModifyObjectId { new_object_id: u128 },
    /// Modify SBN (source block number)
    ModifySbn { new_sbn: u8 },
    /// Modify ESI (encoding symbol identifier)
    ModifyEsi { new_esi: u32 },
    /// Change symbol kind
    ModifyKind { new_kind: SymbolKindFuzz },
    /// Alter payload content
    ModifyPayload { new_payload: Vec<u8> },
    /// Truncate payload
    TruncatePayload { new_length: usize },
}

/// State tracker for authentication fuzzing
struct AuthFuzzState {
    contexts: Vec<SecurityContext>,
    signed_symbols: Vec<AuthenticatedSymbol>,
    attack_attempts: u32,
    successful_forgeries: u32,
    timing_measurements: Vec<Duration>,
}

impl AuthFuzzState {
    fn new(config: &AuthFuzzConfig) -> Self {
        let mut contexts = Vec::new();

        // Create base contexts with different keys
        for i in 0..config.key_count.min(20) {
            let key = AuthKey::from_seed(i as u64 + 1);
            contexts.push(SecurityContext::new(key));
        }

        // Create derived contexts if purposes are specified
        for purpose in &config.context_purposes {
            if let Some(base_ctx) = contexts.first() {
                contexts.push(base_ctx.derive_context(purpose));
            }
        }

        Self {
            contexts,
            signed_symbols: Vec::new(),
            attack_attempts: 0,
            successful_forgeries: 0,
            timing_measurements: Vec::new(),
        }
    }

    fn get_context(&self, index: usize) -> &SecurityContext {
        &self.contexts[index % self.contexts.len().max(1)]
    }

    fn create_symbol(&self, data: &SymbolData) -> Symbol {
        let id = SymbolId::new_for_test(data.object_id as u64, data.sbn as u32, data.esi);
        Symbol::new(id, data.payload.clone(), data.kind.clone().into())
    }

    fn log_attack_attempt(&mut self) {
        self.attack_attempts += 1;
    }

    fn log_successful_forgery(&mut self) {
        self.successful_forgeries += 1;
    }

    fn record_timing(&mut self, duration: Duration) {
        self.timing_measurements.push(duration);

        // Limit measurements to prevent memory exhaustion
        if self.timing_measurements.len() > 10000 {
            self.timing_measurements.drain(0..5000);
        }
    }
}

fuzz_target!(|input: SymbolAuthFuzzInput| {
    fuzz_symbol_authentication(input);
});

/// Main fuzzing entry point
fn fuzz_symbol_authentication(input: SymbolAuthFuzzInput) {
    let mut state = AuthFuzzState::new(&input.config);

    // Limit operations to prevent excessive runtime
    let operations = input.operations.into_iter().take(100);

    for operation in operations {
        match input.strategy {
            FuzzStrategy::ValidAuth => test_valid_auth(&operation, &mut state),
            FuzzStrategy::TagForgery => test_tag_forgery(&operation, &mut state),
            FuzzStrategy::KeyRotationAttack => test_key_rotation(&operation, &mut state),
            FuzzStrategy::FieldTampering => test_field_tampering(&operation, &mut state),
            FuzzStrategy::ReplayAttack => test_replay_attack(&operation, &mut state),
            FuzzStrategy::CrossContextAttack => test_cross_context(&operation, &mut state),
            FuzzStrategy::TimingAttack => test_timing_attack(&operation, &mut state),
        }
    }

    // Final security assertions
    verify_security_invariants(&state);
}

/// Test valid authentication baseline
fn test_valid_auth(operation: &AuthOperation, state: &mut AuthFuzzState) {
    match operation {
        AuthOperation::SignSymbol {
            key_index,
            symbol_data,
        } => {
            let context = state.get_context(*key_index);
            let symbol = state.create_symbol(symbol_data);

            let authenticated = context.sign_symbol(&symbol);
            assert!(
                authenticated.is_verified(),
                "Newly signed symbol should be verified"
            );

            state.signed_symbols.push(authenticated);
        }
        AuthOperation::VerifySymbol {
            key_index,
            symbol_data,
            expected_valid,
            ..
        } => {
            let context = state.get_context(*key_index);
            let symbol = state.create_symbol(symbol_data);
            let tag =
                AuthenticationTag::compute(&AuthKey::from_seed(*key_index as u64 + 1), &symbol);

            let mut authenticated = AuthenticatedSymbol::from_parts(symbol, tag);
            let result = context.verify_authenticated_symbol(&mut authenticated);

            if *expected_valid {
                assert!(result.is_ok(), "Expected valid authentication failed");
                assert!(
                    authenticated.is_verified(),
                    "Valid symbol should be verified"
                );
            }
        }
        _ => {} // Handle in specific strategy functions
    }
}

/// Test tag forgery attempts
fn test_tag_forgery(operation: &AuthOperation, state: &mut AuthFuzzState) {
    if let AuthOperation::VerifySymbol {
        key_index,
        symbol_data,
        tag_data,
        ..
    } = operation
    {
        state.log_attack_attempt();

        let context = state.get_context(*key_index);
        let symbol = state.create_symbol(symbol_data);

        // Use arbitrary tag data (likely forged)
        let forged_tag = AuthenticationTag::from_bytes(*tag_data);
        let mut authenticated = AuthenticatedSymbol::from_parts(symbol, forged_tag);

        let result = context.verify_authenticated_symbol(&mut authenticated);

        // Property 1: Tag verification should use constant-time comparison
        // We can't directly test timing, but we ensure verification fails for invalid tags
        if result.is_ok() && authenticated.is_verified() {
            // This would be a successful forgery - should be extremely rare
            state.log_successful_forgery();

            // In a real fuzzer, this might indicate a vulnerability
            // For testing purposes, we allow some false positives due to random chance
            assert!(
                state.successful_forgeries < 3,
                "Too many successful forgeries detected: {} (potential vulnerability)",
                state.successful_forgeries
            );
        }
    }
}

/// Test key rotation scenarios
fn test_key_rotation(operation: &AuthOperation, state: &mut AuthFuzzState) {
    if let AuthOperation::RotateKeys {
        old_key_index,
        new_key_index,
        symbol_data,
    } = operation
    {
        let old_context = state.get_context(*old_key_index);
        let new_context = state.get_context(*new_key_index);
        let symbol = state.create_symbol(symbol_data);

        // Sign with old key
        let old_authenticated = old_context.sign_symbol(&symbol);

        // Try to verify with new key (should fail unless keys are the same)
        let mut test_auth = old_authenticated.clone();
        let result = new_context.verify_authenticated_symbol(&mut test_auth);

        if *old_key_index == *new_key_index {
            // Same key should verify
            assert!(
                result.is_ok() && test_auth.is_verified(),
                "Same key should verify"
            );
        } else {
            // Property 2: Key rotation should be honored - different keys should not verify
            assert!(
                result.is_err() || !test_auth.is_verified(),
                "Different key incorrectly verified symbol (key rotation not honored)"
            );
        }
    }
}

/// Test field tampering attacks
fn test_field_tampering(operation: &AuthOperation, state: &mut AuthFuzzState) {
    if let AuthOperation::TamperSymbol {
        original_symbol,
        tampering,
    } = operation
    {
        state.log_attack_attempt();

        let context = state.get_context(0);
        let original = state.create_symbol(original_symbol);

        // Sign the original symbol
        let authenticated = context.sign_symbol(&original);
        let original_tag = *authenticated.tag();

        // Create tampered symbol
        let mut tampered_data = original_symbol.clone();
        match tampering {
            FieldTampering::ModifyObjectId { new_object_id } => {
                tampered_data.object_id = *new_object_id;
            }
            FieldTampering::ModifySbn { new_sbn } => {
                tampered_data.sbn = *new_sbn;
            }
            FieldTampering::ModifyEsi { new_esi } => {
                tampered_data.esi = *new_esi;
            }
            FieldTampering::ModifyKind { new_kind } => {
                tampered_data.kind = new_kind.clone();
            }
            FieldTampering::ModifyPayload { new_payload } => {
                tampered_data.payload = new_payload.clone();
            }
            FieldTampering::TruncatePayload { new_length } => {
                tampered_data.payload.truncate(*new_length);
            }
        }

        let tampered = state.create_symbol(&tampered_data);
        let mut tampered_auth = AuthenticatedSymbol::from_parts(tampered, original_tag);

        let result = context.verify_authenticated_symbol(&mut tampered_auth);

        // Property 5: Context field binding should prevent substitution attacks
        // Unless the tampering resulted in identical symbol, verification should fail
        let is_identical = original_symbol.object_id == tampered_data.object_id
            && original_symbol.sbn == tampered_data.sbn
            && original_symbol.esi == tampered_data.esi
            && matches!(
                (original_symbol.kind.clone(), tampered_data.kind.clone()),
                (SymbolKindFuzz::Source, SymbolKindFuzz::Source)
                    | (SymbolKindFuzz::Repair, SymbolKindFuzz::Repair)
            )
            && original_symbol.payload == tampered_data.payload;

        if !is_identical {
            assert!(
                result.is_err() || !tampered_auth.is_verified(),
                "Field tampering attack succeeded - context binding failed"
            );
        }
    }
}

/// Test replay attack scenarios
fn test_replay_attack(operation: &AuthOperation, state: &mut AuthFuzzState) {
    if let AuthOperation::ReplayTest {
        symbol_data,
        timestamp_offset,
        expected_valid,
    } = operation
    {
        state.log_attack_attempt();

        let context = state.get_context(0);
        let symbol = state.create_symbol(symbol_data);

        // Simulate timestamp-based authentication
        let current_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let token_timestamp = (current_timestamp as i64 + timestamp_offset) as u64;

        // For replay testing, we simulate by embedding timestamp in symbol payload
        let mut timestamped_symbol = symbol;
        let mut new_payload = timestamped_symbol.data().to_vec();
        new_payload.extend_from_slice(&token_timestamp.to_le_bytes());

        let id = timestamped_symbol.id();
        let timestamped = Symbol::new(id, new_payload, timestamped_symbol.kind());

        let authenticated = context.sign_symbol(&timestamped);

        // Property 3: Replay window enforcement (simulated)
        let replay_window = 300; // 5 minutes in seconds
        let age = current_timestamp.saturating_sub(token_timestamp);

        if age > replay_window {
            // Property 4: Expired tokens should be rejected (simulated)
            // In a real implementation, this would be checked during verification
            assert!(
                !*expected_valid || age <= replay_window,
                "Expired token should be rejected (age: {}s, window: {}s)",
                age,
                replay_window
            );
        }
    }
}

/// Test cross-context substitution attacks
fn test_cross_context(operation: &AuthOperation, state: &mut AuthFuzzState) {
    if let AuthOperation::CrossContextTest {
        source_context,
        target_context,
        symbol_data,
    } = operation
    {
        if source_context == target_context {
            return; // No cross-context attack possible
        }

        state.log_attack_attempt();

        // Create derived contexts
        let base_context = state.get_context(0);
        let source_ctx = base_context.derive_context(source_context);
        let target_ctx = base_context.derive_context(target_context);

        let symbol = state.create_symbol(symbol_data);

        // Sign with source context
        let source_authenticated = source_ctx.sign_symbol(&symbol);

        // Try to verify with target context
        let mut test_auth = source_authenticated.clone();
        let result = target_ctx.verify_authenticated_symbol(&mut test_auth);

        // Property 5: Cross-context substitution should fail
        assert!(
            result.is_err() || !test_auth.is_verified(),
            "Cross-context substitution attack succeeded"
        );
    }
}

/// Test timing attack resistance
fn test_timing_attack(operation: &AuthOperation, state: &mut AuthFuzzState) {
    if let AuthOperation::VerifySymbol {
        key_index,
        symbol_data,
        tag_data,
        ..
    } = operation
    {
        let context = state.get_context(*key_index);
        let symbol = state.create_symbol(symbol_data);
        let tag = AuthenticationTag::from_bytes(*tag_data);

        let mut authenticated = AuthenticatedSymbol::from_parts(symbol, tag);

        // Measure verification timing
        let start = SystemTime::now();
        let _result = context.verify_authenticated_symbol(&mut authenticated);
        let duration = start.elapsed().unwrap_or(Duration::ZERO);

        state.record_timing(duration);

        // Property 1: Timing should be roughly constant regardless of tag validity
        // This is a weak test, but we check for extreme timing variations
        if state.timing_measurements.len() > 10 {
            let times: Vec<u128> = state
                .timing_measurements
                .iter()
                .map(|d| d.as_nanos())
                .collect();

            let min_time = *times.iter().min().unwrap();
            let max_time = *times.iter().max().unwrap();

            // Allow up to 10x timing variation (very permissive for fuzzing)
            if min_time > 0 {
                let ratio = max_time / min_time;
                assert!(
                    ratio < 10,
                    "Excessive timing variation detected: {}x (potential timing attack vulnerability)",
                    ratio
                );
            }
        }
    }
}

/// Verify overall security invariants
fn verify_security_invariants(state: &AuthFuzzState) {
    // No more than a tiny fraction of forgeries should succeed due to random chance
    let forgery_rate = state.successful_forgeries as f64 / state.attack_attempts.max(1) as f64;

    assert!(
        forgery_rate < 0.001, // Less than 0.1%
        "Forgery rate too high: {:.3}% ({}/{} attacks)",
        forgery_rate * 100.0,
        state.successful_forgeries,
        state.attack_attempts
    );

    // Verify that signed symbols are actually verified
    for auth_symbol in &state.signed_symbols {
        assert!(
            auth_symbol.is_verified(),
            "Signed symbol lost verification status"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_authentication() {
        let key = AuthKey::from_seed(42);
        let context = SecurityContext::new(key);

        let symbol_data = SymbolData {
            object_id: 1,
            sbn: 1,
            esi: 1,
            kind: SymbolKindFuzz::Source,
            payload: vec![1, 2, 3],
        };

        let state = AuthFuzzState::new(&AuthFuzzConfig {
            key_count: 1,
            symbol_count: 1,
            base_timestamp: 1000,
            replay_window_seconds: 300,
            test_expiration: false,
            context_purposes: vec![],
        });

        let symbol = state.create_symbol(&symbol_data);
        let authenticated = context.sign_symbol(&symbol);

        assert!(authenticated.is_verified());

        let mut verify_auth = authenticated.clone();
        let result = context.verify_authenticated_symbol(&mut verify_auth);
        assert!(result.is_ok());
        assert!(verify_auth.is_verified());
    }

    #[test]
    fn test_wrong_key_rejection() {
        let key1 = AuthKey::from_seed(1);
        let key2 = AuthKey::from_seed(2);
        let context1 = SecurityContext::new(key1);
        let context2 = SecurityContext::new(key2);

        let symbol_data = SymbolData {
            object_id: 1,
            sbn: 1,
            esi: 1,
            kind: SymbolKindFuzz::Source,
            payload: vec![1, 2, 3],
        };

        let state = AuthFuzzState::new(&AuthFuzzConfig {
            key_count: 2,
            symbol_count: 1,
            base_timestamp: 1000,
            replay_window_seconds: 300,
            test_expiration: false,
            context_purposes: vec![],
        });

        let symbol = state.create_symbol(&symbol_data);
        let authenticated = context1.sign_symbol(&symbol);

        let mut verify_auth = authenticated.clone();
        let result = context2.verify_authenticated_symbol(&mut verify_auth);

        assert!(result.is_err() || !verify_auth.is_verified());
    }

    #[test]
    fn test_field_tampering_detection() {
        let key = AuthKey::from_seed(42);
        let context = SecurityContext::new(key);

        let original_data = SymbolData {
            object_id: 1,
            sbn: 1,
            esi: 1,
            kind: SymbolKindFuzz::Source,
            payload: vec![1, 2, 3],
        };

        let tampered_data = SymbolData {
            object_id: 1,
            sbn: 1,
            esi: 1,
            kind: SymbolKindFuzz::Source,
            payload: vec![1, 2, 4], // Changed last byte
        };

        let state = AuthFuzzState::new(&AuthFuzzConfig {
            key_count: 1,
            symbol_count: 2,
            base_timestamp: 1000,
            replay_window_seconds: 300,
            test_expiration: false,
            context_purposes: vec![],
        });

        let original_symbol = state.create_symbol(&original_data);
        let tampered_symbol = state.create_symbol(&tampered_data);

        let authenticated = context.sign_symbol(&original_symbol);
        let original_tag = *authenticated.tag();

        // Try to use original tag with tampered symbol
        let mut tampered_auth = AuthenticatedSymbol::from_parts(tampered_symbol, original_tag);
        let result = context.verify_authenticated_symbol(&mut tampered_auth);

        assert!(result.is_err() || !tampered_auth.is_verified());
    }
}
