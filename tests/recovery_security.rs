use asupersync::distributed::recovery::{
    CollectedSymbol, RecoveryConfig, RecoveryDecodingConfig, RecoveryOrchestrator, RecoveryTrigger,
};
use asupersync::security::{AuthenticationTag, SecurityContext};
use asupersync::types::symbol::{ObjectId, ObjectParams, Symbol, SymbolId, SymbolKind};
use asupersync::types::{RegionId, Time};
use std::time::Duration;

#[test]
fn orchestrator_trusts_fake_verified_symbol() {
    // Setup security context with a specific key
    let ctx = SecurityContext::for_testing(123);
    
    // Create parameters
    let params = ObjectParams::new(ObjectId::new_for_test(1), 1000, 128, 1, 1);
    
    // Create a FAKE symbol (invalid tag)
    let symbol_data = vec![0u8; 128];
    let symbol = Symbol::new(
        SymbolId::new(params.object_id, 0, 0),
        symbol_data,
        SymbolKind::Source,
    );
    let invalid_tag = AuthenticationTag::zero(); // This tag is definitely invalid for key 123
    
    // Create a CollectedSymbol that CLAIMS to be verified
    let fake_verified_symbol = CollectedSymbol {
        symbol: symbol.clone(),
        tag: invalid_tag,
        source_replica: "malicious".to_string(),
        collected_at: Time::ZERO,
        verified: true, // LIE!
    };
    
    // Configure orchestrator to VERIFY integrity
    let orchestrator_config = RecoveryDecodingConfig {
        verify_integrity: true,
        auth_context: Some(ctx),
        ..Default::default()
    };
    
    let mut orchestrator = RecoveryOrchestrator::new(
        RecoveryConfig::default(),
        orchestrator_config,
    );
    
    let trigger = RecoveryTrigger::ManualTrigger {
        region_id: RegionId::new_for_test(1, 0),
        initiator: "test".to_string(),
        reason: None,
    };
    
    // Attempt recovery
    // If the orchestrator blindly trusts `verified=true`, this will succeed (and be WRONG).
    // If the orchestrator respects `verify_integrity=true`, it should re-verify, see the invalid tag, and FAIL.
    let result = orchestrator.recover_from_symbols(
        &trigger,
        &[fake_verified_symbol],
        params,
        Duration::ZERO,
    );
    
    // Current behavior: Err because we ignore the verified flag when integrity check is enabled.
    assert!(result.is_err(), "Orchestrator should reject the fake symbol despite verified=true flag");
}
