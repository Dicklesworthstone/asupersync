//! Regression test for high-ESI symbol acceptance during recovery.

use asupersync::distributed::{
    CollectedSymbol, RecoveryConfig, RecoveryDecodingConfig, RecoveryOrchestrator, RecoveryTrigger,
};
use asupersync::security::tag::AuthenticationTag;
use asupersync::types::symbol::{ObjectId, ObjectParams, Symbol};
use asupersync::types::{RegionId, Time};
use std::time::Duration;

#[test]
fn repro_recovery_high_esi_accepted() {
    let mut orchestrator =
        RecoveryOrchestrator::new(RecoveryConfig::default(), RecoveryDecodingConfig::default());

    let trigger = RecoveryTrigger::ManualTrigger {
        region_id: RegionId::new_for_test(1, 0),
        initiator: "test".to_string(),
        reason: None,
    };

    // Parameters: K=10.
    // Max expected source = 10.
    // Old limit = 10 + 100 = 110.
    // New limit = 10 + 50_000 = 50_010.
    let params = ObjectParams::new(ObjectId::new_for_test(1), 1000, 128, 1, 10);

    // Create a symbol with ESI 200 (would fail before fix).
    let high_esi_symbol = CollectedSymbol {
        symbol: Symbol::new_for_test(1, 0, 200, &[0u8; 128]),
        tag: AuthenticationTag::zero(),
        source_replica: "r1".to_string(),
        collected_at: Time::ZERO,
        verified: false,
    };

    // We need 10 symbols to decode.
    // Provide 9 low ESI symbols + 1 high ESI symbol.
    let mut symbols = Vec::new();
    for i in 0..9 {
        symbols.push(CollectedSymbol {
            symbol: Symbol::new_for_test(1, 0, i, &[0u8; 128]),
            tag: AuthenticationTag::zero(),
            source_replica: "r1".to_string(),
            collected_at: Time::ZERO,
            verified: false,
        });
    }
    symbols.push(high_esi_symbol);

    // Attempt recovery.
    // Note: Decoding will fail because the data is just zeroes and doesn't match a real snapshot.
    // BUT, we want to check that it doesn't fail with "CorruptedSymbol" (ESI out of range).
    // It should fail with "DecodingFailed" or similar, or succeed if we disable integrity checks and provide consistent zero data (which RaptorQ might decode to zeroes).
    // Actually, RaptorQ decoding of all-zero symbols results in all-zero output.
    // The `decode_snapshot` step will fail deserialization if it's garbage.
    // So we expect `DecodingFailed` (deserialization error), NOT `CorruptedSymbol`.

    let result =
        orchestrator.recover_from_symbols(&trigger, &symbols, params, Duration::from_millis(10));

    match result {
        Ok(_) => {
            // Surprise success (zeroes decoded to valid snapshot? unlikely but possible if 0 is valid proto)
            // Ideally we check if `metrics.symbols_corrupt` is 0.
            assert_eq!(orchestrator.progress().symbols_collected, 10);
        }
        Err(e) => {
            // Assert it is NOT CorruptedSymbol
            assert_ne!(
                e.kind(),
                asupersync::error::ErrorKind::CorruptedSymbol,
                "High ESI symbol was rejected as corrupt: {e}",
            );
            // It might fail decoding, which is fine for this test.
        }
    }
}
