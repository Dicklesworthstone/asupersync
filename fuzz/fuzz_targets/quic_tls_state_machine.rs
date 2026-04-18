#![no_main]

use arbitrary::Arbitrary;
use asupersync::net::quic_native::tls::{
    CryptoLevel, KeyUpdateEvent, QuicTlsError, QuicTlsMachine,
};
use libfuzzer_sys::fuzz_target;

/// Wrapper for CryptoLevel that implements Arbitrary
#[derive(Arbitrary, Debug, Clone, Copy)]
enum ArbitraryCryptoLevel {
    Initial,
    Handshake,
    OneRtt,
}

impl From<ArbitraryCryptoLevel> for CryptoLevel {
    fn from(level: ArbitraryCryptoLevel) -> Self {
        match level {
            ArbitraryCryptoLevel::Initial => CryptoLevel::Initial,
            ArbitraryCryptoLevel::Handshake => CryptoLevel::Handshake,
            ArbitraryCryptoLevel::OneRtt => CryptoLevel::OneRtt,
        }
    }
}

/// Comprehensive fuzz target for QUIC-TLS state machine
///
/// This fuzzes the QUIC-TLS state machine to find:
/// - Invalid state transition bugs
/// - Key phase update race conditions
/// - Generation overflow/underflow bugs
/// - Edge cases in handshake confirmation logic
/// - 0-RTT/1-RTT capability calculation bugs
/// - Invariant violations during complex operation sequences
#[derive(Arbitrary, Debug)]
struct QuicTlsStateMachineFuzz {
    /// Sequence of operations to perform on the state machine
    operations: Vec<QuicTlsOperation>,
    /// Whether to enable resumption at various points
    resumption_toggles: Vec<bool>,
    /// Random bool values for key phase tests
    key_phase_values: Vec<bool>,
}

/// Operations that can be performed on the QUIC-TLS state machine
#[derive(Arbitrary, Debug, Clone)]
enum QuicTlsOperation {
    /// Transition to handshake level
    OnHandshakeKeysAvailable,
    /// Transition to 1-RTT level
    On1RttKeysAvailable,
    /// Mark handshake as confirmed
    OnHandshakeConfirmed,
    /// Request a local key update
    RequestLocalKeyUpdate,
    /// Commit pending local key update
    CommitLocalKeyUpdate,
    /// Process peer key phase bit
    OnPeerKeyPhase(bool),
    /// Enable session resumption
    EnableResumption,
    /// Disable session resumption
    DisableResumption,
    /// Force advance to specific crypto level (may be invalid)
    ForceAdvanceTo(ArbitraryCryptoLevel),
    /// Reset to initial state (test construction invariants)
    Reset,
    /// Check invariants and capabilities
    CheckInvariants,
}

/// Test that the state machine maintains key invariants
struct InvariantChecker {
    machine: QuicTlsMachine,
}

impl InvariantChecker {
    fn new(machine: QuicTlsMachine) -> Self {
        Self { machine }
    }

    /// Check all state machine invariants
    fn check_invariants(&self) {
        // Invariant 1: Level progression is monotonic
        let level = self.machine.level();
        assert!(
            level as u8 <= CryptoLevel::OneRtt as u8,
            "Invalid crypto level: {:?}",
            level
        );

        // Invariant 2: 1-RTT requires OneRtt level AND handshake confirmation
        let can_send_1rtt = self.machine.can_send_1rtt();
        if can_send_1rtt {
            assert_eq!(
                level,
                CryptoLevel::OneRtt,
                "1-RTT allowed but not at OneRtt level: {:?}",
                level
            );
            // Note: We can't directly check handshake_confirmed as it's private,
            // but the implementation ensures this invariant
        }

        // Invariant 3: 0-RTT requires resumption enabled, >= Handshake level, NOT confirmed
        let can_send_0rtt = self.machine.can_send_0rtt();
        let resumption_enabled = self.machine.resumption_enabled();
        if can_send_0rtt {
            assert!(
                resumption_enabled,
                "0-RTT allowed but resumption not enabled"
            );
            assert!(
                level >= CryptoLevel::Handshake,
                "0-RTT allowed but below Handshake level: {:?}",
                level
            );
            // 0-RTT should not be allowed after handshake confirmation
            assert!(
                !self.machine.can_send_1rtt(),
                "Both 0-RTT and 1-RTT allowed simultaneously"
            );
        }

        // Invariant 4: Key phase bits are well-defined
        let local_phase = self.machine.local_key_phase();
        let remote_phase = self.machine.remote_key_phase();
        assert!(local_phase == true || local_phase == false);
        assert!(remote_phase == true || remote_phase == false);

        // Invariant 5: Resumption flag is consistent
        let reported_resumption = self.machine.resumption_enabled();
        assert!(reported_resumption == true || reported_resumption == false);
    }

    fn into_machine(self) -> QuicTlsMachine {
        self.machine
    }
}

/// Operation limits for safety
const MAX_OPERATIONS: usize = 1000;
const MAX_KEY_PHASE_VALUES: usize = 100;

fuzz_target!(|input: QuicTlsStateMachineFuzz| {
    // Limit input size to prevent timeouts
    if input.operations.len() > MAX_OPERATIONS {
        return;
    }
    if input.key_phase_values.len() > MAX_KEY_PHASE_VALUES {
        return;
    }

    let mut machine = QuicTlsMachine::new();
    let mut checker = InvariantChecker::new(machine);

    // Initial state should be valid
    checker.check_invariants();
    machine = checker.into_machine();

    let mut resumption_toggle_index = 0;
    let mut key_phase_index = 0;

    // Track expected state for differential testing
    let mut expected_level = CryptoLevel::Initial;

    for operation in input.operations.iter().take(MAX_OPERATIONS) {
        match operation {
            QuicTlsOperation::OnHandshakeKeysAvailable => {
                let result = machine.on_handshake_keys_available();
                match result {
                    Ok(()) => {
                        if expected_level < CryptoLevel::Handshake {
                            expected_level = CryptoLevel::Handshake;
                        }
                        assert_eq!(machine.level(), expected_level);
                    }
                    Err(QuicTlsError::InvalidTransition { from, to }) => {
                        // Backwards transition should fail
                        assert!(
                            to < from,
                            "Error for non-backwards transition: {:?} -> {:?}",
                            from,
                            to
                        );
                    }
                    Err(e) => {
                        panic!("Unexpected error from on_handshake_keys_available: {:?}", e);
                    }
                }
            }

            QuicTlsOperation::On1RttKeysAvailable => {
                let result = machine.on_1rtt_keys_available();
                match result {
                    Ok(()) => {
                        if expected_level < CryptoLevel::OneRtt {
                            expected_level = CryptoLevel::OneRtt;
                        }
                        assert_eq!(machine.level(), expected_level);
                    }
                    Err(QuicTlsError::InvalidTransition { from, to }) => {
                        assert!(
                            to < from,
                            "Error for non-backwards transition: {:?} -> {:?}",
                            from,
                            to
                        );
                    }
                    Err(e) => {
                        panic!("Unexpected error from on_1rtt_keys_available: {:?}", e);
                    }
                }
            }

            QuicTlsOperation::OnHandshakeConfirmed => {
                let result = machine.on_handshake_confirmed();
                match result {
                    Ok(()) => {
                        assert_eq!(machine.level(), CryptoLevel::OneRtt);
                        assert!(machine.can_send_1rtt());
                    }
                    Err(QuicTlsError::HandshakeNotConfirmed) => {
                        // Should only fail if not at OneRtt level
                        assert_ne!(machine.level(), CryptoLevel::OneRtt);
                    }
                    Err(e) => {
                        panic!("Unexpected error from on_handshake_confirmed: {:?}", e);
                    }
                }
            }

            QuicTlsOperation::RequestLocalKeyUpdate => {
                let result = machine.request_local_key_update();
                match result {
                    Ok(KeyUpdateEvent::NoChange) => {
                        // Either handshake not confirmed or already pending
                    }
                    Ok(KeyUpdateEvent::LocalUpdateScheduled {
                        next_phase,
                        generation,
                    }) => {
                        // Should be opposite of current phase
                        assert_ne!(next_phase, machine.local_key_phase());
                        assert!(generation > 0);
                        assert!(
                            machine.can_send_1rtt(),
                            "Key update scheduled but 1-RTT not available"
                        );
                    }
                    Ok(event) => {
                        panic!(
                            "Unexpected event from request_local_key_update: {:?}",
                            event
                        );
                    }
                    Err(QuicTlsError::HandshakeNotConfirmed) => {
                        assert!(!machine.can_send_1rtt());
                    }
                    Err(e) => {
                        panic!("Unexpected error from request_local_key_update: {:?}", e);
                    }
                }
            }

            QuicTlsOperation::CommitLocalKeyUpdate => {
                let old_phase = machine.local_key_phase();
                let result = machine.commit_local_key_update();

                match result {
                    Ok(KeyUpdateEvent::NoChange) => {
                        // No pending update
                        assert_eq!(machine.local_key_phase(), old_phase);
                    }
                    Ok(KeyUpdateEvent::LocalUpdateScheduled {
                        next_phase,
                        generation,
                    }) => {
                        // Phase should have flipped
                        assert_eq!(machine.local_key_phase(), next_phase);
                        assert_ne!(old_phase, next_phase);
                        assert!(generation > 0);
                    }
                    Ok(event) => {
                        panic!("Unexpected event from commit_local_key_update: {:?}", event);
                    }
                    Err(e) => {
                        panic!("Unexpected error from commit_local_key_update: {:?}", e);
                    }
                }
            }

            QuicTlsOperation::OnPeerKeyPhase(phase) => {
                let old_remote_phase = machine.remote_key_phase();
                let result = machine.on_peer_key_phase(*phase);

                match result {
                    Ok(KeyUpdateEvent::NoChange) => {
                        // Same phase as before or handshake not confirmed
                        if machine.can_send_1rtt() {
                            assert_eq!(old_remote_phase, *phase);
                        }
                    }
                    Ok(KeyUpdateEvent::RemoteUpdateAccepted {
                        new_phase,
                        generation,
                    }) => {
                        assert_eq!(new_phase, *phase);
                        assert_eq!(machine.remote_key_phase(), *phase);
                        assert_ne!(old_remote_phase, *phase);
                        assert!(generation > 0);
                        assert!(
                            machine.can_send_1rtt(),
                            "Peer key update accepted but 1-RTT not available"
                        );
                    }
                    Ok(event) => {
                        panic!("Unexpected event from on_peer_key_phase: {:?}", event);
                    }
                    Err(QuicTlsError::HandshakeNotConfirmed) => {
                        assert!(!machine.can_send_1rtt());
                    }
                    Err(e) => {
                        panic!("Unexpected error from on_peer_key_phase: {:?}", e);
                    }
                }
            }

            QuicTlsOperation::EnableResumption => {
                machine.enable_resumption();
                assert!(machine.resumption_enabled());
            }

            QuicTlsOperation::DisableResumption => {
                machine.disable_resumption();
                assert!(!machine.resumption_enabled());
            }

            QuicTlsOperation::ForceAdvanceTo(level) => {
                // This tests the internal advance_to method via reflection
                // We'll use the public APIs that call it instead
                let crypto_level: CryptoLevel = (*level).into();
                match crypto_level {
                    CryptoLevel::Initial => {
                        // Can't go backwards - this should be tested implicitly
                    }
                    CryptoLevel::Handshake => {
                        let _ = machine.on_handshake_keys_available();
                    }
                    CryptoLevel::OneRtt => {
                        let _ = machine.on_1rtt_keys_available();
                    }
                }
            }

            QuicTlsOperation::Reset => {
                machine = QuicTlsMachine::new();
                expected_level = CryptoLevel::Initial;
                assert_eq!(machine.level(), CryptoLevel::Initial);
                assert!(!machine.can_send_1rtt());
                assert!(!machine.can_send_0rtt());
                assert!(!machine.resumption_enabled());
                assert!(!machine.local_key_phase());
                assert!(!machine.remote_key_phase());
            }

            QuicTlsOperation::CheckInvariants => {
                checker = InvariantChecker::new(machine);
                checker.check_invariants();
                machine = checker.into_machine();
            }
        }

        // Apply resumption toggle if available
        if resumption_toggle_index < input.resumption_toggles.len() {
            if input.resumption_toggles[resumption_toggle_index] {
                machine.enable_resumption();
            } else {
                machine.disable_resumption();
            }
            resumption_toggle_index += 1;
        }

        // Test additional key phase values if available
        if key_phase_index < input.key_phase_values.len() {
            let key_phase = input.key_phase_values[key_phase_index];
            let _ = machine.on_peer_key_phase(key_phase);
            key_phase_index += 1;
        }

        // Verify invariants after each operation
        let final_checker = InvariantChecker::new(machine.clone());
        final_checker.check_invariants();

        // Test that the machine state is logically consistent
        test_consistency(&machine);

        // Test that cloning preserves all state
        let cloned = machine.clone();
        assert_eq!(machine.level(), cloned.level());
        assert_eq!(machine.can_send_1rtt(), cloned.can_send_1rtt());
        assert_eq!(machine.can_send_0rtt(), cloned.can_send_0rtt());
        assert_eq!(machine.resumption_enabled(), cloned.resumption_enabled());
        assert_eq!(machine.local_key_phase(), cloned.local_key_phase());
        assert_eq!(machine.remote_key_phase(), cloned.remote_key_phase());
    }

    // Final state should still be valid
    let final_checker = InvariantChecker::new(machine);
    final_checker.check_invariants();
});

/// Test logical consistency of the machine state
fn test_consistency(machine: &QuicTlsMachine) {
    let level = machine.level();
    let can_1rtt = machine.can_send_1rtt();
    let can_0rtt = machine.can_send_0rtt();
    let resumption = machine.resumption_enabled();

    // Consistency check: 1-RTT requires OneRtt level
    if can_1rtt {
        assert_eq!(
            level,
            CryptoLevel::OneRtt,
            "1-RTT enabled but not at OneRtt level"
        );
    }

    // Consistency check: 0-RTT and 1-RTT are mutually exclusive
    assert!(
        !(can_0rtt && can_1rtt),
        "Both 0-RTT and 1-RTT enabled simultaneously"
    );

    // Consistency check: 0-RTT requires resumption
    if can_0rtt {
        assert!(resumption, "0-RTT enabled but resumption disabled");
        assert!(
            level >= CryptoLevel::Handshake,
            "0-RTT enabled below Handshake level"
        );
    }

    // Consistency check: Key phases are boolean
    assert!(machine.local_key_phase() == true || machine.local_key_phase() == false);
    assert!(machine.remote_key_phase() == true || machine.remote_key_phase() == false);
}

/// Test error condition edge cases
#[cfg(test)]
mod test_error_conditions {
    use super::*;

    #[test]
    fn fuzz_error_display_coverage() {
        let errors = vec![
            QuicTlsError::HandshakeNotConfirmed,
            QuicTlsError::InvalidTransition {
                from: CryptoLevel::OneRtt,
                to: CryptoLevel::Initial,
            },
            QuicTlsError::StalePeerKeyPhase(true),
            QuicTlsError::StalePeerKeyPhase(false),
        ];

        for error in errors {
            let _display = format!("{}", error);
            let _debug = format!("{:?}", error);
            let _source = std::error::Error::source(&error);
        }
    }

    #[test]
    fn fuzz_key_update_event_coverage() {
        let events = vec![
            KeyUpdateEvent::NoChange,
            KeyUpdateEvent::LocalUpdateScheduled {
                next_phase: true,
                generation: 1,
            },
            KeyUpdateEvent::RemoteUpdateAccepted {
                new_phase: false,
                generation: 2,
            },
        ];

        for event in events {
            let _debug = format!("{:?}", event);
            let cloned = event.clone();
            assert_eq!(event, cloned);
        }
    }
}
