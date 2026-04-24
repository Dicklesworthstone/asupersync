//! QUIC-TLS conformance test harness against RFC 9001.
//!
//! This module provides reference implementations and differential testing
//! to verify compliance with the QUIC-TLS specification (RFC 9001).

#![cfg(test)]

use super::tls::*;
use proptest::prelude::*;

/// Reference implementation of QUIC crypto level progression per RFC 9001 §4.1.1
#[derive(Debug, Clone, PartialEq, Eq)]
struct RefCryptoLevelMachine {
    current_level: CryptoLevel,
    handshake_confirmed: bool,
    /// Tracks whether each level has been reached
    level_history: Vec<CryptoLevel>,
}

impl RefCryptoLevelMachine {
    fn new() -> Self {
        Self {
            current_level: CryptoLevel::Initial,
            handshake_confirmed: false,
            level_history: vec![CryptoLevel::Initial],
        }
    }

    /// RFC 9001 §4.1.1: Crypto levels MUST advance monotonically
    fn advance_level(&mut self, target: CryptoLevel) -> Result<(), QuicTlsError> {
        if target < self.current_level {
            return Err(QuicTlsError::InvalidTransition {
                from: self.current_level,
                to: target,
            });
        }
        if target > self.current_level {
            self.current_level = target;
            self.level_history.push(target);
        }
        Ok(())
    }

    fn confirm_handshake(&mut self) -> Result<(), QuicTlsError> {
        // RFC 9001 §4.1.2: Handshake can only be confirmed at 1-RTT level
        if self.current_level != CryptoLevel::OneRtt {
            return Err(QuicTlsError::HandshakeNotConfirmed);
        }
        self.handshake_confirmed = true;
        Ok(())
    }

    /// RFC 9001 §4.6.1: 0-RTT data rules
    fn can_send_0rtt(&self, resumption_enabled: bool) -> bool {
        // 0-RTT requires:
        // 1. At least handshake level reached
        // 2. Handshake NOT yet confirmed
        // 3. Session resumption enabled
        self.current_level >= CryptoLevel::Handshake
            && !self.handshake_confirmed
            && resumption_enabled
    }

    /// RFC 9001: 1-RTT data rules
    fn can_send_1rtt(&self) -> bool {
        // 1-RTT requires both 1-RTT level AND confirmed handshake
        self.current_level == CryptoLevel::OneRtt && self.handshake_confirmed
    }
}

/// Reference implementation of key update protocol per RFC 9001 §6
#[derive(Debug, Clone, PartialEq, Eq)]
struct RefKeyUpdateMachine {
    handshake_confirmed: bool,
    local_key_phase: bool,
    remote_key_phase: bool,
    local_generation: u64,
    remote_generation: u64,
    pending_local_update: bool,
}

impl RefKeyUpdateMachine {
    fn new() -> Self {
        Self {
            handshake_confirmed: false,
            local_key_phase: false,
            remote_key_phase: false,
            local_generation: 0,
            remote_generation: 0,
            pending_local_update: false,
        }
    }

    fn confirm_handshake(&mut self) {
        self.handshake_confirmed = true;
    }

    /// RFC 9001 §6.1: Key updates can only occur after handshake confirmation
    fn request_local_key_update(&mut self) -> Result<KeyUpdateEvent, QuicTlsError> {
        if !self.handshake_confirmed {
            return Err(QuicTlsError::HandshakeNotConfirmed);
        }
        if self.pending_local_update {
            return Ok(KeyUpdateEvent::NoChange);
        }

        self.pending_local_update = true;
        Ok(KeyUpdateEvent::LocalUpdateScheduled {
            next_phase: !self.local_key_phase,
            generation: self.local_generation + 1,
        })
    }

    /// RFC 9001 §6.2: Commit the scheduled key update
    fn commit_local_key_update(&mut self) -> Result<KeyUpdateEvent, QuicTlsError> {
        if !self.pending_local_update {
            return Ok(KeyUpdateEvent::NoChange);
        }

        self.pending_local_update = false;
        self.local_key_phase = !self.local_key_phase;
        self.local_generation += 1;

        Ok(KeyUpdateEvent::LocalUpdateScheduled {
            next_phase: self.local_key_phase,
            generation: self.local_generation,
        })
    }

    /// RFC 9001 §6.3: Process peer key phase changes
    fn on_peer_key_phase(&mut self, phase: bool) -> Result<KeyUpdateEvent, QuicTlsError> {
        if !self.handshake_confirmed {
            return Err(QuicTlsError::HandshakeNotConfirmed);
        }

        if phase == self.remote_key_phase {
            return Ok(KeyUpdateEvent::NoChange);
        }

        self.remote_key_phase = phase;
        self.remote_generation += 1;

        Ok(KeyUpdateEvent::RemoteUpdateAccepted {
            new_phase: self.remote_key_phase,
            generation: self.remote_generation,
        })
    }
}

/// Test suite covering RFC 9001 compliance
mod rfc9001_conformance {
    use super::*;

    /// CONFORMANCE TEST 1: Crypto level progression (RFC 9001 §4.1.1)
    #[test]
    fn rfc9001_4_1_1_crypto_level_monotonic_progression() {
        let test_cases = [
            // Valid progressions
            (vec![CryptoLevel::Handshake], true),
            (vec![CryptoLevel::OneRtt], true),
            (vec![CryptoLevel::Handshake, CryptoLevel::OneRtt], true),
            // Invalid regressions
            (vec![CryptoLevel::Handshake, CryptoLevel::Initial], false),
            (vec![CryptoLevel::OneRtt, CryptoLevel::Handshake], false),
            (vec![CryptoLevel::OneRtt, CryptoLevel::Initial], false),
        ];

        for (sequence, should_succeed) in test_cases {
            let mut reference = RefCryptoLevelMachine::new();
            let mut implementation = QuicTlsMachine::new();

            let mut ref_success = true;
            let mut impl_success = true;

            for &level in &sequence {
                // Test reference implementation
                if reference.advance_level(level).is_err() {
                    ref_success = false;
                }

                // Test actual implementation
                let result = match level {
                    CryptoLevel::Initial => Ok(()), // No-op
                    CryptoLevel::Handshake => implementation.on_handshake_keys_available(),
                    CryptoLevel::OneRtt => implementation.on_1rtt_keys_available(),
                };
                if result.is_err() {
                    impl_success = false;
                }
            }

            assert_eq!(
                ref_success, should_succeed,
                "Reference implementation behavior mismatch for sequence: {:?}",
                sequence
            );
            assert_eq!(
                impl_success, should_succeed,
                "Implementation behavior mismatch for sequence: {:?}",
                sequence
            );
            assert_eq!(
                ref_success, impl_success,
                "Reference vs implementation disagreement for sequence: {:?}",
                sequence
            );
        }
    }

    /// CONFORMANCE TEST 2: Handshake confirmation requirements (RFC 9001 §4.1.2)
    #[test]
    fn rfc9001_4_1_2_handshake_confirmation_rules() {
        // Case 1: Confirm handshake before reaching 1-RTT level
        let mut machine = QuicTlsMachine::new();
        machine.on_handshake_keys_available().unwrap();
        let result = machine.on_handshake_confirmed();
        assert!(
            result.is_err(),
            "Should not confirm handshake before 1-RTT level"
        );

        // Case 2: Confirm handshake at 1-RTT level
        let mut machine = QuicTlsMachine::new();
        machine.on_handshake_keys_available().unwrap();
        machine.on_1rtt_keys_available().unwrap();
        let result = machine.on_handshake_confirmed();
        assert!(result.is_ok(), "Should confirm handshake at 1-RTT level");

        // Verify reference implementation matches
        let mut reference = RefCryptoLevelMachine::new();
        reference.advance_level(CryptoLevel::OneRtt).unwrap();
        let ref_result = reference.confirm_handshake();
        assert!(ref_result.is_ok(), "Reference should also succeed");
    }

    /// CONFORMANCE TEST 3: 0-RTT data transmission rules (RFC 9001 §4.6.1)
    #[test]
    fn rfc9001_4_6_1_zero_rtt_data_rules() {
        let test_cases = [
            // (level, confirmed, resumption, expected_0rtt, expected_1rtt)
            (CryptoLevel::Initial, false, false, false, false),
            (CryptoLevel::Initial, false, true, false, false),
            (CryptoLevel::Handshake, false, false, false, false),
            (CryptoLevel::Handshake, false, true, true, false), // 0-RTT allowed
            (CryptoLevel::OneRtt, false, true, true, false),
            (CryptoLevel::OneRtt, true, true, false, true), // 1-RTT allowed
            (CryptoLevel::OneRtt, true, false, false, true),
        ];

        for (level, confirmed, resumption, expect_0rtt, expect_1rtt) in test_cases {
            // Test implementation
            let mut machine = QuicTlsMachine::new();
            if resumption {
                machine.enable_resumption();
            }

            match level {
                CryptoLevel::Initial => {}
                CryptoLevel::Handshake => {
                    machine.on_handshake_keys_available().unwrap();
                }
                CryptoLevel::OneRtt => {
                    machine.on_handshake_keys_available().unwrap();
                    machine.on_1rtt_keys_available().unwrap();
                }
            }

            if confirmed && level == CryptoLevel::OneRtt {
                machine.on_handshake_confirmed().unwrap();
            }

            assert_eq!(
                machine.can_send_0rtt(),
                expect_0rtt,
                "0-RTT capability mismatch at level {:?}, confirmed={}, resumption={}",
                level,
                confirmed,
                resumption
            );
            assert_eq!(
                machine.can_send_1rtt(),
                expect_1rtt,
                "1-RTT capability mismatch at level {:?}, confirmed={}, resumption={}",
                level,
                confirmed,
                resumption
            );

            // Verify against reference
            let mut reference = RefCryptoLevelMachine::new();
            if level > CryptoLevel::Initial {
                reference.advance_level(level).unwrap();
            }
            if confirmed && level == CryptoLevel::OneRtt {
                reference.confirm_handshake().unwrap();
            }

            assert_eq!(
                reference.can_send_0rtt(resumption),
                expect_0rtt,
                "Reference 0-RTT mismatch"
            );
            assert_eq!(
                reference.can_send_1rtt(),
                expect_1rtt,
                "Reference 1-RTT mismatch"
            );
        }
    }

    /// CONFORMANCE TEST 4: Key update protocol (RFC 9001 §6)
    #[test]
    fn rfc9001_6_key_update_protocol() {
        // Test key updates before handshake confirmation
        let mut machine = QuicTlsMachine::new();
        machine.on_handshake_keys_available().unwrap();
        machine.on_1rtt_keys_available().unwrap();

        let result = machine.request_local_key_update();
        assert!(
            result.is_err(),
            "Key update should fail before handshake confirmation"
        );

        // Test key updates after handshake confirmation
        machine.on_handshake_confirmed().unwrap();

        // Test local key update flow
        let scheduled = machine.request_local_key_update().unwrap();
        assert!(matches!(
            scheduled,
            KeyUpdateEvent::LocalUpdateScheduled { .. }
        ));

        let committed = machine.commit_local_key_update().unwrap();
        assert!(matches!(
            committed,
            KeyUpdateEvent::LocalUpdateScheduled { .. }
        ));

        // Test peer key update
        let peer_update = machine.on_peer_key_phase(true).unwrap();
        assert!(matches!(
            peer_update,
            KeyUpdateEvent::RemoteUpdateAccepted { .. }
        ));

        // Verify against reference implementation
        let mut reference = RefKeyUpdateMachine::new();
        reference.confirm_handshake();

        let ref_scheduled = reference.request_local_key_update().unwrap();
        let ref_committed = reference.commit_local_key_update().unwrap();
        let ref_peer = reference.on_peer_key_phase(true).unwrap();

        assert_eq!(scheduled, ref_scheduled, "Local update scheduling mismatch");
        assert_eq!(committed, ref_committed, "Local update commit mismatch");
        assert_eq!(peer_update, ref_peer, "Peer update mismatch");
    }

    /// CONFORMANCE TEST 5: Key phase bit semantics (RFC 9001 §5.4)
    #[test]
    fn rfc9001_5_4_key_phase_bit_semantics() {
        let mut machine = QuicTlsMachine::new();
        machine.on_handshake_keys_available().unwrap();
        machine.on_1rtt_keys_available().unwrap();
        machine.on_handshake_confirmed().unwrap();

        // Initial key phases should be false (generation 0)
        assert!(!machine.local_key_phase());
        assert!(!machine.remote_key_phase());

        // Local key update should flip local phase
        machine.request_local_key_update().unwrap();
        machine.commit_local_key_update().unwrap();
        assert!(machine.local_key_phase()); // Now true
        assert!(!machine.remote_key_phase()); // Unchanged

        // Second local update should flip back
        machine.request_local_key_update().unwrap();
        machine.commit_local_key_update().unwrap();
        assert!(!machine.local_key_phase()); // Back to false
        assert!(!machine.remote_key_phase()); // Unchanged

        // Peer update should flip remote phase
        machine.on_peer_key_phase(true).unwrap();
        assert!(!machine.local_key_phase()); // Unchanged
        assert!(machine.remote_key_phase()); // Now true
    }
}

/// Property-based conformance tests using proptest
mod property_conformance {
    use super::*;

    prop_compose! {
        fn arb_crypto_sequence()(
            levels in prop::collection::vec(
                prop_oneof![
                    Just(CryptoLevel::Initial),
                    Just(CryptoLevel::Handshake),
                    Just(CryptoLevel::OneRtt)
                ],
                0..5
            )
        ) -> Vec<CryptoLevel> {
            levels
        }
    }

    proptest! {
        /// Property: Any valid monotonic sequence should succeed in both implementations
        #[test]
        fn prop_monotonic_sequences_match(
            sequence in arb_crypto_sequence()
        ) {
            let mut reference = RefCryptoLevelMachine::new();
            let mut implementation = QuicTlsMachine::new();

            let mut ref_levels = vec![];
            let mut impl_levels = vec![];

            for &level in &sequence {
                // Apply to reference
                if reference.advance_level(level).is_ok() {
                    ref_levels.push(level);
                }

                // Apply to implementation
                let result = match level {
                    CryptoLevel::Initial => Ok(()),
                    CryptoLevel::Handshake => implementation.on_handshake_keys_available(),
                    CryptoLevel::OneRtt => implementation.on_1rtt_keys_available(),
                };
                if result.is_ok() {
                    impl_levels.push(level);
                }
            }

            prop_assert_eq!(ref_levels, impl_levels, "Level progression sequences differ");
        }

        /// Property: Key update generations should increment correctly
        #[test]
        fn prop_key_update_generations(update_count in 0u32..10) {
            let mut machine = QuicTlsMachine::new();
            machine.on_handshake_keys_available().unwrap();
            machine.on_1rtt_keys_available().unwrap();
            machine.on_handshake_confirmed().unwrap();

            let mut expected_generation = 0u64;
            let mut expected_phase = false;

            #[allow(clippy::explicit_counter_loop)]
            for _ in 0..update_count { // ignore
                expected_generation += 1;
                expected_phase = !expected_phase;

                let scheduled = machine.request_local_key_update().unwrap();
                if let KeyUpdateEvent::LocalUpdateScheduled { next_phase, generation } = scheduled {
                    prop_assert_eq!(next_phase, expected_phase);
                    prop_assert_eq!(generation, expected_generation);
                } else {
                    prop_assert!(false, "Expected LocalUpdateScheduled event");
                }

                let committed = machine.commit_local_key_update().unwrap();
                if let KeyUpdateEvent::LocalUpdateScheduled { next_phase, generation } = committed {
                    prop_assert_eq!(next_phase, expected_phase);
                    prop_assert_eq!(generation, expected_generation);
                } else {
                    prop_assert!(false, "Expected LocalUpdateScheduled event");
                }

                prop_assert_eq!(machine.local_key_phase(), expected_phase);
            }
        }

        /// Property: Peer key updates should be independent of local updates
        #[test]
        fn prop_peer_key_independence(
            local_updates in 0u32..5,
            peer_updates in prop::collection::vec(any::<bool>(), 0..5)
        ) {
            let mut machine = QuicTlsMachine::new();
            machine.on_handshake_keys_available().unwrap();
            machine.on_1rtt_keys_available().unwrap();
            machine.on_handshake_confirmed().unwrap();

            // Perform local updates
            for _ in 0..local_updates {
                let _ = machine.request_local_key_update();
                let _ = machine.commit_local_key_update();
            }
            let local_phase_after_local_updates = machine.local_key_phase();

            // Perform peer updates
            let mut expected_remote_phase = false;
            for &new_phase in &peer_updates {
                if new_phase != machine.remote_key_phase() {
                    let result = machine.on_peer_key_phase(new_phase).unwrap();
                    if let KeyUpdateEvent::RemoteUpdateAccepted { new_phase: accepted_phase, .. } = result {
                        expected_remote_phase = accepted_phase;
                    }
                }
            }

            // Local phase should be unchanged by peer updates
            prop_assert_eq!(machine.local_key_phase(), local_phase_after_local_updates);
            // Remote phase should match last accepted update
            if !peer_updates.is_empty() {
                prop_assert_eq!(machine.remote_key_phase(), expected_remote_phase);
            }
        }
    }
}

#[cfg(test)]
mod differential_tests {
    use super::*;

    /// Differential test: Implementation vs Reference for full state machine
    #[test]
    fn differential_full_state_machine() {
        let scenarios = vec![
            // Scenario 1: Complete handshake flow
            vec![
                "handshake_keys",
                "1rtt_keys",
                "handshake_confirmed",
                "local_key_update_1",
                "peer_key_update_true",
            ],
            // Scenario 2: Handshake with resumption
            vec![
                "enable_resumption",
                "handshake_keys",
                "check_0rtt_allowed",
                "1rtt_keys",
                "handshake_confirmed",
                "check_0rtt_disabled",
            ],
            // Scenario 3: Multiple key updates
            vec![
                "handshake_keys",
                "1rtt_keys",
                "handshake_confirmed",
                "local_key_update_1",
                "local_key_update_2",
                "local_key_update_3",
                "peer_key_update_true",
                "peer_key_update_false",
            ],
        ];

        for (i, scenario) in scenarios.iter().enumerate() {
            let mut machine = QuicTlsMachine::new();
            let mut ref_crypto = RefCryptoLevelMachine::new();
            let mut ref_key = RefKeyUpdateMachine::new();

            for step in scenario {
                match *step {
                    "enable_resumption" => {
                        machine.enable_resumption();
                    }
                    "handshake_keys" => {
                        machine.on_handshake_keys_available().unwrap();
                        ref_crypto.advance_level(CryptoLevel::Handshake).unwrap();
                    }
                    "1rtt_keys" => {
                        machine.on_1rtt_keys_available().unwrap();
                        ref_crypto.advance_level(CryptoLevel::OneRtt).unwrap();
                    }
                    "handshake_confirmed" => {
                        machine.on_handshake_confirmed().unwrap();
                        ref_crypto.confirm_handshake().unwrap();
                        ref_key.confirm_handshake();
                    }
                    "check_0rtt_allowed" => {
                        assert_eq!(
                            machine.can_send_0rtt(),
                            ref_crypto.can_send_0rtt(machine.resumption_enabled()),
                            "0-RTT capability mismatch in scenario {}",
                            i
                        );
                    }
                    "check_0rtt_disabled" => {
                        assert!(
                            !machine.can_send_0rtt(),
                            "0-RTT should be disabled after confirmation"
                        );
                        assert!(
                            !ref_crypto.can_send_0rtt(true),
                            "Reference 0-RTT should also be disabled"
                        );
                    }
                    "local_key_update_1" | "local_key_update_2" | "local_key_update_3" => {
                        let impl_scheduled = machine.request_local_key_update().unwrap();
                        let ref_scheduled = ref_key.request_local_key_update().unwrap();
                        assert_eq!(
                            impl_scheduled, ref_scheduled,
                            "Local update scheduling mismatch"
                        );

                        let impl_committed = machine.commit_local_key_update().unwrap();
                        let ref_committed = ref_key.commit_local_key_update().unwrap();
                        assert_eq!(
                            impl_committed, ref_committed,
                            "Local update commit mismatch"
                        );
                    }
                    "peer_key_update_true" => {
                        let impl_result = machine.on_peer_key_phase(true).unwrap();
                        let ref_result = ref_key.on_peer_key_phase(true).unwrap();
                        assert_eq!(impl_result, ref_result, "Peer update true mismatch");
                    }
                    "peer_key_update_false" => {
                        let impl_result = machine.on_peer_key_phase(false).unwrap();
                        let ref_result = ref_key.on_peer_key_phase(false).unwrap();
                        assert_eq!(impl_result, ref_result, "Peer update false mismatch");
                    }
                    _ => panic!("Unknown step: {}", step),
                }
            }

            // Final state verification
            assert_eq!(
                machine.level(),
                ref_crypto.current_level,
                "Final crypto level mismatch in scenario {}",
                i
            );
            assert_eq!(
                machine.can_send_1rtt(),
                ref_crypto.can_send_1rtt(),
                "Final 1-RTT capability mismatch in scenario {}",
                i
            );
        }
    }
}
