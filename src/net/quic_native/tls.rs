//! QUIC-TLS/key-phase state machine.
//!
//! This module models QUIC crypto-level progression and key updates without
//! coupling to a specific cryptographic backend.

use std::fmt;

/// QUIC crypto level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CryptoLevel {
    /// Initial keys.
    Initial,
    /// Handshake keys.
    Handshake,
    /// Application (1-RTT) keys.
    OneRtt,
}

/// Result event from processing a key-update signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyUpdateEvent {
    /// No change was required.
    NoChange,
    /// A new local key phase was scheduled.
    LocalUpdateScheduled {
        /// Next key phase bit.
        next_phase: bool,
        /// Key generation number.
        generation: u64,
    },
    /// Peer moved to a new key phase.
    RemoteUpdateAccepted {
        /// Accepted peer key phase bit.
        new_phase: bool,
        /// Peer generation number.
        generation: u64,
    },
}

/// TLS/key-phase state machine errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuicTlsError {
    /// Operation requires handshake confirmation.
    HandshakeNotConfirmed,
    /// Invalid crypto-level transition.
    InvalidTransition {
        /// Current crypto level.
        from: CryptoLevel,
        /// Requested level.
        to: CryptoLevel,
    },
    /// Peer key-phase value is stale.
    StalePeerKeyPhase(bool),
}

impl fmt::Display for QuicTlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HandshakeNotConfirmed => write!(f, "handshake not confirmed"),
            Self::InvalidTransition { from, to } => {
                write!(f, "invalid crypto transition: {from:?} -> {to:?}")
            }
            Self::StalePeerKeyPhase(phase) => write!(f, "stale peer key phase: {phase}"),
        }
    }
}

impl std::error::Error for QuicTlsError {}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct KeyEpoch {
    phase: bool,
    generation: u64,
}

/// Native QUIC-TLS progression state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicTlsMachine {
    level: CryptoLevel,
    handshake_confirmed: bool,
    resumption_enabled: bool,
    local: KeyEpoch,
    remote: KeyEpoch,
    pending_local_update: bool,
}

impl Default for QuicTlsMachine {
    fn default() -> Self {
        Self {
            level: CryptoLevel::Initial,
            handshake_confirmed: false,
            resumption_enabled: false,
            local: KeyEpoch::default(),
            remote: KeyEpoch::default(),
            pending_local_update: false,
        }
    }
}

impl QuicTlsMachine {
    /// Create a new TLS machine at `Initial`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Current crypto level.
    #[must_use]
    pub fn level(&self) -> CryptoLevel {
        self.level
    }

    /// Whether 1-RTT traffic is allowed.
    #[must_use]
    pub fn can_send_1rtt(&self) -> bool {
        self.level == CryptoLevel::OneRtt && self.handshake_confirmed
    }

    /// Whether 0-RTT application-data packets are currently allowed.
    #[must_use]
    pub fn can_send_0rtt(&self) -> bool {
        self.level >= CryptoLevel::Handshake && !self.handshake_confirmed && self.resumption_enabled
    }

    /// Whether session resumption is enabled for this handshake.
    #[must_use]
    pub fn resumption_enabled(&self) -> bool {
        self.resumption_enabled
    }

    /// Enable session resumption/0-RTT mode for the current handshake.
    pub fn enable_resumption(&mut self) {
        self.resumption_enabled = true;
    }

    /// Disable session resumption/0-RTT mode.
    pub fn disable_resumption(&mut self) {
        self.resumption_enabled = false;
    }

    /// Current local key phase bit.
    #[must_use]
    pub fn local_key_phase(&self) -> bool {
        self.local.phase
    }

    /// Current remote key phase bit.
    #[must_use]
    pub fn remote_key_phase(&self) -> bool {
        self.remote.phase
    }

    /// Transition to `Handshake` level.
    pub fn on_handshake_keys_available(&mut self) -> Result<(), QuicTlsError> {
        self.advance_to(CryptoLevel::Handshake)
    }

    /// Transition to `OneRtt` level (keys installed).
    pub fn on_1rtt_keys_available(&mut self) -> Result<(), QuicTlsError> {
        self.advance_to(CryptoLevel::OneRtt)
    }

    /// Mark handshake as confirmed.
    pub fn on_handshake_confirmed(&mut self) -> Result<(), QuicTlsError> {
        if self.level != CryptoLevel::OneRtt {
            return Err(QuicTlsError::HandshakeNotConfirmed);
        }
        self.handshake_confirmed = true;
        Ok(())
    }

    /// Request a local key update.
    pub fn request_local_key_update(&mut self) -> Result<KeyUpdateEvent, QuicTlsError> {
        if !self.handshake_confirmed {
            return Err(QuicTlsError::HandshakeNotConfirmed);
        }
        if self.pending_local_update {
            return Ok(KeyUpdateEvent::NoChange);
        }
        self.pending_local_update = true;
        Ok(KeyUpdateEvent::LocalUpdateScheduled {
            next_phase: !self.local.phase,
            generation: self.local.generation + 1,
        })
    }

    /// Commit the pending local key update after keys are installed.
    pub fn commit_local_key_update(&mut self) -> Result<KeyUpdateEvent, QuicTlsError> {
        if !self.pending_local_update {
            return Ok(KeyUpdateEvent::NoChange);
        }
        self.pending_local_update = false;
        self.local.phase = !self.local.phase;
        self.local.generation += 1;
        Ok(KeyUpdateEvent::LocalUpdateScheduled {
            next_phase: self.local.phase,
            generation: self.local.generation,
        })
    }

    /// Process peer key-phase bit from a protected packet.
    pub fn on_peer_key_phase(&mut self, phase: bool) -> Result<KeyUpdateEvent, QuicTlsError> {
        if !self.handshake_confirmed {
            return Err(QuicTlsError::HandshakeNotConfirmed);
        }
        if phase == self.remote.phase {
            return Ok(KeyUpdateEvent::NoChange);
        }
        self.remote.phase = phase;
        self.remote.generation += 1;
        Ok(KeyUpdateEvent::RemoteUpdateAccepted {
            new_phase: self.remote.phase,
            generation: self.remote.generation,
        })
    }

    fn advance_to(&mut self, target: CryptoLevel) -> Result<(), QuicTlsError> {
        if target < self.level {
            return Err(QuicTlsError::InvalidTransition {
                from: self.level,
                to: target,
            });
        }
        if target > self.level {
            self.level = target;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[test]
    fn level_transitions_are_monotonic() {
        let mut m = QuicTlsMachine::new();
        assert_eq!(m.level(), CryptoLevel::Initial);
        m.on_handshake_keys_available().expect("handshake keys");
        assert_eq!(m.level(), CryptoLevel::Handshake);
        m.on_1rtt_keys_available().expect("1rtt keys");
        assert_eq!(m.level(), CryptoLevel::OneRtt);
        let err = m.advance_to(CryptoLevel::Initial).expect_err("must fail");
        assert_eq!(
            err,
            QuicTlsError::InvalidTransition {
                from: CryptoLevel::OneRtt,
                to: CryptoLevel::Initial
            }
        );
    }

    #[test]
    fn key_update_requires_confirmed_handshake() {
        let mut m = QuicTlsMachine::new();
        m.on_handshake_keys_available().expect("handshake");
        m.on_1rtt_keys_available().expect("1rtt");
        let err = m.request_local_key_update().expect_err("must fail");
        assert_eq!(err, QuicTlsError::HandshakeNotConfirmed);
    }

    #[test]
    fn local_key_update_flow() {
        let mut m = QuicTlsMachine::new();
        m.on_handshake_keys_available().expect("handshake");
        m.on_1rtt_keys_available().expect("1rtt");
        m.on_handshake_confirmed().expect("confirmed");
        assert!(!m.local_key_phase());

        let scheduled = m.request_local_key_update().expect("schedule");
        assert_eq!(
            scheduled,
            KeyUpdateEvent::LocalUpdateScheduled {
                next_phase: true,
                generation: 1
            }
        );
        let committed = m.commit_local_key_update().expect("commit");
        assert_eq!(
            committed,
            KeyUpdateEvent::LocalUpdateScheduled {
                next_phase: true,
                generation: 1
            }
        );
        assert!(m.local_key_phase());
    }

    #[test]
    fn peer_key_phase_updates_are_applied() {
        let mut m = QuicTlsMachine::new();
        m.on_handshake_keys_available().expect("handshake");
        m.on_1rtt_keys_available().expect("1rtt");
        m.on_handshake_confirmed().expect("confirmed");

        let evt = m.on_peer_key_phase(true).expect("peer update");
        assert_eq!(
            evt,
            KeyUpdateEvent::RemoteUpdateAccepted {
                new_phase: true,
                generation: 1
            }
        );
        assert!(m.remote_key_phase());
    }

    // --- gap-filling tests ---

    #[test]
    fn on_peer_key_phase_before_handshake_confirmed() {
        let mut m = QuicTlsMachine::new();
        m.on_handshake_keys_available().expect("handshake");
        m.on_1rtt_keys_available().expect("1rtt");
        // handshake NOT confirmed
        let err = m.on_peer_key_phase(true).expect_err("must fail");
        assert_eq!(err, QuicTlsError::HandshakeNotConfirmed);
    }

    #[test]
    fn on_peer_key_phase_same_phase_returns_no_change() {
        let mut m = QuicTlsMachine::new();
        m.on_handshake_keys_available().expect("handshake");
        m.on_1rtt_keys_available().expect("1rtt");
        m.on_handshake_confirmed().expect("confirmed");

        // Remote phase starts at false; sending false again is same phase.
        let evt = m.on_peer_key_phase(false).expect("same phase");
        assert_eq!(evt, KeyUpdateEvent::NoChange);
        assert!(!m.remote_key_phase());
    }

    #[test]
    fn double_request_local_key_update_is_idempotent() {
        let mut m = QuicTlsMachine::new();
        m.on_handshake_keys_available().expect("handshake");
        m.on_1rtt_keys_available().expect("1rtt");
        m.on_handshake_confirmed().expect("confirmed");

        let first = m.request_local_key_update().expect("first request");
        assert_eq!(
            first,
            KeyUpdateEvent::LocalUpdateScheduled {
                next_phase: true,
                generation: 1,
            }
        );

        // Second request while the first is still pending returns NoChange.
        let second = m.request_local_key_update().expect("second request");
        assert_eq!(second, KeyUpdateEvent::NoChange);
    }

    #[test]
    fn commit_local_key_update_without_prior_request() {
        let mut m = QuicTlsMachine::new();
        m.on_handshake_keys_available().expect("handshake");
        m.on_1rtt_keys_available().expect("1rtt");
        m.on_handshake_confirmed().expect("confirmed");

        // No request_local_key_update was issued.
        let evt = m.commit_local_key_update().expect("commit without request");
        assert_eq!(evt, KeyUpdateEvent::NoChange);
        // Phase and generation remain at defaults.
        assert!(!m.local_key_phase());
    }

    #[test]
    fn multiple_key_update_generations() {
        let mut m = QuicTlsMachine::new();
        m.on_handshake_keys_available().expect("handshake");
        m.on_1rtt_keys_available().expect("1rtt");
        m.on_handshake_confirmed().expect("confirmed");

        // Generation 0 -> 1
        m.request_local_key_update().expect("request gen1");
        m.commit_local_key_update().expect("commit gen1");
        assert!(m.local_key_phase()); // phase flipped to true
        assert_eq!(m.local.generation, 1);

        // Generation 1 -> 2
        let sched = m.request_local_key_update().expect("request gen2");
        assert_eq!(
            sched,
            KeyUpdateEvent::LocalUpdateScheduled {
                next_phase: false, // flips back
                generation: 2,
            }
        );
        let committed = m.commit_local_key_update().expect("commit gen2");
        assert_eq!(
            committed,
            KeyUpdateEvent::LocalUpdateScheduled {
                next_phase: false,
                generation: 2,
            }
        );
        assert!(!m.local_key_phase());
        assert_eq!(m.local.generation, 2);

        // Generation 2 -> 3
        let sched = m.request_local_key_update().expect("request gen3");
        assert_eq!(
            sched,
            KeyUpdateEvent::LocalUpdateScheduled {
                next_phase: true,
                generation: 3,
            }
        );
        let committed = m.commit_local_key_update().expect("commit gen3");
        assert_eq!(
            committed,
            KeyUpdateEvent::LocalUpdateScheduled {
                next_phase: true,
                generation: 3,
            }
        );
        assert!(m.local_key_phase());
        assert_eq!(m.local.generation, 3);
    }

    #[test]
    fn advance_to_skipping_handshake_level() {
        let mut m = QuicTlsMachine::new();
        assert_eq!(m.level(), CryptoLevel::Initial);

        // Skip directly from Initial to OneRtt.
        m.advance_to(CryptoLevel::OneRtt).expect("skip to 1rtt");
        assert_eq!(m.level(), CryptoLevel::OneRtt);

        // Going backwards must fail.
        let err = m
            .advance_to(CryptoLevel::Handshake)
            .expect_err("must fail backwards");
        assert_eq!(
            err,
            QuicTlsError::InvalidTransition {
                from: CryptoLevel::OneRtt,
                to: CryptoLevel::Handshake,
            }
        );
    }

    #[test]
    fn quic_tls_error_display_messages() {
        let e1 = QuicTlsError::HandshakeNotConfirmed;
        assert_eq!(e1.to_string(), "handshake not confirmed");

        let e2 = QuicTlsError::InvalidTransition {
            from: CryptoLevel::Handshake,
            to: CryptoLevel::Initial,
        };
        assert_eq!(
            e2.to_string(),
            "invalid crypto transition: Handshake -> Initial"
        );

        let e3 = QuicTlsError::StalePeerKeyPhase(true);
        assert_eq!(e3.to_string(), "stale peer key phase: true");

        let e4 = QuicTlsError::StalePeerKeyPhase(false);
        assert_eq!(e4.to_string(), "stale peer key phase: false");
    }

    #[test]
    fn crypto_level_ord_semantics() {
        assert!(CryptoLevel::Initial < CryptoLevel::Handshake);
        assert!(CryptoLevel::Handshake < CryptoLevel::OneRtt);
        assert!(CryptoLevel::Initial < CryptoLevel::OneRtt);

        // Verify ordering consistency with Ord trait.
        let mut levels = vec![
            CryptoLevel::OneRtt,
            CryptoLevel::Initial,
            CryptoLevel::Handshake,
        ];
        levels.sort();
        assert_eq!(
            levels,
            vec![
                CryptoLevel::Initial,
                CryptoLevel::Handshake,
                CryptoLevel::OneRtt,
            ]
        );
    }

    // =========================================================================
    // Wave 44 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn crypto_level_debug_clone_copy_eq() {
        let l = CryptoLevel::Initial;
        let copied = l;
        let cloned = l;
        assert_eq!(copied, cloned);
        assert_ne!(CryptoLevel::Initial, CryptoLevel::OneRtt);
        let dbg = format!("{l:?}");
        assert!(dbg.contains("Initial"), "{dbg}");
    }

    #[test]
    fn key_update_event_debug_clone_copy_eq() {
        let e1 = KeyUpdateEvent::NoChange;
        let e2 = KeyUpdateEvent::LocalUpdateScheduled {
            next_phase: true,
            generation: 1,
        };
        let e3 = KeyUpdateEvent::RemoteUpdateAccepted {
            new_phase: false,
            generation: 2,
        };
        assert!(format!("{e1:?}").contains("NoChange"));
        assert!(format!("{e2:?}").contains("LocalUpdateScheduled"));
        assert!(format!("{e3:?}").contains("RemoteUpdateAccepted"));
        let copied = e2;
        let cloned = e2;
        assert_eq!(copied, cloned);
        assert_ne!(e1, e2);
    }

    #[test]
    fn quic_tls_error_debug_clone_eq_display() {
        let e1 = QuicTlsError::HandshakeNotConfirmed;
        let e2 = QuicTlsError::InvalidTransition {
            from: CryptoLevel::Initial,
            to: CryptoLevel::OneRtt,
        };
        let e3 = QuicTlsError::StalePeerKeyPhase(true);

        assert!(format!("{e1:?}").contains("HandshakeNotConfirmed"));
        assert!(format!("{e1}").contains("handshake not confirmed"));
        assert!(format!("{e2}").contains("invalid crypto transition"));
        assert!(format!("{e3}").contains("stale peer key phase"));

        assert_eq!(e1.clone(), e1);
        assert_ne!(e1, e2);

        let err: &dyn std::error::Error = &e1;
        assert!(err.source().is_none());
    }

    #[test]
    fn quic_tls_machine_debug_clone_eq() {
        let m = QuicTlsMachine::new();
        let dbg = format!("{m:?}");
        assert!(dbg.contains("QuicTlsMachine"), "{dbg}");
        let cloned = m.clone();
        assert_eq!(m, cloned);
    }

    #[test]
    fn zero_rtt_requires_resumption_and_pre_confirmation_state() {
        let mut m = QuicTlsMachine::new();
        m.on_handshake_keys_available().expect("handshake");
        assert!(!m.can_send_0rtt());

        m.enable_resumption();
        assert!(m.resumption_enabled());
        assert!(m.can_send_0rtt());

        m.on_1rtt_keys_available().expect("1rtt");
        assert!(m.can_send_0rtt());

        m.on_handshake_confirmed().expect("confirmed");
        assert!(!m.can_send_0rtt());
        assert!(m.can_send_1rtt());

        m.disable_resumption();
        assert!(!m.resumption_enabled());
        assert!(!m.can_send_0rtt());
    }
}
