//! QUIC Key Schedule Management
//!
//! Handles QUIC key derivation, key phases, and key updates according to RFC 9000.

use crate::net::atp::handshake::state_machine::{PacketSpace, HandshakeError};
use crate::types::outcome::Outcome;
use std::collections::HashMap;

/// Key phase identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyPhase(pub u8);

impl KeyPhase {
    /// Initial key phase
    pub const INITIAL: Self = KeyPhase(0);

    /// Next key phase
    pub fn next(self) -> Self {
        KeyPhase(self.0.wrapping_add(1))
    }
}

/// Key material for packet protection
#[derive(Debug, Clone)]
pub struct KeyMaterial {
    /// Packet protection key
    pub key: Vec<u8>,
    /// IV for packet protection
    pub iv: Vec<u8>,
    /// Header protection key
    pub hp_key: Vec<u8>,
}

impl KeyMaterial {
    /// Create new key material
    pub fn new(key: Vec<u8>, iv: Vec<u8>, hp_key: Vec<u8>) -> Self {
        Self { key, iv, hp_key }
    }

    /// Create zero key material (for testing)
    pub fn zero(key_len: usize, iv_len: usize) -> Self {
        Self {
            key: vec![0u8; key_len],
            iv: vec![0u8; iv_len],
            hp_key: vec![0u8; key_len],
        }
    }
}

/// Key schedule state for a QUIC connection
#[derive(Debug)]
pub struct KeySchedule {
    /// Current keys by packet space
    current_keys: HashMap<PacketSpace, (KeyMaterial, KeyMaterial)>, // (local, remote)
    /// Current key phase for 1-RTT keys
    current_phase: KeyPhase,
    /// Next key phase keys (pre-computed for updates)
    next_phase_keys: Option<(KeyMaterial, KeyMaterial)>,
    /// Key update generation counter
    key_update_count: u64,
    /// Whether keys have been established for each space
    keys_established: HashMap<PacketSpace, bool>,
}

impl KeySchedule {
    /// Create a new key schedule
    pub fn new() -> Self {
        let mut keys_established = HashMap::new();
        keys_established.insert(PacketSpace::Initial, false);
        keys_established.insert(PacketSpace::Handshake, false);
        keys_established.insert(PacketSpace::Application, false);

        Self {
            current_keys: HashMap::new(),
            current_phase: KeyPhase::INITIAL,
            next_phase_keys: None,
            key_update_count: 0,
            keys_established,
        }
    }

    /// Install initial keys (derived from Initial salt and connection ID)
    pub fn install_initial_keys(
        &mut self,
        local_keys: KeyMaterial,
        remote_keys: KeyMaterial,
    ) -> Outcome<(), HandshakeError> {
        self.current_keys.insert(PacketSpace::Initial, (local_keys, remote_keys));
        self.keys_established.insert(PacketSpace::Initial, true);
        Ok(())
    }

    /// Install handshake keys (derived from TLS handshake)
    pub fn install_handshake_keys(
        &mut self,
        local_keys: KeyMaterial,
        remote_keys: KeyMaterial,
    ) -> Outcome<(), HandshakeError> {
        self.current_keys.insert(PacketSpace::Handshake, (local_keys, remote_keys));
        self.keys_established.insert(PacketSpace::Handshake, true);
        Ok(())
    }

    /// Install 1-RTT keys (derived from TLS application secrets)
    pub fn install_application_keys(
        &mut self,
        local_keys: KeyMaterial,
        remote_keys: KeyMaterial,
    ) -> Outcome<(), HandshakeError> {
        self.current_keys.insert(PacketSpace::Application, (local_keys, remote_keys));
        self.keys_established.insert(PacketSpace::Application, true);
        self.current_phase = KeyPhase::INITIAL;
        Ok(())
    }

    /// Get current local keys for a packet space
    pub fn local_keys(&self, space: PacketSpace) -> Option<&KeyMaterial> {
        self.current_keys.get(&space).map(|(local, _)| local)
    }

    /// Get current remote keys for a packet space
    pub fn remote_keys(&self, space: PacketSpace) -> Option<&KeyMaterial> {
        self.current_keys.get(&space).map(|(_, remote)| remote)
    }

    /// Check if keys are established for a packet space
    pub fn keys_established(&self, space: PacketSpace) -> bool {
        self.keys_established.get(&space).copied().unwrap_or(false)
    }

    /// Get current key phase for 1-RTT packets
    pub fn current_key_phase(&self) -> KeyPhase {
        self.current_phase
    }

    /// Initiate a key update (generate next phase keys)
    pub fn initiate_key_update(&mut self) -> Outcome<(), HandshakeError> {
        if !self.keys_established(PacketSpace::Application) {
            return Err(HandshakeError::ProtectionError {
                reason: "cannot update keys before 1-RTT keys established".to_string(),
            });
        }

        if self.next_phase_keys.is_some() {
            return Err(HandshakeError::ProtectionError {
                reason: "key update already in progress".to_string(),
            });
        }

        // In a real implementation, this would derive new keys from the TLS application secrets
        // For now, we'll create placeholder keys
        let local_keys = KeyMaterial::zero(32, 12);
        let remote_keys = KeyMaterial::zero(32, 12);

        self.next_phase_keys = Some((local_keys, remote_keys));
        Ok(())
    }

    /// Commit to next key phase (after receiving key update from peer)
    pub fn commit_key_update(&mut self) -> Outcome<(), HandshakeError> {
        if let Some((local_keys, remote_keys)) = self.next_phase_keys.take() {
            self.current_keys.insert(PacketSpace::Application, (local_keys, remote_keys));
            self.current_phase = self.current_phase.next();
            self.key_update_count += 1;
            Ok(())
        } else {
            Err(HandshakeError::ProtectionError {
                reason: "no key update in progress".to_string(),
            })
        }
    }

    /// Discard keys for a packet space (after handshake completion)
    pub fn discard_keys(&mut self, space: PacketSpace) -> Outcome<(), HandshakeError> {
        match space {
            PacketSpace::Initial | PacketSpace::Handshake => {
                self.current_keys.remove(&space);
                self.keys_established.insert(space, false);
                Ok(())
            }
            PacketSpace::Application => {
                Err(HandshakeError::ProtectionError {
                    reason: "cannot discard 1-RTT keys".to_string(),
                })
            }
        }
    }

    /// Check if handshake keys can be discarded
    pub fn can_discard_handshake_keys(&self) -> bool {
        // Handshake keys can be discarded after 1-RTT keys are established
        // and handshake confirmation is complete
        self.keys_established(PacketSpace::Application)
    }

    /// Check if initial keys can be discarded
    pub fn can_discard_initial_keys(&self) -> bool {
        // Initial keys can be discarded after handshake keys are established
        self.keys_established(PacketSpace::Handshake)
    }

    /// Get key update count
    pub fn key_update_count(&self) -> u64 {
        self.key_update_count
    }

    /// Check if a key update is in progress
    pub fn key_update_pending(&self) -> bool {
        self.next_phase_keys.is_some()
    }
}

impl Default for KeySchedule {
    fn default() -> Self {
        Self::new()
    }
}

/// Key derivation utilities
pub struct KeyDerivation;

impl KeyDerivation {
    /// Derive initial keys from connection ID (simplified version)
    pub fn derive_initial_keys(connection_id: &[u8]) -> Outcome<(KeyMaterial, KeyMaterial), HandshakeError> {
        // In a real implementation, this would use HKDF with the Initial salt
        // For now, we'll create deterministic keys based on connection ID
        let mut local_key = vec![0u8; 32];
        let mut remote_key = vec![0u8; 32];

        // Simple deterministic derivation for testing
        for (i, &byte) in connection_id.iter().enumerate() {
            if i < 32 {
                local_key[i] = byte;
                remote_key[i] = byte.wrapping_add(1);
            }
        }

        let local_iv = vec![0u8; 12];
        let remote_iv = vec![1u8; 12];

        let local_hp = vec![2u8; 32];
        let remote_hp = vec![3u8; 32];

        let local_keys = KeyMaterial::new(local_key, local_iv, local_hp);
        let remote_keys = KeyMaterial::new(remote_key, remote_iv, remote_hp);

        Ok((local_keys, remote_keys))
    }

    /// Derive handshake keys from TLS secrets (simplified version)
    pub fn derive_handshake_keys(_handshake_secret: &[u8]) -> Outcome<(KeyMaterial, KeyMaterial), HandshakeError> {
        // In a real implementation, this would use HKDF-Expand with handshake secret
        let local_keys = KeyMaterial::zero(32, 12);
        let remote_keys = KeyMaterial::zero(32, 12);
        Ok((local_keys, remote_keys))
    }

    /// Derive 1-RTT keys from TLS application secrets (simplified version)
    pub fn derive_application_keys(_app_secret: &[u8]) -> Outcome<(KeyMaterial, KeyMaterial), HandshakeError> {
        // In a real implementation, this would use HKDF-Expand with application secret
        let local_keys = KeyMaterial::zero(32, 12);
        let remote_keys = KeyMaterial::zero(32, 12);
        Ok((local_keys, remote_keys))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_schedule_creation() {
        let schedule = KeySchedule::new();

        assert!(!schedule.keys_established(PacketSpace::Initial));
        assert!(!schedule.keys_established(PacketSpace::Handshake));
        assert!(!schedule.keys_established(PacketSpace::Application));
        assert_eq!(schedule.current_key_phase(), KeyPhase::INITIAL);
    }

    #[test]
    fn test_key_installation() {
        let mut schedule = KeySchedule::new();

        let local_keys = KeyMaterial::zero(32, 12);
        let remote_keys = KeyMaterial::zero(32, 12);

        assert!(schedule.install_initial_keys(local_keys, remote_keys).is_ok());
        assert!(schedule.keys_established(PacketSpace::Initial));
        assert!(schedule.local_keys(PacketSpace::Initial).is_some());
        assert!(schedule.remote_keys(PacketSpace::Initial).is_some());
    }

    #[test]
    fn test_key_update_lifecycle() {
        let mut schedule = KeySchedule::new();

        // Install 1-RTT keys first
        let local_keys = KeyMaterial::zero(32, 12);
        let remote_keys = KeyMaterial::zero(32, 12);
        schedule.install_application_keys(local_keys, remote_keys).unwrap();

        assert_eq!(schedule.current_key_phase(), KeyPhase::INITIAL);
        assert!(!schedule.key_update_pending());

        // Initiate key update
        assert!(schedule.initiate_key_update().is_ok());
        assert!(schedule.key_update_pending());

        // Commit key update
        assert!(schedule.commit_key_update().is_ok());
        assert_eq!(schedule.current_key_phase(), KeyPhase(1));
        assert!(!schedule.key_update_pending());
        assert_eq!(schedule.key_update_count(), 1);
    }

    #[test]
    fn test_key_discard_rules() {
        let mut schedule = KeySchedule::new();

        let local_keys = KeyMaterial::zero(32, 12);
        let remote_keys = KeyMaterial::zero(32, 12);

        // Install all keys
        schedule.install_initial_keys(local_keys.clone(), remote_keys.clone()).unwrap();
        schedule.install_handshake_keys(local_keys.clone(), remote_keys.clone()).unwrap();
        schedule.install_application_keys(local_keys, remote_keys).unwrap();

        // Initial keys can be discarded after handshake keys are established
        assert!(schedule.can_discard_initial_keys());

        // Handshake keys can be discarded after 1-RTT keys are established
        assert!(schedule.can_discard_handshake_keys());

        // Test actual discard
        assert!(schedule.discard_keys(PacketSpace::Initial).is_ok());
        assert!(!schedule.keys_established(PacketSpace::Initial));

        assert!(schedule.discard_keys(PacketSpace::Handshake).is_ok());
        assert!(!schedule.keys_established(PacketSpace::Handshake));

        // Cannot discard 1-RTT keys
        assert!(schedule.discard_keys(PacketSpace::Application).is_err());
    }

    #[test]
    fn test_key_derivation() {
        let connection_id = b"test_connection_id";
        let result = KeyDerivation::derive_initial_keys(connection_id);

        assert!(result.is_ok());
        let (local_keys, remote_keys) = result.unwrap();

        assert_eq!(local_keys.key.len(), 32);
        assert_eq!(local_keys.iv.len(), 12);
        assert_eq!(remote_keys.key.len(), 32);
        assert_eq!(remote_keys.iv.len(), 12);

        // Keys should be different
        assert_ne!(local_keys.key, remote_keys.key);
    }

    #[test]
    fn test_key_phase_progression() {
        let phase0 = KeyPhase::INITIAL;
        let phase1 = phase0.next();
        let phase2 = phase1.next();

        assert_eq!(phase0.0, 0);
        assert_eq!(phase1.0, 1);
        assert_eq!(phase2.0, 2);
    }

    #[test]
    fn test_key_update_without_application_keys() {
        let mut schedule = KeySchedule::new();

        // Try to update keys without 1-RTT keys established
        let result = schedule.initiate_key_update();
        assert!(result.is_err());
    }

    #[test]
    fn test_double_key_update() {
        let mut schedule = KeySchedule::new();

        let local_keys = KeyMaterial::zero(32, 12);
        let remote_keys = KeyMaterial::zero(32, 12);
        schedule.install_application_keys(local_keys, remote_keys).unwrap();

        // First update should succeed
        assert!(schedule.initiate_key_update().is_ok());

        // Second update while first is pending should fail
        assert!(schedule.initiate_key_update().is_err());
    }
}