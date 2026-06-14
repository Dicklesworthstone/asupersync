//! QUIC Key Schedule Management
//!
//! Handles QUIC key derivation, key phases, and key updates according to RFC 9001.
//! Implements proper HKDF-based key derivation with Initial salt, TLS secrets,
//! and key update mechanisms.

use crate::net::atp::handshake::state_machine::{HandshakeError, PacketSpace};
use crate::types::outcome::Outcome;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::collections::HashMap;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
struct HkdfSha256 {
    prk: Vec<u8>,
}

impl HkdfSha256 {
    fn new(salt: Option<&[u8]>, ikm: &[u8]) -> Self {
        let zero_salt = [0u8; 32];
        let salt = salt.unwrap_or(&zero_salt);
        Self {
            prk: hmac_sha256(salt, ikm).to_vec(),
        }
    }

    fn from_prk(prk: &[u8]) -> Result<Self, ()> {
        if prk.len() < 32 {
            return Err(());
        }
        Ok(Self { prk: prk.to_vec() })
    }

    fn expand(&self, info: &[u8], output: &mut [u8]) -> Result<(), ()> {
        let blocks = output.len().div_ceil(32);
        if blocks > u8::MAX as usize {
            return Err(());
        }

        let mut previous = Vec::new();
        let mut written = 0;
        for block_index in 1..=blocks {
            let mut mac =
                HmacSha256::new_from_slice(&self.prk).expect("HMAC accepts any key length");
            mac.update(&previous);
            mac.update(info);
            mac.update(&[block_index as u8]);
            previous = mac.finalize().into_bytes().to_vec();

            let remaining = output.len() - written;
            let to_copy = remaining.min(previous.len());
            output[written..written + to_copy].copy_from_slice(&previous[..to_copy]);
            written += to_copy;
        }

        Ok(())
    }
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

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
        // Verify initial keys match RFC 9001 Initial packet protection.
        match KeyDerivation::verify_key_material(&local_keys, INITIAL_KEY_MATERIAL) {
            Outcome::Ok(()) => {}
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }
        match KeyDerivation::verify_key_material(&remote_keys, INITIAL_KEY_MATERIAL) {
            Outcome::Ok(()) => {}
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        self.current_keys
            .insert(PacketSpace::Initial, (local_keys, remote_keys));
        self.keys_established.insert(PacketSpace::Initial, true);
        Outcome::ok(())
    }

    /// Install handshake keys (derived from TLS handshake)
    pub fn install_handshake_keys(
        &mut self,
        local_keys: KeyMaterial,
        remote_keys: KeyMaterial,
    ) -> Outcome<(), HandshakeError> {
        // Verify keys match this module's traffic-key profile.
        match KeyDerivation::verify_key_material(&local_keys, DEFAULT_TRAFFIC_KEY_MATERIAL) {
            Outcome::Ok(()) => {}
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }
        match KeyDerivation::verify_key_material(&remote_keys, DEFAULT_TRAFFIC_KEY_MATERIAL) {
            Outcome::Ok(()) => {}
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        self.current_keys
            .insert(PacketSpace::Handshake, (local_keys, remote_keys));
        self.keys_established.insert(PacketSpace::Handshake, true);
        Outcome::ok(())
    }

    /// Install 1-RTT keys (derived from TLS application secrets)
    pub fn install_application_keys(
        &mut self,
        local_keys: KeyMaterial,
        remote_keys: KeyMaterial,
    ) -> Outcome<(), HandshakeError> {
        // Verify keys match this module's traffic-key profile.
        match KeyDerivation::verify_key_material(&local_keys, DEFAULT_TRAFFIC_KEY_MATERIAL) {
            Outcome::Ok(()) => {}
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }
        match KeyDerivation::verify_key_material(&remote_keys, DEFAULT_TRAFFIC_KEY_MATERIAL) {
            Outcome::Ok(()) => {}
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        self.current_keys
            .insert(PacketSpace::Application, (local_keys, remote_keys));
        self.keys_established.insert(PacketSpace::Application, true);
        self.current_phase = KeyPhase::INITIAL;
        Outcome::ok(())
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
    pub fn initiate_key_update(
        &mut self,
        local_traffic_secret: &[u8],
        remote_traffic_secret: &[u8],
    ) -> Outcome<(), HandshakeError> {
        if !self.keys_established(PacketSpace::Application) {
            return Outcome::Err(HandshakeError::ProtectionError {
                reason: "cannot update keys before 1-RTT keys established".to_string(),
            });
        }

        if self.next_phase_keys.is_some() {
            return Outcome::Err(HandshakeError::ProtectionError {
                reason: "key update already in progress".to_string(),
            });
        }

        // Derive new keys from current traffic secrets using key update mechanism
        let local_keys = match KeyDerivation::derive_updated_keys(local_traffic_secret) {
            Outcome::Ok(keys) => keys,
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(r) => return Outcome::Cancelled(r),
            Outcome::Panicked(p) => return Outcome::Panicked(p),
        };

        let remote_keys = match KeyDerivation::derive_updated_keys(remote_traffic_secret) {
            Outcome::Ok(keys) => keys,
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(r) => return Outcome::Cancelled(r),
            Outcome::Panicked(p) => return Outcome::Panicked(p),
        };

        self.next_phase_keys = Some((local_keys, remote_keys));
        Outcome::ok(())
    }

    /// Commit to next key phase (after receiving key update from peer)
    pub fn commit_key_update(&mut self) -> Outcome<(), HandshakeError> {
        if let Some((local_keys, remote_keys)) = self.next_phase_keys.take() {
            // Verify updated keys match this module's traffic-key profile.
            match KeyDerivation::verify_key_material(&local_keys, DEFAULT_TRAFFIC_KEY_MATERIAL) {
                Outcome::Ok(()) => {}
                Outcome::Err(e) => return Outcome::Err(e),
                Outcome::Cancelled(r) => return Outcome::Cancelled(r),
                Outcome::Panicked(p) => return Outcome::Panicked(p),
            }
            match KeyDerivation::verify_key_material(&remote_keys, DEFAULT_TRAFFIC_KEY_MATERIAL) {
                Outcome::Ok(()) => {}
                Outcome::Err(e) => return Outcome::Err(e),
                Outcome::Cancelled(r) => return Outcome::Cancelled(r),
                Outcome::Panicked(p) => return Outcome::Panicked(p),
            }

            self.current_keys
                .insert(PacketSpace::Application, (local_keys, remote_keys));
            self.current_phase = self.current_phase.next();
            self.key_update_count += 1;
            Outcome::ok(())
        } else {
            Outcome::Err(HandshakeError::ProtectionError {
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
                Outcome::ok(())
            }
            PacketSpace::Application => Outcome::Err(HandshakeError::ProtectionError {
                reason: "cannot discard 1-RTT keys".to_string(),
            }),
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

/// QUIC key derivation constants from RFC 9001
const INITIAL_SALT: &[u8] = &[
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const TRAFFIC_SECRET_LEN: usize = 32;
const INITIAL_KEY_LEN: usize = 16;
const INITIAL_IV_LEN: usize = 12;
const INITIAL_HP_KEY_LEN: usize = 16;
const DEFAULT_TRAFFIC_KEY_LEN: usize = 32;
const DEFAULT_TRAFFIC_IV_LEN: usize = 12;
const DEFAULT_TRAFFIC_HP_KEY_LEN: usize = 32;

#[derive(Debug, Clone, Copy)]
struct KeyMaterialShape {
    name: &'static str,
    key_len: usize,
    iv_len: usize,
    hp_key_len: usize,
}

const INITIAL_KEY_MATERIAL: KeyMaterialShape = KeyMaterialShape {
    name: "initial",
    key_len: INITIAL_KEY_LEN,
    iv_len: INITIAL_IV_LEN,
    hp_key_len: INITIAL_HP_KEY_LEN,
};

const DEFAULT_TRAFFIC_KEY_MATERIAL: KeyMaterialShape = KeyMaterialShape {
    name: "traffic",
    key_len: DEFAULT_TRAFFIC_KEY_LEN,
    iv_len: DEFAULT_TRAFFIC_IV_LEN,
    hp_key_len: DEFAULT_TRAFFIC_HP_KEY_LEN,
};

/// Key derivation utilities implementing RFC 9001 QUIC-TLS
pub struct KeyDerivation;

impl KeyDerivation {
    /// Derive initial keys from connection ID using RFC 9001 Initial salt
    pub fn derive_initial_keys(
        connection_id: &[u8],
    ) -> Outcome<(KeyMaterial, KeyMaterial), HandshakeError> {
        // HKDF-Extract with Initial salt
        let hkdf = HkdfSha256::new(Some(INITIAL_SALT), connection_id);

        // Derive client initial secret
        let client_secret =
            match Self::hkdf_expand_label(&hkdf, TRAFFIC_SECRET_LEN, b"client in", &[]) {
                Outcome::Ok(secret) => secret,
                Outcome::Err(e) => return Outcome::Err(e),
                Outcome::Cancelled(r) => return Outcome::Cancelled(r),
                Outcome::Panicked(p) => return Outcome::Panicked(p),
            };

        // Derive server initial secret
        let server_secret =
            match Self::hkdf_expand_label(&hkdf, TRAFFIC_SECRET_LEN, b"server in", &[]) {
                Outcome::Ok(secret) => secret,
                Outcome::Err(e) => return Outcome::Err(e),
                Outcome::Cancelled(r) => return Outcome::Cancelled(r),
                Outcome::Panicked(p) => return Outcome::Panicked(p),
            };

        // Derive key material from secrets
        let client_keys = match Self::derive_initial_keys_from_secret(&client_secret) {
            Outcome::Ok(keys) => keys,
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(r) => return Outcome::Cancelled(r),
            Outcome::Panicked(p) => return Outcome::Panicked(p),
        };
        let server_keys = match Self::derive_initial_keys_from_secret(&server_secret) {
            Outcome::Ok(keys) => keys,
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(r) => return Outcome::Cancelled(r),
            Outcome::Panicked(p) => return Outcome::Panicked(p),
        };

        Outcome::ok((client_keys, server_keys))
    }

    /// Derive handshake keys from TLS handshake secret
    pub fn derive_handshake_keys(
        handshake_secret: &[u8],
    ) -> Outcome<(KeyMaterial, KeyMaterial), HandshakeError> {
        if handshake_secret.is_empty() {
            return Outcome::Err(HandshakeError::ProtectionError {
                reason: "handshake secret cannot be empty".to_string(),
            });
        }

        match Self::derive_keys_from_secret(handshake_secret) {
            Outcome::Ok(keys) => Outcome::ok((keys.clone(), keys)),
            Outcome::Err(e) => Outcome::Err(e),
            Outcome::Cancelled(r) => Outcome::Cancelled(r),
            Outcome::Panicked(p) => Outcome::Panicked(p),
        }
    }

    /// Derive 1-RTT application keys from TLS application secret
    pub fn derive_application_keys(
        app_secret: &[u8],
    ) -> Outcome<(KeyMaterial, KeyMaterial), HandshakeError> {
        if app_secret.is_empty() {
            return Outcome::Err(HandshakeError::ProtectionError {
                reason: "application secret cannot be empty".to_string(),
            });
        }

        match Self::derive_keys_from_secret(app_secret) {
            Outcome::Ok(keys) => Outcome::ok((keys.clone(), keys)),
            Outcome::Err(e) => Outcome::Err(e),
            Outcome::Cancelled(r) => Outcome::Cancelled(r),
            Outcome::Panicked(p) => Outcome::Panicked(p),
        }
    }

    /// Derive updated keys for key update from current traffic secret
    pub fn derive_updated_keys(current_secret: &[u8]) -> Outcome<KeyMaterial, HandshakeError> {
        if current_secret.is_empty() {
            return Outcome::Err(HandshakeError::ProtectionError {
                reason: "current secret cannot be empty for key update".to_string(),
            });
        }

        // Update traffic secret using HKDF-Expand-Label
        let hkdf = match HkdfSha256::from_prk(current_secret) {
            Ok(hkdf) => hkdf,
            Err(_) => {
                return Outcome::Err(HandshakeError::ProtectionError {
                    reason: "invalid PRK for key update".to_string(),
                });
            }
        };

        let updated_secret =
            match Self::hkdf_expand_label(&hkdf, TRAFFIC_SECRET_LEN, b"quic ku", &[]) {
                Outcome::Ok(secret) => secret,
                Outcome::Err(e) => return Outcome::Err(e),
                Outcome::Cancelled(r) => return Outcome::Cancelled(r),
                Outcome::Panicked(p) => return Outcome::Panicked(p),
            };

        Self::derive_keys_from_secret(&updated_secret)
    }

    /// Derive key material (key, IV, header protection key) from a traffic secret
    fn derive_keys_from_secret(secret: &[u8]) -> Outcome<KeyMaterial, HandshakeError> {
        Self::derive_key_material_from_secret(secret, DEFAULT_TRAFFIC_KEY_MATERIAL)
    }

    /// Derive Initial packet key material from an Initial traffic secret.
    fn derive_initial_keys_from_secret(secret: &[u8]) -> Outcome<KeyMaterial, HandshakeError> {
        Self::derive_key_material_from_secret(secret, INITIAL_KEY_MATERIAL)
    }

    fn derive_key_material_from_secret(
        secret: &[u8],
        shape: KeyMaterialShape,
    ) -> Outcome<KeyMaterial, HandshakeError> {
        let hkdf = match HkdfSha256::from_prk(secret) {
            Ok(hkdf) => hkdf,
            Err(_) => {
                return Outcome::Err(HandshakeError::ProtectionError {
                    reason: "invalid secret for key derivation".to_string(),
                });
            }
        };

        let key = match Self::hkdf_expand_label(&hkdf, shape.key_len, b"quic key", &[]) {
            Outcome::Ok(k) => k,
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(r) => return Outcome::Cancelled(r),
            Outcome::Panicked(p) => return Outcome::Panicked(p),
        };

        let iv = match Self::hkdf_expand_label(&hkdf, shape.iv_len, b"quic iv", &[]) {
            Outcome::Ok(i) => i,
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(r) => return Outcome::Cancelled(r),
            Outcome::Panicked(p) => return Outcome::Panicked(p),
        };

        let hp_key = match Self::hkdf_expand_label(&hkdf, shape.hp_key_len, b"quic hp", &[]) {
            Outcome::Ok(h) => h,
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(r) => return Outcome::Cancelled(r),
            Outcome::Panicked(p) => return Outcome::Panicked(p),
        };

        Outcome::ok(KeyMaterial::new(key, iv, hp_key))
    }

    fn verify_key_material(
        keys: &KeyMaterial,
        shape: KeyMaterialShape,
    ) -> Outcome<(), HandshakeError> {
        if keys.key.len() != shape.key_len {
            return Outcome::Err(HandshakeError::ProtectionError {
                reason: format!(
                    "{} packet protection key must be {} bytes, got {}",
                    shape.name,
                    shape.key_len,
                    keys.key.len()
                ),
            });
        }

        if keys.iv.len() != shape.iv_len {
            return Outcome::Err(HandshakeError::ProtectionError {
                reason: format!(
                    "{} IV must be {} bytes, got {}",
                    shape.name,
                    shape.iv_len,
                    keys.iv.len()
                ),
            });
        }

        if keys.hp_key.len() != shape.hp_key_len {
            return Outcome::Err(HandshakeError::ProtectionError {
                reason: format!(
                    "{} header protection key must be {} bytes, got {}",
                    shape.name,
                    shape.hp_key_len,
                    keys.hp_key.len()
                ),
            });
        }

        Self::verify_non_zero_keys(keys)
    }

    /// HKDF-Expand-Label implementation for QUIC (RFC 9001, Section 5.1)
    fn hkdf_expand_label(
        hkdf: &HkdfSha256,
        length: usize,
        label: &[u8],
        context: &[u8],
    ) -> Outcome<Vec<u8>, HandshakeError> {
        if length > 255 {
            return Outcome::Err(HandshakeError::ProtectionError {
                reason: "HKDF length too large".to_string(),
            });
        }

        // Construct HkdfLabel structure
        let mut info = Vec::new();

        // Length (2 bytes, big-endian)
        info.extend_from_slice(&(length as u16).to_be_bytes());

        // Label with "tls13 " prefix (1 byte length + data)
        let prefixed_label = [b"tls13 ", label].concat();
        if prefixed_label.len() > 255 {
            return Outcome::Err(HandshakeError::ProtectionError {
                reason: "label too long".to_string(),
            });
        }
        info.push(prefixed_label.len() as u8);
        info.extend_from_slice(&prefixed_label);

        // Context (1 byte length + data)
        if context.len() > 255 {
            return Outcome::Err(HandshakeError::ProtectionError {
                reason: "context too long".to_string(),
            });
        }
        info.push(context.len() as u8);
        info.extend_from_slice(context);

        // Expand
        let mut output = vec![0u8; length];
        match hkdf.expand(&info, &mut output) {
            Ok(()) => {}
            Err(_) => {
                return Outcome::Err(HandshakeError::ProtectionError {
                    reason: "HKDF expand failed".to_string(),
                });
            }
        }

        Outcome::ok(output)
    }

    /// Verify that key material is not all zeros (security check)
    pub fn verify_non_zero_keys(keys: &KeyMaterial) -> Outcome<(), HandshakeError> {
        if keys.key.iter().all(|&b| b == 0) {
            return Outcome::Err(HandshakeError::ProtectionError {
                reason: "derived packet protection key is all zeros".to_string(),
            });
        }

        if keys.iv.iter().all(|&b| b == 0) {
            return Outcome::Err(HandshakeError::ProtectionError {
                reason: "derived IV is all zeros".to_string(),
            });
        }

        if keys.hp_key.iter().all(|&b| b == 0) {
            return Outcome::Err(HandshakeError::ProtectionError {
                reason: "derived header protection key is all zeros".to_string(),
            });
        }

        Outcome::ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn initial_test_keys(base: u8) -> KeyMaterial {
        KeyMaterial::new(
            vec![base; INITIAL_KEY_LEN],
            vec![base.wrapping_add(1); INITIAL_IV_LEN],
            vec![base.wrapping_add(2); INITIAL_HP_KEY_LEN],
        )
    }

    fn traffic_test_keys(base: u8) -> KeyMaterial {
        KeyMaterial::new(
            vec![base; DEFAULT_TRAFFIC_KEY_LEN],
            vec![base.wrapping_add(1); DEFAULT_TRAFFIC_IV_LEN],
            vec![base.wrapping_add(2); DEFAULT_TRAFFIC_HP_KEY_LEN],
        )
    }

    fn decode_hex(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0);
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

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

        // Create non-zero test keys
        let local_keys = initial_test_keys(1);
        let remote_keys = initial_test_keys(4);

        assert!(
            schedule
                .install_initial_keys(local_keys, remote_keys)
                .is_ok()
        );
        assert!(schedule.keys_established(PacketSpace::Initial));
        assert!(schedule.local_keys(PacketSpace::Initial).is_some());
        assert!(schedule.remote_keys(PacketSpace::Initial).is_some());
    }

    #[test]
    fn test_zero_key_rejection() {
        let mut schedule = KeySchedule::new();

        // Zero keys should be rejected
        let zero_keys = KeyMaterial::zero(INITIAL_KEY_LEN, INITIAL_IV_LEN);
        let non_zero_keys = initial_test_keys(1);

        assert!(
            schedule
                .install_initial_keys(zero_keys, non_zero_keys)
                .is_err()
        );
    }

    #[test]
    fn test_initial_install_rejects_wrong_key_lengths() {
        let mut schedule = KeySchedule::new();

        let traffic_sized_keys = traffic_test_keys(1);
        let initial_keys = initial_test_keys(4);

        assert!(
            schedule
                .install_initial_keys(traffic_sized_keys, initial_keys)
                .is_err()
        );
    }

    #[test]
    fn test_application_install_rejects_wrong_key_lengths() {
        let mut schedule = KeySchedule::new();

        let initial_sized_keys = initial_test_keys(1);
        let traffic_keys = traffic_test_keys(4);

        assert!(
            schedule
                .install_application_keys(initial_sized_keys, traffic_keys)
                .is_err()
        );
    }

    #[test]
    fn test_key_update_lifecycle() {
        let mut schedule = KeySchedule::new();

        // Install 1-RTT keys first
        let local_keys = KeyMaterial::new(vec![1u8; 32], vec![2u8; 12], vec![3u8; 32]);
        let remote_keys = KeyMaterial::new(vec![4u8; 32], vec![5u8; 12], vec![6u8; 32]);
        schedule
            .install_application_keys(local_keys, remote_keys)
            .unwrap();

        assert_eq!(schedule.current_key_phase(), KeyPhase::INITIAL);
        assert!(!schedule.key_update_pending());

        // Initiate key update with traffic secrets
        let local_traffic_secret = vec![0x10u8; 32];
        let remote_traffic_secret = vec![0x20u8; 32];
        assert!(
            schedule
                .initiate_key_update(&local_traffic_secret, &remote_traffic_secret)
                .is_ok()
        );
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

        let initial_local_keys = initial_test_keys(1);
        let initial_remote_keys = initial_test_keys(4);
        let local_keys = traffic_test_keys(7);
        let remote_keys = traffic_test_keys(10);

        // Install all keys
        schedule
            .install_initial_keys(initial_local_keys, initial_remote_keys)
            .unwrap();
        schedule
            .install_handshake_keys(local_keys.clone(), remote_keys.clone())
            .unwrap();
        schedule
            .install_application_keys(local_keys, remote_keys)
            .unwrap();

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
    fn test_initial_key_derivation() {
        let connection_id = b"test_connection_id";
        let result = KeyDerivation::derive_initial_keys(connection_id);

        assert!(result.is_ok());
        let (client_keys, server_keys) = result.unwrap();

        // Verify key lengths
        assert_eq!(client_keys.key.len(), INITIAL_KEY_LEN);
        assert_eq!(client_keys.iv.len(), INITIAL_IV_LEN);
        assert_eq!(client_keys.hp_key.len(), INITIAL_HP_KEY_LEN);
        assert_eq!(server_keys.key.len(), INITIAL_KEY_LEN);
        assert_eq!(server_keys.iv.len(), INITIAL_IV_LEN);
        assert_eq!(server_keys.hp_key.len(), INITIAL_HP_KEY_LEN);

        // Keys should be different
        assert_ne!(client_keys.key, server_keys.key);
        assert_ne!(client_keys.iv, server_keys.iv);
        assert_ne!(client_keys.hp_key, server_keys.hp_key);

        // Keys should not be zero
        assert!(KeyDerivation::verify_non_zero_keys(&client_keys).is_ok());
        assert!(KeyDerivation::verify_non_zero_keys(&server_keys).is_ok());
    }

    #[test]
    fn test_empty_connection_id_derivation_allowed() {
        let result = KeyDerivation::derive_initial_keys(&[]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_handshake_key_derivation() {
        let handshake_secret = vec![0x42u8; 32];
        let result = KeyDerivation::derive_handshake_keys(&handshake_secret);

        assert!(result.is_ok());
        let (keys1, keys2) = result.unwrap();

        // Keys should not be zero
        assert!(KeyDerivation::verify_non_zero_keys(&keys1).is_ok());
        assert!(KeyDerivation::verify_non_zero_keys(&keys2).is_ok());
    }

    #[test]
    fn test_application_key_derivation() {
        let app_secret = vec![0x55u8; 32];
        let result = KeyDerivation::derive_application_keys(&app_secret);

        assert!(result.is_ok());
        let (keys1, keys2) = result.unwrap();

        // Keys should not be zero
        assert!(KeyDerivation::verify_non_zero_keys(&keys1).is_ok());
        assert!(KeyDerivation::verify_non_zero_keys(&keys2).is_ok());
    }

    #[test]
    fn test_key_update_derivation() {
        let current_secret = vec![0xAAu8; 32];
        let result = KeyDerivation::derive_updated_keys(&current_secret);

        assert!(result.is_ok());
        let updated_keys = result.unwrap();

        // Updated keys should not be zero
        assert!(KeyDerivation::verify_non_zero_keys(&updated_keys).is_ok());
    }

    #[test]
    fn test_key_update_uses_quic_update_label() {
        let current_secret = vec![0xAAu8; TRAFFIC_SECRET_LEN];
        let actual = KeyDerivation::derive_updated_keys(&current_secret).unwrap();
        let hkdf = HkdfSha256::from_prk(&current_secret).unwrap();

        let quic_update_secret =
            KeyDerivation::hkdf_expand_label(&hkdf, TRAFFIC_SECRET_LEN, b"quic ku", &[]).unwrap();
        let quic_expected = KeyDerivation::derive_keys_from_secret(&quic_update_secret).unwrap();

        let tls_update_secret =
            KeyDerivation::hkdf_expand_label(&hkdf, TRAFFIC_SECRET_LEN, b"traffic upd", &[])
                .unwrap();
        let tls_expected = KeyDerivation::derive_keys_from_secret(&tls_update_secret).unwrap();

        assert_eq!(actual.key, quic_expected.key);
        assert_eq!(actual.iv, quic_expected.iv);
        assert_eq!(actual.hp_key, quic_expected.hp_key);
        assert_ne!(actual.key, tls_expected.key);
        assert_ne!(actual.iv, tls_expected.iv);
        assert_ne!(actual.hp_key, tls_expected.hp_key);
    }

    #[test]
    fn test_empty_secret_rejection() {
        assert!(KeyDerivation::derive_handshake_keys(&[]).is_err());
        assert!(KeyDerivation::derive_application_keys(&[]).is_err());
        assert!(KeyDerivation::derive_updated_keys(&[]).is_err());
    }

    #[test]
    fn test_rfc9001_initial_keys_match_appendix_a_vector() {
        let connection_id = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let (client_keys, server_keys) =
            KeyDerivation::derive_initial_keys(&connection_id).unwrap();

        assert_eq!(
            client_keys.key,
            decode_hex("1f369613dd76d5467730efcbe3b1a22d")
        );
        assert_eq!(client_keys.iv, decode_hex("fa044b2f42a3fd3b46fb255c"));
        assert_eq!(
            client_keys.hp_key,
            decode_hex("9f50449e04a0e810283a1e9933adedd2")
        );
        assert_eq!(
            server_keys.key,
            decode_hex("cf3a5331653c364c88f0f379b6067e37")
        );
        assert_eq!(server_keys.iv, decode_hex("0ac1493ca1905853b0bba03e"));
        assert_eq!(
            server_keys.hp_key,
            decode_hex("c206b8d9b9f0f37644430b490eeaa314")
        );
    }

    #[test]
    fn test_key_update_progression() {
        // Test that key updates produce different keys
        let initial_secret = vec![0x11u8; 32];
        let first_update = KeyDerivation::derive_updated_keys(&initial_secret).unwrap();

        // Use first update as input for second update
        // In practice, we'd derive new traffic secret first, but this tests the mechanism
        let second_secret = vec![0x22u8; 32];
        let second_update = KeyDerivation::derive_updated_keys(&second_secret).unwrap();

        // Updates should produce different keys
        assert_ne!(first_update.key, second_update.key);
        assert_ne!(first_update.iv, second_update.iv);
        assert_ne!(first_update.hp_key, second_update.hp_key);
    }

    #[test]
    fn test_zero_key_material_detection() {
        let zero_keys = KeyMaterial::zero(32, 12);
        assert!(KeyDerivation::verify_non_zero_keys(&zero_keys).is_err());

        let non_zero_keys = KeyMaterial::new(vec![1u8; 32], vec![2u8; 12], vec![3u8; 32]);
        assert!(KeyDerivation::verify_non_zero_keys(&non_zero_keys).is_ok());

        // Mixed case - only key is zero
        let mixed_keys = KeyMaterial::new(vec![0u8; 32], vec![2u8; 12], vec![3u8; 32]);
        assert!(KeyDerivation::verify_non_zero_keys(&mixed_keys).is_err());
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
        let local_traffic_secret = vec![0x10u8; 32];
        let remote_traffic_secret = vec![0x20u8; 32];
        let result = schedule.initiate_key_update(&local_traffic_secret, &remote_traffic_secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_double_key_update() {
        let mut schedule = KeySchedule::new();

        let local_keys = KeyMaterial::new(vec![1u8; 32], vec![2u8; 12], vec![3u8; 32]);
        let remote_keys = KeyMaterial::new(vec![4u8; 32], vec![5u8; 12], vec![6u8; 32]);
        schedule
            .install_application_keys(local_keys, remote_keys)
            .unwrap();

        let local_traffic_secret = vec![0x10u8; 32];
        let remote_traffic_secret = vec![0x20u8; 32];

        // First update should succeed
        assert!(
            schedule
                .initiate_key_update(&local_traffic_secret, &remote_traffic_secret)
                .is_ok()
        );

        // Second update while first is pending should fail
        assert!(
            schedule
                .initiate_key_update(&local_traffic_secret, &remote_traffic_secret)
                .is_err()
        );
    }
}
