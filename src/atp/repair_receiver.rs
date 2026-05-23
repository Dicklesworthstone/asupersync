//! ATP-G2 Repair symbol receiver with authentication validation.
//!
//! This module implements receiver-side validation logic for RaptorQ repair symbols
//! to ensure symbols match expected manifest, repair group parameters, and authentication
//! requirements as specified in ATP-G2.

use crate::atp::manifest::{
    AuthenticationAlgorithm, MerkleRoot, RaptorQSymbol, RepairGroup, RepairGroupId,
};
use hmac::KeyInit;
use sha2::Sha256;
use std::time::{Duration, SystemTime};

/// Errors specific to repair symbol reception and validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepairReceiveError {
    /// Symbol belongs to unknown repair group.
    UnknownRepairGroup(RepairGroupId),
    /// Symbol parameters don't match expected repair group.
    ParameterMismatch {
        /// Field name that mismatched.
        field: String,
        /// Expected value.
        expected: String,
        /// Received value.
        received: String,
    },
    /// Authentication tag verification failed.
    AuthenticationFailed(String),
    /// Symbol is replayed (already received).
    ReplayedSymbol {
        /// Symbol ESI.
        esi: u32,
        /// Previous receive timestamp.
        previous_timestamp: SystemTime,
    },
    /// Symbol session has expired.
    ExpiredSession {
        /// Session expiry time.
        expired_at: SystemTime,
        /// Current time.
        current_time: SystemTime,
    },
    /// Symbol object ID doesn't match expected.
    ObjectIdMismatch {
        /// Expected object ID.
        expected: String,
        /// Received object ID.
        received: String,
    },
    /// Manifest root doesn't match expected.
    ManifestRootMismatch {
        /// Expected manifest root.
        expected: MerkleRoot,
        /// Symbol's claimed manifest root.
        received: MerkleRoot,
    },
    /// Transform policy mismatch.
    TransformPolicyMismatch(String),
}

impl std::fmt::Display for RepairReceiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownRepairGroup(id) => {
                write!(f, "unknown repair group: {id}")
            }
            Self::ParameterMismatch {
                field,
                expected,
                received,
            } => {
                write!(
                    f,
                    "parameter mismatch in {field}: expected {expected}, got {received}"
                )
            }
            Self::AuthenticationFailed(msg) => {
                write!(f, "authentication failed: {msg}")
            }
            Self::ReplayedSymbol {
                esi,
                previous_timestamp,
            } => {
                write!(
                    f,
                    "replayed symbol ESI {esi}, previously received at {previous_timestamp:?}"
                )
            }
            Self::ExpiredSession {
                expired_at,
                current_time,
            } => {
                write!(
                    f,
                    "session expired at {expired_at:?}, current time {current_time:?}"
                )
            }
            Self::ObjectIdMismatch { expected, received } => {
                write!(f, "object ID mismatch: expected {expected}, got {received}")
            }
            Self::ManifestRootMismatch { expected, received } => {
                write!(
                    f,
                    "manifest root mismatch: expected {expected}, got {received}"
                )
            }
            Self::TransformPolicyMismatch(msg) => {
                write!(f, "transform policy mismatch: {msg}")
            }
        }
    }
}

impl std::error::Error for RepairReceiveError {}

/// Session context for tracking received symbols and preventing replay attacks.
#[derive(Debug, Clone)]
pub struct RepairSessionContext {
    /// Repair group this session belongs to.
    pub repair_group_id: RepairGroupId,
    /// Session start time.
    pub start_time: SystemTime,
    /// Session expiry time.
    pub expiry_time: SystemTime,
    /// Set of received symbol ESIs to prevent replay.
    pub received_esis: std::collections::BTreeSet<u32>,
    /// Authentication key for HMAC verification.
    pub auth_key: Vec<u8>,
    /// Session binding context.
    pub session_binding: Option<Vec<u8>>,
}

impl RepairSessionContext {
    /// Create a new session context.
    pub fn new(
        repair_group_id: RepairGroupId,
        session_duration: Duration,
        auth_key: Vec<u8>,
        session_binding: Option<Vec<u8>>,
    ) -> Self {
        let start_time = SystemTime::now();
        let expiry_time = start_time + session_duration;

        Self {
            repair_group_id,
            start_time,
            expiry_time,
            received_esis: std::collections::BTreeSet::new(),
            auth_key,
            session_binding,
        }
    }

    /// Check if this session has expired.
    pub fn is_expired(&self) -> bool {
        SystemTime::now() > self.expiry_time
    }

    /// Mark a symbol ESI as received.
    pub fn mark_received(&mut self, esi: u32) -> bool {
        self.received_esis.insert(esi)
    }

    /// Check if a symbol ESI was already received.
    pub fn was_received(&self, esi: u32) -> Option<SystemTime> {
        if self.received_esis.contains(&esi) {
            // Return approximate receive time (we don't track exact timestamps per ESI)
            Some(self.start_time)
        } else {
            None
        }
    }
}

/// ATP-G2 repair symbol receiver with comprehensive validation.
#[derive(Debug)]
pub struct RepairReceiver {
    /// Expected manifest root for validation.
    expected_manifest_root: MerkleRoot,
    /// Repair group configurations.
    repair_groups: std::collections::BTreeMap<RepairGroupId, RepairGroup>,
    /// Active sessions for replay protection.
    sessions: std::collections::BTreeMap<RepairGroupId, RepairSessionContext>,
}

impl RepairReceiver {
    /// Create a new repair receiver.
    pub fn new(
        expected_manifest_root: MerkleRoot,
        repair_groups: std::collections::BTreeMap<RepairGroupId, RepairGroup>,
    ) -> Self {
        Self {
            expected_manifest_root,
            repair_groups,
            sessions: std::collections::BTreeMap::new(),
        }
    }

    /// Start a new session for a repair group.
    pub fn start_session(
        &mut self,
        repair_group_id: RepairGroupId,
        session_duration: Duration,
        auth_key: Vec<u8>,
        session_binding: Option<Vec<u8>>,
    ) -> Result<(), RepairReceiveError> {
        // Verify repair group exists
        if !self.repair_groups.contains_key(&repair_group_id) {
            return Err(RepairReceiveError::UnknownRepairGroup(repair_group_id));
        }

        let session = RepairSessionContext::new(
            repair_group_id.clone(),
            session_duration,
            auth_key,
            session_binding,
        );

        self.sessions.insert(repair_group_id, session);
        Ok(())
    }

    /// Validate and accept a repair symbol with comprehensive ATP-G2 checks.
    pub fn validate_repair_symbol(
        &mut self,
        symbol: &RaptorQSymbol,
        claimed_manifest_root: &MerkleRoot,
        claimed_object_id: &str,
    ) -> Result<(), RepairReceiveError> {
        // Extract repair group ID from symbol
        let group_id = symbol.repair_group_id.as_ref().ok_or_else(|| {
            RepairReceiveError::ParameterMismatch {
                field: "repair_group_id".to_string(),
                expected: "Some(group_id)".to_string(),
                received: "None".to_string(),
            }
        })?;

        // Verify repair group exists
        let repair_group = self
            .repair_groups
            .get(group_id)
            .ok_or_else(|| RepairReceiveError::UnknownRepairGroup(group_id.clone()))?;

        // Validate manifest root
        if *claimed_manifest_root != self.expected_manifest_root {
            return Err(RepairReceiveError::ManifestRootMismatch {
                expected: self.expected_manifest_root.clone(),
                received: claimed_manifest_root.clone(),
            });
        }

        // Validate object ID
        if claimed_object_id != repair_group.object_id.to_string() {
            return Err(RepairReceiveError::ObjectIdMismatch {
                expected: repair_group.object_id.to_string(),
                received: claimed_object_id.to_string(),
            });
        }

        // Validate symbol parameters against repair group
        self.validate_symbol_parameters(symbol, repair_group)?;

        // Check session and replay protection
        let _session_valid = if let Some(session) = self.sessions.get_mut(group_id) {
            Self::validate_session_and_replay_static(symbol, session)?;
            true
        } else {
            false
        };

        // Validate authentication tag
        self.validate_authentication(symbol, repair_group)?;

        Ok(())
    }

    /// Validate symbol parameters match repair group configuration.
    fn validate_symbol_parameters(
        &self,
        symbol: &RaptorQSymbol,
        repair_group: &RepairGroup,
    ) -> Result<(), RepairReceiveError> {
        // Validate ESI is within valid range for this repair group
        let max_esi =
            repair_group.source_symbols_k + repair_group.repair_layout.total_repair_symbols;
        if symbol.esi >= max_esi {
            return Err(RepairReceiveError::ParameterMismatch {
                field: "esi".to_string(),
                expected: format!("< {max_esi}"),
                received: symbol.esi.to_string(),
            });
        }

        // Validate symbol size
        if symbol.size_bytes != repair_group.symbol_size {
            return Err(RepairReceiveError::ParameterMismatch {
                field: "size_bytes".to_string(),
                expected: repair_group.symbol_size.to_string(),
                received: symbol.size_bytes.to_string(),
            });
        }

        // Validate source/repair symbol classification
        let is_source_expected = symbol.esi < repair_group.source_symbols_k;
        if symbol.is_source != is_source_expected {
            return Err(RepairReceiveError::ParameterMismatch {
                field: "is_source".to_string(),
                expected: is_source_expected.to_string(),
                received: symbol.is_source.to_string(),
            });
        }

        Ok(())
    }

    /// Validate session status and check for replay attacks.
    fn validate_session_and_replay_static(
        symbol: &RaptorQSymbol,
        session: &mut RepairSessionContext,
    ) -> Result<(), RepairReceiveError> {
        let current_time = SystemTime::now(); // ubs:ignore - time check, not crypto randomness // ubs:ignore

        // Check session expiry
        if current_time > session.expiry_time {
            return Err(RepairReceiveError::ExpiredSession {
                expired_at: session.expiry_time,
                current_time,
            });
        }

        // Check for replay
        if let Some(previous_timestamp) = session.was_received(symbol.esi) {
            return Err(RepairReceiveError::ReplayedSymbol {
                esi: symbol.esi,
                previous_timestamp,
            });
        }

        // Mark as received
        session.mark_received(symbol.esi);

        Ok(())
    }

    /// Validate authentication tag.
    fn validate_authentication(
        &self,
        symbol: &RaptorQSymbol,
        repair_group: &RepairGroup,
    ) -> Result<(), RepairReceiveError> {
        let auth_tag = symbol.auth_tag.as_ref().ok_or_else(|| {
            RepairReceiveError::AuthenticationFailed("missing authentication tag".to_string())
        })?;

        // Get session for auth key
        let session = self.sessions.get(&repair_group.group_id).ok_or_else(|| {
            RepairReceiveError::AuthenticationFailed("no active session for group".to_string())
        })?;

        match repair_group.auth_domain.auth_algorithm {
            AuthenticationAlgorithm::HmacSha256 => {
                let expected_tag = self.compute_hmac_sha256_tag(symbol, repair_group, session)?;
                let tags_match: bool =
                    subtle::ConstantTimeEq::ct_eq(&auth_tag[..], &expected_tag[..]).into();
                if !tags_match {
                    return Err(RepairReceiveError::AuthenticationFailed(
                        "HMAC-SHA256 verification failed".to_string(),
                    ));
                }
            }
            AuthenticationAlgorithm::EdDsa => {
                return Err(RepairReceiveError::AuthenticationFailed(
                    "EdDSA authentication not yet implemented".to_string(),
                ));
            }
            AuthenticationAlgorithm::X25519Ecdh => {
                return Err(RepairReceiveError::AuthenticationFailed(
                    "X25519-ECDH authentication not yet implemented".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Compute HMAC-SHA256 authentication tag for a symbol.
    fn compute_hmac_sha256_tag(
        &self,
        symbol: &RaptorQSymbol,
        repair_group: &RepairGroup,
        session: &RepairSessionContext,
    ) -> Result<[u8; 32], RepairReceiveError> {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(&session.auth_key).map_err(|_| {
            RepairReceiveError::AuthenticationFailed("invalid auth key".to_string())
        })?;

        // Include all critical symbol and group parameters in the MAC
        mac.update(b"ATP-G2-RepairSymbol");
        mac.update(repair_group.group_id.as_bytes());
        mac.update(repair_group.manifest_root.hash());
        mac.update(repair_group.object_id.hash_bytes());
        mac.update(&repair_group.source_block_number.to_be_bytes());
        mac.update(&repair_group.source_symbols_k.to_be_bytes());
        mac.update(&repair_group.k_prime.to_be_bytes());
        mac.update(&symbol.esi.to_be_bytes());
        mac.update(&symbol.size_bytes.to_be_bytes());
        mac.update(&symbol.content_hash);
        mac.update(&[u8::from(symbol.is_source)]);

        // Include session binding if present
        if let Some(binding) = &session.session_binding {
            mac.update(b"session_binding:");
            mac.update(binding);
        }

        let result = mac.finalize().into_bytes();
        Ok(result.into())
    }

    /// Clean up expired sessions.
    pub fn cleanup_expired_sessions(&mut self) {
        let current_time = SystemTime::now(); // ubs:ignore - time check, not crypto randomness // ubs:ignore
        self.sessions
            .retain(|_, session| current_time <= session.expiry_time);
    }

    /// Get statistics about active sessions.
    pub fn session_stats(&self) -> (usize, usize) {
        let active_sessions = self.sessions.len();
        let total_received_symbols: usize = self
            .sessions
            .values()
            .map(|session| session.received_esis.len())
            .sum();
        (active_sessions, total_received_symbols)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::manifest::*;
    use crate::atp::object::{ContentId, ObjectId};
    use std::collections::BTreeMap;
    use std::time::Duration;

    fn test_object_id(content: &[u8]) -> ObjectId {
        ObjectId::content(ContentId::from_bytes(content))
    }

    fn create_test_repair_group() -> (RepairGroupId, RepairGroup) {
        let object_id = test_object_id(&[1, 2, 3, 4]);
        let group_id = RepairGroupId::new(&object_id, 0, 1024);

        let repair_group = RepairGroup {
            group_id: group_id.clone(),
            object_id,
            source_block_number: 0,
            chunk_range: ChunkRange {
                start_chunk: 0,
                end_chunk: 1,
                start_offset: 0,
                end_offset: 1024,
            },
            source_symbols_k: 1000,
            k_prime: 1024,
            symbol_size: 1024,
            repair_layout: RepairLayout {
                total_repair_symbols: 200,
                overhead_ratio: 0.2,
                systematic_config: SystematicConfig {
                    systematic_rows: 1000,
                    sub_symbols: 1,
                    alignment: 8,
                },
                interleaving: InterleavingPattern {
                    block_size: 1,
                    depth: 1,
                    pattern_type: InterleavingType::None,
                },
            },
            hash_domain: HashDomain {
                domain_id: "test".to_string(),
                hash_algorithm: HashAlgorithm::Sha256,
                context: vec![],
            },
            transform_policy: None,
            auth_domain: AuthenticationDomain {
                domain_id: "test-auth".to_string(),
                required_proof_strength: ProofStrength::Basic,
                auth_algorithm: AuthenticationAlgorithm::HmacSha256,
                peer_identity_required: false,
                transfer_identity_binding: false,
                session_binding: true,
            },
            capability_policy: None,
            manifest_root: MerkleRoot::new([0u8; 32]),
        };

        (group_id, repair_group)
    }

    #[test]
    fn test_session_creation() {
        let (group_id, repair_group) = create_test_repair_group();
        let manifest_root = repair_group.manifest_root.clone();

        let mut repair_groups = BTreeMap::new();
        repair_groups.insert(group_id.clone(), repair_group);

        let mut receiver = RepairReceiver::new(manifest_root, repair_groups);

        // Should succeed
        let result = receiver.start_session(
            group_id.clone(),
            Duration::from_secs(3600),
            vec![1, 2, 3, 4],
            Some(b"test_session".to_vec()),
        );
        assert!(result.is_ok());

        // Should fail for unknown group
        let unknown_group = RepairGroupId::new(&test_object_id(&[5, 6, 7, 8]), 1, 512);
        let result = receiver.start_session(
            unknown_group,
            Duration::from_secs(3600),
            vec![1, 2, 3, 4],
            None,
        );
        assert!(matches!(
            result,
            Err(RepairReceiveError::UnknownRepairGroup(_))
        ));
    }

    #[test]
    fn test_symbol_parameter_validation() {
        let (group_id, repair_group) = create_test_repair_group();
        let manifest_root = repair_group.manifest_root.clone();
        let object_id = repair_group.object_id.clone();

        let mut repair_groups = BTreeMap::new();
        repair_groups.insert(group_id.clone(), repair_group);

        let receiver = RepairReceiver::new(manifest_root.clone(), repair_groups);

        // Valid symbol
        let valid_symbol = RaptorQSymbol {
            index: 0,
            esi: 500,
            size_bytes: 1024,
            content_hash: [0u8; 32],
            is_source: true,
            repair_group_id: Some(group_id.clone()),
            auth_tag: Some([0u8; 32]),
        };

        // Should pass parameter validation (ignoring session/auth for this test)
        let result =
            receiver.validate_symbol_parameters(&valid_symbol, &receiver.repair_groups[&group_id]);
        assert!(result.is_ok());

        // Invalid ESI (too high)
        let invalid_esi_symbol = RaptorQSymbol {
            esi: 2000, // > k + total_repair_symbols
            ..valid_symbol.clone()
        };

        let result = receiver
            .validate_symbol_parameters(&invalid_esi_symbol, &receiver.repair_groups[&group_id]);
        assert!(
            matches!(result, Err(RepairReceiveError::ParameterMismatch { field, .. }) if field == "esi") // ubs:ignore - error field name comparison
        );

        // Invalid size
        let invalid_size_symbol = RaptorQSymbol {
            size_bytes: 512, // Should be 1024
            ..valid_symbol.clone()
        };

        let result = receiver
            .validate_symbol_parameters(&invalid_size_symbol, &receiver.repair_groups[&group_id]);
        assert!(
            matches!(result, Err(RepairReceiveError::ParameterMismatch { field, .. }) if field == "size_bytes") // ubs:ignore
        );
    }

    #[test]
    fn test_replay_detection() {
        let (group_id, _repair_group) = create_test_repair_group();

        let mut session = RepairSessionContext::new(
            group_id.clone(),
            Duration::from_secs(3600),
            vec![1, 2, 3, 4],
            None,
        );

        // First symbol should be accepted
        assert!(session.mark_received(100));

        // Same ESI should be detected as replay
        assert!(!session.mark_received(100));
        assert!(session.was_received(100).is_some());

        // Different ESI should be accepted
        assert!(session.mark_received(101));
    }

    #[test]
    fn test_session_expiry() {
        let (group_id, _) = create_test_repair_group();

        // Create session with very short duration
        let session =
            RepairSessionContext::new(group_id, Duration::from_millis(1), vec![1, 2, 3, 4], None);

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(10));

        assert!(session.is_expired());
    }
}
