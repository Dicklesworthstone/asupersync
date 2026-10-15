//! Capability signature verification and validation.

use super::{Capability, CapabilityError, CapabilityResult};
use crate::atp::identity::DurablePeerIdentity;
use crate::security::keys::IdentityKeyStore;
use crate::types::outcome::Outcome;
use nkeys::KeyPair;
use serde_json;

/// Capability signer for creating signed capability grants.
pub struct CapabilitySigner {
    /// Identity for signing grants
    identity: DurablePeerIdentity,
    /// Key store for signing operations
    key_store: IdentityKeyStore,
}

impl CapabilitySigner {
    /// Create a new capability signer.
    pub fn new(key_store: IdentityKeyStore) -> CapabilityResult<Self> {
        let identity = match DurablePeerIdentity::from_key_store(&key_store) {
            Ok(identity) => identity,
            Err(e) => return Outcome::err(CapabilityError::Storage(e.to_string())),
        };

        Outcome::ok(Self {
            identity,
            key_store,
        })
    }

    /// Sign a capability grant.
    pub fn sign_capability(&self, capability: &mut Capability) -> CapabilityResult<()> {
        // Create canonical representation for signing
        let signing_data = match self.create_signing_data(capability) {
            Outcome::Ok(data) => data,
            Outcome::Err(error) => return Outcome::Err(error),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        };

        // Sign with the key store
        let key_pair = match self.key_store.active_key_pair() {
            Ok(key_pair) => key_pair,
            Err(e) => return Outcome::err(CapabilityError::Storage(e.to_string())),
        };
        let signature = match key_pair.sign(&signing_data) {
            Ok(signature) => signature,
            Err(e) => return Outcome::err(CapabilityError::Storage(e.to_string())),
        };

        capability.signature = signature;
        Outcome::ok(())
    }

    /// Create signing data for a capability.
    fn create_signing_data(&self, capability: &Capability) -> CapabilityResult<Vec<u8>> {
        // Create a deterministic signing representation
        let signing_cap = SigningCapability {
            grant_id: &capability.grant_id,
            subject: capability.subject,
            issuer: capability.issuer,
            scope_digest: capability.scope.digest(),
            actions: {
                let mut actions: Vec<_> = capability.actions.iter().collect();
                actions.sort_by_key(|a| format!("{a:?}"));
                actions
            },
            temporal_hash: self.hash_temporal_scope(&capability.temporal),
            constraints_digest: capability.constraints.digest(),
            issued_at_secs: capability
                .issued_at
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        match serde_json::to_vec(&signing_cap) {
            Ok(data) => Outcome::ok(data),
            Err(e) => Outcome::err(CapabilityError::Serialization(e)),
        }
    }

    /// Create a hash of temporal scope for signing.
    fn hash_temporal_scope(&self, temporal: &super::TemporalScope) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();

        if let Some(not_before) = temporal.not_before {
            hasher.update(
                not_before
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    .to_le_bytes(),
            );
        }
        if let Some(not_after) = temporal.not_after {
            hasher.update(
                not_after
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    .to_le_bytes(),
            );
        }
        if let Some(max_uses) = temporal.max_uses {
            hasher.update(max_uses.to_le_bytes());
        }

        hasher.finalize().into()
    }

    /// Get the signer's peer identity.
    #[must_use]
    pub fn identity(&self) -> &DurablePeerIdentity {
        &self.identity
    }
}

/// Capability verifier for validating signed grants.
pub struct CapabilityVerifier {
    /// Known peer identities for verification
    trusted_peers:
        std::collections::HashMap<crate::net::atp::protocol::PeerId, DurablePeerIdentity>,
}

impl CapabilityVerifier {
    /// Create a new capability verifier.
    #[must_use]
    pub fn new() -> Self {
        Self {
            trusted_peers: std::collections::HashMap::new(),
        }
    }

    /// Add a trusted peer for verification.
    pub fn add_trusted_peer(&mut self, identity: DurablePeerIdentity) {
        self.trusted_peers.insert(identity.peer_id(), identity);
    }

    /// Verify a capability signature.
    pub fn verify_capability(&self, capability: &Capability) -> CapabilityResult<bool> {
        // Get the issuer's identity
        let issuer_identity = match self.trusted_peers.get(&capability.issuer) {
            Some(identity) => identity,
            None => {
                return Outcome::err(CapabilityError::InvalidCapability {
                    reason: "issuer not in trusted peers".to_string(),
                });
            }
        };

        if capability.signature.is_empty() {
            return Outcome::ok(false);
        }

        // Create the signing data
        let signing_data = match self.create_verification_data(capability) {
            Outcome::Ok(data) => data,
            Outcome::Err(error) => return Outcome::Err(error),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        };

        let issuer_key = match KeyPair::from_public_key(issuer_identity.public_key()) {
            Ok(key) => key,
            Err(error) => {
                return Outcome::err(CapabilityError::InvalidCapability {
                    reason: format!("issuer public key invalid: {error}"),
                });
            }
        };

        Outcome::ok(
            issuer_key
                .verify(&signing_data, &capability.signature)
                .is_ok(),
        )
    }

    /// Verify and validate a capability comprehensively.
    pub fn validate_capability(
        &self,
        capability: &Capability,
    ) -> CapabilityResult<ValidationResult> {
        self.validate_capability_at(capability, std::time::SystemTime::now())
    }

    /// Verify and validate a capability at an explicit evaluation time.
    pub fn validate_capability_at(
        &self,
        capability: &Capability,
        now: std::time::SystemTime,
    ) -> CapabilityResult<ValidationResult> {
        let mut issues = Vec::new();

        // Check signature
        match self.verify_capability(capability) {
            Outcome::Ok(true) => {}
            Outcome::Ok(false) => issues.push(ValidationIssue::InvalidSignature),
            Outcome::Err(e) => issues.push(ValidationIssue::SignatureError(e.to_string())),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        // Check if issuer is subject (self-signed) and issuer is trusted
        if capability.issuer == capability.subject
            && !self.trusted_peers.contains_key(&capability.issuer)
        {
            issues.push(ValidationIssue::UntrustedSelfSigned);
        }

        // Check temporal validity
        if !capability.temporal.is_valid_at(now) {
            issues.push(ValidationIssue::TemporalViolation);
        }

        // Check for empty actions
        if capability.actions.is_empty() {
            issues.push(ValidationIssue::NoActions);
        }

        // Check grant ID format
        if capability.grant_id.is_empty() || capability.grant_id.len() < 8 {
            issues.push(ValidationIssue::InvalidGrantId);
        }

        let valid = issues.is_empty();
        Outcome::ok(ValidationResult { valid, issues })
    }

    /// Create verification data for a capability.
    fn create_verification_data(&self, capability: &Capability) -> CapabilityResult<Vec<u8>> {
        // This should match the signing data creation in CapabilitySigner
        let signing_cap = SigningCapability {
            grant_id: &capability.grant_id,
            subject: capability.subject,
            issuer: capability.issuer,
            scope_digest: capability.scope.digest(),
            actions: {
                let mut actions: Vec<_> = capability.actions.iter().collect();
                actions.sort_by_key(|a| format!("{a:?}"));
                actions
            },
            temporal_hash: self.hash_temporal_scope(&capability.temporal),
            constraints_digest: capability.constraints.digest(),
            issued_at_secs: capability
                .issued_at
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        match serde_json::to_vec(&signing_cap) {
            Ok(data) => Outcome::ok(data),
            Err(e) => Outcome::err(CapabilityError::Serialization(e)),
        }
    }

    /// Create a hash of temporal scope for verification.
    fn hash_temporal_scope(&self, temporal: &super::TemporalScope) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();

        if let Some(not_before) = temporal.not_before {
            hasher.update(
                not_before
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    .to_le_bytes(),
            );
        }
        if let Some(not_after) = temporal.not_after {
            hasher.update(
                not_after
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    .to_le_bytes(),
            );
        }
        if let Some(max_uses) = temporal.max_uses {
            hasher.update(max_uses.to_le_bytes());
        }

        hasher.finalize().into()
    }
}

impl Default for CapabilityVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Deterministic signing representation of a capability.
#[derive(serde::Serialize)]
struct SigningCapability<'a> {
    grant_id: &'a str,
    subject: crate::net::atp::protocol::PeerId,
    issuer: crate::net::atp::protocol::PeerId,
    scope_digest: [u8; 32],
    actions: Vec<&'a super::CapabilityAction>,
    temporal_hash: [u8; 32],
    constraints_digest: [u8; 32],
    issued_at_secs: u64,
}

/// Result of capability validation.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Whether the capability is valid
    pub valid: bool,
    /// List of validation issues found
    pub issues: Vec<ValidationIssue>,
}

/// Issues that can be found during capability validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationIssue {
    /// Invalid signature
    InvalidSignature,
    /// Signature verification error
    SignatureError(String),
    /// Untrusted self-signed capability
    UntrustedSelfSigned,
    /// Temporal constraint violation
    TemporalViolation,
    /// No actions specified
    NoActions,
    /// Invalid grant ID format
    InvalidGrantId,
}

impl std::fmt::Display for ValidationIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSignature => write!(f, "invalid signature"),
            Self::SignatureError(msg) => write!(f, "signature error: {msg}"),
            Self::UntrustedSelfSigned => write!(f, "untrusted self-signed capability"),
            Self::TemporalViolation => write!(f, "temporal constraint violation"),
            Self::NoActions => write!(f, "no actions specified"),
            Self::InvalidGrantId => write!(f, "invalid grant ID format"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::policy::{CapabilityAction, ResourceScope, ScopeConstraints, TemporalScope};
    use crate::net::atp::protocol::PeerId;
    use std::collections::HashSet;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tempfile::tempdir;

    fn fixed_time(seconds_since_epoch: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds_since_epoch)
    }

    fn fixed_issued_at() -> SystemTime {
        fixed_time(1_800_000_000)
    }

    fn fixed_validation_time() -> SystemTime {
        fixed_time(1_800_000_100)
    }

    fn fixed_valid_temporal_scope() -> TemporalScope {
        TemporalScope::window(fixed_time(1_799_999_900), fixed_time(1_800_003_700))
    }

    const fn strong_test_seed() -> [u8; 32] {
        [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ]
    }

    fn create_test_signer() -> CapabilitySigner {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("test-key.json");
        let key_store =
            IdentityKeyStore::create(path, strong_test_seed(), 1).expect("create key store");
        CapabilitySigner::new(key_store).expect("create signer")
    }

    fn create_test_capability(signer: &CapabilitySigner) -> Capability {
        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);

        let mut capability = Capability::new(
            "test-grant-12345".to_string(),
            PeerId::test(1),
            signer.identity().peer_id(),
            ResourceScope::Any,
            actions,
            fixed_valid_temporal_scope(),
            ScopeConstraints::default(),
        );
        capability.issued_at = fixed_issued_at();
        capability
    }

    #[test]
    fn capability_signing_and_verification() {
        let signer = create_test_signer();
        let mut capability = create_test_capability(&signer);

        // Sign the capability
        signer
            .sign_capability(&mut capability)
            .expect("sign capability"); // ubs:ignore - test oracle
        assert!(!capability.signature.is_empty());

        // Create verifier and add trusted peer
        let mut verifier = CapabilityVerifier::new();
        verifier.add_trusted_peer(signer.identity().clone());

        // Verify the capability
        let valid = verifier
            .verify_capability(&capability)
            .expect("verify capability"); // ubs:ignore - test oracle
        assert!(valid);
    }

    #[test]
    fn capability_verification_rejects_tampered_signed_field() {
        let signer = create_test_signer();
        let mut capability = create_test_capability(&signer);
        signer
            .sign_capability(&mut capability)
            .expect("sign capability"); // ubs:ignore - test oracle

        capability.grant_id.push_str("-tampered");

        let mut verifier = CapabilityVerifier::new();
        verifier.add_trusted_peer(signer.identity().clone());

        let valid = verifier
            .verify_capability(&capability)
            .expect("verify tampered capability"); // ubs:ignore - test oracle
        assert!(!valid);

        let result = verifier
            .validate_capability_at(&capability, fixed_validation_time())
            .expect("validate tampered capability"); // ubs:ignore - test oracle
        assert!(!result.valid);
        assert!(result.issues.contains(&ValidationIssue::InvalidSignature));
    }

    #[test]
    fn capability_verification_rejects_tampered_signature() {
        let signer = create_test_signer();
        let mut capability = create_test_capability(&signer);
        signer
            .sign_capability(&mut capability)
            .expect("sign capability"); // ubs:ignore - test oracle

        capability.signature[0] ^= 0x01;

        let mut verifier = CapabilityVerifier::new();
        verifier.add_trusted_peer(signer.identity().clone());

        let valid = verifier
            .verify_capability(&capability)
            .expect("verify tampered signature"); // ubs:ignore - test oracle
        assert!(!valid);
    }

    #[test]
    fn capability_validation_rejects_missing_signature() {
        let signer = create_test_signer();
        let capability = create_test_capability(&signer);

        let mut verifier = CapabilityVerifier::new();
        verifier.add_trusted_peer(signer.identity().clone());

        let valid = verifier
            .verify_capability(&capability)
            .expect("verify unsigned capability"); // ubs:ignore - test oracle
        assert!(!valid);

        let result = verifier
            .validate_capability_at(&capability, fixed_validation_time())
            .expect("validate unsigned capability"); // ubs:ignore - test oracle
        assert!(!result.valid);
        assert!(result.issues.contains(&ValidationIssue::InvalidSignature));
    }

    #[test]
    fn capability_validation_detects_issues() {
        let signer = create_test_signer();
        let mut capability = create_test_capability(&signer);

        // Create invalid capability (empty actions)
        capability.actions.clear();

        signer
            .sign_capability(&mut capability)
            .expect("sign capability"); // ubs:ignore - test oracle

        let mut verifier = CapabilityVerifier::new();
        verifier.add_trusted_peer(signer.identity().clone());

        let result = verifier
            .validate_capability_at(&capability, fixed_validation_time())
            .expect("validate capability");
        assert!(!result.valid);
        assert!(result.issues.contains(&ValidationIssue::NoActions));
    }

    #[test]
    fn expired_capability_validation() {
        let signer = create_test_signer();
        let mut capability = create_test_capability(&signer);

        // Set capability to expire in the past
        let past = fixed_validation_time() - Duration::from_secs(100);
        capability.temporal = TemporalScope::window(past - Duration::from_secs(100), past);

        signer
            .sign_capability(&mut capability)
            .expect("sign capability"); // ubs:ignore - test oracle

        let mut verifier = CapabilityVerifier::new();
        verifier.add_trusted_peer(signer.identity().clone());

        let result = verifier
            .validate_capability_at(&capability, fixed_validation_time())
            .expect("validate capability");
        assert!(!result.valid);
        assert!(result.issues.contains(&ValidationIssue::TemporalViolation));
    }

    #[test]
    fn untrusted_issuer_verification_fails() {
        let signer = create_test_signer();
        let mut capability = create_test_capability(&signer);
        signer
            .sign_capability(&mut capability)
            .expect("sign capability"); // ubs:ignore - test oracle

        // Create verifier without adding the trusted peer
        let verifier = CapabilityVerifier::new();

        let result = verifier.verify_capability(&capability);
        assert!(result.is_err());
    }

    #[test]
    fn signing_data_is_deterministic() {
        let signer = create_test_signer();
        let capability1 = create_test_capability(&signer);
        let capability2 = create_test_capability(&signer);

        let data1 = signer
            .create_signing_data(&capability1)
            .expect("create signing data");
        let data2 = signer
            .create_signing_data(&capability2)
            .expect("create signing data");

        assert_eq!(data1, data2);
    }
}
