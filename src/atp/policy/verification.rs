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
#[path = "verification_inline_tests.rs"]
mod tests;
