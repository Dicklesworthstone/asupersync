//! Durable ATP peer identity adapters.
//!
//! This module bridges the persistent key store with ATP session negotiation,
//! proof bundles, and transfer-id derivation. The public key remains the stable
//! source of identity; `PeerId` and key fingerprints are derived from it.

use crate::atp::proof::PeerIdentityInfo;
use crate::atp::transfer::TransferId;
use crate::net::atp::protocol::{
    ClientHello, PeerId, PeerIdentityError, SessionContextKind, SessionTraceId, TransferNonce,
};
use crate::security::keys::{IdentityKeyStore, KeyFingerprint, KeyStoreError, PublicIdentityKey};
use nkeys::{KeyPair, KeyPairType};

#[path = "../directory/mod.rs"]
pub mod directory;

pub use directory::{
    DeviceRecord, DirectoryAuditRecord, DirectoryEntryView, DirectoryError, DirectoryGrant,
    DirectoryGroupSummary, DirectoryIoError, DirectoryList, DirectoryOperation,
    DirectoryPeerSummary, DirectorySubject, GroupRecord, PathHint, PeerDirectory, PeerRecord,
    ResolvedDirectoryGrant, StalePathHint, TrustScope,
};

/// Durable ATP identity derived from a persisted public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurablePeerIdentity {
    peer_id: PeerId,
    public_key: String,
    fingerprint: KeyFingerprint,
    generation: u64,
}

impl DurablePeerIdentity {
    /// Build an identity from an exported public key.
    pub fn from_public_key(public_key: &PublicIdentityKey) -> Result<Self, IdentityError> {
        if public_key.revoked {
            return Err(IdentityError::RevokedPublicKey {
                generation: public_key.generation,
                fingerprint: public_key.fingerprint,
            });
        }
        Self::from_parts(
            public_key.public_key.clone(),
            public_key.fingerprint,
            public_key.generation,
        )
    }

    /// Build the active durable identity from a key store.
    pub fn from_key_store(store: &IdentityKeyStore) -> Result<Self, IdentityError> {
        let public_key = store.export_public()?;
        Self::from_public_key(&public_key)
    }

    fn from_parts(
        public_key: String,
        fingerprint: KeyFingerprint,
        generation: u64,
    ) -> Result<Self, IdentityError> {
        validate_nkey_public_key(&public_key, generation)?;
        let derived_fingerprint = KeyFingerprint::from_public_key(public_key.as_bytes())?;
        if derived_fingerprint != fingerprint {
            return Err(IdentityError::FingerprintMismatch {
                expected: derived_fingerprint,
                actual: fingerprint,
            });
        }
        let peer_id = PeerId::from_public_key(public_key.as_bytes())?;
        Ok(Self {
            peer_id,
            public_key,
            fingerprint,
            generation,
        })
    }

    /// Return the canonical session peer id.
    #[must_use]
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Return the public key material.
    #[must_use]
    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    /// Return the public key fingerprint.
    #[must_use]
    pub const fn fingerprint(&self) -> KeyFingerprint {
        self.fingerprint
    }

    /// Return the key generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Return the full canonical peer id as lowercase hex.
    #[must_use]
    pub fn peer_id_hex(&self) -> String {
        hex::encode(self.peer_id.as_bytes())
    }

    /// Build a client hello bound to this durable identity.
    #[must_use]
    pub fn client_hello_to(
        &self,
        responder: &Self,
        nonce: TransferNonce,
        context: SessionContextKind,
        trace_id: SessionTraceId,
    ) -> ClientHello {
        ClientHello::new(self.peer_id, responder.peer_id, nonce, context, trace_id)
    }

    /// Build proof-bundle peer identity metadata for a transfer.
    #[must_use]
    pub fn proof_identity_to(
        &self,
        destination: &Self,
        authenticated_at_micros: u64,
        mutual_auth: bool,
    ) -> PeerIdentityInfo {
        PeerIdentityInfo {
            source_peer_id: self.peer_id_hex(),
            destination_peer_id: destination.peer_id_hex(),
            auth_method: "nkey-ed25519".to_string(),
            key_fingerprints: vec![self.fingerprint.to_hex(), destination.fingerprint.to_hex()],
            authenticated_at_micros,
            mutual_auth,
        }
    }

    /// Derive the canonical ATP H2 transfer id for this peer pair.
    #[must_use]
    pub fn derive_transfer_id(
        &self,
        remote: &Self,
        nonce: TransferNonce,
        manifest_root: [u8; 32],
        policy_digest: [u8; 32],
    ) -> TransferId {
        TransferId::derive_with_policy(
            *self.peer_id.as_bytes(),
            *remote.peer_id.as_bytes(),
            *nonce.as_bytes(),
            manifest_root,
            policy_digest,
        )
    }
}

fn validate_nkey_public_key(public_key: &str, generation: u64) -> Result<(), KeyStoreError> {
    let key_pair = KeyPair::from_public_key(public_key).map_err(|err| {
        KeyStoreError::InvalidPublicKey(format!(
            "generation {generation} public key could not be decoded: {err}"
        ))
    })?;
    if key_pair.key_pair_type() != KeyPairType::User {
        return Err(KeyStoreError::InvalidPublicKey(format!(
            "generation {generation} is {:?}, expected User",
            key_pair.key_pair_type()
        )));
    }
    Ok(())
}

/// Durable identity construction failures.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// Key-store operation failed.
    #[error(transparent)]
    KeyStore(#[from] KeyStoreError),
    /// Peer id derivation rejected public key material.
    #[error(transparent)]
    PeerIdentity(#[from] PeerIdentityError),
    /// Public key fingerprint did not match the exported key.
    #[error("public key fingerprint mismatch: expected {expected}, got {actual}")]
    FingerprintMismatch {
        /// Fingerprint derived from the public key.
        expected: KeyFingerprint,
        /// Fingerprint supplied by the key export.
        actual: KeyFingerprint,
    },
    /// Revoked public-key generations cannot become active peer identities.
    #[error("public identity key generation {generation} is revoked ({fingerprint})")]
    RevokedPublicKey {
        /// Revoked key generation.
        generation: u64,
        /// Revoked public-key fingerprint.
        fingerprint: KeyFingerprint,
    },
}

#[cfg(test)]
#[path = "mod_inline_tests.rs"]
mod tests;
