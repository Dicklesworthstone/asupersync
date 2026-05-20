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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::atp::protocol::{
        AtpFeature, SessionNegotiationState, SessionNegotiator, SessionPolicy,
    };
    use sha2::{Digest, Sha256};
    use tempfile::tempdir;

    fn strong_seed(tag: u8) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"asupersync::atp::identity::tests");
        hasher.update([tag]);
        hasher.finalize().into()
    }

    fn identity(tag: u8) -> DurablePeerIdentity {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join(format!("identity-{tag}.json"));
        let store = IdentityKeyStore::create(path, strong_seed(tag), u64::from(tag))
            .expect("create key store");
        DurablePeerIdentity::from_key_store(&store).expect("durable identity")
    }

    #[test]
    fn durable_peer_id_is_stable_from_public_key() {
        let alice = identity(1);
        let exported = PublicIdentityKey {
            generation: alice.generation(),
            public_key: alice.public_key().to_string(),
            fingerprint: alice.fingerprint(),
            revoked: false,
        };
        let round_trip = DurablePeerIdentity::from_public_key(&exported).expect("round trip");

        assert_eq!(alice.peer_id(), round_trip.peer_id());
        assert_eq!(
            alice.peer_id(),
            PeerId::from_public_key(alice.public_key().as_bytes()).expect("peer id")
        );
    }

    #[test]
    fn transfer_id_binds_durable_peers_nonce_manifest_and_policy() {
        let alice = identity(2);
        let bob = identity(3);
        let nonce = TransferNonce::from_seed("durable-transfer");
        let manifest_root = [4; 32];
        let policy_digest = [5; 32];
        let baseline = alice.derive_transfer_id(&bob, nonce, manifest_root, policy_digest);

        assert_eq!(
            baseline,
            alice.derive_transfer_id(&bob, nonce, manifest_root, policy_digest)
        );
        assert_ne!(
            baseline,
            bob.derive_transfer_id(&alice, nonce, manifest_root, policy_digest)
        );
        assert_ne!(
            baseline,
            alice.derive_transfer_id(
                &bob,
                TransferNonce::from_seed("other"),
                manifest_root,
                policy_digest
            )
        );
        assert_ne!(
            baseline,
            alice.derive_transfer_id(&bob, nonce, [9; 32], policy_digest)
        );
        assert_ne!(
            baseline,
            alice.derive_transfer_id(&bob, nonce, manifest_root, [9; 32])
        );
    }

    #[test]
    fn durable_identity_feeds_session_auth_and_proof_metadata() {
        let alice = identity(6);
        let bob = identity(7);
        let nonce = TransferNonce::from_seed("identity-session");
        let hello = alice
            .client_hello_to(
                &bob,
                nonce,
                SessionContextKind::Direct,
                SessionTraceId::new(11),
            )
            .with_features(&[
                AtpFeature::EncryptionPolicy,
                AtpFeature::ProofBundles,
                AtpFeature::Resume,
            ]);

        let mut server = SessionNegotiator::server(bob.peer_id());
        let mut policy = SessionPolicy::new(bob.peer_id(), 1_000);
        let (server_hello, _frame, proof) = server
            .accept_client_hello(&hello, &mut policy)
            .expect("accept hello");

        assert!(matches!(
            server.state(),
            SessionNegotiationState::ServerHelloSent
        ));
        assert_eq!(server_hello.initiator, alice.peer_id());
        assert_eq!(server_hello.acceptor, bob.peer_id());
        assert_eq!(proof.rejected_reason, None);

        let proof_identity = alice.proof_identity_to(&bob, 1_234, true);
        assert_eq!(proof_identity.source_peer_id, alice.peer_id_hex());
        assert_eq!(proof_identity.destination_peer_id, bob.peer_id_hex());
        assert_eq!(proof_identity.auth_method, "nkey-ed25519");
        assert_eq!(
            proof_identity.key_fingerprints,
            vec![alice.fingerprint().to_hex(), bob.fingerprint().to_hex()]
        );
    }
}
