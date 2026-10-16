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
    fn durable_identity_rejects_revoked_public_history_entries() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("identity.json");
        let mut store = IdentityKeyStore::create(&path, strong_seed(8), 100).expect("create store");
        let retired = store.export_public().expect("retired public");
        store.rotate(strong_seed(9), 200).expect("rotate");
        let revoked = store.revoke(retired.fingerprint, 300).expect("revoke");

        assert!(matches!(
            DurablePeerIdentity::from_public_key(&revoked),
            Err(IdentityError::RevokedPublicKey {
                generation,
                fingerprint,
            }) if generation == retired.generation && fingerprint == retired.fingerprint
        ));
    }

    #[test]
    fn durable_identity_rejects_malformed_public_key_with_matching_fingerprint() {
        let public_key = "not-an-nkey-public-identity".to_string();
        let exported = PublicIdentityKey {
            generation: 42,
            fingerprint: KeyFingerprint::from_public_key(public_key.as_bytes())
                .expect("syntactic fingerprint"),
            public_key,
            revoked: false,
        };

        assert!(matches!(
            DurablePeerIdentity::from_public_key(&exported),
            Err(IdentityError::KeyStore(KeyStoreError::InvalidPublicKey(message)))
                if message.contains("generation 42")
        ));
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
