    use super::*;
    use crate::atp::verifier::{VerificationEvidence, VerificationStage};

    fn trusted_key_map(
        fingerprint: &str,
        auth_key: AuthKey,
    ) -> std::collections::BTreeMap<String, AuthKey> {
        std::collections::BTreeMap::from([(fingerprint.to_string(), auth_key)])
    }

    #[test]
    fn proof_timestamp_rejects_clock_before_unix_epoch() {
        let err = system_time_micros_since_unix_epoch(
            UNIX_EPOCH - Duration::from_micros(1),
            "created_at_micros",
        )
        .expect_err("pre-epoch system time must fail closed");

        assert_eq!(
            err,
            AtpProofBundleError::InvalidSystemTime {
                field: "created_at_micros",
            }
        );
    }

    #[test]
    fn proof_timestamp_rejects_microsecond_overflow() {
        let err = duration_micros_to_u64(Duration::from_secs(u64::MAX), "signed_at_micros")
            .expect_err("oversized duration must not truncate");

        assert!(matches!(
            err,
            AtpProofBundleError::TimestampOutOfRange {
                field: "signed_at_micros",
                ..
            }
        ));
    }

    #[test]
    fn chunk_bitmap_basic_operations() {
        let mut bitmap = ChunkBitmap::new(10);
        assert_eq!(bitmap.total_chunks, 10);
        assert_eq!(bitmap.received_count, 0);
        assert!(!bitmap.is_received(0));

        bitmap.mark_received(0);
        bitmap.mark_received(5);
        bitmap.mark_received(9);

        assert!(bitmap.is_received(0));
        assert!(bitmap.is_received(5));
        assert!(bitmap.is_received(9));
        assert!(!bitmap.is_received(1));
        assert!(!bitmap.is_received(8));
        assert_eq!(bitmap.received_count, 3);
        assert_eq!(bitmap.completion_ratio(), 0.3);
    }

    #[test]
    fn chunk_bitmap_duplicate_marking() {
        let mut bitmap = ChunkBitmap::new(5);
        bitmap.mark_received(2);
        bitmap.mark_received(2); // Duplicate
        assert_eq!(bitmap.received_count, 1);
    }

    #[test]
    fn chunk_bitmap_out_of_bounds() {
        let mut bitmap = ChunkBitmap::new(5);
        bitmap.mark_received(10); // Out of bounds
        assert_eq!(bitmap.received_count, 0);
        assert!(!bitmap.is_received(10));
    }

    fn franken_export_test_bundle(include_manifest_evidence: bool) -> AtpProofBundle {
        use crate::atp::object::Object;
        use crate::atp::proof::replay::AtpReplayPointer;

        let manifest_root = crate::atp::manifest::MerkleRoot::new([1; 32]);
        let object_id = Object::file(b"test".to_vec()).id;
        let mut chunk_bitmap = ChunkBitmap::new(1);
        chunk_bitmap.mark_received(0);

        let peer_identity = PeerIdentityInfo {
            source_peer_id: "source".to_string(),
            destination_peer_id: "dest".to_string(),
            auth_method: "ed25519".to_string(),
            key_fingerprints: vec!["key1".to_string()],
            authenticated_at_micros: 12345,
            mutual_auth: true,
        };

        let path_summary = TransferPathSummary {
            primary_protocol: "quic".to_string(),
            fallback_protocols: vec!["tcp".to_string()],
            rtt_millis: Some(50.0),
            bandwidth_bps: Some(1_000_000),
            relay_used: false,
            relay_nodes: vec![],
            path_setup_duration_millis: 100,
            path_switches: 0,
        };

        let journal = TransferJournal {
            digest: SerializableContentId::from(&crate::atp::object::ContentId::from_bytes(
                b"journal",
            )),
            format_version: 1,
            entry_count: 10,
            size_bytes: 1024,
            is_complete: true,
            created_at_micros: 12345,
            finalized_at_micros: Some(12400),
        };

        let replay_pointer = AtpReplayPointer::new(
            "transfer-replay",
            10,
            42,
            SerializableContentId::from(&crate::atp::object::ContentId::from_bytes(b"replay")),
        );

        let mut builder = AtpProofBundleBuilder::new("test-transfer")
            .manifest_root(manifest_root)
            .object_roots(vec![object_id])
            .chunk_bitmap(chunk_bitmap)
            .peer_identity(peer_identity)
            .path_summary(path_summary)
            .journal(journal)
            .add_replay_pointer("failure-trace", replay_pointer)
            .add_verification_evidence(VerificationEvidence {
                stage: VerificationStage::ChunkHash,
                summary: "chunk verified".to_string(),
                digest: Some(crate::atp::object::ContentId::from_bytes(b"chunk")),
            });

        if include_manifest_evidence {
            builder = builder.add_verification_evidence(VerificationEvidence {
                stage: VerificationStage::Manifest,
                summary: "manifest verified".to_string(),
                digest: Some(crate::atp::object::ContentId::from_bytes(b"manifest")),
            });
        }

        builder
            .build()
            .expect("franken export test bundle should build")
    }

    #[test]
    fn franken_export_accepts_valid_bundle_with_stable_ids() {
        let bundle = franken_export_test_bundle(true);
        let export = bundle.to_franken_proof_export();

        assert_eq!(export.validation_status, AtpProofValidationStatus::Accepted);
        assert_eq!(export.decision_audit.action_chosen, ATP_PROOF_ACCEPT_ACTION);
        assert_eq!(
            export.decision_audit.contract_name,
            ATP_PROOF_DECISION_CONTRACT
        );
        assert_eq!(
            export.decision_audit.decision_id.as_u128(),
            bundle.stable_decision_id().as_u128()
        );
        assert_eq!(
            export.decision_audit.trace_id.as_u128(),
            bundle.stable_trace_id().as_u128()
        );
        assert!(export.evidence_ledger.is_valid());
        assert_eq!(export.evidence_ledger.action, ATP_PROOF_ACCEPT_ACTION);
        assert_eq!(
            bundle.to_evidence_ledger().action,
            export.evidence_ledger.action
        );

        assert!(export.audit_artifacts.iter().any(|artifact| {
            artifact.key == "proof_bundle"
                && artifact
                    .digest
                    .as_deref()
                    .is_some_and(|digest| digest.starts_with("sha256:"))
        }));
        assert!(export.audit_artifacts.iter().any(|artifact| {
            artifact.key == "replay:failure-trace" && artifact.replay_range == Some((10, 42))
        }));
    }

    #[test]
    fn franken_export_quarantines_invalid_bundle_with_evidence() {
        let bundle = franken_export_test_bundle(false);
        let export = bundle.to_franken_proof_export();

        match &export.validation_status {
            AtpProofValidationStatus::Quarantined { reason } => {
                assert!(reason.contains("missing manifest evidence"));
            }
            AtpProofValidationStatus::Accepted => panic!("invalid bundle must be quarantined"),
        }
        assert_eq!(
            export.decision_audit.action_chosen,
            ATP_PROOF_QUARANTINE_ACTION
        );
        assert!(export.decision_audit.fallback_active);
        assert!(export.evidence_ledger.is_valid());
        assert_eq!(export.evidence_ledger.action, ATP_PROOF_QUARANTINE_ACTION);
    }

    #[test]
    fn proof_bundle_builder_minimal() {
        use crate::atp::object::Object;

        let manifest_root = crate::atp::manifest::MerkleRoot::new([1; 32]);
        let object_id = Object::file(b"test".to_vec()).id;
        let mut chunk_bitmap = ChunkBitmap::new(1);
        chunk_bitmap.mark_received(0);

        let peer_identity = PeerIdentityInfo {
            source_peer_id: "source".to_string(),
            destination_peer_id: "dest".to_string(),
            auth_method: "ed25519".to_string(),
            key_fingerprints: vec!["key1".to_string()],
            authenticated_at_micros: 12345,
            mutual_auth: true,
        };

        let path_summary = TransferPathSummary {
            primary_protocol: "quic".to_string(),
            fallback_protocols: vec![],
            rtt_millis: Some(50.0),
            bandwidth_bps: Some(1_000_000),
            relay_used: false,
            relay_nodes: vec![],
            path_setup_duration_millis: 100,
            path_switches: 0,
        };

        let journal = TransferJournal {
            digest: SerializableContentId::from(&crate::atp::object::ContentId::from_bytes(
                b"journal",
            )),
            format_version: 1,
            entry_count: 10,
            size_bytes: 1024,
            is_complete: true,
            created_at_micros: 12345,
            finalized_at_micros: Some(12400),
        };

        let bundle = AtpProofBundleBuilder::new("test-transfer")
            .manifest_root(manifest_root)
            .object_roots(vec![object_id])
            .chunk_bitmap(chunk_bitmap)
            .peer_identity(peer_identity)
            .path_summary(path_summary)
            .journal(journal)
            .add_verification_evidence(VerificationEvidence {
                stage: VerificationStage::ChunkHash,
                summary: "chunk verified".to_string(),
                digest: Some(crate::atp::object::ContentId::from_bytes(b"chunk")),
            })
            .add_verification_evidence(VerificationEvidence {
                stage: VerificationStage::Manifest,
                summary: "manifest verified".to_string(),
                digest: Some(crate::atp::object::ContentId::from_bytes(b"manifest")),
            })
            .build()
            .expect("minimal bundle should build");

        bundle.validate().expect("minimal bundle should validate");
        assert_eq!(bundle.transfer_id, "test-transfer");
        assert_eq!(bundle.calculate_proof_strength(), ProofStrength::Basic);
        assert!(bundle.meets_policy_requirements());
    }

    #[test]
    fn proof_bundle_validation_fails_for_missing_evidence() {
        use crate::atp::object::Object;

        let manifest_root = crate::atp::manifest::MerkleRoot::new([1; 32]);
        let object_id = Object::file(b"test".to_vec()).id;
        let chunk_bitmap = ChunkBitmap::new(1);

        let peer_identity = PeerIdentityInfo {
            source_peer_id: "source".to_string(),
            destination_peer_id: "dest".to_string(),
            auth_method: "ed25519".to_string(),
            key_fingerprints: vec![],
            authenticated_at_micros: 12345,
            mutual_auth: true,
        };

        let path_summary = TransferPathSummary {
            primary_protocol: "quic".to_string(),
            fallback_protocols: vec![],
            rtt_millis: Some(50.0),
            bandwidth_bps: Some(1_000_000),
            relay_used: false,
            relay_nodes: vec![],
            path_setup_duration_millis: 100,
            path_switches: 0,
        };

        let journal = TransferJournal {
            digest: SerializableContentId::from(&crate::atp::object::ContentId::from_bytes(
                b"journal",
            )),
            format_version: 1,
            entry_count: 10,
            size_bytes: 1024,
            is_complete: true,
            created_at_micros: 12345,
            finalized_at_micros: Some(12400),
        };

        // Missing manifest evidence
        let bundle = AtpProofBundleBuilder::new("test-transfer")
            .manifest_root(manifest_root)
            .object_roots(vec![object_id])
            .chunk_bitmap(chunk_bitmap)
            .peer_identity(peer_identity)
            .path_summary(path_summary)
            .journal(journal)
            .add_verification_evidence(VerificationEvidence {
                stage: VerificationStage::ChunkHash,
                summary: "chunk verified".to_string(),
                digest: Some(crate::atp::object::ContentId::from_bytes(b"chunk")),
            })
            .build()
            .expect("bundle should build");

        let err = bundle.validate().expect_err("validation should fail");
        assert!(matches!(
            err,
            AtpProofBundleError::InvalidVerificationEvidence(_)
        ));
    }

    #[test]
    fn proof_strength_calculation() {
        use crate::atp::object::Object;

        let manifest_root = crate::atp::manifest::MerkleRoot::new([1; 32]);
        let object_id = Object::file(b"test".to_vec()).id.clone();

        let mut bundle = AtpProofBundleBuilder::new("test-transfer")
            .manifest_root(manifest_root)
            .object_roots(vec![object_id.clone()])
            .chunk_bitmap(ChunkBitmap::new(1))
            .peer_identity(PeerIdentityInfo {
                source_peer_id: "source".to_string(),
                destination_peer_id: "dest".to_string(),
                auth_method: "ed25519".to_string(),
                key_fingerprints: vec!["key1".to_string()],
                authenticated_at_micros: 12345,
                mutual_auth: true,
            })
            .path_summary(TransferPathSummary {
                primary_protocol: "quic".to_string(),
                fallback_protocols: vec![],
                rtt_millis: Some(50.0),
                bandwidth_bps: Some(1_000_000),
                relay_used: false,
                relay_nodes: vec![],
                path_setup_duration_millis: 100,
                path_switches: 0,
            })
            .journal(TransferJournal {
                digest: SerializableContentId::from(&crate::atp::object::ContentId::from_bytes(
                    b"journal",
                )),
                format_version: 1,
                entry_count: 10,
                size_bytes: 1024,
                is_complete: true,
                created_at_micros: 12345,
                finalized_at_micros: Some(12400),
            })
            .add_verification_evidence(VerificationEvidence {
                stage: VerificationStage::ChunkHash,
                summary: "chunk verified".to_string(),
                digest: Some(crate::atp::object::ContentId::from_bytes(b"chunk")),
            })
            .add_verification_evidence(VerificationEvidence {
                stage: VerificationStage::Manifest,
                summary: "manifest verified".to_string(),
                digest: Some(crate::atp::object::ContentId::from_bytes(b"manifest")),
            })
            .add_repair_group(RepairGroupMetadata {
                group_id: "group1".to_string(),
                covered_objects: vec![SerializableObjectId::from(&object_id)],
                repair_strategy: "raptorq".to_string(),
                redundancy_factor: 1.5,
                repair_activated: true,
                repair_completed_at: Some(12345),
            })
            .build()
            .expect("enhanced bundle should build");

        assert_eq!(bundle.calculate_proof_strength(), ProofStrength::Enhanced);

        // Add cryptographic evidence. The no-key proof-strength path stays
        // fail-closed; only the trusted-key path may elevate to Cryptographic.
        let auth_key = AuthKey::from_seed(12_345);
        bundle
            .sign_bundle("source", "key1", &auth_key)
            .expect("source signature should be recorded");
        assert_eq!(bundle.calculate_proof_strength(), ProofStrength::Enhanced);
        let trusted_keys = trusted_key_map("key1", auth_key);
        assert_eq!(
            bundle.calculate_proof_strength_with_keys(&trusted_keys),
            ProofStrength::Cryptographic
        );
    }

    #[test]
    fn semantic_validation_detects_inconsistencies() {
        use crate::atp::object::Object;

        let manifest_root = crate::atp::manifest::MerkleRoot::new([1; 32]);
        let object_id = Object::file(b"test".to_vec()).id;

        // Create inconsistent bundle: repair activated but no RaptorQ metadata
        let bundle = AtpProofBundleBuilder::new("test-transfer")
            .manifest_root(manifest_root)
            .object_roots(vec![object_id.clone()])
            .chunk_bitmap(ChunkBitmap::new(1))
            .peer_identity(PeerIdentityInfo {
                source_peer_id: "source".to_string(),
                destination_peer_id: "dest".to_string(),
                auth_method: "ed25519".to_string(),
                key_fingerprints: vec![],
                authenticated_at_micros: 12345,
                mutual_auth: true,
            })
            .path_summary(TransferPathSummary {
                primary_protocol: "quic".to_string(),
                fallback_protocols: vec![],
                rtt_millis: Some(50.0),
                bandwidth_bps: Some(1_000_000),
                relay_used: false,
                relay_nodes: vec![],
                path_setup_duration_millis: 100,
                path_switches: 0,
            })
            .journal(TransferJournal {
                digest: SerializableContentId::from(&crate::atp::object::ContentId::from_bytes(
                    b"journal",
                )),
                format_version: 1,
                entry_count: 10,
                size_bytes: 1024,
                is_complete: true,
                created_at_micros: 12345,
                finalized_at_micros: Some(12400),
            })
            .add_verification_evidence(VerificationEvidence {
                stage: VerificationStage::ChunkHash,
                summary: "chunk verified".to_string(),
                digest: Some(crate::atp::object::ContentId::from_bytes(b"chunk")),
            })
            .add_verification_evidence(VerificationEvidence {
                stage: VerificationStage::Manifest,
                summary: "manifest verified".to_string(),
                digest: Some(crate::atp::object::ContentId::from_bytes(b"manifest")),
            })
            .add_repair_group(RepairGroupMetadata {
                group_id: "group1".to_string(),
                covered_objects: vec![SerializableObjectId::from(&object_id)],
                repair_strategy: "raptorq".to_string(),
                redundancy_factor: 1.5,
                repair_activated: true, // But no RaptorQ metadata
                repair_completed_at: Some(12345),
            })
            .build()
            .expect("bundle should build");

        let err = bundle
            .validate()
            .expect_err("semantic validation should fail");
        assert!(matches!(
            err,
            AtpProofBundleError::SemanticValidationFailed(_)
        ));
    }

    #[test]
    fn cryptographic_signature_verification() {
        use crate::atp::object::ObjectId;
        use crate::security::AuthKey;

        let manifest_root = crate::atp::manifest::MerkleRoot::new([1; 32]);
        let object_id = ObjectId::content(crate::atp::object::ContentId::from_bytes(b"test"));
        let chunk_bitmap = ChunkBitmap::new(1);

        let peer_identity = PeerIdentityInfo {
            source_peer_id: "peer1".to_string(),
            destination_peer_id: "peer2".to_string(),
            auth_method: "hmac".to_string(),
            key_fingerprints: vec!["test-key-fp".to_string()],
            authenticated_at_micros: 12000,
            mutual_auth: true,
        };

        let path_summary = TransferPathSummary {
            primary_protocol: "quic".to_string(),
            fallback_protocols: vec![],
            rtt_millis: Some(50.0),
            bandwidth_bps: Some(1000000),
            relay_used: false,
            relay_nodes: vec![],
            path_setup_duration_millis: 100,
            path_switches: 0,
        };

        let journal = TransferJournal {
            digest: SerializableContentId::from(&crate::atp::object::ContentId::from_bytes(
                b"journal",
            )),
            format_version: 1,
            entry_count: 10,
            size_bytes: 1024,
            is_complete: true,
            created_at_micros: 12000,
            finalized_at_micros: Some(12500),
        };

        // Create bundle without repair metadata or signatures - peer identity alone is Basic.
        let mut bundle = AtpProofBundleBuilder::new("test-transfer")
            .manifest_root(manifest_root.clone())
            .object_roots(vec![object_id.clone()])
            .chunk_bitmap(chunk_bitmap.clone())
            .peer_identity(peer_identity.clone())
            .path_summary(path_summary.clone())
            .journal(journal.clone())
            .add_verification_evidence(VerificationEvidence {
                stage: VerificationStage::ChunkHash,
                summary: "chunk verified".to_string(),
                digest: Some(crate::atp::object::ContentId::from_bytes(b"chunk")),
            })
            .add_verification_evidence(VerificationEvidence {
                stage: VerificationStage::Manifest,
                summary: "manifest verified".to_string(),
                digest: Some(crate::atp::object::ContentId::from_bytes(b"manifest")),
            })
            .build()
            .expect("bundle should build");

        assert_eq!(bundle.calculate_proof_strength(), ProofStrength::Basic);

        // Sign the bundle
        let auth_key = AuthKey::from_seed(12345);
        bundle
            .sign_bundle("peer1", "test-key-fp", &auth_key)
            .expect("signing should succeed");

        // Signature-shaped evidence alone must not satisfy cryptographic
        // strength; the verifier needs trusted key material.
        assert_eq!(bundle.calculate_proof_strength(), ProofStrength::Basic);
        let wrong_keys = trusted_key_map("test-key-fp", AuthKey::from_seed(54321));
        assert!(
            !bundle
                .verify_cryptographic_signatures_with_keys(&wrong_keys)
                .expect("wrong trusted key verification should not error")
        );
        assert_eq!(
            bundle.calculate_proof_strength_with_keys(&wrong_keys),
            ProofStrength::Basic
        );
        let trusted_keys = trusted_key_map("test-key-fp", auth_key);
        assert!(
            bundle
                .verify_cryptographic_signatures_with_keys(&trusted_keys)
                .expect("trusted key verification should not error")
        );
        assert_eq!(
            bundle.calculate_proof_strength_with_keys(&trusted_keys),
            ProofStrength::Cryptographic
        );
    }

    #[test]
    fn cryptographic_signature_validation_rejects_tampering() {
        use crate::atp::object::ObjectId;

        let manifest_root = crate::atp::manifest::MerkleRoot::new([1; 32]);
        let object_id = ObjectId::content(crate::atp::object::ContentId::from_bytes(b"test"));
        let repair_object = SerializableObjectId::from(&object_id);
        let chunk_bitmap = ChunkBitmap::new(1);

        let peer_identity = PeerIdentityInfo {
            source_peer_id: "peer1".to_string(),
            destination_peer_id: "peer2".to_string(),
            auth_method: "hmac".to_string(),
            key_fingerprints: vec!["test-key-fp".to_string()],
            authenticated_at_micros: 12000,
            mutual_auth: true,
        };

        let path_summary = TransferPathSummary {
            primary_protocol: "quic".to_string(),
            fallback_protocols: vec![],
            rtt_millis: Some(50.0),
            bandwidth_bps: Some(1000000),
            relay_used: false,
            relay_nodes: vec![],
            path_setup_duration_millis: 100,
            path_switches: 0,
        };

        let journal = TransferJournal {
            digest: SerializableContentId::from(&crate::atp::object::ContentId::from_bytes(
                b"journal",
            )),
            format_version: 1,
            entry_count: 10,
            size_bytes: 1024,
            is_complete: true,
            created_at_micros: 12000,
            finalized_at_micros: Some(12500),
        };

        let mut bundle = AtpProofBundleBuilder::new("test-transfer")
            .manifest_root(manifest_root)
            .object_roots(vec![object_id])
            .chunk_bitmap(chunk_bitmap)
            .peer_identity(peer_identity)
            .path_summary(path_summary)
            .journal(journal)
            .add_repair_group(RepairGroupMetadata {
                group_id: "group1".to_string(),
                covered_objects: vec![repair_object],
                repair_strategy: "raptorq".to_string(),
                redundancy_factor: 1.5,
                repair_activated: true,
                repair_completed_at: Some(12_500),
            })
            .build()
            .expect("bundle should build");

        let tampered_signatures = CryptographicSignatures {
            signatures: vec![CryptographicSignature {
                signer_id: "peer1".to_string(),
                key_fingerprint: "test-key-fp".to_string(),
                signature: vec![0u8; 32], // Invalid signature
                signed_at_micros: 12345,
            }],
            hash_algorithm: "SHA-256".to_string(),
            bundle_hash: vec![0u8; 32], // Wrong hash
        };

        bundle.extensions.insert(
            "cryptographic_signatures".to_string(),
            serde_json::to_value(tampered_signatures).unwrap(),
        );

        // Should reject tampering (wrong bundle hash), even with the trusted key.
        let trusted_keys = trusted_key_map("test-key-fp", AuthKey::from_seed(12345));
        assert!(
            !bundle
                .verify_cryptographic_signatures_with_keys(&trusted_keys)
                .expect("tampered signature verification should not error")
        );
        assert_eq!(bundle.calculate_proof_strength(), ProofStrength::Enhanced);
        assert_eq!(
            bundle.calculate_proof_strength_with_keys(&trusted_keys),
            ProofStrength::Enhanced
        );
    }

    #[test]
    fn cryptographic_signature_rejects_unauthorized_signers() {
        use crate::atp::object::ObjectId;
        use crate::security::AuthKey;

        let manifest_root = crate::atp::manifest::MerkleRoot::new([1; 32]);
        let object_id = ObjectId::content(crate::atp::object::ContentId::from_bytes(b"test"));
        let chunk_bitmap = ChunkBitmap::new(1);

        let peer_identity = PeerIdentityInfo {
            source_peer_id: "peer1".to_string(),
            destination_peer_id: "peer2".to_string(),
            auth_method: "hmac".to_string(),
            key_fingerprints: vec!["test-key-fp".to_string()],
            authenticated_at_micros: 12000,
            mutual_auth: true,
        };

        let path_summary = TransferPathSummary {
            primary_protocol: "quic".to_string(),
            fallback_protocols: vec![],
            rtt_millis: Some(50.0),
            bandwidth_bps: Some(1000000),
            relay_used: false,
            relay_nodes: vec![],
            path_setup_duration_millis: 100,
            path_switches: 0,
        };

        let journal = TransferJournal {
            digest: SerializableContentId::from(&crate::atp::object::ContentId::from_bytes(
                b"journal",
            )),
            format_version: 1,
            entry_count: 10,
            size_bytes: 1024,
            is_complete: true,
            created_at_micros: 12000,
            finalized_at_micros: Some(12500),
        };

        let mut bundle = AtpProofBundleBuilder::new("test-transfer")
            .manifest_root(manifest_root)
            .object_roots(vec![object_id])
            .chunk_bitmap(chunk_bitmap)
            .peer_identity(peer_identity)
            .path_summary(path_summary)
            .journal(journal)
            .build()
            .expect("bundle should build");

        let auth_key = AuthKey::from_seed(12345);

        // Try to sign with an unauthorized peer
        let result = bundle.sign_bundle("peer3", "test-key-fp", &auth_key);
        assert!(result.is_err());

        // Try to sign with an unknown key fingerprint
        let result = bundle.sign_bundle("peer1", "unknown-key-fp", &auth_key);
        assert!(result.is_err());
    }
