    use super::*;
    use crate::atp::object::{ContentId, Object};
    use crate::atp::proof::serde_types::SerializableContentId;
    use crate::atp::proof::{
        AtpProofBundle, AtpProofBundleBuilder, ChunkBitmap, PeerIdentityInfo, ProofStrength,
        TransferJournal, TransferPathSummary,
    };
    use crate::atp::verifier::{VerificationEvidence, VerificationStage};

    fn create_test_bundle() -> AtpProofBundle {
        let manifest_root = crate::atp::manifest::MerkleRoot::new([1; 32]);
        let object_id = Object::file(b"test".to_vec()).id;
        // A COMPLETE transfer: all 10 chunks received so it passes the
        // fail-closed coverage gate (asupersync-u5owrm). Tests that want an
        // incomplete/empty transfer override `bundle.chunk_bitmap` afterwards.
        let mut chunk_bitmap = ChunkBitmap::new(10);
        for i in 0..10 {
            chunk_bitmap.mark_received(i);
        }
        // A valid commit record so strict verification (the default policy
        // requires it) has the manifest<->merkle binding to verify.
        let mut commit_graph = crate::atp::object::ObjectGraph::new();
        commit_graph
            .add_root(Object::file(b"test".to_vec()))
            .expect("add root to commit graph");
        let commit_manifest = crate::atp::manifest::Manifest::from_graph(
            &commit_graph,
            crate::atp::object::MetadataPolicy::default(),
        )
        .expect("manifest from graph");
        let commit = crate::atp::manifest::GraphCommit::new(
            None,
            commit_manifest,
            crate::atp::manifest::CommitMetadata {
                timestamp_nanos: 1_234_567_890,
                author: "test".to_string(),
                message: "test commit".to_string(),
            },
        );

        AtpProofBundleBuilder::new("test-transfer")
            .manifest_root(manifest_root)
            .object_roots(vec![object_id])
            .chunk_bitmap(chunk_bitmap)
            .commit_record(commit)
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
                digest: SerializableContentId::from(&ContentId::from_bytes(b"journal")),
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
                digest: Some(ContentId::from_bytes(b"chunk")),
            })
            .add_verification_evidence(VerificationEvidence {
                stage: VerificationStage::Manifest,
                summary: "manifest verified".to_string(),
                digest: Some(ContentId::from_bytes(b"manifest")),
            })
            .build()
            .expect("test bundle should build")
    }

    #[test]
    fn bundle_verifier_basic_verification() {
        let bundle = create_test_bundle();
        let verifier = AtpBundleVerifier::new();

        let result = verifier.verify_bundle(&bundle);

        assert!(result.status.is_success());
        assert!(!result.checks.is_empty());
        assert_eq!(result.report.transfer_summary.transfer_id, "test-transfer");
    }

    #[test]
    fn verification_policy_enforcement() {
        let mut bundle = create_test_bundle();
        bundle.metadata.required_proof_strength = ProofStrength::Enhanced;
        bundle.metadata.require_repair_evidence = true;

        let verifier = AtpBundleVerifier::new();
        let result = verifier.verify_bundle(&bundle);

        // Should fail because we require enhanced proof strength and repair evidence
        // but the test bundle only has basic evidence
        assert!(result.status.is_failure());
        assert!(!result.report.policy_compliance.violations.is_empty());
    }

    #[test]
    fn verification_with_warnings() {
        let mut bundle = create_test_bundle();
        bundle.journal.is_complete = false; // Incomplete journal

        let verifier = AtpBundleVerifier::new();
        let result = verifier.verify_bundle(&bundle);

        assert_eq!(result.status, VerificationStatus::PassedWithWarnings);
        assert!(!result.warnings.is_empty());
    }

    #[test]
    fn verification_status_methods() {
        assert!(VerificationStatus::Passed.is_success());
        assert!(VerificationStatus::PassedWithWarnings.is_success());
        assert!(!VerificationStatus::Failed.is_success());
        assert!(!VerificationStatus::Inconclusive.is_success());

        assert!(VerificationStatus::Failed.is_failure());
        assert!(!VerificationStatus::Passed.is_failure());
    }

    #[test]
    fn custom_verification_policy() {
        let policy = VerificationPolicy {
            require_all_stages: false,
            min_chunk_coverage: 0.5, // Lower requirement
            strict_replay_validation: true,
            custom_policies: BTreeMap::new(),
        };

        let verifier = AtpBundleVerifier::with_policy(policy);
        let bundle = create_test_bundle();

        let result = verifier.verify_bundle(&bundle);
        assert!(result.status.is_success()); // Should pass with relaxed policy
    }

    #[test]
    fn incomplete_transfer_is_rejected_under_default_policy() {
        // Headline asupersync-u5owrm fix: a transfer missing chunks must NOT pass
        // verification (it was only a warning -> PassedWithWarnings -> accepted).
        let mut bundle = create_test_bundle();
        let mut partial = ChunkBitmap::new(10);
        partial.mark_received(0); // 1 of 10
        bundle.chunk_bitmap = partial;

        let result = AtpBundleVerifier::new().verify_bundle(&bundle);
        assert!(
            result.status.is_failure(),
            "incomplete transfer must fail, got {:?}",
            result.status
        );
        assert!(
            result
                .checks
                .iter()
                .any(|c| c.check_name == "chunk_coverage" && c.status.is_failure()),
            "a failed chunk_coverage check must be present"
        );
    }

    #[test]
    fn empty_bitmap_is_not_reported_complete() {
        // total_chunks == 0 must not read as 100% complete (completion_ratio()
        // returns 1.0 there); coverage is computed from the popcount as 0.0.
        let mut bundle = create_test_bundle();
        bundle.chunk_bitmap = ChunkBitmap::new(0);

        let result = AtpBundleVerifier::new().verify_bundle(&bundle);
        assert!(
            result.status.is_failure(),
            "empty bitmap must not pass as complete, got {:?}",
            result.status
        );
    }

    #[test]
    fn inflated_received_count_does_not_bypass_coverage() {
        // A crafted bundle that sets received_count == total_chunks without
        // setting the bitmap bits must still fail: coverage is recomputed from
        // the bitmap popcount, not the off-wire received_count field.
        let mut bundle = create_test_bundle();
        let mut crafted = ChunkBitmap::new(10);
        crafted.received_count = 10; // lie: no bits actually set
        bundle.chunk_bitmap = crafted;

        let result = AtpBundleVerifier::new().verify_bundle(&bundle);
        assert!(
            result.status.is_failure(),
            "inflated received_count must not bypass coverage, got {:?}",
            result.status
        );
    }

    #[test]
    fn missing_commit_record_fails_strict_policy() {
        // A complete-coverage bundle with no commit record must FAIL the strict
        // default policy (the manifest<->merkle binding is absent), not just warn.
        let mut bundle = create_test_bundle();
        bundle.commit_record = None;

        let result = AtpBundleVerifier::new().verify_bundle(&bundle);
        assert!(
            result.status.is_failure(),
            "strict policy must reject a bundle with no commit record, got {:?}",
            result.status
        );
    }
