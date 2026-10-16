    use super::*;
    use crate::atp::manifest::{CommitMetadata, GraphCommit};
    use crate::atp::object::{MetadataPolicy, ObjectEdge};

    #[test]
    fn chunk_verifier_accepts_matching_digest() {
        let verifier = AtpVerifier::default();
        let bytes = b"verified chunk";
        let digest = chunk_verification_digest(7, 4096, bytes);

        let evidence = verifier
            .verify_chunk(ChunkVerification {
                chunk_index: 7,
                offset: 4096,
                bytes,
                expected_digest: digest.clone(),
            })
            .expect("matching digest should verify");

        assert_eq!(evidence.stage, VerificationStage::ChunkHash);
        assert_eq!(evidence.digest, Some(digest));
        assert!(evidence.summary.contains("chunk=7"));
    }

    #[test]
    fn chunk_verifier_rejects_mismatched_digest_without_payload_leak() {
        let verifier = AtpVerifier::default();
        let err = verifier
            .verify_chunk(ChunkVerification {
                chunk_index: 2,
                offset: 0,
                bytes: b"actual bytes",
                expected_digest: chunk_verification_digest(2, 0, b"expected bytes"),
            })
            .expect_err("mismatched digest must fail closed");

        assert_eq!(err.stage(), VerificationStage::ChunkHash);
        assert_eq!(err.redacted_reason(), "chunk 2 digest mismatch");
        assert!(!err.to_string().contains("actual bytes"));
    }

    #[test]
    fn object_verifier_rejects_wrong_file_identity() {
        let verifier = AtpVerifier::default();
        let mut object = Object::file(b"original".to_vec());
        object.content = Some(b"tampered".to_vec());

        let err = verifier
            .verify_object(&object)
            .expect_err("tampered content must not verify");

        assert_eq!(err.stage(), VerificationStage::ObjectContent);
        assert_eq!(err.redacted_reason(), "object identity mismatch");
    }

    #[test]
    fn object_verifier_rejects_file_with_smuggled_children() {
        // A file object's id commits to content only; children outside that
        // commitment must be rejected fail-closed (symmetric with directory
        // objects rejecting stray inline content), so `verify_object` can
        // never attest a "verified" file that carries unverified edges.
        let verifier = AtpVerifier::default();
        let mut object = Object::file(b"payload".to_vec());
        object
            .children
            .push(ObjectEdge::new(object.id.clone(), "smuggled".to_string()));

        let err = verifier
            .verify_object(&object)
            .expect_err("file with children must not verify");

        assert_eq!(err.stage(), VerificationStage::ObjectContent);
        assert_eq!(
            err.redacted_reason(),
            "object kind file carried unexpected children"
        );
    }

    #[test]
    fn object_verifier_rejects_file_payload_above_configured_limit() {
        let verifier = AtpVerifier::new(VerifierConfig {
            max_object_bytes: 4,
            ..VerifierConfig::default()
        });
        let object = Object::file(b"oversized".to_vec());

        let err = verifier
            .verify_object(&object)
            .expect_err("oversized file object must fail before hashing");

        assert_eq!(err.stage(), VerificationStage::ObjectContent);
        assert_eq!(
            err.redacted_reason(),
            "input length 9 exceeds verifier limit 4"
        );
        assert!(!err.to_string().contains("oversized"));
    }

    #[test]
    fn manifest_graph_verifier_accepts_canonical_graph() {
        let verifier = AtpVerifier::default();
        let mut graph = ObjectGraph::new();
        let file = Object::file(b"file payload".to_vec());
        let file_id = file.id.clone();
        graph.add_object(file).expect("add file");
        let dir = Object::directory(vec![ObjectEdge::new(file_id, "file.txt".to_string())]);
        graph.add_root(dir).expect("add root");

        let manifest = Manifest::from_graph(&graph, MetadataPolicy::default()).expect("manifest");
        let evidence = verifier
            .verify_manifest_graph(&manifest, &graph)
            .expect("manifest should match graph");

        assert_eq!(evidence.stage, VerificationStage::Manifest);
        assert!(evidence.summary.contains("canonical_graph_objects=2"));
    }

    #[test]
    fn graph_verifier_rejects_wrong_merkle_root() {
        let verifier = AtpVerifier::default();
        let mut graph = ObjectGraph::new();
        graph
            .add_root(Object::file(b"file payload".to_vec()))
            .expect("add root");
        let wrong_root = MerkleRoot::new([9; 32]);

        let err = verifier
            .verify_graph(&graph, &wrong_root)
            .expect_err("wrong root must fail");

        assert_eq!(err.stage(), VerificationStage::GraphMerkle);
        assert_eq!(err.redacted_reason(), "merkle root mismatch");
    }

    #[test]
    fn commit_verifier_rejects_tampered_commit_id() {
        let verifier = AtpVerifier::default();
        let mut graph = ObjectGraph::new();
        graph
            .add_root(Object::file(b"payload".to_vec()))
            .expect("root");
        let manifest = Manifest::from_graph(&graph, MetadataPolicy::default()).expect("manifest");
        let metadata = CommitMetadata {
            timestamp_nanos: 10,
            author: "atp-test".to_string(),
            message: "verify".to_string(),
        };
        let mut commit = GraphCommit::new(None, manifest, metadata);
        commit.metadata.message = "tampered".to_string();

        let err = verifier
            .verify_commit(&commit)
            .expect_err("tampered commit metadata must fail");

        assert_eq!(err.stage(), VerificationStage::Commit);
    }

    #[test]
    fn repair_symbol_verifier_covers_metadata_and_bytes() {
        let verifier = AtpVerifier::default();
        let bytes = b"repair-symbol";
        let digest = repair_symbol_digest(3, 99, bytes);

        verifier
            .verify_repair_symbol(RepairSymbolVerification {
                source_block: 3,
                repair_index: 99,
                bytes,
                expected_digest: digest,
            })
            .expect("repair symbol should verify");

        let err = verifier
            .verify_repair_symbol(RepairSymbolVerification {
                source_block: 4,
                repair_index: 99,
                bytes,
                expected_digest: repair_symbol_digest(3, 99, bytes),
            })
            .expect_err("metadata mismatch must fail");

        assert_eq!(err.stage(), VerificationStage::RepairSymbol);
        assert_eq!(err.redacted_reason(), "repair symbol 4:99 digest mismatch");
    }

    #[test]
    fn verifier_evidence_digests_are_domain_separated() {
        let bytes = b"shared verifier evidence";
        let chunk_digest = chunk_verification_digest(1, 0, bytes);
        let repair_digest = repair_symbol_digest(1, 0, bytes);
        let proof_seed = ProofBundleVerification {
            merkle_root: MerkleRoot::new([9; 32]),
            entries: vec![ProofBundleEntry {
                stage: VerificationStage::ChunkHash,
                digest: ContentId::from_bytes(bytes),
            }],
            expected_digest: ContentId::from_bytes(b"proof-bundle-seed"),
        };
        let proof_digest = proof_bundle_digest(&proof_seed);

        assert_ne!(chunk_digest, repair_digest);
        assert_ne!(chunk_digest, proof_digest);
        assert_ne!(repair_digest, proof_digest);
    }

    #[test]
    fn proof_bundle_verifier_rejects_replayed_digest() {
        let verifier = AtpVerifier::default();
        let merkle_root = MerkleRoot::new([1; 32]);
        let entry = ProofBundleEntry {
            stage: VerificationStage::ChunkHash,
            digest: ContentId::from_bytes(b"chunk"),
        };
        let good_bundle = ProofBundleVerification {
            merkle_root: merkle_root.clone(),
            entries: vec![entry.clone()],
            expected_digest: ContentId::from_bytes(b"proof-bundle-seed"),
        };
        let expected_digest = proof_bundle_digest(&good_bundle);

        let mut bundle = ProofBundleVerification {
            merkle_root,
            entries: vec![entry],
            expected_digest,
        };
        verifier
            .verify_proof_bundle(&bundle)
            .expect("fresh bundle should verify");

        bundle.entries.push(ProofBundleEntry {
            stage: VerificationStage::RepairSymbol,
            digest: ContentId::from_bytes(b"replayed"),
        });
        let err = verifier
            .verify_proof_bundle(&bundle)
            .expect_err("replayed bundle must fail digest verification");

        assert_eq!(err.stage(), VerificationStage::ProofBundle);
        assert_eq!(err.redacted_reason(), "proof bundle digest mismatch");
    }

    #[test]
    fn final_proof_bundle_requires_stage_coverage() {
        let verifier = AtpVerifier::default();
        let merkle_root = MerkleRoot::new([8; 32]);
        let incomplete = ProofBundleVerification {
            merkle_root,
            entries: vec![ProofBundleEntry {
                stage: VerificationStage::ChunkHash,
                digest: ContentId::from_bytes(b"chunk"),
            }],
            expected_digest: ContentId::from_bytes(b"proof-bundle-seed"),
        };
        let incomplete = ProofBundleVerification {
            expected_digest: proof_bundle_digest(&incomplete),
            ..incomplete
        };

        let err = verifier
            .verify_final_proof_bundle(&incomplete)
            .expect_err("final proof must include all mandatory stages");

        assert_eq!(err.stage(), VerificationStage::ProofBundle);
        assert_eq!(
            err.redacted_reason(),
            "proof bundle missing object_content evidence"
        );
    }

    #[test]
    fn final_proof_bundle_rejects_duplicate_stage_even_with_fresh_digest() {
        let verifier = AtpVerifier::default();
        let entries = VerificationStage::required_final_proof_stages()
            .iter()
            .copied()
            .chain(std::iter::once(VerificationStage::Commit))
            .map(|stage| ProofBundleEntry {
                stage,
                digest: ContentId::from_bytes(stage.as_str().as_bytes()),
            })
            .collect::<Vec<_>>();
        let bundle = ProofBundleVerification {
            merkle_root: MerkleRoot::new([6; 32]),
            entries,
            expected_digest: ContentId::from_bytes(b"proof-bundle-seed"),
        };
        let bundle = ProofBundleVerification {
            expected_digest: proof_bundle_digest(&bundle),
            ..bundle
        };

        let err = verifier
            .verify_final_proof_bundle(&bundle)
            .expect_err("duplicate stage evidence must fail closed");

        assert_eq!(err.stage(), VerificationStage::ProofBundle);
        assert_eq!(
            err.redacted_reason(),
            "proof bundle has duplicate commit evidence"
        );
    }

    #[test]
    fn final_proof_bundle_accepts_complete_unique_pipeline() {
        let verifier = AtpVerifier::default();
        let entries = VerificationStage::required_final_proof_stages()
            .iter()
            .copied()
            .map(|stage| ProofBundleEntry {
                stage,
                digest: ContentId::from_bytes(stage.as_str().as_bytes()),
            })
            .collect::<Vec<_>>();
        let bundle = ProofBundleVerification {
            merkle_root: MerkleRoot::new([7; 32]),
            entries,
            expected_digest: ContentId::from_bytes(b"proof-bundle-seed"),
        };
        let bundle = ProofBundleVerification {
            expected_digest: proof_bundle_digest(&bundle),
            ..bundle
        };

        let evidence = verifier
            .verify_final_proof_bundle(&bundle)
            .expect("complete final proof should verify");

        assert_eq!(evidence.stage, VerificationStage::ProofBundle);
        assert!(evidence.summary.contains("required_stages=7"));
    }

    #[test]
    fn finalizer_proof_rejects_leaks_and_cancelled_exposure() {
        let verifier = AtpVerifier::default();

        let leak = verifier
            .verify_finalizer_proof(&FinalizerProof {
                stage: VerificationStage::Finalizer,
                leases_acquired: 3,
                leases_released: 2,
                cancellation_requested: false,
                final_output_exposed: false,
            })
            .expect_err("lease leak must fail");
        assert_eq!(leak.stage(), VerificationStage::Finalizer);
        assert_eq!(leak.redacted_reason(), "finalizer released 2 of 3 leases");

        let exposure = verifier
            .verify_finalizer_proof(&FinalizerProof {
                stage: VerificationStage::Commit,
                leases_acquired: 1,
                leases_released: 1,
                cancellation_requested: true,
                final_output_exposed: true,
            })
            .expect_err("cancelled final exposure must fail");
        assert_eq!(
            exposure.redacted_reason(),
            "cancelled verifier exposed final output at commit"
        );
    }

    #[test]
    fn finalizer_ledger_proves_balanced_cleanup_after_cancellation() {
        let verifier = AtpVerifier::default();
        let mut ledger = VerifierFinalizerLedger::new(VerificationStage::Finalizer);
        ledger.acquire_lease();
        ledger.acquire_lease();
        ledger.request_cancellation();
        ledger.release_lease();
        ledger.release_lease();

        let evidence = verifier
            .verify_finalizer_ledger(&ledger)
            .expect("balanced cancelled cleanup should verify");

        assert_eq!(evidence.stage, VerificationStage::Finalizer);
        assert!(evidence.summary.contains("leases=2"));
        assert!(evidence.summary.contains("cancellation_requested=true"));
    }

    #[test]
    fn finalizer_ledger_rejects_cancelled_output_exposure() {
        let verifier = AtpVerifier::default();
        let mut ledger = VerifierFinalizerLedger::new(VerificationStage::Commit);
        ledger.acquire_lease();
        ledger.request_cancellation();
        ledger.expose_final_output();
        ledger.release_lease();

        let err = verifier
            .verify_finalizer_ledger(&ledger)
            .expect_err("cancelled final exposure must fail");

        assert_eq!(err.stage(), VerificationStage::Finalizer);
        assert_eq!(
            err.redacted_reason(),
            "cancelled verifier exposed final output at commit"
        );
    }

    fn complete_proof_entries() -> Vec<ProofBundleEntry> {
        VerificationStage::required_final_proof_stages()
            .iter()
            .copied()
            .map(|stage| ProofBundleEntry {
                stage,
                digest: ContentId::from_bytes(stage.as_str().as_bytes()),
            })
            .collect()
    }

    fn pipeline_proof(cancelled: bool) -> VerifierPipelineProof {
        let manifest_root = MerkleRoot::new([42; 32]);
        let proof_entries = complete_proof_entries();
        let seed_bundle = ProofBundleVerification {
            merkle_root: manifest_root.clone(),
            entries: proof_entries.clone(),
            expected_digest: ContentId::from_bytes(b"proof-bundle-seed"),
        };
        let expected_proof_digest = proof_bundle_digest(&seed_bundle);

        VerifierPipelineProof {
            transfer_id: "transfer-42".to_string(),
            manifest_root,
            proof_entries,
            expected_proof_digest: expected_proof_digest.clone(),
            finalizer: FinalizerProof {
                stage: VerificationStage::Finalizer,
                leases_acquired: 2,
                leases_released: 2,
                cancellation_requested: cancelled,
                final_output_exposed: false,
            },
            resume_state: cancelled.then_some(VerifierResumeState {
                journal_sequence: 99,
                verified_stage_count: 4,
                proof_bundle_digest: expected_proof_digest,
            }),
            workers_started: 3,
            workers_drained: 3,
            permits_acquired: 5,
            permits_released: 5,
            finalizer_obligations_started: 1,
            finalizer_obligations_completed: 1,
            final_output_exposed: false,
            replay_crashpack_pointer: "journal://transfer-42@99".to_string(),
        }
    }

    #[test]
    fn pipeline_finalization_proves_cancelled_resume_and_drained_cleanup() {
        let verifier = AtpVerifier::default();
        let proof = pipeline_proof(true);

        let report = verifier
            .verify_pipeline_finalization(&proof)
            .expect("balanced cancelled verifier pipeline should commit proof only");

        assert_eq!(
            report.proof_bundle_evidence.stage,
            VerificationStage::ProofBundle
        );
        assert_eq!(
            report.finalizer_evidence.stage,
            VerificationStage::Finalizer
        );
        assert_eq!(
            report.log_entry.finalizer_outcome,
            VerifierFinalizerOutcome::CancelledDrained
        );
        assert_eq!(
            report
                .resume_state
                .expect("cancelled pipeline must preserve resume")
                .journal_sequence,
            99
        );
        assert_eq!(report.log_entry.rejection_reason, None);
        assert_eq!(
            report.log_entry.replay_crashpack_pointer,
            "journal://transfer-42@99"
        );
    }

    #[test]
    fn pipeline_finalization_rejects_cancellation_without_resume_state() {
        let verifier = AtpVerifier::default();
        let mut proof = pipeline_proof(true);
        proof.resume_state = None;

        let err = verifier
            .verify_pipeline_finalization(&proof)
            .expect_err("cancelled verifier without resume state must fail closed");

        assert_eq!(err.stage(), VerificationStage::Finalizer);
        assert_eq!(
            err.redacted_reason(),
            "cancelled verifier at finalizer without resume state"
        );
    }

    #[test]
    fn pipeline_finalization_rejects_worker_permit_and_finalizer_leaks() {
        let verifier = AtpVerifier::default();

        let mut worker_leak = pipeline_proof(false);
        worker_leak.workers_drained = 2;
        let err = verifier
            .verify_pipeline_finalization(&worker_leak)
            .expect_err("undrained workers must fail closed");
        assert_eq!(err.redacted_reason(), "verifier drained 2 of 3 workers");

        let mut permit_leak = pipeline_proof(false);
        permit_leak.permits_released = 4;
        let err = verifier
            .verify_pipeline_finalization(&permit_leak)
            .expect_err("unreleased permits must fail closed");
        assert_eq!(err.redacted_reason(), "verifier released 4 of 5 permits");

        let mut finalizer_leak = pipeline_proof(false);
        finalizer_leak.finalizer_obligations_completed = 0;
        let err = verifier
            .verify_pipeline_finalization(&finalizer_leak)
            .expect_err("incomplete finalizer obligations must fail closed");
        assert_eq!(
            err.redacted_reason(),
            "finalizer completed 0 of 1 obligations"
        );
    }

    #[test]
    fn pipeline_finalization_rejects_cancelled_final_exposure_and_missing_crashpack() {
        let verifier = AtpVerifier::default();

        let mut exposed = pipeline_proof(true);
        exposed.final_output_exposed = true;
        let err = verifier
            .verify_pipeline_finalization(&exposed)
            .expect_err("cancelled verifier must not expose final output");
        assert_eq!(
            err.redacted_reason(),
            "cancelled verifier exposed final output at finalizer"
        );

        let mut missing_pointer = pipeline_proof(false);
        missing_pointer.replay_crashpack_pointer.clear();
        let err = verifier
            .verify_pipeline_finalization(&missing_pointer)
            .expect_err("final proof needs replay/crashpack pointer");
        assert_eq!(
            err.redacted_reason(),
            "verifier finalization missing replay/crashpack pointer"
        );
    }
