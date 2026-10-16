    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::messaging::fabric::{
        CellTemperature, DataCapsule, NodeRole, PlacementPolicy, RepairPolicy, StewardCandidate,
        StorageClass, SubjectPattern,
    };

    fn candidate(name: &str, domain: &str) -> StewardCandidate {
        StewardCandidate::new(NodeId::new(name), domain)
            .with_role(NodeRole::Steward)
            .with_role(NodeRole::RepairWitness)
            .with_storage_class(StorageClass::Durable)
    }

    fn test_cell() -> SubjectCell {
        SubjectCell::new(
            &SubjectPattern::parse("orders.created").expect("pattern"),
            CellEpoch::new(7, 11),
            &[
                candidate("node-a", "rack-a"),
                candidate("node-b", "rack-b"),
                candidate("node-c", "rack-c"),
            ],
            &PlacementPolicy {
                cold_stewards: 3,
                warm_stewards: 3,
                hot_stewards: 3,
                ..PlacementPolicy::default()
            },
            RepairPolicy::default(),
            DataCapsule {
                temperature: CellTemperature::Warm,
                retained_message_blocks: 4,
            },
        )
        .expect("cell")
    }

    fn obligation(index: u32) -> ObligationId {
        ObligationId::new_for_test(index, 0)
    }

    #[test]
    fn evacuation_carries_obligation_frontier_proof() {
        let cell = test_cell();
        let certificate = cell
            .issue_cut_certificate(
                [obligation(7), obligation(3), obligation(7)],
                ConsumerStateDigest::new(0xfeed_cafe),
                Time::from_secs(9),
                NodeId::new("node-a"),
            )
            .expect("certificate");

        let proof = cell
            .certify_mobility(
                &certificate,
                &MobilityOperation::Evacuate {
                    from: NodeId::new("node-a"),
                    to: NodeId::new("node-b"),
                },
            )
            .expect("evacuation proof");

        assert_eq!(
            certificate.obligation_frontier,
            vec![obligation(3), obligation(7)]
        );
        assert!(certificate.covers_obligation(obligation(3)));
        assert_eq!(
            proof.obligation_frontier_digest,
            certificate.obligation_frontier_digest()
        );
        assert_eq!(
            proof.resulting_cell.control_capsule.active_sequencer,
            Some(NodeId::new("node-b"))
        );
        assert_eq!(
            proof.resulting_cell.steward_set.first(),
            Some(&NodeId::new("node-b"))
        );
        assert_eq!(
            proof.resulting_cell.steward_set.last(),
            Some(&NodeId::new("node-a"))
        );
        assert_eq!(
            proof
                .resulting_cell
                .control_capsule
                .sequencer_lease_generation,
            cell.control_capsule.sequencer_lease_generation + 1
        );
    }

    #[test]
    fn handoff_uses_explicit_cut_certificate() {
        let cell = test_cell();
        let certificate = cell
            .issue_cut_certificate(
                [obligation(10)],
                ConsumerStateDigest::new(0x1234),
                Time::from_secs(11),
                NodeId::new("node-a"),
            )
            .expect("certificate");

        let proof = cell
            .certify_mobility(
                &certificate,
                &MobilityOperation::Handoff {
                    from: NodeId::new("node-a"),
                    to: NodeId::new("node-c"),
                },
            )
            .expect("handoff proof");

        assert_eq!(
            proof.resulting_cell.control_capsule.active_sequencer,
            Some(NodeId::new("node-c"))
        );
        assert_eq!(proof.resulting_cell.steward_set, cell.steward_set);
        assert_eq!(
            proof.resulting_cell.control_capsule.steward_pool,
            cell.control_capsule.steward_pool
        );
        assert_eq!(
            proof.resulting_cell.control_capsule.policy_revision,
            cell.control_capsule.policy_revision + 1
        );
    }

    #[test]
    fn warm_restore_rebinds_epoch_and_cell_id_from_capsule() {
        let cell = test_cell();
        let restored_epoch = CellEpoch::new(8, 1);
        let certificate = cell
            .issue_cut_certificate(
                [obligation(2)],
                ConsumerStateDigest::new(0xface_b00c),
                Time::from_secs(13),
                NodeId::new("node-a"),
            )
            .expect("certificate");

        let proof = cell
            .certify_mobility(
                &certificate,
                &MobilityOperation::WarmRestore {
                    target: NodeId::new("edge-restore"),
                    restored_epoch,
                    capsule_digest: CapsuleDigest::new(0x9abc),
                },
            )
            .expect("warm restore proof");

        assert_eq!(proof.resulting_cell.epoch, restored_epoch);
        assert_eq!(
            proof.resulting_cell.cell_id,
            CellId::for_partition(restored_epoch, &cell.subject_partition)
        );
        assert_ne!(proof.resulting_cell.cell_id, cell.cell_id);
        assert_eq!(
            proof.resulting_cell.control_capsule.active_sequencer,
            Some(NodeId::new("edge-restore"))
        );
        assert_eq!(
            proof.resulting_cell.steward_set.first(),
            Some(&NodeId::new("edge-restore"))
        );
    }

    #[test]
    fn failover_removes_failed_steward_and_promotes_replacement() {
        let cell = test_cell();
        let certificate = cell
            .issue_cut_certificate(
                [obligation(1), obligation(4)],
                ConsumerStateDigest::new(0x2222),
                Time::from_secs(21),
                NodeId::new("node-b"),
            )
            .expect("certificate");

        let proof = cell
            .certify_mobility(
                &certificate,
                &MobilityOperation::Failover {
                    failed: NodeId::new("node-a"),
                    promote_to: NodeId::new("node-c"),
                },
            )
            .expect("failover proof");

        assert_eq!(
            proof.resulting_cell.control_capsule.active_sequencer,
            Some(NodeId::new("node-c"))
        );
        assert!(
            !proof
                .resulting_cell
                .steward_set
                .contains(&NodeId::new("node-a"))
        );
        assert!(
            !proof
                .resulting_cell
                .control_capsule
                .steward_pool
                .contains(&NodeId::new("node-a"))
        );
        assert_eq!(
            proof.resulting_cell.steward_set.first(),
            Some(&NodeId::new("node-c"))
        );
        assert_eq!(
            proof
                .resulting_cell
                .control_capsule
                .sequencer_lease_generation,
            cell.control_capsule.sequencer_lease_generation + 1
        );
    }

    #[test]
    fn warm_restore_rejects_missing_capsule_or_consumer_state() {
        let cell = test_cell();
        let empty_certificate = cell
            .issue_cut_certificate(
                [],
                ConsumerStateDigest::ZERO,
                Time::from_secs(14),
                NodeId::new("node-a"),
            )
            .expect("certificate");

        let err = cell
            .certify_mobility(
                &empty_certificate,
                &MobilityOperation::WarmRestore {
                    target: NodeId::new("edge-restore"),
                    restored_epoch: CellEpoch::new(9, 1),
                    capsule_digest: CapsuleDigest::ZERO,
                },
            )
            .expect_err("restore without state must fail");

        assert_eq!(err, CutMobilityError::MissingConsumerStateDigest);
    }

    // -----------------------------------------------------------------------
    // Incident rehearsal tests
    // -----------------------------------------------------------------------

    fn make_snapshot() -> (SubjectCell, CutCertificate, IncidentSnapshot) {
        let cell = test_cell();
        let cert = cell
            .issue_cut_certificate(
                [obligation(5), obligation(10)],
                ConsumerStateDigest::new(0xdead),
                Time::from_secs(100),
                NodeId::new("node-a"),
            )
            .expect("certificate");

        let snap = IncidentSnapshot::capture(
            &cell,
            &cert,
            MobilityOperation::Evacuate {
                from: NodeId::new("node-a"),
                to: NodeId::new("node-b"),
            },
            "test-outage-1",
            Time::from_secs(100),
        )
        .expect("snapshot");

        (cell, cert, snap)
    }

    #[test]
    fn incident_snapshot_captures_cell_and_certificate() {
        let (cell, cert, snap) = make_snapshot();
        assert_eq!(snap.cell.cell_id, cell.cell_id);
        assert_eq!(
            snap.certificate.certificate_digest(),
            cert.certificate_digest()
        );
        assert_eq!(snap.label, "test-outage-1");
    }

    #[test]
    fn incident_snapshot_digest_is_deterministic() {
        let (_, _, snap1) = make_snapshot();
        let (_, _, snap2) = make_snapshot();
        assert_eq!(snap1.snapshot_digest(), snap2.snapshot_digest());
    }

    #[test]
    fn incident_snapshot_rejects_invalid_certificate() {
        let cell = test_cell();
        let bad_cert = CutCertificate {
            cell_id: cell.cell_id,
            epoch: CellEpoch::new(99, 99),
            obligation_frontier: vec![],
            consumer_state_digest: ConsumerStateDigest::ZERO,
            timestamp: Time::from_secs(1),
            signer: NodeId::new("node-a"),
        };

        let err = IncidentSnapshot::capture(
            &cell,
            &bad_cert,
            MobilityOperation::Evacuate {
                from: NodeId::new("node-a"),
                to: NodeId::new("node-b"),
            },
            "bad-cert",
            Time::from_secs(1),
        )
        .expect_err("should reject mismatched cert");

        assert!(matches!(err, RehearsalError::InvalidCertificate { .. }));
    }

    #[test]
    fn replay_original_produces_same_result_as_direct_certify() {
        let (cell, cert, snap) = make_snapshot();

        let direct = snap
            .original_operation
            .certify(&cell, &cert)
            .expect("direct");
        let replayed = snap.replay_original().expect("replayed");

        assert_eq!(
            direct.resulting_cell.control_capsule.active_sequencer,
            replayed.resulting_cell.control_capsule.active_sequencer,
        );
        assert_eq!(direct.mobility_digest(), replayed.mobility_digest());
    }

    #[test]
    fn fork_rehearsal_rebases_epoch_and_cell_id() {
        let (_, _, snap) = make_snapshot();
        let rehearsal_epoch = CellEpoch::new(10, 1);

        let fork = snap
            .fork_rehearsal(RehearsalPolicy::default(), rehearsal_epoch)
            .expect("fork");

        assert_eq!(fork.forked_cell.epoch, rehearsal_epoch);
        assert_ne!(fork.forked_cell.cell_id, snap.cell.cell_id);
        assert_eq!(fork.forked_certificate.epoch, rehearsal_epoch);
        assert_eq!(fork.forked_certificate.cell_id, fork.forked_cell.cell_id);
        assert_eq!(fork.snapshot_digest, snap.snapshot_digest());
    }

    #[test]
    fn fork_rehearsal_rejects_stale_epoch() {
        let (_, _, snap) = make_snapshot();
        let stale = snap.cell.epoch;

        let err = snap
            .fork_rehearsal(RehearsalPolicy::default(), stale)
            .expect_err("stale epoch must fail");

        assert!(matches!(err, RehearsalError::StaleRehearsalEpoch { .. }));
    }

    #[test]
    fn fork_with_steward_override_replaces_steward_set() {
        let (_, _, snap) = make_snapshot();
        let new_stewards = vec![
            NodeId::new("node-x"),
            NodeId::new("node-y"),
            NodeId::new("node-z"),
        ];

        let fork = snap
            .fork_rehearsal(
                RehearsalPolicy {
                    steward_override: Some(new_stewards.clone()),
                    description: "different steward set".to_owned(),
                    ..Default::default()
                },
                CellEpoch::new(10, 1),
            )
            .expect("fork");

        assert_eq!(fork.forked_cell.steward_set, new_stewards);
        assert_eq!(fork.forked_cell.control_capsule.steward_pool, new_stewards);
        // The original signer (node-a) is NOT in the new steward set.
        // The forked certificate must adapt the signer to node-x so
        // replay validation does not reject the certificate.
        assert_eq!(fork.forked_certificate.signer, NodeId::new("node-x"));
    }

    #[test]
    fn fork_with_steward_override_that_excludes_signer_still_replays() {
        let (_, _, snap) = make_snapshot();
        let new_stewards = vec![NodeId::new("node-x"), NodeId::new("node-y")];

        let fork = snap
            .fork_rehearsal(
                RehearsalPolicy {
                    steward_override: Some(new_stewards),
                    description: "entirely new steward set".to_owned(),
                    ..Default::default()
                },
                CellEpoch::new(10, 1),
            )
            .expect("fork with replaced signers");

        // Replay an evacuation from node-x to node-y in the forked steward set.
        let outcome = fork.replay(&MobilityOperation::Evacuate {
            from: NodeId::new("node-x"),
            to: NodeId::new("node-y"),
        });
        assert!(
            outcome.succeeded(),
            "rehearsal with completely replaced steward set must succeed"
        );
    }

    #[test]
    fn fork_with_data_capsule_override() {
        let (_, _, snap) = make_snapshot();

        let fork = snap
            .fork_rehearsal(
                RehearsalPolicy {
                    data_capsule_override: Some(DataCapsule {
                        temperature: CellTemperature::Hot,
                        retained_message_blocks: 16,
                    }),
                    description: "hot temperature rehearsal".to_owned(),
                    ..Default::default()
                },
                CellEpoch::new(10, 1),
            )
            .expect("fork");

        assert_eq!(
            fork.forked_cell.data_capsule.temperature,
            CellTemperature::Hot
        );
        assert_eq!(fork.forked_cell.data_capsule.retained_message_blocks, 16);
    }

    #[test]
    fn rehearsal_replay_succeeds_with_same_operation() {
        let (_, _, snap) = make_snapshot();
        let rehearsal_epoch = CellEpoch::new(10, 1);

        let fork = snap
            .fork_rehearsal(RehearsalPolicy::default(), rehearsal_epoch)
            .expect("fork");

        let outcome = fork.replay(&MobilityOperation::Evacuate {
            from: NodeId::new("node-a"),
            to: NodeId::new("node-b"),
        });

        assert!(outcome.succeeded());
        let resulting = outcome.resulting_cell().expect("cell");
        assert_eq!(
            resulting.control_capsule.active_sequencer,
            Some(NodeId::new("node-b"))
        );
    }

    #[test]
    fn rehearsal_replay_with_different_operation() {
        let (_, _, snap) = make_snapshot();
        let rehearsal_epoch = CellEpoch::new(10, 1);

        let fork = snap
            .fork_rehearsal(RehearsalPolicy::default(), rehearsal_epoch)
            .expect("fork");

        let outcome = fork.replay(&MobilityOperation::Handoff {
            from: NodeId::new("node-a"),
            to: NodeId::new("node-c"),
        });

        assert!(outcome.succeeded());
        assert_eq!(
            outcome
                .resulting_cell()
                .expect("cell")
                .control_capsule
                .active_sequencer,
            Some(NodeId::new("node-c"))
        );
    }

    #[test]
    fn rehearsal_replay_captures_failure() {
        let (_, _, snap) = make_snapshot();
        let rehearsal_epoch = CellEpoch::new(10, 1);

        let fork = snap
            .fork_rehearsal(
                RehearsalPolicy {
                    steward_override: Some(vec![NodeId::new("node-a"), NodeId::new("node-c")]),
                    description: "steward set without node-b".to_owned(),
                    ..Default::default()
                },
                rehearsal_epoch,
            )
            .expect("fork");

        let outcome = fork.replay(&MobilityOperation::Evacuate {
            from: NodeId::new("node-a"),
            to: NodeId::new("node-b"),
        });

        assert!(!outcome.succeeded());
    }

    #[test]
    fn comparison_detects_cell_drift() {
        let (_, _, snap) = make_snapshot();

        let fork = snap
            .fork_rehearsal(RehearsalPolicy::default(), CellEpoch::new(10, 1))
            .expect("fork");

        let rehearsal_outcome = fork.replay(&snap.original_operation);

        let comparison =
            RehearsalComparison::compare(&snap, rehearsal_outcome).expect("comparison");

        // Not equivalent because epoch/cell_id differ (forked branch has new epoch).
        assert!(!comparison.is_equivalent());
        match &comparison.divergence {
            RehearsalDivergence::CellDrift { differences } => {
                assert!(differences.contains(&"cell_id".to_owned()));
                assert!(differences.contains(&"epoch".to_owned()));
            }
            other => panic!("expected CellDrift, got {other:?}"),
        }
    }

    #[test]
    fn comparison_detects_rehearsal_failure() {
        let (_, _, snap) = make_snapshot();

        let fork = snap
            .fork_rehearsal(
                RehearsalPolicy {
                    steward_override: Some(vec![NodeId::new("node-a"), NodeId::new("node-c")]),
                    description: "no node-b".to_owned(),
                    ..Default::default()
                },
                CellEpoch::new(10, 1),
            )
            .expect("fork");

        let rehearsal_outcome = fork.replay(&MobilityOperation::Evacuate {
            from: NodeId::new("node-a"),
            to: NodeId::new("node-b"),
        });

        let comparison =
            RehearsalComparison::compare(&snap, rehearsal_outcome).expect("comparison");

        assert!(matches!(
            comparison.divergence,
            RehearsalDivergence::RehearsalFailed { .. }
        ));
    }

    #[test]
    fn comparison_digest_is_deterministic() {
        let (_, _, snap) = make_snapshot();

        let fork = snap
            .fork_rehearsal(RehearsalPolicy::default(), CellEpoch::new(10, 1))
            .expect("fork");
        let outcome = fork.replay(&snap.original_operation);
        let c1 = RehearsalComparison::compare(&snap, outcome).expect("comparison");

        let fork2 = snap
            .fork_rehearsal(RehearsalPolicy::default(), CellEpoch::new(10, 1))
            .expect("fork");
        let outcome2 = fork2.replay(&snap.original_operation);
        let c2 = RehearsalComparison::compare(&snap, outcome2).expect("comparison");

        assert_eq!(c1.comparison_digest(), c2.comparison_digest());
    }

    #[test]
    fn fork_digest_is_deterministic() {
        let (_, _, snap) = make_snapshot();
        let fork1 = snap
            .fork_rehearsal(RehearsalPolicy::default(), CellEpoch::new(10, 1))
            .expect("fork1");
        let fork2 = snap
            .fork_rehearsal(RehearsalPolicy::default(), CellEpoch::new(10, 1))
            .expect("fork2");
        assert_eq!(fork1.fork_digest(), fork2.fork_digest());
    }

    #[test]
    fn rehearsal_with_repair_policy_override() {
        let (_, _, snap) = make_snapshot();

        let fork = snap
            .fork_rehearsal(
                RehearsalPolicy {
                    repair_override: Some(RepairPolicy {
                        recoverability_target: 5,
                        cold_witnesses: 10,
                        hot_witnesses: 10,
                    }),
                    description: "aggressive repair".to_owned(),
                    ..Default::default()
                },
                CellEpoch::new(10, 1),
            )
            .expect("fork");

        assert_eq!(fork.forked_cell.repair_policy.recoverability_target, 5);
        assert_eq!(fork.forked_cell.repair_policy.cold_witnesses, 10);

        let outcome = fork.replay(&snap.original_operation);
        assert!(outcome.succeeded());
    }

    #[test]
    fn end_to_end_rehearsal_workflow() {
        // Simulate: "Replay this failover with a different steward set."
        let cell = test_cell();
        let cert = cell
            .issue_cut_certificate(
                [obligation(1), obligation(2), obligation(3)],
                ConsumerStateDigest::new(0xbeef),
                Time::from_secs(200),
                NodeId::new("node-b"),
            )
            .expect("certificate");

        let snap = IncidentSnapshot::capture(
            &cell,
            &cert,
            MobilityOperation::Failover {
                failed: NodeId::new("node-a"),
                promote_to: NodeId::new("node-c"),
            },
            "failover-incident-2026-03-20",
            Time::from_secs(200),
        )
        .expect("snapshot");

        // Question: "What if we had node-d available instead of node-c?"
        let fork = snap
            .fork_rehearsal(
                RehearsalPolicy {
                    steward_override: Some(vec![
                        NodeId::new("node-a"),
                        NodeId::new("node-b"),
                        NodeId::new("node-d"),
                    ]),
                    description: "failover with node-d instead of node-c".to_owned(),
                    ..Default::default()
                },
                CellEpoch::new(10, 1),
            )
            .expect("fork");

        let outcome = fork.replay(&MobilityOperation::Failover {
            failed: NodeId::new("node-a"),
            promote_to: NodeId::new("node-d"),
        });

        assert!(outcome.succeeded());
        assert_eq!(
            outcome
                .resulting_cell()
                .expect("cell")
                .control_capsule
                .active_sequencer,
            Some(NodeId::new("node-d"))
        );

        let comparison = RehearsalComparison::compare(&snap, outcome).expect("comparison");
        assert!(!comparison.is_equivalent());

        match &comparison.divergence {
            RehearsalDivergence::CellDrift { differences } => {
                assert!(differences.contains(&"active_sequencer".to_owned()));
                assert!(differences.contains(&"steward_set".to_owned()));
            }
            other => panic!("expected CellDrift, got {other:?}"),
        }
    }

    #[test]
    fn promotion_accepts_rehearsal_that_beats_failed_original_within_envelope() {
        let (_, _, snap) = make_snapshot();

        let fork = snap
            .fork_rehearsal(
                RehearsalPolicy {
                    steward_override: Some(vec![
                        NodeId::new("node-a"),
                        NodeId::new("node-b"),
                        NodeId::new("node-d"),
                    ]),
                    description: "recover with node-d".to_owned(),
                    ..Default::default()
                },
                CellEpoch::new(10, 1),
            )
            .expect("fork");

        let outcome = fork.replay(&MobilityOperation::Evacuate {
            from: NodeId::new("node-a"),
            to: NodeId::new("node-d"),
        });
        let comparison = RehearsalComparison::compare(&snap, outcome).expect("comparison");

        let decision = comparison.evaluate_promotion(
            &CounterfactualScore {
                policy_gain: 0.1,
                evidence_confidence: 0.9,
                violation_rate: 0.1,
            },
            &CounterfactualScore {
                policy_gain: 0.8,
                evidence_confidence: 0.95,
                violation_rate: 0.1,
            },
            &CounterfactualPromotionEnvelope {
                reliability: SafetyEnvelope {
                    min_stewards: 2,
                    max_stewards: 4,
                    min_repair_depth: 1,
                    max_repair_depth: 4,
                    evidence_threshold: 0.8,
                    rollback_violation_threshold: 0.2,
                    ..SafetyEnvelope::default()
                },
                max_temperature: CellTemperature::Warm,
                max_retained_message_blocks: 8,
                max_cold_witnesses: 2,
                max_hot_witnesses: 4,
            },
        );

        assert!(matches!(
            decision,
            CounterfactualPromotionDecision::Promote { .. }
        ));
    }

    #[test]
    fn promotion_rejects_candidate_below_evidence_threshold() {
        let (_, _, snap) = make_snapshot();
        let fork = snap
            .fork_rehearsal(RehearsalPolicy::default(), CellEpoch::new(10, 1))
            .expect("fork");
        let outcome = fork.replay(&snap.original_operation);
        let comparison = RehearsalComparison::compare(&snap, outcome).expect("comparison");

        let decision = comparison.evaluate_promotion(
            &CounterfactualScore {
                policy_gain: 0.2,
                evidence_confidence: 0.9,
                violation_rate: 0.1,
            },
            &CounterfactualScore {
                policy_gain: 0.7,
                evidence_confidence: 0.4,
                violation_rate: 0.1,
            },
            &CounterfactualPromotionEnvelope {
                reliability: SafetyEnvelope {
                    evidence_threshold: 0.8,
                    ..SafetyEnvelope::default()
                },
                ..Default::default()
            },
        );

        assert_eq!(
            decision,
            CounterfactualPromotionDecision::RejectInsufficientEvidence {
                observed: 0.4,
                required: 0.8,
            }
        );
    }

    #[test]
    fn promotion_rejects_candidate_outside_safety_envelope() {
        let (_, _, snap) = make_snapshot();

        let fork = snap
            .fork_rehearsal(
                RehearsalPolicy {
                    repair_override: Some(RepairPolicy {
                        recoverability_target: 6,
                        cold_witnesses: 5,
                        hot_witnesses: 7,
                    }),
                    data_capsule_override: Some(DataCapsule {
                        temperature: CellTemperature::Hot,
                        retained_message_blocks: 32,
                    }),
                    description: "aggressive unsafe branch".to_owned(),
                    ..Default::default()
                },
                CellEpoch::new(10, 1),
            )
            .expect("fork");

        let outcome = fork.replay(&snap.original_operation);
        let comparison = RehearsalComparison::compare(&snap, outcome).expect("comparison");

        let decision = comparison.evaluate_promotion(
            &CounterfactualScore {
                policy_gain: 0.2,
                evidence_confidence: 0.9,
                violation_rate: 0.1,
            },
            &CounterfactualScore {
                policy_gain: 0.9,
                evidence_confidence: 0.95,
                violation_rate: 0.1,
            },
            &CounterfactualPromotionEnvelope {
                reliability: SafetyEnvelope {
                    min_repair_depth: 1,
                    max_repair_depth: 4,
                    evidence_threshold: 0.8,
                    rollback_violation_threshold: 0.2,
                    ..SafetyEnvelope::default()
                },
                max_temperature: CellTemperature::Warm,
                max_retained_message_blocks: 8,
                max_cold_witnesses: 2,
                max_hot_witnesses: 4,
            },
        );

        match decision {
            CounterfactualPromotionDecision::RejectEnvelopeViolation { reasons } => {
                assert!(reasons.iter().any(|r| r.contains("recoverability_target")));
                assert!(reasons.iter().any(|r| r.contains("temperature")));
                assert!(
                    reasons
                        .iter()
                        .any(|r| r.contains("retained_message_blocks"))
                );
                assert!(reasons.iter().any(|r| r.contains("cold_witnesses")));
                assert!(reasons.iter().any(|r| r.contains("hot_witnesses")));
            }
            other => panic!("expected RejectEnvelopeViolation, got {other:?}"),
        }
    }

    #[test]
    fn promotion_rejects_candidate_with_nan_policy_gain() {
        let (_, _, snap) = make_snapshot();
        let fork = snap
            .fork_rehearsal(RehearsalPolicy::default(), CellEpoch::new(10, 1))
            .expect("fork");
        let outcome = fork.replay(&MobilityOperation::Failover {
            failed: NodeId::new("node-a"),
            promote_to: NodeId::new("node-b"),
        });
        let comparison = RehearsalComparison::compare(&snap, outcome).expect("comparison");

        let decision = comparison.evaluate_promotion(
            &CounterfactualScore {
                policy_gain: 0.2,
                evidence_confidence: 0.9,
                violation_rate: 0.1,
            },
            &CounterfactualScore {
                policy_gain: f64::NAN,
                evidence_confidence: 0.95,
                violation_rate: 0.05,
            },
            &CounterfactualPromotionEnvelope::default(),
        );

        assert!(matches!(
            decision,
            CounterfactualPromotionDecision::RejectInvalidScore {
                field: "policy_gain",
                value,
            } if value.is_nan()
        ));
    }

    #[test]
    fn promotion_rejects_invalid_envelope_before_threshold_checks() {
        let (_, _, snap) = make_snapshot();
        let fork = snap
            .fork_rehearsal(RehearsalPolicy::default(), CellEpoch::new(10, 1))
            .expect("fork");
        let outcome = fork.replay(&MobilityOperation::Failover {
            failed: NodeId::new("node-a"),
            promote_to: NodeId::new("node-b"),
        });
        let comparison = RehearsalComparison::compare(&snap, outcome).expect("comparison");

        let decision = comparison.evaluate_promotion(
            &CounterfactualScore {
                policy_gain: 0.2,
                evidence_confidence: 0.9,
                violation_rate: 0.1,
            },
            &CounterfactualScore {
                policy_gain: 0.8,
                evidence_confidence: 0.95,
                violation_rate: 0.05,
            },
            &CounterfactualPromotionEnvelope {
                reliability: SafetyEnvelope {
                    evidence_threshold: f64::NAN,
                    ..SafetyEnvelope::default()
                },
                ..Default::default()
            },
        );

        assert!(matches!(
            decision,
            CounterfactualPromotionDecision::RejectInvalidEnvelope {
                error: ReliabilityControlError::InvalidProbability {
                    field: "evidence_threshold",
                    value,
                },
            } if value.is_nan()
        ));
    }

    #[test]
    fn promotion_rejects_baseline_with_nan_policy_gain() {
        let (_, _, snap) = make_snapshot();
        let fork = snap
            .fork_rehearsal(RehearsalPolicy::default(), CellEpoch::new(10, 1))
            .expect("fork");
        let outcome = fork.replay(&MobilityOperation::Failover {
            failed: NodeId::new("node-a"),
            promote_to: NodeId::new("node-b"),
        });
        let comparison = RehearsalComparison::compare(&snap, outcome).expect("comparison");

        let decision = comparison.evaluate_promotion(
            &CounterfactualScore {
                policy_gain: f64::NAN,
                evidence_confidence: 0.9,
                violation_rate: 0.1,
            },
            &CounterfactualScore {
                policy_gain: 0.8,
                evidence_confidence: 0.95,
                violation_rate: 0.05,
            },
            &CounterfactualPromotionEnvelope::default(),
        );

        assert!(matches!(
            decision,
            CounterfactualPromotionDecision::RejectInvalidScore {
                field: "baseline_policy_gain",
                value,
            } if value.is_nan()
        ));
    }

    // -----------------------------------------------------------------------
    // Cut lattice index tests
    // -----------------------------------------------------------------------

    fn make_index_cert(
        cell: &SubjectCell,
        signer: &str,
        obligations: &[u32],
        time_secs: u64,
    ) -> CutCertificate {
        cell.issue_cut_certificate(
            obligations.iter().map(|&i| obligation(i)),
            ConsumerStateDigest::new(0xaaaa),
            Time::from_secs(time_secs),
            NodeId::new(signer),
        )
        .expect("certificate")
    }

    fn make_regime(rev: u64, label: &str) -> PolicyRegime {
        PolicyRegime {
            policy_revision: rev,
            label: label.to_owned(),
        }
    }

    #[test]
    fn index_cut_and_query_by_cell() {
        let cell = test_cell();
        let mut idx = CutLatticeIndex::with_defaults();

        let cert = make_index_cert(&cell, "node-a", &[1, 2], 100);
        let eid = idx.index_cut(
            cert,
            make_regime(1, "v1"),
            CutAccessClass::Operator,
            2,
            0,
            Time::from_secs(100),
        );

        assert_eq!(idx.len(), 1);
        assert!(!idx.is_empty());

        let results = idx.query(&CutIndexQuery {
            cell_id: Some(cell.cell_id),
            ..Default::default()
        });
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].entry_id, eid);
    }

    #[test]
    fn query_by_time_range() {
        let cell = test_cell();
        let mut idx = CutLatticeIndex::with_defaults();

        for t in [100, 200, 300] {
            let cert = make_index_cert(&cell, "node-a", &[1], t);
            idx.index_cut(
                cert,
                make_regime(1, "v1"),
                CutAccessClass::Operator,
                1,
                0,
                Time::from_secs(t),
            );
        }

        let results = idx.query(&CutIndexQuery {
            after: Some(Time::from_secs(150)),
            before: Some(Time::from_secs(250)),
            ..Default::default()
        });
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].certificate.timestamp, Time::from_secs(200));
    }

    #[test]
    fn query_by_policy_label() {
        let cell = test_cell();
        let mut idx = CutLatticeIndex::with_defaults();

        let cert1 = make_index_cert(&cell, "node-a", &[1], 100);
        idx.index_cut(
            cert1,
            make_regime(1, "v1-strict"),
            CutAccessClass::Operator,
            1,
            0,
            Time::from_secs(100),
        );

        let cert2 = make_index_cert(&cell, "node-a", &[2], 200);
        idx.index_cut(
            cert2,
            make_regime(2, "v2-relaxed"),
            CutAccessClass::Operator,
            1,
            0,
            Time::from_secs(200),
        );

        let results = idx.query(&CutIndexQuery {
            policy_label: Some("v1-strict".to_owned()),
            ..Default::default()
        });
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].policy_regime.label, "v1-strict");
    }

    #[test]
    fn query_with_obligation_filter() {
        let cell = test_cell();
        let mut idx = CutLatticeIndex::with_defaults();

        let cert1 = make_index_cert(&cell, "node-a", &[5, 10], 100);
        idx.index_cut(
            cert1,
            make_regime(1, "v1"),
            CutAccessClass::Operator,
            2,
            0,
            Time::from_secs(100),
        );

        let cert2 = make_index_cert(&cell, "node-a", &[20, 30], 200);
        idx.index_cut(
            cert2,
            make_regime(1, "v1"),
            CutAccessClass::Operator,
            2,
            0,
            Time::from_secs(200),
        );

        let results = idx.query(&CutIndexQuery {
            covers_obligation: Some(obligation(10)),
            ..Default::default()
        });
        assert_eq!(results.len(), 1);
        assert!(results[0].certificate.covers_obligation(obligation(10)));
    }

    #[test]
    fn query_respects_access_class_filter() {
        let cell = test_cell();
        let mut idx = CutLatticeIndex::with_defaults();

        let cert1 = make_index_cert(&cell, "node-a", &[1], 100);
        idx.index_cut(
            cert1,
            make_regime(1, "v1"),
            CutAccessClass::Operator,
            1,
            0,
            Time::from_secs(100),
        );

        let cert2 = make_index_cert(&cell, "node-a", &[2], 200);
        idx.index_cut(
            cert2,
            make_regime(1, "v1"),
            CutAccessClass::AuditOnly,
            1,
            0,
            Time::from_secs(200),
        );

        let results = idx.query(&CutIndexQuery {
            max_access_class: Some(CutAccessClass::Operator),
            ..Default::default()
        });
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].access_class, CutAccessClass::Operator);
    }

    #[test]
    fn query_limit_truncates_results() {
        let cell = test_cell();
        let mut idx = CutLatticeIndex::with_defaults();

        for t in [100, 200, 300, 400, 500] {
            let cert = make_index_cert(&cell, "node-a", &[1], t);
            idx.index_cut(
                cert,
                make_regime(1, "v1"),
                CutAccessClass::Operator,
                1,
                0,
                Time::from_secs(t),
            );
        }

        let results = idx.query(&CutIndexQuery {
            limit: 2,
            ..Default::default()
        });
        assert_eq!(results.len(), 2);
        // Most recent first.
        assert_eq!(results[0].certificate.timestamp, Time::from_secs(500));
        assert_eq!(results[1].certificate.timestamp, Time::from_secs(400));
    }

    #[test]
    fn latest_for_cell_returns_most_recent() {
        let cell = test_cell();
        let mut idx = CutLatticeIndex::with_defaults();

        for t in [100, 200, 300] {
            let cert = make_index_cert(&cell, "node-a", &[1], t);
            idx.index_cut(
                cert,
                make_regime(1, "v1"),
                CutAccessClass::Operator,
                1,
                0,
                Time::from_secs(t),
            );
        }

        let latest = idx.latest_for_cell(cell.cell_id).expect("latest");
        assert_eq!(latest.certificate.timestamp, Time::from_secs(300));
    }

    #[test]
    fn latest_for_policy_returns_most_recent() {
        let cell = test_cell();
        let mut idx = CutLatticeIndex::with_defaults();

        let cert = make_index_cert(&cell, "node-a", &[1], 100);
        idx.index_cut(
            cert,
            make_regime(1, "canary-policy"),
            CutAccessClass::Operator,
            1,
            0,
            Time::from_secs(100),
        );

        let result = idx.latest_for_policy("canary-policy").expect("found");
        assert_eq!(result.policy_regime.label, "canary-policy");
        assert!(idx.latest_for_policy("nonexistent").is_none());
    }

    #[test]
    fn register_descendant_branch() {
        let cell = test_cell();
        let mut idx = CutLatticeIndex::with_defaults();

        let cert = make_index_cert(&cell, "node-a", &[1], 100);
        let eid = idx.index_cut(
            cert,
            make_regime(1, "v1"),
            CutAccessClass::Operator,
            1,
            0,
            Time::from_secs(100),
        );

        assert!(idx.register_descendant(eid, 0x1234));
        assert!(idx.register_descendant(eid, 0x5678));
        // Duplicate is idempotent.
        assert!(idx.register_descendant(eid, 0x1234));

        let entry = idx.query(&CutIndexQuery::default());
        assert_eq!(entry[0].descendant_branches, vec![0x1234, 0x5678]);

        // Nonexistent entry returns false.
        assert!(!idx.register_descendant(0xdead, 0x9999));
    }

    #[test]
    fn compact_dematerializes_old_entries() {
        let cell = test_cell();
        let mut idx = CutLatticeIndex::new(CutRetentionPolicy {
            max_materialized_per_cell: 2,
            max_age_nanos: 500_000_000_000, // 500s
            min_retained_per_cell: 1,
        });

        // Insert 4 entries at t=100, 200, 300, 400.
        for t in [100, 200, 300, 400] {
            let cert = make_index_cert(&cell, "node-a", &[1], t);
            idx.index_cut(
                cert,
                make_regime(1, "v1"),
                CutAccessClass::Operator,
                1,
                0,
                Time::from_secs(t),
            );
        }

        assert_eq!(idx.len(), 4);

        // Compact at t=450 — all within age, but exceeds max_materialized=2.
        let compacted = idx.compact(Time::from_secs(450));
        // Entries at rank ≥ 2 with rank ≥ min_retained=1 get compacted.
        // rank 0: t=400 (keep materialized)
        // rank 1: t=300 (keep materialized)
        // rank 2: t=200 (compact — rank ≥ max_materialized AND rank ≥ min_retained)
        // rank 3: t=100 (compact)
        assert_eq!(compacted, 2);

        let materialized = idx.query(&CutIndexQuery {
            materialized_only: true,
            ..Default::default()
        });
        assert_eq!(materialized.len(), 2);
    }

    #[test]
    fn compact_respects_min_retained() {
        let cell = test_cell();
        let mut idx = CutLatticeIndex::new(CutRetentionPolicy {
            max_materialized_per_cell: 1,
            max_age_nanos: 1, // Very aggressive age policy.
            min_retained_per_cell: 2,
        });

        for t in [100, 200, 300] {
            let cert = make_index_cert(&cell, "node-a", &[1], t);
            idx.index_cut(
                cert,
                make_regime(1, "v1"),
                CutAccessClass::Operator,
                1,
                0,
                Time::from_secs(t),
            );
        }

        // Even with very aggressive compaction, min_retained=2 keeps 2 alive.
        let compacted = idx.compact(Time::from_secs(10_000));
        assert_eq!(compacted, 1); // Only the 3rd-oldest gets compacted.

        // The 2 most recent are not compacted.
        let all = idx.query(&CutIndexQuery::default());
        let non_compacted: Vec<_> = all
            .iter()
            .filter(|e| e.materialization != MaterializationState::Compacted)
            .collect();
        assert_eq!(non_compacted.len(), 2);
    }

    #[test]
    fn materialize_reconstructible_entry() {
        let cell = test_cell();
        let mut idx = CutLatticeIndex::new(CutRetentionPolicy {
            max_materialized_per_cell: 1,
            max_age_nanos: u64::MAX,
            min_retained_per_cell: 3,
        });

        for t in [100, 200, 300] {
            let cert = make_index_cert(&cell, "node-a", &[1], t);
            idx.index_cut(
                cert,
                make_regime(1, "v1"),
                CutAccessClass::Operator,
                1,
                0,
                Time::from_secs(t),
            );
        }

        // Compact to make older entries reconstructible.
        idx.compact(Time::from_secs(400));

        // Find a reconstructible entry.
        let all = idx.query(&CutIndexQuery::default());
        let recon = all
            .iter()
            .find(|e| e.materialization == MaterializationState::Reconstructible);
        if let Some(entry) = recon {
            let eid = entry.entry_id;
            assert!(idx.materialize(eid));

            // Verify it's now materialized.
            let refreshed = idx.query(&CutIndexQuery {
                materialized_only: true,
                ..Default::default()
            });
            assert!(refreshed.iter().any(|e| e.entry_id == eid));
        }
    }

    #[test]
    fn entry_digest_is_deterministic() {
        let cell = test_cell();
        let mut idx = CutLatticeIndex::with_defaults();

        let cert1 = make_index_cert(&cell, "node-a", &[1, 2], 100);
        let cert2 = make_index_cert(&cell, "node-a", &[1, 2], 100);

        let eid1 = idx.index_cut(
            cert1,
            make_regime(1, "v1"),
            CutAccessClass::Operator,
            2,
            0,
            Time::from_secs(100),
        );

        let eid2 = idx.index_cut(
            cert2,
            make_regime(1, "v1"),
            CutAccessClass::Operator,
            2,
            0,
            Time::from_secs(100),
        );

        assert_eq!(eid1, eid2);

        // Idempotent: second insert is a no-op, only 1 entry exists.
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn entry_digest_deterministic_across_indexes() {
        let cell = test_cell();
        let mut idx1 = CutLatticeIndex::with_defaults();
        let mut idx2 = CutLatticeIndex::with_defaults();

        let cert1 = make_index_cert(&cell, "node-a", &[1, 2], 100);
        let cert2 = make_index_cert(&cell, "node-a", &[1, 2], 100);

        idx1.index_cut(
            cert1,
            make_regime(1, "v1"),
            CutAccessClass::Operator,
            2,
            0,
            Time::from_secs(100),
        );
        idx2.index_cut(
            cert2,
            make_regime(1, "v1"),
            CutAccessClass::Operator,
            2,
            0,
            Time::from_secs(100),
        );

        let e1 = &idx1.query(&CutIndexQuery::default())[0];
        let e2 = &idx2.query(&CutIndexQuery::default())[0];
        assert_eq!(e1.entry_digest(), e2.entry_digest());
    }

    #[test]
    fn empty_index_queries_return_none() {
        let idx = CutLatticeIndex::with_defaults();
        assert!(idx.is_empty());
        assert_eq!(idx.len(), 0);
        assert!(
            idx.latest_for_cell(CellId::for_partition(
                CellEpoch::new(1, 1),
                &SubjectPattern::parse("x").expect("pat")
            ))
            .is_none()
        );
        assert!(idx.latest_for_policy("any").is_none());
    }

    // -----------------------------------------------------------------------
    // Branch-addressable reality tests
    // -----------------------------------------------------------------------

    fn make_index_with_entry() -> (SubjectCell, CutLatticeIndex, u64) {
        let cell = test_cell();
        let mut idx = CutLatticeIndex::with_defaults();
        let cert = make_index_cert(&cell, "node-a", &[1, 2], 100);
        let eid = idx.index_cut(
            cert,
            make_regime(1, "v1"),
            CutAccessClass::Operator,
            2,
            0,
            Time::from_secs(100),
        );
        (cell, idx, eid)
    }

    #[test]
    fn branch_type_default_mutability() {
        assert!(BranchType::Live.default_mutable());
        assert!(BranchType::Canary.default_mutable());
        assert!(!BranchType::Lagged.default_mutable());
        assert!(!BranchType::Replayed.default_mutable());
        assert!(!BranchType::Forensic.default_mutable());
    }

    #[test]
    fn branch_type_fencing() {
        assert!(!BranchType::Live.is_fenced());
        assert!(BranchType::Lagged.is_fenced());
        assert!(BranchType::Replayed.is_fenced());
        assert!(BranchType::Canary.is_fenced());
        assert!(BranchType::Forensic.is_fenced());
    }

    #[test]
    fn access_policy_write_semantics() {
        assert!(!BranchAccessPolicy::ReadOnly.allows_writes());
        assert!(BranchAccessPolicy::Sandboxed.allows_writes());
        assert!(BranchAccessPolicy::ReadWrite.allows_writes());

        assert!(!BranchAccessPolicy::ReadOnly.propagates_to_live());
        assert!(!BranchAccessPolicy::Sandboxed.propagates_to_live());
        assert!(BranchAccessPolicy::ReadWrite.propagates_to_live());
    }

    #[test]
    fn create_live_branch() {
        let cell = test_cell();
        let mut reg = BranchRegistry::new();
        let branch = reg
            .create_live(cell.cell_id, Time::from_secs(1))
            .expect("live");
        assert_eq!(branch.branch_type, BranchType::Live);
        assert_eq!(branch.access_policy, BranchAccessPolicy::ReadWrite);
        assert_eq!(branch.cell_id, cell.cell_id);
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn create_lagged_branch() {
        let (cell, idx, eid) = make_index_with_entry();
        let mut reg = BranchRegistry::new();
        let branch = reg
            .create_lagged(eid, cell.cell_id, "trailing live", Time::from_secs(2), &idx)
            .expect("lagged");
        assert_eq!(branch.branch_type, BranchType::Lagged);
        assert_eq!(branch.access_policy, BranchAccessPolicy::ReadOnly);
        assert_eq!(branch.cut_entry_id, eid);
    }

    #[test]
    fn create_replayed_branch() {
        let (cell, idx, eid) = make_index_with_entry();
        let mut reg = BranchRegistry::new();
        let branch = reg
            .create_replayed(
                eid,
                cell.cell_id,
                "v2-strict",
                "replay under strict policy",
                Time::from_secs(3),
                &idx,
            )
            .expect("replayed");
        assert_eq!(branch.branch_type, BranchType::Replayed);
        assert_eq!(branch.policy_label, "v2-strict");
        assert_eq!(branch.access_policy, BranchAccessPolicy::ReadOnly);
    }

    #[test]
    fn create_canary_branch_is_sandboxed() {
        let (cell, idx, eid) = make_index_with_entry();
        let mut reg = BranchRegistry::new();
        let branch = reg
            .create_canary(
                eid,
                cell.cell_id,
                "candidate-policy",
                "canary evaluation",
                Time::from_secs(4),
                &idx,
            )
            .expect("canary");
        assert_eq!(branch.branch_type, BranchType::Canary);
        assert_eq!(branch.access_policy, BranchAccessPolicy::Sandboxed);
        assert!(branch.access_policy.allows_writes());
        assert!(!branch.access_policy.propagates_to_live());
    }

    #[test]
    fn create_forensic_branch() {
        let (cell, idx, eid) = make_index_with_entry();
        let mut reg = BranchRegistry::new();
        let branch = reg
            .create_forensic(
                eid,
                cell.cell_id,
                "explain ticket-1234",
                Time::from_secs(5),
                &idx,
            )
            .expect("forensic");
        assert_eq!(branch.branch_type, BranchType::Forensic);
        assert_eq!(branch.access_policy, BranchAccessPolicy::ReadOnly);
    }

    #[test]
    fn create_branch_rejects_missing_cut() {
        let (cell, idx, _eid) = make_index_with_entry();
        let mut reg = BranchRegistry::new();
        let err = reg
            .create_lagged(0xdead, cell.cell_id, "orphan", Time::from_secs(6), &idx)
            .expect_err("should reject missing cut");
        assert!(matches!(err, BranchError::CutNotFound { .. }));
    }

    #[test]
    fn create_duplicate_branch_rejected() {
        let cell = test_cell();
        let mut reg = BranchRegistry::new();
        reg.create_live(cell.cell_id, Time::from_secs(1))
            .expect("first");
        let err = reg
            .create_live(cell.cell_id, Time::from_secs(2))
            .expect_err("duplicate");
        assert!(matches!(err, BranchError::DuplicateBranch { .. }));
    }

    #[test]
    fn lookup_by_id() {
        let (cell, idx, eid) = make_index_with_entry();
        let mut reg = BranchRegistry::new();
        let branch = reg
            .create_forensic(eid, cell.cell_id, "lookup test", Time::from_secs(7), &idx)
            .expect("forensic");
        let bid = branch.branch_id;

        assert!(reg.get(bid).is_some());
        assert!(reg.get(0xffff).is_none());
    }

    #[test]
    fn live_for_cell() {
        let cell = test_cell();
        let mut reg = BranchRegistry::new();
        assert!(reg.live_for_cell(cell.cell_id).is_none());

        reg.create_live(cell.cell_id, Time::from_secs(1))
            .expect("live");
        assert!(reg.live_for_cell(cell.cell_id).is_some());
    }

    #[test]
    fn branches_for_cell_lists_all() {
        let (cell, idx, eid) = make_index_with_entry();
        let mut reg = BranchRegistry::new();
        reg.create_live(cell.cell_id, Time::from_secs(1))
            .expect("live");
        reg.create_forensic(eid, cell.cell_id, "forensic", Time::from_secs(2), &idx)
            .expect("forensic");
        reg.create_canary(
            eid,
            cell.cell_id,
            "canary-pol",
            "canary",
            Time::from_secs(3),
            &idx,
        )
        .expect("canary");

        assert_eq!(reg.branches_for_cell(cell.cell_id).len(), 3);
    }

    #[test]
    fn branches_of_type() {
        let (cell, idx, eid) = make_index_with_entry();
        let mut reg = BranchRegistry::new();
        reg.create_live(cell.cell_id, Time::from_secs(1))
            .expect("live");
        reg.create_forensic(eid, cell.cell_id, "f1", Time::from_secs(2), &idx)
            .expect("f1");

        assert_eq!(reg.branches_of_type(BranchType::Live).len(), 1);
        assert_eq!(reg.branches_of_type(BranchType::Forensic).len(), 1);
        assert_eq!(reg.branches_of_type(BranchType::Canary).len(), 0);
    }

    #[test]
    fn remove_branch() {
        let cell = test_cell();
        let mut reg = BranchRegistry::new();
        let branch = reg
            .create_live(cell.cell_id, Time::from_secs(1))
            .expect("live");
        let bid = branch.branch_id;

        assert!(reg.remove(bid));
        assert!(reg.is_empty());
        assert!(!reg.remove(bid)); // idempotent
    }

    #[test]
    fn branch_address_digest_is_deterministic() {
        let (cell, idx, eid) = make_index_with_entry();
        let mut reg1 = BranchRegistry::new();
        let mut reg2 = BranchRegistry::new();

        let b1 = reg1
            .create_canary(eid, cell.cell_id, "pol", "test", Time::from_secs(1), &idx)
            .expect("b1");
        let b2 = reg2
            .create_canary(eid, cell.cell_id, "pol", "test", Time::from_secs(2), &idx)
            .expect("b2");

        // Same branch type + cut + cell + policy → same address digest
        // (created_at differs but doesn't affect the address identity).
        assert_eq!(b1.address_digest(), b2.address_digest());
    }

    #[test]
    fn empty_registry() {
        let reg = BranchRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
    }
