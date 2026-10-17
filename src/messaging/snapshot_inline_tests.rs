    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::super::class::DeliveryClass;
    use super::super::fabric::{
        CellTemperature, DataCapsule, NodeRole, PlacementPolicy, RepairPolicy, StewardCandidate,
        StorageClass, SubjectPattern,
    };
    use super::super::privacy::{CellKeyContext, SubgroupKeyContext};
    use super::super::stream::{InMemoryStorageBackend, Stream, StreamConfig};
    use super::super::subject::Subject;
    use super::*;
    use crate::remote::NodeId;
    use crate::types::{ObligationId, RegionId};

    fn candidate(
        name: &str,
        domain: &str,
        storage: StorageClass,
        latency_millis: u32,
    ) -> StewardCandidate {
        StewardCandidate::new(NodeId::new(name), domain)
            .with_role(NodeRole::Steward)
            .with_storage_class(storage)
            .with_latency_millis(latency_millis)
    }

    fn subject_cell() -> SubjectCell {
        let candidates = vec![
            candidate("node-a", "rack-a", StorageClass::Durable, 5),
            candidate("node-b", "rack-b", StorageClass::Durable, 7),
            candidate("node-c", "rack-c", StorageClass::Standard, 9),
        ];

        SubjectCell::new(
            &SubjectPattern::parse("orders.created").expect("pattern"),
            CellEpoch::new(11, 2),
            &candidates,
            &PlacementPolicy::default(),
            RepairPolicy {
                recoverability_target: 3,
                cold_witnesses: 1,
                hot_witnesses: 2,
            },
            DataCapsule {
                temperature: CellTemperature::Warm,
                retained_message_blocks: 4,
            },
        )
        .expect("subject cell")
    }

    fn key_hierarchy_spec() -> CellKeyHierarchySpec {
        CellKeyHierarchySpec {
            subgroup: SubgroupKeyContext {
                subgroup_epoch: 4,
                subgroup_roster_hash: "subgroup-roster-hash-a".to_owned(),
            },
            cell: CellKeyContext {
                cell_id: "cell.orders.created".to_owned(),
                cell_epoch: 11,
                roster_hash: "cell-roster-hash-a".to_owned(),
                config_epoch_hash: "config-epoch-hash-a".to_owned(),
                cell_rekey_generation: 2,
            },
        }
    }

    fn captured_state() -> ServiceCapsuleState {
        ServiceCapsuleState::new(
            CapsuleStateDigest::new(11),
            CapsuleStateDigest::new(13),
            CapsuleStateDigest::new(17),
            CapsuleStateDigest::new(19),
            CapsuleStateDigest::new(23),
            [
                EvidenceDigest::new(7),
                EvidenceDigest::new(3),
                EvidenceDigest::new(7),
            ],
        )
    }

    fn cut_certificate(cell: &SubjectCell) -> CutCertificate {
        cell.issue_cut_certificate(
            [
                ObligationId::new_for_test(5, 0),
                ObligationId::new_for_test(2, 0),
            ],
            ConsumerStateDigest::new(41),
            Time::from_secs(3),
            cell.steward_set
                .first()
                .cloned()
                .expect("active steward in cut"),
        )
        .expect("cut certificate")
    }

    fn frontierless_cut_certificate(cell: &SubjectCell) -> CutCertificate {
        cell.issue_cut_certificate(
            [],
            ConsumerStateDigest::new(41),
            Time::from_secs(3),
            cell.steward_set
                .first()
                .cloned()
                .expect("active steward in cut"),
        )
        .expect("cut certificate")
    }

    fn test_region(index: u32) -> RegionId {
        RegionId::new_for_test(index, 1)
    }

    fn stream_config(filter: &str) -> StreamConfig {
        StreamConfig {
            subject_filter: SubjectPattern::new(filter),
            ..StreamConfig::default()
        }
    }

    fn quiescent_stream_snapshot() -> StreamSnapshot {
        let mut stream = Stream::new(
            "orders-stream",
            test_region(70),
            Time::from_secs(10),
            stream_config("orders.>"),
            InMemoryStorageBackend::default(),
        )
        .expect("stream");
        stream
            .append(
                Subject::new("orders.created"),
                b"payload".to_vec(),
                Time::from_secs(11),
            )
            .expect("append");
        stream.snapshot().expect("snapshot")
    }

    fn non_quiescent_stream_snapshot() -> StreamSnapshot {
        let mut stream = Stream::new(
            "orders-stream",
            test_region(71),
            Time::from_secs(10),
            stream_config("orders.>"),
            InMemoryStorageBackend::default(),
        )
        .expect("stream");
        stream
            .append(
                Subject::new("orders.created"),
                b"payload".to_vec(),
                Time::from_secs(11),
            )
            .expect("append");
        let consumer = stream.attach_consumer();
        stream
            .add_mirror_region(test_region(72))
            .expect("mirror region");
        let snapshot = stream.snapshot().expect("snapshot");
        assert_eq!(snapshot.consumer_ids, vec![consumer]);
        snapshot
    }

    #[test]
    fn capture_builds_capsule_digest_and_canonicalizes_evidence_frontier() {
        let cell = subject_cell();
        let capsule = RecoverableServiceCapsule::capture(
            "orders-service",
            &cell,
            &cut_certificate(&cell),
            key_hierarchy_spec(),
            &captured_state(),
            Time::from_secs(5),
        )
        .expect("capsule capture");

        assert_ne!(capsule.capsule_digest, CapsuleDigest::ZERO);
        assert!(capsule.state.has_restorable_payload());
        assert_eq!(
            capsule.state.local_evidence_frontier,
            vec![EvidenceDigest::new(3), EvidenceDigest::new(7)]
        );
    }

    #[test]
    fn capture_rejects_invalid_key_hierarchy_spec() {
        let cell = subject_cell();
        let mut invalid_hierarchy = key_hierarchy_spec();
        invalid_hierarchy.cell.cell_id = "   ".to_owned();

        let err = RecoverableServiceCapsule::capture(
            "orders-service",
            &cell,
            &cut_certificate(&cell),
            invalid_hierarchy,
            &captured_state(),
            Time::from_secs(5),
        )
        .expect_err("invalid hierarchy must be rejected at capture time");

        assert_eq!(
            err,
            ServiceCapsuleError::KeyHierarchy(KeyHierarchyError::EmptyField { field: "cell_id" })
        );
    }

    #[test]
    fn capture_rejects_key_hierarchy_for_different_subject_binding() {
        let cell = subject_cell();
        let mut wrong_hierarchy = key_hierarchy_spec();
        wrong_hierarchy.cell.cell_id = "cell.payments.captured".to_owned();

        let err = RecoverableServiceCapsule::capture(
            "orders-service",
            &cell,
            &cut_certificate(&cell),
            wrong_hierarchy,
            &captured_state(),
            Time::from_secs(5),
        )
        .expect_err("mismatched key hierarchy binding must fail closed");

        assert_eq!(
            err,
            ServiceCapsuleError::KeyHierarchyCellBindingMismatch {
                expected: "cell.orders.created".to_owned(),
                actual: "cell.payments.captured".to_owned(),
            }
        );
    }

    #[test]
    fn capture_rejects_key_hierarchy_for_different_membership_epoch() {
        let cell = subject_cell();
        let mut wrong_hierarchy = key_hierarchy_spec();
        wrong_hierarchy.cell.cell_epoch += 1;

        let err = RecoverableServiceCapsule::capture(
            "orders-service",
            &cell,
            &cut_certificate(&cell),
            wrong_hierarchy,
            &captured_state(),
            Time::from_secs(5),
        )
        .expect_err("mismatched key hierarchy epoch must fail closed");

        assert_eq!(
            err,
            ServiceCapsuleError::KeyHierarchyCellEpochMismatch {
                expected: 11,
                actual: 12,
            }
        );
    }

    #[test]
    fn capture_rejects_pre_hibernated_service_state() {
        let cell = subject_cell();
        let err = RecoverableServiceCapsule::capture(
            "orders-service",
            &cell,
            &cut_certificate(&cell),
            key_hierarchy_spec(),
            &captured_state().hibernate(),
            Time::from_secs(5),
        )
        .expect_err("capture must reject already-hibernated service state");

        assert_eq!(err, ServiceCapsuleError::CapturedStateMustStartLive);
    }

    #[test]
    fn restore_plan_scrubs_authority_and_rebinds_to_fresh_epoch() {
        let cell = subject_cell();
        let capsule = RecoverableServiceCapsule::capture(
            "orders-service",
            &cell,
            &cut_certificate(&cell),
            key_hierarchy_spec(),
            &captured_state(),
            Time::from_secs(5),
        )
        .expect("capsule capture")
        .hibernate();
        let restored_epoch = CellEpoch::new(12, 4);
        let restore = capsule
            .plan_restore(
                NodeId::new("restore-node"),
                restored_epoch,
                &RestoreScrubRequest {
                    subgroup: SubgroupKeyContext {
                        subgroup_epoch: 9,
                        subgroup_roster_hash: "subgroup-roster-hash-restored".to_owned(),
                    },
                    cell: CellKeyContext {
                        cell_id: "cell.orders.created.restored".to_owned(),
                        cell_epoch: 44,
                        roster_hash: "cell-roster-hash-restored".to_owned(),
                        config_epoch_hash: "config-epoch-hash-restored".to_owned(),
                        cell_rekey_generation: 3,
                    },
                },
            )
            .expect("restore plan");

        assert_eq!(
            restore.certified_mobility.resulting_cell.epoch,
            restored_epoch
        );
        assert_ne!(
            restore.certified_mobility.resulting_cell.cell_id,
            cell.cell_id
        );
        assert_eq!(
            restore
                .certified_mobility
                .resulting_cell
                .control_capsule
                .active_sequencer_holder(),
            Some(&NodeId::new("restore-node"))
        );
        assert_eq!(
            restore.scrubbed_key_hierarchy.cell.cell_id,
            "cell.orders.created.restored"
        );
        assert_eq!(restore.scrubbed_key_hierarchy.cell.cell_epoch, 44);
        assert!(restore.restored_state.hibernated);
    }

    #[test]
    fn hibernate_resume_cycle_preserves_capsule_provenance() {
        let cell = subject_cell();
        let hibernated = RecoverableServiceCapsule::capture(
            "orders-service",
            &cell,
            &cut_certificate(&cell),
            key_hierarchy_spec(),
            &captured_state(),
            Time::from_secs(5),
        )
        .expect("capsule capture")
        .hibernate();
        let source_digest = hibernated.capsule_digest;
        let restored = hibernated
            .plan_restore(
                NodeId::new("resume-node"),
                CellEpoch::new(12, 3),
                &RestoreScrubRequest {
                    subgroup: SubgroupKeyContext {
                        subgroup_epoch: 8,
                        subgroup_roster_hash: "subgroup-roster-hash-b".to_owned(),
                    },
                    cell: CellKeyContext {
                        cell_id: "cell.orders.created.resumed".to_owned(),
                        cell_epoch: 45,
                        roster_hash: "cell-roster-hash-b".to_owned(),
                        config_epoch_hash: "config-epoch-hash-b".to_owned(),
                        cell_rekey_generation: 6,
                    },
                },
            )
            .expect("restore plan")
            .resume(Time::from_secs(8));

        assert_eq!(restored.source_capsule_digest, source_digest);
        assert_eq!(restored.resumed_at, Time::from_secs(8));
        assert!(!restored.active_state.hibernated);
        assert_eq!(
            restored.consumer_state_digest(),
            ConsumerStateDigest::new(41)
        );
    }

    #[test]
    fn cross_environment_transfer_preserves_evidence_frontier_through_restore() {
        let cell = subject_cell();
        let restored = RecoverableServiceCapsule::capture(
            "orders-service",
            &cell,
            &cut_certificate(&cell),
            key_hierarchy_spec(),
            &captured_state(),
            Time::from_secs(5),
        )
        .expect("capsule capture")
        .hibernate()
        .plan_restore(
            NodeId::new("edge-node"),
            CellEpoch::new(13, 1),
            &RestoreScrubRequest {
                subgroup: SubgroupKeyContext {
                    subgroup_epoch: 12,
                    subgroup_roster_hash: "subgroup-roster-hash-edge".to_owned(),
                },
                cell: CellKeyContext {
                    cell_id: "cell.orders.created.edge".to_owned(),
                    cell_epoch: 51,
                    roster_hash: "cell-roster-hash-edge".to_owned(),
                    config_epoch_hash: "config-epoch-hash-edge".to_owned(),
                    cell_rekey_generation: 9,
                },
            },
        )
        .expect("restore plan")
        .resume(Time::from_secs(9));

        assert_eq!(
            restored.active_state.local_evidence_frontier,
            vec![EvidenceDigest::new(3), EvidenceDigest::new(7)]
        );
        assert_eq!(restored.scrubbed_key_hierarchy.subgroup.subgroup_epoch, 12);
        assert_eq!(
            restored.restored_cell().subject_partition,
            cell.subject_partition
        );
        assert_eq!(
            restored
                .restored_cell()
                .control_capsule
                .active_sequencer_holder(),
            Some(&NodeId::new("edge-node"))
        );
    }

    #[test]
    fn restore_requires_hibernated_capsule() {
        let cell = subject_cell();
        let capsule = RecoverableServiceCapsule::capture(
            "orders-service",
            &cell,
            &cut_certificate(&cell),
            key_hierarchy_spec(),
            &captured_state(),
            Time::from_secs(5),
        )
        .expect("capsule capture");

        let err = capsule
            .plan_restore(
                NodeId::new("restore-node"),
                CellEpoch::new(12, 3),
                &RestoreScrubRequest {
                    subgroup: SubgroupKeyContext {
                        subgroup_epoch: 8,
                        subgroup_roster_hash: "subgroup-roster-hash-restored".to_owned(),
                    },
                    cell: CellKeyContext {
                        cell_id: "cell.orders.created.restored".to_owned(),
                        cell_epoch: 45,
                        roster_hash: "cell-roster-hash-restored".to_owned(),
                        config_epoch_hash: "config-epoch-hash-restored".to_owned(),
                        cell_rekey_generation: 6,
                    },
                },
            )
            .expect_err("live snapshot must be hibernated first");

        assert_eq!(err, ServiceCapsuleError::CapsuleMustBeHibernated);
    }

    #[test]
    fn recoverable_stream_snapshot_requires_frontier_for_non_quiescent_capture() {
        let cell = subject_cell();
        let err = RecoverableStreamSnapshot::capture(
            &non_quiescent_stream_snapshot(),
            &cell,
            &frontierless_cut_certificate(&cell),
            key_hierarchy_spec(),
            Time::from_secs(12),
        )
        .expect_err("non-quiescent capture must carry an explicit frontier");

        assert_eq!(
            err,
            StreamSnapshotError::NonQuiescentWithoutObligationFrontier {
                consumers: 1,
                mirrors: 1,
                sources: 0,
            }
        );
    }

    #[test]
    fn recoverable_stream_snapshot_restore_rebinds_epoch_and_scrubs_live_authority() {
        let cell = subject_cell();
        let captured_stream = non_quiescent_stream_snapshot();
        let cut = cut_certificate(&cell);
        let recoverable = RecoverableStreamSnapshot::capture(
            &captured_stream,
            &cell,
            &cut,
            key_hierarchy_spec(),
            Time::from_secs(12),
        )
        .expect("recoverable stream capture");

        let restored = recoverable
            .restore_into_staging(
                NodeId::new("restore-node"),
                test_region(90),
                CellEpoch::new(12, 4),
                &RestoreScrubRequest {
                    subgroup: SubgroupKeyContext {
                        subgroup_epoch: 9,
                        subgroup_roster_hash: "subgroup-roster-hash-restored".to_owned(),
                    },
                    cell: CellKeyContext {
                        cell_id: "cell.orders.created.restored".to_owned(),
                        cell_epoch: 44,
                        roster_hash: "cell-roster-hash-restored".to_owned(),
                        config_epoch_hash: "config-epoch-hash-restored".to_owned(),
                        cell_rekey_generation: 3,
                    },
                },
                "_INBOX.restored",
                Time::from_secs(20),
            )
            .expect("restore stream snapshot");

        assert_eq!(
            restored.certified_mobility.resulting_cell.epoch,
            CellEpoch::new(12, 4)
        );
        assert_eq!(
            restored.scrubbed_key_hierarchy.cell.cell_id,
            "cell.orders.created.restored"
        );
        assert_eq!(restored.restored_stream_state.region_id, test_region(90));
        assert_eq!(
            restored.restored_stream_state.storage,
            captured_stream.storage
        );
        assert_eq!(restored.restored_stream_state.state.msg_count, 1);
        assert!(restored.restored_stream_state.is_quiescent());
        assert_eq!(
            restored.restored_stream_state.consumer_ids,
            Vec::<u64>::new()
        );
        assert_eq!(
            restored.restored_consumer_states,
            vec![RestoredStreamConsumerState {
                consumer_id: captured_stream.consumer_ids[0],
                lease_invalidated: true,
            }]
        );
        assert_eq!(restored.obligation_frontier, cut.obligation_frontier);
        assert_eq!(
            restored.scrub_summary.reply_subject_prefix,
            "_INBOX.restored"
        );
        assert!(restored.scrub_summary.import_credentials_stripped);
        assert!(restored.scrub_summary.export_credentials_stripped);
        assert!(restored.scrub_summary.consumer_leases_invalidated);
    }

    #[test]
    fn recoverable_stream_snapshot_can_fork_under_counterfactual_policy() {
        let cell = subject_cell();
        let captured_stream = quiescent_stream_snapshot();
        let recoverable = RecoverableStreamSnapshot::capture(
            &captured_stream,
            &cell,
            &cut_certificate(&cell),
            key_hierarchy_spec(),
            Time::from_secs(12),
        )
        .expect("recoverable stream capture");
        let mut counterfactual_config = captured_stream.config.clone();
        counterfactual_config.delivery_class = DeliveryClass::ForensicReplayable;

        let forked = recoverable
            .fork_with_config(test_region(91), counterfactual_config.clone())
            .expect("forked stream snapshot");

        assert_eq!(forked.region_id, test_region(91));
        assert_eq!(forked.config, counterfactual_config);
        assert_eq!(forked.storage, captured_stream.storage);
        assert_eq!(forked.state.msg_count, captured_stream.state.msg_count);
        assert_eq!(forked.state.first_seq, captured_stream.state.first_seq);
        assert_eq!(forked.state.last_seq, captured_stream.state.last_seq);
        assert_eq!(forked.consumer_ids, Vec::<u64>::new());
    }
