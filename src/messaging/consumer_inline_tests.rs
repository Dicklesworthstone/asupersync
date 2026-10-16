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

    fn partition_consumers(partition: u16) -> BTreeSet<String> {
        [
            format!("consumer-{partition}-a"),
            format!("consumer-{partition}-b"),
        ]
        .into_iter()
        .collect()
    }

    fn partition_assignment(
        partition: u16,
        selector: CursorPartitionSelector,
    ) -> CursorPartitionAssignment {
        CursorPartitionAssignment {
            partition,
            leader: CursorLeaseHolder::Steward(NodeId::new("node-a")),
            selector,
            consumers: partition_consumers(partition),
        }
    }

    fn delegate_partition_to_holder(
        cursor: &mut FabricConsumerCursor,
        partition: u16,
        holder: CursorLeaseHolder,
        transfer_obligation: ObligationId,
    ) -> ContestedTransferResolution {
        if cursor.partition_assignment(partition).is_none() {
            cursor
                .assign_partition(partition_assignment(
                    partition,
                    CursorPartitionSelector::ConsumerGroup(format!("group-{partition}")),
                ))
                .expect("assign partition");
        }

        cursor
            .resolve_contested_transfer(&[CursorTransferProposal::delegated_partition(
                holder,
                partition,
                cursor.current_lease().lease_generation,
                transfer_obligation,
            )])
            .expect("delegate partition")
    }

    #[test]
    fn cursor_lease_starts_from_the_control_capsule() {
        let cell = test_cell();
        let cursor = FabricConsumerCursor::new(&cell).expect("cursor");

        assert_eq!(cursor.current_lease().cell_id, cell.cell_id);
        assert_eq!(cursor.current_lease().epoch, cell.epoch);
        assert_eq!(
            cursor.current_lease().holder,
            CursorLeaseHolder::Steward(NodeId::new("node-a"))
        );
        assert_eq!(
            cursor.current_lease().lease_generation,
            cell.control_capsule.sequencer_lease_generation
        );
    }

    #[test]
    fn delivery_attempts_commit_against_the_current_lease_holder() {
        let cell = test_cell();
        let cursor = FabricConsumerCursor::new(&cell).expect("cursor");
        let window = SequenceWindow::new(10, 12).expect("window");
        let attempt = cursor
            .issue_attempt(CursorDeliveryMode::Push { window }, 1, obligation(10))
            .expect("attempt");
        let capsule = RecoverableCapsule::default().with_window(NodeId::new("node-a"), window);

        assert_eq!(
            cursor.plan_delivery(attempt.delivery_mode, &capsule, None),
            Ok(DeliveryPlan::CurrentSteward(NodeId::new("node-a")))
        );
        assert_eq!(
            cursor.acknowledge(&attempt),
            Ok(AckResolution::Committed {
                obligation_id: obligation(10),
                against: CursorLeaseHolder::Steward(NodeId::new("node-a")),
            })
        );
    }

    #[test]
    fn pull_demand_class_attempts_preserve_the_named_request() {
        let cell = test_cell();
        let cursor = FabricConsumerCursor::new(&cell).expect("cursor");
        let attempt = cursor
            .issue_attempt(
                CursorDeliveryMode::Pull(CursorRequest::DemandClass(ConsumerDemandClass::Tail)),
                2,
                obligation(11),
            )
            .expect("attempt");

        assert_eq!(
            attempt.delivery_mode,
            CursorDeliveryMode::Pull(CursorRequest::DemandClass(ConsumerDemandClass::Tail))
        );
        assert_eq!(
            cursor.plan_delivery(attempt.delivery_mode, &RecoverableCapsule::default(), None),
            Ok(DeliveryPlan::CurrentSteward(NodeId::new("node-a")))
        );
    }

    #[test]
    fn failover_bumps_generation_and_turns_old_acks_into_stale_noops() {
        let cell = test_cell();
        let mut cursor = FabricConsumerCursor::new(&cell).expect("cursor");
        let window = SequenceWindow::new(20, 20).expect("window");
        let first_attempt = cursor
            .issue_attempt(
                CursorDeliveryMode::Pull(CursorRequest::Window(window)),
                1,
                obligation(12),
            )
            .expect("attempt");

        cursor.failover(NodeId::new("node-b")).expect("failover");
        assert_eq!(
            cursor.acknowledge(&first_attempt),
            Ok(AckResolution::StaleNoOp {
                obligation_id: obligation(12),
                current_generation: cell.control_capsule.sequencer_lease_generation + 1,
                current_holder: CursorLeaseHolder::Steward(NodeId::new("node-b")),
            })
        );

        let second_attempt = cursor
            .issue_attempt(
                CursorDeliveryMode::Pull(CursorRequest::Sequence(20)),
                2,
                obligation(13),
            )
            .expect("attempt");
        assert_eq!(
            cursor.acknowledge(&second_attempt),
            Ok(AckResolution::Committed {
                obligation_id: obligation(13),
                against: CursorLeaseHolder::Steward(NodeId::new("node-b")),
            })
        );
    }

    #[test]
    fn relay_delivery_requires_a_matching_read_ticket() {
        let cell = test_cell();
        let mut cursor = FabricConsumerCursor::new(&cell).expect("cursor");
        let window = SequenceWindow::new(30, 35).expect("window");

        let resolution = delegate_partition_to_holder(
            &mut cursor,
            7,
            CursorLeaseHolder::Relay(NodeId::new("relay-1")),
            obligation(14),
        );
        assert!(matches!(
            resolution,
            ContestedTransferResolution::Accepted { .. }
        ));

        let ticket = cursor
            .grant_read_ticket(
                NodeId::new("relay-1"),
                window,
                4,
                CacheabilityRule::Private { max_age_ticks: 2 },
            )
            .expect("ticket");
        let capsule = RecoverableCapsule::default().with_window(NodeId::new("relay-1"), window);

        assert_eq!(
            ticket.cursor_lease_ref.lease_generation,
            cursor.current_lease().lease_generation
        );
        assert_eq!(ticket.segment_window, window);
        assert_eq!(
            ticket.cacheability_rules,
            CacheabilityRule::Private { max_age_ticks: 2 }
        );
        assert_eq!(ticket.expiry.issued_at_tick, 0);
        assert_eq!(ticket.expiry.not_after_tick, 4);

        assert_eq!(
            cursor.plan_delivery(CursorDeliveryMode::Push { window }, &capsule, Some(&ticket)),
            Ok(DeliveryPlan::LeasedRelay {
                relay: NodeId::new("relay-1"),
                ticket,
            })
        );
    }

    #[test]
    fn relay_delivery_rejects_missing_ticket_when_authority_is_delegated() {
        let cell = test_cell();
        let mut cursor = FabricConsumerCursor::new(&cell).expect("cursor");
        let window = SequenceWindow::new(36, 38).expect("window");
        let relay = NodeId::new("relay-2");

        delegate_partition_to_holder(
            &mut cursor,
            8,
            CursorLeaseHolder::Relay(relay.clone()),
            obligation(15),
        );

        let capsule = RecoverableCapsule::default().with_window(relay.clone(), window);

        assert_eq!(
            cursor.plan_delivery(CursorDeliveryMode::Push { window }, &capsule, None),
            Err(ConsumerCursorError::MissingReadDelegationTicket { relay })
        );
    }

    #[test]
    fn read_delegation_ticket_expiry_is_enforced() {
        let cell = test_cell();
        let mut cursor = FabricConsumerCursor::new(&cell).expect("cursor");
        let window = SequenceWindow::new(46, 49).expect("window");
        let relay = NodeId::new("relay-expiring");

        delegate_partition_to_holder(
            &mut cursor,
            9,
            CursorLeaseHolder::Relay(relay.clone()),
            obligation(16),
        );

        let ticket = cursor
            .grant_read_ticket(relay.clone(), window, 1, CacheabilityRule::NoCache)
            .expect("ticket");
        cursor.advance_ticket_clock(2);

        let capsule = RecoverableCapsule::default().with_window(relay.clone(), window);

        assert_eq!(
            cursor.plan_delivery(CursorDeliveryMode::Push { window }, &capsule, Some(&ticket)),
            Err(ConsumerCursorError::ExpiredReadDelegationTicket {
                relay,
                expired_at_tick: 1,
                current_tick: 2,
            })
        );
    }

    #[test]
    fn read_delegation_ticket_revocation_is_enforced() {
        let cell = test_cell();
        let mut cursor = FabricConsumerCursor::new(&cell).expect("cursor");
        let window = SequenceWindow::new(50, 52).expect("window");
        let relay = NodeId::new("relay-revoked");

        delegate_partition_to_holder(
            &mut cursor,
            10,
            CursorLeaseHolder::Relay(relay.clone()),
            obligation(17),
        );

        let ticket = cursor
            .grant_read_ticket(
                relay.clone(),
                window,
                5,
                CacheabilityRule::Shared { max_age_ticks: 1 },
            )
            .expect("ticket");
        cursor.revoke_read_ticket(ticket.revocation_handle, ticket.expiry.not_after_tick);

        let capsule = RecoverableCapsule::default().with_window(relay.clone(), window);

        assert_eq!(
            cursor.plan_delivery(CursorDeliveryMode::Push { window }, &capsule, Some(&ticket)),
            Err(ConsumerCursorError::RevokedReadDelegationTicket {
                relay,
                revocation_handle: ticket.revocation_handle,
            })
        );
    }

    #[test]
    fn prune_expired_revocations_removes_stale_entries() {
        let cell = test_cell();
        let mut cursor = FabricConsumerCursor::new(&cell).expect("cursor");
        let window = SequenceWindow::new(50, 55).expect("window");
        let relay = NodeId::new("relay-prune");

        delegate_partition_to_holder(
            &mut cursor,
            10,
            CursorLeaseHolder::Relay(relay.clone()),
            obligation(30),
        );

        let ticket = cursor
            .grant_read_ticket(
                relay,
                window,
                5, // TTL = 5 ticks
                CacheabilityRule::Private { max_age_ticks: 1 },
            )
            .expect("ticket");

        // Revoke the ticket (not_after_tick = issued_at + 5 = 0 + 5 = 5).
        cursor.revoke_read_ticket(ticket.revocation_handle, ticket.expiry.not_after_tick);
        assert_eq!(cursor.revoked_tickets.len(), 1);

        // Advance clock past the ticket's expiry.
        cursor.ticket_clock = 6;
        cursor.prune_expired_revocations();

        // The revocation entry should be pruned since the ticket has expired.
        assert_eq!(
            cursor.revoked_tickets.len(),
            0,
            "expired revocation entries must be pruned"
        );
    }

    #[test]
    fn stale_epoch_read_delegation_ticket_is_rejected() {
        let cell = test_cell();
        let mut cursor = FabricConsumerCursor::new(&cell).expect("cursor");
        let window = SequenceWindow::new(60, 63).expect("window");
        let relay = NodeId::new("relay-stale");

        delegate_partition_to_holder(
            &mut cursor,
            11,
            CursorLeaseHolder::Relay(relay.clone()),
            obligation(18),
        );

        let mut ticket = cursor
            .grant_read_ticket(relay.clone(), window, 5, CacheabilityRule::NoCache)
            .expect("ticket");
        ticket.epoch = CellEpoch::new(6, 99);

        let capsule = RecoverableCapsule::default().with_window(relay.clone(), window);

        assert_eq!(
            cursor.plan_delivery(CursorDeliveryMode::Push { window }, &capsule, Some(&ticket)),
            Err(ConsumerCursorError::StaleReadDelegationEpoch {
                relay,
                ticket_cell: cell.cell_id,
                ticket_epoch: CellEpoch::new(6, 99),
                current_cell: cell.cell_id,
                current_epoch: cell.epoch,
            })
        );
    }

    #[test]
    fn partition_assignments_preserve_selector_strategies_and_consumers() {
        let cell = test_cell();
        let mut cursor = FabricConsumerCursor::new(&cell).expect("cursor");
        let by_group = partition_assignment(
            20,
            CursorPartitionSelector::ConsumerGroup("orders-tail".to_owned()),
        );
        let by_range = partition_assignment(
            21,
            CursorPartitionSelector::SubjectSubRange {
                start: "orders.a".to_owned(),
                end: "orders.m".to_owned(),
            },
        );
        let by_bucket = partition_assignment(
            22,
            CursorPartitionSelector::HashBucket {
                bucket: 1,
                buckets: 4,
            },
        );

        cursor
            .assign_partition(by_group.clone())
            .expect("assign group partition");
        cursor
            .assign_partition(by_range.clone())
            .expect("assign range partition");
        cursor
            .assign_partition(by_bucket.clone())
            .expect("assign bucket partition");

        assert_eq!(cursor.partition_assignment(20), Some(&by_group));
        assert_eq!(cursor.partition_assignment(21), Some(&by_range));
        assert_eq!(cursor.partition_assignment(22), Some(&by_bucket));
        assert_eq!(
            cursor
                .partition_assignment(21)
                .map(|entry| entry.consumers.len()),
            Some(2)
        );
    }

    #[test]
    fn delegated_attempts_expose_partition_lease_metadata() {
        let cell = test_cell();
        let mut cursor = FabricConsumerCursor::new(&cell).expect("cursor");
        let relay = NodeId::new("relay-partition");

        let resolution = delegate_partition_to_holder(
            &mut cursor,
            23,
            CursorLeaseHolder::Relay(relay.clone()),
            obligation(181),
        );
        assert!(matches!(
            resolution,
            ContestedTransferResolution::Accepted { .. }
        ));

        let attempt = cursor
            .issue_attempt(
                CursorDeliveryMode::Push {
                    window: SequenceWindow::new(64, 66).expect("window"),
                },
                1,
                obligation(182),
            )
            .expect("attempt");

        assert_eq!(
            attempt.cursor_partition_lease(),
            Some(CursorPartitionLease {
                partition: 23,
                leader: CursorLeaseHolder::Relay(relay),
                lease_generation: cursor.current_lease().lease_generation,
            })
        );
    }

    #[test]
    fn relay_transfer_requires_partition_scope_and_registered_partition() {
        let cell = test_cell();
        let mut cursor = FabricConsumerCursor::new(&cell).expect("cursor");
        let relay = NodeId::new("relay-invalid");
        let generation = cursor.current_lease().lease_generation;

        assert_eq!(
            cursor.resolve_contested_transfer(&[CursorTransferProposal::control_capsule(
                CursorLeaseHolder::Relay(relay.clone()),
                generation,
                obligation(183),
            )]),
            Err(ConsumerCursorError::RelayTransferRequiresPartition {
                relay: relay.clone()
            })
        );
        assert_eq!(
            cursor.resolve_contested_transfer(&[CursorTransferProposal::delegated_partition(
                CursorLeaseHolder::Relay(relay),
                99,
                generation,
                obligation(184),
            )]),
            Err(ConsumerCursorError::UnknownCursorPartition { partition: 99 })
        );
    }

    #[test]
    fn partition_checkpoint_reporting_records_summary_for_active_partition() {
        let cell = test_cell();
        let mut cursor = FabricConsumerCursor::new(&cell).expect("cursor");
        let relay = NodeId::new("relay-summary");

        delegate_partition_to_holder(
            &mut cursor,
            24,
            CursorLeaseHolder::Relay(relay.clone()),
            obligation(185),
        );

        let summary = cursor
            .report_partition_checkpoint(CursorPartitionCheckpoint {
                partition: 24,
                lease_generation: cursor.current_lease().lease_generation,
                ack_floor: 120,
                delivered_through: 127,
                pending_count: 3,
                consumer_count: 2,
            })
            .expect("checkpoint")
            .clone();

        assert_eq!(
            summary,
            CursorPartitionSummary {
                partition: 24,
                selector: CursorPartitionSelector::ConsumerGroup("group-24".to_owned()),
                leader: CursorLeaseHolder::Relay(relay),
                lease_generation: cursor.current_lease().lease_generation,
                ack_floor: 120,
                delivered_through: 127,
                pending_count: 3,
                consumer_count: 2,
            }
        );
        assert_eq!(cursor.partition_summary(24), Some(&summary));
    }

    #[test]
    fn partition_checkpoint_reporting_requires_matching_scope_and_generation() {
        let cell = test_cell();
        let mut cursor = FabricConsumerCursor::new(&cell).expect("cursor");

        assert_eq!(
            cursor.report_partition_checkpoint(CursorPartitionCheckpoint {
                partition: 25,
                lease_generation: cursor.current_lease().lease_generation,
                ack_floor: 0,
                delivered_through: 0,
                pending_count: 0,
                consumer_count: 2,
            }),
            Err(
                ConsumerCursorError::PartitionCheckpointRequiresDelegatedLease {
                    partition: 25,
                    current_scope: CursorLeaseScope::ControlCapsule,
                }
            )
        );

        let relay = NodeId::new("relay-fenced");
        delegate_partition_to_holder(
            &mut cursor,
            25,
            CursorLeaseHolder::Relay(relay),
            obligation(186),
        );

        let current_generation = cursor.current_lease().lease_generation;
        assert_eq!(
            cursor.report_partition_checkpoint(CursorPartitionCheckpoint {
                partition: 25,
                lease_generation: current_generation.saturating_sub(1),
                ack_floor: 0,
                delivered_through: 0,
                pending_count: 0,
                consumer_count: 2,
            }),
            Err(ConsumerCursorError::StaleCursorPartitionCheckpoint {
                partition: 25,
                report_generation: current_generation.saturating_sub(1),
                current_generation,
            })
        );
        assert_eq!(
            cursor.report_partition_checkpoint(CursorPartitionCheckpoint {
                partition: 25,
                lease_generation: current_generation,
                ack_floor: 0,
                delivered_through: 0,
                pending_count: 0,
                consumer_count: 1,
            }),
            Err(
                ConsumerCursorError::PartitionCheckpointConsumerCountMismatch {
                    partition: 25,
                    reported_consumer_count: 1,
                    assigned_consumer_count: 2,
                }
            )
        );
    }

    #[test]
    fn replacing_partition_assignment_invalidates_stale_summary() {
        let cell = test_cell();
        let mut cursor = FabricConsumerCursor::new(&cell).expect("cursor");

        delegate_partition_to_holder(
            &mut cursor,
            26,
            CursorLeaseHolder::Relay(NodeId::new("relay-a")),
            obligation(187),
        );
        cursor
            .report_partition_checkpoint(CursorPartitionCheckpoint {
                partition: 26,
                lease_generation: cursor.current_lease().lease_generation,
                ack_floor: 200,
                delivered_through: 208,
                pending_count: 4,
                consumer_count: 2,
            })
            .expect("checkpoint");
        assert!(cursor.partition_summary(26).is_some());

        cursor
            .assign_partition(partition_assignment(
                26,
                CursorPartitionSelector::SubjectSubRange {
                    start: "orders.n".to_owned(),
                    end: "orders.z".to_owned(),
                },
            ))
            .expect("replace assignment");

        assert_eq!(
            cursor
                .partition_assignment(26)
                .map(|assignment| &assignment.selector),
            Some(&CursorPartitionSelector::SubjectSubRange {
                start: "orders.n".to_owned(),
                end: "orders.z".to_owned(),
            })
        );
        assert_eq!(cursor.partition_summary(26), None);
    }

    #[test]
    fn partition_rebalance_updates_assignment_and_invalidates_stale_summary() {
        let cell = test_cell();
        let mut cursor = FabricConsumerCursor::new(&cell).expect("cursor");
        let relay_a = NodeId::new("relay-a");
        let relay_b = NodeId::new("relay-b");

        delegate_partition_to_holder(
            &mut cursor,
            26,
            CursorLeaseHolder::Relay(relay_a),
            obligation(187),
        );
        cursor
            .report_partition_checkpoint(CursorPartitionCheckpoint {
                partition: 26,
                lease_generation: cursor.current_lease().lease_generation,
                ack_floor: 200,
                delivered_through: 208,
                pending_count: 4,
                consumer_count: 2,
            })
            .expect("checkpoint");

        let stale_generation = cursor.current_lease().lease_generation.saturating_sub(1);
        assert_eq!(
            cursor
                .rebalance_partition(
                    26,
                    CursorLeaseHolder::Relay(relay_b.clone()),
                    stale_generation,
                    obligation(188),
                )
                .expect("stale rebalance result"),
            ContestedTransferResolution::StaleNoOp {
                current_lease: cursor.current_lease().clone(),
            }
        );

        let accepted = cursor
            .rebalance_partition(
                26,
                CursorLeaseHolder::Relay(relay_b.clone()),
                cursor.current_lease().lease_generation,
                obligation(189),
            )
            .expect("rebalance");
        assert!(matches!(
            accepted,
            ContestedTransferResolution::Accepted { .. }
        ));
        assert_eq!(
            cursor
                .partition_assignment(26)
                .map(|assignment| &assignment.leader),
            Some(&CursorLeaseHolder::Relay(relay_b.clone()))
        );
        assert_eq!(cursor.partition_summary(26), None);
        let checkpoint = cursor
            .report_partition_checkpoint(CursorPartitionCheckpoint {
                partition: 26,
                lease_generation: cursor.current_lease().lease_generation,
                ack_floor: 209,
                delivered_through: 214,
                pending_count: 1,
                consumer_count: 2,
            })
            .expect("post-rebalance checkpoint");
        assert_eq!(checkpoint.leader, CursorLeaseHolder::Relay(relay_b));
    }

    #[test]
    fn reconstruction_is_used_when_no_single_peer_covers_the_full_window() {
        let cell = test_cell();
        let mut cursor = FabricConsumerCursor::new(&cell).expect("cursor");
        let window = SequenceWindow::new(40, 45).expect("window");

        cursor
            .failover(NodeId::new("node-b"))
            .expect("make node-b current");

        let capsule = RecoverableCapsule::default()
            .with_window(
                NodeId::new("node-a"),
                SequenceWindow::new(40, 42).expect("left window"),
            )
            .with_window(
                NodeId::new("node-c"),
                SequenceWindow::new(43, 45).expect("right window"),
            );

        assert_eq!(
            cursor.plan_delivery(
                CursorDeliveryMode::Pull(CursorRequest::Window(window)),
                &capsule,
                None
            ),
            Ok(DeliveryPlan::Reconstructed {
                contributors: vec![NodeId::new("node-a"), NodeId::new("node-c")],
            })
        );
    }

    #[test]
    fn contested_transfer_prefers_steward_order_and_filters_stale_proposals() {
        let cell = test_cell();
        let mut cursor = FabricConsumerCursor::new(&cell).expect("cursor");
        let current_generation = cursor.current_lease().lease_generation;

        let resolution = cursor
            .resolve_contested_transfer(&[
                CursorTransferProposal::control_capsule(
                    CursorLeaseHolder::Steward(NodeId::new("node-c")),
                    current_generation,
                    obligation(20),
                ),
                CursorTransferProposal::control_capsule(
                    CursorLeaseHolder::Steward(NodeId::new("node-b")),
                    current_generation,
                    obligation(21),
                ),
                CursorTransferProposal::delegated_partition(
                    CursorLeaseHolder::Relay(NodeId::new("relay-2")),
                    27,
                    current_generation.saturating_sub(1),
                    obligation(22),
                ),
            ])
            .expect("resolve contested transfer");

        assert_eq!(
            resolution,
            ContestedTransferResolution::Accepted {
                new_lease: cursor.current_lease().clone(),
                winning_obligation: obligation(21),
            }
        );
        assert_eq!(
            cursor.current_lease().holder,
            CursorLeaseHolder::Steward(NodeId::new("node-b"))
        );
        assert_eq!(
            cursor.current_lease().lease_generation,
            current_generation + 1
        );
    }

    #[test]
    fn fabric_consumer_creation_preserves_config_and_starts_clean() {
        let cell = test_cell();
        let config = FabricConsumerConfig {
            durable_name: Some("orders-durable".to_owned()),
            filter_subject: Some(SubjectPattern::parse("orders.*").expect("pattern")),
            flow_control: true,
            heartbeat: Some(std::time::Duration::from_secs(5)),
            idle_heartbeat: Some(std::time::Duration::from_secs(15)),
            ..FabricConsumerConfig::default()
        };

        let consumer = FabricConsumer::new(&cell, config.clone()).expect("consumer");
        assert_eq!(consumer.config(), &config);
        assert_eq!(consumer.policy().mode, ConsumerDispatchMode::Push);
        assert!(!consumer.policy().paused);
        assert_eq!(consumer.state().delivered_count, 0);
        assert_eq!(consumer.state().pending_count, 0);
        assert_eq!(consumer.state().ack_floor, 0);
        assert_eq!(consumer.waiting_pull_request_count(), 0);
        assert_eq!(
            consumer.current_lease().holder,
            CursorLeaseHolder::Steward(NodeId::new("node-a"))
        );
    }

    #[test]
    fn fabric_consumer_config_rejects_zero_heartbeat_values() {
        let heartbeat = FabricConsumerConfig {
            heartbeat: Some(Duration::ZERO),
            ..FabricConsumerConfig::default()
        };
        assert_eq!(
            heartbeat.validate(),
            Err(FabricConsumerError::InvalidHeartbeat { field: "heartbeat" })
        );

        let idle_heartbeat = FabricConsumerConfig {
            idle_heartbeat: Some(Duration::ZERO),
            ..FabricConsumerConfig::default()
        };
        assert_eq!(
            idle_heartbeat.validate(),
            Err(FabricConsumerError::InvalidHeartbeat {
                field: "idle_heartbeat",
            })
        );
    }

    #[test]
    fn fabric_consumer_mode_switching_clears_waiting_pull_requests() {
        let cell = test_cell();
        let mut consumer =
            FabricConsumer::new(&cell, FabricConsumerConfig::default()).expect("consumer");

        consumer.switch_mode(ConsumerDispatchMode::Pull);
        consumer
            .queue_pull_request(
                PullRequest::new(2, ConsumerDemandClass::CatchUp).expect("pull request"),
            )
            .expect("queue pull request");
        assert_eq!(consumer.waiting_pull_request_count(), 1);

        consumer.switch_mode(ConsumerDispatchMode::Push);
        assert_eq!(consumer.policy().mode, ConsumerDispatchMode::Push);
        assert_eq!(consumer.waiting_pull_request_count(), 0);
    }

    #[test]
    fn fabric_consumer_pull_queue_respects_max_waiting() {
        let cell = test_cell();
        let mut consumer = FabricConsumer::new(
            &cell,
            FabricConsumerConfig {
                max_waiting: 1,
                ..FabricConsumerConfig::default()
            },
        )
        .expect("consumer");

        consumer.switch_mode(ConsumerDispatchMode::Pull);
        consumer
            .queue_pull_request(
                PullRequest::new(1, ConsumerDemandClass::CatchUp).expect("first request"),
            )
            .expect("queue first");

        assert_eq!(
            consumer.queue_pull_request(
                PullRequest::new(1, ConsumerDemandClass::Tail).expect("second request")
            ),
            Err(FabricConsumerError::MaxWaitingExceeded { limit: 1 })
        );
    }

    #[test]
    fn fabric_consumer_stable_kernel_replaces_priority_overflow_without_audit_log() {
        let cell = test_cell();
        let mut consumer = FabricConsumer::new(
            &cell,
            FabricConsumerConfig {
                max_waiting: 1,
                overflow_policy: ConsumerOverflowPolicy::ReplaceLowestPriority,
                ..FabricConsumerConfig::default()
            },
        )
        .expect("consumer");

        consumer.switch_mode(ConsumerDispatchMode::Pull);
        consumer
            .queue_pull_request(PullRequest::new(1, ConsumerDemandClass::Replay).expect("replay"))
            .expect("queue replay");

        consumer
            .queue_pull_request(PullRequest::new(1, ConsumerDemandClass::Tail).expect("tail"))
            .expect("replace replay with tail");

        let capsule = RecoverableCapsule::default().with_window(
            NodeId::new("node-a"),
            SequenceWindow::new(1, 20).expect("window"),
        );
        let delivery = match consumer
            .dispatch_next_pull(20, &capsule, None)
            .expect("dispatch tail")
        {
            PullDispatchOutcome::Scheduled(delivery) => *delivery,
            PullDispatchOutcome::Waiting(_) => panic!("tail request should dispatch"),
        };

        assert!(matches!(
            delivery.request,
            ScheduledConsumerRequest::Pull(PullRequest {
                demand_class: ConsumerDemandClass::Tail,
                ..
            })
        ));
        assert!(consumer.decision_log().is_empty());
    }

    #[test]
    fn fabric_consumer_priority_groups_dispatch_tail_before_replay() {
        let cell = test_cell();
        let mut consumer =
            FabricConsumer::new(&cell, FabricConsumerConfig::default()).expect("consumer");
        let capsule = RecoverableCapsule::default().with_window(
            NodeId::new("node-a"),
            SequenceWindow::new(1, 20).expect("window"),
        );

        consumer.switch_mode(ConsumerDispatchMode::Pull);
        consumer
            .queue_pull_request(PullRequest::new(2, ConsumerDemandClass::Replay).expect("replay"))
            .expect("queue replay");
        consumer
            .queue_pull_request(PullRequest::new(2, ConsumerDemandClass::Tail).expect("tail"))
            .expect("queue tail");

        let first = match consumer
            .dispatch_next_pull(20, &capsule, None)
            .expect("dispatch first")
        {
            PullDispatchOutcome::Scheduled(delivery) => *delivery,
            PullDispatchOutcome::Waiting(_) => panic!("tail request should schedule first"),
        };
        assert!(matches!(
            &first.request,
            ScheduledConsumerRequest::Pull(request)
                if request.demand_class == ConsumerDemandClass::Tail
        ));
        assert_eq!(
            first.window,
            SequenceWindow::new(19, 20).expect("tail window")
        );

        let second = match consumer
            .dispatch_next_pull(20, &capsule, None)
            .expect("dispatch second")
        {
            PullDispatchOutcome::Scheduled(delivery) => *delivery,
            PullDispatchOutcome::Waiting(_) => panic!("replay request should schedule second"),
        };
        assert!(matches!(
            &second.request,
            ScheduledConsumerRequest::Pull(request)
                if request.demand_class == ConsumerDemandClass::Replay
        ));
        assert_eq!(
            second.window,
            SequenceWindow::new(1, 2).expect("replay window")
        );
    }

    #[test]
    fn fabric_consumer_replay_clamps_by_start_sequence_to_earliest_retained_window() {
        let cell = test_cell();
        let mut consumer = FabricConsumer::new(
            &cell,
            FabricConsumerConfig {
                deliver_policy: DeliverPolicy::ByStartSequence(2),
                ..FabricConsumerConfig::default()
            },
        )
        .expect("consumer");
        let capsule = RecoverableCapsule::default().with_window(
            NodeId::new("node-a"),
            SequenceWindow::new(10, 12).expect("window"),
        );

        consumer.switch_mode(ConsumerDispatchMode::Pull);
        consumer
            .queue_pull_request(PullRequest::new(2, ConsumerDemandClass::Replay).expect("replay"))
            .expect("queue replay");

        let delivery = match consumer
            .dispatch_next_pull(12, &capsule, None)
            .expect("dispatch replay")
        {
            PullDispatchOutcome::Scheduled(delivery) => *delivery,
            PullDispatchOutcome::Waiting(_) => panic!("replay request should schedule"),
        };

        assert_eq!(
            delivery.window,
            SequenceWindow::new(10, 11).expect("clamped replay window")
        );
    }

    #[test]
    fn fabric_consumer_replay_by_start_time_uses_earliest_retained_window() {
        let cell = test_cell();
        let mut consumer = FabricConsumer::new(
            &cell,
            FabricConsumerConfig {
                deliver_policy: DeliverPolicy::ByStartTime(std::time::UNIX_EPOCH),
                ..FabricConsumerConfig::default()
            },
        )
        .expect("consumer");
        let capsule = RecoverableCapsule::default().with_window(
            NodeId::new("node-a"),
            SequenceWindow::new(10, 12).expect("window"),
        );

        consumer.switch_mode(ConsumerDispatchMode::Pull);
        consumer
            .queue_pull_request(PullRequest::new(2, ConsumerDemandClass::Replay).expect("replay"))
            .expect("queue replay");

        let delivery = match consumer
            .dispatch_next_pull(12, &capsule, None)
            .expect("dispatch replay")
        {
            PullDispatchOutcome::Scheduled(delivery) => *delivery,
            PullDispatchOutcome::Waiting(_) => panic!("replay request should schedule"),
        };

        assert_eq!(
            delivery.window,
            SequenceWindow::new(10, 11).expect("time-anchored replay window")
        );
    }

    #[test]
    fn fabric_consumer_audit_backed_overflow_replaces_replay_with_tail_and_records_evidence() {
        let cell = test_cell();
        let mut consumer = FabricConsumer::new(
            &cell,
            FabricConsumerConfig {
                max_waiting: 1,
                adaptive_kernel: AdaptiveConsumerKernel::AuditBacked,
                overflow_policy: ConsumerOverflowPolicy::ReplaceLowestPriority,
                ..FabricConsumerConfig::default()
            },
        )
        .expect("consumer");

        consumer.switch_mode(ConsumerDispatchMode::Pull);
        consumer
            .queue_pull_request(PullRequest::new(1, ConsumerDemandClass::Replay).expect("replay"))
            .expect("queue replay");
        consumer
            .queue_pull_request(PullRequest::new(1, ConsumerDemandClass::Tail).expect("tail"))
            .expect("queue tail replacement");

        assert_eq!(consumer.waiting_pull_request_count(), 1);
        assert_eq!(consumer.decision_log().len(), 1);
        let overflow = &consumer.decision_log()[0];
        assert_eq!(overflow.kind, ConsumerDecisionKind::Overflow);
        assert_eq!(overflow.action_name, "replace_low_priority");
        assert_eq!(overflow.demand_class, Some(ConsumerDemandClass::Tail));
    }

    #[test]
    fn fabric_consumer_pull_dispatches_audited_pinned_client_leased_delivery() {
        let cell = test_cell();
        let mut consumer = FabricConsumer::new(
            &cell,
            FabricConsumerConfig {
                adaptive_kernel: AdaptiveConsumerKernel::AuditBacked,
                ..FabricConsumerConfig::default()
            },
        )
        .expect("consumer");
        let relay = NodeId::new("relay-1");
        let window = SequenceWindow::new(1, 2).expect("window");
        let capsule = RecoverableCapsule::default().with_window(relay.clone(), window);

        let transfer = delegate_partition_to_holder(
            &mut consumer.cursor,
            28,
            CursorLeaseHolder::Relay(relay.clone()),
            ObligationId::new_for_test(88, 0),
        );
        assert!(matches!(
            transfer,
            ContestedTransferResolution::Accepted { .. }
        ));

        let ticket = consumer
            .cursor
            .grant_read_ticket(
                relay.clone(),
                window,
                8,
                CacheabilityRule::Private { max_age_ticks: 4 },
            )
            .expect("ticket");

        consumer.switch_mode(ConsumerDispatchMode::Pull);
        consumer
            .queue_pull_request(
                PullRequest::new(2, ConsumerDemandClass::CatchUp)
                    .expect("pull request")
                    .with_pinned_client(relay.clone()),
            )
            .expect("queue pull");

        let delivery = match consumer
            .dispatch_next_pull(2, &capsule, Some(&ticket))
            .expect("dispatch pinned")
        {
            PullDispatchOutcome::Scheduled(delivery) => *delivery,
            PullDispatchOutcome::Waiting(_) => panic!("pinned request should schedule"),
        };
        assert!(matches!(
            &delivery.plan,
            DeliveryPlan::LeasedRelay { relay: chosen, .. } if chosen == &relay
        ));
        let decision = consumer.decision_log().last().expect("decision record");
        assert_eq!(decision.kind, ConsumerDecisionKind::PullScheduling);
        assert_eq!(decision.action_name, "leased_relay");
        assert_eq!(decision.pinned_client.as_ref(), Some(&relay));
        assert_eq!(decision.obligation_id, Some(delivery.attempt.obligation_id));
    }

    #[test]
    fn fabric_consumer_rejects_pinned_client_ticket_mismatch() {
        let cell = test_cell();
        let mut consumer = FabricConsumer::new(
            &cell,
            FabricConsumerConfig {
                adaptive_kernel: AdaptiveConsumerKernel::AuditBacked,
                ..FabricConsumerConfig::default()
            },
        )
        .expect("consumer");
        let pinned = NodeId::new("relay-pinned");
        let wrong_relay = NodeId::new("relay-wrong");
        let window = SequenceWindow::new(1, 1).expect("window");
        let capsule = RecoverableCapsule::default().with_window(wrong_relay.clone(), window);

        let transfer = delegate_partition_to_holder(
            &mut consumer.cursor,
            29,
            CursorLeaseHolder::Relay(wrong_relay.clone()),
            ObligationId::new_for_test(89, 0),
        );
        assert!(matches!(
            transfer,
            ContestedTransferResolution::Accepted { .. }
        ));

        let wrong_ticket = consumer
            .cursor
            .grant_read_ticket(
                wrong_relay.clone(),
                window,
                8,
                CacheabilityRule::Private { max_age_ticks: 4 },
            )
            .expect("ticket");

        consumer.switch_mode(ConsumerDispatchMode::Pull);
        consumer
            .queue_pull_request(
                PullRequest::new(1, ConsumerDemandClass::CatchUp)
                    .expect("pull request")
                    .with_pinned_client(pinned.clone()),
            )
            .expect("queue pull");

        assert_eq!(
            consumer.dispatch_next_pull(1, &capsule, Some(&wrong_ticket)),
            Err(FabricConsumerError::PinnedClientTicketMismatch {
                pinned_client: pinned,
                ticket_relay: wrong_relay,
            })
        );
        assert_eq!(consumer.waiting_pull_request_count(), 1);
    }

    #[test]
    fn fabric_consumer_keeps_pull_request_queued_when_dispatch_is_paused() {
        let cell = test_cell();
        let mut consumer = FabricConsumer::new(
            &cell,
            FabricConsumerConfig {
                flow_control: true,
                ..FabricConsumerConfig::default()
            },
        )
        .expect("consumer");
        let capsule = RecoverableCapsule::default().with_window(
            NodeId::new("node-a"),
            SequenceWindow::new(1, 4).expect("window"),
        );

        consumer.switch_mode(ConsumerDispatchMode::Pull);
        consumer
            .queue_pull_request(PullRequest::new(2, ConsumerDemandClass::CatchUp).expect("pull"))
            .expect("queue pull");
        consumer.pause().expect("pause");

        assert_eq!(
            consumer.dispatch_next_pull(4, &capsule, None),
            Err(FabricConsumerError::ConsumerPaused)
        );
        assert_eq!(consumer.waiting_pull_request_count(), 1);
    }

    #[test]
    fn fabric_consumer_pull_dispatches_catchup_then_tail_windows() {
        let cell = test_cell();
        let mut consumer =
            FabricConsumer::new(&cell, FabricConsumerConfig::default()).expect("consumer");
        let capsule = RecoverableCapsule::default().with_window(
            NodeId::new("node-a"),
            SequenceWindow::new(1, 12).expect("window"),
        );

        consumer.switch_mode(ConsumerDispatchMode::Pull);
        consumer
            .queue_pull_request(
                PullRequest::new(3, ConsumerDemandClass::CatchUp).expect("catchup request"),
            )
            .expect("queue catchup");

        let first_outcome = consumer
            .dispatch_next_pull(12, &capsule, None)
            .expect("dispatch catchup");
        let first = if let PullDispatchOutcome::Scheduled(delivery) = first_outcome {
            *delivery
        } else {
            assert!(false, "catchup request should schedule");
            return;
        };
        assert_eq!(first.window, SequenceWindow::new(1, 3).expect("window"));
        assert_eq!(consumer.state().pending_count, 3);
        assert_eq!(
            consumer.acknowledge_delivery(&first.attempt),
            Ok(AckResolution::Committed {
                obligation_id: first.attempt.obligation_id,
                against: CursorLeaseHolder::Steward(NodeId::new("node-a")),
            })
        );
        assert_eq!(consumer.state().pending_count, 0);
        assert_eq!(consumer.state().ack_floor, 3);

        consumer
            .queue_pull_request(PullRequest::new(2, ConsumerDemandClass::Tail).expect("tail"))
            .expect("queue tail");
        let tail_outcome = consumer
            .dispatch_next_pull(12, &capsule, None)
            .expect("dispatch tail");
        let tail = if let PullDispatchOutcome::Scheduled(delivery) = tail_outcome {
            *delivery
        } else {
            assert!(false, "tail request should schedule");
            return;
        };
        assert_eq!(tail.window, SequenceWindow::new(11, 12).expect("window"));
    }

    #[test]
    fn fabric_consumer_tail_waits_when_fully_caught_up() {
        let cell = test_cell();
        let mut consumer =
            FabricConsumer::new(&cell, FabricConsumerConfig::default()).expect("consumer");
        let capsule = RecoverableCapsule::default().with_window(
            NodeId::new("node-a"),
            SequenceWindow::new(1, 10).expect("window"),
        );

        consumer.switch_mode(ConsumerDispatchMode::Pull);
        consumer
            .queue_pull_request(PullRequest::new(10, ConsumerDemandClass::CatchUp).expect("req"))
            .expect("queue catchup");
        let catchup = match consumer
            .dispatch_next_pull(10, &capsule, None)
            .expect("dispatch")
        {
            PullDispatchOutcome::Scheduled(delivery) => *delivery,
            PullDispatchOutcome::Waiting(_) => panic!("catchup request should schedule"),
        };
        consumer
            .acknowledge_delivery(&catchup.attempt)
            .expect("ack catchup");
        assert_eq!(consumer.state().ack_floor, 10);

        consumer
            .queue_pull_request(PullRequest::new(2, ConsumerDemandClass::Tail).expect("tail"))
            .expect("queue tail");
        let outcome = consumer
            .dispatch_next_pull(10, &capsule, None)
            .expect("tail should wait for fresh data");
        assert!(matches!(outcome, PullDispatchOutcome::Waiting(_)));
        assert_eq!(consumer.waiting_pull_request_count(), 1);
    }

    #[test]
    fn fabric_consumer_tail_clamps_to_unacked_suffix() {
        let cell = test_cell();
        let mut consumer =
            FabricConsumer::new(&cell, FabricConsumerConfig::default()).expect("consumer");
        let capsule = RecoverableCapsule::default().with_window(
            NodeId::new("node-a"),
            SequenceWindow::new(1, 10).expect("window"),
        );

        consumer.switch_mode(ConsumerDispatchMode::Pull);
        consumer
            .queue_pull_request(PullRequest::new(9, ConsumerDemandClass::CatchUp).expect("req"))
            .expect("queue catchup");
        let catchup = match consumer
            .dispatch_next_pull(10, &capsule, None)
            .expect("dispatch")
        {
            PullDispatchOutcome::Scheduled(delivery) => *delivery,
            PullDispatchOutcome::Waiting(_) => panic!("catchup request should schedule"),
        };
        consumer
            .acknowledge_delivery(&catchup.attempt)
            .expect("ack catchup");
        assert_eq!(consumer.state().ack_floor, 9);

        consumer
            .queue_pull_request(PullRequest::new(3, ConsumerDemandClass::Tail).expect("tail"))
            .expect("queue tail");
        let tail = match consumer
            .dispatch_next_pull(10, &capsule, None)
            .expect("dispatch tail")
        {
            PullDispatchOutcome::Scheduled(delivery) => *delivery,
            PullDispatchOutcome::Waiting(_) => panic!("tail should schedule newest unacked suffix"),
        };
        assert_eq!(tail.window, SequenceWindow::new(10, 10).expect("suffix"));
    }

    #[test]
    fn fabric_consumer_pause_and_resume_gate_dispatch() {
        let cell = test_cell();
        let mut consumer = FabricConsumer::new(
            &cell,
            FabricConsumerConfig {
                flow_control: true,
                ..FabricConsumerConfig::default()
            },
        )
        .expect("consumer");
        let window = SequenceWindow::new(1, 1).expect("window");
        let capsule = RecoverableCapsule::default().with_window(NodeId::new("node-a"), window);

        consumer.pause().expect("pause");
        assert_eq!(
            consumer.dispatch_push(window, &capsule, None),
            Err(FabricConsumerError::ConsumerPaused)
        );

        consumer.resume();
        let delivery = consumer
            .dispatch_push(window, &capsule, None)
            .expect("dispatch after resume");
        assert_eq!(delivery.window, window);
    }

    #[test]
    fn fabric_consumer_max_ack_pending_blocks_until_ack_commit() {
        let cell = test_cell();
        let mut consumer = FabricConsumer::new(
            &cell,
            FabricConsumerConfig {
                max_ack_pending: 2,
                ..FabricConsumerConfig::default()
            },
        )
        .expect("consumer");
        let first_window = SequenceWindow::new(1, 2).expect("window");
        let second_window = SequenceWindow::new(3, 3).expect("window");
        let capsule = RecoverableCapsule::default().with_window(
            NodeId::new("node-a"),
            SequenceWindow::new(1, 3).expect("capsule"),
        );

        let first = consumer
            .dispatch_push(first_window, &capsule, None)
            .expect("first dispatch");
        assert_eq!(consumer.state().pending_count, 2);
        assert_eq!(
            consumer.dispatch_push(second_window, &capsule, None),
            Err(FabricConsumerError::MaxAckPendingExceeded {
                limit: 2,
                pending: 2,
            })
        );

        assert!(matches!(
            consumer.acknowledge_delivery(&first.attempt),
            Ok(AckResolution::Committed { .. })
        ));
        assert_eq!(consumer.state().pending_count, 0);

        let second = consumer
            .dispatch_push(second_window, &capsule, None)
            .expect("second dispatch");
        assert_eq!(second.window, second_window);
    }

    #[test]
    fn fabric_consumer_ack_commits_obligation_backed_state() {
        let cell = test_cell();
        let owner = FabricConsumerOwner {
            holder: TaskId::new_for_test(41, 0),
            region: RegionId::new_for_test(7, 0),
        };
        let mut consumer = FabricConsumer::new_owned(&cell, FabricConsumerConfig::default(), owner)
            .expect("consumer");
        let window = SequenceWindow::new(5, 6).expect("window");
        let capsule = RecoverableCapsule::default().with_window(NodeId::new("node-a"), window);

        let delivery = consumer
            .dispatch_push(window, &capsule, None)
            .expect("dispatch");
        let reserved = consumer
            .ledger
            .get(delivery.attempt.obligation_id)
            .expect("reserved record");
        assert_eq!(reserved.kind, ObligationKind::Ack);
        assert_eq!(reserved.holder, owner.holder);
        assert_eq!(reserved.region, owner.region);
        assert_eq!(consumer.obligation_stats().pending, 1);
        assert_eq!(consumer.obligation_stats().total_acquired, 1);

        assert!(matches!(
            consumer.acknowledge_delivery(&delivery.attempt),
            Ok(AckResolution::Committed { .. })
        ));

        let committed = consumer
            .ledger
            .get(delivery.attempt.obligation_id)
            .expect("committed record");
        assert_eq!(committed.state, crate::record::ObligationState::Committed);
        assert_eq!(consumer.obligation_stats().pending, 0);
        assert_eq!(consumer.obligation_stats().total_committed, 1);
    }

    /// A long-running consumer's ledger stays bounded. It used to keep one
    /// record per delivery forever, and its index space ran out after
    /// u32::MAX deliveries. Committed records past the retention are dropped,
    /// and the counters still count every delivery (br-asupersync-rrtgoy).
    #[test]
    fn fabric_consumer_ledger_stays_bounded_across_many_deliveries() {
        let cell = test_cell();
        let mut consumer =
            FabricConsumer::new(&cell, FabricConsumerConfig::default()).expect("consumer");
        let deliveries = u64::try_from(FABRIC_CONSUMER_RESOLVED_OBLIGATIONS).unwrap() + 8;
        let mut first = None;
        for sequence in 1..=deliveries {
            let window = SequenceWindow::new(sequence, sequence).expect("window");
            let capsule = RecoverableCapsule::default().with_window(NodeId::new("node-a"), window);
            let delivery = consumer
                .dispatch_push(window, &capsule, None)
                .expect("dispatch");
            first.get_or_insert(delivery.attempt.obligation_id);
            assert!(matches!(
                consumer.acknowledge_delivery(&delivery.attempt),
                Ok(AckResolution::Committed { .. })
            ));
        }
        assert_eq!(consumer.ledger.len(), FABRIC_CONSUMER_RESOLVED_OBLIGATIONS);
        assert!(
            consumer.ledger.get(first.expect("a delivery")).is_none(),
            "the oldest delivery's record is dropped"
        );
        let stats = consumer.obligation_stats();
        assert_eq!(
            (stats.total_acquired, stats.total_committed, stats.pending),
            (deliveries, deliveries, 0)
        );
    }

    #[test]
    fn fabric_consumer_nack_aborts_obligation_and_old_ack_is_stale() {
        let cell = test_cell();
        let mut consumer =
            FabricConsumer::new(&cell, FabricConsumerConfig::default()).expect("consumer");
        let window = SequenceWindow::new(7, 7).expect("window");
        let capsule = RecoverableCapsule::default().with_window(NodeId::new("node-a"), window);

        let delivery = consumer
            .dispatch_push(window, &capsule, None)
            .expect("dispatch");
        assert_eq!(
            consumer.nack_delivery(&delivery.attempt, ConsumerNackReason::Explicit),
            Ok(NackResolution::Aborted {
                obligation_id: delivery.attempt.obligation_id,
                window,
                reason: ConsumerNackReason::Explicit,
            })
        );

        let record = consumer
            .ledger
            .get(delivery.attempt.obligation_id)
            .expect("aborted record");
        assert_eq!(record.state, crate::record::ObligationState::Aborted);
        assert_eq!(record.abort_reason, Some(ObligationAbortReason::Explicit));
        assert_eq!(consumer.obligation_stats().total_aborted, 1);
        assert_eq!(
            consumer.acknowledge_delivery(&delivery.attempt),
            Ok(AckResolution::StaleNoOp {
                obligation_id: delivery.attempt.obligation_id,
                current_generation: consumer.current_lease().lease_generation,
                current_holder: CursorLeaseHolder::Steward(NodeId::new("node-a")),
            })
        );
    }

    #[test]
    fn fabric_consumer_redelivery_mints_new_obligation_and_supersedes_old_attempt() {
        let cell = test_cell();
        let config = FabricConsumerConfig {
            max_deliver: 3,
            ..FabricConsumerConfig::default()
        };
        let mut consumer = FabricConsumer::new(&cell, config).expect("consumer");
        let window = SequenceWindow::new(8, 9).expect("window");
        let capsule = RecoverableCapsule::default().with_window(NodeId::new("node-a"), window);

        let first = consumer
            .dispatch_push(window, &capsule, None)
            .expect("first dispatch");
        let redelivery = consumer
            .redeliver_delivery(&first.attempt, &capsule, None)
            .expect("redelivery");

        assert_ne!(
            first.attempt.obligation_id,
            redelivery.attempt.obligation_id
        );
        assert!(consumer.decision_log().is_empty());
        assert_eq!(
            redelivery.attempt.supersedes_obligation_id,
            Some(first.attempt.obligation_id)
        );
        let first_record = consumer
            .ledger
            .get(first.attempt.obligation_id)
            .expect("first record");
        assert_eq!(first_record.state, crate::record::ObligationState::Aborted);
        assert_eq!(
            first_record.abort_reason,
            Some(ObligationAbortReason::Explicit)
        );
        assert_eq!(
            consumer.acknowledge_delivery(&first.attempt),
            Ok(AckResolution::StaleNoOp {
                obligation_id: first.attempt.obligation_id,
                current_generation: consumer.current_lease().lease_generation,
                current_holder: CursorLeaseHolder::Steward(NodeId::new("node-a")),
            })
        );
        assert!(matches!(
            consumer.acknowledge_delivery(&redelivery.attempt),
            Ok(AckResolution::Committed { obligation_id, .. })
                if obligation_id == redelivery.attempt.obligation_id
        ));
        let stats = consumer.obligation_stats();
        assert_eq!(stats.total_acquired, 2);
        assert_eq!(stats.total_aborted, 1);
        assert_eq!(stats.total_committed, 1);
        assert_eq!(stats.pending, 0);
    }

    #[test]
    fn fabric_consumer_audit_backed_redelivery_requires_dead_letter_at_retry_limit() {
        let cell = test_cell();
        let mut consumer = FabricConsumer::new(
            &cell,
            FabricConsumerConfig {
                adaptive_kernel: AdaptiveConsumerKernel::AuditBacked,
                max_deliver: 1,
                ..FabricConsumerConfig::default()
            },
        )
        .expect("consumer");
        let window = SequenceWindow::new(12, 12).expect("window");
        let capsule = RecoverableCapsule::default().with_window(NodeId::new("node-a"), window);

        let first = consumer
            .dispatch_push(window, &capsule, None)
            .expect("dispatch");
        assert_eq!(
            consumer.redeliver_delivery(&first.attempt, &capsule, None),
            Err(FabricConsumerError::RedeliveryRequiresDeadLetter {
                obligation_id: first.attempt.obligation_id,
                delivery_attempt: 2,
            })
        );
        let decision = consumer.decision_log().last().expect("redelivery decision");
        assert_eq!(decision.kind, ConsumerDecisionKind::Redelivery);
        assert_eq!(decision.action_name, "dead_letter");
        assert_eq!(decision.obligation_id, Some(first.attempt.obligation_id));
    }

    #[test]
    fn fabric_consumer_audit_backed_redelivery_defers_under_pending_pressure() {
        let cell = test_cell();
        let mut consumer = FabricConsumer::new(
            &cell,
            FabricConsumerConfig {
                adaptive_kernel: AdaptiveConsumerKernel::AuditBacked,
                max_deliver: 3,
                max_ack_pending: 1,
                ..FabricConsumerConfig::default()
            },
        )
        .expect("consumer");
        let window = SequenceWindow::new(13, 13).expect("window");
        let capsule = RecoverableCapsule::default().with_window(NodeId::new("node-a"), window);

        let first = consumer
            .dispatch_push(window, &capsule, None)
            .expect("dispatch");
        assert_eq!(
            consumer.redeliver_delivery(&first.attempt, &capsule, None),
            Err(FabricConsumerError::RedeliveryDeferred {
                obligation_id: first.attempt.obligation_id,
                delivery_attempt: 2,
            })
        );
        let decision = consumer.decision_log().last().expect("redelivery decision");
        assert_eq!(decision.kind, ConsumerDecisionKind::Redelivery);
        assert_eq!(decision.action_name, "delay");
        assert_eq!(decision.obligation_id, Some(first.attempt.obligation_id));
    }

    #[test]
    fn fabric_consumer_dead_letter_records_reason_and_aborts_obligation() {
        let cell = test_cell();
        let mut consumer =
            FabricConsumer::new(&cell, FabricConsumerConfig::default()).expect("consumer");
        let window = SequenceWindow::new(10, 10).expect("window");
        let capsule = RecoverableCapsule::default().with_window(NodeId::new("node-a"), window);

        let delivery = consumer
            .dispatch_push(window, &capsule, None)
            .expect("dispatch");
        let transfer = consumer
            .dead_letter_delivery(&delivery.attempt, "poison payload")
            .expect("dead letter");

        assert_eq!(transfer.obligation_id, delivery.attempt.obligation_id);
        assert_eq!(transfer.window, window);
        assert_eq!(transfer.reason, "poison payload");
        let record = consumer
            .ledger
            .get(delivery.attempt.obligation_id)
            .expect("dead-letter record");
        assert_eq!(record.state, crate::record::ObligationState::Aborted);
        assert_eq!(record.abort_reason, Some(ObligationAbortReason::Error));
        assert_eq!(consumer.obligation_stats().pending, 0);
        assert_eq!(consumer.obligation_stats().total_aborted, 1);
    }

    #[test]
    fn fabric_consumer_finalize_region_aborts_pending_and_fences_late_ack() {
        let cell = test_cell();
        let owner = FabricConsumerOwner {
            holder: TaskId::new_for_test(41, 0),
            region: RegionId::new_for_test(7, 0),
        };
        let mut consumer = FabricConsumer::new_owned(&cell, FabricConsumerConfig::default(), owner)
            .expect("consumer");
        let window = SequenceWindow::new(11, 12).expect("window");
        let capsule = RecoverableCapsule::default().with_window(NodeId::new("node-a"), window);

        let delivery = consumer
            .dispatch_push(window, &capsule, None)
            .expect("dispatch");
        consumer.switch_mode(ConsumerDispatchMode::Pull);
        consumer
            .queue_pull_request(PullRequest::new(1, ConsumerDemandClass::Tail).expect("pull"))
            .expect("queue before finalize");

        let receipt = consumer.finalize_region();
        assert_eq!(receipt.region, owner.region);
        assert!(receipt.finalized_now);
        assert_eq!(receipt.aborted_obligations, 1);
        assert_eq!(receipt.released_messages, 2);
        assert_eq!(receipt.cleared_waiting_pull_requests, 1);
        assert_eq!(receipt.orphaned_tokens_aborted, 0);
        assert!(consumer.is_region_finalized());
        assert_eq!(consumer.state().pending_count, 0);
        assert_eq!(consumer.waiting_pull_request_count(), 0);

        let record = consumer
            .ledger
            .get(delivery.attempt.obligation_id)
            .expect("finalized record");
        assert_eq!(record.state, crate::record::ObligationState::Aborted);
        assert_eq!(record.abort_reason, Some(ObligationAbortReason::Cancel));
        let stats_after_finalize = consumer.obligation_stats();
        assert_eq!(stats_after_finalize.pending, 0);
        assert_eq!(stats_after_finalize.total_aborted, 1);
        assert_eq!(stats_after_finalize.total_committed, 0);

        assert_eq!(
            consumer.acknowledge_delivery(&delivery.attempt),
            Ok(AckResolution::StaleNoOp {
                obligation_id: delivery.attempt.obligation_id,
                current_generation: consumer.current_lease().lease_generation,
                current_holder: CursorLeaseHolder::Steward(NodeId::new("node-a")),
            })
        );
        let stats_after_late_ack = consumer.obligation_stats();
        assert_eq!(stats_after_late_ack.pending, stats_after_finalize.pending);
        assert_eq!(
            stats_after_late_ack.total_aborted,
            stats_after_finalize.total_aborted
        );
        assert_eq!(
            stats_after_late_ack.total_committed,
            stats_after_finalize.total_committed
        );

        let err = consumer
            .queue_pull_request(PullRequest::new(1, ConsumerDemandClass::Tail).expect("pull"))
            .expect_err("finalized consumer must reject new pull work");
        assert_eq!(
            err,
            FabricConsumerError::RegionFinalized {
                region: owner.region
            }
        );

        let second = consumer.finalize_region();
        assert!(!second.finalized_now);
        assert_eq!(second.aborted_obligations, 0);
        assert_eq!(second.released_messages, 0);
        assert_eq!(second.cleared_waiting_pull_requests, 0);
    }

    #[test]
    fn fabric_consumer_finalize_region_drains_tokenless_pending_ack() {
        let cell = test_cell();
        let owner = FabricConsumerOwner {
            holder: TaskId::new_for_test(41, 0),
            region: RegionId::new_for_test(7, 0),
        };
        let mut consumer = FabricConsumer::new_owned(&cell, FabricConsumerConfig::default(), owner)
            .expect("consumer");
        let window = SequenceWindow::new(31, 33).expect("window");
        let capsule = RecoverableCapsule::default().with_window(NodeId::new("node-a"), window);

        let delivery = consumer
            .dispatch_push(window, &capsule, None)
            .expect("dispatch");
        let dropped_token = consumer
            .pending_ack_tokens
            .remove(&delivery.attempt.obligation_id)
            .expect("test setup removes token");
        drop(dropped_token);

        let receipt = consumer.finalize_region();
        assert_eq!(receipt.aborted_obligations, 1);
        assert_eq!(receipt.released_messages, 3);
        assert_eq!(receipt.orphaned_tokens_aborted, 0);
        assert!(consumer.ledger.is_region_clean(owner.region));
        assert!(consumer.is_region_finalized());

        let record = consumer
            .ledger
            .get(delivery.attempt.obligation_id)
            .expect("drained tokenless record");
        assert_eq!(record.state, crate::record::ObligationState::Aborted);
        assert_eq!(record.abort_reason, Some(ObligationAbortReason::Cancel));
        assert_eq!(
            consumer.acknowledge_delivery(&delivery.attempt),
            Ok(AckResolution::StaleNoOp {
                obligation_id: delivery.attempt.obligation_id,
                current_generation: consumer.current_lease().lease_generation,
                current_holder: CursorLeaseHolder::Steward(NodeId::new("node-a")),
            })
        );
    }

    #[test]
    fn pull_request_expiry_measured_from_original_enqueue_not_re_enqueue() {
        let cell = test_cell();
        let mut consumer = FabricConsumer::new(
            &cell,
            FabricConsumerConfig {
                max_waiting: 4,
                ..FabricConsumerConfig::default()
            },
        )
        .expect("consumer");
        consumer.switch_mode(ConsumerDispatchMode::Pull);

        // Enqueue a pull request that expires in 10 ticks.
        let request = PullRequest::new(1, ConsumerDemandClass::Tail).expect("request");
        let request = request.with_expires(10);
        consumer.queue_pull_request(request).expect("enqueue");

        // Advance clock 5 ticks, then dispatch — no data available, so it
        // re-enqueues.  The request should still remember its original
        // enqueue time.
        consumer.advance_clock(5);
        let capsule = RecoverableCapsule::default();
        let outcome = consumer
            .dispatch_next_pull(0, &capsule, None)
            .expect("dispatch with no data");
        assert!(matches!(outcome, PullDispatchOutcome::Waiting(_)));
        assert_eq!(consumer.waiting_pull_request_count(), 1);

        // Advance 6 more ticks — original deadline (tick 0 + 10 = 10) is
        // now passed (current tick = 11).  The request must have expired.
        consumer.advance_clock(6);
        let err = consumer.dispatch_next_pull(0, &capsule, None);
        assert!(
            err.is_err(),
            "request should have expired by its original enqueue time"
        );
    }

    #[test]
    fn out_of_order_ack_does_not_advance_floor_past_pending() {
        let cell = test_cell();
        let mut consumer =
            FabricConsumer::new(&cell, FabricConsumerConfig::default()).expect("consumer");
        let capsule = RecoverableCapsule::default().with_window(
            NodeId::new("node-a"),
            SequenceWindow::new(1, 20).expect("window"),
        );

        consumer.switch_mode(ConsumerDispatchMode::Pull);

        // Dispatch [1,5] and ack it sequentially.  Floor = 5.
        consumer
            .queue_pull_request(PullRequest::new(5, ConsumerDemandClass::CatchUp).expect("req"))
            .expect("queue");
        let d1 = match consumer.dispatch_next_pull(20, &capsule, None).expect("d") {
            PullDispatchOutcome::Scheduled(d) => *d,
            other => panic!("expected Scheduled, got {other:?}"), // ubs:ignore - test logic
        };
        consumer.acknowledge_delivery(&d1.attempt).expect("ack");
        assert_eq!(consumer.state().ack_floor, 5);

        // Dispatch [6,10] (pending, not yet acked).
        consumer
            .queue_pull_request(PullRequest::new(5, ConsumerDemandClass::CatchUp).expect("req"))
            .expect("queue");
        let d2 = match consumer.dispatch_next_pull(20, &capsule, None).expect("d") {
            PullDispatchOutcome::Scheduled(d) => *d,
            other => panic!("expected Scheduled, got {other:?}"), // ubs:ignore - test logic
        };
        assert_eq!(d2.window, SequenceWindow::new(6, 10).expect("w"));

        // Dispatch [6,10] again (CatchUp restarts from ack_floor+1=6 since
        // the first [6,10] is pending but CatchUp doesn't skip pending windows).
        // Then ack this second [6,10] — it will advance floor to at most 5
        // because the first [6,10] is still pending.
        consumer
            .queue_pull_request(PullRequest::new(5, ConsumerDemandClass::CatchUp).expect("req"))
            .expect("queue");
        let d3 = match consumer.dispatch_next_pull(20, &capsule, None).expect("d") {
            PullDispatchOutcome::Scheduled(d) => *d,
            other => panic!("expected Scheduled, got {other:?}"), // ubs:ignore - test logic
        };
        consumer.acknowledge_delivery(&d3.attempt).expect("ack d3");

        // Floor must not advance past the still-pending d2 [6,10].
        assert!(
            consumer.state().ack_floor <= 5,
            "ack_floor must not advance past pending [6,10]; got {}",
            consumer.state().ack_floor
        );

        // Now ack d2 [6,10].  Floor should advance to 10.
        consumer.acknowledge_delivery(&d2.attempt).expect("ack d2");
        assert_eq!(
            consumer.state().ack_floor,
            10,
            "ack_floor should advance to 10 once all windows up to 10 are acked"
        );
    }

    // ── ConsumerActor unit tests ──────────────────────────────────

    #[test]
    fn consumer_actor_lifecycle_transitions() {
        let cell = test_cell();
        let config = FabricConsumerConfig {
            durable_name: Some("test-actor".to_owned()),
            ..FabricConsumerConfig::default()
        };
        let consumer = FabricConsumer::new(&cell, config).expect("consumer");
        let actor = ConsumerActor::new(consumer);

        assert_eq!(actor.lifecycle(), ConsumerActorLifecycle::Running);
        assert_eq!(
            actor.consumer().config().durable_name.as_deref(),
            Some("test-actor")
        );
    }

    #[test]
    fn consumer_actor_pause_and_resume() {
        let cell = test_cell();
        let consumer =
            FabricConsumer::new(&cell, FabricConsumerConfig::default()).expect("consumer");
        let mut actor = ConsumerActor::new(consumer);
        let cx = crate::cx::Cx::for_testing();

        assert_eq!(actor.lifecycle(), ConsumerActorLifecycle::Running);

        futures_lite::future::block_on(
            <ConsumerActor as crate::gen_server::GenServer>::handle_cast(
                &mut actor,
                &cx,
                ConsumerCast::Pause,
            ),
        );
        assert_eq!(actor.lifecycle(), ConsumerActorLifecycle::Paused);

        futures_lite::future::block_on(
            <ConsumerActor as crate::gen_server::GenServer>::handle_cast(
                &mut actor,
                &cx,
                ConsumerCast::Resume,
            ),
        );
        assert_eq!(actor.lifecycle(), ConsumerActorLifecycle::Running);
    }

    #[test]
    fn consumer_actor_stopping_lifecycle() {
        let cell = test_cell();
        let consumer =
            FabricConsumer::new(&cell, FabricConsumerConfig::default()).expect("consumer");
        let mut actor = ConsumerActor::new(consumer);
        let cx = crate::cx::Cx::for_testing();

        futures_lite::future::block_on(<ConsumerActor as crate::gen_server::GenServer>::on_stop(
            &mut actor, &cx,
        ));
        assert_eq!(actor.lifecycle(), ConsumerActorLifecycle::Stopping);
        assert!(actor.consumer().is_region_finalized());
    }

    #[test]
    fn consumer_actor_on_stop_finalizes_pending_consumer_obligations() {
        let cell = test_cell();
        let owner = FabricConsumerOwner {
            holder: TaskId::new_for_test(41, 0),
            region: RegionId::new_for_test(7, 0),
        };
        let consumer = FabricConsumer::new_owned(&cell, FabricConsumerConfig::default(), owner)
            .expect("consumer");
        let mut actor = ConsumerActor::new(consumer);
        let cx = crate::cx::Cx::for_testing();
        let window = SequenceWindow::new(21, 22).expect("window");
        let capsule = RecoverableCapsule::default().with_window(NodeId::new("node-a"), window);

        let delivery = actor
            .consumer_mut()
            .dispatch_push(window, &capsule, None)
            .expect("dispatch before stop");
        assert_eq!(actor.consumer().obligation_stats().pending, 1);

        futures_lite::future::block_on(<ConsumerActor as crate::gen_server::GenServer>::on_stop(
            &mut actor, &cx,
        ));

        assert_eq!(actor.lifecycle(), ConsumerActorLifecycle::Stopping);
        assert!(actor.consumer().is_region_finalized());
        assert_eq!(actor.consumer().state().pending_count, 0);
        assert_eq!(actor.consumer().obligation_stats().pending, 0);
        assert_eq!(actor.consumer().obligation_stats().total_aborted, 1);
        let current_generation = actor.consumer().current_lease().lease_generation;
        assert_eq!(
            actor.consumer_mut().acknowledge_delivery(&delivery.attempt),
            Ok(AckResolution::StaleNoOp {
                obligation_id: delivery.attempt.obligation_id,
                current_generation,
                current_holder: CursorLeaseHolder::Steward(NodeId::new("node-a")),
            })
        );
    }

    #[test]
    fn consumer_actor_state_query() {
        let cell = test_cell();
        let consumer =
            FabricConsumer::new(&cell, FabricConsumerConfig::default()).expect("consumer");
        let actor = ConsumerActor::new(consumer);

        let state = actor.consumer().state();
        assert_eq!(state.delivered_count, 0);
        assert_eq!(state.pending_count, 0);
        assert_eq!(state.ack_floor, 0);
    }

    #[test]
    fn consumer_actor_mutable_consumer_access() {
        let cell = test_cell();
        let consumer =
            FabricConsumer::new(&cell, FabricConsumerConfig::default()).expect("consumer");
        let mut actor = ConsumerActor::new(consumer);

        let consumer_ref = actor.consumer_mut();
        assert_eq!(consumer_ref.state().delivered_count, 0);
    }
