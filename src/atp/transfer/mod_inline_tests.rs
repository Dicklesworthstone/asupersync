    use super::super::actor::{TransferActorTopology, TransferChildRole, TransferRegionId};
    use super::super::autotune::{
        AtpAutotuneApplicationOutcome, AtpAutotuneMetric, AtpAutotuneMetricSample,
    };
    use super::*;

    fn manifest() -> TransferManifestRef {
        TransferManifestRef {
            schema_version: 1,
            merkle_root: [7; 32],
            object_count: 3,
        }
    }

    fn topology() -> TransferActorTopology {
        TransferActorTopology::new(TransferRegionId::new(1), TransferRegionId::new(2))
            .with_child(TransferRegionId::new(3), TransferChildRole::PathRace)
            .with_child(TransferRegionId::new(4), TransferChildRole::Writer)
            .with_child(TransferRegionId::new(5), TransferChildRole::Finalizer)
    }

    fn actor() -> TransferActor {
        TransferActor::new(
            TransferActorId::new(11),
            TransferId::derive([1; 32], [2; 32], [3; 32], [4; 32]),
            manifest(),
            PeerCapabilities {
                relay: true,
                mailbox: true,
                swarm: true,
                max_inflight_obligations: 4,
            },
            topology(),
        )
        .unwrap()
    }

    fn complete_sources(trace_id: &str) -> TransferPressureSources {
        let mut sources = TransferPressureSources::new(trace_id, 5);
        sources.transport = Some(TransferTransportPressure {
            trace_id: trace_id.to_string(),
            rtt_micros: 42_000,
            loss_permille: 8,
            pto_micros: 120_000,
            congestion_window_bytes: 64_000,
            send_buffer_queued_bytes: 2_048,
        });
        sources.disk = Some(TransferDiskPressure {
            trace_id: trace_id.to_string(),
            read_lag_micros: 9_000,
            write_lag_micros: 11_000,
        });
        sources.coding = Some(TransferCodingPressure {
            trace_id: trace_id.to_string(),
            encode_backlog_symbols: 7,
            decode_backlog_symbols: 3,
        });
        sources.repair = Some(TransferRepairPressure {
            trace_id: trace_id.to_string(),
            symbols_sent: 20,
            useful_symbols: 10,
        });
        sources.relay = Some(TransferRelayPressure {
            trace_id: trace_id.to_string(),
            cost_micros: 250_000,
            bytes: 1_048_576,
        });
        sources.migration = Some(TransferMigrationPressure {
            trace_id: trace_id.to_string(),
            events: 0,
        });
        sources
    }

    #[test]
    fn actor_construction_uses_inline_empty_collections() {
        let actor = actor();

        assert!(!actor.applied_keys.spilled());
        assert!(!actor.open_obligations.spilled());
        assert!(!actor.settled_obligations.spilled());
        assert!(!actor.journal.spilled());
    }

    #[test]
    fn transfer_id_binds_peers_nonce_manifest_and_policy() {
        let baseline = TransferId::derive_with_policy([1; 32], [2; 32], [3; 32], [4; 32], [5; 32]);

        assert_eq!(
            baseline,
            TransferId::derive_with_policy([1; 32], [2; 32], [3; 32], [4; 32], [5; 32])
        );
        assert_ne!(
            baseline,
            TransferId::derive_with_policy([2; 32], [1; 32], [3; 32], [4; 32], [5; 32])
        );
        assert_ne!(
            baseline,
            TransferId::derive_with_policy([1; 32], [2; 32], [9; 32], [4; 32], [5; 32])
        );
        assert_ne!(
            baseline,
            TransferId::derive_with_policy([1; 32], [2; 32], [3; 32], [9; 32], [5; 32])
        );
        assert_ne!(
            baseline,
            TransferId::derive_with_policy([1; 32], [2; 32], [3; 32], [4; 32], [9; 32])
        );
    }

    #[test]
    fn transfer_id_hex_is_stable_lowercase() {
        let mut bytes = [0_u8; 32];
        bytes[0] = 0xab;
        bytes[1] = 0xcd;
        bytes[30] = 0x12;
        bytes[31] = 0x34;

        assert_eq!(
            TransferId::new(bytes).to_hex(),
            "abcd000000000000000000000000000000000000000000000000000000001234"
        );
    }

    #[test]
    fn transfer_progress_collects_actor_owned_pressure_metrics() {
        let mut actor = actor();
        actor.progress.offered_bytes = 8_192;
        actor.progress.verified_bytes = 3_072;
        actor.progress.committed_bytes = 1_024;

        let snapshot = actor.pressure_snapshot("trace-transfer-actor", 4);

        assert_eq!(snapshot.trace_id, "trace-transfer-actor");
        assert_eq!(snapshot.transfer_id, actor.transfer_id.to_hex());
        assert_eq!(snapshot.sample_count, 4);
        assert_eq!(snapshot.in_flight_bytes, Some(5_120));
        assert_eq!(snapshot.receive_buffer_queued_bytes, Some(2_048));

        let report = snapshot.to_report();
        assert_eq!(
            report.samples,
            vec![
                AtpAutotuneMetricSample::new(AtpAutotuneMetric::InFlightBytes, 5_120),
                AtpAutotuneMetricSample::new(AtpAutotuneMetric::ReceiveBufferQueuedBytes, 2_048,),
            ]
        );
    }

    #[test]
    fn transfer_progress_pressure_snapshot_saturates_inconsistent_counters() {
        let progress = TransferProgress {
            offered_bytes: 10,
            verified_bytes: 20,
            committed_bytes: 30,
            repair_symbols: 0,
            selected_path: None,
        };

        let snapshot =
            progress.to_pressure_snapshot("trace-saturating", TransferId::from_u128(7), 1);

        assert_eq!(snapshot.in_flight_bytes, Some(0));
        assert_eq!(snapshot.receive_buffer_queued_bytes, Some(0));
    }

    #[test]
    fn complete_pressure_snapshot_collects_every_metric_family() {
        let mut actor = actor();
        actor.progress.offered_bytes = 4_096;
        actor.progress.verified_bytes = 1_024;
        actor.progress.committed_bytes = 256;

        let snapshot = actor
            .collect_complete_pressure_snapshot(complete_sources("trace-complete"))
            .expect("complete pressure sources");

        assert_eq!(snapshot.trace_id, "trace-complete");
        assert_eq!(snapshot.transfer_id, actor.transfer_id.to_hex());
        assert_eq!(snapshot.sample_count, 5);
        assert_eq!(snapshot.in_flight_bytes, Some(3_072));
        assert_eq!(snapshot.receive_buffer_queued_bytes, Some(768));
        assert_eq!(snapshot.repair_roi_permille(), Some(500));
        assert_eq!(snapshot.relay_cost_micros_per_mib(), Some(250_000));

        let report = snapshot.to_report();
        assert_eq!(
            report.samples,
            vec![
                AtpAutotuneMetricSample::new(AtpAutotuneMetric::RttMicros, 42_000),
                AtpAutotuneMetricSample::new(AtpAutotuneMetric::LossPermille, 8),
                AtpAutotuneMetricSample::new(AtpAutotuneMetric::PtoMicros, 120_000),
                AtpAutotuneMetricSample::new(AtpAutotuneMetric::CongestionWindowBytes, 64_000,),
                AtpAutotuneMetricSample::new(AtpAutotuneMetric::InFlightBytes, 3_072),
                AtpAutotuneMetricSample::new(AtpAutotuneMetric::SendBufferQueuedBytes, 2_048,),
                AtpAutotuneMetricSample::new(AtpAutotuneMetric::ReceiveBufferQueuedBytes, 768,),
                AtpAutotuneMetricSample::new(AtpAutotuneMetric::DiskReadLagMicros, 9_000),
                AtpAutotuneMetricSample::new(AtpAutotuneMetric::DiskWriteLagMicros, 11_000),
                AtpAutotuneMetricSample::new(AtpAutotuneMetric::EncodeBacklogSymbols, 7),
                AtpAutotuneMetricSample::new(AtpAutotuneMetric::DecodeBacklogSymbols, 3),
                AtpAutotuneMetricSample::new(AtpAutotuneMetric::RepairRoiPermille, 500),
                AtpAutotuneMetricSample::new(AtpAutotuneMetric::RelayCostMicrosPerMiB, 250_000,),
                AtpAutotuneMetricSample::new(AtpAutotuneMetric::MigrationEvents, 0),
            ]
        );
    }

    #[test]
    fn complete_pressure_snapshot_fails_closed_for_missing_source() {
        let mut sources = complete_sources("trace-missing");
        sources.disk = None;

        let err = actor()
            .collect_complete_pressure_snapshot(sources)
            .expect_err("missing disk source must fail closed");

        assert_eq!(err.reason_code(), "missing_pressure_source");
        assert!(matches!(
            err,
            TransferPressureCollectionError::MissingSource {
                source: TransferPressureSourceKind::Disk
            }
        ));
    }

    #[test]
    fn complete_pressure_snapshot_fails_closed_for_stale_trace_id() {
        let mut sources = complete_sources("trace-current");
        sources.repair.as_mut().expect("repair source").trace_id = "trace-stale".to_string();

        let err = actor()
            .collect_complete_pressure_snapshot(sources)
            .expect_err("stale repair trace must fail closed");

        assert_eq!(err.reason_code(), "stale_pressure_trace_id");
        assert!(matches!(
            err,
            TransferPressureCollectionError::StaleSourceTrace {
                source: TransferPressureSourceKind::Repair,
                ..
            }
        ));
    }

    #[test]
    fn complete_pressure_snapshot_fails_closed_for_zero_samples() {
        let mut sources = complete_sources("trace-zero");
        sources.sample_count = 0;

        let err = actor()
            .collect_complete_pressure_snapshot(sources)
            .expect_err("zero-sample complete source must fail closed");

        assert_eq!(err.reason_code(), "zero_pressure_samples");
        assert!(matches!(err, TransferPressureCollectionError::ZeroSamples));
    }

    #[test]
    fn complete_pressure_snapshot_fails_closed_for_contradictory_progress() {
        let mut actor = actor();
        actor.progress.offered_bytes = 10;
        actor.progress.verified_bytes = 20;
        actor.progress.committed_bytes = 5;

        let err = actor
            .collect_complete_pressure_snapshot(complete_sources("trace-progress"))
            .expect_err("backwards progress counters must fail closed");

        assert_eq!(err.reason_code(), "contradictory_progress_counters");
        assert!(matches!(
            err,
            TransferPressureCollectionError::ContradictoryProgress {
                offered_bytes: 10,
                verified_bytes: 20,
                committed_bytes: 5,
            }
        ));
    }

    #[test]
    fn complete_pressure_snapshot_fails_closed_for_contradictory_repair_or_relay() {
        let mut repair_sources = complete_sources("trace-repair");
        repair_sources
            .repair
            .as_mut()
            .expect("repair source")
            .useful_symbols = 21;

        let repair_err = actor()
            .collect_complete_pressure_snapshot(repair_sources)
            .expect_err("useful repair cannot exceed sent repair");
        assert_eq!(repair_err.reason_code(), "contradictory_repair_counters");

        let mut relay_sources = complete_sources("trace-relay");
        let relay = relay_sources.relay.as_mut().expect("relay source");
        relay.bytes = 0;
        relay.cost_micros = 1;

        let relay_err = actor()
            .collect_complete_pressure_snapshot(relay_sources)
            .expect_err("relay cost without payload must fail closed");
        assert_eq!(relay_err.reason_code(), "contradictory_relay_counters");
    }

    #[test]
    fn transfer_actor_applies_autotune_growth_after_hysteresis() {
        let policy = AtpAutotunePolicy::default();
        let mut actor = actor();
        let initial = actor.autotune_settings();
        let mut first_sources = complete_sources("trace-growth-1");
        first_sources.sample_count = 16;

        let first = actor
            .apply_complete_pressure_autotune(policy, first_sources)
            .expect("first healthy pressure window");

        assert_eq!(
            first.outcome,
            AtpAutotuneApplicationOutcome::DeferredGrowthHysteresis
        );
        assert!(!first.applied);
        assert_eq!(actor.autotune_settings(), initial);
        assert_eq!(
            actor
                .autotune_application_state()
                .consecutive_growth_windows,
            1
        );

        let mut second_sources = complete_sources("trace-growth-2");
        second_sources.sample_count = 16;
        let second = actor
            .apply_complete_pressure_autotune(policy, second_sources)
            .expect("second healthy pressure window");

        assert_eq!(
            second.outcome,
            AtpAutotuneApplicationOutcome::AppliedConfirmedGrowth
        );
        assert!(second.applied);
        assert!(actor.autotune_settings().in_flight_bytes > initial.in_flight_bytes);
        assert!(actor.autotune_settings().stream_count > initial.stream_count);
        assert!(actor.autotune_settings().chunk_size_bytes > initial.chunk_size_bytes);
        assert_eq!(
            actor
                .autotune_application_state()
                .consecutive_growth_windows,
            0
        );
    }

    #[test]
    fn transfer_actor_applies_autotune_pressure_to_independent_knobs() {
        let policy = AtpAutotunePolicy::default();

        let mut network_actor = actor();
        let network_initial = network_actor.autotune_settings();
        let mut network_sources = complete_sources("trace-network");
        network_sources.sample_count = 16;
        network_sources
            .transport
            .as_mut()
            .expect("transport source")
            .loss_permille = policy.loss_backoff_permille + 1;

        let network_receipt = network_actor
            .apply_complete_pressure_autotune(policy, network_sources)
            .expect("network pressure window");

        assert_eq!(
            network_receipt.outcome,
            AtpAutotuneApplicationOutcome::AppliedPressureBackoff
        );
        assert!(
            network_actor.autotune_settings().in_flight_bytes < network_initial.in_flight_bytes
        );
        assert!(network_actor.autotune_settings().stream_count < network_initial.stream_count);
        assert!(
            network_actor.autotune_settings().repair_symbols_per_second
                > network_initial.repair_symbols_per_second
        );

        let mut disk_cpu_actor = actor();
        let disk_cpu_initial = disk_cpu_actor.autotune_settings();
        let mut disk_cpu_sources = complete_sources("trace-disk-cpu");
        disk_cpu_sources.sample_count = 16;
        disk_cpu_sources
            .disk
            .as_mut()
            .expect("disk source")
            .write_lag_micros = policy.disk_lag_micros + 1;
        disk_cpu_sources
            .coding
            .as_mut()
            .expect("coding source")
            .encode_backlog_symbols = policy.cpu_backlog_symbols + 1;

        let disk_cpu_receipt = disk_cpu_actor
            .apply_complete_pressure_autotune(policy, disk_cpu_sources)
            .expect("disk/cpu pressure window");

        assert_eq!(
            disk_cpu_receipt.outcome,
            AtpAutotuneApplicationOutcome::AppliedPressureBackoff
        );
        assert_eq!(
            disk_cpu_actor.autotune_settings().in_flight_bytes,
            disk_cpu_initial.in_flight_bytes
        );
        assert!(
            disk_cpu_actor.autotune_settings().chunk_size_bytes < disk_cpu_initial.chunk_size_bytes
        );

        let mut relay_actor = actor();
        let relay_initial = relay_actor.autotune_settings();
        let mut relay_sources = complete_sources("trace-relay-cost");
        relay_sources.sample_count = 16;
        let relay = relay_sources.relay.as_mut().expect("relay source");
        relay.bytes = 1_048_576;
        relay.cost_micros = policy.relay_cost_micros_per_mib + 1;

        let relay_receipt = relay_actor
            .apply_complete_pressure_autotune(policy, relay_sources)
            .expect("relay pressure window");

        assert_eq!(
            relay_receipt.outcome,
            AtpAutotuneApplicationOutcome::AppliedPressureBackoff
        );
        assert!(relay_actor.autotune_settings().in_flight_bytes < relay_initial.in_flight_bytes);
        assert!(relay_actor.autotune_settings().stream_count < relay_initial.stream_count);
        assert_eq!(
            relay_actor.autotune_settings().repair_symbols_per_second,
            relay_initial.repair_symbols_per_second
        );
    }

    #[test]
    fn transfer_actor_rejects_contradictory_autotune_sources_without_mutation() {
        let policy = AtpAutotunePolicy::default();
        let mut actor = actor();
        actor.progress.offered_bytes = 10;
        actor.progress.verified_bytes = 20;
        actor.progress.committed_bytes = 5;
        let before = actor.autotune_settings();
        let mut sources = complete_sources("trace-contradictory");
        sources.sample_count = 16;

        let err = actor
            .apply_complete_pressure_autotune(policy, sources)
            .expect_err("contradictory progress must reject before mutation");

        assert_eq!(err.reason_code(), "contradictory_progress_counters");
        assert!(matches!(
            err,
            TransferAutotuneApplicationError::PressureCollection(
                TransferPressureCollectionError::ContradictoryProgress { .. }
            )
        ));
        assert_eq!(actor.autotune_settings(), before);
    }

    #[test]
    fn transfer_actor_rejects_autotune_while_cancelling_without_obligation_or_settings_mutation() {
        let policy = AtpAutotunePolicy::default();
        let mut actor = actor();
        actor
            .apply(cmd(
                1,
                TransferCommandKind::Accept {
                    obligation: TransferObligationId::new(1),
                },
            ))
            .expect("accept");
        actor
            .apply(cmd(
                2,
                TransferCommandKind::Start {
                    path_id: 7,
                    obligation: TransferObligationId::new(2),
                },
            ))
            .expect("start");
        actor
            .apply(cmd(
                3,
                TransferCommandKind::Cancel {
                    phase: TransferCancelPhase::Requested,
                },
            ))
            .expect("cancel");

        let before_settings = actor.autotune_settings();
        let before_open = actor.open_obligation_count();
        let before_journal_len = actor.journal().len();
        let mut sources = complete_sources("trace-cancelled");
        sources.sample_count = 16;

        let err = actor
            .apply_complete_pressure_autotune(policy, sources)
            .expect_err("cancelled actor must not apply autotune");

        assert_eq!(err.reason_code(), "transfer_not_tunable");
        assert!(matches!(
            err,
            TransferAutotuneApplicationError::ActorNotTunable {
                state: TransferState::Cancelling
            }
        ));
        assert_eq!(actor.autotune_settings(), before_settings);
        assert_eq!(actor.open_obligation_count(), before_open);
        assert_eq!(actor.journal().len(), before_journal_len);
    }

    fn cmd(key: u128, kind: TransferCommandKind) -> TransferCommand {
        TransferCommand::new(IdempotencyKey::new(key), kind)
    }

    #[test]
    fn state_coverage_matches_atp_e1() {
        assert_eq!(TransferState::ALL.len(), 12);
        assert!(TransferState::ALL.contains(&TransferState::Offered));
        assert!(TransferState::ALL.contains(&TransferState::Accepted));
        assert!(TransferState::ALL.contains(&TransferState::Running));
        assert!(TransferState::ALL.contains(&TransferState::Paused));
        assert!(TransferState::ALL.contains(&TransferState::Cancelling));
        assert!(TransferState::ALL.contains(&TransferState::Failed));
        assert!(TransferState::ALL.contains(&TransferState::Committed));
        assert!(TransferState::ALL.contains(&TransferState::Resumed));
        assert!(TransferState::ALL.contains(&TransferState::MailboxStored));
        assert!(TransferState::ALL.contains(&TransferState::RelayForwarded));
        assert!(TransferState::ALL.contains(&TransferState::Seeded));
        assert!(TransferState::ALL.contains(&TransferState::SwarmAssisted));
    }

    #[test]
    fn offer_accept_running_commit_shutdown_is_quiescent() {
        let mut actor = actor();
        actor.progress.verified_bytes = 4096;

        actor
            .apply(cmd(
                1,
                TransferCommandKind::Accept {
                    obligation: TransferObligationId::new(101),
                },
            ))
            .unwrap();
        actor
            .apply(cmd(
                2,
                TransferCommandKind::Start {
                    path_id: 55,
                    obligation: TransferObligationId::new(102),
                },
            ))
            .unwrap();
        actor
            .apply(cmd(
                3,
                TransferCommandKind::Commit {
                    obligation: TransferObligationId::new(103),
                },
            ))
            .unwrap();
        let reply = actor
            .apply(cmd(4, TransferCommandKind::Shutdown))
            .expect("shutdown after commit");

        assert_eq!(actor.state(), TransferState::Committed);
        assert_eq!(actor.progress.selected_path, Some(55));
        assert_eq!(actor.progress.committed_bytes, 4096);
        assert_eq!(actor.open_obligation_count(), 0);
        assert_eq!(actor.settled_obligations().len(), 3);
        assert_eq!(actor.journal()[0].actor_id, actor.actor_id);
        assert_eq!(actor.journal()[0].transfer_id, actor.transfer_id);
        assert_eq!(actor.journal()[0].actor_region, actor.topology.actor_region);
        assert_eq!(
            actor.journal()[0].supervisor_region,
            actor.topology.supervisor_region
        );
        assert_eq!(
            actor.journal()[0].child_topology,
            actor.topology.child_regions
        );
        assert_eq!(
            actor.journal()[0].replay_crashpack_path,
            "atp/replay/actor-11/transition-0.crashpack"
        );
        assert!(matches!(
            reply,
            TransferReply::ShutdownQuiescent {
                state: TransferState::Committed
            }
        ));
    }

    #[test]
    fn invalid_transition_aborts_obligation_without_state_change() {
        let mut actor = actor();
        let err = actor
            .apply(cmd(
                1,
                TransferCommandKind::Commit {
                    obligation: TransferObligationId::new(77),
                },
            ))
            .expect_err("commit from offered must fail");

        assert_eq!(actor.state(), TransferState::Offered);
        assert_eq!(actor.open_obligation_count(), 0);
        assert_eq!(
            actor.settled_obligations(),
            &[(TransferObligationId::new(77), ObligationOutcome::Aborted)]
        );
        assert!(matches!(
            err,
            TransferActorError::InvalidTransition {
                state: TransferState::Offered,
                command: "commit"
            }
        ));
    }

    #[test]
    fn duplicate_messages_are_idempotent() {
        let mut actor = actor();
        let command = cmd(
            1,
            TransferCommandKind::Accept {
                obligation: TransferObligationId::new(10),
            },
        );

        actor.apply(command.clone()).unwrap();
        let duplicate = actor.apply(command).unwrap();

        assert_eq!(actor.state(), TransferState::Accepted);
        assert_eq!(actor.journal().len(), 1);
        assert_eq!(actor.settled_obligations().len(), 1);
        assert!(matches!(
            duplicate,
            TransferReply::Duplicate {
                state: TransferState::Accepted
            }
        ));
    }

    #[test]
    fn cancellation_is_accepted_from_every_nonterminal_state() {
        for state in [
            TransferState::Offered,
            TransferState::Accepted,
            TransferState::Running,
            TransferState::Paused,
            TransferState::Resumed,
            TransferState::MailboxStored,
            TransferState::RelayForwarded,
            TransferState::SwarmAssisted,
        ] {
            let mut actor = actor();
            actor.state = state;
            actor
                .apply(cmd(
                    1,
                    TransferCommandKind::Cancel {
                        phase: TransferCancelPhase::Requested,
                    },
                ))
                .unwrap();
            assert_eq!(actor.state(), TransferState::Cancelling);
            assert_eq!(
                actor.journal()[0].cancel_phase,
                Some(TransferCancelPhase::Requested)
            );
        }
    }

    #[test]
    fn restart_from_journal_preserves_state_and_idempotency() {
        let mut actor = actor();
        actor
            .apply(cmd(
                1,
                TransferCommandKind::Accept {
                    obligation: TransferObligationId::new(1),
                },
            ))
            .unwrap();
        actor
            .apply(cmd(
                2,
                TransferCommandKind::Start {
                    path_id: 9,
                    obligation: TransferObligationId::new(2),
                },
            ))
            .unwrap();

        let mut restarted = TransferActor::restart_from_journal(
            actor.actor_id,
            actor.transfer_id,
            actor.manifest.clone(),
            actor.peer_capabilities.clone(),
            actor.topology.clone(),
            actor.journal(),
        )
        .unwrap();

        assert_eq!(restarted.state(), TransferState::Running);
        let duplicate = restarted
            .apply(cmd(
                2,
                TransferCommandKind::Start {
                    path_id: 9,
                    obligation: TransferObligationId::new(2),
                },
            ))
            .unwrap();
        assert!(matches!(
            duplicate,
            TransferReply::Duplicate {
                state: TransferState::Running
            }
        ));
    }

    #[test]
    fn failed_peer_disk_and_repair_paths_are_distinct() {
        for (key, failure) in [
            (1, TransferFailureKind::Peer),
            (2, TransferFailureKind::Disk),
            (3, TransferFailureKind::Repair),
        ] {
            let mut actor = actor();
            actor
                .apply(cmd(key, TransferCommandKind::Fail { kind: failure }))
                .unwrap();
            assert_eq!(actor.state(), TransferState::Failed);
            assert_eq!(actor.open_obligation_count(), 0);
        }
    }

    #[test]
    fn restart_from_journal_preserves_obligation_state() {
        // Test demonstrates current synchronous obligation behavior and documents
        // expected behavior for future asynchronous obligation support
        let mut actor = actor();

        // Apply commands that create and immediately settle obligations
        actor
            .apply(cmd(
                1,
                TransferCommandKind::Accept {
                    obligation: TransferObligationId::new(101),
                },
            ))
            .unwrap();
        actor
            .apply(cmd(
                2,
                TransferCommandKind::Start {
                    path_id: 42,
                    obligation: TransferObligationId::new(102),
                },
            ))
            .unwrap();

        // All obligations should be settled, none open
        assert_eq!(actor.open_obligation_count(), 0);
        assert_eq!(actor.settled_obligations().len(), 2);

        // Restart from journal
        let restarted = TransferActor::restart_from_journal(
            actor.actor_id,
            actor.transfer_id,
            actor.manifest.clone(),
            actor.peer_capabilities.clone(),
            actor.topology.clone(),
            actor.journal(),
        )
        .unwrap();

        // After restart, state should be preserved
        assert_eq!(restarted.state(), TransferState::Running);
        assert_eq!(restarted.open_obligation_count(), 0);
        assert_eq!(restarted.settled_obligations().len(), 2);

        // The two settled obligations should match the original
        let original_settled = actor.settled_obligations();
        let restarted_settled = restarted.settled_obligations();
        assert_eq!(original_settled, restarted_settled);

        // Verify specific obligation IDs and outcomes are preserved
        assert!(
            original_settled
                .contains(&(TransferObligationId::new(101), ObligationOutcome::Committed))
        );
        assert!(
            original_settled
                .contains(&(TransferObligationId::new(102), ObligationOutcome::Committed))
        );
    }
