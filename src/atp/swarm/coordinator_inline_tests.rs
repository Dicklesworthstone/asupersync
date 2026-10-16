    use super::*;
    use crate::atp::swarm::{PeerCapabilities, PeerReputation, PieceStatus};
    use crate::channel::mpsc;
    use crate::cx::Cx;
    use futures_lite::future::block_on;
    use std::collections::BTreeSet;

    fn test_peer(id: &str, pieces: impl IntoIterator<Item = PieceId>) -> SwarmPeer {
        SwarmPeer {
            peer_id: PeerId::new(id),
            endpoint: "127.0.0.1:8080".parse().unwrap(),
            available_pieces: pieces.into_iter().collect::<BTreeSet<_>>(),
            quality: PeerQuality {
                overall_score: 0.9,
                ..Default::default()
            },
            reputation: PeerReputation::default(),
            last_seen: swarm_time_now(),
            pending_requests: BTreeSet::new(),
            capabilities: PeerCapabilities::default(),
        }
    }

    #[test]
    fn test_coordinator_creation() {
        let config = SwarmConfig::default();
        let coordinator = SwarmCoordinator::new(config);

        assert_eq!(coordinator.peers.len(), 0);
        assert_eq!(coordinator.active_transfers.len(), 0);
    }

    #[test]
    fn test_piece_priority_calculation() {
        let coordinator = SwarmCoordinator::new(SwarmConfig::default());
        let transfer = SwarmTransfer {
            metadata: SwarmTransferMetadata {
                object_id: "test".to_string(),
                total_size: 1000,
                piece_count: 10,
                piece_size: 100,
                content_hash: "test".to_string(),
            },
            status: SwarmTransferStatus {
                transfer_id: MailboxTransferId::new(),
                total_pieces: 10,
                completed_pieces: 0,
                pending_pieces: 0,
                remaining_pieces: 10,
                active_peers: HashMap::new(),
                download_rate: 0.0,
                upload_rate: 0.0,
                estimated_completion: None,
                quality_metrics: SwarmQualityMetrics {
                    avg_peer_response_time: Duration::from_secs(1),
                    verification_failure_rate: 0.0,
                    peer_churn_rate: 0.0,
                    avg_piece_redundancy: 1.0,
                    incentive_balance_score: 1.0,
                    health_score: 1.0,
                },
            },
            active_requests: HashMap::new(),
            completed_pieces: HashSet::new(),
            started_at: Instant::now(),
            last_activity: Instant::now(),
        };

        let priority = coordinator.calculate_piece_priority(&PieceId::new(1), &transfer);
        assert!(priority >= 100);
    }

    #[test]
    fn validate_piece_count_rejects_piece_map_mismatch() {
        let piece_map = PieceMap::new(2, 1024, "test-hash".to_string());

        let err = SwarmCoordinator::validate_piece_count_matches_map(3, &piece_map)
            .expect_err("mismatched piece metadata must fail before transfer creation");

        assert!(
            matches!(&err, SwarmError::ConfigurationError { details } if details.contains("piece_count 3") && details.contains("piece_map.total_pieces 2")),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn validate_piece_count_accepts_piece_map_match() {
        let piece_map = PieceMap::new(3, 1024, "test-hash".to_string());

        SwarmCoordinator::validate_piece_count_matches_map(3, &piece_map)
            .expect("matching transfer and piece-map metadata must be accepted");
    }

    #[test]
    fn verification_failure_releases_piece_for_reassignment() {
        block_on(async {
            let cx = Cx::for_testing();
            let mut coordinator = SwarmCoordinator::new(SwarmConfig {
                peer_quality_threshold: 0.0,
                max_pieces_per_peer: 1,
                ..SwarmConfig::default()
            });
            let piece_id = PieceId::new(0);
            let peer_a = test_peer("peer-a", [piece_id]);
            let peer_b = test_peer("peer-b", [piece_id]);
            let mut piece_map = PieceMap::new(1, 1024, "test-hash".to_string());
            piece_map.add_peer_pieces(peer_a.peer_id.clone(), std::iter::once(piece_id).collect());
            piece_map.add_peer_pieces(peer_b.peer_id.clone(), std::iter::once(piece_id).collect());

            let transfer_id = coordinator
                .start_swarm_transfer(
                    &cx,
                    "object".to_string(),
                    1024,
                    1,
                    vec![peer_a.clone(), peer_b.clone()],
                    piece_map,
                )
                .await
                .unwrap();
            let first_assignments = coordinator.assign_pieces(&cx, &transfer_id).await.unwrap();
            assert_eq!(first_assignments.len(), 1);
            assert_eq!(first_assignments[0].peer_id, peer_a.peer_id);
            assert!(
                coordinator
                    .peers
                    .get(&peer_a.peer_id)
                    .unwrap()
                    .pending_requests
                    .contains(&piece_id)
            );

            coordinator
                .handle_piece_verification_failed(
                    &cx,
                    &transfer_id,
                    piece_id,
                    &peer_a.peer_id,
                    "digest mismatch".to_string(),
                )
                .await
                .unwrap();

            assert!(
                coordinator
                    .active_transfers
                    .get(&transfer_id)
                    .unwrap()
                    .active_requests
                    .is_empty()
            );
            assert!(
                !coordinator
                    .peers
                    .get(&peer_a.peer_id)
                    .unwrap()
                    .pending_requests
                    .contains(&piece_id)
            );
            assert!(matches!(
                coordinator
                    .piece_tracker
                    .get_piece_status(&transfer_id, &piece_id)
                    .unwrap(),
                PieceStatus::Failed { peer_id, .. } if peer_id == peer_a.peer_id
            ));

            let retry_assignments = coordinator.assign_pieces(&cx, &transfer_id).await.unwrap();
            assert_eq!(retry_assignments.len(), 1);
            assert_eq!(retry_assignments[0].peer_id, peer_b.peer_id);
            assert!(matches!(
                coordinator
                    .piece_tracker
                    .get_piece_status(&transfer_id, &piece_id)
                    .unwrap(),
                PieceStatus::Requested { peer_id, .. } if peer_id == peer_b.peer_id
            ));
        });
    }

    #[test]
    fn max_transfer_duration_emits_transfer_failed_and_cleans_state() {
        block_on(async {
            let cx = Cx::for_testing();
            let mut coordinator = SwarmCoordinator::new(SwarmConfig {
                peer_quality_threshold: 0.0,
                max_pieces_per_peer: 1,
                max_transfer_duration: Duration::ZERO,
                ..SwarmConfig::default()
            });
            let (event_tx, mut event_rx) = mpsc::channel(8);
            coordinator.set_event_sink(event_tx);

            let piece_id = PieceId::new(0);
            let peer = test_peer("peer-a", [piece_id]);
            let mut piece_map = PieceMap::new(1, 1024, "test-hash".to_string());
            piece_map.add_peer_pieces(peer.peer_id.clone(), std::iter::once(piece_id).collect());

            let transfer_id = coordinator
                .start_swarm_transfer(
                    &cx,
                    "object".to_string(),
                    1024,
                    1,
                    vec![peer.clone()],
                    piece_map,
                )
                .await
                .unwrap();
            let assignments = coordinator.assign_pieces(&cx, &transfer_id).await.unwrap();
            assert_eq!(assignments.len(), 1);
            assert!(
                coordinator
                    .peers
                    .get(&peer.peer_id)
                    .unwrap()
                    .pending_requests
                    .contains(&piece_id)
            );

            coordinator.process_timeouts(&cx).await.unwrap();

            assert!(coordinator.get_transfer_status(&transfer_id).is_none());
            assert!(
                !coordinator
                    .peers
                    .get(&peer.peer_id)
                    .unwrap()
                    .pending_requests
                    .contains(&piece_id)
            );
            assert!(matches!(
                coordinator
                    .piece_tracker
                    .get_transfer_progress(&transfer_id),
                Err(SwarmError::TransferNotFound { transfer_id: missing }) if missing == transfer_id
            ));

            let mut failed_event = None;
            while let Ok(event) = event_rx.try_recv() {
                if let SwarmEvent::TransferFailed {
                    transfer_id: failed_transfer_id,
                    reason,
                    completed_pieces,
                    total_pieces,
                } = event
                {
                    failed_event =
                        Some((failed_transfer_id, reason, completed_pieces, total_pieces));
                }
            }

            let (failed_transfer_id, reason, completed_pieces, total_pieces) =
                failed_event.expect("transfer failure event must be emitted");
            assert_eq!(failed_transfer_id, transfer_id);
            assert!(reason.contains("max duration"));
            assert_eq!(completed_pieces, 0);
            assert_eq!(total_pieces, 1);
        });
    }

    #[test]
    fn test_piece_selection_strategies() {
        let needed_pieces = vec![PieceId::new(1), PieceId::new(2), PieceId::new(3)];
        let peers = std::iter::once((
            PeerId::new("peer-a"),
            test_peer(
                "peer-a",
                [PieceId::new(1), PieceId::new(2), PieceId::new(3)],
            ),
        ))
        .collect::<HashMap<_, _>>();

        let sequential = SequentialStrategy::new();
        let selected = sequential.select_pieces(&needed_pieces, &peers, 2).unwrap();
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0], PieceId::new(1));
        assert_eq!(selected[1], PieceId::new(2));
    }
