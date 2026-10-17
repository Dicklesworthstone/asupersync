    use super::*;

    fn create_test_piece_map() -> PieceMap {
        let mut piece_map = PieceMap::new(10, 1024, "test-hash".to_string());

        let peer1 = PeerId::new("peer1");
        let peer2 = PeerId::new("peer2");

        piece_map.add_peer_pieces(peer1, (0..5).map(PieceId::new).collect());
        piece_map.add_peer_pieces(peer2, (3..10).map(PieceId::new).collect());

        piece_map
    }

    #[test]
    fn test_piece_tracker_creation() {
        let tracker = PieceTracker::new();
        assert_eq!(tracker.transfer_maps.len(), 0);
        assert_eq!(tracker.global_availability.len(), 0);
    }

    #[test]
    fn test_initialize_transfer() {
        let mut tracker = PieceTracker::new();
        let piece_map = create_test_piece_map();
        let transfer_id = MailboxTransferId::new();

        let result = tracker.initialize_transfer(&transfer_id, &piece_map);
        assert!(result.is_ok());
        assert!(tracker.transfer_maps.contains_key(&transfer_id));
    }

    #[test]
    fn initialize_transfer_rejects_excessive_piece_count_before_allocation() {
        let mut tracker = PieceTracker::new();
        let piece_map = PieceMap::new(
            MAX_TRACKED_PIECES_PER_TRANSFER + 1,
            1024,
            "test-hash".to_string(),
        );
        let transfer_id = MailboxTransferId::new();

        let err = tracker
            .initialize_transfer(&transfer_id, &piece_map)
            .expect_err("excessive piece count must be rejected");

        assert!(
            matches!(&err, SwarmError::ConfigurationError { details } if details.contains("exceeding tracker limit")),
            "unexpected error: {err}"
        );
        assert!(tracker.transfer_maps.is_empty());
        assert!(tracker.global_availability.is_empty());
    }

    #[test]
    fn initialize_transfer_rejects_out_of_range_peer_piece() {
        let mut tracker = PieceTracker::new();
        let mut piece_map = PieceMap::new(2, 1024, "test-hash".to_string());
        piece_map.add_peer_pieces(
            PeerId::new("peer1"),
            [PieceId::new(0), PieceId::new(2)].into_iter().collect(),
        );
        let transfer_id = MailboxTransferId::new();

        let err = tracker
            .initialize_transfer(&transfer_id, &piece_map)
            .expect_err("out-of-range advertised piece must be rejected");

        assert!(
            matches!(&err, SwarmError::ConfigurationError { details } if details.contains("outside declared range 0..2")),
            "unexpected error: {err}"
        );
        assert!(tracker.transfer_maps.is_empty());
        assert!(tracker.global_availability.is_empty());
    }

    #[test]
    fn test_get_needed_pieces() {
        let mut tracker = PieceTracker::new();
        let piece_map = create_test_piece_map();
        let transfer_id = MailboxTransferId::new();

        tracker
            .initialize_transfer(&transfer_id, &piece_map)
            .unwrap();
        let needed = tracker.get_needed_pieces(&transfer_id).unwrap();

        assert_eq!(needed.len(), 10); // All pieces initially needed
    }

    #[test]
    fn test_piece_status_transitions() {
        let mut tracker = PieceTracker::new();
        let piece_map = create_test_piece_map();
        let transfer_id = MailboxTransferId::new();
        let piece_id = PieceId::new(0);
        let peer_id = PeerId::new("peer1");

        tracker
            .initialize_transfer(&transfer_id, &piece_map)
            .unwrap();

        // Test requested -> downloading -> completed
        tracker
            .mark_piece_requested(&transfer_id, piece_id, peer_id.clone())
            .unwrap();
        let status = tracker.get_piece_status(&transfer_id, &piece_id).unwrap();
        assert!(matches!(status, PieceStatus::Requested { .. }));

        tracker
            .mark_piece_downloading(&transfer_id, piece_id, peer_id.clone())
            .unwrap();
        let status = tracker.get_piece_status(&transfer_id, &piece_id).unwrap();
        assert!(matches!(status, PieceStatus::Downloading { .. }));

        tracker
            .mark_piece_completed(&transfer_id, piece_id)
            .unwrap();
        let status = tracker.get_piece_status(&transfer_id, &piece_id).unwrap();
        assert!(matches!(status, PieceStatus::Completed { .. }));
    }

    #[test]
    fn completed_piece_cannot_be_regressed_to_failed() {
        let mut tracker = PieceTracker::new();
        let piece_map = create_test_piece_map();
        let transfer_id = MailboxTransferId::new();
        let piece_id = PieceId::new(0);
        let peer_id = PeerId::new("peer1");

        tracker
            .initialize_transfer(&transfer_id, &piece_map)
            .unwrap();
        tracker
            .mark_piece_downloading(&transfer_id, piece_id, peer_id.clone())
            .unwrap();
        tracker
            .mark_piece_completed(&transfer_id, piece_id)
            .unwrap();

        tracker
            .mark_piece_failed(
                &transfer_id,
                piece_id,
                "late verification failure".to_string(),
            )
            .unwrap();

        let status = tracker.get_piece_status(&transfer_id, &piece_id).unwrap();
        assert!(
            matches!(status, PieceStatus::Completed { peer_id: completed_by, .. } if completed_by == peer_id)
        );
        let needed = tracker.get_needed_pieces(&transfer_id).unwrap();
        assert!(
            !needed.contains(&piece_id),
            "completed piece must not re-enter the retry set"
        );
        let progress = tracker.get_transfer_progress(&transfer_id).unwrap();
        assert_eq!(progress.completed, 1);
        assert_eq!(progress.failed, 0);
        assert_eq!(progress.needed, 9);
        assert_eq!(progress.completion_percentage, 10.0);
    }

    #[test]
    fn failed_piece_does_not_synthesize_unknown_peer() {
        let mut tracker = PieceTracker::new();
        let piece_map = create_test_piece_map();
        let transfer_id = MailboxTransferId::new();
        let unassigned_piece = PieceId::new(1);
        let requested_piece = PieceId::new(0);
        let real_unknown_peer = PeerId::new("unknown");

        tracker
            .initialize_transfer(&transfer_id, &piece_map)
            .unwrap();

        let err = tracker
            .mark_piece_failed(
                &transfer_id,
                unassigned_piece,
                "failure before request".to_string(),
            )
            .expect_err("unassigned failures must not invent a peer id");
        assert!(
            matches!(&err, SwarmError::InvalidPieceState { piece_id, current_state } if *piece_id == unassigned_piece && current_state == "needed"),
            "unexpected error: {err}"
        );
        assert!(matches!(
            tracker
                .get_piece_status(&transfer_id, &unassigned_piece)
                .unwrap(),
            PieceStatus::Needed
        ));

        tracker
            .mark_piece_requested(&transfer_id, requested_piece, real_unknown_peer.clone())
            .unwrap();
        tracker
            .mark_piece_failed(
                &transfer_id,
                requested_piece,
                "real peer named unknown failed".to_string(),
            )
            .unwrap();

        let status = tracker
            .get_piece_status(&transfer_id, &requested_piece)
            .unwrap();
        assert!(
            matches!(status, PieceStatus::Failed { peer_id, .. } if peer_id == real_unknown_peer)
        );
    }

    #[test]
    fn cleanup_transfer_preserves_other_transfer_availability_for_same_piece() {
        let mut tracker = PieceTracker::new();
        let transfer_a = MailboxTransferId::new();
        let transfer_b = MailboxTransferId::new();
        let piece_id = PieceId::new(0);
        let peer_a = PeerId::new("peer-a");
        let peer_b = PeerId::new("peer-b");

        let mut map_a = PieceMap::new(1, 1024, "hash-a".to_string());
        map_a.add_peer_pieces(peer_a.clone(), std::iter::once(piece_id).collect());
        let mut map_b = PieceMap::new(1, 1024, "hash-b".to_string());
        map_b.add_peer_pieces(peer_b.clone(), std::iter::once(piece_id).collect());

        tracker.initialize_transfer(&transfer_a, &map_a).unwrap();
        tracker.initialize_transfer(&transfer_b, &map_b).unwrap();
        assert_eq!(tracker.global_availability.len(), 2);

        tracker.cleanup_transfer(&transfer_a);

        assert!(!tracker.transfer_maps.contains_key(&transfer_a));
        assert!(tracker.transfer_maps.contains_key(&transfer_b));
        assert!(!tracker.global_availability.contains_key(&AvailabilityKey {
            transfer_id: transfer_a,
            piece_id,
        }));

        let remaining_peers = tracker
            .global_availability
            .get(&AvailabilityKey {
                transfer_id: transfer_b,
                piece_id,
            })
            .expect("second transfer availability must remain");
        assert_eq!(remaining_peers.len(), 1);
        assert!(remaining_peers.contains(&peer_b));
        assert!(!remaining_peers.contains(&peer_a));
    }

    #[test]
    fn remove_peer_drops_availability_and_retries_inflight_pieces() {
        let mut tracker = PieceTracker::new();
        let transfer_id = MailboxTransferId::new();
        let peer_a = PeerId::new("peer-a");
        let peer_b = PeerId::new("peer-b");
        let piece_a = PieceId::new(0);
        let shared_piece = PieceId::new(1);
        let mut piece_map = PieceMap::new(2, 1024, "test-hash".to_string());
        piece_map.add_peer_pieces(
            peer_a.clone(),
            [piece_a, shared_piece].into_iter().collect(),
        );
        piece_map.add_peer_pieces(peer_b.clone(), std::iter::once(shared_piece).collect());

        tracker
            .initialize_transfer(&transfer_id, &piece_map)
            .unwrap();
        tracker
            .mark_piece_requested(&transfer_id, piece_a, peer_a.clone())
            .unwrap();
        tracker
            .mark_piece_downloading(&transfer_id, shared_piece, peer_b.clone())
            .unwrap();

        tracker.remove_peer(&peer_a);

        assert!(
            tracker
                .get_peer_pieces(&transfer_id, &peer_a)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            tracker.get_peer_pieces(&transfer_id, &peer_b).unwrap(),
            std::iter::once(shared_piece).collect()
        );
        assert_eq!(
            tracker
                .get_piece_redundancy(&transfer_id, &piece_a)
                .unwrap(),
            0
        );
        assert_eq!(
            tracker
                .get_piece_redundancy(&transfer_id, &shared_piece)
                .unwrap(),
            1
        );

        let failed_status = tracker.get_piece_status(&transfer_id, &piece_a).unwrap();
        assert!(
            matches!(failed_status, PieceStatus::Failed { peer_id, reason, .. } if peer_id == peer_a && reason == "peer removed")
        );
        let shared_status = tracker
            .get_piece_status(&transfer_id, &shared_piece)
            .unwrap();
        assert!(
            matches!(shared_status, PieceStatus::Downloading { peer_id, .. } if peer_id == peer_b)
        );

        let needed = tracker.get_needed_pieces(&transfer_id).unwrap();
        assert!(needed.contains(&piece_a));
        assert!(!needed.contains(&shared_piece));
        assert!(!tracker.global_availability.contains_key(&AvailabilityKey {
            transfer_id,
            piece_id: piece_a,
        }));
        let remaining_peers = tracker
            .global_availability
            .get(&AvailabilityKey {
                transfer_id,
                piece_id: shared_piece,
            })
            .expect("shared piece availability must remain");
        assert_eq!(remaining_peers.len(), 1);
        assert!(remaining_peers.contains(&peer_b));
    }

    #[test]
    fn test_transfer_progress() {
        let mut tracker = PieceTracker::new();
        let piece_map = create_test_piece_map();
        let transfer_id = MailboxTransferId::new();

        tracker
            .initialize_transfer(&transfer_id, &piece_map)
            .unwrap();

        // Complete one piece
        let piece_id = PieceId::new(0);
        let peer_id = PeerId::new("peer1");
        tracker
            .mark_piece_downloading(&transfer_id, piece_id, peer_id)
            .unwrap();
        tracker
            .mark_piece_completed(&transfer_id, piece_id)
            .unwrap();

        let progress = tracker.get_transfer_progress(&transfer_id).unwrap();
        assert_eq!(progress.total_pieces, 10);
        assert_eq!(progress.completed, 1);
        assert_eq!(progress.needed, 9);
        assert_eq!(progress.completion_percentage, 10.0);
    }

    #[test]
    fn test_piece_map_redundancy() {
        let piece_map = create_test_piece_map();

        // Piece 0: only on peer1 (redundancy 1)
        assert_eq!(piece_map.get_piece_redundancy(&PieceId::new(0)), 1);

        // Piece 4: on both peers (redundancy 2)
        assert_eq!(piece_map.get_piece_redundancy(&PieceId::new(4)), 2);

        // Piece 8: only on peer2 (redundancy 1)
        assert_eq!(piece_map.get_piece_redundancy(&PieceId::new(8)), 1);

        let stats = piece_map.get_distribution_stats();
        assert_eq!(stats.min_redundancy, 1);
        assert_eq!(stats.max_redundancy, 2);
    }

    #[test]
    fn test_pieces_by_rarity() {
        let mut tracker = PieceTracker::new();
        let piece_map = create_test_piece_map();
        let transfer_id = MailboxTransferId::new();

        tracker
            .initialize_transfer(&transfer_id, &piece_map)
            .unwrap();
        let by_rarity = tracker.get_pieces_by_rarity(&transfer_id).unwrap();

        // Should be sorted with rarest pieces (redundancy 1) first
        assert_eq!(by_rarity.len(), 10);
    }
