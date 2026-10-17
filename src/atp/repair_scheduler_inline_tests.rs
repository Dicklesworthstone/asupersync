    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn create_test_peer_id(port: u16) -> PeerId {
        PeerId::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            [port as u8; 32],
        )
    }

    fn create_test_peer_info(
        scheduler: &MultiSourceRepairScheduler,
        peer_id: PeerId,
        symbols: Vec<u32>,
    ) -> PeerInfo {
        PeerInfo {
            peer_id,
            available_symbols: symbols.into_iter().collect(),
            path_quality: PathQuality {
                latency_ms: 50.0,
                bandwidth_bps: 1_000_000,
                loss_rate: 0.01,
                jitter_ms: 5.0,
            },
            upload_budget_bytes: 1_000_000,
            trust_score: 0.8,
            relay_cost_per_byte: 0.001,
            churn_probability: 0.1,
            last_seen: Time::from_secs(100),
            auth_domain: scheduler.expected_auth_domain(),
        }
    }

    #[test]
    fn test_repair_scheduler_creation() {
        let scheduler = MultiSourceRepairScheduler::new(
            RepairSchedulerConfig::default(),
            crate::atp::object::ObjectId::content(crate::atp::object::ContentId::new([1u8; 32])),
            "test-group".to_string(),
            10,
        );

        assert_eq!(scheduler.k_prime, 10);
        assert!(scheduler.peers.is_empty());
    }

    #[test]
    fn test_peer_registration() {
        let mut scheduler = MultiSourceRepairScheduler::new(
            RepairSchedulerConfig::default(),
            crate::atp::object::ObjectId::content(crate::atp::object::ContentId::new([1u8; 32])),
            "test-group".to_string(),
            10,
        );

        let peer_id = create_test_peer_id(8001);
        let peer_info = create_test_peer_info(&scheduler, peer_id.clone(), vec![1, 2, 3, 4, 5]);

        assert!(scheduler.register_peer(peer_info).is_ok());
        assert!(scheduler.peers.contains_key(&peer_id));
    }

    #[test]
    fn test_peer_scoring() {
        let mut scheduler = MultiSourceRepairScheduler::new(
            RepairSchedulerConfig::default(),
            crate::atp::object::ObjectId::content(crate::atp::object::ContentId::new([1u8; 32])),
            "test-group".to_string(),
            10,
        );

        // Add peers with different qualities
        let high_quality_peer = create_test_peer_id(8001);
        let high_quality_info =
            create_test_peer_info(&scheduler, high_quality_peer.clone(), vec![1, 2, 3]);

        let low_quality_peer = create_test_peer_id(8002);
        let mut low_quality_info =
            create_test_peer_info(&scheduler, low_quality_peer.clone(), vec![4, 5, 6]);
        low_quality_info.path_quality.latency_ms = 200.0;
        low_quality_info.trust_score = 0.3;

        scheduler.register_peer(high_quality_info).unwrap();
        scheduler.register_peer(low_quality_info).unwrap();

        let scores = scheduler.calculate_peer_scores();

        let high_score = scores.get(&high_quality_peer).unwrap();
        let low_score = scores.get(&low_quality_peer).unwrap();

        assert!(
            high_score > low_score,
            "High quality peer should have better score"
        );
    }

    #[test]
    fn test_relay_cost_and_churn_penalize_worse_peers() {
        // Regression: relay_cost / churn weights are negative, so a cheaper,
        // more stable peer must score HIGHER than an expensive, churny one.
        // The previous code inverted the metrics before applying the negative
        // weight (double negation), penalizing the better peer.
        let scheduler = MultiSourceRepairScheduler::new(
            RepairSchedulerConfig::default(),
            crate::atp::object::ObjectId::content(crate::atp::object::ContentId::new([1u8; 32])),
            "test-group".to_string(),
            10,
        );

        let mut cheap_stable =
            create_test_peer_info(&scheduler, create_test_peer_id(9001), vec![1]);
        cheap_stable.relay_cost_per_byte = 0.0;
        cheap_stable.churn_probability = 0.0;

        let mut expensive_churny =
            create_test_peer_info(&scheduler, create_test_peer_id(9002), vec![1]);
        expensive_churny.relay_cost_per_byte = 0.001; // caps at normalized 1.0
        expensive_churny.churn_probability = 1.0;

        let cheap_score = scheduler.calculate_individual_peer_score(&cheap_stable);
        let expensive_score = scheduler.calculate_individual_peer_score(&expensive_churny);

        assert!(
            cheap_score > expensive_score,
            "cheap/stable peer ({cheap_score}) must outscore expensive/churny ({expensive_score})"
        );
    }

    #[test]
    fn select_best_peer_accepts_available_peer_with_negative_score() {
        let mut scheduler = MultiSourceRepairScheduler::new(
            RepairSchedulerConfig::default(),
            crate::atp::object::ObjectId::content(crate::atp::object::ContentId::new([1u8; 32])),
            "test-group".to_string(),
            10,
        );

        let peer_id = create_test_peer_id(8103);
        let peer_info = create_test_peer_info(&scheduler, peer_id.clone(), vec![7]);
        scheduler.register_peer(peer_info).unwrap();

        let mut peer_scores = HashMap::new();
        peer_scores.insert(peer_id.clone(), -0.5);

        assert_eq!(
            scheduler.select_best_peer_for_symbol(7, &peer_scores, &HashMap::new(), true),
            Some(peer_id),
            "an available peer remains selectable even when policy scoring is non-positive"
        );
    }

    #[test]
    fn test_symbols_needed_tracks_decode_rank_not_received_count() {
        // Regression: a linearly-dependent symbol raises the received count
        // without advancing decode rank; need must be measured against rank,
        // otherwise the scheduler reports 0 needed while decode is impossible.
        let mut scheduler = MultiSourceRepairScheduler::new(
            RepairSchedulerConfig::default(),
            crate::atp::object::ObjectId::content(crate::atp::object::ContentId::new([1u8; 32])),
            "test-group".to_string(),
            3,
        );

        // Two independent source symbols → decode rank 2 (k_prime is 3).
        scheduler.decode_matrix.add_symbol(0, &[1u8; 32]).unwrap();
        scheduler.decode_matrix.add_symbol(1, &[2u8; 32]).unwrap();
        assert_eq!(scheduler.decode_matrix.decode_rank, 2);

        // A third symbol is received and counted, but it was linearly
        // dependent (no rank gain). The scheduler's received set therefore
        // holds 3 entries while decode rank is still 2 and decode is
        // impossible.
        scheduler.received_symbols.insert(0);
        scheduler.received_symbols.insert(1);
        scheduler.received_symbols.insert(2);

        assert!(!scheduler.decode_matrix.can_decode());
        // Old (buggy) formula: k_prime(3) - received_count(3) = 0 → stall.
        // New formula: k_prime(3) - decode_rank(2) = 1 → keep requesting.
        assert_eq!(
            scheduler.calculate_symbols_needed(),
            1,
            "need must follow decode rank, not received count"
        );
    }

    #[test]
    fn test_symbol_rarity_calculation() {
        let mut scheduler = MultiSourceRepairScheduler::new(
            RepairSchedulerConfig::default(),
            crate::atp::object::ObjectId::content(crate::atp::object::ContentId::new([1u8; 32])),
            "test-group".to_string(),
            10,
        );

        // Peer 1 has symbols 1, 2, 3
        let peer1 = create_test_peer_info(&scheduler, create_test_peer_id(8001), vec![1, 2, 3]);
        // Peer 2 has symbols 2, 3, 4 (symbol 2 and 3 are common)
        let peer2 = create_test_peer_info(&scheduler, create_test_peer_id(8002), vec![2, 3, 4]);

        scheduler.register_peer(peer1).unwrap();
        scheduler.register_peer(peer2).unwrap();

        // Symbol 1 should be rarer (only peer1 has it)
        let rarity_1 = scheduler.symbol_rarity_map.get(&1).unwrap();
        let rarity_2 = scheduler.symbol_rarity_map.get(&2).unwrap();

        assert!(
            rarity_1 > rarity_2,
            "Symbol 1 should be rarer than symbol 2"
        );
    }

    #[test]
    fn peer_reregistration_recalculates_symbol_rarity_without_stale_counts() {
        let mut scheduler = MultiSourceRepairScheduler::new(
            RepairSchedulerConfig::default(),
            crate::atp::object::ObjectId::content(crate::atp::object::ContentId::new([1u8; 32])),
            "test-group".to_string(),
            10,
        );

        let peer1_id = create_test_peer_id(8104);
        let peer2_id = create_test_peer_id(8105);

        let peer1_initial = create_test_peer_info(&scheduler, peer1_id.clone(), vec![1, 2]);
        let peer2_initial = create_test_peer_info(&scheduler, peer2_id.clone(), vec![2]);
        scheduler.register_peer(peer1_initial).unwrap();
        scheduler.register_peer(peer2_initial).unwrap();

        assert_eq!(scheduler.symbol_rarity_map.get(&2), Some(&0.5));

        let peer1_updated = create_test_peer_info(&scheduler, peer1_id, vec![1]);
        scheduler.register_peer(peer1_updated).unwrap();

        assert_eq!(
            scheduler.symbol_rarity_map.get(&2),
            Some(&1.0),
            "re-registering a peer must drop its old symbol inventory before recounting rarity"
        );

        let peer2_updated = create_test_peer_info(&scheduler, peer2_id, vec![3]);
        scheduler.register_peer(peer2_updated).unwrap();

        assert!(
            !scheduler.symbol_rarity_map.contains_key(&2),
            "symbols no current peer advertises must not remain in the rarity map"
        );
    }

    #[test]
    fn most_useful_symbols_deduplicates_non_adjacent_peer_overlap() {
        let mut scheduler = MultiSourceRepairScheduler::new(
            RepairSchedulerConfig::default(),
            crate::atp::object::ObjectId::content(crate::atp::object::ContentId::new([1u8; 32])),
            "test-group".to_string(),
            4,
        );

        let peer1 = create_test_peer_info(&scheduler, create_test_peer_id(8101), vec![1, 3]);
        let peer2 = create_test_peer_info(&scheduler, create_test_peer_id(8102), vec![1, 2]);

        scheduler.register_peer(peer1).unwrap();
        scheduler.register_peer(peer2).unwrap();

        let useful_symbols = scheduler.get_most_useful_symbols(4);
        let unique_symbols: BTreeSet<u32> = useful_symbols.iter().copied().collect();

        assert_eq!(
            useful_symbols.len(),
            unique_symbols.len(),
            "overlapping peers must not schedule the same symbol twice"
        );
        assert_eq!(unique_symbols, BTreeSet::from([1, 2, 3]));
    }

    #[test]
    fn test_symbol_request_scheduling() {
        let mut scheduler = MultiSourceRepairScheduler::new(
            RepairSchedulerConfig::default(),
            crate::atp::object::ObjectId::content(crate::atp::object::ContentId::new([1u8; 32])),
            "test-group".to_string(),
            5,
        );

        let peer_info =
            create_test_peer_info(&scheduler, create_test_peer_id(8001), vec![1, 2, 3, 4, 5]);
        scheduler.register_peer(peer_info).unwrap();

        let requests = scheduler
            .schedule_next_batch_at(Time::from_secs(10))
            .unwrap();

        assert!(!requests.is_empty(), "Should schedule some requests");
        assert!(requests.len() <= 5, "Should not request more than needed");
    }

    #[test]
    fn test_symbol_processing() {
        let mut scheduler = MultiSourceRepairScheduler::new(
            RepairSchedulerConfig::default(),
            crate::atp::object::ObjectId::content(crate::atp::object::ContentId::new([1u8; 32])),
            "test-group".to_string(),
            3,
        );

        let peer_id = create_test_peer_id(8001);
        let peer_info = create_test_peer_info(&scheduler, peer_id.clone(), vec![1, 2, 3]);
        scheduler.register_peer(peer_info).unwrap();

        // Schedule a request
        let requests = scheduler
            .schedule_next_batch_at(Time::from_secs(10))
            .unwrap();
        assert!(!requests.is_empty());

        // Process received symbol
        let symbol_data = vec![0u8; 100];
        let result = scheduler
            .process_received_symbol(1, &symbol_data, &peer_id)
            .unwrap();

        match result {
            SymbolProcessResult::Accepted {
                decode_contribution,
                ..
            } => {
                assert!(decode_contribution > 0.0);
            }
            SymbolProcessResult::Rejected { .. } => {
                panic!("Symbol should have been accepted");
            }
        }

        assert!(scheduler.received_symbols.contains(&1));
    }

    #[test]
    fn received_symbol_from_unrequested_peer_is_rejected_without_poisoning_decode() {
        let mut scheduler = MultiSourceRepairScheduler::new(
            RepairSchedulerConfig::default(),
            crate::atp::object::ObjectId::content(crate::atp::object::ContentId::new([1u8; 32])),
            "test-group".to_string(),
            3,
        );

        // Every scheduled request is assigned to the only registered peer.
        let requested_peer = create_test_peer_id(8001);
        let requested_info =
            create_test_peer_info(&scheduler, requested_peer.clone(), vec![1, 2, 3]);
        scheduler.register_peer(requested_info).unwrap();

        let requests = scheduler
            .schedule_next_batch_at(Time::from_secs(10))
            .unwrap();
        assert!(!requests.is_empty(), "expected scheduled requests");
        let hijacked_index = requests[0].symbol_index;
        assert!(
            requests[0].peer_id == requested_peer,
            "request must be assigned to the registered peer"
        );

        // A different, registered peer tries to answer that request. Even a
        // known peer must not be able to hijack another peer's symbol.
        let attacker = create_test_peer_id(9999);
        let attacker_info = create_test_peer_info(&scheduler, attacker.clone(), vec![1, 2, 3]);
        scheduler.register_peer(attacker_info).unwrap();
        let attacker_trust_before = scheduler.peers.get(&attacker).unwrap().trust_score;

        let symbol_data = vec![7u8; 100];
        let result = scheduler
            .process_received_symbol(hijacked_index, &symbol_data, &attacker)
            .unwrap();

        match result {
            SymbolProcessResult::Rejected { reason } => assert!(
                matches!(reason, RejectionReason::MaliciousPeer { .. }),
                "hijacked symbol must be flagged malicious, got {reason:?}"
            ),
            SymbolProcessResult::Accepted { .. } => {
                panic!("a symbol delivered by a peer it was not requested from must be rejected")
            }
        }

        // The decode matrix must not be poisoned by the hijack attempt...
        assert!(
            !scheduler.received_symbols.contains(&hijacked_index),
            "rejected hijack must not be recorded as received"
        );
        // ...and the legitimate outstanding request must remain so the honest
        // peer can still deliver the symbol.
        assert!(
            scheduler.pending_requests.contains_key(&hijacked_index),
            "forged response must not cancel the honest peer's pending request"
        );
        let attacker_trust_after = scheduler.peers.get(&attacker).unwrap().trust_score;
        assert!(
            attacker_trust_after < attacker_trust_before,
            "default malicious detection should decay trust on a hijack attempt"
        );

        // The honest peer's later delivery is still accepted.
        let honest = scheduler
            .process_received_symbol(hijacked_index, &symbol_data, &requested_peer)
            .unwrap();
        assert!(
            matches!(honest, SymbolProcessResult::Accepted { .. }),
            "the requested peer's delivery must still be accepted"
        );
    }

    #[test]
    fn malicious_detection_flag_only_controls_trust_decay() {
        let config = RepairSchedulerConfig {
            enable_malicious_detection: false,
            ..RepairSchedulerConfig::default()
        };
        let mut scheduler = MultiSourceRepairScheduler::new(
            config,
            crate::atp::object::ObjectId::content(crate::atp::object::ContentId::new([1u8; 32])),
            "test-group".to_string(),
            3,
        );

        let requested_peer = create_test_peer_id(8011);
        let attacker = create_test_peer_id(8012);
        scheduler
            .register_peer(create_test_peer_info(
                &scheduler,
                requested_peer.clone(),
                vec![1, 2, 3],
            ))
            .unwrap();
        scheduler
            .register_peer(create_test_peer_info(
                &scheduler,
                attacker.clone(),
                vec![1, 2, 3],
            ))
            .unwrap();

        let requests = scheduler
            .schedule_next_batch_at(Time::from_secs(10))
            .unwrap();
        let symbol_index = requests[0].symbol_index;
        let attacker_trust_before = scheduler.peers.get(&attacker).unwrap().trust_score;

        let result = scheduler
            .process_received_symbol(symbol_index, &[7u8; 100], &attacker)
            .unwrap();

        assert!(
            matches!(
                result,
                SymbolProcessResult::Rejected {
                    reason: RejectionReason::MaliciousPeer { .. }
                }
            ),
            "wrong-peer delivery must still fail closed even when trust decay is disabled"
        );
        assert!(
            scheduler.pending_requests.contains_key(&symbol_index),
            "wrong-peer delivery must not consume the honest peer's pending request"
        );
        assert_eq!(
            scheduler.peers.get(&attacker).unwrap().trust_score,
            attacker_trust_before,
            "disabling malicious detection should disable attacker trust decay only"
        );
    }

    #[test]
    fn timed_out_request_decays_the_assigned_peer_trust() {
        let mut scheduler = MultiSourceRepairScheduler::new(
            RepairSchedulerConfig::default(),
            crate::atp::object::ObjectId::content(crate::atp::object::ContentId::new([1u8; 32])),
            "test-group".to_string(),
            3,
        );

        let peer_id = create_test_peer_id(8001);
        let peer_info = create_test_peer_info(&scheduler, peer_id.clone(), vec![1, 2, 3]);
        scheduler.register_peer(peer_info).unwrap();

        let start = Time::from_secs(10);
        let requests = scheduler.schedule_next_batch_at(start).unwrap();
        assert!(!requests.is_empty(), "expected scheduled requests");
        assert!(
            requests.iter().all(|request| request.requested_at == start),
            "requests must inherit the explicit logical scheduling time"
        );
        assert!(
            requests
                .iter()
                .all(|request| request.timeout_at
                    == start + scheduler.config.symbol_timeout_duration),
            "request deadlines must derive from the explicit logical scheduling time"
        );

        let trust_before = scheduler.peers.get(&peer_id).unwrap().trust_score;

        // Advance past the request timeout and run the cleanup sweep.
        let later = start + scheduler.config.symbol_timeout_duration + Duration::from_secs(1);
        scheduler.cleanup_timed_out_requests(later);

        let trust_after = scheduler.peers.get(&peer_id).unwrap().trust_score;
        assert!(
            trust_after < trust_before,
            "a timed-out peer's trust must decay: {trust_before} -> {trust_after}"
        );
        assert!(
            scheduler.pending_requests.is_empty(),
            "timed-out requests must be cleared"
        );
        assert_eq!(
            scheduler.get_decode_progress().rejected_symbols,
            requests.len(),
            "every timed-out request is counted as rejected"
        );
    }

    #[test]
    fn timed_out_symbol_stops_after_configured_retries() {
        let config = RepairSchedulerConfig {
            max_symbol_retries: 1,
            ..RepairSchedulerConfig::default()
        };
        let mut scheduler = MultiSourceRepairScheduler::new(
            config,
            crate::atp::object::ObjectId::content(crate::atp::object::ContentId::new([1u8; 32])),
            "test-group".to_string(),
            1,
        );

        let peer_id = create_test_peer_id(8001);
        let peer_info = create_test_peer_info(&scheduler, peer_id, vec![1]);
        scheduler.register_peer(peer_info).unwrap();

        let first_start = Time::from_secs(10);
        let first = scheduler.schedule_next_batch_at(first_start).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].symbol_index, 1);
        assert_eq!(first[0].retry_count, 0);

        scheduler.cleanup_timed_out_requests(
            first_start + scheduler.config.symbol_timeout_duration + Duration::from_secs(1),
        );

        let retry_start = Time::from_secs(50);
        let retry = scheduler.schedule_next_batch_at(retry_start).unwrap();
        assert_eq!(retry.len(), 1);
        assert_eq!(retry[0].symbol_index, 1);
        assert_eq!(
            retry[0].retry_count, 1,
            "the next request must carry the preserved retry count"
        );

        scheduler.cleanup_timed_out_requests(
            retry_start + scheduler.config.symbol_timeout_duration + Duration::from_secs(1),
        );

        let exhausted = scheduler
            .schedule_next_batch_at(Time::from_secs(90))
            .unwrap();
        assert!(
            exhausted.is_empty(),
            "symbol 1 already had its initial attempt plus one configured retry"
        );
        assert_eq!(scheduler.retry_count_for_symbol(1), 2);
        assert_eq!(scheduler.get_decode_progress().rejected_symbols, 2);
    }

    #[test]
    fn unregistered_peer_request_consumes_retry_budget() {
        let config = RepairSchedulerConfig {
            max_symbol_retries: 1,
            ..RepairSchedulerConfig::default()
        };
        let mut scheduler = MultiSourceRepairScheduler::new(
            config,
            crate::atp::object::ObjectId::content(crate::atp::object::ContentId::new([1u8; 32])),
            "test-group".to_string(),
            1,
        );

        let first_peer = create_test_peer_id(8001);
        let retry_peer = create_test_peer_id(8002);
        let exhausted_peer = create_test_peer_id(8003);

        for peer in [&first_peer, &retry_peer, &exhausted_peer] {
            let info = create_test_peer_info(&scheduler, peer.clone(), vec![1]);
            scheduler.register_peer(info).unwrap();
        }

        let first = scheduler
            .schedule_next_batch_at(Time::from_secs(10))
            .unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].peer_id, first_peer);
        assert_eq!(first[0].retry_count, 0);

        scheduler.unregister_peer(&first_peer);
        assert!(scheduler.pending_requests.is_empty());
        assert_eq!(scheduler.retry_count_for_symbol(1), 1);
        assert_eq!(scheduler.get_decode_progress().rejected_symbols, 1);
        assert!(
            matches!(
                scheduler.rejected_requests.back().map(|(_, reason)| reason),
                Some(RejectionReason::PeerUnavailable { .. })
            ),
            "peer departure must be recorded as an unavailable-peer rejection"
        );

        let retry = scheduler
            .schedule_next_batch_at(Time::from_secs(20))
            .unwrap();
        assert_eq!(retry.len(), 1);
        assert_eq!(retry[0].peer_id, retry_peer);
        assert_eq!(
            retry[0].retry_count, 1,
            "peer departure must preserve the retry count for the next request"
        );

        scheduler.unregister_peer(&retry_peer);
        assert_eq!(scheduler.retry_count_for_symbol(1), 2);

        let exhausted = scheduler
            .schedule_next_batch_at(Time::from_secs(30))
            .unwrap();
        assert!(
            exhausted.is_empty(),
            "initial request plus one configured retry were already consumed by peer churn"
        );
        assert_eq!(scheduler.get_decode_progress().rejected_symbols, 2);
    }

    #[test]
    fn rejected_request_history_is_bounded_but_total_count_is_exact() {
        let mut scheduler = MultiSourceRepairScheduler::new(
            RepairSchedulerConfig::default(),
            crate::atp::object::ObjectId::content(crate::atp::object::ContentId::new([1u8; 32])),
            "test-group".to_string(),
            3,
        );

        let peer_id = create_test_peer_id(8001);
        let total = MAX_RETAINED_REJECTIONS + 50;
        for index in 0..total {
            let request = RepairSymbolRequest {
                symbol_index: index as u32,
                peer_id: peer_id.clone(),
                requested_at: Time::from_secs(10),
                decode_usefulness: 0.0,
                retry_count: 0,
                timeout_at: Time::from_secs(10),
            };
            scheduler.record_rejection(request, RejectionReason::DuplicateSymbol);
        }

        assert!(
            scheduler.rejected_requests.len() <= MAX_RETAINED_REJECTIONS,
            "retained rejection history must stay bounded"
        );
        assert_eq!(
            scheduler.get_decode_progress().rejected_symbols,
            total,
            "lifetime rejected count must remain exact despite bounded retention"
        );
    }

    #[test]
    fn schedule_next_batch_enforces_per_peer_fairness() {
        let config = RepairSchedulerConfig {
            max_symbols_per_peer_batch: 2,
            max_concurrent_peers: 3,
            ..RepairSchedulerConfig::default()
        };
        let mut scheduler = MultiSourceRepairScheduler::new(
            config,
            crate::atp::object::ObjectId::content(crate::atp::object::ContentId::new([1u8; 32])),
            "test-group".to_string(),
            20,
        );

        // Five peers all advertise the same broad symbol inventory, so a naive
        // argmax selection could route every request to a single peer.
        let symbols: Vec<u32> = (0..20).collect();
        for port in 0..5u16 {
            let peer = create_test_peer_id(9000 + port);
            let info = create_test_peer_info(&scheduler, peer, symbols.clone());
            scheduler.register_peer(info).unwrap();
        }

        let requests = scheduler
            .schedule_next_batch_at(Time::from_secs(10))
            .unwrap();
        assert!(!requests.is_empty(), "expected scheduled requests");

        let mut per_peer: HashMap<PeerId, usize> = HashMap::new();
        for req in &requests {
            *per_peer.entry(req.peer_id.clone()).or_insert(0) += 1;
        }
        assert!(
            per_peer.values().all(|&n| n <= 2),
            "no peer may exceed max_symbols_per_peer_batch=2: {:?}",
            per_peer.values().collect::<Vec<_>>()
        );
        assert!(
            per_peer.len() <= 3,
            "no more than max_concurrent_peers=3 distinct peers may be used, got {}",
            per_peer.len()
        );
    }

    #[test]
    fn peer_selection_is_deterministic_on_tied_scores() {
        let mut scheduler = MultiSourceRepairScheduler::new(
            RepairSchedulerConfig::default(),
            crate::atp::object::ObjectId::content(crate::atp::object::ContentId::new([1u8; 32])),
            "test-group".to_string(),
            3,
        );

        // Register peers out of address order; they share identical scoring
        // inputs, so selection is a pure tie-break. With deterministic
        // (BTreeMap) peer iteration the smallest PeerId must always win,
        // independent of registration/hash order.
        for port in [8003u16, 8001, 8002] {
            let info = create_test_peer_info(&scheduler, create_test_peer_id(port), vec![1, 2, 3]);
            scheduler.register_peer(info).unwrap();
        }

        let peer_scores = scheduler.calculate_peer_scores();
        let selected = scheduler
            .select_best_peer_for_symbol(1, &peer_scores, &HashMap::new(), true)
            .expect("a peer must be selectable");
        assert_eq!(
            selected,
            create_test_peer_id(8001),
            "tied-score selection must be deterministic (smallest PeerId wins)"
        );
    }

    #[test]
    fn test_decode_progress() {
        let mut scheduler = MultiSourceRepairScheduler::new(
            RepairSchedulerConfig::default(),
            crate::atp::object::ObjectId::content(crate::atp::object::ContentId::new([1u8; 32])),
            "test-group".to_string(),
            3,
        );

        let progress = scheduler.get_decode_progress();
        assert_eq!(progress.symbols_received, 0);
        assert_eq!(progress.symbols_needed, 3);
        assert!(!scheduler.is_decode_complete());

        // Add some symbols
        scheduler.received_symbols.insert(1);
        scheduler.decode_matrix.add_symbol(1, &[0u8; 100]).unwrap();

        let progress = scheduler.get_decode_progress();
        assert_eq!(progress.symbols_received, 1);
        assert!(progress.decode_progress_ratio > 0.0);
    }
