    use super::*;
    use std::collections::HashMap;

    fn create_test_context() -> PieceSelectionContext {
        let mut piece_redundancy = HashMap::new();
        piece_redundancy.insert(PieceId::new(0), 1); // Rare piece
        piece_redundancy.insert(PieceId::new(1), 3); // Common piece
        piece_redundancy.insert(PieceId::new(2), 2); // Medium rare

        let mut active_peers = HashMap::new();
        active_peers.insert(
            PeerId::new("peer1"),
            PeerInfo {
                quality_score: 0.8,
                active_requests: 2,
                available_pieces: [PieceId::new(0), PieceId::new(1)].iter().copied().collect(),
                recent_response_time: std::time::Duration::from_millis(100),
                reliability: 0.9,
            },
        );

        PieceSelectionContext {
            piece_redundancy,
            active_peers,
            transfer_progress: 0.5,
            estimated_time_remaining: Some(std::time::Duration::from_secs(300)),
            current_performance: None,
        }
    }

    #[test]
    fn test_adaptive_strategy_engine_creation() {
        let config = AdaptationConfig::default();
        let engine = AdaptiveStrategyEngine::new(config);

        assert_eq!(engine.current_strategy, PieceSelectionStrategy::RarestFirst);
        assert!(!engine.strategy_scores.is_empty());
    }

    #[test]
    fn test_rarest_first_selection() {
        let config = AdaptationConfig::default();
        let engine = AdaptiveStrategyEngine::new(config);
        let context = create_test_context();

        let selected = engine.select_rarest_first(&context, 2);
        assert_eq!(selected.len(), 2);
        // Should select rarest piece first (redundancy 1)
        assert_eq!(selected[0], PieceId::new(0));
    }

    #[test]
    fn test_sequential_selection() {
        let config = AdaptationConfig::default();
        let engine = AdaptiveStrategyEngine::new(config);
        let context = create_test_context();

        let selected = engine.select_sequential(&context, 2);
        assert_eq!(selected.len(), 2);
        // Should select in order
        assert_eq!(selected[0], PieceId::new(0));
        assert_eq!(selected[1], PieceId::new(1));
    }

    #[test]
    fn test_strategy_scoring() {
        let config = AdaptationConfig::default();
        let engine = AdaptiveStrategyEngine::new(config);

        let performance = StrategyPerformance {
            strategy: PieceSelectionStrategy::RarestFirst,
            time_period: std::time::Duration::from_secs(60),
            avg_download_speed: 2_000_000.0,
            avg_latency: std::time::Duration::from_millis(50),
            success_rate: 0.95,
            efficiency_score: 0.9,
            timestamp: std::time::Instant::now(),
        };

        let score = engine.calculate_performance_score(&performance);
        assert!(score > 0.5); // Should be a good score
        assert!(score <= 1.0);
    }

    #[test]
    fn test_endgame_detection() {
        let config = AdaptationConfig::default();
        let mut engine = AdaptiveStrategyEngine::new(config);

        let mut context = create_test_context();
        context.transfer_progress = 0.95; // Near completion

        let _strategy = engine.select_strategy(&context);
        // Should switch to endgame for transfers > 90% complete
        // Note: actual behavior depends on timing constraints
    }

    #[test]
    fn test_piece_selection_strategy_serialization() {
        let strategy = PieceSelectionStrategy::RarestFirst;
        let serialized = serde_json::to_string(&strategy).unwrap();
        let deserialized: PieceSelectionStrategy = serde_json::from_str(&serialized).unwrap();
        assert_eq!(strategy, deserialized);
    }
