    use super::*;
    use futures_lite::future::block_on;
    use std::collections::HashMap;
    use tempfile::TempDir;

    #[test]
    fn test_planner_creation() {
        let planner = AtpTransferPlanner::new_default();
        assert_eq!(planner.config.default_chunk_size, 64 * 1024);
    }

    #[test]
    fn test_plan_id_generation() {
        let planner = AtpTransferPlanner::new_default();
        let id1 = planner.generate_plan_id();
        let id2 = planner.generate_plan_id();

        assert_ne!(id1, id2);
        assert!(id1.starts_with("plan_"));
        assert!(id2.starts_with("plan_"));
    }

    #[test]
    fn test_object_graph_analysis_file() {
        block_on(async {
            let cx = Cx::for_testing();
            let planner = AtpTransferPlanner::new_default();

            let temp_dir = TempDir::new().unwrap();
            let test_file = temp_dir.path().join("test.txt");

            // Create test file
            std::fs::write(&test_file, b"test content").unwrap();

            let result = planner.analyze_object_graph(&cx, &test_file).await.unwrap();

            assert_eq!(result.object_count, 1);
            assert_eq!(result.file_count, 1);
            assert_eq!(result.directory_count, 0);
            assert_eq!(result.total_bytes, 12); // "test content" length
        });
    }

    #[test]
    fn test_planning_options_default() {
        let options = PlannerOptions::default();
        assert_eq!(options.transfer_mode, TransferMode::Direct);
        assert!(options.cache_enabled);
        assert!(options.allow_resume);
    }

    #[test]
    fn test_chunking_profile_generation() {
        let planner = AtpTransferPlanner::new_default();

        let object_graph = ObjectGraphSummary {
            object_count: 1,
            total_bytes: 1024 * 1024, // 1MB
            file_count: 1,
            directory_count: 0,
            largest_file_bytes: 1024 * 1024,
            small_files_count: 0,
        };

        let profile = planner.generate_chunking_profile(&object_graph);

        assert_eq!(profile.chunk_size, 64 * 1024);
        assert_eq!(profile.estimated_chunks, 16); // exact 1MiB / 64KiB boundary
        assert_eq!(profile.repair_overhead_ratio, 0.1);

        let non_aligned_graph = ObjectGraphSummary {
            total_bytes: (1024 * 1024) + 1,
            ..object_graph
        };
        let non_aligned_profile = planner.generate_chunking_profile(&non_aligned_graph);
        assert_eq!(non_aligned_profile.estimated_chunks, 17);
    }

    #[test]
    fn test_path_candidates_generation() {
        block_on(async {
            let planner = AtpTransferPlanner::new_default();

            let options = PlannerOptions {
                transfer_mode: TransferMode::Direct,
                ..Default::default()
            };

            let candidates = planner.generate_path_candidates(&options).await.unwrap();

            assert_eq!(candidates.len(), 1);
            assert_eq!(candidates[0].path_type, "direct");
            assert!(candidates[0].preferred);
        });
    }

    #[test]
    fn test_swarm_path_candidates() {
        block_on(async {
            let planner = AtpTransferPlanner::new_default();

            let options = PlannerOptions {
                transfer_mode: TransferMode::Swarm,
                ..Default::default()
            };

            let candidates = planner.generate_path_candidates(&options).await.unwrap();

            assert_eq!(candidates.len(), 3);
            assert!(candidates[0].preferred);
            assert!(!candidates[1].preferred);
            assert!(!candidates[2].preferred);
        });
    }

    #[test]
    fn test_cache_analysis() {
        block_on(async {
            let planner = AtpTransferPlanner::new_default();

            let object_graph = ObjectGraphSummary {
                object_count: 1,
                total_bytes: 1024 * 1024,
                file_count: 1,
                directory_count: 0,
                largest_file_bytes: 1024 * 1024,
                small_files_count: 0,
            };

            let options = PlannerOptions {
                cache_enabled: true,
                ..Default::default()
            };

            let cache_analysis = planner
                .analyze_cache_opportunities(&object_graph, &options)
                .await
                .unwrap();

            assert!(cache_analysis.local_hit_ratio > 0.0);
            assert!(cache_analysis.bytes_from_cache > 0);
            assert!(!cache_analysis.cache_locations.is_empty());
        });
    }

    #[test]
    fn test_bytes_on_wire_calculation() {
        let planner = AtpTransferPlanner::new_default();

        let object_graph = ObjectGraphSummary {
            object_count: 1,
            total_bytes: 1024 * 1024, // 1MB
            file_count: 1,
            directory_count: 0,
            largest_file_bytes: 1024 * 1024,
            small_files_count: 0,
        };

        let chunking_profile = ChunkingProfile {
            chunk_size: 64 * 1024,
            estimated_chunks: 16,
            repair_overhead_ratio: 0.1,
            compression_ratio: 0.8,
        };

        let bytes_on_wire = planner.estimate_bytes_on_wire(&object_graph, &chunking_profile);

        // Compressed: 1048576 * 0.8 = 838860
        // Repair: 838860 * 0.1 = 83886
        // Protocol: 838860 / 100 = 8388
        // Total: 838860 + 83886 + 8388 = 931134
        assert_eq!(bytes_on_wire, 931134);
    }

    #[test]
    fn test_execution_tracker() {
        let mut tracker = PlanExecutionTracker::new("test_plan".to_string());

        tracker.record_deviation(
            "bandwidth".to_string(),
            "10Mbps".to_string(),
            "5Mbps".to_string(),
            "network congestion".to_string(),
            "medium".to_string(),
        );

        assert_eq!(tracker.deviations.len(), 1);
        assert_eq!(tracker.deviations[0].deviation_type, "bandwidth");

        let report = tracker.generate_report(true, None, HashMap::new());

        assert_eq!(report.plan_id, "test_plan");
        assert!(report.success);
        assert!(report.completed_at.is_some());
        assert_eq!(report.deviations.len(), 1);
    }
