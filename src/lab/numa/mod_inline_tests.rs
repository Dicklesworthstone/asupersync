    use super::*;

    fn snapshot(
        resident_bytes: u64,
        hot_resident_bytes: u64,
        spill_eligible_bytes: u64,
        pressure_bps: u16,
    ) -> ArtifactMemoryPressureSnapshot {
        ArtifactMemoryPressureSnapshot {
            resident_bytes,
            max_resident_bytes: 1_000,
            hot_resident_bytes,
            cold_resident_bytes: resident_bytes.saturating_sub(hot_resident_bytes),
            spill_eligible_bytes,
            remote_numa_bytes: 0,
            pressure_bps,
            high_pressure: pressure_bps >= 8_500,
            duplicate_bytes_avoided: 0,
            artifact_count: 8,
        }
    }

    fn input(cache: ArtifactMemoryPressureSnapshot) -> NumaCachePressureInput {
        NumaCachePressureInput {
            scenario_id: "asw4-64c-256g".to_string(),
            cache,
            agent_budget_bytes: 1_000,
            agent_resident_bytes: 760,
            local_node_bytes: 700,
            remote_node_bytes: 300,
            topology_confidence_bps: 9_000,
            replay_pointer: "trace://asw4/numa".to_string(),
        }
    }

    #[test]
    fn projection_uses_numa_penalty_when_topology_confidence_is_high() {
        let projection = project_numa_cache_pressure(&input(snapshot(800, 200, 500, 8_000)));

        assert!(projection.numa_hint_used);
        assert_eq!(projection.remote_numa_penalty_bps, 3_000);
        assert_eq!(projection.hot_cache_discount_bps, 2_500);
        assert_eq!(projection.pressure_class, NumaPressureClass::Amber);
        assert_eq!(projection.recommended_eviction_bytes, 600);
        assert_eq!(projection.spill_to_disk_bytes, 500);
    }

    #[test]
    fn low_topology_confidence_uses_portable_fallback() {
        let mut model = input(snapshot(800, 200, 500, 8_000));
        model.topology_confidence_bps = 4_000;

        let projection = project_numa_cache_pressure(&model);

        assert!(!projection.numa_hint_used);
        assert_eq!(projection.remote_numa_penalty_bps, 0);
        assert_eq!(projection.pressure_class, NumaPressureClass::Amber);
    }

    #[test]
    fn red_pressure_targets_budget_overage_and_cold_bytes() {
        let mut model = input(snapshot(1_200, 100, 900, 12_000));
        model.agent_resident_bytes = 1_400;

        let projection = project_numa_cache_pressure(&model);

        assert_eq!(projection.pressure_class, NumaPressureClass::Red);
        assert_eq!(projection.recommended_eviction_bytes, 1_100);
        assert_eq!(projection.spill_to_disk_bytes, 900);
    }

    #[test]
    fn green_pressure_keeps_cache_resident() {
        let mut model = input(snapshot(400, 350, 200, 4_000));
        model.agent_resident_bytes = 300;
        model.remote_node_bytes = 0;

        let projection = project_numa_cache_pressure(&model);

        assert_eq!(projection.pressure_class, NumaPressureClass::Green);
        assert_eq!(projection.recommended_eviction_bytes, 0);
        assert_eq!(projection.spill_to_disk_bytes, 0);
    }
