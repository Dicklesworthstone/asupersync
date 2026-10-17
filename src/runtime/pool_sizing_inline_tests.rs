    use super::*;

    fn estimate(arrivals_per_second: u64, service_micros: u64) -> PoolWorkloadEstimate {
        PoolWorkloadEstimate::new(
            arrivals_per_second.saturating_mul(POOL_SIZING_SCALE),
            service_micros,
            u128::from(service_micros).saturating_mul(u128::from(service_micros)),
        )
    }

    #[test]
    fn offered_load_and_cv2_are_fixed_point() {
        let workload = PoolWorkloadEstimate::new(25 * POOL_SIZING_SCALE, 200_000, 40_000_000_000);

        assert_eq!(workload.offered_load_ppm(), 5 * POOL_SIZING_SCALE);
        assert_eq!(workload.service_cv2_ppm(), POOL_SIZING_SCALE);
        assert_eq!(workload.service_variability_bps(), 10_000);
    }

    #[test]
    fn erlang_c_matches_known_mm_k_table_values() {
        let half_load_one_server = erlang_c_wait_probability_ppm(POOL_SIZING_SCALE_U128 / 2, 1);
        let one_load_two_servers = erlang_c_wait_probability_ppm(POOL_SIZING_SCALE_U128, 2);
        let two_load_three_servers = erlang_c_wait_probability_ppm(2 * POOL_SIZING_SCALE_U128, 3);

        assert!(
            (499_999..=500_000).contains(&half_load_one_server),
            "M/M/1 with R=0.5 should wait with probability 0.5, got {half_load_one_server}"
        );
        assert!(
            (333_333..=333_334).contains(&one_load_two_servers),
            "M/M/2 with R=1 should wait with probability 1/3, got {one_load_two_servers}"
        );
        assert!(
            (444_444..=444_445).contains(&two_load_three_servers),
            "M/M/3 with R=2 should wait with probability 4/9, got {two_load_three_servers}"
        );
    }

    #[test]
    fn recommendation_selects_first_candidate_that_meets_wait_probability() {
        let workload = estimate(5, 1_000_000);
        let recommendation = recommend_pool_size(
            workload,
            PoolSizingBounds::new(1, 16),
            PoolSizingTarget::MaxWaitProbabilityPpm(100_000),
        );

        assert_eq!(recommendation.reason, PoolSizingReason::TargetMet);
        assert!(recommendation.target_met);
        assert_eq!(recommendation.recommended_size, 9);
        assert!(recommendation.square_root_staffing_size >= 8);
        assert!(recommendation.selected_metrics.wait_probability_ppm <= 100_000);
    }

    #[test]
    fn floor_and_ceiling_are_hard_bounds() {
        let no_load = PoolWorkloadEstimate::new(0, 0, 0);
        let floor = recommend_pool_size(
            no_load,
            PoolSizingBounds::new(3, 12),
            PoolSizingTarget::MaxWaitProbabilityPpm(1),
        );
        assert_eq!(floor.recommended_size, 3);
        assert_eq!(floor.reason, PoolSizingReason::NoObservedLoad);

        let overloaded = estimate(100, 1_000_000);
        let ceiling = recommend_pool_size(
            overloaded,
            PoolSizingBounds::new(1, 4),
            PoolSizingTarget::MaxWaitProbabilityPpm(10_000),
        );
        assert_eq!(ceiling.recommended_size, 4);
        assert_eq!(ceiling.reason, PoolSizingReason::TargetUnmetAtCeiling);
        assert!(!ceiling.target_met);
    }

    #[test]
    fn mean_wait_target_uses_selected_candidate_metrics() {
        let workload = estimate(4, 250_000);
        let recommendation = recommend_pool_size(
            workload,
            PoolSizingBounds::new(1, 8),
            PoolSizingTarget::MaxMeanWaitMicros(50_000),
        );

        assert!(recommendation.target_met);
        assert!(recommendation.selected_metrics.mean_wait_micros <= 50_000);
        assert!(recommendation.recommended_size >= 2);
    }

    #[test]
    fn estimator_uses_virtual_time_observations_only() {
        let mut estimator = PoolSizingEstimator::new(500_000);
        let first = estimator
            .observe(PoolSizingObservation::new(
                1_000_000,
                10,
                10,
                2_000_000,
                400_000_000_000,
            ))
            .expect("first completed window yields an estimate");

        assert_eq!(first.arrival_rate_per_sec_ppm, 10 * POOL_SIZING_SCALE);
        assert_eq!(first.service_time_mean_micros, 200_000);
        assert_eq!(first.service_time_variance_micros2, 0);

        let second = estimator
            .observe(PoolSizingObservation::new(
                1_000_000,
                20,
                20,
                8_000_000,
                3_200_000_000_000,
            ))
            .expect("second completed window updates estimate");

        assert_eq!(estimator.sample_count(), 2);
        assert_eq!(second.arrival_rate_per_sec_ppm, 15 * POOL_SIZING_SCALE);
        assert_eq!(second.service_time_mean_micros, 300_000);
        assert_eq!(second.service_time_variance_micros2, 10_000_000_000);
    }

    #[test]
    fn estimator_reset_clears_old_regime_before_next_observation() {
        let mut estimator = PoolSizingEstimator::new(500_000);
        let old_regime = estimator
            .observe(PoolSizingObservation::new(
                1_000_000,
                20,
                20,
                8_000_000,
                3_200_000_000_000,
            ))
            .expect("old regime yields an estimate");
        assert_eq!(old_regime.arrival_rate_per_sec_ppm, 20 * POOL_SIZING_SCALE);
        assert_eq!(old_regime.service_time_mean_micros, 400_000);
        assert_eq!(estimator.sample_count(), 1);

        estimator.reset();
        assert_eq!(estimator.sample_count(), 0);
        assert_eq!(estimator.estimate(), None);

        let new_regime = estimator
            .observe(PoolSizingObservation::new(
                1_000_000,
                2,
                2,
                200_000,
                20_000_000_000,
            ))
            .expect("first post-reset observation yields a fresh estimate");

        assert_eq!(estimator.sample_count(), 1);
        assert_eq!(new_regime.arrival_rate_per_sec_ppm, 2 * POOL_SIZING_SCALE);
        assert_eq!(new_regime.service_time_mean_micros, 100_000);
        assert_eq!(new_regime.service_time_variance_micros2, 0);
    }

    #[test]
    fn advisory_mode_never_requests_resize() {
        let policy = PoolSizingPolicy::advisory(PoolSizingBounds::new(1, 16));
        let state = PoolSizingControllerState {
            current_size: 2,
            last_resize_epoch: 0,
        };

        let decision = decide_pool_sizing(policy, state, estimate(8, 1_000_000), 100);

        assert_eq!(decision.action, PoolSizingAction::ObserveOnly);
        assert!(decision.recommendation.recommended_size > state.current_size);
    }

    #[test]
    fn managed_mode_respects_hysteresis_and_cadence() {
        let mut policy = PoolSizingPolicy::managed(
            PoolSizingBounds::new(1, 16),
            PoolSizingTarget::MaxWaitProbabilityPpm(100_000),
        );
        policy.hysteresis_bps = 5_000;
        policy.resize_cadence_epochs = 4;
        let state = PoolSizingControllerState {
            current_size: 10,
            last_resize_epoch: 10,
        };

        let small_move = decide_pool_sizing(policy, state, estimate(5, 1_000_000), 20);
        assert_eq!(small_move.recommendation.recommended_size, 9);
        assert_eq!(small_move.action, PoolSizingAction::HoldHysteresis);

        let cadence_hold = decide_pool_sizing(policy, state, estimate(12, 1_000_000), 12);
        assert!(cadence_hold.recommendation.recommended_size > state.current_size);
        assert_eq!(cadence_hold.action, PoolSizingAction::HoldCadence);

        let resize = decide_pool_sizing(policy, state, estimate(12, 1_000_000), 15);
        assert_eq!(
            resize.action,
            PoolSizingAction::Resize {
                from_size: 10,
                to_size: resize.recommendation.recommended_size
            }
        );
    }

    #[test]
    fn recommendation_replays_identically_from_same_observations() {
        let observations = [
            PoolSizingObservation::new(1_000_000, 5, 5, 500_000, 50_000_000_000),
            PoolSizingObservation::new(1_000_000, 10, 10, 2_000_000, 400_000_000_000),
            PoolSizingObservation::new(2_000_000, 16, 16, 4_800_000, 1_440_000_000_000),
        ];

        let run = || {
            let mut estimator = PoolSizingEstimator::new(250_000);
            let mut last = None;
            for observation in observations {
                last = estimator.observe(observation);
            }
            recommend_pool_size(
                last.expect("observations should produce an estimate"),
                PoolSizingBounds::new(1, 16),
                PoolSizingTarget::MaxWaitProbabilityPpm(100_000),
            )
        };

        assert_eq!(run(), run());
    }

    fn ramp_observation(arrivals_per_second: u64, service_micros: u64) -> PoolSizingObservation {
        // One-second window: arrivals == arrivals/sec, completions match arrivals.
        PoolSizingObservation::new(
            1_000_000,
            arrivals_per_second,
            arrivals_per_second,
            u128::from(arrivals_per_second).saturating_mul(u128::from(service_micros)),
            u128::from(arrivals_per_second)
                .saturating_mul(u128::from(service_micros))
                .saturating_mul(u128::from(service_micros)),
        )
    }

    #[test]
    fn divergence_fires_at_two_x_and_is_silent_within_tolerance() {
        // 4 vs 2 is exactly 2x => fires (undersized).
        let under = pool_sizing_divergence(4, 2, DEFAULT_DIVERGENCE_WARN_BPS)
            .expect("2x undersize must warn");
        assert_eq!(under.direction, PoolSizingDivergenceDirection::Undersized);
        assert_eq!(under.factor_bps, 20_000);

        // 2 vs 4 is 2x the other way => fires (oversized).
        let over = pool_sizing_divergence(2, 4, DEFAULT_DIVERGENCE_WARN_BPS)
            .expect("2x oversize must warn");
        assert_eq!(over.direction, PoolSizingDivergenceDirection::Oversized);

        // 4 vs 3 is ~1.33x => within tolerance.
        assert_eq!(
            pool_sizing_divergence(4, 3, DEFAULT_DIVERGENCE_WARN_BPS),
            None
        );
        // Equality never warns.
        assert_eq!(
            pool_sizing_divergence(5, 5, DEFAULT_DIVERGENCE_WARN_BPS),
            None
        );
        // Any positive size vs a zero floor is an unbounded divergence.
        let from_zero = pool_sizing_divergence(8, 0, DEFAULT_DIVERGENCE_WARN_BPS)
            .expect("nonzero recommendation vs zero size warns");
        assert_eq!(from_zero.factor_bps, u32::MAX);
        assert_eq!(
            from_zero.direction,
            PoolSizingDivergenceDirection::Undersized
        );
    }

    #[test]
    fn advisory_controller_warns_on_deliberate_undersizing() {
        // AC2: advisory mode publishes a divergence when the pool is far below
        // the recommendation under a heavy load, and never acts.
        let policy = PoolSizingPolicy::advisory(PoolSizingBounds::new(1, 32));
        let mut controller = ManagedPoolSizingController::new(policy, 1_000_000, 2);
        let decision = controller.observe(ramp_observation(40, 500_000), 1);
        assert_eq!(decision.action, PoolSizingAction::ObserveOnly);
        assert_eq!(controller.current_size(), 2, "advisory mode never resizes");
        let divergence = controller
            .divergence()
            .expect("a 2-worker pool under R=20 load must diverge from the recommendation");
        assert_eq!(
            divergence.direction,
            PoolSizingDivergenceDirection::Undersized
        );
        assert!(divergence.recommended_size >= 2 * divergence.actual_size);
    }

    #[test]
    fn managed_controller_follows_load_ramp_without_flapping() {
        // AC3: under a monotone load ramp the managed pool grows toward the
        // recommendation, settles, and the resize count stays small (no flap).
        let policy = PoolSizingPolicy::managed(
            PoolSizingBounds::new(1, 32),
            PoolSizingTarget::MaxWaitProbabilityPpm(100_000),
        );
        // alpha = 1.0 so the EWMA tracks each window exactly for a clean proof.
        let mut controller = ManagedPoolSizingController::new(policy, 1_000_000, 1);

        let mut sizes = Vec::new();
        // Ramp up over several epochs, then hold at the peak load.
        let ramp = [4_u64, 8, 12, 16, 20, 20, 20, 20];
        for (i, arrivals) in ramp.iter().enumerate() {
            let epoch = (i as u64) + 1;
            controller.observe(ramp_observation(*arrivals, 500_000), epoch);
            sizes.push(controller.current_size());
        }

        // Size grows monotonically during the ramp.
        for pair in sizes.windows(2) {
            assert!(
                pair[1] >= pair[0],
                "managed size should not shrink mid-ramp"
            );
        }
        // It actually grew above the floor.
        assert!(
            *sizes.last().unwrap() > 1,
            "managed pool should scale up under load"
        );
        // Once load is steady the controller stops acting (hysteresis holds).
        let resizes_after_ramp = controller.applied_resizes();
        controller.observe(ramp_observation(20, 500_000), 9);
        controller.observe(ramp_observation(20, 500_000), 10);
        assert_eq!(
            controller.applied_resizes(),
            resizes_after_ramp,
            "steady load must not trigger further resizes"
        );
        // Action count is bounded well below the number of ticks (no flapping).
        assert!(
            controller.applied_resizes() <= ramp.len() as u64,
            "resize count {} should be bounded by the ramp length",
            controller.applied_resizes()
        );
    }

    #[test]
    fn managed_controller_replays_identically() {
        // AC4: identical observation/epoch sequences yield identical trajectories.
        let policy = PoolSizingPolicy::managed(
            PoolSizingBounds::new(1, 32),
            PoolSizingTarget::MaxWaitProbabilityPpm(100_000),
        );
        let ramp = [3_u64, 9, 15, 21, 21, 21];
        let run = || {
            let mut controller = ManagedPoolSizingController::new(policy, 400_000, 1);
            let mut trace = Vec::new();
            for (i, arrivals) in ramp.iter().enumerate() {
                controller.observe(ramp_observation(*arrivals, 400_000), (i as u64) + 1);
                trace.push(controller.current_size());
            }
            (
                trace,
                controller.applied_resizes(),
                controller.last_resize_epoch(),
            )
        };
        assert_eq!(run(), run());
    }

    #[test]
    fn managed_controller_respects_floor_and_ceiling() {
        // AC5: a crushing load can never push the pool past the ceiling, and a
        // trickle of load can never pull it below the floor.
        let policy = PoolSizingPolicy::managed(
            PoolSizingBounds::new(4, 8),
            PoolSizingTarget::MaxWaitProbabilityPpm(10_000),
        );
        let mut controller = ManagedPoolSizingController::new(policy, 1_000_000, 4);
        for epoch in 1..=6 {
            controller.observe(ramp_observation(1_000, 1_000_000), epoch);
            assert!(
                controller.current_size() <= 8,
                "ceiling must always win, got {}",
                controller.current_size()
            );
            assert!(controller.current_size() >= 4, "floor must always hold");
        }
        assert_eq!(
            controller.current_size(),
            8,
            "crushing load pins at the ceiling"
        );

        // Now a near-idle workload: the floor still holds.
        let mut idle = ManagedPoolSizingController::new(policy, 1_000_000, 8);
        for epoch in 1..=4 {
            idle.observe(ramp_observation(1, 1_000), epoch);
            assert!(idle.current_size() >= 4, "floor must hold under idle load");
        }
    }

    #[test]
    fn controller_cold_start_observes_only() {
        // No estimate yet on the very first tick (no observation folded).
        let policy = PoolSizingPolicy::managed(
            PoolSizingBounds::new(1, 16),
            PoolSizingTarget::conservative_wait_probability(),
        );
        let mut controller = ManagedPoolSizingController::new(policy, 500_000, 4);
        let decision = controller.tick(5);
        assert_eq!(decision.action, PoolSizingAction::ObserveOnly);
        assert_eq!(controller.current_size(), 4);
        assert_eq!(controller.applied_resizes(), 0);
    }

    #[test]
    fn reset_estimator_preserves_live_size() {
        // AC7: a regime reset clears learning but never resizes the pool itself.
        let policy = PoolSizingPolicy::managed(
            PoolSizingBounds::new(1, 32),
            PoolSizingTarget::MaxWaitProbabilityPpm(100_000),
        );
        let mut controller = ManagedPoolSizingController::new(policy, 1_000_000, 1);
        for epoch in 1..=4 {
            controller.observe(ramp_observation(16, 500_000), epoch);
        }
        let size_before = controller.current_size();
        assert!(size_before > 1);
        controller.reset_estimator();
        assert_eq!(
            controller.current_size(),
            size_before,
            "reset must not resize"
        );
        assert_eq!(controller.estimate(), None, "reset clears the estimate");
    }

    #[test]
    fn explain_card_substitutes_live_values() {
        // AC6: the galaxy-brain card names the recommendation and the inputs.
        let policy = PoolSizingPolicy::advisory(PoolSizingBounds::new(1, 32));
        let mut controller = ManagedPoolSizingController::new(policy, 1_000_000, 1);
        controller.observe(ramp_observation(16, 400_000), 1);
        let card = controller.explain();
        assert!(card.contains("pool-sizing card"), "card header: {card}");
        assert!(
            card.contains("offered load R ="),
            "card shows offered load: {card}"
        );
        assert!(
            card.contains("square-root staffing"),
            "card shows the formula: {card}"
        );
        assert!(
            card.contains("P(wait)"),
            "card shows wait probability: {card}"
        );

        // Cold-start card is explicit about the lack of data.
        let cold = ManagedPoolSizingController::new(policy, 1_000_000, 1).explain();
        assert!(cold.contains("no observed load"), "cold card: {cold}");
    }
