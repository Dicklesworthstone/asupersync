    use super::*;

    fn est(loss: f64, bw: f64) -> PathEstimate {
        PathEstimate {
            rtt_s: 0.09,
            loss_p_hat: loss,
            loss_p_bar: loss,
            bw_median_bps: bw,
            bw_trough_bps: bw * 0.7,
            enc_symbols_per_s: 2_000_000.0,
            dec_symbols_per_s: 1_500_000.0,
            coding_ref_k: 1024,
            coding_gamma: 1.5,
            samples: 10,
        }
    }

    #[test]
    fn normal_cdf_is_sane() {
        assert!((normal_cdf(0.0) - 0.5).abs() < 1e-6);
        assert!(normal_cdf(3.0) > 0.998 && normal_cdf(3.0) < 0.9995);
        assert!((normal_cdf(-3.0) + normal_cdf(3.0) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn z_for_alpha_matches_known_quantiles() {
        // Φ⁻¹(0.999) ≈ 3.0902, so z for α=1e-3 ≈ 3.09.
        assert!((z_for_alpha(1e-3) - 3.0902).abs() < 0.01);
        // α=0.025 ⇒ z ≈ 1.96.
        assert!((z_for_alpha(0.025) - 1.95996).abs() < 0.01);
    }

    #[test]
    fn decode_fail_decreases_with_overhead() {
        // Choose (K, p, overheads) in the measurable transition band so the
        // values do not both underflow to exactly 0.0 at high overhead.
        let p = 0.10;
        let a = decode_fail_probability(512, 0.10, p);
        let b = decode_fail_probability(512, 0.13, p);
        let c = decode_fail_probability(512, 0.16, p);
        assert!(
            a > b && b > c && c >= 0.0,
            "more overhead ⇒ strictly lower failure: {a} {b} {c}"
        );
    }

    #[test]
    fn overhead_concentration_law_shrinks_with_k() {
        // THE key alien-artifact fact: at fixed (p, α), required overhead falls
        // as K grows (received-count concentration ~ 1/√K).
        let alpha = 1e-3;
        let p = 0.03;
        let e512 = overhead_for_target(512, p, alpha, 0.5);
        let e2048 = overhead_for_target(2048, p, alpha, 0.5);
        let e8192 = overhead_for_target(8192, p, alpha, 0.5);
        assert!(
            e512 > e2048 && e2048 > e8192,
            "overhead must shrink with K: {e512} {e2048} {e8192}"
        );
        // And every choice must actually meet the target.
        for &k in &[512u32, 2048, 8192] {
            let e = overhead_for_target(k, p, alpha, 0.5);
            assert!(
                decode_fail_probability(k, e, p) <= alpha * 1.000_001,
                "K={k} ε={e} must hit α"
            );
        }
    }

    #[test]
    fn overhead_increases_with_loss() {
        let alpha = 1e-3;
        let lo = overhead_for_target(2048, 0.01, alpha, 0.5);
        let hi = overhead_for_target(2048, 0.10, alpha, 0.5);
        assert!(hi > lo, "more loss ⇒ more overhead: {lo} {hi}");
    }

    #[test]
    fn overhead_deadband_elides_near_clean_repair_symbols() {
        let alpha = 1e-3;
        for loss in [0.0, 0.0005, CLEAN_LINK_REPAIR_OVERHEAD_DEADBAND] {
            assert_eq!(
                overhead_for_target(512, loss, alpha, 0.5),
                0.0,
                "near-clean loss should not pre-spray repair symbols: {loss}"
            );
        }

        let lossy = overhead_for_target(512, CLEAN_LINK_REPAIR_OVERHEAD_DEADBAND * 2.0, alpha, 0.5);
        assert!(
            lossy > 0.0,
            "loss above the near-clean deadband should re-enable calibrated repair overhead"
        );
    }

    #[test]
    fn overhead_deadband_eliminates_near_clean_repair_floor() {
        let alpha = 1e-3;
        for loss in [0.0, 0.0005, CLEAN_LINK_REPAIR_OVERHEAD_DEADBAND] {
            assert_eq!(
                overhead_for_target(2048, loss, alpha, 0.5),
                0.0,
                "near-clean measured loss must not inherit a repair floor"
            );
        }

        let lossy = overhead_for_target(2048, 0.02, alpha, 0.5);
        assert!(
            lossy > 0.0,
            "non-clean measured loss still needs calibrated repair overhead"
        );
        assert!(
            decode_fail_probability(2048, lossy, 0.02) <= alpha * 1.000_001,
            "lossy calibrated overhead must still hit the decode-failure target"
        );
    }

    #[test]
    fn overhead_adds_round_budget_margin_for_bad_regime_loss() {
        let alpha = 1e-6;
        let k = 437;
        let loss = LOSSY_ROUND_BUDGET_FULL_STRENGTH_LOSS;
        let base = decode_repair_overhead_for_target(k, loss, alpha, 0.5);
        let budgeted = overhead_for_target(k, loss, alpha, 0.5);

        assert!(
            budgeted >= base * 1.99,
            "2% bad-regime loss should spend a full round-budget repair margin: base={base} budgeted={budgeted}"
        );
        assert!(
            decode_fail_probability(k, budgeted, loss) <= alpha * 1.000_001,
            "round-budgeted overhead must preserve the decode-failure target"
        );
    }

    #[test]
    fn overhead_round_budget_margin_does_not_touch_near_clean_paths() {
        let alpha = 1e-6;
        assert_eq!(
            overhead_for_target(437, CLEAN_LINK_REPAIR_OVERHEAD_DEADBAND, alpha, 0.5),
            0.0
        );
        assert_eq!(
            lossy_round_budget_multiplier(CLEAN_LINK_REPAIR_OVERHEAD_DEADBAND),
            1.0
        );
        assert_eq!(
            lossy_round_budget_multiplier(LOSSY_ROUND_BUDGET_FULL_STRENGTH_LOSS),
            LOSSY_ROUND_BUDGET_MAX_REPAIR_MULTIPLIER
        );
    }

    #[test]
    fn overhead_sanitizes_malformed_inputs_to_safe_zero() {
        assert_eq!(overhead_for_target(2048, f64::NAN, 1e-3, 0.5), 0.0);
        assert_eq!(overhead_for_target(2048, f64::INFINITY, 1e-3, 0.0), 0.0);
        assert_eq!(overhead_for_target(2048, 0.02, 1e-3, f64::NAN), 0.0);
        assert_eq!(
            overhead_for_target(2048, 0.02, f64::NAN, 0.5),
            overhead_for_target(2048, 0.02, 1e-3, 0.5)
        );
        assert_eq!(
            overhead_for_target(2048, 0.02, -1.0, 0.5),
            overhead_for_target(2048, 0.02, 1e-3, 0.5)
        );
    }

    #[test]
    fn overhead_respects_max_overhead_when_loss_model_wants_more() {
        let capped = overhead_for_target(16, 0.90, 1e-12, 0.01);
        assert_eq!(
            capped, 0.01,
            "adaptive FEC must never exceed the caller's configured overhead cap"
        );
    }

    #[test]
    fn optimal_block_is_network_bound_on_clean_fast_path() {
        // Clean path, fast CPU relative to BW ⇒ push K up (network-bound regime).
        let policy = AdaptivePolicy::default();
        let fast_cpu = PathEstimate {
            dec_symbols_per_s: 50_000_000.0, // very fast decode
            ..est(0.005, 25_000_000.0)
        };
        let plan = optimal_block(&fast_cpu, &policy, 1024);
        assert!(
            plan.k >= 2048,
            "clean fast path should pick a large block, got K={}",
            plan.k
        );
    }

    #[test]
    fn optimal_block_is_coding_bound_on_slow_cpu() {
        // Slow decode relative to BW ⇒ pull K down (coding-bound regime).
        let policy = AdaptivePolicy::default();
        let slow_cpu = PathEstimate {
            dec_symbols_per_s: 80_000.0, // slow decode
            coding_gamma: 2.0,           // strongly superlinear
            ..est(0.01, 50_000_000.0)
        };
        let plan = optimal_block(&slow_cpu, &policy, 1024);
        assert!(
            plan.k <= 1024,
            "slow CPU should pick a small block, got K={}",
            plan.k
        );
    }

    #[test]
    fn rate_matched_pacing_plan_cold_starts_on_thin_or_malformed_evidence() {
        let policy = AdaptivePolicy::default();
        let thin = PathEstimate {
            samples: 1,
            bw_median_bps: f64::INFINITY,
            rtt_s: f64::NAN,
            ..est(0.02, 50_000_000.0)
        };

        let plan = rate_matched_pacing_plan(&thin, &policy, 1200, 1_250_000.0, 0);

        assert!(plan.cold_start);
        assert_eq!(plan.raw_pacing_bits_per_s, 10_000_000);
        assert_eq!(plan.datagrams_per_s, 1041);
        assert_eq!(plan.max_burst_datagrams, 1);
        assert_eq!(plan.block.overhead, 0.0);
    }

    #[test]
    fn rate_matched_pacing_plan_cold_starts_on_negative_loss_evidence() {
        let policy = AdaptivePolicy {
            min_samples_to_activate: 1,
            arm_grid_k: vec![1024],
            arm_grid_fanout: vec![1],
            ..AdaptivePolicy::default()
        };
        let malformed_loss = PathEstimate {
            loss_p_hat: -0.05,
            loss_p_bar: -0.01,
            bw_median_bps: 100_000_000.0,
            bw_trough_bps: 75_000_000.0,
            dec_symbols_per_s: 50_000_000.0,
            samples: 16,
            ..est(0.02, 100_000_000.0)
        };

        let plan = rate_matched_pacing_plan(&malformed_loss, &policy, 1200, 1_250_000.0, 32);

        assert!(plan.cold_start);
        assert_eq!(plan.raw_pacing_bits_per_s, 10_000_000);
        assert_eq!(plan.block.overhead, 0.0);
    }

    #[test]
    fn rate_matched_pacing_plan_reports_overhead_adjusted_useful_rate() {
        let mut policy = AdaptivePolicy {
            min_samples_to_activate: 1,
            arm_grid_k: vec![1024],
            arm_grid_fanout: vec![1],
            ..AdaptivePolicy::default()
        };
        policy.max_overhead = 0.50;
        let plan =
            rate_matched_pacing_plan(&est(0.05, 12_000_000.0), &policy, 1200, 1_000_000.0, 32);

        assert!(!plan.cold_start);
        assert!(
            plan.block.overhead > 0.05,
            "expected calibrated FEC overhead"
        );
        assert!(plan.raw_pacing_bits_per_s > 0);
        let raw_bytes_per_s = plan.raw_pacing_bits_per_s as f64 / 8.0;
        assert!(
            plan.useful_pacing_bytes_per_s < raw_bytes_per_s,
            "repair overhead must lower useful rate: useful={} raw={}",
            plan.useful_pacing_bytes_per_s,
            raw_bytes_per_s
        );
        assert!(plan.datagrams_per_s > 0);
    }

    #[test]
    fn rate_matched_pacing_plan_caps_raw_rate_to_sustained_trough() {
        let policy = AdaptivePolicy {
            min_samples_to_activate: 1,
            arm_grid_k: vec![1024],
            arm_grid_fanout: vec![1],
            ..AdaptivePolicy::default()
        };
        let path = PathEstimate {
            bw_median_bps: 100_000_000.0,
            bw_trough_bps: 25_000_000.0,
            dec_symbols_per_s: 50_000_000.0,
            ..est(0.02, 100_000_000.0)
        };

        let plan = rate_matched_pacing_plan(&path, &policy, 1200, 1_000_000.0, 32);

        let raw_bytes_per_s = plan.raw_pacing_bits_per_s as f64 / 8.0;
        let sustained_capacity = path.bw_trough_bps * fanout_gain(1);
        assert!(
            raw_bytes_per_s <= sustained_capacity + 1.0,
            "raw pacing must follow sustained trough, raw={raw_bytes_per_s} cap={sustained_capacity}"
        );
        assert!(!plan.cold_start);
    }

    #[test]
    fn rate_matched_pacing_plan_uses_median_when_trough_is_malformed() {
        let policy = AdaptivePolicy {
            min_samples_to_activate: 1,
            arm_grid_k: vec![1024],
            arm_grid_fanout: vec![1],
            ..AdaptivePolicy::default()
        };
        let malformed_trough = PathEstimate {
            bw_median_bps: 40_000_000.0,
            bw_trough_bps: f64::NAN,
            dec_symbols_per_s: 50_000_000.0,
            ..est(0.02, 40_000_000.0)
        };

        let plan = rate_matched_pacing_plan(&malformed_trough, &policy, 1200, 1_000_000.0, 32);

        assert!(!plan.cold_start);
        assert!(
            plan.raw_pacing_bits_per_s as f64 / 8.0 > malformed_trough.bw_median_bps * 0.25,
            "malformed trough evidence should not collapse a valid median estimate"
        );
    }

    #[test]
    fn rate_matched_pacing_plan_keeps_clean_links_source_first() {
        let mut policy = AdaptivePolicy {
            min_samples_to_activate: 1,
            arm_grid_k: vec![1024],
            arm_grid_fanout: vec![1],
            ..AdaptivePolicy::default()
        };
        policy.max_overhead = 0.50;

        let plan = rate_matched_pacing_plan(
            &est(CLEAN_LINK_REPAIR_OVERHEAD_DEADBAND, 12_000_000.0),
            &policy,
            1200,
            1_000_000.0,
            32,
        );

        assert!(!plan.cold_start);
        assert_eq!(
            plan.block.overhead, 0.0,
            "near-clean adaptive FEC should not add round-0 repair overhead"
        );
        assert!(plan.raw_pacing_bits_per_s > 0);
        assert!(plan.datagrams_per_s > 0);
    }

    #[test]
    fn rate_matched_pacing_plan_drops_to_decode_cpu_capacity() {
        let policy = AdaptivePolicy {
            min_samples_to_activate: 1,
            arm_grid_k: vec![4096],
            arm_grid_fanout: vec![1],
            cores: 1.0,
            cpu_responsiveness_cap: 0.50,
            ..AdaptivePolicy::default()
        };
        let decode_bound = PathEstimate {
            dec_symbols_per_s: 2_000.0,
            coding_gamma: 1.0,
            ..est(0.01, 100_000_000.0)
        };

        let plan = rate_matched_pacing_plan(&decode_bound, &policy, 1000, 1_000_000.0, 16);

        assert!(!plan.cold_start);
        assert!(
            plan.useful_pacing_bytes_per_s <= 1_000_000.0,
            "CPU cap should reduce useful pacing to <= 0.5 * 2000 * 1000 B/s, got {}",
            plan.useful_pacing_bytes_per_s
        );
        assert!(
            plan.raw_pacing_bits_per_s < 100_000_000 * 8,
            "decode-bound path must not spray at full measured path rate"
        );
    }

    #[test]
    fn rate_matched_pacing_plan_respects_flow_control_credit() {
        let policy = AdaptivePolicy {
            min_samples_to_activate: 1,
            arm_grid_k: vec![1024],
            arm_grid_fanout: vec![1],
            ..AdaptivePolicy::default()
        };
        let est = PathEstimate {
            rtt_s: 0.100,
            dec_symbols_per_s: 50_000_000.0,
            ..est(0.01, 100_000_000.0)
        };
        let credit = 12_000;

        let plan =
            rate_matched_pacing_plan_with_flow_credit(&est, &policy, 1200, 8_000_000.0, 32, credit)
                .expect("non-zero credit permits a bounded pacing plan");

        let planned_one_rtt_bytes = (plan.raw_pacing_bits_per_s as f64 / 8.0) * est.rtt_s;
        assert!(
            planned_one_rtt_bytes <= credit as f64 + 1.0,
            "planned RTT inflight {planned_one_rtt_bytes} must stay within credit {credit}"
        );
        assert!(
            plan.raw_pacing_bits_per_s < 100_000_000 * 8,
            "flow credit must cap the raw high-bandwidth path rate"
        );
        assert!(
            u64::from(plan.max_burst_datagrams) * 1200 <= credit,
            "flow-credit burst must fit within advertised receiver credit"
        );
    }

    #[test]
    fn rate_matched_pacing_plan_flow_credit_preserves_repair_overhead_accounting() {
        let mut policy = AdaptivePolicy {
            min_samples_to_activate: 1,
            arm_grid_k: vec![1024],
            arm_grid_fanout: vec![1],
            ..AdaptivePolicy::default()
        };
        policy.max_overhead = 0.50;
        let est = PathEstimate {
            rtt_s: 0.050,
            dec_symbols_per_s: 50_000_000.0,
            ..est(0.08, 100_000_000.0)
        };

        let plan =
            rate_matched_pacing_plan_with_flow_credit(&est, &policy, 1200, 8_000_000.0, 32, 24_000)
                .expect("lossy path with receiver credit should still produce a pacing plan");

        assert!(
            plan.block.overhead > 0.0,
            "loss evidence should keep calibrated repair overhead enabled"
        );
        let raw_bytes_per_s = plan.raw_pacing_bits_per_s as f64 / 8.0;
        let overhead_factor = 1.0 + plan.block.overhead;
        assert!(
            plan.useful_pacing_bytes_per_s <= raw_bytes_per_s / overhead_factor + 1.0,
            "flow-credit capping must not forget repair overhead: useful={} raw={} overhead={}",
            plan.useful_pacing_bytes_per_s,
            raw_bytes_per_s,
            plan.block.overhead
        );
    }

    #[test]
    fn rate_matched_pacing_plan_declines_zero_or_too_small_credit() {
        let policy = AdaptivePolicy {
            min_samples_to_activate: 1,
            arm_grid_k: vec![1024],
            arm_grid_fanout: vec![1],
            ..AdaptivePolicy::default()
        };
        let mut est = est(0.01, 10_000_000.0);
        est.rtt_s = 2.0;

        assert!(
            rate_matched_pacing_plan_with_flow_credit(&est, &policy, 1200, 8_000_000.0, 32, 0)
                .is_none(),
            "zero credit means no send budget"
        );
        assert!(
            rate_matched_pacing_plan_with_flow_credit(&est, &policy, 1200, 8_000_000.0, 32, 1)
                .is_none(),
            "sub-byte-per-second credit cannot be represented safely"
        );
        assert!(
            rate_matched_pacing_plan_with_flow_credit(&est, &policy, 1200, 8_000_000.0, 32, 1199)
                .is_none(),
            "credit smaller than one symbol must not fabricate a datagram burst"
        );
    }

    #[test]
    fn rate_matched_pacing_plan_flow_credit_caps_burst_datagrams() {
        let policy = AdaptivePolicy {
            min_samples_to_activate: 1,
            arm_grid_k: vec![1024],
            arm_grid_fanout: vec![1],
            ..AdaptivePolicy::default()
        };
        let est = PathEstimate {
            rtt_s: 0.050,
            dec_symbols_per_s: 50_000_000.0,
            ..est(0.02, 200_000_000.0)
        };
        let symbol_size = 1200;
        let credit = 12_000;

        let plan = rate_matched_pacing_plan_with_flow_credit(
            &est,
            &policy,
            symbol_size,
            8_000_000.0,
            64,
            credit,
        )
        .expect("one-symbol-or-larger credit should produce a bounded plan");

        assert_eq!(plan.max_burst_datagrams, 10);
        assert!(
            u64::from(plan.max_burst_datagrams) * u64::from(symbol_size) <= credit,
            "burst cap must never exceed receiver credit"
        );
    }

    #[test]
    fn rate_matched_pacing_plan_credit_cap_is_replay_stable() {
        let policy = AdaptivePolicy {
            min_samples_to_activate: 1,
            arm_grid_k: vec![512, 1024, 2048],
            arm_grid_fanout: vec![1, 2],
            ..AdaptivePolicy::default()
        };
        let est = PathEstimate {
            rtt_s: 0.025,
            dec_symbols_per_s: 10_000_000.0,
            ..est(0.025, 64_000_000.0)
        };

        let first =
            rate_matched_pacing_plan_with_flow_credit(&est, &policy, 1200, 8_000_000.0, 16, 64_000);
        let replay =
            rate_matched_pacing_plan_with_flow_credit(&est, &policy, 1200, 8_000_000.0, 16, 64_000);

        assert_eq!(first, replay);
    }

    #[test]
    fn rate_matched_pacing_plan_malformed_rtt_uses_credit_safe_window() {
        let policy = AdaptivePolicy::default();
        let malformed = PathEstimate {
            samples: 0,
            rtt_s: f64::NAN,
            bw_median_bps: f64::INFINITY,
            ..est(0.02, 50_000_000.0)
        };
        let credit = 64 * 1024;

        let plan = rate_matched_pacing_plan_with_flow_credit(
            &malformed,
            &policy,
            1200,
            8_000_000.0,
            32,
            credit,
        )
        .expect("valid credit with malformed path evidence uses bounded cold start");

        assert!(plan.cold_start);
        assert!(
            plan.raw_pacing_bits_per_s <= credit * 8,
            "malformed RTT must use a conservative one-second credit window"
        );
    }

    #[test]
    fn controller_declines_until_evidence() {
        let mut c = AdaptiveController::new(AdaptivePolicy::default(), 42);
        // No estimate yet ⇒ None (fall back to fixed config).
        assert!(c.next_block_plan(1024).is_none());
        // Thin evidence ⇒ still None.
        c.update_estimate(PathEstimate {
            samples: 1,
            ..est(0.02, 10_000_000.0)
        });
        assert!(c.next_block_plan(1024).is_none());
        // Enough evidence ⇒ activates.
        c.update_estimate(est(0.02, 10_000_000.0));
        assert!(c.next_block_plan(1024).is_some());
    }

    #[test]
    fn first_active_epoch_uses_closed_form_model_plan() {
        let mut c = AdaptiveController::new(AdaptivePolicy::default(), 42);
        c.update_estimate(est(0.02, 10_000_000.0));
        let expected = c.model_plan(1024);

        let actual = c
            .next_block_plan(1024)
            .expect("enough evidence activates controller");

        assert_eq!(actual, expected);
        let snapshot = c.diagnostic_snapshot();
        assert_eq!(snapshot.epoch, 1);
        assert_eq!(snapshot.selected_plan, Some(expected));
    }

    #[test]
    fn controller_is_deterministic_given_seed() {
        let mk = || {
            let mut c = AdaptiveController::new(AdaptivePolicy::default(), 7);
            c.update_estimate(est(0.02, 10_000_000.0));
            let mut picks = Vec::new();
            for _ in 0..20 {
                let plan = c.next_block_plan(1024).unwrap();
                c.observe(
                    u64::from(plan.k),
                    u64::from(plan.k),
                    0.01,
                    u64::from(plan.k) * 1024,
                );
                picks.push(plan.k);
            }
            picks
        };
        assert_eq!(mk(), mk(), "same seed ⇒ identical decision sequence");
    }

    #[test]
    fn path_signals_are_clamped_and_smoothed() {
        let mut c = AdaptiveController::new(AdaptivePolicy::default(), 11);
        let first = c.update_path_signals(PathSignalSample {
            smoothed_rtt_s: f64::NAN,
            congestion_window_bytes: 0,
            loss_rate: f64::NAN,
        });
        assert_eq!(first.smoothed_rtt_s, MIN_PATH_RTT_S);
        assert_eq!(first.congestion_window_bytes, 1);
        assert_eq!(first.loss_rate, 0.0);

        let bounded = PathSignalSample {
            smoothed_rtt_s: f64::INFINITY,
            congestion_window_bytes: 0,
            loss_rate: f64::INFINITY,
        }
        .clamped();
        assert_eq!(bounded.smoothed_rtt_s, MAX_PATH_RTT_S);
        assert_eq!(bounded.congestion_window_bytes, 1);
        assert_eq!(bounded.loss_rate, MAX_PATH_LOSS_RATE);

        let second = c.update_path_signals(PathSignalSample {
            smoothed_rtt_s: 1.0,
            congestion_window_bytes: 1_000_000,
            loss_rate: 0.50,
        });
        assert!(
            second.smoothed_rtt_s > MIN_PATH_RTT_S && second.smoothed_rtt_s < 1.0,
            "RTT should move by EMA, not jump to the sample: {second:?}"
        );
        assert!(
            second.congestion_window_bytes > 1 && second.congestion_window_bytes < 1_000_000,
            "cwnd should move by EMA, not jump to the sample: {second:?}"
        );
        assert!(
            second.loss_rate > 0.0 && second.loss_rate < 0.50,
            "loss should move by EMA, not jump to the sample: {second:?}"
        );
    }

    #[test]
    fn path_signal_zero_useful_outcome_updates_reward() {
        let policy = AdaptivePolicy {
            arm_grid_k: vec![512, 8192],
            arm_grid_fanout: vec![1],
            exp3_eta: 0.30,
            min_samples_to_activate: 1,
            ..AdaptivePolicy::default()
        };
        let mut c = AdaptiveController::new(policy, 31);
        c.update_estimate(PathEstimate {
            samples: 8,
            dec_symbols_per_s: 50_000_000.0,
            ..est(0.02, 20_000_000.0)
        });

        let plan = c.next_block_plan(1024).expect("controller activates");
        let before = c.diagnostic_snapshot();
        let arm = before
            .selected_arm_index
            .expect("next_block_plan records selected arm");
        let before_weight = before.weights[arm];
        assert!(before.path_signals.is_none());

        c.observe_path_signals(
            u64::from(plan.k),
            0,
            0.050,
            0,
            1024,
            PathSignalSample {
                smoothed_rtt_s: 0.050,
                congestion_window_bytes: 512 * 1024,
                loss_rate: 0.75,
            },
        );

        let after = c.diagnostic_snapshot();
        assert!(
            after.path_signals.is_some(),
            "sent-but-zero-useful outcomes must still record path signals"
        );
        assert!(
            after.weights[arm] < before_weight,
            "sent-but-zero-useful outcomes must penalize the played arm: before={} after={}",
            before_weight,
            after.weights[arm]
        );
        assert!(
            c.loss_scale > 0.0,
            "zero-useful feedback must enter the EXP3 loss normalizer"
        );
    }

    #[test]
    fn path_signal_reward_shifts_arm_under_loss_and_small_cwnd() {
        fn train(signals: PathSignalSample) -> usize {
            let mut policy = AdaptivePolicy {
                arm_grid_k: vec![512, 8192],
                arm_grid_fanout: vec![1],
                exp3_eta: 0.30,
                min_samples_to_activate: 1,
                ..AdaptivePolicy::default()
            };
            policy.max_overhead = 0.50;

            let mut c = AdaptiveController::new(policy, 23);
            c.update_estimate(PathEstimate {
                samples: 8,
                dec_symbols_per_s: 50_000_000.0,
                ..est(0.02, 20_000_000.0)
            });
            let mut large_selected_late = 0usize;
            let trials = 700usize;
            for t in 0..trials {
                let plan = c.next_block_plan(1024).expect("controller activates");
                if t >= trials - 200 && plan.k == 8192 {
                    large_selected_late += 1;
                }
                let wall_s = if plan.k == 8192 { 0.004 } else { 0.006 };
                c.observe_path_signals(
                    u64::from(plan.k),
                    u64::from(plan.k),
                    wall_s,
                    u64::from(plan.k) * 1024,
                    1024,
                    signals,
                );
            }
            large_selected_late
        }

        let clean_large = train(PathSignalSample {
            smoothed_rtt_s: 0.010,
            congestion_window_bytes: 64 * 1024 * 1024,
            loss_rate: 0.001,
        });
        let lossy_large = train(PathSignalSample {
            smoothed_rtt_s: 0.050,
            congestion_window_bytes: 512 * 1024,
            loss_rate: 0.25,
        });

        assert!(
            clean_large > 140,
            "clean/high-cwnd path should learn the large arm, got {clean_large}/200"
        );
        assert!(
            lossy_large < 80,
            "lossy/small-cwnd path should shift away from the large arm, got {lossy_large}/200"
        );
    }

    #[test]
    fn exp3_concentrates_on_the_cheap_arm() {
        // Synthetic: one K is always cheaper. The EXP3 loss is seconds-per-useful
        // -byte, so to isolate the arm signal we hold useful_bytes CONSTANT across
        // arms (otherwise larger K trivially amortizes wall time). EXP3 should
        // then raise the cheap arm's selection share well above uniform.
        let mut policy = AdaptivePolicy::default();
        policy.arm_grid_fanout = vec![4]; // collapse fanout so arms == K grid (6 arms)
        policy.exp3_eta = 0.25;
        let cheap_k = 2048u32;
        let mut c = AdaptiveController::new(policy, 99);
        c.update_estimate(est(0.02, 10_000_000.0));
        let mut cheap_selected = 0;
        let trials = 1200;
        const USEFUL: u64 = 1_000_000; // constant across arms
        for t in 0..trials {
            let plan = c.next_block_plan(1024).unwrap();
            // Cheap arm: low wall; all others: 10x wall. Loss ∝ wall now.
            let wall = if plan.k == cheap_k { 0.005 } else { 0.05 };
            if t >= trials - 200 && plan.k == cheap_k {
                cheap_selected += 1;
            }
            c.observe(u64::from(plan.k), u64::from(plan.k), wall, USEFUL);
        }
        // In the last 200 rounds the cheap arm should dominate (uniform share is
        // 200/6 ≈ 33; concentration should push it well past that).
        assert!(
            cheap_selected > 80,
            "EXP3 should concentrate on the cheap arm, got {cheap_selected}/200"
        );
    }
