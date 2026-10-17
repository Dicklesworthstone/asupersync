    #![allow(clippy::pedantic, clippy::nursery, clippy::float_cmp)]

    use super::*;
    use crate::lab::runtime::InvariantViolation;

    #[test]
    fn empty_series_reports_uncalibrated_upper_bound() {
        let estimate = ExplorationBudget::estimate_from_novelty(
            [],
            ExplorationBudgetConfig::new(0.05, 0.95)
                .min_samples(5)
                .max_additional_runs(3),
        );

        assert_eq!(estimate.total_runs, 0);
        assert_eq!(estimate.discoveries, 0);
        assert_eq!(estimate.residual_discovery_rate, 1.0);
        assert_eq!(estimate.conformal_upper_bound, 1.0);
        assert_eq!(estimate.recommended_additional_runs, 3);
        assert!(estimate.exhausted_recommendation);
        assert!(!estimate.target_met);
    }

    #[test]
    fn existing_class_hits_can_satisfy_target_after_min_samples() {
        let estimate = ExplorationBudget::estimate_from_novelty(
            [false; 25],
            ExplorationBudgetConfig::new(0.20, 0.80).min_samples(5),
        );

        assert_eq!(estimate.total_runs, 25);
        assert!(estimate.conformal_upper_bound <= estimate.target_residual_rate);
        assert_eq!(estimate.recommended_additional_runs, 0);
        assert!(estimate.target_met);
        assert!(!estimate.exhausted_recommendation);
    }

    #[test]
    fn binary_bound_fails_closed_before_min_samples() {
        let estimate = ExplorationBudget::estimate_from_novelty(
            [false; 18],
            ExplorationBudgetConfig::new(0.05, 0.95)
                .min_samples(20)
                .max_additional_runs(3),
        );

        assert_eq!(estimate.conformal_upper_bound, 1.0);
        assert!(!estimate.target_met);
        assert_eq!(estimate.recommended_additional_runs, 3);
    }

    #[test]
    fn target_coverage_changes_decision_for_same_observations() {
        let relaxed = ExplorationBudget::estimate_from_novelty(
            [false; 25],
            ExplorationBudgetConfig::new(0.20, 0.80)
                .min_samples(5)
                .max_additional_runs(400),
        );
        let strict = ExplorationBudget::estimate_from_novelty(
            [false; 25],
            ExplorationBudgetConfig::new(0.20, 0.95)
                .min_samples(5)
                .max_additional_runs(400),
        );

        assert_eq!(relaxed.conformal_upper_bound, strict.conformal_upper_bound);
        assert!(relaxed.target_met);
        assert!(!strict.target_met);
        assert_eq!(relaxed.recommended_additional_runs, 0);
        assert!(strict.recommended_additional_runs > 0);
    }

    #[test]
    fn discoveries_keep_conformal_bound_conservative() {
        let no_discoveries = ExplorationBudget::estimate_from_novelty(
            [false; 25],
            ExplorationBudgetConfig::new(0.20, 0.80).min_samples(5),
        );
        let with_discoveries = ExplorationBudget::estimate_from_novelty(
            [
                true, true, true, true, true, false, false, false, false, false, false, false,
                false, false, false, false, false, false, false, false, false, false, false, false,
                false,
            ],
            ExplorationBudgetConfig::new(0.20, 0.80).min_samples(5),
        );

        assert!(with_discoveries.conformal_upper_bound >= no_discoveries.conformal_upper_bound);
        assert!(with_discoveries.recommended_additional_runs > 0);
    }

    #[test]
    fn counts_match_same_size_novelty_series() {
        let config = ExplorationBudgetConfig::new(0.20, 0.80).min_samples(5);
        let from_counts = ExplorationBudget::estimate_from_counts(10, 2, config);
        let from_series = ExplorationBudget::estimate_from_novelty(
            [
                true, false, false, true, false, false, false, false, false, false,
            ],
            config,
        );

        assert_eq!(
            from_counts.conformal_upper_bound,
            from_series.conformal_upper_bound
        );
        assert_eq!(
            from_counts.residual_discovery_rate,
            from_series.residual_discovery_rate
        );
    }

    #[test]
    fn run_results_feed_budget_estimator() {
        let runs = [
            RunResult {
                seed: 1,
                steps: 10,
                fingerprint: 101,
                is_new_class: true,
                violations: Vec::<InvariantViolation>::new(),
                certificate_hash: 1_001,
            },
            RunResult {
                seed: 2,
                steps: 8,
                fingerprint: 101,
                is_new_class: false,
                violations: Vec::<InvariantViolation>::new(),
                certificate_hash: 1_001,
            },
        ];

        let estimate = ExplorationBudget::estimate_from_runs(
            &runs,
            ExplorationBudgetConfig::new(0.20, 0.80).min_samples(2),
        );

        assert_eq!(estimate.total_runs, 2);
        assert_eq!(estimate.discoveries, 1);
        assert_eq!(estimate.residual_discovery_rate, 0.5);
    }
