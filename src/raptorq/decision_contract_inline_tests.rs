    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[test]
    fn healthy_snapshot_has_dominant_healthy_posterior() {
        let telemetry = evaluate_governance(&GovernanceSnapshot {
            n_rows: 24,
            n_cols: 16,
            density_permille: 90,
            rank_deficit_permille: 0,
            inactivation_pressure_permille: 80,
            overhead_ratio_permille: 120,
            budget_exhausted: false,
            baseline_loss: 540,
            high_support_loss: 760,
            block_schur_loss: u32::MAX,
        });

        // With missing block_schur (u32::MAX) there is non-trivial uncertainty,
        // so the expected-loss-optimal action is canary_hold (cautious monitoring).
        // The loss matrix favors canary_hold when degraded/unknown mass > ~15%.
        assert!(
            telemetry.chosen_action == "canary_hold" || telemetry.chosen_action == "continue",
            "healthy snapshot should prefer canary_hold or continue, got: {}",
            telemetry.chosen_action
        );
        assert!(!telemetry.deterministic_fallback_triggered);
        assert_eq!(telemetry.replay_ref, G7_DECISION_REPLAY_REF);
        assert!(
            telemetry.state_posterior_permille[state::HEALTHY]
                > telemetry.state_posterior_permille[state::DEGRADED]
        );
    }

    #[test]
    fn very_clean_snapshot_prefers_continue() {
        // Minimal pressure, all losses available and well-separated
        let telemetry = evaluate_governance(&GovernanceSnapshot {
            n_rows: 16,
            n_cols: 12,
            density_permille: 20,
            rank_deficit_permille: 0,
            inactivation_pressure_permille: 10,
            overhead_ratio_permille: 15,
            budget_exhausted: false,
            baseline_loss: 100,
            high_support_loss: 800,
            block_schur_loss: 900,
        });

        assert_eq!(
            telemetry.chosen_action, "continue",
            "very clean snapshot with well-separated losses should prefer continue"
        );
        assert!(!telemetry.deterministic_fallback_triggered);
    }

    #[test]
    fn surfaced_expected_loss_ties_drive_the_reported_action() {
        let telemetry = evaluate_governance(&GovernanceSnapshot {
            n_rows: 24,
            n_cols: 16,
            density_permille: 0,
            rank_deficit_permille: 0,
            inactivation_pressure_permille: 0,
            overhead_ratio_permille: 150,
            budget_exhausted: false,
            baseline_loss: 520,
            high_support_loss: 900,
            block_schur_loss: 900,
        });

        assert!(!telemetry.deterministic_fallback_triggered);
        assert_eq!(
            telemetry.expected_loss_terms[action::CONTINUE],
            telemetry.expected_loss_terms[action::CANARY_HOLD],
            "regression fixture requires a surfaced tie on the minimum expected-loss terms"
        );
        assert_eq!(
            telemetry.chosen_action,
            action_label(choose_action_from_expected_loss_terms(
                telemetry.expected_loss_terms,
            )),
        );
        assert_eq!(telemetry.chosen_action, "canary_hold");
    }

    #[test]
    fn exact_canary_hold_action_is_reported_without_fallback() {
        let contract = RaptorQDecisionContract::new();
        let snapshot = GovernanceSnapshot {
            n_rows: 24,
            n_cols: 16,
            density_permille: 0,
            rank_deficit_permille: 0,
            inactivation_pressure_permille: 0,
            overhead_ratio_permille: 0,
            budget_exhausted: false,
            baseline_loss: 500,
            high_support_loss: 520,
            block_schur_loss: 540,
        };

        let telemetry = contract.telemetry(&snapshot);
        let ctx = eval_context(
            &snapshot,
            telemetry.confidence_score,
            telemetry.uncertainty_score,
        );
        let fallback = contract.fallback_policy();

        assert_eq!(telemetry.chosen_action, "canary_hold");
        assert!(!telemetry.deterministic_fallback_triggered);
        assert_eq!(telemetry.deterministic_fallback_reason, "none");
        assert!(
            telemetry.expected_loss_terms[action::CANARY_HOLD]
                < telemetry.expected_loss_terms[action::CONTINUE]
        );
        assert!(
            telemetry.expected_loss_terms[action::CANARY_HOLD]
                < telemetry.expected_loss_terms[action::ROLLBACK]
        );
        assert!(
            telemetry.expected_loss_terms[action::CANARY_HOLD]
                < telemetry.expected_loss_terms[action::FALLBACK]
        );
        assert!(ctx.calibration_score >= fallback.calibration_drift_threshold);
        assert!(ctx.e_process <= fallback.e_process_breach_threshold);
        assert!(ctx.ci_width <= fallback.confidence_width_threshold);
    }

    #[test]
    fn budget_exhaustion_forces_fallback() {
        let telemetry = evaluate_governance(&GovernanceSnapshot {
            n_rows: 65,
            n_cols: 65,
            density_permille: 1000,
            rank_deficit_permille: 500,
            inactivation_pressure_permille: 900,
            overhead_ratio_permille: 0,
            budget_exhausted: true,
            baseline_loss: 1024,
            high_support_loss: 1700,
            block_schur_loss: 1600,
        });

        assert_eq!(telemetry.chosen_action, "fallback");
        assert!(telemetry.deterministic_fallback_triggered);
        assert_eq!(
            telemetry.deterministic_fallback_reason,
            FALLBACK_REASON_POLICY_BUDGET_EXHAUSTED
        );
    }

    #[test]
    fn policy_fallback_never_reports_none_reason() {
        let telemetry = evaluate_governance(&GovernanceSnapshot {
            n_rows: 48,
            n_cols: 32,
            density_permille: 10,
            rank_deficit_permille: 0,
            inactivation_pressure_permille: 600,
            overhead_ratio_permille: 0,
            budget_exhausted: false,
            baseline_loss: 100,
            high_support_loss: 800,
            block_schur_loss: 900,
        });

        assert!(
            telemetry.deterministic_fallback_triggered,
            "e-process breach should activate fallback"
        );
        assert_eq!(telemetry.chosen_action, "fallback");
        assert_eq!(
            telemetry.deterministic_fallback_reason, FALLBACK_REASON_UNCLASSIFIED,
            "fallback-active telemetry must never report reason=none"
        );
        assert!(
            telemetry.confidence_score <= 250,
            "fallback-active telemetry must clamp surfaced confidence even when the reason is synthesized"
        );
        assert_eq!(
            telemetry.confidence_score + telemetry.uncertainty_score,
            1000,
            "fallback-active telemetry must keep confidence/uncertainty normalized after clamping"
        );
    }

    #[test]
    fn explicit_regression_low_confidence_reason_is_reported() {
        let contract = RaptorQDecisionContract::new();
        let snapshot = GovernanceSnapshot {
            n_rows: 48,
            n_cols: 32,
            density_permille: 0,
            rank_deficit_permille: 650,
            inactivation_pressure_permille: 150,
            overhead_ratio_permille: 100,
            budget_exhausted: false,
            baseline_loss: 500,
            high_support_loss: 520,
            block_schur_loss: 540,
        };

        let posterior_permille = RaptorQDecisionContract::state_posterior_permille(&snapshot);
        let posterior = posterior_from_permille(posterior_permille)
            .expect("state_posterior_permille must produce a valid posterior");
        let preliminary_confidence = (((u32::from(concentration_score(posterior_permille)) * 7)
            + (u32::from(action_margin_score(expected_loss_terms(
                contract.loss_matrix(),
                &posterior,
            ))) * 3))
            / 10) as u16;
        let telemetry = contract.telemetry(&snapshot);

        assert!(posterior_permille[state::REGRESSION] > posterior_permille[state::HEALTHY]);
        assert!(posterior_permille[state::REGRESSION] > posterior_permille[state::DEGRADED]);
        assert!(posterior_permille[state::REGRESSION] > posterior_permille[state::UNKNOWN]);
        assert!(
            preliminary_confidence < 500,
            "test must stay on the low-confidence side of the explicit REGRESSION fallback seam"
        );
        assert_eq!(
            deterministic_fallback_reason(&snapshot, posterior_permille, preliminary_confidence),
            FALLBACK_REASON_REGRESSION_LOW_CONFIDENCE
        );
        assert!(telemetry.deterministic_fallback_triggered);
        assert_eq!(telemetry.chosen_action, "fallback");
        assert_eq!(
            telemetry.deterministic_fallback_reason,
            FALLBACK_REASON_REGRESSION_LOW_CONFIDENCE
        );
        assert!(
            telemetry.confidence_score <= 250,
            "fallback-reason path should clamp surfaced confidence"
        );
    }

    #[test]
    fn telemetry_fields_are_normalized_and_stable() {
        let snapshot = GovernanceSnapshot {
            n_rows: 18,
            n_cols: 16,
            density_permille: 820,
            rank_deficit_permille: 140,
            inactivation_pressure_permille: 760,
            overhead_ratio_permille: 60,
            budget_exhausted: false,
            baseline_loss: 1180,
            high_support_loss: 900,
            block_schur_loss: 880,
        };

        let first = evaluate_governance(&snapshot);
        let second = evaluate_governance(&snapshot);

        assert_eq!(first, second, "governance evaluation must be deterministic");
        assert_eq!(
            first
                .state_posterior_permille
                .iter()
                .map(|&value| u32::from(value))
                .sum::<u32>(),
            PERMILLE_SCALE
        );
        assert_eq!(
            first
                .top_evidence_contributors
                .iter()
                .map(|entry| u32::from(entry.contribution_permille))
                .sum::<u32>(),
            PERMILLE_SCALE
        );
        assert!(first.confidence_score <= 1000);
        assert!(first.uncertainty_score <= 1000);
    }

    #[test]
    fn high_pressure_snapshot_prefers_rollback_or_fallback() {
        let telemetry = evaluate_governance(&GovernanceSnapshot {
            n_rows: 64,
            n_cols: 64,
            density_permille: 950,
            rank_deficit_permille: 800,
            inactivation_pressure_permille: 850,
            overhead_ratio_permille: 700,
            budget_exhausted: false,
            baseline_loss: 2000,
            high_support_loss: 1800,
            block_schur_loss: 1900,
        });

        assert!(
            telemetry.chosen_action == "rollback" || telemetry.chosen_action == "fallback",
            "high-pressure snapshot should prefer rollback or fallback, got: {}",
            telemetry.chosen_action
        );
        assert!(
            telemetry.state_posterior_permille[state::REGRESSION]
                > telemetry.state_posterior_permille[state::HEALTHY],
            "regression posterior should exceed healthy under high pressure"
        );
    }

    #[test]
    fn exact_rollback_action_is_reported_without_fallback() {
        let contract = RaptorQDecisionContract::new();
        let snapshot = GovernanceSnapshot {
            n_rows: 40,
            n_cols: 32,
            density_permille: 500,
            rank_deficit_permille: 50,
            inactivation_pressure_permille: 400,
            overhead_ratio_permille: 600,
            budget_exhausted: false,
            baseline_loss: 100,
            high_support_loss: 800,
            block_schur_loss: 900,
        };

        let telemetry = contract.telemetry(&snapshot);
        let ctx = eval_context(
            &snapshot,
            telemetry.confidence_score,
            telemetry.uncertainty_score,
        );
        let fallback = contract.fallback_policy();

        assert_eq!(telemetry.chosen_action, "rollback");
        assert!(!telemetry.deterministic_fallback_triggered);
        assert_eq!(telemetry.deterministic_fallback_reason, "none");
        assert!(
            telemetry.expected_loss_terms[action::ROLLBACK]
                < telemetry.expected_loss_terms[action::CONTINUE]
        );
        assert!(
            telemetry.expected_loss_terms[action::ROLLBACK]
                < telemetry.expected_loss_terms[action::CANARY_HOLD]
        );
        assert!(
            telemetry.expected_loss_terms[action::ROLLBACK]
                < telemetry.expected_loss_terms[action::FALLBACK]
        );
        assert!(ctx.calibration_score >= fallback.calibration_drift_threshold);
        assert!(ctx.e_process <= fallback.e_process_breach_threshold);
        assert!(ctx.ci_width <= fallback.confidence_width_threshold);
    }

    #[test]
    fn moderate_pressure_selects_conservative_action() {
        let telemetry = evaluate_governance(&GovernanceSnapshot {
            n_rows: 32,
            n_cols: 24,
            density_permille: 450,
            rank_deficit_permille: 200,
            inactivation_pressure_permille: 400,
            overhead_ratio_permille: 350,
            budget_exhausted: false,
            baseline_loss: 800,
            high_support_loss: 600,
            block_schur_loss: 750,
        });

        // Under moderate pressure the expected-loss engine may select
        // canary_hold, rollback, or fallback depending on posterior shape.
        assert!(
            telemetry.chosen_action != "continue",
            "moderate pressure should not prefer continue, got: {}",
            telemetry.chosen_action
        );
    }

    #[test]
    fn unknown_state_low_confidence_triggers_fallback() {
        // Conflicting policy signals + missing block_schur → high unknown posterior
        let telemetry = evaluate_governance(&GovernanceSnapshot {
            n_rows: 40,
            n_cols: 32,
            density_permille: 300,
            rank_deficit_permille: 100,
            inactivation_pressure_permille: 200,
            overhead_ratio_permille: 100,
            budget_exhausted: true,
            baseline_loss: 500,
            high_support_loss: 500,
            block_schur_loss: u32::MAX,
        });

        assert!(
            telemetry.deterministic_fallback_triggered,
            "budget exhaustion should trigger deterministic fallback"
        );
        assert_eq!(telemetry.chosen_action, "fallback");
    }

    #[test]
    fn explicit_unknown_low_confidence_reason_is_reported() {
        // Missing block_schur plus maximally conflicting policy losses make UNKNOWN
        // the dominant posterior state, while high rank pressure keeps confidence low
        // without relying on the separate budget-exhaustion fallback path.
        let telemetry = evaluate_governance(&GovernanceSnapshot {
            n_rows: 48,
            n_cols: 32,
            density_permille: 0,
            rank_deficit_permille: 650,
            inactivation_pressure_permille: 0,
            overhead_ratio_permille: 190,
            budget_exhausted: false,
            baseline_loss: 500,
            high_support_loss: 500,
            block_schur_loss: u32::MAX,
        });

        assert!(
            telemetry.state_posterior_permille[state::UNKNOWN]
                > telemetry.state_posterior_permille[state::HEALTHY]
        );
        assert!(
            telemetry.state_posterior_permille[state::UNKNOWN]
                > telemetry.state_posterior_permille[state::DEGRADED]
        );
        assert!(
            telemetry.state_posterior_permille[state::UNKNOWN]
                > telemetry.state_posterior_permille[state::REGRESSION]
        );
        assert!(
            telemetry.confidence_score < 350,
            "test must stay on the low-confidence side of the explicit UNKNOWN fallback seam"
        );
        assert!(
            telemetry.deterministic_fallback_triggered,
            "explicit low-confidence UNKNOWN path must trigger deterministic fallback"
        );
        assert_eq!(telemetry.chosen_action, "fallback");
        assert_eq!(
            telemetry.deterministic_fallback_reason,
            FALLBACK_REASON_UNKNOWN_LOW_CONFIDENCE
        );
    }

    #[test]
    fn conflicting_evidence_raises_uncertainty() {
        // All policy losses are nearly identical → high conflict → high unknown
        let telemetry = evaluate_governance(&GovernanceSnapshot {
            n_rows: 20,
            n_cols: 16,
            density_permille: 200,
            rank_deficit_permille: 50,
            inactivation_pressure_permille: 100,
            overhead_ratio_permille: 50,
            budget_exhausted: false,
            baseline_loss: 1000,
            high_support_loss: 1001,
            block_schur_loss: 1002,
        });

        // With closely matched losses, uncertainty should be material
        assert!(
            telemetry.uncertainty_score >= 500,
            "conflicting evidence should produce high uncertainty, got: {}",
            telemetry.uncertainty_score
        );
    }

    #[test]
    fn structured_log_contains_all_required_fields() {
        let telemetry = evaluate_governance(&GovernanceSnapshot {
            n_rows: 24,
            n_cols: 16,
            density_permille: 90,
            rank_deficit_permille: 0,
            inactivation_pressure_permille: 80,
            overhead_ratio_permille: 120,
            budget_exhausted: false,
            baseline_loss: 540,
            high_support_loss: 760,
            block_schur_loss: u32::MAX,
        });

        let log = telemetry.to_structured_log();

        assert!(
            log.starts_with("g7_decision:"),
            "log must start with g7_decision prefix"
        );
        assert!(log.contains("decision_id="), "log must include decision id");
        assert!(log.contains("trace_id="), "log must include trace id");
        assert!(
            log.contains("state_posterior="),
            "log must include state_posterior"
        );
        assert!(
            log.contains("expected_loss="),
            "log must include expected_loss"
        );
        assert!(log.contains("action="), "log must include chosen action");
        assert!(
            log.contains("confidence="),
            "log must include confidence score"
        );
        assert!(
            log.contains("uncertainty="),
            "log must include uncertainty score"
        );
        assert!(log.contains("fallback="), "log must include fallback flag");
        assert!(log.contains("reason="), "log must include fallback reason");
        assert!(log.contains("replay="), "log must include replay ref");
        assert!(
            log.contains("top="),
            "log must include top evidence contributors"
        );
        assert!(
            log.contains(&format!("decision_id={}", telemetry.decision_id)),
            "log decision id must match telemetry"
        );
        assert!(
            log.contains(&format!("trace_id={}", telemetry.trace_id)),
            "log trace id must match telemetry"
        );
    }

    #[test]
    fn display_impl_matches_structured_log() {
        let telemetry = evaluate_governance(&GovernanceSnapshot {
            n_rows: 24,
            n_cols: 16,
            density_permille: 500,
            rank_deficit_permille: 300,
            inactivation_pressure_permille: 400,
            overhead_ratio_permille: 200,
            budget_exhausted: false,
            baseline_loss: 800,
            high_support_loss: 900,
            block_schur_loss: 850,
        });

        assert_eq!(
            format!("{telemetry}"),
            telemetry.to_structured_log(),
            "Display impl must match to_structured_log"
        );
    }

    #[test]
    fn replay_reproducibility_across_contract_instances() {
        let snapshot = GovernanceSnapshot {
            n_rows: 48,
            n_cols: 32,
            density_permille: 600,
            rank_deficit_permille: 250,
            inactivation_pressure_permille: 500,
            overhead_ratio_permille: 300,
            budget_exhausted: false,
            baseline_loss: 1200,
            high_support_loss: 950,
            block_schur_loss: 1100,
        };

        let contract_a = RaptorQDecisionContract::new();
        let contract_b = RaptorQDecisionContract::new();

        let telemetry_a = contract_a.telemetry(&snapshot);
        let telemetry_b = contract_b.telemetry(&snapshot);

        assert_eq!(
            telemetry_a, telemetry_b,
            "different contract instances must produce identical telemetry for the same snapshot"
        );
        assert_eq!(
            telemetry_a.to_structured_log(),
            telemetry_b.to_structured_log(),
            "structured log output must be identical across instances"
        );
    }

    #[test]
    fn confidence_uncertainty_are_complementary() {
        for (density, rank, inact, overhead) in [
            (0, 0, 0, 0),
            (500, 500, 500, 500),
            (1000, 1000, 1000, 1000),
            (100, 900, 50, 200),
        ] {
            let telemetry = evaluate_governance(&GovernanceSnapshot {
                n_rows: 32,
                n_cols: 24,
                density_permille: density,
                rank_deficit_permille: rank,
                inactivation_pressure_permille: inact,
                overhead_ratio_permille: overhead,
                budget_exhausted: false,
                baseline_loss: 600,
                high_support_loss: 800,
                block_schur_loss: 700,
            });

            assert_eq!(
                telemetry.confidence_score + telemetry.uncertainty_score,
                1000,
                "confidence + uncertainty must equal 1000 for density={density} rank={rank}"
            );
        }
    }

    #[test]
    fn all_actions_are_reachable() {
        // Very clean → continue (well-separated losses, no missing block_schur)
        let healthy = evaluate_governance(&GovernanceSnapshot {
            n_rows: 16,
            n_cols: 12,
            density_permille: 20,
            rank_deficit_permille: 0,
            inactivation_pressure_permille: 10,
            overhead_ratio_permille: 15,
            budget_exhausted: false,
            baseline_loss: 100,
            high_support_loss: 800,
            block_schur_loss: 900,
        });
        assert_eq!(healthy.chosen_action, "continue");

        // Budget exhausted → fallback
        let exhausted = evaluate_governance(&GovernanceSnapshot {
            n_rows: 64,
            n_cols: 64,
            density_permille: 900,
            rank_deficit_permille: 700,
            inactivation_pressure_permille: 800,
            overhead_ratio_permille: 600,
            budget_exhausted: true,
            baseline_loss: 2000,
            high_support_loss: 1800,
            block_schur_loss: 1900,
        });
        assert_eq!(exhausted.chosen_action, "fallback");

        // Verify each action is a valid label
        for action_name in &["continue", "canary_hold", "rollback", "fallback"] {
            let idx = match *action_name {
                "continue" => action::CONTINUE,
                "canary_hold" => action::CANARY_HOLD,
                "rollback" => action::ROLLBACK,
                "fallback" => action::FALLBACK,
                _ => unreachable!(),
            };
            assert_eq!(action_label(idx), *action_name);
        }
    }

    #[test]
    fn action_label_out_of_range_returns_fallback() {
        assert_eq!(action_label(99), "fallback");
        assert_eq!(action_label(usize::MAX), "fallback");
    }

    #[test]
    fn normalize_permille_zero_total_gives_uniform() {
        let result = normalize_permille([0, 0, 0, 0]);
        assert_eq!(result, [250, 250, 250, 250]);
    }

    #[test]
    fn normalize_permille_does_not_assign_remainder_to_zero_score_bucket() {
        let result = normalize_permille([1, 1, 1, 0]);
        assert_eq!(result, [334, 333, 333, 0]);
    }

    #[test]
    fn posterior_from_permille_rejects_malformed_distribution() {
        let err = posterior_from_permille([1000, 1000, 1000, 1000])
            .expect_err("non-normalized permille input must not construct a posterior");

        assert!(
            matches!(err, ValidationError::PosteriorNotNormalized { sum } if (sum - 4.0).abs() < f64::EPSILON),
            "expected PosteriorNotNormalized, got {err:?}"
        );
    }

    #[test]
    fn malformed_posterior_telemetry_fails_closed_with_full_uncertainty() {
        let snapshot = GovernanceSnapshot {
            n_rows: 48,
            n_cols: 32,
            density_permille: 400,
            rank_deficit_permille: 250,
            inactivation_pressure_permille: 300,
            overhead_ratio_permille: 150,
            budget_exhausted: false,
            baseline_loss: 500,
            high_support_loss: 520,
            block_schur_loss: 540,
        };
        let posterior_permille = [1000, 1000, 1000, 1000];
        let error = posterior_from_permille(posterior_permille)
            .expect_err("malformed posterior fixture must reject before telemetry fallback");
        let telemetry = RaptorQDecisionContract::malformed_posterior_fallback_telemetry(
            &snapshot,
            posterior_permille,
            &error,
        );

        assert_eq!(telemetry.state_posterior_permille, posterior_permille);
        assert_eq!(
            telemetry.expected_loss_terms,
            MALFORMED_POSTERIOR_EXPECTED_LOSS_TERMS
        );
        assert_eq!(telemetry.chosen_action, "fallback");
        assert!(telemetry.deterministic_fallback_triggered);
        assert_eq!(
            telemetry.deterministic_fallback_reason,
            FALLBACK_REASON_UNCLASSIFIED
        );
        assert_eq!(telemetry.confidence_score, 0);
        assert_eq!(telemetry.uncertainty_score, 1000);
        assert!(
            is_runtime_fallback_reason(telemetry.deterministic_fallback_reason),
            "malformed posterior fallback must use a canonical runtime reason"
        );
    }

    #[test]
    fn contributor_normalization_does_not_assign_remainder_to_zero_weight() {
        let result = normalize_contributor_permille([2, 1, 0]);
        assert_eq!(result, [667, 333, 0]);
    }

    #[test]
    fn contract_trait_methods_are_consistent() {
        let contract = RaptorQDecisionContract::new();
        assert_eq!(contract.name(), "raptorq_expected_loss_governance");
        assert_eq!(contract.state_space().len(), state::COUNT);
        assert_eq!(contract.action_set().len(), action::COUNT);
        assert_eq!(contract.fallback_action(), action::FALLBACK);

        // Loss matrix dimensions match states × actions
        let losses = contract.loss_matrix();
        for s in 0..state::COUNT {
            for a in 0..action::COUNT {
                let loss = losses.get(s, a);
                assert!(loss >= 0.0, "loss({s},{a}) must be non-negative");
            }
        }
    }

    #[test]
    fn choose_action_uses_conservative_tie_breaker() {
        let contract = RaptorQDecisionContract::new();

        let continue_vs_hold = Posterior::new(vec![0.75, 0.25, 0.0, 0.0]).unwrap();
        assert_eq!(
            contract.choose_action(&continue_vs_hold),
            action::CANARY_HOLD,
            "equal expected loss between continue/canary_hold must prefer canary_hold"
        );

        let rollback_vs_fallback = Posterior::new(vec![0.25, 0.0, 0.75, 0.0]).unwrap();
        assert_eq!(
            contract.choose_action(&rollback_vs_fallback),
            action::FALLBACK,
            "equal expected loss between rollback/fallback must prefer fallback"
        );
    }

    #[test]
    fn posterior_update_concentrates_on_observation() {
        let contract = RaptorQDecisionContract::new();
        let mut posterior = Posterior::uniform(state::COUNT);
        contract
            .update_posterior(&mut posterior, state::REGRESSION)
            .expect("update_posterior succeeds for matching length + valid observation");

        // After observing REGRESSION, its probability should increase
        let probs = posterior.probs();
        assert!(
            probs[state::REGRESSION] > probs[state::HEALTHY],
            "regression probability should exceed healthy after observing regression"
        );
    }

    #[test]
    fn choose_action_fails_closed_for_malformed_posterior_length() {
        let contract = RaptorQDecisionContract::new();
        let malformed = Posterior::new(vec![0.34, 0.33, 0.33]).unwrap();

        assert_eq!(
            contract.choose_action(&malformed),
            action::FALLBACK,
            "malformed posterior length must fail closed to fallback"
        );
    }

    #[test]
    fn posterior_update_returns_length_mismatch_error() {
        // br-asupersync-u5uhpt: previously a wrong-length posterior was
        // a silent no-op. Now it surfaces a typed error and the posterior
        // remains unchanged so callers can fall back deterministically.
        let contract = RaptorQDecisionContract::new();
        let mut malformed = Posterior::new(vec![0.34, 0.33, 0.33]).unwrap();
        let before = malformed.probs().to_vec();

        let err = contract
            .update_posterior(&mut malformed, state::REGRESSION)
            .expect_err("wrong-length posterior must surface a typed error");

        assert!(
            matches!(
                err,
                franken_decision::UpdatePosteriorError::LengthMismatch {
                    expected: state::COUNT,
                    actual: 3,
                }
            ),
            "expected LengthMismatch, got {err:?}"
        );
        assert_eq!(
            malformed.probs(),
            before.as_slice(),
            "malformed posterior length must remain unchanged after update"
        );
    }

    #[test]
    fn posterior_update_returns_observation_out_of_range_error() {
        // br-asupersync-u5uhpt: an out-of-range observation must surface a
        // typed error; the posterior must remain unchanged.
        let contract = RaptorQDecisionContract::new();
        let mut posterior = Posterior::uniform(state::COUNT);
        let before = posterior.probs().to_vec();

        let err = contract
            .update_posterior(&mut posterior, usize::MAX)
            .expect_err("out-of-range observation must surface a typed error");

        assert!(
            matches!(
                err,
                franken_decision::UpdatePosteriorError::ObservationOutOfRange {
                    observation: usize::MAX,
                    state_count: state::COUNT,
                }
            ),
            "expected ObservationOutOfRange, got {err:?}"
        );
        assert_eq!(
            posterior.probs(),
            before.as_slice(),
            "out-of-range observations must not perturb posterior state"
        );
    }

    #[test]
    fn default_impl_matches_new() {
        let from_new = RaptorQDecisionContract::new();
        let from_default = RaptorQDecisionContract::default();
        assert_eq!(from_new.name(), from_default.name());
        assert_eq!(from_new.state_space(), from_default.state_space());
        assert_eq!(from_new.action_set(), from_default.action_set());
    }

    #[test]
    fn runtime_fallback_reason_boundary_matches_live_contract() {
        assert_eq!(
            G7_RUNTIME_FALLBACK_REASONS,
            &[
                FALLBACK_REASON_POLICY_BUDGET_EXHAUSTED,
                FALLBACK_REASON_UNKNOWN_LOW_CONFIDENCE,
                FALLBACK_REASON_REGRESSION_LOW_CONFIDENCE,
                FALLBACK_REASON_UNCLASSIFIED,
            ],
            "live runtime fallback boundary must stay aligned with canonical telemetry reasons"
        );

        for reason in G7_RUNTIME_FALLBACK_REASONS {
            assert!(
                is_runtime_fallback_reason(reason),
                "{reason} must remain runtime-emittable"
            );
        }
    }

    #[test]
    fn broader_contract_only_triggers_are_not_runtime_emittable_reasons() {
        for reason in [
            "decode_mismatch_detected",
            "proof_replay_mismatch",
            "none",
            "unknown_reason",
        ] {
            assert!(
                !is_runtime_fallback_reason(reason),
                "{reason} must stay outside the live runtime-emittable reason boundary"
            );
        }
    }

    #[test]
    fn evidence_contributors_are_always_three() {
        for budget_exhausted in [false, true] {
            let telemetry = evaluate_governance(&GovernanceSnapshot {
                n_rows: 32,
                n_cols: 24,
                density_permille: 500,
                rank_deficit_permille: 300,
                inactivation_pressure_permille: 400,
                overhead_ratio_permille: 200,
                budget_exhausted,
                baseline_loss: 800,
                high_support_loss: 900,
                block_schur_loss: 850,
            });

            assert_eq!(telemetry.top_evidence_contributors.len(), 3);
            for contributor in &telemetry.top_evidence_contributors {
                assert!(
                    !contributor.name.is_empty(),
                    "contributor name must not be empty"
                );
                assert!(
                    contributor.contribution_permille <= 1000,
                    "contributor weight must be <= 1000"
                );
            }
        }
    }

    /// br-asupersync-s2jxu0 — DecisionId / TraceId derived from
    /// (n_rows, n_cols) must NOT collide for distinct dimension
    /// pairs. The previous bit-pack
    ///   `(n_rows as u64) << 32 | (n_cols as u64) & 0xFFFF_FFFF`
    /// silently truncated bits >= 32 of either dimension on 64-bit
    /// targets, producing identical IDs for distinct pairs that
    /// differed only in those bits. The fix derives ts_unix_ms from
    /// a DetHasher mix that covers every bit of usize.
    #[test]
    fn s2jxu0_decision_id_distinct_for_distinct_dimensions() {
        fn snapshot_with(n_rows: usize, n_cols: usize) -> GovernanceSnapshot {
            GovernanceSnapshot {
                n_rows,
                n_cols,
                density_permille: 0,
                rank_deficit_permille: 0,
                inactivation_pressure_permille: 0,
                overhead_ratio_permille: 0,
                budget_exhausted: false,
                baseline_loss: 0,
                high_support_loss: 0,
                block_schur_loss: 0,
            }
        }

        // Value pair from the bead instructions: u32::MAX vs u32::MAX-1.
        let a = eval_context(
            &snapshot_with(u32::MAX as usize, (u32::MAX - 1) as usize),
            500,
            500,
        );
        let b = eval_context(
            &snapshot_with((u32::MAX - 1) as usize, u32::MAX as usize),
            500,
            500,
        );
        assert_ne!(
            a.decision_id, b.decision_id,
            "swapping (n_rows, n_cols) must yield distinct DecisionIds"
        );
        assert_ne!(
            a.trace_id, b.trace_id,
            "swapping (n_rows, n_cols) must yield distinct TraceIds"
        );

        // 64-bit-only collision pair: differs only in bits >= 32 of
        // n_rows. Under the old shift-truncating logic these would
        // produce the same ts_unix_ms; under the fix they must
        // differ.
        #[cfg(target_pointer_width = "64")]
        {
            let small = eval_context(&snapshot_with(1, 1), 500, 500);
            // n_rows = 1 + (1 << 32); on the OLD `(n_rows as u64) << 32`
            // path, the bit at index 32 shifts out of u64 and the low
            // bit ends up at position 32 — the same as the small
            // snapshot's encoding. After the fix, full-bit-width
            // hashing makes them distinct.
            let big = eval_context(&snapshot_with(1 + (1usize << 32), 1), 500, 500);
            assert_ne!(
                small.decision_id, big.decision_id,
                "(1,1) and (1+2^32,1) must NOT collide after s2jxu0 fix"
            );
            assert_ne!(
                small.trace_id, big.trace_id,
                "(1,1) and (1+2^32,1) must NOT collide after s2jxu0 fix"
            );
        }

        // Stress: 100 distinct dimension pairs all produce distinct
        // ts_unix_ms surrogates.
        let mut seen = std::collections::HashSet::new();
        for r in 0..10usize {
            for c in 0..10usize {
                let ctx = eval_context(&snapshot_with(r, c), 500, 500);
                assert!(
                    seen.insert(ctx.ts_unix_ms),
                    "duplicate ts_unix_ms for ({r},{c})"
                );
            }
        }
        assert_eq!(seen.len(), 100);
    }

    /// br-asupersync-gqnv2o: when `outcome.fallback_active` is true
    /// AND the deterministic_fallback_reason resolves to "none" (the
    /// UNCLASSIFIED bucket at the publish site), the published
    /// `confidence_score` MUST be the clamped fallback ceiling (250)
    /// rather than the unclamped `preliminary_confidence`. Pre-fix the
    /// triple was inconsistent — a downstream rollback gate that
    /// keys on `(deterministic_fallback_triggered=true,
    /// confidence_score < threshold)` would observe (true, high) and
    /// silently skip the safety branch despite the explicit fallback
    /// signal. The fix re-binds confidence_score and uncertainty_score
    /// to the clamped values when the asymmetry is observed; this
    /// test pins the contract.
    #[test]
    fn gqnv2o_named_fallback_clamps_confidence_to_ceiling() {
        let telemetry = evaluate_governance(&GovernanceSnapshot {
            n_rows: 24,
            n_cols: 16,
            density_permille: 90,
            rank_deficit_permille: 0,
            inactivation_pressure_permille: 80,
            overhead_ratio_permille: 120,
            budget_exhausted: true,
            baseline_loss: 540,
            high_support_loss: 760,
            block_schur_loss: u32::MAX,
        });
        assert!(telemetry.deterministic_fallback_triggered);
        assert!(
            telemetry.confidence_score <= 250,
            "named-reason fallback must clamp confidence to <= 250, \
             got {}",
            telemetry.confidence_score
        );
        assert_eq!(
            u32::from(telemetry.uncertainty_score) + u32::from(telemetry.confidence_score),
            1000
        );
    }

    /// br-asupersync-gqnv2o: defensive sweep — for every snapshot in
    /// a small adversarial set, the
    /// `(deterministic_fallback_triggered=true ⇒ confidence_score<=250)`
    /// implication MUST hold. Catches any future code path that
    /// re-introduces the pre-fix asymmetry.
    #[test]
    fn gqnv2o_fallback_implies_clamped_confidence_invariant() {
        let snapshots = [
            GovernanceSnapshot {
                n_rows: 16,
                n_cols: 16,
                density_permille: 100,
                rank_deficit_permille: 0,
                inactivation_pressure_permille: 0,
                overhead_ratio_permille: 0,
                budget_exhausted: true,
                baseline_loss: 0,
                high_support_loss: 0,
                block_schur_loss: 0,
            },
            GovernanceSnapshot {
                n_rows: 32,
                n_cols: 16,
                density_permille: 200,
                rank_deficit_permille: 100,
                inactivation_pressure_permille: 200,
                overhead_ratio_permille: 250,
                budget_exhausted: true,
                baseline_loss: u32::MAX,
                high_support_loss: u32::MAX,
                block_schur_loss: u32::MAX,
            },
        ];
        for (i, s) in snapshots.iter().enumerate() {
            let telemetry = evaluate_governance(s);
            if telemetry.deterministic_fallback_triggered {
                assert!(
                    telemetry.confidence_score <= 250,
                    "snapshot[{i}]: fallback triggered but confidence={} \
                     — gate would not engage rollback (br-asupersync-gqnv2o)",
                    telemetry.confidence_score
                );
                assert_eq!(
                    u32::from(telemetry.uncertainty_score) + u32::from(telemetry.confidence_score),
                    1000,
                    "snapshot[{i}]: uncertainty + confidence != 1000"
                );
            }
        }
    }

    /// br-asupersync-dezwpc: pin the contract-evaluation-error fallback path
    /// constants. The early-return GovernanceTelemetry on `evaluate()` Err
    /// must use action::FALLBACK (the conservative action) and a reason
    /// registered in G7_RUNTIME_FALLBACK_REASONS. Previously emitted
    /// action::CONTINUE (most-aggressive) and "contract_action_out_of_range"
    /// (unregistered) — fail-open on contract error, broke reason invariant.
    #[test]
    fn dezwpc_contract_error_fallback_uses_canonical_action_and_reason() {
        // The action emitted on the contract-evaluation-error path must
        // resolve to the conservative "fallback" label, not "continue".
        assert_eq!(
            action_label(action::FALLBACK),
            "fallback",
            "action::FALLBACK must label as 'fallback' for safety-gate matching"
        );
        assert_ne!(
            action_label(action::FALLBACK),
            action_label(action::CONTINUE),
            "FALLBACK and CONTINUE labels must be distinct"
        );

        // The deterministic_fallback_reason emitted on the error path must
        // pass the canonical-reason filter, otherwise replay/golden-snapshot
        // validators silently drop these telemetry rows.
        assert!(
            is_runtime_fallback_reason(FALLBACK_REASON_UNCLASSIFIED),
            "FALLBACK_REASON_UNCLASSIFIED must be registered in G7_RUNTIME_FALLBACK_REASONS"
        );
        // The previous (buggy) reason string must NOT pass the filter — pin
        // the regression so a future revert is caught.
        assert!(
            !is_runtime_fallback_reason("contract_action_out_of_range"),
            "the previously-emitted unregistered reason string must remain rejected; \
             if you re-add it, also register it in G7_RUNTIME_FALLBACK_REASONS"
        );
    }
