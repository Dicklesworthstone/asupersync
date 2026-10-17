    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::types::Time;
    use franken_decision::{EvalContext, Posterior, evaluate};
    use franken_kernel::{DecisionId, TraceId};
    use serde_json::{Value, json};

    #[inline]
    fn test_ctx(cal: f64) -> EvalContext {
        EvalContext {
            calibration_score: cal,
            e_process: 1.0,
            ci_width: 0.1,
            decision_id: DecisionId::from_parts(1_700_000_000_000, 42),
            trace_id: TraceId::from_parts(1_700_000_000_000, 1),
            ts_unix_ms: 1_700_000_000_000,
        }
    }

    #[inline]
    fn zero_snapshot() -> StateSnapshot {
        StateSnapshot {
            time: Time::ZERO,
            live_tasks: 0,
            pending_obligations: 0,
            obligation_age_sum_ns: 0,
            draining_regions: 0,
            deadline_pressure: 0.0,
            pending_send_permits: 0,
            pending_acks: 0,
            pending_leases: 0,
            pending_io_ops: 0,
            cancel_requested_tasks: 0,
            cancelling_tasks: 0,
            finalizing_tasks: 0,
            ready_queue_depth: 0,
        }
    }

    fn scrub_decision_output(value: Value) -> Value {
        let mut scrubbed = value;

        if let Some(audit) = scrubbed
            .get_mut("audit_entry")
            .and_then(Value::as_object_mut)
        {
            if let Some(decision_id) = audit.get_mut("decision_id") {
                *decision_id = Value::String("[DECISION_ID]".into());
            }
            if let Some(trace_id) = audit.get_mut("trace_id") {
                *trace_id = Value::String("[TRACE_ID]".into());
            }
            if let Some(ts_unix_ms) = audit.get_mut("ts_unix_ms") {
                *ts_unix_ms = Value::String("[TS_MS]".into());
            }
        }

        scrubbed
    }

    #[test]
    fn contract_creation() {
        let c = SchedulerDecisionContract::new();
        assert_eq!(c.name(), "scheduler");
        assert_eq!(c.state_space().len(), 4);
        assert_eq!(c.action_set().len(), 3);
    }

    #[test]
    fn healthy_state_prefers_aggressive() {
        let c = SchedulerDecisionContract::new();
        // Posterior concentrated on healthy.
        let posterior = Posterior::new(vec![0.9, 0.03, 0.03, 0.04]).unwrap();
        let outcome =
            evaluate(&c, &posterior, &test_ctx(0.95)).expect("test contract action_index in range");
        assert_eq!(outcome.action_index, action::AGGRESSIVE);
        assert!(!outcome.fallback_active);
    }

    #[test]
    fn congested_state_prefers_conservative() {
        let c = SchedulerDecisionContract::new();
        // Posterior concentrated on congested.
        let posterior = Posterior::new(vec![0.05, 0.85, 0.05, 0.05]).unwrap();
        let outcome =
            evaluate(&c, &posterior, &test_ctx(0.95)).expect("test contract action_index in range");
        assert_eq!(outcome.action_index, action::CONSERVATIVE);
    }

    #[test]
    fn partitioned_state_prefers_conservative() {
        let c = SchedulerDecisionContract::new();
        // Posterior concentrated on partitioned.
        let posterior = Posterior::new(vec![0.05, 0.05, 0.05, 0.85]).unwrap();
        let outcome =
            evaluate(&c, &posterior, &test_ctx(0.95)).expect("test contract action_index in range");
        assert_eq!(outcome.action_index, action::CONSERVATIVE);
    }

    #[test]
    fn unstable_state_prefers_conservative() {
        let c = SchedulerDecisionContract::new();
        // Posterior concentrated on unstable.
        let posterior = Posterior::new(vec![0.05, 0.05, 0.85, 0.05]).unwrap();
        let outcome =
            evaluate(&c, &posterior, &test_ctx(0.95)).expect("test contract action_index in range");
        assert_eq!(outcome.action_index, action::CONSERVATIVE);
    }

    #[test]
    fn fallback_chooses_conservative() {
        let c = SchedulerDecisionContract::new();
        let posterior = Posterior::uniform(4);
        // Low calibration triggers fallback.
        let outcome =
            evaluate(&c, &posterior, &test_ctx(0.3)).expect("test contract action_index in range");
        assert!(outcome.fallback_active);
        assert_eq!(outcome.action_index, action::CONSERVATIVE);
    }

    #[test]
    fn uniform_posterior_prefers_conservative() {
        // With uniform prior: E[aggressive]=17.0, E[balanced]=9.0, E[conservative]=6.75
        // So uniform should prefer conservative.
        let c = SchedulerDecisionContract::new();
        let posterior = Posterior::uniform(4);
        let outcome =
            evaluate(&c, &posterior, &test_ctx(0.95)).expect("test contract action_index in range");
        assert_eq!(outcome.action_index, action::CONSERVATIVE);
    }

    #[test]
    fn audit_entry_produces_valid_evidence() {
        let c = SchedulerDecisionContract::new();
        let posterior = Posterior::new(vec![0.7, 0.1, 0.1, 0.1]).unwrap();
        let outcome =
            evaluate(&c, &posterior, &test_ctx(0.92)).expect("test contract action_index in range");
        let evidence = outcome.audit_entry.to_evidence_ledger();
        assert_eq!(evidence.component, "scheduler");
        assert!(evidence.is_valid());
    }

    #[test]
    fn decision_output_snapshot_scrubbed() {
        let c = SchedulerDecisionContract::new();
        let posterior = Posterior::new(vec![0.12, 0.18, 0.2, 0.5]).unwrap();
        let outcome =
            evaluate(&c, &posterior, &test_ctx(0.91)).expect("test contract action_index in range");

        insta::assert_json_snapshot!(
            "decision_output_scrubbed",
            scrub_decision_output(json!({
                "action_index": outcome.action_index,
                "action_name": outcome.action_name,
                "expected_loss": outcome.expected_loss,
                "fallback_active": outcome.fallback_active,
                "audit_entry": outcome.audit_entry,
            }))
        );
    }

    #[test]
    fn snapshot_likelihoods_quiescent() {
        let snapshot = zero_snapshot();
        let likelihoods = SchedulerDecisionContract::snapshot_likelihoods(&snapshot);
        // When quiescent, healthy should be dominant.
        assert!(likelihoods[state::HEALTHY] > likelihoods[state::CONGESTED]);
        assert!(likelihoods[state::HEALTHY] > likelihoods[state::UNSTABLE]);
        assert!(likelihoods[state::HEALTHY] > likelihoods[state::PARTITIONED]);
    }

    #[test]
    fn snapshot_likelihoods_high_cancel_load() {
        let mut snapshot = zero_snapshot();
        snapshot.cancel_requested_tasks = 50;
        snapshot.cancelling_tasks = 20;
        let likelihoods = SchedulerDecisionContract::snapshot_likelihoods(&snapshot);
        // High cancel load should push unstable higher.
        assert!(likelihoods[state::UNSTABLE] > likelihoods[state::HEALTHY]);
    }

    #[test]
    fn snapshot_likelihoods_high_queue_depth() {
        let mut snapshot = zero_snapshot();
        snapshot.ready_queue_depth = 100;
        snapshot.pending_obligations = 30;
        let likelihoods = SchedulerDecisionContract::snapshot_likelihoods(&snapshot);
        // High queue should push congested higher.
        assert!(likelihoods[state::CONGESTED] > likelihoods[state::HEALTHY]);
    }

    #[test]
    fn snapshot_likelihoods_stale_obligation_age_increases_congestion() {
        let mut fresh = zero_snapshot();
        fresh.pending_obligations = 1;

        let mut stale = fresh.clone();
        stale.obligation_age_sum_ns = 5_000_000_000;

        let fresh_likelihoods = SchedulerDecisionContract::snapshot_likelihoods(&fresh);
        let stale_likelihoods = SchedulerDecisionContract::snapshot_likelihoods(&stale);

        assert!(stale_likelihoods[state::CONGESTED] > fresh_likelihoods[state::CONGESTED]);
        assert!(stale_likelihoods[state::HEALTHY] < fresh_likelihoods[state::HEALTHY]);
    }

    #[test]
    fn snapshot_likelihoods_high_deadline_pressure() {
        let mut snapshot = zero_snapshot();
        snapshot.deadline_pressure = 1.0;
        let likelihoods = SchedulerDecisionContract::snapshot_likelihoods(&snapshot);
        // High deadline pressure should not look healthy.
        assert!(likelihoods[state::PARTITIONED] > likelihoods[state::HEALTHY]);
    }

    #[test]
    fn snapshot_likelihoods_deadline_plus_cancel_pressure_prefers_partitioned() {
        let mut snapshot = zero_snapshot();
        snapshot.deadline_pressure = 1.0;
        snapshot.cancel_requested_tasks = 40;
        snapshot.cancelling_tasks = 30;
        snapshot.draining_regions = 20;
        let likelihoods = SchedulerDecisionContract::snapshot_likelihoods(&snapshot);
        // Combined deadline + cancel/drain pressure should favor partitioned.
        assert!(likelihoods[state::PARTITIONED] > likelihoods[state::UNSTABLE]);
    }

    #[test]
    fn end_to_end_posterior_update_and_decide() {
        let c = SchedulerDecisionContract::new();
        let mut posterior = Posterior::uniform(4);

        // Feed healthy observations repeatedly.
        let healthy_likelihoods = [0.8, 0.05, 0.05, 0.1];
        for _ in 0..10 {
            posterior.bayesian_update(&healthy_likelihoods);
        }

        // Should converge toward healthy → aggressive.
        let outcome =
            evaluate(&c, &posterior, &test_ctx(0.95)).expect("test contract action_index in range");
        assert_eq!(outcome.action_index, action::AGGRESSIVE);
    }

    #[test]
    fn custom_loss_matrix() {
        // Swap so conservative is bad everywhere → aggressive wins.
        let losses = vec![
            1.0, 2.0, 50.0, // healthy
            5.0, 3.0, 50.0, // congested
            8.0, 6.0, 50.0, // unstable
            10.0, 8.0, 50.0, // partitioned
        ];
        let c =
            SchedulerDecisionContract::with_losses_and_policy(losses, FallbackPolicy::default());
        let posterior = Posterior::uniform(4);
        let outcome =
            evaluate(&c, &posterior, &test_ctx(0.95)).expect("test contract action_index in range");
        // Conservative is very expensive everywhere, so aggressive/balanced wins.
        assert_ne!(outcome.action_index, action::CONSERVATIVE);
    }

    #[test]
    fn update_posterior_out_of_range_returns_typed_error() {
        // br-asupersync-u5uhpt: an out-of-range observation surfaces a
        // typed error (not a silent no-op) and leaves the posterior
        // unchanged so callers can fall back deterministically.
        let c = SchedulerDecisionContract::new();
        let mut posterior = Posterior::uniform(state::COUNT);
        let before = posterior.probs().to_vec();
        let err = c
            .update_posterior(&mut posterior, state::COUNT + 5)
            .expect_err("out-of-range observation must surface a typed error");
        assert!(
            matches!(
                err,
                franken_decision::UpdatePosteriorError::ObservationOutOfRange { .. }
            ),
            "expected ObservationOutOfRange, got {err:?}"
        );
        assert_eq!(posterior.probs(), before.as_slice());
    }

    #[test]
    fn update_posterior_wrong_dimension_returns_typed_error() {
        // br-asupersync-u5uhpt: a wrong-dimension posterior surfaces a
        // typed error and remains unchanged.
        let c = SchedulerDecisionContract::new();
        let mut posterior = Posterior::uniform(state::COUNT - 1);
        let before = posterior.probs().to_vec();
        let err = c
            .update_posterior(&mut posterior, state::HEALTHY)
            .expect_err("wrong-dimension posterior must surface a typed error");
        assert!(
            matches!(
                err,
                franken_decision::UpdatePosteriorError::LengthMismatch { .. }
            ),
            "expected LengthMismatch, got {err:?}"
        );
        assert_eq!(posterior.probs(), before.as_slice());
    }

    #[test]
    fn choose_action_wrong_dimension_uses_fallback() {
        let c = SchedulerDecisionContract::new();
        let posterior = Posterior::uniform(state::COUNT - 1);
        assert_eq!(c.choose_action(&posterior), action::CONSERVATIVE);
    }
