    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use serde_json::{from_str, to_string};

    fn slice(
        name: &str,
        service_class: SemanticServiceClass,
        delivery_class: DeliveryClass,
    ) -> TrafficSlice {
        TrafficSlice::new(name, service_class, delivery_class)
    }

    #[test]
    fn plan_reserves_capacity_for_control_and_recovery_lanes() {
        let policy = DegradationPolicy::new(2, 1);
        let control = slice(
            "control",
            SemanticServiceClass::ControlRecovery,
            DeliveryClass::EphemeralInteractive,
        );
        let fanout = slice(
            "fanout",
            SemanticServiceClass::LowValueFanout,
            DeliveryClass::EphemeralInteractive,
        )
        .with_required_slots(2);

        let plan = policy.plan(&[fanout, control]);

        assert_eq!(plan.admitted.len(), 1);
        assert_eq!(plan.admitted[0].slice, "control");
        assert!(plan.admitted[0].reserved_lane);
        assert_eq!(plan.degraded.len(), 1);
        assert_eq!(plan.degraded[0].slice, "fanout");
        assert_eq!(
            plan.degraded[0].disposition,
            DegradationDisposition::ReduceFanout
        );
    }

    #[test]
    fn plan_prefers_reply_obligations_over_read_models() {
        let policy = DegradationPolicy::new(2, 0);
        let reply = slice(
            "reply",
            SemanticServiceClass::ReplyCritical,
            DeliveryClass::ObligationBacked,
        )
        .with_obligation_load(ObligationLoad::Reply)
        .with_deadline(Duration::from_millis(80));
        let durable = slice(
            "durable",
            SemanticServiceClass::DurablePipeline,
            DeliveryClass::DurableOrdered,
        );
        let read_model = slice(
            "read-model",
            SemanticServiceClass::ReadModel,
            DeliveryClass::DurableOrdered,
        );

        let plan = policy.plan(&[read_model, durable, reply]);

        assert_eq!(plan.admitted.len(), 2);
        assert_eq!(plan.admitted[0].slice, "reply");
        assert_eq!(plan.admitted[1].slice, "durable");
        assert_eq!(plan.degraded.len(), 1);
        assert_eq!(plan.degraded[0].slice, "read-model");
        assert_eq!(plan.degraded[0].disposition, DegradationDisposition::Defer);
    }

    #[test]
    fn plan_widens_repair_for_lease_sensitive_work() {
        let policy = DegradationPolicy::new(0, 0);
        let lease = slice(
            "lease",
            SemanticServiceClass::LeaseRepair,
            DeliveryClass::ObligationBacked,
        )
        .with_obligation_load(ObligationLoad::Lease)
        .with_cleanup_urgency(CleanupUrgency::Immediate);

        let plan = policy.plan(&[lease]);

        assert!(plan.admitted.is_empty());
        assert_eq!(plan.degraded.len(), 1);
        assert_eq!(plan.degraded[0].slice, "lease");
        assert_eq!(
            plan.degraded[0].disposition,
            DegradationDisposition::WidenRepair
        );
    }

    #[test]
    fn plan_degrades_replay_before_stronger_contracts() {
        let policy = DegradationPolicy::new(1, 0);
        let replay = slice(
            "replay",
            SemanticServiceClass::ExpensiveReplay,
            DeliveryClass::ForensicReplayable,
        );
        let reply_critical = slice(
            "reply",
            SemanticServiceClass::ReplyCritical,
            DeliveryClass::ObligationBacked,
        )
        .with_obligation_load(ObligationLoad::Reply)
        .with_deadline(Duration::from_millis(50));

        let plan = policy.plan(&[replay, reply_critical]);

        assert_eq!(plan.admitted.len(), 1);
        assert_eq!(plan.admitted[0].slice, "reply");
        assert_eq!(plan.degraded.len(), 1);
        assert_eq!(plan.degraded[0].slice, "replay");
        assert_eq!(
            plan.degraded[0].disposition,
            DegradationDisposition::PauseReplay
        );
    }

    #[test]
    fn plan_uses_deadlines_to_break_ties_within_same_service_class() {
        let policy = DegradationPolicy::new(1, 0);
        let urgent = slice(
            "urgent",
            SemanticServiceClass::DurablePipeline,
            DeliveryClass::DurableOrdered,
        )
        .with_deadline(Duration::from_millis(40));
        let relaxed = slice(
            "relaxed",
            SemanticServiceClass::DurablePipeline,
            DeliveryClass::DurableOrdered,
        )
        .with_deadline(Duration::from_secs(10));

        let plan = policy.plan(&[relaxed, urgent]);

        assert_eq!(plan.admitted.len(), 1);
        assert_eq!(plan.admitted[0].slice, "urgent");
        assert_eq!(plan.degraded.len(), 1);
        assert_eq!(plan.degraded[0].slice, "relaxed");
        assert_eq!(
            plan.degraded[0].disposition,
            DegradationDisposition::RejectNew
        );
    }

    #[test]
    fn control_recovery_widens_repair_when_degraded() {
        // ControlRecovery is documented as "must stay live" traffic.
        // When it can't be admitted, its degradation disposition must be
        // WidenRepair (not RejectNew), because rejecting control/recovery
        // work grows semantic debt.
        let policy = DegradationPolicy::new(0, 0);
        let control = slice(
            "control",
            SemanticServiceClass::ControlRecovery,
            DeliveryClass::EphemeralInteractive,
        );

        let plan = policy.plan(&[control]);

        assert!(plan.admitted.is_empty());
        assert_eq!(plan.degraded.len(), 1);
        assert_eq!(plan.degraded[0].slice, "control");
        assert_eq!(
            plan.degraded[0].disposition,
            DegradationDisposition::WidenRepair
        );
    }

    #[test]
    fn plan_does_not_drop_distinct_slices_that_share_a_name() {
        let policy = DegradationPolicy::new(1, 1);
        let control = slice(
            "shared",
            SemanticServiceClass::ControlRecovery,
            DeliveryClass::EphemeralInteractive,
        );
        let fanout = slice(
            "shared",
            SemanticServiceClass::LowValueFanout,
            DeliveryClass::EphemeralInteractive,
        );

        let plan = policy.plan(&[control, fanout]);

        assert_eq!(plan.admitted.len(), 1);
        assert_eq!(plan.admitted[0].slice, "shared");
        assert!(plan.admitted[0].reserved_lane);
        assert_eq!(plan.degraded.len(), 1);
        assert_eq!(plan.degraded[0].slice, "shared");
        assert_eq!(
            plan.degraded[0].disposition,
            DegradationDisposition::ReduceFanout
        );
    }

    #[test]
    fn safety_envelope_rejects_invalid_ranges() {
        let invalid = SafetyEnvelope {
            min_stewards: 3,
            max_stewards: 2,
            ..SafetyEnvelope::default()
        };

        assert!(matches!(
            invalid.validate(),
            Err(ReliabilityControlError::InvalidEnvelopeRange { field: "stewards" })
        ));
    }

    #[test]
    fn reliability_controller_requires_strong_evidence_before_shifting() {
        let envelope = SafetyEnvelope::default();
        let current = ReliabilitySettings::default();
        let mut controller =
            BoundedRegretReliabilityController::new(envelope, current.clone()).expect("controller");

        let decision = controller
            .apply(ReliabilityEvidence {
                evidence_score: 0.6,
                confidence: 0.7,
                latency_violation_rate: 0.2,
                repair_pressure: 0.8,
                relay_pressure: 0.7,
                replay_pressure: 0.9,
                observation_window: 32,
            })
            .expect("decision");

        assert_eq!(decision.action, ReliabilityAction::Hold);
        assert_eq!(decision.previous, current);
        assert_eq!(decision.next, current);
        assert!(controller.rollback_target().is_none());
    }

    #[test]
    fn reliability_controller_tightens_within_envelope_and_records_rollback() {
        let envelope = SafetyEnvelope {
            max_stewards: 3,
            max_repair_depth: 2,
            max_relay_budget: 1,
            max_delivery_class: DeliveryClass::ObligationBacked,
            max_redelivery_attempts: 3,
            max_replay_buffer_events: 256,
            ..SafetyEnvelope::default()
        };
        let current = ReliabilitySettings {
            steward_count: 2,
            repair_depth: 1,
            relay_budget: 0,
            delivery_class: DeliveryClass::DurableOrdered,
            redelivery_attempts: 2,
            replay_buffer_events: 128,
        };
        let mut controller =
            BoundedRegretReliabilityController::new(envelope, current.clone()).expect("controller");

        let decision = controller
            .apply(ReliabilityEvidence {
                evidence_score: 0.95,
                confidence: 0.97,
                latency_violation_rate: 0.12,
                repair_pressure: 0.9,
                relay_pressure: 0.8,
                replay_pressure: 0.85,
                observation_window: 64,
            })
            .expect("decision");

        assert_eq!(decision.action, ReliabilityAction::Tighten);
        assert_eq!(decision.previous, current);
        assert_eq!(
            decision.next,
            ReliabilitySettings {
                steward_count: 3,
                repair_depth: 2,
                relay_budget: 1,
                delivery_class: DeliveryClass::ObligationBacked,
                redelivery_attempts: 3,
                replay_buffer_events: 256,
            }
        );
        assert_eq!(decision.rollback_target, Some(current));
        assert_eq!(controller.current, decision.next);
        assert_eq!(controller.rollback_target(), Some(&decision.previous));
    }

    #[test]
    fn reliability_controller_rolls_back_after_violation_spike() {
        let envelope = SafetyEnvelope {
            rollback_violation_threshold: 0.2,
            ..SafetyEnvelope::default()
        };
        let baseline = ReliabilitySettings::default();
        let mut controller = BoundedRegretReliabilityController::new(envelope, baseline.clone())
            .expect("controller");

        let tighten = controller
            .apply(ReliabilityEvidence {
                evidence_score: 0.95,
                confidence: 0.95,
                latency_violation_rate: 0.08,
                repair_pressure: 0.6,
                relay_pressure: 0.0,
                replay_pressure: 0.0,
                observation_window: 32,
            })
            .expect("tighten");
        assert_eq!(tighten.action, ReliabilityAction::Tighten);
        assert_ne!(controller.current, baseline);

        let rollback = controller
            .apply(ReliabilityEvidence {
                evidence_score: 0.99,
                confidence: 0.99,
                latency_violation_rate: 0.4,
                repair_pressure: 0.9,
                relay_pressure: 0.9,
                replay_pressure: 0.9,
                observation_window: 32,
            })
            .expect("rollback");

        assert_eq!(rollback.action, ReliabilityAction::Rollback);
        assert_eq!(rollback.next, baseline);
        assert_eq!(controller.current, baseline);
        assert!(controller.rollback_target().is_none());
    }

    #[test]
    fn compiler_maps_latency_plus_sovereignty_to_reply_critical_artifacts() {
        let intent = OperatorIntent::new("tenant-latency")
            .with_latency_objective(Duration::from_millis(120))
            .with_sovereignty(SovereigntyMode::Strict);

        let compiled = OperatorIntentCompiler::compile(&intent).expect("compiled intent");

        assert_eq!(compiled.service_class, SemanticServiceClass::ReplyCritical);
        assert_eq!(
            compiled.delivery_policy.default_class,
            DeliveryClass::ObligationBacked
        );
        assert_eq!(compiled.safety_envelope.max_relay_budget, 0);
        assert!(compiled.federation_constraints.preserve_sovereignty);
        assert_eq!(
            compiled.control_capsule_policy.promotion_approval,
            PromotionApproval::OperatorApprovalRequired
        );
        assert_eq!(
            compiled.control_capsule_policy.promotion_evidence,
            PromotionEvidence::ReplayBacked
        );
    }

    #[test]
    fn compiler_prefers_quiescent_mobility_over_restart_failover() {
        let intent = OperatorIntent::new("quiescent-mobility")
            .with_mobility(MobilityPreference::PreferQuiescent);

        let compiled = OperatorIntentCompiler::compile(&intent).expect("compiled intent");

        assert_eq!(compiled.service_class, SemanticServiceClass::LeaseRepair);
        assert_eq!(
            compiled.delivery_policy.default_class,
            DeliveryClass::MobilitySafe
        );
        assert_eq!(
            compiled.safety_envelope.min_delivery_class,
            DeliveryClass::MobilitySafe
        );
        assert_eq!(
            compiled.safety_envelope.max_delivery_class,
            DeliveryClass::MobilitySafe
        );
        assert!(compiled.mobility_budget.prefer_quiescent);
        assert!(!compiled.mobility_budget.allow_restart_failover);
        assert_eq!(
            compiled.control_capsule_policy.promotion_approval,
            PromotionApproval::OperatorApprovalRequired
        );
    }

    #[test]
    fn compiler_minimizes_egress_until_recoverability_floor() {
        let intent = OperatorIntent::new("minimize-egress")
            .with_egress_budget(EgressBudget::new(
                EgressBudgetMode::MinimizeUnlessRecoverabilityDrops,
                0,
            ))
            .with_recoverability_floor(5);

        let compiled = OperatorIntentCompiler::compile(&intent).expect("compiled intent");

        assert_eq!(
            compiled.service_class,
            SemanticServiceClass::DurablePipeline
        );
        assert_eq!(compiled.federation_constraints.max_remote_relays, 0);
        assert_eq!(compiled.mobility_budget.recoverability_floor, 5);
        assert_eq!(
            compiled
                .control_capsule_policy
                .recoverability_override_floor,
            Some(5)
        );
        assert_eq!(compiled.degradation_policy.total_slots, 3);
    }

    #[test]
    fn compiler_keeps_federation_relays_within_safety_envelope_budget() {
        let intent = OperatorIntent::new("relay-alignment")
            .with_latency_objective(Duration::from_millis(80))
            .with_egress_budget(EgressBudget::new(EgressBudgetMode::Minimize, 8));

        let compiled = OperatorIntentCompiler::compile(&intent).expect("compiled intent");

        assert_eq!(compiled.safety_envelope.max_relay_budget, 1);
        assert_eq!(
            compiled.federation_constraints.max_remote_relays,
            compiled.safety_envelope.max_relay_budget
        );
    }

    #[test]
    fn compiler_requires_certificate_edges_for_cross_tenant_traffic() {
        let intent = OperatorIntent::new("certified-cross-tenant")
            .with_cross_tenant_policy(CrossTenantTrafficPolicy::RequireCertificates);

        let compiled = OperatorIntentCompiler::compile(&intent).expect("compiled intent");

        assert_eq!(
            compiled.service_class,
            SemanticServiceClass::DurablePipeline
        );
        assert!(compiled.federation_constraints.allow_cross_tenant);
        assert!(compiled.federation_constraints.require_certificate_edges);
        assert_eq!(
            compiled.delivery_policy.default_class,
            DeliveryClass::ObligationBacked
        );
        assert_eq!(compiled.degradation_policy.reserved_control_slots, 1);
        assert_eq!(
            compiled.control_capsule_policy.promotion_approval,
            PromotionApproval::OperatorApprovalRequired
        );
    }

    #[test]
    fn compiler_maps_read_model_workload_shape_to_read_model_lane() {
        let intent =
            OperatorIntent::new("read-model").with_workload_shape(OperatorWorkloadShape::ReadModel);

        let compiled = OperatorIntentCompiler::compile(&intent).expect("compiled intent");

        assert_eq!(compiled.service_class, SemanticServiceClass::ReadModel);
        assert_eq!(
            compiled.delivery_policy.default_class,
            DeliveryClass::DurableOrdered
        );
        let plan = DegradationPolicy::new(0, 0).plan(&[slice(
            "read-model",
            compiled.service_class,
            compiled.delivery_policy.default_class,
        )]);
        assert_eq!(plan.degraded.len(), 1);
        assert_eq!(plan.degraded[0].disposition, DegradationDisposition::Defer);
    }

    #[test]
    fn compiler_maps_low_value_fanout_workload_shape_to_fanout_lane() {
        let intent = OperatorIntent::new("fanout")
            .with_workload_shape(OperatorWorkloadShape::LowValueFanout);

        let compiled = OperatorIntentCompiler::compile(&intent).expect("compiled intent");

        assert_eq!(compiled.service_class, SemanticServiceClass::LowValueFanout);
        assert_eq!(
            compiled.delivery_policy.default_class,
            DeliveryClass::EphemeralInteractive
        );
        let plan = DegradationPolicy::new(0, 0).plan(&[slice(
            "fanout",
            compiled.service_class,
            compiled.delivery_policy.default_class,
        )]);
        assert_eq!(plan.degraded.len(), 1);
        assert_eq!(
            plan.degraded[0].disposition,
            DegradationDisposition::ReduceFanout
        );
    }

    #[test]
    fn compiler_maps_expensive_replay_workload_shape_to_forensic_lane() {
        let intent = OperatorIntent::new("replay")
            .with_workload_shape(OperatorWorkloadShape::ExpensiveReplay)
            .with_cross_tenant_policy(CrossTenantTrafficPolicy::RequireCertificates);

        let compiled = OperatorIntentCompiler::compile(&intent).expect("compiled intent");

        assert_eq!(
            compiled.service_class,
            SemanticServiceClass::ExpensiveReplay
        );
        assert_eq!(
            compiled.delivery_policy.default_class,
            DeliveryClass::ForensicReplayable
        );
        assert_eq!(
            compiled.safety_envelope.max_delivery_class,
            DeliveryClass::ForensicReplayable
        );
        let plan = DegradationPolicy::new(0, 0).plan(&[slice(
            "replay",
            compiled.service_class,
            compiled.delivery_policy.default_class,
        )]);
        assert_eq!(plan.degraded.len(), 1);
        assert_eq!(
            plan.degraded[0].disposition,
            DegradationDisposition::PauseReplay
        );
        assert!(compiled.federation_constraints.require_certificate_edges);
    }

    #[test]
    fn intent_round_trip_preserves_compiled_artifacts() {
        let intent = OperatorIntent::new("round-trip")
            .with_latency_objective(Duration::from_millis(150))
            .with_sovereignty(SovereigntyMode::PreferLocal)
            .with_mobility(MobilityPreference::Balanced)
            .with_workload_shape(OperatorWorkloadShape::ExpensiveReplay)
            .with_egress_budget(EgressBudget::new(EgressBudgetMode::Minimize, 1))
            .with_cross_tenant_policy(CrossTenantTrafficPolicy::AllowTrusted);

        let encoded = to_string(&intent).expect("serialize");
        let decoded: OperatorIntent = from_str(&encoded).expect("deserialize");

        let compiled = OperatorIntentCompiler::compile(&intent).expect("compiled original");
        let round_tripped = OperatorIntentCompiler::compile(&decoded).expect("compiled decoded");

        assert_eq!(decoded, intent);
        assert_eq!(round_tripped, compiled);
    }
