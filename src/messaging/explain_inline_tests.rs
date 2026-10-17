    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use std::time::Duration;

    use crate::messaging::class::DeliveryClass;
    use crate::messaging::compiler::{CompiledSubjectCost, FabricCompileReport};
    use crate::messaging::fabric::SubjectPattern;
    use crate::messaging::ir::{CostVector, RetentionPolicy, SubjectFamily};
    use franken_decision::DecisionAuditEntry;
    use franken_kernel::{DecisionId, TraceId};

    fn test_audit_entry(seed: u128, action: &str) -> DecisionAuditEntry {
        let alternate_action = if action == "allow" { "deny" } else { "allow" };
        DecisionAuditEntry {
            decision_id: DecisionId::from_parts(1_700_000_000_000, seed),
            trace_id: TraceId::from_parts(1_700_000_000_000, seed),
            contract_name: "fabric.explain".to_owned(),
            action_chosen: action.to_owned(),
            expected_loss: 0.05,
            calibration_score: 0.97,
            fallback_active: false,
            posterior_snapshot: vec![0.8, 0.2],
            expected_loss_by_action: BTreeMap::from([
                (action.to_owned(), 0.05),
                (alternate_action.to_owned(), 0.8),
            ]),
            ts_unix_ms: 1_700_000_000_000,
        }
    }

    fn test_spec(kind: DataPlaneDecisionKind, index: u64) -> ExplainDecisionSpec {
        ExplainDecisionSpec::new(
            kind,
            format!("tenant.fabric.{index}"),
            SubjectFamily::Command,
            DeliveryClass::ObligationBacked,
            format!("decision summary {index}"),
            RetentionPolicy::RetainForEvents { events: index + 1 },
        )
        .with_annotation("policy", format!("policy-{index}"))
    }

    fn subject_pattern(raw: &str) -> SubjectPattern {
        SubjectPattern::parse(raw).expect("valid subject pattern")
    }

    fn cell_id(raw: &str, epoch: CellEpoch) -> CellId {
        CellId::for_partition(epoch, &subject_pattern(raw))
    }

    fn node(name: &str) -> NodeId {
        NodeId::new(name)
    }

    fn obligation(index: u32) -> ObligationId {
        ObligationId::new_for_test(index, 0)
    }

    fn dedicated_reply(prefix: &str) -> Option<ReplySpaceRule> {
        Some(ReplySpaceRule::DedicatedPrefix {
            prefix: prefix.to_owned(),
        })
    }

    fn shared_reply(prefix: &str) -> Option<ReplySpaceRule> {
        Some(ReplySpaceRule::SharedPrefix {
            prefix: prefix.to_owned(),
        })
    }

    #[test]
    fn explain_plan_includes_cost_breakdown_for_every_subject() {
        let cost = CostVector::baseline_for_delivery_class(DeliveryClass::DurableOrdered);
        let report = FabricCompileReport {
            schema_version: 1,
            subject_costs: vec![CompiledSubjectCost {
                pattern: "tenant.orders.stream".to_owned(),
                family: SubjectFamily::Event,
                delivery_class: DeliveryClass::DurableOrdered,
                estimated_cost: cost,
            }],
            aggregate_cost: cost,
            artifacts: Vec::new(),
            warnings: Vec::new(),
            errors: Vec::new(),
        };

        let plan = ExplainPlan::from_compile_report(&report);
        assert_eq!(plan.aggregate_cost, cost);
        assert_eq!(plan.breakdown.len(), 1);
        assert_eq!(plan.breakdown[0].label, "tenant.orders.stream");
        assert!(
            plan.breakdown[0]
                .reasons
                .iter()
                .any(|reason| reason.contains("delivery_class=durable-ordered"))
        );
        assert!(plan.important_decisions.is_empty());
    }

    #[test]
    fn explain_plan_attaches_evidence_for_every_decision_kind() {
        let mut plan = ExplainPlan::default();
        let kinds = [
            DataPlaneDecisionKind::SecuritySensitiveRouting,
            DataPlaneDecisionKind::AdaptiveDeliveryPolicy,
            DataPlaneDecisionKind::MultiTenantGovernance,
            DataPlaneDecisionKind::DistributedFailover,
            DataPlaneDecisionKind::OperatorTrust,
        ];

        for (kind, index) in kinds.into_iter().zip(0_u64..) {
            plan.record_audit_entry(
                test_spec(kind, index).with_estimated_cost(
                    CostVector::baseline_for_delivery_class(DeliveryClass::ObligationBacked),
                ),
                test_audit_entry(u128::from(index) + 1, "allow"),
            );
        }

        assert_eq!(plan.important_decisions.len(), 5);
        for kind in kinds {
            let matching = plan.decisions_for_kind(kind);
            assert_eq!(matching.len(), 1);
            assert!(matching[0].evidence.is_valid());
            assert_eq!(matching[0].evidence.component, "fabric.explain");
        }
    }

    #[test]
    fn explain_plan_queries_evidence_and_retention_by_decision() {
        let mut plan = ExplainPlan::default();
        let audit_entry = test_audit_entry(42, "failover");
        let decision_id = audit_entry.decision_id;

        plan.record_audit_entry(
            ExplainDecisionSpec::new(
                DataPlaneDecisionKind::DistributedFailover,
                "tenant.fabric.failover",
                SubjectFamily::Event,
                DeliveryClass::DurableOrdered,
                "reroute to replica b",
                RetentionPolicy::RetainFor {
                    duration: Duration::from_secs(90),
                },
            )
            .with_annotation("path", "replica-b"),
            audit_entry,
        );

        let evidence = plan
            .evidence_for(decision_id)
            .expect("decision evidence should be queryable by decision id");
        assert_eq!(evidence.action, "failover");
        assert_eq!(evidence.component, "fabric.explain");
        assert!(matches!(
            plan.retention_for(decision_id),
            Some(RetentionPolicy::RetainFor { duration }) if *duration == Duration::from_secs(90)
        ));
    }

    #[test]
    fn explain_plan_queries_decisions_by_contract_and_cell() {
        let epoch = CellEpoch::new(9, 2);
        let cell_id = cell_id("tenant.fabric.orders", epoch);
        let mut plan = ExplainPlan::default();
        let audit_entry = DecisionAuditEntry {
            decision_id: DecisionId::from_parts(1_700_000_000_010, 77),
            trace_id: TraceId::from_parts(1_700_000_000_010, 77),
            contract_name: "fabric_routing_decision".to_owned(),
            action_chosen: "single_cell".to_owned(),
            expected_loss: 0.12,
            calibration_score: 0.95,
            fallback_active: false,
            posterior_snapshot: vec![0.84, 0.08, 0.08],
            expected_loss_by_action: BTreeMap::from([
                ("single_cell".to_owned(), 0.12),
                ("fanout_cells".to_owned(), 0.9),
            ]),
            ts_unix_ms: 1_700_000_000_010,
        };

        plan.record_audit_entry(
            ExplainDecisionSpec::new(
                DataPlaneDecisionKind::SecuritySensitiveRouting,
                "tenant.fabric.orders.created",
                SubjectFamily::Event,
                DeliveryClass::EphemeralInteractive,
                "route through one canonical cell",
                RetentionPolicy::Forever,
            )
            .with_annotation("cell_id", cell_id.to_string())
            .with_annotation("contract", "fabric_routing_decision"),
            audit_entry,
        );

        assert_eq!(
            plan.decisions_for_contract("fabric_routing_decision").len(),
            1
        );
        assert_eq!(plan.decisions_for_cell(cell_id).len(), 1);
        assert_eq!(
            plan.decisions_with_annotation("contract", "fabric_routing_decision")
                .len(),
            1
        );
    }

    #[test]
    fn explain_plan_records_decision_outcomes_without_losing_audit_metadata() {
        let audit_entry = test_audit_entry(7, "allow");
        let decision_id = audit_entry.decision_id;
        let outcome = DecisionOutcome {
            action_index: 0,
            action_name: "allow".to_owned(),
            expected_loss: 0.05,
            expected_losses: BTreeMap::from([("allow".to_owned(), 0.05), ("deny".to_owned(), 0.8)]),
            fallback_active: false,
            audit_entry,
        };

        let mut plan = ExplainPlan::default();
        plan.record_outcome(
            ExplainDecisionSpec::new(
                DataPlaneDecisionKind::OperatorTrust,
                "tenant.fabric.operator_gate",
                SubjectFamily::Reply,
                DeliveryClass::EphemeralInteractive,
                "publish go/no-go advisory",
                RetentionPolicy::Forever,
            ),
            &outcome,
        );

        let record = plan
            .decision(decision_id)
            .expect("decision record should be queryable");
        assert_eq!(record.audit_entry.action_chosen, "allow");
        assert_eq!(record.evidence.action, "allow");
        assert_eq!(record.summary, "publish go/no-go advisory");
        assert_eq!(record.delivery_class, DeliveryClass::EphemeralInteractive);
    }

    #[test]
    fn consistency_checker_builds_valid_global_section() {
        let epoch = CellEpoch::new(7, 1);
        let cell_id = cell_id("tenant.orders", epoch);
        let witness_a = node("node-a");
        let witness_b = node("node-b");

        let report = ConsistencyChecker::new(vec![
            ConsistencySection::new(ConsistencyComponentKind::FederationEdge, "orders-export")
                .with_fact(ConsistencyFact::ReplySpaceBoundary(
                    ReplySpaceBoundaryFact {
                        route_id: "orders-rpc".to_owned(),
                        subject_space: "tenant.orders.command".to_owned(),
                        reply_space: dedicated_reply("_RPLY.orders"),
                        reply_contract_required: true,
                    },
                )),
            ConsistencySection::new(ConsistencyComponentKind::FederationEdge, "orders-import")
                .with_fact(ConsistencyFact::ReplySpaceBoundary(
                    ReplySpaceBoundaryFact {
                        route_id: "orders-rpc".to_owned(),
                        subject_space: "edge.orders.command".to_owned(),
                        reply_space: dedicated_reply("_RPLY.orders"),
                        reply_contract_required: true,
                    },
                )),
            ConsistencySection::new(ConsistencyComponentKind::Morphism, "tenant-to-fabric")
                .with_fact(ConsistencyFact::Morphism(MorphismFact {
                    name: "tenant-to-fabric".to_owned(),
                    from_space: "tenant.orders".to_owned(),
                    to_space: "fabric.orders".to_owned(),
                    preserves_reply_space: true,
                    delivery_class: DeliveryClass::ObligationBacked,
                })),
            ConsistencySection::new(ConsistencyComponentKind::Morphism, "fabric-to-edge")
                .with_fact(ConsistencyFact::Morphism(MorphismFact {
                    name: "fabric-to-edge".to_owned(),
                    from_space: "fabric.orders".to_owned(),
                    to_space: "edge.orders".to_owned(),
                    preserves_reply_space: true,
                    delivery_class: DeliveryClass::MobilitySafe,
                })),
            ConsistencySection::new(ConsistencyComponentKind::CursorPartition, "cursor-a")
                .with_fact(ConsistencyFact::CursorDelegation(CursorDelegationFact {
                    cell_id,
                    epoch,
                    holder: witness_a.clone(),
                    delegated_partitions: BTreeSet::from([0, 1]),
                })),
            ConsistencySection::new(ConsistencyComponentKind::CursorPartition, "cursor-b")
                .with_fact(ConsistencyFact::CursorDelegation(CursorDelegationFact {
                    cell_id,
                    epoch,
                    holder: witness_b.clone(),
                    delegated_partitions: BTreeSet::from([2, 3]),
                })),
            ConsistencySection::new(ConsistencyComponentKind::SupervisorDomain, "cutover-a")
                .with_fact(ConsistencyFact::CutoverCoverage(CutoverCoverageFact {
                    plan_id: "cutover-1".to_owned(),
                    cell_id,
                    live_obligations: BTreeSet::from([obligation(1), obligation(2), obligation(3)]),
                    covered_obligations: BTreeSet::from([obligation(1), obligation(2)]),
                })),
            ConsistencySection::new(ConsistencyComponentKind::SupervisorDomain, "cutover-b")
                .with_fact(ConsistencyFact::CutoverCoverage(CutoverCoverageFact {
                    plan_id: "cutover-1".to_owned(),
                    cell_id,
                    live_obligations: BTreeSet::from([obligation(3)]),
                    covered_obligations: BTreeSet::from([obligation(3)]),
                })),
            ConsistencySection::new(ConsistencyComponentKind::SupervisorDomain, "witness-a")
                .with_fact(ConsistencyFact::WitnessPlacement(WitnessPlacementFact {
                    placement_id: "placement-1".to_owned(),
                    cell_id,
                    witnesses: BTreeSet::from([witness_a.clone()]),
                    witness_domains: BTreeMap::from([(witness_a.clone(), "zone-a".to_owned())]),
                    minimum_witnesses: 2,
                    minimum_failure_domains: 2,
                    confidentiality_allowlist: BTreeSet::from([
                        "zone-a".to_owned(),
                        "zone-b".to_owned(),
                    ]),
                })),
            ConsistencySection::new(ConsistencyComponentKind::SupervisorDomain, "witness-b")
                .with_fact(ConsistencyFact::WitnessPlacement(WitnessPlacementFact {
                    placement_id: "placement-1".to_owned(),
                    cell_id,
                    witnesses: BTreeSet::from([witness_b.clone()]),
                    witness_domains: BTreeMap::from([(witness_b.clone(), "zone-b".to_owned())]),
                    minimum_witnesses: 2,
                    minimum_failure_domains: 2,
                    confidentiality_allowlist: BTreeSet::from([
                        "zone-a".to_owned(),
                        "zone-b".to_owned(),
                    ]),
                })),
            ConsistencySection::new(ConsistencyComponentKind::SupervisorDomain, "policy-core")
                .with_fact(ConsistencyFact::AdaptivePolicy(AdaptivePolicyFact {
                    policy_id: "adaptive-1".to_owned(),
                    fabric_id: "core".to_owned(),
                    certified_max_latency: Duration::from_millis(40),
                    certified_min_success_probability_bps: 9_900,
                    certified_max_degradation_tier: 1,
                    observed_latency: Duration::from_millis(30),
                    observed_success_probability_bps: 9_950,
                    observed_degradation_tier: 1,
                })),
            ConsistencySection::new(ConsistencyComponentKind::FederationEdge, "policy-edge")
                .with_fact(ConsistencyFact::AdaptivePolicy(AdaptivePolicyFact {
                    policy_id: "adaptive-1".to_owned(),
                    fabric_id: "edge".to_owned(),
                    certified_max_latency: Duration::from_millis(35),
                    certified_min_success_probability_bps: 9_850,
                    certified_max_degradation_tier: 2,
                    observed_latency: Duration::from_millis(32),
                    observed_success_probability_bps: 9_920,
                    observed_degradation_tier: 0,
                })),
        ])
        .check();

        assert!(report.is_globally_consistent());
        assert!(report.obstructions.is_empty());

        let binding = report
            .global_section
            .reply_space_bindings
            .get("orders-rpc")
            .expect("reply-space binding should glue");
        assert_eq!(binding.reply_space, dedicated_reply("_RPLY.orders"));
        assert_eq!(binding.subject_spaces.len(), 2);

        let morphism_key = morphism_scope_key("tenant.orders", "edge.orders");
        let morphism = report
            .global_section
            .morphisms
            .get(&morphism_key)
            .expect("composed morphism should be synthesized");
        assert!(morphism.preserves_reply_space);
        assert_eq!(morphism.delivery_class, DeliveryClass::MobilitySafe);

        let cursor = report
            .global_section
            .cursor_delegations
            .get(&cell_epoch_scope_key(cell_id, epoch))
            .expect("cursor partitions should glue");
        assert_eq!(cursor.partition_holders.get(&0), Some(&witness_a));
        assert_eq!(cursor.partition_holders.get(&3), Some(&witness_b));

        let cutover = report
            .global_section
            .cutovers
            .get(&cutover_scope_key("cutover-1", cell_id))
            .expect("cutover should cover every live obligation");
        assert_eq!(cutover.live_obligations.len(), 3);
        assert_eq!(cutover.covered_obligations.len(), 3);

        let witnesses = report
            .global_section
            .witness_placements
            .get(&witness_scope_key("placement-1", cell_id))
            .expect("witness placement should satisfy all constraints");
        assert_eq!(witnesses.witnesses.len(), 2);
        assert_eq!(witnesses.minimum_failure_domains, 2);

        let adaptive = report
            .global_section
            .adaptive_policies
            .get("adaptive-1")
            .expect("adaptive envelope should glue");
        assert_eq!(adaptive.certified_max_latency, Duration::from_millis(35));
        assert_eq!(adaptive.certified_min_success_probability_bps, 9_900);
        assert_eq!(adaptive.certified_max_degradation_tier, 1);
    }

    #[test]
    fn consistency_checker_emits_reply_space_obstruction() {
        let report = ConsistencyChecker::new(vec![
            ConsistencySection::new(ConsistencyComponentKind::FederationEdge, "export").with_fact(
                ConsistencyFact::ReplySpaceBoundary(ReplySpaceBoundaryFact {
                    route_id: "rpc".to_owned(),
                    subject_space: "tenant.rpc".to_owned(),
                    reply_space: dedicated_reply("_RPLY.rpc"),
                    reply_contract_required: true,
                }),
            ),
            ConsistencySection::new(ConsistencyComponentKind::FederationEdge, "import").with_fact(
                ConsistencyFact::ReplySpaceBoundary(ReplySpaceBoundaryFact {
                    route_id: "rpc".to_owned(),
                    subject_space: "edge.rpc".to_owned(),
                    reply_space: shared_reply("_RPLY.rpc"),
                    reply_contract_required: true,
                }),
            ),
        ])
        .check();

        assert!(!report.is_globally_consistent());
        assert_eq!(
            report
                .obstructions_for_kind(ObstructionKind::ReplySpaceMismatch)
                .len(),
            1
        );
    }

    #[test]
    fn consistency_checker_emits_morphism_composition_obstruction() {
        let report = ConsistencyChecker::new(vec![
            ConsistencySection::new(ConsistencyComponentKind::Morphism, "a-b").with_fact(
                ConsistencyFact::Morphism(MorphismFact {
                    name: "a-b".to_owned(),
                    from_space: "a".to_owned(),
                    to_space: "b".to_owned(),
                    preserves_reply_space: true,
                    delivery_class: DeliveryClass::DurableOrdered,
                }),
            ),
            ConsistencySection::new(ConsistencyComponentKind::Morphism, "b-c").with_fact(
                ConsistencyFact::Morphism(MorphismFact {
                    name: "b-c".to_owned(),
                    from_space: "b".to_owned(),
                    to_space: "c".to_owned(),
                    preserves_reply_space: false,
                    delivery_class: DeliveryClass::ObligationBacked,
                }),
            ),
            ConsistencySection::new(ConsistencyComponentKind::Morphism, "a-c-direct").with_fact(
                ConsistencyFact::Morphism(MorphismFact {
                    name: "a-c-direct".to_owned(),
                    from_space: "a".to_owned(),
                    to_space: "c".to_owned(),
                    preserves_reply_space: true,
                    delivery_class: DeliveryClass::ObligationBacked,
                }),
            ),
        ])
        .check();

        assert_eq!(
            report
                .obstructions_for_kind(ObstructionKind::MorphismCompositionConflict)
                .len(),
            1
        );
        assert!(
            !report
                .global_section
                .morphisms
                .contains_key(&morphism_scope_key("a", "c"))
        );
    }

    #[test]
    fn consistency_checker_emits_cursor_overlap_obstruction() {
        let epoch = CellEpoch::new(2, 9);
        let cell_id = cell_id("tenant.cursor", epoch);
        let report = ConsistencyChecker::new(vec![
            ConsistencySection::new(ConsistencyComponentKind::CursorPartition, "holder-a")
                .with_fact(ConsistencyFact::CursorDelegation(CursorDelegationFact {
                    cell_id,
                    epoch,
                    holder: node("node-a"),
                    delegated_partitions: BTreeSet::from([7]),
                })),
            ConsistencySection::new(ConsistencyComponentKind::CursorPartition, "holder-b")
                .with_fact(ConsistencyFact::CursorDelegation(CursorDelegationFact {
                    cell_id,
                    epoch,
                    holder: node("node-b"),
                    delegated_partitions: BTreeSet::from([7]),
                })),
        ])
        .check();

        assert_eq!(
            report
                .obstructions_for_kind(ObstructionKind::CursorDelegationOverlap)
                .len(),
            1
        );
        assert!(
            !report
                .global_section
                .cursor_delegations
                .contains_key(&cell_epoch_scope_key(cell_id, epoch))
        );
    }

    #[test]
    fn consistency_checker_emits_cutover_gap_obstruction() {
        let epoch = CellEpoch::new(3, 1);
        let cell_id = cell_id("tenant.cutover", epoch);
        let report = ConsistencyChecker::new(vec![
            ConsistencySection::new(ConsistencyComponentKind::SupervisorDomain, "cutover")
                .with_fact(ConsistencyFact::CutoverCoverage(CutoverCoverageFact {
                    plan_id: "cutover-gap".to_owned(),
                    cell_id,
                    live_obligations: BTreeSet::from([obligation(1), obligation(2), obligation(3)]),
                    covered_obligations: BTreeSet::from([obligation(1), obligation(2)]),
                })),
        ])
        .check();

        assert_eq!(
            report
                .obstructions_for_kind(ObstructionKind::CutoverCoverageGap)
                .len(),
            1
        );
    }

    #[test]
    fn consistency_checker_emits_witness_placement_obstruction() {
        let epoch = CellEpoch::new(4, 2);
        let cell_id = cell_id("tenant.witness", epoch);
        let witness_a = node("node-a");
        let witness_b = node("node-b");

        let report = ConsistencyChecker::new(vec![
            ConsistencySection::new(ConsistencyComponentKind::SupervisorDomain, "placement")
                .with_fact(ConsistencyFact::WitnessPlacement(WitnessPlacementFact {
                    placement_id: "placement-gap".to_owned(),
                    cell_id,
                    witnesses: BTreeSet::from([witness_a.clone(), witness_b.clone()]),
                    witness_domains: BTreeMap::from([
                        (witness_a, "zone-a".to_owned()),
                        (witness_b, "zone-b".to_owned()),
                    ]),
                    minimum_witnesses: 2,
                    minimum_failure_domains: 2,
                    confidentiality_allowlist: BTreeSet::from(["zone-a".to_owned()]),
                })),
        ])
        .check();

        assert_eq!(
            report
                .obstructions_for_kind(ObstructionKind::WitnessPlacementUnsatisfied)
                .len(),
            1
        );
    }

    #[test]
    fn consistency_checker_emits_adaptive_policy_obstruction() {
        let report =
            ConsistencyChecker::new(vec![
                ConsistencySection::new(ConsistencyComponentKind::SupervisorDomain, "core")
                    .with_fact(ConsistencyFact::AdaptivePolicy(AdaptivePolicyFact {
                        policy_id: "adaptive-gap".to_owned(),
                        fabric_id: "core".to_owned(),
                        certified_max_latency: Duration::from_millis(50),
                        certified_min_success_probability_bps: 9_800,
                        certified_max_degradation_tier: 2,
                        observed_latency: Duration::from_millis(45),
                        observed_success_probability_bps: 9_850,
                        observed_degradation_tier: 1,
                    })),
                ConsistencySection::new(ConsistencyComponentKind::FederationEdge, "edge")
                    .with_fact(ConsistencyFact::AdaptivePolicy(AdaptivePolicyFact {
                        policy_id: "adaptive-gap".to_owned(),
                        fabric_id: "edge".to_owned(),
                        certified_max_latency: Duration::from_millis(40),
                        certified_min_success_probability_bps: 9_900,
                        certified_max_degradation_tier: 1,
                        observed_latency: Duration::from_millis(42),
                        observed_success_probability_bps: 9_850,
                        observed_degradation_tier: 2,
                    })),
            ])
            .check();

        assert_eq!(
            report
                .obstructions_for_kind(ObstructionKind::AdaptivePolicyEnvelopeViolation)
                .len(),
            1
        );
    }

    #[test]
    fn consistency_checker_keeps_partial_global_section_when_some_components_fail() {
        let epoch = CellEpoch::new(5, 4);
        let cell_id = cell_id("tenant.partial", epoch);
        let report = ConsistencyChecker::new(vec![
            ConsistencySection::new(ConsistencyComponentKind::FederationEdge, "reply-a").with_fact(
                ConsistencyFact::ReplySpaceBoundary(ReplySpaceBoundaryFact {
                    route_id: "partial-rpc".to_owned(),
                    subject_space: "tenant.partial.command".to_owned(),
                    reply_space: dedicated_reply("_RPLY.partial"),
                    reply_contract_required: true,
                }),
            ),
            ConsistencySection::new(ConsistencyComponentKind::FederationEdge, "reply-b").with_fact(
                ConsistencyFact::ReplySpaceBoundary(ReplySpaceBoundaryFact {
                    route_id: "partial-rpc".to_owned(),
                    subject_space: "edge.partial.command".to_owned(),
                    reply_space: dedicated_reply("_RPLY.partial"),
                    reply_contract_required: true,
                }),
            ),
            ConsistencySection::new(ConsistencyComponentKind::SupervisorDomain, "cutover")
                .with_fact(ConsistencyFact::CutoverCoverage(CutoverCoverageFact {
                    plan_id: "partial-cutover".to_owned(),
                    cell_id,
                    live_obligations: BTreeSet::from([obligation(11)]),
                    covered_obligations: BTreeSet::from([obligation(11)]),
                })),
            ConsistencySection::new(ConsistencyComponentKind::CursorPartition, "cursor-a")
                .with_fact(ConsistencyFact::CursorDelegation(CursorDelegationFact {
                    cell_id,
                    epoch,
                    holder: node("node-a"),
                    delegated_partitions: BTreeSet::from([9]),
                })),
            ConsistencySection::new(ConsistencyComponentKind::CursorPartition, "cursor-b")
                .with_fact(ConsistencyFact::CursorDelegation(CursorDelegationFact {
                    cell_id,
                    epoch,
                    holder: node("node-b"),
                    delegated_partitions: BTreeSet::from([9]),
                })),
        ])
        .check();

        assert!(!report.is_globally_consistent());
        assert_eq!(
            report
                .obstructions_for_kind(ObstructionKind::CursorDelegationOverlap)
                .len(),
            1
        );
        assert!(
            report
                .global_section
                .reply_space_bindings
                .contains_key("partial-rpc")
        );
        assert!(
            !report
                .global_section
                .cursor_delegations
                .contains_key(&cell_epoch_scope_key(cell_id, epoch))
        );
        assert!(
            report
                .global_section
                .cutovers
                .contains_key(&cutover_scope_key("partial-cutover", cell_id))
        );
    }
