//! Deterministic explain-plan output for FABRIC cost estimation and
//! evidence-native operational decisions.

use std::collections::BTreeMap;

use franken_decision::{DecisionAuditEntry, DecisionOutcome};
use franken_evidence::EvidenceLedger;
use franken_kernel::DecisionId;

use super::class::DeliveryClass;
use super::compiler::FabricCompileReport;
use super::ir::{CostVector, RetentionPolicy, SubjectFamily};
use serde::{Deserialize, Serialize};

/// One operator-facing cost breakdown row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CostBreakdown {
    /// Human-readable entry label.
    pub label: String,
    /// Estimated cost envelope for the entry.
    pub cost: CostVector,
    /// Short rationale explaining the dominant cost drivers.
    pub reasons: Vec<String>,
}

/// Operator-relevant decision classes that must emit structured evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataPlaneDecisionKind {
    /// Routing choice with tenant, capability, or trust implications.
    SecuritySensitiveRouting,
    /// Delivery policy or degradation choice taken at runtime.
    AdaptiveDeliveryPolicy,
    /// Governance decision affecting tenant or metadata boundaries.
    MultiTenantGovernance,
    /// Failover, recovery, or replay-selection decision.
    DistributedFailover,
    /// Operator-facing trust or release-safety decision.
    OperatorTrust,
}

/// Declarative metadata for one evidence-native data-plane decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExplainDecisionSpec {
    /// High-level decision class for operator search and filtering.
    pub kind: DataPlaneDecisionKind,
    /// Subject or routing scope affected by the decision.
    pub subject: String,
    /// Semantic subject family for the decision scope.
    pub family: SubjectFamily,
    /// Delivery class in force when the decision was made.
    pub delivery_class: DeliveryClass,
    /// Human-readable decision summary.
    pub summary: String,
    /// Deterministic evidence-retention contract for this decision.
    pub retention: RetentionPolicy,
    /// Conservative cost envelope attached to the decision.
    pub estimated_cost: CostVector,
    /// Extra deterministic key/value annotations for operators.
    pub annotations: BTreeMap<String, String>,
}

impl ExplainDecisionSpec {
    /// Construct a deterministic decision spec with the delivery-class
    /// baseline cost envelope.
    #[must_use]
    pub fn new(
        kind: DataPlaneDecisionKind,
        subject: impl Into<String>,
        family: SubjectFamily,
        delivery_class: DeliveryClass,
        summary: impl Into<String>,
        retention: RetentionPolicy,
    ) -> Self {
        Self {
            kind,
            subject: subject.into(),
            family,
            delivery_class,
            summary: summary.into(),
            retention,
            estimated_cost: CostVector::baseline_for_delivery_class(delivery_class),
            annotations: BTreeMap::new(),
        }
    }

    /// Attach a deterministic annotation to the spec.
    #[must_use]
    pub fn with_annotation(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.annotations.insert(key.into(), value.into());
        self
    }

    /// Override the default delivery-class cost envelope.
    #[must_use]
    pub fn with_estimated_cost(mut self, estimated_cost: CostVector) -> Self {
        self.estimated_cost = estimated_cost;
        self
    }
}

/// Fully materialized decision + evidence artifact for the data plane.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplainDecisionRecord {
    /// High-level decision class for filtering and reporting.
    pub kind: DataPlaneDecisionKind,
    /// Subject or routing scope affected by the decision.
    pub subject: String,
    /// Semantic family for the decision scope.
    pub family: SubjectFamily,
    /// Delivery class in force when the decision was made.
    pub delivery_class: DeliveryClass,
    /// Human-readable summary of the operational choice.
    pub summary: String,
    /// Deterministic evidence-retention contract.
    pub retention: RetentionPolicy,
    /// Conservative cost envelope attached to the decision.
    pub estimated_cost: CostVector,
    /// Extra deterministic annotations for operator tooling.
    pub annotations: BTreeMap<String, String>,
    /// Decision-contract audit payload.
    pub audit_entry: DecisionAuditEntry,
    /// Evidence ledger derived directly from the decision audit entry.
    pub evidence: EvidenceLedger,
}

impl PartialEq for ExplainDecisionRecord {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.subject == other.subject
            && self.family == other.family
            && self.delivery_class == other.delivery_class
            && self.summary == other.summary
            && self.retention == other.retention
            && self.estimated_cost == other.estimated_cost
            && self.annotations == other.annotations
            && self.audit_entry.decision_id == other.audit_entry.decision_id
            && self.audit_entry.trace_id == other.audit_entry.trace_id
            && self.audit_entry.contract_name == other.audit_entry.contract_name
            && self.audit_entry.action_chosen == other.audit_entry.action_chosen
            && self.audit_entry.expected_loss.to_bits() == other.audit_entry.expected_loss.to_bits()
            && self.audit_entry.calibration_score.to_bits()
                == other.audit_entry.calibration_score.to_bits()
            && self.audit_entry.fallback_active == other.audit_entry.fallback_active
            && self.audit_entry.posterior_snapshot.len()
                == other.audit_entry.posterior_snapshot.len()
            && self
                .audit_entry
                .posterior_snapshot
                .iter()
                .zip(&other.audit_entry.posterior_snapshot)
                .all(|(a, b)| a.to_bits() == b.to_bits())
            && self.audit_entry.expected_loss_by_action.len()
                == other.audit_entry.expected_loss_by_action.len()
            && self
                .audit_entry
                .expected_loss_by_action
                .iter()
                .zip(other.audit_entry.expected_loss_by_action.iter())
                .all(|((k1, v1), (k2, v2))| k1 == k2 && v1.to_bits() == v2.to_bits())
            && self.audit_entry.ts_unix_ms == other.audit_entry.ts_unix_ms
            && self.evidence == other.evidence
    }
}

impl ExplainDecisionRecord {
    /// Materialize a data-plane decision record from a decision audit entry.
    #[must_use]
    pub fn from_audit_entry(spec: ExplainDecisionSpec, audit_entry: DecisionAuditEntry) -> Self {
        let evidence = audit_entry.to_evidence_ledger();
        Self {
            kind: spec.kind,
            subject: spec.subject,
            family: spec.family,
            delivery_class: spec.delivery_class,
            summary: spec.summary,
            retention: spec.retention,
            estimated_cost: spec.estimated_cost,
            annotations: spec.annotations,
            audit_entry,
            evidence,
        }
    }

    /// Materialize a decision record from an evaluated decision outcome.
    #[must_use]
    pub fn from_outcome(spec: ExplainDecisionSpec, outcome: &DecisionOutcome) -> Self {
        Self::from_audit_entry(spec, outcome.audit_entry.clone())
    }

    /// Stable decision identifier for cross-linking evidence and operator
    /// reports.
    #[must_use]
    pub fn decision_id(&self) -> DecisionId {
        self.audit_entry.decision_id
    }
}

/// Explain-plan payload emitted from a compiled FABRIC IR report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ExplainPlan {
    /// Human-readable explain summary.
    pub summary: String,
    /// Conservative aggregate envelope across all costed entries.
    pub aggregate_cost: CostVector,
    /// Per-entry breakdown in deterministic declaration order.
    pub breakdown: Vec<CostBreakdown>,
    /// Evidence-native operational decisions attached to the plan.
    #[serde(default)]
    pub important_decisions: Vec<ExplainDecisionRecord>,
}

impl ExplainPlan {
    /// Build an explain plan from a compiler report.
    #[must_use]
    pub fn from_compile_report(report: &FabricCompileReport) -> Self {
        let breakdown = report
            .subject_costs
            .iter()
            .map(|subject| CostBreakdown {
                label: subject.pattern.clone(),
                cost: subject.estimated_cost,
                reasons: vec![
                    format!("family={}", subject.family.as_str()),
                    format!("delivery_class={}", subject.delivery_class),
                ],
            })
            .collect::<Vec<_>>();

        Self {
            summary: format!(
                "Compiled {} FABRIC subject declaration(s) into deterministic cost envelopes",
                report.subject_costs.len()
            ),
            aggregate_cost: report.aggregate_cost,
            breakdown,
            important_decisions: Vec::new(),
        }
    }

    /// Attach a fully materialized decision record.
    pub fn record_decision(&mut self, record: ExplainDecisionRecord) {
        self.important_decisions.push(record);
    }

    /// Attach a decision audit entry using a deterministic spec.
    pub fn record_audit_entry(
        &mut self,
        spec: ExplainDecisionSpec,
        audit_entry: DecisionAuditEntry,
    ) {
        self.record_decision(ExplainDecisionRecord::from_audit_entry(spec, audit_entry));
    }

    /// Attach an evaluated decision outcome using a deterministic spec.
    pub fn record_outcome(&mut self, spec: ExplainDecisionSpec, outcome: &DecisionOutcome) {
        self.record_decision(ExplainDecisionRecord::from_outcome(spec, outcome));
    }

    /// Return the first decision record for `decision_id`.
    #[must_use]
    pub fn decision(&self, decision_id: DecisionId) -> Option<&ExplainDecisionRecord> {
        self.important_decisions
            .iter()
            .find(|record| record.decision_id() == decision_id)
    }

    /// Return the evidence ledger for `decision_id`, if recorded.
    #[must_use]
    pub fn evidence_for(&self, decision_id: DecisionId) -> Option<&EvidenceLedger> {
        self.decision(decision_id).map(|record| &record.evidence)
    }

    /// Return the retention policy for `decision_id`, if recorded.
    #[must_use]
    pub fn retention_for(&self, decision_id: DecisionId) -> Option<&RetentionPolicy> {
        self.decision(decision_id).map(|record| &record.retention)
    }

    /// Return all recorded decisions for one operator-facing decision kind.
    #[must_use]
    pub fn decisions_for_kind(&self, kind: DataPlaneDecisionKind) -> Vec<&ExplainDecisionRecord> {
        self.important_decisions
            .iter()
            .filter(|record| record.kind == kind)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use crate::messaging::class::DeliveryClass;
    use crate::messaging::compiler::{CompiledSubjectCost, FabricCompileReport};
    use crate::messaging::ir::{CostVector, RetentionPolicy, SubjectFamily};
    use franken_decision::DecisionAuditEntry;
    use franken_kernel::{DecisionId, TraceId};

    fn test_audit_entry(seed: u128, action: &str) -> DecisionAuditEntry {
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
                ("allow".to_owned(), 0.05),
                ("deny".to_owned(), 0.8),
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
}
