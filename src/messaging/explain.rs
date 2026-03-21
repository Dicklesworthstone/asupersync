//! Deterministic explain-plan output for FABRIC cost estimation and
//! evidence-native operational decisions.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use franken_decision::{DecisionAuditEntry, DecisionOutcome};
use franken_evidence::EvidenceLedger;
use franken_kernel::DecisionId;

use super::class::DeliveryClass;
use super::compiler::FabricCompileReport;
use super::fabric::{CellEpoch, CellId};
use super::ir::{CostVector, ReplySpaceRule, RetentionPolicy, SubjectFamily};
use crate::remote::NodeId;
use crate::types::ObligationId;
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

/// Component classes that can emit local topology sections for gluing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConsistencyComponentKind {
    /// Subject-cell placement or cut-certified ownership surface.
    Cell,
    /// Canonicalization or import/export rewrite boundary.
    Morphism,
    /// Delegated cursor-partition authority.
    CursorPartition,
    /// Cross-fabric import/export boundary.
    FederationEdge,
    /// Supervisor-scoped cutover or policy controller.
    SupervisorDomain,
}

/// Stable identifier for one local section emitter.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConsistencyEmitter {
    /// Component class of the emitter.
    pub kind: ConsistencyComponentKind,
    /// Human-readable component identifier.
    pub name: String,
}

impl ConsistencyEmitter {
    /// Construct a stable emitter descriptor.
    #[must_use]
    pub fn new(kind: ConsistencyComponentKind, name: impl Into<String>) -> Self {
        Self {
            kind,
            name: name.into(),
        }
    }
}

/// One local consistency section emitted by a FABRIC component.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConsistencySection {
    /// Originating cell, morphism, edge, or supervisor surface.
    pub emitter: Option<ConsistencyEmitter>,
    /// Local facts exported by the component.
    pub facts: Vec<ConsistencyFact>,
}

impl ConsistencySection {
    /// Construct an empty section for `emitter`.
    #[must_use]
    pub fn new(kind: ConsistencyComponentKind, name: impl Into<String>) -> Self {
        Self {
            emitter: Some(ConsistencyEmitter::new(kind, name)),
            facts: Vec::new(),
        }
    }

    /// Append one fact to the section.
    #[must_use]
    pub fn with_fact(mut self, fact: ConsistencyFact) -> Self {
        self.facts.push(fact);
        self
    }
}

/// Local topology fact emitted by one component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsistencyFact {
    /// Import/export side of a reply-space contract.
    ReplySpaceBoundary(ReplySpaceBoundaryFact),
    /// Morphism edge participating in a larger rewrite chain.
    Morphism(MorphismFact),
    /// Cursor delegation slice assigned to one holder.
    CursorDelegation(CursorDelegationFact),
    /// Cutover coverage fragment for live obligations.
    CutoverCoverage(CutoverCoverageFact),
    /// Witness-placement fragment with durability/confidentiality constraints.
    WitnessPlacement(WitnessPlacementFact),
    /// Adaptive-policy certificate plus current runtime posture.
    AdaptivePolicy(AdaptivePolicyFact),
}

/// Local import/export fact for a reply-bearing route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplySpaceBoundaryFact {
    /// Shared route identifier spanning import/export sides.
    pub route_id: String,
    /// Subject or canonical subject-space label.
    pub subject_space: String,
    /// Reply-space rule claimed at this boundary.
    pub reply_space: Option<ReplySpaceRule>,
    /// Whether the route must carry an explicit reply contract.
    pub reply_contract_required: bool,
}

/// Local morphism edge exported by the normalization or federation plane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MorphismFact {
    /// Human-readable morphism or bridge name.
    pub name: String,
    /// Source namespace or subject space.
    pub from_space: String,
    /// Destination namespace or subject space.
    pub to_space: String,
    /// Whether reply-space declarations survive the rewrite.
    pub preserves_reply_space: bool,
    /// Strongest delivery class enforced after the rewrite.
    pub delivery_class: DeliveryClass,
}

/// Delegated cursor partitions served by one holder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorDelegationFact {
    /// Subject cell whose cursor authority is being delegated.
    pub cell_id: CellId,
    /// Cell epoch fenced into the delegation.
    pub epoch: CellEpoch,
    /// Peer currently serving the delegated partitions.
    pub holder: NodeId,
    /// Deterministic partition identifiers delegated to the holder.
    pub delegated_partitions: BTreeSet<u16>,
}

/// One cutover fragment describing live and covered obligations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CutoverCoverageFact {
    /// Human-readable cutover or failover plan id.
    pub plan_id: String,
    /// Cell whose outstanding obligations must be fenced.
    pub cell_id: CellId,
    /// Obligations currently live below the cut.
    pub live_obligations: BTreeSet<ObligationId>,
    /// Obligations explicitly covered by this fragment of the plan.
    pub covered_obligations: BTreeSet<ObligationId>,
}

/// One witness-placement fragment for durability/confidentiality checking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessPlacementFact {
    /// Placement plan or certificate identifier.
    pub placement_id: String,
    /// Cell whose witness set is being certified.
    pub cell_id: CellId,
    /// Witnesses nominated by this local section.
    pub witnesses: BTreeSet<NodeId>,
    /// Failure-domain label for any witness referenced by the section.
    pub witness_domains: BTreeMap<NodeId, String>,
    /// Minimum number of witnesses that must survive the plan.
    pub minimum_witnesses: usize,
    /// Minimum number of distinct failure domains required for durability.
    pub minimum_failure_domains: usize,
    /// Allowed failure domains for confidential witness placement.
    pub confidentiality_allowlist: BTreeSet<String>,
}

/// One adaptive-policy envelope plus the local runtime posture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdaptivePolicyFact {
    /// Stable adaptive-policy identifier across fabrics.
    pub policy_id: String,
    /// Fabric, edge, or region reporting this posture.
    pub fabric_id: String,
    /// Certified upper bound for latency after adaptation.
    pub certified_max_latency: Duration,
    /// Certified lower bound for success probability in basis points.
    pub certified_min_success_probability_bps: u16,
    /// Certified maximum degradation tier.
    pub certified_max_degradation_tier: u8,
    /// Locally active latency after the current adaptation.
    pub observed_latency: Duration,
    /// Locally active success probability in basis points.
    pub observed_success_probability_bps: u16,
    /// Locally active degradation tier.
    pub observed_degradation_tier: u8,
}

/// Glued topology state assembled from compatible local sections.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GlobalConsistencySection {
    /// Reply-space contracts that glued successfully.
    pub reply_space_bindings: BTreeMap<String, GluedReplySpaceBinding>,
    /// Canonical and composed morphisms that glued successfully.
    pub morphisms: BTreeMap<String, GluedMorphism>,
    /// Cursor partitions with an unambiguous holder.
    pub cursor_delegations: BTreeMap<String, GluedCursorDelegation>,
    /// Cutover plans with full outstanding-obligation coverage.
    pub cutovers: BTreeMap<String, GluedCutoverPlan>,
    /// Witness placements satisfying durability and confidentiality together.
    pub witness_placements: BTreeMap<String, GluedWitnessPlacement>,
    /// Adaptive policies that stay inside one global certified envelope.
    pub adaptive_policies: BTreeMap<String, GluedAdaptivePolicy>,
}

/// Successful reply-space gluing for one route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GluedReplySpaceBinding {
    /// Shared route identifier.
    pub route_id: String,
    /// Subject spaces contributed by the participating local sections.
    pub subject_spaces: Vec<String>,
    /// Agreed reply-space contract.
    pub reply_space: Option<ReplySpaceRule>,
    /// Emitters that agreed on the contract.
    pub emitters: Vec<ConsistencyEmitter>,
}

/// Successful explicit or composed morphism.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GluedMorphism {
    /// Source namespace.
    pub from_space: String,
    /// Destination namespace.
    pub to_space: String,
    /// Whether reply-space contracts are preserved end to end.
    pub preserves_reply_space: bool,
    /// Strongest delivery class induced by the composed path.
    pub delivery_class: DeliveryClass,
    /// Explicit or composed path names supporting the gluing.
    pub evidence_paths: Vec<String>,
}

/// Successful cursor delegation for one cell epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GluedCursorDelegation {
    /// Subject cell under delegation.
    pub cell_id: CellId,
    /// Epoch fenced into the delegation.
    pub epoch: CellEpoch,
    /// Unambiguous partition ownership map.
    pub partition_holders: BTreeMap<u16, NodeId>,
}

/// Successful cutover plan with complete obligation coverage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GluedCutoverPlan {
    /// Cutover or failover plan id.
    pub plan_id: String,
    /// Covered subject cell.
    pub cell_id: CellId,
    /// All live obligations aggregated across local sections.
    pub live_obligations: BTreeSet<ObligationId>,
    /// All obligations accounted for by the glued plan.
    pub covered_obligations: BTreeSet<ObligationId>,
    /// Emitters contributing to the full coverage proof.
    pub emitters: Vec<ConsistencyEmitter>,
}

/// Successful witness placement satisfying all local constraints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GluedWitnessPlacement {
    /// Witness-placement certificate id.
    pub placement_id: String,
    /// Cell whose witness set was certified.
    pub cell_id: CellId,
    /// Witnesses in the glued placement.
    pub witnesses: BTreeSet<NodeId>,
    /// Failure-domain mapping used to certify durability.
    pub witness_domains: BTreeMap<NodeId, String>,
    /// Strongest durability requirement seen across sections.
    pub minimum_witnesses: usize,
    /// Strongest failure-domain requirement seen across sections.
    pub minimum_failure_domains: usize,
    /// Intersection of confidentiality allowlists across sections.
    pub confidentiality_allowlist: BTreeSet<String>,
}

/// Successful adaptive-policy envelope agreed across fabrics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GluedAdaptivePolicy {
    /// Shared adaptive-policy identifier.
    pub policy_id: String,
    /// Fabrics or regions contributing local posture.
    pub fabrics: Vec<String>,
    /// Strictest certified latency bound across fabrics.
    pub certified_max_latency: Duration,
    /// Strictest certified success-probability floor across fabrics.
    pub certified_min_success_probability_bps: u16,
    /// Strictest certified degradation cap across fabrics.
    pub certified_max_degradation_tier: u8,
}

/// Typed obstruction discovered while trying to glue local sections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObstructionKind {
    /// Import/export sides disagree on the reply-space contract.
    ReplySpaceMismatch,
    /// Explicit and composed morphisms disagree on the global rewrite.
    MorphismCompositionConflict,
    /// Two holders claim an overlapping cursor partition.
    CursorDelegationOverlap,
    /// The cutover plan leaves live obligations uncovered.
    CutoverCoverageGap,
    /// Witness placement cannot satisfy durability and confidentiality together.
    WitnessPlacementUnsatisfied,
    /// The observed adaptive posture leaves the certified envelope.
    AdaptivePolicyEnvelopeViolation,
}

/// Proof artifact explaining why a global section could not be glued.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObstructionCertificate {
    /// Obstruction class.
    pub kind: ObstructionKind,
    /// Human-readable scope key for the failed gluing attempt.
    pub scope: String,
    /// Short operator-facing summary.
    pub summary: String,
    /// Emitters participating in the failed overlap.
    pub emitters: Vec<ConsistencyEmitter>,
    /// Deterministic detail map for tooling and tests.
    pub details: BTreeMap<String, String>,
}

/// Result of trying to glue all local topology sections.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConsistencyReport {
    /// Successfully glued global section fragments.
    pub global_section: GlobalConsistencySection,
    /// Obstruction certificates for any global inconsistency.
    pub obstructions: Vec<ObstructionCertificate>,
}

impl ConsistencyReport {
    /// Return true when every local section glued into the global section.
    #[must_use]
    pub fn is_globally_consistent(&self) -> bool {
        self.obstructions.is_empty()
    }

    /// Return all obstruction certificates of one kind.
    #[must_use]
    pub fn obstructions_for_kind(&self, kind: ObstructionKind) -> Vec<&ObstructionCertificate> {
        self.obstructions
            .iter()
            .filter(|obstruction| obstruction.kind == kind)
            .collect()
    }
}

/// Sheaf-style topology checker for FABRIC explain output.
pub struct ConsistencyChecker {
    sections: Vec<ConsistencySection>,
}

impl ConsistencyChecker {
    /// Construct a checker for the supplied local sections.
    #[must_use]
    pub fn new(sections: Vec<ConsistencySection>) -> Self {
        Self { sections }
    }

    /// Attempt to glue all local sections into a global section.
    #[must_use]
    pub fn check(&self) -> ConsistencyReport {
        let mut report = ConsistencyReport::default();
        self.glue_reply_spaces(&mut report);
        self.glue_morphisms(&mut report);
        self.glue_cursor_delegations(&mut report);
        self.glue_cutovers(&mut report);
        self.glue_witness_placements(&mut report);
        self.glue_adaptive_policies(&mut report);
        report
    }

    fn glue_reply_spaces(&self, report: &mut ConsistencyReport) {
        let mut groups: BTreeMap<String, Vec<EmittedFact<ReplySpaceBoundaryFact>>> =
            BTreeMap::new();

        for section in &self.sections {
            let Some(emitter) = &section.emitter else {
                continue;
            };
            for fact in &section.facts {
                if let ConsistencyFact::ReplySpaceBoundary(boundary) = fact {
                    groups
                        .entry(boundary.route_id.clone())
                        .or_default()
                        .push(EmittedFact::new(emitter.clone(), boundary.clone()));
                }
            }
        }

        for (route_id, entries) in groups {
            let signatures = entries
                .iter()
                .map(|entry| reply_space_signature(entry.fact.reply_space.as_ref()))
                .collect::<BTreeSet<_>>();
            let missing_required = entries
                .iter()
                .filter(|entry| {
                    entry.fact.reply_contract_required && entry.fact.reply_space.is_none()
                })
                .map(|entry| entry.emitter.name.clone())
                .collect::<Vec<_>>();

            if signatures.len() > 1 || !missing_required.is_empty() {
                let mut details = BTreeMap::new();
                details.insert(
                    "reply_space_signatures".to_owned(),
                    signatures.into_iter().collect::<Vec<_>>().join(","),
                );
                if !missing_required.is_empty() {
                    details.insert(
                        "missing_reply_space_emitters".to_owned(),
                        missing_required.join(","),
                    );
                }
                report.obstructions.push(ObstructionCertificate {
                    kind: ObstructionKind::ReplySpaceMismatch,
                    scope: route_id,
                    summary: "import/export reply-space contracts do not glue".to_owned(),
                    emitters: collect_emitters(&entries),
                    details,
                });
                continue;
            }

            let subject_spaces = entries
                .iter()
                .map(|entry| entry.fact.subject_space.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let reply_space = entries
                .first()
                .and_then(|entry| entry.fact.reply_space.clone());
            report.global_section.reply_space_bindings.insert(
                entries[0].fact.route_id.clone(),
                GluedReplySpaceBinding {
                    route_id: entries[0].fact.route_id.clone(),
                    subject_spaces,
                    reply_space,
                    emitters: collect_emitters(&entries),
                },
            );
        }
    }

    fn glue_morphisms(&self, report: &mut ConsistencyReport) {
        let candidates = self.collect_morphism_candidates();
        let mut groups: BTreeMap<String, Vec<MorphismCandidate>> = BTreeMap::new();

        for candidate in candidates {
            groups
                .entry(morphism_scope_key(
                    &candidate.fact.from_space,
                    &candidate.fact.to_space,
                ))
                .or_default()
                .push(candidate);
        }

        for (scope, candidates) in groups {
            let signatures = candidates
                .iter()
                .map(MorphismCandidate::signature)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();

            if signatures.len() > 1 {
                let mut details = BTreeMap::new();
                details.insert("candidate_signatures".to_owned(), signatures.join(","));
                report.obstructions.push(ObstructionCertificate {
                    kind: ObstructionKind::MorphismCompositionConflict,
                    scope,
                    summary: "local morphisms do not compose into one global rewrite certificate"
                        .to_owned(),
                    emitters: collect_morphism_emitters(&candidates),
                    details,
                });
                continue;
            }

            let candidate = &candidates[0];
            report.global_section.morphisms.insert(
                morphism_scope_key(&candidate.fact.from_space, &candidate.fact.to_space),
                GluedMorphism {
                    from_space: candidate.fact.from_space.clone(),
                    to_space: candidate.fact.to_space.clone(),
                    preserves_reply_space: candidate.fact.preserves_reply_space,
                    delivery_class: candidate.fact.delivery_class,
                    evidence_paths: collect_morphism_paths(&candidates),
                },
            );
        }
    }

    fn glue_cursor_delegations(&self, report: &mut ConsistencyReport) {
        let mut groups: BTreeMap<String, Vec<EmittedFact<CursorDelegationFact>>> = BTreeMap::new();

        for section in &self.sections {
            let Some(emitter) = &section.emitter else {
                continue;
            };
            for fact in &section.facts {
                if let ConsistencyFact::CursorDelegation(cursor) = fact {
                    groups
                        .entry(cell_epoch_scope_key(cursor.cell_id, cursor.epoch))
                        .or_default()
                        .push(EmittedFact::new(emitter.clone(), cursor.clone()));
                }
            }
        }

        for (scope, entries) in groups {
            let mut partition_holders: BTreeMap<u16, NodeId> = BTreeMap::new();
            let mut conflicted = false;

            for entry in &entries {
                for partition in &entry.fact.delegated_partitions {
                    if let Some(existing) = partition_holders.get(partition)
                        && existing != &entry.fact.holder
                    {
                        let mut details = BTreeMap::new();
                        details.insert("partition".to_owned(), partition.to_string());
                        details.insert("existing_holder".to_owned(), existing.as_str().to_owned());
                        details.insert(
                            "conflicting_holder".to_owned(),
                            entry.fact.holder.as_str().to_owned(),
                        );
                        report.obstructions.push(ObstructionCertificate {
                            kind: ObstructionKind::CursorDelegationOverlap,
                            scope: scope.clone(),
                            summary: "cursor partition was delegated to multiple holders"
                                .to_owned(),
                            emitters: collect_emitters(&entries),
                            details,
                        });
                        conflicted = true;
                        continue;
                    }
                    partition_holders.insert(*partition, entry.fact.holder.clone());
                }
            }

            if conflicted {
                continue;
            }

            if let Some(first) = entries.first()
                && !partition_holders.is_empty()
            {
                report.global_section.cursor_delegations.insert(
                    scope,
                    GluedCursorDelegation {
                        cell_id: first.fact.cell_id,
                        epoch: first.fact.epoch,
                        partition_holders,
                    },
                );
            }
        }
    }

    fn glue_cutovers(&self, report: &mut ConsistencyReport) {
        let mut groups: BTreeMap<String, Vec<EmittedFact<CutoverCoverageFact>>> = BTreeMap::new();

        for section in &self.sections {
            let Some(emitter) = &section.emitter else {
                continue;
            };
            for fact in &section.facts {
                if let ConsistencyFact::CutoverCoverage(cutover) = fact {
                    groups
                        .entry(cutover_scope_key(&cutover.plan_id, cutover.cell_id))
                        .or_default()
                        .push(EmittedFact::new(emitter.clone(), cutover.clone()));
                }
            }
        }

        for (scope, entries) in groups {
            let mut live_obligations = BTreeSet::new();
            let mut covered_obligations = BTreeSet::new();

            for entry in &entries {
                live_obligations.extend(entry.fact.live_obligations.iter().copied());
                covered_obligations.extend(entry.fact.covered_obligations.iter().copied());
            }

            let missing = live_obligations
                .difference(&covered_obligations)
                .map(ToString::to_string)
                .collect::<Vec<_>>();

            if !missing.is_empty() {
                let mut details = BTreeMap::new();
                details.insert("missing_obligations".to_owned(), missing.join(","));
                report.obstructions.push(ObstructionCertificate {
                    kind: ObstructionKind::CutoverCoverageGap,
                    scope,
                    summary: "cutover plan leaves live obligations uncovered".to_owned(),
                    emitters: collect_emitters(&entries),
                    details,
                });
                continue;
            }

            let first = &entries[0].fact;
            report.global_section.cutovers.insert(
                cutover_scope_key(&first.plan_id, first.cell_id),
                GluedCutoverPlan {
                    plan_id: first.plan_id.clone(),
                    cell_id: first.cell_id,
                    live_obligations,
                    covered_obligations,
                    emitters: collect_emitters(&entries),
                },
            );
        }
    }

    #[allow(clippy::too_many_lines)]
    fn glue_witness_placements(&self, report: &mut ConsistencyReport) {
        let mut groups: BTreeMap<String, Vec<EmittedFact<WitnessPlacementFact>>> = BTreeMap::new();

        for section in &self.sections {
            let Some(emitter) = &section.emitter else {
                continue;
            };
            for fact in &section.facts {
                if let ConsistencyFact::WitnessPlacement(witness) = fact {
                    groups
                        .entry(witness_scope_key(&witness.placement_id, witness.cell_id))
                        .or_default()
                        .push(EmittedFact::new(emitter.clone(), witness.clone()));
                }
            }
        }

        for (scope, entries) in groups {
            let mut witnesses = BTreeSet::new();
            let mut witness_domains = BTreeMap::new();
            let mut minimum_witnesses = 0;
            let mut minimum_failure_domains = 0;
            let mut confidentiality_allowlist: Option<BTreeSet<String>> = None;

            for entry in &entries {
                witnesses.extend(entry.fact.witnesses.iter().cloned());
                witness_domains.extend(entry.fact.witness_domains.clone());
                minimum_witnesses = minimum_witnesses.max(entry.fact.minimum_witnesses);
                minimum_failure_domains =
                    minimum_failure_domains.max(entry.fact.minimum_failure_domains);
                if !entry.fact.confidentiality_allowlist.is_empty() {
                    match &mut confidentiality_allowlist {
                        Some(current) => current
                            .retain(|domain| entry.fact.confidentiality_allowlist.contains(domain)),
                        None => {
                            confidentiality_allowlist =
                                Some(entry.fact.confidentiality_allowlist.clone());
                        }
                    }
                }
            }

            let confidentiality_allowlist = confidentiality_allowlist.unwrap_or_default();
            let missing_domains = witnesses
                .iter()
                .filter(|witness| !witness_domains.contains_key(*witness))
                .map(|witness| witness.as_str().to_owned())
                .collect::<Vec<_>>();
            let disallowed_domains = witnesses
                .iter()
                .filter_map(|witness| {
                    let domain = witness_domains.get(witness)?;
                    (!confidentiality_allowlist.is_empty()
                        && !confidentiality_allowlist.contains(domain))
                    .then(|| format!("{}:{domain}", witness.as_str()))
                })
                .collect::<Vec<_>>();
            let distinct_domains = witnesses
                .iter()
                .filter_map(|witness| witness_domains.get(witness).cloned())
                .filter(|domain| {
                    confidentiality_allowlist.is_empty()
                        || confidentiality_allowlist.contains(domain)
                })
                .collect::<BTreeSet<_>>();

            if !missing_domains.is_empty()
                || !disallowed_domains.is_empty()
                || witnesses.len() < minimum_witnesses
                || distinct_domains.len() < minimum_failure_domains
            {
                let mut details = BTreeMap::new();
                if !missing_domains.is_empty() {
                    details.insert(
                        "missing_domain_witnesses".to_owned(),
                        missing_domains.join(","),
                    );
                }
                if !disallowed_domains.is_empty() {
                    details.insert(
                        "disallowed_witnesses".to_owned(),
                        disallowed_domains.join(","),
                    );
                }
                details.insert("witness_count".to_owned(), witnesses.len().to_string());
                details.insert(
                    "required_witness_count".to_owned(),
                    minimum_witnesses.to_string(),
                );
                details.insert(
                    "distinct_failure_domains".to_owned(),
                    distinct_domains.len().to_string(),
                );
                details.insert(
                    "required_failure_domains".to_owned(),
                    minimum_failure_domains.to_string(),
                );
                report.obstructions.push(ObstructionCertificate {
                    kind: ObstructionKind::WitnessPlacementUnsatisfied,
                    scope,
                    summary:
                        "witness placement cannot satisfy durability and confidentiality together"
                            .to_owned(),
                    emitters: collect_emitters(&entries),
                    details,
                });
                continue;
            }

            let first = &entries[0].fact;
            report.global_section.witness_placements.insert(
                witness_scope_key(&first.placement_id, first.cell_id),
                GluedWitnessPlacement {
                    placement_id: first.placement_id.clone(),
                    cell_id: first.cell_id,
                    witnesses,
                    witness_domains,
                    minimum_witnesses,
                    minimum_failure_domains,
                    confidentiality_allowlist,
                },
            );
        }
    }

    fn glue_adaptive_policies(&self, report: &mut ConsistencyReport) {
        let mut groups: BTreeMap<String, Vec<EmittedFact<AdaptivePolicyFact>>> = BTreeMap::new();

        for section in &self.sections {
            let Some(emitter) = &section.emitter else {
                continue;
            };
            for fact in &section.facts {
                if let ConsistencyFact::AdaptivePolicy(policy) = fact {
                    groups
                        .entry(policy.policy_id.clone())
                        .or_default()
                        .push(EmittedFact::new(emitter.clone(), policy.clone()));
                }
            }
        }

        for (policy_id, entries) in groups {
            let certified_max_latency = entries
                .iter()
                .map(|entry| entry.fact.certified_max_latency)
                .min()
                .unwrap_or(Duration::ZERO);
            let certified_min_success_probability_bps = entries
                .iter()
                .map(|entry| entry.fact.certified_min_success_probability_bps)
                .max()
                .unwrap_or(0);
            let certified_max_degradation_tier = entries
                .iter()
                .map(|entry| entry.fact.certified_max_degradation_tier)
                .min()
                .unwrap_or(0);

            let violating_fabrics = entries
                .iter()
                .filter(|entry| {
                    entry.fact.observed_latency > certified_max_latency
                        || entry.fact.observed_success_probability_bps
                            < certified_min_success_probability_bps
                        || entry.fact.observed_degradation_tier > certified_max_degradation_tier
                })
                .map(|entry| entry.fact.fabric_id.clone())
                .collect::<Vec<_>>();

            if !violating_fabrics.is_empty() {
                let mut details = BTreeMap::new();
                details.insert("violating_fabrics".to_owned(), violating_fabrics.join(","));
                details.insert(
                    "certified_max_latency_ms".to_owned(),
                    certified_max_latency.as_millis().to_string(),
                );
                details.insert(
                    "certified_min_success_bps".to_owned(),
                    certified_min_success_probability_bps.to_string(),
                );
                details.insert(
                    "certified_max_degradation_tier".to_owned(),
                    certified_max_degradation_tier.to_string(),
                );
                report.obstructions.push(ObstructionCertificate {
                    kind: ObstructionKind::AdaptivePolicyEnvelopeViolation,
                    scope: policy_id,
                    summary: "adaptive policy escaped the globally certified operating envelope"
                        .to_owned(),
                    emitters: collect_emitters(&entries),
                    details,
                });
                continue;
            }

            report.global_section.adaptive_policies.insert(
                entries[0].fact.policy_id.clone(),
                GluedAdaptivePolicy {
                    policy_id: entries[0].fact.policy_id.clone(),
                    fabrics: entries
                        .iter()
                        .map(|entry| entry.fact.fabric_id.clone())
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect(),
                    certified_max_latency,
                    certified_min_success_probability_bps,
                    certified_max_degradation_tier,
                },
            );
        }
    }

    fn collect_morphism_candidates(&self) -> Vec<MorphismCandidate> {
        let mut candidates = Vec::new();

        for section in &self.sections {
            let Some(emitter) = &section.emitter else {
                continue;
            };
            for fact in &section.facts {
                if let ConsistencyFact::Morphism(morphism) = fact {
                    candidates.push(MorphismCandidate {
                        fact: morphism.clone(),
                        emitters: vec![emitter.clone()],
                        evidence_paths: vec![morphism.name.clone()],
                    });
                }
            }
        }

        let mut changed = true;
        while changed {
            changed = false;
            let snapshot = candidates.clone();
            for left in &snapshot {
                for right in &snapshot {
                    if left.fact.to_space != right.fact.from_space {
                        continue;
                    }
                    if left.fact.from_space == right.fact.to_space {
                        continue;
                    }

                    let candidate = MorphismCandidate {
                        fact: MorphismFact {
                            name: format!("{}+{}", left.fact.name, right.fact.name),
                            from_space: left.fact.from_space.clone(),
                            to_space: right.fact.to_space.clone(),
                            preserves_reply_space: left.fact.preserves_reply_space
                                && right.fact.preserves_reply_space,
                            delivery_class: left.fact.delivery_class.max(right.fact.delivery_class),
                        },
                        emitters: merge_emitters(&left.emitters, &right.emitters),
                        evidence_paths: merge_strings(
                            &left.evidence_paths,
                            &right.evidence_paths,
                            &format!(
                                "{}->{}->{}",
                                left.fact.from_space, left.fact.to_space, right.fact.to_space
                            ),
                        ),
                    };

                    if !candidates
                        .iter()
                        .any(|existing| existing.same_signature(&candidate))
                    {
                        candidates.push(candidate);
                        changed = true;
                    }
                }
            }
        }

        candidates
    }
}

#[derive(Debug, Clone)]
struct EmittedFact<T> {
    emitter: ConsistencyEmitter,
    fact: T,
}

impl<T> EmittedFact<T> {
    fn new(emitter: ConsistencyEmitter, fact: T) -> Self {
        Self { emitter, fact }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MorphismCandidate {
    fact: MorphismFact,
    emitters: Vec<ConsistencyEmitter>,
    evidence_paths: Vec<String>,
}

impl MorphismCandidate {
    fn same_signature(&self, other: &Self) -> bool {
        self.fact.from_space == other.fact.from_space
            && self.fact.to_space == other.fact.to_space
            && self.fact.preserves_reply_space == other.fact.preserves_reply_space
            && self.fact.delivery_class == other.fact.delivery_class
    }

    fn signature(&self) -> String {
        format!(
            "{}=>{}:{}:{}",
            self.fact.from_space,
            self.fact.to_space,
            self.fact.preserves_reply_space,
            self.fact.delivery_class
        )
    }
}

fn reply_space_signature(rule: Option<&ReplySpaceRule>) -> String {
    match rule {
        None => "none".to_owned(),
        Some(ReplySpaceRule::CallerInbox) => "caller_inbox".to_owned(),
        Some(ReplySpaceRule::SharedPrefix { prefix }) => format!("shared:{prefix}"),
        Some(ReplySpaceRule::DedicatedPrefix { prefix }) => format!("dedicated:{prefix}"),
    }
}

fn morphism_scope_key(from_space: &str, to_space: &str) -> String {
    format!("{from_space}=>{to_space}")
}

fn cell_epoch_scope_key(cell_id: CellId, epoch: CellEpoch) -> String {
    format!("{cell_id}@{}:{}", epoch.membership_epoch, epoch.generation)
}

fn cutover_scope_key(plan_id: &str, cell_id: CellId) -> String {
    format!("{plan_id}:{cell_id}")
}

fn witness_scope_key(placement_id: &str, cell_id: CellId) -> String {
    format!("{placement_id}:{cell_id}")
}

fn collect_emitters<T>(entries: &[EmittedFact<T>]) -> Vec<ConsistencyEmitter> {
    entries
        .iter()
        .map(|entry| entry.emitter.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn collect_morphism_emitters(candidates: &[MorphismCandidate]) -> Vec<ConsistencyEmitter> {
    candidates
        .iter()
        .flat_map(|candidate| candidate.emitters.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn collect_morphism_paths(candidates: &[MorphismCandidate]) -> Vec<String> {
    candidates
        .iter()
        .flat_map(|candidate| candidate.evidence_paths.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn merge_emitters(
    left: &[ConsistencyEmitter],
    right: &[ConsistencyEmitter],
) -> Vec<ConsistencyEmitter> {
    left.iter()
        .chain(right.iter())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn merge_strings(left: &[String], right: &[String], extra: &str) -> Vec<String> {
    left.iter()
        .chain(right.iter())
        .cloned()
        .chain(std::iter::once(extra.to_owned()))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
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
}
