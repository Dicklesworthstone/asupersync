//! Deterministic FABRIC validation and cost-estimation compiler scaffolding.

use super::class::DeliveryClass;
use super::ir::{
    BranchAttachment, BranchMutationMode, CapabilityPermission, CapabilityTokenSchema,
    ConsumerMode, ConsumerPolicy, CostVector, CpuEstimate, CutPolicy, DurationEstimate,
    EvidencePolicy, FabricIr, FabricIrValidationError, MaterializationPolicy, MetadataDisclosure,
    MobilityPermission, MorphismPlan, MorphismTransform, PrivacyPolicy, ProtocolContract,
    QuantitativeObligationContract, RetentionPolicy, ServiceContract, SessionStep, SubjectFamily,
    SubjectPattern, SubjectSchema,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

/// Deterministic compiler for FABRIC IR declarations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FabricCompiler;

/// Cost estimate emitted for one compiled subject declaration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompiledSubjectCost {
    /// Canonical subject pattern.
    pub pattern: String,
    /// Semantic family attached to the subject.
    pub family: SubjectFamily,
    /// Delivery class used as the baseline cost envelope.
    pub delivery_class: DeliveryClass,
    /// Estimated cost envelope for this subject.
    pub estimated_cost: CostVector,
}

impl CompiledSubjectCost {
    fn from_subject(schema: &SubjectSchema) -> Self {
        Self {
            pattern: schema.pattern.as_str().to_owned(),
            family: schema.family,
            delivery_class: schema.delivery_class,
            estimated_cost: CostVector::estimate_subject(schema),
        }
    }
}

/// High-level kind emitted by the FABRIC compiler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledArtifactKind {
    /// Subject-family declaration.
    Subject,
    /// Morphism rewrite plan.
    Morphism,
    /// Service contract.
    Service,
    /// Session-typed protocol contract.
    Protocol,
    /// Consumer policy.
    Consumer,
    /// Standalone privacy policy.
    PrivacyPolicy,
    /// Cut/checkpoint policy.
    CutPolicy,
    /// Counterfactual branch policy.
    BranchPolicy,
    /// Quantitative obligation contract.
    ObligationContract,
    /// Capability token schema.
    CapabilityToken,
}

/// Deterministic runtime artifact emitted by the compiler.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompiledArtifact {
    /// Artifact kind.
    pub kind: CompiledArtifactKind,
    /// Stable human-readable artifact name.
    pub name: String,
    /// Deterministic dependency keys the artifact was compiled against.
    pub dependencies: Vec<String>,
    /// Cost envelope associated with the artifact.
    pub estimated_cost: CostVector,
}

/// Non-fatal compiler finding surfaced to operators.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilerWarning {
    /// Logical field path that triggered the warning.
    pub field: String,
    /// Human-readable warning message.
    pub message: String,
}

impl CompilerWarning {
    fn new(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
        }
    }
}

/// Deterministic compiler output for one FABRIC IR configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FabricCompileReport {
    /// The schema version validated by the compiler.
    pub schema_version: u16,
    /// Per-subject cost estimates in declaration order.
    pub subject_costs: Vec<CompiledSubjectCost>,
    /// Worst-case cost envelope across all compiled artifacts.
    pub aggregate_cost: CostVector,
    /// Deterministic runtime artifacts emitted in declaration order.
    pub artifacts: Vec<CompiledArtifact>,
    /// Non-fatal findings emitted by the compiler.
    pub warnings: Vec<CompilerWarning>,
    /// Validation errors are empty on successful compilation.
    pub errors: Vec<FabricIrValidationError>,
}

/// Compiler failures.
#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
pub enum FabricCompilerError {
    /// Structural validation failed before cost estimation could run.
    #[error("FABRIC IR validation failed with {errors_len} error(s)")]
    Validation {
        /// Validation errors reported by the IR validator.
        errors: Vec<FabricIrValidationError>,
        /// Stable count for diagnostics without parsing the error vector.
        errors_len: usize,
    },
}

impl FabricCompiler {
    /// Validate a FABRIC IR document and emit deterministic subject-cost
    /// estimates for explain-plan and operator reporting surfaces.
    pub fn compile(ir: &FabricIr) -> Result<FabricCompileReport, FabricCompilerError> {
        let mut errors = ir.validate();
        errors.extend(validate_subject_constraints(ir));
        errors.extend(validate_morphisms(ir));
        errors.extend(validate_services(ir));
        errors.extend(validate_protocols(ir));
        errors.extend(validate_capabilities(ir));
        errors.extend(validate_consumers(ir));
        if !errors.is_empty() {
            return Err(FabricCompilerError::Validation {
                errors_len: errors.len(),
                errors,
            });
        }

        let subject_costs = ir
            .subjects
            .iter()
            .map(CompiledSubjectCost::from_subject)
            .collect::<Vec<_>>();
        let warnings = collect_warnings(ir);
        let artifacts = compile_artifacts(ir, &subject_costs);
        let aggregate_cost = CostVector::max_dimensions(
            subject_costs
                .iter()
                .map(|subject| subject.estimated_cost)
                .chain(artifacts.iter().map(|artifact| artifact.estimated_cost)),
        );

        Ok(FabricCompileReport {
            schema_version: ir.schema_version,
            subject_costs,
            aggregate_cost,
            artifacts,
            warnings,
            errors: Vec::new(),
        })
    }
}

fn validate_subject_constraints(ir: &FabricIr) -> Vec<FabricIrValidationError> {
    let mut errors = Vec::new();
    for (index, subject) in ir.subjects.iter().enumerate() {
        let base = format!("subjects[{index}]");
        let evidence = &subject.evidence_policy;
        let privacy = &subject.privacy_policy;

        if subject.delivery_class == DeliveryClass::ForensicReplayable {
            if evidence.sampling_ratio < 1.0 {
                errors.push(validation_error(
                    format!("{base}.evidence_policy.sampling_ratio"),
                    "forensic-replayable subjects must sample evidence at 100%",
                ));
            }
            if !evidence.record_payload_hashes {
                errors.push(validation_error(
                    format!("{base}.evidence_policy.record_payload_hashes"),
                    "forensic-replayable subjects must record payload hashes",
                ));
            }
            if !evidence.record_control_transitions {
                errors.push(validation_error(
                    format!("{base}.evidence_policy.record_control_transitions"),
                    "forensic-replayable subjects must record control transitions",
                ));
            }
            if matches!(evidence.retention, RetentionPolicy::DropImmediately) {
                errors.push(validation_error(
                    format!("{base}.evidence_policy.retention"),
                    "forensic-replayable subjects must retain evidence beyond the immediate action",
                ));
            }
        }

        if subject.mobility != MobilityPermission::LocalOnly
            && privacy.metadata_disclosure == MetadataDisclosure::Full
            && !privacy.allow_cross_tenant_flow
        {
            errors.push(validation_error(
                format!("{base}.privacy_policy.allow_cross_tenant_flow"),
                "full metadata disclosure across a federated or stewardship boundary requires explicit cross-tenant flow permission",
            ));
        }
    }
    errors
}

fn validate_morphisms(ir: &FabricIr) -> Vec<FabricIrValidationError> {
    let mut errors = Vec::new();
    for (index, morphism) in ir.morphisms.iter().enumerate() {
        let base = format!("morphisms[{index}]");
        let matched_subjects = matching_subjects_for_families(
            &ir.subjects,
            &morphism.source_pattern,
            &morphism.allowed_families,
        );
        if matched_subjects.is_empty() {
            errors.push(validation_error(
                format!("{base}.source_pattern"),
                "morphism source pattern does not overlap any declared subject in its allowed families",
            ));
            continue;
        }

        for (transform_index, transform) in morphism.transforms.iter().enumerate() {
            match transform {
                MorphismTransform::FilterFamily { family }
                    if !morphism.allowed_families.contains(family) =>
                {
                    errors.push(validation_error(
                        format!("{base}.transforms[{transform_index}]"),
                        format!(
                            "filter-family transform references `{}` outside the morphism's allowed_families",
                            family.as_str()
                        ),
                    ));
                }
                MorphismTransform::EscalateDeliveryClass { class } => {
                    for subject in &matched_subjects {
                        if *class < subject.delivery_class {
                            errors.push(validation_error(
                                format!("{base}.transforms[{transform_index}]"),
                                format!(
                                    "escalated delivery class `{class}` is weaker than matched subject `{}` with class `{}`",
                                    subject.pattern.as_str(),
                                    subject.delivery_class
                                ),
                            ));
                        }
                    }
                }
                MorphismTransform::AttachEvidencePolicy { policy }
                    if policy.sampling_ratio <= 0.0
                        && matched_subjects.iter().any(|subject| {
                            subject.delivery_class == DeliveryClass::ForensicReplayable
                        }) =>
                {
                    errors.push(validation_error(
                        format!("{base}.transforms[{transform_index}]"),
                        "forensic-replayable subjects cannot attach zero-sampling evidence policies during compilation",
                    ));
                }
                MorphismTransform::RenamePrefix { .. }
                | MorphismTransform::FilterFamily { .. }
                | MorphismTransform::PreserveReplySpace
                | MorphismTransform::AttachEvidencePolicy { .. } => {}
            }
        }

        if matched_subjects.iter().any(|subject| {
            subject.reply_space.is_some() || subject.family == SubjectFamily::ProtocolStep
        }) && !morphism_is_reversible(morphism)
        {
            errors.push(validation_error(
                format!("{base}.transforms"),
                "morphisms touching reply-space or protocol-step subjects must stay structurally reversible",
            ));
        }
    }
    errors
}

fn validate_services(ir: &FabricIr) -> Vec<FabricIrValidationError> {
    let mut errors = Vec::new();
    for (service_index, service) in ir.services.iter().enumerate() {
        let base = format!("services[{service_index}]");
        let capability = service
            .required_capability
            .as_deref()
            .and_then(|name| ir.capability_tokens.iter().find(|token| token.name == name));

        for (operation_index, operation) in service.operations.iter().enumerate() {
            let field = format!("{base}.operations[{operation_index}]");
            let matched_commands = matching_subjects_for_families(
                &ir.subjects,
                &operation.request,
                &[SubjectFamily::Command],
            );
            if matched_commands.is_empty() {
                errors.push(validation_error(
                    format!("{field}.request"),
                    "service operations must target at least one declared command subject",
                ));
                continue;
            }

            for subject in &matched_commands {
                if operation.delivery_class < subject.delivery_class {
                    errors.push(validation_error(
                        format!("{field}.delivery_class"),
                        format!(
                            "service operation delivery class `{}` is weaker than matched command subject `{}` with class `{}`",
                            operation.delivery_class,
                            subject.pattern.as_str(),
                            subject.delivery_class
                        ),
                    ));
                }
            }

            if let Some(capability) = capability {
                if !capability
                    .permissions
                    .contains(&CapabilityPermission::Request)
                {
                    errors.push(validation_error(
                        format!("{base}.required_capability"),
                        format!(
                            "required capability token `{}` must grant request permission for service operations",
                            capability.name
                        ),
                    ));
                }
                if !capability.families.contains(&SubjectFamily::Command) {
                    errors.push(validation_error(
                        format!("{base}.required_capability"),
                        format!(
                            "required capability token `{}` must authorize command subjects",
                            capability.name
                        ),
                    ));
                }
                if !capability
                    .delivery_classes
                    .contains(&operation.delivery_class)
                {
                    errors.push(validation_error(
                        format!("{base}.required_capability"),
                        format!(
                            "required capability token `{}` must authorize delivery class `{}`",
                            capability.name, operation.delivery_class
                        ),
                    ));
                }
            }
        }
    }
    errors
}

fn validate_protocols(ir: &FabricIr) -> Vec<FabricIrValidationError> {
    let mut errors = Vec::new();
    for (index, protocol) in ir.protocols.iter().enumerate() {
        let base = format!("protocols[{index}]");
        if !has_matching_subject(&ir.subjects, &protocol.entry_subject) {
            errors.push(validation_error(
                format!("{base}.entry_subject"),
                "protocol entry subject must overlap at least one declared subject",
            ));
        }
        validate_protocol_steps(
            &ir.subjects,
            &protocol.session.steps,
            &format!("{base}.session.steps"),
            &mut errors,
        );
    }
    errors
}

fn validate_capabilities(ir: &FabricIr) -> Vec<FabricIrValidationError> {
    let mut errors = Vec::new();
    for (index, capability) in ir.capability_tokens.iter().enumerate() {
        let base = format!("capability_tokens[{index}]");
        if !ir
            .subjects
            .iter()
            .any(|subject| capability.families.contains(&subject.family))
        {
            errors.push(validation_error(
                format!("{base}.families"),
                "capability token does not authorize any family present in this FABRIC document",
            ));
        }
        if !ir.subjects.iter().any(|subject| {
            capability
                .delivery_classes
                .contains(&subject.delivery_class)
        }) {
            errors.push(validation_error(
                format!("{base}.delivery_classes"),
                "capability token does not authorize any subject delivery class present in this FABRIC document",
            ));
        }
    }
    errors
}

fn validate_consumers(ir: &FabricIr) -> Vec<FabricIrValidationError> {
    let mut errors = Vec::new();
    let replayable_subject_exists = ir.subjects.iter().any(subject_supports_replay);
    for (index, consumer) in ir.consumers.iter().enumerate() {
        if consumer.mode == ConsumerMode::Replayable && !replayable_subject_exists {
            errors.push(validation_error(
                format!("consumers[{index}].mode"),
                "replayable consumers require at least one declared subject that retains evidence for replay",
            ));
        }
    }
    errors
}

fn collect_warnings(ir: &FabricIr) -> Vec<CompilerWarning> {
    let mut warnings = Vec::new();
    for (index, subject) in ir.subjects.iter().enumerate() {
        if subject.privacy_policy.metadata_disclosure == MetadataDisclosure::Redacted
            && !subject.privacy_policy.redact_subject_literals
        {
            warnings.push(CompilerWarning::new(
                format!("subjects[{index}].privacy_policy.redact_subject_literals"),
                "redacted metadata disclosure still leaves literal namespace segments visible unless subject literals are also redacted",
            ));
        }
    }

    for (index, morphism) in ir.morphisms.iter().enumerate() {
        let touches_reply_space = matching_subjects_for_families(
            &ir.subjects,
            &morphism.source_pattern,
            &morphism.allowed_families,
        )
        .iter()
        .any(|subject| subject.reply_space.is_some());
        let preserves_reply_space = morphism
            .transforms
            .iter()
            .any(|transform| matches!(transform, MorphismTransform::PreserveReplySpace));
        if touches_reply_space && !preserves_reply_space {
            warnings.push(CompilerWarning::new(
                format!("morphisms[{index}].transforms"),
                "morphism touches reply-space-bearing subjects but does not explicitly preserve reply-space declarations",
            ));
        }
    }

    warnings
}

fn compile_artifacts(
    ir: &FabricIr,
    subject_costs: &[CompiledSubjectCost],
) -> Vec<CompiledArtifact> {
    let mut artifacts = ir
        .subjects
        .iter()
        .zip(subject_costs.iter())
        .map(|(subject, cost)| CompiledArtifact {
            kind: CompiledArtifactKind::Subject,
            name: subject.pattern.as_str().to_owned(),
            dependencies: Vec::new(),
            estimated_cost: cost.estimated_cost,
        })
        .collect::<Vec<_>>();

    artifacts.extend(ir.morphisms.iter().map(|morphism| CompiledArtifact {
        kind: CompiledArtifactKind::Morphism,
        name: morphism.name.clone(),
        dependencies: morphism_dependencies(morphism, &ir.subjects),
        estimated_cost: estimate_morphism_cost(morphism, &ir.subjects),
    }));
    artifacts.extend(ir.services.iter().map(|service| CompiledArtifact {
        kind: CompiledArtifactKind::Service,
        name: service.name.clone(),
        dependencies: service_dependencies(service),
        estimated_cost: estimate_service_cost(service, &ir.subjects),
    }));
    artifacts.extend(ir.protocols.iter().map(|protocol| CompiledArtifact {
        kind: CompiledArtifactKind::Protocol,
        name: protocol.name.clone(),
        dependencies: protocol_dependencies(protocol),
        estimated_cost: estimate_protocol_cost(protocol, &ir.subjects),
    }));
    artifacts.extend(ir.consumers.iter().map(|consumer| CompiledArtifact {
        kind: CompiledArtifactKind::Consumer,
        name: consumer.name.clone(),
        dependencies: Vec::new(),
        estimated_cost: estimate_consumer_cost(consumer),
    }));
    artifacts.extend(ir.privacy_policies.iter().map(|policy| CompiledArtifact {
        kind: CompiledArtifactKind::PrivacyPolicy,
        name: policy.name.clone(),
        dependencies: Vec::new(),
        estimated_cost: estimate_privacy_cost(policy),
    }));
    artifacts.extend(ir.cut_policies.iter().map(|policy| CompiledArtifact {
        kind: CompiledArtifactKind::CutPolicy,
        name: policy.name.clone(),
        dependencies: Vec::new(),
        estimated_cost: estimate_cut_policy_cost(policy),
    }));
    artifacts.extend(ir.branch_policies.iter().map(|policy| CompiledArtifact {
        kind: CompiledArtifactKind::BranchPolicy,
        name: policy.name.clone(),
        dependencies: Vec::new(),
        estimated_cost: estimate_branch_policy_cost(policy),
    }));
    artifacts.extend(
        ir.obligation_contracts
            .iter()
            .map(|contract| CompiledArtifact {
                kind: CompiledArtifactKind::ObligationContract,
                name: contract.name.clone(),
                dependencies: Vec::new(),
                estimated_cost: estimate_quantitative_obligation_cost(contract),
            }),
    );
    artifacts.extend(
        ir.capability_tokens
            .iter()
            .map(|capability| CompiledArtifact {
                kind: CompiledArtifactKind::CapabilityToken,
                name: capability.name.clone(),
                dependencies: Vec::new(),
                estimated_cost: estimate_capability_cost(capability),
            }),
    );

    artifacts
}

fn validate_protocol_steps(
    subjects: &[SubjectSchema],
    steps: &[SessionStep],
    field: &str,
    errors: &mut Vec<FabricIrValidationError>,
) {
    for (index, step) in steps.iter().enumerate() {
        let step_field = format!("{field}[{index}]");
        match step {
            SessionStep::Send { subject, .. } | SessionStep::Receive { subject, .. } => {
                if !has_matching_subject(subjects, subject) {
                    errors.push(validation_error(
                        format!("{step_field}.subject"),
                        "protocol step subject must overlap at least one declared subject",
                    ));
                }
            }
            SessionStep::Choice { branches, .. } => {
                for (branch_index, branch) in branches.iter().enumerate() {
                    validate_protocol_steps(
                        subjects,
                        &branch.steps,
                        &format!("{step_field}.branches[{branch_index}].steps"),
                        errors,
                    );
                }
            }
            SessionStep::End => {}
        }
    }
}

fn validation_error(
    field: impl Into<String>,
    message: impl Into<String>,
) -> FabricIrValidationError {
    FabricIrValidationError {
        field: field.into(),
        message: message.into(),
    }
}

fn matching_subjects_for_families<'a>(
    subjects: &'a [SubjectSchema],
    pattern: &SubjectPattern,
    families: &[SubjectFamily],
) -> Vec<&'a SubjectSchema> {
    subjects
        .iter()
        .filter(|subject| families.contains(&subject.family) && pattern.overlaps(&subject.pattern))
        .collect()
}

fn has_matching_subject(subjects: &[SubjectSchema], pattern: &SubjectPattern) -> bool {
    subjects
        .iter()
        .any(|subject| pattern.overlaps(&subject.pattern))
}

fn subject_supports_replay(subject: &SubjectSchema) -> bool {
    subject.evidence_policy.sampling_ratio > 0.0
        && !matches!(
            subject.evidence_policy.retention,
            RetentionPolicy::DropImmediately
        )
}

fn morphism_is_reversible(morphism: &MorphismPlan) -> bool {
    morphism.transforms.iter().all(transform_is_reversible)
}

fn transform_is_reversible(transform: &MorphismTransform) -> bool {
    matches!(
        transform,
        MorphismTransform::RenamePrefix { .. } | MorphismTransform::PreserveReplySpace
    )
}

fn morphism_dependencies(morphism: &MorphismPlan, subjects: &[SubjectSchema]) -> Vec<String> {
    let mut dependencies = Vec::new();
    for subject in matching_subjects_for_families(
        subjects,
        &morphism.source_pattern,
        &morphism.allowed_families,
    ) {
        push_unique(&mut dependencies, subject.pattern.as_str().to_owned());
    }
    dependencies
}

fn service_dependencies(service: &ServiceContract) -> Vec<String> {
    let mut dependencies = service
        .operations
        .iter()
        .map(|operation| operation.request.as_str().to_owned())
        .collect::<Vec<_>>();
    if let Some(required_capability) = service.required_capability.as_ref() {
        push_unique(
            &mut dependencies,
            format!("capability:{required_capability}"),
        );
    }
    dependencies
}

fn protocol_dependencies(protocol: &ProtocolContract) -> Vec<String> {
    let mut dependencies = vec![protocol.entry_subject.as_str().to_owned()];
    collect_protocol_step_dependencies(&protocol.session.steps, &mut dependencies);
    dependencies
}

fn collect_protocol_step_dependencies(steps: &[SessionStep], dependencies: &mut Vec<String>) {
    for step in steps {
        match step {
            SessionStep::Send { subject, .. } | SessionStep::Receive { subject, .. } => {
                push_unique(dependencies, subject.as_str().to_owned());
            }
            SessionStep::Choice { branches, .. } => {
                for branch in branches {
                    collect_protocol_step_dependencies(&branch.steps, dependencies);
                }
            }
            SessionStep::End => {}
        }
    }
}

fn estimate_morphism_cost(morphism: &MorphismPlan, subjects: &[SubjectSchema]) -> CostVector {
    let mut cost = CostVector::max_dimensions(
        matching_subjects_for_families(
            subjects,
            &morphism.source_pattern,
            &morphism.allowed_families,
        )
        .into_iter()
        .map(CostVector::estimate_subject),
    );
    add_cpu_cost(
        &mut cost,
        (morphism.transforms.len() as u64).saturating_mul(3),
        (morphism.transforms.len() as u64).saturating_mul(9),
    );
    for transform in &morphism.transforms {
        match transform {
            MorphismTransform::RenamePrefix { .. } => {
                cost.control_plane_amplification += 0.03;
            }
            MorphismTransform::FilterFamily { .. } => {
                cost.control_plane_amplification += 0.02;
            }
            MorphismTransform::EscalateDeliveryClass { class } => {
                cost = CostVector::max_dimensions([
                    cost,
                    CostVector::baseline_for_delivery_class(*class),
                ]);
            }
            MorphismTransform::PreserveReplySpace => {
                cost.control_plane_amplification += 0.05;
                add_cpu_cost(&mut cost, 2, 6);
            }
            MorphismTransform::AttachEvidencePolicy { policy } => {
                apply_evidence_policy_delta(&mut cost, policy);
            }
        }
    }
    cost
}

fn estimate_service_cost(service: &ServiceContract, subjects: &[SubjectSchema]) -> CostVector {
    let mut cost = CostVector::max_dimensions(service.operations.iter().map(|operation| {
        let matched =
            matching_subjects_for_families(subjects, &operation.request, &[SubjectFamily::Command]);
        let matched_cost =
            CostVector::max_dimensions(matched.into_iter().map(CostVector::estimate_subject));
        let mut operation_cost = CostVector::max_dimensions([
            matched_cost,
            CostVector::baseline_for_delivery_class(operation.delivery_class),
        ]);
        if operation.reply_space.is_some() {
            operation_cost.control_plane_amplification += 0.04;
            add_cpu_cost(&mut operation_cost, 2, 6);
        }
        operation_cost
    }));
    apply_consumer_policy_delta(&mut cost, &service.default_consumer_policy);
    if let Some(contract) = service.quantitative_obligation.as_ref() {
        cost = CostVector::max_dimensions([cost, estimate_quantitative_obligation_cost(contract)]);
    }
    cost
}

fn estimate_protocol_cost(protocol: &ProtocolContract, subjects: &[SubjectSchema]) -> CostVector {
    let mut cost =
        CostVector::max_dimensions(protocol_dependencies(protocol).into_iter().filter_map(
            |dependency| {
                subjects
                    .iter()
                    .find(|subject| subject.pattern.as_str() == dependency)
                    .map(CostVector::estimate_subject)
            },
        ));
    let choice_count = count_protocol_choices(&protocol.session.steps) as u64;
    if choice_count > 0 {
        cost.control_plane_amplification += 0.05 * choice_count as f64;
        add_cpu_cost(
            &mut cost,
            choice_count.saturating_mul(3),
            choice_count.saturating_mul(12),
        );
    }
    cost = CostVector::max_dimensions([cost, estimate_branch_policy_cost(&protocol.branch_policy)]);
    cost
}

fn count_protocol_choices(steps: &[SessionStep]) -> usize {
    steps
        .iter()
        .map(|step| match step {
            SessionStep::Choice { branches, .. } => {
                1 + branches
                    .iter()
                    .map(|branch| count_protocol_choices(&branch.steps))
                    .sum::<usize>()
            }
            SessionStep::Send { .. } | SessionStep::Receive { .. } | SessionStep::End => 0,
        })
        .sum()
}

fn estimate_consumer_cost(consumer: &ConsumerPolicy) -> CostVector {
    let mut cost = CostVector::baseline_for_delivery_class(consumer.delivery_class);
    apply_consumer_policy_delta(&mut cost, consumer);
    cost
}

fn apply_consumer_policy_delta(cost: &mut CostVector, consumer: &ConsumerPolicy) {
    cost.control_plane_amplification += f64::from(consumer.max_deliver.saturating_sub(1)) * 0.02;
    add_cpu_cost(
        cost,
        u64::from(consumer.max_deliver),
        u64::from(consumer.max_deliver) * 4,
    );
    if consumer.mode == ConsumerMode::Replayable {
        cost.control_plane_amplification += 0.08;
        add_restore_time(
            cost,
            Duration::from_millis(10),
            Duration::from_millis(50),
            Duration::from_millis(200),
        );
    }
    if let Some(window) = consumer.replay_window {
        let secs = window.as_secs().min(3600);
        cost.storage_amplification += secs as f64 / 3600.0 * 0.2;
    }
}

fn estimate_privacy_cost(policy: &PrivacyPolicy) -> CostVector {
    let mut cost = CostVector::zero();
    if policy.noise_budget.is_some() {
        add_cpu_cost(&mut cost, 4, 12);
    }
    if policy.metadata_disclosure != MetadataDisclosure::Full {
        add_cpu_cost(&mut cost, 1, 4);
    }
    cost
}

fn estimate_cut_policy_cost(policy: &CutPolicy) -> CostVector {
    let mut cost = estimate_retention_cost(&policy.retention);
    match policy.materialization {
        MaterializationPolicy::MetadataOnly => {
            add_evidence_bytes(&mut cost, 16, 64, 128);
        }
        MaterializationPolicy::ControlPlaneOnly => {
            cost.control_plane_amplification += 0.06;
            add_evidence_bytes(&mut cost, 32, 128, 256);
        }
        MaterializationPolicy::FullReplayable => {
            cost = CostVector::max_dimensions([
                cost,
                CostVector::baseline_for_delivery_class(DeliveryClass::ForensicReplayable),
            ]);
        }
    }
    cost
}

fn estimate_branch_policy_cost(policy: &super::ir::BranchPolicy) -> CostVector {
    let mut cost = estimate_retention_cost(&policy.retention);
    if policy.mutation_mode == BranchMutationMode::SandboxedMutation {
        cost.control_plane_amplification += 0.08;
        add_restore_time(
            &mut cost,
            Duration::from_millis(10),
            Duration::from_millis(40),
            Duration::from_millis(200),
        );
    }
    if policy.attachment == BranchAttachment::AuditedAnalyst {
        add_evidence_bytes(&mut cost, 32, 96, 192);
    }
    cost
}

fn estimate_quantitative_obligation_cost(contract: &QuantitativeObligationContract) -> CostVector {
    let mut cost = CostVector::baseline_for_delivery_class(contract.class);
    cost.tail_latency.median = cost.tail_latency.median.max(contract.target_latency);
    cost.tail_latency.p99 = cost
        .tail_latency
        .p99
        .max(contract.target_latency.saturating_mul(2));
    cost.tail_latency.p999 = cost
        .tail_latency
        .p999
        .max(contract.target_latency.saturating_mul(4));
    cost.control_plane_amplification += 0.05;
    cost
}

fn estimate_capability_cost(capability: &CapabilityTokenSchema) -> CostVector {
    let strongest_class = capability
        .delivery_classes
        .iter()
        .copied()
        .max()
        .unwrap_or_default();
    let mut cost = CostVector::baseline_for_delivery_class(strongest_class);
    cost.control_plane_amplification += capability.permissions.len() as f64 * 0.03;
    add_cpu_cost(
        &mut cost,
        capability.permissions.len() as u64 * 2,
        capability.permissions.len() as u64 * 6,
    );
    cost
}

fn estimate_retention_cost(retention: &RetentionPolicy) -> CostVector {
    match retention {
        RetentionPolicy::DropImmediately => CostVector::zero(),
        RetentionPolicy::RetainFor { duration } => {
            let secs = duration.as_secs().min(3600);
            let mut cost = CostVector::zero();
            cost.storage_amplification += secs as f64 / 3600.0 * 0.25;
            add_restore_time(
                &mut cost,
                Duration::from_millis(5),
                Duration::from_millis(20),
                Duration::from_millis(80),
            );
            cost
        }
        RetentionPolicy::RetainForEvents { events } => {
            let mut cost = CostVector::zero();
            cost.storage_amplification += (*events).min(10_000) as f64 / 10_000.0 * 0.35;
            cost
        }
        RetentionPolicy::Forever => {
            let mut cost = CostVector::zero();
            cost.storage_amplification += 0.6;
            add_evidence_bytes(&mut cost, 64, 256, 1024);
            cost
        }
    }
}

fn apply_evidence_policy_delta(cost: &mut CostVector, policy: &EvidencePolicy) {
    let sampled_bytes = (policy.sampling_ratio.clamp(0.0, 1.0) * 128.0).round() as u64;
    add_evidence_bytes(
        cost,
        sampled_bytes / 2,
        sampled_bytes,
        sampled_bytes.saturating_mul(2),
    );
    if policy.record_control_transitions {
        cost.control_plane_amplification += 0.05;
    }
    if policy.record_counterfactual_branches {
        cost.storage_amplification += 0.15;
        add_restore_time(
            cost,
            Duration::from_millis(10),
            Duration::from_millis(50),
            Duration::from_millis(150),
        );
    }
}

fn add_cpu_cost(cost: &mut CostVector, typical_micros: u64, p99_micros: u64) {
    cost.cpu_crypto_cost = CpuEstimate::new(
        cost.cpu_crypto_cost
            .typical_micros
            .saturating_add(typical_micros),
        cost.cpu_crypto_cost.p99_micros.saturating_add(p99_micros),
    );
}

fn add_evidence_bytes(cost: &mut CostVector, min_bytes: u64, typical_bytes: u64, max_bytes: u64) {
    cost.evidence_bytes.min_bytes = cost.evidence_bytes.min_bytes.saturating_add(min_bytes);
    cost.evidence_bytes.typical_bytes = cost
        .evidence_bytes
        .typical_bytes
        .saturating_add(typical_bytes);
    cost.evidence_bytes.max_bytes = cost.evidence_bytes.max_bytes.saturating_add(max_bytes);
}

fn add_restore_time(cost: &mut CostVector, min: Duration, typical: Duration, max: Duration) {
    cost.restore_handoff_time = DurationEstimate::new(
        cost.restore_handoff_time.min.saturating_add(min),
        cost.restore_handoff_time.typical.saturating_add(typical),
        cost.restore_handoff_time.max.saturating_add(max),
    );
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.iter().any(|existing| existing == &value) {
        values.push(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messaging::class::AckKind;
    use crate::messaging::ir::{
        BranchPolicy, CapabilityTokenSchema, ConsumerPolicy, MorphismPlan, ProtocolContract,
        ReplySpaceRule, RetryLaw, ServiceOperation, SessionSchema,
    };

    fn retained_event_policy() -> EvidencePolicy {
        EvidencePolicy {
            retention: RetentionPolicy::RetainFor {
                duration: Duration::from_secs(60),
            },
            ..EvidencePolicy::default()
        }
    }

    fn valid_ir() -> FabricIr {
        FabricIr {
            subjects: vec![
                SubjectSchema {
                    pattern: SubjectPattern::new("tenant.orders.command"),
                    family: SubjectFamily::Command,
                    delivery_class: DeliveryClass::ObligationBacked,
                    evidence_policy: EvidencePolicy::default(),
                    privacy_policy: PrivacyPolicy::default(),
                    reply_space: Some(ReplySpaceRule::CallerInbox),
                    mobility: MobilityPermission::LocalOnly,
                    quantitative_obligation: None,
                },
                SubjectSchema {
                    pattern: SubjectPattern::new("tenant.orders.event"),
                    family: SubjectFamily::Event,
                    delivery_class: DeliveryClass::DurableOrdered,
                    evidence_policy: retained_event_policy(),
                    privacy_policy: PrivacyPolicy::default(),
                    reply_space: None,
                    mobility: MobilityPermission::Federated,
                    quantitative_obligation: None,
                },
                SubjectSchema {
                    pattern: SubjectPattern::new("tenant.orders.protocol.step"),
                    family: SubjectFamily::ProtocolStep,
                    delivery_class: DeliveryClass::DurableOrdered,
                    evidence_policy: retained_event_policy(),
                    privacy_policy: PrivacyPolicy::default(),
                    reply_space: None,
                    mobility: MobilityPermission::LocalOnly,
                    quantitative_obligation: None,
                },
                SubjectSchema {
                    pattern: SubjectPattern::new("tenant.orders.reply"),
                    family: SubjectFamily::Reply,
                    delivery_class: DeliveryClass::DurableOrdered,
                    evidence_policy: retained_event_policy(),
                    privacy_policy: PrivacyPolicy::default(),
                    reply_space: None,
                    mobility: MobilityPermission::LocalOnly,
                    quantitative_obligation: None,
                },
            ],
            morphisms: vec![MorphismPlan {
                name: "edge-export".to_owned(),
                source_pattern: SubjectPattern::new("tenant.orders.event"),
                target_prefix: "edge.orders".to_owned(),
                allowed_families: vec![SubjectFamily::Event],
                transforms: vec![MorphismTransform::RenamePrefix {
                    from: "tenant.orders".to_owned(),
                    to: "edge.orders".to_owned(),
                }],
            }],
            services: vec![ServiceContract {
                name: "orders.service".to_owned(),
                operations: vec![ServiceOperation {
                    name: "create".to_owned(),
                    request: SubjectPattern::new("tenant.orders.command"),
                    reply_space: Some(ReplySpaceRule::CallerInbox),
                    delivery_class: DeliveryClass::ObligationBacked,
                    idempotent: true,
                }],
                default_consumer_policy: ConsumerPolicy::default(),
                required_capability: Some("orders.request".to_owned()),
                quantitative_obligation: Some(QuantitativeObligationContract {
                    name: "orders.slo".to_owned(),
                    class: DeliveryClass::ObligationBacked,
                    target_latency: Duration::from_millis(25),
                    target_probability: 0.99,
                    retry_law: RetryLaw::default(),
                    degradation_policy: super::super::ir::DegradationPolicy::default(),
                }),
            }],
            protocols: vec![ProtocolContract {
                name: "orders.protocol".to_owned(),
                roles: vec!["caller".to_owned(), "service".to_owned()],
                entry_subject: SubjectPattern::new("tenant.orders.protocol.step"),
                session: SessionSchema {
                    name: "orders.session".to_owned(),
                    steps: vec![
                        SessionStep::Send {
                            role: "caller".to_owned(),
                            subject: SubjectPattern::new("tenant.orders.protocol.step"),
                        },
                        SessionStep::Receive {
                            role: "service".to_owned(),
                            subject: SubjectPattern::new("tenant.orders.reply"),
                        },
                        SessionStep::End,
                    ],
                },
                branch_policy: BranchPolicy::default(),
            }],
            consumers: vec![ConsumerPolicy {
                name: "orders.replay".to_owned(),
                mode: ConsumerMode::Replayable,
                delivery_class: DeliveryClass::DurableOrdered,
                ack_kind: AckKind::Recoverable,
                max_pending: 256,
                max_deliver: 2,
                replay_window: Some(Duration::from_secs(30)),
            }],
            capability_tokens: vec![CapabilityTokenSchema {
                name: "orders.request".to_owned(),
                families: vec![SubjectFamily::Command],
                delivery_classes: vec![DeliveryClass::ObligationBacked],
                permissions: vec![CapabilityPermission::Request],
            }],
            ..FabricIr::default()
        }
    }

    #[test]
    fn compiler_rejects_invalid_ir_before_estimating_costs() {
        let ir = FabricIr {
            schema_version: 999,
            ..FabricIr::default()
        };

        let err = FabricCompiler::compile(&ir).expect_err("invalid schema version should fail");
        match err {
            FabricCompilerError::Validation { errors_len, errors } => {
                assert_eq!(errors_len, errors.len());
                assert!(!errors.is_empty());
            }
        }
    }

    #[test]
    fn compiler_emits_artifacts_warnings_and_aggregate_envelope() {
        let report = FabricCompiler::compile(&valid_ir()).expect("valid fabric ir should compile");
        assert_eq!(report.subject_costs.len(), 4);
        assert!(report.warnings.is_empty());
        assert!(report.errors.is_empty());
        assert_eq!(
            report
                .subject_costs
                .iter()
                .map(|subject| subject.pattern.as_str())
                .collect::<Vec<_>>(),
            vec![
                "tenant.orders.command",
                "tenant.orders.event",
                "tenant.orders.protocol.step",
                "tenant.orders.reply",
            ]
        );
        assert!(
            report
                .artifacts
                .iter()
                .any(|artifact| artifact.kind == CompiledArtifactKind::Morphism
                    && artifact.name == "edge-export")
        );
        assert!(
            report
                .artifacts
                .iter()
                .any(|artifact| artifact.kind == CompiledArtifactKind::Service
                    && artifact.name == "orders.service")
        );
        assert!(
            report
                .aggregate_cost
                .more_expensive_on_any_dimension(&CostVector::zero())
        );
    }

    #[test]
    fn compiler_rejects_required_capability_without_request_permission() {
        let mut ir = valid_ir();
        ir.capability_tokens[0].permissions = vec![CapabilityPermission::Publish];

        let err = FabricCompiler::compile(&ir).expect_err("invalid capability should fail");
        let FabricCompilerError::Validation { errors, .. } = err;
        assert!(
            errors
                .iter()
                .any(|error| error.field == "services[0].required_capability"
                    && error.message.contains("request permission")),
            "expected request-permission error, got {errors:?}"
        );
    }

    #[test]
    fn compiler_rejects_irreversible_morphism_for_reply_space_subjects() {
        let mut ir = valid_ir();
        ir.morphisms[0] = MorphismPlan {
            name: "command-rewrite".to_owned(),
            source_pattern: SubjectPattern::new("tenant.orders.command"),
            target_prefix: "edge.orders".to_owned(),
            allowed_families: vec![SubjectFamily::Command],
            transforms: vec![MorphismTransform::FilterFamily {
                family: SubjectFamily::Command,
            }],
        };

        let err = FabricCompiler::compile(&ir).expect_err("irreversible morphism should fail");
        let FabricCompilerError::Validation { errors, .. } = err;
        assert!(
            errors
                .iter()
                .any(|error| error.field == "morphisms[0].transforms"
                    && error.message.contains("structurally reversible")),
            "expected reversibility error, got {errors:?}"
        );
    }

    #[test]
    fn compiler_rejects_forensic_subject_without_retained_evidence() {
        let mut ir = valid_ir();
        ir.subjects[0].delivery_class = DeliveryClass::ForensicReplayable;

        let err = FabricCompiler::compile(&ir).expect_err("forensic subject should fail");
        let FabricCompilerError::Validation { errors, .. } = err;
        assert!(
            errors.iter().any(
                |error| error.field == "subjects[0].evidence_policy.retention"
                    && error.message.contains("retain evidence")
            ),
            "expected replay-retention error, got {errors:?}"
        );
    }

    #[test]
    fn compiler_warns_when_redaction_omits_literal_scrubbing() {
        let mut ir = valid_ir();
        ir.subjects[1].privacy_policy = PrivacyPolicy {
            name: "redacted".to_owned(),
            metadata_disclosure: MetadataDisclosure::Redacted,
            redact_subject_literals: false,
            noise_budget: None,
            allow_cross_tenant_flow: false,
        };

        let report = FabricCompiler::compile(&ir).expect("warning-only IR should compile");
        assert!(
            report.warnings.iter().any(
                |warning| warning.field == "subjects[1].privacy_policy.redact_subject_literals"
            ),
            "expected redaction warning, got {:?}",
            report.warnings
        );
    }
}
