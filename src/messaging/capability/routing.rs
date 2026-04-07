//! Capability-checked routing programs for FABRIC subject operations.

use super::{FabricCapability, FabricCapabilityGrant, FabricCapabilityId, GrantedFabricToken};
use crate::cx::Cx;
use crate::messaging::ir::{MorphismPlan, MorphismTransform, SubjectFamily};
use crate::messaging::subject::{Subject, SubjectPattern, SubjectPatternError, SubjectToken};
use std::fmt;
use thiserror::Error;

/// Direction for a compiled routing program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum RoutingDirection {
    /// Route traffic into the local authority boundary.
    Import,
    /// Route traffic out of the local authority boundary.
    #[default]
    Export,
}

impl fmt::Display for RoutingDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Import => "import",
            Self::Export => "export",
        };
        write!(f, "{name}")
    }
}

/// Subject operation enforced by a routing program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum RoutingOperationKind {
    /// Publish a concrete subject.
    #[default]
    Publish,
    /// Subscribe to a subject pattern.
    Subscribe,
    /// Create a stream rooted in a subject space.
    CreateStream,
    /// Transform a subject space through a morphism boundary.
    TransformSpace,
}

impl RoutingOperationKind {
    fn capability_for(self, subject: SubjectPattern) -> FabricCapability {
        match self {
            Self::Publish => FabricCapability::Publish { subject },
            Self::Subscribe => FabricCapability::Subscribe { subject },
            Self::CreateStream => FabricCapability::CreateStream { subject },
            Self::TransformSpace => FabricCapability::TransformSpace { subject },
        }
    }
}

impl fmt::Display for RoutingOperationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Publish => "publish",
            Self::Subscribe => "subscribe",
            Self::CreateStream => "create_stream",
            Self::TransformSpace => "transform_space",
        };
        write!(f, "{name}")
    }
}

/// Concrete request routed through a [`RoutingProgram`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingRequest {
    /// Publish a concrete subject.
    Publish(Subject),
    /// Subscribe to a subject pattern.
    Subscribe(SubjectPattern),
    /// Create a stream rooted in a subject space.
    CreateStream(SubjectPattern),
    /// Rewrite or delegate a subject space.
    TransformSpace(SubjectPattern),
}

impl RoutingRequest {
    /// Return the operation kind represented by this request.
    #[must_use]
    pub const fn operation(&self) -> RoutingOperationKind {
        match self {
            Self::Publish(_) => RoutingOperationKind::Publish,
            Self::Subscribe(_) => RoutingOperationKind::Subscribe,
            Self::CreateStream(_) => RoutingOperationKind::CreateStream,
            Self::TransformSpace(_) => RoutingOperationKind::TransformSpace,
        }
    }

    /// Return the requested subject space as a pattern.
    #[must_use]
    pub fn subject_pattern(&self) -> SubjectPattern {
        match self {
            Self::Publish(subject) => SubjectPattern::from(subject),
            Self::Subscribe(pattern)
            | Self::CreateStream(pattern)
            | Self::TransformSpace(pattern) => pattern.clone(),
        }
    }

    fn required_capability(&self) -> FabricCapability {
        self.operation().capability_for(self.subject_pattern())
    }
}

/// Statically compiled step in a routing program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RoutingProgramStep {
    /// Match the incoming subject against the program source pattern.
    MatchSourcePattern,
    /// Check that the route family is admitted by the program.
    CheckAllowedFamily,
    /// Enforce the required FABRIC capability for the subject operation.
    CheckCapability,
    /// Rewrite the destination prefix deterministically.
    RewriteTargetPrefix,
    /// Emit audit evidence for the final route choice.
    EmitAudit,
}

impl fmt::Display for RoutingProgramStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::MatchSourcePattern => "match_source_pattern",
            Self::CheckAllowedFamily => "check_allowed_family",
            Self::CheckCapability => "check_capability",
            Self::RewriteTargetPrefix => "rewrite_target_prefix",
            Self::EmitAudit => "emit_audit",
        };
        write!(f, "{name}")
    }
}

/// Compiled capability-checked routing program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingProgram {
    name: String,
    direction: RoutingDirection,
    operation: RoutingOperationKind,
    source_pattern: SubjectPattern,
    target_prefix: SubjectPattern,
    allowed_families: Vec<SubjectFamily>,
    steps: Vec<RoutingProgramStep>,
}

impl RoutingProgram {
    /// Compile an import-side routing program from a morphism plan.
    pub fn compile_import(
        plan: &MorphismPlan,
        operation: RoutingOperationKind,
    ) -> Result<Self, RoutingProgramCompileError> {
        Self::compile(plan, RoutingDirection::Import, operation)
    }

    /// Compile an export-side routing program from a morphism plan.
    pub fn compile_export(
        plan: &MorphismPlan,
        operation: RoutingOperationKind,
    ) -> Result<Self, RoutingProgramCompileError> {
        Self::compile(plan, RoutingDirection::Export, operation)
    }

    fn compile(
        plan: &MorphismPlan,
        direction: RoutingDirection,
        operation: RoutingOperationKind,
    ) -> Result<Self, RoutingProgramCompileError> {
        let target_prefix_raw = effective_target_prefix(plan);
        let target_prefix = SubjectPattern::parse(&target_prefix_raw).map_err(|source| {
            RoutingProgramCompileError::InvalidTargetPrefix {
                prefix: target_prefix_raw.clone(),
                source,
            }
        })?;
        ensure_literal_only_prefix(&target_prefix).map_err(|source| {
            RoutingProgramCompileError::NonLiteralTargetPrefix {
                prefix: target_prefix_raw.clone(),
                source,
            }
        })?;

        let allowed_families = effective_allowed_families(plan);
        if allowed_families.is_empty() {
            return Err(RoutingProgramCompileError::NoAllowedFamilies {
                program: plan.name.clone(),
            });
        }
        let source_pattern =
            SubjectPattern::parse(plan.source_pattern.as_str()).expect("validated morphism plan");
        ensure_literal_source_anchor(&source_pattern).map_err(|()| {
            RoutingProgramCompileError::NonLiteralSourcePatternAnchor {
                pattern: source_pattern.as_str().to_owned(),
            }
        })?;

        Ok(Self {
            name: plan.name.clone(),
            direction,
            operation,
            source_pattern,
            target_prefix,
            allowed_families,
            steps: vec![
                RoutingProgramStep::MatchSourcePattern,
                RoutingProgramStep::CheckAllowedFamily,
                RoutingProgramStep::CheckCapability,
                RoutingProgramStep::RewriteTargetPrefix,
                RoutingProgramStep::EmitAudit,
            ],
        })
    }

    /// Return the program name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return the compiled route direction.
    #[must_use]
    pub const fn direction(&self) -> RoutingDirection {
        self.direction
    }

    /// Return the operation protected by this program.
    #[must_use]
    pub const fn operation(&self) -> RoutingOperationKind {
        self.operation
    }

    /// Return the admitted semantic families.
    #[must_use]
    pub fn allowed_families(&self) -> &[SubjectFamily] {
        &self.allowed_families
    }

    /// Return the source subject pattern covered by this program.
    #[must_use]
    pub fn source_pattern(&self) -> &SubjectPattern {
        &self.source_pattern
    }

    /// Return the literal target prefix applied by this program.
    #[must_use]
    pub fn target_prefix(&self) -> &SubjectPattern {
        &self.target_prefix
    }

    /// Return the compiled execution steps.
    #[must_use]
    pub fn steps(&self) -> &[RoutingProgramStep] {
        &self.steps
    }

    /// Execute the program against an in-process token.
    pub fn authorize_in_process<T>(
        &self,
        token: &GrantedFabricToken<T>,
        family: SubjectFamily,
        request: &RoutingRequest,
    ) -> Result<AuthorizedRoute, CapabilityRoutingError> {
        self.authorize_inner(family, request, |required| {
            token.grant().capability().allows(required)
        })
        .map(|route| {
            route.with_authorization(RoutingAuthorization::InProcess {
                grant_id: token.grant_id(),
            })
        })
    }

    /// Execute the program against an already-minted in-process grant.
    pub fn authorize_with_grant(
        &self,
        grant: &FabricCapabilityGrant,
        family: SubjectFamily,
        request: &RoutingRequest,
    ) -> Result<AuthorizedRoute, CapabilityRoutingError> {
        self.authorize_inner(family, request, |required| {
            grant.capability().allows(required)
        })
        .map(|route| {
            route.with_authorization(RoutingAuthorization::InProcess {
                grant_id: grant.id(),
            })
        })
    }

    /// Execute the program against a distributed-path [`Cx`] runtime grant set.
    pub fn authorize_distributed<Caps>(
        &self,
        cx: &Cx<Caps>,
        family: SubjectFamily,
        request: &RoutingRequest,
    ) -> Result<AuthorizedRoute, CapabilityRoutingError> {
        self.authorize_inner(family, request, |required| {
            cx.check_fabric_capability(required)
        })
        .map(|route| route.with_authorization(RoutingAuthorization::Distributed))
    }

    fn authorize_inner(
        &self,
        family: SubjectFamily,
        request: &RoutingRequest,
        allows: impl Fn(&FabricCapability) -> bool,
    ) -> Result<AuthorizedRoute, CapabilityRoutingError> {
        if request.operation() != self.operation {
            return Err(CapabilityRoutingError::OperationMismatch {
                program: self.name.clone(),
                expected: self.operation,
                actual: request.operation(),
            });
        }
        if !self.allowed_families.contains(&family) {
            return Err(CapabilityRoutingError::UnsupportedFamily {
                program: self.name.clone(),
                family,
            });
        }

        let required = request.required_capability();
        let admitted = self.operation.capability_for(self.source_pattern.clone());
        if !admitted.allows(&required) {
            return Err(CapabilityRoutingError::SubjectOutsideProgram {
                program: self.name.clone(),
                source_pattern: self.source_pattern.as_str().to_owned(),
                requested: request.subject_pattern().as_str().to_owned(),
            });
        }
        if !allows(&required) {
            return Err(CapabilityRoutingError::CapabilityDenied {
                program: self.name.clone(),
                required,
            });
        }

        let source = request.subject_pattern();
        let destination = rewrite_destination(&source, &self.source_pattern, &self.target_prefix);

        Ok(AuthorizedRoute {
            destination,
            audit: RoutingAuditTrail {
                program: self.name.clone(),
                direction: self.direction,
                family,
                authorized_capability: request.required_capability(),
                authorization: None,
                steps: self.steps.clone(),
            },
        })
    }
}

/// Successful route authorization plus deterministic audit data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedRoute {
    destination: SubjectPattern,
    audit: RoutingAuditTrail,
}

impl AuthorizedRoute {
    #[must_use]
    fn with_authorization(mut self, authorization: RoutingAuthorization) -> Self {
        self.audit.authorization = Some(authorization);
        self
    }

    /// Return the rewritten route destination.
    #[must_use]
    pub fn destination(&self) -> &SubjectPattern {
        &self.destination
    }

    /// Return the audit trail for this route decision.
    #[must_use]
    pub fn audit(&self) -> &RoutingAuditTrail {
        &self.audit
    }
}

/// Authorization source recorded in a route audit trail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingAuthorization {
    /// Authorization came from an in-process linear capability token/grant.
    InProcess {
        /// Stable identifier for the backing runtime grant.
        grant_id: FabricCapabilityId,
    },
    /// Authorization came from a distributed runtime capability check in `Cx`.
    Distributed,
}

impl RoutingAuthorization {
    /// Return the backing grant id when authorization came from an in-process token.
    #[must_use]
    pub const fn grant_id(&self) -> Option<FabricCapabilityId> {
        match self {
            Self::InProcess { grant_id } => Some(*grant_id),
            Self::Distributed => None,
        }
    }
}

/// Audit trail for one routing decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingAuditTrail {
    program: String,
    direction: RoutingDirection,
    family: SubjectFamily,
    authorized_capability: FabricCapability,
    authorization: Option<RoutingAuthorization>,
    steps: Vec<RoutingProgramStep>,
}

impl RoutingAuditTrail {
    /// Return the program that emitted this audit record.
    #[must_use]
    pub fn program(&self) -> &str {
        &self.program
    }

    /// Return the route direction.
    #[must_use]
    pub const fn direction(&self) -> RoutingDirection {
        self.direction
    }

    /// Return the semantic family attached to the routed subject.
    #[must_use]
    pub const fn family(&self) -> SubjectFamily {
        self.family
    }

    /// Return the capability that authorized the route.
    #[must_use]
    pub fn authorized_capability(&self) -> &FabricCapability {
        &self.authorized_capability
    }

    /// Return the authorization source, if routing completed successfully.
    #[must_use]
    pub fn authorization(&self) -> Option<&RoutingAuthorization> {
        self.authorization.as_ref()
    }

    /// Return the compiled steps that were executed for this route.
    #[must_use]
    pub fn steps(&self) -> &[RoutingProgramStep] {
        &self.steps
    }
}

/// Compile-time failures while building a routing program.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RoutingProgramCompileError {
    /// The target prefix could not be parsed as a subject pattern.
    #[error("routing program target prefix `{prefix}` is invalid")]
    InvalidTargetPrefix {
        /// Raw target prefix from the plan.
        prefix: String,
        /// Underlying parse failure.
        source: SubjectPatternError,
    },
    /// Routing rewrites require a literal-only target prefix.
    #[error("routing program target prefix `{prefix}` must contain only literal segments")]
    NonLiteralTargetPrefix {
        /// Raw target prefix from the plan.
        prefix: String,
        /// Underlying literal-only validation failure.
        source: SubjectPatternError,
    },
    /// Family filters left the program with no admissible subject families.
    #[error("routing program `{program}` must admit at least one subject family")]
    NoAllowedFamilies {
        /// Program name from the plan.
        program: String,
    },
    /// Prefix rewrites require a source pattern with a literal anchor.
    #[error("routing program source pattern `{pattern}` must start with a literal segment")]
    NonLiteralSourcePatternAnchor {
        /// Source pattern compiled into the program.
        pattern: String,
    },
}

/// Runtime failures while authorizing a route.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CapabilityRoutingError {
    /// The request operation did not match the compiled program.
    #[error("routing program `{program}` expects `{expected}` operations but received `{actual}`")]
    OperationMismatch {
        /// Program name.
        program: String,
        /// Compiled operation kind.
        expected: RoutingOperationKind,
        /// Request operation kind.
        actual: RoutingOperationKind,
    },
    /// The request family is not admitted by the compiled plan.
    #[error("routing program `{program}` does not admit subject family `{family:?}`")]
    UnsupportedFamily {
        /// Program name.
        program: String,
        /// Rejected semantic family.
        family: SubjectFamily,
    },
    /// The request subject escaped the program's source envelope.
    #[error(
        "routing program `{program}` only covers source pattern `{source_pattern}`, but received `{requested}`"
    )]
    SubjectOutsideProgram {
        /// Program name.
        program: String,
        /// Source pattern compiled into the program.
        source_pattern: String,
        /// Requested subject or subject pattern.
        requested: String,
    },
    /// The caller lacks the required capability for the routed operation.
    #[error("routing program `{program}` denied missing capability `{required}`")]
    CapabilityDenied {
        /// Program name.
        program: String,
        /// Capability required by the routed operation.
        required: FabricCapability,
    },
}

fn effective_allowed_families(plan: &MorphismPlan) -> Vec<SubjectFamily> {
    let mut allowed = Vec::new();
    for family in plan.allowed_families.iter().copied() {
        if !allowed.contains(&family) {
            allowed.push(family);
        }
    }
    for transform in &plan.transforms {
        if let MorphismTransform::FilterFamily { family } = transform {
            allowed.retain(|candidate| candidate == family);
        }
    }
    allowed
}

fn effective_target_prefix(plan: &MorphismPlan) -> String {
    plan.transforms
        .iter()
        .rev()
        .find_map(|transform| match transform {
            MorphismTransform::RenamePrefix { to, .. } => Some(to.clone()),
            MorphismTransform::FilterFamily { .. }
            | MorphismTransform::EscalateDeliveryClass { .. }
            | MorphismTransform::PreserveReplySpace
            | MorphismTransform::AttachEvidencePolicy { .. } => None,
        })
        .unwrap_or_else(|| plan.target_prefix.clone())
}

fn ensure_literal_only_prefix(pattern: &SubjectPattern) -> Result<(), SubjectPatternError> {
    for segment in pattern.segments() {
        match segment {
            SubjectToken::Literal(_) => {}
            SubjectToken::One | SubjectToken::Tail => {
                return Err(SubjectPatternError::LiteralOnlyPatternRequired(
                    pattern.as_str().to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn ensure_literal_source_anchor(pattern: &SubjectPattern) -> Result<(), ()> {
    match pattern.segments().first() {
        Some(SubjectToken::Literal(_)) => Ok(()),
        Some(SubjectToken::One | SubjectToken::Tail) | None => Err(()),
    }
}

fn leading_literal_prefix(pattern: &SubjectPattern) -> Vec<String> {
    let mut prefix = Vec::new();
    for segment in pattern.segments() {
        match segment {
            SubjectToken::Literal(value) => prefix.push(value.clone()),
            SubjectToken::One | SubjectToken::Tail => break,
        }
    }
    prefix
}

fn literal_target_tokens(pattern: &SubjectPattern) -> Vec<SubjectToken> {
    pattern
        .segments()
        .iter()
        .map(|segment| match segment {
            SubjectToken::Literal(value) => SubjectToken::Literal(value.clone()),
            SubjectToken::One | SubjectToken::Tail => {
                unreachable!("target prefix is validated as literal-only during compilation")
            }
        })
        .collect()
}

fn rewrite_destination(
    source: &SubjectPattern,
    source_pattern: &SubjectPattern,
    target_prefix: &SubjectPattern,
) -> SubjectPattern {
    let literal_prefix = leading_literal_prefix(source_pattern);
    let literal_prefix_len = literal_prefix.len();

    let remainder = source
        .segments()
        .iter()
        .skip(literal_prefix_len)
        .cloned()
        .collect::<Vec<_>>();

    let mut destination = literal_target_tokens(target_prefix);
    destination.extend(remainder);
    SubjectPattern::from_tokens(destination)
        .expect("rewritten routing destination must remain syntactically valid")
}

#[cfg(test)]
mod tests {
    use super::super::{EventFamily, PublishPermit};
    use super::*;
    use crate::Budget;
    use crate::messaging::class::DeliveryClass;
    use crate::messaging::ir::{
        CapabilityPermission, CapabilityTokenSchema, MorphismPlan, MorphismTransform,
        SubjectFamily, SubjectPattern as IrSubjectPattern,
    };
    use crate::types::{RegionId, TaskId};
    use crate::util::ArenaIndex;

    fn test_cx() -> Cx {
        Cx::new(
            RegionId::from_arena(ArenaIndex::new(0, 0)),
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            Budget::INFINITE,
        )
    }

    fn publish_schema() -> CapabilityTokenSchema {
        CapabilityTokenSchema {
            name: "fabric.route.publish".to_owned(),
            families: vec![SubjectFamily::Event],
            delivery_classes: vec![DeliveryClass::EphemeralInteractive],
            permissions: vec![CapabilityPermission::Publish],
        }
    }

    fn export_plan() -> MorphismPlan {
        MorphismPlan {
            name: "orders-export".to_owned(),
            source_pattern: IrSubjectPattern::new("orders.>"),
            target_prefix: "federated.orders".to_owned(),
            allowed_families: vec![SubjectFamily::Event, SubjectFamily::Command],
            transforms: vec![
                MorphismTransform::FilterFamily {
                    family: SubjectFamily::Event,
                },
                MorphismTransform::PreserveReplySpace,
            ],
        }
    }

    #[test]
    fn compile_export_program_rejects_non_literal_target_prefix() {
        let mut plan = export_plan();
        plan.target_prefix = "federated.>".to_owned();

        let error = RoutingProgram::compile_export(&plan, RoutingOperationKind::Publish)
            .expect_err("wildcard target prefixes must fail closed");

        assert_eq!(
            error,
            RoutingProgramCompileError::NonLiteralTargetPrefix {
                prefix: "federated.>".to_owned(),
                source: SubjectPatternError::LiteralOnlyPatternRequired("federated.>".to_owned()),
            }
        );
    }

    #[test]
    fn compile_export_program_rejects_source_pattern_without_literal_anchor() {
        let mut plan = export_plan();
        plan.source_pattern = IrSubjectPattern::new("*.orders.created");

        let error = RoutingProgram::compile_export(&plan, RoutingOperationKind::Publish)
            .expect_err("wildcard-leading source patterns must fail closed");

        assert_eq!(
            error,
            RoutingProgramCompileError::NonLiteralSourcePatternAnchor {
                pattern: "*.orders.created".to_owned(),
            }
        );
    }

    #[test]
    fn distributed_publish_route_requires_capability_and_records_audit() {
        let program = RoutingProgram::compile_export(&export_plan(), RoutingOperationKind::Publish)
            .expect("routing program");
        let cx = test_cx();
        cx.grant_fabric_capability(FabricCapability::Publish {
            subject: SubjectPattern::new("orders.created"),
        })
        .expect("publish grant");

        let route = program
            .authorize_distributed(
                &cx,
                SubjectFamily::Event,
                &RoutingRequest::Publish(Subject::new("orders.created")),
            )
            .expect("distributed route should pass");

        assert_eq!(route.destination().as_str(), "federated.orders.created");
        assert_eq!(route.audit().program(), "orders-export");
        assert_eq!(route.audit().direction(), RoutingDirection::Export);
        assert_eq!(route.audit().family(), SubjectFamily::Event);
        assert_eq!(
            route.audit().authorized_capability(),
            &FabricCapability::Publish {
                subject: SubjectPattern::new("orders.created"),
            }
        );
        assert_eq!(
            route.audit().authorization(),
            Some(&RoutingAuthorization::Distributed)
        );
        assert_eq!(route.audit().steps(), program.steps());
    }

    #[test]
    fn distributed_publish_route_denies_missing_capability() {
        let program = RoutingProgram::compile_export(&export_plan(), RoutingOperationKind::Publish)
            .expect("routing program");
        let cx = test_cx();

        let error = program
            .authorize_distributed(
                &cx,
                SubjectFamily::Event,
                &RoutingRequest::Publish(Subject::new("orders.created")),
            )
            .expect_err("missing capability must fail closed");

        assert_eq!(
            error,
            CapabilityRoutingError::CapabilityDenied {
                program: "orders-export".to_owned(),
                required: FabricCapability::Publish {
                    subject: SubjectPattern::new("orders.created"),
                },
            }
        );
    }

    #[test]
    fn distributed_publish_route_rejects_bare_prefix_for_tail_program() {
        let program = RoutingProgram::compile_export(&export_plan(), RoutingOperationKind::Publish)
            .expect("routing program");
        let cx = test_cx();
        cx.grant_fabric_capability(FabricCapability::Publish {
            subject: SubjectPattern::new("orders.>"),
        })
        .expect("publish grant");

        let error = program
            .authorize_distributed(
                &cx,
                SubjectFamily::Event,
                &RoutingRequest::Publish(Subject::new("orders")),
            )
            .expect_err("bare prefix must be outside the tail-wildcard program");

        assert_eq!(
            error,
            CapabilityRoutingError::SubjectOutsideProgram {
                program: "orders-export".to_owned(),
                source_pattern: "orders.>".to_owned(),
                requested: "orders".to_owned(),
            }
        );
    }

    #[test]
    fn in_process_and_distributed_publish_routes_are_equivalent() {
        let program = RoutingProgram::compile_export(&export_plan(), RoutingOperationKind::Publish)
            .expect("routing program");
        let cx = test_cx();
        let token: GrantedFabricToken<PublishPermit<EventFamily>> = cx
            .grant_publish_capability::<EventFamily>(
                SubjectPattern::new("orders.>"),
                &publish_schema(),
                DeliveryClass::EphemeralInteractive,
            )
            .expect("publish token");
        let request = RoutingRequest::Publish(Subject::new("orders.shipped.eu"));

        let in_process = program
            .authorize_in_process(&token, SubjectFamily::Event, &request)
            .expect("in-process route");
        let distributed = program
            .authorize_distributed(&cx, SubjectFamily::Event, &request)
            .expect("distributed route");

        assert_eq!(in_process.destination(), distributed.destination());
        assert_eq!(
            in_process.audit().authorized_capability(),
            distributed.audit().authorized_capability()
        );
        assert_eq!(in_process.audit().family(), distributed.audit().family());
        assert_eq!(
            in_process.audit().authorization(),
            Some(&RoutingAuthorization::InProcess {
                grant_id: token.grant_id(),
            })
        );
        assert_eq!(
            distributed.audit().authorization(),
            Some(&RoutingAuthorization::Distributed)
        );
    }

    #[test]
    fn family_filters_fail_closed_before_routing() {
        let program = RoutingProgram::compile_export(&export_plan(), RoutingOperationKind::Publish)
            .expect("routing program");
        let cx = test_cx();
        cx.grant_fabric_capability(FabricCapability::Publish {
            subject: SubjectPattern::new("orders.created"),
        })
        .expect("publish grant");

        let error = program
            .authorize_distributed(
                &cx,
                SubjectFamily::Command,
                &RoutingRequest::Publish(Subject::new("orders.created")),
            )
            .expect_err("filtered-out families must fail");

        assert_eq!(
            error,
            CapabilityRoutingError::UnsupportedFamily {
                program: "orders-export".to_owned(),
                family: SubjectFamily::Command,
            }
        );
    }
}
