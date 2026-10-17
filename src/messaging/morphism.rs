//! Typed namespace morphisms and facet-checked certificates for FABRIC.
//!
//! This module keeps the morphism surface finite and inspectable. A morphism
//! declares how one subject language lowers into another, what authority it
//! carries, whether the rewrite is reversible, what privacy and sharing rules
//! apply, and what quota envelope bounds the handoff.

use super::ir::{EvidencePolicy, MetadataDisclosure, PrivacyPolicy, ReplySpaceRule};
use super::subject::SubjectPattern;
use crate::util::DetHasher;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::hash::Hasher;
use std::time::Duration;
use thiserror::Error;

/// Classification for a subject-language morphism.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
#[serde(rename_all = "snake_case")]
pub enum MorphismClass {
    /// Reversible, reply-authoritative, capability-bearing rewrites.
    Authoritative,
    /// Redacting or summarizing rewrites that must not originate authority.
    #[default]
    DerivedView,
    /// One-way export into a weaker trust or replay domain.
    Egress,
    /// Temporary sub-language delegation with bounded duration and revocation.
    Delegation,
}

impl MorphismClass {
    /// Exhaustive morphism-class taxonomy.
    pub const ALL: [Self; 4] = [
        Self::Authoritative,
        Self::DerivedView,
        Self::Egress,
        Self::Delegation,
    ];
}

/// Capability required to install or execute a morphism.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum FabricCapability {
    /// Rewrite or normalize a subject namespace.
    #[default]
    RewriteNamespace,
    /// Move authority across a morphism boundary.
    CarryAuthority,
    /// Rebind replies as authoritative responses.
    ReplyAuthority,
    /// Attach or inspect evidence produced by the morphism.
    ObserveEvidence,
    /// Delegate a bounded sub-language to another actor or steward.
    DelegateNamespace,
    /// Export traffic into a weaker or cross-boundary domain.
    CrossBoundaryEgress,
}

impl FabricCapability {
    /// Exhaustive capability taxonomy for the morphism surface.
    pub const ALL: [Self; 6] = [
        Self::RewriteNamespace,
        Self::CarryAuthority,
        Self::ReplyAuthority,
        Self::ObserveEvidence,
        Self::DelegateNamespace,
        Self::CrossBoundaryEgress,
    ];

    /// Return true when the capability moves or rebinds authority.
    #[must_use]
    pub const fn is_authority_bearing(self) -> bool {
        matches!(
            self,
            Self::CarryAuthority | Self::ReplyAuthority | Self::DelegateNamespace
        )
    }
}

/// Reversibility promise attached to a morphism.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ReversibilityRequirement {
    /// The rewrite is explainable through retained evidence but not bijective.
    #[default]
    EvidenceBacked,
    /// The rewrite is structurally reversible without lossy steps.
    Bijective,
    /// The rewrite is intentionally one-way and may discard information.
    Irreversible,
}

/// Sharing boundary for traffic after the morphism applies.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum SharingPolicy {
    /// Keep the rewritten traffic inside the local authority boundary.
    #[default]
    Private,
    /// Share only within a tenant-scoped boundary.
    TenantScoped,
    /// Share across a federated but still policy-bound domain.
    Federated,
    /// Allow public read access to the rewritten output.
    PublicRead,
}

/// Reply-handling rule for the rewritten namespace.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ResponsePolicy {
    /// Preserve caller-managed reply semantics.
    #[default]
    PreserveCallerReplies,
    /// Rebind replies as authoritative responses from the morphism destination.
    ReplyAuthoritative,
    /// Forward replies opaquely without rebinding authority.
    ForwardOpaque,
    /// Strip reply semantics entirely.
    StripReplies,
}

/// Finite transform vocabulary for typed namespace rewrites.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SubjectTransform {
    /// Leave the subject language unchanged.
    #[default]
    Identity,
    /// Rename one namespace prefix to another.
    RenamePrefix {
        /// Source prefix to rewrite.
        from: SubjectPattern,
        /// Target prefix after rewriting.
        to: SubjectPattern,
    },
    /// Redact literal subject segments while preserving shape.
    RedactLiterals,
    /// Collapse the tail of a subject after keeping the leading prefix.
    SummarizeTail {
        /// Number of leading segments that remain visible.
        preserve_segments: usize,
    },
    /// Hash-partition the rewritten stream into a bounded number of buckets.
    HashPartition {
        /// Number of output buckets.
        buckets: u16,
    },
    /// Capture a single wildcard expansion by its 1-based index.
    WildcardCapture {
        /// 1-based wildcard/capture index.
        index: usize,
    },
    /// Deterministically hash one or more captured tokens into a bucket.
    DeterministicHash {
        /// Number of output buckets.
        buckets: u16,
        /// 1-based token indices used as the hash key. Empty means all tokens.
        source_indices: Vec<usize>,
    },
    /// Split a captured token and keep a bounded slice of the resulting pieces.
    SplitSlice {
        /// 1-based token index to split.
        index: usize,
        /// Delimiter used to split the selected token.
        delimiter: String,
        /// Zero-based starting piece after splitting.
        start: usize,
        /// Number of split pieces to keep.
        len: usize,
    },
    /// Keep the left-most characters from a captured token.
    LeftExtract {
        /// 1-based token index to project.
        index: usize,
        /// Number of characters to keep from the left.
        len: usize,
    },
    /// Keep the right-most characters from a captured token.
    RightExtract {
        /// 1-based token index to project.
        index: usize,
        /// Number of characters to keep from the right.
        len: usize,
    },
    /// Compose a finite sequence of transforms into a deterministic pipeline.
    Compose {
        /// Ordered transform pipeline.
        steps: Vec<Self>,
    },
}

impl SubjectTransform {
    /// Return true when the transform intentionally discards information.
    #[must_use]
    pub fn is_lossy(&self) -> bool {
        match self {
            Self::Identity | Self::RenamePrefix { .. } => false,
            Self::Compose { steps } => steps.iter().any(Self::is_lossy),
            Self::RedactLiterals
            | Self::SummarizeTail { .. }
            | Self::HashPartition { .. }
            | Self::WildcardCapture { .. }
            | Self::DeterministicHash { .. }
            | Self::SplitSlice { .. }
            | Self::LeftExtract { .. }
            | Self::RightExtract { .. } => true,
        }
    }

    /// Return true when the transform admits a structural inverse.
    #[must_use]
    pub fn is_invertible(&self) -> bool {
        self.inverse().is_some()
    }

    /// Return the structural inverse when the transform is bijective.
    #[must_use]
    pub fn inverse(&self) -> Option<Self> {
        match self {
            Self::Identity => Some(Self::Identity),
            Self::RenamePrefix { from, to } => Some(Self::RenamePrefix {
                from: to.clone(),
                to: from.clone(),
            }),
            Self::Compose { steps } => {
                let mut inverse_steps = Vec::with_capacity(steps.len());
                for step in steps.iter().rev() {
                    inverse_steps.push(step.inverse()?);
                }
                Some(Self::Compose {
                    steps: inverse_steps,
                })
            }
            Self::RedactLiterals
            | Self::SummarizeTail { .. }
            | Self::HashPartition { .. }
            | Self::WildcardCapture { .. }
            | Self::DeterministicHash { .. }
            | Self::SplitSlice { .. }
            | Self::LeftExtract { .. }
            | Self::RightExtract { .. } => None,
        }
    }

    /// Apply the transform deterministically to a token vector.
    ///
    /// Higher layers can feed this with wildcard captures or a tokenized
    /// concrete subject depending on which facet they are evaluating.
    pub fn apply_tokens(&self, tokens: &[String]) -> Result<Vec<String>, MorphismEvaluationError> {
        match self {
            Self::Identity => Ok(tokens.to_vec()),
            Self::RenamePrefix { from, to } => {
                let from_literals = literal_only_segments(from)?;
                let to_literals = literal_only_segments(to)?;
                if tokens.starts_with(&from_literals) {
                    let mut rewritten = to_literals;
                    rewritten.extend_from_slice(&tokens[from_literals.len()..]);
                    Ok(rewritten)
                } else {
                    Ok(tokens.to_vec())
                }
            }
            Self::RedactLiterals => Ok(tokens.iter().map(|_| String::from("_")).collect()),
            Self::SummarizeTail { preserve_segments } => {
                if tokens.len() <= *preserve_segments {
                    return Ok(tokens.to_vec());
                }
                let mut summarized = tokens[..*preserve_segments].to_vec();
                summarized.push(String::from("..."));
                Ok(summarized)
            }
            Self::HashPartition { buckets } => Ok(vec![
                deterministic_bucket(tokens, &[], *buckets)?.to_string(),
            ]),
            Self::WildcardCapture { index } => Ok(vec![select_token(tokens, *index)?.to_owned()]),
            Self::DeterministicHash {
                buckets,
                source_indices,
            } => Ok(vec![
                deterministic_bucket(tokens, source_indices, *buckets)?.to_string(),
            ]),
            Self::SplitSlice {
                index,
                delimiter,
                start,
                len,
            } => {
                let token = select_token(tokens, *index)?;
                let pieces = token.split(delimiter).collect::<Vec<_>>();
                if *start >= pieces.len() {
                    return Ok(Vec::new());
                }
                let end = start.saturating_add(*len).min(pieces.len());
                Ok(pieces[*start..end]
                    .iter()
                    .map(|piece| (*piece).to_owned())
                    .collect())
            }
            Self::LeftExtract { index, len } => {
                let token = select_token(tokens, *index)?;
                Ok(vec![take_left(token, *len)])
            }
            Self::RightExtract { index, len } => {
                let token = select_token(tokens, *index)?;
                Ok(vec![take_right(token, *len)])
            }
            Self::Compose { steps } => {
                let mut current = tokens.to_vec();
                for step in steps {
                    current = step.apply_tokens(&current)?;
                }
                Ok(current)
            }
        }
    }

    fn validate(&self) -> Result<(), MorphismValidationError> {
        match self {
            Self::RenamePrefix { from, to } if from == to => {
                Err(MorphismValidationError::RenamePrefixIdentity)
            }
            Self::SummarizeTail { preserve_segments } if *preserve_segments == 0 => {
                Err(MorphismValidationError::SummarizeTailMustPreserveSegments)
            }
            Self::HashPartition { buckets } if *buckets == 0 => {
                Err(MorphismValidationError::HashPartitionRequiresBuckets)
            }
            Self::WildcardCapture { index } if *index == 0 => {
                Err(MorphismValidationError::WildcardCaptureRequiresIndex)
            }
            Self::DeterministicHash { buckets, .. } if *buckets == 0 => {
                Err(MorphismValidationError::DeterministicHashRequiresBuckets)
            }
            Self::DeterministicHash { source_indices, .. } if source_indices.contains(&0) => {
                Err(MorphismValidationError::DeterministicHashIndexMustBePositive)
            }
            Self::SplitSlice { index, .. } if *index == 0 => {
                Err(MorphismValidationError::SplitSliceRequiresIndex)
            }
            Self::SplitSlice { delimiter, .. } if delimiter.is_empty() => {
                Err(MorphismValidationError::SplitSliceRequiresDelimiter)
            }
            Self::SplitSlice { len, .. } if *len == 0 => {
                Err(MorphismValidationError::SplitSliceRequiresLength)
            }
            Self::LeftExtract { index, .. } if *index == 0 => {
                Err(MorphismValidationError::LeftExtractRequiresIndex)
            }
            Self::LeftExtract { len, .. } if *len == 0 => {
                Err(MorphismValidationError::LeftExtractRequiresLength)
            }
            Self::RightExtract { index, .. } if *index == 0 => {
                Err(MorphismValidationError::RightExtractRequiresIndex)
            }
            Self::RightExtract { len, .. } if *len == 0 => {
                Err(MorphismValidationError::RightExtractRequiresLength)
            }
            Self::Compose { steps } if steps.is_empty() => {
                Err(MorphismValidationError::ComposeRequiresSteps)
            }
            Self::Compose { steps } => {
                for step in steps {
                    step.validate()?;
                }
                Ok(())
            }
            Self::Identity
            | Self::RedactLiterals
            | Self::RenamePrefix { .. }
            | Self::SummarizeTail { .. }
            | Self::HashPartition { .. }
            | Self::WildcardCapture { .. }
            | Self::DeterministicHash { .. }
            | Self::SplitSlice { .. }
            | Self::LeftExtract { .. }
            | Self::RightExtract { .. } => Ok(()),
        }
    }
}

/// Cost and handoff envelope for a morphism.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuotaPolicy {
    /// Maximum multiplicative expansion factor after rewriting.
    pub max_expansion_factor: u16,
    /// Maximum delivery fanout created by the morphism.
    pub max_fanout: u16,
    /// Maximum evidence or observability bytes emitted per decision.
    pub max_observability_bytes: u32,
    /// Maximum duration a delegated morphism may remain active.
    pub max_handoff_duration: Option<Duration>,
    /// Whether the handoff must support explicit revocation.
    pub revocation_required: bool,
}

impl Default for QuotaPolicy {
    fn default() -> Self {
        Self {
            max_expansion_factor: 1,
            max_fanout: 1,
            max_observability_bytes: 4_096,
            max_handoff_duration: None,
            revocation_required: false,
        }
    }
}

impl QuotaPolicy {
    fn validate(&self) -> Result<(), MorphismValidationError> {
        if self.max_expansion_factor == 0 {
            return Err(MorphismValidationError::ZeroMaxExpansionFactor);
        }
        if self.max_fanout == 0 {
            return Err(MorphismValidationError::ZeroMaxFanout);
        }
        if self.max_observability_bytes == 0 {
            return Err(MorphismValidationError::ZeroMaxObservabilityBytes);
        }
        if self
            .max_handoff_duration
            .is_some_and(|duration| duration.is_zero())
        {
            return Err(MorphismValidationError::ZeroMaxHandoffDuration);
        }
        Ok(())
    }
}

/// Typed namespace morphism declaration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Morphism {
    /// Source subject language accepted by the morphism.
    pub source_language: SubjectPattern,
    /// Destination subject language emitted by the morphism.
    pub dest_language: SubjectPattern,
    /// High-level morphism class.
    pub class: MorphismClass,
    /// Concrete transform algebra element.
    pub transform: SubjectTransform,
    /// Reversibility promise for the rewrite.
    pub reversibility: ReversibilityRequirement,
    /// Capabilities required to authorize the morphism.
    pub capability_requirements: Vec<FabricCapability>,
    /// Sharing boundary for the rewritten output.
    pub sharing_policy: SharingPolicy,
    /// Privacy and metadata disclosure policy.
    pub privacy_policy: PrivacyPolicy,
    /// Reply-handling semantics after rewriting.
    pub response_policy: ResponsePolicy,
    /// Bounded quota envelope for the morphism.
    pub quota_policy: QuotaPolicy,
    /// Evidence policy attached to the morphism.
    pub evidence_policy: EvidencePolicy,
}

impl Default for Morphism {
    fn default() -> Self {
        Self {
            source_language: SubjectPattern::new("fabric.subject.>"),
            dest_language: SubjectPattern::new("fabric.subject.>"),
            class: MorphismClass::DerivedView,
            transform: SubjectTransform::Identity,
            reversibility: ReversibilityRequirement::EvidenceBacked,
            capability_requirements: vec![FabricCapability::RewriteNamespace],
            sharing_policy: SharingPolicy::Private,
            privacy_policy: PrivacyPolicy::default(),
            response_policy: ResponsePolicy::PreserveCallerReplies,
            quota_policy: QuotaPolicy::default(),
            evidence_policy: EvidencePolicy::default(),
        }
    }
}

impl Morphism {
    /// Validate the morphism against class-specific guardrails.
    pub fn validate(&self) -> Result<(), MorphismValidationError> {
        self.transform.validate()?;
        self.quota_policy.validate()?;

        if let Some(duplicate) = duplicate_capability(&self.capability_requirements) {
            return Err(MorphismValidationError::DuplicateCapability(duplicate));
        }
        if self.reversibility == ReversibilityRequirement::Bijective
            && !self.transform.is_invertible()
        {
            return Err(MorphismValidationError::TransformCannotSatisfyBijectiveRequirement);
        }

        match self.class {
            MorphismClass::Authoritative => {
                if self.capability_requirements.is_empty() {
                    return Err(MorphismValidationError::AuthoritativeRequiresCapability);
                }
                if !self
                    .capability_requirements
                    .iter()
                    .copied()
                    .any(FabricCapability::is_authority_bearing)
                {
                    return Err(MorphismValidationError::AuthoritativeRequiresAuthorityCapability);
                }
                if self.response_policy != ResponsePolicy::ReplyAuthoritative {
                    return Err(MorphismValidationError::AuthoritativeRequiresReplyAuthority);
                }
                if self.reversibility == ReversibilityRequirement::Irreversible {
                    return Err(MorphismValidationError::AuthoritativeMustBeReversible);
                }
                if self.transform.is_lossy() {
                    return Err(MorphismValidationError::AuthoritativeTransformMustBeLossless);
                }
                if let SubjectTransform::RenamePrefix { from, to } = &self.transform
                    && (from.has_wildcards() || to.has_wildcards())
                {
                    return Err(MorphismValidationError::AuthoritativeRenameMustBeLiteralOnly);
                }
            }
            MorphismClass::DerivedView => {
                if self
                    .capability_requirements
                    .iter()
                    .copied()
                    .any(FabricCapability::is_authority_bearing)
                {
                    return Err(
                        MorphismValidationError::DerivedViewCannotRequireAuthorityCapability,
                    );
                }
                if self.response_policy == ResponsePolicy::ReplyAuthoritative {
                    return Err(MorphismValidationError::DerivedViewCannotOriginateReplyAuthority);
                }
            }
            MorphismClass::Egress => {
                if self.response_policy != ResponsePolicy::StripReplies {
                    return Err(MorphismValidationError::EgressMustStripReplies);
                }
                if self.reversibility != ReversibilityRequirement::Irreversible {
                    return Err(MorphismValidationError::EgressMustBeIrreversible);
                }
                if self.sharing_policy == SharingPolicy::Private {
                    return Err(MorphismValidationError::EgressMustCrossBoundary);
                }
            }
            MorphismClass::Delegation => {
                if !self
                    .capability_requirements
                    .contains(&FabricCapability::DelegateNamespace)
                {
                    return Err(MorphismValidationError::DelegationRequiresDelegateCapability);
                }
                if self.reversibility == ReversibilityRequirement::Irreversible {
                    return Err(MorphismValidationError::DelegationMustBeReversible);
                }
                if self.transform.is_lossy() {
                    return Err(MorphismValidationError::DelegationTransformMustBeLossless);
                }
                if self.quota_policy.max_handoff_duration.is_none() {
                    return Err(MorphismValidationError::DelegationMustBeTimeBounded);
                }
                if !self.quota_policy.revocation_required {
                    return Err(MorphismValidationError::DelegationMustBeRevocable);
                }
            }
        }

        Ok(())
    }

    /// Return the authority facet of the morphism.
    #[must_use]
    pub fn authority_facet(&self) -> AuthorityFacet {
        AuthorityFacet {
            class: self.class,
            capability_requirements: canonical_capabilities(&self.capability_requirements),
            response_policy: self.response_policy,
        }
    }

    /// Return the reversibility facet of the morphism.
    #[must_use]
    pub fn reversibility_facet(&self) -> ReversibilityFacet {
        ReversibilityFacet {
            requirement: self.reversibility,
            lossy_transform: self.transform.is_lossy(),
        }
    }

    /// Return the secrecy and metadata-exposure facet of the morphism.
    #[must_use]
    pub fn secrecy_facet(&self) -> SecrecyFacet {
        SecrecyFacet {
            sharing_policy: self.sharing_policy,
            privacy_policy: self.privacy_policy.clone(),
        }
    }

    /// Return the bounded cost and quota facet of the morphism.
    #[must_use]
    pub fn cost_facet(&self) -> CostFacet {
        CostFacet {
            quota_policy: self.quota_policy.clone(),
        }
    }

    /// Return the observability and evidence facet of the morphism.
    #[must_use]
    pub fn observability_facet(&self) -> ObservabilityFacet {
        ObservabilityFacet {
            evidence_policy: self.evidence_policy.clone(),
        }
    }

    /// Return all five independently checkable morphism facets.
    #[must_use]
    pub fn facet_set(&self) -> MorphismFacetSet {
        MorphismFacetSet {
            authority: self.authority_facet(),
            reversibility: self.reversibility_facet(),
            secrecy: self.secrecy_facet(),
            cost: self.cost_facet(),
            observability: self.observability_facet(),
        }
    }

    /// Compile the morphism into a deterministic certificate.
    pub fn compile(&self) -> Result<MorphismCertificate, MorphismValidationError> {
        self.validate()?;

        let bytes = serde_json::to_vec(self)
            .map_err(|error| MorphismValidationError::SerializeCertificate(error.to_string()))?;
        let mut hasher = DetHasher::default();
        hasher.write(&bytes);

        Ok(MorphismCertificate {
            fingerprint: format!("{:016x}", hasher.finish()),
            class: self.class,
            source_language: self.source_language.clone(),
            dest_language: self.dest_language.clone(),
            transform: self.transform.clone(),
            facets: self.facet_set(),
        })
    }

    /// Compile the morphism into a verified export-side boundary plan.
    pub fn compile_export_plan(
        &self,
        requested_reply_space: Option<ReplySpaceRule>,
    ) -> Result<ExportPlan, MorphismCompileError> {
        let parts =
            compile_boundary_plan(self, MorphismPlanDirection::Export, requested_reply_space)?;
        Ok(ExportPlan {
            direction: parts.direction,
            certificate: parts.certificate,
            attached_capabilities: parts.attached_capabilities,
            selected_reply_space: parts.selected_reply_space,
            permitted_reply_spaces: parts.permitted_reply_spaces,
            metadata_boundary: parts.metadata_boundary,
            steps: parts.steps,
            reasoning: parts.reasoning,
        })
    }

    /// Compile the morphism into a verified import-side boundary plan.
    pub fn compile_import_plan(
        &self,
        requested_reply_space: Option<ReplySpaceRule>,
    ) -> Result<ImportPlan, MorphismCompileError> {
        let parts =
            compile_boundary_plan(self, MorphismPlanDirection::Import, requested_reply_space)?;
        Ok(ImportPlan {
            direction: parts.direction,
            certificate: parts.certificate,
            attached_capabilities: parts.attached_capabilities,
            selected_reply_space: parts.selected_reply_space,
            permitted_reply_spaces: parts.permitted_reply_spaces,
            metadata_boundary: parts.metadata_boundary,
            steps: parts.steps,
            reasoning: parts.reasoning,
        })
    }

    fn crosses_boundary(&self) -> bool {
        self.sharing_policy != SharingPolicy::Private
            || matches!(
                self.class,
                MorphismClass::Egress | MorphismClass::Delegation
            )
    }
}

/// Independently checkable authority facet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityFacet {
    /// Class that determines the authority envelope.
    pub class: MorphismClass,
    /// Canonicalized capability requirements.
    pub capability_requirements: Vec<FabricCapability>,
    /// Reply-handling policy for the rewritten namespace.
    pub response_policy: ResponsePolicy,
}

/// Independently checkable reversibility facet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReversibilityFacet {
    /// Declared reversibility requirement.
    pub requirement: ReversibilityRequirement,
    /// Whether the chosen transform is intrinsically lossy.
    pub lossy_transform: bool,
}

/// Independently checkable secrecy and metadata-exposure facet.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecrecyFacet {
    /// Sharing boundary after the morphism applies.
    pub sharing_policy: SharingPolicy,
    /// Privacy rules for metadata and subject disclosure.
    pub privacy_policy: PrivacyPolicy,
}

/// Independently checkable cost and quota facet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CostFacet {
    /// Quota envelope that bounds expansion, fanout, and delegation.
    pub quota_policy: QuotaPolicy,
}

/// Independently checkable observability and evidence facet.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservabilityFacet {
    /// Evidence policy emitted by the morphism.
    pub evidence_policy: EvidencePolicy,
}

/// Aggregated view of the five morphism facets.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MorphismFacetSet {
    /// Authority and capability requirements.
    pub authority: AuthorityFacet,
    /// Reversibility contract.
    pub reversibility: ReversibilityFacet,
    /// Secrecy and metadata-disclosure policy.
    pub secrecy: SecrecyFacet,
    /// Cost and quota envelope.
    pub cost: CostFacet,
    /// Evidence and observability obligations.
    pub observability: ObservabilityFacet,
}

/// Deterministic compiled artifact for a validated morphism.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MorphismCertificate {
    /// Stable fingerprint over the serialized morphism declaration.
    pub fingerprint: String,
    /// Class of the validated morphism.
    pub class: MorphismClass,
    /// Source language encoded into the certificate.
    pub source_language: SubjectPattern,
    /// Destination language encoded into the certificate.
    pub dest_language: SubjectPattern,
    /// Transform algebra element encoded into the certificate.
    pub transform: SubjectTransform,
    /// Faceted summary used by downstream validators.
    pub facets: MorphismFacetSet,
}

/// Direction for a compiled morphism boundary plan.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum MorphismPlanDirection {
    /// Compile an inbound/import-side boundary plan.
    Import,
    /// Compile an outbound/export-side boundary plan.
    #[default]
    Export,
}

impl MorphismPlanDirection {
    #[must_use]
    const fn as_str(self) -> &'static str {
        match self {
            Self::Import => "import",
            Self::Export => "export",
        }
    }
}

/// Deterministic execution steps in a compiled boundary plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MorphismPlanStep {
    /// Match the incoming namespace against the source language.
    MatchSourceLanguage,
    /// Enforce the attached capability envelope.
    EnforceCapabilityEnvelope,
    /// Apply the transform certificate deterministically.
    ApplyTransformCertificate,
    /// Enforce reply-space policy for cross-boundary requests.
    EnforceReplySpace,
    /// Enforce metadata disclosure policy at the boundary.
    EnforceMetadataBoundary,
    /// Emit auditable reasoning for the plan installation.
    EmitAuditReasoning,
}

/// Semantic class for a risky morphism cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticCycleClass {
    /// The loop could preserve or re-amplify authority.
    Authority,
    /// The loop hides a lossy or irreversible rewrite.
    Reversibility,
    /// The loop composes boundary-crossing capabilities into a cycle.
    Capability,
}

/// Auditable summary of what metadata crosses a morphism boundary.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataBoundarySummary {
    /// Whether the plan crosses an authority or stewardship boundary.
    pub crosses_boundary: bool,
    /// Metadata disclosure level across the boundary.
    pub metadata_disclosure: MetadataDisclosure,
    /// Whether literal subject segments are redacted before crossing.
    pub subject_literals_redacted: bool,
    /// Whether cross-tenant metadata movement is explicitly allowed.
    pub cross_tenant_flow_allowed: bool,
    /// Whether payload hashes remain observable after the boundary.
    pub payload_hashes_recorded: bool,
}

/// Auditable reasoning note attached to a compiled plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MorphismAuditNote {
    /// Stable category for the note.
    pub code: String,
    /// Human-readable explanation for auditors.
    pub detail: String,
}

/// Compiled export-side routing plan for a morphism boundary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExportPlan {
    /// Direction for the compiled plan.
    pub direction: MorphismPlanDirection,
    /// Transform certificate emitted by the compiler.
    pub certificate: MorphismCertificate,
    /// Canonical attached capability envelope.
    pub attached_capabilities: Vec<FabricCapability>,
    /// Reply space selected for the boundary.
    pub selected_reply_space: Option<ReplySpaceRule>,
    /// Reply spaces permitted by the compiled policy.
    pub permitted_reply_spaces: Vec<ReplySpaceRule>,
    /// Metadata disclosure summary for the boundary.
    pub metadata_boundary: MetadataBoundarySummary,
    /// Deterministic execution steps for the plan.
    pub steps: Vec<MorphismPlanStep>,
    /// Auditable reasoning notes emitted by compilation.
    pub reasoning: Vec<MorphismAuditNote>,
}

/// Compiled import-side routing plan for a morphism boundary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImportPlan {
    /// Direction for the compiled plan.
    pub direction: MorphismPlanDirection,
    /// Transform certificate emitted by the compiler.
    pub certificate: MorphismCertificate,
    /// Canonical attached capability envelope.
    pub attached_capabilities: Vec<FabricCapability>,
    /// Reply space selected for the boundary.
    pub selected_reply_space: Option<ReplySpaceRule>,
    /// Reply spaces permitted by the compiled policy.
    pub permitted_reply_spaces: Vec<ReplySpaceRule>,
    /// Metadata disclosure summary for the boundary.
    pub metadata_boundary: MetadataBoundarySummary,
    /// Deterministic execution steps for the plan.
    pub steps: Vec<MorphismPlanStep>,
    /// Auditable reasoning notes emitted by compilation.
    pub reasoning: Vec<MorphismAuditNote>,
}

/// Compilation failures while building import/export plans.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MorphismCompileError {
    /// The morphism declaration itself failed validation.
    #[error(transparent)]
    InvalidMorphism(#[from] MorphismValidationError),
    /// Cross-boundary traffic selected a forbidden reply space.
    #[error(
        "cross-boundary reply space `{requested:?}` is not permitted for response policy `{policy:?}`; permitted reply spaces: {permitted:?}"
    )]
    ReplySpaceNotPermitted {
        /// Response policy being enforced.
        policy: ResponsePolicy,
        /// Requested reply space for the boundary.
        requested: ReplySpaceRule,
        /// Reply spaces admitted by the compiler.
        permitted: Vec<ReplySpaceRule>,
    },
    /// Cross-boundary traffic attempted to keep replies when the policy strips them.
    #[error("cross-boundary replies are forbidden for response policy `{policy:?}`")]
    ReplySpaceForbidden {
        /// Response policy being enforced.
        policy: ResponsePolicy,
    },
    /// A morphism chain creates a risky semantic loop.
    #[error("semantic {class:?} cycle detected across morphism chain {path:?}")]
    SemanticCycleDetected {
        /// Semantic class of the detected loop.
        class: SemanticCycleClass,
        /// Human-readable path for the cycle.
        path: Vec<String>,
    },
    /// The privacy boundary permits more metadata than the policy authorizes.
    #[error(
        "sharing policy `{sharing_policy:?}` with metadata disclosure `{metadata_disclosure:?}` requires explicit cross-tenant permission"
    )]
    MetadataBoundaryViolation {
        /// Boundary sharing level that triggered the violation.
        sharing_policy: SharingPolicy,
        /// Metadata disclosure mode that exceeded policy.
        metadata_disclosure: MetadataDisclosure,
    },
}

/// Detect risky semantic cycles across a chain of morphisms.
pub fn detect_semantic_cycles(morphisms: &[Morphism]) -> Result<(), MorphismCompileError> {
    for morphism in morphisms {
        morphism.validate()?;
    }

    for start in 0..morphisms.len() {
        let mut path = vec![start];
        let mut visited = BTreeSet::from([start]);
        detect_semantic_cycle_from(morphisms, start, start, &mut path, &mut visited)?;
    }

    Ok(())
}

/// Validation failures for typed namespace morphisms.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MorphismValidationError {
    /// Authoritative morphisms must declare at least one capability.
    #[error("authoritative morphisms require at least one capability")]
    AuthoritativeRequiresCapability,
    /// Authoritative morphisms must carry an authority-bearing capability.
    #[error("authoritative morphisms require an authority-bearing capability")]
    AuthoritativeRequiresAuthorityCapability,
    /// Authoritative morphisms must control replies explicitly.
    #[error("authoritative morphisms must use reply-authoritative response policy")]
    AuthoritativeRequiresReplyAuthority,
    /// Authoritative morphisms must not be declared one-way.
    #[error("authoritative morphisms must be reversible")]
    AuthoritativeMustBeReversible,
    /// Authoritative morphisms must not use lossy transforms.
    #[error("authoritative morphisms must use lossless transforms")]
    AuthoritativeTransformMustBeLossless,
    /// Authoritative prefix rewrites must stay literal-only.
    #[error("authoritative rename-prefix morphisms must use literal-only patterns")]
    AuthoritativeRenameMustBeLiteralOnly,
    /// Derived views must not require authority-bearing capabilities.
    #[error("derived-view morphisms must not require authority-bearing capabilities")]
    DerivedViewCannotRequireAuthorityCapability,
    /// Derived views must not rebind replies as authority.
    #[error("derived-view morphisms must not originate reply authority")]
    DerivedViewCannotOriginateReplyAuthority,
    /// Egress morphisms must strip reply semantics.
    #[error("egress morphisms must strip replies")]
    EgressMustStripReplies,
    /// Egress morphisms are intentionally one-way.
    #[error("egress morphisms must be irreversible")]
    EgressMustBeIrreversible,
    /// Egress morphisms must leave the private boundary.
    #[error("egress morphisms must cross a non-private sharing boundary")]
    EgressMustCrossBoundary,
    /// Delegation requires the delegation capability.
    #[error("delegation morphisms require delegate-namespace capability")]
    DelegationRequiresDelegateCapability,
    /// Delegation preserves authority and therefore must not be one-way.
    #[error("delegation morphisms must be reversible")]
    DelegationMustBeReversible,
    /// Delegation preserves authority and therefore must not use lossy rewrites.
    #[error("delegation morphisms must use lossless transforms")]
    DelegationTransformMustBeLossless,
    /// Delegation must declare a finite handoff duration.
    #[error("delegation morphisms must declare a bounded handoff duration")]
    DelegationMustBeTimeBounded,
    /// Delegation must be explicitly revocable.
    #[error("delegation morphisms must be revocable")]
    DelegationMustBeRevocable,
    /// Capability requirements must be unique.
    #[error("duplicate capability requirement `{0:?}`")]
    DuplicateCapability(FabricCapability),
    /// Rename-prefix transforms must actually change the namespace.
    #[error("rename-prefix transform must change the namespace")]
    RenamePrefixIdentity,
    /// Tail summarization must preserve at least one segment.
    #[error("summarize-tail transform must preserve at least one segment")]
    SummarizeTailMustPreserveSegments,
    /// Hash partitioning requires at least one bucket.
    #[error("hash-partition transform requires at least one bucket")]
    HashPartitionRequiresBuckets,
    /// Wildcard capture transforms must name a 1-based index.
    #[error("wildcard-capture transform requires a positive index")]
    WildcardCaptureRequiresIndex,
    /// Deterministic hash transforms require at least one bucket.
    #[error("deterministic-hash transform requires at least one bucket")]
    DeterministicHashRequiresBuckets,
    /// Deterministic hash transforms use 1-based token indices.
    #[error("deterministic-hash source indices must be positive")]
    DeterministicHashIndexMustBePositive,
    /// Split-and-slice transforms must name a 1-based token index.
    #[error("split-slice transform requires a positive token index")]
    SplitSliceRequiresIndex,
    /// Split-and-slice transforms need a non-empty delimiter.
    #[error("split-slice transform requires a non-empty delimiter")]
    SplitSliceRequiresDelimiter,
    /// Split-and-slice transforms must keep at least one piece.
    #[error("split-slice transform requires a positive slice length")]
    SplitSliceRequiresLength,
    /// Left-extract transforms must name a 1-based token index.
    #[error("left-extract transform requires a positive token index")]
    LeftExtractRequiresIndex,
    /// Left-extract transforms must keep at least one character.
    #[error("left-extract transform requires a positive length")]
    LeftExtractRequiresLength,
    /// Right-extract transforms must name a 1-based token index.
    #[error("right-extract transform requires a positive token index")]
    RightExtractRequiresIndex,
    /// Right-extract transforms must keep at least one character.
    #[error("right-extract transform requires a positive length")]
    RightExtractRequiresLength,
    /// Compose transforms must contain at least one step.
    #[error("compose transform requires at least one step")]
    ComposeRequiresSteps,
    /// Bijective requirements need an invertible transform.
    #[error("bijective reversibility requires an invertible transform")]
    TransformCannotSatisfyBijectiveRequirement,
    /// Expansion factor must be positive.
    #[error("quota max expansion factor must be greater than zero")]
    ZeroMaxExpansionFactor,
    /// Fanout must be positive.
    #[error("quota max fanout must be greater than zero")]
    ZeroMaxFanout,
    /// Observability budget must be positive.
    #[error("quota max observability bytes must be greater than zero")]
    ZeroMaxObservabilityBytes,
    /// Handoff duration must be positive when present.
    #[error("quota max handoff duration must be greater than zero")]
    ZeroMaxHandoffDuration,
    /// Certificate compilation failed while serializing the morphism.
    #[error("failed to serialize morphism certificate: {0}")]
    SerializeCertificate(String),
}

/// Evaluation failures while executing a deterministic transform pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MorphismEvaluationError {
    /// A transform referenced a token/capture index that is not present.
    #[error("token index {index} is out of range for {available} available tokens")]
    TokenIndexOutOfRange {
        /// 1-based index requested by the transform.
        index: usize,
        /// Number of tokens available to the transform.
        available: usize,
    },
    /// Prefix rewrites can only execute against literal-only patterns.
    #[error("pattern `{0}` must contain only literal segments for evaluation")]
    NonLiteralPattern(String),
    /// Deterministic hashing requires at least one bucket.
    #[error("deterministic bucket count must be greater than zero")]
    ZeroBuckets,
}

fn canonical_capabilities(capabilities: &[FabricCapability]) -> Vec<FabricCapability> {
    capabilities
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn duplicate_capability(capabilities: &[FabricCapability]) -> Option<FabricCapability> {
    let mut seen = BTreeSet::new();
    for capability in capabilities {
        if !seen.insert(*capability) {
            return Some(*capability);
        }
    }
    None
}

fn literal_only_segments(pattern: &SubjectPattern) -> Result<Vec<String>, MorphismEvaluationError> {
    pattern
        .segments()
        .iter()
        .map(|segment| match segment {
            super::subject::SubjectToken::Literal(value) => Ok(value.clone()),
            super::subject::SubjectToken::One | super::subject::SubjectToken::Tail => Err(
                MorphismEvaluationError::NonLiteralPattern(pattern.canonical_key()),
            ),
        })
        .collect()
}

fn select_token(tokens: &[String], index: usize) -> Result<&str, MorphismEvaluationError> {
    let offset = index
        .checked_sub(1)
        .ok_or(MorphismEvaluationError::TokenIndexOutOfRange {
            index,
            available: tokens.len(),
        })?;
    tokens
        .get(offset)
        .map(String::as_str)
        .ok_or(MorphismEvaluationError::TokenIndexOutOfRange {
            index,
            available: tokens.len(),
        })
}

fn deterministic_bucket(
    tokens: &[String],
    source_indices: &[usize],
    buckets: u16,
) -> Result<u16, MorphismEvaluationError> {
    if buckets == 0 {
        return Err(MorphismEvaluationError::ZeroBuckets);
    }

    let mut hasher = DetHasher::default();
    if source_indices.is_empty() {
        for token in tokens {
            hasher.write(token.as_bytes());
            hasher.write_u8(0xff);
        }
    } else {
        for index in source_indices {
            hasher.write(select_token(tokens, *index)?.as_bytes());
            hasher.write_u8(0xff);
        }
    }

    Ok((hasher.finish() % u64::from(buckets)) as u16)
}

fn take_left(token: &str, len: usize) -> String {
    let limit = token.chars().count().min(len);
    token.chars().take(limit).collect()
}

fn take_right(token: &str, len: usize) -> String {
    let char_count = token.chars().count();
    let start = char_count.saturating_sub(len);
    token.chars().skip(start).collect()
}

#[derive(Debug)]
struct CompiledPlanParts {
    direction: MorphismPlanDirection,
    certificate: MorphismCertificate,
    attached_capabilities: Vec<FabricCapability>,
    selected_reply_space: Option<ReplySpaceRule>,
    permitted_reply_spaces: Vec<ReplySpaceRule>,
    metadata_boundary: MetadataBoundarySummary,
    steps: Vec<MorphismPlanStep>,
    reasoning: Vec<MorphismAuditNote>,
}

fn compile_boundary_plan(
    morphism: &Morphism,
    direction: MorphismPlanDirection,
    requested_reply_space: Option<ReplySpaceRule>,
) -> Result<CompiledPlanParts, MorphismCompileError> {
    let certificate = morphism.compile()?;
    let attached_capabilities = canonical_capabilities(&morphism.capability_requirements);
    let permitted_reply_spaces = permitted_reply_spaces(morphism);
    let selected_reply_space =
        select_reply_space(morphism, requested_reply_space, &permitted_reply_spaces)?;
    let metadata_boundary = compile_metadata_boundary(morphism)?;
    let reasoning = vec![
        audit_note(
            "direction",
            format!(
                "{} plan rewrites `{}` into `{}`",
                direction.as_str(),
                morphism.source_language,
                morphism.dest_language
            ),
        ),
        audit_note(
            "capabilities",
            format!("attached capabilities: {attached_capabilities:?}"),
        ),
        audit_note(
            "reply_space",
            format!(
                "response policy {:?} selected {:?} from permitted spaces {:?}",
                morphism.response_policy, selected_reply_space, permitted_reply_spaces
            ),
        ),
        audit_note(
            "metadata_boundary",
            format!(
                "boundary crosses={}, disclosure={:?}, subject_literals_redacted={}, cross_tenant_flow_allowed={}, payload_hashes_recorded={}",
                metadata_boundary.crosses_boundary,
                metadata_boundary.metadata_disclosure,
                metadata_boundary.subject_literals_redacted,
                metadata_boundary.cross_tenant_flow_allowed,
                metadata_boundary.payload_hashes_recorded,
            ),
        ),
    ];

    Ok(CompiledPlanParts {
        direction,
        certificate,
        attached_capabilities,
        selected_reply_space,
        permitted_reply_spaces,
        metadata_boundary,
        steps: vec![
            MorphismPlanStep::MatchSourceLanguage,
            MorphismPlanStep::EnforceCapabilityEnvelope,
            MorphismPlanStep::ApplyTransformCertificate,
            MorphismPlanStep::EnforceReplySpace,
            MorphismPlanStep::EnforceMetadataBoundary,
            MorphismPlanStep::EmitAuditReasoning,
        ],
        reasoning,
    })
}

fn permitted_reply_spaces(morphism: &Morphism) -> Vec<ReplySpaceRule> {
    match morphism.response_policy {
        ResponsePolicy::StripReplies => Vec::new(),
        ResponsePolicy::PreserveCallerReplies | ResponsePolicy::ForwardOpaque => {
            vec![ReplySpaceRule::CallerInbox]
        }
        ResponsePolicy::ReplyAuthoritative => {
            let prefix = morphism.dest_language.as_str().to_owned();
            vec![
                ReplySpaceRule::DedicatedPrefix {
                    prefix: prefix.clone(),
                },
                ReplySpaceRule::SharedPrefix { prefix },
            ]
        }
    }
}

fn select_reply_space(
    morphism: &Morphism,
    requested_reply_space: Option<ReplySpaceRule>,
    permitted_reply_spaces: &[ReplySpaceRule],
) -> Result<Option<ReplySpaceRule>, MorphismCompileError> {
    let selected_reply_space = requested_reply_space.map_or_else(
        || default_reply_space(morphism, permitted_reply_spaces),
        Some,
    );

    if !morphism.crosses_boundary() {
        return Ok(selected_reply_space);
    }

    selected_reply_space.map_or(Ok(None), |reply_space| {
        if permitted_reply_spaces.contains(&reply_space) {
            Ok(Some(reply_space))
        } else if permitted_reply_spaces.is_empty() {
            Err(MorphismCompileError::ReplySpaceForbidden {
                policy: morphism.response_policy,
            })
        } else {
            Err(MorphismCompileError::ReplySpaceNotPermitted {
                policy: morphism.response_policy,
                requested: reply_space,
                permitted: permitted_reply_spaces.to_vec(),
            })
        }
    })
}

fn default_reply_space(
    morphism: &Morphism,
    permitted_reply_spaces: &[ReplySpaceRule],
) -> Option<ReplySpaceRule> {
    match morphism.response_policy {
        ResponsePolicy::StripReplies => None,
        ResponsePolicy::PreserveCallerReplies | ResponsePolicy::ForwardOpaque => {
            Some(ReplySpaceRule::CallerInbox)
        }
        ResponsePolicy::ReplyAuthoritative => permitted_reply_spaces.first().cloned(),
    }
}

fn compile_metadata_boundary(
    morphism: &Morphism,
) -> Result<MetadataBoundarySummary, MorphismCompileError> {
    let summary = MetadataBoundarySummary {
        crosses_boundary: morphism.crosses_boundary(),
        metadata_disclosure: morphism.privacy_policy.metadata_disclosure,
        subject_literals_redacted: morphism.privacy_policy.redact_subject_literals
            || matches!(morphism.transform, SubjectTransform::RedactLiterals),
        cross_tenant_flow_allowed: morphism.privacy_policy.allow_cross_tenant_flow,
        payload_hashes_recorded: morphism.evidence_policy.record_payload_hashes,
    };

    if summary.crosses_boundary
        && matches!(
            morphism.sharing_policy,
            SharingPolicy::Federated | SharingPolicy::PublicRead
        )
        && summary.metadata_disclosure == MetadataDisclosure::Full
        && !summary.cross_tenant_flow_allowed
    {
        return Err(MorphismCompileError::MetadataBoundaryViolation {
            sharing_policy: morphism.sharing_policy,
            metadata_disclosure: summary.metadata_disclosure,
        });
    }

    Ok(summary)
}

fn detect_semantic_cycle_from(
    morphisms: &[Morphism],
    start: usize,
    current: usize,
    path: &mut Vec<usize>,
    visited: &mut BTreeSet<usize>,
) -> Result<(), MorphismCompileError> {
    if morphisms[current]
        .dest_language
        .overlaps(&morphisms[start].source_language)
    {
        let cycle = path
            .iter()
            .map(|index| &morphisms[*index])
            .collect::<Vec<_>>();
        if let Some(class) = classify_semantic_cycle(&cycle) {
            return Err(MorphismCompileError::SemanticCycleDetected {
                class,
                path: path
                    .iter()
                    .map(|index| describe_morphism(&morphisms[*index]))
                    .collect(),
            });
        }
    }

    for next in 0..morphisms.len() {
        if !morphisms[current]
            .dest_language
            .overlaps(&morphisms[next].source_language)
        {
            continue;
        }
        if visited.contains(&next) {
            continue;
        }

        visited.insert(next);
        path.push(next);
        let result = detect_semantic_cycle_from(morphisms, start, next, path, visited);
        path.pop();
        visited.remove(&next);
        result?;
    }

    Ok(())
}

fn classify_semantic_cycle(morphisms: &[&Morphism]) -> Option<SemanticCycleClass> {
    if morphisms.iter().any(|morphism| {
        morphism.class == MorphismClass::Authoritative
            || morphism.response_policy == ResponsePolicy::ReplyAuthoritative
            || morphism
                .capability_requirements
                .iter()
                .copied()
                .any(FabricCapability::is_authority_bearing)
    }) {
        return Some(SemanticCycleClass::Authority);
    }

    if morphisms.iter().any(|morphism| {
        morphism.reversibility == ReversibilityRequirement::Irreversible
            || morphism.transform.is_lossy()
    }) {
        return Some(SemanticCycleClass::Reversibility);
    }

    if morphisms.iter().any(|morphism| {
        morphism.sharing_policy != SharingPolicy::Private
            || morphism.capability_requirements.iter().any(|capability| {
                matches!(
                    capability,
                    FabricCapability::ObserveEvidence | FabricCapability::CrossBoundaryEgress
                )
            })
    }) {
        return Some(SemanticCycleClass::Capability);
    }

    None
}

fn describe_morphism(morphism: &Morphism) -> String {
    format!(
        "{:?}:{}->{}",
        morphism.class, morphism.source_language, morphism.dest_language
    )
}

fn audit_note(code: &str, detail: String) -> MorphismAuditNote {
    MorphismAuditNote {
        code: code.to_owned(),
        detail,
    }
}

#[cfg(test)]
#[path = "morphism_inline_tests.rs"]
mod tests;
