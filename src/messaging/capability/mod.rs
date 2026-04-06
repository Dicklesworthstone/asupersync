//! Static capability-layer building blocks for FABRIC.

use super::subject::{NamespaceKernel, SubjectPattern, SubjectToken};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;

pub mod routing;
pub mod tokens;

pub use routing::{
    AuthorizedRoute, CapabilityRoutingError, RoutingAuditTrail, RoutingAuthorization,
    RoutingDirection, RoutingOperationKind, RoutingProgram, RoutingProgramCompileError,
    RoutingProgramStep, RoutingRequest,
};
pub use tokens::{
    AppendCertificate, CapabilityTokenError, CaptureSelectorFamily, CommandFamily, ControlFamily,
    CursorAuthorityLease, DerivedViewFamily, EventFamily, FenceToken, ProtocolMarker,
    ProtocolStepFamily, PublishPermit, ReplyFamily, SessionStateMarker, SessionToken,
    SubjectFamilyTag, SubscribeToken,
};

/// Stable identifier for a runtime FABRIC capability grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FabricCapabilityId(u64);

impl FabricCapabilityId {
    pub(crate) const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Return the raw monotonic identifier.
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Coarse-grained capability scope used for bulk revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FabricCapabilityScope {
    /// Publish authority for one or more subjects.
    Publish,
    /// Subscribe authority for one or more subjects.
    Subscribe,
    /// Authority to create a stream over a subject space.
    CreateStream,
    /// Authority to consume a named stream.
    ConsumeStream,
    /// Authority to rewrite or transform a subject space.
    TransformSpace,
    /// Authority to perform administrative control-plane actions.
    AdminControl,
}

impl fmt::Display for FabricCapabilityScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Publish => "publish",
            Self::Subscribe => "subscribe",
            Self::CreateStream => "create_stream",
            Self::ConsumeStream => "consume_stream",
            Self::TransformSpace => "transform_space",
            Self::AdminControl => "admin_control",
        };
        write!(f, "{name}")
    }
}

/// Runtime FABRIC capability grant carried by a [`Cx`](crate::cx::Cx).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FabricCapability {
    /// Authorize publishing within the covered subject space.
    Publish {
        /// Subject space covered by the grant.
        subject: SubjectPattern,
    },
    /// Authorize subscriptions within the covered subject space.
    Subscribe {
        /// Subject space covered by the grant.
        subject: SubjectPattern,
    },
    /// Authorize creation of streams rooted in the covered subject space.
    CreateStream {
        /// Subject space covered by the grant.
        subject: SubjectPattern,
    },
    /// Authorize consumption from one named stream.
    ConsumeStream {
        /// Stable stream identifier for the current stream state machine.
        stream: String,
    },
    /// Authorize namespace transforms within the covered subject space.
    TransformSpace {
        /// Subject space covered by the grant.
        subject: SubjectPattern,
    },
    /// Authorize administrative control-plane operations.
    AdminControl,
}

impl FabricCapability {
    /// Return the coarse scope for this capability.
    #[must_use]
    pub const fn scope(&self) -> FabricCapabilityScope {
        match self {
            Self::Publish { .. } => FabricCapabilityScope::Publish,
            Self::Subscribe { .. } => FabricCapabilityScope::Subscribe,
            Self::CreateStream { .. } => FabricCapabilityScope::CreateStream,
            Self::ConsumeStream { .. } => FabricCapabilityScope::ConsumeStream,
            Self::TransformSpace { .. } => FabricCapabilityScope::TransformSpace,
            Self::AdminControl => FabricCapabilityScope::AdminControl,
        }
    }

    fn canonicalize(self) -> Result<Self, FabricCapabilityGrantError> {
        match self {
            Self::ConsumeStream { stream } => {
                let trimmed = stream.trim();
                if trimmed.is_empty() {
                    return Err(FabricCapabilityGrantError::EmptyStreamName);
                }
                Ok(Self::ConsumeStream {
                    stream: trimmed.to_owned(),
                })
            }
            other => Ok(other),
        }
    }

    fn subject_scope(&self) -> Option<&SubjectPattern> {
        match self {
            Self::Publish { subject }
            | Self::Subscribe { subject }
            | Self::CreateStream { subject }
            | Self::TransformSpace { subject } => Some(subject),
            Self::ConsumeStream { .. } | Self::AdminControl => None,
        }
    }

    fn allows(&self, requested: &Self) -> bool {
        match (self, requested) {
            (Self::Publish { subject: granted }, Self::Publish { subject: requested })
            | (Self::Subscribe { subject: granted }, Self::Subscribe { subject: requested })
            | (
                Self::CreateStream { subject: granted },
                Self::CreateStream { subject: requested },
            )
            | (
                Self::TransformSpace { subject: granted },
                Self::TransformSpace { subject: requested },
            ) => pattern_covers_pattern(granted, requested),
            (
                Self::ConsumeStream {
                    stream: granted_stream,
                },
                Self::ConsumeStream {
                    stream: requested_stream,
                },
            ) => granted_stream == requested_stream,
            (Self::AdminControl, Self::AdminControl) => true,
            _ => false,
        }
    }
}

impl fmt::Display for FabricCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Publish { subject } => write!(f, "publish({subject})"),
            Self::Subscribe { subject } => write!(f, "subscribe({subject})"),
            Self::CreateStream { subject } => write!(f, "create_stream({subject})"),
            Self::ConsumeStream { stream } => write!(f, "consume_stream({stream})"),
            Self::TransformSpace { subject } => write!(f, "transform_space({subject})"),
            Self::AdminControl => write!(f, "admin_control"),
        }
    }
}

/// One runtime FABRIC capability grant stored in a context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FabricCapabilityGrant {
    id: FabricCapabilityId,
    capability: FabricCapability,
}

impl FabricCapabilityGrant {
    /// Return the stable identifier for this grant.
    #[must_use]
    pub const fn id(&self) -> FabricCapabilityId {
        self.id
    }

    /// Return the granted capability envelope.
    #[must_use]
    pub fn capability(&self) -> &FabricCapability {
        &self.capability
    }
}

/// Typed in-process token plus the runtime grant that backs distributed checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantedFabricToken<T> {
    grant: FabricCapabilityGrant,
    token: T,
}

impl<T> GrantedFabricToken<T> {
    pub(crate) fn new(grant: FabricCapabilityGrant, token: T) -> Self {
        Self { grant, token }
    }

    /// Return the runtime grant attached to this token.
    #[must_use]
    pub fn grant(&self) -> &FabricCapabilityGrant {
        &self.grant
    }

    /// Return the stable grant identifier.
    #[must_use]
    pub const fn grant_id(&self) -> FabricCapabilityId {
        self.grant.id
    }

    /// Return the granted capability envelope.
    #[must_use]
    pub fn capability(&self) -> &FabricCapability {
        &self.grant.capability
    }

    /// Borrow the typed in-process token.
    #[must_use]
    pub fn token(&self) -> &T {
        &self.token
    }

    /// Consume the wrapper and return the token plus runtime grant receipt.
    #[must_use]
    pub fn into_parts(self) -> (FabricCapabilityGrant, T) {
        (self.grant, self.token)
    }
}

/// Validation failures for runtime FABRIC capability grants.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FabricCapabilityGrantError {
    /// Stream-scoped grants require a stable non-empty stream name.
    #[error("fabric stream capability name must not be empty")]
    EmptyStreamName,
    /// Minting the corresponding static token failed validation.
    #[error(transparent)]
    InvalidToken {
        /// Underlying static token validation failure.
        #[from]
        source: CapabilityTokenError,
    },
}

/// Shared runtime registry of FABRIC capability grants carried by `Cx`.
#[derive(Debug, Default)]
pub(crate) struct FabricCapabilityRegistry {
    next_id: AtomicU64,
    grants: parking_lot::RwLock<BTreeMap<FabricCapabilityId, FabricCapability>>,
}

impl FabricCapabilityRegistry {
    pub(crate) fn grant(
        &self,
        capability: FabricCapability,
    ) -> Result<FabricCapabilityGrant, FabricCapabilityGrantError> {
        let capability = capability.canonicalize()?;
        let id = FabricCapabilityId::new(self.next_id.fetch_add(1, Ordering::Relaxed) + 1);
        self.grants.write().insert(id, capability.clone());
        Ok(FabricCapabilityGrant { id, capability })
    }

    #[must_use]
    pub(crate) fn snapshot(&self) -> Vec<FabricCapabilityGrant> {
        self.grants
            .read()
            .iter()
            .map(|(id, capability)| FabricCapabilityGrant {
                id: *id,
                capability: capability.clone(),
            })
            .collect()
    }

    #[must_use]
    pub(crate) fn check(&self, capability: &FabricCapability) -> bool {
        self.grants
            .read()
            .values()
            .any(|granted| granted.allows(capability))
    }

    pub(crate) fn revoke_by_id(&self, id: FabricCapabilityId) -> Option<FabricCapability> {
        self.grants.write().remove(&id)
    }

    #[must_use]
    pub(crate) fn revoke_by_subject(&self, subject: &SubjectPattern) -> usize {
        let revoked = self
            .grants
            .read()
            .iter()
            .filter(|(_, capability)| {
                capability
                    .subject_scope()
                    .is_some_and(|granted| granted.overlaps(subject))
            })
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();

        if revoked.is_empty() {
            return 0;
        }

        let mut grants = self.grants.write();
        for id in &revoked {
            grants.remove(id);
        }
        drop(grants);
        revoked.len()
    }

    #[must_use]
    pub(crate) fn revoke_scope(&self, scope: FabricCapabilityScope) -> usize {
        let revoked = self
            .grants
            .read()
            .iter()
            .filter(|(_, capability)| capability.scope() == scope)
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();

        if revoked.is_empty() {
            return 0;
        }

        let mut grants = self.grants.write();
        for id in &revoked {
            grants.remove(id);
        }
        drop(grants);
        revoked.len()
    }
}

fn pattern_covers_pattern(granted: &SubjectPattern, requested: &SubjectPattern) -> bool {
    pattern_covers_segments(granted.segments(), requested.segments())
}

fn pattern_covers_segments(granted: &[SubjectToken], requested: &[SubjectToken]) -> bool {
    match (granted.split_first(), requested.split_first()) {
        (Some((SubjectToken::Tail, _)), Some(_)) | (None, None) => true,
        (None, Some(_))
        | (Some(_), None)
        | (
            Some((SubjectToken::Literal(_), _)),
            Some((SubjectToken::One | SubjectToken::Tail, _)),
        )
        | (Some((SubjectToken::One, _)), Some((SubjectToken::Tail, _))) => false,
        (
            Some((SubjectToken::Literal(granted_head), granted_rest)),
            Some((SubjectToken::Literal(requested_head), requested_rest)),
        ) => {
            granted_head == requested_head && pattern_covers_segments(granted_rest, requested_rest)
        }
        (
            Some((SubjectToken::One, granted_rest)),
            Some((SubjectToken::Literal(_) | SubjectToken::One, requested_rest)),
        ) => pattern_covers_segments(granted_rest, requested_rest),
    }
}

/// Capability envelope for one tenant/service namespace kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceCapabilityEnvelope {
    namespace: NamespaceKernel,
}

impl NamespaceCapabilityEnvelope {
    /// Build a capability envelope for one namespace kernel.
    #[must_use]
    pub fn new(namespace: NamespaceKernel) -> Self {
        Self { namespace }
    }

    /// Return the underlying namespace kernel.
    #[must_use]
    pub fn namespace(&self) -> &NamespaceKernel {
        &self.namespace
    }

    /// Publish authority for the namespace trust boundary.
    #[must_use]
    pub fn publish_capability(&self) -> FabricCapability {
        FabricCapability::Publish {
            subject: self.namespace.trust_boundary_pattern(),
        }
    }

    /// Subscribe authority for the namespace trust boundary.
    #[must_use]
    pub fn subscribe_capability(&self) -> FabricCapability {
        FabricCapability::Subscribe {
            subject: self.namespace.trust_boundary_pattern(),
        }
    }

    /// Stream-capture authority for the namespace's durable capture selector.
    #[must_use]
    pub fn capture_capability(&self) -> FabricCapability {
        FabricCapability::CreateStream {
            subject: self.namespace.durable_capture_pattern(),
        }
    }

    /// Namespace-transform authority for import/export trust-boundary rewrites.
    #[must_use]
    pub fn transform_capability(&self) -> FabricCapability {
        FabricCapability::TransformSpace {
            subject: self.namespace.trust_boundary_pattern(),
        }
    }

    /// Build an explicit trust-boundary relation to another namespace.
    #[must_use]
    pub fn trust_boundary(&self, destination: NamespaceKernel) -> NamespaceTrustBoundary {
        NamespaceTrustBoundary {
            source: self.namespace.clone(),
            destination,
        }
    }
}

/// Explicit boundary between two tenant/service namespaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceTrustBoundary {
    source: NamespaceKernel,
    destination: NamespaceKernel,
}

impl NamespaceTrustBoundary {
    /// Return the source namespace.
    #[must_use]
    pub fn source(&self) -> &NamespaceKernel {
        &self.source
    }

    /// Return the destination namespace.
    #[must_use]
    pub fn destination(&self) -> &NamespaceKernel {
        &self.destination
    }

    /// Return true when the boundary crosses tenant trust domains.
    #[must_use]
    pub fn crosses_tenant_boundary(&self) -> bool {
        !self.source.same_tenant(&self.destination)
    }

    /// Return the capability required to rewrite across this boundary.
    #[must_use]
    pub fn required_transform_capability(&self) -> FabricCapability {
        FabricCapability::TransformSpace {
            subject: self.source.trust_boundary_pattern(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_registry_matches_subject_prefixes_fail_closed() {
        let registry = FabricCapabilityRegistry::default();
        registry
            .grant(FabricCapability::Publish {
                subject: SubjectPattern::new("orders.>"),
            })
            .expect("grant should succeed");

        assert!(registry.check(&FabricCapability::Publish {
            subject: SubjectPattern::new("orders.created"),
        }));
        assert!(registry.check(&FabricCapability::Publish {
            subject: SubjectPattern::new("orders.*"),
        }));
        assert!(!registry.check(&FabricCapability::Publish {
            subject: SubjectPattern::new("orders"),
        }));
        assert!(!registry.check(&FabricCapability::Publish {
            subject: SubjectPattern::new("payments.created"),
        }));

        let fail_closed = FabricCapabilityRegistry::default();
        fail_closed
            .grant(FabricCapability::Publish {
                subject: SubjectPattern::new("orders.*"),
            })
            .expect("narrow publish grant");
        assert!(!fail_closed.check(&FabricCapability::Publish {
            subject: SubjectPattern::new("orders.created.>"),
        }));
    }

    #[test]
    fn capability_registry_revokes_by_subject_and_scope() {
        let registry = FabricCapabilityRegistry::default();
        registry
            .grant(FabricCapability::Publish {
                subject: SubjectPattern::new("orders.>"),
            })
            .expect("publish grant");
        registry
            .grant(FabricCapability::Subscribe {
                subject: SubjectPattern::new("payments.>"),
            })
            .expect("subscribe grant");
        registry
            .grant(FabricCapability::AdminControl)
            .expect("admin grant");

        assert_eq!(
            registry.revoke_by_subject(&SubjectPattern::new("orders.created")),
            1
        );
        assert!(!registry.check(&FabricCapability::Publish {
            subject: SubjectPattern::new("orders.created"),
        }));
        assert!(registry.check(&FabricCapability::Subscribe {
            subject: SubjectPattern::new("payments.captured"),
        }));
        assert_eq!(
            registry.revoke_scope(FabricCapabilityScope::AdminControl),
            1
        );
        assert!(!registry.check(&FabricCapability::AdminControl));
    }

    #[test]
    fn namespace_capability_envelope_fails_closed_across_tenants() {
        let registry = FabricCapabilityRegistry::default();
        let acme_orders = NamespaceCapabilityEnvelope::new(
            NamespaceKernel::new("acme", "orders").expect("acme orders namespace"),
        );
        let bravo_orders = NamespaceKernel::new("bravo", "orders").expect("bravo orders namespace");

        registry
            .grant(acme_orders.publish_capability())
            .expect("publish capability");
        registry
            .grant(acme_orders.capture_capability())
            .expect("capture capability");

        assert!(
            registry.check(&FabricCapability::Publish {
                subject: SubjectPattern::from(
                    &acme_orders
                        .namespace()
                        .mailbox_subject("worker-1")
                        .expect("acme mailbox"),
                ),
            })
        );
        assert!(
            !registry.check(&FabricCapability::Publish {
                subject: SubjectPattern::from(
                    &bravo_orders
                        .mailbox_subject("worker-1")
                        .expect("bravo mailbox"),
                ),
            })
        );
        assert!(registry.check(&FabricCapability::CreateStream {
            subject: acme_orders.namespace().durable_capture_pattern(),
        }));
        assert!(!registry.check(&FabricCapability::CreateStream {
            subject: bravo_orders.durable_capture_pattern(),
        }));
    }

    #[test]
    fn namespace_trust_boundary_marks_cross_tenant_rewrites() {
        let acme_orders = NamespaceCapabilityEnvelope::new(
            NamespaceKernel::new("acme", "orders").expect("acme orders namespace"),
        );
        let acme_payments = NamespaceKernel::new("acme", "payments").expect("acme payments");
        let bravo_orders = NamespaceKernel::new("bravo", "orders").expect("bravo orders");

        let local = acme_orders.trust_boundary(acme_payments);
        let foreign = acme_orders.trust_boundary(bravo_orders);

        assert!(!local.crosses_tenant_boundary());
        assert!(foreign.crosses_tenant_boundary());
        assert_eq!(
            foreign.required_transform_capability(),
            FabricCapability::TransformSpace {
                subject: acme_orders.namespace().trust_boundary_pattern(),
            }
        );
    }
}
