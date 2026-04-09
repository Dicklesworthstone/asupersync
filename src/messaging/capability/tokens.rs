//! Static capability tokens for the FABRIC lane.
//!
//! These tokens are intentionally linear: they are owned values, they do not
//! implement `Copy` or `Clone`, and consuming APIs must take them by value.
//!
//! ```compile_fail
//! # use asupersync::messaging::class::DeliveryClass;
//! # use asupersync::messaging::ir::{CapabilityPermission, CapabilityTokenSchema, SubjectFamily};
//! # use asupersync::messaging::capability::{EventFamily, PublishPermit};
//! # let schema = CapabilityTokenSchema {
//! #     name: "fabric.publish.events".to_owned(),
//! #     families: vec![SubjectFamily::Event],
//! #     delivery_classes: vec![DeliveryClass::EphemeralInteractive],
//! #     permissions: vec![CapabilityPermission::Publish],
//! # };
//! let permit = PublishPermit::<EventFamily>::authorize(
//!     &schema,
//!     DeliveryClass::EphemeralInteractive,
//! ).unwrap();
//! let moved = permit;
//! let _reuse = permit;
//! # let _ = moved;
//! ```
//!
//! ```compile_fail
//! # use asupersync::messaging::capability::{ProtocolMarker, SessionStateMarker, SessionToken};
//! # struct DemoProtocol;
//! # impl ProtocolMarker for DemoProtocol {
//! #     const NAME: &'static str = "demo.protocol";
//! # }
//! # struct Init;
//! # impl SessionStateMarker for Init {
//! #     const NAME: &'static str = "init";
//! # }
//! let token = SessionToken::<DemoProtocol, Init>::new(42).unwrap();
//! let moved = token;
//! let _reuse = token;
//! # let _ = moved;
//! ```

use crate::messaging::class::DeliveryClass;
use crate::messaging::fabric::{CellEpoch, CellId};
use crate::messaging::ir::{CapabilityPermission, CapabilityTokenSchema, SubjectFamily};
use crate::types::Time;
use std::fmt;
use std::marker::PhantomData;
use thiserror::Error;

mod sealed {
    pub trait Sealed {}
}

/// Validation failures for static FABRIC capability tokens.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CapabilityTokenError {
    /// Capability schemas must have a stable name for diagnostics and replay.
    #[error("capability token schema name must not be empty")]
    EmptySchemaName,
    /// The capability schema did not authorize the requested subject family.
    #[error(
        "capability token schema `{schema}` does not authorize subject family `{required_family}`"
    )]
    MissingSubjectFamily {
        /// Capability schema name used for the authorization attempt.
        schema: String,
        /// Subject family required by the token's type-level marker.
        required_family: &'static str,
    },
    /// The capability schema did not authorize the requested permission.
    #[error(
        "capability token schema `{schema}` does not authorize permission `{required_permission}`"
    )]
    MissingPermission {
        /// Capability schema name used for the authorization attempt.
        schema: String,
        /// Permission required by the token type.
        required_permission: &'static str,
    },
    /// The requested delivery class is outside the schema envelope.
    #[error(
        "capability token schema `{schema}` does not authorize delivery class `{delivery_class}`"
    )]
    UnsupportedDeliveryClass {
        /// Capability schema name used for the authorization attempt.
        schema: String,
        /// Delivery class the caller attempted to bind into the token.
        delivery_class: DeliveryClass,
    },
    /// Session ids must be non-zero for deterministic diagnostics.
    #[error("session token id must be non-zero")]
    ZeroSessionId,
    /// Protocol marker names must be present for inspectable artifacts.
    #[error("protocol marker name must not be empty")]
    EmptyProtocolName,
    /// Session state marker names must be present for inspectable artifacts.
    #[error("session state marker name must not be empty")]
    EmptyStateName,
    /// Cursor-authority leases need a finite expiry boundary.
    #[error("cursor authority lease expiry must be greater than zero")]
    ZeroLeaseExpiry,
    /// Append certificates must bind to a concrete positive sequence.
    #[error("append certificate sequence must be greater than zero")]
    ZeroSequence,
}

/// Closed set of built-in subject-family markers used by static publish and
/// subscribe tokens.
pub trait SubjectFamilyTag: sealed::Sealed {
    /// Canonical FABRIC subject family authorized by this marker.
    const FAMILY: SubjectFamily;
    /// Human-readable family name used in diagnostics and display output.
    const NAME: &'static str;
}

macro_rules! subject_family_marker {
    ($name:ident, $family:expr, $label:literal) => {
        #[doc = concat!("Type-level subject-family marker for `", $label, "`.")]
        #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name;

        impl sealed::Sealed for $name {}

        impl SubjectFamilyTag for $name {
            const FAMILY: SubjectFamily = $family;
            const NAME: &'static str = $label;
        }
    };
}

subject_family_marker!(CommandFamily, SubjectFamily::Command, "command");
subject_family_marker!(EventFamily, SubjectFamily::Event, "event");
subject_family_marker!(ReplyFamily, SubjectFamily::Reply, "reply");
subject_family_marker!(ControlFamily, SubjectFamily::Control, "control");
subject_family_marker!(
    ProtocolStepFamily,
    SubjectFamily::ProtocolStep,
    "protocol_step"
);
subject_family_marker!(
    CaptureSelectorFamily,
    SubjectFamily::CaptureSelector,
    "capture_selector"
);
subject_family_marker!(
    DerivedViewFamily,
    SubjectFamily::DerivedView,
    "derived_view"
);

/// Protocol marker for session-typed conversations.
pub trait ProtocolMarker {
    /// Stable protocol identifier used for diagnostics and replay.
    const NAME: &'static str;
}

/// State marker for session-token typestate transitions.
pub trait SessionStateMarker {
    /// Stable state identifier used for diagnostics and replay.
    const NAME: &'static str;
}

/// Linear authority to publish onto a specific subject family.
#[derive(Debug, PartialEq, Eq)]
pub struct PublishPermit<S: SubjectFamilyTag> {
    schema_name: String,
    delivery_class: DeliveryClass,
    _family: PhantomData<fn() -> S>,
}

impl<S: SubjectFamilyTag> PublishPermit<S> {
    /// Authorize a publish permit against a capability schema and delivery
    /// class envelope.
    pub fn authorize(
        schema: &CapabilityTokenSchema,
        delivery_class: DeliveryClass,
    ) -> Result<Self, CapabilityTokenError> {
        validate_schema_authorization::<S>(schema, CapabilityPermission::Publish, delivery_class)?;
        Ok(Self {
            schema_name: schema.name.clone(),
            delivery_class,
            _family: PhantomData,
        })
    }

    /// Schema name used to mint this permit.
    #[must_use]
    pub fn schema_name(&self) -> &str {
        &self.schema_name
    }

    /// Subject family authorized by this permit.
    #[must_use]
    pub const fn family(&self) -> SubjectFamily {
        S::FAMILY
    }

    /// Delivery class envelope attached to this permit.
    #[must_use]
    pub const fn delivery_class(&self) -> DeliveryClass {
        self.delivery_class
    }
}

impl<S: SubjectFamilyTag> fmt::Display for PublishPermit<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "publish-permit[schema={}, family={}, class={}]",
            self.schema_name,
            S::NAME,
            self.delivery_class
        )
    }
}

/// Linear authority to register interest in a specific subject family.
#[derive(Debug, PartialEq, Eq)]
pub struct SubscribeToken<S: SubjectFamilyTag> {
    schema_name: String,
    delivery_class: DeliveryClass,
    _family: PhantomData<fn() -> S>,
}

impl<S: SubjectFamilyTag> SubscribeToken<S> {
    /// Authorize a subscription token against a capability schema and delivery
    /// class envelope.
    pub fn authorize(
        schema: &CapabilityTokenSchema,
        delivery_class: DeliveryClass,
    ) -> Result<Self, CapabilityTokenError> {
        validate_schema_authorization::<S>(
            schema,
            CapabilityPermission::Subscribe,
            delivery_class,
        )?;
        Ok(Self {
            schema_name: schema.name.clone(),
            delivery_class,
            _family: PhantomData,
        })
    }

    /// Schema name used to mint this token.
    #[must_use]
    pub fn schema_name(&self) -> &str {
        &self.schema_name
    }

    /// Subject family authorized by this token.
    #[must_use]
    pub const fn family(&self) -> SubjectFamily {
        S::FAMILY
    }

    /// Delivery class envelope attached to this token.
    #[must_use]
    pub const fn delivery_class(&self) -> DeliveryClass {
        self.delivery_class
    }
}

impl<S: SubjectFamilyTag> fmt::Display for SubscribeToken<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "subscribe-token[schema={}, family={}, class={}]",
            self.schema_name,
            S::NAME,
            self.delivery_class
        )
    }
}

/// Linear protocol-state token for session-typed conversations.
#[derive(Debug, PartialEq, Eq)]
pub struct SessionToken<P: ProtocolMarker, State: SessionStateMarker> {
    session_id: u64,
    _protocol: PhantomData<fn() -> P>,
    _state: PhantomData<fn() -> State>,
}

impl<P: ProtocolMarker, State: SessionStateMarker> SessionToken<P, State> {
    /// Create a new session token rooted at the provided typestate.
    pub fn new(session_id: u64) -> Result<Self, CapabilityTokenError> {
        validate_session_metadata::<P, State>(session_id)?;
        Ok(Self {
            session_id,
            _protocol: PhantomData,
            _state: PhantomData,
        })
    }

    /// Stable session identifier carried for diagnostics and replay.
    #[must_use]
    pub const fn session_id(&self) -> u64 {
        self.session_id
    }

    /// Advance this token into the next typestate.
    pub fn advance<NextState: SessionStateMarker>(
        self,
    ) -> Result<SessionToken<P, NextState>, CapabilityTokenError> {
        SessionToken::<P, NextState>::new(self.session_id)
    }
}

impl<P: ProtocolMarker, State: SessionStateMarker> fmt::Display for SessionToken<P, State> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "session-token[protocol={}, state={}, session_id={}]",
            P::NAME,
            State::NAME,
            self.session_id
        )
    }
}

/// Authority artifact for cursor operations scoped to a subject cell and epoch.
#[derive(Debug, PartialEq, Eq)]
pub struct CursorAuthorityLease {
    cell_id: CellId,
    epoch: CellEpoch,
    expires_at: Time,
}

impl CursorAuthorityLease {
    /// Construct a new cursor-authority lease.
    pub fn new(
        cell_id: CellId,
        epoch: CellEpoch,
        expires_at: Time,
    ) -> Result<Self, CapabilityTokenError> {
        if expires_at == Time::ZERO {
            return Err(CapabilityTokenError::ZeroLeaseExpiry);
        }
        Ok(Self {
            cell_id,
            epoch,
            expires_at,
        })
    }

    /// Subject-cell identifier bound into this lease.
    #[must_use]
    pub const fn cell_id(&self) -> CellId {
        self.cell_id
    }

    /// Epoch fence bound into this lease.
    #[must_use]
    pub const fn epoch(&self) -> CellEpoch {
        self.epoch
    }

    /// Lease expiry boundary.
    #[must_use]
    pub const fn expires_at(&self) -> Time {
        self.expires_at
    }
}

impl fmt::Display for CursorAuthorityLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cursor-authority-lease[cell={}, epoch={}:{}, expires_at_ns={}]",
            self.cell_id,
            self.epoch.membership_epoch,
            self.epoch.generation,
            self.expires_at.as_nanos()
        )
    }
}

/// Authority certificate for appending to a stream-backed subject cell.
#[derive(Debug, PartialEq, Eq)]
pub struct AppendCertificate {
    cell_id: CellId,
    epoch: CellEpoch,
    sequence: u64,
}

impl AppendCertificate {
    /// Construct a new append certificate.
    pub fn new(
        cell_id: CellId,
        epoch: CellEpoch,
        sequence: u64,
    ) -> Result<Self, CapabilityTokenError> {
        if sequence == 0 {
            return Err(CapabilityTokenError::ZeroSequence);
        }
        Ok(Self {
            cell_id,
            epoch,
            sequence,
        })
    }

    /// Subject-cell identifier bound into this certificate.
    #[must_use]
    pub const fn cell_id(&self) -> CellId {
        self.cell_id
    }

    /// Epoch fence bound into this certificate.
    #[must_use]
    pub const fn epoch(&self) -> CellEpoch {
        self.epoch
    }

    /// Stream-local append sequence authorized by this certificate.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
}

impl fmt::Display for AppendCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "append-certificate[cell={}, epoch={}:{}, sequence={}]",
            self.cell_id, self.epoch.membership_epoch, self.epoch.generation, self.sequence
        )
    }
}

/// Authority token for fencing operations on a specific subject cell epoch.
#[derive(Debug, PartialEq, Eq)]
pub struct FenceToken {
    cell_id: CellId,
    epoch: CellEpoch,
}

impl FenceToken {
    /// Construct a new fence token.
    #[must_use]
    pub const fn new(cell_id: CellId, epoch: CellEpoch) -> Self {
        Self { cell_id, epoch }
    }

    /// Subject-cell identifier fenced by this token.
    #[must_use]
    pub const fn cell_id(&self) -> CellId {
        self.cell_id
    }

    /// Epoch boundary fenced by this token.
    #[must_use]
    pub const fn epoch(&self) -> CellEpoch {
        self.epoch
    }
}

impl fmt::Display for FenceToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "fence-token[cell={}, epoch={}:{}]",
            self.cell_id, self.epoch.membership_epoch, self.epoch.generation
        )
    }
}

fn validate_schema_authorization<S: SubjectFamilyTag>(
    schema: &CapabilityTokenSchema,
    permission: CapabilityPermission,
    delivery_class: DeliveryClass,
) -> Result<(), CapabilityTokenError> {
    if schema.name.trim().is_empty() {
        return Err(CapabilityTokenError::EmptySchemaName);
    }
    if !schema.families.contains(&S::FAMILY) {
        return Err(CapabilityTokenError::MissingSubjectFamily {
            schema: schema.name.clone(),
            required_family: S::NAME,
        });
    }
    if !schema.permissions.contains(&permission) {
        return Err(CapabilityTokenError::MissingPermission {
            schema: schema.name.clone(),
            required_permission: capability_permission_name(permission),
        });
    }
    if !schema.delivery_classes.contains(&delivery_class) {
        return Err(CapabilityTokenError::UnsupportedDeliveryClass {
            schema: schema.name.clone(),
            delivery_class,
        });
    }
    Ok(())
}

fn validate_session_metadata<P: ProtocolMarker, State: SessionStateMarker>(
    session_id: u64,
) -> Result<(), CapabilityTokenError> {
    if session_id == 0 {
        return Err(CapabilityTokenError::ZeroSessionId);
    }
    if P::NAME.trim().is_empty() {
        return Err(CapabilityTokenError::EmptyProtocolName);
    }
    if State::NAME.trim().is_empty() {
        return Err(CapabilityTokenError::EmptyStateName);
    }
    Ok(())
}

const fn capability_permission_name(permission: CapabilityPermission) -> &'static str {
    match permission {
        CapabilityPermission::Publish => "publish",
        CapabilityPermission::Subscribe => "subscribe",
        CapabilityPermission::Request => "request",
        CapabilityPermission::Reply => "reply",
        CapabilityPermission::BranchAttach => "branch_attach",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messaging::fabric::CellEpoch;
    use crate::messaging::subject::SubjectPattern;

    struct DemoProtocol;
    impl ProtocolMarker for DemoProtocol {
        const NAME: &'static str = "fabric.demo";
    }

    struct Init;
    impl SessionStateMarker for Init {
        const NAME: &'static str = "init";
    }

    struct Established;
    impl SessionStateMarker for Established {
        const NAME: &'static str = "established";
    }

    struct EmptyProtocol;
    impl ProtocolMarker for EmptyProtocol {
        const NAME: &'static str = "";
    }

    fn schema_with(
        families: Vec<SubjectFamily>,
        delivery_classes: Vec<DeliveryClass>,
        permissions: Vec<CapabilityPermission>,
    ) -> CapabilityTokenSchema {
        CapabilityTokenSchema {
            name: "fabric.token.demo".to_owned(),
            families,
            delivery_classes,
            permissions,
        }
    }

    fn demo_cell_id(epoch: CellEpoch) -> CellId {
        CellId::for_partition(epoch, &SubjectPattern::new("orders.created"))
    }

    #[test]
    fn publish_permit_validates_family_permission_and_class() {
        let schema = schema_with(
            vec![SubjectFamily::Event],
            vec![DeliveryClass::EphemeralInteractive],
            vec![CapabilityPermission::Publish],
        );

        let permit =
            PublishPermit::<EventFamily>::authorize(&schema, DeliveryClass::EphemeralInteractive)
                .expect("event publish permit should authorize");

        assert_eq!(permit.schema_name(), "fabric.token.demo");
        assert_eq!(permit.family(), SubjectFamily::Event);
        assert_eq!(permit.delivery_class(), DeliveryClass::EphemeralInteractive);
    }

    #[test]
    fn subscribe_token_rejects_wrong_family() {
        let schema = schema_with(
            vec![SubjectFamily::Reply],
            vec![DeliveryClass::EphemeralInteractive],
            vec![CapabilityPermission::Subscribe],
        );

        let error =
            SubscribeToken::<EventFamily>::authorize(&schema, DeliveryClass::EphemeralInteractive)
                .expect_err("mismatched family should fail");

        assert_eq!(
            error,
            CapabilityTokenError::MissingSubjectFamily {
                schema: "fabric.token.demo".to_owned(),
                required_family: "event",
            }
        );
    }

    #[test]
    fn publish_permit_rejects_missing_permission() {
        let schema = schema_with(
            vec![SubjectFamily::Event],
            vec![DeliveryClass::EphemeralInteractive],
            vec![CapabilityPermission::Subscribe],
        );

        let error =
            PublishPermit::<EventFamily>::authorize(&schema, DeliveryClass::EphemeralInteractive)
                .expect_err("missing publish permission should fail");

        assert_eq!(
            error,
            CapabilityTokenError::MissingPermission {
                schema: "fabric.token.demo".to_owned(),
                required_permission: "publish",
            }
        );
    }

    #[test]
    fn session_token_validates_and_advances_typestate() {
        let token = SessionToken::<DemoProtocol, Init>::new(9).expect("session token");
        let next = token
            .advance::<Established>()
            .expect("session advance should preserve metadata");

        assert_eq!(next.session_id(), 9);
        assert_eq!(
            next.to_string(),
            "session-token[protocol=fabric.demo, state=established, session_id=9]"
        );
    }

    #[test]
    fn session_token_rejects_empty_protocol_name() {
        assert!(matches!(
            SessionToken::<EmptyProtocol, Init>::new(7),
            Err(CapabilityTokenError::EmptyProtocolName)
        ));
    }

    #[test]
    fn cursor_authority_lease_rejects_zero_expiry() {
        let epoch = CellEpoch::new(7, 2);
        let error = CursorAuthorityLease::new(demo_cell_id(epoch), epoch, Time::ZERO)
            .expect_err("zero expiry must fail");
        assert_eq!(error, CapabilityTokenError::ZeroLeaseExpiry);
    }

    #[test]
    fn append_certificate_rejects_zero_sequence() {
        let epoch = CellEpoch::new(11, 4);
        let error = AppendCertificate::new(demo_cell_id(epoch), epoch, 0)
            .expect_err("zero sequence must fail");
        assert_eq!(error, CapabilityTokenError::ZeroSequence);
    }

    #[test]
    fn display_formats_are_stable() {
        let schema = schema_with(
            vec![SubjectFamily::Event],
            vec![DeliveryClass::DurableOrdered],
            vec![
                CapabilityPermission::Publish,
                CapabilityPermission::Subscribe,
            ],
        );
        let epoch = CellEpoch::new(5, 3);
        let cell_id = demo_cell_id(epoch);

        let publish =
            PublishPermit::<EventFamily>::authorize(&schema, DeliveryClass::DurableOrdered)
                .expect("publish token");
        let subscribe =
            SubscribeToken::<EventFamily>::authorize(&schema, DeliveryClass::DurableOrdered)
                .expect("subscribe token");
        let session = SessionToken::<DemoProtocol, Init>::new(21).expect("session token");
        let lease =
            CursorAuthorityLease::new(cell_id, epoch, Time::from_secs(30)).expect("cursor lease");
        let append = AppendCertificate::new(cell_id, epoch, 17).expect("append cert");
        let fence = FenceToken::new(cell_id, epoch);

        assert_eq!(
            publish.to_string(),
            "publish-permit[schema=fabric.token.demo, family=event, class=durable-ordered]"
        );
        assert_eq!(
            subscribe.to_string(),
            "subscribe-token[schema=fabric.token.demo, family=event, class=durable-ordered]"
        );
        assert_eq!(
            session.to_string(),
            "session-token[protocol=fabric.demo, state=init, session_id=21]"
        );
        assert_eq!(
            lease.to_string(),
            format!(
                "cursor-authority-lease[cell={}, epoch=5:3, expires_at_ns={}]",
                cell_id,
                Time::from_secs(30).as_nanos()
            )
        );
        assert_eq!(
            append.to_string(),
            format!(
                "append-certificate[cell={cell_id}, epoch=5:3, sequence=17]"
            )
        );
        assert_eq!(
            fence.to_string(),
            format!("fence-token[cell={cell_id}, epoch=5:3]")
        );
    }
}
