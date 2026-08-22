//! Capability context and scope API.
//!
//! The [`Cx`] type is the capability token that provides access to runtime effects.
//! The [`Scope`] type provides the API for spawning work within a region.
//!
//! All effects in Asupersync flow through explicit capabilities, ensuring
//! no ambient authority exists.
//!
//! # Canonical context and scope usage
//!
//! A runtime entry point supplies the [`Cx`]. Derive a [`Scope`] from that
//! context when an API needs an explicit ownership target, and spawn through
//! the context so every child remains region-owned.
//!
//! <!-- core-api-doctest: cx-scope -->
//! ```
//! use asupersync::{Cx, main};
//!
//! #[main]
//! async fn main(cx: &Cx) {
//!     assert!(!cx.is_cancel_requested());
//!
//!     let scope = cx.scope();
//!     assert_eq!(scope.region_id(), cx.region_id());
//!
//!     let mut child = cx
//!         .spawn(|child_cx| async move {
//!             child_cx.checkpoint().expect("child remains active");
//!             42_u8
//!         })
//!         .expect("the runtime-wired Cx has spawn authority");
//!     assert_eq!(child.join(cx).await.expect("child completes"), 42);
//! }
//! ```
//!
//! A detached context deliberately has no runtime effects. This fail-closed
//! behavior is useful in adapters that must never invent ambient authority:
//!
//! ```
//! use asupersync::{CancelKind, Cx};
//!
//! let cx = Cx::detached_cancel_context();
//! let capabilities = cx.capabilities();
//! assert!(!capabilities.spawn);
//! assert!(!capabilities.time);
//! assert!(!capabilities.io);
//!
//! cx.cancel_with(CancelKind::User, Some("adapter shutdown"));
//! assert!(cx.is_cancel_requested());
//! assert!(cx.checkpoint().is_err());
//! ```
//!
//! # Module Contents
//!
//! - [`Cx`]: The capability context token
//! - [`Scope`]: API for spawning tasks and creating child regions

pub mod cap;
pub mod capacity_ticket;
pub mod child_region;
pub mod cx;
pub mod macaroon;
pub mod registry;
pub mod scope;
pub mod scoped_cpu;
pub mod wrappers;

pub use cap::{
    All as AllCaps, CapMask, CapSet, CapSetRuntimeMask, HasIo, HasRandom, HasRemote, HasSpawn,
    HasTime, None as NoCaps, SubsetOf,
};
pub use capacity_ticket::{
    CapacityTicket, CapacityTicketId, CapacityTicketReceipt, CapacityTicketReceiptStatus,
    CapacityTicketRefusal, CapacityTicketRequest, CapacityTicketWorkKind, request_capacity_ticket,
    request_capacity_ticket_from_budget,
};
pub(crate) use cx::CancelWakerToken;
pub use cx::{
    BudgetStats, CapabilityLayerSnapshot, CapabilitySnapshot, CostBudgetStats, Cx,
    DeadlineBudgetStats, PollBudgetStats, SpanGuard,
};
pub use macaroon::{
    BindError, CaveatPredicate, MacaroonKeyRing, MacaroonToken, VerificationContext,
    VerificationError,
};
pub use registry::{
    NameLease, NameLeaseError, NameRegistry, RegistryCap, RegistryEvent, RegistryHandle,
};
pub use child_region::{ChildRegion, ChildRegionError, ChildRegionOpening, ChildRegionSpec};
pub use scope::Scope;
pub use scoped_cpu::{CpuCx, ScopedCpu, ScopedCpuError};
pub use wrappers::{
    BackgroundCaps, BackgroundContext, EntropyCaps, GrpcCaps, GrpcContext, PureCaps, WebCaps,
    WebContext, narrow,
};
