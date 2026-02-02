//! Capability context and scope API.
//!
//! The [`Cx`] type is the capability token that provides access to runtime effects.
//! The [`Scope`] type provides the API for spawning work within a region.
//!
//! All effects in Asupersync flow through explicit capabilities, ensuring
//! no ambient authority exists.
//!
//! # For External Crate Authors
//!
//! If you're building a framework (like fastapi_rust) that depends on Asupersync,
//! the `Cx` type is your primary interface to the runtime. You can:
//!
//! ```ignore
//! use asupersync::Cx;
//!
//! // Wrap Cx in your own context type
//! pub struct RequestContext<'a> {
//!     cx: &'a Cx,
//!     request_id: u64,
//! }
//!
//! impl<'a> RequestContext<'a> {
//!     pub fn new(cx: &'a Cx, request_id: u64) -> Self {
//!         Self { cx, request_id }
//!     }
//!
//!     // Delegate to Cx
//!     pub fn is_cancelled(&self) -> bool {
//!         self.cx.is_cancel_requested()
//!     }
//! }
//! ```
//!
//! # Module Contents
//!
//! - [`Cx`]: The capability context token
//! - [`Scope`]: API for spawning tasks and creating child regions

pub mod cx;
pub mod scope;

pub use cx::{Cx, SpanGuard};
pub use scope::Scope;
