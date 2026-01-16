//! Capability context and scope API.
//!
//! The `Cx` type is the capability token that provides access to runtime effects.
//! The `Scope` type provides the API for spawning work within a region.
//!
//! All effects in Asupersync flow through explicit capabilities, ensuring
//! no ambient authority exists.

pub mod cx;
pub mod scope;

pub use cx::Cx;
pub use scope::Scope;
