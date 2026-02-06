//! Registry capability (Spork).
//!
//! This module defines the *capability plumbing* for a Spork-style registry:
//! the registry itself is not a global singleton; instead it is carried as an
//! explicit capability on [`Cx`](crate::cx::Cx) and propagated to child tasks
//! by the region/scope APIs.
//!
//! The design goal for `bd-133q8` is deliberately narrow:
//! - Provide a capability slot on `Cx` so multiple registries can exist in one process.
//! - Avoid ambient authority (no statics, no globals).
//! - Keep the interface minimal; semantics (leases, determinism, collisions) are
//!   layered on in follow-on Spork beads.
//!
//! Follow-on work builds the actual API surface (`register/whereis/unregister`)
//! and linear/lease semantics on top of this handle.

use std::fmt;
use std::sync::Arc;

/// Capability trait for a Spork registry implementation.
///
/// Implementations are expected to provide deterministic behavior in the lab
/// runtime (stable ordering, explicit tie-breaking) and to avoid ambient
/// authority.
///
/// Note: The concrete API lives in follow-on beads. For `bd-133q8` we only
/// need a capability handle that can be carried by `Cx`.
pub trait RegistryCap: Send + Sync + 'static {}

/// Shared handle to a registry capability.
#[derive(Clone)]
pub struct RegistryHandle {
    inner: Arc<dyn RegistryCap>,
}

impl RegistryHandle {
    /// Wrap an `Arc` registry capability as a handle.
    #[must_use]
    pub fn new(inner: Arc<dyn RegistryCap>) -> Self {
        Self { inner }
    }

    /// Returns the underlying capability object.
    #[must_use]
    pub fn as_arc(&self) -> Arc<dyn RegistryCap> {
        Arc::clone(&self.inner)
    }
}

impl fmt::Debug for RegistryHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegistryHandle")
            .field("inner", &format_args!("Arc<dyn RegistryCap>(..)"))
            .finish()
    }
}
