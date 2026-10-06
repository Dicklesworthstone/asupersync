//! Runtime-accounted name ownership over the canonical [`NameRegistry`].
//!
//! Raw registry leases deliberately retain their legacy drop-bomb contract.
//! This opt-in API instead requires a runtime-wired [`Cx`], reserves checked
//! `Lease` quota before publishing a name, and couples registry removal with
//! obligation settlement. Dropping a guard aborts both resources. A forgotten
//! guard remains visible to the runtime's holder-completion leak audit; it is
//! not a promise that `mem::forget` can reclaim the registry entry.
//!
//! The backing registry is private: raw force-removal/replacement could bypass
//! the guard's ownership and create an ABA collision at the same virtual time.
//! Clones share one canonical registry. Use one instance per runtime, and keep
//! guards within the lifetime of the task named by the admitting context. A
//! Rust move does not transfer the obligation to another task or region.

use super::registry::{NameLease, NameLeaseError, NameRegistry, RegistryCap, RegistryHandle};
use super::Cx;
use crate::record::{ObligationAbortReason, ObligationKind};
use crate::runtime::obligation_mailbox::{ObligationAdmissionError, ObligationToken};
use crate::types::{RegionId, TaskId, Time};
use parking_lot::Mutex;
use std::sync::Arc;

/// Refusal of a runtime-accounted name operation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TrackedNameError {
    /// The context's cancellation checkpoint refused the operation.
    Cancelled,
    /// A stateless context cannot provide runtime accounting.
    RuntimeRequired,
    /// The sentinel region cannot own a graded name lease.
    UnscopedRegion,
    /// Authoritative runtime admission refused the lease.
    Admission(ObligationAdmissionError),
    /// The canonical registry refused the operation.
    Registry(NameLeaseError),
    /// Cleanup freed the name, but the runtime did not accept settlement.
    /// The runtime may be gone or the original holder may already have leaked it.
    SettlementRejected,
}

impl std::fmt::Display for TrackedNameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => f.write_str("name operation cancelled"),
            Self::RuntimeRequired => f.write_str("tracked names require a runtime-wired context"),
            Self::UnscopedRegion => f.write_str("a name lease requires a non-sentinel region"),
            Self::Admission(error) => write!(f, "name obligation admission: {error}"),
            Self::Registry(error) => std::fmt::Display::fmt(error, f),
            Self::SettlementRejected => f.write_str("name removed but runtime settlement refused"),
        }
    }
}

impl std::error::Error for TrackedNameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Admission(error) => Some(error),
            Self::Registry(error) => Some(error),
            _ => None,
        }
    }
}

/// Shared registry whose name guards also own checked runtime obligations.
///
/// This wraps [`NameRegistry`], rather than maintaining a second name-resolution
/// algorithm. All write authority remains in the returned guards; lookup is
/// available through every clone. Raw leases and managed-supervisor registries
/// are unchanged and do not acquire accounting merely by existing elsewhere.
#[derive(Debug, Clone)]
pub struct TrackedNameRegistry {
    inner: Arc<Mutex<NameRegistry>>,
}

impl Default for TrackedNameRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl RegistryCap for TrackedNameRegistry {}

impl TrackedNameRegistry {
    /// Creates an empty, independently owned registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(NameRegistry::new())),
        }
    }

    /// An explicit capability handle sharing this registry's ownership.
    #[must_use]
    pub fn capability(&self) -> RegistryHandle {
        RegistryHandle::new(Arc::new(self.clone()))
    }

    /// Looks up an active name. No runtime or global registry is inferred.
    #[must_use]
    pub fn whereis(&self, name: &str) -> Option<TaskId> {
        self.inner.lock().whereis(name)
    }

    /// Publishes a name owned by `cx` and returns its runtime-accounted guard.
    ///
    /// Quota, holder liveness, and region admission are checked before registry
    /// mutation. Cancellation during an admission notification also refuses
    /// publication. On collision the unused quota is returned synchronously.
    /// All admission and settlement notifications run outside the registry lock.
    pub fn register(
        &self,
        cx: &Cx,
        name: impl Into<String>,
    ) -> Result<TrackedNameLease, TrackedNameError> {
        let name = name.into();
        let mut admission = Admission::new(cx)?;
        let now = cx.now();
        cx.checkpoint().map_err(|_| TrackedNameError::Cancelled)?;
        let result = {
            self.inner
                .lock()
                .register(name, cx.task_id(), cx.region_id(), now)
        };
        let lease = result.map_err(TrackedNameError::Registry)?;
        Ok(TrackedNameLease {
            registry: self.clone(),
            lease: Some(lease),
            obligation: admission.token.take(),
        })
    }
}

/// Owns both discovery and its runtime `Lease` obligation.
///
/// `release` removes the name and commits the runtime obligation. `abort` and
/// drop remove the name and abort the obligation. Settlement returns quota
/// synchronously; the runtime projects its terminal record on mailbox drain.
/// Deliberately forgetting this guard is detectable but does not free the name.
#[derive(Debug)]
#[must_use = "dropping the guard unregisters the name and aborts its obligation"]
pub struct TrackedNameLease {
    registry: TrackedNameRegistry,
    lease: Option<NameLease>,
    obligation: Option<ObligationToken>,
}

impl TrackedNameLease {
    /// The registered name.
    #[must_use]
    pub fn name(&self) -> &str {
        self.lease.as_ref().expect("live name guard").name()
    }

    /// The original holder; a Rust move does not change this identity.
    #[must_use]
    pub fn holder(&self) -> TaskId {
        self.lease.as_ref().expect("live name guard").holder()
    }

    /// The runtime region accountable for this lease.
    #[must_use]
    pub fn region(&self) -> RegionId {
        self.lease.as_ref().expect("live name guard").region()
    }

    /// Acquisition time from the admitting context's clock.
    #[must_use]
    pub fn acquired_at(&self) -> Time {
        self.lease.as_ref().expect("live name guard").acquired_at()
    }

    /// Stable runtime mailbox ticket for diagnostics.
    #[must_use]
    pub fn obligation_ticket(&self) -> u64 {
        self.obligation.as_ref().expect("live name obligation").ticket()
    }

    /// Removes discovery and commits the obligation, returning quota immediately.
    pub fn release(mut self) -> Result<(), TrackedNameError> {
        self.resolve(None)
    }

    /// Removes discovery and explicitly aborts the obligation.
    pub fn abort(mut self) -> Result<(), TrackedNameError> {
        self.resolve(Some(ObligationAbortReason::Explicit))
    }

    fn resolve(&mut self, abort: Option<ObligationAbortReason>) -> Result<(), TrackedNameError> {
        let Some(mut lease) = self.lease.take() else {
            return Ok(());
        };
        // Defuse the legacy drop bomb before registry cleanup can unwind. This
        // does not settle runtime credit or change registry ownership identity.
        let grade = if abort.is_some() {
            lease.abort().map(|_| ())
        } else {
            lease.release().map(|_| ())
        };
        let removed = self
            .registry
            .inner
            .lock()
            .unregister_owned_and_grant(&lease, lease.acquired_at());
        // There are no raw waiters in this private registry, so removal needs
        // no fresh clock callback. Never run user/runtime callbacks under it.
        let result = grade.and(removed).map_err(TrackedNameError::Registry);
        let token = self.obligation.take().expect("name guard owns runtime credit");
        let accepted = match (abort, result.is_ok()) {
            (None, true) => token.commit(),
            (Some(reason), true) => token.abort(reason),
            (_, false) => token.abort(ObligationAbortReason::Error),
        };
        result?;
        if accepted { Ok(()) } else { Err(TrackedNameError::SettlementRejected) }
    }
}

impl Drop for TrackedNameLease {
    fn drop(&mut self) {
        let _ = self.resolve(Some(ObligationAbortReason::Cancel));
    }
}

// A refused or panicking acquisition must abort an admitted credit, not report
// a leaked resource that the caller never received. Checked-token settlement
// suppresses arbitrary notification callbacks during an existing unwind.
struct Admission {
    token: Option<ObligationToken>,
}

impl Admission {
    fn new(cx: &Cx) -> Result<Self, TrackedNameError> {
        cx.checkpoint().map_err(|_| TrackedNameError::Cancelled)?;
        let token = cx
            .try_register_obligation_checked(ObligationKind::Lease, cx.task_id())
            .map_err(TrackedNameError::Admission)?
            .ok_or(TrackedNameError::RuntimeRequired)?;
        let admission = Self { token: Some(token) };
        if cx.region_id().as_u64() == 0 {
            return Err(TrackedNameError::UnscopedRegion);
        }
        Ok(admission)
    }
}

impl Drop for Admission {
    fn drop(&mut self) {
        if let Some(token) = self.token.take() {
            let _ = token.abort(ObligationAbortReason::Error);
        }
    }
}

#[cfg(test)]
#[path = "tracked_registry_tests.rs"]
mod tests;
