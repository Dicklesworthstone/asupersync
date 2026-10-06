//! Two-phase, runtime-accounted name publication.

use super::{Admission, TrackedNameError, TrackedNameLease, TrackedNameRegistry};
use crate::cx::Cx;
use crate::cx::registry::NamePermit;
use crate::record::ObligationAbortReason;
use crate::runtime::obligation_mailbox::ObligationToken;
use crate::types::{RegionId, TaskId, Time};

impl TrackedNameRegistry {
    /// Reserves an invisible name and its checked runtime obligation.
    ///
    /// Setup can await while holding the returned permit. Until `commit`,
    /// `whereis` returns `None`, but a competing registration cannot take the
    /// reserved name. Setup failure, cancellation/drop, and explicit abort
    /// remove the reservation and return quota. Commit transfers the SAME
    /// runtime credit to the visible lease; it neither settles that obligation
    /// nor requests a second credit. Keep the permit within its original task.
    pub fn reserve<'a>(
        &self,
        cx: &'a Cx,
        name: impl Into<String>,
    ) -> Result<TrackedNamePermit<'a>, TrackedNameError> {
        let name = name.into();
        let mut admission = Admission::new(cx)?;
        let now = cx.now();
        cx.checkpoint().map_err(|_| TrackedNameError::Cancelled)?;
        let result = {
            self.inner
                .lock()
                .reserve(name, cx.task_id(), cx.region_id(), now)
        };
        let permit = result.map_err(TrackedNameError::Registry)?;
        Ok(TrackedNamePermit {
            registry: self.clone(),
            cx,
            permit: Some(permit),
            obligation: admission.token.take(),
        })
    }
}

/// Invisible name reservation that remains accountable during async setup.
///
/// `commit` checks the original context's cancellation checkpoint before
/// publishing. A move is not a transfer of holder liability. As with a checked
/// channel permit, callers must not let the original holder complete before
/// resolving its obligation. Forgetting a permit is ledger-visible but cannot
/// reclaim the name. No raw permit or registry mutation handle is exposed.
#[derive(Debug)]
#[must_use = "dropping the permit cancels the invisible name reservation"]
pub struct TrackedNamePermit<'a> {
    registry: TrackedNameRegistry,
    cx: &'a Cx,
    permit: Option<NamePermit>,
    obligation: Option<ObligationToken>,
}

impl TrackedNamePermit<'_> {
    /// The reserved, not yet published name.
    #[must_use]
    pub fn name(&self) -> &str {
        self.permit.as_ref().expect("live name permit").name()
    }

    /// The original holder of the checked obligation.
    #[must_use]
    pub fn holder(&self) -> TaskId {
        self.permit.as_ref().expect("live name permit").holder()
    }

    /// The region accountable for both reservation and published lease.
    #[must_use]
    pub fn region(&self) -> RegionId {
        self.permit.as_ref().expect("live name permit").region()
    }

    /// Reservation time from the original context's clock.
    #[must_use]
    pub fn reserved_at(&self) -> Time {
        self.permit.as_ref().expect("live name permit").reserved_at()
    }

    /// The same ticket will be carried by the committed lease.
    #[must_use]
    pub fn obligation_ticket(&self) -> u64 {
        self.obligation.as_ref().expect("live name obligation").ticket()
    }

    /// Publishes discovery without releasing or reacquiring runtime quota.
    ///
    /// Cancellation observed at the checkpoint aborts the still-invisible
    /// reservation. As with other two-phase primitives, a cancellation racing
    /// after that checkpoint does not undo an already committed publication.
    pub fn commit(mut self) -> Result<TrackedNameLease, TrackedNameError> {
        self.cx.checkpoint().map_err(|_| TrackedNameError::Cancelled)?;
        let permit = self.permit.take().expect("live name permit");
        let result = { self.registry.inner.lock().commit_permit(permit) };
        match result {
            Ok(lease) => Ok(TrackedNameLease {
                registry: self.registry.clone(),
                lease: Some(lease),
                obligation: self.obligation.take(),
            }),
            Err(error) => {
                // commit_permit defuses a refused raw permit. Retire its runtime
                // credit too, outside the registry lock, without fabricating a leak.
                let _ = self.abort_inner(ObligationAbortReason::Error);
                Err(TrackedNameError::Registry(error))
            }
        }
    }

    /// Cancels setup and returns its name reservation and quota immediately.
    pub fn abort(mut self) -> Result<(), TrackedNameError> {
        self.abort_inner(ObligationAbortReason::Explicit)
    }

    fn abort_inner(&mut self, reason: ObligationAbortReason) -> Result<(), TrackedNameError> {
        let removed = if let Some(permit) = self.permit.take() {
            // This private registry has no raw waiters. Reuse the recorded time
            // rather than calling an arbitrary clock driver during unwinding.
            let at = permit.reserved_at();
            self.registry
                .inner
                .lock()
                .abort_permit(permit, at)
                .map(|_| ())
                .map_err(TrackedNameError::Registry)
        } else {
            Ok(())
        };
        let accepted = self.obligation.take().is_none_or(|token| {
            token.abort(if removed.is_ok() { reason } else { ObligationAbortReason::Error })
        });
        removed?;
        if accepted { Ok(()) } else { Err(TrackedNameError::SettlementRejected) }
    }
}

impl Drop for TrackedNamePermit<'_> {
    fn drop(&mut self) {
        let _ = self.abort_inner(ObligationAbortReason::Cancel);
    }
}

#[cfg(test)]
#[path = "permit_tests.rs"]
mod tests;
