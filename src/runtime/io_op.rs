//! I/O operation obligation handle.
//!
//! `IoOp` models the two-phase I/O obligation lifecycle:
//! - submit: reserve an obligation
//! - complete: commit the obligation
//! - cancel/abort: abort the obligation
//!
//! This ensures in-flight I/O participates in region quiescence.

use crate::error::{Error, ErrorKind};
use crate::record::{ObligationAbortReason, ObligationKind};
use crate::runtime::state::RuntimeState;
use crate::types::{ObligationId, RegionId, TaskId};

/// Handle for a submitted I/O operation obligation.
#[derive(Debug)]
#[must_use = "IoOp must be completed, cancelled, aborted, or explicitly disarmed with into_raw()"]
pub struct IoOp {
    obligation: ObligationId,
    resolved: bool,
}

impl IoOp {
    /// Submit a new I/O operation obligation.
    #[allow(clippy::result_large_err)]
    pub fn submit(
        state: &mut RuntimeState,
        holder: TaskId,
        region: RegionId,
        description: Option<String>,
    ) -> Result<Self, Error> {
        let obligation =
            state.create_obligation(ObligationKind::IoOp, holder, region, description)?;
        Ok(Self {
            obligation,
            resolved: false,
        })
    }

    /// Returns the underlying obligation id.
    #[must_use]
    pub const fn id(&self) -> ObligationId {
        self.obligation
    }

    /// Returns whether this handle has already been resolved or disarmed.
    #[must_use]
    pub const fn is_resolved(&self) -> bool {
        self.resolved
    }

    /// Explicitly disarm the drop guard and return the raw obligation id.
    ///
    /// This escape hatch is for runtime-owned I/O that intentionally outlives
    /// the handle value, and for tests that need to model an external leak.
    #[must_use]
    pub fn into_raw(mut self) -> ObligationId {
        self.resolved = true;
        self.obligation
    }

    /// Completes the I/O operation, committing the obligation.
    #[allow(clippy::result_large_err)]
    pub fn complete(&mut self, state: &mut RuntimeState) -> Result<u64, Error> {
        self.resolve_with(state, RuntimeState::commit_obligation)
    }

    /// Cancels the I/O operation, aborting the obligation with `Cancel`.
    #[allow(clippy::result_large_err)]
    pub fn cancel(&mut self, state: &mut RuntimeState) -> Result<u64, Error> {
        self.resolve_with(state, |state, obligation| {
            state.abort_obligation(obligation, ObligationAbortReason::Cancel)
        })
    }

    /// Aborts the I/O operation with an explicit reason.
    #[allow(clippy::result_large_err)]
    pub fn abort(
        &mut self,
        state: &mut RuntimeState,
        reason: ObligationAbortReason,
    ) -> Result<u64, Error> {
        self.resolve_with(state, |state, obligation| {
            state.abort_obligation(obligation, reason)
        })
    }

    #[allow(clippy::result_large_err)]
    fn resolve_with(
        &mut self,
        state: &mut RuntimeState,
        resolve: impl FnOnce(&mut RuntimeState, ObligationId) -> Result<u64, Error>,
    ) -> Result<u64, Error> {
        if self.resolved {
            return Err(Error::new(ErrorKind::ObligationAlreadyResolved)
                .with_message("I/O obligation handle already resolved"));
        }

        match resolve(state, self.obligation) {
            Ok(duration) => {
                self.resolved = true;
                Ok(duration)
            }
            Err(err) => {
                // br-asupersync-bg1fil: any error from resolve means we
                // ATTEMPTED resolution. Pre-fix only ObligationAlready-
                // Resolved disarmed the handle; every other error kind
                // (transient lock-busy, runtime in-shutdown, etc.) left
                // self.resolved = false, so Drop would panic — even
                // though the obligation was either already in a terminal
                // state (lock-busy implies someone else is finishing it)
                // OR the runtime is going down anyway.
                //
                // Disarm on EVERY error kind. The Err return still
                // surfaces the failure to the caller, who can decide
                // whether to retry via a new IoOp (the obligation has
                // either been finished by another agent or will be
                // reaped by the runtime's GC/timeout sweep). Drop's
                // panic is preserved for the actual safety case it was
                // designed for: developer forgot to call complete() /
                // cancel() / abort() / into_raw() entirely.
                self.resolved = true;
                Err(err)
            }
        }
    }
}

impl Drop for IoOp {
    fn drop(&mut self) {
        if !self.resolved {
            if std::thread::panicking() {
                return;
            }
            // ubs:ignore - safety guard against resource leaks
            panic!(
                "[ASUP-E104] I/O obligation {:?} was dropped without completion, cancellation, abort, or explicit into_raw() handoff; see docs/error_codes/ASUP-E104.md",
                self.obligation
            );
        }
    }
}

#[cfg(test)]
#[path = "io_op_inline_tests.rs"]
mod tests;
