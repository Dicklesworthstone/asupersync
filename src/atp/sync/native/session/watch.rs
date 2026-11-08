//! Bounded observation and explicit application over durable native history.
//!
//! This is the local polling slice of `asupersync-bi2462.71`. It reuses the
//! canonical inventories, three-way planner, guarded application and persistent
//! session. It is not a remote watcher, daemon protocol or filesystem event log.

use super::{
    NativeDirectoryError, NativeDirectorySessionReport, NativeDirectoryStatePublication,
    NativeDirectorySyncSession, PreparedNativeDirectorySessionSync, PreparedNativeDirectorySync,
    checkpoint,
};
use crate::atp::sync::DestructiveAuthorization;
use crate::cx::Cx;
use crate::time::{SleepError, sleep_cx};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(test)]
mod tests;

/// Polling and coalescing policy for one exclusively owned native session.
///
/// Every observation is a full scan under the session's existing entry, depth,
/// file-byte and total-byte limits. There is no filesystem event queue to
/// overflow. Intermediate states between scans are deliberately not recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeDirectoryWatchConfig {
    /// Minimum pause between completed scans, measured by the supplied `Cx`.
    /// Must be nonzero and fit that timer's supported horizon; scanning time is
    /// additional to this interval.
    pub poll_interval: Duration,
    /// Consecutive equal inventory pairs required before offering a review.
    /// Must be in `1..=1024`. The default coalesces changes across two scans.
    pub settle_observations: u32,
}

impl Default for NativeDirectoryWatchConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(1),
            settle_observations: 2,
        }
    }
}

impl NativeDirectoryWatchConfig {
    fn validate(self) -> Result<(), NativeDirectoryWatchError> {
        if self.poll_interval.is_zero()
            || self.settle_observations == 0
            || self.settle_observations > 1024
        {
            return Err(NativeDirectoryWatchError::InvalidConfig);
        }
        Ok(())
    }
}

/// A watch could not observe or apply its next reviewed change.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NativeDirectoryWatchError {
    /// The interval or stability requirement is outside the supported bounds.
    #[error(
        "native directory watch requires a nonzero interval within the timer horizon and 1..=1024 stable observations"
    )]
    InvalidConfig,
    /// A canonical inventory, session or application operation was refused.
    #[error("native directory watch: {0}")]
    Native(#[from] NativeDirectoryError),
    /// The explicit context's timer is unavailable or its wait was cancelled.
    #[error("native directory watch timer: {0}")]
    Timer(#[from] SleepError),
    /// Application or decline was requested without an outstanding review.
    #[error("native directory watch has no pending review")]
    NoPendingReview,
    /// The supplied identity is not the exact currently pending review.
    #[error("native directory watch review identity does not match the pending plan")]
    ReviewMismatch,
    /// An incomplete or uncertain application requires caller intervention.
    #[error(
        "native directory watch stopped after an incomplete application; inspect its receipt and recover explicitly"
    )]
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InventoryFingerprint {
    generation: u64,
    local: [u8; 32],
    remote: [u8; 32],
}

impl InventoryFingerprint {
    fn from_prepared(generation: u64, prepared: &PreparedNativeDirectorySync) -> Self {
        Self {
            generation,
            local: prepared.local().manifest().tree_root(),
            remote: prepared.remote().manifest().tree_root(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Candidate {
    fingerprint: InventoryFingerprint,
    observations: u32,
}

/// Serial change observation with one opaque review and explicit effect grants.
///
/// `next_review` only scans. The caller may inspect or decline its result, or
/// pass its exact identity and independent destructive grants to `apply_pending`.
/// This preserves the report-only meaning of [`crate::atp::sync::SyncMode::Watch`]:
/// observing a change never implicitly authorizes overwrites or deletions. An
/// application can implement an explicitly requested continuous policy by
/// reviewing each returned plan and supplying only its allowed grants.
///
/// The watch owns the existing session and writer lease. It keeps at most one
/// candidate fingerprint and one bounded native plan; it starts no background
/// loop and holds no event backlog. A pending plan pauses scanning until the
/// caller applies or declines it. Application still revalidates actual roots,
/// ancestry, objects and content through the canonical engine, so settling is
/// not a substitute for stale-plan guards or exclusive ownership of the trees.
///
/// Dropping a timer wait is harmless. Dropping an active scan fences the session
/// until drop and explicit reopen: its scoped blocking job may still be retiring
/// and retains the writer lease. Awaited cancellation retires that job before
/// returning. Application uses the existing drained job and preserves its actual
/// partial receipt. Any failed or incomplete application stops this watch; it
/// does not silently replan around effects that need recovery.
///
/// No receipts or prior staging jobs are accumulated or removed by this type.
/// Callers must retain application receipts and bound the number or total bytes
/// of authorized applications when a long-lived policy could retain many jobs.
#[derive(Debug)]
pub struct NativeDirectoryWatch {
    session: NativeDirectorySyncSession,
    config: NativeDirectoryWatchConfig,
    candidate: Option<Candidate>,
    observed: Option<InventoryFingerprint>,
    pending: Option<PreparedNativeDirectorySync>,
    wait_before_scan: bool,
    stopped: bool,
}

impl NativeDirectorySyncSession {
    /// Observe changes using this session's durable common history.
    ///
    /// Configuration and session readiness are checked without starting work.
    /// Existing `prepare` and `apply` semantics are unchanged. The watch's first
    /// settled inventory pair is offered even when it requires no file changes,
    /// allowing an explicit application to establish or advance common history.
    ///
    /// # Errors
    /// Refuses invalid polling limits or a session already requiring reopen.
    pub fn into_watch(
        self,
        config: NativeDirectoryWatchConfig,
    ) -> Result<NativeDirectoryWatch, NativeDirectoryWatchError> {
        config.validate()?;
        self.require_ready()?;
        Ok(NativeDirectoryWatch {
            session: self,
            config,
            candidate: None,
            observed: None,
            pending: None,
            wait_before_scan: false,
            stopped: false,
        })
    }
}

impl NativeDirectoryWatch {
    /// Last durably observed common-baseline generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.session.generation()
    }

    /// Private history directory still protected by the session's writer lease.
    #[must_use]
    pub fn state_directory(&self) -> &Path {
        self.session.state_directory()
    }

    /// Whether an application failed or an abandoned operation requires reopen.
    #[must_use]
    pub const fn is_stopped(&self) -> bool {
        self.stopped || self.session.is_fenced()
    }

    /// Current opaque review; inspecting it never authorizes application.
    #[must_use]
    pub const fn pending_review(&self) -> Option<&PreparedNativeDirectorySync> {
        self.pending.as_ref()
    }

    /// Return the owned session without clearing its uncertainty fence.
    ///
    /// Any pending read-only plan is dropped. A fenced session still refuses
    /// preparation and application until it is dropped and explicitly reopened.
    #[must_use]
    pub fn into_session(self) -> NativeDirectorySyncSession {
        self.session
    }

    /// Wait for a settled inventory pair different from the last offered pair.
    ///
    /// An existing pending review is returned unchanged. Otherwise scans run
    /// serially, separated by `poll_interval` using this call's authorized timer.
    /// The first scan is immediate. The same content seen under a newly minted
    /// plan identity is not a new change. Declined content remains suppressed
    /// until either side changes; successful application suppresses the resulting
    /// converged pair under its newly persisted generation.
    ///
    /// A failed or unstable scan is surfaced without applying anything. The
    /// caller can retry an awaited scan failure; a dropped in-flight scan instead
    /// fences the session so another call cannot overlap its retiring worker.
    ///
    /// # Errors
    /// Refuses a stopped/fenced session, unavailable time authority, cancellation,
    /// invalid or unstable roots, exceeded inventory limits and filesystem errors.
    pub async fn next_review(
        &mut self,
        cx: &Cx,
    ) -> Result<&PreparedNativeDirectorySync, NativeDirectoryWatchError> {
        self.ensure_pending(cx).await?;
        self.pending
            .as_ref()
            .ok_or(NativeDirectoryWatchError::NoPendingReview)
    }

    async fn ensure_pending(&mut self, cx: &Cx) -> Result<(), NativeDirectoryWatchError> {
        self.require_running()?;
        checkpoint(cx)?;
        // Even the first scan belongs to a timer-driven watch. Fail before
        // dispatching it if later polling cannot have an authorized wake source.
        let driver = cx.timer_driver().ok_or(SleepError::TimerUnavailable)?;
        if self.config.poll_interval > driver.max_timer_duration() {
            return Err(NativeDirectoryWatchError::InvalidConfig);
        }
        while self.pending.is_none() {
            if self.wait_before_scan {
                sleep_cx(cx, self.config.poll_interval).await?;
            }
            self.session.require_ready()?;
            self.wait_before_scan = true;
            // prepare_owned does not clear this fence. A dropped await leaves
            // it in place, including if into_session is used afterwards. The
            // scoped worker retains the same lease until actual retirement.
            self.session.fenced = true;
            let result = self.session.prepare_owned(cx).await;
            self.session.fenced = false;
            match result {
                Ok(prepared) => {
                    self.observe(prepared);
                }
                Err(error) => {
                    self.candidate = None;
                    return Err(error.into());
                }
            }
        }
        Ok(())
    }

    // Actual scans and deterministic tests share this transition. No timestamps
    // or execution nonces participate in content-change/coalescing decisions.
    fn observe(&mut self, prepared: PreparedNativeDirectorySync) -> bool {
        let fingerprint = InventoryFingerprint::from_prepared(self.session.generation(), &prepared);
        if self.observed == Some(fingerprint) {
            self.candidate = None;
            return false;
        }
        let observations = match self.candidate {
            Some(candidate) if candidate.fingerprint == fingerprint => {
                candidate.observations.saturating_add(1)
            }
            _ => 1,
        };
        if observations < self.config.settle_observations {
            self.candidate = Some(Candidate {
                fingerprint,
                observations,
            });
            return false;
        }
        self.candidate = None;
        self.observed = Some(fingerprint);
        self.pending = Some(prepared);
        true
    }

    /// Decline this exact pending review without filesystem or history effects.
    ///
    /// The same inventory pair is not offered again until a subsequent scan
    /// observes a change. A mismatched identity preserves the pending plan.
    ///
    /// # Errors
    /// Refuses a stopped/fenced watch, a missing review or a mismatched identity.
    pub fn decline_pending(&mut self, expected_id: &str) -> Result<(), NativeDirectoryWatchError> {
        self.check_pending(expected_id)?;
        self.pending = None;
        Ok(())
    }

    /// Apply this exact review through the existing guarded session engine.
    ///
    /// An identity mismatch returns before consuming the review or touching
    /// staging. Destructive grants remain independent; no watch configuration
    /// can bypass them. Staging, quarantine and durable baseline publication use
    /// the same rules and receipts as [`PreparedNativeDirectorySessionSync::apply`].
    ///
    /// A dry run consumes the review as an observation without advancing history.
    /// A complete durable application permits further observation. Every other
    /// actual report is returned intact and stops this watch, including any
    /// completed file effects or retained originals. An error or abandoned apply
    /// also stops the watch; `into_session` never clears an uncertainty fence.
    ///
    /// # Errors
    /// Refuses a stopped/fenced watch, a missing/mismatched review or a canonical
    /// application failure. Inspect retained staging before retrying an uncertain
    /// application; dropping or cancelling an await does not roll effects back.
    pub async fn apply_pending(
        &mut self,
        cx: &Cx,
        expected_id: &str,
        authorization: DestructiveAuthorization,
        staging_root: impl Into<PathBuf>,
    ) -> Result<NativeDirectorySessionReport, NativeDirectoryWatchError> {
        self.check_pending(expected_id)?;
        let prepared = self
            .pending
            .take()
            .ok_or(NativeDirectoryWatchError::NoPendingReview)?;
        self.candidate = None;
        self.stopped = true;
        let report = PreparedNativeDirectorySessionSync {
            session: &mut self.session,
            prepared,
        }
        .apply(cx, authorization, staging_root)
        .await?;
        let no_failure = report.sync.failure.is_none() && report.persistence_failure.is_none();
        if no_failure
            && report.sync.dry_run
            && report.publication == NativeDirectoryStatePublication::Unchanged
        {
            self.stopped = false;
        } else if no_failure
            && report.sync.complete
            && !report.sync.dry_run
            && matches!(report.publication, NativeDirectoryStatePublication::Durable { generation }
                if generation == self.session.generation())
            && let Some(baseline) = self.session.baseline()
        {
            let root = baseline.tree_root();
            self.observed = Some(InventoryFingerprint {
                generation: self.session.generation(),
                local: root,
                remote: root,
            });
            self.stopped = false;
        }
        Ok(report)
    }

    fn require_running(&self) -> Result<(), NativeDirectoryWatchError> {
        if self.stopped {
            return Err(NativeDirectoryWatchError::Stopped);
        }
        self.session.require_ready()?;
        Ok(())
    }

    fn check_pending(&self, expected_id: &str) -> Result<(), NativeDirectoryWatchError> {
        self.require_running()?;
        let pending = self
            .pending
            .as_ref()
            .ok_or(NativeDirectoryWatchError::NoPendingReview)?;
        if pending.plan_id() != expected_id {
            return Err(NativeDirectoryWatchError::ReviewMismatch);
        }
        Ok(())
    }
}
