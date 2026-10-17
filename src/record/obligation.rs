//! Obligation record for the runtime.
//!
//! Obligations represent resources that must be resolved (commit, abort, etc.)
//! before their owning region can close. They implement the two-phase pattern.

use crate::tracing_compat::{error, info, trace};
use crate::types::{ObligationId, RegionId, TaskId, Time};
use core::fmt;
use serde::{Deserialize, Serialize};
use std::backtrace::Backtrace;
use std::sync::Arc;

/// Source location captured at obligation acquisition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceLocation {
    /// Source file path.
    pub file: &'static str,
    /// 1-based line number.
    pub line: u32,
    /// 1-based column number.
    pub column: u32,
}

impl SourceLocation {
    /// Returns the sentinel value for an unknown source location.
    #[must_use]
    pub const fn unknown() -> Self {
        Self {
            file: "<unknown>",
            line: 0,
            column: 0,
        }
    }

    /// Builds a source location from a `std::panic::Location`.
    #[must_use]
    pub fn from_panic_location(location: &'static std::panic::Location<'static>) -> Self {
        Self {
            file: location.file(),
            line: location.line(),
            column: location.column(),
        }
    }
}

impl fmt::Display for SourceLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.file, self.line, self.column)
    }
}

/// The kind of obligation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ObligationKind {
    /// A send permit for a channel.
    SendPermit,
    /// An acknowledgement for a received message.
    Ack,
    /// A lease for a remote resource.
    Lease,
    /// A pending I/O operation.
    IoOp,
    /// A semaphore permit that must be released.
    SemaphorePermit,
    /// An open database transaction that must be committed or rolled back.
    ///
    /// The flagship application of the obligation model outside channels
    /// (br-asupersync-server-stack-hardening-eeexl1.5): an open transaction is
    /// a tracked, typed obligation, so a transaction dropped or cancelled
    /// without an explicit `commit` deterministically rolls back during drain
    /// rather than lingering.
    Transaction,
}

impl ObligationKind {
    /// Returns a short string for tracing and diagnostics.
    #[inline]
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SendPermit => "send_permit",
            Self::Ack => "ack",
            Self::Lease => "lease",
            Self::IoOp => "io_op",
            Self::SemaphorePermit => "semaphore_permit",
            Self::Transaction => "transaction",
        }
    }
}

impl fmt::Display for ObligationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The reason an obligation was aborted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObligationAbortReason {
    /// Aborted due to cancellation.
    Cancel,
    /// Aborted due to an error.
    Error,
    /// Explicitly aborted by the caller.
    Explicit,
}

impl ObligationAbortReason {
    /// Returns a short string for tracing and diagnostics.
    #[inline]
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cancel => "cancel",
            Self::Error => "error",
            Self::Explicit => "explicit",
        }
    }
}

impl fmt::Display for ObligationAbortReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Terminal lifecycle transition for an obligation.
///
/// This is the shared transition vocabulary used by the runtime record and
/// ledger. It keeps the state target and abort reason coupled so callers cannot
/// accidentally record an `Aborted` state without its reason, or attach an abort
/// reason to a non-abort terminal state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObligationResolution {
    /// The obligation was committed successfully.
    Commit,
    /// The obligation was aborted for the given reason.
    Abort(ObligationAbortReason),
    /// The holder completed without resolving the obligation.
    Leak,
}

impl ObligationResolution {
    /// Returns the terminal state represented by this resolution.
    #[inline]
    #[must_use]
    pub const fn state(self) -> ObligationState {
        match self {
            Self::Commit => ObligationState::Committed,
            Self::Abort(_) => ObligationState::Aborted,
            Self::Leak => ObligationState::Leaked,
        }
    }

    /// Returns the abort reason associated with this resolution, if any.
    #[inline]
    #[must_use]
    pub const fn abort_reason(self) -> Option<ObligationAbortReason> {
        match self {
            Self::Abort(reason) => Some(reason),
            Self::Commit | Self::Leak => None,
        }
    }
}

impl fmt::Display for ObligationResolution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Commit => f.write_str("commit"),
            Self::Abort(reason) => write!(f, "abort({reason})"),
            Self::Leak => f.write_str("leak"),
        }
    }
}

/// The state of an obligation.
///
/// Implements `inv.obligation.linear` (#18): each obligation transitions from
/// Reserved to exactly one of {Committed, Aborted, Leaked}. No re-reservation.
///
/// State transitions:
/// ```text
/// Reserved ──► Committed
///    │
///    ├────────► Aborted
///    │
///    └────────► Leaked (error: holder completed without resolving)
/// ```
///
/// All terminal states (Committed, Aborted, Leaked) are absorbing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObligationState {
    /// Obligation is reserved but not yet resolved.
    /// Blocks region close until resolved.
    Reserved,
    /// Obligation was committed (successful resolution).
    /// The effect took place (e.g., message was sent).
    Committed,
    /// Obligation was aborted (clean cancellation).
    /// No data loss, resources released.
    Aborted,
    /// ERROR: Obligation was leaked (holder completed without resolving).
    /// This indicates a bug in user code or library.
    /// In lab mode: triggers panic. In prod mode: log and attempt recovery.
    Leaked,
}

impl ObligationState {
    /// Returns true if the obligation is in a terminal state.
    #[inline]
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Committed | Self::Aborted | Self::Leaked)
    }

    /// Returns true if the obligation is resolved (not pending).
    /// Note: Leaked counts as resolved (it's terminal, just not successful).
    #[inline]
    #[must_use]
    pub const fn is_resolved(self) -> bool {
        self.is_terminal()
    }

    /// Returns true if the obligation was successfully resolved (not leaked).
    #[inline]
    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Committed | Self::Aborted)
    }

    /// Returns true if the obligation leaked (error state).
    #[inline]
    #[must_use]
    pub const fn is_leaked(self) -> bool {
        matches!(self, Self::Leaked)
    }
}

/// Internal record for an obligation in the runtime.
#[derive(Debug)]
pub struct ObligationRecord {
    /// Unique identifier for this obligation.
    pub id: ObligationId,
    /// The kind of obligation.
    pub kind: ObligationKind,
    /// The task holding this obligation.
    pub holder: TaskId,
    /// The region that owns this obligation.
    pub region: RegionId,
    /// Current state.
    pub state: ObligationState,
    /// Optional description for debugging.
    pub description: Option<String>,
    /// Source location where the obligation was acquired.
    pub acquired_at: SourceLocation,
    /// Optional backtrace captured at acquisition (debug-only).
    pub acquire_backtrace: Option<Arc<Backtrace>>,
    /// Time when the obligation was reserved.
    pub reserved_at: Time,
    /// Time when the obligation was resolved.
    pub resolved_at: Option<Time>,
    /// Reason for abort, if applicable.
    pub abort_reason: Option<ObligationAbortReason>,
}

impl ObligationRecord {
    /// Creates a new obligation record.
    #[must_use]
    pub fn new(
        id: ObligationId,
        kind: ObligationKind,
        holder: TaskId,
        region: RegionId,
        reserved_at: Time,
    ) -> Self {
        Self::new_with_context(
            id,
            kind,
            holder,
            region,
            reserved_at,
            SourceLocation::unknown(),
            None,
        )
    }

    /// Creates a new obligation record with acquisition context.
    #[must_use]
    pub fn new_with_context(
        id: ObligationId,
        kind: ObligationKind,
        holder: TaskId,
        region: RegionId,
        reserved_at: Time,
        acquired_at: SourceLocation,
        acquire_backtrace: Option<Arc<Backtrace>>,
    ) -> Self {
        trace!(
            obligation_id = ?id,
            kind = %kind,
            holder_task = ?holder,
            owning_region = ?region,
            reserved_at = ?reserved_at,
            acquired_at = %acquired_at,
            "obligation reserved"
        );
        Self {
            id,
            kind,
            holder,
            region,
            state: ObligationState::Reserved,
            description: None,
            acquired_at,
            acquire_backtrace,
            reserved_at,
            resolved_at: None,
            abort_reason: None,
        }
    }

    /// Creates an obligation with a description.
    #[must_use]
    pub fn with_description(
        id: ObligationId,
        kind: ObligationKind,
        holder: TaskId,
        region: RegionId,
        reserved_at: Time,
        description: impl Into<String>,
    ) -> Self {
        Self::with_description_and_context(
            id,
            kind,
            holder,
            region,
            reserved_at,
            description,
            SourceLocation::unknown(),
            None,
        )
    }

    /// Creates an obligation with a description and acquisition context.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn with_description_and_context(
        id: ObligationId,
        kind: ObligationKind,
        holder: TaskId,
        region: RegionId,
        reserved_at: Time,
        description: impl Into<String>,
        acquired_at: SourceLocation,
        acquire_backtrace: Option<Arc<Backtrace>>,
    ) -> Self {
        let desc = description.into();
        trace!(
            obligation_id = ?id,
            kind = %kind,
            holder_task = ?holder,
            owning_region = ?region,
            reserved_at = ?reserved_at,
            description = %desc,
            acquired_at = %acquired_at,
            "obligation reserved"
        );
        Self {
            id,
            kind,
            holder,
            region,
            state: ObligationState::Reserved,
            description: Some(desc),
            acquired_at,
            acquire_backtrace,
            reserved_at,
            resolved_at: None,
            abort_reason: None,
        }
    }

    /// Returns true if the obligation is still pending.
    #[inline]
    #[must_use]
    pub const fn is_pending(&self) -> bool {
        matches!(self.state, ObligationState::Reserved)
    }

    /// Applies a terminal lifecycle transition without emitting a trace.
    ///
    /// The runtime's `ObligationTable` settles records through this while the
    /// runtime lock is held and returns the facts to its caller, which emits
    /// the lifecycle events after the lock is released (br-asupersync-8texo0).
    /// An event emitted here would reach a tracing subscriber under that lock.
    ///
    /// # Panics
    ///
    /// Panics if already resolved.
    pub(crate) fn resolve(&mut self, now: Time, resolution: ObligationResolution) -> u64 {
        assert!(self.is_pending(), "obligation already resolved");
        self.state = resolution.state();
        self.resolved_at = Some(now);
        self.abort_reason = resolution.abort_reason();
        now.duration_since(self.reserved_at)
    }

    /// Applies a terminal lifecycle transition and emits the matching trace.
    ///
    /// This is crate-visible so the central runtime ledger can use the same
    /// record transition primitive for token-based, ID-based, and leak paths.
    ///
    /// # Panics
    ///
    /// Panics if already resolved.
    pub(crate) fn resolve_with(&mut self, now: Time, resolution: ObligationResolution) -> u64 {
        let duration_held = self.resolve(now, resolution);
        match resolution {
            ObligationResolution::Commit => {
                info!(
                    obligation_id = ?self.id,
                    kind = %self.kind,
                    duration_held_ns = duration_held,
                    "obligation committed"
                );
            }
            ObligationResolution::Abort(_) => {
                info!(
                    obligation_id = ?self.id,
                    kind = %self.kind,
                    abort_reason = ?self.abort_reason,
                    duration_held_ns = duration_held,
                    "obligation aborted"
                );
            }
            ObligationResolution::Leak => {
                error!(
                    obligation_id = ?self.id,
                    kind = %self.kind,
                    holder_task = ?self.holder,
                    owning_region = ?self.region,
                    duration_held_ns = duration_held,
                    description = ?self.description,
                    "OBLIGATION LEAKED: holder completed without resolving obligation"
                );
            }
        }
        duration_held
    }

    /// Commits the obligation.
    ///
    /// # Panics
    ///
    /// Panics if already resolved.
    pub fn commit(&mut self, now: Time) -> u64 {
        self.resolve_with(now, ObligationResolution::Commit)
    }

    /// Aborts the obligation.
    ///
    /// # Panics
    ///
    /// Panics if already resolved.
    pub fn abort(&mut self, now: Time, reason: ObligationAbortReason) -> u64 {
        self.resolve_with(now, ObligationResolution::Abort(reason))
    }

    /// Marks the obligation as leaked.
    ///
    /// Called by the runtime when it detects that an obligation holder
    /// completed without resolving the obligation. This is an error state.
    ///
    /// # Panics
    ///
    /// Panics if already resolved.
    pub fn mark_leaked(&mut self, now: Time) -> u64 {
        self.resolve_with(now, ObligationResolution::Leak)
    }

    /// Returns true if this obligation leaked.
    #[must_use]
    pub const fn is_leaked(&self) -> bool {
        self.state.is_leaked()
    }
}

#[cfg(test)]
#[path = "obligation_inline_tests.rs"]
mod tests;
