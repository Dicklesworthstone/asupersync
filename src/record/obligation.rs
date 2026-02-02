//! Obligation record for the runtime.
//!
//! Obligations represent resources that must be resolved (commit, abort, etc.)
//! before their owning region can close. They implement the two-phase pattern.

use crate::tracing_compat::{error, info, trace};
use crate::types::{ObligationId, RegionId, TaskId, Time};
use core::fmt;
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
    /// Returns an unknown source location placeholder.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ObligationKind {
    /// A send permit for a channel.
    SendPermit,
    /// An acknowledgement for a received message.
    Ack,
    /// A lease for a remote resource.
    Lease,
    /// A pending I/O operation.
    IoOp,
}

impl ObligationKind {
    /// Returns a short string for tracing and diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SendPermit => "send_permit",
            Self::Ack => "ack",
            Self::Lease => "lease",
            Self::IoOp => "io_op",
        }
    }
}

impl fmt::Display for ObligationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The reason an obligation was aborted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// The state of an obligation.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Committed | Self::Aborted | Self::Leaked)
    }

    /// Returns true if the obligation is resolved (not pending).
    /// Note: Leaked counts as resolved (it's terminal, just not successful).
    #[must_use]
    pub const fn is_resolved(self) -> bool {
        self.is_terminal()
    }

    /// Returns true if the obligation was successfully resolved (not leaked).
    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Committed | Self::Aborted)
    }

    /// Returns true if the obligation leaked (error state).
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
    #[must_use]
    pub const fn is_pending(&self) -> bool {
        matches!(self.state, ObligationState::Reserved)
    }

    /// Commits the obligation.
    ///
    /// # Panics
    ///
    /// Panics if already resolved.
    pub fn commit(&mut self, now: Time) -> u64 {
        assert!(self.is_pending(), "obligation already resolved");
        self.state = ObligationState::Committed;
        self.resolved_at = Some(now);
        self.abort_reason = None;

        let duration_held = now.duration_since(self.reserved_at);
        info!(
            obligation_id = ?self.id,
            kind = %self.kind,
            duration_held_ns = duration_held,
            "obligation committed"
        );
        duration_held
    }

    /// Aborts the obligation.
    ///
    /// # Panics
    ///
    /// Panics if already resolved.
    pub fn abort(&mut self, now: Time, reason: ObligationAbortReason) -> u64 {
        assert!(self.is_pending(), "obligation already resolved");
        self.state = ObligationState::Aborted;
        self.resolved_at = Some(now);
        self.abort_reason = Some(reason);

        let duration_held = now.duration_since(self.reserved_at);
        info!(
            obligation_id = ?self.id,
            kind = %self.kind,
            abort_reason = %reason,
            duration_held_ns = duration_held,
            "obligation aborted"
        );
        duration_held
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
        assert!(self.is_pending(), "obligation already resolved");
        self.state = ObligationState::Leaked;
        self.resolved_at = Some(now);
        self.abort_reason = None;

        let duration_held = now.duration_since(self.reserved_at);
        error!(
            obligation_id = ?self.id,
            kind = %self.kind,
            holder_task = ?self.holder,
            owning_region = ?self.region,
            duration_held_ns = duration_held,
            description = ?self.description,
            "OBLIGATION LEAKED: holder completed without resolving obligation"
        );
        duration_held
    }

    /// Returns true if this obligation leaked.
    #[must_use]
    pub const fn is_leaked(&self) -> bool {
        self.state.is_leaked()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::ArenaIndex;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn test_ids() -> (ObligationId, TaskId, RegionId) {
        (
            ObligationId::from_arena(ArenaIndex::new(0, 0)),
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            RegionId::from_arena(ArenaIndex::new(0, 0)),
        )
    }

    #[test]
    fn obligation_state_predicates() {
        init_test("obligation_state_predicates");
        let reserved_terminal = ObligationState::Reserved.is_terminal();
        crate::assert_with_log!(
            !reserved_terminal,
            "reserved terminal",
            false,
            reserved_terminal
        );
        let committed_terminal = ObligationState::Committed.is_terminal();
        crate::assert_with_log!(
            committed_terminal,
            "committed terminal",
            true,
            committed_terminal
        );
        let aborted_terminal = ObligationState::Aborted.is_terminal();
        crate::assert_with_log!(aborted_terminal, "aborted terminal", true, aborted_terminal);
        let leaked_terminal = ObligationState::Leaked.is_terminal();
        crate::assert_with_log!(leaked_terminal, "leaked terminal", true, leaked_terminal);

        let reserved_resolved = ObligationState::Reserved.is_resolved();
        crate::assert_with_log!(
            !reserved_resolved,
            "reserved resolved",
            false,
            reserved_resolved
        );
        let committed_resolved = ObligationState::Committed.is_resolved();
        crate::assert_with_log!(
            committed_resolved,
            "committed resolved",
            true,
            committed_resolved
        );
        let aborted_resolved = ObligationState::Aborted.is_resolved();
        crate::assert_with_log!(aborted_resolved, "aborted resolved", true, aborted_resolved);
        let leaked_resolved = ObligationState::Leaked.is_resolved();
        crate::assert_with_log!(leaked_resolved, "leaked resolved", true, leaked_resolved);

        let reserved_success = ObligationState::Reserved.is_success();
        crate::assert_with_log!(
            !reserved_success,
            "reserved success",
            false,
            reserved_success
        );
        let committed_success = ObligationState::Committed.is_success();
        crate::assert_with_log!(
            committed_success,
            "committed success",
            true,
            committed_success
        );
        let aborted_success = ObligationState::Aborted.is_success();
        crate::assert_with_log!(aborted_success, "aborted success", true, aborted_success);
        let leaked_success = ObligationState::Leaked.is_success();
        crate::assert_with_log!(!leaked_success, "leaked success", false, leaked_success);

        let reserved_leaked = ObligationState::Reserved.is_leaked();
        crate::assert_with_log!(!reserved_leaked, "reserved leaked", false, reserved_leaked);
        let committed_leaked = ObligationState::Committed.is_leaked();
        crate::assert_with_log!(
            !committed_leaked,
            "committed leaked",
            false,
            committed_leaked
        );
        let aborted_leaked = ObligationState::Aborted.is_leaked();
        crate::assert_with_log!(!aborted_leaked, "aborted leaked", false, aborted_leaked);
        let leaked_leaked = ObligationState::Leaked.is_leaked();
        crate::assert_with_log!(leaked_leaked, "leaked leaked", true, leaked_leaked);
        crate::test_complete!("obligation_state_predicates");
    }

    #[test]
    fn obligation_lifecycle_commit() {
        init_test("obligation_lifecycle_commit");
        let (oid, tid, rid) = test_ids();
        let reserved_at = Time::from_nanos(10);
        let mut ob = ObligationRecord::new(oid, ObligationKind::SendPermit, tid, rid, reserved_at);

        let pending = ob.is_pending();
        crate::assert_with_log!(pending, "pending", true, pending);
        let leaked = ob.is_leaked();
        crate::assert_with_log!(!leaked, "leaked", false, leaked);
        crate::assert_with_log!(
            ob.state == ObligationState::Reserved,
            "state",
            ObligationState::Reserved,
            ob.state
        );

        let duration = ob.commit(Time::from_nanos(25));
        let pending = ob.is_pending();
        crate::assert_with_log!(!pending, "pending", false, pending);
        let leaked = ob.is_leaked();
        crate::assert_with_log!(!leaked, "leaked", false, leaked);
        crate::assert_with_log!(
            ob.state == ObligationState::Committed,
            "state",
            ObligationState::Committed,
            ob.state
        );
        crate::assert_with_log!(duration == 15, "duration", 15, duration);
        let resolved = ob.resolved_at;
        crate::assert_with_log!(
            resolved == Some(Time::from_nanos(25)),
            "resolved_at",
            Some(Time::from_nanos(25)),
            resolved
        );
        crate::test_complete!("obligation_lifecycle_commit");
    }

    #[test]
    fn obligation_lifecycle_abort() {
        init_test("obligation_lifecycle_abort");
        let (oid, tid, rid) = test_ids();
        let reserved_at = Time::from_nanos(100);
        let mut ob = ObligationRecord::new(oid, ObligationKind::Ack, tid, rid, reserved_at);

        let duration = ob.abort(Time::from_nanos(140), ObligationAbortReason::Explicit);
        let pending = ob.is_pending();
        crate::assert_with_log!(!pending, "pending", false, pending);
        let leaked = ob.is_leaked();
        crate::assert_with_log!(!leaked, "leaked", false, leaked);
        crate::assert_with_log!(
            ob.state == ObligationState::Aborted,
            "state",
            ObligationState::Aborted,
            ob.state
        );
        crate::assert_with_log!(duration == 40, "duration", 40, duration);
        let reason = ob.abort_reason;
        crate::assert_with_log!(
            reason == Some(ObligationAbortReason::Explicit),
            "abort_reason",
            Some(ObligationAbortReason::Explicit),
            reason
        );
        crate::test_complete!("obligation_lifecycle_abort");
    }

    #[test]
    fn obligation_lifecycle_leaked() {
        init_test("obligation_lifecycle_leaked");
        let (oid, tid, rid) = test_ids();
        let reserved_at = Time::from_nanos(5);
        let mut ob = ObligationRecord::new(oid, ObligationKind::Lease, tid, rid, reserved_at);

        let duration = ob.mark_leaked(Time::from_nanos(8));
        let pending = ob.is_pending();
        crate::assert_with_log!(!pending, "pending", false, pending);
        let leaked = ob.is_leaked();
        crate::assert_with_log!(leaked, "leaked", true, leaked);
        crate::assert_with_log!(
            ob.state == ObligationState::Leaked,
            "state",
            ObligationState::Leaked,
            ob.state
        );
        crate::assert_with_log!(duration == 3, "duration", 3, duration);
        crate::test_complete!("obligation_lifecycle_leaked");
    }

    #[test]
    #[should_panic(expected = "obligation already resolved")]
    fn double_commit_panics() {
        init_test("double_commit_panics");
        let (oid, tid, rid) = test_ids();
        let mut ob = ObligationRecord::new(oid, ObligationKind::IoOp, tid, rid, Time::ZERO);
        ob.commit(Time::ZERO);
        ob.commit(Time::ZERO); // Should panic
    }

    #[test]
    #[should_panic(expected = "obligation already resolved")]
    fn double_abort_panics() {
        init_test("double_abort_panics");
        let (oid, tid, rid) = test_ids();
        let mut ob = ObligationRecord::new(oid, ObligationKind::IoOp, tid, rid, Time::ZERO);
        ob.abort(Time::ZERO, ObligationAbortReason::Explicit);
        ob.abort(Time::ZERO, ObligationAbortReason::Explicit); // Should panic
    }

    #[test]
    #[should_panic(expected = "obligation already resolved")]
    fn commit_after_abort_panics() {
        init_test("commit_after_abort_panics");
        let (oid, tid, rid) = test_ids();
        let mut ob = ObligationRecord::new(oid, ObligationKind::SendPermit, tid, rid, Time::ZERO);
        ob.abort(Time::ZERO, ObligationAbortReason::Cancel);
        ob.commit(Time::ZERO); // Should panic
    }

    #[test]
    #[should_panic(expected = "obligation already resolved")]
    fn mark_leaked_after_commit_panics() {
        init_test("mark_leaked_after_commit_panics");
        let (oid, tid, rid) = test_ids();
        let mut ob = ObligationRecord::new(oid, ObligationKind::SendPermit, tid, rid, Time::ZERO);
        ob.commit(Time::ZERO);
        ob.mark_leaked(Time::ZERO); // Should panic
    }

    #[test]
    fn obligation_kinds_are_distinguishable() {
        init_test("obligation_kinds_are_distinguishable");
        crate::assert_with_log!(
            ObligationKind::SendPermit != ObligationKind::Ack,
            "send != ack",
            "not equal",
            (ObligationKind::SendPermit, ObligationKind::Ack)
        );
        crate::assert_with_log!(
            ObligationKind::Ack != ObligationKind::Lease,
            "ack != lease",
            "not equal",
            (ObligationKind::Ack, ObligationKind::Lease)
        );
        crate::assert_with_log!(
            ObligationKind::Lease != ObligationKind::IoOp,
            "lease != ioop",
            "not equal",
            (ObligationKind::Lease, ObligationKind::IoOp)
        );
        crate::test_complete!("obligation_kinds_are_distinguishable");
    }

    #[test]
    fn with_description_sets_description() {
        init_test("with_description_sets_description");
        let (oid, tid, rid) = test_ids();
        let ob = ObligationRecord::with_description(
            oid,
            ObligationKind::SendPermit,
            tid,
            rid,
            Time::ZERO,
            "test description",
        );
        crate::assert_with_log!(
            ob.description == Some("test description".to_string()),
            "description",
            Some("test description".to_string()),
            ob.description
        );
        crate::test_complete!("with_description_sets_description");
    }
}
