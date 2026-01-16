//! Obligation record for the runtime.
//!
//! Obligations represent resources that must be resolved (commit, abort, etc.)
//! before their owning region can close. They implement the two-phase pattern.

use crate::types::{ObligationId, RegionId, TaskId};

/// The kind of obligation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
}

impl ObligationRecord {
    /// Creates a new obligation record.
    #[must_use]
    pub fn new(id: ObligationId, kind: ObligationKind, holder: TaskId, region: RegionId) -> Self {
        Self {
            id,
            kind,
            holder,
            region,
            state: ObligationState::Reserved,
            description: None,
        }
    }

    /// Creates an obligation with a description.
    #[must_use]
    pub fn with_description(
        id: ObligationId,
        kind: ObligationKind,
        holder: TaskId,
        region: RegionId,
        description: impl Into<String>,
    ) -> Self {
        Self {
            id,
            kind,
            holder,
            region,
            state: ObligationState::Reserved,
            description: Some(description.into()),
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
    pub fn commit(&mut self) {
        assert!(self.is_pending(), "obligation already resolved");
        self.state = ObligationState::Committed;
    }

    /// Aborts the obligation.
    ///
    /// # Panics
    ///
    /// Panics if already resolved.
    pub fn abort(&mut self) {
        assert!(self.is_pending(), "obligation already resolved");
        self.state = ObligationState::Aborted;
    }

    /// Marks the obligation as leaked.
    ///
    /// Called by the runtime when it detects that an obligation holder
    /// completed without resolving the obligation. This is an error state.
    ///
    /// # Panics
    ///
    /// Panics if already resolved.
    pub fn mark_leaked(&mut self) {
        assert!(self.is_pending(), "obligation already resolved");
        self.state = ObligationState::Leaked;
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

    fn test_ids() -> (ObligationId, TaskId, RegionId) {
        (
            ObligationId::from_arena(ArenaIndex::new(0, 0)),
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            RegionId::from_arena(ArenaIndex::new(0, 0)),
        )
    }

    #[test]
    fn obligation_state_predicates() {
        assert!(!ObligationState::Reserved.is_terminal());
        assert!(ObligationState::Committed.is_terminal());
        assert!(ObligationState::Aborted.is_terminal());
        assert!(ObligationState::Leaked.is_terminal());

        assert!(!ObligationState::Reserved.is_resolved());
        assert!(ObligationState::Committed.is_resolved());
        assert!(ObligationState::Aborted.is_resolved());
        assert!(ObligationState::Leaked.is_resolved());

        assert!(!ObligationState::Reserved.is_success());
        assert!(ObligationState::Committed.is_success());
        assert!(ObligationState::Aborted.is_success());
        assert!(!ObligationState::Leaked.is_success());

        assert!(!ObligationState::Reserved.is_leaked());
        assert!(!ObligationState::Committed.is_leaked());
        assert!(!ObligationState::Aborted.is_leaked());
        assert!(ObligationState::Leaked.is_leaked());
    }

    #[test]
    fn obligation_lifecycle_commit() {
        let (oid, tid, rid) = test_ids();
        let mut ob = ObligationRecord::new(oid, ObligationKind::SendPermit, tid, rid);

        assert!(ob.is_pending());
        assert!(!ob.is_leaked());
        assert_eq!(ob.state, ObligationState::Reserved);

        ob.commit();
        assert!(!ob.is_pending());
        assert!(!ob.is_leaked());
        assert_eq!(ob.state, ObligationState::Committed);
    }

    #[test]
    fn obligation_lifecycle_abort() {
        let (oid, tid, rid) = test_ids();
        let mut ob = ObligationRecord::new(oid, ObligationKind::Ack, tid, rid);

        ob.abort();
        assert!(!ob.is_pending());
        assert!(!ob.is_leaked());
        assert_eq!(ob.state, ObligationState::Aborted);
    }

    #[test]
    fn obligation_lifecycle_leaked() {
        let (oid, tid, rid) = test_ids();
        let mut ob = ObligationRecord::new(oid, ObligationKind::Lease, tid, rid);

        ob.mark_leaked();
        assert!(!ob.is_pending());
        assert!(ob.is_leaked());
        assert_eq!(ob.state, ObligationState::Leaked);
    }

    #[test]
    #[should_panic(expected = "obligation already resolved")]
    fn double_commit_panics() {
        let (oid, tid, rid) = test_ids();
        let mut ob = ObligationRecord::new(oid, ObligationKind::IoOp, tid, rid);
        ob.commit();
        ob.commit(); // Should panic
    }

    #[test]
    #[should_panic(expected = "obligation already resolved")]
    fn double_abort_panics() {
        let (oid, tid, rid) = test_ids();
        let mut ob = ObligationRecord::new(oid, ObligationKind::IoOp, tid, rid);
        ob.abort();
        ob.abort(); // Should panic
    }

    #[test]
    #[should_panic(expected = "obligation already resolved")]
    fn commit_after_abort_panics() {
        let (oid, tid, rid) = test_ids();
        let mut ob = ObligationRecord::new(oid, ObligationKind::SendPermit, tid, rid);
        ob.abort();
        ob.commit(); // Should panic
    }

    #[test]
    #[should_panic(expected = "obligation already resolved")]
    fn mark_leaked_after_commit_panics() {
        let (oid, tid, rid) = test_ids();
        let mut ob = ObligationRecord::new(oid, ObligationKind::SendPermit, tid, rid);
        ob.commit();
        ob.mark_leaked(); // Should panic
    }

    #[test]
    fn obligation_kinds_are_distinguishable() {
        assert_ne!(ObligationKind::SendPermit, ObligationKind::Ack);
        assert_ne!(ObligationKind::Ack, ObligationKind::Lease);
        assert_ne!(ObligationKind::Lease, ObligationKind::IoOp);
    }

    #[test]
    fn with_description_sets_description() {
        let (oid, tid, rid) = test_ids();
        let ob = ObligationRecord::with_description(
            oid,
            ObligationKind::SendPermit,
            tid,
            rid,
            "test description",
        );
        assert_eq!(ob.description, Some("test description".to_string()));
    }
}
