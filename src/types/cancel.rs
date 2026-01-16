//! Cancellation reason and kind types.
//!
//! Cancellation in Asupersync is a first-class protocol, not a silent drop.
//! This module defines the types that describe why and how cancellation occurred.

use super::Budget;
use core::fmt;

/// The kind of cancellation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CancelKind {
    /// Explicit cancellation requested by user code.
    User,
    /// Cancellation due to timeout/deadline.
    Timeout,
    /// Cancellation due to fail-fast policy (sibling failed).
    FailFast,
    /// Cancellation due to losing a race (another branch completed first).
    RaceLost,
    /// Cancellation due to parent region being cancelled/closing.
    ParentCancelled,
    /// Cancellation due to runtime shutdown.
    Shutdown,
}

impl CancelKind {
    /// Returns the severity of this cancellation kind.
    ///
    /// Higher severity cancellations take precedence when strengthening.
    #[must_use]
    pub const fn severity(self) -> u8 {
        match self {
            Self::User => 0,
            Self::Timeout => 1,
            Self::FailFast | Self::RaceLost => 2,
            Self::ParentCancelled => 3,
            Self::Shutdown => 4,
        }
    }
}

impl fmt::Display for CancelKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::User => write!(f, "user"),
            Self::Timeout => write!(f, "timeout"),
            Self::FailFast => write!(f, "fail-fast"),
            Self::RaceLost => write!(f, "race lost"),
            Self::ParentCancelled => write!(f, "parent cancelled"),
            Self::Shutdown => write!(f, "shutdown"),
        }
    }
}

/// The reason for a cancellation, including kind and optional context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelReason {
    /// The kind of cancellation.
    pub kind: CancelKind,
    /// Optional human-readable message (static for determinism).
    pub message: Option<&'static str>,
}

impl CancelReason {
    /// Creates a new cancellation reason with the given kind.
    #[must_use]
    pub const fn new(kind: CancelKind) -> Self {
        Self {
            kind,
            message: None,
        }
    }

    /// Creates a user cancellation reason with a message.
    #[must_use]
    pub const fn user(message: &'static str) -> Self {
        Self {
            kind: CancelKind::User,
            message: Some(message),
        }
    }

    /// Creates a timeout cancellation reason.
    #[must_use]
    pub const fn timeout() -> Self {
        Self::new(CancelKind::Timeout)
    }

    /// Creates a fail-fast cancellation reason (sibling failed).
    #[must_use]
    pub const fn sibling_failed() -> Self {
        Self::new(CancelKind::FailFast)
    }

    /// Creates a race loser cancellation reason.
    ///
    /// Used when a task is cancelled because another task in a race completed first.
    #[must_use]
    pub const fn race_loser() -> Self {
        Self::new(CancelKind::RaceLost)
    }

    /// Creates a race lost cancellation reason (alias for race_loser).
    ///
    /// Used when a task is cancelled because another task in a race completed first.
    #[must_use]
    pub const fn race_lost() -> Self {
        Self::new(CancelKind::RaceLost)
    }

    /// Creates a parent-cancelled cancellation reason.
    #[must_use]
    pub const fn parent_cancelled() -> Self {
        Self::new(CancelKind::ParentCancelled)
    }

    /// Creates a shutdown cancellation reason.
    #[must_use]
    pub const fn shutdown() -> Self {
        Self::new(CancelKind::Shutdown)
    }

    /// Strengthens this reason with another, keeping the more severe one.
    ///
    /// Returns `true` if the reason was changed.
    pub fn strengthen(&mut self, other: &Self) -> bool {
        if other.kind > self.kind {
            self.kind = other.kind;
            self.message = other.message;
            return true;
        }

        if other.kind < self.kind {
            return false;
        }

        match (self.message, other.message) {
            (None, Some(msg)) => {
                self.message = Some(msg);
                true
            }
            (Some(current), Some(candidate)) if candidate < current => {
                self.message = Some(candidate);
                true
            }
            _ => false,
        }
    }

    /// Returns true if this reason indicates shutdown.
    #[must_use]
    pub const fn is_shutdown(&self) -> bool {
        matches!(self.kind, CancelKind::Shutdown)
    }

    /// Returns the appropriate cleanup budget for this cancellation reason.
    ///
    /// Different cancellation kinds get different cleanup budgets:
    /// - **User**: Generous budget (1000 polls) for user-initiated cancellation
    /// - **Timeout**: Moderate budget (500 polls) for deadline-driven cleanup
    /// - **FailFast/RaceLost**: Tight budget (200 polls) for sibling failure cleanup
    /// - **ParentCancelled**: Tight budget (200 polls) for cascading cleanup
    /// - **Shutdown**: Minimal budget (50 polls) for urgent shutdown
    ///
    /// These budgets ensure the cancellation completeness theorem holds:
    /// tasks will reach terminal state within bounded resources.
    #[must_use]
    pub fn cleanup_budget(&self) -> Budget {
        match self.kind {
            CancelKind::User => Budget::new().with_poll_quota(1000).with_priority(200),
            CancelKind::Timeout => Budget::new().with_poll_quota(500).with_priority(210),
            CancelKind::FailFast | CancelKind::RaceLost | CancelKind::ParentCancelled => {
                Budget::new().with_poll_quota(200).with_priority(220)
            }
            CancelKind::Shutdown => Budget::new().with_poll_quota(50).with_priority(255),
        }
    }

    /// Returns the kind of this cancellation reason.
    #[must_use]
    pub const fn kind(&self) -> CancelKind {
        self.kind
    }
}

impl Default for CancelReason {
    fn default() -> Self {
        Self::new(CancelKind::User)
    }
}

impl fmt::Display for CancelReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind)?;
        if let Some(msg) = self.message {
            write!(f, ": {msg}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering() {
        assert!(CancelKind::User.severity() < CancelKind::Timeout.severity());
        assert!(CancelKind::Timeout.severity() < CancelKind::FailFast.severity());
        assert!(CancelKind::FailFast.severity() < CancelKind::ParentCancelled.severity());
        assert!(CancelKind::ParentCancelled.severity() < CancelKind::Shutdown.severity());
    }

    #[test]
    fn strengthen_takes_more_severe() {
        let mut reason = CancelReason::new(CancelKind::User);
        assert!(reason.strengthen(&CancelReason::timeout()));
        assert_eq!(reason.kind, CancelKind::Timeout);

        assert!(reason.strengthen(&CancelReason::shutdown()));
        assert_eq!(reason.kind, CancelKind::Shutdown);

        // Less severe should not change.
        assert!(!reason.strengthen(&CancelReason::timeout()));
        assert_eq!(reason.kind, CancelKind::Shutdown);
    }

    #[test]
    fn strengthen_is_idempotent() {
        let mut reason = CancelReason::timeout();
        assert!(!reason.strengthen(&CancelReason::timeout()));
        assert_eq!(reason.kind, CancelKind::Timeout);
    }

    #[test]
    fn strengthen_is_associative() {
        fn combine(mut a: CancelReason, b: &CancelReason) -> CancelReason {
            a.strengthen(b);
            a
        }

        let a = CancelReason::user("a");
        let b = CancelReason::timeout();
        let c = CancelReason::shutdown();

        let left = combine(combine(a.clone(), &b), &c);
        let right = {
            let bc = combine(b, &c);
            combine(a, &bc)
        };

        assert_eq!(left, right);
    }

    #[test]
    fn strengthen_same_kind_picks_deterministic_message() {
        let mut reason = CancelReason::user("b");
        assert!(reason.strengthen(&CancelReason::user("a")));
        assert_eq!(reason.kind, CancelKind::User);
        assert_eq!(reason.message, Some("a"));
    }

    #[test]
    fn strengthen_resets_message_when_kind_increases() {
        let mut reason = CancelReason::user("please stop");
        assert!(reason.strengthen(&CancelReason::shutdown()));
        assert_eq!(reason.kind, CancelKind::Shutdown);
        assert_eq!(reason.message, None);
    }

    #[test]
    fn cleanup_budget_scales_with_severity() {
        // User cancellation gets the most generous budget
        let user_budget = CancelReason::user("stop").cleanup_budget();
        assert_eq!(user_budget.poll_quota, 1000);

        // Timeout gets moderate budget
        let timeout_budget = CancelReason::timeout().cleanup_budget();
        assert_eq!(timeout_budget.poll_quota, 500);

        // FailFast gets tight budget
        let fail_fast_budget = CancelReason::sibling_failed().cleanup_budget();
        assert_eq!(fail_fast_budget.poll_quota, 200);

        // Shutdown gets minimal budget with highest priority
        let shutdown_budget = CancelReason::shutdown().cleanup_budget();
        assert_eq!(shutdown_budget.poll_quota, 50);
        assert_eq!(shutdown_budget.priority, 255);

        // Priority increases with severity (cancel lane needs higher priority)
        assert!(user_budget.priority < timeout_budget.priority);
        assert!(timeout_budget.priority < fail_fast_budget.priority);
        assert!(fail_fast_budget.priority < shutdown_budget.priority);
    }
}
