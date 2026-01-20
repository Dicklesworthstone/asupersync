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
    use crate::test_utils::init_test_logging;

    fn init_test(test_name: &str) {
        init_test_logging();
        crate::test_phase!(test_name);
    }

    #[test]
    fn severity_ordering() {
        init_test("severity_ordering");
        crate::assert_with_log!(
            CancelKind::User.severity() < CancelKind::Timeout.severity(),
            "User should be below Timeout",
            true,
            CancelKind::User.severity() < CancelKind::Timeout.severity()
        );
        crate::assert_with_log!(
            CancelKind::Timeout.severity() < CancelKind::FailFast.severity(),
            "Timeout should be below FailFast",
            true,
            CancelKind::Timeout.severity() < CancelKind::FailFast.severity()
        );
        crate::assert_with_log!(
            CancelKind::FailFast.severity() < CancelKind::ParentCancelled.severity(),
            "FailFast should be below ParentCancelled",
            true,
            CancelKind::FailFast.severity() < CancelKind::ParentCancelled.severity()
        );
        crate::assert_with_log!(
            CancelKind::ParentCancelled.severity() < CancelKind::Shutdown.severity(),
            "ParentCancelled should be below Shutdown",
            true,
            CancelKind::ParentCancelled.severity() < CancelKind::Shutdown.severity()
        );
        crate::test_complete!("severity_ordering");
    }

    #[test]
    fn strengthen_takes_more_severe() {
        init_test("strengthen_takes_more_severe");
        let mut reason = CancelReason::new(CancelKind::User);
        let strengthened = reason.strengthen(&CancelReason::timeout());
        crate::assert_with_log!(
            strengthened,
            "should strengthen to Timeout",
            true,
            strengthened
        );
        crate::assert_with_log!(
            reason.kind == CancelKind::Timeout,
            "kind should be Timeout",
            CancelKind::Timeout,
            reason.kind
        );

        let strengthened_shutdown = reason.strengthen(&CancelReason::shutdown());
        crate::assert_with_log!(
            strengthened_shutdown,
            "should strengthen to Shutdown",
            true,
            strengthened_shutdown
        );
        crate::assert_with_log!(
            reason.kind == CancelKind::Shutdown,
            "kind should be Shutdown",
            CancelKind::Shutdown,
            reason.kind
        );

        // Less severe should not change.
        let unchanged = !reason.strengthen(&CancelReason::timeout());
        crate::assert_with_log!(
            unchanged,
            "less severe should not change",
            true,
            unchanged
        );
        crate::assert_with_log!(
            reason.kind == CancelKind::Shutdown,
            "kind should remain Shutdown",
            CancelKind::Shutdown,
            reason.kind
        );
        crate::test_complete!("strengthen_takes_more_severe");
    }

    #[test]
    fn strengthen_is_idempotent() {
        init_test("strengthen_is_idempotent");
        let mut reason = CancelReason::timeout();
        let unchanged = !reason.strengthen(&CancelReason::timeout());
        crate::assert_with_log!(
            unchanged,
            "strengthen should be idempotent",
            true,
            unchanged
        );
        crate::assert_with_log!(
            reason.kind == CancelKind::Timeout,
            "kind should remain Timeout",
            CancelKind::Timeout,
            reason.kind
        );
        crate::test_complete!("strengthen_is_idempotent");
    }

    #[test]
    fn strengthen_is_associative() {
        init_test("strengthen_is_associative");
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

        crate::assert_with_log!(
            left == right,
            "strengthen should be associative",
            left.clone(),
            right
        );
        crate::test_complete!("strengthen_is_associative");
    }

    #[test]
    fn strengthen_same_kind_picks_deterministic_message() {
        init_test("strengthen_same_kind_picks_deterministic_message");
        let mut reason = CancelReason::user("b");
        let changed = reason.strengthen(&CancelReason::user("a"));
        crate::assert_with_log!(
            changed,
            "same-kind strengthen should change message",
            true,
            changed
        );
        crate::assert_with_log!(
            reason.kind == CancelKind::User,
            "kind should remain User",
            CancelKind::User,
            reason.kind
        );
        crate::assert_with_log!(
            reason.message == Some("a"),
            "message should be deterministic",
            Some("a"),
            reason.message
        );
        crate::test_complete!("strengthen_same_kind_picks_deterministic_message");
    }

    #[test]
    fn strengthen_resets_message_when_kind_increases() {
        init_test("strengthen_resets_message_when_kind_increases");
        let mut reason = CancelReason::user("please stop");
        let changed = reason.strengthen(&CancelReason::shutdown());
        crate::assert_with_log!(
            changed,
            "kind increase should change reason",
            true,
            changed
        );
        crate::assert_with_log!(
            reason.kind == CancelKind::Shutdown,
            "kind should be Shutdown",
            CancelKind::Shutdown,
            reason.kind
        );
        crate::assert_with_log!(
            reason.message.is_none(),
            "message should reset on kind increase",
            true,
            reason.message.is_none()
        );
        crate::test_complete!("strengthen_resets_message_when_kind_increases");
    }

    #[test]
    fn cleanup_budget_scales_with_severity() {
        init_test("cleanup_budget_scales_with_severity");
        // User cancellation gets the most generous budget
        let user_budget = CancelReason::user("stop").cleanup_budget();
        crate::assert_with_log!(
            user_budget.poll_quota == 1000,
            "user budget poll_quota should be 1000",
            1000,
            user_budget.poll_quota
        );

        // Timeout gets moderate budget
        let timeout_budget = CancelReason::timeout().cleanup_budget();
        crate::assert_with_log!(
            timeout_budget.poll_quota == 500,
            "timeout budget poll_quota should be 500",
            500,
            timeout_budget.poll_quota
        );

        // FailFast gets tight budget
        let fail_fast_budget = CancelReason::sibling_failed().cleanup_budget();
        crate::assert_with_log!(
            fail_fast_budget.poll_quota == 200,
            "fail_fast budget poll_quota should be 200",
            200,
            fail_fast_budget.poll_quota
        );

        // Shutdown gets minimal budget with highest priority
        let shutdown_budget = CancelReason::shutdown().cleanup_budget();
        crate::assert_with_log!(
            shutdown_budget.poll_quota == 50,
            "shutdown budget poll_quota should be 50",
            50,
            shutdown_budget.poll_quota
        );
        crate::assert_with_log!(
            shutdown_budget.priority == 255,
            "shutdown budget priority should be 255",
            255,
            shutdown_budget.priority
        );

        // Priority increases with severity (cancel lane needs higher priority)
        crate::assert_with_log!(
            user_budget.priority < timeout_budget.priority,
            "user priority should be below timeout",
            true,
            user_budget.priority < timeout_budget.priority
        );
        crate::assert_with_log!(
            timeout_budget.priority < fail_fast_budget.priority,
            "timeout priority should be below fail_fast",
            true,
            timeout_budget.priority < fail_fast_budget.priority
        );
        crate::assert_with_log!(
            fail_fast_budget.priority < shutdown_budget.priority,
            "fail_fast priority should be below shutdown",
            true,
            fail_fast_budget.priority < shutdown_budget.priority
        );
        crate::test_complete!("cleanup_budget_scales_with_severity");
    }
}
