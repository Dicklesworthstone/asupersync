//!
//! This module provides diagnostic queries that answer questions like:
//! - "Why can't this region close?"
//! - "What's blocking this task?"
//! - "Why was this task cancelled?"
//! - "Which obligations look leaked?"
//!
//! Explanations are intended to be deterministic (stable ordering) and
//! cancel-safe to compute (pure reads of runtime state).
//!
//! # Example
//!
//! ```ignore
//! use asupersync::observability::Diagnostics;
//!
//! let d = Diagnostics::new(state.clone());
//! let e = d.explain_region_open(region_id);
//! println!("{e}");
//! ```

use crate::console::Console;
use crate::record::region::RegionState;
use crate::record::task::TaskState;
use crate::record::ObligationState;
use crate::runtime::state::RuntimeState;
use crate::time::TimerDriverHandle;
use crate::tracing_compat::{debug, trace, warn};
use crate::types::{CancelKind, ObligationId, RegionId, TaskId, Time};
use std::fmt;
use std::sync::Arc;

/// Diagnostics engine for runtime troubleshooting.
#[derive(Debug)]
pub struct Diagnostics {
    state: Arc<RuntimeState>,
    console: Option<Console>,
}

impl Diagnostics {
    /// Create a new diagnostics engine.
    #[must_use]
    pub fn new(state: Arc<RuntimeState>) -> Self {
        Self {
            state,
            console: None,
        }
    }

    /// Create a diagnostics engine with console output (used for richer rendering).
    #[must_use]
    pub fn with_console(state: Arc<RuntimeState>, console: Console) -> Self {
        Self {
            state,
            console: Some(console),
        }
    }

    /// Get the current logical time from the timer driver, or ZERO if unavailable.
    fn now(&self) -> Time {
        self.state
            .timer_driver()
            .map_or(Time::ZERO, TimerDriverHandle::now)
    }

    /// Explain why a region cannot close.
    ///
    /// This inspects region state, children, live tasks, and held obligations.
    #[must_use]
    pub fn explain_region_open(&self, region_id: RegionId) -> RegionOpenExplanation {
        trace!(region_id = ?region_id, "diagnostics: explain_region_open");

        let Some(region) = self.state.region(region_id) else {
            return RegionOpenExplanation {
                region_id,
                region_state: None,
                reasons: vec![Reason::RegionNotFound],
                recommendations: vec!["Verify region id is valid".to_string()],
            };
        };

        let region_state = region.state();
        if region_state == RegionState::Closed {
            return RegionOpenExplanation {
                region_id,
                region_state: Some(region_state),
                reasons: Vec::new(),
                recommendations: Vec::new(),
            };
        }

        let mut reasons = Vec::new();

        // Children first (structural).
        let mut child_ids = region.child_ids();
        child_ids.sort();
        for child_id in child_ids {
            if let Some(child) = self.state.region(child_id) {
                let child_state = child.state();
                if child_state != RegionState::Closed {
                    reasons.push(Reason::ChildRegionOpen {
                        child_id,
                        child_state,
                    });
                }
            }
        }

        // Live tasks.
        let mut task_ids = region.task_ids();
        task_ids.sort();
        for task_id in task_ids {
            if let Some(task) = self.state.task(task_id) {
                if !task.state.is_terminal() {
                    reasons.push(Reason::TaskRunning {
                        task_id,
                        task_state: task.state_name().to_string(),
                        poll_count: task.total_polls,
                    });
                }
            }
        }

        // Held obligations in this region.
        let mut held = Vec::new();
        for (_, ob) in self.state.obligations.iter() {
            if ob.region == region_id && ob.state == ObligationState::Reserved {
                held.push((ob.id, ob.holder, ob.kind));
            }
        }
        held.sort_by_key(|(id, _, _)| *id);
        for (id, holder, kind) in held {
            reasons.push(Reason::ObligationHeld {
                obligation_id: id,
                obligation_type: format!("{kind:?}"),
                holder_task: holder,
            });
        }

        let mut recommendations = Vec::new();
        if reasons
            .iter()
            .any(|r| matches!(r, Reason::ChildRegionOpen { .. }))
        {
            recommendations.push("Wait for child regions to close, or cancel them.".to_string());
        }
        if reasons
            .iter()
            .any(|r| matches!(r, Reason::TaskRunning { .. }))
        {
            recommendations
                .push("Wait for live tasks to complete, or cancel the region.".to_string());
        }
        if reasons
            .iter()
            .any(|r| matches!(r, Reason::ObligationHeld { .. }))
        {
            recommendations
                .push("Ensure obligations are committed/aborted before closing.".to_string());
        }

        debug!(
            region_id = ?region_id,
            region_state = ?region_state,
            reason_count = reasons.len(),
            "diagnostics: region open explanation computed"
        );

        RegionOpenExplanation {
            region_id,
            region_state: Some(region_state),
            reasons,
            recommendations,
        }
    }

    /// Explain what is blocking a task.
    #[must_use]
    pub fn explain_task_blocked(&self, task_id: TaskId) -> TaskBlockedExplanation {
        trace!(task_id = ?task_id, "diagnostics: explain_task_blocked");

        let Some(task) = self.state.task(task_id) else {
            return TaskBlockedExplanation {
                task_id,
                block_reason: BlockReason::TaskNotFound,
                details: Vec::new(),
                recommendations: vec!["Verify task id is valid".to_string()],
            };
        };

        let mut details = Vec::new();
        let mut recommendations = Vec::new();

        let block_reason = match &task.state {
            TaskState::Created => {
                recommendations.push("Task has not started polling yet.".to_string());
                BlockReason::NotStarted
            }
            TaskState::Running => {
                // We cannot introspect await points yet, but we can surface wake state.
                if task.wake_state.is_notified() {
                    recommendations
                        .push("Task has a pending wake; it should be scheduled soon.".to_string());
                    BlockReason::AwaitingSchedule
                } else {
                    recommendations
                        .push("Task appears to be awaiting an async operation.".to_string());
                    BlockReason::AwaitingFuture {
                        description: "unknown await point".to_string(),
                    }
                }
            }
            TaskState::CancelRequested { reason, .. } => {
                details.push(format!("cancel kind: {}", reason.kind));
                if let Some(msg) = &reason.message {
                    details.push(format!("message: {msg}"));
                }
                recommendations.push("Task is cancelling; wait for drain/finalizers.".to_string());
                BlockReason::CancelRequested {
                    reason: CancelReasonInfo::from_reason(reason.kind, reason.message),
                }
            }
            TaskState::Cancelling {
                reason,
                cleanup_budget,
            } => {
                details.push(format!("cancel kind: {}", reason.kind));
                details.push(format!(
                    "cleanup polls remaining: {}",
                    cleanup_budget.poll_quota
                ));
                BlockReason::RunningCleanup {
                    reason: CancelReasonInfo::from_reason(reason.kind, reason.message),
                    polls_remaining: cleanup_budget.poll_quota,
                }
            }
            TaskState::Finalizing {
                reason,
                cleanup_budget,
            } => {
                details.push(format!("cancel kind: {}", reason.kind));
                details.push(format!(
                    "cleanup polls remaining: {}",
                    cleanup_budget.poll_quota
                ));
                BlockReason::Finalizing {
                    reason: CancelReasonInfo::from_reason(reason.kind, reason.message),
                    polls_remaining: cleanup_budget.poll_quota,
                }
            }
            TaskState::Completed(outcome) => {
                details.push(format!("outcome: {outcome:?}"));
                BlockReason::Completed
            }
        };

        // Include waiter info as additional context.
        if !task.waiters.is_empty() {
            details.push(format!("waiters: {}", task.waiters.len()));
        }

        TaskBlockedExplanation {
            task_id,
            block_reason,
            details,
            recommendations,
        }
    }

    /// Find obligations that look leaked (still reserved) and return a snapshot.
    ///
    /// This is a low-level heuristic. For stronger guarantees, prefer lab oracles.
    #[must_use]
    pub fn find_leaked_obligations(&self) -> Vec<ObligationLeak> {
        let now = self.now();
        let mut leaks = Vec::new();

        for (_, ob) in self.state.obligations.iter() {
            if ob.state == ObligationState::Reserved {
                let age = std::time::Duration::from_nanos(now.duration_since(ob.reserved_at));
                leaks.push(ObligationLeak {
                    obligation_id: ob.id,
                    obligation_type: format!("{:?}", ob.kind),
                    holder_task: Some(ob.holder),
                    region_id: ob.region,
                    age,
                });
            }
        }

        // Deterministic ordering.
        leaks.sort_by_key(|l| (l.region_id, l.obligation_id));

        if !leaks.is_empty() {
            warn!(
                count = leaks.len(),
                "diagnostics: potential obligation leaks detected"
            );
        }

        leaks
    }
}

/// Explanation for why a region is still open.
#[derive(Debug, Clone)]
pub struct RegionOpenExplanation {
    /// Region being explained.
    pub region_id: RegionId,
    /// Current region state (if found).
    pub region_state: Option<RegionState>,
    /// Reasons preventing close.
    pub reasons: Vec<Reason>,
    /// Suggested follow-ups.
    pub recommendations: Vec<String>,
}

impl fmt::Display for RegionOpenExplanation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Region {:?} is still open.", self.region_id)?;
        if let Some(st) = self.region_state {
            writeln!(f, "  state: {st:?}")?;
        }
        for r in &self.reasons {
            writeln!(f, "  - {r}")?;
        }
        for rec in &self.recommendations {
            writeln!(f, "  -> {rec}")?;
        }
        Ok(())
    }
}

/// A reason a region cannot close.
#[derive(Debug, Clone)]
pub enum Reason {
    /// Region id not present in runtime state.
    RegionNotFound,
    /// A child region is still open.
    ChildRegionOpen {
        /// Child id.
        child_id: RegionId,
        /// Child state.
        child_state: RegionState,
    },
    /// A task in the region is still running.
    TaskRunning {
        /// Task id.
        task_id: TaskId,
        /// State name.
        task_state: String,
        /// Poll count observed.
        poll_count: u64,
    },
    /// An obligation is still reserved/held.
    ObligationHeld {
        /// Obligation id.
        obligation_id: ObligationId,
        /// Obligation kind/type.
        obligation_type: String,
        /// Task holding the obligation.
        holder_task: TaskId,
    },
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegionNotFound => write!(f, "region not found"),
            Self::ChildRegionOpen {
                child_id,
                child_state,
            } => write!(f, "child region {child_id:?} still open ({child_state:?})"),
            Self::TaskRunning {
                task_id,
                task_state,
                poll_count,
            } => write!(
                f,
                "task {task_id:?} still running (state={task_state}, polls={poll_count})"
            ),
            Self::ObligationHeld {
                obligation_id,
                obligation_type,
                holder_task,
            } => write!(
                f,
                "obligation {obligation_id:?} held by task {holder_task:?} (type={obligation_type})"
            ),
        }
    }
}

/// Explanation for why a task appears blocked.
#[derive(Debug, Clone)]
pub struct TaskBlockedExplanation {
    /// Task being explained.
    pub task_id: TaskId,
    /// Primary classification of the block.
    pub block_reason: BlockReason,
    /// Additional details (freeform, deterministic order).
    pub details: Vec<String>,
    /// Suggested follow-ups.
    pub recommendations: Vec<String>,
}

impl fmt::Display for TaskBlockedExplanation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Task {:?} blocked: {}", self.task_id, self.block_reason)?;
        for d in &self.details {
            writeln!(f, "  - {d}")?;
        }
        for rec in &self.recommendations {
            writeln!(f, "  -> {rec}")?;
        }
        Ok(())
    }
}

/// High-level classifications for why a task is blocked.
#[derive(Debug, Clone)]
pub enum BlockReason {
    /// Task id not present.
    TaskNotFound,
    /// Task has not started.
    NotStarted,
    /// Task is runnable but waiting to be scheduled.
    AwaitingSchedule,
    /// Task is awaiting an async operation.
    AwaitingFuture {
        /// Short, human-readable description of what the task is awaiting.
        description: String,
    },
    /// Cancellation requested.
    CancelRequested {
        /// Cancellation reason as observed on the task.
        reason: CancelReasonInfo,
    },
    /// Task is running cancellation cleanup.
    RunningCleanup {
        /// Cancellation reason driving cleanup.
        reason: CancelReasonInfo,
        /// Remaining poll budget at the time of inspection.
        polls_remaining: u32,
    },
    /// Task is finalizing.
    Finalizing {
        /// Cancellation reason driving finalization.
        reason: CancelReasonInfo,
        /// Remaining poll budget at the time of inspection.
        polls_remaining: u32,
    },
    /// Task is completed.
    Completed,
}

impl fmt::Display for BlockReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TaskNotFound => f.write_str("task not found"),
            Self::NotStarted => f.write_str("not started"),
            Self::AwaitingSchedule => f.write_str("awaiting schedule"),
            Self::AwaitingFuture { description } => write!(f, "awaiting future ({description})"),
            Self::CancelRequested { reason } => write!(f, "cancel requested ({reason})"),
            Self::RunningCleanup {
                reason,
                polls_remaining,
            } => write!(
                f,
                "running cleanup ({reason}, polls_remaining={polls_remaining})"
            ),
            Self::Finalizing {
                reason,
                polls_remaining,
            } => write!(
                f,
                "finalizing ({reason}, polls_remaining={polls_remaining})"
            ),
            Self::Completed => f.write_str("completed"),
        }
    }
}

/// Explanation of a cancellation chain.
#[derive(Debug, Clone)]
pub struct CancellationExplanation {
    /// The observed cancellation kind.
    pub kind: CancelKind,
    /// Optional message/context.
    pub message: Option<String>,
    /// The propagation path (root -> leaf).
    pub propagation_path: Vec<CancellationStep>,
}

/// A single step in a cancellation propagation chain.
#[derive(Debug, Clone)]
pub struct CancellationStep {
    /// Region at this step.
    pub region_id: RegionId,
    /// Cancellation kind.
    pub kind: CancelKind,
}

/// Cancellation reason info rendered for humans.
#[derive(Debug, Clone)]
pub struct CancelReasonInfo {
    /// Cancellation kind.
    pub kind: CancelKind,
    /// Optional message.
    pub message: Option<String>,
}

impl CancelReasonInfo {
    fn from_reason(kind: CancelKind, message: Option<&str>) -> Self {
        Self {
            kind,
            message: message.map(str::to_string),
        }
    }
}

impl fmt::Display for CancelReasonInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(msg) = &self.message {
            write!(f, "{} ({msg})", self.kind)
        } else {
            write!(f, "{}", self.kind)
        }
    }
}

/// A suspected leaked obligation.
#[derive(Debug, Clone)]
pub struct ObligationLeak {
    /// Obligation id.
    pub obligation_id: ObligationId,
    /// Kind/type as string for stable printing.
    pub obligation_type: String,
    /// Task holding the obligation, if known.
    pub holder_task: Option<TaskId>,
    /// Region where the obligation was created/held.
    pub region_id: RegionId,
    /// Age since creation.
    pub age: std::time::Duration,
}

#[cfg(test)]
#[allow(clippy::arc_with_non_send_sync)]
mod tests {
    use super::*;
    use crate::record::obligation::{ObligationKind, ObligationRecord};
    use crate::record::region::RegionRecord;
    use crate::record::task::{TaskRecord, TaskState};
    use crate::time::{TimerDriverHandle, VirtualClock};
    use crate::types::{Budget, CancelReason, Outcome};
    use crate::util::ArenaIndex;
    use std::sync::Arc;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn insert_child_region(state: &mut RuntimeState, parent: RegionId) -> RegionId {
        let idx = state.regions.insert(RegionRecord::new(
            RegionId::from_arena(ArenaIndex::new(0, 0)),
            Some(parent),
            Budget::INFINITE,
        ));
        let id = RegionId::from_arena(idx);
        let record = state.regions.get_mut(idx).expect("child region missing");
        record.id = id;
        let added = state
            .regions
            .get(parent.arena_index())
            .expect("parent missing")
            .add_child(id);
        crate::assert_with_log!(added.is_ok(), "child added", true, added.is_ok());
        id
    }

    fn insert_task(state: &mut RuntimeState, region: RegionId, task_state: TaskState) -> TaskId {
        let idx = state.tasks.insert(TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            region,
            Budget::INFINITE,
        ));
        let id = TaskId::from_arena(idx);
        let record = state.tasks.get_mut(idx).expect("task missing");
        record.id = id;
        record.state = task_state;
        let added = state
            .regions
            .get(region.arena_index())
            .expect("region missing")
            .add_task(id);
        crate::assert_with_log!(added.is_ok(), "task added", true, added.is_ok());
        id
    }

    fn insert_obligation(
        state: &mut RuntimeState,
        region: RegionId,
        holder: TaskId,
        kind: ObligationKind,
        reserved_at: Time,
    ) -> ObligationId {
        let idx = state.obligations.insert(ObligationRecord::new(
            ObligationId::from_arena(ArenaIndex::new(0, 0)),
            kind,
            holder,
            region,
            reserved_at,
        ));
        let id = ObligationId::from_arena(idx);
        let record = state.obligations.get_mut(idx).expect("obligation missing");
        record.id = id;
        id
    }

    #[test]
    fn test_explain_region_open_unknown_region_returns_reason() {
        init_test("test_explain_region_open_unknown_region_returns_reason");
        let state = Arc::new(RuntimeState::new());
        let diagnostics = Diagnostics::new(state);
        let missing = RegionId::new_for_test(99, 0);

        let explanation = diagnostics.explain_region_open(missing);
        crate::assert_with_log!(
            explanation.region_state.is_none(),
            "region_state none",
            true,
            explanation.region_state.is_none()
        );
        crate::assert_with_log!(
            explanation.reasons.len() == 1,
            "single reason",
            1usize,
            explanation.reasons.len()
        );
        let is_not_found = matches!(explanation.reasons.first(), Some(Reason::RegionNotFound));
        crate::assert_with_log!(is_not_found, "region not found reason", true, is_not_found);
        let has_recommendation = explanation
            .recommendations
            .iter()
            .any(|rec| rec.contains("Verify region id"));
        crate::assert_with_log!(
            has_recommendation,
            "recommendation present",
            true,
            has_recommendation
        );
        crate::test_complete!("test_explain_region_open_unknown_region_returns_reason");
    }

    #[test]
    fn test_explain_region_open_closed_region_has_no_reasons() {
        init_test("test_explain_region_open_closed_region_has_no_reasons");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let region = state.region(root).expect("root missing");
        let did_close =
            region.begin_close(None) && region.begin_finalize() && region.complete_close();
        crate::assert_with_log!(did_close, "region closed", true, did_close);

        let diagnostics = Diagnostics::new(Arc::new(state));
        let explanation = diagnostics.explain_region_open(root);
        crate::assert_with_log!(
            explanation.region_state == Some(RegionState::Closed),
            "closed state",
            true,
            explanation.region_state == Some(RegionState::Closed)
        );
        crate::assert_with_log!(
            explanation.reasons.is_empty(),
            "no reasons",
            true,
            explanation.reasons.is_empty()
        );
        crate::assert_with_log!(
            explanation.recommendations.is_empty(),
            "no recommendations",
            true,
            explanation.recommendations.is_empty()
        );
        crate::test_complete!("test_explain_region_open_closed_region_has_no_reasons");
    }

    #[test]
    fn test_explain_region_open_reports_children_tasks_obligations() {
        init_test("test_explain_region_open_reports_children_tasks_obligations");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let child = insert_child_region(&mut state, root);

        let task_id = insert_task(&mut state, root, TaskState::Running);
        let task = state
            .tasks
            .get_mut(task_id.arena_index())
            .expect("task missing");
        task.total_polls = 7;

        let obligation_id = insert_obligation(
            &mut state,
            root,
            task_id,
            ObligationKind::SendPermit,
            Time::from_millis(10),
        );

        let diagnostics = Diagnostics::new(Arc::new(state));
        let explanation = diagnostics.explain_region_open(root);

        let mut saw_child = false;
        let mut saw_task = false;
        let mut saw_obligation = false;
        for reason in &explanation.reasons {
            match reason {
                Reason::ChildRegionOpen { child_id, .. } if *child_id == child => {
                    saw_child = true;
                }
                Reason::TaskRunning {
                    task_id: id,
                    poll_count,
                    ..
                } if *id == task_id && *poll_count == 7 => {
                    saw_task = true;
                }
                Reason::ObligationHeld {
                    obligation_id: id,
                    holder_task,
                    ..
                } if *id == obligation_id && *holder_task == task_id => {
                    saw_obligation = true;
                }
                _ => {}
            }
        }
        crate::assert_with_log!(saw_child, "child reason", true, saw_child);
        crate::assert_with_log!(saw_task, "task reason", true, saw_task);
        crate::assert_with_log!(saw_obligation, "obligation reason", true, saw_obligation);

        let recs = &explanation.recommendations;
        let has_child_rec = recs.iter().any(|r| r.contains("child regions"));
        let has_task_rec = recs.iter().any(|r| r.contains("live tasks"));
        let has_obligation_rec = recs.iter().any(|r| r.contains("obligations"));
        crate::assert_with_log!(has_child_rec, "child rec", true, has_child_rec);
        crate::assert_with_log!(has_task_rec, "task rec", true, has_task_rec);
        crate::assert_with_log!(
            has_obligation_rec,
            "obligation rec",
            true,
            has_obligation_rec
        );

        let rendered = explanation.to_string();
        crate::assert_with_log!(
            rendered.contains("child region"),
            "display includes child",
            true,
            rendered.contains("child region")
        );
        crate::assert_with_log!(
            rendered.contains("obligation"),
            "display includes obligation",
            true,
            rendered.contains("obligation")
        );
        crate::test_complete!("test_explain_region_open_reports_children_tasks_obligations");
    }

    #[test]
    fn test_explain_region_open_nested_child_reports_immediate_child() {
        init_test("test_explain_region_open_nested_child_reports_immediate_child");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let child = insert_child_region(&mut state, root);
        let grandchild = insert_child_region(&mut state, child);

        let diagnostics = Diagnostics::new(Arc::new(state));
        let explanation = diagnostics.explain_region_open(child);

        let saw_grandchild = explanation.reasons.iter().any(|reason| {
            matches!(
                reason,
                Reason::ChildRegionOpen { child_id, .. } if *child_id == grandchild
            )
        });
        crate::assert_with_log!(saw_grandchild, "grandchild reason", true, saw_grandchild);
        crate::test_complete!("test_explain_region_open_nested_child_reports_immediate_child");
    }

    #[test]
    fn test_explain_task_blocked_running_notified_reports_schedule() {
        init_test("test_explain_task_blocked_running_notified_reports_schedule");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let task_id = insert_task(&mut state, root, TaskState::Running);
        let task = state
            .tasks
            .get_mut(task_id.arena_index())
            .expect("task missing");
        let notified = task.wake_state.notify();
        crate::assert_with_log!(notified, "wake notified", true, notified);
        task.waiters.push(TaskId::new_for_test(77, 0));

        let diagnostics = Diagnostics::new(Arc::new(state));
        let explanation = diagnostics.explain_task_blocked(task_id);
        crate::assert_with_log!(
            matches!(explanation.block_reason, BlockReason::AwaitingSchedule),
            "awaiting schedule",
            true,
            matches!(explanation.block_reason, BlockReason::AwaitingSchedule)
        );
        let has_waiters = explanation.details.iter().any(|d| d.contains("waiters"));
        crate::assert_with_log!(has_waiters, "waiters detail", true, has_waiters);
        crate::test_complete!("test_explain_task_blocked_running_notified_reports_schedule");
    }

    #[test]
    fn test_explain_task_blocked_cancel_requested_includes_reason() {
        init_test("test_explain_task_blocked_cancel_requested_includes_reason");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let reason = CancelReason::user("stop");
        let cleanup_budget = reason.cleanup_budget();
        let task_id = insert_task(
            &mut state,
            root,
            TaskState::CancelRequested {
                reason,
                cleanup_budget,
            },
        );

        let diagnostics = Diagnostics::new(Arc::new(state));
        let explanation = diagnostics.explain_task_blocked(task_id);
        let matches_reason = matches!(
            explanation.block_reason,
            BlockReason::CancelRequested {
                reason: CancelReasonInfo {
                    kind: CancelKind::User,
                    message: Some(_)
                }
            }
        );
        crate::assert_with_log!(matches_reason, "cancel requested", true, matches_reason);
        let rendered = explanation.to_string();
        crate::assert_with_log!(
            rendered.contains("cancel requested"),
            "display includes cancel",
            true,
            rendered.contains("cancel requested")
        );
        crate::test_complete!("test_explain_task_blocked_cancel_requested_includes_reason");
    }

    #[test]
    fn test_explain_task_blocked_completed_reports_completed() {
        init_test("test_explain_task_blocked_completed_reports_completed");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let task_id = insert_task(&mut state, root, TaskState::Completed(Outcome::Ok(())));

        let diagnostics = Diagnostics::new(Arc::new(state));
        let explanation = diagnostics.explain_task_blocked(task_id);
        crate::assert_with_log!(
            matches!(explanation.block_reason, BlockReason::Completed),
            "completed",
            true,
            matches!(explanation.block_reason, BlockReason::Completed)
        );
        crate::test_complete!("test_explain_task_blocked_completed_reports_completed");
    }

    #[test]
    fn test_find_leaked_obligations_sorted_and_aged() {
        init_test("test_find_leaked_obligations_sorted_and_aged");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let child = insert_child_region(&mut state, root);

        let clock = Arc::new(VirtualClock::starting_at(Time::from_millis(100)));
        state.set_timer_driver(TimerDriverHandle::with_virtual_clock(Arc::clone(&clock)));

        let root_task = insert_task(&mut state, root, TaskState::Running);
        let child_task = insert_task(&mut state, child, TaskState::Running);

        let root_ob = insert_obligation(
            &mut state,
            root,
            root_task,
            ObligationKind::Ack,
            Time::from_millis(10),
        );
        let child_ob = insert_obligation(
            &mut state,
            child,
            child_task,
            ObligationKind::Lease,
            Time::from_millis(20),
        );

        let diagnostics = Diagnostics::new(Arc::new(state));
        let leaks = diagnostics.find_leaked_obligations();
        crate::assert_with_log!(leaks.len() == 2, "two leaks", 2usize, leaks.len());

        crate::assert_with_log!(
            leaks[0].region_id == root,
            "root first",
            true,
            leaks[0].region_id == root
        );
        crate::assert_with_log!(
            leaks[1].region_id == child,
            "child second",
            true,
            leaks[1].region_id == child
        );
        crate::assert_with_log!(
            leaks[0].obligation_id == root_ob,
            "root obligation id",
            true,
            leaks[0].obligation_id == root_ob
        );
        crate::assert_with_log!(
            leaks[1].obligation_id == child_ob,
            "child obligation id",
            true,
            leaks[1].obligation_id == child_ob
        );

        let root_age_ms = leaks[0].age.as_millis();
        let child_age_ms = leaks[1].age.as_millis();
        crate::assert_with_log!(root_age_ms == 90, "root age", 90u128, root_age_ms);
        crate::assert_with_log!(child_age_ms == 80, "child age", 80u128, child_age_ms);

        crate::test_complete!("test_find_leaked_obligations_sorted_and_aged");
    }
}
