//! 'Explain Why' diagnostics for intelligent runtime troubleshooting.
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
use crate::tracing_compat::{debug, trace, warn};
use crate::types::{CancelKind, ObligationId, RegionId, TaskId, Time};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

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
        self.state.timer_driver().map(|d| d.now()).unwrap_or(Time::ZERO)
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
        let mut child_ids = region.child_ids().to_vec();
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
        let mut task_ids = region.task_ids().to_vec();
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
        if reasons.iter().any(|r| matches!(r, Reason::ChildRegionOpen { .. })) {
            recommendations.push("Wait for child regions to close, or cancel them.".to_string());
        }
        if reasons.iter().any(|r| matches!(r, Reason::TaskRunning { .. })) {
            recommendations.push("Wait for live tasks to complete, or cancel the region.".to_string());
        }
        if reasons.iter().any(|r| matches!(r, Reason::ObligationHeld { .. })) {
            recommendations.push("Ensure obligations are committed/aborted before closing.".to_string());
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
                    recommendations.push("Task has a pending wake; it should be scheduled soon.".to_string());
                    BlockReason::AwaitingSchedule
                } else {
                    recommendations.push("Task appears to be awaiting an async operation.".to_string());
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
                    reason: CancelReasonInfo::from_reason(reason.kind, reason.message.as_deref()),
                }
            }
            TaskState::Cancelling {
                reason,
                cleanup_budget,
            } => {
                details.push(format!("cancel kind: {}", reason.kind));
                details.push(format!("cleanup polls remaining: {}", cleanup_budget.poll_quota));
                BlockReason::RunningCleanup {
                    reason: CancelReasonInfo::from_reason(reason.kind, reason.message.as_deref()),
                    polls_remaining: cleanup_budget.poll_quota,
                }
            }
            TaskState::Finalizing {
                reason,
                cleanup_budget,
            } => {
                details.push(format!("cancel kind: {}", reason.kind));
                details.push(format!("cleanup polls remaining: {}", cleanup_budget.poll_quota));
                BlockReason::Finalizing {
                    reason: CancelReasonInfo::from_reason(reason.kind, reason.message.as_deref()),
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
                let age = Duration::from_nanos(now.duration_since(ob.reserved_at));
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
            warn!(count = leaks.len(), "diagnostics: potential obligation leaks detected");
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
            } => write!(f, "child region {:?} still open ({child_state:?})", child_id),
            Self::TaskRunning {
                task_id,
                task_state,
                poll_count,
            } => write!(
                f,
                "task {:?} still running (state={task_state}, polls={poll_count})",
                task_id
            ),
            Self::ObligationHeld {
                obligation_id,
                obligation_type,
                holder_task,
            } => write!(
                f,
                "obligation {:?} held by task {:?} (type={obligation_type})",
                obligation_id, holder_task
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
    AwaitingFuture { description: String },
    /// Cancellation requested.
    CancelRequested { reason: CancelReasonInfo },
    /// Task is running cancellation cleanup.
    RunningCleanup {
        reason: CancelReasonInfo,
        polls_remaining: u32,
    },
    /// Task is finalizing.
    Finalizing {
        reason: CancelReasonInfo,
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
            } => write!(f, "running cleanup ({reason}, polls_remaining={polls_remaining})"),
            Self::Finalizing {
                reason,
                polls_remaining,
            } => write!(f, "finalizing ({reason}, polls_remaining={polls_remaining})"),
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
    pub age: Duration,
}
