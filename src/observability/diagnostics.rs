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
use crate::observability::spectral_health::{
    SpectralHealthMonitor, SpectralHealthReport, SpectralThresholds,
};
use crate::record::ObligationState;
use crate::record::region::RegionState;
use crate::record::task::TaskState;
use crate::runtime::state::RuntimeState;
use crate::time::TimerDriverHandle;
use crate::tracing_compat::{debug, trace, warn};
use crate::types::{CancelKind, ObligationId, RegionId, TaskId, Time};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

/// Diagnostics engine for runtime troubleshooting.
#[derive(Debug)]
pub struct Diagnostics {
    state: Arc<RuntimeState>,
    console: Option<Console>,
    spectral_monitor: parking_lot::Mutex<SpectralHealthMonitor>,
}

impl Diagnostics {
    /// Create a new diagnostics engine.
    #[must_use]
    pub fn new(state: Arc<RuntimeState>) -> Self {
        Self {
            state,
            console: None,
            spectral_monitor: parking_lot::Mutex::new(SpectralHealthMonitor::new(
                SpectralThresholds::default(),
            )),
        }
    }

    /// Create a diagnostics engine with console output (used for richer rendering).
    #[must_use]
    pub fn with_console(state: Arc<RuntimeState>, console: Console) -> Self {
        Self {
            state,
            console: Some(console),
            spectral_monitor: parking_lot::Mutex::new(SpectralHealthMonitor::new(
                SpectralThresholds::default(),
            )),
        }
    }

    /// Get the current logical time from the timer driver, or ZERO if unavailable.
    fn now(&self) -> Time {
        self.state
            .timer_driver()
            .map_or(Time::ZERO, TimerDriverHandle::now)
    }

    fn build_task_wait_graph(&self) -> TaskWaitGraph {
        let mut task_ids: Vec<TaskId> = self
            .state
            .tasks_iter()
            .filter_map(|(_, task)| (!task.state.is_terminal()).then_some(task.id))
            .collect();
        task_ids.sort();
        let index_by_task: BTreeMap<TaskId, usize> = task_ids
            .iter()
            .enumerate()
            .map(|(i, id)| (*id, i))
            .collect();

        let mut directed_edges = Vec::new();
        for (_, task) in self.state.tasks_iter() {
            if task.state.is_terminal() {
                continue;
            }
            let Some(&target_idx) = index_by_task.get(&task.id) else {
                continue;
            };
            // waiter -> task dependency edges
            for waiter in &task.waiters {
                if let Some(&waiter_idx) = index_by_task.get(waiter) {
                    directed_edges.push((waiter_idx, target_idx));
                }
            }
        }
        directed_edges.sort_unstable();
        directed_edges.dedup();

        let undirected_edges: Vec<(usize, usize)> = directed_edges
            .iter()
            .map(|(u, v)| if u < v { (*u, *v) } else { (*v, *u) })
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();

        TaskWaitGraph {
            task_ids,
            directed_edges,
            undirected_edges,
        }
    }

    /// Analyze structural runtime health from the live task wait graph.
    ///
    /// This is a default diagnostics path and updates the monitor's spectral
    /// history each time it is called.
    #[must_use]
    pub fn analyze_structural_health(&self) -> SpectralHealthReport {
        let graph = self.build_task_wait_graph();
        let mut monitor = self.spectral_monitor.lock();
        monitor.analyze(graph.task_ids.len(), &graph.undirected_edges)
    }

    /// Analyze directional deadlock risk from wait-for dependencies.
    #[must_use]
    pub fn analyze_directional_deadlock(&self) -> DirectionalDeadlockReport {
        let graph = self.build_task_wait_graph();
        if graph.task_ids.is_empty() {
            return DirectionalDeadlockReport::empty();
        }

        let mut adjacency = vec![Vec::new(); graph.task_ids.len()];
        for &(u, v) in &graph.directed_edges {
            if u < adjacency.len() && v < adjacency.len() {
                adjacency[u].push(v);
            }
        }
        for edges in &mut adjacency {
            edges.sort_unstable();
            edges.dedup();
        }

        let sccs = strongly_connected_components(&adjacency);
        let mut components = Vec::new();
        let mut trapped = 0_u32;
        let mut cycle_nodes = 0_usize;

        for nodes in sccs {
            let has_cycle = if nodes.len() > 1 {
                true
            } else {
                let n0 = nodes[0];
                adjacency[n0].contains(&n0)
            };
            if !has_cycle {
                continue;
            }
            cycle_nodes += nodes.len();
            let mut ingress = 0_u32;
            let mut egress = 0_u32;
            for &u in &nodes {
                for &v in &adjacency[u] {
                    if nodes.binary_search(&v).is_ok() {
                        continue;
                    }
                    egress = egress.saturating_add(1);
                }
            }
            let node_set: std::collections::BTreeSet<usize> = nodes.iter().copied().collect();
            for (u, edges) in adjacency.iter().enumerate() {
                if node_set.contains(&u) {
                    continue;
                }
                for &v in edges {
                    if node_set.contains(&v) {
                        ingress = ingress.saturating_add(1);
                    }
                }
            }
            let trapped_component = egress == 0;
            if trapped_component {
                trapped = trapped.saturating_add(1);
            }
            let mut tasks: Vec<TaskId> = nodes.iter().map(|idx| graph.task_ids[*idx]).collect();
            tasks.sort();
            components.push(DeadlockCycle {
                tasks,
                ingress_edges: ingress,
                egress_edges: egress,
                trapped: trapped_component,
            });
        }

        components.sort_by_key(|c| c.tasks.len());
        components.reverse();

        #[allow(clippy::cast_precision_loss)]
        let cycle_ratio = if graph.task_ids.is_empty() {
            0.0
        } else {
            cycle_nodes as f64 / graph.task_ids.len() as f64
        };
        #[allow(clippy::cast_precision_loss)]
        let trapped_ratio = if components.is_empty() {
            0.0
        } else {
            f64::from(trapped) / components.len() as f64
        };
        let risk_score = 0.6f64
            .mul_add(trapped_ratio, 0.4 * cycle_ratio)
            .clamp(0.0, 1.0);
        let severity = if trapped > 0 {
            DeadlockSeverity::Critical
        } else if !components.is_empty() {
            DeadlockSeverity::Elevated
        } else {
            DeadlockSeverity::None
        };

        DirectionalDeadlockReport {
            severity,
            risk_score,
            cycles: components,
        }
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
        for (_, ob) in self.state.obligations_iter() {
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

        let deadlock = self.analyze_directional_deadlock();
        if deadlock.severity != DeadlockSeverity::None {
            recommendations.push(format!(
                "Directional deadlock risk {:?} (score {:.3}); inspect cycles and break wait-for loops.",
                deadlock.severity, deadlock.risk_score
            ));
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

        for (_, ob) in self.state.obligations_iter() {
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

#[derive(Debug, Clone)]
struct TaskWaitGraph {
    task_ids: Vec<TaskId>,
    directed_edges: Vec<(usize, usize)>,
    undirected_edges: Vec<(usize, usize)>,
}

/// Directional deadlock severity from wait-for graph analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadlockSeverity {
    /// No directed cycle risk observed.
    None,
    /// Directed cycles were found, but all have external exits.
    Elevated,
    /// At least one cycle is trapped (no outgoing edge).
    Critical,
}

/// A directed wait-for cycle component.
#[derive(Debug, Clone)]
pub struct DeadlockCycle {
    /// Tasks participating in the cycle.
    pub tasks: Vec<TaskId>,
    /// Incoming edges from outside the SCC.
    pub ingress_edges: u32,
    /// Outgoing edges to nodes outside the SCC.
    pub egress_edges: u32,
    /// Whether the cycle has no outgoing edge.
    pub trapped: bool,
}

/// Directional deadlock risk report.
#[derive(Debug, Clone)]
pub struct DirectionalDeadlockReport {
    /// Severity level.
    pub severity: DeadlockSeverity,
    /// Composite risk score in `[0, 1]`.
    pub risk_score: f64,
    /// Cycle components sorted by descending size.
    pub cycles: Vec<DeadlockCycle>,
}

impl DirectionalDeadlockReport {
    #[must_use]
    fn empty() -> Self {
        Self {
            severity: DeadlockSeverity::None,
            risk_score: 0.0,
            cycles: Vec::new(),
        }
    }
}

/// Tarjan SCC decomposition over adjacency lists.
#[must_use]
fn strongly_connected_components(adjacency: &[Vec<usize>]) -> Vec<Vec<usize>> {
    struct Tarjan<'a> {
        adjacency: &'a [Vec<usize>],
        index: usize,
        stack: Vec<usize>,
        on_stack: Vec<bool>,
        indices: Vec<Option<usize>>,
        lowlink: Vec<usize>,
        sccs: Vec<Vec<usize>>,
    }

    impl Tarjan<'_> {
        fn strongconnect(&mut self, v: usize) {
            self.indices[v] = Some(self.index);
            self.lowlink[v] = self.index;
            self.index += 1;
            self.stack.push(v);
            self.on_stack[v] = true;

            for &w in &self.adjacency[v] {
                if self.indices[w].is_none() {
                    self.strongconnect(w);
                    self.lowlink[v] = self.lowlink[v].min(self.lowlink[w]);
                } else if self.on_stack[w] {
                    self.lowlink[v] = self.lowlink[v].min(self.indices[w].unwrap_or(usize::MAX));
                }
            }

            if self.lowlink[v] == self.indices[v].unwrap_or(usize::MAX) {
                let mut scc = Vec::new();
                while let Some(w) = self.stack.pop() {
                    self.on_stack[w] = false;
                    scc.push(w);
                    if w == v {
                        break;
                    }
                }
                scc.sort_unstable();
                self.sccs.push(scc);
            }
        }
    }

    let n = adjacency.len();
    let mut tarjan = Tarjan {
        adjacency,
        index: 0,
        stack: Vec::new(),
        on_stack: vec![false; n],
        indices: vec![None; n],
        lowlink: vec![0; n],
        sccs: Vec::new(),
    };

    for v in 0..n {
        if tarjan.indices[v].is_none() {
            tarjan.strongconnect(v);
        }
    }
    tarjan.sccs
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

/// Advanced observability taxonomy contract version.
pub const ADVANCED_OBSERVABILITY_CONTRACT_VERSION: &str = "doctor-observability-v1";
/// Baseline contract version consumed by advanced taxonomy mapping.
pub const ADVANCED_OBSERVABILITY_BASELINE_VERSION: &str = "doctor-logging-v1";

/// Advanced event classes for operator-facing diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdvancedEventClass {
    /// Command lifecycle in execution flow.
    CommandLifecycle,
    /// Cross-system synchronization and error boundaries.
    IntegrationReliability,
    /// Guided remediation lifecycle and verification.
    RemediationSafety,
    /// Deterministic replay lifecycle.
    ReplayDeterminism,
    /// Verification and gate-level summary events.
    VerificationGovernance,
}

impl AdvancedEventClass {
    /// Stable canonical string for schema/docs/export use.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CommandLifecycle => "command_lifecycle",
            Self::IntegrationReliability => "integration_reliability",
            Self::RemediationSafety => "remediation_safety",
            Self::ReplayDeterminism => "replay_determinism",
            Self::VerificationGovernance => "verification_governance",
        }
    }
}

/// Severity semantics for advanced diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdvancedSeverity {
    /// Informational event without operator action requirement.
    Info,
    /// Event that should be reviewed.
    Warning,
    /// Event indicates an actionable failure.
    Error,
    /// Event indicates taxonomy/contract contradiction requiring immediate attention.
    Critical,
}

impl AdvancedSeverity {
    /// Stable canonical string for schema/docs/export use.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }
}

/// Troubleshooting dimensions used for fast triage and filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TroubleshootingDimension {
    /// Cancellation protocol and drain/finalize lifecycle.
    CancellationPath,
    /// Schema/contract conformance and validation behavior.
    ContractCompliance,
    /// Determinism/replay and schedule stability.
    Determinism,
    /// External integration/dependency boundary behavior.
    ExternalDependency,
    /// Immediate operator action and investigation intent.
    OperatorAction,
    /// Recovery planning and remediation follow-through.
    RecoveryPlanning,
    /// Runtime-state/invariant integrity.
    RuntimeInvariant,
}

impl TroubleshootingDimension {
    /// Stable canonical string for schema/docs/export use.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CancellationPath => "cancellation_path",
            Self::ContractCompliance => "contract_compliance",
            Self::Determinism => "determinism",
            Self::ExternalDependency => "external_dependency",
            Self::OperatorAction => "operator_action",
            Self::RecoveryPlanning => "recovery_planning",
            Self::RuntimeInvariant => "runtime_invariant",
        }
    }
}

/// Event-class specification for taxonomy contract export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvancedEventClassSpec {
    /// Canonical identifier.
    pub class_id: String,
    /// Description for operator-facing diagnostics.
    pub description: String,
}

/// Severity specification for taxonomy contract export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvancedSeveritySpec {
    /// Canonical severity identifier.
    pub severity: String,
    /// Meaning/intent of this severity.
    pub meaning: String,
}

/// Troubleshooting-dimension specification for taxonomy contract export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TroubleshootingDimensionSpec {
    /// Canonical dimension identifier.
    pub dimension: String,
    /// Why this dimension is useful during triage.
    pub purpose: String,
}

/// Advanced observability contract layered on top of baseline doctor logging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvancedObservabilityContract {
    /// Advanced contract version.
    pub contract_version: String,
    /// Required baseline contract version for mapping.
    pub baseline_contract_version: String,
    /// Event classes in lexical order.
    pub event_classes: Vec<AdvancedEventClassSpec>,
    /// Severity semantics in lexical order.
    pub severity_semantics: Vec<AdvancedSeveritySpec>,
    /// Troubleshooting dimensions in lexical order.
    pub troubleshooting_dimensions: Vec<TroubleshootingDimensionSpec>,
    /// Compatibility notes for downstream readers.
    pub compatibility_notes: Vec<String>,
}

/// Baseline flow/event/outcome tuple consumed by the advanced classifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaselineLogEvent<'a> {
    /// Baseline flow identifier.
    pub flow_id: &'a str,
    /// Baseline event kind.
    pub event_kind: &'a str,
    /// Baseline outcome class.
    pub outcome_class: &'a str,
}

/// Conflict detected while mapping baseline fields to advanced semantics.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdvancedClassificationConflict {
    /// Event kind is not allowed for this flow in baseline contract.
    FlowEventMismatch {
        /// Baseline flow identifier.
        flow_id: String,
        /// Baseline event kind.
        event_kind: String,
    },
    /// Outcome conflicts with event-kind semantics.
    OutcomeEventMismatch {
        /// Baseline event kind.
        event_kind: String,
        /// Baseline outcome class.
        outcome_class: String,
    },
}

/// Classified advanced semantic view of one baseline event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvancedLogClassification {
    /// Advanced event class.
    pub event_class: AdvancedEventClass,
    /// Resolved severity.
    pub severity: AdvancedSeverity,
    /// Troubleshooting dimensions in deterministic lexical order.
    pub dimensions: Vec<TroubleshootingDimension>,
    /// Operator-facing narrative sentence.
    pub narrative: String,
    /// Recommended next action.
    pub recommended_action: String,
    /// Conflicts discovered during mapping/resolution.
    pub conflicts: Vec<AdvancedClassificationConflict>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BaselineFlowId {
    Execution,
    Integration,
    Remediation,
    Replay,
}

impl BaselineFlowId {
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "execution" => Some(Self::Execution),
            "integration" => Some(Self::Integration),
            "remediation" => Some(Self::Remediation),
            "replay" => Some(Self::Replay),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BaselineEventKind {
    CommandComplete,
    CommandStart,
    IntegrationError,
    IntegrationSync,
    RemediationApply,
    RemediationVerify,
    ReplayComplete,
    ReplayStart,
    VerificationSummary,
}

impl BaselineEventKind {
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "command_complete" => Some(Self::CommandComplete),
            "command_start" => Some(Self::CommandStart),
            "integration_error" => Some(Self::IntegrationError),
            "integration_sync" => Some(Self::IntegrationSync),
            "remediation_apply" => Some(Self::RemediationApply),
            "remediation_verify" => Some(Self::RemediationVerify),
            "replay_complete" => Some(Self::ReplayComplete),
            "replay_start" => Some(Self::ReplayStart),
            "verification_summary" => Some(Self::VerificationSummary),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BaselineOutcomeClass {
    Cancelled,
    Failed,
    Success,
}

impl BaselineOutcomeClass {
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "cancelled" => Some(Self::Cancelled),
            "failed" => Some(Self::Failed),
            "success" => Some(Self::Success),
            _ => None,
        }
    }
}

/// Returns the advanced observability taxonomy contract.
#[must_use]
pub fn advanced_observability_contract() -> AdvancedObservabilityContract {
    AdvancedObservabilityContract {
        contract_version: ADVANCED_OBSERVABILITY_CONTRACT_VERSION.to_string(),
        baseline_contract_version: ADVANCED_OBSERVABILITY_BASELINE_VERSION.to_string(),
        event_classes: vec![
            AdvancedEventClassSpec {
                class_id: AdvancedEventClass::CommandLifecycle.as_str().to_string(),
                description: "Execution command lifecycle and gate telemetry.".to_string(),
            },
            AdvancedEventClassSpec {
                class_id: AdvancedEventClass::IntegrationReliability
                    .as_str()
                    .to_string(),
                description: "Cross-system integration health and boundary reliability."
                    .to_string(),
            },
            AdvancedEventClassSpec {
                class_id: AdvancedEventClass::RemediationSafety.as_str().to_string(),
                description: "Remediation safety, application, and post-fix verification."
                    .to_string(),
            },
            AdvancedEventClassSpec {
                class_id: AdvancedEventClass::ReplayDeterminism.as_str().to_string(),
                description: "Replay lifecycle and deterministic reproducibility.".to_string(),
            },
            AdvancedEventClassSpec {
                class_id: AdvancedEventClass::VerificationGovernance
                    .as_str()
                    .to_string(),
                description: "Verification summary and governance gate posture.".to_string(),
            },
        ],
        severity_semantics: vec![
            AdvancedSeveritySpec {
                severity: AdvancedSeverity::Critical.as_str().to_string(),
                meaning: "Contract/taxonomy contradiction requiring immediate correction."
                    .to_string(),
            },
            AdvancedSeveritySpec {
                severity: AdvancedSeverity::Error.as_str().to_string(),
                meaning: "Actionable failure impacting reliability or correctness.".to_string(),
            },
            AdvancedSeveritySpec {
                severity: AdvancedSeverity::Info.as_str().to_string(),
                meaning: "Expected state transition with no direct intervention required."
                    .to_string(),
            },
            AdvancedSeveritySpec {
                severity: AdvancedSeverity::Warning.as_str().to_string(),
                meaning: "Non-terminal issue or cancellation requiring review.".to_string(),
            },
        ],
        troubleshooting_dimensions: vec![
            TroubleshootingDimensionSpec {
                dimension: TroubleshootingDimension::CancellationPath
                    .as_str()
                    .to_string(),
                purpose: "Track request/drain/finalize behavior for cancelled runs.".to_string(),
            },
            TroubleshootingDimensionSpec {
                dimension: TroubleshootingDimension::ContractCompliance
                    .as_str()
                    .to_string(),
                purpose: "Validate schema, gate, and policy conformance.".to_string(),
            },
            TroubleshootingDimensionSpec {
                dimension: TroubleshootingDimension::Determinism.as_str().to_string(),
                purpose: "Confirm replay stability and deterministic artifact lineage.".to_string(),
            },
            TroubleshootingDimensionSpec {
                dimension: TroubleshootingDimension::ExternalDependency
                    .as_str()
                    .to_string(),
                purpose: "Isolate third-party/system boundary failures.".to_string(),
            },
            TroubleshootingDimensionSpec {
                dimension: TroubleshootingDimension::OperatorAction
                    .as_str()
                    .to_string(),
                purpose: "Prioritize immediate operator decision paths.".to_string(),
            },
            TroubleshootingDimensionSpec {
                dimension: TroubleshootingDimension::RecoveryPlanning
                    .as_str()
                    .to_string(),
                purpose: "Drive remediation and verify-after-change sequencing.".to_string(),
            },
            TroubleshootingDimensionSpec {
                dimension: TroubleshootingDimension::RuntimeInvariant
                    .as_str()
                    .to_string(),
                purpose: "Connect events to runtime invariant health.".to_string(),
            },
        ],
        compatibility_notes: vec![
            "Additive dimensions/classes may be introduced without baseline schema changes."
                .to_string(),
            "Field removals or semantic redefinitions require a contract-version bump.".to_string(),
            "Unknown baseline flow/event/outcome values are hard validation errors.".to_string(),
        ],
    }
}

/// Classifies one baseline doctor logging event into advanced semantics.
///
/// Conflict resolution is deterministic:
/// 1. Start with outcome-based severity (`success` -> info, `cancelled` -> warning, `failed` -> error).
/// 2. Escalate for semantic contradictions (for example, `integration_error` + `success`).
/// 3. Escalate to `critical` when flow/event pairing violates baseline contract.
pub fn classify_baseline_log_event(
    event: BaselineLogEvent<'_>,
) -> Result<AdvancedLogClassification, String> {
    let flow = BaselineFlowId::parse(event.flow_id)
        .ok_or_else(|| format!("unknown flow_id {}", event.flow_id))?;
    let kind = BaselineEventKind::parse(event.event_kind)
        .ok_or_else(|| format!("unknown event_kind {}", event.event_kind))?;
    let outcome = BaselineOutcomeClass::parse(event.outcome_class)
        .ok_or_else(|| format!("unknown outcome_class {}", event.outcome_class))?;

    let (event_class, mut dimensions, kind_narrative, action_hint) = kind_semantics(kind);
    let mut conflicts = Vec::new();
    let mut severity = match outcome {
        BaselineOutcomeClass::Success => AdvancedSeverity::Info,
        BaselineOutcomeClass::Cancelled => AdvancedSeverity::Warning,
        BaselineOutcomeClass::Failed => AdvancedSeverity::Error,
    };

    if !flow_allows_event(flow, kind) {
        conflicts.push(AdvancedClassificationConflict::FlowEventMismatch {
            flow_id: event.flow_id.to_string(),
            event_kind: event.event_kind.to_string(),
        });
        severity = AdvancedSeverity::Critical;
        dimensions.push(TroubleshootingDimension::ContractCompliance);
    }

    if kind == BaselineEventKind::IntegrationError && outcome == BaselineOutcomeClass::Success {
        conflicts.push(AdvancedClassificationConflict::OutcomeEventMismatch {
            event_kind: event.event_kind.to_string(),
            outcome_class: event.outcome_class.to_string(),
        });
        severity = severity.max(AdvancedSeverity::Error);
        dimensions.push(TroubleshootingDimension::ContractCompliance);
    }

    if outcome == BaselineOutcomeClass::Cancelled {
        dimensions.push(TroubleshootingDimension::CancellationPath);
    }
    if outcome == BaselineOutcomeClass::Failed {
        dimensions.push(TroubleshootingDimension::RecoveryPlanning);
    }
    dimensions.sort_unstable();
    dimensions.dedup();
    conflicts.sort();

    let outcome_phrase = match outcome {
        BaselineOutcomeClass::Success => "completed successfully",
        BaselineOutcomeClass::Cancelled => "was cancelled",
        BaselineOutcomeClass::Failed => "failed",
    };

    Ok(AdvancedLogClassification {
        event_class,
        severity,
        dimensions,
        narrative: format!(
            "{}:{} {}. {}",
            event.flow_id, event.event_kind, outcome_phrase, kind_narrative
        ),
        recommended_action: if conflicts.is_empty() {
            action_hint.to_string()
        } else {
            format!(
                "{action_hint} Resolve taxonomy conflicts before trusting downstream automation."
            )
        },
        conflicts,
    })
}

/// Classifies a baseline event stream in-order.
pub fn classify_baseline_log_events(
    events: &[BaselineLogEvent<'_>],
) -> Result<Vec<AdvancedLogClassification>, String> {
    events
        .iter()
        .map(|event| classify_baseline_log_event(*event))
        .collect()
}

fn flow_allows_event(flow: BaselineFlowId, kind: BaselineEventKind) -> bool {
    match flow {
        BaselineFlowId::Execution => matches!(
            kind,
            BaselineEventKind::CommandComplete
                | BaselineEventKind::CommandStart
                | BaselineEventKind::VerificationSummary
        ),
        BaselineFlowId::Integration => matches!(
            kind,
            BaselineEventKind::IntegrationError
                | BaselineEventKind::IntegrationSync
                | BaselineEventKind::VerificationSummary
        ),
        BaselineFlowId::Remediation => matches!(
            kind,
            BaselineEventKind::RemediationApply
                | BaselineEventKind::RemediationVerify
                | BaselineEventKind::VerificationSummary
        ),
        BaselineFlowId::Replay => matches!(
            kind,
            BaselineEventKind::ReplayComplete
                | BaselineEventKind::ReplayStart
                | BaselineEventKind::VerificationSummary
        ),
    }
}

fn kind_semantics(
    kind: BaselineEventKind,
) -> (
    AdvancedEventClass,
    Vec<TroubleshootingDimension>,
    &'static str,
    &'static str,
) {
    match kind {
        BaselineEventKind::CommandComplete => (
            AdvancedEventClass::CommandLifecycle,
            vec![
                TroubleshootingDimension::ContractCompliance,
                TroubleshootingDimension::OperatorAction,
            ],
            "Execution gate completed and emitted a deterministic artifact pointer",
            "Review gate summary and continue pipeline progression.",
        ),
        BaselineEventKind::CommandStart => (
            AdvancedEventClass::CommandLifecycle,
            vec![TroubleshootingDimension::OperatorAction],
            "Execution gate started with reproducible command provenance",
            "Monitor for completion and verify emitted command provenance.",
        ),
        BaselineEventKind::IntegrationError => (
            AdvancedEventClass::IntegrationReliability,
            vec![
                TroubleshootingDimension::ExternalDependency,
                TroubleshootingDimension::OperatorAction,
            ],
            "Integration boundary reported an error at an external/system edge",
            "Inspect integration target, retry posture, and boundary adapter diagnostics.",
        ),
        BaselineEventKind::IntegrationSync => (
            AdvancedEventClass::IntegrationReliability,
            vec![TroubleshootingDimension::ExternalDependency],
            "Integration synchronization event captured adapter boundary state",
            "Verify upstream/downstream contract alignment for this sync point.",
        ),
        BaselineEventKind::RemediationApply => (
            AdvancedEventClass::RemediationSafety,
            vec![
                TroubleshootingDimension::ContractCompliance,
                TroubleshootingDimension::RecoveryPlanning,
            ],
            "Remediation apply phase executed against diagnosed findings",
            "Confirm changes are scoped and queue remediation verification.",
        ),
        BaselineEventKind::RemediationVerify => (
            AdvancedEventClass::RemediationSafety,
            vec![
                TroubleshootingDimension::ContractCompliance,
                TroubleshootingDimension::RecoveryPlanning,
            ],
            "Post-remediation verification assessed health deltas and invariants",
            "Evaluate health delta and close or reopen remediation loops.",
        ),
        BaselineEventKind::ReplayComplete => (
            AdvancedEventClass::ReplayDeterminism,
            vec![
                TroubleshootingDimension::Determinism,
                TroubleshootingDimension::RuntimeInvariant,
            ],
            "Replay completion captured deterministic scenario convergence status",
            "Compare replay artifacts against baseline and investigate divergence.",
        ),
        BaselineEventKind::ReplayStart => (
            AdvancedEventClass::ReplayDeterminism,
            vec![TroubleshootingDimension::Determinism],
            "Replay start established deterministic execution context",
            "Track replay progress and preserve trace/evidence join keys.",
        ),
        BaselineEventKind::VerificationSummary => (
            AdvancedEventClass::VerificationGovernance,
            vec![
                TroubleshootingDimension::ContractCompliance,
                TroubleshootingDimension::Determinism,
                TroubleshootingDimension::RuntimeInvariant,
            ],
            "Verification summary synthesized gate outcomes for governance review",
            "Use summary to decide promotion, rollback, or targeted investigation.",
        ),
    }
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
        let idx = state.insert_task(TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            region,
            Budget::INFINITE,
        ));
        let id = TaskId::from_arena(idx);
        let record = state.task_mut(id).expect("task missing");
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
        let task = state.task_mut(task_id).expect("task missing");
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
        let task = state.task_mut(task_id).expect("task missing");
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

    // Pure data-type tests (wave 18 – CyanBarn)

    #[test]
    fn reason_debug_clone() {
        let r = Reason::RegionNotFound;
        let r2 = r;
        assert!(format!("{r2:?}").contains("RegionNotFound"));
    }

    #[test]
    fn reason_display_all_variants() {
        let r1 = Reason::RegionNotFound;
        assert!(r1.to_string().contains("not found"));

        let r2 = Reason::ChildRegionOpen {
            child_id: RegionId::new_for_test(1, 0),
            child_state: RegionState::Open,
        };
        assert!(r2.to_string().contains("child region"));

        let r3 = Reason::TaskRunning {
            task_id: TaskId::new_for_test(1, 0),
            task_state: "Running".into(),
            poll_count: 5,
        };
        assert!(r3.to_string().contains("task"));
        assert!(r3.to_string().contains("polls=5"));

        let r4 = Reason::ObligationHeld {
            obligation_id: ObligationId::new_for_test(1, 0),
            obligation_type: "Lease".into(),
            holder_task: TaskId::new_for_test(2, 0),
        };
        assert!(r4.to_string().contains("obligation"));
        assert!(r4.to_string().contains("Lease"));
    }

    #[test]
    fn region_open_explanation_debug_clone() {
        let explanation = RegionOpenExplanation {
            region_id: RegionId::new_for_test(1, 0),
            region_state: Some(RegionState::Open),
            reasons: vec![Reason::RegionNotFound],
            recommendations: vec!["check it".into()],
        };
        let explanation2 = explanation;
        assert!(format!("{explanation2:?}").contains("RegionOpenExplanation"));
    }

    #[test]
    fn region_open_explanation_display() {
        let explanation = RegionOpenExplanation {
            region_id: RegionId::new_for_test(1, 0),
            region_state: Some(RegionState::Open),
            reasons: vec![Reason::RegionNotFound],
            recommendations: vec!["fix it".into()],
        };
        let s = explanation.to_string();
        assert!(s.contains("still open"));
        assert!(s.contains("fix it"));
    }

    #[test]
    fn task_blocked_explanation_debug_clone() {
        let explanation = TaskBlockedExplanation {
            task_id: TaskId::new_for_test(1, 0),
            block_reason: BlockReason::NotStarted,
            details: vec!["detail".into()],
            recommendations: vec!["wait".into()],
        };
        let explanation2 = explanation;
        assert!(format!("{explanation2:?}").contains("TaskBlockedExplanation"));
    }

    #[test]
    fn task_blocked_explanation_display() {
        let explanation = TaskBlockedExplanation {
            task_id: TaskId::new_for_test(1, 0),
            block_reason: BlockReason::AwaitingSchedule,
            details: vec!["pending wake".into()],
            recommendations: vec!["wait for scheduler".into()],
        };
        let s = explanation.to_string();
        assert!(s.contains("blocked"));
        assert!(s.contains("awaiting schedule"));
    }

    #[test]
    fn block_reason_debug_clone() {
        let r = BlockReason::TaskNotFound;
        let r2 = r;
        assert!(format!("{r2:?}").contains("TaskNotFound"));
    }

    #[test]
    fn block_reason_display_all_variants() {
        let variants: Vec<BlockReason> = vec![
            BlockReason::TaskNotFound,
            BlockReason::NotStarted,
            BlockReason::AwaitingSchedule,
            BlockReason::AwaitingFuture {
                description: "channel recv".into(),
            },
            BlockReason::CancelRequested {
                reason: CancelReasonInfo {
                    kind: CancelKind::User,
                    message: Some("stop".into()),
                },
            },
            BlockReason::RunningCleanup {
                reason: CancelReasonInfo {
                    kind: CancelKind::User,
                    message: None,
                },
                polls_remaining: 10,
            },
            BlockReason::Finalizing {
                reason: CancelReasonInfo {
                    kind: CancelKind::User,
                    message: None,
                },
                polls_remaining: 5,
            },
            BlockReason::Completed,
        ];
        for v in &variants {
            assert!(!v.to_string().is_empty());
        }
    }

    #[test]
    fn cancellation_explanation_debug_clone() {
        let explanation = CancellationExplanation {
            kind: CancelKind::User,
            message: Some("timeout".into()),
            propagation_path: vec![CancellationStep {
                region_id: RegionId::new_for_test(1, 0),
                kind: CancelKind::User,
            }],
        };
        let explanation2 = explanation;
        assert!(format!("{explanation2:?}").contains("CancellationExplanation"));
    }

    #[test]
    fn cancellation_step_debug_clone() {
        let step = CancellationStep {
            region_id: RegionId::new_for_test(1, 0),
            kind: CancelKind::User,
        };
        let step2 = step;
        assert!(format!("{step2:?}").contains("CancellationStep"));
    }

    #[test]
    fn cancel_reason_info_debug_clone_display() {
        let info = CancelReasonInfo {
            kind: CancelKind::User,
            message: Some("stop".into()),
        };
        let info2 = info.clone();
        assert!(format!("{info2:?}").contains("CancelReasonInfo"));
        let s = info.to_string();
        assert!(s.contains("stop"));

        let info_no_msg = CancelReasonInfo {
            kind: CancelKind::User,
            message: None,
        };
        assert!(!info_no_msg.to_string().is_empty());
    }

    #[test]
    fn obligation_leak_debug_clone() {
        let leak = ObligationLeak {
            obligation_id: ObligationId::new_for_test(1, 0),
            obligation_type: "Ack".into(),
            holder_task: Some(TaskId::new_for_test(2, 0)),
            region_id: RegionId::new_for_test(1, 0),
            age: std::time::Duration::from_mins(1),
        };
        let leak2 = leak;
        assert!(format!("{leak2:?}").contains("ObligationLeak"));
    }

    #[test]
    fn directional_deadlock_cycle_detection_reports_critical() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let t1 = insert_task(&mut state, root, TaskState::Running);
        let t2 = insert_task(&mut state, root, TaskState::Running);
        state.task_mut(t1).expect("t1").waiters.push(t2); // t2 -> t1
        state.task_mut(t2).expect("t2").waiters.push(t1); // t1 -> t2

        let diagnostics = Diagnostics::new(Arc::new(state));
        let report = diagnostics.analyze_directional_deadlock();
        assert_eq!(report.severity, DeadlockSeverity::Critical);
        assert!(!report.cycles.is_empty());
        assert!(report.cycles[0].trapped);
        assert!(report.cycles[0].tasks.contains(&t1));
        assert!(report.cycles[0].tasks.contains(&t2));
    }

    #[test]
    fn explain_region_open_includes_directional_deadlock_recommendation() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let t1 = insert_task(&mut state, root, TaskState::Running);
        let t2 = insert_task(&mut state, root, TaskState::Running);
        state.task_mut(t1).expect("t1").waiters.push(t2);
        state.task_mut(t2).expect("t2").waiters.push(t1);

        let diagnostics = Diagnostics::new(Arc::new(state));
        let explanation = diagnostics.explain_region_open(root);
        assert!(
            explanation
                .recommendations
                .iter()
                .any(|r| r.contains("Directional deadlock risk")),
            "expected directional deadlock recommendation"
        );
    }

    #[test]
    fn advanced_observability_contract_has_sorted_dimensions_and_classes() {
        let contract = advanced_observability_contract();

        let classes: Vec<&str> = contract
            .event_classes
            .iter()
            .map(|item| item.class_id.as_str())
            .collect();
        let mut sorted_classes = classes.clone();
        sorted_classes.sort_unstable();
        sorted_classes.dedup();
        assert_eq!(classes, sorted_classes);

        let dimensions: Vec<&str> = contract
            .troubleshooting_dimensions
            .iter()
            .map(|item| item.dimension.as_str())
            .collect();
        let mut sorted_dimensions = dimensions.clone();
        sorted_dimensions.sort_unstable();
        sorted_dimensions.dedup();
        assert_eq!(dimensions, sorted_dimensions);
    }

    #[test]
    fn classify_baseline_log_event_maps_known_event() {
        let classified = classify_baseline_log_event(BaselineLogEvent {
            flow_id: "execution",
            event_kind: "command_start",
            outcome_class: "success",
        })
        .expect("classification should succeed");

        assert_eq!(classified.event_class, AdvancedEventClass::CommandLifecycle);
        assert_eq!(classified.severity, AdvancedSeverity::Info);
        assert!(classified.conflicts.is_empty());
        assert!(
            classified
                .dimensions
                .contains(&TroubleshootingDimension::OperatorAction)
        );
    }

    #[test]
    fn classify_baseline_log_event_detects_flow_event_conflict() {
        let classified = classify_baseline_log_event(BaselineLogEvent {
            flow_id: "execution",
            event_kind: "integration_sync",
            outcome_class: "success",
        })
        .expect("classification should succeed with conflict");

        assert_eq!(classified.severity, AdvancedSeverity::Critical);
        assert!(classified.conflicts.iter().any(|conflict| matches!(
            conflict,
            AdvancedClassificationConflict::FlowEventMismatch { .. }
        )));
    }

    #[test]
    fn classify_baseline_log_event_detects_outcome_event_conflict() {
        let classified = classify_baseline_log_event(BaselineLogEvent {
            flow_id: "integration",
            event_kind: "integration_error",
            outcome_class: "success",
        })
        .expect("classification should succeed with conflict");

        assert_eq!(
            classified.event_class,
            AdvancedEventClass::IntegrationReliability
        );
        assert_eq!(classified.severity, AdvancedSeverity::Error);
        assert!(classified.conflicts.iter().any(|conflict| matches!(
            conflict,
            AdvancedClassificationConflict::OutcomeEventMismatch { .. }
        )));
    }

    #[test]
    fn classify_baseline_log_events_is_deterministic() {
        let stream = vec![
            BaselineLogEvent {
                flow_id: "execution",
                event_kind: "command_start",
                outcome_class: "success",
            },
            BaselineLogEvent {
                flow_id: "execution",
                event_kind: "verification_summary",
                outcome_class: "failed",
            },
            BaselineLogEvent {
                flow_id: "replay",
                event_kind: "replay_complete",
                outcome_class: "cancelled",
            },
        ];

        let a = classify_baseline_log_events(&stream).expect("stream classification should pass");
        let b = classify_baseline_log_events(&stream).expect("stream classification should pass");
        assert_eq!(a, b);
        assert!(!a.is_empty());
        assert!(a.iter().all(|entry| !entry.narrative.is_empty()));
    }

    #[test]
    fn classify_baseline_log_event_rejects_unknown_tokens() {
        let err = classify_baseline_log_event(BaselineLogEvent {
            flow_id: "unknown",
            event_kind: "command_start",
            outcome_class: "success",
        })
        .expect_err("unknown flow must be rejected");
        assert!(err.contains("unknown flow_id"));
    }

    #[test]
    fn diagnostics_debug() {
        let state = Arc::new(RuntimeState::new());
        let diagnostics = Diagnostics::new(state);
        assert!(format!("{diagnostics:?}").contains("Diagnostics"));
    }
}
