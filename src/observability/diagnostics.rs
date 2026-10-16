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

/// Maximum bytes a sanitized cancel-reason message may contribute to a
/// diagnostic string (br-asupersync-3fq08n). Larger messages are truncated
/// with an ellipsis suffix.
///
/// Defends against log-amplification: a CancelReason::message can come from
/// arbitrary code (peer-bounded gateway → service paths, user-input
/// passthrough, etc.) and a multi-KB message would explode log volume per
/// diagnostic record.
const MAX_SANITIZED_CANCEL_MESSAGE_LEN: usize = 256;

/// Strip CR, LF, tab, NUL, and other ASCII control characters from a
/// cancel-reason message before embedding it into a diagnostic string.
///
/// br-asupersync-3fq08n: `CancelReason::message` is set by callers via
/// `cancel(reason, ...)` and may contain arbitrary text — including `\r`,
/// `\n`, ANSI escapes, and other control characters. When diagnostic
/// records are written to stdout / structured log / file / shipped to a
/// SIEM, these embedded controls can:
///   * spoof additional log lines (newline injection)
///   * corrupt downstream parsers (newline-delimited JSON)
///   * hide or alter records (CR overwrite)
///   * inject ANSI escape sequences that change terminal display
///
/// Same sanitization rules as `tls/error.rs::sanitize_for_log` (kxw8nx
/// pattern). Kept inline rather than refactored into a shared util to
/// preserve loose coupling between observability and tls modules; if a
/// third site arises, that's the time to refactor.
///
/// Sanitization rules:
///   * `\r`, `\n`, `\t` → ASCII space (preserves field separation)
///   * Any other ASCII control char (0x00..=0x1F, 0x7F) → `?` replacement marker
///   * UTF-8 truncation at MAX_SANITIZED_CANCEL_MESSAGE_LEN bytes, cut on
///     a char boundary, with `…` suffix on truncation
fn sanitize_cancel_message(input: &str) -> String {
    let mut out = String::with_capacity(input.len().min(MAX_SANITIZED_CANCEL_MESSAGE_LEN + 3));
    let mut byte_count = 0usize;
    let mut truncated = false;
    for ch in input.chars() {
        let mapped = match ch {
            '\r' | '\n' | '\t' => ' ',
            c if (c as u32) < 0x20 || c == '\u{7f}' => '?',
            c => c,
        };
        let mapped_len = mapped.len_utf8();
        // Use saturating arithmetic to prevent overflow
        if byte_count.saturating_add(mapped_len) > MAX_SANITIZED_CANCEL_MESSAGE_LEN {
            truncated = true;
            break;
        }
        out.push(mapped);
        byte_count = byte_count.saturating_add(mapped_len);
    }
    if truncated {
        out.push('…');
    }
    out
}
use crate::observability::task_inspector::{RuntimeStateSource, RuntimeStateView};
use crate::record::ObligationState;
use crate::record::region::RegionState;
use crate::record::task::TaskState;
use crate::runtime::state::RuntimeState;
use crate::tracing_compat::{debug, trace, warn};
use crate::types::{CancelKind, CancelReason, ObligationId, Outcome, RegionId, TaskId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

/// Diagnostics engine for runtime troubleshooting.
#[derive(Debug)]
pub struct Diagnostics {
    state: RuntimeStateSource,
    spectral_monitor: parking_lot::Mutex<SpectralHealthMonitor>,
}

impl Diagnostics {
    /// Create a new diagnostics engine.
    #[must_use]
    pub fn new(state: Arc<RuntimeState>) -> Self {
        Self::from_source(RuntimeStateSource::Owned(state))
    }

    /// Create a diagnostics engine with console output (used for richer rendering).
    #[must_use]
    pub fn with_console(state: Arc<RuntimeState>, _console: Console) -> Self {
        Self::from_source(RuntimeStateSource::Owned(state))
    }

    /// Create a diagnostics engine over any state source: detached state or
    /// a live runtime's shared state (see
    /// [`Runtime::diagnostics`](crate::runtime::Runtime::diagnostics)).
    pub(crate) fn from_source(state: RuntimeStateSource) -> Self {
        Self {
            state,
            spectral_monitor: parking_lot::Mutex::new(SpectralHealthMonitor::new(
                SpectralThresholds::default(),
            )),
        }
    }

    fn build_task_wait_graph_in(view: &RuntimeStateView<'_>) -> TaskWaitGraph {
        let mut task_ids: Vec<TaskId> = view
            .tasks()
            .filter_map(|task| (!task.state.is_terminal()).then_some(task.id))
            .collect();
        task_ids.sort();
        let index_by_task: BTreeMap<TaskId, usize> = task_ids
            .iter()
            .enumerate()
            .map(|(i, id)| (*id, i))
            .collect();

        let mut directed_edges = Vec::new();
        for task in view.tasks() {
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
        let graph = self.state.with_view(Self::build_task_wait_graph_in);
        let adjacency = wait_graph_adjacency(&graph);
        let mut monitor = self.spectral_monitor.lock();
        monitor.analyze_with_trapped_cycle(
            graph.task_ids.len(),
            &graph.undirected_edges,
            has_trapped_wait_cycle(&adjacency),
        )
    }

    /// Analyze directional deadlock risk from wait-for dependencies.
    #[must_use]
    pub fn analyze_directional_deadlock(&self) -> DirectionalDeadlockReport {
        let graph = self.state.with_view(Self::build_task_wait_graph_in);
        Self::directional_deadlock_from_graph(&graph)
    }

    /// Directional deadlock analysis over an already-captured wait graph.
    fn directional_deadlock_from_graph(graph: &TaskWaitGraph) -> DirectionalDeadlockReport {
        if graph.task_ids.is_empty() {
            return DirectionalDeadlockReport::empty();
        }

        let adjacency = wait_graph_adjacency(graph);

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
            cycle_nodes = cycle_nodes.saturating_add(nodes.len());
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
        let explanation = self
            .state
            .with_view(|view| Self::explain_region_open_in(view, region_id));
        if explanation.region_state.is_some() {
            debug!(
                region_id = ?region_id,
                region_state = ?explanation.region_state,
                reason_count = explanation.reasons.len(),
                "diagnostics: region open explanation computed"
            );
        }
        explanation
    }

    /// Pure read behind [`Self::explain_region_open`]; runs under the state
    /// lock for live runtimes, so it must not emit tracing or call out.
    fn explain_region_open_in(
        view: &RuntimeStateView<'_>,
        region_id: RegionId,
    ) -> RegionOpenExplanation {
        let Some(region) = view.region(region_id) else {
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
            if let Some(child) = view.region(child_id) {
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
            if let Some(task) = view.task(task_id) {
                if !task.state.is_terminal() {
                    let mut waiters = task.waiters.to_vec();
                    waiters.sort();
                    reasons.push(Reason::TaskRunning {
                        task_id,
                        task_state: task.state_name().to_string(),
                        poll_count: task.total_polls,
                        waiters,
                        last_checkpoint_message: Self::task_checkpoint_message(task),
                    });
                }
            }
        }

        // Held obligations in this region.
        let mut held = Vec::new();
        for ob in view.obligations() {
            if ob.region == region_id && ob.state == ObligationState::Reserved {
                held.push((ob.id, ob.holder, ob.kind));
            }
        }
        held.sort_by_key(|(id, _, _)| *id);
        for (id, holder, kind) in held {
            let (holder_waiters, holder_last_checkpoint_message) =
                view.task(holder).map_or((Vec::new(), None), |holder_task| {
                    let mut waiters = holder_task.waiters.to_vec();
                    waiters.sort();
                    (waiters, Self::task_checkpoint_message(holder_task))
                });
            reasons.push(Reason::ObligationHeld {
                obligation_id: id,
                obligation_type: format!("{kind:?}"),
                holder_task: holder,
                holder_waiters,
                holder_last_checkpoint_message,
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

        let deadlock = Self::directional_deadlock_from_graph(&Self::build_task_wait_graph_in(view));
        if deadlock.severity != DeadlockSeverity::None {
            recommendations.push(format!(
                "Directional deadlock risk {:?} (score {:.3}); inspect cycles and break wait-for loops.",
                deadlock.severity, deadlock.risk_score
            ));
        }

        RegionOpenExplanation {
            region_id,
            region_state: Some(region_state),
            reasons,
            recommendations,
        }
    }

    fn task_checkpoint_message(task: &crate::record::task::TaskRecord) -> Option<String> {
        task.cx
            .as_ref()
            .and_then(|cx| cx.checkpoint_state().last_message)
            .or_else(|| {
                task.cx_inner
                    .as_ref()
                    .and_then(|inner| inner.read().materialised_checkpoint_state().last_message)
            })
            .map(|message| sanitize_cancel_message(&message))
    }

    /// Explain what is blocking a task.
    #[must_use]
    pub fn explain_task_blocked(&self, task_id: TaskId) -> TaskBlockedExplanation {
        trace!(task_id = ?task_id, "diagnostics: explain_task_blocked");
        self.state
            .with_view(|view| Self::explain_task_blocked_in(view, task_id))
    }

    /// Pure read behind [`Self::explain_task_blocked`]; runs under the state
    /// lock for live runtimes, so it must not emit tracing or call out.
    fn explain_task_blocked_in(
        view: &RuntimeStateView<'_>,
        task_id: TaskId,
    ) -> TaskBlockedExplanation {
        let Some(task) = view.task(task_id) else {
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
                if let Some(msg) = &reason.message.as_deref() {
                    // br-asupersync-3fq08n: peer/user-controlled message
                    // sanitized before embedding into diagnostic string.
                    details.push(format!("message: {}", sanitize_cancel_message(msg)));
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
                details.push(format!(
                    "cleanup polls remaining: {}",
                    cleanup_budget.poll_quota
                ));
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
                details.push(format!(
                    "cleanup polls remaining: {}",
                    cleanup_budget.poll_quota
                ));
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

    /// Explain the cancellation a task has observed, if any.
    ///
    /// Returns `None` when the task is unknown or has never had cancellation
    /// requested (`Created`/`Running`, or completed without a cancelled
    /// outcome). Otherwise `kind` and `message` are the task's own
    /// (leaf) cancel reason exactly as the runtime recorded it, and
    /// `propagation_path` is that reason's cause chain rendered root -> leaf:
    /// one [`CancellationStep`] per chained reason, each naming the region the
    /// runtime stamped as that link's origin. Region-tree propagation builds
    /// the chain through `CancelReason::with_cause_limited`, so the path is
    /// bounded by the runtime's `CancelAttributionConfig` and a truncated
    /// chain simply ends early; a task cancelled directly in its own region
    /// yields a single step.
    ///
    /// Messages are sanitized like every other diagnostic string (control
    /// characters stripped, length capped) before they are returned.
    #[must_use]
    pub fn explain_cancellation(&self, task_id: TaskId) -> Option<CancellationExplanation> {
        trace!(task_id = ?task_id, "diagnostics: explain_cancellation");
        self.state.with_view(|view| {
            let task = view.task(task_id)?;
            let reason = match &task.state {
                TaskState::Completed(Outcome::Cancelled(reason)) => reason,
                _ => task.cancel_reason()?,
            };
            Some(Self::explain_cancel_reason(reason))
        })
    }

    /// Render one recorded cancel reason (and its cause chain) as an
    /// explanation. Pure; safe to call under the state lock.
    fn explain_cancel_reason(reason: &CancelReason) -> CancellationExplanation {
        // `chain()` walks leaf -> root cause; the explanation is documented
        // root -> leaf.
        let mut propagation_path: Vec<CancellationStep> = reason
            .chain()
            .map(|link| CancellationStep {
                region_id: link.origin_region,
                kind: link.kind,
            })
            .collect();
        propagation_path.reverse();
        CancellationExplanation {
            kind: reason.kind,
            message: reason.message.as_deref().map(sanitize_cancel_message),
            propagation_path,
        }
    }

    /// Find obligations that look leaked (still reserved) and return a snapshot.
    ///
    /// This is a low-level heuristic. For stronger guarantees, prefer lab oracles.
    /// It includes reservations held by live tasks and omits terminal `Leaked`
    /// records. Use [`Self::find_confirmed_obligation_leaks`] to distinguish
    /// recorded leaks and abandoned reservations from ordinary live holdings.
    #[must_use]
    pub fn find_leaked_obligations(&self) -> Vec<ObligationLeak> {
        let mut leaks = self.state.with_view(|view| {
            let now = view.now();
            let mut leaks = Vec::new();
            for ob in view.obligations() {
                if ob.state == ObligationState::Reserved {
                    // Skip obligations whose holder task has already completed.
                    // A completed holder will tear down its obligations via
                    // the normal scope-exit path, so flagging them here would
                    // produce false positives in leak detection.
                    if let Some(holder) = view.task(ob.holder) {
                        if matches!(holder.state, TaskState::Completed(_)) {
                            continue;
                        }
                    }
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
            leaks
        });

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

    /// Find drain-correct races whose participants have not all completed
    /// `min_age` after the race began.
    ///
    /// Covers every race recorded through `Scope::race` / `Scope::race_all`:
    /// `race!`, blocking `select!`, and the `Cx::race_drained*` family. A
    /// race whose winner is selected but whose loser never finishes usually
    /// has a prebuilt branch awaiting a cancel-aware operation on the caller's
    /// context. Loser cancellation targets the branch's own task, so that
    /// operation never observes it and the race waits for it indefinitely.
    /// The factory forms (`race!(cx, { move |child| .. })`,
    /// [`Cx::race_drained_with`](crate::cx::Cx::race_drained_with)) avoid it.
    ///
    /// Each entry names the race, its region, and the branch indexes and tasks
    /// still pending. Results are ordered oldest first. A race that is only
    /// waiting for its first winner is reported too, with
    /// `winner_selected == false`; `min_age` filters routine waits.
    #[must_use]
    pub fn find_stalled_race_drains(&self, min_age: std::time::Duration) -> Vec<StalledRaceDrain> {
        use crate::runtime::state::LoserDrainHistoryEvent;

        let (history, now) = self
            .state
            .with_view(|view| (view.loser_drain_history(), view.now()));
        let completed: std::collections::HashSet<TaskId> = history
            .iter()
            .filter_map(|event| match event {
                LoserDrainHistoryEvent::TaskCompleted { task, .. } => Some(*task),
                _ => None,
            })
            .collect();
        let finished: std::collections::HashSet<u64> = history
            .iter()
            .filter_map(|event| match event {
                LoserDrainHistoryEvent::RaceCompleted { race_id, .. } => Some(*race_id),
                _ => None,
            })
            .collect();
        let mut stalled: Vec<StalledRaceDrain> = history
            .iter()
            .filter_map(|event| match event {
                LoserDrainHistoryEvent::RaceStarted {
                    race_id,
                    region,
                    participants,
                    time,
                } if !finished.contains(race_id) => {
                    let age = std::time::Duration::from_nanos(now.duration_since(*time));
                    let pending: Vec<(usize, TaskId)> = participants
                        .iter()
                        .copied()
                        .enumerate()
                        .filter(|(_, task)| !completed.contains(task))
                        .collect();
                    (age >= min_age && !pending.is_empty()).then(|| StalledRaceDrain {
                        race_id: *race_id,
                        region_id: *region,
                        age,
                        winner_selected: pending.len() < participants.len(),
                        pending,
                    })
                }
                _ => None,
            })
            .collect();
        stalled.sort_by(|a, b| b.age.cmp(&a.age).then(a.race_id.cmp(&b.race_id)));

        if !stalled.is_empty() {
            warn!(
                count = stalled.len(),
                "diagnostics: drain-correct races with losers still pending"
            );
        }
        stalled
    }

    /// Find recorded leaks and reservations whose holder can no longer resolve them.
    ///
    /// An obligation qualifies when the runtime marked it `Leaked`, or when it
    /// remains `Reserved` but its exact holder task id is missing or terminal.
    /// Reservations held by live tasks, including tasks draining cancellation
    /// or running finalizers, are excluded. `Committed` and `Aborted` records
    /// are excluded regardless of the holder's state.
    ///
    /// The query reads the obligation and task tables in one consistent
    /// snapshot, including external scheduler tables. Results are ordered by
    /// region id and obligation id; ages use the runtime's current clock.
    /// The recorded holder id remains available even after its task retires.
    ///
    /// This inspects retained runtime records. An empty snapshot does not
    /// establish that no leak occurred historically or outside runtime tracking.
    /// [`Self::find_leaked_obligations`] retains its broader legacy heuristic.
    #[must_use]
    pub fn find_confirmed_obligation_leaks(&self) -> Vec<ObligationLeak> {
        let mut leaks = self.state.with_view(|view| {
            let now = view.now();
            view.obligations()
                .filter(|ob| Self::obligation_is_confirmed_leak(view, ob))
                .map(|ob| ObligationLeak {
                    obligation_id: ob.id,
                    obligation_type: format!("{:?}", ob.kind),
                    holder_task: Some(ob.holder),
                    region_id: ob.region,
                    age: std::time::Duration::from_nanos(now.duration_since(ob.reserved_at)),
                })
                .collect::<Vec<_>>()
        });
        leaks.sort_by_key(|leak| (leak.region_id, leak.obligation_id));
        if !leaks.is_empty() {
            warn!(
                count = leaks.len(),
                "diagnostics: confirmed obligation leaks detected"
            );
        }
        leaks
    }

    /// Whether the current snapshot contains a confirmed obligation leak.
    ///
    /// This uses the same classification as
    /// [`Self::find_confirmed_obligation_leaks`] without allocating a report or
    /// emitting a warning. Health checks can opt into this signal without
    /// treating every live permit or acknowledgement as a leak. It does not
    /// change the legacy leak heuristic or structural-health classification.
    /// Separate query calls may observe different runtime snapshots.
    #[must_use]
    pub fn has_confirmed_obligation_leaks(&self) -> bool {
        self.state.with_view(|view| {
            view.obligations()
                .any(|ob| Self::obligation_is_confirmed_leak(view, ob))
        })
    }

    fn obligation_is_confirmed_leak(
        view: &RuntimeStateView<'_>,
        obligation: &crate::record::ObligationRecord,
    ) -> bool {
        match obligation.state {
            ObligationState::Leaked => true,
            ObligationState::Reserved => view
                .task(obligation.holder)
                .is_none_or(|holder| holder.state.is_terminal()),
            ObligationState::Committed | ObligationState::Aborted => false,
        }
    }
}

#[derive(Debug, Clone)]
struct TaskWaitGraph {
    task_ids: Vec<TaskId>,
    directed_edges: Vec<(usize, usize)>,
    undirected_edges: Vec<(usize, usize)>,
}

fn wait_graph_adjacency(graph: &TaskWaitGraph) -> Vec<Vec<usize>> {
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
    adjacency
}

fn has_trapped_wait_cycle(adjacency: &[Vec<usize>]) -> bool {
    for nodes in strongly_connected_components(adjacency) {
        let has_cycle = if nodes.len() > 1 {
            true
        } else {
            let n0 = nodes[0];
            adjacency[n0].contains(&n0)
        };
        if !has_cycle {
            continue;
        }

        let node_set: std::collections::BTreeSet<usize> = nodes.iter().copied().collect();
        let has_egress = nodes
            .iter()
            .any(|&u| adjacency[u].iter().any(|v| !node_set.contains(v)));
        if !has_egress {
            return true;
        }
    }

    false
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
        let blocked_region_close = self
            .region_state
            .is_some_and(|state| state != RegionState::Closed)
            && !self.reasons.is_empty()
            && !self
                .reasons
                .iter()
                .all(|reason| matches!(reason, Reason::RegionNotFound));

        if blocked_region_close {
            writeln!(
                f,
                "[ASUP-E301] region close drain still blocked for {:?}.",
                self.region_id
            )?;
            writeln!(f, "  doc: docs/error_codes/ASUP-E301.md")?;
        } else {
            writeln!(f, "Region {:?} is still open.", self.region_id)?;
        }
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
        /// Tasks currently waiting on this task, ordered by id.
        waiters: Vec<TaskId>,
        /// Last checkpoint message recorded by the task, when available.
        last_checkpoint_message: Option<String>,
    },
    /// An obligation is still reserved/held.
    ObligationHeld {
        /// Obligation id.
        obligation_id: ObligationId,
        /// Obligation kind/type.
        obligation_type: String,
        /// Task holding the obligation.
        holder_task: TaskId,
        /// Tasks waiting on the holder, ordered by id.
        holder_waiters: Vec<TaskId>,
        /// Last checkpoint recorded by the holder task, when available.
        holder_last_checkpoint_message: Option<String>,
    },
}

fn format_region_checkpoint(message: Option<&str>) -> String {
    message.map_or_else(|| "\"<none>\"".to_string(), |msg| format!("{msg:?}"))
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
                waiters,
                last_checkpoint_message,
            } => write!(
                f,
                "task {task_id:?} still running (state={task_state}, polls={poll_count}, wait_edges={waiters:?}, last_checkpoint={})",
                format_region_checkpoint(last_checkpoint_message.as_deref())
            ),
            Self::ObligationHeld {
                obligation_id,
                obligation_type,
                holder_task,
                holder_waiters,
                holder_last_checkpoint_message,
            } => write!(
                f,
                "obligation {obligation_id:?} held by task {holder_task:?} (type={obligation_type}, holder_waiters={holder_waiters:?}, holder_last_checkpoint={})",
                format_region_checkpoint(holder_last_checkpoint_message.as_deref())
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
    /// br-asupersync-3fq08n: sanitize the cancel-reason message at the
    /// chokepoint so all downstream consumers (Display, serde, debug)
    /// observe the cleaned value. Once the value enters this struct, it
    /// is safe for any log path.
    fn from_reason(kind: CancelKind, message: Option<&str>) -> Self {
        Self {
            kind,
            message: message.map(sanitize_cancel_message),
        }
    }
}

impl fmt::Display for CancelReasonInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(msg) = &self.message {
            // Message was sanitized at construction (from_reason) so this
            // path is safe — no embedded CR/LF/control chars can splice
            // forged log lines.
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

/// A drain-correct race whose participants have not all completed.
///
/// Returned by [`Diagnostics::find_stalled_race_drains`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StalledRaceDrain {
    /// Race identifier inside the runtime state.
    pub race_id: u64,
    /// Region that owns the race.
    pub region_id: RegionId,
    /// Time since the race began.
    pub age: std::time::Duration,
    /// Whether some participant has already completed. When true, the race is
    /// draining losers that have not finished.
    pub winner_selected: bool,
    /// Branch index (position in the race) and task of every participant
    /// that has not completed.
    pub pending: Vec<(usize, TaskId)>,
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

/// Tail-latency taxonomy contract version.
pub const TAIL_LATENCY_TAXONOMY_CONTRACT_VERSION: &str = "runtime-tail-latency-taxonomy-v1";

/// Stable structured-log field defined by the tail-latency taxonomy contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailLatencyLogFieldSpec {
    /// Stable structured-log field key.
    pub key: String,
    /// Unit for this field.
    pub unit: String,
    /// Whether every tail-latency emission must include the field.
    pub required: bool,
    /// Operator-facing meaning of the field.
    pub meaning: String,
}

/// Concrete source binding for one tail-latency signal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailLatencySignalSpec {
    /// Stable signal identifier.
    pub signal_id: String,
    /// Stable structured-log key emitted by runtime/test harnesses.
    pub structured_log_key: String,
    /// Unit for the signal.
    pub unit: String,
    /// Classification of the signal source.
    pub producer_kind: String,
    /// Fully qualified Rust symbol or explicit contract surface.
    pub producer_symbol: String,
    /// Repository-relative file path containing the producer.
    pub producer_file: String,
    /// Whether the signal is direct, proxy, or the unknown bucket.
    pub measurement_class: String,
    /// Whether the signal belongs to the compact always-on core.
    pub core: bool,
    /// Additional interpretation notes.
    pub notes: String,
}

/// One term in the canonical tail decomposition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailLatencyTermSpec {
    /// Stable term identifier.
    pub term_id: String,
    /// Operator-facing description of the contribution.
    pub description: String,
    /// Reserved structured-log key for direct duration attribution.
    pub direct_duration_key: String,
    /// Structured-log key describing whether attribution is measured/proxy/unknown.
    pub attribution_state_key: String,
    /// Concrete signals that feed the term.
    pub signals: Vec<TailLatencySignalSpec>,
}

/// Versioned tail-latency decomposition contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailLatencyTaxonomyContract {
    /// Contract version for artifacts and logs.
    pub contract_version: String,
    /// Canonical decomposition equation.
    pub equation: String,
    /// Stable field for the total latency under analysis.
    pub total_latency_key: String,
    /// Explicit bucket for unmeasured or ambiguous contribution.
    pub unknown_bucket_key: String,
    /// Compact always-on field set every emitter must understand.
    pub required_log_fields: Vec<TailLatencyLogFieldSpec>,
    /// Decomposition terms in canonical equation order.
    pub terms: Vec<TailLatencyTermSpec>,
    /// Required sampling/retention policy notes.
    pub sampling_policy: Vec<String>,
    /// Compatibility notes for downstream tools.
    pub compatibility_notes: Vec<String>,
}

/// Compact tail-causal event schema emitted by the always-on attribution path.
pub const TAIL_LATENCY_COMPACT_EVENT_SCHEMA_VERSION: &str =
    "runtime-tail-causal-attribution-event-v1";

/// Value carried by one stable tail-latency structured-log field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TailLatencyFieldValue {
    /// Text value, used for schema identifiers and state labels.
    Text(String),
    /// Unsigned integer value, used for nanoseconds, counts, and bytes.
    Unsigned(u64),
}

/// Configuration for compact tail-causal attribution emission.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TailLatencyEmitterConfig {
    /// Whether the emitter should produce events.
    pub enabled: bool,
    /// Whether replay/forensics-only byte pressure should be included.
    pub include_extended_allocator_bytes_live: bool,
}

impl TailLatencyEmitterConfig {
    /// Return a config that enables the compact always-on core only.
    #[must_use]
    pub const fn enabled_core() -> Self {
        Self {
            enabled: true,
            include_extended_allocator_bytes_live: false,
        }
    }

    /// Enable replay/forensics-only allocator byte pressure in addition to the
    /// compact core.
    #[must_use]
    pub const fn with_extended_allocator_bytes_live(mut self) -> Self {
        self.include_extended_allocator_bytes_live = true;
        self
    }
}

/// Explicit input sample for one compact tail-causal attribution event.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TailLatencyCompactSample {
    /// End-to-end latency under analysis.
    pub total_latency_ns: u64,
    /// Ready queue backlog proxy.
    pub ready_queue_depth: Option<u64>,
    /// Task poll demand proxy.
    pub poll_count: Option<u64>,
    /// Reactor/network event pressure proxy.
    pub events_received: Option<u64>,
    /// Direct retry/backoff delay, when measured.
    pub retries_total_delay_ns: Option<u64>,
    /// Direct lock wait delay, when measured.
    pub synchronization_lock_wait_ns: Option<u64>,
    /// Live allocator/cache pressure proxy.
    pub allocator_live_allocations: Option<u64>,
    /// Replay/forensics-only live byte pressure proxy.
    pub allocator_bytes_live: Option<u64>,
}

impl TailLatencyCompactSample {
    /// Create an empty sample for the supplied total latency.
    #[must_use]
    pub const fn new(total_latency_ns: u64) -> Self {
        Self {
            total_latency_ns,
            ready_queue_depth: None,
            poll_count: None,
            events_received: None,
            retries_total_delay_ns: None,
            synchronization_lock_wait_ns: None,
            allocator_live_allocations: None,
            allocator_bytes_live: None,
        }
    }

    /// Attach the compact core queueing proxy.
    #[must_use]
    pub const fn with_ready_queue_depth(mut self, value: u64) -> Self {
        self.ready_queue_depth = Some(value);
        self
    }

    /// Attach the compact core service proxy.
    #[must_use]
    pub const fn with_poll_count(mut self, value: u64) -> Self {
        self.poll_count = Some(value);
        self
    }

    /// Attach the compact core I/O or network proxy.
    #[must_use]
    pub const fn with_events_received(mut self, value: u64) -> Self {
        self.events_received = Some(value);
        self
    }

    /// Attach measured retry/backoff delay.
    #[must_use]
    pub const fn with_retries_total_delay_ns(mut self, value: u64) -> Self {
        self.retries_total_delay_ns = Some(value);
        self
    }

    /// Attach measured synchronization lock wait.
    #[must_use]
    pub const fn with_synchronization_lock_wait_ns(mut self, value: u64) -> Self {
        self.synchronization_lock_wait_ns = Some(value);
        self
    }

    /// Attach the compact core allocator/cache proxy.
    #[must_use]
    pub const fn with_allocator_live_allocations(mut self, value: u64) -> Self {
        self.allocator_live_allocations = Some(value);
        self
    }

    /// Attach replay/forensics-only allocator byte pressure.
    #[must_use]
    pub const fn with_allocator_bytes_live(mut self, value: u64) -> Self {
        self.allocator_bytes_live = Some(value);
        self
    }
}

/// Compact, deterministic event row suitable for certificates and smoke logs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailLatencyCompactEvent {
    /// Event schema version.
    pub schema_version: String,
    /// Scenario or workload identifier supplied by the caller.
    pub scenario_id: String,
    /// Event identifier supplied by the caller.
    pub event_id: String,
    /// Taxonomy version backing the field set.
    pub taxonomy_version: String,
    /// Stable structured fields in lexical order.
    pub fields: BTreeMap<String, TailLatencyFieldValue>,
    /// Per-term attribution states in lexical order.
    pub attribution_states: BTreeMap<String, String>,
    /// Required producers that were unavailable for this event.
    pub missing_producers: Vec<String>,
    /// Explicit residual that remains unattributed by measured durations.
    pub unknown_unmeasured_ns: u64,
    /// Conservative deterministic overhead estimate for this compact event.
    pub overhead_estimate_bytes: usize,
}

/// Failure while building a compact tail-causal event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TailLatencyEmitError {
    /// Scenario id was empty.
    EmptyScenarioId,
    /// Event id was empty.
    EmptyEventId,
    /// Direct measured durations exceed the observed total latency.
    DirectDurationExceedsTotal {
        /// Observed total latency.
        total_latency_ns: u64,
        /// Sum of direct measured terms.
        direct_duration_ns: u64,
    },
}

impl fmt::Display for TailLatencyEmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyScenarioId => f.write_str("tail-latency scenario id must not be empty"),
            Self::EmptyEventId => f.write_str("tail-latency event id must not be empty"),
            Self::DirectDurationExceedsTotal {
                total_latency_ns,
                direct_duration_ns,
            } => write!(
                f,
                "tail-latency direct durations ({direct_duration_ns}ns) exceed total latency ({total_latency_ns}ns)"
            ),
        }
    }
}

impl std::error::Error for TailLatencyEmitError {}

fn push_tail_missing(
    missing: &mut Vec<String>,
    attribution_states: &mut BTreeMap<String, String>,
    term: &str,
    producer_key: &str,
) {
    missing.push(producer_key.to_string());
    attribution_states.insert(term.to_string(), "missing_producer".to_string());
}

fn tail_field_from_optional(
    fields: &mut BTreeMap<String, TailLatencyFieldValue>,
    missing: &mut Vec<String>,
    attribution_states: &mut BTreeMap<String, String>,
    key: &str,
    term: &str,
    state_when_present: &str,
    value: Option<u64>,
) {
    match value {
        Some(value) => {
            fields.insert(key.to_string(), TailLatencyFieldValue::Unsigned(value));
            attribution_states.insert(term.to_string(), state_when_present.to_string());
        }
        None => {
            fields.insert(key.to_string(), TailLatencyFieldValue::Unsigned(0));
            push_tail_missing(missing, attribution_states, term, key);
        }
    }
}

fn tail_compact_event_overhead_estimate_bytes(
    field_count: usize,
    state_count: usize,
    missing_count: usize,
) -> usize {
    std::mem::size_of::<TailLatencyCompactSample>()
        + std::mem::size_of::<TailLatencyCompactEvent>()
        + (field_count * 96)
        + (state_count * 64)
        + (missing_count * 48)
}

/// Emit one compact tail-causal attribution event.
///
/// The emitter is disabled by default. When enabled, every required compact
/// field is present in the output. Missing producers are represented by a
/// zero-valued stand-in plus a `missing_producers` entry and a nonzero unknown
/// residual whenever measured direct terms do not cover the observed total.
pub fn emit_tail_latency_compact_event(
    config: TailLatencyEmitterConfig,
    scenario_id: &str,
    event_id: &str,
    sample: TailLatencyCompactSample,
) -> Result<Option<TailLatencyCompactEvent>, TailLatencyEmitError> {
    if !config.enabled {
        return Ok(None);
    }
    if scenario_id.trim().is_empty() {
        return Err(TailLatencyEmitError::EmptyScenarioId);
    }
    if event_id.trim().is_empty() {
        return Err(TailLatencyEmitError::EmptyEventId);
    }

    let direct_duration_ns = sample
        .retries_total_delay_ns
        .unwrap_or(0)
        .saturating_add(sample.synchronization_lock_wait_ns.unwrap_or(0));
    if direct_duration_ns > sample.total_latency_ns {
        return Err(TailLatencyEmitError::DirectDurationExceedsTotal {
            total_latency_ns: sample.total_latency_ns,
            direct_duration_ns,
        });
    }
    let unknown_unmeasured_ns = sample.total_latency_ns - direct_duration_ns;

    let mut fields = BTreeMap::new();
    let mut attribution_states = BTreeMap::new();
    let mut missing_producers = Vec::new();

    fields.insert(
        "tail.contract_version".to_string(),
        TailLatencyFieldValue::Text(TAIL_LATENCY_TAXONOMY_CONTRACT_VERSION.to_string()),
    );
    fields.insert(
        "tail.total_latency_ns".to_string(),
        TailLatencyFieldValue::Unsigned(sample.total_latency_ns),
    );
    tail_field_from_optional(
        &mut fields,
        &mut missing_producers,
        &mut attribution_states,
        "tail.queueing.ready_queue_depth",
        "queueing",
        "proxy_signal",
        sample.ready_queue_depth,
    );
    tail_field_from_optional(
        &mut fields,
        &mut missing_producers,
        &mut attribution_states,
        "tail.service.poll_count",
        "service",
        "proxy_signal",
        sample.poll_count,
    );
    tail_field_from_optional(
        &mut fields,
        &mut missing_producers,
        &mut attribution_states,
        "tail.io_or_network.events_received",
        "io_or_network",
        "proxy_signal",
        sample.events_received,
    );
    tail_field_from_optional(
        &mut fields,
        &mut missing_producers,
        &mut attribution_states,
        "tail.retries.total_delay_ns",
        "retries",
        "direct_duration",
        sample.retries_total_delay_ns,
    );
    tail_field_from_optional(
        &mut fields,
        &mut missing_producers,
        &mut attribution_states,
        "tail.synchronization.lock_wait_ns",
        "synchronization",
        "direct_duration",
        sample.synchronization_lock_wait_ns,
    );
    tail_field_from_optional(
        &mut fields,
        &mut missing_producers,
        &mut attribution_states,
        "tail.allocator_or_cache.live_allocations",
        "allocator_or_cache",
        "proxy_signal",
        sample.allocator_live_allocations,
    );
    fields.insert(
        "tail.unknown.unmeasured_ns".to_string(),
        TailLatencyFieldValue::Unsigned(unknown_unmeasured_ns),
    );
    attribution_states.insert(
        "unknown".to_string(),
        if unknown_unmeasured_ns == 0 {
            "fully_attributed".to_string()
        } else {
            "residual".to_string()
        },
    );

    if config.include_extended_allocator_bytes_live {
        if let Some(bytes_live) = sample.allocator_bytes_live {
            fields.insert(
                "tail.allocator_or_cache.bytes_live".to_string(),
                TailLatencyFieldValue::Unsigned(bytes_live),
            );
        }
    }

    missing_producers.sort();
    missing_producers.dedup();
    let overhead_estimate_bytes = tail_compact_event_overhead_estimate_bytes(
        fields.len(),
        attribution_states.len(),
        missing_producers.len(),
    );

    Ok(Some(TailLatencyCompactEvent {
        schema_version: TAIL_LATENCY_COMPACT_EVENT_SCHEMA_VERSION.to_string(),
        scenario_id: scenario_id.trim().to_string(),
        event_id: event_id.trim().to_string(),
        taxonomy_version: TAIL_LATENCY_TAXONOMY_CONTRACT_VERSION.to_string(),
        fields,
        attribution_states,
        missing_producers,
        unknown_unmeasured_ns,
        overhead_estimate_bytes,
    }))
}

/// Latency-budget certificate schema version.
pub const TAIL_LATENCY_BUDGET_CERTIFICATE_SCHEMA_VERSION: &str =
    "runtime-latency-budget-certificate-v1";

/// Operator-facing verdict for a latency-budget certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TailLatencyBudgetVerdict {
    /// Evidence is valid and the candidate stays within the requested budget.
    Pass,
    /// Evidence is valid, but the conservative fallback is safer.
    NoWin,
    /// Evidence is incomplete, stale, contradictory, or proxy-only.
    FailClosed,
}

impl TailLatencyBudgetVerdict {
    /// Stable string representation used by artifacts and smoke reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::NoWin => "no_win",
            Self::FailClosed => "fail_closed",
        }
    }
}

/// Quantile evidence required before a latency-budget certificate can pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailLatencyBudgetQuantiles {
    /// Median latency for the scenario.
    pub p50_latency_ns: u64,
    /// p95 latency for the scenario.
    pub p95_latency_ns: u64,
    /// p99 latency for the scenario.
    pub p99_latency_ns: u64,
    /// p999 latency for the scenario.
    pub p999_latency_ns: u64,
}

impl TailLatencyBudgetQuantiles {
    /// Build quantile evidence.
    #[must_use]
    pub const fn new(
        p50_latency_ns: u64,
        p95_latency_ns: u64,
        p99_latency_ns: u64,
        p999_latency_ns: u64,
    ) -> Self {
        Self {
            p50_latency_ns,
            p95_latency_ns,
            p99_latency_ns,
            p999_latency_ns,
        }
    }

    fn ordered(self) -> bool {
        self.p50_latency_ns <= self.p95_latency_ns
            && self.p95_latency_ns <= self.p99_latency_ns
            && self.p99_latency_ns <= self.p999_latency_ns
    }
}

/// Conservative uncertainty interval around the reported tail quantile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailLatencyBudgetUncertainty {
    /// Lower uncertainty bound in nanoseconds.
    pub lower_bound_ns: u64,
    /// Upper uncertainty bound in nanoseconds.
    pub upper_bound_ns: u64,
}

impl TailLatencyBudgetUncertainty {
    /// Build uncertainty evidence.
    #[must_use]
    pub const fn new(lower_bound_ns: u64, upper_bound_ns: u64) -> Self {
        Self {
            lower_bound_ns,
            upper_bound_ns,
        }
    }

    fn valid(self) -> bool {
        self.lower_bound_ns <= self.upper_bound_ns
    }
}

/// Verification gates for one latency-budget certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailLatencyBudgetGate {
    /// Maximum certified p999 latency after uncertainty is applied.
    pub budget_p999_latency_ns: u64,
    /// Minimum number of samples needed before the quantiles are meaningful.
    pub min_sample_count: u64,
    /// Maximum total unknown residual accepted across compact tail events.
    pub max_unknown_residual_ns: u64,
    /// Maximum unknown residual as basis points of total observed latency.
    pub max_unknown_residual_basis_points: u64,
    /// Latest evidence epoch covered by calibration.
    pub calibration_valid_until_epoch: u64,
    /// Candidate p999 may regress by this many nanoseconds before fallback wins.
    pub allowed_p999_regression_ns: u64,
}

impl TailLatencyBudgetGate {
    /// Build a latency-budget gate.
    #[must_use]
    pub const fn new(
        budget_p999_latency_ns: u64,
        min_sample_count: u64,
        max_unknown_residual_ns: u64,
        max_unknown_residual_basis_points: u64,
        calibration_valid_until_epoch: u64,
        allowed_p999_regression_ns: u64,
    ) -> Self {
        Self {
            budget_p999_latency_ns,
            min_sample_count,
            max_unknown_residual_ns,
            max_unknown_residual_basis_points,
            calibration_valid_until_epoch,
            allowed_p999_regression_ns,
        }
    }
}

/// Evidence consumed by the latency-budget certificate verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailLatencyBudgetEvidence {
    /// Stable certificate identifier.
    pub certificate_id: String,
    /// Scenario or workload identifier.
    pub scenario_id: String,
    /// Candidate profile or controller id.
    pub candidate_id: String,
    /// Conservative fallback profile id.
    pub fallback_profile: String,
    /// Deterministic replay command for the evidence packet.
    pub replay_command: String,
    /// Number of samples behind the quantiles.
    pub sample_count: u64,
    /// Epoch of the evidence packet.
    pub evidence_epoch: u64,
    /// Optional quantile evidence. Absence is treated as mean-only evidence.
    pub quantiles: Option<TailLatencyBudgetQuantiles>,
    /// Optional uncertainty interval around the tail quantile.
    pub uncertainty: Option<TailLatencyBudgetUncertainty>,
    /// Baseline p999 latency for asymmetric regression checks.
    pub baseline_p999_latency_ns: u64,
    /// Candidate p999 latency for asymmetric regression checks.
    pub candidate_p999_latency_ns: u64,
    /// Verification gates.
    pub gate: TailLatencyBudgetGate,
    /// Compact tail rows backing the term breakdown.
    pub tail_events: Vec<TailLatencyCompactEvent>,
}

impl TailLatencyBudgetEvidence {
    /// Build evidence with conservative empty optional fields.
    #[must_use]
    pub fn new(
        certificate_id: impl Into<String>,
        scenario_id: impl Into<String>,
        candidate_id: impl Into<String>,
        fallback_profile: impl Into<String>,
        replay_command: impl Into<String>,
        gate: TailLatencyBudgetGate,
    ) -> Self {
        Self {
            certificate_id: certificate_id.into(),
            scenario_id: scenario_id.into(),
            candidate_id: candidate_id.into(),
            fallback_profile: fallback_profile.into(),
            replay_command: replay_command.into(),
            sample_count: 0,
            evidence_epoch: 0,
            quantiles: None,
            uncertainty: None,
            baseline_p999_latency_ns: 0,
            candidate_p999_latency_ns: 0,
            gate,
            tail_events: Vec::new(),
        }
    }

    /// Attach quantile evidence.
    #[must_use]
    pub fn with_quantiles(mut self, quantiles: TailLatencyBudgetQuantiles) -> Self {
        self.quantiles = Some(quantiles);
        self
    }

    /// Attach uncertainty bounds.
    #[must_use]
    pub fn with_uncertainty(mut self, uncertainty: TailLatencyBudgetUncertainty) -> Self {
        self.uncertainty = Some(uncertainty);
        self
    }

    /// Attach sample count and evidence epoch.
    #[must_use]
    pub fn with_sample_window(mut self, sample_count: u64, evidence_epoch: u64) -> Self {
        self.sample_count = sample_count;
        self.evidence_epoch = evidence_epoch;
        self
    }

    /// Attach baseline and candidate p999 values for asymmetric regression checks.
    #[must_use]
    pub fn with_regression_window(
        mut self,
        baseline_p999_latency_ns: u64,
        candidate_p999_latency_ns: u64,
    ) -> Self {
        self.baseline_p999_latency_ns = baseline_p999_latency_ns;
        self.candidate_p999_latency_ns = candidate_p999_latency_ns;
        self
    }

    /// Attach compact tail events.
    #[must_use]
    pub fn with_tail_events(mut self, tail_events: Vec<TailLatencyCompactEvent>) -> Self {
        self.tail_events = tail_events;
        self
    }
}

/// Per-term evidence row carried by a latency-budget certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailLatencyBudgetTermEvidence {
    /// Canonical term id.
    pub term_id: String,
    /// Stable structured field key used for the term's compact evidence.
    pub field_key: String,
    /// Direct, proxy, or unknown bucket evidence class.
    pub measurement_class: String,
    /// Aggregated attribution state for the term.
    pub attribution_state: String,
    /// Sum of observed compact field values across all events.
    pub observed_value: u64,
    /// Sum of direct-duration nanoseconds for terms with direct measurements.
    pub direct_duration_ns: u64,
}

/// Verifier output for one latency-budget certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailLatencyBudgetCertificate {
    /// Certificate schema version.
    pub schema_version: String,
    /// Stable certificate identifier.
    pub certificate_id: String,
    /// Deterministic FNV-1a hash over the certificate projection.
    pub certificate_hash: String,
    /// Scenario or workload identifier.
    pub scenario_id: String,
    /// Candidate profile or controller id.
    pub candidate_id: String,
    /// Conservative fallback profile id.
    pub fallback_profile: String,
    /// Taxonomy version backing compact tail events.
    pub taxonomy_version: String,
    /// Operator-facing verdict.
    pub verdict: TailLatencyBudgetVerdict,
    /// Stable reason codes explaining fail-closed or no-win outcomes.
    pub reason_codes: Vec<String>,
    /// First fallback or fail-closed reason, if any.
    pub fallback_reason: Option<String>,
    /// Number of samples behind the quantiles.
    pub sample_count: u64,
    /// Certified p50 latency.
    pub p50_latency_ns: Option<u64>,
    /// Certified p95 latency.
    pub p95_latency_ns: Option<u64>,
    /// Certified p99 latency.
    pub p99_latency_ns: Option<u64>,
    /// Certified p999 latency.
    pub p999_latency_ns: Option<u64>,
    /// Lower uncertainty bound.
    pub uncertainty_lower_bound_ns: Option<u64>,
    /// Upper uncertainty bound.
    pub uncertainty_upper_bound_ns: Option<u64>,
    /// Budget gate applied to p999 plus uncertainty.
    pub budget_p999_latency_ns: u64,
    /// Total unknown residual across compact tail events.
    pub unknown_residual_ns: u64,
    /// Unknown residual as basis points of total compact-event latency.
    pub unknown_residual_basis_points: u64,
    /// Per-term evidence breakdown in canonical term order.
    pub term_breakdown: Vec<TailLatencyBudgetTermEvidence>,
    /// Deterministic replay command for the evidence packet.
    pub replay_command: String,
}

fn tail_field_unsigned(event: &TailLatencyCompactEvent, key: &str) -> Option<u64> {
    match event.fields.get(key) {
        Some(TailLatencyFieldValue::Unsigned(value)) => Some(*value),
        _ => None,
    }
}

fn tail_term_field_key(term_id: &str) -> &'static str {
    match term_id {
        "queueing" => "tail.queueing.ready_queue_depth",
        "service" => "tail.service.poll_count",
        "io_or_network" => "tail.io_or_network.events_received",
        "retries" => "tail.retries.total_delay_ns",
        "synchronization" => "tail.synchronization.lock_wait_ns",
        "allocator_or_cache" => "tail.allocator_or_cache.live_allocations",
        "unknown" => "tail.unknown.unmeasured_ns",
        _ => "tail.unknown.unmeasured_ns",
    }
}

fn tail_term_measurement_class(term_id: &str) -> &'static str {
    match term_id {
        "retries" | "synchronization" => "direct_duration",
        "unknown" => "unknown_bucket",
        _ => "proxy_signal",
    }
}

fn unique_push_reason(reasons: &mut Vec<String>, reason: impl Into<String>) {
    let reason = reason.into();
    if !reasons.contains(&reason) {
        reasons.push(reason);
    }
}

fn stable_fnv1a64_hex(bytes: &[u8]) -> String {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;

    let mut hash = OFFSET;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }
    format!("fnv1a64:{hash:016x}")
}

fn tail_latency_budget_certificate_hash(certificate: &TailLatencyBudgetCertificate) -> String {
    let mut projection = String::new();
    projection.push_str(&certificate.schema_version);
    projection.push('|');
    projection.push_str(&certificate.certificate_id);
    projection.push('|');
    projection.push_str(&certificate.scenario_id);
    projection.push('|');
    projection.push_str(&certificate.candidate_id);
    projection.push('|');
    projection.push_str(certificate.verdict.as_str());
    projection.push('|');
    projection.push_str(&certificate.sample_count.to_string());
    projection.push('|');
    projection.push_str(&certificate.unknown_residual_ns.to_string());
    projection.push('|');
    projection.push_str(&certificate.unknown_residual_basis_points.to_string());
    for reason in &certificate.reason_codes {
        projection.push('|');
        projection.push_str(reason);
    }
    for term in &certificate.term_breakdown {
        projection.push('|');
        projection.push_str(&term.term_id);
        projection.push('=');
        projection.push_str(&term.measurement_class);
        projection.push(':');
        projection.push_str(&term.attribution_state);
        projection.push(':');
        projection.push_str(&term.observed_value.to_string());
        projection.push(':');
        projection.push_str(&term.direct_duration_ns.to_string());
    }
    stable_fnv1a64_hex(projection.as_bytes())
}

/// Verify one latency-budget certificate from compact tail evidence.
///
/// Invalid evidence returns a `fail_closed` certificate instead of a pass. Valid
/// evidence that misses the requested budget returns `no_win`, preserving the
/// conservative fallback profile.
#[must_use]
pub fn verify_tail_latency_budget_certificate(
    evidence: TailLatencyBudgetEvidence,
) -> TailLatencyBudgetCertificate {
    let contract = tail_latency_taxonomy_contract();
    let mut fail_reasons = Vec::new();
    let mut no_win_reasons = Vec::new();
    let mut direct_duration_seen = false;
    let mut unknown_residual_ns = 0_u64;
    let mut total_latency_ns = 0_u64;

    if evidence.certificate_id.trim().is_empty() {
        unique_push_reason(&mut fail_reasons, "empty_certificate_id");
    }
    if evidence.scenario_id.trim().is_empty() {
        unique_push_reason(&mut fail_reasons, "empty_scenario_id");
    }
    if evidence.candidate_id.trim().is_empty() {
        unique_push_reason(&mut fail_reasons, "empty_candidate_id");
    }
    if evidence.fallback_profile.trim().is_empty() {
        unique_push_reason(&mut fail_reasons, "empty_fallback_profile");
    }
    if evidence.replay_command.trim().is_empty() {
        unique_push_reason(&mut fail_reasons, "missing_replay_command");
    }
    if evidence.tail_events.is_empty() {
        unique_push_reason(&mut fail_reasons, "missing_tail_events");
    }
    if evidence.sample_count < evidence.gate.min_sample_count {
        unique_push_reason(&mut fail_reasons, "insufficient_sample_count");
    }
    if evidence.evidence_epoch > evidence.gate.calibration_valid_until_epoch {
        unique_push_reason(&mut fail_reasons, "stale_calibration");
    }

    let quantiles = evidence.quantiles;
    if let Some(quantiles) = quantiles {
        if !quantiles.ordered() {
            unique_push_reason(&mut fail_reasons, "unordered_quantiles");
        }
    } else {
        unique_push_reason(&mut fail_reasons, "missing_quantiles_mean_only_evidence");
    }

    let uncertainty = evidence.uncertainty;
    if let Some(uncertainty) = uncertainty {
        if !uncertainty.valid() {
            unique_push_reason(&mut fail_reasons, "invalid_uncertainty_bounds");
        }
    } else {
        unique_push_reason(&mut fail_reasons, "missing_uncertainty_bounds");
    }

    let term_ids: Vec<&str> = contract
        .terms
        .iter()
        .map(|term| term.term_id.as_str())
        .collect();
    let required_keys: Vec<&str> = contract
        .required_log_fields
        .iter()
        .map(|field| field.key.as_str())
        .collect();
    let mut term_breakdown = Vec::with_capacity(term_ids.len());

    for event in &evidence.tail_events {
        if event.schema_version != TAIL_LATENCY_COMPACT_EVENT_SCHEMA_VERSION {
            unique_push_reason(&mut fail_reasons, "wrong_tail_event_schema");
        }
        if event.taxonomy_version != TAIL_LATENCY_TAXONOMY_CONTRACT_VERSION {
            unique_push_reason(&mut fail_reasons, "wrong_tail_taxonomy_version");
        }
        for key in &required_keys {
            if !event.fields.contains_key(*key) {
                unique_push_reason(&mut fail_reasons, format!("missing_required_field:{key}"));
            }
        }
        for term_id in &term_ids {
            if !event.attribution_states.contains_key(*term_id) {
                unique_push_reason(&mut fail_reasons, format!("missing_term:{term_id}"));
            }
        }

        let event_total = tail_field_unsigned(event, "tail.total_latency_ns").unwrap_or(0);
        total_latency_ns = total_latency_ns.saturating_add(event_total);
        let unknown_field = tail_field_unsigned(event, "tail.unknown.unmeasured_ns");
        if unknown_field != Some(event.unknown_unmeasured_ns) {
            unique_push_reason(&mut fail_reasons, "hidden_unknown_bucket");
        }
        if !event.missing_producers.is_empty() && event.unknown_unmeasured_ns == 0 {
            unique_push_reason(&mut fail_reasons, "hidden_unknown_bucket");
        }
        unknown_residual_ns = unknown_residual_ns.saturating_add(event.unknown_unmeasured_ns);

        let retries_direct = tail_field_unsigned(event, "tail.retries.total_delay_ns").unwrap_or(0);
        let sync_direct =
            tail_field_unsigned(event, "tail.synchronization.lock_wait_ns").unwrap_or(0);
        direct_duration_seen |= retries_direct > 0 || sync_direct > 0;
    }

    if !evidence.tail_events.is_empty() && !direct_duration_seen {
        unique_push_reason(&mut fail_reasons, "proxy_only_green_row");
    }

    for term_id in &term_ids {
        let field_key = tail_term_field_key(term_id);
        let measurement_class = tail_term_measurement_class(term_id);
        let mut observed_value = 0_u64;
        let mut direct_duration_ns = 0_u64;
        let mut state = "absent";
        let mut missing = false;
        for event in &evidence.tail_events {
            observed_value =
                observed_value.saturating_add(tail_field_unsigned(event, field_key).unwrap_or(0));
            if measurement_class == "direct_duration" {
                direct_duration_ns = direct_duration_ns
                    .saturating_add(tail_field_unsigned(event, field_key).unwrap_or(0));
            }
            match event.attribution_states.get(*term_id).map(String::as_str) {
                Some("missing_producer") => missing = true,
                Some(current) if state == "absent" => state = current,
                Some(current) if state != current => state = "mixed",
                _ => {}
            }
        }
        if missing {
            state = "missing_producer";
        }
        term_breakdown.push(TailLatencyBudgetTermEvidence {
            term_id: (*term_id).to_string(),
            field_key: field_key.to_string(),
            measurement_class: measurement_class.to_string(),
            attribution_state: state.to_string(),
            observed_value,
            direct_duration_ns,
        });
    }

    let unknown_residual_basis_points = if total_latency_ns == 0 {
        0
    } else {
        unknown_residual_ns
            .saturating_mul(10_000)
            .saturating_div(total_latency_ns)
    };

    if unknown_residual_ns > evidence.gate.max_unknown_residual_ns {
        unique_push_reason(&mut no_win_reasons, "unknown_residual_above_limit");
    }
    if unknown_residual_basis_points > evidence.gate.max_unknown_residual_basis_points {
        unique_push_reason(&mut no_win_reasons, "unknown_fraction_above_limit");
    }
    if let (Some(quantiles), Some(uncertainty)) = (quantiles, uncertainty) {
        let conservative_p999 = quantiles
            .p999_latency_ns
            .saturating_add(uncertainty.upper_bound_ns);
        if conservative_p999 > evidence.gate.budget_p999_latency_ns {
            unique_push_reason(&mut no_win_reasons, "p999_budget_exceeded");
        }
        let allowed_candidate_p999 = evidence
            .baseline_p999_latency_ns
            .saturating_add(evidence.gate.allowed_p999_regression_ns);
        if evidence.candidate_p999_latency_ns > allowed_candidate_p999 {
            unique_push_reason(&mut no_win_reasons, "asymmetric_regression_gate");
        }
    }

    let (verdict, reason_codes) = if fail_reasons.is_empty() {
        if no_win_reasons.is_empty() {
            (TailLatencyBudgetVerdict::Pass, Vec::new())
        } else {
            (TailLatencyBudgetVerdict::NoWin, no_win_reasons)
        }
    } else {
        (TailLatencyBudgetVerdict::FailClosed, fail_reasons)
    };
    let fallback_reason = reason_codes.first().cloned();

    let mut certificate = TailLatencyBudgetCertificate {
        schema_version: TAIL_LATENCY_BUDGET_CERTIFICATE_SCHEMA_VERSION.to_string(),
        certificate_id: evidence.certificate_id.trim().to_string(),
        certificate_hash: String::new(),
        scenario_id: evidence.scenario_id.trim().to_string(),
        candidate_id: evidence.candidate_id.trim().to_string(),
        fallback_profile: evidence.fallback_profile.trim().to_string(),
        taxonomy_version: TAIL_LATENCY_TAXONOMY_CONTRACT_VERSION.to_string(),
        verdict,
        reason_codes,
        fallback_reason,
        sample_count: evidence.sample_count,
        p50_latency_ns: quantiles.map(|value| value.p50_latency_ns),
        p95_latency_ns: quantiles.map(|value| value.p95_latency_ns),
        p99_latency_ns: quantiles.map(|value| value.p99_latency_ns),
        p999_latency_ns: quantiles.map(|value| value.p999_latency_ns),
        uncertainty_lower_bound_ns: uncertainty.map(|value| value.lower_bound_ns),
        uncertainty_upper_bound_ns: uncertainty.map(|value| value.upper_bound_ns),
        budget_p999_latency_ns: evidence.gate.budget_p999_latency_ns,
        unknown_residual_ns,
        unknown_residual_basis_points,
        term_breakdown,
        replay_command: evidence.replay_command,
    };
    certificate.certificate_hash = tail_latency_budget_certificate_hash(&certificate);
    certificate
}

/// Wait-cause remediation report schema version.
pub const WAIT_CAUSE_REMEDIATION_REPORT_SCHEMA_VERSION: &str =
    "runtime-wait-cause-remediation-report-v1";

/// Operator-facing report verdict for wait-cause remediation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WaitCauseRemediationVerdict {
    /// The report has ranked findings and safe next actions.
    Actionable,
    /// The report is valid, but only low-confidence unknown waits were found.
    Investigate,
    /// The evidence packet was incomplete, stale, or off-contract.
    Refused,
}

impl WaitCauseRemediationVerdict {
    /// Stable string representation used by artifacts and smoke reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Actionable => "actionable",
            Self::Investigate => "investigate",
            Self::Refused => "refused",
        }
    }
}

/// Canonical wait-cause classes surfaced to operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WaitCauseCategory {
    /// A directed wait-for cycle was found.
    DeadlockCycle,
    /// A task is stuck awaiting a future without a pending wake.
    Futurelock,
    /// A reserved obligation is still held.
    ObligationLeak,
    /// The system can identify a wait, but not a stronger root cause.
    UnknownWait,
}

impl WaitCauseCategory {
    /// Stable string representation used by artifacts and smoke reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeadlockCycle => "deadlock_cycle",
            Self::Futurelock => "futurelock",
            Self::ObligationLeak => "obligation_leak",
            Self::UnknownWait => "unknown_wait",
        }
    }
}

/// Severity of one wait-cause remediation finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WaitCauseSeverity {
    /// Trapped cycle or high-confidence leak that can stop quiescence.
    Critical,
    /// Strong evidence of a blocked runtime path.
    High,
    /// Weak or ambiguous evidence that still needs investigation.
    Warning,
    /// Informational row.
    Info,
}

impl WaitCauseSeverity {
    /// Stable string representation used by artifacts and smoke reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Warning => "warning",
            Self::Info => "info",
        }
    }

    const fn sort_rank(self) -> u8 {
        match self {
            Self::Critical => 4,
            Self::High => 3,
            Self::Warning => 2,
            Self::Info => 1,
        }
    }
}

/// Task wait kind consumed by the remediation report builder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitCauseTaskWaitKind {
    /// The task is awaiting a future or external producer.
    AwaitingFuture,
    /// The task has a pending wake and should be scheduled.
    AwaitingSchedule,
    /// The task is blocked, but the await point is unknown.
    Unknown,
}

impl WaitCauseTaskWaitKind {
    /// Stable string representation used in graph hashes.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AwaitingFuture => "awaiting_future",
            Self::AwaitingSchedule => "awaiting_schedule",
            Self::Unknown => "unknown",
        }
    }
}

/// Evidence for one task-level wait row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaitCauseTaskEvidence {
    /// Blocked task.
    pub task_id: TaskId,
    /// Owning region if known.
    pub region_id: Option<RegionId>,
    /// Wait classification.
    pub wait_kind: WaitCauseTaskWaitKind,
    /// Resource or producer the task appears to be waiting on.
    pub blocked_resource: String,
    /// Observed wait age in nanoseconds.
    pub wait_age_ns: u64,
    /// Whether a wake is already pending for this task.
    pub wake_pending: bool,
    /// Sanitized detail strings used only for evidence hashing and summaries.
    pub details: Vec<String>,
}

impl WaitCauseTaskEvidence {
    /// Build task wait evidence.
    #[must_use]
    pub fn new(
        task_id: TaskId,
        region_id: Option<RegionId>,
        wait_kind: WaitCauseTaskWaitKind,
        blocked_resource: impl Into<String>,
    ) -> Self {
        Self {
            task_id,
            region_id,
            wait_kind,
            blocked_resource: blocked_resource.into(),
            wait_age_ns: 0,
            wake_pending: false,
            details: Vec::new(),
        }
    }

    /// Build task evidence from an existing task-blocked explanation.
    #[must_use]
    pub fn from_task_blocked(
        explanation: &TaskBlockedExplanation,
        region_id: Option<RegionId>,
        wait_age_ns: u64,
        wake_pending: bool,
    ) -> Self {
        let wait_kind = match &explanation.block_reason {
            BlockReason::AwaitingFuture { .. } => WaitCauseTaskWaitKind::AwaitingFuture,
            BlockReason::AwaitingSchedule => WaitCauseTaskWaitKind::AwaitingSchedule,
            _ => WaitCauseTaskWaitKind::Unknown,
        };
        let blocked_resource = sanitize_remediation_text(&explanation.block_reason.to_string());
        Self {
            task_id: explanation.task_id,
            region_id,
            wait_kind,
            blocked_resource,
            wait_age_ns,
            wake_pending,
            details: explanation
                .details
                .iter()
                .map(|detail| sanitize_remediation_text(detail))
                .collect(),
        }
    }

    /// Attach observed wait age.
    #[must_use]
    pub const fn with_wait_age_ns(mut self, wait_age_ns: u64) -> Self {
        self.wait_age_ns = wait_age_ns;
        self
    }

    /// Mark whether a wake is pending.
    #[must_use]
    pub const fn with_wake_pending(mut self, wake_pending: bool) -> Self {
        self.wake_pending = wake_pending;
        self
    }

    /// Attach deterministic detail strings.
    #[must_use]
    pub fn with_details(mut self, details: Vec<String>) -> Self {
        self.details = details
            .into_iter()
            .map(|detail| sanitize_remediation_text(&detail))
            .collect();
        self
    }
}

/// Evidence for one obligation held across a wait-cause snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaitCauseObligationEvidence {
    /// Obligation id.
    pub obligation_id: ObligationId,
    /// Stable obligation kind string.
    pub obligation_type: String,
    /// Task currently holding the obligation.
    pub holder_task: Option<TaskId>,
    /// Region that owns the obligation.
    pub region_id: RegionId,
    /// Observed age in nanoseconds.
    pub age_ns: u64,
}

impl WaitCauseObligationEvidence {
    /// Build obligation wait evidence.
    #[must_use]
    pub fn new(
        obligation_id: ObligationId,
        obligation_type: impl Into<String>,
        holder_task: Option<TaskId>,
        region_id: RegionId,
        age_ns: u64,
    ) -> Self {
        Self {
            obligation_id,
            obligation_type: sanitize_remediation_text(&obligation_type.into()),
            holder_task,
            region_id,
            age_ns,
        }
    }

    /// Build obligation evidence from an existing leak snapshot.
    #[must_use]
    pub fn from_obligation_leak(leak: &ObligationLeak) -> Self {
        let nanos = u64::try_from(leak.age.as_nanos()).unwrap_or(u64::MAX);
        Self::new(
            leak.obligation_id,
            leak.obligation_type.clone(),
            leak.holder_task,
            leak.region_id,
            nanos,
        )
    }
}

/// Input packet consumed by the wait-cause remediation report builder.
#[derive(Debug, Clone)]
pub struct WaitCauseRemediationEvidence {
    /// Stable report id.
    pub report_id: String,
    /// Scenario or workload id.
    pub scenario_id: String,
    /// Deterministic replay command for this snapshot.
    pub replay_command: String,
    /// Tail taxonomy contract version linked to this report.
    pub tail_taxonomy_version: String,
    /// Optional directional deadlock report from runtime diagnostics.
    pub deadlock_report: Option<DirectionalDeadlockReport>,
    /// Task-level wait evidence rows.
    pub task_waits: Vec<WaitCauseTaskEvidence>,
    /// Obligation-level wait evidence rows.
    pub obligation_leaks: Vec<WaitCauseObligationEvidence>,
    /// Artifact, certificate, or source references used to produce the report.
    pub evidence_refs: Vec<String>,
}

impl WaitCauseRemediationEvidence {
    /// Build a remediation evidence packet with the current tail taxonomy.
    #[must_use]
    pub fn new(
        report_id: impl Into<String>,
        scenario_id: impl Into<String>,
        replay_command: impl Into<String>,
    ) -> Self {
        Self {
            report_id: report_id.into(),
            scenario_id: scenario_id.into(),
            replay_command: replay_command.into(),
            tail_taxonomy_version: TAIL_LATENCY_TAXONOMY_CONTRACT_VERSION.to_string(),
            deadlock_report: None,
            task_waits: Vec::new(),
            obligation_leaks: Vec::new(),
            evidence_refs: Vec::new(),
        }
    }

    /// Override the tail taxonomy version. Non-current values fail closed.
    #[must_use]
    pub fn with_tail_taxonomy_version(mut self, version: impl Into<String>) -> Self {
        self.tail_taxonomy_version = version.into();
        self
    }

    /// Attach a directional deadlock report.
    #[must_use]
    pub fn with_deadlock_report(mut self, report: DirectionalDeadlockReport) -> Self {
        self.deadlock_report = Some(report);
        self
    }

    /// Attach task wait evidence rows.
    #[must_use]
    pub fn with_task_waits(mut self, waits: Vec<WaitCauseTaskEvidence>) -> Self {
        self.task_waits = waits;
        self
    }

    /// Attach obligation leak evidence rows.
    #[must_use]
    pub fn with_obligation_leaks(mut self, leaks: Vec<WaitCauseObligationEvidence>) -> Self {
        self.obligation_leaks = leaks;
        self
    }

    /// Attach deterministic evidence references.
    #[must_use]
    pub fn with_evidence_refs(mut self, refs: Vec<String>) -> Self {
        self.evidence_refs = refs
            .into_iter()
            .map(|reference| sanitize_cancel_message(&reference))
            .collect();
        self
    }
}

/// One ranked root-cause finding in a wait-cause remediation report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaitCauseRemediationFinding {
    /// Deterministic finding id assigned after ranking.
    pub finding_id: String,
    /// One-based rank in the report.
    pub rank: usize,
    /// Stable ASUP error code, when this wait cause maps to the runtime registry.
    pub asup_code: Option<String>,
    /// Registry-backed remediation page, when an ASUP code is available.
    pub remediation_doc_path: Option<String>,
    /// Wait-cause category.
    pub category: WaitCauseCategory,
    /// Finding severity.
    pub severity: WaitCauseSeverity,
    /// Confidence in basis points.
    pub confidence_basis_points: u16,
    /// Stable reason code.
    pub reason_code: String,
    /// Operator-safe summary.
    pub summary: String,
    /// Blocked resource or wait-graph component.
    pub blocked_resource: String,
    /// Owning task id if known.
    pub owner_task_id: Option<String>,
    /// Owning region id if known.
    pub owner_region_id: Option<String>,
    /// Evidence references backing this finding.
    pub evidence_refs: Vec<String>,
    /// Safe next actions. These must be non-destructive.
    pub safe_actions: Vec<String>,
    /// Explicitly forbidden destructive or ambiguous actions.
    pub forbidden_actions: Vec<String>,
    /// Replay command for the finding.
    pub replay_command: String,
}

/// Deterministic operator report for wait-cause remediation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaitCauseRemediationReport {
    /// Report schema version.
    pub schema_version: String,
    /// Stable report id.
    pub report_id: String,
    /// Deterministic hash over the report projection.
    pub report_hash: String,
    /// Scenario or workload id.
    pub scenario_id: String,
    /// Deterministic hash over the wait-cause evidence graph.
    pub wait_cause_graph_hash: String,
    /// Linked tail taxonomy contract version.
    pub tail_taxonomy_version: String,
    /// Overall report verdict.
    pub verdict: WaitCauseRemediationVerdict,
    /// Refusal reason for off-contract evidence.
    pub refusal_reason: Option<String>,
    /// Ranked findings.
    pub findings: Vec<WaitCauseRemediationFinding>,
    /// Flattened, deduplicated safe action list.
    pub safe_actions: Vec<String>,
    /// Explicit destructive-action disclaimer.
    pub forbidden_action_disclaimer: String,
    /// Deterministic replay command.
    pub replay_command: String,
    /// Evidence references used by the report.
    pub evidence_refs: Vec<String>,
}

fn sanitize_remediation_text(input: &str) -> String {
    let sanitized = sanitize_cancel_message(input);
    let mut tokens = Vec::new();
    for token in sanitized.split_whitespace() {
        if token.contains('/') || token.contains('\\') {
            tokens.push("[redacted-path]".to_string());
        } else if token.contains('@') {
            tokens.push("[redacted-identity]".to_string());
        } else {
            tokens.push(token.to_string());
        }
    }
    if tokens.is_empty() {
        String::new()
    } else {
        tokens.join(" ")
    }
}

fn remediation_forbidden_actions() -> Vec<String> {
    vec![
        "Do not delete files, artifacts, or trace evidence while diagnosing the wait.".to_string(),
        "Do not reset git state or discard unrelated work to clear a stall.".to_string(),
        "Do not kill unknown tasks or processes until ownership and replay evidence are recorded."
            .to_string(),
    ]
}

fn deadlock_safe_actions(trapped: bool) -> Vec<String> {
    let mut actions = vec![
        "Capture the wait-graph artifact before changing runtime state.".to_string(),
        "Replay and minimize the cycle before widening the investigation.".to_string(),
    ];
    if trapped {
        actions.push(
            "Cancel the smallest non-critical owning region only after drain ownership is known."
                .to_string(),
        );
    } else {
        actions.push("Inspect the egress edge before forcing cancellation.".to_string());
    }
    actions
}

fn futurelock_safe_actions() -> Vec<String> {
    vec![
        "Inspect the awaited producer and wake path for the blocked task.".to_string(),
        "Use the replay command before adding timeouts or policy changes.".to_string(),
        "Cancel the owning region only if the task is non-critical and drain evidence is recorded."
            .to_string(),
    ]
}

fn obligation_safe_actions() -> Vec<String> {
    vec![
        "Resolve the named obligation through its owning protocol commit or abort path."
            .to_string(),
        "Inspect the holder task before closing the region.".to_string(),
        "Verify drain and finalize paths clear the obligation in replay.".to_string(),
    ]
}

fn unknown_wait_safe_actions() -> Vec<String> {
    vec![
        "Collect a fresh diagnostics snapshot with task, region, and obligation rows.".to_string(),
        "Preserve replay artifacts before attempting remediation.".to_string(),
        "Escalate to focused instrumentation instead of guessing at destructive cleanup."
            .to_string(),
    ]
}

fn wait_cause_asup_metadata(
    category: WaitCauseCategory,
) -> (Option<&'static str>, Option<&'static str>) {
    match category {
        WaitCauseCategory::Futurelock => (Some("ASUP-E402"), Some("docs/error_codes/ASUP-E402.md")),
        WaitCauseCategory::ObligationLeak => {
            (Some("ASUP-E101"), Some("docs/error_codes/ASUP-E101.md"))
        }
        WaitCauseCategory::DeadlockCycle | WaitCauseCategory::UnknownWait => (None, None),
    }
}

fn wait_cause_graph_hash(evidence: &WaitCauseRemediationEvidence) -> String {
    let mut projection = String::new();
    projection.push_str(&evidence.report_id);
    projection.push('|');
    projection.push_str(&evidence.scenario_id);
    projection.push('|');
    projection.push_str(&evidence.tail_taxonomy_version);
    if let Some(report) = &evidence.deadlock_report {
        projection.push_str("|deadlock:");
        projection.push_str(report.severity.as_str());
        projection.push(':');
        projection.push_str(&format!("{:.6}", report.risk_score));
        for cycle in &report.cycles {
            projection.push('|');
            projection.push_str(if cycle.trapped { "trapped" } else { "egress" });
            projection.push(':');
            projection.push_str(&cycle.ingress_edges.to_string());
            projection.push(':');
            projection.push_str(&cycle.egress_edges.to_string());
            for task in &cycle.tasks {
                projection.push(':');
                projection.push_str(&format!("{task:?}"));
            }
        }
    }
    for wait in &evidence.task_waits {
        projection.push_str("|task:");
        projection.push_str(&format!("{:?}", wait.task_id));
        projection.push(':');
        projection.push_str(wait.wait_kind.as_str());
        projection.push(':');
        projection.push_str(&wait.wait_age_ns.to_string());
        projection.push(':');
        projection.push_str(if wait.wake_pending { "wake" } else { "no_wake" });
        projection.push(':');
        projection.push_str(&sanitize_remediation_text(&wait.blocked_resource));
    }
    for leak in &evidence.obligation_leaks {
        projection.push_str("|obligation:");
        projection.push_str(&format!("{:?}", leak.obligation_id));
        projection.push(':');
        projection.push_str(&sanitize_remediation_text(&leak.obligation_type));
        projection.push(':');
        projection.push_str(&format!("{:?}", leak.region_id));
        projection.push(':');
        projection.push_str(&leak.age_ns.to_string());
    }
    stable_fnv1a64_hex(projection.as_bytes())
}

impl DeadlockSeverity {
    fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Elevated => "elevated",
            Self::Critical => "critical",
        }
    }
}

fn push_deadlock_findings(
    findings: &mut Vec<WaitCauseRemediationFinding>,
    report: &DirectionalDeadlockReport,
    evidence: &WaitCauseRemediationEvidence,
) {
    for cycle in &report.cycles {
        let severity = if cycle.trapped {
            WaitCauseSeverity::Critical
        } else {
            WaitCauseSeverity::High
        };
        let confidence_basis_points = if cycle.trapped { 9_600 } else { 8_100 };
        let reason_code = if cycle.trapped {
            "trapped_wait_cycle"
        } else {
            "cyclic_wait_with_egress"
        };
        let blocked_resource = sanitize_remediation_text(&format!(
            "wait_graph_cycle:{}:{}",
            if cycle.trapped { "trapped" } else { "egress" },
            cycle
                .tasks
                .iter()
                .map(|task| format!("{task:?}"))
                .collect::<Vec<_>>()
                .join("->")
        ));
        findings.push(WaitCauseRemediationFinding {
            finding_id: String::new(),
            rank: 0,
            asup_code: None,
            remediation_doc_path: None,
            category: WaitCauseCategory::DeadlockCycle,
            severity,
            confidence_basis_points,
            reason_code: reason_code.to_string(),
            summary: format!(
                "{} wait-for cycle across {} task(s)",
                if cycle.trapped {
                    "trapped"
                } else {
                    "egress-capable"
                },
                cycle.tasks.len()
            ),
            blocked_resource,
            owner_task_id: cycle.tasks.first().map(|task| format!("{task:?}")),
            owner_region_id: None,
            evidence_refs: evidence.evidence_refs.clone(),
            safe_actions: deadlock_safe_actions(cycle.trapped),
            forbidden_actions: remediation_forbidden_actions(),
            replay_command: evidence.replay_command.clone(),
        });
    }
}

fn push_task_wait_findings(
    findings: &mut Vec<WaitCauseRemediationFinding>,
    evidence: &WaitCauseRemediationEvidence,
) {
    for wait in &evidence.task_waits {
        let (category, severity, confidence_basis_points, reason_code, safe_actions) =
            match (wait.wait_kind, wait.wake_pending) {
                (WaitCauseTaskWaitKind::AwaitingFuture, false) => (
                    WaitCauseCategory::Futurelock,
                    WaitCauseSeverity::High,
                    8_200,
                    "future_wait_without_pending_wake",
                    futurelock_safe_actions(),
                ),
                (WaitCauseTaskWaitKind::AwaitingFuture, true) => (
                    WaitCauseCategory::UnknownWait,
                    WaitCauseSeverity::Warning,
                    5_200,
                    "future_wait_has_pending_wake",
                    unknown_wait_safe_actions(),
                ),
                (WaitCauseTaskWaitKind::AwaitingSchedule, _) => (
                    WaitCauseCategory::UnknownWait,
                    WaitCauseSeverity::Info,
                    4_200,
                    "awaiting_scheduler_turn",
                    unknown_wait_safe_actions(),
                ),
                (WaitCauseTaskWaitKind::Unknown, _) => (
                    WaitCauseCategory::UnknownWait,
                    WaitCauseSeverity::Warning,
                    4_800,
                    "unknown_wait_cause",
                    unknown_wait_safe_actions(),
                ),
            };

        let blocked_resource = sanitize_remediation_text(&wait.blocked_resource);
        let (asup_code, remediation_doc_path) = wait_cause_asup_metadata(category);
        findings.push(WaitCauseRemediationFinding {
            finding_id: String::new(),
            rank: 0,
            asup_code: asup_code.map(str::to_string),
            remediation_doc_path: remediation_doc_path.map(str::to_string),
            category,
            severity,
            confidence_basis_points,
            reason_code: reason_code.to_string(),
            summary: format!(
                "task {:?} wait classified as {} for {}ns",
                wait.task_id,
                category.as_str(),
                wait.wait_age_ns
            ),
            blocked_resource: if blocked_resource.is_empty() {
                "unknown_resource".to_string()
            } else {
                blocked_resource
            },
            owner_task_id: Some(format!("{:?}", wait.task_id)),
            owner_region_id: wait.region_id.map(|region| format!("{region:?}")),
            evidence_refs: evidence.evidence_refs.clone(),
            safe_actions,
            forbidden_actions: remediation_forbidden_actions(),
            replay_command: evidence.replay_command.clone(),
        });
    }
}

fn push_obligation_findings(
    findings: &mut Vec<WaitCauseRemediationFinding>,
    evidence: &WaitCauseRemediationEvidence,
) {
    for leak in &evidence.obligation_leaks {
        let obligation_type = sanitize_remediation_text(&leak.obligation_type);
        let (asup_code, remediation_doc_path) =
            wait_cause_asup_metadata(WaitCauseCategory::ObligationLeak);
        findings.push(WaitCauseRemediationFinding {
            finding_id: String::new(),
            rank: 0,
            asup_code: asup_code.map(str::to_string),
            remediation_doc_path: remediation_doc_path.map(str::to_string),
            category: WaitCauseCategory::ObligationLeak,
            severity: WaitCauseSeverity::Critical,
            confidence_basis_points: 9_000,
            reason_code: "reserved_obligation_still_held".to_string(),
            summary: format!(
                "obligation {:?} ({}) held for {}ns",
                leak.obligation_id, obligation_type, leak.age_ns
            ),
            blocked_resource: format!("obligation:{:?}", leak.obligation_id),
            owner_task_id: leak.holder_task.map(|task| format!("{task:?}")),
            owner_region_id: Some(format!("{:?}", leak.region_id)),
            evidence_refs: evidence.evidence_refs.clone(),
            safe_actions: obligation_safe_actions(),
            forbidden_actions: remediation_forbidden_actions(),
            replay_command: evidence.replay_command.clone(),
        });
    }
}

fn rank_wait_cause_findings(findings: &mut [WaitCauseRemediationFinding]) {
    findings.sort_by(|a, b| {
        b.severity
            .sort_rank()
            .cmp(&a.severity.sort_rank())
            .then_with(|| b.confidence_basis_points.cmp(&a.confidence_basis_points))
            .then_with(|| a.category.cmp(&b.category))
            .then_with(|| a.blocked_resource.cmp(&b.blocked_resource))
            .then_with(|| a.owner_task_id.cmp(&b.owner_task_id))
    });
    for (idx, finding) in findings.iter_mut().enumerate() {
        finding.rank = idx + 1;
        finding.finding_id = format!("wait-cause-remediation-{:04}", idx + 1);
    }
}

fn wait_cause_report_hash(report: &WaitCauseRemediationReport) -> String {
    let mut projection = String::new();
    projection.push_str(&report.schema_version);
    projection.push('|');
    projection.push_str(&report.report_id);
    projection.push('|');
    projection.push_str(&report.scenario_id);
    projection.push('|');
    projection.push_str(report.verdict.as_str());
    projection.push('|');
    projection.push_str(&report.wait_cause_graph_hash);
    if let Some(reason) = &report.refusal_reason {
        projection.push('|');
        projection.push_str(reason);
    }
    for finding in &report.findings {
        projection.push('|');
        projection.push_str(&finding.finding_id);
        projection.push(':');
        if let Some(asup_code) = &finding.asup_code {
            projection.push_str(asup_code);
            projection.push(':');
        }
        if let Some(doc_path) = &finding.remediation_doc_path {
            projection.push_str(doc_path);
            projection.push(':');
        }
        projection.push_str(finding.category.as_str());
        projection.push(':');
        projection.push_str(finding.severity.as_str());
        projection.push(':');
        projection.push_str(&finding.confidence_basis_points.to_string());
        projection.push(':');
        projection.push_str(&finding.reason_code);
    }
    stable_fnv1a64_hex(projection.as_bytes())
}

fn flattened_safe_actions(findings: &[WaitCauseRemediationFinding]) -> Vec<String> {
    let mut actions = Vec::new();
    for finding in findings {
        for action in &finding.safe_actions {
            if !actions.contains(action) {
                actions.push(action.clone());
            }
        }
    }
    actions
}

/// Build one deterministic wait-cause remediation report.
///
/// Off-contract evidence returns a refused report instead of actionable advice.
/// Action rows are deliberately non-destructive and include explicit forbidden
/// action disclaimers for operator use.
#[must_use]
pub fn build_wait_cause_remediation_report(
    evidence: WaitCauseRemediationEvidence,
) -> WaitCauseRemediationReport {
    let mut refusal_reasons = Vec::new();
    if evidence.report_id.trim().is_empty() {
        unique_push_reason(&mut refusal_reasons, "empty_report_id");
    }
    if evidence.scenario_id.trim().is_empty() {
        unique_push_reason(&mut refusal_reasons, "empty_scenario_id");
    }
    if evidence.replay_command.trim().is_empty() {
        unique_push_reason(&mut refusal_reasons, "missing_replay_command");
    }
    if evidence.tail_taxonomy_version != TAIL_LATENCY_TAXONOMY_CONTRACT_VERSION {
        unique_push_reason(&mut refusal_reasons, "wrong_tail_taxonomy_version");
    }

    let graph_hash = wait_cause_graph_hash(&evidence);
    let mut findings = Vec::new();
    if let Some(report) = &evidence.deadlock_report {
        push_deadlock_findings(&mut findings, report, &evidence);
    }
    push_task_wait_findings(&mut findings, &evidence);
    push_obligation_findings(&mut findings, &evidence);
    rank_wait_cause_findings(&mut findings);

    if findings.is_empty() {
        unique_push_reason(&mut refusal_reasons, "no_wait_cause_evidence");
    }

    let verdict = if refusal_reasons.is_empty() {
        if findings
            .iter()
            .all(|finding| finding.category == WaitCauseCategory::UnknownWait)
        {
            WaitCauseRemediationVerdict::Investigate
        } else {
            WaitCauseRemediationVerdict::Actionable
        }
    } else {
        findings.clear();
        WaitCauseRemediationVerdict::Refused
    };

    let mut report = WaitCauseRemediationReport {
        schema_version: WAIT_CAUSE_REMEDIATION_REPORT_SCHEMA_VERSION.to_string(),
        report_id: evidence.report_id.trim().to_string(),
        report_hash: String::new(),
        scenario_id: evidence.scenario_id.trim().to_string(),
        wait_cause_graph_hash: graph_hash,
        tail_taxonomy_version: evidence.tail_taxonomy_version,
        verdict,
        refusal_reason: refusal_reasons.first().cloned(),
        safe_actions: flattened_safe_actions(&findings),
        findings,
        forbidden_action_disclaimer:
            "All remediation actions must preserve evidence and avoid destructive cleanup unless explicitly authorized."
                .to_string(),
        replay_command: evidence.replay_command,
        evidence_refs: evidence.evidence_refs,
    };
    report.report_hash = wait_cause_report_hash(&report);
    report
}

fn tail_latency_log_field(
    key: &str,
    unit: &str,
    required: bool,
    meaning: &str,
) -> TailLatencyLogFieldSpec {
    TailLatencyLogFieldSpec {
        key: key.to_string(),
        unit: unit.to_string(),
        required,
        meaning: meaning.to_string(),
    }
}

#[allow(clippy::too_many_arguments)]
fn tail_latency_signal(
    signal_id: &str,
    structured_log_key: &str,
    unit: &str,
    producer_kind: &str,
    producer_symbol: &str,
    producer_file: &str,
    measurement_class: &str,
    core: bool,
    notes: &str,
) -> TailLatencySignalSpec {
    TailLatencySignalSpec {
        signal_id: signal_id.to_string(),
        structured_log_key: structured_log_key.to_string(),
        unit: unit.to_string(),
        producer_kind: producer_kind.to_string(),
        producer_symbol: producer_symbol.to_string(),
        producer_file: producer_file.to_string(),
        measurement_class: measurement_class.to_string(),
        core,
        notes: notes.to_string(),
    }
}

fn queueing_tail_latency_term() -> TailLatencyTermSpec {
    TailLatencyTermSpec {
        term_id: "queueing".to_string(),
        description:
            "Backlog before useful work begins, spanning ready queues, waiters, and drain queues."
                .to_string(),
        direct_duration_key: "tail.queueing.ns".to_string(),
        attribution_state_key: "tail.queueing.attribution_state".to_string(),
        signals: vec![
            tail_latency_signal(
                "queueing.ready_queue_depth",
                "tail.queueing.ready_queue_depth",
                "count",
                "snapshot_field",
                "asupersync::obligation::lyapunov::StateSnapshot::ready_queue_depth",
                "src/obligation/lyapunov.rs",
                "proxy_signal",
                true,
                "Canonical scheduler backlog proxy used by the three-lane decision contract.",
            ),
            tail_latency_signal(
                "queueing.draining_regions",
                "tail.queueing.draining_regions",
                "count",
                "snapshot_field",
                "asupersync::obligation::lyapunov::StateSnapshot::draining_regions",
                "src/obligation/lyapunov.rs",
                "proxy_signal",
                true,
                "Captures cancellation/finalizer drain backlog that elongates queueing tails.",
            ),
            tail_latency_signal(
                "queueing.bulkhead_queue_depth",
                "tail.queueing.bulkhead_queue_depth",
                "count",
                "stats_struct",
                "asupersync::combinator::bulkhead::BulkheadMetrics::queue_depth",
                "src/combinator/bulkhead.rs",
                "proxy_signal",
                false,
                "Extended queueing proxy for admission-controlled bulkhead lanes.",
            ),
            tail_latency_signal(
                "queueing.pool_waiters",
                "tail.queueing.pool_waiters",
                "count",
                "stats_struct",
                "asupersync::sync::pool::PoolStats::waiters",
                "src/sync/pool.rs",
                "proxy_signal",
                false,
                "Extended backlog proxy for pool acquisition queues.",
            ),
        ],
    }
}

fn service_tail_latency_term() -> TailLatencyTermSpec {
    TailLatencyTermSpec {
        term_id: "service".to_string(),
        description:
            "CPU work once the task is scheduled, including poll consumption and budget burn."
                .to_string(),
        direct_duration_key: "tail.service.ns".to_string(),
        attribution_state_key: "tail.service.attribution_state".to_string(),
        signals: vec![
            tail_latency_signal(
                "service.poll_count",
                "tail.service.poll_count",
                "count",
                "snapshot_field",
                "asupersync::runtime::state::TaskSnapshot::poll_count",
                "src/runtime/state.rs",
                "proxy_signal",
                true,
                "Canonical always-on service proxy derived from task budget consumption.",
            ),
            tail_latency_signal(
                "service.poll_quota_consumed",
                "tail.service.poll_quota_consumed",
                "quota_units",
                "stats_struct",
                "asupersync::observability::resource_accounting::ResourceAccountingSnapshot::poll_quota_consumed",
                "src/observability/resource_accounting.rs",
                "proxy_signal",
                true,
                "Aggregated service-pressure counter for runtime/test emitters.",
            ),
            tail_latency_signal(
                "service.cost_quota_consumed",
                "tail.service.cost_quota_consumed",
                "cost_units",
                "stats_struct",
                "asupersync::observability::resource_accounting::ResourceAccountingSnapshot::cost_quota_consumed",
                "src/observability/resource_accounting.rs",
                "proxy_signal",
                false,
                "Extended service-pressure counter for cost-aware workloads.",
            ),
        ],
    }
}

fn io_or_network_tail_latency_term() -> TailLatencyTermSpec {
    TailLatencyTermSpec {
        term_id: "io_or_network".to_string(),
        description: "Latency spent waiting on or draining reactor/network activity.".to_string(),
        direct_duration_key: "tail.io_or_network.ns".to_string(),
        attribution_state_key: "tail.io_or_network.attribution_state".to_string(),
        signals: vec![
            tail_latency_signal(
                "io_or_network.events_received",
                "tail.io_or_network.events_received",
                "count",
                "stats_struct",
                "asupersync::runtime::io_driver::IoStats::events_received",
                "src/runtime/io_driver.rs",
                "proxy_signal",
                true,
                "Canonical always-on I/O/network pressure proxy from the reactor driver.",
            ),
            tail_latency_signal(
                "io_or_network.polls",
                "tail.io_or_network.polls",
                "count",
                "stats_struct",
                "asupersync::runtime::io_driver::IoStats::polls",
                "src/runtime/io_driver.rs",
                "proxy_signal",
                false,
                "Extended reactor activity proxy for sustained polling pressure.",
            ),
            tail_latency_signal(
                "io_or_network.wakers_dispatched",
                "tail.io_or_network.wakers_dispatched",
                "count",
                "stats_struct",
                "asupersync::runtime::io_driver::IoStats::wakers_dispatched",
                "src/runtime/io_driver.rs",
                "proxy_signal",
                false,
                "Extended proxy for wake fan-out caused by readiness events.",
            ),
        ],
    }
}

fn retries_tail_latency_term() -> TailLatencyTermSpec {
    TailLatencyTermSpec {
        term_id: "retries".to_string(),
        description:
            "Backoff and reattempt inflation introduced by retry/rate-limit/circuit-breaker control loops."
                .to_string(),
        direct_duration_key: "tail.retries.ns".to_string(),
        attribution_state_key: "tail.retries.attribution_state".to_string(),
        signals: vec![
            tail_latency_signal(
                "retries.total_delay_ns",
                "tail.retries.total_delay_ns",
                "ns",
                "state_field",
                "asupersync::combinator::retry::RetryState::total_delay",
                "src/combinator/retry.rs",
                "direct_duration",
                true,
                "Direct retry-delay contribution from the retry combinator.",
            ),
            tail_latency_signal(
                "retries.rate_limit_total_wait_ns",
                "tail.retries.rate_limit_total_wait_ns",
                "ns",
                "stats_struct",
                "asupersync::combinator::rate_limit::RateLimitMetrics::total_wait_time",
                "src/combinator/rate_limit.rs",
                "direct_duration",
                false,
                "Extended direct delay when token-bucket admission defers work.",
            ),
            tail_latency_signal(
                "retries.circuit_rejected_total",
                "tail.retries.circuit_rejected_total",
                "count",
                "stats_struct",
                "asupersync::combinator::circuit_breaker::CircuitBreakerMetrics::total_rejected",
                "src/combinator/circuit_breaker.rs",
                "proxy_signal",
                false,
                "Extended retry/control-loop pressure proxy when open circuits reject work.",
            ),
        ],
    }
}

fn synchronization_tail_latency_term() -> TailLatencyTermSpec {
    TailLatencyTermSpec {
        term_id: "synchronization".to_string(),
        description:
            "Coordination delay from locks, pools, obligations, and cancellation-aware rendezvous."
                .to_string(),
        direct_duration_key: "tail.synchronization.ns".to_string(),
        attribution_state_key: "tail.synchronization.attribution_state".to_string(),
        signals: vec![
            tail_latency_signal(
                "synchronization.lock_wait_ns",
                "tail.synchronization.lock_wait_ns",
                "ns",
                "stats_struct",
                "asupersync::sync::contended_mutex::LockMetricsSnapshot::wait_ns",
                "src/sync/contended_mutex.rs",
                "direct_duration",
                true,
                "Canonical direct synchronization delay from contention-instrumented locks.",
            ),
            tail_latency_signal(
                "synchronization.lock_hold_ns",
                "tail.synchronization.lock_hold_ns",
                "ns",
                "stats_struct",
                "asupersync::sync::contended_mutex::LockMetricsSnapshot::hold_ns",
                "src/sync/contended_mutex.rs",
                "proxy_signal",
                false,
                "Extended proxy for convoying and long critical sections.",
            ),
            tail_latency_signal(
                "synchronization.pool_total_wait_ns",
                "tail.synchronization.pool_total_wait_ns",
                "ns",
                "stats_struct",
                "asupersync::sync::pool::PoolStats::total_wait_time",
                "src/sync/pool.rs",
                "direct_duration",
                false,
                "Extended direct delay from resource-pool acquisition waits.",
            ),
            tail_latency_signal(
                "synchronization.obligations_pending",
                "tail.synchronization.obligations_pending",
                "count",
                "stats_struct",
                "asupersync::observability::resource_accounting::ResourceAccountingSnapshot::obligations_pending",
                "src/observability/resource_accounting.rs",
                "proxy_signal",
                true,
                "Captures obligation/cancellation backlog that can extend synchronization tails.",
            ),
        ],
    }
}

fn allocator_or_cache_tail_latency_term() -> TailLatencyTermSpec {
    TailLatencyTermSpec {
        term_id: "allocator_or_cache".to_string(),
        description:
            "Allocator and cache-locality pressure observable from region-heap churn and memory high-water marks."
                .to_string(),
        direct_duration_key: "tail.allocator_or_cache.ns".to_string(),
        attribution_state_key: "tail.allocator_or_cache.attribution_state".to_string(),
        signals: vec![
            tail_latency_signal(
                "allocator_or_cache.live_allocations",
                "tail.allocator_or_cache.live_allocations",
                "count",
                "stats_struct",
                "asupersync::runtime::region_heap::HeapStats::live",
                "src/runtime/region_heap.rs",
                "proxy_signal",
                true,
                "Canonical allocator-pressure proxy from live region-heap allocations.",
            ),
            tail_latency_signal(
                "allocator_or_cache.bytes_live",
                "tail.allocator_or_cache.bytes_live",
                "bytes",
                "stats_struct",
                "asupersync::runtime::region_heap::HeapStats::bytes_live",
                "src/runtime/region_heap.rs",
                "proxy_signal",
                false,
                "Extended allocator-pressure proxy for live retained bytes.",
            ),
            tail_latency_signal(
                "allocator_or_cache.heap_bytes_peak",
                "tail.allocator_or_cache.heap_bytes_peak",
                "bytes",
                "stats_struct",
                "asupersync::observability::resource_accounting::ResourceAccountingSnapshot::heap_bytes_peak",
                "src/observability/resource_accounting.rs",
                "proxy_signal",
                false,
                "Extended region-level memory high-water mark for cache/allocator analysis.",
            ),
        ],
    }
}

fn unknown_tail_latency_term() -> TailLatencyTermSpec {
    TailLatencyTermSpec {
        term_id: "unknown".to_string(),
        description:
            "Residual latency that remains unattributed after measured terms and proxies are accounted for."
                .to_string(),
        direct_duration_key: "tail.unknown.unmeasured_ns".to_string(),
        attribution_state_key: "tail.unknown.attribution_state".to_string(),
        signals: vec![tail_latency_signal(
            "unknown.unmeasured_ns",
            "tail.unknown.unmeasured_ns",
            "ns",
            "contract_field",
            "asupersync::observability::diagnostics::tail_latency_taxonomy_contract",
            "src/observability/diagnostics.rs",
            "unknown_bucket",
            true,
            "Must be emitted whenever any term lacks direct attribution so latency does not disappear from evidence bundles.",
        )],
    }
}

/// Returns the tail-latency decomposition contract used by runtime-ascension work.
#[must_use]
pub fn tail_latency_taxonomy_contract() -> TailLatencyTaxonomyContract {
    TailLatencyTaxonomyContract {
        contract_version: TAIL_LATENCY_TAXONOMY_CONTRACT_VERSION.to_string(),
        equation: "tail_latency_ns = queueing_ns + service_ns + io_or_network_ns + retries_ns + synchronization_ns + allocator_or_cache_ns + unknown_ns".to_string(),
        total_latency_key: "tail.total_latency_ns".to_string(),
        unknown_bucket_key: "tail.unknown.unmeasured_ns".to_string(),
        required_log_fields: vec![
            tail_latency_log_field(
                "tail.contract_version",
                "schema_id",
                true,
                "Versioned tail-latency taxonomy contract identifier.",
            ),
            tail_latency_log_field(
                "tail.total_latency_ns",
                "ns",
                true,
                "Observed end-to-end tail latency for the operation under analysis.",
            ),
            tail_latency_log_field(
                "tail.queueing.ready_queue_depth",
                "count",
                true,
                "Always-on queueing proxy based on runnable backlog.",
            ),
            tail_latency_log_field(
                "tail.service.poll_count",
                "count",
                true,
                "Service-side work proxy based on task poll demand.",
            ),
            tail_latency_log_field(
                "tail.io_or_network.events_received",
                "count",
                true,
                "I/O or network pressure proxy based on reactor event volume.",
            ),
            tail_latency_log_field(
                "tail.retries.total_delay_ns",
                "ns",
                true,
                "Direct retry/backoff delay accumulated by retry combinators.",
            ),
            tail_latency_log_field(
                "tail.synchronization.lock_wait_ns",
                "ns",
                true,
                "Direct synchronization delay from contention-instrumented locks.",
            ),
            tail_latency_log_field(
                "tail.allocator_or_cache.live_allocations",
                "count",
                true,
                "Allocator/cache pressure proxy based on live region-heap allocations.",
            ),
            tail_latency_log_field(
                "tail.unknown.unmeasured_ns",
                "ns",
                true,
                "Residual latency that remains unattributed after measured terms and proxies are recorded.",
            ),
        ],
        terms: vec![
            queueing_tail_latency_term(),
            service_tail_latency_term(),
            io_or_network_tail_latency_term(),
            retries_tail_latency_term(),
            synchronization_tail_latency_term(),
            allocator_or_cache_tail_latency_term(),
            unknown_tail_latency_term(),
        ],
        sampling_policy: vec![
            "Always emit the required core fields for any tail-latency event, even when extended observability sampling is disabled.".to_string(),
            "Extended fields may be sampled or emitted only in replay/forensics modes, but they must retain the stable keys defined here.".to_string(),
            "If a direct-duration field is unavailable for a term, preserve proxy signals and roll the residual duration into tail.unknown.unmeasured_ns.".to_string(),
        ],
        compatibility_notes: vec![
            "Structured-log keys are append-only within a contract version; removals or unit changes require a new contract version.".to_string(),
            "Proxy signals are not interchangeable with direct-duration fields; emitters must preserve both semantics explicitly.".to_string(),
            "Unknown contribution is mandatory whenever attribution is incomplete so downstream controllers never treat missing data as zero.".to_string(),
        ],
    }
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

// br-asupersync-t36ete: NDJSON serialization support for diagnostic types
impl DirectionalDeadlockReport {
    /// Serialize to NDJSON (newline-delimited JSON) format.
    ///
    /// Returns a string where each diagnostic field is on its own line as valid JSON.
    /// This format is commonly used for log aggregation and streaming analytics.
    #[must_use]
    pub fn to_ndjson(&self) -> String {
        let mut lines = Vec::new();

        lines.push(serde_json::json!({
            "type": "deadlock_report",
            "severity": format!("{:?}", self.severity),
            "risk_score": self.risk_score
        }));

        for (i, cycle) in self.cycles.iter().enumerate() {
            lines.push(serde_json::json!({
                "type": "deadlock_cycle",
                "cycle_index": i,
                "cycle_length": cycle.tasks.len(),
                "task_ids": cycle.tasks.iter().map(|id| format!("{:?}", id)).collect::<Vec<_>>()
            }));
        }

        lines
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl RegionOpenExplanation {
    /// Serialize to NDJSON format.
    #[must_use]
    pub fn to_ndjson(&self) -> String {
        let mut lines = Vec::new();

        lines.push(serde_json::json!({
            "type": "region_explanation",
            "region_id": format!("{:?}", self.region_id),
            "region_state": format!("{:?}", self.region_state),
            "reason_count": self.reasons.len(),
            "recommendation_count": self.recommendations.len()
        }));

        for (i, reason) in self.reasons.iter().enumerate() {
            lines.push(serde_json::json!({
                "type": "region_reason",
                "region_id": format!("{:?}", self.region_id),
                "reason_index": i,
                "reason": format!("{:?}", reason)
            }));
        }

        for (i, rec) in self.recommendations.iter().enumerate() {
            lines.push(serde_json::json!({
                "type": "region_recommendation",
                "region_id": format!("{:?}", self.region_id),
                "recommendation_index": i,
                "recommendation": rec
            }));
        }

        lines
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl TaskBlockedExplanation {
    /// Serialize to NDJSON format.
    #[must_use]
    pub fn to_ndjson(&self) -> String {
        let mut lines = Vec::new();

        lines.push(serde_json::json!({
            "type": "task_explanation",
            "task_id": format!("{:?}", self.task_id),
            "block_reason": format!("{:?}", self.block_reason),
            "detail_count": self.details.len(),
            "recommendation_count": self.recommendations.len()
        }));

        for (i, detail) in self.details.iter().enumerate() {
            lines.push(serde_json::json!({
                "type": "task_detail",
                "task_id": format!("{:?}", self.task_id),
                "detail_index": i,
                "detail": detail
            }));
        }

        for (i, rec) in self.recommendations.iter().enumerate() {
            lines.push(serde_json::json!({
                "type": "task_recommendation",
                "task_id": format!("{:?}", self.task_id),
                "recommendation_index": i,
                "recommendation": rec
            }));
        }

        lines
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl ObligationLeak {
    /// Serialize to NDJSON format.
    #[must_use]
    pub fn to_ndjson(&self) -> String {
        serde_json::json!({
            "type": "obligation_leak",
            "obligation_id": format!("{:?}", self.obligation_id),
            "obligation_type": self.obligation_type,
            "holder_task": self.holder_task.map(|id| format!("{:?}", id)),
            "region_id": format!("{:?}", self.region_id),
            "age_ms": self.age.as_millis()
        })
        .to_string()
    }
}

#[cfg(test)]
#[allow(clippy::arc_with_non_send_sync)]
#[path = "diagnostics_inline_tests.rs"]
mod tests;
