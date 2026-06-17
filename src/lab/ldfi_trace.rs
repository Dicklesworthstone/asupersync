//! Lab-runtime adapter for LDFI: build a [`CausalLineage`] from a recorded trace.
//!
//! The pure LDFI core ([`crate::lab::ldfi`]) is deliberately free of any trace,
//! I/O, or clock types: it reasons over an abstract happens-before relation and
//! the family of derivations extracted from it. This module is the *adapter*
//! that the core's docs call out as a sibling slice — it consumes a recorded lab
//! trace (`crate::trace`) and fills the pure [`CausalLineage`] from the trace's
//! happens-before structure, so a real successful run can drive minimal
//! fault-hypothesis generation.
//!
//! # What it extracts
//!
//! Every [`TraceEvent`] becomes a [`FaultEventId`] keyed by its `seq` (trace seq
//! numbers are monotonic and unique). Each event is classified fault-able or
//! structural by [`default_faultable`]. Happens-before edges are recovered from
//! three independent, composable sources, each documented below:
//!
//! 1. **Per-task program order** — consecutive events that name the same owning
//!    task form a chain (a thread of execution is totally ordered).
//! 2. **Per-resource correlation** — events that share a resource handle (I/O
//!    token, obligation id, timer id, monitor/link ref) are linked: the request
//!    or grant happens-before the later delivery on the same handle.
//! 3. **Logical clocks** — when events carry a [`LogicalTime`], every strictly
//!    `Before` pair (per the vector/Lamport causal order) becomes an edge. This
//!    is the cross-task happens-before machinery shared with `trace/causality`.
//!
//! # Soundness
//!
//! Per the core's soundness contract, *over-approximating* the happens-before
//! relation (adding edges, enlarging cones) is safe — it only yields extra fault
//! hypotheses the experiment loop will refute. *Under-approximation* is unsafe:
//! a missing edge can hide the fault that breaks the outcome. The three sources
//! above are therefore additive and the classifier errs toward fault-able. With
//! vector clocks source (3) is precise; with Lamport clocks it over-approximates
//! to the total order (still sound, but every earlier event joins the cone), so
//! prefer vector clocks or the structural sources (1)/(2) for precise lineages.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::lab::ldfi::{
    CausalLineage, FaultEventId, HittingSetResult, LdfiExperimentReport, LdfiExperimentStatus,
    SupportGraph,
};
use crate::trace::distributed::CausalOrder;
use crate::trace::{TraceData, TraceEvent, TraceEventKind};
use crate::types::{ObligationId, TaskId};

/// Classifies a trace event kind as fault-able (a fault can be injected on it) or
/// structural (it propagates causality but carries no injectable fault).
///
/// Fault-able events are the deliveries, fires, grants, and acks the chaos/fault
/// machinery can actually remove: a wakeup, a timer fire, an I/O readiness or
/// result, a lease reserve/commit, a cancellation or worker ack, a monitor `Down`
/// or link `Exit` delivery, and existing chaos points. Everything else — spawns,
/// schedules, polls, completions, region/time lifecycle, interest registration,
/// RNG, checkpoints, the user-trace outcome assertion itself — only carries
/// causality and has no fault to inject.
///
/// Per the module soundness note, mis-labelling a structural event fault-able
/// only adds a hypothesis the experiment loop refutes; mis-labelling a fault-able
/// event structural is unsafe, so the default leans toward fault-able for any
/// delivery/grant/fire/ack kind.
#[must_use]
pub const fn default_faultable(kind: TraceEventKind) -> bool {
    matches!(
        kind,
        TraceEventKind::Wake
            | TraceEventKind::CancelAck
            | TraceEventKind::WorkerCancelAcknowledged
            | TraceEventKind::WorkerDrainCompleted
            | TraceEventKind::WorkerFinalizeCompleted
            | TraceEventKind::TimerFired
            | TraceEventKind::IoReady
            | TraceEventKind::IoResult
            | TraceEventKind::ObligationReserve
            | TraceEventKind::ObligationCommit
            | TraceEventKind::DownDelivered
            | TraceEventKind::ExitDelivered
            | TraceEventKind::ChaosInjection
    )
}

/// Configuration for [`build_causal_lineage`].
///
/// Both edge augmentations default to on; disabling one narrows the recovered
/// happens-before relation (handy for isolating which source a lineage depends
/// on, as in the adapter tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceLineageConfig {
    /// Recover cross-task edges from logical clocks when events carry them.
    /// Precise for vector clocks; a sound over-approximation for Lamport. This
    /// pass is `O(n^2)` in the number of clock-carrying events.
    pub use_logical_time: bool,
    /// Recover edges by correlating shared resource handles (I/O tokens,
    /// obligation ids, timer ids, monitor/link refs).
    pub correlate_resources: bool,
}

impl Default for TraceLineageConfig {
    fn default() -> Self {
        Self {
            use_logical_time: true,
            correlate_resources: true,
        }
    }
}

/// Builds a [`CausalLineage`] from a recorded trace using the configured
/// happens-before sources. Deterministic: a given `(events, config)` always
/// produces the same lineage.
///
/// Compose the result with [`CausalLineage::support_of`] /
/// [`SupportGraph::from_causal_cones`] and the pure hitting-set generator to get
/// the trace → fault-hypothesis pipeline; [`support_graph_for`] wires that up.
#[must_use]
pub fn build_causal_lineage(events: &[TraceEvent], config: TraceLineageConfig) -> CausalLineage {
    let mut lineage = CausalLineage::new();

    // Register every event with its fault-ability up front, before any edges, so
    // a later `add_happens_before` (which only touches the predecessor map) can
    // never clobber a fault-able flag.
    for ev in events {
        lineage.add_event(FaultEventId::new(ev.seq), default_faultable(ev.kind));
    }

    // Single forward pass for program order and resource correlation. Each map
    // holds the seq of the most recent event keyed by that handle; chaining to
    // the previous one yields a happens-before edge while keeping the relation
    // transitively reachable.
    let mut last_by_task: BTreeMap<TaskId, u64> = BTreeMap::new();
    let mut last_by_token: BTreeMap<u64, u64> = BTreeMap::new();
    let mut last_by_obligation: BTreeMap<ObligationId, u64> = BTreeMap::new();
    let mut timer_origin: BTreeMap<u64, u64> = BTreeMap::new();
    let mut monitor_origin: BTreeMap<u64, u64> = BTreeMap::new();
    let mut link_origin: BTreeMap<u64, u64> = BTreeMap::new();

    for ev in events {
        let this = FaultEventId::new(ev.seq);

        // (1) Per-task program order.
        if let Some(task) = owning_task(&ev.data) {
            if let Some(&prev) = last_by_task.get(&task) {
                lineage.add_happens_before(FaultEventId::new(prev), this);
            }
            last_by_task.insert(task, ev.seq);
        }

        if config.correlate_resources {
            // (2a) I/O token chain (interest -> readiness -> result/error).
            if let Some(token) = io_token(&ev.data) {
                if let Some(&prev) = last_by_token.get(&token) {
                    lineage.add_happens_before(FaultEventId::new(prev), this);
                }
                last_by_token.insert(token, ev.seq);
            }

            // (2b) Obligation lifecycle chain (reserve -> commit/abort/leak).
            if let Some(ob) = obligation_of(&ev.data) {
                if let Some(&prev) = last_by_obligation.get(&ob) {
                    lineage.add_happens_before(FaultEventId::new(prev), this);
                }
                last_by_obligation.insert(ob, ev.seq);
            }

            // (2c) Timer: scheduled happens-before its fire/cancel.
            if let Some(tid) = timer_id(&ev.data) {
                match ev.kind {
                    TraceEventKind::TimerScheduled => {
                        timer_origin.insert(tid, ev.seq);
                    }
                    TraceEventKind::TimerFired | TraceEventKind::TimerCancelled => {
                        if let Some(&origin) = timer_origin.get(&tid) {
                            lineage.add_happens_before(FaultEventId::new(origin), this);
                        }
                    }
                    _ => {}
                }
            }

            // (2d) Monitor: creation happens-before the Down delivery/drop.
            if let Some(mref) = monitor_ref(&ev.data) {
                match ev.kind {
                    TraceEventKind::MonitorCreated => {
                        monitor_origin.insert(mref, ev.seq);
                    }
                    TraceEventKind::DownDelivered | TraceEventKind::MonitorDropped => {
                        if let Some(&origin) = monitor_origin.get(&mref) {
                            lineage.add_happens_before(FaultEventId::new(origin), this);
                        }
                    }
                    _ => {}
                }
            }

            // (2e) Link: creation happens-before the Exit delivery/drop.
            if let Some(lref) = link_ref(&ev.data) {
                match ev.kind {
                    TraceEventKind::LinkCreated => {
                        link_origin.insert(lref, ev.seq);
                    }
                    TraceEventKind::ExitDelivered | TraceEventKind::LinkDropped => {
                        if let Some(&origin) = link_origin.get(&lref) {
                            lineage.add_happens_before(FaultEventId::new(origin), this);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // (3) Logical-clock happens-before. For every strictly-`Before` pair add an
    // edge; cycle-free because `Before` is a strict partial order, deterministic
    // because trace order is fixed.
    if config.use_logical_time {
        for (j, later) in events.iter().enumerate() {
            let Some(lt_later) = later.logical_time.as_ref() else {
                continue;
            };
            for earlier in events.iter().take(j) {
                let Some(lt_earlier) = earlier.logical_time.as_ref() else {
                    continue;
                };
                if lt_earlier.causal_order(lt_later) == CausalOrder::Before {
                    lineage.add_happens_before(
                        FaultEventId::new(earlier.seq),
                        FaultEventId::new(later.seq),
                    );
                }
            }
        }
    }

    lineage
}

/// Collects the [`FaultEventId`]s of the trace events satisfying `predicate` —
/// the outcome-producing events whose fault-able cones become the derivations of
/// a [`SupportGraph`].
pub fn outcome_events<P>(events: &[TraceEvent], mut predicate: P) -> Vec<FaultEventId>
where
    P: FnMut(&TraceEvent) -> bool,
{
    events
        .iter()
        .filter(|ev| predicate(ev))
        .map(|ev| FaultEventId::new(ev.seq))
        .collect()
}

/// Trace → [`SupportGraph`] in one step: build the lineage, then take the
/// fault-able causal cone of each event matching `predicate` as one derivation.
///
/// Feed the result to [`SupportGraph::minimal_hitting_sets`] for the fault
/// hypotheses worth testing.
#[must_use]
pub fn support_graph_for<P>(
    events: &[TraceEvent],
    config: TraceLineageConfig,
    predicate: P,
) -> SupportGraph
where
    P: FnMut(&TraceEvent) -> bool,
{
    let lineage = build_causal_lineage(events, config);
    SupportGraph::from_causal_cones(&lineage, outcome_events(events, predicate))
}

/// Schema token stamped into every serialized [`LdfiReport`]; bump on any
/// breaking change to the report shape.
pub const LDFI_REPORT_SCHEMA: &str = "ldfi-report-v1";

/// A deterministic, serde-serializable view of an LDFI run, suitable for the
/// `frankenlab ldfi --json` output (AC5).
///
/// Every fault hypothesis is rendered as a sorted list of raw event ids, so the
/// JSON is byte-stable across runs of the same input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LdfiReport {
    /// Report schema token ([`LDFI_REPORT_SCHEMA`]).
    pub schema: String,
    /// Fault depth `k` the hitting-set search ran under.
    pub max_depth: usize,
    /// Whether the bounded hypothesis space was explored without truncation.
    pub exhausted: bool,
    /// Whether some derivation had no fault-able support (outcome unbreakable).
    pub unbreakable: bool,
    /// Minimal fault hypotheses, smallest-first, each a sorted event-id list.
    pub hypotheses: Vec<Vec<u64>>,
    /// Per-corpus coverage certificate `Some(k)`: no `<= k`-fault counterexample
    /// exists for this trace, or `None` if the search was inconclusive.
    pub coverage_certificate: Option<usize>,
    /// How many single-fault experiments undirected blind chaos would run on this
    /// trace (one per fault-able event) — the baseline LDFI improves on.
    pub blind_chaos_single_fault_experiments: usize,
    /// The experiment-loop summary, present once hypotheses have been executed.
    pub experiment: Option<LdfiExperimentSummary>,
}

/// A serde-serializable view of an [`LdfiExperimentReport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LdfiExperimentSummary {
    /// Stop-condition token: `found_violation`, `refuted_up_to_depth`,
    /// `experiment_budget_exhausted`, or `hypothesis_search_truncated`.
    pub status: String,
    /// Number of hypotheses actually executed.
    pub experiments_run: usize,
    /// The hypothesis that broke the invariant, if any (sorted event ids).
    pub violating_hypothesis: Option<Vec<u64>>,
    /// Hypotheses tested without violating the invariant (sorted event ids).
    pub refuted: Vec<Vec<u64>>,
    /// Generated hypotheses left untested when the experiment budget ran out.
    pub remaining_hypotheses: Option<usize>,
    /// Fault depth covered when the corpus was refuted up to depth.
    pub max_depth: Option<usize>,
    /// Per-corpus coverage certificate from this experiment run, if any.
    pub coverage_certificate: Option<usize>,
}

impl LdfiExperimentSummary {
    /// Projects an [`LdfiExperimentReport`] into its serializable summary.
    #[must_use]
    pub fn from_report(report: &LdfiExperimentReport) -> Self {
        let (status, violating_hypothesis, remaining_hypotheses, max_depth) = match &report.status {
            LdfiExperimentStatus::FoundViolation { hypothesis } => {
                ("found_violation", Some(event_ids(hypothesis)), None, None)
            }
            LdfiExperimentStatus::RefutedUpToDepth { max_depth } => {
                ("refuted_up_to_depth", None, None, Some(*max_depth))
            }
            LdfiExperimentStatus::ExperimentBudgetExhausted {
                remaining_hypotheses,
            } => (
                "experiment_budget_exhausted",
                None,
                Some(*remaining_hypotheses),
                None,
            ),
            LdfiExperimentStatus::HypothesisSearchTruncated => {
                ("hypothesis_search_truncated", None, None, None)
            }
        };
        Self {
            status: status.to_string(),
            experiments_run: report.experiments_run,
            violating_hypothesis,
            refuted: report.refuted.iter().map(event_ids).collect(),
            remaining_hypotheses,
            max_depth,
            coverage_certificate: report.coverage_certificate(),
        }
    }
}

impl LdfiReport {
    /// Attaches an experiment-loop summary to the report.
    #[must_use]
    pub fn with_experiment(mut self, report: &LdfiExperimentReport) -> Self {
        self.experiment = Some(LdfiExperimentSummary::from_report(report));
        self
    }
}

/// Builds a deterministic [`LdfiReport`] from a hitting-set result and the
/// blind-chaos baseline (see [`blind_chaos_single_fault_count`]).
#[must_use]
pub fn ldfi_report(
    result: &HittingSetResult,
    blind_chaos_single_fault_experiments: usize,
) -> LdfiReport {
    LdfiReport {
        schema: LDFI_REPORT_SCHEMA.to_string(),
        max_depth: result.max_depth,
        exhausted: result.exhausted,
        unbreakable: result.unbreakable,
        hypotheses: result.hypotheses.iter().map(event_ids).collect(),
        coverage_certificate: result.coverage_certificate(),
        blind_chaos_single_fault_experiments,
        experiment: None,
    }
}

/// The number of single-fault experiments undirected blind chaos would run on
/// this trace: one per fault-able event.
///
/// This is the baseline the directed LDFI hypothesis count is compared against
/// (AC1's committed count comparison).
#[must_use]
pub fn blind_chaos_single_fault_count(events: &[TraceEvent]) -> usize {
    events
        .iter()
        .filter(|ev| default_faultable(ev.kind))
        .count()
}

/// Renders a hypothesis as a sorted list of raw event ids for stable output.
fn event_ids(hypothesis: &BTreeSet<FaultEventId>) -> Vec<u64> {
    hypothesis.iter().map(|e| e.get()).collect()
}

/// The single owning task of an event whose data names exactly one task, used for
/// per-task program order. Multi-task events (`Down`, `Link`, `Exit`) are left to
/// the resource-correlation and logical-clock sources instead.
fn owning_task(data: &TraceData) -> Option<TaskId> {
    match data {
        TraceData::Task { task, .. }
        | TraceData::Cancel { task, .. }
        | TraceData::Futurelock { task, .. }
        | TraceData::Obligation { task, .. }
        | TraceData::Worker { task, .. }
        | TraceData::Budget { task, .. } => Some(*task),
        _ => None,
    }
}

/// The obligation id an event references, if any (for the obligation chain).
fn obligation_of(data: &TraceData) -> Option<ObligationId> {
    match data {
        TraceData::Obligation { obligation, .. } | TraceData::Worker { obligation, .. } => {
            Some(*obligation)
        }
        _ => None,
    }
}

/// The I/O token an event references, if any (for the token chain).
fn io_token(data: &TraceData) -> Option<u64> {
    match data {
        TraceData::IoRequested { token, .. }
        | TraceData::IoReady { token, .. }
        | TraceData::IoResult { token, .. }
        | TraceData::IoError { token, .. } => Some(*token),
        _ => None,
    }
}

/// The timer id an event references, if any (for the timer correlation).
fn timer_id(data: &TraceData) -> Option<u64> {
    match data {
        TraceData::Timer { timer_id, .. } => Some(*timer_id),
        _ => None,
    }
}

/// The monitor ref an event references, if any (for the monitor correlation).
fn monitor_ref(data: &TraceData) -> Option<u64> {
    match data {
        TraceData::Monitor { monitor_ref, .. } | TraceData::Down { monitor_ref, .. } => {
            Some(*monitor_ref)
        }
        _ => None,
    }
}

/// The link ref an event references, if any (for the link correlation).
fn link_ref(data: &TraceData) -> Option<u64> {
    match data {
        TraceData::Link { link_ref, .. } | TraceData::Exit { link_ref, .. } => Some(*link_ref),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lab::ldfi::HittingSetBudget;
    use crate::record::ObligationKind;
    use crate::remote::NodeId;
    use crate::trace::distributed::{LogicalTime, VectorClock};
    use crate::types::{RegionId, Time};

    fn task(id: u32) -> TaskId {
        TaskId::new_for_test(id, 0)
    }

    fn region() -> RegionId {
        RegionId::new_for_test(0, 0)
    }

    fn ob(id: u32) -> ObligationId {
        ObligationId::new_for_test(id, 0)
    }

    fn support(lineage: &CausalLineage, seq: u64) -> Vec<u64> {
        lineage
            .support_of(FaultEventId::new(seq))
            .into_iter()
            .map(FaultEventId::get)
            .collect()
    }

    #[test]
    fn classifier_marks_deliveries_faultable_and_structure_not() {
        assert!(default_faultable(TraceEventKind::Wake));
        assert!(default_faultable(TraceEventKind::TimerFired));
        assert!(default_faultable(TraceEventKind::IoReady));
        assert!(default_faultable(TraceEventKind::ObligationCommit));
        assert!(default_faultable(TraceEventKind::DownDelivered));
        assert!(!default_faultable(TraceEventKind::Spawn));
        assert!(!default_faultable(TraceEventKind::Poll));
        assert!(!default_faultable(TraceEventKind::Complete));
        assert!(!default_faultable(TraceEventKind::IoRequested));
        assert!(!default_faultable(TraceEventKind::UserTrace));
    }

    #[test]
    fn program_order_chains_same_task() {
        // spawn(structural) -> wake(faultable) -> complete(structural), all task 1.
        let events = vec![
            TraceEvent::spawn(0, Time::ZERO, task(1), region()),
            TraceEvent::wake(1, Time::ZERO, task(1), region()),
            TraceEvent::complete(2, Time::ZERO, task(1), region()),
        ];
        let lineage = build_causal_lineage(&events, TraceLineageConfig::default());
        // The completion's cone is the whole chain; its fault-able support is just
        // the wake.
        assert_eq!(support(&lineage, 2), vec![1]);
        assert!(!lineage.is_faultable(FaultEventId::new(0)));
        assert!(lineage.is_faultable(FaultEventId::new(1)));
    }

    #[test]
    fn io_token_correlation_links_send_to_ack() {
        // Same token: result(send, faultable) then ready(ack, faultable).
        let events = vec![
            TraceEvent::io_result(0, Time::ZERO, 5, 4),
            TraceEvent::io_ready(1, Time::ZERO, 5, 1),
        ];
        let with_corr = build_causal_lineage(&events, TraceLineageConfig::default());
        assert_eq!(support(&with_corr, 1), vec![0, 1]);

        // Disabling correlation (and logical time) isolates the ack.
        let no_corr = build_causal_lineage(
            &events,
            TraceLineageConfig {
                use_logical_time: false,
                correlate_resources: false,
            },
        );
        assert_eq!(support(&no_corr, 1), vec![1]);
    }

    #[test]
    fn obligation_lifecycle_chains_reserve_to_commit() {
        let events = vec![
            TraceEvent::obligation_reserve(
                0,
                Time::ZERO,
                ob(1),
                task(1),
                region(),
                ObligationKind::Lease,
            ),
            TraceEvent::obligation_commit(
                1,
                Time::ZERO,
                ob(1),
                task(1),
                region(),
                ObligationKind::Lease,
                10,
            ),
        ];
        // Reserve and commit are both fault-able leases; commit's support is both.
        let lineage = build_causal_lineage(
            &events,
            TraceLineageConfig {
                use_logical_time: false,
                correlate_resources: true,
            },
        );
        assert_eq!(support(&lineage, 1), vec![0, 1]);
    }

    #[test]
    fn timer_scheduled_happens_before_fire() {
        let events = vec![
            TraceEvent::timer_scheduled(0, Time::ZERO, 9, Time::ZERO),
            TraceEvent::timer_fired(1, Time::ZERO, 9),
        ];
        let lineage = build_causal_lineage(
            &events,
            TraceLineageConfig {
                use_logical_time: false,
                correlate_resources: true,
            },
        );
        // Scheduled is structural; the fire is fault-able and reachable from it.
        assert_eq!(
            lineage
                .causal_cone(FaultEventId::new(1))
                .into_iter()
                .map(FaultEventId::get)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
        assert_eq!(support(&lineage, 1), vec![1]);
    }

    #[test]
    fn vector_clock_adds_cross_task_edge() {
        // send (task net) before recv-ack (task b) only via the vector clock.
        let net = NodeId::new("net");
        let b = NodeId::new("b");
        let mut send_vc = VectorClock::new();
        send_vc.increment(&net);
        let mut ack_vc = send_vc.clone();
        ack_vc.increment(&b);

        let events = vec![
            TraceEvent::io_result(0, Time::ZERO, 10, 4)
                .with_logical_time(LogicalTime::Vector(send_vc)),
            TraceEvent::io_ready(1, Time::ZERO, 20, 1)
                .with_logical_time(LogicalTime::Vector(ack_vc)),
        ];
        // Different tokens => only the logical clock can link them.
        let with_lt = build_causal_lineage(&events, TraceLineageConfig::default());
        assert_eq!(support(&with_lt, 1), vec![0, 1]);
        let without_lt = build_causal_lineage(
            &events,
            TraceLineageConfig {
                use_logical_time: false,
                correlate_resources: true,
            },
        );
        assert_eq!(support(&without_lt, 1), vec![1]);
    }

    #[test]
    fn deterministic() {
        let events = vec![
            TraceEvent::spawn(0, Time::ZERO, task(1), region()),
            TraceEvent::wake(1, Time::ZERO, task(1), region()),
            TraceEvent::io_result(2, Time::ZERO, 5, 4),
            TraceEvent::io_ready(3, Time::ZERO, 5, 1),
        ];
        let a = build_causal_lineage(&events, TraceLineageConfig::default());
        let b = build_causal_lineage(&events, TraceLineageConfig::default());
        assert_eq!(a, b);
    }

    #[test]
    fn support_graph_for_pipeline_finds_shared_root() {
        // Two ack tokens both rooted at one send via the vector clock; the outcome
        // user-traces depend on each ack. Minimal breaking hypothesis is {send}.
        let net = NodeId::new("net");
        let a = NodeId::new("a");
        let b = NodeId::new("b");
        let mut send_vc = VectorClock::new();
        send_vc.increment(&net);
        let mut ack_a_vc = send_vc.clone();
        ack_a_vc.increment(&a);
        let mut ack_b_vc = send_vc.clone();
        ack_b_vc.increment(&b);
        let mut ok_a_vc = ack_a_vc.clone();
        ok_a_vc.increment(&a);
        let mut ok_b_vc = ack_b_vc.clone();
        ok_b_vc.increment(&b);

        let events = vec![
            TraceEvent::io_result(1, Time::ZERO, 10, 4)
                .with_logical_time(LogicalTime::Vector(send_vc)),
            TraceEvent::io_ready(2, Time::ZERO, 20, 1)
                .with_logical_time(LogicalTime::Vector(ack_a_vc)),
            TraceEvent::io_ready(3, Time::ZERO, 30, 1)
                .with_logical_time(LogicalTime::Vector(ack_b_vc)),
            TraceEvent::user_trace(10, Time::ZERO, "delivered-a")
                .with_logical_time(LogicalTime::Vector(ok_a_vc)),
            TraceEvent::user_trace(11, Time::ZERO, "delivered-b")
                .with_logical_time(LogicalTime::Vector(ok_b_vc)),
        ];

        let graph = support_graph_for(&events, TraceLineageConfig::default(), |ev| {
            ev.kind == TraceEventKind::UserTrace
        });
        assert_eq!(graph.derivations().len(), 2);
        let result = graph.minimal_hitting_sets(HittingSetBudget::default());
        let smallest = result.hypotheses.first().expect("a hypothesis exists");
        assert_eq!(smallest.len(), 1);
        assert!(smallest.contains(&FaultEventId::new(1)));
    }
}
