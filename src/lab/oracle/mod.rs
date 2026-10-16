//! Test oracles for verifying runtime invariants.
//!
//! Oracles observe runtime events and verify that the 6 non-negotiable
//! invariants hold. They are used in lab mode for deterministic testing.
//!
//! # The 6 Non-Negotiable Invariants
//!
//! | # | Invariant | Oracle |
//! |---|-----------|--------|
//! | 1 | Structured concurrency – every task is owned by exactly one region | [`TaskLeakOracle`] |
//! | 2 | Region close = quiescence – no live tasks/children, finalizers done, ledger empty | [`QuiescenceOracle`] |
//! | 3 | Cancellation is a protocol – request → drain → finalize | [`CancellationProtocolOracle`] |
//! | 4 | Losers are drained – races must cancel AND fully drain losers | [`LoserDrainOracle`] |
//! | 5 | No obligation leaks – permits/acks/leases must be committed or aborted | [`ObligationLeakOracle`] |
//! | 6 | No ambient authority – effects flow through Cx and explicit capabilities | [`AmbientAuthorityOracle`] |
//!
//! Additionally:
//! - [`FinalizerOracle`] verifies all registered finalizers ran.
//! - [`RegionTreeOracle`] verifies INV-TREE: regions form a proper rooted tree.
//! - [`DeadlineMonotoneOracle`] verifies INV-DEADLINE-MONOTONE: child deadlines ≤ parent deadlines.
//!
//! # Actor-Specific Oracles
//!
//! - [`ActorLeakOracle`]: Detects actors not properly stopped before region close.
//! - [`SupervisionOracle`]: Verifies supervision tree behavior (restarts, escalation).
//! - [`MailboxOracle`]: Verifies mailbox invariants (capacity, backpressure).
//!
//! # FABRIC-Specific Oracles
//!
//! Available when the `messaging-fabric` feature is enabled:
//!
//! - `FabricPublishOracle`: committed publishes appear in the matching subscriber set.
//! - `FabricReplyOracle`: obligation-backed replies resolve before region close.
//! - `FabricQuiescenceOracle`: tracked FABRIC cells are empty when regions close.
//! - `FabricRedeliveryOracle`: redelivery stays within an explicit bound.

pub mod actor;
pub mod ambient_authority;
pub mod cancel_correctness;
pub mod cancel_debt;
pub mod cancel_signal_ordering;
pub mod cancellation_protocol;
pub mod channel_atomicity;
pub mod deadline_monotone;
pub mod determinism;
pub mod eprocess;
pub mod evidence;
#[cfg(feature = "messaging-fabric")]
pub mod fabric;
pub mod finalizer;
pub mod loser_drain;
pub mod obligation_leak;
pub mod priority_inversion;
pub mod quiescence;
pub mod region_leak;
pub mod region_tree;
pub mod registry;
pub mod rref_access;
pub mod runtime_epoch;
pub mod spork;
pub mod task_leak;
pub mod waker_dedup;

pub use actor::{
    ActorLeakOracle, ActorLeakViolation, MailboxOracle, MailboxViolation, MailboxViolationKind,
    SupervisionOracle, SupervisionViolation, SupervisionViolationKind,
};
pub use ambient_authority::{
    AmbientAuthorityOracle, AmbientAuthorityViolation, CapabilityKind, CapabilitySet,
};
pub use cancel_correctness::{
    CancelCorrectnessConfig, CancelCorrectnessOracle, CancelCorrectnessStatistics,
    CancelCorrectnessViolation, InvalidInitialWitnessKind,
};
pub use cancel_debt::{
    CancelDebtConfig, CancelDebtOracle, CancelDebtStatistics, CancelDebtViolation,
};
pub use cancel_signal_ordering::{
    CancelOrderingConfig, CancelOrderingOracle, CancelOrderingStatistics, CancelOrderingViolation,
};
pub use cancellation_protocol::{
    CancellationProtocolOracle, CancellationProtocolViolation, TaskStateKind,
};
pub use channel_atomicity::{
    ChannelAtomicityConfig, ChannelAtomicityOracle, ChannelAtomicityStatistics,
    ChannelAtomicityViolation, ChannelId, EnforcementMode, ReservationId, ViolationRecord,
    WakerId as ChannelWakerId,
};
pub use deadline_monotone::{DeadlineMonotoneOracle, DeadlineMonotoneViolation};
pub use determinism::{
    DeterminismOracle, DeterminismSourceHint, DeterminismViolation, TraceEventSummary,
    assert_deterministic, assert_deterministic_for_seeds, assert_deterministic_multi,
};
pub use eprocess::{EProcess, EProcessConfig, EProcessMonitor, EValue, MonitorResult};
pub use evidence::{
    BayesFactor, DetectionModel, EvidenceEntry, EvidenceLedger, EvidenceLine, EvidenceStrength,
    EvidenceSummary, LogLikelihoodContributions,
};
#[cfg(feature = "messaging-fabric")]
pub use fabric::{
    FabricPublishOracle, FabricPublishViolation, FabricQuiescenceOracle, FabricQuiescenceViolation,
    FabricRedeliveryOracle, FabricRedeliveryViolation, FabricReplyOracle, FabricReplyViolation,
};
pub use finalizer::{FinalizerId, FinalizerOracle, FinalizerViolation};
pub use loser_drain::{LoserDrainOracle, LoserDrainViolation};
pub use obligation_leak::{ObligationLeakOracle, ObligationLeakViolation};
pub use priority_inversion::{
    InversionId, InversionType, Priority, PriorityInversion, PriorityInversionConfig,
    PriorityInversionOracle, PriorityInversionStatistics, ResourceId,
};
pub use quiescence::{QuiescenceOracle, QuiescenceViolation};
pub use region_leak::{
    BudgetInfo, RegionLeakConfig, RegionLeakOracle, RegionLeakStatistics, RegionLifecycleState,
    RegionState as RegionLeakState, RegionViolation, TaskLifecycleState, TaskState,
    ViolationContext, ViolationType,
};
pub use region_tree::{RegionTreeEntry, RegionTreeOracle, RegionTreeViolation};
pub use registry::{
    ALL_REPORTED_ORACLE_NAMES, LAB_RUNTIME_FED_ORACLE_NAMES, ORACLE_ALL, ORACLE_DESCRIPTORS,
    OracleDescriptor, OracleRegistry, OracleRegistryError,
};
pub use rref_access::{RRefAccessOracle, RRefAccessViolation, RRefAccessViolationKind, RRefId};
pub use runtime_epoch::{
    ConsistencyLevel, RuntimeEpochConfig, RuntimeEpochOracle, RuntimeEpochStatistics,
    RuntimeEpochViolation, RuntimeModule,
};
pub use spork::{
    DownOrderOracle, DownOrderViolation, RegistryLeaseOracle, RegistryLeaseViolation,
    ReplyLinearityOracle, ReplyLinearityViolation, SupervisorQuiescenceOracle,
    SupervisorQuiescenceViolation,
};
pub use task_leak::{TaskLeakOracle, TaskLeakViolation};
pub use waker_dedup::{
    ViolationRecord as WakerViolationRecord, WakerDedupConfig, WakerDedupOracle,
    WakerDedupStatistics, WakerDedupViolation, WakerId as WakerDedupId, WakerStatus,
};

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use crate::obligation::dialectica::ContractChecker;
use crate::obligation::marking::{MarkingAnalyzer, MarkingEvent};
use crate::obligation::no_aliasing_proof::NoAliasingProver;
use crate::record::region::RegionState;
use crate::runtime::RuntimeState;
use crate::types::Time;

/// A violation detected by an oracle.
#[derive(Debug, Clone)]
pub enum OracleViolation {
    /// A task leak was detected.
    TaskLeak(TaskLeakViolation),
    /// An obligation leak was detected.
    ObligationLeak(ObligationLeakViolation),
    /// Quiescence violation on region close.
    Quiescence(QuiescenceViolation),
    /// Race losers were not properly drained.
    LoserDrain(LoserDrainViolation),
    /// Finalizers did not all run.
    Finalizer(FinalizerViolation),
    /// Region tree structure is malformed.
    RegionTree(RegionTreeViolation),
    /// Region leak or structured concurrency violation detected.
    RegionLeak(RegionViolation),
    /// Effects performed without appropriate capabilities.
    AmbientAuthority(AmbientAuthorityViolation),
    /// Child deadline exceeds parent deadline.
    DeadlineMonotone(DeadlineMonotoneViolation),
    /// Cancellation protocol violated.
    CancellationProtocol(CancellationProtocolViolation),
    /// Cancel-correctness property violated.
    CancelCorrectness(CancelCorrectnessViolation),
    /// Cancel debt accumulation violated.
    CancelDebt(CancelDebtViolation),
    /// Cancel signal ordering violated.
    CancelOrdering(CancelOrderingViolation),
    /// Runtime epoch consistency violated.
    RuntimeEpoch(RuntimeEpochViolation),
    /// Channel atomicity violation (reservation lifecycle, waker consistency, etc.).
    ChannelAtomicity(ChannelAtomicityViolation),
    /// Waker deduplication violation (lost/spurious wakeups, state inconsistency).
    WakerDedup(WakerDedupViolation),
    /// An actor leak was detected.
    ActorLeak(ActorLeakViolation),
    /// Supervision tree behavior violated.
    Supervision(SupervisionViolation),
    /// Mailbox invariant violated.
    Mailbox(MailboxViolation),
    /// RRef access violation (cross-region, post-close, or witness mismatch).
    RRefAccess(RRefAccessViolation),
    /// GenServer reply dropped without send or abort.
    ReplyLinearity(ReplyLinearityViolation),
    /// Name lease not committed or aborted (stale name).
    RegistryLease(RegistryLeaseViolation),
    /// DOWN messages delivered in non-deterministic order.
    DownOrder(DownOrderViolation),
    /// Supervisor region closed with active children.
    SupervisorQuiescence(SupervisorQuiescenceViolation),
    /// FABRIC publish was not observed by the expected subscriber set.
    #[cfg(feature = "messaging-fabric")]
    FabricPublish(FabricPublishViolation),
    /// FABRIC obligation-backed reply remained unresolved at region close.
    #[cfg(feature = "messaging-fabric")]
    FabricReply(FabricReplyViolation),
    /// FABRIC cells remained non-quiescent when a region closed.
    #[cfg(feature = "messaging-fabric")]
    FabricQuiescence(FabricQuiescenceViolation),
    /// FABRIC redelivery exceeded its configured bound.
    #[cfg(feature = "messaging-fabric")]
    FabricRedelivery(FabricRedeliveryViolation),
    /// Priority inversion violation (high-priority task blocked by low-priority task).
    PriorityInversion(PriorityInversion),
}

impl std::fmt::Display for OracleViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TaskLeak(v) => write!(f, "Task leak: {v}"),
            Self::ObligationLeak(v) => write!(f, "Obligation leak: {v}"),
            Self::Quiescence(v) => write!(f, "Quiescence violation: {v}"),
            Self::LoserDrain(v) => write!(f, "Loser drain violation: {v}"),
            Self::Finalizer(v) => write!(f, "Finalizer violation: {v}"),
            Self::RegionTree(v) => write!(f, "Region tree violation: {v}"),
            Self::RegionLeak(v) => write!(f, "Region leak violation: {v}"),
            Self::AmbientAuthority(v) => write!(f, "Ambient authority violation: {v}"),
            Self::DeadlineMonotone(v) => write!(f, "Deadline monotonicity violation: {v}"),
            Self::CancellationProtocol(v) => write!(f, "Cancellation protocol violation: {v}"),
            Self::CancelCorrectness(v) => write!(f, "Cancel-correctness violation: {v}"),
            Self::CancelDebt(v) => write!(f, "Cancel debt violation: {v}"),
            Self::CancelOrdering(v) => write!(f, "Cancel ordering violation: {v}"),
            Self::RuntimeEpoch(v) => write!(f, "Runtime epoch violation: {v}"),
            Self::ChannelAtomicity(v) => write!(f, "Channel atomicity violation: {v}"),
            Self::WakerDedup(v) => write!(f, "Waker deduplication violation: {v}"),
            Self::ActorLeak(v) => write!(f, "Actor leak: {v}"),
            Self::Supervision(v) => write!(f, "Supervision violation: {v}"),
            Self::Mailbox(v) => write!(f, "Mailbox violation: {v}"),
            Self::RRefAccess(v) => write!(f, "RRef access violation: {v}"),
            Self::ReplyLinearity(v) => write!(f, "Reply linearity violation: {v}"),
            Self::RegistryLease(v) => write!(f, "Registry lease violation: {v}"),
            Self::DownOrder(v) => write!(f, "DOWN order violation: {v}"),
            Self::SupervisorQuiescence(v) => write!(f, "Supervisor quiescence violation: {v}"),
            #[cfg(feature = "messaging-fabric")]
            Self::FabricPublish(v) => write!(f, "FABRIC publish violation: {v}"),
            #[cfg(feature = "messaging-fabric")]
            Self::FabricReply(v) => write!(f, "FABRIC reply violation: {v}"),
            #[cfg(feature = "messaging-fabric")]
            Self::FabricQuiescence(v) => write!(f, "FABRIC quiescence violation: {v}"),
            #[cfg(feature = "messaging-fabric")]
            Self::FabricRedelivery(v) => write!(f, "FABRIC redelivery violation: {v}"),
            Self::PriorityInversion(v) => write!(
                f,
                "Priority inversion: Task {:?}(P{:?}) blocked by Task {:?}(P{:?}) on Resource {:?} for {:?}",
                v.blocked_task,
                v.blocked_priority,
                v.blocking_task,
                v.blocking_priority,
                v.resource_id,
                v.duration.unwrap_or_else(|| v.start_time.elapsed())
            ),
        }
    }
}

impl std::error::Error for OracleViolation {}

/// Aggregates all oracles for convenient use in lab runtime.
#[derive(Debug, Default)]
pub struct OracleSuite {
    /// Task leak oracle.
    pub task_leak: TaskLeakOracle,
    /// Obligation leak oracle.
    pub obligation_leak: ObligationLeakOracle,
    /// Quiescence oracle.
    pub quiescence: QuiescenceOracle,
    /// Loser drain oracle.
    pub loser_drain: LoserDrainOracle,
    /// Finalizer oracle.
    pub finalizer: FinalizerOracle,
    /// Region tree oracle.
    pub region_tree: RegionTreeOracle,
    /// Region leak detection oracle.
    pub region_leak: RegionLeakOracle,
    /// Ambient authority oracle.
    pub ambient_authority: AmbientAuthorityOracle,
    /// Deadline monotonicity oracle.
    pub deadline_monotone: DeadlineMonotoneOracle,
    /// Cancellation protocol oracle.
    pub cancellation_protocol: CancellationProtocolOracle,
    /// Cancel-correctness property oracle.
    pub cancel_correctness: CancelCorrectnessOracle,
    /// Cancel debt accumulation oracle.
    pub cancel_debt: CancelDebtOracle,
    /// Cancel signal ordering oracle.
    pub cancel_signal_ordering: CancelOrderingOracle,
    /// Runtime epoch consistency oracle.
    pub runtime_epoch: RuntimeEpochOracle,
    /// Channel atomicity oracle.
    pub channel_atomicity: ChannelAtomicityOracle,
    /// Waker deduplication oracle.
    pub waker_dedup: WakerDedupOracle,
    /// Actor leak oracle.
    pub actor_leak: ActorLeakOracle,
    /// Supervision oracle.
    pub supervision: SupervisionOracle,
    /// Mailbox oracle.
    pub mailbox: MailboxOracle,
    /// RRef access oracle.
    pub rref_access: RRefAccessOracle,
    /// Spork: reply linearity oracle.
    pub reply_linearity: ReplyLinearityOracle,
    /// Spork: registry lease linearity oracle.
    pub registry_lease: RegistryLeaseOracle,
    /// Spork: deterministic DOWN ordering oracle.
    pub down_order: DownOrderOracle,
    /// Spork: supervisor quiescence oracle.
    pub supervisor_quiescence: SupervisorQuiescenceOracle,
    /// FABRIC: committed publishes appear in the matching subscriber set.
    #[cfg(feature = "messaging-fabric")]
    pub fabric_publish: FabricPublishOracle,
    /// FABRIC: obligation-backed replies resolve before region close.
    #[cfg(feature = "messaging-fabric")]
    pub fabric_reply: FabricReplyOracle,
    /// FABRIC: tracked cells are quiescent on region close.
    #[cfg(feature = "messaging-fabric")]
    pub fabric_quiescence: FabricQuiescenceOracle,
    /// FABRIC: redelivery remains bounded.
    #[cfg(feature = "messaging-fabric")]
    pub fabric_redelivery: FabricRedeliveryOracle,
    /// Anytime-valid e-process monitor for sequential invariant testing.
    ///
    /// Continuously monitors oracle reports via betting martingales so that
    /// peeking after every scheduling step preserves Type-I error control
    /// (Ville's inequality). When `Some`, initialized with standard invariants
    /// (task_leak, obligation_leak, quiescence) and fed every oracle report.
    pub eprocess_monitor: Option<EProcessMonitor>,
}

impl OracleSuite {
    /// Creates a new oracle suite with all oracles initialized.
    #[must_use]
    pub fn new() -> Self {
        Self {
            eprocess_monitor: Some(EProcessMonitor::standard()),
            ..Self::default()
        }
    }

    /// Rebuilds core temporal-oracle state from a runtime snapshot.
    ///
    /// This hydrates invariant checkers that require lifecycle observations but
    /// are often inspected post-run from the current runtime state.
    #[allow(clippy::too_many_lines)]
    pub fn hydrate_temporal_from_state(&mut self, state: &RuntimeState, now: Time) {
        #[derive(Clone, Copy)]
        struct RegionSnapshot {
            id: crate::types::RegionId,
            parent: Option<crate::types::RegionId>,
            state: RegionState,
            budget: crate::types::Budget,
            created_at: Time,
        }

        fn walk_regions(
            id: crate::types::RegionId,
            children: &BTreeMap<crate::types::RegionId, Vec<crate::types::RegionId>>,
            seen: &mut BTreeSet<crate::types::RegionId>,
            pre_order: &mut Vec<crate::types::RegionId>,
            post_order: &mut Vec<crate::types::RegionId>,
        ) {
            if !seen.insert(id) {
                return;
            }
            pre_order.push(id);
            if let Some(kids) = children.get(&id) {
                for &child in kids {
                    walk_regions(child, children, seen, pre_order, post_order);
                }
            }
            post_order.push(id);
        }

        self.task_leak.reset();
        self.obligation_leak.snapshot_from_state(state, now);
        self.quiescence.snapshot_from_state(state, now);
        self.finalizer.reset();
        self.region_tree.reset();
        self.deadline_monotone.reset();
        if self.cancellation_protocol.has_observed_events() {
            // Live task history stays; the region tree and region
            // cancellations, which the lab does not feed live, come from the
            // state (br-asupersync-vcu2oz).
            self.cancellation_protocol
                .refresh_region_topology_from_state(state);
        } else {
            self.cancellation_protocol.snapshot_from_state(state, now);
        }
        self.cancel_correctness.reset();
        self.cancel_debt.reset();
        self.cancel_signal_ordering.reset();
        self.runtime_epoch.reset();

        // DOWN deliveries of runtime monitors (kpmoy5.6.1), replayed whole on
        // every hydration. A suite fed by hand, with no runtime monitor, keeps
        // its events.
        let mut downs = state.down_history().peekable();
        if downs.peek().is_some() {
            self.down_order.reset();
            for (watcher, monitored, completion_vt) in downs {
                self.down_order
                    .on_down_delivered_at(watcher, monitored, completion_vt);
            }
        }

        // Managed-supervisor restart history (br-asupersync-52hxjz), replayed
        // whole on every hydration. A suite fed by hand keeps its events. Each
        // event's time is its log position: the controller publishes a restart
        // batch in causal order, while virtual time can give a failure and an
        // immediate re-crash the same instant and merge their windows.
        let supervision = state.supervision_history();
        if !supervision.is_empty() {
            use crate::runtime::state::SupervisionHistoryEvent;
            self.supervision.reset();
            let mut ids: BTreeMap<(u64, Option<usize>), crate::actor::ActorId> = BTreeMap::new();
            let mut actor = |supervisor: u64, child: Option<usize>| {
                let next = u32::try_from(ids.len()).unwrap_or(u32::MAX);
                *ids.entry((supervisor, child)).or_insert_with(|| {
                    crate::actor::ActorId::from_task(crate::types::TaskId::from_arena(
                        crate::util::ArenaIndex::new(next, 0),
                    ))
                })
            };
            for (position, event) in supervision.iter().enumerate() {
                let time = Time::from_nanos(
                    u64::try_from(position)
                        .unwrap_or(u64::MAX)
                        .saturating_add(1),
                );
                match *event {
                    SupervisionHistoryEvent::Supervisor {
                        supervisor,
                        restart_policy,
                        max_restarts,
                        escalation,
                        children,
                    } => {
                        let parent = actor(supervisor, None);
                        self.supervision.register_supervisor(
                            parent,
                            restart_policy,
                            max_restarts,
                            escalation,
                        );
                        for index in 0..children {
                            self.supervision
                                .register_child(parent, actor(supervisor, Some(index)));
                        }
                    }
                    SupervisionHistoryEvent::ChildFailed { supervisor, child } => {
                        self.supervision.on_child_failed(
                            actor(supervisor, None),
                            actor(supervisor, Some(child)),
                            time,
                            String::from("managed child failed"),
                        );
                    }
                    SupervisionHistoryEvent::Restarted {
                        supervisor,
                        child,
                        attempt,
                    } => {
                        self.supervision
                            .on_restart(actor(supervisor, Some(child)), attempt, time);
                    }
                    SupervisionHistoryEvent::Escalated { supervisor } => {
                        let parent = actor(supervisor, None);
                        self.supervision.on_escalation(
                            parent,
                            parent,
                            time,
                            String::from("managed restart window exhausted"),
                        );
                    }
                }
            }
        }

        // GenServer reply history (br-asupersync-52hxjz), replayed whole on
        // every hydration. It replaces the oracle's events; a suite fed by
        // hand keeps them only while the runtime has recorded no reply. Each `Reply`
        // gets its own synthetic task, so calls to one server do not share an
        // entry. A reply recorded as dropped is reported at once. Any other
        // reply still unresolved while some task runs is in flight, so a
        // mid-run report leaves it out: a `Reply` can be moved into a helper
        // task that outlives its server. Once no task runs, an unresolved
        // reply was lost (for example forgotten) and is reported.
        let replies = state.reply_history();
        if !replies.is_empty() {
            use crate::runtime::state::ReplyHistoryEvent;
            self.reply_linearity.reset();
            let any_task_running = state
                .tasks_iter()
                .any(|(_, task)| !task.state.is_terminal());
            let resolved: std::collections::BTreeSet<u64> = replies
                .iter()
                .filter_map(|event| match *event {
                    ReplyHistoryEvent::Sent { call } | ReplyHistoryEvent::Aborted { call } => {
                        Some(call)
                    }
                    ReplyHistoryEvent::Created { .. } | ReplyHistoryEvent::Dropped { .. } => None,
                })
                .collect();
            let dropped: std::collections::BTreeSet<u64> = replies
                .iter()
                .filter_map(|event| match *event {
                    ReplyHistoryEvent::Dropped { call } => Some(call),
                    _ => None,
                })
                .collect();
            let call_task = |call: u64| {
                crate::types::TaskId::from_arena(crate::util::ArenaIndex::new(
                    u32::try_from(call).unwrap_or(u32::MAX),
                    0,
                ))
            };
            let mut servers: BTreeMap<u64, crate::actor::ActorId> = BTreeMap::new();
            for event in &replies {
                match *event {
                    ReplyHistoryEvent::Created { call, server, time } => {
                        let in_flight = !resolved.contains(&call)
                            && !dropped.contains(&call)
                            && any_task_running;
                        if !in_flight {
                            let server = crate::actor::ActorId::from_task(server);
                            servers.insert(call, server);
                            self.reply_linearity
                                .on_reply_created(server, call_task(call), time);
                        }
                    }
                    ReplyHistoryEvent::Sent { call } => {
                        if let Some(&server) = servers.get(&call) {
                            self.reply_linearity.on_reply_sent(server, call_task(call));
                        }
                    }
                    ReplyHistoryEvent::Aborted { call } => {
                        if let Some(&server) = servers.get(&call) {
                            self.reply_linearity
                                .on_reply_aborted(server, call_task(call));
                        }
                    }
                    // Fed above as created and never resolved.
                    ReplyHistoryEvent::Dropped { .. } => {}
                }
            }
        }

        // Replayed on every hydration, not only the first: a race in flight
        // at one report completes by the next (br-asupersync-vcu2oz). A suite
        // fed by hand keeps its events; an empty history marks nothing, so
        // events fed after it are still kept apart.
        if self.loser_drain.accepts_state_history() {
            for event in state.loser_drain_history() {
                self.loser_drain.mark_hydrated_from_state();
                match event {
                    crate::runtime::state::LoserDrainHistoryEvent::RaceStarted {
                        race_id,
                        region,
                        participants,
                        time,
                    } => {
                        self.loser_drain
                            .on_race_start_with_id(race_id, region, participants, time)
                    }
                    crate::runtime::state::LoserDrainHistoryEvent::TaskCompleted { task, time } => {
                        self.loser_drain.on_task_complete(task, time);
                    }
                    crate::runtime::state::LoserDrainHistoryEvent::RaceCompleted {
                        race_id,
                        winner,
                        time,
                    } => self.loser_drain.on_race_complete(race_id, winner, time),
                }
            }
        }

        for event in state.finalizer_history() {
            match *event {
                crate::runtime::state::FinalizerHistoryEvent::Registered { id, region, time } => {
                    self.finalizer.on_register(FinalizerId(id), region, time);
                }
                crate::runtime::state::FinalizerHistoryEvent::Ran { id, time } => {
                    self.finalizer.on_run(FinalizerId(id), time);
                }
                crate::runtime::state::FinalizerHistoryEvent::RegionClosed { region, time } => {
                    self.finalizer.on_region_close(region, time);
                }
            }
        }

        let mut regions: BTreeMap<crate::types::RegionId, RegionSnapshot> = BTreeMap::new();
        let mut children: BTreeMap<crate::types::RegionId, Vec<crate::types::RegionId>> =
            BTreeMap::new();

        for (_, region) in state.regions_iter() {
            let snapshot = RegionSnapshot {
                id: region.id,
                parent: region.parent,
                state: region.state(),
                budget: region.budget(),
                created_at: region.created_at(),
            };
            regions.insert(snapshot.id, snapshot);
            children.entry(snapshot.id).or_default();
        }

        for snapshot in regions.values() {
            if let Some(parent) = snapshot.parent {
                children.entry(parent).or_default().push(snapshot.id);
            }
        }
        for kids in children.values_mut() {
            kids.sort();
        }

        let mut roots = Vec::new();
        for (id, snapshot) in &regions {
            if snapshot
                .parent
                .is_none_or(|parent| !regions.contains_key(&parent))
            {
                roots.push(*id);
            }
        }

        let mut pre_order = Vec::new();
        let mut post_order = Vec::new();
        let mut seen = BTreeSet::new();

        for root in roots {
            walk_regions(root, &children, &mut seen, &mut pre_order, &mut post_order);
        }
        for &id in regions.keys() {
            walk_regions(id, &children, &mut seen, &mut pre_order, &mut post_order);
        }

        for region_id in &pre_order {
            let Some(snapshot) = regions.get(region_id) else {
                continue;
            };
            self.region_tree
                .on_region_create(snapshot.id, snapshot.parent, snapshot.created_at);
            self.deadline_monotone.on_region_create(
                snapshot.id,
                snapshot.parent,
                &snapshot.budget,
                now,
            );
        }

        let mut tasks = Vec::new();
        for (_, task) in state.tasks_iter() {
            tasks.push((task.id, task.owner, task.state.is_terminal()));
        }
        tasks.sort_by_key(|(task, _, _)| *task);

        for (task_id, region_id, terminal) in tasks {
            self.task_leak.on_spawn(task_id, region_id, now);
            if terminal {
                self.task_leak.on_complete(task_id, now);
            }
        }

        // A closed region leaves the runtime's table in the walk that closes
        // it; its close survives only in the history (br-asupersync-iwbef2).
        for event in state.finalizer_history() {
            if let crate::runtime::state::FinalizerHistoryEvent::RegionClosed { region, time } =
                *event
                && regions
                    .get(&region)
                    .is_none_or(|snapshot| !snapshot.state.is_terminal())
            {
                self.task_leak.on_region_close(region, time);
            }
        }

        for region_id in post_order {
            let Some(snapshot) = regions.get(&region_id) else {
                continue;
            };
            if snapshot.state.is_terminal() {
                self.task_leak.on_region_close(region_id, now);
            }
        }
    }

    /// `RegionLeakOracle` may return `Err` in fail-fast mode after recording
    /// the underlying violations internally. Preserve those recorded
    /// violations instead of silently treating the oracle as clean.
    fn region_leak_violations(&mut self) -> Vec<RegionViolation> {
        match self.region_leak.check_for_violations() {
            Ok(violations) => violations,
            Err(_) => self.region_leak.violations().iter().cloned().collect(),
        }
    }

    /// Checks all oracles and returns any violations.
    #[must_use]
    pub fn check_all(&mut self, now: Time) -> Vec<OracleViolation> {
        self.waker_dedup.set_logical_time(now);
        let mut violations = Vec::new();

        if let Err(v) = self.task_leak.check(now) {
            violations.push(OracleViolation::TaskLeak(v));
        }

        if let Err(v) = self.obligation_leak.check(now) {
            violations.push(OracleViolation::ObligationLeak(v));
        }

        if let Err(v) = self.quiescence.check() {
            violations.push(OracleViolation::Quiescence(v));
        }

        if let Err(v) = self.loser_drain.check() {
            violations.push(OracleViolation::LoserDrain(v));
        }

        if let Err(v) = self.finalizer.check() {
            violations.push(OracleViolation::Finalizer(v));
        }

        if let Err(v) = self.region_tree.check() {
            violations.push(OracleViolation::RegionTree(v));
        }

        for violation in self.region_leak_violations() {
            violations.push(OracleViolation::RegionLeak(violation));
        }

        if let Err(v) = self.ambient_authority.check() {
            violations.push(OracleViolation::AmbientAuthority(v));
        }

        if let Err(v) = self.deadline_monotone.check() {
            violations.push(OracleViolation::DeadlineMonotone(v));
        }

        if let Err(v) = self.cancellation_protocol.check() {
            violations.push(OracleViolation::CancellationProtocol(v));
        }

        if let Err(v) = self.cancel_correctness.check(now) {
            violations.push(OracleViolation::CancelCorrectness(v));
        }

        if let Err(v) = self.cancel_debt.check(now) {
            violations.push(OracleViolation::CancelDebt(v));
        }

        if let Err(v) = self.cancel_signal_ordering.check(now) {
            violations.push(OracleViolation::CancelOrdering(v));
        }

        if let Err(v) = self.runtime_epoch.check(now) {
            violations.push(OracleViolation::RuntimeEpoch(v));
        }

        let channel_atomicity_violations = self.channel_atomicity.check_for_violations();
        if let Ok(violations_vec) = channel_atomicity_violations {
            for violation in violations_vec {
                violations.push(OracleViolation::ChannelAtomicity(violation));
            }
        } else {
            // Handle case where oracle fails - this would be a critical error
            // For now, we'll skip adding violations
        }

        let waker_dedup_violations = self.waker_dedup.check_for_violations();
        if let Ok(violations_vec) = waker_dedup_violations {
            for violation in violations_vec {
                violations.push(OracleViolation::WakerDedup(violation));
            }
        } else {
            // Handle case where oracle fails - this would be a critical error
            // For now, we'll skip adding violations
        }

        if let Err(v) = self.actor_leak.check(now) {
            violations.push(OracleViolation::ActorLeak(v));
        }

        if let Err(v) = self.supervision.check(now) {
            violations.push(OracleViolation::Supervision(v));
        }

        if let Err(v) = self.mailbox.check(now) {
            violations.push(OracleViolation::Mailbox(v));
        }

        if let Err(v) = self.rref_access.check() {
            violations.push(OracleViolation::RRefAccess(v));
        }

        if let Err(v) = self.reply_linearity.check() {
            violations.push(OracleViolation::ReplyLinearity(v));
        }

        if let Err(v) = self.registry_lease.check() {
            violations.push(OracleViolation::RegistryLease(v));
        }

        if let Err(v) = self.down_order.check() {
            violations.push(OracleViolation::DownOrder(v));
        }

        if let Err(v) = self.supervisor_quiescence.check() {
            violations.push(OracleViolation::SupervisorQuiescence(v));
        }

        #[cfg(feature = "messaging-fabric")]
        if let Err(v) = self.fabric_publish.check() {
            violations.push(OracleViolation::FabricPublish(v));
        }

        #[cfg(feature = "messaging-fabric")]
        if let Err(v) = self.fabric_reply.check() {
            violations.push(OracleViolation::FabricReply(v));
        }

        #[cfg(feature = "messaging-fabric")]
        if let Err(v) = self.fabric_quiescence.check() {
            violations.push(OracleViolation::FabricQuiescence(v));
        }

        #[cfg(feature = "messaging-fabric")]
        if let Err(v) = self.fabric_redelivery.check() {
            violations.push(OracleViolation::FabricRedelivery(v));
        }

        violations
    }

    /// Resets all oracles to their initial state.
    pub fn reset(&mut self) {
        self.task_leak.reset();
        self.obligation_leak.reset();
        self.quiescence.reset();
        self.loser_drain.reset();
        self.finalizer.reset();
        self.region_tree.reset();
        self.region_leak.reset();
        self.ambient_authority.reset();
        self.deadline_monotone.reset();
        self.cancellation_protocol.reset();
        self.cancel_correctness.reset();
        self.cancel_debt.reset();
        self.cancel_signal_ordering.reset();
        self.runtime_epoch.reset();
        self.channel_atomicity.reset();
        self.waker_dedup.reset();
        self.actor_leak.reset();
        self.supervision.reset();
        self.mailbox.reset();
        self.rref_access.reset();
        self.reply_linearity.reset();
        self.registry_lease.reset();
        self.down_order.reset();
        self.supervisor_quiescence.reset();
        #[cfg(feature = "messaging-fabric")]
        self.fabric_publish.reset();
        #[cfg(feature = "messaging-fabric")]
        self.fabric_reply.reset();
        #[cfg(feature = "messaging-fabric")]
        self.fabric_quiescence.reset();
        #[cfg(feature = "messaging-fabric")]
        self.fabric_redelivery.reset();
    }

    /// Generates a unified oracle report with per-oracle status and statistics.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn report(&mut self, now: Time) -> OracleReport {
        self.waker_dedup.set_logical_time(now);
        let entries = vec![
            OracleEntryReport::from_result(
                "task_leak",
                self.task_leak
                    .check(now)
                    .err()
                    .map(OracleViolation::TaskLeak),
                OracleStats {
                    entities_tracked: self.task_leak.task_count(),
                    events_recorded: self.task_leak.task_count()
                        + self.task_leak.completed_count()
                        + self.task_leak.closed_region_count(),
                },
            ),
            OracleEntryReport::from_result(
                "obligation_leak",
                self.obligation_leak
                    .check(now)
                    .err()
                    .map(OracleViolation::ObligationLeak),
                OracleStats {
                    entities_tracked: self.obligation_leak.obligation_count(),
                    events_recorded: self.obligation_leak.obligation_count()
                        + self.obligation_leak.closed_region_count(),
                },
            ),
            OracleEntryReport::from_result(
                "quiescence",
                self.quiescence
                    .check()
                    .err()
                    .map(OracleViolation::Quiescence),
                OracleStats {
                    entities_tracked: self.quiescence.region_count(),
                    events_recorded: self.quiescence.region_count()
                        + self.quiescence.closed_count(),
                },
            ),
            OracleEntryReport::from_result(
                "loser_drain",
                self.loser_drain
                    .check()
                    .err()
                    .map(OracleViolation::LoserDrain),
                OracleStats {
                    entities_tracked: self.loser_drain.race_count(),
                    events_recorded: self.loser_drain.race_count()
                        + self.loser_drain.completed_race_count(),
                },
            ),
            OracleEntryReport::from_result(
                "finalizer",
                self.finalizer.check().err().map(OracleViolation::Finalizer),
                OracleStats {
                    entities_tracked: self.finalizer.registered_count(),
                    events_recorded: self.finalizer.registered_count()
                        + self.finalizer.ran_count()
                        + self.finalizer.closed_region_count(),
                },
            ),
            OracleEntryReport::from_result(
                "region_tree",
                self.region_tree
                    .check()
                    .err()
                    .map(OracleViolation::RegionTree),
                OracleStats {
                    entities_tracked: self.region_tree.region_count(),
                    events_recorded: self.region_tree.region_count(),
                },
            ),
            OracleEntryReport::from_result(
                "region_leak",
                self.region_leak_violations()
                    .into_iter()
                    .next()
                    .map(OracleViolation::RegionLeak),
                OracleStats {
                    entities_tracked: self.region_leak.statistics().active_regions as usize,
                    events_recorded: (self.region_leak.statistics().total_regions_created
                        + self.region_leak.statistics().total_tasks_spawned)
                        as usize,
                },
            ),
            OracleEntryReport::from_result(
                "ambient_authority",
                self.ambient_authority
                    .check()
                    .err()
                    .map(OracleViolation::AmbientAuthority),
                OracleStats {
                    entities_tracked: self.ambient_authority.task_count(),
                    events_recorded: self.ambient_authority.task_count()
                        + self.ambient_authority.effect_count(),
                },
            ),
            OracleEntryReport::from_result(
                "deadline_monotone",
                self.deadline_monotone
                    .check()
                    .err()
                    .map(OracleViolation::DeadlineMonotone),
                OracleStats {
                    entities_tracked: self.deadline_monotone.region_count(),
                    events_recorded: self.deadline_monotone.region_count(),
                },
            ),
            OracleEntryReport::from_result(
                "cancellation_protocol",
                self.cancellation_protocol
                    .check()
                    .err()
                    .map(OracleViolation::CancellationProtocol),
                OracleStats {
                    entities_tracked: self.cancellation_protocol.region_count(),
                    events_recorded: self.cancellation_protocol.region_count()
                        + self.cancellation_protocol.cancel_count(),
                },
            ),
            OracleEntryReport::from_result(
                "cancel_correctness",
                self.cancel_correctness
                    .check(now)
                    .err()
                    .map(OracleViolation::CancelCorrectness),
                OracleStats {
                    entities_tracked: self.cancel_correctness.get_statistics().active_tasks,
                    events_recorded: self.cancel_correctness.get_statistics().witnesses_processed
                        as usize,
                },
            ),
            OracleEntryReport::from_result(
                "cancel_debt",
                self.cancel_debt
                    .check(now)
                    .err()
                    .map(OracleViolation::CancelDebt),
                OracleStats {
                    entities_tracked: self.cancel_debt.get_statistics().tracked_queues,
                    events_recorded: self.cancel_debt.get_statistics().work_items_tracked as usize,
                },
            ),
            OracleEntryReport::from_result(
                "cancel_signal_ordering",
                self.cancel_signal_ordering
                    .check(now)
                    .err()
                    .map(OracleViolation::CancelOrdering),
                OracleStats {
                    entities_tracked: self.cancel_signal_ordering.get_statistics().tracked_signals,
                    events_recorded: self
                        .cancel_signal_ordering
                        .get_statistics()
                        .signals_processed as usize,
                },
            ),
            OracleEntryReport::from_result(
                "runtime_epoch",
                self.runtime_epoch
                    .check(now)
                    .err()
                    .map(OracleViolation::RuntimeEpoch),
                OracleStats {
                    entities_tracked: self.runtime_epoch.get_statistics().tracked_modules,
                    events_recorded: self.runtime_epoch.get_statistics().transitions_tracked
                        as usize,
                },
            ),
            OracleEntryReport::from_result(
                "channel_atomicity",
                self.channel_atomicity
                    .check_for_violations()
                    .ok()
                    .and_then(|violations| violations.first().cloned())
                    .map(OracleViolation::ChannelAtomicity),
                OracleStats {
                    entities_tracked: (self
                        .channel_atomicity
                        .statistics()
                        .total_reservations_created
                        + self.channel_atomicity.statistics().total_wakers_registered)
                        as usize,
                    events_recorded: (self
                        .channel_atomicity
                        .statistics()
                        .total_reservations_created
                        + self
                            .channel_atomicity
                            .statistics()
                            .total_reservations_committed
                        + self
                            .channel_atomicity
                            .statistics()
                            .total_reservations_aborted
                        + self.channel_atomicity.statistics().total_wakers_registered
                        + self.channel_atomicity.statistics().total_wakeups_expected
                        + self.channel_atomicity.statistics().total_wakeups_actual)
                        as usize,
                },
            ),
            OracleEntryReport::from_result(
                "waker_dedup",
                self.waker_dedup
                    .check_for_violations()
                    .ok()
                    .and_then(|violations| violations.first().cloned())
                    .map(OracleViolation::WakerDedup),
                OracleStats {
                    entities_tracked: self.waker_dedup.statistics().active_wakers as usize,
                    events_recorded: (self.waker_dedup.statistics().total_wakers_registered
                        + self.waker_dedup.statistics().total_wakers_woken
                        + self.waker_dedup.statistics().total_wakers_dropped)
                        as usize,
                },
            ),
            OracleEntryReport::from_result(
                "actor_leak",
                self.actor_leak
                    .check(now)
                    .err()
                    .map(OracleViolation::ActorLeak),
                OracleStats {
                    entities_tracked: self.actor_leak.actor_count(),
                    events_recorded: self.actor_leak.actor_count()
                        + self.actor_leak.stopped_count()
                        + self.actor_leak.closed_region_count(),
                },
            ),
            OracleEntryReport::from_result(
                "supervision",
                self.supervision
                    .check(now)
                    .err()
                    .map(OracleViolation::Supervision),
                OracleStats {
                    entities_tracked: self.supervision.failure_count()
                        + self.supervision.restart_count(),
                    events_recorded: self.supervision.failure_count()
                        + self.supervision.restart_count()
                        + self.supervision.escalation_count(),
                },
            ),
            OracleEntryReport::from_result(
                "mailbox",
                self.mailbox.check(now).err().map(OracleViolation::Mailbox),
                OracleStats {
                    entities_tracked: self.mailbox.mailbox_count(),
                    events_recorded: self.mailbox.mailbox_count(),
                },
            ),
            OracleEntryReport::from_result(
                "rref_access",
                self.rref_access
                    .check()
                    .err()
                    .map(OracleViolation::RRefAccess),
                OracleStats {
                    entities_tracked: self.rref_access.rref_count(),
                    events_recorded: self.rref_access.rref_count()
                        + self.rref_access.task_count()
                        + self.rref_access.closed_region_count(),
                },
            ),
            OracleEntryReport::from_result(
                "reply_linearity",
                self.reply_linearity
                    .check()
                    .err()
                    .map(OracleViolation::ReplyLinearity),
                OracleStats {
                    entities_tracked: self.reply_linearity.created_count(),
                    events_recorded: self.reply_linearity.created_count()
                        + self.reply_linearity.resolved_count(),
                },
            ),
            OracleEntryReport::from_result(
                "registry_lease",
                self.registry_lease
                    .check()
                    .err()
                    .map(OracleViolation::RegistryLease),
                OracleStats {
                    entities_tracked: self.registry_lease.acquired_count(),
                    events_recorded: self.registry_lease.acquired_count()
                        + self.registry_lease.resolved_count(),
                },
            ),
            OracleEntryReport::from_result(
                "down_order",
                self.down_order
                    .check()
                    .err()
                    .map(OracleViolation::DownOrder),
                OracleStats {
                    entities_tracked: self.down_order.monitor_count(),
                    events_recorded: self.down_order.down_count(),
                },
            ),
            OracleEntryReport::from_result(
                "supervisor_quiescence",
                self.supervisor_quiescence
                    .check()
                    .err()
                    .map(OracleViolation::SupervisorQuiescence),
                OracleStats {
                    entities_tracked: self.supervisor_quiescence.supervisor_count(),
                    events_recorded: self.supervisor_quiescence.child_count()
                        + self.supervisor_quiescence.closed_region_count(),
                },
            ),
            #[cfg(feature = "messaging-fabric")]
            self.fabric_publish.report_entry(),
            #[cfg(feature = "messaging-fabric")]
            self.fabric_reply.report_entry(),
            #[cfg(feature = "messaging-fabric")]
            self.fabric_quiescence.report_entry(),
            #[cfg(feature = "messaging-fabric")]
            self.fabric_redelivery.report_entry(),
        ];

        let total = entries.len();
        let passed = entries.iter().filter(|e| e.passed).count();
        let failed = total - passed;

        OracleReport {
            entries,
            total,
            passed,
            failed,
            check_time_nanos: now.as_nanos(),
        }
    }

    /// Generates an oracle report and feeds it to the e-process monitor for
    /// anytime-valid sequential testing.
    ///
    /// This closes the loop between oracle observations and statistical
    /// evidence accumulation: each call updates the per-invariant betting
    /// martingales, so that `eprocess_monitor.any_rejected()` provides a
    /// continuously valid (Ville's inequality) rejection signal.
    #[must_use]
    pub fn report_and_observe(&mut self, now: Time) -> OracleReport {
        let report = self.report(now);
        if let Some(ref mut monitor) = self.eprocess_monitor {
            monitor.observe_report(&report);
        }
        report
    }

    /// Returns the names of invariants rejected by the e-process monitor,
    /// if any. Empty if no monitor is active or no invariant has been rejected.
    #[must_use]
    pub fn eprocess_rejected_invariants(&self) -> Vec<String> {
        self.eprocess_monitor.as_ref().map_or_else(Vec::new, |m| {
            m.rejected_invariants()
                .into_iter()
                .map(String::from)
                .collect()
        })
    }

    /// Runs post-hoc obligation theory validators on a collected marking
    /// event trace.
    ///
    /// This wires the formal methods modules (VASS marking analysis,
    /// Dialectica contract checking, and no-aliasing proof) into the oracle
    /// pipeline. Call after a lab run with the marking events projected from
    /// the runtime trace.
    ///
    /// Returns a list of violations from all three validators combined.
    /// An empty list means all obligation-theory invariants held.
    #[must_use]
    pub fn check_obligation_theory(
        &self,
        marking_events: &[MarkingEvent],
    ) -> Vec<ObligationTheoryViolation> {
        let mut violations = Vec::new();

        // VASS marking analysis: verify zero-marking at region close.
        let mut marking_analyzer = MarkingAnalyzer::new();
        let marking_result = marking_analyzer.analyze(marking_events);
        if !marking_result.is_safe() {
            for leak in &marking_result.leaks {
                violations.push(ObligationTheoryViolation::MarkingLeak {
                    description: format!("VASS marking non-zero at region close: {leak:?}"),
                });
            }
            for invalid in &marking_result.invalid_transitions {
                violations.push(ObligationTheoryViolation::InvalidTransition {
                    description: format!("Invalid marking transition: {invalid:?}"),
                });
            }
        }

        // Dialectica contract checking: verify exhaustive resolution,
        // no partial commit, region closure safety, cancellation
        // non-cascading, and kind-uniform state machine.
        let mut contract_checker = ContractChecker::new();
        let contract_result = contract_checker.check(marking_events);
        for violation in &contract_result.violations {
            violations.push(ObligationTheoryViolation::ContractViolation {
                description: format!("{violation:?}"),
            });
        }

        // No-aliasing proof: verify single-ownership invariant.
        let mut aliasing_prover = NoAliasingProver::new();
        let aliasing_result = aliasing_prover.check(marking_events);
        for counterexample in &aliasing_result.counterexamples {
            violations.push(ObligationTheoryViolation::AliasingViolation {
                description: format!("{counterexample:?}"),
            });
        }

        violations
    }
}

/// A violation detected by the obligation theory validators
/// (marking analysis, Dialectica contracts, no-aliasing proof).
#[derive(Debug, Clone)]
pub enum ObligationTheoryViolation {
    /// VASS marking was non-zero at region close (obligation leak).
    MarkingLeak {
        /// Human-readable description of the marking leak.
        description: String,
    },
    /// Invalid state transition in the obligation state machine.
    InvalidTransition {
        /// Human-readable description of the invalid transition.
        description: String,
    },
    /// Dialectica contract violation (exhaustive resolution, etc.).
    ContractViolation {
        /// Human-readable description of the contract violation.
        description: String,
    },
    /// Single-ownership (no-aliasing) invariant violated.
    AliasingViolation {
        /// Human-readable description of the aliasing violation.
        description: String,
    },
}

impl std::fmt::Display for ObligationTheoryViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MarkingLeak { description } => write!(f, "Marking leak: {description}"),
            Self::InvalidTransition { description } => {
                write!(f, "Invalid transition: {description}")
            }
            Self::ContractViolation { description } => {
                write!(f, "Contract violation: {description}")
            }
            Self::AliasingViolation { description } => {
                write!(f, "Aliasing violation: {description}")
            }
        }
    }
}

/// Per-oracle statistics snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OracleStats {
    /// Number of entities (tasks, regions, actors, etc.) tracked by this oracle.
    pub entities_tracked: usize,
    /// Number of events (spawns, stops, closes, etc.) recorded.
    pub events_recorded: usize,
}

/// Report for a single oracle within the unified report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleEntryReport {
    /// Oracle invariant name (e.g., "task_leak", "quiescence").
    pub invariant: String,
    /// Whether this oracle passed (no violations).
    pub passed: bool,
    /// Violation description, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub violation: Option<String>,
    /// Statistics for this oracle.
    pub stats: OracleStats,
}

impl OracleEntryReport {
    fn from_result(
        invariant: &'static str,
        violation: Option<OracleViolation>,
        stats: OracleStats,
    ) -> Self {
        let passed = violation.is_none();
        let violation_text = violation.map(|violation| violation.to_string());
        crate::tracing_compat::info!(
            event = "oracle_check",
            invariant = invariant,
            passed,
            entities_tracked = stats.entities_tracked,
            events_recorded = stats.events_recorded,
            details = violation_text.as_deref().unwrap_or("clean"),
            "oracle_check"
        );

        Self {
            invariant: invariant.to_owned(),
            passed,
            violation: violation_text,
            stats,
        }
    }
}

/// Common adapter for oracles that can emit a single report row.
pub trait Oracle {
    /// Stable invariant name used in reports, coverage, and evidence ledgers.
    fn invariant_name(&self) -> &'static str;

    /// The current violation, if any.
    fn violation(&self) -> Option<OracleViolation>;

    /// Snapshot statistics for the oracle.
    fn stats(&self) -> OracleStats;

    /// Convert the oracle into a report row.
    fn report_entry(&self) -> OracleEntryReport {
        OracleEntryReport::from_result(self.invariant_name(), self.violation(), self.stats())
    }
}

/// Unified oracle report covering all oracles with per-oracle status and statistics.
///
/// Produced by [`OracleSuite::report()`]. Serializable to JSON for artifact storage
/// and renderable as human-readable text.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleReport {
    /// Per-oracle entries in a stable order.
    pub entries: Vec<OracleEntryReport>,
    /// Total number of oracles checked.
    pub total: usize,
    /// Number of oracles that passed.
    pub passed: usize,
    /// Number of oracles that failed (had violations).
    pub failed: usize,
    /// The time (nanoseconds) at which the check was performed.
    pub check_time_nanos: u64,
}

impl OracleReport {
    /// Returns true if all oracles passed.
    #[must_use]
    pub fn all_passed(&self) -> bool {
        self.failed == 0
    }

    /// Returns entries that failed.
    #[must_use]
    pub fn failures(&self) -> Vec<&OracleEntryReport> {
        self.entries.iter().filter(|e| !e.passed).collect()
    }

    /// Returns the entry for a specific invariant.
    #[must_use]
    pub fn entry(&self, invariant: &str) -> Option<&OracleEntryReport> {
        self.entries
            .iter()
            .find(|e| e.invariant.as_str() == invariant)
    }

    /// Serializes the report to JSON.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }

    /// Renders the report as human-readable text.
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            &mut out,
            "Oracle Report: {}/{} passed ({} failed)",
            self.passed, self.total, self.failed
        );
        let _ = writeln!(&mut out, "Check time: {}ns", self.check_time_nanos);
        let _ = writeln!(&mut out, "---");
        for entry in &self.entries {
            let status = if entry.passed { "PASS" } else { "FAIL" };
            let _ = write!(
                &mut out,
                "[{}] {} (tracked={}, events={})",
                status, entry.invariant, entry.stats.entities_tracked, entry.stats.events_recorded
            );
            if let Some(ref v) = entry.violation {
                let _ = write!(&mut out, " -- {v}");
            } else if entry.stats.entities_tracked == 0 && entry.stats.events_recorded == 0 {
                // A pass with nothing observed checked nothing; most such
                // oracles are ones LabRuntime does not feed
                // (OracleRegistry::is_fed_by_lab_runtime, br-asupersync-52hxjz).
                let _ = write!(&mut out, " -- checked nothing: no events");
            }
            let _ = writeln!(&mut out);
        }
        out
    }
}

#[cfg(test)]
#[path = "mod_inline_tests.rs"]
mod tests;
