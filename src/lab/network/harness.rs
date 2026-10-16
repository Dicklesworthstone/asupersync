//! Deterministic distributed test harness.
//!
//! Bridges the [`DeterministicNetwork`] with the remote execution model to
//! enable deterministic, reproducible testing of distributed structured
//! concurrency under controlled failure conditions.
//!
//! # Architecture
//!
//! ```text
//!  ┌────────────┐    ┌────────────┐    ┌────────────┐
//!  │  SimNode A  │    │  SimNode B  │    │  SimNode C  │
//!  │  (inbox)    │←──→│  (inbox)    │←──→│  (inbox)    │
//!  └──────┬─────┘    └──────┬─────┘    └──────┬─────┘
//!         │                 │                 │
//!         └─────────────────┼─────────────────┘
//!                           │
//!                  ┌────────┴────────┐
//!                  │DeterministicNet │
//!                  │ (deterministic)  │
//!                  └─────────────────┘
//! ```
//!
//! Each [`SimNode`] processes incoming remote messages (spawn requests,
//! acks, cancellations, result deliveries, lease renewals) and generates
//! outgoing messages. The harness drives the network simulation and
//! message dispatch.
//!
//! # Fault Scenarios
//!
//! The harness supports composable fault scenarios via [`FaultScript`]:
//!
//! ```text
//! at(100ms) → Partition(A, B)
//! at(500ms) → Heal(A, B)
//! at(200ms) → CrashNode(C)
//! at(800ms) → RestartNode(C)
//! at(300ms) → ExpireLeases(A)
//! ```

use super::network::MAX_DUPLICATE_PACKET_DELAY;
use crate::bytes::Bytes;
use crate::lab::network::{DeterministicNetwork, Fault, HostId, NetworkConfig};
use crate::remote::{
    CancelRequest, IdempotencyKey, IdempotencyRequestFingerprint, IdempotencyStore, LeaseRenewal,
    MessageEnvelope, NodeId, RemoteCap, RemoteError, RemoteMessage, RemoteOutcome, RemoteRuntime,
    RemoteTaskId, RemoteTaskState, ResultDelivery, SpawnAck, SpawnAckStatus, SpawnRejectReason,
    SpawnRequest,
};
use crate::trace::distributed::{CausalTracker, LogicalTime, VectorClock};
use crate::types::{RegionId, TaskId, Time};
use parking_lot::Mutex;
use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug)]
struct PendingResultEntry {
    tx: Option<crate::channel::oneshot::Sender<Result<RemoteOutcome, RemoteError>>>,
    state: RemoteTaskState,
}

type PendingResultsMap = BTreeMap<RemoteTaskId, PendingResultEntry>;
type SharedPendingResults = Arc<Mutex<PendingResultsMap>>;

#[inline]
const fn harness_origin_region() -> RegionId {
    RegionId::from_arena(crate::util::ArenaIndex::new(0, 1))
}

#[inline]
const fn harness_origin_task() -> TaskId {
    TaskId::testing_default()
}

#[derive(Clone, Debug)]
struct StoredEnvelope {
    envelope: MessageEnvelope<RemoteMessage>,
    retain_until: Option<Duration>,
}

/// A virtual runtime bridge for testing distributed logic.
#[derive(Debug)]
pub struct VirtualNetworkRuntime {
    local_node: NodeId,
    outbox: Arc<Mutex<VecDeque<(NodeId, RemoteMessage)>>>,
    pending_results: SharedPendingResults,
}

impl RemoteRuntime for VirtualNetworkRuntime {
    fn send_message(
        &self,
        destination: &NodeId,
        envelope: MessageEnvelope<RemoteMessage>,
    ) -> Result<(), RemoteError> {
        // SECURITY: Validate sender identity to prevent node impersonation attacks.
        // The harness owns sender identity per SimNode. Verify the origin_node matches
        // this runtime's local_node to prevent spoofing attacks.
        let message = match envelope.payload {
            RemoteMessage::SpawnRequest(mut req) => {
                // Security check: origin_node must match runtime's identity
                if req.origin_node.as_str() != "" && req.origin_node != self.local_node {
                    return Err(RemoteError::TransportError(format!(
                        "Identity spoofing detected: request origin_node {:?} does not match runtime's local_node {:?}",
                        req.origin_node, self.local_node
                    )));
                }
                req.origin_node = self.local_node.clone();
                RemoteMessage::SpawnRequest(req)
            }
            RemoteMessage::CancelRequest(mut cancel) => {
                // Security check: origin_node must match runtime's identity
                if cancel.origin_node.as_str() != "" && cancel.origin_node != self.local_node {
                    return Err(RemoteError::TransportError(format!(
                        "Identity spoofing detected: cancel origin_node {:?} does not match runtime's local_node {:?}",
                        cancel.origin_node, self.local_node
                    )));
                }
                cancel.origin_node = self.local_node.clone();
                RemoteMessage::CancelRequest(cancel)
            }
            other => other,
        };

        self.outbox.lock().push_back((destination.clone(), message));
        Ok(())
    }

    fn register_task(
        &self,
        task_id: RemoteTaskId,
        tx: crate::channel::oneshot::Sender<Result<RemoteOutcome, RemoteError>>,
    ) {
        let mut pending = self.pending_results.lock();
        pending.insert(
            task_id,
            PendingResultEntry {
                tx: Some(tx),
                state: RemoteTaskState::Pending,
            },
        );
    }

    fn observe_task_state(&self, task_id: RemoteTaskId) -> Option<RemoteTaskState> {
        let pending = self.pending_results.lock();
        pending.get(&task_id).map(|entry| entry.state)
    }

    fn clear_task_state(&self, task_id: RemoteTaskId) {
        let mut pending = self.pending_results.lock();
        pending.remove(&task_id);
    }

    fn unregister_task(&self, task_id: RemoteTaskId) {
        let mut pending = self.pending_results.lock();
        pending.remove(&task_id);
    }
}

/// A virtual node in the distributed test harness.
///
/// Each node maintains its own state: pending remote tasks, leases,
/// idempotency store, and causal tracker.
#[derive(Debug)]
pub struct SimNode {
    /// The node's logical identity.
    pub node_id: NodeId,
    /// The host ID in the deterministic virtual network.
    pub host_id: HostId,
    /// Outgoing messages awaiting send (from harness logic).
    outbox: VecDeque<(NodeId, RemoteMessage)>,
    /// Outgoing messages from application code (via VirtualNetworkRuntime).
    app_outbox: Arc<Mutex<VecDeque<(NodeId, RemoteMessage)>>>,
    /// Tasks currently running on this node.
    running_tasks: BTreeMap<RemoteTaskId, RunningTask>,
    /// Duplicate task IDs waiting on the canonical task's terminal result.
    duplicate_waiters: BTreeMap<RemoteTaskId, Vec<RemoteTaskId>>,
    /// Reverse lookup from duplicate task IDs to the canonical running task.
    duplicate_aliases: BTreeMap<RemoteTaskId, RemoteTaskId>,
    /// Pending results expected by local tasks (application code).
    pending_results: SharedPendingResults,
    /// Idempotency store for deduplication.
    dedup: IdempotencyStore,
    /// Causal tracker for vector clock metadata.
    causal: CausalTracker,
    /// Whether this node is crashed.
    crashed: bool,
    /// Node event log for assertions.
    event_log: Vec<NodeEvent>,
}

/// A task running on a virtual node.
#[derive(Debug, Clone)]
pub struct RunningTask {
    /// The remote task ID.
    pub task_id: RemoteTaskId,
    /// Idempotency key for deduplication.
    pub idempotency_key: IdempotencyKey,
    /// Origin node that spawned this task.
    pub origin: NodeId,
    /// Virtual work remaining (in time units).
    pub work_remaining: Duration,
    /// Whether a cancellation has been requested.
    pub cancel_requested: bool,
}

/// An event recorded in a node's local log.
#[derive(Debug, Clone)]
pub enum NodeEvent {
    /// Received a spawn request.
    SpawnReceived {
        /// Task id in the spawn request.
        task_id: RemoteTaskId,
        /// Originating node.
        from: NodeId,
    },
    /// Accepted a spawn request.
    SpawnAccepted {
        /// Task id that was accepted.
        task_id: RemoteTaskId,
    },
    /// Rejected a spawn request.
    SpawnRejected {
        /// Task id that was rejected.
        task_id: RemoteTaskId,
        /// Rejection reason.
        reason: SpawnRejectReason,
    },
    /// Task completed.
    TaskCompleted {
        /// Task id that completed.
        task_id: RemoteTaskId,
    },
    /// Task cancelled.
    TaskCancelled {
        /// Task id that was cancelled.
        task_id: RemoteTaskId,
    },
    /// Received a cancellation request.
    CancelReceived {
        /// Task id for the cancellation request.
        task_id: RemoteTaskId,
    },
    /// Received a lease renewal.
    LeaseRenewed {
        /// Task id for the lease renewal.
        task_id: RemoteTaskId,
    },
    /// Duplicate spawn detected.
    DuplicateSpawn {
        /// Task id that was duplicated.
        task_id: RemoteTaskId,
    },
    /// Node crashed.
    Crashed,
    /// Node restarted.
    Restarted,
}

impl SimNode {
    /// Creates a new virtual node.
    #[must_use]
    pub fn new(node_id: NodeId, host_id: HostId) -> Self {
        Self {
            causal: CausalTracker::new(node_id.clone()),
            node_id,
            host_id,
            outbox: VecDeque::new(),
            app_outbox: Arc::new(Mutex::new(VecDeque::new())),
            running_tasks: BTreeMap::new(),
            duplicate_waiters: BTreeMap::new(),
            duplicate_aliases: BTreeMap::new(),
            pending_results: Arc::new(Mutex::new(BTreeMap::new())),
            dedup: IdempotencyStore::new(Duration::from_mins(5)),
            crashed: false,
            event_log: Vec::new(),
        }
    }

    /// Creates a RemoteCap connected to this node.
    #[must_use]
    pub fn create_cap(&self) -> RemoteCap {
        let runtime = VirtualNetworkRuntime {
            local_node: self.node_id.clone(),
            outbox: self.app_outbox.clone(),
            pending_results: self.pending_results.clone(),
        };
        RemoteCap::new()
            .with_local_node(self.node_id.clone())
            .with_runtime(Arc::new(runtime))
    }

    /// Processes an incoming remote message with logical time metadata.
    pub fn handle_message(&mut self, envelope: MessageEnvelope<RemoteMessage>, now: Time) {
        if self.crashed {
            return; // Silently drop messages to crashed nodes
        }

        self.record_receive(&envelope.sender_time);

        match envelope.payload {
            RemoteMessage::SpawnRequest(req) => self.handle_spawn(req, now),
            RemoteMessage::SpawnAck(ack) => self.handle_spawn_ack(ack),
            RemoteMessage::CancelRequest(cancel) => self.handle_cancel(&cancel),
            RemoteMessage::ResultDelivery(result) => self.handle_result(result),
            RemoteMessage::LeaseRenewal(renewal) => self.handle_lease_renewal(&renewal),
        }
    }

    fn record_receive(&mut self, sender_time: &LogicalTime) {
        match sender_time {
            LogicalTime::Vector(clock) => self.causal.on_receive(clock),
            _ => {
                self.causal.record_local_event();
            }
        }
    }

    fn handle_spawn(&mut self, req: SpawnRequest, now: Time) {
        self.event_log.push(NodeEvent::SpawnReceived {
            task_id: req.remote_task_id,
            from: req.origin_node.clone(),
        });

        // Bulk-evict terminal records whose retention window elapsed. Live
        // operations remain resident regardless of age.
        let _ = self.dedup.evict_expired(now);

        // Decide and reserve new keys in one store operation so no second
        // caller can observe a gap between the check and insertion.
        let request = IdempotencyRequestFingerprint::from_spawn_request(&req);
        let dedup =
            self.dedup
                .check_and_record(req.idempotency_key, req.remote_task_id, request, now);
        match dedup {
            crate::remote::DedupDecision::Duplicate(record) => {
                if record.outcome.is_none() {
                    self.register_duplicate_alias(record.remote_task_id, req.remote_task_id);
                }
                self.event_log.push(NodeEvent::DuplicateSpawn {
                    task_id: req.remote_task_id,
                });
                self.outbox.push_back((
                    req.origin_node.clone(),
                    RemoteMessage::SpawnAck(SpawnAck {
                        // Retries may carry a fresh correlation ID while
                        // reusing the same idempotency key. Echo the current
                        // request ID so the caller can match the cached reply
                        // to its live handle.
                        remote_task_id: req.remote_task_id,
                        status: SpawnAckStatus::Accepted,
                        assigned_node: self.node_id.clone(),
                    }),
                ));
                if let Some(outcome) = record.outcome.clone() {
                    self.outbox.push_back((
                        req.origin_node,
                        RemoteMessage::ResultDelivery(ResultDelivery {
                            remote_task_id: req.remote_task_id,
                            outcome,
                            execution_time: Duration::ZERO,
                        }),
                    ));
                }
                return;
            }
            crate::remote::DedupDecision::Conflict => {
                self.outbox.push_back((
                    req.origin_node.clone(),
                    RemoteMessage::SpawnAck(SpawnAck {
                        remote_task_id: req.remote_task_id,
                        status: SpawnAckStatus::Rejected(SpawnRejectReason::IdempotencyConflict),
                        assigned_node: self.node_id.clone(),
                    }),
                ));
                self.event_log.push(NodeEvent::SpawnRejected {
                    task_id: req.remote_task_id,
                    reason: SpawnRejectReason::IdempotencyConflict,
                });
                return;
            }
            crate::remote::DedupDecision::New => {}
        }

        // Accept the spawn
        let task = RunningTask {
            task_id: req.remote_task_id,
            idempotency_key: req.idempotency_key,
            origin: req.origin_node.clone(),
            work_remaining: Duration::from_millis(100), // Default virtual work
            cancel_requested: false,
        };
        self.running_tasks.insert(req.remote_task_id, task);

        self.outbox.push_back((
            req.origin_node,
            RemoteMessage::SpawnAck(SpawnAck {
                remote_task_id: req.remote_task_id,
                status: SpawnAckStatus::Accepted,
                assigned_node: self.node_id.clone(),
            }),
        ));
        self.event_log.push(NodeEvent::SpawnAccepted {
            task_id: req.remote_task_id,
        });
    }

    fn handle_spawn_ack(&self, ack: SpawnAck) {
        let rejected = {
            let mut pending = self.pending_results.lock();
            pending
                .get_mut(&ack.remote_task_id)
                .and_then(|entry| match ack.status {
                    SpawnAckStatus::Accepted => {
                        if entry.state == RemoteTaskState::Pending {
                            entry.state = RemoteTaskState::Running;
                        }
                        None
                    }
                    SpawnAckStatus::Rejected(reason) => {
                        if entry.state != RemoteTaskState::Pending {
                            return None;
                        }
                        entry.state = RemoteTaskState::Failed;
                        entry.tx.take().map(|tx| (tx, reason))
                    }
                })
        };

        if let Some((tx, reason)) = rejected {
            // Result delivery is terminal harness bookkeeping, not
            // cancellable simulated task work.
            let _ = tx.send_blocking(Err(RemoteError::SpawnRejected(reason)));
        }
    }

    fn handle_cancel(&mut self, cancel: &CancelRequest) {
        self.event_log.push(NodeEvent::CancelReceived {
            task_id: cancel.remote_task_id,
        });

        let canonical_task_id = self.canonical_task_id(cancel.remote_task_id);
        if let Some(task) = self.running_tasks.get_mut(&canonical_task_id) {
            task.cancel_requested = true;
        }
    }

    fn handle_result(&self, result: ResultDelivery) {
        let ResultDelivery {
            remote_task_id,
            outcome,
            execution_time: _,
        } = result;

        let tx = {
            let mut pending = self.pending_results.lock();
            pending.get_mut(&remote_task_id).and_then(|entry| {
                let tx = entry.tx.take()?;
                entry.state = match &outcome {
                    RemoteOutcome::Success(_) => RemoteTaskState::Completed,
                    RemoteOutcome::Cancelled(_) => RemoteTaskState::Cancelled,
                    RemoteOutcome::Failed(_) | RemoteOutcome::Panicked(_) => {
                        RemoteTaskState::Failed
                    }
                };
                Some(tx)
            })
        };

        if let Some(tx) = tx {
            if tx.send_blocking(Ok(outcome)).is_err() {
                self.pending_results.lock().remove(&remote_task_id);
            }
        }
    }

    fn handle_lease_renewal(&mut self, renewal: &LeaseRenewal) {
        self.event_log.push(NodeEvent::LeaseRenewed {
            task_id: renewal.remote_task_id,
        });
    }

    /// Advances virtual work on all running tasks by the given duration.
    /// Returns completed or cancelled tasks that need result delivery.
    pub fn tick(&mut self, elapsed: Duration, now: Time) -> Vec<(NodeId, RemoteMessage)> {
        if self.crashed {
            return Vec::new();
        }

        let mut completed = Vec::new();
        let mut finalized = Vec::new();
        let mut to_remove = Vec::new();

        for (id, task) in &mut self.running_tasks {
            if task.cancel_requested {
                let outcome =
                    RemoteOutcome::Cancelled(crate::types::CancelReason::user("harness cancel"));
                let _ = self
                    .dedup
                    .complete(&task.idempotency_key, *id, outcome.clone(), now);
                finalized.push((*id, task.origin.clone(), outcome));
                self.event_log
                    .push(NodeEvent::TaskCancelled { task_id: *id });
                to_remove.push(*id);
            } else if task.work_remaining <= elapsed {
                let outcome = RemoteOutcome::Success(vec![]);
                let _ = self
                    .dedup
                    .complete(&task.idempotency_key, *id, outcome.clone(), now);
                finalized.push((*id, task.origin.clone(), outcome));
                self.event_log
                    .push(NodeEvent::TaskCompleted { task_id: *id });
                to_remove.push(*id);
            } else {
                task.work_remaining -= elapsed;
            }
        }

        for (task_id, origin, outcome) in finalized {
            completed.push((
                origin.clone(),
                RemoteMessage::ResultDelivery(ResultDelivery {
                    remote_task_id: task_id,
                    outcome: outcome.clone(),
                    execution_time: Duration::ZERO,
                }),
            ));
            for duplicate_task_id in self.take_duplicate_waiters(task_id) {
                completed.push((
                    origin.clone(),
                    RemoteMessage::ResultDelivery(ResultDelivery {
                        remote_task_id: duplicate_task_id,
                        outcome: outcome.clone(),
                        execution_time: Duration::ZERO,
                    }),
                ));
            }
        }

        for id in to_remove {
            self.running_tasks.remove(&id);
        }

        completed
    }

    /// Applies a node crash: drops all running tasks.
    pub fn crash(&mut self) {
        self.crashed = true;
        self.running_tasks.clear();
        self.duplicate_waiters.clear();
        self.duplicate_aliases.clear();
        self.outbox.clear();
        {
            let mut app = self.app_outbox.lock();
            app.clear();
        }
        self.event_log.push(NodeEvent::Crashed);
    }

    /// Applies a node restart: clears crash flag, starts fresh.
    pub fn restart(&mut self) {
        self.crashed = false;
        self.duplicate_waiters.clear();
        self.duplicate_aliases.clear();
        self.dedup = IdempotencyStore::new(Duration::from_mins(5));
        self.event_log.push(NodeEvent::Restarted);
    }

    fn register_duplicate_alias(
        &mut self,
        canonical_task_id: RemoteTaskId,
        duplicate_task_id: RemoteTaskId,
    ) {
        if canonical_task_id == duplicate_task_id {
            return;
        }

        let waiters = self.duplicate_waiters.entry(canonical_task_id).or_default();
        if !waiters.contains(&duplicate_task_id) {
            waiters.push(duplicate_task_id);
        }
        self.duplicate_aliases
            .insert(duplicate_task_id, canonical_task_id);
    }

    fn canonical_task_id(&self, task_id: RemoteTaskId) -> RemoteTaskId {
        self.duplicate_aliases
            .get(&task_id)
            .copied()
            .unwrap_or(task_id)
    }

    fn take_duplicate_waiters(&mut self, canonical_task_id: RemoteTaskId) -> Vec<RemoteTaskId> {
        let waiters = self
            .duplicate_waiters
            .remove(&canonical_task_id)
            .unwrap_or_default();
        for duplicate_task_id in &waiters {
            self.duplicate_aliases.remove(duplicate_task_id);
        }
        waiters
    }

    /// Returns the event log for assertions.
    #[must_use]
    pub fn events(&self) -> &[NodeEvent] {
        &self.event_log
    }

    /// Returns the number of currently running tasks.
    #[must_use]
    pub fn running_task_count(&self) -> usize {
        self.running_tasks.len()
    }

    /// Returns the causal tracker for this node.
    #[must_use]
    pub fn causal_tracker(&self) -> &CausalTracker {
        &self.causal
    }

    /// Drains the outbox, returning all pending messages.
    pub fn drain_outbox(&mut self) -> Vec<(NodeId, RemoteMessage)> {
        let mut msgs: Vec<_> = self.outbox.drain(..).collect();
        {
            let mut app = self.app_outbox.lock();
            msgs.extend(app.drain(..));
        }
        msgs
    }
}

/// A scripted fault injection event.
#[derive(Clone, Debug)]
pub struct FaultEvent {
    /// When to inject the fault (relative to simulation start).
    pub at: Duration,
    /// The fault to inject.
    pub fault: HarnessFault,
}

/// Faults that the harness can inject.
#[derive(Clone, Debug)]
pub enum HarnessFault {
    /// Network-level fault (partition, heal, crash, restart).
    Network(Fault),
    /// Crash a specific node by its logical NodeId.
    CrashNode(NodeId),
    /// Restart a specific node by its logical NodeId.
    RestartNode(NodeId),
    /// Force-expire all leases on a node.
    ExpireLeases(NodeId),
}

/// A script of fault events, sorted by time.
#[derive(Clone, Debug, Default)]
pub struct FaultScript {
    events: Vec<FaultEvent>,
}

impl FaultScript {
    /// Creates an empty fault script.
    #[must_use]
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    /// Adds a fault at the given time offset.
    #[must_use]
    pub fn at(mut self, offset: Duration, fault: HarnessFault) -> Self {
        self.events.push(FaultEvent { at: offset, fault });
        self
    }

    /// Returns fault events sorted by time.
    #[must_use]
    pub fn sorted_events(&self) -> Vec<&FaultEvent> {
        let mut sorted: Vec<_> = self.events.iter().collect();
        sorted.sort_by_key(|e| e.at);
        sorted
    }
}

/// The distributed test harness.
///
/// Orchestrates the deterministic virtual network, nodes, and fault script to run
/// deterministic distributed tests.
pub struct DistributedHarness {
    /// The underlying deterministic virtual network.
    network: DeterministicNetwork,
    /// Nodes indexed by their logical NodeId.
    nodes: BTreeMap<NodeId, SimNode>,
    /// Mapping from NodeId to HostId.
    node_to_host: BTreeMap<NodeId, HostId>,
    /// Mapping from HostId to NodeId.
    host_to_node: BTreeMap<HostId, NodeId>,
    /// Fault script to execute.
    fault_script: FaultScript,
    /// Current simulation time.
    sim_time: Duration,
    /// Tick resolution for the simulation.
    tick: Duration,
    /// Execution trace for debugging.
    trace: Vec<HarnessTraceEvent>,
    /// Next message id for the harness-local side-channel codec.
    next_msg_id: u64,
    /// Harness-local message store for side-channel decoding.
    msg_store: BTreeMap<u64, StoredEnvelope>,
}

/// A trace event in the harness execution.
#[derive(Clone, Debug)]
pub struct HarnessTraceEvent {
    /// When this event occurred.
    pub time: Duration,
    /// What happened.
    pub kind: HarnessTraceKind,
}

/// Types of harness trace events.
#[derive(Clone, Debug)]
pub enum HarnessTraceKind {
    /// A message was sent between nodes.
    MessageSent {
        /// Sender node.
        from: NodeId,
        /// Recipient node.
        to: NodeId,
        /// Message type label.
        msg_type: String,
    },
    /// A message was delivered.
    MessageDelivered {
        /// Sender node.
        from: NodeId,
        /// Recipient node.
        to: NodeId,
        /// Message type label.
        msg_type: String,
    },
    /// A fault was injected.
    FaultInjected(String),
    /// A task completed on a node.
    TaskCompleted {
        /// Node that completed the task.
        node: NodeId,
        /// Completed task id.
        task_id: RemoteTaskId,
    },
}

impl DistributedHarness {
    /// Creates a new harness with the given network configuration.
    #[must_use]
    pub fn new(config: NetworkConfig) -> Self {
        let tick = normalized_tick(config.tick_resolution);
        Self {
            network: DeterministicNetwork::new(config),
            nodes: BTreeMap::new(),
            node_to_host: BTreeMap::new(),
            host_to_node: BTreeMap::new(),
            fault_script: FaultScript::new(),
            sim_time: Duration::ZERO,
            tick,
            trace: Vec::new(),
            next_msg_id: 1,
            msg_store: BTreeMap::new(),
        }
    }

    /// Adds a node to the harness. Returns the HostId for network-level operations.
    pub fn add_node(&mut self, name: &str) -> NodeId {
        let node_id = NodeId::new(name);
        let host_id = self.network.add_host(name);
        let sim_node = SimNode::new(node_id.clone(), host_id);
        self.nodes.insert(node_id.clone(), sim_node);
        self.node_to_host.insert(node_id.clone(), host_id);
        self.host_to_node.insert(host_id, node_id.clone());
        node_id
    }

    /// Sets the fault script.
    pub fn set_fault_script(&mut self, script: FaultScript) {
        self.fault_script = script;
    }

    /// Sets the tick resolution.
    pub fn set_tick(&mut self, tick: Duration) {
        self.tick = normalized_tick(tick);
    }

    /// Injects a spawn request from `origin` to `target`.
    pub fn inject_spawn(&mut self, origin: &NodeId, target: &NodeId, task_id: RemoteTaskId) {
        let req = SpawnRequest {
            remote_task_id: task_id,
            computation: crate::remote::ComputationName::new("test-computation"),
            input: crate::remote::RemoteInput::new(vec![]),
            lease: Duration::from_secs(30),
            idempotency_key: IdempotencyKey::from_raw(u128::from(task_id.raw())),
            budget: None,
            origin_node: origin.clone(),
            origin_region: harness_origin_region(),
            origin_task: harness_origin_task(),
        };

        let msg = RemoteMessage::SpawnRequest(req);
        self.send_message(origin, target, &msg);
    }

    /// Injects a cancel request from `origin` to `target`.
    pub fn inject_cancel(&mut self, origin: &NodeId, target: &NodeId, task_id: RemoteTaskId) {
        let cancel = CancelRequest {
            remote_task_id: task_id,
            reason: crate::types::CancelReason::user("harness cancel"),
            origin_node: origin.clone(),
        };
        let msg = RemoteMessage::CancelRequest(cancel);
        self.send_message(origin, target, &msg);
    }

    /// Sends a remote message between nodes via the deterministic virtual network.
    fn send_message(&mut self, from: &NodeId, to: &NodeId, msg: &RemoteMessage) {
        let src = self.node_to_host[from];
        let Some(&dst) = self.node_to_host.get(to) else {
            if let RemoteMessage::SpawnRequest(req) = msg {
                let tx = if let Some(node) = self.nodes.get_mut(from) {
                    let mut pending = node.pending_results.lock();
                    pending.get_mut(&req.remote_task_id).and_then(|entry| {
                        entry.state = RemoteTaskState::Failed;
                        entry.tx.take()
                    })
                } else {
                    None
                };
                if let Some(tx) = tx {
                    let _ =
                        tx.send_blocking(Err(RemoteError::NodeUnreachable(to.as_str().to_owned())));
                }
            }
            return;
        };

        let msg_type = msg_type_name(msg);
        self.trace.push(HarnessTraceEvent {
            time: self.sim_time,
            kind: HarnessTraceKind::MessageSent {
                from: from.clone(),
                to: to.clone(),
                msg_type: msg_type.to_string(),
            },
        });

        let sender_time = self.nodes.get_mut(from).map_or_else(
            || LogicalTime::Vector(VectorClock::new()),
            |node| LogicalTime::Vector(node.causal.on_send()),
        );
        let envelope = MessageEnvelope::new(from.clone(), sender_time, msg.clone());

        // Serialize message as opaque bytes for the deterministic virtual network.
        // In Phase 0, we use a simple encoding: message type tag + task ID.
        let encoded = self.encode_message(&envelope);
        self.network.send(src, dst, Bytes::from(encoded));
    }

    /// Runs the simulation for the given duration.
    ///
    /// This advances the deterministic virtual network, delivers messages, processes
    /// node logic, and executes fault scripts.
    pub fn run_for(&mut self, duration: Duration) {
        let target = self.sim_time.saturating_add(duration);
        let fault_events: Vec<FaultEvent> = self
            .fault_script
            .sorted_events()
            .into_iter()
            .cloned()
            .collect();
        let mut next_fault = 0;

        while self.sim_time < target {
            while fault_events
                .get(next_fault)
                .is_some_and(|fe| fe.at < self.sim_time)
            {
                next_fault += 1;
            }

            let step_end = self.sim_time.saturating_add(self.tick).min(target);
            let next_stop = fault_events
                .get(next_fault)
                .filter(|fe| fe.at < step_end)
                .map_or(step_end, |fe| fe.at);

            if next_stop > self.sim_time {
                self.advance_segment(next_stop.saturating_sub(self.sim_time));
            }

            while let Some(fe) = fault_events.get(next_fault) {
                if fe.at != self.sim_time || fe.at >= target {
                    break;
                }
                self.execute_fault(&fe.fault);
                next_fault += 1;
            }
        }
    }

    fn logical_now(&self) -> Time {
        let nanos = self.sim_time.as_nanos().min(u128::from(u64::MAX)) as u64;
        Time::from_nanos(nanos)
    }

    /// Delivers packets from the deterministic virtual network to the appropriate nodes.
    fn deliver_packets(&mut self) {
        // Phase 1: Drain raw payloads without borrowing `self.nodes` and
        // `self.network` in conflicting ways.
        let mut raw_payloads: Vec<(NodeId, Bytes)> = Vec::new();
        let node_hosts: Vec<(NodeId, HostId)> = self
            .nodes
            .iter()
            .map(|(node_id, node)| (node_id.clone(), node.host_id))
            .collect();
        for (node_id, host_id) in node_hosts {
            if let Some(packets) = self.network.take_inbox(host_id) {
                for packet in packets {
                    raw_payloads.push((node_id.clone(), packet.payload));
                }
            }
        }

        // Phase 2: Decode payloads (needs &mut self for msg_store).
        let mut deliveries: Vec<(NodeId, MessageEnvelope<RemoteMessage>)> = Vec::new();
        for (node_id, payload) in raw_payloads {
            if let Some(envelope) = self.decode_message(&payload) {
                let src_node = envelope.sender.clone();
                self.trace.push(HarnessTraceEvent {
                    time: self.sim_time,
                    kind: HarnessTraceKind::MessageDelivered {
                        from: src_node,
                        to: node_id.clone(),
                        msg_type: msg_type_name(&envelope.payload).to_string(),
                    },
                });
                deliveries.push((node_id, envelope));
            }
        }

        let now = self.logical_now();
        for (node_id, envelope) in deliveries {
            if let Some(node) = self.nodes.get_mut(&node_id) {
                node.handle_message(envelope, now);
            }
        }
    }

    /// Ticks all nodes and collects result deliveries.
    fn tick_nodes(&mut self, elapsed: Duration) {
        let mut result_messages: Vec<(NodeId, NodeId, RemoteMessage)> = Vec::new();
        let now = self.logical_now();

        for (node_id, node) in &mut self.nodes {
            let completed = node.tick(elapsed, now);
            for (dest, msg) in completed {
                if let RemoteMessage::ResultDelivery(ref rd) = msg {
                    self.trace.push(HarnessTraceEvent {
                        time: self.sim_time,
                        kind: HarnessTraceKind::TaskCompleted {
                            node: node_id.clone(),
                            task_id: rd.remote_task_id,
                        },
                    });
                }
                result_messages.push((node_id.clone(), dest, msg));
            }
        }

        for (from, to, msg) in result_messages {
            self.send_message(&from, &to, &msg);
        }
    }

    // -----------------------------------------------------------------------
    // Simple message encoding/decoding for the deterministic virtual network.
    // -----------------------------------------------------------------------

    fn encode_message(&mut self, msg: &MessageEnvelope<RemoteMessage>) -> Vec<u8> {
        let id = self.next_msg_id;
        self.next_msg_id = self.next_msg_id.wrapping_add(1);
        self.msg_store.insert(
            id,
            StoredEnvelope {
                envelope: msg.clone(),
                retain_until: None,
            },
        );
        id.to_le_bytes().to_vec()
    }

    fn decode_message(&mut self, payload: &Bytes) -> Option<MessageEnvelope<RemoteMessage>> {
        if payload.len() < 8 {
            return None;
        }
        let id = u64::from_le_bytes(payload[..8].try_into().ok()?);
        let stored = self.msg_store.get_mut(&id)?;
        if stored.retain_until.is_none() {
            stored.retain_until = Some(self.sim_time.saturating_add(MAX_DUPLICATE_PACKET_DELAY));
        }
        Some(stored.envelope.clone())
    }

    fn prune_decoded_messages(&mut self) {
        let now = self.sim_time;
        self.msg_store.retain(|_, stored| {
            stored
                .retain_until
                .is_none_or(|retain_until| now <= retain_until)
        });
    }

    fn advance_segment(&mut self, elapsed: Duration) {
        if elapsed.is_zero() {
            return;
        }

        self.network.run_for(elapsed);
        self.sim_time = self.sim_time.saturating_add(elapsed);
        self.deliver_packets();
        self.tick_nodes(elapsed);
        self.flush_outboxes();
        self.prune_decoded_messages();
    }

    /// Flushes outgoing messages from all nodes.
    fn flush_outboxes(&mut self) {
        let mut outgoing: Vec<(NodeId, NodeId, RemoteMessage)> = Vec::new();

        for (node_id, node) in &mut self.nodes {
            for (dest, msg) in node.drain_outbox() {
                outgoing.push((node_id.clone(), dest, msg));
            }
        }

        for (from, to, msg) in outgoing {
            self.send_message(&from, &to, &msg);
        }
    }

    /// Executes a fault against the harness.
    fn execute_fault(&mut self, fault: &HarnessFault) {
        let now = self.logical_now();
        self.trace.push(HarnessTraceEvent {
            time: self.sim_time,
            kind: HarnessTraceKind::FaultInjected(format!("{fault:?}")),
        });

        match fault {
            HarnessFault::Network(net_fault) => {
                self.network.inject_fault(net_fault);
            }
            HarnessFault::CrashNode(node_id) => {
                if let Some(node) = self.nodes.get_mut(node_id) {
                    let host = node.host_id;
                    node.crash();
                    self.network.inject_fault(&Fault::HostCrash { host });
                }
            }
            HarnessFault::RestartNode(node_id) => {
                if let Some(node) = self.nodes.get_mut(node_id) {
                    let host = node.host_id;
                    node.restart();
                    self.network.inject_fault(&Fault::HostRestart { host });
                }
            }
            HarnessFault::ExpireLeases(node_id) => {
                // Clear all running tasks (models lease expiry)
                if let Some(node) = self.nodes.get_mut(node_id) {
                    let task_ids: Vec<RemoteTaskId> = node.running_tasks.keys().copied().collect();
                    for tid in task_ids {
                        if let Some(task) = node.running_tasks.remove(&tid) {
                            let outcome = RemoteOutcome::Failed("lease expired".into());
                            let _ = node.dedup.complete(
                                &task.idempotency_key,
                                tid,
                                outcome.clone(),
                                now,
                            );
                            node.outbox.push_back((
                                task.origin.clone(),
                                RemoteMessage::ResultDelivery(ResultDelivery {
                                    remote_task_id: tid,
                                    outcome: outcome.clone(),
                                    execution_time: Duration::ZERO,
                                }),
                            ));
                            for duplicate_task_id in node.take_duplicate_waiters(tid) {
                                node.outbox.push_back((
                                    task.origin.clone(),
                                    RemoteMessage::ResultDelivery(ResultDelivery {
                                        remote_task_id: duplicate_task_id,
                                        outcome: outcome.clone(),
                                        execution_time: Duration::ZERO,
                                    }),
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    /// Returns the node state for assertions.
    #[must_use]
    pub fn node(&self, node_id: &NodeId) -> Option<&SimNode> {
        self.nodes.get(node_id)
    }

    /// Returns the execution trace.
    #[must_use]
    pub fn trace(&self) -> &[HarnessTraceEvent] {
        &self.trace
    }

    /// Returns the network metrics.
    #[must_use]
    pub fn network_metrics(&self) -> &crate::lab::network::NetworkMetrics {
        self.network.metrics()
    }

    /// Returns the current simulation time.
    #[must_use]
    pub fn sim_time(&self) -> Duration {
        self.sim_time
    }
}

fn normalized_tick(tick: Duration) -> Duration {
    if tick.is_zero() {
        Duration::from_nanos(1)
    } else {
        tick
    }
}

impl fmt::Debug for DistributedHarness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DistributedHarness")
            .field("sim_time", &self.sim_time)
            .field("nodes", &self.nodes.keys().collect::<Vec<_>>())
            .field("trace_len", &self.trace.len())
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Simple message encoding/decoding for the deterministic virtual network.
// In Phase 0, we use a tag byte + task ID. Real transport would use
// a proper codec.
// ---------------------------------------------------------------------------

fn msg_type_name(msg: &RemoteMessage) -> &'static str {
    match msg {
        RemoteMessage::SpawnRequest(_) => "SpawnRequest",
        RemoteMessage::SpawnAck(_) => "SpawnAck",
        RemoteMessage::CancelRequest(_) => "CancelRequest",
        RemoteMessage::ResultDelivery(_) => "ResultDelivery",
        RemoteMessage::LeaseRenewal(_) => "LeaseRenewal",
    }
}

#[cfg(test)]
#[path = "harness_inline_tests.rs"]
mod tests;
