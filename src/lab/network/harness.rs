//! Deterministic distributed test harness.
//!
//! Bridges the [`SimulatedNetwork`] with the remote execution model to
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
//!                  │ SimulatedNetwork │
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

use crate::bytes::Bytes;
use crate::cx::Cx;
use crate::lab::network::{Fault, HostId, NetworkConfig, SimulatedNetwork};
use crate::remote::{
    CancelRequest, IdempotencyKey, IdempotencyStore, LeaseRenewal, MessageEnvelope, NodeId,
    RemoteCap, RemoteError, RemoteMessage, RemoteOutcome, RemoteRuntime, RemoteTaskId,
    ResultDelivery, SpawnAck, SpawnAckStatus, SpawnRejectReason, SpawnRequest,
};
use crate::trace::distributed::{CausalTracker, LogicalTime, VectorClock};
use crate::types::Time;
use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

type PendingResultsMap =
    BTreeMap<RemoteTaskId, crate::channel::oneshot::Sender<Result<RemoteOutcome, RemoteError>>>;
type SharedPendingResults = Arc<Mutex<PendingResultsMap>>;

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
        // The harness owns sender identity per SimNode. Rewrite protocol-origin fields so
        // reply routing uses this node's actual ID instead of placeholder defaults.
        let message = match envelope.payload {
            RemoteMessage::SpawnRequest(mut req) => {
                req.origin_node = self.local_node.clone();
                RemoteMessage::SpawnRequest(req)
            }
            RemoteMessage::CancelRequest(mut cancel) => {
                cancel.origin_node = self.local_node.clone();
                RemoteMessage::CancelRequest(cancel)
            }
            other => other,
        };

        self.outbox
            .lock()
            .unwrap()
            .push_back((destination.clone(), message));
        Ok(())
    }

    fn register_task(
        &self,
        task_id: RemoteTaskId,
        tx: crate::channel::oneshot::Sender<Result<RemoteOutcome, RemoteError>>,
    ) {
        let mut pending = self.pending_results.lock().unwrap();
        pending.insert(task_id, tx);
    }

    fn unregister_task(&self, task_id: RemoteTaskId) {
        let mut pending = self.pending_results.lock().unwrap();
        pending.remove(&task_id);
    }
}

/// A simulated node in the distributed test harness.
///
/// Each node maintains its own state: pending remote tasks, leases,
/// idempotency store, and causal tracker.
#[derive(Debug)]
pub struct SimNode {
    /// The node's logical identity.
    pub node_id: NodeId,
    /// The host ID in the simulated network.
    pub host_id: HostId,
    /// Outgoing messages awaiting send (from harness logic).
    outbox: VecDeque<(NodeId, RemoteMessage)>,
    /// Outgoing messages from application code (via VirtualNetworkRuntime).
    app_outbox: Arc<Mutex<VecDeque<(NodeId, RemoteMessage)>>>,
    /// Tasks currently running on this node.
    running_tasks: BTreeMap<RemoteTaskId, RunningTask>,
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

/// A task running on a simulated node.
#[derive(Debug, Clone)]
pub struct RunningTask {
    /// The remote task ID.
    pub task_id: RemoteTaskId,
    /// Idempotency key for deduplication.
    pub idempotency_key: IdempotencyKey,
    /// Origin node that spawned this task.
    pub origin: NodeId,
    /// Simulated work remaining (in time units).
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
    /// Creates a new simulated node.
    #[must_use]
    pub fn new(node_id: NodeId, host_id: HostId) -> Self {
        Self {
            causal: CausalTracker::new(node_id.clone()),
            node_id,
            host_id,
            outbox: VecDeque::new(),
            app_outbox: Arc::new(Mutex::new(VecDeque::new())),
            running_tasks: BTreeMap::new(),
            pending_results: Arc::new(Mutex::new(BTreeMap::new())),
            dedup: IdempotencyStore::new(Duration::from_secs(300)),
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
    pub fn handle_message(&mut self, envelope: MessageEnvelope<RemoteMessage>) {
        if self.crashed {
            return; // Silently drop messages to crashed nodes
        }

        self.record_receive(&envelope.sender_time);

        match envelope.payload {
            RemoteMessage::SpawnRequest(req) => self.handle_spawn(req),
            RemoteMessage::SpawnAck(ack) => Self::handle_spawn_ack(ack),
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

    fn handle_spawn(&mut self, req: SpawnRequest) {
        self.event_log.push(NodeEvent::SpawnReceived {
            task_id: req.remote_task_id,
            from: req.origin_node.clone(),
        });

        // Check idempotency
        let dedup = self.dedup.check(&req.idempotency_key, &req.computation);
        match dedup {
            crate::remote::DedupDecision::Duplicate(record) => {
                self.event_log.push(NodeEvent::DuplicateSpawn {
                    task_id: req.remote_task_id,
                });
                self.outbox.push_back((
                    req.origin_node.clone(),
                    RemoteMessage::SpawnAck(SpawnAck {
                        remote_task_id: record.remote_task_id,
                        status: SpawnAckStatus::Accepted,
                        assigned_node: self.node_id.clone(),
                    }),
                ));
                if let Some(outcome) = record.outcome.clone() {
                    self.outbox.push_back((
                        req.origin_node,
                        RemoteMessage::ResultDelivery(ResultDelivery {
                            remote_task_id: record.remote_task_id,
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

        // Record for idempotency
        self.dedup.record(
            req.idempotency_key,
            req.remote_task_id,
            req.computation.clone(),
            Time::ZERO,
        );

        // Accept the spawn
        let task = RunningTask {
            task_id: req.remote_task_id,
            idempotency_key: req.idempotency_key,
            origin: req.origin_node.clone(),
            work_remaining: Duration::from_millis(100), // Default simulated work
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

    fn handle_spawn_ack(_ack: SpawnAck) {
        // Origin node processes ack — in a full implementation this would
        // update the RemoteHandle state. For harness testing, we log only.
    }

    fn handle_cancel(&mut self, cancel: &CancelRequest) {
        self.event_log.push(NodeEvent::CancelReceived {
            task_id: cancel.remote_task_id,
        });

        if let Some(task) = self.running_tasks.get_mut(&cancel.remote_task_id) {
            task.cancel_requested = true;
        }
    }

    fn handle_result(&self, result: ResultDelivery) {
        // Deliver result to pending local task (application code)
        let mut pending = self.pending_results.lock().unwrap();
        if let Some(tx) = pending.remove(&result.remote_task_id) {
            let cx = Cx::for_testing();
            let _ = tx.send(&cx, Ok(result.outcome));
        }
    }

    fn handle_lease_renewal(&mut self, renewal: &LeaseRenewal) {
        self.event_log.push(NodeEvent::LeaseRenewed {
            task_id: renewal.remote_task_id,
        });
    }

    /// Advances simulated work on all running tasks by the given duration.
    /// Returns completed or cancelled tasks that need result delivery.
    pub fn tick(&mut self, elapsed: Duration) -> Vec<(NodeId, RemoteMessage)> {
        if self.crashed {
            return Vec::new();
        }

        let mut completed = Vec::new();
        let mut to_remove = Vec::new();

        for (id, task) in &mut self.running_tasks {
            if task.cancel_requested {
                let outcome =
                    RemoteOutcome::Cancelled(crate::types::CancelReason::user("harness cancel"));
                let _ = self.dedup.complete(&task.idempotency_key, outcome.clone());
                completed.push((
                    task.origin.clone(),
                    RemoteMessage::ResultDelivery(ResultDelivery {
                        remote_task_id: *id,
                        outcome,
                        execution_time: Duration::ZERO,
                    }),
                ));
                self.event_log
                    .push(NodeEvent::TaskCancelled { task_id: *id });
                to_remove.push(*id);
            } else if task.work_remaining <= elapsed {
                let outcome = RemoteOutcome::Success(vec![]);
                let _ = self.dedup.complete(&task.idempotency_key, outcome.clone());
                completed.push((
                    task.origin.clone(),
                    RemoteMessage::ResultDelivery(ResultDelivery {
                        remote_task_id: *id,
                        outcome,
                        execution_time: Duration::ZERO,
                    }),
                ));
                self.event_log
                    .push(NodeEvent::TaskCompleted { task_id: *id });
                to_remove.push(*id);
            } else {
                task.work_remaining -= elapsed;
            }
        }

        for id in to_remove {
            self.running_tasks.remove(&id);
        }

        completed
    }

    /// Simulates a node crash: drops all running tasks.
    pub fn crash(&mut self) {
        self.crashed = true;
        self.running_tasks.clear();
        self.outbox.clear();
        {
            let mut app = self.app_outbox.lock().unwrap();
            app.clear();
        }
        self.event_log.push(NodeEvent::Crashed);
    }

    /// Simulates a node restart: clears crash flag, starts fresh.
    pub fn restart(&mut self) {
        self.crashed = false;
        self.dedup = IdempotencyStore::new(Duration::from_secs(300));
        self.event_log.push(NodeEvent::Restarted);
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
            let mut app = self.app_outbox.lock().unwrap();
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
/// Orchestrates the simulated network, nodes, and fault script to run
/// deterministic distributed tests.
pub struct DistributedHarness {
    /// The underlying simulated network.
    network: SimulatedNetwork,
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
    msg_store: BTreeMap<u64, MessageEnvelope<RemoteMessage>>,
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
        Self {
            network: SimulatedNetwork::new(config),
            nodes: BTreeMap::new(),
            node_to_host: BTreeMap::new(),
            host_to_node: BTreeMap::new(),
            fault_script: FaultScript::new(),
            sim_time: Duration::ZERO,
            tick: Duration::from_millis(1),
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
        self.tick = tick;
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
            origin_region: crate::types::RegionId::new_for_test(0, 0),
            origin_task: crate::types::TaskId::new_for_test(0, 0),
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

    /// Sends a remote message between nodes via the simulated network.
    fn send_message(&mut self, from: &NodeId, to: &NodeId, msg: &RemoteMessage) {
        let src = self.node_to_host[from];
        let dst = self.node_to_host[to];

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

        // Serialize message as opaque bytes for the simulated network.
        // In Phase 0, we use a simple encoding: message type tag + task ID.
        let encoded = self.encode_message(&envelope);
        self.network.send(src, dst, Bytes::from(encoded));
    }

    /// Runs the simulation for the given duration.
    ///
    /// This advances the simulated network, delivers messages, processes
    /// node logic, and executes fault scripts.
    pub fn run_for(&mut self, duration: Duration) {
        let target = self.sim_time + duration;
        let fault_events: Vec<FaultEvent> = self.fault_script.events.clone();

        while self.sim_time < target {
            // Execute any faults at the current time.
            for fe in &fault_events {
                if fe.at >= self.sim_time && fe.at < self.sim_time + self.tick {
                    self.execute_fault(&fe.fault.clone());
                }
            }

            // Advance network simulation by one tick.
            self.network.run_for(self.tick);

            // Deliver packets from network to nodes.
            self.deliver_packets();

            // Tick all nodes (advance simulated work).
            self.tick_nodes();

            // Send outgoing messages from nodes.
            self.flush_outboxes();

            self.sim_time += self.tick;
        }
    }

    /// Delivers packets from the simulated network to the appropriate nodes.
    fn deliver_packets(&mut self) {
        // Phase 1: Collect raw payloads without borrowing &mut self.
        let mut raw_payloads: Vec<(NodeId, Bytes)> = Vec::new();
        for (node_id, node) in &self.nodes {
            if let Some(packets) = self.network.inbox(node.host_id) {
                for packet in packets {
                    raw_payloads.push((node_id.clone(), packet.payload.clone()));
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

        for (node_id, envelope) in deliveries {
            if let Some(node) = self.nodes.get_mut(&node_id) {
                node.handle_message(envelope);
            }
        }
    }

    /// Ticks all nodes and collects result deliveries.
    fn tick_nodes(&mut self) {
        let mut result_messages: Vec<(NodeId, NodeId, RemoteMessage)> = Vec::new();

        for (node_id, node) in &mut self.nodes {
            let completed = node.tick(self.tick);
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
    // Simple message encoding/decoding for the simulated network.
    // -----------------------------------------------------------------------

    fn encode_message(&mut self, msg: &MessageEnvelope<RemoteMessage>) -> Vec<u8> {
        let id = self.next_msg_id;
        self.next_msg_id = self.next_msg_id.wrapping_add(1);
        self.msg_store.insert(id, msg.clone());
        id.to_le_bytes().to_vec()
    }

    fn decode_message(&mut self, payload: &Bytes) -> Option<MessageEnvelope<RemoteMessage>> {
        if payload.len() < 8 {
            return None;
        }
        let id = u64::from_le_bytes(payload[..8].try_into().ok()?);
        self.msg_store.remove(&id)
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
                // Clear all running tasks (simulates lease expiry)
                if let Some(node) = self.nodes.get_mut(node_id) {
                    let task_ids: Vec<RemoteTaskId> = node.running_tasks.keys().copied().collect();
                    for tid in task_ids {
                        if let Some(task) = node.running_tasks.remove(&tid) {
                            let outcome = RemoteOutcome::Failed("lease expired".into());
                            let _ = node.dedup.complete(&task.idempotency_key, outcome.clone());
                            node.outbox.push_back((
                                task.origin,
                                RemoteMessage::ResultDelivery(ResultDelivery {
                                    remote_task_id: tid,
                                    outcome,
                                    execution_time: Duration::ZERO,
                                }),
                            ));
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
// Simple message encoding/decoding for the simulated network.
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
mod tests {
    use super::*;

    fn setup_harness() -> (DistributedHarness, NodeId, NodeId) {
        let config = NetworkConfig {
            default_conditions: crate::lab::network::NetworkConditions::local(),
            ..NetworkConfig::default()
        };
        let mut harness = DistributedHarness::new(config);
        let a = harness.add_node("node-a");
        let b = harness.add_node("node-b");
        (harness, a, b)
    }

    #[test]
    fn spawn_and_complete_across_nodes() {
        let (mut harness, a, b) = setup_harness();
        let task_id = RemoteTaskId::next();

        // A spawns a task on B
        harness.inject_spawn(&a, &b, task_id);

        // Run long enough for the message to arrive, task to execute, and result to return
        harness.run_for(Duration::from_millis(500));

        // B should have received and completed the spawn
        let node_b = harness.node(&b).unwrap();
        assert!(node_b
            .events()
            .iter()
            .any(|e| matches!(e, NodeEvent::SpawnReceived { .. })));
        assert!(node_b
            .events()
            .iter()
            .any(|e| matches!(e, NodeEvent::SpawnAccepted { .. })));
        assert!(node_b
            .events()
            .iter()
            .any(|e| matches!(e, NodeEvent::TaskCompleted { .. })));
    }

    #[test]
    fn duplicate_spawn_resends_ack() {
        let (mut harness, a, b) = setup_harness();
        let task_id = RemoteTaskId::next();

        harness.inject_spawn(&a, &b, task_id);
        harness.run_for(Duration::from_millis(10));

        harness.inject_spawn(&a, &b, task_id);
        harness.run_for(Duration::from_millis(10));

        let ack_count = harness
            .trace()
            .iter()
            .filter(|event| {
                matches!(
                    event,
                    HarnessTraceEvent {
                        kind: HarnessTraceKind::MessageSent { from, to, msg_type },
                        ..
                    } if from == &b && to == &a && msg_type == "SpawnAck"
                )
            })
            .count();
        assert!(ack_count >= 2);

        let node_b = harness.node(&b).unwrap();
        assert!(node_b
            .events()
            .iter()
            .any(|e| matches!(e, NodeEvent::DuplicateSpawn { .. })));
        assert_eq!(node_b.running_task_count(), 1);
    }

    #[test]
    fn duplicate_spawn_after_completion_resends_result() {
        let (mut harness, a, b) = setup_harness();
        let task_id = RemoteTaskId::next();

        harness.inject_spawn(&a, &b, task_id);
        harness.run_for(Duration::from_millis(300));

        harness.inject_spawn(&a, &b, task_id);
        harness.run_for(Duration::from_millis(20));

        let result_count = harness
            .trace()
            .iter()
            .filter(|event| {
                matches!(
                    event,
                    HarnessTraceEvent {
                        kind: HarnessTraceKind::MessageSent { from, to, msg_type },
                        ..
                    } if from == &b && to == &a && msg_type == "ResultDelivery"
                )
            })
            .count();
        assert!(result_count >= 2);
    }

    #[test]
    fn cancel_propagates() {
        let (mut harness, a, b) = setup_harness();
        let task_id = RemoteTaskId::next();

        // A spawns a task on B
        harness.inject_spawn(&a, &b, task_id);

        // Run briefly so the spawn arrives
        harness.run_for(Duration::from_millis(10));

        // A cancels the task
        harness.inject_cancel(&a, &b, task_id);

        // Run to let cancellation propagate
        harness.run_for(Duration::from_millis(200));

        let node_b = harness.node(&b).unwrap();
        assert!(node_b
            .events()
            .iter()
            .any(|e| matches!(e, NodeEvent::CancelReceived { .. })));
        assert!(node_b
            .events()
            .iter()
            .any(|e| matches!(e, NodeEvent::TaskCancelled { .. })));
    }

    #[test]
    fn partition_prevents_delivery() {
        let config = NetworkConfig {
            default_conditions: crate::lab::network::NetworkConditions::local(),
            ..NetworkConfig::default()
        };
        let mut harness = DistributedHarness::new(config);
        let a = harness.add_node("node-a");
        let b = harness.add_node("node-b");

        let host_a = harness.node(&a).unwrap().host_id;
        let host_b = harness.node(&b).unwrap().host_id;

        // Partition before spawning
        harness.execute_fault(&HarnessFault::Network(Fault::Partition {
            hosts_a: vec![host_a],
            hosts_b: vec![host_b],
        }));

        let task_id = RemoteTaskId::next();
        harness.inject_spawn(&a, &b, task_id);
        harness.run_for(Duration::from_millis(100));

        // B should NOT have received the spawn
        let node_b = harness.node(&b).unwrap();
        assert!(!node_b
            .events()
            .iter()
            .any(|e| matches!(e, NodeEvent::SpawnReceived { .. })));
    }

    #[test]
    fn node_crash_drops_tasks() {
        let (mut harness, a, b) = setup_harness();
        let task_id = RemoteTaskId::next();

        harness.inject_spawn(&a, &b, task_id);
        harness.run_for(Duration::from_millis(10));

        // Crash node B
        harness.execute_fault(&HarnessFault::CrashNode(b.clone()));

        let node_b = harness.node(&b).unwrap();
        assert!(node_b.crashed);
        assert_eq!(node_b.running_task_count(), 0);
        assert!(node_b
            .events()
            .iter()
            .any(|e| matches!(e, NodeEvent::Crashed)));
    }

    #[test]
    fn lease_expiry_fails_tasks() {
        let (mut harness, a, b) = setup_harness();
        let task_id = RemoteTaskId::next();

        harness.inject_spawn(&a, &b, task_id);
        harness.run_for(Duration::from_millis(10));

        // Expire leases on B
        harness.execute_fault(&HarnessFault::ExpireLeases(b.clone()));

        // B should have no running tasks
        let node_b = harness.node(&b).unwrap();
        assert_eq!(node_b.running_task_count(), 0);
    }

    #[test]
    fn fault_script_executes_in_order() {
        let config = NetworkConfig {
            default_conditions: crate::lab::network::NetworkConditions::local(),
            ..NetworkConfig::default()
        };
        let mut harness = DistributedHarness::new(config);
        let a = harness.add_node("node-a");
        let b = harness.add_node("node-b");

        let script = FaultScript::new()
            .at(
                Duration::from_millis(50),
                HarnessFault::CrashNode(b.clone()),
            )
            .at(
                Duration::from_millis(150),
                HarnessFault::RestartNode(b.clone()),
            );
        harness.set_fault_script(script);

        let task_id = RemoteTaskId::next();
        harness.inject_spawn(&a, &b, task_id);

        harness.run_for(Duration::from_millis(200));

        let node_b = harness.node(&b).unwrap();
        assert!(node_b
            .events()
            .iter()
            .any(|e| matches!(e, NodeEvent::Crashed)));
        assert!(node_b
            .events()
            .iter()
            .any(|e| matches!(e, NodeEvent::Restarted)));
        // After restart, node is not crashed
        assert!(!node_b.crashed);
    }

    #[test]
    fn deterministic_replay() {
        // Same setup should produce identical event logs.
        fn run_scenario() -> Vec<String> {
            let config = NetworkConfig {
                seed: 42,
                default_conditions: crate::lab::network::NetworkConditions::lan(),
                ..NetworkConfig::default()
            };
            let mut harness = DistributedHarness::new(config);
            let a = harness.add_node("node-a");
            let b = harness.add_node("node-b");

            // Use a fixed task ID for reproducibility
            let task_id = RemoteTaskId::from_raw(1000);
            harness.inject_spawn(&a, &b, task_id);
            harness.run_for(Duration::from_millis(300));

            harness
                .trace()
                .iter()
                .map(|e| format!("{:?}:{:?}", e.time, e.kind))
                .collect()
        }

        let run1 = run_scenario();
        let run2 = run_scenario();
        assert_eq!(run1, run2, "Replay should be deterministic");
    }

    #[test]
    fn idempotent_spawn_dedup() {
        let (mut harness, a, b) = setup_harness();
        let task_id = RemoteTaskId::next();

        // Send same spawn request twice
        harness.inject_spawn(&a, &b, task_id);
        harness.inject_spawn(&a, &b, task_id);

        harness.run_for(Duration::from_millis(50));

        let node_b = harness.node(&b).unwrap();
        let spawn_count = node_b
            .events()
            .iter()
            .filter(|e| matches!(e, NodeEvent::SpawnAccepted { .. }))
            .count();
        let dedup_count = node_b
            .events()
            .iter()
            .filter(|e| matches!(e, NodeEvent::DuplicateSpawn { .. }))
            .count();

        // First should be accepted, second should be deduped
        assert_eq!(spawn_count, 1);
        assert_eq!(dedup_count, 1);
    }

    #[test]
    fn partition_heal_recovers_delivery() {
        let (mut harness, a, b) = setup_harness();
        let host_a = harness.node(&a).unwrap().host_id;
        let host_b = harness.node(&b).unwrap().host_id;

        harness.execute_fault(&HarnessFault::Network(Fault::Partition {
            hosts_a: vec![host_a],
            hosts_b: vec![host_b],
        }));

        let dropped_task = RemoteTaskId::next();
        harness.inject_spawn(&a, &b, dropped_task);
        harness.run_for(Duration::from_millis(100));

        let node_b = harness.node(&b).unwrap();
        assert!(!node_b.events().iter().any(
            |e| matches!(e, NodeEvent::SpawnReceived { task_id, .. } if *task_id == dropped_task)
        ));

        harness.execute_fault(&HarnessFault::Network(Fault::Heal {
            hosts_a: vec![host_a],
            hosts_b: vec![host_b],
        }));

        let recovered_task = RemoteTaskId::next();
        harness.inject_spawn(&a, &b, recovered_task);
        harness.run_for(Duration::from_millis(250));

        let node_b = harness.node(&b).unwrap();
        assert!(node_b.events().iter().any(
            |e| matches!(e, NodeEvent::SpawnReceived { task_id, .. } if *task_id == recovered_task)
        ));
        assert!(node_b.events().iter().any(
            |e| matches!(e, NodeEvent::TaskCompleted { task_id } if *task_id == recovered_task)
        ));
        assert_eq!(node_b.running_task_count(), 0);
    }

    #[test]
    fn crash_restart_recovers_new_tasks() {
        let (mut harness, a, b) = setup_harness();
        let initial_task = RemoteTaskId::next();

        harness.inject_spawn(&a, &b, initial_task);
        harness.run_for(Duration::from_millis(10));

        harness.execute_fault(&HarnessFault::CrashNode(b.clone()));
        let node_b = harness.node(&b).unwrap();
        assert!(node_b.crashed);
        assert_eq!(node_b.running_task_count(), 0);

        harness.execute_fault(&HarnessFault::RestartNode(b.clone()));

        let recovered_task = RemoteTaskId::next();
        harness.inject_spawn(&a, &b, recovered_task);
        harness.run_for(Duration::from_millis(250));

        let node_b = harness.node(&b).unwrap();
        assert!(!node_b.crashed);
        assert!(node_b
            .events()
            .iter()
            .any(|e| matches!(e, NodeEvent::Restarted)));
        assert!(node_b.events().iter().any(
            |e| matches!(e, NodeEvent::TaskCompleted { task_id } if *task_id == recovered_task)
        ));
        assert_eq!(node_b.running_task_count(), 0);
    }

    #[test]
    fn message_loss_then_recovery_delivers_new_work() {
        let (mut harness, a, b) = setup_harness();
        let host_a = harness.node(&a).unwrap().host_id;
        let host_b = harness.node(&b).unwrap().host_id;

        let mut loss = crate::lab::network::NetworkConditions::local();
        loss.packet_loss = 1.0;
        harness
            .network
            .set_link_conditions(host_a, host_b, loss.clone());
        harness.network.set_link_conditions(host_b, host_a, loss);

        let dropped_task = RemoteTaskId::next();
        harness.inject_spawn(&a, &b, dropped_task);
        harness.run_for(Duration::from_millis(100));

        let node_b = harness.node(&b).unwrap();
        assert!(!node_b.events().iter().any(
            |e| matches!(e, NodeEvent::SpawnReceived { task_id, .. } if *task_id == dropped_task)
        ));
        assert!(harness.network_metrics().packets_dropped > 0);

        let recovered = crate::lab::network::NetworkConditions::local();
        harness
            .network
            .set_link_conditions(host_a, host_b, recovered.clone());
        harness
            .network
            .set_link_conditions(host_b, host_a, recovered);

        let recovered_task = RemoteTaskId::next();
        harness.inject_spawn(&a, &b, recovered_task);
        harness.run_for(Duration::from_millis(250));

        let node_b = harness.node(&b).unwrap();
        assert!(node_b.events().iter().any(
            |e| matches!(e, NodeEvent::TaskCompleted { task_id } if *task_id == recovered_task)
        ));
        assert_eq!(node_b.running_task_count(), 0);
    }

    #[test]
    fn clock_skew_advances_causal_clock() {
        let (mut harness, a, b) = setup_harness();
        let host_a = harness.node(&a).unwrap().host_id;
        let host_b = harness.node(&b).unwrap().host_id;

        let task_id = RemoteTaskId::next();
        let req = SpawnRequest {
            remote_task_id: task_id,
            computation: crate::remote::ComputationName::new("test-computation"),
            input: crate::remote::RemoteInput::new(vec![]),
            lease: Duration::from_secs(30),
            idempotency_key: IdempotencyKey::from_raw(u128::from(task_id.raw())),
            budget: None,
            origin_node: a.clone(),
            origin_region: crate::types::RegionId::new_for_test(0, 0),
            origin_task: crate::types::TaskId::new_for_test(0, 0),
        };

        let mut skewed = VectorClock::new();
        skewed.set(&a, 100);
        let envelope = MessageEnvelope::new(
            a.clone(),
            LogicalTime::Vector(skewed.clone()),
            RemoteMessage::SpawnRequest(req),
        );
        let encoded = harness.encode_message(&envelope);
        harness.network.send(host_a, host_b, Bytes::from(encoded));

        harness.run_for(Duration::from_millis(250));

        let node_b = harness.node(&b).unwrap();
        assert!(node_b.events().iter().any(
            |e| matches!(e, NodeEvent::SpawnReceived { task_id: seen, .. } if *seen == task_id)
        ));
        let clock = node_b.causal_tracker().current_clock();
        assert!(
            clock.get(&a) >= 100,
            "expected skewed clock to merge into receiver"
        );
        assert_eq!(node_b.running_task_count(), 0);
    }
}
