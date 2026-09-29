//! Practical Byzantine Fault Tolerance (PBFT) consensus algorithm.
//!
//! This implements the PBFT protocol as described in "Practical Byzantine
//! Fault Tolerance" by Castro and Liskov. The protocol provides safety
//! and liveness guarantees in partially synchronous networks with up to
//! f Byzantine faults in a system of 3f+1 replicas.
//!
//! # Protocol Overview
//!
//! PBFT operates in views, where each view has a designated primary replica
//! that orders client requests. The protocol consists of three phases:
//!
//! 1. **Pre-prepare**: Primary proposes ordering for a batch of requests
//! 2. **Prepare**: Replicas agree on the ordering proposed by the primary
//! 3. **Commit**: Replicas commit to executing the ordered requests
//!
//! View changes occur when the primary is suspected of being faulty.
//!
//! # Experimental — not Byzantine-fault-tolerant yet
//!
//! This implementation is **experimental and incomplete**. The normal-case
//! three-phase path (pre-prepare/prepare/commit) is implemented, but
//! view-change/new-view handling is **not** (the handlers fail closed rather
//! than silently succeed), and there is no message authentication, no
//! watermark/checkpoint stability, and no log pruning. As a result it does
//! **not** provide liveness under primary failure or safety against a
//! Byzantine primary. Do not rely on it for fault tolerance. Tracked by
//! `asupersync-v8mszr`.
//!
//! For application execution on the experimental normal-case path, use
//! [`PbftExecution`] with an explicit [`PbftStateMachine`]. The legacy
//! [`PbftConsensus::submit`] remains a deprecated compatibility scaffold.

use crate::cx::Cx;
use crate::error::{Error, ErrorKind, Result};
use crate::time::timeout;
use crate::types::{Outcome, Time};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::types::{
    ConsensusBatch, ConsensusRequest, ConsensusResponse, MessageCertificate, MessageDigest,
    PhaseKind, ReplicaId, SequenceNumber, ViewNumber,
};

/// Configuration for PBFT consensus.
#[derive(Debug, Clone)]
pub struct PbftConfig {
    /// Total number of replicas in the system.
    pub replica_count: usize,
    /// Maximum number of Byzantine faults tolerated.
    pub fault_tolerance: usize,
    /// Timeout for pre-prepare phase.
    pub preprepare_timeout: Duration,
    /// Timeout for prepare phase.
    pub prepare_timeout: Duration,
    /// Timeout for commit phase.
    pub commit_timeout: Duration,
    /// Timeout for view change.
    pub view_change_timeout: Duration,
    /// Maximum batch size for requests.
    pub max_batch_size: usize,
    /// Batch timeout - max time to wait for full batch.
    pub batch_timeout: Duration,
}

impl PbftConfig {
    /// Create configuration for n replicas with f Byzantine faults.
    pub fn new(replica_count: usize, fault_tolerance: usize) -> Result<Self> {
        if fault_tolerance
            .checked_mul(3)
            .is_none_or(|minimum| replica_count <= minimum)
        {
            return Err(Error::new(ErrorKind::InvalidInput));
        }

        Ok(Self {
            replica_count,
            fault_tolerance,
            preprepare_timeout: Duration::from_secs(5),
            prepare_timeout: Duration::from_secs(5),
            commit_timeout: Duration::from_secs(5),
            view_change_timeout: Duration::from_secs(10),
            max_batch_size: 100,
            batch_timeout: Duration::from_millis(10),
        })
    }

    /// Check if we have enough replicas for given fault tolerance.
    pub fn is_valid(&self) -> bool {
        self.fault_tolerance
            .checked_mul(3)
            .is_some_and(|minimum| self.replica_count > minimum)
    }

    /// Get the minimum number of signatures needed for a quorum.
    pub fn quorum_size(&self) -> usize {
        self.fault_tolerance.saturating_mul(2).saturating_add(1)
    }
}

/// PBFT protocol message types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PbftMessage {
    /// Client request for consensus.
    Request(ConsensusRequest),
    /// Primary proposes ordering (pre-prepare phase).
    PrePrepare {
        view: ViewNumber,
        sequence: SequenceNumber,
        digest: MessageDigest,
        batch: ConsensusBatch,
        replica_id: ReplicaId,
    },
    /// Replica agrees with ordering (prepare phase).
    Prepare {
        view: ViewNumber,
        sequence: SequenceNumber,
        digest: MessageDigest,
        replica_id: ReplicaId,
    },
    /// Replica commits to execution (commit phase).
    Commit {
        view: ViewNumber,
        sequence: SequenceNumber,
        digest: MessageDigest,
        replica_id: ReplicaId,
    },
    /// View change request.
    ViewChange {
        new_view: ViewNumber,
        replica_id: ReplicaId,
        certificates: Vec<MessageCertificate>,
    },
    /// New view establishment.
    NewView {
        view: ViewNumber,
        view_change_msgs: Vec<PbftMessage>,
        preprepare_msgs: Vec<PbftMessage>,
    },
}

impl PbftMessage {
    /// Compute cryptographic digest of this message.
    pub fn digest(&self) -> Result<MessageDigest> {
        MessageDigest::of(self)
    }

    /// Get the phase kind of this message.
    pub fn phase(&self) -> PhaseKind {
        match self {
            PbftMessage::PrePrepare { .. } => PhaseKind::PrePrepare,
            PbftMessage::Prepare { .. } => PhaseKind::Prepare,
            PbftMessage::Commit { .. } => PhaseKind::Commit,
            PbftMessage::ViewChange { .. } => PhaseKind::ViewChange,
            PbftMessage::NewView { .. } => PhaseKind::NewView,
            PbftMessage::Request(_) => PhaseKind::PrePrepare, // Requests trigger pre-prepare
        }
    }
}

/// Current state of a PBFT replica.
#[derive(Debug, Clone)]
pub struct PbftState {
    /// Current view number.
    pub view: ViewNumber,
    /// Next sequence number to assign.
    pub sequence: SequenceNumber,
    /// Request batches in various phases.
    pub log: HashMap<SequenceNumber, LogEntry>,
    /// Pending client requests.
    pub pending_requests: VecDeque<ConsensusRequest>,
    /// Last executed sequence number.
    pub last_executed: SequenceNumber,
    /// View change state.
    pub view_change_state: Option<ViewChangeState>,
}

/// Entry in the consensus log for tracking message phases.
#[derive(Debug, Clone)]
pub struct LogEntry {
    /// The batch of requests.
    pub batch: ConsensusBatch,
    /// Digest of the batch.
    pub digest: MessageDigest,
    /// View number when created.
    pub view: ViewNumber,
    /// Pre-prepare received.
    pub preprepared: bool,
    /// Prepare messages received.
    pub prepare_msgs: HashMap<ReplicaId, PbftMessage>,
    /// Commit messages received.
    pub commit_msgs: HashMap<ReplicaId, PbftMessage>,
    /// Execution result if completed.
    pub result: Option<Outcome<Vec<u8>, String>>,
}

/// State during view change protocol.
#[derive(Debug, Clone)]
pub struct ViewChangeState {
    /// Target view number.
    pub target_view: ViewNumber,
    /// View change messages received.
    pub view_change_msgs: HashMap<ReplicaId, PbftMessage>,
    /// Whether this replica sent view change.
    pub sent_view_change: bool,
    /// Timestamp when view change started.
    pub started_at: Time,
}

/// Transport interface for PBFT message delivery.
pub trait PbftTransport: Send + Sync {
    /// Send message to a specific replica.
    fn send_to_replica(
        &self,
        replica_id: &ReplicaId,
        message: PbftMessage,
    ) -> impl std::future::Future<Output = Result<()>> + Send;

    /// Broadcast message to all replicas.
    fn broadcast(
        &self,
        message: PbftMessage,
    ) -> impl std::future::Future<Output = Result<()>> + Send;

    /// Receive next message (blocking).
    fn receive(&self) -> impl std::future::Future<Output = Result<PbftMessage>> + Send;
}

/// State machine for PBFT consensus node.
pub struct PbftNode<T: PbftTransport> {
    /// Replica identifier for this node.
    replica_id: ReplicaId,
    /// Canonical numeric index for this replica in the configured replica set.
    replica_index: usize,
    /// Configuration parameters.
    config: PbftConfig,
    /// Current state.
    state: Arc<Mutex<PbftState>>,
    /// Transport for message delivery.
    transport: T,
}

impl<T: PbftTransport> PbftNode<T> {
    /// Create a new PBFT node.
    pub fn new(replica_id: ReplicaId, config: PbftConfig, transport: T) -> Result<Self> {
        if !config.is_valid() {
            return Err(Error::new(ErrorKind::InvalidInput));
        }
        let replica_index = parse_replica_index(&replica_id, config.replica_count)?;

        let state = PbftState {
            view: ViewNumber::new(0),
            // Sequence numbers are assigned starting at 1. `last_executed` is the
            // watermark of the highest sequence already executed, and starts at 0
            // to mean "nothing executed yet". Execution is gap-free and gated on
            // `sequence == last_executed.next()` (see `handle_commit`), so the
            // first batch MUST be sequence 1 — otherwise `0 == 0.next() == 1` is
            // never satisfied and the first batch (and thus the whole pipeline)
            // can never execute.
            sequence: SequenceNumber::new(1),
            log: HashMap::new(),
            pending_requests: VecDeque::new(),
            last_executed: SequenceNumber::new(0),
            view_change_state: None,
        };

        Ok(Self {
            replica_id,
            replica_index,
            config,
            state: Arc::new(Mutex::new(state)),
            transport,
        })
    }

    /// Check if this replica is the primary for the current view.
    pub fn is_primary(&self) -> bool {
        let state = self.state.lock().unwrap();
        let primary_idx = state.view.primary(self.config.replica_count);
        self.replica_index == primary_idx
    }

    /// The highest sequence number this replica has executed. Execution is
    /// gap-free, so every sequence in `1..=last_executed` has been applied.
    pub fn last_executed(&self) -> SequenceNumber {
        self.state.lock().unwrap().last_executed
    }

    /// Submit a client request for consensus.
    pub async fn submit_request(&self, cx: &Cx, request: ConsensusRequest) -> Result<()> {
        {
            let mut state = self.state.lock().unwrap();
            state.pending_requests.push_back(request);
        }

        // If we're the primary, try to create a batch
        if self.is_primary() {
            self.try_create_batch(cx).await?;
        }

        Ok(())
    }

    /// Try to create a batch of pending requests.
    async fn try_create_batch(&self, cx: &Cx) -> Result<()> {
        let (batch, sequence, view) = {
            let mut state = self.state.lock().unwrap();

            if state.pending_requests.is_empty() {
                return Ok(()); // No requests to batch
            }

            // Collect requests for batch
            let mut requests = Vec::new();
            while requests.len() < self.config.max_batch_size && !state.pending_requests.is_empty()
            {
                if let Some(request) = state.pending_requests.pop_front() {
                    requests.push(request);
                }
            }

            let batch = ConsensusBatch::new(requests);
            let sequence = state.sequence;
            let view = state.view;

            (batch, sequence, view)
        };

        let result = self
            .send_preprepare(cx, view, sequence, batch.clone())
            .await;
        let mut state = self.state.lock().unwrap();
        match result {
            Ok(()) => {
                if state.sequence == sequence {
                    state.sequence = state.sequence.next();
                }
                Ok(())
            }
            Err(err) => {
                if state.sequence == sequence.next() {
                    state.sequence = sequence;
                }
                if let Ok(digest) = MessageDigest::of(&batch) {
                    if state
                        .log
                        .get(&sequence)
                        .is_some_and(|entry| entry.view == view && entry.digest == digest)
                    {
                        state.log.remove(&sequence);
                    }
                }
                for request in batch.requests.iter().rev() {
                    state.pending_requests.push_front(request.clone());
                }
                Err(err)
            }
        }
    }

    /// Send pre-prepare message as primary.
    async fn send_preprepare(
        &self,
        cx: &Cx,
        view: ViewNumber,
        sequence: SequenceNumber,
        batch: ConsensusBatch,
    ) -> Result<()> {
        let digest = MessageDigest::of(&batch)?;

        // Create log entry
        {
            let mut state = self.state.lock().unwrap();
            if state.log.contains_key(&sequence) {
                return Err(
                    Error::new(ErrorKind::InvalidStateTransition).with_message(format!(
                        "PBFT pre-prepare sequence {sequence} already has a log entry"
                    )),
                );
            }
            let entry = LogEntry {
                batch: batch.clone(),
                digest: digest.clone(),
                view,
                preprepared: true,
                prepare_msgs: HashMap::new(),
                commit_msgs: HashMap::new(),
                result: None,
            };
            state.log.insert(sequence, entry);
        }

        let message = PbftMessage::PrePrepare {
            view,
            sequence,
            digest,
            batch,
            replica_id: self.replica_id.clone(),
        };

        // Broadcast pre-prepare to all replicas
        timeout(
            cx.now(),
            self.config.preprepare_timeout,
            self.transport.broadcast(message),
        )
        .await
        .map_err(|_| Error::new(ErrorKind::DeadlineExceeded))??;

        // A one-replica configuration already has both local quorums. There
        // will be no remote prepare/commit packet to trigger execution.
        self.drain_committed().await
    }

    /// Process an incoming PBFT message.
    pub async fn process_message(&self, cx: &Cx, message: PbftMessage) -> Result<()> {
        match message {
            PbftMessage::Request(request) => self.submit_request(cx, request).await,
            PbftMessage::PrePrepare {
                view,
                sequence,
                digest,
                batch,
                replica_id,
            } => {
                self.handle_preprepare(cx, view, sequence, digest, batch, replica_id)
                    .await
            }
            PbftMessage::Prepare {
                view,
                sequence,
                digest,
                replica_id,
            } => {
                self.handle_prepare(cx, view, sequence, digest, replica_id)
                    .await
            }
            PbftMessage::Commit {
                view,
                sequence,
                digest,
                replica_id,
            } => {
                self.handle_commit(cx, view, sequence, digest, replica_id)
                    .await
            }
            PbftMessage::ViewChange {
                new_view,
                replica_id,
                certificates,
            } => {
                self.handle_view_change(cx, new_view, replica_id, certificates)
                    .await
            }
            PbftMessage::NewView {
                view,
                view_change_msgs,
                preprepare_msgs,
            } => {
                self.handle_new_view(cx, view, view_change_msgs, preprepare_msgs)
                    .await
            }
        }
    }

    /// Handle pre-prepare message from primary.
    async fn handle_preprepare(
        &self,
        cx: &Cx,
        view: ViewNumber,
        sequence: SequenceNumber,
        digest: MessageDigest,
        batch: ConsensusBatch,
        replica_id: ReplicaId,
    ) -> Result<()> {
        self.validate_preprepare_primary(view, &replica_id)?;
        // Validate the payload even on the duplicate path, before any state
        // mutation. Install it under the same lock as the equivocation check.
        if digest != MessageDigest::of(&batch)? {
            return Err(Error::new(ErrorKind::InvalidInput));
        }
        {
            let mut state = self.state.lock().unwrap();
            if view != state.view {
                return Err(Error::new(ErrorKind::InvalidInput));
            }
            if sequence <= state.last_executed {
                return Err(
                    Error::new(ErrorKind::InvalidStateTransition).with_message(format!(
                        "PBFT pre-prepare sequence {sequence} is at or below executed watermark {}",
                        state.last_executed
                    )),
                );
            }

            if let Some(entry) = state.log.get_mut(&sequence) {
                if entry.view != view || entry.digest != digest {
                    return Err(Error::new(ErrorKind::InvalidStateTransition).with_message(
                        format!("PBFT pre-prepare equivocation for {sequence} in {view}"),
                    ));
                }
                if entry.preprepared {
                    return Ok(());
                }
                entry.batch = batch;
                entry.preprepared = true;
            } else {
                let entry = LogEntry {
                    batch,
                    digest: digest.clone(),
                    view,
                    preprepared: true,
                    prepare_msgs: HashMap::new(),
                    commit_msgs: HashMap::new(),
                    result: None,
                };
                state.log.insert(sequence, entry);
            }
        }

        // Send prepare message
        let prepare_msg = PbftMessage::Prepare {
            view,
            sequence,
            digest,
            replica_id: self.replica_id.clone(),
        };

        timeout(
            cx.now(),
            self.config.prepare_timeout,
            self.transport.broadcast(prepare_msg),
        )
        .await
        .map_err(|_| Error::new(ErrorKind::DeadlineExceeded))??;

        self.drain_committed().await
    }

    /// Handle prepare message from replica.
    async fn handle_prepare(
        &self,
        cx: &Cx,
        view: ViewNumber,
        sequence: SequenceNumber,
        digest: MessageDigest,
        replica_id: ReplicaId,
    ) -> Result<()> {
        let replica_id = self.validate_remote_replica(&replica_id)?;
        let should_commit = {
            let mut state = self.state.lock().unwrap();

            // Find log entry
            let entry = match state.log.get_mut(&sequence) {
                Some(entry) if entry.view == view && entry.digest == digest => entry,
                _ => return Ok(()), // Ignore if no matching entry
            };

            // Add prepare message
            let msg = PbftMessage::Prepare {
                view,
                sequence,
                digest: digest.clone(),
                replica_id: replica_id.clone(),
            };
            entry.prepare_msgs.insert(replica_id, msg);

            // Check if we have enough prepares (2f+1 including our own).
            entry.preprepared && entry.prepare_msgs.len() + 1 >= self.config.quorum_size()
        };

        // Send commit message if we have quorum
        if should_commit {
            let commit_msg = PbftMessage::Commit {
                view,
                sequence,
                digest,
                replica_id: self.replica_id.clone(),
            };

            timeout(
                cx.now(),
                self.config.commit_timeout,
                self.transport.broadcast(commit_msg),
            )
            .await
            .map_err(|_| Error::new(ErrorKind::DeadlineExceeded))??;

            // Commit votes may arrive before the last prepare vote. Recheck
            // execution here as well: a completed certificate must not need
            // an extra duplicate commit packet to make progress.
            self.drain_committed().await?;
        }

        Ok(())
    }

    /// Handle commit message from replica.
    async fn handle_commit(
        &self,
        _cx: &Cx,
        view: ViewNumber,
        sequence: SequenceNumber,
        digest: MessageDigest,
        replica_id: ReplicaId,
    ) -> Result<()> {
        let replica_id = self.validate_remote_replica(&replica_id)?;
        let should_execute = {
            let mut state = self.state.lock().unwrap();
            let next_to_execute = state.last_executed.next();

            // Find log entry
            let entry = match state.log.get_mut(&sequence) {
                Some(entry) if entry.view == view && entry.digest == digest => entry,
                _ => return Ok(()), // Ignore if no matching entry
            };

            // Add commit message
            let msg = PbftMessage::Commit {
                view,
                sequence,
                digest: digest.clone(),
                replica_id: replica_id.clone(),
            };
            entry.commit_msgs.insert(replica_id, msg);

            let prepared =
                entry.preprepared && entry.prepare_msgs.len() + 1 >= self.config.quorum_size();
            let committed = entry.commit_msgs.len() + 1 >= self.config.quorum_size();

            prepared && committed && sequence == next_to_execute && entry.result.is_none()
        };

        // Execute the batch if we have quorum and it's the next in sequence,
        // then drain any successors whose commit-quorum completed out of order.
        // Execution is otherwise only re-triggered by the arrival of a NEW
        // commit for the exact `last_executed.next()`, so a higher sequence that
        // already holds a full commit certificate would stall permanently behind
        // a lower one — ordinary under network reordering, not just adversarial.
        if should_execute {
            self.drain_committed().await?;
        }

        Ok(())
    }

    /// Execute the entire contiguous prefix whose prepare and commit
    /// certificates are complete, regardless of which phase completed last.
    async fn drain_committed(&self) -> Result<()> {
        while let Some(next) = self.next_executable_sequence() {
            self.execute_batch(next).await?;
        }
        Ok(())
    }

    /// The next sequence that is prepared, committed, and not yet executed.
    fn next_executable_sequence(&self) -> Option<SequenceNumber> {
        let state = self.state.lock().unwrap();
        let next = state.last_executed.next();
        let entry = state.log.get(&next)?;
        let prepared =
            entry.preprepared && entry.prepare_msgs.len() + 1 >= self.config.quorum_size();
        let committed = entry.commit_msgs.len() + 1 >= self.config.quorum_size();
        (prepared && committed && entry.result.is_none()).then_some(next)
    }

    /// Execute a batch of requests.
    async fn execute_batch(&self, sequence: SequenceNumber) -> Result<()> {
        let batch = {
            let mut state = self.state.lock().unwrap();

            if sequence != state.last_executed.next() {
                return Ok(());
            }

            let batch = {
                let entry = state.log.get_mut(&sequence).ok_or_else(|| {
                    Error::new(ErrorKind::InvalidStateTransition).with_message(format!(
                        "PBFT cannot execute missing log entry for {sequence}"
                    ))
                })?;
                if entry.result.is_some() {
                    return Ok(());
                }
                let batch = entry.batch.clone();

                // For simplicity, just simulate execution
                let result = Outcome::Ok(b"executed".to_vec());
                entry.result = Some(result);
                batch
            };

            state.last_executed = sequence;
            batch
        };

        let batch_size = batch.len();

        // In a real implementation, this would execute the actual state machine.
        // With tracing disabled, keep the execution path side-effect free.
        #[cfg(feature = "tracing-integration")]
        tracing::info!(
            replica_id = %self.replica_id,
            sequence = %sequence,
            batch_size,
            "Executed consensus batch"
        );
        #[cfg(not(feature = "tracing-integration"))]
        let _ = batch_size;

        Ok(())
    }

    fn validate_remote_replica(&self, replica_id: &ReplicaId) -> Result<ReplicaId> {
        let index = parse_replica_index(replica_id, self.config.replica_count)?;
        if index == self.replica_index {
            return Err(Error::new(ErrorKind::InvalidInput).with_message(format!(
                "PBFT rejected self-authored remote quorum message from {replica_id}"
            )));
        }
        // Count configured replicas, not alternate spellings of the same
        // numeric id (for example, "2" and "02"). Keep accepting the legacy
        // spelling at the API boundary while using a canonical quorum key.
        Ok(ReplicaId::new(index.to_string()))
    }

    fn validate_preprepare_primary(&self, view: ViewNumber, replica_id: &ReplicaId) -> Result<()> {
        let index = parse_replica_index(replica_id, self.config.replica_count)?;
        let expected = view.primary(self.config.replica_count);
        if index != expected {
            return Err(Error::new(ErrorKind::InvalidInput).with_message(format!(
                "PBFT rejected pre-prepare from {replica_id}; primary for {view} is replica:{expected}"
            )));
        }
        Ok(())
    }

    /// Handle view change message.
    ///
    /// **Not implemented.** A correct PBFT view-change requires validated
    /// view-change certificates, watermark/checkpoint stability, and new-view
    /// construction. Until that lands this returns an explicit error rather
    /// than silently succeeding — a silent `Ok(())` here would let a caller
    /// believe primary-failure recovery occurred when it did not. See the
    /// experimental warning on [`PbftConsensus`].
    async fn handle_view_change(
        &self,
        _cx: &Cx,
        _new_view: ViewNumber,
        _replica_id: ReplicaId,
        _certificates: Vec<MessageCertificate>,
    ) -> Result<()> {
        Err(Error::new(ErrorKind::InvalidStateTransition).with_message(
            "PBFT view-change is not implemented (experimental consensus; no Byzantine \
             fault tolerance under primary failure)",
        ))
    }

    /// Handle new view message.
    ///
    /// **Not implemented** — see [`Self::handle_view_change`]. Fails closed
    /// rather than pretending to install a new view.
    async fn handle_new_view(
        &self,
        _cx: &Cx,
        _view: ViewNumber,
        _view_change_msgs: Vec<PbftMessage>,
        _preprepare_msgs: Vec<PbftMessage>,
    ) -> Result<()> {
        Err(Error::new(ErrorKind::InvalidStateTransition).with_message(
            "PBFT new-view is not implemented (experimental consensus; no Byzantine \
             fault tolerance under primary failure)",
        ))
    }
}

fn parse_replica_index(replica_id: &ReplicaId, replica_count: usize) -> Result<usize> {
    let index = replica_id.as_str().parse::<usize>().map_err(|_| {
        Error::new(ErrorKind::InvalidInput).with_message(format!(
            "PBFT replica id {replica_id} must be a numeric index"
        ))
    })?;
    if index >= replica_count {
        return Err(Error::new(ErrorKind::InvalidInput).with_message(format!(
            "PBFT replica id {replica_id} is outside configured replica set size {replica_count}"
        )));
    }
    Ok(index)
}

/// High-level PBFT consensus interface.
pub struct PbftConsensus<T: PbftTransport> {
    node: PbftNode<T>,
}

impl<T: PbftTransport> PbftConsensus<T> {
    /// Create a new PBFT consensus instance.
    pub fn new(replica_id: ReplicaId, config: PbftConfig, transport: T) -> Result<Self> {
        let node = PbftNode::new(replica_id, config, transport)?;
        Ok(Self { node })
    }

    /// Submit a request for consensus.
    ///
    /// # Experimental stub
    ///
    /// This forwards the request to the local node and then returns a
    /// **placeholder** response (`view 0`, `sequence 0`, the fixed bytes
    /// `b"consensus result"`, timestamp `0`). It does not wait for the
    /// three-phase protocol to execute the request and does not return the
    /// replicated result. Treat it as a scaffold for the message loop, not
    /// as a working consensus API; the deprecation attribute exists so that
    /// callers cannot pick it up by accident. The item stays exported and
    /// functional under the 0.4.x compatibility rule.
    #[deprecated(
        since = "0.4.11",
        note = "experimental PBFT scaffold: returns a fixed placeholder response, not a replicated \
                consensus result"
    )]
    pub async fn submit(&self, cx: &Cx, request: ConsensusRequest) -> Result<ConsensusResponse> {
        self.node.submit_request(cx, request.clone()).await?;

        // For simplicity, return a dummy response
        // A real implementation would wait for execution and return the result
        Ok(ConsensusResponse {
            view: ViewNumber::new(0),
            sequence: SequenceNumber::new(0),
            result: Outcome::Ok(b"consensus result".to_vec()),
            replica_id: self.node.replica_id.clone(),
            timestamp: Time::from_millis(0),
        })
    }

    /// Run the consensus protocol message loop.
    pub async fn run(&self, cx: &Cx) -> Result<()> {
        loop {
            // Receive and process messages
            let message = self.node.transport.receive().await?;
            self.node.process_message(cx, message).await?;
        }
    }
}

/// Deterministic application state applied to committed PBFT requests.
///
/// Implementations must be bounded, synchronous, and deterministic from the
/// request and their owned state. They must not perform I/O or re-enter the
/// execution driver. Return an application error as an [`Outcome::Err`]; a
/// panic poisons the driver so a possibly applied operation is never retried.
pub trait PbftStateMachine: Send {
    /// Apply one request, in the order established by the committed log.
    fn apply(&mut self, request: &ConsensusRequest) -> Outcome<Vec<u8>, String>;
}

impl<F> PbftStateMachine for F
where
    F: FnMut(&ConsensusRequest) -> Outcome<Vec<u8>, String> + Send,
{
    fn apply(&mut self, request: &ConsensusRequest) -> Outcome<Vec<u8>, String> {
        self(request)
    }
}

struct ApplicationState<S> {
    machine: S,
    last_applied: SequenceNumber,
    responses: HashMap<MessageDigest, ConsensusResponse>,
    identities: HashSet<MessageDigest>,
}

/// Application execution and real result retrieval for the experimental PBFT
/// normal-case protocol.
///
/// Unlike the deprecated [`PbftConsensus::submit`], this driver only publishes
/// responses after a request has a local commit certificate and its application
/// has run. Supply the same deterministic [`PbftStateMachine`] on every replica,
/// then drive [`Self::process_message`] or [`Self::run`] in an owned task. A
/// successful [`Self::submit_request`] means admission/forwarding, not consensus;
/// inspect [`Self::committed_response`] for the actual application outcome.
///
/// Exact request replays return the original response without applying twice.
/// Reusing a client id and timestamp for different operation bytes produces an
/// application error without invoking the state machine. Receipts and replay
/// protection are process-local and retained for the driver's lifetime: there
/// is no durable recovery, pruning, view change, or message authentication here.
/// The experimental fault-tolerance limitations of this module still apply.
pub struct PbftExecution<T: PbftTransport, S: PbftStateMachine> {
    node: PbftNode<T>,
    application: Mutex<ApplicationState<S>>,
    // Serialize proposal writers without holding a blocking mutex across
    // transport awaits. The reserved proposal itself survives cancellation.
    proposals: crate::sync::Mutex<()>,
}

impl<T: PbftTransport, S: PbftStateMachine> PbftExecution<T, S> {
    /// Construct an execution driver with an explicitly supplied application.
    ///
    /// This normal-case driver requires exactly `3f + 1` replicas: the legacy
    /// protocol's `2f + 1` quorum is not sufficient for arbitrary larger sets.
    pub fn new(
        replica_id: ReplicaId,
        config: PbftConfig,
        transport: T,
        machine: S,
    ) -> Result<Self> {
        if config.max_batch_size == 0 {
            return Err(Error::new(ErrorKind::InvalidInput)
                .with_message("PBFT application execution requires a nonzero batch size"));
        }
        if config
            .fault_tolerance
            .checked_mul(3)
            .and_then(|replicas| replicas.checked_add(1))
            != Some(config.replica_count)
        {
            return Err(Error::new(ErrorKind::InvalidInput)
                .with_message("PBFT application execution requires exactly 3f + 1 replicas"));
        }
        Ok(Self {
            node: PbftNode::new(replica_id, config, transport)?,
            application: Mutex::new(ApplicationState {
                machine,
                last_applied: SequenceNumber::new(0),
                responses: HashMap::new(),
                identities: HashSet::new(),
            }),
            proposals: crate::sync::Mutex::new(()),
        })
    }

    /// Highest sequence fully applied to this driver's application.
    ///
    /// This is distinct from the protocol's commit watermark. A poisoned
    /// application returns an error instead of pretending execution completed.
    pub fn last_applied(&self) -> Result<SequenceNumber> {
        Ok(self.lock_application()?.last_applied)
    }

    /// Look up a terminal result for this exact client request.
    ///
    /// `None` means no application result is available, never a fabricated
    /// success. Replays retain the original sequence, view, and timestamp.
    pub fn committed_response(
        &self,
        request: &ConsensusRequest,
    ) -> Result<Option<ConsensusResponse>> {
        let digest = MessageDigest::of(request)?;
        Ok(self.lock_application()?.responses.get(&digest).cloned())
    }

    /// Admit a request on the primary, or forward it to the current primary.
    ///
    /// The caller must also drive incoming messages. Cancellation or a transport
    /// error does not prove non-delivery; do not interpret it as a rollback of
    /// committed application effects. An exact replay can recover a retained
    /// response without executing the application a second time. On the
    /// primary, retrying an unfinished request retransmits its original
    /// proposal and sequence, including after cancellation or an ambiguous send.
    pub async fn submit_request(&self, cx: &Cx, request: ConsensusRequest) -> Result<()> {
        let _proposal = self.proposals.lock(cx).await.map_err(|error| {
            let kind = match error {
                crate::sync::LockError::Cancelled => ErrorKind::Cancelled,
                _ => ErrorKind::InvalidStateTransition,
            };
            Error::new(kind).with_message(format!("PBFT proposal admission failed: {error}"))
        })?;
        self.apply_ready(cx)?;
        if self.committed_response(&request)?.is_some() {
            return Ok(());
        }

        if self.node.is_primary() {
            let message = self.primary_proposal(cx, request)?;
            timeout(
                cx.now(),
                self.node.config.preprepare_timeout,
                self.node.transport.broadcast(message),
            )
            .await
            .map_err(|_| Error::new(ErrorKind::DeadlineExceeded))??;
            self.node.drain_committed().await?;
        } else {
            let primary = {
                let state = self.node.state.lock().unwrap();
                ReplicaId::new(state.view.primary(self.node.config.replica_count).to_string())
            };
            timeout(
                cx.now(),
                self.node.config.preprepare_timeout,
                self.node
                    .transport
                    .send_to_replica(&primary, PbftMessage::Request(request)),
            )
            .await
            .map_err(|_| Error::new(ErrorKind::DeadlineExceeded))??;
        }
        self.apply_ready(cx)
    }

    fn primary_proposal(&self, cx: &Cx, request: ConsensusRequest) -> Result<PbftMessage> {
        let mut state = self.node.state.lock().unwrap();
        // A failed send may already have reached peers. Never roll back or
        // reassign that sequence; retransmit the exact retained proposal.
        if let Some((sequence, entry)) = state
            .log
            .iter()
            .filter(|(sequence, entry)| {
                **sequence > state.last_executed
                    && entry.batch.requests.iter().any(|existing| {
                        existing.client_id == request.client_id
                            && existing.timestamp == request.timestamp
                            && existing.operation == request.operation
                    })
            })
            .min_by_key(|(sequence, _)| **sequence)
        {
            return Ok(PbftMessage::PrePrepare {
                view: entry.view,
                sequence: *sequence,
                digest: entry.digest.clone(),
                batch: entry.batch.clone(),
                replica_id: self.node.replica_id.clone(),
            });
        }

        let sequence = state.sequence;
        let next = sequence.0.checked_add(1).ok_or_else(|| {
            Error::new(ErrorKind::InvalidStateTransition)
                .with_message("PBFT proposal sequence space is exhausted")
        })?;
        let view = state.view;
        let mut batch = ConsensusBatch::new(vec![request]);
        batch.timestamp = cx.now();
        let digest = MessageDigest::of(&batch)?;
        if state.log.contains_key(&sequence) {
            return Err(Error::new(ErrorKind::InvalidStateTransition)
                .with_message(format!("PBFT proposal sequence {sequence} is already reserved")));
        }
        state.log.insert(
            sequence,
            LogEntry {
                batch: batch.clone(),
                digest: digest.clone(),
                view,
                preprepared: true,
                prepare_msgs: HashMap::new(),
                commit_msgs: HashMap::new(),
                result: None,
            },
        );
        state.sequence = SequenceNumber::new(next);
        Ok(PbftMessage::PrePrepare {
            view,
            sequence,
            digest,
            batch,
            replica_id: self.node.replica_id.clone(),
        })
    }

    /// Advance the protocol and apply every newly committed batch in order.
    pub async fn process_message(&self, cx: &Cx, message: PbftMessage) -> Result<()> {
        if let PbftMessage::Request(request) = message {
            return self.submit_request(cx, request).await;
        }
        self.node.process_message(cx, message).await?;
        self.apply_ready(cx)
    }

    /// Run the message pump in a caller-owned task.
    ///
    /// This does not spawn or detach any work. The transport is responsible for
    /// terminating its receive operation when its owning task is shutting down.
    pub async fn run(&self, cx: &Cx) -> Result<()> {
        loop {
            let message = self.node.transport.receive().await?;
            self.process_message(cx, message).await?;
        }
    }

    fn lock_application(&self) -> Result<std::sync::MutexGuard<'_, ApplicationState<S>>> {
        self.application.lock().map_err(|_| {
            Error::new(ErrorKind::InvalidStateTransition).with_message(
                "PBFT application panicked; refusing to retry possibly applied operations",
            )
        })
    }

    fn apply_ready(&self, cx: &Cx) -> Result<()> {
        // There are no awaits while the application is locked. Serializing
        // application access also makes concurrent message deliveries apply a
        // committed prefix exactly once, rather than racing on a cloned batch.
        let mut application = self.lock_application()?;
        loop {
            let sequence = application.last_applied.next();
            let (view, batch) = {
                let state = self.node.state.lock().unwrap();
                if sequence > state.last_executed {
                    return Ok(());
                }
                let entry = state.log.get(&sequence).ok_or_else(|| {
                    Error::new(ErrorKind::InvalidStateTransition)
                        .with_message(format!("PBFT committed log is missing {sequence}"))
                })?;
                if entry.result.is_none() {
                    return Err(Error::new(ErrorKind::InvalidStateTransition)
                        .with_message(format!("PBFT committed log is incomplete at {sequence}")));
                }
                (entry.view, entry.batch.clone())
            };

            for request in &batch.requests {
                let digest = MessageDigest::of(request)?;
                let identity = MessageDigest::of(&(&request.client_id, request.timestamp))?;
                let ApplicationState {
                    machine,
                    responses,
                    identities,
                    ..
                } = &mut *application;
                let std::collections::hash_map::Entry::Vacant(slot) = responses.entry(digest) else {
                    continue;
                };
                let result = if identities.insert(identity) {
                    machine.apply(request)
                } else {
                    Outcome::Err(
                        "PBFT client id and timestamp were reused for a different operation"
                            .to_owned(),
                    )
                };
                slot.insert(ConsensusResponse {
                    view,
                    sequence,
                    result,
                    replica_id: self.node.replica_id.clone(),
                    timestamp: cx.now(),
                });
            }
            application.last_applied = sequence;
        }
    }
}

#[cfg(test)]
mod progress_tests {
    use super::*;
    use std::future::{Future, ready};

    #[derive(Default)]
    struct RecordingTransport {
        sent: Mutex<Vec<PbftMessage>>,
        recipients: Mutex<Vec<ReplicaId>>,
    }

    impl PbftTransport for RecordingTransport {
        fn send_to_replica(
            &self,
            replica_id: &ReplicaId,
            message: PbftMessage,
        ) -> impl Future<Output = Result<()>> + Send {
            self.recipients.lock().unwrap().push(replica_id.clone());
            self.sent.lock().unwrap().push(message);
            ready(Ok(()))
        }

        fn broadcast(&self, message: PbftMessage) -> impl Future<Output = Result<()>> + Send {
            self.sent.lock().unwrap().push(message);
            ready(Ok(()))
        }

        fn receive(&self) -> impl Future<Output = Result<PbftMessage>> + Send {
            ready(Err(Error::new(ErrorKind::ChannelEmpty)))
        }
    }

    fn backup() -> PbftNode<RecordingTransport> {
        PbftNode::new(
            ReplicaId::new("1".to_owned()),
            PbftConfig::new(4, 1).unwrap(),
            RecordingTransport::default(),
        )
        .unwrap()
    }

    fn preprepare(
        node: &PbftNode<RecordingTransport>,
        cx: &Cx,
        sequence: u64,
    ) -> MessageDigest {
        let batch = ConsensusBatch::new(vec![ConsensusRequest::new(
            "client".to_owned(),
            Time::from_millis(sequence),
            sequence.to_le_bytes().to_vec(),
        )]);
        let digest = MessageDigest::of(&batch).unwrap();
        futures_lite::future::block_on(node.process_message(
            cx,
            PbftMessage::PrePrepare {
                view: ViewNumber::new(0),
                sequence: SequenceNumber::new(sequence),
                digest: digest.clone(),
                batch,
                replica_id: ReplicaId::new("0".to_owned()),
            },
        ))
        .unwrap();
        digest
    }

    fn vote(sequence: u64, digest: &MessageDigest, event: usize) -> PbftMessage {
        let replica_id = ReplicaId::new(if event % 2 == 0 { "0" } else { "2" }.to_owned());
        if event < 2 {
            PbftMessage::Prepare {
                view: ViewNumber::new(0),
                sequence: SequenceNumber::new(sequence),
                digest: digest.clone(),
                replica_id,
            }
        } else {
            PbftMessage::Commit {
                view: ViewNumber::new(0),
                sequence: SequenceNumber::new(sequence),
                digest: digest.clone(),
                replica_id,
            }
        }
    }

    #[test]
    fn every_prepare_commit_permutation_executes_only_after_both_quorums() {
        let cx = Cx::for_testing();
        let mut permutations = 0;
        for a in 0..4 {
            for b in 0..4 {
                for c in 0..4 {
                    for d in 0..4 {
                        if a == b || a == c || a == d || b == c || b == d || c == d {
                            continue;
                        }
                        let node = backup();
                        let digest = preprepare(&node, &cx, 1);
                        let mut prepares = 0;
                        let mut commits = 0;
                        for event in [a, b, c, d] {
                            futures_lite::future::block_on(
                                node.process_message(&cx, vote(1, &digest, event)),
                            )
                            .unwrap();
                            if event < 2 {
                                prepares += 1;
                            } else {
                                commits += 1;
                            }
                            let expected = u64::from(prepares == 2 && commits == 2);
                            assert_eq!(node.last_executed(), SequenceNumber::new(expected));
                        }
                        permutations += 1;
                    }
                }
            }
        }
        assert_eq!(permutations, 24);
    }

    #[test]
    fn late_prepare_drains_already_committed_successors_without_extra_packets() {
        let cx = Cx::for_testing();
        let node = backup();
        let first = preprepare(&node, &cx, 1);
        let second = preprepare(&node, &cx, 2);
        for event in [0, 1, 2, 3] {
            futures_lite::future::block_on(node.process_message(&cx, vote(2, &second, event)))
                .unwrap();
        }
        assert_eq!(node.last_executed(), SequenceNumber::new(0));
        for event in [2, 3, 0, 1] {
            futures_lite::future::block_on(node.process_message(&cx, vote(1, &first, event)))
                .unwrap();
        }
        assert_eq!(node.last_executed(), SequenceNumber::new(2));
    }

    #[test]
    fn single_replica_executes_without_transport_loopback() {
        let node = PbftNode::new(
            ReplicaId::new("0".to_owned()),
            PbftConfig::new(1, 0).unwrap(),
            RecordingTransport::default(),
        )
        .unwrap();
        let cx = Cx::for_testing();
        for sequence in 1..=2 {
            let request = ConsensusRequest::new(
                "client".to_owned(),
                Time::from_millis(sequence),
                vec![42],
            );
            futures_lite::future::block_on(node.submit_request(&cx, request)).unwrap();
            assert_eq!(node.last_executed(), SequenceNumber::new(sequence));
        }
    }

    #[test]
    fn duplicate_votes_cannot_replace_distinct_quorum_members() {
        let cx = Cx::for_testing();
        let node = backup();
        let digest = preprepare(&node, &cx, 1);
        for _ in 0..4 {
            for event in [0, 2] {
                futures_lite::future::block_on(node.process_message(&cx, vote(1, &digest, event)))
                    .unwrap();
            }
        }
        assert_eq!(node.last_executed(), SequenceNumber::new(0));
        for event in [3, 1] {
            futures_lite::future::block_on(node.process_message(&cx, vote(1, &digest, event)))
                .unwrap();
        }
        assert_eq!(node.last_executed(), SequenceNumber::new(1));
    }

    #[test]
    fn numeric_replica_aliases_cannot_inflate_either_quorum() {
        let cx = Cx::for_testing();
        let node = backup();
        let digest = preprepare(&node, &cx, 1);
        for alias in ["0", "00", "000"] {
            for mut message in [vote(1, &digest, 0), vote(1, &digest, 2)] {
                match &mut message {
                    PbftMessage::Prepare { replica_id, .. }
                    | PbftMessage::Commit { replica_id, .. } => {
                        *replica_id = ReplicaId::new(alias.to_owned());
                    }
                    _ => unreachable!(),
                }
                futures_lite::future::block_on(node.process_message(&cx, message)).unwrap();
            }
        }
        assert_eq!(node.last_executed(), SequenceNumber::new(0));
        {
            let state = node.state.lock().unwrap();
            let entry = &state.log[&SequenceNumber::new(1)];
            assert_eq!(entry.prepare_msgs.len(), 1);
            assert_eq!(entry.commit_msgs.len(), 1);
        }
        for event in [3, 1] {
            futures_lite::future::block_on(node.process_message(&cx, vote(1, &digest, event)))
                .unwrap();
        }
        assert_eq!(node.last_executed(), SequenceNumber::new(1));
    }

    #[test]
    fn duplicate_preprepare_still_verifies_the_supplied_payload() {
        let cx = Cx::for_testing();
        let node = backup();
        let digest = preprepare(&node, &cx, 1);
        let original_batch = node.state.lock().unwrap().log[&SequenceNumber::new(1)]
            .batch
            .clone();
        let mut tampered_batch = original_batch.clone();
        tampered_batch.requests[0].operation.push(255);
        let duplicate = |batch| PbftMessage::PrePrepare {
            view: ViewNumber::new(0),
            sequence: SequenceNumber::new(1),
            digest: digest.clone(),
            batch,
            replica_id: ReplicaId::new("0".to_owned()),
        };
        assert!(
            futures_lite::future::block_on(node.process_message(&cx, duplicate(tampered_batch)))
                .is_err()
        );
        futures_lite::future::block_on(node.process_message(&cx, duplicate(original_batch)))
            .unwrap();
        assert_eq!(
            MessageDigest::of(&node.state.lock().unwrap().log[&SequenceNumber::new(1)].batch)
                .unwrap(),
            digest
        );
    }

    #[test]
    fn configuration_arithmetic_fails_closed_on_overflow() {
        assert!(PbftConfig::new(usize::MAX, usize::MAX).is_err());
        assert!(PbftConfig::new(0, 0).is_err());
        let mut config = PbftConfig::new(4, 1).unwrap();
        config.fault_tolerance = usize::MAX;
        assert!(!config.is_valid());
        assert_eq!(config.quorum_size(), usize::MAX);
        assert!(
            PbftNode::new(
                ReplicaId::new("0".to_owned()),
                config,
                RecordingTransport::default(),
            )
            .is_err()
        );
    }

    #[test]
    fn execution_rejects_zero_batch_capacity_and_unsafe_quorum_topology() {
        let mut empty_batch = PbftConfig::new(4, 1).unwrap();
        empty_batch.max_batch_size = 0;
        for config in [empty_batch, PbftConfig::new(5, 1).unwrap()] {
            assert!(
                PbftExecution::new(
                    ReplicaId::new("0".to_owned()),
                    config,
                    RecordingTransport::default(),
                    |request: &ConsensusRequest| Outcome::Ok(request.operation.clone()),
                )
                .is_err()
            );
        }
    }

    fn execution(
        calls: Arc<Mutex<Vec<Vec<u8>>>>,
    ) -> PbftExecution<RecordingTransport, impl PbftStateMachine> {
        PbftExecution::new(
            ReplicaId::new("1".to_owned()),
            PbftConfig::new(4, 1).unwrap(),
            RecordingTransport::default(),
            move |request: &ConsensusRequest| {
                calls.lock().unwrap().push(request.operation.clone());
                let mut result = request.operation.clone();
                result.push(99);
                Outcome::Ok(result)
            },
        )
        .unwrap()
    }

    fn propose<S: PbftStateMachine>(
        driver: &PbftExecution<RecordingTransport, S>,
        cx: &Cx,
        sequence: u64,
        requests: Vec<ConsensusRequest>,
    ) -> MessageDigest {
        let batch = ConsensusBatch::new(requests);
        let digest = MessageDigest::of(&batch).unwrap();
        futures_lite::future::block_on(driver.process_message(
            cx,
            PbftMessage::PrePrepare {
                view: ViewNumber::new(0),
                sequence: SequenceNumber::new(sequence),
                digest: digest.clone(),
                batch,
                replica_id: ReplicaId::new("0".to_owned()),
            },
        ))
        .unwrap();
        digest
    }

    fn finish<S: PbftStateMachine>(
        driver: &PbftExecution<RecordingTransport, S>,
        cx: &Cx,
        sequence: u64,
        digest: &MessageDigest,
    ) {
        // Complete commits before prepares to exercise the repaired path too.
        for event in [2, 3, 0, 1] {
            futures_lite::future::block_on(driver.process_message(cx, vote(sequence, digest, event)))
                .unwrap();
        }
    }

    #[test]
    fn execution_forwards_to_primary_and_never_fabricates_a_result() {
        let cx = Cx::for_testing();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let driver = execution(Arc::clone(&calls));
        let request = ConsensusRequest::new("client".to_owned(), Time::from_millis(1), vec![7]);
        futures_lite::future::block_on(driver.submit_request(&cx, request.clone())).unwrap();
        assert_eq!(
            *driver.node.transport.recipients.lock().unwrap(),
            vec![ReplicaId::new("0".to_owned())]
        );
        assert!(driver.committed_response(&request).unwrap().is_none());
        assert!(calls.lock().unwrap().is_empty());
        let digest = propose(&driver, &cx, 1, vec![request.clone()]);
        assert!(driver.committed_response(&request).unwrap().is_none());
        let before_execution = cx.now();
        finish(&driver, &cx, 1, &digest);
        let response = driver.committed_response(&request).unwrap().unwrap();
        assert_eq!(response.result, Outcome::Ok(vec![7, 99]));
        assert_eq!(response.sequence, SequenceNumber::new(1));
        assert_eq!(response.view, ViewNumber::new(0));
        assert_eq!(response.replica_id, ReplicaId::new("1".to_owned()));
        assert!(response.timestamp >= before_execution);
        assert!(response.timestamp <= cx.now());
        assert_eq!(driver.last_applied().unwrap(), SequenceNumber::new(1));
    }

    #[test]
    fn execution_replays_once_and_rejects_conflicting_client_identity() {
        let cx = Cx::for_testing();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let driver = execution(Arc::clone(&calls));
        let request = ConsensusRequest::new("client".to_owned(), Time::from_millis(1), vec![7]);
        for sequence in 1..=2 {
            // Include an exact duplicate inside each batch as well as across batches.
            let digest = propose(&driver, &cx, sequence, vec![request.clone(), request.clone()]);
            finish(&driver, &cx, sequence, &digest);
        }
        let original = driver.committed_response(&request).unwrap().unwrap();
        assert_eq!(original.sequence, SequenceNumber::new(1));
        assert_eq!(original.result, Outcome::Ok(vec![7, 99]));
        let mut conflict = request.clone();
        conflict.operation = vec![8];
        let digest = propose(&driver, &cx, 3, vec![conflict.clone()]);
        finish(&driver, &cx, 3, &digest);
        let rejected = driver.committed_response(&conflict).unwrap().unwrap();
        assert!(matches!(rejected.result, Outcome::Err(message) if message.contains("reused")));
        assert_eq!(rejected.sequence, SequenceNumber::new(3));
        assert_eq!(*calls.lock().unwrap(), vec![vec![7]]);
        assert_eq!(driver.last_applied().unwrap(), SequenceNumber::new(3));
    }

    #[test]
    fn execution_applies_out_of_order_commits_in_log_order() {
        let cx = Cx::for_testing();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let driver = execution(Arc::clone(&calls));
        let first = ConsensusRequest::new("client".to_owned(), Time::from_millis(1), vec![1]);
        let second = ConsensusRequest::new("client".to_owned(), Time::from_millis(2), vec![2]);
        let first_digest = propose(&driver, &cx, 1, vec![first.clone()]);
        let second_digest = propose(&driver, &cx, 2, vec![second.clone()]);
        finish(&driver, &cx, 2, &second_digest);
        assert!(calls.lock().unwrap().is_empty());
        assert!(driver.committed_response(&second).unwrap().is_none());
        finish(&driver, &cx, 1, &first_digest);
        assert_eq!(*calls.lock().unwrap(), vec![vec![1], vec![2]]);
        assert_eq!(driver.last_applied().unwrap(), SequenceNumber::new(2));
        assert_eq!(
            driver.committed_response(&second).unwrap().unwrap().result,
            Outcome::Ok(vec![2, 99])
        );
    }

    #[test]
    fn execution_preserves_application_errors_and_solo_replay_receipts() {
        let cx = Cx::for_testing();
        let driver = PbftExecution::new(
            ReplicaId::new("0".to_owned()),
            PbftConfig::new(1, 0).unwrap(),
            RecordingTransport::default(),
            |request: &ConsensusRequest| {
                if request.operation.is_empty() {
                    Outcome::Err("empty operation".to_owned())
                } else {
                    Outcome::Ok(request.operation.clone())
                }
            },
        )
        .unwrap();
        let invalid = ConsensusRequest::new("client".to_owned(), Time::from_millis(1), vec![]);
        let valid = ConsensusRequest::new("client".to_owned(), Time::from_millis(2), vec![8]);
        for request in [&invalid, &valid, &invalid] {
            futures_lite::future::block_on(driver.submit_request(&cx, request.clone())).unwrap();
        }
        assert_eq!(
            driver.committed_response(&invalid).unwrap().unwrap().result,
            Outcome::Err("empty operation".to_owned())
        );
        assert_eq!(
            driver.committed_response(&valid).unwrap().unwrap().result,
            Outcome::Ok(vec![8])
        );
        assert_eq!(driver.last_applied().unwrap(), SequenceNumber::new(2));
    }

    #[test]
    fn execution_panic_fails_closed_without_reapplying() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let cx = Cx::for_testing();
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        let driver = PbftExecution::new(
            ReplicaId::new("0".to_owned()),
            PbftConfig::new(1, 0).unwrap(),
            RecordingTransport::default(),
            move |_request: &ConsensusRequest| -> Outcome<Vec<u8>, String> {
                seen.fetch_add(1, Ordering::SeqCst);
                panic!("application failed after mutation")
            },
        )
        .unwrap();
        let request = ConsensusRequest::new("client".to_owned(), Time::from_millis(1), vec![1]);
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            futures_lite::future::block_on(driver.submit_request(&cx, request.clone()))
        }));
        assert!(panicked.is_err());
        assert!(driver.last_applied().is_err());
        assert!(driver.committed_response(&request).is_err());
        assert!(futures_lite::future::block_on(driver.submit_request(&cx, request)).is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn execution_retry_retains_proposal_after_ambiguous_transport_error() {
        use std::sync::atomic::{AtomicBool, Ordering};

        #[derive(Default)]
        struct AmbiguousTransport {
            failed_once: AtomicBool,
            sent: Mutex<Vec<PbftMessage>>,
        }

        impl PbftTransport for AmbiguousTransport {
            fn send_to_replica(
                &self,
                _replica_id: &ReplicaId,
                message: PbftMessage,
            ) -> impl Future<Output = Result<()>> + Send {
                self.broadcast(message)
            }

            fn broadcast(&self, message: PbftMessage) -> impl Future<Output = Result<()>> + Send {
                self.sent.lock().unwrap().push(message);
                let result = if self.failed_once.swap(true, Ordering::SeqCst) {
                    Ok(())
                } else {
                    Err(Error::new(ErrorKind::ConnectionLost))
                };
                ready(result)
            }

            fn receive(&self) -> impl Future<Output = Result<PbftMessage>> + Send {
                ready(Err(Error::new(ErrorKind::ChannelEmpty)))
            }
        }

        let cx = Cx::for_testing();
        let driver = PbftExecution::new(
            ReplicaId::new("0".to_owned()),
            PbftConfig::new(1, 0).unwrap(),
            AmbiguousTransport::default(),
            |request: &ConsensusRequest| Outcome::Ok(request.operation.clone()),
        )
        .unwrap();
        let request = ConsensusRequest::new("client".to_owned(), Time::from_millis(1), vec![6]);
        assert!(
            futures_lite::future::block_on(driver.submit_request(&cx, request.clone())).is_err()
        );
        assert!(driver.committed_response(&request).unwrap().is_none());
        futures_lite::future::block_on(driver.submit_request(&cx, request.clone())).unwrap();
        let sent = driver.node.transport.sent.lock().unwrap();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0].digest().unwrap(), sent[1].digest().unwrap());
        let response = driver.committed_response(&request).unwrap().unwrap();
        assert_eq!(response.sequence, SequenceNumber::new(1));
        assert_eq!(response.result, Outcome::Ok(vec![6]));
        assert_eq!(driver.last_applied().unwrap(), SequenceNumber::new(1));
    }
}
