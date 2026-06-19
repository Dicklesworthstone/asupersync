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

use crate::cx::Cx;
use crate::error::{Error, ErrorKind, Result};
use crate::time::timeout;
use crate::types::{Outcome, Time};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
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
        if replica_count < 3 * fault_tolerance + 1 {
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
        self.replica_count > 3 * self.fault_tolerance
    }

    /// Get the minimum number of signatures needed for a quorum.
    pub fn quorum_size(&self) -> usize {
        2 * self.fault_tolerance + 1
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
        _cx: &Cx,
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
            Time::from_millis(0),
            self.config.preprepare_timeout,
            self.transport.broadcast(message),
        )
        .await
        .map_err(|_| Error::new(ErrorKind::DeadlineExceeded))?
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
        _cx: &Cx,
        view: ViewNumber,
        sequence: SequenceNumber,
        digest: MessageDigest,
        batch: ConsensusBatch,
        replica_id: ReplicaId,
    ) -> Result<()> {
        self.validate_preprepare_primary(view, &replica_id)?;
        // Validate view and primary
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
            }
        }

        // Verify digest
        let computed_digest = MessageDigest::of(&batch)?;
        if digest != computed_digest {
            return Err(Error::new(ErrorKind::InvalidInput));
        }

        // Create or mark the log entry without overwriting accumulated messages.
        {
            let mut state = self.state.lock().unwrap();
            if let Some(entry) = state.log.get_mut(&sequence) {
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
            Time::from_millis(0),
            self.config.prepare_timeout,
            self.transport.broadcast(prepare_msg),
        )
        .await
        .map_err(|_| Error::new(ErrorKind::DeadlineExceeded))?
    }

    /// Handle prepare message from replica.
    async fn handle_prepare(
        &self,
        _cx: &Cx,
        view: ViewNumber,
        sequence: SequenceNumber,
        digest: MessageDigest,
        replica_id: ReplicaId,
    ) -> Result<()> {
        self.validate_remote_replica(&replica_id)?;
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
                Time::from_millis(0),
                self.config.commit_timeout,
                self.transport.broadcast(commit_msg),
            )
            .await
            .map_err(|_| Error::new(ErrorKind::DeadlineExceeded))??;
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
        self.validate_remote_replica(&replica_id)?;
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

        // Execute the batch if we have quorum and it's the next in sequence
        if should_execute {
            self.execute_batch(sequence).await?;
        }

        Ok(())
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

    fn validate_remote_replica(&self, replica_id: &ReplicaId) -> Result<()> {
        let index = parse_replica_index(replica_id, self.config.replica_count)?;
        if index == self.replica_index {
            return Err(Error::new(ErrorKind::InvalidInput).with_message(format!(
                "PBFT rejected self-authored remote quorum message from {replica_id}"
            )));
        }
        Ok(())
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
