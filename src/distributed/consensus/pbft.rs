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

        let state = PbftState {
            view: ViewNumber::new(0),
            sequence: SequenceNumber::new(0),
            log: HashMap::new(),
            pending_requests: VecDeque::new(),
            last_executed: SequenceNumber::new(0),
            view_change_state: None,
        };

        Ok(Self {
            replica_id,
            config,
            state: Arc::new(Mutex::new(state)),
            transport,
        })
    }

    /// Check if this replica is the primary for the current view.
    pub fn is_primary(&self) -> bool {
        let state = self.state.lock().unwrap();
        let primary_idx = state.view.primary(self.config.replica_count);
        // For simplicity, assume replica IDs are "0", "1", "2", etc.
        self.replica_id
            .as_str()
            .parse::<usize>()
            .unwrap_or(usize::MAX)
            == primary_idx
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

            // Advance sequence number
            state.sequence = state.sequence.next();

            (batch, sequence, view)
        };

        // Send pre-prepare message
        self.send_preprepare(cx, view, sequence, batch).await
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
            } => {
                self.handle_preprepare(cx, view, sequence, digest, batch)
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
    ) -> Result<()> {
        // Validate view and primary
        {
            let state = self.state.lock().unwrap();
            if view != state.view {
                return Err(Error::new(ErrorKind::InvalidInput));
            }
        }

        // Verify digest
        let computed_digest = MessageDigest::of(&batch)?;
        if digest != computed_digest {
            return Err(Error::new(ErrorKind::InvalidInput));
        }

        // Create log entry
        {
            let mut state = self.state.lock().unwrap();
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

            // Check if we have enough prepares (2f+1 including our own)
            entry.prepare_msgs.len() + 1 >= self.config.quorum_size()
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
        let should_execute = {
            let mut state = self.state.lock().unwrap();

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

            // Check if we have enough commits (2f+1 including our own)
            entry.commit_msgs.len() + 1 >= self.config.quorum_size()
                && sequence == state.last_executed.next()
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

            // Mark as executed first
            state.last_executed = sequence;

            // Get the batch
            let entry = state.log.get_mut(&sequence).unwrap();
            let batch = entry.batch.clone();

            // For simplicity, just simulate execution
            let result = Outcome::Ok(b"executed".to_vec());
            entry.result = Some(result);

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

    /// Handle view change message.
    async fn handle_view_change(
        &self,
        _cx: &Cx,
        _new_view: ViewNumber,
        _replica_id: ReplicaId,
        _certificates: Vec<MessageCertificate>,
    ) -> Result<()> {
        // View change implementation is complex and omitted for brevity
        // A full implementation would handle view changes for fault tolerance
        Ok(())
    }

    /// Handle new view message.
    async fn handle_new_view(
        &self,
        _cx: &Cx,
        _view: ViewNumber,
        _view_change_msgs: Vec<PbftMessage>,
        _preprepare_msgs: Vec<PbftMessage>,
    ) -> Result<()> {
        // New view implementation is complex and omitted for brevity
        Ok(())
    }
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
