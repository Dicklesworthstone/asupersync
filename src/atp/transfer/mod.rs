//! ATP per-transfer actor state machine.
//!
//! `TransferActor` is the single owner for one transfer session. It owns
//! manifest identity, peer capability decisions, path progress, scheduler
//! feedback inputs, commit state, and the obligation ledger for request/reply
//! protocol edges.

use super::actor::{
    TransferActorId, TransferActorTopology, TransferChildRegion, TransferObligationId,
    TransferRegionId, TransferTopologyError,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Deterministic transfer id bound to peers, nonce, and manifest root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TransferId([u8; 32]);

impl TransferId {
    /// Construct a transfer id from canonical bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Derive a stable transfer id for tests and transcripts.
    #[must_use]
    pub fn derive(
        local_peer: [u8; 32],
        remote_peer: [u8; 32],
        nonce: [u8; 32],
        root: [u8; 32],
    ) -> Self {
        let mut out = [0u8; 32];
        for (index, byte) in local_peer
            .iter()
            .chain(remote_peer.iter())
            .chain(nonce.iter())
            .chain(root.iter())
            .enumerate()
        {
            let slot = index % 32;
            out[slot] = out[slot]
                .wrapping_add(*byte)
                .rotate_left((index % 8) as u32)
                ^ (index as u8).wrapping_mul(17);
        }
        Self(out)
    }

    /// Borrow canonical transfer-id bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Idempotency key for replay-safe transfer commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IdempotencyKey(u128);

impl IdempotencyKey {
    /// Construct an idempotency key.
    #[must_use]
    pub const fn new(raw: u128) -> Self {
        Self(raw)
    }
}

/// Manifest summary owned by the transfer actor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferManifestRef {
    /// Manifest schema version.
    pub schema_version: u32,
    /// Manifest or graph Merkle root.
    pub merkle_root: [u8; 32],
    /// Number of objects covered by the manifest.
    pub object_count: u64,
}

/// Peer capability snapshot accepted for this transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerCapabilities {
    /// Peer can use an online relay path.
    pub relay: bool,
    /// Peer can use encrypted store-and-forward mailbox.
    pub mailbox: bool,
    /// Peer can participate in swarm transfer.
    pub swarm: bool,
    /// Maximum number of in-flight request/reply obligations.
    pub max_inflight_obligations: usize,
}

impl Default for PeerCapabilities {
    fn default() -> Self {
        Self {
            relay: false,
            mailbox: false,
            swarm: false,
            max_inflight_obligations: 8,
        }
    }
}

/// Transfer progress and scheduler input surface.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TransferProgress {
    /// Bytes offered by the sender.
    pub offered_bytes: u64,
    /// Bytes verified by the receiver.
    pub verified_bytes: u64,
    /// Bytes committed to exposed output.
    pub committed_bytes: u64,
    /// Repair symbols processed.
    pub repair_symbols: u64,
    /// Selected path id, if a path has won.
    pub selected_path: Option<u64>,
}

/// Transfer actor states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TransferState {
    /// Sender has offered a transfer.
    Offered,
    /// Receiver accepted the offer and capability grant.
    Accepted,
    /// Object bytes are moving.
    Running,
    /// Transfer is paused with journal state intact.
    Paused,
    /// Cancellation requested and finalizers are draining.
    Cancelling,
    /// Transfer failed with a typed failure class.
    Failed,
    /// Manifest commit and finalizer proof completed.
    Committed,
    /// Transfer resumed from journal state.
    Resumed,
    /// Store-and-forward mailbox accepted encrypted transfer state.
    MailboxStored,
    /// Online relay accepted forwarding responsibility.
    RelayForwarded,
    /// Committed transfer is now serving verified data to peers.
    Seeded,
    /// Swarm peers are assisting with verified chunks or repair symbols.
    SwarmAssisted,
}

impl TransferState {
    /// Every state covered by ATP-E1.
    pub const ALL: [Self; 12] = [
        Self::Offered,
        Self::Accepted,
        Self::Running,
        Self::Paused,
        Self::Cancelling,
        Self::Failed,
        Self::Committed,
        Self::Resumed,
        Self::MailboxStored,
        Self::RelayForwarded,
        Self::Seeded,
        Self::SwarmAssisted,
    ];

    /// Whether this state should have no live child obligations.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Cancelling | Self::Failed | Self::Committed | Self::Seeded
        )
    }
}

/// Cancellation phase preserved in logs and replay artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferCancelPhase {
    /// User or parent requested cancellation.
    Requested,
    /// Losers, writers, and relay grants are draining.
    Draining,
    /// Finalizers completed.
    Finalized,
}

/// Failure class preserved across actor logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferFailureKind {
    /// Remote peer failed or violated policy.
    Peer,
    /// Disk, sparse writer, or commit finalizer failed.
    Disk,
    /// Repair-symbol encode/decode failed.
    Repair,
    /// Manifest or verifier rejected input.
    Verification,
    /// Transfer exceeded a resource budget.
    ResourceBudget,
}

/// Actor command variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferCommandKind {
    /// Accept an offered transfer.
    Accept { obligation: TransferObligationId },
    /// Select a path and begin movement.
    Start {
        /// Winning path identifier.
        path_id: u64,
        /// Request/reply obligation for the start edge.
        obligation: TransferObligationId,
    },
    /// Pause a running transfer.
    Pause,
    /// Resume from a journal position.
    Resume {
        /// Last durable journal sequence observed before resume.
        journal_seq: u64,
        /// Request/reply obligation for the resume edge.
        obligation: TransferObligationId,
    },
    /// Begin cancellation.
    Cancel { phase: TransferCancelPhase },
    /// Fail with a stable class.
    Fail { kind: TransferFailureKind },
    /// Commit verified output.
    Commit { obligation: TransferObligationId },
    /// Store encrypted state in mailbox.
    StoreMailbox { obligation: TransferObligationId },
    /// Forward encrypted bytes through relay.
    ForwardRelay { obligation: TransferObligationId },
    /// Seed committed data to peers.
    Seed { obligation: TransferObligationId },
    /// Join a swarm-assisted transfer.
    JoinSwarm { obligation: TransferObligationId },
    /// Stop the actor after terminal quiescence.
    Shutdown,
}

impl TransferCommandKind {
    fn obligation(&self) -> Option<TransferObligationId> {
        match self {
            Self::Accept { obligation }
            | Self::Start { obligation, .. }
            | Self::Resume { obligation, .. }
            | Self::Commit { obligation }
            | Self::StoreMailbox { obligation }
            | Self::ForwardRelay { obligation }
            | Self::Seed { obligation }
            | Self::JoinSwarm { obligation } => Some(*obligation),
            Self::Pause | Self::Cancel { .. } | Self::Fail { .. } | Self::Shutdown => None,
        }
    }
}

/// Transfer actor command with an idempotency key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferCommand {
    /// Idempotency key.
    pub key: IdempotencyKey,
    /// Command payload.
    pub kind: TransferCommandKind,
}

impl TransferCommand {
    /// Construct a command.
    #[must_use]
    pub const fn new(key: IdempotencyKey, kind: TransferCommandKind) -> Self {
        Self { key, kind }
    }
}

/// Settled obligation outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObligationOutcome {
    /// Command transition committed.
    Committed,
    /// Command transition aborted.
    Aborted,
}

/// Journal entry emitted by every non-duplicate command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferJournalEntry {
    /// Monotonic journal sequence.
    pub seq: u64,
    /// Actor that emitted this transition.
    pub actor_id: TransferActorId,
    /// Transfer governed by this actor.
    pub transfer_id: TransferId,
    /// Idempotency key for replay.
    pub key: IdempotencyKey,
    /// Previous state.
    pub previous: TransferState,
    /// New state.
    pub next: TransferState,
    /// Settled obligation, if the command required one.
    pub obligation: Option<(TransferObligationId, ObligationOutcome)>,
    /// Parent region that supervises the actor.
    pub supervisor_region: TransferRegionId,
    /// Region that owns the actor state.
    pub actor_region: TransferRegionId,
    /// Child topology snapshot at the time of transition.
    pub child_topology: Vec<TransferChildRegion>,
    /// Cancellation phase carried by this transition.
    pub cancel_phase: Option<TransferCancelPhase>,
    /// Deterministic replay/crashpack path hint for this transition.
    pub replay_crashpack_path: String,
}

/// Reply returned by the transfer actor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferReply {
    /// State changed.
    Transitioned {
        /// Previous state.
        previous: TransferState,
        /// New state.
        next: TransferState,
    },
    /// Duplicate command was ignored.
    Duplicate {
        /// Current state.
        state: TransferState,
    },
    /// Terminal actor had no open obligations at shutdown.
    ShutdownQuiescent {
        /// Final state.
        state: TransferState,
    },
}

/// Transfer actor errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferActorError {
    /// Topology violates region ownership.
    InvalidTopology(TransferTopologyError),
    /// Transition is not allowed.
    InvalidTransition {
        /// Current state.
        state: TransferState,
        /// Command attempted in that state.
        command: &'static str,
    },
    /// In-flight obligations would exceed peer policy.
    ObligationBudgetExceeded {
        /// Configured limit.
        limit: usize,
    },
    /// Actor cannot shut down with open obligations.
    ObligationLeak {
        /// Number of leaked obligations.
        open: usize,
    },
}

impl fmt::Display for TransferActorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTopology(err) => write!(f, "invalid transfer topology: {err}"),
            Self::InvalidTransition { state, command } => {
                write!(f, "invalid transfer transition {command} from {state:?}")
            }
            Self::ObligationBudgetExceeded { limit } => {
                write!(f, "transfer obligation budget exceeded: limit {limit}")
            }
            Self::ObligationLeak { open } => {
                write!(f, "transfer actor has {open} open obligations")
            }
        }
    }
}

impl std::error::Error for TransferActorError {}

/// Single-owner state for one ATP transfer.
#[derive(Debug, Clone)]
pub struct TransferActor {
    /// Actor id.
    pub actor_id: TransferActorId,
    /// Transfer id.
    pub transfer_id: TransferId,
    /// Manifest summary.
    pub manifest: TransferManifestRef,
    /// Peer capabilities accepted for this transfer.
    pub peer_capabilities: PeerCapabilities,
    /// Region ownership topology.
    pub topology: TransferActorTopology,
    /// Transfer progress.
    pub progress: TransferProgress,
    state: TransferState,
    next_journal_seq: u64,
    applied_keys: BTreeSet<IdempotencyKey>,
    open_obligations: BTreeMap<TransferObligationId, IdempotencyKey>,
    settled_obligations: Vec<(TransferObligationId, ObligationOutcome)>,
    journal: Vec<TransferJournalEntry>,
}

impl TransferActor {
    /// Construct a transfer actor in the offered state.
    pub fn new(
        actor_id: TransferActorId,
        transfer_id: TransferId,
        manifest: TransferManifestRef,
        peer_capabilities: PeerCapabilities,
        topology: TransferActorTopology,
    ) -> Result<Self, TransferActorError> {
        topology
            .validate()
            .map_err(TransferActorError::InvalidTopology)?;

        Ok(Self {
            actor_id,
            transfer_id,
            manifest,
            peer_capabilities,
            topology,
            progress: TransferProgress::default(),
            state: TransferState::Offered,
            next_journal_seq: 0,
            applied_keys: BTreeSet::new(),
            open_obligations: BTreeMap::new(),
            settled_obligations: Vec::new(),
            journal: Vec::new(),
        })
    }

    /// Current transfer state.
    #[must_use]
    pub const fn state(&self) -> TransferState {
        self.state
    }

    /// Durable journal entries.
    #[must_use]
    pub fn journal(&self) -> &[TransferJournalEntry] {
        &self.journal
    }

    /// Settled obligations.
    #[must_use]
    pub fn settled_obligations(&self) -> &[(TransferObligationId, ObligationOutcome)] {
        &self.settled_obligations
    }

    /// Number of open obligations.
    #[must_use]
    pub fn open_obligation_count(&self) -> usize {
        self.open_obligations.len()
    }

    /// Apply a command to the actor.
    pub fn apply(&mut self, command: TransferCommand) -> Result<TransferReply, TransferActorError> {
        if self.applied_keys.contains(&command.key) {
            return Ok(TransferReply::Duplicate { state: self.state });
        }

        let previous = self.state;
        let obligation = command.kind.obligation();
        if let Some(id) = obligation {
            self.open_obligation(id, command.key)?;
        }

        let transition = self.transition_for(&command.kind);
        match transition {
            Ok(next) => {
                if let Some(id) = obligation {
                    self.settle_obligation(id, ObligationOutcome::Committed);
                }
                self.apply_side_effects(&command.kind);
                self.state = next;
                self.applied_keys.insert(command.key);
                self.push_journal(
                    command.key,
                    previous,
                    next,
                    obligation,
                    ObligationOutcome::Committed,
                    &command.kind,
                );
                if matches!(command.kind, TransferCommandKind::Shutdown) {
                    self.assert_quiescent()?;
                    return Ok(TransferReply::ShutdownQuiescent { state: self.state });
                }
                Ok(TransferReply::Transitioned { previous, next })
            }
            Err(err) => {
                if let Some(id) = obligation {
                    self.settle_obligation(id, ObligationOutcome::Aborted);
                    self.push_journal(
                        command.key,
                        previous,
                        previous,
                        obligation,
                        ObligationOutcome::Aborted,
                        &command.kind,
                    );
                }
                Err(err)
            }
        }
    }

    /// Assert terminal shutdown quiescence.
    pub fn assert_quiescent(&self) -> Result<(), TransferActorError> {
        if self.open_obligations.is_empty() {
            Ok(())
        } else {
            Err(TransferActorError::ObligationLeak {
                open: self.open_obligations.len(),
            })
        }
    }

    /// Rebuild an actor from a journal by replaying idempotent commands.
    pub fn restart_from_journal(
        actor_id: TransferActorId,
        transfer_id: TransferId,
        manifest: TransferManifestRef,
        peer_capabilities: PeerCapabilities,
        topology: TransferActorTopology,
        journal: &[TransferJournalEntry],
    ) -> Result<Self, TransferActorError> {
        let mut actor = Self::new(actor_id, transfer_id, manifest, peer_capabilities, topology)?;
        for entry in journal {
            actor.state = entry.next;
            actor.applied_keys.insert(entry.key);
            actor.next_journal_seq = actor.next_journal_seq.max(entry.seq + 1);
            if let Some((id, outcome)) = entry.obligation {
                actor.settled_obligations.push((id, outcome));
            }
            actor.journal.push(entry.clone());
        }
        actor.assert_quiescent()?;
        Ok(actor)
    }

    fn open_obligation(
        &mut self,
        obligation: TransferObligationId,
        key: IdempotencyKey,
    ) -> Result<(), TransferActorError> {
        if self.open_obligations.len() >= self.peer_capabilities.max_inflight_obligations {
            return Err(TransferActorError::ObligationBudgetExceeded {
                limit: self.peer_capabilities.max_inflight_obligations,
            });
        }
        self.open_obligations.insert(obligation, key);
        Ok(())
    }

    fn settle_obligation(&mut self, id: TransferObligationId, outcome: ObligationOutcome) {
        self.open_obligations.remove(&id);
        self.settled_obligations.push((id, outcome));
    }

    fn transition_for(
        &self,
        command: &TransferCommandKind,
    ) -> Result<TransferState, TransferActorError> {
        match command {
            TransferCommandKind::Accept { .. } if self.state == TransferState::Offered => {
                Ok(TransferState::Accepted)
            }
            TransferCommandKind::Start { .. }
                if matches!(self.state, TransferState::Accepted | TransferState::Resumed) =>
            {
                Ok(TransferState::Running)
            }
            TransferCommandKind::Pause
                if matches!(
                    self.state,
                    TransferState::Running
                        | TransferState::Resumed
                        | TransferState::RelayForwarded
                        | TransferState::SwarmAssisted
                ) =>
            {
                Ok(TransferState::Paused)
            }
            TransferCommandKind::Resume { .. }
                if matches!(
                    self.state,
                    TransferState::Paused | TransferState::Failed | TransferState::MailboxStored
                ) =>
            {
                Ok(TransferState::Resumed)
            }
            TransferCommandKind::Cancel { .. } if !self.state.is_terminal() => {
                Ok(TransferState::Cancelling)
            }
            TransferCommandKind::Fail { .. } if self.state != TransferState::Committed => {
                Ok(TransferState::Failed)
            }
            TransferCommandKind::Commit { .. }
                if matches!(
                    self.state,
                    TransferState::Running
                        | TransferState::Resumed
                        | TransferState::MailboxStored
                        | TransferState::RelayForwarded
                        | TransferState::SwarmAssisted
                ) =>
            {
                Ok(TransferState::Committed)
            }
            TransferCommandKind::StoreMailbox { .. }
                if matches!(self.state, TransferState::Running | TransferState::Resumed) =>
            {
                Ok(TransferState::MailboxStored)
            }
            TransferCommandKind::ForwardRelay { .. }
                if matches!(self.state, TransferState::Running | TransferState::Resumed) =>
            {
                Ok(TransferState::RelayForwarded)
            }
            TransferCommandKind::Seed { .. } if self.state == TransferState::Committed => {
                Ok(TransferState::Seeded)
            }
            TransferCommandKind::JoinSwarm { .. }
                if matches!(
                    self.state,
                    TransferState::Running | TransferState::Resumed | TransferState::Seeded
                ) =>
            {
                Ok(TransferState::SwarmAssisted)
            }
            TransferCommandKind::Shutdown if self.state.is_terminal() => Ok(self.state),
            _ => Err(TransferActorError::InvalidTransition {
                state: self.state,
                command: command_name(command),
            }),
        }
    }

    fn apply_side_effects(&mut self, command: &TransferCommandKind) {
        match command {
            TransferCommandKind::Start { path_id, .. } => {
                self.progress.selected_path = Some(*path_id);
            }
            TransferCommandKind::Commit { .. } => {
                self.progress.committed_bytes = self.progress.verified_bytes;
            }
            TransferCommandKind::Fail { .. } | TransferCommandKind::Cancel { .. } => {
                self.progress.committed_bytes = 0;
            }
            TransferCommandKind::JoinSwarm { .. } => {
                self.progress.repair_symbols = self.progress.repair_symbols.saturating_add(1);
            }
            TransferCommandKind::Accept { .. }
            | TransferCommandKind::Pause
            | TransferCommandKind::Resume { .. }
            | TransferCommandKind::StoreMailbox { .. }
            | TransferCommandKind::ForwardRelay { .. }
            | TransferCommandKind::Seed { .. }
            | TransferCommandKind::Shutdown => {}
        }
    }

    fn push_journal(
        &mut self,
        key: IdempotencyKey,
        previous: TransferState,
        next: TransferState,
        obligation: Option<TransferObligationId>,
        outcome: ObligationOutcome,
        command: &TransferCommandKind,
    ) {
        self.journal.push(TransferJournalEntry {
            seq: self.next_journal_seq,
            actor_id: self.actor_id,
            transfer_id: self.transfer_id,
            key,
            previous,
            next,
            obligation: obligation.map(|id| (id, outcome)),
            supervisor_region: self.topology.supervisor_region,
            actor_region: self.topology.actor_region,
            child_topology: self.topology.child_regions.clone(),
            cancel_phase: match command {
                TransferCommandKind::Cancel { phase } => Some(*phase),
                _ => None,
            },
            replay_crashpack_path: format!(
                "atp/replay/actor-{}/transition-{}.crashpack",
                self.actor_id.get(),
                self.next_journal_seq
            ),
        });
        self.next_journal_seq += 1;
    }
}

fn command_name(command: &TransferCommandKind) -> &'static str {
    match command {
        TransferCommandKind::Accept { .. } => "accept",
        TransferCommandKind::Start { .. } => "start",
        TransferCommandKind::Pause => "pause",
        TransferCommandKind::Resume { .. } => "resume",
        TransferCommandKind::Cancel { .. } => "cancel",
        TransferCommandKind::Fail { .. } => "fail",
        TransferCommandKind::Commit { .. } => "commit",
        TransferCommandKind::StoreMailbox { .. } => "store_mailbox",
        TransferCommandKind::ForwardRelay { .. } => "forward_relay",
        TransferCommandKind::Seed { .. } => "seed",
        TransferCommandKind::JoinSwarm { .. } => "join_swarm",
        TransferCommandKind::Shutdown => "shutdown",
    }
}

#[cfg(test)]
mod tests {
    use super::super::actor::{TransferActorTopology, TransferChildRole, TransferRegionId};
    use super::*;

    fn manifest() -> TransferManifestRef {
        TransferManifestRef {
            schema_version: 1,
            merkle_root: [7; 32],
            object_count: 3,
        }
    }

    fn topology() -> TransferActorTopology {
        TransferActorTopology::new(TransferRegionId::new(1), TransferRegionId::new(2))
            .with_child(TransferRegionId::new(3), TransferChildRole::PathRace)
            .with_child(TransferRegionId::new(4), TransferChildRole::Writer)
            .with_child(TransferRegionId::new(5), TransferChildRole::Finalizer)
    }

    fn actor() -> TransferActor {
        TransferActor::new(
            TransferActorId::new(11),
            TransferId::derive([1; 32], [2; 32], [3; 32], [4; 32]),
            manifest(),
            PeerCapabilities {
                relay: true,
                mailbox: true,
                swarm: true,
                max_inflight_obligations: 4,
            },
            topology(),
        )
        .unwrap()
    }

    fn cmd(key: u128, kind: TransferCommandKind) -> TransferCommand {
        TransferCommand::new(IdempotencyKey::new(key), kind)
    }

    #[test]
    fn state_coverage_matches_atp_e1() {
        assert_eq!(TransferState::ALL.len(), 12);
        assert!(TransferState::ALL.contains(&TransferState::Offered));
        assert!(TransferState::ALL.contains(&TransferState::Accepted));
        assert!(TransferState::ALL.contains(&TransferState::Running));
        assert!(TransferState::ALL.contains(&TransferState::Paused));
        assert!(TransferState::ALL.contains(&TransferState::Cancelling));
        assert!(TransferState::ALL.contains(&TransferState::Failed));
        assert!(TransferState::ALL.contains(&TransferState::Committed));
        assert!(TransferState::ALL.contains(&TransferState::Resumed));
        assert!(TransferState::ALL.contains(&TransferState::MailboxStored));
        assert!(TransferState::ALL.contains(&TransferState::RelayForwarded));
        assert!(TransferState::ALL.contains(&TransferState::Seeded));
        assert!(TransferState::ALL.contains(&TransferState::SwarmAssisted));
    }

    #[test]
    fn offer_accept_running_commit_shutdown_is_quiescent() {
        let mut actor = actor();
        actor.progress.verified_bytes = 4096;

        actor
            .apply(cmd(
                1,
                TransferCommandKind::Accept {
                    obligation: TransferObligationId::new(101),
                },
            ))
            .unwrap();
        actor
            .apply(cmd(
                2,
                TransferCommandKind::Start {
                    path_id: 55,
                    obligation: TransferObligationId::new(102),
                },
            ))
            .unwrap();
        actor
            .apply(cmd(
                3,
                TransferCommandKind::Commit {
                    obligation: TransferObligationId::new(103),
                },
            ))
            .unwrap();
        let reply = actor
            .apply(cmd(4, TransferCommandKind::Shutdown))
            .expect("shutdown after commit");

        assert_eq!(actor.state(), TransferState::Committed);
        assert_eq!(actor.progress.selected_path, Some(55));
        assert_eq!(actor.progress.committed_bytes, 4096);
        assert_eq!(actor.open_obligation_count(), 0);
        assert_eq!(actor.settled_obligations().len(), 3);
        assert_eq!(actor.journal()[0].actor_id, actor.actor_id);
        assert_eq!(actor.journal()[0].transfer_id, actor.transfer_id);
        assert_eq!(actor.journal()[0].actor_region, actor.topology.actor_region);
        assert_eq!(
            actor.journal()[0].supervisor_region,
            actor.topology.supervisor_region
        );
        assert_eq!(
            actor.journal()[0].child_topology,
            actor.topology.child_regions
        );
        assert_eq!(
            actor.journal()[0].replay_crashpack_path,
            "atp/replay/actor-11/transition-0.crashpack"
        );
        assert!(matches!(
            reply,
            TransferReply::ShutdownQuiescent {
                state: TransferState::Committed
            }
        ));
    }

    #[test]
    fn invalid_transition_aborts_obligation_without_state_change() {
        let mut actor = actor();
        let err = actor
            .apply(cmd(
                1,
                TransferCommandKind::Commit {
                    obligation: TransferObligationId::new(77),
                },
            ))
            .expect_err("commit from offered must fail");

        assert_eq!(actor.state(), TransferState::Offered);
        assert_eq!(actor.open_obligation_count(), 0);
        assert_eq!(
            actor.settled_obligations(),
            &[(TransferObligationId::new(77), ObligationOutcome::Aborted)]
        );
        assert!(matches!(
            err,
            TransferActorError::InvalidTransition {
                state: TransferState::Offered,
                command: "commit"
            }
        ));
    }

    #[test]
    fn duplicate_messages_are_idempotent() {
        let mut actor = actor();
        let command = cmd(
            1,
            TransferCommandKind::Accept {
                obligation: TransferObligationId::new(10),
            },
        );

        actor.apply(command.clone()).unwrap();
        let duplicate = actor.apply(command).unwrap();

        assert_eq!(actor.state(), TransferState::Accepted);
        assert_eq!(actor.journal().len(), 1);
        assert_eq!(actor.settled_obligations().len(), 1);
        assert!(matches!(
            duplicate,
            TransferReply::Duplicate {
                state: TransferState::Accepted
            }
        ));
    }

    #[test]
    fn cancellation_is_accepted_from_every_nonterminal_state() {
        for state in [
            TransferState::Offered,
            TransferState::Accepted,
            TransferState::Running,
            TransferState::Paused,
            TransferState::Resumed,
            TransferState::MailboxStored,
            TransferState::RelayForwarded,
            TransferState::SwarmAssisted,
        ] {
            let mut actor = actor();
            actor.state = state;
            actor
                .apply(cmd(
                    1,
                    TransferCommandKind::Cancel {
                        phase: TransferCancelPhase::Requested,
                    },
                ))
                .unwrap();
            assert_eq!(actor.state(), TransferState::Cancelling);
            assert_eq!(
                actor.journal()[0].cancel_phase,
                Some(TransferCancelPhase::Requested)
            );
        }
    }

    #[test]
    fn restart_from_journal_preserves_state_and_idempotency() {
        let mut actor = actor();
        actor
            .apply(cmd(
                1,
                TransferCommandKind::Accept {
                    obligation: TransferObligationId::new(1),
                },
            ))
            .unwrap();
        actor
            .apply(cmd(
                2,
                TransferCommandKind::Start {
                    path_id: 9,
                    obligation: TransferObligationId::new(2),
                },
            ))
            .unwrap();

        let mut restarted = TransferActor::restart_from_journal(
            actor.actor_id,
            actor.transfer_id,
            actor.manifest.clone(),
            actor.peer_capabilities.clone(),
            actor.topology.clone(),
            actor.journal(),
        )
        .unwrap();

        assert_eq!(restarted.state(), TransferState::Running);
        let duplicate = restarted
            .apply(cmd(
                2,
                TransferCommandKind::Start {
                    path_id: 9,
                    obligation: TransferObligationId::new(2),
                },
            ))
            .unwrap();
        assert!(matches!(
            duplicate,
            TransferReply::Duplicate {
                state: TransferState::Running
            }
        ));
    }

    #[test]
    fn failed_peer_disk_and_repair_paths_are_distinct() {
        for (key, failure) in [
            (1, TransferFailureKind::Peer),
            (2, TransferFailureKind::Disk),
            (3, TransferFailureKind::Repair),
        ] {
            let mut actor = actor();
            actor
                .apply(cmd(key, TransferCommandKind::Fail { kind: failure }))
                .unwrap();
            assert_eq!(actor.state(), TransferState::Failed);
            assert_eq!(actor.open_obligation_count(), 0);
        }
    }
}
