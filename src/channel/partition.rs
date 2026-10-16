//! Partition fault injection for channels (bd-2ktrc.2).
//!
//! Simulates network partitions between actors communicating via channels.
//! A [`PartitionController`] manages connectivity state between named actors.
//! [`PartitionSender`] wraps a standard [`Sender`] and checks the controller
//! before each send, dropping messages (or returning errors) when the
//! source→destination link is partitioned.
//!
//! # Partition Types
//!
//! - **Symmetric**: A cannot reach B and B cannot reach A
//! - **Asymmetric**: A can reach B but B cannot reach A
//! - **Cascading**: Multiple overlapping partitions
//!
//! # Healing
//!
//! Partitions can be healed, restoring connectivity. Queued messages
//! during partition (if buffering mode is enabled) are delivered on heal.
//!
//! # Determinism
//!
//! Partition decisions are based on the controller's partition set, not
//! randomness. The same sequence of partition/heal calls produces
//! identical behavior.
//!
//! # Evidence Logging
//!
//! Every partition, heal, and dropped-during-partition event is logged
//! to an [`EvidenceSink`].

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::channel::mpsc::{SendError, Sender};
use crate::cx::Cx;
use crate::evidence_sink::EvidenceSink;
use franken_evidence::EvidenceLedger;
use parking_lot::Mutex;

// ---------------------------------------------------------------------------
// ActorId
// ---------------------------------------------------------------------------

/// Identifier for an actor endpoint in the partition model.
///
/// This is a lightweight wrapper over `u64` used to label channel endpoints
/// for partition tracking. Actors do not need to correspond to real runtime
/// tasks — they are logical identifiers for the partition topology.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ActorId(u64);

impl ActorId {
    /// Create an actor id from a raw integer.
    #[must_use]
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Returns the raw identifier.
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for ActorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "actor-{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// PartitionController
// ---------------------------------------------------------------------------

/// Statistics for partition fault injection.
#[derive(Debug, Clone, Default)]
pub struct PartitionStats {
    /// Number of times a partition was created.
    pub partitions_created: u64,
    /// Number of times a partition was healed.
    pub partitions_healed: u64,
    /// Messages dropped due to partition.
    pub messages_dropped: u64,
    /// Messages buffered during partition (if buffering is enabled).
    pub messages_buffered: u64,
}

impl std::fmt::Display for PartitionStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PartitionStats {{ created: {}, healed: {}, dropped: {}, buffered: {} }}",
            self.partitions_created,
            self.partitions_healed,
            self.messages_dropped,
            self.messages_buffered,
        )
    }
}

/// What to do when a message is sent across a partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionBehavior {
    /// Drop the message silently (simulates packet loss).
    Drop,
    /// Return `SendError::Disconnected` to the sender.
    Error,
}

/// Controls partition state between actors.
///
/// Shared across multiple [`PartitionSender`] instances. Thread-safe.
///
/// Partitions are directed: `partition(A, B)` blocks A→B but not B→A.
/// For symmetric partitions, call `partition_symmetric(A, B)`.
#[derive(Debug)]
pub struct PartitionController {
    /// Active directed partitions: (src, dst) pairs.
    partitions: Mutex<HashSet<(u64, u64)>>,
    /// What happens when sending across a partition.
    behavior: PartitionBehavior,
    /// Number of active partitions, for lock-free fast-path in is_partitioned.
    partition_count: AtomicUsize,
    /// Deterministic evidence event sequence for replayable partition logs.
    evidence_seq: AtomicU64,
    /// Diagnostic counters (relaxed atomics, no mutex needed).
    partitions_created: AtomicU64,
    partitions_healed: AtomicU64,
    messages_dropped: AtomicU64,
    messages_buffered: AtomicU64,
    /// Evidence sink for logging.
    evidence_sink: Arc<dyn EvidenceSink>,
}

impl PartitionController {
    /// Create a new partition controller with the given behavior and evidence sink.
    #[must_use]
    pub fn new(behavior: PartitionBehavior, evidence_sink: Arc<dyn EvidenceSink>) -> Self {
        Self {
            partitions: Mutex::new(HashSet::new()),
            behavior,
            partition_count: AtomicUsize::new(0),
            evidence_seq: AtomicU64::new(0),
            partitions_created: AtomicU64::new(0),
            partitions_healed: AtomicU64::new(0),
            messages_dropped: AtomicU64::new(0),
            messages_buffered: AtomicU64::new(0),
            evidence_sink,
        }
    }

    /// Create a partition blocking messages from `src` to `dst`.
    ///
    /// This is a directed partition: `src` cannot reach `dst`, but
    /// `dst` can still reach `src` (unless a reverse partition exists).
    pub fn partition(&self, src: ActorId, dst: ActorId) {
        let created = {
            let mut partitions = self.partitions.lock();
            let created = partitions.insert((src.0, dst.0));
            if created {
                self.partition_count.fetch_add(1, Ordering::Relaxed);
            }
            drop(partitions);
            created
        };

        if created {
            self.partitions_created.fetch_add(1, Ordering::Relaxed);
            emit_partition_evidence(
                &self.evidence_sink,
                self.next_evidence_ts(),
                "create",
                src,
                dst,
            );
        }
    }

    /// Create a symmetric partition between `a` and `b`.
    ///
    /// Neither can reach the other.
    pub fn partition_symmetric(&self, a: ActorId, b: ActorId) {
        self.partition(a, b);
        self.partition(b, a);
    }

    /// Heal a directed partition from `src` to `dst`.
    pub fn heal(&self, src: ActorId, dst: ActorId) {
        let healed = {
            let mut partitions = self.partitions.lock();
            let healed = partitions.remove(&(src.0, dst.0));
            if healed {
                self.partition_count.fetch_sub(1, Ordering::Relaxed);
            }
            drop(partitions);
            healed
        };

        if healed {
            self.partitions_healed.fetch_add(1, Ordering::Relaxed);
            emit_partition_evidence(
                &self.evidence_sink,
                self.next_evidence_ts(),
                "heal",
                src,
                dst,
            );
        }
    }

    /// Heal a symmetric partition between `a` and `b`.
    pub fn heal_symmetric(&self, a: ActorId, b: ActorId) {
        self.heal(a, b);
        self.heal(b, a);
    }

    /// Heal all active partitions.
    #[allow(clippy::cast_possible_truncation)]
    pub fn heal_all(&self) {
        let healed_edges: Vec<(u64, u64)> = {
            let mut partitions = self.partitions.lock();
            let edges = std::mem::take(&mut *partitions).into_iter().collect();
            self.partition_count.store(0, Ordering::Relaxed);
            drop(partitions);
            edges
        };
        let count = healed_edges.len() as u64;
        self.partitions_healed.fetch_add(count, Ordering::Relaxed);
        for (src, dst) in healed_edges {
            emit_partition_evidence(
                &self.evidence_sink,
                self.next_evidence_ts(),
                "heal",
                ActorId::new(src),
                ActorId::new(dst),
            );
        }
    }

    /// Returns `true` if there is an active partition from `src` to `dst`.
    #[inline]
    #[must_use]
    pub fn is_partitioned(&self, src: ActorId, dst: ActorId) -> bool {
        // Fast-path: skip the lock when no partitions exist (the common case).
        if self.partition_count.load(Ordering::Relaxed) == 0 {
            return false;
        }
        self.partitions.lock().contains(&(src.0, dst.0))
    }

    /// Returns the number of active directed partitions.
    #[inline]
    #[must_use]
    pub fn active_partition_count(&self) -> usize {
        self.partition_count.load(Ordering::Relaxed)
    }

    /// Returns a snapshot of the partition statistics.
    pub fn stats(&self) -> PartitionStats {
        PartitionStats {
            partitions_created: self.partitions_created.load(Ordering::Relaxed),
            partitions_healed: self.partitions_healed.load(Ordering::Relaxed),
            messages_dropped: self.messages_dropped.load(Ordering::Relaxed),
            messages_buffered: self.messages_buffered.load(Ordering::Relaxed),
        }
    }

    /// Returns the configured behavior for partitioned sends.
    #[inline]
    #[must_use]
    pub fn behavior(&self) -> PartitionBehavior {
        self.behavior
    }

    #[inline]
    fn record_drop(&self) {
        self.messages_dropped.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn next_evidence_ts(&self) -> u64 {
        self.evidence_seq
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1)
    }
}

// ---------------------------------------------------------------------------
// PartitionSender
// ---------------------------------------------------------------------------

/// Channel sender that respects partition state from a [`PartitionController`].
///
/// When the link from `src` to `dst` is partitioned, sends either:
/// - Drop the message silently ([`PartitionBehavior::Drop`])
/// - Return `SendError::Disconnected` ([`PartitionBehavior::Error`])
pub struct PartitionSender<T> {
    inner: Sender<T>,
    controller: Arc<PartitionController>,
    src: ActorId,
    dst: ActorId,
}

impl<T: std::fmt::Debug> std::fmt::Debug for PartitionSender<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PartitionSender")
            .field("src", &self.src)
            .field("dst", &self.dst)
            .finish_non_exhaustive()
    }
}

impl<T> PartitionSender<T> {
    /// Create a partition-aware sender.
    #[must_use]
    pub fn new(
        sender: Sender<T>,
        controller: Arc<PartitionController>,
        src: ActorId,
        dst: ActorId,
    ) -> Self {
        Self {
            inner: sender,
            controller,
            src,
            dst,
        }
    }

    fn handle_partitioned_send(&self, value: T) -> Result<(), SendError<T>> {
        match self.controller.behavior() {
            PartitionBehavior::Drop => {
                self.controller.record_drop();
                emit_partition_evidence(
                    &self.controller.evidence_sink,
                    self.controller.next_evidence_ts(),
                    "message_dropped",
                    self.src,
                    self.dst,
                );
                Ok(())
            }
            PartitionBehavior::Error => {
                emit_partition_evidence(
                    &self.controller.evidence_sink,
                    self.controller.next_evidence_ts(),
                    "message_rejected",
                    self.src,
                    self.dst,
                );
                Err(SendError::Disconnected(value))
            }
        }
    }

    /// Send a value, respecting the partition controller.
    ///
    /// If the link is partitioned, the behavior depends on
    /// [`PartitionBehavior`]:
    /// - `Drop`: returns `Ok(())` but the message is silently discarded
    /// - `Error`: returns `Err(SendError::Disconnected(value))`
    pub async fn send(&self, cx: &Cx, value: T) -> Result<(), SendError<T>> {
        if cx.checkpoint().is_err() {
            return Err(SendError::Cancelled(value));
        }

        if self.controller.is_partitioned(self.src, self.dst) {
            return self.handle_partitioned_send(value);
        }

        let permit = match self.inner.reserve(cx).await {
            Ok(permit) => permit,
            Err(SendError::Disconnected(())) => return Err(SendError::Disconnected(value)),
            Err(SendError::Cancelled(())) => return Err(SendError::Cancelled(value)),
            Err(SendError::Full(())) => return Err(SendError::Full(value)),
        };

        // Recheck the authoritative set after the capacity wait. Keep the
        // topology lock through the queue commit so partition() cannot return
        // while a previously parked, still sender-side value remains able to
        // enter the channel afterward. The MPSC helper detaches its receiver
        // waker so no external callback runs under this lock.
        let partitions = self.controller.partitions.lock();
        if partitions.contains(&(self.src.0, self.dst.0)) {
            drop(partitions);
            permit.abort();
            return self.handle_partitioned_send(value);
        }

        let (result, recv_waker) = permit.try_send_deferred_wake(value);
        drop(partitions);
        recv_waker.wake();
        result
    }

    /// Returns the source actor id.
    #[inline]
    #[must_use]
    pub fn src(&self) -> ActorId {
        self.src
    }

    /// Returns the destination actor id.
    #[inline]
    #[must_use]
    pub fn dst(&self) -> ActorId {
        self.dst
    }

    /// Returns a reference to the underlying sender.
    #[inline]
    #[must_use]
    pub fn inner(&self) -> &Sender<T> {
        &self.inner
    }

    /// Returns a reference to the partition controller.
    #[inline]
    #[must_use]
    pub fn controller(&self) -> &Arc<PartitionController> {
        &self.controller
    }
}

// ---------------------------------------------------------------------------
// Convenience constructor
// ---------------------------------------------------------------------------

/// Create a partition-aware MPSC channel.
///
/// Returns a `PartitionSender` and standard `Receiver`. The controller
/// manages partition state; call `controller.partition()` / `heal()`
/// to inject/remove faults.
pub fn partition_channel<T>(
    capacity: usize,
    controller: Arc<PartitionController>,
    src: ActorId,
    dst: ActorId,
) -> (PartitionSender<T>, super::Receiver<T>) {
    let (tx, rx) = super::mpsc::channel(capacity);
    let ptx = PartitionSender::new(tx, controller, src, dst);
    (ptx, rx)
}

// ---------------------------------------------------------------------------
// Evidence emission
// ---------------------------------------------------------------------------

fn emit_partition_evidence(
    sink: &Arc<dyn EvidenceSink>,
    ts_unix_ms: u64,
    action: &str,
    src: ActorId,
    dst: ActorId,
) {
    let action_str = format!("partition_{action}");

    #[allow(clippy::cast_precision_loss)]
    let entry = EvidenceLedger {
        ts_unix_ms,
        component: "channel_partition".to_string(),
        action: action_str.clone(),
        posterior: vec![1.0],
        expected_loss_by_action: std::collections::BTreeMap::from([(action_str, 0.0)]),
        chosen_expected_loss: 0.0,
        calibration_score: 1.0,
        fallback_active: false,
        top_features: vec![
            ("src_actor".to_string(), src.0 as f64),
            ("dst_actor".to_string(), dst.0 as f64),
        ],
    };
    sink.emit(&entry);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "partition_inline_tests.rs"]
mod tests;
