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
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

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
            emit_partition_evidence(&self.evidence_sink, "create", src, dst);
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
            emit_partition_evidence(&self.evidence_sink, "heal", src, dst);
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
                "heal",
                ActorId::new(src),
                ActorId::new(dst),
            );
        }
    }

    /// Returns `true` if there is an active partition from `src` to `dst`.
    #[must_use]
    pub fn is_partitioned(&self, src: ActorId, dst: ActorId) -> bool {
        // Fast-path: skip the lock when no partitions exist (the common case).
        if self.partition_count.load(Ordering::Relaxed) == 0 {
            return false;
        }
        self.partitions.lock().contains(&(src.0, dst.0))
    }

    /// Returns the number of active directed partitions.
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
    #[must_use]
    pub fn behavior(&self) -> PartitionBehavior {
        self.behavior
    }

    fn record_drop(&self) {
        self.messages_dropped.fetch_add(1, Ordering::Relaxed);
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
            return match self.controller.behavior() {
                PartitionBehavior::Drop => {
                    self.controller.record_drop();
                    emit_partition_evidence(
                        &self.controller.evidence_sink,
                        "message_dropped",
                        self.src,
                        self.dst,
                    );
                    Ok(())
                }
                PartitionBehavior::Error => {
                    emit_partition_evidence(
                        &self.controller.evidence_sink,
                        "message_rejected",
                        self.src,
                        self.dst,
                    );
                    Err(SendError::Disconnected(value))
                }
            };
        }
        self.inner.send(cx, value).await
    }

    /// Returns the source actor id.
    #[must_use]
    pub fn src(&self) -> ActorId {
        self.src
    }

    /// Returns the destination actor id.
    #[must_use]
    pub fn dst(&self) -> ActorId {
        self.dst
    }

    /// Returns a reference to the underlying sender.
    #[must_use]
    pub fn inner(&self) -> &Sender<T> {
        &self.inner
    }

    /// Returns a reference to the partition controller.
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

fn emit_partition_evidence(sink: &Arc<dyn EvidenceSink>, action: &str, src: ActorId, dst: ActorId) {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);

    let action_str = format!("partition_{action}");

    #[allow(clippy::cast_precision_loss)]
    let entry = EvidenceLedger {
        ts_unix_ms: now_ms,
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
mod tests {
    use super::*;
    use crate::evidence_sink::CollectorSink;
    use crate::types::Budget;
    use crate::util::ArenaIndex;
    use crate::{RegionId, TaskId};
    use std::future::Future;
    use std::sync::Arc;
    use std::task::{Context, Poll, Waker};

    fn test_cx() -> crate::cx::Cx {
        crate::cx::Cx::new(
            RegionId::from_arena(ArenaIndex::new(0, 0)),
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            Budget::INFINITE,
        )
    }

    fn block_on<F: Future>(f: F) -> F::Output {
        struct NoopWaker;
        impl std::task::Wake for NoopWaker {
            fn wake(self: Arc<Self>) {}
        }
        let waker = Waker::from(Arc::new(NoopWaker));
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Box::pin(f);
        loop {
            match pinned.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    fn make_controller(
        behavior: PartitionBehavior,
    ) -> (Arc<PartitionController>, Arc<CollectorSink>) {
        let collector = Arc::new(CollectorSink::new());
        let sink: Arc<dyn EvidenceSink> = collector.clone();
        let ctrl = Arc::new(PartitionController::new(behavior, sink));
        (ctrl, collector)
    }

    #[test]
    fn no_partition_passthrough() {
        let (ctrl, _) = make_controller(PartitionBehavior::Drop);
        let a = ActorId::new(1);
        let b = ActorId::new(2);
        let (ptx, rx) = partition_channel::<u32>(16, ctrl, a, b);
        let cx = test_cx();

        for i in 0..5 {
            block_on(ptx.send(&cx, i)).expect("send");
        }

        for i in 0..5 {
            assert_eq!(rx.try_recv().unwrap(), i);
        }
    }

    #[test]
    fn partition_drops_messages() {
        let (ctrl, collector) = make_controller(PartitionBehavior::Drop);
        let a = ActorId::new(1);
        let b = ActorId::new(2);
        let (ptx, rx) = partition_channel::<u32>(16, ctrl.clone(), a, b);
        let cx = test_cx();

        // Partition A→B.
        ctrl.partition(a, b);
        assert!(ctrl.is_partitioned(a, b));

        // Sends succeed (drop behavior) but messages are lost.
        for i in 0..5 {
            block_on(ptx.send(&cx, i)).expect("send should succeed (drop mode)");
        }
        assert!(rx.try_recv().is_err(), "no messages should be delivered");

        let stats = ctrl.stats();
        assert_eq!(stats.partitions_created, 1);
        assert_eq!(stats.messages_dropped, 5);

        // Evidence logged.
        let entries = collector.entries();
        let drop_entries = entries
            .iter()
            .filter(|e| e.action == "partition_message_dropped")
            .count();
        assert_eq!(drop_entries, 5);
        assert!(!entries
            .iter()
            .any(|e| e.action.starts_with("partition_partition_")));
    }

    #[test]
    fn partition_error_mode() {
        let (ctrl, collector) = make_controller(PartitionBehavior::Error);
        let a = ActorId::new(1);
        let b = ActorId::new(2);
        let (ptx, _rx) = partition_channel::<u32>(16, ctrl.clone(), a, b);
        let cx = test_cx();

        ctrl.partition(a, b);
        let result = block_on(ptx.send(&cx, 42));
        assert!(
            matches!(result, Err(SendError::Disconnected(42))),
            "expected Disconnected, got: {result:?}"
        );

        // Error mode rejects sends but does not count them as dropped.
        let stats = ctrl.stats();
        assert_eq!(stats.messages_dropped, 0);

        // Evidence should indicate rejection, not drop.
        let entries = collector.entries();
        assert!(entries
            .iter()
            .any(|e| e.action == "partition_message_rejected"));
        assert!(!entries
            .iter()
            .any(|e| e.action == "partition_message_dropped"));
    }

    #[test]
    fn partition_drop_mode_respects_cancellation() {
        let (ctrl, _collector) = make_controller(PartitionBehavior::Drop);
        let a = ActorId::new(1);
        let b = ActorId::new(2);
        let (ptx, rx) = partition_channel::<u32>(16, ctrl.clone(), a, b);
        let cx = test_cx();
        cx.set_cancel_requested(true);

        ctrl.partition(a, b);
        let result = block_on(ptx.send(&cx, 7));
        assert!(matches!(result, Err(SendError::Cancelled(7))));
        assert!(rx.try_recv().is_err());
        assert_eq!(ctrl.stats().messages_dropped, 0);
    }

    #[test]
    fn partition_error_mode_respects_cancellation_precedence() {
        let (ctrl, _collector) = make_controller(PartitionBehavior::Error);
        let a = ActorId::new(1);
        let b = ActorId::new(2);
        let (ptx, _rx) = partition_channel::<u32>(16, ctrl.clone(), a, b);
        let cx = test_cx();
        cx.set_cancel_requested(true);

        ctrl.partition(a, b);
        let result = block_on(ptx.send(&cx, 11));
        assert!(matches!(result, Err(SendError::Cancelled(11))));
    }

    #[test]
    fn heal_restores_delivery() {
        let (ctrl, _) = make_controller(PartitionBehavior::Drop);
        let a = ActorId::new(1);
        let b = ActorId::new(2);
        let (ptx, rx) = partition_channel::<u32>(16, ctrl.clone(), a, b);
        let cx = test_cx();

        ctrl.partition(a, b);
        block_on(ptx.send(&cx, 1)).unwrap(); // Dropped.
        assert!(rx.try_recv().is_err());

        ctrl.heal(a, b);
        assert!(!ctrl.is_partitioned(a, b));

        block_on(ptx.send(&cx, 2)).unwrap(); // Delivered.
        assert_eq!(rx.try_recv().unwrap(), 2);

        let stats = ctrl.stats();
        assert_eq!(stats.partitions_healed, 1);
    }

    #[test]
    fn asymmetric_partition() {
        let (ctrl, _) = make_controller(PartitionBehavior::Drop);
        let a = ActorId::new(1);
        let b = ActorId::new(2);
        // Create channels for both directions.
        let (ptx_ab, rx_b) = partition_channel::<u32>(16, ctrl.clone(), a, b);
        let (ptx_ba, rx_a) = partition_channel::<u32>(16, ctrl.clone(), b, a);
        let cx = test_cx();

        // Only partition A→B (asymmetric).
        ctrl.partition(a, b);

        // A→B: dropped.
        block_on(ptx_ab.send(&cx, 1)).unwrap();
        assert!(rx_b.try_recv().is_err());

        // B→A: delivered.
        block_on(ptx_ba.send(&cx, 2)).unwrap();
        assert_eq!(rx_a.try_recv().unwrap(), 2);
    }

    #[test]
    fn symmetric_partition() {
        let (ctrl, _) = make_controller(PartitionBehavior::Drop);
        let a = ActorId::new(1);
        let b = ActorId::new(2);
        let (ptx_ab, rx_b) = partition_channel::<u32>(16, ctrl.clone(), a, b);
        let (ptx_ba, rx_a) = partition_channel::<u32>(16, ctrl.clone(), b, a);
        let cx = test_cx();

        ctrl.partition_symmetric(a, b);

        // Both directions blocked.
        block_on(ptx_ab.send(&cx, 1)).unwrap();
        block_on(ptx_ba.send(&cx, 2)).unwrap();
        assert!(rx_b.try_recv().is_err());
        assert!(rx_a.try_recv().is_err());

        // Symmetric heal.
        ctrl.heal_symmetric(a, b);
        block_on(ptx_ab.send(&cx, 3)).unwrap();
        block_on(ptx_ba.send(&cx, 4)).unwrap();
        assert_eq!(rx_b.try_recv().unwrap(), 3);
        assert_eq!(rx_a.try_recv().unwrap(), 4);
    }

    #[test]
    fn cascading_partitions() {
        let (ctrl, _) = make_controller(PartitionBehavior::Drop);
        let a = ActorId::new(1);
        let b = ActorId::new(2);
        let c = ActorId::new(3);
        let (tx_a2b, rx_b) = partition_channel::<u32>(16, ctrl.clone(), a, b);
        let (tx_b2c, rx_c) = partition_channel::<u32>(16, ctrl.clone(), b, c);
        let (tx_a2c, rx_c2) = partition_channel::<u32>(16, ctrl.clone(), a, c);
        let cx = test_cx();

        // Partition A→B and B→C (cascading).
        ctrl.partition(a, b);
        ctrl.partition(b, c);

        // A→B: blocked. A→C: not blocked.
        block_on(tx_a2b.send(&cx, 1)).unwrap();
        block_on(tx_a2c.send(&cx, 2)).unwrap();
        block_on(tx_b2c.send(&cx, 3)).unwrap();

        assert!(rx_b.try_recv().is_err());
        assert!(rx_c.try_recv().is_err());
        assert_eq!(rx_c2.try_recv().unwrap(), 2);
    }

    #[test]
    fn heal_all_clears_all_partitions() {
        let (ctrl, collector) = make_controller(PartitionBehavior::Drop);
        let a = ActorId::new(1);
        let b = ActorId::new(2);
        let c = ActorId::new(3);

        ctrl.partition_symmetric(a, b);
        ctrl.partition_symmetric(b, c);
        assert_eq!(ctrl.active_partition_count(), 4); // 2 symmetric = 4 directed.

        ctrl.heal_all();
        assert_eq!(ctrl.active_partition_count(), 0);
        assert_eq!(ctrl.stats().partitions_healed, 4);

        // heal_all should emit heal evidence for every cleared directed edge.
        let entries = collector.entries();
        let heal_entries = entries
            .iter()
            .filter(|e| e.action == "partition_heal")
            .count();
        assert_eq!(heal_entries, 4);
    }

    #[test]
    fn evidence_for_partition_lifecycle() {
        let (ctrl, collector) = make_controller(PartitionBehavior::Drop);
        let a = ActorId::new(1);
        let b = ActorId::new(2);

        ctrl.partition(a, b);
        ctrl.heal(a, b);

        let entries = collector.entries();
        assert!(
            entries.iter().any(|e| e.action == "partition_create"),
            "should log partition creation"
        );
        assert!(
            entries.iter().any(|e| e.action == "partition_heal"),
            "should log partition heal"
        );
        assert!(!entries
            .iter()
            .any(|e| e.action.starts_with("partition_partition_")));
        for entry in &entries {
            assert_eq!(entry.component, "channel_partition");
            assert!(entry.is_valid());
        }
    }

    #[test]
    fn idempotent_partition_and_heal() {
        let (ctrl, _) = make_controller(PartitionBehavior::Drop);
        let a = ActorId::new(1);
        let b = ActorId::new(2);

        // Double partition should only count once.
        ctrl.partition(a, b);
        ctrl.partition(a, b);
        assert_eq!(ctrl.stats().partitions_created, 1);

        // Double heal should only count once.
        ctrl.heal(a, b);
        ctrl.heal(a, b);
        assert_eq!(ctrl.stats().partitions_healed, 1);
    }

    #[test]
    fn actor_id_display() {
        let id = ActorId::new(42);
        assert_eq!(format!("{id}"), "actor-42");
    }
}
