//! Fault-injecting channel wrapper for testing (bd-2ktrc.1).
//!
//! Wraps a standard MPSC [`Sender`] to inject probabilistic message
//! reordering and duplication. Designed for lab/test scenarios where
//! deterministic, reproducible fault sequences are required.
//!
//! # Fault Types
//!
//! - **Reorder**: Buffers up to `reorder_buffer_size` messages and flushes
//!   them in a random permutation. Tests that consumers handle out-of-order
//!   delivery correctly.
//! - **Duplication**: Clones a message and delivers it twice. Tests
//!   idempotency in receivers.
//!
//! # Determinism
//!
//! All fault decisions use [`ChaosRng`] (xorshift64). Same seed → same
//! fault sequence, enabling reproducible test failures.
//!
//! # Evidence Logging
//!
//! Every injected fault is logged to an [`EvidenceSink`] for post-hoc
//! debugging and methodology compliance.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::channel::{mpsc, fault::*};
//! use asupersync::evidence_sink::{CollectorSink, EvidenceSink};
//! use std::sync::Arc;
//!
//! let (tx, rx) = mpsc::channel::<u32>(16);
//! let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
//! let config = FaultChannelConfig::new(42)
//!     .with_reorder(0.3, 4)
//!     .with_duplication(0.1);
//!
//! let fault_tx = FaultSender::new(tx, config, sink);
//! ```

use std::sync::{Arc, Mutex};

use crate::channel::mpsc::{SendError, Sender};
use crate::cx::Cx;
use crate::evidence_sink::EvidenceSink;
use crate::lab::chaos::ChaosRng;
use franken_evidence::EvidenceLedger;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for channel fault injection.
#[derive(Debug, Clone)]
pub struct FaultChannelConfig {
    /// Probability of buffering a message for reorder [0.0, 1.0].
    pub reorder_probability: f64,
    /// Maximum reorder buffer size. When full, the buffer is flushed
    /// in a random permutation.
    pub reorder_buffer_size: usize,
    /// Probability of duplicating a message [0.0, 1.0].
    pub duplication_probability: f64,
    /// Deterministic seed for the PRNG.
    pub seed: u64,
}

impl FaultChannelConfig {
    /// Create a new config with the given seed and no faults enabled.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self {
            reorder_probability: 0.0,
            reorder_buffer_size: 4,
            duplication_probability: 0.0,
            seed,
        }
    }

    /// Enable reorder injection with the given probability and buffer size.
    ///
    /// # Panics
    ///
    /// Panics if `probability` is not in [0.0, 1.0] or `buffer_size` is 0.
    #[must_use]
    pub fn with_reorder(mut self, probability: f64, buffer_size: usize) -> Self {
        assert!(
            (0.0..=1.0).contains(&probability),
            "reorder probability must be in [0.0, 1.0], got {probability}"
        );
        assert!(buffer_size > 0, "reorder buffer size must be > 0");
        self.reorder_probability = probability;
        self.reorder_buffer_size = buffer_size;
        self
    }

    /// Enable duplication injection with the given probability.
    ///
    /// # Panics
    ///
    /// Panics if `probability` is not in [0.0, 1.0].
    #[must_use]
    pub fn with_duplication(mut self, probability: f64) -> Self {
        assert!(
            (0.0..=1.0).contains(&probability),
            "duplication probability must be in [0.0, 1.0], got {probability}"
        );
        self.duplication_probability = probability;
        self
    }

    /// Returns `true` if any fault injection is enabled.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.reorder_probability > 0.0 || self.duplication_probability > 0.0
    }
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

/// Statistics for channel fault injection.
#[derive(Debug, Clone, Default)]
pub struct FaultChannelStats {
    /// Total messages processed through the fault sender.
    pub messages_sent: u64,
    /// Messages that were buffered for reordering.
    pub messages_reordered: u64,
    /// Messages that were duplicated.
    pub messages_duplicated: u64,
    /// Number of times the reorder buffer was flushed.
    pub reorder_flushes: u64,
}

impl std::fmt::Display for FaultChannelStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "FaultChannelStats {{ sent: {}, reordered: {}, duplicated: {}, flushes: {} }}",
            self.messages_sent,
            self.messages_reordered,
            self.messages_duplicated,
            self.reorder_flushes,
        )
    }
}

// ---------------------------------------------------------------------------
// FaultSender
// ---------------------------------------------------------------------------

/// Fault-injecting channel sender wrapper.
///
/// Wraps a standard [`Sender<T>`] and applies probabilistic message
/// reordering and duplication on the send path. All decisions are
/// deterministic (seeded PRNG) and logged to an [`EvidenceSink`].
///
/// `T: Clone` is required because duplication clones the message.
pub struct FaultSender<T: Clone> {
    inner: Sender<T>,
    config: FaultChannelConfig,
    rng: Mutex<ChaosRng>,
    reorder_buffer: Mutex<Vec<T>>,
    stats: Mutex<FaultChannelStats>,
    evidence_sink: Arc<dyn EvidenceSink>,
}

impl<T: Clone + std::fmt::Debug> std::fmt::Debug for FaultSender<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FaultSender")
            .field("config", &self.config)
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

impl<T: Clone> FaultSender<T> {
    /// Create a fault-injecting sender wrapping the given sender.
    #[must_use]
    pub fn new(
        sender: Sender<T>,
        config: FaultChannelConfig,
        evidence_sink: Arc<dyn EvidenceSink>,
    ) -> Self {
        let rng = ChaosRng::new(config.seed);
        Self {
            inner: sender,
            config,
            rng: Mutex::new(rng),
            reorder_buffer: Mutex::new(Vec::new()),
            stats: Mutex::new(FaultChannelStats::default()),
            evidence_sink,
        }
    }

    /// Send a value through the fault-injecting channel.
    ///
    /// The message may be:
    /// - Buffered for later reordered delivery
    /// - Duplicated (sent twice)
    /// - Sent normally
    pub async fn send(&self, cx: &Cx, value: T) -> Result<(), SendError<T>> {
        // Preserve base sender semantics: if the receiver side is already gone,
        // fail immediately instead of buffering and reporting a false success.
        if self.inner.is_closed() {
            return Err(SendError::Disconnected(value));
        }

        let should_reorder;
        let should_duplicate;
        {
            let mut rng = self.rng.lock().expect("fault rng lock poisoned");
            should_reorder = rng.should_inject(self.config.reorder_probability);
            should_duplicate = rng.should_inject(self.config.duplication_probability);
        }

        if should_reorder {
            self.record_reorder();
            let needs_flush = {
                let mut buffer = self.reorder_buffer.lock().expect("reorder buffer poisoned");
                buffer.push(value);
                buffer.len() >= self.config.reorder_buffer_size
            };
            if needs_flush {
                // Value is already consumed into the buffer; if flush fails
                // (e.g., receiver dropped), messages remain in the buffer.
                // Callers should check `flush()` separately for cleanup.
                let _ = self.flush(cx).await;
            }
            return Ok(());
        }

        // Clone before send only if duplication is needed.
        let duplicate = if should_duplicate {
            Some(value.clone())
        } else {
            None
        };

        self.inner.send(cx, value).await?;
        self.record_sent();

        // Send duplicate if triggered.
        if let Some(dup) = duplicate {
            self.record_duplication();
            emit_fault_evidence(&*self.evidence_sink, "duplication", "channel_send");
            // Best-effort: ignore errors (channel may be full/closed).
            let _ = self.inner.send(cx, dup).await;
        }

        Ok(())
    }

    /// Flush the reorder buffer, sending all buffered messages in a
    /// random permutation.
    ///
    /// Call this after the message stream ends to ensure all buffered
    /// messages are delivered (eventual delivery guarantee).
    pub async fn flush(&self, cx: &Cx) -> Result<(), SendError<()>> {
        let mut messages = {
            let mut buffer = self.reorder_buffer.lock().expect("reorder buffer poisoned");
            std::mem::take(&mut *buffer)
        };

        if messages.is_empty() {
            return Ok(());
        }

        // Shuffle the buffer.
        {
            let mut rng = self.rng.lock().expect("fault rng lock poisoned");
            shuffle_vec(&mut messages, &mut rng);
        }

        emit_fault_evidence(
            &*self.evidence_sink,
            "reorder_flush",
            &format!("buffer_size_{}", messages.len()),
        );

        if let Ok(mut stats) = self.stats.lock() {
            stats.reorder_flushes += 1;
        }

        for msg in messages {
            self.inner.send(cx, msg).await.map_err(|e| match e {
                SendError::Disconnected(_) => SendError::Disconnected(()),
                SendError::Cancelled(_) => SendError::Cancelled(()),
                SendError::Full(_) => SendError::Full(()),
            })?;
            self.record_sent();
        }

        Ok(())
    }

    /// Returns a snapshot of the fault injection statistics.
    pub fn stats(&self) -> FaultChannelStats {
        self.stats.lock().map(|s| s.clone()).unwrap_or_default()
    }

    /// Returns the number of messages currently buffered for reordering.
    pub fn buffered_count(&self) -> usize {
        self.reorder_buffer.lock().map_or(0, |b| b.len())
    }

    /// Returns a reference to the underlying sender.
    pub fn inner(&self) -> &Sender<T> {
        &self.inner
    }

    fn record_sent(&self) {
        if let Ok(mut stats) = self.stats.lock() {
            stats.messages_sent += 1;
        }
    }

    fn record_reorder(&self) {
        if let Ok(mut stats) = self.stats.lock() {
            stats.messages_reordered += 1;
        }
        emit_fault_evidence(&*self.evidence_sink, "reorder_buffer", "channel_send");
    }

    fn record_duplication(&self) {
        if let Ok(mut stats) = self.stats.lock() {
            stats.messages_duplicated += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Evidence emission
// ---------------------------------------------------------------------------

/// Emit an evidence entry for a channel fault injection event.
fn emit_fault_evidence(sink: &dyn EvidenceSink, fault_type: &str, context: &str) {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);

    let entry = EvidenceLedger {
        ts_unix_ms: now_ms,
        component: "channel_fault".to_string(),
        action: format!("inject_{fault_type}"),
        posterior: vec![1.0],
        expected_loss_by_action: std::collections::BTreeMap::from([(
            format!("inject_{fault_type}"),
            0.0,
        )]),
        chosen_expected_loss: 0.0,
        calibration_score: 1.0,
        fallback_active: false,
        #[allow(clippy::cast_precision_loss)] // context.len() is always small
        top_features: vec![
            ("fault_type".to_string(), 1.0),
            ("context_len".to_string(), context.len() as f64),
        ],
    };
    sink.emit(&entry);
}

/// Fisher-Yates shuffle using `ChaosRng`.
fn shuffle_vec<T>(vec: &mut [T], rng: &mut ChaosRng) {
    for i in (1..vec.len()).rev() {
        let j = rng.next_u64() as usize % (i + 1);
        vec.swap(i, j);
    }
}

// ---------------------------------------------------------------------------
// Convenience constructor
// ---------------------------------------------------------------------------

/// Create a fault-injecting MPSC channel.
///
/// Returns a `FaultSender` that applies fault injection and a standard
/// `Receiver`. The receiver is unchanged; faults are injected on the
/// send path.
pub fn fault_channel<T: Clone>(
    capacity: usize,
    config: FaultChannelConfig,
    evidence_sink: Arc<dyn EvidenceSink>,
) -> (FaultSender<T>, super::Receiver<T>) {
    let (tx, rx) = super::mpsc::channel(capacity);
    let fault_tx = FaultSender::new(tx, config, evidence_sink);
    (fault_tx, rx)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::mpsc;
    use crate::evidence_sink::CollectorSink;
    use crate::types::Budget;
    use crate::util::ArenaIndex;
    use crate::{RegionId, TaskId};
    use std::future::Future;
    use std::sync::Arc;
    use std::task::{Context, Poll, Waker};

    fn test_cx() -> Cx {
        Cx::new(
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

    #[test]
    fn config_defaults_disabled() {
        let config = FaultChannelConfig::new(42);
        assert!(!config.is_enabled());
    }

    #[test]
    fn config_builder() {
        let config = FaultChannelConfig::new(42)
            .with_reorder(0.3, 4)
            .with_duplication(0.1);
        assert!(config.is_enabled());
        assert!((config.reorder_probability - 0.3).abs() < f64::EPSILON);
        assert_eq!(config.reorder_buffer_size, 4);
        assert!((config.duplication_probability - 0.1).abs() < f64::EPSILON);
    }

    #[test]
    #[should_panic(expected = "reorder probability must be in [0.0, 1.0]")]
    fn config_rejects_invalid_reorder_probability() {
        let _ = FaultChannelConfig::new(42).with_reorder(1.5, 4);
    }

    #[test]
    #[should_panic(expected = "reorder buffer size must be > 0")]
    fn config_rejects_zero_buffer_size() {
        let _ = FaultChannelConfig::new(42).with_reorder(0.5, 0);
    }

    #[test]
    #[should_panic(expected = "duplication probability must be in [0.0, 1.0]")]
    fn config_rejects_invalid_duplication_probability() {
        let _ = FaultChannelConfig::new(42).with_duplication(-0.1);
    }

    #[test]
    fn passthrough_when_disabled() {
        let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
        let config = FaultChannelConfig::new(42);
        let (fault_tx, rx) = fault_channel::<u32>(16, config, sink);
        let cx = test_cx();

        for i in 0..10 {
            block_on(fault_tx.send(&cx, i)).expect("send failed");
        }

        // All messages should arrive in order.
        for i in 0..10 {
            let val = rx.try_recv().expect("recv failed");
            assert_eq!(val, i);
        }

        let stats = fault_tx.stats();
        assert_eq!(stats.messages_sent, 10);
        assert_eq!(stats.messages_reordered, 0);
        assert_eq!(stats.messages_duplicated, 0);
    }

    #[test]
    fn duplication_sends_twice() {
        let collector = Arc::new(CollectorSink::new());
        let sink: Arc<dyn EvidenceSink> = collector.clone();
        // 100% duplication probability.
        let config = FaultChannelConfig::new(42).with_duplication(1.0);
        let (fault_tx, rx) = fault_channel::<u32>(32, config, sink);
        let cx = test_cx();

        block_on(fault_tx.send(&cx, 42)).expect("send failed");

        // Should receive the original + duplicate.
        let v1 = rx.try_recv().expect("recv original");
        let v2 = rx.try_recv().expect("recv duplicate");
        assert_eq!(v1, 42);
        assert_eq!(v2, 42);

        let stats = fault_tx.stats();
        assert_eq!(stats.messages_duplicated, 1);

        // Evidence should be logged.
        assert!(!collector.is_empty());
        let entries = collector.entries();
        assert!(entries.iter().any(|e| e.action.contains("duplication")));
    }

    #[test]
    fn reorder_buffers_and_flushes() {
        let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
        // 100% reorder probability, buffer size 3.
        let config = FaultChannelConfig::new(42).with_reorder(1.0, 3);
        let (fault_tx, rx) = fault_channel::<u32>(32, config, sink);
        let cx = test_cx();

        // Send 3 messages — should fill buffer and auto-flush.
        for i in 0..3 {
            block_on(fault_tx.send(&cx, i)).expect("send failed");
        }

        // All 3 should be delivered (but possibly reordered).
        let mut received = Vec::new();
        while let Ok(val) = rx.try_recv() {
            received.push(val);
        }
        assert_eq!(received.len(), 3);
        // All values present (eventual delivery).
        received.sort_unstable();
        assert_eq!(received, vec![0, 1, 2]);

        let stats = fault_tx.stats();
        assert_eq!(stats.messages_reordered, 3);
        assert_eq!(stats.reorder_flushes, 1);
    }

    #[test]
    fn manual_flush_delivers_buffered() {
        let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
        // 100% reorder, large buffer so auto-flush doesn't trigger.
        let config = FaultChannelConfig::new(42).with_reorder(1.0, 100);
        let (fault_tx, rx) = fault_channel::<u32>(32, config, sink);
        let cx = test_cx();

        for i in 0..5 {
            block_on(fault_tx.send(&cx, i)).expect("send failed");
        }
        assert_eq!(fault_tx.buffered_count(), 5);

        // Nothing received yet.
        assert!(rx.try_recv().is_err());

        // Flush should deliver all.
        block_on(fault_tx.flush(&cx)).expect("flush failed");
        assert_eq!(fault_tx.buffered_count(), 0);

        let mut received = Vec::new();
        while let Ok(val) = rx.try_recv() {
            received.push(val);
        }
        assert_eq!(received.len(), 5);
        received.sort_unstable();
        assert_eq!(received, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn deterministic_fault_sequence() {
        // Two senders with the same seed should make identical decisions.
        let sink1: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
        let sink2: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());

        let config = FaultChannelConfig::new(99)
            .with_reorder(0.5, 4)
            .with_duplication(0.3);

        let (fault_tx1, rx1) = fault_channel::<u32>(64, config.clone(), sink1);
        let (fault_tx2, rx2) = fault_channel::<u32>(64, config, sink2);
        let cx = test_cx();

        for i in 0..20 {
            block_on(fault_tx1.send(&cx, i)).expect("send1");
            block_on(fault_tx2.send(&cx, i)).expect("send2");
        }
        block_on(fault_tx1.flush(&cx)).expect("flush1");
        block_on(fault_tx2.flush(&cx)).expect("flush2");

        // Collect all received values.
        let mut recv1 = Vec::new();
        let mut recv2 = Vec::new();
        while let Ok(v) = rx1.try_recv() {
            recv1.push(v);
        }
        while let Ok(v) = rx2.try_recv() {
            recv2.push(v);
        }

        // Same seed should produce identical receive sequences.
        assert_eq!(recv1, recv2);
        assert_eq!(
            fault_tx1.stats().messages_reordered,
            fault_tx2.stats().messages_reordered
        );
        assert_eq!(
            fault_tx1.stats().messages_duplicated,
            fault_tx2.stats().messages_duplicated
        );
    }

    #[test]
    fn eventual_delivery_all_messages_arrive() {
        let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
        let config = FaultChannelConfig::new(77)
            .with_reorder(0.5, 5)
            .with_duplication(0.0);
        let (fault_tx, rx) = fault_channel::<u32>(128, config, sink);
        let cx = test_cx();

        let count = 50;
        for i in 0..count {
            block_on(fault_tx.send(&cx, i)).expect("send");
        }
        block_on(fault_tx.flush(&cx)).expect("flush");

        let mut received = Vec::new();
        while let Ok(v) = rx.try_recv() {
            received.push(v);
        }
        // Every message must arrive exactly once.
        received.sort_unstable();
        let expected: Vec<u32> = (0..count).collect();
        assert_eq!(received, expected);
    }

    #[test]
    fn mixed_reorder_and_duplication() {
        let collector = Arc::new(CollectorSink::new());
        let sink: Arc<dyn EvidenceSink> = collector.clone();
        let config = FaultChannelConfig::new(42)
            .with_reorder(0.3, 4)
            .with_duplication(0.2);
        let (fault_tx, rx) = fault_channel::<u32>(256, config, sink);
        let cx = test_cx();

        let count = 30;
        for i in 0..count {
            block_on(fault_tx.send(&cx, i)).expect("send");
        }
        block_on(fault_tx.flush(&cx)).expect("flush");

        let mut received = Vec::new();
        while let Ok(v) = rx.try_recv() {
            received.push(v);
        }

        // With duplication, we may have more messages than sent.
        // With reorder, order may differ. But all originals must be present.
        let stats = fault_tx.stats();
        assert!(received.len() as u64 >= stats.messages_sent);

        // All original values should appear at least once.
        for i in 0..count {
            assert!(
                received.contains(&i),
                "missing message {i}, received: {received:?}, stats: {stats}"
            );
        }

        // Evidence should be logged for faults.
        let entries = collector.entries();
        assert!(
            !entries.is_empty(),
            "expected evidence entries for injected faults"
        );
    }

    #[test]
    fn empty_flush_is_noop() {
        let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
        let config = FaultChannelConfig::new(42).with_reorder(1.0, 4);
        let (fault_tx, _rx) = fault_channel::<u32>(16, config, sink);
        let cx = test_cx();

        // Flush with nothing buffered should succeed.
        block_on(fault_tx.flush(&cx)).expect("empty flush");
        assert_eq!(fault_tx.stats().reorder_flushes, 0);
    }

    #[test]
    fn send_after_receiver_drop_returns_error() {
        let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
        let config = FaultChannelConfig::new(42);
        let (tx, rx) = mpsc::channel::<u32>(1);
        let fault_tx = FaultSender::new(tx, config, sink);
        let cx = test_cx();

        drop(rx);
        let result = block_on(fault_tx.send(&cx, 1));
        assert!(matches!(result, Err(SendError::Disconnected(_))));
    }

    #[test]
    fn send_after_receiver_drop_with_reorder_returns_error() {
        let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
        let config = FaultChannelConfig::new(42).with_reorder(1.0, 4);
        let (tx, rx) = mpsc::channel::<u32>(1);
        let fault_tx = FaultSender::new(tx, config, sink);
        let cx = test_cx();

        drop(rx);
        let result = block_on(fault_tx.send(&cx, 1));
        assert!(matches!(result, Err(SendError::Disconnected(1))));
        assert_eq!(fault_tx.buffered_count(), 0);
    }

    #[test]
    fn evidence_entries_are_valid() {
        let collector = Arc::new(CollectorSink::new());
        let sink: Arc<dyn EvidenceSink> = collector.clone();
        let config = FaultChannelConfig::new(42)
            .with_reorder(1.0, 2)
            .with_duplication(1.0);
        let (fault_tx, _rx) = fault_channel::<u32>(64, config, sink);
        let cx = test_cx();

        // Send enough to trigger both reorder flush and duplication.
        // With reorder=1.0 everything goes to buffer, so duplication
        // won't trigger (reorder takes precedence). Send with reorder
        // first, then reconfigure. For simplicity, test reorder evidence.
        for i in 0..4 {
            block_on(fault_tx.send(&cx, i)).expect("send");
        }

        let entries = collector.entries();
        for entry in &entries {
            assert_eq!(entry.component, "channel_fault");
            assert!(entry.action.starts_with("inject_"));
            assert!(entry.is_valid(), "invalid evidence: {entry:?}");
        }
    }

    #[test]
    fn fault_channel_convenience_constructor() {
        let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
        let config = FaultChannelConfig::new(42)
            .with_reorder(0.5, 4)
            .with_duplication(0.2);
        let (fault_tx, rx) = fault_channel::<String>(16, config, sink);
        let cx = test_cx();

        block_on(fault_tx.send(&cx, "hello".to_string())).expect("send");
        block_on(fault_tx.flush(&cx)).expect("flush");

        let mut received = Vec::new();
        while let Ok(v) = rx.try_recv() {
            received.push(v);
        }
        assert!(received.contains(&"hello".to_string()));
    }
}
