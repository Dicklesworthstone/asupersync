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
//! ```
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

use parking_lot::Mutex;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

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
    #[inline]
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
    /// Cumulative count of messages that were drained from the reorder
    /// buffer during an in-progress auto-flush, were NOT delivered
    /// (cancel / disconnect / full mid-flush), and were restored to
    /// the reorder buffer for a subsequent flush. A non-zero value is
    /// not a bug — the AutoFlushGuard correctly preserves the values —
    /// but a steadily-growing counter indicates that auto_flush is
    /// being cancelled often enough to slow effective drain rate, and
    /// the operator may want to call [`FaultSender::flush`] explicitly
    /// from a non-cancelled context. (br-asupersync-rnbjfb.)
    pub reorder_cancel_residue: u64,
}

impl std::fmt::Display for FaultChannelStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "FaultChannelStats {{ sent: {}, reordered: {}, duplicated: {}, flushes: {}, \
             cancel_residue: {} }}",
            self.messages_sent,
            self.messages_reordered,
            self.messages_duplicated,
            self.reorder_flushes,
            self.reorder_cancel_residue,
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
    /// Deterministic evidence event sequence for replayable fault logs.
    evidence_seq: AtomicU64,
    /// Atomic stats counters — avoids locking on every send.
    stat_messages_sent: AtomicU64,
    stat_messages_reordered: AtomicU64,
    stat_messages_duplicated: AtomicU64,
    stat_reorder_flushes: AtomicU64,
    /// Cumulative count of values that were drained out of the reorder
    /// buffer for an in-progress auto-flush, did NOT reach the receiver
    /// (because of cancel/disconnect/full mid-flush), and were
    /// restored to the reorder buffer for a subsequent flush.
    /// Surfaced in [`FaultChannelStats`] so SREs can see how often the
    /// cancel-mid-reorder path is actually exercised — without this
    /// counter the AutoFlushGuard restoration is silent
    /// (br-asupersync-rnbjfb).
    stat_reorder_cancel_residue: AtomicU64,
    evidence_sink: Arc<dyn EvidenceSink>,
}

impl<T: Clone + std::fmt::Debug> std::fmt::Debug for FaultSender<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FaultSender")
            .field("config", &self.config)
            .field("stats", &self.stats())
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
        let buf_cap = config.reorder_buffer_size;
        Self {
            inner: sender,
            config,
            rng: Mutex::new(rng),
            reorder_buffer: Mutex::new(Vec::with_capacity(buf_cap)),
            evidence_seq: AtomicU64::new(0),
            stat_messages_sent: AtomicU64::new(0),
            stat_messages_reordered: AtomicU64::new(0),
            stat_messages_duplicated: AtomicU64::new(0),
            stat_reorder_flushes: AtomicU64::new(0),
            stat_reorder_cancel_residue: AtomicU64::new(0),
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
        if cx.checkpoint().is_err() {
            return Err(SendError::Cancelled(value));
        }
        // Preserve base sender semantics: if the receiver side is already gone,
        // fail immediately instead of buffering and reporting a false success.
        if self.inner.is_closed() {
            return Err(SendError::Disconnected(value));
        }

        let (should_reorder, should_duplicate) = {
            let mut rng = self.rng.lock();
            let should_reorder = rng.should_inject(self.config.reorder_probability);
            // Treat reorder vs duplication as mutually exclusive outcomes for a
            // single send attempt so buffered sends never leak eager duplicates.
            let should_duplicate =
                !should_reorder && rng.should_inject(self.config.duplication_probability);
            drop(rng);
            (should_reorder, should_duplicate)
        };

        let duplicate = if should_duplicate {
            Some(value.clone())
        } else {
            None
        };

        if should_reorder {
            // Defer record_reorder() until after the send path succeeds
            // to prevent stat corruption when auto_flush fails.
            let value_to_flush = {
                let mut buffer = self.reorder_buffer.lock();
                if buffer.len() + 1 < self.config.reorder_buffer_size {
                    buffer.push(value);
                    drop(buffer);
                    None
                } else {
                    drop(buffer);
                    Some(value)
                }
            };
            if let Some(v) = value_to_flush {
                self.auto_flush_including_current(cx, v).await?;
            }
            self.record_reorder();
        } else {
            self.inner.send(cx, value).await?;
            self.record_sent();
        }

        // Send duplicate if triggered — only record evidence after successful delivery.
        if let Some(dup) = duplicate {
            if self.inner.send(cx, dup).await.is_ok() {
                self.record_duplication();
            }
        }

        Ok(())
    }

    #[allow(clippy::significant_drop_tightening, clippy::too_many_lines)]
    async fn auto_flush_including_current(&self, cx: &Cx, value: T) -> Result<(), SendError<T>> {
        enum AutoFlushItem<T> {
            Buffered(T),
            Current(T),
        }

        impl<T> AutoFlushItem<T> {
            fn into_value(self) -> T {
                match self {
                    Self::Buffered(value) | Self::Current(value) => value,
                }
            }
        }

        struct AutoFlushGuard<'a, T> {
            buffer: &'a parking_lot::Mutex<Vec<T>>,
            pending: std::collections::VecDeque<AutoFlushItem<T>>,
            current: Option<AutoFlushItem<T>>,
            /// Counter incremented by Drop with the number of items that
            /// were restored to the reorder buffer because the flush
            /// was cancelled / disconnected / full mid-iteration.
            /// Surfaces residue via FaultChannelStats.reorder_cancel_residue
            /// so SREs can observe how often auto-flush is being
            /// interrupted before completion. (br-asupersync-rnbjfb.)
            cancel_residue_counter: &'a AtomicU64,
        }

        impl<T> AutoFlushGuard<'_, T> {
            fn take_current_value(&mut self) -> Option<T> {
                match self.current.take() {
                    Some(AutoFlushItem::Current(value)) => return Some(value),
                    Some(item) => self.current = Some(item),
                    None => {}
                }

                let current_idx = self
                    .pending
                    .iter()
                    .position(|item| matches!(item, AutoFlushItem::Current(_)))?;

                match self.pending.remove(current_idx) {
                    Some(AutoFlushItem::Current(value)) => Some(value),
                    Some(AutoFlushItem::Buffered(_)) => unreachable!("matched current item"),
                    None => None,
                }
            }
        }

        impl<T> Drop for AutoFlushGuard<'_, T> {
            fn drop(&mut self) {
                let mut to_restore = Vec::new();
                if let Some(item) = self.current.take() {
                    to_restore.push(item.into_value());
                }
                to_restore.extend(self.pending.drain(..).map(AutoFlushItem::into_value));
                if !to_restore.is_empty() {
                    let restored = to_restore.len();
                    let mut buf = self.buffer.lock();
                    buf.extend(to_restore);
                    drop(buf);
                    // br-asupersync-rnbjfb: surface the cancel-induced
                    // restoration so the silent path becomes a
                    // monotone counter visible via FaultChannelStats.
                    // The user's CURRENT value is extracted by
                    // take_current_value() BEFORE Drop runs, so the
                    // residue counted here is purely buffered values
                    // that were eligible for this auto-flush attempt
                    // and will retry on the next flush.
                    self.cancel_residue_counter
                        .fetch_add(restored as u64, Ordering::Relaxed);
                }
            }
        }

        let mut messages = {
            let mut buffer = self.reorder_buffer.lock();
            let buffered = std::mem::replace(
                &mut *buffer,
                Vec::with_capacity(self.config.reorder_buffer_size),
            );
            let mut messages = Vec::with_capacity(buffered.len() + 1);
            messages.extend(buffered.into_iter().map(AutoFlushItem::Buffered));
            messages.push(AutoFlushItem::Current(value));
            messages
        };

        {
            let mut rng = self.rng.lock();
            shuffle_vec(&mut messages, &mut rng);
        }

        let flush_context = format!("buffer_size_{}", messages.len());
        let mut guard = AutoFlushGuard {
            buffer: &self.reorder_buffer,
            pending: messages.into(),
            current: None,
            cancel_residue_counter: &self.stat_reorder_cancel_residue,
        };
        let mut flush_recorded = false;

        while let Some(item) = guard.pending.pop_front() {
            guard.current = Some(item);

            let permit = match self.inner.reserve(cx).await {
                Ok(p) => p,
                Err(SendError::Disconnected(())) => {
                    if let Some(value) = guard.take_current_value() {
                        return Err(SendError::Disconnected(value));
                    }
                    return Ok(());
                }
                Err(SendError::Cancelled(())) => {
                    if let Some(value) = guard.take_current_value() {
                        return Err(SendError::Cancelled(value));
                    }
                    return Ok(());
                }
                Err(SendError::Full(())) => {
                    if let Some(value) = guard.take_current_value() {
                        return Err(SendError::Full(value));
                    }
                    return Ok(());
                }
            };

            let Some(current_item) = guard.current.take() else {
                continue;
            };

            match current_item {
                AutoFlushItem::Buffered(msg) => match permit.try_send(msg) {
                    Ok(()) => {
                        if !flush_recorded {
                            emit_fault_evidence(
                                &*self.evidence_sink,
                                self.next_evidence_ts(),
                                "reorder_flush",
                                &flush_context,
                            );
                            self.stat_reorder_flushes.fetch_add(1, Ordering::Relaxed);
                            flush_recorded = true;
                        }
                        self.record_sent();
                    }
                    Err(SendError::Disconnected(value)) => {
                        guard.current = Some(AutoFlushItem::Buffered(value));
                        if let Some(current) = guard.take_current_value() {
                            return Err(SendError::Disconnected(current));
                        }
                        return Ok(());
                    }
                    Err(SendError::Cancelled(value)) => {
                        guard.current = Some(AutoFlushItem::Buffered(value));
                        if let Some(current) = guard.take_current_value() {
                            return Err(SendError::Cancelled(current));
                        }
                        return Ok(());
                    }
                    Err(SendError::Full(value)) => {
                        guard.current = Some(AutoFlushItem::Buffered(value));
                        if let Some(current) = guard.take_current_value() {
                            return Err(SendError::Full(current));
                        }
                        return Ok(());
                    }
                },
                AutoFlushItem::Current(msg) => match permit.try_send(msg) {
                    Ok(()) => {
                        if !flush_recorded {
                            emit_fault_evidence(
                                &*self.evidence_sink,
                                self.next_evidence_ts(),
                                "reorder_flush",
                                &flush_context,
                            );
                            self.stat_reorder_flushes.fetch_add(1, Ordering::Relaxed);
                            flush_recorded = true;
                        }
                        self.record_sent();
                    }
                    Err(err) => return Err(err),
                },
            }
        }

        Ok(())
    }

    /// Flush the reorder buffer, sending all buffered messages in a
    /// random permutation.
    ///
    /// Call this after the message stream ends to ensure all buffered
    /// messages are delivered (eventual delivery guarantee).
    #[allow(clippy::significant_drop_tightening)]
    pub async fn flush(&self, cx: &Cx) -> Result<(), SendError<()>> {
        struct FlushGuard<'a, T> {
            buffer: &'a parking_lot::Mutex<Vec<T>>,
            pending: Option<std::vec::IntoIter<T>>,
            current: Option<T>,
        }

        impl<T> Drop for FlushGuard<'_, T> {
            fn drop(&mut self) {
                let mut to_restore = Vec::new();
                if let Some(msg) = self.current.take() {
                    to_restore.push(msg);
                }
                if let Some(pending) = self.pending.take() {
                    to_restore.extend(pending);
                }
                if !to_restore.is_empty() {
                    let mut buf = self.buffer.lock();
                    buf.extend(to_restore);
                }
            }
        }

        let mut messages = {
            let mut buffer = self.reorder_buffer.lock();
            // Replace with a freshly pre-sized buffer so subsequent sends keep a
            // stable reorder allocation profile even after repeated flushes.
            std::mem::replace(
                &mut *buffer,
                Vec::with_capacity(self.config.reorder_buffer_size),
            )
        };

        if messages.is_empty() {
            return Ok(());
        }

        // Shuffle the buffer.
        {
            let mut rng = self.rng.lock();
            shuffle_vec(&mut messages, &mut rng);
        }

        let flush_context = format!("buffer_size_{}", messages.len());

        let mut guard = FlushGuard {
            buffer: &self.reorder_buffer,
            pending: Some(messages.into_iter()),
            current: None,
        };
        let mut flush_recorded = false;

        while let Some(msg) = guard.pending.as_mut().and_then(std::iter::Iterator::next) {
            guard.current = Some(msg);

            let permit = match self.inner.reserve(cx).await {
                Ok(p) => p,
                Err(err) => {
                    // The Drop guard will restore `current` and `pending` to the buffer.
                    match err {
                        SendError::Disconnected(()) => return Err(SendError::Disconnected(())),
                        SendError::Cancelled(()) => return Err(SendError::Cancelled(())),
                        SendError::Full(()) => return Err(SendError::Full(())),
                    }
                }
            };

            let Some(msg) = guard.current.take() else {
                continue;
            };
            match permit.try_send(msg) {
                Ok(()) => {
                    if !flush_recorded {
                        emit_fault_evidence(
                            &*self.evidence_sink,
                            self.next_evidence_ts(),
                            "reorder_flush",
                            &flush_context,
                        );
                        self.stat_reorder_flushes.fetch_add(1, Ordering::Relaxed);
                        flush_recorded = true;
                    }
                    self.record_sent();
                }
                Err(err) => {
                    // Receiver disconnected while we were sending
                    match err {
                        SendError::Disconnected(value) => {
                            guard.current = Some(value);
                            return Err(SendError::Disconnected(()));
                        }
                        SendError::Cancelled(value) => {
                            guard.current = Some(value);
                            return Err(SendError::Cancelled(()));
                        }
                        SendError::Full(value) => {
                            guard.current = Some(value);
                            return Err(SendError::Full(()));
                        }
                    }
                }
            }
        }

        guard.pending = None;
        Ok(())
    }

    /// Returns a snapshot of the fault injection statistics.
    #[inline]
    pub fn stats(&self) -> FaultChannelStats {
        FaultChannelStats {
            messages_sent: self.stat_messages_sent.load(Ordering::Relaxed),
            messages_reordered: self.stat_messages_reordered.load(Ordering::Relaxed),
            messages_duplicated: self.stat_messages_duplicated.load(Ordering::Relaxed),
            reorder_flushes: self.stat_reorder_flushes.load(Ordering::Relaxed),
            reorder_cancel_residue: self.stat_reorder_cancel_residue.load(Ordering::Relaxed),
        }
    }

    /// Returns the number of messages currently buffered for reordering.
    pub fn buffered_count(&self) -> usize {
        self.reorder_buffer.lock().len()
    }

    /// Returns a reference to the underlying sender.
    #[inline]
    pub fn inner(&self) -> &Sender<T> {
        &self.inner
    }

    fn record_sent(&self) {
        self.stat_messages_sent.fetch_add(1, Ordering::Relaxed);
    }

    fn next_evidence_ts(&self) -> u64 {
        self.evidence_seq
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1)
    }

    fn record_reorder(&self) {
        self.stat_messages_reordered.fetch_add(1, Ordering::Relaxed);
        emit_fault_evidence(
            &*self.evidence_sink,
            self.next_evidence_ts(),
            "reorder_buffer",
            "channel_send",
        );
    }

    fn record_duplication(&self) {
        self.stat_messages_duplicated
            .fetch_add(1, Ordering::Relaxed);
        emit_fault_evidence(
            &*self.evidence_sink,
            self.next_evidence_ts(),
            "duplication",
            "channel_send",
        );
    }
}

// ---------------------------------------------------------------------------
// Evidence emission
// ---------------------------------------------------------------------------

/// Emit an evidence entry for a channel fault injection event.
fn emit_fault_evidence(sink: &dyn EvidenceSink, ts_unix_ms: u64, fault_type: &str, context: &str) {
    let action = format!("inject_{fault_type}");
    let entry = EvidenceLedger {
        ts_unix_ms,
        component: "channel_fault".to_string(),
        expected_loss_by_action: std::collections::BTreeMap::from([(action.clone(), 0.0)]),
        action,
        posterior: vec![1.0],
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
#[path = "fault_inline_tests.rs"]
mod tests;
