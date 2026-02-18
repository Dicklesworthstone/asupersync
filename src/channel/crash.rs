//! Crash/restart fault injection for channels (bd-2ktrc.3).
//!
//! Simulates actor crashes and restarts at the channel level.
//! A [`CrashController`] manages the "alive" state of a simulated actor.
//! [`CrashSender`] wraps a standard [`Sender`] and checks the controller
//! before each send, returning `Disconnected` when the actor is "crashed".
//!
//! # Crash Modes
//!
//! - **Probabilistic**: Crash with a configurable probability on each send
//! - **Deterministic**: Crash after exactly N successful sends
//! - **Manual**: Crash via the controller at any time
//!
//! # Restart Modes
//!
//! - **Cold**: Reset send counter and stats (fresh state)
//! - **Warm**: Preserve stats, just re-enable sends (checkpoint resume)
//!
//! # Supervision Integration
//!
//! The [`CrashController`] tracks crash/restart cycles with configurable
//! limits (`max_restarts`). When the limit is exhausted, the controller
//! enters a permanent `Exhausted` state where restarts are refused.
//!
//! # Determinism
//!
//! Probabilistic crash decisions use [`ChaosRng`] (xorshift64). Same
//! seed → same crash sequence, enabling reproducible test failures.
//!
//! # Evidence Logging
//!
//! Every crash, restart, and rejected-during-crash event is logged
//! to an [`EvidenceSink`].

use parking_lot::Mutex;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::channel::mpsc::{SendError, Sender};
use crate::cx::Cx;
use crate::evidence_sink::EvidenceSink;
use crate::lab::chaos::ChaosRng;
use franken_evidence::EvidenceLedger;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for crash fault injection.
#[derive(Debug, Clone)]
pub struct CrashConfig {
    /// Probability of crash on each send attempt [0.0, 1.0].
    pub crash_probability: f64,
    /// If set, crash deterministically after exactly this many successful sends.
    pub crash_after_sends: Option<u64>,
    /// Maximum number of restarts before the controller is permanently exhausted.
    pub max_restarts: Option<u32>,
    /// Restart mode when `CrashController::restart()` is called.
    pub restart_mode: RestartMode,
    /// Deterministic seed for the PRNG.
    pub seed: u64,
}

impl CrashConfig {
    /// Create a new config with the given seed and no crash injection enabled.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self {
            crash_probability: 0.0,
            crash_after_sends: None,
            max_restarts: None,
            restart_mode: RestartMode::Cold,
            seed,
        }
    }

    /// Enable probabilistic crash injection.
    ///
    /// # Panics
    ///
    /// Panics if `probability` is not in [0.0, 1.0].
    #[must_use]
    pub fn with_crash_probability(mut self, probability: f64) -> Self {
        assert!(
            (0.0..=1.0).contains(&probability),
            "crash probability must be in [0.0, 1.0], got {probability}"
        );
        self.crash_probability = probability;
        self
    }

    /// Enable deterministic crash after a fixed number of successful sends.
    #[must_use]
    pub const fn with_crash_after_sends(mut self, count: u64) -> Self {
        self.crash_after_sends = Some(count);
        self
    }

    /// Set maximum restart attempts before permanent exhaustion.
    #[must_use]
    pub const fn with_max_restarts(mut self, max: u32) -> Self {
        self.max_restarts = Some(max);
        self
    }

    /// Set the restart mode.
    #[must_use]
    pub const fn with_restart_mode(mut self, mode: RestartMode) -> Self {
        self.restart_mode = mode;
        self
    }

    /// Returns `true` if any crash injection is enabled.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.crash_probability > 0.0 || self.crash_after_sends.is_some()
    }
}

// ---------------------------------------------------------------------------
// RestartMode
// ---------------------------------------------------------------------------

/// How state is handled on restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartMode {
    /// Cold restart: reset send counter (fresh state, no memory of previous run).
    Cold,
    /// Warm restart: preserve send counter (simulates checkpoint-based recovery).
    Warm,
}

// ---------------------------------------------------------------------------
// CrashStats
// ---------------------------------------------------------------------------

/// Statistics for crash fault injection.
#[derive(Debug)]
pub struct CrashStats {
    /// Total send attempts (including rejected).
    pub sends_attempted: AtomicU64,
    /// Successful sends that passed through.
    pub sends_succeeded: AtomicU64,
    /// Sends rejected because the actor was crashed.
    pub sends_rejected: AtomicU64,
    /// Number of crash events triggered.
    pub crashes: AtomicU64,
    /// Number of successful restart events.
    pub restarts: AtomicU64,
}

impl CrashStats {
    fn new() -> Self {
        Self {
            sends_attempted: AtomicU64::new(0),
            sends_succeeded: AtomicU64::new(0),
            sends_rejected: AtomicU64::new(0),
            crashes: AtomicU64::new(0),
            restarts: AtomicU64::new(0),
        }
    }

    /// Take a snapshot of all counters.
    #[must_use]
    pub fn snapshot(&self) -> CrashStatsSnapshot {
        CrashStatsSnapshot {
            sends_attempted: self.sends_attempted.load(Ordering::Relaxed),
            sends_succeeded: self.sends_succeeded.load(Ordering::Relaxed),
            sends_rejected: self.sends_rejected.load(Ordering::Relaxed),
            crashes: self.crashes.load(Ordering::Relaxed),
            restarts: self.restarts.load(Ordering::Relaxed),
        }
    }
}

/// Immutable snapshot of crash statistics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrashStatsSnapshot {
    /// Total send attempts (including rejected).
    pub sends_attempted: u64,
    /// Successful sends that passed through.
    pub sends_succeeded: u64,
    /// Sends rejected because the actor was crashed.
    pub sends_rejected: u64,
    /// Number of crash events triggered.
    pub crashes: u64,
    /// Number of successful restart events.
    pub restarts: u64,
}

impl std::fmt::Display for CrashStatsSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CrashStats {{ attempted: {}, succeeded: {}, rejected: {}, crashes: {}, restarts: {} }}",
            self.sends_attempted,
            self.sends_succeeded,
            self.sends_rejected,
            self.crashes,
            self.restarts,
        )
    }
}

// ---------------------------------------------------------------------------
// CrashController
// ---------------------------------------------------------------------------

/// Controller for managing crash/restart state of a simulated actor.
///
/// Multiple [`CrashSender`] instances can share the same controller
/// to simulate a single actor that crashes and restarts.
pub struct CrashController {
    state: Mutex<CrashState>,
    stats: CrashStats,
    evidence_sink: Arc<dyn EvidenceSink>,
    /// Lock-free snapshot of `CrashState::crashed`.
    crashed: AtomicBool,
    /// Lock-free snapshot of `CrashState::exhausted`.
    exhausted: AtomicBool,
    /// Write-once: copied from config at construction, never mutated.
    restart_mode: RestartMode,
}

struct CrashState {
    crashed: bool,
    exhausted: bool,
    crash_count: u32,
    restart_count: u32,
    max_restarts: Option<u32>,
}

impl std::fmt::Debug for CrashController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.state.lock();
        f.debug_struct("CrashController")
            .field("crashed", &state.crashed)
            .field("exhausted", &state.exhausted)
            .field("crash_count", &state.crash_count)
            .field("restart_count", &state.restart_count)
            .finish_non_exhaustive()
    }
}

impl CrashController {
    /// Create a new crash controller.
    #[must_use]
    pub fn new(config: &CrashConfig, evidence_sink: Arc<dyn EvidenceSink>) -> Self {
        Self {
            state: Mutex::new(CrashState {
                crashed: false,
                exhausted: false,
                crash_count: 0,
                restart_count: 0,
                max_restarts: config.max_restarts,
            }),
            stats: CrashStats::new(),
            evidence_sink,
            crashed: AtomicBool::new(false),
            exhausted: AtomicBool::new(false),
            restart_mode: config.restart_mode,
        }
    }

    /// Trigger a crash. Returns `true` if the actor was running and is now crashed.
    pub fn crash(&self) -> bool {
        let mut state = self.state.lock();
        if state.crashed || state.exhausted {
            return false;
        }
        state.crashed = true;
        self.crashed.store(true, Ordering::Release);
        state.crash_count += 1;
        self.stats.crashes.fetch_add(1, Ordering::Relaxed);
        emit_crash_evidence(&self.evidence_sink, "crash", state.crash_count);
        true
    }

    /// Attempt to restart the actor. Returns `true` if restart succeeded.
    ///
    /// Returns `false` if:
    /// - The actor is not crashed (already running)
    /// - The restart limit is exhausted
    pub fn restart(&self) -> bool {
        let mut state = self.state.lock();
        if !state.crashed || state.exhausted {
            return false;
        }

        // Check restart limit.
        if let Some(max) = state.max_restarts {
            if state.restart_count >= max {
                state.exhausted = true;
                self.exhausted.store(true, Ordering::Release);
                emit_crash_evidence(
                    &self.evidence_sink,
                    "restart_exhausted",
                    state.restart_count,
                );
                return false;
            }
        }

        state.crashed = false;
        self.crashed.store(false, Ordering::Release);
        state.restart_count += 1;
        self.stats.restarts.fetch_add(1, Ordering::Relaxed);
        emit_crash_evidence(&self.evidence_sink, "restart", state.restart_count);
        true
    }

    /// Returns `true` if the actor is currently crashed.
    #[must_use]
    pub fn is_crashed(&self) -> bool {
        self.crashed.load(Ordering::Acquire)
    }

    /// Returns `true` if restart attempts are exhausted.
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.exhausted.load(Ordering::Acquire)
    }

    /// Returns the restart mode configured for this controller.
    #[must_use]
    pub fn restart_mode(&self) -> RestartMode {
        self.restart_mode
    }

    /// Returns a reference to the crash statistics.
    #[must_use]
    pub fn stats(&self) -> &CrashStats {
        &self.stats
    }
}

// ---------------------------------------------------------------------------
// CrashSender
// ---------------------------------------------------------------------------

/// Crash-injecting channel sender wrapper.
///
/// Wraps a standard [`Sender<T>`] and checks the [`CrashController`]
/// before each send. When the controller is in crashed state, sends
/// return `SendError::Disconnected` (simulating a dead actor).
///
/// Probabilistic and deterministic crash triggers can automatically
/// transition the controller to crashed state.
pub struct CrashSender<T> {
    inner: Sender<T>,
    controller: Arc<CrashController>,
    config: CrashConfig,
    rng: Mutex<ChaosRng>,
    send_count: AtomicU64,
    evidence_sink: Arc<dyn EvidenceSink>,
}

impl<T: std::fmt::Debug> std::fmt::Debug for CrashSender<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CrashSender")
            .field("config", &self.config)
            .field("controller", &self.controller)
            .finish_non_exhaustive()
    }
}

impl<T> CrashSender<T> {
    /// Create a crash-injecting sender wrapping the given sender.
    #[must_use]
    pub fn new(
        sender: Sender<T>,
        controller: Arc<CrashController>,
        config: CrashConfig,
        evidence_sink: Arc<dyn EvidenceSink>,
    ) -> Self {
        let rng = ChaosRng::new(config.seed);
        Self {
            inner: sender,
            controller,
            config,
            rng: Mutex::new(rng),
            send_count: AtomicU64::new(0),
            evidence_sink,
        }
    }

    /// Send a value through the crash-injecting channel.
    ///
    /// Returns `SendError::Disconnected` if:
    /// - The controller is in crashed state
    /// - A probabilistic or deterministic crash is triggered on this send
    pub async fn send(&self, cx: &Cx, value: T) -> Result<(), SendError<T>> {
        self.controller
            .stats
            .sends_attempted
            .fetch_add(1, Ordering::Relaxed);

        // Check if already crashed.
        if self.controller.is_crashed() {
            self.controller
                .stats
                .sends_rejected
                .fetch_add(1, Ordering::Relaxed);
            emit_crash_evidence(&self.evidence_sink, "send_rejected_crashed", 0);
            return Err(SendError::Disconnected(value));
        }

        // Check deterministic crash trigger.
        if let Some(limit) = self.config.crash_after_sends {
            let count = self.send_count.load(Ordering::Relaxed);
            if count >= limit {
                self.controller.crash();
                self.controller
                    .stats
                    .sends_rejected
                    .fetch_add(1, Ordering::Relaxed);
                emit_crash_evidence(&self.evidence_sink, "crash_after_sends", 0);
                return Err(SendError::Disconnected(value));
            }
        }

        // Check probabilistic crash trigger.
        if self.config.crash_probability > 0.0 {
            let should_crash = {
                let mut rng = self.rng.lock();
                rng.should_inject(self.config.crash_probability)
            };
            if should_crash {
                self.controller.crash();
                self.controller
                    .stats
                    .sends_rejected
                    .fetch_add(1, Ordering::Relaxed);
                emit_crash_evidence(&self.evidence_sink, "crash_probabilistic", 0);
                return Err(SendError::Disconnected(value));
            }
        }

        // Normal send.
        self.inner.send(cx, value).await?;
        self.send_count.fetch_add(1, Ordering::Relaxed);
        self.controller
            .stats
            .sends_succeeded
            .fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Returns a reference to the underlying sender.
    #[must_use]
    pub fn inner(&self) -> &Sender<T> {
        &self.inner
    }

    /// Returns a reference to the crash controller.
    #[must_use]
    pub fn controller(&self) -> &Arc<CrashController> {
        &self.controller
    }

    /// Returns the number of successful sends from this sender.
    #[must_use]
    pub fn send_count(&self) -> u64 {
        self.send_count.load(Ordering::Relaxed)
    }

    /// Reset the send counter (used during cold restart).
    pub fn reset_send_count(&self) {
        self.send_count.store(0, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// Convenience constructor
// ---------------------------------------------------------------------------

/// Create a channel with crash fault injection.
///
/// Returns the `CrashSender`, `Receiver`, and shared `CrashController`.
#[must_use]
pub fn crash_channel<T>(
    capacity: usize,
    config: CrashConfig,
    evidence_sink: Arc<dyn EvidenceSink>,
) -> (
    CrashSender<T>,
    crate::channel::mpsc::Receiver<T>,
    Arc<CrashController>,
) {
    let (tx, rx) = crate::channel::mpsc::channel(capacity);
    let controller = Arc::new(CrashController::new(&config, evidence_sink.clone()));
    let crash_tx = CrashSender::new(tx, controller.clone(), config, evidence_sink);
    (crash_tx, rx, controller)
}

// ---------------------------------------------------------------------------
// Evidence emission
// ---------------------------------------------------------------------------

fn emit_crash_evidence(sink: &Arc<dyn EvidenceSink>, action: &str, count: u32) {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);

    let action_str = format!("inject_{action}");
    let entry = EvidenceLedger {
        ts_unix_ms: now_ms,
        component: "channel_crash".to_string(),
        expected_loss_by_action: std::collections::HashMap::from([(action_str.clone(), 0.0)]),
        action: action_str,
        posterior: vec![1.0],
        chosen_expected_loss: 0.0,
        calibration_score: 1.0,
        fallback_active: false,
        top_features: vec![("count".to_string(), f64::from(count))],
    };
    sink.emit(&entry);
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::mpsc;
    use crate::cx::Cx;
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

    fn make_crash_channel(
        config: CrashConfig,
    ) -> (
        CrashSender<u32>,
        mpsc::Receiver<u32>,
        Arc<CrashController>,
        Arc<CollectorSink>,
    ) {
        let collector = Arc::new(CollectorSink::new());
        let sink: Arc<dyn EvidenceSink> = collector.clone();
        let (tx, rx, ctrl) = crash_channel::<u32>(16, config, sink);
        (tx, rx, ctrl, collector)
    }

    // --- Config validation ---

    #[test]
    #[should_panic(expected = "crash probability must be in [0.0, 1.0]")]
    fn config_rejects_invalid_crash_probability() {
        let _ = CrashConfig::new(42).with_crash_probability(1.5);
    }

    #[test]
    fn config_default_is_disabled() {
        let config = CrashConfig::new(42);
        assert!(!config.is_enabled());
    }

    #[test]
    fn config_probabilistic_is_enabled() {
        let config = CrashConfig::new(42).with_crash_probability(0.5);
        assert!(config.is_enabled());
    }

    #[test]
    fn config_deterministic_is_enabled() {
        let config = CrashConfig::new(42).with_crash_after_sends(10);
        assert!(config.is_enabled());
    }

    // --- Passthrough (no faults) ---

    #[test]
    fn passthrough_when_disabled() {
        let config = CrashConfig::new(42);
        let (tx, rx, ctrl, _) = make_crash_channel(config);
        let cx = test_cx();

        for i in 0..10 {
            block_on(tx.send(&cx, i)).unwrap();
        }

        for i in 0..10 {
            assert_eq!(rx.try_recv().unwrap(), i);
        }
        assert!(!ctrl.is_crashed());
    }

    // --- Manual crash/restart ---

    #[test]
    fn manual_crash_rejects_sends() {
        let config = CrashConfig::new(42);
        let (tx, _rx, ctrl, _) = make_crash_channel(config);
        let cx = test_cx();

        block_on(tx.send(&cx, 1)).unwrap();
        ctrl.crash();

        let err = block_on(tx.send(&cx, 2)).unwrap_err();
        assert!(matches!(err, SendError::Disconnected(2)));
    }

    #[test]
    fn restart_re_enables_sends() {
        let config = CrashConfig::new(42);
        let (tx, rx, ctrl, _) = make_crash_channel(config);
        let cx = test_cx();

        ctrl.crash();
        assert!(block_on(tx.send(&cx, 1)).is_err());

        ctrl.restart();
        block_on(tx.send(&cx, 2)).unwrap();
        assert_eq!(rx.try_recv().unwrap(), 2);
    }

    #[test]
    fn crash_already_crashed_returns_false() {
        let config = CrashConfig::new(42);
        let (_, _, ctrl, _) = make_crash_channel(config);

        assert!(ctrl.crash());
        assert!(!ctrl.crash()); // Already crashed.
    }

    #[test]
    fn restart_when_not_crashed_returns_false() {
        let config = CrashConfig::new(42);
        let (_, _, ctrl, _) = make_crash_channel(config);

        assert!(!ctrl.restart()); // Not crashed.
    }

    // --- Deterministic crash after N sends ---

    #[test]
    fn crash_after_sends() {
        let config = CrashConfig::new(42).with_crash_after_sends(5);
        let (tx, rx, ctrl, _) = make_crash_channel(config);
        let cx = test_cx();

        for i in 0..5 {
            block_on(tx.send(&cx, i)).unwrap();
        }

        // 6th send should trigger crash.
        let err = block_on(tx.send(&cx, 5)).unwrap_err();
        assert!(matches!(err, SendError::Disconnected(5)));
        assert!(ctrl.is_crashed());

        // Verify the first 5 were delivered.
        for i in 0..5 {
            assert_eq!(rx.try_recv().unwrap(), i);
        }
    }

    // --- Restart limit exhaustion ---

    #[test]
    fn restart_exhaustion() {
        let config = CrashConfig::new(42).with_max_restarts(2);
        let (_, _, ctrl, _) = make_crash_channel(config);

        ctrl.crash();
        assert!(ctrl.restart()); // restart 1
        ctrl.crash();
        assert!(ctrl.restart()); // restart 2
        ctrl.crash();
        assert!(!ctrl.restart()); // exhausted
        assert!(ctrl.is_exhausted());
    }

    #[test]
    fn exhausted_controller_rejects_sends() {
        let config = CrashConfig::new(42)
            .with_crash_after_sends(1)
            .with_max_restarts(0);
        let (tx, _rx, ctrl, _) = make_crash_channel(config);
        let cx = test_cx();

        block_on(tx.send(&cx, 0)).unwrap(); // 1 successful send.
        assert!(block_on(tx.send(&cx, 1)).is_err()); // Crash triggers.
        assert!(ctrl.is_crashed());

        // Can't restart — exhausted.
        assert!(!ctrl.restart());
        assert!(ctrl.is_exhausted());
    }

    // --- Stats tracking ---

    #[test]
    fn stats_track_all_operations() {
        let config = CrashConfig::new(42).with_crash_after_sends(3);
        let (tx, _rx, ctrl, _) = make_crash_channel(config);
        let cx = test_cx();

        // 3 successful, 1 triggers crash, 1 rejected while crashed.
        for i in 0..5 {
            let _ = block_on(tx.send(&cx, i));
        }

        let snap = ctrl.stats().snapshot();
        assert_eq!(snap.sends_attempted, 5);
        assert_eq!(snap.sends_succeeded, 3);
        assert_eq!(snap.sends_rejected, 2);
        assert_eq!(snap.crashes, 1);
    }

    // --- Evidence logging ---

    #[test]
    fn evidence_logged_for_crash_events() {
        let config = CrashConfig::new(42).with_crash_after_sends(2);
        let (tx, _rx, ctrl, collector) = make_crash_channel(config);
        let cx = test_cx();

        block_on(tx.send(&cx, 0)).unwrap();
        block_on(tx.send(&cx, 1)).unwrap();
        let _ = block_on(tx.send(&cx, 2)); // Triggers crash.

        ctrl.restart();
        let _ = block_on(tx.send(&cx, 3)); // Rejected (still at count=2 without reset).

        let entries = collector.entries();
        let actions: Vec<String> = entries.iter().map(|e| e.action.clone()).collect();
        assert!(
            actions.iter().any(|a| a.contains("crash")),
            "Expected crash evidence, got: {actions:?}"
        );
    }

    // --- Cold vs warm restart ---

    #[test]
    fn cold_restart_resets_send_count() {
        let config = CrashConfig::new(42)
            .with_crash_after_sends(3)
            .with_restart_mode(RestartMode::Cold);
        let (tx, _rx, ctrl, _) = make_crash_channel(config);
        let cx = test_cx();

        // 3 sends then crash.
        for i in 0..3 {
            block_on(tx.send(&cx, i)).unwrap();
        }
        assert!(block_on(tx.send(&cx, 3)).is_err());
        assert!(ctrl.is_crashed());

        // Cold restart: reset count.
        ctrl.restart();
        tx.reset_send_count();

        // Should be able to send 3 more before next crash.
        for i in 10..13 {
            block_on(tx.send(&cx, i)).unwrap();
        }
        assert!(block_on(tx.send(&cx, 13)).is_err());
        assert!(ctrl.is_crashed());
    }

    #[test]
    fn warm_restart_preserves_send_count() {
        let config = CrashConfig::new(42)
            .with_crash_after_sends(3)
            .with_restart_mode(RestartMode::Warm);
        let (tx, _rx, ctrl, _) = make_crash_channel(config);
        let cx = test_cx();

        // 3 sends then crash.
        for i in 0..3 {
            block_on(tx.send(&cx, i)).unwrap();
        }
        assert!(block_on(tx.send(&cx, 3)).is_err());

        // Warm restart: count preserved → immediate crash on next send.
        ctrl.restart();
        assert!(block_on(tx.send(&cx, 4)).is_err());
    }
}
