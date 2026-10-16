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
//! - **Cold**: Reset the actor-wide send counter and per-incarnation send stats
//! - **Warm**: Preserve send state and stats (checkpoint resume)
//!
//! Crash and restart counts remain cumulative in both modes so a cold restart
//! cannot erase lifecycle history or bypass the configured restart budget.
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
    /// Cold restart: reset the actor-wide send count and send statistics.
    Cold,
    /// Warm restart: preserve send state (simulates checkpoint-based recovery).
    Warm,
}

// ---------------------------------------------------------------------------
// CrashStats
// ---------------------------------------------------------------------------

/// Statistics for crash fault injection.
///
/// Send counters describe the current incarnation and reset after a successful
/// cold restart. Crash and restart counters describe the controller lifetime
/// and remain cumulative across both cold and warm restarts.
#[derive(Debug)]
pub struct CrashStats {
    /// Send attempts in the current incarnation (including rejected).
    pub sends_attempted: AtomicU64,
    /// Successful sends in the current incarnation.
    pub sends_succeeded: AtomicU64,
    /// Sends rejected in the current incarnation because the actor was crashed.
    pub sends_rejected: AtomicU64,
    /// Number of crash events over the controller lifetime.
    pub crashes: AtomicU64,
    /// Number of successful restart events over the controller lifetime.
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
            sends_attempted: self.sends_attempted.load(Ordering::Acquire),
            sends_succeeded: self.sends_succeeded.load(Ordering::Relaxed),
            sends_rejected: self.sends_rejected.load(Ordering::Relaxed),
            crashes: self.crashes.load(Ordering::Relaxed),
            restarts: self.restarts.load(Ordering::Relaxed),
        }
    }

    fn reset_send_counters(&self) {
        self.sends_succeeded.store(0, Ordering::Relaxed);
        self.sends_rejected.store(0, Ordering::Relaxed);
        // Publish the reset last. An acquiring snapshot that observes this
        // store (or a later attempt RMW in its release sequence) also observes
        // both outcome-counter resets above.
        self.sends_attempted.store(0, Ordering::Release);
    }
}

/// Immutable snapshot of crash statistics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrashStatsSnapshot {
    /// Send attempts in the current incarnation (including rejected).
    pub sends_attempted: u64,
    /// Successful sends in the current incarnation.
    pub sends_succeeded: u64,
    /// Sends rejected in the current incarnation because the actor was crashed.
    pub sends_rejected: u64,
    /// Number of crash events over the controller lifetime.
    pub crashes: u64,
    /// Number of successful restart events over the controller lifetime.
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
    /// Serializes actor-wide send admission commits with restart transitions.
    send_commit: Mutex<()>,
    /// Successful sends in the current actor incarnation.
    send_count: AtomicU64,
    /// Changes after every successful restart so pre-restart sends cannot
    /// commit into the next incarnation.
    incarnation: AtomicU64,
    evidence_sink: Arc<dyn EvidenceSink>,
    /// Deterministic evidence event sequence for replayable crash logs.
    evidence_seq: AtomicU64,
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
            send_commit: Mutex::new(()),
            send_count: AtomicU64::new(0),
            incarnation: AtomicU64::new(0),
            evidence_sink,
            evidence_seq: AtomicU64::new(0),
            crashed: AtomicBool::new(false),
            exhausted: AtomicBool::new(false),
            restart_mode: config.restart_mode,
        }
    }

    /// Trigger a crash. Returns `true` if the actor was running and is now crashed.
    pub fn crash(&self) -> bool {
        let crash_count = {
            let _send_guard = self.send_commit.lock();
            self.transition_to_crashed()
        };
        let Some(crash_count) = crash_count else {
            return false;
        };
        self.emit_crash_transition(crash_count);
        true
    }

    /// Mark the current incarnation crashed while `send_commit` is held.
    /// Evidence emission is deliberately separate so callbacks never run under
    /// either controller mutex.
    fn transition_to_crashed(&self) -> Option<u32> {
        let mut state = self.state.lock();
        if state.crashed || state.exhausted {
            return None;
        }
        state.crashed = true;
        self.crashed.store(true, Ordering::Release);
        state.crash_count += 1;
        self.stats.crashes.fetch_add(1, Ordering::Relaxed);
        Some(state.crash_count)
    }

    fn emit_crash_transition(&self, crash_count: u32) {
        emit_crash_evidence(
            &self.evidence_sink,
            self.next_evidence_ts(),
            "crash",
            crash_count,
        );
    }

    /// Attempt to restart the actor. Returns `true` if restart succeeded.
    ///
    /// Returns `false` if:
    /// - The actor is not crashed (already running)
    /// - The restart limit is exhausted
    pub fn restart(&self) -> bool {
        // A successful restart and the corresponding send-state transition are
        // one operation. Send futures may wait for channel capacity without
        // this gate, but they must re-enter it before committing and validate
        // the incarnation captured before they waited.
        let send_guard = self.send_commit.lock();
        let (action, count, restarted) = {
            let mut state = self.state.lock();
            if !state.crashed || state.exhausted {
                return false;
            }

            // Check restart limit.
            if let Some(max) = state.max_restarts {
                if state.restart_count >= max {
                    state.exhausted = true;
                    self.exhausted.store(true, Ordering::Release);
                    ("restart_exhausted", state.restart_count, false)
                } else {
                    if self.restart_mode == RestartMode::Cold {
                        self.send_count.store(0, Ordering::Relaxed);
                        self.stats.reset_send_counters();
                    }
                    self.incarnation.fetch_add(1, Ordering::AcqRel);
                    state.crashed = false;
                    self.crashed.store(false, Ordering::Release);
                    state.restart_count += 1;
                    self.stats.restarts.fetch_add(1, Ordering::Relaxed);
                    ("restart", state.restart_count, true)
                }
            } else {
                if self.restart_mode == RestartMode::Cold {
                    self.send_count.store(0, Ordering::Relaxed);
                    self.stats.reset_send_counters();
                }
                self.incarnation.fetch_add(1, Ordering::AcqRel);
                state.crashed = false;
                self.crashed.store(false, Ordering::Release);
                state.restart_count += 1;
                self.stats.restarts.fetch_add(1, Ordering::Relaxed);
                ("restart", state.restart_count, true)
            }
        };
        drop(send_guard);
        emit_crash_evidence(&self.evidence_sink, self.next_evidence_ts(), action, count);
        restarted
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

    fn next_evidence_ts(&self) -> u64 {
        self.evidence_seq
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1)
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
            evidence_sink,
        }
    }

    /// Send a value through the crash-injecting channel.
    ///
    /// Returns `SendError::Disconnected` if:
    /// - The controller is in crashed state
    /// - A probabilistic or deterministic crash is triggered on this send
    pub async fn send(&self, cx: &Cx, value: T) -> Result<(), SendError<T>> {
        // Account and decide against one controller incarnation. Restart takes
        // the same short gate, so a successful cold reset cannot race these
        // per-incarnation counters. No channel-capacity wait occurs under it.
        let incarnation = {
            let send_guard = self.controller.send_commit.lock();
            let incarnation = self.controller.incarnation.load(Ordering::Acquire);
            self.controller
                .stats
                .sends_attempted
                .fetch_add(1, Ordering::Relaxed);

            if self.controller.is_crashed() {
                self.controller
                    .stats
                    .sends_rejected
                    .fetch_add(1, Ordering::Relaxed);
                drop(send_guard);
                emit_crash_evidence(
                    &self.evidence_sink,
                    self.controller.next_evidence_ts(),
                    "send_rejected_crashed",
                    0,
                );
                return Err(SendError::Disconnected(value));
            }

            if let Some(limit) = self.config.crash_after_sends
                && self.controller.send_count.load(Ordering::Relaxed) >= limit
            {
                let crash_count = self.controller.transition_to_crashed();
                self.controller
                    .stats
                    .sends_rejected
                    .fetch_add(1, Ordering::Relaxed);
                drop(send_guard);
                if let Some(count) = crash_count {
                    self.controller.emit_crash_transition(count);
                }
                let action = if crash_count.is_some() {
                    "crash_after_sends"
                } else {
                    "send_rejected_crashed"
                };
                emit_crash_evidence(
                    &self.evidence_sink,
                    self.controller.next_evidence_ts(),
                    action,
                    0,
                );
                return Err(SendError::Disconnected(value));
            }

            if self.config.crash_probability > 0.0 {
                let should_crash = {
                    let mut rng = self.rng.lock();
                    rng.should_inject(self.config.crash_probability)
                };
                if should_crash {
                    let crash_count = self.controller.transition_to_crashed();
                    self.controller
                        .stats
                        .sends_rejected
                        .fetch_add(1, Ordering::Relaxed);
                    drop(send_guard);
                    if let Some(count) = crash_count {
                        self.controller.emit_crash_transition(count);
                    }
                    let action = if crash_count.is_some() {
                        "crash_probabilistic"
                    } else {
                        "send_rejected_crashed"
                    };
                    emit_crash_evidence(
                        &self.evidence_sink,
                        self.controller.next_evidence_ts(),
                        action,
                        0,
                    );
                    return Err(SendError::Disconnected(value));
                }
            }

            incarnation
        };

        // Reserve capacity before entering exact-N admission. A capacity wake
        // may synchronously reenter this sender, so no admission permit may be
        // held across the reserve await.
        let permit = match self.inner.reserve(cx).await {
            Ok(permit) => permit,
            Err(SendError::Disconnected(())) => return Err(SendError::Disconnected(value)),
            Err(SendError::Cancelled(())) => return Err(SendError::Cancelled(value)),
            Err(SendError::Full(())) => return Err(SendError::Full(value)),
        };

        // Successful-send state belongs to the shared controller, not one
        // wrapper. The gate covers only the authoritative state recheck,
        // non-awaiting commit, and accounting; callbacks run after release.
        let send_guard = self.controller.send_commit.lock();

        // A send that waited across any restart belongs to the prior
        // incarnation and must not commit into the new one. Cold restart has
        // already discarded its attempt count; Warm preserves that count, so
        // only the Warm case records the terminal rejection here.
        if self.controller.incarnation.load(Ordering::Acquire) != incarnation {
            if self.controller.restart_mode == RestartMode::Warm {
                self.controller
                    .stats
                    .sends_rejected
                    .fetch_add(1, Ordering::Relaxed);
            }
            drop(send_guard);
            drop(permit);
            emit_crash_evidence(
                &self.evidence_sink,
                self.controller.next_evidence_ts(),
                "send_rejected_restart",
                0,
            );
            return Err(SendError::Disconnected(value));
        }

        // A concurrent admitted send or manual crash may have changed the
        // authoritative state while this attempt waited for the gate. Release
        // the gate before evidence callbacks, which may reenter this sender.
        if self.controller.is_crashed() {
            self.controller
                .stats
                .sends_rejected
                .fetch_add(1, Ordering::Relaxed);
            drop(send_guard);
            drop(permit);
            emit_crash_evidence(
                &self.evidence_sink,
                self.controller.next_evidence_ts(),
                "send_rejected_crashed",
                0,
            );
            return Err(SendError::Disconnected(value));
        }
        if let Some(limit) = self.config.crash_after_sends
            && self.controller.send_count.load(Ordering::Relaxed) >= limit
        {
            let crash_count = self.controller.transition_to_crashed();
            self.controller
                .stats
                .sends_rejected
                .fetch_add(1, Ordering::Relaxed);
            drop(send_guard);
            drop(permit);
            if let Some(count) = crash_count {
                self.controller.emit_crash_transition(count);
            }
            let action = if crash_count.is_some() {
                "crash_after_sends"
            } else {
                "send_rejected_crashed"
            };
            emit_crash_evidence(
                &self.evidence_sink,
                self.controller.next_evidence_ts(),
                action,
                0,
            );
            return Err(SendError::Disconnected(value));
        }

        // Commit without invoking the receiver's arbitrary Waker until
        // successful-send accounting is durable. This ensures a panicking
        // receiver wake cannot under-count an already-visible message.
        let (result, receiver_wake) = permit.try_send_deferred_wake(value);
        if result.is_ok() {
            self.controller.send_count.fetch_add(1, Ordering::Relaxed);
            self.controller
                .stats
                .sends_succeeded
                .fetch_add(1, Ordering::Relaxed);
        }

        // Release admission before invoking the arbitrary receiver callback.
        // Reentry observes the already-committed count, while synchronous
        // block-on reentry cannot park behind a permit held by this callback.
        drop(send_guard);
        receiver_wake.wake();
        result
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

    /// Returns actor-wide successful sends in the current incarnation.
    ///
    /// Every sender sharing this controller observes the same count. A
    /// successful cold restart resets it; a warm restart preserves it.
    #[must_use]
    pub fn send_count(&self) -> u64 {
        self.controller.send_count.load(Ordering::Relaxed)
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

fn emit_crash_evidence(sink: &Arc<dyn EvidenceSink>, ts_unix_ms: u64, action: &str, count: u32) {
    let action_str = format!("inject_{action}");
    let entry = EvidenceLedger {
        ts_unix_ms,
        component: "channel_crash".to_string(),
        expected_loss_by_action: std::collections::BTreeMap::from([(action_str.clone(), 0.0)]),
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
#[path = "crash_inline_tests.rs"]
mod tests;
