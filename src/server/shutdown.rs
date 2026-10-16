//! Shutdown coordination for HTTP server lifecycle.
//!
//! This module provides [`ShutdownSignal`] for coordinating graceful server shutdown
//! with drain timeouts and phase tracking. It builds on the lower-level
//! [`ShutdownController`] by adding drain-phase
//! awareness and timeout semantics.

use crate::cancel::{DrainPhase, ProgressCertificate};
use crate::cx::Cx;
use crate::signal::{ShutdownController, ShutdownReceiver};
use crate::sync::Notify;
use crate::time::{Sleep, TimerDriverHandle, sleep_until, wall_now};
use crate::types::Time;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::time::Duration;

#[cfg(test)]
thread_local! {
    static TRIGGER_IMMEDIATE_PRE_PHASE_HOOK:
        std::cell::RefCell<Option<Box<dyn FnMut()>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn run_trigger_immediate_pre_phase_hook() {
    TRIGGER_IMMEDIATE_PRE_PHASE_HOOK.with(|hook| {
        if let Some(mut hook) = hook.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(not(test))]
fn run_trigger_immediate_pre_phase_hook() {}

#[derive(Clone)]
enum ShutdownTimeSource {
    WallClock,
    TimerDriver(TimerDriverHandle),
    Custom(fn() -> Time),
}

impl ShutdownTimeSource {
    fn capture_from_current() -> Self {
        Cx::current()
            .and_then(|cx| cx.timer_driver())
            .map_or(Self::WallClock, Self::TimerDriver)
    }

    fn now(&self) -> Time {
        match self {
            Self::WallClock => wall_now(),
            Self::TimerDriver(driver) => driver.now(),
            Self::Custom(time_getter) => time_getter(),
        }
    }
}

/// Phases of a graceful server shutdown.
///
/// Shutdown proceeds through these phases in order:
/// 1. [`Running`](ShutdownPhase::Running) — normal operation
/// 2. [`Draining`](ShutdownPhase::Draining) — stopped accepting, waiting for in-flight
/// 3. [`ForceClosing`](ShutdownPhase::ForceClosing) — drain timeout exceeded, force-closing
/// 4. [`Stopped`](ShutdownPhase::Stopped) — all connections closed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ShutdownPhase {
    /// Normal operation — accepting connections and processing requests.
    Running = 0,
    /// Stopped accepting new connections; waiting for in-flight requests to complete.
    Draining = 1,
    /// Drain timeout exceeded; force-closing remaining connections.
    ForceClosing = 2,
    /// All connections closed; server fully stopped.
    Stopped = 3,
}

impl ShutdownPhase {
    fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Running,
            1 => Self::Draining,
            2 => Self::ForceClosing,
            _ => Self::Stopped,
        }
    }
}

impl std::fmt::Display for ShutdownPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Running => write!(f, "Running"),
            Self::Draining => write!(f, "Draining"),
            Self::ForceClosing => write!(f, "ForceClosing"),
            Self::Stopped => write!(f, "Stopped"),
        }
    }
}

/// Statistics collected during shutdown.
#[derive(Debug, Clone)]
pub struct ShutdownStats {
    /// Number of connections that completed gracefully during drain.
    pub drained: usize,
    /// Number of connections force-closed after the drain timeout.
    pub force_closed: usize,
    /// Total shutdown duration.
    pub duration: Duration,
    /// Request-aware drain report when the shutdown was supervised by a
    /// [`GracefulDrainSupervisor`]
    /// (br-asupersync-server-stack-hardening-eeexl1.2, D2.2b).
    ///
    /// `None` for connection-level-only drains (no request supervision was
    /// attached). The report carries the in-flight request trajectory and the
    /// [`ProgressCertificate`]
    /// verdict for the drain.
    pub drain_report: Option<GracefulDrainReport>,
}

// ============================================================================
// Request-aware drain certificate (br-asupersync-server-stack-hardening-eeexl1.2, D2.1)
// ============================================================================

/// Structured outcome of a request-aware graceful drain.
///
/// Unlike [`ShutdownStats`], which counts *connections*, this report tracks
/// in-flight *requests* (region children — see `RegionRecord::child_count`)
/// and carries the [`ProgressCertificate`] verdict as a measurable
/// accepted-history diagnostic. It is the operator-visible surface for the
/// drain: a structured log line plus a programmatic value that tests and
/// dashboards can inspect without treating the empirical status as a future
/// completion guarantee.
///
/// The [`Display`](std::fmt::Display) rendering is deterministic (fixed float
/// precision, duration in whole milliseconds) so it can be golden-tested.
#[derive(Debug, Clone, PartialEq)]
pub struct GracefulDrainReport {
    /// In-flight request count observed when the drain began.
    pub requests_at_drain_start: usize,
    /// Requests that completed during the drain window
    /// (`requests_at_drain_start` minus those still live at the end).
    pub requests_completed: usize,
    /// Requests still in flight when the drain ended (force-cancelled at the
    /// hard deadline). Zero on a clean drain to quiescence.
    pub requests_stranded: usize,
    /// In-flight request count at the moment the soft budget elapsed and the
    /// drain escalated stragglers, or `None` if escalation never fired.
    ///
    /// `requests_completed` counts the in-flight counter reaching zero and
    /// cannot distinguish naturally-completed requests from ones interrupted
    /// by post-escalation force-close; this field preserves that boundary
    /// (br-asupersync-server-stack-hardening-eeexl1.2, D2.4).
    pub requests_at_escalation: Option<usize>,
    /// Number of in-flight-count observations fed to the certificate.
    pub observations: usize,
    /// Final drain-phase classification from the progress certificate.
    pub final_phase: DrainPhase,
    /// Whether the certificate's accepted-history heuristic classified the
    /// drain as empirically converging.
    ///
    /// This is separate from the conditional tail calculations and is not a
    /// probability, future-drift, termination, or bounded-drain guarantee.
    pub converging: bool,
    /// Conditional lower-tail confidence calculation for quiescence within
    /// twice the plug-in estimated remaining steps.
    pub confidence_bound: f64,
    /// Estimated remaining steps to quiescence (`None` if undetermined).
    pub estimated_remaining_steps: Option<f64>,
    /// Whether the certificate detected a stall (no progress) during drain.
    pub stall_detected: bool,
    /// Whether the drain reached quiescence (zero in-flight requests).
    pub reached_quiescence: bool,
    /// Whether the drain ended by hitting the hard deadline rather than
    /// reaching quiescence.
    pub hard_deadline_hit: bool,
    /// Wall/virtual time elapsed from drain start to drain end.
    pub drain_duration: Duration,
}

impl std::fmt::Display for GracefulDrainReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Graceful Drain Report")?;
        writeln!(f, "=====================")?;
        writeln!(f, "Requests at start:  {}", self.requests_at_drain_start)?;
        writeln!(f, "Requests completed: {}", self.requests_completed)?;
        writeln!(f, "Requests stranded:  {}", self.requests_stranded)?;
        match self.requests_at_escalation {
            Some(count) => writeln!(f, "At escalation:      {count}")?,
            None => writeln!(f, "At escalation:      never")?,
        }
        writeln!(f, "Observations:       {}", self.observations)?;
        writeln!(f, "Final drain phase:  {}", self.final_phase)?;
        writeln!(f, "Converging:         {}", self.converging)?;
        writeln!(f, "Confidence bound:   {:.6}", self.confidence_bound)?;
        match self.estimated_remaining_steps {
            Some(est) => writeln!(f, "Est. remaining:     {est:.1} steps")?,
            None => writeln!(f, "Est. remaining:     N/A")?,
        }
        writeln!(f, "Stall detected:     {}", self.stall_detected)?;
        writeln!(f, "Reached quiescence: {}", self.reached_quiescence)?;
        writeln!(f, "Hard deadline hit:  {}", self.hard_deadline_hit)?;
        writeln!(
            f,
            "Drain duration:     {}ms",
            self.drain_duration.as_millis()
        )?;
        Ok(())
    }
}

/// Drives a [`ProgressCertificate`] over the live in-flight request count for
/// the duration of a graceful drain, then produces a [`GracefulDrainReport`].
///
/// The certificate models the remaining in-flight request count as a Lyapunov
/// potential that should descend to zero (quiescence). Feed it one observation
/// per drain tick via [`observe`](Self::observe); the resulting
/// [`drain_phase`](Self::phase) supplies a heuristic distinction between an
/// observed `slow_tail` and a configured `stalled` run. Operators combine it
/// with deadlines and telemetry completeness when deciding whether to keep
/// waiting or escalate; it is not a standalone proof of future behavior.
///
/// This type is intentionally transport-agnostic: the HTTP/server layers
/// (D2.2+) supply the in-flight count (e.g. `RegionRecord::child_count`) and
/// the clock; the certificate math lives entirely in
/// [`ProgressCertificate`].
#[derive(Debug)]
pub struct GracefulDrainTracker {
    certificate: ProgressCertificate,
    requests_at_drain_start: usize,
    last_remaining: usize,
    requests_at_escalation: Option<usize>,
    observations: usize,
    start_time: Time,
}

impl GracefulDrainTracker {
    /// Begin tracking a drain that starts with `initial_in_flight` requests
    /// at logical time `now`.
    ///
    /// The initial count is recorded as the certificate's first observation so
    /// the report's `requests_at_drain_start` and the certificate's initial
    /// potential agree.
    #[must_use]
    pub fn new(initial_in_flight: usize, now: Time) -> Self {
        let mut certificate = ProgressCertificate::with_defaults();
        certificate.observe(usize_to_potential(initial_in_flight));
        Self {
            certificate,
            requests_at_drain_start: initial_in_flight,
            last_remaining: initial_in_flight,
            requests_at_escalation: None,
            observations: 1,
            start_time: now,
        }
    }

    /// Record that the drain escalated stragglers with `remaining_in_flight`
    /// requests still live.
    ///
    /// Call at most once, at the soft-deadline escalation transition; the
    /// first recorded value wins. The report's `requests_at_escalation`
    /// preserves the completed-naturally vs interrupted-by-escalation
    /// boundary that the final counter value alone cannot express.
    pub fn record_escalation(&mut self, remaining_in_flight: usize) {
        if self.requests_at_escalation.is_none() {
            self.requests_at_escalation = Some(remaining_in_flight);
        }
    }

    /// Record the current in-flight request count.
    ///
    /// Call once per drain tick. Monotonic descent is expected but not
    /// required; the certificate clamps and tracks non-decreasing runs as
    /// stalls.
    pub fn observe(&mut self, remaining_in_flight: usize) {
        self.certificate
            .observe(usize_to_potential(remaining_in_flight));
        self.last_remaining = remaining_in_flight;
        self.observations += 1;
    }

    /// The certificate's current drain-phase classification.
    #[must_use]
    pub fn phase(&self) -> DrainPhase {
        self.certificate.drain_phase()
    }

    /// The most recently observed in-flight request count.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.last_remaining
    }

    /// Finish the drain at logical time `now` and produce the report.
    ///
    /// `hard_deadline_hit` records whether the drain ended because the hard
    /// deadline elapsed (rather than reaching quiescence). Any requests still
    /// in flight at that point are reported as `requests_stranded`.
    #[must_use]
    pub fn finish(&self, now: Time, hard_deadline_hit: bool) -> GracefulDrainReport {
        let verdict = self.certificate.verdict();
        let stranded = self.last_remaining;
        let completed = self.requests_at_drain_start.saturating_sub(stranded);
        let drain_duration = if now > self.start_time {
            Duration::from_nanos(now.duration_since(self.start_time))
        } else {
            Duration::ZERO
        };
        GracefulDrainReport {
            requests_at_drain_start: self.requests_at_drain_start,
            requests_completed: completed,
            requests_stranded: stranded,
            requests_at_escalation: self.requests_at_escalation,
            observations: self.observations,
            final_phase: verdict.drain_phase,
            converging: verdict.converging,
            confidence_bound: verdict.confidence_bound,
            estimated_remaining_steps: verdict.estimated_remaining_steps,
            stall_detected: verdict.stall_detected,
            reached_quiescence: stranded == 0,
            hard_deadline_hit,
            drain_duration,
        }
    }
}

/// Maps an in-flight request count to a certificate potential.
///
/// `usize` request counts are far below `f64`'s exact-integer range
/// (`2^53`), so the conversion is lossless for any realistic in-flight count.
#[inline]
#[allow(clippy::cast_precision_loss)]
fn usize_to_potential(count: usize) -> f64 {
    // Precision-safe for counts up to 2^53; above that, saturate rather than
    // silently aliasing (a count near 2^53 is itself a runtime pathology).
    const MAX_EXACT_F64: f64 = 9_007_199_254_740_992.0;
    let count_as_f64 = count as f64;
    count_as_f64.min(MAX_EXACT_F64)
}

/// The action a graceful-drain driver should take after one in-flight-count
/// observation.
///
/// This is the decision output of [`GracefulDrainSupervisor::observe`]. The
/// driver (the HTTP accept/shutdown supervisor, wired in a later slice) maps
/// each variant to a concrete action; the supervisor itself performs no I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainStep {
    /// Requests are still draining within the soft budget; keep waiting.
    Continue,
    /// The soft drain budget elapsed with requests still in flight: the driver
    /// should escalate the stragglers through the cancellation protocol. Emitted
    /// at most once (the transition into the escalation window).
    Escalate,
    /// All in-flight requests completed; the drain reached quiescence and the
    /// driver should finish and emit the report.
    Quiescent,
    /// The hard deadline elapsed with requests still in flight: the driver
    /// should force-close the stragglers and emit the report.
    HardDeadline,
}

/// Decision state machine for a request-aware graceful drain.
///
/// Wraps a [`GracefulDrainTracker`] (which carries the progress certificate)
/// and adds the soft-budget / hard-deadline sequencing the operator-facing
/// drain needs: feed it the current in-flight request count once per tick via
/// [`observe`](Self::observe) and it returns the [`DrainStep`] the driver
/// should act on. It is deliberately synchronous and I/O-free so the drain
/// policy can be unit-tested deterministically; the async driving loop, the
/// in-flight counter, and the actual straggler cancellation are wired by the
/// HTTP-layer integration slice.
///
/// Two budgets, both measured from drain start:
/// * `drain_budget` — soft: in-flight requests are allowed to finish on their
///   own until it elapses, after which the driver escalates ([`DrainStep::Escalate`]).
/// * `hard_budget` — hard: after it elapses the driver force-closes any
///   stragglers ([`DrainStep::HardDeadline`]). Must be `>= drain_budget`.
#[derive(Debug)]
pub struct GracefulDrainSupervisor {
    tracker: GracefulDrainTracker,
    drain_deadline: Time,
    hard_deadline: Time,
    escalated: bool,
}

impl GracefulDrainSupervisor {
    /// Begin supervising a drain that starts at `now` with
    /// `initial_in_flight` requests.
    ///
    /// `drain_budget` is the soft window; `hard_budget` is the hard window.
    /// `hard_budget` is clamped up to at least `drain_budget` so the hard
    /// deadline can never precede the soft one.
    #[must_use]
    pub fn new(
        initial_in_flight: usize,
        now: Time,
        drain_budget: Duration,
        hard_budget: Duration,
    ) -> Self {
        let effective_hard = hard_budget.max(drain_budget);
        let to_nanos = |d: Duration| -> u64 { d.as_nanos().min(u128::from(u64::MAX)) as u64 };
        Self {
            tracker: GracefulDrainTracker::new(initial_in_flight, now),
            drain_deadline: now.saturating_add_nanos(to_nanos(drain_budget)),
            hard_deadline: now.saturating_add_nanos(to_nanos(effective_hard)),
            escalated: false,
        }
    }

    /// Record the current in-flight request count at logical time `now` and
    /// return the action the driver should take.
    ///
    /// Quiescence (zero in-flight) wins over every deadline; the hard deadline
    /// wins over the returned action for the soft escalation window. The
    /// escalation boundary is still recorded before a hard-deadline return so
    /// the final report preserves the last pre-cancellation in-flight count.
    /// [`DrainStep::Escalate`] is emitted at most once — on the first
    /// observation at or after the soft deadline while requests remain and
    /// before the hard deadline — so the driver escalates exactly once.
    pub fn observe(&mut self, remaining_in_flight: usize, now: Time) -> DrainStep {
        self.tracker.observe(remaining_in_flight);
        if remaining_in_flight == 0 {
            return DrainStep::Quiescent;
        }
        if now >= self.drain_deadline && !self.escalated {
            self.escalated = true;
            self.tracker.record_escalation(remaining_in_flight);
            if now < self.hard_deadline {
                return DrainStep::Escalate;
            }
        }
        if now >= self.hard_deadline {
            return DrainStep::HardDeadline;
        }
        DrainStep::Continue
    }

    /// Record that another driver path already escalated to force-close at or
    /// after the soft deadline.
    ///
    /// The HTTP listener runs the request-aware supervisor concurrently with
    /// the connection-manager drain. The connection manager may win the race at
    /// the soft deadline, force-close handlers, and drop the in-flight counter
    /// to zero before the supervisor's next tick. In that case the supervisor
    /// must preserve the last observed non-zero request count as the
    /// escalation boundary even though its next observed action is
    /// [`DrainStep::Quiescent`].
    #[must_use]
    pub fn record_external_escalation(&mut self) -> bool {
        if self.escalated {
            return false;
        }
        let remaining = self.tracker.remaining();
        if remaining == 0 {
            return false;
        }
        self.escalated = true;
        self.tracker.record_escalation(remaining);
        true
    }

    /// The current drain-phase classification from the progress certificate.
    #[must_use]
    pub fn phase(&self) -> DrainPhase {
        self.tracker.phase()
    }

    /// The most recently observed in-flight request count.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.tracker.remaining()
    }

    /// The soft drain deadline (escalation point).
    #[must_use]
    pub fn drain_deadline(&self) -> Time {
        self.drain_deadline
    }

    /// The hard drain deadline (force-close point).
    #[must_use]
    pub fn hard_deadline(&self) -> Time {
        self.hard_deadline
    }

    /// Whether the soft budget has elapsed and escalation has been signalled.
    #[must_use]
    pub fn escalated(&self) -> bool {
        self.escalated
    }

    /// Produce the final report at logical time `now`.
    ///
    /// `hard_deadline_hit` should reflect whether the drain ended on the hard
    /// deadline (the driver typically passes `true` when it last saw
    /// [`DrainStep::HardDeadline`]). Any still-in-flight requests are reported
    /// as stranded.
    #[must_use]
    pub fn finish(&self, now: Time, hard_deadline_hit: bool) -> GracefulDrainReport {
        self.tracker.finish(now, hard_deadline_hit)
    }
}

/// Internal state shared between the signal and its subscribers.
pub(crate) struct SignalState {
    pub(crate) phase: AtomicU8,
    pub(crate) controller: ShutdownController,
    pub(crate) phase_notify: Notify,
    pub(crate) force_close_notify: Notify,
    pub(crate) stopped_notify: Notify,
    time_source: ShutdownTimeSource,
    pub(crate) has_drain_deadline: AtomicBool,
    pub(crate) drain_deadline: AtomicU64,
    pub(crate) has_drain_start: AtomicBool,
    pub(crate) drain_start: AtomicU64,
}

/// Broadcast signal for server shutdown coordination.
///
/// `ShutdownSignal` wraps the lower-level [`ShutdownController`] with
/// shutdown-phase tracking and drain timeout awareness. Handlers can check
/// whether the server is draining to add `Connection: close` headers or
/// reject new work.
///
/// # Example
///
/// ```ignore
/// use asupersync::server::ShutdownSignal;
/// use std::time::Duration;
///
/// let signal = ShutdownSignal::new();
///
/// // In the accept loop:
/// if signal.is_draining() {
///     break; // stop accepting
/// }
///
/// // Initiate shutdown with a 30-second drain period:
/// signal.begin_drain(Duration::from_secs(30));
/// ```
#[derive(Clone)]
pub struct ShutdownSignal {
    pub(crate) state: Arc<SignalState>,
}

impl ShutdownSignal {
    fn duration_to_nanos(duration: Duration) -> u64 {
        duration.as_nanos().min(u128::from(u64::MAX)) as u64
    }

    /// Creates a new shutdown signal in the [`Running`](ShutdownPhase::Running) phase.
    #[must_use]
    pub fn new() -> Self {
        Self::with_time_source(ShutdownTimeSource::capture_from_current())
    }

    /// Creates a new shutdown signal with a custom time source.
    #[must_use]
    pub fn with_time_getter(time_getter: fn() -> Time) -> Self {
        Self::with_time_source(ShutdownTimeSource::Custom(time_getter))
    }

    fn with_time_source(time_source: ShutdownTimeSource) -> Self {
        Self {
            state: Arc::new(SignalState {
                phase: AtomicU8::new(ShutdownPhase::Running as u8),
                controller: ShutdownController::new(),
                phase_notify: Notify::new(),
                force_close_notify: Notify::new(),
                stopped_notify: Notify::new(),
                time_source,
                has_drain_deadline: AtomicBool::new(false),
                drain_deadline: AtomicU64::new(0),
                has_drain_start: AtomicBool::new(false),
                drain_start: AtomicU64::new(0),
            }),
        }
    }

    pub(crate) fn current_time(&self) -> Time {
        self.state.time_source.now()
    }

    pub(crate) async fn wait_until(&self, deadline: Time) {
        let sleep = match &self.state.time_source {
            ShutdownTimeSource::TimerDriver(driver) => {
                Sleep::with_timer_driver(deadline, driver.clone())
            }
            ShutdownTimeSource::Custom(time_getter) => {
                Sleep::with_time_getter(deadline, *time_getter)
            }
            ShutdownTimeSource::WallClock => sleep_until(deadline),
        };
        // Wait for the deadline itself. A cancel-aware sleep completes as soon
        // as the waiting task is cancelled, which is how a region-owned
        // listener is shut down, and every drain loop re-checking the clock
        // then spun on it until the deadline (br-asupersync-m8xsjx).
        let mut sleep = std::pin::pin!(sleep);
        std::future::poll_fn(|cx| sleep.as_mut().poll_deadline(cx)).await;
    }

    /// Returns the current shutdown phase.
    #[must_use]
    pub fn phase(&self) -> ShutdownPhase {
        ShutdownPhase::from_u8(self.state.phase.load(Ordering::Acquire))
    }

    /// Returns `true` if the server is in the draining phase.
    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.phase() == ShutdownPhase::Draining
    }

    /// Returns `true` if shutdown has been initiated (draining or later).
    #[must_use]
    pub fn is_shutting_down(&self) -> bool {
        self.phase() != ShutdownPhase::Running
    }

    /// Returns `true` if the server has fully stopped.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.phase() == ShutdownPhase::Stopped
    }

    /// Returns the drain deadline, if one has been set.
    #[must_use]
    pub fn drain_deadline(&self) -> Option<Time> {
        self.state
            .has_drain_deadline
            .load(Ordering::Acquire)
            .then(|| Time::from_nanos(self.state.drain_deadline.load(Ordering::Acquire)))
    }

    /// Subscribes to the underlying shutdown controller for async waiting.
    #[must_use]
    pub fn subscribe(&self) -> ShutdownReceiver {
        self.state.controller.subscribe()
    }

    /// Begins the drain phase with the given timeout.
    ///
    /// Transitions from `Running` to `Draining` and sets a drain deadline.
    /// The caller should stop accepting new connections after this call.
    ///
    /// Returns `false` if shutdown was already initiated.
    #[must_use]
    pub fn begin_drain(&self, timeout: Duration) -> bool {
        let result = self.state.phase.compare_exchange(
            ShutdownPhase::Running as u8,
            ShutdownPhase::Draining as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        if result.is_ok() {
            let now = self.current_time();
            let deadline = now.saturating_add_nanos(Self::duration_to_nanos(timeout));
            self.state
                .drain_deadline
                .store(deadline.as_nanos(), Ordering::Release);
            self.state.has_drain_deadline.store(true, Ordering::Release);
            self.state
                .drain_start
                .store(now.as_nanos(), Ordering::Release);
            self.state.has_drain_start.store(true, Ordering::Release);
            self.state.controller.shutdown();
            self.state.phase_notify.notify_waiters();
            true
        } else {
            false
        }
    }

    /// Transitions to the force-closing phase.
    ///
    /// Called when the drain timeout has expired and remaining connections
    /// must be terminated. Returns `false` if not currently draining.
    #[must_use]
    pub fn begin_force_close(&self) -> bool {
        if self.enter_force_closing() {
            self.notify_force_closing();
            true
        } else {
            false
        }
    }

    /// The `Draining -> ForceClosing` transition alone, without waking anyone,
    /// so a caller can make it under its own lock and notify after unlocking.
    pub(crate) fn enter_force_closing(&self) -> bool {
        self.state
            .phase
            .compare_exchange(
                ShutdownPhase::Draining as u8,
                ShutdownPhase::ForceClosing as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Wakes the waiters of a force-close entered with
    /// [`Self::enter_force_closing`].
    pub(crate) fn notify_force_closing(&self) {
        self.state.force_close_notify.notify_waiters();
        self.state.phase_notify.notify_waiters();
    }

    /// Marks the server as fully stopped.
    ///
    /// Called when all connections have been closed.
    ///
    /// Also trips the underlying shutdown controller so subscribers blocked on
    /// [`ShutdownReceiver::wait`] wake even if the server reaches `Stopped`
    /// without first entering the drain phase.
    pub fn mark_stopped(&self) {
        self.state
            .phase
            .store(ShutdownPhase::Stopped as u8, Ordering::Release);
        self.state.controller.shutdown();
        self.state.stopped_notify.notify_waiters();
        self.state.force_close_notify.notify_waiters();
        self.state.phase_notify.notify_waiters();
    }

    /// Waits until the shutdown phase reaches or passes the target phase.
    ///
    /// This method is race-free: it guarantees that it will not miss a phase
    /// transition that occurs concurrently.
    pub async fn wait_for_phase(&self, target: ShutdownPhase) {
        let state = Arc::clone(&self.state);
        loop {
            if ShutdownPhase::from_u8(state.phase.load(Ordering::Acquire)) as u8 >= target as u8 {
                return;
            }

            let notify = match target {
                ShutdownPhase::ForceClosing => &state.force_close_notify,
                ShutdownPhase::Stopped => &state.stopped_notify,
                ShutdownPhase::Running | ShutdownPhase::Draining => &state.phase_notify,
            };
            let mut notified = std::pin::pin!(notify.notified());
            std::future::poll_fn(|cx| {
                if std::future::Future::poll(notified.as_mut(), cx).is_ready()
                    || ShutdownPhase::from_u8(state.phase.load(Ordering::Acquire)) as u8
                        >= target as u8
                {
                    return std::task::Poll::Ready(());
                }
                std::task::Poll::Pending
            })
            .await;
        }
    }

    /// Returns a notification future that is signaled on phase changes and drain deadlines.
    #[must_use]
    pub fn phase_notified(&self) -> crate::sync::Notified<'_> {
        self.state.phase_notify.notified()
    }

    /// Returns the time when drain began, if applicable.
    #[must_use]
    pub fn drain_start(&self) -> Option<Time> {
        self.state
            .has_drain_start
            .load(Ordering::Acquire)
            .then(|| Time::from_nanos(self.state.drain_start.load(Ordering::Acquire)))
    }

    /// Collects shutdown statistics.
    ///
    /// Call after `mark_stopped()` to get the final stats. The `drained` count
    /// is the number of connections that completed gracefully, and `force_closed`
    /// is the number that were force-closed after the drain timeout.
    ///
    /// # Arguments
    ///
    /// * `drained` — Number of connections that completed during drain phase.
    /// * `force_closed` — Number of connections force-closed after timeout.
    #[must_use]
    pub fn collect_stats(&self, drained: usize, force_closed: usize) -> ShutdownStats {
        let duration = self.drain_start().map_or(Duration::ZERO, |start| {
            let now = self.current_time();
            Duration::from_nanos(now.duration_since(start))
        });
        ShutdownStats {
            drained,
            force_closed,
            duration,
            drain_report: None,
        }
    }

    /// Triggers an immediate stop (skips drain phase).
    ///
    /// This transitions directly to [`ShutdownPhase::ForceClosing`], records a
    /// zero-length drain deadline at the current time, and wakes drain waiters.
    /// Call [`mark_stopped`](Self::mark_stopped) once all connections have
    /// actually closed to reach the terminal [`ShutdownPhase::Stopped`] phase.
    ///
    /// Useful for hard shutdowns or test scenarios.
    pub fn trigger_immediate(&self) {
        if self.phase() == ShutdownPhase::Stopped {
            self.state.controller.shutdown();
            self.state.stopped_notify.notify_waiters();
            self.state.force_close_notify.notify_waiters();
            self.state.phase_notify.notify_waiters();
            return;
        }
        let now = self.current_time();
        run_trigger_immediate_pre_phase_hook();
        self.state
            .phase
            .fetch_max(ShutdownPhase::ForceClosing as u8, Ordering::AcqRel);
        if self.phase() == ShutdownPhase::Stopped {
            self.state.controller.shutdown();
            self.state.stopped_notify.notify_waiters();
            self.state.force_close_notify.notify_waiters();
            self.state.phase_notify.notify_waiters();
            return;
        }
        self.state
            .drain_deadline
            .store(now.as_nanos(), Ordering::Release);
        self.state.has_drain_deadline.store(true, Ordering::Release);
        if !self.state.has_drain_start.load(Ordering::Acquire) {
            self.state
                .drain_start
                .store(now.as_nanos(), Ordering::Release);
            self.state.has_drain_start.store(true, Ordering::Release);
        }
        self.state.controller.shutdown();
        self.state.force_close_notify.notify_waiters();
        self.state.phase_notify.notify_waiters();
    }
}

impl Default for ShutdownSignal {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ShutdownSignal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShutdownSignal")
            .field("phase", &self.phase())
            .finish()
    }
}

#[cfg(test)]
#[path = "shutdown_inline_tests.rs"]
mod tests;
