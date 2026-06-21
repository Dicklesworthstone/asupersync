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
    /// [`ProgressCertificate`](crate::cancel::progress_certificate::ProgressCertificate)
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
/// and carries the [`ProgressCertificate`] verdict that turns "is the drain
/// converging?" into a measurable claim. It is the operator-visible surface
/// for the drain: a structured log line plus a programmatic value that tests
/// and dashboards can assert against.
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
    /// Whether the certificate judged the drain to be converging.
    pub converging: bool,
    /// Lower bound on P(quiescence within the estimated remaining steps).
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
/// [`drain_phase`](Self::phase) distinguishes a normal `slow_tail` from a true
/// `stalled` drain, which is exactly the signal an operator needs to decide
/// whether to keep waiting or escalate to the hard deadline.
///
/// This type is intentionally transport-agnostic: the HTTP/server layers
/// (D2.2+) supply the in-flight count (e.g. `RegionRecord::child_count`) and
/// the clock; the certificate math lives entirely in
/// [`ProgressCertificate`](crate::cancel::ProgressCertificate).
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
struct SignalState {
    phase: AtomicU8,
    controller: ShutdownController,
    phase_notify: Notify,
    force_close_notify: Notify,
    stopped_notify: Notify,
    time_source: ShutdownTimeSource,
    has_drain_deadline: AtomicBool,
    drain_deadline: AtomicU64,
    has_drain_start: AtomicBool,
    drain_start: AtomicU64,
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
    state: Arc<SignalState>,
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
        match &self.state.time_source {
            ShutdownTimeSource::TimerDriver(driver) => {
                Sleep::with_timer_driver(deadline, driver.clone()).await;
            }
            ShutdownTimeSource::Custom(time_getter) => {
                Sleep::with_time_getter(deadline, *time_getter).await;
            }
            ShutdownTimeSource::WallClock => {
                sleep_until(deadline).await;
            }
        }
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
        let result = self.state.phase.compare_exchange(
            ShutdownPhase::Draining as u8,
            ShutdownPhase::ForceClosing as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        if result.is_ok() {
            self.state.force_close_notify.notify_waiters();
            self.state.phase_notify.notify_waiters();
            true
        } else {
            false
        }
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
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::cx::Cx;
    use crate::test_utils::init_test_logging;
    use crate::time::{TimerDriverHandle, VirtualClock};
    use crate::types::{Budget, RegionId, TaskId};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_NOW: AtomicU64 = AtomicU64::new(0);

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    fn set_test_time(nanos: u64) {
        TEST_NOW.store(nanos, Ordering::SeqCst);
    }

    fn test_time() -> Time {
        Time::from_nanos(TEST_NOW.load(Ordering::SeqCst))
    }

    fn set_trigger_immediate_pre_phase_hook(hook: Option<Box<dyn FnMut()>>) {
        TRIGGER_IMMEDIATE_PRE_PHASE_HOOK.with(|slot| {
            *slot.borrow_mut() = hook;
        });
    }

    struct FlagWaker(Arc<AtomicBool>);

    impl std::task::Wake for FlagWaker {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn initial_state_is_running() {
        init_test("initial_state_is_running");
        let signal = ShutdownSignal::new();
        crate::assert_with_log!(
            signal.phase() == ShutdownPhase::Running,
            "phase",
            ShutdownPhase::Running,
            signal.phase()
        );
        crate::assert_with_log!(
            !signal.is_draining(),
            "not draining",
            false,
            signal.is_draining()
        );
        crate::assert_with_log!(
            !signal.is_shutting_down(),
            "not shutting down",
            false,
            signal.is_shutting_down()
        );
        crate::assert_with_log!(
            !signal.is_stopped(),
            "not stopped",
            false,
            signal.is_stopped()
        );
        crate::test_complete!("initial_state_is_running");
    }

    #[test]
    fn begin_drain_transitions_to_draining() {
        init_test("begin_drain_transitions_to_draining");
        let signal = ShutdownSignal::new();
        let initiated = signal.begin_drain(Duration::from_secs(30));
        crate::assert_with_log!(initiated, "initiated", true, initiated);
        crate::assert_with_log!(
            signal.phase() == ShutdownPhase::Draining,
            "phase",
            ShutdownPhase::Draining,
            signal.phase()
        );
        crate::assert_with_log!(
            signal.is_draining(),
            "is draining",
            true,
            signal.is_draining()
        );
        crate::assert_with_log!(
            signal.is_shutting_down(),
            "is shutting down",
            true,
            signal.is_shutting_down()
        );
        let has_deadline = signal.drain_deadline().is_some();
        crate::assert_with_log!(has_deadline, "has deadline", true, has_deadline);
        crate::test_complete!("begin_drain_transitions_to_draining");
    }

    #[test]
    fn begin_drain_idempotent() {
        init_test("begin_drain_idempotent");
        let signal = ShutdownSignal::new();
        let first = signal.begin_drain(Duration::from_secs(30));
        crate::assert_with_log!(first, "first drain", true, first);

        let second = signal.begin_drain(Duration::from_secs(60));
        crate::assert_with_log!(!second, "second drain rejected", false, second);

        crate::assert_with_log!(
            signal.phase() == ShutdownPhase::Draining,
            "still draining",
            ShutdownPhase::Draining,
            signal.phase()
        );
        crate::test_complete!("begin_drain_idempotent");
    }

    #[test]
    fn with_time_getter_controls_deadline_and_duration() {
        init_test("with_time_getter_controls_deadline_and_duration");
        set_test_time(0);
        let signal = ShutdownSignal::with_time_getter(test_time);

        let initiated = signal.begin_drain(Duration::from_nanos(25));
        crate::assert_with_log!(initiated, "initiated", true, initiated);
        crate::assert_with_log!(
            signal.drain_start() == Some(Time::from_nanos(0)),
            "drain start uses injected clock",
            Some(Time::from_nanos(0)),
            signal.drain_start()
        );
        crate::assert_with_log!(
            signal.drain_deadline() == Some(Time::from_nanos(25)),
            "deadline uses injected clock",
            Some(Time::from_nanos(25)),
            signal.drain_deadline()
        );

        set_test_time(80);
        let stats = signal.collect_stats(2, 1);
        crate::assert_with_log!(
            stats.duration == Duration::from_nanos(80),
            "duration uses injected clock",
            Duration::from_nanos(80),
            stats.duration
        );
        crate::test_complete!("with_time_getter_controls_deadline_and_duration");
    }

    #[test]
    fn new_captures_timer_driver_from_current_context() {
        init_test("new_captures_timer_driver_from_current_context");
        let virtual_clock = Arc::new(VirtualClock::starting_at(Time::from_secs(42)));
        let timer_driver = TimerDriverHandle::with_virtual_clock(Arc::clone(&virtual_clock));
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(7, 0),
            TaskId::new_for_test(9, 0),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer_driver),
            None,
        );

        let signal = {
            let _guard = Cx::set_current(Some(cx));
            ShutdownSignal::new()
        };

        let initiated = signal.begin_drain(Duration::from_secs(3));
        crate::assert_with_log!(initiated, "initiated", true, initiated);
        crate::assert_with_log!(
            signal.drain_start() == Some(Time::from_secs(42)),
            "captured driver sets drain start",
            Some(Time::from_secs(42)),
            signal.drain_start()
        );
        crate::assert_with_log!(
            signal.drain_deadline() == Some(Time::from_secs(45)),
            "captured driver sets drain deadline",
            Some(Time::from_secs(45)),
            signal.drain_deadline()
        );

        virtual_clock.advance(7_000_000_000);
        let stats = signal.collect_stats(1, 0);
        crate::assert_with_log!(
            stats.duration == Duration::from_secs(7),
            "captured driver sets stats duration",
            Duration::from_secs(7),
            stats.duration
        );
        crate::test_complete!("new_captures_timer_driver_from_current_context");
    }

    #[test]
    fn wait_until_uses_captured_timer_driver_without_ambient_context() {
        init_test("wait_until_uses_captured_timer_driver_without_ambient_context");
        let virtual_clock = Arc::new(VirtualClock::starting_at(Time::from_secs(10)));
        let timer_driver = TimerDriverHandle::with_virtual_clock(Arc::clone(&virtual_clock));
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(7, 1),
            TaskId::new_for_test(9, 1),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer_driver.clone()),
            None,
        );

        let signal = {
            let _guard = Cx::set_current(Some(cx));
            ShutdownSignal::new()
        };
        let _no_cx = Cx::set_current(None);

        let waker = std::task::Waker::noop();
        let mut task_cx = std::task::Context::from_waker(waker);
        let deadline = Time::from_secs(12);
        let mut wait = std::pin::pin!(signal.wait_until(deadline));

        let first_poll = std::future::Future::poll(wait.as_mut(), &mut task_cx);
        crate::assert_with_log!(
            first_poll.is_pending(),
            "wait is pending before deadline",
            true,
            first_poll.is_pending()
        );
        crate::assert_with_log!(
            timer_driver.pending_count() == 1,
            "captured timer driver owns registration",
            1,
            timer_driver.pending_count()
        );

        virtual_clock.advance(1_000_000_000);
        let fired_before_deadline = timer_driver.process_timers();
        crate::assert_with_log!(
            fired_before_deadline == 0,
            "timer does not fire before deadline",
            0,
            fired_before_deadline
        );

        virtual_clock.advance(1_000_000_000);
        let fired_at_deadline = timer_driver.process_timers();
        crate::assert_with_log!(
            fired_at_deadline == 1,
            "captured timer driver fires at deadline",
            1,
            fired_at_deadline
        );

        let second_poll = std::future::Future::poll(wait.as_mut(), &mut task_cx);
        crate::assert_with_log!(
            second_poll.is_ready(),
            "wait becomes ready after captured timer fires",
            true,
            second_poll.is_ready()
        );
        crate::assert_with_log!(
            timer_driver.pending_count() == 0,
            "registration clears after completion",
            0,
            timer_driver.pending_count()
        );
        crate::test_complete!("wait_until_uses_captured_timer_driver_without_ambient_context");
    }

    #[test]
    fn wait_until_with_time_getter_wakes_after_logical_clock_advance() {
        init_test("wait_until_with_time_getter_wakes_after_logical_clock_advance");
        set_test_time(0);
        let signal = ShutdownSignal::with_time_getter(test_time);

        let woke = Arc::new(AtomicBool::new(false));
        let waker = std::task::Waker::from(Arc::new(FlagWaker(Arc::clone(&woke))));
        let mut task_cx = std::task::Context::from_waker(&waker);
        let deadline = Time::from_secs(10);
        let mut wait = std::pin::pin!(signal.wait_until(deadline));

        let first_poll = std::future::Future::poll(wait.as_mut(), &mut task_cx);
        crate::assert_with_log!(
            first_poll.is_pending(),
            "wait is pending before deadline",
            true,
            first_poll.is_pending()
        );

        set_test_time(deadline.as_nanos());

        let second_poll = std::future::Future::poll(wait.as_mut(), &mut task_cx);
        crate::assert_with_log!(
            second_poll.is_ready(),
            "wait becomes ready after logical deadline",
            true,
            second_poll.is_ready()
        );
        crate::test_complete!("wait_until_with_time_getter_wakes_after_logical_clock_advance");
    }

    #[test]
    fn force_close_from_draining() {
        init_test("force_close_from_draining");
        let signal = ShutdownSignal::new();
        let began = signal.begin_drain(Duration::from_secs(1));
        crate::assert_with_log!(began, "begin drain", true, began);

        let forced = signal.begin_force_close();
        crate::assert_with_log!(forced, "force close", true, forced);
        crate::assert_with_log!(
            signal.phase() == ShutdownPhase::ForceClosing,
            "phase",
            ShutdownPhase::ForceClosing,
            signal.phase()
        );
        crate::test_complete!("force_close_from_draining");
    }

    #[test]
    fn force_close_waiter_is_not_consumed_by_drain_transition() {
        init_test("force_close_waiter_is_not_consumed_by_drain_transition");
        let signal = ShutdownSignal::new();
        let woke = Arc::new(AtomicBool::new(false));
        let waker = std::task::Waker::from(Arc::new(FlagWaker(Arc::clone(&woke))));
        let mut task_cx = std::task::Context::from_waker(&waker);
        let mut wait = Box::pin(signal.wait_for_phase(ShutdownPhase::ForceClosing));

        let first_poll = std::future::Future::poll(wait.as_mut(), &mut task_cx);
        crate::assert_with_log!(
            first_poll.is_pending(),
            "force-close waiter starts pending",
            true,
            first_poll.is_pending()
        );

        let began = signal.begin_drain(Duration::from_secs(1));
        crate::assert_with_log!(began, "begin drain", true, began);
        crate::assert_with_log!(
            !woke.load(Ordering::SeqCst),
            "drain transition does not consume force-close waiter",
            false,
            woke.load(Ordering::SeqCst)
        );

        let forced = signal.begin_force_close();
        crate::assert_with_log!(forced, "force close", true, forced);
        crate::assert_with_log!(
            woke.load(Ordering::SeqCst),
            "force-close transition wakes force-close waiter",
            true,
            woke.load(Ordering::SeqCst)
        );

        let second_poll = std::future::Future::poll(wait.as_mut(), &mut task_cx);
        crate::assert_with_log!(
            second_poll.is_ready(),
            "force-close waiter completes after target transition",
            true,
            second_poll.is_ready()
        );
        crate::test_complete!("force_close_waiter_is_not_consumed_by_drain_transition");
    }

    #[test]
    fn force_close_only_from_draining() {
        init_test("force_close_only_from_draining");
        let signal = ShutdownSignal::new();

        // Can't force close from Running
        let forced = signal.begin_force_close();
        crate::assert_with_log!(!forced, "can't force from running", false, forced);
        crate::assert_with_log!(
            signal.phase() == ShutdownPhase::Running,
            "still running",
            ShutdownPhase::Running,
            signal.phase()
        );
        crate::test_complete!("force_close_only_from_draining");
    }

    #[test]
    fn mark_stopped() {
        init_test("mark_stopped");
        let signal = ShutdownSignal::new();
        let began = signal.begin_drain(Duration::from_secs(1));
        crate::assert_with_log!(began, "begin drain", true, began);
        let forced = signal.begin_force_close();
        crate::assert_with_log!(forced, "force close", true, forced);
        signal.mark_stopped();

        crate::assert_with_log!(
            signal.phase() == ShutdownPhase::Stopped,
            "stopped",
            ShutdownPhase::Stopped,
            signal.phase()
        );
        crate::assert_with_log!(signal.is_stopped(), "is stopped", true, signal.is_stopped());
        crate::test_complete!("mark_stopped");
    }

    #[test]
    fn trigger_immediate_skips_drain() {
        init_test("trigger_immediate_skips_drain");
        let signal = ShutdownSignal::new();
        signal.trigger_immediate();

        crate::assert_with_log!(
            signal.phase() == ShutdownPhase::ForceClosing,
            "force-closing immediately",
            ShutdownPhase::ForceClosing,
            signal.phase()
        );
        crate::assert_with_log!(
            !signal.is_stopped(),
            "not stopped until mark_stopped",
            false,
            signal.is_stopped()
        );
        crate::test_complete!("trigger_immediate_skips_drain");
    }

    #[test]
    fn trigger_immediate_records_force_close_metadata_without_prior_drain() {
        init_test("trigger_immediate_records_force_close_metadata_without_prior_drain");
        set_test_time(123);
        let signal = ShutdownSignal::with_time_getter(test_time);

        signal.trigger_immediate();

        crate::assert_with_log!(
            signal.drain_start() == Some(Time::from_nanos(123)),
            "immediate start uses injected clock",
            Some(Time::from_nanos(123)),
            signal.drain_start()
        );
        crate::assert_with_log!(
            signal.drain_deadline() == Some(Time::from_nanos(123)),
            "immediate deadline is current time",
            Some(Time::from_nanos(123)),
            signal.drain_deadline()
        );
        crate::test_complete!("trigger_immediate_records_force_close_metadata_without_prior_drain");
    }

    #[test]
    fn trigger_immediate_does_not_regress_stopped_phase() {
        init_test("trigger_immediate_does_not_regress_stopped_phase");
        let signal = ShutdownSignal::new();
        signal.mark_stopped();

        signal.trigger_immediate();

        crate::assert_with_log!(
            signal.phase() == ShutdownPhase::Stopped,
            "stopped phase preserved",
            ShutdownPhase::Stopped,
            signal.phase()
        );
        crate::test_complete!("trigger_immediate_does_not_regress_stopped_phase");
    }

    #[test]
    fn trigger_immediate_preserves_stopped_phase_under_interleaved_mark_stopped() {
        init_test("trigger_immediate_preserves_stopped_phase_under_interleaved_mark_stopped");
        let signal = ShutdownSignal::new();
        let hook_signal = signal.clone();
        set_trigger_immediate_pre_phase_hook(Some(Box::new(move || {
            hook_signal.mark_stopped();
        })));

        signal.trigger_immediate();

        crate::assert_with_log!(
            signal.phase() == ShutdownPhase::Stopped,
            "interleaved mark_stopped keeps terminal phase",
            ShutdownPhase::Stopped,
            signal.phase()
        );
        crate::assert_with_log!(
            signal.is_stopped(),
            "signal remains stopped after interleaving",
            true,
            signal.is_stopped()
        );
        crate::test_complete!(
            "trigger_immediate_preserves_stopped_phase_under_interleaved_mark_stopped"
        );
    }

    #[test]
    fn trigger_immediate_overrides_interleaved_begin_drain_metadata() {
        init_test("trigger_immediate_overrides_interleaved_begin_drain_metadata");
        set_test_time(123);
        let signal = ShutdownSignal::with_time_getter(test_time);
        let hook_signal = signal.clone();
        set_trigger_immediate_pre_phase_hook(Some(Box::new(move || {
            let began = hook_signal.begin_drain(Duration::from_secs(30));
            assert!(began, "hook begin_drain should succeed");
        })));

        signal.trigger_immediate();

        crate::assert_with_log!(
            signal.phase() == ShutdownPhase::ForceClosing,
            "interleaved begin_drain still reaches force-closing",
            ShutdownPhase::ForceClosing,
            signal.phase()
        );
        crate::assert_with_log!(
            signal.drain_start() == Some(Time::from_nanos(123)),
            "original drain start is retained",
            Some(Time::from_nanos(123)),
            signal.drain_start()
        );
        crate::assert_with_log!(
            signal.drain_deadline() == Some(Time::from_nanos(123)),
            "immediate trigger overwrites graceful-drain deadline",
            Some(Time::from_nanos(123)),
            signal.drain_deadline()
        );
        crate::test_complete!("trigger_immediate_overrides_interleaved_begin_drain_metadata");
    }

    #[test]
    fn subscribe_receives_shutdown() {
        init_test("subscribe_receives_shutdown");
        let signal = ShutdownSignal::new();
        let receiver = signal.subscribe();

        let not_shutting = receiver.is_shutting_down();
        crate::assert_with_log!(!not_shutting, "not shutting", false, not_shutting);

        let began = signal.begin_drain(Duration::from_secs(30));
        crate::assert_with_log!(began, "begin drain", true, began);

        let shutting = receiver.is_shutting_down();
        crate::assert_with_log!(shutting, "shutting down", true, shutting);
        crate::test_complete!("subscribe_receives_shutdown");
    }

    #[test]
    fn display_formatting() {
        init_test("display_formatting");
        let cases = [
            (ShutdownPhase::Running, "Running"),
            (ShutdownPhase::Draining, "Draining"),
            (ShutdownPhase::ForceClosing, "ForceClosing"),
            (ShutdownPhase::Stopped, "Stopped"),
        ];
        for (phase, expected) in cases {
            let actual = format!("{phase}");
            crate::assert_with_log!(actual == expected, "phase display", expected, actual);
        }
        crate::test_complete!("display_formatting");
    }

    #[test]
    fn clone_shares_state() {
        init_test("clone_shares_state");
        let signal = ShutdownSignal::new();
        let cloned = signal.clone();

        let began = signal.begin_drain(Duration::from_secs(30));
        crate::assert_with_log!(began, "begin drain", true, began);

        crate::assert_with_log!(
            cloned.is_draining(),
            "clone sees drain",
            true,
            cloned.is_draining()
        );
        crate::test_complete!("clone_shares_state");
    }

    // ====================================================================
    // Async integration tests
    // ====================================================================

    #[test]
    fn phase_changed_fires_on_drain() {
        init_test("phase_changed_fires_on_drain");
        crate::test_utils::run_test(|| async {
            let signal = ShutdownSignal::new();
            let signal2 = signal.clone();

            // Spawn a thread that will begin drain after a short delay
            let handle = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                let began = signal2.begin_drain(Duration::from_secs(30));
                assert!(began, "begin drain should succeed");
            });

            // Wait for the phase change
            signal.wait_for_phase(ShutdownPhase::Draining).await;
            let new_phase = signal.phase();
            crate::assert_with_log!(
                new_phase == ShutdownPhase::Draining,
                "phase after drain",
                ShutdownPhase::Draining,
                new_phase
            );

            handle.join().expect("thread panicked");
        });
        crate::test_complete!("phase_changed_fires_on_drain");
    }

    #[test]
    fn phase_changed_fires_on_force_close() {
        init_test("phase_changed_fires_on_force_close");
        crate::test_utils::run_test(|| async {
            let signal = ShutdownSignal::new();
            let began = signal.begin_drain(Duration::from_secs(30));
            crate::assert_with_log!(began, "begin drain", true, began);

            let signal2 = signal.clone();
            let handle = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                let forced = signal2.begin_force_close();
                assert!(forced, "force close should succeed");
            });

            signal.wait_for_phase(ShutdownPhase::ForceClosing).await;
            let new_phase = signal.phase();
            crate::assert_with_log!(
                new_phase == ShutdownPhase::ForceClosing,
                "phase after force close",
                ShutdownPhase::ForceClosing,
                new_phase
            );

            handle.join().expect("thread panicked");
        });
        crate::test_complete!("phase_changed_fires_on_force_close");
    }

    #[test]
    fn phase_changed_fires_on_mark_stopped() {
        init_test("phase_changed_fires_on_mark_stopped");
        crate::test_utils::run_test(|| async {
            let signal = ShutdownSignal::new();
            let began = signal.begin_drain(Duration::from_secs(30));
            crate::assert_with_log!(began, "begin drain", true, began);
            let forced = signal.begin_force_close();
            crate::assert_with_log!(forced, "force close", true, forced);

            let signal2 = signal.clone();
            let handle = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                signal2.mark_stopped();
            });

            signal.wait_for_phase(ShutdownPhase::Stopped).await;
            let new_phase = signal.phase();
            crate::assert_with_log!(
                new_phase == ShutdownPhase::Stopped,
                "phase after stopped",
                ShutdownPhase::Stopped,
                new_phase
            );

            handle.join().expect("thread panicked");
        });
        crate::test_complete!("phase_changed_fires_on_mark_stopped");
    }

    #[test]
    fn phase_changed_fires_on_immediate() {
        init_test("phase_changed_fires_on_immediate");
        crate::test_utils::run_test(|| async {
            let signal = ShutdownSignal::new();
            let signal2 = signal.clone();

            let handle = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                signal2.trigger_immediate();
            });

            signal.wait_for_phase(ShutdownPhase::ForceClosing).await;
            let new_phase = signal.phase();
            crate::assert_with_log!(
                new_phase == ShutdownPhase::ForceClosing,
                "phase after immediate",
                ShutdownPhase::ForceClosing,
                new_phase
            );

            handle.join().expect("thread panicked");
        });
        crate::test_complete!("phase_changed_fires_on_immediate");
    }

    #[test]
    fn full_lifecycle_phase_transitions() {
        init_test("full_lifecycle_phase_transitions");
        crate::test_utils::run_test(|| async {
            let signal = ShutdownSignal::new();

            // Phase 1: Running
            crate::assert_with_log!(
                signal.phase() == ShutdownPhase::Running,
                "starts running",
                ShutdownPhase::Running,
                signal.phase()
            );

            // Phase 2: Draining (triggered from another thread)
            {
                let sig = signal.clone();
                let h = std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(10));
                    let began = sig.begin_drain(Duration::from_secs(1));
                    assert!(began, "begin drain should succeed");
                });
                signal.wait_for_phase(ShutdownPhase::Draining).await;
                let p = signal.phase();
                crate::assert_with_log!(
                    p == ShutdownPhase::Draining,
                    "draining",
                    ShutdownPhase::Draining,
                    p
                );
                h.join().expect("thread panicked");
            }

            // Phase 3: ForceClosing
            {
                let sig = signal.clone();
                let h = std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(10));
                    let forced = sig.begin_force_close();
                    assert!(forced, "force close should succeed");
                });
                signal.wait_for_phase(ShutdownPhase::ForceClosing).await;
                let p = signal.phase();
                crate::assert_with_log!(
                    p == ShutdownPhase::ForceClosing,
                    "force closing",
                    ShutdownPhase::ForceClosing,
                    p
                );
                h.join().expect("thread panicked");
            }

            // Phase 4: Stopped
            {
                let sig = signal.clone();
                let h = std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(10));
                    sig.mark_stopped();
                });
                signal.wait_for_phase(ShutdownPhase::Stopped).await;
                let p = signal.phase();
                crate::assert_with_log!(
                    p == ShutdownPhase::Stopped,
                    "stopped",
                    ShutdownPhase::Stopped,
                    p
                );
                h.join().expect("thread panicked");
            }
        });
        crate::test_complete!("full_lifecycle_phase_transitions");
    }

    #[test]
    fn subscriber_receives_drain_signal() {
        init_test("subscriber_receives_drain_signal");
        crate::test_utils::run_test(|| async {
            let signal = ShutdownSignal::new();
            let mut receiver = signal.subscribe();

            let not_shutting = receiver.is_shutting_down();
            crate::assert_with_log!(!not_shutting, "not shutting down", false, not_shutting);

            // Trigger drain from thread
            let sig = signal.clone();
            let h = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(10));
                let began = sig.begin_drain(Duration::from_secs(30));
                assert!(began, "begin drain should succeed");
            });

            // Wait for the underlying signal
            receiver.wait().await;

            let shutting = receiver.is_shutting_down();
            crate::assert_with_log!(shutting, "is shutting down", true, shutting);

            h.join().expect("thread panicked");
        });
        crate::test_complete!("subscriber_receives_drain_signal");
    }

    #[test]
    fn subscriber_receives_mark_stopped_without_prior_drain() {
        init_test("subscriber_receives_mark_stopped_without_prior_drain");
        crate::test_utils::run_test(|| async {
            let signal = ShutdownSignal::new();
            let mut receiver = signal.subscribe();
            let signal2 = signal.clone();

            let handle = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(10));
                signal2.mark_stopped();
            });

            receiver.wait().await;

            let shutting = receiver.is_shutting_down();
            crate::assert_with_log!(shutting, "receiver sees shutdown", true, shutting);
            crate::assert_with_log!(
                signal.phase() == ShutdownPhase::Stopped,
                "phase after mark_stopped",
                ShutdownPhase::Stopped,
                signal.phase()
            );

            handle.join().expect("thread panicked");
        });
        crate::test_complete!("subscriber_receives_mark_stopped_without_prior_drain");
    }

    // ====================================================================
    // Stats collection tests
    // ====================================================================

    #[test]
    fn collect_stats_before_drain() {
        init_test("collect_stats_before_drain");
        let signal = ShutdownSignal::new();

        let stats = signal.collect_stats(0, 0);
        crate::assert_with_log!(stats.drained == 0, "drained", 0, stats.drained);
        crate::assert_with_log!(
            stats.force_closed == 0,
            "force_closed",
            0,
            stats.force_closed
        );
        // Duration should be zero since drain hasn't started
        crate::assert_with_log!(
            stats.duration == Duration::ZERO,
            "duration zero",
            Duration::ZERO,
            stats.duration
        );
        crate::test_complete!("collect_stats_before_drain");
    }

    #[test]
    fn collect_stats_after_drain() {
        init_test("collect_stats_after_drain");
        let signal = ShutdownSignal::new();

        let began = signal.begin_drain(Duration::from_secs(30));
        crate::assert_with_log!(began, "drain started", true, began);

        // Small sleep to ensure measurable duration
        std::thread::sleep(Duration::from_millis(5));

        let stats = signal.collect_stats(10, 3);
        crate::assert_with_log!(stats.drained == 10, "drained", 10, stats.drained);
        crate::assert_with_log!(
            stats.force_closed == 3,
            "force_closed",
            3,
            stats.force_closed
        );

        let nonzero = stats.duration > Duration::ZERO;
        crate::assert_with_log!(nonzero, "nonzero duration", true, nonzero);
        crate::test_complete!("collect_stats_after_drain");
    }

    #[test]
    fn drain_start_tracking() {
        init_test("drain_start_tracking");
        let signal = ShutdownSignal::new();

        let before = signal.drain_start();
        crate::assert_with_log!(
            before.is_none(),
            "no start before drain",
            true,
            before.is_none()
        );

        let began = signal.begin_drain(Duration::from_secs(30));
        crate::assert_with_log!(began, "drain started", true, began);

        let after = signal.drain_start();
        crate::assert_with_log!(after.is_some(), "start after drain", true, after.is_some());
        crate::test_complete!("drain_start_tracking");
    }

    #[test]
    fn concurrent_begin_drain_only_one_wins() {
        init_test("concurrent_begin_drain_only_one_wins");
        let signal = ShutdownSignal::new();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let winners = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..2 {
            let sig = signal.clone();
            let b = std::sync::Arc::clone(&barrier);
            let w = std::sync::Arc::clone(&winners);
            handles.push(std::thread::spawn(move || {
                b.wait();
                if sig.begin_drain(Duration::from_secs(30)) {
                    w.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }));
        }

        barrier.wait();
        for h in handles {
            h.join().expect("thread panicked");
        }

        let winner_count = winners.load(std::sync::atomic::Ordering::Relaxed);
        crate::assert_with_log!(winner_count == 1, "exactly one winner", 1, winner_count);
        crate::assert_with_log!(
            signal.phase() == ShutdownPhase::Draining,
            "phase is draining",
            ShutdownPhase::Draining,
            signal.phase()
        );
        crate::test_complete!("concurrent_begin_drain_only_one_wins");
    }

    #[test]
    fn mark_stopped_from_draining_skips_force_close() {
        init_test("mark_stopped_from_draining_skips_force_close");
        let signal = ShutdownSignal::new();
        let began = signal.begin_drain(Duration::from_secs(30));
        crate::assert_with_log!(began, "begin drain", true, began);

        // Directly mark stopped without going through ForceClosing
        signal.mark_stopped();
        crate::assert_with_log!(
            signal.phase() == ShutdownPhase::Stopped,
            "stopped from draining",
            ShutdownPhase::Stopped,
            signal.phase()
        );
        crate::test_complete!("mark_stopped_from_draining_skips_force_close");
    }

    #[test]
    fn shutdown_phase_debug_clone_copy_eq() {
        let p = ShutdownPhase::Draining;
        let dbg = format!("{p:?}");
        assert!(dbg.contains("Draining"), "{dbg}");
        let copied: ShutdownPhase = p;
        let cloned = p;
        assert_eq!(copied, cloned);
        assert_ne!(p, ShutdownPhase::Running);
    }

    #[test]
    fn shutdown_stats_debug_clone() {
        let s = ShutdownStats {
            drained: 5,
            force_closed: 1,
            duration: Duration::from_secs(3),
            drain_report: None,
        };
        let dbg = format!("{s:?}");
        assert!(dbg.contains("ShutdownStats"), "{dbg}");
        let cloned = s;
        assert_eq!(format!("{cloned:?}"), dbg);
    }

    // ------------------------------------------------------------------
    // Request-aware drain certificate (D2.1, br-...-eeexl1.2)
    // ------------------------------------------------------------------

    fn t(nanos: u64) -> Time {
        Time::from_nanos(nanos)
    }

    /// A clean drain from N in-flight requests down to zero reaches
    /// quiescence with nothing stranded and a converging certificate.
    #[test]
    fn drain_tracker_clean_drain_reaches_quiescence() {
        init_test("drain_tracker_clean_drain_reaches_quiescence");
        let mut tracker = GracefulDrainTracker::new(50, t(0));
        // Steady descent: 50 -> 0 in 10 even steps.
        for step in 1..=10 {
            let remaining = 50 - step * 5;
            tracker.observe(remaining);
        }
        assert_eq!(tracker.remaining(), 0);
        let report = tracker.finish(t(1_000_000), false);

        assert_eq!(report.requests_at_drain_start, 50);
        assert_eq!(report.requests_completed, 50);
        assert_eq!(report.requests_stranded, 0);
        assert!(report.reached_quiescence);
        assert!(!report.hard_deadline_hit);
        assert!(
            report.converging,
            "a monotone descent to zero must read as converging: {report:?}"
        );
        assert_eq!(report.drain_duration, Duration::from_millis(1));
        crate::test_complete!("drain_tracker_clean_drain_reaches_quiescence");
    }

    /// A drain that plateaus (no progress) is classified as stalled and
    /// strands the remaining requests when the hard deadline is hit.
    #[test]
    fn drain_tracker_stalled_drain_strands_requests() {
        init_test("drain_tracker_stalled_drain_strands_requests");
        let mut tracker = GracefulDrainTracker::new(8, t(0));
        // Stuck at 5 in-flight for many ticks: no progress.
        for _ in 0..40 {
            tracker.observe(5);
        }
        let report = tracker.finish(t(5_000_000), true);

        assert_eq!(report.requests_at_drain_start, 8);
        assert_eq!(report.requests_stranded, 5);
        assert_eq!(report.requests_completed, 3);
        assert!(!report.reached_quiescence);
        assert!(report.hard_deadline_hit);
        assert!(
            matches!(report.final_phase, DrainPhase::Stalled),
            "a long plateau must classify as stalled, got {}",
            report.final_phase
        );
        assert!(report.stall_detected, "stall must be detected: {report:?}");
        crate::test_complete!("drain_tracker_stalled_drain_strands_requests");
    }

    /// A partial drain that hits the hard deadline mid-descent strands only
    /// the still-in-flight requests and counts the rest as completed.
    #[test]
    fn drain_tracker_partial_drain_accounts_completed_and_stranded() {
        init_test("drain_tracker_partial_drain_accounts_completed_and_stranded");
        let mut tracker = GracefulDrainTracker::new(20, t(0));
        for remaining in [16, 12, 9, 7] {
            tracker.observe(remaining);
        }
        let report = tracker.finish(t(2_000_000), true);

        assert_eq!(report.requests_completed, 13);
        assert_eq!(report.requests_stranded, 7);
        assert_eq!(report.observations, 5); // initial + 4 observations
        assert!(report.hard_deadline_hit);
        assert!(!report.reached_quiescence);
        crate::test_complete!("drain_tracker_partial_drain_accounts_completed_and_stranded");
    }

    /// The report rendering is deterministic and golden-stable. The float
    /// fields are produced by the certificate from the fixed observation
    /// series, so the whole block is reproducible.
    #[test]
    fn drain_report_display_is_golden_stable() {
        init_test("drain_report_display_is_golden_stable");
        // A directly-constructed report keeps the golden independent of the
        // certificate's internal float evolution (which has its own tests);
        // this pins the operator-facing rendering contract.
        let report = GracefulDrainReport {
            requests_at_drain_start: 50,
            requests_completed: 50,
            requests_stranded: 0,
            requests_at_escalation: None,
            observations: 11,
            final_phase: DrainPhase::Quiescent,
            converging: true,
            confidence_bound: 0.987_654,
            estimated_remaining_steps: Some(0.0),
            stall_detected: false,
            reached_quiescence: true,
            hard_deadline_hit: false,
            drain_duration: Duration::from_millis(42),
        };
        let expected = "\
Graceful Drain Report
=====================
Requests at start:  50
Requests completed: 50
Requests stranded:  0
At escalation:      never
Observations:       11
Final drain phase:  quiescent
Converging:         true
Confidence bound:   0.987654
Est. remaining:     0.0 steps
Stall detected:     false
Reached quiescence: true
Hard deadline hit:  false
Drain duration:     42ms
";
        assert_eq!(report.to_string(), expected);
        crate::test_complete!("drain_report_display_is_golden_stable");
    }

    /// The estimated-remaining `None` branch renders as `N/A`.
    #[test]
    fn drain_report_display_handles_unknown_remaining() {
        init_test("drain_report_display_handles_unknown_remaining");
        let report = GracefulDrainReport {
            requests_at_drain_start: 3,
            requests_completed: 0,
            requests_stranded: 3,
            requests_at_escalation: Some(3),
            observations: 1,
            final_phase: DrainPhase::Warmup,
            converging: false,
            confidence_bound: 0.0,
            estimated_remaining_steps: None,
            stall_detected: false,
            reached_quiescence: false,
            hard_deadline_hit: true,
            drain_duration: Duration::ZERO,
        };
        let rendered = report.to_string();
        assert!(rendered.contains("Est. remaining:     N/A"), "{rendered}");
        assert!(
            rendered.contains("Final drain phase:  warmup"),
            "{rendered}"
        );
        assert!(rendered.contains("At escalation:      3"), "{rendered}");
        assert!(rendered.contains("Drain duration:     0ms"), "{rendered}");
        crate::test_complete!("drain_report_display_handles_unknown_remaining");
    }

    /// The supervisor records the in-flight count at the escalation
    /// transition; the report keeps the completed-vs-interrupted boundary
    /// (br-asupersync-server-stack-hardening-eeexl1.2, D2.4).
    #[test]
    fn supervisor_records_requests_at_escalation() {
        init_test("supervisor_records_requests_at_escalation");
        let mut supervisor =
            GracefulDrainSupervisor::new(5, t(0), Duration::from_secs(1), Duration::from_secs(10));

        // Within the soft budget: no escalation recorded.
        assert_eq!(supervisor.observe(5, t(500_000_000)), DrainStep::Continue);

        // Soft deadline elapses with 3 still in flight: escalation fires once
        // and captures the boundary.
        assert_eq!(supervisor.observe(3, t(1_500_000_000)), DrainStep::Escalate);
        assert_eq!(supervisor.observe(1, t(2_000_000_000)), DrainStep::Continue);
        assert_eq!(
            supervisor.observe(0, t(2_500_000_000)),
            DrainStep::Quiescent
        );

        let report = supervisor.finish(t(2_500_000_000), false);
        assert_eq!(report.requests_at_escalation, Some(3));
        assert_eq!(report.requests_completed, 5);
        assert!(report.reached_quiescence);
        crate::test_complete!("supervisor_records_requests_at_escalation");
    }

    /// A drain that reaches quiescence inside the soft budget never
    /// escalates, and the report says so.
    #[test]
    fn supervisor_reports_never_escalated_on_clean_drain() {
        init_test("supervisor_reports_never_escalated_on_clean_drain");
        let mut supervisor =
            GracefulDrainSupervisor::new(2, t(0), Duration::from_secs(1), Duration::from_secs(10));
        assert_eq!(supervisor.observe(1, t(200_000_000)), DrainStep::Continue);
        assert_eq!(supervisor.observe(0, t(400_000_000)), DrainStep::Quiescent);

        let report = supervisor.finish(t(400_000_000), false);
        assert_eq!(report.requests_at_escalation, None);
        assert!(report.to_string().contains("At escalation:      never"));
        crate::test_complete!("supervisor_reports_never_escalated_on_clean_drain");
    }

    /// If another driver path force-closes at the soft deadline before the
    /// supervisor's next tick, the report still preserves the last observed
    /// in-flight count as the escalation boundary.
    #[test]
    fn supervisor_records_external_escalation_before_quiescent_tick() {
        init_test("supervisor_records_external_escalation_before_quiescent_tick");
        let mut supervisor =
            GracefulDrainSupervisor::new(5, t(0), Duration::from_secs(1), Duration::from_secs(10));
        assert_eq!(supervisor.observe(5, t(500_000_000)), DrainStep::Continue);
        assert!(supervisor.record_external_escalation());
        assert_eq!(
            supervisor.observe(0, t(1_100_000_000)),
            DrainStep::Quiescent
        );

        let report = supervisor.finish(t(1_100_000_000), false);
        assert_eq!(report.requests_at_escalation, Some(5));
        assert!(report.reached_quiescence);
        crate::test_complete!("supervisor_records_external_escalation_before_quiescent_tick");
    }

    /// `finish` clamps a backward clock to a zero duration rather than
    /// underflowing.
    #[test]
    fn drain_tracker_backward_clock_is_zero_duration() {
        init_test("drain_tracker_backward_clock_is_zero_duration");
        let mut tracker = GracefulDrainTracker::new(2, t(1_000));
        tracker.observe(0);
        let report = tracker.finish(t(500), false);
        assert_eq!(report.drain_duration, Duration::ZERO);
        assert!(report.reached_quiescence);
        crate::test_complete!("drain_tracker_backward_clock_is_zero_duration");
    }

    // ------------------------------------------------------------------
    // Drain supervisor decision state machine (D2.2a)
    // ------------------------------------------------------------------

    /// A drain that empties before the soft budget reports Continue then
    /// Quiescent, never escalating.
    #[test]
    fn drain_supervisor_clean_drain_never_escalates() {
        init_test("drain_supervisor_clean_drain_never_escalates");
        let mut sup = GracefulDrainSupervisor::new(
            10,
            t(0),
            Duration::from_secs(30),
            Duration::from_secs(60),
        );
        assert_eq!(sup.observe(6, t(1_000_000_000)), DrainStep::Continue);
        assert_eq!(sup.observe(2, t(2_000_000_000)), DrainStep::Continue);
        assert_eq!(sup.observe(0, t(3_000_000_000)), DrainStep::Quiescent);
        assert!(!sup.escalated());
        let report = sup.finish(t(3_000_000_000), false);
        assert!(report.reached_quiescence);
        assert_eq!(report.requests_stranded, 0);
        crate::test_complete!("drain_supervisor_clean_drain_never_escalates");
    }

    /// Crossing the soft budget with requests still in flight escalates
    /// exactly once, then keeps reporting Continue until the hard deadline.
    #[test]
    fn drain_supervisor_escalates_once_at_soft_budget() {
        init_test("drain_supervisor_escalates_once_at_soft_budget");
        let mut sup =
            GracefulDrainSupervisor::new(5, t(0), Duration::from_secs(10), Duration::from_secs(30));
        // Before the soft deadline: keep waiting.
        assert_eq!(sup.observe(5, t(5_000_000_000)), DrainStep::Continue);
        // First observation at/after the soft deadline escalates.
        assert_eq!(sup.observe(4, t(10_000_000_000)), DrainStep::Escalate);
        assert!(sup.escalated());
        // Subsequent observations in the escalation window do not re-escalate.
        assert_eq!(sup.observe(3, t(12_000_000_000)), DrainStep::Continue);
        assert_eq!(sup.observe(2, t(20_000_000_000)), DrainStep::Continue);
        crate::test_complete!("drain_supervisor_escalates_once_at_soft_budget");
    }

    /// Reaching the hard deadline with requests still in flight reports
    /// HardDeadline; the report records the stranded requests.
    #[test]
    fn drain_supervisor_hard_deadline_strands_remaining() {
        init_test("drain_supervisor_hard_deadline_strands_remaining");
        let mut sup =
            GracefulDrainSupervisor::new(8, t(0), Duration::from_secs(10), Duration::from_secs(20));
        assert_eq!(sup.observe(6, t(10_000_000_000)), DrainStep::Escalate);
        assert_eq!(sup.observe(4, t(20_000_000_000)), DrainStep::HardDeadline);
        let report = sup.finish(t(20_000_000_000), true);
        assert!(report.hard_deadline_hit);
        assert_eq!(report.requests_stranded, 4);
        assert_eq!(report.requests_completed, 4);
        assert!(!report.reached_quiescence);
        crate::test_complete!("drain_supervisor_hard_deadline_strands_remaining");
    }

    /// Quiescence wins over a simultaneously-elapsed hard deadline: a tick
    /// that observes zero in-flight reports Quiescent even past the deadline.
    #[test]
    fn drain_supervisor_quiescence_beats_hard_deadline() {
        init_test("drain_supervisor_quiescence_beats_hard_deadline");
        let mut sup =
            GracefulDrainSupervisor::new(3, t(0), Duration::from_secs(10), Duration::from_secs(20));
        // Past the hard deadline, but the count hit zero this tick.
        assert_eq!(sup.observe(0, t(25_000_000_000)), DrainStep::Quiescent);
        let report = sup.finish(t(25_000_000_000), false);
        assert!(report.reached_quiescence);
        assert_eq!(report.requests_stranded, 0);
        crate::test_complete!("drain_supervisor_quiescence_beats_hard_deadline");
    }

    /// `hard_budget` is clamped up to at least `drain_budget` so the hard
    /// deadline can never precede the soft escalation point.
    #[test]
    fn drain_supervisor_clamps_hard_budget_below_soft() {
        init_test("drain_supervisor_clamps_hard_budget_below_soft");
        let sup = GracefulDrainSupervisor::new(
            1,
            t(0),
            Duration::from_secs(30),
            Duration::from_secs(5), // smaller than the soft budget
        );
        assert!(
            sup.hard_deadline() >= sup.drain_deadline(),
            "hard deadline must not precede the soft deadline"
        );
        crate::test_complete!("drain_supervisor_clamps_hard_budget_below_soft");
    }
}
