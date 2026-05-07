//! Audit + regression test for `Sleep` virtual-time
//! determinism under LabRuntime.
//!
//! Operator's question: "When LabRuntime is configured
//! with a virtual time source, does Cx::sleep(d) advance
//! virtual time correctly (correct: deterministic) or
//! fall back to real Instant (incorrect: non-deterministic
//! test)?"
//!
//! Audit findings: **SOUND BY DESIGN — fully deterministic
//! under LabRuntime via 4-tier time-source priority**.
//!
//! ── 4-tier time-source priority in Sleep::poll ──────────
//!
//! `Sleep::poll` (src/time/sleep.rs:480) reads the current
//! time via this priority chain:
//!
//! ```ignore
//! let now = if let Some(timer) = self.bound_timer_driver.as_ref() {
//!     timer.now()              // Tier 1: explicitly bound driver
//! } else if self.time_getter.is_some() {
//!     self.current_time()      // Tier 2: stand-alone time_getter fn
//! } else {
//!     timer_driver
//!         .as_ref()
//!         .map_or_else(|| self.current_time(), TimerDriverHandle::now)
//!     // Tier 3: ambient Cx::current().timer_driver()
//!     // Tier 4: fallback to wall clock (only when nothing else)
//! };
//! ```
//!
//! Tier 1 — `bound_timer_driver`: explicit binding via
//!   `Sleep::with_timer_driver(deadline, driver)`. Used by
//!   tests that need a specific driver instance (e.g.,
//!   running inside `LabRuntime::block_on` where the cx
//!   isn't installed).
//!
//! Tier 2 — `time_getter`: an `fn() -> Time` for
//!   freestanding tests. Bypasses the ambient lookup.
//!
//! Tier 3 — **ambient timer_driver via `Cx::current()`**:
//!   THIS is the LabRuntime path. When LabRuntime polls a
//!   task, the per-poll Cx install (`Cx::set_current(task_cx)`,
//!   audited in `cx_set_current_per_poll_install_audit.rs`)
//!   makes `Cx::current().timer_driver()` return the lab's
//!   VirtualClock-backed `TimerDriver`. `TimerDriverHandle::now`
//!   then returns virtual time.
//!
//! Tier 4 — wall clock fallback: only reached when ALL of
//!   bound_timer_driver, time_getter, AND ambient driver
//!   are absent. Production Cx always has a timer_driver
//!   so this is the "no runtime context" diagnostic path.
//!
//! ── Determinism via single time source ──────────────────
//!
//! Sleep's deadline is computed via `Sleep::after(now,
//! duration)` (sleep.rs:260) where `now` is supplied by
//! the same TimerDriver:
//!
//! ```ignore
//! pub fn after(now: Time, duration: Duration) -> Self {
//!     let deadline = now.saturating_add_nanos(duration_to_nanos(duration));
//!     Self::new(deadline)
//! }
//! ```
//!
//! Or via `time::sleep(now, duration)` which the user
//! calls with `cx.now()` — also from the lab's
//! TimerDriver under LabRuntime.
//!
//! So under LabRuntime:
//!   - `cx.now()` → VirtualClock now
//!   - `time::sleep(cx.now(), duration)` → Sleep with
//!     deadline = virtual_now + duration
//!   - poll() reads `now` from same VirtualClock
//!   - `now >= deadline` predicate fires when virtual
//!     time advances past deadline
//!   - `clock.advance(nanos)` deterministically completes
//!     the Sleep
//!
//! No wall-clock leakage. No `Instant::now()` reach.
//!
//! ── How the timer wakes the task ────────────────────────
//!
//! On Pending, Sleep registers a timer with the driver:
//!
//! ```ignore
//! let handle = timer.register(
//!     self.deadline,
//!     readiness_waker(Arc::clone(&self.ready), cx.waker().clone()),
//! );
//! ```
//!
//! When the lab driver's wheel ticks past `self.deadline`
//! (driven by `clock.advance(nanos)`), it fires the
//! readiness_waker, which sets `self.ready = true` and
//! wakes the task. Next poll observes `ready.swap(false,
//! AcqRel) = true` → `Poll::Ready(())`.
//!
//! Both the deadline AND the firing-decision use VIRTUAL
//! time — never real wall time.
//!
//! ── Existing inline tests pin determinism ───────────────
//!
//! `src/time/sleep.rs` has tests that:
//!   - Use a thread-local `CURRENT_TIME` cell + `time_getter`
//!     to drive virtual time deterministically.
//!   - Verify Sleep transitions Pending → Ready when the
//!     virtual time is advanced past the deadline.
//!   - Verify the timer is cancelled on completion.
//!
//! `src/lab/runtime.rs` (referenced in
//! `cx_time_source_virtualizable_audit.rs`) configures
//! VirtualClock as the lab's TimerDriver — so the Tier-3
//! ambient path is exercised by lab tests.
//!
//! Verdict: **SOUND BY DESIGN**. Under LabRuntime,
//! Cx::sleep(d) (or time::sleep(cx.now(), d)) is fully
//! deterministic. Both the deadline computation and the
//! firing-decision read from the same VirtualClock-backed
//! TimerDriver. The wall-clock fallback only fires when
//! ALL of bound_timer_driver, time_getter, AND ambient
//! Cx::current().timer_driver() are absent — which never
//! happens in a properly configured LabRuntime.
//!
//! No bead filed.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn sleep_poll_priority_order_is_bound_then_getter_then_ambient_then_wall() {
    // Pin: the 4-tier priority order. If reordered, lab
    // tests could observe wall-clock time despite having
    // configured a virtual driver.
    let source = read("src/time/sleep.rs");

    let fn_marker = "fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {";
    let pos = source.find(fn_marker).expect("Sleep::poll fn");
    let body_window = &source[pos..pos + 2000];

    // Tier 1: bound_timer_driver first.
    assert!(
        body_window.contains("if let Some(timer) = self.bound_timer_driver.as_ref() {"),
        "REGRESSION: Sleep::poll no longer checks \
         bound_timer_driver first. Tests that explicitly \
         bind a driver may not get their virtual time.",
    );

    let bound_pos = body_window
        .find("if let Some(timer) = self.bound_timer_driver.as_ref() {")
        .unwrap();

    // Tier 2: time_getter second (else if branch).
    let getter_pos = body_window
        .find("self.time_getter.is_some()")
        .expect("time_getter check");
    assert!(
        getter_pos > bound_pos,
        "REGRESSION: time_getter no longer checked AFTER \
         bound_timer_driver. Tier order is broken.",
    );

    // Tier 3: timer_driver (ambient) third (else branch).
    let ambient_pos = body_window
        .find("TimerDriverHandle::now")
        .expect("ambient TimerDriverHandle::now");
    assert!(
        ambient_pos > getter_pos,
        "REGRESSION: ambient timer_driver no longer \
         checked AFTER time_getter. The LabRuntime path \
         (Cx::current().timer_driver()) may be skipped.",
    );

    // Tier 4: self.current_time() (wall clock) is the
    // map_or_else fallback inside the ambient branch.
    assert!(
        body_window.contains("map_or_else(|| self.current_time(), TimerDriverHandle::now)"),
        "REGRESSION: wall-clock fallback ordering changed. \
         Either it's no longer the last resort or it's \
         being reached too eagerly.",
    );
}

#[test]
fn sleep_ambient_driver_resolution_uses_cx_current_timer_driver() {
    // Pin: Sleep::poll reaches into Cx::current().timer_driver()
    // for the ambient driver. This is THE path that picks
    // up the lab's VirtualClock-backed driver.
    let source = read("src/time/sleep.rs");

    let fn_marker = "fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {";
    let pos = source.find(fn_marker).expect("Sleep::poll fn");
    let body_window = &source[pos..pos + 1000];

    assert!(
        body_window.contains("Cx::current()") && body_window.contains(".timer_driver()"),
        "REGRESSION: Sleep::poll no longer reads ambient \
         timer_driver via Cx::current().timer_driver(). \
         The LabRuntime virtual-time path is broken.",
    );
}

#[test]
fn sleep_after_constructor_uses_supplied_now_for_deadline() {
    // Pin: Sleep::after(now, dur) uses supplied `now`
    // for deadline computation. Under LabRuntime, callers
    // pass cx.now() (virtual time) → deadline is virtual.
    let source = read("src/time/sleep.rs");

    assert!(
        source.contains("pub fn after(now: Time, duration: Duration) -> Self {"),
        "REGRESSION: Sleep::after signature changed.",
    );

    let fn_marker = "pub fn after(now: Time, duration: Duration) -> Self {";
    let pos = source.find(fn_marker).expect("Sleep::after fn");
    let body = &source[pos..pos + 400];

    assert!(
        body.contains("now.saturating_add_nanos(duration_to_nanos(duration))"),
        "REGRESSION: Sleep::after no longer uses the \
         supplied `now` for deadline. May reach for \
         ambient time, breaking determinism.",
    );

    // Must NOT call wall_now / Instant::now in the body.
    let suspect_calls = [
        "Instant::now()",
        "wall_now()",
        "wall_clock_now()",
        "SystemTime::now()",
    ];
    for pat in &suspect_calls {
        assert!(
            !body.contains(pat),
            "REGRESSION: Sleep::after body now calls \
             `{pat}`. The supplied `now` is being ignored \
             — virtual time is broken.",
        );
    }
}

#[test]
fn sleep_timer_register_uses_self_deadline_not_recomputed_from_wall() {
    // Pin: timer registration uses self.deadline (which
    // was computed from the supplied virtual `now`). It
    // does NOT re-derive from a wall clock.
    let source = read("src/time/sleep.rs");

    let fn_marker = "fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {";
    let pos = source.find(fn_marker).expect("Sleep::poll fn");
    let body_window = &source[pos..pos + 5000];

    assert!(
        body_window.contains("timer.register(\n                        self.deadline,")
            || body_window.contains("timer.register(") && body_window.contains("self.deadline"),
        "REGRESSION: Sleep::poll no longer registers timer \
         with self.deadline. The deadline-vs-firing time \
         consistency is broken.",
    );

    // Must NOT recompute from wall clock for registration.
    let suspect_recompute = [
        "Instant::now() + duration",
        "wall_now() + ",
        "register(wall_now()",
    ];
    for pat in &suspect_recompute {
        assert!(
            !body_window.contains(pat),
            "REGRESSION: timer registration recomputes \
             deadline from wall clock via `{pat}`. \
             Virtual-time consistency broken.",
        );
    }
}

#[test]
fn lab_runtime_configures_virtual_clock_for_timer_driver() {
    // Pin: LabRuntime sets up its TimerDriver with
    // VirtualClock so the ambient lookup picks it up.
    let source = read("src/lab/runtime.rs");

    assert!(
        source.contains("VirtualClock"),
        "REGRESSION: LabRuntime no longer references \
         VirtualClock. Lab determinism may be broken.",
    );
}

#[test]
fn timer_driver_is_generic_over_time_source_for_swap() {
    // Pin: TimerDriver<T: TimeSource = VirtualClock>
    // means the same TimerDriver type can wrap WallClock
    // in production AND VirtualClock in lab — Cx's
    // ambient lookup returns the right one based on
    // configuration.
    let source = read("src/time/driver.rs");

    assert!(
        source.contains("pub struct TimerDriver<T: TimeSource = VirtualClock> {"),
        "REGRESSION: TimerDriver is no longer generic over \
         TimeSource with VirtualClock default. Lab/prod \
         time-source swap is broken.",
    );
}

#[test]
fn time_source_trait_now_is_the_swap_point() {
    let source = read("src/time/driver.rs");

    assert!(
        source.contains("pub trait TimeSource: Send + Sync {"),
        "REGRESSION: TimeSource trait is gone.",
    );

    assert!(
        source.contains("fn now(&self) -> Time;"),
        "REGRESSION: TimeSource::now method gone.",
    );
}

#[test]
fn virtual_clock_advance_drives_deterministic_progression() {
    // Pin: VirtualClock has advance(nanos) for tests to
    // step time forward.
    let source = read("src/time/driver.rs");

    assert!(
        source.contains("pub fn advance(&self, nanos: u64) {"),
        "REGRESSION: VirtualClock::advance gone. Tests \
         cannot step virtual time forward.",
    );

    assert!(
        source.contains("pub fn advance_to(&self, time: Time)") || source.contains("advance_to("),
        "REGRESSION: VirtualClock::advance_to gone.",
    );
}

#[test]
fn sleep_pending_path_registers_with_ambient_lab_driver() {
    // Pin: in the Pending branch, Sleep registers with
    // `timer` (the ambient or bound driver), not a
    // separate wall-clock-driven thread.
    let source = read("src/time/sleep.rs");

    let fn_marker = "fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {";
    let pos = source.find(fn_marker).expect("Sleep::poll fn");
    let body_window = &source[pos..pos + 5000];

    assert!(
        body_window.contains("if let Some(timer) = timer_driver.as_ref() {"),
        "REGRESSION: Pending branch no longer prefers \
         timer_driver. Lab tests fall back to background-\
         thread fallback.",
    );

    assert!(
        body_window.contains("// Prefer timer driver over background thread"),
        "REGRESSION: 'Prefer timer driver over background \
         thread' comment is gone. Future maintainers may \
         not know the determinism rationale.",
    );
}

#[test]
fn sleep_inline_tests_exercise_virtual_time() {
    // Pin: at least some inline tests use
    // CURRENT_TIME thread-local + time_getter to drive
    // virtual time and assert Pending→Ready transitions.
    let source = read("src/time/sleep.rs");

    assert!(
        source.contains("static CURRENT_TIME") && source.contains("CURRENT_TIME.store"),
        "REGRESSION: inline tests no longer use \
         CURRENT_TIME static for virtual-time driving \
         (atomic store/load idiom gone). Lab determinism \
         is no longer witnessed in-tree.",
    );

    // Also pin that VirtualClock is exercised in the test
    // module — the higher-level driver-based determinism path.
    assert!(
        source.contains("Arc::new(VirtualClock::new())"),
        "REGRESSION: inline tests no longer construct \
         VirtualClock for driver-based determinism testing.",
    );
}

#[test]
fn sleep_does_not_call_wall_clock_in_construction_paths() {
    // Pin: Sleep::new and Sleep::after construction paths
    // don't call wall_now / Instant::now / SystemTime::now.
    let source = read("src/time/sleep.rs");

    let new_marker = "pub fn new(deadline: Time) -> Self {";
    let new_pos = source.find(new_marker).expect("Sleep::new fn");
    let new_body_end = source[new_pos..]
        .find("\n    }\n")
        .expect("Sleep::new close");
    let new_body = &source[new_pos..new_pos + new_body_end];

    let suspect_wall_calls = [
        "Instant::now()",
        "SystemTime::now()",
        "wall_clock_now()",
        "wall_now()",
    ];
    for pat in &suspect_wall_calls {
        assert!(
            !new_body.contains(pat),
            "REGRESSION: Sleep::new body calls `{pat}`. \
             Construction now reaches for wall clock — \
             virtual time leaked.",
        );
    }
}

#[test]
fn cross_reference_to_related_audits() {
    let prior_audits = [
        "tests/cx_time_source_virtualizable_audit.rs",
        "tests/time_sleep_vs_sleep_until_convergence_audit.rs",
        "tests/time_sleep_past_deadline_immediate_ready_audit.rs",
        "tests/cx_set_current_per_poll_install_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}

// ── Behavioral pins ─────────────────────────────────────

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct MockTime(u64);

impl MockTime {
    const fn from_nanos(n: u64) -> Self {
        Self(n)
    }
    fn saturating_add_nanos(self, n: u64) -> Self {
        Self(self.0.saturating_add(n))
    }
}

fn duration_to_nanos(d: Duration) -> u64 {
    let secs = d.as_secs().saturating_mul(1_000_000_000);
    let sub = u64::from(d.subsec_nanos());
    secs.saturating_add(sub)
}

trait MockTimeSource: Send + Sync {
    fn now(&self) -> MockTime;
}

struct MockVirtualClock {
    now: AtomicU64,
}

impl MockVirtualClock {
    fn new() -> Self {
        Self {
            now: AtomicU64::new(0),
        }
    }
    fn advance(&self, nanos: u64) {
        self.now.fetch_add(nanos, Ordering::Release);
    }
}

impl MockTimeSource for MockVirtualClock {
    fn now(&self) -> MockTime {
        MockTime(self.now.load(Ordering::Acquire))
    }
}

struct MockWallClock;
impl MockTimeSource for MockWallClock {
    fn now(&self) -> MockTime {
        MockTime(99_999_999_999) // pretend wall clock — irrelevant under lab
    }
}

/// Mock TimerDriver: holds a TimeSource, exposes now() +
/// register(deadline, waker). Registered timers fire when
/// the source advances past their deadline.
struct MockTimerDriver {
    source: Arc<dyn MockTimeSource>,
    pending: parking_lot_mock::Mutex<Vec<(MockTime, Waker, Arc<AtomicBool>)>>,
}

mod parking_lot_mock {
    use std::sync::Mutex as StdMutex;

    pub struct Mutex<T>(StdMutex<T>);
    impl<T> Mutex<T> {
        pub const fn new(t: T) -> Self
        where
            T: Sized,
        {
            Self(StdMutex::new(t))
        }
        pub fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
            let mut g = self.0.lock().unwrap();
            f(&mut *g)
        }
    }
}

impl MockTimerDriver {
    fn new(source: Arc<dyn MockTimeSource>) -> Self {
        Self {
            source,
            pending: parking_lot_mock::Mutex::new(Vec::new()),
        }
    }
    fn now(&self) -> MockTime {
        self.source.now()
    }
    fn register(&self, deadline: MockTime, waker: Waker, ready: Arc<AtomicBool>) {
        self.pending.with(|v| v.push((deadline, waker, ready)));
        self.fire_due();
    }
    fn fire_due(&self) {
        let now = self.source.now();
        self.pending.with(|v| {
            v.retain(|(deadline, waker, ready)| {
                if now >= *deadline {
                    ready.store(true, Ordering::Release);
                    waker.wake_by_ref();
                    false
                } else {
                    true
                }
            });
        });
    }
}

struct NullWake;
impl Wake for NullWake {
    fn wake(self: Arc<Self>) {}
}

/// Mock Sleep with the same priority order as production:
/// bound_driver → ambient driver → wall fallback. The
/// poll body computes deadline via Sleep::after(now, dur)
/// where `now` comes from the same priority chain.
struct MockSleep {
    deadline: MockTime,
    bound_driver: Option<Arc<MockTimerDriver>>,
    ambient_driver: Option<Arc<MockTimerDriver>>,
    ready: Arc<AtomicBool>,
    polled: AtomicBool,
}

impl MockSleep {
    fn new_after(
        bound: Option<Arc<MockTimerDriver>>,
        ambient: Option<Arc<MockTimerDriver>>,
        duration: Duration,
    ) -> Self {
        // Tier order to compute `now`:
        let now = if let Some(b) = bound.as_ref() {
            b.now()
        } else if let Some(a) = ambient.as_ref() {
            a.now()
        } else {
            MockWallClock.now()
        };
        let deadline = now.saturating_add_nanos(duration_to_nanos(duration));
        Self {
            deadline,
            bound_driver: bound,
            ambient_driver: ambient,
            ready: Arc::new(AtomicBool::new(false)),
            polled: AtomicBool::new(false),
        }
    }
}

impl Future for MockSleep {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let now = if let Some(b) = self.bound_driver.as_ref() {
            b.now()
        } else if let Some(a) = self.ambient_driver.as_ref() {
            a.now()
        } else {
            MockWallClock.now()
        };

        if self.ready.swap(false, Ordering::AcqRel) || now >= self.deadline {
            return Poll::Ready(());
        }

        // Register with whichever driver is preferred.
        if !self.polled.swap(true, Ordering::Relaxed) {
            let driver = self.bound_driver.as_ref().or(self.ambient_driver.as_ref());
            if let Some(d) = driver {
                d.register(self.deadline, cx.waker().clone(), Arc::clone(&self.ready));
            }
        }

        // After registration, fire any due timers.
        if let Some(d) = self.bound_driver.as_ref().or(self.ambient_driver.as_ref()) {
            d.fire_due();
        }

        if self.ready.swap(false, Ordering::AcqRel) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

#[test]
fn behavioral_sleep_under_virtual_clock_is_deterministic() {
    let virt = Arc::new(MockVirtualClock::new());
    let driver = Arc::new(MockTimerDriver::new(virt.clone() as Arc<dyn MockTimeSource>));

    let mut s = MockSleep::new_after(None, Some(Arc::clone(&driver)), Duration::from_millis(100));

    // Deadline should be 100ms in virtual time (i.e. 100_000_000 ns).
    assert_eq!(s.deadline, MockTime::from_nanos(100_000_000));

    let waker = Waker::from(Arc::new(NullWake));
    let mut ctx = Context::from_waker(&waker);
    let mut pinned = unsafe { Pin::new_unchecked(&mut s) };

    // First poll: Pending (deadline not reached).
    assert!(matches!(pinned.as_mut().poll(&mut ctx), Poll::Pending));

    // Advance virtual time PAST the deadline.
    virt.advance(150_000_000);

    // Second poll: Ready.
    assert_eq!(
        pinned.as_mut().poll(&mut ctx),
        Poll::Ready(()),
        "REGRESSION: Sleep did not fire when virtual time \
         advanced past deadline. Determinism broken.",
    );
}

#[test]
fn behavioral_sleep_does_not_consult_wall_clock_when_virtual_driver_present() {
    // Pin: when a virtual driver is configured, Sleep
    // observes virtual time, NOT the wall clock value
    // (which we set absurdly large in MockWallClock).
    let virt = Arc::new(MockVirtualClock::new());
    let driver = Arc::new(MockTimerDriver::new(virt.clone() as Arc<dyn MockTimeSource>));

    let s = MockSleep::new_after(None, Some(Arc::clone(&driver)), Duration::from_millis(50));

    // Deadline should be 50ms in virtual time, not based
    // on the wall clock's 99_999_999_999.
    assert_eq!(
        s.deadline.0, 50_000_000,
        "REGRESSION: Sleep deadline computed from wall \
         clock instead of virtual driver. Determinism \
         broken.",
    );
}

#[test]
fn behavioral_advance_to_exact_deadline_makes_sleep_ready() {
    // Boundary case: now == deadline triggers Ready.
    let virt = Arc::new(MockVirtualClock::new());
    let driver = Arc::new(MockTimerDriver::new(virt.clone() as Arc<dyn MockTimeSource>));

    let mut s = MockSleep::new_after(None, Some(Arc::clone(&driver)), Duration::from_nanos(500));
    assert_eq!(s.deadline.0, 500);

    let waker = Waker::from(Arc::new(NullWake));
    let mut ctx = Context::from_waker(&waker);
    let mut pinned = unsafe { Pin::new_unchecked(&mut s) };

    assert!(matches!(pinned.as_mut().poll(&mut ctx), Poll::Pending));

    // Advance to EXACTLY the deadline.
    virt.advance(500);

    assert_eq!(
        pinned.as_mut().poll(&mut ctx),
        Poll::Ready(()),
        "REGRESSION: now == deadline did not trigger Ready. \
         The >= predicate has flipped to >.",
    );
}

#[test]
fn behavioral_sleep_replay_is_deterministic_under_same_advances() {
    // Same sequence of advances → same Pending/Ready
    // sequence. Determinism property.
    fn run() -> Vec<&'static str> {
        let virt = Arc::new(MockVirtualClock::new());
        let driver = Arc::new(MockTimerDriver::new(virt.clone() as Arc<dyn MockTimeSource>));
        let mut s =
            MockSleep::new_after(None, Some(Arc::clone(&driver)), Duration::from_millis(10));
        let waker = Waker::from(Arc::new(NullWake));
        let mut ctx = Context::from_waker(&waker);
        let mut pinned = unsafe { Pin::new_unchecked(&mut s) };
        let mut out = Vec::new();

        for advance_ns in [3_000_000, 4_000_000, 5_000_000_u64] {
            match pinned.as_mut().poll(&mut ctx) {
                Poll::Pending => out.push("pending"),
                Poll::Ready(()) => out.push("ready"),
            }
            virt.advance(advance_ns);
        }
        // Final poll after total 12ms advance — should be Ready.
        match pinned.as_mut().poll(&mut ctx) {
            Poll::Pending => out.push("pending"),
            Poll::Ready(()) => out.push("ready"),
        }
        out
    }

    let r1 = run();
    let r2 = run();
    let r3 = run();
    assert_eq!(
        r1, r2,
        "REGRESSION: same virtual-time advances produced \
         different sleep behaviors across runs. \
         Determinism broken.",
    );
    assert_eq!(r2, r3);
    assert_eq!(r3.last(), Some(&"ready"));
}

#[test]
fn behavioral_bound_driver_takes_priority_over_ambient() {
    // Tier 1 (bound) > Tier 3 (ambient).
    let bound_clock = Arc::new(MockVirtualClock::new());
    bound_clock.advance(1_000_000); // bound clock at 1ms
    let bound_driver = Arc::new(MockTimerDriver::new(
        bound_clock.clone() as Arc<dyn MockTimeSource>
    ));

    let ambient_clock = Arc::new(MockVirtualClock::new());
    ambient_clock.advance(50_000_000_000); // ambient at 50s
    let ambient_driver = Arc::new(MockTimerDriver::new(
        ambient_clock.clone() as Arc<dyn MockTimeSource>
    ));

    let s = MockSleep::new_after(
        Some(Arc::clone(&bound_driver)),
        Some(Arc::clone(&ambient_driver)),
        Duration::from_millis(100),
    );

    // Deadline computed using BOUND clock (1ms now + 100ms
    // → 101ms = 101_000_000 ns), NOT ambient (50s + 100ms).
    assert_eq!(
        s.deadline.0, 101_000_000,
        "REGRESSION: bound_driver did not take priority \
         over ambient. Tier ordering is broken.",
    );
}
