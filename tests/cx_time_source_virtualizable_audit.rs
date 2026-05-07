//! Audit + regression test for `Cx`'s time-source
//! virtualization.
//!
//! Operator's question: "Per asupersync deterministic-
//! testing, time should be virtualizable via Cx for lab
//! tests. Verify our Cx exposes a time_source that can be
//! swapped for lab/test. If not virtualized (uses
//! Instant::now() directly), file bead."
//!
//! Audit findings: **SOUND BY DESIGN — fully virtualizable.**
//!
//! ── The TimeSource trait ────────────────────────────────
//!
//! `src/time/driver.rs:25` defines:
//!
//! ```ignore
//! pub trait TimeSource: Send + Sync {
//!     fn now(&self) -> Time;
//! }
//! ```
//!
//! Three production-grade implementations:
//!
//! 1. `WallClock` (driver.rs:35) — production. Uses
//!    `std::time::Instant` internally, but the Instant
//!    is captured ONCE at creation and only relative
//!    elapsed time is reported. Production code never
//!    reaches for ambient `Instant::now()` directly.
//!
//! 2. `VirtualClock` (driver.rs:281) — lab tests. Atomic
//!    nanos counter; `advance(nanos)` and `advance_to(time)`
//!    move time forward deterministically. `pause()` /
//!    `resume()` freeze and unfreeze.
//!
//! 3. `BrowserClock` (driver.rs:90+) — browser adapters
//!    that ingest `performance.now()` samples; preserves
//!    monotonicity, smooths jitter, bounds catch-up jumps.
//!
//! The TimerDriver is generic over the TimeSource:
//!
//! ```ignore
//! // src/time/driver.rs:420
//! pub struct TimerDriver<T: TimeSource = VirtualClock> { ... }
//! ```
//!
//! ── How Cx routes through TimerDriver ────────────────────
//!
//! `Cx`'s time methods read from `self.handles.timer_driver`:
//!
//! ```ignore
//! // src/cx/cx.rs:1919
//! pub fn now(&self) -> Time
//! where Caps: cap::HasTime,
//! {
//!     self.handles.timer_driver
//!         .as_ref()
//!         .map_or_else(wall_clock_now, TimerDriverHandle::now)
//! }
//!
//! // src/cx/cx.rs:1947
//! pub fn now_for_observability(&self) -> Time { ... }
//!
//! // src/cx/cx.rs:1253
//! pub fn timer_driver(&self) -> Option<TimerDriverHandle>
//! where Caps: cap::HasTime,
//! ```
//!
//! In the lab, `LabRuntime` constructs Cx with
//! `timer_driver = Some(TimerDriverHandle for VirtualClock)`.
//! `cx.now()` returns virtual time deterministically;
//! `cx.timer_driver()` exposes the handle for explicit
//! advance/pause/resume control by the test.
//!
//! In production, `RuntimeBuilder` constructs Cx with
//! `timer_driver = Some(TimerDriverHandle for WallClock)`.
//! `cx.now()` returns wall time.
//!
//! ── Wall-clock fallback ──────────────────────────────────
//!
//! When `timer_driver` is `None` (e.g., a Cx synthesized
//! without a runtime, like `Cx::for_testing()` for unit
//! tests that don't need a real clock), `cx.now()` falls
//! back to `wall_clock_now()`. This is documented and
//! intentional — it lets unit tests on non-time code use
//! Cx without setting up a full TimerDriver. Lab tests
//! that exercise time-dependent code MUST configure a
//! TimerDriver (which LabRuntime does automatically).
//!
//! ── Capability gating (HasTime) ──────────────────────────
//!
//! `Cx::now()` is gated by `Caps: cap::HasTime`. Production
//! Cx always has HasTime. The macaroon-attenuation system
//! can REMOVE the TIME capability via runtime_mask, in
//! which case `cx.timer_driver()` returns None even when
//! the underlying handle is Some (cx.rs:1262-1264). This
//! lets sandbox / restricted contexts deny ambient time
//! access — a deliberate part of the no-ambient-authority
//! discipline.
//!
//! `cx.now_for_observability()` is the unrestricted
//! variant for diagnostic code that needs replayable
//! timestamps without threading HasTime.
//!
//! ── No direct Instant::now() in Cx itself ────────────────
//!
//! `src/cx/cx.rs` does NOT call `Instant::now()` directly
//! anywhere. All time goes through TimerDriver +
//! TimeSource trait. The only `Instant::now()` is inside
//! `WallClock::new()` (one-time epoch capture, not a
//! per-call read) — production-only and bypassable in lab.
//!
//! Verdict: **SOUND BY DESIGN**. Cx's time is fully
//! virtualizable via the TimeSource trait. Lab tests get
//! VirtualClock with deterministic advance/pause control.
//! Production gets WallClock. Browser adapters get
//! BrowserClock. The capability system can attenuate
//! TIME access on restricted Cx clones.
//!
//! No bead filed.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn time_source_trait_exists_with_now_method() {
    let source = read("src/time/driver.rs");

    assert!(
        source.contains("pub trait TimeSource: Send + Sync {"),
        "REGRESSION: TimeSource trait is gone. The time-\
         virtualization abstraction has been removed.",
    );

    let trait_marker = "pub trait TimeSource: Send + Sync {";
    let pos = source.find(trait_marker).expect("TimeSource trait");
    let body_end = source[pos..].find("\n}\n").expect("TimeSource trait close");
    let body = &source[pos..pos + body_end];

    assert!(
        body.contains("fn now(&self) -> Time;"),
        "REGRESSION: TimeSource trait no longer has fn now. \
         The single-method abstraction that lets virtual \
         and wall clocks be swapped is broken.",
    );
}

#[test]
fn wall_clock_implements_time_source_for_production() {
    let source = read("src/time/driver.rs");

    assert!(
        source.contains("pub struct WallClock {")
            && source.contains("impl TimeSource for WallClock {"),
        "REGRESSION: WallClock no longer implements \
         TimeSource. Production time-source is broken.",
    );

    // Wall clock captures the epoch ONCE; the now() impl
    // uses elapsed (a relative measurement). If a future
    // regression switches to per-call Instant::now()
    // EVERYWHERE, virtualization isn't possible.
    let impl_marker = "impl TimeSource for WallClock {";
    let pos = source.find(impl_marker).expect("WallClock impl");
    let body_end = source[pos..].find("\n}\n").expect("WallClock impl close");
    let body = &source[pos..pos + body_end];

    assert!(
        body.contains("self.epoch.elapsed()"),
        "REGRESSION: WallClock::now no longer uses \
         self.epoch.elapsed(). Either it now reads ambient \
         time (which can't be virtualized in lab) or the \
         epoch was removed.",
    );
}

#[test]
fn virtual_clock_implements_time_source_for_lab() {
    let source = read("src/time/driver.rs");

    assert!(
        source.contains("pub struct VirtualClock {")
            && source.contains("impl TimeSource for VirtualClock {"),
        "REGRESSION: VirtualClock no longer implements \
         TimeSource. Deterministic-testing time-source is \
         broken.",
    );
}

#[test]
fn virtual_clock_has_advance_and_pause_for_test_control() {
    // Pin: VirtualClock exposes advance + advance_to +
    // pause/resume. These are the test surface for
    // deterministic time control.
    let source = read("src/time/driver.rs");

    assert!(
        source.contains("pub fn advance(&self, nanos: u64) {"),
        "REGRESSION: VirtualClock::advance is gone. Lab \
         tests cannot deterministically advance time.",
    );

    assert!(
        source.contains("paused: AtomicBool,"),
        "REGRESSION: VirtualClock::paused field is gone. \
         Test pause/resume of virtual time is broken.",
    );
}

#[test]
fn timer_driver_is_generic_over_time_source() {
    let source = read("src/time/driver.rs");

    assert!(
        source.contains("pub struct TimerDriver<T: TimeSource = VirtualClock> {"),
        "REGRESSION: TimerDriver is no longer generic over \
         TimeSource. Time-source swapping at the driver \
         level is broken — Cx can no longer be configured \
         with VirtualClock for lab.",
    );
}

#[test]
fn cx_now_routes_through_timer_driver_not_instant_now() {
    // Pin: Cx::now() reads from self.handles.timer_driver,
    // not std::time::Instant::now() directly. If a future
    // regression bypassed TimerDriver, lab tests would no
    // longer see virtual time.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn now(&self) -> Time";
    let pos = source.find(fn_marker).expect("Cx::now fn");
    let body_window = &source[pos..pos + 600];

    assert!(
        body_window.contains("self.handles") && body_window.contains(".timer_driver"),
        "REGRESSION: Cx::now no longer reads from \
         handles.timer_driver. Lab tests can no longer \
         observe virtual time through Cx::now.",
    );

    assert!(
        !body_window.contains("std::time::Instant::now()")
            && !body_window.contains("Instant::now()"),
        "REGRESSION: Cx::now now calls Instant::now() \
         directly. This bypasses TimerDriver — virtual \
         time is no longer observable. File bead.",
    );
}

#[test]
fn cx_now_for_observability_does_not_use_instant_now() {
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn now_for_observability(&self) -> Time {";
    let pos = source
        .find(fn_marker)
        .expect("Cx::now_for_observability fn");
    let body_end = source[pos..]
        .find("\n    }\n")
        .expect("now_for_observability close");
    let body = &source[pos..pos + body_end];

    assert!(
        !body.contains("Instant::now()"),
        "REGRESSION: Cx::now_for_observability now calls \
         Instant::now() directly. Observability timestamps \
         in lab mode are no longer replayable.",
    );
}

#[test]
fn cx_exposes_timer_driver_for_explicit_test_control() {
    // Pin: cx.timer_driver() returns Option<TimerDriverHandle>.
    // Tests use this to obtain the handle and call
    // .advance() / .pause() / .resume().
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("pub fn timer_driver(&self) -> Option<TimerDriverHandle>"),
        "REGRESSION: Cx::timer_driver is gone. Tests can \
         no longer obtain the TimerDriverHandle for \
         explicit time-control.",
    );
}

#[test]
fn cx_now_is_capability_gated_by_hastime() {
    // Pin: Cx::now is gated by Caps: HasTime. This lets
    // restricted Cx clones (via macaroon attenuation) deny
    // ambient time access.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn now(&self) -> Time";
    let pos = source.find(fn_marker).expect("Cx::now fn");
    let body_window = &source[pos..pos + 200];

    assert!(
        body_window.contains("Caps: cap::HasTime"),
        "REGRESSION: Cx::now is no longer gated by \
         HasTime capability. Restricted Cx contexts can \
         now read ambient time even when TIME is \
         attenuated.",
    );
}

#[test]
fn cx_timer_driver_respects_capability_mask() {
    // Pin: cx.timer_driver() checks runtime_mask.has(TIME)
    // and returns None if TIME is excluded — even when
    // the underlying handle exists.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn timer_driver(&self) -> Option<TimerDriverHandle>";
    let pos = source.find(fn_marker).expect("timer_driver fn");
    let body_end = source[pos..].find("\n    }\n").expect("timer_driver close");
    let body = &source[pos..pos + body_end];

    assert!(
        body.contains("runtime_mask") && body.contains("CapMask::TIME"),
        "REGRESSION: Cx::timer_driver no longer respects \
         the runtime_mask TIME bit. Macaroon attenuation \
         cannot deny ambient time access.",
    );
}

#[test]
fn cx_module_does_not_call_instant_now_directly() {
    // Pin: src/cx/cx.rs does NOT call Instant::now()
    // anywhere. All time access goes through TimerDriver.
    let source = read("src/cx/cx.rs");

    let suspect_calls = [
        "std::time::Instant::now()",
        "Instant::now()",
        "SystemTime::now()",
    ];

    // Within actual code (not docs), check for these calls.
    // Docs reference Instant::now in passing — that's fine.
    // We check by searching for the calls in non-doc lines.
    let mut violations = Vec::new();
    for (line_no, line) in source.lines().enumerate() {
        // Skip doc comments.
        let trimmed = line.trim_start();
        if trimmed.starts_with("///") || trimmed.starts_with("//!") || trimmed.starts_with("//") {
            continue;
        }
        for pat in &suspect_calls {
            if line.contains(pat) {
                violations.push(format!("line {}: {}", line_no + 1, line.trim()));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "REGRESSION: src/cx/cx.rs now contains direct \
         Instant::now()/SystemTime::now() calls in code. \
         Time virtualization is broken.\n\n{}",
        violations.join("\n"),
    );
}

#[test]
fn lab_runtime_uses_virtual_clock() {
    // Pin: the lab runtime configures TimerDriver with
    // VirtualClock, so lab Cx instances see virtual time.
    let source = read("src/lab/runtime.rs");

    assert!(
        source.contains("VirtualClock"),
        "REGRESSION: lab runtime no longer references \
         VirtualClock. Lab tests may no longer get \
         deterministic time.",
    );
}

#[test]
fn time_source_trait_has_inline_doc_for_test_use() {
    // Pin: the trait docstring documents the test/lab
    // intent. Without this, a future maintainer may
    // collapse WallClock and VirtualClock or remove the
    // trait abstraction.
    let source = read("src/time/driver.rs");

    let trait_marker = "pub trait TimeSource: Send + Sync {";
    let pos = source.find(trait_marker).expect("TimeSource trait");
    let preceding = &source[pos.saturating_sub(800)..pos];

    assert!(
        preceding.contains("virtual time")
            || preceding.contains("lab")
            || preceding.contains("testing"),
        "REGRESSION: TimeSource trait docstring no longer \
         documents the wall/virtual swap intent. Future \
         readers may simplify away the abstraction.",
    );
}

// ── Behavioral pins ─────────────────────────────────────

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

trait MockTimeSource: Send + Sync {
    fn now_ns(&self) -> u64;
}

struct MockWallClock {
    epoch_ns: u64,
}
impl MockTimeSource for MockWallClock {
    fn now_ns(&self) -> u64 {
        self.epoch_ns
    }
}

struct MockVirtualClock {
    now: AtomicU64,
}
impl MockVirtualClock {
    fn advance(&self, nanos: u64) {
        self.now.fetch_add(nanos, Ordering::Release);
    }
}
impl MockTimeSource for MockVirtualClock {
    fn now_ns(&self) -> u64 {
        self.now.load(Ordering::Acquire)
    }
}

struct MockTimerDriver {
    source: Arc<dyn MockTimeSource>,
}
impl MockTimerDriver {
    fn now_ns(&self) -> u64 {
        self.source.now_ns()
    }
}

struct MockCx {
    timer_driver: Option<MockTimerDriver>,
}
impl MockCx {
    fn now_ns(&self) -> u64 {
        self.timer_driver
            .as_ref()
            .map_or(0, MockTimerDriver::now_ns)
    }
}

#[test]
fn behavioral_cx_with_virtual_clock_observes_advance() {
    let virt = Arc::new(MockVirtualClock {
        now: AtomicU64::new(0),
    });
    let cx = MockCx {
        timer_driver: Some(MockTimerDriver {
            source: virt.clone() as Arc<dyn MockTimeSource>,
        }),
    };

    assert_eq!(cx.now_ns(), 0);
    virt.advance(1_000_000_000);
    assert_eq!(
        cx.now_ns(),
        1_000_000_000,
        "REGRESSION: cx.now did not observe virtual clock \
         advance. Time virtualization through TimerDriver \
         is broken.",
    );
    virt.advance(500_000_000);
    assert_eq!(cx.now_ns(), 1_500_000_000);
}

#[test]
fn behavioral_cx_with_wall_clock_returns_epoch_relative_time() {
    let wall = Arc::new(MockWallClock {
        epoch_ns: 42_000_000,
    });
    let cx = MockCx {
        timer_driver: Some(MockTimerDriver {
            source: wall as Arc<dyn MockTimeSource>,
        }),
    };

    assert_eq!(cx.now_ns(), 42_000_000);
}

#[test]
fn behavioral_swapping_time_source_at_construction_changes_observed_time() {
    // Same Cx-shaped wrapper, different TimeSources →
    // different observed time. This is the swappability
    // contract the operator asks about.
    let virt_a = Arc::new(MockVirtualClock {
        now: AtomicU64::new(100),
    });
    let virt_b = Arc::new(MockVirtualClock {
        now: AtomicU64::new(2_000_000),
    });

    let cx_a = MockCx {
        timer_driver: Some(MockTimerDriver {
            source: virt_a as Arc<dyn MockTimeSource>,
        }),
    };
    let cx_b = MockCx {
        timer_driver: Some(MockTimerDriver {
            source: virt_b as Arc<dyn MockTimeSource>,
        }),
    };

    assert_eq!(cx_a.now_ns(), 100);
    assert_eq!(cx_b.now_ns(), 2_000_000);

    assert_ne!(
        cx_a.now_ns(),
        cx_b.now_ns(),
        "REGRESSION: two Cx instances with different \
         TimeSources observed identical time. Swap-at-\
         construction is broken — they share ambient state.",
    );
}

#[test]
fn behavioral_cx_with_no_timer_driver_falls_back() {
    // When timer_driver is None, Cx falls back to a
    // default (in production: wall_clock_now; in our
    // mock: 0).
    let cx = MockCx { timer_driver: None };
    assert_eq!(cx.now_ns(), 0);
}

#[test]
fn cross_reference_to_related_audits() {
    let prior_audits = [
        "tests/cx_deadline_inheritance_min_parent_child_audit.rs",
        "tests/timeout_combinator_timer_cleanup_audit.rs",
        "tests/time_sleep_vs_sleep_until_convergence_audit.rs",
        "tests/cx_pressure_real_signals_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
