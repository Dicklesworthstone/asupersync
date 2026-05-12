//! Audit + regression test for `src/time/sleep.rs` and
//! `src/time/wheel.rs` Sleep / TimerWheel resolution behavior
//! on sub-millisecond deadlines.
//!
//! Operator's question: "Sleep with very short deadline (<1ms):
//! does it use a high-precision timer (correct) or get rounded
//! up to next millisecond tick (could miss deadlines)?"
//!
//! Audit findings (TWO-LAYER ARCHITECTURE):
//!
//!   The asupersync timing system has TWO layers with different
//!   resolution properties:
//!
//!   1. **`Sleep` struct (sleep.rs)** stores deadlines at
//!      NANOSECOND precision. `Sleep::after(now, duration)`
//!      computes `deadline = now + duration_to_nanos(duration)`
//!      via `Time::saturating_add_nanos`, which preserves the
//!      full nanosecond resolution of the input `Duration`.
//!      `Sleep::poll_with_time(now)` returns `Poll::Ready(())`
//!      whenever `now >= self.deadline` — an EXACT comparison
//!      with no rounding. So a `Sleep::after(now, 500us)`
//!      polled with a `now` that is 500us past creation
//!      returns Ready immediately on that poll.
//!
//!   2. **TimerWheel (wheel.rs)** has 1ms LEVEL-0 RESOLUTION
//!      (`LEVEL0_RESOLUTION_NS: u64 = 1_000_000`, wheel.rs:45).
//!      When a worker parks waiting for the next timer, it
//!      wakes at the wheel's next 1ms tick. So a Sleep with a
//!      sub-millisecond deadline that REQUIRES parking
//!      (because the worker had no other work) may over-sleep
//!      by up to ~1ms in the worst case.
//!
//!   This matches tokio's design (`tokio::time::sleep` also
//!   uses a 1ms wheel by default) and standard industry
//!   practice for async runtime timer wheels. Sub-millisecond
//!   precision in async wake-up requires either:
//!     a. Polling with a tighter `now` source (the user's
//!        time getter or `bound_timer_driver` can advance at
//!        any rate — Sleep itself doesn't round).
//!     b. Busy-spinning until the deadline (the user's choice
//!        — asupersync doesn't enforce 1ms-or-bust).
//!     c. A specialized HRES timer primitive (would be a
//!        separate type, NOT Sleep).
//!
//!   The in-crate test `conformance_sleep_tolerance_within_
//!   wheel_granularity` (wheel.rs:2270+) explicitly documents
//!   this contract: "Level 0 resolution is 1ms, so tolerance
//!   should be within that bound".
//!
//! Verdict: **SOUND with documented 1ms wheel granularity**.
//! Sleep itself is sub-millisecond capable (nanosecond storage
//! and exact comparison). The timer wheel — needed for sleep-
//! and-wake when no other work is available — rounds park-
//! wake-ups to 1ms ticks. This is a documented design choice,
//! not a defect.
//!
//! Tasks with sub-millisecond deadline requirements should
//! use:
//!   - Frequent polling (no parking) with their own time
//!     source via `Sleep::with_time_getter`,
//!   - Or busy-wait spinning until deadline,
//!   - Or a custom platform-specific HRES timer primitive
//!     (asupersync doesn't ship one — that's a future
//!     opportunity per `br-asupersync-hres-timer`).
//!
//! A regression that:
//!   - rounded `Sleep::after`'s deadline to the nearest 1ms
//!     (would lose nanosecond precision at the storage level
//!     — sub-ms sleeps would be impossible even with a fast
//!     time getter),
//!   - changed `poll_with_time(now)` to compare `now / 1ms_tick`
//!     with `deadline / 1ms_tick` (would round both sides to
//!     1ms ticks, eliminating the sub-ms fast path),
//!   - increased `LEVEL0_RESOLUTION_NS` to 10ms (would multiply
//!     the worst-case over-sleep by 10x),
//!   - removed the existing tolerance test (would let a
//!     regression in resolution slip through),
//!     would all be caught here.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn timer_wheel_level0_resolution_is_one_millisecond() {
    // Pin: the canonical level-0 resolution constant is 1ms.
    // A regression to 10ms would 10x the worst-case over-
    // sleep; a regression below 1ms would over-resolution
    // the wheel (more slots, more memory, marginal benefit
    // for typical workloads).
    let source = read("src/time/wheel.rs");

    assert!(
        source.contains("const LEVEL0_RESOLUTION_NS: u64 = 1_000_000; // 1ms"),
        "REGRESSION: LEVEL0_RESOLUTION_NS is no longer \
         1_000_000 (1ms). The 1ms granularity is the \
         documented tolerance for Sleep park-wake-ups. If \
         the value genuinely needs to change, update the \
         conformance_sleep_tolerance_within_wheel_granularity \
         test in wheel.rs AND this audit pin AND the user-\
         facing doc that promises ~1ms tolerance.",
    );
}

#[test]
fn sleep_struct_stores_deadline_at_nanosecond_precision() {
    // Pin: Sleep stores `deadline: Time` and computes it via
    // `now.saturating_add_nanos(duration_to_nanos(duration))`.
    // No rounding to ms ticks. A regression that pre-rounded
    // the deadline at construction would lose sub-ms
    // precision before the wheel is even consulted.
    let source = read("src/time/sleep.rs");

    let fn_marker = "pub fn after(now: Time, duration: Duration) -> Self {";
    let pos = source.find(fn_marker);
    if let Some(start) = pos {
        let body_end = source[start..].find("\n    }\n").expect("after() close");
        let body = &source[start..start + body_end];

        assert!(
            body.contains("now.saturating_add_nanos(duration_to_nanos(duration))"),
            "REGRESSION: Sleep::after no longer computes the \
             deadline via saturating_add_nanos with nanosecond \
             precision. A regression that rounded to ms ticks \
             at construction would defeat the sub-ms storage \
             property.\n\nfn body:\n{body}",
        );

        // Forbid suspicious rounding in the deadline calc.
        let suspect_round_patterns = [
            "/ 1_000_000",
            "/ LEVEL0_RESOLUTION_NS",
            "duration.as_millis()",
        ];
        for pat in &suspect_round_patterns {
            assert!(
                !body.contains(pat),
                "REGRESSION: Sleep::after now contains `{pat}` \
                 — looks like a ms-rounding step. The deadline \
                 storage MUST stay at nanosecond precision.",
            );
        }
    } else {
        panic!(
            "Sleep::after function signature changed; pin needs \
             update."
        );
    }
}

#[test]
fn sleep_poll_with_time_uses_exact_nanosecond_comparison() {
    // Pin: Sleep::poll_with_time(now) returns Ready when
    // `now >= self.deadline` — an exact nanosecond comparison.
    // A regression to `now / 1ms >= deadline / 1ms` would
    // round both sides, eliminating the sub-ms fast path.
    let source = read("src/time/sleep.rs");

    let fn_marker = "pub fn poll_with_time(&self, now: Time) -> Poll<()> {";
    let start = source.find(fn_marker).expect("poll_with_time fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("poll_with_time close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("now >= self.deadline"),
        "REGRESSION: poll_with_time no longer uses the exact \
         `now >= self.deadline` comparison. A regression that \
         rounded to ms ticks (`now.as_millis() >= \
         self.deadline.as_millis()`) would eliminate the \
         sub-ms fast path — every Sleep with a sub-ms \
         deadline would round up to the next ms tick even \
         when polled by a fast time source.\n\n\
         fn body:\n{body}",
    );

    // Forbid the rounding patterns explicitly.
    let suspect_round_patterns = [
        "now.as_millis()",
        "self.deadline.as_millis()",
        "(now / 1_000_000)",
        "(now.as_nanos() / 1_000_000)",
    ];
    for pat in &suspect_round_patterns {
        assert!(
            !body.contains(pat),
            "REGRESSION: poll_with_time now contains `{pat}` \
             — a ms-rounding step. The exact-ns comparison is \
             the load-bearing part of the sub-ms fast path.",
        );
    }
}

#[test]
fn duration_to_nanos_helper_preserves_precision() {
    // Pin: the `duration_to_nanos` helper saturates at u64::MAX
    // but otherwise preserves nanosecond precision. A
    // regression to `duration.as_millis() * 1_000_000` would
    // round to ms ticks AND overflow on long durations.
    let source = read("src/time/sleep.rs");

    let fn_marker = "fn duration_to_nanos(duration: Duration) -> u64 {";
    let start = source.find(fn_marker).expect("duration_to_nanos fn");
    let body_end = source[start..]
        .find("\n}\n")
        .expect("duration_to_nanos close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("duration.as_nanos().min(u128::from(u64::MAX)) as u64"),
        "REGRESSION: duration_to_nanos no longer uses \
         `duration.as_nanos().min(u128::from(u64::MAX)) as u64`. \
         The `as_nanos()` call preserves the full Duration \
         precision; a regression to `as_millis()` would round \
         sub-ms durations to 0 (wrong) or 1 (still wrong).\n\n\
         fn body:\n{body}",
    );
}

#[test]
fn wheel_resolution_test_pins_sleep_tolerance_invariant() {
    // Pin: the in-crate conformance test
    // `conformance_sleep_tolerance_within_wheel_granularity`
    // exists and documents the 1ms tolerance contract. A
    // regression that removed the test would let a wheel-
    // resolution change slip past CI.
    let source = read("src/time/wheel.rs");

    assert!(
        source.contains("fn conformance_sleep_tolerance_within_wheel_granularity()"),
        "REGRESSION: the in-crate \
         conformance_sleep_tolerance_within_wheel_granularity \
         test is gone from wheel.rs. This test was the \
         existing pin for the 1ms tolerance contract — \
         removing it would let a wheel-resolution change slip \
         through.",
    );

    // The test doc should describe the 1ms tolerance.
    assert!(
        source.contains("Level 0 resolution is 1ms"),
        "REGRESSION: the conformance test no longer mentions \
         'Level 0 resolution is 1ms'. The doc is the public \
         contract; if the resolution changes, both the test \
         body and its documentation must update together.",
    );
}

#[test]
fn sleep_supports_user_supplied_time_getter() {
    // Pin: Sleep supports a user-supplied time_getter, which
    // is the documented escape hatch for sub-ms precision.
    // A user that polls Sleep with their own high-precision
    // `now()` source can drive the Ready transition at
    // sub-ms resolution. A regression that removed the
    // time_getter field would force ALL Sleeps through the
    // 1ms wheel.
    let source = read("src/time/sleep.rs");

    assert!(
        source.contains("pub fn with_time_getter(") || source.contains("with_time_getter(deadline"),
        "REGRESSION: Sleep::with_time_getter is gone. This \
         was the documented escape hatch for sub-ms precision \
         — without it, every Sleep is bound to the runtime's \
         1ms wheel.",
    );

    // The Sleep struct must carry the time_getter field.
    let struct_marker = "pub struct Sleep {";
    let struct_pos = source.find(struct_marker).expect("Sleep struct");
    let struct_end = source[struct_pos..]
        .find("\n}\n")
        .expect("Sleep struct close");
    let struct_body = &source[struct_pos..struct_pos + struct_end];

    assert!(
        struct_body.contains("time_getter") || struct_body.contains("TimeGetter"),
        "REGRESSION: Sleep struct no longer has a time_getter \
         field. The field is the load-bearing part of the \
         user-time-source escape hatch.\n\nstruct body:\n\
         {struct_body}",
    );
}

#[test]
fn sleep_doc_describes_cancel_safety_and_time_source() {
    // Pin: the Sleep doc comment describes (a) cancel safety
    // (drop is safe) and (b) the time-source flexibility (the
    // user can supply a time getter). A regression that
    // changed these would signal a behavioral change worth
    // re-auditing.
    let source = read("src/time/sleep.rs");

    let required_phrases = ["core primitive for time-based delays", "cancel-safe"];
    for phrase in &required_phrases {
        assert!(
            source.contains(phrase),
            "REGRESSION: Sleep doc no longer mentions \
             `{phrase}`. The doc is the public contract for \
             the timing primitive; if the semantics changed, \
             update doc + audit pins together.",
        );
    }
}

#[test]
fn timer_wheel_level_count_is_four() {
    // Pin: the timer wheel has 4 levels with hierarchical
    // resolution (1ms, 256ms, ~65s, ~4.6h). A regression
    // that changed the level count would alter the wheel's
    // capacity / overflow semantics — possibly truncating
    // long-duration sleeps.
    let source = read("src/time/wheel.rs");

    assert!(
        source.contains("const LEVEL_COUNT: usize = 4;"),
        "REGRESSION: LEVEL_COUNT is no longer 4. The 4-level \
         hierarchy with 256 slots/level gives the wheel a \
         capacity of ~4.6 hours of direct timer scheduling. \
         A change here affects long-duration sleeps and the \
         overflow-list semantics.",
    );
    assert!(
        source.contains("const SLOTS_PER_LEVEL: usize = 256;"),
        "REGRESSION: SLOTS_PER_LEVEL is no longer 256. The \
         level capacity affects direct vs overflow scheduling \
         boundaries.",
    );
}

// ─── Behavioral end-to-end pin (gated on test-internals) ────────────

#[cfg(feature = "test-internals")]
mod behavioral {
    use asupersync::time::Sleep;
    use asupersync::types::Time;
    use std::task::Poll;
    use std::time::Duration;

    #[test]
    fn sleep_with_500us_deadline_is_ready_when_polled_past() {
        // Pin AUDIT-CRITICAL: a Sleep with a 500us deadline
        // returns Ready when polled with a `now` that is past
        // 500us. The wheel's 1ms granularity does NOT round
        // up the Sleep's deadline at the data-structure
        // level.
        let now = Time::ZERO;
        let sleep = Sleep::after(now, Duration::from_micros(500));

        // Poll with now slightly past the deadline (600us in).
        let past = Time::from_nanos(600_000); // 600us
        let result = sleep.poll_with_time(past);
        assert_eq!(
            result,
            Poll::Ready(()),
            "REGRESSION: Sleep::poll_with_time at 600us did \
             NOT return Ready for a 500us-deadline Sleep. The \
             nanosecond-precision comparison is broken.",
        );
    }

    #[test]
    fn sleep_with_500us_deadline_is_pending_when_polled_at_300us() {
        // Pin: a 500us Sleep is NOT ready at 300us. The
        // sub-ms comparison must distinguish 300us from 500us.
        let now = Time::ZERO;
        let sleep = Sleep::after(now, Duration::from_micros(500));

        let intermediate = Time::from_nanos(300_000); // 300us
        let result = sleep.poll_with_time(intermediate);
        assert_eq!(
            result,
            Poll::Pending,
            "REGRESSION: Sleep at 300us into a 500us deadline \
             returned Ready. A regression to ms-rounding \
             would round 300us to 0ms and 500us to 0/1ms, \
             producing wrong comparisons.",
        );
    }

    #[test]
    fn sleep_with_zero_deadline_is_immediately_ready() {
        // Pin: a Sleep with Duration::ZERO is ready on the
        // first poll (deadline == now). A regression that
        // rounded UP from zero to 1ms would force every
        // zero-duration sleep to wait 1ms.
        let now = Time::ZERO;
        let sleep = Sleep::after(now, Duration::ZERO);

        let result = sleep.poll_with_time(now);
        assert_eq!(
            result,
            Poll::Ready(()),
            "REGRESSION: zero-duration Sleep is no longer \
             immediately ready. A round-up regression would \
             defer the Ready by ~1ms — breaking yield_now-\
             style patterns that rely on Duration::ZERO.",
        );
    }

    #[test]
    fn sleep_with_1ns_deadline_is_pending_at_creation_time() {
        // Pin: Sleep with a 1-NANOSECOND deadline is Pending
        // when polled at exactly the creation time (now ==
        // creation, deadline == creation+1ns). The
        // nanosecond-precision comparison must return
        // Pending here, NOT Ready.
        let now = Time::ZERO;
        let sleep = Sleep::after(now, Duration::from_nanos(1));

        let result = sleep.poll_with_time(now);
        assert_eq!(
            result,
            Poll::Pending,
            "REGRESSION: Sleep with 1ns deadline returned \
             Ready when polled at creation time. Either the \
             deadline computation underflowed or the \
             comparison is wrong — sub-ns precision is \
             broken.",
        );

        // And ready 1ns later.
        let after_1ns = Time::from_nanos(1);
        let sleep = Sleep::after(now, Duration::from_nanos(1));
        let result = sleep.poll_with_time(after_1ns);
        assert_eq!(
            result,
            Poll::Ready(()),
            "REGRESSION: Sleep with 1ns deadline did NOT \
             return Ready when polled 1ns later. The exact-\
             ns comparison is broken.",
        );
    }
}
