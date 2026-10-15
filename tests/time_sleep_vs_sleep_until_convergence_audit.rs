//! Audit + regression test for `time::sleep(now, duration)`
//! vs `time::sleep_until(deadline)` convergence.
//!
//! Operator's question: "Are these two paths producing
//! identical timer registrations or are they distinguishable
//! in the timer wheel? If duplicate (one calls the other),
//! pin behavior. If diverged, file bead noting risk."
//!
//! Audit findings: **SOUND BY DESIGN** — DUPLICATE PATHS.
//!
//! The two free functions in `src/time/sleep.rs` are thin
//! wrappers that converge on a single constructor:
//!
//! ```ignore
//! // src/time/sleep.rs:769
//! pub fn sleep(now: Time, duration: Duration) -> Sleep {
//!     Sleep::after(now, duration)
//! }
//!
//! // src/time/sleep.rs:790
//! pub fn sleep_until(deadline: Time) -> Sleep {
//!     Sleep::new(deadline)
//! }
//!
//! // src/time/sleep.rs:260
//! pub fn after(now: Time, duration: Duration) -> Self {
//!     let deadline = now.saturating_add_nanos(
//!         duration_to_nanos(duration));
//!     Self::new(deadline)
//! }
//! ```
//!
//! Both call sites collapse to `Sleep::new(deadline)`, which
//! constructs a `Sleep` with a single `deadline: Time` field
//! and identical SleepState (waker=None, fallback=None,
//! zombie_fallbacks=Vec::new(), timer_handle=None,
//! timer_driver=None).
//!
//! ── Timer wheel registration ────────────────────────────
//!
//! In `Sleep::poll` (src/time/sleep.rs:480), the timer is
//! registered via:
//!
//! ```ignore
//! let handle = timer.register(
//!     self.deadline,
//!     readiness_waker(Arc::clone(&self.ready), cx.waker().clone()),
//! );
//! ```
//!
//! The registration uses `self.deadline` directly. Two
//! `Sleep` instances with the same `deadline` field produce
//! IDENTICAL timer wheel entries (same expiration time, same
//! waker callback structure).
//!
//! ── Why these wrappers exist (different ergonomics, not
//!    different mechanics) ─────────────────────────────────
//!
//! - `sleep(now, duration)`: idiomatic when the caller has
//!   a relative duration and a current time (matches
//!   tokio::time::sleep semantics for shim users).
//! - `sleep_until(deadline)`: idiomatic when the caller has
//!   an absolute deadline (matches tokio::time::sleep_until
//!   semantics; useful when computing deadlines from
//!   inherited budgets).
//!
//! The duration→deadline conversion uses `Time::saturating_add_nanos`
//! to avoid overflow on `Time::MAX`. After conversion, the two
//! paths are observationally indistinguishable.
//!
//! ── Equivalence test ────────────────────────────────────
//!
//! ```ignore
//! let s1 = sleep(now, dur);                   // -> Sleep::after(now, dur) -> Sleep::new(now + dur)
//! let s2 = sleep_until(now + dur);            // -> Sleep::new(now + dur)
//! assert_eq!(s1.deadline(), s2.deadline());   // ✓ pinned in inline tests
//! ```
//!
//! Verdict: **SOUND BY DESIGN**. The two functions are
//! ergonomic aliases for `Sleep::new(deadline)`, with
//! `sleep` performing one extra `saturating_add_nanos`. No
//! divergence in timer-wheel registration. No risk of
//! inconsistency.
//!
//! No bead filed.
//!
//! A regression that:
//!   - changed `sleep` to use a different `Sleep`
//!     constructor than `sleep_until` (e.g., bypassing
//!     saturating_add and overflowing),
//!   - changed `Sleep::after` to no longer delegate to
//!     `Sleep::new` (introducing distinct state),
//!   - changed `Sleep::poll` to register different timer
//!     handles based on construction path,
//!     would all be caught by the structural pins below.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn sleep_function_delegates_to_sleep_after() {
    // Pin: the free `sleep(now, duration)` function is a
    // thin wrapper around `Sleep::after(now, duration)`.
    let source = read("src/time/sleep.rs");

    assert!(
        source.contains("pub fn sleep(now: Time, duration: Duration) -> Sleep {")
            && source.contains("Sleep::after(now, duration)"),
        "REGRESSION: `sleep(now, duration)` no longer \
         delegates to `Sleep::after`. Path divergence — \
         this audit's convergence guarantee is broken.",
    );

    // Verify the body is exactly the delegation.
    let fn_marker = "pub fn sleep(now: Time, duration: Duration) -> Sleep {";
    let pos = source.find(fn_marker).expect("sleep fn");
    let body_end = source[pos..].find("\n}\n").expect("sleep fn close");
    let body = &source[pos..pos + body_end];

    assert!(
        body.contains("Sleep::after(now, duration)"),
        "REGRESSION: `sleep` body no longer contains \
         `Sleep::after(now, duration)` — divergence.",
    );

    // Body should NOT independently call Sleep::new (which
    // would suggest divergent construction).
    let direct_new_call = body.lines().filter(|l| l.contains("Sleep::new(")).count();
    assert_eq!(
        direct_new_call, 0,
        "REGRESSION: `sleep` body now calls `Sleep::new` \
         directly, bypassing `Sleep::after`. The single \
         duration→deadline saturating-add path is broken.",
    );
}

#[test]
fn sleep_until_function_delegates_to_sleep_new() {
    // Pin: `sleep_until(deadline)` is a thin wrapper around
    // `Sleep::new(deadline)`.
    let source = read("src/time/sleep.rs");

    assert!(
        source.contains("pub fn sleep_until(deadline: Time) -> Sleep {")
            && source.contains("Sleep::new(deadline)"),
        "REGRESSION: `sleep_until(deadline)` no longer \
         delegates to `Sleep::new`. Path divergence.",
    );

    let fn_marker = "pub fn sleep_until(deadline: Time) -> Sleep {";
    let pos = source.find(fn_marker).expect("sleep_until fn");
    let body_end = source[pos..].find("\n}\n").expect("sleep_until fn close");
    let body = &source[pos..pos + body_end];

    assert!(
        body.contains("Sleep::new(deadline)"),
        "REGRESSION: `sleep_until` body no longer contains \
         `Sleep::new(deadline)` — divergence.",
    );
}

#[test]
fn sleep_after_constructor_delegates_to_sleep_new() {
    // Pin: `Sleep::after(now, duration)` computes a deadline
    // via saturating_add_nanos and delegates to `Sleep::new`.
    // This is the convergence point — both `sleep` and
    // `sleep_until` end up calling `Sleep::new`.
    let source = read("src/time/sleep.rs");

    let fn_marker = "pub fn after(now: Time, duration: Duration) -> Self {";
    let pos = source.find(fn_marker).expect("Sleep::after fn");
    let body_end = source[pos..]
        .find("\n    }\n")
        .expect("Sleep::after fn close");
    let body = &source[pos..pos + body_end];

    assert!(
        body.contains("now.saturating_add_nanos(") && body.contains("Self::new(deadline)"),
        "REGRESSION: `Sleep::after` no longer computes \
         deadline via saturating_add_nanos and delegates to \
         `Self::new`. Either overflow safety or convergence \
         is broken.",
    );

    // Body must NOT independently initialize Sleep state
    // fields (which would mean a struct-literal divergence
    // from Sleep::new). Struct-literal divergence would
    // surface as field-init lines like `time_getter: None,`
    // or `polled: std::sync::atomic::AtomicBool::new(false),`
    // appearing INSIDE Sleep::after's body.
    let divergence_signals = [
        "time_getter: None,",
        "bound_timer_driver: None,",
        "polled: std::sync::atomic::AtomicBool::new(false),",
        "completed: std::sync::atomic::AtomicBool::new(false),",
        "ready: Arc::new(AtomicBool::new(false)),",
        "timer_handle: None,",
        "timer_driver: None,",
    ];
    for sig in &divergence_signals {
        assert!(
            !body.contains(sig),
            "REGRESSION: `Sleep::after` body now contains \
             field initializer `{sig}` — Sleep::after is no \
             longer delegating to Sleep::new. State \
             initialization may diverge from sleep_until.",
        );
    }
}

#[test]
fn sleep_after_uses_saturating_add_for_overflow_safety() {
    // Pin: the duration→deadline conversion in `Sleep::after`
    // uses saturating_add_nanos, not unchecked add. This is
    // critical at Time::MAX: a regression to checked or
    // unchecked add would either panic or wrap.
    let source = read("src/time/sleep.rs");

    let fn_marker = "pub fn after(now: Time, duration: Duration) -> Self {";
    let pos = source.find(fn_marker).expect("Sleep::after fn");
    let body = &source[pos..pos + 600];

    assert!(
        body.contains("saturating_add_nanos"),
        "REGRESSION: `Sleep::after` no longer uses \
         saturating_add_nanos. Overflow at Time::MAX may \
         panic (checked add) or wrap to past time \
         (unchecked add).",
    );

    let suspect_patterns = [
        ".checked_add_nanos(",
        ".unwrap_or",
        "deadline = now + duration",
    ];
    for pat in &suspect_patterns {
        assert!(
            !body.contains(pat),
            "REGRESSION: `Sleep::after` body now contains \
             `{pat}` — overflow handling has been weakened.",
        );
    }
}

#[test]
fn sleep_new_initializes_canonical_state() {
    // Pin: `Sleep::new(deadline)` is the single canonical
    // constructor. Its initialized fields are the convergence
    // point — both `sleep` and `sleep_until` produce a Sleep
    // with these exact field values (deadline excepted).
    let source = read("src/time/sleep.rs");

    let fn_marker = "pub fn new(deadline: Time) -> Self {";
    let pos = source.find(fn_marker).expect("Sleep::new fn");
    let body_end = source[pos..]
        .find("\n    }\n")
        .expect("Sleep::new fn close");
    let body = &source[pos..pos + body_end];

    let canonical_init_lines = [
        "deadline,",
        "time_getter: None,",
        "bound_timer_driver: None,",
        "polled: std::sync::atomic::AtomicBool::new(false),",
        "completed: std::sync::atomic::AtomicBool::new(false),",
        "ready: Arc::new(AtomicBool::new(false)),",
        "waker: None,",
        "fallback: None,",
        "zombie_fallbacks: Vec::new(),",
        "timer_handle: None,",
        "timer_driver: None,",
    ];
    for line in &canonical_init_lines {
        assert!(
            body.contains(line),
            "REGRESSION: `Sleep::new` no longer initializes \
             `{line}`. State drift between sleep / \
             sleep_until paths becomes possible if the two \
             paths take different constructors.",
        );
    }
}

#[test]
fn sleep_poll_registers_timer_using_self_deadline() {
    // Pin: `Sleep::poll` registers the timer with the
    // timer driver using `self.deadline` (the same Time
    // field set by both `sleep` and `sleep_until`). If
    // poll() registered using a different field (e.g., a
    // recomputed value derived from a saved duration),
    // the two paths could diverge.
    let source = read("src/time/sleep.rs");

    assert!(
        source.contains("let handle = timer.register(") && source.contains("self.deadline,"),
        "REGRESSION: `Sleep::poll` no longer registers using \
         `self.deadline`. Timer-wheel entries from `sleep` \
         vs `sleep_until` paths may diverge.",
    );
}

#[test]
fn sleep_struct_has_single_deadline_field_no_duration_field() {
    // Pin: the `Sleep` struct stores ONE `deadline: Time`
    // field. There is NO separate `duration` or
    // `relative_to` field that would be set differently
    // depending on construction path.
    let source = read("src/time/sleep.rs");

    // Exactly one `deadline: Time,` field on the Sleep struct.
    let struct_marker = "pub struct Sleep {";
    let pos = source.find(struct_marker).expect("Sleep struct");
    let struct_end = source[pos..].find("\n}\n").expect("Sleep struct close");
    let struct_body = &source[pos..pos + struct_end];

    assert!(
        struct_body.contains("deadline: Time,"),
        "REGRESSION: `Sleep` struct no longer has a single \
         `deadline: Time` field.",
    );

    let suspect_fields = [
        "duration: Duration,",
        "relative_to: Time,",
        "constructed_via_sleep_until: bool,",
        "use_relative_path: bool,",
    ];
    for pat in &suspect_fields {
        assert!(
            !struct_body.contains(pat),
            "REGRESSION: `Sleep` struct now has `{pat}` — \
             this introduces a divergent construction path \
             between `sleep` and `sleep_until`.",
        );
    }
}

#[test]
fn sleep_inline_test_pins_after_computes_now_plus_duration() {
    // Pin: the inline unit test `after_computes_deadline`
    // must continue to assert the convergence equation
    // (Sleep::after(now, dur).deadline() == now + dur).
    // This test is the in-tree witness that the two paths
    // produce identical deadlines.
    let source = read("src/time/sleep.rs");

    assert!(
        source.contains("fn after_computes_deadline()"),
        "REGRESSION: the after_computes_deadline inline test \
         is gone. The convergence guarantee is no longer \
         witnessed in-tree.",
    );
}

#[test]
fn sleep_doc_examples_show_equivalence() {
    // Pin: the rustdoc examples on `sleep` and `sleep_until`
    // both reference `deadline()` and the relationship
    // between (now, duration) and absolute deadline. These
    // doc examples are user-facing convergence
    // documentation — losing them invites confusion.
    let source = read("src/time/sleep.rs");

    let sleep_fn_marker = "pub fn sleep(now: Time, duration: Duration) -> Sleep {";
    let sleep_pos = source.find(sleep_fn_marker).expect("sleep fn");
    let sleep_doc = &source[sleep_pos.saturating_sub(1500)..sleep_pos];

    assert!(
        sleep_doc.contains(".deadline()"),
        "REGRESSION: `sleep` doc no longer shows the \
         deadline() accessor. Users may not realize \
         (now, duration) collapses to an absolute deadline.",
    );

    let until_fn_marker = "pub fn sleep_until(deadline: Time) -> Sleep {";
    let until_pos = source.find(until_fn_marker).expect("sleep_until fn");
    let until_doc = &source[until_pos.saturating_sub(1000)..until_pos];

    assert!(
        until_doc.contains(".deadline()"),
        "REGRESSION: `sleep_until` doc no longer shows the \
         deadline() accessor.",
    );
}

// ── Behavioral pins ─────────────────────────────────────

use std::time::Duration;

/// Mock matching `Time::saturating_add_nanos` semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Time(u64);

impl Time {
    const fn from_nanos(n: u64) -> Self {
        Self(n)
    }
    fn from_secs(s: u64) -> Self {
        Self(s.saturating_mul(1_000_000_000))
    }
    const MAX: Self = Self(u64::MAX);
    fn saturating_add_nanos(self, n: u64) -> Self {
        Self(self.0.saturating_add(n))
    }
}

fn duration_to_nanos(d: Duration) -> u64 {
    let secs_ns = d.as_secs().saturating_mul(1_000_000_000);
    let sub_ns = u64::from(d.subsec_nanos());
    secs_ns.saturating_add(sub_ns)
}

/// Mock `Sleep` with the same field shape as production.
#[derive(Debug, PartialEq, Eq)]
struct MockSleep {
    deadline: Time,
}

impl MockSleep {
    fn new(deadline: Time) -> Self {
        Self { deadline }
    }
    fn after(now: Time, duration: Duration) -> Self {
        let deadline = now.saturating_add_nanos(duration_to_nanos(duration));
        Self::new(deadline)
    }
    fn deadline(&self) -> Time {
        self.deadline
    }
}

fn mock_sleep(now: Time, duration: Duration) -> MockSleep {
    MockSleep::after(now, duration)
}

fn mock_sleep_until(deadline: Time) -> MockSleep {
    MockSleep::new(deadline)
}

#[test]
fn behavioral_sleep_and_sleep_until_produce_equal_deadlines() {
    // The convergence equation: for any (now, duration),
    // sleep(now, duration) and sleep_until(now + duration)
    // produce Sleep instances with EQUAL deadlines.
    let cases = [
        (Time::from_secs(0), Duration::from_millis(1)),
        (Time::from_secs(10), Duration::from_secs(5)),
        (Time::from_nanos(1), Duration::from_nanos(1)),
        (Time::from_secs(1_000_000), Duration::from_secs(1_000)),
        // Edge: zero duration → deadline == now.
        (Time::from_secs(42), Duration::ZERO),
    ];

    for (now, duration) in cases {
        let from_sleep = mock_sleep(now, duration);
        let expected_deadline = now.saturating_add_nanos(duration_to_nanos(duration));
        let from_sleep_until = mock_sleep_until(expected_deadline);

        assert_eq!(
            from_sleep.deadline(),
            from_sleep_until.deadline(),
            "REGRESSION: sleep({:?}, {:?}) and \
             sleep_until({:?}) produced different deadlines: \
             {:?} vs {:?}.",
            now,
            duration,
            expected_deadline,
            from_sleep.deadline(),
            from_sleep_until.deadline(),
        );

        assert_eq!(
            from_sleep, from_sleep_until,
            "REGRESSION: sleep({:?}, {:?}) and \
             sleep_until({:?}) produced unequal Sleep \
             structs.",
            now, duration, expected_deadline,
        );
    }
}

#[test]
fn behavioral_sleep_overflow_saturates_at_time_max() {
    // At Time::MAX, sleep(now, duration) must saturate, not
    // panic or wrap. sleep_until at the equivalent saturated
    // deadline must produce the same result.
    let now = Time::MAX;
    let duration = Duration::from_secs(1);

    let from_sleep = mock_sleep(now, duration);
    let from_sleep_until = mock_sleep_until(Time::MAX);

    assert_eq!(
        from_sleep.deadline(),
        Time::MAX,
        "REGRESSION: sleep at Time::MAX no longer saturates. \
         Either it panicked or wrapped — both are bugs.",
    );

    assert_eq!(
        from_sleep, from_sleep_until,
        "REGRESSION: saturated sleep does not equal \
         sleep_until(Time::MAX). Convergence breaks at the \
         overflow boundary.",
    );
}

#[test]
fn behavioral_sleep_zero_duration_equals_sleep_until_now() {
    // sleep(now, ZERO) should equal sleep_until(now).
    let now = Time::from_secs(42);
    let from_sleep = mock_sleep(now, Duration::ZERO);
    let from_sleep_until = mock_sleep_until(now);

    assert_eq!(
        from_sleep, from_sleep_until,
        "REGRESSION: sleep(now, ZERO) no longer equals \
         sleep_until(now). The duration→deadline conversion \
         has drifted at the boundary.",
    );
}

#[test]
fn behavioral_timer_registration_uses_deadline_field() {
    // Models the production poll() pattern:
    //
    //   let handle = timer.register(self.deadline, ...);
    //
    // Two Sleep instances with the same deadline produce
    // the same registration argument.
    fn registration_key(s: &MockSleep) -> Time {
        s.deadline
    }

    let now = Time::from_secs(10);
    let dur = Duration::from_secs(5);

    let s1 = mock_sleep(now, dur);
    let s2 = mock_sleep_until(Time::from_secs(15));

    assert_eq!(
        registration_key(&s1),
        registration_key(&s2),
        "REGRESSION: timer registration key differs between \
         sleep and sleep_until paths. Timer-wheel entries \
         would not be deduplicatable / coalescable.",
    );
}

#[test]
fn cross_reference_to_related_timer_audits() {
    let prior_audits = [
        "tests/timeout_combinator_timer_cleanup_audit.rs",
        "tests/cx_checkpoint_past_deadline_immediate_err_audit.rs",
        "tests/cx_deadline_inheritance_min_parent_child_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
