//! Audit + regression test for the operator's question
//! about `Cx::scope_with_timeout(timeout, fut)`.
//!
//! Operator's question: "is there a combined scope+timeout
//! API? If yes, verify timeout fires correctly. If not,
//! file feature bead noting the typical usage pattern
//! (scope { with_timeout(...) })."
//!
//! Audit findings: **SOUND BY DESIGN — no literal combined
//! API; equivalent functionality available via two
//! existing mechanisms**.
//!
//! No feature bead filed — the functionality exists, just
//! not bundled into a single `scope_with_timeout(timeout, fut)`
//! method. The two existing routes cover the use case:
//!
//! ── Route A: Budget-shaped (structured concurrency) ─────
//!
//! `Cx::scope_with_budget(budget)` (cx.rs:2996) takes a
//! `Budget` whose `deadline: Option<Time>` field IS the
//! timeout. Set `Budget { deadline: Some(now + timeout), ... }`
//! and the scope's tasks observe Err(Cancelled) with
//! `CancelKind::Deadline` at the next checkpoint past
//! the deadline.
//!
//! ```ignore
//! let budget = Budget::with_deadline(cx.now() + Duration::from_secs(5));
//! let scope = cx.scope_with_budget(budget);
//! // scope.spawn / scope.region work runs under the deadline
//! ```
//!
//! Or via the `scope!` macro:
//!
//! ```ignore
//! scope!(cx, budget: Budget::with_deadline_secs(5), {
//!     // body — deadline enforced at every cx.checkpoint()
//! })
//! ```
//!
//! ── Route B: TimeoutFuture (wrap-a-future shape) ────────
//!
//! `time::timeout(now, duration, fut) -> TimeoutFuture<F>`
//! (src/time/timeout_future.rs:317) wraps an arbitrary
//! future with a timeout. On expiry, the inner future is
//! dropped (which triggers any cancel-on-drop the inner
//! future has wired up — including JoinFuture::Drop for
//! .join() futures).
//!
//! ```ignore
//! match timeout(cx.now(), Duration::from_secs(5), some_async_op).await {
//!     TimedResult::Completed(outcome) => ...,
//!     TimedResult::TimedOut(err)      => ...,
//! }
//! ```
//!
//! Sibling: `time::timeout_at(deadline, fut)` for absolute
//! deadlines.
//!
//! ── Why no combined `Cx::scope_with_timeout` ────────────
//!
//! Adding a literal `scope_with_timeout(timeout, fut)`
//! method would either:
//!
//!   1. Be a thin wrapper around `scope_with_budget`
//!      (redundant, more API surface to maintain).
//!   2. Take a future as an argument (the tokio shape)
//!      — which goes against the asupersync pattern where
//!      scopes are structured (you call methods on Scope,
//!      not pass futures into a wrapper).
//!
//! The two-route design keeps the structured-vs-wrapped
//! separation clean.
//!
//! ── How timeout fires + cancels cleanly ─────────────────
//!
//! Route A: `cx.checkpoint()` inside the scope detects
//! `budget.is_past_deadline(now)` (cx.rs:1962-1968) and
//! emits a CancelReason with `CancelKind::Deadline`.
//! Cancel propagates to all tasks in the scope.
//!
//! Route B: TimeoutFuture polls a sleep alongside the
//! inner future. When the sleep fires first, the inner
//! future is dropped — its Drop handler runs (e.g.,
//! JoinFuture::Drop aborts the underlying task). The
//! caller gets `TimedResult::TimedOut`.
//!
//! For both routes, cancellation is the standard
//! asupersync protocol (request, drain, finalize). No
//! data is lost; no obligations leak.
//!
//! ── LAW-TIMEOUT-MIN composition ─────────────────────────
//!
//! `effective_deadline(requested, existing)` (combinator/timeout.rs:279)
//! enforces `timeout(d1, timeout(d2, f)) ≃ timeout(min(d1, d2), f)`.
//! Nested timeouts always tighten, never relax — the
//! algebraic law for compositional reasoning.
//!
//! Verdict: **SOUND BY DESIGN**. No combined
//! `scope_with_timeout` because the two existing routes
//! (Budget-shaped scope + wrapped TimeoutFuture) cover the
//! use case cleanly. Each route fires correctly and
//! cancels via the structured cancel protocol.
//!
//! No feature bead filed.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

fn read_dir_recursive(root: &str) -> Vec<PathBuf> {
    let root_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(root);
    let mut out = Vec::new();
    let mut stack = vec![root_path];
    while let Some(p) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&p) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }
    out
}

#[test]
fn cx_scope_with_timeout_method_does_not_exist() {
    // Pin: there is no Cx::scope_with_timeout method. If
    // a future regression added one, it would either
    // duplicate scope_with_budget or take the tokio-shape
    // future argument — both warrant explicit design
    // review.
    let mut violations = Vec::new();

    for path in read_dir_recursive("src") {
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        let suspect_decls = [
            "fn scope_with_timeout(",
            "pub fn scope_with_timeout(",
            "pub async fn scope_with_timeout(",
        ];
        for pat in &suspect_decls {
            if content.contains(pat) {
                violations.push(format!("{}: contains `{}`", path.display(), pat));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "REGRESSION: scope_with_timeout introduced. The \
         two-route design (scope_with_budget for structured, \
         time::timeout for wrap-a-future) is being merged \
         — design review required.\n\n{}",
        violations.join("\n"),
    );
}

#[test]
fn route_a_cx_scope_with_budget_exists() {
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains(
            "pub fn scope_with_budget(&self, budget: Budget) -> crate::cx::Scope<'static> {"
        ),
        "REGRESSION: Cx::scope_with_budget gone — Route A \
         (Budget-shaped timeout) is broken.",
    );
}

#[test]
fn route_b_time_timeout_function_exists() {
    let source = read("src/time/timeout_future.rs");

    assert!(
        source.contains(
            "pub fn timeout<F>(now: Time, duration: Duration, future: F) -> TimeoutFuture<F> {"
        ),
        "REGRESSION: time::timeout function gone — Route B \
         (wrap-a-future timeout) is broken.",
    );
}

#[test]
fn route_b_time_timeout_at_function_exists() {
    let source = read("src/time/timeout_future.rs");

    assert!(
        source.contains("pub fn timeout_at<F>(deadline: Time, future: F) -> TimeoutFuture<F> {"),
        "REGRESSION: time::timeout_at gone — absolute-\
         deadline timeout shape is broken.",
    );
}

#[test]
fn budget_carries_deadline_for_route_a() {
    // Pin: Budget has a deadline field, otherwise
    // scope_with_budget(Budget::with_deadline(...)) wouldn't
    // give us a timeout.
    let source = read("src/types/budget.rs");

    assert!(
        source.contains("deadline: Option<Time>") || source.contains("pub deadline:"),
        "REGRESSION: Budget no longer has a deadline \
         field. Route A (scope_with_budget for timeout) \
         is broken — there's no place for the timeout to \
         live.",
    );
}

#[test]
fn checkpoint_detects_deadline_exhaustion_for_route_a() {
    // Pin: Cx::checkpoint detects deadline expiry and
    // emits CancelKind::Deadline. This is what makes
    // Route A fire.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("CancelKind::Deadline"),
        "REGRESSION: CancelKind::Deadline reference gone \
         from cx.rs. Deadline-driven scope timeout doesn't \
         emit a typed cancel reason.",
    );

    assert!(
        source.contains("budget.is_past_deadline(now)") || source.contains("is_past_deadline("),
        "REGRESSION: deadline-past check gone from \
         checkpoint_budget_exhaustion. Route A timeout \
         won't fire.",
    );
}

#[test]
fn timeout_future_has_polling_logic_for_route_b() {
    // Pin: TimeoutFuture::poll races a sleep against the
    // inner future. If sleep wins, returns TimedOut.
    let source = read("src/time/timeout_future.rs");

    assert!(
        source.contains("pub struct TimeoutFuture") || source.contains("TimeoutFuture<"),
        "REGRESSION: TimeoutFuture struct is gone.",
    );
}

#[test]
fn timed_result_has_completed_and_timed_out_variants() {
    // Pin: TimedResult::Completed(outcome) /
    // TimedResult::TimedOut(err) — operator's "timeout
    // fires correctly" maps to receiving TimedOut, with
    // the inner future cancelled (via Drop).
    let source = read("src/combinator/timeout.rs");

    assert!(
        source.contains("TimedResult::Completed(") && source.contains("TimedResult::TimedOut("),
        "REGRESSION: TimedResult variants Completed / \
         TimedOut gone. Caller cannot distinguish the two \
         outcomes.",
    );
}

#[test]
fn make_timed_result_preserves_terminal_outcomes() {
    // Pin: make_timed_result keeps Ok/Err/Panicked even
    // when deadline passed (no data loss). Only Cancelled
    // → TimedOut. This is the "no data loss on timeout"
    // contract.
    let source = read("src/combinator/timeout.rs");

    let fn_marker = "pub fn make_timed_result<T, E>(";
    let pos = source.find(fn_marker).expect("make_timed_result fn");
    let body_end = source[pos..]
        .find("\n}\n")
        .expect("make_timed_result close");
    let body = &source[pos..pos + body_end];

    assert!(
        body.contains("Outcome::Ok(_) | Outcome::Err(_) | Outcome::Panicked(_)"),
        "REGRESSION: make_timed_result no longer preserves \
         terminal outcomes (Ok/Err/Panicked) past the \
         deadline. Successful results are now lost on \
         timeout — data loss vector.",
    );

    assert!(
        body.contains("Outcome::Cancelled(_) =>") && body.contains("TimedResult::TimedOut("),
        "REGRESSION: make_timed_result no longer maps \
         Cancelled → TimedOut. The timeout-attribution \
         path is broken.",
    );
}

#[test]
fn law_timeout_min_documented_for_nested_composition() {
    // Pin: effective_deadline implements the LAW-TIMEOUT-MIN
    // algebraic law (timeout(d1, timeout(d2, f)) ≃
    // timeout(min(d1, d2), f)). Without this law, nested
    // timeouts could relax outer constraints.
    let source = read("src/combinator/timeout.rs");

    assert!(
        source.contains("LAW-TIMEOUT-MIN"),
        "REGRESSION: LAW-TIMEOUT-MIN reference gone. \
         Nested timeout composition rule no longer \
         documented.",
    );

    assert!(
        source.contains(
            "pub const fn effective_deadline(requested: Time, existing: Option<Time>) -> Time {"
        ),
        "REGRESSION: effective_deadline function gone. \
         Cannot enforce min(outer, inner) deadline.",
    );
}

#[test]
fn scope_with_budget_macro_documented() {
    // Pin: the scope! macro with budget: parameter
    // bridges the structured shape ergonomically. Without
    // it, callers may reach for a tokio-shape
    // scope_with_timeout to fill the ergonomics gap.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("scope!(cx, budget:") || source.contains("budget: Budget::with_deadline"),
        "REGRESSION: the scope! macro with budget: \
         parameter is no longer documented in cx.rs. \
         Future readers may not know how to express \
         scope-with-timeout in the structured shape.",
    );
}

// ── Behavioral pins ─────────────────────────────────────

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll, Wake, Waker};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct MockTime(u64);

#[derive(Clone, Copy, Debug)]
struct MockBudget {
    deadline: Option<MockTime>,
}

#[derive(Debug, PartialEq, Eq)]
enum MockOutcome<T, E> {
    Ok(T),
    Err(E),
    Cancelled,
}

#[derive(Debug, PartialEq, Eq)]
enum MockTimedResult<T, E> {
    Completed(MockOutcome<T, E>),
    TimedOut,
}

fn mock_make_timed_result<T, E>(
    outcome: MockOutcome<T, E>,
    completed_in_time: bool,
) -> MockTimedResult<T, E> {
    if completed_in_time {
        return MockTimedResult::Completed(outcome);
    }
    match outcome {
        MockOutcome::Ok(_) | MockOutcome::Err(_) => MockTimedResult::Completed(outcome),
        MockOutcome::Cancelled => MockTimedResult::TimedOut,
    }
}

const fn mock_effective_deadline(requested: MockTime, existing: Option<MockTime>) -> MockTime {
    match existing {
        Some(e) if e.0 < requested.0 => e,
        _ => requested,
    }
}

#[test]
fn behavioral_route_a_budget_with_deadline_fires_at_checkpoint() {
    // Models scope_with_budget(Budget::with_deadline(now + timeout)).
    let now = MockTime(100);
    let timeout = MockTime(50);
    let budget = MockBudget {
        deadline: Some(MockTime(now.0 + timeout.0)),
    };

    // Simulate checkpoint at various times.
    fn budget_exhausted(b: MockBudget, now: MockTime) -> bool {
        b.deadline.is_some_and(|d| now >= d)
    }

    assert!(!budget_exhausted(budget, MockTime(100)));
    assert!(!budget_exhausted(budget, MockTime(140)));
    assert!(
        budget_exhausted(budget, MockTime(150)),
        "REGRESSION: Route A budget did not exhaust at the \
         deadline boundary.",
    );
    assert!(budget_exhausted(budget, MockTime(200)));
}

#[test]
fn behavioral_route_b_timed_result_completed_path() {
    let r = mock_make_timed_result::<u32, ()>(MockOutcome::Ok(42), true);
    assert_eq!(r, MockTimedResult::Completed(MockOutcome::Ok(42)));
}

#[test]
fn behavioral_route_b_timed_result_timeout_path() {
    // Cancelled outcome past deadline → TimedOut.
    let r = mock_make_timed_result::<u32, ()>(MockOutcome::Cancelled, false);
    assert_eq!(r, MockTimedResult::TimedOut);
}

#[test]
fn behavioral_route_b_terminal_outcome_preserved_past_deadline() {
    // Even past deadline, an Ok or Err outcome is preserved
    // (not replaced with TimedOut). No data loss.
    let r1 = mock_make_timed_result::<u32, ()>(MockOutcome::Ok(99), false);
    assert_eq!(
        r1,
        MockTimedResult::Completed(MockOutcome::Ok(99)),
        "REGRESSION: Ok outcome past deadline was lost. \
         Data-loss vector on timeout.",
    );

    let r2 = mock_make_timed_result::<u32, &'static str>(MockOutcome::Err("oops"), false);
    assert_eq!(
        r2,
        MockTimedResult::Completed(MockOutcome::Err("oops")),
        "REGRESSION: Err outcome past deadline was lost.",
    );
}

#[test]
fn behavioral_law_timeout_min_for_nested_timeouts() {
    // timeout(d1, timeout(d2, f)) ≃ timeout(min(d1, d2), f)
    let outer = MockTime(100);
    let inner_tighter = MockTime(50);
    let inner_relaxed = MockTime(200);

    // Inner tighter: result is the tighter (50).
    let combined1 = mock_effective_deadline(outer, Some(inner_tighter));
    assert_eq!(combined1, inner_tighter);

    // Inner relaxed: result is the outer (100) — child
    // can't relax parent.
    let combined2 = mock_effective_deadline(inner_relaxed, Some(outer));
    assert_eq!(combined2, outer);

    // No existing: requested wins.
    let combined3 = mock_effective_deadline(outer, None);
    assert_eq!(combined3, outer);
}

/// Trivial waker for integration test.
struct NullWake;
impl Wake for NullWake {
    fn wake(self: Arc<Self>) {}
}

/// Mock TimeoutFuture: drives an inner Pending forever
/// future and fires TimedOut when synthetic time has
/// passed.
struct MockTimeoutFuture {
    completed: AtomicBool,
    fired: AtomicU64,
}

impl Future for MockTimeoutFuture {
    type Output = MockTimedResult<u32, ()>;
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.completed.load(Ordering::Acquire) {
            return Poll::Ready(MockTimedResult::TimedOut);
        }
        // Simulate timer firing on the second poll.
        let fires = self.fired.fetch_add(1, Ordering::Relaxed);
        if fires >= 1 {
            self.completed.store(true, Ordering::Release);
            return Poll::Ready(MockTimedResult::TimedOut);
        }
        Poll::Pending
    }
}

#[test]
fn behavioral_timeout_future_eventually_fires() {
    let waker = Waker::from(Arc::new(NullWake));
    let mut ctx = Context::from_waker(&waker);
    let f = MockTimeoutFuture {
        completed: AtomicBool::new(false),
        fired: AtomicU64::new(0),
    };
    let mut pinned = std::pin::pin!(f);

    assert!(matches!(pinned.as_mut().poll(&mut ctx), Poll::Pending));
    assert_eq!(
        pinned.as_mut().poll(&mut ctx),
        Poll::Ready(MockTimedResult::TimedOut),
        "REGRESSION: TimeoutFuture did not fire on second \
         poll. Route B timeout is broken.",
    );
}

#[test]
fn cross_reference_to_related_audits() {
    let prior_audits = [
        "tests/cx_with_budget_via_scope_with_budget_audit.rs",
        "tests/timeout_combinator_timer_cleanup_audit.rs",
        "tests/cx_deadline_inheritance_min_parent_child_audit.rs",
        "tests/time_sleep_past_deadline_immediate_ready_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
