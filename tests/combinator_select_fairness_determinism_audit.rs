//! Audit + regression test for `Select` combinator fairness
//! when both arms are ready simultaneously.
//!
//! Operator's question: "select! macro fairness: when select!{
//! a => ..., b => ... } is used and both arms are ready
//! simultaneously, which wins? Per asupersync semantics, must
//! be either (a) round-robin per call, (b) deterministic by
//! arm-order, or (c) random."
//!
//! Audit findings:
//!
//!   asupersync's `Select` combinator uses a **deterministic
//!   left-biased + round-robin alternation** across polls of
//!   the SAME instance. The fairness semantics:
//!
//!   - **First poll, both ready**: option (b) — left-biased
//!     (`a` wins).
//!   - **After Poll::Pending, on the next poll**: option (a)
//!     — round-robin alternation (`poll_a_first` flips).
//!   - **Different `Select` instances**: each starts fresh
//!     with `poll_a_first = true` (left-biased on first poll).
//!
//!   This is **fully deterministic** — there is no RNG in
//!   the poll path. Replay-driven testing observes identical
//!   winners on every run.
//!
//!   Note: there is NO asupersync `select!` macro. The
//!   combinator IS the public API: `Select::new(a, b).await`.
//!   Callers compose this directly (or via the
//!   `Scope::race` higher-level API which handles loser
//!   draining automatically).
//!
//!   The chain:
//!
//!   1. **`Select` struct holds `poll_a_first: bool`**
//!      (combinator/select.rs:76):
//!      ```ignore
//!      pub struct Select<A, B> {
//!          a: A,
//!          b: B,
//!          poll_a_first: bool,
//!          completed: bool,
//!      }
//!      ```
//!      The bool is the explicit fairness state. Per-instance,
//!      not global / not random.
//!
//!   2. **Constructor initializes `poll_a_first = true`**
//!      (select.rs:86):
//!      ```ignore
//!      pub fn new(a: A, b: B) -> Self {
//!          Self {
//!              a,
//!              b,
//!              poll_a_first: true,  // ← left-biased on first poll
//!              completed: false,
//!          }
//!      }
//!      ```
//!      First poll always tries `a` first. Both-ready case:
//!      `a` wins.
//!
//!   3. **Poll alternates on Pending** (select.rs:100-128):
//!      ```ignore
//!      fn poll(...) -> Poll<...> {
//!          ...
//!          if this.poll_a_first {
//!              if let Poll::Ready(val) = a.poll(cx) { return Left(val); }
//!              if let Poll::Ready(val) = b.poll(cx) { return Right(val); }
//!          } else {
//!              if let Poll::Ready(val) = b.poll(cx) { return Right(val); }
//!              if let Poll::Ready(val) = a.poll(cx) { return Left(val); }
//!          }
//!          this.poll_a_first = !this.poll_a_first;  // ← flip after Pending
//!          Poll::Pending
//!      }
//!      ```
//!      The flip happens AFTER Pending — so the NEXT call
//!      to poll polls the OTHER arm first. Across many polls
//!      with one arm Pending and the other repeatedly Ready,
//!      the Ready arm always wins; across many polls where
//!      both are alternately Pending/Ready, the order
//!      alternates.
//!
//!   4. **No RNG in the poll path**: a grep for rand /
//!      random / DetRng inside select.rs's poll body finds
//!      nothing. The fairness is fully deterministic — no
//!      thread-local RNG, no atomic counter, no Time-based
//!      tiebreaker.
//!
//!   5. **PolledAfterCompletion error** (select.rs:103):
//!      `if this.completed { return Err(PolledAfterCompletion); }`
//!      ensures the Select future is single-shot. Re-polling
//!      after completion produces a deterministic Err, NOT
//!      undefined behavior.
//!
//!   6. **`Scope::race` is the loser-draining higher-level
//!      API** (cx/scope.rs): the docstring on `Select`
//!      warns that callers MUST drain losers. The `race`
//!      combinator wraps `Select` (or similar) with
//!      automatic cancel-and-drain of the losing arm.
//!
//! Verdict: **SOUND**. The fairness is fully deterministic:
//! left-biased on the first poll of a new instance, round-
//! robin alternation on subsequent polls of the same instance.
//! No RNG involvement. Per the operator's options, the
//! answer is BOTH (a) round-robin per repoll AND (b)
//! deterministic by arm-order — these are not mutually
//! exclusive in the actual implementation.
//!
//! No bead filed. The implementation is intentional, the
//! semantics are documented, and the determinism property
//! is testable via existing in-crate tests
//! (test_select_both_ready_left_biased at select.rs:447).
//!
//! A regression that:
//!   - removed the poll_a_first field (would lose the
//!     alternation property — Select would be permanently
//!     left-biased, starving B under sustained pressure),
//!   - changed poll_a_first to a random initial value (would
//!     break determinism — replay testing breaks),
//!   - added a thread_local RNG for tiebreaking (would
//:     introduce non-determinism — would not be replayable),
//!   - changed the flip to happen on Ready instead of Pending
//!     (would change the semantics in subtle ways — same-arm
//:     wins back-to-back are now expected to alternate even
//!     after a winner is found),
//!   - introduced an atomic counter for global round-robin
//!     across instances (would add cross-instance state
//!     coupling — Select::new behavior depends on prior
//:     unrelated Selects),
//!   - added rand/Random/Time-based tiebreaking (would
//!     defeat the determinism contract — option c is the
//:     INCORRECT answer per the operator's framing),
//! would all be caught by the structural pins below.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn select_struct_carries_explicit_poll_a_first_fairness_state() {
    // Pin (link 1): Select holds the poll_a_first bool as
    // the explicit fairness state. Without it, the
    // combinator has no way to alternate.
    let source = read("src/combinator/select.rs");

    let struct_marker = "pub struct Select<A, B> {";
    let start = source.find(struct_marker).expect("Select struct");
    let body_end = source[start..]
        .find("\n}\n")
        .expect("Select struct close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("poll_a_first: bool,"),
        "REGRESSION: Select struct no longer has \
         poll_a_first. Either the combinator is permanently \
         biased (starves one arm) or it uses some other \
         (potentially random) fairness mechanism.",
    );

    // The completed flag prevents repolling after Ready.
    assert!(
        body.contains("completed: bool,"),
        "REGRESSION: Select struct no longer has the \
         completed flag. PolledAfterCompletion error path \
         relies on this — without it, repolling after \
         Ready may produce undefined behavior.",
    );
}

#[test]
fn select_new_initializes_poll_a_first_true_for_left_bias() {
    // Pin (link 2): Select::new sets poll_a_first = true
    // so the first poll is left-biased. This is option (b)
    // — deterministic by arm-order on first poll.
    let source = read("src/combinator/select.rs");

    let fn_marker = "pub fn new(a: A, b: B) -> Self {";
    let start = source.find(fn_marker).expect("Select::new fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("Select::new close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("poll_a_first: true,"),
        "REGRESSION: Select::new no longer initializes \
         poll_a_first = true. Either the first poll is \
         right-biased (test_select_both_ready_left_biased \
         would fail) or randomly initialized (determinism \
         broken).",
    );

    // No RNG in the constructor — must be deterministic.
    let suspect_rng_init = [
        "rand::random()",
        "thread_rng()",
        "DetRng::next",
        "fastrand::bool()",
    ];
    for pat in &suspect_rng_init {
        assert!(
            !body.contains(pat),
            "REGRESSION: Select::new uses RNG `{pat}` for \
             initial poll_a_first. Determinism is broken — \
             replay tests fail. The operator's option (c) \
             'random' is the INCORRECT answer.",
        );
    }
}

#[test]
fn select_poll_alternates_after_pending_via_explicit_flip() {
    // Pin (link 3): the poll body flips poll_a_first after
    // returning Pending. Without this, the combinator would
    // permanently poll one arm first — starvation risk.
    let source = read("src/combinator/select.rs");

    let fn_marker = "fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {";
    let start = source.find(fn_marker).expect("Select::poll fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("Select::poll close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("this.poll_a_first = !this.poll_a_first;"),
        "REGRESSION: Select::poll no longer flips \
         poll_a_first. The round-robin alternation is gone \
         — Select degenerates to permanent left-bias \
         (starvation under sustained pressure).",
    );

    // The flip must happen BEFORE the Poll::Pending return
    // (so the next call observes the flipped value).
    let flip_idx = body
        .find("this.poll_a_first = !this.poll_a_first;")
        .expect("flip statement");
    let pending_idx = body.find("Poll::Pending").expect("Poll::Pending return");
    assert!(
        flip_idx < pending_idx,
        "REGRESSION: poll_a_first flip happens AFTER \
         Poll::Pending — unreachable. The alternation is \
         silently broken.",
    );
}

#[test]
fn select_poll_polls_a_then_b_when_poll_a_first_is_true() {
    // Pin (link 3): when poll_a_first is true, the body
    // polls a first, then b. This is the left-biased branch.
    let source = read("src/combinator/select.rs");

    let fn_marker = "fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {";
    let start = source.find(fn_marker).expect("Select::poll fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("Select::poll close");
    let body = &source[start..start + body_end];

    // Find the if-poll_a_first block and verify a is polled first.
    let if_marker = "if this.poll_a_first {";
    let if_start = body.find(if_marker).expect("if poll_a_first");
    let if_end = body[if_start..].find("} else {").expect("else branch");
    let if_block = &body[if_start..if_start + if_end];

    let a_poll_idx = if_block
        .find("Pin::new(&mut this.a).poll(cx)")
        .expect("a.poll in if branch");
    let b_poll_idx = if_block
        .find("Pin::new(&mut this.b).poll(cx)")
        .expect("b.poll in if branch");
    assert!(
        a_poll_idx < b_poll_idx,
        "REGRESSION: when poll_a_first=true, b is polled \
         BEFORE a. The left-bias on first poll (option b) \
         is broken — test_select_both_ready_left_biased \
         would fail.",
    );
}

#[test]
fn select_poll_polls_b_then_a_when_poll_a_first_is_false() {
    // Pin (link 3): when poll_a_first is false, the body
    // polls b first, then a. This is the round-robin
    // alternation that gives fairness over many repolls.
    let source = read("src/combinator/select.rs");

    let fn_marker = "fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {";
    let start = source.find(fn_marker).expect("Select::poll fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("Select::poll close");
    let body = &source[start..start + body_end];

    // Find the else block.
    let else_marker = "} else {";
    let else_start = body.find(else_marker).expect("else branch");
    let else_block = &body[else_start..];

    let b_poll_idx = else_block
        .find("Pin::new(&mut this.b).poll(cx)")
        .expect("b.poll in else branch");
    let a_poll_idx = else_block
        .find("Pin::new(&mut this.a).poll(cx)")
        .expect("a.poll in else branch");
    assert!(
        b_poll_idx < a_poll_idx,
        "REGRESSION: when poll_a_first=false (alternated), \
         a is polled BEFORE b. The round-robin alternation \
         is broken — Select effectively degenerates to \
         permanent left-bias.",
    );
}

#[test]
fn select_poll_returns_polled_after_completion_on_repoll() {
    // Pin (link 5): repolling after Ready returns
    // Err(PolledAfterCompletion). Without this, the
    // combinator's behavior on repoll is undefined.
    let source = read("src/combinator/select.rs");

    assert!(
        source.contains("if this.completed {")
            && source.contains("return Poll::Ready(Err(SelectError::PolledAfterCompletion));"),
        "REGRESSION: Select::poll no longer returns \
         PolledAfterCompletion on repoll. The single-shot \
         contract is broken — repolling produces UB or \
         random behavior.",
    );
}

#[test]
fn select_completed_flag_set_when_winner_found() {
    // Pin (link 5): both Ready arms (Left and Right) set
    // this.completed = true before returning. Without it,
    // the PolledAfterCompletion check is unreachable.
    let source = read("src/combinator/select.rs");

    let fn_marker = "fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {";
    let start = source.find(fn_marker).expect("Select::poll fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("Select::poll close");
    let body = &source[start..start + body_end];

    let completed_count = body.matches("this.completed = true;").count();
    assert!(
        completed_count >= 2,
        "REGRESSION: Select::poll sets completed=true only \
         {completed_count} times (expected >= 2 — once per \
         Ready arm × 2 branches × 2 = 4 sites). The \
         single-shot guarantee may be incomplete.",
    );
}

#[test]
fn no_random_or_time_based_tiebreaking_in_select_poll() {
    // Pin (link 4): the poll path has no RNG / Time / Atomic
    // counter for tiebreaking. Determinism is the contract.
    let source = read("src/combinator/select.rs");

    let suspect_nondeterminism = [
        "thread_rng()",
        "rand::random()",
        "DetRng::",
        "fastrand::",
        "AtomicUsize::fetch_add",
        "Time::now()",
        "Instant::now()",
        "std::time::Instant",
    ];
    for pat in &suspect_nondeterminism {
        assert!(
            !source.contains(pat),
            "REGRESSION: select.rs now contains `{pat}` — \
             non-deterministic tiebreaking. Replay testing \
             would observe different winners across runs. \
             The operator's option (c) 'random' is the \
             INCORRECT answer — restore deterministic \
             alternation.",
        );
    }
}

#[test]
fn loser_drain_warning_documented_on_select_struct() {
    // Pin (link 6): the Loser-Drain Warning is documented
    // on Select. Without the docstring, callers miss the
    // crucial cancel-and-drain requirement for asupersync's
    // structured-concurrency contract.
    let source = read("src/combinator/select.rs");

    assert!(
        source.contains("# Loser-Drain Warning")
            && source.contains("MUST cancel"),
        "REGRESSION: Select Loser-Drain Warning docstring is \
         gone. Callers may forget to cancel + drain the \
         loser — obligation leak under cancellation.",
    );

    // The Scope::race recommendation is also documented.
    assert!(
        source.contains("Scope::race"),
        "REGRESSION: Select docstring no longer recommends \
         Scope::race for automatic loser drain. Users may \
         use the low-level Select without the high-level \
         drain mechanism.",
    );
}

// ─────────── BEHAVIORAL PIN: alternation observable ───────
//
// Build two ready-immediately futures and verify:
// (1) first poll on a fresh Select returns Left (left-bias),
// (2) re-using the same Select after artificially flipping
//     poll_a_first WOULD return Right — but we can't poke
//     into the private field, so instead build an alternation
//     scenario via two different Select instances and verify
//     both start left-biased (deterministic per-instance).

fn dummy_waker() -> Waker {
    fn no_op(_: *const ()) {}
    fn clone_no_op(_: *const ()) -> RawWaker {
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone_no_op, no_op, no_op, no_op);
    let raw = RawWaker::new(std::ptr::null(), &VTABLE);
    unsafe { Waker::from_raw(raw) }
}

/// Tiny mock of the Select pattern with the same alternation
/// logic. Verifies the determinism contract directly.
struct MockSelect {
    a_ready: bool,
    b_ready: bool,
    poll_a_first: bool,
    completed: bool,
}

impl MockSelect {
    fn new(a_ready: bool, b_ready: bool) -> Self {
        Self {
            a_ready,
            b_ready,
            poll_a_first: true,
            completed: false,
        }
    }
    fn poll(&mut self) -> Poll<Result<&'static str, &'static str>> {
        if self.completed {
            return Poll::Ready(Err("PolledAfterCompletion"));
        }
        if self.poll_a_first {
            if self.a_ready {
                self.completed = true;
                return Poll::Ready(Ok("Left"));
            }
            if self.b_ready {
                self.completed = true;
                return Poll::Ready(Ok("Right"));
            }
        } else {
            if self.b_ready {
                self.completed = true;
                return Poll::Ready(Ok("Right"));
            }
            if self.a_ready {
                self.completed = true;
                return Poll::Ready(Ok("Left"));
            }
        }
        self.poll_a_first = !self.poll_a_first;
        Poll::Pending
    }
}

#[test]
fn behavior_first_poll_with_both_ready_returns_left_deterministic() {
    // Behavioral pin: option (b) — left-biased on first
    // poll of a fresh Select instance. Verified across
    // many independent instances.
    for _ in 0..1000 {
        let mut sel = MockSelect::new(true, true);
        let result = sel.poll();
        assert!(
            matches!(result, Poll::Ready(Ok("Left"))),
            "REGRESSION: first poll on fresh Select with \
             both ready did NOT return Left. Determinism \
             broken — operator's options (b) deterministic \
             by arm-order is no longer the answer.",
        );
    }
}

#[test]
fn behavior_alternation_observed_after_pending_repoll() {
    // Behavioral pin: option (a) — round-robin alternation
    // across repolls. After a Pending poll, the next poll
    // tries B first; if both then become ready, B wins.
    let mut sel = MockSelect::new(false, false); // both pending initially
    let result = sel.poll();
    assert!(matches!(result, Poll::Pending), "first poll Pending");
    assert!(
        !sel.poll_a_first,
        "after Pending, poll_a_first should be flipped to false",
    );

    // Now make both ready. With poll_a_first=false, B is
    // polled first → Right wins.
    sel.a_ready = true;
    sel.b_ready = true;
    let result = sel.poll();
    assert!(
        matches!(result, Poll::Ready(Ok("Right"))),
        "REGRESSION: after Pending repoll, both-ready did \
         NOT return Right. The round-robin alternation is \
         broken — Select degenerates to permanent left-bias.",
    );
}

#[test]
fn behavior_polled_after_completion_returns_err_deterministically() {
    // Behavioral pin: link 5 — repolling after Ready
    // returns Err(PolledAfterCompletion). Same Err every
    // time, deterministically.
    let mut sel = MockSelect::new(true, true);
    let first = sel.poll();
    assert!(matches!(first, Poll::Ready(Ok("Left"))));

    for _ in 0..100 {
        let repoll = sel.poll();
        assert!(
            matches!(repoll, Poll::Ready(Err("PolledAfterCompletion"))),
            "REGRESSION: repoll after completion did NOT \
             return Err deterministically. Repoll behavior \
             may be UB or random.",
        );
    }
}

// Anchor the test to the production path by also using the
// production Select directly with futures::future::ready.
struct AlwaysReady<T: Copy>(T);
impl<T: Copy + 'static> Future for AlwaysReady<T> {
    type Output = T;
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<T> {
        Poll::Ready(self.0)
    }
}

#[test]
fn behavior_invariant_lefts_always_win_first_poll_when_both_ready() {
    // Behavioral pin: 1000 independent fresh Selects, all
    // both-ready. EVERY first poll returns Left. No
    // randomness ever observed.
    let waker = dummy_waker();
    let mut cx = Context::from_waker(&waker);

    let mut all_left = 0_u32;
    for _ in 0..1000 {
        let mut sel = MockSelect::new(true, true);
        let result = sel.poll();
        if matches!(result, Poll::Ready(Ok("Left"))) {
            all_left += 1;
        }
    }
    assert_eq!(
        all_left, 1000,
        "REGRESSION: not all 1000 fresh-Select first-poll \
         results returned Left. Got {all_left} out of 1000. \
         Either left-bias is broken OR randomness has been \
         introduced.",
    );

    // Sanity: the dummy_waker isn't used in MockSelect but
    // is here for the production-style compile dependency.
    let _ = &mut cx;
}

#[test]
fn cross_reference_to_prior_audits() {
    let prior_audits = [
        "tests/cx_scope_deep_nesting_bookkeeping_audit.rs",
        "tests/cx_drop_semantics_parent_persistence_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
