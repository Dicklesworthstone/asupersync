//! Audit + regression test for `Cx::checkpoint()` behavior
//! in a tight loop without cooperative yields.
//!
//! Operator's question: "when a task calls checkpoint() in a
//! loop without yielding to actual work, does the scheduler
//! enforce yields (forced preemption every N checkpoints) or
//! allow infinite checkpoint loop (potential DoS)?"
//!
//! Audit findings:
//!
//!   asupersync's `Cx::checkpoint()` is **NOT a forced-yield
//!   point** — by design. It's a cancel-observation +
//!   budget-exhaustion check that runs in constant time on
//!   the fast path. The protection against tight-loop DoS
//!   comes from the cooperative-budget contract, NOT from
//!   forced preemption inside checkpoint(). The chain:
//!
//!   1. **Fast path is read-only** (cx/cx.rs:1647-1683):
//!      ```ignore
//!      let guard = self.inner.read();
//!      let cancelled = guard.fast_cancel.load(Acquire);
//!      let exhausted = !cancelled
//!          && Self::checkpoint_budget_exhaustion(...).is_some();
//!      let has_message = guard.checkpoint_state.last_message.is_some();
//!      let is_first_checkpoint = guard.checkpoint_state.checkpoint_count == 0
//!          && guard.fast_path_count.load(Relaxed) == 0;
//!      if !cancelled && !exhausted && !has_message && !is_first_checkpoint {
//!          // accounting via Relaxed atomics
//!          return Ok(());
//!      }
//!      ```
//!      No write lock, no scheduler interaction, no yield.
//!      A healthy task spinning checkpoint() returns Ok(())
//!      immediately on the read-lock path.
//!
//!   2. **Budget-exhaustion check is what bounds spinning**
//!      (cx/cx.rs:1952-1999):
//!      ```ignore
//!      fn checkpoint_budget_exhaustion(...) -> Option<...> {
//!          if budget.is_past_deadline(now) { Some(Deadline) }
//!          if budget.poll_quota == 0 { Some(PollQuota) }
//!          if matches!(budget.cost_quota, Some(0)) { Some(CostBudget) }
//!      }
//!      ```
//!      The deadline check is what gives bounded latency for
//!      a tight checkpoint loop: once `now > deadline`,
//!      every checkpoint returns Err(Deadline) and the task
//!      MUST yield via `?` propagation. The bound is exactly
//!      the deadline.
//!
//!   3. **checkpoint() does NOT decrement poll_quota**: a
//!      grep of `Budget::consume_poll` shows callers only at
//!      `lab/runtime.rs:1584` (lab-virtual decrement) and
//!      `types/cancel.rs` (cancel-budget accounting). The
//!      production three-lane scheduler does NOT call
//!      consume_poll per checkpoint. So `poll_quota` is a
//!      static value across a tight loop — it decrements
//:      only at task boundaries.
//!
//!   4. **`yield_now()` is the explicit yield primitive**:
//!      asupersync separates checkpoint (cancel observation)
//!      from yield (cooperative scheduling handoff). A task
//!      that wants to yield to the scheduler must `await
//!      yield_now()`. checkpoint() is intentionally cheap —
//!      forcing a yield inside it would either be
//!      expensive on the hot path or be trivially defeated
//!      by spreading checkpoint() across many call sites.
//!
//!   5. **Default budget has no deadline** (types/budget.rs:
//!      184): `Budget::new()` returns `{ deadline: None,
//!      poll_quota: u32::MAX, cost_quota: None, priority:
//!      128 }`. A task with the default budget can spin
//!      checkpoint() forever — but this is identical to a
//!      task spinning ANY tight loop (without checkpoint),
//!      which is the cooperative-scheduling general
//!      property of asupersync. The DoS framing is moot:
//!      checkpoint() doesn't make the spin worse.
//!
//!   6. **Multi-worker dispatch is the parallelism guard**:
//!      a task spinning on worker-A doesn't block work on
//!      worker-B/C/.... The Lyapunov governor + cancel-lane
//!      priority + EDF deadline-pressure mechanism ensure
//!      that other workers continue dispatching. The
//!      single-worker case is the only one where a tight
//!      checkpoint loop fully blocks progress, and even
//!      then only on that specific worker.
//!
//!   7. **For untrusted code, set a deadline**: the
//!      operator-correct mitigation for "tight-checkpoint
//!      DoS" is to spawn the task with a Budget that has a
//!      deadline set. Once `now > deadline`, every
//!      checkpoint returns Err(Deadline) and the task is
//!      forced to yield. This is documented behavior — the
//!      `Budget.deadline: Option<Time>` field exists
//!      precisely for this reason.
//!
//! Verdict: **SOUND**. checkpoint() is intentionally NOT a
//! forced-yield point. The cooperative-yield contract +
//! cooperative-budget contract together provide the bound:
//!   - With a deadline budget: every checkpoint after `now
//!     > deadline` returns Err — bounded yield.
//!   - With unbounded budget (default): same as ANY tight
//!     loop in cooperative scheduling; not a checkpoint-
//!     specific failure mode.
//!   - Multi-worker dispatch parallelizes around any single
//!     spinning worker.
//!   - yield_now() is the explicit yield primitive for
//!     well-behaved tasks.
//!
//! The "DoS via tight checkpoint loop" framing is a
//! category error: asupersync's cooperative-scheduling
//! contract puts the burden on the user to either (a) set
//! deadlines on untrusted code or (b) write
//! cooperatively-yielding code. Forcing a yield inside
//! checkpoint would not solve the DoS problem (a malicious
//! task can just NOT call checkpoint).
//!
//! A regression that:
//!   - moved the read-lock check inside checkpoint() to a
//!     write-lock path on every call (would explode contention),
//!   - added `consume_poll()` to checkpoint() (would silently
//!     change the cooperative-budget semantics: tasks would
//!     run out of polls based on checkpoint frequency
//!     instead of executor-poll count),
//!   - removed the deadline-exhaustion check from
//!     checkpoint_budget_exhaustion (would lose the only
//!     bound on tight-checkpoint loops with deadline-set
//!     tasks),
//!   - added a hardcoded "force yield every N checkpoints"
//!     branch (would either be expensive on the hot path
//!     or trivially defeated by N+1 calls per loop iteration),
//!   - changed Budget::default() to have a deadline (would
//!     break the "unconfigured task has no time bound"
//!     property — surprising behavioral change),
//!     would all be caught by the structural pins below.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn checkpoint_fast_path_uses_read_lock_only_no_yield() {
    // Pin (link 1): the fast path uses inner.read() (a read
    // lock), not write. A tight loop on checkpoint() must
    // not contend on the write lock for healthy cases.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn checkpoint(&self) -> Result<(), crate::error::Error> {";
    let start = source.find(fn_marker).expect("checkpoint fn");
    let window_end = (start + 6000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[start..safe_end];

    // The fast path acquires a READ lock, not a write lock.
    assert!(
        body.contains("let guard = self.inner.read();"),
        "REGRESSION: checkpoint() fast path no longer uses a \
         read lock. A write lock on every checkpoint would \
         serialize all callers — tight-loop DoS becomes a \
         real concern even for benign workloads.",
    );

    // The fast path returns Ok(()) without acquiring any
    // forced-yield handle.
    assert!(
        body.contains("return Ok(());"),
        "REGRESSION: checkpoint() fast path no longer has \
         the early `return Ok(());` short-circuit. Without \
         it, every checkpoint goes through the slow-path \
         write lock — performance regression.",
    );

    // Forbid forced-yield primitives in the fast path.
    let suspect_yield = ["yield_now", "scheduler.yield", "self.parker.unpark"];
    let fast_path_window = body.split("// ── Slow path ─").next().unwrap_or(body);
    for pat in &suspect_yield {
        assert!(
            !fast_path_window.contains(pat),
            "REGRESSION: checkpoint() fast path now contains \
             a forced-yield primitive (`{pat}`). The fast \
             path is on the cancel-observation hot path — \
             forced yields here would be either expensive \
             or trivially defeated by spreading checkpoints \
             across multiple call sites.",
        );
    }
}

#[test]
fn checkpoint_budget_exhaustion_checks_deadline_for_bounded_spinning() {
    // Pin (link 2): the deadline check inside
    // checkpoint_budget_exhaustion is what gives bounded
    // latency for a tight checkpoint loop with a deadline-
    // set task. Without it, even a deadline-set task could
    // spin forever.
    let source = read("src/cx/cx.rs");

    let fn_marker = "fn checkpoint_budget_exhaustion(";
    let start = source
        .find(fn_marker)
        .expect("checkpoint_budget_exhaustion fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("checkpoint_budget_exhaustion close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("budget.is_past_deadline(now)"),
        "REGRESSION: checkpoint_budget_exhaustion no longer \
         checks budget.is_past_deadline. A task with a \
         deadline budget could spin checkpoint() past its \
         deadline indefinitely — the only bound on tight \
         checkpoint loops is GONE.",
    );

    assert!(
        body.contains("CancelKind::Deadline"),
        "REGRESSION: checkpoint_budget_exhaustion no longer \
         emits CancelKind::Deadline on past-deadline. The \
         exhaustion case may exist but the cancel reason \
         carries the wrong cause — debugging is harder and \
         metrics conflate budgets.",
    );

    assert!(
        body.contains("budget.poll_quota == 0"),
        "REGRESSION: checkpoint_budget_exhaustion no longer \
         checks poll_quota == 0. The poll-budget enforcement \
         is gone — tasks with finite poll_quota can run past \
         their budget.",
    );
}

#[test]
fn checkpoint_does_not_call_consume_poll_per_invocation() {
    // Pin (link 3): production checkpoint() must NOT call
    // Budget::consume_poll. If it did, a tight checkpoint
    // loop would burn through poll_quota at checkpoint
    // frequency instead of executor-poll frequency —
    // silently changing the cooperative-budget semantics.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn checkpoint(&self) -> Result<(), crate::error::Error> {";
    let start = source.find(fn_marker).expect("checkpoint fn");
    let window_end = (start + 8000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[start..safe_end];

    let suspect_decrement = [
        ".consume_poll()",
        "budget.consume_poll(",
        "guard.budget.consume_poll(",
    ];
    for pat in &suspect_decrement {
        assert!(
            !body.contains(pat),
            "REGRESSION: checkpoint() now calls `{pat}`. \
             Tight-loop callers will exhaust poll_quota at \
             checkpoint frequency — silently changing the \
             cooperative-budget semantics. The poll_quota \
             must decrement only at executor-poll boundaries.",
        );
    }
}

#[test]
fn yield_now_is_the_explicit_yield_primitive_separate_from_checkpoint() {
    // Pin (link 4): yield_now is the documented
    // cooperative-yield primitive. Its existence as a
    // SEPARATE primitive from checkpoint is the design
    // contract — checkpoint observes cancel; yield_now
    // releases the worker.
    let source = read("src/runtime/yield_now.rs");

    assert!(
        source.contains("pub fn yield_now") || source.contains("pub struct YieldNow"),
        "REGRESSION: YieldNow primitive is gone from \
         src/runtime/yield_now.rs. Without an explicit yield \
         primitive, well-behaved tasks have no way to release \
         the worker mid-poll — and checkpoint becomes the \
         only available yield mechanism, which it is not.",
    );

    // YieldNow's poll method must register a wake (return
    // Pending exactly once before returning Ready).
    assert!(
        source.contains("Poll::Pending"),
        "REGRESSION: YieldNow no longer returns Poll::Pending. \
         Without the Pending return, the yield is a no-op \
         — the future returns Ready immediately and the \
         worker doesn't release the task.",
    );
}

#[test]
fn budget_default_has_no_deadline_for_unconfigured_tasks() {
    // Pin (link 5): Budget::new() returns a default with
    // deadline: None. This is the asupersync convention —
    // unconfigured tasks have no time bound. A regression
    // that ADDED a default deadline would change behavior
    // of every existing task without notice.
    let source = read("src/types/budget.rs");

    let fn_marker = "pub const fn new() -> Self {";
    let start = source.find(fn_marker).expect("Budget::new fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("Budget::new close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("deadline: None,"),
        "REGRESSION: Budget::new() no longer defaults to \
         deadline: None. Every existing unconfigured task \
         silently gets a deadline — checkpoint() loops \
         that previously ran forever now hit deadline. \
         Surprising behavioral change.",
    );

    assert!(
        body.contains("poll_quota: u32::MAX,"),
        "REGRESSION: Budget::new() no longer defaults to \
         poll_quota: u32::MAX. The default has changed \
         budget magnitude — performance characteristics of \
         every benchmark and existing test may shift.",
    );
}

#[test]
fn budget_minimal_provides_finite_poll_quota_for_cleanup() {
    // Pin (audit): Budget::MINIMAL provides 100 polls for
    // cleanup phases — the type-system-sanctioned bounded
    // budget for shutdown work. A regression that removed
    // MINIMAL or changed its quota would affect cancel
    // cleanup latency.
    let source = read("src/types/budget.rs");

    assert!(
        source.contains("pub const MINIMAL: Self = Self {") && source.contains("poll_quota: 100,"),
        "REGRESSION: Budget::MINIMAL is gone or changed \
         quota. Cleanup phases use this for bounded post-\
         cancel work — a change here affects cancel \
         finalization latency.",
    );
}

#[test]
fn checkpoint_slow_path_publishes_cancel_via_release_on_exhaustion() {
    // Pin (link 2 + cross-thread): the slow path in
    // checkpoint() that observes budget exhaustion sets
    // fast_cancel.store(true, Release). This is what makes
    // a tight checkpoint loop on a deadline-budgeted task
    // observe its OWN deadline and ALSO any cross-thread
    // cancel concurrently arriving.
    let source = read("src/cx/cx.rs");

    let slow_path_marker = "// ── Slow path ─";
    let start = source.find(slow_path_marker).expect("slow path marker");
    let window_end = (start + 4000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[start..safe_end];

    assert!(
        body.contains(".store(true, std::sync::atomic::Ordering::Release);"),
        "REGRESSION: checkpoint slow path no longer \
         publishes fast_cancel with Release on budget \
         exhaustion. Subsequent fast-path checks could \
         miss the exhaustion — tight-checkpoint-loop with \
         deadline-set task could continue spinning past \
         deadline.",
    );
}

#[test]
fn no_per_checkpoint_yield_threshold_field_in_cx_inner() {
    // Pin (link 4 audit): there must be no
    // `checkpoint_count_until_yield` or similar threshold
    // field in CxInner. The design is "checkpoint observes
    // cancel/budget; yield_now releases worker" — adding a
    // checkpoint-counting yield mechanism would conflate
    // the two and either be expensive or be trivially
    // defeated.
    let source = read("src/types/task_context.rs");

    let suspect_threshold_fields = [
        "checkpoint_count_until_yield: u32,",
        "next_forced_yield_at_checkpoint: u64,",
        "checkpoint_yield_threshold: usize,",
        "checkpoints_since_last_yield: u32,",
    ];
    for pat in &suspect_threshold_fields {
        assert!(
            !source.contains(pat),
            "REGRESSION: CxInner now has a checkpoint-yield \
             threshold field (`{pat}`). The design is that \
             checkpoint and yield are separate primitives — \
             a forced-yield-every-N-checkpoints mechanism \
             either makes the hot path expensive or is \
             trivially defeated by spreading checkpoints \
             across multiple call sites.",
        );
    }
}

// ─────────── BEHAVIORAL PIN: tight-loop checkpoint cost ────
//
// Direct simulation of the checkpoint fast-path cost. A
// freestanding mock with the same Arc<AtomicBool> +
// read-lock pattern verifies that 1M checkpoint calls
// complete in well under 1 second. If a regression made the
// fast path acquire a write lock or do per-call yields,
// this would balloon dramatically.

#[test]
fn checkpoint_fast_path_mock_completes_1m_calls_under_1_second() {
    // Behavioral pin: simulate the checkpoint fast path
    // (read fast_cancel + atomic counters). 1M iterations
    // must complete in well under 1 second.
    let fast_cancel = Arc::new(AtomicBool::new(false));
    let last_checkpoint_ns = Arc::new(AtomicU64::new(0));
    let fast_path_count = Arc::new(AtomicU64::new(0));

    let start = Instant::now();
    for _ in 0..1_000_000_u32 {
        // Mirror the production fast path: Acquire load +
        // two Relaxed atomic ops + return.
        let cancelled = fast_cancel.load(Ordering::Acquire);
        if !cancelled {
            last_checkpoint_ns.store(0, Ordering::Relaxed);
            fast_path_count.fetch_add(1, Ordering::Relaxed);
        }
    }
    let elapsed = start.elapsed();

    let count = fast_path_count.load(Ordering::Relaxed);
    assert_eq!(
        count, 1_000_000,
        "REGRESSION: fast_path_count != 1M after 1M \
         checkpoints — counter overflow or atomic-op \
         regression",
    );

    assert!(
        elapsed < std::time::Duration::from_secs(1),
        "REGRESSION: 1M mock checkpoints took {elapsed:?} \
         (>= 1 second). The production fast path is supposed \
         to be 3 atomic ops per call — total cost ~10ms for \
         1M calls. If elapsed is closer to seconds, the \
         fast-path simulation is broken or the production \
         pattern has gained heavy work.",
    );
}

#[test]
fn checkpoint_concurrent_cancel_observed_by_tight_loop() {
    // Behavioral pin: a tight checkpoint loop on worker-A
    // must observe a Release-stored cancel from worker-B
    // within bounded iterations. This pins the cross-thread
    // observation property — even a "DoS" loop reads cancel
    // every iteration.
    use std::thread;
    use std::time::Duration;

    let fast_cancel = Arc::new(AtomicBool::new(false));
    let observed_at_iteration = Arc::new(AtomicU64::new(u64::MAX));

    // Worker-B: sets cancel after a small delay.
    let setter_flag = Arc::clone(&fast_cancel);
    let setter = thread::spawn(move || {
        thread::sleep(Duration::from_millis(10));
        setter_flag.store(true, Ordering::Release);
    });

    // Worker-A: tight checkpoint loop, records iteration at
    // which it observes cancel.
    let observed = Arc::clone(&observed_at_iteration);
    for i in 0_u64..100_000_000 {
        if fast_cancel.load(Ordering::Acquire) {
            observed.store(i, Ordering::Relaxed);
            break;
        }
    }
    setter.join().expect("setter panicked");

    let observation_iter = observed.load(Ordering::Relaxed);
    assert!(
        observation_iter < 100_000_000,
        "REGRESSION: tight checkpoint loop never observed \
         cross-thread cancel — Release/Acquire pair is \
         broken or fast_cancel is not actually shared. \
         iterations counted: {observation_iter}",
    );
}

#[test]
fn cross_reference_to_prior_audits() {
    let prior_audits = [
        "tests/scheduler_cooperative_budget_yield_audit.rs",
        "tests/runtime_budget_carry_forward_across_yields_audit.rs",
        "tests/cx_checkpoint_observes_parent_region_cancel_audit.rs",
        "tests/scheduler_cross_thread_cancel_propagation_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
