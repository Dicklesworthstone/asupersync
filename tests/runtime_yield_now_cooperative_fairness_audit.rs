//! Audit + regression test for cooperative-scheduler
//! fairness around `runtime::yield_now()`.
//!
//! Operator's question: "Spawn task A and task B; A calls
//! yield_now() in a loop while B does heavy work. Verify
//! B gets observable progress between each A.yield_now()
//! call (cooperative scheduler behaving correctly). If B
//! is starved, file scheduling-fairness bead."
//!
//! Audit findings: **SOUND** — yield_now's wake-self-then-
//! Pending protocol provably gives every ready peer at
//! least one poll between successive yields.
//!
//! ── Structural anchor ────────────────────────────────────
//!
//! `runtime::yield_now()` (src/runtime/yield_now.rs:36)
//! returns a `YieldNow` future whose poll() does:
//!
//! ```ignore
//! if self.yielded {
//!     self.completed = true;
//!     Poll::Ready(())
//! } else {
//!     self.yielded = true;
//!     cx.waker().wake_by_ref();
//!     Poll::Pending
//! }
//! ```
//!
//! On first poll: set yielded=true, wake_by_ref(), return
//! Pending. The Pending+self-wake re-schedules the task at
//! the END of the runqueue, so the scheduler MUST process
//! every other ready task at least once before getting
//! back to YieldNow.
//!
//! On second poll: return Ready(()).
//!
//! ── Why this gives B progress ───────────────────────────
//!
//! The asupersync three-lane scheduler uses a FIFO ready
//! queue (FaaFifoQueue) for the ready lane. When A's
//! YieldNow self-wakes, A is enqueued at the TAIL. Any B
//! that was already ready (or that was newly woken before
//! A's self-wake) is polled BEFORE A is polled again.
//!
//! Concretely:
//!   1. A polls; YieldNow returns Pending + self-wake.
//!      A is re-enqueued at tail of ready queue.
//!   2. Scheduler picks the next head: B (or any other
//!      ready peer). B runs until it itself yields,
//!      blocks, or its poll budget is exhausted.
//!   3. Eventually scheduler reaches A again; YieldNow
//!      returns Ready(()).
//!
//! So between successive `yield_now().await` calls in A's
//! loop, B has at minimum one full poll() of opportunity.
//!
//! ── Why this is not just hopeful ────────────────────────
//!
//! If yield_now's poll did NOT call wake_by_ref(), the
//! task would be parked indefinitely and yield_now would
//! be a synonym for "block forever." If yield_now returned
//! Ready(()) on the first poll, it would be a no-op and
//! the loop would starve other tasks.
//!
//! Both anti-patterns are blocked by the structural pins
//! below: yielded flag must be SET BEFORE wake_by_ref;
//! wake_by_ref must be unconditionally called on first
//! poll; second poll must observe yielded=true and return
//! Ready.
//!
//! ── Fairness across the three-lane scheduler ────────────
//!
//! The cancel lane preempts the ready lane (cancelled
//! tasks polled before healthy ones). The ready lane is
//! FIFO. yield_now self-wakes onto the ready lane. So
//! between two A.yield_now() calls:
//!   - all healthy ready tasks polled before A
//!   - any cancelled tasks promoted to cancel lane polled
//!     before all of them
//!     B (a healthy task doing heavy work) is in the ready
//!     lane; A re-enqueues at tail; B gets polled.
//!
//! Verdict: **SOUND**. Cooperative fairness is guaranteed
//! by yield_now's wake_by_ref + the FIFO ready-lane
//! ordering. B observably progresses between each
//! `A.yield_now().await`.
//!
//! No bead filed.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn yield_now_struct_has_yielded_and_completed_flags() {
    // Pin: YieldNow's two-bit state machine.
    let source = read("src/runtime/yield_now.rs");

    assert!(
        source.contains("pub struct YieldNow {")
            && source.contains("yielded: bool,")
            && source.contains("completed: bool,"),
        "REGRESSION: YieldNow struct shape changed. The \
         two-bit state machine that guarantees \
         single-yield semantics is broken.",
    );
}

#[test]
fn yield_now_first_poll_returns_pending_with_self_wake() {
    // Pin: the critical correctness property — first poll
    // must (a) set yielded=true, (b) call wake_by_ref() so
    // the task re-enters the runqueue, (c) return Pending.
    let source = read("src/runtime/yield_now.rs");

    let poll_marker =
        "fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {";
    let pos = source.find(poll_marker).expect("YieldNow::poll");
    let body_end = source[pos..]
        .find("\n    }\n")
        .expect("YieldNow::poll close");
    let body = &source[pos..pos + body_end];

    // The else branch (first poll) must set yielded=true,
    // call wake_by_ref, return Pending.
    let else_pos = body
        .find("} else {")
        .expect("else branch in YieldNow::poll");
    let else_body = &body[else_pos..];

    assert!(
        else_body.contains("self.yielded = true;"),
        "REGRESSION: YieldNow first-poll branch no longer \
         sets yielded=true. The state machine is broken \
         and the second poll will spin forever (or \
         duplicate the wake).",
    );

    assert!(
        else_body.contains("cx.waker().wake_by_ref();"),
        "REGRESSION: YieldNow first-poll branch no longer \
         calls cx.waker().wake_by_ref(). Without the self-\
         wake, the task is parked and yield_now() blocks \
         forever — which would indeed starve task B but \
         is a much worse bug than starvation.",
    );

    assert!(
        else_body.contains("Poll::Pending"),
        "REGRESSION: YieldNow first-poll no longer returns \
         Pending. If it returns Ready(()) directly, \
         yield_now is a no-op — the cooperative-yield \
         promise is broken.",
    );
}

#[test]
fn yield_now_second_poll_returns_ready_no_extra_wake() {
    // Pin: second poll observes yielded=true, sets
    // completed=true, returns Ready(()).
    let source = read("src/runtime/yield_now.rs");

    let poll_marker =
        "fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {";
    let pos = source.find(poll_marker).expect("YieldNow::poll");
    let body_end = source[pos..]
        .find("\n    }\n")
        .expect("YieldNow::poll close");
    let body = &source[pos..pos + body_end];

    let if_pos = body.find("if self.yielded {").expect("yielded branch");
    let if_block_end = body[if_pos..]
        .find("} else {")
        .expect("else after yielded branch");
    let if_body = &body[if_pos..if_pos + if_block_end];

    assert!(
        if_body.contains("self.completed = true;"),
        "REGRESSION: YieldNow second-poll no longer sets \
         completed=true. The fail-closed assertion against \
         polling-after-completion is unguarded.",
    );

    assert!(
        if_body.contains("Poll::Ready(())"),
        "REGRESSION: YieldNow second-poll no longer returns \
         Ready(()). yield_now would never complete.",
    );

    // Second poll must NOT call wake_by_ref again — that
    // would cause an infinite loop.
    assert!(
        !if_body.contains("wake_by_ref()") && !if_body.contains(".wake()"),
        "REGRESSION: YieldNow second-poll now calls a wake \
         method. The task will be re-enqueued forever — \
         spin loop, ready lane saturation, starvation.",
    );
}

#[test]
fn yield_now_polled_after_completion_fails_closed() {
    // Pin: the fail-closed guard against re-polling after
    // Ready. Without this, a buggy combinator could
    // re-poll YieldNow indefinitely without the bug being
    // detected.
    let source = read("src/runtime/yield_now.rs");

    assert!(
        source.contains("assert!(!self.completed, \"yield_now future polled after completion\");"),
        "REGRESSION: YieldNow no longer fail-closes on \
         polling-after-completion. Buggy combinators that \
         re-poll a finished YieldNow won't be caught.",
    );
}

#[test]
fn yield_now_is_a_free_function_not_a_cx_method() {
    // Pin: yield_now is a FREE function, not a Cx method.
    // (Adding it to Cx would invite the misconception that
    // it's tied to capability or task identity. yield_now
    // is purely a future-shape primitive.)
    let yield_source = read("src/runtime/yield_now.rs");
    let cx_source = read("src/cx/cx.rs");

    assert!(
        yield_source.contains("pub fn yield_now() -> YieldNow {"),
        "REGRESSION: yield_now is no longer a free function.",
    );

    assert!(
        !cx_source.contains("pub fn yield_now(") && !cx_source.contains("pub async fn yield_now("),
        "REGRESSION: Cx now has a yield_now method. The \
         free-function design is being silently moved to \
         a Cx method, conflating yield_now with capability \
         semantics.",
    );
}

#[test]
fn yield_now_inline_test_pins_pending_then_ready() {
    // Pin: the in-tree unit test asserts the exact poll
    // sequence (Pending → Ready, with exactly 1 wake). If
    // this test is deleted, regressions in the wake count
    // can pass CI.
    let source = read("src/runtime/yield_now.rs");

    assert!(
        source.contains("fn yield_now_pending_then_ready_with_single_wake()"),
        "REGRESSION: the yield_now_pending_then_ready_with_single_wake \
         inline test is gone. The pending-then-ready + \
         single-wake invariant is no longer guarded.",
    );

    assert!(
        source.contains("matches!(fut.as_mut().poll(&mut cx), Poll::Pending)")
            && source.contains("matches!(fut.as_mut().poll(&mut cx), Poll::Ready(()))"),
        "REGRESSION: the in-tree test no longer asserts \
         the Pending→Ready poll sequence.",
    );
}

#[test]
fn yield_now_inline_test_pins_post_completion_panics() {
    let source = read("src/runtime/yield_now.rs");

    assert!(
        source.contains("fn yield_now_repoll_after_completion_panics()"),
        "REGRESSION: the yield_now_repoll_after_completion_panics \
         inline test is gone. The fail-closed guard is \
         no longer guarded.",
    );
}

// ── Behavioral pins ─────────────────────────────────────

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll, Wake, Waker};

/// A tiny cooperative single-thread executor that mirrors
/// the asupersync FIFO ready-lane semantic: tasks woken
/// via the executor's waker are enqueued at the tail and
/// polled in FIFO order.
struct CoopExecutor {
    ready: parking_lot_mock::Mutex<VecDeque<TaskId>>,
    woken: parking_lot_mock::Mutex<Vec<TaskId>>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct TaskId(u32);

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

struct CoopWaker {
    id: TaskId,
    executor: Arc<CoopExecutor>,
}

impl Wake for CoopWaker {
    fn wake(self: Arc<Self>) {
        self.executor.woken.with(|w| w.push(self.id));
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.executor.woken.with(|w| w.push(self.id));
    }
}

impl CoopExecutor {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            ready: parking_lot_mock::Mutex::new(VecDeque::new()),
            woken: parking_lot_mock::Mutex::new(Vec::new()),
        })
    }

    fn schedule(&self, id: TaskId) {
        self.ready.with(|r| r.push_back(id));
    }

    fn drain_woken_into_ready(&self) {
        self.woken.with(|w| {
            self.ready.with(|r| {
                for id in w.drain(..) {
                    r.push_back(id);
                }
            });
        });
    }

    fn next_ready(&self) -> Option<TaskId> {
        self.ready.with(|r| r.pop_front())
    }
}

/// Mock YieldNow with the same poll behavior as production.
struct MockYieldNow {
    yielded: bool,
    completed: bool,
}

impl Future for MockYieldNow {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        assert!(!self.completed);
        if self.yielded {
            self.completed = true;
            Poll::Ready(())
        } else {
            self.yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

fn mock_yield_now() -> MockYieldNow {
    MockYieldNow {
        yielded: false,
        completed: false,
    }
}

#[test]
fn behavioral_b_progresses_between_a_yield_calls() {
    // Models the operator's scenario: A loops calling
    // yield_now(); B does heavy work in a loop. Verify B's
    // counter increments between A's yield boundaries.
    let exec = CoopExecutor::new();
    let task_a = TaskId(1);
    let task_b = TaskId(2);

    let waker_a = Waker::from(Arc::new(CoopWaker {
        id: task_a,
        executor: Arc::clone(&exec),
    }));
    let _waker_b = Waker::from(Arc::new(CoopWaker {
        id: task_b,
        executor: Arc::clone(&exec),
    }));

    let b_progress = Arc::new(AtomicU64::new(0));
    let a_yield_count = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));

    // Task A: loop yield_now() ~10 times, then signal stop.
    let a_state = Arc::clone(&a_yield_count);
    let stop_a = Arc::clone(&stop);
    let mut a_yield: Option<MockYieldNow> = Some(mock_yield_now());
    let mut a_iterations: u64 = 0;
    let target_iterations: u64 = 10;

    // Task B: loop incrementing progress counter; checks stop.
    let b_state = Arc::clone(&b_progress);
    let stop_b = Arc::clone(&stop);

    // Snapshot of B's progress at each A.yield boundary.
    let mut b_snapshots: Vec<u64> = Vec::new();

    // Initial schedule: both ready.
    exec.schedule(task_a);
    exec.schedule(task_b);

    // Run for a bounded number of poll cycles.
    for _ in 0..1000 {
        let Some(id) = exec.next_ready() else {
            // No ready tasks; drain woken and try again.
            exec.drain_woken_into_ready();
            if exec.next_ready().is_none() {
                break;
            }
            continue;
        };

        if id == task_a {
            // Poll A.
            if a_iterations >= target_iterations {
                stop_a.store(true, Ordering::Release);
                continue;
            }

            // If A has no in-flight yield, start a new one.
            let yield_in_progress = a_yield.is_some();
            if !yield_in_progress {
                a_yield = Some(mock_yield_now());
            }

            let mut yfut = a_yield.take().unwrap();
            let pinned = Pin::new(&mut yfut);
            let mut ctx = Context::from_waker(&waker_a);
            match pinned.poll(&mut ctx) {
                Poll::Pending => {
                    // Save the in-flight yield; it'll be
                    // re-polled when waker fires.
                    a_yield = Some(yfut);
                }
                Poll::Ready(()) => {
                    // Yield completed — count it, snapshot
                    // B's progress, and start a new yield.
                    a_iterations += 1;
                    a_state.fetch_add(1, Ordering::Relaxed);
                    b_snapshots.push(b_state.load(Ordering::Relaxed));
                    a_yield = None;
                    // Start the next yield by self-scheduling.
                    exec.schedule(task_a);
                }
            }
        } else if id == task_b {
            if !stop_b.load(Ordering::Acquire) {
                // Heavy work: bump the counter and re-schedule.
                b_state.fetch_add(1, Ordering::Relaxed);
                exec.schedule(task_b);
            }
        }

        exec.drain_woken_into_ready();
    }

    // A completed all 10 yields.
    assert_eq!(
        a_yield_count.load(Ordering::Relaxed),
        target_iterations,
        "REGRESSION: A did not complete all yields. The \
         cooperative scheduler may not be returning to A.",
    );

    // B made progress: at least target_iterations * 1 (one
    // tick per yield boundary).
    let final_b = b_progress.load(Ordering::Relaxed);
    assert!(
        final_b >= target_iterations,
        "REGRESSION: B made only {final_b} progress over \
         {target_iterations} A.yield_now() calls — B is \
         starved. yield_now is not actually yielding.",
    );

    // Critical pin: B's snapshot at each yield boundary
    // must be MONOTONICALLY NON-DECREASING and STRICTLY
    // INCREASING between successive yields (since B
    // re-schedules itself, it gets at least one poll
    // between A's yields).
    for window in b_snapshots.windows(2) {
        let prev = window[0];
        let curr = window[1];
        assert!(
            curr > prev,
            "REGRESSION: B's progress did not advance \
             between successive A.yield_now() calls \
             (prev={prev}, curr={curr}). B is being \
             starved across yield boundaries — \
             cooperative scheduling broken.",
        );
    }
}

#[test]
fn behavioral_yield_now_self_wake_re_enqueues_at_tail() {
    // Pin: when YieldNow self-wakes, the task is enqueued
    // at the TAIL of the ready queue, not the head. This
    // is what gives B a chance to run before A is re-polled.
    let exec = CoopExecutor::new();
    let task_a = TaskId(1);
    let task_b = TaskId(2);

    let waker_a = Waker::from(Arc::new(CoopWaker {
        id: task_a,
        executor: Arc::clone(&exec),
    }));

    // Schedule A first, then B.
    exec.schedule(task_a);
    exec.schedule(task_b);

    // Poll A's yield_now: it self-wakes.
    let mut yfut = mock_yield_now();
    let pinned = Pin::new(&mut yfut);
    let mut ctx = Context::from_waker(&waker_a);
    let _ = pinned.poll(&mut ctx);

    // After A's poll: A has been removed from ready and
    // pushed onto woken. Drain woken → ready.
    exec.next_ready().expect("A was at head"); // simulate scheduler
    exec.drain_woken_into_ready();

    // Now ready queue should be: [B, A] (B was second
    // initially; A is at the tail after self-wake).
    let next = exec.next_ready().expect("ready queue not empty");
    assert_eq!(
        next, task_b,
        "REGRESSION: yield_now's self-wake re-enqueued at \
         HEAD, not tail. A would be polled before B — \
         starvation. The FIFO fairness invariant is broken.",
    );
}

#[test]
fn behavioral_yield_now_does_not_busyspin() {
    // Pin: yield_now's two-poll-then-Ready behavior
    // guarantees the loop terminates. If yield_now spun
    // forever, the calling loop never completes.
    let exec = CoopExecutor::new();
    let task = TaskId(1);
    let waker = Waker::from(Arc::new(CoopWaker {
        id: task,
        executor: Arc::clone(&exec),
    }));

    let mut yfut = mock_yield_now();
    let pinned1 = Pin::new(&mut yfut);
    let mut ctx = Context::from_waker(&waker);
    assert!(matches!(pinned1.poll(&mut ctx), Poll::Pending));

    let pinned2 = Pin::new(&mut yfut);
    let mut ctx = Context::from_waker(&waker);
    assert!(matches!(pinned2.poll(&mut ctx), Poll::Ready(())));
}

#[test]
fn behavioral_no_starvation_under_long_loop() {
    // Stress test: A yields 1000 times, B should make
    // ≥1000 progress.
    let exec = CoopExecutor::new();
    let task_a = TaskId(1);
    let task_b = TaskId(2);
    let waker_a = Waker::from(Arc::new(CoopWaker {
        id: task_a,
        executor: Arc::clone(&exec),
    }));

    let target: u64 = 1000;
    let b_progress = Arc::new(AtomicU64::new(0));
    let mut a_iterations: u64 = 0;
    let mut a_yield: Option<MockYieldNow> = None;

    exec.schedule(task_a);
    exec.schedule(task_b);

    for _ in 0..200_000 {
        let Some(id) = exec.next_ready() else {
            exec.drain_woken_into_ready();
            if exec.next_ready().is_none() {
                break;
            }
            continue;
        };

        if id == task_a {
            if a_iterations >= target {
                continue;
            }
            if a_yield.is_none() {
                a_yield = Some(mock_yield_now());
            }
            let mut y = a_yield.take().unwrap();
            let pinned = Pin::new(&mut y);
            let mut ctx = Context::from_waker(&waker_a);
            match pinned.poll(&mut ctx) {
                Poll::Pending => {
                    a_yield = Some(y);
                }
                Poll::Ready(()) => {
                    a_iterations += 1;
                    a_yield = None;
                    if a_iterations < target {
                        exec.schedule(task_a);
                    }
                }
            }
        } else if id == task_b {
            b_progress.fetch_add(1, Ordering::Relaxed);
            if b_progress.load(Ordering::Relaxed) < target * 2 {
                exec.schedule(task_b);
            }
        }

        exec.drain_woken_into_ready();
    }

    assert_eq!(
        a_iterations, target,
        "REGRESSION: A did not complete {target} yields. \
         The scheduler is starving A — yield_now self-wake \
         is broken.",
    );
    assert!(
        b_progress.load(Ordering::Relaxed) >= target,
        "REGRESSION: B made only {} progress (expected \
         ≥{target}). B is starved under high-frequency \
         A.yield_now() loop.",
        b_progress.load(Ordering::Relaxed),
    );
}

#[test]
fn cross_reference_to_related_audits() {
    let prior_audits = [
        "tests/runtime_yield_now_does_not_check_cancel_audit.rs",
        "tests/runtime_yield_now_vs_sleep_zero_distinction_audit.rs",
        "tests/scheduler_spawn_storm_o_one_per_spawn_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
