//! Bounded-concurrency terminal combinators for streams.
//!
//! [`for_each_concurrent`] and [`try_for_each_concurrent`] apply an async
//! function to every item of a stream with at most `limit` items in flight at
//! once.
//!
//! # Why these are not just `buffer_unordered(limit).for_each(..)`
//!
//! [`BufferUnordered`](super::BufferUnordered) holds *plain futures* that this
//! process polls inline. When it is dropped — on cancellation, on an early
//! return, on a `?` — those in-flight futures are dropped where they stand,
//! unpolled, with no cancellation signal and no cleanup budget. That is fine for
//! pure computation and wrong for work that holds obligations.
//!
//! The combinators here own **region tasks** instead. Every in-flight item is a
//! real child of the caller's region, so:
//!
//! - it participates in region-close quiescence — the region cannot close while
//!   it runs;
//! - cancellation is delivered as the request → drain → finalize protocol
//!   rather than a silent drop;
//! - the terminal [`Outcome`] of every member is *observed*, so a panicking or
//!   cancelled item cannot vanish unnoticed.
//!
//! Both functions therefore end with an explicit drain: on cancellation, on the
//! first `Err`, and on the happy path, every member the set still owns is
//! cancelled and then **joined** before the function returns. No item is
//! abandoned in flight.
//!
//! # Cost of that guarantee
//!
//! Because members are real tasks, item values and item futures must be `Send +
//! 'static`, and the factory must be `Clone` so each member gets its own copy.
//! When the work is pure and cheap and no obligation is involved,
//! [`buffer_unordered`](super::StreamExt::buffer_unordered) remains the lighter
//! choice — it needs none of those bounds.
//!
//! # Observability
//!
//! Unlike the buffering combinators, these functions expose no
//! [`StreamTelemetrySnapshot`](super::StreamTelemetrySnapshot) accessor — a
//! deliberate decision, not an omission. They are async functions: the caller
//! holds no combinator object to snapshot while the call runs, and the two
//! ways to manufacture one (returning a handle instead of a plain future, or
//! threading a caller-supplied observer callback through the signature) would
//! reshape the public API of every call site to serve a diagnostic.
//!
//! The in-flight items do not need that instrument, because they are **region
//! tasks** — already visible to the runtime's own observability surfaces. Task
//! inspection reports their obligation holdings, poll counts, and cancellation
//! status; the lab oracles account for every member in quiescence and leak
//! checks; and each member's terminal [`Outcome`] is observed by the drive
//! loop rather than dropped. The buffering combinators need a snapshot API
//! precisely because their in-flight futures are *not* tasks and would
//! otherwise be invisible; these functions sit on the other side of that
//! trade.

use super::Stream;
use crate::combinator::JoinSet;
use crate::cx::{CancelWakerToken, Cx};
use crate::runtime::yield_now;
use crate::types::policy::FailFast;
use crate::types::{CancelReason, Outcome, PanicPayload};
use std::convert::Infallible;
use std::future::{Future, poll_fn};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::{Pin, pin};
use std::task::Poll;

/// Bound admission work even when both the source and spawn gateway stay
/// ready. The user-provided concurrency limit is a resource ceiling, not a
/// cooperative scheduling budget.
const CONCURRENT_ADMISSION_BUDGET: usize = 1024;

/// Applies `f` to every item of `stream`, keeping at most `limit` items in
/// flight.
///
/// This is the bounded-parallelism "handle each item" pattern. Each item
/// becomes a region-owned task, so in-flight work is drained rather than
/// abandoned when the caller is cancelled.
///
/// The returned [`Outcome`] is `Ok(())` when every item completed. Its error
/// type is [`Infallible`] because the per-item future cannot fail — use
/// [`try_for_each_concurrent`] when it can. `Cancelled` and `Panicked` are still
/// reachable: the caller may be cancelled, and an item may panic.
///
/// # Example
///
/// ```
/// use asupersync::stream::{for_each_concurrent, iter};
///
/// async fn fetch_all(cx: &asupersync::Cx, urls: Vec<String>) {
///     // At most 8 requests in flight, whatever the length of `urls`.
///     let outcome = for_each_concurrent(cx, iter(urls), 8, |item_cx, url| async move {
///         handle(&item_cx, url).await;
///     })
///     .await;
///     assert!(outcome.is_ok());
/// }
/// # async fn handle(_cx: &asupersync::Cx, _url: String) {}
/// ```
///
/// # Panics
///
/// Panics if `limit` is zero. A zero concurrency limit can make no progress, so
/// it is a caller bug rather than a runtime condition.
pub async fn for_each_concurrent<S, F, Fut>(
    cx: &Cx,
    stream: S,
    limit: usize,
    mut f: F,
) -> Outcome<(), Infallible>
where
    S: Stream + Unpin,
    S::Item: Send + 'static,
    F: FnMut(Cx, S::Item) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    try_for_each_concurrent(cx, stream, limit, move |item_cx, item| {
        let fut = f(item_cx, item);
        async move {
            fut.await;
            Ok(())
        }
    })
    .await
}

/// Applies fallible `f` to every item of `stream`, keeping at most `limit`
/// items in flight, and stops at the first failure.
///
/// # Short-circuit and drain
///
/// The first member to resolve non-`Ok` — `Err`, `Cancelled`, or `Panicked` —
/// stops admission of new items. Every member still in flight is then
/// **cancelled and joined** before this function returns. This drain-on-error
/// behaviour is the point of the combinator: the returned failure means "no
/// item of this stream is still running", not merely "one item failed and the
/// rest were abandoned".
///
/// The value returned is the *first* observed failure, not an aggregate. One
/// exception: if a member panics while being drained, the panic is reported
/// instead, because a panic is never an expected consequence of the
/// cancellation this function itself requested.
///
/// A panic from source polling or cloning the item factory also stops admission
/// and takes the same explicit drain path. It is reported as `Panicked`, never
/// retried against potentially inconsistent source/factory state. Panicking
/// destructors, abort-on-panic builds, and callbacks that do not return remain
/// outside this unwind-based guarantee. Dropping this function's future requests
/// cancellation but leaves asynchronous joining to the enclosing region.
///
/// # Scheduler cooperation
///
/// An always-ready source with a large concurrency limit cannot admit its
/// entire workload in one uninterrupted burst: admission yields periodically
/// so other tasks can run and publish failures or cancellation. Pending waits
/// still park on real source, member, and cancellation wakeups. This bounds
/// admission count, not the duration of an individual source poll or factory
/// clone; those operations must themselves return.
///
/// # Determinism
///
/// Completions are collected through [`JoinSet::join_next`] and
/// [`JoinSet::try_join_next`], whose
/// tie-break is the earliest-spawned ready member. With a deterministic scheduler, the
/// reported first failure is therefore deterministic for a given schedule.
///
/// # Example
///
/// ```
/// use asupersync::stream::{iter, try_for_each_concurrent};
/// use asupersync::Outcome;
///
/// async fn upload_all(cx: &asupersync::Cx, chunks: Vec<Vec<u8>>) -> Outcome<(), UploadError> {
///     // On the first failed chunk, the chunks still uploading are cancelled
///     // and joined before this returns - none is left running.
///     try_for_each_concurrent(cx, iter(chunks), 4, |item_cx, chunk| async move {
///         upload(&item_cx, chunk).await
///     })
///     .await
/// }
/// # struct UploadError;
/// # async fn upload(_cx: &asupersync::Cx, _c: Vec<u8>) -> Result<(), UploadError> { Ok(()) }
/// ```
///
/// # Panics
///
/// Panics if `limit` is zero.
pub async fn try_for_each_concurrent<S, F, Fut, E>(
    cx: &Cx,
    stream: S,
    limit: usize,
    f: F,
) -> Outcome<(), E>
where
    S: Stream + Unpin,
    S::Item: Send + 'static,
    F: FnMut(Cx, S::Item) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Result<(), E>> + Send + 'static,
    E: Send + 'static,
{
    assert!(
        limit > 0,
        "try_for_each_concurrent limit must be non-zero; a zero limit can never make progress"
    );

    let mut stream = stream;
    let mut set: JoinSet<'static, (), E, FailFast> = JoinSet::in_cx(cx);
    let mut source_done = false;
    let mut admissions_since_yield = 0usize;
    let mut terminal: Option<Outcome<(), E>> = None;

    'drive: loop {
        // Reap members that already finished, without waiting. Skipping this
        // would let completed-but-uncollected members occupy the concurrency
        // budget, silently throttling the stream below `limit`.
        while let Some(outcome) = set.try_join_next() {
            if let Some(failure) = failure_of(outcome) {
                terminal = Some(failure);
                break 'drive;
            }
        }

        // Cancellation is checked before admitting more work, so a cancelled
        // caller stops *growing* the in-flight set immediately. Members already
        // spawned are drained below rather than abandoned.
        if cx.is_cancel_requested() {
            terminal = Some(Outcome::cancelled(CancelReason::user(
                "try_for_each_concurrent: caller cancelled",
            )));
            break 'drive;
        }

        if !source_done && set.len() < limit {
            // Wait for the next item while still watching the members and the
            // caller. Parked on the source alone, a member's failure or the
            // caller's cancellation went unseen until another item arrived,
            // which for a quiet source may be never, and that item was then
            // admitted after the failure.
            let admission = {
                let mut cancel_wake = CancelWake { cx, token: None };
                let mut waiting_for_member = !set.is_empty();
                let mut completion = pin!(set.join_next(cx));
                poll_fn(|task| {
                    // Register before inspecting cancellation, so a request
                    // racing this poll cannot leave the caller parked.
                    cancel_wake.token =
                        Some(cx.refresh_cancel_waker(cancel_wake.token, task.waker()));
                    if waiting_for_member {
                        match completion.as_mut().poll(task) {
                            Poll::Ready(Some(outcome)) => {
                                return Poll::Ready(Admission::Finished(outcome));
                            }
                            Poll::Ready(None) => waiting_for_member = false,
                            Poll::Pending => {}
                        }
                    }
                    if cx.is_cancel_requested() {
                        return Poll::Ready(Admission::Cancelled);
                    }
                    match catch_unwind(AssertUnwindSafe(|| Pin::new(&mut stream).poll_next(task))) {
                        Ok(Poll::Ready(Some(item))) => Poll::Ready(Admission::Item(item)),
                        Ok(Poll::Ready(None)) => Poll::Ready(Admission::SourceDone),
                        Ok(Poll::Pending) => Poll::Pending,
                        Err(payload) => Poll::Ready(Admission::Panicked(caught_panic(payload))),
                    }
                })
                .await
                // Dropping a borrowed join_next wait neither consumes nor
                // cancels pending members. The set retains their handles and
                // wake registrations when the source wins this wait.
            };
            match admission {
                Admission::Finished(outcome) => {
                    if let Some(failure) = failure_of(outcome) {
                        terminal = Some(failure);
                        break 'drive;
                    }
                    continue 'drive;
                }
                // The check at the top of the loop reports it.
                Admission::Cancelled => continue 'drive,
                Admission::Panicked(payload) => {
                    terminal = Some(Outcome::Panicked(payload));
                    break 'drive;
                }
                Admission::Item(item) => {
                    let mut make = match catch_unwind(AssertUnwindSafe(|| f.clone())) {
                        Ok(make) => make,
                        Err(payload) => {
                            terminal = Some(Outcome::Panicked(caught_panic(payload)));
                            break 'drive;
                        }
                    };
                    if let Err(err) = set.spawn(cx, move |item_cx| make(item_cx, item)) {
                        // A member could not be admitted to the region. This is
                        // structural misuse (no spawn gateway on this `Cx`),
                        // not an item error, and there is no `E` to describe
                        // it. Report it as `Panicked` so it dominates the
                        // severity lattice and can never be mistaken for a
                        // per-item failure or for success.
                        terminal = Some(Outcome::panicked(PanicPayload::new(format!(
                            "try_for_each_concurrent: could not admit item to region: {err}"
                        ))));
                        break 'drive;
                    }
                    admissions_since_yield += 1;
                    if admissions_since_yield >= CONCURRENT_ADMISSION_BUDGET {
                        admissions_since_yield = 0;
                        yield_now().await;
                    }
                    continue 'drive;
                }
                Admission::SourceDone => {
                    source_done = true;
                    continue 'drive;
                }
            }
        }

        if source_done && set.is_empty() {
            break 'drive;
        }

        // Park on member completion AND caller cancellation. Awaiting only
        // join_next would deadlock when members need our cancellation request
        // to terminate. Registering both wake sources preserves that drain
        // guarantee without a self-waking readiness scan on every turn.
        let completed = {
            let mut cancel_wake = CancelWake { cx, token: None };
            let mut completion = pin!(set.join_next(cx));
            poll_fn(|task| {
                cancel_wake.token =
                    Some(cx.refresh_cancel_waker(cancel_wake.token, task.waker()));
                if let Poll::Ready(outcome) = completion.as_mut().poll(task) {
                    return Poll::Ready(outcome);
                }
                if cx.is_cancel_requested() {
                    Poll::Ready(None)
                } else {
                    Poll::Pending
                }
            })
            .await
        };

        match completed {
            Some(outcome) => {
                if let Some(failure) = failure_of(outcome) {
                    terminal = Some(failure);
                    break 'drive;
                }
            }
            None => {
                if cx.is_cancel_requested() {
                    terminal = Some(Outcome::cancelled(CancelReason::user(
                        "try_for_each_concurrent: caller cancelled",
                    )));
                }
                break 'drive;
            }
        }
    }

    // DRAIN. Whatever the exit path, every member the set still owns is
    // cancelled and then joined. On the happy path the set is already empty and
    // this is a no-op; on the short-circuit and cancellation paths it is the
    // guarantee that no item is left running behind us.
    let drained = set
        .cancel_all_with_reason(
            cx,
            CancelReason::user("try_for_each_concurrent: draining in-flight items"),
        )
        .await;

    finish(terminal, drained)
}

/// What the wait for the next item saw first.
enum Admission<T, E> {
    /// The source yielded an item.
    Item(T),
    /// The source is exhausted.
    SourceDone,
    /// A member finished.
    Finished(Outcome<(), E>),
    /// The caller was cancelled.
    Cancelled,
    /// Source polling panicked before it could produce an item.
    Panicked(PanicPayload),
}

/// Retain a diagnostic, not an arbitrary panic payload across drain.
/// Retiring that payload is itself user code: a secondary destructor panic
/// must not prevent already-owned tasks from receiving cancellation and joining.
fn caught_panic(payload: Box<dyn std::any::Any + Send>) -> PanicPayload {
    let message = if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_owned()
    } else {
        "stream admission panicked with a non-string payload".to_owned()
    };
    if let Err(secondary) = catch_unwind(AssertUnwindSafe(|| drop(payload))) {
        // Even the secondary payload may panic on drop. Do not double-unwind.
        std::mem::forget(secondary);
    }
    PanicPayload::new(message)
}

/// Clears the wait's cancellation-waker registration when the wait ends.
struct CancelWake<'a> {
    cx: &'a Cx,
    token: Option<CancelWakerToken>,
}

impl Drop for CancelWake<'_> {
    fn drop(&mut self) {
        if let Some(token) = self.token.take() {
            self.cx.clear_cancel_waker(token);
        }
    }
}

/// Maps a member outcome to `Some(failure)` when it is not `Ok`.
#[inline]
fn failure_of<E>(outcome: Outcome<(), E>) -> Option<Outcome<(), E>> {
    match outcome {
        Outcome::Ok(()) => None,
        failure => Some(failure),
    }
}

/// Chooses what the combinator reports, given the first observed failure (if
/// any) and the outcomes of the drained members.
///
/// Rules, in order:
///
/// 1. A member that **panicked during drain** always wins. We asked those
///    members to cancel; a panic is not an expected response to that request,
///    so it is new information and must not be swallowed by the cancellation we
///    ourselves caused.
/// 2. Otherwise the first observed failure is reported unchanged. Drained
///    members are `Cancelled` because *we* cancelled them; reporting that back
///    would overwrite the real cause with our own reaction to it.
/// 3. Otherwise `Ok(())`.
#[inline]
fn finish<E>(terminal: Option<Outcome<(), E>>, drained: Vec<Outcome<(), E>>) -> Outcome<(), E> {
    let mut drain_panic = None;
    let mut drain_failure = None;
    for outcome in drained {
        match outcome {
            Outcome::Panicked(_) if drain_panic.is_none() => drain_panic = Some(outcome),
            Outcome::Ok(()) | Outcome::Panicked(_) => {}
            other if drain_failure.is_none() => drain_failure = Some(other),
            _ => {}
        }
    }

    if let Some(panicked) = drain_panic {
        return panicked;
    }
    if let Some(failure) = terminal {
        return failure;
    }
    // No failure was observed on the drive loop. The set should already be
    // empty here, so this only fires if a member resolved non-`Ok` between the
    // final reap and the drain.
    drain_failure.unwrap_or(Outcome::ok(()))
}

#[cfg(test)]
mod admission_panic_tests {
    #![allow(clippy::pedantic, clippy::nursery, clippy::future_not_send)]

    use super::*;
    use crate::channel::mpsc;
    use crate::combinator::try_map_collect_concurrent;
    use crate::lab::run_async_under_lab;
    use parking_lot::Mutex;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::{Context, Waker};

    #[derive(Clone, Copy)]
    enum Fault {
        Source,
        FactoryClone,
        PayloadDrop,
    }

    #[derive(Default)]
    struct Signal {
        holding: AtomicBool,
        waker: Mutex<Option<Waker>>,
        source_failures: AtomicUsize,
        payload_drops: AtomicUsize,
    }

    struct HostilePayload(Arc<Signal>);

    impl Drop for HostilePayload {
        fn drop(&mut self) {
            self.0.payload_drops.fetch_add(1, Ordering::SeqCst);
            panic!("secondary panic while retiring source payload");
        }
    }

    struct Source {
        phase: u8,
        signal: Arc<Signal>,
        fault: Fault,
    }

    impl Stream for Source {
        type Item = u8;

        fn poll_next(mut self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Option<u8>> {
            if self.phase == 0 {
                self.phase = 1;
                return Poll::Ready(Some(0));
            }
            if self.phase == 2 {
                return Poll::Ready(None);
            }
            // The failure is armed only AFTER the first child owns its checked
            // send permit. No source event or spin rescues the child later.
            let incoming = task.waker().clone();
            let mut registered = self.signal.waker.lock();
            if !self.signal.holding.load(Ordering::SeqCst) {
                let retired = registered.replace(incoming);
                drop(registered);
                drop(retired);
                return Poll::Pending;
            }
            drop(registered);
            drop(incoming);
            match self.fault {
                Fault::Source => {
                    self.signal.source_failures.fetch_add(1, Ordering::SeqCst);
                    panic!("source poll panic");
                }
                Fault::PayloadDrop => {
                    self.signal.source_failures.fetch_add(1, Ordering::SeqCst);
                    std::panic::panic_any(HostilePayload(Arc::clone(&self.signal)));
                }
                Fault::FactoryClone => {
                    self.phase = 2;
                    Poll::Ready(Some(1))
                }
            }
        }
    }

    struct CloneBomb {
        calls: Arc<AtomicUsize>,
        armed: bool,
    }

    impl Clone for CloneBomb {
        fn clone(&self) -> Self {
            let index = self.calls.fetch_add(1, Ordering::SeqCst);
            if self.armed && index == 1 {
                panic!("factory clone panic");
            }
            Self { calls: Arc::clone(&self.calls), armed: self.armed }
        }
    }

    impl CloneBomb {
        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    fn panic_message<T, E>(outcome: Outcome<T, E>) -> String {
        match outcome {
            Outcome::Panicked(payload) => format!("{payload:?}"),
            _ => panic!("admission failure must be reported as Panicked"),
        }
    }

    async fn journey(cx: Cx, fault: Fault, collect: bool, cleanup_panics: bool) {
        let signal = Arc::new(Signal::default());
        let cleaned = Arc::new(AtomicUsize::new(0));
        let clones = Arc::new(AtomicUsize::new(0));
        let source = Source { phase: 0, signal: Arc::clone(&signal), fault };
        let (sender, mut receiver) = mpsc::channel::<u8>(1);
        let child_sender = sender.clone();
        let child_signal = Arc::clone(&signal);
        let child_cleaned = Arc::clone(&cleaned);
        let bomb = CloneBomb { calls: Arc::clone(&clones), armed: matches!(fault, Fault::FactoryClone) };
        let factory = move |child: Cx, item| {
            // Capture the complete CloneBomb, not just one of its fields.
            assert!(bomb.calls() > 0);
            assert_eq!(item, 0, "no item may be admitted after the armed failure");
            let sender = child_sender.clone();
            let signal = Arc::clone(&child_signal);
            let cleaned = Arc::clone(&child_cleaned);
            async move {
                let permit = sender.reserve_checked(&child).await.unwrap();
                signal.holding.store(true, Ordering::SeqCst);
                let wake = signal.waker.lock().take();
                if let Some(wake) = wake { wake.wake(); }
                child.cancelled().await;
                assert!(child.checkpoint().is_err());
                // Cleanup is asynchronous: abort-and-return without joining
                // cannot satisfy the counter and capacity assertions below.
                yield_now().await;
                yield_now().await;
                drop(permit);
                cleaned.fetch_add(1, Ordering::SeqCst);
                if cleanup_panics { panic!("cleanup panic wins"); }
                Err::<(), _>("child drained")
            }
        };
        let message = if collect {
            panic_message(try_map_collect_concurrent(&cx, source, 2, factory).await)
        } else {
            panic_message(try_for_each_concurrent(&cx, source, 2, factory).await)
        };
        assert!(signal.holding.load(Ordering::SeqCst));
        assert_eq!(cleaned.load(Ordering::SeqCst), 1, "checked before parent region teardown");
        assert!(matches!(receiver.try_recv(), Err(mpsc::RecvError::Empty)));
        assert_eq!(sender.telemetry_snapshot(1).reserved_uncommitted_obligations, 0);
        sender.try_reserve().expect("the child's capacity was returned").abort();
        let expected = if cleanup_panics {
            "cleanup panic wins"
        } else {
            match fault {
                Fault::Source => "source poll panic",
                Fault::FactoryClone => "factory clone panic",
                Fault::PayloadDrop => "non-string payload",
            }
        };
        assert!(message.contains(expected), "{message}");
        assert_eq!(clones.load(Ordering::SeqCst), if matches!(fault, Fault::FactoryClone) { 2 } else { 1 });
        assert_eq!(signal.source_failures.load(Ordering::SeqCst), usize::from(!matches!(fault, Fault::FactoryClone)));
        assert_eq!(signal.payload_drops.load(Ordering::SeqCst), usize::from(matches!(fault, Fault::PayloadDrop)));
    }

    #[test]
    fn source_and_factory_panics_drain_checked_members_in_lab() {
        for fault in [Fault::Source, Fault::FactoryClone, Fault::PayloadDrop] {
            for collect in [false, true] {
                let ((), report) = run_async_under_lab(0xC020, move |cx| journey(cx, fault, collect, false));
                assert!(report.quiescent && report.invariant_violations.is_empty());
            }
        }
    }

    #[test]
    fn cleanup_panic_takes_precedence_after_admission_panic() {
        for collect in [false, true] {
            let ((), report) = run_async_under_lab(0xC021, move |cx| journey(cx, Fault::Source, collect, true));
            assert!(report.quiescent && report.invariant_violations.is_empty());
        }
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn source_and_factory_panics_drain_checked_members_on_native_runtime() {
        for fault in [Fault::Source, Fault::FactoryClone, Fault::PayloadDrop] {
            for collect in [false, true] {
                let runtime = crate::runtime::RuntimeBuilder::current_thread().build().unwrap();
                runtime.block_on(runtime.handle().spawn(async move {
                    let cx = Cx::current().expect("native parent context");
                    journey(cx, fault, collect, false).await;
                }));
            }
        }
    }
}
