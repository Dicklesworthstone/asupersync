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

use super::{Stream, StreamExt};
use crate::combinator::JoinSet;
use crate::cx::Cx;
use crate::runtime::yield_now;
use crate::types::policy::FailFast;
use crate::types::{CancelReason, Outcome, PanicPayload};
use std::convert::Infallible;
use std::future::Future;

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
/// ```ignore
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
/// # Determinism
///
/// Completions are collected through [`JoinSet::join_next`], whose tie-break is
/// the earliest-spawned ready member. With a deterministic scheduler, the
/// reported first failure is therefore deterministic for a given schedule.
///
/// # Example
///
/// ```ignore
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
            match stream.next().await {
                Some(item) => {
                    let mut make = f.clone();
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
                    continue 'drive;
                }
                None => {
                    source_done = true;
                    continue 'drive;
                }
            }
        }

        if source_done && set.is_empty() {
            break 'drive;
        }

        // Either at the concurrency ceiling, or the source is exhausted with
        // members still running. Wait for the next completion — but stay
        // responsive to cancellation while doing so.
        //
        // This deliberately does NOT use `JoinSet::join_next`, which is
        // documented as uninterruptible: it waits for a member's terminal
        // outcome so that no-orphan accounting always holds. That is the right
        // default for a caller who will eventually be satisfied, and it
        // DEADLOCKS here. An item that only terminates *because* it was
        // cancelled can never terminate while this loop is parked waiting for
        // it, because the parked loop never reaches the cancellation check and
        // therefore never reaches the drain that would cancel it. Measured, not
        // theorised: parking here burned the lab's entire 100_000-step budget
        // and came back non-quiescent
        // (tests/stream_for_each_concurrent_lab_proof.rs).
        //
        // TRADEOFF: polling cooperatively costs one wakeup per scheduler turn
        // while waiting, where parking would cost none. That is the price of
        // being cancellable, and it is the correct trade for a combinator whose
        // entire reason to exist is drain-on-cancel.
        let mut completed = None;
        loop {
            if let Some(outcome) = set.try_join_next() {
                completed = Some(outcome);
                break;
            }
            if cx.is_cancel_requested() || set.is_empty() {
                break;
            }
            yield_now().await;
        }

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
