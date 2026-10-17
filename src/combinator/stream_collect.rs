//! Ordered collection of concurrent, region-owned stream work.
//!
//! Unlike buffering plain futures, these terminals use the stream task driver:
//! non-success stops admission and cancels and joins the remaining items before
//! returning. Successes are indexed by input order, not completion order.
//!
//! Bead: asupersync-dx-core-api-v2-u1z5hn.8 (bounded stream task composition).

use crate::cx::{ChildRegionError, ChildRegionSpec, Cx};
use crate::stream::{Stream, StreamExt, try_for_each_concurrent};
use crate::types::Outcome;
use parking_lot::Mutex;
use std::convert::Infallible;
use std::future::Future;
use std::sync::Arc;

/// An item failure or failure of the explicit stream cleanup boundary.
#[derive(Debug)]
#[non_exhaustive]
pub enum ScopedStreamError<E> {
    /// An item returned an application error.
    Item(E),
    /// The runtime refused region creation or could not confirm its closure.
    Region(ChildRegionError),
    /// A finalizer or other runtime-owned cleanup operation failed.
    Cleanup(crate::error::Error),
}

impl<E: std::fmt::Display> std::fmt::Display for ScopedStreamError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Item(error) => write!(f, "stream item failed: {error}"),
            Self::Region(error) => write!(f, "stream region failed: {error}"),
            Self::Cleanup(error) => write!(f, "stream cleanup failed: {error}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for ScopedStreamError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Item(error) => Some(error),
            Self::Region(error) => Some(error),
            Self::Cleanup(error) => Some(error),
        }
    }
}

/// Executes fallible stream work inside one independently owned child region.
///
/// Unlike [`try_for_each_concurrent`], returning waits for the WHOLE work
/// subtree: direct item tasks, their descendants, and registered finalizers.
/// After direct work finishes, leftover descendants are cancelled, not allowed
/// to outlive the operation. On failure or owner cancellation the subtree is
/// cancelled BEFORE joining direct items, which may await descendant cleanup.
/// Unrelated work in the caller's region is neither cancelled nor awaited.
///
/// The existing stream driver still owns admission, wakeups, source/clone-panic
/// containment, and direct joins. `limit` bounds direct item tasks, not arbitrary
/// descendants they spawn. This adds one child region, not a coordinator task
/// or one region per item. The source may borrow and need not be `Send`.
/// Factories must use their supplied child `Cx` for work covered by this scope;
/// a captured outer context can deliberately spawn outside the boundary.
///
/// A finalizer or descendant panic wins over a direct result. Explicit finalizer
/// failure/cancellation is also reported; cancellation caused only by closing
/// leftover descendants does not replace an otherwise successful direct result.
/// Cleanup failure takes precedence over an item error. Runtime loss is a typed
/// region error, never a successful quiescence claim. The owner is checked again
/// after close so cancellation during cleanup cannot become success.
///
/// Dropping this future requests subtree close through its owned region handle;
/// it cannot synchronously wait for cleanup. Uncooperative callbacks, panicking
/// destructors and abort-on-panic builds retain the existing runtime boundaries.
/// The original shared-region stream APIs are unchanged.
///
/// # Panics
/// Panics if `limit` is zero, before opening a region or polling the source.
pub async fn try_for_each_concurrent_scoped<S, F, Fut, E>(
    cx: &Cx,
    stream: S,
    limit: usize,
    f: F,
) -> Outcome<(), ScopedStreamError<E>>
where
    S: Stream + Unpin,
    S::Item: Send + 'static,
    F: FnMut(Cx, S::Item) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Result<(), E>> + Send + 'static,
    E: Send + 'static,
{
    assert!(limit > 0, "scoped stream concurrency limit must be non-zero");
    if cx.is_cancel_requested() {
        return Outcome::Cancelled(scoped_cancel_reason(cx));
    }
    // Observe mint completion even if cancellation arrives while opening. An
    // admitted region must be owned and closed, not merely abandoned on return.
    let region = match cx.open_child_region(ChildRegionSpec::inherit()).await {
        Ok(region) => region,
        Err(error) => return Outcome::Err(ScopedStreamError::Region(error)),
    };
    let work = region.for_each_stream(cx, stream, limit, f).await;
    let close = match region.close_with_outcome().await {
        Ok(close) => close,
        Err(error) => return Outcome::Err(ScopedStreamError::Region(error)),
    };
    let outcome = scoped_outcome(work, close);
    // A cancelled owner gets its own reason back, also when the stream driver
    // saw the cancellation while items ran: the driver reports that one with a
    // generic reason, so the same cancellation read differently depending on
    // whether it landed before the call, during the run or during close.
    if matches!(outcome, Outcome::Ok(()) | Outcome::Cancelled(_)) && cx.is_cancel_requested() {
        Outcome::Cancelled(scoped_cancel_reason(cx))
    } else {
        outcome
    }
}

/// Infallible item work with the subtree cleanup contract of
/// [`try_for_each_concurrent_scoped`]. Region and cleanup failures remain typed.
///
/// # Panics
/// Panics if `limit` is zero.
pub async fn for_each_concurrent_scoped<S, F, Fut>(
    cx: &Cx,
    stream: S,
    limit: usize,
    mut f: F,
) -> Outcome<(), ScopedStreamError<Infallible>>
where
    S: Stream + Unpin,
    S::Item: Send + 'static,
    F: FnMut(Cx, S::Item) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    try_for_each_concurrent_scoped(cx, stream, limit, move |child, item| {
        let future = f(child, item);
        async move {
            future.await;
            Ok(())
        }
    })
    .await
}

fn scoped_cancel_reason(cx: &Cx) -> crate::types::CancelReason {
    cx.cancel_reason().unwrap_or_else(|| {
        crate::types::CancelReason::user("scoped stream owner cancelled")
    })
}

pub(super) fn scoped_outcome<E>(
    work: Outcome<(), E>,
    close: crate::record::region::RegionCloseOutcome,
) -> Outcome<(), ScopedStreamError<E>> {
    // The region's aggregate includes cancellations we deliberately requested.
    // Its separate finalizer outcome distinguishes failed cleanup from that
    // expected consequence. Descendant panics must still be surfaced,
    // including one in a nested region, which reaches this region's receipt
    // apart from its own outcome (br-asupersync-b834ta).
    let cleanup = match (close.cleanup_outcome, close.descendant_panic) {
        (Some(Outcome::Panicked(payload)), _) | (_, Some(payload)) => {
            Some(Outcome::Panicked(payload))
        }
        (cleanup, None) => cleanup,
    };
    match (work, close.outcome, cleanup) {
        (_, _, Some(Outcome::Panicked(payload)))
        | (_, Outcome::Panicked(payload), _)
        | (Outcome::Panicked(payload), _, _) => Outcome::Panicked(payload),
        (_, _, Some(Outcome::Cancelled(reason))) => Outcome::Cancelled(reason),
        (_, _, Some(Outcome::Err(error))) => Outcome::Err(ScopedStreamError::Cleanup(error)),
        (Outcome::Ok(()), Outcome::Err(error), _) => {
            Outcome::Err(ScopedStreamError::Cleanup(error))
        }
        (Outcome::Ok(()), _, _) => Outcome::Ok(()),
        (Outcome::Err(error), _, _) => Outcome::Err(ScopedStreamError::Item(error)),
        (Outcome::Cancelled(reason), _, _) => Outcome::Cancelled(reason),
    }
}

/// Maps a stream concurrently and collects results in input order.
///
/// Each item runs as a region-owned task. At most `limit` items run at once;
/// successful values are retained until the complete collection is returned.
/// This bounds concurrent work, NOT total result memory: a finite source with
/// N items retains O(N) values. Bound an untrusted source with `StreamExt::take`
/// or use `for_each_concurrent` when its results need not be retained.
///
/// The factory is cloned per admitted item, as with `for_each_concurrent`.
/// Neither input nor output values need to be `Clone`. The source itself may
/// borrow caller state and need not be `Send`; the item tasks are `Send + 'static`.
/// A result must remain valid after its item task exits: returning a value does
/// not transfer a runtime obligation's holder liability to the collecting task.
///
/// Cancellation and panics are still possible with an infallible item function.
/// For fallible work, use [`try_map_collect_concurrent`].
///
/// # Panics
/// Panics if `limit` is zero.
pub async fn map_collect_concurrent<S, F, Fut, T>(
    cx: &Cx,
    stream: S,
    limit: usize,
    mut f: F,
) -> Outcome<Vec<T>, Infallible>
where
    S: Stream + Unpin,
    S::Item: Send + 'static,
    F: FnMut(Cx, S::Item) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    try_map_collect_concurrent(cx, stream, limit, move |item_cx, item| {
        let future = f(item_cx, item);
        async move { Ok(future.await) }
    })
    .await
}

/// Maps fallible work concurrently, returning ordered results only on success.
///
/// Input-order output does not impose input-order failure observation. The
/// first non-success observed by `try_for_each_concurrent` stops admission;
/// all remaining members are cancelled and joined. A panic during that drain
/// takes precedence over the initiating failure. Completed successes are
/// discarded after drain on failure, rather than returned as a partial success.
///
/// A slow early item does not prevent later completions from freeing task slots.
/// Only short result-placement sections are synchronized; no user factory,
/// asynchronous work, or result destructor is deliberately invoked under that
/// lock. The existing stream driver supplies wakeups and cooperative admission
/// yields; this adapter starts no separate coordinator task.
///
/// Dropping the collecting future requests cancellation through its JoinSet;
/// it cannot synchronously join tasks. The enclosing region remains the final
/// cleanup barrier after abandonment. Effects already committed by successful
/// item tasks are not rolled back. Returned resource-bearing values need their
/// own lifetime/transfer contract, just as for a direct task join.
///
/// ```no_run
/// # async fn example(cx: &asupersync::Cx) {
/// use asupersync::combinator::stream_collect::try_map_collect_concurrent;
/// use asupersync::stream::iter;
/// use asupersync::Outcome;
/// let result = try_map_collect_concurrent(cx, iter([3, 1, 2]), 2,
///     |_item_cx, n| async move { Ok::<_, &'static str>(n * 10) }).await;
/// assert!(matches!(result, Outcome::Ok(values) if values == [30, 10, 20]));
/// # }
/// ```
///
/// # Panics
/// Panics if `limit` is zero. Unwinding panics from source polling or factory
/// cloning are instead reported as `Panicked` after draining owned tasks.
/// Panicking destructors and abort-on-panic builds remain outside that guarantee.
pub async fn try_map_collect_concurrent<S, F, Fut, T, E>(
    cx: &Cx,
    stream: S,
    limit: usize,
    mut f: F,
) -> Outcome<Vec<T>, E>
where
    S: Stream + Unpin,
    S::Item: Send + 'static,
    F: FnMut(Cx, S::Item) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Result<T, E>> + Send + 'static,
    T: Send + 'static,
    E: Send + 'static,
{
    let results = Results::new();
    let writer = results.clone();
    let outcome = try_for_each_concurrent(cx, stream.enumerate(), limit, move |item_cx, (index, item)| {
        let writer = writer.clone();
        let future = f(item_cx, item);
        async move {
            writer.store(index, future.await?);
            Ok(())
        }
    })
    .await;
    results.finish(outcome)
}

/// Maps and collects in source order, then closes the complete work subtree.
///
/// This combines [`try_map_collect_concurrent`]'s ordering with
/// [`try_for_each_concurrent_scoped`]'s descendant/finalizer barrier. Successful
/// values stay owned by the collector during cleanup. They are returned only
/// if both direct work and cleanup succeed; otherwise they are dropped AFTER
/// cleanup, outside the result lock. A successful mapper cannot hide a later
/// descendant or finalizer panic behind its already-staged value.
///
/// `limit` bounds direct tasks, not result memory or descendants: N successful
/// inputs retain O(N) values. Returned values must remain valid after their
/// item's task AND this operation's region have closed. Returning a value does
/// not transfer live obligations or extend a region-owned resource's lifetime.
/// Dropping this future requests subtree close but cannot synchronously drain.
///
/// ```no_run
/// # async fn example(cx: &asupersync::Cx) {
/// use asupersync::combinator::stream_collect::try_map_collect_concurrent_scoped;
/// use asupersync::stream::iter;
/// use asupersync::Outcome;
/// let result = try_map_collect_concurrent_scoped(cx, iter([3, 1, 2]), 2,
///     |_child, n| async move { Ok::<_, &'static str>(n * 10) }).await;
/// assert!(matches!(result, Outcome::Ok(values) if values == [30, 10, 20]));
/// # }
/// ```
///
/// # Panics
/// Panics if `limit` is zero. Source/clone unwind containment and cleanup
/// precedence follow [`try_for_each_concurrent_scoped`].
pub async fn try_map_collect_concurrent_scoped<S, F, Fut, T, E>(
    cx: &Cx,
    stream: S,
    limit: usize,
    mut f: F,
) -> Outcome<Vec<T>, ScopedStreamError<E>>
where
    S: Stream + Unpin,
    S::Item: Send + 'static,
    F: FnMut(Cx, S::Item) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Result<T, E>> + Send + 'static,
    T: Send + 'static,
    E: Send + 'static,
{
    let results = Results::new();
    let writer = results.clone();
    let outcome = try_for_each_concurrent_scoped(
        cx,
        stream.enumerate(),
        limit,
        move |child, (index, item)| {
            let writer = writer.clone();
            let future = f(child, item);
            async move {
                writer.store(index, future.await?);
                Ok(())
            }
        },
    ).await;
    results.finish(outcome)
}

/// Infallible mapping with ordered results and complete subtree cleanup.
///
/// See [`try_map_collect_concurrent_scoped`] for result lifetime and memory
/// bounds. Runtime admission and cleanup can fail even if mapping is infallible.
///
/// # Panics
/// Panics if `limit` is zero.
pub async fn map_collect_concurrent_scoped<S, F, Fut, T>(
    cx: &Cx,
    stream: S,
    limit: usize,
    mut f: F,
) -> Outcome<Vec<T>, ScopedStreamError<Infallible>>
where
    S: Stream + Unpin,
    S::Item: Send + 'static,
    F: FnMut(Cx, S::Item) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    try_map_collect_concurrent_scoped(cx, stream, limit, move |child, item| {
        let future = f(child, item);
        async move { Ok(future.await) }
    }).await
}

// Both collection modes use this one result-placement and retirement path.
// Cloning the handle shares storage; it never adds a Clone bound to T.
struct Results<T>(Arc<Mutex<Vec<Option<T>>>>);

impl<T> Clone for Results<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<T> Results<T> {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(Vec::new())))
    }

    fn store(&self, index: usize, value: T) {
        let mut slots = self.0.lock();
        if slots.len() <= index {
            slots.resize_with(index.checked_add(1).expect("stream result index overflow"), || None);
        }
        // Each source index is admitted once. Never overwrite a previous T.
        assert!(slots[index].is_none(), "duplicate stream result index");
        slots[index] = Some(value);
    }

    fn finish<E>(self, outcome: Outcome<(), E>) -> Outcome<Vec<T>, E> {
        // No user destructor may run under the result lock. Callers finish only
        // after their selected task-only or full-subtree barrier has resolved.
        let slots = std::mem::take(&mut *self.0.lock());
        match outcome {
            Outcome::Ok(()) => Outcome::Ok(slots.into_iter().map(|slot| {
                slot.expect("successful stream collection has every admitted result")
            }).collect()),
            Outcome::Err(error) => Outcome::Err(error),
            Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => Outcome::Panicked(payload),
        }
    }
}

#[cfg(test)]
#[path = "stream_collect_inline_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "stream_collect_scoped_tests_inline_tests.rs"]
mod scoped_tests;
