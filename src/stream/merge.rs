//! Merge combinator for streams.
//!
//! The `Merge` combinator interleaves items from multiple streams, polling
//! them in round-robin order.

use super::Stream;
use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Wake, Waker};

/// Cooperative budget for child-stream scans in a single poll.
///
/// Without this bound, a large merge set can monopolize one executor turn
/// while `Merge` walks every child looking for a ready item.
const MERGE_COOPERATIVE_POLL_BUDGET: usize = 64;

/// A stream that merges multiple streams.
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct Merge<S> {
    streams: VecDeque<S>,
    /// Round-robin cursor for fair polling without moving elements.
    next_index: usize,
    /// Records child wakes and forwards them to the task; the children are
    /// polled with [`Self::child_waker`], made from it.
    child_wake: Arc<ChildWake>,
    child_waker: Waker,
    /// Count of child streams that have returned `Pending` (and therefore
    /// registered [`Self::child_waker`]) since the last progress or child wake.
    ///
    /// A cooperative-budget yield re-wakes the task to continue scanning only
    /// while this is below the live child count. Once every remaining child has
    /// registered the current waker, the combinator parks WITHOUT a self-wake:
    /// a self-wake at that point would busy-loop at 100% CPU because no scan can
    /// make progress until a child fires. Mirrors the `Buffered` epoch gate.
    pending_registered: usize,
}

impl<S> Merge<S> {
    /// Creates a new `Merge` from the given streams.
    #[inline]
    pub(crate) fn new(streams: impl IntoIterator<Item = S>) -> Self {
        let child_wake = Arc::new(ChildWake::default());
        Self {
            streams: streams.into_iter().collect(),
            next_index: 0,
            child_waker: Waker::from(Arc::clone(&child_wake)),
            child_wake,
            pending_registered: 0,
        }
    }

    /// Returns the number of active streams.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.streams.len()
    }

    /// Returns true if there are no active streams.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.streams.is_empty()
    }

    /// Returns a reference to the active streams.
    #[inline]
    #[must_use]
    pub fn get_ref(&self) -> &VecDeque<S> {
        &self.streams
    }

    /// Returns a mutable reference to the active streams.
    #[inline]
    pub fn get_mut(&mut self) -> &mut VecDeque<S> {
        &mut self.streams
    }

    /// Consumes the combinator, returning the remaining streams.
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> VecDeque<S> {
        self.streams
    }
}

impl<S: Unpin> Unpin for Merge<S> {}

/// The waker a [`Merge`]'s children are polled with: it records that a child
/// woke the merge, then wakes the merge's task.
#[derive(Debug, Default)]
struct ChildWake {
    woken: AtomicBool,
    task: parking_lot::Mutex<Option<Waker>>,
}

impl ChildWake {
    fn set_task(&self, waker: &Waker) {
        let mut task = self.task.lock();
        if !task
            .as_ref()
            .is_some_and(|current| current.will_wake(waker))
        {
            *task = Some(waker.clone());
        }
    }
}

impl Wake for ChildWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.woken.store(true, Ordering::Release);
        let task = self.task.lock().clone();
        if let Some(task) = task {
            task.wake();
        }
    }
}

impl<S> Stream for Merge<S>
where
    S: Stream + Unpin,
{
    type Item = S::Item;

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let initial_len = this.streams.len();
        if initial_len == 0 {
            return Poll::Ready(None);
        }

        // The children always get `child_waker`, which forwards to the
        // current task waker, so a migrated task needs no re-sweep. A child
        // wake does: the woken child may sit outside the window this poll can
        // scan, or have been scanned earlier in this sweep, so every child is
        // polled again before the merge may park (br-asupersync-jqhteu).
        this.child_wake.set_task(cx.waker());
        if this.child_wake.woken.swap(false, Ordering::AcqRel) {
            this.pending_registered = 0;
        }
        let mut child_cx = Context::from_waker(&this.child_waker);

        let start = this.next_index.min(initial_len.saturating_sub(1));
        // Track how many original streams we've visited (removals don't reduce the budget).
        let mut remaining = initial_len;
        let mut i = start;
        let mut scanned_this_poll = 0usize;

        while remaining > 0 {
            let len = this.streams.len();
            if len == 0 {
                return Poll::Ready(None);
            }
            if i >= len {
                i = 0;
            }

            match Pin::new(&mut this.streams[i]).poll_next(&mut child_cx) {
                Poll::Ready(Some(item)) => {
                    let new_len = this.streams.len();
                    this.next_index = if i + 1 >= new_len { 0 } else { i + 1 };
                    // Progress: a delivered item invalidates the pending-sweep
                    // count so the next poll re-registers before it may park.
                    this.pending_registered = 0;
                    return Poll::Ready(Some(item));
                }
                Poll::Ready(None) => {
                    // Stream exhausted; remove it. The active set changed, so the
                    // pending-registration invariant no longer holds — reset.
                    this.streams.remove(i);
                    this.pending_registered = 0;
                    remaining -= 1;
                    scanned_this_poll += 1;
                    if scanned_this_poll >= MERGE_COOPERATIVE_POLL_BUDGET && remaining > 0 {
                        this.next_index = if this.streams.is_empty() {
                            0
                        } else {
                            i % this.streams.len()
                        };
                        // Removals are progress (the set shrinks toward empty),
                        // so continuing next tick terminates; this self-wake is
                        // bounded and safe.
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    // i now points at the next element (shifted into this slot), don't advance.
                    continue;
                }
                Poll::Pending => {
                    // This child registered the current waker; record it so the
                    // combinator can park once every live child has registered.
                    this.pending_registered = this.pending_registered.saturating_add(1);
                }
            }
            remaining -= 1;
            scanned_this_poll += 1;
            if scanned_this_poll >= MERGE_COOPERATIVE_POLL_BUDGET && remaining > 0 {
                this.next_index = if this.streams.is_empty() {
                    0
                } else {
                    (i + 1) % this.streams.len()
                };
                // Only yield-and-rewake while there is still an unregistered
                // child to scan. Once every live child has registered the
                // current waker, a self-wake would busy-loop at 100% CPU with no
                // possible progress, so park and rely on the children's wakers.
                if this.pending_registered < this.streams.len() {
                    cx.waker().wake_by_ref();
                }
                return Poll::Pending;
            }
            i += 1;
        }

        this.next_index = if this.streams.is_empty() {
            0
        } else {
            i % this.streams.len()
        };
        if this.streams.is_empty() {
            Poll::Ready(None)
        } else {
            Poll::Pending
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let mut lower = 0usize;
        let mut upper = Some(0usize);

        for stream in &self.streams {
            let (l, u) = stream.size_hint();
            lower = lower.saturating_add(l);
            upper = match (upper, u) {
                (Some(total), Some(v)) => total.checked_add(v),
                _ => None,
            };
        }

        (lower, upper)
    }
}

/// Merge multiple streams into a single stream.
#[inline]
pub fn merge<S>(streams: impl IntoIterator<Item = S>) -> Merge<S>
where
    S: Stream,
{
    Merge::new(streams)
}

#[cfg(test)]
#[path = "merge_inline_tests.rs"]
mod tests;
