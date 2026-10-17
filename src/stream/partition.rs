//! Splits one stream into two by a predicate.
//!
//! [`partition`] returns two streams sharing a single source: items matching
//! the predicate go to the first, the rest to the second. The source is pulled
//! exactly once per item — this is a split, not a tee, so no item is
//! duplicated and the predicate runs once per item.

use super::Stream;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

/// Cooperative budget for items routed in a single poll.
///
/// Without this cap, a stream whose items nearly all belong to the *other* lane
/// would let one `poll_next` call route unboundedly many items before yielding.
const PARTITION_COOPERATIVE_BUDGET: usize = 1024;

/// Which half of a partition a value belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lane {
    /// Predicate returned `true`.
    Matched,
    /// Predicate returned `false`.
    Unmatched,
}

impl Lane {
    #[inline]
    const fn other(self) -> Self {
        match self {
            Self::Matched => Self::Unmatched,
            Self::Unmatched => Self::Matched,
        }
    }
}

struct PartitionInner<S: Stream, P> {
    stream: S,
    predicate: P,
    matched: VecDeque<S::Item>,
    unmatched: VecDeque<S::Item>,
    capacity: usize,
    done: bool,
    matched_waker: Option<Waker>,
    unmatched_waker: Option<Waker>,
    matched_dropped: bool,
    unmatched_dropped: bool,
}

impl<S: Stream, P> PartitionInner<S, P> {
    #[inline]
    fn queue(&mut self, lane: Lane) -> &mut VecDeque<S::Item> {
        match lane {
            Lane::Matched => &mut self.matched,
            Lane::Unmatched => &mut self.unmatched,
        }
    }

    #[inline]
    fn len_of(&self, lane: Lane) -> usize {
        match lane {
            Lane::Matched => self.matched.len(),
            Lane::Unmatched => self.unmatched.len(),
        }
    }

    #[inline]
    fn is_dropped(&self, lane: Lane) -> bool {
        match lane {
            Lane::Matched => self.matched_dropped,
            Lane::Unmatched => self.unmatched_dropped,
        }
    }

    #[inline]
    fn take_waker(&mut self, lane: Lane) -> Option<Waker> {
        match lane {
            Lane::Matched => self.matched_waker.take(),
            Lane::Unmatched => self.unmatched_waker.take(),
        }
    }

    #[inline]
    fn register_waker(&mut self, lane: Lane, waker: &Waker) {
        let slot = match lane {
            Lane::Matched => &mut self.matched_waker,
            Lane::Unmatched => &mut self.unmatched_waker,
        };
        match slot {
            Some(existing) if existing.will_wake(waker) => {}
            _ => *slot = Some(waker.clone()),
        }
    }
}

/// One half of a [`partition`].
///
/// Created by [`partition`]; see that function for the backpressure contract.
#[must_use = "streams do nothing unless polled"]
pub struct Partition<S: Stream, P> {
    inner: Arc<Mutex<PartitionInner<S, P>>>,
    lane: Lane,
}

impl<S: Stream, P> fmt::Debug for Partition<S, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = self.inner.lock();
        f.debug_struct("Partition")
            .field("lane", &self.lane)
            .field("buffered", &inner.len_of(self.lane))
            .field("peer_buffered", &inner.len_of(self.lane.other()))
            .field("capacity", &inner.capacity)
            .field("done", &inner.done)
            .finish_non_exhaustive()
    }
}

impl<S: Stream, P> Partition<S, P> {
    /// Number of items buffered for this half and not yet yielded.
    #[must_use]
    pub fn buffered_len(&self) -> usize {
        self.inner.lock().len_of(self.lane)
    }

    /// Number of items buffered for the *other* half.
    ///
    /// This is the backpressure signal: once it reaches the configured
    /// capacity, this half stops pulling from the source until the peer drains.
    #[must_use]
    pub fn peer_buffered_len(&self) -> usize {
        self.inner.lock().len_of(self.lane.other())
    }
}

impl<S: Stream, P> Drop for Partition<S, P> {
    fn drop(&mut self) {
        let mut inner = self.inner.lock();
        match self.lane {
            Lane::Matched => {
                inner.matched_dropped = true;
                inner.matched.clear();
            }
            Lane::Unmatched => {
                inner.unmatched_dropped = true;
                inner.unmatched.clear();
            }
        }
        // The surviving half may be parked on this lane's capacity. Once this
        // half is gone its items are discarded instead of buffered, so the
        // capacity stall is over and the peer must be re-polled.
        let peer = inner.take_waker(self.lane.other());
        drop(inner);
        if let Some(waker) = peer {
            waker.wake();
        }
    }
}

impl<S, P> Stream for Partition<S, P>
where
    S: Stream + Unpin,
    P: FnMut(&S::Item) -> bool,
{
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let lane = self.lane;
        let peer = lane.other();
        let mut inner = self.inner.lock();

        let mut routed_this_poll = 0usize;
        loop {
            // 1. Own buffer first: it is already routed and ordered. Bound the
            //    pop to its own statement so the `&mut` borrow of `inner` ends
            //    before the body touches `inner` again.
            let own = inner.queue(lane).pop_front();
            if let Some(item) = own {
                // Yielding frees a slot in THIS lane, which may be what the
                // peer was stalled on.
                let peer_waker = inner.take_waker(peer);
                drop(inner);
                if let Some(waker) = peer_waker {
                    waker.wake();
                }
                return Poll::Ready(Some(item));
            }

            if inner.done {
                return Poll::Ready(None);
            }

            // 2. Backpressure. If the peer's buffer is full we must not pull,
            //    because the next item might belong to it and we would have
            //    nowhere to put it. A dropped peer is exempt: its items are
            //    discarded, so it can never stall us.
            if !inner.is_dropped(peer) && inner.len_of(peer) >= inner.capacity {
                inner.register_waker(lane, cx.waker());
                let peer_waker = inner.take_waker(peer);
                drop(inner);
                if let Some(waker) = peer_waker {
                    waker.wake();
                }
                return Poll::Pending;
            }

            // 3. Cooperative yield so one poll cannot route unboundedly many
            //    peer-bound items.
            if routed_this_poll >= PARTITION_COOPERATIVE_BUDGET {
                inner.register_waker(lane, cx.waker());
                drop(inner);
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }

            // 4. Pull one item from the shared source.
            let polled = {
                let inner = &mut *inner;
                Pin::new(&mut inner.stream).poll_next(cx)
            };
            match polled {
                Poll::Ready(Some(item)) => {
                    routed_this_poll += 1;
                    let target = {
                        let inner = &mut *inner;
                        if (inner.predicate)(&item) {
                            Lane::Matched
                        } else {
                            Lane::Unmatched
                        }
                    };
                    if target == lane {
                        let peer_waker = inner.take_waker(peer);
                        drop(inner);
                        if let Some(waker) = peer_waker {
                            waker.wake();
                        }
                        return Poll::Ready(Some(item));
                    }
                    // Peer-bound. Drop it on the floor if the peer is gone,
                    // otherwise buffer it and make sure the peer is awake.
                    if inner.is_dropped(target) {
                        continue;
                    }
                    inner.queue(target).push_back(item);
                    if let Some(waker) = inner.take_waker(target) {
                        waker.wake();
                    }
                }
                Poll::Ready(None) => {
                    inner.done = true;
                    // End-of-source is news for the peer too: it may be parked
                    // waiting for items that will now never arrive.
                    let peer_waker = inner.take_waker(peer);
                    drop(inner);
                    if let Some(waker) = peer_waker {
                        waker.wake();
                    }
                    return Poll::Ready(None);
                }
                Poll::Pending => {
                    // The source registered `cx.waker()`, which belongs to THIS
                    // half. The peer is parked on its own waker and would not
                    // be woken by the source, so leave ours registered here too
                    // and let whichever half is polled next drive the source.
                    inner.register_waker(lane, cx.waker());
                    return Poll::Pending;
                }
            }
        }
    }
}

/// Splits `stream` into two streams by `predicate`.
///
/// The first returned stream yields items for which `predicate` returned
/// `true`; the second yields the rest. The predicate runs exactly once per
/// item, and each item is delivered to exactly one half.
///
/// # Backpressure contract
///
/// The two halves share one source, so whichever half is polled pulls for
/// both. An item destined for the *other* half is buffered for it. That buffer
/// is bounded by `lane_capacity`:
///
/// - While the peer's buffer holds fewer than `lane_capacity` items, a poll on
///   this half keeps pulling until it finds an item of its own.
/// - Once the peer's buffer is **full**, this half returns `Poll::Pending`
///   without pulling, and wakes the peer. It resumes as soon as the peer
///   consumes an item.
///
/// # Head-of-line rule
///
/// That is a real head-of-line coupling and it is deliberate: a slow consumer
/// on one half throttles the other half rather than growing an unbounded
/// buffer. **Both halves must be consumed** — if one is only held and never
/// polled, the other stalls permanently once `lane_capacity` items accumulate
/// for it.
///
/// The escape hatch is dropping. A dropped half is exempt from the rule: its
/// pending items are discarded and further items destined for it are dropped on
/// the floor, so the surviving half runs at full speed. Drop the half you do
/// not want rather than leaving it unpolled.
///
/// # Wakeup rule (why "must be consumed" is a real requirement)
///
/// Only one half drives the shared source at a time, and the source registers
/// the waker of whichever half polled it last. A half is therefore woken by
/// exactly three events:
///
/// 1. the driving half routes an item into its buffer,
/// 2. the driving half observes end-of-source,
/// 3. the peer half is dropped, or yields an item and so frees a capacity slot.
///
/// All three are driven by the *other* half being polled. That is why a half
/// which is held but never polled can strand its peer: it is the peer's only
/// source of wakeups once it has been superseded as the source's registrant.
/// Consuming both halves — or dropping the one you do not want — satisfies the
/// rule in every case.
///
/// # Example
///
/// ```ignore
/// use asupersync::stream::{iter, partition};
///
/// // `retries` and `dead` share one source; each record is routed once.
/// let (mut retries, mut dead) = partition(iter(records), |r: &Record| r.retryable, 32);
/// // Both halves must be consumed - see the head-of-line rule above.
/// # struct Record { retryable: bool }
/// # let records: Vec<Record> = Vec::new();
/// ```
///
/// # Panics
///
/// Panics if `lane_capacity` is zero: with no buffer, an item destined for the
/// peer could never be stored and the split could not make progress.
pub fn partition<S, P>(
    stream: S,
    predicate: P,
    lane_capacity: usize,
) -> (Partition<S, P>, Partition<S, P>)
where
    S: Stream + Unpin,
    P: FnMut(&S::Item) -> bool,
{
    assert!(
        lane_capacity > 0,
        "partition lane_capacity must be non-zero; a zero-capacity lane cannot buffer a peer-bound item"
    );
    let inner = Arc::new(Mutex::new(PartitionInner {
        stream,
        predicate,
        matched: VecDeque::new(),
        unmatched: VecDeque::new(),
        capacity: lane_capacity,
        done: false,
        matched_waker: None,
        unmatched_waker: None,
        matched_dropped: false,
        unmatched_dropped: false,
    }));
    (
        Partition {
            inner: Arc::clone(&inner),
            lane: Lane::Matched,
        },
        Partition {
            inner,
            lane: Lane::Unmatched,
        },
    )
}

#[cfg(test)]
#[path = "partition_inline_tests.rs"]
mod tests;
