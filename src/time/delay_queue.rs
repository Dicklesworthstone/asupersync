//! A queue of values that each come due at their own deadline.
//!
//! [`DelayQueue`] holds values with deadlines and yields each one as an
//! [`Expired`] once its deadline passes, earliest first. Entries can be
//! removed or given a new deadline through the [`Key`] returned at insertion.
//! It is the building block for expiring cache entries, session idle
//! timeouts, retry schedules and per-request deadlines, with one timer for the
//! whole queue instead of one task per entry.
//!
//! The stream API uses the same clock as [`Sleep`]: the runtime's timer driver
//! (virtual time under the lab runtime), or the wall clock outside one. For
//! explicit time authority and cancellation that retains unconsumed values,
//! use [`DelayQueue::next_expired`] with deadlines from the supplied context.

use crate::cx::{Cx, cap::HasTime};
use crate::stream::Stream;
use crate::time::{Sleep, wall_now};
use crate::types::{CancelReason, Time};
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

/// Source of entry generations for every queue.
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(0);

/// Identifies an entry of a [`DelayQueue`] for [`DelayQueue::remove`] and
/// [`DelayQueue::reset`]. A key stops being valid when its entry expires or is
/// removed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Key {
    index: usize,
    generation: u64,
}

/// A value whose deadline passed, or that was removed from the queue.
#[derive(Debug)]
pub struct Expired<T> {
    data: T,
    deadline: Time,
    key: Key,
}

impl<T> Expired<T> {
    /// The value.
    pub fn get_ref(&self) -> &T {
        &self.data
    }

    /// The value, mutably.
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Takes the value.
    pub fn into_inner(self) -> T {
        self.data
    }

    /// The deadline the entry had.
    #[must_use]
    pub const fn deadline(&self) -> Time {
        self.deadline
    }

    /// The key the entry had; no longer valid.
    #[must_use]
    pub const fn key(&self) -> Key {
        self.key
    }
}

/// A context-driven expiry wait could not complete.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum DelayQueueNextError {
    /// Cancellation was acknowledged without removing a queued value.
    Cancelled(CancelReason),
    /// A nonempty queue requires the supplied context's authorized timer.
    TimerUnavailable,
}

impl fmt::Display for DelayQueueNextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled(reason) => write!(f, "delay queue wait cancelled: {reason:?}"),
            Self::TimerUnavailable => {
                f.write_str("delay queue wait requires time capability and a timer driver")
            }
        }
    }
}

impl std::error::Error for DelayQueueNextError {}

impl DelayQueueNextError {
    fn cancelled<Caps>(cx: &Cx<Caps>) -> Self {
        Self::Cancelled(
            cx.cancel_reason()
                .unwrap_or_else(|| CancelReason::user("delay queue wait cancelled")),
        )
    }
}

struct Entry<T> {
    data: T,
    deadline: Time,
    /// Fixed at insertion; a [`Key`] is valid while it matches.
    generation: u64,
    /// Changes on every reset; matches exactly one live heap item, and the
    /// others for this slot are stale.
    schedule: u64,
}

/// A queue of values with deadlines; see the [module documentation](self).
///
/// Poll it with [`Self::poll_expired`] or as a [`Stream`]. Polling an empty
/// queue returns `Ready(None)`; values inserted afterwards are yielded by
/// later polls.
///
/// ```
/// use asupersync::runtime::RuntimeBuilder;
/// use asupersync::stream::StreamExt;
/// use asupersync::time::DelayQueue;
/// use std::time::Duration;
///
/// let runtime = RuntimeBuilder::current_thread().build().unwrap();
/// runtime.block_on(async {
///     let mut queue = DelayQueue::new();
///     queue.insert("later", Duration::from_millis(30));
///     let soon = queue.insert("soon", Duration::from_millis(10));
///     queue.insert("dropped", Duration::from_millis(20));
///     queue.reset(&soon, Duration::from_millis(5));
///
///     let first = queue.next().await.unwrap().into_inner();
///     let second = queue.next().await.unwrap().into_inner();
///     assert_eq!((first, second), ("soon", "dropped"));
///     assert_eq!(queue.len(), 1);
/// });
/// ```
pub struct DelayQueue<T> {
    entries: slab::Slab<Entry<T>>,
    /// Earliest deadline first; ties in insertion order.
    heap: BinaryHeap<Reverse<(Time, u64, usize)>>,
    timer: Option<Sleep>,
    /// The deadline `timer` is armed for.
    armed_for: Option<Time>,
    /// The task last parked on `timer`, woken when an earlier entry arrives.
    waker: Option<Waker>,
}

impl<T> DelayQueue<T> {
    /// An empty queue.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(0)
    }

    /// An empty queue with room for `capacity` entries.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: slab::Slab::with_capacity(capacity),
            heap: BinaryHeap::with_capacity(capacity),
            timer: None,
            armed_for: None,
            waker: None,
        }
    }

    /// Inserts `value`, due `timeout` from now.
    pub fn insert(&mut self, value: T, timeout: Duration) -> Key {
        self.insert_at(value, deadline_after(timeout))
    }

    /// Inserts `value`, due at `deadline`.
    pub fn insert_at(&mut self, value: T, deadline: Time) -> Key {
        let generation = Self::bump_generation();
        let index = self.entries.insert(Entry {
            data: value,
            deadline,
            generation,
            schedule: generation,
        });
        self.schedule(deadline, generation, index);
        Key { index, generation }
    }

    /// Removes the entry for `key`.
    ///
    /// # Panics
    ///
    /// Panics when `key` is not valid in this queue; [`Self::try_remove`]
    /// reports that instead.
    #[track_caller]
    pub fn remove(&mut self, key: &Key) -> Expired<T> {
        self.try_remove(key)
            .expect("DelayQueue::remove: the key is not valid in this queue")
    }

    /// Removes the entry for `key`, or returns `None` when the key is not
    /// valid (its entry expired or was removed).
    pub fn try_remove(&mut self, key: &Key) -> Option<Expired<T>> {
        let generation = self.live_generation(key)?;
        let entry = self.entries.remove(key.index);
        // Its heap item is now stale and is skipped when it surfaces.
        Some(Expired {
            data: entry.data,
            deadline: entry.deadline,
            key: Key {
                index: key.index,
                generation,
            },
        })
    }

    /// Moves the entry for `key` to be due `timeout` from now.
    ///
    /// # Panics
    ///
    /// Panics when `key` is not valid in this queue.
    #[track_caller]
    pub fn reset(&mut self, key: &Key, timeout: Duration) {
        self.reset_at(key, deadline_after(timeout));
    }

    /// Moves the entry for `key` to be due at `deadline`.
    ///
    /// The key stays valid.
    ///
    /// # Panics
    ///
    /// Panics when `key` is not valid in this queue.
    #[track_caller]
    pub fn reset_at(&mut self, key: &Key, deadline: Time) {
        assert!(
            self.live_generation(key).is_some(),
            "DelayQueue::reset: the key is not valid in this queue"
        );
        let schedule = Self::bump_generation();
        let entry = &mut self.entries[key.index];
        entry.deadline = deadline;
        entry.schedule = schedule;
        self.schedule(deadline, schedule, key.index);
    }

    /// The deadline of the entry for `key`.
    ///
    /// # Panics
    ///
    /// Panics when `key` is not valid in this queue.
    #[track_caller]
    #[must_use]
    pub fn deadline(&self, key: &Key) -> Time {
        assert!(
            self.live_generation(key).is_some(),
            "DelayQueue::deadline: the key is not valid in this queue"
        );
        self.entries[key.index].deadline
    }

    /// Whether `key` still names an entry of this queue.
    #[must_use]
    pub fn contains(&self, key: &Key) -> bool {
        self.live_generation(key).is_some()
    }

    /// The number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the queue has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Removes every entry.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.heap.clear();
        self.timer = None;
        self.armed_for = None;
    }

    /// Waits for and removes the earliest expired value using `cx`'s timer.
    ///
    /// Returns `Ok(None)` immediately for an empty queue. The mutable borrow
    /// prevents concurrent insertion during this wait; after it returns or is
    /// dropped, entries may be inserted, removed, or reset normally. Equal
    /// deadlines retain the queue's existing scheduling order.
    ///
    /// Deadlines must belong to the supplied context's clock domain. Use
    /// [`Self::insert_at`] and [`Self::reset_at`] with that clock when the
    /// context differs from the ambient runtime. This API captures the
    /// authorized driver and never falls back to a wall clock or timer thread.
    ///
    /// Cancellation, including the context's deadline, is checked before a
    /// value is removed and respects cancellation masks. Dropping a pending
    /// future unregisters its timer and retains every value and key, including
    /// an expiry whose timer fired but whose value was not yet returned. One
    /// timer covers the whole queue. Starting this wait retires any timer and
    /// waker retained by an earlier [`Self::poll_expired`] call.
    ///
    /// # Errors
    ///
    /// Returns [`DelayQueueNextError::Cancelled`] when cancellation is
    /// acknowledged, even if an entry is already due or the queue is empty.
    /// A nonempty queue without an authorized timer returns
    /// [`DelayQueueNextError::TimerUnavailable`] without removing a value.
    /// The existing stream and polling APIs retain their cancellation-blind
    /// behavior.
    pub async fn next_expired<Caps>(
        &mut self,
        cx: &Cx<Caps>,
    ) -> Result<Option<Expired<T>>, DelayQueueNextError>
    where
        Caps: HasTime,
    {
        // No previous stream poll remains live while this method holds &mut
        // self. Detach its registrations before any early refusal, and clear
        // the metadata before dropping a user-owned waker. New registrations
        // belong to this future rather than the queue, so dropping the wait
        // releases them without removing data.
        let previous_timer = self.timer.take();
        self.armed_for = None;
        let previous_waker = self.waker.take();
        drop((previous_timer, previous_waker));
        cx.checkpoint()
            .map_err(|_| DelayQueueNextError::cancelled(cx))?;
        if self.entries.is_empty() {
            return Ok(None);
        }
        let driver = cx
            .timer_driver()
            .ok_or(DelayQueueNextError::TimerUnavailable)?;
        let mut cancelled = std::pin::pin!(cx.cancelled());

        loop {
            let now = driver.now();
            cx.checkpoint()
                .map_err(|_| DelayQueueNextError::cancelled(cx))?;
            let Some((deadline, _, index)) = self.next_live_entry() else {
                return Ok(None);
            };
            if deadline <= now {
                self.heap.pop();
                let entry = self.entries.remove(index);
                return Ok(Some(Expired {
                    data: entry.data,
                    deadline,
                    key: Key {
                        index,
                        generation: entry.generation,
                    },
                }));
            }

            // Expired masked deadlines must not become permanently ready
            // timers. The still-future entry deadline remains a wake source.
            let wake_at = cx
                .budget()
                .deadline
                .filter(|owner| *owner > now)
                .map_or(deadline, |owner| deadline.min(owner));
            let mut timer = std::pin::pin!(Sleep::with_timer_driver(wake_at, driver.clone()));
            poll_fn(|task| {
                if cancelled.as_mut().poll(task).is_ready() && cx.checkpoint().is_err() {
                    return Poll::Ready(());
                }
                if timer.as_mut().poll_deadline(task).is_ready() {
                    return Poll::Ready(());
                }
                Poll::Pending
            })
            .await;
        }
    }

    /// Yields the next entry whose deadline has passed, earliest first.
    ///
    /// Returns `Ready(None)` when the queue is empty and `Pending` until the
    /// earliest deadline passes. A pending poll, or one that found the queue
    /// empty, is woken when that deadline passes or an insert or reset makes
    /// an earlier one.
    ///
    /// Waiting here is not a cancellation point: a cancelled task stays
    /// parked until an entry comes due, then can observe the cancellation
    /// with [`Cx::checkpoint`](crate::Cx::checkpoint). Use [`Self::next_expired`]
    /// to stop sooner while retaining every unconsumed value.
    pub fn poll_expired(&mut self, cx: &mut Context<'_>) -> Poll<Option<Expired<T>>> {
        loop {
            let Some((deadline, _, index)) = self.next_live_entry() else {
                self.timer = None;
                self.armed_for = None;
                // A later insert wakes the task that saw the queue empty.
                store_waker(&mut self.waker, cx);
                return Poll::Ready(None);
            };
            if deadline <= wall_now() {
                self.heap.pop();
                let entry = self.entries.remove(index);
                return Poll::Ready(Some(Expired {
                    data: entry.data,
                    deadline,
                    key: Key {
                        index,
                        generation: entry.generation,
                    },
                }));
            }
            if self.armed_for != Some(deadline) {
                match &mut self.timer {
                    Some(timer) => timer.reset(deadline),
                    None => self.timer = Some(Sleep::new(deadline)),
                }
                self.armed_for = Some(deadline);
            }
            let timer = self.timer.as_mut().expect("armed above");
            // The timer is only a wake source, not a cancellation point: a
            // cancel-aware poll completes at once while the task is
            // cancelled, and re-arming it would spin until the deadline
            // really passed (as stream::debounce did, jqhteu).
            if Pin::new(timer).poll_deadline(cx).is_pending() {
                store_waker(&mut self.waker, cx);
                return Poll::Pending;
            }
            // The timer fired; the loop re-checks the clock before yielding.
            self.timer = None;
            self.armed_for = None;
        }
    }

    fn next_live_entry(&mut self) -> Option<(Time, u64, usize)> {
        loop {
            let &Reverse((deadline, schedule, index)) = self.heap.peek()?;
            if self
                .entries
                .get(index)
                .is_some_and(|entry| entry.schedule == schedule)
            {
                return Some((deadline, schedule, index));
            }
            self.heap.pop();
        }
    }

    fn bump_generation() -> u64 {
        // Process-wide, so a key from another queue never matches a live
        // entry here (both would otherwise count from zero). The values only
        // order this queue's heap items, and they still increase.
        NEXT_GENERATION.fetch_add(1, AtomicOrdering::Relaxed)
    }

    fn live_generation(&self, key: &Key) -> Option<u64> {
        self.entries
            .get(key.index)
            .filter(|entry| entry.generation == key.generation)
            .map(|entry| entry.generation)
    }

    fn schedule(&mut self, deadline: Time, schedule: u64, index: usize) {
        self.heap.push(Reverse((deadline, schedule, index)));
        // Removals and resets leave stale heap items behind until they reach
        // the top. Rebuild from the live entries (this one included) before
        // they dominate, so a queue whose keys are reset repeatedly without
        // being polled stays proportional to its entries.
        if self.heap.len() > 2 * self.entries.len() + 64 {
            self.heap = self
                .entries
                .iter()
                .map(|(index, entry)| Reverse((entry.deadline, entry.schedule, index)))
                .collect();
        }
        // A task parked on a later deadline (or on nothing) must re-arm.
        if self.armed_for.is_none_or(|armed| deadline < armed)
            && let Some(waker) = self.waker.take()
        {
            waker.wake();
        }
    }
}

fn deadline_after(timeout: Duration) -> Time {
    let nanos = u64::try_from(timeout.as_nanos()).unwrap_or(u64::MAX);
    wall_now().saturating_add_nanos(nanos)
}

fn store_waker(slot: &mut Option<Waker>, cx: &Context<'_>) {
    match slot {
        Some(waker) if waker.will_wake(cx.waker()) => {}
        _ => *slot = Some(cx.waker().clone()),
    }
}

impl<T> Default for DelayQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Unpin for DelayQueue<T> {}

impl<T> Stream for DelayQueue<T> {
    type Item = Expired<T>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().poll_expired(cx)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.entries.len()))
    }
}

impl<T: fmt::Debug> fmt::Debug for DelayQueue<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DelayQueue")
            .field("len", &self.entries.len())
            .field("armed_for", &self.armed_for)
            .finish_non_exhaustive()
    }
}

