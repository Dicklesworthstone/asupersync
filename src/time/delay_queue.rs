//! A queue of values that each come due at their own deadline.
//!
//! [`DelayQueue`] holds values with deadlines and yields each one as an
//! [`Expired`] once its deadline passes, earliest first. Entries can be
//! removed or given a new deadline through the [`Key`] returned at insertion.
//! It is the building block for expiring cache entries, session idle
//! timeouts, retry schedules and per-request deadlines, with one timer for the
//! whole queue instead of one task per entry.
//!
//! Deadlines use the same clock as [`Sleep`]: the runtime's timer driver
//! (virtual time under the lab runtime), or the wall clock outside one.

use crate::stream::Stream;
use crate::time::{Sleep, wall_now};
use crate::types::Time;
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

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
    next_generation: u64,
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
            next_generation: 0,
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
        let generation = self.bump_generation();
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
        let schedule = self.bump_generation();
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

    /// Yields the next entry whose deadline has passed, earliest first.
    ///
    /// Returns `Ready(None)` when the queue is empty and `Pending` until the
    /// earliest deadline passes. A pending poll is woken when that deadline
    /// passes or an insert or reset makes an earlier one.
    pub fn poll_expired(&mut self, cx: &mut Context<'_>) -> Poll<Option<Expired<T>>> {
        loop {
            let Some(&Reverse((deadline, schedule, index))) = self.heap.peek() else {
                self.timer = None;
                self.armed_for = None;
                return Poll::Ready(None);
            };
            let live = self
                .entries
                .get(index)
                .is_some_and(|entry| entry.schedule == schedule);
            if !live {
                self.heap.pop();
                continue;
            }
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
            if Pin::new(timer).poll(cx).is_pending() {
                store_waker(&mut self.waker, cx);
                return Poll::Pending;
            }
            // The timer fired (or completed early because the task was
            // cancelled); the loop re-checks the clock before yielding.
            self.timer = None;
            self.armed_for = None;
        }
    }

    fn bump_generation(&mut self) -> u64 {
        let generation = self.next_generation;
        self.next_generation += 1;
        generation
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
