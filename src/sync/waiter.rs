//! Waiter queue management for synchronization primitives.
//!
//! This module provides [`WaiterChain`], a slab-backed doubly-linked FIFO queue
//! used by mutexes, semaphores, and other sync primitives to manage waiting tasks.
//! Each waiter has a stable identity to prevent races when futures are cancelled
//! or wake up out of order.
//!
//! # Design
//!
//! - **Stable IDs**: [`WaiterId`] provides identity that survives slab reuse
//! - **O(1) operations**: Insert, remove, and wake operations are constant time
//! - **FIFO ordering**: Waiters are woken in the order they arrive (fairness)
//! - **Intrusive linking**: Uses slab indices for prev/next pointers
//!
//! # Usage
//!
//! Synchronization primitives use this to queue waiting tasks:
//! 1. `enqueue_waiter()` when a task must wait
//! 2. `remove_waiter()` if the task is cancelled
//! 3. `wake_next()` when resources become available

use slab::Slab;
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::BuildHasherDefault;
use std::sync::Arc;
use std::task::{Wake, Waker};

type PositionMap = HashMap<WaiterId, usize, BuildHasherDefault<DefaultHasher>>;

/// Stable identity for a queued waiter.
///
/// This is intentionally not the slab index: `Slab` may reuse a vacant
/// slot as soon as the head waiter is popped for a handoff. Futures can still
/// hold their old identity until they observe that handoff, so a bare index
/// would allow a stale future to remove or update an unrelated newer waiter.
///
/// Keep this wider than `usize` so 32-bit targets do not re-enter the same
/// identity space after only `usize::MAX + 1` enqueue operations. A stale
/// future can outlive its queue slot after a handoff, so the identity must not
/// be tied to pointer width.
pub type WaiterId = u64;

/// Slab-backed doubly-linked FIFO of waiters
/// (br-asupersync-wlf0xh). Each slot carries the task's `Waker` plus
/// `prev`/`next` slab-index pointers so that O(1) removal at any
/// position is possible from a known stable waiter id.
#[derive(Debug, Clone)]
pub struct WaiterChain<T = ()> {
    slots: Slab<WaiterSlot<T>>,
    positions: PositionMap,
    head: Option<usize>,
    tail: Option<usize>,
    next_id: Option<WaiterId>,
}

#[derive(Debug, Clone)]
struct WaiterSlot<T> {
    id: WaiterId,
    waker: QueuedWaker,
    pub(crate) tag: T,
    prev: Option<usize>,
    next: Option<usize>,
}

/// Known-safe relay used when a caller must notify every queued waiter while
/// its own queue lock is held. Constructing and cloning this Arc-backed waker
/// does not invoke the queued task's RawWaker vtable; delegation happens only
/// when the returned relay is woken after the caller releases its lock.
#[derive(Debug)]
struct DeferredWake {
    inner: Waker,
}

impl Wake for DeferredWake {
    #[inline]
    fn wake(self: Arc<Self>) {
        self.inner.wake_by_ref();
    }

    #[inline]
    fn wake_by_ref(self: &Arc<Self>) {
        self.inner.wake_by_ref();
    }
}

/// A stored task waker whose clone path is a known `Arc` operation.
///
/// The caller must still retire this value outside any internal lock: dropping
/// the final relay owner also drops the original task waker.
#[derive(Debug, Clone)]
pub(super) struct DeferredWaker {
    relay: Arc<DeferredWake>,
}

impl DeferredWaker {
    /// Wrap an already-owned task waker in the known relay representation.
    pub(super) fn new(waker: Waker) -> Self {
        Self {
            relay: Arc::new(DeferredWake { inner: waker }),
        }
    }

    /// Whether the original task waker targets the same task as `other`.
    pub(super) fn will_wake(&self, other: &Waker) -> bool {
        self.relay.inner.will_wake(other)
    }

    /// Produce a wake handle without invoking the original RawWaker's clone
    /// callback. The returned handle must be woken or retired after unlock.
    pub(super) fn clone_waker(&self) -> Waker {
        Waker::from(Arc::clone(&self.relay))
    }
}

/// Keep the original task identity accessible after deferring notifications.
/// A direct waker needs no relay allocation until a deferred batch is built.
/// Once deferred, every batch shares that one relay rather than recursively
/// wrapping an earlier relay and growing wake/drop depth with each notification.
#[derive(Debug, Clone)]
enum QueuedWaker {
    Direct(Waker),
    Deferred(DeferredWaker),
}

impl QueuedWaker {
    fn will_wake(&self, other: &Waker) -> bool {
        match self {
            Self::Direct(waker) => waker.will_wake(other),
            Self::Deferred(waker) => waker.will_wake(other),
        }
    }

    /// Transfer the queued owner without invoking a task's clone/drop callback.
    /// The caller remains responsible for waking or retiring it after unlock.
    fn into_waker(self) -> Waker {
        match self {
            Self::Direct(waker) => waker,
            Self::Deferred(waker) => Waker::from(waker.relay),
        }
    }
}

/// Clone a stored waker through a known Arc-backed relay without invoking the
/// stored task's RawWaker clone/drop callbacks in this call.
///
/// The original waker is moved behind the relay, one relay owner replaces the
/// slot, and a second relay owner is returned. Callers may use this while
/// holding an internal queue lock, then release that lock before waking or
/// retiring the returned owner. They must also retire later slot replacements
/// or removals outside the same lock. Repeated calls reuse the existing relay.
fn clone_waker_deferred(slot: &mut QueuedWaker) -> Waker {
    match slot {
        QueuedWaker::Direct(waker) => {
            let original = std::mem::replace(waker, Waker::noop().clone());
            let relay = DeferredWaker::new(original);
            let outbound = relay.clone_waker();
            // The displaced Direct variant contains only the known noop waker.
            *slot = QueuedWaker::Deferred(relay);
            outbound
        }
        QueuedWaker::Deferred(relay) => relay.clone_waker(),
    }
}

impl<T> Default for WaiterChain<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> WaiterChain<T> {
    pub(crate) fn new() -> Self {
        Self {
            // Keep uncontended synchronization primitives allocation-free. The
            // slab and stable-id index grow together only when the first waiter
            // is actually queued, then retain that capacity for reuse.
            slots: Slab::new(),
            positions: PositionMap::default(),
            head: None,
            tail: None,
            next_id: Some(0),
        }
    }

    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.head.is_none()
    }

    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.slots.len()
    }

    /// Push a new waiter to the BACK of the chain (FIFO insert).
    /// Returns the stable waiter id.
    pub(crate) fn push_back_tagged(&mut self, waker: Waker, tag: T) -> WaiterId {
        let index = self.slots.vacant_key();
        let new_id = self.next_id();
        let inserted = self.slots.insert(WaiterSlot {
            id: new_id,
            waker: QueuedWaker::Direct(waker),
            tag,
            prev: self.tail,
            next: None,
        });
        debug_assert_eq!(inserted, index);
        self.positions.insert(new_id, index);
        match self.tail {
            Some(prev_tail) => {
                self.slots[prev_tail].next = Some(index);
            }
            None => {
                self.head = Some(index);
            }
        }
        self.tail = Some(index);
        new_id
    }

    /// Push a new waiter to the FRONT of the chain (used for
    /// "preserve precedence after spurious requeue", e.g. when a
    /// granted waiter races with a steal).
    pub(crate) fn push_front_tagged(&mut self, waker: Waker, tag: T) -> WaiterId {
        let index = self.slots.vacant_key();
        let new_id = self.next_id();
        let inserted = self.slots.insert(WaiterSlot {
            id: new_id,
            waker: QueuedWaker::Direct(waker),
            tag,
            prev: None,
            next: self.head,
        });
        debug_assert_eq!(inserted, index);
        self.positions.insert(new_id, index);
        match self.head {
            Some(next_head) => {
                self.slots[next_head].prev = Some(index);
            }
            None => {
                self.tail = Some(index);
            }
        }
        self.head = Some(index);
        new_id
    }

    /// Pop the front waiter (FIFO take). Returns `(id, waker, tag)`.
    pub(crate) fn pop_front(&mut self) -> Option<(WaiterId, Waker, T)> {
        let head_index = self.head?;
        let slot = self.slots.remove(head_index);
        self.positions.remove(&slot.id);
        self.head = slot.next;
        match slot.next {
            Some(new_head) => {
                self.slots[new_head].prev = None;
            }
            None => {
                self.tail = None;
            }
        }
        Some((slot.id, slot.waker.into_waker(), slot.tag))
    }

    /// Returns the current front-of-queue id without removing.
    #[inline]
    pub(crate) fn front_id(&self) -> Option<WaiterId> {
        self.head.map(|index| self.slots[index].id)
    }

    /// Returns a reference to the tag of the front waiter.
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn front_tag(&self) -> Option<&T> {
        self.head.map(|id| &self.slots[id].tag)
    }

    /// O(1) remove by waiter id. Returns `Some(waker)` if the id was
    /// in the chain, `None` otherwise.
    pub(crate) fn remove(&mut self, id: WaiterId) -> Option<Waker> {
        let index = self.positions.remove(&id)?;
        let slot = self.slots.remove(index);
        match slot.prev {
            Some(p) => self.slots[p].next = slot.next,
            None => self.head = slot.next,
        }
        match slot.next {
            Some(n) => self.slots[n].prev = slot.prev,
            None => self.tail = slot.prev,
        }
        Some(slot.waker.into_waker())
    }

    /// O(1) waker update by id. Returns whether the slot existed.
    ///
    /// Retained utility: not yet wired to a caller, but kept as the intended
    /// O(1) in-place waker refresh for the slab. `#[allow(dead_code)]` keeps the
    /// crate's `deny(dead_code)` gate green until a call site lands, without
    /// discarding the method.
    #[allow(dead_code)]
    pub(crate) fn update_waker(&mut self, id: WaiterId, new: &Waker) -> bool {
        let Some(&index) = self.positions.get(&id) else {
            return false;
        };
        match self.slots.get_mut(index) {
            Some(slot) => {
                if slot.id != id {
                    return false;
                }
                if !slot.waker.will_wake(new) {
                    slot.waker = QueuedWaker::Direct(new.clone());
                }
                true
            }
            None => false,
        }
    }

    /// Replace a queued waiter's waker without destroying either waker in this
    /// call. The returned `Ok` value is the waker the caller must retire: it is
    /// the previous queued waker when the identity changed, or `new` when both
    /// wakers target the same task. `Err(new)` means the waiter was absent.
    ///
    /// Callers that protect the chain with a lock can therefore move all
    /// user-controlled `RawWaker` destruction outside that lock.
    pub(crate) fn replace_waker(&mut self, id: WaiterId, new: Waker) -> Result<Waker, Waker> {
        let Some(&index) = self.positions.get(&id) else {
            return Err(new);
        };
        let Some(slot) = self.slots.get_mut(index) else {
            return Err(new);
        };
        if slot.id != id {
            return Err(new);
        }
        if slot.waker.will_wake(&new) {
            Ok(new)
        } else {
            Ok(std::mem::replace(&mut slot.waker, QueuedWaker::Direct(new)).into_waker())
        }
    }

    /// Returns the waker of the first element, if any.
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn front_waker(&self) -> Option<Waker> {
        self.head
            .map(|id| self.slots[id].waker.clone().into_waker())
    }

    /// Drain all wakers in order.
    #[allow(dead_code)]
    pub(crate) fn drain(&mut self) -> Vec<Waker> {
        let mut wakers = Vec::with_capacity(self.len());
        while let Some((_, waker, _)) = self.pop_front() {
            wakers.push(waker);
        }
        wakers
    }

    /// Collect all wakers currently in the chain (cloning them)
    #[allow(dead_code)]
    pub(crate) fn clone_wakers(&self) -> Vec<Waker> {
        let mut wakers = Vec::with_capacity(self.len());
        let mut current = self.head;
        while let Some(id) = current {
            wakers.push(self.slots[id].waker.clone().into_waker());
            current = self.slots[id].next;
        }
        wakers
    }

    /// Return one forwarding waker per slot without cloning any queued task's
    /// user-controlled RawWaker in this call.
    ///
    /// Each direct waker is moved into an Arc-backed relay on its first batch;
    /// subsequent batches reuse that relay. One owner stays in the queue and
    /// one is returned to the caller. The caller may
    /// therefore build the notification batch while holding its queue lock,
    /// release that lock, and only then invoke user wake callbacks. Subsequent
    /// replacement/removal must likewise retire the queued relay outside the
    /// caller's lock so the original waker payload is destroyed there.
    pub(crate) fn clone_wakers_deferred(&mut self) -> Vec<Waker> {
        let mut wakers = Vec::with_capacity(self.len());
        let mut current = self.head;
        while let Some(index) = current {
            let slot = &mut self.slots[index];
            current = slot.next;

            wakers.push(clone_waker_deferred(&mut slot.waker));
        }
        wakers
    }

    /// O(1) presence check.
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn contains(&self, id: WaiterId) -> bool {
        self.positions
            .get(&id)
            .and_then(|&index| self.slots.get(index))
            .is_some_and(|slot| slot.id == id)
    }

    #[inline]
    fn next_id(&mut self) -> WaiterId {
        let id = self
            .next_id
            .expect("WaiterChain exhausted its stable waiter ID space");
        self.next_id = id.checked_add(1);
        debug_assert!(
            !self.positions.contains_key(&id),
            "monotonic waiter IDs must never alias a live waiter"
        );
        id
    }
}

impl WaiterChain<()> {
    #[allow(dead_code)]
    pub(crate) fn push_back(&mut self, waker: Waker) -> WaiterId {
        self.push_back_tagged(waker, ())
    }

    #[allow(dead_code)]
    pub(crate) fn push_front(&mut self, waker: Waker) -> WaiterId {
        self.push_front_tagged(waker, ())
    }
}

#[cfg(test)]
#[path = "waiter_inline_tests.rs"]
mod tests;

// Include metamorphic tests
#[cfg(test)]
#[path = "waiter_metamorphic_tests.rs"]
mod metamorphic_tests;
