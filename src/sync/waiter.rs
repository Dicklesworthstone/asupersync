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
    next_id: WaiterId,
}

#[derive(Debug, Clone)]
struct WaiterSlot<T> {
    id: WaiterId,
    waker: Waker,
    pub(crate) tag: T,
    prev: Option<usize>,
    next: Option<usize>,
}

/// Known-safe relay used when a caller must notify every queued waiter while
/// its own queue lock is held. Constructing and cloning this Arc-backed waker
/// does not invoke the queued task's RawWaker vtable; delegation happens only
/// when the returned relay is woken after the caller releases its lock.
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

impl<T> Default for WaiterChain<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> WaiterChain<T> {
    pub(crate) fn new() -> Self {
        Self {
            slots: Slab::with_capacity(4),
            positions: HashMap::with_capacity_and_hasher(4, BuildHasherDefault::default()),
            head: None,
            tail: None,
            next_id: 0,
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
            waker,
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
            waker,
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
        Some((slot.id, slot.waker, slot.tag))
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
        Some(slot.waker)
    }

    /// O(1) waker update by id. Returns whether the slot existed.
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
                    slot.waker.clone_from(new);
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
            Ok(std::mem::replace(&mut slot.waker, new))
        }
    }

    /// Returns the waker of the first element, if any.
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn front_waker(&self) -> Option<Waker> {
        self.head.map(|id| self.slots[id].waker.clone())
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
            wakers.push(self.slots[id].waker.clone());
            current = self.slots[id].next;
        }
        wakers
    }

    /// Return one forwarding waker per slot without cloning any queued task's
    /// user-controlled RawWaker in this call.
    ///
    /// Each stored waker is moved into an Arc-backed relay. One relay waker
    /// stays in the queue and one is returned to the caller. The caller may
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

            // The temporary noop has a known non-user vtable. Moving the
            // original into DeferredWake prevents any user clone/drop callback
            // from running while the caller still holds its queue lock.
            let original = std::mem::replace(&mut slot.waker, Waker::noop().clone());
            let relay = Arc::new(DeferredWake { inner: original });
            slot.waker = Waker::from(Arc::clone(&relay));
            wakers.push(Waker::from(relay));
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
        loop {
            let id = self.next_id;
            self.next_id = self.next_id.wrapping_add(1);
            if !self.positions.contains_key(&id) {
                return id;
            }
        }
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
mod tests {
    use super::WaiterChain;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::Waker;

    fn noop_waker() -> Waker {
        Waker::noop().clone()
    }

    struct DeferredWakeProbe {
        wakes: Arc<AtomicUsize>,
        dropped: Arc<AtomicBool>,
    }

    impl std::task::Wake for DeferredWakeProbe {
        fn wake(self: Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl Drop for DeferredWakeProbe {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn default_waiter_chain_preserves_fifo_after_middle_removal() {
        let mut chain = WaiterChain::new();

        let first = chain.push_back(noop_waker());
        let middle = chain.push_back(noop_waker());
        let last = chain.push_back(noop_waker());

        assert_eq!(chain.len(), 3);
        assert_eq!(chain.front_id(), Some(first));

        assert!(chain.remove(middle).is_some());
        assert_eq!(chain.len(), 2);

        assert_eq!(
            chain.pop_front().map(|(id, _, tag)| (id, tag)),
            Some((first, ()))
        );
        assert_eq!(
            chain.pop_front().map(|(id, _, tag)| (id, tag)),
            Some((last, ()))
        );
        assert!(chain.is_empty());
    }

    #[test]
    fn tagged_waiter_chain_preserves_front_insertion_and_tags() {
        let mut chain = WaiterChain::new();

        let back = chain.push_back_tagged(noop_waker(), "back");
        let front = chain.push_front_tagged(noop_waker(), "front");

        assert_eq!(chain.front_id(), Some(front));
        assert_eq!(chain.front_tag(), Some(&"front"));

        assert_eq!(
            chain.pop_front().map(|(id, _, tag)| (id, tag)),
            Some((front, "front"))
        );
        assert_eq!(
            chain.pop_front().map(|(id, _, tag)| (id, tag)),
            Some((back, "back"))
        );
        assert!(chain.is_empty());
    }

    #[test]
    fn deferred_clone_forwards_wakes_and_retains_queue_identity() {
        let wakes = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicBool::new(false));
        let original = Waker::from(Arc::new(DeferredWakeProbe {
            wakes: Arc::clone(&wakes),
            dropped: Arc::clone(&dropped),
        }));
        let mut chain = WaiterChain::new();
        let id = chain.push_back(original);

        let outbound = chain.clone_wakers_deferred();
        assert_eq!(outbound.len(), 1);
        assert!(chain.contains(id));
        assert!(!dropped.load(Ordering::SeqCst));

        outbound[0].wake_by_ref();
        assert_eq!(wakes.load(Ordering::SeqCst), 1);
        drop(outbound);
        assert!(!dropped.load(Ordering::SeqCst));

        let queued = chain.remove(id).expect("relay remains queued");
        queued.wake_by_ref();
        assert_eq!(wakes.load(Ordering::SeqCst), 2);
        drop(queued);
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn removing_missing_waiter_is_idempotent() {
        let mut chain = WaiterChain::new();
        let id = chain.push_back(noop_waker());

        assert!(chain.remove(id).is_some());
        assert!(chain.remove(id).is_none());
        assert!(chain.pop_front().is_none());
        assert!(chain.is_empty());
    }

    #[test]
    fn popped_waiter_id_cannot_remove_reused_slab_slot() {
        let mut chain = WaiterChain::new();

        let stale_id = chain.push_back(noop_waker());
        let popped = chain.pop_front().map(|(id, _, tag)| (id, tag));
        assert_eq!(popped, Some((stale_id, ())));

        let live_id = chain.push_back(noop_waker());
        assert_ne!(stale_id, live_id);
        assert!(!chain.update_waker(stale_id, &noop_waker()));
        assert!(chain.remove(stale_id).is_none());
        assert!(chain.contains(live_id));
        assert_eq!(
            chain.pop_front().map(|(id, _, tag)| (id, tag)),
            Some((live_id, ()))
        );
        assert!(chain.is_empty());
    }

    #[test]
    fn waiter_ids_are_stable_across_32_bit_boundary() {
        let mut chain = WaiterChain::new();
        chain.next_id = u64::from(u32::MAX) - 1;

        let stale_id = chain.push_back(noop_waker());
        assert_eq!(stale_id, u64::from(u32::MAX) - 1);
        assert_eq!(
            chain.pop_front().map(|(id, _, tag)| (id, tag)),
            Some((stale_id, ()))
        );

        let boundary_id = chain.push_back(noop_waker());
        let after_boundary_id = chain.push_back(noop_waker());

        assert_eq!(boundary_id, u64::from(u32::MAX));
        assert_eq!(after_boundary_id, u64::from(u32::MAX) + 1);
        assert_ne!(stale_id, after_boundary_id);
    }

    #[test]
    fn waiter_id_width_is_not_pointer_width_limited() {
        assert!(
            std::mem::size_of::<super::WaiterId>() >= std::mem::size_of::<u64>(),
            "waiter ids must remain wide enough for 32-bit targets"
        );
    }
}

// Include metamorphic tests
#[cfg(test)]
#[path = "waiter_metamorphic_tests.rs"]
mod metamorphic_tests;
