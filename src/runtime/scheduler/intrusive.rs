//! Cache-local intrusive ring queue for scheduler hot paths.
//!
//! This module provides intrusive data structures that use link fields embedded
//! in `TaskRecord` rather than allocating separate nodes. This eliminates
//! per-operation allocations and improves cache locality.
//!
//! # Structures
//!
//! - [`IntrusiveRing`]: FIFO queue with O(1) push_back/pop_front and bounded
//!   traversal for exact-instance membership/removal
//! - [`IntrusiveStack`]: LIFO stack with FIFO steal (work-stealing pattern)
//!
//! # Design
//!
//! - Links (`next_in_queue`, `prev_in_queue`, `queue_tag`) are stored in `TaskRecord`
//! - Queues maintain only head/tail indices into the task arena
//! - Each task can be in at most one queue (enforced by `queue_tag` plus exact
//!   reachability for ring operations)
//! - Hot-end operations are O(1); all operations use zero allocations
//!
//! # When to Use
//!
//! Use intrusive structures when:
//! - You have exclusive `&mut Arena<TaskRecord>` access
//! - You need zero-allocation queue operations (hot paths)
//! - You're in a single-owner context (not shared across threads)
//!
//! Use regular queues (VecDeque, BinaryHeap) when:
//! - You need shared access (`Arc<Mutex<...>>`)
//! - You don't have arena access (TaskId-only APIs)
//! - You need priority ordering (heap-based)
//!
//! # Integration Points
//!
//! | Component | Uses | Why |
//! |-----------|------|-----|
//! | `ThreeLaneWorker` | Can use intrusive | Has arena via `state` |
//! | `PriorityScheduler` | Regular queues | No arena access, needs priority |
//! | `LocalQueue` | Intrusive stack | Shared via `Arc<Mutex>` + RuntimeState arena |
//! | `GlobalInjector` | Regular queues | Concurrent access |
//!
//! # Safety Proof: No ABA, No Use-After-Free
//!
//! ## Invariants (maintained by all operations):
//!
//! **INV-1 (Exclusive Access):** Every operation takes `&mut Arena<TaskRecord>`,
//! guaranteeing no concurrent mutation. This eliminates data races entirely.
//!
//! **INV-2 (Membership Consistency):** A task in a queue has the queue's `tag`,
//! but multiple queue instances may intentionally share that role tag. Exact
//! `IntrusiveRing` membership is therefore bounded reachability from that
//! ring's head, never a tag-only claim. On removal, `clear_queue_links()` sets
//! `queue_tag = 0` atomically with link erasure.
//!
//! **INV-3 (Link Validity):** If `task.next_in_queue = Some(id)`, then `id` is a
//! valid arena index with `queue_tag == self.tag`. Conversely on removal.
//!
//! ## No ABA:
//! ABA requires a slot to be freed and reallocated while a stale reference exists.
//! Since we use arena indices (not pointers), and INV-2 ensures queue links are
//! zeroed on removal, a stale index cannot satisfy the ring's bounded
//! head-reachability check. The arena itself is `&mut`-borrowed, preventing
//! concurrent reuse of slots.
//!
//! ## No Use-After-Free:
//! Tasks are never freed while in a queue. The arena is `&mut`-borrowed during all
//! operations, so no external code can free arena entries during queue manipulation.
//! After `clear_queue_links()`, the task's link fields are zeroed, and subsequent
//! operations will not follow stale links.
//!
//! # Queue Tags
//!
//! | Tag | Queue |
//! |-----|-------|
//! | 0 | Not in any queue |
//! | 1 | Local ready queue |
//! | 2 | Local cancel queue |
//! | 3 | Reserved |

use crate::record::task::TaskRecord;
use crate::types::TaskId;
use crate::util::Arena;

/// Queue tag for the local ready queue.
pub const QUEUE_TAG_READY: u8 = 1;

/// Queue tag for the local cancel queue.
pub const QUEUE_TAG_CANCEL: u8 = 2;

/// An intrusive doubly-linked ring queue.
///
/// The queue stores only head/tail indices; the actual links are stored
/// in `TaskRecord` fields. End operations are O(1) with zero per-operation
/// allocations. Exact arbitrary membership/removal performs a bounded walk so
/// two rings may safely share the same role tag without inflating `TaskRecord`.
///
/// # Invariants
///
/// - If `head.is_none()`, then `tail.is_none()` and `len == 0`
/// - If `head.is_some()`, then `tail.is_some()` and `len > 0`
/// - For all tasks in the queue: `task.queue_tag == self.tag`; the tag alone
///   does not establish ownership by this particular ring instance
/// - The list forms a proper doubly-linked chain from head to tail
#[derive(Debug)]
pub struct IntrusiveRing {
    /// First task in the queue (front for pop_front).
    head: Option<TaskId>,
    /// Last task in the queue (back for push_back).
    tail: Option<TaskId>,
    /// Number of tasks in the queue.
    len: usize,
    /// Queue role tag for coarse membership classification.
    /// Exact ring ownership additionally requires head reachability.
    tag: u8,
}

impl IntrusiveRing {
    /// Creates a new empty intrusive ring with the given queue tag.
    #[must_use]
    pub const fn new(tag: u8) -> Self {
        assert!(tag != 0, "queue tag 0 is reserved for \"not in any queue\"");
        Self {
            head: None,
            tail: None,
            len: 0,
            tag,
        }
    }

    /// Returns the number of tasks in the queue.
    #[must_use]
    #[inline]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns true if the queue is empty.
    #[must_use]
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the queue tag.
    #[must_use]
    #[inline]
    pub const fn tag(&self) -> u8 {
        self.tag
    }

    /// Pushes a task to the back of the queue.
    ///
    /// # Panics
    ///
    /// Panics if the task is already in a queue (queue_tag != 0).
    ///
    /// # Complexity
    ///
    /// O(1) time, O(0) allocations.
    #[inline]
    pub fn push_back(&mut self, task_id: TaskId, arena: &mut Arena<TaskRecord>) {
        let Some(record) = arena.get_mut(task_id.arena_index()) else {
            return;
        };

        // Check for double-enqueue
        let in_queue = record.is_in_queue();
        debug_assert!(
            !in_queue,
            "task {:?} already in queue (tag={})",
            task_id, record.queue_tag
        );

        if in_queue {
            return;
        }

        match self.tail {
            None => {
                // Empty queue: new task becomes both head and tail
                record.set_queue_links(None, None, self.tag);
                self.head = Some(task_id);
                self.tail = Some(task_id);
            }
            Some(old_tail) => {
                // Link new task after current tail
                record.set_queue_links(Some(old_tail), None, self.tag);

                // Update old tail's next pointer
                if let Some(old_tail_record) = arena.get_mut(old_tail.arena_index()) {
                    old_tail_record.next_in_queue = Some(task_id);
                }

                self.tail = Some(task_id);
            }
        }

        self.len += 1;
    }

    /// Pops a task from the front of the queue.
    ///
    /// Returns `None` if the queue is empty.
    ///
    /// # Complexity
    ///
    /// O(1) time, O(0) allocations.
    #[inline]
    #[must_use]
    pub fn pop_front(&mut self, arena: &mut Arena<TaskRecord>) -> Option<TaskId> {
        let head_id = self.head?;

        let next = {
            let record = arena
                .get_mut(head_id.arena_index())
                .expect("intrusive list broken: task removed from arena while in queue");

            // Verify the task is actually in this queue
            debug_assert!(
                record.is_in_queue_tag(self.tag),
                "head task {:?} has wrong tag (expected {}, got {})",
                head_id,
                self.tag,
                record.queue_tag
            );

            let next = record.next_in_queue;
            record.clear_queue_links();
            next
        };

        self.head = next;

        match next {
            None => {
                // Queue is now empty
                self.tail = None;
            }
            Some(new_head) => {
                // Update new head's prev pointer
                if let Some(new_head_record) = arena.get_mut(new_head.arena_index()) {
                    new_head_record.prev_in_queue = None;
                }
            }
        }

        self.len -= 1;
        Some(head_id)
    }

    /// Removes a specific task from the queue.
    ///
    /// Returns `true` if the task was found and removed, `false` otherwise.
    ///
    /// # Complexity
    ///
    /// O(n) membership validation followed by O(1) unlinking, O(0) allocations.
    #[inline]
    pub fn remove(&mut self, task_id: TaskId, arena: &mut Arena<TaskRecord>) -> bool {
        if !self.contains_linked_task(task_id, arena) {
            return false;
        }

        let Some(record) = arena.get_mut(task_id.arena_index()) else {
            return false;
        };

        let prev = record.prev_in_queue;
        let next = record.next_in_queue;

        // Clear the removed task's links
        record.clear_queue_links();

        // Update predecessor's next pointer
        match prev {
            None => {
                // Task was the head
                self.head = next;
            }
            Some(prev_id) => {
                if let Some(prev_record) = arena.get_mut(prev_id.arena_index()) {
                    prev_record.next_in_queue = next;
                }
            }
        }

        // Update successor's prev pointer
        match next {
            None => {
                // Task was the tail
                self.tail = prev;
            }
            Some(next_id) => {
                if let Some(next_record) = arena.get_mut(next_id.arena_index()) {
                    next_record.prev_in_queue = prev;
                }
            }
        }

        self.len -= 1;
        true
    }

    /// Returns true if the given task is in this queue.
    ///
    /// # Complexity
    ///
    /// O(n) time, bounded by the ring's recorded length.
    #[must_use]
    pub fn contains(&self, task_id: TaskId, arena: &Arena<TaskRecord>) -> bool {
        self.contains_linked_task(task_id, arena)
    }

    /// Validates exact-instance membership without allocating or trusting a
    /// role tag that another ring may share. The length bound prevents a
    /// corrupted cycle from looping forever.
    fn contains_linked_task(&self, task_id: TaskId, arena: &Arena<TaskRecord>) -> bool {
        let mut current = self.head;
        let mut expected_prev = None;

        for _ in 0..self.len {
            let Some(current_id) = current else {
                return false;
            };
            let Some(record) = arena.get(current_id.arena_index()) else {
                return false;
            };
            if !record.is_in_queue_tag(self.tag) || record.prev_in_queue != expected_prev {
                return false;
            }
            if current_id == task_id {
                return true;
            }

            expected_prev = Some(current_id);
            current = record.next_in_queue;
        }

        false
    }

    /// Returns the head task ID without removing it.
    #[must_use]
    #[inline]
    pub const fn peek_front(&self) -> Option<TaskId> {
        self.head
    }

    /// Clears the queue, removing all tasks.
    ///
    /// # Complexity
    ///
    /// O(n) time to clear all links.
    pub fn clear(&mut self, arena: &mut Arena<TaskRecord>) {
        let mut current = self.head;
        while let Some(task_id) = current {
            if let Some(record) = arena.get_mut(task_id.arena_index()) {
                let next = record.next_in_queue;
                record.clear_queue_links();
                current = next;
            } else {
                break;
            }
        }

        self.head = None;
        self.tail = None;
        self.len = 0;
    }
}

impl Default for IntrusiveRing {
    fn default() -> Self {
        Self::new(QUEUE_TAG_READY)
    }
}

/// An intrusive LIFO stack for work-stealing local queues.
///
/// Unlike `IntrusiveRing` which is FIFO, this stack provides LIFO
/// semantics for the owner while supporting FIFO stealing.
/// This matches the cache-locality optimization of processing
/// recently-pushed work first.
///
/// # Invariants
///
/// - If `top.is_none()`, then `len == 0`
/// - For all tasks in the stack: `task.queue_tag == self.tag`
#[derive(Debug)]
pub struct IntrusiveStack {
    /// Top of the stack (most recently pushed).
    top: Option<TaskId>,
    /// Bottom of the stack (oldest, for stealing).
    bottom: Option<TaskId>,
    /// Number of tasks in the stack.
    len: usize,
    /// Number of local (`!Send`) tasks currently in the stack.
    local_count: usize,
    /// Queue tag for membership detection.
    tag: u8,
}

impl IntrusiveStack {
    /// Creates a new empty intrusive stack with the given queue tag.
    #[must_use]
    pub const fn new(tag: u8) -> Self {
        assert!(tag != 0, "queue tag 0 is reserved for \"not in any queue\"");
        Self {
            top: None,
            bottom: None,
            len: 0,
            local_count: 0,
            tag,
        }
    }

    /// Returns the number of tasks in the stack.
    #[must_use]
    #[inline]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns true if the stack is empty.
    #[must_use]
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns true if the stack currently holds any local (`!Send`) tasks.
    #[must_use]
    #[inline]
    pub const fn has_local_tasks(&self) -> bool {
        self.local_count != 0
    }

    /// Pushes a task onto the top of the stack.
    ///
    /// # Complexity
    ///
    /// O(1) time, O(0) allocations.
    #[inline]
    pub fn push(&mut self, task_id: TaskId, arena: &mut Arena<TaskRecord>) {
        let Some(record) = arena.get_mut(task_id.arena_index()) else {
            return;
        };

        if record.is_in_queue() {
            return;
        }
        let is_local = record.is_local();

        match self.top {
            None => {
                // Empty stack
                record.set_queue_links(None, None, self.tag);
                self.top = Some(task_id);
                self.bottom = Some(task_id);
            }
            Some(old_top) => {
                // Link new task as new top, pointing down to old top
                record.set_queue_links(None, Some(old_top), self.tag);

                // Update old top's prev pointer (points up to new top)
                if let Some(old_top_record) = arena.get_mut(old_top.arena_index()) {
                    old_top_record.prev_in_queue = Some(task_id);
                }

                self.top = Some(task_id);
            }
        }

        self.len += 1;
        if is_local {
            self.local_count += 1;
        }
    }

    /// Pushes a known non-local task onto the top of the stack.
    ///
    /// This avoids per-item locality bookkeeping in hot steal-batch paths that
    /// have already proven the source queue contains no local tasks.
    #[inline]
    #[allow(dead_code)] // reserved for future steal-batch optimization
    pub(crate) fn push_assume_non_local(&mut self, task_id: TaskId, arena: &mut Arena<TaskRecord>) {
        let Some(record) = arena.get(task_id.arena_index()) else {
            return;
        };

        if record.is_in_queue() {
            return;
        }
        if record.is_local() {
            // Harden against callers that violate the contract in release builds.
            // Fall back to the safe path that maintains local_count invariants.
            self.push(task_id, arena);
            return;
        }

        let Some(record) = arena.get_mut(task_id.arena_index()) else {
            return;
        };

        match self.top {
            None => {
                // Empty stack
                record.set_queue_links(None, None, self.tag);
                self.top = Some(task_id);
                self.bottom = Some(task_id);
            }
            Some(old_top) => {
                // Link new task as new top, pointing down to old top
                record.set_queue_links(None, Some(old_top), self.tag);

                // Update old top's prev pointer (points up to new top)
                if let Some(old_top_record) = arena.get_mut(old_top.arena_index()) {
                    old_top_record.prev_in_queue = Some(task_id);
                }

                self.top = Some(task_id);
            }
        }

        self.len += 1;
    }

    /// Pushes a task onto the bottom of the stack.
    ///
    /// This is used by steal paths that temporarily remove local (`!Send`) tasks
    /// while scanning for stealable work, then restore them without perturbing
    /// owner-observed ordering.
    #[inline]
    pub fn push_bottom(&mut self, task_id: TaskId, arena: &mut Arena<TaskRecord>) {
        let Some(record) = arena.get_mut(task_id.arena_index()) else {
            return;
        };

        if record.is_in_queue() {
            return;
        }
        let is_local = record.is_local();

        match self.bottom {
            None => {
                // Empty stack.
                record.set_queue_links(None, None, self.tag);
                self.top = Some(task_id);
                self.bottom = Some(task_id);
            }
            Some(old_bottom) => {
                // Link new task as older than current bottom.
                record.set_queue_links(Some(old_bottom), None, self.tag);

                if let Some(old_bottom_record) = arena.get_mut(old_bottom.arena_index()) {
                    old_bottom_record.next_in_queue = Some(task_id);
                }

                self.bottom = Some(task_id);
            }
        }

        self.len += 1;
        if is_local {
            self.local_count += 1;
        }
    }

    /// Pops a task from the top of the stack (LIFO).
    ///
    /// # Complexity
    ///
    /// O(1) time, O(0) allocations.
    #[inline]
    #[must_use]
    pub fn pop(&mut self, arena: &mut Arena<TaskRecord>) -> Option<TaskId> {
        let top_id = self.top?;

        let (next_down, is_local) = {
            let record = arena
                .get_mut(top_id.arena_index())
                .expect("intrusive list broken: task removed from arena while in queue");
            let is_local = record.is_local();
            let next_down = record.next_in_queue; // Points down to older task
            record.clear_queue_links();
            (next_down, is_local)
        };

        self.top = next_down;

        match next_down {
            None => {
                // Stack is now empty
                self.bottom = None;
            }
            Some(new_top) => {
                // Update new top's prev pointer
                if let Some(new_top_record) = arena.get_mut(new_top.arena_index()) {
                    new_top_record.prev_in_queue = None;
                }
            }
        }

        self.len -= 1;
        if is_local {
            debug_assert!(self.local_count > 0);
            self.local_count -= 1;
        }
        Some(top_id)
    }

    /// Steals tasks from the bottom of the stack (FIFO for stealing).
    ///
    /// Returns up to `max_steal` tasks, starting from the oldest.
    ///
    /// # Complexity
    ///
    /// O(k) time where k is the number stolen. Allocates a Vec for the result.
    pub fn steal_batch(
        &mut self,
        max_steal: usize,
        arena: &mut Arena<TaskRecord>,
        stolen: &mut Vec<TaskId>,
    ) {
        if self.is_empty() {
            return;
        }
        let steal_count = (self.len / 2).max(1).min(max_steal);

        for _ in 0..steal_count {
            if let Some((bottom_id, _)) = self.steal_one_with_locality(arena) {
                stolen.push(bottom_id);
            } else {
                break;
            }
        }
    }

    /// Steals up to `max_steal` tasks into the destination stack.
    ///
    /// Returns the number of tasks transferred.
    ///
    /// # Complexity
    ///
    /// O(k) time where k is the number stolen. No allocations.
    pub fn steal_batch_into(
        &mut self,
        max_steal: usize,
        arena: &mut Arena<TaskRecord>,
        dest: &mut Self,
    ) -> usize {
        if self.is_empty() {
            return 0;
        }
        let steal_count = (self.len / 2).max(1).min(max_steal);
        let mut stolen = 0;

        for _ in 0..steal_count {
            if let Some((task_id, _)) = self.steal_one_with_locality(arena) {
                dest.push(task_id, arena);
                stolen += 1;
            } else {
                break;
            }
        }

        stolen
    }

    /// Steals up to `max_steal` known non-local tasks into `dest`.
    ///
    /// Caller must ensure `self.has_local_tasks() == false`.
    #[inline]
    #[allow(dead_code)] // Work-stealing scheduler integration path
    pub(crate) fn steal_batch_into_non_local(
        &mut self,
        max_steal: usize,
        arena: &mut Arena<TaskRecord>,
        dest: &mut Self,
    ) -> usize {
        debug_assert!(
            !self.has_local_tasks(),
            "steal_batch_into_non_local called on stack with local tasks"
        );
        if self.is_empty() {
            return 0;
        }
        let steal_count = (self.len / 2).max(1).min(max_steal);

        if self.tag == dest.tag {
            return self.splice_same_tag_non_local_batch(steal_count, arena, dest);
        }

        self.rebuild_non_local_batch(steal_count, arena, dest)
    }

    #[inline]
    fn splice_same_tag_non_local_batch(
        &mut self,
        steal_count: usize,
        arena: &mut Arena<TaskRecord>,
        dest: &mut Self,
    ) -> usize {
        let Some(segment_bottom) = self.bottom else {
            return 0;
        };

        // When both stacks share the same tag (the LocalQueue hot path),
        // we can splice the validated non-local bottom segment directly
        // into the destination instead of clearing and rebuilding each
        // stolen node one at a time.
        let mut segment_top = segment_bottom;
        let mut new_src_bottom = None;
        let mut stolen = 0usize;
        let mut current = segment_bottom;

        while stolen < steal_count {
            let Some(record) = arena.get(current.arena_index()) else {
                break;
            };
            if record.is_local() {
                // Source queue contract was violated; repair the local-task
                // summary and stop this fast path to avoid stealing !Send work.
                self.local_count = self.local_count.max(1);
                break;
            }

            segment_top = current;
            new_src_bottom = record.prev_in_queue;
            stolen += 1;

            match record.prev_in_queue {
                Some(next_up) => current = next_up,
                None => break,
            }
        }

        if stolen == 0 {
            return 0;
        }

        if new_src_bottom.is_some_and(|task_id| arena.get(task_id.arena_index()).is_none())
            || dest
                .top
                .is_some_and(|task_id| arena.get(task_id.arena_index()).is_none())
        {
            return 0;
        }

        self.bottom = new_src_bottom;
        match new_src_bottom {
            None => {
                self.top = None;
            }
            Some(new_bottom) => {
                if let Some(new_bottom_record) = arena.get_mut(new_bottom.arena_index()) {
                    new_bottom_record.next_in_queue = None;
                }
            }
        }
        self.len -= stolen;

        if let Some(segment_top_record) = arena.get_mut(segment_top.arena_index()) {
            segment_top_record.prev_in_queue = None;
        }

        match dest.top {
            None => {
                if let Some(segment_bottom_record) = arena.get_mut(segment_bottom.arena_index()) {
                    segment_bottom_record.next_in_queue = None;
                }
                dest.top = Some(segment_top);
                dest.bottom = Some(segment_bottom);
            }
            Some(old_top) => {
                if let Some(segment_bottom_record) = arena.get_mut(segment_bottom.arena_index()) {
                    segment_bottom_record.next_in_queue = Some(old_top);
                }
                if let Some(old_top_record) = arena.get_mut(old_top.arena_index()) {
                    old_top_record.prev_in_queue = Some(segment_bottom);
                }
                dest.top = Some(segment_top);
            }
        }

        dest.len += stolen;
        stolen
    }

    #[inline]
    fn rebuild_non_local_batch(
        &mut self,
        steal_count: usize,
        arena: &mut Arena<TaskRecord>,
        dest: &mut Self,
    ) -> usize {
        let mut stolen = 0;

        for _ in 0..steal_count {
            let Some(bottom_id) = self.bottom else {
                break;
            };

            // Detach oldest task from source stack.
            let prev_up = {
                let Some(record) = arena.get_mut(bottom_id.arena_index()) else {
                    break;
                };
                if record.is_local() {
                    // Source queue contract was violated; repair the local-task
                    // summary and stop this fast path to avoid stealing !Send work.
                    self.local_count = self.local_count.max(1);
                    break;
                }
                record.prev_in_queue
            };

            self.bottom = prev_up;
            match prev_up {
                None => {
                    // Source stack is now empty.
                    self.top = None;
                }
                Some(new_bottom) => {
                    if let Some(new_bottom_record) = arena.get_mut(new_bottom.arena_index()) {
                        new_bottom_record.next_in_queue = None;
                    }
                }
            }
            self.len -= 1;

            // Attach directly to destination top.
            let Some(record) = arena.get_mut(bottom_id.arena_index()) else {
                break;
            };
            match dest.top {
                None => {
                    record.set_queue_links(None, None, dest.tag);
                    dest.top = Some(bottom_id);
                    dest.bottom = Some(bottom_id);
                }
                Some(old_top) => {
                    record.set_queue_links(None, Some(old_top), dest.tag);
                    if let Some(old_top_record) = arena.get_mut(old_top.arena_index()) {
                        old_top_record.prev_in_queue = Some(bottom_id);
                    }
                    dest.top = Some(bottom_id);
                }
            }

            dest.len += 1;
            stolen += 1;
        }

        stolen
    }

    /// Steals one task from the bottom of the stack.
    ///
    /// Returns the stolen task and whether it is local (`!Send`), allowing
    /// callers to avoid an extra arena lookup on steal paths that need locality.
    #[inline]
    #[must_use]
    pub(crate) fn steal_one_with_locality(
        &mut self,
        arena: &mut Arena<TaskRecord>,
    ) -> Option<(TaskId, bool)> {
        let bottom_id = self.bottom?;

        let (prev_up, is_local) = {
            let record = arena.get_mut(bottom_id.arena_index())?;
            let is_local = record.is_local();
            let prev_up = record.prev_in_queue; // Points up to newer task
            record.clear_queue_links();
            (prev_up, is_local)
        };

        self.bottom = prev_up;

        match prev_up {
            None => {
                // Stack is now empty
                self.top = None;
            }
            Some(new_bottom) => {
                // Update new bottom's next pointer
                if let Some(new_bottom_record) = arena.get_mut(new_bottom.arena_index()) {
                    new_bottom_record.next_in_queue = None;
                }
            }
        }

        self.len -= 1;
        if is_local {
            debug_assert!(self.local_count > 0);
            self.local_count -= 1;
        }
        Some((bottom_id, is_local))
    }

    /// Steals one task from the bottom when the stack contains no local tasks.
    ///
    /// Caller must ensure `self.has_local_tasks() == false`.
    #[inline]
    #[must_use]
    #[allow(dead_code)] // Work-stealing scheduler integration path
    pub(crate) fn steal_one_assume_non_local(
        &mut self,
        arena: &mut Arena<TaskRecord>,
    ) -> Option<TaskId> {
        debug_assert!(
            !self.has_local_tasks(),
            "steal_one_assume_non_local called on stack with local tasks"
        );
        let bottom_id = self.bottom?;

        let prev_up = {
            let record = arena.get_mut(bottom_id.arena_index())?;
            if record.is_local() {
                // Source queue contract was violated; repair the local-task
                // summary and refuse to steal this task.
                self.local_count = self.local_count.max(1);
                return None;
            }
            let prev_up = record.prev_in_queue; // Points up to newer task
            record.clear_queue_links();
            prev_up
        };

        self.bottom = prev_up;

        match prev_up {
            None => {
                // Stack is now empty
                self.top = None;
            }
            Some(new_bottom) => {
                // Update new bottom's next pointer
                if let Some(new_bottom_record) = arena.get_mut(new_bottom.arena_index()) {
                    new_bottom_record.next_in_queue = None;
                }
            }
        }

        self.len -= 1;
        Some(bottom_id)
    }

    /// Steals one task from the bottom of the stack.
    #[inline]
    #[must_use]
    #[allow(dead_code)] // Work-stealing scheduler integration path
    pub(crate) fn steal_one(&mut self, arena: &mut Arena<TaskRecord>) -> Option<TaskId> {
        self.steal_one_with_locality(arena)
            .map(|(task_id, _)| task_id)
    }

    /// Returns true if the given task is in this stack.
    #[must_use]
    pub fn contains(&self, task_id: TaskId, arena: &Arena<TaskRecord>) -> bool {
        arena
            .get(task_id.arena_index())
            .is_some_and(|record| record.is_in_queue_tag(self.tag))
    }
}

#[cfg(test)]
#[path = "intrusive_inline_tests.rs"]
mod tests;
