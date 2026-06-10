//! Spawn mailbox: lock-free spawn-request intake decoupled from `RuntimeState`.
//!
//! Today every spawn must hold the global `RuntimeState` lock while
//! `create_task` runs. The spawn mailbox is the first half of the fix
//! (br-asupersync-dx-core-api-v2-u1z5hn.1): callers pre-allocate a
//! *provisional* [`TaskId`] from a sharded allocator, package the erased
//! future plus its spawn parameters into a [`SpawnRequest`], and enqueue it
//! onto the [`SpawnMailbox`] **without touching `RuntimeState`**. The
//! scheduler performs admission (region liveness check, task-record
//! insertion, obligation hookup) at dispatch time under the state lock it
//! already holds; that half lands separately
//! (br-asupersync-dx-core-api-v2-u1z5hn.1.3), as does region pending-spawn
//! quiescence accounting (br-asupersync-dx-core-api-v2-u1z5hn.1.2).
//!
//! # Provisional task-id namespace
//!
//! Arena-allocated `TaskId`s carry small generations: fresh slots start at
//! generation 0 and the generation increments once per slot reuse. The
//! mailbox mints ids in a disjoint namespace by setting the generation MSB
//! ([`SPAWN_ID_GENERATION_TAG`]): an arena id would need 2^31 reuses of a
//! single slot to collide, which is unreachable in practice. Layout:
//!
//! ```text
//! generation = TAG(bit 31) | shard(bits 30..24) | epoch(bits 23..0)
//! index      = low 32 bits of the per-shard allocation counter
//! ```
//!
//! Uniqueness proof sketch: distinct shards produce distinct generations, so
//! ids from different shards never collide; within one shard a single atomic
//! `fetch_add` produces a strictly increasing 56-bit (epoch, index) pair, so
//! ids from the same shard never collide before 2^56 allocations per shard.
//! Admission maps a provisional id to its canonical arena id (or adopts it,
//! once the sharded task table lands); the mapping policy is owned by the
//! admission bead.
//!
//! # Capacity and backpressure
//!
//! The mailbox is **unbounded** ([`GlobalFifoQueue`] wraps a lock-free
//! `SegQueue` on native targets, a mutexed `VecDeque` on wasm). `enqueue`
//! never blocks and never drops a request — silent drop is forbidden by the
//! spawn-mailbox contract. Backpressure is an *admission-side* concern:
//! region quotas reject requests with an explicit `SpawnError` when they are
//! admitted, and region close resolves every pending request through
//! [`SpawnRequest::resolve_cancelled`] so the completion slot always learns
//! the outcome. Memory growth is therefore bounded by the same quota that
//! bounds live tasks, just observed at admission instead of enqueue.
//!
//! # Trace ordering
//!
//! [`SpawnMailbox::enqueue`] emits [`TraceEventKind::TaskSpawnEnqueued`]
//! *before* the request is published to the queue. The trace buffer
//! serializes sequence allocation with insertion, so the enqueue event's
//! sequence number is always ordered before any admission-side event for the
//! same request (a consumer can only observe the request after the push).

use crate::runtime::scheduler::global_queue::GlobalFifoQueue;
use crate::runtime::stored_task::StoredTask;
use crate::trace::TraceBufferHandle;
use crate::trace::event::TraceEvent;
use crate::types::{Budget, CancelReason, RegionId, TaskId, Time};
use crate::util::{ArenaIndex, CachePadded};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Generation tag (MSB) marking a provisional spawn-mailbox `TaskId`.
///
/// Arena generations start at 0 and increment once per slot reuse, so an
/// arena id reaches this bit only after 2^31 reuses of one slot.
pub const SPAWN_ID_GENERATION_TAG: u32 = 0x8000_0000;

/// Number of bits in the generation reserved for the epoch counter.
const SPAWN_ID_EPOCH_BITS: u32 = 24;

/// Maximum epoch value before a shard is exhausted (2^24 epochs of 2^32 ids).
const SPAWN_ID_EPOCH_MAX: u64 = (1 << SPAWN_ID_EPOCH_BITS) - 1;

/// Number of allocation shards. Must stay ≤ 128 so the shard index fits the
/// 7-bit field between the tag bit and the epoch bits.
pub const SPAWN_ID_SHARDS: usize = 8;

/// Round-robin seed handing each new thread a home shard.
static NEXT_SHARD_HINT: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    /// Home shard for the current thread (round-robin assigned on first use).
    static SHARD_HINT: usize =
        NEXT_SHARD_HINT.fetch_add(1, Ordering::Relaxed) % SPAWN_ID_SHARDS;
}

/// Returns true if `id` was minted by a [`SpawnIdAllocator`] (provisional
/// spawn-mailbox namespace) rather than by the runtime's task arena.
#[inline]
#[must_use]
pub fn is_spawn_mailbox_id(id: TaskId) -> bool {
    id.arena_index().generation() & SPAWN_ID_GENERATION_TAG != 0
}

/// Sharded allocator for provisional spawn-mailbox [`TaskId`]s.
///
/// Allocation is a single relaxed `fetch_add` on the calling thread's home
/// shard; no locks, no `RuntimeState`. See the module docs for the id layout
/// and the uniqueness argument.
pub struct SpawnIdAllocator {
    shards: [CachePadded<AtomicU64>; SPAWN_ID_SHARDS],
}

impl SpawnIdAllocator {
    /// Creates a new allocator with all shard counters at zero.
    #[must_use]
    pub fn new() -> Self {
        Self {
            shards: std::array::from_fn(|_| CachePadded::new(AtomicU64::new(0))),
        }
    }

    /// Allocates a provisional `TaskId` on the calling thread's home shard.
    #[inline]
    #[must_use]
    pub fn allocate(&self) -> TaskId {
        self.allocate_on(SHARD_HINT.with(|shard| *shard))
    }

    /// Allocates a provisional `TaskId` on an explicit shard.
    ///
    /// # Panics
    ///
    /// Panics if `shard >= SPAWN_ID_SHARDS` or if the shard has exhausted its
    /// 2^56 id space (unreachable in any realistic process lifetime).
    #[must_use]
    pub fn allocate_on(&self, shard: usize) -> TaskId {
        assert!(
            shard < SPAWN_ID_SHARDS,
            "spawn-id shard {shard} out of range (max {SPAWN_ID_SHARDS})"
        );
        let n = self.shards[shard].fetch_add(1, Ordering::Relaxed);
        let epoch = n >> 32;
        assert!(
            epoch <= SPAWN_ID_EPOCH_MAX,
            "spawn-id shard {shard} exhausted after 2^56 allocations"
        );
        let index = u32::try_from(n & u64::from(u32::MAX)).expect("masked to 32 bits");
        let shard_bits = u32::try_from(shard).expect("shard fits in u32") << SPAWN_ID_EPOCH_BITS;
        let epoch_bits = u32::try_from(epoch).expect("epoch fits in 24 bits");
        let generation = SPAWN_ID_GENERATION_TAG | shard_bits | epoch_bits;
        TaskId::from_arena(ArenaIndex::new(index, generation))
    }
}

impl Default for SpawnIdAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SpawnIdAllocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpawnIdAllocator")
            .field("shards", &SPAWN_ID_SHARDS)
            .finish_non_exhaustive()
    }
}

/// Completion slot invoked when a spawn request is cancelled before
/// admission (for example, its region closed while the request was queued).
///
/// The slot must resolve the caller-visible join handle with
/// `Outcome::Cancelled(reason)`; it is invoked at most once.
pub type UnadmittedCancelFn = Box<dyn FnOnce(CancelReason) + Send>;

/// A spawn request travelling through the [`SpawnMailbox`].
///
/// Carries everything admission needs to create the task record under the
/// state lock: the provisional task id, owning region, budget, optional
/// debug name, the erased future, and the completion slot used if the
/// request is cancelled before it is ever admitted.
///
/// Note: `crate::remote::SpawnRequest` is an unrelated wire-protocol type
/// for cross-node spawns; this struct is runtime-local.
pub struct SpawnRequest {
    task_id: TaskId,
    region: RegionId,
    budget: Budget,
    name: Option<Arc<str>>,
    task: StoredTask,
    on_unadmitted_cancel: Option<UnadmittedCancelFn>,
}

/// Destructured [`SpawnRequest`] handed to the admission path.
pub struct SpawnRequestParts {
    /// Provisional task id (spawn-mailbox namespace).
    pub task_id: TaskId,
    /// Region that will own the task.
    pub region: RegionId,
    /// Budget the task starts with.
    pub budget: Budget,
    /// Optional debug name.
    pub name: Option<Arc<str>>,
    /// The erased future to store.
    pub task: StoredTask,
    /// Completion slot for cancel-before-admission.
    pub on_unadmitted_cancel: Option<UnadmittedCancelFn>,
}

impl SpawnRequest {
    /// Creates a new spawn request.
    ///
    /// `task_id` must come from a [`SpawnIdAllocator`] so the id is unique
    /// and identifiable as provisional ([`is_spawn_mailbox_id`]).
    #[must_use]
    pub fn new(task_id: TaskId, region: RegionId, budget: Budget, task: StoredTask) -> Self {
        Self {
            task_id,
            region,
            budget,
            name: None,
            task,
            on_unadmitted_cancel: None,
        }
    }

    /// Attaches a debug name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<Arc<str>>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Attaches the cancel-before-admission completion slot.
    #[must_use]
    pub fn with_unadmitted_cancel(mut self, slot: UnadmittedCancelFn) -> Self {
        self.on_unadmitted_cancel = Some(slot);
        self
    }

    /// Returns the provisional task id.
    #[inline]
    #[must_use]
    pub fn task_id(&self) -> TaskId {
        self.task_id
    }

    /// Returns the owning region.
    #[inline]
    #[must_use]
    pub fn region(&self) -> RegionId {
        self.region
    }

    /// Returns the spawn budget.
    #[inline]
    #[must_use]
    pub fn budget(&self) -> Budget {
        self.budget
    }

    /// Returns the debug name, if any.
    #[inline]
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Destructures the request for admission.
    #[must_use]
    pub fn into_parts(self) -> SpawnRequestParts {
        SpawnRequestParts {
            task_id: self.task_id,
            region: self.region,
            budget: self.budget,
            name: self.name,
            task: self.task,
            on_unadmitted_cancel: self.on_unadmitted_cancel,
        }
    }

    /// Resolves a request that will never be admitted.
    ///
    /// Drops the stored future without polling it and invokes the
    /// cancel-before-admission slot (if any) exactly once with `reason`.
    /// This is the drain path for region-close racing enqueue: the public
    /// semantics are identical to spawning into a closing region today,
    /// just observed later.
    pub fn resolve_cancelled(self, reason: CancelReason) {
        let SpawnRequestParts {
            task,
            on_unadmitted_cancel,
            ..
        } = self.into_parts();
        drop(task);
        if let Some(slot) = on_unadmitted_cancel {
            slot(reason);
        }
    }
}

impl fmt::Debug for SpawnRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpawnRequest")
            .field("task_id", &self.task_id)
            .field("region", &self.region)
            .field("name", &self.name)
            .field("has_cancel_slot", &self.on_unadmitted_cancel.is_some())
            .finish_non_exhaustive()
    }
}

/// Lock-free MPSC intake queue for spawn requests.
///
/// Producers enqueue from any thread without holding `RuntimeState`; the
/// scheduler's admission path consumes. See module docs for capacity,
/// backpressure, and trace-ordering contracts.
pub struct SpawnMailbox {
    queue: GlobalFifoQueue<SpawnRequest>,
    ids: SpawnIdAllocator,
    trace: Option<TraceBufferHandle>,
    total_enqueued: AtomicU64,
    total_dequeued: AtomicU64,
}

impl SpawnMailbox {
    /// Creates a new mailbox with no trace buffer attached.
    #[must_use]
    pub fn new() -> Self {
        Self {
            queue: GlobalFifoQueue::default(),
            ids: SpawnIdAllocator::new(),
            trace: None,
            total_enqueued: AtomicU64::new(0),
            total_dequeued: AtomicU64::new(0),
        }
    }

    /// Creates a new mailbox that emits `TaskSpawnEnqueued` trace events to
    /// `trace`.
    #[must_use]
    pub fn with_trace(trace: TraceBufferHandle) -> Self {
        Self {
            trace: Some(trace),
            ..Self::new()
        }
    }

    /// Allocates a provisional task id for a request bound for this mailbox.
    #[inline]
    #[must_use]
    pub fn allocate_task_id(&self) -> TaskId {
        self.ids.allocate()
    }

    /// Enqueues a spawn request.
    ///
    /// Never blocks and never drops (the queue is unbounded; see the module
    /// docs for the backpressure contract). Emits
    /// [`TraceEventKind::TaskSpawnEnqueued`] *before* publishing the request
    /// so the enqueue event is sequenced ahead of any admission-side event.
    ///
    /// `now` is the caller's current time (explicit, per the runtime-wide
    /// explicit-time idiom; exact under lab virtual time).
    pub fn enqueue(&self, request: SpawnRequest, now: Time) {
        if let Some(trace) = &self.trace {
            let task = request.task_id();
            let region = request.region();
            trace.record_event(|seq| TraceEvent::task_spawn_enqueued(seq, now, task, region));
        }
        self.queue.push(request);
        self.total_enqueued.fetch_add(1, Ordering::Relaxed);
    }

    /// Dequeues the oldest spawn request, if any.
    #[must_use]
    pub fn dequeue(&self) -> Option<SpawnRequest> {
        let request = self.queue.pop();
        if request.is_some() {
            self.total_dequeued.fetch_add(1, Ordering::Relaxed);
        }
        request
    }

    /// Dequeues up to `max` requests into `out`, preserving FIFO order.
    /// Returns the number drained.
    pub fn dequeue_batch_into(&self, max: usize, out: &mut Vec<SpawnRequest>) -> usize {
        let drained = self.queue.pop_batch_into(max, out);
        if drained > 0 {
            self.total_dequeued
                .fetch_add(drained as u64, Ordering::Relaxed);
        }
        drained
    }

    /// Best-effort snapshot of the number of queued requests.
    #[must_use]
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Returns true if the mailbox appears empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Total requests ever enqueued.
    #[must_use]
    pub fn total_enqueued(&self) -> u64 {
        self.total_enqueued.load(Ordering::Relaxed)
    }

    /// Total requests ever dequeued.
    #[must_use]
    pub fn total_dequeued(&self) -> u64 {
        self.total_dequeued.load(Ordering::Relaxed)
    }
}

impl Default for SpawnMailbox {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SpawnMailbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpawnMailbox")
            .field("len", &self.len())
            .field("total_enqueued", &self.total_enqueued())
            .field("total_dequeued", &self.total_dequeued())
            .field("has_trace", &self.trace.is_some())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::event::{TraceData, TraceEventKind};
    use crate::types::Outcome;
    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;
    use std::sync::atomic::AtomicUsize;
    use std::thread;

    fn test_region() -> RegionId {
        RegionId::from_arena(ArenaIndex::new(0, 1))
    }

    fn noop_task(id: TaskId) -> StoredTask {
        StoredTask::new_with_id(async { Outcome::Ok(()) }, id)
    }

    fn request(mailbox: &SpawnMailbox) -> SpawnRequest {
        let id = mailbox.allocate_task_id();
        SpawnRequest::new(id, test_region(), Budget::new(), noop_task(id))
    }

    #[test]
    fn fifo_order_single_thread() {
        let mailbox = SpawnMailbox::new();
        let mut expected = Vec::new();
        for _ in 0..100 {
            let req = request(&mailbox);
            expected.push(req.task_id());
            mailbox.enqueue(req, Time::ZERO);
        }
        let mut actual = Vec::new();
        while let Some(req) = mailbox.dequeue() {
            actual.push(req.task_id());
        }
        assert_eq!(actual, expected, "dequeue order must match enqueue order");
        assert!(mailbox.is_empty());
    }

    #[test]
    fn id_allocator_uniqueness_under_8_thread_contention() {
        const THREADS: usize = 8;
        const PER_THREAD: usize = 10_000;
        let allocator = Arc::new(SpawnIdAllocator::new());
        let mut handles = Vec::new();
        for _ in 0..THREADS {
            let allocator = Arc::clone(&allocator);
            handles.push(thread::spawn(move || {
                (0..PER_THREAD)
                    .map(|_| allocator.allocate().as_u64())
                    .collect::<Vec<u64>>()
            }));
        }
        let mut all = HashSet::new();
        for handle in handles {
            for id in handle.join().expect("allocator thread panicked") {
                assert!(all.insert(id), "duplicate provisional task id {id:#x}");
            }
        }
        assert_eq!(all.len(), THREADS * PER_THREAD);
    }

    #[test]
    fn provisional_ids_carry_namespace_tag() {
        let allocator = SpawnIdAllocator::new();
        for shard in 0..SPAWN_ID_SHARDS {
            let id = allocator.allocate_on(shard);
            assert!(
                is_spawn_mailbox_id(id),
                "provisional id missing namespace tag: {id:?}"
            );
        }
        let arena_id = TaskId::from_arena(ArenaIndex::new(5, 3));
        assert!(!is_spawn_mailbox_id(arena_id));
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn allocate_on_rejects_out_of_range_shard() {
        let allocator = SpawnIdAllocator::new();
        let _ = allocator.allocate_on(SPAWN_ID_SHARDS);
    }

    #[test]
    fn multi_thread_enqueue_preserves_per_producer_fifo() {
        const THREADS: usize = 8;
        const PER_THREAD: usize = 500;
        let mailbox = Arc::new(SpawnMailbox::new());
        let owners: Arc<Mutex<HashMap<u64, usize>>> = Arc::new(Mutex::new(HashMap::new()));
        let mut handles = Vec::new();
        for producer in 0..THREADS {
            let mailbox = Arc::clone(&mailbox);
            let owners = Arc::clone(&owners);
            handles.push(thread::spawn(move || {
                let mut order = Vec::with_capacity(PER_THREAD);
                for _ in 0..PER_THREAD {
                    let id = mailbox.allocate_task_id();
                    owners.lock().unwrap().insert(id.as_u64(), producer);
                    order.push(id.as_u64());
                    let req = SpawnRequest::new(id, test_region(), Budget::new(), noop_task(id));
                    mailbox.enqueue(req, Time::ZERO);
                }
                order
            }));
        }
        let mut per_producer_expected: Vec<Vec<u64>> = Vec::new();
        for handle in handles {
            per_producer_expected.push(handle.join().expect("producer thread panicked"));
        }

        let mut dequeued = Vec::new();
        while let Some(req) = mailbox.dequeue() {
            dequeued.push(req.task_id().as_u64());
        }
        assert_eq!(dequeued.len(), THREADS * PER_THREAD);

        let owners = owners.lock().unwrap();
        let mut per_producer_actual: Vec<Vec<u64>> = vec![Vec::new(); THREADS];
        for id in dequeued {
            let producer = owners[&id];
            per_producer_actual[producer].push(id);
        }
        for producer in 0..THREADS {
            assert_eq!(
                per_producer_actual[producer], per_producer_expected[producer],
                "per-producer FIFO violated for producer {producer}"
            );
        }
    }

    #[test]
    fn unbounded_mailbox_accepts_burst_without_drop() {
        // AC: full-mailbox behavior is explicit — the queue is unbounded,
        // so there is no full state and no silent drop; every enqueued
        // request is observable and drainable.
        const BURST: usize = 10_000;
        let mailbox = SpawnMailbox::new();
        for _ in 0..BURST {
            mailbox.enqueue(request(&mailbox), Time::ZERO);
        }
        assert_eq!(mailbox.len(), BURST);
        assert_eq!(mailbox.total_enqueued(), BURST as u64);
        let mut drained = 0usize;
        while mailbox.dequeue().is_some() {
            drained += 1;
        }
        assert_eq!(drained, BURST);
        assert_eq!(mailbox.total_dequeued(), BURST as u64);
        assert!(mailbox.is_empty());
    }

    #[test]
    fn task_spawn_enqueued_trace_event_emitted() {
        let trace = TraceBufferHandle::new(16);
        let mailbox = SpawnMailbox::with_trace(trace.clone());
        let req = request(&mailbox);
        let task_id = req.task_id();
        let region = req.region();
        let now = Time::from_secs(5);
        mailbox.enqueue(req, now);

        let events = trace.snapshot();
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.kind, TraceEventKind::TaskSpawnEnqueued);
        assert_eq!(event.time, now);
        match &event.data {
            TraceData::Task { task, region: r } => {
                assert_eq!(*task, task_id);
                assert_eq!(*r, region);
            }
            other => panic!("expected TraceData::Task, got {other:?}"),
        }
    }

    #[test]
    fn resolve_cancelled_invokes_completion_slot_once() {
        let mailbox = SpawnMailbox::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let seen_reason: Arc<Mutex<Option<CancelReason>>> = Arc::new(Mutex::new(None));
        let calls_in_slot = Arc::clone(&calls);
        let seen_in_slot = Arc::clone(&seen_reason);
        let id = mailbox.allocate_task_id();
        let req = SpawnRequest::new(id, test_region(), Budget::new(), noop_task(id))
            .with_unadmitted_cancel(Box::new(move |reason| {
                calls_in_slot.fetch_add(1, Ordering::SeqCst);
                *seen_in_slot.lock().unwrap() = Some(reason);
            }));
        mailbox.enqueue(req, Time::ZERO);

        let req = mailbox.dequeue().expect("request queued");
        req.resolve_cancelled(CancelReason::user("region closed before admission"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let seen = seen_reason.lock().unwrap();
        let reason = seen.as_ref().expect("slot received reason");
        assert_eq!(
            reason.message,
            Some("region closed before admission".into())
        );
    }

    #[test]
    fn resolve_cancelled_without_slot_is_noop() {
        let mailbox = SpawnMailbox::new();
        let req = request(&mailbox);
        req.resolve_cancelled(CancelReason::user("no slot attached"));
    }

    #[test]
    fn dequeue_batch_into_drains_in_order() {
        let mailbox = SpawnMailbox::new();
        let mut expected = Vec::new();
        for _ in 0..10 {
            let req = request(&mailbox);
            expected.push(req.task_id());
            mailbox.enqueue(req, Time::ZERO);
        }
        let mut batch = Vec::new();
        assert_eq!(mailbox.dequeue_batch_into(4, &mut batch), 4);
        let batch_ids: Vec<TaskId> = batch.iter().map(SpawnRequest::task_id).collect();
        assert_eq!(batch_ids, expected[..4]);
        assert_eq!(mailbox.len(), 6);
        assert_eq!(mailbox.total_dequeued(), 4);
    }

    #[test]
    fn request_preserves_region_budget_and_name() {
        let mailbox = SpawnMailbox::new();
        let id = mailbox.allocate_task_id();
        let budget = Budget::new().with_poll_quota(123).with_priority(7);
        let req = SpawnRequest::new(id, test_region(), budget, noop_task(id)).with_name("worker-a");
        mailbox.enqueue(req, Time::ZERO);

        let req = mailbox.dequeue().expect("request queued");
        assert_eq!(req.task_id(), id);
        assert_eq!(req.region(), test_region());
        assert_eq!(req.name(), Some("worker-a"));
        let parts = req.into_parts();
        assert_eq!(parts.budget, budget);
        assert!(parts.on_unadmitted_cancel.is_none());
    }
}
