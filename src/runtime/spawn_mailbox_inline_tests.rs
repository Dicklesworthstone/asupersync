    use super::*;
    use crate::runtime::state::{AdmissionTaskTarget, LocalSpawnAdmission};
    use crate::trace::event::{TraceData, TraceEventKind};
    use crate::types::Outcome;
    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::thread;

    struct CountWakes(AtomicUsize);
    impl std::task::Wake for CountWakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn region_create_failure() -> crate::runtime::region_table::RegionCreateError {
        crate::runtime::region_table::RegionCreateError::ParentNotFound(RegionId::new_for_test(
            9, 0,
        ))
    }

    /// The region slot's waiter list holds each waker once, publication wakes
    /// it exactly once, and a registration after publication wakes at once.
    #[test]
    fn region_slot_publication_wakes_each_registered_waiter_once() {
        let slot = AdmittedRegionSlot::new();
        let wakes = Arc::new(CountWakes(AtomicUsize::new(0)));
        let waker = std::task::Waker::from(Arc::clone(&wakes));
        for _ in 0..3 {
            slot.register(waker.clone());
        }
        assert_eq!(slot.waiters.lock().len(), 1, "repeated polls register once");
        assert!(slot.is_pending());
        slot.publish(Err(region_create_failure()));
        assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
        assert!(!slot.is_pending());
        slot.register(waker.clone());
        assert_eq!(
            wakes.0.load(Ordering::SeqCst),
            2,
            "late registration wakes at once"
        );
        assert!(matches!(slot.take(), Some(Err(_))));
        assert!(!slot.is_pending(), "a taken outcome is still published");
        slot.publish(Err(region_create_failure()));
        assert!(slot.take().is_none(), "later publications are ignored");
    }

    /// An abandoned slot hands back an outcome published before abandonment
    /// and stores none published after it.
    #[test]
    fn region_slot_abandonment_returns_or_discards_the_outcome() {
        let published_first = AdmittedRegionSlot::new();
        published_first.publish(Err(region_create_failure()));
        assert!(matches!(published_first.abandon(), Some(Err(_))));
        assert!(published_first.take().is_none());

        let abandoned_first = AdmittedRegionSlot::new();
        assert!(abandoned_first.abandon().is_none());
        abandoned_first.publish(Err(region_create_failure()));
        assert!(!abandoned_first.is_pending());
        assert!(abandoned_first.take().is_none(), "nobody would take it");
    }

    /// Embedded-table admission for the owner-pinned local lane, matching
    /// the production drain entry (`admit_local_spawn_request_in`).
    fn admit_local_embedded(
        state: &mut RuntimeState,
        request: LocalSpawnRequest,
    ) -> LocalSpawnAdmission {
        state.admit_local_spawn_request_in(
            request,
            &mut AdmissionTaskTarget::Embedded,
            &crate::runtime::state::AdmissionRegionTarget::Embedded,
        )
    }

    fn test_region() -> RegionId {
        RegionId::from_arena(ArenaIndex::new(0, 1))
    }

    fn noop_task(id: TaskId) -> StoredTask {
        StoredTask::new_with_id(async { Outcome::Ok(()) }, id)
    }

    fn factory_test_cx() -> crate::cx::Cx {
        crate::cx::Cx::new(
            test_region(),
            TaskId::from_arena(ArenaIndex::new(1, 1)),
            Budget::INFINITE,
        )
    }

    #[test]
    fn lazy_send_factory_contains_synchronous_panic_on_first_poll() {
        let mut task = LazyFactoryTask::new(
            Box::new(|_| -> SpawnBoxFuture { panic!("send factory panic") }),
            factory_test_cx(),
        );
        let waker = std::task::Waker::noop();
        let mut poll_cx = std::task::Context::from_waker(waker);

        match std::pin::Pin::new(&mut task).poll(&mut poll_cx) {
            Poll::Ready(Outcome::Panicked(payload)) => {
                assert_eq!(payload.message(), "send factory panic");
            }
            other => panic!("synchronous send factory panic must be contained: {other:?}"),
        }
    }

    #[test]
    fn lazy_local_factory_contains_synchronous_panic_on_first_poll() {
        let mut task = LocalLazyFactoryTask::new(
            Box::new(|_| -> LocalSpawnBoxFuture { panic!("local factory panic") }),
            factory_test_cx(),
        );
        let waker = std::task::Waker::noop();
        let mut poll_cx = std::task::Context::from_waker(waker);

        match std::pin::Pin::new(&mut task).poll(&mut poll_cx) {
            Poll::Ready(Outcome::Panicked(payload)) => {
                assert_eq!(payload.message(), "local factory panic");
            }
            other => panic!("synchronous local factory panic must be contained: {other:?}"),
        }
    }

    struct AdmissionBoundaryWake {
        attempts: Arc<AtomicUsize>,
        published: Arc<AtomicBool>,
        stored: Arc<AtomicBool>,
        scheduled: Arc<AtomicBool>,
        completed: Arc<AtomicBool>,
        reenter_scheduler: Box<dyn Fn() + Send + Sync>,
    }

    impl std::task::Wake for AdmissionBoundaryWake {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            assert!(
                self.published.load(Ordering::SeqCst),
                "cancel wake observed an unpublished admitted identity"
            );
            assert!(
                self.stored.load(Ordering::SeqCst),
                "cancel wake observed an unstored canonical task"
            );
            assert!(
                self.scheduled.load(Ordering::SeqCst),
                "cancel wake ran before the canonical task was scheduled"
            );
            (self.reenter_scheduler)();
            self.completed.store(true, Ordering::SeqCst);
        }
    }

    /// Holds the pending-reason cache write-locked until admission publishes
    /// the canonical Cx, then installs a cancellation Waker before cached
    /// reason replay snapshots the registry. This gives the tests a fully
    /// deterministic version of the producer-abort/admission race.
    fn install_cancel_waker_during_admission(
        admitted: Arc<AdmittedTaskSlot>,
        pending_reason: PendingCancelReason,
        waker: std::task::Waker,
    ) -> (Arc<std::sync::Barrier>, thread::JoinHandle<()>) {
        let cache_locked = Arc::new(std::sync::Barrier::new(2));
        let installer_barrier = Arc::clone(&cache_locked);
        let installer = thread::spawn(move || {
            let cache_guard = pending_reason.write();
            installer_barrier.wait();
            let inner = loop {
                if let Some(published) = admitted.get() {
                    break published
                        .cx_inner
                        .upgrade()
                        .expect("published admission Cx remains live");
                }
                thread::yield_now();
            };
            inner.write().cancel_waker = Some(Arc::new(
                crate::types::task_context::CancelWaker::new(waker),
            ));
            drop(cache_guard);
        });
        (cache_locked, installer)
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

    /// A denied request whose captured state panics on drop still fires
    /// its completion slot and releases its region credit, and the panic
    /// does not escape into the admission drain.
    #[test]
    fn a_denied_request_with_a_panicking_capture_still_resolves() {
        struct PanicsOnDrop;
        impl Drop for PanicsOnDrop {
            fn drop(&mut self) {
                panic!("captured state panics on drop");
            }
        }
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let handle = state
            .region(root)
            .expect("root region exists")
            .pending_spawn_handle();
        let mailbox = SpawnMailbox::new();
        for failed in [false, true] {
            let id = mailbox.allocate_task_id();
            let capture = PanicsOnDrop;
            let fired = Arc::new(AtomicUsize::new(0));
            let in_slot = Arc::clone(&fired);
            let req = SpawnRequest::new(
                id,
                root,
                Budget::new(),
                StoredTask::new_with_id(
                    async move {
                        let _capture = capture;
                        Outcome::Ok(())
                    },
                    id,
                ),
            )
            .with_pending_reservation(handle.reserve())
            .with_unadmitted_cancel(Box::new(move |_reason| {
                in_slot.fetch_add(1, Ordering::SeqCst);
            }));
            let resolved = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if failed {
                    req.into_parts()
                        .resolve_failed(crate::runtime::state::SpawnError::RegionClosed(root));
                } else {
                    req.resolve_cancelled(CancelReason::new(CancelKind::ParentCancelled));
                }
            }));
            assert!(resolved.is_ok(), "the capture's panic is contained");
            assert_eq!(fired.load(Ordering::SeqCst), 1, "the completion slot fired");
            assert_eq!(handle.count(), 0, "the region credit is released");
        }
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
        assert!(parts.pending_reservation.is_none());
    }

    // === br-asupersync-dx-core-api-v2-u1z5hn.1.2: pending-spawn accounting ===

    use crate::runtime::state::RuntimeState;
    use crate::types::CancelKind;

    /// Reservation travels inside the request; resolve_cancelled releases it
    /// strictly AFTER the cancel slot fires (decrement-after-successor-
    /// visibility): the slot must still observe the credit outstanding.
    #[test]
    fn resolve_cancelled_releases_reservation_after_slot() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let handle = state
            .region(root)
            .expect("root region exists")
            .pending_spawn_handle();

        let mailbox = SpawnMailbox::new();
        let id = mailbox.allocate_task_id();
        let count_seen_in_slot = Arc::new(AtomicUsize::new(usize::MAX));
        let seen = Arc::clone(&count_seen_in_slot);
        let handle_for_slot = Arc::clone(&handle);
        let req = SpawnRequest::new(id, root, Budget::new(), noop_task(id))
            .with_pending_reservation(handle.reserve())
            .with_unadmitted_cancel(Box::new(move |_reason| {
                seen.store(handle_for_slot.count() as usize, Ordering::SeqCst);
            }));
        assert_eq!(handle.count(), 1, "credit taken before enqueue");
        mailbox.enqueue(req, Time::ZERO);

        let req = mailbox.dequeue().expect("request queued");
        req.resolve_cancelled(CancelReason::new(CancelKind::ParentCancelled));
        assert_eq!(
            count_seen_in_slot.load(Ordering::SeqCst),
            1,
            "cancel slot must observe the credit still outstanding"
        );
        assert_eq!(handle.count(), 0, "credit released after resolve");
    }

    /// Parent AC 2(a): region close with N un-admitted spawn requests still
    /// reaches quiescence — the close path refuses to finalize while credits
    /// are outstanding, every request resolves Cancelled exactly once, and
    /// the state machine then closes the region with zero leaks.
    #[test]
    fn region_close_with_unadmitted_requests_reaches_quiescence() {
        const N: usize = 5;
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let region = state
            .create_child_region(root, Budget::INFINITE)
            .expect("child region");
        let handle = state
            .region(region)
            .expect("child region exists")
            .pending_spawn_handle();

        // Producer side (no state lock needed): reserve then enqueue.
        let mailbox = SpawnMailbox::new();
        let cancelled = Arc::new(AtomicUsize::new(0));
        for _ in 0..N {
            let id = mailbox.allocate_task_id();
            let cancelled = Arc::clone(&cancelled);
            let req = SpawnRequest::new(id, region, Budget::new(), noop_task(id))
                .with_pending_reservation(handle.reserve())
                .with_unadmitted_cancel(Box::new(move |reason| {
                    assert_eq!(reason.kind, CancelKind::ParentCancelled);
                    cancelled.fetch_add(1, Ordering::SeqCst);
                }));
            mailbox.enqueue(req, Time::ZERO);
        }
        assert_eq!(handle.count(), N as u32);

        // Begin closing the region. With credits outstanding the state
        // machine must not finalize, complete close, or report quiescence.
        state
            .region(region)
            .expect("child region exists")
            .begin_close(None);
        state.advance_region_state(region);
        assert!(
            !state.can_region_finalize(region),
            "pending spawns must block finalization"
        );
        assert!(!state.can_region_complete_close(region));
        assert!(
            !state.is_quiescent(),
            "pending spawns must block runtime quiescence"
        );
        let mid_close_state = state.region(region).expect("region exists").state();
        assert!(
            !mid_close_state.is_terminal(),
            "region must not close while requests are pending, got {mid_close_state:?}"
        );

        // Drain: the admission loop's region-closed path resolves each
        // request Cancelled (admit-then-cancel semantics land with A1.3;
        // resolve_cancelled is the never-admitted variant with identical
        // public semantics).
        let mut drained = Vec::new();
        mailbox.dequeue_batch_into(N, &mut drained);
        assert_eq!(drained.len(), N);
        for req in drained {
            req.resolve_cancelled(CancelReason::new(CancelKind::ParentCancelled));
        }
        assert_eq!(
            cancelled.load(Ordering::SeqCst),
            N,
            "all N resolved Cancelled"
        );
        assert_eq!(handle.count(), 0);

        // The state machine can now finalize and close to quiescence. A
        // fully closed region is removed from the region table, so "gone"
        // is the strongest success signal; a still-present record must be
        // terminal.
        state.advance_region_state(region);
        assert!(
            state
                .region(region)
                .is_none_or(|r| r.state() == crate::record::region::RegionState::Closed),
            "region closes once pending spawns drain"
        );
        assert!(state.is_quiescent(), "runtime quiescent after drain");
    }

    /// AC3 race matrix, interleaving 1: credit visible before the request —
    /// a close-side check between increment and publish sees the credit and
    /// refuses, so the request cannot be stranded.
    #[test]
    fn race_matrix_close_check_between_increment_and_publish() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let region = state
            .create_child_region(root, Budget::INFINITE)
            .expect("child region");
        let handle = state
            .region(region)
            .expect("region exists")
            .pending_spawn_handle();
        let mailbox = SpawnMailbox::new();

        // Producer step 1: reserve (increment) — request NOT yet published.
        let reservation = handle.reserve();

        // Closer runs its full check here: must refuse.
        state
            .region(region)
            .expect("region exists")
            .begin_close(None);
        state.advance_region_state(region);
        assert!(!state.can_region_finalize(region));
        assert!(
            !state
                .region(region)
                .expect("region exists")
                .state()
                .is_terminal()
        );

        // Producer step 2: publish.
        let id = mailbox.allocate_task_id();
        let req = SpawnRequest::new(id, region, Budget::new(), noop_task(id))
            .with_pending_reservation(reservation);
        mailbox.enqueue(req, Time::ZERO);

        // Drain resolves the request; close then completes (a fully closed
        // region is removed from the table).
        let req = mailbox.dequeue().expect("published request");
        req.resolve_cancelled(CancelReason::new(CancelKind::ParentCancelled));
        state.advance_region_state(region);
        assert!(
            state
                .region(region)
                .is_none_or(|r| r.state() == crate::record::region::RegionState::Closed),
            "region closes once the pending request drains"
        );
    }

    /// AC3 race matrix, interleaving 2: close completes first (count was 0),
    /// then a late producer reserves + enqueues. The accounting stays
    /// consistent: the late request resolves Cancelled, the counter returns
    /// to zero, and global quiescence recovers. (The closed region itself is
    /// already terminal — the admission loop's closed-region path is what
    /// cancels the request, exactly the spawn-into-closing-region semantics.)
    #[test]
    fn race_matrix_late_enqueue_after_close_resolves_cancelled() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let region = state
            .create_child_region(root, Budget::INFINITE)
            .expect("child region");
        let handle = state
            .region(region)
            .expect("region exists")
            .pending_spawn_handle();
        let mailbox = SpawnMailbox::new();

        // Close fully first. The region record is removed from the table
        // once fully closed; the counter Arc survives detached.
        state
            .region(region)
            .expect("region exists")
            .begin_close(None);
        state.advance_region_state(region);
        assert!(
            state
                .region(region)
                .is_none_or(|r| r.state() == crate::record::region::RegionState::Closed),
            "clean close completes with no credits outstanding"
        );

        // Late producer: reserve + publish against the closed region.
        let cancelled = Arc::new(AtomicUsize::new(0));
        let cancelled_in_slot = Arc::clone(&cancelled);
        let id = mailbox.allocate_task_id();
        let req = SpawnRequest::new(id, region, Budget::new(), noop_task(id))
            .with_pending_reservation(handle.reserve())
            .with_unadmitted_cancel(Box::new(move |_| {
                cancelled_in_slot.fetch_add(1, Ordering::SeqCst);
            }));
        mailbox.enqueue(req, Time::ZERO);
        // Post-removal window: once the closed region is recycled out of
        // the region table, a late detached credit is no longer visible to
        // the region-table-based quiescence predicate. Liveness for this
        // window is owned by the admission loop's closed-region fallback
        // (resolve Cancelled on next drain pass) and by A1.3 folding
        // mailbox emptiness into the scheduler's idle/quiescence decision.
        // What this slice guarantees: the request still resolves Cancelled
        // exactly once and the accounting balances.

        // Admission loop finds the region closed (gone) and cancels the
        // request.
        let req = mailbox.dequeue().expect("late request");
        req.resolve_cancelled(CancelReason::new(CancelKind::ParentCancelled));
        assert_eq!(cancelled.load(Ordering::SeqCst), 1);
        assert_eq!(handle.count(), 0);
        assert!(mailbox.is_empty());
        assert!(state.is_quiescent());
    }

    /// AC3 stress: concurrent producers (reserve + enqueue) race a drain
    /// loop. Invariant: no request is ever lost — every enqueued request is
    /// either resolved by the drain loop, and the counter balances to zero.
    #[test]
    fn race_stress_concurrent_producers_vs_drain() {
        const PRODUCERS: usize = 4;
        const PER_PRODUCER: usize = 250;
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let region = state
            .create_child_region(root, Budget::INFINITE)
            .expect("child region");
        let handle = state
            .region(region)
            .expect("region exists")
            .pending_spawn_handle();

        let mailbox = Arc::new(SpawnMailbox::new());
        let resolved = Arc::new(AtomicUsize::new(0));

        let mut producers = Vec::new();
        for _ in 0..PRODUCERS {
            let mailbox = Arc::clone(&mailbox);
            let handle = Arc::clone(&handle);
            producers.push(thread::spawn(move || {
                for _ in 0..PER_PRODUCER {
                    let id = mailbox.allocate_task_id();
                    let req = SpawnRequest::new(
                        id,
                        RegionId::from_arena(ArenaIndex::new(0, 1)),
                        Budget::new(),
                        noop_task(id),
                    )
                    .with_pending_reservation(handle.reserve());
                    mailbox.enqueue(req, Time::ZERO);
                }
            }));
        }

        // Drain loop racing the producers: keep resolving until all
        // producers are done AND the counter says nothing is outstanding.
        let drain_mailbox = Arc::clone(&mailbox);
        let drain_handle = Arc::clone(&handle);
        let drain_resolved = Arc::clone(&resolved);
        let drainer = thread::spawn(move || {
            loop {
                while let Some(req) = drain_mailbox.dequeue() {
                    req.resolve_cancelled(CancelReason::new(CancelKind::ParentCancelled));
                    drain_resolved.fetch_add(1, Ordering::SeqCst);
                }
                if drain_resolved.load(Ordering::SeqCst) == PRODUCERS * PER_PRODUCER {
                    break;
                }
                std::thread::yield_now();
                // Increment-before-visibility: a nonzero counter with an
                // empty queue means a publish is in flight — keep spinning.
                if drain_handle.count() == 0
                    && drain_mailbox.is_empty()
                    && drain_resolved.load(Ordering::SeqCst) == PRODUCERS * PER_PRODUCER
                {
                    break;
                }
            }
        });

        for p in producers {
            p.join().expect("producer panicked");
        }
        drainer.join().expect("drainer panicked");

        assert_eq!(resolved.load(Ordering::SeqCst), PRODUCERS * PER_PRODUCER);
        assert_eq!(handle.count(), 0, "all credits balanced");
        assert_eq!(handle.underflow_count(), 0);
        assert!(mailbox.is_empty());
        assert!(state.is_quiescent());
    }

    // === br-asupersync-dx-core-api-v2-u1z5hn.1.3: admission ===

    use crate::record::region::RegionLimits;
    use crate::runtime::state::{SpawnAdmission, SpawnError};
    use crate::trace::event::TraceEventKind as Kind;

    #[test]
    fn requested_cancel_reason_centrally_overrides_admission_failure_callback() {
        let mailbox = SpawnMailbox::new();
        let provisional = mailbox.allocate_task_id();
        let admitted = Arc::new(AdmittedTaskSlot::new());
        let (_result_tx, result_rx) =
            crate::channel::oneshot::channel::<Result<(), crate::runtime::JoinError>>();
        let handle =
            crate::runtime::TaskHandle::new_pending(provisional, result_rx, Arc::clone(&admitted));
        handle.abort_with_reason(CancelReason::race_loser());
        drop(handle);
        let seen_reason = Arc::new(Mutex::new(None));
        let seen_reason_slot = Arc::clone(&seen_reason);
        let admission_error_called = Arc::new(AtomicBool::new(false));
        let admission_error_slot = Arc::clone(&admission_error_called);

        SpawnRequest::new(
            provisional,
            test_region(),
            Budget::new(),
            noop_task(provisional),
        )
        .with_admitted_slot(admitted)
        .with_unadmitted_cancel(Box::new(move |reason| {
            *seen_reason_slot.lock().expect("reason lock") = Some(reason);
        }))
        .with_admission_error_slot(Box::new(move |_| {
            admission_error_slot.store(true, Ordering::SeqCst);
        }))
        .into_parts()
        .resolve_failed(SpawnError::RuntimeUnavailable);

        assert!(
            !admission_error_called.load(Ordering::SeqCst),
            "requested cancellation must route denial through the cancellation slot"
        );
        let reason = seen_reason
            .lock()
            .expect("reason lock")
            .clone()
            .expect("cancellation slot receives reason");
        assert!(reason.is_kind(CancelKind::RaceLost));
    }

    #[test]
    fn pending_cancel_reason_is_shared_within_and_isolated_between_slots() {
        let slot = Arc::new(AdmittedTaskSlot::new());
        let barrier = Arc::new(std::sync::Barrier::new(9));
        let mut initializers = Vec::new();
        for _ in 0..8 {
            let slot = Arc::clone(&slot);
            let barrier = Arc::clone(&barrier);
            initializers.push(thread::spawn(move || {
                barrier.wait();
                slot.pending_cancel_reason()
            }));
        }
        barrier.wait();
        let reasons = initializers
            .into_iter()
            .map(|initializer| initializer.join().expect("initializer completes"))
            .collect::<Vec<_>>();
        assert!(
            reasons
                .iter()
                .all(|reason| Arc::ptr_eq(reason, &reasons[0])),
            "same-slot initialization must converge on one reason cache"
        );

        *reasons[0].write() = Some(CancelReason::timeout());
        assert!(
            reasons.iter().all(|reason| reason
                .read()
                .as_ref()
                .is_some_and(|reason| reason.is_kind(CancelKind::Timeout))),
            "same-slot readers must observe the shared strongest reason"
        );

        let independent = Arc::new(AdmittedTaskSlot::new()).pending_cancel_reason();
        assert!(
            !Arc::ptr_eq(&reasons[0], &independent),
            "independent spawn slots must never share cancellation state"
        );
        assert!(independent.read().is_none());

        slot.set(AdmittedTask::published(
            TaskId::from_arena(ArenaIndex::new(9, 1)),
            Weak::new(),
        ))
        .expect("test identity publishes");
        let late_handle_reason = slot.pending_handle_cancel_reason();
        assert!(
            !Arc::ptr_eq(&reasons[0], &late_handle_reason),
            "a handle built after runnable publication keeps independent attribution"
        );
        assert!(late_handle_reason.read().is_none());
    }

    #[test]
    fn pre_admission_abort_survives_handle_drop_until_successful_admission() {
        let mut lab = LabRuntime::new(LabConfig::new(17));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let mailbox = SpawnMailbox::new();
        let provisional = mailbox.allocate_task_id();
        let admitted = Arc::new(AdmittedTaskSlot::new());
        let (_result_tx, result_rx) =
            crate::channel::oneshot::channel::<Result<(), crate::runtime::JoinError>>();
        let handle =
            crate::runtime::TaskHandle::new_pending(provisional, result_rx, Arc::clone(&admitted));
        handle.abort_with_reason(CancelReason::race_loser());
        drop(handle);

        let attempts = Arc::new(AtomicUsize::new(0));
        let published = Arc::new(AtomicBool::new(false));
        let stored = Arc::new(AtomicBool::new(false));
        let scheduled = Arc::new(AtomicBool::new(false));
        let completed = Arc::new(AtomicBool::new(false));
        let scheduler_for_wake = Arc::clone(&lab.scheduler);
        let waker = std::task::Waker::from(Arc::new(AdmissionBoundaryWake {
            attempts: Arc::clone(&attempts),
            published: Arc::clone(&published),
            stored: Arc::clone(&stored),
            scheduled: Arc::clone(&scheduled),
            completed: Arc::clone(&completed),
            reenter_scheduler: Box::new(move || {
                let scheduler = scheduler_for_wake
                    .try_lock()
                    .expect("cancel wake runs after the scheduler guard is released");
                assert!(
                    !scheduler.is_empty(),
                    "cancel wake observes the canonical task in the scheduler"
                );
            }),
        }));
        let pending_reason = admitted.pending_cancel_reason();
        let (cache_locked, installer) =
            install_cancel_waker_during_admission(Arc::clone(&admitted), pending_reason, waker);
        cache_locked.wait();

        let parts = SpawnRequest::new(provisional, root, Budget::new(), noop_task(provisional))
            .with_admitted_slot(Arc::clone(&admitted))
            .into_parts();
        let SpawnAdmission::Admitted {
            task_id,
            priority: _,
            cancel_publication,
            spawn_effects,
        } = lab.state.admit_spawn_request(parts)
        else {
            panic!("expected admission to succeed");
        };
        installer.join().expect("cancel-waker installer completes");
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            0,
            "admission neither applies nor dispatches cached cancellation"
        );

        let admitted_task = admitted.get().expect("admission publishes task identity");
        assert_eq!(admitted_task.task_id, task_id);
        assert!(!is_spawn_mailbox_id(task_id), "canonical id is published");
        assert!(
            lab.state.task(task_id).is_some(),
            "canonical task record is published before dispatch"
        );
        published.store(true, Ordering::SeqCst);
        assert!(
            lab.state.get_stored_future(task_id).is_some(),
            "Send payload is stored under the canonical id before dispatch"
        );
        stored.store(true, Ordering::SeqCst);
        let inner = admitted_task
            .cx_inner
            .upgrade()
            .expect("admitted task context remains live");
        let guard = inner.read();
        assert!(
            !guard.cancel_requested && guard.cancel_reason.is_none(),
            "cached abort remains deferred before runnable publication"
        );
        drop(guard);
        assert!(
            lab.scheduler.lock().is_empty(),
            "admission itself does not schedule or dispatch"
        );
        let cancel_wakes = cancel_publication.publish(|cancel_priority| {
            let cancel_priority = cancel_priority.expect("cached abort selects the cancel lane");
            lab.scheduler
                .lock()
                .schedule_cancel(task_id, cancel_priority);
            scheduled.store(true, Ordering::SeqCst);
        });
        assert!(
            !lab.scheduler.lock().is_empty(),
            "canonical task is scheduled before wake dispatch"
        );
        assert!(admitted_task.is_published());
        assert_eq!(
            cancel_wakes.len(),
            1,
            "runnable publication snapshots the installed boundary Waker"
        );
        let guard = inner.read();
        assert!(
            guard.cancel_requested,
            "publication replays the pending abort"
        );
        assert!(
            guard
                .cancel_reason
                .as_ref()
                .is_some_and(|reason| reason.is_kind(CancelKind::RaceLost)),
            "replayed abort preserves RaceLost attribution"
        );
        drop(guard);
        spawn_effects.dispatch();
        cancel_wakes.dispatch();
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert!(
            completed.load(Ordering::SeqCst),
            "reentrant Waker observed published, stored, scheduled state"
        );
        assert!(
            admitted
                .pending_cancel_reason()
                .read()
                .as_ref()
                .is_some_and(|reason| reason.is_kind(CancelKind::RaceLost)),
            "the slot-local cache preserves the strongest requested reason"
        );
    }

    #[test]
    fn admission_publication_uses_strongest_effective_cx_priority_under_lock() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let mailbox = SpawnMailbox::new();
        let provisional = mailbox.allocate_task_id();
        let admitted = Arc::new(AdmittedTaskSlot::new());
        let (_result_tx, result_rx) =
            crate::channel::oneshot::channel::<Result<(), crate::runtime::JoinError>>();
        let handle =
            crate::runtime::TaskHandle::new_pending(provisional, result_rx, Arc::clone(&admitted));
        handle.abort_with_reason(CancelReason::timeout());

        let parts = SpawnRequest::new(provisional, root, Budget::new(), noop_task(provisional))
            .with_admitted_slot(Arc::clone(&admitted))
            .into_parts();
        let SpawnAdmission::Admitted {
            task_id,
            cancel_publication,
            spawn_effects,
            ..
        } = state.admit_spawn_request(parts)
        else {
            panic!("expected admission");
        };
        let inner = admitted
            .get()
            .and_then(|task| task.cx_inner.upgrade())
            .expect("admitted Cx remains live");

        let (should_schedule, state_wakes) = state
            .cancel_task(task_id, &CancelReason::shutdown())
            .into_parts();
        assert!(
            !should_schedule,
            "unpublished admission delegates initial scheduling"
        );
        let publication_wakes = cancel_publication.publish(|effective_priority| {
            assert_eq!(
                effective_priority,
                Some(u8::MAX),
                "stronger Cx shutdown must outrank the cached timeout"
            );
            assert!(
                inner.try_write().is_none(),
                "effective Cx state stays locked through callback-free lane publication"
            );
        });

        let guard = inner.read();
        assert!(
            guard
                .cancel_reason
                .as_ref()
                .is_some_and(|reason| reason.is_kind(CancelKind::Shutdown)),
            "cached timeout replay cannot weaken an existing shutdown"
        );
        drop(guard);
        spawn_effects.dispatch();
        state_wakes.dispatch();
        publication_wakes.dispatch();
    }

    #[test]
    fn slotless_admission_publication_uses_effective_cx_cancel_priority() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let mailbox = SpawnMailbox::new();
        let provisional = mailbox.allocate_task_id();
        let parts = SpawnRequest::new(provisional, root, Budget::new(), noop_task(provisional))
            .into_parts();
        let SpawnAdmission::Admitted {
            task_id,
            cancel_publication,
            spawn_effects,
            ..
        } = state.admit_spawn_request(parts)
        else {
            panic!("expected admission");
        };
        let inner = cancel_publication
            .cx_inner
            .upgrade()
            .expect("slotless admission retains a live Cx");
        let (should_schedule, state_wakes) = state
            .cancel_task(task_id, &CancelReason::shutdown())
            .into_parts();
        assert!(
            !should_schedule,
            "slotless unpublished admission also delegates initial scheduling"
        );

        let publication_wakes = cancel_publication.publish(|effective_priority| {
            assert_eq!(effective_priority, Some(u8::MAX));
            assert!(
                inner.try_write().is_none(),
                "slotless publication also linearizes under the Cx write lock"
            );
        });
        spawn_effects.dispatch();
        state_wakes.dispatch();
        publication_wakes.dispatch();
    }

    #[test]
    fn region_cancel_before_admission_publication_delegates_first_lane_and_wake() {
        let mut lab = LabRuntime::new(LabConfig::new(23));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let mailbox = SpawnMailbox::new();
        let provisional = mailbox.allocate_task_id();
        let admitted = Arc::new(AdmittedTaskSlot::new());
        let parts = SpawnRequest::new(provisional, root, Budget::new(), noop_task(provisional))
            .with_admitted_slot(Arc::clone(&admitted))
            .into_parts();
        let SpawnAdmission::Admitted {
            task_id,
            cancel_publication,
            spawn_effects,
            ..
        } = lab.state.admit_spawn_request(parts)
        else {
            panic!("expected admission");
        };

        let attempts = Arc::new(AtomicUsize::new(0));
        let published = Arc::new(AtomicBool::new(false));
        let stored = Arc::new(AtomicBool::new(true));
        let scheduled = Arc::new(AtomicBool::new(false));
        let completed = Arc::new(AtomicBool::new(false));
        let scheduler_for_wake = Arc::clone(&lab.scheduler);
        let waker = std::task::Waker::from(Arc::new(AdmissionBoundaryWake {
            attempts: Arc::clone(&attempts),
            published: Arc::clone(&published),
            stored,
            scheduled: Arc::clone(&scheduled),
            completed: Arc::clone(&completed),
            reenter_scheduler: Box::new(move || {
                let scheduler = scheduler_for_wake
                    .try_lock()
                    .expect("wake runs after the scheduler guard");
                assert!(!scheduler.is_empty(), "cancel lane is already visible");
            }),
        }));
        let inner = admitted
            .get()
            .and_then(|task| task.cx_inner.upgrade())
            .expect("admitted Cx remains live");
        inner.write().cancel_waker = Some(Arc::new(crate::types::task_context::CancelWaker::new(
            waker,
        )));

        let effects = lab
            .state
            .cancel_request(root, &CancelReason::shutdown(), None);
        lab.state.defer_cancel_dispatch(effects);
        let deferred = lab.state.take_deferred_cancel_dispatches();
        assert_eq!(deferred.len(), 1);
        for effects in deferred {
            let (tasks, wakes) = effects.into_parts();
            assert!(
                tasks.is_empty(),
                "unpublished admission cannot be scheduled by another cancel publisher"
            );
            assert!(
                wakes.is_empty(),
                "unpublished cancellation delegates Waker ownership to admission"
            );
            wakes.dispatch();
        }
        assert!(lab.scheduler.lock().is_empty());
        assert_eq!(attempts.load(Ordering::SeqCst), 0);

        let publication_wakes = cancel_publication.publish(|effective_priority| {
            let priority = effective_priority.expect("cancelled task selects cancel lane");
            lab.scheduler.lock().schedule_cancel(task_id, priority);
            scheduled.store(true, Ordering::SeqCst);
        });
        assert!(admitted.get().is_some_and(AdmittedTask::is_published));
        published.store(true, Ordering::SeqCst);
        assert_eq!(publication_wakes.len(), 1);
        spawn_effects.dispatch();
        publication_wakes.dispatch();
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert!(completed.load(Ordering::SeqCst));
    }

    #[test]
    fn reasonless_cancel_state_publishes_at_fail_closed_priority() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let mailbox = SpawnMailbox::new();
        let provisional = mailbox.allocate_task_id();
        let parts = SpawnRequest::new(
            provisional,
            root,
            Budget::new().with_priority(1),
            noop_task(provisional),
        )
        .into_parts();
        let SpawnAdmission::Admitted {
            cancel_publication,
            spawn_effects,
            ..
        } = state.admit_spawn_request(parts)
        else {
            panic!("expected admission");
        };
        let inner = cancel_publication
            .cx_inner
            .upgrade()
            .expect("admission retains a live Cx");
        {
            let mut guard = inner.write();
            guard.set_cancel_requested(true);
            guard.cancel_reason = None;
        }

        let publication_wakes = cancel_publication.publish(|effective_priority| {
            assert_eq!(
                effective_priority,
                Some(u8::MAX),
                "reasonless cancellation must fail closed, not inherit ready priority"
            );
            assert!(inner.try_write().is_none());
        });
        spawn_effects.dispatch();
        publication_wakes.dispatch();
    }

    /// Successful admission: provisional id replaced by a canonical arena
    /// id, task joins the region's task list, future stored, credit
    /// released, Spawn + TaskAdmitted trace events emitted in order after
    /// the enqueue event.
    #[test]
    fn admit_spawn_request_success_end_to_end() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let handle = state
            .region(root)
            .expect("root region exists")
            .pending_spawn_handle();

        let mailbox = SpawnMailbox::with_trace(state.trace_handle());
        let provisional = mailbox.allocate_task_id();
        let req = SpawnRequest::new(provisional, root, Budget::new(), noop_task(provisional))
            .with_pending_reservation(handle.reserve());
        mailbox.enqueue(req, Time::ZERO);

        let parts = mailbox.dequeue().expect("queued").into_parts();
        let admission = state.admit_spawn_request(parts);
        let SpawnAdmission::Admitted {
            task_id,
            priority,
            cancel_publication,
            spawn_effects,
        } = admission
        else {
            panic!("expected admission to succeed");
        };
        assert!(
            !is_spawn_mailbox_id(task_id),
            "admitted id must be a canonical arena id, got {task_id:?}"
        );
        assert_eq!(priority, Budget::new().priority);
        assert_eq!(handle.count(), 0, "credit released after admission");
        assert_eq!(
            state.region(root).expect("root exists").task_count(),
            1,
            "task joined the region"
        );
        assert!(
            state.get_stored_future(task_id).is_some(),
            "future stored under the arena id"
        );
        let cancel_wakes = cancel_publication.publish(|_| {});
        spawn_effects.dispatch();
        cancel_wakes.dispatch();

        let kinds: Vec<Kind> = state
            .trace_handle()
            .snapshot()
            .iter()
            .map(|e| e.kind)
            .filter(|k| {
                matches!(
                    k,
                    Kind::TaskSpawnEnqueued | Kind::Spawn | Kind::TaskAdmitted
                )
            })
            .collect();
        assert_eq!(
            kinds,
            vec![Kind::TaskSpawnEnqueued, Kind::Spawn, Kind::TaskAdmitted],
            "admission trace ordering"
        );
    }

    /// E1.2 (br-asupersync-sched-hot-path-perf-bt4y5f.2.2): external-table
    /// admission mints the record, its `Cx` wiring, and the stored future in
    /// the external sharded table; the embedded table never sees the task,
    /// while region bookkeeping (Shard B) stays on the unified state.
    #[test]
    fn admit_spawn_request_external_table_mints_externally() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let handle = state
            .region(root)
            .expect("root region exists")
            .pending_spawn_handle();

        let external = crate::sync::ContendedMutex::new(
            "external-tasks",
            crate::runtime::task_table::TaskTable::new(),
        );

        let mailbox = SpawnMailbox::with_trace(state.trace_handle());
        let provisional = mailbox.allocate_task_id();
        let req = SpawnRequest::new(provisional, root, Budget::new(), noop_task(provisional))
            .with_pending_reservation(handle.reserve());
        mailbox.enqueue(req, Time::ZERO);

        let parts = mailbox.dequeue().expect("queued").into_parts();
        let admission = {
            let mut target = crate::runtime::state::AdmissionTaskTarget::External(
                external
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            );
            state.admit_spawn_request_in(
                parts,
                &mut target,
                &crate::runtime::state::AdmissionRegionTarget::Embedded,
            )
        };
        let SpawnAdmission::Admitted {
            task_id,
            cancel_publication,
            spawn_effects,
            ..
        } = admission
        else {
            panic!("expected admission to succeed");
        };

        assert_eq!(handle.count(), 0, "credit released after admission");
        assert_eq!(
            state.region(root).expect("root exists").task_count(),
            1,
            "region bookkeeping stays on the unified state (Shard B)"
        );
        assert!(
            state.task(task_id).is_none(),
            "embedded table must not mint the external task"
        );
        assert!(
            state.get_stored_future(task_id).is_none(),
            "embedded table must not store the external future"
        );
        {
            let mut tt = external
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(
                tt.task(task_id).is_some_and(|record| record.cx.is_some()),
                "record minted externally with Cx wired"
            );
            assert!(
                tt.get_stored_future(task_id).is_some(),
                "future stored under the arena id in the external table"
            );
        }
        let cancel_wakes = cancel_publication.publish(|_| {});
        spawn_effects.dispatch();
        cancel_wakes.dispatch();
    }

    /// E1.2 (br-asupersync-sched-hot-path-perf-bt4y5f.2.2): when region
    /// admission fails after the record was minted externally, rollback
    /// recycles the record from the external table — no orphan record may
    /// survive in either table.
    #[test]
    fn admit_spawn_request_external_table_rollback_recycles_externally() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        state.region(root).expect("root region exists").set_limits(
            crate::record::region::RegionLimits {
                max_tasks: Some(0),
                ..crate::record::region::RegionLimits::UNLIMITED
            },
        );
        let handle = state
            .region(root)
            .expect("root region exists")
            .pending_spawn_handle();

        let external = crate::sync::ContendedMutex::new(
            "external-tasks",
            crate::runtime::task_table::TaskTable::new(),
        );

        let mailbox = SpawnMailbox::new();
        let provisional = mailbox.allocate_task_id();
        let req = SpawnRequest::new(provisional, root, Budget::new(), noop_task(provisional))
            .with_pending_reservation(handle.reserve());
        mailbox.enqueue(req, Time::ZERO);

        let parts = mailbox.dequeue().expect("queued").into_parts();
        let admission = {
            let mut target = crate::runtime::state::AdmissionTaskTarget::External(
                external
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            );
            state.admit_spawn_request_in(
                parts,
                &mut target,
                &crate::runtime::state::AdmissionRegionTarget::Embedded,
            )
        };
        let SpawnAdmission::Denied { parts, error } = admission else {
            panic!("expected capacity denial");
        };
        assert!(
            matches!(&error, SpawnError::RegionAtCapacity { region, .. } if *region == root),
            "expected RegionAtCapacity, got {error:?}"
        );
        assert!(
            external
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty(),
            "rollback must recycle the externally minted record"
        );
        assert!(state.tasks_is_empty(), "embedded table untouched");
        parts.resolve_failed(error);
        assert_eq!(handle.count(), 0, "credit balanced after denial");
    }

    /// RegionClosed denial: admission returns the parts; resolving them
    /// cancelled fires the cancel slot and balances the credit.
    #[test]
    fn admit_spawn_request_region_closed_resolves_cancelled() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let region = state
            .create_child_region(root, Budget::INFINITE)
            .expect("child region");
        let handle = state
            .region(region)
            .expect("region exists")
            .pending_spawn_handle();

        let mailbox = SpawnMailbox::new();
        let cancelled = Arc::new(AtomicUsize::new(0));
        let cancelled_slot = Arc::clone(&cancelled);
        let id = mailbox.allocate_task_id();
        let req = SpawnRequest::new(id, region, Budget::new(), noop_task(id))
            .with_pending_reservation(handle.reserve())
            .with_unadmitted_cancel(Box::new(move |_| {
                cancelled_slot.fetch_add(1, Ordering::SeqCst);
            }));
        mailbox.enqueue(req, Time::ZERO);

        // Close begins; the region can no longer accept work.
        state
            .region(region)
            .expect("region exists")
            .begin_close(None);

        let parts = mailbox.dequeue().expect("queued").into_parts();
        let SpawnAdmission::Denied { parts, error } = state.admit_spawn_request(parts) else {
            panic!("expected denial for closing region");
        };
        assert!(matches!(error, SpawnError::RegionClosed(r) if r == region));
        // Caller resolves after releasing the (conceptual) lock.
        parts.resolve_cancelled(CancelReason::new(CancelKind::ParentCancelled));
        assert_eq!(cancelled.load(Ordering::SeqCst), 1);
        assert_eq!(handle.count(), 0);
        // The denied task never entered the region.
        assert_eq!(state.region(region).expect("region exists").task_count(), 0);
    }

    /// Quota denial: region at capacity routes through resolve_failed and
    /// the admission-error slot receives SpawnError::RegionAtCapacity.
    #[test]
    fn admit_spawn_request_quota_resolves_failed() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let region = state
            .create_child_region(root, Budget::INFINITE)
            .expect("child region");
        state
            .region(region)
            .expect("region exists")
            .set_limits(RegionLimits {
                max_tasks: Some(0),
                ..RegionLimits::UNLIMITED
            });
        let handle = state
            .region(region)
            .expect("region exists")
            .pending_spawn_handle();

        let mailbox = SpawnMailbox::new();
        let failed: Arc<Mutex<Option<SpawnError>>> = Arc::new(Mutex::new(None));
        let failed_slot = Arc::clone(&failed);
        let id = mailbox.allocate_task_id();
        let req = SpawnRequest::new(id, region, Budget::new(), noop_task(id))
            .with_pending_reservation(handle.reserve())
            .with_admission_error_slot(Box::new(move |err| {
                *failed_slot.lock().unwrap() = Some(err);
            }));
        mailbox.enqueue(req, Time::ZERO);

        let parts = mailbox.dequeue().expect("queued").into_parts();
        let SpawnAdmission::Denied { parts, error } = state.admit_spawn_request(parts) else {
            panic!("expected quota denial");
        };
        assert!(matches!(error, SpawnError::RegionAtCapacity { .. }));
        parts.resolve_failed(error);
        let seen = failed.lock().unwrap();
        assert!(
            matches!(
                seen.as_ref(),
                Some(SpawnError::RegionAtCapacity { limit: 0, .. })
            ),
            "error slot received the capacity error, got {seen:?}"
        );
        assert_eq!(handle.count(), 0);
    }

    /// Parent AC 2(b): admission order is mailbox FIFO and replay-stable —
    /// two identical runs produce identical trace fingerprints (event kind
    /// sequence + task/region ids) and identical arena id assignment.
    #[test]
    fn admission_order_deterministic_across_identical_runs() {
        fn run_once() -> Vec<(Kind, u64, u64)> {
            const K: usize = 8;
            let mut state = RuntimeState::new();
            let root = state.create_root_region(Budget::INFINITE);
            let handle = state
                .region(root)
                .expect("root exists")
                .pending_spawn_handle();
            let mailbox = SpawnMailbox::with_trace(state.trace_handle());
            for _ in 0..K {
                let id = mailbox.allocate_task_id();
                let req = SpawnRequest::new(id, root, Budget::new(), noop_task(id))
                    .with_pending_reservation(handle.reserve());
                mailbox.enqueue(req, Time::ZERO);
            }
            // Drain in batches to exercise the batch path too.
            let mut batch = Vec::new();
            while mailbox.dequeue_batch_into(3, &mut batch) > 0 {}
            for req in batch {
                match state.admit_spawn_request(req.into_parts()) {
                    SpawnAdmission::Admitted {
                        cancel_publication,
                        spawn_effects,
                        ..
                    } => {
                        let cancel_wakes = cancel_publication.publish(|_| {});
                        spawn_effects.dispatch();
                        cancel_wakes.dispatch();
                    }
                    SpawnAdmission::Denied { .. } => panic!("unexpected denial"),
                }
            }
            state
                .trace_handle()
                .snapshot()
                .iter()
                .filter(|e| {
                    matches!(
                        e.kind,
                        Kind::TaskSpawnEnqueued | Kind::Spawn | Kind::TaskAdmitted
                    )
                })
                .map(|e| {
                    let (task, region) = match &e.data {
                        crate::trace::event::TraceData::Task { task, region } => {
                            (task.as_u64(), region.as_u64())
                        }
                        other => panic!("unexpected trace data {other:?}"),
                    };
                    (e.kind, task, region)
                })
                .collect()
        }

        let first = run_once();
        let second = run_once();
        assert_eq!(
            first.len(),
            8 * 3,
            "K enqueue + K spawn + K admitted events"
        );
        assert_eq!(first, second, "replay fingerprint must be identical");
    }

    /// End-to-end: a real multi-worker runtime in mailbox admission mode
    /// spawns futures through the lock-free intake, workers admit them at
    /// dispatch time, and every join handle resolves with the task's value.
    /// Also exercises the parked-fleet wakeup (notify_spawn_enqueued) since
    /// workers may be idle when the producer enqueues.
    #[test]
    fn mailbox_mode_runtime_spawns_and_joins_end_to_end() {
        const TASKS: usize = 50;
        let runtime = crate::runtime::builder::RuntimeBuilder::new()
            .worker_threads(2)
            .spawn_admission(crate::runtime::config::SpawnAdmissionMode::Mailbox)
            .build()
            .expect("build mailbox-mode runtime");
        let handle = runtime.handle();

        let counter = Arc::new(AtomicUsize::new(0));
        let mut joins = Vec::new();
        for i in 0..TASKS {
            let counter = Arc::clone(&counter);
            joins.push(handle.spawn(async move {
                counter.fetch_add(1, Ordering::SeqCst);
                i
            }));
        }
        for (i, join) in joins.into_iter().enumerate() {
            let value = runtime.block_on(join);
            assert_eq!(value, i, "join handle resolves with the task value");
        }
        assert_eq!(counter.load(Ordering::SeqCst), TASKS);
    }

    // === br-asupersync-4h8lye (A2.1): factory spawns + lab drain ===

    use crate::lab::{LabConfig, LabRuntime};

    fn factory_request(
        mailbox: &SpawnMailbox,
        region: RegionId,
        ran: &Arc<AtomicUsize>,
        completed: &Arc<AtomicUsize>,
    ) -> SpawnRequest {
        let id = mailbox.allocate_task_id();
        let ran = Arc::clone(ran);
        let completed = Arc::clone(completed);
        SpawnRequest::new_with_factory(
            id,
            region,
            Budget::new(),
            Box::new(move |cx: crate::cx::Cx| {
                ran.fetch_add(1, Ordering::SeqCst);
                assert!(
                    !is_spawn_mailbox_id(cx.task_id()),
                    "factory must receive the admission-built Cx with the \
                     canonical arena id, got {:?}",
                    cx.task_id()
                );
                Box::pin(async move {
                    completed.fetch_add(1, Ordering::SeqCst);
                    Outcome::Ok(())
                })
            }),
        )
    }

    /// The factory runs at the task's FIRST POLL on the lab step loop —
    /// not during admission under the state lock.
    #[test]
    fn factory_runs_at_first_poll_not_at_admission() {
        let mut lab = LabRuntime::new(LabConfig::new(7));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let handle = lab
            .state
            .region(root)
            .expect("root exists")
            .pending_spawn_handle();
        let mailbox = lab.spawn_mailbox();

        let ran = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(AtomicUsize::new(0));
        let req = factory_request(&mailbox, root, &ran, &completed)
            .with_pending_reservation(handle.reserve());
        mailbox.enqueue(req, Time::ZERO);

        // Admit WITHOUT polling: drain directly against state.
        let parts = mailbox.dequeue().expect("queued").into_parts();
        let admission = lab.state.admit_spawn_request(parts);
        let crate::runtime::state::SpawnAdmission::Admitted {
            task_id,
            priority,
            cancel_publication,
            spawn_effects,
        } = admission
        else {
            panic!("expected admission");
        };
        assert_eq!(
            ran.load(Ordering::SeqCst),
            0,
            "factory must NOT run during admission"
        );

        // Schedule + run: factory fires on first poll, future completes.
        let cancel_wakes = cancel_publication.publish(|cancel_priority| {
            assert!(cancel_priority.is_none());
            lab.scheduler.lock().schedule(task_id, priority);
        });
        spawn_effects.dispatch();
        cancel_wakes.dispatch();
        lab.run_until_quiescent();
        assert_eq!(ran.load(Ordering::SeqCst), 1, "factory ran exactly once");
        assert_eq!(completed.load(Ordering::SeqCst), 1, "task completed");
    }

    /// Admission fills the producer-shared admitted slot with the arena id
    /// and a live Cx weak handle.
    #[test]
    fn admitted_slot_filled_with_canonical_identity() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let mailbox = SpawnMailbox::new();
        let slot = Arc::new(AdmittedTaskSlot::new());
        let ran = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(AtomicUsize::new(0));
        let req =
            factory_request(&mailbox, root, &ran, &completed).with_admitted_slot(Arc::clone(&slot));
        let provisional = req.task_id();
        mailbox.enqueue(req, Time::ZERO);

        let parts = mailbox.dequeue().expect("queued").into_parts();
        let crate::runtime::state::SpawnAdmission::Admitted {
            task_id,
            cancel_publication,
            spawn_effects,
            ..
        } = state.admit_spawn_request(parts)
        else {
            panic!("expected admission");
        };
        let admitted = slot.get().expect("slot filled at admission");
        assert_eq!(admitted.task_id, task_id);
        assert_ne!(
            admitted.task_id, provisional,
            "arena id replaces provisional"
        );
        assert!(
            admitted.cx_inner.upgrade().is_some(),
            "cx weak handle is live while the task exists"
        );
        let cancel_wakes = cancel_publication.publish(|_| {});
        spawn_effects.dispatch();
        cancel_wakes.dispatch();
    }

    #[test]
    fn reused_admitted_slot_denies_send_before_runtime_state_mutation() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let pending = state.region(root).expect("root").pending_spawn_handle();
        let mailbox = SpawnMailbox::new();
        let slot = Arc::new(AdmittedTaskSlot::new());
        assert!(slot.try_reserve(), "model an in-flight slot owner");
        let factory_runs = Arc::new(AtomicUsize::new(0));
        let factory_completions = Arc::new(AtomicUsize::new(0));
        let observed_error = Arc::new(Mutex::new(None));
        let observed_error_slot = Arc::clone(&observed_error);
        let request = factory_request(&mailbox, root, &factory_runs, &factory_completions)
            .with_admitted_slot(Arc::clone(&slot))
            .with_pending_reservation(pending.reserve())
            .with_admission_error_slot(Box::new(move |error| {
                *observed_error_slot.lock().expect("error lock") = Some(error);
            }));
        let provisional = request.task_id();

        let live_before = state.live_task_count();
        let region_tasks_before = state.region(root).expect("root").task_count();
        let trace_before = state.trace_handle().snapshot().len();
        let validator_before = state.cancel_protocol_validator().lock().stats();
        let SpawnAdmission::Denied { parts, error } =
            state.admit_spawn_request(request.into_parts())
        else {
            panic!("reused slot must be denied");
        };
        assert!(matches!(
            error,
            SpawnError::AdmissionSlotAlreadyReserved { task_id }
                if task_id == provisional
        ));
        assert_eq!(error.code(), "ASUP-E008");
        assert_eq!(state.live_task_count(), live_before);
        assert_eq!(
            state.region(root).expect("root").task_count(),
            region_tasks_before
        );
        assert_eq!(state.trace_handle().snapshot().len(), trace_before);
        assert_eq!(
            state.cancel_protocol_validator().lock().stats(),
            validator_before
        );
        assert_eq!(
            pending.count(),
            1,
            "denial resolution still owns the credit"
        );
        assert!(
            slot.get().is_none(),
            "loser cannot overwrite the owner slot"
        );

        parts.resolve_failed(error.clone());
        assert_eq!(pending.count(), 0, "denial releases the credit last");
        assert_eq!(factory_runs.load(Ordering::SeqCst), 0);
        assert_eq!(factory_completions.load(Ordering::SeqCst), 0);
        assert_eq!(
            observed_error.lock().expect("error lock").as_ref(),
            Some(&error)
        );
    }

    /// Lab step loop drains the mailbox FIFO and runs factory tasks to
    /// completion; two identical runs produce identical admitted ids.
    #[test]
    fn lab_step_drains_factory_spawns_deterministically() {
        fn run_once() -> (usize, Vec<u64>) {
            const K: usize = 6;
            let mut lab = LabRuntime::new(LabConfig::new(11));
            let root = lab.state.create_root_region(Budget::INFINITE);
            let handle = lab
                .state
                .region(root)
                .expect("root exists")
                .pending_spawn_handle();
            let mailbox = lab.spawn_mailbox();
            let ran = Arc::new(AtomicUsize::new(0));
            let completed = Arc::new(AtomicUsize::new(0));
            let mut slots = Vec::new();
            for _ in 0..K {
                let slot = Arc::new(AdmittedTaskSlot::new());
                let req = factory_request(&mailbox, root, &ran, &completed)
                    .with_pending_reservation(handle.reserve())
                    .with_admitted_slot(Arc::clone(&slot));
                mailbox.enqueue(req, Time::ZERO);
                slots.push(slot);
            }
            // The mailbox gates quiescence via pending credits, so a plain
            // run_until_quiescent drives admission + execution end to end.
            lab.run_until_quiescent();
            assert_eq!(completed.load(Ordering::SeqCst), K);
            assert_eq!(handle.count(), 0, "credits balanced after admission");
            let ids = slots
                .iter()
                .map(|s| s.get().expect("admitted").task_id.as_u64())
                .collect();
            (ran.load(Ordering::SeqCst), ids)
        }

        let (ran_a, ids_a) = run_once();
        let (ran_b, ids_b) = run_once();
        assert_eq!(ran_a, 6);
        assert_eq!(ran_b, 6);
        assert_eq!(ids_a, ids_b, "admitted arena ids replay-identical");
    }

    /// Cancel-before-admission with a factory payload: the factory is
    /// dropped uninvoked and the cancel slot fires.
    #[test]
    fn factory_request_cancelled_before_admission_never_runs() {
        let mailbox = SpawnMailbox::new();
        let ran = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(AtomicUsize::new(0));
        let cancelled = Arc::new(AtomicUsize::new(0));
        let cancelled_slot = Arc::clone(&cancelled);
        let req = factory_request(&mailbox, test_region(), &ran, &completed)
            .with_unadmitted_cancel(Box::new(move |_| {
                cancelled_slot.fetch_add(1, Ordering::SeqCst);
            }));
        mailbox.enqueue(req, Time::ZERO);

        let req = mailbox.dequeue().expect("queued");
        req.resolve_cancelled(CancelReason::new(CancelKind::ParentCancelled));
        assert_eq!(ran.load(Ordering::SeqCst), 0, "factory never invoked");
        assert_eq!(cancelled.load(Ordering::SeqCst), 1);
    }

    // === br-asupersync-hwjqyo (A2.2): Cx::spawn public surface ===

    /// Builds a lab + a live parent task Cx (gateway/counter attached at
    /// Cx construction) and returns both plus the parent task id.
    fn lab_with_parent_cx() -> (LabRuntime, crate::cx::Cx, RegionId) {
        let mut lab = LabRuntime::new(LabConfig::new(21));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let system_cx = lab.state.create_system_cx();
        let (parent_tid, _handle, parent_cx, _result_tx, spawn_effects) = lab
            .state
            .create_task_infrastructure::<()>(&system_cx, root, Budget::new(), false)
            .expect("parent task");
        lab.state.store_spawned_task(
            parent_tid,
            StoredTask::new_with_id(async { Outcome::Ok(()) }, parent_tid),
        );
        lab.scheduler.lock().schedule(parent_tid, 0);
        spawn_effects.dispatch();
        (lab, parent_cx, root)
    }

    #[derive(Debug)]
    struct PanickingChildEntropy;

    impl crate::util::EntropySource for PanickingChildEntropy {
        fn fill_bytes(&self, dest: &mut [u8]) {
            dest.fill(0);
        }

        fn next_u64(&self) -> u64 {
            0
        }

        fn fork(&self, _: TaskId) -> Arc<dyn crate::util::EntropySource> {
            panic!("inherited entropy fork panic");
        }

        fn source_id(&self) -> &'static str {
            "panicking-child"
        }
    }

    #[derive(Debug)]
    struct ParentEntropySeed;

    impl crate::util::EntropySource for ParentEntropySeed {
        fn fill_bytes(&self, dest: &mut [u8]) {
            dest.fill(0);
        }

        fn next_u64(&self) -> u64 {
            0
        }

        fn fork(&self, _: TaskId) -> Arc<dyn crate::util::EntropySource> {
            Arc::new(PanickingChildEntropy)
        }

        fn source_id(&self) -> &'static str {
            "parent-seed"
        }
    }

    fn lab_with_panicking_parent_entropy() -> (LabRuntime, crate::cx::Cx) {
        let mut lab = LabRuntime::new(LabConfig::new(22));
        lab.state.set_entropy_source(Arc::new(ParentEntropySeed));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let system_cx = lab.state.create_system_cx();
        let (parent_tid, _handle, parent_cx, _result_tx, spawn_effects) = lab
            .state
            .create_task_infrastructure::<()>(&system_cx, root, Budget::new(), false)
            .expect("parent task");
        lab.state.store_spawned_task(
            parent_tid,
            StoredTask::new_with_id(async { Outcome::Ok(()) }, parent_tid),
        );
        lab.scheduler.lock().schedule(parent_tid, 0);
        spawn_effects.dispatch();
        (lab, parent_cx)
    }

    /// Cx::spawn end to end under the lab: no RuntimeState at the call
    /// site, factory child runs, handle exposes the canonical arena id.
    #[test]
    fn cx_spawn_runs_child_without_runtime_state() {
        let (mut lab, parent_cx, root) = lab_with_parent_cx();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_in_child = Arc::clone(&counter);
        let handle = parent_cx
            .spawn(move |_child| async move {
                counter_in_child.fetch_add(1, Ordering::SeqCst);
                42usize
            })
            .expect("cx.spawn");
        assert!(
            is_spawn_mailbox_id(handle.task_id()),
            "pre-admission handle reports the provisional id"
        );
        lab.run_until_quiescent();
        assert_eq!(counter.load(Ordering::SeqCst), 1, "child ran");
        assert!(
            !is_spawn_mailbox_id(handle.task_id()),
            "post-admission handle reports the arena id"
        );
        assert_eq!(
            lab.state.region(root).expect("root").pending_spawn_count(),
            0,
            "credits balanced"
        );
    }

    #[test]
    fn cx_spawn_synchronous_factory_panic_resolves_join_panicked() {
        let (mut lab, parent_cx, _root) = lab_with_parent_cx();
        let mut handle = parent_cx
            .spawn(|_child| -> std::future::Ready<()> { panic!("synchronous send factory panic") })
            .expect("cx.spawn enqueues the lazy factory");

        match poll_join_with_lab(&mut lab, &parent_cx, &mut handle) {
            Err(crate::runtime::task_handle::JoinError::Panicked(payload)) => {
                assert_eq!(payload.message(), "synchronous send factory panic");
            }
            other => panic!("synchronous send factory panic must reach the handle: {other:?}"),
        }
    }

    #[test]
    fn cx_spawn_inheritance_panic_resolves_join_panicked() {
        let (mut lab, parent_cx) = lab_with_panicking_parent_entropy();
        let mut handle = parent_cx
            .spawn(|_child| async move { 7usize })
            .expect("cx.spawn enqueues before inheritance runs");

        match poll_join_with_lab(&mut lab, &parent_cx, &mut handle) {
            Err(crate::runtime::task_handle::JoinError::Panicked(payload)) => {
                assert_eq!(payload.message(), "inherited entropy fork panic");
            }
            other => panic!("inheritance panic must reach the public handle: {other:?}"),
        }
    }

    /// The shared `Cx::spawn` / `Cx::spawn_in` gateway path must emit the
    /// same enqueue trace event as the direct mailbox and local-spawn paths.
    #[test]
    fn cx_spawn_gateway_paths_emit_task_spawn_enqueued_trace_events() {
        let (mut lab, parent_cx, root) = lab_with_parent_cx();
        let trace = lab.state.trace_handle();

        let root_handle = parent_cx
            .spawn(|_child| async move { 11usize })
            .expect("cx.spawn");
        let root_provisional = root_handle.task_id();

        let child_region = lab
            .state
            .create_child_region(root, Budget::INFINITE)
            .expect("child region");
        let scope: crate::cx::Scope<'static> =
            crate::cx::Scope::new(child_region, Budget::INFINITE).with_pending_spawn_counter(
                lab.state
                    .region(child_region)
                    .map(crate::record::RegionRecord::pending_spawn_handle),
            );
        let scoped_handle = parent_cx
            .spawn_in(&scope, |_child| async move { 22usize })
            .expect("cx.spawn_in");
        let scoped_provisional = scoped_handle.task_id();

        let events = trace.snapshot();
        for (expected_task, expected_region) in
            [(root_provisional, root), (scoped_provisional, child_region)]
        {
            let matches = events
                .iter()
                .filter(|event| {
                    event.kind == TraceEventKind::TaskSpawnEnqueued
                        && matches!(
                            &event.data,
                            TraceData::Task { task, region }
                                if *task == expected_task && *region == expected_region
                        )
                })
                .count();
            assert_eq!(
                matches, 1,
                "gateway enqueue for {expected_task:?} in {expected_region:?} must be traced exactly once"
            );
        }

        lab.run_until_quiescent();
    }

    /// Deep child: the factory-built child Cx carries the gateway and its
    /// region counter, so it can spawn a grandchild the same way.
    #[test]
    fn cx_spawn_from_factory_child_spawns_grandchild() {
        let (mut lab, parent_cx, _root) = lab_with_parent_cx();
        let grandchild_ran = Arc::new(AtomicUsize::new(0));
        let flag = Arc::clone(&grandchild_ran);
        let _child_handle = parent_cx
            .spawn(move |child| async move {
                let flag_inner = Arc::clone(&flag);
                child
                    .spawn(move |_grandchild| async move {
                        flag_inner.fetch_add(1, Ordering::SeqCst);
                    })
                    .expect("grandchild spawn from factory-built cx");
            })
            .expect("child spawn");
        lab.run_until_quiescent();
        assert_eq!(grandchild_ran.load(Ordering::SeqCst), 1);
    }

    /// A Cx built without runtime wiring (test-internals constructor) has
    /// no gateway: spawn errs with RuntimeUnavailable and never panics.
    #[test]
    fn cx_spawn_without_gateway_returns_runtime_unavailable() {
        let cx: crate::cx::Cx = crate::cx::Cx::new(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 1),
            Budget::new(),
        );
        let result = cx.spawn(|_child| async {});
        assert!(matches!(result, Err(SpawnError::RuntimeUnavailable)));
    }

    /// A retained runtime-wired Cx must fail closed after its runtime drops:
    /// no panic, no orphaned mailbox enqueue, no pending-spawn credit.
    #[test]
    fn cx_spawn_after_runtime_drop_returns_runtime_unavailable() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("runtime build");
        let parent_cx = runtime.block_on(
            runtime
                .handle()
                .spawn(async { crate::cx::Cx::current().expect("runtime task Cx") }),
        );
        let gateway = parent_cx
            .spawn_gateway_handle()
            .expect("runtime task Cx carries spawn gateway");
        let total_enqueued = gateway.mailbox().total_enqueued();

        drop(runtime);

        assert!(
            !gateway.is_runtime_available(),
            "dropping the runtime must expire the gateway liveness token"
        );
        let result = parent_cx.spawn(|_child| async { 7usize });
        assert!(matches!(result, Err(SpawnError::RuntimeUnavailable)));
        assert_eq!(
            gateway.mailbox().total_enqueued(),
            total_enqueued,
            "post-drop Cx::spawn must not publish orphaned mailbox work"
        );
    }

    #[test]
    fn spawn_drop_race_liveness_guard_extends_publication_window() {
        use crate::runtime::task_handle::JoinError;

        let mailbox = Arc::new(SpawnMailbox::new());
        let liveness = Arc::new(());
        let gateway = SpawnGateway::new(
            Arc::clone(&mailbox),
            Arc::new(|| {}),
            None,
            Arc::downgrade(&liveness),
        );
        let guard = gateway
            .liveness_guard()
            .expect("runtime liveness should upgrade before drop starts");
        drop(liveness);

        assert!(
            gateway.is_runtime_available(),
            "a held producer guard keeps the runtime publication window visible"
        );

        let (tx, mut rx) = crate::channel::oneshot::channel::<Result<(), JoinError>>();
        let request = request(&mailbox).with_admission_error_slot(Box::new(move |error| {
            let mut reason = CancelReason::user("spawn admission failed");
            reason.message = Some(error.to_string());
            let _ = tx.send_blocking(Err(JoinError::Cancelled(reason)));
        }));
        gateway
            .enqueue_and_notify(request)
            .expect("held liveness guard should permit publication");
        drop(guard);

        assert!(
            !gateway.is_runtime_available(),
            "dropping the last producer guard expires the gateway"
        );
        let queued = mailbox.dequeue().expect("request was published");
        queued
            .into_parts()
            .resolve_failed(SpawnError::RuntimeUnavailable);
        assert!(
            matches!(rx.try_recv(), Ok(Err(JoinError::Cancelled(_)))),
            "final mailbox drain must resolve the caller-visible handle"
        );
    }

    #[test]
    fn expired_liveness_abandons_managed_pre_admission_spawn_observer() {
        let metrics =
            crate::runtime::state::spawn_observer_test_support::PanickingSpawnMetrics::new();
        let mut state = crate::runtime::state::RuntimeState::new_with_metrics(metrics.clone());
        let root = state.create_root_region(Budget::INFINITE);
        let mailbox = Arc::new(SpawnMailbox::new());
        let liveness = Arc::new(());
        let gateway = Arc::new(SpawnGateway::new(
            Arc::clone(&mailbox),
            Arc::new(|| {}),
            None,
            Arc::downgrade(&liveness),
        ));
        let admitted = Arc::new(AdmittedTaskSlot::new_with_cancel_gateway(Arc::clone(
            &gateway,
        )));
        let provisional = mailbox.allocate_task_id();
        let parts = SpawnRequest::new(provisional, root, Budget::new(), noop_task(provisional))
            .with_admitted_slot(Arc::clone(&admitted))
            .into_parts();
        let SpawnAdmission::Admitted {
            cancel_publication: publication,
            spawn_effects,
            ..
        } = state.admit_spawn_request(parts)
        else {
            panic!("expected admission to remain unpublished");
        };
        let pending_reason = admitted.pending_cancel_reason();
        *pending_reason.write() = Some(CancelReason::race_loser());

        drop(liveness);
        let lane_published = Arc::new(AtomicBool::new(false));
        let lane_published_in_callback = Arc::clone(&lane_published);
        let (wakes, returned_spawn_effects) =
            publication.publish_with_spawn_effects(spawn_effects, move |_| {
                lane_published_in_callback.store(true, Ordering::SeqCst);
            });

        assert!(wakes.is_empty());
        assert!(returned_spawn_effects.is_none());
        assert!(!lane_published.load(Ordering::SeqCst));
        assert!(
            !admitted
                .get()
                .expect("identity remains inspectable")
                .is_published(),
            "expired liveness must not publish an identity without a command"
        );
        assert!(mailbox.handle_cancels_are_empty());
        assert!(
            admitted.spawn_effects.lock().effects.is_none(),
            "an observer with no possible executable lane must be abandoned"
        );
        assert_eq!(metrics.spawn_attempts(), 0);
    }

    #[test]
    fn spawn_drop_race_cx_spawn_resolves_returned_handles() {
        use crate::runtime::task_handle::JoinError;

        let runtime = crate::runtime::RuntimeBuilder::new()
            .worker_threads(1)
            .build()
            .expect("runtime build");
        let parent_cx = runtime.block_on(
            runtime
                .handle()
                .spawn(async { crate::cx::Cx::current().expect("runtime task Cx") }),
        );
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let producer_stop = Arc::clone(&stop);
        let producer_cx = parent_cx.clone();

        let producer = thread::spawn(move || {
            let mut handles = Vec::new();
            let mut unavailable_count = 0usize;
            for _ in 0..64 {
                match producer_cx.spawn(|_child| async move { 1usize }) {
                    Ok(handle) => handles.push(handle),
                    Err(SpawnError::RuntimeUnavailable) => {
                        unavailable_count += 1;
                        break;
                    }
                    Err(error) => panic!("unexpected spawn error before runtime drop: {error:?}"),
                }
            }
            ready_tx
                .send(())
                .expect("test coordinator should receive producer ready");
            while !producer_stop.load(Ordering::Acquire) {
                match producer_cx.spawn(|_child| async move { 1usize }) {
                    Ok(handle) => handles.push(handle),
                    Err(SpawnError::RuntimeUnavailable) => {
                        unavailable_count += 1;
                        break;
                    }
                    Err(error) => panic!("unexpected spawn error during runtime drop: {error:?}"),
                }
                thread::yield_now();
            }
            (handles, unavailable_count)
        });

        ready_rx
            .recv()
            .expect("producer should enter the spawn loop");
        drop(runtime);
        stop.store(true, Ordering::Release);
        let (mut handles, unavailable_count) =
            producer.join().expect("producer thread should not panic");
        assert!(
            !handles.is_empty(),
            "test must exercise at least one returned Cx::spawn handle"
        );

        let mut pending = Vec::new();
        for handle in &mut handles {
            match handle.try_join() {
                Ok(Some(_)) | Err(JoinError::Cancelled(_)) => {}
                Ok(None) => pending.push(handle.task_id()),
                Err(other) => panic!("unexpected join result after runtime drop: {other:?}"),
            }
        }
        assert!(
            pending.is_empty(),
            "spawn handles returned around runtime drop must not hang pending: {pending:?}"
        );
        assert!(
            matches!(
                parent_cx.spawn(|_child| async move { 2usize }),
                Err(SpawnError::RuntimeUnavailable)
            ),
            "retained Cx fails closed after runtime drop"
        );
        assert!(
            unavailable_count <= 1,
            "producer stops at the first observed RuntimeUnavailable"
        );
    }

    /// Spawn into a closing region: admission denies, the cancel slot
    /// resolves the handle, and joining yields JoinError::Cancelled.
    #[test]
    fn cx_spawn_into_closing_region_join_resolves_cancelled() {
        use std::task::{Context, Poll, Waker};

        let (mut lab, parent_cx, root) = lab_with_parent_cx();
        // Begin closing the root region BEFORE the spawn is admitted.
        lab.state.region(root).expect("root").begin_close(None);

        let mut handle = parent_cx
            .spawn(|_child| async move { 7usize })
            .expect("enqueue still succeeds; denial resolves via the handle");

        let waker = Waker::noop();
        let mut poll_cx = Context::from_waker(waker);
        let mut join = handle.join(&parent_cx);
        let mut result = None;
        for _ in 0..200 {
            match Pin::new(&mut join).poll(&mut poll_cx) {
                Poll::Ready(r) => {
                    result = Some(r);
                    break;
                }
                Poll::Pending => lab.step_for_test(),
            }
        }
        drop(join);
        let result = result.expect("join resolved");
        assert!(
            matches!(
                result,
                Err(crate::runtime::task_handle::JoinError::Cancelled(_))
            ),
            "join must resolve Cancelled for a denied spawn, got {result:?}"
        );
    }

    // === br-asupersync-hwjqyo (A2.2): Cx::spawn_in scope-targeting surface ===

    /// `Cx::spawn_in` applies the SCOPE's planned capability budget to the
    /// admitted child — not the calling cx's — matching the legacy
    /// state-threaded scope contract (br-asupersync-4onmas).
    #[test]
    fn cx_spawn_in_applies_scope_capability_budget() {
        let (mut lab, parent_cx, root) = lab_with_parent_cx();
        let planned = crate::types::CapabilityBudget::new()
            .with_memory_bytes(2_048)
            .with_cpu_units(64)
            .with_artifact_bytes(128);
        let scope: crate::cx::Scope<'static> =
            crate::cx::Scope::new_with_capability_budget(root, Budget::INFINITE, planned)
                .with_pending_spawn_counter(
                    lab.state
                        .region(root)
                        .map(crate::record::RegionRecord::pending_spawn_handle),
                );
        let observed: Arc<std::sync::Mutex<Option<crate::types::CapabilityBudget>>> =
            Arc::new(std::sync::Mutex::new(None));
        let observed_in_child = Arc::clone(&observed);
        parent_cx
            .spawn_in(&scope, move |child| async move {
                *observed_in_child
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                    Some(child.capability_budget());
            })
            .expect("cx.spawn_in");
        lab.run_until_quiescent();
        let observed = observed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .expect("child observed a capability budget");
        assert_eq!(
            observed, planned,
            "child must carry the scope's planned capability budget"
        );
    }

    /// `Cx::spawn_in` routes the pending reservation to the scope's region
    /// counter and the admitted child runs there, without `RuntimeState` at
    /// the call site.
    #[test]
    fn cx_spawn_in_targets_scope_region_counter() {
        let (mut lab, parent_cx, root) = lab_with_parent_cx();
        let child_region = lab
            .state
            .create_child_region(root, Budget::INFINITE)
            .expect("child region");
        let scope: crate::cx::Scope<'static> =
            crate::cx::Scope::new(child_region, Budget::INFINITE).with_pending_spawn_counter(
                lab.state
                    .region(child_region)
                    .map(crate::record::RegionRecord::pending_spawn_handle),
            );
        let ran = Arc::new(AtomicUsize::new(0));
        let ran_in_child = Arc::clone(&ran);
        let handle = parent_cx
            .spawn_in(&scope, move |_child| async move {
                ran_in_child.fetch_add(1, Ordering::SeqCst);
            })
            .expect("cx.spawn_in");
        assert!(
            is_spawn_mailbox_id(handle.task_id()),
            "pre-admission handle reports the provisional id"
        );
        assert_eq!(
            lab.state
                .region(child_region)
                .expect("child")
                .pending_spawn_count(),
            1,
            "reservation lands on the scope's region"
        );
        assert_eq!(
            lab.state.region(root).expect("root").pending_spawn_count(),
            0,
            "caller's region carries no reservation for a scope-targeted spawn"
        );
        lab.run_until_quiescent();
        assert_eq!(ran.load(Ordering::SeqCst), 1, "child ran");
        assert_eq!(
            lab.state
                .region(child_region)
                .expect("child")
                .pending_spawn_count(),
            0,
            "credits balanced"
        );
    }

    /// A bare same-region scope (no wiring) falls back to the calling
    /// context's counter, because the counter is per-region.
    #[test]
    fn cx_spawn_in_same_region_bare_scope_falls_back() {
        let (mut lab, parent_cx, root) = lab_with_parent_cx();
        let scope: crate::cx::Scope<'static> = crate::cx::Scope::new(root, Budget::INFINITE);
        let ran = Arc::new(AtomicUsize::new(0));
        let ran_in_child = Arc::clone(&ran);
        parent_cx
            .spawn_in(&scope, move |_child| async move {
                ran_in_child.fetch_add(1, Ordering::SeqCst);
            })
            .expect("same-region fallback uses the cx counter");
        lab.run_until_quiescent();
        assert_eq!(ran.load(Ordering::SeqCst), 1, "child ran");
    }

    /// A counter-less scope for a DIFFERENT region fails closed with
    /// `RuntimeUnavailable`: the calling context's counter must not be
    /// borrowed cross-region.
    #[test]
    fn cx_spawn_in_foreign_bare_scope_runtime_unavailable() {
        let (mut lab, parent_cx, root) = lab_with_parent_cx();
        let child_region = lab
            .state
            .create_child_region(root, Budget::INFINITE)
            .expect("child region");
        let scope: crate::cx::Scope<'static> =
            crate::cx::Scope::new(child_region, Budget::INFINITE);
        let result = parent_cx.spawn_in(&scope, |_child| async move {});
        assert!(
            matches!(
                result,
                Err(crate::runtime::state::SpawnError::RuntimeUnavailable)
            ),
            "cross-region spawn without scope wiring must fail closed"
        );
    }

    /// `Cx::scope()` carries the region's pending-spawn counter, so the
    /// returned scope works with `spawn_in` even when handed to another
    /// task whose Cx targets a different region.
    #[test]
    fn cx_scope_carries_pending_spawn_counter() {
        let (_lab, parent_cx, _root) = lab_with_parent_cx();
        assert!(
            parent_cx.scope().pending_spawn_counter_handle().is_some(),
            "wired Cx must propagate its region counter into Cx::scope()"
        );
    }

    /// `spawn_in` into a closing region: enqueue succeeds, the admission
    /// denial resolves through the handle as `JoinError::Cancelled`
    /// (mirrors the `Cx::spawn` closing-region contract).
    #[test]
    fn cx_spawn_in_closing_scope_region_resolves_cancelled() {
        use std::task::{Context, Poll, Waker};

        let (mut lab, parent_cx, root) = lab_with_parent_cx();
        let child_region = lab
            .state
            .create_child_region(root, Budget::INFINITE)
            .expect("child region");
        let scope: crate::cx::Scope<'static> =
            crate::cx::Scope::new(child_region, Budget::INFINITE).with_pending_spawn_counter(
                lab.state
                    .region(child_region)
                    .map(crate::record::RegionRecord::pending_spawn_handle),
            );
        lab.state
            .region(child_region)
            .expect("child")
            .begin_close(None);

        let mut handle = parent_cx
            .spawn_in(&scope, |_child| async move { 7usize })
            .expect("enqueue still succeeds; denial resolves via the handle");

        let waker = Waker::noop();
        let mut poll_cx = Context::from_waker(waker);
        let mut join = handle.join(&parent_cx);
        let mut result = None;
        for _ in 0..200 {
            match Pin::new(&mut join).poll(&mut poll_cx) {
                Poll::Ready(r) => {
                    result = Some(r);
                    break;
                }
                Poll::Pending => lab.step_for_test(),
            }
        }
        drop(join);
        let result = result.expect("join resolved");
        assert!(
            matches!(
                result,
                Err(crate::runtime::task_handle::JoinError::Cancelled(_))
            ),
            "join must resolve Cancelled for a denied scope-targeted spawn, got {result:?}"
        );
    }

    // === br-asupersync-wwyi9k (A2.2b): Cx::spawn_blocking v2 surface ===

    /// Drives `join` against the lab until it resolves (or the step budget
    /// runs out), returning the join result.
    fn poll_join_with_lab<T: Send + 'static>(
        lab: &mut LabRuntime,
        parent_cx: &crate::cx::Cx,
        handle: &mut crate::runtime::TaskHandle<T>,
    ) -> Result<T, crate::runtime::task_handle::JoinError> {
        use std::task::{Context, Poll, Waker};

        let waker = Waker::noop();
        let mut poll_cx = Context::from_waker(waker);
        let mut join = handle.join(parent_cx);
        for _ in 0..200 {
            match Pin::new(&mut join).poll(&mut poll_cx) {
                Poll::Ready(r) => return r,
                Poll::Pending => lab.step_for_test(),
            }
        }
        panic!("join did not resolve within the step budget");
    }

    // === br-asupersync-i9y5wb (A2.2a): Cx::spawn_local v2 surface ===

    fn clear_local_spawn_lane_for_test() {
        let mut dropped = Vec::new();
        while drain_local_spawn_lane(usize::MAX, &mut dropped) > 0 {
            dropped.clear();
        }
    }

    fn local_spawn_owner_for_test(cx: &crate::cx::Cx) -> ScopedLocalSpawnLaneOwner {
        let gateway = cx
            .spawn_gateway_handle()
            .expect("runtime-wired test Cx carries a spawn gateway");
        ScopedLocalSpawnLaneOwner::new(Arc::clone(gateway.mailbox()))
    }

    fn retire_manually_polled_local_task<T: Send + 'static>(
        lab: &mut LabRuntime,
        parent_cx: &crate::cx::Cx,
        handle: &mut crate::runtime::TaskHandle<T>,
        task_id: TaskId,
        outcome: crate::record::task::TaskOutcome,
    ) {
        let mut poll_cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(
            Pin::new(&mut handle.join(parent_cx))
                .poll(&mut poll_cx)
                .is_pending()
        );
        let record = lab.state.task_mut(task_id).expect("unretired local record");
        let barrier = record
            .cx_inner
            .as_ref()
            .expect("local task context")
            .read()
            .retirement_barrier
            .clone()
            .expect("admission installed retirement barrier");
        assert!(!barrier.is_open());
        assert!(record.complete(outcome));
        let (waiters, observer) = lab.state.task_completed(task_id).into_parts();
        assert!(waiters.is_empty());
        assert!(lab.state.task(task_id).is_none());
        // Manual polling bypasses the scheduler, so the fixture must also
        // perform its post-retirement publication before attempting to join.
        barrier.open_and_wake();
        observer.dispatch();
    }

    /// A runtime-wired Cx still fails closed when called off-worker: a
    /// `!Send` factory cannot be parked anywhere unless an owner worker is
    /// currently draining that thread-local lane.
    #[test]
    fn cx_spawn_local_off_worker_returns_local_scheduler_unavailable() {
        clear_local_spawn_lane_for_test();
        let (lab, parent_cx, root) = lab_with_parent_cx();
        let result = parent_cx.spawn_local(|_child| async {});
        assert!(matches!(
            result,
            Err(crate::runtime::state::SpawnError::LocalSchedulerUnavailable)
        ));
        assert!(
            local_spawn_lane_is_empty(),
            "off-worker call enqueues nothing"
        );
        assert_eq!(
            lab.state.region(root).expect("root").pending_spawn_count(),
            0,
            "failed off-worker spawn takes no pending credit"
        );
    }

    #[test]
    fn ownerless_local_drain_cannot_take_an_owned_request() {
        clear_local_spawn_lane_for_test();
        let (mut lab, parent_cx, root) = lab_with_parent_cx();
        let mut handle = {
            let _worker_guard = crate::runtime::scheduler::three_lane::ScopedWorkerId::new(0);
            let _owner_guard = local_spawn_owner_for_test(&parent_cx);
            parent_cx
                .spawn_local(|_child| async { 7_u8 })
                .expect("owner-worker local spawn")
        };
        assert_eq!(
            lab.state.region(root).expect("root").pending_spawn_count(),
            1,
            "the request is still queued after leaving its owner context"
        );

        let mut requests = Vec::new();
        assert!(local_spawn_lane_is_empty(), "this caller owns no requests");
        assert_eq!(drain_local_spawn_lane(16, &mut requests), 0);
        let _owner_guard = local_spawn_owner_for_test(&parent_cx);
        assert!(!local_spawn_lane_is_empty());
        assert_eq!(drain_local_spawn_lane(16, &mut requests), 1);
        requests
            .pop()
            .expect("the owner's request remains available")
            .resolve_cancelled(CancelReason::shutdown());
        assert!(matches!(
            poll_join_with_lab(&mut lab, &parent_cx, &mut handle),
            Err(crate::runtime::task_handle::JoinError::Cancelled(reason)) if reason.is_shutdown()
        ));
        assert_eq!(
            lab.state.region(root).expect("root").pending_spawn_count(),
            0
        );
    }

    /// Owner-worker local spawn: a `!Send` factory (captures `Rc<Cell<_>>`)
    /// is admitted under the same region/counter discipline, pinned to the
    /// owner worker, stored in TLS, queued only on `local_ready`, and joins
    /// with the produced value.
    #[test]
    fn cx_spawn_local_owner_worker_runs_non_send_future() {
        clear_local_spawn_lane_for_test();
        let (mut lab, parent_cx, root) = lab_with_parent_cx();
        let local_ready = Arc::new(parking_lot::Mutex::new(
            crate::runtime::scheduler::three_lane::LocalReadyQueueInner::new(
                std::collections::VecDeque::new(),
            ),
        ));
        let local_scheduler = Arc::new(parking_lot::Mutex::new(
            crate::runtime::scheduler::PriorityScheduler::new(),
        ));
        let _worker_guard = crate::runtime::scheduler::three_lane::ScopedWorkerId::new(0);
        let _owner_guard = local_spawn_owner_for_test(&parent_cx);
        let _scheduler_guard = crate::runtime::scheduler::three_lane::ScopedLocalScheduler::new(
            Arc::clone(&local_scheduler),
        );
        let _ready_guard =
            crate::runtime::scheduler::three_lane::ScopedLocalReady::new(Arc::clone(&local_ready));

        let cell = std::rc::Rc::new(std::cell::Cell::new(0usize));
        let cell_in_child = std::rc::Rc::clone(&cell);
        let mut handle = parent_cx
            .spawn_local(move |_child| async move {
                cell_in_child.set(11);
                42usize
            })
            .expect("cx.spawn_local on owner worker");
        assert!(
            is_spawn_mailbox_id(handle.task_id()),
            "pre-admission handle reports the provisional id"
        );
        assert_eq!(
            lab.state.region(root).expect("root").pending_spawn_count(),
            1,
            "local spawn reserves a pending credit before admission"
        );

        let mut requests = Vec::new();
        assert_eq!(
            drain_local_spawn_lane(16, &mut requests),
            1,
            "one local request queued"
        );
        let request = requests.pop().expect("request present");
        let admission = admit_local_embedded(&mut lab.state, request);
        let crate::runtime::state::LocalSpawnAdmission::Admitted {
            task_id,
            priority: _,
            stored,
            cancel_publication,
            spawn_effects,
        } = admission
        else {
            panic!("expected local admission");
        };
        assert!(
            !is_spawn_mailbox_id(task_id),
            "admitted id must be canonical"
        );
        let record = lab.state.task(task_id).expect("task record");
        assert!(record.is_local(), "task record is marked local");
        assert_eq!(record.pinned_worker(), Some(0), "task pinned to owner");
        assert_eq!(
            lab.state.region(root).expect("root").pending_spawn_count(),
            0,
            "credit released after local admission"
        );

        crate::runtime::local::store_local_task(task_id, stored);
        let cancel_wakes = cancel_publication.publish(|cancel_priority| {
            assert!(cancel_priority.is_none());
            assert!(
                crate::runtime::scheduler::three_lane::schedule_local_task(task_id),
                "owner worker has local_ready TLS"
            );
        });
        spawn_effects.dispatch();
        cancel_wakes.dispatch();
        assert_eq!(
            local_ready.lock().pop_front(),
            Some(task_id),
            "task is queued on non-stealable local_ready"
        );

        let mut local_task = crate::runtime::local::remove_local_task(task_id)
            .expect("local task stored on owner thread");
        let waker = std::task::Waker::noop();
        let mut poll_cx = std::task::Context::from_waker(waker);
        assert!(matches!(
            local_task.poll(&mut poll_cx),
            std::task::Poll::Ready(Outcome::Ok(()))
        ));
        retire_manually_polled_local_task(
            &mut lab,
            &parent_cx,
            &mut handle,
            task_id,
            Outcome::Ok(()),
        );
        let result = poll_join_with_lab(&mut lab, &parent_cx, &mut handle);
        assert_eq!(result.expect("joined value"), 42);
        assert_eq!(cell.get(), 11, "non-Send future ran on owner thread");
    }

    #[test]
    fn cx_spawn_local_synchronous_factory_panic_resolves_join_panicked() {
        clear_local_spawn_lane_for_test();
        let (mut lab, parent_cx, _root) = lab_with_parent_cx();
        let local_ready = Arc::new(parking_lot::Mutex::new(
            crate::runtime::scheduler::three_lane::LocalReadyQueueInner::new(
                std::collections::VecDeque::new(),
            ),
        ));
        let _worker_guard = crate::runtime::scheduler::three_lane::ScopedWorkerId::new(0);
        let _owner_guard = local_spawn_owner_for_test(&parent_cx);
        let _ready_guard =
            crate::runtime::scheduler::three_lane::ScopedLocalReady::new(Arc::clone(&local_ready));

        let mut handle = parent_cx
            .spawn_local(|_child| -> std::future::Ready<()> {
                panic!("synchronous local factory panic")
            })
            .expect("cx.spawn_local enqueues the lazy factory");
        let mut requests = Vec::new();
        assert_eq!(drain_local_spawn_lane(1, &mut requests), 1);
        let crate::runtime::state::LocalSpawnAdmission::Admitted {
            task_id,
            stored,
            cancel_publication,
            spawn_effects,
            ..
        } = admit_local_embedded(&mut lab.state, requests.pop().expect("local request"))
        else {
            panic!("expected local admission");
        };
        crate::runtime::local::store_local_task(task_id, stored);
        let cancel_wakes = cancel_publication.publish(|cancel_priority| {
            assert!(cancel_priority.is_none());
            assert!(
                crate::runtime::scheduler::three_lane::schedule_local_task(task_id),
                "owner-local task must be physically published before first poll"
            );
        });
        spawn_effects.dispatch();
        cancel_wakes.dispatch();
        assert_eq!(local_ready.lock().pop_front(), Some(task_id));

        let mut local_task = crate::runtime::local::remove_local_task(task_id)
            .expect("local task stored on owner thread");
        let waker = std::task::Waker::noop();
        let mut poll_cx = std::task::Context::from_waker(waker);
        let Poll::Ready(Outcome::Panicked(payload)) = local_task.poll(&mut poll_cx) else {
            panic!("synchronous local factory panic must terminate the stored task");
        };
        retire_manually_polled_local_task(
            &mut lab,
            &parent_cx,
            &mut handle,
            task_id,
            Outcome::Panicked(payload),
        );
        match poll_join_with_lab(&mut lab, &parent_cx, &mut handle) {
            Err(crate::runtime::task_handle::JoinError::Panicked(payload)) => {
                assert_eq!(payload.message(), "synchronous local factory panic");
            }
            other => panic!("synchronous local factory panic must reach the handle: {other:?}"),
        }
    }

    #[test]
    fn local_pre_admission_abort_dispatches_after_publish_store_and_schedule() {
        clear_local_spawn_lane_for_test();
        let (mut lab, parent_cx, _root) = lab_with_parent_cx();
        let local_ready = Arc::new(parking_lot::Mutex::new(
            crate::runtime::scheduler::three_lane::LocalReadyQueueInner::new(
                std::collections::VecDeque::new(),
            ),
        ));
        let local_scheduler = Arc::new(parking_lot::Mutex::new(
            crate::runtime::scheduler::PriorityScheduler::new(),
        ));
        let _worker_guard = crate::runtime::scheduler::three_lane::ScopedWorkerId::new(0);
        let _owner_guard = local_spawn_owner_for_test(&parent_cx);
        let _scheduler_guard = crate::runtime::scheduler::three_lane::ScopedLocalScheduler::new(
            Arc::clone(&local_scheduler),
        );
        let _ready_guard =
            crate::runtime::scheduler::three_lane::ScopedLocalReady::new(Arc::clone(&local_ready));

        let attempts = Arc::new(AtomicUsize::new(0));
        let published = Arc::new(AtomicBool::new(false));
        let stored_flag = Arc::new(AtomicBool::new(false));
        let scheduled = Arc::new(AtomicBool::new(false));
        let completed = Arc::new(AtomicBool::new(false));
        let expected_task: Arc<OnceLock<TaskId>> = Arc::new(OnceLock::new());
        let expected_task_for_wake = Arc::clone(&expected_task);
        let local_scheduler_for_wake = Arc::clone(&local_scheduler);
        let waker = std::task::Waker::from(Arc::new(AdmissionBoundaryWake {
            attempts: Arc::clone(&attempts),
            published: Arc::clone(&published),
            stored: Arc::clone(&stored_flag),
            scheduled: Arc::clone(&scheduled),
            completed: Arc::clone(&completed),
            reenter_scheduler: Box::new(move || {
                let expected = *expected_task_for_wake
                    .get()
                    .expect("canonical local task id published before dispatch");
                let mut scheduler = local_scheduler_for_wake
                    .try_lock()
                    .expect("cancel wake runs after the local scheduler guard is released");
                let observed = scheduler.pop_cancel_only();
                assert_eq!(
                    observed,
                    Some(expected),
                    "cancel wake observes the canonical task in the cancel lane"
                );
                scheduler.schedule_cancel(expected, Budget::ZERO.priority);
            }),
        }));

        let marker = std::rc::Rc::new(std::cell::Cell::new(false));
        let marker_in_child = std::rc::Rc::clone(&marker);
        let mut handle = parent_cx
            .spawn_local(move |_child| async move {
                marker_in_child.set(true);
            })
            .expect("owner-local spawn enqueues");
        let provisional = handle.task_id();
        handle.abort_with_reason(CancelReason::race_loser());

        let mut requests = Vec::new();
        assert_eq!(drain_local_spawn_lane(1, &mut requests), 1);
        let request = requests.pop().expect("local request present");
        let admitted = Arc::clone(
            request
                .admitted_slot
                .as_ref()
                .expect("local request carries an admitted slot"),
        );
        let pending_reason = admitted.pending_cancel_reason();
        let (cache_locked, installer) =
            install_cancel_waker_during_admission(Arc::clone(&admitted), pending_reason, waker);
        cache_locked.wait();

        let crate::runtime::state::LocalSpawnAdmission::Admitted {
            task_id,
            priority: _,
            stored,
            cancel_publication,
            spawn_effects,
        } = admit_local_embedded(&mut lab.state, request)
        else {
            panic!("expected local admission");
        };
        installer.join().expect("cancel-waker installer completes");
        handle.abort_with_reason(CancelReason::race_loser());
        drop(handle.join_with_drop_reason(&parent_cx, CancelReason::race_loser()));
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            0,
            "TaskHandle and JoinFuture aborts stay cached until local runnable publication"
        );

        let admitted_task = admitted.get().expect("local identity published");
        assert_eq!(admitted_task.task_id, task_id);
        assert_eq!(handle.task_id(), task_id, "handle observes canonical id");
        assert_ne!(task_id, provisional, "canonical id replaces provisional id");
        let record = lab
            .state
            .task(task_id)
            .expect("local task record published");
        assert!(record.is_local());
        assert_eq!(record.pinned_worker(), Some(0));
        published.store(true, Ordering::SeqCst);
        let inner = admitted_task
            .cx_inner
            .upgrade()
            .expect("admitted local Cx remains live");
        let guard = inner.read();
        assert!(
            !guard.cancel_requested && guard.cancel_reason.is_none(),
            "cached local abort remains deferred before runnable publication"
        );
        drop(guard);

        assert_eq!(stored.task_id(), Some(task_id));
        let local_task_baseline = crate::runtime::local::local_task_count();
        crate::runtime::local::store_local_task(task_id, stored);
        assert_eq!(
            crate::runtime::local::local_task_count(),
            local_task_baseline + 1,
            "canonical local task stored before dispatch"
        );
        stored_flag.store(true, Ordering::SeqCst);
        expected_task
            .set(task_id)
            .expect("expected task id set once");
        let (cancel_wakes, returned_spawn_effects) = cancel_publication
            .publish_with_spawn_effects(spawn_effects, |_| {
                panic!("managed cached abort delegates its first lane to the command consumer")
            });
        assert!(admitted_task.is_published());
        assert!(
            returned_spawn_effects.is_none(),
            "managed cached abort leaves its spawn observer in the authoritative admission slot"
        );
        assert_eq!(
            cancel_wakes.len(),
            0,
            "managed publication leaves Waker ownership with the command consumer"
        );
        let guard = inner.read();
        assert!(
            guard.cancel_requested,
            "local publication replays cached abort"
        );
        assert!(
            guard
                .cancel_reason
                .as_ref()
                .is_some_and(|reason| reason.is_kind(CancelKind::RaceLost)),
            "cached local abort preserves RaceLost attribution"
        );
        drop(guard);
        cancel_wakes.dispatch();
        assert_eq!(attempts.load(Ordering::SeqCst), 0);

        // Deterministic interleaving: an ordinary runtime cancellation lands
        // after admission delegated the first lane but before the queued handle
        // command is consumed. It may transition the TaskRecord, but must not
        // mistake delegation for an already-visible lane or snapshot the Waker.
        let (region_should_schedule, region_wakes) = lab
            .state
            .cancel_task(task_id, &CancelReason::race_loser())
            .into_parts();
        assert!(
            !region_should_schedule,
            "delegated publication suppresses a competing initial lane"
        );
        assert!(
            region_wakes.is_empty(),
            "delegated publication retains Waker ownership for the command consumer"
        );
        region_wakes.dispatch();

        // A repeat abort after canonical identity publication may race the
        // original delegated command on another worker. Both commands carry
        // the same authoritative slot, so either consumer may win without
        // losing or duplicating the observer receipt.
        handle.abort_with_reason(CancelReason::race_loser());

        let mut commands = Vec::new();
        assert_eq!(
            lab.spawn_mailbox()
                .dequeue_handle_cancels_into(2, &mut commands),
            2,
            "initial publication and repeat abort each enqueue a canonical command"
        );
        let winner = commands.pop().expect("winner command");
        let loser = commands.pop().expect("loser command");
        assert_eq!(winner.task_id, task_id);
        assert_eq!(loser.task_id, task_id);
        assert!(Arc::ptr_eq(
            winner
                .admitted_slot
                .as_ref()
                .expect("winner carries admission slot"),
            loser
                .admitted_slot
                .as_ref()
                .expect("loser carries admission slot")
        ));

        // Model two workers completing phase 1 before either publishes.
        let (winner_route, winner_wakes) = lab
            .state
            .cancel_task_for_handle(winner.task_id, &winner.reason)
            .into_parts();
        let winner_route = winner_route.expect("winner has a lane route");
        assert!(
            winner_route.delegated_initial,
            "cached abort retains delegated state until physical publication"
        );
        let (loser_route, loser_wakes) = lab
            .state
            .cancel_task_for_handle(loser.task_id, &loser.reason)
            .into_parts();
        let loser_route = loser_route.expect("loser also snapshots delegated phase 1");
        assert!(loser_route.delegated_initial);
        assert!(winner_wakes.is_empty());
        assert!(loser_wakes.is_empty());
        let (published_priority, publication_wakes) = lab
            .state
            .publish_handle_cancel_lane(task_id, |priority, is_local, pinned_worker| {
                assert!(is_local);
                assert_eq!(pinned_worker, Some(0));
                assert!(
                    crate::runtime::scheduler::three_lane::schedule_cancel_on_current_local(
                        task_id, priority,
                    ),
                    "runtime-owned consumer publishes the canonical local cancel lane"
                );
                scheduled.store(true, Ordering::SeqCst);
                Some(priority)
            })
            .into_parts();
        assert_eq!(published_priority, Some(winner_route.priority));
        winner
            .admitted_slot
            .as_ref()
            .expect("delegated command carries the authoritative admission slot")
            .publish_spawn_lane_and_take_effects()
            .expect("admission slot owns the spawn observer")
            .dispatch();

        // The losing consumer's closure never runs (the lane is already
        // published), so `panic!`'s `!` return leaves the publication payload
        // type unconstrained; annotate it to match the winner's `Option<u8>`.
        let (loser_publication, loser_publication_wakes): (Option<u8>, _) = lab
            .state
            .publish_handle_cancel_lane(task_id, |_, _, _| {
                panic!("losing consumer must observe the already-published lane")
            })
            .into_parts();
        assert!(loser_publication.is_none());
        assert!(
            loser
                .admitted_slot
                .as_ref()
                .expect("loser carries admission slot")
                .take_spawn_effects_if_lane_published()
                .is_none(),
            "the observer receipt is one-shot across racing consumers"
        );
        winner_wakes.dispatch();
        loser_wakes.dispatch();
        publication_wakes.dispatch();
        loser_publication_wakes.dispatch();
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert!(
            completed.load(Ordering::SeqCst),
            "reentrant local Waker observed publish/store/schedule ordering"
        );
        assert_eq!(
            local_scheduler.lock().pop_cancel_only(),
            Some(task_id),
            "reentrant Waker restored the local cancel-lane task"
        );
        assert_eq!(
            local_scheduler.lock().pop_cancel_only(),
            None,
            "the admission/region/handle interleaving publishes one initial lane"
        );
        let dropped = crate::runtime::local::remove_local_task(task_id);
        assert!(dropped.is_some(), "test removes the unpolled local task");
        assert_eq!(
            crate::runtime::local::local_task_count(),
            local_task_baseline
        );
        assert!(
            !marker.get(),
            "local factory remains unpolled in this boundary test"
        );
    }

    /// Closing-region denial resolves the returned handle as Cancelled and
    /// drops the `!Send` factory uninvoked.
    #[test]
    fn cx_spawn_local_into_closing_region_resolves_cancelled() {
        clear_local_spawn_lane_for_test();
        let (mut lab, parent_cx, root) = lab_with_parent_cx();
        let local_ready = Arc::new(parking_lot::Mutex::new(
            crate::runtime::scheduler::three_lane::LocalReadyQueueInner::new(
                std::collections::VecDeque::new(),
            ),
        ));
        let _worker_guard = crate::runtime::scheduler::three_lane::ScopedWorkerId::new(0);
        let _owner_guard = local_spawn_owner_for_test(&parent_cx);
        let _ready_guard =
            crate::runtime::scheduler::three_lane::ScopedLocalReady::new(Arc::clone(&local_ready));
        lab.state.region(root).expect("root").begin_close(None);

        let ran = std::rc::Rc::new(std::cell::Cell::new(false));
        let ran_in_child = std::rc::Rc::clone(&ran);
        let mut handle = parent_cx
            .spawn_local(move |_child| async move {
                ran_in_child.set(true);
                7usize
            })
            .expect("enqueue still succeeds; denial resolves through handle");
        assert_eq!(
            lab.state.region(root).expect("root").pending_spawn_count(),
            1,
            "pending credit held while request is queued"
        );

        let mut requests = Vec::new();
        assert_eq!(drain_local_spawn_lane(16, &mut requests), 1);
        let request = requests.pop().expect("request present");
        let crate::runtime::state::LocalSpawnAdmission::Denied { request, error } =
            admit_local_embedded(&mut lab.state, request)
        else {
            panic!("expected closing-region denial");
        };
        assert!(matches!(
            error,
            crate::runtime::state::SpawnError::RegionClosed(id) if id == root
        ));
        request.resolve_cancelled(crate::types::CancelReason::new(
            crate::types::CancelKind::ParentCancelled,
        ));
        assert_eq!(
            lab.state.region(root).expect("root").pending_spawn_count(),
            0,
            "denial releases pending credit"
        );

        let result = poll_join_with_lab(&mut lab, &parent_cx, &mut handle);
        assert!(matches!(
            result,
            Err(crate::runtime::task_handle::JoinError::Cancelled(_))
        ));
        assert!(!ran.get(), "local factory was never invoked");
        assert!(local_ready.lock().is_empty(), "denied task never scheduled");
    }

    /// Without a pool handle (lab runtime), the closure runs inline inside
    /// the admitted region-owned task and the value flows through the
    /// handle — the deterministic fallback path.
    #[test]
    fn cx_spawn_blocking_inline_fallback_delivers_value() {
        let (mut lab, parent_cx, root) = lab_with_parent_cx();
        let ran = Arc::new(AtomicUsize::new(0));
        let ran_in_closure = Arc::clone(&ran);
        let mut handle = parent_cx
            .spawn_blocking(move |_child| {
                ran_in_closure.fetch_add(1, Ordering::SeqCst);
                42usize
            })
            .expect("cx.spawn_blocking");
        let result = poll_join_with_lab(&mut lab, &parent_cx, &mut handle);
        assert_eq!(result.expect("blocking value"), 42);
        assert_eq!(ran.load(Ordering::SeqCst), 1, "closure ran exactly once");
        assert_eq!(
            lab.state.region(root).expect("root").pending_spawn_count(),
            0,
            "credits balanced"
        );
    }

    /// The blocking closure's child Cx inherits the caller's budget
    /// (A2.2 acceptance criterion: spawn_blocking budget inheritance).
    ///
    /// The deadline must carry over exactly; the poll quota is asserted
    /// within a small tolerance because the admitted wrapper task's own
    /// polls are charged against the child budget before the closure
    /// observes it.
    #[test]
    fn cx_spawn_blocking_child_inherits_caller_budget() {
        const QUOTA: u32 = 1_000;
        let deadline = Time::from_secs(77);
        let parent_budget = Budget::new().with_deadline(deadline).with_poll_quota(QUOTA);

        let mut lab = LabRuntime::new(LabConfig::new(21));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let system_cx = lab.state.create_system_cx();
        let (parent_tid, _handle, parent_cx, _result_tx, spawn_effects) = lab
            .state
            .create_task_infrastructure::<()>(&system_cx, root, parent_budget, false)
            .expect("parent task");
        lab.state.store_spawned_task(
            parent_tid,
            StoredTask::new_with_id(async { Outcome::Ok(()) }, parent_tid),
        );
        lab.scheduler.lock().schedule(parent_tid, 0);
        spawn_effects.dispatch();

        let observed: Arc<std::sync::Mutex<Option<Budget>>> = Arc::new(std::sync::Mutex::new(None));
        let observed_in_closure = Arc::clone(&observed);
        parent_cx
            .spawn_blocking(move |child| {
                *observed_in_closure
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(child.budget());
            })
            .expect("cx.spawn_blocking");
        lab.run_until_quiescent();
        let observed = observed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .expect("closure observed a budget");
        assert_eq!(
            observed.deadline,
            Some(deadline),
            "child deadline must equal the caller's deadline at spawn time"
        );
        assert!(
            observed.poll_quota <= QUOTA && observed.poll_quota >= QUOTA - 10,
            "child poll quota must inherit the caller's quota modulo wrapper poll \
             accounting, got {} (expected within [{}, {QUOTA}])",
            observed.poll_quota,
            QUOTA - 10
        );
    }

    /// A panic inside the blocking closure resolves the handle as
    /// `JoinError::Panicked` (panic containment parity with the removed
    /// legacy `Scope::spawn_blocking`).
    #[test]
    fn cx_spawn_blocking_panic_resolves_join_panicked() {
        let (mut lab, parent_cx, _root) = lab_with_parent_cx();
        let mut handle = parent_cx
            .spawn_blocking(|_child| -> usize { panic!("blocking closure exploded") })
            .expect("cx.spawn_blocking");
        let result = poll_join_with_lab(&mut lab, &parent_cx, &mut handle);
        assert!(
            matches!(
                result,
                Err(crate::runtime::task_handle::JoinError::Panicked(_))
            ),
            "join must resolve Panicked, got {result:?}"
        );
    }

    /// `spawn_blocking_in` targets the scope's region: reservation and the
    /// admitted task land on the scope's counter/region.
    #[test]
    fn cx_spawn_blocking_in_targets_scope_region() {
        let (mut lab, parent_cx, root) = lab_with_parent_cx();
        let child_region = lab
            .state
            .create_child_region(root, Budget::INFINITE)
            .expect("child region");
        let scope: crate::cx::Scope<'static> =
            crate::cx::Scope::new(child_region, Budget::INFINITE).with_pending_spawn_counter(
                lab.state
                    .region(child_region)
                    .map(crate::record::RegionRecord::pending_spawn_handle),
            );
        let mut handle = parent_cx
            .spawn_blocking_in(&scope, |_child| 7usize)
            .expect("cx.spawn_blocking_in");
        assert_eq!(
            lab.state
                .region(child_region)
                .expect("child")
                .pending_spawn_count(),
            1,
            "reservation lands on the scope's region"
        );
        let result = poll_join_with_lab(&mut lab, &parent_cx, &mut handle);
        assert_eq!(result.expect("blocking value"), 7);
        assert_eq!(
            lab.state
                .region(child_region)
                .expect("child")
                .pending_spawn_count(),
            0,
            "credits balanced"
        );
    }

    /// `spawn_blocking` into a closing region resolves the handle as
    /// `JoinError::Cancelled` without running the closure.
    #[test]
    fn cx_spawn_blocking_into_closing_region_resolves_cancelled() {
        let (mut lab, parent_cx, root) = lab_with_parent_cx();
        lab.state.region(root).expect("root").begin_close(None);
        let ran = Arc::new(AtomicUsize::new(0));
        let ran_in_closure = Arc::clone(&ran);
        let mut handle = parent_cx
            .spawn_blocking(move |_child| {
                ran_in_closure.fetch_add(1, Ordering::SeqCst);
                7usize
            })
            .expect("enqueue still succeeds; denial resolves via the handle");
        let result = poll_join_with_lab(&mut lab, &parent_cx, &mut handle);
        assert!(
            matches!(
                result,
                Err(crate::runtime::task_handle::JoinError::Cancelled(_))
            ),
            "join must resolve Cancelled for a denied blocking spawn, got {result:?}"
        );
        assert_eq!(ran.load(Ordering::SeqCst), 0, "closure never ran");
    }

    // === br-asupersync-i9y5wb (A2.2a): Cx::spawn_local v2 surface ===

    /// Off-worker producers fail closed at spawn time: the thread-local
    /// lane is only drained by runtime workers, so non-worker threads
    /// (including the lab and blocking-pool threads) get
    /// `LocalSchedulerUnavailable` immediately — a parked request can
    /// never rot on a thread with no drainer.
    #[test]
    fn cx_spawn_local_off_worker_fails_local_scheduler_unavailable() {
        let (_lab, parent_cx, _root) = lab_with_parent_cx();
        let result = parent_cx.spawn_local(|_child| async move { 5usize });
        assert!(
            matches!(
                result,
                Err(crate::runtime::state::SpawnError::LocalSchedulerUnavailable)
            ),
            "off-worker spawn_local must fail closed"
        );
    }

    /// Local admission success: the factory defers to first poll, the
    /// pending credit balances once the task joins the region task list,
    /// and the stored task completes when polled.
    #[test]
    fn local_admission_runs_factory_at_first_poll_and_balances_counter() {
        use std::task::{Context, Poll, Waker};

        let mut state = crate::runtime::state::RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);
        let pending = state.region(region).expect("region").pending_spawn_handle();
        let mailbox = SpawnMailbox::new();
        let provisional = mailbox.allocate_task_id();
        let _worker_guard = crate::runtime::scheduler::three_lane::ScopedWorkerId::new(0);

        let ran = Arc::new(AtomicUsize::new(0));
        let ran_in_factory = Arc::clone(&ran);
        let factory: LocalSpawnFactoryFn = Box::new(move |_cx| {
            Box::pin(async move {
                ran_in_factory.fetch_add(1, Ordering::SeqCst);
                Outcome::Ok(())
            })
        });
        let request = LocalSpawnRequest {
            task_id: provisional,
            region,
            budget: Budget::INFINITE,
            factory,
            on_unadmitted_cancel: None,
            on_admission_error: None,
            pending_reservation: Some(pending.reserve()),
            admitted_slot: None,
        };
        assert_eq!(
            state.region(region).expect("region").pending_spawn_count(),
            1,
            "reservation held while the request is parked"
        );

        let crate::runtime::state::LocalSpawnAdmission::Admitted {
            task_id,
            priority: _,
            mut stored,
            cancel_publication,
            spawn_effects,
        } = admit_local_embedded(&mut state, request)
        else {
            panic!("admission must succeed for an open region");
        };
        assert_eq!(
            state.region(region).expect("region").pending_spawn_count(),
            0,
            "credit released once the task is in the region task list"
        );
        assert_eq!(
            ran.load(Ordering::SeqCst),
            0,
            "factory deferred to first poll"
        );
        let cancel_wakes = cancel_publication.publish(|_| {});
        spawn_effects.dispatch();
        cancel_wakes.dispatch();

        let waker = Waker::noop();
        let mut poll_cx = Context::from_waker(waker);
        assert!(matches!(
            stored.poll(&mut poll_cx),
            Poll::Ready(Outcome::Ok(()))
        ));
        assert_eq!(ran.load(Ordering::SeqCst), 1, "factory ran at first poll");
        assert_eq!(stored.task_id(), Some(task_id));
    }

    #[test]
    fn reused_admitted_slot_denies_local_before_runtime_state_mutation() {
        let mut state = crate::runtime::state::RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);
        let pending = state.region(region).expect("region").pending_spawn_handle();
        let mailbox = SpawnMailbox::new();
        let provisional = mailbox.allocate_task_id();
        let slot = Arc::new(AdmittedTaskSlot::new());
        let original_task = TaskId::new_for_test(77, 3);
        let original_cx = crate::cx::Cx::for_testing();
        slot.set(AdmittedTask::published(
            original_task,
            Arc::downgrade(&original_cx.inner),
        ))
        .expect("seed an already-used slot");
        let factory_runs = Arc::new(AtomicUsize::new(0));
        let factory_runs_in_task = Arc::clone(&factory_runs);
        let observed_error = Arc::new(Mutex::new(None));
        let observed_error_slot = Arc::clone(&observed_error);
        let request = LocalSpawnRequest {
            task_id: provisional,
            region,
            budget: Budget::INFINITE,
            factory: Box::new(move |_cx| {
                Box::pin(async move {
                    factory_runs_in_task.fetch_add(1, Ordering::SeqCst);
                    Outcome::Ok(())
                })
            }),
            on_unadmitted_cancel: None,
            on_admission_error: Some(Box::new(move |error| {
                *observed_error_slot.lock().expect("error lock") = Some(error);
            })),
            pending_reservation: Some(pending.reserve()),
            admitted_slot: Some(Arc::clone(&slot)),
        };
        let _worker_guard = crate::runtime::scheduler::three_lane::ScopedWorkerId::new(0);
        let live_before = state.live_task_count();
        let region_tasks_before = state.region(region).expect("region").task_count();
        let trace_before = state.trace_handle().snapshot().len();
        let validator_before = state.cancel_protocol_validator().lock().stats();
        let local_tasks_before = crate::runtime::local::local_task_count();

        let crate::runtime::state::LocalSpawnAdmission::Denied { request, error } =
            admit_local_embedded(&mut state, request)
        else {
            panic!("reused local slot must be denied");
        };
        assert!(matches!(
            error,
            SpawnError::AdmissionSlotAlreadyReserved { task_id }
                if task_id == provisional
        ));
        assert_eq!(error.code(), "ASUP-E008");
        assert_eq!(state.live_task_count(), live_before);
        assert_eq!(
            state.region(region).expect("region").task_count(),
            region_tasks_before
        );
        assert_eq!(state.trace_handle().snapshot().len(), trace_before);
        assert_eq!(
            state.cancel_protocol_validator().lock().stats(),
            validator_before
        );
        assert_eq!(
            crate::runtime::local::local_task_count(),
            local_tasks_before
        );
        assert_eq!(pending.count(), 1);
        assert_eq!(
            slot.get().map(|admitted| admitted.task_id),
            Some(original_task),
            "losing request cannot replace the original identity"
        );

        request.resolve_failed(error.clone());
        assert_eq!(pending.count(), 0);
        assert_eq!(factory_runs.load(Ordering::SeqCst), 0);
        assert_eq!(
            observed_error.lock().expect("error lock").as_ref(),
            Some(&error)
        );
    }

    /// Local admission denial for a closing region: factory never runs,
    /// the cancel slot fires exactly once, and the pending credit is
    /// released last.
    #[test]
    fn local_admission_denied_for_closing_region_resolves_cancelled() {
        let mut state = crate::runtime::state::RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);
        state.region(region).expect("region").begin_close(None);
        let pending = state.region(region).expect("region").pending_spawn_handle();
        let mailbox = SpawnMailbox::new();
        let provisional = mailbox.allocate_task_id();
        let _worker_guard = crate::runtime::scheduler::three_lane::ScopedWorkerId::new(0);

        let ran = Arc::new(AtomicUsize::new(0));
        let ran_in_factory = Arc::clone(&ran);
        let factory: LocalSpawnFactoryFn = Box::new(move |_cx| {
            Box::pin(async move {
                ran_in_factory.fetch_add(1, Ordering::SeqCst);
                Outcome::Ok(())
            })
        });
        let cancelled = Arc::new(AtomicUsize::new(0));
        let cancelled_slot = Arc::clone(&cancelled);
        let request = LocalSpawnRequest {
            task_id: provisional,
            region,
            budget: Budget::INFINITE,
            factory,
            on_unadmitted_cancel: Some(Box::new(move |_| {
                cancelled_slot.fetch_add(1, Ordering::SeqCst);
            })),
            on_admission_error: None,
            pending_reservation: Some(pending.reserve()),
            admitted_slot: None,
        };

        let crate::runtime::state::LocalSpawnAdmission::Denied { request, error } =
            admit_local_embedded(&mut state, request)
        else {
            panic!("admission must deny for a closing region");
        };
        assert!(matches!(
            error,
            crate::runtime::state::SpawnError::RegionClosed(_)
        ));
        request.resolve_cancelled(CancelReason::new(CancelKind::ParentCancelled));
        assert_eq!(ran.load(Ordering::SeqCst), 0, "factory never invoked");
        assert_eq!(
            cancelled.load(Ordering::SeqCst),
            1,
            "cancel slot fired once"
        );
        assert_eq!(
            state.region(region).expect("region").pending_spawn_count(),
            0,
            "credit released on denial"
        );
    }

    /// An opening whose Create or watch command is still queued when the
    /// runtime is torn down is woken and resolves as unavailable instead of
    /// waiting forever (br-asupersync-fbifws).
    #[test]
    fn teardown_wakes_openings_whose_commands_were_never_applied() {
        let mut lab = LabRuntime::new(LabConfig::new(0x00fb_1f05).max_steps(256));
        let root = lab.state.create_root_region(crate::types::Budget::INFINITE);
        let (task, mut joined) = lab
            .state
            .create_task(root, crate::types::Budget::INFINITE, async {
                crate::Cx::current().expect("lab task cx")
            })
            .expect("create task");
        lab.scheduler.lock().schedule(task, 0);
        lab.run_until_idle();
        let cx = joined
            .try_join()
            .expect("join")
            .expect("the task returned its cx");

        let wakes = Arc::new(CountWakes(AtomicUsize::new(0)));
        let waker = std::task::Waker::from(Arc::clone(&wakes));
        let mut context = std::task::Context::from_waker(&waker);
        // Queued, never applied: the lab does not run again.
        let mut region = Box::pin(cx.open_child_region(crate::cx::ChildRegionSpec::inherit()));
        let mut monitor = Box::pin(cx.monitor(TaskId::new_for_test(77, 0)));
        assert!(region.as_mut().poll(&mut context).is_pending());
        assert!(monitor.as_mut().poll(&mut context).is_pending());
        assert_eq!(wakes.0.load(Ordering::SeqCst), 0, "both openings wait");

        drop(lab);
        assert_eq!(
            wakes.0.load(Ordering::SeqCst),
            2,
            "teardown wakes both openings"
        );
        assert!(matches!(
            region.as_mut().poll(&mut context),
            std::task::Poll::Ready(Err(crate::cx::ChildRegionError::RuntimeUnavailable))
        ));
        assert!(matches!(
            monitor.as_mut().poll(&mut context),
            std::task::Poll::Ready(Err(crate::monitor::WatchError::RuntimeUnavailable))
        ));
    }

    /// An established monitor whose DOWN is awaited outside the runtime is
    /// woken at teardown and resolves as unavailable
    /// (br-asupersync-werypv).
    #[test]
    fn teardown_wakes_an_established_monitor_awaited_outside_the_runtime() {
        let mut lab = LabRuntime::new(LabConfig::new(0x0e7e_4f00).max_steps(1024));
        let root = lab.state.create_root_region(crate::types::Budget::INFINITE);
        let (parked, _parked_handle) = lab
            .state
            .create_task(
                root,
                crate::types::Budget::INFINITE,
                std::future::pending::<()>(),
            )
            .expect("create parked task");
        lab.scheduler.lock().schedule(parked, 0);
        let (task, mut joined) = lab
            .state
            .create_task(root, crate::types::Budget::INFINITE, async {
                crate::Cx::current().expect("lab task cx")
            })
            .expect("create task");
        lab.scheduler.lock().schedule(task, 0);
        lab.run_until_idle();
        let cx = joined
            .try_join()
            .expect("join")
            .expect("the task returned its cx");

        let wakes = Arc::new(CountWakes(AtomicUsize::new(0)));
        let waker = std::task::Waker::from(Arc::clone(&wakes));
        let mut context = std::task::Context::from_waker(&waker);
        let mut opening = Box::pin(cx.monitor(parked));
        assert!(opening.as_mut().poll(&mut context).is_pending());
        lab.run_until_idle();
        let std::task::Poll::Ready(Ok(monitor)) = opening.as_mut().poll(&mut context) else {
            panic!("the monitor is established on the parked task");
        };
        let mut down = Box::pin(monitor.down(&cx));
        assert!(down.as_mut().poll(&mut context).is_pending(), "no DOWN yet");
        let before = wakes.0.load(Ordering::SeqCst);

        drop(lab);
        assert!(
            wakes.0.load(Ordering::SeqCst) > before,
            "teardown wakes the waiting DOWN"
        );
        assert!(matches!(
            down.as_mut().poll(&mut context),
            std::task::Poll::Ready(Err(crate::monitor::WatchError::RuntimeUnavailable))
        ));
    }
