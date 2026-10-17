    use super::*;
    use crate::cx::{Cx, cap};
    use crate::lab::{LabConfig, LabRuntime};
    use crate::types::{Budget, RegionId, TaskId};
    use crate::util::{ArenaIndex, DetRng};
    use std::future::Future;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Waker};

    use proptest::prelude::*;

    // ============================================================================
    // Test Infrastructure
    // ============================================================================

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    /// Create a test context for deterministic scheduling.
    fn test_cx() -> Cx<cap::All> {
        test_cx_with_slot(0)
    }

    fn test_cx_with_slot(slot: u32) -> Cx<cap::All> {
        Cx::new(
            RegionId::from_arena(ArenaIndex::new(0, slot)),
            TaskId::from_arena(ArenaIndex::new(0, slot)),
            Budget::INFINITE,
        )
    }

    /// Simple block_on implementation for tests.
    fn block_on<F: Future>(f: F) -> F::Output {
        let waker = std::task::Waker::noop().clone();
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Box::pin(f);
        loop {
            match pinned.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => {}
            }
        }
    }

    fn poll_once<T>(future: &mut (impl Future<Output = T> + Unpin)) -> Option<T> {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        match std::pin::Pin::new(future).poll(&mut cx) {
            Poll::Ready(value) => Some(value),
            Poll::Pending => None,
        }
    }

    /// Count waker that tracks wakeup events.
    #[derive(Debug)]
    struct CountWaker {
        count: Arc<AtomicUsize>,
    }

    impl CountWaker {
        fn new() -> (Self, Arc<AtomicUsize>) {
            let count = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    count: count.clone(),
                },
                count,
            )
        }
    }

    impl std::task::Wake for CountWaker {
        fn wake(self: Arc<Self>) {
            self.count.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Test harness for RwLock metamorphic testing.
    #[derive(Debug)]
    struct RwLockTestHarness<T> {
        lock: Arc<RwLock<T>>,
    }

    impl<T> RwLockTestHarness<T> {
        fn new(value: T) -> Self {
            Self {
                lock: Arc::new(RwLock::new(value)),
            }
        }

        fn lock(&self) -> Arc<RwLock<T>> {
            self.lock.clone()
        }
    }

    // ============================================================================
    // Metamorphic Relations
    // ============================================================================

    /// MR1: Writer Preference Enforcement (Equivalence, Score: 8.5)
    /// Property: A waiting writer blocks all new readers until it is serviced
    /// Catches: Writer starvation, incorrect fairness policy, reader queue jumping
    proptest! {
        #[test]
        fn mr_writer_preference_enforcement(
            num_readers in 2usize..8,
            _seed in any::<u64>(),
        ) {
            let _runtime = std::rc::Rc::new(LabRuntime::new(LabConfig::default()));
            let harness = RwLockTestHarness::new(0u64);
            let lock = harness.lock();
            let cx = test_cx();
            let _rng = DetRng::new(_seed);

            // Establish initial state: acquire write lock to block all subsequent operations
            let write_guard = block_on(lock.write(&cx)).expect("Initial write should succeed");

            // Queue a writer first. This writer should block all later-arriving readers.
            let writer_lock = lock.clone();
            let mut write_fut = OwnedRwLockWriteGuard::write(writer_lock, &cx);
            let (writer_waker, writer_wake_count) = CountWaker::new();
            let writer_waker_obj = Waker::from(Arc::new(writer_waker));
            let mut writer_task_cx = Context::from_waker(&writer_waker_obj);

            let writer_poll = Pin::new(&mut write_fut).poll(&mut writer_task_cx);
            prop_assert!(
                writer_poll.is_pending(),
                "MR1 VIOLATION: Second writer should be pending while first writer active"
            );

            // Create multiple reader futures after the queued writer.
            // These should remain blocked behind the writer turn.
            let mut reader_results = Vec::new();
            for _ in 0..num_readers {
                let lock_clone = lock.clone();
                let (count_waker, wake_count) = CountWaker::new();
                let waker = Waker::from(Arc::new(count_waker));
                let mut task_cx = Context::from_waker(&waker);

                // Use owned future to avoid lifetime issues
                let mut read_fut = OwnedRwLockReadGuard::read(lock_clone, &cx);
                let poll_result = Pin::new(&mut read_fut).poll(&mut task_cx);
                prop_assert!(
                    poll_result.is_pending(),
                    "MR1 VIOLATION: Reader acquired lock while writer was active or queued"
                );

                reader_results.push((read_fut, wake_count));
            }

            // Release the initial write lock
            drop(write_guard);

            // The queued writer should be woken up (has preference)
            prop_assert!(
                writer_wake_count.load(Ordering::SeqCst) > 0,
                "MR1 VIOLATION: Queued writer was not woken when lock released"
            );

            for (_, wake_count) in &reader_results {
                prop_assert_eq!(
                    wake_count.load(Ordering::SeqCst),
                    0,
                    "MR1 VIOLATION: Reader was woken before the older queued writer"
                );
            }

            // Complete the queued writer
            let writer_result = Pin::new(&mut write_fut).poll(&mut writer_task_cx);
            prop_assert!(
                matches!(writer_result, Poll::Ready(Ok(_))),
                "MR1 VIOLATION: Queued writer failed to acquire after being woken"
            );
        }
    }

    /// MR2: Reader Concurrency Capacity (Multiplicative, Score: 7.8)
    /// Property: N readers can coexist without queueing or writer admission
    /// Catches: False reader serialization, leaked waiters, accidental writer barging
    proptest! {
        #[test]
        fn mr_reader_concurrency_capacity(
            num_readers in 2usize..12,
            _seed in any::<u64>(),
        ) {
            let _runtime = std::rc::Rc::new(LabRuntime::new(LabConfig::default()));
            let harness = RwLockTestHarness::new(0u64);
            let lock = harness.lock();
            let cx = test_cx();
            let _rng = DetRng::new(_seed);

            // Ensure no writers are waiting (clean slate)
            prop_assert!(
                matches!(lock.try_read(), Ok(_)),
                "MR2 SETUP VIOLATION: Lock should be available for reads"
            );

            let mut read_guards = Vec::new();

            for _ in 0..num_readers {
                let guard = block_on(lock.read(&cx))
                    .expect("Concurrent reader should succeed");
                read_guards.push(guard);
            }

            prop_assert!(
                read_guards.len() == num_readers,
                "MR2 VIOLATION: Not all concurrent readers succeeded. Got {}, expected {}",
                read_guards.len(), num_readers
            );

            let state = lock.debug_state();
            prop_assert_eq!(
                state.readers,
                num_readers,
                "MR2 VIOLATION: Reader count mismatch while guards are held"
            );
            prop_assert!(
                !state.writer_active && state.writer_waiters == 0,
                "MR2 VIOLATION: Writer state should remain idle while only readers hold the lock"
            );
            prop_assert!(
                state.reader_waiters.is_empty() && state.writer_queue.is_empty(),
                "MR2 VIOLATION: Reader-only acquisition should not enqueue waiters"
            );

            let extra_reader = lock.try_read();
            prop_assert!(
                extra_reader.is_ok(),
                "MR2 VIOLATION: Additional readers should still acquire immediately"
            );
            drop(extra_reader);

            let writer_try_result = lock.try_write();
            prop_assert!(
                matches!(writer_try_result, Err(TryWriteError::Locked)),
                "MR2 VIOLATION: Writer barged in while readers were active"
            );

            drop(read_guards);

            let post_read_writer_try = lock.try_write();
            prop_assert!(
                post_read_writer_try.is_ok(),
                "MR2 VIOLATION: Writer could not acquire after all readers released"
            );
        }
    }

    /// MR3: Writer Cancellation Releases Preference (Invertive, Score: 8.2)
    /// Property: Cancelling a pending writer releases writer-preference for subsequent readers
    /// Catches: Stuck preference state, cancellation cleanup bugs, reader starvation
    proptest! {
        #[test]
        fn mr_writer_cancellation_releases_preference(
            num_readers_after_cancel in 2usize..6,
            _seed in any::<u64>(),
        ) {
            let _runtime = std::rc::Rc::new(LabRuntime::new(LabConfig::default()));
            let harness = RwLockTestHarness::new(0u64);
            let lock = harness.lock();
            let cx = test_cx();
            let _rng = DetRng::new(_seed);

            // Establish writer-preference state by having an active writer
            let blocking_writer = block_on(lock.write(&cx))
                .expect("Blocking writer should acquire");

            // Queue a writer that we will cancel
            let cancelable_lock = lock.clone();
            let mut cancelable_write_fut = OwnedRwLockWriteGuard::write(cancelable_lock, &cx);

            let (cancel_waker, _cancel_wake_count) = CountWaker::new();
            let cancel_waker_obj = Waker::from(Arc::new(cancel_waker));
            let mut cancel_task_cx = Context::from_waker(&cancel_waker_obj);

            // Poll to queue the writer
            let cancel_poll = Pin::new(&mut cancelable_write_fut).poll(&mut cancel_task_cx);
            prop_assert!(
                cancel_poll.is_pending(),
                "MR3 SETUP VIOLATION: Cancelable writer should be pending"
            );

            // Queue readers that should be blocked by writer preference
            let mut reader_futures = Vec::new();
            let mut reader_wake_counts = Vec::new();

            for _ in 0..num_readers_after_cancel {
                let reader_lock = lock.clone();
                let mut read_fut = OwnedRwLockReadGuard::read(reader_lock, &cx);

                let (reader_waker, reader_wake_count) = CountWaker::new();
                let reader_waker_obj = Waker::from(Arc::new(reader_waker));
                let mut reader_task_cx = Context::from_waker(&reader_waker_obj);

                let reader_poll = Pin::new(&mut read_fut).poll(&mut reader_task_cx);
                prop_assert!(
                    reader_poll.is_pending(),
                    "MR3 SETUP VIOLATION: Reader should be blocked by writer preference"
                );

                reader_futures.push(read_fut);
                reader_wake_counts.push(reader_wake_count);
            }

            // Cancel the queued writer by dropping it
            drop(cancelable_write_fut);

            // Release the blocking writer
            drop(blocking_writer);

            // METAMORPHIC ASSERTION: Readers should now be able to acquire
            // (writer preference should be released after writer cancellation)
            for (i, wake_count) in reader_wake_counts.iter().enumerate() {
                prop_assert!(
                    wake_count.load(Ordering::SeqCst) > 0,
                    "MR3 VIOLATION: Reader {} not woken after writer cancellation", i
                );
            }

            // Verify readers can actually complete acquisition
            let mut completed_readers = 0;
            for mut read_fut in reader_futures {
                let (completion_waker, _) = CountWaker::new();
                let completion_waker_obj = Waker::from(Arc::new(completion_waker));
                let mut completion_task_cx = Context::from_waker(&completion_waker_obj);

                let completion_poll = Pin::new(&mut read_fut).poll(&mut completion_task_cx);
                if matches!(completion_poll, Poll::Ready(Ok(_))) {
                    completed_readers += 1;
                }
            }

            prop_assert!(
                completed_readers >= num_readers_after_cancel / 2,
                "MR3 VIOLATION: Too few readers completed after writer cancellation. Got {}, expected at least {}",
                completed_readers, num_readers_after_cancel / 2
            );
        }
    }

    /// MR4: Reader Cancellation Ref Count Correctness (Additive, Score: 8.7)
    /// Property: Reader cancellation during lock-hold correctly releases the read-ref count
    /// Catches: Ref count leaks, stuck read locks, writer starvation from leaked readers
    proptest! {
        #[test]
        fn mr_reader_cancellation_ref_count_correctness(
            num_readers_to_cancel in 1usize..6,
            _seed in any::<u64>(),
        ) {
            let _runtime = std::rc::Rc::new(LabRuntime::new(LabConfig::default()));
            let harness = RwLockTestHarness::new(0u64);
            let lock = harness.lock();
            let cx = test_cx();
            let _rng = DetRng::new(_seed);

            // First acquire multiple readers normally
            let mut reader_guards = Vec::new();
            for _ in 0..num_readers_to_cancel {
                let guard = block_on(lock.read(&cx))
                    .expect("Reader acquisition should succeed");
                reader_guards.push(guard);
            }

            // Verify that a writer cannot acquire while readers are active
            let writer_try_result = lock.try_write();
            prop_assert!(
                matches!(writer_try_result, Err(TryWriteError::Locked)),
                "MR4 SETUP VIOLATION: Writer should be blocked by active readers"
            );

            // Cancel readers by dropping their guards
            let initial_reader_count = reader_guards.len();
            reader_guards.clear(); // Drop all reader guards

            // METAMORPHIC ASSERTION: After all readers are cancelled/dropped,
            // ref count should be zero and writer should be able to acquire
            let post_cancel_writer_try = lock.try_write();
            prop_assert!(
                post_cancel_writer_try.is_ok(),
                "MR4 VIOLATION: Writer cannot acquire after {} readers cancelled - ref count likely leaked",
                initial_reader_count
            );

            // If writer acquired, verify it actually works
            if let Ok(writer_guard) = post_cancel_writer_try {
                // Writer should have exclusive access now
                let concurrent_reader_try = lock.try_read();
                prop_assert!(
                    matches!(concurrent_reader_try, Err(TryReadError::Locked)),
                    "MR4 VIOLATION: Reader can acquire while writer active - exclusive access violated"
                );

                drop(writer_guard);
            }

            // After writer release, readers should work again (ref counting is sound)
            let post_writer_reader = lock.try_read();
            prop_assert!(
                post_writer_reader.is_ok(),
                "MR4 VIOLATION: Readers cannot acquire after writer release - lock state corrupted"
            );
        }
    }

    // ============================================================================
    // Composite Metamorphic Relations
    // ============================================================================

    /// MR5: Writer Preference + Cancellation Composite (Composite, Score: 9.1)
    /// Property: MR1 ∘ MR3 - Writer preference holds even under reader cancellation pressure
    /// Catches: Preference state corruption under cancellation load
    proptest! {
        #[test]
        fn mr_writer_preference_under_cancellation_pressure(
            num_cancellable_readers in 3usize..8,
            num_persistent_readers in 2usize..5,
            _seed in any::<u64>(),
        ) {
            let _runtime = std::rc::Rc::new(LabRuntime::new(LabConfig::default()));
            let harness = RwLockTestHarness::new(0u64);
            let lock = harness.lock();
            let cx = test_cx();
            let _rng = DetRng::new(_seed);

            // Block with initial writer
            let blocking_writer = block_on(lock.write(&cx))
                .expect("Initial writer should acquire");

            // Queue readers that will be cancelled
            let mut cancellable_readers = Vec::new();
            for _ in 0..num_cancellable_readers {
                let reader_lock = lock.clone();
                let read_fut = OwnedRwLockReadGuard::read(reader_lock, &cx);
                cancellable_readers.push(read_fut);
            }

            // Queue a writer (should have preference)
            let priority_writer_lock = lock.clone();
            let mut priority_write_fut = OwnedRwLockWriteGuard::write(priority_writer_lock, &cx);
            let (priority_waker, priority_wake_count) = CountWaker::new();
            let priority_waker_obj = Waker::from(Arc::new(priority_waker));
            let mut priority_task_cx = Context::from_waker(&priority_waker_obj);

            let priority_poll = Pin::new(&mut priority_write_fut).poll(&mut priority_task_cx);
            prop_assert!(
                priority_poll.is_pending(),
                "MR5 SETUP VIOLATION: Priority writer should be pending"
            );

            // Queue persistent readers (should be blocked by writer preference)
            let mut persistent_readers = Vec::new();
            let mut persistent_wake_counts = Vec::new();
            for _ in 0..num_persistent_readers {
                let reader_lock = lock.clone();
                let mut read_fut = OwnedRwLockReadGuard::read(reader_lock, &cx);

                let (reader_waker, reader_wake_count) = CountWaker::new();
                let reader_waker_obj = Waker::from(Arc::new(reader_waker));
                let mut reader_task_cx = Context::from_waker(&reader_waker_obj);

                let reader_poll = Pin::new(&mut read_fut).poll(&mut reader_task_cx);
                prop_assert!(
                    reader_poll.is_pending(),
                    "MR5 SETUP VIOLATION: Persistent reader should be blocked by writer preference"
                );

                persistent_readers.push(read_fut);
                persistent_wake_counts.push(reader_wake_count);
            }

            // Cancel the cancellable readers (simulates cancellation pressure)
            drop(cancellable_readers);

            // Release the blocking writer
            drop(blocking_writer);

            // METAMORPHIC ASSERTION: Priority writer should still get preference
            // despite reader cancellation pressure
            prop_assert!(
                priority_wake_count.load(Ordering::SeqCst) > 0,
                "MR5 VIOLATION: Priority writer not woken despite preference policy"
            );

            // Complete the priority writer
            let priority_result = Pin::new(&mut priority_write_fut).poll(&mut priority_task_cx);
            prop_assert!(
                matches!(priority_result, Poll::Ready(Ok(_))),
                "MR5 VIOLATION: Priority writer failed to acquire despite being woken"
            );

            // Verify persistent readers are still blocked while writer is active
            for (i, wake_count) in persistent_wake_counts.iter().enumerate() {
                prop_assert!(
                    wake_count.load(Ordering::SeqCst) == 0,
                    "MR5 VIOLATION: Persistent reader {} was woken while writer active", i
                );
            }
        }
    }

    #[derive(Debug)]
    struct OlderReaderSuffixOutcome {
        reader_ready_after_release: bool,
        readers_while_guard_held: usize,
        writer_waiters_while_reader_active: usize,
        writer_wakes_before_reader: Vec<usize>,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct UpgradeWriterLivenessSignature {
        active_readers_after_queue: usize,
        queued_writer_waiters_after_queue: usize,
        queued_reader_waiters_after_queue: usize,
        late_reader_wakes_before_writer_turn: Vec<usize>,
        late_readers_pending_while_writer_held: usize,
        late_readers_ready_after_writer_release: usize,
        final_readers: usize,
        final_writer_waiters: usize,
        final_reader_waiters: usize,
    }

    fn older_reader_admission_with_younger_writer_suffix(
        extra_writers: usize,
    ) -> OlderReaderSuffixOutcome {
        let _runtime = std::rc::Rc::new(LabRuntime::new(LabConfig::default()));
        let harness = RwLockTestHarness::new(0u64);
        let lock = harness.lock();
        let cx = test_cx();

        let blocking_writer = block_on(lock.write(&cx)).expect("initial writer should acquire");

        let mut older_reader_fut = OwnedRwLockReadGuard::read(lock.clone(), &cx);
        let (reader_waker, _reader_wake_count) = CountWaker::new();
        let reader_waker_obj = Waker::from(Arc::new(reader_waker));
        let mut reader_task_cx = Context::from_waker(&reader_waker_obj);
        assert!(
            Pin::new(&mut older_reader_fut)
                .poll(&mut reader_task_cx)
                .is_pending(),
            "older reader should queue behind the active writer"
        );

        let mut writer_futs = Vec::new();
        let mut writer_wake_counts = Vec::new();
        let mut writer_wakers = Vec::new();
        for _ in 0..extra_writers {
            let mut writer_fut = OwnedRwLockWriteGuard::write(lock.clone(), &cx);
            let (writer_waker, wake_count) = CountWaker::new();
            let writer_waker_obj = Waker::from(Arc::new(writer_waker));
            let mut writer_task_cx = Context::from_waker(&writer_waker_obj);
            assert!(
                Pin::new(&mut writer_fut)
                    .poll(&mut writer_task_cx)
                    .is_pending(),
                "younger writer should queue behind the older reader"
            );
            writer_futs.push(writer_fut);
            writer_wake_counts.push(wake_count);
            writer_wakers.push(writer_waker_obj);
        }

        drop(blocking_writer);

        let reader_guard = match Pin::new(&mut older_reader_fut).poll(&mut reader_task_cx) {
            Poll::Ready(Ok(guard)) => Some(guard),
            _ => None,
        };
        let state_while_reader_active = lock.debug_state();

        // Snapshot the writer wake counts WHILE the older reader still holds
        // the lock. The property under test is whether any younger writer was
        // woken *before the older reader acquired* — i.e., during the window
        // between the initial writer's release and the reader's admission. We
        // must read the counters here, before dropping the reader guard:
        // releasing the reader legitimately wakes the queued writer via
        // `release_reader`, and capturing the counts afterwards would conflate
        // that expected post-acquisition wake with a fairness violation.
        let writer_wakes_before_reader: Vec<usize> = writer_wake_counts
            .iter()
            .map(|count| count.load(Ordering::SeqCst))
            .collect();

        drop(reader_guard);
        drop(writer_futs);
        drop(writer_wakers);

        OlderReaderSuffixOutcome {
            reader_ready_after_release: state_while_reader_active.readers > 0,
            readers_while_guard_held: state_while_reader_active.readers,
            writer_waiters_while_reader_active: state_while_reader_active.writer_waiters,
            writer_wakes_before_reader,
        }
    }

    fn upgrade_writer_liveness_signature(
        prime_with_read: bool,
        late_readers: usize,
    ) -> UpgradeWriterLivenessSignature {
        let harness = RwLockTestHarness::new(0u64);
        let lock = harness.lock();
        let cx = test_cx();

        let blocking_peer_reader = block_on(lock.read(&cx)).expect("peer reader should acquire");
        if prime_with_read {
            let transient_reader = block_on(lock.read(&cx)).expect("upgrade reader should acquire");
            drop(transient_reader);
        }

        let mut writer_fut = OwnedRwLockWriteGuard::write(lock.clone(), &cx);
        let (writer_waker, writer_wake_count) = CountWaker::new();
        let writer_waker_obj = Waker::from(Arc::new(writer_waker));
        let mut writer_task_cx = Context::from_waker(&writer_waker_obj);
        assert!(
            std::pin::Pin::new(&mut writer_fut)
                .poll(&mut writer_task_cx)
                .is_pending(),
            "writer should queue while the blocking reader is active"
        );

        let mut late_reader_futs = Vec::new();
        let mut late_reader_wake_counts = Vec::new();
        for _ in 0..late_readers {
            let mut late_reader_fut = OwnedRwLockReadGuard::read(lock.clone(), &cx);
            let (late_reader_waker, late_reader_wake_count) = CountWaker::new();
            let late_reader_waker_obj = Waker::from(Arc::new(late_reader_waker));
            let mut late_reader_task_cx = Context::from_waker(&late_reader_waker_obj);
            assert!(
                std::pin::Pin::new(&mut late_reader_fut)
                    .poll(&mut late_reader_task_cx)
                    .is_pending(),
                "late reader should queue behind the waiting writer"
            );
            late_reader_futs.push((late_reader_fut, late_reader_waker_obj));
            late_reader_wake_counts.push(late_reader_wake_count);
        }

        let queued_state = lock.debug_state();
        drop(blocking_peer_reader);

        assert!(
            writer_wake_count.load(Ordering::SeqCst) > 0,
            "writer should be woken once the last blocking reader releases"
        );
        let writer_guard = match std::pin::Pin::new(&mut writer_fut).poll(&mut writer_task_cx) {
            Poll::Ready(Ok(guard)) => guard,
            other => panic!("writer did not acquire after wake: {other:?}"),
        };

        let late_reader_wakes_before_writer_turn = late_reader_wake_counts
            .iter()
            .map(|count| count.load(Ordering::SeqCst))
            .collect::<Vec<_>>();
        let late_readers_pending_while_writer_held = late_reader_futs
            .iter_mut()
            .map(|(fut, waker)| {
                let mut task_cx = Context::from_waker(waker);
                std::pin::Pin::new(fut).poll(&mut task_cx)
            })
            .filter(|poll| poll.is_pending())
            .count();

        drop(writer_guard);

        let mut admitted_late_readers = Vec::new();
        for (mut late_reader_fut, late_reader_waker) in late_reader_futs {
            let mut late_reader_task_cx = Context::from_waker(&late_reader_waker);
            match std::pin::Pin::new(&mut late_reader_fut).poll(&mut late_reader_task_cx) {
                Poll::Ready(Ok(guard)) => admitted_late_readers.push(guard),
                other => panic!("late reader did not acquire after writer turn: {other:?}"),
            }
        }
        let late_readers_ready_after_writer_release = admitted_late_readers.len();
        drop(admitted_late_readers);

        let final_state = lock.debug_state();
        UpgradeWriterLivenessSignature {
            active_readers_after_queue: queued_state.readers,
            queued_writer_waiters_after_queue: queued_state.writer_waiters,
            queued_reader_waiters_after_queue: queued_state.reader_waiters.len(),
            late_reader_wakes_before_writer_turn,
            late_readers_pending_while_writer_held,
            late_readers_ready_after_writer_release,
            final_readers: final_state.readers,
            final_writer_waiters: final_state.writer_waiters,
            final_reader_waiters: final_state.reader_waiters.len(),
        }
    }

    /// MR6: Older Reader Admission Is Invariant To Younger Writer Suffix
    /// (Equivalence, Score: 8.0)
    /// Property: Appending younger writers behind an already-queued reader
    /// must not change that older reader's admission point.
    /// Catches: Queue-order inversions, writer barging over older readers,
    /// starvation-prevention regressions in the mixed reader/writer path.
    proptest! {
        #[test]
        fn mr_older_reader_admission_invariant_to_younger_writer_suffix(
            extra_writers in 1usize..6,
        ) {
            let baseline = older_reader_admission_with_younger_writer_suffix(0);
            let transformed = older_reader_admission_with_younger_writer_suffix(extra_writers);

            prop_assert!(
                baseline.reader_ready_after_release,
                "MR6 SETUP VIOLATION: baseline older reader did not acquire after writer release"
            );
            prop_assert!(
                transformed.reader_ready_after_release,
                "MR6 VIOLATION: older reader was delayed by appended younger writers"
            );
            prop_assert_eq!(
                transformed.readers_while_guard_held,
                baseline.readers_while_guard_held,
                "MR6 VIOLATION: appended younger writers changed active reader cardinality"
            );
            prop_assert_eq!(
                transformed.writer_waiters_while_reader_active,
                extra_writers,
                "MR6 VIOLATION: younger writers should still be queued while the older reader runs"
            );
            for (i, wake_count) in transformed.writer_wakes_before_reader.iter().enumerate() {
                prop_assert_eq!(
                    *wake_count,
                    0,
                    "MR6 VIOLATION: younger writer {} was woken before the older reader acquired",
                    i,
                );
            }
        }
    }

    #[test]
    fn waiting_writer_blocks_late_readers_until_writer_turn_completes() {
        let harness = RwLockTestHarness::new(0u64);
        let lock = harness.lock();
        let cx = test_cx();

        let blocking_reader = block_on(lock.read(&cx)).expect("initial reader should acquire");

        let mut writer_fut = OwnedRwLockWriteGuard::write(lock.clone(), &cx);
        let (writer_waker, writer_wake_count) = CountWaker::new();
        let writer_waker_obj = Waker::from(Arc::new(writer_waker));
        let mut writer_task_cx = Context::from_waker(&writer_waker_obj);
        assert!(
            Pin::new(&mut writer_fut)
                .poll(&mut writer_task_cx)
                .is_pending(),
            "writer should wait behind active reader"
        );

        let mut late_reader_fut = OwnedRwLockReadGuard::read(lock.clone(), &cx);
        let (late_reader_waker, late_reader_wake_count) = CountWaker::new();
        let late_reader_waker_obj = Waker::from(Arc::new(late_reader_waker));
        let mut late_reader_task_cx = Context::from_waker(&late_reader_waker_obj);
        assert!(
            Pin::new(&mut late_reader_fut)
                .poll(&mut late_reader_task_cx)
                .is_pending(),
            "late reader should queue behind waiting writer"
        );

        drop(blocking_reader);

        assert!(
            writer_wake_count.load(Ordering::SeqCst) > 0,
            "writer should be woken when the blocking reader releases"
        );
        assert_eq!(
            late_reader_wake_count.load(Ordering::SeqCst),
            0,
            "late reader must stay blocked until the queued writer runs"
        );

        let writer_guard = match Pin::new(&mut writer_fut).poll(&mut writer_task_cx) {
            Poll::Ready(Ok(guard)) => guard,
            other => panic!("writer did not acquire after wake: {other:?}"),
        };

        assert!(
            Pin::new(&mut late_reader_fut)
                .poll(&mut late_reader_task_cx)
                .is_pending(),
            "late reader must still be blocked while writer guard is held"
        );

        drop(writer_guard);

        assert!(
            late_reader_wake_count.load(Ordering::SeqCst) > 0,
            "late reader should be woken after writer completes its turn"
        );
        assert!(
            matches!(
                Pin::new(&mut late_reader_fut).poll(&mut late_reader_task_cx),
                Poll::Ready(Ok(_))
            ),
            "late reader should acquire once writer turn completes"
        );
    }

    #[test]
    fn cancelled_waiting_writer_reopens_reader_admission() {
        let harness = RwLockTestHarness::new(0u64);
        let lock = harness.lock();
        let cx = test_cx();

        let blocking_reader = block_on(lock.read(&cx)).expect("initial reader should acquire");

        let mut cancelled_writer_fut = OwnedRwLockWriteGuard::write(lock.clone(), &cx);
        let (writer_waker, _writer_wake_count) = CountWaker::new();
        let writer_waker_obj = Waker::from(Arc::new(writer_waker));
        let mut writer_task_cx = Context::from_waker(&writer_waker_obj);
        assert!(
            Pin::new(&mut cancelled_writer_fut)
                .poll(&mut writer_task_cx)
                .is_pending(),
            "writer should queue while reader is active"
        );

        let mut reader_after_cancel_fut = OwnedRwLockReadGuard::read(lock.clone(), &cx);
        let (reader_waker, reader_wake_count) = CountWaker::new();
        let reader_waker_obj = Waker::from(Arc::new(reader_waker));
        let mut reader_task_cx = Context::from_waker(&reader_waker_obj);
        assert!(
            Pin::new(&mut reader_after_cancel_fut)
                .poll(&mut reader_task_cx)
                .is_pending(),
            "reader should be blocked while writer preference is active"
        );

        drop(cancelled_writer_fut);
        let state_after_cancel = lock.debug_state();
        assert_eq!(
            state_after_cancel.writer_waiters, 0,
            "cancelling the queued writer must release writer preference"
        );

        drop(blocking_reader);

        assert!(
            reader_wake_count.load(Ordering::SeqCst) > 0,
            "reader should be woken once the cancelled writer no longer blocks admission"
        );
        assert!(
            matches!(
                Pin::new(&mut reader_after_cancel_fut).poll(&mut reader_task_cx),
                Poll::Ready(Ok(_))
            ),
            "reader should acquire after the cancelled writer is removed"
        );
    }

    #[test]
    fn metamorphic_read_then_write_preserves_liveness_under_reader_pressure() {
        let baseline = upgrade_writer_liveness_signature(false, 2);
        let transformed = upgrade_writer_liveness_signature(true, 2);

        assert_eq!(
            transformed, baseline,
            "dropping an upgrader's read guard before queueing write must preserve the same writer-liveness signature under reader pressure"
        );
        assert_eq!(
            baseline.active_readers_after_queue, 1,
            "the transient upgrader read must not leak into the queued writer state"
        );
        assert_eq!(
            baseline.queued_writer_waiters_after_queue, 1,
            "exactly one writer should be queued in the upgrade-liveness scenario"
        );
        assert_eq!(
            baseline.queued_reader_waiters_after_queue, 2,
            "both late readers should remain queued behind the writer"
        );
        assert!(
            baseline
                .late_reader_wakes_before_writer_turn
                .iter()
                .all(|wake_count| *wake_count == 0),
            "late readers must not be woken before the writer turn completes"
        );
        assert_eq!(
            baseline.late_readers_pending_while_writer_held, 2,
            "late readers must stay pending while the writer guard is held"
        );
        assert_eq!(
            baseline.late_readers_ready_after_writer_release, 2,
            "all queued late readers should be admitted once the writer releases"
        );
        assert_eq!(
            (
                baseline.final_readers,
                baseline.final_writer_waiters,
                baseline.final_reader_waiters
            ),
            (0, 0, 0),
            "the mixed read-then-write path must drain all waiter state"
        );
    }

    /// br-asupersync-jxq2e6: writer-preference under reader-cancellation
    /// cascade. The invariant: cancelling N pending readers (while a
    /// writer is queued behind the writer-preference gate) MUST allow
    /// the writer to acquire — the cancelled readers must not leak
    /// reader-waiter slots that keep the writer-preference gate down.
    ///
    /// Concrete shape:
    ///   1. Reader-1 acquires the lock.
    ///   2. Writer arrives, queues, raises the writer-preference flag
    ///      so subsequent readers must wait.
    ///   3. Three readers (R-2, R-3, R-4) arrive and queue behind
    ///      the writer (preference gate blocks them).
    ///   4. All three readers cancel (futures dropped).
    ///   5. Reader-1 releases.
    ///   6. The writer MUST acquire — the three cancelled-reader
    ///      slots must have been cleared, not left dangling.
    #[test]
    fn jxq2e6_writer_preference_holds_under_reader_cancellation_cascade() {
        let lock = Arc::new(RwLock::new(0_u32));

        let cx = test_cx();
        // Step 1: reader-1 acquires.
        let reader_1 = block_on(lock.read(&cx)).expect("reader-1 acquires");
        let state = lock.debug_state();
        assert_eq!(state.readers, 1, "jxq2e6: one active reader");

        // Step 2: writer arrives, queues, raises writer-preference.
        let waker = Waker::noop().clone();
        let mut writer_task_cx = Context::from_waker(&waker);
        let mut writer_fut = lock.write(&cx);
        let pending = Pin::new(&mut writer_fut)
            .poll(&mut writer_task_cx)
            .is_pending();
        assert!(pending, "jxq2e6: writer must queue while reader-1 holds");

        // Step 3: three readers queue behind the writer-preference gate.
        let mut reader_2 = lock.read(&cx);
        let mut reader_3 = lock.read(&cx);
        let mut reader_4 = lock.read(&cx);
        for r in [
            Pin::new(&mut reader_2),
            Pin::new(&mut reader_3),
            Pin::new(&mut reader_4),
        ] {
            assert!(
                r.poll(&mut writer_task_cx).is_pending(),
                "jxq2e6: queued reader must wait for writer-preference"
            );
        }

        // Step 4: cancel all three pending readers.
        drop(reader_2);
        drop(reader_3);
        drop(reader_4);

        let state_after_cancel = lock.debug_state();
        assert!(
            state_after_cancel.reader_waiters.is_empty(),
            "jxq2e6: cancelled reader-waiter slots must clear (got {} waiters)",
            state_after_cancel.reader_waiters.len()
        );
        assert_eq!(
            state_after_cancel.writer_waiters, 1,
            "jxq2e6: writer still queued"
        );

        // Step 5: reader-1 releases.
        drop(reader_1);

        // Step 6: writer MUST acquire. If the cancelled reader slots
        // had leaked, the lock would still see them as live and
        // refuse to admit the writer.
        let writer_acquired = matches!(
            Pin::new(&mut writer_fut).poll(&mut writer_task_cx),
            Poll::Ready(Ok(_))
        );
        assert!(
            writer_acquired,
            "jxq2e6: writer MUST acquire after reader-1 release + cancelled-reader cleanup"
        );
    }

    #[test]
    fn forced_reader_batch_does_not_strand_readers_when_writer_queue_drains_empty() {
        // Regression: when a writer streak reaches the forced-reader-batch
        // threshold at the exact moment the writer queue drains to empty, the
        // old code forced a single-reader turn (`take_forced_reader_turn`),
        // waking only ONE queued reader. `release_reader` only ever wakes
        // writers, so a second queued reader hung forever with the lock free.
        let lock = Arc::new(RwLock::new(0_u32));
        let cx = test_cx();
        let waker = Waker::noop().clone();
        let mut tcx = Context::from_waker(&waker);

        // W0 holds the lock.
        let w0 = block_on(lock.write(&cx)).expect("w0 acquires");

        // Queue exactly MAX_CONSECUTIVE_WRITERS_BEFORE_READER_BATCH writers so
        // draining them all leaves the counter at the forced-batch threshold
        // with an empty writer queue.
        let n = MAX_CONSECUTIVE_WRITERS_BEFORE_READER_BATCH;
        let mut writers: Vec<_> = (0..n).map(|_| Box::pin(lock.write(&cx))).collect();
        for w in &mut writers {
            assert!(w.as_mut().poll(&mut tcx).is_pending(), "writer must queue");
        }

        // Two readers queue behind the writers (writer-preference).
        let mut r1 = Box::pin(lock.read(&cx));
        let mut r2 = Box::pin(lock.read(&cx));
        assert!(r1.as_mut().poll(&mut tcx).is_pending(), "reader 1 queues");
        assert!(r2.as_mut().poll(&mut tcx).is_pending(), "reader 2 queues");

        // Release W0, then drain every queued writer one at a time. Each
        // hand-off bumps the consecutive-writer counter; the final drop leaves
        // the writer queue empty at the threshold with both readers queued.
        drop(w0);
        for (i, w) in writers.iter_mut().enumerate() {
            match w.as_mut().poll(&mut tcx) {
                Poll::Ready(Ok(g)) => drop(g),
                other => panic!("writer {i} should acquire+release, got {other:?}"),
            }
        }

        // BOTH readers must now be admitted — not just one.
        let r1_ok = matches!(r1.as_mut().poll(&mut tcx), Poll::Ready(Ok(_)));
        let r2_ok = matches!(r2.as_mut().poll(&mut tcx), Poll::Ready(Ok(_)));
        assert!(r1_ok, "reader 1 must acquire once writers drain");
        assert!(
            r2_ok,
            "reader 2 must acquire — pre-fix it was stranded with the lock free"
        );
    }

    /// Metamorphic property: reader-writer fairness under continuous write pressure.
    ///
    /// Property: when writers continuously arrive and readers are queued, each run of
    /// MAX_CONSECUTIVE_WRITERS_BEFORE_READER_BATCH queued-writer hand-offs creates one
    /// forced FIFO reader turn. This checks the first turn, not a wall-clock or
    /// queue-position-independent per-reader bound.
    ///
    /// Metamorphic relationship: increasing excess write pressure must not suppress
    /// that first forced reader turn.
    proptest! {
        #[test]
        fn mr_reader_writer_fairness_bound_invariant(
            num_excess_writers in 1usize..8,
            num_queued_readers in 2usize..5,
        ) {
            let _runtime = std::rc::Rc::new(LabRuntime::new(LabConfig::default()));
            let harness = RwLockTestHarness::new(0u64);
            let lock = harness.lock();
            let cx = test_cx();

            // Total writers = threshold + excess (guarantees a forced turn).
            let total_writers = MAX_CONSECUTIVE_WRITERS_BEFORE_READER_BATCH + num_excess_writers;

            // Start with active writer to force queuing
            let initial_writer = block_on(lock.write(&cx)).expect("initial writer acquire");

            // Queue and poll writers first so they are present in the lock's
            // waiter chain before the readers arrive. The excess writers keep
            // that chain non-empty at the threshold.
            let mut writer_futures = Vec::new();
            for _ in 0..total_writers {
                let writer_lock = lock.clone();
                let mut write_fut = OwnedRwLockWriteGuard::write(writer_lock, &cx);
                prop_assert!(
                    poll_once(&mut write_fut).is_none(),
                    "successor writer should queue"
                );
                writer_futures.push(write_fut);
            }

            // Queue readers behind the established writer chain to observe the
            // first forced FIFO turn rather than natural reader admission.
            //
            // The read futures MUST stay alive to remain queued: dropping a
            // pending read future deregisters its waiter, after which a forced
            // reader turn has nothing to wake.
            let mut reader_futures = Vec::new();
            let mut reader_wake_counts = Vec::new();
            for i in 0..num_queued_readers {
                let reader_lock = lock.clone();
                let mut read_fut = OwnedRwLockReadGuard::read(reader_lock, &cx);

                let (waker, count) = CountWaker::new();
                let waker_obj = Waker::from(Arc::new(waker));
                let mut task_cx = Context::from_waker(&waker_obj);

                prop_assert!(
                    Pin::new(&mut read_fut).poll(&mut task_cx).is_pending(),
                    "Reader {} should be blocked", i
                );

                reader_wake_counts.push(count);
                reader_futures.push(read_fut);
            }

            // Release initial writer to start the consecutive writer sequence
            drop(initial_writer);

            // Execute exactly one threshold-length writer run. FIFO ordering
            // makes the first queued future ready at each hand-off.
            for handoff in 1..=MAX_CONSECUTIVE_WRITERS_BEFORE_READER_BATCH {
                let writer_guard = match poll_once(&mut writer_futures[0]) {
                    Some(Ok(guard)) => guard,
                    other => return Err(TestCaseError::fail(format!(
                        "oldest writer should acquire at hand-off {handoff}: {other:?}"
                    ))),
                };
                drop(writer_futures.remove(0));
                drop(writer_guard);
            }

            let total_reader_wakes = reader_wake_counts
                .iter()
                .map(|count| count.load(Ordering::SeqCst))
                .sum::<usize>();
            prop_assert_eq!(
                total_reader_wakes,
                1,
                "exactly one FIFO reader should wake at the threshold (excess={})",
                num_excess_writers
            );

            let reader_guard = match poll_once(&mut reader_futures[0]) {
                Some(Ok(guard)) => guard,
                other => return Err(TestCaseError::fail(format!(
                    "oldest reader should acquire at the threshold: {other:?}"
                ))),
            };
            for younger_reader in &mut reader_futures[1..] {
                prop_assert!(
                    poll_once(younger_reader).is_none(),
                    "forced turn must not admit a younger queued reader"
                );
            }
            drop(reader_futures.remove(0));
            drop(reader_guard);

            // Pending futures clean up their waiter registrations on drop.
            drop(writer_futures);
            drop(reader_futures);
        }
    }

    /// Writer starvation prevention audit test.
    ///
    /// Verifies that when readers continuously attempt to acquire read locks,
    /// queued writers still get scheduled and cannot wait forever. This test
    /// validates the core below-threshold invariant: after a writer is queued,
    /// a new reader remains queued until that writer runs.
    #[test]
    fn audit_rwlock_writer_starvation_prevention() {
        init_test("audit_rwlock_writer_starvation_prevention");
        let cx = test_cx();
        let lock = RwLock::new(42u64);

        // Step 1: Acquire initial read lock to force writer to queue
        let initial_reader = block_on(lock.read(&cx)).expect("initial reader should acquire");

        // Step 2: Queue a writer (will be blocked by the active reader)
        let mut writer_fut = lock.write(&cx);
        let writer_pending = poll_once(&mut writer_fut).is_none();
        assert!(
            writer_pending,
            "writer should be pending while reader is active"
        );

        // Verify writer_waiters count increased
        {
            let state = lock.state.lock();
            assert!(
                state.writer_waiters > 0,
                "writer_waiters should be > 0 after queuing writer, got {}",
                state.writer_waiters
            );
        }

        // Step 3: Try to acquire new read locks - these should be BLOCKED
        // even though no writer is currently active, because writer_waiters > 0
        let mut new_reader_fut1 = lock.read(&cx);
        let reader1_blocked = poll_once(&mut new_reader_fut1).is_none();
        assert!(
            reader1_blocked,
            "new reader should be blocked when writer_waiters > 0"
        );

        let mut new_reader_fut2 = lock.read(&cx);
        let reader2_blocked = poll_once(&mut new_reader_fut2).is_none();
        assert!(
            reader2_blocked,
            "second new reader should also be blocked when writer_waiters > 0"
        );

        // Step 4: Verify try_read() also correctly blocks due to waiting writers
        let try_read_result = lock.try_read();
        assert!(
            matches!(try_read_result, Err(TryReadError::Locked)),
            "try_read should fail with Locked when writers are waiting, got {:?}",
            try_read_result
        );

        // Step 5: Release the initial reader - this should wake the writer, NOT the new readers
        drop(initial_reader);

        // Step 6: Writer should now be able to acquire the lock
        let writer_guard = poll_once(&mut writer_fut);
        assert!(
            writer_guard.is_some() && writer_guard.as_ref().unwrap().is_ok(),
            "writer should acquire lock after initial reader releases"
        );

        // Step 7: New readers should still be blocked while writer is active
        let reader1_still_blocked = poll_once(&mut new_reader_fut1).is_none();
        let reader2_still_blocked = poll_once(&mut new_reader_fut2).is_none();
        assert!(
            reader1_still_blocked && reader2_still_blocked,
            "readers should remain blocked while writer is active"
        );

        // Step 8: Release the writer - now the queued readers should be able to acquire
        drop(writer_guard.unwrap().unwrap());

        let reader1_acquired = poll_once(&mut new_reader_fut1);
        let reader2_acquired = poll_once(&mut new_reader_fut2);
        assert!(
            reader1_acquired.is_some() && reader1_acquired.as_ref().unwrap().is_ok(),
            "reader1 should acquire after writer releases"
        );
        assert!(
            reader2_acquired.is_some() && reader2_acquired.as_ref().unwrap().is_ok(),
            "reader2 should acquire after writer releases"
        );

        // Step 9: Verify final state is clean
        {
            let state = lock.state.lock();
            assert_eq!(
                state.writer_waiters, 0,
                "writer_waiters should be 0 after writer completes"
            );
            assert_eq!(state.readers, 2, "should have 2 active readers");
            assert!(!state.writer_active, "no writer should be active");
        }

        crate::test_complete!("audit_rwlock_writer_starvation_prevention");
    }

    #[test]
    fn audit_rwlock_no_read_to_write_upgrade() {
        init_test("audit_rwlock_no_read_to_write_upgrade");
        let cx = test_cx();
        let lock = RwLock::new(0_u32);

        let read_guard = block_on(lock.read(&cx)).expect("initial read guard should acquire");
        assert_eq!(*read_guard, 0);
        assert!(
            matches!(lock.try_write(), Err(TryWriteError::Locked)),
            "RwLock intentionally has no in-place read-to-write upgrade; try_write must fail while a read guard is held"
        );

        let mut write_fut = lock.write(&cx);
        assert!(
            poll_once(&mut write_fut).is_none(),
            "write acquisition must wait until the read guard is dropped"
        );

        let state_while_read_held = lock.debug_state();
        assert_eq!(state_while_read_held.readers, 1);
        assert_eq!(state_while_read_held.writer_waiters, 1);
        assert!(
            !state_while_read_held.writer_active,
            "writer must not become active while a read guard is held"
        );

        let mut late_reader_fut = lock.read(&cx);
        assert!(
            poll_once(&mut late_reader_fut).is_none(),
            "late reader must queue behind the pending writer"
        );

        drop(read_guard);

        let mut write_guard = poll_once(&mut write_fut)
            .expect("writer should acquire after dropping read guard")
            .expect("writer acquisition should succeed");
        *write_guard = 7;

        assert!(
            poll_once(&mut late_reader_fut).is_none(),
            "late reader must remain blocked while the writer guard is active"
        );

        drop(write_guard);

        let late_reader = poll_once(&mut late_reader_fut)
            .expect("late reader should acquire after writer releases")
            .expect("late reader acquisition should succeed");
        assert_eq!(
            *late_reader, 7,
            "late reader should observe the write made after the read guard was dropped"
        );

        let state_with_late_reader = lock.debug_state();
        assert_eq!(state_with_late_reader.readers, 1);
        assert_eq!(state_with_late_reader.writer_waiters, 0);
        assert_eq!(state_with_late_reader.reader_waiters.len(), 0);
        assert!(!state_with_late_reader.writer_active);

        drop(late_reader);
        let final_state = lock.debug_state();
        assert_eq!(final_state.readers, 0);
        assert_eq!(final_state.writer_waiters, 0);
        assert_eq!(final_state.reader_waiters.len(), 0);
        assert!(!final_state.writer_active);

        let cancel_cx = test_cx_with_slot(14);
        let cancel_lock = RwLock::new(1_u32);
        let blocking_read =
            block_on(cancel_lock.read(&cx)).expect("blocking read guard should acquire");
        let mut cancelled_write_fut = cancel_lock.write(&cancel_cx);
        assert!(
            poll_once(&mut cancelled_write_fut).is_none(),
            "write waiter should queue behind the active read guard before cancellation"
        );

        cancel_cx.set_cancel_requested(true);
        assert!(
            matches!(
                poll_once(&mut cancelled_write_fut),
                Some(Err(RwLockError::Cancelled))
            ),
            "cancelled write waiter must return a cancellation error without acquiring the lock"
        );

        let state_after_cancel = cancel_lock.debug_state();
        assert_eq!(state_after_cancel.readers, 1);
        assert_eq!(state_after_cancel.writer_waiters, 0);
        assert_eq!(state_after_cancel.writer_queue.len(), 0);
        assert!(!state_after_cancel.writer_active);

        drop(blocking_read);
        let final_cancel_state = cancel_lock.debug_state();
        assert_eq!(final_cancel_state.readers, 0);
        assert_eq!(final_cancel_state.writer_waiters, 0);
        assert_eq!(final_cancel_state.writer_queue.len(), 0);
        assert_eq!(final_cancel_state.reader_waiters.len(), 0);
        assert!(!final_cancel_state.writer_active);

        crate::test_complete!("audit_rwlock_no_read_to_write_upgrade");
    }

    /// Regression test for asupersync-0tv9bv item 3: abandoning a pre-granted
    /// waiter before its next poll must not release a lock-order acquisition
    /// that never happened. A separate lock with the same diagnostic identity
    /// makes an unmatched release observable.
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    #[test]
    fn abandoning_pregranted_waiter_preserves_existing_lock_order_record() {
        fn tracked_regions_locks() -> usize {
            crate::sync::lock_ordering::current_held_locks()
                .get(&LockRank::Regions)
                .map_or(0, |locks| {
                    locks
                        .iter()
                        .filter(|lock| lock.name == "regions_table")
                        .count()
                })
        }

        init_test("abandoning_pregranted_waiter_preserves_existing_lock_order_record");
        crate::sync::lock_ordering::clear_held_locks();
        let cx = test_cx();

        // A queued reader is pre-granted when the blocking writer releases,
        // but the reader future has not yet polled to record its acquisition.
        {
            let sentinel = RwLock::with_name("regions_table", 0_u32);
            let lock = RwLock::with_name("regions_table", 42_u32);
            let sentinel_guard = block_on(sentinel.read(&cx)).expect("sentinel read");
            let blocking_writer = block_on(lock.write(&cx)).expect("blocking write");
            assert_eq!(tracked_regions_locks(), 2);

            let mut read_fut = lock.read(&cx);
            let pending = poll_once(&mut read_fut).is_none();
            crate::assert_with_log!(pending, "reader queued", true, pending);

            drop(blocking_writer);
            assert_eq!(tracked_regions_locks(), 1);

            drop(read_fut);
            assert_eq!(
                tracked_regions_locks(),
                1,
                "abandoning an unpolled read grant must preserve the sentinel record"
            );

            let state = lock.debug_state();
            crate::assert_with_log!(
                state.readers == 0 && !state.writer_active,
                "abandoned read grant cleaned up",
                true,
                state.readers == 0 && !state.writer_active
            );

            drop(sentinel_guard);
            assert_eq!(tracked_regions_locks(), 0);
        }

        // The same invariant applies to a queued writer pre-granted by the
        // final blocking reader.
        {
            let sentinel = RwLock::with_name("regions_table", 0_u32);
            let lock = RwLock::with_name("regions_table", 42_u32);
            let sentinel_guard = block_on(sentinel.read(&cx)).expect("sentinel read");
            let blocking_reader = block_on(lock.read(&cx)).expect("blocking read");
            assert_eq!(tracked_regions_locks(), 2);

            let mut write_fut = lock.write(&cx);
            let pending = poll_once(&mut write_fut).is_none();
            crate::assert_with_log!(pending, "writer queued", true, pending);

            drop(blocking_reader);
            assert_eq!(tracked_regions_locks(), 1);

            drop(write_fut);
            assert_eq!(
                tracked_regions_locks(),
                1,
                "abandoning an unpolled write grant must preserve the sentinel record"
            );

            let state = lock.debug_state();
            crate::assert_with_log!(
                !state.writer_active && state.writer_waiters == 0,
                "abandoned write grant cleaned up",
                true,
                !state.writer_active && state.writer_waiters == 0
            );

            drop(sentinel_guard);
            assert_eq!(tracked_regions_locks(), 0);
        }

        crate::sync::lock_ordering::clear_held_locks();
        crate::test_complete!("abandoning_pregranted_waiter_preserves_existing_lock_order_record");
    }

    #[cfg(debug_assertions)]
    #[test]
    fn queued_read_handoff_checks_lock_order_before_recording_grant() {
        init_test("queued_read_handoff_checks_lock_order_before_recording_grant");
        crate::sync::lock_ordering::clear_held_locks();
        let cx = test_cx();

        let regions_lock = RwLock::with_name("regions_table", 0_u32);
        let tasks_lock = RwLock::with_name("tasks_queue", 0_u32);

        let active_region_writer = block_on(regions_lock.write(&cx)).expect("region writer");
        let tasks_guard = block_on(tasks_lock.write(&cx)).expect("tasks writer");

        let mut read_fut = regions_lock.read(&cx);
        let queued = poll_once(&mut read_fut).is_none();
        crate::assert_with_log!(queued, "reader queued behind writer", true, queued);

        drop(active_region_writer);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = poll_once(&mut read_fut);
        }));
        assert!(
            result.is_err(),
            "pre-granted read waiter must reject Regions acquisition while Tasks is held"
        );

        drop(read_fut);
        drop(tasks_guard);
        crate::sync::lock_ordering::clear_held_locks();

        let state = regions_lock.debug_state();
        assert_eq!(state.readers, 0);
        assert!(!state.writer_active);
        crate::test_complete!("queued_read_handoff_checks_lock_order_before_recording_grant");
    }

    #[cfg(debug_assertions)]
    #[test]
    fn queued_write_handoff_checks_lock_order_before_recording_grant() {
        init_test("queued_write_handoff_checks_lock_order_before_recording_grant");
        crate::sync::lock_ordering::clear_held_locks();
        let cx = test_cx();

        let regions_lock = RwLock::with_name("regions_table", 0_u32);
        let tasks_lock = RwLock::with_name("tasks_queue", 0_u32);

        let active_region_reader = block_on(regions_lock.read(&cx)).expect("region reader");
        let tasks_guard = block_on(tasks_lock.write(&cx)).expect("tasks writer");

        let mut write_fut = regions_lock.write(&cx);
        let queued = poll_once(&mut write_fut).is_none();
        crate::assert_with_log!(queued, "writer queued behind reader", true, queued);

        drop(active_region_reader);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = poll_once(&mut write_fut);
        }));
        assert!(
            result.is_err(),
            "pre-granted write waiter must reject Regions acquisition while Tasks is held"
        );

        drop(write_fut);
        drop(tasks_guard);
        crate::sync::lock_ordering::clear_held_locks();

        let state = regions_lock.debug_state();
        assert_eq!(state.readers, 0);
        assert_eq!(state.writer_waiters, 0);
        assert!(!state.writer_active);
        crate::test_complete!("queued_write_handoff_checks_lock_order_before_recording_grant");
    }

    /// br-asupersync-1dydby: nonblocking `try_read`/`try_write` calls that fail
    /// eligibility (a writer is active) must return their `Err` variant, not
    /// panic ASUP-E205 or record a phantom acquisition edge, even when the
    /// caller holds a higher-ranked (Tasks) lock. An *available* lower-ranked
    /// acquisition must still enforce the ordering panic.
    #[cfg(debug_assertions)]
    #[test]
    fn failed_try_read_write_returns_err_without_false_lock_order_panic() {
        init_test("failed_try_read_write_returns_err_without_false_lock_order_panic");
        crate::sync::lock_ordering::clear_held_locks();

        // Acquire Regions(30) then Tasks(40) -- valid ascending order -- so the
        // caller legitimately holds the higher-ranked Tasks lock. A held writer
        // on `regions` makes both nonblocking views unavailable.
        let regions = RwLock::with_name("regions_table", 0u32);
        let tasks = RwLock::with_name("tasks_queue", 0u32);
        let regions_writer = regions
            .try_write()
            .expect("regions write (valid order, first)");
        let tasks_writer = tasks
            .try_write()
            .expect("tasks write (valid order, second)");

        // (1) try_read unavailable (writer active) -> Locked, not panic.
        let read_locked = matches!(regions.try_read(), Err(TryReadError::Locked));
        crate::assert_with_log!(
            read_locked,
            "unavailable lower-ranked try_read returns Locked, not ASUP-E205",
            true,
            read_locked
        );

        // (2) try_write unavailable (writer active) -> Locked, not panic.
        let write_locked = matches!(regions.try_write(), Err(TryWriteError::Locked));
        crate::assert_with_log!(
            write_locked,
            "unavailable lower-ranked try_write returns Locked, not ASUP-E205",
            true,
            write_locked
        );

        // (3) Available read + violation -> must still panic ASUP-E205.
        let avail_read = RwLock::with_name("regions_table", 0u32);
        let read_enforced = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = avail_read.try_read();
        }))
        .is_err();
        crate::assert_with_log!(
            read_enforced,
            "available lower-ranked try_read still enforces ordering panic",
            true,
            read_enforced
        );

        // (4) Available write + violation -> must still panic ASUP-E205.
        let avail_write = RwLock::with_name("regions_table", 0u32);
        let write_enforced = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = avail_write.try_write();
        }))
        .is_err();
        crate::assert_with_log!(
            write_enforced,
            "available lower-ranked try_write still enforces ordering panic",
            true,
            write_enforced
        );

        drop(tasks_writer);
        drop(regions_writer);
        crate::sync::lock_ordering::clear_held_locks();

        // The rejected acquisitions must not have mutated state or recorded an
        // edge: with the higher-ranked locks released, they acquire cleanly.
        let read_clean = avail_read.try_read().is_ok();
        let write_clean = avail_write.try_write().is_ok();
        crate::assert_with_log!(
            read_clean && write_clean,
            "rejected try_read/try_write left the locks acquirable (no phantom state)",
            true,
            read_clean && write_clean
        );
        crate::sync::lock_ordering::clear_held_locks();
        crate::test_complete!("failed_try_read_write_returns_err_without_false_lock_order_panic");
    }

    #[test]
    fn write_guard_acquired_during_unwinding_does_not_poison_rwlock() {
        let lock = RwLock::new(42);

        struct Cleanup<'a> {
            lock: &'a RwLock<i32>,
        }
        impl Drop for Cleanup<'_> {
            fn drop(&mut self) {
                assert!(std::thread::panicking());
                let mut guard = self
                    .lock
                    .try_write()
                    .expect("try_write during unwinding should succeed");
                *guard += 1;
            }
        }

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _cleanup = Cleanup { lock: &lock };
            panic!("intentional panic to trigger unwinding cleanup");
        }));
        assert!(result.is_err());

        assert!(
            !lock.is_poisoned(),
            "rwlock must not be poisoned by write guard acquired during unwinding"
        );
        let guard = lock
            .try_read()
            .expect("lock should be acquirable after unwinding cleanup");
        assert_eq!(*guard, 43);
    }

    #[test]
    fn owned_write_guard_acquired_during_unwinding_does_not_poison_rwlock() {
        let lock = Arc::new(RwLock::new(100));

        struct OwnedCleanup {
            lock: Arc<RwLock<i32>>,
        }
        impl Drop for OwnedCleanup {
            fn drop(&mut self) {
                assert!(std::thread::panicking());
                let mut guard = OwnedRwLockWriteGuard::try_write(Arc::clone(&self.lock))
                    .expect("try_write during unwinding should succeed");
                *guard += 5;
            }
        }

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _cleanup = OwnedCleanup {
                lock: Arc::clone(&lock),
            };
            panic!("intentional panic for owned cleanup");
        }));
        assert!(result.is_err());

        assert!(
            !lock.is_poisoned(),
            "rwlock must not be poisoned by owned write guard acquired during unwinding"
        );
        let guard = lock
            .try_read()
            .expect("lock should be acquirable after owned unwinding cleanup");
        assert_eq!(*guard, 105);
    }

    #[test]
    fn panic_while_holding_write_guard_poisons_rwlock() {
        let lock = RwLock::new(10);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = lock.try_write().unwrap();
            panic!("panic while holding guard");
        }));
        assert!(result.is_err());
        assert!(
            lock.is_poisoned(),
            "panic while holding write guard must poison rwlock"
        );
    }
