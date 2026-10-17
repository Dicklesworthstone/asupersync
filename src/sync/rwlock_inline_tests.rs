    use super::*;
    use crate::cx::cap;
    use crate::test_utils::init_test_logging;
    use crate::util::ArenaIndex;
    use std::sync::Arc as StdArc;
    use std::sync::Weak;
    use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
    use std::thread;

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    fn poll_once<T>(future: &mut (impl Future<Output = T> + Unpin)) -> Option<T> {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        match std::pin::Pin::new(future).poll(&mut cx) {
            Poll::Ready(v) => Some(v),
            Poll::Pending => None,
        }
    }

    fn poll_until_ready<T>(future: impl Future<Output = T>) -> T {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut future = std::pin::pin!(future);
        loop {
            match future.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    fn read_blocking<'a, T>(lock: &'a RwLock<T>, cx: &Cx) -> RwLockReadGuard<'a, T> {
        poll_until_ready(lock.read(cx)).expect("read failed")
    }

    fn write_blocking<'a, T>(lock: &'a RwLock<T>, cx: &Cx) -> RwLockWriteGuard<'a, T> {
        poll_until_ready(lock.write(cx)).expect("write failed")
    }

    fn test_cx() -> Cx<cap::All> {
        test_cx_with_slot(0)
    }

    fn test_cx_with_slot(slot: u32) -> Cx<cap::All> {
        Cx::new(
            crate::types::RegionId::from_arena(ArenaIndex::new(0, slot)),
            crate::types::TaskId::from_arena(ArenaIndex::new(0, slot)),
            crate::types::Budget::INFINITE,
        )
    }

    struct StateLockDropProbe {
        lock: Weak<RwLock<()>>,
        dropped: StdArc<AtomicBool>,
        state_was_unlocked: StdArc<AtomicBool>,
    }

    #[allow(clippy::manual_noop_waker)]
    impl std::task::Wake for StateLockDropProbe {
        fn wake(self: StdArc<Self>) {}
    }

    impl Drop for StateLockDropProbe {
        fn drop(&mut self) {
            let state_was_unlocked = self
                .lock
                .upgrade()
                .is_some_and(|lock| lock.state.try_lock().is_some());
            self.state_was_unlocked
                .store(state_was_unlocked, AtomicOrdering::SeqCst);
            self.dropped.store(true, AtomicOrdering::SeqCst);
        }
    }

    fn state_lock_drop_probe(
        lock: &StdArc<RwLock<()>>,
    ) -> (Waker, StdArc<AtomicBool>, StdArc<AtomicBool>) {
        let dropped = StdArc::new(AtomicBool::new(false));
        let state_was_unlocked = StdArc::new(AtomicBool::new(false));
        let waker = Waker::from(StdArc::new(StateLockDropProbe {
            lock: StdArc::downgrade(lock),
            dropped: StdArc::clone(&dropped),
            state_was_unlocked: StdArc::clone(&state_was_unlocked),
        }));
        (waker, dropped, state_was_unlocked)
    }

    fn poll_with_waker<T>(
        future: &mut (impl Future<Output = T> + Unpin),
        waker: &Waker,
    ) -> Poll<T> {
        let mut context = Context::from_waker(waker);
        Pin::new(future).poll(&mut context)
    }

    fn assert_probe_retired_after_unlock(
        dropped: &AtomicBool,
        state_was_unlocked: &AtomicBool,
        path: &str,
    ) {
        assert!(dropped.load(AtomicOrdering::SeqCst), "{path} probe dropped");
        assert!(
            state_was_unlocked.load(AtomicOrdering::SeqCst),
            "{path} RawWaker owner must be destroyed after releasing rwlock state"
        );
    }

    /// br-asupersync-dkubr0: releasing a write lock pregrants a batch of eligible
    /// reader waiters (their reader slots are reserved under the state lock) and
    /// then wakes them. A first safe reader Waker panic must not strand the later
    /// pregranted readers -- they must still be woken, the write-drop panic is
    /// resumed once, both readers then complete, and after they release the lock
    /// is writable again with zero readers.
    #[test]
    fn write_release_reader_fanout_panic_still_wakes_peers_then_resumes() {
        struct PanicWaker;
        impl std::task::Wake for PanicWaker {
            fn wake(self: StdArc<Self>) {
                panic!("hostile reader waker panics on wake");
            }
            fn wake_by_ref(self: &StdArc<Self>) {
                panic!("hostile reader waker panics on wake");
            }
        }
        struct CountWaker(StdArc<std::sync::atomic::AtomicUsize>);
        impl std::task::Wake for CountWaker {
            fn wake(self: StdArc<Self>) {
                self.0.fetch_add(1, AtomicOrdering::SeqCst);
            }
            fn wake_by_ref(self: &StdArc<Self>) {
                self.0.fetch_add(1, AtomicOrdering::SeqCst);
            }
        }

        init_test("write_release_reader_fanout_panic_still_wakes_peers_then_resumes");
        // Unknown lock name -> no rank -> no lock-order interference.
        let lock = RwLock::with_name("reader_fanout", 0u32);
        let cx = test_cx();

        // An active writer blocks readers.
        let writer = lock.try_write().expect("writer acquires");

        // Two readers park behind the writer; the first carries a panicking Waker.
        let mut r1 = lock.read(&cx);
        let mut r2 = lock.read(&cx);
        let panic_waker = Waker::from(StdArc::new(PanicWaker));
        let counter = StdArc::new(std::sync::atomic::AtomicUsize::new(0));
        let count_waker = Waker::from(StdArc::new(CountWaker(StdArc::clone(&counter))));
        assert!(
            poll_with_waker(&mut r1, &panic_waker).is_pending(),
            "r1 parks"
        );
        assert!(
            poll_with_waker(&mut r2, &count_waker).is_pending(),
            "r2 parks"
        );

        // Dropping the writer pregrants both readers and wakes them; r1's Waker
        // panics, but r2 must still be woken, then the panic is resumed out of
        // the guard drop.
        let dropped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(writer)));
        assert!(
            dropped.is_err(),
            "write-release reader fanout resumes the panic"
        );
        assert!(
            counter.load(AtomicOrdering::SeqCst) >= 1,
            "later reader still woken despite earlier panic"
        );

        // Both readers were pregranted, so they complete on the next poll without
        // re-incrementing the reader count.
        let g1 = poll_once(&mut r1)
            .expect("r1 ready")
            .expect("r1 read guard");
        let g2 = poll_once(&mut r2)
            .expect("r2 ready")
            .expect("r2 read guard");
        assert_eq!(lock.debug_state().readers, 2, "both readers active");
        drop(g1);
        drop(g2);

        // With both readers released, zero readers remain and a writer acquires.
        assert_eq!(lock.debug_state().readers, 0, "no readers after release");
        assert!(lock.try_write().is_ok(), "lock writable after fanout");
        crate::test_complete!("write_release_reader_fanout_panic_still_wakes_peers_then_resumes");
    }

    #[test]
    fn borrowed_read_repoll_and_cancel_retire_wakers_after_unlock() {
        let lock = StdArc::new(RwLock::new(()));
        let cx = test_cx();
        let holder = lock.try_write().expect("writer blocks readers");
        let mut future = lock.read(&cx);
        let (first_waker, first_dropped, first_unlocked) = state_lock_drop_probe(&lock);

        assert!(poll_with_waker(&mut future, &first_waker).is_pending());
        drop(first_waker);
        assert!(!first_dropped.load(AtomicOrdering::SeqCst));
        assert!(poll_with_waker(&mut future, Waker::noop()).is_pending());
        assert_probe_retired_after_unlock(
            &first_dropped,
            &first_unlocked,
            "borrowed read replacement",
        );

        let (cancel_waker, cancel_dropped, cancel_unlocked) = state_lock_drop_probe(&lock);
        assert!(poll_with_waker(&mut future, &cancel_waker).is_pending());
        drop(cancel_waker);
        cx.set_cancel_requested(true);
        assert!(matches!(
            poll_with_waker(&mut future, Waker::noop()),
            Poll::Ready(Err(RwLockError::Cancelled))
        ));
        assert_probe_retired_after_unlock(
            &cancel_dropped,
            &cancel_unlocked,
            "borrowed read cancellation",
        );
        assert!(lock.debug_state().reader_waiters.is_empty());
        drop(holder);
    }

    #[test]
    fn borrowed_write_repoll_and_cancel_retire_wakers_after_unlock() {
        let lock = StdArc::new(RwLock::new(()));
        let cx = test_cx();
        let holder = lock.try_read().expect("reader blocks writers");
        let mut future = lock.write(&cx);
        let (first_waker, first_dropped, first_unlocked) = state_lock_drop_probe(&lock);

        assert!(poll_with_waker(&mut future, &first_waker).is_pending());
        drop(first_waker);
        assert!(!first_dropped.load(AtomicOrdering::SeqCst));
        assert!(poll_with_waker(&mut future, Waker::noop()).is_pending());
        assert_probe_retired_after_unlock(
            &first_dropped,
            &first_unlocked,
            "borrowed write replacement",
        );

        let (cancel_waker, cancel_dropped, cancel_unlocked) = state_lock_drop_probe(&lock);
        assert!(poll_with_waker(&mut future, &cancel_waker).is_pending());
        drop(cancel_waker);
        cx.set_cancel_requested(true);
        assert!(matches!(
            poll_with_waker(&mut future, Waker::noop()),
            Poll::Ready(Err(RwLockError::Cancelled))
        ));
        assert_probe_retired_after_unlock(
            &cancel_dropped,
            &cancel_unlocked,
            "borrowed write cancellation",
        );
        let state = lock.debug_state();
        assert!(state.writer_queue.is_empty());
        assert_eq!(state.writer_waiters, 0);
        drop(holder);
    }

    #[test]
    fn owned_read_repoll_and_cancel_retire_wakers_after_unlock() {
        let lock = StdArc::new(RwLock::new(()));
        let cx = test_cx();
        let holder = lock.try_write().expect("writer blocks readers");
        let mut future = OwnedRwLockReadGuard::read(StdArc::clone(&lock), &cx);
        let (first_waker, first_dropped, first_unlocked) = state_lock_drop_probe(&lock);

        assert!(poll_with_waker(&mut future, &first_waker).is_pending());
        drop(first_waker);
        assert!(!first_dropped.load(AtomicOrdering::SeqCst));
        assert!(poll_with_waker(&mut future, Waker::noop()).is_pending());
        assert_probe_retired_after_unlock(
            &first_dropped,
            &first_unlocked,
            "owned read replacement",
        );

        let (cancel_waker, cancel_dropped, cancel_unlocked) = state_lock_drop_probe(&lock);
        assert!(poll_with_waker(&mut future, &cancel_waker).is_pending());
        drop(cancel_waker);
        cx.set_cancel_requested(true);
        assert!(matches!(
            poll_with_waker(&mut future, Waker::noop()),
            Poll::Ready(Err(RwLockError::Cancelled))
        ));
        assert_probe_retired_after_unlock(
            &cancel_dropped,
            &cancel_unlocked,
            "owned read cancellation",
        );
        assert!(lock.debug_state().reader_waiters.is_empty());
        drop(holder);
    }

    #[test]
    fn owned_write_repoll_and_cancel_retire_wakers_after_unlock() {
        let lock = StdArc::new(RwLock::new(()));
        let cx = test_cx();
        let holder = lock.try_read().expect("reader blocks writers");
        let mut future = OwnedRwLockWriteGuard::write(StdArc::clone(&lock), &cx);
        let (first_waker, first_dropped, first_unlocked) = state_lock_drop_probe(&lock);

        assert!(poll_with_waker(&mut future, &first_waker).is_pending());
        drop(first_waker);
        assert!(!first_dropped.load(AtomicOrdering::SeqCst));
        assert!(poll_with_waker(&mut future, Waker::noop()).is_pending());
        assert_probe_retired_after_unlock(
            &first_dropped,
            &first_unlocked,
            "owned write replacement",
        );

        let (cancel_waker, cancel_dropped, cancel_unlocked) = state_lock_drop_probe(&lock);
        assert!(poll_with_waker(&mut future, &cancel_waker).is_pending());
        drop(cancel_waker);
        cx.set_cancel_requested(true);
        assert!(matches!(
            poll_with_waker(&mut future, Waker::noop()),
            Poll::Ready(Err(RwLockError::Cancelled))
        ));
        assert_probe_retired_after_unlock(
            &cancel_dropped,
            &cancel_unlocked,
            "owned write cancellation",
        );
        let state = lock.debug_state();
        assert!(state.writer_queue.is_empty());
        assert_eq!(state.writer_waiters, 0);
        drop(holder);
    }

    #[test]
    fn future_drop_matrix_retires_wakers_after_unlock() {
        {
            let lock = StdArc::new(RwLock::new(()));
            let cx = test_cx();
            let holder = lock.try_write().expect("writer blocks borrowed read");
            let mut future = lock.read(&cx);
            let (waker, dropped, unlocked) = state_lock_drop_probe(&lock);
            assert!(poll_with_waker(&mut future, &waker).is_pending());
            drop(waker);
            drop(future);
            assert_probe_retired_after_unlock(&dropped, &unlocked, "borrowed read drop");
            assert!(lock.debug_state().reader_waiters.is_empty());
            drop(holder);
        }

        {
            let lock = StdArc::new(RwLock::new(()));
            let cx = test_cx();
            let holder = lock.try_read().expect("reader blocks borrowed write");
            let mut future = lock.write(&cx);
            let (waker, dropped, unlocked) = state_lock_drop_probe(&lock);
            assert!(poll_with_waker(&mut future, &waker).is_pending());
            drop(waker);
            drop(future);
            assert_probe_retired_after_unlock(&dropped, &unlocked, "borrowed write drop");
            let state = lock.debug_state();
            assert!(state.writer_queue.is_empty());
            assert_eq!(state.writer_waiters, 0);
            drop(holder);
        }

        {
            let lock = StdArc::new(RwLock::new(()));
            let cx = test_cx();
            let holder = lock.try_write().expect("writer blocks owned read");
            let mut future = OwnedRwLockReadGuard::read(StdArc::clone(&lock), &cx);
            let (waker, dropped, unlocked) = state_lock_drop_probe(&lock);
            assert!(poll_with_waker(&mut future, &waker).is_pending());
            drop(waker);
            drop(future);
            assert_probe_retired_after_unlock(&dropped, &unlocked, "owned read drop");
            assert!(lock.debug_state().reader_waiters.is_empty());
            drop(holder);
        }

        {
            let lock = StdArc::new(RwLock::new(()));
            let cx = test_cx();
            let holder = lock.try_read().expect("reader blocks owned write");
            let mut future = OwnedRwLockWriteGuard::write(StdArc::clone(&lock), &cx);
            let (waker, dropped, unlocked) = state_lock_drop_probe(&lock);
            assert!(poll_with_waker(&mut future, &waker).is_pending());
            drop(waker);
            drop(future);
            assert_probe_retired_after_unlock(&dropped, &unlocked, "owned write drop");
            let state = lock.debug_state();
            assert!(state.writer_queue.is_empty());
            assert_eq!(state.writer_waiters, 0);
            drop(holder);
        }
    }

    #[test]
    fn poisoned_release_defers_reader_and_writer_raw_wakers() {
        let lock = StdArc::new(RwLock::new(()));
        let read_cx = test_cx_with_slot(31);
        let write_cx = test_cx_with_slot(32);
        let holder = lock.try_write().expect("writer holds rwlock");
        let mut read_future = lock.read(&read_cx);
        let mut write_future = lock.write(&write_cx);
        let (read_waker, read_dropped, read_unlocked) = state_lock_drop_probe(&lock);
        let (write_waker, write_dropped, write_unlocked) = state_lock_drop_probe(&lock);

        assert!(poll_with_waker(&mut read_future, &read_waker).is_pending());
        assert!(poll_with_waker(&mut write_future, &write_waker).is_pending());
        drop(read_waker);
        drop(write_waker);

        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _holder = holder;
            panic!("poison rwlock while both waiter queues are populated");
        }));
        assert!(poisoned.is_err());
        assert!(lock.is_poisoned());
        assert!(!read_dropped.load(AtomicOrdering::SeqCst));
        assert!(!write_dropped.load(AtomicOrdering::SeqCst));

        assert!(matches!(
            poll_with_waker(&mut read_future, Waker::noop()),
            Poll::Ready(Err(RwLockError::Poisoned))
        ));
        assert!(matches!(
            poll_with_waker(&mut write_future, Waker::noop()),
            Poll::Ready(Err(RwLockError::Poisoned))
        ));
        assert_probe_retired_after_unlock(&read_dropped, &read_unlocked, "poisoned reader queue");
        assert_probe_retired_after_unlock(&write_dropped, &write_unlocked, "poisoned writer queue");
        let state = lock.debug_state();
        assert!(state.reader_waiters.is_empty());
        assert!(state.writer_queue.is_empty());
        assert_eq!(state.writer_waiters, 0);
    }

    #[test]
    fn multiple_readers_allowed() {
        init_test("multiple_readers_allowed");
        let cx = test_cx();
        let lock = RwLock::new(42_u32);

        let guard1 = read_blocking(&lock, &cx);
        let guard2 = read_blocking(&lock, &cx);

        crate::assert_with_log!(*guard1 == 42, "guard1 value", 42u32, *guard1);
        crate::assert_with_log!(*guard2 == 42, "guard2 value", 42u32, *guard2);
        crate::test_complete!("multiple_readers_allowed");
    }

    #[test]
    fn read_accepts_detached_no_cap_context() {
        init_test("read_accepts_detached_no_cap_context");
        let cx = Cx::<cap::None>::detached_cancel_context();
        let lock = RwLock::new(42_u32);

        let guard = poll_until_ready(lock.read(&cx)).expect("read should accept cap::None Cx");

        crate::assert_with_log!(*guard == 42, "read guard value", 42u32, *guard);
        crate::test_complete!("read_accepts_detached_no_cap_context");
    }

    #[test]
    fn write_accepts_detached_no_cap_context() {
        init_test("write_accepts_detached_no_cap_context");
        let cx = Cx::<cap::None>::detached_cancel_context();
        let lock = RwLock::new(5_u32);

        let mut guard =
            poll_until_ready(lock.write(&cx)).expect("write should accept cap::None Cx");
        *guard = 7;

        crate::assert_with_log!(*guard == 7, "write guard value", 7u32, *guard);
        crate::test_complete!("write_accepts_detached_no_cap_context");
    }

    #[test]
    fn owned_read_accepts_detached_no_cap_context() {
        init_test("owned_read_accepts_detached_no_cap_context");
        let cx = Cx::<cap::None>::detached_cancel_context();
        let lock = StdArc::new(RwLock::new(42_u32));

        let guard = poll_until_ready(OwnedRwLockReadGuard::read(StdArc::clone(&lock), &cx))
            .expect("owned read should accept cap::None Cx");

        crate::assert_with_log!(*guard == 42, "owned read guard value", 42u32, *guard);
        crate::test_complete!("owned_read_accepts_detached_no_cap_context");
    }

    #[test]
    fn owned_write_accepts_detached_no_cap_context() {
        init_test("owned_write_accepts_detached_no_cap_context");
        let cx = Cx::<cap::None>::detached_cancel_context();
        let lock = StdArc::new(RwLock::new(5_u32));

        let mut guard = poll_until_ready(OwnedRwLockWriteGuard::write(StdArc::clone(&lock), &cx))
            .expect("owned write should accept cap::None Cx");
        *guard = 7;

        crate::assert_with_log!(*guard == 7, "owned write guard value", 7u32, *guard);
        crate::test_complete!("owned_write_accepts_detached_no_cap_context");
    }

    #[test]
    fn write_excludes_readers_and_writers() {
        init_test("write_excludes_readers_and_writers");
        let cx = test_cx();
        let lock = RwLock::new(5_u32);

        let mut write = write_blocking(&lock, &cx);
        *write = 7;

        let read_locked = matches!(lock.try_read(), Err(TryReadError::Locked));
        crate::assert_with_log!(read_locked, "read locked", true, read_locked);
        let write_locked = matches!(lock.try_write(), Err(TryWriteError::Locked));
        crate::assert_with_log!(write_locked, "write locked", true, write_locked);

        drop(write);

        let read = read_blocking(&lock, &cx);
        crate::assert_with_log!(*read == 7, "read after write", 7u32, *read);
        crate::test_complete!("write_excludes_readers_and_writers");
    }

    #[test]
    fn writer_waiting_blocks_new_readers() {
        init_test("writer_waiting_blocks_new_readers");
        let cx = test_cx();
        let lock = StdArc::new(RwLock::new(1_u32));
        let read_guard = read_blocking(&lock, &cx);

        let writer_started = StdArc::new(AtomicBool::new(false));
        let writer_lock = StdArc::clone(&lock);
        let writer_flag = StdArc::clone(&writer_started);

        let handle = thread::spawn(move || {
            let cx = test_cx();
            writer_flag.store(true, AtomicOrdering::Release);
            let _guard = write_blocking(&writer_lock, &cx);
        });

        // Wait until writer is attempting to acquire.
        while !writer_started.load(AtomicOrdering::Acquire) {
            std::thread::yield_now();
        }

        // New readers should be blocked while a writer is waiting.
        // We loop because setting the flag happens before the writer actually
        // registers itself in the lock state.
        let mut success = false;
        for _ in 0..100 {
            if matches!(lock.try_read(), Err(TryReadError::Locked)) {
                success = true;
                break;
            }
            std::thread::yield_now();
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        crate::assert_with_log!(success, "writer blocked readers", true, success);

        drop(read_guard);
        let _ = handle.join();
        crate::test_complete!("writer_waiting_blocks_new_readers");
    }

    #[test]
    fn try_write_does_not_bypass_waiting_writer_turn() {
        init_test("try_write_does_not_bypass_waiting_writer_turn");
        let cx = test_cx();
        let lock = RwLock::new(1_u32);

        // Hold a read lock so the writer must queue first.
        let read_guard = read_blocking(&lock, &cx);
        let mut queued_writer = lock.write(&cx);
        let pending = poll_once(&mut queued_writer).is_none();
        crate::assert_with_log!(pending, "writer queued while reader held", true, pending);

        // Releasing the reader wakes the queued writer, but before that writer
        // is polled again, try_write() must not barge ahead.
        drop(read_guard);

        let try_write_locked = matches!(lock.try_write(), Err(TryWriteError::Locked));
        crate::assert_with_log!(
            try_write_locked,
            "try_write must not bypass queued writer",
            true,
            try_write_locked
        );

        let queued_guard = poll_until_ready(queued_writer).expect("queued writer should acquire");
        drop(queued_guard);
        crate::test_complete!("try_write_does_not_bypass_waiting_writer_turn");
    }

    #[test]
    fn cancel_during_read_wait() {
        init_test("cancel_during_read_wait");
        let cx = test_cx();
        let lock = RwLock::new(0_u32);

        let _write = write_blocking(&lock, &cx);
        let mut fut = lock.read(&cx);
        let pending = poll_once(&mut fut).is_none();
        crate::assert_with_log!(pending, "read waits while writer held", true, pending);

        cx.set_cancel_requested(true);

        let cancelled = matches!(poll_once(&mut fut), Some(Err(RwLockError::Cancelled)));
        crate::assert_with_log!(cancelled, "read cancelled", true, cancelled);
        drop(fut);

        let state = lock.debug_state();
        let waiters = state.reader_waiters.len();
        crate::assert_with_log!(waiters == 0, "reader waiters cleaned", 0usize, waiters);
        crate::test_complete!("cancel_during_read_wait");
    }

    #[test]
    fn cancel_queued_write_waiter_cleans_state_before_drop() {
        init_test("cancel_queued_write_waiter_cleans_state_before_drop");
        let cx = test_cx();
        let cancel_cx = test_cx_with_slot(10);
        let lock = RwLock::new(42_u32);

        let read_guard = read_blocking(&lock, &cx);

        let mut write_fut = lock.write(&cancel_cx);
        let write_pending = poll_once(&mut write_fut).is_none();
        crate::assert_with_log!(write_pending, "write waiter pending", true, write_pending);

        let mut read_fut = lock.read(&cx);
        let read_pending = poll_once(&mut read_fut).is_none();
        crate::assert_with_log!(
            read_pending,
            "reader blocked by queued writer",
            true,
            read_pending
        );

        cancel_cx.set_cancel_requested(true);
        let cancelled = matches!(poll_once(&mut write_fut), Some(Err(RwLockError::Cancelled)));
        crate::assert_with_log!(cancelled, "write waiter cancelled", true, cancelled);

        let state = lock.debug_state();
        crate::assert_with_log!(
            state.writer_waiters == 0 && state.writer_queue.is_empty(),
            "write waiter removed without drop",
            true,
            state.writer_waiters == 0 && state.writer_queue.is_empty()
        );

        let read_result = poll_once(&mut read_fut);
        let reader_acquired = matches!(read_result, Some(Ok(_)));
        crate::assert_with_log!(
            reader_acquired,
            "reader unblocked before cancelled writer future is dropped",
            true,
            reader_acquired
        );

        if let Some(Ok(guard)) = read_result {
            drop(guard);
        }
        drop(read_guard);
        drop(write_fut);
        crate::test_complete!("cancel_queued_write_waiter_cleans_state_before_drop");
    }

    #[test]
    fn test_rwlock_try_read_success() {
        init_test("test_rwlock_try_read_success");
        let lock = RwLock::new(42_u32);

        // Should succeed when unlocked
        let guard = lock.try_read().expect("try_read should succeed");
        crate::assert_with_log!(*guard == 42, "read value", 42u32, *guard);
        crate::test_complete!("test_rwlock_try_read_success");
    }

    #[test]
    fn test_rwlock_try_write_success() {
        init_test("test_rwlock_try_write_success");
        let lock = RwLock::new(42_u32);

        // Should succeed when unlocked
        let mut guard = lock.try_write().expect("try_write should succeed");
        *guard = 100;
        crate::assert_with_log!(*guard == 100, "write value", 100u32, *guard);
        crate::test_complete!("test_rwlock_try_write_success");
    }

    #[test]
    fn test_rwlock_cancel_during_write_wait() {
        init_test("test_rwlock_cancel_during_write_wait");
        let cx = test_cx();
        let lock = RwLock::new(0_u32);

        // Hold a read lock
        let _read = read_blocking(&lock, &cx);

        let mut fut = lock.write(&cx);
        let pending = poll_once(&mut fut).is_none();
        crate::assert_with_log!(pending, "write waits while reader held", true, pending);

        // Request cancellation
        cx.set_cancel_requested(true);

        // Write should be cancelled
        let cancelled = matches!(poll_once(&mut fut), Some(Err(RwLockError::Cancelled)));
        crate::assert_with_log!(cancelled, "write cancelled", true, cancelled);
        drop(fut);

        let state = lock.debug_state();
        let waiters = state.writer_queue.len();
        let writer_count = state.writer_waiters;
        crate::assert_with_log!(
            waiters == 0 && writer_count == 0,
            "writer waiters cleaned",
            true,
            waiters == 0 && writer_count == 0
        );
        crate::test_complete!("test_rwlock_cancel_during_write_wait");
    }

    #[test]
    fn cancel_pregranted_read_waiter_wakes_writer_before_drop() {
        init_test("cancel_pregranted_read_waiter_wakes_writer_before_drop");
        let cx = test_cx();
        let cancel_cx = test_cx_with_slot(11);
        let lock = RwLock::new(0_u32);

        let active_writer = write_blocking(&lock, &cx);

        let mut read_fut = lock.read(&cancel_cx);
        let read_pending = poll_once(&mut read_fut).is_none();
        crate::assert_with_log!(read_pending, "reader queued", true, read_pending);

        let mut writer_fut = lock.write(&cx);
        let writer_pending = poll_once(&mut writer_fut).is_none();
        crate::assert_with_log!(writer_pending, "writer queued", true, writer_pending);

        drop(active_writer);

        cancel_cx.set_cancel_requested(true);
        let cancelled = matches!(poll_once(&mut read_fut), Some(Err(RwLockError::Cancelled)));
        crate::assert_with_log!(cancelled, "pre-granted reader cancelled", true, cancelled);

        let state = lock.debug_state();
        crate::assert_with_log!(
            state.readers == 0 && state.reader_waiters.is_empty() && state.writer_active,
            "pre-granted reader cleanup forwarded turn to writer",
            true,
            state.readers == 0 && state.reader_waiters.is_empty() && state.writer_active
        );

        let writer_result = poll_once(&mut writer_fut);
        let writer_acquired = matches!(writer_result, Some(Ok(_)));
        crate::assert_with_log!(
            writer_acquired,
            "writer acquires before cancelled reader future is dropped",
            true,
            writer_acquired
        );

        if let Some(Ok(guard)) = writer_result {
            drop(guard);
        }
        drop(read_fut);
        crate::test_complete!("cancel_pregranted_read_waiter_wakes_writer_before_drop");
    }

    #[test]
    fn read_future_second_poll_fails_closed() {
        init_test("read_future_second_poll_fails_closed");
        let cx = test_cx();
        let lock = RwLock::new(42_u32);

        let mut fut = lock.read(&cx);
        let first = poll_once(&mut fut);
        let Some(Ok(guard)) = first else {
            panic!("expected ready read guard");
        };

        let second = poll_once(&mut fut);
        let done = matches!(second, Some(Err(RwLockError::PolledAfterCompletion)));
        crate::assert_with_log!(done, "read future second poll fails closed", true, done);

        drop(guard);
        crate::test_complete!("read_future_second_poll_fails_closed");
    }

    #[test]
    fn write_future_second_poll_fails_closed() {
        init_test("write_future_second_poll_fails_closed");
        let cx = test_cx();
        let lock = RwLock::new(42_u32);

        let mut fut = lock.write(&cx);
        let first = poll_once(&mut fut);
        let Some(Ok(mut guard)) = first else {
            panic!("expected ready write guard");
        };
        *guard = 55;

        let second = poll_once(&mut fut);
        let done = matches!(second, Some(Err(RwLockError::PolledAfterCompletion)));
        crate::assert_with_log!(done, "write future second poll fails closed", true, done);

        drop(guard);
        crate::test_complete!("write_future_second_poll_fails_closed");
    }

    #[test]
    fn owned_read_future_second_poll_fails_closed() {
        init_test("owned_read_future_second_poll_fails_closed");
        let cx = test_cx();
        let lock = StdArc::new(RwLock::new(42_u32));

        let mut fut = OwnedRwLockReadGuard::read(StdArc::clone(&lock), &cx);
        let first = poll_once(&mut fut);
        let Some(Ok(guard)) = first else {
            panic!("expected ready owned read guard");
        };

        let second = poll_once(&mut fut);
        let done = matches!(second, Some(Err(RwLockError::PolledAfterCompletion)));
        crate::assert_with_log!(
            done,
            "owned read future second poll fails closed",
            true,
            done
        );

        drop(guard);
        crate::test_complete!("owned_read_future_second_poll_fails_closed");
    }

    #[test]
    fn owned_write_future_second_poll_fails_closed() {
        init_test("owned_write_future_second_poll_fails_closed");
        let cx = test_cx();
        let lock = StdArc::new(RwLock::new(42_u32));

        let mut fut = OwnedRwLockWriteGuard::write(StdArc::clone(&lock), &cx);
        let first = poll_once(&mut fut);
        let Some(Ok(mut guard)) = first else {
            panic!("expected ready owned write guard");
        };
        *guard = 77;

        let second = poll_once(&mut fut);
        let done = matches!(second, Some(Err(RwLockError::PolledAfterCompletion)));
        crate::assert_with_log!(
            done,
            "owned write future second poll fails closed",
            true,
            done
        );

        drop(guard);
        crate::test_complete!("owned_write_future_second_poll_fails_closed");
    }

    #[test]
    fn test_rwlock_get_mut() {
        init_test("test_rwlock_get_mut");
        let mut lock = RwLock::new(42_u32);

        // get_mut provides direct access when we have &mut
        *lock.get_mut().expect("rwlock should not be poisoned") = 100;
        let value = *lock.get_mut().expect("rwlock should not be poisoned");
        crate::assert_with_log!(value == 100, "get_mut works", 100u32, value);
        crate::test_complete!("test_rwlock_get_mut");
    }

    #[test]
    fn test_rwlock_into_inner() {
        init_test("test_rwlock_into_inner");
        let lock = RwLock::new(42_u32);

        let value = lock.into_inner().expect("rwlock should not be poisoned");
        crate::assert_with_log!(value == 42, "into_inner works", 42u32, value);
        crate::test_complete!("test_rwlock_into_inner");
    }

    #[test]
    fn test_rwlock_read_released_on_drop() {
        init_test("test_rwlock_read_released_on_drop");
        let cx = test_cx();
        let lock = RwLock::new(42_u32);

        // Acquire and drop read
        {
            let _guard = read_blocking(&lock, &cx);
        }

        // Write should succeed now
        let can_write = lock.try_write().is_ok();
        crate::assert_with_log!(can_write, "can write after read drop", true, can_write);
        crate::test_complete!("test_rwlock_read_released_on_drop");
    }

    #[test]
    fn test_rwlock_write_released_on_drop() {
        init_test("test_rwlock_write_released_on_drop");
        let cx = test_cx();
        let lock = RwLock::new(42_u32);

        // Acquire and drop write
        {
            let _guard = write_blocking(&lock, &cx);
        }

        // Read should succeed now
        let can_read = lock.try_read().is_ok();
        crate::assert_with_log!(can_read, "can read after write drop", true, can_read);
        crate::test_complete!("test_rwlock_write_released_on_drop");
    }

    #[test]
    fn test_writer_fifo_ordering() {
        // Verifies that queued writers acquire in FIFO order.
        init_test("test_writer_fifo_ordering");
        let cx = test_cx();
        let lock = StdArc::new(RwLock::new(Vec::<u32>::new()));
        let order = StdArc::new(parking_lot::Mutex::new(Vec::new()));

        // Hold a read lock so writers must queue.
        let read_guard = read_blocking(&lock, &cx);

        let mut handles = Vec::new();
        for id in 1..=3_u32 {
            let lock_c = StdArc::clone(&lock);
            let order_c = StdArc::clone(&order);
            handles.push(thread::spawn(move || {
                let cx = test_cx();
                let mut guard = write_blocking(&lock_c, &cx);
                order_c.lock().push(id);
                guard.push(id);
            }));
            // Small delay to ensure writers queue in id order.
            thread::sleep(std::time::Duration::from_millis(10));
        }

        // Release reader — writers should now acquire one by one in queue order.
        drop(read_guard);
        for h in handles {
            let _ = h.join();
        }

        let final_order = order.lock().clone();
        let data = lock.try_read().unwrap();
        // Both the acquisition order and data should match FIFO.
        crate::assert_with_log!(
            final_order == *data,
            "writer FIFO order matches data",
            true,
            final_order == *data
        );
        crate::test_complete!("test_writer_fifo_ordering");
    }

    #[test]
    fn release_writer_prefers_older_writer_over_reader() {
        init_test("release_writer_prefers_older_writer_over_reader");
        let cx = test_cx();
        let lock = RwLock::new(0_u32);

        // Hold active writer so both waiters queue.
        let active_writer = write_blocking(&lock, &cx);

        // Queue writer first (older), then reader.
        let mut writer_fut = lock.write(&cx);
        let writer_pending = poll_once(&mut writer_fut).is_none();
        crate::assert_with_log!(
            writer_pending,
            "queued writer is pending",
            true,
            writer_pending
        );

        let mut reader_fut = lock.read(&cx);
        let reader_pending = poll_once(&mut reader_fut).is_none();
        crate::assert_with_log!(
            reader_pending,
            "queued reader is pending",
            true,
            reader_pending
        );

        // Releasing active writer should wake the older queued writer first.
        drop(active_writer);

        let writer_result = poll_once(&mut writer_fut);
        let writer_acquired = matches!(writer_result, Some(Ok(_)));
        crate::assert_with_log!(
            writer_acquired,
            "older writer acquires before reader",
            true,
            writer_acquired
        );

        let reader_still_pending = poll_once(&mut reader_fut).is_none();
        crate::assert_with_log!(
            reader_still_pending,
            "reader remains pending while writer holds lock",
            true,
            reader_still_pending
        );

        if let Some(Ok(writer_guard)) = writer_result {
            drop(writer_guard);
        }

        let reader_result = poll_once(&mut reader_fut);
        let reader_acquired = matches!(reader_result, Some(Ok(_)));
        crate::assert_with_log!(
            reader_acquired,
            "reader acquires after writer releases",
            true,
            reader_acquired
        );
        crate::test_complete!("release_writer_prefers_older_writer_over_reader");
    }

    #[test]
    fn release_writer_prefers_older_reader_over_writer() {
        init_test("release_writer_prefers_older_reader_over_writer");
        let cx = test_cx();
        let lock = RwLock::new(0_u32);

        // Hold active writer so both waiters queue.
        let active_writer = write_blocking(&lock, &cx);

        // Queue reader first (older), then writer.
        let mut reader_fut = lock.read(&cx);
        let reader_pending = poll_once(&mut reader_fut).is_none();
        crate::assert_with_log!(
            reader_pending,
            "queued reader is pending",
            true,
            reader_pending
        );

        let mut writer_fut = lock.write(&cx);
        let writer_pending = poll_once(&mut writer_fut).is_none();
        crate::assert_with_log!(
            writer_pending,
            "queued writer is pending",
            true,
            writer_pending
        );

        // Releasing active writer should wake the older queued reader first.
        drop(active_writer);

        let reader_result = poll_once(&mut reader_fut);
        let reader_acquired = matches!(reader_result, Some(Ok(_)));
        crate::assert_with_log!(
            reader_acquired,
            "older reader acquires before writer",
            true,
            reader_acquired
        );

        let writer_still_pending = poll_once(&mut writer_fut).is_none();
        crate::assert_with_log!(
            writer_still_pending,
            "writer remains pending while reader holds lock",
            true,
            writer_still_pending
        );

        if let Some(Ok(reader_guard)) = reader_result {
            drop(reader_guard);
        }

        let writer_result = poll_once(&mut writer_fut);
        let writer_acquired = matches!(writer_result, Some(Ok(_)));
        crate::assert_with_log!(
            writer_acquired,
            "writer acquires after reader releases",
            true,
            writer_acquired
        );
        crate::test_complete!("release_writer_prefers_older_reader_over_writer");
    }

    #[test]
    fn release_writer_does_not_wake_readers_younger_than_first_writer() {
        init_test("release_writer_does_not_wake_readers_younger_than_first_writer");
        let cx = test_cx();
        let lock = RwLock::new(0_u32);

        // Hold active writer so all later waiters queue.
        let active_writer = write_blocking(&lock, &cx);

        // Queue an older reader, then a writer, then a younger reader.
        let mut older_reader_fut = lock.read(&cx);
        let older_reader_pending = poll_once(&mut older_reader_fut).is_none();
        crate::assert_with_log!(
            older_reader_pending,
            "older reader is pending",
            true,
            older_reader_pending
        );

        let mut writer_fut = lock.write(&cx);
        let writer_pending = poll_once(&mut writer_fut).is_none();
        crate::assert_with_log!(writer_pending, "writer is pending", true, writer_pending);

        let mut younger_reader_fut = lock.read(&cx);
        let younger_reader_pending = poll_once(&mut younger_reader_fut).is_none();
        crate::assert_with_log!(
            younger_reader_pending,
            "younger reader is pending",
            true,
            younger_reader_pending
        );

        // The older reader should be granted first, but the younger reader
        // must remain queued behind the writer.
        drop(active_writer);

        let older_reader_result = poll_once(&mut older_reader_fut);
        let older_reader_acquired = matches!(older_reader_result, Some(Ok(_)));
        crate::assert_with_log!(
            older_reader_acquired,
            "older reader acquires first",
            true,
            older_reader_acquired
        );

        let younger_reader_still_pending = poll_once(&mut younger_reader_fut).is_none();
        crate::assert_with_log!(
            younger_reader_still_pending,
            "younger reader stays queued behind writer",
            true,
            younger_reader_still_pending
        );

        let writer_still_pending = poll_once(&mut writer_fut).is_none();
        crate::assert_with_log!(
            writer_still_pending,
            "writer is still queued while older reader holds lock",
            true,
            writer_still_pending
        );

        if let Some(Ok(older_reader_guard)) = older_reader_result {
            drop(older_reader_guard);
        }

        let writer_result = poll_once(&mut writer_fut);
        let writer_acquired = matches!(writer_result, Some(Ok(_)));
        crate::assert_with_log!(
            writer_acquired,
            "writer acquires before younger reader",
            true,
            writer_acquired
        );

        let younger_reader_still_pending = poll_once(&mut younger_reader_fut).is_none();
        crate::assert_with_log!(
            younger_reader_still_pending,
            "younger reader remains queued while writer holds lock",
            true,
            younger_reader_still_pending
        );

        if let Some(Ok(writer_guard)) = writer_result {
            drop(writer_guard);
        }

        let younger_reader_result = poll_once(&mut younger_reader_fut);
        let younger_reader_acquired = matches!(younger_reader_result, Some(Ok(_)));
        crate::assert_with_log!(
            younger_reader_acquired,
            "younger reader acquires after writer releases",
            true,
            younger_reader_acquired
        );
        crate::test_complete!("release_writer_does_not_wake_readers_younger_than_first_writer");
    }

    #[test]
    fn downgrade_preserves_writer_preference_for_younger_readers() {
        init_test("downgrade_preserves_writer_preference_for_younger_readers");
        let cx = test_cx();
        let lock = RwLock::new(0_u32);

        let active_writer = write_blocking(&lock, &cx);

        let mut writer_fut = lock.write(&cx);
        let writer_pending = poll_once(&mut writer_fut).is_none();
        crate::assert_with_log!(
            writer_pending,
            "writer queued behind active writer",
            true,
            writer_pending
        );

        let mut younger_reader_fut = lock.read(&cx);
        let reader_pending = poll_once(&mut younger_reader_fut).is_none();
        crate::assert_with_log!(
            reader_pending,
            "younger reader queued behind writer",
            true,
            reader_pending
        );

        let downgraded_reader = active_writer.downgrade();

        let state = lock.debug_state();
        crate::assert_with_log!(
            state.readers == 1
                && state.writer_waiters == 1
                && state.writer_queue.len() == 1
                && state.reader_waiters.len() == 1,
            "downgrade keeps younger reader queued behind writer",
            true,
            state.readers == 1
                && state.writer_waiters == 1
                && state.writer_queue.len() == 1
                && state.reader_waiters.len() == 1
        );

        let younger_reader_still_pending = poll_once(&mut younger_reader_fut).is_none();
        crate::assert_with_log!(
            younger_reader_still_pending,
            "younger reader stays pending after downgrade",
            true,
            younger_reader_still_pending
        );

        let writer_still_pending = poll_once(&mut writer_fut).is_none();
        crate::assert_with_log!(
            writer_still_pending,
            "writer waits while downgraded reader is held",
            true,
            writer_still_pending
        );

        drop(downgraded_reader);

        let writer_guard = match poll_once(&mut writer_fut) {
            Some(Ok(guard)) => guard,
            other => panic!("writer should acquire before younger reader: {other:?}"),
        };
        let younger_reader_still_pending = poll_once(&mut younger_reader_fut).is_none();
        crate::assert_with_log!(
            younger_reader_still_pending,
            "younger reader remains queued while writer holds lock",
            true,
            younger_reader_still_pending
        );

        drop(writer_guard);

        let younger_reader_guard = match poll_once(&mut younger_reader_fut) {
            Some(Ok(guard)) => guard,
            other => panic!("younger reader should acquire after writer releases: {other:?}"),
        };
        drop(younger_reader_guard);

        crate::test_complete!("downgrade_preserves_writer_preference_for_younger_readers");
    }

    #[test]
    fn owned_downgrade_preserves_writer_preference_for_younger_readers() {
        init_test("owned_downgrade_preserves_writer_preference_for_younger_readers");
        let cx = test_cx();
        let lock = StdArc::new(RwLock::new(0_u32));

        let active_writer = OwnedRwLockWriteGuard::try_write(StdArc::clone(&lock))
            .expect("owned writer should acquire");

        let mut writer_fut = OwnedRwLockWriteGuard::write(StdArc::clone(&lock), &cx);
        let writer_pending = poll_once(&mut writer_fut).is_none();
        crate::assert_with_log!(
            writer_pending,
            "owned writer queued behind active writer",
            true,
            writer_pending
        );

        let mut younger_reader_fut = OwnedRwLockReadGuard::read(StdArc::clone(&lock), &cx);
        let reader_pending = poll_once(&mut younger_reader_fut).is_none();
        crate::assert_with_log!(
            reader_pending,
            "owned younger reader queued behind writer",
            true,
            reader_pending
        );

        let downgraded_reader = active_writer.downgrade();

        let state = lock.debug_state();
        crate::assert_with_log!(
            state.readers == 1
                && state.writer_waiters == 1
                && state.writer_queue.len() == 1
                && state.reader_waiters.len() == 1,
            "owned downgrade keeps younger reader queued behind writer",
            true,
            state.readers == 1
                && state.writer_waiters == 1
                && state.writer_queue.len() == 1
                && state.reader_waiters.len() == 1
        );

        let younger_reader_still_pending = poll_once(&mut younger_reader_fut).is_none();
        crate::assert_with_log!(
            younger_reader_still_pending,
            "owned younger reader stays pending after downgrade",
            true,
            younger_reader_still_pending
        );

        let writer_still_pending = poll_once(&mut writer_fut).is_none();
        crate::assert_with_log!(
            writer_still_pending,
            "owned writer waits while downgraded reader is held",
            true,
            writer_still_pending
        );

        drop(downgraded_reader);

        let writer_guard = match poll_once(&mut writer_fut) {
            Some(Ok(guard)) => guard,
            other => panic!("owned writer should acquire before younger reader: {other:?}"),
        };
        let younger_reader_still_pending = poll_once(&mut younger_reader_fut).is_none();
        crate::assert_with_log!(
            younger_reader_still_pending,
            "owned younger reader remains queued while writer holds lock",
            true,
            younger_reader_still_pending
        );

        drop(writer_guard);

        let younger_reader_guard = match poll_once(&mut younger_reader_fut) {
            Some(Ok(guard)) => guard,
            other => {
                panic!("owned younger reader should acquire after writer releases: {other:?}")
            }
        };
        drop(younger_reader_guard);

        crate::test_complete!("owned_downgrade_preserves_writer_preference_for_younger_readers");
    }

    #[test]
    fn test_write_future_drop_wakes_readers_when_last_writer() {
        // When the last queued WriteFuture is dropped without acquiring,
        // pending readers must be woken.
        init_test("test_write_future_drop_wakes_readers_when_last_writer");
        let cx = test_cx();
        let lock = RwLock::new(42_u32);

        // Queue a writer (it will count itself in writer_waiters).
        let write_guard = write_blocking(&lock, &cx);
        let mut write_fut = lock.write(&cx);
        let pending = poll_once(&mut write_fut).is_none();
        crate::assert_with_log!(pending, "write future pending", true, pending);

        // Queue a reader (blocked because writer_waiters > 0).
        let mut read_fut = lock.read(&cx);
        let read_pending = poll_once(&mut read_fut).is_none();
        crate::assert_with_log!(read_pending, "read future pending", true, read_pending);

        // Release the active writer.
        drop(write_guard);

        // Drop the queued write future. This decrements writer_waiters to 0,
        // which should wake the queued reader.
        drop(write_fut);

        // The reader should now acquire.
        let read_result = poll_once(&mut read_fut);
        let acquired = matches!(read_result, Some(Ok(_)));
        crate::assert_with_log!(
            acquired,
            "reader acquired after writer drop",
            true,
            acquired
        );

        let state = lock.debug_state();
        crate::assert_with_log!(
            state.writer_waiters == 0,
            "no writer waiters left",
            0usize,
            state.writer_waiters
        );
        crate::test_complete!("test_write_future_drop_wakes_readers_when_last_writer");
    }

    #[test]
    fn test_read_future_drop_forwards_wake_to_writer() {
        // When a dequeued ReadFuture is dropped without acquiring, it must
        // forward its wake to a waiting writer.
        init_test("test_read_future_drop_forwards_wake_to_writer");
        let cx = test_cx();
        let lock = StdArc::new(RwLock::new(0_u32));

        // Writer holds the lock.
        let write_guard = write_blocking(&lock, &cx);

        // Queue a reader.
        let mut read_fut = lock.read(&cx);
        let pending = poll_once(&mut read_fut).is_none();
        crate::assert_with_log!(pending, "read pending while writer active", true, pending);

        // Queue a second writer.
        let writer_lock = StdArc::clone(&lock);
        let writer_done = StdArc::new(AtomicBool::new(false));
        let writer_done_c = StdArc::clone(&writer_done);
        let handle = thread::spawn(move || {
            let cx = test_cx();
            let _guard = write_blocking(&writer_lock, &cx);
            writer_done_c.store(true, AtomicOrdering::Release);
        });

        // Wait for the second writer to register.
        thread::sleep(std::time::Duration::from_millis(20));

        // Release active writer. Since writer_waiters > 0, this wakes the second
        // writer directly and DOES NOT dequeue the reader.
        drop(write_guard);

        // Drop the read future without polling. It simply removes itself from the queue.
        // The second writer is already woken and will acquire the lock.
        drop(read_fut);

        let _ = handle.join();
        let done = writer_done.load(AtomicOrdering::Acquire);
        crate::assert_with_log!(done, "second writer eventually acquired", true, done);
        crate::test_complete!("test_read_future_drop_forwards_wake_to_writer");
    }

    #[test]
    fn test_owned_read_guard_basic() {
        init_test("test_owned_read_guard_basic");
        let _cx = test_cx();
        let lock = StdArc::new(RwLock::new(42_u32));

        let guard =
            OwnedRwLockReadGuard::try_read(StdArc::clone(&lock)).expect("try_read should succeed");
        let value = guard.with_read(|v| *v);
        crate::assert_with_log!(value == 42, "owned read guard value", 42u32, value);
        drop(guard);

        // After drop, write should succeed.
        let can_write = lock.try_write().is_ok();
        crate::assert_with_log!(can_write, "write after owned read drop", true, can_write);
        crate::test_complete!("test_owned_read_guard_basic");
    }

    #[test]
    fn test_owned_write_guard_basic() {
        init_test("test_owned_write_guard_basic");
        let _cx = test_cx();
        let lock = StdArc::new(RwLock::new(42_u32));

        let mut guard = OwnedRwLockWriteGuard::try_write(StdArc::clone(&lock))
            .expect("try_write should succeed");
        guard.with_write(|v| *v = 100);
        drop(guard);

        let read_guard = lock.try_read().expect("read after write drop");
        crate::assert_with_log!(
            *read_guard == 100,
            "owned write persisted",
            100u32,
            *read_guard
        );
        crate::test_complete!("test_owned_write_guard_basic");
    }

    #[test]
    fn owned_cancel_queued_read_waiter_cleans_state_before_drop() {
        init_test("owned_cancel_queued_read_waiter_cleans_state_before_drop");
        let cx = test_cx();
        let cancel_cx = test_cx_with_slot(12);
        let lock = StdArc::new(RwLock::new(0_u32));

        let active_writer = write_blocking(lock.as_ref(), &cx);

        let mut read_fut = OwnedRwLockReadGuard::read(StdArc::clone(&lock), &cancel_cx);
        let read_pending = poll_once(&mut read_fut).is_none();
        crate::assert_with_log!(read_pending, "owned reader queued", true, read_pending);

        let mut writer_fut = OwnedRwLockWriteGuard::write(StdArc::clone(&lock), &cx);
        let writer_pending = poll_once(&mut writer_fut).is_none();
        crate::assert_with_log!(writer_pending, "owned writer queued", true, writer_pending);

        cancel_cx.set_cancel_requested(true);
        let cancelled = matches!(poll_once(&mut read_fut), Some(Err(RwLockError::Cancelled)));
        crate::assert_with_log!(cancelled, "owned reader cancelled", true, cancelled);

        let state = lock.debug_state();
        crate::assert_with_log!(
            state.reader_waiters.is_empty(),
            "owned reader waiter removed without drop",
            true,
            state.reader_waiters.is_empty()
        );

        drop(active_writer);

        let writer_result = poll_once(&mut writer_fut);
        let writer_acquired = matches!(writer_result, Some(Ok(_)));
        crate::assert_with_log!(
            writer_acquired,
            "owned writer acquires before cancelled reader future is dropped",
            true,
            writer_acquired
        );

        if let Some(Ok(guard)) = writer_result {
            drop(guard);
        }
        drop(read_fut);
        crate::test_complete!("owned_cancel_queued_read_waiter_cleans_state_before_drop");
    }

    #[test]
    fn owned_cancel_pregranted_write_waiter_unblocks_readers_before_drop() {
        init_test("owned_cancel_pregranted_write_waiter_unblocks_readers_before_drop");
        let cx = test_cx();
        let cancel_cx = test_cx_with_slot(13);
        let lock = StdArc::new(RwLock::new(42_u32));

        let read_guard = read_blocking(lock.as_ref(), &cx);

        let mut write_fut = OwnedRwLockWriteGuard::write(StdArc::clone(&lock), &cancel_cx);
        let write_pending = poll_once(&mut write_fut).is_none();
        crate::assert_with_log!(write_pending, "owned writer queued", true, write_pending);

        let mut read_fut = OwnedRwLockReadGuard::read(StdArc::clone(&lock), &cx);
        let read_pending = poll_once(&mut read_fut).is_none();
        crate::assert_with_log!(
            read_pending,
            "owned reader blocked by queued writer",
            true,
            read_pending
        );

        drop(read_guard);

        cancel_cx.set_cancel_requested(true);
        let cancelled = matches!(poll_once(&mut write_fut), Some(Err(RwLockError::Cancelled)));
        crate::assert_with_log!(
            cancelled,
            "pre-granted owned writer cancelled",
            true,
            cancelled
        );

        let state = lock.debug_state();
        crate::assert_with_log!(
            !state.writer_active && state.writer_waiters == 0,
            "pre-granted owned writer cleanup released writer slot",
            true,
            !state.writer_active && state.writer_waiters == 0
        );

        let read_result = poll_once(&mut read_fut);
        let reader_acquired = matches!(read_result, Some(Ok(_)));
        crate::assert_with_log!(
            reader_acquired,
            "owned reader acquires before cancelled writer future is dropped",
            true,
            reader_acquired
        );

        if let Some(Ok(guard)) = read_result {
            drop(guard);
        }
        drop(write_fut);
        crate::test_complete!("owned_cancel_pregranted_write_waiter_unblocks_readers_before_drop");
    }

    #[test]
    fn test_multiple_writer_cascade() {
        // Multiple writers queue behind an active writer and acquire sequentially.
        init_test("test_multiple_writer_cascade");
        let cx = test_cx();
        let lock = RwLock::new(0_u32);

        let write1 = write_blocking(&lock, &cx);

        // Queue two more writers.
        let mut write2_fut = lock.write(&cx);
        let w2_pending = poll_once(&mut write2_fut).is_none();
        crate::assert_with_log!(w2_pending, "writer 2 pending", true, w2_pending);

        let mut write3_fut = lock.write(&cx);
        let w3_pending = poll_once(&mut write3_fut).is_none();
        crate::assert_with_log!(w3_pending, "writer 3 pending", true, w3_pending);

        let state = lock.debug_state();
        crate::assert_with_log!(
            state.writer_waiters == 2,
            "two writers waiting",
            2usize,
            state.writer_waiters
        );

        // Release first writer — writer 2 should be next.
        drop(write1);

        let w2_result = poll_once(&mut write2_fut);
        let w2_acquired = matches!(w2_result, Some(Ok(_)));
        crate::assert_with_log!(w2_acquired, "writer 2 acquired", true, w2_acquired);

        // Writer 3 should still be pending.
        let w3_still_pending = poll_once(&mut write3_fut).is_none();
        crate::assert_with_log!(
            w3_still_pending,
            "writer 3 still pending",
            true,
            w3_still_pending
        );

        // Release writer 2 — writer 3 should acquire.
        if let Some(Ok(guard)) = w2_result {
            drop(guard);
        }

        let w3_result = poll_once(&mut write3_fut);
        let w3_acquired = matches!(w3_result, Some(Ok(_)));
        crate::assert_with_log!(w3_acquired, "writer 3 acquired", true, w3_acquired);
        crate::test_complete!("test_multiple_writer_cascade");
    }

    #[test]
    fn test_try_read_blocked_by_writer_waiters() {
        // try_read must fail when writers are queued, even if no writer is active.
        init_test("test_try_read_blocked_by_writer_waiters");
        let cx = test_cx();
        let lock = RwLock::new(0_u32);

        // Hold a read lock, then queue a writer.
        let read = read_blocking(&lock, &cx);
        let mut write_fut = lock.write(&cx);
        let pending = poll_once(&mut write_fut).is_none();
        crate::assert_with_log!(pending, "writer queued", true, pending);

        // try_read should fail because writer_waiters > 0.
        let try_read_guard = lock.try_read();
        crate::assert_with_log!(
            try_read_guard.is_err(),
            "try_read blocked by writer waiter",
            true,
            try_read_guard.is_err()
        );

        drop(read);
        crate::test_complete!("test_try_read_blocked_by_writer_waiters");
    }

    // ── Invariant: cancel write waiter unblocks readers ────────────────

    /// Invariant: when the only write waiter is cancelled and dropped,
    /// `writer_waiters` drops to 0 and blocked readers must be able to
    /// acquire the lock.  This tests the `WriteFuture::drop` path that
    /// drains `reader_waiters` when `writer_waiters == 0`.
    #[test]
    fn cancel_only_write_waiter_unblocks_readers() {
        init_test("cancel_only_write_waiter_unblocks_readers");
        let cx = test_cx();
        let lock = RwLock::new(42_u32);

        // Hold a read lock so a write waiter must queue.
        let read_guard = read_blocking(&lock, &cx);

        // Create a write waiter with a cancellable context.
        let cancel_cx: Cx = Cx::new(
            crate::types::RegionId::from_arena(ArenaIndex::new(0, 10)),
            crate::types::TaskId::from_arena(ArenaIndex::new(0, 10)),
            crate::types::Budget::INFINITE,
        );
        let mut write_fut = lock.write(&cancel_cx);
        let pending = poll_once(&mut write_fut).is_none();
        crate::assert_with_log!(pending, "write waiter pending", true, pending);

        // Now try to read — should be blocked by writer_waiters > 0.
        let mut read_fut = lock.read(&cx);
        let read_pending = poll_once(&mut read_fut).is_none();
        crate::assert_with_log!(
            read_pending,
            "reader blocked by writer waiter",
            true,
            read_pending
        );

        // Cancel and drop the write waiter.
        cancel_cx.set_cancel_requested(true);
        let cancelled = matches!(poll_once(&mut write_fut), Some(Err(RwLockError::Cancelled)));
        crate::assert_with_log!(cancelled, "write waiter cancelled", true, cancelled);
        drop(write_fut);

        // Verify writer_waiters is 0.
        let state = lock.debug_state();
        crate::assert_with_log!(
            state.writer_waiters == 0,
            "writer_waiters cleared",
            0usize,
            state.writer_waiters
        );

        // The blocked reader should now be able to acquire.
        let read_result = poll_once(&mut read_fut);
        let reader_acquired = matches!(read_result, Some(Ok(_)));
        crate::assert_with_log!(
            reader_acquired,
            "reader unblocked after write cancel",
            true,
            reader_acquired
        );

        drop(read_guard);
        crate::test_complete!("cancel_only_write_waiter_unblocks_readers");
    }

    /// Invariant: dropping a `WriteFuture` that was polled once (counted=true,
    /// waiter_id assigned) correctly decrements `writer_waiters` and removes
    /// from `writer_queue`.  This simulates a `select!` drop.
    #[test]
    fn drop_write_future_cleans_writer_waiters_counter() {
        init_test("drop_write_future_cleans_writer_waiters_counter");
        let cx = test_cx();
        let lock = RwLock::new(0_u32);

        // Hold a read lock so writers must queue.
        let _read = read_blocking(&lock, &cx);

        // Create two write waiters.
        let mut w1 = lock.write(&cx);
        let _ = poll_once(&mut w1);
        let mut w2 = lock.write(&cx);
        let _ = poll_once(&mut w2);

        let state = lock.debug_state();
        crate::assert_with_log!(
            state.writer_waiters == 2,
            "2 writer waiters",
            2usize,
            state.writer_waiters
        );

        // Drop w1 (simulating select! cancel).
        drop(w1);

        let state = lock.debug_state();
        crate::assert_with_log!(
            state.writer_waiters == 1,
            "1 writer waiter after drop",
            1usize,
            state.writer_waiters
        );
        crate::assert_with_log!(
            state.writer_queue.len() == 1,
            "1 in writer queue after drop",
            1usize,
            state.writer_queue.len()
        );

        // Drop w2.
        drop(w2);

        let state = lock.debug_state();
        crate::assert_with_log!(
            state.writer_waiters == 0,
            "0 writer waiters after both dropped",
            0usize,
            state.writer_waiters
        );
        crate::test_complete!("drop_write_future_cleans_writer_waiters_counter");
    }

    /// Invariant: poison propagation through read/write/try_read/try_write.
    /// A panic while holding a write guard poisons the lock; subsequent
    /// operations must return the appropriate Poisoned error.
    #[test]
    fn rwlock_poison_propagation() {
        init_test("rwlock_poison_propagation");
        let lock = StdArc::new(RwLock::new(0_u32));

        let l = StdArc::clone(&lock);
        let handle = thread::spawn(move || {
            let cx = test_cx();
            let _guard = write_blocking(&l, &cx);
            panic!("poison rwlock");
        });
        let _ = handle.join();

        let poisoned = lock.is_poisoned();
        crate::assert_with_log!(poisoned, "rwlock is poisoned", true, poisoned);

        let try_read = lock.try_read();
        let read_is_poisoned = matches!(try_read, Err(TryReadError::Poisoned));
        crate::assert_with_log!(
            read_is_poisoned,
            "try_read Poisoned",
            true,
            read_is_poisoned
        );

        let try_write = lock.try_write();
        let write_is_poisoned = matches!(try_write, Err(TryWriteError::Poisoned));
        crate::assert_with_log!(
            write_is_poisoned,
            "try_write Poisoned",
            true,
            write_is_poisoned
        );

        let cx = test_cx();
        let mut read_fut = lock.read(&cx);
        let read_result = poll_once(&mut read_fut);
        let read_poisoned = matches!(read_result, Some(Err(RwLockError::Poisoned)));
        crate::assert_with_log!(read_poisoned, "read() Poisoned", true, read_poisoned);

        let mut write_fut = lock.write(&cx);
        let write_result = poll_once(&mut write_fut);
        let write_poisoned = matches!(write_result, Some(Err(RwLockError::Poisoned)));
        crate::assert_with_log!(write_poisoned, "write() Poisoned", true, write_poisoned);

        crate::test_complete!("rwlock_poison_propagation");
    }

    // Pure data-type tests (wave 38 – CyanBarn)

    #[test]
    fn rwlock_error_debug_clone_copy_eq_display() {
        let poisoned = RwLockError::Poisoned;
        let cancelled = RwLockError::Cancelled;
        let polled_after_completion = RwLockError::PolledAfterCompletion;

        let dbg = format!("{poisoned:?}");
        assert!(dbg.contains("Poisoned"));

        let cloned = poisoned;
        assert_eq!(cloned, RwLockError::Poisoned);
        assert_ne!(poisoned, cancelled);
        assert_ne!(poisoned, polled_after_completion);

        assert!(poisoned.to_string().contains("poisoned"));
        assert!(cancelled.to_string().contains("cancelled"));
        assert!(
            polled_after_completion
                .to_string()
                .contains("polled after completion")
        );
    }

    #[test]
    fn try_read_error_debug_clone_copy_eq_display() {
        let locked = TryReadError::Locked;
        let poisoned = TryReadError::Poisoned;

        let dbg = format!("{locked:?}");
        assert!(dbg.contains("Locked"));

        let copied = locked;
        assert_eq!(copied, TryReadError::Locked);
        assert_ne!(locked, poisoned);

        assert!(locked.to_string().contains("write-locked"));
        assert!(poisoned.to_string().contains("poisoned"));
    }

    #[test]
    fn try_write_error_debug_clone_copy_eq_display() {
        let locked = TryWriteError::Locked;
        let poisoned = TryWriteError::Poisoned;

        let dbg = format!("{locked:?}");
        assert!(dbg.contains("Locked"));

        let copied = locked;
        assert_eq!(copied, TryWriteError::Locked);
        assert_ne!(locked, poisoned);

        assert!(locked.to_string().contains("locked"));
        assert!(poisoned.to_string().contains("poisoned"));
    }

    #[test]
    fn rwlock_debug() {
        let lock = RwLock::new(42_i32);
        let dbg = format!("{lock:?}");
        assert!(dbg.contains("RwLock"));
    }

    struct CountWaker(StdArc<std::sync::atomic::AtomicUsize>);
    impl std::task::Wake for CountWaker {
        fn wake(self: StdArc<Self>) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[test]
    fn test_drop_queued_writer_wakes_readers_when_readers_active() {
        init_test("test_drop_queued_writer_wakes_readers_when_readers_active");
        let cx = test_cx();
        let lock = RwLock::new(0_u32);

        let wake_state = StdArc::new(std::sync::atomic::AtomicUsize::new(0));
        let waker = Waker::from(StdArc::new(CountWaker(wake_state.clone())));
        let mut task_cx = Context::from_waker(&waker);

        // 1. Hold a read lock.
        let mut fut_read1 = lock.read(&cx);
        let Poll::Ready(Ok(_guard1)) = std::pin::Pin::new(&mut fut_read1).poll(&mut task_cx) else {
            panic!("Expected Ready") // ubs:ignore - test logic
        };

        // 2. Queue a writer.
        let mut fut_write = lock.write(&cx);
        let pending_write = std::pin::Pin::new(&mut fut_write).poll(&mut task_cx);
        assert!(pending_write.is_pending());

        // 3. Queue a second reader. It blocks because of the writer.
        let mut fut_read2 = lock.read(&cx);
        let pending_read = std::pin::Pin::new(&mut fut_read2).poll(&mut task_cx);
        assert!(pending_read.is_pending());

        wake_state.store(0, AtomicOrdering::SeqCst);

        // 4. Drop the writer. This should wake the second reader because writer_waiters becomes 0,
        // and even though there is an active reader, multiple readers can run concurrently.
        drop(fut_write);

        let wake_count = wake_state.load(AtomicOrdering::SeqCst);
        crate::assert_with_log!(
            wake_count > 0,
            "reader woken after writer drop",
            true,
            wake_count > 0
        );
        crate::test_complete!("test_drop_queued_writer_wakes_readers_when_readers_active");
    }

    /// br-asupersync-4j40bb regression: under continuous write load, a reader
    /// with `p` older queued readers is admitted after at most `(p + 1) * N`
    /// queued-writer hand-offs. Each forced turn admits only the oldest reader,
    /// then returns to the head writer.
    #[test]
    fn bounded_writer_preference_eventually_admits_starved_reader() {
        init_test("bounded_writer_preference_eventually_admits_starved_reader");
        let cx = test_cx();
        let lock = RwLock::new(0_u32);
        const N: usize = MAX_CONSECUTIVE_WRITERS_BEFORE_READER_BATCH;
        const READER_COUNT: usize = 3;
        const WRITER_COUNT: usize = READER_COUNT * N + 1;

        let active_writer = write_blocking(&lock, &cx);

        // The extra writer keeps the writer queue non-empty when the final
        // threshold is reached, so queue drain cannot satisfy the assertion.
        let mut writer_futs: Vec<_> = (0..WRITER_COUNT).map(|_| lock.write(&cx)).collect();
        for writer in &mut writer_futs {
            assert!(poll_once(writer).is_none(), "successor writer must queue");
        }

        let mut reader_futs: Vec<_> = (0..READER_COUNT).map(|_| lock.read(&cx)).collect();
        for reader in &mut reader_futs {
            assert!(poll_once(reader).is_none(), "reader must initially queue");
        }

        drop(active_writer);

        let mut writers_served = 0;
        for original_position in 0..READER_COUNT {
            let handoff_bound = (original_position + 1) * N;
            while writers_served < handoff_bound {
                for reader in &mut reader_futs {
                    assert!(
                        poll_once(reader).is_none(),
                        "reader at original position {original_position} was admitted before \
                         hand-off bound {handoff_bound}"
                    );
                }

                let writer_guard = match poll_once(&mut writer_futs[0]) {
                    Some(Ok(guard)) => guard,
                    other => panic!(
                        "oldest writer should acquire at hand-off {}: {other:?}",
                        writers_served + 1
                    ),
                };
                drop(writer_futs.remove(0));
                writers_served += 1;
                drop(writer_guard);
            }

            let reader_guard = match poll_once(&mut reader_futs[0]) {
                Some(Ok(guard)) => guard,
                other => panic!(
                    "reader at original position {original_position} should acquire by \
                     hand-off {handoff_bound}: {other:?}"
                ),
            };
            for younger_reader in &mut reader_futs[1..] {
                assert!(
                    poll_once(younger_reader).is_none(),
                    "forced turn must admit only the oldest queued reader"
                );
            }
            drop(reader_futs.remove(0));
            drop(reader_guard);
        }

        assert_eq!(writers_served, READER_COUNT * N);
        assert_eq!(writer_futs.len(), 1, "one trailing writer must remain");

        let trailing_writer = match poll_once(&mut writer_futs[0]) {
            Some(Ok(guard)) => guard,
            other => panic!("trailing writer should acquire after final reader: {other:?}"),
        };
        drop(writer_futs.remove(0));
        writers_served += 1;
        drop(trailing_writer);

        assert_eq!(writers_served, WRITER_COUNT);
        let final_state = lock.debug_state();
        assert_eq!(final_state.readers, 0, "all reader guards must be released");
        assert!(!final_state.writer_active, "no writer may remain active");
        assert_eq!(final_state.writer_waiters, 0, "no writer may remain queued");
        assert!(
            final_state.reader_waiters.is_empty(),
            "no reader waiter may remain queued"
        );
        assert!(
            final_state.writer_queue.is_empty(),
            "writer FIFO must be empty"
        );

        crate::test_complete!("bounded_writer_preference_eventually_admits_starved_reader");
    }

    #[test]
    fn forced_reader_turn_does_not_drain_younger_reader_batch_ahead_of_head_writer() {
        init_test("forced_reader_turn_does_not_drain_younger_reader_batch_ahead_of_head_writer");
        let cx = test_cx();
        let lock = RwLock::new(0_u32);
        const N: usize = MAX_CONSECUTIVE_WRITERS_BEFORE_READER_BATCH;

        let active_writer = write_blocking(&lock, &cx);

        let mut writer_futs: Vec<_> = (0..=N).map(|_| lock.write(&cx)).collect();
        for fut in &mut writer_futs {
            assert!(poll_once(fut).is_none(), "queued writer must wait");
        }

        let mut younger_reader_1 = lock.read(&cx);
        let mut younger_reader_2 = lock.read(&cx);
        assert!(
            poll_once(&mut younger_reader_1).is_none(),
            "first younger reader must queue behind the writers"
        );
        assert!(
            poll_once(&mut younger_reader_2).is_none(),
            "second younger reader must queue behind the writers"
        );

        drop(active_writer);

        for cycle in 0..N {
            let mut granted = None;
            for (i, fut) in writer_futs.iter_mut().enumerate() {
                match poll_once(fut) {
                    Some(Ok(guard)) => {
                        granted = Some((i, guard));
                        break;
                    }
                    Some(Err(err)) => panic!("queued writer failed on cycle {cycle}: {err:?}"),
                    None => {}
                }
            }
            let (ready_index, guard) = granted.expect("one queued writer should acquire per cycle");
            writer_futs.remove(ready_index);
            drop(guard);
        }

        assert_eq!(writer_futs.len(), 1, "one head writer should remain queued");

        let reader_guard = match poll_once(&mut younger_reader_1) {
            Some(Ok(guard)) => guard,
            other => panic!("forced reader turn should admit exactly one reader: {other:?}"),
        };
        assert!(
            poll_once(&mut younger_reader_2).is_none(),
            "second younger reader must remain queued behind the head writer"
        );
        assert!(
            poll_once(&mut writer_futs[0]).is_none(),
            "head writer must wait while the forced reader turn is held"
        );

        drop(reader_guard);

        let writer_guard = match poll_once(&mut writer_futs[0]) {
            Some(Ok(guard)) => guard,
            other => {
                panic!("head writer should run immediately after the forced reader turn: {other:?}")
            }
        };
        assert!(
            poll_once(&mut younger_reader_2).is_none(),
            "remaining younger reader must still wait while the head writer runs"
        );
        drop(writer_guard);

        let trailing_reader_guard = match poll_once(&mut younger_reader_2) {
            Some(Ok(guard)) => guard,
            other => panic!("remaining younger reader should run after the head writer: {other:?}"),
        };
        drop(trailing_reader_guard);

        crate::test_complete!(
            "forced_reader_turn_does_not_drain_younger_reader_batch_ahead_of_head_writer"
        );
    }

    #[test]
    fn writer_panic_wakes_all_queued_waiters_without_pregranting_slots() {
        init_test("writer_panic_wakes_all_queued_waiters_without_pregranting_slots");
        let cx = test_cx();
        let lock = RwLock::new(0_u32);

        let active_writer = write_blocking(&lock, &cx);

        let writer_wake_count = StdArc::new(std::sync::atomic::AtomicUsize::new(0));
        let writer_waker = Waker::from(StdArc::new(CountWaker(writer_wake_count.clone())));
        let mut writer_task_cx = Context::from_waker(&writer_waker);
        let mut writer_fut = lock.write(&cx);
        let writer_pending = std::pin::Pin::new(&mut writer_fut)
            .poll(&mut writer_task_cx)
            .is_pending();
        crate::assert_with_log!(
            writer_pending,
            "writer waiter queued before poison",
            true,
            writer_pending
        );

        let reader_wake_count = StdArc::new(std::sync::atomic::AtomicUsize::new(0));
        let reader_waker = Waker::from(StdArc::new(CountWaker(reader_wake_count.clone())));
        let mut reader_task_cx = Context::from_waker(&reader_waker);
        let mut reader_fut = lock.read(&cx);
        let reader_pending = std::pin::Pin::new(&mut reader_fut)
            .poll(&mut reader_task_cx)
            .is_pending();
        crate::assert_with_log!(
            reader_pending,
            "reader waiter queued before poison",
            true,
            reader_pending
        );

        let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = active_writer;
            panic!("poison rwlock");
        }));
        crate::assert_with_log!(
            panic_result.is_err(),
            "writer panic poisons the lock",
            true,
            panic_result.is_err()
        );

        let state = lock.debug_state();
        crate::assert_with_log!(
            !state.writer_active && state.readers == 0,
            "poison handoff does not pregrant reader or writer slots",
            true,
            !state.writer_active && state.readers == 0
        );
        crate::assert_with_log!(
            state.writer_waiters == 1
                && state.writer_queue.len() == 1
                && state.reader_waiters.len() == 1,
            "poison handoff leaves queued waiters to fail closed on poll",
            true,
            state.writer_waiters == 1
                && state.writer_queue.len() == 1
                && state.reader_waiters.len() == 1
        );

        let writer_woken = writer_wake_count.load(AtomicOrdering::SeqCst) > 0;
        let reader_woken = reader_wake_count.load(AtomicOrdering::SeqCst) > 0;
        crate::assert_with_log!(
            writer_woken,
            "queued writer is woken on poison",
            true,
            writer_woken
        );
        crate::assert_with_log!(
            reader_woken,
            "queued reader is also woken on poison",
            true,
            reader_woken
        );

        let writer_result = std::pin::Pin::new(&mut writer_fut).poll(&mut writer_task_cx);
        let writer_poisoned = matches!(writer_result, Poll::Ready(Err(RwLockError::Poisoned)));
        crate::assert_with_log!(
            writer_poisoned,
            "queued writer fails closed with poison",
            true,
            writer_poisoned
        );

        let reader_result = std::pin::Pin::new(&mut reader_fut).poll(&mut reader_task_cx);
        let reader_poisoned = matches!(reader_result, Poll::Ready(Err(RwLockError::Poisoned)));
        crate::assert_with_log!(
            reader_poisoned,
            "queued reader fails closed with poison",
            true,
            reader_poisoned
        );

        let final_state = lock.debug_state();
        crate::assert_with_log!(
            !final_state.writer_active
                && final_state.readers == 0
                && final_state.writer_waiters == 0
                && final_state.writer_queue.is_empty()
                && final_state.reader_waiters.is_empty(),
            "poisoned waiters clean themselves out without leaking reservations",
            true,
            !final_state.writer_active
                && final_state.readers == 0
                && final_state.writer_waiters == 0
                && final_state.writer_queue.is_empty()
                && final_state.reader_waiters.is_empty()
        );
        crate::test_complete!("writer_panic_wakes_all_queued_waiters_without_pregranting_slots");
    }
