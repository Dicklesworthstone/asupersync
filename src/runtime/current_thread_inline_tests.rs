    use super::*;
    use crate::evidence_sink::{CollectorSink, EvidenceSink};

    #[derive(Debug)]
    struct ReentrantWorkerSink {
        driver: std::sync::Weak<CurrentThreadDriver>,
        drop_status: Arc<std::sync::atomic::AtomicUsize>,
        entries: CollectorSink,
    }

    impl EvidenceSink for ReentrantWorkerSink {
        fn emit(&self, entry: &franken_evidence::EvidenceLedger) {
            self.entries.emit(entry);
        }

        fn next_evidence_ts(&self) -> u64 {
            self.entries.next_evidence_ts()
        }
    }

    impl Drop for ReentrantWorkerSink {
        fn drop(&mut self) {
            if let Some(driver) = self.driver.upgrade() {
                // Probe before re-entering so the old lock cycle fails an
                // assertion outside Drop instead of hanging the test process.
                let unlocked = driver.slot.try_lock().is_ok();
                if unlocked {
                    driver.shutdown();
                    self.drop_status.store(1, Ordering::SeqCst);
                } else {
                    self.drop_status.store(2, Ordering::SeqCst);
                }
            }
        }
    }

    #[derive(Debug, Clone, Copy)]
    enum WorkerRetirement {
        Offered,
        Returned,
        ClosedLoanReturn,
        BackgroundWaiting,
    }

    fn assert_worker_drop_can_reenter(retirement: WorkerRetirement) {
        use crate::runtime::RuntimeState;
        use crate::sync::ContendedMutex;
        use std::sync::atomic::AtomicUsize;

        let state = Arc::new(ContendedMutex::new(
            "worker_retirement",
            RuntimeState::new(),
        ));
        let mut scheduler = ThreeLaneScheduler::new(1, &state);
        let driver = Arc::new(CurrentThreadDriver::new(None, scheduler.local_store_key()));
        let drop_status = Arc::new(AtomicUsize::new(0));
        let mut worker = Box::new(scheduler.take_workers().pop().expect("one real worker"));
        worker.set_evidence_sink(Arc::new(ReentrantWorkerSink {
            driver: Arc::downgrade(&driver),
            drop_status: Arc::clone(&drop_status),
            entries: CollectorSink::new(),
        }));

        match retirement {
            WorkerRetirement::Offered => {
                *driver.lock_slot() =
                    WorkerSlot::Offered(std::thread::current().id(), erase_worker(worker));
                driver.shutdown();
            }
            WorkerRetirement::Returned => {
                *driver.lock_slot() = WorkerSlot::Returned(erase_worker(worker));
                driver.shutdown();
            }
            WorkerRetirement::ClosedLoanReturn => {
                driver.shutdown();
                driver.release(worker);
            }
            WorkerRetirement::BackgroundWaiting => {
                *driver.lock_slot() = WorkerSlot::Requested(std::thread::current().id());
                driver.handover_requested.store(true, Ordering::Release);
                let shutdown = Arc::clone(&worker.shutdown);
                let observer_driver = Arc::clone(&driver);
                let observer = std::thread::spawn(move || {
                    let (slot, _) = observer_driver
                        .changed
                        .wait_timeout_while(
                            observer_driver.lock_slot(),
                            Duration::from_secs(5),
                            |slot| matches!(slot, WorkerSlot::Requested(_)),
                        )
                        .unwrap_or_else(PoisonError::into_inner);
                    let offered = matches!(*slot, WorkerSlot::Offered(_, _));
                    shutdown.store(true, Ordering::Release);
                    observer_driver.changed.notify_all();
                    offered
                });
                driver.run_background(*worker, || {});
                assert!(observer.join().expect("shutdown observer exits"));
            }
        }

        assert_eq!(
            drop_status.load(Ordering::SeqCst),
            1,
            "{retirement:?}: the real worker's sink must re-enter without the slot lock"
        );
        assert!(matches!(*driver.lock_slot(), WorkerSlot::Closed));
    }

    #[test]
    fn shutdown_retires_offered_worker_outside_handoff_lock() {
        assert_worker_drop_can_reenter(WorkerRetirement::Offered);
    }

    #[test]
    fn shutdown_retires_returned_worker_outside_handoff_lock() {
        assert_worker_drop_can_reenter(WorkerRetirement::Returned);
    }

    #[test]
    fn closed_loan_retires_worker_outside_handoff_lock() {
        assert_worker_drop_can_reenter(WorkerRetirement::ClosedLoanReturn);
    }

    #[test]
    fn background_shutdown_retires_offered_worker_outside_handoff_lock() {
        assert_worker_drop_can_reenter(WorkerRetirement::BackgroundWaiting);
    }

    #[test]
    fn background_handoff_refuses_queued_local_admission() {
        use crate::runtime::RuntimeState;
        use crate::runtime::spawn_mailbox::LocalSpawnRequest;
        use crate::sync::ContendedMutex;
        use crate::types::{Budget, Outcome};

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let pending = state.region(root).expect("root").pending_spawn_handle();
        let state = Arc::new(ContendedMutex::new("queued_local_handoff", state));
        let mailbox = Arc::new(SpawnMailbox::new());
        let mut scheduler = ThreeLaneScheduler::new(1, &state);
        scheduler.attach_spawn_mailbox(Arc::clone(&mailbox));
        let worker = scheduler.take_workers().pop().expect("one real worker");
        let shutdown = Arc::clone(&worker.shutdown);
        let driver = Arc::new(CurrentThreadDriver::new(None, worker.local_store_key()));
        *driver.lock_slot() = WorkerSlot::Requested(std::thread::current().id());
        driver.handover_requested.store(true, Ordering::Release);

        let observer_driver = Arc::clone(&driver);
        let observer_shutdown = Arc::clone(&shutdown);
        let observer = std::thread::spawn(move || {
            let (slot, timeout) = observer_driver
                .changed
                .wait_timeout_while(
                    observer_driver.lock_slot(),
                    Duration::from_secs(5),
                    |slot| matches!(slot, WorkerSlot::Requested(_)),
                )
                .unwrap_or_else(PoisonError::into_inner);
            let offered = matches!(*slot, WorkerSlot::Offered(_, _));
            let stuck = timeout.timed_out() && matches!(*slot, WorkerSlot::Requested(_));
            drop(slot);
            if offered || stuck {
                // Let the old implementation exit without hanging or moving
                // the queued !Send factory to the observer thread.
                observer_shutdown.store(true, Ordering::Release);
                observer_driver.shutdown();
            }
            (offered, stuck)
        });

        let ran_on = Rc::new(Cell::new(None));
        let task_ran_on = Rc::clone(&ran_on);
        driver.run_background(worker, || {
            spawn_mailbox::enqueue_local_spawn_for_mailbox(
                LocalSpawnRequest {
                    task_id: mailbox.allocate_task_id(),
                    region: root,
                    budget: Budget::INFINITE,
                    factory: Box::new(move |_| {
                        Box::pin(async move {
                            task_ran_on.set(Some(std::thread::current().id()));
                            shutdown.store(true, Ordering::Release);
                            Outcome::Ok(())
                        })
                    }),
                    on_unadmitted_cancel: None,
                    on_admission_error: None,
                    pending_reservation: Some(pending.reserve()),
                    admitted_slot: None,
                },
                &mailbox,
            );
            assert_eq!(pending.count(), 1, "request is queued before handoff");
        });
        let (offered, stuck) = observer.join().expect("handoff observer exits");
        spawn_mailbox::cancel_local_spawns_for_mailbox(&mailbox);

        assert!(!stuck, "background worker must answer the handoff request");
        assert!(
            !offered,
            "queued local admission must prevent a worker loan"
        );
        assert_eq!(ran_on.get(), Some(std::thread::current().id()));
        assert_eq!(pending.count(), 0, "pending admission credit is released");
        assert_eq!(Rc::strong_count(&ran_on), 1, "local capture is retired");
    }

    /// 01oghn L1: a drive that ends with this runtime's local requests still
    /// queued fails them, which releases their regions' pending-spawn credit.
    /// A Closing region whose last blocker was such a request must then
    /// advance; it used to stay Closing.
    #[test]
    fn an_orphaned_local_request_lets_its_closing_region_finish() {
        use crate::record::region::RegionState;
        use crate::runtime::RuntimeState;
        use crate::runtime::spawn_mailbox::LocalSpawnRequest;
        use crate::sync::ContendedMutex;
        use crate::types::{Budget, Outcome};

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let child = state
            .create_child_region(root, Budget::INFINITE)
            .expect("child region");
        let pending = state.region(child).expect("child").pending_spawn_handle();
        let state = Arc::new(ContendedMutex::new("orphaned_local_request", state));
        let mailbox = Arc::new(SpawnMailbox::new());
        let mut scheduler = ThreeLaneScheduler::new(1, &state);
        scheduler.attach_spawn_mailbox(Arc::clone(&mailbox));
        let worker = scheduler.take_workers().pop().expect("one real worker");
        let driver = CurrentThreadDriver::new(None, worker.local_store_key());
        let mut loan = WorkerLoan {
            driver: &driver,
            worker: Some(Box::new(worker)),
            return_to: LoanReturn::Background,
        };

        loan.with_thread_context(|_, _| {
            spawn_mailbox::enqueue_local_spawn_for_mailbox(
                LocalSpawnRequest {
                    task_id: mailbox.allocate_task_id(),
                    region: child,
                    budget: Budget::INFINITE,
                    factory: Box::new(|_| Box::pin(async { Outcome::Ok(()) })),
                    on_unadmitted_cancel: None,
                    on_admission_error: None,
                    pending_reservation: Some(pending.reserve()),
                    admitted_slot: None,
                },
                &mailbox,
            );
            // The region's body is done and the drive ends here, curtailed,
            // with the request still queued.
            let state = state.lock().unwrap_or_else(PoisonError::into_inner);
            assert!(state.region(child).expect("child").begin_close(None));
        });

        assert_eq!(pending.count(), 0, "the failed request released its credit");
        let after = state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .region(child)
            .map(crate::record::region::RegionRecord::state);
        assert!(
            !matches!(after, Some(RegionState::Closing)),
            "the region is still Closing with nothing left to wait for: {after:?}",
        );
    }

    /// Reproduce the state visible to R1 when its handover was refused and
    /// R2 has already borrowed the worker before R1 reacquires the mutex.
    /// The refused caller must not wait for a foreign loan to finish.
    #[test]
    fn refused_request_does_not_wait_for_a_foreign_loan() {
        assert_refused_request_returns(WorkerSlot::Loaned);
    }

    #[test]
    fn refused_request_does_not_wait_for_a_new_requester() {
        assert_refused_request_returns(WorkerSlot::Requested(std::thread::current().id()));
    }

    #[test]
    fn refused_request_does_not_steal_a_new_requesters_offer() {
        // The erased value must never be touched by the refused caller.
        assert_refused_request_returns(WorkerSlot::Offered(
            std::thread::current().id(),
            Box::new(()),
        ));
    }

    fn assert_refused_request_returns(replacement: WorkerSlot) {
        use crate::runtime::RuntimeState;
        use crate::sync::ContendedMutex;
        use std::sync::mpsc;

        let state = Arc::new(ContendedMutex::new("request_race", RuntimeState::new()));
        let scheduler = Arc::new(ThreeLaneScheduler::new(1, &state));
        let driver = Arc::new(CurrentThreadDriver::new(
            None,
            crate::runtime::local::allocate_local_store_key(),
        ));
        let caller_driver = Arc::clone(&driver);
        let (sent, received) = mpsc::channel();
        let caller = std::thread::spawn(move || {
            let refused = caller_driver.acquire(&scheduler).is_none();
            let _ = sent.send(refused);
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut request_seen = false;
        let expected_state = std::mem::discriminant(&replacement);
        while Instant::now() < deadline {
            let mut slot = driver.lock_slot();
            if driver.handover_requested.load(Ordering::Acquire) {
                request_seen = true;
                // The background refusal and R2 acquisition happen while
                // R1 is asleep; only their final state is observable to R1.
                *slot = replacement;
                driver.changed.notify_all();
                break;
            }
            drop(slot);
            std::thread::yield_now();
        }
        let result = received.recv_timeout(Duration::from_secs(2));
        let final_state = std::mem::discriminant(&*driver.lock_slot());
        let flag_retained = driver.handover_requested.load(Ordering::Acquire);
        driver.shutdown();
        caller.join().expect("requester exits after cleanup");
        assert!(
            request_seen,
            "requester must actually enter the handover wait"
        );
        assert!(result.expect("refused requester waited on a foreign loan"));
        assert_eq!(final_state, expected_state, "foreign slot was consumed");
        assert!(
            flag_retained,
            "refused caller cleared a foreign request flag"
        );
    }

    /// `ScopedLocalStoreKey` restores the key of the thread that created it,
    /// so it must not be movable to another thread. The call below is
    /// ambiguous, and fails to compile, if the type ever becomes `Send`.
    #[test]
    fn scoped_local_store_key_is_not_send() {
        trait AmbiguousIfSend<A> {
            fn check() {}
        }
        impl<T> AmbiguousIfSend<()> for T {}
        impl<T: Send> AmbiguousIfSend<u8> for T {}
        <ScopedLocalStoreKey as AmbiguousIfSend<_>>::check();
    }

    /// The loan protocol object is shared between the background thread and
    /// `block_on` callers through an `Arc`, so it must stay `Send + Sync`.
    #[test]
    fn current_thread_driver_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CurrentThreadDriver>();
    }

    /// Shutdown retires the calling thread's keyed store for this runtime
    /// (and only that one).
    #[test]
    fn shutdown_retires_the_calling_threads_keyed_store() {
        use crate::runtime::local::{
            ScopedLocalStoreKey, keyed_local_store_count, local_task_count,
        };
        let before = keyed_local_store_count();
        let driver_key = crate::runtime::local::allocate_local_store_key();
        let other_key = crate::runtime::local::allocate_local_store_key();
        let driver = CurrentThreadDriver::new(None, driver_key);
        let other = CurrentThreadDriver::new(None, other_key);
        {
            let _key = ScopedLocalStoreKey::new(driver_key);
            // Touching the store materializes this runtime's entry.
            assert_eq!(local_task_count(), 0);
        }
        {
            let _key = ScopedLocalStoreKey::new(other_key);
            assert_eq!(local_task_count(), 0);
        }
        assert_eq!(keyed_local_store_count(), before + 2);
        driver.shutdown();
        assert_eq!(keyed_local_store_count(), before + 1);
        other.shutdown();
        assert_eq!(keyed_local_store_count(), before);
    }
