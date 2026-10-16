    use super::WaiterChain;
    use std::panic::{AssertUnwindSafe, catch_unwind};
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
    fn repeated_deferred_clones_reuse_a_single_relay() {
        let wakes = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicBool::new(false));
        let mut chain = WaiterChain::new();
        let id = chain.push_back(Waker::from(Arc::new(DeferredWakeProbe {
            wakes: Arc::clone(&wakes),
            dropped: Arc::clone(&dropped),
        })));

        let first_batch = chain.clone_wakers_deferred();
        for _ in 0..4096 {
            let batch = chain.clone_wakers_deferred();
            assert_eq!(batch.len(), 1);
            assert!(
                first_batch[0].will_wake(&batch[0]),
                "repeated notifications must not allocate a nested relay"
            );
            batch[0].wake_by_ref();
        }
        assert_eq!(wakes.load(Ordering::SeqCst), 4096);
        assert_eq!(chain.len(), 1);
        assert!(chain.contains(id));
        assert!(!dropped.load(Ordering::SeqCst));

        let queued = chain.remove(id).expect("waiter is still queued");
        assert!(queued.will_wake(&first_batch[0]));
        drop(first_batch);
        queued.wake();
        assert_eq!(wakes.load(Ordering::SeqCst), 4097);
        assert!(dropped.load(Ordering::SeqCst));
        assert!(chain.is_empty());
    }

    #[test]
    fn deferred_refresh_preserves_original_task_identity() {
        let wakes = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicBool::new(false));
        let original = Waker::from(Arc::new(DeferredWakeProbe {
            wakes: Arc::clone(&wakes),
            dropped: Arc::clone(&dropped),
        }));
        let mut chain = WaiterChain::new();
        let id = chain.push_back(original.clone());
        let first_batch = chain.clone_wakers_deferred();

        let retired = chain.replace_waker(id, original.clone()).unwrap();
        assert!(retired.will_wake(&original));
        assert!(chain.update_waker(id, &original));
        let next_batch = chain.clone_wakers_deferred();
        assert!(first_batch[0].will_wake(&next_batch[0]));

        drop(retired);
        drop(original);
        drop(first_batch);
        drop(next_batch);
        assert!(!dropped.load(Ordering::SeqCst));
        let queued = chain.remove(id).unwrap();
        queued.wake();
        assert_eq!(wakes.load(Ordering::SeqCst), 1);
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn deferred_replacement_keeps_retired_task_alive_until_returned_owner_drops() {
        let old_wakes = Arc::new(AtomicUsize::new(0));
        let old_dropped = Arc::new(AtomicBool::new(false));
        let new_wakes = Arc::new(AtomicUsize::new(0));
        let new_dropped = Arc::new(AtomicBool::new(false));
        let mut chain = WaiterChain::new();
        let id = chain.push_back(Waker::from(Arc::new(DeferredWakeProbe {
            wakes: Arc::clone(&old_wakes),
            dropped: Arc::clone(&old_dropped),
        })));
        let old_batch = chain.clone_wakers_deferred();
        let retired = chain
            .replace_waker(
                id,
                Waker::from(Arc::new(DeferredWakeProbe {
                    wakes: Arc::clone(&new_wakes),
                    dropped: Arc::clone(&new_dropped),
                })),
            )
            .unwrap();

        assert!(retired.will_wake(&old_batch[0]));
        let new_batch = chain.clone_wakers_deferred();
        assert!(!old_batch[0].will_wake(&new_batch[0]));
        drop(old_batch);
        assert!(!old_dropped.load(Ordering::SeqCst));
        retired.wake();
        assert_eq!(old_wakes.load(Ordering::SeqCst), 1);
        assert!(old_dropped.load(Ordering::SeqCst));

        new_batch[0].wake_by_ref();
        assert_eq!(new_wakes.load(Ordering::SeqCst), 1);
        let (_, queued, ()) = chain.pop_front().unwrap();
        assert!(queued.will_wake(&new_batch[0]));
        drop(new_batch);
        assert!(!new_dropped.load(Ordering::SeqCst));
        drop(queued);
        assert!(new_dropped.load(Ordering::SeqCst));
        assert!(chain.is_empty());
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
        chain.next_id = Some(u64::from(u32::MAX) - 1);

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
    fn waiter_id_exhaustion_fails_closed_before_stale_identity_repeats() {
        let mut chain = WaiterChain::new();
        let stale_id = chain.push_back(noop_waker());
        assert_eq!(stale_id, 0);
        assert_eq!(
            chain.pop_front().map(|(id, _, tag)| (id, tag)),
            Some((stale_id, ()))
        );

        chain.next_id = Some(u64::MAX);
        let terminal_id = chain.push_back(noop_waker());
        assert_eq!(terminal_id, u64::MAX);

        let exhausted = catch_unwind(AssertUnwindSafe(|| chain.push_back(noop_waker())));
        assert!(exhausted.is_err(), "the exhausted counter must not wrap");
        assert!(chain.remove(stale_id).is_none());
        assert!(chain.contains(terminal_id));
        assert_eq!(
            chain.pop_front().map(|(id, _, tag)| (id, tag)),
            Some((terminal_id, ()))
        );
        assert!(chain.is_empty());
    }

    #[test]
    fn waiter_id_width_is_not_pointer_width_limited() {
        assert!(
            std::mem::size_of::<super::WaiterId>() >= std::mem::size_of::<u64>(),
            "waiter ids must remain wide enough for 32-bit targets"
        );
    }
