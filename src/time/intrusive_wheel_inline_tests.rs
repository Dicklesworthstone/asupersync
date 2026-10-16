    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use proptest::prelude::*;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::task::Wake;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    struct CounterWaker {
        counter: Arc<AtomicU64>,
    }

    impl Wake for CounterWaker {
        fn wake(self: Arc<Self>) {
            self.counter.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.counter.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn counter_waker(counter: Arc<AtomicU64>) -> Waker {
        Arc::new(CounterWaker { counter }).into()
    }

    fn intrusive_wheel_signature<const SLOTS: usize>(
        entries: &[(u16, bool)],
        insertion_order: &[usize],
        cancel_after_insert: bool,
    ) -> (Option<Duration>, usize, usize, bool) {
        let base = Instant::now();
        let mut wheel: TimerWheel<SLOTS> = TimerWheel::new_at(Duration::from_millis(1), base);
        let counter = Arc::new(AtomicU64::new(0));
        let mut nodes: Vec<Pin<Box<TimerNode>>> = (0..entries.len())
            .map(|_| Box::pin(TimerNode::new()))
            .collect();

        for &index in insertion_order {
            let (offset_ms, cancelled) = entries[index];
            if !cancel_after_insert && cancelled {
                continue;
            }

            let deadline = base + Duration::from_millis(u64::from(offset_ms));
            let waker = counter_waker(counter.clone());
            unsafe {
                wheel.insert(nodes[index].as_mut(), deadline, waker);
            }
        }

        if cancel_after_insert {
            for (index, (_, cancelled)) in entries.iter().enumerate() {
                if *cancelled {
                    unsafe {
                        wheel.cancel(nodes[index].as_mut());
                    }
                }
            }
        }

        let next = wheel.next_expiration();
        let max_offset_ms = entries
            .iter()
            .filter_map(|(offset_ms, cancelled)| (!cancelled).then_some(*offset_ms))
            .max()
            .unwrap_or(0);
        let advance_target = base + Duration::from_millis(u64::from(max_offset_ms) + 2);
        let wakers = unsafe { wheel.advance_to(advance_target) };
        let wake_count = wakers.len();
        for waker in wakers {
            waker.wake();
        }

        (
            next,
            wake_count,
            nodes.iter().filter(|node| node.is_linked()).count(),
            wheel.is_empty(),
        )
    }

    #[test]
    fn intrusive_wheel_new() {
        init_test("intrusive_wheel_new");
        let wheel: TimerWheel<256> = TimerWheel::new(Duration::from_millis(1));

        crate::assert_with_log!(
            wheel.is_empty(),
            "wheel starts empty",
            true,
            wheel.is_empty()
        );
        crate::assert_with_log!(wheel.is_empty(), "len is 0", 0, wheel.len());
        crate::assert_with_log!(
            wheel.resolution() == Duration::from_millis(1),
            "resolution",
            Duration::from_millis(1),
            wheel.resolution()
        );
        crate::test_complete!("intrusive_wheel_new");
    }

    #[test]
    fn intrusive_wheel_insert_and_tick() {
        init_test("intrusive_wheel_insert_and_tick");
        let base = Instant::now();
        let mut wheel: TimerWheel<256> = TimerWheel::new_at(Duration::from_millis(1), base);
        let counter = Arc::new(AtomicU64::new(0));

        let mut node = Box::pin(TimerNode::new());
        let deadline = base + Duration::from_millis(5);
        let waker = counter_waker(counter.clone());

        unsafe {
            wheel.insert(node.as_mut(), deadline, waker);
        }

        crate::assert_with_log!(wheel.len() == 1, "len is 1", 1, wheel.len());
        crate::assert_with_log!(node.is_linked(), "node is linked", true, node.is_linked());

        // Advance past deadline
        std::thread::sleep(Duration::from_millis(10));
        let wakers = unsafe { wheel.advance_to(Instant::now()) };

        crate::assert_with_log!(wakers.len() == 1, "got 1 waker", 1, wakers.len());

        for waker in wakers {
            waker.wake();
        }

        let count = counter.load(Ordering::SeqCst);
        crate::assert_with_log!(count == 1, "counter is 1", 1, count);
        crate::assert_with_log!(wheel.is_empty(), "wheel is empty", true, wheel.is_empty());
        crate::test_complete!("intrusive_wheel_insert_and_tick");
    }

    #[test]
    fn intrusive_wheel_cancel() {
        init_test("intrusive_wheel_cancel");
        let base = Instant::now();
        let mut wheel: TimerWheel<256> = TimerWheel::new_at(Duration::from_millis(1), base);
        let counter = Arc::new(AtomicU64::new(0));

        let mut node = Box::pin(TimerNode::new());
        let deadline = base + Duration::from_millis(50);
        let waker = counter_waker(counter.clone());

        unsafe {
            wheel.insert(node.as_mut(), deadline, waker);
        }

        crate::assert_with_log!(wheel.len() == 1, "len is 1", 1, wheel.len());

        // Cancel before it fires
        unsafe {
            wheel.cancel(node.as_mut());
        }

        crate::assert_with_log!(!node.is_linked(), "node unlinked", false, node.is_linked());
        crate::assert_with_log!(wheel.is_empty(), "wheel is empty", true, wheel.is_empty());

        // Advance time - should not fire
        std::thread::sleep(Duration::from_millis(60));
        let wakers = unsafe { wheel.advance_to(Instant::now()) };

        crate::assert_with_log!(wakers.is_empty(), "no wakers", true, wakers.is_empty());

        let count = counter.load(Ordering::SeqCst);
        crate::assert_with_log!(count == 0, "counter is 0", 0, count);
        crate::test_complete!("intrusive_wheel_cancel");
    }

    #[test]
    fn intrusive_wheel_multiple_timers() {
        init_test("intrusive_wheel_multiple_timers");
        let base = Instant::now();
        let mut wheel: TimerWheel<256> = TimerWheel::new_at(Duration::from_millis(1), base);
        let counter = Arc::new(AtomicU64::new(0));

        let mut nodes: Vec<Pin<Box<TimerNode>>> =
            (0..5).map(|_| Box::pin(TimerNode::new())).collect();

        // Insert timers at different deadlines
        for (i, node) in nodes.iter_mut().enumerate() {
            let deadline = base + Duration::from_millis((i as u64 + 1) * 10);
            let waker = counter_waker(counter.clone());
            unsafe {
                wheel.insert(node.as_mut(), deadline, waker);
            }
        }

        crate::assert_with_log!(wheel.len() == 5, "len is 5", 5, wheel.len());

        // Advance past all deadlines
        std::thread::sleep(Duration::from_millis(60));
        let wakers = unsafe { wheel.advance_to(Instant::now()) };

        crate::assert_with_log!(wakers.len() == 5, "got 5 wakers", 5, wakers.len());

        for waker in wakers {
            waker.wake();
        }

        let count = counter.load(Ordering::SeqCst);
        crate::assert_with_log!(count == 5, "counter is 5", 5, count);
        crate::test_complete!("intrusive_wheel_multiple_timers");
    }

    #[test]
    fn intrusive_wheel_wrap_around() {
        init_test("intrusive_wheel_wrap_around");
        // Small wheel to test wrap-around
        let base = Instant::now();
        let mut wheel: TimerWheel<4> = TimerWheel::new_at(Duration::from_millis(10), base);
        let counter = Arc::new(AtomicU64::new(0));

        // Insert timer that wraps around (slot 5 % 4 = 1)
        let mut node = Box::pin(TimerNode::new());
        let deadline = base + Duration::from_millis(50);
        let waker = counter_waker(counter);

        unsafe {
            wheel.insert(node.as_mut(), deadline, waker);
        }

        let slot = wheel.slot_for(deadline);
        crate::assert_with_log!(slot == 1, "slot wraps to 1", 1, slot);

        // Advance and fire
        std::thread::sleep(Duration::from_millis(60));
        let wakers = unsafe { wheel.advance_to(Instant::now()) };

        crate::assert_with_log!(wakers.len() == 1, "fired", 1, wakers.len());
        crate::test_complete!("intrusive_wheel_wrap_around");
    }

    #[test]
    fn intrusive_wheel_clear() {
        init_test("intrusive_wheel_clear");
        let base = Instant::now();
        let mut wheel: TimerWheel<256> = TimerWheel::new_at(Duration::from_millis(1), base);
        let counter = Arc::new(AtomicU64::new(0));

        let mut nodes: Vec<Pin<Box<TimerNode>>> =
            (0..3).map(|_| Box::pin(TimerNode::new())).collect();

        for (i, node) in nodes.iter_mut().enumerate() {
            let deadline = base + Duration::from_millis((i as u64 + 1) * 10);
            let waker = counter_waker(counter.clone());
            unsafe {
                wheel.insert(node.as_mut(), deadline, waker);
            }
        }

        crate::assert_with_log!(wheel.len() == 3, "len is 3", 3, wheel.len());

        // Clear without firing
        unsafe {
            wheel.clear();
        }

        crate::assert_with_log!(wheel.is_empty(), "wheel empty", true, wheel.is_empty());

        let count = counter.load(Ordering::SeqCst);
        crate::assert_with_log!(count == 0, "counter still 0", 0, count);
        crate::test_complete!("intrusive_wheel_clear");
    }

    #[test]
    fn timer_node_default() {
        init_test("timer_node_default");
        let node = TimerNode::default();
        crate::assert_with_log!(!node.is_linked(), "not linked", false, node.is_linked());
        crate::test_complete!("timer_node_default");
    }

    #[test]
    fn intrusive_wheel_next_expiration() {
        init_test("intrusive_wheel_next_expiration");
        let base = Instant::now();
        let mut wheel: TimerWheel<256> = TimerWheel::new_at(Duration::from_millis(1), base);

        let empty = wheel.next_expiration();
        crate::assert_with_log!(empty.is_none(), "empty wheel", true, empty.is_none());

        let mut node = Box::pin(TimerNode::new());
        let deadline = base + Duration::from_millis(100);
        let waker = Arc::new(CounterWaker {
            counter: Arc::new(AtomicU64::new(0)),
        })
        .into();

        unsafe {
            wheel.insert(node.as_mut(), deadline, waker);
        }

        let next = wheel.next_expiration();
        crate::assert_with_log!(next.is_some(), "has expiration", true, next.is_some());

        // Cancel the node before it drops — TimerNode::drop asserts !is_linked().
        unsafe {
            wheel.cancel(node.as_mut());
        }

        crate::test_complete!("intrusive_wheel_next_expiration");
    }

    #[test]
    fn intrusive_wheel_next_expiration_uses_wheel_time_not_wall_clock() {
        init_test("intrusive_wheel_next_expiration_uses_wheel_time_not_wall_clock");

        let base = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .unwrap_or_else(Instant::now);
        let mut wheel: TimerWheel<256> = TimerWheel::new_at(Duration::from_millis(1), base);

        let mut node = Box::pin(TimerNode::new());
        let deadline = base + Duration::from_millis(100);
        let waker = Arc::new(CounterWaker {
            counter: Arc::new(AtomicU64::new(0)),
        })
        .into();

        unsafe {
            wheel.insert(node.as_mut(), deadline, waker);
        }

        let next = wheel.next_expiration();
        crate::assert_with_log!(
            next == Some(Duration::from_millis(100)),
            "next expiration is relative to wheel progress, not ambient wall clock",
            Some(Duration::from_millis(100)),
            next
        );

        unsafe {
            wheel.cancel(node.as_mut());
        }

        crate::test_complete!("intrusive_wheel_next_expiration_uses_wheel_time_not_wall_clock");
    }

    #[test]
    fn intrusive_wheel_rebuckets_nonexpired_timer_from_retired_slot() {
        init_test("intrusive_wheel_rebuckets_nonexpired_timer_from_retired_slot");

        let base = Instant::now();
        let mut wheel: TimerWheel<256> = TimerWheel::new_at(Duration::from_millis(1), base);
        let counter = Arc::new(AtomicU64::new(0));

        let mut node = Box::pin(TimerNode::new());
        let deadline = base + Duration::from_micros(5_500);
        let waker = counter_waker(counter.clone());

        unsafe {
            wheel.insert(node.as_mut(), deadline, waker);
        }

        let early = unsafe { wheel.advance_to(base + Duration::from_millis(5)) };
        crate::assert_with_log!(
            early.is_empty(),
            "timer later in the bucket must not fire at the bucket boundary",
            true,
            early.is_empty()
        );
        crate::assert_with_log!(
            node.is_linked(),
            "timer stays scheduled",
            true,
            node.is_linked()
        );

        let due = unsafe { wheel.advance_to(base + Duration::from_millis(6)) };
        crate::assert_with_log!(due.len() == 1, "timer fires on next tick", 1, due.len());
        for waker in due {
            waker.wake();
        }
        let count = counter.load(Ordering::SeqCst);
        crate::assert_with_log!(count == 1, "waker fired once", 1, count);

        crate::test_complete!("intrusive_wheel_rebuckets_nonexpired_timer_from_retired_slot");
    }

    #[test]
    fn intrusive_wheel_rebuckets_survivor_after_full_rotation_advance() {
        init_test("intrusive_wheel_rebuckets_survivor_after_full_rotation_advance");

        let base = Instant::now();
        let mut wheel: TimerWheel<4> = TimerWheel::new_at(Duration::from_millis(10), base);
        let counter = Arc::new(AtomicU64::new(0));

        let mut node = Box::pin(TimerNode::new());
        let deadline = base + Duration::from_millis(45);
        let waker = counter_waker(counter.clone());

        unsafe {
            wheel.insert(node.as_mut(), deadline, waker);
        }

        let early = unsafe { wheel.advance_to(base + Duration::from_millis(40)) };
        crate::assert_with_log!(
            early.is_empty(),
            "full-rotation advance must not fire future timer early",
            true,
            early.is_empty()
        );
        crate::assert_with_log!(
            node.is_linked(),
            "future timer stays scheduled after full rotation",
            true,
            node.is_linked()
        );

        let due = unsafe { wheel.advance_to(base + Duration::from_millis(50)) };
        crate::assert_with_log!(
            due.len() == 1,
            "future timer fires after rebucketing from full rotation",
            1,
            due.len()
        );
        for waker in due {
            waker.wake();
        }
        let count = counter.load(Ordering::SeqCst);
        crate::assert_with_log!(count == 1, "waker fired once", 1, count);

        crate::test_complete!("intrusive_wheel_rebuckets_survivor_after_full_rotation_advance");
    }

    #[test]
    fn hierarchical_cascade_fires_expired() {
        init_test("hierarchical_cascade_fires_expired");
        let base = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .unwrap_or_else(Instant::now);
        let mut wheel = HierarchicalTimerWheel::new_at(Duration::from_millis(1), base);
        let counter = Arc::new(AtomicU64::new(0));

        let mut node = Box::pin(TimerNode::new());
        let deadline = base + Duration::from_millis(300);
        let waker = counter_waker(counter.clone());

        unsafe {
            wheel.insert(node.as_mut(), deadline, waker);
        }

        let (level, slot) = wheel.slot_for(deadline);
        crate::assert_with_log!(level == 1, "timer placed in level1", 1u8, level);

        let mut wakers = Vec::new();
        for _ in 0..(LEVEL0_SLOTS * (slot + 1)) {
            let mut tick_wakers = unsafe { wheel.tick(Instant::now()) };
            wakers.append(&mut tick_wakers);
        }

        for waker in wakers {
            waker.wake();
        }

        let count = counter.load(Ordering::SeqCst);
        crate::assert_with_log!(count == 1, "expired fired", 1, count);
        crate::assert_with_log!(wheel.is_empty(), "wheel empty", true, wheel.is_empty());
        crate::test_complete!("hierarchical_cascade_fires_expired");
    }

    #[test]
    fn hierarchical_next_expiration_uses_wheel_time_not_wall_clock() {
        init_test("hierarchical_next_expiration_uses_wheel_time_not_wall_clock");

        let base = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .unwrap_or_else(Instant::now);
        let mut wheel = HierarchicalTimerWheel::new_at(Duration::from_millis(1), base);

        let mut node = Box::pin(TimerNode::new());
        let deadline = base + Duration::from_millis(100);
        let waker = Arc::new(CounterWaker {
            counter: Arc::new(AtomicU64::new(0)),
        })
        .into();

        unsafe {
            wheel.insert(node.as_mut(), deadline, waker);
        }

        let next = wheel.next_expiration();
        crate::assert_with_log!(
            next == Some(Duration::from_millis(100)),
            "hierarchical next expiration is relative to wheel progress, not ambient wall clock",
            Some(Duration::from_millis(100)),
            next
        );

        unsafe {
            wheel.cancel(node.as_mut());
        }

        crate::test_complete!("hierarchical_next_expiration_uses_wheel_time_not_wall_clock");
    }

    #[test]
    fn hierarchical_wheel_rebuckets_nonexpired_level0_timer_from_retired_slot() {
        init_test("hierarchical_wheel_rebuckets_nonexpired_level0_timer_from_retired_slot");

        let base = Instant::now();
        let mut wheel = HierarchicalTimerWheel::new_at(Duration::from_millis(1), base);
        let counter = Arc::new(AtomicU64::new(0));

        let mut node = Box::pin(TimerNode::new());
        let deadline = base + Duration::from_micros(5_500);
        let waker = counter_waker(counter.clone());

        unsafe {
            wheel.insert(node.as_mut(), deadline, waker);
        }

        let early = unsafe { wheel.advance_to(base + Duration::from_millis(5)) };
        crate::assert_with_log!(
            early.is_empty(),
            "hierarchical wheel must not fire later-in-bucket timers early",
            true,
            early.is_empty()
        );
        crate::assert_with_log!(
            node.is_linked(),
            "timer stays scheduled",
            true,
            node.is_linked()
        );

        let due = unsafe { wheel.advance_to(base + Duration::from_millis(6)) };
        crate::assert_with_log!(due.len() == 1, "timer fires on next tick", 1, due.len());
        for waker in due {
            waker.wake();
        }
        let count = counter.load(Ordering::SeqCst);
        crate::assert_with_log!(count == 1, "waker fired once", 1, count);

        crate::test_complete!(
            "hierarchical_wheel_rebuckets_nonexpired_level0_timer_from_retired_slot"
        );
    }

    #[test]
    fn hierarchical_wheel_cascade_survivor_reinserts_without_extra_tick_delay() {
        init_test("hierarchical_wheel_cascade_survivor_reinserts_without_extra_tick_delay");

        let base = Instant::now();
        let mut wheel = HierarchicalTimerWheel::new_at(Duration::from_millis(1), base);
        let counter = Arc::new(AtomicU64::new(0));

        let mut node = Box::pin(TimerNode::new());
        let deadline = base + Duration::from_micros(256_500);
        let waker = counter_waker(counter.clone());

        unsafe {
            wheel.insert(node.as_mut(), deadline, waker);
        }

        let before_due = unsafe { wheel.advance_to(base + Duration::from_millis(256)) };
        crate::assert_with_log!(
            before_due.is_empty(),
            "cascade boundary must not fire timer early",
            true,
            before_due.is_empty()
        );
        crate::assert_with_log!(
            node.is_linked(),
            "timer remains scheduled after cascade rebucketing",
            true,
            node.is_linked()
        );

        let due = unsafe { wheel.advance_to(base + Duration::from_millis(257)) };
        crate::assert_with_log!(
            due.len() == 1,
            "timer fires on the immediate next tick after cascade",
            1,
            due.len()
        );
        for waker in due {
            waker.wake();
        }

        let count = counter.load(Ordering::SeqCst);
        crate::assert_with_log!(count == 1, "waker fired exactly once", 1, count);
        crate::assert_with_log!(
            wheel.is_empty(),
            "wheel is empty after firing",
            true,
            wheel.is_empty()
        );

        crate::test_complete!(
            "hierarchical_wheel_cascade_survivor_reinserts_without_extra_tick_delay"
        );
    }

    proptest! {
        #[test]
        fn metamorphic_intrusive_wheel_cancelled_subset_matches_filtered_rotation(
            entries in prop::collection::vec((1u16..96u16, any::<bool>()), 1..12),
            raw_shift in 0usize..32,
        ) {
            let mut rotated_order: Vec<usize> = (0..entries.len()).collect();
            rotated_order.rotate_left(raw_shift % entries.len());

            let base_signature =
                intrusive_wheel_signature::<16>(&entries, &rotated_order, true);
            let filtered_signature =
                intrusive_wheel_signature::<16>(&entries, &rotated_order, false);

            let survivor_count = entries.iter().filter(|(_, cancelled)| !cancelled).count();

            prop_assert_eq!(
                base_signature.0,
                filtered_signature.0,
                "cancelling a subset after insertion must preserve the next expiration of surviving timers",
            );
            prop_assert_eq!(
                base_signature.1,
                survivor_count,
                "exactly the uncancelled timers should fire",
            );
            prop_assert_eq!(
                filtered_signature.1,
                survivor_count,
                "filtered insertion should fire the same surviving timers",
            );
            prop_assert_eq!(
                base_signature.1,
                filtered_signature.1,
                "post-insert cancellation must match excluding the same timers up front",
            );
            prop_assert_eq!(
                base_signature.2,
                0,
                "no timer nodes should remain linked after advancing past all survivors",
            );
            prop_assert_eq!(
                filtered_signature.2,
                0,
                "filtered run must also drain all timer nodes",
            );
            prop_assert!(
                base_signature.3 && filtered_signature.3,
                "both wheels should be empty after draining surviving timers",
            );
        }

        #[test]
        fn metamorphic_intrusive_wheel_split_advance_matches_direct_frontier(
            offsets in prop::collection::vec(1u16..96u16, 1..12),
            raw_split_ms in 0u16..96u16,
        ) {
            let base = Instant::now();
            let mut split_wheel: TimerWheel<16> = TimerWheel::new_at(Duration::from_millis(1), base);
            let mut direct_wheel: TimerWheel<16> = TimerWheel::new_at(Duration::from_millis(1), base);
            let counter = Arc::new(AtomicU64::new(0));
            let mut split_nodes: Vec<Pin<Box<TimerNode>>> =
                (0..offsets.len()).map(|_| Box::pin(TimerNode::new())).collect();
            let mut direct_nodes: Vec<Pin<Box<TimerNode>>> =
                (0..offsets.len()).map(|_| Box::pin(TimerNode::new())).collect();

            for (index, offset_ms) in offsets.iter().copied().enumerate() {
                let deadline = base + Duration::from_millis(u64::from(offset_ms));
                unsafe {
                    split_wheel.insert(
                        split_nodes[index].as_mut(),
                        deadline,
                        counter_waker(counter.clone()),
                    );
                    direct_wheel.insert(
                        direct_nodes[index].as_mut(),
                        deadline,
                        counter_waker(counter.clone()),
                    );
                }
            }

            let max_offset_ms = offsets.iter().copied().max().unwrap_or(0);
            let split_ms = raw_split_ms.min(max_offset_ms);
            let early_target = base + Duration::from_millis(u64::from(split_ms));
            let late_target = base + Duration::from_millis(u64::from(max_offset_ms) + 2);

            let early_wakers = unsafe { split_wheel.advance_to(early_target) };
            let late_wakers = unsafe { split_wheel.advance_to(late_target) };
            let direct_wakers = unsafe { direct_wheel.advance_to(late_target) };

            prop_assert!(
                early_wakers.len() <= direct_wakers.len(),
                "an earlier frontier cannot fire more timers than the later direct frontier",
            );
            prop_assert_eq!(
                early_wakers.len() + late_wakers.len(),
                direct_wakers.len(),
                "splitting the advance must preserve the total timers fired by the final frontier",
            );
            prop_assert!(
                split_wheel.is_empty() && direct_wheel.is_empty(),
                "both wheels should be empty after advancing past the latest deadline",
            );
            prop_assert_eq!(
                split_nodes.iter().filter(|node| node.is_linked()).count(),
                0,
                "split advance must unlink every timer node",
            );
            prop_assert_eq!(
                direct_nodes.iter().filter(|node| node.is_linked()).count(),
                0,
                "direct advance must unlink every timer node",
            );
        }
    }
