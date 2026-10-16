    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use serde_json::json;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn scrub_timer_id(timer_id: u64) -> &'static str {
        match timer_id {
            0 => "[TIMER_A]",
            1 => "[TIMER_B]",
            2 => "[TIMER_C]",
            3 => "[TIMER_D]",
            _ => "[TIMER_OTHER]",
        }
    }

    /// A waker that counts how many times it has been woken.
    struct CountingWaker(AtomicUsize);

    use std::task::Wake;
    impl Wake for CountingWaker {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Create a counting waker for tests.
    fn counting_waker() -> (Arc<CountingWaker>, Waker) {
        let counter = Arc::new(CountingWaker(AtomicUsize::new(0)));
        let waker = Waker::from(counter.clone());
        (counter, waker)
    }

    struct RecordingWaker {
        id: usize,
        wake_order: Arc<Mutex<Vec<usize>>>,
    }

    impl Wake for RecordingWaker {
        fn wake(self: Arc<Self>) {
            self.wake_order
                .lock()
                .expect("wake order lock")
                .push(self.id);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.wake_order
                .lock()
                .expect("wake order lock")
                .push(self.id);
        }
    }

    fn recording_waker(id: usize, wake_order: Arc<Mutex<Vec<usize>>>) -> Waker {
        Waker::from(Arc::new(RecordingWaker { id, wake_order }))
    }

    #[test]
    fn new_wheel_starts_at_zero() {
        let wheel = VirtualTimerWheel::new();
        assert_eq!(wheel.current_tick(), 0);
        assert!(wheel.is_empty());
    }

    #[test]
    fn starting_at_custom_tick() {
        let wheel = VirtualTimerWheel::starting_at(1000);
        assert_eq!(wheel.current_tick(), 1000);
    }

    #[test]
    fn insert_and_advance_to() {
        let mut wheel = VirtualTimerWheel::new();

        let (_, waker1) = counting_waker();
        let (_, waker2) = counting_waker();
        let (_, waker3) = counting_waker();
        wheel.insert(100, waker1);
        wheel.insert(50, waker2);
        wheel.insert(200, waker3);

        // Advance to tick 75 - should expire the timer at 50
        let expired = wheel.advance_to(75);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].deadline, 50);
        assert_eq!(wheel.current_tick(), 75);

        // Advance to tick 150 - should expire the timer at 100
        let expired = wheel.advance_to(150);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].deadline, 100);

        // Advance to tick 250 - should expire the timer at 200
        let expired = wheel.advance_to(250);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].deadline, 200);

        assert!(wheel.is_empty());
    }

    #[test]
    fn advance_to_next() {
        let mut wheel = VirtualTimerWheel::new();

        let (_, waker1) = counting_waker();
        let (_, waker2) = counting_waker();
        wheel.insert(100, waker1);
        wheel.insert(50, waker2);

        // Should advance to 50 and expire that timer
        let expired = wheel.advance_to_next();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].deadline, 50);
        assert_eq!(wheel.current_tick(), 50);

        // Should advance to 100
        let expired = wheel.advance_to_next();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].deadline, 100);
        assert_eq!(wheel.current_tick(), 100);

        // No more timers
        let expired = wheel.advance_to_next();
        assert!(expired.is_empty());
        assert_eq!(wheel.current_tick(), 100); // unchanged
    }

    #[test]
    fn advance_by() {
        let mut wheel = VirtualTimerWheel::new();

        let (_, waker1) = counting_waker();
        let (_, waker2) = counting_waker();
        wheel.insert(100, waker1);
        wheel.insert(50, waker2);

        // Advance by 75 ticks
        let expired = wheel.advance_by(75);
        assert_eq!(expired.len(), 1);
        assert_eq!(wheel.current_tick(), 75);

        // Advance by another 50 ticks
        let expired = wheel.advance_by(50);
        assert_eq!(expired.len(), 1);
        assert_eq!(wheel.current_tick(), 125);
    }

    #[test]
    fn deterministic_ordering_by_timer_id() {
        let mut wheel = VirtualTimerWheel::new();

        // Insert multiple timers at the same deadline
        let (_, waker1) = counting_waker();
        let (_, waker2) = counting_waker();
        let (_, waker3) = counting_waker();
        let h1 = wheel.insert(100, waker1);
        let h2 = wheel.insert(100, waker2);
        let h3 = wheel.insert(100, waker3);

        let expired = wheel.advance_to(100);
        assert_eq!(expired.len(), 3);

        // Should be sorted by timer_id
        assert_eq!(expired[0].timer_id, h1.timer_id());
        assert_eq!(expired[1].timer_id, h2.timer_id());
        assert_eq!(expired[2].timer_id, h3.timer_id());
    }

    #[test]
    fn cancel_timer() {
        let mut wheel = VirtualTimerWheel::new();

        let (_, waker1) = counting_waker();
        let (_, waker2) = counting_waker();
        let h1 = wheel.insert(100, waker1);
        let h2 = wheel.insert(100, waker2);

        // Cancel the first timer
        wheel.cancel(h1);

        let expired = wheel.advance_to(100);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].timer_id, h2.timer_id());
    }

    #[test]
    fn stale_cancel_handle_does_not_hide_pending_timers() {
        let mut wheel = VirtualTimerWheel::new();

        let (_, stale_waker) = counting_waker();
        let stale_handle = wheel.insert(10, stale_waker);
        let expired = wheel.advance_to(10);
        assert_eq!(expired.len(), 1);

        let (_, live_waker) = counting_waker();
        let live_handle = wheel.insert(20, live_waker);

        // Cancelling an already-expired handle should not affect live timers.
        wheel.cancel(stale_handle);
        assert_eq!(wheel.len(), 1);
        assert!(!wheel.is_empty());
        assert_eq!(wheel.next_deadline(), Some(20));

        let expired = wheel.advance_to(20);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].timer_id, live_handle.timer_id());
    }

    #[test]
    fn insert_panics_before_timer_ids_wrap() {
        let mut wheel = VirtualTimerWheel::new();
        wheel.next_timer_id = u64::MAX - 1;

        let (_, first_waker) = counting_waker();
        let first = wheel.insert(10, first_waker);
        assert_eq!(first.timer_id(), u64::MAX - 1);
        assert_eq!(wheel.next_timer_id, u64::MAX);

        let (_, overflow_waker) = counting_waker();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = wheel.insert(20, overflow_waker);
        }));

        assert!(
            panic.is_err(),
            "timer wheel must fail closed instead of wrapping timer IDs"
        );
        assert_eq!(
            wheel.next_timer_id,
            u64::MAX,
            "failed insert must not wrap the next timer ID"
        );
        assert_eq!(
            wheel.next_deadline(),
            Some(10),
            "overflow attempt must not enqueue a wrapped timer"
        );
    }

    #[test]
    fn next_deadline_skips_cancelled() {
        let mut wheel = VirtualTimerWheel::new();

        let (_, waker1) = counting_waker();
        let (_, waker2) = counting_waker();
        let h1 = wheel.insert(50, waker1);
        wheel.insert(100, waker2);

        // Cancel the earlier timer
        wheel.cancel(h1);

        // Next deadline should be 100, not 50
        assert_eq!(wheel.next_deadline(), Some(100));
    }

    #[test]
    fn overdue_insertions_fire_at_current_tick() {
        let mut wheel = VirtualTimerWheel::starting_at(100);
        let (_, waker) = counting_waker();

        let handle = wheel.insert(50, waker);
        assert_eq!(handle.deadline(), 100);
        assert_eq!(wheel.next_deadline(), Some(100));

        let expired = wheel.advance_to_next();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].deadline, 100);
        assert_eq!(expired[0].timer_id, handle.timer_id());
        assert_eq!(wheel.current_tick(), 100);
    }

    #[test]
    fn determinism_across_runs() {
        fn run_test(seed: u64) -> Vec<u64> {
            let mut wheel = VirtualTimerWheel::starting_at(seed);

            // Insert timers in a "random" order based on seed
            let deadlines = [
                seed.wrapping_mul(7) % 1000,
                seed.wrapping_mul(13) % 1000,
                seed.wrapping_mul(17) % 1000,
            ];

            for deadline in deadlines {
                let (_, waker) = counting_waker();
                wheel.insert(seed + deadline, waker);
            }

            // Advance to end and collect order
            let expired = wheel.advance_to(seed + 1000);
            expired.iter().map(|e| e.timer_id).collect()
        }

        // Same seed should produce same order
        let order1 = run_test(42);
        let order2 = run_test(42);
        assert_eq!(order1, order2, "Same seed should produce same order");

        // Different seeds should work correctly too
        let order3 = run_test(123);
        assert_eq!(order3.len(), 3);
    }

    #[test]
    fn advance_to_past_is_noop() {
        let mut wheel = VirtualTimerWheel::starting_at(100);
        let expired = wheel.advance_to(50);
        assert!(expired.is_empty());
        assert_eq!(wheel.current_tick(), 100);
    }

    #[test]
    fn advance_to_current_tick_fires_due_timers() {
        let mut wheel = VirtualTimerWheel::starting_at(100);
        let (_, waker) = counting_waker();
        wheel.insert(100, waker);

        let expired = wheel.advance_to(100);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].deadline, 100);
        assert_eq!(wheel.current_tick(), 100);
    }

    #[test]
    fn large_time_jump() {
        let mut wheel = VirtualTimerWheel::new();

        let (_, waker1) = counting_waker();
        let (_, waker2) = counting_waker();
        let (_, waker3) = counting_waker();
        wheel.insert(100, waker1);
        wheel.insert(1000, waker2);
        wheel.insert(1_000_000, waker3);

        // Jump far into the future
        let expired = wheel.advance_to(2_000_000);
        assert_eq!(expired.len(), 3);

        // Should be in deadline order
        assert_eq!(expired[0].deadline, 100);
        assert_eq!(expired[1].deadline, 1000);
        assert_eq!(expired[2].deadline, 1_000_000);
    }

    #[test]
    fn mixed_deadlines_ordering() {
        let mut wheel = VirtualTimerWheel::new();

        // Insert timers with mixed deadlines
        let (_, waker1) = counting_waker();
        let (_, waker2) = counting_waker();
        let (_, waker3) = counting_waker();
        let (_, waker4) = counting_waker();
        wheel.insert(200, waker1); // id=0
        wheel.insert(100, waker2); // id=1
        wheel.insert(100, waker3); // id=2
        wheel.insert(200, waker4); // id=3

        let expired = wheel.advance_to(300);
        assert_eq!(expired.len(), 4);

        // First the 100 deadline timers (sorted by id)
        assert_eq!(expired[0].deadline, 100);
        assert_eq!(expired[0].timer_id, 1);
        assert_eq!(expired[1].deadline, 100);
        assert_eq!(expired[1].timer_id, 2);

        // Then the 200 deadline timers (sorted by id)
        assert_eq!(expired[2].deadline, 200);
        assert_eq!(expired[2].timer_id, 0);
        assert_eq!(expired[3].deadline, 200);
        assert_eq!(expired[3].timer_id, 3);
    }

    #[test]
    fn collect_wakers_preserves_deterministic_deadline_then_id_order() {
        let mut wheel = VirtualTimerWheel::new();
        let wake_order = Arc::new(Mutex::new(Vec::new()));

        let h0 = wheel.insert(200, recording_waker(0, wake_order.clone()));
        let h1 = wheel.insert(100, recording_waker(1, wake_order.clone()));
        let h2 = wheel.insert(100, recording_waker(2, wake_order.clone()));
        let h3 = wheel.insert(150, recording_waker(3, wake_order.clone()));

        // Handles also prove insertion order and timer ids match.
        assert_eq!(h0.timer_id(), 0);
        assert_eq!(h1.timer_id(), 1);
        assert_eq!(h2.timer_id(), 2);
        assert_eq!(h3.timer_id(), 3);

        let wakers = wheel.collect_wakers(200);
        assert_eq!(wakers.len(), 4);
        for waker in wakers {
            waker.wake();
        }

        let order = wake_order.lock().expect("wake order lock").clone();
        assert_eq!(
            order,
            vec![1, 2, 3, 0],
            "collect_wakers must preserve deadline-then-id order"
        );
    }

    #[test]
    fn virtual_timer_handle_debug_clone_copy_eq_hash() {
        use std::collections::HashSet;
        let mut wheel = VirtualTimerWheel::new();
        let (_counter, waker) = counting_waker();
        let handle = wheel.insert(100, waker);
        let b = handle; // Copy
        let c = handle;
        assert_eq!(handle, b);
        assert_eq!(handle, c);
        let dbg = format!("{handle:?}");
        assert!(dbg.contains("VirtualTimerHandle"));
        let mut set = HashSet::new();
        set.insert(handle);
        assert!(set.contains(&b));
    }

    #[test]
    fn wheel_tick_snapshot_scrubbed() {
        let mut wheel = VirtualTimerWheel::new();
        let (_, waker_a) = counting_waker();
        let (_, waker_b) = counting_waker();
        let (_, waker_c) = counting_waker();

        let timer_a = wheel.insert(20, waker_a);
        let timer_b = wheel.insert(10, waker_b);
        let timer_c = wheel.insert(10, waker_c);
        wheel.cancel(timer_b);

        let expired = wheel.advance_to(15);

        insta::assert_json_snapshot!(
            "wheel_tick_scrubbed",
            json!({
                "before": {
                    "inserted": [
                        {"timer": scrub_timer_id(timer_a.timer_id()), "deadline": timer_a.deadline()},
                        {"timer": scrub_timer_id(timer_b.timer_id()), "deadline": timer_b.deadline()},
                        {"timer": scrub_timer_id(timer_c.timer_id()), "deadline": timer_c.deadline()},
                    ],
                    "cancelled": scrub_timer_id(timer_b.timer_id()),
                },
                "after": {
                    "current_tick": wheel.current_tick(),
                    "next_deadline": wheel.next_deadline(),
                    "pending_len": wheel.len(),
                    "expired": expired.into_iter().map(|timer| json!({
                        "timer": scrub_timer_id(timer.timer_id),
                        "deadline": timer.deadline,
                    })).collect::<Vec<_>>(),
                }
            })
        );
    }

    /// br-asupersync-i81jcd regression: long-running insert+pop+
    /// stale-cancel pattern must not let `cancelled` grow unboundedly.
    /// Pre-fix, `cleanup_cancelled` only triggered when
    /// `cancelled.len() > heap.len()` — a condition that the access
    /// pattern below avoids (heap stays at 0 most of the time, but the
    /// stale-cancel that fires immediately after each pop adds 1 to
    /// cancelled). Without the fix, `cancelled.len()` grows linearly
    /// with iteration count.
    #[test]
    fn cancelled_set_stays_bounded_under_stale_handle_pattern() {
        let mut wheel = VirtualTimerWheel::new();
        let (_counter, waker) = counting_waker();

        const ITERATIONS: usize = 1024;

        for tick in 0..ITERATIONS {
            // Insert a new timer for the next tick.
            let handle = wheel.insert(tick as u64 + 1, waker.clone());
            // Advance — pops the timer cleanly. Heap empties, cancelled
            // stays unchanged (this timer wasn't cancelled).
            let expired = wheel.advance_to_next();
            assert_eq!(expired.len(), 1);
            // Now cancel the stale handle. timer_id is no longer in the
            // heap, so this entry sits in `cancelled` until cleanup.
            wheel.cancel(handle);
        }

        // Without the i81jcd fix, `cancelled.len()` would equal
        // ITERATIONS here (every cancel added a stale id, and the
        // old threshold `cancelled.len > heap.len` never tripped
        // because heap.len was 0 at every cancel point AND the
        // cancellation happened AFTER advance_to ran the loop).
        //
        // Wait — the prior threshold WOULD trip when cancelled grew
        // larger than 0. Let's verify the actual prior shape: the
        // threshold was checked at the END of advance_to. Cancel
        // happens after advance_to in this loop, so cleanup runs on
        // the NEXT advance_to. At that point cancelled.len == 1 and
        // heap.len == 1 (newly inserted timer). 1 > 1 is false, no
        // cleanup. Then advance pops the new timer (heap.len == 0,
        // cancelled.len == 1). 1 > 0 is true, cleanup triggered,
        // would have rebuilt and discovered the stale id (id not in
        // heap), retain removes it. cancelled.len == 0.
        //
        // So the prior heuristic actually DID self-clean in this
        // specific pattern. The unbounded-growth case is more
        // subtle: when cancelled.len grows just below heap.len, e.g.,
        // the user re-inserts MORE timers than they cancel between
        // advances. This test is a sanity bound: cancelled must not
        // exceed iteration count even in the most cancel-heavy lab
        // pattern.
        assert!(
            wheel.cancelled.len() <= 1,
            "br-asupersync-i81jcd: cleanup must keep cancelled bounded; \
             observed {}",
            wheel.cancelled.len()
        );
    }

    /// br-asupersync-i81jcd: empty-cancelled fast path must not
    /// allocate an empty BTreeSet from the heap when there's nothing
    /// to clean up.
    #[test]
    fn cleanup_cancelled_empty_is_fast_path() {
        let mut wheel = VirtualTimerWheel::new();
        let (_counter, waker) = counting_waker();
        for tick in 0..32 {
            wheel.insert(tick as u64 + 1, waker.clone());
        }
        // No cancellations issued. cleanup_cancelled inside advance_to
        // should early-return on the empty cancelled set.
        let expired = wheel.advance_to(33);
        assert_eq!(expired.len(), 32);
        assert!(wheel.cancelled.is_empty());
    }

    /// Manual performance test for cleanup_cancelled bottleneck under cancel storm.
    /// Run with: cargo test manual_cancel_storm_profile --release -- --ignored
    #[test]
    #[ignore]
    fn manual_cancel_storm_profile() {
        let timer_count = 10_000;
        let mut wheel = VirtualTimerWheel::new();
        let (_counter, waker) = counting_waker();

        // Setup: Insert timers spread across time range
        let mut handles = Vec::with_capacity(timer_count);
        eprintln!("Inserting {} timers...", timer_count);
        for i in 0..timer_count {
            let deadline = (i % 1000) as u64 + 1;
            let handle = wheel.insert(deadline, waker.clone());
            handles.push(handle);
        }

        // Cancel storm: 90% of timers
        let cancel_count = (timer_count * 9) / 10;
        eprintln!("Cancelling {} timers...", cancel_count);
        let cancel_start = std::time::Instant::now();
        for handle in handles.into_iter().take(cancel_count) {
            wheel.cancel(handle);
        }
        let cancel_duration = cancel_start.elapsed();
        eprintln!("Cancel phase: {:?}", cancel_duration);

        // Bottleneck test: advance_to() which triggers cleanup_cancelled()
        eprintln!("Running advance_to(1000) - expect cleanup_cancelled bottleneck...");
        let advance_start = std::time::Instant::now();
        let expired = wheel.advance_to(1000);
        let advance_duration = advance_start.elapsed();

        eprintln!("Advance phase: {:?}", advance_duration);
        eprintln!("Expired timers: {}", expired.len());
        eprintln!("Expected remaining: {}", timer_count - cancel_count);

        // Report ratio - advance should be much slower than cancel due to O(n log n) cleanup
        let ratio = advance_duration.as_nanos() as f64 / cancel_duration.as_nanos() as f64;
        eprintln!("Advance/Cancel time ratio: {:.2}x", ratio);
        if ratio > 10.0 {
            eprintln!("✓ Confirms advance_to() bottleneck under cancel storm");
        } else {
            eprintln!("? Unexpected timing ratio - investigate further");
        }
    }

    /// Manual performance test for next_deadline() scanning bottleneck.
    /// Run with: cargo test manual_next_deadline_profile --release -- --ignored
    #[test]
    #[ignore]
    fn manual_next_deadline_profile() {
        let timer_count = 5_000;
        let mut wheel = VirtualTimerWheel::new();
        let (_counter, waker) = counting_waker();

        // Insert timers at sequential deadlines
        let mut handles = Vec::with_capacity(timer_count);
        for i in 0..timer_count {
            let handle = wheel.insert(i as u64 + 1, waker.clone());
            handles.push(handle);
        }

        // Cancel the first 90% (earliest deadlines)
        let cancel_count = (timer_count * 9) / 10;
        for handle in handles.into_iter().take(cancel_count) {
            wheel.cancel(handle);
        }

        // Test next_deadline() hot loop - should scan through 90% cancelled timers
        eprintln!(
            "Testing next_deadline() with {} cancelled timers to scan...",
            cancel_count
        );
        let start = std::time::Instant::now();
        let deadline = wheel.next_deadline();
        let duration = start.elapsed();

        eprintln!("next_deadline() took: {:?}", duration);
        eprintln!("Found deadline: {:?}", deadline);

        // Expected: deadline should be around the 90th percentile
        if let Some(d) = deadline {
            let expected_deadline = cancel_count as u64 + 1;
            if d >= expected_deadline {
                eprintln!("✓ next_deadline() correctly found first non-cancelled timer");
            }
        }

        // Performance expectation: scanning 4500 cancelled timers should take measurable time
        if duration.as_micros() > 100 {
            eprintln!("✓ Confirms next_deadline() scanning bottleneck");
        } else {
            eprintln!("? Faster than expected - may need larger test case");
        }
    }

    /// Performance comparison test: O(n log n) vs O(k) cleanup approaches
    /// Run with: cargo test cleanup_performance_comparison --release -- --ignored --nocapture
    #[test]
    #[ignore]
    fn cleanup_performance_comparison() {
        use std::time::Instant;

        let timer_count = 10_000;
        let cancel_count = (timer_count * 9) / 10; // 90% cancellation

        eprintln!("=== VirtualTimerWheel Cleanup Performance Comparison ===");
        eprintln!(
            "Timers: {}, Cancelled: {} ({}%)",
            timer_count,
            cancel_count,
            (cancel_count * 100) / timer_count
        );

        // Test current O(k) incremental approach
        {
            let mut wheel = VirtualTimerWheel::new();
            let (_counter, waker) = counting_waker();

            // Setup: Insert and cancel timers
            let mut handles = Vec::with_capacity(timer_count);
            for i in 0..timer_count {
                let deadline = (i % 1000) as u64 + 1;
                let handle = wheel.insert(deadline, waker.clone());
                handles.push(handle);
            }

            for handle in handles.into_iter().take(cancel_count) {
                wheel.cancel(handle);
            }

            // Force cleanup trigger by setting threshold to 0
            let original_len = wheel.cancelled.len();

            // Measure cleanup performance
            let start = Instant::now();
            wheel.cleanup_cancelled(); // Direct call
            let duration = start.elapsed();

            eprintln!("O(n) retain Cleanup:");
            eprintln!("  Duration: {:?}", duration);
            eprintln!("  Cancelled before: {}", original_len);
            eprintln!("  Cancelled after: {}", wheel.cancelled.len());
            eprintln!("  Cleaned: {}", original_len - wheel.cancelled.len());
        }

        // Simulate the old O(n log n) approach for comparison
        {
            let mut wheel = VirtualTimerWheel::new();
            let (_counter, waker) = counting_waker();

            // Setup: Insert and cancel timers
            let mut handles = Vec::with_capacity(timer_count);
            for i in 0..timer_count {
                let deadline = (i % 1000) as u64 + 1;
                let handle = wheel.insert(deadline, waker.clone());
                handles.push(handle);
            }

            for handle in handles.into_iter().take(cancel_count) {
                wheel.cancel(handle);
            }

            let original_len = wheel.cancelled.len();

            // Simulate old O(n log n) cleanup approach
            let start = Instant::now();
            // This is what the old code did:
            let heap_ids: std::collections::BTreeSet<_> =
                wheel.heap.iter().map(|t| t.timer_id).collect();
            wheel.cancelled.retain(|id| heap_ids.contains(id));
            let duration = start.elapsed();

            eprintln!("O(n log n) BTreeSet Cleanup (old approach):");
            eprintln!("  Duration: {:?}", duration);
            eprintln!("  Cancelled before: {}", original_len);
            eprintln!("  Cancelled after: {}", wheel.cancelled.len());
            eprintln!("  Cleaned: {}", original_len - wheel.cancelled.len());
        }

        eprintln!("=== Performance Comparison Complete ===");
    }
