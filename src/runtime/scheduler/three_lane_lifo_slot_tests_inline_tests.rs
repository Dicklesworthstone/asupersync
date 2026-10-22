    use super::*;
    use crate::channel::mpsc;
    use crate::runtime::RuntimeBuilder;
    use std::sync::atomic::AtomicBool;

    /// br-asupersync-issue65-criticisms-kpmoy5.1.11: a task woken by the task
    /// a worker is executing goes to that worker's LIFO slot, and a ping-pong
    /// over capacity-1 channels still delivers every message.
    #[test]
    fn a_task_woken_by_the_executing_task_goes_to_the_lifo_slot() {
        let before = LIFO_SLOT_WAKES.load(Ordering::Relaxed);
        let rt = RuntimeBuilder::new()
            .worker_threads(4)
            .build()
            .expect("four-worker runtime");
        let total = rt.block_on(rt.handle().spawn(async move {
            let cx = crate::Cx::current().expect("a spawned task has a Cx");
            let (ping_tx, mut ping_rx) = mpsc::channel::<u32>(1);
            let (pong_tx, mut pong_rx) = mpsc::channel::<u32>(1);
            let mut echo = cx
                .spawn(move |cx| async move {
                    while let Ok(value) = ping_rx.recv(&cx).await {
                        if pong_tx.send(&cx, value + 1).await.is_err() {
                            break;
                        }
                    }
                })
                .expect("spawn the echo task");
            let mut total = 0u32;
            for value in 0..1000u32 {
                ping_tx.send(&cx, value).await.expect("ping");
                total += pong_rx.recv(&cx).await.expect("pong");
            }
            drop(ping_tx);
            let _ = echo.join(&cx).await;
            total
        }));
        assert_eq!(total, (1..=1000u32).sum::<u32>(), "every message answered");
        let placed = LIFO_SLOT_WAKES.load(Ordering::Relaxed) - before;
        assert!(placed > 0, "no wake went to a LIFO slot");
    }

    /// Two tasks that wake each other forever on a one-worker runtime keep
    /// refilling the worker's LIFO slot. The bound on consecutive slot
    /// dispatches must still let a third ready task run.
    #[test]
    fn a_chain_of_tasks_waking_each_other_cannot_starve_other_ready_work() {
        let (ran_tx, ran_rx) = std::sync::mpsc::channel::<()>();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_chain = Arc::clone(&stop);
        // The runtime runs on its own thread, so a starved task fails this
        // test by timeout instead of hanging it.
        std::thread::spawn(move || {
            let rt = RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("one-worker runtime");
            rt.block_on(rt.handle().spawn(async move {
                let cx = crate::Cx::current().expect("a spawned task has a Cx");
                let (ping_tx, mut ping_rx) = mpsc::channel::<u32>(1);
                let (pong_tx, mut pong_rx) = mpsc::channel::<u32>(1);
                let mut first = cx
                    .spawn(move |cx| async move {
                        while !stop_chain.load(Ordering::Acquire) {
                            if ping_tx.send(&cx, 1).await.is_err() {
                                break;
                            }
                            if pong_rx.recv(&cx).await.is_err() {
                                break;
                            }
                        }
                    })
                    .expect("spawn the first chain task");
                let mut second = cx
                    .spawn(move |cx| async move {
                        while let Ok(value) = ping_rx.recv(&cx).await {
                            if pong_tx.send(&cx, value).await.is_err() {
                                break;
                            }
                        }
                    })
                    .expect("spawn the second chain task");
                let mut other = cx
                    .spawn(move |_| async move {
                        let _ = ran_tx.send(());
                    })
                    .expect("spawn the other task");
                let _ = other.join(&cx).await;
                let _ = first.join(&cx).await;
                let _ = second.join(&cx).await;
            }));
        });
        let ran = ran_rx.recv_timeout(Duration::from_secs(10));
        stop.store(true, Ordering::Release);
        assert!(
            ran.is_ok(),
            "a task outside the waking chain never ran: the LIFO slot starved it"
        );
    }

    /// GitHub #84: on two workers, B waits on a channel. A sends to it, which
    /// puts B in the LIFO slot of A's worker, and then keeps polling (CPU work
    /// with no await). That worker reaches its slot only when A's poll
    /// returns, so the idle worker must run B while A is still polling.
    #[test]
    fn a_task_woken_by_a_long_poll_runs_on_an_idle_worker_during_that_poll() {
        const POLL_LIMIT: Duration = Duration::from_secs(10);
        let rt = RuntimeBuilder::new()
            .worker_threads(2)
            .build()
            .expect("two-worker runtime");
        let (tx, mut rx) = mpsc::channel::<()>(1);
        let (started_tx, started_rx) = std::sync::mpsc::channel::<TaskId>();
        let b_ran = Arc::new(AtomicBool::new(false));
        let b_ran_in_b = Arc::clone(&b_ran);
        let _b = rt.handle().spawn(async move {
            let cx = crate::Cx::current().expect("a spawned task has a Cx");
            let _ = started_tx.send(cx.task_id());
            rx.recv(&cx).await.expect("a sends");
            b_ran_in_b.store(true, Ordering::Release);
        });
        let b_id = started_rx.recv_timeout(POLL_LIMIT).expect("b starts");
        // Let B's worker finish the poll that parks B in `recv`. A send that
        // raced that poll would be re-queued by B's own worker instead of
        // going to the slot, which the `placed` check below would catch.
        std::thread::sleep(Duration::from_millis(100));

        let (placed, ran_during_poll, polled_for) = rt.block_on(rt.handle().spawn(async move {
            let _ = take_lifo_placed_here();
            tx.try_send(()).expect("wake b");
            let placed = take_lifo_placed_here();
            let started = std::time::Instant::now();
            while !b_ran.load(Ordering::Acquire) && started.elapsed() < POLL_LIMIT {
                std::hint::spin_loop();
            }
            (placed, b_ran.load(Ordering::Acquire), started.elapsed())
        }));
        assert_eq!(
            placed,
            Some(b_id),
            "the send did not put b in the LIFO slot of a's worker"
        );
        assert!(
            ran_during_poll,
            "b waited for a's whole poll ({polled_for:?}) while the other worker was idle"
        );
    }

    /// GitHub #84: a ping-pong on four workers in which both sides sometimes
    /// keep polling for 20 ms after a wake, longer than two of the longest
    /// watch intervals, so the watcher takes some woken tasks from a slot
    /// while the slot's owner takes the rest. Every message is still answered
    /// exactly once and in order, and the run ends.
    #[test]
    fn a_ping_pong_with_long_polls_after_wakes_answers_every_message_in_order() {
        const ROUNDS: u32 = 400;
        fn spin(duration: Duration) {
            let started = std::time::Instant::now();
            while started.elapsed() < duration {
                std::hint::spin_loop();
            }
        }
        let takes_before = LIFO_WATCH_TAKES.load(Ordering::Relaxed);
        let rt = RuntimeBuilder::new()
            .worker_threads(4)
            .build()
            .expect("four-worker runtime");
        let answered = rt.block_on(rt.handle().spawn(async move {
            let cx = crate::Cx::current().expect("a spawned task has a Cx");
            let (ping_tx, mut ping_rx) = mpsc::channel::<u32>(1);
            let (pong_tx, mut pong_rx) = mpsc::channel::<u32>(1);
            let mut echo = cx
                .spawn(move |cx| async move {
                    while let Ok(value) = ping_rx.recv(&cx).await {
                        if pong_tx.send(&cx, value).await.is_err() {
                            break;
                        }
                        if value % 20 == 0 {
                            spin(Duration::from_millis(20));
                        }
                    }
                })
                .expect("spawn the echo task");
            let mut answered = 0u32;
            for value in 0..ROUNDS {
                ping_tx.send(&cx, value).await.expect("ping");
                if value % 20 == 10 {
                    spin(Duration::from_millis(20));
                }
                let pong = pong_rx.recv(&cx).await.expect("pong");
                assert_eq!(pong, value, "a ping was answered out of order or twice");
                answered += 1;
            }
            drop(ping_tx);
            let _ = echo.join(&cx).await;
            answered
        }));
        assert_eq!(answered, ROUNDS, "every ping answered");
        // Supplemental: the counter is process-wide, so this only shows that
        // the watcher path ran, not how often it ran for this runtime.
        assert!(
            LIFO_WATCH_TAKES.load(Ordering::Relaxed) > takes_before,
            "the watcher never took a task from a slot"
        );
    }

    fn lifo_test_coordinator(workers: usize) -> Arc<WorkerCoordinator> {
        Arc::new(WorkerCoordinator::new(
            (0..workers).map(|_| Parker::new()).collect(),
            None,
        ))
    }

    fn lifo_watch_state(coordinator: &WorkerCoordinator) -> u8 {
        coordinator.lifo_watch.load(Ordering::SeqCst)
    }

    fn a_parker_was_woken(coordinator: &WorkerCoordinator) -> bool {
        coordinator
            .parkers
            .iter()
            .any(Parker::notification_pending_for_test)
    }

    /// GitHub #84, the protocol without threads or timing: a wake that fills
    /// a slot while a loop is idle requests a watch and wakes a worker. The
    /// idle loop takes the role, and once B has stayed in the slot for a
    /// whole interval with its owner in the same poll, the watcher empties
    /// the slot and the owner finds it empty, so B runs exactly once.
    #[test]
    fn the_watcher_takes_a_task_left_in_a_slot_for_a_whole_owner_poll() {
        let coordinator = lifo_test_coordinator(2);
        let (a, b) = (TaskId::new_for_test(1, 1), TaskId::new_for_test(2, 1));
        let mut idle = LifoIdle::new(Arc::clone(&coordinator), 1);
        idle.enter();
        assert!(!idle.must_look(), "nothing to watch yet");

        let executing = ExecutingTask::enter(&coordinator, 0, a);
        assert!(matches!(
            claim_lifo_wake(&coordinator, b, 5),
            LifoWake::Placed
        ));
        assert_eq!(lifo_watch_state(&coordinator), LIFO_WATCH_REQUESTED);
        assert!(a_parker_was_woken(&coordinator), "the request woke nobody");
        assert!(idle.must_look(), "the idle loop must answer the request");

        assert_eq!(idle.look(0), None, "the first look comes an interval later");
        assert_eq!(lifo_watch_state(&coordinator), LIFO_WATCH_ACTIVE);
        assert_eq!(
            idle.wait_cap(0),
            Some(Duration::from_nanos(LIFO_WATCH_MIN_INTERVAL_NANOS))
        );
        assert_eq!(idle.look(LIFO_WATCH_MIN_INTERVAL_NANOS - 1), None);
        assert_eq!(idle.look(LIFO_WATCH_MIN_INTERVAL_NANOS), Some(b));
        assert_eq!(
            take_lifo_task(&coordinator, 0),
            None,
            "the owner found the task the watcher took"
        );
        drop(executing);

        idle.leave();
        assert_eq!(lifo_watch_state(&coordinator), LIFO_WATCH_NONE);
        assert_eq!(coordinator.idle_workers.load(Ordering::SeqCst), 0);
    }

    /// A slot task whose owner finished the poll that woke it and started
    /// another one is not taken at the next look: the owner may reach it
    /// next, and the watcher looks again after a doubled interval. The task
    /// is taken once it has stayed through that whole later poll.
    #[test]
    fn the_watcher_leaves_a_slot_task_whose_owner_started_another_poll() {
        let coordinator = lifo_test_coordinator(2);
        let (a, b, c) = (
            TaskId::new_for_test(1, 1),
            TaskId::new_for_test(2, 1),
            TaskId::new_for_test(3, 1),
        );
        let mut idle = LifoIdle::new(Arc::clone(&coordinator), 1);
        idle.enter();
        let executing = ExecutingTask::enter(&coordinator, 0, a);
        assert!(matches!(
            claim_lifo_wake(&coordinator, b, 5),
            LifoWake::Placed
        ));
        drop(executing);
        assert_eq!(idle.look(0), None);

        // The owner runs C (say, cancel work) before it reaches its slot.
        let executing = ExecutingTask::enter(&coordinator, 0, c);
        assert_eq!(idle.look(LIFO_WATCH_MIN_INTERVAL_NANOS), None);
        assert_eq!(lifo_watch_state(&coordinator), LIFO_WATCH_ACTIVE);
        assert_eq!(idle.look(2 * LIFO_WATCH_MIN_INTERVAL_NANOS), None);
        assert_eq!(idle.look(3 * LIFO_WATCH_MIN_INTERVAL_NANOS), Some(b));
        drop(executing);
        assert_eq!(take_lifo_task(&coordinator, 0), None);
    }

    /// The watcher gives the role up at the first look that finds every slot
    /// empty, and then blocks without a cap and does not look again.
    #[test]
    fn the_watcher_retires_once_no_slot_holds_a_task() {
        let coordinator = lifo_test_coordinator(2);
        let (a, b) = (TaskId::new_for_test(1, 1), TaskId::new_for_test(2, 1));
        let mut idle = LifoIdle::new(Arc::clone(&coordinator), 1);
        idle.enter();
        let executing = ExecutingTask::enter(&coordinator, 0, a);
        assert!(matches!(
            claim_lifo_wake(&coordinator, b, 5),
            LifoWake::Placed
        ));
        drop(executing);
        assert_eq!(idle.look(0), None);
        assert_eq!(take_lifo_task(&coordinator, 0), Some((b, 5)));

        assert_eq!(idle.look(LIFO_WATCH_MIN_INTERVAL_NANOS), None);
        assert_eq!(lifo_watch_state(&coordinator), LIFO_WATCH_NONE);
        assert_eq!(idle.wait_cap(LIFO_WATCH_MIN_INTERVAL_NANOS), None);
        assert!(!idle.must_look());
        assert_eq!(idle.look(10 * LIFO_WATCH_MIN_INTERVAL_NANOS), None);
        assert_eq!(lifo_watch_state(&coordinator), LIFO_WATCH_NONE);
    }

    /// While an owner keeps filling and emptying its slot, as in a ping-pong,
    /// the watcher stays on duty and looks at a doubling interval, up to the
    /// bound, instead of retiring and costing the next fill a wake. It gives
    /// the role up once a whole interval passes with no fill.
    #[test]
    fn the_watcher_backs_off_while_an_owner_keeps_draining_its_slot() {
        let coordinator = lifo_test_coordinator(2);
        let (a, b) = (TaskId::new_for_test(1, 1), TaskId::new_for_test(2, 1));
        let fill_and_drain = || {
            let executing = ExecutingTask::enter(&coordinator, 0, a);
            assert!(matches!(
                claim_lifo_wake(&coordinator, b, 5),
                LifoWake::Placed
            ));
            drop(executing);
            assert_eq!(take_lifo_task(&coordinator, 0), Some((b, 5)));
        };
        let mut idle = LifoIdle::new(Arc::clone(&coordinator), 1);
        idle.enter();
        fill_and_drain();
        let mut now = 0;
        assert_eq!(idle.look(now), None);
        assert_eq!(lifo_watch_state(&coordinator), LIFO_WATCH_ACTIVE);

        let mut interval = LIFO_WATCH_MIN_INTERVAL_NANOS;
        for _ in 0..6 {
            now += interval;
            fill_and_drain();
            assert_eq!(idle.look(now), None, "nothing was stranded");
            assert_eq!(
                lifo_watch_state(&coordinator),
                LIFO_WATCH_ACTIVE,
                "the watcher stays while the slot keeps filling"
            );
            interval = (interval * 2).min(LIFO_WATCH_MAX_INTERVAL_NANOS);
            assert_eq!(idle.wait_cap(now), Some(Duration::from_nanos(interval)));
        }
        assert_eq!(interval, LIFO_WATCH_MAX_INTERVAL_NANOS);

        now += interval;
        assert_eq!(idle.look(now), None);
        assert_eq!(lifo_watch_state(&coordinator), LIFO_WATCH_NONE);
        assert_eq!(idle.wait_cap(now), None);
    }

    /// With every worker busy, a wake that fills a slot requests nothing and
    /// wakes nobody. The first loop to go idle looks at the slots before it
    /// blocks and takes the role.
    #[test]
    fn a_slot_filled_while_every_worker_is_busy_is_watched_by_the_next_idle_loop() {
        let coordinator = lifo_test_coordinator(2);
        let (a, b) = (TaskId::new_for_test(1, 1), TaskId::new_for_test(2, 1));
        let executing = ExecutingTask::enter(&coordinator, 0, a);
        assert!(matches!(
            claim_lifo_wake(&coordinator, b, 5),
            LifoWake::Placed
        ));
        assert_eq!(lifo_watch_state(&coordinator), LIFO_WATCH_NONE);
        assert!(!a_parker_was_woken(&coordinator));

        let mut idle = LifoIdle::new(Arc::clone(&coordinator), 1);
        idle.enter();
        assert_eq!(idle.look(0), None);
        assert_eq!(lifo_watch_state(&coordinator), LIFO_WATCH_ACTIVE);
        assert_eq!(idle.look(LIFO_WATCH_MIN_INTERVAL_NANOS), Some(b));
        drop(executing);
    }

    /// A watcher that leaves to run a task while a slot still holds one hands
    /// the watch to another idle loop: it requests it again and wakes a
    /// worker. A wake that displaces an older slot task keeps the newest.
    #[test]
    fn a_watcher_that_leaves_hands_the_watch_on() {
        let coordinator = lifo_test_coordinator(3);
        let (a, b, c) = (
            TaskId::new_for_test(1, 1),
            TaskId::new_for_test(2, 1),
            TaskId::new_for_test(3, 1),
        );
        let mut first = LifoIdle::new(Arc::clone(&coordinator), 1);
        let mut second = LifoIdle::new(Arc::clone(&coordinator), 2);
        first.enter();
        second.enter();
        let executing = ExecutingTask::enter(&coordinator, 0, a);
        assert!(matches!(
            claim_lifo_wake(&coordinator, b, 5),
            LifoWake::Placed
        ));
        assert!(matches!(
            claim_lifo_wake(&coordinator, c, 6),
            LifoWake::Displaced(older, 5) if older == b
        ));
        assert_eq!(first.look(0), None);
        assert_eq!(lifo_watch_state(&coordinator), LIFO_WATCH_ACTIVE);
        assert_eq!(second.look(0), None);
        assert!(!second.must_look(), "one watcher at a time");

        for parker in &coordinator.parkers {
            parker.park_timeout(Duration::ZERO);
        }
        first.leave();
        assert_eq!(lifo_watch_state(&coordinator), LIFO_WATCH_REQUESTED);
        assert!(a_parker_was_woken(&coordinator), "the hand-on woke nobody");
        assert!(second.must_look());
        assert_eq!(second.look(0), None);
        assert_eq!(lifo_watch_state(&coordinator), LIFO_WATCH_ACTIVE);
        assert_eq!(second.look(LIFO_WATCH_MIN_INTERVAL_NANOS), Some(c));
        drop(executing);
    }
