    use super::*;
    use crate::channel::mpsc;
    use crate::record::ObligationKind;
    use crate::runtime::RuntimeBuilder;
    use std::sync::atomic::AtomicUsize;

    /// br-asupersync-e6igie M1: a post made inside the dispatch loop of one of
    /// the scheduler's workers wakes nobody; a post from a plain thread, or
    /// from another scheduler's worker, wakes one worker.
    #[test]
    fn an_obligation_post_wakes_a_worker_only_from_outside_this_schedulers_workers() {
        let state = Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()));
        let scheduler = ThreeLaneScheduler::new(2, &state);
        let wakes = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&wakes);
        scheduler.coordinator.set_wake_notifier(Arc::new(move || {
            counted.fetch_add(1, Ordering::Relaxed);
        }));
        let notify = scheduler.obligation_posted_notifier();

        notify();
        assert_eq!(
            wakes.load(Ordering::Relaxed),
            1,
            "a post from a plain thread wakes a worker"
        );

        {
            let _worker = ScopedLocalReady::new(Arc::clone(&scheduler.workers[1].local_ready));
            notify();
        }
        assert_eq!(
            wakes.load(Ordering::Relaxed),
            1,
            "a post made on one of this scheduler's workers woke a worker"
        );

        let other_state = Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()));
        let other = ThreeLaneScheduler::new(1, &other_state);
        {
            let _worker = ScopedLocalReady::new(Arc::clone(&other.workers[0].local_ready));
            notify();
        }
        assert_eq!(
            wakes.load(Ordering::Relaxed),
            2,
            "a post made on another scheduler's worker wakes one of this scheduler's workers"
        );
    }

    /// The posts above wake nobody, so the posting worker must apply all of
    /// them itself before it waits. A task on a one-worker runtime reserves
    /// 200 channel permits in one poll, more than one 64-post drain batch,
    /// and then waits with a 30 s timer armed. Every reservation must show up
    /// as a live obligation promptly, not when the worker leaves the reactor.
    #[test]
    fn a_worker_applies_its_own_obligation_posts_before_it_blocks_in_the_reactor() {
        const PERMITS: usize = 200;
        let rt = RuntimeBuilder::new()
            .worker_threads(1)
            .build()
            .expect("one-worker runtime");
        let diagnostics = rt.diagnostics();
        let (keep, mut never) = mpsc::channel::<u8>(1);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<TaskId>();
        let holder = rt.handle().spawn(async move {
            let cx = crate::Cx::current().expect("a spawned task has a Cx");
            let (tx, _rx) = mpsc::channel::<u8>(PERMITS);
            let mut permits = Vec::with_capacity(PERMITS);
            for _ in 0..PERMITS {
                permits.push(tx.reserve(&cx).await.expect("reserve capacity"));
            }
            let _ = ready_tx.send(cx.task_id());
            // A 30 s timer, so an idle reactor turn waits up to 30 s. Dropping
            // `keep` below ends the wait.
            let _ = crate::time::timeout(cx.now(), Duration::from_secs(30), never.recv(&cx)).await;
            drop(permits);
        });
        let holder_id = ready_rx
            .recv_timeout(Duration::from_secs(60))
            .expect("the holder reserved its permits");
        let kind = format!("{:?}", ObligationKind::SendPermit);
        let start = std::time::Instant::now();
        let mut live = 0;
        while start.elapsed() < Duration::from_secs(5) {
            live = diagnostics
                .find_leaked_obligations()
                .into_iter()
                .filter(|record| {
                    record.holder_task == Some(holder_id) && record.obligation_type == kind
                })
                .count();
            if live == PERMITS {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        let elapsed = start.elapsed();
        drop(keep);
        rt.block_on(holder);
        assert_eq!(
            live, PERMITS,
            "after {elapsed:?} only {live} of {PERMITS} reservations were applied: the worker blocked in the reactor with its own obligation posts queued"
        );
    }
