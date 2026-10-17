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
