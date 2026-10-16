    use super::*;
    use crate::channel::{mpsc, oneshot};
    use crate::runtime::RuntimeBuilder;

    /// br-asupersync-kopidb H1: a `!Send` local task woken from a plain thread
    /// runs promptly while its worker idles in the reactor with a far timer
    /// armed. Before the fix the wake only unparked the worker, which was
    /// blocked in the reactor, so the task waited for the 30 s timer.
    #[test]
    fn a_local_task_woken_from_another_thread_does_not_wait_for_the_reactor_timeout() {
        let (done_tx, done_rx) = std::sync::mpsc::channel::<Duration>();
        std::thread::spawn(move || {
            let rt = RuntimeBuilder::current_thread()
                .build()
                .expect("current-thread runtime");
            let elapsed = rt.block_on(rt.handle().spawn(async move {
                let cx = crate::Cx::current().expect("a spawned task has a Cx");
                // A 30 s timer, so an idle reactor turn waits up to 30 s. The
                // task waits in a cancel-aware recv, so the abort below ends it.
                let (_keep, mut never) = mpsc::channel::<u8>(1);
                let mut sleeper = cx
                    .spawn(move |cx| async move {
                        let _ = crate::time::timeout(
                            cx.now(),
                            Duration::from_secs(30),
                            never.recv(&cx),
                        )
                        .await;
                    })
                    .expect("spawn the timer task");
                let (tx, mut rx) = oneshot::channel::<u32>();
                let mut local = cx
                    .spawn_local(move |cx| async move { rx.recv(&cx).await.ok() })
                    .expect("spawn the local task");
                let sender = std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(50));
                    let _ = tx.send_blocking(7);
                });
                let start = std::time::Instant::now();
                let value = local.join(&cx).await.expect("the local task");
                let elapsed = start.elapsed();
                assert_eq!(value, Some(7), "the local task received the value");
                sender.join().expect("the sender thread");
                sleeper.abort();
                let _ = sleeper.join(&cx).await;
                elapsed
            }));
            let _ = done_tx.send(elapsed);
        });
        let elapsed = done_rx
            .recv_timeout(Duration::from_secs(60))
            .expect("the runtime thread finished");
        assert!(
            elapsed < Duration::from_secs(5),
            "the local task waited {elapsed:?}: its wake did not reach the worker blocked in the reactor"
        );
    }
