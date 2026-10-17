    use super::super::super::tests::drive;
    use super::super::tests::recorded_exchange;
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    fn require_send<T: Send>(value: T) -> T {
        value
    }

    #[test]
    fn driver_is_send_without_accepting_an_unconsumed_capture() {
        let future = recorded_exchange()
            .replay()
            .run_send(1, |_| Box::pin(async { 42 }));
        assert!(matches!(
            drive(require_send(future)),
            Err(OrderedRunError::Replay(_))
        ));
    }

    struct DropCount(Arc<AtomicUsize>);
    impl Drop for DropCount {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn send_driver_enforces_poll_bound_and_drops_its_consumer_once() {
        let drops = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&drops);
        let future = recorded_exchange().replay().run_send(2, move |_| {
            Box::pin(async move {
                let _guard = DropCount(count);
                poll_fn(|cx| {
                    cx.waker().wake_by_ref();
                    Poll::<()>::Pending
                })
                .await;
            })
        });
        assert_eq!(
            drive(require_send(future)).unwrap_err(),
            OrderedRunError::PollLimit { limit: 2 }
        );
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn dropping_parked_io_contains_reentrant_waker_destructor_panics() {
        use super::super::{OrderedReplaySession, gate::ReplayOrder};
        use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
        use std::task::{Context, Wake, Waker};
        struct DropWake {
            order: Arc<ReplayOrder>,
            calls: Arc<AtomicUsize>,
            panic: bool,
        }
        // A static no-op waker cannot exercise the reentrant, panicking
        // payload destructor that this cancellation regression requires.
        #[allow(clippy::manual_noop_waker)]
        impl Wake for DropWake {
            fn wake(self: Arc<Self>) {}
        }
        impl Drop for DropWake {
            fn drop(&mut self) {
                let _ = self.order.verify();
                self.calls.fetch_add(1, Ordering::Relaxed);
                assert!(!self.panic, "drop-waker sentinel");
            }
        }
        let mut replay: OrderedReplaySession = recorded_exchange().replay();
        let calls = Arc::new(AtomicUsize::new(0));
        let read = Waker::from(Arc::new(DropWake {
            order: Arc::clone(&replay.order),
            calls: Arc::clone(&calls),
            panic: true,
        }));
        let write = Waker::from(Arc::new(DropWake {
            order: Arc::clone(&replay.order),
            calls: Arc::clone(&calls),
            panic: false,
        }));
        let mut bytes = [0; 2];
        assert!(
            Pin::new(replay.inputs().io)
                .poll_read(
                    &mut Context::from_waker(&read),
                    &mut ReadBuf::new(&mut bytes)
                )
                .is_pending()
        );
        assert!(
            Pin::new(replay.inputs().io)
                .poll_write(&mut Context::from_waker(&write), b"x")
                .is_pending()
        );
        drop(read);
        drop(write);
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(replay))).is_ok());
        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }
