    use super::*;
    use crate::security::authenticated::AuthenticatedSymbol;
    use crate::security::tag::AuthenticationTag;
    use crate::transport::{SymbolSinkExt, SymbolStreamExt};
    use crate::types::{Symbol, SymbolId, SymbolKind};
    use futures_lite::future;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Wake, Waker};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn create_symbol(esi: u32) -> AuthenticatedSymbol {
        let id = SymbolId::new_for_test(1, 0, esi);
        let symbol = Symbol::new(id, vec![esi as u8], SymbolKind::Source);
        let tag = AuthenticationTag::zero();
        AuthenticatedSymbol::new_verified(symbol, tag)
    }

    struct FlagWake {
        flag: Arc<AtomicBool>,
    }

    impl Wake for FlagWake {
        fn wake(self: Arc<Self>) {
            self.flag.store(true, Ordering::Release);
        }
    }

    fn flagged_waker(flag: Arc<AtomicBool>) -> Waker {
        Waker::from(Arc::new(FlagWake { flag }))
    }

    #[test]
    fn test_channel_round_trip_and_close() {
        init_test("test_channel_round_trip_and_close");
        let (mut sink, mut stream) = channel(2);
        let s1 = create_symbol(1);
        let s2 = create_symbol(2);

        future::block_on(async {
            sink.send(s1.clone()).await.unwrap();
            sink.send(s2.clone()).await.unwrap();
            sink.close().await.unwrap();

            let r1 = stream.next().await.unwrap().unwrap();
            let r2 = stream.next().await.unwrap().unwrap();
            crate::assert_with_log!(r1 == s1, "first symbol", true, r1 == s1);
            crate::assert_with_log!(r2 == s2, "second symbol", true, r2 == s2);
            crate::assert_with_log!(stream.next().await.is_none(), "stream closed", true, true);
        });

        crate::test_complete!("test_channel_round_trip_and_close");
    }

    #[test]
    fn test_shared_channel_close_wakes_waiters() {
        init_test("test_shared_channel_close_wakes_waiters");
        let shared = SharedChannel::new(1);

        let send_flag = Arc::new(AtomicBool::new(false));
        let recv_flag = Arc::new(AtomicBool::new(false));
        let send_queued = Arc::new(AtomicBool::new(true));
        let recv_queued = Arc::new(AtomicBool::new(true));

        {
            let mut send_wakers = shared.send_wakers.lock();
            send_wakers.push(ChannelWaiter {
                waker: flagged_waker(Arc::clone(&send_flag)),
                queued: Arc::clone(&send_queued),
            });
        }

        {
            let mut recv_wakers = shared.recv_wakers.lock();
            recv_wakers.push(ChannelWaiter {
                waker: flagged_waker(Arc::clone(&recv_flag)),
                queued: Arc::clone(&recv_queued),
            });
        }

        shared.close();

        crate::assert_with_log!(
            shared.closed.load(Ordering::SeqCst),
            "closed flag set",
            true,
            shared.closed.load(Ordering::SeqCst)
        );
        crate::assert_with_log!(
            !send_queued.load(Ordering::Acquire),
            "send queued cleared",
            false,
            send_queued.load(Ordering::Acquire)
        );
        crate::assert_with_log!(
            !recv_queued.load(Ordering::Acquire),
            "recv queued cleared",
            false,
            recv_queued.load(Ordering::Acquire)
        );
        crate::assert_with_log!(
            send_flag.load(Ordering::Acquire),
            "send waker fired",
            true,
            send_flag.load(Ordering::Acquire)
        );
        crate::assert_with_log!(
            recv_flag.load(Ordering::Acquire),
            "recv waker fired",
            true,
            recv_flag.load(Ordering::Acquire)
        );

        crate::test_complete!("test_shared_channel_close_wakes_waiters");
    }

    #[test]
    fn mr_shared_channel_close_is_idempotent() {
        init_test("mr_shared_channel_close_is_idempotent");
        let shared = SharedChannel::new(2);

        {
            let mut queue = shared.queue.lock();
            queue.push_back(create_symbol(7));
        }

        let send_flag = Arc::new(AtomicBool::new(false));
        let recv_flag = Arc::new(AtomicBool::new(false));
        let send_queued = Arc::new(AtomicBool::new(true));
        let recv_queued = Arc::new(AtomicBool::new(true));

        {
            let mut send_wakers = shared.send_wakers.lock();
            send_wakers.push(ChannelWaiter {
                waker: flagged_waker(Arc::clone(&send_flag)),
                queued: Arc::clone(&send_queued),
            });
        }

        {
            let mut recv_wakers = shared.recv_wakers.lock();
            recv_wakers.push(ChannelWaiter {
                waker: flagged_waker(Arc::clone(&recv_flag)),
                queued: Arc::clone(&recv_queued),
            });
        }

        shared.close();
        let first_queue = shared.queue.lock().clone();
        let first_send_waiters = shared.send_wakers.lock().len();
        let first_recv_waiters = shared.recv_wakers.lock().len();

        shared.close();

        crate::assert_with_log!(
            shared.closed.load(Ordering::Acquire),
            "closed flag remains set",
            true,
            shared.closed.load(Ordering::Acquire)
        );
        crate::assert_with_log!(
            shared.queue.lock().iter().eq(first_queue.iter()),
            "queued symbols preserved",
            true,
            true
        );
        crate::assert_with_log!(
            first_send_waiters == 0 && shared.send_wakers.lock().is_empty(),
            "send waiters drained once",
            true,
            shared.send_wakers.lock().len()
        );
        crate::assert_with_log!(
            first_recv_waiters == 0 && shared.recv_wakers.lock().is_empty(),
            "recv waiters drained once",
            true,
            shared.recv_wakers.lock().len()
        );
        crate::assert_with_log!(
            !send_queued.load(Ordering::Acquire) && !recv_queued.load(Ordering::Acquire),
            "queued flags remain cleared",
            true,
            (
                send_queued.load(Ordering::Acquire),
                recv_queued.load(Ordering::Acquire)
            )
        );
        crate::assert_with_log!(
            send_flag.load(Ordering::Acquire) && recv_flag.load(Ordering::Acquire),
            "first close woke both waiter classes",
            true,
            (
                send_flag.load(Ordering::Acquire),
                recv_flag.load(Ordering::Acquire)
            )
        );

        crate::test_complete!("mr_shared_channel_close_is_idempotent");
    }

    #[test]
    #[should_panic(expected = "transport::channel capacity must be > 0")]
    fn test_channel_zero_capacity_panics() {
        let _ = channel(0);
    }
