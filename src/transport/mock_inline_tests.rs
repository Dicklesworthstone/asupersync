    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::security::tag::AuthenticationTag;
    use crate::transport::{SymbolSinkExt, SymbolStreamExt};
    use crate::types::{Symbol, SymbolId, SymbolKind, Time};
    use futures_lite::future;
    use std::sync::atomic::AtomicU64;
    use std::task::{Poll, Waker};

    static STREAM_TEST_NOW: AtomicU64 = AtomicU64::new(0);
    static SINK_TEST_NOW: AtomicU64 = AtomicU64::new(0);
    static CONFIG_TEST_NOW: AtomicU64 = AtomicU64::new(0);
    static SHARED_TEST_NOW: AtomicU64 = AtomicU64::new(0);

    fn create_symbol(i: u32) -> AuthenticatedSymbol {
        let id = SymbolId::new_for_test(1, 0, i);
        let symbol = Symbol::new(id, vec![i as u8], SymbolKind::Source);
        let tag = AuthenticationTag::zero();
        AuthenticatedSymbol::new_verified(symbol, tag)
    }

    #[test]
    fn corrupted_symbol_is_no_longer_marked_verified() {
        let original = create_symbol(7);
        let mut rng = DetRng::new(123);

        let corrupted = corrupt_symbol(&original, &mut rng);

        assert!(!corrupted.is_verified());
        assert_eq!(corrupted.tag(), original.tag());
        assert_ne!(corrupted.symbol().data(), original.symbol().data());
    }

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    struct FlagWake {
        flag: Arc<AtomicBool>,
    }

    use std::task::Wake;
    impl Wake for FlagWake {
        fn wake(self: Arc<Self>) {
            self.flag.store(true, Ordering::Release);
        }
    }

    fn flagged_waker(flag: Arc<AtomicBool>) -> Waker {
        Waker::from(Arc::new(FlagWake { flag }))
    }

    fn set_stream_test_time(nanos: u64) {
        STREAM_TEST_NOW.store(nanos, Ordering::SeqCst);
    }

    fn stream_test_time() -> Time {
        Time::from_nanos(STREAM_TEST_NOW.load(Ordering::SeqCst))
    }

    fn set_sink_test_time(nanos: u64) {
        SINK_TEST_NOW.store(nanos, Ordering::SeqCst);
    }

    fn sink_test_time() -> Time {
        Time::from_nanos(SINK_TEST_NOW.load(Ordering::SeqCst))
    }

    fn set_config_test_time(nanos: u64) {
        CONFIG_TEST_NOW.store(nanos, Ordering::SeqCst);
    }

    fn config_test_time() -> Time {
        Time::from_nanos(CONFIG_TEST_NOW.load(Ordering::SeqCst))
    }

    fn set_shared_test_time(nanos: u64) {
        SHARED_TEST_NOW.store(nanos, Ordering::SeqCst);
    }

    fn shared_test_time() -> Time {
        Time::from_nanos(SHARED_TEST_NOW.load(Ordering::SeqCst))
    }

    #[test]
    fn test_sim_channel_reliable() {
        let (mut sink, mut stream) = sim_channel(SimTransportConfig::reliable());
        let s1 = create_symbol(1);
        let s2 = create_symbol(2);

        future::block_on(async {
            sink.send(s1.clone()).await.unwrap();
            sink.send(s2.clone()).await.unwrap();

            let r1 = stream.next().await.unwrap().unwrap();
            let r2 = stream.next().await.unwrap().unwrap();

            assert_eq!(r1, s1);
            assert_eq!(r2, s2);
        });
    }

    fn run_lossy(seed: u64) -> usize {
        let config = SimTransportConfig {
            loss_rate: 0.5,
            seed: Some(seed),
            capacity: 1024,
            ..SimTransportConfig::default()
        };
        let (mut sink, mut stream) = sim_channel(config);

        future::block_on(async {
            for i in 0..100 {
                sink.send(create_symbol(i)).await.unwrap();
            }
            sink.close().await.unwrap();

            let mut count = 0usize;
            while let Some(item) = stream.next().await {
                if item.is_ok() {
                    count += 1;
                }
            }
            count
        })
    }

    #[test]
    fn test_sim_channel_loss_deterministic() {
        let count1 = run_lossy(42);
        let count2 = run_lossy(42);
        assert_eq!(count1, count2);
        assert!(count1 < 100);
    }

    fn collect_batched_delivery_esis(symbols: &[AuthenticatedSymbol]) -> Vec<u32> {
        let (mut sink, mut stream) = sim_channel(SimTransportConfig {
            capacity: symbols.len().max(1),
            ..SimTransportConfig::reliable()
        });

        future::block_on(async {
            for symbol in symbols {
                sink.send(symbol.clone()).await.unwrap();
            }
            sink.close().await.unwrap();

            let mut delivered = Vec::new();
            while let Some(item) = stream.next().await {
                delivered.push(item.unwrap().symbol().id().esi());
            }
            delivered
        })
    }

    fn collect_interleaved_delivery_esis(symbols: &[AuthenticatedSymbol]) -> Vec<u32> {
        let (mut sink, mut stream) = sim_channel(SimTransportConfig {
            capacity: 1,
            ..SimTransportConfig::reliable()
        });

        future::block_on(async {
            let mut delivered = Vec::new();
            for symbol in symbols {
                sink.send(symbol.clone()).await.unwrap();
                let item = stream
                    .next()
                    .await
                    .expect("reliable channel should deliver one symbol per send")
                    .expect("reliable channel should not fail");
                delivered.push(item.symbol().id().esi());
            }
            sink.close().await.unwrap();
            assert!(stream.next().await.is_none());
            delivered
        })
    }

    #[test]
    fn metamorphic_reliable_delivery_invariant_to_send_drain_schedule() {
        let symbols: Vec<_> = (0..16).map(create_symbol).collect();
        let expected: Vec<_> = (0..16).collect();

        let batched = collect_batched_delivery_esis(&symbols);
        let interleaved = collect_interleaved_delivery_esis(&symbols);

        assert_eq!(batched, expected);
        assert_eq!(
            interleaved, batched,
            "reliable deterministic transport delivery must be invariant to batching versus interleaving sends and receives"
        );
    }

    #[test]
    fn test_sim_channel_duplication() {
        let config = SimTransportConfig {
            duplication_rate: 1.0,
            capacity: 128,
            ..SimTransportConfig::deterministic(7)
        };
        let (mut sink, mut stream) = sim_channel(config);

        future::block_on(async {
            for i in 0..10 {
                sink.send(create_symbol(i)).await.unwrap();
            }
            sink.close().await.unwrap();

            let mut count = 0usize;
            while let Some(item) = stream.next().await {
                if item.is_ok() {
                    count += 1;
                }
            }
            assert_eq!(count, 20);
        });
    }

    #[test]
    fn test_sim_channel_fail_after() {
        let config = SimTransportConfig {
            fail_after: Some(2),
            ..SimTransportConfig::default()
        };
        let (mut sink, _stream) = sim_channel(config);

        future::block_on(async {
            sink.send(create_symbol(1)).await.unwrap();
            sink.send(create_symbol(2)).await.unwrap();
            let err = sink.send(create_symbol(3)).await.unwrap_err();
            assert!(matches!(err, SinkError::SendFailed { .. }));
        });
    }

    #[test]
    fn test_sim_channel_backpressure_pending() {
        let config = SimTransportConfig {
            capacity: 1,
            ..SimTransportConfig::default()
        };
        let (mut sink, _stream) = sim_channel(config);

        future::block_on(async {
            sink.send(create_symbol(1)).await.unwrap();
        });

        let mut poll_result = None;
        future::block_on(future::poll_fn(|cx| {
            poll_result = Some(Pin::new(&mut sink).poll_ready(cx));
            Poll::Ready(())
        }));

        assert!(matches!(poll_result, Some(Poll::Pending)));
    }

    #[test]
    fn test_sim_channel_zero_capacity_ready_fails_fast() {
        let config = SimTransportConfig {
            capacity: 0,
            ..SimTransportConfig::default()
        };
        let (mut sink, _stream) = sim_channel(config);

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let ready = Pin::new(&mut sink).poll_ready(&mut context);
        assert!(matches!(ready, Poll::Ready(Err(SinkError::BufferFull))));

        let send = Pin::new(&mut sink).poll_send(&mut context, create_symbol(1));
        assert!(matches!(send, Poll::Ready(Err(SinkError::BufferFull))));
    }

    #[test]
    fn test_sim_channel_sink_skips_stale_recv_waiter_entries() {
        let shared = Arc::new(SimQueue::new(SimTransportConfig {
            capacity: 2,
            ..SimTransportConfig::reliable()
        }));
        let (mut sink, _stream) = channel_from_shared(Arc::clone(&shared));

        let stale_flag = Arc::new(AtomicBool::new(false));
        let active_flag = Arc::new(AtomicBool::new(false));
        let stale_queued = Arc::new(AtomicBool::new(false));
        let active_queued = Arc::new(AtomicBool::new(true));

        {
            let mut state = shared.state.lock();
            state.recv_wakers.push(SimWaiter {
                waker: flagged_waker(Arc::clone(&stale_flag)),
                queued: Arc::clone(&stale_queued),
            });
            state.recv_wakers.push(SimWaiter {
                waker: flagged_waker(Arc::clone(&active_flag)),
                queued: Arc::clone(&active_queued),
            });
        }

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let send = Pin::new(&mut sink).poll_send(&mut context, create_symbol(5));
        assert!(matches!(send, Poll::Ready(Ok(()))));
        assert!(!stale_flag.load(Ordering::Acquire));
        assert!(active_flag.load(Ordering::Acquire));
        assert!(!active_queued.load(Ordering::Acquire));
        assert!(shared.state.lock().recv_wakers.is_empty());
    }

    #[test]
    fn test_sim_channel_sink_wakes_oldest_recv_waiter_first() {
        let shared = Arc::new(SimQueue::new(SimTransportConfig {
            capacity: 2,
            ..SimTransportConfig::reliable()
        }));
        let (mut sink, _stream) = channel_from_shared(Arc::clone(&shared));

        let first_flag = Arc::new(AtomicBool::new(false));
        let second_flag = Arc::new(AtomicBool::new(false));
        let first_queued = Arc::new(AtomicBool::new(true));
        let second_queued = Arc::new(AtomicBool::new(true));

        {
            let mut state = shared.state.lock();
            state.recv_wakers.push(SimWaiter {
                waker: flagged_waker(Arc::clone(&first_flag)),
                queued: Arc::clone(&first_queued),
            });
            state.recv_wakers.push(SimWaiter {
                waker: flagged_waker(Arc::clone(&second_flag)),
                queued: Arc::clone(&second_queued),
            });
        }

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let send = Pin::new(&mut sink).poll_send(&mut context, create_symbol(9));
        assert!(matches!(send, Poll::Ready(Ok(()))));
        assert!(first_flag.load(Ordering::Acquire));
        assert!(!second_flag.load(Ordering::Acquire));
        assert!(second_queued.load(Ordering::Acquire));
        assert_eq!(shared.state.lock().recv_wakers.len(), 1);
    }

    #[test]
    fn test_sim_channel_stream_skips_stale_send_waiter_entries() {
        let shared = Arc::new(SimQueue::new(SimTransportConfig {
            capacity: 2,
            ..SimTransportConfig::reliable()
        }));
        {
            let mut state = shared.state.lock();
            state.queue.push_back(create_symbol(1));
        }
        let (_sink, mut stream) = channel_from_shared(Arc::clone(&shared));

        let stale_flag = Arc::new(AtomicBool::new(false));
        let active_flag = Arc::new(AtomicBool::new(false));
        let stale_queued = Arc::new(AtomicBool::new(false));
        let active_queued = Arc::new(AtomicBool::new(true));

        {
            let mut state = shared.state.lock();
            state.send_wakers.push(SimWaiter {
                waker: flagged_waker(Arc::clone(&stale_flag)),
                queued: Arc::clone(&stale_queued),
            });
            state.send_wakers.push(SimWaiter {
                waker: flagged_waker(Arc::clone(&active_flag)),
                queued: Arc::clone(&active_queued),
            });
        }

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let recv = Pin::new(&mut stream).poll_next(&mut context);
        assert!(matches!(recv, Poll::Ready(Some(Ok(_)))));
        assert!(!stale_flag.load(Ordering::Acquire));
        assert!(active_flag.load(Ordering::Acquire));
        assert!(!active_queued.load(Ordering::Acquire));
        assert!(shared.state.lock().send_wakers.is_empty());
    }

    #[test]
    fn test_sim_channel_stream_wakes_oldest_send_waiter_first() {
        let shared = Arc::new(SimQueue::new(SimTransportConfig {
            capacity: 2,
            ..SimTransportConfig::reliable()
        }));
        {
            let mut state = shared.state.lock();
            state.queue.push_back(create_symbol(1));
        }
        let (_sink, mut stream) = channel_from_shared(Arc::clone(&shared));

        let first_flag = Arc::new(AtomicBool::new(false));
        let second_flag = Arc::new(AtomicBool::new(false));
        let first_queued = Arc::new(AtomicBool::new(true));
        let second_queued = Arc::new(AtomicBool::new(true));

        {
            let mut state = shared.state.lock();
            state.send_wakers.push(SimWaiter {
                waker: flagged_waker(Arc::clone(&first_flag)),
                queued: Arc::clone(&first_queued),
            });
            state.send_wakers.push(SimWaiter {
                waker: flagged_waker(Arc::clone(&second_flag)),
                queued: Arc::clone(&second_queued),
            });
        }

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let recv = Pin::new(&mut stream).poll_next(&mut context);
        assert!(matches!(recv, Poll::Ready(Some(Ok(_)))));
        assert!(first_flag.load(Ordering::Acquire));
        assert!(!second_flag.load(Ordering::Acquire));
        assert!(second_queued.load(Ordering::Acquire));
        assert_eq!(shared.state.lock().send_wakers.len(), 1);
    }

    #[test]
    fn sim_stream_latency_uses_time_getter_without_sleeping() {
        set_stream_test_time(0);
        let shared = Arc::new(SimQueue::new(
            SimTransportConfig::with_latency(Duration::from_nanos(5), Duration::ZERO)
                .with_time_getter(stream_test_time),
        ));
        {
            let mut state = shared.state.lock();
            state.queue.push_back(create_symbol(1));
        }
        let (_sink, mut stream) = channel_from_shared(shared);

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let poll = Pin::new(&mut stream).poll_next(&mut context);
        assert!(matches!(poll, Poll::Pending));

        set_stream_test_time(5);
        let poll = Pin::new(&mut stream).poll_next(&mut context);
        assert!(matches!(poll, Poll::Ready(Some(Ok(_)))));
    }

    #[test]
    fn sim_sink_latency_uses_time_getter_without_sleeping() {
        set_sink_test_time(0);
        let (mut sink, _stream) = sim_channel(
            SimTransportConfig::with_latency(Duration::from_nanos(5), Duration::ZERO)
                .with_time_getter(sink_test_time),
        );
        let symbol = create_symbol(7);

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let poll = Pin::new(&mut sink).poll_send(&mut context, symbol.clone());
        assert!(matches!(poll, Poll::Pending));
        assert_eq!(sink.sent_count(), 0);

        set_sink_test_time(5);
        let poll = Pin::new(&mut sink).poll_send(&mut context, symbol);
        assert!(matches!(poll, Poll::Ready(Ok(()))));
        assert_eq!(sink.sent_count(), 1);
    }

    #[test]
    fn sim_stream_is_not_empty_while_delayed_symbol_is_pending() {
        let shared = Arc::new(SimQueue::new(SimTransportConfig::with_latency(
            Duration::from_secs(1),
            Duration::ZERO,
        )));
        {
            let mut state = shared.state.lock();
            state.queue.push_back(create_symbol(1));
        }
        let (_sink, mut stream) = channel_from_shared(shared);

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let poll = Pin::new(&mut stream).poll_next(&mut context);
        assert!(matches!(poll, Poll::Pending));
        assert!(!stream.is_empty());
    }

    #[test]
    fn delayed_receive_keeps_capacity_reserved_until_delivery() {
        set_shared_test_time(0);
        let shared = Arc::new(SimQueue::new(
            SimTransportConfig {
                capacity: 1,
                ..SimTransportConfig::with_latency(Duration::from_nanos(5), Duration::ZERO)
            }
            .with_time_getter(shared_test_time),
        ));
        {
            let mut state = shared.state.lock();
            state.queue.push_back(create_symbol(1));
        }
        let (mut sink, mut stream) = channel_from_shared(shared);

        let recv_waker = noop_waker();
        let mut recv_cx = Context::from_waker(&recv_waker);
        assert!(matches!(
            Pin::new(&mut stream).poll_next(&mut recv_cx),
            Poll::Pending
        ));

        let send_ready_woken = Arc::new(AtomicBool::new(false));
        let send_waker = flagged_waker(Arc::clone(&send_ready_woken));
        let mut send_cx = Context::from_waker(&send_waker);
        assert!(matches!(
            Pin::new(&mut sink).poll_ready(&mut send_cx),
            Poll::Pending
        ));
        assert!(
            !send_ready_woken.load(Ordering::SeqCst),
            "capacity must stay reserved while the delayed symbol is still pending"
        );

        set_shared_test_time(5);
        assert!(matches!(
            Pin::new(&mut stream).poll_next(&mut recv_cx),
            Poll::Ready(Some(Ok(_)))
        ));
        assert!(
            send_ready_woken.load(Ordering::SeqCst),
            "delayed delivery completion must wake blocked senders"
        );
        assert!(matches!(
            Pin::new(&mut sink).poll_ready(&mut send_cx),
            Poll::Ready(Ok(()))
        ));
    }

    // Pure data-type tests (wave 14 – CyanBarn)

    #[test]
    fn sim_transport_config_default_values() {
        let cfg = SimTransportConfig::default();
        assert_eq!(cfg.base_latency, Duration::ZERO);
        assert_eq!(cfg.latency_jitter, Duration::ZERO);
        assert!((cfg.loss_rate - 0.0).abs() < f64::EPSILON);
        assert!((cfg.duplication_rate - 0.0).abs() < f64::EPSILON);
        assert!((cfg.corruption_rate - 0.0).abs() < f64::EPSILON);
        assert_eq!(cfg.capacity, 1024);
        assert!(cfg.seed.is_none());
        assert!(cfg.preserve_order);
        assert!(cfg.fail_after.is_none());
    }

    #[test]
    fn sim_transport_config_debug_clone() {
        let cfg = SimTransportConfig::default();
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("SimTransportConfig"));

        let cloned = cfg;
        assert_eq!(cloned.capacity, 1024);
    }

    #[test]
    fn sim_transport_config_reliable() {
        let cfg = SimTransportConfig::reliable();
        assert_eq!(cfg.base_latency, Duration::ZERO);
        assert!((cfg.loss_rate - 0.0).abs() < f64::EPSILON);
        assert!(cfg.preserve_order);
    }

    #[test]
    fn sim_transport_config_lossy() {
        let cfg = SimTransportConfig::lossy(0.5);
        assert!((cfg.loss_rate - 0.5).abs() < f64::EPSILON);
        assert_eq!(cfg.base_latency, Duration::ZERO);
    }

    #[test]
    fn sim_transport_config_with_latency() {
        let cfg =
            SimTransportConfig::with_latency(Duration::from_millis(10), Duration::from_millis(5));
        assert_eq!(cfg.base_latency, Duration::from_millis(10));
        assert_eq!(cfg.latency_jitter, Duration::from_millis(5));
    }

    #[test]
    fn sim_transport_config_with_time_getter() {
        set_config_test_time(123);
        let cfg = SimTransportConfig::reliable().with_time_getter(config_test_time);
        assert_eq!((cfg.time_getter)(), Time::from_nanos(123));
    }

    #[test]
    fn sim_transport_config_deterministic() {
        let cfg = SimTransportConfig::deterministic(42);
        assert_eq!(cfg.seed, Some(42));
    }

    #[test]
    fn sim_link_debug_clone() {
        let link = SimLink {
            config: SimTransportConfig::reliable(),
        };
        let dbg = format!("{link:?}");
        assert!(dbg.contains("SimLink"));

        let cloned = link;
        assert_eq!(cloned.config.capacity, 1024);
    }

    #[test]
    fn sim_network_fully_connected_debug() {
        let net = SimNetwork::fully_connected(3, SimTransportConfig::reliable());
        let dbg = format!("{net:?}");
        assert!(dbg.contains("SimNetwork"));
    }

    #[test]
    fn sim_network_fully_connected_link_count() {
        let net = SimNetwork::fully_connected(3, SimTransportConfig::reliable());
        // 3 nodes, 6 directed links (3 * 2)
        assert_eq!(net.links.len(), 6);
        assert_eq!(net.nodes.len(), 3);
    }

    #[test]
    fn sim_network_ring_link_count() {
        let net = SimNetwork::ring(4, SimTransportConfig::reliable());
        // 4 nodes, 8 directed links (4 bidirectional edges)
        assert_eq!(net.links.len(), 8);
        assert_eq!(net.nodes.len(), 4);
    }

    #[test]
    fn sim_network_ring_zero_nodes() {
        let net = SimNetwork::ring(0, SimTransportConfig::reliable());
        assert_eq!(net.nodes.len(), 0);
        assert_eq!(net.links.len(), 0);
    }

    #[test]
    fn sim_network_ring_one_node_has_no_self_link() {
        let net = SimNetwork::ring(1, SimTransportConfig::reliable());
        assert_eq!(net.nodes.len(), 1);
        assert!(net.nodes.contains(&0));
        assert!(
            !net.links.contains_key(&(0, 0)),
            "one-node ring must not create a self transport link"
        );
        assert_eq!(net.links.len(), 0);
    }

    #[test]
    fn sim_network_partition_and_heal() {
        let mut net = SimNetwork::fully_connected(4, SimTransportConfig::reliable());
        assert_eq!(net.links.len(), 12); // 4 * 3

        net.partition(&[0, 1], &[2, 3]);
        // Removed 0->2, 0->3, 1->2, 1->3, 2->0, 2->1, 3->0, 3->1 = 8 links
        assert_eq!(net.links.len(), 4);

        net.heal_partition(&[0, 1], &[2, 3]);
        assert_eq!(net.links.len(), 12);
    }

    #[test]
    fn sim_network_transport_missing_link() {
        // Ring: 0->1, 1->0, 1->2, 2->1, 2->0, 0->2
        // Partition to create a missing link
        let mut net = SimNetwork::ring(3, SimTransportConfig::reliable());
        net.partition(&[0], &[2]);
        // Getting transport for missing link should return a closed channel
        let (_sink, _stream) = net.transport(0, 2);
    }
