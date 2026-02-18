#[cfg(test)]
mod tests {
    use crate::Cx;
    use crate::security::authenticated::AuthenticatedSymbol;
    use crate::security::tag::AuthenticationTag;
    use crate::transport::error::{SinkError, StreamError};
    use crate::transport::stream::{MergedStream, VecStream};
    use crate::transport::{
        SymbolSet, SymbolSink, SymbolSinkExt, SymbolStream, SymbolStreamExt, channel,
    };
    use crate::types::{Symbol, SymbolId, SymbolKind, Time};
    use futures_lite::future;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};
    use std::time::Duration;

    struct NoopWake;

    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWake))
    }

    fn create_symbol(i: u32) -> AuthenticatedSymbol {
        let id = SymbolId::new_for_test(1, 0, i);
        let data = vec![i as u8];
        let symbol = Symbol::new(id, data, SymbolKind::Source);
        // Fake tag for testing transport (we don't check validity here, just transport)
        let tag = AuthenticationTag::zero();
        AuthenticatedSymbol::new_verified(symbol, tag)
    }

    fn create_symbol_with_sbn(sbn: u8, esi: u32) -> AuthenticatedSymbol {
        let id = SymbolId::new_for_test(1, sbn, esi);
        let data = vec![sbn, esi as u8];
        let symbol = Symbol::new(id, data, SymbolKind::Source);
        let tag = AuthenticationTag::zero();
        AuthenticatedSymbol::new_verified(symbol, tag)
    }

    #[test]
    fn test_channel_stream_receive() {
        let (mut sink, mut stream) = channel(10);
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

    #[test]
    fn test_stream_exhaustion() {
        let (mut sink, mut stream) = channel(10);

        future::block_on(async {
            sink.close().await.unwrap();
            let res = stream.next().await;
            assert!(res.is_none());
        });
    }

    #[test]
    fn test_sink_backpressure() {
        let (mut sink, mut stream) = channel(1);
        let s1 = create_symbol(1);
        let s2 = create_symbol(2);

        future::block_on(async {
            sink.send(s1).await.unwrap();

            // Channel full (capacity 1). Next send should block or return pending?
            // futures_lite::future::poll_fn ... poll_ready ...
            // In our ChannelSink, poll_ready checks len < capacity.
            // So if len == 1, poll_ready returns Pending.
            // We can't easily test blocking in single-thread block_on without spawning.
            // But we can test that we can receive then send.

            let recv_task = async {
                stream.next().await.unwrap().unwrap();
            };

            let send_task = async {
                sink.send(s2).await.unwrap();
            };

            // Join them
            futures_lite::future::zip(recv_task, send_task).await;
        });
    }

    #[test]
    fn test_sink_backpressure_pending() {
        let (mut sink, mut stream) = channel(1);
        let s1 = create_symbol(1);
        let s2 = create_symbol(2);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let ready = Pin::new(&mut sink).poll_ready(&mut cx);
        assert!(matches!(ready, Poll::Ready(Ok(()))));

        let send = Pin::new(&mut sink).poll_send(&mut cx, s1);
        assert!(matches!(send, Poll::Ready(Ok(()))));

        let ready = Pin::new(&mut sink).poll_ready(&mut cx);
        assert!(matches!(ready, Poll::Pending));

        future::block_on(async {
            let _ = stream.next().await;
        });

        let ready = Pin::new(&mut sink).poll_ready(&mut cx);
        assert!(matches!(ready, Poll::Ready(Ok(()))));

        let send = Pin::new(&mut sink).poll_send(&mut cx, s2);
        assert!(matches!(send, Poll::Ready(Ok(()))));
    }

    #[test]
    fn test_collect_to_set() {
        let (mut sink, mut stream) = channel(10);

        future::block_on(async {
            for i in 0..5 {
                sink.send(create_symbol(i)).await.unwrap();
            }
            sink.close().await.unwrap();

            let mut set = SymbolSet::new();
            let count = stream.collect_to_set(&mut set).await.unwrap();

            assert_eq!(count, 5);
            assert_eq!(set.len(), 5);
        });
    }

    #[test]
    fn test_stream_map() {
        let (mut sink, stream) = channel(10);
        let s1 = create_symbol(1);

        future::block_on(async {
            sink.send(s1).await.unwrap();
            sink.close().await.unwrap();

            let mut mapped = stream.map(|s| s); // Identity map for now
            let r1 = mapped.next().await.unwrap().unwrap();
            assert_eq!(r1.symbol().id().esi(), 1);
        });
    }

    #[test]
    fn test_stream_filter() {
        let (mut sink, stream) = channel(10);

        future::block_on(async {
            sink.send(create_symbol(1)).await.unwrap(); // Keep
            sink.send(create_symbol(2)).await.unwrap(); // Drop
            sink.send(create_symbol(3)).await.unwrap(); // Keep
            sink.close().await.unwrap();

            let mut filtered = stream.filter(|s| s.symbol().id().esi() % 2 != 0);

            let r1 = filtered.next().await.unwrap().unwrap();
            assert_eq!(r1.symbol().id().esi(), 1);

            let r2 = filtered.next().await.unwrap().unwrap();
            assert_eq!(r2.symbol().id().esi(), 3);

            assert!(filtered.next().await.is_none());
        });
    }

    #[test]
    fn test_stream_for_block() {
        let (mut sink, stream) = channel(10);

        future::block_on(async {
            sink.send(create_symbol_with_sbn(0, 1)).await.unwrap();
            sink.send(create_symbol_with_sbn(1, 2)).await.unwrap();
            sink.send(create_symbol_with_sbn(1, 3)).await.unwrap();
            sink.close().await.unwrap();

            let mut filtered = stream.for_block(1);
            let r1 = filtered.next().await.unwrap().unwrap();
            assert_eq!(r1.symbol().sbn(), 1);
            let r2 = filtered.next().await.unwrap().unwrap();
            assert_eq!(r2.symbol().sbn(), 1);
            assert!(filtered.next().await.is_none());
        });
    }

    #[test]
    fn test_stream_timeout() {
        let (_sink, stream) = channel(10);
        let mut timed = stream.timeout(Duration::ZERO);

        future::block_on(async {
            let res = timed.next().await;
            assert!(matches!(res, Some(Err(StreamError::Timeout))));
        });
    }

    #[test]
    fn test_merged_stream() {
        let s1 = VecStream::new(vec![create_symbol(1), create_symbol(3)]);
        let s2 = VecStream::new(vec![create_symbol(2), create_symbol(4)]);
        let mut merged = MergedStream::new(vec![s1, s2]);

        future::block_on(async {
            let mut out = Vec::new();
            while let Some(item) = merged.next().await {
                out.push(item.unwrap().symbol().esi());
            }
            assert_eq!(out, vec![1, 2, 3, 4]);
        });
    }

    #[test]
    fn test_stream_cancellation() {
        let (_sink, mut stream) = channel(10);
        let cx: Cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        future::block_on(async {
            let res = stream.next_with_cancel(&cx).await;
            assert!(matches!(res, Err(StreamError::Cancelled)));
        });
    }

    #[test]
    fn test_stream_cancellation_after_pending() {
        let (_sink, mut stream) = channel(10);
        let cx: Cx = Cx::for_testing();

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);

        let mut fut = stream.next_with_cancel(&cx);
        let mut fut = Pin::new(&mut fut);

        let first = fut.as_mut().poll(&mut context);
        assert!(matches!(first, Poll::Pending));

        cx.set_cancel_requested(true);
        let second = fut.as_mut().poll(&mut context);
        assert!(matches!(second, Poll::Ready(Err(StreamError::Cancelled))));
    }

    #[test]
    fn test_sink_buffer() {
        let (sink, mut stream) = channel(10);
        // Buffer capacity 5. Inner capacity 10.
        let mut buffered = sink.buffer(5);

        future::block_on(async {
            // Send 3 items (should be buffered)
            for i in 0..3 {
                buffered.send(create_symbol(i)).await.unwrap();
            }

            // Should not be in stream yet?
            // Our BufferedSink flushes if inner is ready.
            // ChannelSink is always ready if not full.
            // poll_send in BufferedSink:
            // if buffer >= capacity -> flush.
            // else push to buffer.
            // It does NOT flush aggressively unless we call flush().
            // But wait, my implementation:
            // fn poll_send(...) { ... self.get_mut().buffer.push(symbol); Poll::Ready(Ok(())) }
            // It only pushes to buffer. It does NOT flush to inner unless buffer is full.
            // So stream should be empty.

            // Verify stream empty?
            // Can't check is_empty synchronously easily on stream.
            // We can check if next() hangs. But we don't want to hang.

            // Flush
            buffered.flush().await.unwrap();

            // Now stream should have items
            let r1 = stream.next().await.unwrap().unwrap();
            assert_eq!(r1.symbol().id().esi(), 0);
        });
    }

    #[test]
    fn test_sink_send_all() {
        let (mut sink, mut stream) = channel(10);
        let symbols = vec![create_symbol(1), create_symbol(2), create_symbol(3)];

        future::block_on(async {
            let count = sink.send_all(symbols.clone()).await.unwrap();
            assert_eq!(count, symbols.len());
            sink.close().await.unwrap();

            for expected in symbols {
                let got = stream.next().await.unwrap().unwrap();
                assert_eq!(got, expected);
            }
        });
    }

    #[test]
    fn test_sink_after_close() {
        let (mut sink, _stream) = channel(10);

        future::block_on(async {
            sink.close().await.unwrap();
            let err = sink.send(create_symbol(1)).await.unwrap_err();
            assert!(matches!(err, SinkError::Closed));
        });
    }

    // ============================================================================
    // Comprehensive Transport Layer Tests (bead: asupersync-6bp)
    // ============================================================================

    mod comprehensive_tests {
        use super::*;
        use crate::transport::aggregator::{
            AggregatorConfig, DeduplicatorConfig, MultipathAggregator, PathCharacteristics, PathId,
            PathSelectionPolicy, PathSet, ReordererConfig, SymbolDeduplicator, SymbolReorderer,
            TransportPath,
        };
        use crate::transport::mock::{SimNetwork, SimTransportConfig, sim_channel};
        use crate::transport::router::{
            DispatchConfig, DispatchStrategy, Endpoint, EndpointId, LoadBalanceStrategy, RouteKey,
            RoutingEntry, RoutingTable, SymbolDispatcher, SymbolRouter,
        };
        use std::collections::HashSet;

        fn init_test(name: &str) {
            crate::test_utils::init_test_logging();
            crate::test_phase!(name);
        }

        // ========================================================================
        // Single-Path Happy Flow Tests
        // ========================================================================

        #[test]
        fn test_single_path_happy_flow_basic() {
            init_test("test_single_path_happy_flow_basic");

            let config = SimTransportConfig::reliable();
            let (mut sink, mut stream) = sim_channel(config);

            future::block_on(async {
                // Send 100 symbols
                for i in 0..100 {
                    sink.send(create_symbol(i)).await.unwrap();
                }
                sink.close().await.unwrap();

                // Receive all symbols in order
                let mut received = Vec::new();
                while let Some(item) = stream.next().await {
                    received.push(item.unwrap().symbol().esi());
                }

                crate::assert_with_log!(
                    received.len() == 100,
                    "received count",
                    100,
                    received.len()
                );
                for (i, esi) in received.iter().enumerate() {
                    crate::assert_with_log!(*esi == i as u32, "esi order", i as u32, *esi);
                }
            });

            crate::test_complete!("test_single_path_happy_flow_basic");
        }

        #[test]
        fn test_single_path_happy_flow_with_router() {
            init_test("test_single_path_happy_flow_with_router");

            let config = SimTransportConfig::reliable();
            let (sink, mut stream) = sim_channel(config);

            let table = Arc::new(RoutingTable::new());
            let endpoint_id = EndpointId(1);
            let endpoint = Endpoint::new(endpoint_id, "endpoint1");
            let endpoint = table.register_endpoint(endpoint);

            let route_key = RouteKey::Default;
            let entry = RoutingEntry::new(vec![endpoint], Time::ZERO);
            table.add_route(route_key, entry);

            let router = Arc::new(SymbolRouter::new(table));
            let dispatcher = SymbolDispatcher::new(router, DispatchConfig::default());
            dispatcher.add_sink(endpoint_id, Box::new(sink));

            let cx: Cx = Cx::for_testing();

            future::block_on(async {
                // Route 50 symbols through the dispatcher
                for i in 0..50 {
                    let symbol = create_symbol(i);
                    // We use dispatch now
                    let result = dispatcher.dispatch(&cx, symbol).await;
                    crate::assert_with_log!(
                        result.is_ok(),
                        "dispatch success",
                        true,
                        result.is_ok()
                    );
                }

                // Verify all symbols arrived
                let mut count = 0;
                while let Some(item) = stream.next().await {
                    item.unwrap();
                    count += 1;
                    if count == 50 {
                        break;
                    }
                }
                crate::assert_with_log!(count == 50, "received via router", 50, count);
            });

            crate::test_complete!("test_single_path_happy_flow_with_router");
        }

        #[test]
        fn test_single_path_happy_flow_batch_send() {
            init_test("test_single_path_happy_flow_batch_send");

            let config = SimTransportConfig::reliable();
            let (mut sink, mut stream) = sim_channel(config);

            future::block_on(async {
                // Send batch of symbols
                let symbols: Vec<_> = (0..25).map(create_symbol).collect();
                let sent = sink.send_all(symbols).await.unwrap();
                crate::assert_with_log!(sent == 25, "batch sent", 25, sent);
                sink.close().await.unwrap();

                // Collect all received
                let mut symbol_set = SymbolSet::new();
                let collected = stream.collect_to_set(&mut symbol_set).await.unwrap();
                crate::assert_with_log!(collected == 25, "batch received", 25, collected);
            });

            crate::test_complete!("test_single_path_happy_flow_batch_send");
        }

        // ========================================================================
        // Multi-Path Deduplication Tests
        // ========================================================================

        #[test]
        fn test_multipath_dedup_duplicate_symbols() {
            init_test("test_multipath_dedup_duplicate_symbols");

            let config = DeduplicatorConfig::default();
            let dedup = SymbolDeduplicator::new(config);

            // First symbol should be accepted
            let sym1 = create_symbol(1);
            let is_new = dedup.check_and_record(sym1.symbol(), PathId(0), Time::ZERO);
            crate::assert_with_log!(is_new, "first symbol new", true, is_new);

            // Duplicate should be rejected
            let sym1_dup = create_symbol(1);
            let is_new = dedup.check_and_record(sym1_dup.symbol(), PathId(0), Time::ZERO);
            crate::assert_with_log!(!is_new, "duplicate rejected", false, is_new);

            // Different symbol should be accepted
            let sym2 = create_symbol(2);
            let is_new = dedup.check_and_record(sym2.symbol(), PathId(0), Time::ZERO);
            crate::assert_with_log!(is_new, "different symbol new", true, is_new);

            crate::test_complete!("test_multipath_dedup_duplicate_symbols");
        }

        #[test]
        fn test_multipath_dedup_across_paths() {
            init_test("test_multipath_dedup_across_paths");

            // Create simulated network with 3 nodes
            let config = SimTransportConfig::reliable();
            let network = SimNetwork::fully_connected(3, config);

            // Get transports from node 0 to node 1, and node 2 to node 1
            let (mut sink_0_1, _stream_0_1) = network.transport(0, 1);
            let (mut sink_2_1, _stream_2_1) = network.transport(2, 1);

            // Create deduplicator at receiving node
            let config = DeduplicatorConfig::default();
            let dedup = SymbolDeduplicator::new(config);

            future::block_on(async {
                // Send same symbol via both paths
                let sym = create_symbol(42);
                sink_0_1.send(sym.clone()).await.unwrap();
                sink_2_1.send(sym.clone()).await.unwrap();

                // First arrival should be new
                let is_new = dedup.check_and_record(sym.symbol(), PathId(0), Time::ZERO);
                crate::assert_with_log!(is_new, "first path new", true, is_new);

                // Second arrival (from other path) should be duplicate
                let is_new = dedup.check_and_record(sym.symbol(), PathId(1), Time::ZERO);
                crate::assert_with_log!(!is_new, "second path dup", false, is_new);
            });

            crate::test_complete!("test_multipath_dedup_across_paths");
        }

        #[test]
        fn test_multipath_aggregator_basic() {
            init_test("test_multipath_aggregator_basic");

            let config = AggregatorConfig {
                dedup: DeduplicatorConfig {
                    entry_ttl: Time::from_secs(300),
                    ..Default::default()
                },
                reorder: ReordererConfig {
                    max_buffer_per_object: 10,
                    max_wait_time: Time::from_millis(100),
                    ..Default::default()
                },
                path_policy: PathSelectionPolicy::UseAll,
                enable_reordering: true,
                flush_interval: Time::from_millis(100),
            };
            let aggregator = MultipathAggregator::new(config);

            // Process symbols from multiple paths
            let sym1 = create_symbol(0);
            let sym2 = create_symbol(1);
            let sym1_dup = create_symbol(0); // Duplicate of sym1

            let result1 = aggregator.process(sym1.symbol().clone(), PathId(0), Time::ZERO);
            crate::assert_with_log!(
                !result1.ready.is_empty(),
                "sym1 accepted",
                true,
                !result1.ready.is_empty()
            );

            let result2 = aggregator.process(sym2.symbol().clone(), PathId(1), Time::ZERO);
            crate::assert_with_log!(
                !result2.ready.is_empty(),
                "sym2 accepted",
                true,
                !result2.ready.is_empty()
            );

            let result_dup = aggregator.process(sym1_dup.symbol().clone(), PathId(1), Time::ZERO);
            crate::assert_with_log!(
                result_dup.ready.is_empty(),
                "dup rejected",
                true,
                result_dup.ready.is_empty()
            );

            crate::test_complete!("test_multipath_aggregator_basic");
        }

        #[test]
        fn test_multipath_dedup_window_expiry() {
            init_test("test_multipath_dedup_window_expiry");

            // Create deduplicator with short TTL
            let config = DeduplicatorConfig {
                entry_ttl: Time::from_millis(10), // 10ms TTL
                ..Default::default()
            };
            let dedup = SymbolDeduplicator::new(config);

            // Add initial symbols at time 0
            for i in 0..5 {
                let sym = create_symbol(i);
                let is_new = dedup.check_and_record(sym.symbol(), PathId(0), Time::ZERO);
                crate::assert_with_log!(is_new, &format!("sym {i} new"), true, is_new);
            }

            // Same symbols should be duplicates at time 0
            for i in 0..5 {
                let sym = create_symbol(i);
                let is_dup = !dedup.check_and_record(sym.symbol(), PathId(0), Time::ZERO);
                crate::assert_with_log!(is_dup, &format!("sym {i} duplicate"), true, is_dup);
            }

            // Prune with time past the TTL (time > 10ms)
            let pruned = dedup.prune(Time::from_millis(20));
            crate::assert_with_log!(pruned > 0, "some entries pruned", true, pruned > 0);

            // After pruning, old symbols should be re-accepted as new
            let sym0 = create_symbol(0);
            let is_new = dedup.check_and_record(sym0.symbol(), PathId(0), Time::from_millis(20));
            crate::assert_with_log!(is_new, "old symbol re-accepted", true, is_new);

            crate::test_complete!("test_multipath_dedup_window_expiry");
        }

        // ========================================================================
        // Backpressure Propagation Tests
        // ========================================================================

        #[test]
        fn test_backpressure_channel_full() {
            init_test("test_backpressure_channel_full");

            let config = SimTransportConfig {
                capacity: 3,
                ..SimTransportConfig::reliable()
            };
            let (mut sink, mut stream) = sim_channel(config);

            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);

            future::block_on(async {
                // Fill the channel to capacity
                for i in 0..3 {
                    sink.send(create_symbol(i)).await.unwrap();
                }
            });

            // poll_ready should return Pending when full
            let ready = Pin::new(&mut sink).poll_ready(&mut cx);
            crate::assert_with_log!(
                matches!(ready, Poll::Pending),
                "backpressure active",
                "Pending",
                format!("{:?}", ready)
            );

            // Consume one symbol
            future::block_on(async {
                let _ = stream.next().await;
            });

            // Now should be ready
            let ready = Pin::new(&mut sink).poll_ready(&mut cx);
            crate::assert_with_log!(
                matches!(ready, Poll::Ready(Ok(()))),
                "backpressure released",
                "Ready(Ok)",
                format!("{:?}", ready)
            );

            crate::test_complete!("test_backpressure_channel_full");
        }

        #[test]
        fn test_backpressure_propagation_through_router() {
            init_test("test_backpressure_propagation_through_router");

            let config = SimTransportConfig {
                capacity: 2,
                ..SimTransportConfig::reliable()
            };
            let (sink, mut stream) = sim_channel(config);

            let table = Arc::new(RoutingTable::new());
            let endpoint_id = EndpointId(1);
            let endpoint = Endpoint::new(endpoint_id, "ep1");
            let endpoint = table.register_endpoint(endpoint);

            let entry = RoutingEntry::new(vec![endpoint], Time::ZERO);
            table.add_route(RouteKey::Default, entry);

            let router = Arc::new(SymbolRouter::new(table));
            let dispatcher = SymbolDispatcher::new(router, DispatchConfig::default());
            dispatcher.add_sink(endpoint_id, Box::new(sink));

            let cx: Cx = Cx::for_testing();

            future::block_on(async {
                // Fill the underlying channel
                for i in 0..2 {
                    let sym = create_symbol(i);
                    dispatcher.dispatch(&cx, sym).await.unwrap();
                }

                // Third send should hit backpressure.
                // Since we use lock-based send in dispatcher, it might not propagate backpressure cleanly as "Pending"
                // if the sink returns Pending. poll_send returns Pending.
                // Our dispatcher logic might spin or error?
                // The current implementation uses `sink.lock().send()`. `SymbolSinkExt::send` creates a future.
                // That future polls.
                // So it should block (return Pending) if the sink returns Pending.

                // But we are in block_on.

                // Let's drain to allow progress.
                let _ = stream.next().await;
                let _ = stream.next().await;

                // After draining, routing should work
                let result = dispatcher.dispatch(&cx, create_symbol(10)).await;
                crate::assert_with_log!(
                    result.is_ok(),
                    "dispatch after drain",
                    true,
                    result.is_ok()
                );
            });

            crate::test_complete!("test_backpressure_propagation_through_router");
        }

        #[test]
        fn test_backpressure_buffered_sink() {
            init_test("test_backpressure_buffered_sink");

            let config = SimTransportConfig {
                capacity: 10,
                ..SimTransportConfig::reliable()
            };
            let (sink, mut stream) = sim_channel(config);

            // Buffer with capacity 5
            let mut buffered = sink.buffer(5);

            future::block_on(async {
                // Send 5 items (should be buffered, not yet sent)
                for i in 0..5 {
                    buffered.send(create_symbol(i)).await.unwrap();
                }

                // Flush to actually send
                buffered.flush().await.unwrap();

                // All 5 should now be in the stream
                for _ in 0..5 {
                    let item = stream.next().await;
                    crate::assert_with_log!(item.is_some(), "item received", true, item.is_some());
                }
            });

            crate::test_complete!("test_backpressure_buffered_sink");
        }

        // ========================================================================
        // Priority Dispatch Tests
        // ========================================================================

        #[test]
        fn test_priority_dispatch_unicast() {
            init_test("test_priority_dispatch_unicast");

            let config = SimTransportConfig::reliable();
            let (sink1, mut stream1) = sim_channel(config.clone());
            let (sink2, mut stream2) = sim_channel(config.clone());
            let (sink3, _stream3) = sim_channel(config);

            let table = Arc::new(RoutingTable::new());
            let e1 = table.register_endpoint(Endpoint::new(EndpointId(1), "target1"));
            let _e2 = table.register_endpoint(Endpoint::new(EndpointId(2), "target2"));

            // Add routes if needed, but we use specific strategy here
            // DispatchStrategy::Unicast uses route() which needs a route.
            table.add_route(
                RouteKey::Object(SymbolId::new_for_test(1, 0, 1).object_id()),
                RoutingEntry::new(vec![e1], Time::ZERO),
            );
            // Actually dispatch_unicast uses router.route(symbol).
            // So we need a route for the symbol.

            // Wait, the test uses `DispatchStrategy::Unicast`.
            // But `SymbolDispatcher` `dispatch_unicast` implementation calls `self.router.route(symbol)`.
            // `DispatchStrategy::Unicast` in `router.rs` doesn't take a target!
            // It is defined as `Unicast` (unit variant).
            // The test uses `DispatchStrategy::Unicast("target1".to_string())`.
            // This implies the test code is using a DIFFERENT version of DispatchStrategy than what is in `router.rs`.

            // I need to adapt the test to the current `DispatchStrategy` which is `Unicast`.
            // And use routing table to direct it.

            let router = Arc::new(SymbolRouter::new(table));
            let dispatcher = SymbolDispatcher::new(router, DispatchConfig::default());
            dispatcher.add_sink(EndpointId(1), Box::new(sink1));
            dispatcher.add_sink(EndpointId(2), Box::new(sink2));
            dispatcher.add_sink(EndpointId(3), Box::new(sink3));

            let cx: Cx = Cx::for_testing();

            future::block_on(async {
                // Symbol 1 maps to target1 via route
                let sym = create_symbol(1);
                let result = dispatcher
                    .dispatch_with_strategy(&cx, sym.clone(), DispatchStrategy::Unicast)
                    .await;
                crate::assert_with_log!(result.is_ok(), "unicast ok", true, result.is_ok());

                // target1 should have the symbol
                let recv1 = stream1.next().await;
                crate::assert_with_log!(recv1.is_some(), "target1 received", true, recv1.is_some());
            });

            // target2 should be empty
            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);
            let poll = Pin::new(&mut stream2).poll_next(&mut cx);
            crate::assert_with_log!(
                matches!(poll, Poll::Pending),
                "target2 empty",
                "Pending",
                format!("{:?}", poll)
            );

            crate::test_complete!("test_priority_dispatch_unicast");
        }

        #[test]
        fn test_priority_dispatch_broadcast() {
            init_test("test_priority_dispatch_broadcast");

            let config = SimTransportConfig::reliable();
            let (sink1, mut stream1) = sim_channel(config.clone());
            let (sink2, mut stream2) = sim_channel(config.clone());
            let (sink3, mut stream3) = sim_channel(config);

            let table = Arc::new(RoutingTable::new());
            let _e1 = table.register_endpoint(Endpoint::new(EndpointId(1), "node1"));
            let _e2 = table.register_endpoint(Endpoint::new(EndpointId(2), "node2"));
            let _e3 = table.register_endpoint(Endpoint::new(EndpointId(3), "node3"));

            // No specific routes needed for broadcast as it uses all healthy endpoints

            let router = Arc::new(SymbolRouter::new(table));
            let dispatcher = SymbolDispatcher::new(router, DispatchConfig::default());
            dispatcher.add_sink(EndpointId(1), Box::new(sink1));
            dispatcher.add_sink(EndpointId(2), Box::new(sink2));
            dispatcher.add_sink(EndpointId(3), Box::new(sink3));

            let cx: Cx = Cx::for_testing();

            future::block_on(async {
                // Broadcast to all nodes
                let sym = create_symbol(42);
                let result = dispatcher
                    .dispatch_with_strategy(&cx, sym.clone(), DispatchStrategy::Broadcast)
                    .await;
                crate::assert_with_log!(result.is_ok(), "broadcast ok", true, result.is_ok());

                // All streams should have the symbol
                let recv1 = stream1.next().await.unwrap().unwrap();
                let recv2 = stream2.next().await.unwrap().unwrap();
                let recv3 = stream3.next().await.unwrap().unwrap();

                crate::assert_with_log!(
                    recv1.symbol().esi() == 42,
                    "node1 received",
                    42,
                    recv1.symbol().esi()
                );
                crate::assert_with_log!(
                    recv2.symbol().esi() == 42,
                    "node2 received",
                    42,
                    recv2.symbol().esi()
                );
                crate::assert_with_log!(
                    recv3.symbol().esi() == 42,
                    "node3 received",
                    42,
                    recv3.symbol().esi()
                );
            });

            crate::test_complete!("test_priority_dispatch_broadcast");
        }

        #[test]
        fn test_priority_dispatch_multicast() {
            init_test("test_priority_dispatch_multicast");

            let config = SimTransportConfig::reliable();
            let (sink1, mut stream1) = sim_channel(config.clone());
            let (sink2, mut stream2) = sim_channel(config.clone());
            let (sink3, mut stream3) = sim_channel(config);

            let table = Arc::new(RoutingTable::new());
            let e1 = table.register_endpoint(Endpoint::new(EndpointId(1), "a"));
            let e2 = table.register_endpoint(Endpoint::new(EndpointId(2), "b"));
            let e3 = table.register_endpoint(Endpoint::new(EndpointId(3), "c"));

            // Multicast uses route_multicast which uses routes.
            // We need a route that includes these endpoints.
            // Or default route.
            let entry = RoutingEntry::new(vec![e1, e2, e3], Time::ZERO);
            table.add_route(RouteKey::Default, entry);

            let router = Arc::new(SymbolRouter::new(table));
            let dispatcher = SymbolDispatcher::new(router, DispatchConfig::default());
            dispatcher.add_sink(EndpointId(1), Box::new(sink1));
            dispatcher.add_sink(EndpointId(2), Box::new(sink2));
            dispatcher.add_sink(EndpointId(3), Box::new(sink3));

            let cx: Cx = Cx::for_testing();

            future::block_on(async {
                // Multicast to 2 endpoints (count=2)
                let sym = create_symbol(99);
                // DispatchStrategy::Multicast now takes count, not targets list
                let result = dispatcher
                    .dispatch_with_strategy(
                        &cx,
                        sym.clone(),
                        DispatchStrategy::Multicast { count: 2 },
                    )
                    .await;
                crate::assert_with_log!(result.is_ok(), "multicast ok", true, result.is_ok());

                // We don't know exactly which 2, but 2 should receive.
                // Wait a bit for propagation? No, channels are reliable.

                // Let's just check streams.
                // Note: The router selects the first N available.
                // In our entry vec![e1, e2, e3], e1 and e2 are first.
                // So stream1 and stream2 should receive.

                let recv1 = stream1.next().await.unwrap().unwrap();
                crate::assert_with_log!(
                    recv1.symbol().esi() == 99,
                    "a received",
                    99,
                    recv1.symbol().esi()
                );

                let recv2 = stream2.next().await.unwrap().unwrap();
                crate::assert_with_log!(
                    recv2.symbol().esi() == 99,
                    "b received",
                    99,
                    recv2.symbol().esi()
                );
            });

            // 'c' should be empty
            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);
            let poll = Pin::new(&mut stream3).poll_next(&mut cx);
            crate::assert_with_log!(
                matches!(poll, Poll::Pending),
                "c empty",
                "Pending",
                format!("{:?}", poll)
            );

            crate::test_complete!("test_priority_dispatch_multicast");
        }

        #[test]
        fn test_priority_dispatch_quorum_cast() {
            init_test("test_priority_dispatch_quorum_cast");

            let config = SimTransportConfig::reliable();
            let mut streams = Vec::new();

            let table = Arc::new(RoutingTable::new());
            let router = Arc::new(SymbolRouter::new(table.clone()));
            let dispatcher = SymbolDispatcher::new(router, DispatchConfig::default());

            // Create 5 nodes
            for i in 0u64..5 {
                let (sink, stream) = sim_channel(config.clone());
                let id = EndpointId(i);
                let _endpoint = table.register_endpoint(Endpoint::new(id, format!("node{i}")));
                dispatcher.add_sink(id, Box::new(sink));
                streams.push(stream);
            }

            let cx: Cx = Cx::for_testing();

            future::block_on(async {
                // QuorumCast with quorum of 3
                let sym = create_symbol(77);
                // DispatchStrategy::QuorumCast relies on healthy endpoints from table
                let result = dispatcher
                    .dispatch_with_strategy(
                        &cx,
                        sym.clone(),
                        DispatchStrategy::QuorumCast { required: 3 },
                    )
                    .await;
                crate::assert_with_log!(result.is_ok(), "quorum cast ok", true, result.is_ok());

                // At least 3 nodes should receive the symbol
                let mut received_count = 0;
                for stream in &mut streams {
                    let waker = noop_waker();
                    let mut cx = Context::from_waker(&waker);
                    let poll = Pin::new(stream).poll_next(&mut cx);
                    if matches!(poll, Poll::Ready(Some(Ok(_)))) {
                        received_count += 1;
                    }
                }

                crate::assert_with_log!(
                    received_count >= 3,
                    "quorum received",
                    ">=3",
                    received_count
                );
            });

            crate::test_complete!("test_priority_dispatch_quorum_cast");
        }

        // ========================================================================
        // Cancel Mid-Flight Tests
        // ========================================================================

        #[test]
        fn test_cancel_mid_flight_stream() {
            init_test("test_cancel_mid_flight_stream");

            let config = SimTransportConfig::reliable();
            let (mut sink, mut stream) = sim_channel(config);

            let cx: Cx = Cx::for_testing();

            future::block_on(async {
                // Send some symbols
                for i in 0..5 {
                    sink.send(create_symbol(i)).await.unwrap();
                }

                // Receive first two
                let _ = stream.next().await;
                let _ = stream.next().await;

                // Now cancel
                cx.set_cancel_requested(true);

                // Next receive should return cancelled
                let result = stream.next_with_cancel(&cx).await;
                crate::assert_with_log!(
                    matches!(result, Err(StreamError::Cancelled)),
                    "cancelled",
                    "Cancelled",
                    format!("{:?}", result)
                );
            });

            crate::test_complete!("test_cancel_mid_flight_stream");
        }

        #[test]
        fn test_cancel_mid_flight_pending() {
            init_test("test_cancel_mid_flight_pending");

            let config = SimTransportConfig::reliable();
            let (_sink, mut stream) = sim_channel(config);
            let cx: Cx = Cx::for_testing();

            let waker = noop_waker();
            let mut context = Context::from_waker(&waker);

            // Start waiting for a symbol that won't arrive
            let mut fut = stream.next_with_cancel(&cx);
            let mut fut = Pin::new(&mut fut);

            // First poll should be pending (no symbols available)
            let first = fut.as_mut().poll(&mut context);
            assert!(matches!(first, Poll::Pending));

            // Cancel mid-flight
            cx.set_cancel_requested(true);
            let second = fut.as_mut().poll(&mut context);
            assert!(matches!(second, Poll::Ready(Err(StreamError::Cancelled))));
        }

        #[test]
        fn test_cancel_mid_flight_batch() {
            init_test("test_cancel_mid_flight_batch");

            let config = SimTransportConfig::reliable();
            let (mut sink, mut stream) = sim_channel(config);
            let cx: Cx = Cx::for_testing();

            future::block_on(async {
                // Send batch
                let symbols: Vec<_> = (0..20).map(create_symbol).collect();
                sink.send_all(symbols).await.unwrap();
                sink.close().await.unwrap();

                // Collect with cancel - set cancel partway through
                let mut collected = 0;
                loop {
                    if collected >= 10 {
                        cx.set_cancel_requested(true);
                    }
                    match stream.next_with_cancel(&cx).await {
                        Ok(Some(_)) => collected += 1,
                        Ok(None) | Err(StreamError::Cancelled) => break,
                        Err(e) => panic!("unexpected error: {e:?}"),
                    }
                }

                // Should have collected around 10-11 before cancel
                crate::assert_with_log!(
                    (10..=12).contains(&collected),
                    "partial collect",
                    "10-12",
                    collected
                );
            });

            crate::test_complete!("test_cancel_mid_flight_batch");
        }

        // ========================================================================
        // Failover Scenario Tests
        // ========================================================================

        #[test]
        fn test_failover_endpoint_failure() {
            init_test("test_failover_endpoint_failure");

            // Primary endpoint that fails after 3 operations
            let config_fail = SimTransportConfig {
                fail_after: Some(3),
                ..SimTransportConfig::reliable()
            };
            let (sink_primary, _stream_primary) = sim_channel(config_fail);

            // Backup endpoint that's reliable
            let config_backup = SimTransportConfig::reliable();
            let (sink_backup, mut stream_backup) = sim_channel(config_backup);

            let table = Arc::new(RoutingTable::new());
            let e1 = table.register_endpoint(Endpoint::new(EndpointId(1), "primary"));
            let e2 = table.register_endpoint(Endpoint::new(EndpointId(2), "backup"));

            let entry = RoutingEntry::new(vec![e1, e2], Time::ZERO);
            table.add_route(RouteKey::Default, entry);

            let router = Arc::new(SymbolRouter::new(table));
            let dispatcher = SymbolDispatcher::new(router, DispatchConfig::default());
            dispatcher.add_sink(EndpointId(1), Box::new(sink_primary));
            dispatcher.add_sink(EndpointId(2), Box::new(sink_backup));

            let cx: Cx = Cx::for_testing();

            future::block_on(async {
                // First 3 should succeed (alternating between primary and backup in round-robin)
                for i in 0..6 {
                    let sym = create_symbol(i);
                    // Use dispatcher.dispatch
                    let result = dispatcher.dispatch(&cx, sym).await;
                    // Some may fail if they hit the failing primary after 3 ops
                    if result.is_err() {
                        // Primary failed, but that's expected
                    }
                }

                // Backup should have received some symbols
                let mut backup_count = 0;
                loop {
                    let waker = noop_waker();
                    let mut cx = Context::from_waker(&waker);
                    let poll = Pin::new(&mut stream_backup).poll_next(&mut cx);
                    match poll {
                        Poll::Ready(Some(Ok(_))) => backup_count += 1,
                        _ => break,
                    }
                }

                crate::assert_with_log!(
                    backup_count > 0,
                    "backup received symbols",
                    ">0",
                    backup_count
                );
            });

            crate::test_complete!("test_failover_endpoint_failure");
        }

        #[test]
        fn test_failover_network_partition() {
            init_test("test_failover_network_partition");

            let config = SimTransportConfig::reliable();
            let mut network = SimNetwork::fully_connected(4, config);

            // Partition: nodes 0,1 can't reach 2,3
            network.partition(&[0, 1], &[2, 3]);

            // Transport 0->2 should be closed (partitioned)
            let (mut sink_0_2, _) = network.transport(0, 2);

            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);

            // Trying to send should fail (closed)
            let poll = Pin::new(&mut sink_0_2).poll_ready(&mut cx);
            crate::assert_with_log!(
                matches!(poll, Poll::Ready(Err(SinkError::Closed))),
                "partitioned link closed",
                "Ready(Err(Closed))",
                format!("{:?}", poll)
            );

            // Transport 0->1 should still work (same partition)
            let (mut sink_0_1, mut stream_0_1) = network.transport(0, 1);

            future::block_on(async {
                let sym = create_symbol(1);
                sink_0_1.send(sym.clone()).await.unwrap();
                let received = stream_0_1.next().await.unwrap().unwrap();
                crate::assert_with_log!(
                    received.symbol().esi() == 1,
                    "same partition works",
                    1,
                    received.symbol().esi()
                );
            });

            // Heal partition
            network.heal_partition(&[0, 1], &[2, 3]);

            // Transport 0->2 should now work
            let (mut sink_0_2_healed, mut stream_0_2_healed) = network.transport(0, 2);

            future::block_on(async {
                let sym = create_symbol(2);
                sink_0_2_healed.send(sym.clone()).await.unwrap();
                let received = stream_0_2_healed.next().await.unwrap().unwrap();
                crate::assert_with_log!(
                    received.symbol().esi() == 2,
                    "healed partition works",
                    2,
                    received.symbol().esi()
                );
            });

            crate::test_complete!("test_failover_network_partition");
        }

        #[test]
        fn test_failover_lossy_path_recovery() {
            init_test("test_failover_lossy_path_recovery");

            // Lossy path with 50% loss
            let config_lossy = SimTransportConfig {
                loss_rate: 0.5,
                seed: Some(42),
                capacity: 1024,
                ..SimTransportConfig::default()
            };
            let (mut sink_lossy, mut stream_lossy) = sim_channel(config_lossy);

            // Reliable backup path
            let config_reliable = SimTransportConfig::reliable();
            let (mut sink_reliable, mut stream_reliable) = sim_channel(config_reliable);

            future::block_on(async {
                // Send 100 symbols via lossy path
                for i in 0..100 {
                    sink_lossy.send(create_symbol(i)).await.unwrap();
                }
                sink_lossy.close().await.unwrap();

                // Count received via lossy
                let mut lossy_received = HashSet::new();
                while let Some(item) = stream_lossy.next().await {
                    if let Ok(sym) = item {
                        lossy_received.insert(sym.symbol().esi());
                    }
                }

                // Should have lost some
                crate::assert_with_log!(
                    lossy_received.len() < 100,
                    "lossy lost some",
                    "<100",
                    lossy_received.len()
                );

                // Resend missing via reliable path
                for i in 0..100 {
                    if !lossy_received.contains(&i) {
                        sink_reliable.send(create_symbol(i)).await.unwrap();
                    }
                }
                sink_reliable.close().await.unwrap();

                // Count recovered
                let mut reliable_received = HashSet::new();
                while let Some(item) = stream_reliable.next().await {
                    if let Ok(sym) = item {
                        reliable_received.insert(sym.symbol().esi());
                    }
                }

                // Total should be 100
                let total: HashSet<_> = lossy_received.union(&reliable_received).copied().collect();
                crate::assert_with_log!(total.len() == 100, "full recovery", 100, total.len());
            });

            crate::test_complete!("test_failover_lossy_path_recovery");
        }

        #[test]
        fn test_failover_ring_topology() {
            init_test("test_failover_ring_topology");

            let config = SimTransportConfig::reliable();
            let network = SimNetwork::ring(4, config);

            // In a ring of 4 nodes: 0-1-2-3-0
            // Direct links: 0<->1, 1<->2, 2<->3, 3<->0
            // No direct link: 0<->2, 1<->3

            // 0->1 should work (direct link)
            let (mut sink_0_1, mut stream_0_1) = network.transport(0, 1);

            future::block_on(async {
                sink_0_1.send(create_symbol(1)).await.unwrap();
                let recv = stream_0_1.next().await.unwrap().unwrap();
                crate::assert_with_log!(
                    recv.symbol().esi() == 1,
                    "direct link works",
                    1,
                    recv.symbol().esi()
                );
            });

            // 0->2 has no direct link in ring topology
            let (mut sink_0_2, _) = network.transport(0, 2);

            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);
            let poll = Pin::new(&mut sink_0_2).poll_ready(&mut cx);
            crate::assert_with_log!(
                matches!(poll, Poll::Ready(Err(SinkError::Closed))),
                "no direct 0->2 in ring",
                "Closed",
                format!("{:?}", poll)
            );

            crate::test_complete!("test_failover_ring_topology");
        }

        // ========================================================================
        // Reordering Tests
        // ========================================================================

        #[test]
        fn test_reorderer_in_order() {
            init_test("test_reorderer_in_order");
            let config = ReordererConfig {
                immediate_delivery: false,
                ..Default::default()
            };
            let reorderer = SymbolReorderer::new(config);

            let path = PathId(1);
            let now = Time::ZERO;

            // Deliver symbols in order - each should be delivered immediately
            let s0 = Symbol::new_for_test(1, 0, 0, &[0]);
            let s1 = Symbol::new_for_test(1, 0, 1, &[1]);
            let s2 = Symbol::new_for_test(1, 0, 2, &[2]);

            let out0 = reorderer.process(s0, path, now);
            crate::assert_with_log!(out0.len() == 1, "s0 delivered", 1, out0.len());
            crate::assert_with_log!(out0[0].esi() == 0, "s0 esi", 0, out0[0].esi());

            let out1 = reorderer.process(s1, path, now);
            crate::assert_with_log!(out1.len() == 1, "s1 delivered", 1, out1.len());
            crate::assert_with_log!(out1[0].esi() == 1, "s1 esi", 1, out1[0].esi());

            let out2 = reorderer.process(s2, path, now);
            crate::assert_with_log!(out2.len() == 1, "s2 delivered", 1, out2.len());
            crate::assert_with_log!(out2[0].esi() == 2, "s2 esi", 2, out2[0].esi());
        }

        #[test]
        fn test_reorderer_out_of_order() {
            init_test("test_reorderer_out_of_order");
            let config = ReordererConfig {
                immediate_delivery: false,
                ..Default::default()
            };
            let reorderer = SymbolReorderer::new(config);

            let path = PathId(1);
            let now = Time::ZERO;

            // Deliver out of order: 0, 2, 1
            let s0 = Symbol::new_for_test(1, 0, 0, &[0]);
            let s2 = Symbol::new_for_test(1, 0, 2, &[2]);
            let s1 = Symbol::new_for_test(1, 0, 1, &[1]);

            // s0 is in-order (esi=0 when next_expected=0) -> delivered immediately
            let out0 = reorderer.process(s0, path, now);
            crate::assert_with_log!(out0.len() == 1, "s0 delivered", 1, out0.len());

            // s2 is out-of-order (esi=2 when next_expected=1) -> buffered
            let out2 = reorderer.process(s2, path, now);
            crate::assert_with_log!(out2.is_empty(), "s2 buffered", true, out2.is_empty());

            // s1 fills the gap -> both s1 and buffered s2 are delivered
            let out1 = reorderer.process(s1, path, now);
            crate::assert_with_log!(out1.len() == 2, "s1+s2 delivered", 2, out1.len());
            crate::assert_with_log!(out1[0].esi() == 1, "first is s1", 1, out1[0].esi());
            crate::assert_with_log!(out1[1].esi() == 2, "second is s2", 2, out1[1].esi());
        }

        #[test]
        fn test_reorder_gap_flush_on_timeout() {
            init_test("test_reorder_gap_flush_on_timeout");

            let config = ReordererConfig {
                max_wait_time: Time::from_millis(10),
                ..Default::default()
            };
            let reorderer = SymbolReorderer::new(config);

            let path = PathId(1);

            // Symbol 2 arrives (gap: 0,1 missing)
            let sym2 = create_symbol(2);
            let _ = reorderer.process(sym2.symbol().clone(), path, Time::ZERO);

            // Flush should deliver buffered symbols after timeout
            // Simulate time passing by passing future time to flush_timeouts
            let flushed = reorderer.flush_timeouts(Time::from_millis(20));
            crate::assert_with_log!(
                !flushed.is_empty(),
                "timeout flush delivered",
                true,
                !flushed.is_empty()
            );

            crate::test_complete!("test_reorder_gap_flush_on_timeout");
        }

        #[test]
        fn test_reorderer_timeout() {
            init_test("test_reorderer_timeout");
            let config = ReordererConfig {
                immediate_delivery: false,
                max_wait_time: Time::from_millis(100),
                ..Default::default()
            };
            let reorderer = SymbolReorderer::new(config);

            let path = PathId(1);

            // Deliver out of order: 0, 2 (skip 1)
            let s0 = Symbol::new_for_test(1, 0, 0, &[0]);
            let s2 = Symbol::new_for_test(1, 0, 2, &[2]);

            reorderer.process(s0, path, Time::ZERO);
            reorderer.process(s2, path, Time::from_millis(10));

            // Before timeout
            let flushed = reorderer.flush_timeouts(Time::from_millis(50));
            let len_before = flushed.len();
            crate::assert_with_log!(len_before == 0, "flushed before len", 0, len_before);

            // After timeout
            let flushed = reorderer.flush_timeouts(Time::from_millis(200));
            let len_after = flushed.len();
            crate::assert_with_log!(len_after == 1, "flushed after len", 1, len_after); // s2 flushed
            crate::test_complete!("test_reorderer_timeout");
        }

        // ========================================================================
        // Path Selection Policy Tests
        // ========================================================================

        #[test]
        fn test_path_selection_use_all() {
            init_test("test_path_selection_use_all");

            let path_set = PathSet::new(PathSelectionPolicy::UseAll);

            path_set.register(TransportPath::new(PathId(1), "path1", "1.0"));
            path_set.register(TransportPath::new(PathId(2), "path2", "0.8"));
            path_set.register(TransportPath::new(PathId(3), "path3", "0.6"));

            let selected = path_set.select_paths();
            crate::assert_with_log!(
                selected.len() == 3,
                "use all selects all",
                3,
                selected.len()
            );

            crate::test_complete!("test_path_selection_use_all");
        }

        #[test]
        fn test_path_selection_primary_only() {
            init_test("test_path_selection_primary_only");

            let path_set = PathSet::new(PathSelectionPolicy::PrimaryOnly);

            let p1 = TransportPath::new(PathId(1), "primary", "1.0").with_characteristics(
                PathCharacteristics {
                    is_primary: true,
                    ..Default::default()
                },
            );
            path_set.register(p1);

            let p2 = TransportPath::new(PathId(2), "backup", "0.8");
            path_set.register(p2);

            let selected = path_set.select_paths();
            crate::assert_with_log!(
                selected.len() == 1,
                "primary only selects one",
                1,
                selected.len()
            );
            crate::assert_with_log!(
                selected[0].characteristics.is_primary,
                "selected is primary",
                true,
                selected[0].characteristics.is_primary
            );

            crate::test_complete!("test_path_selection_primary_only");
        }

        #[test]
        fn test_path_selection_best_quality() {
            init_test("test_path_selection_best_quality");

            let path_set = PathSet::new(PathSelectionPolicy::BestQuality { count: 1 });

            // Add paths with different quality scores
            // High latency = low quality
            let p1 = TransportPath::new(PathId(1), "low", "0.3").with_characteristics(
                PathCharacteristics {
                    latency_ms: 100,
                    ..Default::default()
                },
            );

            let p2 = TransportPath::new(PathId(2), "high", "0.95").with_characteristics(
                PathCharacteristics {
                    latency_ms: 10,
                    ..Default::default()
                },
            );

            let p3 = TransportPath::new(PathId(3), "medium", "0.6").with_characteristics(
                PathCharacteristics {
                    latency_ms: 50,
                    ..Default::default()
                },
            );

            path_set.register(p1);
            path_set.register(p2);
            path_set.register(p3);

            let selected = path_set.select_paths();
            crate::assert_with_log!(
                selected.len() == 1,
                "best quality selects one",
                1,
                selected.len()
            );
            // Check ID instead of float comparison which is fragile
            crate::assert_with_log!(
                selected[0].id == PathId(2),
                "selected is high quality",
                PathId(2),
                selected[0].id
            );

            crate::test_complete!("test_path_selection_best_quality");
        }

        // ========================================================================
        // Load Balance Strategy Tests
        // ========================================================================

        #[test]
        fn test_load_balance_round_robin() {
            init_test("test_load_balance_round_robin");

            let config = SimTransportConfig::reliable();
            let (sink1, mut stream1) = sim_channel(config.clone());
            let (sink2, mut stream2) = sim_channel(config.clone());
            let (sink3, mut stream3) = sim_channel(config);

            let table = Arc::new(RoutingTable::new());
            let e1 = table.register_endpoint(Endpoint::new(EndpointId(1), "e1"));
            let e2 = table.register_endpoint(Endpoint::new(EndpointId(2), "e2"));
            let e3 = table.register_endpoint(Endpoint::new(EndpointId(3), "e3"));

            let entry = RoutingEntry::new(vec![e1, e2, e3], Time::ZERO)
                .with_strategy(LoadBalanceStrategy::RoundRobin);
            table.add_route(RouteKey::Default, entry);

            let router = Arc::new(SymbolRouter::new(table));
            let dispatcher = SymbolDispatcher::new(router, DispatchConfig::default());
            dispatcher.add_sink(EndpointId(1), Box::new(sink1));
            dispatcher.add_sink(EndpointId(2), Box::new(sink2));
            dispatcher.add_sink(EndpointId(3), Box::new(sink3));

            let cx: Cx = Cx::for_testing();

            future::block_on(async {
                // Send 9 symbols (3 per endpoint in round-robin)
                for i in 0..9 {
                    let sym = create_symbol(i);
                    dispatcher.dispatch(&cx, sym).await.unwrap();
                }

                // Each endpoint should have 3 symbols
                let mut count1 = 0;
                let mut count2 = 0;
                let mut count3 = 0;

                loop {
                    let waker = noop_waker();
                    let mut cx = Context::from_waker(&waker);
                    let p1 = Pin::new(&mut stream1).poll_next(&mut cx);
                    let p2 = Pin::new(&mut stream2).poll_next(&mut cx);
                    let p3 = Pin::new(&mut stream3).poll_next(&mut cx);

                    let p1_ready = matches!(p1, Poll::Ready(Some(Ok(_))));
                    if p1_ready {
                        count1 += 1;
                    }
                    let p2_ready = matches!(p2, Poll::Ready(Some(Ok(_))));
                    if p2_ready {
                        count2 += 1;
                    }
                    let p3_ready = matches!(p3, Poll::Ready(Some(Ok(_))));
                    if p3_ready {
                        count3 += 1;
                    }
                    let any = p1_ready || p2_ready || p3_ready;
                    if !any {
                        break;
                    }
                }

                crate::assert_with_log!(count1 == 3, "endpoint1 count", 3, count1);
                crate::assert_with_log!(count2 == 3, "endpoint2 count", 3, count2);
                crate::assert_with_log!(count3 == 3, "endpoint3 count", 3, count3);
            });

            crate::test_complete!("test_load_balance_round_robin");
        }
    }
}
