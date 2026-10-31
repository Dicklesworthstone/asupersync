    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::security::authenticated::AuthenticatedSymbol;
    use crate::security::tag::AuthenticationTag;
    use crate::transport::SharedChannel;
    use crate::transport::channel;
    use crate::transport::stream::SymbolStream;
    use crate::transport::stream::SymbolStreamExt;
    use crate::types::{Symbol, SymbolId, SymbolKind};
    use futures_lite::future;
    use parking_lot::Mutex;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Poll, Waker};

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

    fn queued_symbol_ids(shared: &SharedChannel) -> Vec<u32> {
        shared
            .queue
            .lock()
            .iter()
            .map(|symbol| symbol.symbol().id().esi())
            .collect()
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

    fn multipath_quality(rtt: u32) -> PathQualitySnapshot {
        PathQualitySnapshot::new(rtt, 0, 0)
    }

    fn repair_symbol(esi: u32) -> AuthenticatedSymbol {
        AuthenticatedSymbol::from_parts(
            Symbol::new(SymbolId::new_for_test(1, 0, esi), vec![esi as u8], SymbolKind::Repair),
            AuthenticationTag::zero(),
        )
    }

    #[test]
    fn multipath_bounds_refuse_before_retaining_or_polling_input() {
        for limits in [(0, 1, 1), (1025, 1, 1), (1, 0, 1), (1, 1, 0), (2, usize::MAX, 8)] {
            assert!(MultipathSink::new(limits.0, limits.1, limits.2).is_err());
        }
        let mut sink = MultipathSink::new(1, 1, 1).unwrap();
        let (output, _input) = channel(1);
        sink.add_path(PathId(1), multipath_quality(0), output).unwrap();
        let (duplicate, _duplicate_rx) = channel(1);
        assert!(sink.add_path(PathId(1), multipath_quality(0), duplicate).is_err());
        let (excess, _excess_rx) = channel(1);
        assert!(sink.add_path(PathId(2), multipath_quality(0), excess).is_err());
        let oversized = AuthenticatedSymbol::from_parts(
            Symbol::new(SymbolId::new_for_test(1, 0, 4), vec![1, 2], SymbolKind::Source),
            AuthenticationTag::zero(),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(Pin::new(&mut sink).poll_send(&mut cx, oversized), Poll::Ready(Err(_))));
        assert_eq!(sink.path_stats(PathId(1)).unwrap(), MultipathPathStats::default());
        assert!(sink.update_path_quality(PathId(1), PathQualitySnapshot {
            rtt_ewma_ms: u32::MAX,
            loss_ewma_permille: u16::MAX,
            reorder_depth: u16::MAX,
        }));
        assert_eq!(sink.paths[0].weight, 1);
        assert!(!sink.update_path_quality(PathId(99), multipath_quality(0)));
        let mut data = Vec::with_capacity(4096);
        data.push(7);
        // Since f1f086db6 (br-asupersync-srqosl) new_verified reports the zero
        // sentinel tag as unverified. Use a real tag so the retained copy can
        // show that it keeps the verified state.
        let spare = Symbol::new(SymbolId::new_for_test(1, 0, 0), data, SymbolKind::Source);
        let tag = AuthenticationTag::compute(&crate::security::AuthKey::from_seed(0x3bb2), &spare);
        let spare_capacity = AuthenticatedSymbol::new_verified(spare, tag);
        assert!(spare_capacity.is_verified());
        assert!(matches!(
            Pin::new(&mut sink).poll_send(&mut cx, spare_capacity),
            Poll::Ready(Ok(()))
        ));
        let (_, _, mut retained) = sink.into_paths().next().unwrap();
        let symbol = retained.pop_front().unwrap().symbol;
        assert!(symbol.is_verified());
        let data = symbol.into_symbol().into_data();
        assert_eq!(data, [7]);
        assert_eq!(data.capacity(), 1, "spare input capacity must not be retained");
    }

    #[test]
    fn multipath_sources_follow_deterministic_weights_and_quality_windows() {
        fn run(reverse: bool) -> (Vec<u32>, Vec<u32>) {
            let (a, mut a_rx) = channel(64);
            let (b, mut b_rx) = channel(64);
            let mut sink = MultipathSink::new(2, 4, 1).unwrap();
            if reverse {
                sink.add_path(PathId(2), multipath_quality(29), b).unwrap();
                sink.add_path(PathId(1), multipath_quality(9), a).unwrap();
            } else {
                sink.add_path(PathId(1), multipath_quality(9), a).unwrap();
                sink.add_path(PathId(2), multipath_quality(29), b).unwrap();
            }
            future::block_on(sink.send_all((0..8).map(create_symbol))).unwrap();
            future::block_on(sink.flush()).unwrap();
            assert_eq!(sink.path_stats(PathId(1)).unwrap().sent_symbols, 6);
            assert_eq!(sink.path_stats(PathId(2)).unwrap().sent_symbols, 2);
            sink.update_path_quality(PathId(1), multipath_quality(29));
            sink.update_path_quality(PathId(2), multipath_quality(9));
            future::block_on(sink.send_all((8..16).map(create_symbol))).unwrap();
            future::block_on(sink.close()).unwrap();
            assert_eq!(sink.path_stats(PathId(1)).unwrap().flushed_symbols, 8);
            assert_eq!(sink.path_stats(PathId(2)).unwrap().flushed_symbols, 8);
            let a = future::block_on(async {
                let mut ids = Vec::new();
                while let Some(symbol) = a_rx.next().await {
                    ids.push(symbol.unwrap().symbol().id().esi());
                }
                ids
            });
            let b = future::block_on(async {
                let mut ids = Vec::new();
                while let Some(symbol) = b_rx.next().await {
                    ids.push(symbol.unwrap().symbol().id().esi());
                }
                ids
            });
            (a, b)
        }
        let normal = run(false);
        assert_eq!(normal, run(true), "path insertion order must not affect routing");
        let mut all = normal.0;
        all.extend(normal.1);
        all.sort_unstable();
        assert_eq!(all, (0..16).collect::<Vec<_>>());
    }

    #[test]
    fn multipath_repairs_prefer_the_best_ready_survivor() {
        let (mut fast, mut fast_rx) = channel(1);
        let (slow, mut slow_rx) = channel(4);
        future::block_on(fast.send(create_symbol(99))).unwrap();
        let mut sink = MultipathSink::new(2, 1, 1).unwrap();
        sink.add_path(PathId(1), multipath_quality(0), fast).unwrap();
        sink.add_path(PathId(2), multipath_quality(500), slow).unwrap();
        future::block_on(sink.send(repair_symbol(20))).unwrap();
        future::block_on(sink.flush()).unwrap();
        assert_eq!(sink.path_stats(PathId(1)).unwrap().sent_symbols, 0);
        assert_eq!(sink.path_stats(PathId(2)).unwrap().sent_symbols, 1);
        assert_eq!(future::block_on(slow_rx.next()).unwrap().unwrap().symbol().id().esi(), 20);
        assert_eq!(future::block_on(fast_rx.next()).unwrap().unwrap().symbol().id().esi(), 99);
        future::block_on(sink.send(repair_symbol(21))).unwrap();
        future::block_on(sink.flush()).unwrap();
        assert_eq!(future::block_on(fast_rx.next()).unwrap().unwrap().symbol().id().esi(), 21);
    }

    #[test]
    fn multipath_full_queues_register_every_path_and_drop_unaccepted_waits() {
        let (mut a, mut a_rx) = channel(1);
        let (mut b, mut b_rx) = channel(1);
        future::block_on(a.send(create_symbol(90))).unwrap();
        future::block_on(b.send(create_symbol(91))).unwrap();
        let mut sink = MultipathSink::new(2, 1, 1).unwrap();
        sink.add_path(PathId(1), multipath_quality(9), a).unwrap();
        sink.add_path(PathId(2), multipath_quality(9), b).unwrap();
        let woke = Arc::new(AtomicBool::new(false));
        let waker = flagged_waker(Arc::clone(&woke));
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(Pin::new(&mut sink).poll_send(&mut cx, create_symbol(0)), Poll::Ready(Ok(()))));
        assert!(matches!(Pin::new(&mut sink).poll_send(&mut cx, create_symbol(1)), Poll::Ready(Ok(()))));
        {
            let mut abandoned = Box::pin(sink.send(create_symbol(77)));
            assert!(abandoned.as_mut().poll(&mut cx).is_pending());
        }
        for path in [PathId(1), PathId(2)] {
            let stats = sink.path_stats(path).unwrap();
            assert_eq!(stats.queued_symbols, 1);
            assert_eq!(stats.high_water_symbols, 1);
        }
        woke.store(false, Ordering::Release);
        assert_eq!(future::block_on(b_rx.next()).unwrap().unwrap().symbol().id().esi(), 91);
        assert!(woke.load(Ordering::Acquire), "the second path must wake a parked sender");
        assert!(matches!(Pin::new(&mut sink).poll_send(&mut cx, create_symbol(2)), Poll::Ready(Ok(()))));
        assert_eq!(future::block_on(b_rx.next()).unwrap().unwrap().symbol().id().esi(), 1);
        assert_eq!(future::block_on(a_rx.next()).unwrap().unwrap().symbol().id().esi(), 90);
        future::block_on(sink.flush()).unwrap();
        assert_eq!(future::block_on(a_rx.next()).unwrap().unwrap().symbol().id().esi(), 0);
        assert_eq!(future::block_on(b_rx.next()).unwrap().unwrap().symbol().id().esi(), 2);
        future::block_on(sink.close()).unwrap();
        assert!(future::block_on(a_rx.next()).is_none());
        assert!(future::block_on(b_rx.next()).is_none());
    }

    #[test]
    fn multipath_pre_send_path_failure_reassigns_owned_symbols_once() {
        let (a, a_rx) = channel(2);
        let failed_channel = Arc::clone(&a.shared);
        let (b, mut b_rx) = channel(2);
        let mut sink = MultipathSink::new(2, 1, 1).unwrap();
        sink.add_path(PathId(1), multipath_quality(0), a).unwrap();
        sink.add_path(PathId(2), multipath_quality(500), b).unwrap();
        future::block_on(sink.send(create_symbol(7))).unwrap();
        assert_eq!(sink.path_stats(PathId(1)).unwrap().queued_symbols, 1);
        failed_channel.close();
        drop(a_rx);
        future::block_on(sink.flush()).unwrap();
        let failed = sink.path_stats(PathId(1)).unwrap();
        assert!(failed.failed);
        assert!(!failed.outcome_uncertain);
        assert_eq!(failed.reassigned_symbols, 1);
        assert_eq!(failed.queued_symbols, 0);
        assert!(matches!(sink.path_error(PathId(1)), Some(SinkError::Closed)));
        assert_eq!(future::block_on(b_rx.next()).unwrap().unwrap().symbol().id().esi(), 7);
        future::block_on(sink.close()).unwrap();
        assert!(future::block_on(b_rx.next()).is_none());
    }

    struct MultipathGateState {
        ready: bool,
        pending_send: bool,
        pending_at_send: usize,
        needs_flush: bool,
        fail_send: bool,
        flush_ready: bool,
        fail_flush: bool,
        close_ready: bool,
        fail_close: bool,
        sent: Vec<AuthenticatedSymbol>,
        sends: usize,
        closes: usize,
        flush_waker: Option<Waker>,
        close_waker: Option<Waker>,
    }

    #[derive(Clone)]
    struct MultipathGate(Arc<Mutex<MultipathGateState>>);

    impl MultipathGate {
        fn new() -> Self {
            Self(Arc::new(Mutex::new(MultipathGateState {
                ready: false,
                pending_send: false,
                pending_at_send: 0,
                needs_flush: false,
                fail_send: false,
                flush_ready: true,
                fail_flush: false,
                close_ready: true,
                fail_close: false,
                sent: Vec::new(),
                sends: 0,
                closes: 0,
                flush_waker: None,
                close_waker: None,
            })))
        }
    }

    impl SymbolSink for MultipathGate {
        fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            if self.0.lock().ready { Poll::Ready(Ok(())) } else { Poll::Pending }
        }

        fn poll_send(self: Pin<&mut Self>, _: &mut Context<'_>, symbol: AuthenticatedSymbol) -> Poll<Result<(), SinkError>> {
            let mut state = self.0.lock();
            state.sends += 1;
            if state.sends == state.pending_at_send {
                state.ready = false;
                state.needs_flush = true;
                return Poll::Pending;
            }
            if state.pending_send {
                state.pending_send = false;
                return Poll::Pending;
            }
            state.sent.push(symbol);
            if state.fail_send {
                Poll::Ready(Err(SinkError::SendFailed { reason: "accepted then connection lost".into() }))
            } else {
                Poll::Ready(Ok(()))
            }
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            let mut state = self.0.lock();
            if state.needs_flush {
                state.needs_flush = false;
                state.ready = true;
            }
            if !state.flush_ready {
                state.flush_waker = Some(cx.waker().clone());
                Poll::Pending
            } else if state.fail_flush {
                Poll::Ready(Err(SinkError::SendFailed { reason: "flush failed".into() }))
            } else {
                Poll::Ready(Ok(()))
            }
        }

        fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            let mut state = self.0.lock();
            state.closes += 1;
            if !state.close_ready {
                state.close_waker = Some(cx.waker().clone());
                Poll::Pending
            } else if state.fail_close {
                Poll::Ready(Err(SinkError::Closed))
            } else {
                Poll::Ready(Ok(()))
            }
        }
    }

    #[test]
    fn multipath_uncertain_send_never_replays_and_flush_drains_healthy_paths() {
        let a = MultipathGate::new();
        let b = MultipathGate::new();
        let mut sink = MultipathSink::new(2, 1, 1).unwrap();
        sink.add_path(PathId(1), multipath_quality(9), a.clone()).unwrap();
        sink.add_path(PathId(2), multipath_quality(9), b.clone()).unwrap();
        let woke = Arc::new(AtomicBool::new(false));
        let waker = flagged_waker(Arc::clone(&woke));
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(Pin::new(&mut sink).poll_send(&mut cx, create_symbol(0)), Poll::Ready(Ok(()))));
        assert!(matches!(Pin::new(&mut sink).poll_send(&mut cx, create_symbol(1)), Poll::Ready(Ok(()))));
        { let mut state = a.0.lock(); state.ready = true; state.fail_send = true; }
        { let mut state = b.0.lock(); state.ready = true; state.flush_ready = false; }
        assert!(Pin::new(&mut sink).poll_flush(&mut cx).is_pending(), "healthy accepted work still needs flushing");
        assert_eq!(a.0.lock().sent[0].symbol().id().esi(), 0);
        assert_eq!(b.0.lock().sent[0].symbol().id().esi(), 1);
        assert!(sink.path_stats(PathId(1)).unwrap().outcome_uncertain);
        assert_eq!(sink.path_stats(PathId(2)).unwrap().unflushed_symbols, 1);
        let wake = { let mut state = b.0.lock(); state.flush_ready = true; state.flush_waker.take().unwrap() };
        woke.store(false, Ordering::Release);
        wake.wake();
        assert!(woke.load(Ordering::Acquire));
        assert!(matches!(Pin::new(&mut sink).poll_flush(&mut cx), Poll::Ready(Err(_))));
        assert!(matches!(Pin::new(&mut sink).poll_send(&mut cx, create_symbol(2)), Poll::Ready(Err(_))));
        assert_eq!(a.0.lock().sends, 1);
        assert_eq!(b.0.lock().sent.len(), 1);
        assert_eq!(sink.path_stats(PathId(2)).unwrap().flushed_symbols, 1);
        assert!(matches!(Pin::new(&mut sink).poll_close(&mut cx), Poll::Ready(Err(_))));
        assert_eq!(a.0.lock().closes, 1);
        assert_eq!(b.0.lock().closes, 1);
        let mut parts = sink.into_paths();
        let (id, _, queued) = parts.next().unwrap();
        assert_eq!(id, PathId(1));
        assert_eq!(queued.len(), 1);
        assert!(queued[0].attempted);
        assert_eq!(queued[0].symbol.symbol().id().esi(), 0);
        assert!(parts.next().unwrap().2.is_empty());
    }

    #[test]
    fn multipath_pending_send_stays_on_its_path_and_flush_failure_is_sticky() {
        let a = MultipathGate::new();
        { let mut state = a.0.lock(); state.ready = true; state.pending_send = true; }
        let b = MultipathGate::new();
        b.0.lock().ready = true;
        let mut sink = MultipathSink::new(2, 1, 1).unwrap();
        sink.add_path(PathId(1), multipath_quality(0), a.clone()).unwrap();
        sink.add_path(PathId(2), multipath_quality(500), b.clone()).unwrap();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(Pin::new(&mut sink).poll_send(&mut cx, create_symbol(8)), Poll::Ready(Ok(()))));
        assert!(Pin::new(&mut sink).poll_flush(&mut cx).is_pending());
        assert_eq!(a.0.lock().sends, 1);
        assert_eq!(b.0.lock().sends, 0);
        sink.update_path_quality(PathId(2), multipath_quality(0));
        a.0.lock().fail_flush = true;
        assert!(matches!(Pin::new(&mut sink).poll_flush(&mut cx), Poll::Ready(Err(_))));
        assert_eq!(a.0.lock().sends, 2);
        assert_eq!(a.0.lock().sent.len(), 1);
        assert_eq!(b.0.lock().sends, 0);
        assert!(sink.path_stats(PathId(1)).unwrap().outcome_uncertain);
        assert_eq!(sink.path_stats(PathId(1)).unwrap().unflushed_symbols, 1);
        assert!(matches!(Pin::new(&mut sink).poll_flush(&mut cx), Poll::Ready(Err(_))));
        assert_eq!(a.0.lock().sends, 2);
    }

    #[test]
    fn multipath_close_drives_every_path_after_one_close_error() {
        let a = MultipathGate::new();
        { let mut state = a.0.lock(); state.ready = true; state.fail_close = true; }
        let b = MultipathGate::new();
        { let mut state = b.0.lock(); state.ready = true; state.close_ready = false; }
        let mut sink = MultipathSink::new(2, 1, 1).unwrap();
        sink.add_path(PathId(1), multipath_quality(9), a.clone()).unwrap();
        sink.add_path(PathId(2), multipath_quality(9), b.clone()).unwrap();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut sink).poll_close(&mut cx).is_pending());
        assert_eq!(a.0.lock().closes, 1);
        assert_eq!(b.0.lock().closes, 1);
        assert!(matches!(Pin::new(&mut sink).poll_send(&mut cx, create_symbol(0)), Poll::Ready(Err(SinkError::Closed))));
        let wake = { let mut state = b.0.lock(); state.close_ready = true; state.close_waker.take().unwrap() };
        wake.wake();
        assert!(matches!(Pin::new(&mut sink).poll_close(&mut cx), Poll::Ready(Err(_))));
        assert_eq!(a.0.lock().closes, 1, "completed close must not be polled again");
        assert_eq!(b.0.lock().closes, 2);
    }

    #[test]
    fn multipath_pending_send_drives_prior_flush_without_reassigning() {
        let path = MultipathGate::new();
        let mut sink = MultipathSink::new(1, 2, 1).unwrap();
        sink.add_path(PathId(1), multipath_quality(9), path.clone()).unwrap();
        let woke = Arc::new(AtomicBool::new(false));
        let waker = flagged_waker(Arc::clone(&woke));
        let mut cx = Context::from_waker(&waker);
        for esi in [0, 1] {
            assert!(matches!(Pin::new(&mut sink).poll_send(&mut cx, create_symbol(esi)), Poll::Ready(Ok(()))));
        }
        { let mut state = path.0.lock(); state.ready = true; state.pending_at_send = 2; }
        woke.store(false, Ordering::Release);
        assert!(Pin::new(&mut sink).poll_flush(&mut cx).is_pending());
        assert!(woke.load(Ordering::Acquire), "flush progress must schedule the retained send");
        assert_eq!(path.0.lock().sends, 2);
        assert_eq!(path.0.lock().sent.len(), 1);
        assert!(matches!(Pin::new(&mut sink).poll_flush(&mut cx), Poll::Ready(Ok(()))));
        assert_eq!(path.0.lock().sends, 3);
        assert_eq!(path.0.lock().sent.iter().map(|symbol| symbol.symbol().id().esi()).collect::<Vec<_>>(), vec![0, 1]);
        assert_eq!(sink.path_stats(PathId(1)).unwrap().flushed_symbols, 2);
    }

    #[test]
    fn multipath_global_poll_budget_yields_and_rotates_without_starvation() {
        let mut sink = MultipathSink::new(64, 2, 1).unwrap();
        let paths = (0..64).map(|id| {
            let path = MultipathGate::new();
            sink.add_path(PathId(id), multipath_quality(9), path.clone()).unwrap();
            path
        }).collect::<Vec<_>>();
        let woke = Arc::new(AtomicBool::new(false));
        let waker = flagged_waker(Arc::clone(&woke));
        let mut cx = Context::from_waker(&waker);
        for esi in 0..128 {
            assert!(matches!(Pin::new(&mut sink).poll_send(&mut cx, create_symbol(esi)), Poll::Ready(Ok(()))));
        }
        for path in &paths { path.0.lock().ready = true; }
        woke.store(false, Ordering::Release);
        assert!(Pin::new(&mut sink).poll_flush(&mut cx).is_pending());
        assert_eq!(paths.iter().map(|path| path.0.lock().sends).sum::<usize>(), 64);
        assert!(woke.load(Ordering::Acquire));
        assert!(matches!(Pin::new(&mut sink).poll_flush(&mut cx), Poll::Ready(Ok(()))));
        for (id, path) in paths.iter().enumerate() {
            assert_eq!(path.0.lock().sends, 2);
            let stats = sink.path_stats(PathId(id as u64)).unwrap();
            assert_eq!(stats.flushed_symbols, 2);
            assert_eq!(stats.high_water_symbols, 2);
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn multipath_native_parked_cancel_preserves_admitted_symbols_and_quiescence() {
        use std::time::{Duration, Instant};
        for sharded in [false, true] {
            let builder = if sharded {
                crate::runtime::RuntimeBuilder::multi_thread().worker_threads(2)
                    .with_sharded_state(true)
            } else {
                crate::runtime::RuntimeBuilder::current_thread()
            };
            let runtime = builder.build().unwrap();
            runtime.block_on(runtime.handle().spawn(async move {
                let cx = crate::Cx::current().expect("native task context");
                let (mut a, mut a_rx) = channel(1);
                let (mut b, mut b_rx) = channel(1);
                let a_state = Arc::clone(&a.shared);
                let b_state = Arc::clone(&b.shared);
                a.send(create_symbol(90)).await.unwrap();
                b.send(create_symbol(91)).await.unwrap();
                let mut sink = MultipathSink::new(2, 1, 1).unwrap();
                sink.add_path(PathId(1), multipath_quality(9), a).unwrap();
                sink.add_path(PathId(2), multipath_quality(9), b).unwrap();
                sink.send(create_symbol(0)).await.unwrap();
                sink.send(create_symbol(1)).await.unwrap();
                let parked = Arc::new(AtomicBool::new(false));
                let witnessed = Arc::clone(&parked);
                let mut child = cx.spawn(move |_child_cx| async move {
                    let result = {
                        let mut send = Box::pin(sink.send(create_symbol(77)));
                        std::future::poll_fn(|task| {
                            let result = send.as_mut().poll(task);
                            if result.is_pending() { witnessed.store(true, Ordering::Release); }
                            result
                        }).await
                    };
                    (result, sink)
                }).unwrap();
                let started = Instant::now();
                while !parked.load(Ordering::Acquire) {
                    assert!(started.elapsed() < Duration::from_secs(5));
                    crate::runtime::yield_now().await;
                }
                for state in [&a_state, &b_state] {
                    assert_eq!(state.queue.lock().len(), 1);
                    assert_eq!(state.send_wakers.lock().len(), 1);
                }
                child.abort();
                let joined = {
                    let mut join = Box::pin(child.join(&cx));
                    std::future::poll_fn(|task| {
                        let result = join.as_mut().poll(task);
                        if result.is_pending() {
                            assert!(started.elapsed() < Duration::from_secs(5));
                            task.waker().wake_by_ref();
                        }
                        result
                    }).await
                };
                let (result, mut sink) = joined.expect("acknowledged cancellation keeps typed result");
                assert!(matches!(result, Err(SinkError::Io { source }) if source.kind() == std::io::ErrorKind::Interrupted));
                for path in [PathId(1), PathId(2)] {
                    assert_eq!(sink.path_stats(path).unwrap().queued_symbols, 1);
                }
                assert_eq!(a_rx.next().await.unwrap().unwrap().symbol().id().esi(), 90);
                assert_eq!(b_rx.next().await.unwrap().unwrap().symbol().id().esi(), 91);
                sink.flush().await.unwrap();
                assert_eq!(a_rx.next().await.unwrap().unwrap().symbol().id().esi(), 0);
                assert_eq!(b_rx.next().await.unwrap().unwrap().symbol().id().esi(), 1);
                sink.close().await.unwrap();
                assert!(a_rx.next().await.is_none());
                assert!(b_rx.next().await.is_none());
                drop(sink);
                assert!(a_state.send_wakers.lock().is_empty());
                assert!(b_state.send_wakers.lock().is_empty());
            }));
            assert_eq!(runtime.drain_root_region(Duration::from_secs(5)), crate::runtime::RootDrainOutcome::Quiescent);
            assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
            assert!(runtime.is_quiescent());
        }
    }

    #[test]
    fn multipath_raptorq_authenticated_roundtrip_uses_real_channels_and_aggregation() {
        use crate::config::RaptorQConfig;
        use crate::raptorq::{RaptorQReceiverBuilder, RaptorQSenderBuilder};
        use crate::security::{AuthMode, SecurityContext};
        use crate::transport::{AggregatorConfig, MultipathAggregator};
        use crate::transport::stream::VecStream;
        use crate::types::{ObjectId, ObjectParams, Time};

        let cx = crate::Cx::for_testing();
        let security = SecurityContext::for_testing_with_mode(0x51_7a, AuthMode::Strict);
        let data = (0..4096).map(|i| ((i * 31 + i / 7) % 251) as u8).collect::<Vec<_>>();
        let object_id = ObjectId::new(0, 0x51_7a);
        let mut config = RaptorQConfig::default();
        config.encoding.symbol_size = 256;
        config.encoding.max_block_size = 4096;
        config.encoding.repair_overhead = 2.0;
        let (a, mut a_rx) = channel(128);
        let (b, mut b_rx) = channel(128);
        let mut sink = MultipathSink::new(2, 4, 256).unwrap();
        sink.add_path(PathId(1), multipath_quality(9), a).unwrap();
        sink.add_path(PathId(2), multipath_quality(29), b).unwrap();
        let mut sender = RaptorQSenderBuilder::new().config(config.clone())
            .security(security.clone()).transport(sink).build().unwrap();
        let sent = sender.send_object(&cx, object_id, &data).unwrap();
        assert!(sent.source_symbols > 0 && sent.repair_symbols >= 3);
        for id in [PathId(1), PathId(2)] {
            let stats = sender.transport_mut().path_stats(id).unwrap();
            assert!(stats.sent_symbols > 0, "both real paths must carry source symbols");
            assert!(stats.high_water_symbols <= 4);
            assert_eq!(stats.queued_symbols, 0);
            assert_eq!(stats.unflushed_symbols, 0);
        }
        future::block_on(sender.transport_mut().close()).unwrap();
        let aggregator = MultipathAggregator::new(AggregatorConfig::default());
        let mut received = Vec::new();
        let mut dropped = 0;
        for (path, input) in [(PathId(1), &mut a_rx), (PathId(2), &mut b_rx)] {
            while let Some(symbol) = future::block_on(input.next()) {
                let symbol = symbol.unwrap();
                if symbol.symbol().kind().is_source() && symbol.symbol().id().esi() < 3 {
                    dropped += 1;
                    continue;
                }
                let result = aggregator.process_fungible_symbol(symbol.symbol().clone(), path, Time::ZERO);
                assert!(result.ready.is_some());
                let duplicate = aggregator.process_fungible_symbol(symbol.symbol().clone(), path, Time::ZERO);
                assert!(duplicate.was_duplicate && duplicate.ready.is_none());
                received.push(symbol);
            }
        }
        assert_eq!(dropped, 3);
        assert_eq!(received.len() + dropped, sent.symbols_sent);
        config.encoding.repair_overhead = 1.0;
        let params = ObjectParams::new(object_id, data.len() as u64, 256, 1, sent.source_symbols as u16);
        let mut receiver = RaptorQReceiverBuilder::new().config(config)
            .security(security).source(VecStream::new(received)).build().unwrap();
        let decoded = receiver.receive_object(&cx, &params).unwrap();
        assert_eq!(decoded.data, data);
        assert!(decoded.all_symbols_verified());
    }

    #[allow(clippy::struct_excessive_bools)]
    struct TrackingSinkState {
        ready_after: usize,
        ready_polls: usize,
        send_pending_once: bool,
        send_pending_done: bool,
        send_error_once: bool,
        sent: Vec<AuthenticatedSymbol>,
        flush_count: usize,
        closed: bool,
    }

    impl TrackingSinkState {
        fn new() -> Self {
            Self {
                ready_after: 0,
                ready_polls: 0,
                send_pending_once: false,
                send_pending_done: false,
                send_error_once: false,
                sent: Vec::new(),
                flush_count: 0,
                closed: false,
            }
        }
    }

    #[derive(Clone)]
    struct TrackingSink {
        state: Arc<Mutex<TrackingSinkState>>,
    }

    impl TrackingSink {
        fn new(state: TrackingSinkState) -> Self {
            Self {
                state: Arc::new(Mutex::new(state)),
            }
        }

        fn state(&self) -> Arc<Mutex<TrackingSinkState>> {
            Arc::clone(&self.state)
        }
    }

    impl SymbolSink for TrackingSink {
        fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            let mut state = self.state.lock();
            if state.closed {
                drop(state);
                return Poll::Ready(Err(SinkError::Closed));
            }
            if state.ready_polls < state.ready_after {
                state.ready_polls += 1;
                drop(state);
                return Poll::Pending;
            }
            drop(state);
            Poll::Ready(Ok(()))
        }

        fn poll_send(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            symbol: AuthenticatedSymbol,
        ) -> Poll<Result<(), SinkError>> {
            let mut state = self.state.lock();
            if state.closed {
                drop(state);
                return Poll::Ready(Err(SinkError::Closed));
            }
            if state.send_error_once {
                state.send_error_once = false;
                drop(state);
                return Poll::Ready(Err(SinkError::SendFailed {
                    reason: "send failed".to_string(),
                }));
            }
            if state.send_pending_once && !state.send_pending_done {
                state.send_pending_done = true;
                drop(state);
                return Poll::Pending;
            }
            state.sent.push(symbol);
            drop(state);
            Poll::Ready(Ok(()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            let mut state = self.state.lock();
            if state.closed {
                drop(state);
                return Poll::Ready(Err(SinkError::Closed));
            }
            state.flush_count += 1;
            drop(state);
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            let mut state = self.state.lock();
            state.closed = true;
            drop(state);
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Default)]
    struct SequencedSendSinkState {
        send_calls: usize,
        pending_send_call: usize,
        sent: Vec<AuthenticatedSymbol>,
        flush_count: usize,
    }

    #[derive(Clone)]
    struct SequencedSendSink {
        state: Arc<Mutex<SequencedSendSinkState>>,
    }

    impl SequencedSendSink {
        fn new(pending_send_call: usize) -> Self {
            Self {
                state: Arc::new(Mutex::new(SequencedSendSinkState {
                    pending_send_call,
                    ..SequencedSendSinkState::default()
                })),
            }
        }

        fn state(&self) -> Arc<Mutex<SequencedSendSinkState>> {
            Arc::clone(&self.state)
        }
    }

    impl SymbolSink for SequencedSendSink {
        fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            Poll::Ready(Ok(()))
        }

        fn poll_send(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            symbol: AuthenticatedSymbol,
        ) -> Poll<Result<(), SinkError>> {
            let mut state = self.state.lock();
            state.send_calls = state.send_calls.saturating_add(1);
            if state.pending_send_call != 0 && state.send_calls == state.pending_send_call {
                return Poll::Pending;
            }
            state.sent.push(symbol);
            drop(state);
            Poll::Ready(Ok(()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            let mut state = self.state.lock();
            state.flush_count = state.flush_count.saturating_add(1);
            drop(state);
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn test_send_future_pending_then_ready() {
        init_test("test_send_future_pending_then_ready");
        let mut sink = TrackingSink::new({
            let mut state = TrackingSinkState::new();
            state.ready_after = 1;
            state
        });

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let mut fut = sink.send(create_symbol(1));
        let mut fut = Pin::new(&mut fut);

        let first = fut.as_mut().poll(&mut context);
        crate::assert_with_log!(
            matches!(first, Poll::Pending),
            "pending",
            true,
            matches!(first, Poll::Pending)
        );

        let second = fut.as_mut().poll(&mut context);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Ok(()))),
            "ready",
            true,
            matches!(second, Poll::Ready(Ok(())))
        );

        let sent_len = {
            let state = sink.state.lock();
            state.sent.len()
        };
        crate::assert_with_log!(sent_len == 1, "sent", 1usize, sent_len);
        crate::test_complete!("test_send_future_pending_then_ready");
    }

    #[test]
    fn test_send_future_propagates_send_error() {
        init_test("test_send_future_propagates_send_error");
        let mut sink = TrackingSink::new({
            let mut state = TrackingSinkState::new();
            state.send_error_once = true;
            state
        });

        let res = future::block_on(async { sink.send(create_symbol(2)).await });
        crate::assert_with_log!(
            matches!(res, Err(SinkError::SendFailed { .. })),
            "send failed",
            true,
            matches!(res, Err(SinkError::SendFailed { .. }))
        );

        let sent_empty = {
            let state = sink.state.lock();
            state.sent.is_empty()
        };
        crate::assert_with_log!(sent_empty, "no sent", true, sent_empty);
        crate::test_complete!("test_send_future_propagates_send_error");
    }

    #[test]
    fn test_send_future_repoll_after_completion_fails_closed() {
        init_test("test_send_future_repoll_after_completion_fails_closed");
        let mut sink = TrackingSink::new(TrackingSinkState::new());
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let mut future = sink.send(create_symbol(44));
        let mut future = Pin::new(&mut future);

        let first = future.as_mut().poll(&mut context);
        crate::assert_with_log!(
            matches!(first, Poll::Ready(Ok(()))),
            "first send completes",
            true,
            matches!(first, Poll::Ready(Ok(())))
        );

        let second = future.as_mut().poll(&mut context);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Err(SinkError::PolledAfterCompletion))),
            "second poll fails closed",
            true,
            matches!(second, Poll::Ready(Err(SinkError::PolledAfterCompletion)))
        );

        let sent_len = {
            let state = sink.state.lock();
            state.sent.len()
        };
        crate::assert_with_log!(sent_len == 1, "symbol sent once", 1usize, sent_len);
        crate::test_complete!("test_send_future_repoll_after_completion_fails_closed");
    }

    #[test]
    fn test_send_all_counts_and_flushes() {
        init_test("test_send_all_counts_and_flushes");
        let mut sink = TrackingSink::new(TrackingSinkState::new());
        let symbols = vec![create_symbol(1), create_symbol(2), create_symbol(3)];

        let count = future::block_on(async { sink.send_all(symbols).await.unwrap() });
        let (sent_len, flush_count) = {
            let state = sink.state.lock();
            (state.sent.len(), state.flush_count)
        };

        crate::assert_with_log!(count == 3, "count", 3usize, count);
        crate::assert_with_log!(sent_len == 3, "sent", 3usize, sent_len);
        crate::assert_with_log!(flush_count == 1, "flush count", 1usize, flush_count);
        crate::test_complete!("test_send_all_counts_and_flushes");
    }

    #[test]
    fn test_send_all_yields_after_budget_on_always_ready_sink() {
        init_test("test_send_all_yields_after_budget_on_always_ready_sink");
        let mut sink = TrackingSink::new(TrackingSinkState::new());
        let state = sink.state();
        let symbols = (0..(SEND_ALL_COOPERATIVE_BUDGET as u32 + 5))
            .map(create_symbol)
            .collect::<Vec<_>>();
        let woke = Arc::new(AtomicBool::new(false));
        let waker = flagged_waker(woke.clone());
        let mut context = Context::from_waker(&waker);
        let mut future = sink.send_all(symbols);
        let mut future = Pin::new(&mut future);

        let first = future.as_mut().poll(&mut context);
        crate::assert_with_log!(
            matches!(first, Poll::Pending),
            "first poll yields cooperatively",
            "Poll::Pending",
            first
        );
        crate::assert_with_log!(
            woke.load(Ordering::SeqCst),
            "cooperative yield self-wakes",
            true,
            woke.load(Ordering::SeqCst)
        );
        crate::assert_with_log!(
            future.count == SEND_ALL_COOPERATIVE_BUDGET,
            "budgeted sends counted before yielding",
            SEND_ALL_COOPERATIVE_BUDGET,
            future.count
        );
        let (sent_len, flush_count) = {
            let state = state.lock();
            (state.sent.len(), state.flush_count)
        };
        crate::assert_with_log!(
            sent_len == SEND_ALL_COOPERATIVE_BUDGET,
            "sink observed only budgeted sends on first poll",
            SEND_ALL_COOPERATIVE_BUDGET,
            sent_len
        );
        crate::assert_with_log!(
            flush_count == 0,
            "flush deferred until iterator drains",
            0usize,
            flush_count
        );

        let second = future.as_mut().poll(&mut context);
        let second_total = match second {
            Poll::Ready(Ok(total)) => Some(total),
            _ => None,
        };
        crate::assert_with_log!(
            second_total == Some(SEND_ALL_COOPERATIVE_BUDGET + 5),
            "second poll completes remaining sends",
            Some(SEND_ALL_COOPERATIVE_BUDGET + 5),
            second_total
        );
        let (sent_len, flush_count) = {
            let state = state.lock();
            (state.sent.len(), state.flush_count)
        };
        crate::assert_with_log!(
            sent_len == SEND_ALL_COOPERATIVE_BUDGET + 5,
            "all symbols were eventually sent",
            SEND_ALL_COOPERATIVE_BUDGET + 5,
            sent_len
        );
        crate::assert_with_log!(
            flush_count == 1,
            "final completion still flushes exactly once",
            1usize,
            flush_count
        );
        crate::test_complete!("test_send_all_yields_after_budget_on_always_ready_sink");
    }

    #[test]
    fn test_send_all_repoll_after_completion_fails_closed() {
        init_test("test_send_all_repoll_after_completion_fails_closed");
        let mut sink = TrackingSink::new(TrackingSinkState::new());
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let mut future = sink.send_all(vec![create_symbol(8), create_symbol(9)]);
        let mut future = Pin::new(&mut future);

        let first = future.as_mut().poll(&mut context);
        crate::assert_with_log!(
            matches!(first, Poll::Ready(Ok(2))),
            "first poll sends all",
            true,
            matches!(first, Poll::Ready(Ok(2)))
        );

        let second = future.as_mut().poll(&mut context);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Err(SinkError::PolledAfterCompletion))),
            "second poll fails closed",
            true,
            matches!(second, Poll::Ready(Err(SinkError::PolledAfterCompletion)))
        );

        let (sent_len, flush_count) = {
            let state = sink.state.lock();
            (state.sent.len(), state.flush_count)
        };
        crate::assert_with_log!(sent_len == 2, "symbols sent once", 2usize, sent_len);
        crate::assert_with_log!(flush_count == 1, "flush ran once", 1usize, flush_count);
        crate::test_complete!("test_send_all_repoll_after_completion_fails_closed");
    }

    #[test]
    fn test_send_all_propagates_error() {
        init_test("test_send_all_propagates_error");
        let mut sink = TrackingSink::new({
            let mut state = TrackingSinkState::new();
            state.send_error_once = true;
            state
        });

        let res = future::block_on(async { sink.send_all(vec![create_symbol(9)]).await });
        crate::assert_with_log!(
            matches!(res, Err(SinkError::SendFailed { .. })),
            "error",
            true,
            matches!(res, Err(SinkError::SendFailed { .. }))
        );
        crate::test_complete!("test_send_all_propagates_error");
    }

    #[test]
    fn metamorphic_batching_preserves_sink_send_order() {
        init_test("metamorphic_batching_preserves_sink_send_order");

        let symbols = vec![
            create_symbol(11),
            create_symbol(12),
            create_symbol(13),
            create_symbol(14),
        ];

        let mut baseline_sink = TrackingSink::new(TrackingSinkState::new());
        for symbol in symbols.clone() {
            future::block_on(async { baseline_sink.send(symbol).await.unwrap() });
        }
        let baseline_ids = {
            let state = baseline_sink.state.lock();
            state
                .sent
                .iter()
                .map(|symbol| symbol.symbol().id().esi())
                .collect::<Vec<_>>()
        };

        let mut transformed_sink = TrackingSink::new(TrackingSinkState::new());
        let transformed_count =
            future::block_on(async { transformed_sink.send_all(symbols).await.unwrap() });
        let (transformed_ids, transformed_flushes) = {
            let state = transformed_sink.state.lock();
            (
                state
                    .sent
                    .iter()
                    .map(|symbol| symbol.symbol().id().esi())
                    .collect::<Vec<_>>(),
                state.flush_count,
            )
        };

        crate::assert_with_log!(
            transformed_ids == baseline_ids,
            "batching the same symbol sequence must preserve sink emission order",
            baseline_ids,
            transformed_ids
        );
        crate::assert_with_log!(
            transformed_count == 4,
            "send_all reports the full batched symbol count",
            4usize,
            transformed_count
        );
        crate::assert_with_log!(
            transformed_flushes == 1,
            "send_all still flushes exactly once after batching",
            1usize,
            transformed_flushes
        );
        crate::test_complete!("metamorphic_batching_preserves_sink_send_order");
    }

    #[test]
    fn metamorphic_batch_partitioning_preserves_symbol_count_and_order() {
        init_test("metamorphic_batch_partitioning_preserves_symbol_count_and_order");

        let symbols = vec![
            create_symbol(31),
            create_symbol(32),
            create_symbol(33),
            create_symbol(34),
            create_symbol(35),
            create_symbol(36),
        ];

        let mut baseline_sink = TrackingSink::new(TrackingSinkState::new());
        let baseline_count =
            future::block_on(async { baseline_sink.send_all(symbols.clone()).await.unwrap() });
        let baseline_ids = {
            let state = baseline_sink.state.lock();
            state
                .sent
                .iter()
                .map(|symbol| symbol.symbol().id().esi())
                .collect::<Vec<_>>()
        };

        let partitions = [2usize, 1usize, 3usize];
        let mut transformed_sink = TrackingSink::new(TrackingSinkState::new());
        let mut transformed_count = 0usize;
        let mut offset = 0usize;
        for width in partitions {
            let upper = offset + width;
            transformed_count += future::block_on(async {
                transformed_sink
                    .send_all(symbols[offset..upper].iter().cloned())
                    .await
                    .unwrap()
            });
            offset = upper;
        }
        let (transformed_ids, transformed_flushes) = {
            let state = transformed_sink.state.lock();
            (
                state
                    .sent
                    .iter()
                    .map(|symbol| symbol.symbol().id().esi())
                    .collect::<Vec<_>>(),
                state.flush_count,
            )
        };

        crate::assert_with_log!(
            transformed_ids == baseline_ids,
            "partitioning one batch into smaller batches must preserve emitted order",
            baseline_ids,
            transformed_ids
        );
        crate::assert_with_log!(
            transformed_count == baseline_count,
            "partitioning must preserve the total number of emitted symbols",
            baseline_count,
            transformed_count
        );
        crate::assert_with_log!(
            transformed_flushes == partitions.len(),
            "each partition still flushes exactly once",
            partitions.len(),
            transformed_flushes
        );
        crate::test_complete!("metamorphic_batch_partitioning_preserves_symbol_count_and_order");
    }

    #[test]
    fn metamorphic_cancelled_batch_preserves_committed_prefix() {
        init_test("metamorphic_cancelled_batch_preserves_committed_prefix");

        let symbols = vec![
            create_symbol(41),
            create_symbol(42),
            create_symbol(43),
            create_symbol(44),
        ];

        let mut baseline_sink = TrackingSink::new(TrackingSinkState::new());
        future::block_on(async {
            baseline_sink.send(symbols[0].clone()).await.unwrap();
            baseline_sink.send(symbols[1].clone()).await.unwrap();
        });
        let baseline_prefix_ids = {
            let state = baseline_sink.state.lock();
            state
                .sent
                .iter()
                .map(|symbol| symbol.symbol().id().esi())
                .collect::<Vec<_>>()
        };

        let cx = crate::cx::Cx::for_testing();
        let _current_guard = crate::cx::Cx::set_current(Some(cx.clone()));
        let mut sink = SequencedSendSink::new(3);
        let state = sink.state();
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let mut future = sink.send_all(symbols);
        let mut future = Pin::new(&mut future);

        let first = future.as_mut().poll(&mut context);
        crate::assert_with_log!(
            matches!(first, Poll::Pending),
            "partial batch reaches backpressure before cancellation",
            true,
            matches!(first, Poll::Pending)
        );

        let committed_prefix_ids = {
            let state = state.lock();
            state
                .sent
                .iter()
                .map(|symbol| symbol.symbol().id().esi())
                .collect::<Vec<_>>()
        };
        crate::assert_with_log!(
            committed_prefix_ids == baseline_prefix_ids,
            "partial progress before cancellation preserves the committed prefix",
            baseline_prefix_ids.clone(),
            committed_prefix_ids
        );

        cx.set_cancel_requested(true);
        let cancelled = future.as_mut().poll(&mut context);
        let cancel_kind = match cancelled {
            Poll::Ready(Err(SinkError::Io { source })) => Some(source.kind()),
            _ => None,
        };
        crate::assert_with_log!(
            cancel_kind == Some(std::io::ErrorKind::Interrupted),
            "cancellation converts the in-flight batch into an interrupted sink error",
            Some(std::io::ErrorKind::Interrupted),
            cancel_kind
        );

        let (cancelled_ids, flush_count) = {
            let state = state.lock();
            (
                state
                    .sent
                    .iter()
                    .map(|symbol| symbol.symbol().id().esi())
                    .collect::<Vec<_>>(),
                state.flush_count,
            )
        };
        crate::assert_with_log!(
            cancelled_ids == baseline_prefix_ids,
            "cancellation must not duplicate or reorder the already-committed prefix",
            baseline_prefix_ids,
            cancelled_ids
        );
        crate::assert_with_log!(
            flush_count == 0,
            "cancelled partial batches must not flush a not-yet-exhausted iterator",
            0usize,
            flush_count
        );
        crate::test_complete!("metamorphic_cancelled_batch_preserves_committed_prefix");
    }

    #[test]
    fn metamorphic_buffered_sink_backpressure_preserves_capacity_and_delivery_order() {
        init_test("metamorphic_buffered_sink_backpressure_preserves_capacity_and_delivery_order");

        let symbols = [1_u32, 2, 3, 4].map(create_symbol);

        let mut baseline_sink = TrackingSink::new(TrackingSinkState::new());
        let baseline_count = future::block_on(async {
            baseline_sink
                .send_all(symbols.iter().cloned())
                .await
                .unwrap()
        });
        let baseline_ids = {
            let state = baseline_sink.state.lock();
            state
                .sent
                .iter()
                .map(|symbol| symbol.symbol().id().esi())
                .collect::<Vec<_>>()
        };

        let inner = TrackingSink::new({
            let mut state = TrackingSinkState::new();
            state.ready_after = 10;
            state
        });
        let state = inner.state();
        let mut buffered = BufferedSink::new(inner, 2);

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        for symbol in symbols.iter().cloned() {
            let poll = Pin::new(&mut buffered).poll_send(&mut context, symbol);
            crate::assert_with_log!(
                matches!(poll, Poll::Ready(Ok(()))),
                "buffered send accepted despite downstream backpressure",
                true,
                matches!(poll, Poll::Ready(Ok(())))
            );
            crate::assert_with_log!(
                buffered.buffer.len() <= buffered.capacity,
                "primary buffer never exceeds configured capacity",
                true,
                buffered.buffer.len() <= buffered.capacity
            );
        }

        let mut flush_completed = false;
        for _ in 0..=10 {
            let poll = Pin::new(&mut buffered).poll_flush(&mut context);
            crate::assert_with_log!(
                buffered.buffer.len() <= buffered.capacity,
                "flush retries keep the primary buffer bounded",
                true,
                buffered.buffer.len() <= buffered.capacity
            );
            if matches!(poll, Poll::Ready(Ok(()))) {
                flush_completed = true;
                break;
            }
            crate::assert_with_log!(
                matches!(poll, Poll::Pending),
                "intermediate flushes stay pending until the inner sink is ready",
                true,
                matches!(poll, Poll::Pending)
            );
        }

        let transformed_ids = {
            let state = state.lock();
            state
                .sent
                .iter()
                .map(|symbol| symbol.symbol().id().esi())
                .collect::<Vec<_>>()
        };

        crate::assert_with_log!(
            flush_completed,
            "eventual flush completes once backpressure clears",
            true,
            flush_completed
        );
        crate::assert_with_log!(
            transformed_ids == baseline_ids,
            "backpressure retries preserve final delivery order",
            baseline_ids.clone(),
            transformed_ids
        );
        crate::assert_with_log!(
            baseline_count == baseline_ids.len(),
            "baseline count matches delivered symbols",
            baseline_ids.len(),
            baseline_count
        );
        crate::assert_with_log!(
            buffered.buffer.is_empty() && buffered.staged_symbols.is_empty(),
            "all local buffering drains after the final flush",
            true,
            buffered.buffer.is_empty() && buffered.staged_symbols.is_empty()
        );
        crate::test_complete!(
            "metamorphic_buffered_sink_backpressure_preserves_capacity_and_delivery_order"
        );
    }

    #[test]
    fn metamorphic_cancelled_send_future_does_not_consume_released_channel_capacity() {
        init_test("metamorphic_cancelled_send_future_does_not_consume_released_channel_capacity");

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);

        let (mut baseline_fill, mut baseline_stream) = channel(1);
        let baseline_shared = Arc::clone(&baseline_fill.shared);
        future::block_on(async {
            baseline_fill.send(create_symbol(1)).await.unwrap();
            let received = baseline_stream.next().await.unwrap().unwrap();
            crate::assert_with_log!(
                received.symbol().id().esi() == 1,
                "baseline drain receives the queued symbol",
                1_u32,
                received.symbol().id().esi()
            );
        });

        let mut baseline_replacement = ChannelSink::new(Arc::clone(&baseline_shared));
        let baseline_ready = Pin::new(&mut baseline_replacement).poll_ready(&mut context);
        let baseline_send =
            Pin::new(&mut baseline_replacement).poll_send(&mut context, create_symbol(2));
        crate::assert_with_log!(
            matches!(baseline_ready, Poll::Ready(Ok(()))),
            "baseline replacement sender sees freed capacity",
            true,
            matches!(baseline_ready, Poll::Ready(Ok(())))
        );
        crate::assert_with_log!(
            matches!(baseline_send, Poll::Ready(Ok(()))),
            "baseline replacement send succeeds",
            true,
            matches!(baseline_send, Poll::Ready(Ok(())))
        );
        let baseline_ids = queued_symbol_ids(&baseline_shared);

        let (mut transformed_fill, mut transformed_stream) = channel(1);
        let transformed_shared = Arc::clone(&transformed_fill.shared);
        future::block_on(async {
            transformed_fill.send(create_symbol(1)).await.unwrap();
        });

        let mut cancelled_sender = ChannelSink::new(Arc::clone(&transformed_shared));
        let mut replacement_sender = ChannelSink::new(Arc::clone(&transformed_shared));
        {
            let cx = crate::cx::Cx::for_testing();
            let _current_guard = crate::cx::Cx::set_current(Some(cx.clone()));
            let mut pending_send = cancelled_sender.send(create_symbol(99));
            let mut pending_send = Pin::new(&mut pending_send);

            let first = pending_send.as_mut().poll(&mut context);
            crate::assert_with_log!(
                matches!(first, Poll::Pending),
                "full channel blocks the in-flight send before cancellation",
                true,
                matches!(first, Poll::Pending)
            );
            let waiter_registered = transformed_shared.send_wakers.lock().len();
            crate::assert_with_log!(
                waiter_registered == 1,
                "pending send registers exactly one waiter",
                1usize,
                waiter_registered
            );

            cx.set_cancel_requested(true);
            let cancelled = pending_send.as_mut().poll(&mut context);
            let cancel_kind = match cancelled {
                Poll::Ready(Err(SinkError::Io { source })) => Some(source.kind()),
                _ => None,
            };
            crate::assert_with_log!(
                cancel_kind == Some(std::io::ErrorKind::Interrupted),
                "cancellation converts the blocked send into an interrupted error",
                Some(std::io::ErrorKind::Interrupted),
                cancel_kind
            );
        }

        future::block_on(async {
            let received = transformed_stream.next().await.unwrap().unwrap();
            crate::assert_with_log!(
                received.symbol().id().esi() == 1,
                "transformed drain receives the original queued symbol",
                1_u32,
                received.symbol().id().esi()
            );
        });

        let transformed_ready = Pin::new(&mut replacement_sender).poll_ready(&mut context);
        let transformed_send =
            Pin::new(&mut replacement_sender).poll_send(&mut context, create_symbol(2));
        crate::assert_with_log!(
            matches!(transformed_ready, Poll::Ready(Ok(()))),
            "replacement sender sees the released capacity after cancellation",
            true,
            matches!(transformed_ready, Poll::Ready(Ok(())))
        );
        crate::assert_with_log!(
            matches!(transformed_send, Poll::Ready(Ok(()))),
            "replacement sender can commit after the cancelled send drops out",
            true,
            matches!(transformed_send, Poll::Ready(Ok(())))
        );

        let transformed_ids = queued_symbol_ids(&transformed_shared);
        let waiter_cleared = cancelled_sender
            .waiter
            .as_ref()
            .is_some_and(|waiter| !waiter.load(Ordering::Acquire));
        let remaining_waiters = transformed_shared.send_wakers.lock().len();
        crate::assert_with_log!(
            transformed_ids == baseline_ids,
            "cancelled sends do not consume the next released buffer slot",
            baseline_ids,
            transformed_ids
        );
        crate::assert_with_log!(
            waiter_cleared,
            "draining the queued symbol clears the cancelled sender waiter",
            true,
            waiter_cleared
        );
        crate::assert_with_log!(
            remaining_waiters == 0,
            "no stale send waiters remain after the cancelled path drains",
            0usize,
            remaining_waiters
        );
        crate::test_complete!(
            "metamorphic_cancelled_send_future_does_not_consume_released_channel_capacity"
        );
    }

    #[test]
    fn metamorphic_channel_sink_concurrent_poll_ready_preserves_total_send_order() {
        init_test("metamorphic_channel_sink_concurrent_poll_ready_preserves_total_send_order");

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);

        let baseline_shared = Arc::new(SharedChannel::new(2));
        let mut baseline_first = ChannelSink::new(Arc::clone(&baseline_shared));
        let mut baseline_second = ChannelSink::new(Arc::clone(&baseline_shared));

        let baseline_first_ready = Pin::new(&mut baseline_first).poll_ready(&mut context);
        let baseline_first_send =
            Pin::new(&mut baseline_first).poll_send(&mut context, create_symbol(11));
        let baseline_second_ready = Pin::new(&mut baseline_second).poll_ready(&mut context);
        let baseline_second_send =
            Pin::new(&mut baseline_second).poll_send(&mut context, create_symbol(12));
        crate::assert_with_log!(
            matches!(baseline_first_ready, Poll::Ready(Ok(())))
                && matches!(baseline_first_send, Poll::Ready(Ok(())))
                && matches!(baseline_second_ready, Poll::Ready(Ok(())))
                && matches!(baseline_second_send, Poll::Ready(Ok(()))),
            "baseline send order commits cleanly",
            true,
            matches!(baseline_first_ready, Poll::Ready(Ok(())))
                && matches!(baseline_first_send, Poll::Ready(Ok(())))
                && matches!(baseline_second_ready, Poll::Ready(Ok(())))
                && matches!(baseline_second_send, Poll::Ready(Ok(())))
        );
        let baseline_ids = queued_symbol_ids(&baseline_shared);

        let transformed_shared = Arc::new(SharedChannel::new(2));
        let mut transformed_first = ChannelSink::new(Arc::clone(&transformed_shared));
        let mut transformed_second = ChannelSink::new(Arc::clone(&transformed_shared));

        let transformed_first_ready = Pin::new(&mut transformed_first).poll_ready(&mut context);
        let transformed_second_ready = Pin::new(&mut transformed_second).poll_ready(&mut context);
        let transformed_first_send =
            Pin::new(&mut transformed_first).poll_send(&mut context, create_symbol(11));
        let transformed_second_send =
            Pin::new(&mut transformed_second).poll_send(&mut context, create_symbol(12));
        crate::assert_with_log!(
            matches!(transformed_first_ready, Poll::Ready(Ok(())))
                && matches!(transformed_second_ready, Poll::Ready(Ok(())))
                && matches!(transformed_first_send, Poll::Ready(Ok(())))
                && matches!(transformed_second_send, Poll::Ready(Ok(()))),
            "concurrent ready polling still allows both sends to commit",
            true,
            matches!(transformed_first_ready, Poll::Ready(Ok(())))
                && matches!(transformed_second_ready, Poll::Ready(Ok(())))
                && matches!(transformed_first_send, Poll::Ready(Ok(())))
                && matches!(transformed_second_send, Poll::Ready(Ok(())))
        );

        let transformed_ids = queued_symbol_ids(&transformed_shared);
        crate::assert_with_log!(
            transformed_ids == baseline_ids,
            "extra poll_ready interleaving preserves the committed channel order",
            baseline_ids.clone(),
            transformed_ids
        );
        crate::assert_with_log!(
            baseline_ids == vec![11, 12],
            "queue order matches the committed send order",
            vec![11_u32, 12_u32],
            baseline_ids
        );
        crate::test_complete!(
            "metamorphic_channel_sink_concurrent_poll_ready_preserves_total_send_order"
        );
    }

    #[test]
    fn test_flush_future_repoll_after_completion_fails_closed() {
        init_test("test_flush_future_repoll_after_completion_fails_closed");
        let mut sink = TrackingSink::new(TrackingSinkState::new());
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let mut future = sink.flush();
        let mut future = Pin::new(&mut future);

        let first = future.as_mut().poll(&mut context);
        crate::assert_with_log!(
            matches!(first, Poll::Ready(Ok(()))),
            "first flush completes",
            true,
            matches!(first, Poll::Ready(Ok(())))
        );

        let second = future.as_mut().poll(&mut context);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Err(SinkError::PolledAfterCompletion))),
            "second flush poll fails closed",
            true,
            matches!(second, Poll::Ready(Err(SinkError::PolledAfterCompletion)))
        );

        let flush_count = {
            let state = sink.state.lock();
            state.flush_count
        };
        crate::assert_with_log!(flush_count == 1, "flush invoked once", 1usize, flush_count);
        crate::test_complete!("test_flush_future_repoll_after_completion_fails_closed");
    }

    #[test]
    fn test_close_future_repoll_after_completion_fails_closed() {
        init_test("test_close_future_repoll_after_completion_fails_closed");
        let mut sink = TrackingSink::new(TrackingSinkState::new());
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let mut future = sink.close();
        let mut future = Pin::new(&mut future);

        let first = future.as_mut().poll(&mut context);
        crate::assert_with_log!(
            matches!(first, Poll::Ready(Ok(()))),
            "first close completes",
            true,
            matches!(first, Poll::Ready(Ok(())))
        );

        let second = future.as_mut().poll(&mut context);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Err(SinkError::PolledAfterCompletion))),
            "second close poll fails closed",
            true,
            matches!(second, Poll::Ready(Err(SinkError::PolledAfterCompletion)))
        );

        let closed = {
            let state = sink.state.lock();
            state.closed
        };
        crate::assert_with_log!(closed, "sink closed", true, closed);
        crate::test_complete!("test_close_future_repoll_after_completion_fails_closed");
    }

    #[test]
    fn test_buffered_sink_defers_send_until_flush() {
        init_test("test_buffered_sink_defers_send_until_flush");
        let mut buffered = BufferedSink::new(CollectingSink::new(), 2);
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);

        let first = Pin::new(&mut buffered).poll_send(&mut context, create_symbol(1));
        let second = Pin::new(&mut buffered).poll_send(&mut context, create_symbol(2));
        crate::assert_with_log!(
            matches!(first, Poll::Ready(Ok(()))),
            "first buffered",
            true,
            matches!(first, Poll::Ready(Ok(())))
        );
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Ok(()))),
            "second buffered",
            true,
            matches!(second, Poll::Ready(Ok(())))
        );
        crate::assert_with_log!(
            buffered.inner.symbols.is_empty(),
            "inner empty before flush",
            true,
            buffered.inner.symbols.is_empty()
        );

        let flushed = Pin::new(&mut buffered).poll_flush(&mut context);
        crate::assert_with_log!(
            matches!(flushed, Poll::Ready(Ok(()))),
            "flush ok",
            true,
            matches!(flushed, Poll::Ready(Ok(())))
        );
        crate::assert_with_log!(
            buffered.inner.symbols.len() == 2,
            "inner received",
            2usize,
            buffered.inner.symbols.len()
        );
        crate::test_complete!("test_buffered_sink_defers_send_until_flush");
    }

    #[test]
    fn test_buffered_sink_zero_capacity_fails_without_staging() {
        init_test("test_buffered_sink_zero_capacity_fails_without_staging");
        let mut buffered = BufferedSink::new(CollectingSink::new(), 0);
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);

        let ready = Pin::new(&mut buffered).poll_ready(&mut context);
        crate::assert_with_log!(
            matches!(ready, Poll::Ready(Err(SinkError::BufferFull))),
            "zero-capacity buffered sink reports no local capacity",
            true,
            matches!(ready, Poll::Ready(Err(SinkError::BufferFull)))
        );

        let sent = Pin::new(&mut buffered).poll_send(&mut context, create_symbol(99));
        crate::assert_with_log!(
            matches!(sent, Poll::Ready(Err(SinkError::BufferFull))),
            "zero-capacity buffered sink rejects sends instead of staging forever",
            true,
            matches!(sent, Poll::Ready(Err(SinkError::BufferFull)))
        );
        crate::assert_with_log!(
            buffered.buffer.is_empty() && buffered.staged_symbols.is_empty(),
            "rejected symbol is not retained in undrainable local queues",
            true,
            buffered.buffer.is_empty() && buffered.staged_symbols.is_empty()
        );
        crate::assert_with_log!(
            buffered.inner.symbols().is_empty(),
            "rejected symbol is not delivered to the inner sink",
            true,
            buffered.inner.symbols().is_empty()
        );
        crate::test_complete!("test_buffered_sink_zero_capacity_fails_without_staging");
    }

    #[test]
    fn test_buffered_sink_close_flushes_buffer_before_closing_inner() {
        init_test("test_buffered_sink_close_flushes_buffer_before_closing_inner");
        let inner = TrackingSink::new(TrackingSinkState::new());
        let state = inner.state();
        let mut buffered = BufferedSink::new(inner, 3);

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        for esi in [21_u32, 22_u32] {
            let sent = Pin::new(&mut buffered).poll_send(&mut context, create_symbol(esi));
            crate::assert_with_log!(
                matches!(sent, Poll::Ready(Ok(()))),
                "symbol accepted into the local buffer before close",
                true,
                matches!(sent, Poll::Ready(Ok(())))
            );
        }

        let sent_before_close = {
            let state = state.lock();
            state.sent.len()
        };
        crate::assert_with_log!(
            sent_before_close == 0,
            "buffered symbols are not emitted until flush or close",
            0usize,
            sent_before_close
        );

        let closed = Pin::new(&mut buffered).poll_close(&mut context);
        crate::assert_with_log!(
            matches!(closed, Poll::Ready(Ok(()))),
            "close completes after flushing buffered symbols",
            true,
            matches!(closed, Poll::Ready(Ok(())))
        );

        let (sent_ids, flush_count, inner_closed) = {
            let state = state.lock();
            (
                state
                    .sent
                    .iter()
                    .map(|symbol| symbol.symbol().id().esi())
                    .collect::<Vec<_>>(),
                state.flush_count,
                state.closed,
            )
        };
        crate::assert_with_log!(
            sent_ids == vec![21, 22],
            "close flushes buffered symbols in FIFO order",
            vec![21_u32, 22_u32],
            sent_ids
        );
        crate::assert_with_log!(
            flush_count == 1,
            "close invokes the inner flush before closing",
            1usize,
            flush_count
        );
        crate::assert_with_log!(
            inner_closed,
            "inner sink is closed after the buffered flush",
            true,
            inner_closed
        );
        crate::assert_with_log!(
            buffered.buffer.is_empty() && buffered.staged_symbols.is_empty(),
            "all buffered state is drained by close",
            true,
            buffered.buffer.is_empty() && buffered.staged_symbols.is_empty()
        );
        crate::test_complete!("test_buffered_sink_close_flushes_buffer_before_closing_inner");
    }

    #[test]
    fn test_buffered_sink_ready_pending_when_inner_not_ready() {
        init_test("test_buffered_sink_ready_pending_when_inner_not_ready");
        let inner = TrackingSink::new({
            let mut state = TrackingSinkState::new();
            // The terminal-error probe in poll_send's poll_ready path consumes
            // one poll_ready call on the inner. Set ready_after=2 so the inner
            // is still not ready when the full-buffer flush attempts to drain.
            state.ready_after = 2;
            state
        });
        let mut buffered = BufferedSink::new(inner, 1);

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let send = Pin::new(&mut buffered).poll_send(&mut context, create_symbol(7));
        crate::assert_with_log!(
            matches!(send, Poll::Ready(Ok(()))),
            "buffered send",
            true,
            matches!(send, Poll::Ready(Ok(())))
        );

        let ready = Pin::new(&mut buffered).poll_ready(&mut context);
        crate::assert_with_log!(
            matches!(ready, Poll::Pending),
            "ready pending",
            true,
            matches!(ready, Poll::Pending)
        );
        crate::assert_with_log!(
            buffered.buffer.len() == 1,
            "buffer retained",
            1usize,
            buffered.buffer.len()
        );
        crate::test_complete!("test_buffered_sink_ready_pending_when_inner_not_ready");
    }

    #[test]
    fn test_buffered_sink_pending_full_send_retains_staged_symbol() {
        init_test("test_buffered_sink_pending_full_send_retains_staged_symbol");
        let inner = TrackingSink::new({
            let mut state = TrackingSinkState::new();
            // First send consumes one transient pending poll via the terminal
            // probe. The second send then sees another transient pending in the
            // full-buffer flush path and must retain the staged symbol.
            state.ready_after = 3;
            state
        });
        let mut buffered = BufferedSink::new(inner, 1);

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let first = Pin::new(&mut buffered).poll_send(&mut context, create_symbol(1));
        crate::assert_with_log!(
            matches!(first, Poll::Ready(Ok(()))),
            "first symbol buffered",
            true,
            matches!(first, Poll::Ready(Ok(())))
        );

        // When the primary buffer is full and the inner sink is transiently
        // pending, BufferedSink stages the overflow symbol and returns Ready(Ok)
        // rather than Pending: this prevents callers from retrying the send and
        // causing duplicate delivery. The symbol is retained (not dropped) in the
        // staged backlog and the original buffered symbol is preserved.
        let second = Pin::new(&mut buffered).poll_send(&mut context, create_symbol(2));
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Ok(()))),
            "second send is accepted into the staged backlog instead of dropping",
            true,
            matches!(second, Poll::Ready(Ok(())))
        );
        crate::assert_with_log!(
            buffered.buffer.len() == 1,
            "full buffer still holds original symbol",
            1usize,
            buffered.buffer.len()
        );
        crate::assert_with_log!(
            buffered.staged_symbols.len() == 1,
            "staged symbol retained across flush backpressure",
            true,
            buffered.staged_symbols.len() == 1
        );

        let flushed = Pin::new(&mut buffered).poll_flush(&mut context);
        crate::assert_with_log!(
            matches!(flushed, Poll::Ready(Ok(()))),
            "flush drains both buffered and pending symbols",
            true,
            matches!(flushed, Poll::Ready(Ok(())))
        );

        let sent_ids = {
            let state = buffered.inner.state.lock();
            state
                .sent
                .iter()
                .map(|symbol| symbol.symbol().id().esi())
                .collect::<Vec<_>>()
        };
        crate::assert_with_log!(
            sent_ids == vec![1, 2],
            "flush preserves symbol order and retention",
            vec![1_u32, 2_u32],
            sent_ids
        );
        crate::assert_with_log!(
            buffered.staged_symbols.is_empty(),
            "staged backlog cleared after flush",
            true,
            buffered.staged_symbols.is_empty()
        );
        crate::test_complete!("test_buffered_sink_pending_full_send_retains_staged_symbol");
    }

    #[test]
    fn test_buffered_sink_direct_poll_send_preserves_fifo_with_staged_backlog() {
        init_test("test_buffered_sink_direct_poll_send_preserves_fifo_with_staged_backlog");
        let inner = SequencedSendSink::new(2);
        let state = inner.state();
        let mut buffered = BufferedSink::new(inner, 2);

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);

        let first = Pin::new(&mut buffered).poll_send(&mut context, create_symbol(1));
        let second = Pin::new(&mut buffered).poll_send(&mut context, create_symbol(2));
        let third = Pin::new(&mut buffered).poll_send(&mut context, create_symbol(3));

        crate::assert_with_log!(
            matches!(first, Poll::Ready(Ok(()))),
            "first symbol buffered",
            true,
            matches!(first, Poll::Ready(Ok(())))
        );
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Ok(()))),
            "second symbol buffered",
            true,
            matches!(second, Poll::Ready(Ok(())))
        );
        // The third send finds the primary buffer full, performs a partial drain
        // (flushing the head symbol to the inner sink), and is then accepted into
        // the freed buffer slot, returning Ready(Ok) rather than Pending. Accepting
        // the symbol avoids caller retries and duplicate delivery; FIFO order is
        // preserved because only the head symbol drained.
        crate::assert_with_log!(
            matches!(third, Poll::Ready(Ok(()))),
            "third symbol is accepted after a partial head drain",
            true,
            matches!(third, Poll::Ready(Ok(())))
        );

        let sent_after_third = {
            let state = state.lock();
            state
                .sent
                .iter()
                .map(|symbol| symbol.symbol().id().esi())
                .collect::<Vec<_>>()
        };
        crate::assert_with_log!(
            sent_after_third == vec![1],
            "partial drain only sends the head symbol",
            vec![1_u32],
            sent_after_third
        );

        let fourth = Pin::new(&mut buffered).poll_send(&mut context, create_symbol(4));
        crate::assert_with_log!(
            matches!(fourth, Poll::Ready(Ok(()))),
            "fourth direct send is retained and drained without reordering",
            true,
            matches!(fourth, Poll::Ready(Ok(())))
        );

        let flushed = Pin::new(&mut buffered).poll_flush(&mut context);
        crate::assert_with_log!(
            matches!(flushed, Poll::Ready(Ok(()))),
            "final flush completes",
            true,
            matches!(flushed, Poll::Ready(Ok(())))
        );

        let sent_ids = {
            let state = state.lock();
            state
                .sent
                .iter()
                .map(|symbol| symbol.symbol().id().esi())
                .collect::<Vec<_>>()
        };
        crate::assert_with_log!(
            sent_ids == vec![1, 2, 3, 4],
            "all directly-polled sends retain FIFO order",
            vec![1_u32, 2_u32, 3_u32, 4_u32],
            sent_ids
        );
        crate::assert_with_log!(
            buffered.buffer.is_empty(),
            "local buffer drained",
            true,
            buffered.buffer.is_empty()
        );
        crate::assert_with_log!(
            buffered.staged_symbols.is_empty(),
            "staged backlog drained",
            true,
            buffered.staged_symbols.is_empty()
        );
        crate::test_complete!(
            "test_buffered_sink_direct_poll_send_preserves_fifo_with_staged_backlog"
        );
    }

    #[test]
    fn test_buffered_sink_ready_errors_when_inner_closed() {
        init_test("test_buffered_sink_ready_errors_when_inner_closed");
        let inner = TrackingSink::new({
            let mut state = TrackingSinkState::new();
            state.closed = true;
            state
        });
        let mut buffered = BufferedSink::new(inner, 2);

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let ready = Pin::new(&mut buffered).poll_ready(&mut context);
        crate::assert_with_log!(
            matches!(ready, Poll::Ready(Err(SinkError::Closed))),
            "closed inner fails poll_ready",
            true,
            matches!(ready, Poll::Ready(Err(SinkError::Closed)))
        );
        crate::assert_with_log!(
            buffered.buffer.is_empty(),
            "buffer remains empty",
            true,
            buffered.buffer.is_empty()
        );
        crate::test_complete!("test_buffered_sink_ready_errors_when_inner_closed");
    }

    #[test]
    fn test_buffered_sink_send_future_rejects_closed_inner_without_buffering() {
        init_test("test_buffered_sink_send_future_rejects_closed_inner_without_buffering");
        let inner = TrackingSink::new({
            let mut state = TrackingSinkState::new();
            state.closed = true;
            state
        });
        let mut buffered = BufferedSink::new(inner, 2);

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        {
            let mut send = buffered.send(create_symbol(13));
            let poll = Pin::new(&mut send).poll(&mut context);
            crate::assert_with_log!(
                matches!(poll, Poll::Ready(Err(SinkError::Closed))),
                "closed inner fails send future",
                true,
                matches!(poll, Poll::Ready(Err(SinkError::Closed)))
            );
        }
        crate::assert_with_log!(
            buffered.buffer.is_empty(),
            "symbol not stranded in buffer",
            true,
            buffered.buffer.is_empty()
        );
        crate::test_complete!(
            "test_buffered_sink_send_future_rejects_closed_inner_without_buffering"
        );
    }

    #[test]
    fn test_buffered_sink_ready_still_buffers_through_transient_inner_pending() {
        init_test("test_buffered_sink_ready_still_buffers_through_transient_inner_pending");
        let inner = TrackingSink::new({
            let mut state = TrackingSinkState::new();
            state.ready_after = 1;
            state
        });
        let mut buffered = BufferedSink::new(inner, 2);

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let ready = Pin::new(&mut buffered).poll_ready(&mut context);
        crate::assert_with_log!(
            matches!(ready, Poll::Ready(Ok(()))),
            "transient inner pending still permits buffering",
            true,
            matches!(ready, Poll::Ready(Ok(())))
        );

        let send = Pin::new(&mut buffered).poll_send(&mut context, create_symbol(14));
        crate::assert_with_log!(
            matches!(send, Poll::Ready(Ok(()))),
            "send buffers symbol despite transient backpressure",
            true,
            matches!(send, Poll::Ready(Ok(())))
        );
        crate::assert_with_log!(
            buffered.buffer.len() == 1,
            "symbol buffered locally",
            1usize,
            buffered.buffer.len()
        );
        crate::test_complete!(
            "test_buffered_sink_ready_still_buffers_through_transient_inner_pending"
        );
    }

    #[test]
    fn test_channel_sink_pending_when_full_and_ready_after_recv() {
        init_test("test_channel_sink_pending_when_full_and_ready_after_recv");
        let (mut sink, mut stream) = channel(1);
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);

        let ready = Pin::new(&mut sink).poll_ready(&mut context);
        crate::assert_with_log!(
            matches!(ready, Poll::Ready(Ok(()))),
            "ready ok",
            true,
            matches!(ready, Poll::Ready(Ok(())))
        );
        let send = Pin::new(&mut sink).poll_send(&mut context, create_symbol(1));
        crate::assert_with_log!(
            matches!(send, Poll::Ready(Ok(()))),
            "send ok",
            true,
            matches!(send, Poll::Ready(Ok(())))
        );

        let pending = Pin::new(&mut sink).poll_ready(&mut context);
        crate::assert_with_log!(
            matches!(pending, Poll::Pending),
            "pending when full",
            true,
            matches!(pending, Poll::Pending)
        );
        let queued = sink
            .waiter
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Acquire));
        crate::assert_with_log!(queued, "waiter queued", true, queued);

        future::block_on(async {
            let _ = stream.next().await.unwrap().unwrap();
        });

        let ready_after = Pin::new(&mut sink).poll_ready(&mut context);
        crate::assert_with_log!(
            matches!(ready_after, Poll::Ready(Ok(()))),
            "ready after recv",
            true,
            matches!(ready_after, Poll::Ready(Ok(())))
        );
        let queued_after = sink
            .waiter
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Acquire));
        crate::assert_with_log!(!queued_after, "waiter cleared", false, queued_after);

        crate::test_complete!("test_channel_sink_pending_when_full_and_ready_after_recv");
    }

    #[test]
    fn test_channel_sink_drop_removes_queued_waiter() {
        init_test("test_channel_sink_drop_removes_queued_waiter");
        let shared = Arc::new(SharedChannel::new(1));
        {
            let mut queue = shared.queue.lock();
            queue.push_back(create_symbol(1));
        }

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let mut sink = ChannelSink::new(Arc::clone(&shared));
        let pending = Pin::new(&mut sink).poll_ready(&mut context);
        crate::assert_with_log!(
            matches!(pending, Poll::Pending),
            "ready pending when full",
            true,
            matches!(pending, Poll::Pending)
        );
        let queued_before = shared.send_wakers.lock().len();
        crate::assert_with_log!(
            queued_before == 1,
            "one waiter registered",
            1usize,
            queued_before
        );

        drop(sink);

        let queued_after = shared.send_wakers.lock().len();
        crate::assert_with_log!(
            queued_after == 0,
            "queued waiter removed on drop",
            0usize,
            queued_after
        );
        crate::test_complete!("test_channel_sink_drop_removes_queued_waiter");
    }

    #[test]
    fn test_channel_sink_refreshes_queued_waker_on_repoll() {
        init_test("test_channel_sink_refreshes_queued_waker_on_repoll");
        let (mut sink, mut stream) = channel(1);
        let ready_waker = noop_waker();
        let mut ready_context = Context::from_waker(&ready_waker);
        let _ = Pin::new(&mut sink).poll_send(&mut ready_context, create_symbol(1));

        let first_flag = Arc::new(AtomicBool::new(false));
        let second_flag = Arc::new(AtomicBool::new(false));
        let first_waker = flagged_waker(Arc::clone(&first_flag));
        let second_waker = flagged_waker(Arc::clone(&second_flag));
        let mut first_context = Context::from_waker(&first_waker);
        let mut second_context = Context::from_waker(&second_waker);

        let first_pending = Pin::new(&mut sink).poll_ready(&mut first_context);
        crate::assert_with_log!(
            matches!(first_pending, Poll::Pending),
            "first poll pending",
            true,
            matches!(first_pending, Poll::Pending)
        );

        let second_pending = Pin::new(&mut sink).poll_ready(&mut second_context);
        crate::assert_with_log!(
            matches!(second_pending, Poll::Pending),
            "second poll pending",
            true,
            matches!(second_pending, Poll::Pending)
        );

        let _ = SymbolStream::poll_next(Pin::new(&mut stream), &mut ready_context);

        let first_woke = first_flag.load(Ordering::Acquire);
        let second_woke = second_flag.load(Ordering::Acquire);
        crate::assert_with_log!(!first_woke, "stale waker not used", false, first_woke);
        crate::assert_with_log!(second_woke, "latest waker used", true, second_woke);
        crate::test_complete!("test_channel_sink_refreshes_queued_waker_on_repoll");
    }

    #[test]
    fn test_channel_sink_skips_stale_recv_waiter_entries() {
        init_test("test_channel_sink_skips_stale_recv_waiter_entries");
        let shared = Arc::new(SharedChannel::new(1));
        let mut sink = ChannelSink::new(Arc::clone(&shared));

        let stale_flag = Arc::new(AtomicBool::new(false));
        let active_flag = Arc::new(AtomicBool::new(false));
        let stale_queued = Arc::new(AtomicBool::new(false));
        let active_queued = Arc::new(AtomicBool::new(true));

        {
            let mut recv_wakers = shared.recv_wakers.lock();
            recv_wakers.push(ChannelWaiter {
                waker: flagged_waker(Arc::clone(&active_flag)),
                queued: Arc::clone(&active_queued),
            });
            // Stale waiter remains in the queue until pop-time pruning.
            recv_wakers.push(ChannelWaiter {
                waker: flagged_waker(Arc::clone(&stale_flag)),
                queued: Arc::clone(&stale_queued),
            });
        }

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let send = Pin::new(&mut sink).poll_send(&mut context, create_symbol(5));
        crate::assert_with_log!(
            matches!(send, Poll::Ready(Ok(()))),
            "send succeeds",
            true,
            matches!(send, Poll::Ready(Ok(())))
        );

        let stale_woke = stale_flag.load(Ordering::Acquire);
        let active_woke = active_flag.load(Ordering::Acquire);
        crate::assert_with_log!(!stale_woke, "stale waiter not woken", false, stale_woke);
        crate::assert_with_log!(active_woke, "active waiter woken", true, active_woke);
        let active_cleared = !active_queued.load(Ordering::Acquire);
        crate::assert_with_log!(
            active_cleared,
            "active waiter flag cleared",
            true,
            active_cleared
        );
        let recv_waiters_empty = shared.recv_wakers.lock().is_empty();
        crate::assert_with_log!(
            recv_waiters_empty,
            "stale entries pruned",
            true,
            recv_waiters_empty
        );

        crate::test_complete!("test_channel_sink_skips_stale_recv_waiter_entries");
    }

    #[test]
    fn test_channel_sink_wakes_oldest_recv_waiter_first() {
        init_test("test_channel_sink_wakes_oldest_recv_waiter_first");
        let shared = Arc::new(SharedChannel::new(2));
        let mut sink = ChannelSink::new(Arc::clone(&shared));

        let first_flag = Arc::new(AtomicBool::new(false));
        let second_flag = Arc::new(AtomicBool::new(false));
        let first_queued = Arc::new(AtomicBool::new(true));
        let second_queued = Arc::new(AtomicBool::new(true));

        {
            let mut recv_wakers = shared.recv_wakers.lock();
            recv_wakers.push(ChannelWaiter {
                waker: flagged_waker(Arc::clone(&first_flag)),
                queued: Arc::clone(&first_queued),
            });
            recv_wakers.push(ChannelWaiter {
                waker: flagged_waker(Arc::clone(&second_flag)),
                queued: Arc::clone(&second_queued),
            });
        }

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let send = Pin::new(&mut sink).poll_send(&mut context, create_symbol(9));
        crate::assert_with_log!(
            matches!(send, Poll::Ready(Ok(()))),
            "send succeeds",
            true,
            matches!(send, Poll::Ready(Ok(())))
        );

        let first_woke = first_flag.load(Ordering::Acquire);
        let second_woke = second_flag.load(Ordering::Acquire);
        crate::assert_with_log!(first_woke, "first waiter woken", true, first_woke);
        crate::assert_with_log!(
            !second_woke,
            "second waiter still waiting",
            false,
            second_woke
        );
        let second_still_queued = second_queued.load(Ordering::Acquire);
        crate::assert_with_log!(
            second_still_queued,
            "second waiter remains queued",
            true,
            second_still_queued
        );
        let queued_len = shared.recv_wakers.lock().len();
        crate::assert_with_log!(queued_len == 1, "one waiter remains", 1usize, queued_len);

        crate::test_complete!("test_channel_sink_wakes_oldest_recv_waiter_first");
    }

    #[test]
    fn test_channel_sink_poll_send_buffer_full() {
        init_test("test_channel_sink_poll_send_buffer_full");
        let (mut sink, _stream) = channel(1);
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);

        let ready = Pin::new(&mut sink).poll_ready(&mut context);
        crate::assert_with_log!(
            matches!(ready, Poll::Ready(Ok(()))),
            "ready ok",
            true,
            matches!(ready, Poll::Ready(Ok(())))
        );
        let send = Pin::new(&mut sink).poll_send(&mut context, create_symbol(1));
        crate::assert_with_log!(
            matches!(send, Poll::Ready(Ok(()))),
            "send ok",
            true,
            matches!(send, Poll::Ready(Ok(())))
        );

        let full = Pin::new(&mut sink).poll_send(&mut context, create_symbol(2));
        crate::assert_with_log!(
            matches!(full, Poll::Ready(Err(SinkError::BufferFull))),
            "buffer full",
            true,
            matches!(full, Poll::Ready(Err(SinkError::BufferFull)))
        );

        crate::test_complete!("test_channel_sink_poll_send_buffer_full");
    }

    #[test]
    fn test_collecting_sink_collects() {
        init_test("test_collecting_sink_collects");
        let mut sink = CollectingSink::new();

        future::block_on(async {
            sink.send(create_symbol(1)).await.unwrap();
            sink.send(create_symbol(2)).await.unwrap();
        });

        crate::assert_with_log!(
            sink.symbols().len() == 2,
            "len",
            2usize,
            sink.symbols().len()
        );
        crate::test_complete!("test_collecting_sink_collects");
    }

    #[test]
    fn test_channel_sink_close_sets_closed_and_ready_errors() {
        init_test("test_channel_sink_close_sets_closed_and_ready_errors");
        let (mut sink, _stream) = channel(1);
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);

        let close = Pin::new(&mut sink).poll_close(&mut context);
        crate::assert_with_log!(
            matches!(close, Poll::Ready(Ok(()))),
            "close ok",
            true,
            matches!(close, Poll::Ready(Ok(())))
        );

        let ready = Pin::new(&mut sink).poll_ready(&mut context);
        crate::assert_with_log!(
            matches!(ready, Poll::Ready(Err(SinkError::Closed))),
            "ready closed",
            true,
            matches!(ready, Poll::Ready(Err(SinkError::Closed)))
        );

        crate::test_complete!("test_channel_sink_close_sets_closed_and_ready_errors");
    }
