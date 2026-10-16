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
    use crate::transport::sink::{SymbolSink, SymbolSinkExt};
    use crate::transport::{SymbolStreamExt, channel};
    use crate::types::{Symbol, SymbolId, SymbolKind};
    use futures_lite::future;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::task::Waker;
    use std::thread;
    use std::time::Instant;

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

    fn collect_esis<S: SymbolStream + Unpin>(stream: &mut S) -> Vec<u32> {
        future::block_on(async {
            let mut out = Vec::new();
            while let Some(item) = stream.next().await {
                out.push(item.unwrap().symbol().id().esi());
            }
            out
        })
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
            self.flag.store(true, Ordering::SeqCst);
        }
    }

    fn flagged_waker(flag: Arc<AtomicBool>) -> Waker {
        Waker::from(Arc::new(FlagWake { flag }))
    }

    struct PendingStream;

    impl SymbolStream for PendingStream {
        fn poll_next(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
            Poll::Pending
        }
    }

    struct AlwaysReadyRejectingStream {
        remaining: usize,
        emitted: Arc<AtomicUsize>,
    }

    impl AlwaysReadyRejectingStream {
        fn new(remaining: usize, emitted: Arc<AtomicUsize>) -> Self {
            Self { remaining, emitted }
        }
    }

    impl SymbolStream for AlwaysReadyRejectingStream {
        fn poll_next(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
            if self.remaining == 0 {
                return Poll::Ready(None);
            }
            self.remaining = self.remaining.saturating_sub(1);
            self.emitted.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Some(Ok(create_symbol(2))))
        }
    }

    struct AlwaysReadySymbolStream {
        next_esi: u32,
        end_esi: u32,
        emitted: Arc<AtomicUsize>,
    }

    impl AlwaysReadySymbolStream {
        fn new(total: usize, emitted: Arc<AtomicUsize>) -> Self {
            Self {
                next_esi: 0,
                end_esi: total as u32,
                emitted,
            }
        }
    }

    impl SymbolStream for AlwaysReadySymbolStream {
        fn poll_next(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
            if self.next_esi >= self.end_esi {
                return Poll::Ready(None);
            }

            let esi = self.next_esi;
            self.next_esi = self.next_esi.saturating_add(1);
            self.emitted.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Some(Ok(create_symbol(esi))))
        }
    }

    struct ErrorStream {
        returned: bool,
    }

    impl ErrorStream {
        fn new() -> Self {
            Self { returned: false }
        }
    }

    impl SymbolStream for ErrorStream {
        fn poll_next(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
            if self.returned {
                Poll::Ready(None)
            } else {
                self.returned = true;
                Poll::Ready(Some(Err(StreamError::Reset)))
            }
        }
    }

    struct ExhaustedStream {
        items: Vec<AuthenticatedSymbol>,
        index: usize,
    }

    impl ExhaustedStream {
        fn new(items: Vec<AuthenticatedSymbol>) -> Self {
            Self { items, index: 0 }
        }
    }

    impl SymbolStream for ExhaustedStream {
        fn poll_next(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
            if self.index < self.items.len() {
                let item = self.items[self.index].clone();
                self.index += 1;
                Poll::Ready(Some(Ok(item)))
            } else {
                Poll::Ready(None)
            }
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            let remaining = self.items.len().saturating_sub(self.index);
            (remaining, Some(remaining))
        }

        fn is_exhausted(&self) -> bool {
            self.index >= self.items.len()
        }
    }

    struct EmptyThenPanics {
        polls: Arc<AtomicUsize>,
    }

    impl EmptyThenPanics {
        fn new(polls: Arc<AtomicUsize>) -> Self {
            Self { polls }
        }
    }

    impl SymbolStream for EmptyThenPanics {
        fn poll_next(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
            let polls = self.polls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(polls, 0, "inner stream repolled after exhaustion");
            Poll::Ready(None)
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            (0, Some(0))
        }

        fn is_exhausted(&self) -> bool {
            self.polls.load(Ordering::SeqCst) > 0
        }
    }

    #[test]
    fn test_next_future_yields_items_and_none() {
        init_test("test_next_future_yields_items_and_none");
        let mut stream = VecStream::new(vec![create_symbol(1), create_symbol(2)]);

        future::block_on(async {
            let first = stream.next().await.unwrap().unwrap();
            let second = stream.next().await.unwrap().unwrap();
            let done = stream.next().await;

            let first_esi = first.symbol().id().esi();
            let second_esi = second.symbol().id().esi();
            crate::assert_with_log!(first_esi == 1, "first esi", 1u32, first_esi);
            crate::assert_with_log!(second_esi == 2, "second esi", 2u32, second_esi);
            crate::assert_with_log!(done.is_none(), "stream done", true, done.is_none());
        });

        crate::test_complete!("test_next_future_yields_items_and_none");
    }

    #[test]
    fn test_next_future_repoll_after_completion_fails_closed_without_consuming_next_item() {
        init_test(
            "test_next_future_repoll_after_completion_fails_closed_without_consuming_next_item",
        );
        let mut stream = VecStream::new(vec![create_symbol(1), create_symbol(2)]);
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let mut future = stream.next();
        let mut pinned = Pin::new(&mut future);

        let first = pinned.as_mut().poll(&mut context);
        crate::assert_with_log!(
            matches!(&first, Poll::Ready(Some(Ok(symbol))) if symbol.symbol().id().esi() == 1),
            "first poll yields first symbol",
            true,
            &first
        );

        let second = pinned.as_mut().poll(&mut context);
        crate::assert_with_log!(
            matches!(
                &second,
                Poll::Ready(Some(Err(StreamError::PolledAfterCompletion)))
            ),
            "second poll fails closed",
            true,
            &second
        );

        let mut next_future = stream.next();
        let third = Pin::new(&mut next_future).poll(&mut context);
        crate::assert_with_log!(
            matches!(&third, Poll::Ready(Some(Ok(symbol))) if symbol.symbol().id().esi() == 2),
            "fresh future still yields second symbol",
            true,
            &third
        );

        crate::test_complete!(
            "test_next_future_repoll_after_completion_fails_closed_without_consuming_next_item"
        );
    }

    #[test]
    fn test_next_future_repoll_after_error_fails_closed() {
        init_test("test_next_future_repoll_after_error_fails_closed");
        let mut stream = ErrorStream::new();
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let mut future = stream.next();
        let mut future = Pin::new(&mut future);

        let first = future.as_mut().poll(&mut context);
        crate::assert_with_log!(
            matches!(&first, Poll::Ready(Some(Err(StreamError::Reset)))),
            "first poll yields source error",
            true,
            &first
        );

        let second = future.as_mut().poll(&mut context);
        crate::assert_with_log!(
            matches!(
                &second,
                Poll::Ready(Some(Err(StreamError::PolledAfterCompletion)))
            ),
            "second poll fails closed after error",
            true,
            &second
        );

        crate::test_complete!("test_next_future_repoll_after_error_fails_closed");
    }

    #[test]
    fn test_next_future_repoll_after_none_fails_closed() {
        init_test("test_next_future_repoll_after_none_fails_closed");
        let mut stream = VecStream::new(Vec::new());
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let mut future = stream.next();
        let mut future = Pin::new(&mut future);

        let first = future.as_mut().poll(&mut context);
        crate::assert_with_log!(
            matches!(&first, Poll::Ready(None)),
            "first poll reports exhaustion",
            true,
            &first
        );

        let second = future.as_mut().poll(&mut context);
        crate::assert_with_log!(
            matches!(
                &second,
                Poll::Ready(Some(Err(StreamError::PolledAfterCompletion)))
            ),
            "second poll fails closed after exhaustion",
            true,
            &second
        );

        crate::test_complete!("test_next_future_repoll_after_none_fails_closed");
    }

    #[test]
    fn test_collect_to_set_deduplicates_and_counts() {
        init_test("test_collect_to_set_deduplicates_and_counts");
        let mut stream = VecStream::new(vec![create_symbol(1), create_symbol(1), create_symbol(2)]);
        let mut set = SymbolSet::new();

        let count = future::block_on(async { stream.collect_to_set(&mut set).await.unwrap() });

        crate::assert_with_log!(count == 2, "unique count", 2usize, count);
        crate::assert_with_log!(set.len() == 2, "set size", 2usize, set.len());
        crate::test_complete!("test_collect_to_set_deduplicates_and_counts");
    }

    #[test]
    fn test_collect_to_set_counts_only_new_insertions_into_prepopulated_set() {
        init_test("test_collect_to_set_counts_only_new_insertions_into_prepopulated_set");
        let mut stream = VecStream::new(vec![create_symbol(1), create_symbol(2)]);
        let mut set = SymbolSet::new();
        set.insert(create_symbol(1).into_symbol());

        let count = future::block_on(async { stream.collect_to_set(&mut set).await.unwrap() });

        crate::assert_with_log!(count == 1, "one new symbol inserted", 1usize, count);
        crate::assert_with_log!(
            set.len() == 2,
            "set contains both unique symbols",
            2usize,
            set.len()
        );
        crate::test_complete!(
            "test_collect_to_set_counts_only_new_insertions_into_prepopulated_set"
        );
    }

    #[test]
    fn test_collect_to_set_duplicate_only_stream_reports_zero_new_insertions() {
        init_test("test_collect_to_set_duplicate_only_stream_reports_zero_new_insertions");
        let mut stream = VecStream::new(vec![create_symbol(7), create_symbol(7)]);
        let mut set = SymbolSet::new();
        set.insert(create_symbol(7).into_symbol());

        let count = future::block_on(async { stream.collect_to_set(&mut set).await.unwrap() });

        crate::assert_with_log!(
            count == 0,
            "duplicate-only stream adds nothing new",
            0usize,
            count
        );
        crate::assert_with_log!(set.len() == 1, "set size unchanged", 1usize, set.len());
        crate::test_complete!(
            "test_collect_to_set_duplicate_only_stream_reports_zero_new_insertions"
        );
    }

    #[test]
    fn test_collect_to_set_repoll_after_completion_fails_closed() {
        init_test("test_collect_to_set_repoll_after_completion_fails_closed");
        let mut stream = VecStream::new(vec![create_symbol(1), create_symbol(1), create_symbol(2)]);
        let mut set = SymbolSet::new();
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let mut future = stream.collect_to_set(&mut set);
        let mut pinned = Pin::new(&mut future);

        let first = pinned.as_mut().poll(&mut context);
        crate::assert_with_log!(
            matches!(&first, Poll::Ready(Ok(2))),
            "first poll completes collection",
            true,
            &first
        );

        let second = pinned.as_mut().poll(&mut context);
        crate::assert_with_log!(
            matches!(
                &second,
                Poll::Ready(Err(StreamError::PolledAfterCompletion))
            ),
            "second poll fails closed",
            true,
            &second
        );

        crate::assert_with_log!(set.len() == 2, "set preserved", 2usize, set.len());
        crate::test_complete!("test_collect_to_set_repoll_after_completion_fails_closed");
    }

    #[test]
    fn test_collect_to_set_yields_after_budget_on_always_ready_stream() {
        init_test("test_collect_to_set_yields_after_budget_on_always_ready_stream");
        let emitted = Arc::new(AtomicUsize::new(0));
        let total = COLLECT_TO_SET_COOPERATIVE_BUDGET + 5;
        let mut stream = AlwaysReadySymbolStream::new(total, Arc::clone(&emitted));
        let mut set = SymbolSet::new();
        let woke = Arc::new(AtomicBool::new(false));
        let waker = flagged_waker(Arc::clone(&woke));
        let mut context = Context::from_waker(&waker);

        {
            let mut future = stream.collect_to_set(&mut set);
            let mut future = Pin::new(&mut future);
            let first = future.as_mut().poll(&mut context);
            crate::assert_with_log!(
                matches!(first, Poll::Pending),
                "first poll yields cooperatively",
                true,
                matches!(first, Poll::Pending)
            );
        }

        crate::assert_with_log!(
            woke.load(Ordering::SeqCst),
            "cooperative yield self-wakes",
            true,
            woke.load(Ordering::SeqCst)
        );
        crate::assert_with_log!(
            emitted.load(Ordering::SeqCst) == COLLECT_TO_SET_COOPERATIVE_BUDGET,
            "drained symbols bounded by budget",
            COLLECT_TO_SET_COOPERATIVE_BUDGET,
            emitted.load(Ordering::SeqCst)
        );
        crate::assert_with_log!(
            set.len() == COLLECT_TO_SET_COOPERATIVE_BUDGET,
            "partial set retained across yield",
            COLLECT_TO_SET_COOPERATIVE_BUDGET,
            set.len()
        );

        {
            let mut future = stream.collect_to_set(&mut set);
            let mut future = Pin::new(&mut future);
            let second = future.as_mut().poll(&mut context);
            crate::assert_with_log!(
                matches!(second, Poll::Ready(Ok(count)) if count == 5),
                "second poll completes collection",
                5,
                second
            );
        }
        crate::assert_with_log!(set.len() == total, "set fully populated", total, set.len());
        crate::test_complete!("test_collect_to_set_yields_after_budget_on_always_ready_stream");
    }

    #[test]
    fn test_next_with_cancel_immediate() {
        init_test("test_next_with_cancel_immediate");
        let (mut sink, mut stream) = channel(1);
        let cx: Cx = Cx::for_testing();
        future::block_on(async {
            SymbolSinkExt::send(&mut sink, create_symbol(5))
                .await
                .unwrap();
        });
        cx.set_cancel_requested(true);

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let mut future = stream.next_with_cancel(&cx);
        let mut pinned = Pin::new(&mut future);

        let first = pinned.as_mut().poll(&mut context);
        crate::assert_with_log!(
            matches!(&first, Poll::Ready(Err(StreamError::Cancelled))),
            "first poll cancels immediately",
            true,
            &first
        );

        let second = pinned.as_mut().poll(&mut context);
        crate::assert_with_log!(
            matches!(
                &second,
                Poll::Ready(Err(StreamError::PolledAfterCompletion))
            ),
            "second poll fails closed",
            true,
            &second
        );

        cx.set_cancel_requested(false);
        let mut next_future = stream.next_with_cancel(&cx);
        let third = Pin::new(&mut next_future).poll(&mut context);
        crate::assert_with_log!(
            matches!(&third, Poll::Ready(Ok(Some(symbol))) if symbol.symbol().id().esi() == 5),
            "cancelled future does not consume queued symbol",
            true,
            &third
        );

        crate::test_complete!("test_next_with_cancel_immediate");
    }

    #[test]
    fn test_next_with_cancel_after_pending() {
        init_test("test_next_with_cancel_after_pending");
        let mut stream = PendingStream;
        let cx: Cx = Cx::for_testing();

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let mut fut = stream.next_with_cancel(&cx);
        let mut fut = Pin::new(&mut fut);

        let first = fut.as_mut().poll(&mut context);
        crate::assert_with_log!(
            matches!(&first, Poll::Pending),
            "first pending",
            true,
            &first
        );

        cx.set_cancel_requested(true);
        let second = fut.as_mut().poll(&mut context);
        crate::assert_with_log!(
            matches!(&second, Poll::Ready(Err(StreamError::Cancelled))),
            "cancel after pending",
            true,
            &second
        );

        let third = fut.as_mut().poll(&mut context);
        crate::assert_with_log!(
            matches!(&third, Poll::Ready(Err(StreamError::PolledAfterCompletion))),
            "third poll fails closed after cancellation",
            true,
            &third
        );

        crate::test_complete!("test_next_with_cancel_after_pending");
    }

    #[test]
    fn test_next_with_cancel_repoll_after_success_fails_closed_without_consuming_next_item() {
        init_test(
            "test_next_with_cancel_repoll_after_success_fails_closed_without_consuming_next_item",
        );
        let mut stream = VecStream::new(vec![create_symbol(1), create_symbol(2)]);
        let cx: Cx = Cx::for_testing();
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let mut future = stream.next_with_cancel(&cx);
        let mut pinned = Pin::new(&mut future);

        let first = pinned.as_mut().poll(&mut context);
        crate::assert_with_log!(
            matches!(&first, Poll::Ready(Ok(Some(symbol))) if symbol.symbol().id().esi() == 1),
            "first poll yields first symbol",
            true,
            &first
        );

        let second = pinned.as_mut().poll(&mut context);
        crate::assert_with_log!(
            matches!(
                &second,
                Poll::Ready(Err(StreamError::PolledAfterCompletion))
            ),
            "second poll fails closed",
            true,
            &second
        );

        let mut next_future = stream.next_with_cancel(&cx);
        let third = Pin::new(&mut next_future).poll(&mut context);
        crate::assert_with_log!(
            matches!(&third, Poll::Ready(Ok(Some(symbol))) if symbol.symbol().id().esi() == 2),
            "fresh future still yields second symbol",
            true,
            &third
        );

        crate::test_complete!(
            "test_next_with_cancel_repoll_after_success_fails_closed_without_consuming_next_item"
        );
    }

    #[test]
    fn test_map_stream_transforms_symbol() {
        init_test("test_map_stream_transforms_symbol");
        let stream = VecStream::new(vec![create_symbol(7)]);
        let mut mapped = stream.map(|symbol| {
            let id = symbol.symbol().id();
            let new_symbol = Symbol::new(id, vec![42u8], SymbolKind::Source);
            AuthenticatedSymbol::new_verified(new_symbol, AuthenticationTag::zero())
        });

        future::block_on(async {
            let item = mapped.next().await.unwrap().unwrap();
            crate::assert_with_log!(
                item.symbol().data() == [42u8],
                "mapped data",
                true,
                item.symbol().data() == [42u8]
            );
        });

        crate::test_complete!("test_map_stream_transforms_symbol");
    }

    #[test]
    fn test_map_stream_tracks_size_hint_and_exhaustion() {
        init_test("test_map_stream_tracks_size_hint_and_exhaustion");
        let stream = ExhaustedStream::new(vec![create_symbol(1), create_symbol(2)]);
        let mut mapped = stream.map(|symbol| symbol);

        let initial_hint = mapped.size_hint();
        crate::assert_with_log!(
            initial_hint == (2, Some(2)),
            "initial hint delegates to inner",
            (2, Some(2)),
            initial_hint
        );

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        while let Poll::Ready(Some(_)) = Pin::new(&mut mapped).poll_next(&mut context) {}

        let exhausted = mapped.is_exhausted();
        let final_hint = mapped.size_hint();
        crate::assert_with_log!(exhausted, "mapped exhausted", true, exhausted);
        crate::assert_with_log!(
            final_hint == (0, Some(0)),
            "mapped hint drops to zero after exhaustion",
            (0, Some(0)),
            final_hint
        );
        crate::test_complete!("test_map_stream_tracks_size_hint_and_exhaustion");
    }

    #[test]
    fn test_map_stream_does_not_repoll_inner_after_exhaustion() {
        init_test("test_map_stream_does_not_repoll_inner_after_exhaustion");
        let polls = Arc::new(AtomicUsize::new(0));
        let inner = EmptyThenPanics::new(Arc::clone(&polls));
        let mut mapped = inner.map(|symbol| symbol);
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);

        let first = Pin::new(&mut mapped).poll_next(&mut context);
        let second = Pin::new(&mut mapped).poll_next(&mut context);

        crate::assert_with_log!(
            matches!(first, Poll::Ready(None)),
            "first poll exhausts mapped stream",
            true,
            matches!(first, Poll::Ready(None))
        );
        crate::assert_with_log!(
            matches!(second, Poll::Ready(None)),
            "second poll stays exhausted without repolling inner",
            true,
            matches!(second, Poll::Ready(None))
        );
        crate::assert_with_log!(
            polls.load(Ordering::SeqCst) == 1,
            "inner polled once",
            1usize,
            polls.load(Ordering::SeqCst)
        );
        crate::test_complete!("test_map_stream_does_not_repoll_inner_after_exhaustion");
    }

    #[test]
    fn test_filter_stream_skips_and_passes() {
        init_test("test_filter_stream_skips_and_passes");
        let stream = VecStream::new(vec![create_symbol(1), create_symbol(2), create_symbol(3)]);
        let mut filtered = stream.filter(|symbol| symbol.symbol().id().esi() % 2 == 1);

        future::block_on(async {
            let first = filtered.next().await.unwrap().unwrap();
            let second = filtered.next().await.unwrap().unwrap();
            let done = filtered.next().await;

            let first_esi = first.symbol().id().esi();
            let second_esi = second.symbol().id().esi();
            crate::assert_with_log!(first_esi == 1, "first", 1u32, first_esi);
            crate::assert_with_log!(second_esi == 3, "second", 3u32, second_esi);
            crate::assert_with_log!(done.is_none(), "done", true, done.is_none());
        });

        crate::test_complete!("test_filter_stream_skips_and_passes");
    }

    #[test]
    fn metamorphic_filter_commutes_with_identity_map() {
        init_test("metamorphic_filter_commutes_with_identity_map");

        let symbols: Vec<_> = (0..8).map(create_symbol).collect();
        let mut filter_then_map = VecStream::new(symbols.clone())
            .filter(|symbol| symbol.symbol().id().esi() % 2 == 0)
            .map(|symbol| symbol);
        let mut map_then_filter = VecStream::new(symbols)
            .map(|symbol| symbol)
            .filter(|symbol| symbol.symbol().id().esi() % 2 == 0);

        assert_eq!(
            collect_esis(&mut filter_then_map),
            collect_esis(&mut map_then_filter),
            "identity map must not perturb filter ordering or membership"
        );

        crate::test_complete!("metamorphic_filter_commutes_with_identity_map");
    }

    #[test]
    fn test_filter_stream_propagates_error() {
        init_test("test_filter_stream_propagates_error");
        let stream = ErrorStream::new();
        let mut filtered = stream.filter(|_symbol| true);

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let poll = Pin::new(&mut filtered).poll_next(&mut context);
        crate::assert_with_log!(
            matches!(poll, Poll::Ready(Some(Err(StreamError::Reset)))),
            "error propagates",
            true,
            matches!(poll, Poll::Ready(Some(Err(StreamError::Reset))))
        );

        crate::test_complete!("test_filter_stream_propagates_error");
    }

    #[test]
    fn test_filter_stream_tracks_size_hint_and_exhaustion() {
        init_test("test_filter_stream_tracks_size_hint_and_exhaustion");
        let stream = ExhaustedStream::new(vec![create_symbol(1), create_symbol(2)]);
        let mut filtered = stream.filter(|symbol| symbol.symbol().id().esi() > 0);

        let initial_hint = filtered.size_hint();
        crate::assert_with_log!(
            initial_hint == (0, Some(2)),
            "filter preserves only the upper bound before exhaustion",
            (0, Some(2)),
            initial_hint
        );

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        while let Poll::Ready(Some(_)) = Pin::new(&mut filtered).poll_next(&mut context) {}

        let exhausted = filtered.is_exhausted();
        let final_hint = filtered.size_hint();
        crate::assert_with_log!(exhausted, "filtered exhausted", true, exhausted);
        crate::assert_with_log!(
            final_hint == (0, Some(0)),
            "filtered hint drops to zero after exhaustion",
            (0, Some(0)),
            final_hint
        );
        crate::test_complete!("test_filter_stream_tracks_size_hint_and_exhaustion");
    }

    #[test]
    fn test_filter_stream_does_not_repoll_inner_after_exhaustion() {
        init_test("test_filter_stream_does_not_repoll_inner_after_exhaustion");
        let polls = Arc::new(AtomicUsize::new(0));
        let inner = EmptyThenPanics::new(Arc::clone(&polls));
        let mut filtered = inner.filter(|_symbol| true);
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);

        let first = Pin::new(&mut filtered).poll_next(&mut context);
        let second = Pin::new(&mut filtered).poll_next(&mut context);

        crate::assert_with_log!(
            matches!(first, Poll::Ready(None)),
            "first poll exhausts filtered stream",
            true,
            matches!(first, Poll::Ready(None))
        );
        crate::assert_with_log!(
            matches!(second, Poll::Ready(None)),
            "second poll stays exhausted without repolling inner",
            true,
            matches!(second, Poll::Ready(None))
        );
        crate::assert_with_log!(
            polls.load(Ordering::SeqCst) == 1,
            "inner polled once",
            1usize,
            polls.load(Ordering::SeqCst)
        );
        crate::test_complete!("test_filter_stream_does_not_repoll_inner_after_exhaustion");
    }

    #[test]
    fn test_filter_stream_yields_after_rejection_budget_on_always_ready_stream() {
        init_test("test_filter_stream_yields_after_rejection_budget_on_always_ready_stream");
        let emitted = Arc::new(AtomicUsize::new(0));
        let stream = AlwaysReadyRejectingStream::new(10_000, Arc::clone(&emitted));
        let mut filtered = stream.filter(|_symbol| false);

        let woke = Arc::new(AtomicBool::new(false));
        let waker = flagged_waker(Arc::clone(&woke));
        let mut context = Context::from_waker(&waker);

        let first = Pin::new(&mut filtered).poll_next(&mut context);
        crate::assert_with_log!(
            matches!(first, Poll::Pending),
            "first poll yields cooperatively",
            true,
            matches!(first, Poll::Pending)
        );
        crate::assert_with_log!(
            woke.load(Ordering::SeqCst),
            "cooperative yield self-wakes",
            true,
            woke.load(Ordering::SeqCst)
        );

        let drained = emitted.load(Ordering::SeqCst);
        crate::assert_with_log!(
            drained == FILTER_REJECTION_BUDGET,
            "drained rejected symbols bounded by budget",
            FILTER_REJECTION_BUDGET,
            drained
        );

        crate::test_complete!(
            "test_filter_stream_yields_after_rejection_budget_on_always_ready_stream"
        );
    }

    #[test]
    fn test_filter_stream_resumes_to_first_match_after_rejection_budget() {
        init_test("test_filter_stream_resumes_to_first_match_after_rejection_budget");
        let emitted = Arc::new(AtomicUsize::new(0));
        let total = FILTER_REJECTION_BUDGET + 1;
        let accepted_esi = FILTER_REJECTION_BUDGET as u32;
        let stream = AlwaysReadySymbolStream::new(total, Arc::clone(&emitted));
        let mut filtered = stream.filter(move |symbol| symbol.symbol().id().esi() == accepted_esi);

        let woke = Arc::new(AtomicBool::new(false));
        let waker = flagged_waker(Arc::clone(&woke));
        let mut context = Context::from_waker(&waker);

        let first = Pin::new(&mut filtered).poll_next(&mut context);
        crate::assert_with_log!(
            matches!(first, Poll::Pending),
            "first poll yields after rejection budget",
            true,
            matches!(first, Poll::Pending)
        );
        crate::assert_with_log!(
            emitted.load(Ordering::SeqCst) == FILTER_REJECTION_BUDGET,
            "rejected symbols drained up to budget",
            FILTER_REJECTION_BUDGET,
            emitted.load(Ordering::SeqCst)
        );
        crate::assert_with_log!(
            woke.load(Ordering::SeqCst),
            "budget yield self-wakes for continuation",
            true,
            woke.load(Ordering::SeqCst)
        );

        let second = Pin::new(&mut filtered).poll_next(&mut context);
        crate::assert_with_log!(
            matches!(&second, Poll::Ready(Some(Ok(symbol))) if symbol.symbol().id().esi() == accepted_esi),
            "next poll resumes and returns first accepted symbol",
            true,
            &second
        );
        crate::assert_with_log!(
            emitted.load(Ordering::SeqCst) == total,
            "accepted symbol consumed exactly once",
            total,
            emitted.load(Ordering::SeqCst)
        );

        crate::test_complete!("test_filter_stream_resumes_to_first_match_after_rejection_budget");
    }

    #[test]
    fn test_merged_stream_round_robin_and_drop_exhausted() {
        init_test("test_merged_stream_round_robin_and_drop_exhausted");
        let s1 = VecStream::new(vec![create_symbol(1), create_symbol(3)]);
        let s2 = VecStream::new(vec![create_symbol(2), create_symbol(4)]);
        let mut merged = MergedStream::new(vec![s1, s2]);

        future::block_on(async {
            let mut out = Vec::new();
            while let Some(item) = merged.next().await {
                out.push(item.unwrap().symbol().id().esi());
            }
            crate::assert_with_log!(
                out == vec![1, 2, 3, 4],
                "merged order",
                true,
                out == vec![1, 2, 3, 4]
            );
        });

        crate::test_complete!("test_merged_stream_round_robin_and_drop_exhausted");
    }

    #[test]
    fn test_merged_stream_size_hint_and_is_exhausted() {
        init_test("test_merged_stream_size_hint_and_is_exhausted");
        let s1 = ExhaustedStream::new(vec![create_symbol(1), create_symbol(2)]);
        let s2 = ExhaustedStream::new(vec![create_symbol(3)]);
        let mut merged = MergedStream::new(vec![s1, s2]);

        let hint = merged.size_hint();
        crate::assert_with_log!(hint == (3, Some(3)), "size hint", (3, Some(3)), hint);

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        while let Poll::Ready(Some(_)) = Pin::new(&mut merged).poll_next(&mut context) {}
        crate::assert_with_log!(
            merged.is_exhausted(),
            "exhausted",
            true,
            merged.is_exhausted()
        );

        crate::test_complete!("test_merged_stream_size_hint_and_is_exhausted");
    }

    #[test]
    fn test_channel_stream_registers_waiter_and_receives() {
        init_test("test_channel_stream_registers_waiter_and_receives");
        let shared = Arc::new(SharedChannel::new(1));
        let mut stream = ChannelStream::new(Arc::clone(&shared));
        let mut sink = crate::transport::sink::ChannelSink::new(shared);

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);

        let first = Pin::new(&mut stream).poll_next(&mut context);
        crate::assert_with_log!(
            matches!(first, Poll::Pending),
            "pending when empty",
            true,
            matches!(first, Poll::Pending)
        );
        let queued = stream
            .waiter
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Acquire));
        crate::assert_with_log!(queued, "waiter queued", true, queued);

        let symbol = create_symbol(9);
        let send = Pin::new(&mut sink).poll_send(&mut context, symbol);
        crate::assert_with_log!(
            matches!(send, Poll::Ready(Ok(()))),
            "send ok",
            true,
            matches!(send, Poll::Ready(Ok(())))
        );

        let second = Pin::new(&mut stream).poll_next(&mut context);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Some(Ok(_)))),
            "receive after send",
            true,
            matches!(second, Poll::Ready(Some(Ok(_))))
        );
        let queued_after = stream
            .waiter
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Acquire));
        crate::assert_with_log!(!queued_after, "waiter cleared", false, queued_after);

        crate::test_complete!("test_channel_stream_registers_waiter_and_receives");
    }

    #[test]
    fn test_channel_stream_drop_removes_queued_waiter() {
        init_test("test_channel_stream_drop_removes_queued_waiter");
        let shared = Arc::new(SharedChannel::new(1));
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let mut stream = ChannelStream::new(Arc::clone(&shared));

        let pending = Pin::new(&mut stream).poll_next(&mut context);
        crate::assert_with_log!(
            matches!(pending, Poll::Pending),
            "pending when queue empty",
            true,
            matches!(pending, Poll::Pending)
        );
        let queued_before = shared.recv_wakers.lock().len();
        crate::assert_with_log!(
            queued_before == 1,
            "one waiter registered",
            1usize,
            queued_before
        );

        drop(stream);

        let queued_after = shared.recv_wakers.lock().len();
        crate::assert_with_log!(
            queued_after == 0,
            "queued waiter removed on drop",
            0usize,
            queued_after
        );
        crate::test_complete!("test_channel_stream_drop_removes_queued_waiter");
    }

    #[test]
    fn test_channel_stream_drop_wakes_next_waiter_for_pending_symbol() {
        init_test("test_channel_stream_drop_wakes_next_waiter_for_pending_symbol");
        let shared = Arc::new(SharedChannel::new(2));
        let mut first_stream = ChannelStream::new(Arc::clone(&shared));
        let mut second_stream = ChannelStream::new(Arc::clone(&shared));
        let mut sink = crate::transport::sink::ChannelSink::new(Arc::clone(&shared));

        let first_flag = Arc::new(AtomicBool::new(false));
        let second_flag = Arc::new(AtomicBool::new(false));
        let first_waker = flagged_waker(Arc::clone(&first_flag));
        let second_waker = flagged_waker(Arc::clone(&second_flag));
        let mut first_context = Context::from_waker(&first_waker);
        let mut second_context = Context::from_waker(&second_waker);

        let first_pending = Pin::new(&mut first_stream).poll_next(&mut first_context);
        crate::assert_with_log!(
            matches!(first_pending, Poll::Pending),
            "first receiver pending",
            true,
            matches!(first_pending, Poll::Pending)
        );
        let second_pending = Pin::new(&mut second_stream).poll_next(&mut second_context);
        crate::assert_with_log!(
            matches!(second_pending, Poll::Pending),
            "second receiver pending",
            true,
            matches!(second_pending, Poll::Pending)
        );

        let ready_waker = noop_waker();
        let mut ready_context = Context::from_waker(&ready_waker);
        let sent = Pin::new(&mut sink).poll_send(&mut ready_context, create_symbol(55));
        crate::assert_with_log!(
            matches!(sent, Poll::Ready(Ok(()))),
            "send succeeds",
            true,
            matches!(sent, Poll::Ready(Ok(())))
        );

        let first_woke = first_flag.load(Ordering::Acquire);
        let second_woke_before_drop = second_flag.load(Ordering::Acquire);
        crate::assert_with_log!(first_woke, "first waiter woken", true, first_woke);
        crate::assert_with_log!(
            !second_woke_before_drop,
            "second waiter still sleeping before baton pass",
            false,
            second_woke_before_drop
        );

        drop(first_stream);

        let second_woke_after_drop = second_flag.load(Ordering::Acquire);
        crate::assert_with_log!(
            second_woke_after_drop,
            "drop baton wakes next receiver",
            true,
            second_woke_after_drop
        );

        let received = Pin::new(&mut second_stream).poll_next(&mut second_context);
        crate::assert_with_log!(
            matches!(received, Poll::Ready(Some(Ok(_)))),
            "second receiver consumes pending symbol",
            true,
            matches!(received, Poll::Ready(Some(Ok(_))))
        );
        let received_esi = match received {
            Poll::Ready(Some(Ok(symbol))) => symbol.symbol().esi(),
            _ => panic!("expected pending symbol"), // ubs:ignore - test logic
        };
        crate::assert_with_log!(
            received_esi == 55,
            "pending symbol forwarded to next waiter",
            55u32,
            received_esi
        );

        crate::test_complete!("test_channel_stream_drop_wakes_next_waiter_for_pending_symbol");
    }

    #[test]
    fn test_channel_stream_refreshes_queued_waker_on_repoll() {
        init_test("test_channel_stream_refreshes_queued_waker_on_repoll");
        let (mut sink, mut stream) = channel(1);

        let first_flag = Arc::new(AtomicBool::new(false));
        let second_flag = Arc::new(AtomicBool::new(false));
        let first_waker = flagged_waker(Arc::clone(&first_flag));
        let second_waker = flagged_waker(Arc::clone(&second_flag));
        let mut first_context = Context::from_waker(&first_waker);
        let mut second_context = Context::from_waker(&second_waker);

        let first_pending = Pin::new(&mut stream).poll_next(&mut first_context);
        crate::assert_with_log!(
            matches!(first_pending, Poll::Pending),
            "first poll pending",
            true,
            matches!(first_pending, Poll::Pending)
        );

        let second_pending = Pin::new(&mut stream).poll_next(&mut second_context);
        crate::assert_with_log!(
            matches!(second_pending, Poll::Pending),
            "second poll pending",
            true,
            matches!(second_pending, Poll::Pending)
        );

        let ready_waker = noop_waker();
        let mut ready_context = Context::from_waker(&ready_waker);
        let sent = Pin::new(&mut sink).poll_send(&mut ready_context, create_symbol(77));
        crate::assert_with_log!(
            matches!(sent, Poll::Ready(Ok(()))),
            "send wakes waiting stream",
            true,
            matches!(sent, Poll::Ready(Ok(())))
        );

        let first_woke = first_flag.load(Ordering::Acquire);
        let second_woke = second_flag.load(Ordering::Acquire);
        crate::assert_with_log!(!first_woke, "stale waker not used", false, first_woke);
        crate::assert_with_log!(second_woke, "latest waker used", true, second_woke);
        crate::test_complete!("test_channel_stream_refreshes_queued_waker_on_repoll");
    }

    #[test]
    fn test_channel_stream_skips_stale_send_waiter_entries() {
        init_test("test_channel_stream_skips_stale_send_waiter_entries");
        let shared = Arc::new(SharedChannel::new(1));
        {
            let mut queue = shared.queue.lock();
            queue.push_back(create_symbol(11));
        }
        let mut stream = ChannelStream::new(Arc::clone(&shared));

        let stale_flag = Arc::new(AtomicBool::new(false));
        let active_flag = Arc::new(AtomicBool::new(false));
        let stale_queued = Arc::new(AtomicBool::new(false));
        let active_queued = Arc::new(AtomicBool::new(true));

        {
            let mut send_wakers = shared.send_wakers.lock();
            send_wakers.push(ChannelWaiter {
                waker: flagged_waker(Arc::clone(&active_flag)),
                queued: Arc::clone(&active_queued),
            });
            // Stale waiter remains in the queue until pop-time pruning.
            send_wakers.push(ChannelWaiter {
                waker: flagged_waker(Arc::clone(&stale_flag)),
                queued: Arc::clone(&stale_queued),
            });
        }

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let recv = Pin::new(&mut stream).poll_next(&mut context);
        crate::assert_with_log!(
            matches!(recv, Poll::Ready(Some(Ok(_)))),
            "receive succeeds",
            true,
            matches!(recv, Poll::Ready(Some(Ok(_))))
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
        let send_waiters_empty = shared.send_wakers.lock().is_empty();
        crate::assert_with_log!(
            send_waiters_empty,
            "stale entries pruned",
            true,
            send_waiters_empty
        );

        crate::test_complete!("test_channel_stream_skips_stale_send_waiter_entries");
    }

    #[test]
    fn test_channel_stream_wakes_oldest_send_waiter_first() {
        init_test("test_channel_stream_wakes_oldest_send_waiter_first");
        let shared = Arc::new(SharedChannel::new(2));
        {
            let mut queue = shared.queue.lock();
            queue.push_back(create_symbol(1));
        }
        let mut stream = ChannelStream::new(Arc::clone(&shared));

        let first_flag = Arc::new(AtomicBool::new(false));
        let second_flag = Arc::new(AtomicBool::new(false));
        let first_queued = Arc::new(AtomicBool::new(true));
        let second_queued = Arc::new(AtomicBool::new(true));

        {
            let mut send_wakers = shared.send_wakers.lock();
            send_wakers.push(ChannelWaiter {
                waker: flagged_waker(Arc::clone(&first_flag)),
                queued: Arc::clone(&first_queued),
            });
            send_wakers.push(ChannelWaiter {
                waker: flagged_waker(Arc::clone(&second_flag)),
                queued: Arc::clone(&second_queued),
            });
        }

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let recv = Pin::new(&mut stream).poll_next(&mut context);
        crate::assert_with_log!(
            matches!(recv, Poll::Ready(Some(Ok(_)))),
            "receive succeeds",
            true,
            matches!(recv, Poll::Ready(Some(Ok(_))))
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
        let queued_len = shared.send_wakers.lock().len();
        crate::assert_with_log!(queued_len == 1, "one waiter remains", 1usize, queued_len);

        crate::test_complete!("test_channel_stream_wakes_oldest_send_waiter_first");
    }

    #[test]
    fn test_timeout_stream_triggers_and_resets() {
        static NOW: AtomicU64 = AtomicU64::new(0);
        fn test_now() -> Time {
            Time::from_nanos(NOW.load(Ordering::SeqCst))
        }

        init_test("test_timeout_stream_triggers_and_resets");
        let inner = PendingStream;
        let mut timed = TimeoutStream::with_time_getter(inner, Duration::from_nanos(10), test_now);
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);

        NOW.store(0, Ordering::SeqCst);
        let first = Pin::new(&mut timed).poll_next(&mut context);
        crate::assert_with_log!(
            matches!(first, Poll::Pending),
            "pending before timeout",
            true,
            matches!(first, Poll::Pending)
        );

        NOW.store(10, Ordering::SeqCst);
        let second = Pin::new(&mut timed).poll_next(&mut context);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Some(Err(StreamError::Timeout)))),
            "timeout",
            true,
            matches!(second, Poll::Ready(Some(Err(StreamError::Timeout))))
        );

        NOW.store(10, Ordering::SeqCst);
        let third = Pin::new(&mut timed).poll_next(&mut context);
        crate::assert_with_log!(
            matches!(third, Poll::Pending),
            "reset after timeout",
            true,
            matches!(third, Poll::Pending)
        );

        crate::test_complete!("test_timeout_stream_triggers_and_resets");
    }

    #[test]
    fn test_timeout_stream_resets_on_item() {
        static NOW: AtomicU64 = AtomicU64::new(0);
        fn test_now() -> Time {
            Time::from_nanos(NOW.load(Ordering::SeqCst))
        }

        struct OneItemThenPending {
            item: Option<AuthenticatedSymbol>,
        }

        impl SymbolStream for OneItemThenPending {
            fn poll_next(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
                self.item
                    .take()
                    .map_or(Poll::Pending, |item| Poll::Ready(Some(Ok(item))))
            }
        }

        init_test("test_timeout_stream_resets_on_item");
        let inner = OneItemThenPending {
            item: Some(create_symbol(5)),
        };
        let mut timed = TimeoutStream::with_time_getter(inner, Duration::from_nanos(10), test_now);
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);

        NOW.store(0, Ordering::SeqCst);
        let first = Pin::new(&mut timed).poll_next(&mut context);
        crate::assert_with_log!(
            matches!(first, Poll::Ready(Some(Ok(_)))),
            "item received",
            true,
            matches!(first, Poll::Ready(Some(Ok(_))))
        );

        NOW.store(5, Ordering::SeqCst);
        let second = Pin::new(&mut timed).poll_next(&mut context);
        crate::assert_with_log!(
            matches!(second, Poll::Pending),
            "pending before new deadline",
            true,
            matches!(second, Poll::Pending)
        );

        crate::test_complete!("test_timeout_stream_resets_on_item");
    }

    #[test]
    fn test_timeout_stream_duration_max_saturates_deadline() {
        static NOW: AtomicU64 = AtomicU64::new(0);
        fn test_now() -> Time {
            Time::from_nanos(NOW.load(Ordering::SeqCst))
        }

        init_test("test_timeout_stream_duration_max_saturates_deadline");
        NOW.store(123, Ordering::SeqCst);

        let inner = PendingStream;
        let mut timed = TimeoutStream::with_time_getter(inner, Duration::MAX, test_now);
        crate::assert_with_log!(
            timed.sleep.deadline() == Time::MAX,
            "deadline saturates to max",
            Time::MAX,
            timed.sleep.deadline()
        );

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);

        let before_max = Pin::new(&mut timed).poll_next(&mut context);
        crate::assert_with_log!(
            matches!(before_max, Poll::Pending),
            "pending before max time",
            true,
            matches!(before_max, Poll::Pending)
        );

        NOW.store(u64::MAX, Ordering::SeqCst);
        let at_max = Pin::new(&mut timed).poll_next(&mut context);
        crate::assert_with_log!(
            matches!(at_max, Poll::Ready(Some(Err(StreamError::Timeout)))),
            "times out at max deadline",
            true,
            matches!(at_max, Poll::Ready(Some(Err(StreamError::Timeout))))
        );

        crate::test_complete!("test_timeout_stream_duration_max_saturates_deadline");
    }

    #[test]
    fn test_timeout_stream_zero_duration_times_out_immediately() {
        static NOW: AtomicU64 = AtomicU64::new(0);
        fn test_now() -> Time {
            Time::from_nanos(NOW.load(Ordering::SeqCst))
        }

        init_test("test_timeout_stream_zero_duration_times_out_immediately");
        NOW.store(42, Ordering::SeqCst);

        let inner = PendingStream;
        let mut timed = TimeoutStream::with_time_getter(inner, Duration::ZERO, test_now);
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);

        let first = Pin::new(&mut timed).poll_next(&mut context);
        crate::assert_with_log!(
            matches!(first, Poll::Ready(Some(Err(StreamError::Timeout)))),
            "zero-duration timeout fires on the first pending poll",
            true,
            matches!(first, Poll::Ready(Some(Err(StreamError::Timeout))))
        );
        crate::assert_with_log!(
            !timed.is_exhausted(),
            "timeout errors do not exhaust a still-pending stream",
            false,
            timed.is_exhausted()
        );
        crate::assert_with_log!(
            timed.sleep.deadline() == Time::from_nanos(42),
            "zero-duration reset keeps the deadline at the current virtual instant",
            Time::from_nanos(42),
            timed.sleep.deadline()
        );

        crate::test_complete!("test_timeout_stream_zero_duration_times_out_immediately");
    }

    #[test]
    fn test_timeout_stream_tracks_exhaustion_without_repolling_inner() {
        init_test("test_timeout_stream_tracks_exhaustion_without_repolling_inner");
        let polls = Arc::new(AtomicUsize::new(0));
        let inner = EmptyThenPanics::new(Arc::clone(&polls));
        let mut timed = TimeoutStream::new(inner, Duration::from_nanos(10));
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);

        let first = Pin::new(&mut timed).poll_next(&mut context);
        let second = Pin::new(&mut timed).poll_next(&mut context);
        let exhausted = timed.is_exhausted();
        let hint = timed.size_hint();

        crate::assert_with_log!(
            matches!(first, Poll::Ready(None)),
            "first poll exhausts timeout stream when inner is done",
            true,
            matches!(first, Poll::Ready(None))
        );
        crate::assert_with_log!(
            matches!(second, Poll::Ready(None)),
            "second poll stays exhausted without repolling inner",
            true,
            matches!(second, Poll::Ready(None))
        );
        crate::assert_with_log!(exhausted, "timeout stream exhausted", true, exhausted);
        crate::assert_with_log!(
            hint == (0, Some(0)),
            "timeout hint zero after exhaustion",
            (0, Some(0)),
            hint
        );
        crate::assert_with_log!(
            polls.load(Ordering::SeqCst) == 1,
            "inner polled once",
            1usize,
            polls.load(Ordering::SeqCst)
        );
        crate::test_complete!("test_timeout_stream_tracks_exhaustion_without_repolling_inner");
    }

    /// Regression test for lost-wakeup race in ChannelStream::poll_next.
    ///
    /// A sender may push between the queue check and waiter registration,
    /// finding no recv_waker to wake. The re-check after registration
    /// closes this race by self-waking when items are found.
    #[test]
    fn test_channel_stream_no_lost_wakeup_concurrent() {
        init_test("test_channel_stream_no_lost_wakeup_concurrent");

        // Run many iterations to maximise the chance of hitting the race window.
        for iteration in 0..200 {
            let (mut sink, mut stream) = channel(1);

            let send_handle = thread::spawn(move || {
                let waker = noop_waker();
                let mut cx = Context::from_waker(&waker);
                let _ = Pin::new(&mut sink).poll_send(&mut cx, create_symbol(iteration));
            });

            let recv_handle = thread::spawn(move || {
                let flag = Arc::new(AtomicBool::new(false));
                let waker = flagged_waker(Arc::clone(&flag));
                let mut cx = Context::from_waker(&waker);
                let start = Instant::now();

                loop {
                    match Pin::new(&mut stream).poll_next(&mut cx) {
                        Poll::Ready(Some(Ok(_))) => return true,
                        Poll::Ready(Some(Err(_)) | None) => return false,
                        Poll::Pending => {
                            if start.elapsed() > Duration::from_millis(500) {
                                return false; // Timeout — lost wakeup
                            }
                            // If the waker was invoked, repoll immediately.
                            if flag.swap(false, Ordering::AcqRel) {
                                continue;
                            }
                            thread::yield_now();
                        }
                    }
                }
            });

            send_handle.join().unwrap();
            let received = recv_handle.join().unwrap();
            crate::assert_with_log!(received, "no lost wakeup", true, received);
        }

        crate::test_complete!("test_channel_stream_no_lost_wakeup_concurrent");
    }

    // ── Audit regression tests (asupersync-10x0x.82) ─────────────────────

    #[test]
    fn merged_stream_removal_adjusts_current_when_removing_before() {
        init_test("merged_stream_removal_adjusts_current_when_removing_before");
        // Streams: [done, A, B]. current = 2 (starts at B).
        // Removing done at idx 0 should adjust current from 2 to 1,
        // so B (now at idx 1) is still reached next round.
        let done_stream = VecStream::new(vec![]); // exhausted immediately
        let s_a = VecStream::new(vec![create_symbol(10)]);
        let s_b = VecStream::new(vec![create_symbol(20)]);
        let mut merged = MergedStream::new(vec![done_stream, s_a, s_b]);
        merged.current = 2; // start at B

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // First poll: starts at idx 2 (B) → Ready(Ok(20)).
        // Round-robin advances to next.
        let first = Pin::new(&mut merged).poll_next(&mut cx);
        let esi = match &first {
            Poll::Ready(Some(Ok(sym))) => sym.symbol().id().esi(),
            _ => panic!("expected Ready(Some(Ok))"), // ubs:ignore - test logic
        };
        crate::assert_with_log!(esi == 20, "B dispatched first", 20u32, esi);

        // Second poll: should visit the done stream (removed) and then A.
        let second = Pin::new(&mut merged).poll_next(&mut cx);
        let esi2 = match &second {
            Poll::Ready(Some(Ok(sym))) => sym.symbol().id().esi(),
            _ => panic!("expected Ready(Some(Ok))"), // ubs:ignore - test logic
        };
        crate::assert_with_log!(esi2 == 10, "A dispatched after removal", 10u32, esi2);

        // Third: all exhausted.
        let third = Pin::new(&mut merged).poll_next(&mut cx);
        crate::assert_with_log!(
            matches!(third, Poll::Ready(None)),
            "all exhausted",
            true,
            matches!(third, Poll::Ready(None))
        );
        crate::test_complete!("merged_stream_removal_adjusts_current_when_removing_before");
    }

    #[test]
    fn channel_stream_closed_after_waiter_registration() {
        init_test("channel_stream_closed_after_waiter_registration");
        let shared = Arc::new(SharedChannel::new(1));
        let mut stream = ChannelStream::new(Arc::clone(&shared));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // First poll registers waiter.
        let first = Pin::new(&mut stream).poll_next(&mut cx);
        crate::assert_with_log!(
            matches!(first, Poll::Pending),
            "pending on empty",
            true,
            matches!(first, Poll::Pending)
        );

        // Close channel — should wake and detect closed on next poll.
        shared.close();
        let second = Pin::new(&mut stream).poll_next(&mut cx);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(None)),
            "returns None after close",
            true,
            matches!(second, Poll::Ready(None))
        );
        crate::test_complete!("channel_stream_closed_after_waiter_registration");
    }

    /// Stream that produces 1 good item then an error.
    struct GoodThenError(bool);
    impl SymbolStream for GoodThenError {
        fn poll_next(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
            if self.0 {
                Poll::Ready(None)
            } else {
                self.0 = true;
                Poll::Ready(Some(Err(StreamError::Reset)))
            }
        }
    }

    #[test]
    fn collect_to_set_propagates_error_stops_early() {
        init_test("collect_to_set_propagates_error_stops_early");
        let mut stream = GoodThenError(false);
        let mut set = SymbolSet::new();
        let result = future::block_on(async { stream.collect_to_set(&mut set).await });
        crate::assert_with_log!(result.is_err(), "error propagated", true, result.is_err());
        crate::assert_with_log!(set.is_empty(), "set empty on error", true, set.is_empty());
        crate::test_complete!("collect_to_set_propagates_error_stops_early");
    }

    #[test]
    fn vec_stream_size_hint_tracks_remaining() {
        init_test("vec_stream_size_hint_tracks_remaining");
        let mut stream = VecStream::new(vec![create_symbol(1), create_symbol(2), create_symbol(3)]);

        let hint = stream.size_hint();
        crate::assert_with_log!(hint == (3, Some(3)), "initial hint", (3, Some(3)), hint);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let _ = Pin::new(&mut stream).poll_next(&mut cx); // consume one

        let hint2 = stream.size_hint();
        crate::assert_with_log!(hint2 == (2, Some(2)), "after one", (2, Some(2)), hint2);
        crate::test_complete!("vec_stream_size_hint_tracks_remaining");
    }
