    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::observability::Metrics;
    use crate::security::{AuthMode, AuthenticationTag, SecurityContext};
    use crate::transport::channel;
    use crate::transport::error::{SinkError, StreamError};
    use crate::types::symbol::{ObjectId, ObjectParams, Symbol};
    use std::pin::Pin;
    use std::task::{Context, Poll};

    struct VecSink {
        symbols: Vec<AuthenticatedSymbol>,
    }

    impl VecSink {
        fn new() -> Self {
            Self {
                symbols: Vec::new(),
            }
        }
    }

    impl SymbolSink for VecSink {
        fn poll_send(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            symbol: AuthenticatedSymbol,
        ) -> Poll<Result<(), SinkError>> {
            self.symbols.push(symbol);
            Poll::Ready(Ok(()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            Poll::Ready(Ok(()))
        }

        fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Unpin for VecSink {}

    struct PendingSink;

    impl SymbolSink for PendingSink {
        fn poll_send(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _symbol: AuthenticatedSymbol,
        ) -> Poll<Result<(), SinkError>> {
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            Poll::Ready(Ok(()))
        }

        fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Unpin for PendingSink {}

    struct FlushPendingSink {
        symbols: Vec<AuthenticatedSymbol>,
    }

    impl FlushPendingSink {
        fn new() -> Self {
            Self {
                symbols: Vec::new(),
            }
        }
    }

    impl SymbolSink for FlushPendingSink {
        fn poll_send(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            symbol: AuthenticatedSymbol,
        ) -> Poll<Result<(), SinkError>> {
            self.symbols.push(symbol);
            Poll::Ready(Ok(()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            Poll::Pending
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            Poll::Ready(Ok(()))
        }

        fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Unpin for FlushPendingSink {}

    struct VecStream {
        symbols: Vec<AuthenticatedSymbol>,
        index: usize,
    }

    impl VecStream {
        fn new(symbols: Vec<AuthenticatedSymbol>) -> Self {
            Self { symbols, index: 0 }
        }
    }

    impl SymbolStream for VecStream {
        fn poll_next(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
            if self.index < self.symbols.len() {
                let sym = self.symbols[self.index].clone();
                self.index += 1;
                Poll::Ready(Some(Ok(sym)))
            } else {
                Poll::Ready(None)
            }
        }
    }

    impl Unpin for VecStream {}

    struct PendingStream;

    impl SymbolStream for PendingStream {
        fn poll_next(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
            Poll::Pending
        }
    }

    impl Unpin for PendingStream {}

    struct ErrorStream {
        error: Option<StreamError>,
    }

    impl ErrorStream {
        fn new(error: StreamError) -> Self {
            Self { error: Some(error) }
        }
    }

    impl SymbolStream for ErrorStream {
        fn poll_next(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
            Poll::Ready(self.error.take().map(Err))
        }
    }

    impl Unpin for ErrorStream {}

    fn params_for(
        object_id: ObjectId,
        data_len: usize,
        symbol_size: u16,
        source_symbols: usize,
    ) -> ObjectParams {
        ObjectParams::new(
            object_id,
            data_len as u64,
            symbol_size,
            1,
            source_symbols as u16,
        )
    }

    #[test]
    fn compute_repair_count_overhead_one_requests_zero_repairs() {
        // EncodingConfig docs: repair_overhead=1.0 means "0% extra symbols".
        let data_len = 1024;
        let symbol_size = 256;
        assert_eq!(compute_repair_count(data_len, symbol_size, 1.0), 0);
    }

    #[test]
    fn compute_repair_count_empty_data_requests_zero_repairs() {
        assert_eq!(compute_repair_count(0, 256, 1.10), 0);
    }

    #[test]
    fn compute_repair_count_overhead_above_one_includes_systematic_padding() {
        // br-asupersync-7gxb8n: post-fix the formula is
        //   (K' - K) + max(ceil(K' * (overhead - 1.0)), 1)
        // For data_len=64, symbol_size=256: source=ceil(64/256)=1, K'=10
        // (per RFC 6330 Table 2 — smallest K' >= 1 is 10). overhead=1.01
        // gives erasure_margin=ceil(10*0.01)=1. Total repair = 9 + 1 = 10.
        let data_len = 64;
        let symbol_size = 256;
        assert_eq!(compute_repair_count(data_len, symbol_size, 1.01), 10);
    }

    #[test]
    fn compute_total_repair_count_uses_per_block_ceilings() {
        // br-asupersync-7gxb8n: per-block repair counts now include the
        // systematic K' padding from RFC 6330 §5.6 Table 2.
        //
        // - data_len=161, symbol_size=8 → ceil(161/8) = 21 source symbols
        //   in the single-block view. K'(21) = 26 (smallest table entry >= 21).
        //   padding = 26 - 21 = 5; erasure = ceil(26 * 0.05) = 2;
        //   compute_repair_count = max(5 + 2, 5 + 1) = 7.
        //
        // - For per-block (max_block_size=80), the encoder splits the
        //   payload into exact max-size chunks plus a tail:
        //   * block1: 80 bytes = 10 source. K'(10)=10. padding=0.
        //     erasure=ceil(10*0.05)=1. Per-block = max(0+1, 0+1) = 1.
        //   * block2: 80 bytes = 10 source. K'(10)=10. padding=0.
        //     erasure=ceil(10*0.05)=1. Per-block = max(0+1, 0+1) = 1.
        //   * block3: 1 byte = 1 source. K'(1)=10. padding=9.
        //     erasure=ceil(10*0.05)=1. Per-block = max(9+1, 9+1) = 10.
        //   * Total = 1 + 1 + 10 = 12.
        let data_len = 161;
        let max_block_size = 80;
        let symbol_size = 8;
        let overhead = 1.05;

        assert_eq!(compute_repair_count(data_len, symbol_size, overhead), 7);
        assert_eq!(
            compute_total_repair_count(data_len, max_block_size, symbol_size, overhead),
            12
        );
    }

    #[test]
    fn compute_repair_count_systematic_padding_strictly_added() {
        // br-asupersync-7gxb8n regression test: for ANY K in the RFC table
        // range, the repair count MUST be at least (K' - K) so the decoder
        // receives at least K' encoded symbols (RFC 6330 §1.3 baseline).
        // K' values per RFC 6330 §5.6 Table 2 (smallest K' ≥ K).
        for &(source, expected_k_prime) in &[
            (1usize, 10usize),
            (5, 10),
            (10, 10),
            (11, 12),
            (13, 18),
            (49, 49),
            (100, 101),
        ] {
            // Multiply with overhead=1.0 + ε epsilon so the check exercises
            // both the padding and erasure-margin paths.
            let symbol_size = 64;
            let data_len = source * symbol_size;
            let repair = compute_repair_count(data_len, symbol_size, 1.001);
            assert!(
                repair >= expected_k_prime.saturating_sub(source),
                "K={source}: expected repair >= (K'-K)=({expected_k_prime}-{source})={}, got {repair}",
                expected_k_prime.saturating_sub(source)
            );
        }
    }

    #[test]
    fn sender_pool_bounds_caps_initial_allocation_to_object_need() {
        let configured_pool_size = 1024;
        let source_symbols = 256;
        let repair_symbols = 64;

        let (initial, max) =
            sender_pool_bounds(configured_pool_size, source_symbols, repair_symbols);
        assert_eq!(
            initial, 320,
            "initial pool should be capped to required source+repair symbols"
        );
        assert_eq!(
            max, configured_pool_size,
            "max pool should preserve configured ceiling when it exceeds object need"
        );
    }

    #[test]
    fn sender_pool_bounds_preserves_capacity_for_large_objects() {
        let configured_pool_size = 1024;
        let source_symbols = 1200;
        let repair_symbols = 300;

        let (initial, max) =
            sender_pool_bounds(configured_pool_size, source_symbols, repair_symbols);
        assert_eq!(
            initial, configured_pool_size,
            "initial pool should remain configured when object need exceeds baseline"
        );
        assert_eq!(
            max, 1500,
            "max pool should expand to full source+repair demand"
        );
    }

    #[test]
    fn usize_to_u32_saturating_caps_large_values() {
        assert_eq!(usize_to_u32_saturating(42), 42);
        assert_eq!(usize_to_u32_saturating(usize::MAX), u32::MAX);
    }

    #[test]
    fn test_send_object_roundtrip_all_symbols_succeeds() {
        let cx: Cx = Cx::for_testing();
        let sink = VecSink::new();
        let mut sender = RaptorQSender::new(RaptorQConfig::default(), sink, None, None);

        let data = vec![0xABu8; 512];
        let object_id = ObjectId::new_for_test(7);
        let outcome = sender.send_object(&cx, object_id, &data).unwrap();
        let params = params_for(
            object_id,
            data.len(),
            sender.config().encoding.symbol_size,
            outcome.source_symbols,
        );

        let symbols: Vec<AuthenticatedSymbol> = sender.transport_mut().symbols.drain(..).collect();
        let stream = VecStream::new(symbols);
        let mut receiver = RaptorQReceiver::new(RaptorQConfig::default(), stream, None, None);

        let recv = receiver.receive_object(&cx, &params).unwrap();
        assert_eq!(&recv.data[..data.len()], &data);
        assert!(!recv.authenticated);
    }

    #[test]
    fn test_send_object_roundtrip_source_only_succeeds() {
        let cx: Cx = Cx::for_testing();
        let sink = VecSink::new();
        let mut sender = RaptorQSender::new(RaptorQConfig::default(), sink, None, None);

        let data = vec![0xCDu8; 256];
        let object_id = ObjectId::new_for_test(9);
        let outcome = sender.send_object(&cx, object_id, &data).unwrap();
        let params = params_for(
            object_id,
            data.len(),
            sender.config().encoding.symbol_size,
            outcome.source_symbols,
        );

        let mut symbols: Vec<AuthenticatedSymbol> =
            sender.transport_mut().symbols.drain(..).collect();
        symbols.truncate(outcome.source_symbols);
        let stream = VecStream::new(symbols);
        let mut receiver = RaptorQReceiver::new(RaptorQConfig::default(), stream, None, None);

        let recv = receiver.receive_object(&cx, &params).unwrap();
        assert_eq!(&recv.data[..data.len()], &data);
    }

    #[test]
    fn test_send_object_rejects_oversized_data() {
        let cx: Cx = Cx::for_testing();
        let sink = VecSink::new();
        let mut sender = RaptorQSender::new(RaptorQConfig::default(), sink, None, None);

        let max = max_object_size(sender.config().encoding.max_block_size) as u64;
        let data = vec![0u8; (max + 1) as usize];
        let result = sender.send_object(&cx, ObjectId::new_for_test(1), &data);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::DataTooLarge);
    }

    #[test]
    fn test_send_object_cancelled_returns_cancelled() {
        let cx: Cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let sink = VecSink::new();
        let mut sender = RaptorQSender::new(RaptorQConfig::default(), sink, None, None);
        let data = vec![0xEFu8; 64];
        let result = sender.send_object(&cx, ObjectId::new_for_test(2), &data);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::Cancelled);
    }

    #[test]
    fn test_send_object_accepts_valid_non_default_small_symbol_size() {
        let cx: Cx = Cx::for_testing();
        let sink = VecSink::new();
        let mut config = RaptorQConfig::default();
        config.encoding.symbol_size = 8;
        config.encoding.max_block_size = 32;
        config.encoding.repair_overhead = 1.0;
        let mut sender = RaptorQSender::new(config, sink, None, None);

        // This exceeded the old max_block_size * symbol_size guard, but it still fits
        // within the byte-based 256-block contract enforced by EncodingPipeline.
        let data = vec![0xA5u8; 257];
        let outcome = sender
            .send_object(&cx, ObjectId::new_for_test(20), &data)
            .expect("byte-valid payload should not be rejected early");

        assert!(outcome.symbols_sent >= outcome.source_symbols);
        assert_eq!(sender.transport_mut().symbols.len(), outcome.symbols_sent);
    }

    #[test]
    fn test_send_object_multiblock_uses_per_block_repair_budget() {
        let cx: Cx = Cx::for_testing();
        let sink = VecSink::new();
        let mut config = RaptorQConfig::default();
        config.encoding.symbol_size = 8;
        config.encoding.max_block_size = 80;
        config.encoding.repair_overhead = 1.05;
        config.resources.symbol_pool_size = 1;
        let mut sender = RaptorQSender::new(config, sink, None, None);

        let data = vec![0xA5u8; 161];
        let outcome = sender
            .send_object(&cx, ObjectId::new_for_test(22), &data)
            .expect("multi-block send should size repairs and pool from block-local needs");

        assert_eq!(outcome.source_symbols, 21);
        assert_eq!(outcome.repair_symbols, 3);
        assert_eq!(outcome.symbols_sent, 24);
        assert_eq!(sender.transport_mut().symbols.len(), outcome.symbols_sent);
    }

    #[test]
    fn test_send_object_rejects_large_symbol_size_payload_with_data_too_large() {
        let cx: Cx = Cx::for_testing();
        let sink = VecSink::new();
        let mut config = RaptorQConfig::default();
        config.encoding.symbol_size = 512;
        config.encoding.max_block_size = 32;
        config.encoding.repair_overhead = 1.0;
        let mut sender = RaptorQSender::new(config, sink, None, None);

        let data = vec![0u8; max_object_size(sender.config().encoding.max_block_size) + 1];
        let err = sender
            .send_object(&cx, ObjectId::new_for_test(21), &data)
            .expect_err("payload beyond byte contract must fail before encoding");

        assert_eq!(err.kind(), ErrorKind::DataTooLarge);
    }

    #[test]
    fn test_send_symbols_direct_count_matches() {
        let cx: Cx = Cx::for_testing();
        let sink = VecSink::new();
        let mut sender = RaptorQSender::new(RaptorQConfig::default(), sink, None, None);

        let symbols: Vec<AuthenticatedSymbol> = (0..3)
            .map(|i| {
                let sym = Symbol::new_for_test(1, 0, i, &[i as u8; 256]);
                AuthenticatedSymbol::new_verified(sym, AuthenticationTag::zero())
            })
            .collect();

        let count = sender.send_symbols(&cx, symbols).unwrap();
        assert_eq!(count, 3);
        assert_eq!(sender.transport_mut().symbols.len(), 3);
    }

    #[test]
    fn test_send_symbols_successful_flush_records_metrics() {
        let cx: Cx = Cx::for_testing();
        let sink = VecSink::new();
        let mut metrics = Metrics::new();
        let symbols_sent_counter = metrics.counter("raptorq.symbols_sent");
        let mut sender = RaptorQSender::new(RaptorQConfig::default(), sink, None, Some(metrics));

        let symbols: Vec<AuthenticatedSymbol> = (0..4)
            .map(|i| {
                let sym = Symbol::new_for_test(1, 0, i, &[i as u8; 256]);
                AuthenticatedSymbol::new_verified(sym, AuthenticationTag::zero())
            })
            .collect();

        let count = sender
            .send_symbols(&cx, symbols)
            .expect("successful direct symbol flush should record metrics");

        assert_eq!(count, 4);
        assert_eq!(symbols_sent_counter.get(), 4);
    }

    #[test]
    fn test_send_object_pending_sink_returns_rejected() {
        let cx: Cx = Cx::for_testing();
        let sink = PendingSink;
        let mut sender = RaptorQSender::new(RaptorQConfig::default(), sink, None, None);

        let data = vec![0xAAu8; 64];
        let result = sender.send_object(&cx, ObjectId::new_for_test(3), &data);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::SinkRejected);
    }

    #[test]
    fn test_send_object_pending_flush_returns_rejected() {
        let cx: Cx = Cx::for_testing();
        let sink = FlushPendingSink::new();
        let mut sender = RaptorQSender::new(RaptorQConfig::default(), sink, None, None);

        let data = vec![0x33u8; 64];
        let result = sender.send_object(&cx, ObjectId::new_for_test(31), &data);
        let err = result.expect_err("pending flush must not report send success");

        assert_eq!(err.kind(), ErrorKind::SinkRejected);
        assert!(
            !sender.transport_mut().symbols.is_empty(),
            "symbols may have been accepted before flush blocked"
        );
    }

    #[test]
    fn test_send_object_channel_backpressure_returns_rejected() {
        let cx: Cx = Cx::for_testing();
        let (sink, _stream) = channel(1);
        let mut sender = RaptorQSender::new(RaptorQConfig::default(), sink, None, None);

        let data = vec![0x33u8; 257];
        let err = sender
            .send_object(&cx, ObjectId::new_for_test(34), &data)
            .expect_err("channel backpressure must fail closed as not-ready");

        assert_eq!(err.kind(), ErrorKind::SinkRejected);
    }

    #[test]
    fn test_send_symbols_pending_flush_returns_rejected() {
        let cx: Cx = Cx::for_testing();
        let sink = FlushPendingSink::new();
        let mut sender = RaptorQSender::new(RaptorQConfig::default(), sink, None, None);

        let symbols: Vec<AuthenticatedSymbol> = (0..2)
            .map(|i| {
                let sym = Symbol::new_for_test(1, 0, i, &[i as u8; 256]);
                AuthenticatedSymbol::new_verified(sym, AuthenticationTag::zero())
            })
            .collect();

        let err = sender
            .send_symbols(&cx, symbols)
            .expect_err("pending flush must not report direct send success");

        assert_eq!(err.kind(), ErrorKind::SinkRejected);
        assert_eq!(
            sender.transport_mut().symbols.len(),
            2,
            "all symbols may be staged before flush reports pending"
        );
    }

    #[test]
    fn test_send_symbols_pending_flush_does_not_increment_metrics() {
        let cx: Cx = Cx::for_testing();
        let sink = FlushPendingSink::new();
        let mut metrics = Metrics::new();
        let symbols_sent_counter = metrics.counter("raptorq.symbols_sent");
        let mut sender = RaptorQSender::new(RaptorQConfig::default(), sink, None, Some(metrics));

        let symbols: Vec<AuthenticatedSymbol> = (0..2)
            .map(|i| {
                let sym = Symbol::new_for_test(1, 0, i, &[i as u8; 256]);
                AuthenticatedSymbol::new_verified(sym, AuthenticationTag::zero())
            })
            .collect();

        let err = sender
            .send_symbols(&cx, symbols)
            .expect_err("pending flush must not report direct send success");

        assert_eq!(err.kind(), ErrorKind::SinkRejected);
        assert_eq!(
            symbols_sent_counter.get(),
            0,
            "flush failure must not overcount direct symbol sends"
        );
    }

    #[test]
    fn test_send_symbols_channel_backpressure_returns_rejected() {
        let cx: Cx = Cx::for_testing();
        let (sink, _stream) = channel(1);
        let mut sender = RaptorQSender::new(RaptorQConfig::default(), sink, None, None);

        let symbols: Vec<AuthenticatedSymbol> = (0..2)
            .map(|i| {
                let sym = Symbol::new_for_test(1, 0, i, &[i as u8; 256]);
                AuthenticatedSymbol::new_verified(sym, AuthenticationTag::zero())
            })
            .collect();

        let err = sender
            .send_symbols(&cx, symbols)
            .expect_err("channel backpressure must fail closed as not-ready");

        assert_eq!(err.kind(), ErrorKind::SinkRejected);
    }

    #[test]
    fn test_send_object_metrics_increment_only_after_successful_flush() {
        let cx: Cx = Cx::for_testing();
        let sink = VecSink::new();
        let mut metrics = Metrics::new();
        let symbols_sent_counter = metrics.counter("raptorq.symbols_sent");
        let objects_sent_counter = metrics.counter("raptorq.objects_sent");
        let mut sender = RaptorQSender::new(RaptorQConfig::default(), sink, None, Some(metrics));

        let data = vec![0x5Au8; 64];
        let outcome = sender
            .send_object(&cx, ObjectId::new_for_test(32), &data)
            .expect("successful flush should record metrics");

        assert_eq!(symbols_sent_counter.get(), outcome.symbols_sent as u64);
        assert_eq!(objects_sent_counter.get(), 1);
    }

    #[test]
    fn test_send_object_pending_flush_does_not_increment_sent_metrics() {
        let cx: Cx = Cx::for_testing();
        let sink = FlushPendingSink::new();
        let mut metrics = Metrics::new();
        let symbols_sent_counter = metrics.counter("raptorq.symbols_sent");
        let objects_sent_counter = metrics.counter("raptorq.objects_sent");
        let mut sender = RaptorQSender::new(RaptorQConfig::default(), sink, None, Some(metrics));

        let data = vec![0x44u8; 64];
        let err = sender
            .send_object(&cx, ObjectId::new_for_test(33), &data)
            .expect_err("pending flush must not report success");

        assert_eq!(err.kind(), ErrorKind::SinkRejected);
        assert_eq!(
            symbols_sent_counter.get(),
            0,
            "flush failure must not overcount sent symbols"
        );
        assert_eq!(objects_sent_counter.get(), 0);
    }

    #[test]
    fn test_receive_object_insufficient_symbols_errors() {
        let cx: Cx = Cx::for_testing();
        let stream = VecStream::new(vec![]);
        let mut receiver = RaptorQReceiver::new(RaptorQConfig::default(), stream, None, None);

        let params = params_for(ObjectId::new_for_test(5), 128, 256, 1);
        let result = receiver.receive_object(&cx, &params);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::InsufficientSymbols);
    }

    #[test]
    fn test_receive_object_pending_stream_returns_rejected() {
        let cx: Cx = Cx::for_testing();
        let stream = PendingStream;
        let mut receiver = RaptorQReceiver::new(RaptorQConfig::default(), stream, None, None);

        let params = params_for(ObjectId::new_for_test(12), 128, 256, 1);
        let result = receiver.receive_object(&cx, &params);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::SinkRejected);
    }

    #[test]
    fn test_receive_object_stream_auth_failure_maps_to_corrupted_symbol() {
        let cx: Cx = Cx::for_testing();
        let stream = ErrorStream::new(StreamError::AuthenticationFailed {
            reason: "bad tag".to_string(),
        });
        let mut receiver = RaptorQReceiver::new(RaptorQConfig::default(), stream, None, None);

        let params = params_for(ObjectId::new_for_test(40), 128, 256, 1);
        let err = receiver
            .receive_object(&cx, &params)
            .expect_err("auth failure must fail closed");

        assert_eq!(err.kind(), ErrorKind::CorruptedSymbol);
        assert!(err.to_string().contains("bad tag"));
    }

    #[test]
    fn test_receive_object_stream_protocol_error_preserves_protocol_kind() {
        let cx: Cx = Cx::for_testing();
        let stream = ErrorStream::new(StreamError::ProtocolError {
            details: "frame mismatch".to_string(),
        });
        let mut receiver = RaptorQReceiver::new(RaptorQConfig::default(), stream, None, None);

        let params = params_for(ObjectId::new_for_test(41), 128, 256, 1);
        let err = receiver
            .receive_object(&cx, &params)
            .expect_err("protocol failures must not be flattened");

        assert_eq!(err.kind(), ErrorKind::ProtocolError);
        assert!(err.to_string().contains("frame mismatch"));
    }

    #[test]
    fn test_receive_object_stream_reset_maps_to_connection_lost() {
        let cx: Cx = Cx::for_testing();
        let stream = ErrorStream::new(StreamError::Reset);
        let mut receiver = RaptorQReceiver::new(RaptorQConfig::default(), stream, None, None);

        let params = params_for(ObjectId::new_for_test(42), 128, 256, 1);
        let err = receiver
            .receive_object(&cx, &params)
            .expect_err("reset must surface as connection loss");

        assert_eq!(err.kind(), ErrorKind::ConnectionLost);
    }

    #[test]
    fn test_receive_object_stream_timeout_maps_to_threshold_timeout() {
        let cx: Cx = Cx::for_testing();
        let stream = ErrorStream::new(StreamError::Timeout);
        let mut receiver = RaptorQReceiver::new(RaptorQConfig::default(), stream, None, None);

        let params = params_for(ObjectId::new_for_test(43), 128, 256, 1);
        let err = receiver
            .receive_object(&cx, &params)
            .expect_err("timeout must remain distinguishable from stream end");

        assert_eq!(err.kind(), ErrorKind::ThresholdTimeout);
    }

    #[test]
    fn test_receive_object_stream_cancelled_preserves_cancelled_kind() {
        let cx: Cx = Cx::for_testing();
        let stream = ErrorStream::new(StreamError::Cancelled);
        let mut receiver = RaptorQReceiver::new(RaptorQConfig::default(), stream, None, None);

        let params = params_for(ObjectId::new_for_test(44), 128, 256, 1);
        let err = receiver
            .receive_object(&cx, &params)
            .expect_err("stream cancellation must stay cancelled");

        assert_eq!(err.kind(), ErrorKind::Cancelled);
    }

    #[test]
    fn test_receive_object_cancelled_returns_cancelled() {
        let cx: Cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let stream = VecStream::new(vec![]);
        let mut receiver = RaptorQReceiver::new(RaptorQConfig::default(), stream, None, None);
        let params = params_for(ObjectId::new_for_test(6), 256, 256, 1);
        let result = receiver.receive_object(&cx, &params);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::Cancelled);
    }

    #[test]
    fn test_receive_object_authenticated_flag_true_with_security() {
        let cx: Cx = Cx::for_testing();
        let security = SecurityContext::for_testing(42);
        let sink = VecSink::new();
        let mut sender =
            RaptorQSender::new(RaptorQConfig::default(), sink, Some(security.clone()), None);

        // Use larger data to ensure k > L overhead requirements
        // With symbol_size=256, 1KB gives k=4, which has enough margin
        let data = vec![0x11u8; 1024];
        let object_id = ObjectId::new_for_test(10);
        let outcome = sender.send_object(&cx, object_id, &data).unwrap();
        let params = params_for(
            object_id,
            data.len(),
            sender.config().encoding.symbol_size,
            outcome.source_symbols,
        );

        let symbols: Vec<AuthenticatedSymbol> = sender.transport_mut().symbols.drain(..).collect();
        let stream = VecStream::new(symbols);
        let mut receiver =
            RaptorQReceiver::new(RaptorQConfig::default(), stream, Some(security), None);

        let recv = receiver.receive_object(&cx, &params).unwrap();
        assert!(recv.authenticated);
        assert_eq!(recv.authentication.verified, recv.symbols_received);
        assert!(recv.authentication.all_verified());
        assert!(!recv.authentication.has_unauthenticated_sentinel());
    }

    #[test]
    fn receive_object_config_auth_key_seed_authenticates_without_explicit_context() {
        // br-asupersync-x7ad3b: a receiver given ONLY a config `auth_key_seed`
        // (no explicit SecurityContext) must authenticate symbols using the
        // configured key. This proves the config knob is wired into the live
        // decode path rather than parsed-and-ignored.
        let cx: Cx = Cx::for_testing();
        let security = SecurityContext::for_testing(7);
        let sink = VecSink::new();
        let mut sender = RaptorQSender::new(RaptorQConfig::default(), sink, Some(security), None);

        let data = vec![0x22u8; 1024];
        let object_id = ObjectId::new_for_test(70);
        let outcome = sender.send_object(&cx, object_id, &data).unwrap();
        let params = params_for(
            object_id,
            data.len(),
            sender.config().encoding.symbol_size,
            outcome.source_symbols,
        );

        let symbols: Vec<AuthenticatedSymbol> = sender.transport_mut().symbols.drain(..).collect();
        let stream = VecStream::new(symbols);

        let mut config = RaptorQConfig::default();
        config.security.auth_key_seed = Some(7);
        // No explicit SecurityContext: authentication must come from config alone.
        let mut receiver = RaptorQReceiver::new(config, stream, None, None);

        let recv = receiver.receive_object(&cx, &params).unwrap();
        assert!(
            recv.authenticated,
            "config auth_key_seed must drive symbol verification"
        );
        assert_eq!(recv.authentication.verified, recv.symbols_received);
        assert!(recv.authentication.all_verified());
    }

    #[test]
    fn receive_object_reject_unauthenticated_fails_closed_against_unsigned_symbols() {
        // br-asupersync-x7ad3b: with a configured key + reject_unauthenticated
        // (the fail-closed default), UNSIGNED symbols must be rejected rather
        // than silently accepted. Pre-fix config.security was never read, so an
        // operator hardening a deployment via RAPTORQ_SECURITY_* gained nothing.
        let cx: Cx = Cx::for_testing();
        let sink = VecSink::new();
        // Sender has NO security -> emits unsigned symbols (erasure-only style).
        let mut sender = RaptorQSender::new(RaptorQConfig::default(), sink, None, None);

        let data = vec![0x33u8; 1024];
        let object_id = ObjectId::new_for_test(71);
        let outcome = sender.send_object(&cx, object_id, &data).unwrap();
        let params = params_for(
            object_id,
            data.len(),
            sender.config().encoding.symbol_size,
            outcome.source_symbols,
        );

        let symbols: Vec<AuthenticatedSymbol> = sender.transport_mut().symbols.drain(..).collect();
        let stream = VecStream::new(symbols);

        let mut config = RaptorQConfig::default();
        config.security.auth_key_seed = Some(7); // operator demands authentication
        assert!(config.security.reject_unauthenticated);
        let mut metrics = Metrics::new();
        let auth_rejected = metrics.counter("raptorq.auth_rejected");
        let symbols_received = metrics.counter("raptorq.symbols_received");
        let mut receiver = RaptorQReceiver::new(config, stream, None, Some(metrics));

        let result = receiver.receive_object(&cx, &params);
        assert!(
            result.is_err(),
            "unsigned symbols must fail closed when a key is configured"
        );
        assert_eq!(result.unwrap_err().kind(), ErrorKind::CorruptedSymbol);
        assert_eq!(
            auth_rejected.get(),
            1,
            "fail-closed unsigned symbol rejection must be counted"
        );
        assert_eq!(
            symbols_received.get(),
            0,
            "unauthenticated symbols must be rejected before decode acceptance"
        );
    }

    #[test]
    fn receive_object_no_auth_material_preserves_erasure_only_accept() {
        // br-asupersync-x7ad3b regression guard: the default no-key path (no
        // explicit context AND no configured seed) is UNCHANGED — it still
        // accepts unauthenticated symbols and reports authenticated=false.
        // Hardening this default is the larger e880xo transport change,
        // intentionally out of scope here.
        let cx: Cx = Cx::for_testing();
        let sink = VecSink::new();
        let mut sender = RaptorQSender::new(RaptorQConfig::default(), sink, None, None);

        let data = vec![0x44u8; 512];
        let object_id = ObjectId::new_for_test(72);
        let outcome = sender.send_object(&cx, object_id, &data).unwrap();
        let params = params_for(
            object_id,
            data.len(),
            sender.config().encoding.symbol_size,
            outcome.source_symbols,
        );

        let symbols: Vec<AuthenticatedSymbol> = sender.transport_mut().symbols.drain(..).collect();
        let stream = VecStream::new(symbols);
        // Default config: reject_unauthenticated=true but auth_key_seed=None.
        let mut receiver = RaptorQReceiver::new(RaptorQConfig::default(), stream, None, None);

        let recv = receiver.receive_object(&cx, &params).unwrap();
        assert_eq!(&recv.data[..data.len()], &data);
        assert!(!recv.authenticated);
        assert_eq!(recv.authentication.total(), recv.symbols_received);
        assert_eq!(recv.authentication.verified, 0);
        assert_eq!(recv.authentication.unverified_tagged, 0);
        assert_eq!(
            recv.authentication.unauthenticated_sentinel,
            recv.symbols_received
        );
        assert!(recv.authentication.has_unauthenticated_sentinel());
    }

    #[test]
    fn test_receive_object_bad_target_tag_with_strict_security_fails_closed() {
        let cx: Cx = Cx::for_testing();
        let sender_security = SecurityContext::for_testing(42);
        let sink = VecSink::new();
        let mut sender =
            RaptorQSender::new(RaptorQConfig::default(), sink, Some(sender_security), None);

        let data = vec![0x11u8; 1024];
        let object_id = ObjectId::new_for_test(45);
        let outcome = sender.send_object(&cx, object_id, &data).unwrap();
        let params = params_for(
            object_id,
            data.len(),
            sender.config().encoding.symbol_size,
            outcome.source_symbols,
        );

        let mut symbols: Vec<AuthenticatedSymbol> =
            sender.transport_mut().symbols.drain(..).collect();
        let corrupted = symbols.remove(0);
        symbols.insert(
            0,
            AuthenticatedSymbol::from_parts(corrupted.into_symbol(), AuthenticationTag::zero()),
        );
        let stream = VecStream::new(symbols);
        let mut metrics = Metrics::new();
        let auth_rejected = metrics.counter("raptorq.auth_rejected");
        let symbols_received = metrics.counter("raptorq.symbols_received");
        let mut receiver = RaptorQReceiver::new(
            RaptorQConfig::default(),
            stream,
            Some(SecurityContext::for_testing(42)),
            Some(metrics),
        );

        let err = receiver
            .receive_object(&cx, &params)
            .expect_err("strict auth should fail closed on a bad target tag");

        assert_eq!(err.kind(), ErrorKind::CorruptedSymbol);
        assert_eq!(
            auth_rejected.get(),
            1,
            "strict bad-tag rejection must be counted"
        );
        assert_eq!(
            symbols_received.get(),
            0,
            "bad tags must be rejected before decode acceptance"
        );
    }

    #[test]
    fn test_receive_object_permissive_security_marks_receive_as_unauthenticated() {
        let cx: Cx = Cx::for_testing();
        let sender_security = SecurityContext::for_testing(42);
        let sink = VecSink::new();
        let mut sender =
            RaptorQSender::new(RaptorQConfig::default(), sink, Some(sender_security), None);

        let data = vec![0x77u8; 1024];
        let object_id = ObjectId::new_for_test(46);
        let outcome = sender.send_object(&cx, object_id, &data).unwrap();
        let params = params_for(
            object_id,
            data.len(),
            sender.config().encoding.symbol_size,
            outcome.source_symbols,
        );

        let mut symbols: Vec<AuthenticatedSymbol> =
            sender.transport_mut().symbols.drain(..).collect();
        let corrupted = symbols.remove(0);
        symbols.insert(
            0,
            AuthenticatedSymbol::from_parts(corrupted.into_symbol(), AuthenticationTag::zero()),
        );
        let stream = VecStream::new(symbols);
        let mut receiver = RaptorQReceiver::new(
            RaptorQConfig::default(),
            stream,
            Some(SecurityContext::for_testing_with_mode(
                42,
                AuthMode::Permissive,
            )),
            None,
        );

        let recv = receiver
            .receive_object(&cx, &params)
            .expect("permissive mode should allow decode to continue");

        assert_eq!(&recv.data[..data.len()], &data);
        assert!(
            !recv.authenticated,
            "permissive-mode decode with an unverified symbol must not report authenticated"
        );
        assert_eq!(recv.authentication.total(), recv.symbols_received);
        assert_eq!(recv.authentication.unauthenticated_sentinel, 1);
        assert_eq!(
            recv.authentication.verified,
            recv.symbols_received.saturating_sub(1)
        );
        assert!(recv.authentication.has_unauthenticated_sentinel());
        assert!(!recv.authentication.has_unverified_tagged());
    }

    #[test]
    fn test_receive_object_duplicate_symbols_do_not_inflate_used_count() {
        let cx: Cx = Cx::for_testing();
        let sink = VecSink::new();
        let mut sender = RaptorQSender::new(RaptorQConfig::default(), sink, None, None);

        let data = vec![0x5Au8; 512];
        let object_id = ObjectId::new_for_test(11);
        let outcome = sender.send_object(&cx, object_id, &data).unwrap();
        let params = params_for(
            object_id,
            data.len(),
            sender.config().encoding.symbol_size,
            outcome.source_symbols,
        );

        let mut symbols: Vec<AuthenticatedSymbol> =
            sender.transport_mut().symbols.drain(..).collect();
        symbols.truncate(outcome.source_symbols);
        let duplicate = symbols[0].clone();
        let mut stream_symbols = vec![duplicate.clone(), duplicate];
        stream_symbols.extend(symbols);

        let stream = VecStream::new(stream_symbols);
        let mut receiver = RaptorQReceiver::new(RaptorQConfig::default(), stream, None, None);
        let recv = receiver.receive_object(&cx, &params).unwrap();

        assert_eq!(&recv.data[..data.len()], &data);
        assert_eq!(
            recv.symbols_received, outcome.source_symbols,
            "duplicate symbols must not count as used-for-decoding"
        );
        assert_eq!(recv.authentication.total(), recv.symbols_received);
        assert_eq!(
            recv.authentication.unauthenticated_sentinel,
            recv.symbols_received
        );
    }

    #[test]
    fn test_receive_object_bad_permissive_duplicate_does_not_poison_authenticated_flag() {
        let cx: Cx = Cx::for_testing();
        let sink = VecSink::new();
        let mut sender = RaptorQSender::new(
            RaptorQConfig::default(),
            sink,
            Some(SecurityContext::for_testing(42)),
            None,
        );

        let data = vec![0xC3u8; 1024];
        let object_id = ObjectId::new_for_test(47);
        let outcome = sender.send_object(&cx, object_id, &data).unwrap();
        let params = params_for(
            object_id,
            data.len(),
            sender.config().encoding.symbol_size,
            outcome.source_symbols,
        );

        let mut symbols: Vec<AuthenticatedSymbol> =
            sender.transport_mut().symbols.drain(..).collect();
        symbols.truncate(outcome.source_symbols);
        let good_first = symbols[0].clone();
        let bad_duplicate = AuthenticatedSymbol::from_parts(
            good_first.clone().into_symbol(),
            AuthenticationTag::zero(),
        );
        let mut stream_symbols = vec![good_first, bad_duplicate];
        stream_symbols.extend(symbols);

        let stream = VecStream::new(stream_symbols);
        let permissive_security = SecurityContext::for_testing_with_mode(42, AuthMode::Permissive);
        let mut receiver = RaptorQReceiver::new(
            RaptorQConfig::default(),
            stream,
            Some(permissive_security),
            None,
        );

        let recv = receiver
            .receive_object(&cx, &params)
            .expect("bad duplicate should be ignored after permissive auth check");

        assert_eq!(&recv.data[..data.len()], &data);
        assert!(
            recv.authenticated,
            "a rejected duplicate must not mark the decoded object unauthenticated"
        );
        assert_eq!(recv.authentication.total(), recv.symbols_received);
        assert_eq!(
            recv.authentication.verified, recv.symbols_received,
            "a rejected duplicate must not count in the receive auth summary"
        );
        assert!(!recv.authentication.has_unauthenticated_sentinel());
    }

    #[test]
    fn send_outcome_debug_clone() {
        let o = SendOutcome {
            object_id: ObjectId::new_for_test(1),
            source_symbols: 10,
            repair_symbols: 5,
            symbols_sent: 15,
        };
        let dbg = format!("{o:?}");
        assert!(dbg.contains("SendOutcome"), "{dbg}");
        let cloned = o;
        assert_eq!(format!("{cloned:?}"), dbg);
    }

    #[test]
    fn send_progress_debug_clone() {
        let p = SendProgress { sent: 3, total: 10 };
        let dbg = format!("{p:?}");
        assert!(dbg.contains("SendProgress"), "{dbg}");
        let cloned = p;
        assert_eq!(format!("{cloned:?}"), dbg);
    }

    #[test]
    fn receive_outcome_debug() {
        let r = ReceiveOutcome {
            data: vec![0u8; 16],
            symbols_received: 20,
            authenticated: true,
            authentication: ReceiveAuthenticationSummary {
                verified: 20,
                unverified_tagged: 0,
                unauthenticated_sentinel: 0,
            },
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("ReceiveOutcome"), "{dbg}");
    }

    #[test]
    fn receive_authentication_summary_reports_totals_and_flags() {
        let summary = ReceiveAuthenticationSummary {
            verified: 2,
            unverified_tagged: 1,
            unauthenticated_sentinel: 3,
        };

        assert_eq!(summary.total(), 6);
        assert!(!summary.all_verified());
        assert!(summary.has_unverified_tagged());
        assert!(summary.has_unauthenticated_sentinel());
    }
