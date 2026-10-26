    use super::*;

    #[test]
    fn config_validation() {
        assert!(EcConfig::default().validate().is_ok());
        assert_eq!(
            EcConfig {
                symbol_size: 0,
                ..EcConfig::default()
            }
            .validate(),
            Err(EcError::ZeroSymbolSize)
        );
        assert_eq!(
            EcConfig {
                max_message_size: 0,
                ..EcConfig::default()
            }
            .validate(),
            Err(EcError::ZeroMaxMessage)
        );
    }

    #[test]
    fn small_message_is_one_source_symbol() {
        let cfg = EcConfig {
            symbol_size: 1024,
            repair_overhead: 4,
            max_message_size: 1 << 20,
        };
        let layout = cfg.plan(10).expect("plan");
        assert_eq!(layout.source_symbols, 1);
        assert_eq!(layout.repair_symbols, 4);
        assert_eq!(layout.total_symbols, 5);
        assert_eq!(layout.padding, 1014);
    }

    #[test]
    fn exact_multiple_has_no_padding() {
        let cfg = EcConfig {
            symbol_size: 100,
            repair_overhead: 2,
            max_message_size: 1 << 20,
        };
        let layout = cfg.plan(300).expect("plan");
        assert_eq!(layout.source_symbols, 3);
        assert_eq!(layout.total_symbols, 5);
        assert_eq!(layout.padding, 0);
    }

    #[test]
    fn non_multiple_pads_final_symbol() {
        let cfg = EcConfig {
            symbol_size: 100,
            repair_overhead: 1,
            max_message_size: 1 << 20,
        };
        let layout = cfg.plan(250).expect("plan");
        assert_eq!(layout.source_symbols, 3); // ceil(250/100)
        assert_eq!(layout.padding, 50); // 300 - 250
    }

    #[test]
    fn empty_message_still_gets_one_symbol() {
        let layout = EcConfig::default().plan(0).expect("plan");
        assert_eq!(layout.source_symbols, 1);
    }

    #[test]
    fn message_too_large_rejected() {
        let cfg = EcConfig {
            symbol_size: 16,
            repair_overhead: 2,
            max_message_size: 100,
        };
        assert_eq!(
            cfg.plan(101),
            Err(EcError::MessageTooLarge {
                size: 101,
                max: 100
            })
        );
    }

    #[test]
    fn loss_margin_matches_overhead_fraction() {
        let cfg = EcConfig {
            symbol_size: 100,
            repair_overhead: 5,
            max_message_size: 1 << 20,
        };
        let layout = cfg.plan(500).expect("plan"); // K=5, N=10
        assert_eq!(layout.total_symbols, 10);
        assert!((layout.loss_margin() - 0.5).abs() < 1e-9);
        assert_eq!(layout.min_symbols_to_decode(), 5);
    }

    #[test]
    fn header_roundtrips() {
        let cfg = EcConfig::default();
        let layout = cfg.plan(5000).expect("plan");
        let header = MessageHeader::from_layout(7, &layout).expect("header");
        let bytes = header.encode();
        assert_eq!(bytes.len(), MessageHeader::ENCODED_LEN);
        let decoded = MessageHeader::decode(&bytes).expect("decode");
        assert_eq!(decoded, header);
        assert_eq!(decoded.message_id, 7);
        assert_eq!(decoded.message_size, 5000);
    }

    #[test]
    fn header_decode_rejects_short_buffer() {
        let result = MessageHeader::decode(&[0u8; 4]);
        assert_eq!(
            result,
            Err(EcError::ShortHeader {
                got: 4,
                need: MessageHeader::ENCODED_LEN
            })
        );
    }

    #[test]
    fn decode_progress_predicates_track_the_repair_budget() {
        let cfg = EcConfig {
            symbol_size: 100,
            repair_overhead: 5,
            max_message_size: 1 << 20,
        };
        let layout = cfg.plan(500).expect("plan"); // K=5, N=10, repair=5
        assert_eq!(layout.source_symbols, 5);
        assert_eq!(layout.total_symbols, 10);

        // Not enough below K; decodable from exactly K onward.
        assert!(!layout.is_decodable(4));
        assert!(layout.is_decodable(5));
        assert!(layout.is_decodable(7));

        // Remaining count shrinks to zero at K and stays there.
        assert_eq!(layout.symbols_until_decodable(0), 5);
        assert_eq!(layout.symbols_until_decodable(3), 2);
        assert_eq!(layout.symbols_until_decodable(5), 0);
        assert_eq!(layout.symbols_until_decodable(9), 0);

        // Losing up to the whole repair budget stays recoverable; one more is
        // out of reach (10 - 6 = 4 < K=5).
        assert!(!layout.is_unrecoverable(5));
        assert!(layout.is_unrecoverable(6));
    }

    #[test]
    fn decode_predicates_are_self_consistent_across_the_range() {
        let cfg = EcConfig {
            symbol_size: 64,
            repair_overhead: 3,
            max_message_size: 1 << 20,
        };
        let layout = cfg.plan(400).expect("plan"); // K=ceil(400/64)=7, N=10
        let n = layout.total_symbols;

        // is_decodable iff nothing more is needed, monotone as symbols arrive.
        let mut last_remaining = u16::MAX;
        for received in 0..=n {
            let remaining = layout.symbols_until_decodable(received);
            assert_eq!(layout.is_decodable(received), remaining == 0);
            assert!(remaining <= last_remaining, "remaining must not grow");
            last_remaining = remaining;
        }

        // is_unrecoverable iff losses exceed the repair budget; the boundary is
        // exactly repair_symbols losable.
        for lost in 0..=n {
            assert_eq!(layout.is_unrecoverable(lost), lost > layout.repair_symbols);
        }
        assert!(!layout.is_unrecoverable(layout.repair_symbols));
        assert!(layout.is_unrecoverable(layout.repair_symbols + 1));
    }

    #[test]
    fn block_layout_inverts_from_layout() {
        let cfg = EcConfig::default();
        for size in [0usize, 1, 10, 1023, 1024, 1025, 5000, 65_535, 1 << 20] {
            let layout = cfg.plan(size).expect("plan");
            let header = MessageHeader::from_layout(42, &layout).expect("header");
            assert_eq!(
                header.block_layout(),
                layout,
                "block_layout must invert from_layout at size {size}"
            );
        }
    }

    #[test]
    fn block_layout_recomputes_geometry_from_header_fields() {
        // A header carries no padding/repair fields; block_layout derives both.
        let header = MessageHeader {
            message_id: 9,
            message_size: 250,
            symbol_size: 100,
            source_symbols: 3,
            total_symbols: 7,
        };
        let layout = header.block_layout();
        assert_eq!(layout.repair_symbols, 4); // 7 - 3
        assert_eq!(layout.padding, 50); // 3*100 - 250
        assert_eq!(layout.message_size, 250);
        assert_eq!(layout.min_symbols_to_decode(), 3);
    }

    fn k3_n5_header(message_id: u64) -> MessageHeader {
        // symbol_size=4, K=ceil(9/4)=3, repair=2, N=5.
        let cfg = EcConfig {
            symbol_size: 4,
            repair_overhead: 2,
            max_message_size: 1 << 20,
        };
        let layout = cfg.plan(9).expect("plan");
        assert_eq!(layout.source_symbols, 3);
        assert_eq!(layout.total_symbols, 5);
        MessageHeader::from_layout(message_id, &layout).expect("header")
    }

    #[test]
    fn symbol_frame_roundtrips() {
        let frame = SymbolFrame::new(0x00A1_B2C3_D4E5_F601, 9, vec![1, 2, 3, 4, 5]);
        assert_eq!(frame.encoded_len(), SymbolFrame::HEADER_LEN + 5);
        let bytes = frame.encode();
        assert_eq!(bytes.len(), frame.encoded_len());
        let decoded = SymbolFrame::decode(&bytes).expect("decode");
        assert_eq!(decoded, frame);
        assert_eq!(decoded.message_id, 0x00A1_B2C3_D4E5_F601);
        assert_eq!(decoded.esi, 9);
        assert_eq!(decoded.payload, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn symbol_frame_empty_payload_roundtrips() {
        let frame = SymbolFrame::new(5, 0, Vec::new());
        let bytes = frame.encode();
        assert_eq!(bytes.len(), SymbolFrame::HEADER_LEN);
        let decoded = SymbolFrame::decode(&bytes).expect("decode");
        assert_eq!(decoded, frame);
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn symbol_frame_decode_rejects_short_buffer() {
        let result = SymbolFrame::decode(&[0u8; 9]);
        assert_eq!(
            result,
            Err(EcError::ShortFrame {
                got: 9,
                need: SymbolFrame::HEADER_LEN
            })
        );
    }

    #[test]
    fn reassembler_dedups_reorders_and_tracks_readiness() {
        let header = k3_n5_header(11);
        let mut ra = MessageReassembler::new(&header);
        assert_eq!(ra.message_id(), 11);
        assert_eq!(ra.layout().source_symbols, 3);
        assert_eq!(ra.distinct_received(), 0);
        assert!(!ra.is_ready());
        assert_eq!(ra.symbols_until_ready(), 3);

        // Out-of-order arrivals are accepted.
        assert_eq!(ra.accept(3, &[3, 3, 3, 3]), SymbolAccept::Accepted);
        assert_eq!(ra.accept(0, &[0, 0, 0, 0]), SymbolAccept::Accepted);
        assert_eq!(ra.distinct_received(), 2);
        assert!(!ra.is_ready());
        assert_eq!(ra.symbols_until_ready(), 1);

        // A repeated esi (even with different bytes) is a duplicate; the first
        // copy is kept and the count does not advance.
        assert_eq!(ra.accept(3, &[9, 9, 9, 9]), SymbolAccept::Duplicate);
        assert_eq!(ra.distinct_received(), 2);

        // The third distinct symbol reaches K and flips readiness.
        assert_eq!(ra.accept(4, &[4, 4, 4, 4]), SymbolAccept::Accepted);
        assert_eq!(ra.distinct_received(), 3);
        assert!(ra.is_ready());
        assert_eq!(ra.symbols_until_ready(), 0);

        // Extra symbols beyond K are still accepted (decode-overhead headroom).
        assert_eq!(ra.accept(1, &[1, 1, 1, 1]), SymbolAccept::Accepted);
        assert_eq!(ra.distinct_received(), 4);
        assert!(ra.is_ready());

        // Held symbols come back in ascending esi order regardless of arrival
        // order, and esi 3 retained its FIRST payload (not the duplicate).
        let held: Vec<(u16, Vec<u8>)> = ra.symbols().map(|(e, b)| (e, b.to_vec())).collect();
        assert_eq!(
            held,
            vec![
                (0, vec![0, 0, 0, 0]),
                (1, vec![1, 1, 1, 1]),
                (3, vec![3, 3, 3, 3]),
                (4, vec![4, 4, 4, 4]),
            ]
        );
    }

    #[test]
    fn reassembler_rejects_out_of_range_and_wrong_size() {
        let header = k3_n5_header(1);
        let mut ra = MessageReassembler::new(&header);

        // esi == total_symbols (5) is out of range; valid ids are 0..5.
        assert_eq!(
            ra.accept(5, &[0, 0, 0, 0]),
            SymbolAccept::OutOfRange { esi: 5, total: 5 }
        );
        // Payload length must equal symbol_size (4).
        assert_eq!(
            ra.accept(0, &[0, 0, 0]),
            SymbolAccept::WrongSize {
                esi: 0,
                got: 3,
                expected: 4
            }
        );
        // Rejected offers store nothing.
        assert_eq!(ra.distinct_received(), 0);
    }

    #[test]
    fn reassembler_routes_frames_by_message_id() {
        let header = k3_n5_header(100);
        let mut ra = MessageReassembler::new(&header);

        let foreign = SymbolFrame::new(200, 0, vec![0, 0, 0, 0]);
        assert_eq!(
            ra.accept_frame(&foreign),
            SymbolAccept::WrongMessage {
                expected: 100,
                got: 200
            }
        );
        assert_eq!(ra.distinct_received(), 0);

        let ours = SymbolFrame::new(100, 0, vec![7, 7, 7, 7]);
        assert_eq!(ra.accept_frame(&ours), SymbolAccept::Accepted);
        assert_eq!(ra.distinct_received(), 1);
        // Re-offering the same frame deduplicates.
        assert_eq!(ra.accept_frame(&ours), SymbolAccept::Duplicate);
        assert_eq!(ra.distinct_received(), 1);
    }

    #[test]
    fn reassembler_intake_is_arrival_order_independent() {
        // The same symbol set delivered in two different orders yields an
        // identical held sequence and identical readiness — the determinism the
        // seeded loss-injection suite relies on (AC7).
        let header = k3_n5_header(7);
        let payloads: [(u16, [u8; 4]); 3] = [(0, [10; 4]), (1, [11; 4]), (2, [12; 4])];

        let mut forward = MessageReassembler::new(&header);
        for (esi, bytes) in payloads {
            assert_eq!(forward.accept(esi, &bytes), SymbolAccept::Accepted);
        }

        let mut reversed = MessageReassembler::new(&header);
        for (esi, bytes) in payloads.iter().rev() {
            assert_eq!(reversed.accept(*esi, bytes), SymbolAccept::Accepted);
        }

        let fwd: Vec<(u16, Vec<u8>)> = forward.symbols().map(|(e, b)| (e, b.to_vec())).collect();
        let rev: Vec<(u16, Vec<u8>)> = reversed.symbols().map(|(e, b)| (e, b.to_vec())).collect();
        assert_eq!(fwd, rev);
        assert_eq!(forward.is_ready(), reversed.is_ready());
        assert!(forward.is_ready());
    }

    fn k5_n8_header(message_id: u64) -> MessageHeader {
        // symbol_size=4, K=ceil(20/4)=5, repair=3, N=8.
        let cfg = EcConfig {
            symbol_size: 4,
            repair_overhead: 3,
            max_message_size: 1 << 20,
        };
        let layout = cfg.plan(20).expect("plan");
        assert_eq!(layout.source_symbols, 5);
        assert_eq!(layout.total_symbols, 8);
        MessageHeader::from_layout(message_id, &layout).expect("header")
    }

    fn n_frames(message_id: u64, n: u16) -> Vec<SymbolFrame> {
        (0..n)
            .map(|esi| SymbolFrame::new(message_id, esi, vec![esi as u8; 4]))
            .collect()
    }

    #[test]
    fn loss_model_lossless_is_identity() {
        let frames = n_frames(1, 8);
        let delivered = LossModel::new(42).apply(&frames);
        assert_eq!(
            delivered, frames,
            "a lossless model must deliver its input verbatim"
        );
    }

    #[test]
    fn loss_model_total_drop_delivers_nothing() {
        let frames = n_frames(1, 8);
        let model = LossModel::new(42).with_drop_ppm(LossModel::PPM_SCALE);
        assert!(model.apply(&frames).is_empty());
    }

    #[test]
    fn loss_model_total_duplicate_delivers_each_twice() {
        let frames = n_frames(1, 4);
        let model = LossModel::new(42).with_duplicate_ppm(LossModel::PPM_SCALE);
        let delivered = model.apply(&frames);
        let expected: Vec<SymbolFrame> =
            frames.iter().flat_map(|f| [f.clone(), f.clone()]).collect();
        assert_eq!(
            delivered, expected,
            "every frame must be delivered exactly twice"
        );
    }

    #[test]
    fn loss_model_is_deterministic_for_a_seed() {
        let frames = n_frames(1, 8);
        let model = LossModel::new(7)
            .with_drop_ppm(300_000)
            .with_duplicate_ppm(100_000);
        // Same model, repeated application: byte-identical (AC7 replayability).
        assert_eq!(model.apply(&frames), model.apply(&frames));
        // A second model with the same seed/rates is identical to the first.
        let twin = LossModel::new(7)
            .with_drop_ppm(300_000)
            .with_duplicate_ppm(100_000);
        assert_eq!(model, twin);
        assert_eq!(model.apply(&frames), twin.apply(&frames));
    }

    #[test]
    fn loss_model_saturates_out_of_range_rates() {
        let model = LossModel::new(1)
            .with_drop_ppm(2_000_000)
            .with_duplicate_ppm(5_000_000);
        assert_eq!(model.drop_ppm, LossModel::PPM_SCALE);
        assert_eq!(model.duplicate_ppm, LossModel::PPM_SCALE);
    }

    #[test]
    fn loss_model_feeds_reassembler_respecting_repair_budget() {
        // AC1 at the intake layer: after seeded drops, the reassembler reports
        // ready iff the number lost stays within the repair budget — the count
        // complement of the loss margin — exactly tracking BlockLayout.
        let header = k5_n8_header(55);
        let frames = n_frames(55, header.total_symbols);
        let layout = header.block_layout();

        for seed in [1u64, 2, 7, 99, 12_345, 654_321] {
            let model = LossModel::new(seed).with_drop_ppm(300_000);
            let delivered = model.apply(&frames);

            let mut ra = MessageReassembler::new(&header);
            for frame in &delivered {
                let _ = ra.accept_frame(frame);
            }
            let lost = header.total_symbols - ra.distinct_received();
            assert_eq!(
                ra.is_ready(),
                !layout.is_unrecoverable(lost),
                "seed {seed}: readiness must track the repair budget (lost={lost}, repair={})",
                layout.repair_symbols
            );
        }
    }

    #[test]
    fn loss_model_duplicates_never_inflate_distinct_count() {
        // Duplicates are deduplicated by the reassembler: a heavy duplicate rate
        // with zero drops still yields exactly the distinct symbol set.
        let header = k5_n8_header(8);
        let frames = n_frames(8, header.total_symbols);
        let model = LossModel::new(3).with_duplicate_ppm(LossModel::PPM_SCALE);
        let delivered = model.apply(&frames);
        assert_eq!(delivered.len(), 2 * frames.len());

        let mut ra = MessageReassembler::new(&header);
        let mut duplicates = 0u32;
        for frame in &delivered {
            if ra.accept_frame(frame) == SymbolAccept::Duplicate {
                duplicates += 1;
            }
        }
        assert_eq!(ra.distinct_received(), header.total_symbols);
        assert_eq!(duplicates, u32::from(header.total_symbols));
        assert!(ra.is_ready());
    }

    #[test]
    fn pending_reassembly_buffer_is_bounded_with_fifo_eviction() {
        // Regression: a lossy/abandoning sender that emits headers for messages
        // that never collect their K source symbols must not grow the
        // reassembly map without bound. Feed 6 distinct headers (K=3) with NO
        // symbols, so every message stays permanently incomplete.
        let (_tx, mut rx) = channel(EcConfig::default());
        rx.max_pending = 4;
        for id in 0..6u64 {
            let _ = rx.ingest_unit(WireUnit::Header(k3_n5_header(id)));
        }
        // Capped at 4: the two oldest (ids 0,1) are evicted FIFO, the newest
        // four (2..=5) retained, and the eviction index stays in exact sync.
        assert_eq!(rx.pending.len(), 4);
        assert_eq!(rx.pending_order.len(), rx.pending.len());
        assert!(!rx.pending.contains_key(&0));
        assert!(!rx.pending.contains_key(&1));
        for id in 2..6u64 {
            assert!(rx.pending.contains_key(&id), "id {id} should be retained");
        }
    }

    fn authenticated_config() -> EcConfig {
        EcConfig {
            symbol_size: 64,
            repair_overhead: 6,
            max_message_size: 16 * 1024,
        }
    }

    fn authenticated_pair(capacity: usize) -> (AuthenticatedEcSender, AuthenticatedEcReceiver) {
        authenticated_channel(
            authenticated_config(),
            capacity,
            &SecurityContext::for_testing(0xec_2026),
            [17; 32],
        )
        .expect("bounded authenticated channel")
    }

    #[derive(Default)]
    struct AuthenticatedWakeCount(std::sync::atomic::AtomicUsize);

    impl std::task::Wake for AuthenticatedWakeCount {
        fn wake(self: std::sync::Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &std::sync::Arc<Self>) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[test]
    fn authenticated_channel_rejects_invalid_and_unrepresentable_bounds() {
        let auth = SecurityContext::for_testing(1);
        assert!(matches!(
            authenticated_channel(authenticated_config(), 0, &auth, [0; 32]),
            Err(AuthenticatedEcError::Configuration(_))
        ));
        assert!(matches!(
            authenticated_channel(authenticated_config(), usize::MAX, &auth, [0; 32]),
            Err(AuthenticatedEcError::Configuration(_))
        ));
        assert!(matches!(
            authenticated_channel(
                EcConfig { symbol_size: 0, ..authenticated_config() },
                1,
                &auth,
                [0; 32],
            ),
            Err(AuthenticatedEcError::Message(EcError::ZeroSymbolSize))
        ));
        assert!(matches!(
            authenticated_channel(
                EcConfig { symbol_size: 1, max_message_size: 65_536, repair_overhead: 0 },
                1,
                &auth,
                [0; 32],
            ),
            Err(AuthenticatedEcError::Message(EcError::SymbolCountOverflow))
        ));
        assert!(matches!(
            authenticated_channel(
                EcConfig { symbol_size: 1, max_message_size: 56_404, repair_overhead: 0 },
                1,
                &auth,
                [0; 32],
            ),
            Err(AuthenticatedEcError::Message(EcError::Coding(_)))
        ));
    }

    #[test]
    fn authenticated_channel_roundtrips_bytes_empty_and_typed_messages_in_order() {
        use futures_lite::future::block_on;

        let (mut tx, mut rx) = authenticated_pair(3);
        let cx = Cx::for_testing();
        let bytes: Vec<u8> = (0_u8..=255).cycle().take(900).collect();
        let value = serde_json::json!({"actor": "worker", "generation": 42, "ready": true});
        assert_eq!(block_on(tx.send(&cx, &bytes)), Ok(0));
        assert_eq!(block_on(tx.send(&cx, &[])), Ok(1));
        assert_eq!(block_on(tx.send_value(&cx, &value)), Ok(2));
        let queued = rx.rx.telemetry_snapshot(1);
        assert_eq!(queued.queued_messages, 3);
        assert_eq!(queued.reserved_uncommitted_obligations, 0);
        assert_eq!(block_on(rx.recv(&cx)), Ok(bytes));
        assert_eq!(block_on(rx.recv(&cx)), Ok(Vec::new()));
        assert_eq!(block_on(rx.recv_value::<serde_json::Value>(&cx)), Ok(value));
        drop(tx);
        assert_eq!(
            block_on(rx.recv(&cx)),
            Err(AuthenticatedEcError::Message(EcError::TransportClosed))
        );
    }

    #[test]
    fn authenticated_channel_capacity_wait_does_not_encode_or_serialize_before_admission() {
        use futures_lite::future::block_on;
        use std::future::Future;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::{Context, Poll, Waker};

        struct CountSerialization<'a>(&'a AtomicUsize);
        impl serde::Serialize for CountSerialization<'_> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                self.0.fetch_add(1, Ordering::SeqCst);
                serializer.serialize_str("after capacity")
            }
        }

        let (mut tx, mut rx) = authenticated_pair(1);
        let cx = Cx::for_testing();
        assert_eq!(block_on(tx.send(&cx, b"already committed")), Ok(0));
        let before_signed = tx.auth.stats().signed.load(Ordering::SeqCst);
        let serialized = AtomicUsize::new(0);
        let value = CountSerialization(&serialized);
        let cancelled = Cx::for_testing();
        let wakes = Arc::new(AuthenticatedWakeCount::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut poll_cx = Context::from_waker(&waker);
        let mut send = Box::pin(tx.send_value(&cancelled, &value));
        assert!(send.as_mut().poll(&mut poll_cx).is_pending());
        let parked = rx.rx.telemetry_snapshot(2);
        assert_eq!(parked.send_waiter_count, 1);
        assert_eq!(parked.queued_messages, 1);
        assert_eq!(parked.reserved_uncommitted_obligations, 0);
        assert_eq!(serialized.load(Ordering::SeqCst), 0);
        cancelled.cancel_fast(crate::types::CancelKind::User);
        assert!(wakes.0.load(Ordering::SeqCst) > 0);
        assert!(matches!(
            send.as_mut().poll(&mut poll_cx),
            Poll::Ready(Err(AuthenticatedEcError::Message(EcError::Cancelled)))
        ));
        drop(send);
        assert_eq!(serialized.load(Ordering::SeqCst), 0);
        assert_eq!(tx.auth.stats().signed.load(Ordering::SeqCst), before_signed);
        assert_eq!(tx.next_message_id, Some(1));
        assert_eq!(rx.rx.telemetry_snapshot(2).send_waiter_count, 0);
        assert_eq!(block_on(rx.recv(&cx)).unwrap(), b"already committed");
        assert_eq!(block_on(tx.send_value(&cx, &value)), Ok(1));
        assert_eq!(serialized.load(Ordering::SeqCst), 1);
        assert_eq!(block_on(rx.recv_value::<String>(&cx)).unwrap(), "after capacity");
    }

    #[test]
    fn authenticated_channel_dropped_waits_and_permits_restore_capacity() {
        use futures_lite::future::block_on;
        use std::future::Future;
        use std::task::{Context, Waker};

        let (mut tx, mut rx) = authenticated_pair(1);
        let cx = Cx::for_testing();
        assert_eq!(block_on(tx.send(&cx, b"first")), Ok(0));
        let mut waiting = Box::pin(tx.reserve(&cx));
        let mut poll_cx = Context::from_waker(Waker::noop());
        assert!(waiting.as_mut().poll(&mut poll_cx).is_pending());
        assert_eq!(rx.rx.telemetry_snapshot(3).send_waiter_count, 1);
        drop(waiting);
        assert_eq!(rx.rx.telemetry_snapshot(3).send_waiter_count, 0);
        assert_eq!(block_on(rx.recv(&cx)).unwrap(), b"first");
        let permit = block_on(tx.reserve(&cx)).unwrap();
        assert_eq!(rx.rx.telemetry_snapshot(3).reserved_uncommitted_obligations, 1);
        drop(permit);
        assert_eq!(rx.rx.telemetry_snapshot(3).reserved_uncommitted_obligations, 0);
        block_on(tx.reserve(&cx)).unwrap().abort();
        assert_eq!(tx.next_message_id, Some(1));
        assert_eq!(block_on(tx.send(&cx, b"reused")), Ok(1));
        assert_eq!(block_on(rx.recv(&cx)).unwrap(), b"reused");
        drop(rx);
        assert_eq!(
            block_on(tx.send(&cx, b"closed")),
            Err(AuthenticatedEcError::Message(EcError::TransportClosed))
        );
        assert_eq!(tx.next_message_id, Some(2));
    }

    #[test]
    fn authenticated_channel_cancelled_receiver_keeps_committed_messages() {
        use futures_lite::future::block_on;
        use std::future::Future;
        use std::sync::Arc;
        use std::sync::atomic::Ordering;
        use std::task::{Context, Poll, Waker};

        let (mut tx, mut rx) = authenticated_pair(1);
        let cx = Cx::for_testing();
        let cancelled = Cx::for_testing();
        let wakes = Arc::new(AuthenticatedWakeCount::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut poll_cx = Context::from_waker(&waker);
        let mut recv = Box::pin(rx.recv(&cancelled));
        assert!(recv.as_mut().poll(&mut poll_cx).is_pending());
        cancelled.cancel_fast(crate::types::CancelKind::User);
        assert!(wakes.0.load(Ordering::SeqCst) > 0);
        assert!(matches!(
            recv.as_mut().poll(&mut poll_cx),
            Poll::Ready(Err(AuthenticatedEcError::Message(EcError::Cancelled)))
        ));
        drop(recv);
        assert_eq!(rx.rx.telemetry_snapshot(4).recv_waiter_count, 0);
        assert_eq!(block_on(tx.send(&cx, b"retained")), Ok(0));
        assert_eq!(
            block_on(rx.recv(&cancelled)),
            Err(AuthenticatedEcError::Message(EcError::Cancelled))
        );
        assert_eq!(rx.rx.len(), 1);
        assert_eq!(block_on(rx.recv(&cx)).unwrap(), b"retained");
    }

    #[test]
    fn authenticated_channel_verifies_key_session_and_header_before_decode() {
        use futures_lite::future::block_on;

        for wrong_session in [false, true] {
            let (mut tx, mut rx) = authenticated_pair(1);
            let cx = Cx::for_testing();
            let authentic = rx.auth.clone();
            let wrong_key = if wrong_session { 0xec_2026 } else { 0xec_2027 };
            let session = if wrong_session { [18; 32] } else { [17; 32] };
            let (_, wrong_rx) = authenticated_channel(
                authenticated_config(), 1, &SecurityContext::for_testing(wrong_key), session,
            ).unwrap();
            rx.auth = wrong_rx.auth;
            assert_eq!(block_on(tx.send(&cx, b"signed")), Ok(0));
            assert_eq!(
                block_on(rx.recv(&cx)),
                Err(AuthenticatedEcError::Message(EcError::AuthenticationFailed))
            );
            rx.auth = authentic;
            assert_eq!(block_on(tx.send(&cx, b"next is healthy")), Ok(1));
            assert_eq!(block_on(rx.recv(&cx)).unwrap(), b"next is healthy");
        }

        let (mut tx, mut rx) = authenticated_pair(1);
        let cx = Cx::for_testing();
        block_on(tx.send(&cx, &[19; 900])).unwrap();
        let mut message = rx.rx.try_recv().unwrap();
        message.header.header.message_size -= 1; // Same valid K, stale MAC.
        tx.tx.try_send(message).unwrap();
        assert_eq!(
            block_on(rx.recv(&cx)),
            Err(AuthenticatedEcError::Message(EcError::AuthenticationFailed))
        );
        assert!(rx.rx.is_empty());
    }

    #[test]
    fn authenticated_channel_repairs_forged_and_lost_symbols_in_every_input_mode() {
        use futures_lite::future::block_on;

        for mode in [AuthMode::Strict, AuthMode::Permissive, AuthMode::Disabled] {
            let context = SecurityContext::for_testing_with_mode(42, mode);
            let (mut tx, mut rx) = authenticated_channel(
                authenticated_config(), 1, &context, [21; 32],
            ).unwrap();
            assert_eq!(tx.auth.mode(), AuthMode::Strict);
            assert_eq!(rx.auth.mode(), AuthMode::Strict);
            let cx = Cx::for_testing();
            let bytes: Vec<u8> = (0_u8..=255).cycle().take(900).collect();
            block_on(tx.send(&cx, &bytes)).unwrap();
            let mut message = rx.rx.try_recv().unwrap();
            message.symbols.remove(0); // One source symbol is lost in transport.
            let mut corrupted = message.symbols[0].symbol().clone();
            corrupted.data_mut()[0] ^= 1;
            message.symbols[0] = AuthenticatedSymbol::from_parts(
                corrupted,
                *message.symbols[0].tag(),
            );
            message.symbols.push(message.symbols[1].clone()); // A duplicate adds no rank.
            message.symbols.reverse();
            tx.tx.try_send(message).unwrap();
            assert_eq!(block_on(rx.recv(&cx)), Ok(bytes.clone()));

            block_on(tx.send(&cx, &bytes)).unwrap();
            let mut forged = rx.rx.try_recv().unwrap();
            for symbol in &mut forged.symbols {
                *symbol = AuthenticatedSymbol::from_parts(
                    symbol.symbol().clone(),
                    AuthenticationTag::zero(),
                );
            }
            tx.tx.try_send(forged).unwrap();
            assert!(matches!(
                block_on(rx.recv(&cx)),
                Err(AuthenticatedEcError::Message(EcError::IncompleteDecode { .. }))
            ));
        }
    }

    #[test]
    fn authenticated_channel_checks_reconstructed_payload_and_transport_bounds() {
        use futures_lite::future::block_on;

        let (mut tx, mut rx) = authenticated_pair(1);
        let cx = Cx::for_testing();
        block_on(tx.send(&cx, &[23; 900])).unwrap();
        let mut message = rx.rx.try_recv().unwrap();
        let binding = message.header.symbol_context(&tx.auth);
        let (_, different) = tx.config
            .encode_message_authenticated(message.header.header.message_id, &[24; 900], &tx.auth)
            .unwrap();
        message.symbols = different.iter()
            .map(|symbol| binding.sign_symbol(symbol.symbol()))
            .collect();
        tx.tx.try_send(message).unwrap();
        assert_eq!(
            block_on(rx.recv(&cx)),
            Err(AuthenticatedEcError::Message(EcError::AuthenticationFailed)),
            "even valid symbol tags cannot change the committed payload digest"
        );

        block_on(tx.send(&cx, b"bounded")).unwrap();
        let mut excessive = rx.rx.try_recv().unwrap();
        excessive.symbols.push(excessive.symbols[0].clone());
        tx.tx.try_send(excessive).unwrap();
        assert!(matches!(
            block_on(rx.recv(&cx)),
            Err(AuthenticatedEcError::InvalidEnvelope(_))
        ));

        let too_large = vec![31; tx.config.max_message_size + 1];
        let larger_config = EcConfig { max_message_size: too_large.len(), ..tx.config };
        let (header, symbols) = larger_config.encode_message_authenticated(9, &too_large, &tx.auth)
            .unwrap();
        tx.tx.try_send(AuthenticatedEcEnvelope { header, symbols }).unwrap();
        assert_eq!(
            block_on(rx.recv(&cx)),
            Err(AuthenticatedEcError::Message(EcError::MessageTooLarge {
                size: too_large.len(), max: tx.config.max_message_size,
            }))
        );
        assert_eq!(block_on(tx.send(&cx, b"still works")), Ok(2));
        assert_eq!(block_on(rx.recv(&cx)).unwrap(), b"still works");
    }

    #[test]
    fn authenticated_channel_bounds_serialization_and_checks_cancel_before_commit() {
        use futures_lite::future::block_on;

        struct CancelsWhileSerializing<'a>(&'a Cx);
        impl serde::Serialize for CancelsWhileSerializing<'_> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                self.0.cancel_fast(crate::types::CancelKind::User);
                serializer.serialize_str("cancelled")
            }
        }

        let config = EcConfig { max_message_size: 32, ..authenticated_config() };
        let (mut tx, mut rx) = authenticated_channel(
            config, 1, &SecurityContext::for_testing(55), [22; 32],
        ).unwrap();
        let cx = Cx::for_testing();
        assert!(matches!(
            block_on(tx.send_value(&cx, &"x".repeat(1000))),
            Err(AuthenticatedEcError::Message(EcError::MessageTooLarge { max: 32, .. }))
        ));
        assert_eq!(tx.next_message_id, Some(0));
        assert_eq!(rx.rx.telemetry_snapshot(5).reserved_uncommitted_obligations, 0);
        assert!(rx.rx.is_empty());
        let cancelled = Cx::for_testing();
        assert_eq!(
            block_on(tx.send_value(&cancelled, &CancelsWhileSerializing(&cancelled))),
            Err(AuthenticatedEcError::Message(EcError::Cancelled))
        );
        assert!(rx.rx.is_empty());
        assert_eq!(rx.rx.telemetry_snapshot(5).reserved_uncommitted_obligations, 0);
        assert_eq!(block_on(tx.send_value(&cx, &"healthy")), Ok(0));
        assert_eq!(block_on(rx.recv_value::<String>(&cx)).unwrap(), "healthy");
    }

    #[test]
    fn authenticated_channel_accepts_large_source_counts_and_refuses_id_reuse() {
        use futures_lite::future::block_on;

        let config = EcConfig {
            symbol_size: 8,
            repair_overhead: 0,
            max_message_size: 8_193 * 8,
        };
        let (mut tx, mut rx) = authenticated_channel(
            config, 1, &SecurityContext::for_testing(59), [23; 32],
        ).unwrap();
        let cx = Cx::for_testing();
        let bytes: Vec<u8> = (0_u8..=255).cycle().take(config.max_message_size).collect();
        tx.next_message_id = Some(u64::MAX);
        block_on(tx.reserve(&cx)).unwrap().abort();
        assert_eq!(block_on(tx.send(&cx, &bytes)), Ok(u64::MAX));
        assert_eq!(block_on(rx.recv(&cx)), Ok(bytes));
        assert_eq!(tx.next_message_id, None);
        assert_eq!(
            block_on(tx.send(&cx, b"cannot wrap to zero")),
            Err(AuthenticatedEcError::MessageIdExhausted)
        );
        assert!(rx.rx.is_empty());
    }

    #[test]
    fn authenticated_channel_commit_retires_id_before_receiver_wake_panics() {
        use futures_lite::future::block_on;
        use std::future::Future;
        use std::sync::Arc;
        use std::task::{Context, Poll, Wake, Waker};

        struct PanicWake;
        impl Wake for PanicWake {
            fn wake(self: Arc<Self>) {
                panic!("receiver wake after authenticated publication");
            }
        }

        let (mut tx, mut rx) = authenticated_pair(1);
        let cx = Cx::for_testing();
        let waker = Waker::from(Arc::new(PanicWake));
        let mut poll_cx = Context::from_waker(&waker);
        let mut recv = Box::pin(rx.recv(&cx));
        assert!(recv.as_mut().poll(&mut poll_cx).is_pending());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            block_on(tx.send(&cx, b"committed before panic"))
        })).is_err());
        assert_eq!(tx.next_message_id, Some(1));
        let mut no_wake = Context::from_waker(Waker::noop());
        assert!(matches!(
            recv.as_mut().poll(&mut no_wake),
            Poll::Ready(Ok(bytes)) if bytes == b"committed before panic"
        ));
        drop(recv);
        assert_eq!(block_on(tx.send(&cx, b"next id")), Ok(1));
        assert_eq!(block_on(rx.recv(&cx)).unwrap(), b"next id");
    }

    #[test]
    fn authenticated_channel_checked_obligations_settle_on_every_exit() {
        use futures_lite::future::block_on;
        use crate::runtime::obligation_mailbox::ObligationAdmissionError;
        use crate::types::Budget;
        use std::sync::Arc;

        for limit in [0, 1] {
            let mut lab = crate::lab::LabRuntime::new(
                crate::lab::LabConfig::new(0xec_c0de).max_steps(128),
            );
            let root = lab.state.create_root_region(Budget::INFINITE);
            assert!(lab.state.set_region_limits(root, crate::record::RegionLimits {
                max_obligations: Some(limit),
                ..crate::record::RegionLimits::UNLIMITED
            }));
            let (task, mut handle) = lab.state.create_task(root, Budget::INFINITE, async {}).unwrap();
            let cx = lab.state.task(task).unwrap().cx.clone().unwrap();
            let mailbox = Arc::clone(lab.state.obligation_gateway().unwrap().mailbox());
            let (mut tx, mut rx) = authenticated_pair(1);
            if limit == 0 {
                assert!(matches!(
                    block_on(tx.reserve(&cx)),
                    Err(AuthenticatedEcError::Admission(
                        ObligationAdmissionError::LimitReached { limit: 0, live: 0 }
                    ))
                ));
            } else {
                let permit = block_on(tx.reserve(&cx)).unwrap();
                let (other, _other_rx) = mpsc::channel::<u8>(1);
                assert!(matches!(
                    other.try_reserve_checked(&cx),
                    Err(mpsc::CheckedSendError::Admission {
                        error: ObligationAdmissionError::LimitReached { limit: 1, live: 1 }, ..
                    })
                ));
                drop(permit);
                block_on(tx.reserve(&cx)).unwrap().abort();
                let oversized = vec![0; tx.config.max_message_size + 1];
                assert!(block_on(tx.reserve(&cx)).unwrap().send(&oversized).is_err());
                assert!(block_on(tx.reserve(&cx))
                    .unwrap()
                    .send_value(&"x".repeat(oversized.len()))
                    .is_err());
                assert_eq!(block_on(tx.send(&cx, b"first")), Ok(0));
                assert_eq!(block_on(rx.recv(&cx)).unwrap(), b"first");
                assert_eq!(block_on(tx.send(&cx, b"same-poll quota reuse")), Ok(1));
                assert_eq!(block_on(rx.recv(&cx)).unwrap(), b"same-poll quota reuse");
            }
            assert_eq!(rx.rx.telemetry_snapshot(6).reserved_uncommitted_obligations, 0);
            assert!(rx.rx.is_empty());
            lab.scheduler.lock().schedule(task, 0);
            let report = lab.run_until_quiescent_with_report();
            assert!(report.oracle_report.all_passed(), "{:?}", report.oracle_report.failures());
            assert!(report.invariant_violations.is_empty());
            assert!(handle.try_join().unwrap().is_some());
            let stats = mailbox.stats();
            assert_eq!(stats.reserved, if limit == 0 { 0 } else { 6 });
            assert_eq!(stats.committed, if limit == 0 { 0 } else { 2 });
            assert_eq!(stats.aborted, if limit == 0 { 0 } else { 4 });
            assert_eq!(stats.posted, stats.applied);
            assert_eq!(stats.leaked, 0);
            assert_eq!(mailbox.open_tickets(), 0);
            assert_eq!(lab.state.pending_obligation_count(), 0);
            assert_eq!(lab.state.leak_count(), 0);
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn authenticated_channel_native_parked_send_preserves_cancel_result_and_quiescence() {
        use std::future::Future;
        use std::time::{Duration, Instant};

        for sharded in [false, true] {
            let builder = if sharded {
                crate::runtime::RuntimeBuilder::multi_thread()
                    .worker_threads(2)
                    .with_sharded_state(true)
            } else {
                crate::runtime::RuntimeBuilder::current_thread()
            };
            let runtime = builder.root_region_limits(crate::record::RegionLimits {
                max_obligations: Some(1),
                ..crate::record::RegionLimits::UNLIMITED
            }).build().unwrap();
            runtime.block_on(runtime.handle().spawn(async move {
                let cx = Cx::current().expect("native task context");
                let (mut tx, mut rx) = authenticated_pair(1);
                assert_eq!(tx.send(&cx, b"committed").await, Ok(0));
                let mut child = cx.spawn(move |child_cx| async move {
                    let input = b"cancelled input remains owned".to_vec();
                    let result = tx.send(&child_cx, &input).await;
                    (result, tx, input)
                }).unwrap();
                let started = Instant::now();
                while rx.rx.telemetry_snapshot(7).send_waiter_count != 1 {
                    assert!(started.elapsed() < Duration::from_secs(5), "send must reach capacity wait");
                    crate::runtime::yield_now().await;
                }
                assert_eq!(rx.rx.len(), 1, "capacity stays full until the child is cancelled");
                child.abort();
                let joined = {
                    let mut joining = Box::pin(child.join(&cx));
                    std::future::poll_fn(|poll_cx| {
                        let result = joining.as_mut().poll(poll_cx);
                        if result.is_pending() {
                            assert!(
                                started.elapsed() < Duration::from_secs(5),
                                "cancelled sender must retire"
                            );
                            poll_cx.waker().wake_by_ref();
                        }
                        result
                    }).await
                };
                let (result, mut tx, input) =
                    joined.expect("acknowledged cancellation preserves typed result");
                assert_eq!(result, Err(AuthenticatedEcError::Message(EcError::Cancelled)));
                assert_eq!(input, b"cancelled input remains owned");
                let settled = rx.rx.telemetry_snapshot(7);
                assert_eq!(settled.send_waiter_count, 0);
                assert_eq!(settled.reserved_uncommitted_obligations, 0);
                assert_eq!(rx.recv(&cx).await.unwrap(), b"committed");
                assert_eq!(tx.send(&cx, b"after cancellation").await, Ok(1));
                assert_eq!(rx.recv(&cx).await.unwrap(), b"after cancellation");
            }));
            assert_eq!(
                runtime.drain_root_region(Duration::from_secs(5)),
                crate::runtime::RootDrainOutcome::Quiescent,
            );
            assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
            assert!(runtime.is_quiescent());
        }
    }
