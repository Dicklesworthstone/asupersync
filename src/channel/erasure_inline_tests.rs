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
