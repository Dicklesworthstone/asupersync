    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::encoding::EncodingPipeline;
    use crate::types::resource::{PoolConfig, SymbolPool};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn pool() -> SymbolPool {
        SymbolPool::new(PoolConfig {
            symbol_size: 256,
            initial_size: 64,
            max_size: 64,
            allow_growth: false,
            growth_increment: 0,
        })
    }

    fn encoding_config() -> crate::config::EncodingConfig {
        crate::config::EncodingConfig {
            symbol_size: 256,
            max_block_size: 1024,
            repair_overhead: 1.05,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        }
    }

    fn decoder_with_params(
        config: &crate::config::EncodingConfig,
        object_id: ObjectId,
        data_len: usize,
        repair_overhead: f64,
        min_overhead: usize,
    ) -> DecodingPipeline {
        let mut decoder = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            repair_overhead,
            min_overhead,
            max_buffered_symbols: 8192,
            block_timeout: Duration::from_secs(30),
            verify_auth: false,
        });
        let symbols_per_block = (data_len.div_ceil(usize::from(config.symbol_size))) as u16;
        decoder
            .set_object_params(ObjectParams::new(
                object_id,
                data_len as u64,
                config.symbol_size,
                1,
                symbols_per_block,
            ))
            .expect("params");
        decoder
    }

    #[test]
    fn missing_source_symbols_reports_absent_source_esis() {
        init_test("missing_source_symbols_reports_absent_source_esis");
        let config = encoding_config();
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id = ObjectId::new_for_test(101);
        let data = vec![7u8; 768];
        let mut decoder = decoder_with_params(&config, object_id, data.len(), 1.0, 0);

        for encoded in encoder.encode_with_repair(object_id, &data, 0) {
            let symbol = encoded.expect("encode").into_symbol();
            if symbol.esi() == 1 {
                continue;
            }
            decoder
                .feed(AuthenticatedSymbol::new_unauthenticated(symbol))
                .expect("feed");
        }

        assert_eq!(
            decoder.missing_source_symbols(0),
            vec![MissingSourceSymbol { sbn: 0, esi: 1 }]
        );
        assert_eq!(
            decoder.missing_source_symbols(1),
            vec![MissingSourceSymbol { sbn: 0, esi: 1 }]
        );
    }

    #[test]
    fn decode_roundtrip_sources_only() {
        init_test("decode_roundtrip_sources_only");
        let config = encoding_config();
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id = ObjectId::new_for_test(1);
        let data = vec![42u8; 512];
        let symbols: Vec<Symbol> = encoder
            .encode_with_repair(object_id, &data, 0)
            .map(|res| res.unwrap().into_symbol())
            .collect();

        let mut decoder = decoder_with_params(&config, object_id, data.len(), 1.0, 0);

        for symbol in symbols {
            let auth = AuthenticatedSymbol::from_parts(
                symbol,
                crate::security::tag::AuthenticationTag::zero(),
            );
            let _ = decoder.feed(auth).unwrap();
        }

        let decoded_data = decoder.into_data().expect("decoded");
        let ok = decoded_data == data;
        crate::assert_with_log!(ok, "decoded data", data, decoded_data);
        crate::test_complete!("decode_roundtrip_sources_only");
    }

    #[test]
    fn decode_roundtrip_out_of_order() {
        init_test("decode_roundtrip_out_of_order");
        let config = encoding_config();
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id = ObjectId::new_for_test(2);
        let data = vec![7u8; 768];
        let mut symbols: Vec<Symbol> = encoder
            .encode_with_repair(object_id, &data, 2)
            .map(|res| res.expect("encode").into_symbol())
            .collect();

        symbols.reverse();

        let mut decoder =
            decoder_with_params(&config, object_id, data.len(), config.repair_overhead, 0);

        for symbol in symbols {
            let auth = AuthenticatedSymbol::from_parts(
                symbol,
                crate::security::tag::AuthenticationTag::zero(),
            );
            let _ = decoder.feed(auth).expect("feed");
        }

        let decoded_data = decoder.into_data().expect("decoded");
        let ok = decoded_data == data;
        crate::assert_with_log!(ok, "decoded data", data, decoded_data);
        crate::test_complete!("decode_roundtrip_out_of_order");
    }

    #[test]
    fn reject_wrong_object_id() {
        init_test("reject_wrong_object_id");
        let config = encoding_config();
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id_a = ObjectId::new_for_test(10);
        let object_id_b = ObjectId::new_for_test(11);
        let data = vec![1u8; 128];

        let mut decoder =
            decoder_with_params(&config, object_id_a, data.len(), config.repair_overhead, 0);

        let symbol_b = encoder
            .encode_with_repair(object_id_b, &data, 0)
            .next()
            .expect("symbol")
            .expect("encode")
            .into_symbol();
        let auth = AuthenticatedSymbol::from_parts(
            symbol_b,
            crate::security::tag::AuthenticationTag::zero(),
        );

        let result = decoder.feed(auth).expect("feed");
        let expected = SymbolAcceptResult::Rejected(RejectReason::WrongObjectId);
        let ok = result == expected;
        crate::assert_with_log!(ok, "wrong object id", expected, result);
        crate::test_complete!("reject_wrong_object_id");
    }

    #[test]
    fn reject_symbol_size_mismatch() {
        init_test("reject_symbol_size_mismatch");
        let config = encoding_config();
        let mut decoder = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            repair_overhead: config.repair_overhead,
            min_overhead: 0,
            max_buffered_symbols: 8192,
            block_timeout: Duration::from_secs(30),
            verify_auth: false,
        });

        let symbol = Symbol::new(
            SymbolId::new(ObjectId::new_for_test(20), 0, 0),
            vec![0u8; 8],
            SymbolKind::Source,
        );
        let auth = AuthenticatedSymbol::from_parts(
            symbol,
            crate::security::tag::AuthenticationTag::zero(),
        );
        let result = decoder.feed(auth).expect("feed");
        let expected = SymbolAcceptResult::Rejected(RejectReason::SymbolSizeMismatch);
        let ok = result == expected;
        crate::assert_with_log!(ok, "symbol size mismatch", expected, result);
        crate::test_complete!("reject_symbol_size_mismatch");
    }

    #[test]
    fn reject_invalid_metadata_esi_out_of_range() {
        init_test("reject_invalid_metadata_esi_out_of_range");
        let mut decoder = DecodingPipeline::new(DecodingConfig {
            symbol_size: 8,
            max_block_size: 8,
            repair_overhead: 1.0,
            min_overhead: 0,
            max_buffered_symbols: 8192,
            block_timeout: Duration::from_secs(30),
            verify_auth: false,
        });
        let object_id = ObjectId::new_for_test(21);
        decoder
            .set_object_params(ObjectParams::new(object_id, 8, 8, 1, 1))
            .expect("params");

        let symbol = Symbol::new(
            SymbolId::new(object_id, 0, 1),
            vec![0u8; 8],
            SymbolKind::Source,
        );
        let auth = AuthenticatedSymbol::from_parts(
            symbol,
            crate::security::tag::AuthenticationTag::zero(),
        );

        let result = decoder.feed(auth).expect("feed");
        let expected = SymbolAcceptResult::Rejected(RejectReason::InvalidMetadata);
        let ok = result == expected;
        crate::assert_with_log!(ok, "invalid metadata", expected, result);
        crate::test_complete!("reject_invalid_metadata_esi_out_of_range");
    }

    #[test]
    fn auto_buffer_limit_scales_per_block_cap_to_k() {
        init_test("auto_buffer_limit_scales_per_block_cap_to_k");
        // A single block with K > the fixed 8192 default. With
        // max_buffered_symbols == 0, set_object_params must size the per-block
        // accept cap to cover K (configure_auto_buffer_limit); with the fixed
        // default it stays at 8192 and would reject legitimately-received
        // symbols past 8192 so the block never decodes (the receive_object /
        // erasure / recovery class of bug).
        let big_k: u16 = 16_384;
        let object_size = u64::from(big_k) * 8;
        let max_block_size = usize::try_from(object_size).expect("fits usize");
        let object_id = ObjectId::new_for_test(99);

        let mut auto = DecodingPipeline::new(DecodingConfig {
            symbol_size: 8,
            max_block_size,
            repair_overhead: 1.05,
            min_overhead: 0,
            max_buffered_symbols: 0,
            block_timeout: Duration::from_secs(30),
            verify_auth: false,
        });
        auto.set_object_params(ObjectParams::new(object_id, object_size, 8, 1, big_k))
            .expect("params");
        let auto_cap = auto.block_accept_cap();
        crate::assert_with_log!(
            auto_cap >= usize::from(big_k),
            "auto-sized per-block cap covers K",
            usize::from(big_k),
            auto_cap
        );

        let mut fixed = DecodingPipeline::new(DecodingConfig {
            symbol_size: 8,
            max_block_size,
            repair_overhead: 1.05,
            min_overhead: 0,
            max_buffered_symbols: 8192,
            block_timeout: Duration::from_secs(30),
            verify_auth: false,
        });
        fixed
            .set_object_params(ObjectParams::new(object_id, object_size, 8, 1, big_k))
            .expect("params");
        let fixed_cap = fixed.block_accept_cap();
        crate::assert_with_log!(
            fixed_cap == 8192,
            "fixed default does not scale with K (the bug)",
            8192,
            fixed_cap
        );

        crate::test_complete!("auto_buffer_limit_scales_per_block_cap_to_k");
    }

    #[test]
    fn reject_invalid_metadata_repair_esi_overflow_without_panicking() {
        init_test("reject_invalid_metadata_repair_esi_overflow_without_panicking");
        let mut decoder = DecodingPipeline::new(DecodingConfig {
            symbol_size: 8,
            max_block_size: 16,
            repair_overhead: 1.0,
            min_overhead: 0,
            max_buffered_symbols: 8192,
            block_timeout: Duration::from_secs(30),
            verify_auth: false,
        });
        let object_id = ObjectId::new_for_test(22);
        decoder
            .set_object_params(ObjectParams::new(object_id, 16, 8, 1, 2))
            .expect("params");

        let source = Symbol::new(
            SymbolId::new(object_id, 0, 0),
            vec![0x11; 8],
            SymbolKind::Source,
        );
        let repair = Symbol::new(
            SymbolId::new(object_id, 0, u32::MAX),
            vec![0x22; 8],
            SymbolKind::Repair,
        );

        let first = decoder
            .feed(AuthenticatedSymbol::from_parts(
                source,
                crate::security::tag::AuthenticationTag::zero(),
            ))
            .expect("feed source");
        let first_ok = matches!(first, SymbolAcceptResult::Accepted { .. });
        crate::assert_with_log!(first_ok, "source accepted before threshold", true, first_ok);

        let result = decoder
            .feed(AuthenticatedSymbol::from_parts(
                repair,
                crate::security::tag::AuthenticationTag::zero(),
            ))
            .expect("feed repair overflow");
        let expected = SymbolAcceptResult::Rejected(RejectReason::InvalidMetadata);
        let ok = result == expected;
        crate::assert_with_log!(
            ok,
            "repair overflow rejected as invalid metadata",
            expected,
            result
        );

        crate::test_complete!("reject_invalid_metadata_repair_esi_overflow_without_panicking");
    }

    #[test]
    fn out_of_range_esis_do_not_stop_a_block_recovering_from_repair() {
        init_test("out_of_range_esis_do_not_stop_a_block_recovering_from_repair");
        // One block of K = 2 four-byte symbols. Source symbol 1 is lost, so
        // the block can only decode with a repair symbol.
        let config = crate::config::EncodingConfig {
            symbol_size: 4,
            max_block_size: 8,
            repair_overhead: 1.0,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        };
        // The geometry, data and seed of deferred_streaming_feed_finishes_via_decode_job,
        // which decodes from source symbol 0 and the first repair symbol.
        let object_id = ObjectId::new_for_test(113);
        let data = b"ABCDEFGH".to_vec();
        let encoder_pool = SymbolPool::new(PoolConfig {
            symbol_size: config.symbol_size,
            initial_size: 16,
            max_size: 16,
            allow_growth: false,
            growth_increment: 0,
        });
        let mut encoder = EncodingPipeline::new(config.clone(), encoder_pool);
        let mut source_zero = None;
        let mut repair = None;
        for encoded in encoder.encode_single_block_with_repair(object_id, 0, &data, 2) {
            let symbol = encoded.expect("encode").into_symbol();
            match symbol.kind() {
                SymbolKind::Source if symbol.esi() == 0 => source_zero = Some(symbol),
                SymbolKind::Repair if repair.is_none() => repair = Some(symbol),
                _ => {}
            }
        }

        let mut decoder = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            repair_overhead: 1.0,
            min_overhead: 0,
            max_buffered_symbols: 8192,
            block_timeout: Duration::from_secs(30),
            verify_auth: false,
        });
        decoder
            .set_object_params(ObjectParams::new(
                object_id,
                data.len() as u64,
                config.symbol_size,
                1,
                2,
            ))
            .expect("set params");
        let mut feed = |symbol: Symbol| {
            decoder
                .feed(AuthenticatedSymbol::new_unauthenticated(symbol))
                .expect("feed")
        };

        // A source ESI beyond K, a repair ESI below K and a repair ESI past
        // the decoder's ceiling: no decode of this block can use them.
        let out_of_range: Vec<SymbolAcceptResult> = [
            (5, SymbolKind::Source),
            (1, SymbolKind::Repair),
            (MAX_ALLOWED_ESI + 1, SymbolKind::Repair),
        ]
        .into_iter()
        .map(|(esi, kind)| {
            feed(Symbol::new(
                SymbolId::new(object_id, 0, esi),
                vec![0xEE; 4],
                kind,
            ))
        })
        .collect();

        let first = feed(source_zero.expect("source zero"));
        let first_ok = matches!(first, SymbolAcceptResult::Accepted { .. });
        crate::assert_with_log!(first_ok, "source symbol 0 accepted", true, first);
        let recovered = feed(repair.expect("repair symbol"));
        let expected = SymbolAcceptResult::BlockComplete {
            block_sbn: 0,
            data: data.clone(),
        };
        crate::assert_with_log!(
            recovered == expected,
            "the block recovers its lost source symbol from the repair symbol",
            expected,
            recovered
        );

        let refused = SymbolAcceptResult::Rejected(RejectReason::InvalidMetadata);
        let all_refused = out_of_range.iter().all(|result| *result == refused);
        crate::assert_with_log!(
            all_refused,
            "out-of-range ESIs are refused when they arrive",
            refused,
            out_of_range
        );

        crate::test_complete!("out_of_range_esis_do_not_stop_a_block_recovering_from_repair");
    }

    #[test]
    fn reject_invalid_metadata_out_of_layout_sbn_without_buffering() {
        init_test("reject_invalid_metadata_out_of_layout_sbn_without_buffering");
        let mut decoder = DecodingPipeline::new(DecodingConfig {
            symbol_size: 8,
            max_block_size: 8,
            repair_overhead: 1.0,
            min_overhead: 0,
            max_buffered_symbols: 8192,
            block_timeout: Duration::from_secs(30),
            verify_auth: false,
        });
        let object_id = ObjectId::new_for_test(23);
        decoder
            .set_object_params(ObjectParams::new(object_id, 8, 8, 1, 1))
            .expect("params");

        let result = decoder
            .feed(AuthenticatedSymbol::from_parts(
                Symbol::new(
                    SymbolId::new(object_id, 1, 0),
                    vec![0x33; 8],
                    SymbolKind::Source,
                ),
                crate::security::tag::AuthenticationTag::zero(),
            ))
            .expect("feed out-of-layout block");
        let expected = SymbolAcceptResult::Rejected(RejectReason::InvalidMetadata);
        let ok = result == expected;
        crate::assert_with_log!(ok, "out-of-layout sbn rejected", expected, result);

        let progress = decoder.progress();
        crate::assert_with_log!(
            progress.symbols_received == 0,
            "rejected out-of-layout block must not advance buffered symbol count",
            0,
            progress.symbols_received
        );
        crate::assert_with_log!(
            decoder.block_status(1).is_none(),
            "rejected out-of-layout block must not create block state",
            true,
            decoder.block_status(1).is_some()
        );

        crate::test_complete!("reject_invalid_metadata_out_of_layout_sbn_without_buffering");
    }

    #[test]
    fn duplicate_symbol_before_decode() {
        init_test("duplicate_symbol_before_decode");
        let config = encoding_config();
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id = ObjectId::new_for_test(30);
        // Ensure K > 1 so the first symbol cannot complete the block decode.
        let data = vec![9u8; 512];

        let symbol = encoder
            .encode_with_repair(object_id, &data, 0)
            .next()
            .expect("symbol")
            .expect("encode")
            .into_symbol();

        let mut decoder = decoder_with_params(&config, object_id, data.len(), 1.5, 1);

        let first = decoder
            .feed(AuthenticatedSymbol::from_parts(
                symbol.clone(),
                crate::security::tag::AuthenticationTag::zero(),
            ))
            .expect("feed");
        let accepted = matches!(
            first,
            SymbolAcceptResult::Accepted { .. } | SymbolAcceptResult::DecodingStarted { .. }
        );
        crate::assert_with_log!(accepted, "first accepted", true, accepted);

        let second = decoder
            .feed(AuthenticatedSymbol::from_parts(
                symbol,
                crate::security::tag::AuthenticationTag::zero(),
            ))
            .expect("feed");
        let expected = SymbolAcceptResult::Duplicate;
        let ok = second == expected;
        crate::assert_with_log!(ok, "second duplicate", expected, second);
        crate::test_complete!("duplicate_symbol_before_decode");
    }

    #[test]
    fn into_data_reports_insufficient_symbols() {
        init_test("into_data_reports_insufficient_symbols");
        let config = encoding_config();
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id = ObjectId::new_for_test(40);
        let data = vec![5u8; 512];

        let mut decoder =
            decoder_with_params(&config, object_id, data.len(), config.repair_overhead, 0);

        let symbol = encoder
            .encode_with_repair(object_id, &data, 0)
            .next()
            .expect("symbol")
            .expect("encode")
            .into_symbol();
        let auth = AuthenticatedSymbol::from_parts(
            symbol,
            crate::security::tag::AuthenticationTag::zero(),
        );
        let _ = decoder.feed(auth).expect("feed");

        let err = decoder
            .into_data()
            .expect_err("expected insufficient symbols");
        let insufficient = matches!(err, DecodingError::InsufficientSymbols { .. });
        crate::assert_with_log!(insufficient, "insufficient symbols", true, insufficient);
        crate::test_complete!("into_data_reports_insufficient_symbols");
    }

    // ---- DecodingError Display ----

    #[test]
    fn decoding_error_display_authentication_failed() {
        let err = DecodingError::AuthenticationFailed {
            symbol_id: SymbolId::new(ObjectId::new_for_test(1), 0, 0),
        };
        let msg = err.to_string();
        assert!(msg.contains("authentication failed"), "{msg}");
    }

    #[test]
    fn decoding_error_display_insufficient_symbols() {
        let err = DecodingError::InsufficientSymbols {
            received: 3,
            needed: 10,
        };
        assert_eq!(err.to_string(), "insufficient symbols: have 3, need 10");
    }

    #[test]
    fn decoding_error_display_matrix_inversion() {
        let err = DecodingError::MatrixInversionFailed {
            reason: "rank deficient".into(),
        };
        assert_eq!(err.to_string(), "matrix inversion failed: rank deficient");
    }

    #[test]
    fn decoding_error_display_block_timeout() {
        let err = DecodingError::BlockTimeout {
            sbn: 2,
            elapsed: Duration::from_millis(1500),
        };
        let msg = err.to_string();
        assert!(msg.contains("block timeout"), "{msg}");
        assert!(msg.contains("1.5"), "{msg}");
    }

    #[test]
    fn decoding_error_display_inconsistent_metadata() {
        let err = DecodingError::InconsistentMetadata {
            sbn: 0,
            details: "mismatch".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("inconsistent block metadata"), "{msg}");
        assert!(msg.contains("mismatch"), "{msg}");
    }

    #[test]
    fn decoding_error_display_symbol_size_mismatch() {
        let err = DecodingError::SymbolSizeMismatch {
            expected: 256,
            actual: 128,
        };
        assert_eq!(
            err.to_string(),
            "symbol size mismatch: expected 256, got 128"
        );
    }

    // ---- DecodingError -> Error conversion ----

    #[test]
    fn decoding_error_into_error_auth() {
        let err = DecodingError::AuthenticationFailed {
            symbol_id: SymbolId::new(ObjectId::new_for_test(1), 0, 0),
        };
        let error: crate::error::Error = err.into();
        assert_eq!(error.kind(), crate::error::ErrorKind::CorruptedSymbol);
    }

    #[test]
    fn decoding_error_into_error_insufficient() {
        let err = DecodingError::InsufficientSymbols {
            received: 1,
            needed: 5,
        };
        let error: crate::error::Error = err.into();
        assert_eq!(error.kind(), crate::error::ErrorKind::InsufficientSymbols);
    }

    #[test]
    fn decoding_error_into_error_matrix() {
        let err = DecodingError::MatrixInversionFailed {
            reason: "singular".into(),
        };
        let error: crate::error::Error = err.into();
        assert_eq!(error.kind(), crate::error::ErrorKind::DecodingFailed);
    }

    #[test]
    fn decoding_error_into_error_timeout() {
        let err = DecodingError::BlockTimeout {
            sbn: 0,
            elapsed: Duration::from_secs(30),
        };
        let error: crate::error::Error = err.into();
        assert_eq!(error.kind(), crate::error::ErrorKind::ThresholdTimeout);
    }

    #[test]
    fn decoding_error_into_error_inconsistent() {
        let err = DecodingError::InconsistentMetadata {
            sbn: 1,
            details: "x".into(),
        };
        let error: crate::error::Error = err.into();
        assert_eq!(error.kind(), crate::error::ErrorKind::DecodingFailed);
    }

    #[test]
    fn decoding_error_into_error_size_mismatch() {
        let err = DecodingError::SymbolSizeMismatch {
            expected: 256,
            actual: 64,
        };
        let error: crate::error::Error = err.into();
        assert_eq!(error.kind(), crate::error::ErrorKind::DecodingFailed);
    }

    // ---- RejectReason ----

    #[test]
    fn reject_reason_variants_are_eq() {
        assert_eq!(RejectReason::WrongObjectId, RejectReason::WrongObjectId);
        assert_ne!(
            RejectReason::AuthenticationFailed,
            RejectReason::SymbolSizeMismatch
        );
    }

    #[test]
    fn reject_reason_debug() {
        let dbg = format!("{:?}", RejectReason::BlockAlreadyDecoded);
        assert_eq!(dbg, "BlockAlreadyDecoded");
    }

    // ---- SymbolAcceptResult ----

    #[test]
    fn symbol_accept_result_accepted_eq() {
        let a = SymbolAcceptResult::Accepted {
            received: 3,
            needed: 5,
        };
        let b = SymbolAcceptResult::Accepted {
            received: 3,
            needed: 5,
        };
        assert_eq!(a, b);
    }

    #[test]
    fn symbol_accept_result_duplicate_eq() {
        assert_eq!(SymbolAcceptResult::Duplicate, SymbolAcceptResult::Duplicate);
    }

    #[test]
    fn symbol_accept_result_rejected_eq() {
        let a = SymbolAcceptResult::Rejected(RejectReason::MemoryLimitReached);
        let b = SymbolAcceptResult::Rejected(RejectReason::MemoryLimitReached);
        assert_eq!(a, b);
    }

    #[test]
    fn symbol_accept_result_variants_ne() {
        assert_ne!(
            SymbolAcceptResult::Duplicate,
            SymbolAcceptResult::Rejected(RejectReason::WrongObjectId)
        );
    }

    // ---- DecodingConfig default ----

    #[test]
    fn decoding_config_default_values() {
        let cfg = DecodingConfig::default();
        assert_eq!(cfg.symbol_size, 256);
        assert_eq!(cfg.max_block_size, 1024 * 1024);
        assert!((cfg.repair_overhead - 1.05).abs() < f64::EPSILON);
        assert_eq!(cfg.min_overhead, 0);
        assert_eq!(cfg.max_buffered_symbols, 8192);
        assert_eq!(cfg.block_timeout, Duration::from_secs(30));
        assert!(cfg.verify_auth);
    }

    #[test]
    fn required_symbols_uses_total_factor_and_minimum_extra_floor() {
        assert_eq!(required_symbols(0, 1.05, 3), 0);
        assert_eq!(required_symbols(10, 1.05, 3), 13);
        assert_eq!(required_symbols(10, 1.5, 1), 15);
        assert_eq!(required_symbols(10, 0.5, 0), 10);
        assert_eq!(required_symbols(10, f64::NAN, 3), 13);
        assert_eq!(required_symbols(10, f64::INFINITY, 3), usize::MAX);
    }

    // ---- BlockStateKind ----

    #[test]
    fn block_state_kind_eq_and_debug() {
        assert_eq!(BlockStateKind::Collecting, BlockStateKind::Collecting);
        assert_ne!(BlockStateKind::Collecting, BlockStateKind::Decoded);
        assert_eq!(format!("{:?}", BlockStateKind::Failed), "Failed");
        assert_eq!(format!("{:?}", BlockStateKind::Decoding), "Decoding");
    }

    // ---- DecodingPipeline construction ----

    #[test]
    fn pipeline_new_starts_empty() {
        let pipeline = DecodingPipeline::new(DecodingConfig::default());
        let progress = pipeline.progress();
        assert_eq!(progress.blocks_complete, 0);
        assert_eq!(progress.symbols_received, 0);
    }

    #[test]
    fn pipeline_set_object_params_rejects_mismatched_symbol_size() {
        let mut pipeline = DecodingPipeline::new(DecodingConfig {
            symbol_size: 256,
            ..DecodingConfig::without_auth()
        });
        let params = ObjectParams::new(ObjectId::new_for_test(1), 1024, 128, 1, 8);
        let err = pipeline.set_object_params(params).unwrap_err();
        assert!(matches!(err, DecodingError::SymbolSizeMismatch { .. }));
    }

    #[test]
    fn pipeline_set_object_params_rejects_inconsistent_object_id() {
        let config = encoding_config();
        let oid1 = ObjectId::new_for_test(1);
        let oid2 = ObjectId::new_for_test(2);

        let mut pipeline = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            ..DecodingConfig::without_auth()
        });
        pipeline
            .set_object_params(ObjectParams::new(oid1, 512, config.symbol_size, 1, 2))
            .expect("first set_object_params");
        let err = pipeline
            .set_object_params(ObjectParams::new(oid2, 512, config.symbol_size, 1, 2))
            .unwrap_err();
        assert!(matches!(err, DecodingError::InconsistentMetadata { .. }));
    }

    #[test]
    fn pipeline_set_object_params_same_id_is_ok() {
        let config = encoding_config();
        let oid = ObjectId::new_for_test(1);

        let mut pipeline = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            ..DecodingConfig::without_auth()
        });
        pipeline
            .set_object_params(ObjectParams::new(oid, 512, config.symbol_size, 1, 2))
            .expect("first");
        pipeline
            .set_object_params(ObjectParams::new(oid, 512, config.symbol_size, 1, 2))
            .expect("second with same id should succeed");
    }

    #[test]
    fn pipeline_indexes_block_plans_by_sbn() {
        let object_id = ObjectId::new_for_test(3);
        let mut pipeline = DecodingPipeline::new(DecodingConfig {
            symbol_size: 8,
            max_block_size: 16,
            ..DecodingConfig::without_auth()
        });
        pipeline
            .set_object_params(ObjectParams::new(object_id, 40, 8, 3, 2))
            .expect("multi-block params");

        assert_eq!(pipeline.block_plan_by_sbn[0], Some(0));
        assert_eq!(pipeline.block_plan_by_sbn[1], Some(1));
        assert_eq!(pipeline.block_plan_by_sbn[2], Some(2));
        assert_eq!(pipeline.block_plan(2).map(|plan| plan.len), Some(8));
        assert!(pipeline.block_plan(3).is_none());
    }

    #[test]
    fn pipeline_set_object_params_rejects_k_above_rfc_systematic_max() {
        // br-asupersync-qokghh: a misconfigured DecodingConfig (here:
        // symbol_size=1 with default max_block_size=1MB) drives K above
        // the RFC 6330 systematic-index table maximum (56,403). Without
        // the validation guard, decode_block would later panic via
        // SystematicParams::for_source_block; with the guard the error
        // is surfaced as a typed InconsistentMetadata at the validation
        // boundary so callers can react instead of crashing the
        // decoder.
        let object_id = ObjectId::new_for_test(0xDE);
        let mut pipeline = DecodingPipeline::new(DecodingConfig {
            symbol_size: 1,
            max_block_size: 1024 * 1024,
            ..DecodingConfig::without_auth()
        });
        // 65_000 bytes / 1-byte-symbols = 65_000 symbols/block — exceeds
        // the RFC max of 56,403.
        let err = pipeline
            .set_object_params(ObjectParams::new(object_id, 65_000, 1, 1, 65_000))
            .unwrap_err();
        assert!(
            matches!(err, DecodingError::InconsistentMetadata { .. }),
            "expected InconsistentMetadata, got {err:?}"
        );
        assert!(
            err.to_string().contains("RFC 6330 systematic-index table"),
            "expected RFC bound message, got: {err}"
        );
    }

    #[test]
    fn pipeline_set_object_params_rejects_declared_block_count_drift() {
        let config = encoding_config();
        let object_id = ObjectId::new_for_test(104);

        let mut pipeline = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            ..DecodingConfig::without_auth()
        });
        let err = pipeline
            .set_object_params(ObjectParams::new(object_id, 1536, config.symbol_size, 1, 4))
            .unwrap_err();
        assert!(matches!(err, DecodingError::InconsistentMetadata { .. }));
        assert!(
            err.to_string().contains("block count mismatch"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn pipeline_set_object_params_rejects_total_k_metadata_for_multi_block_object() {
        let config = encoding_config();
        let object_id = ObjectId::new_for_test(105);

        let mut pipeline = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            ..DecodingConfig::without_auth()
        });
        let err = pipeline
            .set_object_params(ObjectParams::new(object_id, 2048, config.symbol_size, 2, 8))
            .unwrap_err();
        assert!(matches!(err, DecodingError::InconsistentMetadata { .. }));
        assert!(
            err.to_string().contains("symbols_per_block mismatch"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn pipeline_set_object_params_failure_does_not_latch_object_identity() {
        let config = encoding_config();
        let invalid_object_id = ObjectId::new_for_test(106);
        let valid_object_id = ObjectId::new_for_test(107);

        let mut pipeline = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            ..DecodingConfig::without_auth()
        });
        let err = pipeline
            .set_object_params(ObjectParams::new(
                invalid_object_id,
                2048,
                config.symbol_size,
                2,
                8,
            ))
            .unwrap_err();
        assert!(matches!(err, DecodingError::InconsistentMetadata { .. }));

        pipeline
            .set_object_params(ObjectParams::new(
                valid_object_id,
                512,
                config.symbol_size,
                1,
                2,
            ))
            .expect("failed set_object_params must not poison object identity");
    }

    #[test]
    fn pipeline_set_object_params_accepts_empty_object_single_block_sentinel_metadata() {
        let config = encoding_config();
        let object_id = ObjectId::new_for_test(108);

        let mut pipeline = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            ..DecodingConfig::without_auth()
        });
        pipeline
            .set_object_params(ObjectParams::new(
                object_id,
                0,
                config.symbol_size,
                1,
                config
                    .max_block_size
                    .div_ceil(usize::from(config.symbol_size))
                    .try_into()
                    .expect("sentinel block K should fit in u16"),
            ))
            .expect("empty object sentinel metadata should be accepted");

        assert!(pipeline.is_complete());
        assert_eq!(pipeline.progress().blocks_total, Some(0));
        assert_eq!(
            pipeline.into_data().expect("empty object should decode"),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn pipeline_set_object_params_accepts_full_256_block_boundary() {
        let config = crate::config::EncodingConfig {
            symbol_size: 8,
            max_block_size: 8,
            ..encoding_config()
        };
        let object_id = ObjectId::new_for_test(109);

        let mut pipeline = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            ..DecodingConfig::without_auth()
        });
        pipeline
            .set_object_params(ObjectParams::new(
                object_id,
                u64::try_from(config.max_block_size * 256).expect("boundary object size fits u64"),
                config.symbol_size,
                256,
                1,
            ))
            .expect("256-block metadata boundary should be representable");

        assert_eq!(pipeline.progress().blocks_total, Some(256));
    }

    // ---- Gap tests ----

    #[test]
    fn feed_batch_returns_results_per_symbol() {
        init_test("feed_batch_returns_results_per_symbol");
        let config = encoding_config();
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id = ObjectId::new_for_test(100);
        let data = vec![0xAAu8; 768]; // 3 source symbols at 256 bytes each

        let symbols: Vec<AuthenticatedSymbol> = encoder
            .encode_with_repair(object_id, &data, 0)
            .map(|res| {
                AuthenticatedSymbol::from_parts(
                    res.unwrap().into_symbol(),
                    crate::security::tag::AuthenticationTag::zero(),
                )
            })
            .take(3)
            .collect();

        let mut decoder = decoder_with_params(&config, object_id, data.len(), 1.5, 1);

        let results = decoder.feed_batch(symbols.into_iter());
        let len = results.len();
        let expected_len = 3usize;
        crate::assert_with_log!(len == expected_len, "batch length", expected_len, len);
        for (i, r) in results.iter().enumerate() {
            let is_ok = r.is_ok();
            crate::assert_with_log!(is_ok, &format!("result[{i}] is Ok"), true, is_ok);
        }
        crate::test_complete!("feed_batch_returns_results_per_symbol");
    }

    #[test]
    fn skipped_verifications_count_only_inserted_symbols() {
        init_test("skipped_verifications_count_only_inserted_symbols");
        let config = encoding_config();
        let object_id = ObjectId::new_for_test(103);
        let mut decoder = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            verify_auth: false,
            ..DecodingConfig::without_auth()
        });
        decoder
            .set_object_params(ObjectParams::new(object_id, 512, config.symbol_size, 1, 2))
            .expect("set object params");

        let wrong_object = Symbol::new(
            SymbolId::new(ObjectId::new_for_test(104), 0, 0),
            vec![0u8; usize::from(config.symbol_size)],
            SymbolKind::Source,
        );
        let result = decoder
            .feed(AuthenticatedSymbol::from_parts(
                wrong_object,
                crate::security::tag::AuthenticationTag::zero(),
            ))
            .expect("wrong-object feed should not error");
        assert_eq!(
            result,
            SymbolAcceptResult::Rejected(RejectReason::WrongObjectId)
        );
        assert_eq!(decoder.skipped_verifications(), 0);

        let valid = Symbol::new(
            SymbolId::new(object_id, 0, 0),
            vec![1u8; usize::from(config.symbol_size)],
            SymbolKind::Source,
        );
        let result = decoder
            .feed(AuthenticatedSymbol::from_parts(
                valid.clone(),
                crate::security::tag::AuthenticationTag::zero(),
            ))
            .expect("valid feed should not error");
        assert!(matches!(result, SymbolAcceptResult::Accepted { .. }));
        assert_eq!(decoder.skipped_verifications(), 1);

        let result = decoder
            .feed(AuthenticatedSymbol::from_parts(
                valid,
                crate::security::tag::AuthenticationTag::zero(),
            ))
            .expect("duplicate feed should not error");
        assert_eq!(result, SymbolAcceptResult::Duplicate);
        assert_eq!(decoder.skipped_verifications(), 1);

        crate::test_complete!("skipped_verifications_count_only_inserted_symbols");
    }

    #[test]
    fn is_complete_false_without_params() {
        init_test("is_complete_false_without_params");
        let pipeline = DecodingPipeline::new(DecodingConfig::default());
        let complete = pipeline.is_complete();
        crate::assert_with_log!(!complete, "is_complete without params", false, complete);
        crate::test_complete!("is_complete_false_without_params");
    }

    #[test]
    fn is_complete_true_after_all_blocks_decoded() {
        init_test("is_complete_true_after_all_blocks_decoded");
        let config = encoding_config();
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id = ObjectId::new_for_test(101);
        let data = vec![42u8; 512];
        let symbols: Vec<Symbol> = encoder
            .encode_with_repair(object_id, &data, 0)
            .map(|res| res.unwrap().into_symbol())
            .collect();

        let mut decoder = decoder_with_params(&config, object_id, data.len(), 1.0, 0);

        for symbol in symbols {
            let auth = AuthenticatedSymbol::from_parts(
                symbol,
                crate::security::tag::AuthenticationTag::zero(),
            );
            let _ = decoder.feed(auth).unwrap();
        }

        let complete = decoder.is_complete();
        crate::assert_with_log!(complete, "is_complete after all blocks", true, complete);
        crate::test_complete!("is_complete_true_after_all_blocks_decoded");
    }

    #[test]
    fn progress_reports_blocks_total_after_params() {
        init_test("progress_reports_blocks_total_after_params");
        let config = encoding_config();
        let object_id = ObjectId::new_for_test(102);

        let mut pipeline = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: 1024,
            ..DecodingConfig::without_auth()
        });
        // data_len=512 < max_block_size=1024 => 1 block
        let k = (512usize).div_ceil(usize::from(config.symbol_size)) as u16;
        pipeline
            .set_object_params(ObjectParams::new(object_id, 512, config.symbol_size, 1, k))
            .expect("set params");

        let progress = pipeline.progress();
        let blocks_total = progress.blocks_total;
        let expected_blocks = Some(1usize);
        crate::assert_with_log!(
            blocks_total == expected_blocks,
            "blocks_total",
            expected_blocks,
            blocks_total
        );
        let estimate = progress.symbols_needed_estimate;
        let positive = estimate > 0;
        crate::assert_with_log!(positive, "symbols_needed_estimate > 0", true, positive);
        crate::test_complete!("progress_reports_blocks_total_after_params");
    }

    #[test]
    fn progress_symbols_needed_estimate_does_not_double_count_min_overhead() {
        init_test("progress_symbols_needed_estimate_does_not_double_count_min_overhead");
        let object_id = ObjectId::new_for_test(1020);
        let symbol_size = 256u16;
        let k = 10u16;
        let data_len = usize::from(symbol_size) * usize::from(k);

        let mut pipeline = DecodingPipeline::new(DecodingConfig {
            symbol_size,
            max_block_size: 4096,
            repair_overhead: 1.05,
            min_overhead: 3,
            max_buffered_symbols: 8192,
            block_timeout: Duration::from_secs(30),
            verify_auth: false,
        });
        pipeline
            .set_object_params(ObjectParams::new(
                object_id,
                data_len as u64,
                symbol_size,
                1,
                k,
            ))
            .expect("set params");

        let progress = pipeline.progress();
        assert_eq!(progress.blocks_total, Some(1));
        assert_eq!(progress.symbols_needed_estimate, 13);
        crate::test_complete!(
            "progress_symbols_needed_estimate_does_not_double_count_min_overhead"
        );
    }

    #[test]
    fn progress_symbols_needed_estimate_saturates_for_infinite_overhead() {
        init_test("progress_symbols_needed_estimate_saturates_for_infinite_overhead");
        let object_id = ObjectId::new_for_test(1021);
        let symbol_size = 256u16;
        let data_len = 2048usize;

        let mut pipeline = DecodingPipeline::new(DecodingConfig {
            symbol_size,
            max_block_size: 1024,
            repair_overhead: f64::INFINITY,
            min_overhead: 0,
            max_buffered_symbols: 8192,
            block_timeout: Duration::from_secs(30),
            verify_auth: false,
        });
        pipeline
            .set_object_params(ObjectParams::new(
                object_id,
                data_len as u64,
                symbol_size,
                2,
                4,
            ))
            .expect("set params");

        let progress = pipeline.progress();
        assert_eq!(progress.blocks_total, Some(2));
        assert_eq!(progress.symbols_needed_estimate, usize::MAX);
        crate::test_complete!("progress_symbols_needed_estimate_saturates_for_infinite_overhead");
    }

    #[test]
    fn block_status_none_for_unknown_block() {
        init_test("block_status_none_for_unknown_block");
        let config = encoding_config();
        let object_id = ObjectId::new_for_test(103);

        let mut pipeline = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            ..DecodingConfig::without_auth()
        });
        let k = (512usize).div_ceil(usize::from(config.symbol_size)) as u16;
        pipeline
            .set_object_params(ObjectParams::new(object_id, 512, config.symbol_size, 1, k))
            .expect("set params");

        let status = pipeline.block_status(99);
        let is_none = status.is_none();
        crate::assert_with_log!(is_none, "block_status(99) is None", true, is_none);
        crate::test_complete!("block_status_none_for_unknown_block");
    }

    #[test]
    fn block_status_collecting_after_partial_feed() {
        init_test("block_status_collecting_after_partial_feed");
        let config = encoding_config();
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id = ObjectId::new_for_test(104);
        let data = vec![0xBBu8; 512];

        let first_symbol = encoder
            .encode_with_repair(object_id, &data, 0)
            .next()
            .expect("symbol")
            .expect("encode")
            .into_symbol();

        // Use high overhead so 1 symbol doesn't trigger decode
        let mut decoder = decoder_with_params(&config, object_id, data.len(), 1.5, 1);

        let auth = AuthenticatedSymbol::from_parts(
            first_symbol,
            crate::security::tag::AuthenticationTag::zero(),
        );
        let _ = decoder.feed(auth).expect("feed");

        let status = decoder.block_status(0);
        let is_some = status.is_some();
        crate::assert_with_log!(is_some, "block_status(0) is Some", true, is_some);

        let status = status.unwrap();
        let state = status.state;
        let expected_state = BlockStateKind::Collecting;
        crate::assert_with_log!(
            state == expected_state,
            "state is Collecting",
            expected_state,
            state
        );
        let received = status.symbols_received;
        let expected_received = 1usize;
        crate::assert_with_log!(
            received == expected_received,
            "symbols_received",
            expected_received,
            received
        );
        // The cheap count used on per-symbol paths agrees with the status.
        let cheap = decoder.block_symbols_received(0);
        crate::assert_with_log!(
            cheap == Some(received),
            "block_symbols_received matches block_status",
            Some(received),
            cheap
        );
        let unknown = decoder.block_symbols_received(99);
        crate::assert_with_log!(unknown.is_none(), "unknown block", None::<usize>, unknown);
        let rank_is_available = status.rank.is_some();
        crate::assert_with_log!(rank_is_available, "rank available", true, rank_is_available);
        let rank_deficit_positive = status.rank_deficit.is_some_and(|deficit| deficit > 0);
        crate::assert_with_log!(
            rank_deficit_positive,
            "rank_deficit positive",
            true,
            rank_deficit_positive
        );
        crate::test_complete!("block_status_collecting_after_partial_feed");
    }

    /// br-asupersync-w9yojl: the ATP QUIC receiver asks for every block's
    /// status on every feedback round, and atpd's listener does not
    /// authenticate clients. A round that saw no new symbol for a block
    /// reuses its last rank analysis instead of rebuilding the block's
    /// constraint system; a new symbol runs it again, with the result a fresh
    /// analysis gives.
    #[test]
    fn block_status_reuses_the_rank_analysis_until_the_block_changes() {
        fn feed(decoder: &mut DecodingPipeline, symbol: Symbol) {
            let auth = AuthenticatedSymbol::from_parts(
                symbol,
                crate::security::tag::AuthenticationTag::zero(),
            );
            let _ = decoder.feed(auth).expect("feed");
        }
        fn analyses(decoder: &DecodingPipeline) -> usize {
            decoder
                .rank_analyses
                .load(std::sync::atomic::Ordering::Relaxed)
        }
        init_test("block_status_reuses_the_rank_analysis_until_the_block_changes");
        let config = encoding_config();
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id = ObjectId::new_for_test(105);
        let data = vec![0xC3u8; 1024];
        let mut symbols = encoder
            .encode_with_repair(object_id, &data, 0)
            .map(|symbol| symbol.expect("encode").into_symbol());
        // K = 4, so two symbols keep the block collecting (not yet decodable).
        let mut decoder = decoder_with_params(&config, object_id, data.len(), 1.5, 1);
        feed(&mut decoder, symbols.next().expect("first symbol"));

        let first = decoder.block_status(0).expect("status");
        for _ in 0..8 {
            let again = decoder.block_status(0).expect("status");
            assert_eq!(
                (again.rank, again.rank_deficit),
                (first.rank, first.rank_deficit)
            );
        }
        assert_eq!(analyses(&decoder), 1, "an unchanged block is analyzed once");

        feed(&mut decoder, symbols.next().expect("second symbol"));
        let after = decoder.block_status(0).expect("status");
        assert_eq!(
            analyses(&decoder),
            2,
            "a new symbol runs the analysis again"
        );
        assert_eq!(after.symbols_received, 2);
        let received: Vec<Symbol> = decoder.symbols.symbols_for_block(0).cloned().collect();
        let fresh = rank_status_for_block(decoder.block_plan(0).expect("plan"), &received, 256)
            .expect("fresh analysis");
        assert_eq!(after.rank, Some(fresh.rank));
        assert_eq!(after.rank_deficit, Some(fresh.deficit));
        crate::test_complete!("block_status_reuses_the_rank_analysis_until_the_block_changes");
    }

    #[test]
    fn block_status_decoded_after_complete() {
        init_test("block_status_decoded_after_complete");
        let config = encoding_config();
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id = ObjectId::new_for_test(105);
        let data = vec![42u8; 512];
        let symbols: Vec<Symbol> = encoder
            .encode_with_repair(object_id, &data, 0)
            .map(|res| res.unwrap().into_symbol())
            .collect();

        let mut decoder = decoder_with_params(&config, object_id, data.len(), 1.0, 0);

        for symbol in symbols {
            let auth = AuthenticatedSymbol::from_parts(
                symbol,
                crate::security::tag::AuthenticationTag::zero(),
            );
            let _ = decoder.feed(auth).unwrap();
        }

        // Block 0 should now be decoded; symbols are cleared but block state persists.
        // After decode, symbols are cleared so block_progress returns None.
        // The completed_blocks set tracks completion separately.
        let _status = decoder.block_status(0);
        let complete = decoder.is_complete();
        crate::assert_with_log!(complete, "is_complete", true, complete);

        // Verify via completed_blocks indirectly: feeding another sbn=0 symbol
        // should give BlockAlreadyDecoded
        let extra = Symbol::new(
            SymbolId::new(object_id, 0, 99),
            vec![0u8; usize::from(config.symbol_size)],
            SymbolKind::Source,
        );
        let auth =
            AuthenticatedSymbol::from_parts(extra, crate::security::tag::AuthenticationTag::zero());
        let result = decoder.feed(auth).expect("feed");
        let expected = SymbolAcceptResult::Rejected(RejectReason::BlockAlreadyDecoded);
        let ok = result == expected;
        crate::assert_with_log!(ok, "block already decoded", expected, result);
        crate::test_complete!("block_status_decoded_after_complete");
    }

    #[test]
    fn streaming_source_complete_block_returns_data_without_retaining_copy() {
        init_test("streaming_source_complete_block_returns_data_without_retaining_copy");
        let config = encoding_config();
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id = ObjectId::new_for_test(205);
        let data = (0..700).map(|i| (i % 251) as u8).collect::<Vec<_>>();
        let symbols = encoder
            .encode_with_repair(object_id, &data, 0)
            .map(|res| res.expect("source symbol").into_symbol())
            .collect::<Vec<_>>();

        let mut decoder = decoder_with_params(&config, object_id, data.len(), 1.0, 0);
        let mut completed = None;
        let mut deferred_jobs = 0usize;
        for symbol in symbols {
            let auth = AuthenticatedSymbol::from_parts(
                symbol,
                crate::security::tag::AuthenticationTag::zero(),
            );
            match decoder
                .feed_streaming_block_deferred(auth)
                .expect("feed streaming source")
            {
                DeferredSymbolAcceptResult::Immediate(SymbolAcceptResult::BlockComplete {
                    ..
                }) => {
                    panic!("source-complete deferred feed must return a decode job");
                }
                DeferredSymbolAcceptResult::Immediate(_) => {}
                DeferredSymbolAcceptResult::Decode(job) => {
                    deferred_jobs = deferred_jobs.saturating_add(1);
                    let expected_sources = data.len().div_ceil(usize::from(config.symbol_size));
                    assert_eq!(
                        job.source_symbols, expected_sources,
                        "source-complete deferred jobs must carry the exact source count"
                    );
                    let outcome = run_block_decode_job(job);
                    assert_eq!(outcome.kind(), BlockDecodeKind::SourceComplete);
                    let result = decoder.finish_decode_job(outcome);
                    if let SymbolAcceptResult::BlockComplete { data, .. } = result {
                        completed = Some(data);
                    }
                }
            }
        }

        crate::assert_with_log!(
            deferred_jobs == 1,
            "source-complete deferred feed queues one blocking job",
            1,
            deferred_jobs
        );
        let decoded = completed.expect("source-complete block");
        crate::assert_with_log!(decoded == data, "decoded source block", data, decoded);
        let complete = decoder.is_complete();
        crate::assert_with_log!(complete, "decoder complete", true, complete);
        let retained = decoder
            .blocks
            .get(&0)
            .and_then(|block| block.decoded.as_ref());
        crate::assert_with_log!(
            retained.is_none(),
            "streaming decode should not retain block copy",
            true,
            retained.is_none()
        );
        crate::test_complete!(
            "streaming_source_complete_block_returns_data_without_retaining_copy"
        );
    }

    #[test]
    fn block_already_decoded_reject() {
        init_test("block_already_decoded_reject");
        let config = encoding_config();
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id = ObjectId::new_for_test(106);
        let data = vec![42u8; 512];
        let symbols: Vec<Symbol> = encoder
            .encode_with_repair(object_id, &data, 0)
            .map(|res| res.unwrap().into_symbol())
            .collect();

        let mut decoder = decoder_with_params(&config, object_id, data.len(), 1.0, 0);

        for symbol in symbols {
            let auth = AuthenticatedSymbol::from_parts(
                symbol,
                crate::security::tag::AuthenticationTag::zero(),
            );
            let _ = decoder.feed(auth).unwrap();
        }

        // Feed one more symbol for sbn=0
        let extra = Symbol::new(
            SymbolId::new(object_id, 0, 0),
            vec![0u8; usize::from(config.symbol_size)],
            SymbolKind::Source,
        );
        let auth =
            AuthenticatedSymbol::from_parts(extra, crate::security::tag::AuthenticationTag::zero());
        let result = decoder.feed(auth).expect("feed");
        let expected = SymbolAcceptResult::Rejected(RejectReason::BlockAlreadyDecoded);
        let ok = result == expected;
        crate::assert_with_log!(ok, "block already decoded reject", expected, result);
        crate::test_complete!("block_already_decoded_reject");
    }

    #[test]
    fn verify_auth_no_context_unverified_symbol_errors() {
        init_test("verify_auth_no_context_unverified_symbol_errors");
        let config = encoding_config();
        let mut decoder = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            verify_auth: true,
            ..DecodingConfig::without_auth()
        });

        let symbol = Symbol::new(
            SymbolId::new(ObjectId::new_for_test(107), 0, 0),
            vec![0u8; usize::from(config.symbol_size)],
            SymbolKind::Source,
        );
        // from_parts creates an unverified symbol
        let auth = AuthenticatedSymbol::from_parts(
            symbol,
            crate::security::tag::AuthenticationTag::zero(),
        );

        let result = decoder.feed(auth);
        let is_ok = result.is_ok();
        crate::assert_with_log!(
            is_ok,
            "unverified with no context is rejected safely",
            true,
            is_ok
        );

        let accept = result.unwrap();
        let expected = SymbolAcceptResult::Rejected(RejectReason::AuthenticationFailed);
        crate::assert_with_log!(
            accept == expected,
            "rejected as auth failed",
            expected,
            accept
        );
        crate::test_complete!("verify_auth_no_context_unverified_symbol_errors");
    }

    #[test]
    fn verify_auth_no_context_preverified_symbol_rejected() {
        init_test("verify_auth_no_context_preverified_symbol_rejected");
        let config = encoding_config();
        let mut decoder = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            verify_auth: true,
            ..DecodingConfig::without_auth()
        });

        let symbol = Symbol::new(
            SymbolId::new(ObjectId::new_for_test(108), 0, 0),
            vec![0u8; usize::from(config.symbol_size)],
            SymbolKind::Source,
        );
        let auth = crate::security::SecurityContext::for_testing(108).sign_symbol(&symbol);

        let result = decoder.feed(auth);
        let is_ok = result.is_ok();
        crate::assert_with_log!(is_ok, "preverified symbol rejected safely", true, is_ok);
        let accept = result.unwrap();
        let expected = SymbolAcceptResult::Rejected(RejectReason::AuthenticationFailed);
        crate::assert_with_log!(
            accept == expected,
            "result is auth rejection without verifier context",
            expected,
            accept
        );
        crate::test_complete!("verify_auth_no_context_preverified_symbol_rejected");
    }

    #[test]
    fn with_auth_rejects_bad_tag() {
        init_test("with_auth_rejects_bad_tag");
        let config = encoding_config();
        let mut decoder = DecodingPipeline::with_auth(
            DecodingConfig {
                symbol_size: config.symbol_size,
                max_block_size: config.max_block_size,
                verify_auth: true,
                ..DecodingConfig::without_auth()
            },
            crate::security::SecurityContext::for_testing(42),
        );

        let symbol = Symbol::new(
            SymbolId::new(ObjectId::new_for_test(109), 0, 0),
            vec![0u8; usize::from(config.symbol_size)],
            SymbolKind::Source,
        );
        // zero tag is wrong for any real key
        let auth = AuthenticatedSymbol::from_parts(
            symbol,
            crate::security::tag::AuthenticationTag::zero(),
        );

        let result = decoder.feed(auth).expect("feed should not return Err");
        let expected = SymbolAcceptResult::Rejected(RejectReason::AuthenticationFailed);
        let ok = result == expected;
        crate::assert_with_log!(ok, "bad tag rejected", expected, result);
        crate::test_complete!("with_auth_rejects_bad_tag");
    }

    #[test]
    fn source_first_with_auth_verifies_hmac_before_fast_path_completion() {
        init_test("source_first_with_auth_verifies_hmac_before_fast_path_completion");
        let config = encoding_config();
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id = ObjectId::new_for_test(111);
        let data = (0..700).map(|i| (i % 251) as u8).collect::<Vec<_>>();
        let security = crate::security::SecurityContext::for_testing(111);
        let mut decoder = DecodingPipeline::with_auth(
            DecodingConfig {
                symbol_size: config.symbol_size,
                max_block_size: config.max_block_size,
                repair_overhead: 1.0,
                min_overhead: 0,
                max_buffered_symbols: 8192,
                block_timeout: Duration::from_secs(30),
                verify_auth: true,
            },
            security.clone(),
        );
        decoder
            .set_object_params(ObjectParams::new(
                object_id,
                data.len() as u64,
                config.symbol_size,
                1,
                data.len().div_ceil(usize::from(config.symbol_size)) as u16,
            ))
            .expect("params");

        let source_symbols = encoder
            .encode_with_repair(object_id, &data, 0)
            .map(|res| res.expect("encode source").into_symbol())
            .collect::<Vec<_>>();

        let mut completed = None;
        for symbol in source_symbols {
            let signed = security.sign_symbol(&symbol);
            let tag = *signed.tag();
            if let SymbolAcceptResult::BlockComplete { data, .. } = decoder
                .feed(AuthenticatedSymbol::from_parts(signed.into_symbol(), tag))
                .expect("feed signed source")
            {
                completed = Some(data);
            }
        }

        assert_eq!(completed.expect("source-first completion"), data);
        assert!(decoder.is_complete());
        assert_eq!(decoder.skipped_verifications(), 0);
        crate::test_complete!("source_first_with_auth_verifies_hmac_before_fast_path_completion");
    }

    #[test]
    fn source_first_with_auth_rejects_permissive_hmac_mismatch() {
        init_test("source_first_with_auth_rejects_permissive_hmac_mismatch");
        let config = encoding_config();
        let object_id = ObjectId::new_for_test(112);
        let signer = crate::security::SecurityContext::for_testing(112);
        let verifier = crate::security::SecurityContext::for_testing_with_mode(
            113,
            crate::security::AuthMode::Permissive,
        );
        let mut decoder = DecodingPipeline::with_auth(
            DecodingConfig {
                symbol_size: config.symbol_size,
                max_block_size: config.max_block_size,
                repair_overhead: 1.0,
                min_overhead: 0,
                max_buffered_symbols: 8192,
                block_timeout: Duration::from_secs(30),
                verify_auth: true,
            },
            verifier,
        );
        decoder
            .set_object_params(ObjectParams::new(object_id, 512, config.symbol_size, 1, 2))
            .expect("params");

        let symbol = Symbol::new(
            SymbolId::new(object_id, 0, 0),
            vec![7u8; usize::from(config.symbol_size)],
            SymbolKind::Source,
        );
        let signed = signer.sign_symbol(&symbol);
        let tag = *signed.tag();
        let result = decoder
            .feed(AuthenticatedSymbol::from_parts(signed.into_symbol(), tag))
            .expect("feed mismatched signed source");

        assert_eq!(
            result,
            SymbolAcceptResult::Rejected(RejectReason::AuthenticationFailed)
        );
        assert!(!decoder.is_complete());
        assert_eq!(decoder.progress().symbols_received, 0);
        crate::test_complete!("source_first_with_auth_rejects_permissive_hmac_mismatch");
    }

    /// br-asupersync-b1fojq: the default decode configuration MUST be
    /// fail-closed (`verify_auth = true`). This test locks the secure default
    /// in place so a future change cannot silently reintroduce the fail-open
    /// posture, and verifies the explicit opt-out
    /// [`DecodingConfig::without_auth`] differs from the default ONLY in
    /// `verify_auth`.
    #[test]
    fn default_config_is_fail_closed() {
        init_test("default_config_is_fail_closed");
        let secure = DecodingConfig::default();
        crate::assert_with_log!(
            secure.verify_auth,
            "DecodingConfig::default() is fail-closed (verify_auth=true)",
            true,
            secure.verify_auth
        );

        let insecure = DecodingConfig::without_auth();
        crate::assert_with_log!(
            !insecure.verify_auth,
            "DecodingConfig::without_auth() opts out (verify_auth=false)",
            false,
            insecure.verify_auth
        );

        let fields_match = insecure.symbol_size == secure.symbol_size
            && insecure.max_block_size == secure.max_block_size
            && insecure.repair_overhead.to_bits() == secure.repair_overhead.to_bits()
            && insecure.min_overhead == secure.min_overhead
            && insecure.max_buffered_symbols == secure.max_buffered_symbols
            && insecure.block_timeout == secure.block_timeout;
        crate::assert_with_log!(
            fields_match,
            "without_auth differs from default only in verify_auth",
            true,
            fields_match
        );
        crate::test_complete!("default_config_is_fail_closed");
    }

    /// br-asupersync-b1fojq: end-to-end proof that a pipeline built from the
    /// default config (no [`SecurityContext`] installed) REJECTS an
    /// unauthenticated symbol instead of silently accepting it. Pre-fix the
    /// default was `verify_auth = false`, so this exact symbol would have been
    /// accepted (decode-matrix poisoning).
    #[test]
    fn default_config_pipeline_rejects_unauthenticated_symbol() {
        init_test("default_config_pipeline_rejects_unauthenticated_symbol");
        let mut decoder = DecodingPipeline::new(DecodingConfig::default());
        let symbol = Symbol::new(
            SymbolId::new(ObjectId::new_for_test(201), 0, 0),
            vec![0u8; usize::from(DecodingConfig::default().symbol_size)],
            SymbolKind::Source,
        );
        let auth = AuthenticatedSymbol::from_parts(
            symbol,
            crate::security::tag::AuthenticationTag::zero(),
        );
        let result = decoder.feed(auth).expect("feed should not return Err");
        let expected = SymbolAcceptResult::Rejected(RejectReason::AuthenticationFailed);
        let ok = result == expected;
        crate::assert_with_log!(
            ok,
            "default-config pipeline rejects unauthenticated symbol",
            expected,
            result
        );
        crate::test_complete!("default_config_pipeline_rejects_unauthenticated_symbol");
    }

    #[test]
    fn multi_block_roundtrip() {
        init_test("multi_block_roundtrip");
        let config = crate::config::EncodingConfig {
            symbol_size: 256,
            max_block_size: 1024,
            repair_overhead: 1.05,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        };
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id = ObjectId::new_for_test(110);
        let data: Vec<u8> = (0u32..2048).map(|i| (i % 251) as u8).collect();

        let symbols: Vec<Symbol> = encoder
            .encode_with_repair(object_id, &data, 0)
            .map(|res| res.unwrap().into_symbol())
            .collect();

        let mut decoder = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            repair_overhead: 1.0,
            min_overhead: 0,
            max_buffered_symbols: 8192,
            block_timeout: Duration::from_secs(30),
            verify_auth: false,
        });

        // Compute block plan matching what the encoder does
        let symbol_size = usize::from(config.symbol_size);
        let num_blocks = data.len().div_ceil(config.max_block_size);
        let mut full_block_k: u16 = 0;
        for b in 0..num_blocks {
            let block_start = b * config.max_block_size;
            let block_len = usize::min(config.max_block_size, data.len() - block_start);
            let k = block_len.div_ceil(symbol_size) as u16;
            full_block_k = full_block_k.max(k);
        }
        decoder
            .set_object_params(ObjectParams::new(
                object_id,
                data.len() as u64,
                config.symbol_size,
                num_blocks as u16,
                full_block_k,
            ))
            .expect("set params");

        for symbol in symbols {
            let auth = AuthenticatedSymbol::from_parts(
                symbol,
                crate::security::tag::AuthenticationTag::zero(),
            );
            let _ = decoder.feed(auth).unwrap();
        }

        let complete = decoder.is_complete();
        crate::assert_with_log!(complete, "multi-block is_complete", true, complete);

        let decoded_data = decoder.into_data().expect("decoded");
        let ok = decoded_data == data;
        crate::assert_with_log!(
            ok,
            "multi-block roundtrip data",
            data.len(),
            decoded_data.len()
        );
        crate::test_complete!("multi_block_roundtrip");
    }

    #[test]
    fn deferred_streaming_feed_finishes_via_decode_job() {
        init_test("deferred_streaming_feed_finishes_via_decode_job");
        let config = crate::config::EncodingConfig {
            symbol_size: 4,
            max_block_size: 8,
            repair_overhead: 1.0,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        };
        let object_id = ObjectId::new_for_test(113);
        let data = b"ABCDEFGH".to_vec();
        let encoder_pool = SymbolPool::new(PoolConfig {
            symbol_size: config.symbol_size,
            initial_size: 16,
            max_size: 16,
            allow_growth: false,
            growth_increment: 0,
        });
        let mut encoder = EncodingPipeline::new(config.clone(), encoder_pool);
        let mut source_zero = None;
        let mut first_repair = None;
        for encoded in encoder.encode_single_block_with_repair(object_id, 0, &data, 1) {
            let symbol = encoded.expect("encode").into_symbol();
            match symbol.kind() {
                SymbolKind::Source if symbol.esi() == 0 => source_zero = Some(symbol),
                SymbolKind::Repair if first_repair.is_none() => first_repair = Some(symbol),
                _ => {}
            }
        }

        let mut decoder = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            repair_overhead: 1.0,
            min_overhead: 0,
            max_buffered_symbols: 8192,
            block_timeout: Duration::from_secs(30),
            verify_auth: false,
        });
        decoder
            .set_object_params(ObjectParams::new(
                object_id,
                data.len() as u64,
                config.symbol_size,
                1,
                2,
            ))
            .expect("set params");

        let first = decoder
            .feed_streaming_block_deferred(AuthenticatedSymbol::new_unauthenticated(
                source_zero.expect("source zero"),
            ))
            .expect("feed source");
        assert!(matches!(
            first,
            DeferredSymbolAcceptResult::Immediate(SymbolAcceptResult::Accepted { .. })
        ));

        let second = decoder
            .feed_streaming_block_deferred(AuthenticatedSymbol::new_unauthenticated(
                first_repair.expect("repair"),
            ))
            .expect("feed repair");
        let DeferredSymbolAcceptResult::Decode(job) = second else {
            panic!("second symbol should start deferred decode");
        };
        assert_eq!(
            job.source_symbols, 1,
            "repair decode jobs must carry source count below k"
        );

        let outcome = run_block_decode_job(job);
        assert_eq!(outcome.kind(), BlockDecodeKind::RaptorQRepair);
        assert!(
            outcome.elapsed().as_nanos() > 0,
            "deferred decode jobs must record solve wall time for receiver profiling"
        );
        let result = decoder.finish_decode_job(outcome);
        match result {
            SymbolAcceptResult::BlockComplete {
                block_sbn,
                data: got,
            } => {
                assert_eq!(block_sbn, 0);
                assert_eq!(got, data);
            }
            other => panic!("deferred decode should complete block, got {other:?}"),
        }
        assert!(decoder.is_complete());
        crate::test_complete!("deferred_streaming_feed_finishes_via_decode_job");
    }

    #[test]
    fn deferred_streaming_feed_does_not_spawn_duplicate_decode_for_pending_block() {
        init_test("deferred_streaming_feed_does_not_spawn_duplicate_decode_for_pending_block");
        let config = crate::config::EncodingConfig {
            symbol_size: 4,
            max_block_size: 8,
            repair_overhead: 1.0,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        };
        let object_id = ObjectId::new_for_test(114);
        let data = b"ABCDEFGH".to_vec();
        let encoder_pool = SymbolPool::new(PoolConfig {
            symbol_size: config.symbol_size,
            initial_size: 16,
            max_size: 16,
            allow_growth: false,
            growth_increment: 0,
        });
        let mut encoder = EncodingPipeline::new(config.clone(), encoder_pool);
        let mut source_zero = None;
        let mut repairs = Vec::new();
        for encoded in encoder.encode_single_block_with_repair(object_id, 0, &data, 2) {
            let symbol = encoded.expect("encode").into_symbol();
            match symbol.kind() {
                SymbolKind::Source if symbol.esi() == 0 => source_zero = Some(symbol),
                SymbolKind::Repair => repairs.push(symbol),
                _ => {}
            }
        }
        assert!(
            repairs.len() >= 2,
            "test fixture must provide at least two repair symbols"
        );

        let mut decoder = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            repair_overhead: 1.0,
            min_overhead: 0,
            max_buffered_symbols: 8192,
            block_timeout: Duration::from_secs(30),
            verify_auth: false,
        });
        decoder
            .set_object_params(ObjectParams::new(
                object_id,
                data.len() as u64,
                config.symbol_size,
                1,
                2,
            ))
            .expect("set params");

        let first = decoder
            .feed_streaming_block_deferred(AuthenticatedSymbol::new_unauthenticated(
                source_zero.expect("source zero"),
            ))
            .expect("feed source");
        assert!(matches!(
            first,
            DeferredSymbolAcceptResult::Immediate(SymbolAcceptResult::Accepted { .. })
        ));

        let started = decoder
            .feed_streaming_block_deferred(AuthenticatedSymbol::new_unauthenticated(
                repairs.remove(0),
            ))
            .expect("feed first repair");
        let DeferredSymbolAcceptResult::Decode(job) = started else {
            panic!("first repair should start deferred decode");
        };

        let duplicate = decoder
            .feed_streaming_block_deferred(AuthenticatedSymbol::new_unauthenticated(
                repairs.remove(0),
            ))
            .expect("feed second repair while decode pending");
        assert!(
            matches!(
                duplicate,
                DeferredSymbolAcceptResult::Immediate(SymbolAcceptResult::Accepted { .. })
            ),
            "extra symbols for a pending block must not spawn duplicate decode jobs: {duplicate:?}"
        );

        let outcome = run_block_decode_job(job);
        let result = decoder.finish_decode_job(outcome);
        match result {
            SymbolAcceptResult::BlockComplete {
                block_sbn,
                data: got,
            } => {
                assert_eq!(block_sbn, 0);
                assert_eq!(got, data);
            }
            other => panic!("deferred decode should complete block, got {other:?}"),
        }
        assert!(decoder.is_complete());
        crate::test_complete!(
            "deferred_streaming_feed_does_not_spawn_duplicate_decode_for_pending_block"
        );
    }

    #[test]
    fn deferred_retry_rechecks_symbols_buffered_during_pending_decode() {
        init_test("deferred_retry_rechecks_symbols_buffered_during_pending_decode");
        let config = crate::config::EncodingConfig {
            symbol_size: 4,
            max_block_size: 8,
            repair_overhead: 1.0,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        };
        let object_id = ObjectId::new_for_test(115);
        let data = b"ABCDEFGH".to_vec();
        let encoder_pool = SymbolPool::new(PoolConfig {
            symbol_size: config.symbol_size,
            initial_size: 16,
            max_size: 16,
            allow_growth: false,
            growth_increment: 0,
        });
        let mut encoder = EncodingPipeline::new(config.clone(), encoder_pool);
        let mut source_zero = None;
        let mut repairs = Vec::new();
        for encoded in encoder.encode_single_block_with_repair(object_id, 0, &data, 2) {
            let symbol = encoded.expect("encode").into_symbol();
            match symbol.kind() {
                SymbolKind::Source if symbol.esi() == 0 => source_zero = Some(symbol),
                SymbolKind::Repair => repairs.push(symbol),
                _ => {}
            }
        }
        assert!(
            repairs.len() >= 2,
            "test fixture must provide two repair symbols"
        );

        let mut decoder = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            repair_overhead: 1.0,
            min_overhead: 0,
            max_buffered_symbols: 8192,
            block_timeout: Duration::from_secs(30),
            verify_auth: false,
        });
        decoder
            .set_object_params(ObjectParams::new(
                object_id,
                data.len() as u64,
                config.symbol_size,
                1,
                2,
            ))
            .expect("set params");

        let first = decoder
            .feed_streaming_block_deferred(AuthenticatedSymbol::new_unauthenticated(
                source_zero.expect("source zero"),
            ))
            .expect("feed source zero");
        assert!(matches!(
            first,
            DeferredSymbolAcceptResult::Immediate(SymbolAcceptResult::Accepted { .. })
        ));

        let started = decoder
            .feed_streaming_block_deferred(AuthenticatedSymbol::new_unauthenticated(
                repairs.remove(0),
            ))
            .expect("feed repair");
        let DeferredSymbolAcceptResult::Decode(job) = started else {
            panic!("repair should start deferred decode");
        };
        let stale_sbn = job.sbn();
        let stale_symbols = job.symbols.clone();

        let buffered = decoder
            .feed_streaming_block_deferred(AuthenticatedSymbol::new_unauthenticated(
                repairs.remove(0),
            ))
            .expect("feed second repair while decode pending");
        assert!(
            matches!(
                buffered,
                DeferredSymbolAcceptResult::Immediate(SymbolAcceptResult::Accepted { .. })
            ),
            "new symbols accepted during a pending decode must stay buffered: {buffered:?}"
        );

        let stale_retry = BlockDecodeOutcome {
            sbn: stale_sbn,
            input_symbols: stale_symbols.len(),
            retain_decoded_block: false,
            kind: BlockDecodeKind::RaptorQRepair,
            elapsed: Duration::ZERO,
            resolution: BlockDecodeResolution::Retry {
                reason: RejectReason::InconsistentEquations,
                symbols: stale_symbols,
            },
        };
        let retry = decoder.finish_decode_job_deferred(stale_retry);
        let DeferredSymbolAcceptResult::Decode(retry_job) = retry else {
            panic!("stale deferred retry should return a fresh decode job, got {retry:?}");
        };
        assert!(
            !decoder.is_complete(),
            "deferred retry must not run the heavy decode inline"
        );

        let result = decoder.finish_decode_job(run_block_decode_job(retry_job));
        match result {
            SymbolAcceptResult::BlockComplete {
                block_sbn,
                data: got,
            } => {
                assert_eq!(block_sbn, 0);
                assert_eq!(got, data);
            }
            other => panic!("stale deferred retry should recheck buffered symbols, got {other:?}"),
        }
        assert!(decoder.is_complete());
        crate::test_complete!("deferred_retry_rechecks_symbols_buffered_during_pending_decode");
    }

    #[test]
    fn multi_block_roundtrip_respects_partial_last_block_metadata() {
        init_test("multi_block_roundtrip_respects_partial_last_block_metadata");
        let config = crate::config::EncodingConfig {
            symbol_size: 4,
            max_block_size: 6,
            repair_overhead: 1.0,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        };
        let encoder_pool = SymbolPool::new(PoolConfig {
            symbol_size: config.symbol_size,
            initial_size: 16,
            max_size: 16,
            allow_growth: false,
            growth_increment: 0,
        });
        let mut encoder = EncodingPipeline::new(config.clone(), encoder_pool);
        let object_id = ObjectId::new_for_test(112);
        let data = b"ABCDEFGHIJKLM".to_vec();

        let symbols: Vec<Symbol> = encoder
            .encode_with_repair(object_id, &data, 0)
            .map(|res| res.expect("encode").into_symbol())
            .collect();

        let mut decoder = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            repair_overhead: 1.0,
            min_overhead: 0,
            max_buffered_symbols: 8192,
            block_timeout: Duration::from_secs(30),
            verify_auth: false,
        });
        decoder
            .set_object_params(ObjectParams::new(
                object_id,
                data.len() as u64,
                config.symbol_size,
                3,
                2,
            ))
            .expect("set params for uneven multi-block object");

        let expected_blocks = Some(3usize);
        let blocks_total = decoder.progress().blocks_total;
        crate::assert_with_log!(
            blocks_total == expected_blocks,
            "partial last block count",
            expected_blocks,
            blocks_total
        );

        for symbol in symbols {
            let auth = AuthenticatedSymbol::from_parts(
                symbol,
                crate::security::tag::AuthenticationTag::zero(),
            );
            let _ = decoder.feed(auth).expect("feed");
        }

        let complete = decoder.is_complete();
        crate::assert_with_log!(
            complete,
            "partial last block roundtrip is_complete",
            true,
            complete
        );

        let decoded_data = decoder.into_data().expect("decoded");
        let ok = decoded_data == data;
        crate::assert_with_log!(
            ok,
            "partial last block roundtrip data",
            data.len(),
            decoded_data.len()
        );
        crate::test_complete!("multi_block_roundtrip_respects_partial_last_block_metadata");
    }

    #[test]
    fn multi_block_progress_retains_cumulative_symbols_after_block_completion() {
        init_test("multi_block_progress_retains_cumulative_symbols_after_block_completion");
        let config = crate::config::EncodingConfig {
            symbol_size: 256,
            max_block_size: 1024,
            repair_overhead: 1.05,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        };
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id = ObjectId::new_for_test(111);
        let data: Vec<u8> = (0u32..2048).map(|i| (i % 251) as u8).collect();

        let mut block_zero_symbols: Vec<Symbol> = encoder
            .encode_with_repair(object_id, &data, 0)
            .map(|res| res.expect("encode").into_symbol())
            .filter(|symbol| symbol.sbn() == 0)
            .collect();
        block_zero_symbols.sort_by_key(Symbol::esi);
        assert_eq!(block_zero_symbols.len(), 4);

        let mut decoder = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            repair_overhead: 1.0,
            min_overhead: 0,
            max_buffered_symbols: 8192,
            block_timeout: Duration::from_secs(30),
            verify_auth: false,
        });
        decoder
            .set_object_params(ObjectParams::new(
                object_id,
                data.len() as u64,
                config.symbol_size,
                2,
                4,
            ))
            .expect("set params");

        for symbol in block_zero_symbols {
            let auth = AuthenticatedSymbol::from_parts(
                symbol,
                crate::security::tag::AuthenticationTag::zero(),
            );
            let _ = decoder.feed(auth).expect("feed");
        }

        assert_eq!(decoder.progress().blocks_complete, 1);
        assert_eq!(decoder.progress().blocks_total, Some(2));
        assert_eq!(decoder.progress().symbols_received, 4);
        assert_eq!(decoder.progress().symbols_needed_estimate, 8);

        let err = decoder.into_data().expect_err("block one is still missing");
        assert!(matches!(
            err,
            DecodingError::InsufficientSymbols {
                received: 4,
                needed: 8
            }
        ));
        crate::test_complete!(
            "multi_block_progress_retains_cumulative_symbols_after_block_completion"
        );
    }

    #[test]
    fn into_data_no_params_errors() {
        init_test("into_data_no_params_errors");
        let pipeline = DecodingPipeline::new(DecodingConfig::default());
        let result = pipeline.into_data();
        let is_err = result.is_err();
        crate::assert_with_log!(is_err, "into_data without params errors", true, is_err);
        let err = result.unwrap_err();
        let msg = err.to_string();
        let contains = msg.contains("object parameters not set");
        crate::assert_with_log!(
            contains,
            "error message contains expected text",
            true,
            contains
        );
        crate::test_complete!("into_data_no_params_errors");
    }

    // --- wave 76 trait coverage ---

    #[test]
    fn reject_reason_debug_clone_copy_eq() {
        let r = RejectReason::WrongObjectId;
        let r2 = r; // Copy
        let r3 = r;
        assert_eq!(r, r2);
        assert_eq!(r, r3);
        assert_ne!(r, RejectReason::AuthenticationFailed);
        assert_ne!(r, RejectReason::SymbolSizeMismatch);
        assert_ne!(r, RejectReason::BlockAlreadyDecoded);
        assert_ne!(r, RejectReason::InsufficientRank);
        assert_ne!(r, RejectReason::InconsistentEquations);
        assert_ne!(r, RejectReason::InvalidMetadata);
        assert_ne!(r, RejectReason::MemoryLimitReached);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("WrongObjectId"));
    }

    #[test]
    fn symbol_accept_result_debug_clone_eq() {
        let a = SymbolAcceptResult::Accepted {
            received: 3,
            needed: 5,
        };
        let a2 = a.clone();
        assert_eq!(a, a2);
        assert_ne!(a, SymbolAcceptResult::Duplicate);
        let r = SymbolAcceptResult::Rejected(RejectReason::InvalidMetadata);
        let r2 = r.clone();
        assert_eq!(r, r2);
        let dbg = format!("{a:?}");
        assert!(dbg.contains("Accepted"));
    }

    #[test]
    fn block_state_kind_debug_clone_copy_eq() {
        let s = BlockStateKind::Collecting;
        let s2 = s; // Copy
        let s3 = s;
        assert_eq!(s, s2);
        assert_eq!(s, s3);
        assert_ne!(s, BlockStateKind::Decoding);
        assert_ne!(s, BlockStateKind::Decoded);
        assert_ne!(s, BlockStateKind::Failed);
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Collecting"));
    }

    /// c54to7 residual hunt: honest symbols fed through arbitrary orders,
    /// duplicate re-feeds, and repeated STALE-REQUEUE cycles must NEVER
    /// produce InconsistentEquations — across block shapes including short
    /// final symbols (the last-shard boundary class the residual skews to).
    /// If this holds, the decoder core + snapshot/restore machinery is
    /// exonerated deterministically and the residual source is
    /// transport-side state.
    #[test]
    fn honest_symbols_never_inconsistent_across_stale_requeue_cycles() {
        init_test("honest_symbols_never_inconsistent_across_stale_requeue_cycles");
        // Deterministic LCG (no external RNG; Date/random are banned).
        let mut rng_state: u64 = 0xC54_707;
        let mut next_rand = move |bound: usize| -> usize {
            rng_state = rng_state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            usize::try_from((rng_state >> 33) % (bound.max(1) as u64)).unwrap_or(0)
        };

        // Block shapes: (symbol_size, data_len) — full blocks, short final
        // symbol, single-symbol blocks, and K around the observed class.
        let shapes: [(u16, usize); 6] = [
            (8, 64),  // k=8 exact
            (8, 61),  // k=8, short final symbol (the shard-boundary class)
            (8, 9),   // k=2, tiny short final
            (16, 33), // k=3, one-past boundary
            (4, 4),   // k=1 single symbol
            (8, 57),  // k=8, 1-byte final symbol
        ];

        for (shape_index, (symbol_size, data_len)) in shapes.iter().enumerate() {
            let config = crate::config::EncodingConfig {
                symbol_size: *symbol_size,
                max_block_size: 1 << 20,
                repair_overhead: 1.0,
                encoding_parallelism: 1,
                decoding_parallelism: 1,
            };
            let object_id = ObjectId::new_for_test(4200 + shape_index as u64);
            let data: Vec<u8> = (0..*data_len).map(|i| (i * 31 + 7) as u8).collect();
            let encoder_pool = SymbolPool::new(PoolConfig {
                symbol_size: config.symbol_size,
                initial_size: 64,
                max_size: 64,
                allow_growth: false,
                growth_increment: 0,
            });
            let mut encoder = EncodingPipeline::new(config.clone(), encoder_pool);
            let mut sources = Vec::new();
            let mut repairs = Vec::new();
            for encoded in encoder.encode_single_block_with_repair(object_id, 0, &data, 8) {
                let symbol = encoded.expect("encode").into_symbol();
                match symbol.kind() {
                    SymbolKind::Source => sources.push(symbol),
                    SymbolKind::Repair => repairs.push(symbol),
                }
            }
            let k = sources.len();

            // Several randomized trials per shape: shuffle a mixed subset,
            // inject staleness mid-stream, re-feed duplicates.
            for trial in 0..24usize {
                let mut decoder = DecodingPipeline::new(DecodingConfig {
                    symbol_size: config.symbol_size,
                    max_block_size: config.max_block_size,
                    repair_overhead: 1.0,
                    min_overhead: 0,
                    max_buffered_symbols: 8192,
                    block_timeout: Duration::from_secs(30),
                    verify_auth: false,
                });
                decoder
                    .set_object_params(ObjectParams::new(
                        object_id,
                        data.len() as u64,
                        config.symbol_size,
                        1,
                        u16::try_from(k).unwrap_or(u16::MAX),
                    ))
                    .expect("set params");

                // Feed order: drop `dropped` sources, replace with repairs.
                let dropped = trial % (k + 1);
                let mut feed: Vec<Symbol> = sources
                    .iter()
                    .skip(dropped)
                    .chain(repairs.iter().take(dropped + 2))
                    .cloned()
                    .collect();
                // Deterministic shuffle.
                for i in (1..feed.len()).rev() {
                    feed.swap(i, next_rand(i + 1));
                }

                let mut pending_job: Option<BlockDecodeJob> = None;
                let mut complete = false;
                for (feed_index, symbol) in feed.iter().enumerate() {
                    if complete {
                        break;
                    }
                    let result = decoder
                        .feed_streaming_block_deferred(AuthenticatedSymbol::new_unauthenticated(
                            symbol.clone(),
                        ))
                        .expect("feed");
                    match result {
                        DeferredSymbolAcceptResult::Decode(job) => {
                            // Sometimes run it now; sometimes hold it so more
                            // symbols land first, then report it back STALE.
                            if feed_index % 2 == 0 {
                                let outcome = run_block_decode_job(job);
                                match decoder.finish_decode_job(outcome) {
                                    SymbolAcceptResult::Rejected(reason) => {
                                        assert_ne!(
                                            reason,
                                            RejectReason::InconsistentEquations,
                                            "honest symbols must never be inconsistent \
                                             (shape {shape_index}, trial {trial})"
                                        );
                                    }
                                    SymbolAcceptResult::BlockComplete { data: got, .. } => {
                                        assert_eq!(got, data, "decoded bytes must match");
                                        complete = true;
                                    }
                                    _ => {}
                                }
                            } else {
                                pending_job = Some(job);
                            }
                        }
                        DeferredSymbolAcceptResult::Immediate(SymbolAcceptResult::Rejected(
                            reason,
                        )) => {
                            assert_ne!(
                                reason,
                                RejectReason::InconsistentEquations,
                                "honest feed must never be inconsistent \
                                 (shape {shape_index}, trial {trial})"
                            );
                        }
                        DeferredSymbolAcceptResult::Immediate(
                            SymbolAcceptResult::BlockComplete { data: got, .. },
                        ) => {
                            assert_eq!(got, data, "decoded bytes must match");
                            complete = true;
                        }
                        DeferredSymbolAcceptResult::Immediate(_) => {}
                    }
                    // Stale cycle: resolve the held job AFTER newer symbols
                    // arrived — the deferred finish must produce a fresh job
                    // (or an honest outcome), never an inconsistency.
                    if let Some(job) = pending_job.take() {
                        let outcome = run_block_decode_job(job);
                        match decoder.finish_decode_job_deferred(outcome) {
                            DeferredSymbolAcceptResult::Decode(fresh) => {
                                let outcome = run_block_decode_job(fresh);
                                match decoder.finish_decode_job(outcome) {
                                    SymbolAcceptResult::Rejected(reason) => {
                                        assert_ne!(
                                            reason,
                                            RejectReason::InconsistentEquations,
                                            "stale-requeue cycle must stay consistent \
                                             (shape {shape_index}, trial {trial})"
                                        );
                                    }
                                    SymbolAcceptResult::BlockComplete { data: got, .. } => {
                                        assert_eq!(got, data);
                                        complete = true;
                                    }
                                    _ => {}
                                }
                            }
                            DeferredSymbolAcceptResult::Immediate(
                                SymbolAcceptResult::Rejected(reason),
                            ) => {
                                assert_ne!(
                                    reason,
                                    RejectReason::InconsistentEquations,
                                    "stale finish must stay consistent \
                                     (shape {shape_index}, trial {trial})"
                                );
                            }
                            DeferredSymbolAcceptResult::Immediate(
                                SymbolAcceptResult::BlockComplete { data: got, .. },
                            ) => {
                                assert_eq!(got, data);
                                complete = true;
                            }
                            DeferredSymbolAcceptResult::Immediate(_) => {}
                        }
                    }
                }
                // With ≥ K honest symbols delivered the block must complete.
                if feed.len() > k {
                    assert!(
                        complete || feed.len() < k,
                        "block should complete with {} symbols for k={k} \
                         (shape {shape_index}, trial {trial})",
                        feed.len()
                    );
                }
            }
        }
        crate::test_complete!("honest_symbols_never_inconsistent_across_stale_requeue_cycles");
    }
