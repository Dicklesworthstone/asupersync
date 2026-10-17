    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::types::ObjectId;
    use crate::types::resource::PoolConfig;

    fn test_config(
        symbol_size: u16,
        max_block_size: usize,
        repair_overhead: f64,
    ) -> EncodingConfig {
        EncodingConfig {
            symbol_size,
            max_block_size,
            repair_overhead,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        }
    }

    fn pool_for(symbol_size: u16, max_size: usize) -> SymbolPool {
        SymbolPool::new(PoolConfig {
            symbol_size,
            initial_size: max_size,
            max_size,
            allow_growth: false,
            growth_increment: 0,
        })
    }

    #[test]
    fn test_encode_small_data() {
        let mut pipeline = EncodingPipeline::new(
            test_config(4, 16, 1.0),
            SymbolPool::new(PoolConfig::default()),
        );
        let data = b"hello";
        let symbols: Vec<_> = pipeline
            .encode(ObjectId::new_for_test(1), data)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(symbols.len(), 2);
        assert_eq!(symbols[0].symbol().data().len(), 4);
        assert_eq!(symbols[1].symbol().data().len(), 4);
    }

    #[test]
    fn test_encode_exact_block_size() {
        let mut pipeline = EncodingPipeline::new(
            test_config(4, 8, 1.0),
            SymbolPool::new(PoolConfig::default()),
        );
        let data = b"abcdefgh";
        let symbols: Vec<_> = pipeline
            .encode(ObjectId::new_for_test(2), data)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(symbols.len(), 2);
        assert!(symbols.iter().all(|s| s.kind() == SymbolKind::Source));
    }

    #[test]
    fn test_encode_multiple_blocks() {
        let mut pipeline = EncodingPipeline::new(
            test_config(4, 8, 1.0),
            SymbolPool::new(PoolConfig::default()),
        );
        let data = b"abcdefghijklmnop";
        let symbols: Vec<_> = pipeline
            .encode(ObjectId::new_for_test(3), data)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let sbns: Vec<u8> = symbols.iter().map(|s| s.id().sbn()).collect();
        assert!(sbns.contains(&0));
        assert!(sbns.contains(&1));
    }

    #[test]
    fn test_encode_multiple_blocks_preserves_non_aligned_boundaries() {
        let mut pipeline = EncodingPipeline::new(
            test_config(4, 6, 1.0),
            SymbolPool::new(PoolConfig::default()),
        );
        let data = b"ABCDEFGHIJKLM";
        let symbols: Vec<_> = pipeline
            .encode(ObjectId::new_for_test(13), data)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let expected = [
            (0u8, 0u32, b"ABCD".to_vec()),
            (0u8, 1u32, vec![b'E', b'F', 0, 0]),
            (1u8, 0u32, b"GHIJ".to_vec()),
            (1u8, 1u32, vec![b'K', b'L', 0, 0]),
            (2u8, 0u32, vec![b'M', 0, 0, 0]),
        ];

        assert_eq!(symbols.len(), expected.len());
        for (symbol, (expected_sbn, expected_esi, expected_bytes)) in symbols.iter().zip(expected) {
            assert_eq!(symbol.kind(), SymbolKind::Source);
            assert_eq!(symbol.id().sbn(), expected_sbn);
            assert_eq!(symbol.id().esi(), expected_esi);
            assert_eq!(symbol.symbol().data(), expected_bytes.as_slice());
        }
    }

    #[test]
    fn test_encode_empty_data() {
        let mut pipeline = EncodingPipeline::new(
            test_config(8, 32, 1.0),
            SymbolPool::new(PoolConfig::default()),
        );
        let symbols: Vec<_> = pipeline
            .encode(ObjectId::new_for_test(4), &[])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert!(symbols.is_empty());
    }

    #[test]
    fn test_repair_overhead_respected() {
        let mut pipeline = EncodingPipeline::new(
            test_config(4, 16, 1.5),
            SymbolPool::new(PoolConfig::default()),
        );
        let data = b"abcdefgh";
        let symbols: Vec<_> = pipeline
            .encode(ObjectId::new_for_test(5), data)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let repair_count = symbols
            .iter()
            .filter(|s| s.kind() == SymbolKind::Repair)
            .count();
        assert_eq!(repair_count, 1);
    }

    #[test]
    fn test_symbol_ids_unique() {
        let mut pipeline = EncodingPipeline::new(
            test_config(4, 16, 1.2),
            SymbolPool::new(PoolConfig::default()),
        );
        let data = b"abcdefgh";
        let symbols: Vec<_> = pipeline
            .encode(ObjectId::new_for_test(6), data)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let mut ids = symbols.iter().map(EncodedSymbol::id).collect::<Vec<_>>();
        ids.sort_by_key(|id| (id.sbn(), id.esi()));
        ids.dedup();
        assert_eq!(ids.len(), symbols.len());
    }

    #[test]
    fn test_data_too_large_error() {
        let mut pipeline = EncodingPipeline::new(
            test_config(1, 1, 1.0),
            SymbolPool::new(PoolConfig::default()),
        );
        let data = vec![0_u8; 257];
        let err = pipeline
            .encode(ObjectId::new_for_test(7), &data)
            .next()
            .unwrap()
            .unwrap_err();

        assert!(matches!(err, EncodingError::DataTooLarge { .. }));
    }

    #[test]
    fn test_pool_exhaustion_handling() {
        let mut pipeline = EncodingPipeline::new(test_config(4, 16, 1.0), pool_for(4, 1));
        let data = b"abcdefgh";
        let mut iter = pipeline.encode(ObjectId::new_for_test(8), data);

        let _ = iter.next().unwrap().unwrap();
        let err = iter.next().unwrap().unwrap_err();
        assert!(matches!(err, EncodingError::PoolExhausted));
    }

    #[test]
    fn test_source_symbol_zero_pads_with_pool() {
        let symbol_size = 4u16;
        let mut pool = pool_for(symbol_size, 1);
        let mut buffer = pool.allocate().unwrap();
        buffer.as_mut_slice().fill(0xAA);
        pool.deallocate(buffer);

        let mut pipeline = EncodingPipeline::new(test_config(symbol_size, 16, 1.0), pool);
        let data = [0x11u8];
        let symbols: Vec<_> = pipeline
            .encode(ObjectId::new_for_test(11), &data)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(symbols.len(), 1);
        let bytes = symbols[0].symbol().data();
        assert_eq!(bytes[0], 0x11);
        assert!(bytes[1..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn test_deterministic_output() {
        let data = b"deterministic";
        let object_id = ObjectId::new_for_test(9);
        let config = test_config(4, 16, 1.5);

        let mut pipeline_a =
            EncodingPipeline::new(config.clone(), SymbolPool::new(PoolConfig::default()));
        let mut pipeline_b = EncodingPipeline::new(config, SymbolPool::new(PoolConfig::default()));

        let symbols_a: Vec<_> = pipeline_a
            .encode(object_id, data)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let symbols_b: Vec<_> = pipeline_b
            .encode(object_id, data)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let bytes_a: Vec<Vec<u8>> = symbols_a
            .iter()
            .map(|s| s.symbol().data().to_vec())
            .collect();
        let bytes_b: Vec<Vec<u8>> = symbols_b
            .iter()
            .map(|s| s.symbol().data().to_vec())
            .collect();

        assert_eq!(bytes_a, bytes_b);
    }

    #[test]
    fn test_repair_symbols_match_systematic_encoder() {
        let symbol_size = 8usize;
        let max_block_size = 64usize;
        let repair_count = 3usize;
        let data: Vec<u8> = (0u8..37).map(|i| i.wrapping_mul(7)).collect();
        let object_id = ObjectId::new_for_test(10);

        let mut pipeline = EncodingPipeline::new(
            test_config(symbol_size as u16, max_block_size, 1.0),
            SymbolPool::new(PoolConfig::default()),
        );
        let symbols: Vec<_> = pipeline
            .encode_with_repair(object_id, &data, repair_count)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let k = data.len().div_ceil(symbol_size);
        let block = BlockPlan {
            sbn: 0,
            start: 0,
            len: data.len(),
            k,
        };
        let source_symbols = build_source_symbols(&data, &block, symbol_size);
        let seed = seed_for_block(object_id, block.sbn);
        let encoder = SystematicEncoder::new(&source_symbols, symbol_size, seed).expect("encoder");

        for sym in symbols.iter().filter(|s| s.kind() == SymbolKind::Repair) {
            let esi = sym.id().esi();
            let expected = encoder.repair_symbol(esi);
            assert_eq!(sym.symbol().data(), expected.as_slice());
        }
    }

    #[test]
    fn test_encode_repair_range_skips_sources_and_preserves_repair_esis() {
        let symbol_size = 4usize;
        let max_block_size = 8usize;
        let data = b"ABCDEFGHIJKLMNOP";
        let object_id = ObjectId::new_for_test(14);

        let mut pipeline = EncodingPipeline::new(
            test_config(symbol_size as u16, max_block_size, 1.0),
            SymbolPool::new(PoolConfig::default()),
        );
        let symbols: Vec<_> = pipeline
            .encode_repair_range(object_id, data, 1, 2)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(symbols.len(), 4);
        assert!(symbols.iter().all(|s| s.kind() == SymbolKind::Repair));
        assert_eq!(pipeline.stats().source_symbols, 0);
        assert_eq!(pipeline.stats().repair_symbols, 4);

        let ids: Vec<(u8, u32)> = symbols
            .iter()
            .map(|s| (s.id().sbn(), s.id().esi()))
            .collect();
        assert_eq!(ids, vec![(0, 3), (0, 4), (1, 3), (1, 4)]);

        let first_block = BlockPlan {
            sbn: 0,
            start: 0,
            len: max_block_size,
            k: 2,
        };
        let source_symbols = build_source_symbols(data, &first_block, symbol_size);
        let encoder =
            SystematicEncoder::new(&source_symbols, symbol_size, seed_for_block(object_id, 0))
                .expect("encoder");
        assert_eq!(symbols[0].symbol().data(), encoder.repair_symbol(3));
        assert_eq!(symbols[1].symbol().data(), encoder.repair_symbol(4));
    }

    #[test]
    fn test_rejects_block_above_systematic_k_limit_before_emission() {
        let mut pipeline = EncodingPipeline::new(
            test_config(8, 451_232, 1.1),
            SymbolPool::new(PoolConfig::default()),
        );
        let data = vec![0u8; 451_232];

        let err = pipeline
            .encode_with_repair(ObjectId::new_for_test(12), &data, 1)
            .next()
            .expect("iterator should yield planning error")
            .unwrap_err();

        assert!(matches!(err, EncodingError::InvalidConfig { .. }));
        assert!(
            err.to_string().contains("unsupported source block K=56404"),
            "unexpected error: {err}"
        );
        assert_eq!(pipeline.stats().source_symbols, 0);
        assert_eq!(pipeline.stats().repair_symbols, 0);
    }

    // ========================================================================
    // Pure data-type trait coverage (wave 25)
    // ========================================================================

    #[test]
    fn encoding_error_debug_display_data_too_large() {
        let err = EncodingError::DataTooLarge {
            size: 1024,
            limit: 512,
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("DataTooLarge"));
        let disp = format!("{err}");
        assert!(disp.contains("1024"));
        assert!(disp.contains("512"));
    }

    #[test]
    fn encoding_error_display_pool_exhausted() {
        let err = EncodingError::PoolExhausted;
        let disp = format!("{err}");
        assert!(disp.contains("pool") || disp.contains("exhausted"));
    }

    #[test]
    fn encoding_error_display_invalid_config() {
        let err = EncodingError::InvalidConfig {
            reason: "symbol_size must be non-zero".into(),
        };
        let disp = format!("{err}");
        assert!(disp.contains("symbol_size"));
    }

    #[test]
    fn encoding_error_display_computation_failed() {
        let err = EncodingError::ComputationFailed {
            details: "singular matrix".into(),
        };
        let disp = format!("{err}");
        assert!(disp.contains("singular matrix"));
    }

    #[test]
    fn encoding_error_is_std_error() {
        let err = EncodingError::PoolExhausted;
        let dyn_err: &dyn std::error::Error = &err;
        assert!(!dyn_err.to_string().is_empty());
    }

    #[test]
    fn encoding_error_from_pool_exhausted() {
        let pool_err = PoolExhausted;
        let encoding_err: EncodingError = pool_err.into();
        assert!(matches!(encoding_err, EncodingError::PoolExhausted));
    }

    #[test]
    fn encoding_error_into_error() {
        let err = EncodingError::DataTooLarge {
            size: 100,
            limit: 50,
        };
        let generic: Error = err.into();
        let msg = format!("{generic}");
        assert!(!msg.is_empty());

        let err2 = EncodingError::PoolExhausted;
        let generic2: Error = err2.into();
        assert!(!format!("{generic2}").is_empty());

        let err3 = EncodingError::InvalidConfig {
            reason: "bad".into(),
        };
        let generic3: Error = err3.into();
        assert!(!format!("{generic3}").is_empty());

        let err4 = EncodingError::ComputationFailed {
            details: "fail".into(),
        };
        let generic4: Error = err4.into();
        assert!(!format!("{generic4}").is_empty());
    }

    #[test]
    fn encoding_stats_debug_clone_copy_default() {
        let stats = EncodingStats::default();
        assert_eq!(stats.bytes_in, 0);
        assert_eq!(stats.blocks, 0);
        assert_eq!(stats.source_symbols, 0);
        assert_eq!(stats.repair_symbols, 0);
        let dbg = format!("{stats:?}");
        assert!(dbg.contains("EncodingStats"));
        let s2 = stats; // Copy
        assert_eq!(s2.bytes_in, stats.bytes_in);
    }

    #[test]
    fn encoding_stats_reset_for() {
        let mut stats = EncodingStats {
            source_symbols: 10,
            repair_symbols: 5,
            ..EncodingStats::default()
        };
        stats.reset_for(1024, 4);
        assert_eq!(stats.bytes_in, 1024);
        assert_eq!(stats.blocks, 4);
        assert_eq!(stats.source_symbols, 0);
        assert_eq!(stats.repair_symbols, 0);
    }

    #[test]
    fn encoded_symbol_debug_clone_accessors() {
        let sym = Symbol::new(
            SymbolId::new(ObjectId::new_for_test(1), 0, 0),
            vec![1, 2, 3, 4],
            SymbolKind::Source,
        );
        let encoded = EncodedSymbol::new(sym);
        let dbg = format!("{encoded:?}");
        assert!(dbg.contains("EncodedSymbol"));
        assert_eq!(encoded.kind(), SymbolKind::Source);

        let cloned = encoded.clone();
        assert_eq!(cloned.symbol().data(), encoded.symbol().data());

        let id = encoded.id();
        assert_eq!(id.sbn(), 0);
        assert_eq!(id.esi(), 0);

        let sym_back = encoded.into_symbol();
        assert_eq!(sym_back.data(), &[1, 2, 3, 4]);
    }

    #[test]
    fn block_plan_debug_clone_end() {
        let plan = BlockPlan {
            sbn: 0,
            start: 100,
            len: 50,
            k: 5,
        };
        let dbg = format!("{plan:?}");
        assert!(dbg.contains("BlockPlan"));
        let plan2 = plan;
        assert_eq!(plan2.end(), 150);
        assert_eq!(plan2.sbn, 0);
        assert_eq!(plan2.k, 5);
    }

    #[test]
    fn compute_repair_count_cases() {
        // overhead 1.0 means 0 repair
        assert_eq!(compute_repair_count(10, 1.0), 0);
        // overhead 1.5 means ceil(10*1.5)=15, so 5 repair
        assert_eq!(compute_repair_count(10, 1.5), 5);
        // overhead 2.0 means ceil(10*2.0)=20, so 10 repair
        assert_eq!(compute_repair_count(10, 2.0), 10);
        // k=1 with overhead 1.5 means ceil(1.5)=2, so 1 repair
        assert_eq!(compute_repair_count(1, 1.5), 1);
    }

    #[test]
    fn compute_repair_count_large_k_does_not_truncate() {
        // Regression guard: casting k through u32 would wrap this to zero.
        let k = (u32::MAX as usize) + 1;
        assert_eq!(compute_repair_count(k, 1.25), k / 4);
    }

    #[test]
    fn seed_for_block_deterministic() {
        let id = ObjectId::new_for_test(42);
        let s1 = seed_for_block(id, 0);
        let s2 = seed_for_block(id, 0);
        assert_eq!(s1, s2);
        // Different blocks should (almost certainly) yield different seeds
        let s3 = seed_for_block(id, 1);
        assert_ne!(s1, s3);
    }

    #[test]
    fn repair_overhead_nan_rejected() {
        let mut pipeline = EncodingPipeline::new(
            test_config(4, 16, f64::NAN),
            SymbolPool::new(PoolConfig::default()),
        );
        let err = pipeline
            .encode(ObjectId::new_for_test(100), b"test")
            .next()
            .unwrap()
            .unwrap_err();
        assert!(matches!(err, EncodingError::InvalidConfig { .. }));
    }

    #[test]
    fn repair_overhead_infinity_rejected() {
        let mut pipeline = EncodingPipeline::new(
            test_config(4, 16, f64::INFINITY),
            SymbolPool::new(PoolConfig::default()),
        );
        let err = pipeline
            .encode(ObjectId::new_for_test(101), b"test")
            .next()
            .unwrap()
            .unwrap_err();
        assert!(matches!(err, EncodingError::InvalidConfig { .. }));
    }

    #[test]
    fn empty_payload_still_rejects_zero_symbol_size() {
        let mut pipeline = EncodingPipeline::new(
            test_config(0, 16, 1.0),
            SymbolPool::new(PoolConfig::default()),
        );
        let err = pipeline
            .encode(ObjectId::new_for_test(102), &[])
            .next()
            .unwrap()
            .unwrap_err();
        assert!(matches!(err, EncodingError::InvalidConfig { .. }));
    }

    #[test]
    fn empty_payload_still_rejects_invalid_repair_overhead() {
        let mut pipeline = EncodingPipeline::new(
            test_config(4, 16, f64::NAN),
            SymbolPool::new(PoolConfig::default()),
        );
        let err = pipeline
            .encode(ObjectId::new_for_test(103), &[])
            .next()
            .unwrap()
            .unwrap_err();
        assert!(matches!(err, EncodingError::InvalidConfig { .. }));
    }

    #[test]
    fn empty_payload_still_rejects_pool_symbol_size_mismatch() {
        let mut pipeline = EncodingPipeline::new(test_config(4, 16, 1.0), pool_for(8, 1));
        let err = pipeline
            .encode(ObjectId::new_for_test(104), &[])
            .next()
            .unwrap()
            .unwrap_err();
        assert!(matches!(err, EncodingError::InvalidConfig { .. }));
    }

    #[test]
    fn encoding_pipeline_stats_and_reset() {
        let mut pipeline = EncodingPipeline::new(
            test_config(4, 16, 1.0),
            SymbolPool::new(PoolConfig::default()),
        );

        let stats = pipeline.stats();
        assert_eq!(stats.bytes_in, 0);

        let _: Vec<_> = pipeline
            .encode(ObjectId::new_for_test(99), b"test")
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let stats = pipeline.stats();
        assert!(stats.source_symbols > 0);

        pipeline.reset();
        let stats = pipeline.stats();
        assert_eq!(stats.bytes_in, 0);
        assert_eq!(stats.source_symbols, 0);
    }
