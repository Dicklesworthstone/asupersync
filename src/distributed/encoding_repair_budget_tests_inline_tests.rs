    use super::*;
    use crate::distributed::recovery::{RecoveryDecodingConfig, StateDecoder};
    use crate::security::{AuthKey, SecurityContext};
    use crate::types::RegionId;
    use raptorq::{ObjectTransmissionInformation, SourceBlockEncoder};
    use std::collections::BTreeSet;

    fn snapshot_with_size(size: usize) -> RegionSnapshot {
        let mut snapshot = RegionSnapshot::empty(RegionId::new_for_test(37, 0));
        let envelope_size = snapshot.to_bytes().len();
        assert!(size >= envelope_size);
        snapshot.metadata.resize(size - envelope_size, 0);
        DetRng::new(71).fill_bytes(&mut snapshot.metadata);
        assert_eq!(snapshot.to_bytes().len(), size);
        snapshot
    }

    fn config(overhead: f32) -> EncodingConfig {
        EncodingConfig {
            symbol_size: 128,
            min_repair_symbols: 0,
            max_source_blocks: 4,
            repair_overhead: overhead,
            path_quality: None,
        }
    }

    #[test]
    fn overhead_budget_is_total_and_rounded_once_for_uneven_blocks() {
        // 2065 bytes need 17 source symbols. Four actual blocks contain
        // 5, 5, 5, 2 source symbols; no per-block ceil may multiply the budget.
        let snapshot = snapshot_with_size(16 * 128 + 17);
        for (overhead, expected_repairs, per_block) in [
            (1.0, 0, [0, 0, 0, 0]),
            (1.25, 5, [2, 1, 1, 1]),
            (1.5, 9, [3, 2, 2, 2]),
            (2.0, 17, [5, 4, 4, 4]),
        ] {
            let encoded = StateEncoder::new(config(overhead), DetRng::new(42))
                .encode(&snapshot, Time::ZERO)
                .unwrap();
            assert_eq!(encoded.source_count, 17);
            assert_eq!(encoded.repair_count, expected_repairs);
            assert_eq!(encoded.params.source_blocks, 4);
            assert_eq!(encoded.symbols.len(), 17 + usize::from(expected_repairs));
            assert_eq!(rebuild_source_bytes(&encoded), snapshot.to_bytes());
            for (block, expected) in per_block.into_iter().enumerate() {
                let repairs = encoded
                    .repair_symbols()
                    .filter(|symbol| usize::from(symbol.id().sbn()) == block)
                    .map(|symbol| symbol.id().esi())
                    .collect::<Vec<_>>();
                let source_count = [5, 5, 5, 2][block];
                assert_eq!(repairs, (source_count..source_count + expected).collect::<Vec<_>>());
            }
        }
    }

    #[test]
    fn overhead_budget_preserves_minimum_and_adaptive_floors() {
        let snapshot = snapshot_with_size(16 * 128);
        let severe = Some(PathQualitySnapshot::new(400, 300, 32));
        for (overhead, minimum, quality, expected_floor, expected_repairs) in [
            (1.0, 0, None, 0, 0),
            (1.125, 3, None, 3, 3),
            (1.125, 3, severe, 8, 8),
            (2.0, 3, severe, 8, 16),
            (1.0, 0, severe, 3, 3),
        ] {
            let mut settings = config(overhead);
            settings.min_repair_symbols = minimum;
            settings.path_quality = quality;
            let encoded = StateEncoder::new(settings, DetRng::new(43))
                .encode(&snapshot, Time::ZERO)
                .unwrap();
            assert_eq!(encoded.source_count, 16);
            assert_eq!(encoded.layout_decision.effective_min_repair_symbols, expected_floor);
            assert_eq!(encoded.repair_count, expected_repairs);
            assert_eq!(encoded.repair_symbols().count(), usize::from(expected_repairs));
        }
    }

    #[test]
    fn overhead_budget_uses_the_configured_f32_value_without_rounding_down() {
        // 1.2_f32 represents a value slightly above 1.2. Five source
        // symbols therefore need two repairs to meet that exact configured
        // bound. Widening before multiplication intentionally preserves it.
        let encoded = StateEncoder::new(config(1.2), DetRng::new(44))
            .encode(&snapshot_with_size(5 * 128), Time::ZERO)
            .unwrap();
        assert!(f64::from(1.2_f32) > 1.2_f64);
        assert_eq!(encoded.source_count, 5);
        assert_eq!(encoded.repair_count, 2);
    }

    #[test]
    fn overhead_budget_rejects_invalid_and_unrepresentable_requests() {
        let snapshot = snapshot_with_size(16 * 128);
        for overhead in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, -1.0, 0.999] {
            let error = StateEncoder::new(config(overhead), DetRng::new(45))
                .encode(&snapshot, Time::ZERO)
                .unwrap_err();
            assert_eq!(error, EncodingError::InvalidConfig {
                reason: "repair_overhead must be finite and >= 1.0".to_string(),
            });
        }
        for overhead in [4097.0, f32::MAX] {
            let error = StateEncoder::new(config(overhead), DetRng::new(46))
                .encode(&snapshot, Time::ZERO)
                .unwrap_err();
            assert_eq!(error, EncodingError::InvalidConfig {
                reason: "repair_overhead requires more than 65535 repair symbols".to_string(),
            });
        }
        assert_eq!(total_repair_budget(u16::MAX, 2.0, 0), Ok(u16::MAX));
        assert_eq!(total_repair_budget(1, 1.0, u16::MAX), Ok(u16::MAX));
        assert!(total_repair_budget(u16::MAX, 2.000_001, 0).is_err());

        let error = StateEncoder::new(EncodingConfig {
            symbol_size: 1,
            max_source_blocks: 256,
            ..config(1.0)
        }, DetRng::new(47))
        .encode(&snapshot_with_size(65536), Time::ZERO)
        .unwrap_err();
        assert_eq!(error, EncodingError::SymbolCountOverflow {
            field: "source_count", value: 65536, max: 65535,
        });

        let error = StateEncoder::new(EncodingConfig {
            max_source_blocks: 257,
            ..config(1.0)
        }, DetRng::new(48))
        .encode(&snapshot_with_size(257 * 128), Time::ZERO)
        .unwrap_err();
        assert_eq!(error, EncodingError::SymbolCountOverflow {
            field: "source_blocks", value: 257, max: 256,
        });
    }

    #[test]
    fn overhead_repairs_recover_authenticated_snapshot_after_multiblock_erasure() {
        let snapshot_key = AuthKey::from_seed(75);
        let security = SecurityContext::new(AuthKey::from_seed(76));
        let snapshot = snapshot_with_size(32 * 128).signed(&snapshot_key);
        let encoded = StateEncoder::new(config(2.0), DetRng::new(49))
            .encode(&snapshot, Time::ZERO)
            .unwrap();
        assert_eq!((encoded.source_count, encoded.repair_count), (32, 32));
        assert_eq!(encoded.params.source_blocks, 4);

        let mut decoder = StateDecoder::new(RecoveryDecodingConfig {
            auth_context: Some(security.clone()),
            snapshot_auth_key: Some(snapshot_key.clone()),
            ..Default::default()
        });
        let mut source_only = StateDecoder::new(RecoveryDecodingConfig {
            auth_context: Some(security.clone()),
            snapshot_auth_key: Some(snapshot_key),
            ..Default::default()
        });
        let mut lost_by_block = [0; 4];
        for symbol in &encoded.symbols {
            if symbol.kind().is_source() && symbol.id().esi() < 2 {
                lost_by_block[usize::from(symbol.id().sbn())] += 1;
                continue;
            }
            let authenticated = security.sign_symbol(symbol);
            decoder.add_symbol(&authenticated).unwrap();
            if symbol.kind().is_source() {
                source_only.add_symbol(&authenticated).unwrap();
            }
        }
        assert_eq!(lost_by_block, [2, 2, 2, 2]);
        assert_eq!(source_only.symbols_received(), 24);
        assert!(source_only.decode_snapshot(&encoded.params).is_err());
        let recovered = decoder.decode_snapshot(&encoded.params).unwrap();
        assert_eq!(recovered.to_bytes(), snapshot.to_bytes());
    }

    #[test]
    fn repair_continuation_skips_sparse_prefix_and_matches_independent_encoder() {
        let snapshot = snapshot_with_size(16 * 128 + 17);
        let mut encoder = StateEncoder::new(config(2.0), DetRng::new(50));
        let mut encoded = encoder.encode(&snapshot, Time::ZERO).unwrap();
        let last_esi = [9, 8, 8, 5];
        encoded.symbols.retain(|symbol| symbol.kind().is_source()
            || symbol.id().esi() == last_esi[usize::from(symbol.id().sbn())]);
        encoded.repair_count = 4;
        let additional = encoder.generate_repair(&encoded, 7).unwrap();
        assert_eq!(additional.len(), 7);
        let expected_esis = [vec![10, 11], vec![9, 10], vec![9, 10], vec![6]];
        for (block, expected) in expected_esis.into_iter().enumerate() {
            let generated = additional.iter()
                .filter(|symbol| usize::from(symbol.id().sbn()) == block)
                .collect::<Vec<_>>();
            assert_eq!(generated.iter().map(|symbol| symbol.id().esi()).collect::<Vec<_>>(), expected);
            let source_bytes = encoded.source_symbols()
                .filter(|symbol| usize::from(symbol.id().sbn()) == block)
                .flat_map(|symbol| symbol.data().iter().copied())
                .collect::<Vec<_>>();
            let reference_config = ObjectTransmissionInformation::new(
                u64::try_from(source_bytes.len()).unwrap(), 128, 1, 1, 1,
            );
            let reference = SourceBlockEncoder::new(0, &reference_config, &source_bytes);
            let first = expected[0] - u32::try_from(source_bytes.len() / 128).unwrap();
            let reference_repairs = reference.repair_packets(first, u32::try_from(expected.len()).unwrap());
            for (actual, expected) in generated.into_iter().zip(reference_repairs) {
                assert_eq!(actual.id().esi(), expected.payload_id().encoding_symbol_id());
                assert_eq!(actual.data(), expected.data());
            }
        }
        encoded.symbols.extend(additional);
        encoded.repair_count += 7;
        let second = encoder.generate_repair(&encoded, 4).unwrap();
        assert_eq!(second.iter().map(|symbol| symbol.id().esi()).collect::<Vec<_>>(), [12, 11, 11, 7]);
        let mut ids = encoded.symbols.iter().map(Symbol::id).collect::<BTreeSet<_>>();
        for symbol in second {
            assert!(ids.insert(symbol.id()), "continuation must not duplicate retained ESIs");
        }
        assert!(encoder.generate_repair(&encoded, 0).unwrap().is_empty());
    }

    #[test]
    fn repair_continuation_refuses_invalid_source_shape_and_rfc_esi_exhaustion() {
        let snapshot = snapshot_with_size(5 * 128);
        let mut encoder = StateEncoder::new(EncodingConfig {
            max_source_blocks: 1, ..config(1.0)
        }, DetRng::new(51));
        for defect in 0..6 {
            let mut state = encoder.encode(&snapshot, Time::ZERO).unwrap();
            let source = state.symbols[0].clone();
            match defect {
                0 => state.params.object_size += 1,
                1 => state.symbols[0] = Symbol::new(
                    SymbolId::new(ObjectId::new_for_test(999), 0, 0),
                    source.into_data(), SymbolKind::Source,
                ),
                2 => state.symbols[0] = Symbol::new(
                    source.id(), vec![0; 127], SymbolKind::Source,
                ),
                3 => state.symbols.push(Symbol::new(
                    SymbolId::new(state.params.object_id, 0, 4),
                    vec![0; 128], SymbolKind::Repair,
                )),
                4 => state.symbols.push(Symbol::new(
                    SymbolId::new(state.params.object_id, 0, u32::MAX),
                    vec![0; 128], SymbolKind::Repair,
                )),
                5 => {
                    // K=5 maps to K'=10, so u32::MAX-5 is the last valid
                    // repair ESI. A request after it must return an error,
                    // before the lower-level encoder's panicking ESI API.
                    state.symbols.push(Symbol::new(
                        SymbolId::new(state.params.object_id, 0, u32::MAX - 5),
                        vec![0; 128], SymbolKind::Repair,
                    ));
                }
                _ => unreachable!(),
            }
            let error = encoder.generate_repair(&state, 1).unwrap_err();
            if defect == 5 {
                assert_eq!(error, EncodingError::InvalidConfig {
                    reason: "repair ESI range in block 0 exceeds the RFC encoding limit".to_string(),
                });
            } else {
                assert!(matches!(error, EncodingError::Pipeline(_)), "defect {defect}: {error}");
            }
        }
    }
