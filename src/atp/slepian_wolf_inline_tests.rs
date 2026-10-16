    use super::*;
    use crate::atp::delta::{
        ContentAddressedChunkStore, PersistentChunkManifest,
        plan_incremental_resync_from_verified_receiver_manifest,
    };
    use proptest::prelude::*;

    const SMALL_APPEND_LIKE_DELTA_BYTES: usize = 4 * 1024;
    const COMPACT_RECEIVER_SIDECAR_BASELINE_BYTES: usize = 14 * 1024;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct SyndromeSidecarMeasurement {
        append_delta_bytes: usize,
        syndrome_value_bytes: usize,
        receiver_sidecar_baseline_bytes: usize,
    }

    impl SyndromeSidecarMeasurement {
        fn syndrome_minus_sidecar_bytes(self) -> usize {
            self.syndrome_value_bytes
                .saturating_sub(self.receiver_sidecar_baseline_bytes)
        }

        fn sidecar_minus_syndrome_bytes(self) -> usize {
            self.receiver_sidecar_baseline_bytes
                .saturating_sub(self.syndrome_value_bytes)
        }

        fn syndrome_to_sidecar_ratio_milli(self) -> usize {
            self.syndrome_value_bytes * 1000 / self.receiver_sidecar_baseline_bytes
        }
    }

    fn deterministic_append_payload(len: usize) -> Vec<u8> {
        (0..len)
            .map(|idx| ((idx * 19 + idx / 7 + 3) % 251) as u8)
            .collect()
    }

    fn small_append_like_syndrome_sidecar_measurement() -> SyndromeSidecarMeasurement {
        let append = deterministic_append_payload(SMALL_APPEND_LIKE_DELTA_BYTES);
        let shape = LdpcShape::new(append.len(), 0, 1).expect("shape");
        let config = RatelessLdpcConfig::foundation(shape, 0x51de_cafe).expect("config");
        let frame =
            encode_rateless_syndrome(&append, config, shape.n).expect("small append syndrome");

        SyndromeSidecarMeasurement {
            append_delta_bytes: append.len(),
            syndrome_value_bytes: frame.encoded_value_bytes(),
            receiver_sidecar_baseline_bytes: COMPACT_RECEIVER_SIDECAR_BASELINE_BYTES,
        }
    }

    #[test]
    fn localize_chunks_then_rateless_syndrome_decode_round_trips() {
        let old = b"AAabcdefgZZ".to_vec();
        let new = b"AAxbcydZgZZ".to_vec();

        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender_report = sender_store
            .ingest_ordered_chunks([new.as_slice()])
            .expect("sender ingest");
        let receiver_report = receiver_store
            .ingest_ordered_chunks([old.as_slice()])
            .expect("receiver ingest");
        let sender_manifest =
            PersistentChunkManifest::new("tree", sender_report.chunks).expect("sender manifest");
        let receiver_manifest = PersistentChunkManifest::new("tree", receiver_report.chunks)
            .expect("receiver manifest");

        let regions = localize_manifest_changed_regions(
            &sender_manifest,
            &sender_store,
            &receiver_manifest,
            &receiver_store,
        )
        .expect("changed regions");
        assert_eq!(regions.len(), 1);

        let region = &regions[0];
        assert_eq!(region.byte_offset, 2);
        assert_eq!(region.old_bytes, b"abcdef");
        assert_eq!(region.new_bytes, b"xbcydZ");
        let uncertain = region.truth_uncertain_indices();
        assert_eq!(uncertain, vec![0, 3, 4, 5]);

        let shape = LdpcShape::new(
            region.source_symbols(),
            region.source_symbols() - uncertain.len(),
            3,
        )
        .expect("shape");
        assert_eq!(shape.design_syndrome_symbols(), uncertain.len());
        assert_eq!(shape.rate().as_f64(), 2.0 / 6.0);

        let config = RatelessLdpcConfig::foundation(shape, 0x51ed_1d0c).expect("config");
        let frame = encode_rateless_syndrome(&region.new_bytes, config, shape.n).expect("syndrome");
        assert_eq!(frame.schema, ATP_SLEPIAN_WOLF_SYNDROME_SCHEMA);
        assert!(frame.syndrome_weight() > 0);
        assert_eq!(
            frame.floor_gap_report(),
            SyndromeFloorGapReport {
                source_symbols: 6,
                side_info_symbols: 2,
                floor_bytes: 4,
                syndrome_value_bytes: 6,
                gap_bytes: 2,
                gap_over_floor_per_mille: Some(500),
            }
        );

        let decoded = decode_with_side_information(&frame, &region.old_bytes, &uncertain, 1)
            .expect("bp decode");
        assert_eq!(decoded.bytes, region.new_bytes);
        assert!(decoded.report.converged);
        assert_eq!(decoded.report.used_symbols, 6);
        assert_eq!(decoded.report.pulled_symbols, 5);
        assert!(decoded.report.stalled_windows > 0);
        assert_eq!(decoded.report.known_symbols, region.source_symbols());
        assert!(decoded.report.syndrome_weight > 0);
    }

    #[test]
    fn bp_decode_old_file_side_info_recovers_sparse_edits_without_uncertainty_sidecar() {
        let old = b"0123456789abcdef".to_vec();
        let mut new = old.clone();
        new[0] = b'X';
        new[7] = b'Y';
        new[15] = b'Z';

        let changed_symbols = old
            .iter()
            .zip(new.iter())
            .filter(|(old, new)| old != new)
            .count();
        let shape = LdpcShape::new(new.len(), new.len() - changed_symbols, 3).expect("shape");
        let config = RatelessLdpcConfig::foundation(shape, 0xdec0_de01).expect("config");
        let frame = encode_rateless_syndrome(&new, config, shape.n).expect("syndrome");

        let decoded =
            decode_with_old_file_side_information(&frame, &old, shape.design_syndrome_symbols())
                .expect("old-file side-info BP decode");

        assert_eq!(decoded.bytes, new);
        assert!(decoded.report.converged);
        assert_eq!(decoded.report.used_symbols, shape.n);
        assert_eq!(
            decoded.report.pulled_symbols,
            shape.n - shape.design_syndrome_symbols()
        );
        assert!(decoded.report.stalled_windows > 0);
        assert_eq!(decoded.report.known_symbols, shape.n);
        assert!(decoded.report.syndrome_weight > 0);
    }

    #[test]
    fn sidecar_free_missing_append_syndrome_beats_rsync_target() {
        let base = vec![0x31; 5 * 1024 * 1024];
        let append = deterministic_append_payload(64 * 1024);

        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender_report = sender_store
            .ingest_ordered_chunks([base.as_slice(), append.as_slice()])
            .expect("sender ingest");
        let receiver_report = receiver_store
            .ingest_ordered_chunks([base.as_slice()])
            .expect("receiver ingest");
        let sender_manifest =
            PersistentChunkManifest::new("tree", sender_report.chunks).expect("sender manifest");
        let receiver_manifest = PersistentChunkManifest::new("tree", receiver_report.chunks)
            .expect("receiver manifest");

        let delta_plan = plan_incremental_resync_from_verified_receiver_manifest(
            &sender_manifest,
            Some(&receiver_manifest),
        );
        assert_eq!(delta_plan.missing_chunks.len(), 1);
        assert_eq!(delta_plan.missing_bytes, append.len() as u64);

        let syndrome_plan =
            encode_missing_chunk_syndrome_plan(&delta_plan, &sender_store, 0x51de_cafe, 0)
                .expect("syndrome plan");

        assert!(syndrome_plan.is_sidecar_free());
        assert_eq!(syndrome_plan.payload_bytes, append.len() as u64);
        assert_eq!(syndrome_plan.whole_chunk_bytes, append.len() as u64);
        assert!(syndrome_plan.payload_bytes < 96 * 1024);
        assert_eq!(
            syndrome_plan.floor_gap_report(),
            SyndromeFloorGapReport {
                source_symbols: append.len(),
                side_info_symbols: 0,
                floor_bytes: append.len(),
                syndrome_value_bytes: append.len(),
                gap_bytes: 0,
                gap_over_floor_per_mille: Some(0),
            }
        );

        let chunk = &syndrome_plan.chunks[0];
        assert_eq!(chunk.side_info_symbols, 0);
        assert_eq!(chunk.initial_symbols, append.len());
        assert_eq!(chunk.encoded_value_bytes(), append.len());
        assert_eq!(chunk.floor_gap_report(), syndrome_plan.floor_gap_report());
        let decoded = decode_missing_chunk_syndrome(&chunk.frame, chunk.initial_symbols)
            .expect("missing chunk decode");
        assert_eq!(decoded.bytes, append);
    }

    #[test]
    fn small_append_like_syndrome_measurement_beats_compact_sidecar_baseline() {
        let measurement = small_append_like_syndrome_sidecar_measurement();

        assert_eq!(
            measurement.append_delta_bytes,
            SMALL_APPEND_LIKE_DELTA_BYTES
        );
        assert_eq!(measurement.syndrome_value_bytes, 4_096);
        assert_eq!(
            measurement.receiver_sidecar_baseline_bytes,
            COMPACT_RECEIVER_SIDECAR_BASELINE_BYTES
        );
        assert_eq!(measurement.syndrome_minus_sidecar_bytes(), 0);
        assert_eq!(measurement.sidecar_minus_syndrome_bytes(), 10_240);
        assert_eq!(measurement.syndrome_to_sidecar_ratio_milli(), 285);
    }

    #[test]
    fn old_file_side_info_decode_reports_stall_when_rows_are_exhausted() {
        let source = b"wxyz";
        let old = b"abcd";
        let shape = LdpcShape::new(4, 0, 3).expect("shape");
        let config = RatelessLdpcConfig::foundation(shape, 7).expect("config");
        let frame = encode_rateless_syndrome(source, config, 2).expect("syndrome");
        let err = decode_with_old_file_side_information(&frame, old, 1)
            .expect_err("not enough rows to decode all side-info deltas");

        assert_eq!(
            err,
            SlepianWolfError::DecodeStalled {
                known_symbols: 2,
                source_symbols: 4,
                used_symbols: 2,
            }
        );
    }

    #[test]
    fn bp_decode_reports_stall_when_syndrome_window_is_exhausted() {
        let source = b"wxyz";
        let old = b"abcd";
        let shape = LdpcShape::new(4, 0, 3).expect("shape");
        let config = RatelessLdpcConfig::foundation(shape, 7).expect("config");
        let frame = encode_rateless_syndrome(source, config, 2).expect("syndrome");
        let err = decode_with_side_information(&frame, old, &[0, 1, 2, 3], 1)
            .expect_err("not enough rows to decode all erasures");

        assert_eq!(
            err,
            SlepianWolfError::DecodeStalled {
                known_symbols: 2,
                source_symbols: 4,
                used_symbols: 2,
            }
        );
    }

    #[test]
    fn compact_syndrome_wire_frame_round_trips_without_serialized_taps() {
        let old = b"same-prefix-012345".to_vec();
        let mut new = old.clone();
        new[3] = b'X';
        new[14] = b'Y';

        let changed_symbols = old
            .iter()
            .zip(new.iter())
            .filter(|(old, new)| old != new)
            .count();
        let shape = LdpcShape::new(new.len(), new.len() - changed_symbols, 3).expect("shape");
        let config = RatelessLdpcConfig::foundation(shape, 0xfeed_51de).expect("config");
        let frame = encode_rateless_syndrome(&new, config, shape.n).expect("syndrome");

        let wire = frame.to_compact_wire_frame().expect("compact wire frame");
        assert_eq!(wire.values.len(), frame.symbols.len());
        let wire_json = serde_json::to_string(&wire).expect("serialize compact frame");
        assert!(!wire_json.contains("taps"));

        let decoded_wire: CompactRatelessSyndromeFrame =
            serde_json::from_str(&wire_json).expect("deserialize compact frame");
        let restored = decoded_wire
            .into_rateless_syndrome()
            .expect("restore syndrome");
        assert_eq!(restored.shape, frame.shape);
        assert_eq!(restored.seed, frame.seed);
        assert_eq!(restored.min_degree, frame.min_degree);
        assert_eq!(restored.max_degree, frame.max_degree);
        assert_eq!(restored.symbols, frame.symbols);

        let decoded =
            decode_with_old_file_side_information(&restored, &old, shape.design_syndrome_symbols())
                .expect("compact syndrome decodes");
        assert_eq!(decoded.bytes, new);
    }

    #[test]
    fn compact_syndrome_wire_frame_rejects_non_contiguous_rows() {
        let shape = LdpcShape::new(4, 0, 1).expect("shape");
        let config = RatelessLdpcConfig::foundation(shape, 0x51de).expect("config");
        let mut frame = encode_rateless_syndrome(b"abcd", config, 4).expect("syndrome");
        frame.symbols[1].id = 3;

        assert_eq!(
            frame.to_compact_wire_frame(),
            Err(SlepianWolfError::NonContiguousSyndromeRows {
                expected: 1,
                actual: 3,
            })
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 64,
            ..ProptestConfig::default()
        })]

        #[test]
        fn bp_decode_old_file_side_info_converges_for_random_sparse_edits(
            cells in proptest::collection::vec((any::<u8>(), any::<u8>(), any::<bool>()), 1..65),
            seed in any::<u64>(),
        ) {
            let old = cells.iter().map(|(byte, _, _)| *byte).collect::<Vec<_>>();
            let new = cells
                .iter()
                .map(|(old, raw_delta, should_change)| {
                    if *should_change {
                        *old ^ (*raw_delta | 1)
                    } else {
                        *old
                    }
                })
                .collect::<Vec<_>>();
            let changed_symbols = old
                .iter()
                .zip(new.iter())
                .filter(|(old, new)| old != new)
                .count();
            let shape = LdpcShape::new(new.len(), new.len() - changed_symbols, 3).expect("shape");
            let config = RatelessLdpcConfig::foundation(shape, seed).expect("config");
            let frame = encode_rateless_syndrome(&new, config, shape.n).expect("syndrome");

            let decoded =
                decode_with_old_file_side_information(&frame, &old, shape.design_syndrome_symbols())
                    .expect("old-file side-info BP decode");

            prop_assert_eq!(decoded.bytes, new);
            prop_assert!(decoded.report.converged);
            prop_assert_eq!(decoded.report.known_symbols, shape.n);
            prop_assert!(decoded.report.used_symbols <= shape.n);
            prop_assert_eq!(
                decoded.report.pulled_symbols,
                decoded.report.used_symbols.saturating_sub(shape.design_syndrome_symbols())
            );
        }
    }
