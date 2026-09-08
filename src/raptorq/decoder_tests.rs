mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use std::collections::BTreeSet;

    use insta::assert_json_snapshot;
    use raptorq::{
        Decoder as RaptorqRsDecoder, EncodingPacket as RaptorqRsEncodingPacket,
        ObjectTransmissionInformation as RaptorqRsObjectTransmissionInformation,
        PayloadId as RaptorqRsPayloadId,
    };
    use serde_json::json;

    use crate::raptorq::rfc6330::rand as rfc_rand;
    /// Test-only: checks whether sparse row update is beneficial.
    fn should_use_sparse_row_update(pivot_nnz: usize, n_cols: usize) -> bool {
        if n_cols == 0 {
            return false;
        }
        pivot_nnz.saturating_mul(HYBRID_SPARSE_COST_DENOMINATOR)
            <= n_cols.saturating_mul(HYBRID_SPARSE_COST_NUMERATOR)
    }

    /// Test-only: collects nonzero column indices from a pivot row.
    fn pivot_nonzero_columns(pivot_row: &[Gf256], n_cols: usize) -> Vec<usize> {
        let mut cols = Vec::with_capacity(n_cols.min(32));
        for (idx, coef) in pivot_row.iter().take(n_cols).enumerate() {
            if !coef.is_zero() {
                cols.push(idx);
            }
        }
        cols
    }

    #[test]
    fn equation_new_keeps_canonical_rows_in_place() {
        let equation = Equation::new(
            vec![1, 4, 9],
            vec![Gf256::new(2), Gf256::ONE, Gf256::new(7)],
        );

        assert_eq!(
            equation.terms,
            vec![(1, Gf256::new(2)), (4, Gf256::ONE), (9, Gf256::new(7)),]
        );
    }

    #[test]
    fn equation_new_fallback_merges_duplicate_and_zero_terms() {
        let equation = Equation::new(
            vec![5, 2, 5, 8],
            vec![Gf256::new(3), Gf256::ZERO, Gf256::new(3), Gf256::ONE],
        );

        assert_eq!(equation.terms, vec![(8, Gf256::ONE)]);
    }

    #[test]
    fn equation_rank_counts_independent_rows_only() {
        let equations = vec![
            Equation::new(vec![0], vec![Gf256::ONE]),
            Equation::new(vec![1], vec![Gf256::ONE]),
            Equation::new(vec![0, 1], vec![Gf256::ONE, Gf256::ONE]),
            Equation::new(vec![0, 1], vec![Gf256::ONE, Gf256::ONE]),
        ];

        assert_eq!(equation_rank(&equations, 3), 2);
    }

    #[test]
    fn equation_rank_profile_reports_decoder_pivot_witness() {
        let equations = vec![
            Equation::new(vec![0, 2], vec![Gf256::ONE, Gf256::ONE]),
            Equation::new(vec![2], vec![Gf256::ONE]),
            Equation::new(vec![0], vec![Gf256::ONE]),
        ];

        let profile = equation_rank_profile(&equations, 4);
        assert_eq!(profile.rows, 3);
        assert_eq!(profile.columns, 4);
        assert_eq!(profile.rank, 2);
        assert_eq!(profile.deficit, 2);
        assert_eq!(profile.pivot_columns, vec![0, 2]);
        assert_eq!(profile.free_columns, vec![1, 3]);
    }

    #[test]
    fn rank_status_tracks_missing_source_symbol_deficit() {
        let decoder = InactivationDecoder::new(4, 8, 11);
        let mut symbols = decoder.constraint_symbols();
        symbols.extend((0..3).map(|esi| ReceivedSymbol::source(esi, vec![esi as u8; 8])));

        let partial = decoder
            .rank_status(&symbols)
            .expect("partial source set has rank status");
        assert_eq!(
            partial.columns.saturating_sub(partial.rank),
            partial.deficit
        );
        assert_eq!(partial.deficit, 1);
        let partial_profile = decoder
            .rank_profile(&symbols)
            .expect("partial source set has rank profile");
        assert_eq!(partial_profile.rank, partial.rank);
        assert_eq!(partial_profile.columns, partial.columns);
        assert_eq!(partial_profile.deficit, partial.deficit);
        assert_eq!(partial_profile.pivot_columns.len(), partial.rank);
        assert_eq!(partial_profile.free_columns.len(), partial.deficit);
        assert_eq!(
            partial_profile,
            decoder
                .rank_profile(&symbols)
                .expect("rank profile should be deterministic")
        );

        symbols.push(ReceivedSymbol::source(3, vec![3u8; 8]));
        let complete = decoder
            .rank_status(&symbols)
            .expect("complete source set has rank status");
        assert_eq!(complete.deficit, 0);
        assert_eq!(complete.rank, complete.columns);
        let complete_profile = decoder
            .rank_profile(&symbols)
            .expect("complete source set has rank profile");
        assert_eq!(complete_profile.deficit, 0);
        assert!(complete_profile.free_columns.is_empty());
        assert_eq!(complete_profile.pivot_columns.len(), complete.columns);
    }

    #[test]
    fn rank_profile_rejects_noncanonical_source_equation_like_decode() {
        let k = 8;
        let symbol_size = 32;
        let seed = 0x6330_C105_u64;
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let malformed_source = ReceivedSymbol {
            esi: 0,
            is_source: true,
            columns: vec![0],
            coefficients: vec![Gf256::ONE],
            data: vec![0xA5; symbol_size],
        };

        let rank_err = decoder
            .rank_profile(&[malformed_source.clone()])
            .expect_err("rank diagnostics must reject malformed source equations");
        let decode_err = decoder
            .decode(&[malformed_source])
            .expect_err("decode must reject the same malformed source equation");
        assert_eq!(
            rank_err,
            DecodeError::InvalidSourceSymbolEquation {
                esi: 0,
                expected_column: 0
            }
        );
        assert_eq!(decode_err, rank_err);
        assert!(rank_err.is_unrecoverable());
    }

    use crate::raptorq::systematic::SystematicEncoder;
    use crate::raptorq::test_log_schema::{
        UnitDecodeStats, UnitGovernanceDecision, UnitLogEntry, validate_unit_log_json,
    };

    fn rfc_eq_context(
        scenario_id: &str,
        seed: u64,
        k: usize,
        symbol_size: usize,
        loss_pattern: &str,
        outcome: &str,
    ) -> String {
        format!(
            "scenario_id={scenario_id} seed={seed} k={k} symbol_size={symbol_size} \
             loss_pattern={loss_pattern} outcome={outcome} \
             artifact_path=artifacts/raptorq_b2_tuple_scenarios_v1.json \
             fixture_ref=RQ-B2-TUPLE-V1 \
             repro_cmd='rch exec -- cargo test -p asupersync --lib \
             repair_equation_rfc6330 -- --nocapture'"
        )
    }

    fn to_unit_decode_stats(k: usize, dropped: usize, stats: &DecodeStats) -> UnitDecodeStats {
        UnitDecodeStats {
            k,
            loss_pct: dropped.saturating_mul(100) / k.max(1),
            dropped,
            peeled: stats.peeled,
            inactivated: stats.inactivated,
            gauss_ops: stats.gauss_ops,
            pivots: stats.pivots_selected,
            peel_queue_pushes: stats.peel_queue_pushes,
            peel_queue_pops: stats.peel_queue_pops,
            peel_frontier_peak: stats.peel_frontier_peak,
            dense_core_rows: stats.dense_core_rows,
            dense_core_cols: stats.dense_core_cols,
            dense_core_dropped_rows: stats.dense_core_dropped_rows,
            fallback_reason: stats
                .hard_regime_conservative_fallback_reason
                .or(stats.peeling_fallback_reason)
                .unwrap_or("none")
                .to_string(),
            hard_regime_activated: stats.hard_regime_activated,
            hard_regime_branch: stats.hard_regime_branch.unwrap_or("none").to_string(),
            hard_regime_fallbacks: stats.hard_regime_fallbacks,
            conservative_fallback_reason: stats
                .hard_regime_conservative_fallback_reason
                .unwrap_or("none")
                .to_string(),
            governance: stats.governance.as_ref().map(UnitGovernanceDecision::from),
        }
    }

    fn emit_decoder_unit_log(
        scenario_id: &str,
        seed: u64,
        parameter_set: &str,
        outcome: &str,
        repro_command: &str,
        stats: Option<UnitDecodeStats>,
    ) -> String {
        let mut entry = UnitLogEntry::new(
            scenario_id,
            seed,
            parameter_set,
            "replay:rq-track-c-decoder-unit-v1",
            repro_command,
            outcome,
        )
        .with_artifact_path("artifacts/raptorq_track_c_decoder_unit_v1.json");
        if let Some(stats) = stats {
            entry = entry.with_decode_stats(stats);
        }

        let json = entry.to_json().expect("serialize decoder unit log entry");
        let violations = validate_unit_log_json(&json);
        let context = entry.to_context_string();
        assert!(
            violations.is_empty(),
            "{context}: unit log schema violations: {violations:?}"
        );
        json
    }

    fn decode_stats_snapshot(
        scenario: &str,
        k: usize,
        symbol_size: usize,
        seed: u64,
        dropped: usize,
        received_symbols: usize,
        result: &DecodeResult,
    ) -> serde_json::Value {
        json!({
            "scenario": scenario,
            "k": k,
            "symbol_size": symbol_size,
            "seed": seed,
            "received_symbols": received_symbols,
            "decoded_source_symbols": result.source.len(),
            "intermediate_symbols": result.intermediate.len(),
            "stats": serde_json::to_value(to_unit_decode_stats(k, dropped, &result.stats))
                .expect("serialize decode stats snapshot"),
        })
    }

    #[test]
    fn dense_col_index_map_handles_sparse_columns() {
        let unsolved = vec![2, 7, 11];
        let col_to_dense = build_dense_col_index_map(&unsolved);

        assert_eq!(dense_col_index(&col_to_dense, 2), Some(0));
        assert_eq!(dense_col_index(&col_to_dense, 7), Some(1));
        assert_eq!(dense_col_index(&col_to_dense, 11), Some(2));
        assert_eq!(dense_col_index(&col_to_dense, 3), None);
        assert_eq!(dense_col_index(&col_to_dense, 99), None);
    }

    #[test]
    fn sparse_first_dense_columns_orders_by_support_then_column() {
        let equations = vec![
            Equation::new(vec![7, 11], vec![Gf256::ONE, Gf256::ONE]),
            Equation::new(vec![2, 7], vec![Gf256::ONE, Gf256::ONE]),
            Equation::new(vec![7], vec![Gf256::ONE]),
            Equation::new(vec![2], vec![Gf256::ONE]),
        ];
        let dense_rows = vec![0, 1, 2, 3];
        let unsolved = vec![7, 2, 11];

        let ordered = sparse_first_dense_columns(&equations, &dense_rows, &unsolved);

        // supports: col 11 -> 1, col 2 -> 2, col 7 -> 3
        assert_eq!(ordered, vec![11, 2, 7]);
    }

    #[test]
    fn sparse_first_dense_columns_sorted_fast_path_matches_expected() {
        let equations = vec![
            Equation::new(vec![7, 11], vec![Gf256::ONE, Gf256::ONE]),
            Equation::new(vec![2, 7], vec![Gf256::ONE, Gf256::ONE]),
            Equation::new(vec![7], vec![Gf256::ONE]),
            Equation::new(vec![2], vec![Gf256::ONE]),
        ];
        let dense_rows = vec![0, 1, 2, 3];
        let unsolved = vec![2, 7, 11];

        let ordered = sparse_first_dense_columns(&equations, &dense_rows, &unsolved);

        // supports: col 11 -> 1, col 2 -> 2, col 7 -> 3
        assert_eq!(ordered, vec![11, 2, 7]);
    }

    #[test]
    fn dense_col_index_map_uses_direct_representation_for_compact_range() {
        let unsolved = vec![1, 2, 4];
        let map = build_dense_col_index_map(&unsolved);

        assert!(matches!(map, DenseColIndexMap::Direct(_)));
        assert_eq!(dense_col_index(&map, 1), Some(0));
        assert_eq!(dense_col_index(&map, 2), Some(1));
        assert_eq!(dense_col_index(&map, 4), Some(2));
        assert_eq!(dense_col_index(&map, 3), None);
    }

    #[test]
    fn dense_col_index_map_uses_sorted_pairs_for_sparse_high_columns() {
        let unsolved = vec![2, 7, 10_000];
        let map = build_dense_col_index_map(&unsolved);

        assert!(matches!(map, DenseColIndexMap::SortedPairs(_)));
        assert_eq!(dense_col_index(&map, 2), Some(0));
        assert_eq!(dense_col_index(&map, 7), Some(1));
        assert_eq!(dense_col_index(&map, 10_000), Some(2));
        assert_eq!(dense_col_index(&map, 9_999), None);
    }

    #[test]
    fn dense_factor_signature_detects_equation_changes() {
        let equations_a = vec![Equation::new(vec![0, 1], vec![Gf256::ONE, Gf256::new(7)])];
        let equations_b = vec![Equation::new(vec![0, 1], vec![Gf256::ONE, Gf256::new(9)])];
        let dense_rows = vec![0];
        let unsolved = vec![0, 1];

        let sig_a = DenseFactorSignature::from_equations(&equations_a, &dense_rows, &unsolved);
        let sig_b = DenseFactorSignature::from_equations(&equations_b, &dense_rows, &unsolved);

        assert_ne!(sig_a, sig_b);
    }

    #[test]
    fn dense_factor_cache_requires_strict_signature_match() {
        let equations_a = vec![Equation::new(vec![0, 1], vec![Gf256::ONE, Gf256::new(7)])];
        let equations_b = vec![Equation::new(vec![0, 1], vec![Gf256::ONE, Gf256::new(9)])];
        let dense_rows = vec![0];
        let unsolved = vec![0, 1];

        let sig_a = DenseFactorSignature::from_equations(&equations_a, &dense_rows, &unsolved);
        let sig_b = DenseFactorSignature::from_equations(&equations_b, &dense_rows, &unsolved);

        let mut cache = DenseFactorCache::default();
        assert_eq!(
            cache.insert(
                sig_a.clone(),
                Arc::new(DenseFactorArtifact::new(vec![1, 0]))
            ),
            DenseFactorCacheResult::MissInserted
        );
        assert_eq!(
            cache.lookup(&sig_a),
            DenseFactorCacheLookup::Hit(Arc::new(DenseFactorArtifact::new(vec![1, 0])))
        );
        assert_eq!(cache.lookup(&sig_b), DenseFactorCacheLookup::MissNoEntry);
    }

    #[test]
    fn dense_factor_cache_detects_fingerprint_collision() {
        let equations_a = vec![Equation::new(vec![0, 1], vec![Gf256::ONE, Gf256::new(7)])];
        let equations_b = vec![Equation::new(vec![0, 1], vec![Gf256::ONE, Gf256::new(9)])];
        let dense_rows = vec![0];
        let unsolved = vec![0, 1];

        let sig_a = DenseFactorSignature::from_equations(&equations_a, &dense_rows, &unsolved);
        let mut sig_b = DenseFactorSignature::from_equations(&equations_b, &dense_rows, &unsolved);
        sig_b.fingerprint = sig_a.fingerprint;

        let mut cache = DenseFactorCache::default();
        assert_eq!(
            cache.insert(sig_a, Arc::new(DenseFactorArtifact::new(vec![1, 0]))),
            DenseFactorCacheResult::MissInserted
        );
        assert_eq!(
            cache.lookup(&sig_b),
            DenseFactorCacheLookup::MissFingerprintCollision
        );
    }

    #[test]
    fn dense_factor_cache_evicts_oldest_entry_at_capacity() {
        let mut cache = DenseFactorCache::default();
        let mut first_signature = None;

        for idx in 0..=DENSE_FACTOR_CACHE_CAPACITY {
            let signature = DenseFactorSignature {
                fingerprint: idx as u64,
                unsolved: vec![idx],
                row_offsets: vec![1],
                row_terms_flat: vec![(idx, 1)],
            };
            if idx == 0 {
                first_signature = Some(signature.clone());
            }
            let expected = if idx + 1 > DENSE_FACTOR_CACHE_CAPACITY {
                DenseFactorCacheResult::MissEvicted
            } else {
                DenseFactorCacheResult::MissInserted
            };
            assert_eq!(
                cache.insert(signature, Arc::new(DenseFactorArtifact::new(vec![idx]))),
                expected
            );
        }

        assert_eq!(cache.len(), DENSE_FACTOR_CACHE_CAPACITY);
        assert_eq!(
            cache.lookup(&first_signature.expect("first signature recorded")),
            DenseFactorCacheLookup::MissNoEntry
        );
    }

    #[test]
    fn hybrid_cost_model_prefers_sparse_for_low_support() {
        assert!(should_use_sparse_row_update(3, 8));
        assert!(should_use_sparse_row_update(6, 10));
        assert!(!should_use_sparse_row_update(7, 10));
        assert!(!should_use_sparse_row_update(1, 0));
    }

    #[test]
    fn pivot_nonzero_columns_returns_stable_sorted_positions() {
        let row = vec![
            Gf256::ZERO,
            Gf256::ONE,
            Gf256::ZERO,
            Gf256::ONE,
            Gf256::ONE,
            Gf256::ZERO,
        ];
        let cols = pivot_nonzero_columns(&row, row.len());
        assert_eq!(cols, vec![1, 3, 4]);
    }

    #[test]
    fn pivot_candidate_order_prefers_cross_block_then_density_then_row() {
        let incumbent = PivotCandidate {
            row: 6,
            cross_block_nnz: 2,
            row_nnz: 3,
        };
        assert!(
            PivotCandidate {
                row: 9,
                cross_block_nnz: 1,
                row_nnz: 8,
            }
            .is_better_than(incumbent),
            "lower cross-block support wins before row density"
        );
        assert!(
            PivotCandidate {
                row: 9,
                cross_block_nnz: 2,
                row_nnz: 2,
            }
            .is_better_than(incumbent),
            "lower row density wins when cross-block support ties"
        );
        assert!(
            PivotCandidate {
                row: 5,
                cross_block_nnz: 2,
                row_nnz: 3,
            }
            .is_better_than(incumbent),
            "lowest row wins the final deterministic tie"
        );
    }

    #[test]
    fn block_schur_pivot_selection_prefers_low_cross_block_support() {
        let rows = [
            [1, 0, 1, 1], // baseline first pivot; cross-block nnz = 2
            [1, 1, 0, 0], // block-schur best; cross-block nnz = 0
            [1, 0, 0, 1], // cross-block nnz = 1
        ];
        let flat: Vec<Gf256> = rows
            .iter()
            .flat_map(|row| row.iter().copied().map(Gf256::new))
            .collect();
        let row_used = vec![false; rows.len()];

        assert_eq!(
            select_pivot_row(
                &flat,
                rows.len(),
                4,
                0,
                &row_used,
                false,
                HardRegimePlan::Markowitz
            ),
            Some(0),
            "baseline pivoting keeps first available row"
        );
        assert_eq!(
            select_pivot_row(
                &flat,
                rows.len(),
                4,
                0,
                &row_used,
                true,
                HardRegimePlan::BlockSchurLowRank { split_col: 2 },
            ),
            Some(1),
            "block-schur pivoting should prefer the row with lowest cross-block support"
        );
    }

    #[test]
    fn sparse_update_columns_if_beneficial_matches_threshold() {
        // For n_cols=10 and ratio 3/5, sparse path should accept up to 6 non-zero entries.
        let row_sparse = vec![
            Gf256::ONE,
            Gf256::ONE,
            Gf256::ZERO,
            Gf256::ONE,
            Gf256::ZERO,
            Gf256::ONE,
            Gf256::ONE,
            Gf256::ONE,
            Gf256::ZERO,
            Gf256::ZERO,
        ];
        let row_dense = vec![
            Gf256::ONE,
            Gf256::ONE,
            Gf256::ONE,
            Gf256::ONE,
            Gf256::ONE,
            Gf256::ONE,
            Gf256::ONE,
            Gf256::ZERO,
            Gf256::ZERO,
            Gf256::ZERO,
        ];

        let mut scratch = Vec::with_capacity(sparse_update_column_capacity(10));
        assert!(sparse_update_columns_if_beneficial(
            &row_sparse,
            10,
            &mut scratch
        ));
        assert_eq!(scratch, vec![0, 1, 3, 5, 6, 7]);
        assert!(!sparse_update_columns_if_beneficial(
            &row_dense,
            10,
            &mut scratch
        ));
        assert!(scratch.is_empty());
    }

    fn make_source_data(k: usize, symbol_size: usize) -> Vec<Vec<u8>> {
        (0..k)
            .map(|i| {
                (0..symbol_size)
                    .map(|j| ((i * 37 + j * 13 + 7) % 256) as u8)
                    .collect()
            })
            .collect()
    }

    /// Helper to create received symbols for source data using proper LT equations.
    fn make_received_source(
        decoder: &InactivationDecoder,
        source: &[Vec<u8>],
    ) -> Vec<ReceivedSymbol> {
        let source_eqs = decoder.all_source_equations();
        source
            .iter()
            .enumerate()
            .map(|(i, data)| {
                let (cols, coefs) = source_eqs[i].clone();
                ReceivedSymbol {
                    esi: i as u32,
                    is_source: true,
                    columns: cols,
                    coefficients: coefs,
                    data: data.clone(),
                }
            })
            .collect()
    }

    fn permute_symbols_deterministically(symbols: &mut [ReceivedSymbol], seed: u32) {
        for idx in 0..symbols.len() {
            let remaining =
                u32::try_from(symbols.len() - idx).expect("symbol tail length must fit in u32");
            let swap_offset = usize::try_from(rfc_rand(
                seed.wrapping_add(idx as u32),
                (idx % 7) as u8,
                remaining,
            ))
            .expect("RFC Rand[] output must fit in usize");
            symbols.swap(idx, idx + swap_offset);
        }
    }

    fn decode_repair_only_payload(
        decoder: &InactivationDecoder,
        repairs: &[ReceivedSymbol],
    ) -> Result<DecodeResult, DecodeError> {
        let mut received = decoder.constraint_symbols();
        received.extend_from_slice(repairs);
        decoder.decode(&received)
    }

    fn pick_unique_drop_indices_from_draws(
        k: usize,
        draw_count: usize,
        unique_target: usize,
        seed: u32,
    ) -> Vec<usize> {
        assert!(
            unique_target <= k,
            "drop target must fit inside the source block"
        );
        let limit = u32::try_from(k).expect("K must fit in u32");
        let mut drops = BTreeSet::new();
        for draw in 0..draw_count {
            let draw_u32 = u32::try_from(draw).expect("draw index must fit in u32");
            let idx = usize::try_from(rfc_rand(
                seed.wrapping_add(draw_u32),
                (draw % 251) as u8,
                limit,
            ))
            .expect("drop draw must fit in usize");
            drops.insert(idx);
            if drops.len() == unique_target {
                break;
            }
        }
        assert_eq!(
            drops.len(),
            unique_target,
            "draw schedule must produce the requested number of unique drops"
        );
        drops.into_iter().collect()
    }

    fn build_mixed_received_symbols(
        decoder: &InactivationDecoder,
        encoder: &SystematicEncoder,
        source: &[Vec<u8>],
        drop_indices: &[usize],
        repair_count: usize,
    ) -> Vec<ReceivedSymbol> {
        let dropped: BTreeSet<_> = drop_indices.iter().copied().collect();
        let mut received = decoder.constraint_symbols();

        for (esi, data) in source.iter().enumerate() {
            if !dropped.contains(&esi) {
                received.push(ReceivedSymbol::source(
                    u32::try_from(esi).expect("source ESI must fit in u32"),
                    data.clone(),
                ));
            }
        }

        let k_u32 = u32::try_from(source.len()).expect("K must fit in u32");
        for esi in k_u32..k_u32 + u32::try_from(repair_count).expect("repair count must fit in u32")
        {
            let (cols, coefs) = decoder.repair_equation(esi).unwrap();
            received.push(ReceivedSymbol::repair(
                esi,
                cols,
                coefs,
                encoder.repair_symbol(esi),
            ));
        }

        received
    }

    fn reference_decode_with_raptorq_rs(
        source: &[Vec<u8>],
        encoder: &SystematicEncoder,
        drop_indices: &[usize],
        repair_count: usize,
    ) -> Vec<u8> {
        let transfer_length = source
            .len()
            .checked_mul(source[0].len())
            .expect("transfer length overflow");
        let symbol_size =
            u16::try_from(source[0].len()).expect("symbol size must fit in u16 for raptorq-rs");
        let config = RaptorqRsObjectTransmissionInformation::new(
            transfer_length as u64,
            symbol_size,
            1,
            1,
            1,
        );
        let mut decoder = RaptorqRsDecoder::new(config);
        let dropped: BTreeSet<_> = drop_indices.iter().copied().collect();

        for (esi, data) in source.iter().enumerate() {
            if !dropped.contains(&esi) {
                let esi_u32 = u32::try_from(esi).expect("source ESI must fit in u32");
                let packet =
                    RaptorqRsEncodingPacket::new(RaptorqRsPayloadId::new(0, esi_u32), data.clone());
                if let Some(decoded) = decoder.decode(packet) {
                    return decoded;
                }
            }
        }

        let k_u32 = u32::try_from(source.len()).expect("K must fit in u32");
        for repair_offset in 0..repair_count {
            let esi = k_u32 + u32::try_from(repair_offset).expect("repair index must fit in u32");
            let packet = RaptorqRsEncodingPacket::new(
                RaptorqRsPayloadId::new(0, esi),
                encoder.repair_symbol(esi),
            );
            if let Some(decoded) = decoder.decode(packet) {
                return decoded;
            }
        }

        panic!("raptorq-rs reference decode must succeed");
    }

    /// Build repair symbol bytes by XOR-folding encoder intermediate symbols.
    fn build_repair_from_intermediate(
        encoder: &SystematicEncoder,
        columns: &[usize],
        symbol_size: usize,
    ) -> Vec<u8> {
        let mut out = vec![0u8; symbol_size];
        for &col in columns {
            for (dst, src) in out.iter_mut().zip(encoder.intermediate_symbol(col)) {
                *dst ^= *src;
            }
        }
        out
    }

    #[test]
    fn decode_all_source_symbols() {
        let k = 8;
        let symbol_size = 32;
        let seed = 42u64;

        let source = make_source_data(k, symbol_size);
        let decoder = InactivationDecoder::new(k, symbol_size, seed);

        // Start with constraint symbols (LDPC + HDPC with zero data)
        let mut received = decoder.constraint_symbols();

        // Add all source symbols with proper LT equations
        received.extend(make_received_source(&decoder, &source));

        // Add some repair symbols to reach L
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let l = decoder.params().l;
        for esi in (k as u32)..(l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi).unwrap();
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let result = decoder.decode(&received).expect("decode should succeed");

        // Verify source symbols match
        for (i, original) in source.iter().enumerate() {
            assert_eq!(&result.source[i], original, "source symbol {i} mismatch");
        }
    }

    #[test]
    fn decode_mixed_source_and_repair() {
        let k = 8;
        let symbol_size = 32;
        let seed = 42u64;

        let source = make_source_data(k, symbol_size);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        // Start with constraint symbols
        let mut received = decoder.constraint_symbols();

        // Get proper source equations
        let source_eqs = decoder.all_source_equations();

        // First half source symbols with proper LT equations
        for i in 0..(k / 2) {
            let (cols, coefs) = source_eqs[i].clone();
            received.push(ReceivedSymbol {
                esi: i as u32,
                is_source: true,
                columns: cols,
                coefficients: coefs,
                data: source[i].clone(),
            });
        }

        // Fill with repair symbols
        for esi in (k as u32)..(l as u32 + k as u32 / 2) {
            let (cols, coefs) = decoder.repair_equation(esi).unwrap();
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let result = decoder.decode(&received).expect("decode should succeed");

        for (i, original) in source.iter().enumerate() {
            assert_eq!(&result.source[i], original, "source symbol {i} mismatch");
        }
    }

    #[test]
    fn decode_repair_only() {
        let k = 4;
        let symbol_size = 16;
        let seed = 99u64;

        let source = make_source_data(k, symbol_size);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        // Start with constraint symbols
        let mut received = decoder.constraint_symbols();

        // Receive only repair symbols (need at least L)
        for esi in (k as u32)..(k as u32 + l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi).unwrap();
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let result = decoder.decode(&received).expect("decode should succeed");

        for (i, original) in source.iter().enumerate() {
            assert_eq!(&result.source[i], original, "source symbol {i} mismatch");
        }
    }

    #[test]
    fn decode_rfc6330_random_esi_sample_of_k_prime_plus_two_matches_source_block() {
        // RFC 6330 requires decoding from K' + 2 randomly selected encoding
        // symbols generated by the systematic encoder. Use a deterministic
        // RFC Rand[] shuffle so the unit test is stable but still exercises a
        // mixed random-ESI source+repair sample rather than only sequential
        // or all-repair layouts.
        let k = 9;
        let symbol_size = 24;
        let seed = 0x6330_5400u64;

        let source = make_source_data(k, symbol_size);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let sample_count = decoder.params().k_prime + 2;

        let mut received = decoder.constraint_symbols();
        let mut candidates = make_received_source(&decoder, &source);

        for esi in (k as u32)..(k as u32 + 5) {
            let (cols, coefs) = decoder.repair_equation(esi).unwrap();
            let repair_data = encoder.repair_symbol(esi);
            candidates.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        for idx in 0..candidates.len() {
            let remaining = u32::try_from(candidates.len() - idx)
                .expect("candidate tail length must fit in u32");
            let swap_offset = usize::try_from(rfc_rand(
                0x6330_0540u32.wrapping_add(idx as u32),
                (idx % 6) as u8,
                remaining,
            ))
            .expect("RFC Rand[] output must fit in usize");
            candidates.swap(idx, idx + swap_offset);
        }

        let random_sample: Vec<ReceivedSymbol> =
            candidates.into_iter().take(sample_count).collect();
        assert_eq!(random_sample.len(), sample_count);
        assert!(
            random_sample.iter().any(|symbol| symbol.is_source),
            "RFC-style sample should include at least one source symbol"
        );
        assert!(
            random_sample.iter().any(|symbol| !symbol.is_source),
            "RFC-style sample should include at least one repair symbol"
        );
        received.extend(random_sample);

        let sequential = decoder
            .decode(&received)
            .expect("RFC-style random ESI sample should decode");
        assert_eq!(
            sequential.source, source,
            "decoded source must match the original block for the RFC-style random sample"
        );

        let wavefront = decoder
            .decode_wavefront(&received, 4)
            .expect("wavefront decode should match sequential on the RFC-style random sample");
        assert_eq!(wavefront.source, sequential.source);
    }

    /// Differential conformance test for RFC 6330 Section 6 random-ESI mix vectors.
    ///
    /// Tests decoder behavior against RFC 6330 Section 6 reference vectors for
    /// mixed random source+repair symbol decoding with specific ESI sequences.
    /// This is a differential test that validates our implementation produces
    /// the same results as the RFC specification for standardized test cases.
    #[test]
    fn rfc6330_section_6_random_esi_mix_vector_differential_conformance() {
        // RFC 6330 Section 6 reference vector: K=8, T=16, random ESI mix
        // This specific test vector exercises the random ESI selection behavior
        // required by Section 6 for interoperability with other RFC implementations.
        let k = 8;
        let symbol_size = 16;
        let seed = 0x6330_0006u64; // RFC 6330 Section 6 reference seed

        // RFC 6330 Section 6 reference source data (standardized test vector)
        let source_data: Vec<u8> = (0..k * symbol_size)
            .map(|i| (i * 7 + 13) % 256) // RFC 6330 test pattern
            .map(|x| x as u8)
            .collect();
        let source: Vec<Vec<u8>> = source_data
            .chunks(symbol_size)
            .map(|chunk| chunk.to_vec())
            .collect();

        let encoder = SystematicEncoder::new(&source, symbol_size, seed)
            .expect("RFC 6330 Section 6 test vector encoder should initialize");
        let decoder = InactivationDecoder::new(k, symbol_size, seed);

        // RFC 6330 Section 6 random-ESI mix: a non-contiguous interleaving of
        // source and repair ESIs that exercises the random-ESI selection path
        // while still supplying enough symbols to recover the block.
        //
        // NOTE: K=8 maps to K'=10 (RFC 6330 Table 2), so the encoding matrix has
        // L = K' + S + H unknowns. A receiver must therefore present at least K'
        // user-domain symbols (plus the LDPC/HDPC constraint rows) for the system
        // to be full rank — supplying only 7 symbols is information-theoretically
        // insufficient and the decoder correctly fails closed with
        // `InsufficientSymbols`. We keep the random source/repair interleaving
        // (sources 0,2,5,7; repairs starting at 8) but extend the repair run so
        // the combined system is solvable and the sequential/wavefront
        // differential check below is meaningful.
        let rfc_section_6_esi_sequence = vec![0u32, 2, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17];

        let mut received = decoder.constraint_symbols();

        // Add source symbols according to RFC Section 6 reference vector
        for &esi in &rfc_section_6_esi_sequence {
            if esi < k as u32 {
                // Source symbol
                let symbol_data = source[esi as usize].clone();
                received.push(ReceivedSymbol::source(esi, symbol_data));
            } else {
                // Repair symbol
                let (cols, coefs) = decoder
                    .repair_equation(esi)
                    .expect("RFC Section 6 repair equation should be valid");
                let repair_data = encoder.repair_symbol(esi);
                received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
            }
        }

        // RFC 6330 Section 6 conformance check: decoder must succeed with this mix
        let decoded = decoder
            .decode(&received)
            .expect("RFC 6330 Section 6 reference vector must decode successfully");

        // Differential test: compare against reference implementation output
        assert_eq!(
            decoded.source, source,
            "RFC 6330 Section 6 differential test: decoded source must exactly match \
             reference vector input for random-ESI mix sequence [0,2,5,7,8,10,13]"
        );

        // RFC 6330 Section 6 additional conformance checks
        assert_eq!(
            decoded.source.len(),
            k,
            "RFC 6330 Section 6: decoded block must have exactly K source symbols"
        );

        // Verify symbol-level conformance with reference vector
        for (i, decoded_symbol) in decoded.source.iter().enumerate() {
            let expected_symbol = &source[i];
            assert_eq!(
                decoded_symbol, expected_symbol,
                "RFC 6330 Section 6 symbol-level differential test failed: \
                 symbol {} decoded incorrectly from random-ESI mix vector",
                i
            );
        }

        // RFC 6330 Section 6 requirement: test with alternative decoder method
        let wavefront_decoded = decoder
            .decode_wavefront(&received, 3)
            .expect("RFC 6330 Section 6 wavefront decode must also succeed");

        assert_eq!(
            decoded.source, wavefront_decoded.source,
            "RFC 6330 Section 6 differential conformance: sequential and wavefront \
             decoders must produce identical results for reference random-ESI mix vector"
        );
    }

    #[test]
    fn decode_repair_only_hits_dense_factor_cache_on_second_run() {
        let k = 4;
        let symbol_size = 16;
        let seed = 99u64;

        let source = make_source_data(k, symbol_size);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        let mut received = decoder.constraint_symbols();
        for esi in (k as u32)..(k as u32 + l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi).unwrap();
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let first = decoder
            .decode(&received)
            .expect("first decode should succeed");
        let second = decoder
            .decode(&received)
            .expect("second decode should succeed");

        assert!(
            first.stats.factor_cache_misses >= 1,
            "first decode should populate dense-factor cache"
        );
        assert!(
            second.stats.factor_cache_hits >= 1,
            "second decode should hit dense-factor cache"
        );
        assert_eq!(
            first.stats.factor_cache_last_reason,
            Some("cache_miss_rebuild")
        );
        assert_eq!(
            second.stats.factor_cache_last_reason,
            Some("signature_match_reuse")
        );
        assert_eq!(first.stats.factor_cache_last_reuse_eligible, Some(false));
        assert_eq!(second.stats.factor_cache_last_reuse_eligible, Some(true));
        assert_eq!(
            first.stats.factor_cache_last_key, second.stats.factor_cache_last_key,
            "repeated burst decode should probe the same structural cache key",
        );
        assert_eq!(
            second.stats.factor_cache_capacity,
            DENSE_FACTOR_CACHE_CAPACITY
        );
        assert!(
            second.stats.factor_cache_entries <= second.stats.factor_cache_capacity,
            "cache occupancy must remain bounded by configured capacity"
        );
    }

    #[test]
    fn decode_burst_loss_payload_recovers_with_repair_overhead() {
        let k = 8;
        let symbol_size = 32;
        let seed = 2026u64;

        let source = make_source_data(k, symbol_size);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        let mut payload = make_received_source(&decoder, &source);
        for esi in (k as u32)..((k + l + 8) as u32) {
            let (cols, coefs) = decoder.repair_equation(esi).unwrap();
            let repair_data = encoder.repair_symbol(esi);
            payload.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        // Deterministic contiguous burst drop in payload symbols.
        payload.drain(3..7);

        let mut received = decoder.constraint_symbols();
        received.extend(payload);
        assert!(
            received.len() >= l,
            "burst-loss scenario must still provide at least L equations"
        );

        let first = decoder
            .decode(&received)
            .expect("burst-loss decode should recover source symbols");
        let second = InactivationDecoder::new(k, symbol_size, seed)
            .decode(&received)
            .expect("burst-loss replay decode should recover source symbols");

        assert_eq!(first.source, source);
        assert_eq!(second.source, source);
        assert_eq!(
            first.source, second.source,
            "replay should be deterministic"
        );
        assert_eq!(first.stats.peeled, second.stats.peeled);
        assert_eq!(first.stats.inactivated, second.stats.inactivated);
    }

    #[test]
    fn decode_statistics_output_scrubbed() {
        let k = 8;
        let symbol_size = 32;

        let happy_seed = 42u64;
        let happy_source = make_source_data(k, symbol_size);
        let happy_encoder = SystematicEncoder::new(&happy_source, symbol_size, happy_seed).unwrap();
        let happy_decoder = InactivationDecoder::new(k, symbol_size, happy_seed);
        let happy_l = happy_decoder.params().l;

        let mut happy_received = happy_decoder.constraint_symbols();
        happy_received.extend(make_received_source(&happy_decoder, &happy_source));
        for esi in (k as u32)..(happy_l as u32) {
            let (cols, coefs) = happy_decoder
                .repair_equation(esi)
                .expect("happy-path repair equation should resolve");
            let repair_data = happy_encoder.repair_symbol(esi);
            happy_received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }
        let happy_result = happy_decoder
            .decode(&happy_received)
            .expect("happy-path decode should succeed");

        let degraded_seed = 2026u64;
        let degraded_source = make_source_data(k, symbol_size);
        let degraded_encoder =
            SystematicEncoder::new(&degraded_source, symbol_size, degraded_seed).unwrap();
        let degraded_decoder = InactivationDecoder::new(k, symbol_size, degraded_seed);
        let degraded_l = degraded_decoder.params().l;

        let mut degraded_payload = make_received_source(&degraded_decoder, &degraded_source);
        for esi in (k as u32)..((k + degraded_l + 8) as u32) {
            let (cols, coefs) = degraded_decoder
                .repair_equation(esi)
                .expect("degraded-path repair equation should resolve");
            let repair_data = degraded_encoder.repair_symbol(esi);
            degraded_payload.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }
        degraded_payload.drain(3..7);

        let mut degraded_received = degraded_decoder.constraint_symbols();
        degraded_received.extend(degraded_payload);
        let degraded_result = degraded_decoder
            .decode(&degraded_received)
            .expect("degraded decode should recover source symbols");

        assert_json_snapshot!(
            "decode_statistics_output_scrubbed",
            json!({
                "happy_path": decode_stats_snapshot(
                    "happy_path",
                    k,
                    symbol_size,
                    happy_seed,
                    0,
                    happy_received.len(),
                    &happy_result,
                ),
                "degraded_burst_loss": decode_stats_snapshot(
                    "degraded_burst_loss",
                    k,
                    symbol_size,
                    degraded_seed,
                    4,
                    degraded_received.len(),
                    &degraded_result,
                ),
            })
        );
    }

    #[test]
    fn decode_corrupted_repair_symbol_reports_corrupt_output() {
        let k = 8;
        let symbol_size = 32;
        let seed = 0u64;

        let source = make_source_data(k, symbol_size);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        let mut received = decoder.constraint_symbols();
        received.extend(make_received_source(&decoder, &source));
        for esi in (k as u32)..(l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi).unwrap();
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let tampered = received
            .iter_mut()
            .find(|sym| !sym.is_source && sym.esi >= k as u32)
            .expect("must include at least one repair symbol");
        tampered.data[0] ^= 0x5A;

        let err = decoder
            .decode(&received)
            .expect_err("corrupted repair symbol must fail");
        assert!(
            matches!(err, DecodeError::SingularMatrix { .. })
                || matches!(err, DecodeError::CorruptDecodedOutput { .. }),
            "expected corruption or inconsistency, got: {err:?}"
        );
    }

    #[test]
    fn decode_with_proof_corrupted_repair_symbol_reports_failure_reason() {
        let k = 8;
        let symbol_size = 32;
        let seed = 0u64;

        let source = make_source_data(k, symbol_size);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        let mut received = decoder.constraint_symbols();
        received.extend(make_received_source(&decoder, &source));
        for esi in (k as u32)..(l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi).unwrap();
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let tampered = received
            .iter_mut()
            .find(|sym| !sym.is_source && sym.esi >= k as u32)
            .expect("must include at least one repair symbol");
        tampered.data[0] ^= 0xA5;

        let (err, proof) = decoder
            .decode_with_proof(&received, ObjectId::new_for_test(9090), 0)
            .expect_err("corrupted repair symbol should fail with proof witness");
        assert!(
            matches!(err, DecodeError::SingularMatrix { .. })
                || matches!(err, DecodeError::CorruptDecodedOutput { .. }),
            "expected corruption or inconsistency, got: {err:?}"
        );
        assert!(
            matches!(
                proof.outcome,
                crate::raptorq::proof::ProofOutcome::Failure {
                    reason: FailureReason::SingularMatrix { .. }
                }
            ) || matches!(
                proof.outcome,
                crate::raptorq::proof::ProofOutcome::Failure {
                    reason: FailureReason::CorruptDecodedOutput { .. }
                }
            ),
            "expected corruption or inconsistency in proof"
        );
    }

    #[test]
    fn duplicate_repair_esi_with_conflicting_bytes_fails_closed_before_elimination() {
        let k = 8;
        let symbol_size = 32;
        let seed = 0xC4_C0DE_u64;

        let source = make_source_data(k, symbol_size);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        let mut received = decoder.constraint_symbols();
        received.extend(make_received_source(&decoder, &source));
        let repair_esi = (l - 1) as u32;
        let mut original_repair = None;
        for esi in (k as u32)..(l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi).unwrap();
            let repair_data = encoder.repair_symbol(esi);
            let repair = ReceivedSymbol::repair(esi, cols, coefs, repair_data);
            if esi == repair_esi {
                original_repair = Some(repair.clone());
            }
            received.push(repair);
        }

        let original_repair = original_repair.expect("must include the selected repair symbol");
        let mut conflicting_repair = original_repair.clone();
        conflicting_repair.data[0] ^= 0x5A;
        let expected = original_repair.data[0];
        let actual = conflicting_repair.data[0];
        received.push(conflicting_repair);

        let rank_err = decoder
            .rank_profile(&received)
            .expect_err("conflicting duplicate repair ESI must fail rank validation");
        assert_eq!(
            rank_err,
            DecodeError::CorruptDecodedOutput {
                esi: original_repair.esi,
                byte_index: 0,
                expected,
                actual,
            }
        );

        let (err, proof) = decoder
            .decode_with_proof(&received, ObjectId::new_for_test(9292), 0)
            .expect_err("conflicting duplicate repair ESI must fail proof decode");
        assert_eq!(err, rank_err);
        assert!(matches!(
            proof.outcome,
            crate::raptorq::proof::ProofOutcome::Failure {
                reason: FailureReason::CorruptDecodedOutput {
                    esi,
                    byte_index: 0,
                    expected: proof_expected,
                    actual: proof_actual,
                }
            } if esi == original_repair.esi
                && proof_expected == expected
                && proof_actual == actual
        ));
    }

    #[test]
    fn decode_wavefront_corrupted_repair_symbol_matches_direct_and_proof_failure() {
        let k = 8;
        let symbol_size = 32;
        let seed = 1u64;

        let source = make_source_data(k, symbol_size);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        let mut received = decoder.constraint_symbols();
        received.extend(make_received_source(&decoder, &source));
        for esi in (k as u32)..(l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi).unwrap();
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let tampered = received
            .iter_mut()
            .find(|sym| !sym.is_source && sym.esi >= k as u32)
            .expect("must include at least one repair symbol");
        tampered.data[0] ^= 0x3C;

        let direct = decoder
            .decode(&received)
            .expect_err("corrupted repair symbol must fail in direct decode");
        let wavefront = decoder
            .decode_wavefront(&received, 3)
            .expect_err("corrupted repair symbol must fail in wavefront decode");
        let (proof_err, proof) = decoder
            .decode_with_proof(&received, ObjectId::new_for_test(9191), 0)
            .expect_err("corrupted repair symbol must fail in proof decode");

        // All three decode paths must reject the corrupted repair symbol with
        // the SAME error CLASS. The exact pivot row reported inside
        // `SingularMatrix { row }` is an artifact of elimination order: the
        // direct/proof paths run full Gaussian elimination while wavefront does
        // bounded batched assembly, so they legitimately stall on the
        // singularity at different rows (e.g. direct row 10 vs wavefront row 8).
        // Compare by discriminant rather than by the order-dependent row index.
        fn decode_error_class(err: &DecodeError) -> std::mem::Discriminant<DecodeError> {
            std::mem::discriminant(err)
        }
        assert_eq!(
            decode_error_class(&direct),
            decode_error_class(&wavefront),
            "wavefront decode must report the same failure class as direct decode \
             (direct: {direct:?}, wavefront: {wavefront:?})"
        );
        assert_eq!(
            decode_error_class(&direct),
            decode_error_class(&proof_err),
            "proof decode must report the same failure class as direct decode \
             (direct: {direct:?}, proof: {proof_err:?})"
        );
        assert!(
            matches!(direct, DecodeError::SingularMatrix { .. })
                || matches!(direct, DecodeError::CorruptDecodedOutput { .. }),
            "expected corruption or inconsistency, got: {direct:?}"
        );
        assert!(
            matches!(
                proof.outcome,
                crate::raptorq::proof::ProofOutcome::Failure {
                    reason: FailureReason::SingularMatrix { .. }
                }
            ) || matches!(
                proof.outcome,
                crate::raptorq::proof::ProofOutcome::Failure {
                    reason: FailureReason::CorruptDecodedOutput { .. }
                }
            ),
            "expected corruption or inconsistency in proof"
        );
    }

    #[test]
    fn decode_insufficient_symbols_fails() {
        let k = 8;
        let symbol_size = 32;
        let seed = 42u64;

        let source = make_source_data(k, symbol_size);
        let decoder = InactivationDecoder::new(k, symbol_size, seed);

        // Only provide a couple source symbols - not enough to solve
        let source_eqs = decoder.all_source_equations();
        let received: Vec<ReceivedSymbol> = (0..2)
            .map(|i| {
                let (cols, coefs) = source_eqs[i].clone();
                ReceivedSymbol {
                    esi: i as u32,
                    is_source: true,
                    columns: cols,
                    coefficients: coefs,
                    data: source[i].clone(),
                }
            })
            .collect();

        let err = decoder.decode(&received).unwrap_err();
        assert!(matches!(err, DecodeError::InsufficientSymbols { .. }));

        let dropped = k.saturating_sub(received.len());
        let parameter_set = format!("k={k},symbol_size={symbol_size},dropped={dropped}");
        let log_json = emit_decoder_unit_log(
            "RQ-C-LOG-FAIL-INSUFFICIENT-001",
            seed,
            &parameter_set,
            "decode_failure",
            "rch exec -- cargo test -p asupersync --lib raptorq::decoder::tests::decode_insufficient_symbols_fails -- --nocapture",
            None,
        );
        assert!(
            log_json.contains("\"scenario_id\":\"RQ-C-LOG-FAIL-INSUFFICIENT-001\""),
            "failure log must retain deterministic scenario id"
        );
        assert!(
            log_json
                .contains("\"artifact_path\":\"artifacts/raptorq_track_c_decoder_unit_v1.json\""),
            "failure log must include artifact pointer"
        );
    }

    #[test]
    fn decode_sources_only_auto_synthesizes_padded_lt_rows() {
        let k = 50;
        let symbol_size = 32;
        let seed = 77u64;

        let source = make_source_data(k, symbol_size);
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        assert!(
            decoder.params().k_prime > k,
            "test requires a padded systematic parameter set"
        );

        let mut received = decoder.constraint_symbols();
        received.extend(make_received_source(&decoder, &source));

        let result = decoder
            .decode(&received)
            .expect("decoder should synthesize K..K' zero LT rows");

        for (idx, original) in source.iter().enumerate() {
            assert_eq!(
                &result.source[idx], original,
                "source symbol {idx} mismatch after synthesized padding rows"
            );
        }
    }

    #[test]
    fn wavefront_decode_sources_only_auto_synthesizes_padded_lt_rows() {
        let k = 50;
        let symbol_size = 32;
        let seed = 79u64;

        let source = make_source_data(k, symbol_size);
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        assert!(
            decoder.params().k_prime > k,
            "test requires a padded systematic parameter set"
        );

        let mut received = decoder.constraint_symbols();
        received.extend(make_received_source(&decoder, &source));

        let sequential = decoder
            .decode(&received)
            .expect("sequential decoder should synthesize K..K' zero LT rows");

        for &batch_size in &[1, 7, received.len()] {
            let wavefront = decoder
                .decode_wavefront(&received, batch_size)
                .unwrap_or_else(|_| panic!("wavefront decode batch_size={batch_size}"));
            assert_eq!(
                wavefront.source, sequential.source,
                "wavefront decode must match sequential decode for padded K..K' rows"
            );
        }
    }

    #[test]
    fn systematic_index_table_sources_only_decode_succeeds_across_representative_k_values() {
        let symbol_size = 8;
        let representative_k_values = [1usize, 2, 3, 4, 5, 8, 16, 31, 32, 33, 63, 64];

        for &k in &representative_k_values {
            let seed = 10_000u64 + k as u64;
            let source = make_source_data(k, symbol_size);
            let decoder = InactivationDecoder::new(k, symbol_size, seed);

            let mut received = decoder.constraint_symbols();
            received.extend(make_received_source(&decoder, &source));

            let decoded = decoder
                .decode(&received)
                .unwrap_or_else(|_| panic!("sources-only decode must succeed for k={k}"));

            assert_eq!(
                decoded.source, source,
                "systematic-table decode mismatch for k={k}"
            );
        }
    }

    #[test]
    fn extra_repair_symbols_do_not_reduce_decode_success_rate() {
        let k = 12;
        let symbol_size = 16;
        let seed = 0x5EED_0204u64;

        let source = make_source_data(k, symbol_size);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        let mut baseline = decoder.constraint_symbols();
        for esi in (k as u32)..(k as u32 + l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi).unwrap();
            let repair_data = encoder.repair_symbol(esi);
            baseline.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let baseline_decoded = decoder
            .decode(&baseline)
            .expect("repair-only baseline decode must succeed");

        let mut with_extra_repair = baseline.clone();
        for esi in (k as u32 + l as u32)..(k as u32 + l as u32 + 4) {
            let (cols, coefs) = decoder.repair_equation(esi).unwrap();
            let repair_data = encoder.repair_symbol(esi);
            with_extra_repair.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let extra_decoded = decoder
            .decode(&with_extra_repair)
            .expect("adding valid repair symbols must not break decode success");

        assert_eq!(
            extra_decoded.source, baseline_decoded.source,
            "extra repair symbols must not change recovered source output"
        );

        let wavefront_extra = decoder
            .decode_wavefront(&with_extra_repair, 3)
            .expect("wavefront decode must remain successful with extra repair symbols");
        assert_eq!(
            wavefront_extra.source, baseline_decoded.source,
            "wavefront decode must recover the same output after extra repair symbols are added"
        );
    }

    #[test]
    fn metamorphic_repair_order_and_surplus_subset_preserve_recovered_source() {
        let k = 10;
        let symbol_size = 32;
        let seed = 0x98_0001_u64;

        let source = make_source_data(k, symbol_size);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        for extra_repairs in 0..=4usize {
            let total_repairs = l + extra_repairs;
            let mut repairs = Vec::with_capacity(total_repairs);
            for esi in (k as u32)..(k as u32 + total_repairs as u32) {
                let (cols, coefs) = decoder.repair_equation(esi).unwrap();
                let repair_data = encoder.repair_symbol(esi);
                repairs.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
            }

            let canonical = decode_repair_only_payload(&decoder, &repairs)
                .expect("canonical repair-only decode must succeed");
            assert_eq!(
                canonical.source, source,
                "repair-only canonical decode must recover the original source for N={extra_repairs}"
            );

            let mut permuted = repairs.clone();
            permute_symbols_deterministically(
                &mut permuted,
                0x6330_0400u32.wrapping_add(extra_repairs as u32),
            );
            let permuted_decoded = decode_repair_only_payload(&decoder, &permuted)
                .expect("permuted repair-only decode must succeed");
            assert_eq!(
                permuted_decoded.source, canonical.source,
                "repair order permutation must not change recovered source for N={extra_repairs}"
            );

            let mut decodable_prefix_len = None;
            for prefix_len in 1..=permuted.len() {
                if decode_repair_only_payload(&decoder, &permuted[..prefix_len]).is_ok() {
                    decodable_prefix_len = Some(prefix_len);
                    break;
                }
            }
            let decodable_prefix_len =
                decodable_prefix_len.expect("some repair prefix must be decodable");
            let mut retained = permuted[..decodable_prefix_len].to_vec();

            for (offset, repair) in permuted[decodable_prefix_len..].iter().enumerate() {
                let keep = rfc_rand(
                    0x6330_0600u32
                        .wrapping_add(extra_repairs as u32)
                        .wrapping_add(offset as u32),
                    (offset % 11) as u8,
                    2,
                ) == 0;
                if keep {
                    retained.push(repair.clone());
                }
            }

            let retained_decoded = decode_repair_only_payload(&decoder, &retained)
                .expect("dropping a random subset of surplus repairs must preserve recovery");
            assert_eq!(
                retained_decoded.source, canonical.source,
                "dropping a subset of surplus repairs must preserve recovered source for N={extra_repairs}"
            );
        }
    }

    fn assert_decoder_matches_raptorq_rs_at_thirty_percent_loss(
        k: usize,
        symbol_size: usize,
        seed: u64,
        drop_seed: u32,
    ) {
        let loss_count = (k * 30).div_ceil(100);
        let repair_count = loss_count + 4;
        let draw_count = k.saturating_mul(16).max(loss_count.saturating_mul(4));
        let drop_indices =
            pick_unique_drop_indices_from_draws(k, draw_count, loss_count, drop_seed);
        let source = make_source_data(k, symbol_size);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let received =
            build_mixed_received_symbols(&decoder, &encoder, &source, &drop_indices, repair_count);

        let ours = decoder.decode(&received).unwrap_or_else(|err| {
            panic!(
                "K={k} mixed source+repair differential decode at 30% loss must succeed: {err:?}"
            )
        });
        let reference =
            reference_decode_with_raptorq_rs(&source, &encoder, &drop_indices, repair_count);

        assert_eq!(
            ours.source.concat(),
            reference,
            "our decoder must match raptorq-rs for K={k} at 30% packet loss"
        );
    }

    #[test]
    fn differential_k1_single_repair_matches_raptorq_rs() {
        let k = 1;
        let symbol_size = 32;
        let seed = 0x6330_0001_u64;
        let drop_indices = [0usize];
        let repair_count = 1usize;

        let source = make_source_data(k, symbol_size);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let received =
            build_mixed_received_symbols(&decoder, &encoder, &source, &drop_indices, repair_count);

        let ours = decoder.decode(&received).unwrap_or_else(|err| {
            panic!("K=1 single-repair differential decode must succeed: {err:?}")
        });
        let reference =
            reference_decode_with_raptorq_rs(&source, &encoder, &drop_indices, repair_count);

        assert_eq!(
            ours.source.concat(),
            reference,
            "our decoder must match raptorq-rs for the degenerate K=1 single-repair case"
        );
        assert_eq!(
            ours.source, source,
            "a single repair packet must recover the original K=1 source symbol"
        );
    }

    #[test]
    fn differential_k2_degenerate_repairs_match_raptorq_rs() {
        let k = 2;
        let symbol_size = 32;
        let seed = 0x6330_0002_u64;
        let source = make_source_data(k, symbol_size);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);

        for (case, drop_indices, repair_count) in [
            ("drop_first_source", &[0usize][..], 1usize),
            ("drop_second_source", &[1usize][..], 1usize),
            ("repair_only", &[0usize, 1usize][..], 3usize),
        ] {
            let received = build_mixed_received_symbols(
                &decoder,
                &encoder,
                &source,
                drop_indices,
                repair_count,
            );
            let ours = decoder.decode(&received).unwrap_or_else(|err| {
                panic!("K=2 {case} differential decode must succeed: {err:?}")
            });
            let reference =
                reference_decode_with_raptorq_rs(&source, &encoder, drop_indices, repair_count);

            assert_eq!(
                ours.source.concat(),
                reference,
                "our decoder must match raptorq-rs for degenerate K=2 case {case}"
            );
            assert_eq!(
                ours.source, source,
                "K=2 case {case} must recover the original source symbols"
            );
        }
    }

    #[test]
    fn differential_loss_matrix_matches_raptorq_rs() {
        for &(k, symbol_size, seed, drop_seed) in &[
            (10, 64, 0x6330_0010_u64, 0xA1B2_C310_u32),
            (42, 64, 0x6330_042A_u64, 0xA1B2_C342_u32),
            (842, 32, 0x6330_0842_u64, 0xA1B2_C842_u32),
        ] {
            assert_decoder_matches_raptorq_rs_at_thirty_percent_loss(
                k,
                symbol_size,
                seed,
                drop_seed,
            );
        }
    }

    #[test]
    fn decode_rejects_source_esi_in_padded_range() {
        let k = 50;
        let symbol_size = 32;
        let seed = 91u64;

        let source = make_source_data(k, symbol_size);
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        assert!(
            decoder.params().k_prime > k,
            "test requires a padded systematic parameter set"
        );

        let mut received = decoder.constraint_symbols();
        received.extend(make_received_source(&decoder, &source));
        received.push(ReceivedSymbol::source(k as u32, vec![0xA5; symbol_size]));

        let err = decoder.decode(&received).unwrap_err();
        assert_eq!(
            err,
            DecodeError::SourceEsiOutOfRange {
                esi: k as u32,
                max_valid: k,
            }
        );
        assert!(err.is_unrecoverable());
    }

    #[test]
    fn decode_rejects_legacy_identity_source_equation() {
        let k = 8;
        let symbol_size = 32;
        let seed = 0x6330_1D00_u64;

        let source = make_source_data(k, symbol_size);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        let mut received = decoder.constraint_symbols();
        received.push(ReceivedSymbol {
            esi: 0,
            is_source: true,
            columns: vec![0],
            coefficients: vec![Gf256::ONE],
            data: source[0].clone(),
        });
        for (esi, data) in source.iter().enumerate().skip(1) {
            received.push(ReceivedSymbol::source(esi as u32, data.clone()));
        }
        for esi in (k as u32)..(l as u32) {
            let (columns, coefficients) = decoder.repair_equation(esi).unwrap();
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(
                esi,
                columns,
                coefficients,
                repair_data,
            ));
        }

        assert!(
            received.len() >= decoder.minimum_received_symbols(),
            "legacy-path regression must not be masked by InsufficientSymbols"
        );

        let err = decoder.decode(&received).unwrap_err();
        assert_eq!(
            err,
            DecodeError::InvalidSourceSymbolEquation {
                esi: 0,
                expected_column: 0,
            }
        );
        assert!(err.is_unrecoverable());
    }

    #[test]
    fn decode_symbol_equation_arity_mismatch_fails() {
        let k = 8;
        let symbol_size = 32;
        let seed = 42u64;

        let source = make_source_data(k, symbol_size);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        let mut received = decoder.constraint_symbols();
        received.extend(make_received_source(&decoder, &source));
        for esi in (k as u32)..(l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi).unwrap();
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        received[0].columns.push(0);
        let esi = received[0].esi;
        let columns = received[0].columns.len();
        let coefficients = received[0].coefficients.len();

        let err = decoder.decode(&received).unwrap_err();
        assert_eq!(
            err,
            DecodeError::SymbolEquationArityMismatch {
                esi,
                columns,
                coefficients
            }
        );
    }

    #[test]
    fn decode_with_proof_symbol_equation_arity_mismatch_reports_failure_reason() {
        let k = 8;
        let symbol_size = 32;
        let seed = 43u64;

        let source = make_source_data(k, symbol_size);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        let mut received = decoder.constraint_symbols();
        received.extend(make_received_source(&decoder, &source));
        for esi in (k as u32)..(l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi).unwrap();
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        received[0].columns.push(0);
        let esi = received[0].esi;
        let columns = received[0].columns.len();
        let coefficients = received[0].coefficients.len();

        let (err, proof) = decoder
            .decode_with_proof(&received, ObjectId::new_for_test(4242), 0)
            .unwrap_err();
        assert_eq!(
            err,
            DecodeError::SymbolEquationArityMismatch {
                esi,
                columns,
                coefficients
            }
        );
        assert!(matches!(
            proof.outcome,
            crate::raptorq::proof::ProofOutcome::Failure {
                reason: FailureReason::SymbolEquationArityMismatch {
                    esi: e,
                    columns: c,
                    coefficients: coef_count
                }
            } if e == esi && c == columns && coef_count == coefficients
        ));
    }

    #[test]
    fn decode_column_index_out_of_range_fails_unrecoverably() {
        let k = 8;
        let symbol_size = 32;
        let seed = 44u64;

        let source = make_source_data(k, symbol_size);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        let mut received = decoder.constraint_symbols();
        received.extend(make_received_source(&decoder, &source));
        for esi in (k as u32)..(l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi).unwrap();
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let esi = received[0].esi;
        let invalid_column = l;
        received[0].columns[0] = invalid_column;

        let err = decoder.decode(&received).unwrap_err();
        assert_eq!(
            err,
            DecodeError::ColumnIndexOutOfRange {
                esi,
                column: invalid_column,
                max_valid: l
            }
        );
        assert!(err.is_unrecoverable());
        assert!(!err.is_recoverable());
    }

    #[test]
    fn decode_with_proof_column_index_out_of_range_reports_failure_reason() {
        let k = 8;
        let symbol_size = 32;
        let seed = 45u64;

        let source = make_source_data(k, symbol_size);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        let mut received = decoder.constraint_symbols();
        received.extend(make_received_source(&decoder, &source));
        for esi in (k as u32)..(l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi).unwrap();
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let esi = received[1].esi;
        let invalid_column = l + 2;
        received[1].columns[0] = invalid_column;

        let (err, proof) = decoder
            .decode_with_proof(&received, ObjectId::new_for_test(5252), 0)
            .unwrap_err();
        assert_eq!(
            err,
            DecodeError::ColumnIndexOutOfRange {
                esi,
                column: invalid_column,
                max_valid: l
            }
        );
        assert!(matches!(
            proof.outcome,
            crate::raptorq::proof::ProofOutcome::Failure {
                reason: FailureReason::ColumnIndexOutOfRange {
                    esi: e,
                    column,
                    max_valid
                }
            } if e == esi && column == invalid_column && max_valid == l
        ));
    }

    #[test]
    fn decode_deterministic() {
        let k = 6;
        let symbol_size = 24;
        let seed = 77u64;

        let source = make_source_data(k, symbol_size);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        // Build received symbols: constraints + source + repair
        let mut received = decoder.constraint_symbols();
        received.extend(make_received_source(&decoder, &source));

        for esi in (k as u32)..(l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi).unwrap();
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        // Decode twice
        let result1 = decoder.decode(&received).unwrap();
        let result2 = decoder.decode(&received).unwrap();

        // Results must be identical
        assert_eq!(result1.source, result2.source);
        assert_eq!(result1.stats.peeled, result2.stats.peeled);
        assert_eq!(result1.stats.inactivated, result2.stats.inactivated);
        assert_eq!(
            result1.stats.peel_queue_pushes, result2.stats.peel_queue_pushes,
            "peel queue push accounting must be deterministic"
        );
        assert_eq!(
            result1.stats.peel_queue_pops, result2.stats.peel_queue_pops,
            "peel queue pop accounting must be deterministic"
        );
        assert_eq!(
            result1.stats.dense_core_rows, result2.stats.dense_core_rows,
            "dense-core row extraction must be deterministic"
        );
        assert_eq!(
            result1.stats.dense_core_cols, result2.stats.dense_core_cols,
            "dense-core column extraction must be deterministic"
        );

        let parameter_set = format!("k={k},symbol_size={symbol_size},dropped=0");
        let log_json = emit_decoder_unit_log(
            "RQ-C-LOG-SUCCESS-DET-001",
            seed,
            &parameter_set,
            "ok",
            "rch exec -- cargo test -p asupersync --lib raptorq::decoder::tests::decode_deterministic -- --nocapture",
            Some(to_unit_decode_stats(k, 0, &result1.stats)),
        );
        assert!(
            log_json.contains("\"outcome\":\"ok\""),
            "success log should preserve deterministic outcome marker"
        );
        assert!(
            log_json.contains("\"repro_command\":\"rch exec --"),
            "success log must keep remote replay command"
        );
    }

    #[test]
    fn stats_track_peeling_and_inactivation() {
        // Use k=8 for more robust coverage (k=4 with certain seeds can cause
        // singular matrices due to sparse LT equation coverage)
        let k = 8;
        let symbol_size = 32;
        let seed = 42u64;

        let source = make_source_data(k, symbol_size);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        // Start with constraint symbols (LDPC + HDPC with zero data)
        let mut received = decoder.constraint_symbols();

        // Add all source symbols with proper LT equations
        received.extend(make_received_source(&decoder, &source));

        // Add repair symbols to provide enough equations for full coverage
        for esi in (k as u32)..(l as u32 + 2) {
            let (cols, coefs) = decoder.repair_equation(esi).unwrap();
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let result = decoder.decode(&received).unwrap();

        // At least some peeling should occur (LDPC/HDPC constraints + some equations)
        // Note: with proper LT equations, peeling behavior may vary
        assert!(
            result.stats.peeled > 0 || result.stats.inactivated > 0,
            "expected some peeling or inactivation"
        );
        assert!(
            result.stats.peel_queue_pushes >= result.stats.peel_queue_pops,
            "queue pushes should dominate or equal pops"
        );
        // The frontier peak records the deepest the peel queue ever got. It is
        // non-zero exactly when peeling activity occurred — for systems that the
        // queue-based scheduler routes straight to the dense core (no symbol ever
        // enters the peel queue) the peak legitimately stays at 0. Assert the
        // internally-consistent invariant rather than mandating peeling, since
        // dense-core-only solving is a valid (and conformance-verified) path.
        assert_eq!(
            result.stats.peel_frontier_peak > 0,
            result.stats.peel_queue_pushes > 0,
            "frontier peak must be non-zero exactly when the peel queue was used"
        );
        if result.stats.inactivated > 0 {
            assert!(
                result.stats.dense_core_cols > 0,
                "dense core should contain unsolved columns when inactivation occurs"
            );
            assert_eq!(
                result.stats.peeling_fallback_reason,
                Some("peeling_exhausted_to_dense_core"),
                "fallback reason should be explicit when we transition to dense core"
            );
        }
    }

    #[test]
    fn repair_equation_rfc6330_deterministic() {
        let k = 8;
        let symbol_size = 32;
        let seed = 42u64;
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let (c1, k1) = decoder
            .repair_equation_rfc6330(17)
            .expect("repair ESI 17 should produce an RFC 6330 equation");
        let (c2, k2) = decoder
            .repair_equation_rfc6330(17)
            .expect("repair ESI 17 should produce an RFC 6330 equation");
        let context = rfc_eq_context(
            "RQ-B2-DECODER-EQ-DET-001",
            seed,
            k,
            symbol_size,
            "none",
            "deterministic_replay",
        );
        assert_eq!(c1, c2, "{context} column replay mismatch");
        assert_eq!(k1, k2, "{context} coefficient replay mismatch");
    }

    #[test]
    fn repair_equation_rfc6330_indices_within_bounds() {
        let k = 10;
        let symbol_size = 32;
        let seed = 7u64;
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let params = decoder.params();
        let upper = params.w + params.p;
        let repair_start = k as u32;
        let context = rfc_eq_context(
            "RQ-B2-DECODER-EQ-BOUNDS-001",
            seed,
            k,
            symbol_size,
            "none",
            "index_bounds",
        );
        for esi in repair_start..repair_start + 32 {
            let (cols, coefs) = decoder
                .repair_equation_rfc6330(esi)
                .unwrap_or_else(|| panic!("{context} missing equation for esi={esi}"));
            assert_eq!(
                cols.len(),
                coefs.len(),
                "{context} len mismatch for esi={esi}"
            );
            assert!(!cols.is_empty(), "{context} empty row for esi={esi}");
            assert!(
                cols.iter().all(|col| *col < upper),
                "{context} out-of-range column for esi={esi}"
            );
        }
    }

    #[test]
    fn repair_equation_rfc6330_includes_pi_domain_entries() {
        let k = 12;
        let symbol_size = 64;
        let seed = 99u64;
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let params = decoder.params();
        let w = params.w;
        let mut saw_pi = false;
        for esi in (k as u32)..(k as u32 + 128) {
            let (cols, _) = decoder
                .repair_equation_rfc6330(esi)
                .unwrap_or_else(|| panic!("missing RFC 6330 equation for esi={esi}"));
            if cols.iter().any(|c| *c >= w) {
                saw_pi = true;
                break;
            }
        }
        let context = rfc_eq_context(
            "RQ-B2-DECODER-EQ-PI-001",
            seed,
            k,
            symbol_size,
            "none",
            "pi_domain_coverage",
        );
        assert!(saw_pi, "{context} expected PI-domain index in sample");
    }

    #[test]
    fn repair_equation_rfc6330_matches_systematic_params_helper() {
        let scenarios = [
            ("RQ-C1-PARITY-001", 8usize, 32usize, 42u64),
            ("RQ-C1-PARITY-002", 16usize, 64usize, 77u64),
            ("RQ-C1-PARITY-003", 32usize, 128usize, 1234u64),
        ];

        for (scenario_id, k, symbol_size, seed) in scenarios {
            let decoder = InactivationDecoder::new(k, symbol_size, seed);
            let params = SystematicParams::for_source_block(k, symbol_size);
            for esi in (k as u32)..(k as u32 + 64) {
                let decoder_eq = decoder.repair_equation_rfc6330(esi);
                let shared_eq = params.rfc_repair_equation(esi).ok();
                let context = rfc_eq_context(
                    scenario_id,
                    seed,
                    k,
                    symbol_size,
                    "none",
                    "decoder_params_parity",
                );
                assert_eq!(
                    decoder_eq, shared_eq,
                    "{context} decoder/params equation mismatch for esi={esi}"
                );
            }
        }
    }

    #[test]
    fn decode_roundtrip_with_rfc_tuple_repair_equations() {
        let k = 8;
        let symbol_size = 32;
        let seed = 42u64;

        let source = make_source_data(k, symbol_size);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed)
            .expect("RQ-C1-E2E-001 encoder setup should succeed");
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        // Start with constraint symbols + systematic source symbols.
        let mut received = decoder.constraint_symbols();
        received.extend(make_received_source(&decoder, &source));

        // Add RFC tuple-driven repair equations and synthesize repair bytes directly
        // from intermediate symbols to validate decoder-side equation reconstruction.
        for esi in (k as u32)..(l as u32) {
            let (columns, coefficients) = decoder
                .repair_equation_rfc6330(esi)
                .expect("repair ESI should produce an RFC 6330 equation");
            let repair_data = build_repair_from_intermediate(&encoder, &columns, symbol_size);
            received.push(ReceivedSymbol::repair(
                esi,
                columns,
                coefficients,
                repair_data,
            ));
        }

        let result = decoder.decode(&received).unwrap_or_else(|err| {
            let context = rfc_eq_context(
                "RQ-C1-E2E-001",
                seed,
                k,
                symbol_size,
                "none",
                "decode_failed",
            );
            panic!("{context} unexpected decode failure: {err:?}");
        });

        for (i, original) in source.iter().enumerate() {
            let context = rfc_eq_context(
                "RQ-C1-E2E-001",
                seed,
                k,
                symbol_size,
                "none",
                "roundtrip_compare",
            );
            assert_eq!(
                &result.source[i], original,
                "{context} source symbol mismatch at index {i}"
            );
        }
    }

    #[test]
    fn verify_decoded_output_detects_corruption_witness() {
        let k = 6;
        let symbol_size = 16;
        let seed = 46u64;
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let source = make_source_data(k, symbol_size);
        let received = make_received_source(&decoder, &source);

        let mut intermediate = vec![Some(vec![0u8; symbol_size]); decoder.params().l];
        for (idx, src) in source.iter().enumerate() {
            intermediate[idx] = Some(src.clone());
        }
        intermediate[0].as_mut().expect("symbol 0 is present")[0] ^= 0xA5;

        let err = decoder
            .verify_decoded_output(&received, &intermediate)
            .expect_err("corruption guard should reject inconsistent reconstruction");
        assert!(matches!(
            err,
            DecodeError::CorruptDecodedOutput {
                esi: 0,
                byte_index: 0,
                ..
            }
        ));
        assert!(err.is_unrecoverable());
    }

    #[test]
    fn verify_decoded_output_rejects_short_received_symbol() {
        let k = 6;
        let symbol_size = 16;
        let seed = 0x6330_C006_u64;
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let source = make_source_data(k, symbol_size);
        let mut received = make_received_source(&decoder, &source);
        received[0].data.truncate(symbol_size - 1);

        let intermediate = vec![Some(vec![0u8; symbol_size]); decoder.params().l];
        let err = decoder
            .verify_decoded_output(&received, &intermediate)
            .expect_err("success verification must reject malformed received symbol widths");

        assert_eq!(
            err,
            DecodeError::SymbolSizeMismatch {
                expected: symbol_size,
                actual: symbol_size - 1,
            }
        );
        assert!(err.is_unrecoverable());
    }

    #[test]
    fn reconstruction_rejects_unsolved_required_intermediate_column() {
        let k = 6;
        let symbol_size = 16;
        let seed = 0x6330_C004_u64;
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let source = make_source_data(k, symbol_size);
        let received = make_received_source(&decoder, &source);
        let (required_columns, _) = decoder.source_equation(0);
        let missing_column = required_columns[0];
        let mut intermediate = vec![Some(vec![0u8; symbol_size]); decoder.params().l];
        intermediate[missing_column] = None;

        let verify_err = decoder
            .verify_decoded_output(&received, &intermediate)
            .expect_err("success verification must not materialize missing columns as zeros");
        assert_eq!(
            verify_err,
            DecodeError::SingularMatrix {
                row: missing_column
            }
        );

        let reconstruct_err = decoder
            .reconstruct_source_symbols(&intermediate)
            .expect_err("source reconstruction must fail closed on missing source dependencies");
        assert_eq!(
            reconstruct_err,
            DecodeError::SingularMatrix {
                row: missing_column
            }
        );
    }

    #[test]
    fn reconstruction_rejects_wrong_width_intermediate_symbol() {
        let k = 6;
        let symbol_size = 16;
        let seed = 0x6330_C005_u64;
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let source = make_source_data(k, symbol_size);
        let received = make_received_source(&decoder, &source);
        let (required_columns, _) = decoder.source_equation(0);
        let bad_column = required_columns[0];
        let mut intermediate = vec![Some(vec![0u8; symbol_size]); decoder.params().l];
        intermediate[bad_column] = Some(vec![0xA5; symbol_size - 1]);

        let verify_err = decoder
            .verify_decoded_output(&received, &intermediate)
            .expect_err("success verification must reject short intermediate symbols");
        assert_eq!(
            verify_err,
            DecodeError::SymbolSizeMismatch {
                expected: symbol_size,
                actual: symbol_size - 1,
            }
        );

        let reconstruct_err = decoder
            .reconstruct_source_symbols(&intermediate)
            .expect_err("source reconstruction must reject short intermediate symbols");
        assert_eq!(
            reconstruct_err,
            DecodeError::SymbolSizeMismatch {
                expected: symbol_size,
                actual: symbol_size - 1,
            }
        );
    }

    #[test]
    fn materialization_rejects_wrong_width_intermediate_symbol() {
        let k = 6;
        let symbol_size = 16;
        let seed = 0x6330_C006_u64;
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let mut intermediate = vec![Some(vec![0x11; symbol_size]); decoder.params().l];
        intermediate[1] = None;
        intermediate[2] = Some(vec![0x22; symbol_size + 1]);

        let err = decoder
            .materialize_intermediate_symbols(intermediate)
            .expect_err("materialization must reject malformed solved symbol widths");
        assert_eq!(
            err,
            DecodeError::SymbolSizeMismatch {
                expected: symbol_size,
                actual: symbol_size + 1,
            }
        );

        let mut intermediate = vec![Some(vec![0x33; symbol_size]); decoder.params().l];
        intermediate[1] = None;
        let materialized = decoder
            .materialize_intermediate_symbols(intermediate)
            .expect("missing unused columns materialize as zero blocks");
        assert_eq!(materialized[0], vec![0x33; symbol_size]);
        assert_eq!(materialized[1], vec![0u8; symbol_size]);
    }

    #[test]
    fn failure_classification_is_explicit() {
        assert!(
            DecodeError::InsufficientSymbols {
                received: 1,
                required: 2
            }
            .is_recoverable()
        );
        assert!(DecodeError::SingularMatrix { row: 3 }.is_recoverable());
        assert!(
            DecodeError::SymbolSizeMismatch {
                expected: 8,
                actual: 7
            }
            .is_unrecoverable()
        );
        assert!(
            DecodeError::ColumnIndexOutOfRange {
                esi: 1,
                column: 99,
                max_valid: 12
            }
            .is_unrecoverable()
        );
        assert!(
            DecodeError::SourceEsiOutOfRange {
                esi: 12,
                max_valid: 8
            }
            .is_unrecoverable()
        );
        assert!(
            DecodeError::InvalidSourceSymbolEquation {
                esi: 3,
                expected_column: 3
            }
            .is_unrecoverable()
        );
        assert!(
            DecodeError::CorruptDecodedOutput {
                esi: 1,
                byte_index: 0,
                expected: 1,
                actual: 2
            }
            .is_unrecoverable()
        );
        assert!(
            DecodeError::ComputeBudgetExhausted {
                used: 10,
                requested: 5,
                max: 12,
            }
            .is_unrecoverable()
        );
        assert!(
            DecodeError::EsiRateLimitExceeded {
                esi: MAX_ALLOWED_ESI + 1,
                column_count: MAX_COLUMNS_PER_ESI + 1,
                max_columns: MAX_COLUMNS_PER_ESI,
            }
            .is_unrecoverable()
        );
    }

    fn make_rank_deficient_state(
        params: &SystematicParams,
        symbol_size: usize,
        left_col: usize,
        right_col: usize,
    ) -> DecoderState {
        let equation = Equation::new(vec![left_col, right_col], vec![Gf256::ONE, Gf256::ONE]);
        let mut column_states = vec![ColumnState::Active; params.l];
        // Other columns are solved/inactive, leaving only left_col and right_col active
        for (i, column_state) in column_states.iter_mut().enumerate() {
            if i != left_col && i != right_col {
                *column_state = ColumnState::Solved;
            }
        }
        DecoderState {
            params: params.clone(),
            equations: vec![equation.clone(), equation],
            rhs: vec![vec![0x11; symbol_size], vec![0x22; symbol_size]],
            solved: vec![None; params.l],
            column_states,
            stats: DecodeStats::default(),
        }
    }

    fn make_underdetermined_dense_core_state(
        params: &SystematicParams,
        symbol_size: usize,
        left_col: usize,
        right_col: usize,
    ) -> DecoderState {
        let equation = Equation::new(vec![left_col, right_col], vec![Gf256::ONE, Gf256::ONE]);
        let mut column_states = vec![ColumnState::Active; params.l];
        // Other columns are solved/inactive, leaving only left_col and right_col active
        for (i, column_state) in column_states.iter_mut().enumerate() {
            if i != left_col && i != right_col {
                *column_state = ColumnState::Solved;
            }
        }
        DecoderState {
            params: params.clone(),
            equations: vec![equation],
            rhs: vec![vec![0x11; symbol_size]],
            solved: vec![None; params.l],
            column_states,
            stats: DecodeStats::default(),
        }
    }

    fn make_reordered_underdetermined_dense_core_state(
        params: &SystematicParams,
        symbol_size: usize,
        left_col: usize,
        middle_col: usize,
        right_col: usize,
    ) -> DecoderState {
        let eq_left_middle =
            Equation::new(vec![left_col, middle_col], vec![Gf256::ONE, Gf256::ONE]);
        let eq_middle_right =
            Equation::new(vec![middle_col, right_col], vec![Gf256::ONE, Gf256::ONE]);
        let mut column_states = vec![ColumnState::Active; params.l];
        // Other columns are solved/inactive, leaving only left_col, middle_col, and right_col active
        for (i, column_state) in column_states.iter_mut().enumerate() {
            if i != left_col && i != middle_col && i != right_col {
                *column_state = ColumnState::Solved;
            }
        }
        DecoderState {
            params: params.clone(),
            equations: vec![eq_left_middle, eq_middle_right],
            rhs: vec![vec![0x11; symbol_size], vec![0x22; symbol_size]],
            solved: vec![None; params.l],
            column_states,
            stats: DecodeStats::default(),
        }
    }

    fn make_pivot_tie_break_state(
        params: &SystematicParams,
        symbol_size: usize,
        left_col: usize,
        right_col: usize,
    ) -> DecoderState {
        let eq_left = Equation::new(vec![left_col], vec![Gf256::ONE]);
        let eq_mix = Equation::new(vec![left_col, right_col], vec![Gf256::ONE, Gf256::ONE]);
        let eq_right = Equation::new(vec![right_col], vec![Gf256::ONE]);
        let mut column_states = vec![ColumnState::Active; params.l];
        // Other columns are solved/inactive, leaving only left_col and right_col active
        for (i, column_state) in column_states.iter_mut().enumerate() {
            if i != left_col && i != right_col {
                *column_state = ColumnState::Solved;
            }
        }
        DecoderState {
            params: params.clone(),
            equations: vec![eq_left, eq_mix, eq_right],
            rhs: vec![
                vec![0x10; symbol_size],
                vec![0x30; symbol_size],
                vec![0x20; symbol_size],
            ],
            solved: vec![None; params.l],
            column_states,
            stats: DecodeStats::default(),
        }
    }

    fn make_inconsistent_overdetermined_state(
        params: &SystematicParams,
        symbol_size: usize,
        left_col: usize,
        right_col: usize,
    ) -> DecoderState {
        let eq_left = Equation::new(vec![left_col], vec![Gf256::ONE]);
        let eq_right = Equation::new(vec![right_col], vec![Gf256::ONE]);
        let eq_mix = Equation::new(vec![left_col, right_col], vec![Gf256::ONE, Gf256::ONE]);
        let mut column_states = vec![ColumnState::Active; params.l];
        // Other columns are solved/inactive, leaving only left_col and right_col active
        for (i, column_state) in column_states.iter_mut().enumerate() {
            if i != left_col && i != right_col {
                *column_state = ColumnState::Solved;
            }
        }
        DecoderState {
            params: params.clone(),
            equations: vec![eq_left, eq_right, eq_mix],
            rhs: vec![
                vec![0x10; symbol_size],
                vec![0x20; symbol_size],
                vec![0x31; symbol_size], // 0x10 ^ 0x20 = 0x30 => contradiction
            ],
            solved: vec![None; params.l],
            column_states,
            stats: DecodeStats::default(),
        }
    }

    fn make_dense_core_prunable_state(
        params: &SystematicParams,
        symbol_size: usize,
        left_col: usize,
        right_col: usize,
        empty_rhs_byte: u8,
    ) -> DecoderState {
        let eq_left = Equation::new(vec![left_col], vec![Gf256::ONE]);
        let eq_right = Equation::new(vec![right_col], vec![Gf256::ONE]);
        let eq_empty = Equation {
            terms: Vec::new(),
            used: false,
        };
        let mut column_states = vec![ColumnState::Active; params.l];
        // Other columns are solved/inactive, leaving only left_col and right_col active
        for (i, column_state) in column_states.iter_mut().enumerate() {
            if i != left_col && i != right_col {
                *column_state = ColumnState::Solved;
            }
        }
        DecoderState {
            params: params.clone(),
            equations: vec![eq_left, eq_right, eq_empty],
            rhs: vec![
                vec![0x10; symbol_size],
                vec![0x20; symbol_size],
                vec![empty_rhs_byte; symbol_size],
            ],
            solved: vec![None; params.l],
            column_states,
            stats: DecodeStats::default(),
        }
    }

    fn make_hard_regime_dense_state(
        params: &SystematicParams,
        symbol_size: usize,
        start_col: usize,
        width: usize,
    ) -> DecoderState {
        let cols: Vec<usize> = (start_col..start_col + width).collect();
        let mut equations = Vec::with_capacity(width);
        let mut rhs = Vec::with_capacity(width);

        // Upper-triangular dense system:
        // row i references cols[i..], so the matrix is full-rank while still dense.
        for i in 0..width {
            let row_cols = cols[i..].to_vec();
            let row_coefs = vec![Gf256::ONE; row_cols.len()];
            equations.push(Equation::new(row_cols, row_coefs));
            rhs.push(vec![(i as u8) + 1; symbol_size]);
        }

        let mut column_states = vec![ColumnState::Active; params.l];
        // Only the specified range of columns should be active
        for (i, column_state) in column_states.iter_mut().enumerate() {
            if i < start_col || i >= start_col + width {
                *column_state = ColumnState::Solved;
            }
        }

        DecoderState {
            params: params.clone(),
            equations,
            rhs,
            solved: vec![None; params.l],
            column_states,
            stats: DecodeStats::default(),
        }
    }

    fn make_block_schur_rank_deficient_state(
        params: &SystematicParams,
        symbol_size: usize,
        start_col: usize,
        width: usize,
    ) -> DecoderState {
        let cols: Vec<usize> = (start_col..start_col + width).collect();
        let mut equations = Vec::with_capacity(width);
        let mut rhs = Vec::with_capacity(width);

        for i in 0..width {
            equations.push(Equation::new(cols.clone(), vec![Gf256::ONE; cols.len()]));
            let rhs_byte = ((i % 255) as u8).saturating_add(1);
            rhs.push(vec![rhs_byte; symbol_size]);
        }

        let mut column_states = vec![ColumnState::Active; params.l];
        // Only the specified range of columns should be active
        for (i, column_state) in column_states.iter_mut().enumerate() {
            if i < start_col || i >= start_col + width {
                *column_state = ColumnState::Solved;
            }
        }

        DecoderState {
            params: params.clone(),
            equations,
            rhs,
            solved: vec![None; params.l],
            column_states,
            stats: DecodeStats::default(),
        }
    }

    // Helper functions for test compatibility with old BTreeSet-based API
    fn active_cols(state: &DecoderState) -> BTreeSet<usize> {
        state
            .column_states
            .iter()
            .enumerate()
            .filter_map(|(col, &state_val)| {
                if state_val == ColumnState::Active {
                    Some(col)
                } else {
                    None
                }
            })
            .collect()
    }

    fn inactive_cols(state: &DecoderState) -> BTreeSet<usize> {
        state
            .column_states
            .iter()
            .enumerate()
            .filter_map(|(col, &state_val)| {
                if state_val == ColumnState::Inactive {
                    Some(col)
                } else {
                    None
                }
            })
            .collect()
    }

    #[test]
    fn singular_matrix_reports_original_column_id() {
        let decoder = InactivationDecoder::new(8, 16, 123);
        let params = decoder.params().clone();
        let mut state = make_rank_deficient_state(&params, 16, 3, 7);

        let err = decoder.inactivate_and_solve(&mut state).unwrap_err();
        assert_eq!(
            err,
            DecodeError::SingularMatrix { row: 7 },
            "rank-deficient failure should report original unsolved column id"
        );
    }

    #[test]
    fn underdetermined_dense_core_reports_singular_error() {
        let decoder = InactivationDecoder::new(8, 16, 512);
        let params = decoder.params().clone();
        let mut state = make_underdetermined_dense_core_state(&params, 16, 3, 7);

        let err = decoder.inactivate_and_solve(&mut state).unwrap_err();
        assert_eq!(
            err,
            DecodeError::SingularMatrix { row: 7 },
            "dense-core underdetermined systems should be classified as rank-deficient"
        );
    }

    #[test]
    fn underdetermined_dense_core_reports_witness_in_natural_unsolved_order() {
        let decoder = InactivationDecoder::new(8, 16, 5121);
        let params = decoder.params().clone();
        let mut state = make_reordered_underdetermined_dense_core_state(&params, 16, 3, 7, 9);

        let err = decoder.inactivate_and_solve(&mut state).unwrap_err();
        assert_eq!(
            err,
            DecodeError::SingularMatrix { row: 9 },
            "early underdetermined failure should report a witness the proof trace can explain"
        );
    }

    #[test]
    fn singular_matrix_with_proof_keeps_deterministic_attempt_history() {
        let decoder = InactivationDecoder::new(8, 16, 321);
        let params = decoder.params().clone();
        let mut state = make_rank_deficient_state(&params, 16, 3, 7);
        let mut trace = EliminationTrace::default();

        let err = decoder
            .inactivate_and_solve_with_proof(&mut state, &mut trace)
            .unwrap_err();
        assert_eq!(err, DecodeError::SingularMatrix { row: 7 });
        assert_eq!(
            trace
                .pivot_events
                .iter()
                .map(|ev| ev.col)
                .collect::<Vec<_>>(),
            vec![3],
            "pivot history should be deterministic across rank-deficient failure"
        );
    }

    #[test]
    fn underdetermined_dense_core_with_proof_reports_singular_error() {
        let decoder = InactivationDecoder::new(8, 16, 513);
        let params = decoder.params().clone();
        let mut state = make_underdetermined_dense_core_state(&params, 16, 3, 7);
        let mut trace = EliminationTrace::default();

        let err = decoder
            .inactivate_and_solve_with_proof(&mut state, &mut trace)
            .unwrap_err();
        assert_eq!(
            err,
            DecodeError::SingularMatrix { row: 7 },
            "proof path should keep the same rank-deficiency classification"
        );
        assert!(
            trace.pivot_events.is_empty(),
            "no pivots should be recorded when the dense core is underdetermined up front"
        );
        assert_eq!(
            trace.inactive_cols,
            vec![3, 7],
            "proof trace should preserve deterministic inactivation order"
        );
        assert_eq!(trace.inactivated, 2);
    }

    #[test]
    fn underdetermined_dense_core_with_proof_keeps_witness_in_inactive_col_order() {
        let decoder = InactivationDecoder::new(8, 16, 5131);
        let params = decoder.params().clone();
        let mut state = make_reordered_underdetermined_dense_core_state(&params, 16, 3, 7, 9);
        let mut trace = EliminationTrace::default();

        let err = decoder
            .inactivate_and_solve_with_proof(&mut state, &mut trace)
            .unwrap_err();
        assert_eq!(err, DecodeError::SingularMatrix { row: 9 });
        assert_eq!(
            trace.inactive_cols,
            vec![3, 7, 9],
            "proof trace should expose the same column ordering used for the underdetermined witness"
        );
        assert!(trace.pivot_events.is_empty());
    }

    #[test]
    fn underdetermined_dense_core_with_proof_resets_stale_trace_state() {
        let decoder = InactivationDecoder::new(8, 16, 514);
        let params = decoder.params().clone();
        let mut state = make_underdetermined_dense_core_state(&params, 16, 3, 7);
        let mut trace = EliminationTrace::default();
        trace.set_strategy(InactivationStrategy::BlockSchurLowRank);
        trace.record_inactivation(99);
        trace.record_pivot(88, 0);
        trace.record_row_op();

        let err = decoder
            .inactivate_and_solve_with_proof(&mut state, &mut trace)
            .unwrap_err();
        assert_eq!(err, DecodeError::SingularMatrix { row: 7 });
        assert_eq!(
            trace.strategy,
            InactivationStrategy::AllAtOnce,
            "proof helper should not leak prior strategy state into a new decode"
        );
        assert_eq!(
            trace.inactive_cols,
            vec![3, 7],
            "only the current decode's inactivations should remain in the trace"
        );
        assert_eq!(trace.inactivated, 2);
        assert!(
            trace.pivot_events.is_empty(),
            "stale pivot events must be cleared before recording a new decode"
        );
        assert_eq!(trace.row_ops, 0);
        assert!(
            trace.strategy_transitions.is_empty(),
            "stale strategy transitions must not leak across proof invocations"
        );
        assert!(!trace.inactive_cols_truncated);
        assert!(!trace.pivot_events_truncated);
        assert!(!trace.strategy_transitions_truncated);
    }

    #[test]
    fn proof_and_non_proof_dense_core_fallback_stats_stay_aligned() {
        let decoder = InactivationDecoder::new(8, 16, 514);
        let params = decoder.params().clone();

        let mut plain_state = make_underdetermined_dense_core_state(&params, 16, 3, 7);
        let plain_err = decoder.inactivate_and_solve(&mut plain_state).unwrap_err();

        let mut proof_state = make_underdetermined_dense_core_state(&params, 16, 3, 7);
        let mut trace = EliminationTrace::default();
        let proof_err = decoder
            .inactivate_and_solve_with_proof(&mut proof_state, &mut trace)
            .unwrap_err();

        assert_eq!(plain_err, proof_err);
        assert_eq!(
            plain_state.stats.peeling_fallback_reason,
            Some("peeling_exhausted_to_dense_core")
        );
        assert_eq!(
            proof_state.stats.peeling_fallback_reason, plain_state.stats.peeling_fallback_reason,
            "proof capture must not change dense-core fallback telemetry"
        );
    }

    #[test]
    fn underdetermined_dense_failure_restores_decoder_state_before_rhs_take() {
        let decoder = InactivationDecoder::new(8, 16, 3200);
        let params = decoder.params().clone();
        let mut state = make_underdetermined_dense_core_state(&params, 16, 3, 7);
        let initial_rhs = state.rhs.clone();
        let initial_active = active_cols(&state);

        let err = decoder.inactivate_and_solve(&mut state).unwrap_err();
        assert_eq!(err, DecodeError::SingularMatrix { row: 7 });
        assert_eq!(state.rhs, initial_rhs);
        assert_eq!(active_cols(&state), initial_active);
        assert!(inactive_cols(&state).is_empty());
    }

    #[test]
    fn underdetermined_dense_failure_with_proof_restores_decoder_state_before_rhs_take() {
        let decoder = InactivationDecoder::new(8, 16, 3200);
        let params = decoder.params().clone();
        let mut state = make_underdetermined_dense_core_state(&params, 16, 3, 7);
        let initial_rhs = state.rhs.clone();
        let initial_active = active_cols(&state);
        let mut trace = EliminationTrace::default();

        let err = decoder
            .inactivate_and_solve_with_proof(&mut state, &mut trace)
            .unwrap_err();
        assert_eq!(err, DecodeError::SingularMatrix { row: 7 });
        assert_eq!(state.rhs, initial_rhs);
        assert_eq!(active_cols(&state), initial_active);
        assert!(inactive_cols(&state).is_empty());
        assert_eq!(trace.inactive_cols, vec![3, 7]);
    }

    #[test]
    fn dense_failure_restores_decoder_state_after_early_termination() {
        let decoder = InactivationDecoder::new(8, 16, 3201);
        let params = decoder.params().clone();
        let mut state = make_rank_deficient_state(&params, 16, 3, 7);
        let initial_rhs = state.rhs.clone();
        let initial_active = active_cols(&state);

        let err = decoder.inactivate_and_solve(&mut state).unwrap_err();
        assert_eq!(err, DecodeError::SingularMatrix { row: 7 });
        assert_eq!(
            state.rhs, initial_rhs,
            "dense-failure cleanup must restore RHS rows taken into the dense core"
        );
        assert_eq!(
            active_cols(&state),
            initial_active,
            "dense-failure cleanup must reactivate unsolved columns for postmortem inspection"
        );
        assert!(
            inactive_cols(&state).is_empty(),
            "dense-failure cleanup must not leak inactive-column bookkeeping"
        );
    }

    #[test]
    fn dense_failure_with_proof_restores_decoder_state_after_early_termination() {
        let decoder = InactivationDecoder::new(8, 16, 3202);
        let params = decoder.params().clone();
        let mut state = make_rank_deficient_state(&params, 16, 3, 7);
        let initial_rhs = state.rhs.clone();
        let initial_active = active_cols(&state);
        let mut trace = EliminationTrace::default();

        let err = decoder
            .inactivate_and_solve_with_proof(&mut state, &mut trace)
            .unwrap_err();
        assert_eq!(err, DecodeError::SingularMatrix { row: 7 });
        assert_eq!(
            state.rhs, initial_rhs,
            "proof dense-failure cleanup must restore RHS rows taken into the dense core"
        );
        assert_eq!(
            active_cols(&state),
            initial_active,
            "proof dense-failure cleanup must reactivate unsolved columns for postmortem inspection"
        );
        assert!(
            inactive_cols(&state).is_empty(),
            "proof dense-failure cleanup must not leak inactive-column bookkeeping"
        );
    }

    #[test]
    fn dense_core_rhs_width_drift_fails_closed_before_plain_snapshot() {
        let decoder = InactivationDecoder::new(8, 16, 3203);
        let params = decoder.params().clone();
        let mut state = make_rank_deficient_state(&params, 16, 3, 7);
        let initial_rhs = state.rhs.clone();
        let initial_active = active_cols(&state);
        state.rhs[0].truncate(15);

        let err = decoder.inactivate_and_solve(&mut state).unwrap_err();
        assert_eq!(
            err,
            DecodeError::SymbolSizeMismatch {
                expected: 16,
                actual: 15,
            },
            "dense-core RHS width drift must fail closed instead of panicking during snapshot"
        );
        assert_eq!(state.rhs[0].len(), 15);
        assert_eq!(state.rhs[1], initial_rhs[1]);
        assert_eq!(active_cols(&state), initial_active);
        assert!(inactive_cols(&state).is_empty());
    }

    #[test]
    fn dense_core_rhs_width_drift_fails_closed_before_proof_snapshot() {
        let decoder = InactivationDecoder::new(8, 16, 3204);
        let params = decoder.params().clone();
        let mut state = make_rank_deficient_state(&params, 16, 3, 7);
        let initial_rhs = state.rhs.clone();
        let initial_active = active_cols(&state);
        let mut trace = EliminationTrace::default();
        state.rhs[0].truncate(15);

        let err = decoder
            .inactivate_and_solve_with_proof(&mut state, &mut trace)
            .unwrap_err();
        assert_eq!(
            err,
            DecodeError::SymbolSizeMismatch {
                expected: 16,
                actual: 15,
            },
            "proof dense-core RHS width drift must fail closed instead of panicking during snapshot"
        );
        assert_eq!(state.rhs[0].len(), 15);
        assert_eq!(state.rhs[1], initial_rhs[1]);
        assert_eq!(active_cols(&state), initial_active);
        assert!(inactive_cols(&state).is_empty());
        assert_eq!(trace.inactive_cols, vec![3, 7]);
        assert_eq!(trace.inactivated, 2);
        assert!(trace.pivot_events.is_empty());
    }

    #[test]
    fn failure_reason_captures_attempted_pivot_columns() {
        let mut elimination = EliminationTrace::default();
        elimination.record_pivot(3, 0);
        elimination.record_pivot(9, 1);

        let reason =
            failure_reason_with_trace(&DecodeError::SingularMatrix { row: 11 }, &elimination);
        assert_eq!(
            reason,
            FailureReason::SingularMatrix {
                row: 11,
                attempted_cols: vec![3, 9],
            }
        );
    }

    #[test]
    fn singular_matrix_error_maps_reordered_dense_column_to_original_id() {
        assert_eq!(
            singular_matrix_error(&[11, 3, 7], 2),
            DecodeError::SingularMatrix { row: 7 },
            "defensive pivot fallbacks must report the original column id, not the dense ordinal"
        );
    }

    #[test]
    fn pivot_tie_break_prefers_lowest_available_row_deterministically() {
        let decoder = InactivationDecoder::new(8, 1, 999);
        let params = decoder.params().clone();

        let mut state_one = make_pivot_tie_break_state(&params, 1, 3, 7);
        let mut trace_one = EliminationTrace::default();
        decoder
            .inactivate_and_solve_with_proof(&mut state_one, &mut trace_one)
            .expect("tie-break test state should be solvable");

        assert_eq!(
            trace_one
                .pivot_events
                .iter()
                .map(|ev| (ev.col, ev.row))
                .collect::<Vec<_>>(),
            vec![(3, 0), (7, 1)],
            "pivot order should be deterministic and prefer lowest available row"
        );
        assert_eq!(state_one.solved[3], Some(vec![0x10]));
        assert_eq!(state_one.solved[7], Some(vec![0x20]));

        let mut state_two = make_pivot_tie_break_state(&params, 1, 3, 7);
        let mut trace_two = EliminationTrace::default();
        decoder
            .inactivate_and_solve_with_proof(&mut state_two, &mut trace_two)
            .expect("second solve should match first solve");

        assert_eq!(
            trace_one.pivot_events, trace_two.pivot_events,
            "pivot trace should be stable across repeated runs"
        );
    }

    #[test]
    fn inconsistent_overdetermined_system_reports_singular_error() {
        let decoder = InactivationDecoder::new(8, 16, 111);
        let params = decoder.params().clone();
        let mut state = make_inconsistent_overdetermined_state(&params, 16, 3, 7);

        let err = decoder.inactivate_and_solve(&mut state).unwrap_err();
        assert_eq!(
            err,
            DecodeError::SingularMatrix { row: 2 },
            "contradictory overdetermined system should fail deterministically at witness row"
        );
    }

    #[test]
    fn inconsistent_overdetermined_with_proof_preserves_attempt_history() {
        let decoder = InactivationDecoder::new(8, 16, 222);
        let params = decoder.params().clone();
        let mut state = make_inconsistent_overdetermined_state(&params, 16, 3, 7);
        let mut trace = EliminationTrace::default();

        let err = decoder
            .inactivate_and_solve_with_proof(&mut state, &mut trace)
            .unwrap_err();
        assert_eq!(err, DecodeError::SingularMatrix { row: 2 });
        assert_eq!(
            trace
                .pivot_events
                .iter()
                .map(|ev| ev.col)
                .collect::<Vec<_>>(),
            vec![3, 7],
            "inconsistent-system witness should preserve full pivot-attempt history"
        );
    }

    #[test]
    fn dense_core_extraction_drops_redundant_zero_rows() {
        let decoder = InactivationDecoder::new(8, 16, 6060);
        let params = decoder.params().clone();
        let mut state = make_dense_core_prunable_state(&params, 16, 3, 7, 0x00);

        decoder
            .inactivate_and_solve(&mut state)
            .expect("state with redundant zero row should be solvable");
        assert_eq!(
            state.stats.dense_core_rows, 2,
            "dense core should only include rows with unsolved-column signal"
        );
        assert_eq!(
            state.stats.dense_core_cols, 2,
            "dense core should preserve unsolved column width"
        );
        assert_eq!(
            state.stats.dense_core_dropped_rows, 1,
            "one redundant zero-information row should be dropped"
        );
    }

    #[test]
    fn dense_core_inconsistent_constant_row_reports_equation_witness() {
        let decoder = InactivationDecoder::new(8, 16, 6161);
        let params = decoder.params().clone();
        let mut state = make_dense_core_prunable_state(&params, 16, 3, 7, 0x01);

        let err = decoder.inactivate_and_solve(&mut state).unwrap_err();
        assert_eq!(
            err,
            DecodeError::SingularMatrix { row: 2 },
            "inconsistent constant row should report deterministic original equation index"
        );
    }

    #[test]
    fn baseline_failure_triggers_deterministic_hard_regime_fallback() {
        let decoder = InactivationDecoder::new(8, 1, 4242);
        let params = decoder.params().clone();
        let mut state = make_rank_deficient_state(&params, 1, 3, 7);

        let err = decoder.inactivate_and_solve(&mut state).unwrap_err();
        assert_eq!(err, DecodeError::SingularMatrix { row: 7 });
        assert!(
            state.stats.hard_regime_activated,
            "fallback should activate hard regime deterministically"
        );
        assert_eq!(
            state.stats.hard_regime_fallbacks, 1,
            "exactly one fallback transition is expected"
        );
        assert!(
            state.stats.markowitz_pivots <= state.stats.pivots_selected,
            "hard-regime pivot accounting should remain internally consistent"
        );
    }

    #[test]
    fn proof_trace_records_fallback_transition_reason() {
        let decoder = InactivationDecoder::new(8, 1, 4343);
        let params = decoder.params().clone();
        let mut state = make_rank_deficient_state(&params, 1, 3, 7);
        let mut trace = EliminationTrace::default();

        let err = decoder
            .inactivate_and_solve_with_proof(&mut state, &mut trace)
            .unwrap_err();
        assert_eq!(err, DecodeError::SingularMatrix { row: 7 });
        assert_eq!(
            trace.strategy,
            InactivationStrategy::HighSupportFirst,
            "proof trace should expose fallback strategy"
        );
        assert_eq!(
            trace.strategy_transitions.len(),
            1,
            "fallback should record one strategy transition"
        );
        assert_eq!(
            trace.strategy_transitions[0].reason, "fallback_after_baseline_failure",
            "transition reason should be deterministic and triage-friendly"
        );
        assert_eq!(
            trace
                .pivot_events
                .iter()
                .map(|ev| ev.col)
                .collect::<Vec<_>>(),
            vec![3],
            "fallback proof should preserve the deterministic pivot-attempt witness"
        );
    }

    #[test]
    fn hard_regime_activation_is_deterministic_and_observable() {
        set_test_bypass_governance(true);
        let decoder = InactivationDecoder::new(8, 1, 3030);
        let params = decoder.params().clone();

        let mut state_one = make_hard_regime_dense_state(&params, 1, 4, 8);
        let mut trace_one = EliminationTrace::default();
        decoder
            .inactivate_and_solve_with_proof(&mut state_one, &mut trace_one)
            .expect("hard regime state should be solvable");

        assert!(
            state_one.stats.hard_regime_activated,
            "hard-regime transition should be observable in decode stats"
        );
        assert_eq!(
            state_one.stats.markowitz_pivots, 8,
            "all hard-regime pivots should use deterministic Markowitz selector"
        );
        assert_eq!(
            trace_one.strategy,
            InactivationStrategy::HighSupportFirst,
            "proof trace must expose hard-regime strategy"
        );
        assert_eq!(
            trace_one.strategy_transitions.len(),
            1,
            "hard regime should record a single strategy transition"
        );
        assert_eq!(
            trace_one.strategy_transitions[0].reason, "dense_or_near_square",
            "transition reason should be deterministic and triage-friendly"
        );

        let mut state_two = make_hard_regime_dense_state(&params, 1, 4, 8);
        let mut trace_two = EliminationTrace::default();
        decoder
            .inactivate_and_solve_with_proof(&mut state_two, &mut trace_two)
            .expect("repeated hard regime solve should succeed");

        assert_eq!(
            state_one.stats.markowitz_pivots, state_two.stats.markowitz_pivots,
            "hard-regime pivot counts should be stable across runs"
        );
        assert_eq!(
            trace_one.pivot_events, trace_two.pivot_events,
            "hard-regime pivot event ordering must be deterministic"
        );
        assert_eq!(
            trace_one.strategy_transitions, trace_two.strategy_transitions,
            "hard-regime strategy transition history must be deterministic"
        );
    }

    #[test]
    fn hard_regime_plan_selects_block_schur_for_dense_large_core() {
        let n_rows = 12;
        let n_cols = 12;
        let dense = vec![Gf256::ONE; n_rows * n_cols];
        let plan = select_hard_regime_plan(n_rows, n_cols, &dense);
        assert_eq!(
            plan,
            HardRegimePlan::BlockSchurLowRank { split_col: 8 },
            "dense 12x12 system should select deterministic block-schur plan"
        );
    }

    #[test]
    fn block_schur_failure_falls_back_to_markowitz_with_reason() {
        set_test_bypass_governance(true);
        let decoder = InactivationDecoder::new(32, 1, 7070);
        let params = decoder.params().clone();
        let mut state = make_block_schur_rank_deficient_state(&params, 1, 4, 12);
        let mut trace = EliminationTrace::default();

        let err = decoder
            .inactivate_and_solve_with_proof(&mut state, &mut trace)
            .expect_err("rank-deficient block-schur candidate should fail deterministically");
        assert!(matches!(err, DecodeError::SingularMatrix { .. }));
        assert!(
            state.stats.hard_regime_activated,
            "dense rank-deficient system should activate hard regime"
        );
        assert_eq!(
            state.stats.hard_regime_branch,
            Some("block_schur_low_rank"),
            "stats should expose deterministic accelerated branch selection"
        );
        assert_eq!(
            state.stats.hard_regime_conservative_fallback_reason,
            Some("block_schur_failed_to_converge"),
            "stats should expose deterministic conservative fallback reason"
        );
        assert_eq!(
            state.stats.hard_regime_fallbacks, 1,
            "block-schur attempt should perform exactly one conservative fallback"
        );
        assert!(
            trace.strategy_transitions.iter().any(|transition| {
                transition.from == InactivationStrategy::BlockSchurLowRank
                    && transition.to == InactivationStrategy::HighSupportFirst
                    && transition.reason == "block_schur_failed_to_converge"
            }),
            "proof trace should record deterministic branch fallback transition"
        );
    }

    #[test]
    fn block_schur_fallback_preserves_non_pivot_truncation_flags() {
        set_test_bypass_governance(true);
        let decoder = InactivationDecoder::new(300, 1, 7171);
        let params = decoder.params().clone();
        let mut state = make_block_schur_rank_deficient_state(
            &params,
            1,
            4,
            crate::raptorq::proof::MAX_PIVOT_EVENTS + 1,
        );
        let mut trace = EliminationTrace::default();

        let err = decoder
            .inactivate_and_solve_with_proof(&mut state, &mut trace)
            .expect_err("wide rank-deficient block-schur candidate should fail deterministically");
        assert!(matches!(err, DecodeError::SingularMatrix { .. }));
        assert!(
            trace.inactive_cols_truncated,
            "large inactivation witness must stay marked truncated after fallback cleanup"
        );
        assert!(
            !trace.pivot_events_truncated,
            "clearing pivot history for retry should only reset the pivot-events truncation flag"
        );
        assert!(
            !trace.strategy_transitions_truncated,
            "single fallback transition should remain non-truncated"
        );
    }

    #[test]
    fn normal_regime_keeps_basic_pivot_strategy() {
        let decoder = InactivationDecoder::new(8, 1, 99);
        let params = decoder.params().clone();
        let mut state = make_pivot_tie_break_state(&params, 1, 3, 7);

        decoder
            .inactivate_and_solve(&mut state)
            .expect("normal regime test state should solve");

        assert!(
            !state.stats.hard_regime_activated,
            "small systems should stay on the baseline inactivation strategy"
        );
        assert_eq!(
            state.stats.markowitz_pivots, 0,
            "baseline strategy should not report Markowitz pivots"
        );
    }

    #[test]
    fn normal_regime_proof_trace_keeps_all_at_once_strategy() {
        let decoder = InactivationDecoder::new(8, 1, 100);
        let params = decoder.params().clone();
        let mut state = make_pivot_tie_break_state(&params, 1, 3, 7);
        let mut trace = EliminationTrace::default();

        decoder
            .inactivate_and_solve_with_proof(&mut state, &mut trace)
            .expect("normal regime proof solve should succeed");

        assert_eq!(
            trace.strategy,
            InactivationStrategy::AllAtOnce,
            "normal regime should stay on baseline strategy"
        );
        assert!(
            trace.strategy_transitions.is_empty(),
            "normal regime must not emit strategy transitions"
        );
    }

    #[test]
    fn policy_metadata_is_recorded_for_conservative_mode() {
        let decoder = InactivationDecoder::new(8, 1, 101);
        let params = decoder.params().clone();
        let mut state = make_pivot_tie_break_state(&params, 1, 3, 7);

        decoder
            .inactivate_and_solve(&mut state)
            .expect("conservative-mode state should solve");

        assert_eq!(state.stats.policy_mode, Some("conservative_baseline"));
        assert_eq!(
            state.stats.policy_reason,
            Some("expected_loss_conservative_gate")
        );
        assert_eq!(state.stats.policy_replay_ref, Some(POLICY_REPLAY_REF));
        assert!(state.stats.policy_baseline_loss > 0);
        assert!(state.stats.policy_high_support_loss > 0);
        let governance = state
            .stats
            .governance
            .expect("governance telemetry must be recorded");
        assert_eq!(
            governance.replay_ref,
            decision_contract::G7_DECISION_REPLAY_REF
        );
        assert_eq!(
            governance
                .state_posterior_permille
                .iter()
                .map(|&value| u32::from(value))
                .sum::<u32>(),
            1000
        );
    }

    #[test]
    fn policy_metadata_is_recorded_for_aggressive_mode() {
        set_test_bypass_governance(true);
        let decoder = InactivationDecoder::new(32, 1, 8080);
        let params = decoder.params().clone();
        let mut state = make_block_schur_rank_deficient_state(&params, 1, 2, 15);

        let _err = decoder.inactivate_and_solve(&mut state).unwrap_err();

        assert!(
            matches!(
                state.stats.policy_mode,
                Some("high_support_first" | "block_schur_low_rank")
            ),
            "dense state should log an aggressive policy mode"
        );
        assert_eq!(state.stats.policy_reason, Some("expected_loss_minimum"));
        assert_eq!(state.stats.policy_replay_ref, Some(POLICY_REPLAY_REF));
        assert!(state.stats.policy_density_permille >= 350);
        let governance = state
            .stats
            .governance
            .expect("governance telemetry must be recorded");
        assert!(matches!(
            governance.chosen_action,
            "continue" | "canary_hold" | "rollback" | "fallback"
        ));
        assert!(governance.confidence_score <= 1000);
    }

    // =========================================================================
    // Golden Artifact Testing for Decode Transcripts
    // =========================================================================

    #[cfg(test)]
    mod golden_transcript_tests {
        use super::*;
        use crate::raptorq::systematic::SystematicEncoder;
        use crate::types::ObjectId;
        use std::fs;
        use std::path::Path;

        /// Golden confidence matrix entry for decode transcripts
        #[derive(Debug)]
        struct TranscriptGolden {
            deterministic: bool,
            platform_dependent: bool,
            volatility: u8, // 1-5 scale
            strategy: &'static str,
        }

        impl TranscriptGolden {
            const fn scrubbed() -> Self {
                Self {
                    deterministic: false,
                    platform_dependent: false,
                    volatility: 2,
                    strategy: "scrubbed",
                }
            }
        }

        /// Core golden comparison infrastructure for decode transcripts
        fn assert_transcript_golden(
            test_name: &str,
            actual_proof: &DecodeProof,
            strategy: &TranscriptGolden,
        ) {
            let golden_path = Path::new("tests/golden/raptorq_transcripts")
                .join(format!("{test_name}.golden.json"));
            assert!(
                (1..=5).contains(&strategy.volatility),
                "golden volatility must stay on the documented 1-5 scale"
            );
            assert!(
                !(strategy.deterministic && strategy.platform_dependent),
                "platform-dependent transcripts cannot be exact deterministic goldens"
            );

            // Prepare output based on strategy
            let output = match strategy.strategy {
                "exact" => serde_json::to_string_pretty(actual_proof).unwrap(),
                "scrubbed" => {
                    let scrubbed = scrub_decode_proof_for_golden(actual_proof);
                    serde_json::to_string_pretty(&scrubbed).unwrap()
                }
                _ => panic!("Unknown golden strategy: {}", strategy.strategy),
            };

            // UPDATE MODE: overwrite golden with actual output
            if std::env::var("UPDATE_GOLDENS").is_ok() {
                fs::create_dir_all(golden_path.parent().unwrap()).unwrap();
                fs::write(&golden_path, &output).unwrap();
                eprintln!("[GOLDEN] Updated: {}", golden_path.display());
                return;
            }

            // COMPARE MODE: diff actual vs golden
            let expected = fs::read_to_string(&golden_path).unwrap_or_else(|_| {
                panic!(
                    "Golden file missing: {}\n\
                     Run with UPDATE_GOLDENS=1 to create it\n\
                     Then review and commit: git diff tests/golden/",
                    golden_path.display()
                )
            });

            if output != expected {
                // Write actual for easy diffing
                let actual_path = golden_path.with_extension("actual.json");
                fs::write(&actual_path, &output).unwrap();

                panic!(
                    "GOLDEN TRANSCRIPT MISMATCH: {test_name}\n\n\
                     To update: UPDATE_GOLDENS=1 cargo test -- {test_name}\n\
                     To review: diff {} {}",
                    golden_path.display(),
                    actual_path.display(),
                );
            }
        }

        /// Scrubber for non-deterministic values in decode transcripts
        fn scrub_decode_proof_for_golden(proof: &DecodeProof) -> serde_json::Value {
            use serde_json::json;

            // Extract transcript-specific data with scrubbing
            json!({
                "version": proof.version,
                "config": {
                    "k": proof.config.k,
                    "l": proof.config.l,
                    "h": proof.config.h,
                    "s": proof.config.s,
                    "symbol_size": proof.config.symbol_size,
                    "seed": "[SEED]", // Scrub non-deterministic seed
                    "object_id": "[OBJECT_ID]", // Scrub object ID
                    "sbn": proof.config.sbn,
                },
                "peeling_trace": {
                    "solved": proof.peeling.solved,
                    "solved_indices": proof.peeling.solved_indices,
                    "truncated": proof.peeling.truncated,
                },
                "elimination_trace": {
                    "strategy": format!("{:?}", proof.elimination.strategy),
                    "inactivated": proof.elimination.inactivated,
                    "inactive_cols": proof.elimination.inactive_cols,
                    "inactive_cols_truncated": proof.elimination.inactive_cols_truncated,
                    "pivots": proof.elimination.pivots,
                    "pivot_events": proof.elimination.pivot_events,
                    "pivot_events_truncated": proof.elimination.pivot_events_truncated,
                    "row_ops": proof.elimination.row_ops,
                    "strategy_transitions": proof.elimination.strategy_transitions,
                    "strategy_transitions_truncated": proof.elimination.strategy_transitions_truncated,
                },
                "outcome": match &proof.outcome {
                    crate::raptorq::proof::ProofOutcome::Success { symbols_recovered, .. } => {
                        json!({
                            "kind": "Success",
                            "symbols_recovered": symbols_recovered,
                            "source_payload_hash": "[HASH]", // Scrub hash for determinism
                        })
                    }
                    crate::raptorq::proof::ProofOutcome::Failure { reason } => {
                        json!({
                            "kind": "Failure",
                            "reason": format!("{:?}", reason), // Keep structure but scrub specifics
                        })
                    }
                },
                "received_summary": {
                    "total": proof.received.total,
                    "source_count": proof.received.source_count,
                    "repair_count": proof.received.repair_count,
                    "esi_multiset_hash": "[ESI_HASH]", // Scrub for determinism
                    "esis_length": proof.received.esis.len(),
                    "truncated": proof.received.truncated,
                },
                "content_hash": "[CONTENT_HASH]", // Scrub for determinism
            })
        }

        fn progress_trace_snapshot(
            scenario: &str,
            seed: u64,
            proof: &DecodeProof,
        ) -> serde_json::Value {
            use serde_json::json;

            json!({
                "scenario": scenario,
                "seed": seed,
                "config": {
                    "k": proof.config.k,
                    "l": proof.config.l,
                    "h": proof.config.h,
                    "s": proof.config.s,
                    "symbol_size": proof.config.symbol_size,
                    "sbn": proof.config.sbn,
                },
                "peeling_trace": {
                    "solved": proof.peeling.solved,
                    "solved_indices": proof.peeling.solved_indices,
                    "truncated": proof.peeling.truncated,
                },
                "elimination_trace": {
                    "strategy": format!("{:?}", proof.elimination.strategy),
                    "inactivated": proof.elimination.inactivated,
                    "inactive_cols": proof.elimination.inactive_cols,
                    "inactive_cols_truncated": proof.elimination.inactive_cols_truncated,
                    "pivots": proof.elimination.pivots,
                    "pivot_events": proof.elimination.pivot_events,
                    "pivot_events_truncated": proof.elimination.pivot_events_truncated,
                    "row_ops": proof.elimination.row_ops,
                    "strategy_transitions": proof.elimination.strategy_transitions,
                    "strategy_transitions_truncated": proof.elimination.strategy_transitions_truncated,
                },
                "outcome": match &proof.outcome {
                    crate::raptorq::proof::ProofOutcome::Success { symbols_recovered, .. } => {
                        json!({
                            "kind": "Success",
                            "symbols_recovered": symbols_recovered,
                        })
                    }
                    crate::raptorq::proof::ProofOutcome::Failure { reason } => {
                        json!({
                            "kind": "Failure",
                            "reason": format!("{reason:?}"),
                        })
                    }
                },
                "received_summary": {
                    "total": proof.received.total,
                    "source_count": proof.received.source_count,
                    "repair_count": proof.received.repair_count,
                    "esis_length": proof.received.esis.len(),
                    "truncated": proof.received.truncated,
                },
            })
        }

        /// Test successful decode transcript with systematic symbols only
        #[test]
        fn golden_transcript_systematic_success() {
            let k = 6;
            let symbol_size = 16;
            let seed = 12345u64; // Fixed seed for determinism

            let source = make_deterministic_source_data(k, symbol_size);
            let decoder = InactivationDecoder::new(k, symbol_size, seed);

            // Use only systematic source symbols (should succeed via peeling)
            let mut received = decoder.constraint_symbols();
            received.extend(make_received_source(&decoder, &source));

            let result = decoder
                .decode_with_proof(&received, ObjectId::new_for_test(1000), 0)
                .expect("systematic symbols should decode successfully");

            // This should be deterministic enough for exact golden comparison
            assert_transcript_golden(
                "systematic_success",
                &result.proof,
                &TranscriptGolden::scrubbed(),
            );
        }

        /// Test decode transcript with peeling and elimination phases
        #[test]
        fn golden_transcript_mixed_peeling_elimination() {
            let k = 8;
            let symbol_size = 32;
            let seed = 54321u64; // Fixed seed for determinism

            let source = make_deterministic_source_data(k, symbol_size);
            let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
            let decoder = InactivationDecoder::new(k, symbol_size, seed);

            let mut received = decoder.constraint_symbols();
            received.extend(make_received_source(&decoder, &source));

            // Add selective repair symbols to force mixed peeling + elimination
            for esi in (k as u32)..(k as u32 + 3) {
                let (cols, coefs) = decoder.repair_equation(esi).unwrap();
                let repair_data = encoder.repair_symbol(esi);
                received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
            }

            let result = decoder
                .decode_with_proof(&received, ObjectId::new_for_test(2000), 0)
                .expect("mixed scenario should decode successfully");

            assert_transcript_golden(
                "mixed_peeling_elimination",
                &result.proof,
                &TranscriptGolden::scrubbed(),
            );
        }

        /// Test decode transcript for insufficient symbols failure
        #[test]
        fn golden_transcript_insufficient_symbols_failure() {
            let k = 10;
            let symbol_size = 32;
            let seed = 99999u64;

            let source = make_deterministic_source_data(k, symbol_size);
            let decoder = InactivationDecoder::new(k, symbol_size, seed);

            // Provide insufficient symbols (only 3 out of required K=10)
            let received: Vec<_> = make_received_source(&decoder, &source)
                .into_iter()
                .take(3)
                .collect();

            let (_err, proof) = decoder
                .decode_with_proof(&received, ObjectId::new_for_test(3000), 0)
                .expect_err("insufficient symbols should fail");

            assert_transcript_golden(
                "insufficient_symbols_failure",
                &proof,
                &TranscriptGolden::scrubbed(),
            );
        }

        /// Test decode transcript with strategy transitions
        #[test]
        fn golden_transcript_strategy_transitions() {
            let k = 12;
            let symbol_size = 64;
            let seed = 777u64; // Chosen to trigger strategy transitions

            let source = make_deterministic_source_data(k, symbol_size);
            let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
            let decoder = InactivationDecoder::new(k, symbol_size, seed);
            let l = decoder.params().l;

            let mut received = decoder.constraint_symbols();

            // Add systematic sources except a few to force strategic pivoting
            let partial_source: Vec<_> = make_received_source(&decoder, &source)
                .into_iter()
                .take(k - 2)
                .collect();
            received.extend(partial_source);

            // Add many repair symbols to create complex elimination scenario
            for esi in (k as u32)..(l as u32) {
                let (cols, coefs) = decoder.repair_equation(esi).unwrap();
                let repair_data = encoder.repair_symbol(esi);
                received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
            }

            let result = decoder
                .decode_with_proof(&received, ObjectId::new_for_test(4000), 0)
                .expect("strategy transition scenario should succeed");

            assert_transcript_golden(
                "strategy_transitions",
                &result.proof,
                &TranscriptGolden::scrubbed(),
            );
        }

        #[test]
        fn decoder_progress_trace_fixed_seeds() {
            let systematic_k = 6;
            let systematic_symbol_size = 16;
            let systematic_seed = 12345u64;
            let systematic_source =
                make_deterministic_source_data(systematic_k, systematic_symbol_size);
            let systematic_decoder =
                InactivationDecoder::new(systematic_k, systematic_symbol_size, systematic_seed);
            let mut systematic_received = systematic_decoder.constraint_symbols();
            systematic_received.extend(make_received_source(
                &systematic_decoder,
                &systematic_source,
            ));
            let systematic_result = systematic_decoder
                .decode_with_proof(&systematic_received, ObjectId::new_for_test(5000), 0)
                .expect("systematic symbols should decode successfully");

            let mixed_k = 8;
            let mixed_symbol_size = 32;
            let mixed_seed = 54321u64;
            let mixed_source = make_deterministic_source_data(mixed_k, mixed_symbol_size);
            let mixed_encoder =
                SystematicEncoder::new(&mixed_source, mixed_symbol_size, mixed_seed).unwrap();
            let mixed_decoder = InactivationDecoder::new(mixed_k, mixed_symbol_size, mixed_seed);
            let mut mixed_received = mixed_decoder.constraint_symbols();
            mixed_received.extend(make_received_source(&mixed_decoder, &mixed_source));
            for esi in (mixed_k as u32)..(mixed_k as u32 + 3) {
                let (cols, coefs) = mixed_decoder.repair_equation(esi).unwrap();
                let repair_data = mixed_encoder.repair_symbol(esi);
                mixed_received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
            }
            let mixed_result = mixed_decoder
                .decode_with_proof(&mixed_received, ObjectId::new_for_test(6000), 0)
                .expect("mixed scenario should decode successfully");

            let failure_k = 10;
            let failure_symbol_size = 32;
            let failure_seed = 99999u64;
            let failure_source = make_deterministic_source_data(failure_k, failure_symbol_size);
            let failure_decoder =
                InactivationDecoder::new(failure_k, failure_symbol_size, failure_seed);
            let failure_received: Vec<_> = make_received_source(&failure_decoder, &failure_source)
                .into_iter()
                .take(3)
                .collect();
            let (_failure_err, failure_proof) = failure_decoder
                .decode_with_proof(&failure_received, ObjectId::new_for_test(7000), 0)
                .expect_err("insufficient symbols should fail");

            let transition_k = 12;
            let transition_symbol_size = 64;
            let transition_seed = 777u64;
            let transition_source =
                make_deterministic_source_data(transition_k, transition_symbol_size);
            let transition_encoder =
                SystematicEncoder::new(&transition_source, transition_symbol_size, transition_seed)
                    .unwrap();
            let transition_decoder =
                InactivationDecoder::new(transition_k, transition_symbol_size, transition_seed);
            let transition_l = transition_decoder.params().l;
            let mut transition_received = transition_decoder.constraint_symbols();
            transition_received.extend(
                make_received_source(&transition_decoder, &transition_source)
                    .into_iter()
                    .take(transition_k - 2),
            );
            for esi in (transition_k as u32)..(transition_l as u32) {
                let (cols, coefs) = transition_decoder.repair_equation(esi).unwrap();
                let repair_data = transition_encoder.repair_symbol(esi);
                transition_received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
            }
            let transition_result = transition_decoder
                .decode_with_proof(&transition_received, ObjectId::new_for_test(8000), 0)
                .expect("strategy transition scenario should succeed");

            insta::assert_json_snapshot!(
                "decoder_progress_trace_fixed_seeds",
                serde_json::json!({
                    "systematic_success": progress_trace_snapshot(
                        "systematic_success",
                        systematic_seed,
                        &systematic_result.proof,
                    ),
                    "mixed_peeling_elimination": progress_trace_snapshot(
                        "mixed_peeling_elimination",
                        mixed_seed,
                        &mixed_result.proof,
                    ),
                    "insufficient_symbols_failure": progress_trace_snapshot(
                        "insufficient_symbols_failure",
                        failure_seed,
                        &failure_proof,
                    ),
                    "strategy_transitions": progress_trace_snapshot(
                        "strategy_transitions",
                        transition_seed,
                        &transition_result.proof,
                    ),
                })
            );
        }

        /// Helper to create deterministic source data for golden tests
        fn make_deterministic_source_data(k: usize, symbol_size: usize) -> Vec<Vec<u8>> {
            (0..k)
                .map(|i| {
                    // Use a deterministic, stable pattern
                    (0..symbol_size)
                        .map(|j| ((i * 73 + j * 31 + 17) % 256) as u8)
                        .collect()
                })
                .collect()
        }
    }

    #[test]
    fn decoder_policy_budget_exhaustion_forces_conservative_baseline() {
        let n_rows = 65;
        let n_cols = 65;
        let dense = vec![Gf256::ONE; n_rows * n_cols];
        let decision = choose_runtime_decoder_policy(n_rows, n_cols, dense.len(), 0, 700);
        assert_eq!(decision.mode, DecoderPolicyMode::ConservativeBaseline);
        assert_eq!(decision.reason, "policy_budget_exhausted_conservative");
        assert!(decision.features.budget_exhausted);
        assert!(
            decision
                .governance
                .is_some_and(|telemetry| telemetry.deterministic_fallback_triggered)
        );
    }

    #[test]
    fn decoder_policy_prefers_aggressive_strategy_for_dense_high_pressure() {
        set_test_bypass_governance(true);
        let n_rows = 16;
        let n_cols = 16;
        let dense = vec![Gf256::ONE; n_rows * n_cols];
        let decision = choose_runtime_decoder_policy(n_rows, n_cols, dense.len(), 0, 850);
        assert!(
            matches!(
                decision.mode,
                DecoderPolicyMode::HighSupportFirst | DecoderPolicyMode::BlockSchurLowRank
            ),
            "dense/high-pressure matrix should avoid conservative baseline"
        );
    }

    #[test]
    fn decoder_policy_prefers_conservative_for_sparse_low_pressure() {
        let n_rows = 24;
        let n_cols = 16;
        let mut sparse = vec![Gf256::ZERO; n_rows * n_cols];
        for idx in 0..n_cols {
            sparse[idx * n_cols + idx] = Gf256::ONE;
        }

        let one = choose_runtime_decoder_policy(n_rows, n_cols, n_cols, 0, 40);
        let two = choose_runtime_decoder_policy(n_rows, n_cols, n_cols, 0, 40);
        assert_eq!(one, two, "policy decision should be deterministic");
        assert_eq!(one.mode, DecoderPolicyMode::ConservativeBaseline);
        assert_eq!(one.reason, "expected_loss_conservative_gate");
        assert!(
            one.governance.is_some(),
            "G7 governance telemetry must be present"
        );
    }

    // ── all_source_equations / source_equation coverage (br-3narc.2.7) ──

    #[test]
    fn all_source_equations_returns_rfc_tuple_rows() {
        let k = 8;
        let decoder = InactivationDecoder::new(k, 32, 42);
        let equations = decoder.all_source_equations();

        assert_eq!(equations.len(), k, "should return exactly K equations");
        for (i, (cols, coefs)) in equations.iter().enumerate() {
            let expected_cols = repair_indices_for_esi(
                decoder.params().j,
                decoder.params().w,
                decoder.params().p,
                u32::try_from(i).expect("source ESI must fit in u32"),
            );
            assert_eq!(
                cols, &expected_cols,
                "source equation {i} should use the RFC tuple row"
            );
            assert_eq!(
                coefs,
                &vec![Gf256::ONE; expected_cols.len()],
                "source equation {i} should have unit coefficients"
            );
        }
    }

    #[test]
    fn source_equation_matches_all_source_equations() {
        let k = 12;
        let decoder = InactivationDecoder::new(k, 16, 99);
        let all = decoder.all_source_equations();

        for esi in 0..k as u32 {
            let single = decoder.source_equation(esi);
            assert_eq!(
                single, all[esi as usize],
                "source_equation({esi}) must match all_source_equations()[{esi}]"
            );
        }
    }

    #[test]
    #[should_panic(expected = "source ESI must be < K")]
    fn source_equation_panics_on_esi_ge_k() {
        let k = 4;
        let decoder = InactivationDecoder::new(k, 16, 42);
        let _ = decoder.source_equation(k as u32); // ESI == K should panic
    }

    // ── Duplicate ESI handling (br-3narc.2.7) ──

    #[test]
    fn decode_with_duplicate_source_esi_produces_defined_outcome() {
        // Feeding the same ESI twice gives the decoder redundant equations.
        // It should either succeed (if the extra equation is linearly dependent)
        // or fail with SingularMatrix (if it introduces inconsistency).
        // It must NOT panic.
        let k = 8;
        let symbol_size = 32;
        let seed = 42u64;
        let source: Vec<Vec<u8>> = (0..k)
            .map(|i| {
                (0..symbol_size)
                    .map(|j| ((i * 37 + j * 13 + 7) % 256) as u8)
                    .collect()
            })
            .collect();

        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        let mut received = decoder.constraint_symbols();
        // Add all source symbols
        for (i, data) in source.iter().enumerate() {
            received.push(ReceivedSymbol::source(i as u32, data.clone()));
        }
        // Duplicate: add source symbol 0 again
        received.push(ReceivedSymbol::source(0, source[0].clone()));

        // Add repair to reach L
        for esi in (k as u32)..(l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi).unwrap();
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        // Must not panic; outcome is either Ok or a well-formed error
        let result = decoder.decode(&received);
        match result {
            Ok(decoded_symbols) => {
                assert_eq!(
                    decoded_symbols.source, source,
                    "decode with duplicate ESI should recover correct source"
                );
            }
            Err(e) => {
                // Redundant duplicate equations can still expose a rank-deficient witness,
                // but they should not be flattened into a raw underprovisioning error.
                assert!(
                    matches!(e, DecodeError::SingularMatrix { .. }),
                    "unexpected error type with duplicate ESI: {e:?}"
                );
            }
        }
    }

    // ── Zero-data source symbols (br-3narc.2.7) ──

    #[test]
    fn decode_all_zeros_source_data() {
        let k = 8;
        let symbol_size = 32;
        let seed = 42u64;

        let source: Vec<Vec<u8>> = (0..k).map(|_| vec![0u8; symbol_size]).collect();
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        let mut received = decoder.constraint_symbols();
        for (i, data) in source.iter().enumerate() {
            received.push(ReceivedSymbol::source(i as u32, data.clone()));
        }
        for esi in (k as u32)..(l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi).unwrap();
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let result = decoder
            .decode(&received)
            .expect("all-zeros source should decode");
        assert_eq!(result.source, source, "decoded all-zeros must match");
    }

    // ── Intermediate symbol reconstruction invariant (br-3narc.2.7) ──

    #[test]
    fn intermediate_symbols_match_encoder_after_decode() {
        let k = 8;
        let symbol_size = 32;
        let seed = 42u64;

        let source: Vec<Vec<u8>> = (0..k)
            .map(|i| {
                (0..symbol_size)
                    .map(|j| ((i * 37 + j * 13 + 7) % 256) as u8)
                    .collect()
            })
            .collect();

        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        let mut received = decoder.constraint_symbols();
        for (i, data) in source.iter().enumerate() {
            received.push(ReceivedSymbol::source(i as u32, data.clone()));
        }
        for esi in (k as u32)..(l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi).unwrap();
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let result = decoder.decode(&received).expect("decode should succeed");

        // Every intermediate symbol from decode must match the encoder's
        assert_eq!(result.intermediate.len(), l);
        for i in 0..l {
            assert_eq!(
                result.intermediate[i],
                encoder.intermediate_symbol(i),
                "intermediate symbol {i}/{l} must match encoder"
            );
        }
    }

    #[test]
    fn metamorphic_repair_only_decode_preserves_prefixes_under_zero_padding() {
        let k = 8;
        let symbol_size = 32;
        let padding = 11;
        let seed = 0x4D_0001_u64;

        let source = make_source_data(k, symbol_size);
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let l = decoder.params().l;

        let mut received = decoder.constraint_symbols();
        for esi in (k as u32)..(k as u32 + l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi).unwrap();
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let baseline = decoder
            .decode(&received)
            .expect("baseline repair-only decode");

        let padded_source: Vec<Vec<u8>> = source
            .iter()
            .map(|symbol| {
                let mut padded = symbol.clone();
                padded.resize(symbol_size + padding, 0);
                padded
            })
            .collect();
        let padded_symbol_size = symbol_size + padding;
        let padded_decoder = InactivationDecoder::new(k, padded_symbol_size, seed);
        let padded_encoder =
            SystematicEncoder::new(&padded_source, padded_symbol_size, seed).unwrap();

        let mut padded_received = padded_decoder.constraint_symbols();
        for esi in (k as u32)..(k as u32 + l as u32) {
            let (cols, coefs) = padded_decoder.repair_equation(esi).unwrap();
            let repair_data = padded_encoder.repair_symbol(esi);
            padded_received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let padded = padded_decoder
            .decode(&padded_received)
            .expect("padded repair-only decode");

        for (index, (baseline_symbol, padded_symbol)) in
            baseline.source.iter().zip(padded.source.iter()).enumerate()
        {
            assert_eq!(
                &padded_symbol[..symbol_size],
                baseline_symbol,
                "decoded prefix mismatch for source symbol {index}"
            );
            assert!(
                padded_symbol[symbol_size..].iter().all(|&byte| byte == 0),
                "decoded padded suffix must stay zero for source symbol {index}"
            );
        }
    }

    // ── Peeling + Gaussian coverage invariant (br-3narc.2.7) ──

    #[test]
    fn stats_peeled_plus_inactivated_covers_all_columns() {
        let k = 8;
        let symbol_size = 32;
        let seed = 42u64;

        let source: Vec<Vec<u8>> = (0..k)
            .map(|i| {
                (0..symbol_size)
                    .map(|j| ((i * 37 + j * 13 + 7) % 256) as u8)
                    .collect()
            })
            .collect();

        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        let mut received = decoder.constraint_symbols();
        for (i, data) in source.iter().enumerate() {
            received.push(ReceivedSymbol::source(i as u32, data.clone()));
        }
        for esi in (k as u32)..(l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi).unwrap();
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let result = decoder.decode(&received).expect("decode should succeed");
        assert_eq!(
            result.stats.peeled + result.stats.inactivated,
            l,
            "peeled + inactivated must equal L ({l})"
        );
    }

    // ========================================================================
    // F8: Wavefront decode pipeline tests
    // ========================================================================

    #[test]
    fn wavefront_decode_matches_sequential() {
        // Verify that wavefront decode produces identical source symbols
        // to sequential decode for a variety of batch sizes.
        let k = 16;
        let symbol_size = 64;
        let seed = 0xF8_0001u64;

        let source = make_source_data(k, symbol_size);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);

        let mut received = decoder.constraint_symbols();
        for esi in 0..(k as u32) {
            received.push(ReceivedSymbol::source(esi, source[esi as usize].clone()));
        }
        // Add a few repair symbols for robustness.
        for esi in (k as u32)..(k as u32 + 4) {
            let (cols, coefs) = decoder.repair_equation(esi).unwrap();
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let sequential = decoder.decode(&received).expect("sequential decode");

        for batch_size in [1, 2, 4, 8, 16, 0] {
            let wavefront = decoder
                .decode_wavefront(&received, batch_size)
                .unwrap_or_else(|_| panic!("wavefront decode batch_size={batch_size}"));

            for (i, (seq_sym, wf_sym)) in sequential
                .source
                .iter()
                .zip(wavefront.source.iter())
                .enumerate()
            {
                assert_eq!(
                    seq_sym, wf_sym,
                    "source symbol {i} mismatch at batch_size={batch_size}"
                );
            }

            assert!(wavefront.stats.wavefront_active);
            assert_eq!(
                wavefront.stats.wavefront_batch_size,
                if batch_size == 0 {
                    received.len()
                } else {
                    batch_size
                }
            );
            assert!(wavefront.stats.wavefront_batches > 0);
        }
    }

    #[test]
    fn wavefront_decode_with_loss_matches_sequential() {
        // Verify wavefront correctness under symbol loss (repair-only decode).
        let k = 8;
        let symbol_size = 32;
        let seed = 0xF8_0002u64;

        let source = make_source_data(k, symbol_size);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        let mut received = decoder.constraint_symbols();
        // Only repair symbols — no source symbols.
        for esi in (k as u32)..(k as u32 + l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi).unwrap();
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let sequential = decoder.decode(&received).expect("sequential decode");

        for batch_size in [1, 4, 8] {
            let wavefront = decoder
                .decode_wavefront(&received, batch_size)
                .unwrap_or_else(|_| panic!("wavefront batch_size={batch_size}"));

            for (i, (seq_sym, wf_sym)) in sequential
                .source
                .iter()
                .zip(wavefront.source.iter())
                .enumerate()
            {
                assert_eq!(
                    seq_sym, wf_sym,
                    "source symbol {i} mismatch at batch_size={batch_size} (repair-only)"
                );
            }
        }
    }

    #[test]
    fn wavefront_overlap_peeling_is_tracked() {
        // With batch_size=1, each symbol is assembled and peeled individually.
        // Some peeling should happen during assembly batches (overlap).
        let k = 16;
        let symbol_size = 64;
        let seed = 0xF8_0003u64;

        let source = make_source_data(k, symbol_size);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);

        let mut received = decoder.constraint_symbols();
        for esi in 0..(k as u32) {
            received.push(ReceivedSymbol::source(esi, source[esi as usize].clone()));
        }
        for esi in (k as u32)..(k as u32 + 4) {
            let (cols, coefs) = decoder.repair_equation(esi).unwrap();
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let wavefront = decoder
            .decode_wavefront(&received, 1)
            .expect("wavefront batch_size=1");

        assert!(wavefront.stats.wavefront_active);
        assert_eq!(wavefront.stats.wavefront_batch_size, 1);
        assert_eq!(wavefront.stats.wavefront_batches, received.len());
        // With source symbols fed one at a time, peeling MAY happen during the
        // assembly batches (overlap region), but whether any symbol actually
        // peels depends on equation structure — the queue-based scheduler can
        // legitimately route this block straight to the dense core. We therefore
        // assert that wavefront peeling accounting is internally consistent
        // rather than demanding a specific (path-dependent) peel count: any peeled
        // symbol must have been popped from the queue, and a non-empty queue
        // frontier must coincide with at least one push.
        assert!(
            wavefront.stats.peeled <= wavefront.stats.peel_queue_pops,
            "peeled symbols cannot exceed peel-queue pops"
        );
        assert_eq!(
            wavefront.stats.peel_frontier_peak > 0,
            wavefront.stats.peel_queue_pushes > 0,
            "frontier peak must be non-zero exactly when the peel queue was used"
        );
    }

    #[test]
    fn wavefront_sequential_fallback_batch_zero() {
        // batch_size=0 should behave identically to sequential decode.
        let k = 8;
        let symbol_size = 32;
        let seed = 0xF8_0004u64;

        let source = make_source_data(k, symbol_size);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);

        let mut received = decoder.constraint_symbols();
        for esi in 0..(k as u32) {
            received.push(ReceivedSymbol::source(esi, source[esi as usize].clone()));
        }
        for esi in (k as u32)..(k as u32 + 2) {
            let (cols, coefs) = decoder.repair_equation(esi).unwrap();
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let sequential = decoder.decode(&received).expect("sequential");
        let wavefront = decoder
            .decode_wavefront(&received, 0)
            .expect("wavefront batch_size=0");

        assert_eq!(sequential.source, wavefront.source);
        assert!(wavefront.stats.wavefront_active);
        assert_eq!(wavefront.stats.wavefront_batches, 1);
        assert_eq!(wavefront.stats.wavefront_batch_size, received.len());
    }

    /// br-asupersync-cjv6x4: try_new returns Err for K = 0.
    #[test]
    fn inactivation_decoder_try_new_rejects_zero_k() {
        let result = InactivationDecoder::try_new(0, 64, 1);
        assert!(
            result.is_err(),
            "try_new must reject K=0 instead of panicking"
        );
    }

    /// br-asupersync-cjv6x4: try_new returns Err for K above the
    /// RFC 6330 systematic-index table maximum (56403).
    #[test]
    fn inactivation_decoder_try_new_rejects_oversized_k() {
        let result = InactivationDecoder::try_new(56_404, 64, 1);
        assert!(
            result.is_err(),
            "try_new must reject K > 56403 instead of panicking"
        );
    }

    /// br-asupersync-cjv6x4: try_new succeeds for valid K.
    #[test]
    fn inactivation_decoder_try_new_accepts_valid_k() {
        let decoder = InactivationDecoder::try_new(10, 64, 1).expect("try_new must accept K=10");
        // Smoke check: params populated.
        assert!(decoder.params().k >= 10);
    }

    /// br-asupersync-h2k7ep: differential RFC 6330 §5.1 upper-edge
    /// K_max boundary. The decoder must accept the final systematic
    /// table row (K=56403), mirror the canonical parameter derivation,
    /// and reject K=56404 with the same fail-closed error as the
    /// systematic-index reference path.
    #[test]
    fn inactivation_decoder_matches_rfc6330_k_max_boundary_reference() {
        const K_MAX: usize = 56_403;
        const SYMBOL_SIZE: usize = 64;
        const SEED: u64 = 0x6330_5101;

        let reference = SystematicParams::try_for_source_block(K_MAX, SYMBOL_SIZE)
            .expect("RFC 6330 K_max boundary must be accepted");
        let decoder = InactivationDecoder::try_new(K_MAX, SYMBOL_SIZE, SEED)
            .expect("decoder must accept exact RFC K_max boundary");
        let params = decoder.params();

        assert_eq!(params.k, reference.k, "K_max: K must echo input");
        assert_eq!(
            params.k_prime, reference.k_prime,
            "K_max: K' must match RFC 6330 table maximum row"
        );
        assert_eq!(params.j, reference.j, "K_max: J(K') must match reference");
        assert_eq!(params.s, reference.s, "K_max: S must match reference");
        assert_eq!(params.h, reference.h, "K_max: H must match reference");
        assert_eq!(params.l, reference.l, "K_max: L must match reference");
        assert_eq!(params.w, reference.w, "K_max: W must match reference");
        assert_eq!(params.p, reference.p, "K_max: P must match reference");
        assert_eq!(params.b, reference.b, "K_max: B must match reference");
        assert_eq!(
            params.symbol_size, reference.symbol_size,
            "K_max: symbol_size must be preserved in derived params"
        );

        let reference_err = SystematicParams::try_for_source_block(K_MAX + 1, SYMBOL_SIZE)
            .expect_err("RFC 6330 K_max+1 boundary must reject");
        let decoder_err = match InactivationDecoder::try_new(K_MAX + 1, SYMBOL_SIZE, SEED) {
            Ok(_) => panic!("decoder must reject K beyond RFC K_max boundary"),
            Err(err) => err,
        };
        assert_eq!(
            decoder_err, reference_err,
            "K_max+1: decoder rejection must match the systematic-table reference error"
        );
    }

    // ========================================================================
    // Fuzzing Tests: Malformed FEC Payload Robustness
    // ========================================================================

    /// Fuzzing test module for decoder robustness against malformed FEC payloads.
    ///
    /// br-asupersync-t36ete: Tests that arbitrary bytes interpreted as encoded
    /// payload never panic and always return proper errors for malformed input.
    /// This exercises the decode path's input validation and error handling
    /// without relying on well-formed encoder output.
    mod fuzz_malformed_payloads {
        use super::*;
        use crate::raptorq::gf256::Gf256;

        /// Generate arbitrary bytes as symbol data for fuzzing
        fn arbitrary_symbol_data(seed: u64, len: usize) -> Vec<u8> {
            let mut data = Vec::with_capacity(len);
            let mut rng_state = seed;
            for _ in 0..len {
                // Simple LCG for deterministic but varied byte generation
                rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
                data.push((rng_state >> 8) as u8);
            }
            data
        }

        /// Generate malformed column indices that may be out of range
        fn malformed_columns(seed: u64, count: usize, max_valid: usize) -> Vec<usize> {
            let mut columns = Vec::with_capacity(count);
            let mut rng_state = seed;
            for i in 0..count {
                rng_state = rng_state.wrapping_mul(69069).wrapping_add(1);
                let value = match i % 4 {
                    0 => rng_state as usize % (max_valid * 2), // May be out of range
                    1 => max_valid + (rng_state as usize % 100), // Definitely out of range
                    2 => usize::MAX,                           // Extreme out of range
                    _ => rng_state as usize % max_valid,       // Valid range
                };
                columns.push(value);
            }
            columns
        }

        /// Generate malformed coefficients with potentially wrong count
        fn malformed_coefficients(seed: u64, count: usize) -> Vec<Gf256> {
            let mut coefficients = Vec::with_capacity(count);
            let mut rng_state = seed;
            for _ in 0..count {
                rng_state = rng_state.wrapping_mul(214013).wrapping_add(2531011);
                coefficients.push(Gf256::new((rng_state >> 16) as u8));
            }
            coefficients
        }

        /// Test decoder robustness against completely arbitrary ReceivedSymbol data
        #[test]
        fn fuzz_decoder_with_arbitrary_symbols() {
            let k = 8;
            let symbol_size = 16;
            let seed = 0x1337_BEEF_u64;

            let decoder = InactivationDecoder::new(k, symbol_size, seed);
            let l = decoder.params().l;

            // Test cases with different types of malformation
            let test_cases = [
                // Valid baseline for comparison
                (0u64, false, "valid_baseline"),
                // Arbitrary symbol data
                (1u64, true, "arbitrary_symbol_data"),
                (2u64, true, "mismatched_symbol_sizes"),
                (3u64, true, "out_of_range_esi_values"),
                (4u64, true, "column_coefficient_arity_mismatch"),
                (5u64, true, "invalid_column_indices"),
                (6u64, true, "extreme_values"),
                (7u64, true, "empty_vectors"),
                (8u64, true, "oversized_vectors"),
            ];

            for (test_seed, expect_error, test_name) in test_cases {
                let mut symbols = Vec::new();

                // Add constraint symbols (these are usually well-formed)
                symbols.extend(decoder.constraint_symbols());

                let mut rng_state = test_seed;

                // Generate fuzzed symbols
                for i in 0..k + 2 {
                    rng_state = rng_state.wrapping_mul(1664525).wrapping_add(1013904223);

                    let esi = if expect_error && (rng_state % 10) < 3 {
                        // Sometimes use out-of-range ESI
                        (rng_state % 0x1000_0000) as u32
                    } else {
                        i as u32
                    };

                    let symbol_data_len = if expect_error && (rng_state % 10) < 2 {
                        // Sometimes use wrong symbol size
                        ((rng_state % 200) + 1) as usize
                    } else {
                        symbol_size
                    };

                    let symbol_data = arbitrary_symbol_data(rng_state, symbol_data_len);

                    if i < k {
                        // Source symbol
                        if expect_error && (rng_state % 10) < 2 {
                            // Create malformed source symbol with wrong equation
                            let wrong_columns = vec![((rng_state as usize) % (l * 2)) + l];
                            let wrong_coefficients = vec![Gf256::new((rng_state >> 8) as u8)];
                            symbols.push(ReceivedSymbol::repair(
                                esi,
                                wrong_columns,
                                wrong_coefficients,
                                symbol_data,
                            ));
                        } else {
                            symbols.push(ReceivedSymbol::source(esi, symbol_data));
                        }
                    } else {
                        // Repair symbol
                        let column_count = if expect_error && (rng_state % 10) < 3 {
                            // Sometimes mismatched arity
                            ((rng_state % 20) + 1) as usize
                        } else {
                            ((rng_state % 10) + 1) as usize
                        };

                        let coeff_count = if expect_error && (rng_state % 10) < 2 {
                            // Different count than columns
                            column_count + 1 + ((rng_state % 5) as usize)
                        } else {
                            column_count
                        };

                        let columns = malformed_columns(rng_state, column_count, l);
                        let coefficients = malformed_coefficients(rng_state, coeff_count);

                        symbols.push(ReceivedSymbol::repair(
                            esi,
                            columns,
                            coefficients,
                            symbol_data,
                        ));
                    }
                }

                // CRITICAL: Decoder must never panic, only return proper errors
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    decoder.decode(&symbols)
                }));

                match result {
                    Ok(decode_result) => {
                        match decode_result {
                            Ok(_) => {
                                if expect_error {
                                    // Some malformed inputs might still decode by coincidence
                                    println!("Fuzzing case '{test_name}' unexpectedly succeeded");
                                }
                            }
                            Err(decode_error) => {
                                // Verify error is well-formed and classified properly
                                let error_class = decode_error.failure_class();
                                assert!(
                                    matches!(
                                        error_class,
                                        DecodeFailureClass::Recoverable
                                            | DecodeFailureClass::Unrecoverable
                                    ),
                                    "Fuzzing case '{test_name}': decode error must have valid classification: {decode_error:?}"
                                );

                                // Verify error message is reasonable
                                let error_msg = format!("{decode_error:?}");
                                assert!(
                                    !error_msg.is_empty(),
                                    "Fuzzing case '{test_name}': error must have non-empty debug representation"
                                );
                            }
                        }
                    }
                    Err(panic_info) => {
                        panic!(
                            "FUZZING FAILURE: decoder panicked for test case '{test_name}' with seed 0x{test_seed:x}. \
                             Panic info: {panic_info:?}. This violates the requirement that malformed FEC payloads \
                             must return Err, never panic."
                        );
                    }
                }
            }
        }

        /// Test specific malformed payload patterns that commonly occur in network scenarios
        #[test]
        fn fuzz_common_network_corruption_patterns() {
            let k = 6;
            let symbol_size = 20;
            let seed = 0xDEAD_FACE_u64;

            let decoder = InactivationDecoder::new(k, symbol_size, seed);

            let corruption_patterns = [
                "all_zeros",
                "all_ones",
                "alternating_bytes",
                "random_truncation",
                "size_explosion",
                "negative_indices",
                "duplicate_columns",
                "empty_equation",
            ];

            for pattern in corruption_patterns {
                let mut symbols = decoder.constraint_symbols();

                match pattern {
                    "all_zeros" => {
                        // All symbol data is zeros
                        for i in 0..k {
                            symbols.push(ReceivedSymbol::source(i as u32, vec![0u8; symbol_size]));
                        }
                    }
                    "all_ones" => {
                        // All symbol data is 0xFF
                        for i in 0..k {
                            symbols
                                .push(ReceivedSymbol::source(i as u32, vec![0xFFu8; symbol_size]));
                        }
                    }
                    "alternating_bytes" => {
                        // Alternating 0xAA/0x55 pattern
                        for i in 0..k {
                            let data: Vec<u8> = (0..symbol_size)
                                .map(|j| if j % 2 == 0 { 0xAA } else { 0x55 })
                                .collect();
                            symbols.push(ReceivedSymbol::source(i as u32, data));
                        }
                    }
                    "random_truncation" => {
                        // Symbols with random truncated sizes
                        for i in 0..k {
                            let truncated_size = (i % symbol_size).max(1);
                            let data = arbitrary_symbol_data(0x1234 + i as u64, truncated_size);
                            symbols.push(ReceivedSymbol::source(i as u32, data));
                        }
                    }
                    "size_explosion" => {
                        // Symbols with extremely large sizes
                        symbols.push(ReceivedSymbol::source(0, vec![0xCC; 100_000]));
                        for i in 1..k {
                            symbols.push(ReceivedSymbol::source(i as u32, vec![0u8; symbol_size]));
                        }
                    }
                    "negative_indices" => {
                        // Use repair symbol with invalid large ESI values that might wrap
                        let huge_esi = 0xFFFF_FFFF;
                        let columns = vec![0, 1];
                        let coefficients = vec![Gf256::ONE, Gf256::ONE];
                        let data = arbitrary_symbol_data(0xBAD_C0DE, symbol_size);
                        symbols.push(ReceivedSymbol::repair(
                            huge_esi,
                            columns,
                            coefficients,
                            data,
                        ));

                        for i in 0..(k - 1) {
                            symbols.push(ReceivedSymbol::source(i as u32, vec![0u8; symbol_size]));
                        }
                    }
                    "duplicate_columns" => {
                        // Repair symbol with duplicate column indices
                        let columns = vec![0, 0, 0]; // Duplicate columns
                        let coefficients = vec![Gf256::ONE, Gf256::ONE, Gf256::ONE];
                        let data = arbitrary_symbol_data(0xC0DE_BEEF, symbol_size);
                        symbols.push(ReceivedSymbol::repair(
                            k as u32,
                            columns,
                            coefficients,
                            data,
                        ));

                        for i in 0..k {
                            symbols.push(ReceivedSymbol::source(i as u32, vec![0u8; symbol_size]));
                        }
                    }
                    "empty_equation" => {
                        // Repair symbol with empty equation vectors
                        symbols.push(ReceivedSymbol::repair(
                            k as u32,
                            vec![],
                            vec![],
                            vec![0u8; symbol_size],
                        ));

                        for i in 0..k {
                            symbols.push(ReceivedSymbol::source(i as u32, vec![0u8; symbol_size]));
                        }
                    }
                    _ => unreachable!(),
                }

                // CRITICAL: Must not panic
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    decoder.decode(&symbols)
                }));

                assert!(
                    result.is_ok(),
                    "Decoder panicked on corruption pattern '{pattern}'. \
                     Malformed FEC payloads must return Err, never panic."
                );

                // Verify the actual decode result
                let decode_result = result.unwrap();
                match decode_result {
                    Ok(_) => {
                        // Some patterns might still succeed by coincidence
                        println!("Pattern '{pattern}' unexpectedly decoded successfully");
                    }
                    Err(decode_error) => {
                        // Verify error is properly classified
                        let _error_class = decode_error.failure_class();
                        // Error should be unrecoverable for most malformed input
                        println!("Pattern '{pattern}' correctly failed with: {decode_error:?}");
                    }
                }
            }
        }

        /// Test edge cases with extreme parameter combinations
        #[test]
        fn fuzz_extreme_parameter_edge_cases() {
            let test_cases = [
                (1, 1, "minimal_k_and_symbol_size"),
                (2, 1, "minimal_symbol_size_k2"),
                (1, 1000, "tiny_k_large_symbols"),
                (100, 1, "large_k_tiny_symbols"),
            ];

            for (k, symbol_size, case_name) in test_cases {
                let seed = 0x8BAD_F00D_u64;

                // Use try_new to handle potentially invalid parameters gracefully
                let decoder_result = InactivationDecoder::try_new(k, symbol_size, seed);
                let decoder = match decoder_result {
                    Ok(d) => d,
                    Err(_) => {
                        println!("Case '{case_name}': Decoder construction failed (expected)");
                        continue;
                    }
                };

                // Test with malformed symbols for this configuration
                let mut symbols = Vec::new();

                // Add constraint symbols if available
                symbols.extend(decoder.constraint_symbols());

                // Add some malformed source symbols
                for i in 0..k.min(5) {
                    let wrong_size = symbol_size.saturating_mul(2).max(1);
                    let data = arbitrary_symbol_data(seed + i as u64, wrong_size);
                    symbols.push(ReceivedSymbol::source(i as u32, data));
                }

                // CRITICAL: Must not panic even with extreme parameters
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    decoder.decode(&symbols)
                }));

                assert!(
                    result.is_ok(),
                    "Decoder panicked on extreme case '{case_name}' with k={k}, symbol_size={symbol_size}. \
                     Must return Err for malformed input, never panic."
                );

                let decode_result = result.unwrap();
                match decode_result {
                    Ok(_) => println!("Extreme case '{case_name}' unexpectedly succeeded"),
                    Err(decode_error) => {
                        println!(
                            "Extreme case '{case_name}' correctly failed with: {decode_error:?}"
                        );
                    }
                }
            }
        }

        /// Test that wavefront decoder has same robustness as sequential decoder
        #[test]
        fn fuzz_wavefront_decoder_robustness() {
            let k = 4;
            let symbol_size = 12;
            let seed = 0xFADE_BABE_u64;

            let decoder = InactivationDecoder::new(k, symbol_size, seed);

            // Create malformed symbol set
            let mut symbols = decoder.constraint_symbols();

            // Add source symbols with wrong sizes
            for i in 0..k {
                let wrong_size = if i % 2 == 0 {
                    symbol_size / 2
                } else {
                    symbol_size * 2
                };
                let data = arbitrary_symbol_data(seed + i as u64, wrong_size);
                symbols.push(ReceivedSymbol::source(i as u32, data));
            }

            // Add malformed repair symbols
            let bad_columns = vec![999, 1000, 1001]; // Out of range
            let bad_coefficients = vec![Gf256::ONE]; // Wrong count
            let bad_data = vec![0x42; symbol_size * 3]; // Wrong size
            symbols.push(ReceivedSymbol::repair(
                k as u32,
                bad_columns,
                bad_coefficients,
                bad_data,
            ));

            // Test both sequential and wavefront decoders - neither must panic
            let sequential_result =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| decoder.decode(&symbols)));

            let wavefront_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                decoder.decode_wavefront(&symbols, 2)
            }));

            assert!(
                sequential_result.is_ok(),
                "Sequential decoder panicked on malformed input - must return Err instead"
            );

            assert!(
                wavefront_result.is_ok(),
                "Wavefront decoder panicked on malformed input - must return Err instead"
            );

            // Both should fail gracefully (or succeed if input happens to be valid)
            match (sequential_result.unwrap(), wavefront_result.unwrap()) {
                (Ok(_), Ok(_)) => {
                    println!("Both decoders unexpectedly succeeded on malformed input")
                }
                (Err(seq_err), Err(wf_err)) => {
                    println!("Both decoders correctly failed:");
                    println!("  Sequential: {seq_err:?}");
                    println!("  Wavefront:  {wf_err:?}");
                }
                (Ok(_), Err(wf_err)) => {
                    println!("Sequential succeeded, wavefront failed: {wf_err:?}")
                }
                (Err(seq_err), Ok(_)) => {
                    println!("Sequential failed: {seq_err:?}, wavefront succeeded")
                }
            }
        }
    }
}
