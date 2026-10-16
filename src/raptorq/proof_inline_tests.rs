    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
    use crate::raptorq::systematic::SystematicEncoder;
    use serde_json::json;

    fn make_test_config() -> DecodeConfig {
        DecodeConfig {
            object_id: ObjectId::new(0, 1),
            sbn: 0,
            k: 10,
            s: 3,
            h: 2,
            l: 15,
            symbol_size: 64,
            seed: 42,
        }
    }

    fn make_test_recovered(config: &DecodeConfig) -> Vec<Vec<u8>> {
        vec![vec![0u8; config.symbol_size]; config.k]
    }

    /// Build a minimal, fully-terminated proof for hash/content tests.
    ///
    /// The proof builder now requires both `received` and `outcome` to be set
    /// before `build()` (br-asupersync-gvxrxv). Hash-equality/sensitivity tests
    /// that only care about config/received/elimination provenance terminate the
    /// builder with a neutral failure outcome so the build contract is satisfied
    /// without binding any incidental success payload.
    fn built_test_proof(config: DecodeConfig) -> DecodeProof {
        let mut builder = DecodeProof::builder(config);
        builder.set_received(ReceivedSummary::from_received(std::iter::empty()));
        builder.set_failure(FailureReason::InsufficientSymbols {
            received: 0,
            required: 1,
        });
        builder.build()
    }

    fn deterministic_artifact_payload(len: usize) -> Vec<u8> {
        (0..len)
            .map(|idx| (idx.wrapping_mul(37).wrapping_add(11) % 251) as u8)
            .collect()
    }

    fn scrub_failure_reason_for_snapshot_test(reason: &FailureReason) -> serde_json::Value {
        match reason {
            FailureReason::InsufficientSymbols { received, required } => json!({
                "kind": "InsufficientSymbols",
                "received": received,
                "required": required,
            }),
            FailureReason::SingularMatrix {
                row,
                attempted_cols,
            } => json!({
                "kind": "SingularMatrix",
                "row": row,
                "attempted_cols": attempted_cols,
            }),
            FailureReason::SymbolSizeMismatch { expected, actual } => json!({
                "kind": "SymbolSizeMismatch",
                "expected": expected,
                "actual": actual,
            }),
            FailureReason::SymbolEquationArityMismatch {
                esi,
                columns,
                coefficients,
            } => json!({
                "kind": "SymbolEquationArityMismatch",
                "esi": esi,
                "columns": columns,
                "coefficients": coefficients,
            }),
            FailureReason::ColumnIndexOutOfRange {
                esi,
                column,
                max_valid,
            } => json!({
                "kind": "ColumnIndexOutOfRange",
                "esi": esi,
                "column": column,
                "max_valid": max_valid,
            }),
            FailureReason::SourceEsiOutOfRange { esi, max_valid } => json!({
                "kind": "SourceEsiOutOfRange",
                "esi": esi,
                "max_valid": max_valid,
            }),
            FailureReason::InvalidSourceSymbolEquation {
                esi,
                expected_column,
            } => json!({
                "kind": "InvalidSourceSymbolEquation",
                "esi": esi,
                "expected_column": expected_column,
            }),
            FailureReason::CorruptDecodedOutput {
                esi,
                byte_index,
                expected,
                actual,
            } => json!({
                "kind": "CorruptDecodedOutput",
                "esi": esi,
                "byte_index": byte_index,
                "expected": expected,
                "actual": actual,
            }),
            FailureReason::ComputeBudgetExhausted {
                used,
                requested,
                max,
            } => json!({
                "kind": "ComputeBudgetExhausted",
                "used": used,
                "requested": requested,
                "max": max,
            }),
            FailureReason::EsiRateLimitExceeded {
                esi,
                column_count,
                max_columns,
            } => json!({
                "kind": "EsiRateLimitExceeded",
                "esi": esi,
                "column_count": column_count,
                "max_columns": max_columns,
            }),
        }
    }

    fn scrub_decode_proof_for_snapshot_test(proof: &DecodeProof) -> serde_json::Value {
        json!({
            "version": proof.version,
            "content_hash": "[content_hash]",
            "config": {
                "object_id": "[object_id]",
                "sbn": proof.config.sbn,
                "k": proof.config.k,
                "s": proof.config.s,
                "h": proof.config.h,
                "l": proof.config.l,
                "symbol_size": proof.config.symbol_size,
                "seed": "[seed]",
            },
            "received": {
                "total": proof.received.total,
                "source_count": proof.received.source_count,
                "repair_count": proof.received.repair_count,
                "esi_multiset_hash": proof.received.esi_multiset_hash,
                "esis": proof.received.esis,
                "truncated": proof.received.truncated,
            },
            "peeling": {
                "solved": proof.peeling.solved,
                "solved_indices": proof.peeling.solved_indices,
                "truncated": proof.peeling.truncated,
            },
            "elimination": {
                "strategy": format!("{:?}", proof.elimination.strategy),
                "inactivated": proof.elimination.inactivated,
                "inactive_cols": proof.elimination.inactive_cols,
                "inactive_cols_truncated": proof.elimination.inactive_cols_truncated,
                "pivots": proof.elimination.pivots,
                "pivot_events": proof
                    .elimination
                    .pivot_events
                    .iter()
                    .map(|event| json!({"col": event.col, "row": event.row}))
                    .collect::<Vec<_>>(),
                "pivot_events_truncated": proof.elimination.pivot_events_truncated,
                "row_ops": proof.elimination.row_ops,
                "strategy_transitions": proof
                    .elimination
                    .strategy_transitions
                    .iter()
                    .map(|transition| {
                        json!({
                            "from": format!("{:?}", transition.from),
                            "to": format!("{:?}", transition.to),
                            "reason": transition.reason,
                        })
                    })
                    .collect::<Vec<_>>(),
                "strategy_transitions_truncated": proof.elimination.strategy_transitions_truncated,
            },
            "outcome": match &proof.outcome {
                ProofOutcome::Success {
                    symbols_recovered,
                    source_payload_hash,
                } => json!({
                    "kind": "Success",
                    "symbols_recovered": symbols_recovered,
                    "source_payload_hash": source_payload_hash,
                }),
                ProofOutcome::Failure { reason } => json!({
                    "kind": "Failure",
                    "reason": scrub_failure_reason_for_snapshot_test(reason),
                }),
            },
        })
    }

    fn serialize_decode_proof_bytes_for_snapshot_test(proof: &DecodeProof) -> String {
        use std::fmt::Write as _;

        let bytes = serde_json::to_vec(proof).expect("serialize DecodeProof to JSON bytes");
        let mut rendered = String::new();
        let _ = writeln!(&mut rendered, "len={}", bytes.len());
        for (line_index, chunk) in bytes.chunks(16).enumerate() {
            if line_index > 0 {
                rendered.push('\n');
            }
            for (index, byte) in chunk.iter().enumerate() {
                if index > 0 {
                    rendered.push(' ');
                }
                let _ = write!(&mut rendered, "{byte:02x}");
            }
        }
        rendered
    }

    fn make_success_proof_for_snapshot_test() -> DecodeProof {
        let config = make_test_config();
        let recovered = make_test_recovered(&config);
        let mut builder = DecodeProof::builder(config);

        builder.set_received(ReceivedSummary::from_received(
            (0..15).map(|esi| (esi, esi < 10)),
        ));
        builder.peeling_mut().record_solved(0);
        builder.peeling_mut().record_solved(4);
        builder.peeling_mut().record_solved(7);

        let elimination = builder.elimination_mut();
        elimination.set_strategy(InactivationStrategy::AllAtOnce);
        elimination.record_strategy_transition(
            InactivationStrategy::AllAtOnce,
            InactivationStrategy::HighSupportFirst,
            "dense_repair_mix",
        );
        elimination.record_inactivation(11);
        elimination.record_pivot(11, 2);
        elimination.record_row_op();
        elimination.record_pivot(13, 5);
        elimination.record_row_op();

        builder.set_success(&recovered);
        builder.build()
    }

    fn make_degraded_singular_proof_for_snapshot_test() -> DecodeProof {
        let mut config = make_test_config();
        config.seed = 1337;
        let mut builder = DecodeProof::builder(config);

        builder.set_received(ReceivedSummary::from_received(
            [(0, true), (1, true), (3, true), (10, false), (11, false)].into_iter(),
        ));
        builder.peeling_mut().record_solved(0);

        let elimination = builder.elimination_mut();
        elimination.set_strategy(InactivationStrategy::HighSupportFirst);
        elimination.record_inactivation(8);
        elimination.record_inactivation(9);
        elimination.record_pivot(8, 1);
        elimination.record_row_op();
        elimination.record_strategy_transition(
            InactivationStrategy::HighSupportFirst,
            InactivationStrategy::BlockSchurLowRank,
            "rank_drop_detected",
        );

        builder.set_failure(FailureReason::SingularMatrix {
            row: 6,
            attempted_cols: vec![8, 9, 12],
        });
        builder.build()
    }

    fn make_degraded_insufficient_proof_for_snapshot_test() -> DecodeProof {
        let mut config = make_test_config();
        config.seed = 7;
        let required = config.l;
        let mut builder = DecodeProof::builder(config);

        builder.set_received(ReceivedSummary::from_received(
            (0..6).map(|esi| (esi, true)),
        ));
        builder.peeling_mut().record_solved(1);
        builder.peeling_mut().record_solved(2);
        builder
            .elimination_mut()
            .set_strategy(InactivationStrategy::AllAtOnce);

        builder.set_failure(FailureReason::InsufficientSymbols {
            received: 6,
            required,
        });
        builder.build()
    }

    fn make_source_block_payload_for_snapshot_test(
        k: usize,
        symbol_size: usize,
        salt: u8,
    ) -> Vec<Vec<u8>> {
        (0..k)
            .map(|i| {
                (0..symbol_size)
                    .map(|j| ((i * 37 + j * 19 + usize::from(salt)) % 256) as u8)
                    .collect()
            })
            .collect()
    }

    fn make_known_good_source_block_proof_for_snapshot_test() -> DecodeProof {
        let k = 8;
        let symbol_size = 32;
        let seed = 2026;
        let source = make_source_block_payload_for_snapshot_test(k, symbol_size, 0x21);
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let mut received = decoder.constraint_symbols();

        for (esi, data) in source.iter().enumerate() {
            received.push(ReceivedSymbol::source(esi as u32, data.clone()));
        }

        let proof = decoder
            .decode_with_proof(&received, ObjectId::new_for_test(2026), 0)
            .expect("known-good source block should decode")
            .proof;
        assert!(
            matches!(proof.outcome, ProofOutcome::Success { .. }),
            "known-good snapshot scenario must produce a success certificate"
        );
        proof
    }

    fn make_known_bad_source_block_proof_for_snapshot_test() -> DecodeProof {
        let k = 8;
        let symbol_size = 32;
        let seed = 2026;
        let source = make_source_block_payload_for_snapshot_test(k, symbol_size, 0x4D);
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let mut received = decoder.constraint_symbols();

        for (esi, data) in source.iter().enumerate().take(4) {
            received.push(ReceivedSymbol::source(esi as u32, data.clone()));
        }

        let (_err, proof) = decoder
            .decode_with_proof(&received, ObjectId::new_for_test(3030), 0)
            .expect_err("known-bad source block should fail decode");
        assert!(
            matches!(proof.outcome, ProofOutcome::Failure { .. }),
            "known-bad snapshot scenario must produce a failure certificate"
        );
        proof
    }

    #[test]
    fn proof_builder_success() {
        let config = make_test_config();
        let recovered = make_test_recovered(&config);
        let mut builder = DecodeProof::builder(config);

        builder.set_received(ReceivedSummary {
            total: 15,
            source_count: 10,
            repair_count: 5,
            esi_multiset_hash: 123,
            esis: (0..15).collect(),
            truncated: false,
        });

        builder.peeling_mut().record_solved(0);
        builder.peeling_mut().record_solved(1);

        builder.elimination_mut().record_inactivation(2);
        builder.elimination_mut().record_pivot(2, 0);
        builder.elimination_mut().record_row_op();

        builder.set_success(&recovered);

        let proof = builder.build();

        assert_eq!(proof.version, PROOF_SCHEMA_VERSION);
        assert_eq!(proof.peeling.solved, 2);
        assert_eq!(proof.elimination.pivots, 1);
        assert!(matches!(proof.outcome, ProofOutcome::Success { .. }));
    }

    #[test]
    fn proof_builder_failure() {
        let config = make_test_config();
        let mut builder = DecodeProof::builder(config);

        builder.set_received(ReceivedSummary {
            total: 5,
            source_count: 5,
            repair_count: 0,
            esi_multiset_hash: 456,
            esis: (0..5).collect(),
            truncated: false,
        });

        builder.set_failure(FailureReason::InsufficientSymbols {
            received: 5,
            required: 15,
        });

        let proof = builder.build();

        assert!(matches!(
            proof.outcome,
            ProofOutcome::Failure {
                reason: FailureReason::InsufficientSymbols { .. }
            }
        ));
    }

    #[test]
    fn decode_proof_certificate_scrubbed() {
        let success = make_success_proof_for_snapshot_test();
        let degraded_singular = make_degraded_singular_proof_for_snapshot_test();
        let degraded_insufficient = make_degraded_insufficient_proof_for_snapshot_test();
        let source_block_success = make_known_good_source_block_proof_for_snapshot_test();
        let source_block_failure = make_known_bad_source_block_proof_for_snapshot_test();

        insta::assert_json_snapshot!(
            "decode_proof_certificate_scrubbed",
            json!({
                "success": scrub_decode_proof_for_snapshot_test(&success),
                "degraded_singular": scrub_decode_proof_for_snapshot_test(&degraded_singular),
                "degraded_insufficient": scrub_decode_proof_for_snapshot_test(&degraded_insufficient),
                "source_block_success": scrub_decode_proof_for_snapshot_test(&source_block_success),
                "source_block_failure": scrub_decode_proof_for_snapshot_test(&source_block_failure),
            })
        );
    }

    #[test]
    fn decode_proof_byte_serialization() {
        let proof = make_success_proof_for_snapshot_test();

        insta::assert_snapshot!(
            "decode_proof_byte_serialization",
            serialize_decode_proof_bytes_for_snapshot_test(&proof)
        );
    }

    #[test]
    fn source_block_decode_proof_hashes_are_stable() {
        let success1 = make_known_good_source_block_proof_for_snapshot_test();
        let success2 = make_known_good_source_block_proof_for_snapshot_test();
        let failure1 = make_known_bad_source_block_proof_for_snapshot_test();
        let failure2 = make_known_bad_source_block_proof_for_snapshot_test();

        assert_eq!(success1.content_hash(), success2.content_hash());
        assert_eq!(failure1.content_hash(), failure2.content_hash());
    }

    /// Pin the JSON shape of every `FailureReason` variant individually so that
    /// adding/renaming/reshaping a variant trips the golden. The constructed
    /// values use distinct, non-default field values per variant to avoid
    /// accidental equality if two variants are confused during refactoring.
    #[test]
    fn failure_reason_variants_scrubbed() {
        let variants: Vec<(&'static str, FailureReason)> = vec![
            (
                "insufficient_symbols",
                FailureReason::InsufficientSymbols {
                    received: 7,
                    required: 15,
                },
            ),
            (
                "singular_matrix",
                FailureReason::SingularMatrix {
                    row: 11,
                    attempted_cols: vec![3, 8, 12, 14],
                },
            ),
            (
                "symbol_size_mismatch",
                FailureReason::SymbolSizeMismatch {
                    expected: 64,
                    actual: 48,
                },
            ),
            (
                "symbol_equation_arity_mismatch",
                FailureReason::SymbolEquationArityMismatch {
                    esi: 21,
                    columns: 4,
                    coefficients: 3,
                },
            ),
            (
                "column_index_out_of_range",
                FailureReason::ColumnIndexOutOfRange {
                    esi: 33,
                    column: 99,
                    max_valid: 15,
                },
            ),
            (
                "source_esi_out_of_range",
                FailureReason::SourceEsiOutOfRange {
                    esi: 42,
                    max_valid: 10,
                },
            ),
            (
                "invalid_source_symbol_equation",
                FailureReason::InvalidSourceSymbolEquation {
                    esi: 5,
                    expected_column: 5,
                },
            ),
            (
                "corrupt_decoded_output",
                FailureReason::CorruptDecodedOutput {
                    esi: 9,
                    byte_index: 17,
                    expected: 0xAB,
                    actual: 0x37,
                },
            ),
        ];

        let mut catalog = serde_json::Map::with_capacity(variants.len());
        for (key, reason) in &variants {
            catalog.insert(
                (*key).to_string(),
                scrub_failure_reason_for_snapshot_test(reason),
            );
        }

        insta::assert_json_snapshot!(
            "failure_reason_variants_scrubbed",
            serde_json::Value::Object(catalog)
        );
    }

    /// Pin the JSON differential between `ProofOutcome::Success` and
    /// `ProofOutcome::Failure` so a refactor that drops `symbols_recovered`
    /// or `source_payload_hash` from the success arm — or that promotes a
    /// failure into a success without re-running the hash — trips the golden.
    #[test]
    fn proof_outcome_success_vs_failure_scrubbed() {
        let success_proof = make_success_proof_for_snapshot_test();
        let failure_proof = make_degraded_singular_proof_for_snapshot_test();

        let success_outcome = match &success_proof.outcome {
            ProofOutcome::Success {
                symbols_recovered,
                source_payload_hash,
            } => json!({
                "kind": "Success",
                "symbols_recovered": symbols_recovered,
                "source_payload_hash": source_payload_hash,
            }),
            ProofOutcome::Failure { .. } => panic!("success fixture must be Success"),
        };
        let failure_outcome = match &failure_proof.outcome {
            ProofOutcome::Failure { reason } => json!({
                "kind": "Failure",
                "reason": scrub_failure_reason_for_snapshot_test(reason),
            }),
            ProofOutcome::Success { .. } => panic!("failure fixture must be Failure"),
        };

        insta::assert_json_snapshot!(
            "proof_outcome_success_vs_failure_scrubbed",
            json!({
                "success": success_outcome,
                "failure": failure_outcome,
            })
        );
    }

    /// Pin the determinism of `recovered_source_hash` across a fixed table of
    /// shapes so that any change to the hash function (algorithm choice, salt,
    /// length-prefix encoding, byte order) trips the golden. Catches s2jxu0
    /// hash-binding regressions that would otherwise let a divergent decoder
    /// silently bind a stale hash to a successful decode certificate.
    #[test]
    fn recovered_source_hash_golden_table() {
        let cases: Vec<(&'static str, Vec<Vec<u8>>)> = vec![
            ("empty", Vec::new()),
            ("single_zero_symbol_size_64", vec![vec![0u8; 64]]),
            (
                "two_symbols_distinct_pattern",
                vec![
                    (0..32).map(|i| i as u8).collect(),
                    (0..32).map(|i| (255 - i) as u8).collect(),
                ],
            ),
            (
                "k10_symbol_size_64_deterministic_fill",
                (0..10)
                    .map(|i| {
                        (0..64)
                            .map(|j| ((i * 37 + j * 19 + 0x21) % 256) as u8)
                            .collect()
                    })
                    .collect(),
            ),
            (
                "irregular_symbol_lengths",
                vec![
                    vec![0xDE, 0xAD],
                    vec![0xBE, 0xEF, 0x00, 0x01],
                    vec![0xFE; 8],
                ],
            ),
            (
                "empty_symbol_then_full_symbol",
                vec![Vec::new(), vec![0xFFu8; 16]],
            ),
        ];

        let mut table = serde_json::Map::with_capacity(cases.len());
        for (label, source) in &cases {
            let hash = recovered_source_hash(source);
            table.insert(
                (*label).to_string(),
                json!({
                    "shape": source.iter().map(Vec::len).collect::<Vec<_>>(),
                    "hash": hash,
                }),
            );
        }

        insta::assert_json_snapshot!(
            "recovered_source_hash_golden_table",
            serde_json::Value::Object(table)
        );
    }

    #[test]
    fn received_summary_truncation() {
        let symbols = (0..2000).map(|i| (i, i < 1000));
        let summary = ReceivedSummary::from_received(symbols);

        assert_eq!(summary.total, 2000);
        assert_eq!(summary.source_count, 1000);
        assert_eq!(summary.repair_count, 1000);
        assert_eq!(summary.esis.len(), MAX_RECEIVED_SYMBOLS);
        assert!(summary.truncated);
    }

    #[test]
    fn received_summary_hash_changes_when_high_esis_change_beyond_preview() {
        let total = MAX_RECEIVED_SYMBOLS as u32 + 8;
        let original = ReceivedSummary::from_received((0..total).map(|esi| (esi, esi < 8)));
        let mutated = ReceivedSummary::from_received(
            (0..(total - 1))
                .map(|esi| (esi, esi < 8))
                .chain(std::iter::once((u32::MAX - 7, false))),
        );

        assert_eq!(original.total, mutated.total);
        assert_eq!(original.source_count, mutated.source_count);
        assert_eq!(original.repair_count, mutated.repair_count);
        assert_eq!(
            original.esis, mutated.esis,
            "preview ESIs should stay identical when only higher truncated ESIs differ"
        );
        assert!(original.truncated);
        assert!(mutated.truncated);
        assert_ne!(
            original.esi_multiset_hash, mutated.esi_multiset_hash,
            "full multiset hash must distinguish divergence beyond the preview window"
        );
    }

    #[test]
    fn received_summary_hash_is_order_independent_for_same_multiset() {
        let ordered = [
            (9, false),
            (1, true),
            (7, false),
            (1, true),
            (4, false),
            (2, true),
        ];
        let permuted = [
            (2, true),
            (4, false),
            (1, true),
            (9, false),
            (1, true),
            (7, false),
        ];

        let ordered_summary = ReceivedSummary::from_received(ordered.into_iter());
        let permuted_summary = ReceivedSummary::from_received(permuted.into_iter());

        assert_eq!(ordered_summary.total, permuted_summary.total);
        assert_eq!(ordered_summary.source_count, permuted_summary.source_count);
        assert_eq!(ordered_summary.repair_count, permuted_summary.repair_count);
        assert_eq!(ordered_summary.esis, permuted_summary.esis);
        assert_eq!(
            ordered_summary.esi_multiset_hash, permuted_summary.esi_multiset_hash,
            "multiset hash must remain stable across input orderings"
        );
    }

    #[test]
    fn content_hash_deterministic() {
        let config = make_test_config();
        let recovered = make_test_recovered(&config);
        let mut builder1 = DecodeProof::builder(config.clone());
        let mut builder2 = DecodeProof::builder(config);

        for builder in [&mut builder1, &mut builder2] {
            builder.set_received(ReceivedSummary {
                total: 15,
                source_count: 10,
                repair_count: 5,
                esi_multiset_hash: 999,
                esis: (0..15).collect(),
                truncated: false,
            });
            builder.set_success(&recovered);
        }

        let proof1 = builder1.build();
        let proof2 = builder2.build();

        assert_eq!(proof1.content_hash(), proof2.content_hash());
    }

    #[test]
    fn recovered_source_hash_binds_symbol_boundaries() {
        let split_symbols = vec![vec![0x10, 0x20], vec![0x30, 0x40]];
        let merged_suffix = vec![vec![0x10], vec![0x20, 0x30, 0x40]];

        assert_eq!(
            split_symbols.concat(),
            merged_suffix.concat(),
            "test setup should keep the flattened payload identical"
        );
        assert_ne!(
            recovered_source_hash(&split_symbols),
            recovered_source_hash(&merged_suffix),
            "proof success hash must bind per-symbol boundaries, not just flattened bytes"
        );
    }

    #[test]
    fn recovered_source_hash_binds_symbol_order() {
        let ordered = vec![vec![0xAA, 0x01], vec![0xBB, 0x02], vec![0xCC, 0x03]];
        let reordered = vec![vec![0xCC, 0x03], vec![0xBB, 0x02], vec![0xAA, 0x01]];

        assert_ne!(
            recovered_source_hash(&ordered),
            recovered_source_hash(&reordered),
            "proof success hash must distinguish reordered recovered source symbols"
        );
    }

    #[test]
    fn replay_verification_roundtrip() {
        let k = 8;
        let symbol_size = 32;
        let seed = 99u64;

        let source: Vec<Vec<u8>> = (0..k)
            .map(|i| {
                (0..symbol_size)
                    .map(|j| ((i * 53 + j * 19 + 3) % 256) as u8)
                    .collect()
            })
            .collect();

        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        // Start with constraint symbols (LDPC + HDPC with zero data)
        let mut received = decoder.constraint_symbols();

        // Add source symbols
        for (i, data) in source.iter().enumerate() {
            received.push(ReceivedSymbol::source(i as u32, data.clone()));
        }

        // Add repair symbols
        for esi in (k as u32)..(l as u32) {
            let (cols, coefs) = decoder
                .repair_equation(esi)
                .expect("repair equation should succeed with valid test parameters");
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let object_id = ObjectId::new_for_test(777);
        let proof = decoder
            .decode_with_proof(&received, object_id, 0)
            .expect("decode should succeed")
            .proof;

        proof
            .replay_and_verify(&received)
            .expect("replay verification should succeed");
    }

    // Pure data-type tests (wave 18 – CyanBarn)

    #[test]
    fn decode_config_debug_clone_hash_eq() {
        let cfg = make_test_config();
        let cfg2 = cfg.clone();
        assert_eq!(cfg, cfg2);
        assert!(format!("{cfg:?}").contains("DecodeConfig"));
    }

    #[test]
    fn received_summary_debug_clone_hash_eq() {
        let summary = ReceivedSummary {
            total: 10,
            source_count: 7,
            repair_count: 3,
            esi_multiset_hash: 789,
            esis: vec![0, 1, 2],
            truncated: false,
        };
        let summary2 = summary.clone();
        assert_eq!(summary, summary2);
        assert!(format!("{summary:?}").contains("ReceivedSummary"));
    }

    #[test]
    fn received_summary_from_received_empty() {
        let summary = ReceivedSummary::from_received(std::iter::empty());
        assert_eq!(summary.total, 0);
        assert_eq!(summary.source_count, 0);
        assert_eq!(summary.repair_count, 0);
        assert!(summary.esis.is_empty());
        assert!(!summary.truncated);
    }

    #[test]
    fn peeling_trace_debug_clone_default_hash_eq() {
        let trace = PeelingTrace::default();
        let trace2 = trace.clone();
        assert_eq!(trace, trace2);
        assert_eq!(trace.solved, 0);
        assert!(format!("{trace:?}").contains("PeelingTrace"));
    }

    #[test]
    fn peeling_trace_record_solved() {
        let mut trace = PeelingTrace::default();
        trace.record_solved(5);
        trace.record_solved(10);
        assert_eq!(trace.solved, 2);
        assert_eq!(trace.solved_indices, vec![5, 10]);
    }

    #[test]
    fn elimination_trace_debug_clone_default_hash_eq() {
        let trace = EliminationTrace::default();
        let trace2 = trace.clone();
        assert_eq!(trace, trace2);
        assert!(format!("{trace:?}").contains("EliminationTrace"));
    }

    #[test]
    fn elimination_trace_record_operations() {
        let mut trace = EliminationTrace::default();
        trace.record_inactivation(3);
        trace.record_pivot(3, 0);
        trace.record_row_op();
        assert_eq!(trace.inactivated, 1);
        assert_eq!(trace.pivots, 1);
        assert_eq!(trace.row_ops, 1);
        assert_eq!(trace.pivot_events.len(), 1);
        assert!(!trace.inactive_cols_truncated);
        assert!(!trace.pivot_events_truncated);
        assert!(!trace.strategy_transitions_truncated);
    }

    #[test]
    fn replay_verification_keeps_non_truncated_elimination_subtraces_strict() {
        let config = make_test_config();
        let recovered = make_test_recovered(&config);
        let mut expected_builder = DecodeProof::builder(config);
        expected_builder.set_received(ReceivedSummary {
            total: 10,
            source_count: 10,
            repair_count: 0,
            esi_multiset_hash: 321,
            esis: (0..10).collect(),
            truncated: false,
        });
        expected_builder.set_success(&recovered);

        let elimination = expected_builder.elimination_mut();
        for col in 0..=MAX_PIVOT_EVENTS {
            elimination.record_inactivation(col);
        }
        elimination.record_pivot(3, 0);
        elimination.record_strategy_transition(
            InactivationStrategy::AllAtOnce,
            InactivationStrategy::HighSupportFirst,
            "dense_or_near_square",
        );

        let expected = expected_builder.build();
        assert!(expected.elimination.inactive_cols_truncated);
        assert!(!expected.elimination.pivot_events_truncated);
        assert!(!expected.elimination.strategy_transitions_truncated);

        let mut actual = expected.clone();
        actual
            .elimination
            .pivot_events
            .push(PivotEvent { col: 9, row: 1 });

        let err = compare_proofs(&expected, &actual)
            .expect_err("extra non-truncated pivot events must fail replay verification");
        assert!(
            err.to_string().contains("elimination.pivot_events"),
            "mismatch should point directly at the non-truncated elimination sub-trace"
        );
    }

    #[test]
    fn replay_verification_rejects_extra_entries_in_truncated_subtraces() {
        let config = make_test_config();
        let recovered = make_test_recovered(&config);
        let mut expected_builder = DecodeProof::builder(config);
        expected_builder.set_received(ReceivedSummary {
            total: 10,
            source_count: 10,
            repair_count: 0,
            esi_multiset_hash: 321,
            esis: (0..10).collect(),
            truncated: false,
        });
        expected_builder.set_success(&recovered);

        let elimination = expected_builder.elimination_mut();
        for col in 0..=MAX_PIVOT_EVENTS {
            elimination.record_inactivation(col);
        }

        let expected = expected_builder.build();
        assert!(expected.elimination.inactive_cols_truncated);

        let mut actual = expected.clone();
        actual.elimination.inactive_cols.push(MAX_PIVOT_EVENTS + 99);

        let err = compare_proofs(&expected, &actual)
            .expect_err("truncated previews must still reject extra recorded entries");
        assert!(
            err.to_string().contains("elimination.inactive_cols"),
            "mismatch should point directly at the truncated elimination preview"
        );
    }

    #[test]
    fn inactivation_strategy_debug_clone_copy_default_hash_eq() {
        let s = InactivationStrategy::default();
        assert_eq!(s, InactivationStrategy::AllAtOnce);
        let s2 = s;
        assert_eq!(s, s2);
        assert!(format!("{s:?}").contains("AllAtOnce"));
    }

    #[test]
    fn inactivation_strategy_all_variants() {
        let variants = [
            InactivationStrategy::AllAtOnce,
            InactivationStrategy::HighSupportFirst,
            InactivationStrategy::BlockSchurLowRank,
        ];
        for (i, v) in variants.iter().enumerate() {
            for (j, v2) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(v, v2);
                } else {
                    assert_ne!(v, v2);
                }
            }
        }
    }

    #[test]
    fn strategy_transition_debug_clone_hash_eq() {
        let t = StrategyTransition {
            from: InactivationStrategy::AllAtOnce,
            to: InactivationStrategy::HighSupportFirst,
            reason: "escalation",
        };
        let t2 = t.clone();
        assert_eq!(t, t2);
        assert!(format!("{t:?}").contains("StrategyTransition"));
    }

    #[test]
    fn pivot_event_debug_clone_hash_eq() {
        let p = PivotEvent { col: 3, row: 7 };
        let p2 = p.clone();
        assert_eq!(p, p2);
        assert!(format!("{p:?}").contains("PivotEvent"));
    }

    #[test]
    fn proof_outcome_debug_clone_hash_eq() {
        let success = ProofOutcome::Success {
            symbols_recovered: 10,
            source_payload_hash: 123,
        };
        let success2 = success.clone();
        assert_eq!(success, success2);
        assert!(format!("{success:?}").contains("Success"));

        let fail = ProofOutcome::Failure {
            reason: FailureReason::InsufficientSymbols {
                received: 5,
                required: 10,
            },
        };
        assert_ne!(success, fail);
    }

    #[test]
    fn failure_reason_all_variants() {
        let variants: Vec<FailureReason> = vec![
            FailureReason::InsufficientSymbols {
                received: 1,
                required: 2,
            },
            FailureReason::SingularMatrix {
                row: 0,
                attempted_cols: vec![1, 2],
            },
            FailureReason::SymbolSizeMismatch {
                expected: 64,
                actual: 32,
            },
            FailureReason::SymbolEquationArityMismatch {
                esi: 5,
                columns: 3,
                coefficients: 4,
            },
            FailureReason::ColumnIndexOutOfRange {
                esi: 1,
                column: 99,
                max_valid: 15,
            },
            FailureReason::CorruptDecodedOutput {
                esi: 0,
                byte_index: 7,
                expected: 0xAA,
                actual: 0xBB,
            },
        ];
        for v in &variants {
            assert!(!format!("{v:?}").is_empty());
        }
    }

    #[test]
    fn replay_error_display_mismatch() {
        let err = ReplayError::Mismatch {
            field: "version",
            expected: "1".into(),
            actual: "2".into(),
        };
        let s = err.to_string();
        assert!(s.contains("version"));
        assert!(s.contains("expected"));
        assert!(format!("{err:?}").contains("Mismatch"));
    }

    #[test]
    fn replay_error_display_sequence() {
        let err = ReplayError::SequenceMismatch {
            label: "esis",
            index: 5,
            expected: "10".into(),
            actual: "20".into(),
        };
        let s = err.to_string();
        assert!(s.contains("esis"));
        assert!(s.contains("index 5"));
    }

    #[test]
    fn replay_error_trait() {
        let err: Box<dyn std::error::Error> = Box::new(ReplayError::Mismatch {
            field: "test",
            expected: "a".into(),
            actual: "b".into(),
        });
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn decode_proof_debug_clone_eq() {
        let config = make_test_config();
        let recovered = make_test_recovered(&config);
        let mut builder = DecodeProof::builder(config);
        builder.set_received(ReceivedSummary {
            total: 10,
            source_count: 10,
            repair_count: 0,
            esi_multiset_hash: 321,
            esis: (0..10).collect(),
            truncated: false,
        });
        builder.set_success(&recovered);
        let proof = builder.build();
        let proof2 = proof.clone();
        assert_eq!(proof, proof2);
        assert!(format!("{proof:?}").contains("DecodeProof"));
    }

    #[test]
    fn decode_proof_builder_debug() {
        let builder = DecodeProof::builder(make_test_config());
        assert!(format!("{builder:?}").contains("DecodeProofBuilder"));
    }

    /// br-asupersync-gvxrxv: ProofBuilder must reject double-set of
    /// outcome. Internal call-ordering bugs that re-call set_success or
    /// set_failure after an earlier outcome was already recorded must
    /// panic, NOT silently overwrite — silent overwrite would let a
    /// failed-then-succeeded path bind source_payload_hash to garbage and
    /// attest success for a failed decode (bypasses s2jxu0 hash binding).
    #[test]
    #[should_panic(expected = "set_success called after outcome already set")]
    fn gvxrxv_set_success_after_set_success_panics() {
        let mut builder = DecodeProof::builder(make_test_config());
        let recovered: Vec<Vec<u8>> = vec![vec![1, 2, 3]; 4];
        builder.set_success(&recovered);
        builder.set_success(&recovered); // must panic
    }

    #[test]
    #[should_panic(expected = "set_failure called after outcome already set")]
    fn gvxrxv_set_failure_after_set_failure_panics() {
        let mut builder = DecodeProof::builder(make_test_config());
        builder.set_failure(FailureReason::SingularMatrix {
            row: 0,
            attempted_cols: vec![0, 1],
        });
        builder.set_failure(FailureReason::SingularMatrix {
            row: 0,
            attempted_cols: vec![0, 1],
        }); // must panic
    }

    #[test]
    #[should_panic(expected = "set_failure called after outcome already set")]
    fn gvxrxv_set_failure_after_set_success_panics() {
        let mut builder = DecodeProof::builder(make_test_config());
        let recovered: Vec<Vec<u8>> = vec![vec![1, 2, 3]; 4];
        builder.set_success(&recovered);
        builder.set_failure(FailureReason::SingularMatrix {
            row: 0,
            attempted_cols: vec![0, 1],
        }); // must panic — would otherwise corrupt the certified outcome
    }

    #[test]
    #[should_panic(expected = "set_success called after outcome already set")]
    fn gvxrxv_set_success_after_set_failure_panics() {
        let mut builder = DecodeProof::builder(make_test_config());
        builder.set_failure(FailureReason::SingularMatrix {
            row: 0,
            attempted_cols: vec![0, 1],
        });
        let recovered: Vec<Vec<u8>> = vec![vec![1, 2, 3]; 4];
        builder.set_success(&recovered); // must panic — most dangerous case (bypasses s2jxu0 hash binding)
    }

    #[test]
    fn elimination_trace_strategy_transition_same_is_noop() {
        let mut trace = EliminationTrace::default();
        trace.record_strategy_transition(
            InactivationStrategy::AllAtOnce,
            InactivationStrategy::AllAtOnce,
            "noop",
        );
        assert!(trace.strategy_transitions.is_empty());
        assert_eq!(trace.strategy, InactivationStrategy::AllAtOnce);
    }

    #[test]
    fn elimination_trace_strategy_transition_records() {
        let mut trace = EliminationTrace::default();
        trace.record_strategy_transition(
            InactivationStrategy::AllAtOnce,
            InactivationStrategy::HighSupportFirst,
            "escalation",
        );
        assert_eq!(trace.strategy_transitions.len(), 1);
        assert_eq!(trace.strategy, InactivationStrategy::HighSupportFirst);
    }

    #[test]
    fn replay_verification_detects_mismatch() {
        let k = 6;
        let symbol_size = 24;
        let seed = 17u64;

        let source: Vec<Vec<u8>> = (0..k)
            .map(|i| {
                (0..symbol_size)
                    .map(|j| ((i * 41 + j * 11 + 5) % 256) as u8)
                    .collect()
            })
            .collect();

        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        // Start with constraint symbols (LDPC + HDPC with zero data)
        let mut received = decoder.constraint_symbols();

        // Add source symbols
        for (i, data) in source.iter().enumerate() {
            received.push(ReceivedSymbol::source(i as u32, data.clone()));
        }

        // Add repair symbols
        for esi in (k as u32)..(l as u32) {
            let (cols, coefs) = decoder
                .repair_equation(esi)
                .expect("repair equation should succeed with valid test parameters");
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let object_id = ObjectId::new_for_test(42);
        let mut proof = decoder
            .decode_with_proof(&received, object_id, 0)
            .expect("decode should succeed")
            .proof;

        proof.elimination.row_ops = proof.elimination.row_ops.saturating_add(1);

        let err = proof
            .replay_and_verify(&received)
            .expect_err("replay should detect mismatch");
        assert!(err.to_string().contains("row_ops"));
    }

    #[test]
    fn replay_verification_rejects_payload_divergent_success() {
        let k = 8;
        let symbol_size = 32;
        let seed = 123u64;

        let make_source = |salt: u8| -> Vec<Vec<u8>> {
            (0..k)
                .map(|i| {
                    (0..symbol_size)
                        .map(|j| ((i * 53 + j * 19 + usize::from(salt)) % 256) as u8)
                        .collect()
                })
                .collect()
        };
        let make_received =
            |decoder: &InactivationDecoder, source: &[Vec<u8>]| -> Vec<ReceivedSymbol> {
                let encoder = SystematicEncoder::new(source, symbol_size, seed).unwrap();
                let l = decoder.params().l;
                let mut received = decoder.constraint_symbols();
                for (i, data) in source.iter().enumerate() {
                    received.push(ReceivedSymbol::source(i as u32, data.clone()));
                }
                for esi in (k as u32)..(l as u32) {
                    let (cols, coefs) = decoder
                        .repair_equation(esi)
                        .expect("repair equation should succeed with valid test parameters");
                    let repair_data = encoder.repair_symbol(esi);
                    received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
                }
                received
            };

        let source = make_source(3);
        let mutated_source = make_source(11);
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let original_received = make_received(&decoder, &source);
        let mutated_received = make_received(&decoder, &mutated_source);
        let object_id = ObjectId::new_for_test(8080);

        let proof = decoder
            .decode_with_proof(&original_received, object_id, 0)
            .expect("original decode should succeed")
            .proof;
        let mutated_result = decoder
            .decode_with_proof(&mutated_received, object_id, 0)
            .expect("mutated decode should still succeed");
        assert_eq!(mutated_result.result.source, mutated_source);
        assert_ne!(mutated_result.result.source, source);

        let err = proof
            .replay_and_verify(&mutated_received)
            .expect_err("payload-divergent replay must fail verification");
        assert!(err.to_string().contains("source_payload_hash"));
    }

    #[test]
    fn replay_verification_rejects_high_esi_divergence_when_received_preview_truncates() {
        let k = 8;
        let symbol_size = 32;
        let seed = 321u64;
        let repair_count = MAX_RECEIVED_SYMBOLS as u32 + 32;

        let source: Vec<Vec<u8>> = (0..k)
            .map(|i| {
                (0..symbol_size)
                    .map(|j| ((i * 37 + j * 17 + 9) % 256) as u8)
                    .collect()
            })
            .collect();
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);

        let mut original_received = decoder.constraint_symbols();
        for (i, data) in source.iter().enumerate() {
            original_received.push(ReceivedSymbol::source(i as u32, data.clone()));
        }
        for offset in 0..repair_count {
            let esi = k as u32 + offset;
            let (cols, coefs) = decoder
                .repair_equation(esi)
                .expect("repair equation should succeed with valid test parameters");
            let repair_data = encoder.repair_symbol(esi);
            original_received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let mut mutated_received = original_received.clone();
        let replaced_esi = k as u32 + repair_count - 1;
        let replacement_esi = replaced_esi + 10_000;
        let (replacement_cols, replacement_coefs) = decoder
            .repair_equation(replacement_esi)
            .expect("repair equation should succeed with valid test parameters");
        let replacement_data = encoder.repair_symbol(replacement_esi);
        let replacement = ReceivedSymbol::repair(
            replacement_esi,
            replacement_cols,
            replacement_coefs,
            replacement_data,
        );
        let replaced_symbol = mutated_received
            .last_mut()
            .expect("repair-heavy test input must contain a trailing repair symbol");
        assert_eq!(replaced_symbol.esi, replaced_esi);
        *replaced_symbol = replacement;

        let object_id = ObjectId::new_for_test(9090);
        let proof = decoder
            .decode_with_proof(&original_received, object_id, 0)
            .expect("original decode should succeed")
            .proof;
        let mutated_result = decoder
            .decode_with_proof(&mutated_received, object_id, 0)
            .expect("mutated decode should still succeed with enough symbols");
        assert_eq!(mutated_result.result.source, source);

        let original_summary =
            ReceivedSummary::from_received(original_received.iter().map(|s| (s.esi, s.is_source)));
        let mutated_summary =
            ReceivedSummary::from_received(mutated_received.iter().map(|s| (s.esi, s.is_source)));
        assert_eq!(
            original_summary.esis, mutated_summary.esis,
            "preview ESIs should not expose the high-ESI divergence"
        );
        assert_ne!(
            original_summary.esi_multiset_hash, mutated_summary.esi_multiset_hash,
            "full multiset binding must distinguish the mutated higher ESI"
        );

        let err = proof
            .replay_and_verify(&mutated_received)
            .expect_err("truncated received-summary replay must reject higher-ESI divergence");
        assert!(err.to_string().contains("received.esi_multiset_hash"));
    }

    // ============================================================================
    // br-asupersync-x5roo0: Cryptographic attestation security tests
    // ============================================================================

    #[test]
    fn content_hash_produces_256_bit_cryptographic_hash() {
        // br-asupersync-x5roo0: Verify that content_hash now returns a 256-bit
        // cryptographic hash instead of a 64-bit non-cryptographic hash.

        let config = make_test_config();
        let mut builder = DecodeProof::builder(config);
        builder.set_received(ReceivedSummary::from_received(std::iter::empty()));
        builder.set_failure(FailureReason::InsufficientSymbols {
            received: 0,
            required: 1,
        });
        let proof = builder.build();

        let hash = proof.content_hash();

        // Verify it's 256 bits (32 bytes)
        assert_eq!(hash.as_bytes().len(), 32);

        // Verify hex encoding works and produces 64 hex characters
        let hex = hash.to_hex();
        assert_eq!(hex.len(), 64);
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn content_hash_deterministic_across_identical_proofs() {
        // Verify that identical proofs produce identical hashes (deterministic).

        let config = make_test_config();
        let proof1 = built_test_proof(config.clone());
        let proof2 = built_test_proof(config);

        assert_eq!(
            proof1.content_hash().as_bytes(),
            proof2.content_hash().as_bytes()
        );
    }

    #[test]
    fn content_hash_differs_for_different_proofs() {
        // Verify that different proofs produce different hashes (collision resistance).

        let config1 = make_test_config();
        let mut config2 = make_test_config();
        config2.k = config1.k + 1; // Different configuration

        let proof1 = built_test_proof(config1);
        let proof2 = built_test_proof(config2);

        assert_ne!(
            proof1.content_hash().as_bytes(),
            proof2.content_hash().as_bytes()
        );
    }

    #[test]
    fn content_hash_binds_full_decode_config_dimensions() {
        let base = make_test_config();
        let base_proof = built_test_proof(base.clone());
        let base_hash = base_proof.content_hash();

        let mut changed_s = base.clone();
        changed_s.s += 1;
        let changed_s_proof = built_test_proof(changed_s);
        assert_ne!(
            base_hash,
            changed_s_proof.content_hash(),
            "proof attestation hash must bind LDPC symbol count s"
        );
        assert!(
            compare_proofs(&base_proof, &changed_s_proof)
                .expect_err("full-config mismatch must fail replay comparison")
                .to_string()
                .contains("config"),
            "hash binding must stay aligned with compare_proofs for s"
        );

        let mut changed_h = base.clone();
        changed_h.h += 1;
        let changed_h_proof = built_test_proof(changed_h);
        assert_ne!(
            base_hash,
            changed_h_proof.content_hash(),
            "proof attestation hash must bind HDPC symbol count h"
        );
        assert!(
            compare_proofs(&base_proof, &changed_h_proof)
                .expect_err("full-config mismatch must fail replay comparison")
                .to_string()
                .contains("config"),
            "hash binding must stay aligned with compare_proofs for h"
        );

        let mut changed_l = base;
        changed_l.l += 1;
        let changed_l_proof = built_test_proof(changed_l);
        assert_ne!(
            base_hash,
            changed_l_proof.content_hash(),
            "proof attestation hash must bind intermediate symbol count l"
        );
        assert!(
            compare_proofs(&base_proof, &changed_l_proof)
                .expect_err("full-config mismatch must fail replay comparison")
                .to_string()
                .contains("config"),
            "hash binding must stay aligned with compare_proofs for l"
        );
    }

    #[test]
    fn forged_proof_rejected_by_hash_mismatch() {
        // br-asupersync-x5roo0: Regression test ensuring that forged proofs
        // with tampered fields are rejected due to hash mismatch.

        let config = make_test_config();
        let mut original_builder = DecodeProof::builder(config.clone());
        let original_received =
            ReceivedSummary::from_received([(0, true), (1, true), (2, true)].iter().copied());
        original_builder.set_received(original_received);
        let original_source = vec![vec![0x12, 0x34, 0x56, 0x78]; 8];
        original_builder.set_success(&original_source);
        let original_proof = original_builder.build();

        // Create a forged proof with different outcome data but claim it matches
        let mut forged_builder = DecodeProof::builder(config);
        let forged_received =
            ReceivedSummary::from_received([(0, true), (1, true), (2, true)].iter().copied());
        forged_builder.set_received(forged_received);
        // Forge the success outcome with different data
        let forged_source = vec![vec![0xDE, 0xAD, 0xBE, 0xEF]; 10]; // Different from original
        forged_builder.set_success(&forged_source);
        let forged_proof = forged_builder.build();

        // Verify the hashes are different (forgery detected)
        assert_ne!(
            original_proof.content_hash().as_bytes(),
            forged_proof.content_hash().as_bytes(),
            "Forged proof must produce different hash than original"
        );

        // Verify that the hash difference is significant (not just 1-2 bits)
        let original_hash = original_proof.content_hash();
        let forged_hash = forged_proof.content_hash();

        let differing_bytes = original_hash
            .as_bytes()
            .iter()
            .zip(forged_hash.as_bytes())
            .filter(|(a, b)| a != b)
            .count();

        assert!(
            differing_bytes > 16,
            "Cryptographic hash should produce avalanche effect with many differing bytes, got {differing_bytes}"
        );
    }

    #[test]
    fn forged_proof_configuration_tampering_detected() {
        // Test that tampering with configuration fields is detected.

        let config1 = make_test_config();
        let mut config2 = config1.clone();
        config2.seed = config1.seed.wrapping_add(1); // Minimal change

        let proof1 = built_test_proof(config1);
        let proof2 = built_test_proof(config2);

        assert_ne!(
            proof1.content_hash().as_bytes(),
            proof2.content_hash().as_bytes(),
            "Even minimal configuration changes must be detected"
        );
    }

    #[test]
    fn forged_proof_received_summary_tampering_detected() {
        // Test that tampering with received symbol summary is detected.

        let config = make_test_config();

        let mut builder1 = DecodeProof::builder(config.clone());
        let received1 =
            ReceivedSummary::from_received([(0, true), (1, true), (2, true)].iter().copied());
        builder1.set_received(received1);
        builder1.set_failure(FailureReason::InsufficientSymbols {
            received: 0,
            required: 1,
        });
        let proof1 = builder1.build();

        let mut builder2 = DecodeProof::builder(config);
        let mut received2 =
            ReceivedSummary::from_received([(0, true), (1, true), (2, true)].iter().copied());
        received2.esi_multiset_hash = received2.esi_multiset_hash.wrapping_add(1); // Forge the hash
        builder2.set_received(received2);
        builder2.set_failure(FailureReason::InsufficientSymbols {
            received: 0,
            required: 1,
        });
        let proof2 = builder2.build();

        assert_ne!(
            proof1.content_hash().as_bytes(),
            proof2.content_hash().as_bytes(),
            "Tampering with received symbol hash must be detected"
        );
    }

    #[test]
    fn forged_proof_elimination_strategy_tampering_detected() {
        // Test that changing the elimination strategy is detected.

        let config = make_test_config();

        let mut builder1 = DecodeProof::builder(config.clone());
        let received1 = ReceivedSummary::from_received([(0, true), (1, true)].iter().copied());
        builder1.set_received(received1);
        builder1
            .elimination_mut()
            .set_strategy(InactivationStrategy::AllAtOnce);
        builder1.set_failure(FailureReason::InsufficientSymbols {
            received: 0,
            required: 1,
        });
        let proof1 = builder1.build();

        let mut builder2 = DecodeProof::builder(config);
        let received2 = ReceivedSummary::from_received([(0, true), (1, true)].iter().copied());
        builder2.set_received(received2);
        builder2
            .elimination_mut()
            .set_strategy(InactivationStrategy::HighSupportFirst);
        builder2.set_failure(FailureReason::InsufficientSymbols {
            received: 0,
            required: 1,
        });
        let proof2 = builder2.build();

        assert_ne!(
            proof1.content_hash().as_bytes(),
            proof2.content_hash().as_bytes(),
            "Different elimination strategies must produce different hashes"
        );
    }

    #[test]
    fn forged_proof_elimination_pivot_trace_tampering_detected() {
        // RFC 6330 Section 6 recommends integrity checks before accepting a
        // decoded artifact. A forged proof must not be able to rewrite the
        // elimination trace while preserving the attested hash.

        let config = make_test_config();
        let received = ReceivedSummary::from_received([(0, true), (1, true)].iter().copied());

        let mut builder1 = DecodeProof::builder(config.clone());
        builder1.set_received(received.clone());
        builder1.elimination_mut().record_pivot(3, 0);
        builder1.set_failure(FailureReason::InsufficientSymbols {
            received: 0,
            required: 1,
        });
        let proof1 = builder1.build();

        let mut builder2 = DecodeProof::builder(config);
        builder2.set_received(received);
        builder2.elimination_mut().record_pivot(7, 1);
        builder2.set_failure(FailureReason::InsufficientSymbols {
            received: 0,
            required: 1,
        });
        let proof2 = builder2.build();

        assert_eq!(proof1.elimination.pivots, proof2.elimination.pivots);
        assert_ne!(
            proof1.elimination.pivot_events,
            proof2.elimination.pivot_events
        );
        assert_ne!(
            proof1.content_hash().as_bytes(),
            proof2.content_hash().as_bytes(),
            "Forged pivot traces must change the attested proof hash"
        );
    }

    #[test]
    fn recovered_source_hash_upgraded_to_cryptographic() {
        // br-asupersync-x5roo0: Verify that recovered_source_hash now uses
        // SHA-256 internally for cryptographic strength.

        let source1 = vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8]];
        let source2 = vec![vec![1, 2, 3, 5], vec![5, 6, 7, 8]]; // Minimal change

        let hash1 = recovered_source_hash(&source1);
        let hash2 = recovered_source_hash(&source2);

        assert_ne!(
            hash1, hash2,
            "Minimal source changes should produce different hashes"
        );

        // Verify deterministic behavior
        let hash1_repeat = recovered_source_hash(&source1);
        assert_eq!(hash1, hash1_repeat, "Hash should be deterministic");
    }

    #[test]
    fn proof_hash_hex_roundtrip() {
        // Test that ProofHash hex encoding/decoding works correctly.

        let config = make_test_config();
        let proof = built_test_proof(config);
        let original_hash = proof.content_hash();

        let hex = original_hash.to_hex();
        let decoded_hash = ProofHash::from_hex(&hex).expect("Valid hex should decode successfully");

        assert_eq!(original_hash.as_bytes(), decoded_hash.as_bytes());
    }

    #[test]
    fn proof_hash_hex_encoding_invalid_input_rejected() {
        // Test that invalid hex inputs are properly rejected.

        assert!(ProofHash::from_hex("invalid hex").is_none());
        assert!(ProofHash::from_hex("").is_none());
        assert!(ProofHash::from_hex("01234567890abcdef").is_none()); // Too short

        // Test wrong length (63 chars instead of 64)
        let short_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde";
        assert!(ProofHash::from_hex(short_hex).is_none());

        // Test wrong length (65 chars)
        let long_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0";
        assert!(ProofHash::from_hex(long_hex).is_none());
    }

    #[test]
    fn source_payload_hash_mismatch_fails_verification() {
        // Test that hash mismatches are properly detected in fail-closed manner
        let config = make_test_config();

        // Create original proof with one source payload
        let source1 = vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8]];
        let mut builder1 = DecodeProof::builder(config.clone());
        builder1.set_received(ReceivedSummary::from_received(std::iter::empty()));
        builder1.set_success(&source1);
        let proof1 = builder1.build();

        // Create proof with different source payload (different hash)
        let source2 = vec![vec![1, 2, 3, 5], vec![5, 6, 7, 8]]; // Minimal change
        let mut builder2 = DecodeProof::builder(config);
        builder2.set_received(ReceivedSummary::from_received(std::iter::empty()));
        builder2.set_success(&source2);
        let proof2 = builder2.build();

        // Verify hashes are different
        let hash1 = if let ProofOutcome::Success {
            source_payload_hash,
            ..
        } = &proof1.outcome
        {
            *source_payload_hash
        } else {
            panic!("Expected Success outcome");
        };
        let hash2 = if let ProofOutcome::Success {
            source_payload_hash,
            ..
        } = &proof2.outcome
        {
            *source_payload_hash
        } else {
            panic!("Expected Success outcome");
        };
        assert_ne!(
            hash1, hash2,
            "Different sources must produce different hashes"
        );

        // Verify verification fails when comparing proofs with different hashes
        let comparison_result = compare_proofs(&proof1, &proof2);
        assert!(
            comparison_result.is_err(),
            "Hash mismatch should cause verification failure"
        );

        // Verify the error specifically mentions outcome mismatch
        let err = comparison_result.unwrap_err();
        if let ReplayError::Mismatch { field, .. } = err {
            assert_eq!(
                field, "outcome",
                "Error should identify outcome field as mismatched"
            );
        } else {
            panic!("Expected Mismatch error, got: {:?}", err);
        }
    }

    #[test]
    fn proof_artifact_manifest_hash_binds_distribution_metadata() {
        let payload = deterministic_artifact_payload(512);
        let object_id = ObjectId::new_for_test(0xA11CE);

        let first = package_proof_artifact_for_distribution(&payload, 64, 8, 0x5150, object_id, 3)
            .expect("proof artifact should package");
        let second = package_proof_artifact_for_distribution(&payload, 64, 9, 0x5150, object_id, 3)
            .expect("proof artifact should package with different repair count");

        assert!(first.manifest.hash_is_valid());
        assert!(second.manifest.hash_is_valid());
        assert_eq!(
            first.manifest.source_payload_hash, second.manifest.source_payload_hash,
            "same artifact bytes keep the same source-payload hash"
        );
        assert_ne!(
            first.manifest.manifest_hash, second.manifest.manifest_hash,
            "manifest hash must bind repair-symbol distribution metadata"
        );
        assert_eq!(
            first.shards.len(),
            first
                .manifest
                .source_symbols
                .saturating_add(first.manifest.repair_symbols)
        );
    }

    #[test]
    fn proof_artifact_distribution_recovers_after_source_shard_loss() {
        let payload = deterministic_artifact_payload(1024);
        let distribution = package_proof_artifact_for_distribution(
            &payload,
            64,
            20,
            0xD157_71B7_u64,
            ObjectId::new_for_test(0xD151),
            7,
        )
        .expect("proof artifact should package");

        let dropped_source_esis = [1u32, 4, 9, 13];
        let partial_shards: Vec<_> = distribution
            .shards
            .iter()
            .filter(|shard| !(shard.is_source && dropped_source_esis.contains(&shard.esi)))
            .cloned()
            .collect();

        let recovery = recover_proof_artifact_from_shards(&distribution.manifest, &partial_shards)
            .expect("repair shards should recover the missing source shards");

        assert_eq!(recovery.payload, payload);
        assert_eq!(recovery.symbols_received, partial_shards.len());
        assert_eq!(
            recovery.overhead_symbols,
            partial_shards
                .len()
                .saturating_sub(distribution.manifest.source_symbols)
        );
        assert!(recovery.authenticated);
        assert_eq!(recovery.manifest_hash, distribution.manifest.manifest_hash);
    }

    #[test]
    fn proof_artifact_distribution_rejects_corrupted_shard_payload() {
        let payload = deterministic_artifact_payload(384);
        let distribution = package_proof_artifact_for_distribution(
            &payload,
            64,
            10,
            0x0BAD_5EED,
            ObjectId::new_for_test(0xC0DE),
            2,
        )
        .expect("proof artifact should package");

        let mut shards = distribution.shards.clone();
        shards[0].data[0] ^= 0xA5;

        let err = recover_proof_artifact_from_shards(&distribution.manifest, &shards)
            .expect_err("corrupted shard bytes must fail before decode");

        assert!(
            matches!(
                err,
                ProofArtifactDistributionError::ShardPayloadHashMismatch { esi: 0 }
            ),
            "unexpected corruption error: {err:?}"
        );
    }

    #[test]
    fn proof_artifact_distribution_rejects_false_manifest_parameters() {
        let payload = deterministic_artifact_payload(384);
        let distribution = package_proof_artifact_for_distribution(
            &payload,
            64,
            10,
            0xF015_EC0D,
            ObjectId::new_for_test(0xF015),
            4,
        )
        .expect("proof artifact should package");

        let mut forged_manifest = distribution.manifest.clone();
        forged_manifest.k_prime = forged_manifest.k_prime.saturating_add(1);
        forged_manifest.manifest_hash = forged_manifest.recompute_hash();
        assert!(
            forged_manifest.hash_is_valid(),
            "test must cover a self-consistent but semantically false manifest"
        );

        let err = recover_proof_artifact_from_shards(&forged_manifest, &distribution.shards)
            .expect_err("false RFC 6330 metadata must fail before decode");

        assert!(
            matches!(
                err,
                ProofArtifactDistributionError::ManifestParameterMismatch {
                    field: "k_prime",
                    ..
                }
            ),
            "unexpected manifest validation error: {err:?}"
        );
    }

    #[test]
    fn empty_source_payload_produces_valid_nonzero_hash() {
        // Verify that empty source produces a valid hash (not zero due to domain separator)
        let empty_source: Vec<Vec<u8>> = Vec::new();
        let hash = recovered_source_hash(&empty_source);
        assert_ne!(
            hash, 0,
            "Empty source should produce non-zero hash due to domain separator"
        );

        // Verify different empty-like sources produce different hashes
        let empty_symbol = vec![Vec::new()]; // One empty symbol
        let empty_symbol_hash = recovered_source_hash(&empty_symbol);
        assert_ne!(
            hash, empty_symbol_hash,
            "Different empty payloads should produce different hashes"
        );
    }

    // ============================================================================
    // ATP-N15: Comprehensive RaptorQ repair proof unit test harness
    // ============================================================================

    /// Generate deterministic test data for a given size.
    fn generate_atp_test_data(size: usize, offset: u8) -> Vec<u8> {
        (0..size)
            .map(|i| ((i + offset as usize) % 256) as u8)
            .collect()
    }

    /// Create test received symbols with deterministic ESIs.
    fn create_atp_test_received_symbols(k: usize, repair_count: usize) -> Vec<(u32, bool)> {
        let mut symbols = Vec::new();

        // Add source symbols
        for i in 0..k {
            symbols.push((i as u32, true));
        }

        // Add repair symbols starting from K
        for i in 0..repair_count {
            symbols.push(((k + i) as u32, false));
        }

        symbols
    }

    #[test]
    fn test_atp_received_summary_truncation_boundary() {
        let large_symbol_count = MAX_RECEIVED_SYMBOLS + 100;
        let symbols: Vec<(u32, bool)> = (0..large_symbol_count)
            .map(|i| (i as u32, i < large_symbol_count / 2))
            .collect();

        let summary = ReceivedSummary::from_received(symbols.into_iter());

        assert_eq!(summary.total, large_symbol_count);
        assert_eq!(summary.esis.len(), MAX_RECEIVED_SYMBOLS);
        assert!(summary.truncated);

        // Should keep the smallest ESIs due to sorting
        for i in 0..MAX_RECEIVED_SYMBOLS {
            assert_eq!(summary.esis[i], i as u32);
        }
    }

    #[test]
    fn test_atp_received_summary_duplicate_tracking() {
        let symbols = vec![
            (0, true),
            (1, true),
            (1, true), // Duplicate
            (2, false),
            (2, false), // Duplicate
        ];

        let summary = ReceivedSummary::from_received(symbols.into_iter());

        assert_eq!(summary.total, 5); // Includes duplicates in count
        assert_eq!(summary.source_count, 3); // 2 unique + 1 duplicate
        assert_eq!(summary.repair_count, 2); // 1 unique + 1 duplicate
        assert_eq!(summary.esis, vec![0, 1, 1, 2, 2]); // Preserves duplicates
    }

    #[test]
    fn test_atp_received_summary_esi_multiset_hash_stability() {
        let symbols1 = vec![(0, true), (1, true), (2, false)];
        let symbols2 = vec![(0, true), (1, true), (2, false)];
        let symbols3 = vec![(0, true), (2, false), (1, true)]; // Different order

        let summary1 = ReceivedSummary::from_received(symbols1.into_iter());
        let summary2 = ReceivedSummary::from_received(symbols2.into_iter());
        let summary3 = ReceivedSummary::from_received(symbols3.into_iter());

        // Same symbols should produce same hash
        assert_eq!(summary1.esi_multiset_hash, summary2.esi_multiset_hash);
        // Same symbols in different order should produce same hash
        assert_eq!(summary1.esi_multiset_hash, summary3.esi_multiset_hash);
    }

    #[test]
    fn test_atp_proof_hash_hex_roundtrip() {
        let test_bytes = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4,
            0xc3, 0xd2, 0xe1, 0xf0,
        ];
        let hash = ProofHash(test_bytes);

        let hex = hash.to_hex();
        assert_eq!(hex.len(), 64);
        assert_eq!(&hex[..16], "0123456789abcdef");

        #[cfg(test)]
        {
            let recovered = ProofHash::from_hex(&hex).expect("should parse valid hex");
            assert_eq!(recovered, hash);
        }
    }

    #[cfg(test)]
    #[test]
    fn test_atp_proof_hash_hex_validation_boundary() {
        // Valid hex
        let valid_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(ProofHash::from_hex(valid_hex).is_some());

        // Wrong length
        assert!(ProofHash::from_hex("0123456789abcdef").is_none());
        assert!(ProofHash::from_hex(&format!("{valid_hex}00")).is_none());

        // Invalid hex characters
        assert!(
            ProofHash::from_hex("g123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .is_none()
        );
    }

    #[test]
    fn test_atp_decode_proof_content_hash_determinism() {
        let config = make_test_config();
        let symbols = create_atp_test_received_symbols(8, 2);
        let recovered_data = generate_atp_test_data(8 * config.symbol_size, 0);

        let mut builder1 = DecodeProof::builder(config.clone());
        builder1.set_received(ReceivedSummary::from_received(symbols.clone().into_iter()));
        builder1.set_success(std::slice::from_ref(&recovered_data));
        let proof1 = builder1.build();

        let mut builder2 = DecodeProof::builder(config);
        builder2.set_received(ReceivedSummary::from_received(symbols.into_iter()));
        builder2.set_success(&[recovered_data]);
        let proof2 = builder2.build();

        let hash1 = proof1.content_hash();
        let hash2 = proof2.content_hash();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_atp_decode_proof_content_hash_sensitivity() {
        let config = make_test_config();
        let symbols = create_atp_test_received_symbols(8, 2);
        let recovered_data1 = generate_atp_test_data(8 * config.symbol_size, 0);
        let recovered_data2 = generate_atp_test_data(8 * config.symbol_size, 1); // Different data

        let mut builder1 = DecodeProof::builder(config.clone());
        builder1.set_received(ReceivedSummary::from_received(symbols.clone().into_iter()));
        builder1.set_success(&[recovered_data1]);
        let proof1 = builder1.build();

        let mut builder2 = DecodeProof::builder(config);
        builder2.set_received(ReceivedSummary::from_received(symbols.into_iter()));
        builder2.set_success(&[recovered_data2]);
        let proof2 = builder2.build();

        let hash1 = proof1.content_hash();
        let hash2 = proof2.content_hash();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_atp_proof_artifact_manifest_hash_validation_cycle() {
        let test_object_id = ObjectId::new(0x1234, 0x5678);
        let manifest = ProofArtifactManifest {
            version: PROOF_ARTIFACT_DISTRIBUTION_SCHEMA_VERSION,
            object_id: test_object_id,
            sbn: 42,
            artifact_len: 1024,
            symbol_size: 64,
            source_symbols: 16,
            repair_symbols: 4,
            k_prime: 20,
            l: 24,
            seed: 0xdeadbeef,
            source_payload_hash: ProofHash([0; 32]),
            manifest_hash: ProofHash([0; 32]), // Will be wrong
        };

        // Hash should not validate with zero manifest_hash
        assert!(!manifest.hash_is_valid());

        // Recompute and verify
        let correct_hash = manifest.recompute_hash();
        let corrected_manifest = ProofArtifactManifest {
            manifest_hash: correct_hash,
            ..manifest
        };

        assert!(corrected_manifest.hash_is_valid());
    }

    #[test]
    fn test_atp_elimination_trace_pivot_truncation() {
        let config = make_test_config();
        let symbols = create_atp_test_received_symbols(8, 2);

        let mut builder = DecodeProof::builder(config);
        builder.set_received(ReceivedSummary::from_received(symbols.into_iter()));

        // Add many pivot events to test truncation
        for i in 0..(MAX_PIVOT_EVENTS + 50) {
            builder.elimination_mut().record_pivot(i % 100, i % 50); // Arbitrary col, row
        }

        builder.set_success(&[generate_atp_test_data(8 * 64, 0)]);
        let proof = builder.build();

        assert_eq!(proof.elimination.pivot_events.len(), MAX_PIVOT_EVENTS);
        assert!(proof.elimination.pivot_events_truncated);
    }

    #[test]
    fn test_atp_peeling_trace_bounds_checking() {
        let config = make_test_config();
        let symbols = create_atp_test_received_symbols(8, 0);

        let mut builder = DecodeProof::builder(config);
        builder.set_received(ReceivedSummary::from_received(symbols.into_iter()));

        // Add solved indices within bounds
        for i in 0..8 {
            builder.peeling_mut().record_solved(i);
        }

        builder.set_success(&[generate_atp_test_data(8 * 64, 0)]);
        let proof = builder.build();

        assert_eq!(proof.peeling.solved, 8);
        assert_eq!(proof.peeling.solved_indices.len(), 8);
        assert!(!proof.peeling.truncated);
    }

    #[test]
    fn proof_artifact_table_invariant_error_preserves_corruption_evidence() {
        let err = map_systematic_param_error(SystematicParamError::RfcTableInvariantViolation {
            invariant: "K' >= K",
            details: "K=10 K'=9 from RFC systematic index table".to_string(),
        });

        assert_eq!(
            err,
            ProofArtifactDistributionError::RfcTableInvariantViolation {
                invariant: "K' >= K",
                details: "K=10 K'=9 from RFC systematic index table".to_string(),
            }
        );
        assert!(
            !matches!(
                &err,
                ProofArtifactDistributionError::UnsupportedSourceBlock { .. }
            ),
            "table corruption must not be reported as an unsupported source block"
        );

        let display = err.to_string();
        assert!(display.contains("RFC 6330 table invariant violation"));
        assert!(display.contains("K' >= K"));
        assert!(display.contains("K=10 K'=9"));
        let old_sentinel_text = ["maximum supported is ", "0"].concat();
        assert!(!display.contains(&old_sentinel_text));
    }

    #[cfg(feature = "test-internals")]
    #[test]
    fn proof_artifact_table_invariant_error_serializes_as_explicit_corruption() {
        let err = ProofArtifactDistributionError::RfcTableInvariantViolation {
            invariant: "L = K' + S + H",
            details: "K'=20 S=4 H=2 L=21".to_string(),
        };

        let value =
            serde_json::to_value(&err).expect("distribution errors should serialize for proofs");

        assert_eq!(
            value,
            json!({
                "RfcTableInvariantViolation": {
                    "invariant": "L = K' + S + H",
                    "details": "K'=20 S=4 H=2 L=21",
                }
            })
        );
    }

    #[test]
    fn test_atp_proof_distribution_error_coverage() {
        let errors = vec![
            ProofArtifactDistributionError::EmptyArtifact,
            ProofArtifactDistributionError::InvalidSymbolSize,
            ProofArtifactDistributionError::UnsupportedSourceBlock {
                requested: 100000,
                max_supported: 56403,
            },
            ProofArtifactDistributionError::RfcTableInvariantViolation {
                invariant: "P = L - W",
                details: "L=8 W=13 P underflow".to_string(),
            },
            ProofArtifactDistributionError::EncoderUnavailable,
            ProofArtifactDistributionError::ManifestHashMismatch {
                expected: ProofHash([1; 32]),
                actual: ProofHash([2; 32]),
            },
            ProofArtifactDistributionError::ManifestParameterMismatch {
                field: "k_prime",
                expected: 20,
                actual: 24,
            },
            ProofArtifactDistributionError::ShardSizeMismatch {
                esi: 42,
                expected: 64,
                actual: 32,
            },
            ProofArtifactDistributionError::ShardAuthenticationFailed { esi: 99 },
        ];

        for error in errors {
            let display = format!("{error}");
            assert!(!display.is_empty());
            assert!(!display.contains("Debug")); // Should use Display, not Debug
        }
    }

    /// Integration test for ATP gates conformance validation.
    #[test]
    fn test_atp_raptorq_conformance_integration() {
        let config = make_test_config();
        let symbols = create_atp_test_received_symbols(16, 4);
        let recovered_data = generate_atp_test_data(16 * 64, 0);

        let mut builder = DecodeProof::builder(config.clone());
        builder.set_received(ReceivedSummary::from_received(symbols.into_iter()));
        builder.set_success(&[recovered_data]);

        let proof = builder.build();
        let hash = proof.content_hash();

        // Verify proof structure for ATP integration
        assert_eq!(proof.config.k, config.k);
        assert!(matches!(proof.outcome, ProofOutcome::Success { .. }));
        assert!(!hash.to_hex().is_empty());

        // Verify hash determinism for ATP replay
        let hash2 = proof.content_hash();
        assert_eq!(hash, hash2);
    }

    /// Hard-regime telemetry integration test for ATP gates.
    #[test]
    fn test_atp_hard_regime_telemetry_integration() {
        let config = make_test_config();
        let symbols = create_atp_test_received_symbols(12, 6); // High repair overhead

        let mut builder = DecodeProof::builder(config);
        builder.set_received(ReceivedSummary::from_received(symbols.into_iter()));
        builder.set_success(&[generate_atp_test_data(12 * 64, 0)]);
        let proof = builder.build();

        // Verify telemetry data is captured in proof
        assert_eq!(proof.received.repair_count, 6);
        assert!(proof.received.repair_count > proof.config.k / 2); // High overhead condition

        // Proof should be valid for ATP integration
        let hash = proof.content_hash();
        assert_eq!(hash.to_hex().len(), 64);
    }

    /// Boundary condition testing for ATP gate integration.
    #[test]
    fn test_atp_boundary_conditions_for_gates() {
        // Test edge cases that ATP gates need to handle

        // Zero source symbols (minimal config)
        let minimal_config = DecodeConfig {
            object_id: ObjectId::new(0x1234, 0x5678),
            sbn: 0,
            k: 1, // Minimal valid K
            s: 0,
            h: 0,
            l: 1,
            symbol_size: 64,
            seed: 0xdeadbeef,
        };

        let mut builder = DecodeProof::builder(minimal_config);
        builder.set_received(ReceivedSummary::from_received(vec![(0, true)].into_iter()));
        builder.set_success(&[generate_atp_test_data(64, 0)]);
        let proof = builder.build();

        assert!(matches!(proof.outcome, ProofOutcome::Success { .. }));

        // Large symbols (boundary testing)
        let large_config = make_test_config(); // Use existing test config
        let large_symbols = create_atp_test_received_symbols(large_config.k, large_config.k / 4);

        let mut large_builder = DecodeProof::builder(large_config.clone());
        large_builder.set_received(ReceivedSummary::from_received(large_symbols.into_iter()));
        large_builder.set_success(&[generate_atp_test_data(large_config.k * 64, 0)]);
        let large_proof = large_builder.build();

        assert!(matches!(large_proof.outcome, ProofOutcome::Success { .. }));
        assert_eq!(large_proof.config.k, large_config.k);
    }

    #[test]
    fn test_atp_proof_replay_consistency() {
        // Test that proofs maintain consistency across rebuilds for ATP replay
        let config = make_test_config();
        let symbols = create_atp_test_received_symbols(config.k, 2);
        let recovered = make_test_recovered(&config);

        let proof1 = {
            let mut builder = DecodeProof::builder(config.clone());
            builder.set_received(ReceivedSummary::from_received(symbols.clone().into_iter()));
            builder.peeling_mut().record_solved(0);
            builder.peeling_mut().record_solved(4);
            builder.elimination_mut().record_pivot(8, 3);
            builder.elimination_mut().record_pivot(9, 7);
            builder.set_success(&recovered);
            builder.build()
        };

        let proof2 = {
            let mut builder = DecodeProof::builder(config);
            builder.set_received(ReceivedSummary::from_received(symbols.into_iter()));
            builder.peeling_mut().record_solved(0);
            builder.peeling_mut().record_solved(4);
            builder.elimination_mut().record_pivot(8, 3);
            builder.elimination_mut().record_pivot(9, 7);
            builder.set_success(&recovered);
            builder.build()
        };

        // Proofs should be identical for ATP replay consistency
        assert_eq!(proof1.content_hash(), proof2.content_hash());
        assert_eq!(proof1.peeling, proof2.peeling);
        assert_eq!(proof1.elimination.pivots, proof2.elimination.pivots);
    }
