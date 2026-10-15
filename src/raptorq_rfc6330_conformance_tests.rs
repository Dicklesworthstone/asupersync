//! RaptorQ RFC 6330 conformance checks over production seams.
//!
//! This module is intentionally wired into the crate test surface, so it must
//! exercise the real RaptorQ encoder, decoder, parameter table, tuple expansion,
//! and GF(256) arithmetic. It must not carry a local replacement implementation that
//! can report conformance independently of the production code.

#[cfg(test)]
mod tests {
    use crate::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
    use crate::raptorq::gf256::{Gf256, gf256_addmul_slice};
    use crate::raptorq::systematic::{EmittedSymbol, SystematicEncoder, SystematicParams};

    const SYMBOL_SIZE: usize = 16;
    const SEED: u64 = 0x6330_5eed;

    fn source_symbols(k: usize, symbol_size: usize) -> Vec<Vec<u8>> {
        (0..k)
            .map(|symbol_index| {
                (0..symbol_size)
                    .map(|byte_index| {
                        ((symbol_index * 31 + byte_index * 17 + symbol_index * byte_index + 7)
                            % 251) as u8
                    })
                    .collect()
            })
            .collect()
    }

    fn received_from_emitted(
        decoder: &InactivationDecoder,
        emitted: &EmittedSymbol,
    ) -> ReceivedSymbol {
        let (columns, coefficients) = if emitted.is_source {
            decoder.source_equation(emitted.esi)
        } else {
            decoder
                .repair_equation(emitted.esi)
                .expect("repair ESI should map into the RFC tuple domain")
        };

        ReceivedSymbol {
            esi: emitted.esi,
            is_source: emitted.is_source,
            columns,
            coefficients,
            data: emitted.data.clone(),
        }
    }

    #[test]
    fn rfc6330_parameters_are_table_driven_and_fail_closed() {
        for k in [1, 2, 10, 11, 64, 257, 1024, 56_403] {
            let params = SystematicParams::try_for_source_block(k, SYMBOL_SIZE)
                .unwrap_or_else(|err| panic!("K={k} should be supported by RFC Table 2: {err:?}"));

            assert_eq!(params.k, k, "K must be preserved in params for K={k}");
            assert_eq!(
                params.symbol_size, SYMBOL_SIZE,
                "symbol size must be preserved for K={k}"
            );
            assert!(
                params.k_prime >= params.k,
                "K' must extend or equal K for K={k}: {params:?}"
            );
            assert_eq!(
                params.l,
                params.k_prime + params.s + params.h,
                "L must be K' + S + H for K={k}: {params:?}"
            );
            assert_eq!(
                params.p,
                params.l - params.w,
                "P must be L - W for K={k}: {params:?}"
            );
            assert_eq!(
                params.b,
                params.w - params.s,
                "B must be W - S for K={k}: {params:?}"
            );
        }

        assert!(
            SystematicParams::try_for_source_block(0, SYMBOL_SIZE).is_err(),
            "K=0 must be rejected instead of mapped to a sentinel parameter row"
        );
        assert!(
            SystematicParams::try_for_source_block(56_404, SYMBOL_SIZE).is_err(),
            "K above the RFC Table 2 boundary must fail closed"
        );
    }

    #[test]
    fn systematic_encoder_emits_source_symbols_unchanged() {
        let source = source_symbols(8, SYMBOL_SIZE);
        let mut encoder =
            SystematicEncoder::new(&source, SYMBOL_SIZE, SEED).expect("encoder should build");

        let emitted = encoder.emit_systematic();
        assert_eq!(emitted.len(), source.len());

        for (index, (emitted, expected)) in emitted.iter().zip(source.iter()).enumerate() {
            assert_eq!(emitted.esi, index as u32);
            assert!(
                emitted.is_source,
                "systematic ESI {index} must be marked as source"
            );
            assert_eq!(emitted.degree, 1, "source ESI {index} must be degree one");
            assert_eq!(
                &emitted.data, expected,
                "systematic ESI {index} must preserve the original source symbol"
            );
        }

        assert!(
            encoder.emit_systematic().is_empty(),
            "systematic emission should be one-shot and idempotent after first pass"
        );
    }

    #[test]
    fn repair_symbols_match_decoder_rfc_tuple_equations() {
        let k = 9;
        let source = source_symbols(k, SYMBOL_SIZE);
        let encoder =
            SystematicEncoder::new(&source, SYMBOL_SIZE, SEED).expect("encoder should build");
        let decoder = InactivationDecoder::new(k, SYMBOL_SIZE, SEED);

        for repair_offset in 0..4 {
            let esi = k as u32 + repair_offset;
            let expected = encoder.repair_symbol(esi);
            let (columns, coefficients) = decoder
                .repair_equation(esi)
                .expect("repair ESI should produce an RFC tuple equation");

            assert_eq!(
                columns.len(),
                coefficients.len(),
                "repair ESI {esi} must produce matching column/coefficient arity"
            );
            assert!(
                !columns.is_empty(),
                "repair ESI {esi} must depend on at least one intermediate symbol"
            );

            let mut actual = vec![0u8; SYMBOL_SIZE];
            for (column, coefficient) in columns.into_iter().zip(coefficients) {
                gf256_addmul_slice(
                    &mut actual,
                    encoder.intermediate_symbol(column),
                    coefficient,
                );
            }

            assert_eq!(
                actual, expected,
                "repair ESI {esi} must match the decoder's production RFC tuple equation"
            );
        }
    }

    #[test]
    fn production_decoder_round_trips_systematic_symbols() {
        let k = 8;
        let source = source_symbols(k, SYMBOL_SIZE);
        let mut encoder =
            SystematicEncoder::new(&source, SYMBOL_SIZE, SEED).expect("encoder should build");
        let decoder = InactivationDecoder::new(k, SYMBOL_SIZE, SEED);

        let mut received = decoder.constraint_symbols();
        received.extend(
            encoder
                .emit_systematic()
                .iter()
                .map(|emitted| received_from_emitted(&decoder, emitted)),
        );

        let decoded = decoder
            .decode(&received)
            .expect("constraint rows plus all systematic symbols must decode");

        assert_eq!(
            decoded.source, source,
            "production decode must recover the exact source symbols"
        );
    }

    #[test]
    fn production_decoder_recovers_with_mixed_systematic_and_repair_symbols() {
        let k = 10;
        let source = source_symbols(k, SYMBOL_SIZE);
        let mut encoder =
            SystematicEncoder::new(&source, SYMBOL_SIZE, SEED).expect("encoder should build");
        let decoder = InactivationDecoder::new(k, SYMBOL_SIZE, SEED);

        let mut received = decoder.constraint_symbols();
        received.extend(
            encoder
                .emit_systematic()
                .iter()
                .filter(|emitted| !matches!(emitted.esi, 1 | 6 | 8))
                .map(|emitted| received_from_emitted(&decoder, emitted)),
        );

        let repairs = encoder.emit_repair(decoder.params().l);
        assert!(
            !repairs.is_empty(),
            "repair emission must provide production repair rows"
        );
        received.extend(
            repairs
                .iter()
                .map(|emitted| received_from_emitted(&decoder, emitted)),
        );

        let decoded = decoder
            .decode(&received)
            .expect("mixed production source+repair symbols must decode");
        assert_eq!(
            decoded.source, source,
            "production repair symbols must recover withheld source symbols"
        );
    }

    #[test]
    fn production_decoder_is_independent_of_received_symbol_order() {
        let k = 7;
        let source = source_symbols(k, SYMBOL_SIZE);
        let mut encoder =
            SystematicEncoder::new(&source, SYMBOL_SIZE, SEED).expect("encoder should build");
        let decoder = InactivationDecoder::new(k, SYMBOL_SIZE, SEED);

        let mut ordered = decoder.constraint_symbols();
        ordered.extend(
            encoder
                .emit_systematic()
                .iter()
                .map(|emitted| received_from_emitted(&decoder, emitted)),
        );

        let mut reversed = ordered.clone();
        reversed.reverse();

        let ordered_source = decoder
            .decode(&ordered)
            .expect("ordered symbols should decode")
            .source;
        let reversed_source = decoder
            .decode(&reversed)
            .expect("reversed symbols should decode")
            .source;

        assert_eq!(ordered_source, source);
        assert_eq!(
            reversed_source, ordered_source,
            "decode result must not depend on received symbol order"
        );
    }

    #[test]
    fn gf256_field_axioms_use_production_tables() {
        let samples = [1u8, 2, 3, 5, 17, 29, 63, 127, 251, 255];

        assert_eq!(Gf256::ZERO + Gf256::ONE, Gf256::ONE);
        assert_eq!(Gf256::ZERO * Gf256::new(29), Gf256::ZERO);
        assert_eq!(Gf256::ONE * Gf256::new(29), Gf256::new(29));

        for &a_raw in &samples {
            let a = Gf256::new(a_raw);
            assert_eq!(
                a * a.inv(),
                Gf256::ONE,
                "nonzero GF(256) element {a_raw} must have a multiplicative inverse"
            );

            for &b_raw in &samples {
                let b = Gf256::new(b_raw);
                assert_eq!(a + b, b + a, "GF(256) addition must commute");
                assert_eq!(a * b, b * a, "GF(256) multiplication must commute");

                for &c_raw in &samples[..4] {
                    let c = Gf256::new(c_raw);
                    assert_eq!(
                        (a * b) * c,
                        a * (b * c),
                        "GF(256) multiplication must associate for {a_raw}, {b_raw}, {c_raw}"
                    );
                }
            }
        }
    }
}
