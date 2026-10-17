    #![allow(clippy::pedantic, clippy::nursery)]
    // Registered verification filters use double underscores to separate the
    // immutable authority prefix from the relation name.
    #![allow(non_snake_case)]

    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::{FileFailurePersistence, RngSeed, TestRunner};

    const CANONICAL_PROPERTY_FAILURES: &str = "target/test-artifacts/dependency-sovereignty/asupersync_d24mms_10_2_ff120f39f884/asupersync_d24mms_10_2_property/proptest-regressions.txt";
    const LOCAL_PROPERTY_FAILURES: &str =
        "target/test-artifacts/agent-lane/base64_a2_local_proptest-regressions.txt";

    const ENGINES: [Base64Engine; 4] = [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD];

    // bead_id: asupersync-d24mms.10.2
    // capability_ids: CAP-BASE64-CODEC, CAP-AUTH-CREDENTIALS
    // scenario_id: base64_a2_safe_scalar_four_engine_core
    // seed_or_fixture: RFC 4648 sections 3-5 and 10; local seed
    // 0x4236_3441_325f_5246; canonical seeds 0..64
    // registered_unit_filter:
    // ver_a1_asupersync_d24mms_10_2_ff120f39f884__local_invariants
    // registered_property_filter:
    // ver_a1_asupersync_d24mms_10_2_ff120f39f884__property_matrix
    // artifact_path: target/test-artifacts/dependency-sovereignty/
    // asupersync_d24mms_10_2_ff120f39f884/asupersync_d24mms_10_2_property
    // expected_outcome: pass
    // proof boundary: these are in-process codec contracts, not downstream
    // protocol, authentication-journey, performance, or dependency-cutover proof.

    fn assert_owned_error_traits<T: Copy + Eq + StdError>() {}

    #[test]
    fn ver_a1_asupersync_d24mms_10_2_ff120f39f884__local_invariants__owned_error() {
        assert_owned_error_traits::<Base64Error>();
        assert_eq!(STANDARD.name(), "STANDARD");
        assert_eq!(STANDARD_NO_PAD.name(), "STANDARD_NO_PAD");
        assert_eq!(URL_SAFE.name(), "URL_SAFE");
        assert_eq!(URL_SAFE_NO_PAD.name(), "URL_SAFE_NO_PAD");
        assert!(STANDARD.emits_padding());
        assert!(!STANDARD_NO_PAD.emits_padding());

        let cases = [
            (
                Base64Error::InvalidByte {
                    index: 2,
                    byte: 0xff,
                },
                "Invalid Base64 byte 0xff at position 2".to_owned(),
            ),
            (
                Base64Error::InvalidLength { len: 5 },
                "Invalid Base64 input length 5".to_owned(),
            ),
            (
                Base64Error::InvalidPadding { index: 3 },
                "Invalid Base64 padding at position 3".to_owned(),
            ),
            (
                Base64Error::InvalidLastSymbol {
                    index: 3,
                    byte: b'B',
                    value: 1,
                },
                "Invalid Base64 last symbol 0x42 (value 1) at position 3".to_owned(),
            ),
            (
                Base64Error::BinaryLengthExceeded { len: 9, limit: 8 },
                "Base64 binary length 9 exceeds limit 8".to_owned(),
            ),
            (
                Base64Error::TextLengthExceeded { len: 13, limit: 12 },
                "Base64 text length 13 exceeds limit 12".to_owned(),
            ),
            (
                Base64Error::OutputLengthOverflow {
                    input_len: usize::MAX,
                },
                format!(
                    "Base64 output length overflow for input length {}",
                    usize::MAX
                ),
            ),
            (
                Base64Error::InvalidOutputLength {
                    expected: 4,
                    actual: 3,
                },
                "Base64 output length 3 does not match required length 4".to_owned(),
            ),
            (
                Base64Error::AllocationFailed { requested: 17 },
                "Base64 output allocation failed for 17 bytes".to_owned(),
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(error.to_string(), expected);
        }
    }

    #[test]
    fn ver_a1_asupersync_d24mms_10_2_ff120f39f884__local_invariants() {
        let vectors = [
            (b"".as_slice(), "", ""),
            (b"f".as_slice(), "Zg==", "Zg"),
            (b"fo".as_slice(), "Zm8=", "Zm8"),
            (b"foo".as_slice(), "Zm9v", "Zm9v"),
            (b"foob".as_slice(), "Zm9vYg==", "Zm9vYg"),
            (b"fooba".as_slice(), "Zm9vYmE=", "Zm9vYmE"),
            (b"foobar".as_slice(), "Zm9vYmFy", "Zm9vYmFy"),
        ];

        for (binary, padded, unpadded) in vectors {
            for engine in [STANDARD, URL_SAFE] {
                assert_eq!(engine.encode(binary), Ok(padded.to_owned()));
                assert_eq!(engine.decode(padded), Ok(binary.to_vec()));
            }
            for engine in [STANDARD_NO_PAD, URL_SAFE_NO_PAD] {
                assert_eq!(engine.encode(binary), Ok(unpadded.to_owned()));
                assert_eq!(engine.decode(unpadded), Ok(binary.to_vec()));
            }
        }
    }

    #[test]
    fn ver_a1_asupersync_d24mms_10_2_ff120f39f884__local_invariants__alphabets() {
        let binary = [0xfb, 0xff, 0xef];
        assert_eq!(STANDARD.encode(binary), Ok("+//v".to_owned()));
        assert_eq!(STANDARD_NO_PAD.encode(binary), Ok("+//v".to_owned()));
        assert_eq!(URL_SAFE.encode(binary), Ok("-__v".to_owned()));
        assert_eq!(URL_SAFE_NO_PAD.encode(binary), Ok("-__v".to_owned()));

        assert_eq!(STANDARD.encode([0xff]), Ok("/w==".to_owned()));
        assert_eq!(STANDARD_NO_PAD.encode([0xff]), Ok("/w".to_owned()));
        assert_eq!(URL_SAFE.encode([0xff]), Ok("_w==".to_owned()));
        assert_eq!(URL_SAFE_NO_PAD.encode([0xff]), Ok("_w".to_owned()));
        assert_eq!(STANDARD.encode([0xff, 0xff]), Ok("//8=".to_owned()));
        assert_eq!(STANDARD_NO_PAD.encode([0xff, 0xff]), Ok("//8".to_owned()));
        assert_eq!(URL_SAFE.encode([0xff, 0xff]), Ok("__8=".to_owned()));
        assert_eq!(URL_SAFE_NO_PAD.encode([0xff, 0xff]), Ok("__8".to_owned()));

        for engine in ENGINES {
            assert_eq!(engine.encode([]), Ok(String::new()));
            assert_eq!(engine.decode([]), Ok(Vec::new()));
        }
    }

    #[test]
    fn ver_a1_asupersync_d24mms_10_2_ff120f39f884__local_invariants__roundtrip() {
        for len in 0..=257 {
            let binary = (0..len)
                .map(|index| (index as u8).wrapping_mul(73).wrapping_add(19))
                .collect::<Vec<_>>();
            for engine in ENGINES {
                let encoded = engine.encode(&binary).expect("short input is bounded");
                assert_eq!(encoded.len(), engine.encoded_len(len).unwrap());
                assert_eq!(engine.decoded_len(&encoded), Ok(len));
                assert_eq!(engine.decode(&encoded), Ok(binary.clone()));

                let mut encoded_slice = vec![0xa5; encoded.len()];
                assert_eq!(engine.encode_to_slice(&binary, &mut encoded_slice), Ok(()));
                assert_eq!(encoded_slice, encoded.as_bytes());

                let mut decoded_slice = vec![0xa5; len];
                assert_eq!(engine.decode_to_slice(&encoded, &mut decoded_slice), Ok(()));
                assert_eq!(decoded_slice, binary);
            }
        }
    }

    #[test]
    fn ver_a1_asupersync_d24mms_10_2_ff120f39f884__local_invariants__strict_alphabet() {
        for (engine, forbidden) in [
            (STANDARD, *b"-_"),
            (STANDARD_NO_PAD, *b"-_"),
            (URL_SAFE, *b"+/"),
            (URL_SAFE_NO_PAD, *b"+/"),
        ] {
            for byte in forbidden {
                let input = [b'A', byte, b'A', b'A'];
                assert_eq!(
                    engine.decode(input),
                    Err(Base64Error::InvalidByte { index: 1, byte })
                );
            }
            for byte in [b' ', b'\n', b'\r', b'\t', 0, 0x80, 0xff] {
                let input = [b'A', b'A', byte, b'A'];
                assert_eq!(
                    engine.decode(input),
                    Err(Base64Error::InvalidByte { index: 2, byte })
                );
            }
            assert_eq!(
                engine.decode(b"Z g=="),
                Err(Base64Error::InvalidByte {
                    index: 1,
                    byte: b' ',
                })
            );
        }
    }

    #[test]
    fn ver_a1_asupersync_d24mms_10_2_ff120f39f884__local_invariants__invalid_offsets() {
        for engine in ENGINES {
            let values = engine.decode_values();
            for byte in u8::MIN..=u8::MAX {
                if values[usize::from(byte)] != INVALID_VALUE {
                    continue;
                }
                for index in 0..4 {
                    if engine.padded && byte == b'=' && index == 3 {
                        continue;
                    }
                    let mut input = [b'A'; 4];
                    input[index] = byte;
                    let expected = if byte == b'=' {
                        if !engine.padded && index == 3 {
                            Base64Error::InvalidPadding { index }
                        } else {
                            Base64Error::InvalidByte { index, byte }
                        }
                    } else {
                        Base64Error::InvalidByte { index, byte }
                    };
                    assert_eq!(engine.decode(input), Err(expected));
                }
            }
        }
    }

    #[test]
    fn ver_a1_asupersync_d24mms_10_2_ff120f39f884__local_invariants__padding() {
        for engine in ENGINES {
            for (input, index) in [("A=A==", 1), ("Zg===", 2), ("AAAA=", 4), ("AAAA==", 4)] {
                assert_eq!(
                    engine.decode(input),
                    Err(Base64Error::InvalidByte { index, byte: b'=' })
                );
            }
        }

        for engine in [STANDARD, URL_SAFE] {
            for input in ["Zg", "Zg="] {
                assert_eq!(
                    engine.decode(input),
                    Err(Base64Error::InvalidPadding { index: input.len() })
                );
            }
            assert_eq!(
                engine.decode("A"),
                Err(Base64Error::InvalidLength { len: 1 })
            );
            for (input, index) in [("=AAA", 0), ("A=AA", 1), ("AA=A", 2), ("A===", 1)] {
                assert_eq!(
                    engine.decode(input),
                    Err(Base64Error::InvalidByte { index, byte: b'=' })
                );
            }
            for input in ["SGVsbG9", "SGVsbA=", "SGVsbA"] {
                assert_eq!(
                    engine.decode(input),
                    Err(Base64Error::InvalidPadding { index: input.len() })
                );
            }
            assert_eq!(
                engine.decode("SGVsbA===="),
                Err(Base64Error::InvalidByte {
                    index: 6,
                    byte: b'=',
                })
            );
        }

        for engine in [STANDARD_NO_PAD, URL_SAFE_NO_PAD] {
            assert_eq!(
                engine.decode("Zg=="),
                Err(Base64Error::InvalidPadding { index: 2 })
            );
            assert_eq!(
                engine.decode("Zm8="),
                Err(Base64Error::InvalidPadding { index: 3 })
            );
            assert_eq!(
                engine.decode("A"),
                Err(Base64Error::InvalidLength { len: 1 })
            );
        }

        for engine in [STANDARD, URL_SAFE] {
            for mask in 0_u8..16 {
                let mut input = [b'A'; 4];
                for (index, byte) in input.iter_mut().enumerate() {
                    if mask & (1 << index) != 0 {
                        *byte = b'=';
                    }
                }
                assert_eq!(
                    engine.decode(input).is_ok(),
                    matches!(mask, 0 | 8 | 12),
                    "{} padding mask {mask:04b}",
                    engine.name()
                );
            }
        }
        for engine in [STANDARD_NO_PAD, URL_SAFE_NO_PAD] {
            for mask in 0_u8..16 {
                let mut input = [b'A'; 4];
                for (index, byte) in input.iter_mut().enumerate() {
                    if mask & (1 << index) != 0 {
                        *byte = b'=';
                    }
                }
                assert_eq!(
                    engine.decode(input).is_ok(),
                    mask == 0,
                    "{} padding mask {mask:04b}",
                    engine.name()
                );
            }
        }

        for symbol_count in 1..=257 {
            let remainder = symbol_count % 4;
            let mut input = vec![b'A'; symbol_count];
            input.resize(symbol_count + (4 - remainder), b'=');

            for engine in ENGINES {
                let result = engine.decode(&input);
                if remainder < 2 {
                    assert_eq!(
                        result,
                        Err(Base64Error::InvalidByte {
                            index: symbol_count,
                            byte: b'=',
                        }),
                        "{} padding at quartet offset {remainder}",
                        engine.name()
                    );
                } else if engine.padded {
                    assert!(
                        result.is_ok(),
                        "{} rejected canonical padding at quartet offset {remainder}",
                        engine.name()
                    );
                } else {
                    assert_eq!(
                        result,
                        Err(Base64Error::InvalidPadding {
                            index: symbol_count,
                        }),
                        "{} accepted forbidden padding at quartet offset {remainder}",
                        engine.name()
                    );
                }
            }
        }

        for len in 0..=12 {
            let input = vec![b'A'; len];
            for engine in [STANDARD, URL_SAFE] {
                assert_eq!(engine.decode(&input).is_ok(), len.is_multiple_of(4));
            }
            for engine in [STANDARD_NO_PAD, URL_SAFE_NO_PAD] {
                assert_eq!(engine.decode(&input).is_ok(), len % 4 != 1);
            }
        }
    }

    #[test]
    fn ver_a1_asupersync_d24mms_10_2_ff120f39f884__local_invariants__trailing_bits() {
        for engine in [STANDARD, URL_SAFE] {
            assert_eq!(
                engine.decode("SGVsbG9="),
                Err(Base64Error::InvalidLastSymbol {
                    index: 6,
                    byte: b'9',
                    value: 61,
                })
            );
        }

        for engine in ENGINES {
            let alphabet = engine.alphabet_bytes();
            for value in 0_u8..64 {
                let mut two_symbols = vec![alphabet[0], alphabet[usize::from(value)]];
                if engine.padded {
                    two_symbols.extend_from_slice(b"==");
                }
                let result = engine.decode(&two_symbols);
                if value & 0x0f == 0 {
                    assert!(result.is_ok(), "{} rejected value {value}", engine.name());
                } else {
                    assert_eq!(
                        result,
                        Err(Base64Error::InvalidLastSymbol {
                            index: 1,
                            byte: alphabet[usize::from(value)],
                            value,
                        })
                    );
                }

                let mut three_symbols =
                    vec![alphabet[0], alphabet[0], alphabet[usize::from(value)]];
                if engine.padded {
                    three_symbols.push(b'=');
                }
                let result = engine.decode(&three_symbols);
                if value & 0x03 == 0 {
                    assert!(result.is_ok(), "{} rejected value {value}", engine.name());
                } else {
                    assert_eq!(
                        result,
                        Err(Base64Error::InvalidLastSymbol {
                            index: 2,
                            byte: alphabet[usize::from(value)],
                            value,
                        })
                    );
                }
            }
        }
    }

    #[test]
    fn ver_a1_asupersync_d24mms_10_2_ff120f39f884__local_invariants__atomic_decode() {
        for engine in ENGINES {
            let valid = engine.encode([0, 1, 2, 3, 4, 5]).unwrap();
            let mut malformed = valid.into_bytes();
            malformed[7] = b'!';

            let before = [0xa5; 6];
            let mut output = before;
            assert_eq!(
                engine.decode_to_slice(&malformed, &mut output),
                Err(Base64Error::InvalidByte {
                    index: 7,
                    byte: b'!',
                })
            );
            assert_eq!(output, before);

            for actual in [0, 3, 5] {
                let before = vec![0x5a; actual];
                let mut output = before.clone();
                assert_eq!(
                    engine.decode_to_slice(engine.encode([1, 2, 3, 4]).unwrap(), &mut output),
                    Err(Base64Error::InvalidOutputLength {
                        expected: 4,
                        actual,
                    })
                );
                assert_eq!(output, before);
            }
        }
    }

    #[test]
    fn ver_a1_asupersync_d24mms_10_2_ff120f39f884__local_invariants__error_precedence() {
        assert_eq!(
            STANDARD.decode_plan(b"!AAA!", MAX_BASE64_BINARY_LEN),
            Err(Base64Error::InvalidByte {
                index: 4,
                byte: b'!',
            })
        );
        assert_eq!(
            STANDARD.decode_plan(b"!AAAA", MAX_BASE64_BINARY_LEN),
            Err(Base64Error::InvalidByte {
                index: 0,
                byte: b'!',
            })
        );
        assert_eq!(
            STANDARD.decode_plan(b"!AAA", 2),
            Err(Base64Error::BinaryLengthExceeded { len: 3, limit: 2 })
        );
        assert_eq!(
            STANDARD.decode_plan(b"!", MAX_BASE64_BINARY_LEN),
            Err(Base64Error::InvalidByte {
                index: 0,
                byte: b'!',
            })
        );
        assert_eq!(
            STANDARD.decode_plan(b"AAA!", 2),
            Err(Base64Error::BinaryLengthExceeded { len: 3, limit: 2 })
        );

        let before = [0xa5; 2];
        let mut destination = before;
        assert_eq!(
            STANDARD.decode_to_slice(b"AAA!", &mut destination),
            Err(Base64Error::InvalidByte {
                index: 3,
                byte: b'!',
            })
        );
        assert_eq!(destination, before);

        let mut destination = before;
        assert_eq!(
            STANDARD.decode_to_slice(b"AAB=", &mut destination),
            Err(Base64Error::InvalidLastSymbol {
                index: 2,
                byte: b'B',
                value: 1,
            })
        );
        assert_eq!(destination, before);
    }

    #[test]
    fn ver_a1_asupersync_d24mms_10_2_ff120f39f884__local_invariants__atomic_encode() {
        for engine in ENGINES {
            let expected = engine.encoded_len(5).unwrap();
            for actual in [0, expected - 1, expected + 1] {
                let before = vec![0x5a; actual];
                let mut output = before.clone();
                assert_eq!(
                    engine.encode_to_slice([1, 2, 3, 4, 5], &mut output),
                    Err(Base64Error::InvalidOutputLength { expected, actual })
                );
                assert_eq!(output, before);
            }
        }
    }

    #[test]
    fn ver_a1_asupersync_d24mms_10_2_ff120f39f884__local_invariants__length_plans() {
        assert_eq!(STANDARD.encoded_len(0), Ok(0));
        assert_eq!(STANDARD.encoded_len(1), Ok(4));
        assert_eq!(STANDARD_NO_PAD.encoded_len(1), Ok(2));
        assert_eq!(STANDARD.encoded_len(2), Ok(4));
        assert_eq!(STANDARD_NO_PAD.encoded_len(2), Ok(3));
        assert_eq!(STANDARD.encoded_len(3), Ok(4));
        assert_eq!(STANDARD_NO_PAD.encoded_len(3), Ok(4));
        assert_eq!(
            STANDARD.encoded_len(MAX_BASE64_BINARY_LEN),
            Ok(MAX_BASE64_TEXT_LEN)
        );
        for engine in ENGINES {
            assert_eq!(
                engine.encoded_len(MAX_BASE64_BINARY_LEN + 1),
                Err(Base64Error::BinaryLengthExceeded {
                    len: MAX_BASE64_BINARY_LEN + 1,
                    limit: MAX_BASE64_BINARY_LEN,
                })
            );
        }

        assert_eq!(
            encoded_len_with_max(3, 2, true),
            Err(Base64Error::BinaryLengthExceeded { len: 3, limit: 2 })
        );
        assert_eq!(
            STANDARD.decode_plan(b"AAAA", 2),
            Err(Base64Error::BinaryLengthExceeded { len: 3, limit: 2 })
        );
        assert_eq!(
            STANDARD.decode_plan(b"AAAAA", 2),
            Err(Base64Error::TextLengthExceeded { len: 5, limit: 4 })
        );

        let overflowing = (usize::MAX / 4) * 3 + 3;
        assert!(matches!(
            encoded_len_with_max(overflowing, usize::MAX, true),
            Err(Base64Error::OutputLengthOverflow { .. })
        ));
    }

    #[test]
    fn ver_a1_asupersync_d24mms_10_2_ff120f39f884__local_invariants__allocation_errors() {
        assert_eq!(
            reserve_string(usize::MAX),
            Err(Base64Error::AllocationFailed {
                requested: usize::MAX,
            })
        );
        assert_eq!(
            reserve_bytes(usize::MAX),
            Err(Base64Error::AllocationFailed {
                requested: usize::MAX,
            })
        );
    }

    #[test]
    fn ver_a1_asupersync_d24mms_10_2_ff120f39f884__local_invariants__large_roundtrip() {
        const LARGE_LEN: usize = 1024 * 1024;
        let binary = (0..LARGE_LEN)
            .map(|index| (index as u8).wrapping_mul(31).wrapping_add(7))
            .collect::<Vec<_>>();

        for engine in ENGINES {
            let encoded = engine.encode(&binary).expect("one MiB is bounded");
            assert_eq!(encoded.len(), engine.encoded_len(LARGE_LEN).unwrap());
            assert_eq!(engine.decode(&encoded), Ok(binary.clone()));

            let mut destination = vec![0xa5; binary.len()];
            assert_eq!(engine.decode_to_slice(&encoded, &mut destination), Ok(()));
            assert_eq!(destination, binary);
        }
    }

    #[test]
    fn ver_a1_asupersync_d24mms_10_2_ff120f39f884__property_matrix() {
        let strategy = (
            proptest::collection::vec(any::<u8>(), 0..1024),
            proptest::collection::vec(any::<u8>(), 0..1024),
            any::<usize>(),
            any::<usize>(),
            any::<u8>(),
            any::<u8>().prop_filter(
                "byte is outside both RFC 4648 Base64 alphabets and padding",
                |byte| {
                    !matches!(
                        byte,
                        b'A'..=b'Z'
                            | b'a'..=b'z'
                            | b'0'..=b'9'
                            | b'+'
                            | b'/'
                            | b'-'
                            | b'_'
                            | b'='
                    )
                },
            ),
        );

        for seed in 0_u64..64 {
            let mut config = ProptestConfig::with_cases(4);
            config.rng_seed = RngSeed::Fixed(seed);
            config.source_file = Some(file!());
            config.failure_persistence = Some(Box::new(FileFailurePersistence::Direct(
                CANONICAL_PROPERTY_FAILURES,
            )));
            let mut runner = TestRunner::new(config);

            let result = runner.run(
                &strategy,
                |(binary, text, destination_len, raw_position, prefill, invalid)| {
                    for engine in ENGINES {
                        let encoded = engine
                            .encode(&binary)
                            .map_err(|error| TestCaseError::fail(error.to_string()))?;
                        prop_assert_eq!(engine.encoded_len(binary.len()), Ok(encoded.len()));
                        prop_assert_eq!(engine.decode(&encoded), Ok(binary.clone()));

                        let mut destination = vec![prefill; binary.len()];
                        prop_assert_eq!(engine.decode_to_slice(&encoded, &mut destination), Ok(()));
                        prop_assert_eq!(&destination, &binary);

                        if !encoded.is_empty() {
                            let mut malformed = encoded.into_bytes();
                            let symbol_len = malformed
                                .iter()
                                .position(|&byte| byte == b'=')
                                .unwrap_or(malformed.len());
                            let position = raw_position % symbol_len;
                            malformed[position] = invalid;
                            let expected = Base64Error::InvalidByte {
                                index: position,
                                byte: invalid,
                            };
                            prop_assert_eq!(engine.decode(&malformed), Err(expected));

                            let before = vec![prefill; binary.len()];
                            let mut destination = before.clone();
                            prop_assert_eq!(
                                engine.decode_to_slice(&malformed, &mut destination),
                                Err(expected)
                            );
                            prop_assert_eq!(destination, before);
                        }

                        let before = vec![prefill; destination_len % 1024];
                        let mut destination = before.clone();
                        if engine.decode_to_slice(&text, &mut destination).is_err() {
                            prop_assert_eq!(destination, before);
                        }
                    }

                    Ok(())
                },
            );
            assert!(result.is_ok(), "fixed seed {seed} failed: {result:?}");
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 128,
            failure_persistence: Some(Box::new(FileFailurePersistence::Direct(
                LOCAL_PROPERTY_FAILURES,
            ))),
            rng_seed: RngSeed::Fixed(0x4236_3441_325f_5246),
            ..ProptestConfig::default()
        })]

        #[test]
        fn ver_a1_asupersync_d24mms_10_2_ff120f39f884__property_matrix__roundtrip_and_atomicity(
            binary in proptest::collection::vec(any::<u8>(), 0..4096),
            prefill in any::<u8>(),
        ) {
            for engine in ENGINES {
                let encoded = engine.encode(&binary).expect("generated input is bounded");
                prop_assert_eq!(engine.decode(&encoded), Ok(binary.clone()));

                let mut output = vec![prefill; binary.len()];
                prop_assert_eq!(engine.decode_to_slice(&encoded, &mut output), Ok(()));
                prop_assert_eq!(&output, &binary);

                if !encoded.is_empty() {
                    let mut malformed = encoded.into_bytes();
                    let position = malformed.len() / 2;
                    malformed[position] = b'!';
                    let before = vec![prefill; binary.len()];
                    let mut destination = before.clone();
                    prop_assert!(engine.decode_to_slice(&malformed, &mut destination).is_err());
                    prop_assert_eq!(destination, before);
                }
            }
        }

        #[test]
        fn ver_a1_asupersync_d24mms_10_2_ff120f39f884__property_matrix__arbitrary_text_atomicity(
            text in proptest::collection::vec(any::<u8>(), 0..4096),
            destination_len in 0_usize..4096,
            prefill in any::<u8>(),
        ) {
            for engine in ENGINES {
                let before = vec![prefill; destination_len];
                let mut destination = before.clone();
                let result = engine.decode_to_slice(&text, &mut destination);
                if result.is_err() {
                    prop_assert_eq!(destination, before);
                }
            }
        }
    }
