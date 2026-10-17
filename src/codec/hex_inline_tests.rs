    #![allow(clippy::pedantic, clippy::nursery)]
    // Registered verification filters use double underscores to separate the
    // immutable authority prefix from the relation name.
    #![allow(non_snake_case)]

    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::{FileFailurePersistence, RngSeed, TestRunner};

    const CANONICAL_PROPERTY_FAILURES: &str = "target/test-artifacts/dependency-sovereignty/asupersync_d24mms_9_2_99f8c54b8abf/asupersync_d24mms_9_2_property/proptest-regressions.txt";
    const LOCAL_PROPERTY_FAILURES: &str =
        "target/test-artifacts/agent-lane/hex_a2_local_proptest-regressions.txt";

    // bead_id: asupersync-d24mms.9.2
    // scenario_id: hex_a2_safe_scalar_codec
    // seed_or_fixture: local seed 0x4845_585f_4132 plus canonical seeds 0..64
    // command: RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_hex_a2 cargo test -p asupersync --lib codec::hex::tests
    // artifact_path: target/test-artifacts/dependency-sovereignty/asupersync_d24mms_9_2_99f8c54b8abf/asupersync_d24mms_9_2_property on property failure
    // expected_outcome: pass

    fn assert_owned_error_traits<T: Copy + Eq + StdError>() {}

    #[test]
    fn ver_a1_asupersync_d24mms_9_2_99f8c54b8abf__local_invariants__owned_error() {
        assert_owned_error_traits::<HexError>();

        let cases = [
            (
                HexError::InvalidHexCharacter { c: '\n', index: 5 },
                "Invalid character '\\n' at position 5".to_string(),
            ),
            (HexError::OddLength, "Odd number of digits".to_string()),
            (
                HexError::InvalidStringLength,
                "Invalid string length".to_string(),
            ),
            (
                HexError::BinaryLengthExceeded { len: 9, limit: 8 },
                "Hex binary length 9 exceeds limit 8".to_string(),
            ),
            (
                HexError::OutputLengthOverflow {
                    input_len: usize::MAX,
                },
                format!("Hex output length overflow for input length {}", usize::MAX),
            ),
            (
                HexError::AllocationFailed { requested: 17 },
                "Hex output allocation failed for 17 bytes".to_string(),
            ),
        ];

        for (error, expected) in cases {
            assert_eq!(error.to_string(), expected);
        }
    }

    #[test]
    fn ver_a1_asupersync_d24mms_9_2_99f8c54b8abf__local_invariants() {
        let cases: &[(&[u8], &str)] = &[
            (b"", ""),
            (&[0x00], "00"),
            (&[0x09], "09"),
            (&[0x0a], "0a"),
            (&[0x0f], "0f"),
            (&[0x10], "10"),
            (&[0x7f], "7f"),
            (&[0x80], "80"),
            (&[0xf0], "f0"),
            (&[0xff], "ff"),
            (b"Hello world!", "48656c6c6f20776f726c6421"),
        ];

        for &(binary, expected) in cases {
            assert_eq!(encode(binary), Ok(expected.to_string()));
            assert_eq!(decode(expected), Ok(binary.to_vec()));

            let mut destination = vec![0xa5; binary.len()];
            assert_eq!(decode_to_slice(expected, &mut destination), Ok(()));
            assert_eq!(destination, binary);
        }

        assert_eq!(decode("aAbBcC"), Ok(vec![0xaa, 0xbb, 0xcc]));
    }

    #[test]
    fn ver_a1_asupersync_d24mms_9_2_99f8c54b8abf__local_invariants__all_bytes() {
        for value in u8::MIN..=u8::MAX {
            let encoded = encode([value]).expect("one byte is within the codec limit");
            assert_eq!(encoded, format!("{value:02x}"));
            assert_eq!(decode(&encoded), Ok(vec![value]));

            let uppercase = encoded.to_ascii_uppercase();
            assert_eq!(decode(&uppercase), Ok(vec![value]));

            let mut upper_lower = uppercase.into_bytes();
            upper_lower[1].make_ascii_lowercase();
            assert_eq!(decode(&upper_lower), Ok(vec![value]));

            let mut lower_upper = encoded.into_bytes();
            lower_upper[1].make_ascii_uppercase();
            assert_eq!(decode(&lower_upper), Ok(vec![value]));
        }
    }

    #[test]
    fn ver_a1_asupersync_d24mms_9_2_99f8c54b8abf__local_invariants__invalid_positions() {
        for invalid in u8::MIN..=u8::MAX {
            if invalid.is_ascii_hexdigit() {
                continue;
            }

            for index in 0..8 {
                let mut input = vec![b'0'; 8];
                input[index] = invalid;
                let expected = HexError::InvalidHexCharacter {
                    c: char::from(invalid),
                    index,
                };

                assert_eq!(decode(&input), Err(expected));

                let before = [0xa5, 0x5a, 0xc3, 0x3c];
                let mut destination = before;
                assert_eq!(decode_to_slice(&input, &mut destination), Err(expected));
                assert_eq!(destination, before);
            }
        }
    }

    #[test]
    fn ver_a1_asupersync_d24mms_9_2_99f8c54b8abf__local_invariants__strict_alphabet() {
        let cases: &[(&[u8], HexError)] = &[
            (b"0x", HexError::InvalidHexCharacter { c: 'x', index: 1 }),
            (b" 0", HexError::InvalidHexCharacter { c: ' ', index: 0 }),
            (b"0\n", HexError::InvalidHexCharacter { c: '\n', index: 1 }),
            (
                &[0, b'0'],
                HexError::InvalidHexCharacter { c: '\0', index: 0 },
            ),
            (
                "é".as_bytes(),
                HexError::InvalidHexCharacter { c: 'Ã', index: 0 },
            ),
            (
                &[b'0', 0xff],
                HexError::InvalidHexCharacter { c: 'ÿ', index: 1 },
            ),
        ];

        for &(input, expected) in cases {
            assert_eq!(decode(input), Err(expected));
        }
    }

    #[test]
    fn ver_a1_asupersync_d24mms_9_2_99f8c54b8abf__local_invariants__error_precedence() {
        for odd in [b"z".as_slice(), b"0x0".as_slice(), b"00000".as_slice()] {
            assert_eq!(decode(odd), Err(HexError::OddLength));
            let before = [0x11, 0x22, 0x33];
            let mut destination = before;
            assert_eq!(
                decode_to_slice(odd, &mut destination),
                Err(HexError::OddLength)
            );
            assert_eq!(destination, before);
        }

        let before = [0x11, 0x22];
        let mut destination = before;
        assert_eq!(
            decode_to_slice(b"zz", &mut destination),
            Err(HexError::InvalidStringLength)
        );
        assert_eq!(destination, before);

        for destination_len in [0, 1, 3] {
            let before = vec![0x5a; destination_len];
            let mut destination = before.clone();
            assert_eq!(
                decode_to_slice(b"0000", &mut destination),
                Err(HexError::InvalidStringLength)
            );
            assert_eq!(destination, before);
        }
    }

    #[test]
    fn ver_a1_asupersync_d24mms_9_2_99f8c54b8abf__local_invariants__length_plans() {
        assert_eq!(encoded_len(0, MAX_HEX_BINARY_LEN), Ok(0));
        assert_eq!(
            encoded_len(MAX_HEX_BINARY_LEN, MAX_HEX_BINARY_LEN),
            Ok(MAX_HEX_TEXT_LEN)
        );
        assert_eq!(
            decoded_len(MAX_HEX_TEXT_LEN, MAX_HEX_BINARY_LEN),
            Ok(MAX_HEX_BINARY_LEN)
        );

        assert_eq!(
            encoded_len(MAX_HEX_BINARY_LEN + 1, MAX_HEX_BINARY_LEN),
            Err(HexError::BinaryLengthExceeded {
                len: MAX_HEX_BINARY_LEN + 1,
                limit: MAX_HEX_BINARY_LEN,
            })
        );
        assert_eq!(
            decoded_len(MAX_HEX_TEXT_LEN + 2, MAX_HEX_BINARY_LEN),
            Err(HexError::BinaryLengthExceeded {
                len: MAX_HEX_BINARY_LEN + 1,
                limit: MAX_HEX_BINARY_LEN,
            })
        );
        assert_eq!(
            decoded_len(MAX_HEX_TEXT_LEN + 1, MAX_HEX_BINARY_LEN),
            Err(HexError::OddLength)
        );

        let largest_nonoverflowing = usize::MAX / 2;
        assert!(matches!(
            encoded_len(largest_nonoverflowing, MAX_HEX_BINARY_LEN),
            Err(HexError::BinaryLengthExceeded { .. })
        ));
        let overflowing = largest_nonoverflowing + 1;
        assert_eq!(
            encoded_len(overflowing, MAX_HEX_BINARY_LEN),
            Err(HexError::OutputLengthOverflow {
                input_len: overflowing,
            })
        );
    }

    #[test]
    fn ver_a1_asupersync_d24mms_9_2_99f8c54b8abf__local_invariants__small_limits() {
        const SMALL_LIMIT: usize = 2;

        assert_eq!(
            encode_with_max_binary_len(&[0x00, 0xff], SMALL_LIMIT),
            Ok("00ff".to_string())
        );
        assert_eq!(
            encode_with_max_binary_len(&[0x00, 0x11, 0x22], SMALL_LIMIT),
            Err(HexError::BinaryLengthExceeded {
                len: 3,
                limit: SMALL_LIMIT,
            })
        );
        assert_eq!(
            decode_with_max_binary_len(b"00ff", SMALL_LIMIT),
            Ok(vec![0x00, 0xff])
        );
        assert_eq!(
            decode_with_max_binary_len(b"0000zz", SMALL_LIMIT),
            Err(HexError::BinaryLengthExceeded {
                len: 3,
                limit: SMALL_LIMIT,
            })
        );

        let before = [0x11, 0x22, 0x33];
        let mut destination = before;
        assert_eq!(
            decode_to_slice_with_max_binary_len(b"0000zz", &mut destination, SMALL_LIMIT),
            Err(HexError::BinaryLengthExceeded {
                len: 3,
                limit: SMALL_LIMIT,
            })
        );
        assert_eq!(destination, before);
    }

    #[test]
    fn ver_a1_asupersync_d24mms_9_2_99f8c54b8abf__local_invariants__allocation_errors() {
        assert_eq!(
            reserve_string(usize::MAX),
            Err(HexError::AllocationFailed {
                requested: usize::MAX,
            })
        );
        assert_eq!(
            reserve_bytes(usize::MAX),
            Err(HexError::AllocationFailed {
                requested: usize::MAX,
            })
        );
    }

    #[test]
    fn ver_a1_asupersync_d24mms_9_2_99f8c54b8abf__local_invariants__large_roundtrip() {
        const LARGE_LEN: usize = 1024 * 1024;
        let binary = (0..LARGE_LEN)
            .map(|index| (index as u8).wrapping_mul(31).wrapping_add(7))
            .collect::<Vec<_>>();

        let encoded = encode(&binary).expect("one MiB input is within the codec limit");
        assert_eq!(encoded.len(), LARGE_LEN * 2);
        assert_eq!(decode(&encoded), Ok(binary.clone()));

        let mut destination = vec![0; binary.len()];
        assert_eq!(decode_to_slice(&encoded, &mut destination), Ok(()));
        assert_eq!(destination, binary);
    }

    #[test]
    fn ver_a1_asupersync_d24mms_9_2_99f8c54b8abf__property_matrix() {
        let strategy = (
            proptest::collection::vec(any::<u8>(), 0..1024),
            proptest::collection::vec(any::<u8>(), 0..1024),
            proptest::collection::vec(any::<bool>(), 1..2048),
            any::<usize>(),
            any::<u8>().prop_filter("byte is outside the strict ASCII hex alphabet", |byte| {
                !byte.is_ascii_hexdigit()
            }),
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
                |(left, right, case_mask, raw_position, invalid)| {
                    let canonical =
                        encode(&left).map_err(|error| TestCaseError::fail(error.to_string()))?;
                    let mut mixed = canonical.as_bytes().to_vec();
                    for (index, byte) in mixed.iter_mut().enumerate() {
                        if case_mask[index % case_mask.len()] {
                            byte.make_ascii_uppercase();
                        }
                    }
                    prop_assert_eq!(decode(&mixed), Ok(left.clone()));

                    let mut combined = left.clone();
                    combined.extend_from_slice(&right);
                    let mut segmented = canonical.clone();
                    segmented.push_str(
                        &encode(&right).map_err(|error| TestCaseError::fail(error.to_string()))?,
                    );
                    prop_assert_eq!(encode(&combined), Ok(segmented));

                    if !left.is_empty() {
                        let mut invalid_text = canonical.into_bytes();
                        let position = raw_position % invalid_text.len();
                        invalid_text[position] = invalid;
                        let expected = HexError::InvalidHexCharacter {
                            c: char::from(invalid),
                            index: position,
                        };
                        prop_assert_eq!(decode(&invalid_text), Err(expected));

                        let before = vec![0xa5; left.len()];
                        let mut destination = before.clone();
                        prop_assert_eq!(
                            decode_to_slice(&invalid_text, &mut destination),
                            Err(expected)
                        );
                        prop_assert_eq!(destination, before);
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
            rng_seed: RngSeed::Fixed(0x4845_585f_4132),
            ..ProptestConfig::default()
        })]

        #[test]
        fn ver_a1_asupersync_d24mms_9_2_99f8c54b8abf__property_matrix__roundtrip_and_case(
            binary in proptest::collection::vec(any::<u8>(), 0..4096),
            case_mask in proptest::collection::vec(any::<bool>(), 1..8192),
        ) {
            let canonical = encode(&binary).expect("generated input is bounded");
            prop_assert_eq!(canonical.len(), binary.len() * 2);
            prop_assert!(canonical.bytes().all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')));

            let mut mixed = canonical.as_bytes().to_vec();
            for (index, byte) in mixed.iter_mut().enumerate() {
                if case_mask[index % case_mask.len()] {
                    byte.make_ascii_uppercase();
                }
            }

            prop_assert_eq!(decode(&mixed), Ok(binary.clone()));
            let decoded = decode(&mixed).expect("case changes preserve validity");
            prop_assert_eq!(encode(&decoded), Ok(canonical));

            let mut destination = vec![0xa5; binary.len()];
            prop_assert_eq!(decode_to_slice(&mixed, &mut destination), Ok(()));
            prop_assert_eq!(destination, binary);
        }

        #[test]
        fn ver_a1_asupersync_d24mms_9_2_99f8c54b8abf__property_matrix__concatenation(
            left in proptest::collection::vec(any::<u8>(), 0..2048),
            right in proptest::collection::vec(any::<u8>(), 0..2048),
        ) {
            let mut combined = left.clone();
            combined.extend_from_slice(&right);

            let mut segmented = encode(&left).expect("generated left input is bounded");
            segmented.push_str(&encode(&right).expect("generated right input is bounded"));

            prop_assert_eq!(encode(&combined), Ok(segmented));
        }

        #[test]
        fn ver_a1_asupersync_d24mms_9_2_99f8c54b8abf__property_matrix__invalid_atomicity(
            binary in proptest::collection::vec(any::<u8>(), 1..2048),
            raw_position in any::<usize>(),
            invalid in any::<u8>().prop_filter(
                "byte is outside the strict ASCII hex alphabet",
                |byte| !byte.is_ascii_hexdigit(),
            ),
            prefill in any::<u8>(),
        ) {
            let mut encoded = encode(&binary)
                .expect("generated input is bounded")
                .into_bytes();
            let position = raw_position % encoded.len();
            encoded[position] = invalid;
            let expected = HexError::InvalidHexCharacter {
                c: char::from(invalid),
                index: position,
            };

            prop_assert_eq!(decode(&encoded), Err(expected));

            let before = vec![prefill; binary.len()];
            let mut destination = before.clone();
            prop_assert_eq!(decode_to_slice(&encoded, &mut destination), Err(expected));
            prop_assert_eq!(destination, before);
        }

        #[test]
        fn ver_a1_asupersync_d24mms_9_2_99f8c54b8abf__property_matrix__resource_boundary(
            excess in 1_usize..=1_000_000,
        ) {
            let binary_len = MAX_HEX_BINARY_LEN + excess;
            prop_assert_eq!(
                encoded_len(binary_len, MAX_HEX_BINARY_LEN),
                Err(HexError::BinaryLengthExceeded {
                    len: binary_len,
                    limit: MAX_HEX_BINARY_LEN,
                }),
            );

            let text_len = binary_len * 2;
            prop_assert_eq!(
                decoded_len(text_len, MAX_HEX_BINARY_LEN),
                Err(HexError::BinaryLengthExceeded {
                    len: binary_len,
                    limit: MAX_HEX_BINARY_LEN,
                }),
            );
        }
    }
