    #![allow(
        clippy::expect_fun_call,
        clippy::match_wildcard_for_single_variants,
        clippy::needless_collect,
        clippy::pedantic,
        clippy::nursery
    )]

    use super::*;

    fn custom_limits(
        max_input_bytes: usize,
        max_compressed_bytes: usize,
        max_decompressed_bytes: usize,
        max_expansion_ratio: usize,
    ) -> Limits {
        Limits {
            max_input_bytes,
            max_compressed_bytes,
            max_decompressed_bytes,
            max_expansion_ratio,
        }
    }

    fn block(advertised: u32, body: &[u8]) -> Vec<u8> {
        let mut encoded = advertised.to_le_bytes().to_vec();
        encoded.extend_from_slice(body);
        encoded
    }

    #[test]
    fn empty_input_has_canonical_single_token_roundtrip() {
        let encoded = encode_size_prepended(b"", Limits::TRACE).unwrap();
        assert_eq!(encoded, [0, 0, 0, 0, 0]);
        assert_eq!(decode_size_prepended(&encoded, Limits::TRACE).unwrap(), b"");
    }

    #[test]
    fn literal_only_length_boundaries_roundtrip() {
        for len in [1, 4, 5, 12, 13, 14, 15, 16, 269, 270, 271] {
            let payload: Vec<u8> = (0..len).map(|value| value as u8).collect();
            let encoded = encode_size_prepended(&payload, Limits::TRACE).unwrap();
            assert_eq!(
                decode_size_prepended(&encoded, Limits::TRACE).unwrap(),
                payload,
                "length {len}"
            );
        }
    }

    #[test]
    fn decoder_accepts_exact_literal_extension_boundaries() {
        let fifteen = block(15, &[&[0xf0, 0][..], &[b'x'; 15]].concat());
        assert_eq!(
            decode_size_prepended(&fifteen, Limits::TRACE).unwrap(),
            vec![b'x'; 15]
        );

        let two_hundred_seventy = block(270, &[&[0xf0, 255, 0][..], &[b'y'; 270]].concat());
        assert_eq!(
            decode_size_prepended(&two_hundred_seventy, Limits::TRACE).unwrap(),
            vec![b'y'; 270]
        );
    }

    #[test]
    fn overlapping_match_and_match_extension_roundtrip() {
        let encoded = block(
            25,
            &[
                &[0x1f, b'a', 1, 0, 0][..],
                &[0x50, b'b', b'c', b'd', b'e', b'f'][..],
            ]
            .concat(),
        );
        let mut expected = vec![b'a'; 20];
        expected.extend_from_slice(b"bcdef");
        assert_eq!(
            decode_size_prepended(&encoded, Limits::TRACE).unwrap(),
            expected
        );
    }

    #[test]
    fn repeated_payload_is_compressed_and_deterministic() {
        let payload = vec![0xa5; 64 * 1024];
        let first = encode_size_prepended(&payload, Limits::TRACE).unwrap();
        let second = encode_size_prepended(&payload, Limits::TRACE).unwrap();
        assert_eq!(first, second);
        assert!(first.len() < payload.len() / 100);
        assert_eq!(
            decode_size_prepended(&first, Limits::TRACE).unwrap(),
            payload
        );
    }

    #[test]
    fn incumbent_and_owned_codec_accept_each_others_basic_blocks() {
        let payloads: [Vec<u8>; 4] = [
            Vec::new(),
            b"small literal".to_vec(),
            vec![7; 4096],
            (0_usize..65_537)
                .map(|index| (index.wrapping_mul(31) & 0xff) as u8)
                .collect(),
        ];

        for payload in payloads {
            let owned = encode_size_prepended(&payload, Limits::TRACE).unwrap();
            assert_eq!(
                lz4_flex::decompress_size_prepended(&owned).unwrap(),
                payload
            );

            let incumbent = lz4_flex::compress_prepend_size(&payload);
            assert_eq!(
                decode_size_prepended(&incumbent, Limits::TRACE).unwrap(),
                payload
            );
        }
    }

    #[test]
    fn deterministic_roundtrip_sweep_covers_empty_and_mixed_inputs() {
        for len in 0_usize..512 {
            let payload: Vec<u8> = (0..len)
                .map(|index| {
                    let mixed = index ^ (index >> 3) ^ len;
                    (mixed.wrapping_mul(17) & 0xff) as u8
                })
                .collect();
            let encoded = encode_size_prepended(&payload, Limits::TRACE).unwrap();
            assert_eq!(
                decode_size_prepended(&encoded, Limits::TRACE).unwrap(),
                payload,
                "length {len}"
            );
            assert_eq!(
                lz4_flex::decompress_size_prepended(&encoded).unwrap(),
                payload,
                "incumbent decode at length {len}"
            );
        }
    }

    #[test]
    fn encoder_enforces_input_and_output_limits() {
        let input_limited = custom_limits(3, 1024, 1024, 256);
        assert!(matches!(
            encode_size_prepended(b"four", input_limited),
            Err(Error::InputTooLarge { actual: 4, max: 3 })
        ));

        let output_limited = custom_limits(1024, 4, 1024, 256);
        assert!(matches!(
            encode_size_prepended(b"", output_limited),
            Err(Error::CompressedOutputTooLarge { max: 4, .. })
        ));
    }

    #[test]
    fn decoder_enforces_compressed_output_and_ratio_limits_before_decode() {
        let compressed_limited = custom_limits(1024, 4, 1024, 256);
        assert!(matches!(
            decode_size_prepended(&[0, 0, 0, 0, 0], compressed_limited),
            Err(Error::CompressedInputTooLarge { actual: 5, max: 4 })
        ));

        let output_limited = custom_limits(1024, 1024, 4, 256);
        assert!(matches!(
            decode_size_prepended(&block(5, &[0x50, 1, 2, 3, 4, 5]), output_limited),
            Err(Error::AdvertisedOutputTooLarge { actual: 5, max: 4 })
        ));

        let ratio_limited = custom_limits(1024, 1024, 1024, 2);
        let high_ratio = block(
            25,
            &[
                &[0x1f, b'a', 1, 0, 0][..],
                &[0x50, b'b', b'c', b'd', b'e', b'f'][..],
            ]
            .concat(),
        );
        assert!(matches!(
            decode_size_prepended(&high_ratio, ratio_limited),
            Err(Error::ExpansionRatioExceeded {
                advertised: 25,
                max_ratio: 2,
                ..
            })
        ));
    }

    #[test]
    fn zero_ratio_limit_is_rejected() {
        let invalid = custom_limits(1024, 1024, 1024, 0);
        assert!(matches!(
            encode_size_prepended(b"x", invalid),
            Err(Error::InvalidLimits { .. })
        ));
        assert!(matches!(
            decode_size_prepended(&block(0, &[0]), invalid),
            Err(Error::InvalidLimits { .. })
        ));
    }

    #[test]
    fn missing_prefix_and_token_are_typed() {
        assert!(matches!(
            decode_size_prepended(&[0, 0, 0], Limits::TRACE),
            Err(Error::MissingSizePrefix { actual: 3 })
        ));
        assert!(matches!(
            decode_size_prepended(&[0, 0, 0, 0], Limits::TRACE),
            Err(Error::UnexpectedEnd {
                field: "token",
                at: 0
            })
        ));
    }

    #[test]
    fn frame_containers_are_rejected_explicitly() {
        for (magic, expected) in [
            (LZ4_FRAME_MAGIC, UnsupportedContainer::Frame),
            (LZ4_LEGACY_FRAME_MAGIC, UnsupportedContainer::LegacyFrame),
            (
                LZ4_SKIPPABLE_MAGIC.to_le_bytes(),
                UnsupportedContainer::SkippableFrame,
            ),
        ] {
            let mut framed = magic.to_vec();
            framed.push(0);
            assert!(matches!(
                decode_size_prepended(&framed, Limits::TRACE),
                Err(Error::UnsupportedContainer { container }) if container == expected
            ));
        }
    }

    #[test]
    fn truncated_literal_and_match_extensions_are_typed() {
        assert!(matches!(
            decode_size_prepended(&block(15, &[0xf0]), Limits::TRACE),
            Err(Error::UnexpectedEnd {
                field: "literal length",
                ..
            })
        ));
        assert!(matches!(
            decode_size_prepended(&block(20, &[0x1f, b'a', 1, 0]), Limits::TRACE),
            Err(Error::UnexpectedEnd {
                field: "match length",
                ..
            })
        ));
    }

    #[test]
    fn literal_and_offset_truncation_are_typed() {
        assert!(matches!(
            decode_size_prepended(&block(3, &[0x30, b'a']), Limits::TRACE),
            Err(Error::LiteralOutOfBounds {
                length: 3,
                remaining: 1
            })
        ));
        assert!(matches!(
            decode_size_prepended(&block(5, &[0x10, b'a', 1]), Limits::TRACE),
            Err(Error::UnexpectedEnd {
                field: "match offset",
                ..
            })
        ));
    }

    #[test]
    fn zero_and_out_of_history_offsets_fail_closed() {
        assert!(matches!(
            decode_size_prepended(&block(10, &[0x10, b'a', 0, 0]), Limits::TRACE),
            Err(Error::OffsetZero { .. })
        ));
        assert!(matches!(
            decode_size_prepended(&block(10, &[0x10, b'a', 2, 0]), Limits::TRACE),
            Err(Error::ExternalDictionaryRequired {
                offset: 2,
                produced: 1
            })
        ));
    }

    #[test]
    fn decoded_output_must_equal_size_prefix_exactly() {
        assert!(matches!(
            decode_size_prepended(&block(1, &[0x20, b'a', b'b']), Limits::TRACE),
            Err(Error::OutputLengthExceeded {
                needed: 2,
                advertised: 1
            })
        ));
        assert!(matches!(
            decode_size_prepended(&block(2, &[0x10, b'a']), Limits::TRACE),
            Err(Error::OutputLengthMismatch {
                advertised: 2,
                actual: 1
            })
        ));
    }

    #[test]
    fn final_sequence_match_bits_are_rejected() {
        assert!(matches!(
            decode_size_prepended(&block(1, &[0x11, b'a']), Limits::TRACE),
            Err(Error::NonCanonicalBlock {
                rule: "the final literal-only sequence has non-zero match bits"
            })
        ));
    }

    #[test]
    fn independent_block_cannot_start_with_match() {
        assert!(matches!(
            decode_size_prepended(&block(9, &[0x00, 1, 0, 0x50, 1, 2, 3, 4, 5]), Limits::TRACE),
            Err(Error::NonCanonicalBlock {
                rule: "an independent block cannot begin with a match"
            })
        ));
    }

    #[test]
    fn canonical_end_conditions_are_enforced() {
        let four_final_literals = block(
            17,
            &[&[0x18, b'a', 1, 0][..], &[0x40, b'b', b'c', b'd', b'e'][..]].concat(),
        );
        assert!(matches!(
            decode_size_prepended(&four_final_literals, Limits::TRACE),
            Err(Error::NonCanonicalBlock {
                rule: "the last sequence must contain at least five literals"
            })
        ));

        let late_match = block(
            10,
            &[
                &[0x10, b'a', 1, 0][..],
                &[0x50, b'b', b'c', b'd', b'e', b'f'][..],
            ]
            .concat(),
        );
        assert!(matches!(
            decode_size_prepended(&late_match, Limits::TRACE),
            Err(Error::NonCanonicalBlock {
                rule: "the last match must start at least twelve bytes before block end"
            })
        ));
    }

    #[test]
    fn error_display_names_actionable_boundary() {
        let error = Error::ExternalDictionaryRequired {
            offset: 17,
            produced: 3,
        };
        let rendered = error.to_string();
        assert!(rendered.contains("offset 17"));
        assert!(rendered.contains("external dictionaries are unsupported"));
    }
