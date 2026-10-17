    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use prost::Message;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    // Simple test message for unit tests
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct TestMessage {
        #[prost(string, tag = "1")]
        pub name: String,
        #[prost(int32, tag = "2")]
        pub value: i32,
    }

    // Nested message for testing complex structures
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct NestedMessage {
        #[prost(message, optional, tag = "1")]
        pub inner: Option<TestMessage>,
        #[prost(repeated, string, tag = "2")]
        pub items: Vec<String>,
    }

    // Message with all scalar types for wire type testing
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct AllTypesMessage {
        #[prost(double, tag = "1")]
        pub double_field: f64,
        #[prost(float, tag = "2")]
        pub float_field: f32,
        #[prost(int32, tag = "3")]
        pub int32_field: i32,
        #[prost(int64, tag = "4")]
        pub int64_field: i64,
        #[prost(uint32, tag = "5")]
        pub uint32_field: u32,
        #[prost(uint64, tag = "6")]
        pub uint64_field: u64,
        #[prost(sint32, tag = "7")]
        pub sint32_field: i32,
        #[prost(sint64, tag = "8")]
        pub sint64_field: i64,
        #[prost(fixed32, tag = "9")]
        pub fixed32_field: u32,
        #[prost(fixed64, tag = "10")]
        pub fixed64_field: u64,
        #[prost(sfixed32, tag = "11")]
        pub sfixed32_field: i32,
        #[prost(sfixed64, tag = "12")]
        pub sfixed64_field: i64,
        #[prost(bool, tag = "13")]
        pub bool_field: bool,
        #[prost(string, tag = "14")]
        pub string_field: String,
        #[prost(bytes = "vec", tag = "15")]
        pub bytes_field: Vec<u8>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct OptionalU64VarintMessage {
        #[prost(uint64, optional, tag = "1")]
        pub value: Option<u64>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct OptionalU32VarintMessage {
        #[prost(uint32, optional, tag = "1")]
        pub value: Option<u32>,
    }

    #[test]
    fn test_prost_codec_roundtrip() {
        init_test("test_prost_codec_roundtrip");

        let mut codec: ProstCodec<TestMessage, TestMessage> = ProstCodec::new();

        let original = TestMessage {
            name: "hello".to_string(),
            value: 42,
        };

        let encoded = codec.encode(&original).unwrap();
        let decoded = codec.decode(&encoded).unwrap();

        crate::assert_with_log!(
            decoded == original,
            "roundtrip",
            original.name,
            decoded.name
        );
        crate::test_complete!("test_prost_codec_roundtrip");
    }

    #[test]
    fn test_prost_codec_nested_message() {
        init_test("test_prost_codec_nested_message");

        let mut codec: ProstCodec<NestedMessage, NestedMessage> = ProstCodec::new();

        let original = NestedMessage {
            inner: Some(TestMessage {
                name: "inner".to_string(),
                value: 100,
            }),
            items: vec!["a".to_string(), "b".to_string(), "c".to_string()],
        };

        let encoded = codec.encode(&original).unwrap();
        let decoded = codec.decode(&encoded).unwrap();

        crate::assert_with_log!(decoded == original, "nested", true, decoded == original);
        crate::test_complete!("test_prost_codec_nested_message");
    }

    #[test]
    fn test_prost_codec_all_wire_types() {
        init_test("test_prost_codec_all_wire_types");

        let mut codec: ProstCodec<AllTypesMessage, AllTypesMessage> = ProstCodec::new();

        let original = AllTypesMessage {
            double_field: 1.234,
            float_field: 5.678,
            int32_field: -100,
            int64_field: -200,
            uint32_field: 300,
            uint64_field: 400,
            sint32_field: -500,
            sint64_field: -600,
            fixed32_field: 700,
            fixed64_field: 800,
            sfixed32_field: -900,
            sfixed64_field: -1000,
            bool_field: true,
            string_field: "test string".to_string(),
            bytes_field: vec![0x01, 0x02, 0x03, 0x04],
        };

        let encoded = codec.encode(&original).unwrap();
        let decoded = codec.decode(&encoded).unwrap();

        crate::assert_with_log!(decoded == original, "wire types", true, decoded == original);
        crate::test_complete!("test_prost_codec_all_wire_types");
    }

    #[test]
    fn test_prost_codec_empty_message() {
        init_test("test_prost_codec_empty_message");

        let mut codec: ProstCodec<TestMessage, TestMessage> = ProstCodec::new();

        let original = TestMessage::default();

        let encoded = codec.encode(&original).unwrap();
        let empty = encoded.is_empty();
        crate::assert_with_log!(empty, "empty message encodes to empty bytes", true, empty);

        let decoded = codec.decode(&encoded).unwrap();
        crate::assert_with_log!(
            decoded == original,
            "empty roundtrip",
            true,
            decoded == original
        );
        crate::test_complete!("test_prost_codec_empty_message");
    }

    #[test]
    fn test_prost_codec_message_too_large_encode() {
        init_test("test_prost_codec_message_too_large_encode");

        // Create a codec with a small size limit
        let mut codec: ProstCodec<TestMessage, TestMessage> = ProstCodec::with_max_size(10);

        // Create a message that exceeds the limit
        let large_message = TestMessage {
            name: "this is a very long string that exceeds the limit".to_string(),
            value: 42,
        };

        let result = codec.encode(&large_message);
        let is_err = matches!(result, Err(ProtobufError::MessageTooLarge { .. }));
        crate::assert_with_log!(is_err, "encode fails for large message", true, is_err);
        crate::test_complete!("test_prost_codec_message_too_large_encode");
    }

    #[test]
    fn test_prost_codec_message_too_large_decode() {
        init_test("test_prost_codec_message_too_large_decode");

        // Encode with a large limit
        let mut large_codec: ProstCodec<TestMessage, TestMessage> = ProstCodec::new();
        let message = TestMessage {
            name: "this is a long string".to_string(),
            value: 42,
        };
        let encoded = large_codec.encode(&message).unwrap();

        // Try to decode with a small limit
        let mut small_codec: ProstCodec<TestMessage, TestMessage> = ProstCodec::with_max_size(5);
        let result = small_codec.decode(&encoded);
        let is_err = matches!(result, Err(ProtobufError::MessageTooLarge { .. }));
        crate::assert_with_log!(is_err, "decode fails for large message", true, is_err);
        crate::test_complete!("test_prost_codec_message_too_large_decode");
    }

    #[test]
    fn test_prost_codec_size_limit_reports_exact_wire_size() {
        init_test("test_prost_codec_size_limit_reports_exact_wire_size");

        let message = TestMessage {
            name: "abcd".to_string(),
            value: 7,
        };
        let encoded_len = message.encoded_len();
        let limit = encoded_len - 1;

        let mut encode_codec: ProstCodec<TestMessage, TestMessage> =
            ProstCodec::with_max_size(limit);
        let encode_err = encode_codec
            .encode(&message)
            .expect_err("message should exceed encode limit");
        assert!(matches!(
            encode_err,
            ProtobufError::MessageTooLarge { size, limit: got }
                if size == encoded_len && got == limit
        ));

        let mut unbounded_codec: ProstCodec<TestMessage, TestMessage> = ProstCodec::new();
        let encoded = unbounded_codec
            .encode(&message)
            .expect("message should encode with default limit");
        assert_eq!(encoded.len(), encoded_len);

        let mut decode_codec: ProstCodec<TestMessage, TestMessage> =
            ProstCodec::with_max_size(limit);
        let decode_err = decode_codec
            .decode(&encoded)
            .expect_err("message should exceed decode limit");
        assert!(matches!(
            decode_err,
            ProtobufError::MessageTooLarge { size, limit: got }
                if size == encoded_len && got == limit
        ));

        crate::test_complete!("test_prost_codec_size_limit_reports_exact_wire_size");
    }

    #[test]
    fn test_prost_codec_invalid_data() {
        init_test("test_prost_codec_invalid_data");

        let mut codec: ProstCodec<TestMessage, TestMessage> = ProstCodec::new();

        // Invalid protobuf data (malformed varint)
        let invalid_data = Bytes::from_static(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01,
        ]);

        let result = codec.decode(&invalid_data);
        let is_err = matches!(result, Err(ProtobufError::DecodeError(_)));
        crate::assert_with_log!(is_err, "decode fails for invalid data", true, is_err);
        crate::test_complete!("test_prost_codec_invalid_data");
    }

    fn encode_test_varint(mut value: u64, out: &mut Vec<u8>) {
        while value >= 0x80 {
            out.push((value as u8 & 0x7f) | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
    }

    fn decode_test_varint(input: &[u8]) -> Option<(u64, usize)> {
        let mut value = 0u64;
        let mut shift = 0u32;
        for (idx, byte) in input.iter().copied().enumerate() {
            let chunk = u64::from(byte & 0x7f);
            value |= chunk.checked_shl(shift)?;
            if byte & 0x80 == 0 {
                return Some((value, idx + 1));
            }
            shift += 7;
            if shift >= 64 {
                return None;
            }
        }
        None
    }

    fn shortest_varint_len(mut value: u64) -> usize {
        let mut len = 1usize;
        while value >= 0x80 {
            value >>= 7;
            len += 1;
        }
        len
    }

    fn strict_decode_test_varint(input: &[u8]) -> Option<(u64, usize)> {
        let mut value = 0u64;
        let mut shift = 0u32;
        for (idx, byte) in input.iter().copied().enumerate() {
            let chunk = u64::from(byte & 0x7f);
            if idx == 9 && chunk > 1 {
                return None;
            }
            value |= chunk.checked_shl(shift)?;
            if byte & 0x80 == 0 {
                return Some((value, idx + 1));
            }
            if idx == 9 {
                return None;
            }
            shift += 7;
        }
        None
    }

    fn shortest_varint_classification(
        varint_bytes: &[u8],
        decoded_value: Option<u64>,
    ) -> &'static str {
        match decoded_value {
            Some(value) if shortest_varint_len(value) == varint_bytes.len() => "shortest",
            Some(_) => "non_shortest",
            None => "malformed",
        }
    }

    fn encode_optional_u64_varint(
        value: u64,
    ) -> (
        Bytes,
        ProstCodec<OptionalU64VarintMessage, OptionalU64VarintMessage>,
    ) {
        let mut codec: ProstCodec<OptionalU64VarintMessage, OptionalU64VarintMessage> =
            ProstCodec::new();
        let encoded = codec
            .encode(&OptionalU64VarintMessage { value: Some(value) })
            .expect("encode optional u64 varint");
        (encoded, codec)
    }

    fn encode_optional_u32_varint(
        value: u32,
    ) -> (
        Bytes,
        ProstCodec<OptionalU32VarintMessage, OptionalU32VarintMessage>,
    ) {
        let mut codec: ProstCodec<OptionalU32VarintMessage, OptionalU32VarintMessage> =
            ProstCodec::new();
        let encoded = codec
            .encode(&OptionalU32VarintMessage { value: Some(value) })
            .expect("encode optional u32 varint");
        (encoded, codec)
    }

    fn single_field_varint_payload(encoded: &[u8]) -> &[u8] {
        assert!(!encoded.is_empty(), "expected single-field varint payload");
        assert_eq!(encoded[0], 0x08, "expected field-1 varint tag");
        &encoded[1..]
    }

    fn classify_single_field_varint_wire(
        bytes: &[u8],
    ) -> (Option<u64>, Option<usize>, &'static str) {
        if bytes.first() != Some(&0x08) {
            return (None, None, "malformed");
        }

        let payload = &bytes[1..];
        let Some((decoded_value, consumed)) = strict_decode_test_varint(payload) else {
            return (None, None, "malformed");
        };
        if consumed != payload.len() {
            return (None, None, "malformed");
        }

        (
            Some(decoded_value),
            Some(consumed),
            shortest_varint_classification(payload, Some(decoded_value)),
        )
    }

    #[test]
    fn conformance_protobuf_varint_roundtrip_boundary_matrix() {
        init_test("conformance_protobuf_varint_roundtrip_boundary_matrix");

        const EXACT_RCH_COMMAND: &str = "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_asupersync_gnulez_varint cargo test -p asupersync --lib conformance_protobuf_varint_roundtrip_boundary_matrix -- --nocapture";

        let log_case = |corpus_label: &str,
                        input_byte_length: usize,
                        decoded_value: Option<u64>,
                        encoded_length: Option<usize>,
                        shortest_classification: &str,
                        error_kind: &str,
                        final_verdict: &str| {
            eprintln!(
                "PROTOBUF_VARINT_ROUNDTRIP corpus_label={} input_byte_length={} decoded_value={} encoded_length={} shortest_classification={} error_kind={} exact_rch_command=\"{}\" artifact_paths=none final_varint_roundtrip_verdict={}",
                corpus_label,
                input_byte_length,
                decoded_value.map_or_else(|| "none".to_string(), |value| value.to_string()),
                encoded_length.map_or_else(|| "none".to_string(), |len| len.to_string()),
                shortest_classification,
                error_kind,
                EXACT_RCH_COMMAND,
                final_verdict,
            );
        };

        struct ValidU64Case {
            corpus_label: &'static str,
            value: u64,
        }

        let valid_u64_cases = [
            ValidU64Case {
                corpus_label: "u64_zero",
                value: 0,
            },
            ValidU64Case {
                corpus_label: "u64_one",
                value: 1,
            },
            ValidU64Case {
                corpus_label: "u64_pow2_7",
                value: 1_u64 << 7,
            },
            ValidU64Case {
                corpus_label: "u64_pow2_14",
                value: 1_u64 << 14,
            },
            ValidU64Case {
                corpus_label: "u64_pow2_21",
                value: 1_u64 << 21,
            },
            ValidU64Case {
                corpus_label: "u64_pow2_28",
                value: 1_u64 << 28,
            },
            ValidU64Case {
                corpus_label: "u64_pow2_35",
                value: 1_u64 << 35,
            },
            ValidU64Case {
                corpus_label: "u64_pow2_42",
                value: 1_u64 << 42,
            },
            ValidU64Case {
                corpus_label: "u64_pow2_49",
                value: 1_u64 << 49,
            },
            ValidU64Case {
                corpus_label: "u64_pow2_56",
                value: 1_u64 << 56,
            },
            ValidU64Case {
                corpus_label: "u64_pow2_63",
                value: 1_u64 << 63,
            },
            ValidU64Case {
                corpus_label: "u64_max",
                value: u64::MAX,
            },
        ];

        for case in valid_u64_cases {
            let (encoded, mut codec) = encode_optional_u64_varint(case.value);
            let payload = single_field_varint_payload(encoded.as_ref());
            let (decoded_value, consumed) =
                decode_test_varint(payload).expect("u64 payload should decode");
            assert_eq!(consumed, payload.len());
            assert_eq!(decoded_value, case.value);
            assert_eq!(payload.len(), shortest_varint_len(case.value));

            let decoded = codec.decode(&encoded).expect("roundtrip decode u64");
            assert_eq!(decoded.value, Some(case.value));

            log_case(
                case.corpus_label,
                encoded.len(),
                Some(decoded_value),
                Some(payload.len()),
                shortest_varint_classification(payload, Some(decoded_value)),
                "ok",
                "pass",
            );
        }

        let (encoded_u32_max, mut u32_codec) = encode_optional_u32_varint(u32::MAX);
        let payload_u32_max = single_field_varint_payload(encoded_u32_max.as_ref());
        let (decoded_u32_max, consumed_u32_max) =
            decode_test_varint(payload_u32_max).expect("u32 max payload should decode");
        assert_eq!(consumed_u32_max, payload_u32_max.len());
        assert_eq!(decoded_u32_max, u64::from(u32::MAX));
        assert_eq!(
            payload_u32_max.len(),
            shortest_varint_len(u64::from(u32::MAX))
        );
        let decoded_u32_message = u32_codec
            .decode(&encoded_u32_max)
            .expect("roundtrip decode u32 max");
        assert_eq!(decoded_u32_message.value, Some(u32::MAX));
        log_case(
            "u32_max",
            encoded_u32_max.len(),
            Some(decoded_u32_max),
            Some(payload_u32_max.len()),
            shortest_varint_classification(payload_u32_max, Some(decoded_u32_max)),
            "ok",
            "pass",
        );

        struct InvalidCase {
            corpus_label: &'static str,
            bytes: &'static [u8],
            expected_error_kind: &'static str,
            expected_decoded_value: Option<u64>,
        }

        let invalid_cases = [
            InvalidCase {
                corpus_label: "u64_one_non_shortest_manual",
                bytes: &[0x08, 0x81, 0x00],
                expected_error_kind: "ok",
                expected_decoded_value: Some(1),
            },
            InvalidCase {
                corpus_label: "overlong_varint_11_bytes",
                bytes: &[
                    0x08, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00,
                ],
                expected_error_kind: "DecodeError",
                expected_decoded_value: None,
            },
            InvalidCase {
                corpus_label: "truncated_varint",
                bytes: &[0x08, 0x80],
                expected_error_kind: "DecodeError",
                expected_decoded_value: None,
            },
            InvalidCase {
                corpus_label: "continuation_overflow",
                bytes: &[
                    0x08, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02,
                ],
                expected_error_kind: "DecodeError",
                expected_decoded_value: None,
            },
            InvalidCase {
                corpus_label: "arbitrary_malformed_bytes",
                bytes: &[0xFF, 0x00, 0xFF],
                expected_error_kind: "DecodeError",
                expected_decoded_value: None,
            },
        ];

        for case in invalid_cases {
            let (decoded_value, encoded_length, shortest_classification) =
                classify_single_field_varint_wire(case.bytes);

            let mut codec: ProstCodec<OptionalU64VarintMessage, OptionalU64VarintMessage> =
                ProstCodec::new();
            let result = codec.decode(&Bytes::copy_from_slice(case.bytes));

            match case.expected_error_kind {
                "ok" => {
                    let decoded = result.expect("non-shortest decode should still roundtrip");
                    assert_eq!(decoded.value, case.expected_decoded_value);
                }
                "DecodeError" => {
                    assert!(matches!(result, Err(ProtobufError::DecodeError(_))));
                }
                other => panic!("unexpected expected_error_kind {other}"),
            }

            log_case(
                case.corpus_label,
                case.bytes.len(),
                decoded_value,
                encoded_length,
                shortest_classification,
                case.expected_error_kind,
                "pass",
            );
        }

        crate::test_complete!("conformance_protobuf_varint_roundtrip_boundary_matrix");
    }

    #[test]
    fn conformance_protobuf_decode_malformed_boundary_matrix() {
        init_test("conformance_protobuf_decode_malformed_boundary_matrix");

        const EXACT_RCH_COMMAND: &str = "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_asupersync_eo6jp9_protobuf cargo test -p asupersync --lib conformance_protobuf_decode_malformed_boundary_matrix -- --nocapture";

        enum DecodeExpectation {
            DecodeError,
            OkZeroLengthEmbedded,
            OkAtCap,
        }

        struct DecodeScenario {
            corpus_label: &'static str,
            nesting_depth: usize,
            declared_length: Option<usize>,
            actual_length: usize,
            overflow_guard_decision: &'static str,
            parser_state: &'static str,
            wire: Vec<u8>,
            max_size: usize,
            expectation: DecodeExpectation,
        }

        let mut malformed_varint = vec![0x10];
        malformed_varint.extend_from_slice(&[0xFF; 10]);
        malformed_varint.push(0x01);

        let truncated_embedded = vec![0x0A, 0x02, 0x0A, 0x01];
        let zero_length_embedded = vec![0x0A, 0x00];

        let mut embedded_length_overflow = vec![0x0A];
        encode_test_varint(u64::from(u32::MAX), &mut embedded_length_overflow);

        let at_cap_inner = TestMessage {
            name: "cap".to_string(),
            value: 7,
        };
        let at_cap_outer = NestedMessage {
            inner: Some(at_cap_inner),
            items: Vec::new(),
        };
        let mut at_cap_codec: ProstCodec<NestedMessage, NestedMessage> = ProstCodec::new();
        let at_cap_wire = at_cap_codec.encode(&at_cap_outer).unwrap().to_vec();
        let at_cap_max_size = at_cap_wire.len();
        let (declared_len, _) =
            decode_test_varint(&at_cap_wire[1..]).expect("nested message length prefix");

        let scenarios = vec![
            DecodeScenario {
                corpus_label: "malformed_overlong_varint",
                nesting_depth: 0,
                declared_length: None,
                actual_length: malformed_varint.len(),
                overflow_guard_decision: "pass-through",
                parser_state: "top-level-varint",
                wire: malformed_varint,
                max_size: 256,
                expectation: DecodeExpectation::DecodeError,
            },
            DecodeScenario {
                corpus_label: "unsupported_wire_type",
                nesting_depth: 0,
                declared_length: None,
                actual_length: 1,
                overflow_guard_decision: "pass-through",
                parser_state: "top-level-key",
                wire: vec![0x0F],
                max_size: 256,
                expectation: DecodeExpectation::DecodeError,
            },
            DecodeScenario {
                corpus_label: "arbitrary_bytes_typed_err",
                nesting_depth: 0,
                declared_length: None,
                actual_length: 3,
                overflow_guard_decision: "pass-through",
                parser_state: "arbitrary-prefix",
                wire: vec![0xFF, 0x00, 0xFF],
                max_size: 256,
                expectation: DecodeExpectation::DecodeError,
            },
            DecodeScenario {
                corpus_label: "zero_length_embedded",
                nesting_depth: 1,
                declared_length: Some(0),
                actual_length: 0,
                overflow_guard_decision: "exact-fit",
                parser_state: "embedded-message",
                wire: zero_length_embedded,
                max_size: 256,
                expectation: DecodeExpectation::OkZeroLengthEmbedded,
            },
            DecodeScenario {
                corpus_label: "truncated_embedded_message",
                nesting_depth: 1,
                declared_length: Some(2),
                actual_length: 2,
                overflow_guard_decision: "prefix-complete-payload-truncated",
                parser_state: "embedded-message",
                wire: truncated_embedded,
                max_size: 256,
                expectation: DecodeExpectation::DecodeError,
            },
            DecodeScenario {
                corpus_label: "embedded_length_overflow",
                nesting_depth: 1,
                declared_length: Some(u32::MAX as usize),
                actual_length: 0,
                overflow_guard_decision: "declared>remaining",
                parser_state: "embedded-message",
                wire: embedded_length_overflow,
                max_size: 256,
                expectation: DecodeExpectation::DecodeError,
            },
            DecodeScenario {
                corpus_label: "max_bounded_embedded_length",
                nesting_depth: 1,
                declared_length: Some(declared_len as usize),
                actual_length: declared_len as usize,
                overflow_guard_decision: "at-cap-accept",
                parser_state: "embedded-message",
                wire: at_cap_wire,
                max_size: at_cap_max_size,
                expectation: DecodeExpectation::OkAtCap,
            },
        ];

        for scenario in scenarios {
            let mut codec: ProstCodec<NestedMessage, NestedMessage> =
                ProstCodec::with_max_size(scenario.max_size);
            let bytes = Bytes::from(scenario.wire.clone());
            let result = codec.decode(&bytes);

            let (error_kind, final_verdict) = match (&scenario.expectation, &result) {
                (DecodeExpectation::DecodeError, Err(ProtobufError::DecodeError(_))) => {
                    ("DecodeError", "pass")
                }
                (DecodeExpectation::OkZeroLengthEmbedded, Ok(decoded)) => {
                    let inner = decoded.inner.clone().expect("zero-length embedded inner");
                    assert_eq!(inner, TestMessage::default());
                    ("ok", "pass")
                }
                (DecodeExpectation::OkAtCap, Ok(decoded)) => {
                    assert_eq!(decoded, &at_cap_outer);
                    ("ok", "pass")
                }
                _ => panic!(
                    "scenario {} produced unexpected result: {:?}",
                    scenario.corpus_label, result
                ),
            };

            eprintln!(
                "PROTOBUF_MALFORMED_DECODE corpus_label={} nesting_depth={} declared_length={} actual_length={} overflow_guard_decision={} parser_state={} error_kind={} exact_rch_command=\"{}\" artifact_paths=none final_malformed_protobuf_verdict={}",
                scenario.corpus_label,
                scenario.nesting_depth,
                scenario
                    .declared_length
                    .map_or_else(|| "none".to_string(), |len| len.to_string()),
                scenario.actual_length,
                scenario.overflow_guard_decision,
                scenario.parser_state,
                error_kind,
                EXACT_RCH_COMMAND,
                final_verdict,
            );
        }

        crate::test_complete!("conformance_protobuf_decode_malformed_boundary_matrix");
    }

    #[test]
    fn test_prost_codec_nested_length_prefix_consistency() {
        init_test("test_prost_codec_nested_length_prefix_consistency");

        let inner = TestMessage {
            name: "nested".to_string(),
            value: 99,
        };
        let outer = NestedMessage {
            inner: Some(inner.clone()),
            items: Vec::new(),
        };

        let mut codec: ProstCodec<NestedMessage, NestedMessage> = ProstCodec::new();
        let encoded = codec.encode(&outer).unwrap();
        assert_eq!(encoded[0], 0x0A, "expected field 1 nested-message tag");

        let (declared_len, len_len) =
            decode_test_varint(&encoded[1..]).expect("nested length varint");
        let payload = &encoded[1 + len_len..1 + len_len + declared_len as usize];

        assert_eq!(declared_len as usize, payload.len());

        let decoded_inner = <TestMessage as prost::Message>::decode(payload).unwrap();
        assert_eq!(decoded_inner, inner);

        crate::test_complete!("test_prost_codec_nested_length_prefix_consistency");
    }

    #[test]
    fn conformance_prost_codec_roundtrip_boundary_matrix() {
        init_test("conformance_prost_codec_roundtrip_boundary_matrix");

        const EXACT_RCH_COMMAND: &str = "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_asupersync_91ulk2_prost cargo test -p asupersync --lib conformance_prost_codec_roundtrip_boundary_matrix -- --nocapture";

        fn fingerprint(bytes: &[u8]) -> String {
            let prefix = bytes
                .iter()
                .take(8)
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            format!("len{}:{prefix}", bytes.len())
        }

        let log_case = |corpus_label: &str,
                        declared_length: Option<usize>,
                        actual_length: usize,
                        message_type: &str,
                        allocation_guard_decision: &str,
                        decode_outcome: &str,
                        error_kind: &str,
                        roundtrip_fingerprint: &str| {
            eprintln!(
                "PROTOBUF_ENCODE_BOUNDARY corpus_label={} declared_length={} actual_length={} message_type={} allocation_guard_decision={} decode_outcome={} error_kind={} roundtrip_fingerprint={} exact_rch_command=\"{}\" artifact_paths=none final_no_realloc_panic_verdict=pass",
                corpus_label,
                declared_length.map_or_else(|| "none".to_string(), |len| len.to_string()),
                actual_length,
                message_type,
                allocation_guard_decision,
                decode_outcome,
                error_kind,
                roundtrip_fingerprint,
                EXACT_RCH_COMMAND,
            );
        };

        let empty = TestMessage::default();
        let mut empty_codec: ProstCodec<TestMessage, TestMessage> = ProstCodec::with_max_size(0);
        let empty_wire = empty_codec.encode(&empty).unwrap();
        let empty_decoded = empty_codec.decode(&empty_wire).unwrap();
        assert_eq!(empty_decoded, empty);
        log_case(
            "empty_roundtrip",
            Some(empty.encoded_len()),
            empty_wire.len(),
            "TestMessage",
            "exact-cap-accept",
            "roundtrip-ok",
            "ok",
            &fingerprint(&empty_wire),
        );

        let small = TestMessage {
            name: "hello".to_string(),
            value: 42,
        };
        let small_cap = small.encoded_len();
        let mut small_codec: ProstCodec<TestMessage, TestMessage> =
            ProstCodec::with_max_size(small_cap);
        let small_wire = small_codec.encode(&small).unwrap();
        let small_decoded = small_codec.decode(&small_wire).unwrap();
        assert_eq!(small_decoded, small);
        log_case(
            "small_roundtrip",
            Some(small_cap),
            small_wire.len(),
            "TestMessage",
            "exact-cap-accept",
            "roundtrip-ok",
            "ok",
            &fingerprint(&small_wire),
        );

        let nested = NestedMessage {
            inner: Some(TestMessage {
                name: "inner".to_string(),
                value: 7,
            }),
            items: vec!["a".to_string(), "bb".to_string(), "ccc".to_string()],
        };
        let nested_cap = nested.encoded_len();
        let mut nested_codec: ProstCodec<NestedMessage, NestedMessage> =
            ProstCodec::with_max_size(nested_cap);
        let nested_wire = nested_codec.encode(&nested).unwrap();
        let nested_decoded = nested_codec.decode(&nested_wire).unwrap();
        assert_eq!(nested_decoded, nested);
        log_case(
            "nested_repeated_roundtrip",
            Some(nested_cap),
            nested_wire.len(),
            "NestedMessage",
            "exact-cap-accept",
            "roundtrip-ok",
            "ok",
            &fingerprint(&nested_wire),
        );

        let max_bounded = TestMessage {
            name: "max-bounded-message".repeat(8),
            value: i32::MAX,
        };
        let max_bounded_cap = max_bounded.encoded_len();
        let mut max_bounded_codec: ProstCodec<TestMessage, TestMessage> =
            ProstCodec::with_max_size(max_bounded_cap);
        let max_bounded_wire = max_bounded_codec.encode(&max_bounded).unwrap();
        let max_bounded_decoded = max_bounded_codec.decode(&max_bounded_wire).unwrap();
        assert_eq!(max_bounded_decoded, max_bounded);
        log_case(
            "max_bounded_roundtrip",
            Some(max_bounded_cap),
            max_bounded_wire.len(),
            "TestMessage",
            "exact-cap-accept",
            "roundtrip-ok",
            "ok",
            &fingerprint(&max_bounded_wire),
        );

        let unknown_field = TestMessage {
            name: "unknown-field".to_string(),
            value: 99,
        };
        let mut unknown_codec: ProstCodec<TestMessage, TestMessage> = ProstCodec::new();
        let mut unknown_wire = unknown_codec.encode(&unknown_field).unwrap().to_vec();
        unknown_wire.extend_from_slice(&[0x98, 0x06, 0x7B]);
        let unknown_decoded = unknown_codec.decode(&Bytes::from(unknown_wire)).unwrap();
        assert_eq!(unknown_decoded, unknown_field);
        let unknown_reencoded = unknown_codec.encode(&unknown_decoded).unwrap();
        log_case(
            "unknown_field_tolerant_roundtrip",
            Some(unknown_reencoded.len()),
            unknown_reencoded.len(),
            "TestMessage",
            "within-cap-accept",
            "roundtrip-ok",
            "ok",
            &fingerprint(&unknown_reencoded),
        );

        let huge = TestMessage {
            name: "x".repeat(4096),
            value: 1,
        };
        let huge_declared = huge.encoded_len();
        let huge_cap = huge_declared.saturating_sub(1);
        let mut huge_codec: ProstCodec<TestMessage, TestMessage> =
            ProstCodec::with_max_size(huge_cap);
        let huge_err = huge_codec.encode(&huge).unwrap_err();
        assert!(matches!(
            huge_err,
            ProtobufError::MessageTooLarge {
                size,
                limit
            } if size == huge_declared && limit == huge_cap
        ));
        log_case(
            "huge_message_rejected_before_allocation",
            Some(huge_declared),
            huge_declared,
            "TestMessage",
            "reject-before-alloc",
            "encode-rejected",
            "MessageTooLarge",
            "none",
        );

        let malformed_length_prefix = vec![0x0A, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F];
        let (declared_len, len_len) =
            decode_test_varint(&malformed_length_prefix[1..]).expect("declared length");
        let actual_len = malformed_length_prefix.len().saturating_sub(1 + len_len);
        let mut malformed_codec: ProstCodec<TestMessage, TestMessage> = ProstCodec::new();
        let malformed_err = malformed_codec
            .decode(&Bytes::from(malformed_length_prefix))
            .unwrap_err();
        assert!(matches!(malformed_err, ProtobufError::DecodeError(_)));
        log_case(
            "malformed_length_prefix",
            Some(declared_len as usize),
            actual_len,
            "TestMessage",
            "declared>remaining",
            "decode-err",
            "DecodeError",
            "none",
        );

        let truncated_payload = vec![0x0A, 0x03, b'a', b'b'];
        let mut truncated_codec: ProstCodec<TestMessage, TestMessage> = ProstCodec::new();
        let truncated_err = truncated_codec
            .decode(&Bytes::from(truncated_payload.clone()))
            .unwrap_err();
        assert!(matches!(truncated_err, ProtobufError::DecodeError(_)));
        log_case(
            "truncated_payload",
            Some(3),
            truncated_payload.len() - 2,
            "TestMessage",
            "declared>remaining",
            "decode-err",
            "DecodeError",
            "none",
        );

        let arbitrary = vec![0xFF, 0x00, 0xFF];
        let mut arbitrary_codec: ProstCodec<TestMessage, TestMessage> = ProstCodec::new();
        let arbitrary_err = arbitrary_codec
            .decode(&Bytes::from(arbitrary.clone()))
            .unwrap_err();
        assert!(matches!(arbitrary_err, ProtobufError::DecodeError(_)));
        log_case(
            "arbitrary_bytes_typed_err",
            None,
            arbitrary.len(),
            "TestMessage",
            "pass-through",
            "decode-err",
            "DecodeError",
            "none",
        );

        // Unsupported compression flags are not relevant here:
        // ProstCodec operates after gRPC framing has already validated
        // the 1-byte compressed flag and stripped the length prefix.

        crate::test_complete!("conformance_prost_codec_roundtrip_boundary_matrix");
    }

    #[test]
    fn test_prost_codec_unknown_fields() {
        init_test("test_prost_codec_unknown_fields");

        let mut codec: ProstCodec<TestMessage, TestMessage> = ProstCodec::new();
        let message = TestMessage {
            name: "test".to_string(),
            value: 99,
        };

        let mut encoded = codec.encode(&message).unwrap().to_vec();
        encoded.extend_from_slice(&[0x98, 0x06, 0x7B]); // field 99, varint 123

        let decoded = codec.decode(&Bytes::from(encoded)).unwrap();
        let ok = decoded.name == "test" && decoded.value == 99;
        crate::assert_with_log!(ok, "unknown field ignored", true, ok);
        crate::test_complete!("test_prost_codec_unknown_fields");
    }

    #[test]
    fn test_prost_codec_deterministic_encoding() {
        init_test("test_prost_codec_deterministic_encoding");

        let mut codec: ProstCodec<TestMessage, TestMessage> = ProstCodec::new();

        let message = TestMessage {
            name: "deterministic".to_string(),
            value: 123,
        };

        // Encode multiple times
        let encoded1 = codec.encode(&message).unwrap();
        let encoded2 = codec.encode(&message).unwrap();
        let encoded3 = codec.encode(&message).unwrap();

        // All encodings should be identical
        crate::assert_with_log!(
            encoded1 == encoded2,
            "encoding 1 == 2",
            true,
            encoded1 == encoded2
        );
        crate::assert_with_log!(
            encoded2 == encoded3,
            "encoding 2 == 3",
            true,
            encoded2 == encoded3
        );
        crate::test_complete!("test_prost_codec_deterministic_encoding");
    }

    #[test]
    fn test_prost_codec_max_size_accessors() {
        init_test("test_prost_codec_max_size_accessors");

        let default_codec: ProstCodec<TestMessage, TestMessage> = ProstCodec::new();
        let expected = DEFAULT_MAX_MESSAGE_SIZE;
        let actual = default_codec.max_message_size();
        crate::assert_with_log!(actual == expected, "default max size", expected, actual);

        let custom_codec: ProstCodec<TestMessage, TestMessage> = ProstCodec::with_max_size(1024);
        let expected = 1024;
        let actual = custom_codec.max_message_size();
        crate::assert_with_log!(actual == expected, "custom max size", expected, actual);

        crate::test_complete!("test_prost_codec_max_size_accessors");
    }

    #[test]
    fn test_prost_codec_clone() {
        init_test("test_prost_codec_clone");

        let codec: ProstCodec<TestMessage, TestMessage> = ProstCodec::with_max_size(2048);
        let cloned = codec.clone();

        let expected = codec.max_message_size();
        let actual = cloned.max_message_size();
        crate::assert_with_log!(
            actual == expected,
            "clone preserves max size",
            expected,
            actual
        );
        crate::test_complete!("test_prost_codec_clone");
    }

    #[test]
    fn test_symmetric_codec_alias() {
        init_test("test_symmetric_codec_alias");

        let mut codec: SymmetricProstCodec<TestMessage> = SymmetricProstCodec::new();

        let message = TestMessage {
            name: "symmetric".to_string(),
            value: 777,
        };

        let encoded = codec.encode(&message).unwrap();
        let decoded = codec.decode(&encoded).unwrap();

        crate::assert_with_log!(
            decoded == message,
            "symmetric roundtrip",
            true,
            decoded == message
        );
        crate::test_complete!("test_symmetric_codec_alias");
    }

    /// Owned `ProtoMessage` / [`ProtoCodec`] surface (br-asupersync-5z2scg.1.2).
    ///
    /// The messages here are written by hand on purpose. They are the standing
    /// proof that the authoring boundary is open to downstream crates — nothing
    /// in the owned path requires the additive derive macro or an in-tree
    /// schema registry.
    mod owned_codec {
        use super::*;

        /// Field-for-field mirror of the prost `TestMessage` above, so the two
        /// encoders can be compared byte-for-byte.
        #[derive(Clone, Debug, Default, Eq, PartialEq)]
        struct OwnedTestMessage {
            name: String,
            value: i32,
        }

        impl ProtoMessage for OwnedTestMessage {
            fn encode_fields(
                &self,
                encoder: &mut ProtobufWireEncoder,
            ) -> Result<(), ProtobufWireError> {
                // proto3 wire economy: default-valued fields are not emitted,
                // which is also what makes byte parity with prost possible.
                if !self.name.is_empty() {
                    encoder.write_string(1, &self.name)?;
                }
                if self.value != 0 {
                    encoder.write_int32(2, self.value)?;
                }
                Ok(())
            }

            fn merge_field<'wire>(
                &mut self,
                field: &ProtobufWireField<'wire>,
                _decoder: &mut ProtobufWireDecoder<'wire, '_>,
            ) -> Result<bool, ProtobufWireError> {
                match field.field_number() {
                    1 => {
                        self.name = field.as_str()?.to_owned();
                        Ok(true)
                    }
                    2 => {
                        // int32 rides a 64-bit varint; truncation to the low 32
                        // bits is the specified narrowing.
                        self.value = field.as_varint()? as i32;
                        Ok(true)
                    }
                    _ => Ok(false),
                }
            }
        }

        /// Exercises nested descent, a repeated field, and opt-in unknown-field
        /// preservation in one type.
        #[derive(Clone, Debug, Default, Eq, PartialEq)]
        struct OwnedOuter {
            inner: Option<OwnedTestMessage>,
            items: Vec<String>,
            unknown: UnknownFields,
        }

        impl ProtoMessage for OwnedOuter {
            fn encode_fields(
                &self,
                encoder: &mut ProtobufWireEncoder,
            ) -> Result<(), ProtobufWireError> {
                if let Some(inner) = &self.inner {
                    let nested = inner.encode_to_bytes(ProtobufWireLimits::default())?;
                    encoder.write_message(1, nested.as_ref())?;
                }
                for item in &self.items {
                    encoder.write_string(2, item)?;
                }
                // Preserved fields go last so known fields keep ascending order.
                self.unknown.encode(encoder)?;
                Ok(())
            }

            fn merge_field<'wire>(
                &mut self,
                field: &ProtobufWireField<'wire>,
                decoder: &mut ProtobufWireDecoder<'wire, '_>,
            ) -> Result<bool, ProtobufWireError> {
                match field.field_number() {
                    1 => {
                        let target = self.inner.get_or_insert_with(OwnedTestMessage::default);
                        merge_nested_message(target, field, decoder)?;
                        Ok(true)
                    }
                    2 => {
                        self.items.push(field.as_str()?.to_owned());
                        Ok(true)
                    }
                    _ => {
                        if field.wire_type() == WireType::StartGroup {
                            self.unknown.record_group(field, decoder)?;
                        } else {
                            self.unknown.record(field);
                        }
                        Ok(true)
                    }
                }
            }
        }

        /// Same schema as [`OwnedOuter`] but without preservation, to prove
        /// that dropping unknown fields is a per-message choice.
        #[derive(Clone, Debug, Default, Eq, PartialEq)]
        struct OwnedOuterDropping {
            items: Vec<String>,
        }

        impl ProtoMessage for OwnedOuterDropping {
            fn encode_fields(
                &self,
                encoder: &mut ProtobufWireEncoder,
            ) -> Result<(), ProtobufWireError> {
                for item in &self.items {
                    encoder.write_string(2, item)?;
                }
                Ok(())
            }

            fn merge_field<'wire>(
                &mut self,
                field: &ProtobufWireField<'wire>,
                _decoder: &mut ProtobufWireDecoder<'wire, '_>,
            ) -> Result<bool, ProtobufWireError> {
                if field.field_number() == 2 {
                    self.items.push(field.as_str()?.to_owned());
                    return Ok(true);
                }
                Ok(false)
            }
        }

        fn sample() -> OwnedTestMessage {
            OwnedTestMessage {
                name: "owned".to_string(),
                value: 4242,
            }
        }

        #[test]
        fn owned_codec_roundtrips_through_the_codec_trait() {
            init_test("owned_codec_roundtrips_through_the_codec_trait");

            let mut codec: ProtoCodec<OwnedTestMessage, OwnedTestMessage> = ProtoCodec::new();
            let encoded = codec.encode(&sample()).expect("encode");
            let decoded = codec.decode(&encoded).expect("decode");

            assert_eq!(decoded, sample(), "owned codec must round-trip its value");
            crate::test_complete!("owned_codec_roundtrips_through_the_codec_trait");
        }

        #[test]
        fn owned_encoding_is_byte_identical_to_prost_for_the_same_schema() {
            init_test("owned_encoding_is_byte_identical_to_prost_for_the_same_schema");

            // Interop, not just self-consistency: the owned encoder has to
            // agree with an independent implementation on the exact bytes, or
            // a migrated service would silently stop being wire-compatible
            // with peers that have not migrated.
            for (name, value) in [
                ("", 0_i32),
                ("owned", 4242),
                ("negative", -1),
                ("min", i32::MIN),
                ("max", i32::MAX),
                ("unicode \u{1f600}", 7),
            ] {
                let owned = OwnedTestMessage {
                    name: name.to_string(),
                    value,
                };
                let prost_message = TestMessage {
                    name: name.to_string(),
                    value,
                };

                let mut owned_codec: ProtoCodec<OwnedTestMessage, OwnedTestMessage> =
                    ProtoCodec::new();
                let mut prost_codec: ProstCodec<TestMessage, TestMessage> = ProstCodec::new();

                let owned_bytes = owned_codec.encode(&owned).expect("owned encode");
                let prost_bytes = prost_codec.encode(&prost_message).expect("prost encode");
                assert_eq!(
                    owned_bytes.as_ref(),
                    prost_bytes.as_ref(),
                    "owned and prost encodings must match for name={name:?} value={value}"
                );

                // And each side must accept the other's bytes.
                let owned_from_prost = owned_codec.decode(&prost_bytes).expect("owned decode");
                assert_eq!(owned_from_prost, owned);
                let prost_from_owned = prost_codec.decode(&owned_bytes).expect("prost decode");
                assert_eq!(prost_from_owned, prost_message);
            }
            crate::test_complete!("owned_encoding_is_byte_identical_to_prost_for_the_same_schema");
        }

        #[test]
        fn empty_buffer_decodes_to_the_default_value() {
            init_test("empty_buffer_decodes_to_the_default_value");

            let mut codec: ProtoCodec<OwnedTestMessage, OwnedTestMessage> = ProtoCodec::new();
            let decoded = codec.decode(&Bytes::from(Vec::new())).expect("decode");

            assert_eq!(
                decoded,
                OwnedTestMessage::default(),
                "a zero-length message is the default value, not an error"
            );
            crate::test_complete!("empty_buffer_decodes_to_the_default_value");
        }

        #[test]
        fn oversized_inbound_buffer_is_refused_before_parsing() {
            init_test("oversized_inbound_buffer_is_refused_before_parsing");

            let mut codec: ProtoCodec<OwnedTestMessage, OwnedTestMessage> =
                ProtoCodec::with_max_size(8);
            let big = Bytes::from(vec![0_u8; 64]);

            match codec.decode(&big) {
                Err(ProtoCodecError::DecodeMessageTooLarge { size, limit }) => {
                    assert_eq!(size, 64);
                    assert_eq!(limit, 8);
                }
                other => panic!("expected DecodeMessageTooLarge, got {other:?}"),
            }
            crate::test_complete!("oversized_inbound_buffer_is_refused_before_parsing");
        }

        #[test]
        fn oversized_outbound_message_is_refused_by_the_encoder_budget() {
            init_test("oversized_outbound_message_is_refused_by_the_encoder_budget");

            let mut codec: ProtoCodec<OwnedTestMessage, OwnedTestMessage> =
                ProtoCodec::with_max_size(8);
            let message = OwnedTestMessage {
                name: "x".repeat(4096),
                value: 1,
            };

            // The refusal comes from the wire budget while writing, so the
            // encoder never reserves the space it is about to reject.
            assert!(
                matches!(codec.encode(&message), Err(ProtoCodecError::Wire(_))),
                "an over-budget message must fail closed through the wire kernel"
            );
            crate::test_complete!("oversized_outbound_message_is_refused_by_the_encoder_budget");
        }

        #[test]
        fn channel_configured_limits_are_honored_unlike_the_prost_adapter() {
            init_test("channel_configured_limits_are_honored_unlike_the_prost_adapter");

            let mut owned: ProtoCodec<OwnedTestMessage, OwnedTestMessage> = ProtoCodec::new();
            owned.set_max_decode_message_size(4);
            owned.set_max_encode_message_size(4);

            assert_eq!(owned.max_decode_message_size(), 4);
            assert_eq!(owned.max_encode_message_size(), 4);
            assert!(
                owned.wire_limits().max_message_len <= 4,
                "the structural budget must not out-rank the byte ceiling the channel set"
            );
            assert!(
                matches!(
                    owned.decode(&Bytes::from(vec![0_u8; 16])),
                    Err(ProtoCodecError::DecodeMessageTooLarge { .. })
                ),
                "a limit set through the Codec hook must actually apply"
            );

            // Contrast, pinned deliberately: the prost adapter ignores these
            // hooks. This is the documented behavior difference in the
            // migration table, and it is why the owned codec is not merely a
            // like-for-like swap.
            let mut prost_codec: ProstCodec<TestMessage, TestMessage> = ProstCodec::new();
            prost_codec.set_max_decode_message_size(4);
            assert_eq!(
                prost_codec.max_message_size(),
                DEFAULT_MAX_MESSAGE_SIZE,
                "ProstCodec still ignores the channel hook; the owned codec is the fix"
            );
            crate::test_complete!("channel_configured_limits_are_honored_unlike_the_prost_adapter");
        }

        #[test]
        fn malformed_input_fails_closed_with_a_wire_error() {
            init_test("malformed_input_fails_closed_with_a_wire_error");

            let mut codec: ProtoCodec<OwnedTestMessage, OwnedTestMessage> = ProtoCodec::new();

            // Field 1, length-delimited, declaring 200 bytes of payload that
            // are not present.
            let truncated = Bytes::from(vec![0x0a, 200, 0x01]);
            assert!(
                matches!(codec.decode(&truncated), Err(ProtoCodecError::Wire(_))),
                "a truncated length-delimited field must be rejected"
            );

            // Field 1 declared as a string but carrying invalid UTF-8.
            let bad_utf8 = Bytes::from(vec![0x0a, 0x01, 0xff]);
            assert!(
                matches!(codec.decode(&bad_utf8), Err(ProtoCodecError::Wire(_))),
                "invalid UTF-8 in a string field must be rejected"
            );
            crate::test_complete!("malformed_input_fails_closed_with_a_wire_error");
        }

        #[test]
        fn unknown_fields_survive_a_decode_reencode_roundtrip_when_preserved() {
            init_test("unknown_fields_survive_a_decode_reencode_roundtrip_when_preserved");

            // A "newer peer" buffer: known field 2, plus fields 7 and 9 that
            // this schema has never heard of.
            let mut writer = ProtobufWireEncoder::new(ProtobufWireLimits::default());
            writer.write_string(2, "known").expect("write known");
            writer.write_varint(7, 1234).expect("write unknown varint");
            writer
                .write_string(9, "future-field")
                .expect("write unknown string");
            let wire = writer.finish().expect("finish");

            let mut codec: ProtoCodec<OwnedOuter, OwnedOuter> = ProtoCodec::new();
            let decoded = codec.decode(&wire).expect("decode");

            assert_eq!(decoded.items, vec!["known".to_string()]);
            assert!(
                !decoded.unknown.is_empty(),
                "unknown fields must have been preserved"
            );

            // Re-encoding must reproduce the original buffer exactly, which is
            // the property that lets an old binary forward a new binary's
            // fields without corrupting them.
            let reencoded = codec.encode(&decoded).expect("re-encode");
            assert_eq!(
                reencoded.as_ref(),
                wire.as_ref(),
                "decode/re-encode must be lossless when unknown fields are preserved"
            );
            crate::test_complete!(
                "unknown_fields_survive_a_decode_reencode_roundtrip_when_preserved"
            );
        }

        #[test]
        fn unknown_fields_are_skipped_without_error_when_not_preserved() {
            init_test("unknown_fields_are_skipped_without_error_when_not_preserved");

            let mut writer = ProtobufWireEncoder::new(ProtobufWireLimits::default());
            writer.write_string(2, "known").expect("write known");
            writer.write_varint(7, 1234).expect("write unknown");
            let wire = writer.finish().expect("finish");

            let mut codec: ProtoCodec<OwnedOuterDropping, OwnedOuterDropping> = ProtoCodec::new();
            let decoded = codec
                .decode(&wire)
                .expect("unknown fields must not fail a decode");

            assert_eq!(decoded.items, vec!["known".to_string()]);
            let reencoded = codec.encode(&decoded).expect("re-encode");
            assert!(
                reencoded.len() < wire.len(),
                "a message that drops unknown fields must re-encode smaller"
            );
            crate::test_complete!("unknown_fields_are_skipped_without_error_when_not_preserved");
        }

        #[test]
        fn merging_concatenated_buffers_equals_decoding_the_concatenation() {
            init_test("merging_concatenated_buffers_equals_decoding_the_concatenation");

            let limits = ProtobufWireLimits::default();
            let first = OwnedOuterDropping {
                items: vec!["a".to_string()],
            }
            .encode_to_bytes(limits)
            .expect("encode first");
            let second = OwnedOuterDropping {
                items: vec!["b".to_string()],
            }
            .encode_to_bytes(limits)
            .expect("encode second");

            let mut concatenated = Vec::new();
            concatenated.extend_from_slice(first.as_ref());
            concatenated.extend_from_slice(second.as_ref());

            let from_concatenation =
                OwnedOuterDropping::decode_from_bytes(&concatenated, limits).expect("decode");

            let mut incremental = OwnedOuterDropping::default();
            incremental
                .merge_from_bytes(first.as_ref(), limits)
                .expect("merge first");
            incremental
                .merge_from_bytes(second.as_ref(), limits)
                .expect("merge second");

            assert_eq!(
                incremental, from_concatenation,
                "incremental merge must equal decoding the concatenation"
            );
            assert_eq!(
                incremental.items,
                vec!["a".to_string(), "b".to_string()],
                "a repeated field merges by appending, in wire order"
            );
            crate::test_complete!("merging_concatenated_buffers_equals_decoding_the_concatenation");
        }

        #[test]
        fn scalar_merge_is_last_one_wins_and_nested_message_merge_is_recursive() {
            init_test("scalar_merge_is_last_one_wins_and_nested_message_merge_is_recursive");

            let limits = ProtobufWireLimits::default();

            // Two records for the same scalar field: the later one wins.
            let mut writer = ProtobufWireEncoder::new(limits);
            writer.write_string(1, "first").expect("write");
            writer.write_string(1, "second").expect("write");
            let wire = writer.finish().expect("finish");
            let decoded =
                OwnedTestMessage::decode_from_bytes(wire.as_ref(), limits).expect("decode");
            assert_eq!(decoded.name, "second", "scalar merge is last-one-wins");

            // Two records for the same nested-message field: they merge field
            // by field rather than the second replacing the first wholesale.
            let part_one = OwnedTestMessage {
                name: "only-name".to_string(),
                value: 0,
            }
            .encode_to_bytes(limits)
            .expect("encode part one");
            let part_two = OwnedTestMessage {
                name: String::new(),
                value: 99,
            }
            .encode_to_bytes(limits)
            .expect("encode part two");

            let mut writer = ProtobufWireEncoder::new(limits);
            writer.write_message(1, part_one.as_ref()).expect("write");
            writer.write_message(1, part_two.as_ref()).expect("write");
            let wire = writer.finish().expect("finish");

            let outer = OwnedOuter::decode_from_bytes(wire.as_ref(), limits).expect("decode");
            assert_eq!(
                outer.inner,
                Some(OwnedTestMessage {
                    name: "only-name".to_string(),
                    value: 99,
                }),
                "a repeated nested message merges recursively"
            );
            crate::test_complete!(
                "scalar_merge_is_last_one_wins_and_nested_message_merge_is_recursive"
            );
        }

        #[test]
        fn nested_descent_is_charged_against_the_shared_budget() {
            init_test("nested_descent_is_charged_against_the_shared_budget");

            let outer = OwnedOuter {
                inner: Some(sample()),
                items: vec!["a".to_string(), "b".to_string()],
                unknown: UnknownFields::new(),
            };
            let wire = outer
                .encode_to_bytes(ProtobufWireLimits::default())
                .expect("encode");

            // Three top-level records (one nested message + two strings) plus
            // two records inside the nested message: five in aggregate.
            let generous = ProtobufWireLimits::default().with_max_fields(5);
            assert!(
                OwnedOuter::decode_from_bytes(wire.as_ref(), generous).is_ok(),
                "five records must fit a five-record budget"
            );

            // If nested descent started a fresh budget instead of sharing the
            // parent's, this would also succeed — and a hostile peer could
            // amplify work per nesting level for free.
            let tight = ProtobufWireLimits::default().with_max_fields(3);
            assert!(
                OwnedOuter::decode_from_bytes(wire.as_ref(), tight).is_err(),
                "nested fields must count against the parent's aggregate budget"
            );
            crate::test_complete!("nested_descent_is_charged_against_the_shared_budget");
        }

        #[test]
        fn nested_descent_respects_the_depth_ceiling() {
            init_test("nested_descent_respects_the_depth_ceiling");

            let outer = OwnedOuter {
                inner: Some(sample()),
                items: Vec::new(),
                unknown: UnknownFields::new(),
            };
            let wire = outer
                .encode_to_bytes(ProtobufWireLimits::default())
                .expect("encode");

            let no_descent = ProtobufWireLimits::default().with_max_depth(0);
            assert!(
                matches!(
                    OwnedOuter::decode_from_bytes(wire.as_ref(), no_descent),
                    Err(ProtobufWireError::RecursionLimitExceeded { .. })
                ),
                "descending past the depth ceiling must fail closed"
            );
            crate::test_complete!("nested_descent_respects_the_depth_ceiling");
        }

        #[test]
        fn symmetric_alias_default_and_clone_preserve_configuration() {
            init_test("symmetric_alias_default_and_clone_preserve_configuration");

            let configured: SymmetricProtoCodec<OwnedTestMessage> =
                SymmetricProtoCodec::with_max_size(1024);
            let cloned = configured.clone();
            assert_eq!(cloned.max_encode_message_size(), 1024);
            assert_eq!(cloned.max_decode_message_size(), 1024);
            assert_eq!(cloned.wire_limits().max_message_len, 1024);

            let defaulted: SymmetricProtoCodec<OwnedTestMessage> = SymmetricProtoCodec::default();
            assert_eq!(
                defaulted.max_encode_message_size(),
                DEFAULT_MAX_MESSAGE_SIZE
            );

            let mut symmetric: SymmetricProtoCodec<OwnedTestMessage> = SymmetricProtoCodec::new();
            let encoded = symmetric.encode(&sample()).expect("encode");
            assert_eq!(symmetric.decode(&encoded).expect("decode"), sample());
            crate::test_complete!("symmetric_alias_default_and_clone_preserve_configuration");
        }

        #[test]
        fn codec_is_send_and_static_for_streaming_call_sites() {
            init_test("codec_is_send_and_static_for_streaming_call_sites");

            // The gRPC streaming paths require `Codec: Send + 'static`. Pin it
            // here so a future field cannot quietly regress the bound and only
            // fail at a distant call site.
            fn assert_codec<C: Codec + Send + 'static>() {}
            assert_codec::<ProtoCodec<OwnedTestMessage, OwnedOuterDropping>>();
            assert_codec::<SymmetricProtoCodec<OwnedTestMessage>>();
            crate::test_complete!("codec_is_send_and_static_for_streaming_call_sites");
        }
    }
