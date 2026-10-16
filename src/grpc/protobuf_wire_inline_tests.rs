    use std::collections::BTreeMap;

    use proptest::prelude::*;
    use prost::Message;

    use super::*;

    const EXACT_RCH_COMMAND: &str = "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_protobuf_wire_a1 cargo test -p asupersync --lib protobuf_wire -- --nocapture";

    #[derive(Clone, PartialEq, prost::Message)]
    struct ScalarModel {
        #[prost(double, tag = "1")]
        double_value: f64,
        #[prost(float, tag = "2")]
        float_value: f32,
        #[prost(int32, tag = "3")]
        int32_value: i32,
        #[prost(int64, tag = "4")]
        int64_value: i64,
        #[prost(uint32, tag = "5")]
        uint32_value: u32,
        #[prost(uint64, tag = "6")]
        uint64_value: u64,
        #[prost(sint32, tag = "7")]
        sint32_value: i32,
        #[prost(sint64, tag = "8")]
        sint64_value: i64,
        #[prost(fixed32, tag = "9")]
        fixed32_value: u32,
        #[prost(fixed64, tag = "10")]
        fixed64_value: u64,
        #[prost(sfixed32, tag = "11")]
        sfixed32_value: i32,
        #[prost(sfixed64, tag = "12")]
        sfixed64_value: i64,
        #[prost(bool, tag = "13")]
        bool_value: bool,
        #[prost(string, tag = "14")]
        string_value: String,
        #[prost(bytes = "vec", tag = "15")]
        bytes_value: Vec<u8>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    struct Child {
        #[prost(string, tag = "1")]
        name: String,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
    enum Color {
        Unspecified = 0,
        Green = 7,
    }

    #[derive(Clone, PartialEq, prost::Oneof)]
    enum Choice {
        #[prost(string, tag = "4")]
        Text(String),
        #[prost(uint64, tag = "5")]
        Number(u64),
    }

    #[derive(Clone, PartialEq, prost::Message)]
    struct CompositeModel {
        #[prost(sint64, repeated, packed = "true", tag = "1")]
        numbers: Vec<i64>,
        #[prost(message, repeated, tag = "2")]
        children: Vec<Child>,
        #[prost(btree_map = "string, uint32", tag = "3")]
        labels: BTreeMap<String, u32>,
        #[prost(oneof = "Choice", tags = "4, 5")]
        choice: Option<Choice>,
        #[prost(enumeration = "Color", tag = "6")]
        color: i32,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    struct PackedDoubleModel {
        #[prost(double, repeated, packed = "true", tag = "3")]
        values: Vec<f64>,
    }

    fn generous_limits(size: usize) -> ProtobufWireLimits {
        ProtobufWireLimits::for_message_size(size.max(1))
            .with_max_fields(1_024)
            .with_max_work(size.max(1).saturating_mul(16))
    }

    #[test]
    fn protobuf_wire_official_vectors_br_asupersync_5z2scg_1_1() {
        let limits = generous_limits(64);
        let input = [0x08, 0x96, 0x01];
        let mut message = ProtobufWireMessage::new(&input, limits).unwrap();
        let mut decoder = message.decoder();
        let field = decoder.next_field().unwrap().unwrap();
        assert_eq!(field.field_number(), 1);
        assert_eq!(field.as_varint().unwrap(), 150);
        assert!(decoder.next_field().unwrap().is_none());

        let mut encoder = ProtobufWireEncoder::new(limits);
        encoder.write_varint(1, 150).unwrap();
        assert_eq!(encoder.finish().unwrap().as_ref(), input);

        assert_eq!(zigzag_encode_i32(-500), 999);
        assert_eq!(zigzag_decode_i32(999), -500);
        assert_eq!(zigzag_decode_i64(zigzag_encode_i64(i64::MIN)), i64::MIN);
        eprintln!(
            "bead=asupersync-5z2scg.1.1 scenario=official-encoding-vectors fixture=protobuf.dev/encoding seed=none command=\"{EXACT_RCH_COMMAND}\" artifact=none expected=exact-wire-match"
        );
    }

    #[test]
    fn protobuf_wire_exhaustive_small_varints_br_asupersync_5z2scg_1_1() {
        for value in 0u64..=u64::from(u16::MAX) {
            let mut encoder = ProtobufWireEncoder::with_max_size(16);
            encoder.write_varint(1, value).unwrap();
            let bytes = encoder.finish().unwrap();
            let (decoded, consumed) = decode_varint(&bytes[1..]).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(consumed, encoded_varint_len(value));
        }
        assert_eq!(decode_varint(&[0x81, 0x00]).unwrap(), (1, 2));
        assert!(matches!(
            decode_varint(&[0xff; 10]),
            Err(ProtobufWireError::VarintOverflow { offset: 0 })
        ));
        let mut tenth_payload_overflow = [0xff; 10];
        tenth_payload_overflow[9] = 0x02;
        assert!(matches!(
            decode_varint(&tenth_payload_overflow),
            Err(ProtobufWireError::VarintOverflow { offset: 0 })
        ));
        eprintln!(
            "bead=asupersync-5z2scg.1.1 scenario=exhaustive-small-varints fixture=0..=u16::MAX seed=none command=\"{EXACT_RCH_COMMAND}\" artifact=none expected=roundtrip-and-malformed-rejection"
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn protobuf_wire_varint_property_br_asupersync_5z2scg_1_1(values in prop::collection::vec(any::<u64>(), 0..64)) {
            let limits = generous_limits(values.len().saturating_mul(12).saturating_add(1));
            let mut encoder = ProtobufWireEncoder::new(limits);
            for &value in &values {
                encoder.write_varint(1, value).unwrap();
            }
            let bytes = encoder.finish().unwrap();
            let mut message = ProtobufWireMessage::new(&bytes, limits).unwrap();
            let mut decoder = message.decoder();
            let mut decoded = Vec::new();
            while let Some(field) = decoder.next_field().unwrap() {
                decoded.push(field.as_varint().unwrap());
            }
            prop_assert_eq!(decoded, values);
        }

        #[test]
        fn protobuf_wire_arbitrary_input_terminates_br_asupersync_5z2scg_1_1(
            wire in prop::collection::vec(any::<u8>(), 0..256)
        ) {
            let limits = ProtobufWireLimits::for_message_size(256)
                .with_max_fields(256)
                .with_max_depth(32)
                .with_max_work(1_024);
            let mut message = ProtobufWireMessage::new(&wire, limits).unwrap();
            let mut decoder = message.decoder();
            let mut steps = 0usize;
            // `Ok(None)` (clean end) and `Err(_)` (bounded refusal) both mean
            // "stop"; the property under test is only that the loop terminates
            // in at most `wire.len()` steps, so both exits are equivalent here.
            while let Ok(Some(_)) = decoder.next_field() {
                steps += 1;
                prop_assert!(steps <= wire.len());
            }
        }
    }

    #[test]
    fn protobuf_wire_scalar_prost_cross_impl_br_asupersync_5z2scg_1_1() {
        let expected = ScalarModel {
            double_value: 1.25,
            float_value: -2.5,
            int32_value: -3,
            int64_value: -4,
            uint32_value: 5,
            uint64_value: u64::MAX,
            sint32_value: -6,
            sint64_value: i64::MIN,
            fixed32_value: 7,
            fixed64_value: 8,
            sfixed32_value: -9,
            sfixed64_value: -10,
            bool_value: true,
            string_value: "wire".to_owned(),
            bytes_value: vec![0, 1, 0xff],
        };
        let limits = generous_limits(512);
        let mut encoder = ProtobufWireEncoder::new(limits);
        encoder.write_double(1, expected.double_value).unwrap();
        encoder.write_float(2, expected.float_value).unwrap();
        encoder.write_int32(3, expected.int32_value).unwrap();
        encoder.write_int64(4, expected.int64_value).unwrap();
        encoder
            .write_varint(5, u64::from(expected.uint32_value))
            .unwrap();
        encoder.write_varint(6, expected.uint64_value).unwrap();
        encoder.write_sint32(7, expected.sint32_value).unwrap();
        encoder.write_sint64(8, expected.sint64_value).unwrap();
        encoder.write_fixed32(9, expected.fixed32_value).unwrap();
        encoder.write_fixed64(10, expected.fixed64_value).unwrap();
        encoder
            .write_fixed32(11, expected.sfixed32_value as u32)
            .unwrap();
        encoder
            .write_fixed64(12, expected.sfixed64_value as u64)
            .unwrap();
        encoder.write_bool(13, expected.bool_value).unwrap();
        encoder.write_string(14, &expected.string_value).unwrap();
        encoder.write_bytes(15, &expected.bytes_value).unwrap();
        let wire = encoder.finish().unwrap();

        assert_eq!(ScalarModel::decode(wire.as_ref()).unwrap(), expected);

        let prost_wire = expected.encode_to_vec();
        let mut message = ProtobufWireMessage::new(&prost_wire, limits).unwrap();
        let mut decoder = message.decoder();
        let mut fields = Vec::new();
        while let Some(field) = decoder.next_field().unwrap() {
            if field.field_number() == 14 {
                assert_eq!(field.as_str().unwrap(), "wire");
            }
            fields.push((field.field_number(), field.wire_type()));
        }
        assert_eq!(fields.len(), 15);
        assert_eq!(fields[0], (1, WireType::Fixed64));
        assert_eq!(fields[14], (15, WireType::LengthDelimited));
        eprintln!(
            "bead=asupersync-5z2scg.1.1 scenario=scalar-cross-implementation fixture=workspace-prost seed=none command=\"{EXACT_RCH_COMMAND}\" artifact=none expected=bidirectional-wire-compatibility"
        );
    }

    #[test]
    fn protobuf_wire_composite_model_cross_impl_br_asupersync_5z2scg_1_1() {
        let limits = generous_limits(1_024);
        let numbers = [-2, 0, 9, i64::MAX];
        let mut encoder = ProtobufWireEncoder::new(limits);
        let packed = numbers.map(zigzag_encode_i64);
        encoder.write_packed_varints(1, &packed).unwrap();

        for name in ["alpha", "beta"] {
            let mut child = ProtobufWireEncoder::new(limits);
            child.write_string(1, name).unwrap();
            encoder.write_message(2, &child.finish().unwrap()).unwrap();
        }

        for (key, value) in [("a", 1), ("z", 26)] {
            let mut entry = ProtobufWireEncoder::new(limits);
            entry.write_string(1, key).unwrap();
            entry.write_varint(2, value).unwrap();
            encoder.write_message(3, &entry.finish().unwrap()).unwrap();
        }
        encoder.write_string(4, "selected").unwrap();
        encoder.write_enum(6, Color::Green as i32).unwrap();
        let wire = encoder.finish().unwrap();

        let decoded = CompositeModel::decode(wire.as_ref()).unwrap();
        assert_eq!(decoded.numbers, numbers);
        assert_eq!(
            decoded.children,
            vec![
                Child {
                    name: "alpha".to_owned()
                },
                Child {
                    name: "beta".to_owned()
                }
            ]
        );
        assert_eq!(decoded.labels["a"], 1);
        assert_eq!(decoded.labels["z"], 26);
        assert_eq!(decoded.choice, Some(Choice::Text("selected".to_owned())));
        assert_eq!(decoded.color, Color::Green as i32);

        let prost_wire = decoded.encode_to_vec();
        let mut message = ProtobufWireMessage::new(&prost_wire, limits).unwrap();
        let mut decoder = message.decoder();
        let mut child_count = 0;
        while let Some(field) = decoder.next_field().unwrap() {
            if field.field_number() == 2 {
                let mut child_decoder = decoder.nested_message(&field).unwrap();
                let child_name = child_decoder.next_field().unwrap().unwrap();
                assert!(!child_name.as_str().unwrap().is_empty());
                assert!(child_decoder.next_field().unwrap().is_none());
                child_count += 1;
            }
        }
        assert_eq!(child_count, 2);
        eprintln!(
            "bead=asupersync-5z2scg.1.1 scenario=packed-repeated-map-oneof-enum-nested fixture=workspace-prost seed=none command=\"{EXACT_RCH_COMMAND}\" artifact=none expected=full-accepted-data-model"
        );
    }

    #[test]
    fn packed_doubles_match_prost_bytes_without_projection_storage() {
        let values = [1.25, -0.0, f64::from_bits(0x7ff8_0000_0000_0042)];
        let mut encoder = ProtobufWireEncoder::new(generous_limits(64));
        encoder.write_packed_doubles(3, &values).unwrap();
        let wire = encoder.finish().unwrap();

        let expected = [
            0x1a, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf4, 0x3f, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x80, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x7f,
        ];
        assert_eq!(wire.as_ref(), expected);
        assert_eq!(
            wire.as_ref(),
            PackedDoubleModel {
                values: values.to_vec(),
            }
            .encode_to_vec()
        );
    }

    #[test]
    fn packed_doubles_preserve_explicit_empty_record_behavior() {
        let mut encoder = ProtobufWireEncoder::new(generous_limits(16));
        encoder.write_packed_doubles(3, &[]).unwrap();

        assert_eq!(encoder.as_bytes(), [0x1a, 0x00]);
        assert_eq!(encoder.fields_written(), 1);
        assert_eq!(encoder.work_used(), 2);
    }

    #[test]
    fn packed_doubles_reject_limits_without_changing_encoder_state() {
        let limits = generous_limits(64).with_max_field_len(7);
        let mut encoder = ProtobufWireEncoder::new(limits);
        encoder.write_varint(9, 1).unwrap();
        let original = encoder.as_bytes().to_vec();
        let original_fields = encoder.fields_written();
        let original_work = encoder.work_used();

        assert!(matches!(
            encoder.write_packed_doubles(3, &[1.0]),
            Err(ProtobufWireError::FieldLimitExceeded {
                length: 8,
                limit: 7,
                ..
            })
        ));
        assert_eq!(encoder.as_bytes(), original);
        assert_eq!(encoder.fields_written(), original_fields);
        assert_eq!(encoder.work_used(), original_work);
    }

    #[test]
    fn protobuf_wire_unknown_and_group_preservation_br_asupersync_5z2scg_1_1() {
        let limits = generous_limits(128);
        let raw = [0x2b, 0x08, 0x96, 0x01, 0x33, 0x0d, 1, 2, 3, 4, 0x34, 0x2c];
        let mut message = ProtobufWireMessage::new(&raw, limits).unwrap();
        let mut decoder = message.decoder();
        let start = decoder.next_field().unwrap().unwrap();
        assert_eq!(start.wire_type(), WireType::StartGroup);
        let preserved = decoder.skip_group(&start).unwrap();
        assert_eq!(preserved, raw);
        assert!(decoder.next_field().unwrap().is_none());

        let mut encoder = ProtobufWireEncoder::new(limits);
        encoder.write_raw_fields(preserved).unwrap();
        assert_eq!(encoder.finish().unwrap().as_ref(), raw);

        let mismatched = [0x2b, 0x34];
        let mut message = ProtobufWireMessage::new(&mismatched, limits).unwrap();
        let mut decoder = message.decoder();
        decoder.next_field().unwrap().unwrap();
        assert!(matches!(
            decoder.next_field(),
            Err(ProtobufWireError::MismatchedEndGroup {
                expected: 5,
                actual: 6,
                ..
            })
        ));
        eprintln!(
            "bead=asupersync-5z2scg.1.1 scenario=unknown-group-preservation fixture=hand-encoded-nested-group seed=none command=\"{EXACT_RCH_COMMAND}\" artifact=none expected=exact-preservation-and-mismatch-rejection"
        );
    }

    #[test]
    fn protobuf_wire_resource_limits_fail_closed_br_asupersync_5z2scg_1_1() {
        let message_error =
            ProtobufWireMessage::new(&[0; 5], ProtobufWireLimits::for_message_size(4)).unwrap_err();
        assert!(matches!(
            message_error,
            ProtobufWireError::MessageLimitExceeded {
                length: 5,
                limit: 4
            }
        ));

        let field_limits = ProtobufWireLimits::for_message_size(16).with_max_field_len(2);
        let mut message = ProtobufWireMessage::new(&[0x0a, 0x03, 1, 2, 3], field_limits).unwrap();
        assert!(matches!(
            message.decoder().next_field(),
            Err(ProtobufWireError::FieldLimitExceeded {
                length: 3,
                limit: 2,
                ..
            })
        ));

        let count_limits = generous_limits(16).with_max_fields(1);
        let mut message =
            ProtobufWireMessage::new(&[0x08, 0x01, 0x10, 0x02], count_limits).unwrap();
        let mut decoder = message.decoder();
        decoder.next_field().unwrap();
        assert!(matches!(
            decoder.next_field(),
            Err(ProtobufWireError::FieldCountExceeded {
                count: 2,
                limit: 1,
                ..
            })
        ));

        let work_limits = generous_limits(16).with_max_work(1);
        let mut message = ProtobufWireMessage::new(&[0x08, 0x01], work_limits).unwrap();
        assert!(matches!(
            message.decoder().next_field(),
            Err(ProtobufWireError::WorkLimitExceeded {
                work: 2,
                limit: 1,
                ..
            })
        ));

        let depth_limits = generous_limits(16).with_max_depth(1);
        let nested_wire = [0x0a, 0x02, 0x0a, 0x00];
        let mut message = ProtobufWireMessage::new(&nested_wire, depth_limits).unwrap();
        let mut root = message.decoder();
        let outer = root.next_field().unwrap().unwrap();
        let mut level_one = root.nested_message(&outer).unwrap();
        let inner = level_one.next_field().unwrap().unwrap();
        assert!(matches!(
            level_one.nested_message(&inner),
            Err(ProtobufWireError::RecursionLimitExceeded {
                depth: 2,
                limit: 1,
                ..
            })
        ));

        let group_wire = [0x0b, 0x13, 0x14, 0x0c];
        let mut message = ProtobufWireMessage::new(&group_wire, depth_limits).unwrap();
        let mut decoder = message.decoder();
        decoder.next_field().unwrap().unwrap();
        assert!(matches!(
            decoder.next_field(),
            Err(ProtobufWireError::RecursionLimitExceeded {
                depth: 2,
                limit: 1,
                ..
            })
        ));

        let mut encoder =
            ProtobufWireEncoder::new(generous_limits(16).with_max_fields(1).with_max_work(1));
        assert!(matches!(
            encoder.write_varint(1, 1),
            Err(ProtobufWireError::WorkLimitExceeded {
                work: 2,
                limit: 1,
                ..
            })
        ));
        assert!(encoder.is_empty());
        eprintln!(
            "bead=asupersync-5z2scg.1.1 scenario=resource-limit-matrix fixture=message-field-count-work-depth-boundaries seed=none command=\"{EXACT_RCH_COMMAND}\" artifact=none expected=reject-before-allocation"
        );
    }

    #[test]
    fn protobuf_wire_malformed_matrix_br_asupersync_5z2scg_1_1() {
        let limits = generous_limits(64);
        let cases: &[(&[u8], fn(&ProtobufWireError) -> bool)] = &[
            (&[0x00], |error| {
                matches!(
                    error,
                    ProtobufWireError::InvalidFieldNumber {
                        field_number: 0,
                        ..
                    }
                )
            }),
            (&[0x0f], |error| {
                matches!(
                    error,
                    ProtobufWireError::InvalidWireType { wire_type: 7, .. }
                )
            }),
            (&[0x0d, 1, 2], |error| {
                matches!(error, ProtobufWireError::UnexpectedEof { needed: 4, .. })
            }),
            (&[0x0a, 0x02, 1], |error| {
                matches!(
                    error,
                    ProtobufWireError::UnexpectedEof {
                        needed: 2,
                        remaining: 1,
                        ..
                    }
                )
            }),
            (&[0x0b], |error| {
                matches!(
                    error,
                    ProtobufWireError::UnterminatedGroup {
                        field_number: 1,
                        ..
                    }
                )
            }),
        ];
        for (wire, predicate) in cases {
            let mut message = ProtobufWireMessage::new(wire, limits).unwrap();
            let mut decoder = message.decoder();
            let error = loop {
                match decoder.next_field() {
                    Ok(Some(_)) => {}
                    Ok(None) => panic!("malformed case was accepted"),
                    Err(error) => break error,
                }
            };
            assert!(predicate(&error), "unexpected error: {error:?}");
        }

        let invalid_utf8 = [0x0a, 0x01, 0xff];
        let mut message = ProtobufWireMessage::new(&invalid_utf8, limits).unwrap();
        let field = message.decoder().next_field().unwrap().unwrap();
        assert!(matches!(
            field.as_str(),
            Err(ProtobufWireError::InvalidUtf8 { offset: 2 })
        ));
        eprintln!(
            "bead=asupersync-5z2scg.1.1 scenario=malformed-wire-matrix fixture=zero-key-reserved-wire-truncation-group-utf8 seed=none command=\"{EXACT_RCH_COMMAND}\" artifact=none expected=stable-typed-errors-no-panic"
        );
    }

    #[test]
    fn protobuf_wire_deterministic_ordered_operations_br_asupersync_5z2scg_1_1() {
        fn encode() -> Bytes {
            let limits = generous_limits(128);
            let mut encoder = ProtobufWireEncoder::new(limits);
            encoder.write_varint(9, 1).unwrap();
            encoder.write_varint(2, 3).unwrap();
            encoder.write_varint(2, 5).unwrap();
            encoder.write_string(7, "same").unwrap();
            encoder.finish().unwrap()
        }
        assert_eq!(encode(), encode());
        assert_eq!(encode(), encode());
        eprintln!(
            "bead=asupersync-5z2scg.1.1 scenario=deterministic-ordered-operation-stream fixture=noncanonical-field-order seed=none command=\"{EXACT_RCH_COMMAND}\" artifact=none expected=byte-identical-not-canonical"
        );
    }

    #[test]
    fn protobuf_wire_field_key_boundaries_br_asupersync_5z2scg_1_1() {
        let limits = generous_limits(64);
        let mut encoder = ProtobufWireEncoder::new(limits);
        encoder.write_varint(MAX_PROTOBUF_FIELD_NUMBER, 1).unwrap();
        let wire = encoder.finish().unwrap();
        let mut message = ProtobufWireMessage::new(&wire, limits).unwrap();
        let field = message.decoder().next_field().unwrap().unwrap();
        assert_eq!(field.field_number(), MAX_PROTOBUF_FIELD_NUMBER);

        let mut encoder = ProtobufWireEncoder::new(limits);
        assert!(matches!(
            encoder.write_varint(0, 1),
            Err(ProtobufWireError::InvalidFieldNumber {
                field_number: 0,
                ..
            })
        ));
        assert!(matches!(
            encoder.write_varint(MAX_PROTOBUF_FIELD_NUMBER + 1, 1),
            Err(ProtobufWireError::InvalidFieldNumber { .. })
        ));
        assert!(encoder.is_empty());
        eprintln!(
            "bead=asupersync-5z2scg.1.1 scenario=field-key-boundaries fixture=zero-and-29-bit-maximum seed=none command=\"{EXACT_RCH_COMMAND}\" artifact=none expected=max-accepted-neighbors-rejected"
        );
    }

    #[test]
    fn nested_encoder_rolls_back_groups_and_rejects_cross_boundary_close() {
        let limits = generous_limits(128);
        let mut encoder = ProtobufWireEncoder::new(limits);
        encoder.write_varint(9, 1).unwrap();
        let original = encoder.as_bytes().to_vec();
        let original_fields = encoder.fields_written();
        let original_work = encoder.work_used();

        let error = encoder
            .write_nested_message(1, |nested| {
                nested.start_group(2)?;
                Err(ProtobufWireError::SchemaInvariant {
                    offset: nested.len(),
                    invariant: "nested rollback fixture",
                })
            })
            .unwrap_err();
        assert!(matches!(error, ProtobufWireError::SchemaInvariant { .. }));
        assert_eq!(encoder.as_bytes(), original);
        assert_eq!(encoder.fields_written(), original_fields);
        assert_eq!(encoder.work_used(), original_work);

        let mut unclosed = ProtobufWireEncoder::new(limits);
        assert!(matches!(
            unclosed.write_nested_message(1, |nested| nested.start_group(2)),
            Err(ProtobufWireError::EncoderGroupMismatch { .. })
        ));
        assert!(unclosed.is_empty());

        let mut outer = ProtobufWireEncoder::new(limits);
        outer.start_group(2).unwrap();
        let outer_prefix = outer.as_bytes().to_vec();
        assert!(matches!(
            outer.write_nested_message(1, |nested| nested.end_group(2)),
            Err(ProtobufWireError::EncoderGroupMismatch { .. })
        ));
        assert_eq!(outer.as_bytes(), outer_prefix);
        outer.end_group(2).unwrap();
        assert_eq!(outer.finish().unwrap().as_ref(), [0x13, 0x14].as_slice());
    }

    #[test]
    fn nested_encoder_combines_message_group_depth_and_charges_prefix_shift_work() {
        let depth_one = generous_limits(128).with_max_depth(1);
        let mut nested_then_group = ProtobufWireEncoder::new(depth_one);
        assert!(matches!(
            nested_then_group.write_nested_message(1, |nested| nested.start_group(2)),
            Err(ProtobufWireError::RecursionLimitExceeded { depth: 2, .. })
        ));
        assert!(nested_then_group.is_empty());

        let mut group_then_nested = ProtobufWireEncoder::new(depth_one);
        group_then_nested.start_group(1).unwrap();
        assert!(matches!(
            group_then_nested.write_nested_message(2, |_| Ok(())),
            Err(ProtobufWireError::RecursionLimitExceeded { depth: 2, .. })
        ));
        assert!(matches!(
            group_then_nested.write_raw_fields(&[0x1b, 0x1c]),
            Err(ProtobufWireError::RecursionLimitExceeded { .. })
        ));
        group_then_nested.end_group(1).unwrap();

        let work_limited = generous_limits(128).with_max_work(50);
        let mut encoder = ProtobufWireEncoder::new(work_limited);
        encoder
            .write_nested_message(1, |nested| nested.write_bytes(1, &[7; 20]))
            .unwrap();
        assert_eq!(encoder.len(), 24);
        assert_eq!(encoder.work_used(), 46);
        let snapshot = encoder.as_bytes().to_vec();
        assert!(matches!(
            encoder.write_bytes(2, &[8; 4]),
            Err(ProtobufWireError::WorkLimitExceeded { work: 52, .. })
        ));
        assert_eq!(encoder.as_bytes(), snapshot);
        assert_eq!(encoder.work_used(), 46);
    }

    #[test]
    fn preflight_and_counter_overflow_remain_fail_closed_at_maximum_limits() {
        let maximum = ProtobufWireLimits {
            max_message_len: 128,
            max_field_len: 128,
            max_fields: usize::MAX,
            max_depth: usize::MAX,
            max_work: usize::MAX,
        };

        let mut field_overflow = ProtobufWireEncoder::new(maximum);
        field_overflow.fields_written = usize::MAX;
        assert!(matches!(
            field_overflow.write_varint(1, 1),
            Err(ProtobufWireError::FieldCountExceeded {
                count: usize::MAX,
                limit: usize::MAX,
                ..
            })
        ));
        assert!(field_overflow.is_empty());

        let mut work_overflow = ProtobufWireEncoder::new(maximum);
        work_overflow.work_used = usize::MAX;
        assert!(matches!(
            work_overflow.write_varint(1, 1),
            Err(ProtobufWireError::WorkLimitExceeded {
                work: usize::MAX,
                limit: usize::MAX,
                ..
            })
        ));
        assert!(work_overflow.is_empty());

        let mut field_message = ProtobufWireMessage::new(&[0x08, 0x01], maximum).unwrap();
        field_message.state.fields_seen = usize::MAX;
        assert!(matches!(
            field_message.decoder().next_field(),
            Err(ProtobufWireError::FieldCountExceeded {
                count: usize::MAX,
                limit: usize::MAX,
                ..
            })
        ));

        let mut work_message = ProtobufWireMessage::new(&[0x08, 0x01], maximum).unwrap();
        work_message.state.work_used = usize::MAX;
        assert!(matches!(
            work_message.decoder().next_field(),
            Err(ProtobufWireError::WorkLimitExceeded {
                work: usize::MAX,
                limit: usize::MAX,
                ..
            })
        ));

        let mut semantic_message = ProtobufWireMessage::new(&[], maximum).unwrap();
        semantic_message.state.semantic_owned_bytes = usize::MAX;
        assert!(matches!(
            semantic_message
                .decoder()
                .charge_semantic_owned_bytes(1, usize::MAX, 0),
            Err(ProtobufWireError::SchemaLimitExceeded {
                observed: usize::MAX,
                limit: usize::MAX,
                ..
            })
        ));

        let no_fields = maximum.with_max_fields(0);
        let mut nested = ProtobufWireEncoder::new(no_fields);
        assert!(matches!(
            nested.write_nested_message(1, |_| Ok(())),
            Err(ProtobufWireError::FieldCountExceeded {
                count: 1,
                limit: 0,
                ..
            })
        ));
        assert_eq!(nested.nested_messages.capacity(), 0);

        let mut group = ProtobufWireEncoder::new(no_fields);
        assert!(matches!(
            group.start_group(1),
            Err(ProtobufWireError::FieldCountExceeded {
                count: 1,
                limit: 0,
                ..
            })
        ));
        assert_eq!(group.groups.capacity(), 0);
    }
