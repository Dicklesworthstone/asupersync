    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::transport::error::StreamError;
    use proptest::prelude::*;
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    struct Demo {
        id: u64,
        name: String,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct EmptyStruct;

    #[derive(Debug, PartialEq, Eq)]
    struct CustomValue {
        id: u32,
        name: String,
    }

    #[derive(Debug, Clone, Copy)]
    struct CustomValueCodec;

    impl Serializer<CustomValue> for CustomValueCodec {
        fn serialize(
            &self,
            value: &CustomValue,
            format: SerializationFormat,
        ) -> Result<Vec<u8>, SerializationError> {
            if format != SerializationFormat::Custom {
                return Err(SerializationError::UnsupportedType {
                    type_name: std::any::type_name::<CustomValue>().to_string(),
                });
            }
            let name_len =
                u32::try_from(value.name.len()).map_err(|_| SerializationError::ValueTooLarge {
                    size: value.name.len(),
                    max: u32::MAX as usize,
                })?;
            let mut bytes = Vec::with_capacity(8 + value.name.len());
            bytes.extend_from_slice(&value.id.to_le_bytes());
            bytes.extend_from_slice(&name_len.to_le_bytes());
            bytes.extend_from_slice(value.name.as_bytes());
            Ok(bytes)
        }
    }

    impl Deserializer<CustomValue> for CustomValueCodec {
        fn deserialize(
            &self,
            bytes: &[u8],
            format: SerializationFormat,
        ) -> Result<CustomValue, DeserializationError> {
            if format != SerializationFormat::Custom || bytes.len() < 8 {
                return Err(DeserializationError::CorruptData);
            }
            let id = u32::from_le_bytes(
                bytes[..4]
                    .try_into()
                    .map_err(|_| DeserializationError::CorruptData)?,
            );
            let name_len = u32::from_le_bytes(
                bytes[4..8]
                    .try_into()
                    .map_err(|_| DeserializationError::CorruptData)?,
            ) as usize;
            if bytes.len() != 8usize.saturating_add(name_len) {
                return Err(DeserializationError::CorruptData);
            }
            let name = std::str::from_utf8(&bytes[8..])
                .map_err(|_| DeserializationError::CorruptData)?
                .to_string();
            Ok(CustomValue { id, name })
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct EmptyCustomValue;

    #[derive(Debug, Clone, Copy)]
    struct EmptyCustomCodec;

    impl Serializer<EmptyCustomValue> for EmptyCustomCodec {
        fn serialize(
            &self,
            _value: &EmptyCustomValue,
            format: SerializationFormat,
        ) -> Result<Vec<u8>, SerializationError> {
            if format == SerializationFormat::Custom {
                Ok(Vec::new())
            } else {
                Err(SerializationError::UnsupportedType {
                    type_name: std::any::type_name::<EmptyCustomValue>().to_string(),
                })
            }
        }
    }

    impl Deserializer<EmptyCustomValue> for EmptyCustomCodec {
        fn deserialize(
            &self,
            bytes: &[u8],
            format: SerializationFormat,
        ) -> Result<EmptyCustomValue, DeserializationError> {
            if format == SerializationFormat::Custom && bytes.is_empty() {
                Ok(EmptyCustomValue)
            } else {
                Err(DeserializationError::CorruptData)
            }
        }
    }

    struct OversizedCustomCodec;

    impl Serializer<CustomValue> for OversizedCustomCodec {
        fn serialize(
            &self,
            _value: &CustomValue,
            _format: SerializationFormat,
        ) -> Result<Vec<u8>, SerializationError> {
            Ok(vec![
                0;
                crate::types::DEFAULT_SYMBOL_SIZE
                    - TYPED_SYMBOL_HEADER_LEN
                    + 1
            ])
        }
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    enum TestEnum {
        Unit,
        Tuple(u32, String),
        Struct { x: i32, y: i32 },
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Nested {
        inner: Box<Option<Self>>,
        value: f64,
    }

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn test_encoding_config() -> EncodingConfig {
        EncodingConfig {
            symbol_size: 64,
            max_block_size: 128,
            repair_overhead: 1.05,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        }
    }

    fn test_decoding_config() -> DecodingConfig {
        DecodingConfig {
            symbol_size: 64,
            max_block_size: 128,
            repair_overhead: 1.05,
            min_overhead: 0,
            max_buffered_symbols: 8192,
            block_timeout: std::time::Duration::from_secs(1),
            verify_auth: false,
        }
    }

    struct ReadyThenPendingStream {
        items: std::vec::IntoIter<AuthenticatedSymbol>,
    }

    impl ReadyThenPendingStream {
        fn new(items: Vec<AuthenticatedSymbol>) -> Self {
            Self {
                items: items.into_iter(),
            }
        }
    }

    impl SymbolStream for ReadyThenPendingStream {
        fn poll_next(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
            self.items
                .next()
                .map_or(Poll::Pending, |item| Poll::Ready(Some(Ok(item))))
        }
    }

    #[test]
    fn typed_symbol_single_roundtrip() {
        let value = Demo {
            id: 7,
            name: "alpha".to_string(),
        };
        let symbol = TypedSymbol::from_value(&value, SerializationFormat::Bincode).expect("symbol");
        let decoded_value = symbol.into_value().expect("decode");
        assert_eq!(value, decoded_value);
    }

    #[test]
    fn typed_symbol_header_v1_has_stable_bytes_for_every_format() {
        let formats = [
            (SerializationFormat::MessagePack, 1),
            (SerializationFormat::Bincode, 2),
            (SerializationFormat::Json, 3),
            (SerializationFormat::Custom, 255),
        ];

        for (format, format_byte) in formats {
            let encoded =
                TypedHeader::new::<Demo>(format, TYPED_SYMBOL_VERSION, 0x0403_0201).encode();
            let expected = [
                0x54,
                0x53,
                0x59,
                0x4d,
                0x01,
                0x00,
                0xd5,
                0x69,
                0x8d,
                0xb3,
                0x03,
                0x72,
                0x7d,
                0xde,
                format_byte,
                0xd9,
                0x3d,
                0x6b,
                0x9c,
                0x7a,
                0xae,
                0xbc,
                0xde,
                0x01,
                0x02,
                0x03,
                0x04,
            ];
            assert_eq!(encoded, expected);
        }
    }

    #[test]
    fn typed_symbol_default_reader_rejects_unknown_version() {
        let value = Demo {
            id: 8,
            name: "versioned".to_string(),
        };
        let symbol = TypedSymbol::from_value_with_version(
            &value,
            SerializationFormat::Bincode,
            TYPED_SYMBOL_VERSION + 1,
        )
        .expect("versioned symbol");

        assert!(matches!(
            TypedSymbol::<Demo>::try_from_symbol(symbol.clone().into_symbol()),
            Err(TypeMismatchError::VersionMismatch {
                expected: TYPED_SYMBOL_VERSION,
                actual: 2,
            })
        ));

        let decoded = TypedSymbol::<Demo>::try_from_symbol_with_version(
            symbol.into_symbol(),
            TYPED_SYMBOL_VERSION + 1,
        )
        .expect("explicit version")
        .into_value()
        .expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn a7_legacy_admission_requires_every_provenance_field() {
        let value = Demo {
            id: 81,
            name: "legacy-provenance".to_string(),
        };
        let symbol = TypedSymbol::from_value_with_version(&value, SerializationFormat::Bincode, 7)
            .expect("versioned symbol");
        let header = symbol.header;
        let identity =
            LegacyTypedSymbolIdentity::new(header.version, header.type_id, header.schema_hash);

        let admitted =
            TypedSymbol::<Demo>::try_from_legacy_symbol(symbol.clone().into_symbol(), identity)
                .expect("trusted identity admits exact header");
        assert_eq!(admitted.value().expect("decode admitted payload"), value);

        assert!(matches!(
            TypedSymbol::<Demo>::try_from_legacy_symbol(
                symbol.clone().into_symbol(),
                LegacyTypedSymbolIdentity::new(
                    identity.version + 1,
                    identity.type_id,
                    identity.schema_hash,
                ),
            ),
            Err(TypeMismatchError::VersionMismatch { .. })
        ));
        assert!(matches!(
            TypedSymbol::<Demo>::try_from_legacy_symbol(
                symbol.clone().into_symbol(),
                LegacyTypedSymbolIdentity::new(
                    identity.version,
                    identity.type_id ^ 1,
                    identity.schema_hash,
                ),
            ),
            Err(TypeMismatchError::UnknownType { .. })
        ));
        assert!(matches!(
            TypedSymbol::<Demo>::try_from_legacy_symbol(
                symbol.into_symbol(),
                LegacyTypedSymbolIdentity::new(
                    identity.version,
                    identity.type_id,
                    identity.schema_hash ^ 1,
                ),
            ),
            Err(TypeMismatchError::SchemaMismatch { .. })
        ));
    }

    #[test]
    fn typed_symbol_detects_schema_mismatch_and_exact_length_corruption() {
        let value = Demo {
            id: 9,
            name: "bounded".to_string(),
        };
        let symbol = TypedSymbol::from_value(&value, SerializationFormat::Bincode).expect("symbol");

        let mut schema_corrupt = symbol.clone().into_symbol();
        schema_corrupt.data_mut()[15] ^= 0x80;
        assert!(matches!(
            TypedSymbol::<Demo>::try_from_symbol(schema_corrupt),
            Err(TypeMismatchError::SchemaMismatch { .. })
        ));

        let truncated = symbol.clone().into_symbol();
        let truncated = Symbol::new(
            truncated.id(),
            truncated.data()[..truncated.data().len() - 1].to_vec(),
            truncated.kind(),
        );
        let truncated = TypedSymbol::<Demo>::try_from_symbol(truncated).expect("valid header");
        assert!(matches!(
            truncated.value(),
            Err(DeserializationError::CorruptData)
        ));

        let trailing = symbol.into_symbol();
        let mut trailing_data = trailing.data().to_vec();
        trailing_data.push(0);
        let trailing = Symbol::new(trailing.id(), trailing_data, trailing.kind());
        let trailing = TypedSymbol::<Demo>::try_from_symbol(trailing).expect("valid header");
        assert!(matches!(
            trailing.value(),
            Err(DeserializationError::CorruptData)
        ));
    }

    #[test]
    fn custom_codec_roundtrips_non_serde_value_in_single_and_multi_symbol_paths() {
        let value = CustomValue {
            id: 17,
            name: "owned-custom-codec".to_string(),
        };
        let symbol = TypedSymbol::from_value_with_serializer(
            &value,
            SerializationFormat::Custom,
            7,
            &CustomValueCodec,
        )
        .expect("custom symbol");
        assert_eq!(symbol.version(), 7);
        assert_eq!(
            symbol
                .value_with_deserializer(&CustomValueCodec)
                .expect("custom decode"),
            value
        );

        let mut encoder = TypedEncoder::with_serializer(
            test_encoding_config(),
            SerializationFormat::Custom,
            CustomValueCodec,
        )
        .with_version(7);
        let symbols = encoder
            .encode(ObjectId::new_for_test(17), &value)
            .expect("custom encode");
        let mut decoder = TypedDecoder::with_deserializer(
            test_decoding_config(),
            SerializationFormat::Custom,
            CustomValueCodec,
        )
        .with_version(7);
        assert_eq!(decoder.decode(symbols).expect("custom decode"), value);
    }

    #[test]
    fn typed_encoder_roundtrips_empty_custom_payload_with_one_bounded_symbol() {
        let mut encoder = TypedEncoder::with_serializer(
            test_encoding_config(),
            SerializationFormat::Custom,
            EmptyCustomCodec,
        );
        let symbols = encoder
            .encode(ObjectId::new_for_test(18), &EmptyCustomValue)
            .expect("empty custom encode");
        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].payload_len(), 0);
        assert_eq!(symbols[0].symbol().data().len(), 64);

        let mut decoder = TypedDecoder::with_deserializer(
            test_decoding_config(),
            SerializationFormat::Custom,
            EmptyCustomCodec,
        );
        assert_eq!(
            decoder.decode(symbols).expect("empty custom decode"),
            EmptyCustomValue
        );
    }

    #[test]
    fn typed_decoder_rejects_corrupt_empty_payload_sentinel() {
        let mut encoder = TypedEncoder::with_serializer(
            test_encoding_config(),
            SerializationFormat::Custom,
            EmptyCustomCodec,
        );
        let mut symbols = encoder
            .encode(ObjectId::new_for_test(181), &EmptyCustomValue)
            .expect("empty custom encode");
        symbols[0].symbol.data_mut()[TYPED_SYMBOL_HEADER_LEN] = 1;

        let mut decoder = TypedDecoder::with_deserializer(
            test_decoding_config(),
            SerializationFormat::Custom,
            EmptyCustomCodec,
        );
        let error = decoder
            .decode(symbols)
            .expect_err("non-zero sentinel padding must be rejected");
        assert!(matches!(
            error,
            DecodingError::InconsistentMetadata { details, .. }
                if details == "empty typed payload sentinel must be zero-filled"
        ));
    }

    #[test]
    fn typed_symbol_rejects_value_above_single_symbol_limit() {
        let value = CustomValue {
            id: 19,
            name: String::new(),
        };
        let result = TypedSymbol::from_value_with_serializer(
            &value,
            SerializationFormat::Custom,
            TYPED_SYMBOL_VERSION,
            &OversizedCustomCodec,
        );
        assert!(matches!(
            result,
            Err(SerializationError::ValueTooLarge {
                size,
                max
            }) if size == max + 1
        ));
    }

    #[test]
    fn typed_encoder_and_decoder_require_the_same_explicit_version() {
        let value = Demo {
            id: 20,
            name: "configured-version".to_string(),
        };
        let mut encoder =
            TypedEncoder::with_config(test_encoding_config(), SerializationFormat::Json)
                .with_version(9);
        let symbols = encoder
            .encode(ObjectId::new_for_test(20), &value)
            .expect("encode");

        let mut default_decoder =
            TypedDecoder::with_config(test_decoding_config(), SerializationFormat::Json);
        let mismatch = default_decoder
            .decode(symbols.clone())
            .expect_err("default reader must reject version 9");
        assert!(
            mismatch.to_string().contains("expected 1, got 9"),
            "{mismatch}"
        );

        let mut decoder =
            TypedDecoder::with_config(test_decoding_config(), SerializationFormat::Json)
                .with_version(9);
        assert_eq!(decoder.decode(symbols).expect("decode"), value);
    }

    #[test]
    fn typed_encoder_decoder_roundtrip() {
        let value = Demo {
            id: 42,
            name: "beta".to_string(),
        };

        let mut encoder = TypedEncoder::with_config(
            EncodingConfig {
                symbol_size: 64,
                max_block_size: 128,
                repair_overhead: 1.05,
                encoding_parallelism: 1,
                decoding_parallelism: 1,
            },
            SerializationFormat::Bincode,
        );

        let object_id = ObjectId::new(1, 2);
        let symbols = encoder.encode(object_id, &value).expect("encode");
        assert!(!symbols.is_empty());

        let mut decoder: TypedDecoder<Demo> = TypedDecoder::with_config(
            DecodingConfig {
                symbol_size: 64,
                max_block_size: 128,
                repair_overhead: 1.05,
                min_overhead: 0,
                max_buffered_symbols: 8192,
                block_timeout: std::time::Duration::from_secs(1),
                verify_auth: false,
            },
            SerializationFormat::Bincode,
        );

        let decoded_value = decoder.decode(symbols).expect("decode");
        assert_eq!(value, decoded_value);
    }

    #[test]
    fn object_params_for_small_payload_uses_actual_single_block_k() {
        let params = object_params_for_payload(ObjectId::new_for_test(7), 8, 37, 512);

        assert_eq!(params.source_blocks, 1);
        assert_eq!(params.symbols_per_block, 1);
    }

    #[test]
    fn object_params_for_payload_preserves_256_block_boundary() {
        let params = object_params_for_payload(ObjectId::new_for_test(8), 256, 1, 1);

        assert_eq!(params.source_blocks, 256);
        assert_eq!(params.symbols_per_block, 1);
    }

    #[test]
    fn object_params_for_payload_uses_max_per_block_k_for_partial_multi_block_payload() {
        let params = object_params_for_payload(ObjectId::new_for_test(9), 13, 4, 6);

        assert_eq!(params.source_blocks, 3);
        assert_eq!(params.symbols_per_block, 2);
        assert_eq!(params.total_source_symbols(), 4);
        assert_eq!(params.min_symbols_for_decode(), 4);
    }

    #[test]
    #[allow(clippy::similar_names)]
    fn typed_decoder_accepts_small_single_block_payload_with_large_max_block_size() {
        let value: u64 = 42;

        let mut encoder = TypedEncoder::with_config(
            EncodingConfig {
                symbol_size: 64,
                max_block_size: 512,
                repair_overhead: 1.05,
                encoding_parallelism: 1,
                decoding_parallelism: 1,
            },
            SerializationFormat::Bincode,
        );

        let mut decoder: TypedDecoder<u64> = TypedDecoder::with_config(
            DecodingConfig {
                symbol_size: 64,
                max_block_size: 512,
                repair_overhead: 1.05,
                min_overhead: 0,
                max_buffered_symbols: 8192,
                block_timeout: std::time::Duration::from_secs(1),
                verify_auth: false,
            },
            SerializationFormat::Bincode,
        );

        let symbols = encoder
            .encode(ObjectId::new_for_test(9), &value)
            .expect("encode");
        let decoded = decoder.decode(symbols).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn typed_decoder_stream_returns_once_object_is_complete_before_eof() {
        let value: u64 = 42;

        let mut encoder = TypedEncoder::with_config(
            EncodingConfig {
                symbol_size: 64,
                max_block_size: 512,
                repair_overhead: 1.05,
                encoding_parallelism: 1,
                decoding_parallelism: 1,
            },
            SerializationFormat::Bincode,
        );

        let mut decoder: TypedDecoder<u64> = TypedDecoder::with_config(
            DecodingConfig {
                symbol_size: 64,
                max_block_size: 512,
                repair_overhead: 1.05,
                min_overhead: 0,
                max_buffered_symbols: 8192,
                block_timeout: std::time::Duration::from_secs(1),
                verify_auth: false,
            },
            SerializationFormat::Bincode,
        );

        let symbols = encoder
            .encode(ObjectId::new_for_test(11), &value)
            .expect("encode");
        assert!(
            !symbols.is_empty(),
            "test requires at least one encoded symbol for the object"
        );

        let auth_symbols = symbols
            .into_iter()
            .map(|symbol| {
                // asupersync-8kumb7: Use new_unauthenticated() for test symbols
                AuthenticatedSymbol::new_unauthenticated(symbol.into_symbol())
            })
            .collect();
        let mut stream = ReadyThenPendingStream::new(auth_symbols);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut future = Box::pin(decoder.decode_from_stream(&mut stream));

        match Future::poll(future.as_mut(), &mut cx) {
            Poll::Ready(Ok(actual)) => assert_eq!(actual, value),
            other => panic!(
                "stream decode should finish once the first object is complete, even if the stream stays open: {other:?}"
            ),
        }
    }

    #[test]
    fn test_roundtrip_primitive_types() {
        // u64
        let val_u64: u64 = 12_345_678_901_234;
        let sym = TypedSymbol::from_value(&val_u64, SerializationFormat::Bincode).unwrap();
        assert_eq!(sym.into_value().unwrap(), val_u64);

        // i32
        let val_int: i32 = -42;
        let sym = TypedSymbol::from_value(&val_int, SerializationFormat::Bincode).unwrap();
        assert_eq!(sym.into_value().unwrap(), val_int);

        // bool
        let val_bool = true;
        let sym = TypedSymbol::from_value(&val_bool, SerializationFormat::Bincode).unwrap();
        assert_eq!(sym.into_value().unwrap(), val_bool);

        // String
        let val_str = "hello world".to_string();
        let sym = TypedSymbol::from_value(&val_str, SerializationFormat::Bincode).unwrap();
        assert_eq!(sym.into_value().unwrap(), val_str);
    }

    #[test]
    fn test_roundtrip_struct() {
        let value = Demo {
            id: 999,
            name: "struct_test".to_string(),
        };
        let symbol = TypedSymbol::from_value(&value, SerializationFormat::Bincode).unwrap();
        assert_eq!(symbol.into_value().unwrap(), value);
    }

    #[test]
    fn test_roundtrip_enum() {
        let variants = [
            TestEnum::Unit,
            TestEnum::Tuple(42, "tuple".to_string()),
            TestEnum::Struct { x: -10, y: 20 },
        ];
        for value in variants {
            let symbol = TypedSymbol::from_value(&value, SerializationFormat::Bincode).unwrap();
            assert_eq!(symbol.into_value().unwrap(), value);
        }
    }

    #[test]
    fn test_roundtrip_vec() {
        let value: Vec<u32> = vec![1, 2, 3, 4, 5];
        let symbol = TypedSymbol::from_value(&value, SerializationFormat::Bincode).unwrap();
        assert_eq!(symbol.into_value().unwrap(), value);

        let value: Vec<Demo> = vec![
            Demo {
                id: 1,
                name: "a".into(),
            },
            Demo {
                id: 2,
                name: "b".into(),
            },
        ];
        let symbol = TypedSymbol::from_value(&value, SerializationFormat::Bincode).unwrap();
        assert_eq!(symbol.into_value().unwrap(), value);
    }

    #[test]
    fn test_roundtrip_hashmap() {
        let mut value: HashMap<String, i32> = HashMap::new();
        value.insert("one".to_string(), 1);
        value.insert("two".to_string(), 2);
        value.insert("negative".to_string(), -100);

        let symbol = TypedSymbol::from_value(&value, SerializationFormat::Bincode).unwrap();
        assert_eq!(symbol.into_value().unwrap(), value);
    }

    #[test]
    fn test_messagepack_format() {
        let value = Demo {
            id: 1,
            name: "msgpack".to_string(),
        };
        let symbol = TypedSymbol::from_value(&value, SerializationFormat::MessagePack).unwrap();
        assert_eq!(symbol.format(), SerializationFormat::MessagePack);
        assert_eq!(symbol.into_value().unwrap(), value);
    }

    #[test]
    fn test_bincode_format() {
        let value = Demo {
            id: 2,
            name: "bincode".to_string(),
        };
        let symbol = TypedSymbol::from_value(&value, SerializationFormat::Bincode).unwrap();
        assert_eq!(symbol.format(), SerializationFormat::Bincode);
        assert_eq!(symbol.into_value().unwrap(), value);
    }

    #[test]
    fn test_json_format() {
        let value = Demo {
            id: 3,
            name: "json".to_string(),
        };
        let symbol = TypedSymbol::from_value(&value, SerializationFormat::Json).unwrap();
        assert_eq!(symbol.format(), SerializationFormat::Json);
        assert_eq!(symbol.into_value().unwrap(), value);
    }

    #[test]
    fn test_type_mismatch_detected() {
        let value: u64 = 42;
        let symbol = TypedSymbol::from_value(&value, SerializationFormat::Bincode).unwrap();
        let raw = symbol.into_symbol();

        // Try to interpret as a different type
        let result = TypedSymbol::<String>::try_from_symbol(raw);
        assert!(result.is_err());
        match result {
            Err(TypeMismatchError::UnknownType { .. }) => {}
            _ => panic!("Expected UnknownType error"),
        }
    }

    #[test]
    fn test_corrupt_header_detected() {
        // Create a symbol with invalid magic bytes
        let mut data = vec![0u8; TYPED_SYMBOL_HEADER_LEN + 10];
        data[0..4].copy_from_slice(b"XXXX"); // Wrong magic

        let symbol = Symbol::new(
            crate::types::SymbolId::new(ObjectId::new(1, 1), 0, 0),
            data,
            SymbolKind::Source,
        );

        let result = TypedSymbol::<u64>::try_from_symbol(symbol);
        assert!(result.is_err());
        match result {
            Err(TypeMismatchError::InvalidMagic) => {}
            _ => panic!("Expected InvalidMagic error"),
        }
    }

    #[test]
    fn test_unsupported_format_byte_is_reported() {
        let value: u64 = 42;
        let symbol = TypedSymbol::from_value(&value, SerializationFormat::Bincode).unwrap();
        let mut raw = symbol.into_symbol();

        // Corrupt the format byte to an unknown value.
        raw.data_mut()[14] = 4;

        let result = TypedSymbol::<u64>::try_from_symbol(raw);
        match result {
            Err(TypeMismatchError::UnsupportedFormatByte { value: 4 }) => {}
            other => panic!("expected UnsupportedFormatByte {{ value: 4 }}, got {other:?}"),
        }
    }

    #[test]
    fn test_type_registration() {
        let mut registry = TypeRegistry::new();

        assert!(!registry.is_registered::<Demo>());
        registry.register::<Demo>("Demo", 1);
        assert!(registry.is_registered::<Demo>());

        let desc = registry.get::<Demo>().unwrap();
        assert_eq!(desc.name, "Demo");
        assert_eq!(desc.version, 1);
    }

    #[test]
    fn test_type_registry_with_capacity_registration() {
        let mut registry = TypeRegistry::with_capacity(1);
        registry.register::<Demo>("Demo", 2);

        let desc = registry.get::<Demo>().unwrap();
        assert_eq!(desc.name, "Demo");
        assert_eq!(desc.version, 2);
    }

    #[test]
    fn test_schema_hash_stability() {
        // Same type and version should produce same hash
        let hash1 = schema_hash::<Demo>(1);
        let hash2 = schema_hash::<Demo>(1);
        assert_eq!(hash1, hash2);

        // Different version should produce different hash
        let hash3 = schema_hash::<Demo>(2);
        assert_ne!(hash1, hash3);

        // Different type should produce different hash
        let hash4 = schema_hash::<EmptyStruct>(1);
        assert_ne!(hash1, hash4);
    }

    #[test]
    fn test_empty_struct() {
        let value = EmptyStruct;
        let symbol = TypedSymbol::from_value(&value, SerializationFormat::Bincode).unwrap();
        let decoded: EmptyStruct = symbol.into_value().unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    #[allow(clippy::approx_constant)]
    fn test_deeply_nested_type() {
        let value = Nested {
            inner: Box::new(Some(Nested {
                inner: Box::new(Some(Nested {
                    inner: Box::new(None),
                    value: 3.14,
                })),
                value: 2.71,
            })),
            value: 1.41,
        };
        let symbol = TypedSymbol::from_value(&value, SerializationFormat::Bincode).unwrap();
        let decoded: Nested = symbol.into_value().unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn test_header_encode_decode_roundtrip() {
        let header = TypedHeader::new::<Demo>(SerializationFormat::Json, 5, 100);
        let encoded = header.encode();
        let decoded = TypedHeader::decode(&encoded).unwrap();
        assert_eq!(header, decoded);
    }

    #[test]
    fn test_serialization_format_byte_roundtrip() {
        for format in [
            SerializationFormat::MessagePack,
            SerializationFormat::Bincode,
            SerializationFormat::Json,
            SerializationFormat::Custom,
        ] {
            let byte = format.to_byte();
            let recovered = SerializationFormat::from_byte(byte).unwrap();
            assert_eq!(format, recovered);
        }
    }

    proptest! {
        #[test]
        fn typed_header_property_roundtrips_every_bounded_field(
            version in any::<u16>(),
            payload_len in any::<u32>(),
            format_index in 0usize..4,
        ) {
            let formats = [
                SerializationFormat::MessagePack,
                SerializationFormat::Bincode,
                SerializationFormat::Json,
                SerializationFormat::Custom,
            ];
            let header = TypedHeader::new::<Demo>(
                formats[format_index],
                version,
                payload_len,
            );
            let encoded = header.encode();

            prop_assert_eq!(encoded.len(), TYPED_SYMBOL_HEADER_LEN);
            let decoded = TypedHeader::decode(&encoded).expect("generated header must decode");
            prop_assert_eq!(decoded, header);
        }
    }

    // =========================================================================
    // Wave 59 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn serialization_format_debug_clone_copy_eq() {
        let fmt = SerializationFormat::Json;
        let dbg = format!("{fmt:?}");
        assert!(dbg.contains("Json"), "{dbg}");
        let copied = fmt;
        let cloned = fmt;
        assert_eq!(copied, cloned);
        assert_ne!(fmt, SerializationFormat::Bincode);
    }

    #[test]
    fn typed_symbol_json_snapshot_scrubbed_ids() {
        let value = Demo {
            id: 11,
            name: "typed".to_string(),
        };
        let symbol = TypedSymbol::from_value(&value, SerializationFormat::Json)
            .expect("create typed symbol");

        insta::assert_json_snapshot!(
            "typed_symbol_json_scrubbed_ids",
            serde_json::json!({
                "symbol_id": {
                    "object_id": "[OBJECT_ID]",
                    "sbn": symbol.symbol().sbn(),
                    "esi": symbol.symbol().esi(),
                },
                "kind": symbol.symbol().kind().to_string(),
                "format": format!("{:?}", symbol.format()),
                "version": symbol.version(),
                "payload_len": symbol.payload_len(),
                "value": symbol.value().expect("decode typed symbol"),
            })
        );
    }
