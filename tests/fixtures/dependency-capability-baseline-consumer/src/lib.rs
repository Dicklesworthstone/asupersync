//! Standalone downstream-consumer baseline for dependency-sovereignty work.
//!
//! This crate deliberately uses only public asupersync APIs. Its tests freeze
//! generic extension points that would be easy to narrow accidentally while
//! replacing dependencies: downstream Serde and Protobuf types, a
//! downstream-authored stream, configuration and public errors, protocol
//! helpers, metrics exporters, and the Tower adapter.

#[cfg(test)]
mod tests {
    use asupersync::grpc::{Codec, ProstCodec, ProtobufError};
    use asupersync::net::atp::sdk::{AtpReader, AtpWriter, TransferProgress};
    use asupersync::stream::{Stream, StreamExt};
    use asupersync::types::{
        DeserializationError, Deserializer, SerdeCodec, SerializationError, SerializationFormat,
        Serializer, TYPED_SYMBOL_VERSION, TypeMismatchError, TypedSymbol,
    };
    use prost::{Message, Oneof};
    use serde::de::{DeserializeOwned, SeqAccess, Visitor};
    use serde::ser::Error as _;
    use serde::{Deserialize, Serialize};
    use std::cell::Cell;
    use std::collections::{BTreeMap, HashMap, VecDeque};
    use std::fmt;
    use std::marker::PhantomPinned;
    use std::pin::Pin;
    use std::rc::Rc;
    use std::task::{Context, Poll};

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    enum ConsumerMode {
        Empty,
        Named(String),
        Bounded(u64),
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct ConsumerRecord {
        id: u64,
        mode: ConsumerMode,
        labels: BTreeMap<String, String>,
        payload: Vec<u8>,
        optional: Option<i64>,
    }

    impl ConsumerRecord {
        fn boundary_fixture() -> Self {
            Self {
                id: u64::MAX,
                mode: ConsumerMode::Bounded(u64::MAX),
                labels: BTreeMap::from([
                    (String::new(), String::new()),
                    ("unicode".to_owned(), "Grüße \u{1f980}".to_owned()),
                ]),
                payload: vec![0, 1, 127, 128, 254, 255],
                optional: Some(i64::MIN),
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    struct ConsumerUnit;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct ConsumerNewtype(u128);

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct ConsumerTuple(i16, bool, char);

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct ConsumerF32(u32);

    impl Serialize for ConsumerF32 {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.serialize_f32(f32::from_bits(self.0))
        }
    }

    impl<'de> Deserialize<'de> for ConsumerF32 {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            f32::deserialize(deserializer).map(|value| Self(value.to_bits()))
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct ConsumerF64(u64);

    impl Serialize for ConsumerF64 {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.serialize_f64(f64::from_bits(self.0))
        }
    }

    impl<'de> Deserialize<'de> for ConsumerF64 {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            f64::deserialize(deserializer).map(|value| Self(value.to_bits()))
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ConsumerBytes(Vec<u8>);

    impl Serialize for ConsumerBytes {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.serialize_bytes(&self.0)
        }
    }

    struct ConsumerBytesVisitor;

    impl<'de> Visitor<'de> for ConsumerBytesVisitor {
        type Value = ConsumerBytes;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("an owned byte buffer")
        }

        fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(ConsumerBytes(value.to_vec()))
        }

        fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(ConsumerBytes(value))
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut bytes = Vec::with_capacity(sequence.size_hint().unwrap_or(0));
            while let Some(byte) = sequence.next_element()? {
                bytes.push(byte);
            }
            Ok(ConsumerBytes(bytes))
        }
    }

    impl<'de> Deserialize<'de> for ConsumerBytes {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_byte_buf(ConsumerBytesVisitor)
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    enum ConsumerVariant {
        Unit,
        Newtype(ConsumerNewtype),
        Tuple(i32, String),
        Struct { enabled: bool, bytes: ConsumerBytes },
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    enum ConsumerNested {
        Leaf(u64),
        Link(Box<Self>),
    }

    impl ConsumerNested {
        fn with_depth(depth: usize) -> Self {
            (0..depth).fold(Self::Leaf(u64::MAX), |nested, _| {
                Self::Link(Box::new(nested))
            })
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct ConsumerSerdeModel {
        unit: (),
        unit_struct: ConsumerUnit,
        newtype: ConsumerNewtype,
        tuple: (i8, u16, String),
        tuple_struct: ConsumerTuple,
        variants: Vec<ConsumerVariant>,
        boolean: bool,
        signed: (i8, i16, i32, i64, i128),
        unsigned: (u8, u16, u32, u64, u128),
        f32_values: [ConsumerF32; 4],
        f64_values: [ConsumerF64; 4],
        character: char,
        text: String,
        bytes: ConsumerBytes,
        none: Option<i64>,
        some: Option<i64>,
        sequence: Vec<i32>,
        string_map: BTreeMap<String, u64>,
        numeric_map: BTreeMap<i16, String>,
        nested: Vec<Option<BTreeMap<String, ConsumerVariant>>>,
    }

    impl ConsumerSerdeModel {
        fn complete_fixture() -> Self {
            Self {
                unit: (),
                unit_struct: ConsumerUnit,
                newtype: ConsumerNewtype(u128::MAX),
                tuple: (i8::MIN, u16::MAX, "tuple".to_owned()),
                tuple_struct: ConsumerTuple(i16::MIN, true, 'ß'),
                variants: vec![
                    ConsumerVariant::Unit,
                    ConsumerVariant::Newtype(ConsumerNewtype(1)),
                    ConsumerVariant::Tuple(i32::MIN, "variant".to_owned()),
                    ConsumerVariant::Struct {
                        enabled: false,
                        bytes: ConsumerBytes(vec![0, 127, 128, 255]),
                    },
                ],
                boolean: true,
                signed: (i8::MIN, i16::MIN, i32::MIN, i64::MIN, i128::MIN),
                unsigned: (u8::MAX, u16::MAX, u32::MAX, u64::MAX, u128::MAX),
                f32_values: [
                    ConsumerF32(0.0f32.to_bits()),
                    ConsumerF32((-0.0f32).to_bits()),
                    ConsumerF32(f32::INFINITY.to_bits()),
                    ConsumerF32(f32::NAN.to_bits()),
                ],
                f64_values: [
                    ConsumerF64(0.0f64.to_bits()),
                    ConsumerF64((-0.0f64).to_bits()),
                    ConsumerF64(f64::NEG_INFINITY.to_bits()),
                    ConsumerF64(f64::NAN.to_bits()),
                ],
                character: '🦀',
                text: "Grüße from downstream".to_owned(),
                bytes: ConsumerBytes(vec![0, 1, 127, 128, 254, 255]),
                none: None,
                some: Some(i64::MAX),
                sequence: vec![i32::MIN, -1, 0, 1, i32::MAX],
                string_map: BTreeMap::from([(String::new(), 0), ("unicode".to_owned(), u64::MAX)]),
                numeric_map: BTreeMap::from([
                    (i16::MIN, "minimum".to_owned()),
                    (i16::MAX, "maximum".to_owned()),
                ]),
                nested: vec![
                    None,
                    Some(BTreeMap::new()),
                    Some(BTreeMap::from([(
                        "variant".to_owned(),
                        ConsumerVariant::Tuple(7, "nested".to_owned()),
                    )])),
                ],
            }
        }
    }

    struct ConsumerForcedEncodeError;

    impl Serialize for ConsumerForcedEncodeError {
        fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            Err(S::Error::custom("consumer-forced encode failure"))
        }
    }

    fn binary_formats() -> [SerializationFormat; 2] {
        [
            SerializationFormat::MessagePack,
            SerializationFormat::Bincode,
        ]
    }

    fn assert_owned<T: DeserializeOwned>() {}

    fn hex(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for &byte in bytes {
            output.push(char::from(DIGITS[usize::from(byte >> 4)]));
            output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
        }
        output
    }

    #[derive(Debug, PartialEq, Eq)]
    struct ConsumerOpaque {
        sequence: u32,
        label: String,
    }

    struct ConsumerOpaqueCodec;

    impl Serializer<ConsumerOpaque> for ConsumerOpaqueCodec {
        fn serialize(
            &self,
            value: &ConsumerOpaque,
            format: SerializationFormat,
        ) -> Result<Vec<u8>, SerializationError> {
            if format != SerializationFormat::Custom {
                return Err(SerializationError::UnsupportedType {
                    type_name: std::any::type_name::<ConsumerOpaque>().to_owned(),
                });
            }
            let label_len = u32::try_from(value.label.len()).map_err(|_| {
                SerializationError::ValueTooLarge {
                    size: value.label.len(),
                    max: u32::MAX as usize,
                }
            })?;
            let mut bytes = Vec::with_capacity(8 + value.label.len());
            bytes.extend_from_slice(&value.sequence.to_le_bytes());
            bytes.extend_from_slice(&label_len.to_le_bytes());
            bytes.extend_from_slice(value.label.as_bytes());
            Ok(bytes)
        }
    }

    impl Deserializer<ConsumerOpaque> for ConsumerOpaqueCodec {
        fn deserialize(
            &self,
            bytes: &[u8],
            format: SerializationFormat,
        ) -> Result<ConsumerOpaque, DeserializationError> {
            if format != SerializationFormat::Custom || bytes.len() < 8 {
                return Err(DeserializationError::CorruptData);
            }
            let sequence = u32::from_le_bytes(
                bytes[..4]
                    .try_into()
                    .map_err(|_| DeserializationError::CorruptData)?,
            );
            let label_len = u32::from_le_bytes(
                bytes[4..8]
                    .try_into()
                    .map_err(|_| DeserializationError::CorruptData)?,
            ) as usize;
            if bytes.len() != 8usize.saturating_add(label_len) {
                return Err(DeserializationError::CorruptData);
            }
            let label = std::str::from_utf8(&bytes[8..])
                .map_err(|_| DeserializationError::CorruptData)?
                .to_owned();
            Ok(ConsumerOpaque { sequence, label })
        }
    }

    #[derive(Clone, PartialEq, Message)]
    struct ConsumerProto {
        #[prost(uint64, tag = "1")]
        id: u64,
        #[prost(string, repeated, tag = "2")]
        tags: Vec<String>,
        #[prost(map = "string, int64", tag = "3")]
        counters: HashMap<String, i64>,
        #[prost(oneof = "consumer_proto::Payload", tags = "4, 5")]
        payload: Option<consumer_proto::Payload>,
    }

    mod consumer_proto {
        use super::*;

        #[derive(Clone, PartialEq, Oneof)]
        pub enum Payload {
            #[prost(bytes, tag = "4")]
            Bytes(Vec<u8>),
            #[prost(string, tag = "5")]
            Text(String),
        }
    }

    #[derive(Debug)]
    struct DownstreamStream {
        items: VecDeque<u32>,
        pending_once: bool,
    }

    impl DownstreamStream {
        fn new(items: impl IntoIterator<Item = u32>) -> Self {
            Self {
                items: items.into_iter().collect(),
                pending_once: true,
            }
        }
    }

    impl Stream for DownstreamStream {
        type Item = u32;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            if self.pending_once {
                self.pending_once = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Poll::Ready(self.items.pop_front())
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            (self.items.len(), Some(self.items.len()))
        }
    }

    #[derive(Debug)]
    struct DownstreamPinnedLocalStream<'a> {
        item: &'a Cell<Option<u32>>,
        _local_only: Rc<()>,
        _pin: PhantomPinned,
    }

    impl<'a> DownstreamPinnedLocalStream<'a> {
        fn new(item: &'a Cell<Option<u32>>) -> Self {
            Self {
                item,
                _local_only: Rc::new(()),
                _pin: PhantomPinned,
            }
        }
    }

    impl Stream for DownstreamPinnedLocalStream<'_> {
        type Item = u32;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Ready(self.as_ref().get_ref().item.take())
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            let remaining = usize::from(self.item.get().is_some());
            (remaining, Some(remaining))
        }
    }

    fn poll_stream_once<S>(stream: Pin<&mut S>) -> Poll<Option<S::Item>>
    where
        S: Stream,
    {
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        stream.poll_next(&mut cx)
    }

    #[test]
    fn arbitrary_downstream_serde_types_round_trip_all_accepted_formats() {
        let codec = SerdeCodec;
        let fixtures = [
            ConsumerRecord {
                id: 0,
                mode: ConsumerMode::Empty,
                labels: BTreeMap::new(),
                payload: Vec::new(),
                optional: None,
            },
            ConsumerRecord {
                id: 7,
                mode: ConsumerMode::Named("consumer".to_owned()),
                labels: BTreeMap::from([("region".to_owned(), "test".to_owned())]),
                payload: b"\0binary\xff".to_vec(),
                optional: Some(-9),
            },
            ConsumerRecord::boundary_fixture(),
        ];

        for format in [
            SerializationFormat::Json,
            SerializationFormat::Bincode,
            SerializationFormat::MessagePack,
        ] {
            for fixture in &fixtures {
                let encoded = codec
                    .serialize(fixture, format)
                    .expect("public Serde codec must encode downstream type");
                let decoded: ConsumerRecord = codec
                    .deserialize(&encoded, format)
                    .expect("public Serde codec must decode downstream type");
                assert_eq!(&decoded, fixture);
            }
        }
    }

    #[test]
    fn binary_formats_cover_the_complete_owned_serde_model() {
        assert_owned::<ConsumerSerdeModel>();
        let codec = SerdeCodec;
        let fixture = ConsumerSerdeModel::complete_fixture();

        for format in binary_formats() {
            let encoded = codec
                .serialize(&fixture, format)
                .expect("binary format must encode the complete downstream model");
            let decoded: ConsumerSerdeModel = codec
                .deserialize(&encoded, format)
                .expect("binary format must decode the complete downstream model");
            assert_eq!(decoded, fixture, "{format:?} semantic round trip drifted");
        }
    }

    #[test]
    fn binary_format_bytes_are_explicit_downstream_goldens() {
        let codec = SerdeCodec;
        let fixture = ConsumerRecord::boundary_fixture();

        let messagepack = codec
            .serialize(&fixture, SerializationFormat::MessagePack)
            .expect("serialize MessagePack golden");
        assert_eq!(
            hex(&messagepack),
            "95cfffffffffffffffff81a7426f756e646564cfffffffffffffffff82a0a0a7756e69636f6465ac4772c3bcc39f6520f09fa6809600017fcc80ccfeccffd38000000000000000"
        );

        let bincode = codec
            .serialize(&fixture, SerializationFormat::Bincode)
            .expect("serialize legacy Bincode golden");
        assert_eq!(
            hex(&bincode),
            "ffffffffffffffff02000000ffffffffffffffff0200000000000000000000000000000000000000000000000700000000000000756e69636f64650c000000000000004772c3bcc39f6520f09fa680060000000000000000017f80feff010000000000000080"
        );
    }

    #[test]
    fn binary_formats_preserve_errors_trailing_bytes_recovery_and_large_owned_values() {
        let codec = SerdeCodec;
        let fixture = ConsumerSerdeModel::complete_fixture();

        for format in binary_formats() {
            let forced = codec
                .serialize(&ConsumerForcedEncodeError, format)
                .expect_err("forced downstream serializer error must propagate");
            assert!(
                forced
                    .to_string()
                    .contains("consumer-forced encode failure"),
                "{format:?} lost the downstream encode reason: {forced}"
            );

            let encoded = codec
                .serialize(&fixture, format)
                .expect("serialize malformed-input baseline");
            let mut truncated = encoded.clone();
            truncated.pop();
            let malformed: Result<ConsumerSerdeModel, _> = codec.deserialize(&truncated, format);
            let error = malformed.expect_err("truncated binary payload must fail");
            assert!(
                error.to_string().contains("deserialization failed"),
                "{format:?} lost malformed decode context: {error}"
            );

            let mut with_trailing = encoded.clone();
            with_trailing.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
            let decoded: ConsumerSerdeModel = codec
                .deserialize(&with_trailing, format)
                .expect("the established public codec ignores trailing bytes");
            assert_eq!(
                decoded, fixture,
                "{format:?} trailing-byte behavior drifted"
            );

            let recovered: ConsumerSerdeModel = codec
                .deserialize(&encoded, format)
                .expect("valid decode must recover after malformed input");
            assert_eq!(recovered, fixture);

            let large = ConsumerBytes(vec![0xa5; 1024 * 1024]);
            let large_bytes = codec
                .serialize(&large, format)
                .expect("public codec has no hidden one-megabyte encode cap");
            let decoded_large: ConsumerBytes = codec
                .deserialize(&large_bytes, format)
                .expect("public codec has no hidden one-megabyte decode cap");
            assert_eq!(decoded_large, large);

            let deep = ConsumerNested::with_depth(128);
            let deep_bytes = codec
                .serialize(&deep, format)
                .expect("public codec accepts 128 levels of owned nesting");
            let decoded_deep: ConsumerNested = codec
                .deserialize(&deep_bytes, format)
                .expect("public codec decodes 128 levels of owned nesting");
            assert_eq!(decoded_deep, deep);
        }
    }

    #[test]
    fn serde_codec_errors_and_typed_symbol_bytes_remain_observable() {
        let codec = SerdeCodec;
        let malformed: Result<ConsumerRecord, _> =
            codec.deserialize(b"{\"id\":", SerializationFormat::Json);
        let error = malformed.expect_err("truncated JSON must fail");
        assert!(
            error.to_string().contains("deserialization failed"),
            "public error context must remain actionable: {error}"
        );

        let custom = codec.serialize(
            &ConsumerRecord::boundary_fixture(),
            SerializationFormat::Custom,
        );
        assert!(custom.is_err(), "unsupported custom Serde format must fail");

        let recovered = ConsumerRecord::boundary_fixture();
        let encoded = codec
            .serialize(&recovered, SerializationFormat::Json)
            .expect("codec must remain usable after prior errors");
        let decoded: ConsumerRecord = codec
            .deserialize(&encoded, SerializationFormat::Json)
            .expect("valid decode must recover after prior errors");
        assert_eq!(decoded, recovered);

        let symbol = TypedSymbol::from_value(
            &ConsumerRecord::boundary_fixture(),
            SerializationFormat::Bincode,
        )
        .expect("typed symbol");
        assert_eq!(symbol.format(), SerializationFormat::Bincode);
        assert!(!symbol.symbol().data().is_empty());
    }

    #[test]
    fn non_serde_custom_typed_symbol_codec_and_explicit_version_remain_public() {
        let value = ConsumerOpaque {
            sequence: 42,
            label: "downstream-owned".to_owned(),
        };
        let symbol = TypedSymbol::from_value_with_serializer(
            &value,
            SerializationFormat::Custom,
            TYPED_SYMBOL_VERSION + 1,
            &ConsumerOpaqueCodec,
        )
        .expect("public custom serializer");
        assert_eq!(symbol.format(), SerializationFormat::Custom);
        assert_eq!(symbol.version(), TYPED_SYMBOL_VERSION + 1);
        assert_eq!(
            symbol
                .value_with_deserializer(&ConsumerOpaqueCodec)
                .expect("public custom deserializer"),
            value
        );

        assert!(matches!(
            TypedSymbol::<ConsumerOpaque>::try_from_symbol(symbol.into_symbol()),
            Err(TypeMismatchError::VersionMismatch {
                expected: TYPED_SYMBOL_VERSION,
                actual: 2,
            })
        ));
    }

    #[test]
    fn arbitrary_downstream_protobuf_message_round_trips_and_enforces_limits() {
        let fixture = ConsumerProto {
            id: u64::MAX,
            tags: vec![String::new(), "alpha".to_owned(), "Grüße".to_owned()],
            counters: HashMap::from([("min".to_owned(), i64::MIN), ("max".to_owned(), i64::MAX)]),
            payload: Some(consumer_proto::Payload::Bytes(vec![0, 127, 128, 255])),
        };
        let mut codec: ProstCodec<ConsumerProto, ConsumerProto> = ProstCodec::new();
        let encoded = codec
            .encode(&fixture)
            .expect("public Prost codec must encode downstream message");
        let decoded = codec
            .decode(&encoded)
            .expect("public Prost codec must decode downstream message");
        assert_eq!(decoded, fixture);

        let mut limited: ProstCodec<ConsumerProto, ConsumerProto> = ProstCodec::with_max_size(1);
        assert!(matches!(
            limited.encode(&fixture),
            Err(ProtobufError::MessageTooLarge { limit: 1, .. })
        ));
        assert!(limited.decode(&encoded).is_err());

        let malformed = asupersync::bytes::Bytes::from_static(&[0x0a, 0x80]);
        assert!(
            codec.decode(&malformed).is_err(),
            "truncated downstream protobuf must fail"
        );
    }

    #[test]
    fn downstream_authored_stream_preserves_pending_items_order_and_fusion_contract() {
        let mut stream = Box::pin(
            DownstreamStream::new([1, 2, 3])
                .map(|value| value * 2)
                .filter(|value| *value >= 4)
                .fuse(),
        );

        assert!(poll_stream_once(stream.as_mut()).is_pending());
        assert_eq!(poll_stream_once(stream.as_mut()), Poll::Ready(Some(4)));
        assert_eq!(poll_stream_once(stream.as_mut()), Poll::Ready(Some(6)));
        assert_eq!(poll_stream_once(stream.as_mut()), Poll::Ready(None));
        assert_eq!(poll_stream_once(stream.as_mut()), Poll::Ready(None));
    }

    #[test]
    fn downstream_pinned_local_borrowed_stream_uses_forwarding_adapter() {
        let item = Cell::new(Some(9));
        let mut stream = Box::pin(DownstreamPinnedLocalStream::new(&item));

        assert_eq!(Stream::size_hint(&stream), (1, Some(1)));
        {
            let _pending_next = stream.next();
        }
        assert_eq!(poll_stream_once(Pin::new(&mut stream)), Poll::Ready(Some(9)));
        assert_eq!(poll_stream_once(Pin::new(&mut stream)), Poll::Ready(None));
    }

    #[test]
    fn downstream_fallible_stream_terminal_adapter_compile_contract() {
        let _collect = DownstreamStream::new([1, 2, 3])
            .map(|value| {
                if value == 2 {
                    Err("downstream error")
                } else {
                    Ok(value)
                }
            })
            .try_collect::<u32, &'static str, Vec<u32>>();
    }

    #[test]
    fn atp_sdk_progress_types_expose_the_owned_stream_contract() {
        fn assert_owned_progress_stream<S>()
        where
            S: Stream<Item = TransferProgress> + Unpin,
        {
        }

        fn next_owned_progress<S>(stream: &mut S)
        where
            S: Stream<Item = TransferProgress> + Unpin,
        {
            let _next = stream.next();
        }

        assert_owned_progress_stream::<AtpWriter>();
        assert_owned_progress_stream::<AtpReader>();
        let _writer_next: fn(&mut AtpWriter) = next_owned_progress::<AtpWriter>;
        let _reader_next: fn(&mut AtpReader) = next_owned_progress::<AtpReader>;
    }

    #[test]
    fn public_configuration_and_error_contracts_are_available_to_consumers() {
        let mut config = asupersync::config::RaptorQConfig::default();
        assert!(config.validate().is_ok());

        config.encoding.symbol_size = 0;
        let error = config.validate().expect_err("zero symbol size must fail");
        assert_eq!(error.to_string(), "symbol_size out of range");

        // Exercise the public builder shape without reading the worker's ambient
        // RAPTORQ_* environment. Root-owned config tests cover source precedence;
        // this standalone fixture freezes only what a downstream crate can name.
        let _loader =
            asupersync::config::ConfigLoader::new().override_value("ENCODING_SYMBOL_SIZE", "4096");
        let error = asupersync::config::ConfigError::InvalidOverride("CAP_A2_UNKNOWN".to_owned());
        assert_eq!(error.to_string(), "invalid override: CAP_A2_UNKNOWN");
    }

    #[test]
    fn public_protocol_helpers_round_trip_binary_and_reject_malformed_input() {
        let payload = [0, 1, 2, 127, 128, 254, 255];
        let encoded = asupersync::grpc::base64_encode(&payload);
        assert_eq!(
            asupersync::grpc::base64_decode(&encoded).expect("decode canonical base64"),
            payload
        );
        assert_eq!(
            asupersync::grpc::base64_decode("").expect("empty base64"),
            Vec::<u8>::new()
        );
        assert!(asupersync::grpc::base64_decode("%%%").is_err());
    }

    #[test]
    fn deterministic_identity_surfaces_are_stable_without_test_internals() {
        let seed = 0xA5A5_5A5A_DEAD_BEEF;
        assert_eq!(
            asupersync::trace::scoring::seed_fingerprint(seed),
            asupersync::trace::scoring::seed_fingerprint(seed),
            "seed fingerprints must not depend on per-call production entropy",
        );

        let config = asupersync::lab::LabConfig::new(seed);
        let summary = asupersync::lab::LabConfigSummary::from_config(&config);
        assert_eq!(
            summary.config_hash(),
            summary.config_hash(),
            "lab configuration identity must be replay-stable",
        );

        let event = asupersync::trace::event::TraceEvent::new(
            7,
            asupersync::types::Time::ZERO,
            asupersync::trace::event::TraceEventKind::UserTrace,
            asupersync::trace::event::TraceData::Message("downstream identity".to_owned()),
        );
        let events = [event.clone()];

        let mut first_certificate = asupersync::trace::TraceCertificate::new();
        first_certificate.record_event(&event);
        let mut second_certificate = asupersync::trace::TraceCertificate::new();
        second_certificate.record_event(&event);
        assert_eq!(
            first_certificate.event_hash(),
            second_certificate.event_hash(),
            "trace certificates must be byte-replayable in production builds",
        );

        assert_eq!(
            asupersync::trace::trace_fingerprint(&events),
            asupersync::trace::trace_fingerprint(&events),
            "canonical trace fingerprints must be replay-stable",
        );
        assert_eq!(
            asupersync::trace::canonicalize(&events).fingerprint(),
            asupersync::trace::canonicalize(&events).fingerprint(),
            "Foata fingerprints must be replay-stable",
        );

        let task = asupersync::types::TaskId::testing_default();
        let mut first_schedule =
            asupersync::runtime::scheduler::ScheduleCertificate::new();
        first_schedule.record(
            task,
            asupersync::runtime::scheduler::DispatchLane::Ready,
            11,
        );
        let mut second_schedule =
            asupersync::runtime::scheduler::ScheduleCertificate::new();
        second_schedule.record(
            task,
            asupersync::runtime::scheduler::DispatchLane::Ready,
            11,
        );
        assert_eq!(
            first_schedule.hash(),
            second_schedule.hash(),
            "schedule certificates must be replay-stable",
        );
    }

    #[test]
    #[allow(non_snake_case)]
    fn ver_a1_asupersync_dep_p4_nkeys_poc60v_1_3_5e81559b363d__downstream_consumer() {
        use asupersync::security::{
            NKEY_ED25519_PRIVATE_BYTES, NKEY_KEY_BYTES, NkeyCurvePublicKey, NkeyCurveSecretKey,
            NkeyEd25519Kind, NkeyEd25519PrivateKey, NkeyEd25519PublicKey, NkeyEd25519Seed,
            NkeyEd25519SigningMaterial, NkeyOwnedKeyError, NkeyOwnedKeyForm, NkeySecretDisposition,
        };

        fn assert_copy<T: Copy>() {}
        fn signing_kind<T: NkeyEd25519SigningMaterial>(value: &T) -> NkeyEd25519Kind {
            value.kind()
        }

        assert_eq!(NKEY_KEY_BYTES, 32);
        assert_eq!(NKEY_ED25519_PRIVATE_BYTES, 64);
        assert_copy::<NkeyEd25519PublicKey>();
        assert_copy::<NkeyCurvePublicKey>();

        let user_kind: NkeyEd25519Kind = "User".parse().expect("exact public role");
        assert_eq!(user_kind, NkeyEd25519Kind::User);
        assert!("user".parse::<NkeyEd25519Kind>().is_err());

        let public = NkeyEd25519PublicKey::from_bytes(user_kind, [0x51; NKEY_KEY_BYTES]);
        assert_eq!(public.kind(), user_kind);
        assert_eq!(public.as_bytes(), &[0x51; NKEY_KEY_BYTES]);
        assert_eq!(
            NkeyCurvePublicKey::from_bytes([0x71; NKEY_KEY_BYTES]).as_bytes(),
            &[0x71; NKEY_KEY_BYTES]
        );

        const CANARY: &[u8; NKEY_KEY_BYTES] = b"NKEY-DOWNSTREAM-CANARY-012345678";
        let canary_text = std::str::from_utf8(CANARY).expect("ASCII canary");
        let seed = NkeyEd25519Seed::from_bytes(user_kind, *CANARY);
        let private = NkeyEd25519PrivateKey::from_bytes(
            NkeyEd25519Kind::Operator,
            [0x42; NKEY_ED25519_PRIVATE_BYTES],
        );
        let curve = NkeyCurveSecretKey::from_bytes(*CANARY);
        assert_eq!(signing_kind(&seed), NkeyEd25519Kind::User);
        assert_eq!(signing_kind(&private), NkeyEd25519Kind::Operator);

        assert!(matches!(
            seed.export_secret(NkeySecretDisposition::InProcessOperation),
            Err(NkeyOwnedKeyError::SecretDisposition {
                disposition: NkeySecretDisposition::InProcessOperation
            })
        ));
        let export = seed
            .export_secret(NkeySecretDisposition::PlaintextExport)
            .expect("explicit downstream export");
        assert!(export.as_bytes().as_slice() == CANARY.as_slice());

        for rendered in [
            format!("{seed:?}"),
            seed.to_string(),
            format!("{curve:?}"),
            curve.to_string(),
            format!("{export:?}"),
            export.to_string(),
        ] {
            assert!(!rendered.contains(canary_text));
            assert!(rendered.to_ascii_lowercase().contains("redacted"));
        }

        assert_eq!(
            NkeyEd25519PublicKey::try_from_slice(user_kind, &[0; NKEY_KEY_BYTES - 1]),
            Err(NkeyOwnedKeyError::Length {
                form: NkeyOwnedKeyForm::Ed25519Public,
                actual: NKEY_KEY_BYTES - 1,
                expected: NKEY_KEY_BYTES,
            })
        );
    }

    #[test]
    fn standalone_lockfile_pins_consumer_resolution() {
        let lock_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock");
        let lock = std::fs::read_to_string(&lock_path).expect("standalone Cargo.lock");

        assert!(lock.starts_with("# This file is automatically @generated by Cargo."));
        for pinned in [
            "name = \"prost\"\nversion = \"0.14.4\"",
            "name = \"serde\"\nversion = \"1.0.229\"",
            "name = \"tower\"\nversion = \"0.5.3\"",
        ] {
            assert!(
                lock.contains(pinned),
                "standalone resolution lost direct pin {pinned}"
            );
        }

        if std::env::var_os("ASUPERSYNC_CAP_A2_EMIT_LOCK").is_some() {
            println!("__CAP_A2_LOCK_BEGIN__");
            print!("{lock}");
            println!("__CAP_A2_LOCK_END__");
        }
    }

    #[cfg(feature = "metrics-profile")]
    #[test]
    fn external_metrics_exporter_trait_and_privacy_surface_remain_usable() {
        use asupersync::observability::otel::PrivacyConfig;
        use asupersync::observability::{InMemoryExporter, MetricsExporter, MetricsSnapshot};

        let mut snapshot = MetricsSnapshot::new();
        snapshot.add_counter(
            "requests.total",
            vec![("route".to_owned(), "/v1/items".to_owned())],
            3,
        );
        snapshot.add_gauge("workers", Vec::new(), 8);
        snapshot.add_histogram("latency", Vec::new(), 2, 0.75);

        let exporter = InMemoryExporter::new();
        exporter.export(&snapshot).expect("export snapshot");
        exporter.flush().expect("flush exporter");
        assert_eq!(exporter.snapshots().len(), 1);
        assert_eq!(exporter.total_metrics(), 3);

        let privacy = PrivacyConfig::default()
            .try_with_pii_pattern(r"token-[0-9]+")
            .expect("valid downstream regex")
            .with_auto_pii_detection();
        assert_eq!(privacy.redact_pii("token", "token-123"), "[REDACTED]");
        assert_eq!(
            privacy.redact_pii("email", "person@example.com"),
            "[EMAIL_REDACTED]"
        );
    }

    #[cfg(feature = "tower-profile")]
    #[test]
    fn external_tower_service_adapter_retains_trait_compatibility() {
        use asupersync::service::{AsupersyncService, AsupersyncServiceExt};
        use tower::Service as TowerService;

        struct AddOne;

        impl AsupersyncService<u64> for AddOne {
            type Response = u64;
            type Error = std::convert::Infallible;

            async fn call(
                &self,
                _cx: &asupersync::Cx,
                request: u64,
            ) -> Result<Self::Response, Self::Error> {
                Ok(request + 1)
            }
        }

        let mut adapter = AddOne.into_tower();
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let ready = <_ as TowerService<(asupersync::Cx, u64)>>::poll_ready(&mut adapter, &mut cx);
        assert_eq!(ready, Poll::Ready(Ok(())));
    }
}
