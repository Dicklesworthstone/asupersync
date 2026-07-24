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
    use asupersync::stream::{Stream, StreamExt};
    use asupersync::types::{
        Deserializer, SerdeCodec, SerializationFormat, Serializer, TypedSymbol,
    };
    use prost::{Message, Oneof};
    use serde::{Deserialize, Serialize};
    use std::collections::{BTreeMap, HashMap, VecDeque};
    use std::pin::Pin;
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
