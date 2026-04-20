//! Integration tests for gRPC enhancements: F.1 (reflection), F.2 (compression),
//! F.3 (gRPC-web protocol).
//!
//! These tests exercise the public API surface across the gRPC enhancement
//! features, ensuring they compose correctly and handle edge cases.

#![allow(clippy::pedantic)]
#![allow(clippy::nursery)]

mod common;

use asupersync::bytes::{BufMut, Bytes, BytesMut};
use asupersync::grpc::codec::{FramedCodec, GrpcCodec, GrpcMessage, IdentityCodec};
use asupersync::grpc::status::{Code, GrpcError, Status};
use asupersync::grpc::streaming::{Metadata, MetadataValue};
use asupersync::grpc::web::{
    ContentType as WebContentType, WebFrame, WebFrameCodec, base64_decode, base64_encode,
    encode_trailers, is_grpc_web_request, is_text_mode,
};

// ── F.1: Reflection Integration Tests ────────────────────────────────

mod reflection {
    use super::common;
    use asupersync::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
    use asupersync::cx::Cx;
    use asupersync::grpc::health::HealthService;
    use asupersync::grpc::reflection::ReflectionService;
    use asupersync::grpc::service::{
        MethodDescriptor, NamedService, ServiceDescriptor, ServiceHandler,
    };
    use asupersync::grpc::streaming::Request;
    use asupersync::types::Budget;

    /// Mock service for testing reflection.
    struct MockEchoService;

    impl NamedService for MockEchoService {
        const NAME: &'static str = "test.Echo";
    }

    impl ServiceHandler for MockEchoService {
        fn descriptor(&self) -> &ServiceDescriptor {
            static METHODS: &[MethodDescriptor] =
                &[MethodDescriptor::unary("Echo", "/test.Echo/Echo")];
            static DESC: ServiceDescriptor = ServiceDescriptor::new("Echo", "test", METHODS);
            &DESC
        }

        fn method_names(&self) -> Vec<&str> {
            vec!["Echo"]
        }
    }

    #[test]
    fn test_reflection_registers_and_lists_multiple_services() {
        common::init_test_logging();

        let config = TestConfig::new().with_seed(0x5157).with_tracing(true);
        let mut runtime = LabRuntimeTarget::create_runtime(config);

        let (services, health_method_names, checkpoints) =
            LabRuntimeTarget::block_on(&mut runtime, async {
                let cx = Cx::current().expect("lab root task should have a current Cx");
                let reflection = ReflectionService::default();
                let health = HealthService::new();
                let reflection_service = ReflectionService::new();

                reflection.register_handler(&health);
                reflection.register_handler(&reflection_service);

                let list_reflection = reflection.clone();
                let list_handle = LabRuntimeTarget::spawn(&cx, Budget::INFINITE, async move {
                    list_reflection
                        .list_services_async(&Request::new(Default::default()))
                        .await
                        .expect("list services should succeed")
                        .into_inner()
                        .services
                });

                let describe_reflection = reflection.clone();
                let describe_handle =
                    LabRuntimeTarget::spawn(&cx, Budget::INFINITE, async move {
                        describe_reflection
                            .describe_service_async(&Request::new(
                                asupersync::grpc::reflection::ReflectionDescribeServiceRequest::new(
                                    <HealthService as NamedService>::NAME,
                                ),
                            ))
                            .await
                            .expect("describe service should succeed")
                            .into_inner()
                            .service
                            .methods
                            .into_iter()
                            .map(|method| method.name)
                            .collect::<Vec<_>>()
                    });

                asupersync::runtime::yield_now().await;

                let services = match list_handle.await {
                    asupersync::types::Outcome::Ok(services) => services,
                    other => panic!("unexpected list outcome: {other:?}"),
                };
                let health_method_names = match describe_handle.await {
                    asupersync::types::Outcome::Ok(methods) => methods,
                    other => panic!("unexpected describe outcome: {other:?}"),
                };

                let checkpoints = vec![
                    serde_json::json!({
                        "phase": "registered",
                        "services": [
                            <HealthService as NamedService>::NAME,
                            <ReflectionService as NamedService>::NAME,
                        ],
                    }),
                    serde_json::json!({
                        "phase": "listed",
                        "services": services,
                    }),
                    serde_json::json!({
                        "phase": "described",
                        "service": <HealthService as NamedService>::NAME,
                        "methods": health_method_names,
                    }),
                ];

                for checkpoint in &checkpoints {
                    tracing::info!(event = %checkpoint, "grpc_reflection_lab_checkpoint");
                }

                (services, health_method_names, checkpoints)
            });

        assert!(
            services
                .iter()
                .any(|service| service == <HealthService as NamedService>::NAME),
            "real HealthService must be registered in reflection"
        );
        assert!(
            services
                .iter()
                .any(|service| service == <ReflectionService as NamedService>::NAME),
            "real ReflectionService must be registered in reflection"
        );
        assert_eq!(health_method_names, vec!["Check".to_string(), "Watch".to_string()]);
        assert_eq!(checkpoints.len(), 3, "expected deterministic JSON checkpoints");
    }

    #[test]
    fn test_reflection_describe_returns_methods() {
        let reflection = ReflectionService::default();
        let svc = MockEchoService;
        reflection.register_handler(&svc);

        let desc = reflection.describe_service("test.Echo");
        assert!(desc.is_ok(), "describe returns Some");
        let info = desc.unwrap();
        assert!(!info.methods.is_empty(), "has methods");
        assert_eq!(info.methods[0].name, "Echo");
    }

    #[test]
    fn test_reflection_describe_unknown_returns_none() {
        let reflection = ReflectionService::default();
        let desc = reflection.describe_service("nonexistent.Service");
        assert!(desc.is_err(), "unknown service returns error");
    }
}

// ── F.2: Compression Integration Tests ───────────────────────────────

mod compression {
    use super::*;

    #[test]
    fn test_identity_codec_no_compression() {
        let mut codec = FramedCodec::new(IdentityCodec);
        let mut buf = BytesMut::new();
        let data = Bytes::from_static(b"no compression");

        codec.encode_message(&data, &mut buf).unwrap();

        // Flag byte should be 0 (no compression).
        assert_eq!(buf[0], 0, "flag byte is 0 for uncompressed");

        let decoded = codec.decode_message(&mut buf).unwrap().unwrap();
        assert_eq!(decoded, data, "roundtrip without compression");
    }

    #[test]
    fn test_identity_frame_codec_sets_compressed_flag() {
        let mut codec = FramedCodec::new(IdentityCodec).with_identity_frame_codec();
        let mut buf = BytesMut::new();
        let data = Bytes::from_static(b"identity-compressed");

        codec.encode_message(&data, &mut buf).unwrap();

        // Flag byte should be 1 (compressed frame via identity codec).
        assert_eq!(buf[0], 1, "compressed flag set with identity frame codec");

        let decoded = codec.decode_message(&mut buf).unwrap().unwrap();
        assert_eq!(decoded, data);
    }

    #[cfg(feature = "compression")]
    #[test]
    fn test_gzip_compression_reduces_size_for_compressible_data() {
        use asupersync::grpc::codec::{gzip_frame_compress, gzip_frame_decompress};

        // Highly compressible data (repeated bytes).
        let data = vec![b'A'; 10_000];
        let compressed = gzip_frame_compress(&data).unwrap();

        assert!(
            compressed.len() < data.len(),
            "gzip should reduce size for compressible data: {} < {}",
            compressed.len(),
            data.len()
        );

        let decompressed = gzip_frame_decompress(&compressed, 20_000).unwrap();
        assert_eq!(decompressed.as_ref(), data.as_slice());
    }

    #[cfg(feature = "compression")]
    #[test]
    fn test_gzip_framed_codec_end_to_end() {
        let mut codec = FramedCodec::new(IdentityCodec).with_gzip_frame_codec();
        let mut buf = BytesMut::new();
        let data = Bytes::from(vec![b'Z'; 1024]);

        codec.encode_message(&data, &mut buf).unwrap();
        assert_eq!(buf[0], 1, "compressed flag set");

        let decoded = codec.decode_message(&mut buf).unwrap().unwrap();
        assert_eq!(decoded, data, "gzip roundtrip through framed codec");
    }

    #[cfg(feature = "compression")]
    #[test]
    fn test_gzip_decompress_rejects_oversized_output() {
        use asupersync::grpc::codec::{gzip_frame_compress, gzip_frame_decompress};

        let data = vec![0u8; 8192];
        let compressed = gzip_frame_compress(&data).unwrap();

        let result = gzip_frame_decompress(&compressed, 100);
        assert!(
            matches!(result, Err(GrpcError::MessageTooLarge)),
            "decompression bomb rejected"
        );
    }

    #[test]
    fn test_compression_without_compressor_errors() {
        let mut codec = FramedCodec::new(IdentityCodec).with_compression();
        let mut buf = BytesMut::new();
        let data = Bytes::from_static(b"data");

        let result = codec.encode_message(&data, &mut buf);
        assert!(
            matches!(result, Err(GrpcError::Compression(_))),
            "compression without compressor is an error"
        );
    }

    #[test]
    fn test_compressed_frame_without_decompressor_errors() {
        let mut codec_no_decompress = FramedCodec::new(IdentityCodec);
        let mut buf = BytesMut::new();

        // Fabricate a compressed frame.
        buf.put_u8(1); // compressed flag
        buf.put_u32(3);
        buf.extend_from_slice(b"abc");

        let mut decode_buf = BytesMut::from(buf.as_ref());
        let result = codec_no_decompress.decode_message(&mut decode_buf);
        assert!(
            matches!(result, Err(GrpcError::Compression(_))),
            "compressed frame without decompressor is an error"
        );
    }

    #[cfg(feature = "compression")]
    #[test]
    fn test_compression_encoding_resolves_to_functions() {
        use asupersync::grpc::client::CompressionEncoding;

        let identity = CompressionEncoding::Identity;
        assert!(
            identity.frame_compressor().is_none(),
            "Identity has no compressor"
        );
        assert!(
            identity.frame_decompressor().is_none(),
            "Identity has no decompressor"
        );

        let gzip = CompressionEncoding::Gzip;
        assert!(gzip.frame_compressor().is_some(), "Gzip has compressor");
        assert!(gzip.frame_decompressor().is_some(), "Gzip has decompressor");

        // Verify the functions actually work.
        let compress = gzip.frame_compressor().unwrap();
        let decompress = gzip.frame_decompressor().unwrap();
        let data = b"test compression encoding resolution";
        let compressed = compress(data).unwrap();
        let decompressed = decompress(&compressed, 1024).unwrap();
        assert_eq!(decompressed.as_ref(), data.as_slice());
    }

    #[test]
    fn test_compression_encoding_header_parsing() {
        use asupersync::grpc::client::CompressionEncoding;

        assert_eq!(
            CompressionEncoding::from_header_value("identity"),
            Some(CompressionEncoding::Identity)
        );
        assert_eq!(
            CompressionEncoding::from_header_value("gzip"),
            Some(CompressionEncoding::Gzip)
        );
        assert_eq!(CompressionEncoding::from_header_value("deflate"), None);
        assert_eq!(CompressionEncoding::from_header_value(""), None);
    }
}

// ── F.3: gRPC-Web Integration Tests ─────────────────────────────────

mod grpc_web {
    use super::*;

    #[test]
    fn test_content_type_detection_matrix() {
        let cases = [
            ("application/grpc-web", true, false),
            ("application/grpc-web+proto", true, false),
            ("application/grpc-web-text", true, true),
            ("application/grpc-web-text+proto", true, true),
            ("Application/GRPC-WEB", true, false),
            ("application/grpc", false, false),
            ("application/json", false, false),
            ("text/html", false, false),
        ];

        for (ct, expect_web, expect_text) in cases {
            assert_eq!(
                is_grpc_web_request(ct),
                expect_web,
                "is_grpc_web_request({ct})"
            );
            assert_eq!(is_text_mode(ct), expect_text, "is_text_mode({ct})");
        }
    }

    #[test]
    fn test_web_content_type_roundtrip() {
        let binary = WebContentType::GrpcWeb;
        let text = WebContentType::GrpcWebText;

        assert_eq!(
            WebContentType::from_header_value(binary.as_header_value()),
            Some(WebContentType::GrpcWeb)
        );
        assert_eq!(
            WebContentType::from_header_value(text.as_header_value()),
            Some(WebContentType::GrpcWebText)
        );
    }

    #[test]
    fn test_trailer_frame_status_codes() {
        let codes = [
            (Code::Ok, "OK"),
            (Code::Cancelled, "CANCELLED"),
            (Code::Internal, "server error"),
            (Code::NotFound, "not found"),
            (Code::Unauthenticated, "unauthenticated"),
        ];

        for (code, msg) in codes {
            let status = Status::new(code, msg);
            let mut buf = BytesMut::new();
            encode_trailers(&status, &Metadata::new(), &mut buf);

            let codec = WebFrameCodec::new();
            let frame = codec.decode(&mut buf).unwrap().unwrap();
            match frame {
                WebFrame::Trailers(t) => {
                    assert_eq!(t.status.code(), code, "code roundtrip for {msg}");
                    assert_eq!(t.status.message(), msg, "message roundtrip");
                }
                _ => panic!("expected trailer frame"),
            }
        }
    }

    #[test]
    fn test_trailer_binary_metadata() {
        let status = Status::ok();
        let mut metadata = Metadata::new();
        metadata.insert_bin("x-binary-data", Bytes::from_static(b"\x00\x01\x02\xFF"));

        let mut buf = BytesMut::new();
        encode_trailers(&status, &metadata, &mut buf);

        let codec = WebFrameCodec::new();
        let frame = codec.decode(&mut buf).unwrap().unwrap();
        match frame {
            WebFrame::Trailers(t) => {
                let val = t.metadata.get("x-binary-data-bin");
                assert!(val.is_some(), "binary metadata present");
                match val.unwrap() {
                    MetadataValue::Binary(b) => {
                        assert_eq!(
                            b.as_ref(),
                            &[0x00, 0x01, 0x02, 0xFF],
                            "binary metadata roundtrip"
                        );
                    }
                    MetadataValue::Ascii(_) => panic!("expected binary metadata"),
                }
            }
            _ => panic!("expected trailer frame"),
        }
    }

    #[test]
    fn test_web_frame_codec_multi_message_stream() {
        let codec = WebFrameCodec::new();
        let mut buf = BytesMut::new();

        // Simulate a server-streaming response: 3 data + trailer.
        for i in 0..3 {
            let msg = format!("message-{i}");
            codec.encode_data(msg.as_bytes(), false, &mut buf).unwrap();
        }
        codec
            .encode_trailers(&Status::ok(), &Metadata::new(), &mut buf)
            .unwrap();

        let mut messages = Vec::new();
        let mut trailer = None;

        loop {
            match codec.decode(&mut buf).unwrap() {
                Some(WebFrame::Data { data, .. }) => messages.push(data),
                Some(WebFrame::Trailers(t)) => {
                    trailer = Some(t);
                    break;
                }
                None => break,
            }
        }

        assert_eq!(messages.len(), 3, "received all 3 messages");
        assert_eq!(messages[0].as_ref(), b"message-0");
        assert_eq!(messages[1].as_ref(), b"message-1");
        assert_eq!(messages[2].as_ref(), b"message-2");
        assert!(trailer.is_some(), "received trailer");
        assert_eq!(trailer.unwrap().status.code(), Code::Ok);
    }

    #[test]
    fn test_text_mode_binary_mode_equivalence() {
        let codec = WebFrameCodec::new();
        let mut binary_buf = BytesMut::new();

        // Build a message stream.
        codec
            .encode_data(b"test-payload", false, &mut binary_buf)
            .unwrap();
        codec
            .encode_trailers(&Status::ok(), &Metadata::new(), &mut binary_buf)
            .unwrap();

        let binary_copy = BytesMut::from(binary_buf.as_ref());

        // Text mode: base64 encode → decode → should yield identical frames.
        let text = base64_encode(&binary_buf);
        let decoded_bytes = base64_decode(&text).unwrap();

        assert_eq!(
            decoded_bytes.as_slice(),
            binary_copy.as_ref(),
            "text mode is lossless"
        );
    }

    #[test]
    fn test_empty_message_frame() {
        let codec = WebFrameCodec::new();
        let mut buf = BytesMut::new();

        codec.encode_data(&[], false, &mut buf).unwrap();

        let frame = codec.decode(&mut buf).unwrap().unwrap();
        match frame {
            WebFrame::Data { data, compressed } => {
                assert!(!compressed);
                assert!(data.is_empty(), "empty message roundtrip");
            }
            _ => panic!("expected data frame"),
        }
    }

    #[test]
    fn test_trailer_skips_duplicate_status_headers() {
        // If metadata contains grpc-status, encode_trailers should skip it
        // (status is always encoded from the Status struct).
        let status = Status::ok();
        let mut metadata = Metadata::new();
        metadata.insert("grpc-status", "13"); // This should be skipped.
        metadata.insert("x-custom", "value");

        let mut buf = BytesMut::new();
        encode_trailers(&status, &metadata, &mut buf);

        let codec = WebFrameCodec::new();
        let frame = codec.decode(&mut buf).unwrap().unwrap();
        match frame {
            WebFrame::Trailers(t) => {
                // Status should be OK (from Status struct), not Internal (13).
                assert_eq!(
                    t.status.code(),
                    Code::Ok,
                    "status from struct, not metadata"
                );
                assert!(
                    t.metadata.get("x-custom").is_some(),
                    "custom metadata preserved"
                );
            }
            _ => panic!("expected trailer frame"),
        }
    }
}

// ── Cross-Feature Integration Tests ──────────────────────────────────

mod cross_feature {
    use super::*;
    use asupersync::codec::{Decoder, Encoder};

    #[cfg(feature = "compression")]
    #[test]
    fn test_grpc_web_with_compressed_data_frame() {
        use asupersync::grpc::codec::gzip_frame_compress;

        // Simulate a compressed data frame in grpc-web format.
        let payload = b"compressed-grpc-web-payload";
        let compressed = gzip_frame_compress(payload).unwrap();

        let codec = WebFrameCodec::new();
        let mut buf = BytesMut::new();

        // Encode as compressed data frame.
        codec.encode_data(&compressed, true, &mut buf).unwrap();

        // Decode and verify.
        let frame = codec.decode(&mut buf).unwrap().unwrap();
        match frame {
            WebFrame::Data {
                compressed: c,
                data,
            } => {
                assert!(c, "compressed flag set");
                // Decompress the payload.
                use asupersync::grpc::codec::gzip_frame_decompress;
                let decompressed = gzip_frame_decompress(&data, 4096).unwrap();
                assert_eq!(decompressed.as_ref(), payload.as_slice());
            }
            _ => panic!("expected data frame"),
        }
    }

    #[cfg(feature = "compression")]
    #[test]
    fn test_grpc_web_text_mode_with_gzip() {
        use asupersync::grpc::codec::gzip_frame_compress;

        // Build a gzip-compressed grpc-web stream in text mode.
        let payload = b"text-mode-gzip-payload-for-browser";
        let compressed = gzip_frame_compress(payload).unwrap();

        let codec = WebFrameCodec::new();
        let mut binary_buf = BytesMut::new();
        codec
            .encode_data(&compressed, true, &mut binary_buf)
            .unwrap();
        codec
            .encode_trailers(&Status::ok(), &Metadata::new(), &mut binary_buf)
            .unwrap();

        // Convert to text mode.
        let text = base64_encode(&binary_buf);

        // Decode from text mode.
        let binary = base64_decode(&text).unwrap();
        let mut decode_buf = BytesMut::from(binary.as_slice());

        // Verify data frame.
        let f1 = codec.decode(&mut decode_buf).unwrap().unwrap();
        match f1 {
            WebFrame::Data {
                compressed: c,
                data,
            } => {
                assert!(c, "compressed flag preserved through text mode");
                use asupersync::grpc::codec::gzip_frame_decompress;
                let decompressed = gzip_frame_decompress(&data, 4096).unwrap();
                assert_eq!(decompressed.as_ref(), payload.as_slice());
            }
            _ => panic!("expected data frame"),
        }

        // Verify trailer.
        let f2 = codec.decode(&mut decode_buf).unwrap().unwrap();
        assert!(matches!(f2, WebFrame::Trailers(_)), "trailer in text mode");
    }

    #[test]
    fn test_server_config_compression_defaults() {
        use asupersync::grpc::client::CompressionEncoding;
        use asupersync::grpc::server::ServerConfig;

        let config = ServerConfig::default();
        assert!(
            config.send_compression.is_none(),
            "no send compression by default"
        );
        assert_eq!(
            config.accept_compression,
            vec![CompressionEncoding::Identity],
            "accepts identity by default"
        );
    }

    #[test]
    fn test_server_builder_compression_config() {
        use asupersync::grpc::client::CompressionEncoding;
        use asupersync::grpc::server::ServerBuilder;

        let server = ServerBuilder::new()
            .send_compression(CompressionEncoding::Gzip)
            .accept_compressions([CompressionEncoding::Identity, CompressionEncoding::Gzip])
            .build();

        // Server was built without panic — configuration is valid.
        let _server = server;
    }

    #[test]
    fn test_grpc_codec_and_web_codec_frame_compatibility() {
        // Standard GrpcCodec data frames have the same binary format as
        // WebFrameCodec data frames — verify they can decode each other's output.
        let mut grpc_codec = GrpcCodec::new();
        let mut buf = BytesMut::new();

        let msg = GrpcMessage::new(Bytes::from_static(b"cross-codec-test"));
        grpc_codec.encode(msg, &mut buf).unwrap();

        // WebFrameCodec should decode the same bytes as a data frame.
        let web_codec = WebFrameCodec::new();
        let frame = web_codec.decode(&mut buf).unwrap().unwrap();
        match frame {
            WebFrame::Data { compressed, data } => {
                assert!(!compressed, "not compressed");
                assert_eq!(data.as_ref(), b"cross-codec-test", "data preserved");
            }
            _ => panic!("expected data frame from WebFrameCodec"),
        }
    }

    #[test]
    fn test_web_data_frame_decoded_by_grpc_codec() {
        // WebFrameCodec data frame should be decodable by GrpcCodec.
        let web_codec = WebFrameCodec::new();
        let mut buf = BytesMut::new();
        web_codec
            .encode_data(b"web-to-grpc", false, &mut buf)
            .unwrap();

        let mut grpc_codec = GrpcCodec::new();
        let msg = grpc_codec.decode(&mut buf).unwrap().unwrap();
        assert!(!msg.compressed);
        assert_eq!(msg.data.as_ref(), b"web-to-grpc");
    }

    #[test]
    fn test_max_message_size_honored_across_codecs() {
        // Both codecs should respect max size limits.
        let web_codec = WebFrameCodec::with_max_size(50);
        let mut buf = BytesMut::new();

        let result = web_codec.encode_data(&[0u8; 100], false, &mut buf);
        assert!(matches!(result, Err(GrpcError::MessageTooLarge)));

        let mut grpc_codec = GrpcCodec::with_max_size(50);
        let mut buf2 = BytesMut::new();
        let msg = GrpcMessage::new(Bytes::from(vec![0u8; 100]));
        let result2 = grpc_codec.encode(msg, &mut buf2);
        assert!(matches!(result2, Err(GrpcError::MessageTooLarge)));
    }
}
