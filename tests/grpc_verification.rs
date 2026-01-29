//! gRPC Framework Verification Suite
//!
//! Verifies the public API surface of the gRPC module:
//!   - Status codes and error handling (001-006)
//!   - Codec framing and serialization (007-012)
//!   - Streaming types and metadata (013-018)
//!   - Service descriptors and traits (019-022)
//!   - Health checking protocol (023-030)
//!   - Server infrastructure (031-034)
//!   - Client infrastructure (035-037)
//!   - Interceptor middleware (038-045)
//!
//! Bead: bd-hszn

#[macro_use]
mod common;

use common::init_test_logging;

use asupersync::bytes::{BufMut, Bytes, BytesMut};
use asupersync::codec::{Decoder, Encoder};
use asupersync::grpc::{
    auth_bearer_interceptor,
    auth_validator,
    fn_interceptor,
    logging_interceptor,
    metadata_propagator,
    rate_limiter,
    timeout_interceptor,
    trace_interceptor,
    Bidirectional,
    CallContext,
    // Client types
    Channel,
    ChannelConfig,
    ClientStreaming,
    // Status types
    Code,
    FramedCodec,
    GrpcClient,
    // Codec types
    GrpcCodec,
    GrpcError,
    GrpcMessage,
    HealthCheckRequest,
    HealthCheckResponse,
    HealthReporter,
    // Health types
    HealthService,
    HealthServiceBuilder,
    IdentityCodec,
    Interceptor,
    // Interceptor types
    InterceptorLayer,
    // Streaming types
    Metadata,
    MetadataValue,
    // Service types
    MethodDescriptor,
    NamedService,
    Request,
    Response,
    // Server types
    Server,
    ServerConfig,
    ServerStreaming,
    ServiceDescriptor,
    ServiceHandler,
    ServingStatus,
    Status,
    StreamingRequest,
};

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

fn init_test(name: &str) {
    init_test_logging();
    test_phase!(name);
}

// =============================================================================
// Status Codes and Error Handling (001-006)
// =============================================================================

/// GRPC-VERIFY-001: Status code round-trip through i32
///
/// All 17 gRPC codes should survive i32 conversion and unknown values map to Unknown.
#[test]
fn grpc_verify_001_code_i32_roundtrip() {
    init_test("grpc_verify_001_code_i32_roundtrip");

    let codes = [
        (0, Code::Ok),
        (1, Code::Cancelled),
        (2, Code::Unknown),
        (3, Code::InvalidArgument),
        (4, Code::DeadlineExceeded),
        (5, Code::NotFound),
        (6, Code::AlreadyExists),
        (7, Code::PermissionDenied),
        (8, Code::ResourceExhausted),
        (9, Code::FailedPrecondition),
        (10, Code::Aborted),
        (11, Code::OutOfRange),
        (12, Code::Unimplemented),
        (13, Code::Internal),
        (14, Code::Unavailable),
        (15, Code::DataLoss),
        (16, Code::Unauthenticated),
    ];

    for (i, expected) in &codes {
        let code = Code::from_i32(*i);
        assert_eq!(code, *expected, "Code::from_i32({i}) mismatch");
        assert_eq!(code.as_i32(), *i, "as_i32 roundtrip for {i}");
    }

    // Unknown values map to Unknown
    assert_eq!(Code::from_i32(-1), Code::Unknown);
    assert_eq!(Code::from_i32(99), Code::Unknown);
    assert_eq!(Code::from_i32(17), Code::Unknown);

    test_complete!("grpc_verify_001_code_i32_roundtrip");
}

/// GRPC-VERIFY-002: Status code canonical string names
///
/// Each code has a well-defined string representation matching the gRPC spec.
#[test]
fn grpc_verify_002_code_as_str() {
    init_test("grpc_verify_002_code_as_str");

    let expected = [
        (Code::Ok, "OK"),
        (Code::Cancelled, "CANCELLED"),
        (Code::Unknown, "UNKNOWN"),
        (Code::InvalidArgument, "INVALID_ARGUMENT"),
        (Code::DeadlineExceeded, "DEADLINE_EXCEEDED"),
        (Code::NotFound, "NOT_FOUND"),
        (Code::AlreadyExists, "ALREADY_EXISTS"),
        (Code::PermissionDenied, "PERMISSION_DENIED"),
        (Code::ResourceExhausted, "RESOURCE_EXHAUSTED"),
        (Code::FailedPrecondition, "FAILED_PRECONDITION"),
        (Code::Aborted, "ABORTED"),
        (Code::OutOfRange, "OUT_OF_RANGE"),
        (Code::Unimplemented, "UNIMPLEMENTED"),
        (Code::Internal, "INTERNAL"),
        (Code::Unavailable, "UNAVAILABLE"),
        (Code::DataLoss, "DATA_LOSS"),
        (Code::Unauthenticated, "UNAUTHENTICATED"),
    ];

    for (code, name) in &expected {
        assert_eq!(code.as_str(), *name);
        // Display should also produce the same string
        assert_eq!(format!("{code}"), *name);
    }

    test_complete!("grpc_verify_002_code_as_str");
}

/// GRPC-VERIFY-003: Status convenience constructors
///
/// Each named constructor produces a Status with the matching code.
#[test]
fn grpc_verify_003_status_constructors() {
    init_test("grpc_verify_003_status_constructors");

    let test_msg = "test message";

    assert_eq!(Status::ok().code(), Code::Ok);
    assert!(Status::ok().is_ok());

    assert_eq!(Status::cancelled(test_msg).code(), Code::Cancelled);
    assert_eq!(Status::unknown(test_msg).code(), Code::Unknown);
    assert_eq!(
        Status::invalid_argument(test_msg).code(),
        Code::InvalidArgument
    );
    assert_eq!(
        Status::deadline_exceeded(test_msg).code(),
        Code::DeadlineExceeded
    );
    assert_eq!(Status::not_found(test_msg).code(), Code::NotFound);
    assert_eq!(Status::already_exists(test_msg).code(), Code::AlreadyExists);
    assert_eq!(
        Status::permission_denied(test_msg).code(),
        Code::PermissionDenied
    );
    assert_eq!(
        Status::resource_exhausted(test_msg).code(),
        Code::ResourceExhausted
    );
    assert_eq!(
        Status::failed_precondition(test_msg).code(),
        Code::FailedPrecondition
    );
    assert_eq!(Status::aborted(test_msg).code(), Code::Aborted);
    assert_eq!(Status::out_of_range(test_msg).code(), Code::OutOfRange);
    assert_eq!(Status::unimplemented(test_msg).code(), Code::Unimplemented);
    assert_eq!(Status::internal(test_msg).code(), Code::Internal);
    assert_eq!(Status::unavailable(test_msg).code(), Code::Unavailable);
    assert_eq!(Status::data_loss(test_msg).code(), Code::DataLoss);
    assert_eq!(
        Status::unauthenticated(test_msg).code(),
        Code::Unauthenticated
    );

    // Message preserved
    let s = Status::not_found("entity xyz");
    assert_eq!(s.message(), "entity xyz");
    assert!(!s.is_ok());

    test_complete!("grpc_verify_003_status_constructors");
}

/// GRPC-VERIFY-004: Status with binary details
///
/// Status can carry optional binary details for rich error models.
#[test]
fn grpc_verify_004_status_with_details() {
    init_test("grpc_verify_004_status_with_details");

    let details = Bytes::from_static(b"\x08\x01\x12\x0bhello world");
    let status = Status::with_details(Code::Internal, "error occurred", details.clone());

    assert_eq!(status.code(), Code::Internal);
    assert_eq!(status.message(), "error occurred");
    assert_eq!(status.details(), Some(&details));

    // Without details
    let plain = Status::new(Code::Ok, "ok");
    assert!(plain.details().is_none());

    // Display format
    let display = format!("{status}");
    assert!(display.contains("INTERNAL"), "display: {display}");
    assert!(display.contains("error occurred"), "display: {display}");

    test_complete!("grpc_verify_004_status_with_details");
}

/// GRPC-VERIFY-005: GrpcError into_status conversion
///
/// Each GrpcError variant maps to an appropriate Status code.
#[test]
fn grpc_verify_005_grpc_error_into_status() {
    init_test("grpc_verify_005_grpc_error_into_status");

    // Status pass-through
    let status_err = GrpcError::Status(Status::cancelled("cancelled"));
    let s = status_err.into_status();
    assert_eq!(s.code(), Code::Cancelled);

    // Transport -> Unavailable
    let transport = GrpcError::transport("connection refused");
    let s = transport.into_status();
    assert_eq!(s.code(), Code::Unavailable);

    // Protocol -> Internal
    let protocol = GrpcError::protocol("bad frame");
    let s = protocol.into_status();
    assert_eq!(s.code(), Code::Internal);

    // MessageTooLarge -> ResourceExhausted
    let too_large = GrpcError::MessageTooLarge;
    let s = too_large.into_status();
    assert_eq!(s.code(), Code::ResourceExhausted);

    // InvalidMessage -> InvalidArgument
    let invalid = GrpcError::invalid_message("bad proto");
    let s = invalid.into_status();
    assert_eq!(s.code(), Code::InvalidArgument);

    // Compression -> Internal
    let compression = GrpcError::compression("zlib failed");
    let s = compression.into_status();
    assert_eq!(s.code(), Code::Internal);

    test_complete!("grpc_verify_005_grpc_error_into_status");
}

/// GRPC-VERIFY-006: Error type conversions (From impls)
///
/// Both Status and GrpcError implement From<io::Error> and GrpcError implements From<Status>.
#[test]
fn grpc_verify_006_error_conversions() {
    init_test("grpc_verify_006_error_conversions");

    // io::Error -> Status
    let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe broken");
    let status: Status = io_err.into();
    assert_eq!(status.code(), Code::Internal);
    assert!(status.message().contains("pipe broken"));

    // io::Error -> GrpcError
    let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
    let grpc_err: GrpcError = io_err.into();
    assert!(matches!(grpc_err, GrpcError::Transport(_)));

    // Status -> GrpcError
    let status = Status::not_found("missing");
    let grpc_err: GrpcError = status.into();
    assert!(matches!(grpc_err, GrpcError::Status(_)));

    // std::error::Error trait
    let status = Status::internal("oops");
    let _: &dyn std::error::Error = &status;
    let grpc_err = GrpcError::MessageTooLarge;
    let _: &dyn std::error::Error = &grpc_err;

    test_complete!("grpc_verify_006_error_conversions");
}

// =============================================================================
// Codec Framing and Serialization (007-012)
// =============================================================================

/// GRPC-VERIFY-007: GrpcCodec encode/decode roundtrip
///
/// An encoded message should decode back to the original data.
#[test]
fn grpc_verify_007_codec_roundtrip() {
    init_test("grpc_verify_007_codec_roundtrip");

    let mut codec = GrpcCodec::new();
    let mut buf = BytesMut::new();

    let original = GrpcMessage::new(Bytes::from_static(b"hello gRPC world"));
    codec.encode(original.clone(), &mut buf).unwrap();

    // Buffer should contain 5 header bytes + payload
    assert_eq!(buf.len(), 5 + b"hello gRPC world".len());

    let decoded = codec.decode(&mut buf).unwrap().unwrap();
    assert!(!decoded.compressed);
    assert_eq!(decoded.data, original.data);
    assert!(buf.is_empty(), "buffer should be fully consumed");

    test_complete!("grpc_verify_007_codec_roundtrip");
}

/// GRPC-VERIFY-008: GrpcCodec compressed flag
///
/// The compressed flag should be preserved through encode/decode.
#[test]
fn grpc_verify_008_codec_compressed_flag() {
    init_test("grpc_verify_008_codec_compressed_flag");

    let mut codec = GrpcCodec::new();
    let mut buf = BytesMut::new();

    let msg = GrpcMessage::compressed(Bytes::from_static(b"compressed data"));
    codec.encode(msg, &mut buf).unwrap();

    let decoded = codec.decode(&mut buf).unwrap().unwrap();
    assert!(decoded.compressed, "compressed flag should be set");
    assert_eq!(decoded.data, Bytes::from_static(b"compressed data"));

    test_complete!("grpc_verify_008_codec_compressed_flag");
}

/// GRPC-VERIFY-009: GrpcCodec max message size enforcement
///
/// Messages exceeding the configured max size should be rejected on both encode and decode.
#[test]
fn grpc_verify_009_codec_max_message_size() {
    init_test("grpc_verify_009_codec_max_message_size");

    let mut codec = GrpcCodec::with_max_size(100);
    assert_eq!(codec.max_message_size(), 100);

    // Encode too-large message
    let large = GrpcMessage::new(Bytes::from(vec![0u8; 200]));
    let mut buf = BytesMut::new();
    let err = codec.encode(large, &mut buf);
    assert!(matches!(err, Err(GrpcError::MessageTooLarge)));

    // Decode too-large message (craft a header with length > max)
    let mut buf = BytesMut::new();
    buf.put_u8(0); // not compressed
    buf.put_u32(200); // length exceeds max
    buf.extend_from_slice(&vec![0u8; 200]);
    let err = codec.decode(&mut buf);
    assert!(matches!(err, Err(GrpcError::MessageTooLarge)));

    test_complete!("grpc_verify_009_codec_max_message_size");
}

/// GRPC-VERIFY-010: GrpcCodec partial data handling
///
/// Incomplete headers or bodies should return Ok(None) without consuming data.
#[test]
fn grpc_verify_010_codec_partial_data() {
    init_test("grpc_verify_010_codec_partial_data");

    let mut codec = GrpcCodec::new();

    // Empty buffer
    let mut buf = BytesMut::new();
    assert!(codec.decode(&mut buf).unwrap().is_none());

    // Partial header (< 5 bytes)
    let mut buf = BytesMut::from(&[0u8, 0, 0][..]);
    assert!(codec.decode(&mut buf).unwrap().is_none());
    assert_eq!(buf.len(), 3, "partial header should not be consumed");

    // Complete header but incomplete body
    let mut buf = BytesMut::new();
    buf.put_u8(0);
    buf.put_u32(10); // expects 10 bytes
    buf.extend_from_slice(&[1, 2, 3]); // only 3
    assert!(codec.decode(&mut buf).unwrap().is_none());
    assert_eq!(buf.len(), 8, "incomplete message should not be consumed");

    test_complete!("grpc_verify_010_codec_partial_data");
}

/// GRPC-VERIFY-011: IdentityCodec pass-through
///
/// IdentityCodec should pass Bytes through unchanged.
#[test]
fn grpc_verify_011_identity_codec() {
    init_test("grpc_verify_011_identity_codec");

    use asupersync::grpc::codec::Codec;

    let mut codec = IdentityCodec;
    let data = Bytes::from_static(b"raw bytes");

    let encoded = codec.encode(&data).unwrap();
    assert_eq!(encoded, data);

    let decoded = codec.decode(&encoded).unwrap();
    assert_eq!(decoded, data);

    test_complete!("grpc_verify_011_identity_codec");
}

/// GRPC-VERIFY-012: FramedCodec encode/decode roundtrip
///
/// FramedCodec wraps an inner codec with gRPC framing.
#[test]
fn grpc_verify_012_framed_codec_roundtrip() {
    init_test("grpc_verify_012_framed_codec_roundtrip");

    let mut codec = FramedCodec::new(IdentityCodec);
    let mut buf = BytesMut::new();

    let original = Bytes::from_static(b"framed message");
    codec.encode_message(&original, &mut buf).unwrap();

    let decoded = codec.decode_message(&mut buf).unwrap().unwrap();
    assert_eq!(decoded, original);

    // Verify inner access
    let _ = codec.inner();
    let _ = codec.inner_mut();

    // Custom max size
    let mut codec = FramedCodec::with_max_size(IdentityCodec, 50);
    let mut buf = BytesMut::new();
    let large = Bytes::from(vec![0u8; 100]);
    let err = codec.encode_message(&large, &mut buf);
    assert!(err.is_err(), "should reject message exceeding max size");

    test_complete!("grpc_verify_012_framed_codec_roundtrip");
}

// =============================================================================
// Streaming Types and Metadata (013-018)
// =============================================================================

/// GRPC-VERIFY-013: Request creation and accessors
///
/// Request wraps a message with metadata and provides map/into_inner.
#[test]
fn grpc_verify_013_request_basics() {
    init_test("grpc_verify_013_request_basics");

    // Basic creation
    let req = Request::new(42);
    assert_eq!(*req.get_ref(), 42);
    assert!(req.metadata().is_empty());

    // With metadata
    let mut meta = Metadata::new();
    meta.insert("x-key", "value");
    let req = Request::with_metadata("hello", meta);
    assert_eq!(*req.get_ref(), "hello");
    assert!(!req.metadata().is_empty());

    // Mutable access
    let mut req = Request::new(10);
    *req.get_mut() = 20;
    assert_eq!(*req.get_ref(), 20);
    req.metadata_mut().insert("new-key", "new-value");
    assert!(req.metadata().get("new-key").is_some());

    // Map
    let req = Request::new(5);
    let mapped = req.map(|n| n * 3);
    assert_eq!(mapped.into_inner(), 15);

    test_complete!("grpc_verify_013_request_basics");
}

/// GRPC-VERIFY-014: Response creation and accessors
///
/// Response mirrors Request's API for the response side.
#[test]
fn grpc_verify_014_response_basics() {
    init_test("grpc_verify_014_response_basics");

    let resp = Response::new("world");
    assert_eq!(*resp.get_ref(), "world");
    assert!(resp.metadata().is_empty());

    let mut meta = Metadata::new();
    meta.insert("x-resp", "ok");
    let resp = Response::with_metadata(100, meta);
    assert_eq!(*resp.get_ref(), 100);
    assert!(resp.metadata().get("x-resp").is_some());

    let mut resp = Response::new(7);
    *resp.get_mut() = 14;
    assert_eq!(*resp.get_ref(), 14);

    let resp = Response::new(3);
    let mapped = resp.map(|n| format!("value={n}"));
    assert_eq!(mapped.into_inner(), "value=3");

    test_complete!("grpc_verify_014_response_basics");
}

/// GRPC-VERIFY-015: Metadata ASCII and binary operations
///
/// Metadata supports ASCII and binary values with lookup, iteration, and size queries.
#[test]
fn grpc_verify_015_metadata_operations() {
    init_test("grpc_verify_015_metadata_operations");

    let mut meta = Metadata::new();
    assert!(meta.is_empty());
    assert_eq!(meta.len(), 0);

    // ASCII insert and get
    meta.insert("content-type", "application/grpc");
    meta.insert("x-custom", "value");
    assert_eq!(meta.len(), 2);
    assert!(!meta.is_empty());

    match meta.get("content-type") {
        Some(MetadataValue::Ascii(s)) => assert_eq!(s, "application/grpc"),
        other => panic!("expected ASCII value, got: {other:?}"),
    }

    // Binary insert and get
    meta.insert_bin("data-bin", Bytes::from_static(b"\x00\x01\x02\xff"));
    assert_eq!(meta.len(), 3);

    match meta.get("data-bin") {
        Some(MetadataValue::Binary(b)) => assert_eq!(b.as_ref(), &[0, 1, 2, 255]),
        other => panic!("expected Binary value, got: {other:?}"),
    }

    // Missing key
    assert!(meta.get("nonexistent").is_none());

    // Iteration
    let keys: Vec<&str> = meta.iter().map(|(k, _)| k).collect();
    assert_eq!(keys.len(), 3);
    assert!(keys.contains(&"content-type"));
    assert!(keys.contains(&"x-custom"));
    assert!(keys.contains(&"data-bin"));

    // Clone
    let meta2 = meta.clone();
    assert_eq!(meta2.len(), 3);

    test_complete!("grpc_verify_015_metadata_operations");
}

/// GRPC-VERIFY-016: StreamingRequest poll_next placeholder
///
/// StreamingRequest's placeholder impl returns None immediately.
#[test]
fn grpc_verify_016_streaming_request_placeholder() {
    init_test("grpc_verify_016_streaming_request_placeholder");

    use asupersync::grpc::Streaming;

    let waker = futures_lite::future::block_on(async {
        // StreamingRequest default
        let _sr: StreamingRequest<String> = StreamingRequest::default();
    });
    let _ = waker;

    // Poll directly
    let mut sr = StreamingRequest::<i32>::new();
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let result = Pin::new(&mut sr).poll_next(&mut cx);
    assert!(matches!(result, Poll::Ready(None)));

    test_complete!("grpc_verify_016_streaming_request_placeholder");
}

/// GRPC-VERIFY-017: Bidirectional and ClientStreaming construction
///
/// Generic streaming types can be constructed and have correct defaults.
#[test]
fn grpc_verify_017_streaming_type_construction() {
    init_test("grpc_verify_017_streaming_type_construction");

    let _bidi: Bidirectional<String, i32> = Bidirectional::new();
    let _bidi_default: Bidirectional<u8, u8> = Bidirectional::default();

    let _cs: ClientStreaming<String> = ClientStreaming::new();
    let _cs_default: ClientStreaming<i32> = ClientStreaming::default();

    test_complete!("grpc_verify_017_streaming_type_construction");
}

/// GRPC-VERIFY-018: ServerStreaming delegates to inner stream
///
/// ServerStreaming wraps an inner Streaming impl and delegates poll_next.
#[test]
fn grpc_verify_018_server_streaming_delegation() {
    init_test("grpc_verify_018_server_streaming_delegation");

    use asupersync::grpc::Streaming;

    // Use StreamingRequest as inner (returns None immediately)
    let inner = StreamingRequest::<i32>::new();
    let mut ss = ServerStreaming::new(inner);

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let result = Pin::new(&mut ss).poll_next(&mut cx);
    assert!(matches!(result, Poll::Ready(None)));

    // Access inner
    let _ = ss.get_ref();
    let _ = ss.get_mut();
    let _inner = ss.into_inner();

    test_complete!("grpc_verify_018_server_streaming_delegation");
}

// =============================================================================
// Service Descriptors and Traits (019-022)
// =============================================================================

/// GRPC-VERIFY-019: MethodDescriptor streaming patterns
///
/// Each factory method sets the correct streaming flags.
#[test]
fn grpc_verify_019_method_descriptor_patterns() {
    init_test("grpc_verify_019_method_descriptor_patterns");

    let unary = MethodDescriptor::unary("Get", "/pkg.Svc/Get");
    assert!(unary.is_unary());
    assert!(!unary.client_streaming);
    assert!(!unary.server_streaming);
    assert_eq!(unary.name, "Get");
    assert_eq!(unary.path, "/pkg.Svc/Get");

    let server = MethodDescriptor::server_streaming("List", "/pkg.Svc/List");
    assert!(!server.is_unary());
    assert!(!server.client_streaming);
    assert!(server.server_streaming);

    let client = MethodDescriptor::client_streaming("Upload", "/pkg.Svc/Upload");
    assert!(!client.is_unary());
    assert!(client.client_streaming);
    assert!(!client.server_streaming);

    let bidi = MethodDescriptor::bidi_streaming("Chat", "/pkg.Svc/Chat");
    assert!(!bidi.is_unary());
    assert!(bidi.client_streaming);
    assert!(bidi.server_streaming);

    test_complete!("grpc_verify_019_method_descriptor_patterns");
}

/// GRPC-VERIFY-020: ServiceDescriptor full_name
///
/// full_name concatenates package and name, or returns name alone if no package.
#[test]
fn grpc_verify_020_service_descriptor_full_name() {
    init_test("grpc_verify_020_service_descriptor_full_name");

    static METHODS: &[MethodDescriptor] = &[MethodDescriptor::unary("Get", "/test.Svc/Get")];

    let desc = ServiceDescriptor::new("Greeter", "helloworld", METHODS);
    assert_eq!(desc.full_name(), "helloworld.Greeter");
    assert_eq!(desc.methods.len(), 1);

    let desc = ServiceDescriptor::new("StandaloneService", "", &[]);
    assert_eq!(desc.full_name(), "StandaloneService");

    test_complete!("grpc_verify_020_service_descriptor_full_name");
}

/// GRPC-VERIFY-021: HealthService implements NamedService and ServiceHandler
///
/// The HealthService has the correct gRPC health checking service name and methods.
#[test]
fn grpc_verify_021_health_service_traits() {
    init_test("grpc_verify_021_health_service_traits");

    assert_eq!(HealthService::NAME, "grpc.health.v1.Health");

    let svc = HealthService::new();
    let desc = svc.descriptor();
    assert_eq!(desc.name, "Health");
    assert_eq!(desc.package, "grpc.health.v1");
    assert_eq!(desc.methods.len(), 2);

    let names = svc.method_names();
    assert!(names.contains(&"Check"));
    assert!(names.contains(&"Watch"));

    test_complete!("grpc_verify_021_health_service_traits");
}

/// GRPC-VERIFY-022: MethodDescriptor Clone and Debug
///
/// Descriptors are Clone and Debug for use in service registries.
#[test]
fn grpc_verify_022_descriptor_clone_debug() {
    init_test("grpc_verify_022_descriptor_clone_debug");

    let md = MethodDescriptor::unary("Ping", "/test.Svc/Ping");
    let md2 = md.clone();
    assert_eq!(md.name, md2.name);
    assert_eq!(md.path, md2.path);
    let debug = format!("{md:?}");
    assert!(debug.contains("Ping"));

    let sd = ServiceDescriptor::new("TestSvc", "test", &[]);
    let sd2 = sd.clone();
    assert_eq!(sd.name, sd2.name);
    let debug = format!("{sd:?}");
    assert!(debug.contains("TestSvc"));

    test_complete!("grpc_verify_022_descriptor_clone_debug");
}

// =============================================================================
// Health Checking Protocol (023-030)
// =============================================================================

/// GRPC-VERIFY-023: ServingStatus enum coverage
///
/// All four variants have correct i32 mapping, is_healthy, and Display.
#[test]
fn grpc_verify_023_serving_status_enum() {
    init_test("grpc_verify_023_serving_status_enum");

    // from_i32
    assert_eq!(ServingStatus::from_i32(0), Some(ServingStatus::Unknown));
    assert_eq!(ServingStatus::from_i32(1), Some(ServingStatus::Serving));
    assert_eq!(ServingStatus::from_i32(2), Some(ServingStatus::NotServing));
    assert_eq!(
        ServingStatus::from_i32(3),
        Some(ServingStatus::ServiceUnknown)
    );
    assert_eq!(ServingStatus::from_i32(4), None);
    assert_eq!(ServingStatus::from_i32(-1), None);

    // is_healthy
    assert!(!ServingStatus::Unknown.is_healthy());
    assert!(ServingStatus::Serving.is_healthy());
    assert!(!ServingStatus::NotServing.is_healthy());
    assert!(!ServingStatus::ServiceUnknown.is_healthy());

    // Display
    assert_eq!(ServingStatus::Unknown.to_string(), "UNKNOWN");
    assert_eq!(ServingStatus::Serving.to_string(), "SERVING");
    assert_eq!(ServingStatus::NotServing.to_string(), "NOT_SERVING");
    assert_eq!(ServingStatus::ServiceUnknown.to_string(), "SERVICE_UNKNOWN");

    // Default
    assert_eq!(ServingStatus::default(), ServingStatus::Unknown);

    test_complete!("grpc_verify_023_serving_status_enum");
}

/// GRPC-VERIFY-024: HealthService set/get/clear lifecycle
///
/// Services can be registered, updated, cleared individually or globally.
#[test]
fn grpc_verify_024_health_service_lifecycle() {
    init_test("grpc_verify_024_health_service_lifecycle");

    let svc = HealthService::new();

    // Initially no services
    assert!(svc.get_status("test").is_none());
    assert!(!svc.is_serving("test"));
    assert!(svc.services().is_empty());

    // Set status
    svc.set_status("svc.A", ServingStatus::Serving);
    svc.set_status("svc.B", ServingStatus::NotServing);
    assert_eq!(svc.get_status("svc.A"), Some(ServingStatus::Serving));
    assert_eq!(svc.get_status("svc.B"), Some(ServingStatus::NotServing));
    assert!(svc.is_serving("svc.A"));
    assert!(!svc.is_serving("svc.B"));

    let services = svc.services();
    assert_eq!(services.len(), 2);

    // Update status
    svc.set_status("svc.A", ServingStatus::NotServing);
    assert_eq!(svc.get_status("svc.A"), Some(ServingStatus::NotServing));

    // Clear one
    svc.clear_status("svc.A");
    assert!(svc.get_status("svc.A").is_none());
    assert!(svc.get_status("svc.B").is_some());

    // Clear all
    svc.clear();
    assert!(svc.services().is_empty());

    test_complete!("grpc_verify_024_health_service_lifecycle");
}

/// GRPC-VERIFY-025: HealthService check() logic
///
/// check() returns the status for registered services, derives server status,
/// and returns NotFound for unknown services.
#[test]
fn grpc_verify_025_health_check_logic() {
    init_test("grpc_verify_025_health_check_logic");

    let svc = HealthService::new();

    // No services registered: server check returns ServiceUnknown
    let resp = svc.check(&HealthCheckRequest::server()).unwrap();
    assert_eq!(resp.status, ServingStatus::ServiceUnknown);

    // Register a healthy service
    svc.set_status("db", ServingStatus::Serving);
    let resp = svc.check(&HealthCheckRequest::new("db")).unwrap();
    assert_eq!(resp.status, ServingStatus::Serving);

    // Server status derived from all services (all healthy)
    let resp = svc.check(&HealthCheckRequest::server()).unwrap();
    assert_eq!(resp.status, ServingStatus::Serving);

    // Add an unhealthy service -> server becomes NotServing
    svc.set_status("cache", ServingStatus::NotServing);
    let resp = svc.check(&HealthCheckRequest::server()).unwrap();
    assert_eq!(resp.status, ServingStatus::NotServing);

    // Explicit server status overrides
    svc.set_server_status(ServingStatus::Serving);
    let resp = svc.check(&HealthCheckRequest::server()).unwrap();
    assert_eq!(resp.status, ServingStatus::Serving);

    // Unknown service returns NotFound error
    let err = svc
        .check(&HealthCheckRequest::new("nonexistent"))
        .unwrap_err();
    assert_eq!(err.code(), Code::NotFound);

    test_complete!("grpc_verify_025_health_check_logic");
}

/// GRPC-VERIFY-026: HealthService clone shares state
///
/// Cloned HealthService instances share the same backing Arc<RwLock<_>>.
#[test]
fn grpc_verify_026_health_service_clone() {
    init_test("grpc_verify_026_health_service_clone");

    let svc1 = HealthService::new();
    let svc2 = svc1.clone();

    svc1.set_status("shared", ServingStatus::Serving);
    assert_eq!(svc2.get_status("shared"), Some(ServingStatus::Serving));

    svc2.set_status("shared", ServingStatus::NotServing);
    assert_eq!(svc1.get_status("shared"), Some(ServingStatus::NotServing));

    test_complete!("grpc_verify_026_health_service_clone");
}

/// GRPC-VERIFY-027: HealthReporter lifecycle management
///
/// HealthReporter tracks a single service and clears status on drop.
#[test]
fn grpc_verify_027_health_reporter() {
    init_test("grpc_verify_027_health_reporter");

    let svc = HealthService::new();

    {
        let reporter = HealthReporter::new(svc.clone(), "my.Service");
        assert_eq!(reporter.status(), ServingStatus::Unknown);

        reporter.set_serving();
        assert_eq!(reporter.status(), ServingStatus::Serving);
        assert!(svc.is_serving("my.Service"));

        reporter.set_not_serving();
        assert_eq!(reporter.status(), ServingStatus::NotServing);
        assert!(!svc.is_serving("my.Service"));
    }

    // Status cleared on reporter drop
    assert!(svc.get_status("my.Service").is_none());

    test_complete!("grpc_verify_027_health_reporter");
}

/// GRPC-VERIFY-028: HealthServiceBuilder
///
/// Builder pattern for creating pre-configured health services.
#[test]
fn grpc_verify_028_health_service_builder() {
    init_test("grpc_verify_028_health_service_builder");

    let svc = HealthServiceBuilder::new()
        .add("explicit", ServingStatus::NotServing)
        .add_serving(["svc.A", "svc.B", "svc.C"])
        .build();

    assert_eq!(svc.get_status("explicit"), Some(ServingStatus::NotServing));
    assert_eq!(svc.get_status("svc.A"), Some(ServingStatus::Serving));
    assert_eq!(svc.get_status("svc.B"), Some(ServingStatus::Serving));
    assert_eq!(svc.get_status("svc.C"), Some(ServingStatus::Serving));
    assert_eq!(svc.services().len(), 4);

    test_complete!("grpc_verify_028_health_service_builder");
}

/// GRPC-VERIFY-029: HealthCheckRequest constructors
///
/// Verifies named service and server-level request constructors.
#[test]
fn grpc_verify_029_health_check_request() {
    init_test("grpc_verify_029_health_check_request");

    let req = HealthCheckRequest::new("my.Service");
    assert_eq!(req.service, "my.Service");

    let req = HealthCheckRequest::server();
    assert!(req.service.is_empty());

    let req = HealthCheckRequest::default();
    assert!(req.service.is_empty());

    test_complete!("grpc_verify_029_health_check_request");
}

/// GRPC-VERIFY-030: HealthCheckResponse construction
///
/// Verifies response creation and default.
#[test]
fn grpc_verify_030_health_check_response() {
    init_test("grpc_verify_030_health_check_response");

    let resp = HealthCheckResponse::new(ServingStatus::Serving);
    assert_eq!(resp.status, ServingStatus::Serving);

    let resp = HealthCheckResponse::default();
    assert_eq!(resp.status, ServingStatus::Unknown);

    test_complete!("grpc_verify_030_health_check_response");
}

// =============================================================================
// Server Infrastructure (031-034)
// =============================================================================

/// GRPC-VERIFY-031: ServerConfig defaults
///
/// Default configuration follows gRPC conventions.
#[test]
fn grpc_verify_031_server_config_defaults() {
    init_test("grpc_verify_031_server_config_defaults");

    let config = ServerConfig::default();
    assert_eq!(config.max_recv_message_size, 4 * 1024 * 1024);
    assert_eq!(config.max_send_message_size, 4 * 1024 * 1024);
    assert_eq!(config.initial_connection_window_size, 1024 * 1024);
    assert_eq!(config.initial_stream_window_size, 1024 * 1024);
    assert_eq!(config.max_concurrent_streams, 100);
    assert!(config.keepalive_interval_ms.is_none());
    assert!(config.keepalive_timeout_ms.is_none());

    test_complete!("grpc_verify_031_server_config_defaults");
}

/// GRPC-VERIFY-032: Server builder and service registration
///
/// Services are registered by NamedService::NAME and accessible via get_service.
#[test]
fn grpc_verify_032_server_builder() {
    init_test("grpc_verify_032_server_builder");

    let health = HealthService::new();

    let server = Server::builder()
        .max_recv_message_size(8 * 1024 * 1024)
        .max_send_message_size(2 * 1024 * 1024)
        .max_concurrent_streams(200)
        .initial_connection_window_size(2 * 1024 * 1024)
        .initial_stream_window_size(512 * 1024)
        .keepalive_interval(30_000)
        .keepalive_timeout(10_000)
        .add_service(health)
        .build();

    assert_eq!(server.config().max_recv_message_size, 8 * 1024 * 1024);
    assert_eq!(server.config().max_send_message_size, 2 * 1024 * 1024);
    assert_eq!(server.config().max_concurrent_streams, 200);
    assert_eq!(server.config().keepalive_interval_ms, Some(30_000));
    assert_eq!(server.config().keepalive_timeout_ms, Some(10_000));

    assert!(server.get_service("grpc.health.v1.Health").is_some());
    assert!(server.get_service("nonexistent").is_none());

    let names = server.service_names();
    assert!(names.contains(&"grpc.health.v1.Health"));

    test_complete!("grpc_verify_032_server_builder");
}

/// GRPC-VERIFY-033: CallContext accessors
///
/// CallContext provides metadata, deadline, and peer address info.
#[test]
fn grpc_verify_033_call_context() {
    init_test("grpc_verify_033_call_context");

    let ctx = CallContext::new();
    assert!(ctx.metadata().is_empty());
    assert!(ctx.deadline().is_none());
    assert!(ctx.peer_addr().is_none());
    assert!(!ctx.is_expired());

    let ctx2 = CallContext::default();
    assert!(ctx2.metadata().is_empty());

    test_complete!("grpc_verify_033_call_context");
}

/// GRPC-VERIFY-034: NoopInterceptor pass-through
///
/// NoopInterceptor accepts all requests and responses without modification.
#[test]
fn grpc_verify_034_noop_interceptor() {
    init_test("grpc_verify_034_noop_interceptor");

    use asupersync::grpc::server::NoopInterceptor;

    let interceptor = NoopInterceptor;
    let mut request = Request::new(Bytes::new());
    assert!(interceptor.intercept_request(&mut request).is_ok());

    let mut response = Response::new(Bytes::new());
    assert!(interceptor.intercept_response(&mut response).is_ok());

    test_complete!("grpc_verify_034_noop_interceptor");
}

// =============================================================================
// Client Infrastructure (035-037)
// =============================================================================

/// GRPC-VERIFY-035: ChannelConfig defaults
///
/// Default channel configuration follows gRPC conventions.
#[test]
fn grpc_verify_035_channel_config_defaults() {
    init_test("grpc_verify_035_channel_config_defaults");

    let config = ChannelConfig::default();
    assert_eq!(config.connect_timeout, Duration::from_secs(5));
    assert!(config.timeout.is_none());
    assert_eq!(config.max_recv_message_size, 4 * 1024 * 1024);
    assert_eq!(config.max_send_message_size, 4 * 1024 * 1024);
    assert!(!config.use_tls);
    assert!(config.keepalive_interval.is_none());
    assert!(config.keepalive_timeout.is_none());

    test_complete!("grpc_verify_035_channel_config_defaults");
}

/// GRPC-VERIFY-036: ChannelBuilder configuration
///
/// Builder methods correctly configure channel settings.
#[test]
fn grpc_verify_036_channel_builder() {
    init_test("grpc_verify_036_channel_builder");

    let builder = Channel::builder("http://localhost:50051")
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .max_recv_message_size(8 * 1024 * 1024)
        .max_send_message_size(2 * 1024 * 1024)
        .initial_connection_window_size(2 * 1024 * 1024)
        .initial_stream_window_size(512 * 1024)
        .keepalive_interval(Duration::from_secs(60))
        .keepalive_timeout(Duration::from_secs(20))
        .tls();

    // ChannelBuilder has a public config field based on the test patterns
    // Connect produces a Channel
    futures_lite::future::block_on(async {
        let channel = builder.connect().await.unwrap();
        assert_eq!(channel.uri(), "http://localhost:50051");
        assert!(channel.config().use_tls);
        assert_eq!(channel.config().connect_timeout, Duration::from_secs(10));
    });

    test_complete!("grpc_verify_036_channel_builder");
}

/// GRPC-VERIFY-037: GrpcClient creation and unary call
///
/// GrpcClient wraps a Channel; unary calls currently return Unimplemented.
#[test]
fn grpc_verify_037_grpc_client() {
    init_test("grpc_verify_037_grpc_client");

    futures_lite::future::block_on(async {
        let channel = Channel::connect("http://localhost:50051").await.unwrap();
        let mut client = GrpcClient::new(channel.clone());
        assert_eq!(client.channel().uri(), "http://localhost:50051");

        // Unary call returns Unimplemented (placeholder)
        let err: Result<Response<String>, Status> = client
            .unary("/test.Svc/Method", Request::new("hello".to_string()))
            .await;
        assert_eq!(err.unwrap_err().code(), Code::Unimplemented);
    });

    test_complete!("grpc_verify_037_grpc_client");
}

// =============================================================================
// Interceptor Middleware (038-045)
// =============================================================================

/// GRPC-VERIFY-038: InterceptorLayer composition
///
/// Layers compose multiple interceptors; requests flow forward, responses reverse.
#[test]
fn grpc_verify_038_interceptor_layer_composition() {
    init_test("grpc_verify_038_interceptor_layer_composition");

    let layer = InterceptorLayer::new();
    assert!(layer.is_empty());
    assert_eq!(layer.len(), 0);

    let layer = InterceptorLayer::new()
        .layer(trace_interceptor())
        .layer(logging_interceptor())
        .layer(timeout_interceptor(5000));

    assert!(!layer.is_empty());
    assert_eq!(layer.len(), 3);

    // Apply to request - should add x-request-id, x-logged, grpc-timeout
    let mut request = Request::new(Bytes::new());
    layer.intercept_request(&mut request).unwrap();
    assert!(request.metadata().get("x-request-id").is_some());
    assert!(request.metadata().get("x-logged").is_some());
    assert!(request.metadata().get("grpc-timeout").is_some());

    // Apply to response - logging interceptor should mark response
    let mut response = Response::new(Bytes::new());
    layer.intercept_response(&mut response).unwrap();
    assert!(response.metadata().get("x-logged").is_some());

    test_complete!("grpc_verify_038_interceptor_layer_composition");
}

/// GRPC-VERIFY-039: BearerAuth interceptor and validator
///
/// Auth interceptor adds tokens; validator checks them.
#[test]
fn grpc_verify_039_bearer_auth() {
    init_test("grpc_verify_039_bearer_auth");

    // Add token to outgoing request
    let interceptor = auth_bearer_interceptor("secret-token");
    let mut request = Request::new(Bytes::new());
    interceptor.intercept_request(&mut request).unwrap();

    match request.metadata().get("authorization") {
        Some(MetadataValue::Ascii(s)) => assert_eq!(s, "Bearer secret-token"),
        other => panic!("expected Bearer token, got: {other:?}"),
    }

    // Validate token on incoming request
    let validator = auth_validator(|token| token == "secret-token");

    // Valid token
    let mut req = Request::new(Bytes::new());
    req.metadata_mut()
        .insert("authorization", "Bearer secret-token");
    assert!(validator.intercept_request(&mut req).is_ok());

    // Invalid token
    let mut req = Request::new(Bytes::new());
    req.metadata_mut()
        .insert("authorization", "Bearer wrong-token");
    let err = validator.intercept_request(&mut req).unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated);

    // Missing authorization header
    let mut req = Request::new(Bytes::new());
    let err = validator.intercept_request(&mut req).unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated);

    // Bad format (no "Bearer " prefix)
    let mut req = Request::new(Bytes::new());
    req.metadata_mut().insert("authorization", "Basic abc");
    let err = validator.intercept_request(&mut req).unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated);

    test_complete!("grpc_verify_039_bearer_auth");
}

/// GRPC-VERIFY-040: FnInterceptor custom logic
///
/// Function-based interceptors can modify requests with custom logic.
#[test]
fn grpc_verify_040_fn_interceptor() {
    init_test("grpc_verify_040_fn_interceptor");

    let interceptor = fn_interceptor(|request: &mut Request<Bytes>| {
        request.metadata_mut().insert("x-fn-interceptor", "applied");
        Ok(())
    });

    let mut request = Request::new(Bytes::new());
    interceptor.intercept_request(&mut request).unwrap();

    match request.metadata().get("x-fn-interceptor") {
        Some(MetadataValue::Ascii(s)) => assert_eq!(s, "applied"),
        other => panic!("expected ASCII value, got: {other:?}"),
    }

    // FnInterceptor response is no-op
    let mut response = Response::new(Bytes::new());
    interceptor.intercept_response(&mut response).unwrap();
    assert!(response.metadata().is_empty());

    test_complete!("grpc_verify_040_fn_interceptor");
}

/// GRPC-VERIFY-041: RateLimitInterceptor enforcement
///
/// Rate limiter allows requests under the limit and rejects excess.
#[test]
fn grpc_verify_041_rate_limit_interceptor() {
    init_test("grpc_verify_041_rate_limit_interceptor");

    let limiter = rate_limiter(3);
    assert_eq!(limiter.current_count(), 0);

    // Allow 3 requests
    for i in 0..3 {
        let mut req = Request::new(Bytes::new());
        limiter
            .intercept_request(&mut req)
            .unwrap_or_else(|_| panic!("request {i} should succeed"));
    }
    assert_eq!(limiter.current_count(), 3);

    // 4th request rejected
    let mut req = Request::new(Bytes::new());
    let err = limiter.intercept_request(&mut req).unwrap_err();
    assert_eq!(err.code(), Code::ResourceExhausted);

    // Reset allows new requests
    limiter.reset();
    assert_eq!(limiter.current_count(), 0);
    let mut req = Request::new(Bytes::new());
    assert!(limiter.intercept_request(&mut req).is_ok());

    test_complete!("grpc_verify_041_rate_limit_interceptor");
}

/// GRPC-VERIFY-042: TracingInterceptor request ID generation
///
/// Tracing interceptor generates unique-ish request IDs.
#[test]
fn grpc_verify_042_tracing_interceptor() {
    init_test("grpc_verify_042_tracing_interceptor");

    let interceptor = trace_interceptor();

    let mut req1 = Request::new(Bytes::new());
    interceptor.intercept_request(&mut req1).unwrap();
    let id1 = match req1.metadata().get("x-request-id") {
        Some(MetadataValue::Ascii(s)) => s.clone(),
        other => panic!("expected ASCII, got: {other:?}"),
    };
    assert!(id1.starts_with("req-"));

    // Existing request ID is preserved
    let mut req2 = Request::new(Bytes::new());
    req2.metadata_mut().insert("x-request-id", "custom-id");
    interceptor.intercept_request(&mut req2).unwrap();
    match req2.metadata().get("x-request-id") {
        Some(MetadataValue::Ascii(s)) => assert_eq!(s, "custom-id"),
        other => panic!("expected custom-id, got: {other:?}"),
    }

    test_complete!("grpc_verify_042_tracing_interceptor");
}

/// GRPC-VERIFY-043: TimeoutInterceptor grpc-timeout header
///
/// Timeout interceptor adds grpc-timeout header if not already present.
#[test]
fn grpc_verify_043_timeout_interceptor() {
    init_test("grpc_verify_043_timeout_interceptor");

    let interceptor = timeout_interceptor(5000);

    // Adds header when missing
    let mut req = Request::new(Bytes::new());
    interceptor.intercept_request(&mut req).unwrap();
    match req.metadata().get("grpc-timeout") {
        Some(MetadataValue::Ascii(s)) => assert_eq!(s, "5000m"),
        other => panic!("expected 5000m, got: {other:?}"),
    }

    // Preserves existing header
    let mut req = Request::new(Bytes::new());
    req.metadata_mut().insert("grpc-timeout", "1000m");
    interceptor.intercept_request(&mut req).unwrap();
    match req.metadata().get("grpc-timeout") {
        Some(MetadataValue::Ascii(s)) => assert_eq!(s, "1000m"),
        other => panic!("expected 1000m, got: {other:?}"),
    }

    test_complete!("grpc_verify_043_timeout_interceptor");
}

/// GRPC-VERIFY-044: LoggingInterceptor marks both directions
///
/// Logging interceptor sets x-logged on requests and responses when enabled.
#[test]
fn grpc_verify_044_logging_interceptor() {
    init_test("grpc_verify_044_logging_interceptor");

    let interceptor = logging_interceptor();

    let mut req = Request::new(Bytes::new());
    interceptor.intercept_request(&mut req).unwrap();
    assert!(req.metadata().get("x-logged").is_some());

    let mut resp = Response::new(Bytes::new());
    interceptor.intercept_response(&mut resp).unwrap();
    assert!(resp.metadata().get("x-logged").is_some());

    test_complete!("grpc_verify_044_logging_interceptor");
}

/// GRPC-VERIFY-045: MetadataPropagator marks propagation keys
///
/// Propagator records which keys should be forwarded in a special metadata entry.
#[test]
fn grpc_verify_045_metadata_propagator() {
    init_test("grpc_verify_045_metadata_propagator");

    let propagator = metadata_propagator(["x-request-id", "x-trace-id", "x-missing"]);

    let mut req = Request::new(Bytes::new());
    req.metadata_mut().insert("x-request-id", "req-123");
    req.metadata_mut().insert("x-trace-id", "trace-456");
    // x-missing is not set

    propagator.intercept_request(&mut req).unwrap();

    // Only present keys should be recorded
    match req.metadata().get("x-propagate-keys") {
        Some(MetadataValue::Ascii(s)) => {
            assert!(s.contains("x-request-id"));
            assert!(s.contains("x-trace-id"));
            assert!(!s.contains("x-missing"));
        }
        other => panic!("expected propagate keys, got: {other:?}"),
    }

    test_complete!("grpc_verify_045_metadata_propagator");
}

// =============================================================================
// Helpers
// =============================================================================

struct NoopWaker;

impl Wake for NoopWaker {
    fn wake(self: Arc<Self>) {}
}

fn noop_waker() -> Waker {
    Waker::from(Arc::new(NoopWaker))
}
