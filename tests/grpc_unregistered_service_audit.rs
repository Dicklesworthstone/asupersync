//! Audit test for gRPC service routing with unregistered services.
//!
//! When a gRPC request arrives for an unregistered service, the server should
//! respond with grpc-status=12 (UNIMPLEMENTED), not HTTP 404. gRPC clients
//! expect gRPC status codes and won't properly parse HTTP error responses.

use asupersync::bytes::Bytes;
use asupersync::cx::Cx;
use asupersync::grpc::server::Server;
use asupersync::grpc::service::{
    MethodDescriptor, NamedService, ServiceDescriptor, ServiceHandler, ServiceHandlerFuture,
};
use asupersync::grpc::status::{Code, Status};
use asupersync::grpc::streaming::{Metadata, Request, Response};
use asupersync::test_utils::run_test_with_cx;
use asupersync::types::CancelKind;

// Test service used for routing assertions.
#[derive(Debug, Clone)]
struct TestService;

impl NamedService for TestService {
    const NAME: &'static str = "test.TestService";
}

impl ServiceHandler for TestService {
    fn descriptor(&self) -> &ServiceDescriptor {
        static DESCRIPTOR: ServiceDescriptor = ServiceDescriptor {
            name: "TestService",
            package: "test",
            methods: &[MethodDescriptor {
                name: "TestMethod",
                path: "/test.TestService/TestMethod",
                client_streaming: false,
                server_streaming: false,
            }],
        };
        &DESCRIPTOR
    }

    fn method_names(&self) -> Vec<&str> {
        vec!["TestMethod"]
    }

    fn call_unary<'a>(
        &'a self,
        _cx: &'a Cx,
        path: &'a str,
        request: Request<Bytes>,
        trailing_metadata: Metadata,
    ) -> ServiceHandlerFuture<'a> {
        Box::pin(async move {
            assert_eq!(path, "/test.TestService/TestMethod");
            assert!(trailing_metadata.is_empty());
            Ok(Response::new(request.into_inner()))
        })
    }
}

#[derive(Debug, Clone)]
struct LegacyMetadataOnlyService;

impl NamedService for LegacyMetadataOnlyService {
    const NAME: &'static str = "legacy.MetadataOnly";
}

impl ServiceHandler for LegacyMetadataOnlyService {
    fn descriptor(&self) -> &ServiceDescriptor {
        static METHODS: &[MethodDescriptor] = &[MethodDescriptor::unary(
            "LegacyCall",
            "/legacy.MetadataOnly/LegacyCall",
        )];
        static DESCRIPTOR: ServiceDescriptor =
            ServiceDescriptor::new("MetadataOnly", "legacy", METHODS);
        &DESCRIPTOR
    }

    fn method_names(&self) -> Vec<&str> {
        vec!["LegacyCall"]
    }
}

#[test]
fn test_registered_service_works() {
    run_test_with_cx(|cx| async move {
        let server = Server::builder().add_service(TestService).build();

        assert!(server.get_service("test.TestService").is_some());
        let response = server
            .dispatch_registered_unary(
                &cx,
                "/test.TestService/TestMethod",
                Request::new(Bytes::from_static(b"request")),
            )
            .await
            .expect("registered callable service must dispatch");
        assert_eq!(response.into_inner(), Bytes::from_static(b"request"));
        println!("✓ PASS: Registered service found in server");
    });
}

#[test]
fn test_unregistered_service_lookup() {
    run_test_with_cx(|_cx| async move {
        let server = Server::builder().add_service(TestService).build();

        // Test unregistered service lookup
        let unregistered = server.get_service("unregistered.Service");
        assert!(unregistered.is_none());
        println!("✓ PASS: Unregistered service correctly returns None");
    });
}

#[test]
fn registered_dispatch_rejects_unregistered_service() {
    run_test_with_cx(|cx| async move {
        let server = Server::builder().add_service(TestService).build();

        let request = Request::with_metadata(Bytes::from("test"), Metadata::new());
        let result = server
            .dispatch_registered_unary(&cx, "/unregistered.Service/TestMethod", request)
            .await;

        match result {
            Err(status) => {
                assert_eq!(status.code(), Code::Unimplemented);
                println!("✓ PASS: Unregistered service returns grpc-status=12 (UNIMPLEMENTED)");
                println!("  Status code: {:?}", status.code());
                println!("  Status message: {}", status.message());
            }
            Ok(_) => panic!("expected grpc-status=12 for unregistered service"),
        }
    });
}

#[test]
fn test_dispatch_with_unknown_registered_method() {
    run_test_with_cx(|cx| async move {
        let server = Server::builder().add_service(TestService).build();
        let result = server
            .dispatch_registered_unary(
                &cx,
                "/test.TestService/UnknownMethod",
                Request::new(Bytes::from_static(b"test")),
            )
            .await;

        let status = result.expect_err("unknown method must fail closed");
        assert_eq!(status.code(), Code::Unimplemented);
        assert!(status.message().contains("is not registered"));
    });
}

#[test]
fn legacy_metadata_only_service_remains_source_compatible_and_fails_closed() {
    run_test_with_cx(|cx| async move {
        let server = Server::builder()
            .add_service(LegacyMetadataOnlyService)
            .build();
        let result = server
            .dispatch_registered_unary(
                &cx,
                "/legacy.MetadataOnly/LegacyCall",
                Request::new(Bytes::new()),
            )
            .await;

        let status = result.expect_err("legacy metadata-only service is not callable");
        assert_eq!(status.code(), Code::Unimplemented);
        assert!(status.message().contains("no callable unary handler"));
    });
}

#[test]
fn registered_dispatch_rejects_pre_cancelled_context_before_calling_service() {
    run_test_with_cx(|cx| async move {
        let server = Server::builder().add_service(TestService).build();
        cx.cancel_with(CancelKind::User, Some("test cancellation"));

        let result = server
            .dispatch_registered_unary(
                &cx,
                "/test.TestService/TestMethod",
                Request::new(Bytes::from_static(b"must not be echoed")),
            )
            .await;

        let status = result.expect_err("pre-cancelled dispatch must not invoke the service");
        assert_eq!(status.code(), Code::Cancelled);
    });
}

#[test]
fn test_status_unimplemented_creates_correct_grpc_status() {
    // Verify that Status::unimplemented produces the correct gRPC status code
    let status = Status::unimplemented("method unavailable in service registry");

    assert_eq!(status.code(), Code::Unimplemented);
    assert_eq!(status.code() as u32, 12); // gRPC status code 12

    println!("✓ PASS: Status::unimplemented creates grpc-status=12");
    println!("  Code: {:?} ({})", status.code(), status.code() as u32);
}

#[test]
fn test_various_grpc_status_codes() {
    // Verify that gRPC status codes map correctly (not HTTP codes)
    let test_cases = vec![
        (Status::ok(), Code::Ok, 0),
        (Status::cancelled("cancelled"), Code::Cancelled, 1),
        (
            Status::invalid_argument("invalid"),
            Code::InvalidArgument,
            3,
        ),
        (Status::not_found("not found"), Code::NotFound, 5),
        (
            Status::permission_denied("denied"),
            Code::PermissionDenied,
            7,
        ),
        (
            Status::unimplemented("unsupported by service registry"),
            Code::Unimplemented,
            12,
        ),
        (Status::internal("internal error"), Code::Internal, 13),
        (Status::unavailable("unavailable"), Code::Unavailable, 14),
    ];

    for (status, expected_code, expected_number) in test_cases {
        assert_eq!(status.code(), expected_code);
        assert_eq!(status.code() as u32, expected_number);
        println!(
            "✓ Status::{:?} -> grpc-status={}",
            expected_code, expected_number
        );
    }
}

#[test]
fn audit_grpc_unregistered_service_behavior() {
    println!("\n=== GRPC UNREGISTERED SERVICE ROUTING AUDIT ===\n");

    println!("GRPC SPECIFICATION REQUIREMENT:");
    println!("- RFC: gRPC over HTTP/2 requires gRPC status codes, not HTTP status codes");
    println!("- Unregistered services should return grpc-status=12 (UNIMPLEMENTED)");
    println!("- HTTP 404 is incorrect - gRPC clients expect grpc-status in trailers\n");

    println!("IMPLEMENTATION ANALYSIS:");
    println!("File: src/grpc/server.rs");
    println!("1. Server::services: BTreeMap<String, Arc<dyn ServiceHandler>>");
    println!("2. descriptor-driven route resolution validates service and method paths");
    println!("3. dispatch_registered_unary() invokes ServiceHandler::call_unary()");
    println!("4. bind_registered_http2() connects that registry to the native H2 listener");
    println!("5. Status::unimplemented() creates grpc-status=12\n");

    println!("ROUTING BEHAVIOR VERIFICATION:");
    println!("✓ SOUND: Server.get_service() correctly returns None for unregistered services");
    println!("✓ SOUND: Status::unimplemented() maps to grpc-status=12 (not HTTP 404)");
    println!("✓ SOUND: registered dispatch preserves gRPC status semantics");
    println!("✓ SOUND: metadata-only legacy handlers fail closed without an API break");
    println!("✓ SOUND: gRPC status codes properly distinguished from HTTP status codes\n");

    println!("EXPECTED BEHAVIOR:");
    println!("When HTTP/2 request arrives for '/unregistered.Service/Method':");
    println!("1. Transport layer parses gRPC path");
    println!("2. Registered route resolution rejects the unknown service");
    println!("3. No service handler is invoked");
    println!("4. Response contains grpc-status=12 in HTTP/2 trailers");
    println!("5. NOT HTTP 404 status code\n");

    println!("The companion grpc_http2_e2e test proves this route over real TCP/H2.");
}

#[test]
fn run_audit() {
    audit_grpc_unregistered_service_behavior();
}
