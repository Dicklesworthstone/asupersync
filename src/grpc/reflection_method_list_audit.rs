//! gRPC reflection service method list audit test.
//!
//! AUDIT FINDING: SOUND - Reflection service correctly returns real method list
//! for known services per gRPC reflection v1alpha specification. This test pins
//! the compliance behavior.

#![cfg(test)]

use super::reflection::{
    ReflectionDescribeServiceRequest, ReflectionListServicesRequest, ReflectionService,
};
use super::service::{MethodDescriptor, ServiceDescriptor, ServiceHandler};
use super::status::Code;
use super::streaming::Request;

fn init_test(name: &str) {
    crate::test_utils::init_test_logging();
    crate::test_phase!(name);
}

fn install_remote_reflection_cx() -> crate::cx::cx::CurrentCxGuard {
    crate::cx::Cx::set_current(Some(crate::cx::Cx::for_testing_with_remote(
        crate::remote::RemoteCap::new(),
    )))
}

fn method_fingerprint(methods: &[super::reflection::ReflectedMethod]) -> String {
    methods
        .iter()
        .map(|method| {
            format!(
                "{}:{}:{}:{}",
                method.name, method.path, method.client_streaming, method.server_streaming
            )
        })
        .collect::<Vec<_>>()
        .join("|")
}

/// AUDIT: Test service with known methods for reflection testing
#[derive(Clone)]
struct AuditTestService;

impl ServiceHandler for AuditTestService {
    fn descriptor(&self) -> &ServiceDescriptor {
        static METHODS: &[MethodDescriptor] = &[
            MethodDescriptor::unary("GetUser", "/audit.test.TestService/GetUser"),
            MethodDescriptor::server_streaming(
                "StreamUsers",
                "/audit.test.TestService/StreamUsers",
            ),
            MethodDescriptor::client_streaming(
                "CreateUsers",
                "/audit.test.TestService/CreateUsers",
            ),
            MethodDescriptor::bidi_streaming("ChatUsers", "/audit.test.TestService/ChatUsers"),
        ];
        static DESC: ServiceDescriptor =
            ServiceDescriptor::new("TestService", "audit.test", METHODS);
        &DESC
    }

    fn method_names(&self) -> Vec<&str> {
        vec!["GetUser", "StreamUsers", "CreateUsers", "ChatUsers"]
    }
}

/// AUDIT: Verify that reflection returns real method list for known services
///
/// Per gRPC reflection v1alpha specification, when a client requests methods
/// for a registered service, the server must return the actual method list
/// with complete metadata, not empty/error responses.
#[test]
fn audit_reflection_returns_real_method_list_for_known_service() {
    init_test("audit_reflection_returns_real_method_list_for_known_service");
    let _current = install_remote_reflection_cx();

    // Create reflection service and register test service
    let reflection = ReflectionService::new().allow_anonymous(); // Allow access for testing

    let test_service = AuditTestService;
    reflection.register_handler(&test_service);

    // AUDIT: Request methods for known service must return real method list
    let result = reflection.describe_service("audit.test.TestService");

    assert!(
        result.is_ok(),
        "Reflection must succeed for known service, got error: {:?}",
        result.err()
    );

    let described_service = result.unwrap();
    let fingerprint = method_fingerprint(&described_service.methods);
    tracing::info!(
        service = %described_service.name,
        method_count = described_service.methods.len(),
        method_fingerprint = %fingerprint,
        feature_flags = "test-internals",
        proof_command = "rch exec -- cargo test -p asupersync --lib reflection_method_list --features test-internals -- --nocapture",
        "grpc reflection audit method-list harness"
    );

    // AUDIT: Service name must be correct
    assert_eq!(
        described_service.name, "audit.test.TestService",
        "Service name must match registered service"
    );

    // AUDIT: Must return all 4 methods (not empty, not subset)
    assert_eq!(
        described_service.methods.len(),
        4,
        "Must return all registered methods, got {} methods",
        described_service.methods.len()
    );

    // AUDIT: Method names must be concrete/correct (not empty)
    let method_names: Vec<&str> = described_service
        .methods
        .iter()
        .map(|m| m.name.as_str())
        .collect();

    assert!(
        method_names.contains(&"GetUser"),
        "Must include GetUser method, got methods: {:?}",
        method_names
    );
    assert!(
        method_names.contains(&"StreamUsers"),
        "Must include StreamUsers method, got methods: {:?}",
        method_names
    );
    assert!(
        method_names.contains(&"CreateUsers"),
        "Must include CreateUsers method, got methods: {:?}",
        method_names
    );
    assert!(
        method_names.contains(&"ChatUsers"),
        "Must include ChatUsers method, got methods: {:?}",
        method_names
    );

    // AUDIT: Method paths must be fully qualified (not relative/empty)
    for method in &described_service.methods {
        assert!(
            method.path.starts_with("/audit.test.TestService/"),
            "Method path must be fully qualified, got: {}",
            method.path
        );
        assert!(
            !method.name.is_empty(),
            "Method name must not be empty for service {} with fingerprint {}",
            described_service.name,
            fingerprint
        );
    }

    // AUDIT: Streaming flags must reflect actual method types
    let get_user = described_service
        .methods
        .iter()
        .find(|m| m.name == "GetUser")
        .expect("GetUser method must exist");
    assert!(
        !get_user.client_streaming && !get_user.server_streaming,
        "GetUser must be unary (no streaming), got client:{} server:{}",
        get_user.client_streaming,
        get_user.server_streaming
    );

    let stream_users = described_service
        .methods
        .iter()
        .find(|m| m.name == "StreamUsers")
        .expect("StreamUsers method must exist");
    assert!(
        !stream_users.client_streaming && stream_users.server_streaming,
        "StreamUsers must be server streaming, got client:{} server:{}",
        stream_users.client_streaming,
        stream_users.server_streaming
    );

    let create_users = described_service
        .methods
        .iter()
        .find(|m| m.name == "CreateUsers")
        .expect("CreateUsers method must exist");
    assert!(
        create_users.client_streaming && !create_users.server_streaming,
        "CreateUsers must be client streaming, got client:{} server:{}",
        create_users.client_streaming,
        create_users.server_streaming
    );

    let chat_users = described_service
        .methods
        .iter()
        .find(|m| m.name == "ChatUsers")
        .expect("ChatUsers method must exist");
    assert!(
        chat_users.client_streaming && chat_users.server_streaming,
        "ChatUsers must be bidi streaming, got client:{} server:{}",
        chat_users.client_streaming,
        chat_users.server_streaming
    );

    crate::test_complete!(
        "audit_reflection_returns_real_method_list_for_known_service",
        service = described_service.name,
        method_count = described_service.methods.len(),
        method_fingerprint = fingerprint,
    );
}

/// AUDIT: Verify reflection returns NOT_FOUND for unknown services
///
/// Per gRPC reflection spec, requesting methods for unknown service
/// should return NOT_FOUND error, not empty list or other error.
#[test]
fn audit_reflection_returns_not_found_for_unknown_service() {
    init_test("audit_reflection_returns_not_found_for_unknown_service");
    let _current = install_remote_reflection_cx();

    let reflection = ReflectionService::new().allow_anonymous();

    // AUDIT: Unknown service must return NOT_FOUND error
    let result = reflection.describe_service("unknown.service.DoesNotExist");

    assert!(
        result.is_err(),
        "Unknown service must return error, got success"
    );

    let error = result.unwrap_err();
    assert_eq!(
        error.code(),
        Code::NotFound,
        "Unknown service must return NOT_FOUND, got: {:?}",
        error.code()
    );

    // AUDIT: Error message should identify the missing service
    let message = error.message();
    assert!(
        message.contains("unknown.service.DoesNotExist"),
        "Error message must identify missing service, got: {}",
        message
    );
    assert!(
        message.to_lowercase().contains("not found"),
        "Error message must indicate 'not found', got: {}",
        message
    );

    crate::test_complete!(
        "audit_reflection_returns_not_found_for_unknown_service",
        requested_symbol = "unknown.service.DoesNotExist",
        status_code = "NotFound",
        error_kind = "missing service",
    );
}

/// AUDIT: Verify reflection behavior across multiple registered services
///
/// When multiple services are registered, reflection must correctly
/// return methods for each specific service without cross-contamination.
#[test]
fn audit_reflection_isolates_methods_across_multiple_services() {
    init_test("audit_reflection_isolates_methods_across_multiple_services");
    let _current = install_remote_reflection_cx();

    let reflection = ReflectionService::new().allow_anonymous();

    // Register two different services
    reflection.register_handler(&AuditTestService);

    // Create a second test service with different methods
    #[derive(Clone)]
    struct AnotherTestService;

    impl ServiceHandler for AnotherTestService {
        fn descriptor(&self) -> &ServiceDescriptor {
            static METHODS: &[MethodDescriptor] = &[
                MethodDescriptor::unary("Process", "/audit.other.OtherService/Process"),
                MethodDescriptor::unary("Validate", "/audit.other.OtherService/Validate"),
            ];
            static DESC: ServiceDescriptor =
                ServiceDescriptor::new("OtherService", "audit.other", METHODS);
            &DESC
        }

        fn method_names(&self) -> Vec<&str> {
            vec!["Process", "Validate"]
        }
    }

    reflection.register_handler(&AnotherTestService);

    // AUDIT: First service must return only its own methods
    let first_service = reflection
        .describe_service("audit.test.TestService")
        .expect("First service must exist");
    assert_eq!(
        first_service.methods.len(),
        4,
        "First service must have 4 methods"
    );
    let first_method_names: Vec<&str> = first_service
        .methods
        .iter()
        .map(|m| m.name.as_str())
        .collect();
    assert!(
        first_method_names.contains(&"GetUser"),
        "First service must contain GetUser"
    );
    assert!(
        !first_method_names.contains(&"Process"),
        "First service must NOT contain Process"
    );
    assert!(
        !first_method_names.contains(&"Validate"),
        "First service must NOT contain Validate"
    );

    // AUDIT: Second service must return only its own methods
    let second_service = reflection
        .describe_service("audit.other.OtherService")
        .expect("Second service must exist");
    assert_eq!(
        second_service.methods.len(),
        2,
        "Second service must have 2 methods"
    );
    let second_method_names: Vec<&str> = second_service
        .methods
        .iter()
        .map(|m| m.name.as_str())
        .collect();
    assert!(
        second_method_names.contains(&"Process"),
        "Second service must contain Process"
    );
    assert!(
        second_method_names.contains(&"Validate"),
        "Second service must contain Validate"
    );
    assert!(
        !second_method_names.contains(&"GetUser"),
        "Second service must NOT contain GetUser"
    );
    assert!(
        !second_method_names.contains(&"StreamUsers"),
        "Second service must NOT contain StreamUsers"
    );

    // AUDIT: Service paths must be correctly namespaced
    for method in &first_service.methods {
        assert!(
            method.path.starts_with("/audit.test.TestService/"),
            "First service method paths must use correct namespace: {}",
            method.path
        );
    }

    for method in &second_service.methods {
        assert!(
            method.path.starts_with("/audit.other.OtherService/"),
            "Second service method paths must use correct namespace: {}",
            method.path
        );
    }

    let first_fingerprint = method_fingerprint(&first_service.methods);
    let second_fingerprint = method_fingerprint(&second_service.methods);
    crate::test_complete!(
        "audit_reflection_isolates_methods_across_multiple_services",
        first_service = first_service.name,
        first_count = first_service.methods.len(),
        first_fingerprint = first_fingerprint,
        second_service = second_service.name,
        second_count = second_service.methods.len(),
        second_fingerprint = second_fingerprint,
    );
}

/// AUDIT: Verify async describe_service_async returns same data as sync version
///
/// The async wrapper must produce identical reflection data as the sync method.
#[test]
fn audit_reflection_async_method_returns_identical_data() {
    init_test("audit_reflection_async_method_returns_identical_data");
    let _current = install_remote_reflection_cx();

    let reflection = ReflectionService::new().allow_anonymous();
    reflection.register_handler(&AuditTestService);

    // Get sync result
    let sync_result = reflection
        .describe_service("audit.test.TestService")
        .expect("Sync describe_service must succeed");

    // Get async result
    let request = Request::new(ReflectionDescribeServiceRequest::new(
        "audit.test.TestService",
    ));
    let async_result = futures_lite::future::block_on(reflection.describe_service_async(&request))
        .expect("Async describe_service must succeed");

    let async_service = async_result.get_ref();

    // AUDIT: Both results must be identical
    assert_eq!(
        sync_result.name, async_service.service.name,
        "Service names must match between sync and async"
    );

    assert_eq!(
        sync_result.methods.len(),
        async_service.service.methods.len(),
        "Method counts must match between sync and async"
    );

    // AUDIT: All methods must be identical
    for (sync_method, async_method) in sync_result
        .methods
        .iter()
        .zip(async_service.service.methods.iter())
    {
        assert_eq!(
            sync_method.name, async_method.name,
            "Method names must match"
        );
        assert_eq!(
            sync_method.path, async_method.path,
            "Method paths must match"
        );
        assert_eq!(
            sync_method.client_streaming, async_method.client_streaming,
            "Client streaming flags must match"
        );
        assert_eq!(
            sync_method.server_streaming, async_method.server_streaming,
            "Server streaming flags must match"
        );
    }

    let fingerprint = method_fingerprint(&sync_result.methods);
    crate::test_complete!(
        "audit_reflection_async_method_returns_identical_data",
        service = sync_result.name,
        method_count = sync_result.methods.len(),
        method_fingerprint = fingerprint,
    );
}

/// AUDIT: Verify empty registries are observable as an empty service list.
#[test]
fn audit_reflection_empty_registry_lists_no_services() {
    init_test("audit_reflection_empty_registry_lists_no_services");
    let _current = install_remote_reflection_cx();

    let reflection = ReflectionService::new().allow_anonymous();
    let list = futures_lite::future::block_on(
        reflection.list_services_async(&Request::new(ReflectionListServicesRequest)),
    )
    .expect("Empty reflection registry must still list successfully");

    assert!(
        list.get_ref().services.is_empty(),
        "Empty registry must return an empty service list, got {:?}",
        list.get_ref().services
    );

    crate::test_complete!(
        "audit_reflection_empty_registry_lists_no_services",
        service_count = list.get_ref().services.len(),
        artifact = "in-process reflection registry",
        downstream_frontier = "pending rch validation",
    );
}

/// AUDIT: Verify malformed describe requests fail closed with diagnostic context.
#[test]
fn audit_reflection_malformed_describe_request_is_not_found() {
    init_test("audit_reflection_malformed_describe_request_is_not_found");
    let _current = install_remote_reflection_cx();

    let reflection = ReflectionService::new().allow_anonymous();
    reflection.register_handler(&AuditTestService);

    let request = Request::new(ReflectionDescribeServiceRequest::new(""));
    let error = futures_lite::future::block_on(reflection.describe_service_async(&request))
        .expect_err("Empty service symbol must not resolve to a descriptor");

    assert_eq!(
        error.code(),
        Code::NotFound,
        "Malformed empty service symbol must return NotFound, got {:?}: {}",
        error.code(),
        error.message()
    );
    assert!(
        error.message().contains("service '' not found"),
        "Malformed request error must preserve the empty requested symbol, got {}",
        error.message()
    );

    crate::test_complete!(
        "audit_reflection_malformed_describe_request_is_not_found",
        requested_symbol = "<empty>",
        status_code = "NotFound",
        error_kind = "malformed empty service symbol",
    );
}
