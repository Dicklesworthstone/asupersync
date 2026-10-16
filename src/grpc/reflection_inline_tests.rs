    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use insta::assert_json_snapshot;
    use serde_json::{Value, json};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    struct EchoService;

    impl ServiceHandler for EchoService {
        fn descriptor(&self) -> &ServiceDescriptor {
            static METHODS: &[MethodDescriptor] = &[
                MethodDescriptor::unary("Ping", "/pkg.Echo/Ping"),
                MethodDescriptor::server_streaming("Watch", "/pkg.Echo/Watch"),
            ];
            static DESC: ServiceDescriptor = ServiceDescriptor::new("Echo", "pkg", METHODS);
            &DESC
        }

        fn method_names(&self) -> Vec<&str> {
            vec!["Ping", "Watch"]
        }
    }

    struct EnumShapeService;

    impl ServiceHandler for EnumShapeService {
        fn descriptor(&self) -> &ServiceDescriptor {
            static METHODS: &[MethodDescriptor] = &[
                MethodDescriptor::unary("Unary", "/pkg.EnumShape/Unary"),
                MethodDescriptor::server_streaming("ServerStream", "/pkg.EnumShape/ServerStream"),
                MethodDescriptor::client_streaming("ClientStream", "/pkg.EnumShape/ClientStream"),
                MethodDescriptor::bidi_streaming("BidiStream", "/pkg.EnumShape/BidiStream"),
            ];
            static DESC: ServiceDescriptor = ServiceDescriptor::new("EnumShape", "pkg", METHODS);
            &DESC
        }

        fn method_names(&self) -> Vec<&str> {
            vec!["Unary", "ServerStream", "ClientStream", "BidiStream"]
        }
    }

    fn method_kind(method: &ReflectedMethod) -> &'static str {
        match (method.client_streaming, method.server_streaming) {
            (false, false) => "unary",
            (false, true) => "server_streaming",
            (true, false) => "client_streaming",
            (true, true) => "bidi_streaming",
        }
    }

    fn reflected_service_snapshot(service: &ReflectedService) -> Value {
        json!({
            "service": service.name,
            "methods": service.methods.iter().map(|method| {
                json!({
                    "name": method.name,
                    "path": method.path,
                    "kind": method_kind(method),
                })
            }).collect::<Vec<_>>(),
        })
    }

    fn install_remote_reflection_cx() -> crate::cx::cx::CurrentCxGuard {
        Cx::set_current(Some(Cx::for_testing_with_remote(
            crate::remote::RemoteCap::new(),
        )))
    }

    #[test]
    fn reflection_register_list_and_describe() {
        init_test("reflection_register_list_and_describe");
        let reflection = ReflectionService::new().allow_anonymous();
        let echo = EchoService;
        reflection.register_handler(&echo);
        let _remote_cx = install_remote_reflection_cx();

        // Anonymous mode is an explicit dev/test opt-in; `new()` itself is locked.
        let services = reflection
            .list_services()
            .expect("anonymous mode permits list");
        crate::assert_with_log!(
            services == vec!["pkg.Echo".to_string()],
            "service list",
            vec!["pkg.Echo".to_string()],
            services
        );

        let described = reflection
            .describe_service("pkg.Echo")
            .expect("service exists");
        crate::assert_with_log!(
            described.methods.len() == 2,
            "method count",
            2,
            described.methods.len()
        );
        crate::assert_with_log!(
            described.methods[0].name == "Ping",
            "first method name",
            "Ping",
            &described.methods[0].name
        );
        crate::assert_with_log!(
            described.methods[1].server_streaming,
            "server streaming flag",
            true,
            described.methods[1].server_streaming
        );
        crate::test_complete!("reflection_register_list_and_describe");
    }

    #[test]
    fn reflection_describe_missing_service() {
        init_test("reflection_describe_missing_service");
        let reflection = ReflectionService::new().allow_anonymous();
        let _remote_cx = install_remote_reflection_cx();
        let err = reflection
            .describe_service("pkg.Missing")
            .expect_err("missing service should fail");
        crate::assert_with_log!(
            err.code() == super::super::status::Code::NotFound,
            "not found code",
            super::super::status::Code::NotFound,
            err.code()
        );
        crate::test_complete!("reflection_describe_missing_service");
    }

    #[test]
    fn reflection_async_helpers() {
        init_test("reflection_async_helpers");
        let reflection = ReflectionService::new().allow_anonymous();
        let echo = EchoService;
        reflection.register_handler(&echo);
        let _remote_cx = install_remote_reflection_cx();

        let list = futures_lite::future::block_on(
            reflection.list_services_async(&Request::new(ReflectionListServicesRequest)),
        )
        .expect("list succeeds");
        crate::assert_with_log!(
            list.get_ref().services == vec!["pkg.Echo".to_string()],
            "async list",
            vec!["pkg.Echo".to_string()],
            &list.get_ref().services
        );

        let describe = futures_lite::future::block_on(reflection.describe_service_async(
            &Request::new(ReflectionDescribeServiceRequest::new("pkg.Echo")),
        ))
        .expect("describe succeeds");
        crate::assert_with_log!(
            describe.get_ref().service.name == "pkg.Echo",
            "async describe name",
            "pkg.Echo",
            &describe.get_ref().service.name
        );
        crate::test_complete!("reflection_async_helpers");
    }

    #[test]
    fn reflection_service_traits() {
        init_test("reflection_service_traits");
        let reflection = ReflectionService::new().allow_anonymous();
        crate::assert_with_log!(
            ReflectionService::NAME == "grpc.reflection.v1alpha.ServerReflection",
            "service name",
            "grpc.reflection.v1alpha.ServerReflection",
            ReflectionService::NAME
        );
        let desc = reflection.descriptor();
        crate::assert_with_log!(
            desc.full_name() == "grpc.reflection.v1alpha.ServerReflection",
            "descriptor full name",
            "grpc.reflection.v1alpha.ServerReflection",
            desc.full_name()
        );
        let methods = reflection.method_names();
        crate::assert_with_log!(
            methods == vec!["ServerReflectionInfo"],
            "method names match the descriptor-exposed RPCs",
            vec!["ServerReflectionInfo"],
            methods
        );
        crate::test_complete!("reflection_service_traits");
    }

    #[test]
    fn reflection_descriptor_enum_output_snapshot() {
        init_test("reflection_descriptor_enum_output_snapshot");
        let reflection = ReflectionService::new().allow_anonymous();
        let enum_shape = EnumShapeService;
        reflection.register_handler(&enum_shape);
        let _remote_cx = install_remote_reflection_cx();

        let described = reflection
            .describe_service("pkg.EnumShape")
            .expect("enum-shape service exists");

        assert_json_snapshot!(
            "grpc_reflection_descriptor_enum_output",
            reflected_service_snapshot(&described)
        );
        crate::test_complete!("reflection_descriptor_enum_output_snapshot");
    }

    // br-asupersync-3tzd9v: opt-in auth callback regression tests.

    #[test]
    fn auth_allow_anonymous_is_open() {
        init_test("auth_allow_anonymous_is_open");
        let reflection = ReflectionService::new().allow_anonymous();
        reflection.register_handler(&EchoService);
        assert!(
            !reflection.auth_installed(),
            "anonymous mode must not report a production auth callback",
        );
        let _remote_cx = install_remote_reflection_cx();
        // Both entry points succeed in anonymous mode once the caller has the
        // explicit REMOTE capability required for reflection.
        assert!(reflection.list_services().is_ok());
        assert!(reflection.describe_service("pkg.Echo").is_ok());
        crate::test_complete!("auth_allow_anonymous_is_open");
    }

    #[test]
    fn auth_callback_can_reject() {
        init_test("auth_callback_can_reject");
        let reflection = ReflectionService::new()
            .register_for_test()
            .with_auth(|_cx, method| Err(Status::permission_denied(format!("denied: {method}"))));
        assert!(reflection.auth_installed());
        let _remote_cx = install_remote_reflection_cx();
        let err_list = reflection.list_services().expect_err("auth must reject");
        assert_eq!(
            err_list.code(),
            super::super::status::Code::PermissionDenied
        );
        assert!(err_list.message().contains("denied: ListServices"));
        let err_desc = reflection
            .describe_service("pkg.Echo")
            .expect_err("auth must reject");
        assert_eq!(
            err_desc.code(),
            super::super::status::Code::PermissionDenied
        );
        assert!(err_desc.message().contains("denied: DescribeService"));
        crate::test_complete!("auth_callback_can_reject");
    }

    #[test]
    fn auth_method_name_is_passed_to_callback() {
        init_test("auth_method_name_is_passed_to_callback");
        // Use a Cx so the callback is actually invoked rather than being
        // short-circuited by the missing-Cx branch. We assert the method
        // name routed to the callback distinguishes the two RPCs.
        let saw_list = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let saw_describe = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let saw_list_clone = saw_list.clone();
        let saw_describe_clone = saw_describe.clone();
        let reflection =
            ReflectionService::new()
                .register_for_test()
                .with_auth(move |_cx, method| {
                    match method {
                        "ListServices" => {
                            saw_list_clone.store(true, std::sync::atomic::Ordering::Relaxed)
                        }
                        "DescribeService" => {
                            saw_describe_clone.store(true, std::sync::atomic::Ordering::Relaxed)
                        }
                        _ => {}
                    }
                    Ok(())
                });
        let _guard = install_remote_reflection_cx();
        let _ = reflection.list_services();
        let _ = reflection.describe_service("pkg.Echo");
        drop(_guard);
        assert!(
            saw_list.load(std::sync::atomic::Ordering::Relaxed),
            "callback must see ListServices"
        );
        assert!(
            saw_describe.load(std::sync::atomic::Ordering::Relaxed),
            "callback must see DescribeService"
        );
        crate::test_complete!("auth_method_name_is_passed_to_callback");
    }

    /// Test helper: register a single Echo service descriptor and return
    /// the service for further chaining. (Used by the auth tests to keep
    /// noise out of the assertion statements.)
    impl ReflectionService {
        fn register_for_test(self) -> Self {
            self.register_handler(&EchoService);
            self
        }
    }

    // =====================================================================
    // br-asupersync-mi4hzh: fail-closed default tests. ReflectionService::new()
    // returns a service in Locked mode that rejects every RPC until the
    // caller chains either .with_auth(...) (production) or .allow_anonymous()
    // (dev / test).
    // =====================================================================

    #[test]
    fn mi4hzh_locked_default_rejects_list_services() {
        init_test("mi4hzh_locked_default_rejects_list_services");
        let reflection = ReflectionService::new().register_for_test();
        // No .with_auth, no .allow_anonymous. Must reject.
        let err = reflection
            .list_services()
            .expect_err("Locked mode must reject ListServices");
        assert_eq!(err.code(), super::super::status::Code::PermissionDenied);
        // Diagnostic message names both opt-ins so operators can fix.
        let msg = err.message();
        assert!(
            msg.contains(".with_auth") && msg.contains(".allow_anonymous"),
            "PermissionDenied message must name both opt-ins: {msg}"
        );
        crate::test_complete!("mi4hzh_locked_default_rejects_list_services");
    }

    #[test]
    fn mi4hzh_locked_default_rejects_describe_service() {
        init_test("mi4hzh_locked_default_rejects_describe_service");
        let reflection = ReflectionService::new().register_for_test();
        let err = reflection
            .describe_service("pkg.Echo")
            .expect_err("Locked mode must reject DescribeService");
        assert_eq!(err.code(), super::super::status::Code::PermissionDenied);
        crate::test_complete!("mi4hzh_locked_default_rejects_describe_service");
    }

    #[test]
    fn mi4hzh_allow_anonymous_unlocks_dev_mode() {
        init_test("mi4hzh_allow_anonymous_unlocks_dev_mode");
        let reflection = ReflectionService::new()
            .register_for_test()
            .allow_anonymous();
        // Locked → Anonymous → both RPCs succeed.
        let _remote_cx = install_remote_reflection_cx();
        assert!(reflection.list_services().is_ok());
        assert!(reflection.describe_service("pkg.Echo").is_ok());
        // auth_installed() reports false for both Locked and Anonymous —
        // only Required(_) is true (production-hardened).
        assert!(!reflection.auth_installed());
        crate::test_complete!("mi4hzh_allow_anonymous_unlocks_dev_mode");
    }

    #[test]
    fn mi4hzh_with_auth_reports_installed() {
        init_test("mi4hzh_with_auth_reports_installed");
        let reflection = ReflectionService::new()
            .register_for_test()
            .with_auth(|_cx, _method| Ok(()));
        assert!(reflection.auth_installed());
        crate::test_complete!("mi4hzh_with_auth_reports_installed");
    }

    // =====================================================================
    // br-asupersync-tlp8m9: capability-based reflection access control
    // =====================================================================

    #[test]
    fn tlp8m9_reflection_requires_remote_capability() {
        init_test("tlp8m9_reflection_requires_remote_capability");

        // Create a reflection service in anonymous mode (would normally allow access)
        let reflection = ReflectionService::new()
            .register_for_test()
            .allow_anonymous();

        // Test without REMOTE capability using a restricted ambient context.
        let cx = crate::cx::Cx::for_testing();
        let _current = crate::cx::Cx::set_current(Some(cx));
        let _restricted = crate::cx::Cx::push_restriction(crate::cx::cap::CapMask::none());
        let observed_cx = crate::cx::Cx::current().expect("restricted cx should be current");
        assert!(
            !observed_cx.has_remote(),
            "test precondition: restricted current cx must not expose REMOTE"
        );
        let result = reflection.list_services();

        // Should be denied due to missing REMOTE capability
        assert!(
            result.is_err(),
            "list_services should fail without REMOTE capability"
        );
        if let Err(status) = result {
            assert_eq!(status.code(), super::super::status::Code::PermissionDenied);
            assert!(
                status.message().contains("requires REMOTE capability"),
                "Error message should mention REMOTE capability: {}",
                status.message()
            );
        }

        crate::test_complete!("tlp8m9_reflection_requires_remote_capability");
    }

    #[test]
    fn tlp8m9_reflection_allows_with_remote_capability() {
        init_test("tlp8m9_reflection_allows_with_remote_capability");

        // Create a reflection service in anonymous mode
        let reflection = ReflectionService::new()
            .register_for_test()
            .allow_anonymous();

        // Test with REMOTE capability using a remote-capable testing context.
        let full_cx = crate::cx::Cx::for_testing_with_remote(crate::remote::RemoteCap::new());
        let _current = crate::cx::Cx::set_current(Some(full_cx));
        let result = reflection.list_services();

        // Should succeed with REMOTE capability
        assert!(
            result.is_ok(),
            "list_services should succeed with REMOTE capability"
        );

        crate::test_complete!("tlp8m9_reflection_allows_with_remote_capability");
    }

    #[test]
    fn tlp8m9_capability_check_applies_to_all_methods() {
        init_test("tlp8m9_capability_check_applies_to_all_methods");

        let reflection = ReflectionService::new()
            .register_for_test()
            .allow_anonymous();

        let restricted_cx = crate::cx::Cx::for_testing();

        // Test that capability check applies to both list_services and describe_service
        let _current = crate::cx::Cx::set_current(Some(restricted_cx));
        let _restricted = crate::cx::Cx::push_restriction(crate::cx::cap::CapMask::none());
        let list_result = reflection.list_services();
        let describe_result = reflection.describe_service("test.TestService");

        // Both should be denied
        assert!(
            list_result.is_err(),
            "list_services should fail without REMOTE"
        );
        assert!(
            describe_result.is_err(),
            "describe_service should fail without REMOTE"
        );

        crate::test_complete!("tlp8m9_capability_check_applies_to_all_methods");
    }

    #[test]
    fn tlp8m9_capability_check_with_auth_callback() {
        init_test("tlp8m9_capability_check_with_auth_callback");

        // Create reflection service with auth callback that would normally deny
        let reflection = ReflectionService::new()
            .register_for_test()
            .with_auth(|_cx, method| {
                Err(super::super::status::Status::permission_denied(format!(
                    "denied: {method}"
                )))
            });

        let restricted_cx = crate::cx::Cx::for_testing();

        // Even though auth callback would deny, capability check should happen first
        let _current = crate::cx::Cx::set_current(Some(restricted_cx));
        let _restricted = crate::cx::Cx::push_restriction(crate::cx::cap::CapMask::none());
        let result = reflection.list_services();

        assert!(result.is_err());
        if let Err(status) = result {
            // Should get capability error, not auth callback error
            assert!(
                status.message().contains("requires REMOTE capability"),
                "Should get capability error, not auth callback error: {}",
                status.message()
            );
        }

        crate::test_complete!("tlp8m9_capability_check_with_auth_callback");
    }
