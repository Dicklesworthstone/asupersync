    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    static METHODS_GREETER: &[MethodDescriptor] = &[MethodDescriptor::unary(
        "SayHello",
        "/helloworld.Greeter/SayHello",
    )];
    static METHODS_EMPTY: &[MethodDescriptor] = &[];

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_method_descriptor_unary() {
        init_test("test_method_descriptor_unary");
        let desc = MethodDescriptor::unary("SayHello", "/helloworld.Greeter/SayHello");
        let unary = desc.is_unary();
        crate::assert_with_log!(unary, "is_unary", true, unary);
        crate::assert_with_log!(
            !desc.client_streaming,
            "client_streaming",
            false,
            desc.client_streaming
        );
        crate::assert_with_log!(
            !desc.server_streaming,
            "server_streaming",
            false,
            desc.server_streaming
        );
        crate::test_complete!("test_method_descriptor_unary");
    }

    #[test]
    fn test_method_descriptor_server_streaming() {
        init_test("test_method_descriptor_server_streaming");
        let desc =
            MethodDescriptor::server_streaming("ListFeatures", "/route.RouteGuide/ListFeatures");
        let unary = desc.is_unary();
        crate::assert_with_log!(!unary, "not unary", false, unary);
        crate::assert_with_log!(
            !desc.client_streaming,
            "client_streaming",
            false,
            desc.client_streaming
        );
        crate::assert_with_log!(
            desc.server_streaming,
            "server_streaming",
            true,
            desc.server_streaming
        );
        crate::test_complete!("test_method_descriptor_server_streaming");
    }

    #[test]
    fn test_method_descriptor_bidi() {
        init_test("test_method_descriptor_bidi");
        let desc = MethodDescriptor::bidi_streaming("RouteChat", "/route.RouteGuide/RouteChat");
        crate::assert_with_log!(
            desc.client_streaming,
            "client_streaming",
            true,
            desc.client_streaming
        );
        crate::assert_with_log!(
            desc.server_streaming,
            "server_streaming",
            true,
            desc.server_streaming
        );
        crate::test_complete!("test_method_descriptor_bidi");
    }

    #[test]
    fn test_service_descriptor() {
        init_test("test_service_descriptor");
        let desc = ServiceDescriptor::new("Greeter", "helloworld", METHODS_GREETER);
        let name = desc.full_name();
        crate::assert_with_log!(
            name == "helloworld.Greeter",
            "full_name",
            "helloworld.Greeter",
            name
        );
        let len = desc.methods.len();
        crate::assert_with_log!(len == 1, "methods len", 1, len);
        crate::test_complete!("test_service_descriptor");
    }

    #[test]
    fn test_service_descriptor_no_package() {
        init_test("test_service_descriptor_no_package");
        let desc = ServiceDescriptor::new("Service", "", METHODS_EMPTY);
        let name = desc.full_name();
        crate::assert_with_log!(name == "Service", "full_name", "Service", name);
        crate::test_complete!("test_service_descriptor_no_package");
    }

    // =========================================================================
    // Wave 46 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn method_descriptor_debug_clone() {
        let md = MethodDescriptor::unary("Hello", "/pkg.Svc/Hello");
        let dbg = format!("{md:?}");
        assert!(dbg.contains("MethodDescriptor"), "{dbg}");
        assert!(dbg.contains("Hello"), "{dbg}");
        let cloned = md.clone();
        assert_eq!(cloned.name, md.name);
        assert_eq!(cloned.path, md.path);
        assert_eq!(cloned.client_streaming, md.client_streaming);
        assert_eq!(cloned.server_streaming, md.server_streaming);
    }

    #[test]
    fn method_descriptor_client_streaming() {
        let md = MethodDescriptor::client_streaming("Upload", "/pkg.Svc/Upload");
        assert!(md.client_streaming);
        assert!(!md.server_streaming);
        assert!(!md.is_unary());
    }

    #[test]
    fn service_descriptor_debug_clone() {
        let desc = ServiceDescriptor::new("Greeter", "helloworld", METHODS_GREETER);
        let dbg = format!("{desc:?}");
        assert!(dbg.contains("ServiceDescriptor"), "{dbg}");
        let cloned = desc;
        assert_eq!(cloned.name, "Greeter");
        assert_eq!(cloned.package, "helloworld");
        assert_eq!(cloned.methods.len(), 1);
    }
