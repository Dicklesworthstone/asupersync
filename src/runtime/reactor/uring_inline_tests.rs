    #![allow(clippy::pedantic, clippy::nursery, clippy::expect_fun_call, clippy::map_unwrap_or, clippy::cast_possible_wrap, clippy::future_not_send)]
    use super::*;

    #[test]
    fn test_is_available_platform_contract() {
        #[cfg(not(target_os = "linux"))]
        assert!(!is_available());

        #[cfg(target_os = "linux")]
        {
            // Availability depends on kernel version and io_uring policy.
            let _ = is_available();
        }
    }

    #[allow(deprecated)]
    #[test]
    fn test_deprecated_type_alias_exists() {
        // Verify UringReactor is a type alias to IoUringReactor.
        // This test ensures backward compatibility is preserved.
        fn _assert_alias_compiles(_: Option<UringReactor>) {}
    }
