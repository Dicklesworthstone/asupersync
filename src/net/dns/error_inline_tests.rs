    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    // =========================================================================
    // Wave 46 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn dns_error_debug_clone_display() {
        let errors: Vec<DnsError> = vec![
            DnsError::NoRecords("example.com".into()),
            DnsError::Timeout,
            DnsError::Io("broken pipe".into()),
            DnsError::Protocol("bad label".into()),
            DnsError::Connection("refused".into()),
            DnsError::Cancelled,
            DnsError::InvalidHost("???".into()),
            DnsError::ServerError("SERVFAIL".into()),
            DnsError::Protocol("truncated packet".into()),
        ];

        let expected_display = [
            "no DNS records found for: example.com",
            "DNS operation timed out",
            "DNS I/O error: broken pipe",
            "DNS protocol error: bad label",
            "connection error: refused",
            "DNS operation cancelled",
            "invalid hostname: ???",
            "DNS server error: SERVFAIL",
            "DNS protocol error: truncated packet",
        ];

        for (err, expected) in errors.iter().zip(expected_display.iter()) {
            let dbg = format!("{err:?}");
            assert!(!dbg.is_empty());
            let display = format!("{err}");
            assert_eq!(display, *expected);
            let cloned = err.clone();
            assert_eq!(format!("{cloned}"), display);
        }

        let e: &dyn std::error::Error = &errors[0];
        assert!(e.source().is_none());
    }

    #[test]
    fn dns_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionRefused, "test error");
        let dns_err: DnsError = io_err.into();
        let display = format!("{dns_err}");
        assert!(display.contains("DNS I/O error"), "{display}");
    }
