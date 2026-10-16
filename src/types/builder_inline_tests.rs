    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use std::time::Duration;

    #[test]
    fn build_error_missing_required() {
        let err = BuildError::missing_required("name");
        assert_eq!(err.field(), Some("name"));
        assert!(err.is_missing_required());
        assert!(err.to_string().contains("missing required"));
        assert!(err.to_string().contains("name"));
    }

    #[test]
    fn build_error_invalid_value() {
        let err = BuildError::invalid_value("threads", "must be >= 1");
        assert_eq!(err.field(), Some("threads"));
        assert!(err.is_invalid_value());
        assert!(err.to_string().contains("invalid threads"));
    }

    #[test]
    fn build_error_invalid_range() {
        let err = BuildError::invalid_range("connections", 100, 10);
        assert_eq!(err.field(), Some("connections"));
        assert!(err.to_string().contains("min (100)"));
        assert!(err.to_string().contains("max (10)"));
    }

    #[test]
    fn build_error_conflicting_options() {
        let err = BuildError::conflicting_options("sync", "async");
        assert!(err.is_conflicting_options());
        assert!(err.to_string().contains("sync"));
        assert!(err.to_string().contains("async"));
        assert!(err.to_string().contains("cannot both be enabled"));
    }

    #[test]
    fn build_error_invalid_probability() {
        let err = BuildError::invalid_probability("cancel_rate", 1.5);
        assert_eq!(err.field(), Some("cancel_rate"));
        assert!(err.to_string().contains("1.5"));
        assert!(err.to_string().contains("[0.0, 1.0]"));
    }

    #[test]
    fn build_error_invalid_duration() {
        let err = BuildError::invalid_duration("timeout", "must be non-zero");
        assert_eq!(err.field(), Some("timeout"));
        assert!(err.to_string().contains("timeout"));
    }

    #[test]
    fn build_error_dependency_missing() {
        let err = BuildError::dependency_missing("tls", "certificate");
        assert!(err.to_string().contains("tls"));
        assert!(err.to_string().contains("certificate"));
    }

    #[test]
    fn build_error_custom() {
        let err = BuildError::custom("something went wrong");
        assert!(err.to_string().contains("something went wrong"));
    }

    #[test]
    fn validate_probability_valid() {
        assert!(validate::probability("p", 0.0).is_ok());
        assert!(validate::probability("p", 0.5).is_ok());
        assert!(validate::probability("p", 1.0).is_ok());
    }

    #[test]
    fn validate_probability_invalid() {
        assert!(validate::probability("p", -0.1).is_err());
        assert!(validate::probability("p", 1.1).is_err());
    }

    #[test]
    fn validate_positive() {
        assert!(validate::positive("n", 1).is_ok());
        assert!(validate::positive("n", 0).is_err());
    }

    #[test]
    fn validate_range_valid() {
        assert!(validate::range("r", 0, 100).is_ok());
        assert!(validate::range("r", 50, 50).is_ok());
    }

    #[test]
    fn validate_range_invalid() {
        assert!(validate::range("r", 100, 50).is_err());
    }

    #[test]
    fn validate_nonzero_duration() {
        assert!(validate::nonzero_duration("t", Duration::from_secs(1)).is_ok());
        assert!(validate::nonzero_duration("t", Duration::ZERO).is_err());
    }

    #[test]
    fn validate_non_empty_string() {
        assert!(validate::non_empty_string("s", "hello").is_ok());
        assert!(validate::non_empty_string("s", "").is_err());
    }

    #[test]
    fn validate_required() {
        assert!(validate::required("x", Some(42)).is_ok());
        assert!(validate::required::<i32>("x", None).is_err());
    }

    #[test]
    fn build_error_debug_clone_eq() {
        let e = BuildError::missing_required("name");
        let dbg = format!("{e:?}");
        assert!(dbg.contains("MissingRequired"), "{dbg}");
        let cloned = e.clone();
        assert_eq!(e, cloned);

        let e2 = BuildError::invalid_value("port", "must be > 0");
        assert_ne!(e, e2);
        let dbg2 = format!("{e2:?}");
        assert!(dbg2.contains("InvalidValue"), "{dbg2}");

        let e3 = BuildError::conflicting_options("a", "b");
        let dbg3 = format!("{e3:?}");
        assert!(dbg3.contains("ConflictingOptions"), "{dbg3}");
        let cloned3 = e3.clone();
        assert_eq!(e3, cloned3);
    }
