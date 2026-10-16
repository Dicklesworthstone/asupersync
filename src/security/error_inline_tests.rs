    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[test]
    fn error_display() {
        let err = AuthError::new(AuthErrorKind::InvalidTag, "signature mismatch");
        assert_eq!(err.to_string(), "InvalidTag: signature mismatch");
    }

    #[test]
    fn from_kind() {
        let err: AuthError = AuthErrorKind::KeyExpired.into();
        assert_eq!(err.kind(), AuthErrorKind::KeyExpired);
        assert!(err.to_string().contains("expired"));
    }

    #[test]
    fn is_invalid_tag() {
        let err = AuthError::from(AuthErrorKind::InvalidTag);
        assert!(err.is_invalid_tag());

        let err = AuthError::from(AuthErrorKind::KeyMismatch);
        assert!(!err.is_invalid_tag());
    }

    // =========================================================================
    // Wave 52 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn auth_error_kind_debug_clone_copy_hash_eq() {
        use std::collections::HashSet;
        let k = AuthErrorKind::InvalidTag;
        let dbg = format!("{k:?}");
        assert!(dbg.contains("InvalidTag"), "{dbg}");
        let copied = k;
        let cloned = k;
        assert_eq!(copied, cloned);
        assert_ne!(AuthErrorKind::InvalidTag, AuthErrorKind::KeyMismatch);
        let mut set = HashSet::new();
        set.insert(k);
        assert!(set.contains(&AuthErrorKind::InvalidTag));
    }

    #[test]
    fn auth_error_debug_clone_eq() {
        let err = AuthError::new(AuthErrorKind::KeyExpired, "expired");
        let dbg = format!("{err:?}");
        assert!(dbg.contains("AuthError"), "{dbg}");
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }
