//! Security and authentication errors.

use core::fmt;

/// A specialized Result type for security operations.
pub type AuthResult<T> = Result<T, AuthError>;

/// The kind of authentication error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthErrorKind {
    /// The authentication tag did not match the expected value.
    InvalidTag,
    /// The key ID did not match the expected key.
    KeyMismatch,
    /// The key has expired or is no longer valid.
    KeyExpired,
    /// The authentication scheme or version is not supported.
    UnsupportedScheme,
    /// The payload was malformed or too short.
    MalformedPayload,
    /// Authentication is required but was disabled or missing.
    AuthRequired,
}

/// An error that occurred during authentication or verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthError {
    kind: AuthErrorKind,
    message: String,
}

impl AuthError {
    /// Creates a new authentication error.
    pub fn new(kind: AuthErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// Returns the kind of error.
    #[must_use]
    pub const fn kind(&self) -> AuthErrorKind {
        self.kind
    }

    /// Returns true if this is an invalid tag error.
    #[must_use]
    pub const fn is_invalid_tag(&self) -> bool {
        matches!(self.kind, AuthErrorKind::InvalidTag)
    }
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for AuthError {}

impl From<AuthErrorKind> for AuthError {
    fn from(kind: AuthErrorKind) -> Self {
        let msg = match kind {
            AuthErrorKind::InvalidTag => "authentication tag verification failed",
            AuthErrorKind::KeyMismatch => "key identifier mismatch",
            AuthErrorKind::KeyExpired => "authentication key has expired",
            AuthErrorKind::UnsupportedScheme => "unsupported authentication scheme",
            AuthErrorKind::MalformedPayload => "malformed or truncated payload",
            AuthErrorKind::AuthRequired => "authentication required but not provided",
        };
        Self::new(kind, msg)
    }
}

#[cfg(test)]
mod tests {
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
        let cloned = k.clone();
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
}
