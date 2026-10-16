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
#[path = "error_inline_tests.rs"]
mod tests;
