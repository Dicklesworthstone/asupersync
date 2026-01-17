//! Security-related error types.
//!
//! This module defines error types specific to authentication and
//! security operations in the distributed layer.

use core::fmt;

/// The kind of authentication error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthErrorKind {
    /// Authentication tag verification failed.
    VerificationFailed,
    /// The provided key is invalid (e.g., all zeros).
    InvalidKey,
    /// The tag format is malformed.
    MalformedTag,
    /// No authentication context available.
    NoContext,
    /// The symbol has already been verified (double-verification attempt).
    AlreadyVerified,
    /// Authentication was skipped (in permissive mode).
    Skipped,
}

/// An error from authentication operations.
///
/// # Example
///
/// ```
/// use asupersync::security::{AuthError, AuthErrorKind};
///
/// let err = AuthError::new(AuthErrorKind::VerificationFailed)
///     .with_context("symbol 42:0:5");
///
/// assert!(err.is_verification_failure());
/// assert!(err.to_string().contains("42:0:5"));
/// ```
#[derive(Debug, Clone)]
pub struct AuthError {
    /// The kind of error.
    kind: AuthErrorKind,
    /// Optional context about what was being authenticated.
    context: Option<String>,
}

impl AuthError {
    /// Creates a new authentication error with the given kind.
    #[must_use]
    pub const fn new(kind: AuthErrorKind) -> Self {
        Self {
            kind,
            context: None,
        }
    }

    /// Creates a verification failure error.
    #[must_use]
    pub const fn verification_failed() -> Self {
        Self::new(AuthErrorKind::VerificationFailed)
    }

    /// Creates an invalid key error.
    #[must_use]
    pub const fn invalid_key() -> Self {
        Self::new(AuthErrorKind::InvalidKey)
    }

    /// Creates a malformed tag error.
    #[must_use]
    pub const fn malformed_tag() -> Self {
        Self::new(AuthErrorKind::MalformedTag)
    }

    /// Creates a no context error.
    #[must_use]
    pub const fn no_context() -> Self {
        Self::new(AuthErrorKind::NoContext)
    }

    /// Returns the error kind.
    #[must_use]
    pub const fn kind(&self) -> AuthErrorKind {
        self.kind
    }

    /// Returns `true` if this is a verification failure.
    #[must_use]
    pub const fn is_verification_failure(&self) -> bool {
        matches!(self.kind, AuthErrorKind::VerificationFailed)
    }

    /// Returns `true` if this error is due to an invalid key.
    #[must_use]
    pub const fn is_invalid_key(&self) -> bool {
        matches!(self.kind, AuthErrorKind::InvalidKey)
    }

    /// Adds context to the error.
    #[must_use]
    pub fn with_context(mut self, ctx: impl Into<String>) -> Self {
        self.context = Some(ctx.into());
        self
    }

    /// Returns the error context, if any.
    #[must_use]
    pub fn context(&self) -> Option<&str> {
        self.context.as_deref()
    }
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self.kind {
            AuthErrorKind::VerificationFailed => "authentication verification failed",
            AuthErrorKind::InvalidKey => "invalid authentication key",
            AuthErrorKind::MalformedTag => "malformed authentication tag",
            AuthErrorKind::NoContext => "no security context available",
            AuthErrorKind::AlreadyVerified => "symbol already verified",
            AuthErrorKind::Skipped => "authentication skipped",
        };

        write!(f, "{msg}")?;

        if let Some(ctx) = &self.context {
            write!(f, ": {ctx}")?;
        }

        Ok(())
    }
}

impl std::error::Error for AuthError {}

// Integration with the main error type
impl From<AuthError> for crate::error::Error {
    fn from(e: AuthError) -> Self {
        Self::new(crate::error::ErrorKind::User).with_context(e.to_string())
    }
}

/// Result type for authentication operations.
pub type AuthResult<T> = Result<T, AuthError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_kinds() {
        let err = AuthError::new(AuthErrorKind::VerificationFailed);
        assert!(err.is_verification_failure());
        assert!(!err.is_invalid_key());

        let err = AuthError::new(AuthErrorKind::InvalidKey);
        assert!(!err.is_verification_failure());
        assert!(err.is_invalid_key());
    }

    #[test]
    fn error_with_context() {
        let err = AuthError::verification_failed().with_context("symbol 1:0:5");

        assert_eq!(err.kind(), AuthErrorKind::VerificationFailed);
        assert_eq!(err.context(), Some("symbol 1:0:5"));

        let display = err.to_string();
        assert!(display.contains("verification failed"));
        assert!(display.contains("1:0:5"));
    }

    #[test]
    fn error_display() {
        assert!(AuthError::verification_failed()
            .to_string()
            .contains("verification"));
        assert!(AuthError::invalid_key().to_string().contains("invalid"));
        assert!(AuthError::malformed_tag().to_string().contains("malformed"));
        assert!(AuthError::no_context().to_string().contains("context"));
    }

    #[test]
    fn constructor_helpers() {
        assert_eq!(
            AuthError::verification_failed().kind(),
            AuthErrorKind::VerificationFailed
        );
        assert_eq!(AuthError::invalid_key().kind(), AuthErrorKind::InvalidKey);
        assert_eq!(
            AuthError::malformed_tag().kind(),
            AuthErrorKind::MalformedTag
        );
        assert_eq!(AuthError::no_context().kind(), AuthErrorKind::NoContext);
    }
}
