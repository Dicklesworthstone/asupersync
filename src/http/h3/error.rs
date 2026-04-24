//! Error types for HTTP/3 client operations.

use h3::error::{ConnectionError, StreamError};
use thiserror::Error;

/// Error type for HTTP/3 client operations.
#[derive(Debug, Error)]
pub enum H3Error {
    /// Connection-level error reported by the HTTP/3 stack.
    #[error("h3 connection error: {0}")]
    Connection(#[from] ConnectionError),

    /// Stream-level error reported by the HTTP/3 stack.
    #[error("h3 stream error: {0}")]
    Stream(#[from] StreamError),

    /// Operation was cancelled via `Cx` cancellation.
    #[error("cancelled")]
    Cancelled,

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl H3Error {
    /// Returns `true` if this error represents cancellation.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled)
    }
}

impl From<crate::error::Error> for H3Error {
    fn from(err: crate::error::Error) -> Self {
        if err.is_cancelled() {
            Self::Cancelled
        } else {
            Self::Io(std::io::Error::other(err.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::pedantic, clippy::nursery, clippy::expect_fun_call, clippy::map_unwrap_or, clippy::cast_possible_wrap, clippy::future_not_send)]
    use super::H3Error;
    use crate::error::Error;
    use crate::types::CancelReason;

    #[test]
    fn cancelled_error_maps() {
        let err = Error::cancelled(&CancelReason::user("test"));
        let mapped = H3Error::from(err);
        assert!(mapped.is_cancelled());
    }
}
