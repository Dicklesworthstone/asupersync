//! Builder patterns for constructing RaptorQ sender and receiver pipelines.
//!
//! Builders enforce that required components (transport) are provided
//! before constructing the pipeline, while optional components (security,
//! metrics) are wired in when available.

use crate::config::RaptorQConfig;
use crate::error::{Error, ErrorKind};
use crate::observability::Metrics;
use crate::security::SecurityContext;
use crate::transport::sink::SymbolSink;
use crate::transport::stream::SymbolStream;

use super::pipeline::{RaptorQReceiver, RaptorQSender};

/// Builder for [`RaptorQSender`].
///
/// # Example
///
/// ```ignore
/// let sender = RaptorQSenderBuilder::new()
///     .config(config)
///     .transport(sink)
///     .security(security_ctx)
///     .build()?;
/// ```
pub struct RaptorQSenderBuilder<T = ()> {
    config: Option<RaptorQConfig>,
    transport: Option<T>,
    security: Option<SecurityContext>,
    metrics: Option<Metrics>,
}

impl<T> Default for RaptorQSenderBuilder<T> {
    fn default() -> Self {
        Self {
            config: None,
            transport: None,
            security: None,
            metrics: None,
        }
    }
}

impl RaptorQSenderBuilder<()> {
    /// Creates a new sender builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl<T> RaptorQSenderBuilder<T> {
    /// Sets the configuration.
    #[must_use]
    pub fn config(mut self, config: RaptorQConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Sets the transport sink.
    #[must_use]
    pub fn transport<U>(self, transport: U) -> RaptorQSenderBuilder<U> {
        RaptorQSenderBuilder {
            config: self.config,
            transport: Some(transport),
            security: self.security,
            metrics: self.metrics,
        }
    }

    /// Sets the security context for symbol signing.
    #[must_use]
    pub fn security(mut self, ctx: SecurityContext) -> Self {
        self.security = Some(ctx);
        self
    }

    /// Sets the metrics registry.
    #[must_use]
    pub fn metrics(mut self, metrics: Metrics) -> Self {
        self.metrics = Some(metrics);
        self
    }
}

impl<T: SymbolSink + Unpin> RaptorQSenderBuilder<T> {
    /// Builds the sender pipeline.
    ///
    /// # Errors
    ///
    /// Returns an error if no transport has been provided.
    #[allow(clippy::result_large_err)]
    pub fn build(self) -> Result<RaptorQSender<T>, Error> {
        let transport = self.transport.ok_or_else(|| {
            Error::new(ErrorKind::InvalidEncodingParams)
                .with_message("transport is required for RaptorQSender")
        })?;

        let config = self.config.unwrap_or_default();
        config.validate().map_err(|e| {
            Error::new(ErrorKind::InvalidEncodingParams).with_message(e.to_string())
        })?;

        Ok(RaptorQSender::new(
            config,
            transport,
            self.security,
            self.metrics,
        ))
    }
}

/// Builder for [`RaptorQReceiver`].
///
/// # Example
///
/// ```ignore
/// let receiver = RaptorQReceiverBuilder::new()
///     .config(config)
///     .source(stream)
///     .build()?;
/// ```
pub struct RaptorQReceiverBuilder<S = ()> {
    config: Option<RaptorQConfig>,
    source: Option<S>,
    security: Option<SecurityContext>,
    metrics: Option<Metrics>,
}

impl<S> Default for RaptorQReceiverBuilder<S> {
    fn default() -> Self {
        Self {
            config: None,
            source: None,
            security: None,
            metrics: None,
        }
    }
}

impl RaptorQReceiverBuilder<()> {
    /// Creates a new receiver builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl<S> RaptorQReceiverBuilder<S> {
    /// Sets the configuration.
    #[must_use]
    pub fn config(mut self, config: RaptorQConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Sets the symbol source stream.
    #[must_use]
    pub fn source<U>(self, source: U) -> RaptorQReceiverBuilder<U> {
        RaptorQReceiverBuilder {
            config: self.config,
            source: Some(source),
            security: self.security,
            metrics: self.metrics,
        }
    }

    /// Sets the security context for symbol verification.
    #[must_use]
    pub fn security(mut self, ctx: SecurityContext) -> Self {
        self.security = Some(ctx);
        self
    }

    /// Sets the metrics registry.
    #[must_use]
    pub fn metrics(mut self, metrics: Metrics) -> Self {
        self.metrics = Some(metrics);
        self
    }
}

impl<S: SymbolStream + Unpin> RaptorQReceiverBuilder<S> {
    /// Builds the receiver pipeline.
    ///
    /// # Errors
    ///
    /// Returns an error if no source has been provided.
    #[allow(clippy::result_large_err)]
    pub fn build(self) -> Result<RaptorQReceiver<S>, Error> {
        let source = self.source.ok_or_else(|| {
            Error::new(ErrorKind::InvalidEncodingParams)
                .with_message("source is required for RaptorQReceiver")
        })?;

        let config = self.config.unwrap_or_default();
        config.validate().map_err(|e| {
            Error::new(ErrorKind::InvalidEncodingParams).with_message(e.to_string())
        })?;

        Ok(RaptorQReceiver::new(
            config,
            source,
            self.security,
            self.metrics,
        ))
    }
}
