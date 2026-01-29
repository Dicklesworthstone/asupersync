//! End-to-end RaptorQ sender and receiver pipelines.
//!
//! These types compose encoding/decoding, security, transport, and
//! observability into ergonomic send/receive operations.

use std::pin::Pin;
use std::task::{Context, Poll};

use crate::config::RaptorQConfig;
use crate::cx::Cx;
use crate::decoding::{DecodingConfig, DecodingPipeline};
use crate::encoding::EncodingPipeline;
use crate::error::{Error, ErrorKind};
use crate::observability::Metrics;
use crate::security::{AuthenticatedSymbol, SecurityContext};
use crate::transport::sink::SymbolSink;
use crate::transport::stream::SymbolStream;
use crate::types::resource::{PoolConfig, SymbolPool};
use crate::types::symbol::{ObjectId, ObjectParams};

/// Outcome of a send operation.
#[derive(Debug, Clone)]
pub struct SendOutcome {
    /// Object identifier that was sent.
    pub object_id: ObjectId,
    /// Number of source symbols produced.
    pub source_symbols: usize,
    /// Number of repair symbols produced.
    pub repair_symbols: usize,
    /// Total symbols transmitted.
    pub symbols_sent: usize,
}

/// Progress callback information during send.
#[derive(Debug, Clone)]
pub struct SendProgress {
    /// Symbols sent so far.
    pub sent: usize,
    /// Total symbols to send.
    pub total: usize,
}

/// Outcome of a receive operation.
#[derive(Debug)]
pub struct ReceiveOutcome {
    /// Decoded data.
    pub data: Vec<u8>,
    /// Number of symbols used for decoding.
    pub symbols_received: usize,
    /// Whether authentication was verified.
    pub authenticated: bool,
}

/// Sender pipeline: encode → sign → transport.
pub struct RaptorQSender<T> {
    config: RaptorQConfig,
    transport: T,
    security: Option<SecurityContext>,
    metrics: Option<Metrics>,
}

impl<T: SymbolSink + Unpin> RaptorQSender<T> {
    /// Creates a new sender pipeline.
    pub(crate) fn new(
        config: RaptorQConfig,
        transport: T,
        security: Option<SecurityContext>,
        metrics: Option<Metrics>,
    ) -> Self {
        Self {
            config,
            transport,
            security,
            metrics,
        }
    }

    /// Encodes data and sends symbols through the transport.
    ///
    /// The capability context is checked for cancellation at each symbol boundary.
    pub fn send_object(
        &mut self,
        cx: &Cx,
        object_id: ObjectId,
        data: &[u8],
    ) -> Result<SendOutcome, Error> {
        // Validate data size.
        let max_size = (self.config.encoding.max_block_size as u64)
            * u64::from(self.config.encoding.symbol_size);
        if data.len() as u64 > max_size {
            return Err(Error::data_too_large(data.len() as u64, max_size));
        }

        // Encode.
        let repair_count = compute_repair_count(
            data.len(),
            self.config.encoding.symbol_size as usize,
            self.config.encoding.repair_overhead,
        );
        let pool = SymbolPool::new(PoolConfig {
            symbol_size: self.config.encoding.symbol_size,
            initial_size: self.config.resources.symbol_pool_size,
            max_size: self.config.resources.symbol_pool_size,
            allow_growth: true,
            growth_increment: 64,
        });
        let mut encoder = EncodingPipeline::new(self.config.encoding.clone(), pool);
        let symbol_iter = encoder.encode_with_repair(object_id, data, repair_count);

        // Collect encoded symbols, sign them, and transmit.
        let mut symbols_sent = 0usize;
        for encoded_result in symbol_iter {
            cx.checkpoint()?;

            let encoded_sym = encoded_result
                .map_err(|e| Error::new(ErrorKind::EncodingFailed).with_message(e.to_string()))?;
            let symbol = encoded_sym.into_symbol();
            let auth_symbol = self.sign(symbol);

            // Synchronous poll loop for send.
            poll_send_blocking(&mut self.transport, auth_symbol)?;
            symbols_sent += 1;

            if let Some(ref mut m) = self.metrics {
                m.counter("raptorq.symbols_sent").increment();
            }
        }

        // Flush transport.
        poll_flush_blocking(&mut self.transport)?;

        let stats = encoder.stats();
        if let Some(ref mut m) = self.metrics {
            m.counter("raptorq.objects_sent").increment();
        }

        Ok(SendOutcome {
            object_id,
            source_symbols: stats.source_symbols,
            repair_symbols: stats.repair_symbols,
            symbols_sent,
        })
    }

    /// Sends pre-encoded authenticated symbols.
    pub fn send_symbols(
        &mut self,
        cx: &Cx,
        symbols: impl IntoIterator<Item = AuthenticatedSymbol>,
    ) -> Result<usize, Error> {
        let mut count = 0;
        for sym in symbols {
            cx.checkpoint()?;
            poll_send_blocking(&mut self.transport, sym)?;
            count += 1;
        }
        poll_flush_blocking(&mut self.transport)?;
        Ok(count)
    }

    /// Returns a reference to the config.
    #[must_use]
    pub const fn config(&self) -> &RaptorQConfig {
        &self.config
    }

    /// Returns a mutable reference to the transport.
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    fn sign(&self, symbol: crate::types::Symbol) -> AuthenticatedSymbol {
        match &self.security {
            Some(ctx) => ctx.sign_symbol(&symbol),
            None => AuthenticatedSymbol::new_verified(
                symbol,
                crate::security::AuthenticationTag::zero(),
            ),
        }
    }
}

/// Receiver pipeline: transport → verify → decode.
pub struct RaptorQReceiver<S> {
    config: RaptorQConfig,
    source: S,
    security: Option<SecurityContext>,
    metrics: Option<Metrics>,
}

impl<S: SymbolStream + Unpin> RaptorQReceiver<S> {
    /// Creates a new receiver pipeline.
    pub(crate) fn new(
        config: RaptorQConfig,
        source: S,
        security: Option<SecurityContext>,
        metrics: Option<Metrics>,
    ) -> Self {
        Self {
            config,
            source,
            security,
            metrics,
        }
    }

    /// Receives and decodes an object from the stream.
    ///
    /// Reads symbols from the source until enough are collected to
    /// decode, then returns the reconstructed data.
    pub fn receive_object(
        &mut self,
        cx: &Cx,
        params: &ObjectParams,
    ) -> Result<ReceiveOutcome, Error> {
        let decoding_config = DecodingConfig {
            symbol_size: self.config.encoding.symbol_size,
            max_block_size: self.config.encoding.max_block_size,
            repair_overhead: self.config.encoding.repair_overhead,
            verify_auth: self.security.is_some(),
            ..Default::default()
        };

        let mut decoder = match &self.security {
            Some(ctx) => DecodingPipeline::with_auth(decoding_config, ctx.clone()),
            None => DecodingPipeline::new(decoding_config),
        };

        decoder.set_object_params(*params).map_err(Error::from)?;

        let mut symbols_received = 0usize;

        // Read symbols until decoding completes.
        while !decoder.is_complete() {
            cx.checkpoint()?;

            if let Some(auth_symbol) = poll_next_blocking(&mut self.source)? {
                // Skip symbols for other objects.
                if auth_symbol.symbol().object_id() != params.object_id {
                    continue;
                }

                let _ = decoder.feed(auth_symbol);
                symbols_received += 1;

                if let Some(ref mut m) = self.metrics {
                    m.counter("raptorq.symbols_received").increment();
                }
            } else {
                let progress = decoder.progress();
                return Err(Error::insufficient_symbols(
                    progress.symbols_received as u32,
                    progress.symbols_needed_estimate as u32,
                ));
            }
        }

        let authenticated = self.security.is_some();
        let data = decoder.into_data().map_err(Error::from)?;

        if let Some(ref mut m) = self.metrics {
            m.counter("raptorq.objects_received").increment();
        }

        Ok(ReceiveOutcome {
            data,
            symbols_received,
            authenticated,
        })
    }

    /// Returns a reference to the config.
    #[must_use]
    pub const fn config(&self) -> &RaptorQConfig {
        &self.config
    }

    /// Returns a mutable reference to the source stream.
    pub fn source_mut(&mut self) -> &mut S {
        &mut self.source
    }
}

// =========================================================================
// Helpers
// =========================================================================

fn compute_repair_count(data_len: usize, symbol_size: usize, overhead: f64) -> usize {
    if symbol_size == 0 {
        return 0;
    }
    let source_count = (data_len / symbol_size) + 1;
    let total = (source_count as f64 * overhead).ceil() as usize;
    total.saturating_sub(source_count).max(1)
}

/// Synchronous single-poll for sending a symbol.
fn poll_send_blocking<T: SymbolSink + Unpin>(
    sink: &mut T,
    symbol: AuthenticatedSymbol,
) -> Result<(), Error> {
    let waker = std::task::Waker::noop();
    let mut ctx = Context::from_waker(waker);

    match Pin::new(&mut *sink).poll_send(&mut ctx, symbol) {
        Poll::Ready(Ok(())) => Ok(()),
        Poll::Ready(Err(e)) => {
            Err(Error::new(ErrorKind::DispatchFailed).with_message(e.to_string()))
        }
        Poll::Pending => {
            // Phase 0: mock transports are always ready; real async comes later.
            Err(Error::new(ErrorKind::SinkRejected)
                .with_message("transport not ready (sync context)"))
        }
    }
}

/// Synchronous single-poll for flushing.
fn poll_flush_blocking<T: SymbolSink + Unpin>(sink: &mut T) -> Result<(), Error> {
    let waker = std::task::Waker::noop();
    let mut ctx = Context::from_waker(waker);

    match Pin::new(sink).poll_flush(&mut ctx) {
        Poll::Ready(Ok(())) => Ok(()),
        Poll::Ready(Err(e)) => {
            Err(Error::new(ErrorKind::DispatchFailed).with_message(e.to_string()))
        }
        Poll::Pending => Ok(()), // Best-effort flush in sync context
    }
}

/// Synchronous single-poll for receiving a symbol.
fn poll_next_blocking<S: SymbolStream + Unpin>(
    stream: &mut S,
) -> Result<Option<AuthenticatedSymbol>, Error> {
    let waker = std::task::Waker::noop();
    let mut ctx = Context::from_waker(waker);

    match Pin::new(stream).poll_next(&mut ctx) {
        Poll::Ready(Some(Ok(sym))) => Ok(Some(sym)),
        Poll::Ready(Some(Err(e))) => {
            Err(Error::new(ErrorKind::StreamEnded).with_message(e.to_string()))
        }
        Poll::Ready(None) | Poll::Pending => Ok(None), // No symbol available in sync context
    }
}
