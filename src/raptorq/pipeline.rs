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
    #[allow(clippy::result_large_err)]
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
        // Pool max_size must accommodate all source + repair symbols for this
        // object. The configured pool_size is a hint for pre-allocation, but
        // the actual need depends on the data length.
        let source_count = data
            .len()
            .div_ceil(self.config.encoding.symbol_size as usize);
        let needed_symbols = source_count + repair_count;
        let pool_max = self.config.resources.symbol_pool_size.max(needed_symbols);
        let pool = SymbolPool::new(PoolConfig {
            symbol_size: self.config.encoding.symbol_size,
            initial_size: self.config.resources.symbol_pool_size,
            max_size: pool_max,
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
    #[allow(clippy::result_large_err)]
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
    #[allow(clippy::result_large_err)]
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

#[allow(clippy::cast_precision_loss)]
#[allow(clippy::cast_sign_loss)]
fn compute_repair_count(data_len: usize, symbol_size: usize, overhead: f64) -> usize {
    // Overhead is defined as a multiplicative factor on the number of *source*
    // symbols (e.g. 1.05 means "5% extra symbols"). An overhead of 1.0 means
    // "no repairs requested".
    if symbol_size == 0 || data_len == 0 || overhead <= 1.0 {
        return 0;
    }
    let source_count = data_len.div_ceil(symbol_size);
    let total = (source_count as f64 * overhead).ceil() as usize;
    // If overhead > 1.0, we always want at least one repair symbol.
    total.saturating_sub(source_count).max(1)
}

/// Synchronous single-poll for sending a symbol.
#[allow(clippy::result_large_err)]
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
            // Phase 0: sim transports are always ready; real async comes later.
            Err(Error::new(ErrorKind::SinkRejected)
                .with_message("transport not ready (sync context)"))
        }
    }
}

/// Synchronous single-poll for flushing.
#[allow(clippy::result_large_err)]
fn poll_flush_blocking<T: SymbolSink + Unpin>(sink: &mut T) -> Result<(), Error> {
    let waker = std::task::Waker::noop();
    let mut ctx = Context::from_waker(waker);

    match Pin::new(sink).poll_flush(&mut ctx) {
        Poll::Ready(Err(e)) => {
            Err(Error::new(ErrorKind::DispatchFailed).with_message(e.to_string()))
        }
        Poll::Ready(Ok(())) | Poll::Pending => Ok(()), // Best-effort flush in sync context
    }
}

/// Synchronous single-poll for receiving a symbol.
#[allow(clippy::result_large_err)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::{AuthenticationTag, SecurityContext};
    use crate::transport::error::{SinkError, StreamError};
    use crate::types::symbol::{ObjectId, ObjectParams, Symbol};
    use std::pin::Pin;
    use std::task::{Context, Poll};

    struct VecSink {
        symbols: Vec<AuthenticatedSymbol>,
    }

    impl VecSink {
        fn new() -> Self {
            Self {
                symbols: Vec::new(),
            }
        }
    }

    impl SymbolSink for VecSink {
        fn poll_send(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            symbol: AuthenticatedSymbol,
        ) -> Poll<Result<(), SinkError>> {
            self.symbols.push(symbol);
            Poll::Ready(Ok(()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            Poll::Ready(Ok(()))
        }

        fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Unpin for VecSink {}

    struct PendingSink;

    impl SymbolSink for PendingSink {
        fn poll_send(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _symbol: AuthenticatedSymbol,
        ) -> Poll<Result<(), SinkError>> {
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            Poll::Ready(Ok(()))
        }

        fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Unpin for PendingSink {}

    struct VecStream {
        symbols: Vec<AuthenticatedSymbol>,
        index: usize,
    }

    impl VecStream {
        fn new(symbols: Vec<AuthenticatedSymbol>) -> Self {
            Self { symbols, index: 0 }
        }
    }

    impl SymbolStream for VecStream {
        fn poll_next(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
            if self.index < self.symbols.len() {
                let sym = self.symbols[self.index].clone();
                self.index += 1;
                Poll::Ready(Some(Ok(sym)))
            } else {
                Poll::Ready(None)
            }
        }
    }

    impl Unpin for VecStream {}

    fn params_for(
        object_id: ObjectId,
        data_len: usize,
        symbol_size: u16,
        source_symbols: usize,
    ) -> ObjectParams {
        ObjectParams::new(
            object_id,
            data_len as u64,
            symbol_size,
            1,
            source_symbols as u16,
        )
    }

    #[test]
    fn compute_repair_count_overhead_one_requests_zero_repairs() {
        // EncodingConfig docs: repair_overhead=1.0 means "0% extra symbols".
        let data_len = 1024;
        let symbol_size = 256;
        assert_eq!(compute_repair_count(data_len, symbol_size, 1.0), 0);
    }

    #[test]
    fn compute_repair_count_empty_data_requests_zero_repairs() {
        assert_eq!(compute_repair_count(0, 256, 1.10), 0);
    }

    #[test]
    fn compute_repair_count_overhead_above_one_requests_at_least_one_repair() {
        // For small objects, rounding means a small overhead still produces one repair symbol.
        let data_len = 64;
        let symbol_size = 256;
        assert_eq!(compute_repair_count(data_len, symbol_size, 1.01), 1);
    }

    #[test]
    fn test_send_object_roundtrip_all_symbols_succeeds() {
        let cx: Cx = Cx::for_testing();
        let sink = VecSink::new();
        let mut sender = RaptorQSender::new(RaptorQConfig::default(), sink, None, None);

        let data = vec![0xABu8; 512];
        let object_id = ObjectId::new_for_test(7);
        let outcome = sender.send_object(&cx, object_id, &data).unwrap();
        let params = params_for(
            object_id,
            data.len(),
            sender.config().encoding.symbol_size,
            outcome.source_symbols,
        );

        let symbols: Vec<AuthenticatedSymbol> = sender.transport_mut().symbols.drain(..).collect();
        let stream = VecStream::new(symbols);
        let mut receiver = RaptorQReceiver::new(RaptorQConfig::default(), stream, None, None);

        let recv = receiver.receive_object(&cx, &params).unwrap();
        assert_eq!(&recv.data[..data.len()], &data);
        assert!(!recv.authenticated);
    }

    #[test]
    fn test_send_object_roundtrip_source_only_succeeds() {
        let cx: Cx = Cx::for_testing();
        let sink = VecSink::new();
        let mut sender = RaptorQSender::new(RaptorQConfig::default(), sink, None, None);

        let data = vec![0xCDu8; 256];
        let object_id = ObjectId::new_for_test(9);
        let outcome = sender.send_object(&cx, object_id, &data).unwrap();
        let params = params_for(
            object_id,
            data.len(),
            sender.config().encoding.symbol_size,
            outcome.source_symbols,
        );

        let mut symbols: Vec<AuthenticatedSymbol> =
            sender.transport_mut().symbols.drain(..).collect();
        symbols.truncate(outcome.source_symbols);
        let stream = VecStream::new(symbols);
        let mut receiver = RaptorQReceiver::new(RaptorQConfig::default(), stream, None, None);

        let recv = receiver.receive_object(&cx, &params).unwrap();
        assert_eq!(&recv.data[..data.len()], &data);
    }

    #[test]
    fn test_send_object_rejects_oversized_data() {
        let cx: Cx = Cx::for_testing();
        let sink = VecSink::new();
        let mut sender = RaptorQSender::new(RaptorQConfig::default(), sink, None, None);

        let max = u64::from(sender.config().encoding.symbol_size)
            * sender.config().encoding.max_block_size as u64;
        let data = vec![0u8; (max + 1) as usize];
        let result = sender.send_object(&cx, ObjectId::new_for_test(1), &data);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::DataTooLarge);
    }

    #[test]
    fn test_send_object_cancelled_returns_cancelled() {
        let cx: Cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let sink = VecSink::new();
        let mut sender = RaptorQSender::new(RaptorQConfig::default(), sink, None, None);
        let data = vec![0xEFu8; 64];
        let result = sender.send_object(&cx, ObjectId::new_for_test(2), &data);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::Cancelled);
    }

    #[test]
    fn test_send_symbols_direct_count_matches() {
        let cx: Cx = Cx::for_testing();
        let sink = VecSink::new();
        let mut sender = RaptorQSender::new(RaptorQConfig::default(), sink, None, None);

        let symbols: Vec<AuthenticatedSymbol> = (0..3)
            .map(|i| {
                let sym = Symbol::new_for_test(1, 0, i, &[i as u8; 256]);
                AuthenticatedSymbol::new_verified(sym, AuthenticationTag::zero())
            })
            .collect();

        let count = sender.send_symbols(&cx, symbols).unwrap();
        assert_eq!(count, 3);
        assert_eq!(sender.transport_mut().symbols.len(), 3);
    }

    #[test]
    fn test_send_object_pending_sink_returns_rejected() {
        let cx: Cx = Cx::for_testing();
        let sink = PendingSink;
        let mut sender = RaptorQSender::new(RaptorQConfig::default(), sink, None, None);

        let data = vec![0xAAu8; 64];
        let result = sender.send_object(&cx, ObjectId::new_for_test(3), &data);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::SinkRejected);
    }

    #[test]
    fn test_receive_object_insufficient_symbols_errors() {
        let cx: Cx = Cx::for_testing();
        let stream = VecStream::new(vec![]);
        let mut receiver = RaptorQReceiver::new(RaptorQConfig::default(), stream, None, None);

        let params = params_for(ObjectId::new_for_test(5), 128, 256, 4);
        let result = receiver.receive_object(&cx, &params);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::InsufficientSymbols);
    }

    #[test]
    fn test_receive_object_cancelled_returns_cancelled() {
        let cx: Cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let stream = VecStream::new(vec![]);
        let mut receiver = RaptorQReceiver::new(RaptorQConfig::default(), stream, None, None);
        let params = params_for(ObjectId::new_for_test(6), 256, 256, 4);
        let result = receiver.receive_object(&cx, &params);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::Cancelled);
    }

    #[test]
    fn test_receive_object_authenticated_flag_true_with_security() {
        let cx: Cx = Cx::for_testing();
        let security = SecurityContext::for_testing(42);
        let sink = VecSink::new();
        let mut sender =
            RaptorQSender::new(RaptorQConfig::default(), sink, Some(security.clone()), None);

        // Use larger data to ensure k > L overhead requirements
        // With symbol_size=256, 1KB gives k=4, which has enough margin
        let data = vec![0x11u8; 1024];
        let object_id = ObjectId::new_for_test(10);
        let outcome = sender.send_object(&cx, object_id, &data).unwrap();
        let params = params_for(
            object_id,
            data.len(),
            sender.config().encoding.symbol_size,
            outcome.source_symbols,
        );

        let symbols: Vec<AuthenticatedSymbol> = sender.transport_mut().symbols.drain(..).collect();
        let stream = VecStream::new(symbols);
        let mut receiver =
            RaptorQReceiver::new(RaptorQConfig::default(), stream, Some(security), None);

        let recv = receiver.receive_object(&cx, &params).unwrap();
        assert!(recv.authenticated);
    }
}
