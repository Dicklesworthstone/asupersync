//! End-to-end RaptorQ sender and receiver pipelines.
//!
//! These types compose encoding/decoding, security, transport, and
//! observability into ergonomic send/receive operations.

use std::pin::Pin;
use std::task::{Context, Poll};

use crate::config::RaptorQConfig;
use crate::cx::Cx;
use crate::decoding::{DecodingConfig, DecodingPipeline, RejectReason, SymbolAcceptResult};
use crate::encoding::{EncodingPipeline, max_object_size};
use crate::error::{Error, ErrorKind};
use crate::observability::Metrics;
use crate::security::{AuthenticatedSymbol, SecurityContext};
use crate::transport::error::StreamError;
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
    /// Whether every symbol consumed for decode was cryptographically verified.
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
        // Keep sender-side validation aligned with the encoder/decoder byte contract:
        // an object may span up to 256 source blocks because SBN is u8.
        let max_size = max_object_size(self.config.encoding.max_block_size) as u64;
        if data.len() as u64 > max_size {
            return Err(Error::data_too_large(data.len() as u64, max_size));
        }

        // Encode.
        let total_repair_symbols = compute_total_repair_count(
            data.len(),
            self.config.encoding.max_block_size,
            self.config.encoding.symbol_size as usize,
            self.config.encoding.repair_overhead,
        );
        // Pool max_size must accommodate all source + repair symbols for this
        // object. The configured pool_size is a hint for pre-allocation, but
        // the actual need depends on the data length.
        let sym_size = self.config.encoding.symbol_size as usize;
        let source_count = if sym_size == 0 {
            0
        } else {
            data.len().div_ceil(sym_size)
        };
        let (pool_initial, pool_max) = sender_pool_bounds(
            self.config.resources.symbol_pool_size,
            source_count,
            total_repair_symbols,
        );
        let pool = SymbolPool::new(PoolConfig {
            symbol_size: self.config.encoding.symbol_size,
            initial_size: pool_initial,
            max_size: pool_max,
            allow_growth: true,
            growth_increment: 64,
        });
        let mut encoder = EncodingPipeline::new(self.config.encoding.clone(), pool);
        let symbol_iter = encoder.encode(object_id, data);

        // Collect encoded symbols, sign them, and transmit.
        let mut symbols_sent = 0usize;
        for encoded_result in symbol_iter {
            cx.checkpoint()?;

            let encoded_sym = encoded_result.map_err(Error::from)?;
            let symbol = encoded_sym.into_symbol();
            let auth_symbol = self.sign(symbol);

            // Synchronous poll loop for send.
            poll_send_blocking(&mut self.transport, auth_symbol)?;
            symbols_sent += 1;
        }

        // Flush transport.
        poll_flush_blocking(&mut self.transport)?;

        if let Some(ref mut m) = self.metrics {
            m.counter("raptorq.symbols_sent")
                .add(symbols_sent.try_into().unwrap_or(u64::MAX));
        }

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
        if let Some(ref mut m) = self.metrics {
            m.counter("raptorq.symbols_sent")
                .add(count.try_into().unwrap_or(u64::MAX));
        }
        Ok(count)
    }

    /// Returns a reference to the config.
    #[must_use]
    #[inline]
    pub const fn config(&self) -> &RaptorQConfig {
        &self.config
    }

    /// Returns a mutable reference to the transport.
    #[inline]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    #[inline]
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
            // Authenticate target-object symbols at the receiver boundary so
            // strict mode fails closed before decode and ReceiveOutcome can
            // report whether consumed symbols were actually verified.
            verify_auth: false,
            ..Default::default()
        };

        let mut decoder = DecodingPipeline::new(decoding_config);

        decoder.set_object_params(*params).map_err(Error::from)?;

        let mut symbols_received = 0usize;
        let mut authenticated = self.security.is_some();

        // Read symbols until decoding completes.
        while !decoder.is_complete() {
            cx.checkpoint()?;

            if let Some(mut auth_symbol) = poll_next_blocking(&mut self.source)? {
                // Skip symbols for other objects.
                if auth_symbol.symbol().object_id() != params.object_id {
                    continue;
                }

                if let Some(ctx) = &self.security {
                    ctx.verify_authenticated_symbol(&mut auth_symbol)
                        .map_err(|err| {
                            Error::new(ErrorKind::CorruptedSymbol).with_message(err.to_string())
                        })?;
                    authenticated &= auth_symbol.is_verified();
                }

                match decoder.feed(auth_symbol).map_err(Error::from)? {
                    SymbolAcceptResult::Accepted { .. }
                    | SymbolAcceptResult::DecodingStarted { .. }
                    | SymbolAcceptResult::BlockComplete { .. } => {
                        symbols_received += 1;
                        if let Some(ref mut m) = self.metrics {
                            m.counter("raptorq.symbols_received").increment();
                        }
                    }
                    SymbolAcceptResult::Rejected(RejectReason::AuthenticationFailed) => {
                        return Err(Error::new(ErrorKind::CorruptedSymbol)
                            .with_message("symbol authentication failed during receive"));
                    }
                    SymbolAcceptResult::Duplicate | SymbolAcceptResult::Rejected(_) => {
                        // Not used for decoding; keep waiting for usable symbols.
                    }
                }
            } else {
                let progress = decoder.progress();
                return Err(Error::insufficient_symbols(
                    usize_to_u32_saturating(progress.symbols_received),
                    usize_to_u32_saturating(progress.symbols_needed_estimate),
                ));
            }
        }

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
    #[inline]
    pub const fn config(&self) -> &RaptorQConfig {
        &self.config
    }

    /// Returns a mutable reference to the source stream.
    #[inline]
    pub fn source_mut(&mut self) -> &mut S {
        &mut self.source
    }
}

// =========================================================================
// Helpers
// =========================================================================

#[cfg(test)]
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
    compute_repair_count_for_source_symbols(source_count, overhead)
}

#[allow(clippy::cast_precision_loss)]
#[allow(clippy::cast_sign_loss)]
fn compute_repair_count_for_source_symbols(source_count: usize, overhead: f64) -> usize {
    if source_count == 0 || overhead <= 1.0 {
        return 0;
    }

    let total = (source_count as f64 * overhead).ceil() as usize;
    // If overhead > 1.0, we always want at least one repair symbol.
    total.saturating_sub(source_count).max(1)
}

fn compute_total_repair_count(
    data_len: usize,
    max_block_size: usize,
    symbol_size: usize,
    overhead: f64,
) -> usize {
    if max_block_size == 0 || symbol_size == 0 || data_len == 0 || overhead <= 1.0 {
        return 0;
    }

    let mut remaining = data_len;
    let mut total_repairs = 0usize;
    while remaining > 0 {
        let block_len = remaining.min(max_block_size);
        let source_symbols = block_len.div_ceil(symbol_size);
        total_repairs = total_repairs.saturating_add(compute_repair_count_for_source_symbols(
            source_symbols,
            overhead,
        ));
        remaining -= block_len;
    }

    total_repairs
}

/// Derives deterministic symbol-pool bounds for a single send operation.
///
/// The lower bound is capped to actual per-object demand so small sends avoid
/// large pre-allocation bursts, while the upper bound preserves enough headroom
/// for full source+repair coverage.
#[inline]
fn sender_pool_bounds(
    configured_pool_size: usize,
    source_symbols: usize,
    repair_symbols: usize,
) -> (usize, usize) {
    let needed_symbols = source_symbols.saturating_add(repair_symbols);
    (
        configured_pool_size.min(needed_symbols),
        configured_pool_size.max(needed_symbols),
    )
}

#[inline]
fn usize_to_u32_saturating(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn map_stream_error(error: StreamError) -> Error {
    let message = error.to_string();
    let kind = match error {
        StreamError::Closed | StreamError::PolledAfterCompletion => ErrorKind::StreamEnded,
        StreamError::Reset => ErrorKind::ConnectionLost,
        StreamError::Timeout => ErrorKind::ThresholdTimeout,
        StreamError::AuthenticationFailed { .. } => ErrorKind::CorruptedSymbol,
        StreamError::ProtocolError { .. } => ErrorKind::ProtocolError,
        StreamError::Io { source } => match source.kind() {
            std::io::ErrorKind::TimedOut => ErrorKind::ThresholdTimeout,
            std::io::ErrorKind::ConnectionRefused => ErrorKind::ConnectionRefused,
            std::io::ErrorKind::InvalidData | std::io::ErrorKind::InvalidInput => {
                ErrorKind::ProtocolError
            }
            _ => ErrorKind::ConnectionLost,
        },
        StreamError::Cancelled => ErrorKind::Cancelled,
    };
    Error::new(kind).with_message(message)
}

/// Synchronous single-poll for sending a symbol.
#[allow(clippy::result_large_err)]
fn poll_send_blocking<T: SymbolSink + Unpin>(
    sink: &mut T,
    symbol: AuthenticatedSymbol,
) -> Result<(), Error> {
    let waker = std::task::Waker::noop();
    let mut ctx = Context::from_waker(waker);

    match Pin::new(&mut *sink).poll_ready(&mut ctx) {
        Poll::Ready(Ok(())) => {}
        Poll::Ready(Err(e)) => {
            return Err(Error::new(ErrorKind::DispatchFailed).with_message(e.to_string()));
        }
        Poll::Pending => {
            return Err(Error::new(ErrorKind::SinkRejected)
                .with_message("transport not ready (sync context)"));
        }
    }

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
        Poll::Ready(Ok(())) => Ok(()),
        Poll::Pending => Err(Error::new(ErrorKind::SinkRejected)
            .with_message("transport flush not ready (sync context)")),
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
        Poll::Ready(Some(Err(e))) => Err(map_stream_error(e)),
        Poll::Ready(None) => Ok(None),
        Poll::Pending => Err(Error::new(ErrorKind::SinkRejected)
            .with_message("source stream not ready (sync context)")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observability::Metrics;
    use crate::security::{AuthMode, AuthenticationTag, SecurityContext};
    use crate::transport::channel;
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

    struct FlushPendingSink {
        symbols: Vec<AuthenticatedSymbol>,
    }

    impl FlushPendingSink {
        fn new() -> Self {
            Self {
                symbols: Vec::new(),
            }
        }
    }

    impl SymbolSink for FlushPendingSink {
        fn poll_send(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            symbol: AuthenticatedSymbol,
        ) -> Poll<Result<(), SinkError>> {
            self.symbols.push(symbol);
            Poll::Ready(Ok(()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            Poll::Pending
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            Poll::Ready(Ok(()))
        }

        fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Unpin for FlushPendingSink {}

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

    struct PendingStream;

    impl SymbolStream for PendingStream {
        fn poll_next(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
            Poll::Pending
        }
    }

    impl Unpin for PendingStream {}

    struct ErrorStream {
        error: Option<StreamError>,
    }

    impl ErrorStream {
        fn new(error: StreamError) -> Self {
            Self { error: Some(error) }
        }
    }

    impl SymbolStream for ErrorStream {
        fn poll_next(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
            Poll::Ready(self.error.take().map(Err))
        }
    }

    impl Unpin for ErrorStream {}

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
    fn compute_total_repair_count_uses_per_block_ceilings() {
        let data_len = 161;
        let max_block_size = 80;
        let symbol_size = 8;
        let overhead = 1.05;

        assert_eq!(compute_repair_count(data_len, symbol_size, overhead), 2);
        assert_eq!(
            compute_total_repair_count(data_len, max_block_size, symbol_size, overhead),
            3
        );
    }

    #[test]
    fn sender_pool_bounds_caps_initial_allocation_to_object_need() {
        let configured_pool_size = 1024;
        let source_symbols = 256;
        let repair_symbols = 64;

        let (initial, max) =
            sender_pool_bounds(configured_pool_size, source_symbols, repair_symbols);
        assert_eq!(
            initial, 320,
            "initial pool should be capped to required source+repair symbols"
        );
        assert_eq!(
            max, configured_pool_size,
            "max pool should preserve configured ceiling when it exceeds object need"
        );
    }

    #[test]
    fn sender_pool_bounds_preserves_capacity_for_large_objects() {
        let configured_pool_size = 1024;
        let source_symbols = 1200;
        let repair_symbols = 300;

        let (initial, max) =
            sender_pool_bounds(configured_pool_size, source_symbols, repair_symbols);
        assert_eq!(
            initial, configured_pool_size,
            "initial pool should remain configured when object need exceeds baseline"
        );
        assert_eq!(
            max, 1500,
            "max pool should expand to full source+repair demand"
        );
    }

    #[test]
    fn usize_to_u32_saturating_caps_large_values() {
        assert_eq!(usize_to_u32_saturating(42), 42);
        assert_eq!(usize_to_u32_saturating(usize::MAX), u32::MAX);
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

        let max = max_object_size(sender.config().encoding.max_block_size) as u64;
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
    fn test_send_object_accepts_valid_non_default_small_symbol_size() {
        let cx: Cx = Cx::for_testing();
        let sink = VecSink::new();
        let mut config = RaptorQConfig::default();
        config.encoding.symbol_size = 8;
        config.encoding.max_block_size = 32;
        config.encoding.repair_overhead = 1.0;
        let mut sender = RaptorQSender::new(config, sink, None, None);

        // This exceeded the old max_block_size * symbol_size guard, but it still fits
        // within the byte-based 256-block contract enforced by EncodingPipeline.
        let data = vec![0xA5u8; 257];
        let outcome = sender
            .send_object(&cx, ObjectId::new_for_test(20), &data)
            .expect("byte-valid payload should not be rejected early");

        assert!(outcome.symbols_sent >= outcome.source_symbols);
        assert_eq!(sender.transport_mut().symbols.len(), outcome.symbols_sent);
    }

    #[test]
    fn test_send_object_multiblock_uses_per_block_repair_budget() {
        let cx: Cx = Cx::for_testing();
        let sink = VecSink::new();
        let mut config = RaptorQConfig::default();
        config.encoding.symbol_size = 8;
        config.encoding.max_block_size = 80;
        config.encoding.repair_overhead = 1.05;
        config.resources.symbol_pool_size = 1;
        let mut sender = RaptorQSender::new(config, sink, None, None);

        let data = vec![0xA5u8; 161];
        let outcome = sender
            .send_object(&cx, ObjectId::new_for_test(22), &data)
            .expect("multi-block send should size repairs and pool from block-local needs");

        assert_eq!(outcome.source_symbols, 21);
        assert_eq!(outcome.repair_symbols, 3);
        assert_eq!(outcome.symbols_sent, 24);
        assert_eq!(sender.transport_mut().symbols.len(), outcome.symbols_sent);
    }

    #[test]
    fn test_send_object_rejects_large_symbol_size_payload_with_data_too_large() {
        let cx: Cx = Cx::for_testing();
        let sink = VecSink::new();
        let mut config = RaptorQConfig::default();
        config.encoding.symbol_size = 512;
        config.encoding.max_block_size = 32;
        config.encoding.repair_overhead = 1.0;
        let mut sender = RaptorQSender::new(config, sink, None, None);

        let data = vec![0u8; max_object_size(sender.config().encoding.max_block_size) + 1];
        let err = sender
            .send_object(&cx, ObjectId::new_for_test(21), &data)
            .expect_err("payload beyond byte contract must fail before encoding");

        assert_eq!(err.kind(), ErrorKind::DataTooLarge);
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
    fn test_send_symbols_successful_flush_records_metrics() {
        let cx: Cx = Cx::for_testing();
        let sink = VecSink::new();
        let mut metrics = Metrics::new();
        let symbols_sent_counter = metrics.counter("raptorq.symbols_sent");
        let mut sender = RaptorQSender::new(RaptorQConfig::default(), sink, None, Some(metrics));

        let symbols: Vec<AuthenticatedSymbol> = (0..4)
            .map(|i| {
                let sym = Symbol::new_for_test(1, 0, i, &[i as u8; 256]);
                AuthenticatedSymbol::new_verified(sym, AuthenticationTag::zero())
            })
            .collect();

        let count = sender
            .send_symbols(&cx, symbols)
            .expect("successful direct symbol flush should record metrics");

        assert_eq!(count, 4);
        assert_eq!(symbols_sent_counter.get(), 4);
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
    fn test_send_object_pending_flush_returns_rejected() {
        let cx: Cx = Cx::for_testing();
        let sink = FlushPendingSink::new();
        let mut sender = RaptorQSender::new(RaptorQConfig::default(), sink, None, None);

        let data = vec![0x33u8; 64];
        let result = sender.send_object(&cx, ObjectId::new_for_test(31), &data);
        let err = result.expect_err("pending flush must not report send success");

        assert_eq!(err.kind(), ErrorKind::SinkRejected);
        assert!(
            !sender.transport_mut().symbols.is_empty(),
            "symbols may have been accepted before flush blocked"
        );
    }

    #[test]
    fn test_send_object_channel_backpressure_returns_rejected() {
        let cx: Cx = Cx::for_testing();
        let (sink, _stream) = channel(1);
        let mut sender = RaptorQSender::new(RaptorQConfig::default(), sink, None, None);

        let data = vec![0x33u8; 257];
        let err = sender
            .send_object(&cx, ObjectId::new_for_test(34), &data)
            .expect_err("channel backpressure must fail closed as not-ready");

        assert_eq!(err.kind(), ErrorKind::SinkRejected);
    }

    #[test]
    fn test_send_symbols_pending_flush_returns_rejected() {
        let cx: Cx = Cx::for_testing();
        let sink = FlushPendingSink::new();
        let mut sender = RaptorQSender::new(RaptorQConfig::default(), sink, None, None);

        let symbols: Vec<AuthenticatedSymbol> = (0..2)
            .map(|i| {
                let sym = Symbol::new_for_test(1, 0, i, &[i as u8; 256]);
                AuthenticatedSymbol::new_verified(sym, AuthenticationTag::zero())
            })
            .collect();

        let err = sender
            .send_symbols(&cx, symbols)
            .expect_err("pending flush must not report direct send success");

        assert_eq!(err.kind(), ErrorKind::SinkRejected);
        assert_eq!(
            sender.transport_mut().symbols.len(),
            2,
            "all symbols may be staged before flush reports pending"
        );
    }

    #[test]
    fn test_send_symbols_pending_flush_does_not_increment_metrics() {
        let cx: Cx = Cx::for_testing();
        let sink = FlushPendingSink::new();
        let mut metrics = Metrics::new();
        let symbols_sent_counter = metrics.counter("raptorq.symbols_sent");
        let mut sender = RaptorQSender::new(RaptorQConfig::default(), sink, None, Some(metrics));

        let symbols: Vec<AuthenticatedSymbol> = (0..2)
            .map(|i| {
                let sym = Symbol::new_for_test(1, 0, i, &[i as u8; 256]);
                AuthenticatedSymbol::new_verified(sym, AuthenticationTag::zero())
            })
            .collect();

        let err = sender
            .send_symbols(&cx, symbols)
            .expect_err("pending flush must not report direct send success");

        assert_eq!(err.kind(), ErrorKind::SinkRejected);
        assert_eq!(
            symbols_sent_counter.get(),
            0,
            "flush failure must not overcount direct symbol sends"
        );
    }

    #[test]
    fn test_send_symbols_channel_backpressure_returns_rejected() {
        let cx: Cx = Cx::for_testing();
        let (sink, _stream) = channel(1);
        let mut sender = RaptorQSender::new(RaptorQConfig::default(), sink, None, None);

        let symbols: Vec<AuthenticatedSymbol> = (0..2)
            .map(|i| {
                let sym = Symbol::new_for_test(1, 0, i, &[i as u8; 256]);
                AuthenticatedSymbol::new_verified(sym, AuthenticationTag::zero())
            })
            .collect();

        let err = sender
            .send_symbols(&cx, symbols)
            .expect_err("channel backpressure must fail closed as not-ready");

        assert_eq!(err.kind(), ErrorKind::SinkRejected);
    }

    #[test]
    fn test_send_object_metrics_increment_only_after_successful_flush() {
        let cx: Cx = Cx::for_testing();
        let sink = VecSink::new();
        let mut metrics = Metrics::new();
        let symbols_sent_counter = metrics.counter("raptorq.symbols_sent");
        let objects_sent_counter = metrics.counter("raptorq.objects_sent");
        let mut sender = RaptorQSender::new(RaptorQConfig::default(), sink, None, Some(metrics));

        let data = vec![0x5Au8; 64];
        let outcome = sender
            .send_object(&cx, ObjectId::new_for_test(32), &data)
            .expect("successful flush should record metrics");

        assert_eq!(symbols_sent_counter.get(), outcome.symbols_sent as u64);
        assert_eq!(objects_sent_counter.get(), 1);
    }

    #[test]
    fn test_send_object_pending_flush_does_not_increment_sent_metrics() {
        let cx: Cx = Cx::for_testing();
        let sink = FlushPendingSink::new();
        let mut metrics = Metrics::new();
        let symbols_sent_counter = metrics.counter("raptorq.symbols_sent");
        let objects_sent_counter = metrics.counter("raptorq.objects_sent");
        let mut sender = RaptorQSender::new(RaptorQConfig::default(), sink, None, Some(metrics));

        let data = vec![0x44u8; 64];
        let err = sender
            .send_object(&cx, ObjectId::new_for_test(33), &data)
            .expect_err("pending flush must not report success");

        assert_eq!(err.kind(), ErrorKind::SinkRejected);
        assert_eq!(
            symbols_sent_counter.get(),
            0,
            "flush failure must not overcount sent symbols"
        );
        assert_eq!(objects_sent_counter.get(), 0);
    }

    #[test]
    fn test_receive_object_insufficient_symbols_errors() {
        let cx: Cx = Cx::for_testing();
        let stream = VecStream::new(vec![]);
        let mut receiver = RaptorQReceiver::new(RaptorQConfig::default(), stream, None, None);

        let params = params_for(ObjectId::new_for_test(5), 128, 256, 1);
        let result = receiver.receive_object(&cx, &params);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::InsufficientSymbols);
    }

    #[test]
    fn test_receive_object_pending_stream_returns_rejected() {
        let cx: Cx = Cx::for_testing();
        let stream = PendingStream;
        let mut receiver = RaptorQReceiver::new(RaptorQConfig::default(), stream, None, None);

        let params = params_for(ObjectId::new_for_test(12), 128, 256, 1);
        let result = receiver.receive_object(&cx, &params);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::SinkRejected);
    }

    #[test]
    fn test_receive_object_stream_auth_failure_maps_to_corrupted_symbol() {
        let cx: Cx = Cx::for_testing();
        let stream = ErrorStream::new(StreamError::AuthenticationFailed {
            reason: "bad tag".to_string(),
        });
        let mut receiver = RaptorQReceiver::new(RaptorQConfig::default(), stream, None, None);

        let params = params_for(ObjectId::new_for_test(40), 128, 256, 1);
        let err = receiver
            .receive_object(&cx, &params)
            .expect_err("auth failure must fail closed");

        assert_eq!(err.kind(), ErrorKind::CorruptedSymbol);
        assert!(err.to_string().contains("bad tag"));
    }

    #[test]
    fn test_receive_object_stream_protocol_error_preserves_protocol_kind() {
        let cx: Cx = Cx::for_testing();
        let stream = ErrorStream::new(StreamError::ProtocolError {
            details: "frame mismatch".to_string(),
        });
        let mut receiver = RaptorQReceiver::new(RaptorQConfig::default(), stream, None, None);

        let params = params_for(ObjectId::new_for_test(41), 128, 256, 1);
        let err = receiver
            .receive_object(&cx, &params)
            .expect_err("protocol failures must not be flattened");

        assert_eq!(err.kind(), ErrorKind::ProtocolError);
        assert!(err.to_string().contains("frame mismatch"));
    }

    #[test]
    fn test_receive_object_stream_reset_maps_to_connection_lost() {
        let cx: Cx = Cx::for_testing();
        let stream = ErrorStream::new(StreamError::Reset);
        let mut receiver = RaptorQReceiver::new(RaptorQConfig::default(), stream, None, None);

        let params = params_for(ObjectId::new_for_test(42), 128, 256, 1);
        let err = receiver
            .receive_object(&cx, &params)
            .expect_err("reset must surface as connection loss");

        assert_eq!(err.kind(), ErrorKind::ConnectionLost);
    }

    #[test]
    fn test_receive_object_stream_timeout_maps_to_threshold_timeout() {
        let cx: Cx = Cx::for_testing();
        let stream = ErrorStream::new(StreamError::Timeout);
        let mut receiver = RaptorQReceiver::new(RaptorQConfig::default(), stream, None, None);

        let params = params_for(ObjectId::new_for_test(43), 128, 256, 1);
        let err = receiver
            .receive_object(&cx, &params)
            .expect_err("timeout must remain distinguishable from stream end");

        assert_eq!(err.kind(), ErrorKind::ThresholdTimeout);
    }

    #[test]
    fn test_receive_object_stream_cancelled_preserves_cancelled_kind() {
        let cx: Cx = Cx::for_testing();
        let stream = ErrorStream::new(StreamError::Cancelled);
        let mut receiver = RaptorQReceiver::new(RaptorQConfig::default(), stream, None, None);

        let params = params_for(ObjectId::new_for_test(44), 128, 256, 1);
        let err = receiver
            .receive_object(&cx, &params)
            .expect_err("stream cancellation must stay cancelled");

        assert_eq!(err.kind(), ErrorKind::Cancelled);
    }

    #[test]
    fn test_receive_object_cancelled_returns_cancelled() {
        let cx: Cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let stream = VecStream::new(vec![]);
        let mut receiver = RaptorQReceiver::new(RaptorQConfig::default(), stream, None, None);
        let params = params_for(ObjectId::new_for_test(6), 256, 256, 1);
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

    #[test]
    fn test_receive_object_bad_target_tag_with_strict_security_fails_closed() {
        let cx: Cx = Cx::for_testing();
        let sender_security = SecurityContext::for_testing(42);
        let sink = VecSink::new();
        let mut sender =
            RaptorQSender::new(RaptorQConfig::default(), sink, Some(sender_security), None);

        let data = vec![0x11u8; 1024];
        let object_id = ObjectId::new_for_test(45);
        let outcome = sender.send_object(&cx, object_id, &data).unwrap();
        let params = params_for(
            object_id,
            data.len(),
            sender.config().encoding.symbol_size,
            outcome.source_symbols,
        );

        let mut symbols: Vec<AuthenticatedSymbol> =
            sender.transport_mut().symbols.drain(..).collect();
        let corrupted = symbols.remove(0);
        symbols.insert(
            0,
            AuthenticatedSymbol::from_parts(corrupted.into_symbol(), AuthenticationTag::zero()),
        );
        let stream = VecStream::new(symbols);
        let mut receiver = RaptorQReceiver::new(
            RaptorQConfig::default(),
            stream,
            Some(SecurityContext::for_testing(42)),
            None,
        );

        let err = receiver
            .receive_object(&cx, &params)
            .expect_err("strict auth should fail closed on a bad target tag");

        assert_eq!(err.kind(), ErrorKind::CorruptedSymbol);
    }

    #[test]
    fn test_receive_object_permissive_security_marks_receive_as_unauthenticated() {
        let cx: Cx = Cx::for_testing();
        let sender_security = SecurityContext::for_testing(42);
        let sink = VecSink::new();
        let mut sender =
            RaptorQSender::new(RaptorQConfig::default(), sink, Some(sender_security), None);

        let data = vec![0x77u8; 1024];
        let object_id = ObjectId::new_for_test(46);
        let outcome = sender.send_object(&cx, object_id, &data).unwrap();
        let params = params_for(
            object_id,
            data.len(),
            sender.config().encoding.symbol_size,
            outcome.source_symbols,
        );

        let mut symbols: Vec<AuthenticatedSymbol> =
            sender.transport_mut().symbols.drain(..).collect();
        let corrupted = symbols.remove(0);
        symbols.insert(
            0,
            AuthenticatedSymbol::from_parts(corrupted.into_symbol(), AuthenticationTag::zero()),
        );
        let stream = VecStream::new(symbols);
        let mut receiver = RaptorQReceiver::new(
            RaptorQConfig::default(),
            stream,
            Some(SecurityContext::for_testing(42).with_mode(AuthMode::Permissive)),
            None,
        );

        let recv = receiver
            .receive_object(&cx, &params)
            .expect("permissive mode should allow decode to continue");

        assert_eq!(&recv.data[..data.len()], &data);
        assert!(
            !recv.authenticated,
            "permissive-mode decode with an unverified symbol must not report authenticated"
        );
    }

    #[test]
    fn test_receive_object_duplicate_symbols_do_not_inflate_used_count() {
        let cx: Cx = Cx::for_testing();
        let sink = VecSink::new();
        let mut sender = RaptorQSender::new(RaptorQConfig::default(), sink, None, None);

        let data = vec![0x5Au8; 512];
        let object_id = ObjectId::new_for_test(11);
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
        let duplicate = symbols[0].clone();
        let mut stream_symbols = vec![duplicate.clone(), duplicate];
        stream_symbols.extend(symbols);

        let stream = VecStream::new(stream_symbols);
        let mut receiver = RaptorQReceiver::new(RaptorQConfig::default(), stream, None, None);
        let recv = receiver.receive_object(&cx, &params).unwrap();

        assert_eq!(&recv.data[..data.len()], &data);
        assert_eq!(
            recv.symbols_received, outcome.source_symbols,
            "duplicate symbols must not count as used-for-decoding"
        );
    }

    #[test]
    fn send_outcome_debug_clone() {
        let o = SendOutcome {
            object_id: ObjectId::new_for_test(1),
            source_symbols: 10,
            repair_symbols: 5,
            symbols_sent: 15,
        };
        let dbg = format!("{o:?}");
        assert!(dbg.contains("SendOutcome"), "{dbg}");
        let cloned = o;
        assert_eq!(format!("{cloned:?}"), dbg);
    }

    #[test]
    fn send_progress_debug_clone() {
        let p = SendProgress { sent: 3, total: 10 };
        let dbg = format!("{p:?}");
        assert!(dbg.contains("SendProgress"), "{dbg}");
        let cloned = p;
        assert_eq!(format!("{cloned:?}"), dbg);
    }

    #[test]
    fn receive_outcome_debug() {
        let r = ReceiveOutcome {
            data: vec![0u8; 16],
            symbols_received: 20,
            authenticated: true,
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("ReceiveOutcome"), "{dbg}");
    }
}
