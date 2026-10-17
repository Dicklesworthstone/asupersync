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
use crate::raptorq::systematic::SystematicParams;
use crate::security::{AuthMode, AuthenticatedSymbol, AuthenticatedSymbolState, SecurityContext};
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
    /// Authentication posture of the symbols accepted into the decode set.
    pub authentication: ReceiveAuthenticationSummary,
}

impl ReceiveOutcome {
    /// Returns true when the receive path verified every accepted decode symbol.
    #[must_use]
    pub fn all_symbols_verified(&self) -> bool {
        self.authenticated
            && self.authentication.total() == self.symbols_received
            && self.authentication.all_verified()
    }

    /// Returns true when any accepted decode symbol was not verified.
    #[must_use]
    pub fn has_unverified_symbols(&self) -> bool {
        self.authentication.has_unverified_symbols()
    }
}

/// Authentication posture counts for symbols accepted into a receive decode set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReceiveAuthenticationSummary {
    /// Symbols cryptographically verified by the receive path.
    pub verified: usize,
    /// Symbols carrying a non-zero tag that the receive path did not verify.
    pub unverified_tagged: usize,
    /// Symbols carrying the all-zero unauthenticated sentinel tag.
    pub unauthenticated_sentinel: usize,
}

impl ReceiveAuthenticationSummary {
    fn record(&mut self, state: AuthenticatedSymbolState) {
        match state {
            AuthenticatedSymbolState::Verified => {
                self.verified = self.verified.saturating_add(1);
            }
            AuthenticatedSymbolState::UnverifiedTagged => {
                self.unverified_tagged = self.unverified_tagged.saturating_add(1);
            }
            AuthenticatedSymbolState::UnauthenticatedSentinel => {
                self.unauthenticated_sentinel = self.unauthenticated_sentinel.saturating_add(1);
            }
        }
    }

    /// Total symbols represented by this summary.
    #[must_use]
    pub const fn total(self) -> usize {
        self.verified
            .saturating_add(self.unverified_tagged)
            .saturating_add(self.unauthenticated_sentinel)
    }

    /// Returns true when every represented symbol was verified.
    #[must_use]
    pub const fn all_verified(self) -> bool {
        self.total() == self.verified
    }

    /// Returns true when any accepted symbol carried the zero-tag sentinel.
    #[must_use]
    pub const fn has_unauthenticated_sentinel(self) -> bool {
        self.unauthenticated_sentinel > 0
    }

    /// Returns true when any accepted symbol carried a non-zero unverified tag.
    #[must_use]
    pub const fn has_unverified_tagged(self) -> bool {
        self.unverified_tagged > 0
    }

    /// Returns true when any represented symbol was not cryptographically verified.
    #[must_use]
    pub const fn has_unverified_symbols(self) -> bool {
        self.has_unverified_tagged() || self.has_unauthenticated_sentinel()
    }
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
            // Let `set_object_params` size the per-block accept cap to K (via
            // `configure_auto_buffer_limit`). The fixed default (8192) does NOT
            // scale with K, so for a valid large-K config (e.g. symbol_size 64,
            // 1 MiB blocks -> K=16384) it would reject legitimately-received
            // symbols past 8192 and starve the decoder. Mirrors what the live
            // QUIC/RQ transports already pass.
            max_buffered_symbols: 0,
            ..Default::default()
        };

        let mut decoder = DecodingPipeline::new(decoding_config);

        decoder.set_object_params(*params).map_err(Error::from)?;

        // br-asupersync-x7ad3b: honor the parsed SecurityConfig on the live
        // receive path. Resolve the effective authentication context: an
        // explicit builder-supplied context wins; otherwise derive one from the
        // configured `auth_key_seed` + `auth_mode` so those knobs actually
        // authenticate symbols instead of being phantom controls. When
        // `reject_unauthenticated` is set and a context IS active, every
        // consumed symbol must verify or we fail CLOSED before it can poison the
        // decode matrix. (When no auth material is available anywhere the
        // erasure-only / integrity-vs-manifest behavior is preserved unchanged —
        // hardening this no-key default is the larger e880xo transport change.)
        // br-asupersync-x7ad3b: a config-derived context is owned for the whole
        // call; the per-symbol verify below borrows `self.security` OR this
        // local only within each iteration (never across the `&mut self.source`
        // read) to keep the disjoint field borrows clean.
        let config_security = self.config.security.build_context();
        let has_auth_material = self.security.is_some() || config_security.is_some();
        let reject_unauthenticated = self.config.security.reject_unauthenticated
            && self
                .security
                .as_ref()
                .or(config_security.as_ref())
                .is_some_and(|ctx| ctx.mode() == AuthMode::Strict);

        let mut symbols_received = 0usize;
        let mut authenticated = has_auth_material;
        let mut authentication = ReceiveAuthenticationSummary::default();

        // Read symbols until decoding completes.
        while !decoder.is_complete() {
            cx.checkpoint()?;

            if let Some(mut auth_symbol) = poll_next_blocking(&mut self.source)? {
                // Skip symbols for other objects.
                if auth_symbol.symbol().object_id() != params.object_id {
                    // ubs:ignore - object_id is not a secret
                    continue;
                }

                // Explicit builder-supplied context wins; otherwise fall back to
                // the context derived from the configured `auth_key_seed` +
                // `auth_mode` so those knobs actually authenticate symbols
                // instead of being phantom controls.
                let symbol_verified =
                    if let Some(ctx) = self.security.as_ref().or(config_security.as_ref()) {
                        if let Err(err) = ctx.verify_authenticated_symbol(&mut auth_symbol) {
                            if let Some(ref mut m) = self.metrics {
                                m.counter("raptorq.auth_rejected").increment();
                            }
                            return Err(Error::new(ErrorKind::CorruptedSymbol)
                                .with_message(err.to_string()));
                        }
                        auth_symbol.is_verified()
                    } else {
                        false
                    };
                let symbol_authentication_state = auth_symbol.authentication_state();

                // br-asupersync-x7ad3b: reject_unauthenticated enforcement. With
                // auth material available (explicit or config-derived) the
                // operator has the means to authenticate, so an unverified
                // symbol is a hard failure rather than a silently-accepted one.
                // We fail CLOSED before feeding it into the decode matrix.
                if reject_unauthenticated && has_auth_material && !symbol_verified {
                    if let Some(ref mut m) = self.metrics {
                        m.counter("raptorq.auth_rejected").increment();
                    }
                    return Err(Error::new(ErrorKind::CorruptedSymbol).with_message(
                        "symbol rejected: reject_unauthenticated=true and symbol \
                         did not authenticate",
                    ));
                }

                match decoder.feed(auth_symbol).map_err(Error::from)? {
                    SymbolAcceptResult::Accepted { .. }
                    | SymbolAcceptResult::DecodingStarted { .. }
                    | SymbolAcceptResult::BlockComplete { .. } => {
                        authenticated &= symbol_verified;
                        authentication.record(symbol_authentication_state);
                        symbols_received += 1;
                        if let Some(ref mut m) = self.metrics {
                            m.counter("raptorq.symbols_received").increment();
                        }
                    }
                    SymbolAcceptResult::Rejected(RejectReason::AuthenticationFailed) => {
                        if let Some(ref mut m) = self.metrics {
                            m.counter("raptorq.auth_rejected").increment();
                        }
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
            authentication,
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

/// Compute repair-symbol count per RFC 6330 Systematic FEC-OTI semantics.
///
/// **RFC 6330 §5.6 + §4.4.1.2 contract:** RaptorQ encodes a source block of
/// `K` symbols by INTERNALLY padding to `K' = next_lookup_table_entry ≥ K`
/// (Table 2; the largest K' is 56_403). The decoder needs at LEAST `K'`
/// encoded symbols to attempt decoding, NOT just `K`. Per RFC 6330 §1.3,
/// providing `ε` symbols ABOVE K' yields decode failure probability:
///
///   * ε = 0  → ~0.85% failure probability
///   * ε = 1  → ~0.0085% failure probability
///   * ε = 2  → ~0.000085% failure probability
///
/// **Pre-fix bug (br-asupersync-7gxb8n):** the old formula
/// `ceil(K * overhead) - K` gave an overhead RELATIVE TO K, ignoring the
/// systematic K' padding. For typical K=10 with overhead=1.05 it returned 1
/// repair symbol — but K' for K=10 is 18, so the decoder needs (18 - 10) = 8
/// padding-equivalent symbols BEFORE any erasure budget. Result: silent
/// under-provisioning on marginal channels.
///
/// **Post-fix semantics:** the user-facing `overhead` parameter is now
/// applied on top of K' (not K), so the formula is:
///
///   repair_count = (K' - K)  +  ceil(K' * (overhead - 1.0))
///                 ^^^^^^^^^   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
///                 systematic   user-requested erasure margin (ε-equivalent)
///                 padding
///
/// The minimum-1 floor is preserved when `overhead > 1.0` so the request
/// guarantees at least one repair symbol beyond the systematic padding.
///
/// For K beyond the RFC table maximum (≥ 56_404), the function falls back
/// to the multiplicative-only formula since `SystematicParams` cannot
/// derive K' for such blocks; the surrounding encoder rejects them at
/// construction time anyway.
#[allow(clippy::cast_precision_loss)]
#[allow(clippy::cast_sign_loss)]
fn compute_repair_count_for_source_symbols(source_count: usize, overhead: f64) -> usize {
    if source_count == 0 || overhead <= 1.0 {
        return 0;
    }

    // Look up K' from the RFC 6330 Systematic Index Table (§5.6 Table 2).
    // For K > max table entry (56_403), there is no K' — fall back to the
    // pre-fix multiplicative formula. The encoder-construction layer
    // rejects such blocks separately.
    let k_prime = match SystematicParams::try_for_source_block(source_count, 1) {
        Ok(params) => params.k_prime,
        Err(_) => source_count,
    };

    // Systematic padding: zero-symbols added by the encoder so the source
    // block has K' symbols. The decoder treats these as "received for free"
    // ONLY when their ESIs are present — over a real erasure channel the
    // sender must transmit them as encoding symbols too.
    let padding_excess = k_prime.saturating_sub(source_count);

    // Erasure margin ε, computed multiplicatively over K' (NOT K) so the
    // user-visible `overhead` knob has consistent semantics regardless of
    // how much padding the systematic table introduces.
    let erasure_margin = ((k_prime as f64) * (overhead - 1.0)).ceil() as usize;

    // At least one repair symbol when overhead > 1.0 (preserves the
    // pre-fix contract that "any positive overhead requests at least one
    // repair beyond the bare K').
    padding_excess
        .saturating_add(erasure_margin)
        .max(padding_excess.saturating_add(1))
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
#[path = "pipeline_inline_tests.rs"]
mod tests;
