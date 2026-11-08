//! Authenticated, bounded symbol intake from independently owned paths.
//!
//! This adapter composes existing symbol streams, including TCP/TLS framed
//! streams, without introducing another wire protocol. It authenticates every
//! arrival before applying the existing cross-path deduplicator. Unique symbols
//! are delivered immediately: fountain decoding does not require ESI ordering.

use super::aggregator::{DeduplicatorConfig, DeduplicatorStats, PathId, SymbolDeduplicator};
use super::{StreamError, SymbolStream};
use crate::security::{AuthKey, AuthenticatedSymbol, SecurityContext};
use crate::types::{ObjectId, SymbolId, Time};
use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

const MAX_PATHS: usize = 64;
const POLLS_PER_TURN: usize = 64;

/// Immutable limits on path count, symbol payloads, and deduplication history.
///
/// History stores identities rather than payload copies and is allocated
/// lazily. Each path retains its own bounded transport buffers; those bounds
/// remain the caller's responsibility when supplying a custom stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultipathStreamLimits {
    max_paths: usize,
    max_symbol_bytes: usize,
    max_objects: usize,
    max_symbols_per_object: usize,
}

impl MultipathStreamLimits {
    /// Validate finite, nonzero limits. At most 64 paths are supported so every
    /// blocked source can be polled within one bounded executor turn.
    pub fn new(
        max_paths: usize,
        max_symbol_bytes: usize,
        max_objects: usize,
        max_symbols_per_object: usize,
    ) -> Result<Self, StreamError> {
        let history = max_objects
            .checked_mul(max_symbols_per_object)
            .and_then(|count| count.checked_mul(std::mem::size_of::<SymbolId>()));
        if max_paths == 0 || max_paths > MAX_PATHS || max_symbol_bytes == 0
            || max_symbol_bytes > isize::MAX as usize || max_objects == 0
            || max_symbols_per_object == 0 || history.is_none_or(|bytes| bytes > isize::MAX as usize)
        {
            return Err(StreamError::ProtocolError { details: "invalid multipath stream limits".into() });
        }
        Ok(Self { max_paths, max_symbol_bytes, max_objects, max_symbols_per_object })
    }

    /// Maximum number of paths, including retired paths whose errors remain inspectable.
    #[must_use]
    pub const fn max_paths(self) -> usize { self.max_paths }

    /// Maximum accepted symbol payload, checked before authentication or history insertion.
    #[must_use]
    pub const fn max_symbol_bytes(self) -> usize { self.max_symbol_bytes }

    /// Maximum objects retained in deduplication history.
    #[must_use]
    pub const fn max_objects(self) -> usize { self.max_objects }

    /// Maximum identities retained for any one object.
    #[must_use]
    pub const fn max_symbols_per_object(self) -> usize { self.max_symbols_per_object }
}

impl Default for MultipathStreamLimits {
    fn default() -> Self {
        Self::new(8, 64 * 1024, 16, 16_384).expect("default multipath bounds are representable")
    }
}

/// Receive-side counters for one configured path.
///
/// These count locally verified arrivals and deliveries to the consumer. They
/// do not claim remote acknowledgements or that an object has decoded.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MultipathStreamPathStats {
    /// Symbols that passed the explicit receiver key, including duplicates.
    pub authenticated_symbols: u64,
    /// Authenticated symbols delivered downstream after bounded deduplication.
    pub delivered_symbols: u64,
    /// Arrivals discarded because their identities remain in the deduplication history.
    pub duplicate_symbols: u64,
    /// The path ended normally between symbols.
    pub eof: bool,
    /// The path returned an error or violated the authentication/payload boundary.
    pub failed: bool,
}

struct InputPath {
    id: PathId,
    stream: Option<Pin<Box<dyn SymbolStream>>>,
    stats: MultipathStreamPathStats,
    error: Option<StreamError>,
}

/// Merge authenticated symbols while surviving individual transport failures.
///
/// Add paths before starting a receive. TCP/TLS frames, in-memory channels, and
/// other implementations can coexist without a common concrete stream type.
/// A pending source cannot hide another source's wake, and at most 64 provider
/// polls and symbol-verification steps occur in one call. Duplicate traffic
/// yields cooperatively; an entirely blocked set waits for its providers.
///
/// Every symbol is freshly verified against the explicit key BEFORE its
/// identity enters deduplication history, even if it claims to be verified.
/// EOF, reset, timeout, and ordinary I/O failure retire only that path. Other
/// live paths can still complete an object from their union. Authentication,
/// protocol, payload-limit, and cancellation errors terminate the whole merge;
/// an I/O `Interrupted` error is also terminal so cancellation cannot silently
/// become path failover. The original error stays available through
/// [`path_error`](Self::path_error). Once all paths retire, a retained path
/// error is surfaced if any failed; otherwise the stream ends normally.
///
/// Deduplication uses the existing bounded, pass-through-on-capacity policy:
/// symbols beyond the history limits remain deliverable, so a valid large
/// object is not starved. Counters of delivered symbols therefore are not a
/// proof of distinct decoding rank. The RaptorQ decoder still deduplicates its
/// own input. History lasts until [`clear_object`](Self::clear_object) or drop;
/// no ambient clock, timeout task, or background driver is created.
///
/// Dropping a borrowing receive preserves path ownership and each transport's
/// partial-frame state. Dropping this adapter releases its paths. A caught
/// provider panic permanently terminates the adapter because it may have
/// consumed input without reporting what was consumed.
pub struct MultipathSymbolStream {
    paths: Vec<InputPath>,
    limits: MultipathStreamLimits,
    security: SecurityContext,
    dedup: SymbolDeduplicator,
    next: usize,
    ended: bool,
}

impl MultipathSymbolStream {
    /// Create an inert receiver with explicit authentication material and limits.
    #[must_use]
    pub fn new(key: AuthKey, limits: MultipathStreamLimits) -> Self {
        Self {
            paths: Vec::new(),
            limits,
            security: SecurityContext::new(key),
            dedup: SymbolDeduplicator::new(DeduplicatorConfig {
                max_symbols_per_object: limits.max_symbols_per_object,
                max_objects: limits.max_objects,
                entry_ttl: Time::ZERO,
                track_path: true,
            }),
            next: 0,
            ended: false,
        }
    }

    /// Add an owned source. IDs must be unique and retired paths still count
    /// against the configured limit. A terminated stream cannot be reopened.
    pub fn add_path<S: SymbolStream + 'static>(
        &mut self, id: PathId, stream: S,
    ) -> Result<(), StreamError> {
        if self.ended { return Err(StreamError::Closed); }
        if self.paths.len() == self.limits.max_paths || self.paths.iter().any(|path| path.id == id) {
            return Err(StreamError::ProtocolError { details: "multipath path limit or duplicate identifier".into() });
        }
        self.paths.push(InputPath {
            id, stream: Some(Box::pin(stream)), stats: MultipathStreamPathStats::default(), error: None,
        });
        Ok(())
    }

    /// Immutable admission and history limits.
    #[must_use]
    pub const fn limits(&self) -> MultipathStreamLimits { self.limits }

    /// Original path error, retained even after another path completes the object.
    #[must_use]
    pub fn path_error(&self, id: PathId) -> Option<&StreamError> {
        self.paths.iter().find(|path| path.id == id)?.error.as_ref()
    }

    /// Snapshot verified-arrival and terminal-state counters for a path.
    #[must_use]
    pub fn path_stats(&self, id: PathId) -> Option<MultipathStreamPathStats> {
        self.paths.iter().find(|path| path.id == id).map(|path| path.stats)
    }

    /// Current bounded history occupancy and duplicate counters.
    #[must_use]
    pub fn dedup_stats(&self) -> DeduplicatorStats { self.dedup.stats() }

    /// Release an object's history after the consumer has finished routing it.
    /// Reusing its identity later can deliver symbols that were previously seen.
    pub fn clear_object(&mut self, object: ObjectId) { self.dedup.clear_object(object); }

    fn record_error(&mut self, index: usize, error: StreamError) {
        let path = &mut self.paths[index];
        path.stats.failed = true;
        path.error = Some(error);
        path.stream = None;
    }

    fn exhausted_result(&self) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
        match self.paths.iter().find_map(|path| path.error.as_ref()) {
            Some(error) => Poll::Ready(Some(Err(copy_error(error)))),
            None => Poll::Ready(None),
        }
    }

    fn poll_paths(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
        if self.paths.is_empty() { return Poll::Ready(None); }
        let mut pending = 0u64;
        for _ in 0..POLLS_PER_TURN {
            let next = (0..self.paths.len()).map(|offset| (self.next + offset) % self.paths.len())
                .find(|index| self.paths[*index].stream.is_some() && pending & (1u64 << *index) == 0);
            let Some(index) = next else {
                return if self.paths.iter().any(|path| path.stream.is_some()) {
                    Poll::Pending
                } else {
                    self.exhausted_result()
                };
            };
            self.next = (index + 1) % self.paths.len();
            let result = self.paths[index].stream.as_mut().expect("active path selected").as_mut().poll_next(cx);
            match result {
                Poll::Pending => pending |= 1u64 << index,
                Poll::Ready(None) => {
                    self.paths[index].stats.eof = true;
                    self.paths[index].stream = None;
                }
                Poll::Ready(Some(Err(error))) => {
                    let fatal = terminal_error(&error);
                    self.record_error(index, error);
                    if fatal {
                        return Poll::Ready(Some(Err(copy_error(self.paths[index].error.as_ref().expect("error retained")))));
                    }
                }
                Poll::Ready(Some(Ok(mut symbol))) => {
                    if symbol.symbol().data().len() > self.limits.max_symbol_bytes {
                        self.record_error(index, StreamError::ProtocolError { details: "multipath symbol exceeds payload limit".into() });
                        return Poll::Ready(Some(Err(copy_error(self.paths[index].error.as_ref().expect("error retained")))));
                    }
                    if self.security.verify_authenticated_symbol(&mut symbol).is_err() {
                        self.record_error(index, StreamError::AuthenticationFailed { reason: "multipath symbol did not authenticate".into() });
                        return Poll::Ready(Some(Err(copy_error(self.paths[index].error.as_ref().expect("error retained")))));
                    }
                    let path = &mut self.paths[index];
                    path.stats.authenticated_symbols = path.stats.authenticated_symbols.saturating_add(1);
                    if self.dedup.check_and_record(symbol.symbol(), path.id, Time::ZERO) {
                        path.stats.delivered_symbols = path.stats.delivered_symbols.saturating_add(1);
                        return Poll::Ready(Some(Ok(symbol)));
                    }
                    path.stats.duplicate_symbols = path.stats.duplicate_symbols.saturating_add(1);
                }
            }
        }
        if self.paths.iter().all(|path| path.stream.is_none()) {
            return self.exhausted_result();
        }
        // Wake only when the budget left an unpolled or ready source. An all-
        // Pending set has registered every live path's waker and must park.
        if self.paths.iter().enumerate().any(|(index, path)| path.stream.is_some() && pending & (1u64 << index) == 0) {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
}

impl SymbolStream for MultipathSymbolStream {
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
        let this = self.get_mut();
        if this.ended { return Poll::Ready(None); }
        // The flag remains terminal if a provider, destructor, or waker panics.
        this.ended = true;
        let result = this.poll_paths(cx);
        this.ended = matches!(&result, Poll::Ready(None | Some(Err(_))));
        result
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.ended { (0, Some(0)) } else { (0, None) }
    }

    fn is_exhausted(&self) -> bool { self.ended }
}

impl fmt::Debug for MultipathSymbolStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MultipathSymbolStream")
            .field("paths", &self.paths.len()).field("limits", &self.limits)
            .field("ended", &self.ended).finish_non_exhaustive()
    }
}

fn terminal_error(error: &StreamError) -> bool {
    match error {
        StreamError::Closed | StreamError::Reset | StreamError::Timeout => false,
        StreamError::Io { source } => matches!(source.kind(),
            io::ErrorKind::Interrupted | io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput),
        StreamError::Cancelled | StreamError::AuthenticationFailed { .. }
        | StreamError::ProtocolError { .. } | StreamError::PolledAfterCompletion => true,
    }
}

// Keep the original error available for path diagnostics. The yielded I/O error
// preserves its kind and message; raw OS detail remains on the original error.
fn copy_error(error: &StreamError) -> StreamError {
    match error {
        StreamError::Closed => StreamError::Closed,
        StreamError::PolledAfterCompletion => StreamError::PolledAfterCompletion,
        StreamError::Reset => StreamError::Reset,
        StreamError::Timeout => StreamError::Timeout,
        StreamError::AuthenticationFailed { reason } => StreamError::AuthenticationFailed { reason: reason.clone() },
        StreamError::ProtocolError { details } => StreamError::ProtocolError { details: details.clone() },
        StreamError::Io { source } => StreamError::Io { source: io::Error::new(source.kind(), source.to_string()) },
        StreamError::Cancelled => StreamError::Cancelled,
    }
}

#[cfg(test)]
#[path = "multipath_stream/tests.rs"]
mod tests;
