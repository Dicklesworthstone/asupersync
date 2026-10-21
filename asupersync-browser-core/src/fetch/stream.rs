//! Pull-based response bodies: one owned host read, no background prefetch.
//!
//! The caller can process or discard each chunk without retaining the complete
//! response. Bytes already handed to the caller cannot be retracted on a later
//! error. Only `Ok(None)` establishes successful EOF; headers and a byte prefix
//! do not establish a complete transfer. Host buffering and chunks retained by
//! the caller are outside these Rust-side limits.

use super::{FetchBytesError, FetchBytesLimits};
use asupersync::types::{WasmAbiVersion, WasmFetchRequest};
use std::fmt;
use std::future::poll_fn;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Total transfer and individual chunk bounds for a streaming response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FetchStreamLimits {
    /// Request bytes, total response bytes, and total read calls (including EOF).
    /// Here `max_response_bytes` counts all chunks, not just the current buffer.
    pub transfer: FetchBytesLimits,
    /// Maximum single host chunk copied into a Rust allocation. A larger chunk
    /// fails before allocation, even when the total transfer budget permits it.
    pub max_chunk_bytes: usize,
}

impl FetchStreamLimits {
    /// Construct explicit total-transfer and per-chunk limits. Zero is valid.
    #[must_use]
    pub const fn new(transfer: FetchBytesLimits, max_chunk_bytes: usize) -> Self {
        Self { transfer, max_chunk_bytes }
    }
}

/// An exclusively owned response body under an existing browser scope.
///
/// Dropping the body aborts unfinished network work and releases its reader and
/// handle. Dropping just a [`Self::next_chunk`] future does neither: its pending
/// host read remains in this owner, so the next call receives the same chunk.
/// There is at most one outstanding `reader.read()` and no adapter prefetch.
/// The browser itself can still buffer ahead.
///
/// Once EOF or an error is returned, subsequent polls repeat that terminal
/// result without host I/O. This body is local to its JavaScript realm.
#[must_use = "consume the response to EOF or drop it to abort the request"]
pub struct FetchStream {
    pub(super) status: u16,
    #[cfg(target_arch = "wasm32")]
    pub(super) body: super::browser::stream::HostBody,
    // Keep the public type realm-local even in a native build.
    pub(super) _local: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl fmt::Debug for FetchStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FetchStream")
            .field("status", &self.status)
            .field("received_bytes", &self.received_bytes())
            .finish_non_exhaustive()
    }
}

impl FetchStream {
    /// HTTP status, including ordinary 4xx/5xx responses; not body completion.
    #[must_use]
    pub const fn status(&self) -> u16 { self.status }

    /// Bytes successfully handed to the caller, excluding a refused chunk.
    #[must_use]
    pub fn received_bytes(&self) -> usize {
        #[cfg(target_arch = "wasm32")]
        { self.body.received_bytes() }
        #[cfg(not(target_arch = "wasm32"))]
        { 0 }
    }

    /// Poll one chunk. Empty chunks are `Some(Vec::new())`, never invented EOF.
    /// No new host read is started while the previous read is pending.
    pub fn poll_chunk(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Vec<u8>>, FetchBytesError>> {
        #[cfg(target_arch = "wasm32")]
        { self.get_mut().body.poll_chunk(cx) }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (self, cx);
            Poll::Ready(Err(FetchBytesError::UnsupportedHost))
        }
    }

    /// Wait for one chunk without losing an in-flight read when this wait is
    /// dropped. To cancel the transfer itself, drop the body or close its owner.
    pub async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, FetchBytesError> {
        poll_fn(|cx| Pin::new(&mut *self).poll_chunk(cx)).await
    }
}

/// Start a capability-checked fetch and return its owned streaming body.
///
/// Scope, ABI, URL, method, credential and request-byte checks are the same as
/// [`super::fetch_bytes`]. Redirects are refused before following them. The
/// returned body keeps the canonical handle and AbortController alive until
/// EOF, error or drop. No body read is issued merely to return the headers.
///
/// On native targets no handle or network work is admitted; the result is
/// [`FetchBytesError::UnsupportedHost`]. This API does not impose a time limit.
pub async fn fetch_stream(
    request: WasmFetchRequest,
    limits: FetchStreamLimits,
    consumer_version: Option<WasmAbiVersion>,
) -> Result<FetchStream, FetchBytesError> {
    #[cfg(target_arch = "wasm32")]
    { super::browser::stream::open(request, limits, consumer_version).await }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (request, limits, consumer_version);
        Err(FetchBytesError::UnsupportedHost)
    }
}

// Reuse the same checked total-byte/read-work arithmetic as buffered fetches.
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) struct StreamBudget {
    body: super::state::BodyBudget,
    max_chunk_bytes: usize,
    received: usize,
}

#[cfg(any(target_arch = "wasm32", test))]
impl StreamBudget {
    pub(crate) const fn new(limits: FetchStreamLimits) -> Self {
        Self {
            body: super::state::BodyBudget::new(limits.transfer),
            max_chunk_bytes: limits.max_chunk_bytes,
            received: 0,
        }
    }

    pub(crate) fn begin_read(&mut self) -> Result<(), FetchBytesError> {
        self.body.begin_read()
    }

    pub(crate) fn copy_buffer(&self, length: usize) -> Result<Vec<u8>, FetchBytesError> {
        // Validate both limits before attempting allocation or copying JS bytes.
        let _ = self.body.checked_end(self.received, length)?;
        if length > self.max_chunk_bytes {
            return Err(FetchBytesError::ChunkLimit { limit: self.max_chunk_bytes });
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length).map_err(|_| FetchBytesError::Allocation)?;
        bytes.resize(length, 0);
        Ok(bytes)
    }

    pub(crate) fn commit(&mut self, length: usize) -> Result<(), FetchBytesError> {
        self.received = self.body.checked_end(self.received, length)?;
        Ok(())
    }

    pub(crate) const fn received(&self) -> usize { self.received }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;
