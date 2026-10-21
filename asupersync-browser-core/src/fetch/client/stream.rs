//! Buffered and streaming requests share one admission domain.
use super::{ClientState, Credit, FetchBytesClient};
use crate::fetch::{FetchBytesError, FetchStream, FetchStreamLimits, fetch_stream};
use asupersync::types::{WasmAbiVersion, WasmFetchRequest};
use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, ready};

impl FetchBytesClient {
    /// Open a streaming response using this client's shared admission capacity.
    ///
    /// Admission is lazy and a full client refuses before host dispatch, just
    /// like [`Self::fetch`]. Its slot transfers to the returned [`ClientBody`]
    /// and remains charged until actual EOF, error or body drop. Header arrival
    /// cannot bypass the concurrency bound by leaving uncounted bodies alive.
    /// The configured response limit counts total bytes across chunks; the
    /// additional `max_chunk_bytes` bounds each copied Rust chunk.
    pub fn stream(
        &self,
        request: WasmFetchRequest,
        max_chunk_bytes: usize,
        consumer_version: Option<WasmAbiVersion>,
    ) -> ClientStream {
        ClientStream {
            state: Rc::clone(&self.state), request: Some(request),
            max_chunk_bytes, consumer_version, active: None, finished: false,
        }
    }
}

struct Opening {
    // Rust field drop order keeps the credit charged through future cleanup,
    // including when the pinned future's destructor unwinds.
    future: Pin<Box<dyn Future<Output = Result<FetchStream, FetchBytesError>>>>,
    credit: Option<Credit>,
}

/// Lazy future returned by [`FetchBytesClient::stream`].
#[must_use = "streaming requests do nothing unless polled or awaited"]
pub struct ClientStream {
    state: Rc<ClientState>,
    request: Option<WasmFetchRequest>,
    max_chunk_bytes: usize,
    consumer_version: Option<WasmAbiVersion>,
    active: Option<Opening>,
    finished: bool,
}

impl fmt::Debug for ClientStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientStream")
            .field("admitted", &self.active.is_some())
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl Future for ClientStream {
    type Output = Result<ClientBody, FetchBytesError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        assert!(!this.finished, "client stream opening polled after completion");
        if this.active.is_none() {
            let credit = match Credit::acquire(&this.state) {
                Ok(credit) => credit,
                Err(error) => {
                    this.finished = true;
                    this.request = None;
                    return Poll::Ready(Err(error));
                }
            };
            let request = this.request.take().expect("unpolled stream owns its request");
            this.active = Some(Opening {
                future: Box::pin(fetch_stream(request,
                    FetchStreamLimits::new(this.state.limits, this.max_chunk_bytes), this.consumer_version)),
                credit: Some(credit),
            });
        }
        let result = ready!(this.active.as_mut().expect("admission owns opening").future.as_mut().poll(cx));
        this.finished = true;
        let mut opening = this.active.take().expect("terminal opening remains owned");
        match result {
            Ok(body) => {
                // The new body owns the credit before the completed opening is
                // destroyed. There is no gap allowing reentrant over-admission.
                let response = ClientBody {
                    status: body.status(), received: body.received_bytes(), terminal: None,
                    active: Some(AdmittedBody {
                        body, _credit: opening.credit.take().expect("one opening credit"),
                    }),
                };
                drop(opening);
                Poll::Ready(Ok(response))
            }
            Err(error) => {
                drop(opening);
                Poll::Ready(Err(error))
            }
        }
    }
}

struct AdmittedBody {
    // Keep capacity charged through reader release and synchronous abort
    // listeners. Drop glue releases the credit on both normal return/unwind.
    body: FetchStream,
    _credit: Credit,
}

/// A response body carrying its client's in-flight capacity until retirement.
/// There is intentionally no method that detaches the body from its credit.
#[must_use = "consume to EOF or drop to abort and release admission capacity"]
pub struct ClientBody {
    active: Option<AdmittedBody>,
    status: u16,
    received: usize,
    terminal: Option<Result<(), FetchBytesError>>,
}

impl fmt::Debug for ClientBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientBody")
            .field("status", &self.status)
            .field("received_bytes", &self.received)
            .field("terminal", &self.terminal)
            .finish_non_exhaustive()
    }
}

impl ClientBody {
    /// HTTP status, not proof that the body transfer has completed.
    #[must_use]
    pub const fn status(&self) -> u16 { self.status }

    /// Bytes delivered before EOF/error, excluding a refused chunk.
    #[must_use]
    pub const fn received_bytes(&self) -> usize { self.received }

    /// Poll one chunk, returning capacity only at actual EOF or error.
    /// Terminal results are sticky, including while the completed body is kept.
    pub fn poll_chunk(self: Pin<&mut Self>, cx: &mut Context<'_>)
        -> Poll<Result<Option<Vec<u8>>, FetchBytesError>>
    {
        let this = self.get_mut();
        if let Some(result) = this.terminal { return Poll::Ready(result.map(|()| None)); }
        let active = this.active.as_mut().expect("nonterminal body owns admission");
        let result = ready!(Pin::new(&mut active.body).poll_chunk(cx));
        this.received = active.body.received_bytes();
        match &result {
            Ok(Some(_)) => {}
            terminal => {
                this.terminal = Some(terminal.as_ref().map(|_| ()).map_err(|error| *error));
                drop(this.active.take());
            }
        }
        Poll::Ready(result)
    }

    /// Await one chunk. Abandoning this wait retains both the pending host read
    /// and client credit in the body; dropping the body cancels the operation.
    pub async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, FetchBytesError> {
        poll_fn(|cx| Pin::new(&mut *self).poll_chunk(cx)).await
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;

#[cfg(all(test, target_arch = "wasm32"))]
mod browser_tests;
