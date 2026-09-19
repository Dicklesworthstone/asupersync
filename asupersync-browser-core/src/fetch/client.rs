//! Explicit shared admission for bounded fetches; no global default changes.
use super::{FetchBytesError, FetchBytesLimits, FetchBytesResponse, fetch_bytes};
use asupersync::types::{WasmAbiVersion, WasmFetchRequest};
use std::cell::Cell;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;

struct ClientState {
    limits: FetchBytesLimits,
    maximum: usize,
    in_flight: Cell<usize>,
}

/// Cloneable, realm-local fetch client with explicit shared admission capacity.
///
/// All clones share the same in-flight count. Saturation refuses immediately;
/// this client does not hide an unbounded wait queue or spawn background tasks.
/// Each admitted call uses [`fetch_bytes`]'s scope/ABI/authority checks, streamed
/// body bounds, and host abort-on-drop. Creating a client grants no authority.
///
/// Credits remain held through inner-future destruction, including abort
/// listeners. A reentrant listener cannot bypass capacity by starting a
/// replacement before the old operation finishes retiring. The credit returns
/// before terminal completion, even if a caller retains the completed wrapper.
/// Unpolled requests and bodies already delivered to callers are caller-owned
/// storage, outside this client's in-flight bound.
#[derive(Clone)]
pub struct FetchBytesClient {
    state: Rc<ClientState>,
}

impl fmt::Debug for FetchBytesClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FetchBytesClient")
            .field("limits", &self.state.limits)
            .field("maximum", &self.state.maximum)
            .field("in_flight", &self.in_flight())
            .finish()
    }
}

impl FetchBytesClient {
    /// Create one shared admission domain. Zero capacity is a deliberate deny.
    #[must_use]
    pub fn new(limits: FetchBytesLimits, max_in_flight: usize) -> Self {
        Self { state: Rc::new(ClientState { limits, maximum: max_in_flight, in_flight: Cell::new(0) }) }
    }

    /// Currently admitted calls, including operations still being destroyed.
    #[must_use]
    pub fn in_flight(&self) -> usize { self.state.in_flight.get() }

    /// Configured maximum admitted calls across every clone of this client.
    #[must_use]
    pub fn capacity(&self) -> usize { self.state.maximum }

    /// Maximum logical response bytes across admitted calls, or `None` when
    /// that product is not representable. This excludes host/allocator buffers,
    /// caller request storage and bodies handed to callers after completion.
    #[must_use]
    pub fn max_in_flight_response_bytes(&self) -> Option<usize> {
        self.state.maximum.checked_mul(self.state.limits.max_response_bytes)
    }

    /// Create a lazy fetch. Admission occurs on first poll, not construction.
    ///
    /// A full client returns [`FetchBytesError::InFlightLimit`] before allocating
    /// a canonical fetch handle or starting host I/O. Retry policy is explicit
    /// at the caller; polling a completed refusal again is not a retry.
    pub fn fetch(&self, request: WasmFetchRequest, consumer_version: Option<WasmAbiVersion>) -> ClientFetch {
        ClientFetch {
            state: Rc::clone(&self.state), request: Some(request), consumer_version,
            active: None, finished: false,
        }
    }
}

struct Credit(Rc<ClientState>);
impl Credit {
    fn acquire(state: &Rc<ClientState>) -> Result<Self, FetchBytesError> {
        let current = state.in_flight.get();
        if current >= state.maximum {
            return Err(FetchBytesError::InFlightLimit { limit: state.maximum });
        }
        // current < maximum <= usize::MAX, so increment cannot overflow.
        state.in_flight.set(current + 1);
        Ok(Self(Rc::clone(state)))
    }
}
impl Drop for Credit {
    fn drop(&mut self) {
        let next = self.0.in_flight.get().checked_sub(1)
            .expect("an admitted fetch owns exactly one client credit");
        self.0.in_flight.set(next);
    }
}

struct ActiveFetch {
    // Field order is intentional: all inner cleanup (including host callbacks)
    // precedes credit release. Drop glue releases the credit even on unwind.
    future: Pin<Box<dyn Future<Output = Result<FetchBytesResponse, FetchBytesError>>>>,
    _credit: Credit,
}

/// Future returned by [`FetchBytesClient::fetch`]. Owns admission until its real
/// inner operation is retired. It cannot move to another thread/JS realm.
#[must_use = "client fetches do nothing unless polled or awaited"]
pub struct ClientFetch {
    state: Rc<ClientState>,
    request: Option<WasmFetchRequest>,
    consumer_version: Option<WasmAbiVersion>,
    active: Option<ActiveFetch>,
    finished: bool,
}

impl fmt::Debug for ClientFetch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientFetch")
            .field("admitted", &self.active.is_some())
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl Future for ClientFetch {
    type Output = Result<FetchBytesResponse, FetchBytesError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        assert!(!this.finished, "client fetch polled after completion");
        if this.active.is_none() {
            let credit = match Credit::acquire(&this.state) {
                Ok(credit) => credit,
                Err(error) => {
                    this.finished = true;
                    this.request = None;
                    return Poll::Ready(Err(error));
                }
            };
            let request = this.request.take().expect("unpolled fetch owns its request");
            this.active = Some(ActiveFetch {
                future: Box::pin(fetch_bytes(request, this.state.limits, this.consumer_version)),
                _credit: credit,
            });
        }
        let result = this.active.as_mut().expect("admission owns an active future").future.as_mut().poll(cx);
        if result.is_ready() {
            // Commit terminal state before destruction can reenter or panic.
            this.finished = true;
            drop(this.active.take());
        }
        result
    }
}
