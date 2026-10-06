//! Pull-driven native bidirectional RPCs with an asynchronous request source.
//!
//! The existing native duplex owner remains the only HTTP/2 state machine.
//! This adapter couples its single upload slot to a `Streaming` producer while
//! exposing response messages instead of requiring an application event loop.
//! No reader task, producer task, connection pool or response queue is created.

use super::client::GrpcClient;
use super::codec::Codec;
use super::native_stream::{NativeDuplexEvent, NativeDuplexStream};
use super::status::{Code, Status};
use super::streaming::{Metadata, Request, Streaming};
use crate::cx::Cx;
use crate::io::{AsyncRead, AsyncWrite};
use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::{Pin, pin};
use std::task::{Context, Poll};

mod client_streaming;
pub use client_streaming::NativeClientStreamingCall;
mod request_channel;
pub use request_channel::{
    NativeRequestSendError, NativeRequestSender, NativeRequestStream, native_request_channel,
};

const PROGRESS_BUDGET: usize = 32;

/// A native bidirectional RPC driven by response demand.
///
/// Each response poll also progresses the request source and HTTP/2 writes.
/// The source is polled only when the native owner's one-message upload slot
/// is available. A source parked on its own wakeup never prevents incoming
/// responses, flow-control updates, cancellation or deadlines from progressing.
/// Request EOF half-closes HTTP/2 without closing the response direction.
///
/// Dropping a borrowing [`Self::message`] future preserves the producer, every
/// admitted request and all partial network cursors. Dropping this owner closes
/// the dedicated transport and destroys the source under the supplied `Cx`;
/// it does not spawn cleanup or certify remote handler quiescence. A producer
/// needing asynchronous cleanup must remain separately region-owned.
///
/// A server may terminate before consuming the whole request. Its terminal
/// status then ends the call and drops the unused source. Source failures are
/// returned once, as-is, and close the transport. In all cases later polls
/// return EOF and [`Self::status`] retains the classification. Successful EOF
/// requires the underlying owner's validated gRPC trailers, never socket EOF.
///
/// There is no response prefetch between consumer polls. Retention is the
/// existing native stream's bounded buffers plus one boxed source and the
/// source's own storage. Returned messages and arbitrary producer/codec
/// allocations have their own contracts. The source need not be `Unpin` or
/// `'static`; it remains pinned in its allocation for its complete lifetime.
pub struct NativeBidiStream<IO, C, S> {
    cx: Cx,
    call: Option<NativeDuplexStream<IO, C>>,
    source: Option<Pin<Box<S>>>,
    request_control: Option<std::sync::Arc<request_channel::RequestControl>>,
    requests_closed: bool,
    initial: Option<Metadata>,
    trailers: Option<Metadata>,
    status: Option<Status>,
    progress: usize,
}

// No structurally pinned field is exposed. Moving the owner does not move its
// boxed source; the native duplex owner is movable when its transport is Unpin.
impl<IO: Unpin, C, S> Unpin for NativeBidiStream<IO, C, S> {}

impl<IO, C, S> fmt::Debug for NativeBidiStream<IO, C, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeBidiStream")
            .field("requests_closed", &self.requests_closed)
            .field("finished", &self.status.is_some())
            .finish_non_exhaustive()
    }
}

impl<C: Codec> GrpcClient<C> {
    /// Connect a real bidirectional RPC to an asynchronous request source.
    ///
    /// Uses [`Self::into_native_duplex`] for channel metadata, interceptors,
    /// message limits, DNS, TCP, explicit TLS/ALPN and keepalive policy. Setup
    /// does not poll the source or wait for response headers. Returned response
    /// demand drives both directions; always consume responses while uploading.
    ///
    /// `request` carries a `Streaming<Message = C::Encode>` body. Producer polls
    /// run under `cx`, not the context of an unrelated task polling the result.
    /// Its EOF sends END_STREAM exactly once. Its error closes the call instead
    /// of being mistaken for a graceful half-close. No body replay or retry is
    /// performed. Construction of the supplied source happens at the call site.
    ///
    /// This is native HTTP/2, not the legacy loopback-only `bidi_streaming` API.
    /// A missing runtime capability, rejected interceptor or failed connection
    /// returns before the first source poll. The supplied context remains the
    /// authority and cancellation owner throughout the call.
    pub async fn into_native_bidi_streaming<S>(
        self,
        cx: &Cx,
        path: &str,
        request: Request<S>,
    ) -> Result<NativeBidiStream<impl AsyncRead + AsyncWrite + Unpin + Send + 'static, C, S>, Status>
    where
        S: Streaming<Message = C::Encode>,
    {
        cx.with_ambient(async move {
            let headers = request.snapshot(());
            let source = request.into_inner();
            let call = self.into_native_duplex(cx, path, headers).await?;
            Ok(NativeBidiStream::new(cx.clone(), call, source))
        })
        .await
    }
}

impl<IO, C, S> NativeBidiStream<IO, C, S>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: Codec,
    S: Streaming<Message = C::Encode>,
{
    fn new(cx: Cx, call: NativeDuplexStream<IO, C>, source: S) -> Self {
        Self {
            cx,
            call: Some(call),
            source: Some(Box::pin(source)),
            request_control: None,
            requests_closed: false,
            initial: None,
            trailers: None,
            status: None,
            progress: 0,
        }
    }

    /// Initial response metadata, kept separately from trailers.
    #[must_use]
    pub fn initial_metadata(&self) -> Option<&Metadata> {
        self.call.as_ref().and_then(NativeDuplexStream::initial_metadata)
            .or(self.initial.as_ref())
    }

    /// Trailing metadata after the peer has supplied it.
    #[must_use]
    pub fn trailers(&self) -> Option<&Metadata> {
        self.call.as_ref().and_then(NativeDuplexStream::trailers)
            .or(self.trailers.as_ref())
    }

    /// Final status, including a producer failure or explicit cancellation.
    #[must_use]
    pub fn status(&self) -> Option<&Status> {
        self.status.as_ref()
    }

    /// Retire this transport and producer without cancelling the parent `Cx`.
    /// Later reads return EOF; `status()` retains `Cancelled`.
    pub fn cancel(&mut self) {
        if self.status.is_none() {
            self.finish(Status::cancelled("native bidirectional call cancelled"));
        }
    }

    fn finish(&mut self, status: Status) -> Status {
        let _ambient = Cx::set_current(Some(self.cx.clone()));
        if let Some(call) = &self.call {
            self.initial = call.initial_metadata().cloned();
            self.trailers = call.trailers().cloned();
        }
        self.status = Some(status.clone());
        self.requests_closed = true;
        // Remove both owners before invoking user destructors. A caught panic
        // cannot leave this object claiming terminal EOF with a live transport.
        let control = self.request_control.take();
        let source = self.source.take();
        let call = self.call.take();
        drop(call);
        drop(source);
        drop(control);
        status
    }

    fn poll_message(&mut self, task: &mut Context<'_>) -> Poll<Option<Result<C::Decode, Status>>> {
        if self.status.is_some() {
            return Poll::Ready(None);
        }
        let _ambient = Cx::set_current(Some(self.cx.clone()));
        // A bounded channel's producer can fail while one encoded request is
        // blocked on zero peer credit. That failure is control traffic: never
        // wait for request_ready() before observing it or registering its wake.
        if let Some(status) = self.request_control.as_ref().and_then(|control| control.poll_failure(task)) {
            return Poll::Ready(Some(Err(self.finish(status))));
        }
        loop {
            // Bound ready producer work as well as network events. Counting
            // across polls also stops an always-ready response consumer from
            // defeating the cooperative yield by repeatedly awaiting Ready.
            if self.progress == PROGRESS_BUDGET {
                self.progress = 0;
                task.waker().wake_by_ref();
                return Poll::Pending;
            }
            self.progress += 1;
            let incoming = {
                let call = self.call.as_mut().expect("live native bidirectional call");
                // This borrowing future stores no protocol state. Dropping a
                // Pending wait retains the native owner's cursors and wakeups.
                let mut next = pin!(call.next_event());
                next.as_mut().poll(task)
            };
            let network_pending = match incoming {
                Poll::Ready(Err(status)) => return Poll::Ready(Some(Err(self.finish(status)))),
                Poll::Ready(Ok(None)) => {
                    let status = self.call.as_ref().and_then(NativeDuplexStream::status)
                        .cloned().unwrap_or_else(|| Status::internal("missing gRPC terminal status"));
                    let success = status.code() == Code::Ok;
                    let status = self.finish(status);
                    return Poll::Ready(if success { None } else { Some(Err(status)) });
                }
                Poll::Ready(Ok(Some(NativeDuplexEvent::Message(message)))) => {
                    return Poll::Ready(Some(Ok(message)));
                }
                Poll::Ready(Ok(Some(NativeDuplexEvent::RequestFlushed))) => false,
                Poll::Pending => true,
            };
            // Test the slot AFTER the network turn, which can change readiness
            // or observe a peer half-close. Never use a stale pre-poll snapshot.
            let call = self.call.as_mut().expect("live native bidirectional call");
            if !self.requests_closed && call.request_ready() {
                let produced = self.source.as_mut().expect("open request source")
                    .as_mut().poll_next(task);
                match produced {
                    // A RequestFlushed event can precede installation of a
                    // read wakeup. Poll the network again before parking on a
                    // producer alone, or an early response could remain unread.
                    Poll::Pending if network_pending => return Poll::Pending,
                    // The loop polls the network again.
                    Poll::Pending => {}
                    Poll::Ready(Some(Ok(message))) => {
                        if let Err(status) = call.queue_message(&message) {
                            return Poll::Ready(Some(Err(self.finish(status))));
                        }
                    }
                    Poll::Ready(Some(Err(status))) => {
                        return Poll::Ready(Some(Err(self.finish(status))));
                    }
                    Poll::Ready(None) => {
                        if let Err(status) = call.close_requests() {
                            return Poll::Ready(Some(Err(self.finish(status))));
                        }
                        self.requests_closed = true;
                        drop(self.source.take());
                    }
                }
            } else if network_pending {
                return Poll::Pending;
            }
        }
    }
}

impl<IO, C, S> NativeBidiStream<IO, C, S>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
    C: Codec,
    S: Streaming<Message = C::Encode>,
{
    /// Wait for one response while progressing the upload. Dropping this
    /// borrowing wait neither repeats a request nor loses partial network data.
    pub async fn message(&mut self) -> Result<Option<C::Decode>, Status> {
        poll_fn(|task| self.poll_message(task)).await.transpose()
    }
}

impl<IO, C, S> Streaming for NativeBidiStream<IO, C, S>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
    C: Codec,
    S: Streaming<Message = C::Encode>,
{
    type Message = C::Decode;

    fn poll_next(self: Pin<&mut Self>, task: &mut Context<'_>)
        -> Poll<Option<Result<Self::Message, Status>>>
    {
        self.get_mut().poll_message(task)
    }
}

impl<IO, C, S> Drop for NativeBidiStream<IO, C, S> {
    fn drop(&mut self) {
        let _ambient = Cx::set_current(Some(self.cx.clone()));
        let control = self.request_control.take();
        let source = self.source.take();
        let call = self.call.take();
        drop(call);
        drop(source);
        drop(control);
    }
}

#[cfg(test)]
mod tests;
