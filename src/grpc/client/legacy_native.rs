//! Network transport for the legacy `GrpcClient` streaming entry points.
//!
//! [`GrpcClient::server_streaming`](super::GrpcClient::server_streaming),
//! [`client_streaming`](super::GrpcClient::client_streaming) and
//! [`bidi_streaming`](super::GrpcClient::bidi_streaming) hand back separate
//! handles: a [`RequestSink`](super::RequestSink), a
//! [`ResponseFuture`](super::ResponseFuture) or a
//! [`ResponseStream`](super::ResponseStream). On a network channel those
//! handles share one owned native HTTP/2 call ([`NativeServerStream`] or
//! [`NativeDuplexStream`]), the same owners that back
//! `GrpcClient::into_native_server_streaming` and
//! `GrpcClient::into_native_duplex`.
//!
//! There is no background task. Whichever handle is polled drives the call in
//! both directions, so a sink waiting for upload credit also reads responses,
//! and a response wait also flushes queued request bytes. The call is polled
//! with one fan-out waker that wakes every handle parked on it: a sink and a
//! response stream, or clones of one response stream, may live in different
//! tasks without losing a wakeup.
//! Responses read while uploading are buffered up to `MAX_STREAM_BUFFERED`;
//! a sink then waits for the response side to drain them.
//!
//! Dropping an open sink, an unfinished response future, or the last clone of
//! a response stream cancels the call. Dropping every handle closes its
//! dedicated connection. Cancellation and deadlines come from the `Cx` that was
//! current when the call was started.

use std::any::Any;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};

use crate::io::{AsyncRead, AsyncWrite};

use super::super::codec::Codec;
use super::super::native_stream::{NativeDuplexEvent, NativeDuplexStream, NativeServerStream};
use super::super::status::{Code, Status};
use super::super::streaming::{MAX_STREAM_BUFFERED, Metadata, MetadataValue, Streaming};
use super::{downcast_boxed_message, lock_unpoisoned};

/// One step of progress on a native call, with the message type erased.
pub(super) enum LegacyEvent {
    /// The previous request message (or the request headers) left the local
    /// write queues; the next message may be queued.
    RequestFlushed,
    /// One decoded response message (`C::Decode`).
    Message(Box<dyn Any + Send>),
}

/// The native call operations the legacy handles need, type-erased over the
/// transport and codec.
pub(super) trait LegacyCall: Send {
    fn poll_event(&mut self, task: &mut Context<'_>) -> Poll<Option<Result<LegacyEvent, Status>>>;
    fn queue_message(&mut self, message: Box<dyn Any + Send>) -> Result<(), Status>;
    fn close_requests(&mut self) -> Result<(), Status>;
    fn initial_metadata(&self) -> Option<Metadata>;
    fn trailers(&self) -> Option<Metadata>;
    /// The call's recorded final status, once it ended for any reason.
    fn status(&self) -> Option<Status>;
    fn cancel(&mut self);
}

impl<IO, C> LegacyCall for NativeDuplexStream<IO, C>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
    C: Codec,
{
    fn poll_event(&mut self, task: &mut Context<'_>) -> Poll<Option<Result<LegacyEvent, Status>>> {
        NativeDuplexStream::poll_event(self, task).map(|event| {
            event.map(|event| {
                event.map(|event| match event {
                    NativeDuplexEvent::RequestFlushed => LegacyEvent::RequestFlushed,
                    NativeDuplexEvent::Message(message) => LegacyEvent::Message(Box::new(message)),
                })
            })
        })
    }

    fn queue_message(&mut self, message: Box<dyn Any + Send>) -> Result<(), Status> {
        let message = downcast_native_request::<C::Encode>(message)?;
        NativeDuplexStream::queue_message(self, &message)
    }

    fn close_requests(&mut self) -> Result<(), Status> {
        NativeDuplexStream::close_requests(self)
    }

    fn initial_metadata(&self) -> Option<Metadata> {
        NativeDuplexStream::initial_metadata(self).cloned()
    }

    fn trailers(&self) -> Option<Metadata> {
        NativeDuplexStream::trailers(self).cloned()
    }

    fn status(&self) -> Option<Status> {
        NativeDuplexStream::status(self).cloned()
    }

    fn cancel(&mut self) {
        NativeDuplexStream::cancel(self);
    }
}

impl<IO, C> LegacyCall for NativeServerStream<IO, C>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
    C: Codec,
{
    fn poll_event(&mut self, task: &mut Context<'_>) -> Poll<Option<Result<LegacyEvent, Status>>> {
        Streaming::poll_next(std::pin::Pin::new(self), task).map(|event| {
            event.map(|event| event.map(|message| LegacyEvent::Message(Box::new(message))))
        })
    }

    fn queue_message(&mut self, _message: Box<dyn Any + Send>) -> Result<(), Status> {
        Err(Status::failed_precondition(
            "a server-streaming call carries exactly one request message",
        ))
    }

    fn close_requests(&mut self) -> Result<(), Status> {
        Ok(())
    }

    fn initial_metadata(&self) -> Option<Metadata> {
        NativeServerStream::initial_metadata(self).cloned()
    }

    fn trailers(&self) -> Option<Metadata> {
        NativeServerStream::trailers(self).cloned()
    }

    fn status(&self) -> Option<Status> {
        NativeServerStream::status(self).cloned()
    }

    fn cancel(&mut self) {
        NativeServerStream::cancel(self);
    }
}

/// Downcast a legacy request message to the client codec's `Encode` type.
pub(super) fn downcast_native_request<T: Send + 'static>(
    message: Box<dyn Any + Send>,
) -> Result<T, Status> {
    message
        .downcast::<T>()
        .map(|message| *message)
        .map_err(|_| {
            Status::invalid_argument(
                "request message type does not match the client codec's Encode type",
            )
        })
}

/// Downcast a decoded native response to the caller's response type.
pub(super) fn downcast_native_response<T: Send + 'static>(
    message: Box<dyn Any + Send>,
) -> Result<T, Status> {
    downcast_boxed_message::<T>(message, "native gRPC response decoding").map_err(|_| {
        Status::internal("response type does not match the client codec's Decode type")
    })
}

/// Which handle is polling the call. A response handle carries its
/// responder id ([`LegacyNativeCall::new_responder`]): clones of one response
/// stream are separate handles and may be parked in different tasks.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Sink,
    Response(u64),
}

/// Wakes every handle parked on the call. The call keeps one clone of this
/// waker registered with its transport, cancel signal and timers.
#[derive(Default)]
struct Fanout {
    wakers: Mutex<FanoutWakers>,
}

#[derive(Default)]
struct FanoutWakers {
    sink: Option<Waker>,
    /// One waker per parked response handle, by responder id. A handle that
    /// polls again replaces only its own entry, so a clone parked in another
    /// task keeps its wakeup. Every entry is taken when the response side is
    /// woken.
    responses: Vec<(u64, Waker)>,
}

impl Fanout {
    fn register(&self, role: Role, waker: &Waker) {
        let mut wakers = lock_unpoisoned(&self.wakers);
        let slot = match role {
            Role::Sink => &mut wakers.sink,
            Role::Response(responder) => {
                let responses = &mut wakers.responses;
                match responses.iter_mut().find(|(id, _)| *id == responder) {
                    // `Waker::clone_from` keeps an entry that already wakes
                    // the same task.
                    Some((_, current)) => current.clone_from(waker),
                    None => responses.push((responder, waker.clone())),
                }
                return;
            }
        };
        if !slot
            .as_ref()
            .is_some_and(|current| current.will_wake(waker))
        {
            *slot = Some(waker.clone());
        }
    }

    fn wake_sink(&self) {
        let waker = lock_unpoisoned(&self.wakers).sink.take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// Wake every parked response handle.
    fn wake_responses(&self) {
        let responses = std::mem::take(&mut lock_unpoisoned(&self.wakers).responses);
        for (_, waker) in responses {
            waker.wake();
        }
    }
}

impl Wake for Fanout {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        let FanoutWakers { sink, responses } = std::mem::take(&mut *lock_unpoisoned(&self.wakers));
        let responses = responses.into_iter().map(|(_, waker)| waker);
        for waker in sink.into_iter().chain(responses) {
            waker.wake();
        }
    }
}

/// The RPC shape decides how many responses are admitted.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum LegacyShape {
    ServerStreaming,
    ClientStreaming,
    Bidi,
}

struct CallState {
    call: Box<dyn LegacyCall>,
    shape: LegacyShape,
    request_ready: bool,
    request_closed: bool,
    responses: VecDeque<Box<dyn Any + Send>>,
    /// Terminal status once the call ended; `Code::Ok` for success.
    finished: Option<Status>,
}

impl CallState {
    fn finish(&mut self, status: Status) {
        if self.finished.is_none() {
            self.finished = Some(status);
        }
    }

    fn fail(&mut self, status: Status) {
        if self.finished.is_none() {
            self.call.cancel();
            self.finished = Some(status);
        }
    }
}

/// One native call shared by a legacy call's handles.
pub(super) struct LegacyNativeCall {
    state: Mutex<CallState>,
    fanout: Arc<Fanout>,
    /// The last responder id handed out; the handle created with the call
    /// is responder 0. Atomic, so cloning a handle takes no lock.
    last_responder: AtomicU64,
}

impl LegacyNativeCall {
    pub(super) fn new(call: Box<dyn LegacyCall>, shape: LegacyShape) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(CallState {
                call,
                shape,
                // A server-streaming owner already wrote its only request.
                request_ready: false,
                request_closed: shape == LegacyShape::ServerStreaming,
                responses: VecDeque::new(),
                finished: None,
            }),
            fanout: Arc::new(Fanout::default()),
            last_responder: AtomicU64::new(0),
        })
    }

    /// A fresh responder id for another response handle on this call, such
    /// as a clone of its response stream.
    pub(super) fn new_responder(&self) -> u64 {
        self.last_responder.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Forgets the waker a dropped response handle left parked, so handles
    /// cloned and dropped while the call is quiet do not pile up until the
    /// next wake.
    pub(super) fn forget_responder(&self, responder: u64) {
        lock_unpoisoned(&self.fanout.wakers)
            .responses
            .retain(|(id, _)| *id != responder);
    }

    /// Response handles with a waker parked on the call.
    #[cfg(test)]
    pub(super) fn parked_responders(&self) -> usize {
        lock_unpoisoned(&self.fanout.wakers).responses.len()
    }

    /// Progress the call for `role` until `done` holds, the call ends, or the
    /// transport parks. `Ready` means `done` or the call ended.
    fn drive(
        &self,
        state: &mut CallState,
        task: &mut Context<'_>,
        role: Role,
        done: impl Fn(&CallState) -> bool,
    ) -> Poll<()> {
        self.fanout.register(role, task.waker());
        let waker = Waker::from(Arc::clone(&self.fanout));
        let mut call_task = Context::from_waker(&waker);
        loop {
            if state.finished.is_some() || done(state) {
                return Poll::Ready(());
            }
            // An unconsumed response window holds the sink until the
            // response side drains it (it wakes the sink when it pops).
            if role == Role::Sink && state.responses.len() >= MAX_STREAM_BUFFERED {
                return Poll::Pending;
            }
            match state.call.poll_event(&mut call_task) {
                Poll::Ready(Some(Ok(LegacyEvent::RequestFlushed))) => {
                    state.request_ready = !state.request_closed;
                    if role != Role::Sink {
                        self.fanout.wake_sink();
                    }
                }
                Poll::Ready(Some(Ok(LegacyEvent::Message(message)))) => {
                    if state.shape == LegacyShape::ClientStreaming && !state.responses.is_empty() {
                        state.fail(Status::internal(
                            "gRPC client-streaming response contained more than one message",
                        ));
                    } else {
                        state.responses.push_back(message);
                    }
                    if role == Role::Sink {
                        self.fanout.wake_responses();
                    }
                }
                Poll::Ready(None) => {
                    // The owner also reports `None` once it already ended,
                    // for example after refusing a queued message on
                    // cancellation; its recorded status is the outcome.
                    let status = state.call.status().unwrap_or_else(Status::ok);
                    state.finish(status);
                    self.wake_other(role);
                }
                Poll::Ready(Some(Err(status))) => {
                    state.finish(status);
                    self.wake_other(role);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    /// The call ended: wake the handles on the other side, and the other
    /// response handles when a response handle saw the end.
    fn wake_other(&self, role: Role) {
        if role != Role::Sink {
            self.fanout.wake_sink();
        }
        self.fanout.wake_responses();
    }

    /// Queue one request message once the request slot is free.
    pub(super) fn poll_send(
        &self,
        task: &mut Context<'_>,
        message: &mut Option<Box<dyn Any + Send>>,
    ) -> Poll<Result<(), Status>> {
        let mut state = lock_unpoisoned(&self.state);
        if self
            .drive(&mut state, task, Role::Sink, |state| state.request_ready)
            .is_pending()
        {
            return Poll::Pending;
        }
        if let Some(status) = &state.finished {
            return Poll::Ready(Err(ended_call_status(status)));
        }
        let message = message
            .take()
            .ok_or_else(|| Status::internal("request message was already queued"))?;
        let result = state.call.queue_message(message);
        self.settle_request(&mut state, &result);
        Poll::Ready(result)
    }

    /// After queuing a message or the half-close: a success uses the request
    /// slot until the next `RequestFlushed`; a refusal that ended the call
    /// (cancellation, deadline) ends it here too, while one that did not (a
    /// message over the size limit) leaves the slot free for the next send.
    fn settle_request(&self, state: &mut CallState, result: &Result<(), Status>) {
        match result {
            Ok(()) => state.request_ready = false,
            Err(_) => {
                if let Some(status) = state.call.status() {
                    state.finish(status);
                    self.fanout.wake_responses();
                }
            }
        }
    }

    /// Half-close the request side once the request slot is free.
    pub(super) fn poll_close(&self, task: &mut Context<'_>) -> Poll<Result<(), Status>> {
        let mut state = lock_unpoisoned(&self.state);
        if state.request_closed {
            return Poll::Ready(Ok(()));
        }
        if self
            .drive(&mut state, task, Role::Sink, |state| state.request_ready)
            .is_pending()
        {
            return Poll::Pending;
        }
        if let Some(status) = &state.finished {
            // The server ended the call first; its error is the answer.
            return Poll::Ready(if status.code() == Code::Ok {
                Ok(())
            } else {
                Err(status.clone())
            });
        }
        let result = state.call.close_requests();
        self.settle_request(&mut state, &result);
        if result.is_ok() {
            state.request_closed = true;
        }
        // The response side may be waiting for the half-close to be flushed.
        self.fanout.wake_responses();
        Poll::Ready(result)
    }

    /// Next response message, `Ok(None)`-style end as `None`, or the terminal
    /// error once (then `None`), for the response handle `responder`.
    pub(super) fn poll_message(
        &self,
        task: &mut Context<'_>,
        responder: u64,
    ) -> Poll<Option<Result<Box<dyn Any + Send>, Status>>> {
        let mut state = lock_unpoisoned(&self.state);
        if state.responses.is_empty()
            && self
                .drive(&mut state, task, Role::Response(responder), |state| {
                    !state.responses.is_empty()
                })
                .is_pending()
        {
            return Poll::Pending;
        }
        if let Some(message) = state.responses.pop_front() {
            // A response slot freed: a sink held at the window may continue.
            self.fanout.wake_sink();
            return Poll::Ready(Some(Ok(message)));
        }
        match &state.finished {
            Some(status) if status.code() == Code::Ok => Poll::Ready(None),
            Some(status) => Poll::Ready(Some(Err(status.clone()))),
            None => Poll::Pending,
        }
    }

    /// The single response of a client-streaming call, after the call ends.
    pub(super) fn poll_single_response(
        &self,
        task: &mut Context<'_>,
        responder: u64,
    ) -> Poll<Result<(Box<dyn Any + Send>, Metadata), Status>> {
        let mut state = lock_unpoisoned(&self.state);
        if self
            .drive(&mut state, task, Role::Response(responder), |_| false)
            .is_pending()
        {
            return Poll::Pending;
        }
        let status = state.finished.clone().unwrap_or_else(Status::ok);
        if status.code() != Code::Ok {
            return Poll::Ready(Err(status));
        }
        let message = match (state.responses.pop_front(), state.responses.is_empty()) {
            (Some(message), true) => message,
            (None, _) => {
                return Poll::Ready(Err(Status::internal(
                    "gRPC client-streaming response contained no message",
                )));
            }
            (Some(_), false) => {
                return Poll::Ready(Err(Status::internal(
                    "gRPC client-streaming response contained more than one message",
                )));
            }
        };
        let mut metadata = state.call.initial_metadata().unwrap_or_default();
        if let Some(trailers) = state.call.trailers() {
            append_metadata(&mut metadata, &trailers);
        }
        Poll::Ready(Ok((message, metadata)))
    }

    /// Terminal trailers, once received.
    pub(super) fn trailers(&self) -> Option<Metadata> {
        lock_unpoisoned(&self.state).call.trailers()
    }

    /// End the call locally with `status` unless it already ended.
    pub(super) fn cancel(&self, status: Status) {
        let ended = {
            let mut state = lock_unpoisoned(&self.state);
            let open = state.finished.is_none();
            state.fail(status);
            open
        };
        if ended {
            self.fanout.wake_sink();
            self.fanout.wake_responses();
        }
    }
}

fn ended_call_status(status: &Status) -> Status {
    if status.code() == Code::Ok {
        Status::failed_precondition("cannot send after the gRPC call completed")
    } else {
        status.clone()
    }
}

fn append_metadata(into: &mut Metadata, from: &Metadata) {
    for (key, value) in from.iter() {
        match value {
            MetadataValue::Ascii(value) => {
                let _ = into.insert(key, value.clone());
            }
            MetadataValue::Binary(value) => {
                let _ = into.insert_bin(key, value.clone());
            }
        }
    }
}

/// The response side of a legacy call. Dropping the last clone before the call
/// ends cancels it.
pub(super) struct LegacyResponseHandle {
    call: Arc<LegacyNativeCall>,
}

impl LegacyResponseHandle {
    pub(super) fn new(call: Arc<LegacyNativeCall>) -> Self {
        Self { call }
    }

    pub(super) fn call(&self) -> &LegacyNativeCall {
        &self.call
    }
}

impl Drop for LegacyResponseHandle {
    fn drop(&mut self) {
        self.call
            .cancel(Status::cancelled("response stream dropped by client"));
    }
}
