//! Bounded owned writes for the established native HTTP/3 adapter.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::task::{Context, Poll, Waker};

use parking_lot::Mutex;

use super::{
    Bytes, Cx, H3_REQUEST_CANCELLED, NativeH3ResponsePhase, NativeH3ResponseWriter,
    NativeH3SessionError, NativeH3WriteEvent, QuicConnection, StreamId,
};

pub(super) const MAX_REQUEST_WRITERS: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RequestWriterState {
    Active = 0,
    Finished = 1,
    Abandoned = 2,
    Cancelled = 3,
}

#[derive(Debug, Default)]
pub(super) struct RequestWriterWake {
    waker: Mutex<Option<Arc<Waker>>>,
}

impl RequestWriterWake {
    pub(super) fn register(&self, task_cx: &Context<'_>) {
        let current = self.waker.lock().clone();
        if current.is_some_and(|waker| waker.will_wake(task_cx.waker())) {
            return;
        }
        // RawWaker clone/drop callbacks belong outside the bookkeeping lock.
        let replacement = Arc::new(task_cx.waker().clone());
        let previous = self.waker.lock().replace(replacement);
        drop(previous);
    }

    pub(super) fn wake(&self) {
        let waker = self.waker.lock().clone();
        if let Some(waker) = waker {
            waker.wake_by_ref();
        }
    }
}

/// Session clones retain one registry so a surviving driver can reap writers
/// created by a dropped sibling. No transport or waker callback runs under
/// this lock; callers receive owned snapshots of the registrations.
#[derive(Debug, Clone, Default)]
pub(super) struct RequestWriters {
    owners: Arc<Mutex<BTreeMap<StreamId, Arc<RequestWriteOwner>>>>,
}

impl RequestWriters {
    pub(super) fn len(&self) -> usize {
        self.owners.lock().len()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.owners.lock().is_empty()
    }

    pub(super) fn contains_key(&self, stream: &StreamId) -> bool {
        self.owners.lock().contains_key(stream)
    }

    pub(super) fn get(&self, stream: &StreamId) -> Option<Arc<RequestWriteOwner>> {
        self.owners.lock().get(stream).cloned()
    }

    pub(super) fn insert(&self, stream: StreamId, owner: Arc<RequestWriteOwner>) {
        let previous = self.owners.lock().insert(stream, owner);
        drop(previous);
    }

    pub(super) fn retired(&self) -> Vec<(StreamId, Arc<RequestWriteOwner>)> {
        self.owners
            .lock()
            .iter()
            .filter(|(_, owner)| owner.state() != RequestWriterState::Active)
            .map(|(&stream, owner)| (stream, Arc::clone(owner)))
            .collect()
    }

    pub(super) fn remove(&self, stream: &StreamId, owner: &Arc<RequestWriteOwner>) {
        let removed = {
            let mut owners = self.owners.lock();
            if owners.get(stream).is_some_and(|current| Arc::ptr_eq(current, owner)) {
                owners.remove(stream)
            } else {
                None
            }
        };
        drop(removed);
    }
}

#[derive(Debug)]
pub(super) struct RequestWriteOwner {
    state: AtomicU8,
    wake: Arc<RequestWriterWake>,
}

impl RequestWriteOwner {
    pub(super) fn new(wake: Arc<RequestWriterWake>) -> Self {
        Self {
            state: AtomicU8::new(RequestWriterState::Active as u8),
            wake,
        }
    }

    pub(super) fn state(&self) -> RequestWriterState {
        match self.state.load(Ordering::Acquire) {
            0 => RequestWriterState::Active,
            1 => RequestWriterState::Finished,
            2 => RequestWriterState::Abandoned,
            _ => RequestWriterState::Cancelled,
        }
    }

    pub(super) fn abandon(&self) {
        if self
            .state
            .compare_exchange(
                RequestWriterState::Active as u8,
                RequestWriterState::Abandoned as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            self.wake.wake();
        }
    }

    pub(super) fn cancel(&self) {
        self.state
            .store(RequestWriterState::Cancelled as u8, Ordering::Release);
    }
}

/// One complete request frame admitted to the QUIC send queue.
///
/// These events acknowledge local queuing, not delivery or peer acceptance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NativeH3RequestWriteEvent {
    /// Request HEADERS, and optionally FIN, were queued.
    Headers {
        /// Whether the request has no body or trailers.
        end_stream: bool,
    },
    /// All fragments of one DATA frame were queued.
    Data {
        /// Number of application bytes in this frame.
        payload_bytes: usize,
    },
    /// Trailing HEADERS and FIN were queued.
    Trailers,
    /// A FIN-only write was queued.
    Finished,
}

/// Incremental upload on one native HTTP/3 request stream.
///
/// Construct this with [`super::NativeH3Session::start_request_writer`]. Flush
/// the initial HEADERS, then alternate [`Self::queue_data`] and
/// [`Self::poll_flush`]; end with [`Self::finish`] or [`Self::queue_trailers`]
/// and flush that terminal write. At most one encoded frame is retained.
/// Frames are split into QUIC writes that fit the current stream and
/// connection credit, even when a frame is larger than the initial window.
/// The preceding write must leave packet assembly before another is queued.
///
/// Continue driving the QUIC transport and the session's receive events while
/// this writer is pending: incoming credit, STOP_SENDING, and early responses
/// can arrive before the upload finishes. A response FIN completes only the
/// response direction and does not finish this writer.
///
/// Dropping an unfinished writer wakes the session's event poller and queues
/// cancellation on its next `poll_event`, `next_event`, or request start.
/// The session and transport must still be driven to flush that cancellation,
/// as for every other operation on this established-connection adapter. Use
/// [`Self::cancel`] to queue it immediately. No task or executor is detached.
#[derive(Debug)]
#[must_use = "an HTTP/3 upload must be flushed to FIN or cancelled"]
pub struct NativeH3RequestWriter {
    pub(super) inner: NativeH3ResponseWriter,
    pub(super) owner: Arc<RequestWriteOwner>,
    pub(super) write_offset: usize,
}

impl NativeH3RequestWriter {
    /// Request stream, also used to correlate response events.
    #[must_use]
    pub fn stream_id(&self) -> StreamId {
        self.inner.stream_id
    }

    /// Maximum application bytes accepted by one `queue_data` call.
    #[must_use]
    pub fn max_frame_payload_size(&self) -> usize {
        self.inner.max_frame_payload_size
    }

    /// Whether a frame or FIN still needs to be flushed.
    #[must_use]
    pub fn has_pending_write(&self) -> bool {
        self.inner.has_pending_write()
    }

    /// Whether this writer successfully queued request FIN.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.owner.state() == RequestWriterState::Finished
    }

    /// Retain a bounded DATA frame after the preceding frame was flushed.
    pub fn queue_data(&mut self, data: Bytes) -> Result<(), NativeH3SessionError> {
        self.ensure_open()?;
        self.inner.queue_data(data)
    }

    /// Retain validated trailing HEADERS followed by request FIN.
    pub fn queue_trailers(
        &mut self,
        fields: &[(String, String)],
    ) -> Result<(), NativeH3SessionError> {
        self.ensure_open()?;
        self.inner.queue_trailers(fields)
    }

    /// Retain a FIN-only write after the last DATA frame was flushed.
    ///
    /// Calling this again after successful FIN is harmless.
    pub fn finish(&mut self) -> Result<(), NativeH3SessionError> {
        if self.is_finished() {
            return Ok(());
        }
        self.ensure_open()?;
        self.inner.finish()
    }

    /// Queue `H3_REQUEST_CANCELLED` in both directions and release retained
    /// bytes. This bounded cleanup masks task cancellation while queuing the
    /// two transport controls; the caller still drives their transmission.
    pub fn cancel(
        &mut self,
        cx: &Cx,
        connection: &mut QuicConnection,
    ) -> Result<(), NativeH3SessionError> {
        self.owner.abandon();
        self.inner.pending = None;
        cx.masked(|| {
            connection.reset_stream(cx, self.stream_id(), H3_REQUEST_CANCELLED)?;
            connection.stop_stream_receiving(cx, self.stream_id(), H3_REQUEST_CANCELLED)?;
            Ok::<(), NativeH3SessionError>(())
        })?;
        self.owner.cancel();
        Ok(())
    }

    /// Release a stopped upload without cancelling its response direction.
    ///
    /// The transport must already own a send reset, either in response to peer
    /// STOP_SENDING or explicitly queued after the response FIN. Unlike
    /// abandonment, this must not make the session reaper send STOP_SENDING:
    /// an early response can still be arriving on the other half of the stream.
    #[cfg(feature = "tls")]
    pub(crate) fn retire_stopped_upload(
        &mut self,
        connection: &QuicConnection,
    ) -> Result<bool, NativeH3SessionError> {
        let stream = connection
            .inner()
            .streams()
            .stream(self.stream_id())
            .map_err(super::NativeQuicConnectionError::from)?;
        if stream.send_reset.is_none() {
            return Ok(false);
        }
        self.inner.pending = None;
        self.write_offset = 0;
        self.owner.cancel();
        Ok(true)
    }

    /// Poll one complete H3 frame into the transport, retaining its unsent
    /// suffix across `Pending`. Each poll queues at most one QUIC fragment.
    ///
    /// A pending poll can already have queued a prefix. Retrying this method
    /// never repeats that prefix. An error abandons the upload, releases its
    /// retained frame, and leaves the session responsible for cancellation.
    /// `Ok(None)` means there is currently no retained frame.
    pub fn poll_flush(
        &mut self,
        cx: &Cx,
        connection: &mut QuicConnection,
        task_cx: &mut Context<'_>,
    ) -> Poll<Result<Option<NativeH3RequestWriteEvent>, NativeH3SessionError>> {
        if matches!(
            self.owner.state(),
            RequestWriterState::Abandoned | RequestWriterState::Cancelled
        ) {
            self.inner.pending = None;
            return Poll::Ready(Err(NativeH3SessionError::InvalidState(
                "incremental request has been cancelled",
            )));
        }
        let Some(pending) = self.inner.pending.as_ref() else {
            return Poll::Ready(Ok(None));
        };
        let remaining = pending.wire.len() - self.write_offset;
        let required = u64::from(remaining != 0);
        let capacity = match connection.poll_stream_write_ready(cx, self.stream_id(), required, task_cx) {
            Poll::Ready(Ok(capacity)) => capacity,
            Poll::Ready(Err(error)) => return self.fail(error.into()),
            Poll::Pending => return Poll::Pending,
        };
        let count = remaining.min(usize::try_from(capacity).unwrap_or(usize::MAX));
        let end = self.write_offset + count;
        let stream_id = self.stream_id();
        let pending = self
            .inner
            .pending
            .as_mut()
            .expect("frame retained during admission");
        let complete = end == pending.wire.len();
        let wire = pending.wire.slice(self.write_offset..end);
        let fin = complete && pending.fin;
        if let Err(error) = super::write_prepared_head(
            &mut pending.qpack_section, cx, connection, stream_id, wire, fin,
        ) {
            return self.fail(error);
        }
        self.write_offset = end;
        if !complete {
            // The just-queued fragment can drain before the next poll. An
            // explicit wake closes that race; the next poll either progresses
            // or registers for packet-queue/credit readiness without spinning.
            task_cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let pending = self
            .inner
            .pending
            .take()
            .expect("frame retained until complete");
        self.write_offset = 0;
        self.inner.phase = pending.next_phase;
        if fin {
            self.owner
                .state
                .store(RequestWriterState::Finished as u8, Ordering::Release);
        }
        let event = match pending.event {
            NativeH3WriteEvent::Head { end_stream } => NativeH3RequestWriteEvent::Headers { end_stream },
            NativeH3WriteEvent::Data { payload_bytes } => {
                NativeH3RequestWriteEvent::Data { payload_bytes }
            }
            NativeH3WriteEvent::Trailers => NativeH3RequestWriteEvent::Trailers,
            NativeH3WriteEvent::Finished => NativeH3RequestWriteEvent::Finished,
        };
        Poll::Ready(Ok(Some(event)))
    }

    fn ensure_open(&self) -> Result<(), NativeH3SessionError> {
        if self.owner.state() != RequestWriterState::Active
            || self.inner.phase != NativeH3ResponsePhase::Open
            || self.inner.has_pending_write()
        {
            return Err(NativeH3SessionError::InvalidState(
                "incremental request must flush its preceding frame and remain open",
            ));
        }
        Ok(())
    }

    fn fail(
        &mut self,
        error: NativeH3SessionError,
    ) -> Poll<Result<Option<NativeH3RequestWriteEvent>, NativeH3SessionError>> {
        self.owner.abandon();
        self.inner.pending = None;
        Poll::Ready(Err(error))
    }
}

impl Drop for NativeH3RequestWriter {
    fn drop(&mut self) {
        self.owner.abandon();
    }
}

/// One complete response frame admitted to the QUIC send queue.
///
/// These events acknowledge local queuing, not delivery or peer acceptance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NativeH3ResponseWriteEvent {
    /// Final response HEADERS, and optionally FIN, were queued.
    Headers {
        /// Whether the response direction ended with its HEADERS.
        end_stream: bool,
    },
    /// All fragments of one DATA frame were queued.
    Data {
        /// Number of application bytes in this frame.
        payload_bytes: usize,
    },
    /// Trailing HEADERS and FIN were queued.
    Trailers,
    /// A FIN-only write was queued.
    Finished,
}

/// Owned incremental response on one native HTTP/3 request stream.
///
/// Construct this with [`super::NativeH3Session::start_response_body_writer`].
/// Flush the initial HEADERS, then alternate [`Self::queue_data`] and
/// [`Self::poll_flush`]. Finish with [`Self::finish`] or ordinary HTTP trailers.
/// At most one encoded frame is retained; partial writes and flow-control wakes
/// use the same bounded engine as [`NativeH3RequestWriter`].
///
/// Request FIN closes only the receive direction. The response writer remains
/// usable until its own FIN, peer STOP_SENDING, or cancellation. This allows an
/// application to exchange CONNECT DATA in both directions before either FIN.
/// The application owns CONNECT acceptance, tunneled-protocol semantics, and
/// the prohibition on trailers after a successful CONNECT response.
///
/// Dropping an unfinished writer wakes the session and leaves it responsible
/// for queuing cancellation on its next event poll or writer start. Continue
/// driving both session and transport to send those controls. [`Self::cancel`]
/// queues cancellation immediately. No task or executor is detached.
#[derive(Debug)]
#[must_use = "an HTTP/3 response must be flushed to FIN or cancelled"]
pub struct NativeH3ResponseBodyWriter {
    pub(super) writer: NativeH3RequestWriter,
}

impl NativeH3ResponseBodyWriter {
    /// Request stream carrying this response.
    #[must_use]
    pub fn stream_id(&self) -> StreamId {
        self.writer.stream_id()
    }

    /// Maximum application bytes accepted by one `queue_data` call.
    #[must_use]
    pub fn max_frame_payload_size(&self) -> usize {
        self.writer.max_frame_payload_size()
    }

    /// Whether a frame or FIN still needs to be flushed.
    #[must_use]
    pub fn has_pending_write(&self) -> bool {
        self.writer.has_pending_write()
    }

    /// Whether this writer successfully queued response FIN.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.writer.is_finished()
    }

    /// Retain a bounded DATA frame after the preceding frame was flushed.
    pub fn queue_data(&mut self, data: Bytes) -> Result<(), NativeH3SessionError> {
        self.writer.queue_data(data)
    }

    /// Retain ordinary HTTP trailers followed by response FIN.
    ///
    /// Applications must not use trailers after accepting a CONNECT tunnel;
    /// finish that response direction with [`Self::finish`] instead.
    pub fn queue_trailers(
        &mut self,
        fields: &[(String, String)],
    ) -> Result<(), NativeH3SessionError> {
        self.writer.queue_trailers(fields)
    }

    /// Retain response FIN after the last DATA frame was flushed.
    ///
    /// Calling this again after successful FIN is harmless.
    pub fn finish(&mut self) -> Result<(), NativeH3SessionError> {
        self.writer.finish()
    }

    /// Queue cancellation in both directions and release retained bytes.
    ///
    /// The two transport controls are queued under the bounded cancellation
    /// mask used by [`NativeH3RequestWriter::cancel`].
    pub fn cancel(
        &mut self,
        cx: &Cx,
        connection: &mut QuicConnection,
    ) -> Result<(), NativeH3SessionError> {
        self.writer.cancel(cx, connection)
    }

    /// Poll one complete H3 frame into the transport, retaining its unsent
    /// suffix across `Pending`. Errors leave cancellation owned by the session.
    pub fn poll_flush(
        &mut self,
        cx: &Cx,
        connection: &mut QuicConnection,
        task_cx: &mut Context<'_>,
    ) -> Poll<Result<Option<NativeH3ResponseWriteEvent>, NativeH3SessionError>> {
        self.writer.poll_flush(cx, connection, task_cx).map(|result| {
            result.map(|event| {
                event.map(|event| match event {
                    NativeH3RequestWriteEvent::Headers { end_stream } => {
                        NativeH3ResponseWriteEvent::Headers { end_stream }
                    }
                    NativeH3RequestWriteEvent::Data { payload_bytes } => {
                        NativeH3ResponseWriteEvent::Data { payload_bytes }
                    }
                    NativeH3RequestWriteEvent::Trailers => NativeH3ResponseWriteEvent::Trailers,
                    NativeH3RequestWriteEvent::Finished => NativeH3ResponseWriteEvent::Finished,
                })
            })
        })
    }
}

#[cfg(test)]
#[path = "h3_request_writer_inline_tests.rs"]
mod tests;
