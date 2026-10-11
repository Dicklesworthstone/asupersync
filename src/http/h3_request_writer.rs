//! Bounded request-side writes for the established native HTTP/3 adapter.

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

    fn wake(&self) {
        let waker = self.waker.lock().clone();
        if let Some(waker) = waker {
            waker.wake_by_ref();
        }
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
        let pending = self
            .inner
            .pending
            .as_ref()
            .expect("frame retained during admission");
        let complete = end == pending.wire.len();
        let wire = pending.wire.slice(self.write_offset..end);
        let fin = complete && pending.fin;
        if let Err(error) = connection.write_stream(cx, self.stream_id(), wire, fin) {
            return self.fail(error.into());
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::h3_native::{
        H3ConnectionConfig, H3Frame, H3PseudoHeaders, H3RequestHead, H3ResponseHead,
        H3Settings, qpack_encode_request_field_section, qpack_encode_response_field_section,
        qpack_encode_trailer_field_section,
    };
    use crate::http::h3_quic::{NativeH3Event, NativeH3Session};
    use crate::net::atp::protocol::quic_frames::QuicFrame;
    use crate::net::atp::protocol::varint::VarInt;
    use crate::net::quic_native::{NativeQuicConnectionConfig, PacketNumberSpace};
    use std::sync::atomic::AtomicUsize;
    use std::task::Wake;

    fn client(max_frame_payload_size: usize) -> (Cx, QuicConnection, NativeH3Session) {
        let cx = Cx::for_testing();
        let mut connection = QuicConnection::client(NativeQuicConnectionConfig::default());
        connection.begin_handshake(&cx).unwrap();
        connection.mark_handshake_keys_available(&cx).unwrap();
        connection.mark_app_keys_available(&cx).unwrap();
        // A client refuses to confirm until a verifying handshake recorded the
        // server identity (br-asupersync-7pwwwe); these tests stand in for one.
        connection.record_verified_server_identity();
        connection.confirm_handshake(&cx).unwrap();
        let mut session = NativeH3Session::with_config(H3ConnectionConfig {
            max_frame_payload_size,
            ..H3ConnectionConfig::default()
        });
        session.initialize(&cx, &mut connection, H3Settings::default()).unwrap();
        (cx, connection, session)
    }

    fn head() -> H3RequestHead {
        H3RequestHead::new(
            H3PseudoHeaders {
                method: Some("POST".to_owned()),
                scheme: Some("https".to_owned()),
                authority: Some("example.test".to_owned()),
                path: Some("/upload".to_owned()),
                ..H3PseudoHeaders::default()
            },
            Vec::new(),
        )
        .unwrap()
    }

    fn drain(
        cx: &Cx,
        connection: &mut QuicConnection,
        stream: StreamId,
        bytes: &mut Vec<u8>,
    ) -> usize {
        let mut fins = 0;
        for frame in connection.inner_mut().generate_stream_frames_for(
            cx, PacketNumberSpace::ApplicationData, stream, 65_536,
        ).unwrap() {
            if let QuicFrame::Stream { stream_id, offset, data, fin } = frame {
                assert_eq!(stream_id.value(), stream.0);
                assert_eq!(offset.map_or(0, VarInt::value), bytes.len() as u64);
                bytes.extend_from_slice(&data);
                fins += usize::from(fin);
            }
        }
        fins
    }

    fn replenish(cx: &Cx, connection: &mut QuicConnection, stream: StreamId, step: u64) {
        let limit = connection.inner().streams().stream(stream).unwrap().send_offset + step;
        let connection_limit = connection.inner().streams().connection_send_limit() + step;
        for frame in [
            QuicFrame::MaxStreamData {
                stream_id: VarInt::from_u64_unchecked(stream.0),
                maximum_stream_data: VarInt::from_u64_unchecked(limit),
            },
            QuicFrame::MaxData { maximum_data: VarInt::from_u64_unchecked(connection_limit) },
        ] {
            connection.inner_mut().process_frame(cx, &frame, PacketNumberSpace::ApplicationData).unwrap();
        }
    }

    #[test]
    fn incremental_request_fragments_headers_data_and_trailers_without_repeating_prefixes() {
        let (cx, mut connection, mut session) = client(4096);
        let mut head = head();
        head.headers.push(("x-large".to_owned(), "h".repeat(512)));
        let mut writer = session.start_request_writer(&cx, &mut connection, &head, false).unwrap();
        let stream = writer.stream_id();
        connection.inner_mut().set_fresh_stream_send_limit(&cx, stream, 17).unwrap();
        let sent = connection.inner().streams().connection_send_limit()
            - connection.inner().streams().connection_send_remaining();
        connection.inner_mut().constrain_connection_send_limit_for_testing(&cx, sent + 11).unwrap();
        assert!(writer.queue_data(Bytes::new()).is_err(), "HEADERS must go first");
        let data = Bytes::from(vec![0xa5; 2048]);
        let trailers = vec![("x-upload-check".to_owned(), "t".repeat(256))];
        let mut expected = Vec::new();
        H3Frame::Headers(qpack_encode_request_field_section(&head).unwrap()).encode(&mut expected).unwrap();
        H3Frame::Data(data.to_vec()).encode(&mut expected).unwrap();
        H3Frame::Headers(qpack_encode_trailer_field_section(&trailers).unwrap()).encode(&mut expected).unwrap();
        let mut wire = Vec::new();
        let mut fins = 0;
        let mut pending_polls = 0;
        let mut task_cx = Context::from_waker(Waker::noop());
        for expected_event in [
            NativeH3RequestWriteEvent::Headers { end_stream: false },
            NativeH3RequestWriteEvent::Data { payload_bytes: data.len() },
            NativeH3RequestWriteEvent::Trailers,
        ] {
            if matches!(expected_event, NativeH3RequestWriteEvent::Data { .. }) {
                writer.queue_data(data.clone()).unwrap();
                assert!(writer.queue_data(Bytes::new()).is_err(), "only one retained frame");
            } else if expected_event == NativeH3RequestWriteEvent::Trailers {
                writer.queue_trailers(&trailers).unwrap();
                assert!(writer.queue_data(Bytes::new()).is_err(), "trailers are terminal");
            }
            loop {
                let result = writer.poll_flush(&cx, &mut connection, &mut task_cx);
                assert!(connection.pending_stream_data_bytes(stream) <= 17);
                // A second poll before packet assembly cannot enqueue another
                // fragment or change the retained offset.
                if result.is_pending() && connection.has_pending_stream_frames(stream) {
                    let offset = writer.write_offset;
                    assert!(writer.poll_flush(&cx, &mut connection, &mut task_cx).is_pending());
                    assert_eq!(writer.write_offset, offset);
                }
                fins += drain(&cx, &mut connection, stream, &mut wire);
                match result {
                    Poll::Ready(Ok(Some(event))) => { assert_eq!(event, expected_event); break; }
                    Poll::Pending => {
                        pending_polls += 1;
                        assert!(pending_polls < 512, "bounded frame must make credit-driven progress");
                        replenish(&cx, &mut connection, stream, 17);
                    }
                    other @ Poll::Ready(_) => panic!("unexpected upload flush: {other:?}"),
                }
            }
        }
        assert!(pending_polls > 100);
        assert_eq!(wire, expected);
        assert_eq!(fins, 1);
        assert!(writer.is_finished());
        assert!(!writer.has_pending_write());
        writer.finish().unwrap();
        drop(writer);
        assert_eq!(session.next_event(&cx, &mut connection).unwrap(), None);
        assert!(session.request_writers.is_empty());
        assert!(connection.inner().streams().stream(stream).unwrap().send_reset.is_none());
    }

    #[derive(Default)]
    struct WakeCount(AtomicUsize);

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
        fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    }

    #[test]
    fn incremental_request_drop_wakes_session_and_cancellation_releases_pending_bytes() {
        for finish in 0..3 {
            let cancelled_context = finish != 0;
            let (cx, mut connection, mut session) = client(4096);
            let mut writer = session.start_request_writer(&cx, &mut connection, &head(), false).unwrap();
            let stream = writer.stream_id();
            connection.inner_mut().set_fresh_stream_send_limit(&cx, stream, 0).unwrap();
            let counter = Arc::new(WakeCount::default());
            let waker = Waker::from(Arc::clone(&counter));
            let mut task_cx = Context::from_waker(&waker);
            assert!(session.poll_event(&cx, &mut connection, &mut task_cx).is_pending());
            assert!(writer.poll_flush(&cx, &mut connection, &mut task_cx).is_pending());
            assert_eq!(counter.0.load(Ordering::SeqCst), 0);
            if cancelled_context {
                cx.set_cancel_requested(true);
                if finish == 1 {
                    assert!(matches!(
                        writer.poll_flush(&cx, &mut connection, &mut task_cx),
                        Poll::Ready(Err(_))
                    ));
                } else {
                    writer.cancel(&cx, &mut connection).unwrap();
                }
                assert!(!writer.has_pending_write());
            }
            drop(writer);
            assert!(counter.0.load(Ordering::SeqCst) > 0, "drop must wake the parked session");
            let result = session.next_event(&cx, &mut connection);
            assert_eq!(result.is_err(), cancelled_context);
            let state = connection.inner().streams().stream(stream).unwrap();
            assert_eq!(state.send_reset, Some((H3_REQUEST_CANCELLED, 0)));
            assert_eq!(state.receive_stopped_error_code, Some(H3_REQUEST_CANCELLED));
            assert!(session.request_writers.is_empty());
            assert_eq!(connection.pending_stream_data_bytes(stream), 0);
        }
    }

    #[test]
    fn incremental_request_early_response_fin_does_not_close_upload() {
        let (cx, mut connection, mut session) = client(4096);
        let mut writer = session.start_request_writer(&cx, &mut connection, &head(), false).unwrap();
        let stream = writer.stream_id();
        let mut task_cx = Context::from_waker(Waker::noop());
        assert!(matches!(writer.poll_flush(&cx, &mut connection, &mut task_cx), Poll::Ready(Ok(Some(_)))));
        let mut sent = Vec::new();
        assert_eq!(drain(&cx, &mut connection, stream, &mut sent), 0);
        let response = H3ResponseHead::new(200, Vec::new()).unwrap();
        let mut wire = Vec::new();
        H3Frame::Headers(qpack_encode_response_field_section(&response).unwrap()).encode(&mut wire).unwrap();
        connection.inner_mut().receive_stream_bytes(&cx, stream, 0, Bytes::from(wire), true).unwrap();
        assert_eq!(session.next_event(&cx, &mut connection).unwrap(), Some(NativeH3Event::ResponseHeaders { stream_id: stream, head: response }));
        assert_eq!(session.next_event(&cx, &mut connection).unwrap(), Some(NativeH3Event::Finished { stream_id: stream }));
        assert!(!writer.is_finished());
        writer.queue_data(Bytes::from_static(b"upload after response FIN")).unwrap();
        assert!(matches!(writer.poll_flush(&cx, &mut connection, &mut task_cx), Poll::Ready(Ok(Some(NativeH3RequestWriteEvent::Data { .. })))));
        drain(&cx, &mut connection, stream, &mut sent);
        writer.finish().unwrap();
        assert_eq!(writer.poll_flush(&cx, &mut connection, &mut task_cx), Poll::Ready(Ok(Some(NativeH3RequestWriteEvent::Finished))));
        assert_eq!(drain(&cx, &mut connection, stream, &mut sent), 1);
        assert!(writer.is_finished());
    }

    #[test]
    fn incremental_request_refuses_oversized_head_before_stream_allocation() {
        let (cx, mut connection, mut session) = client(8);
        assert!(matches!(
            session.start_request_writer(&cx, &mut connection, &head(), false),
            Err(NativeH3SessionError::Protocol(crate::http::h3_native::H3NativeError::FrameTooLarge { .. }))
        ));
        assert_eq!(session.next_local_request_stream_id, 0);
        assert!(session.request_writers.is_empty());
        assert_eq!(connection.open_bidi_stream(&cx).unwrap(), StreamId(0));
    }
}
