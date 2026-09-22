//! Live request ingress for the native HTTP/2 listener.

use super::*;
use crate::bytes::{Bytes, BytesCursor};
use crate::channel::oneshot;
use crate::http::body::{HeaderName, HeaderValue};
use crate::http::h1::stream::{
    FramedIncomingRequestBodyWriter, IncomingBodyError, IncomingRequestBody, RequestHead,
    StreamingServerRequest,
};
use std::task::Context;

const REQUEST_FRAME_CAPACITY: usize = 8;
const REQUEST_CHUNK_BYTES: usize = 16 * 1024;
const INITIAL_STREAM_CREDIT: usize = 65_535;

type RequestBodyPolicy =
    Arc<dyn Fn(&RequestHead) -> Result<Option<u64>, Response> + Send + Sync + 'static>;
type StreamingHandler = Arc<
    dyn Fn(StreamingServerRequest) -> Pin<Box<dyn Future<Output = Http2Response> + Send>>
        + Send
        + Sync,
>;

/// Opt-in live request-body configuration for [`Http2Listener`].
///
/// The existing [`Http2ListenerConfig`] remains source compatible. Request DATA
/// credit is replenished only after the handler consumes it. The body queue,
/// already granted wire credit, and bounded trailers are reserved together at
/// HEADERS admission and remain charged until the actual request region closes.
#[derive(Clone)]
#[non_exhaustive]
pub struct Http2StreamingListenerConfig {
    /// Shared transport, request deadline, host-policy, and shutdown settings.
    /// The initial stream receive window must be at least 65,535 bytes so a
    /// peer may spend the protocol's initial credit before acknowledging SETTINGS.
    pub listener: Http2ListenerConfig,
    /// Maximum bytes committed to one handler's body queue. Must cover the
    /// larger of the protocol's initial 65,535-byte credit and the configured
    /// initial stream receive window.
    pub request_body_buffer_bytes: NonZeroUsize,
    /// Aggregate reservation available to admitted live bodies on one
    /// connection. Each admission reserves its queue, outstanding receive
    /// credit, and one bounded trailer block.
    pub connection_request_body_buffer_bytes: NonZeroUsize,
    request_body_policy: Option<RequestBodyPolicy>,
}

impl std::fmt::Debug for Http2StreamingListenerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http2StreamingListenerConfig")
            .field("listener", &self.listener)
            .field("request_body_buffer_bytes", &self.request_body_buffer_bytes)
            .field(
                "connection_request_body_buffer_bytes",
                &self.connection_request_body_buffer_bytes,
            )
            .field(
                "has_request_body_policy",
                &self.request_body_policy.is_some(),
            )
            .finish()
    }
}

impl Default for Http2StreamingListenerConfig {
    fn default() -> Self {
        Self {
            listener: Http2ListenerConfig::default(),
            request_body_buffer_bytes: NonZeroUsize::new(INITIAL_STREAM_CREDIT)
                .expect("positive initial stream window"),
            connection_request_body_buffer_bytes: NonZeroUsize::new(
                16 * (2 * INITIAL_STREAM_CREDIT + REQUEST_CHUNK_BYTES),
            )
            .expect("positive connection reservation"),
            request_body_policy: None,
        }
    }
}

impl Http2StreamingListenerConfig {
    /// Add an admission policy evaluated after transport header validation and
    /// host checks, before allocating a request region or body channel.
    ///
    /// `Ok(Some(bytes))` tightens the transport's total-body ceiling;
    /// `Ok(None)` leaves it unchanged. `Err(response)` rejects this request
    /// without invoking its handler. Chained policies all apply in order and
    /// their byte limits meet, so adding Router policy cannot loosen an
    /// existing application policy.
    #[must_use]
    pub fn with_request_body_policy<F>(mut self, policy: F) -> Self
    where
        F: Fn(&RequestHead) -> Result<Option<u64>, Response> + Send + Sync + 'static,
    {
        let previous = self.request_body_policy.take();
        self.request_body_policy = Some(Arc::new(move |head| {
            let first = match &previous {
                Some(previous) => previous(head)?,
                None => None,
            };
            let second = policy(head)?;
            Ok(match (first, second) {
                (Some(first), Some(second)) => Some(first.min(second)),
                (Some(limit), None) | (None, Some(limit)) => Some(limit),
                (None, None) => None,
            })
        }));
        self
    }

    fn wire_credit(&self) -> usize {
        INITIAL_STREAM_CREDIT.max(self.listener.settings.initial_window_size as usize)
    }

    fn reservation(&self) -> Option<usize> {
        self.request_body_buffer_bytes
            .get()
            .checked_add(self.wire_credit())?
            .checked_add(REQUEST_CHUNK_BYTES)
    }

    pub(super) fn validate(&self) -> io::Result<()> {
        if self.listener.settings.initial_window_size < INITIAL_STREAM_CREDIT as u32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "HTTP/2 live ingress requires an initial stream window of at least 65,535 bytes",
            ));
        }
        if self.request_body_buffer_bytes.get() < self.wire_credit() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "HTTP/2 live body queue must cover the initial stream receive credit",
            ));
        }
        if self
            .reservation()
            .is_none_or(|reservation| reservation > self.connection_request_body_buffer_bytes.get())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "HTTP/2 live body connection budget cannot admit one request",
            ));
        }
        Ok(())
    }
}

#[derive(Clone)]
pub(super) struct StreamingDispatch {
    pub(super) config: Http2StreamingListenerConfig,
    pub(super) handler: StreamingHandler,
}

struct BodySource {
    cx: Cx,
    writer: FramedIncomingRequestBodyWriter,
    cancel_on_drop: bool,
    failure: Arc<parking_lot::Mutex<Option<IncomingBodyError>>>,
}

impl Drop for BodySource {
    fn drop(&mut self) {
        // Publication may race connection loss before the driver receives the
        // oneshot. Keep cancellation attached to the source itself so dropping
        // the unopened publication cannot strand an already-running handler.
        if self.cancel_on_drop {
            let error = self
                .failure
                .lock()
                .clone()
                .unwrap_or(IncomingBodyError::ClientAborted);
            let kind = match &error {
                IncomingBodyError::Cancelled { kind } => *kind,
                _ => CancelKind::ParentCancelled,
            };
            self.writer.fail(error);
            self.cx
                .cancel_with(kind, Some("HTTP/2 request source retired"));
        }
    }
}

struct LiveRequest {
    publication: Option<oneshot::Receiver<BodySource>>,
    source: Option<BodySource>,
    coordinator: Option<Pin<Box<CatchUnwind<JoinHandle<()>>>>>,
    pending_data: Vec<u8>,
    pending_trailers: Option<HeaderMap>,
    total_bytes: u64,
    declared_length: Option<u64>,
    max_body_size: u64,
    end_stream: bool,
    finished: bool,
    abandoned: bool,
    failed: bool,
    completion_seen: bool,
    failure: Arc<parking_lot::Mutex<Option<IncomingBodyError>>>,
    completion_posted: Arc<std::sync::atomic::AtomicBool>,
}

impl LiveRequest {
    fn fail(&mut self, error: IncomingBodyError) {
        if self.failed {
            return;
        }
        self.failed = true;
        *self.failure.lock() = Some(error.clone());
        if let Some(mut publication) = self.publication.take()
            && let Ok(source) = publication.try_recv()
        {
            self.source = Some(source);
        }
        self.pending_data.clear();
        self.pending_trailers = None;
        if let Some(BodySource { cx, writer, .. }) = &mut self.source {
            // Publish the exact body cause before cancellation wakes readers.
            writer.fail(error.clone());
            let kind = match error {
                IncomingBodyError::Cancelled { kind } => kind,
                _ => CancelKind::ParentCancelled,
            };
            cx.cancel_with(kind, Some("HTTP/2 live request body failed"));
        }
    }

    fn poll(&mut self, poll_cx: &mut Context<'_>) -> Result<(bool, u64), IncomingBodyError> {
        let mut progress = false;
        if let Some(coordinator) = &mut self.coordinator {
            if let Poll::Ready(result) = coordinator.as_mut().poll(poll_cx) {
                self.coordinator = None;
                progress = true;
                if result.is_err() || !self.completion_posted.load(Ordering::Acquire) {
                    self.completion_seen = true;
                    if !self.failed {
                        return Err(IncomingBodyError::SourceDisconnected);
                    }
                }
            }
        }
        if self.failed || self.abandoned {
            return Ok((progress, 0));
        }
        if let Some(publication) = &mut self.publication {
            match publication.poll_recv_uninterruptible(poll_cx) {
                Poll::Pending => return Ok((progress, 0)),
                Poll::Ready(Err(_)) => return Err(IncomingBodyError::SourceDisconnected),
                Poll::Ready(Ok(source)) => {
                    self.publication = None;
                    self.source = Some(source);
                    progress = true;
                }
            }
        }
        let Some(BodySource { cx, writer, .. }) = &mut self.source else {
            return Ok((progress, 0));
        };
        match writer.poll_consumer_dropped(poll_cx) {
            Poll::Ready(Ok(())) => return Err(IncomingBodyError::ConsumerDropped),
            Poll::Ready(Err(error)) => return Err(error),
            Poll::Pending => {}
        }
        let consumed = writer.poll_consumed_data(poll_cx);
        if self.finished {
            return Ok((progress, consumed));
        }
        if writer.has_pending_frame() {
            match writer.poll_send_frame(cx, poll_cx, &mut None) {
                Poll::Pending => return Ok((progress, consumed)),
                Poll::Ready(Err(error)) => return Err(error),
                Poll::Ready(Ok(())) => progress = true,
            }
        }
        // Coalesce arbitrarily many tiny peer DATA frames into bounded byte
        // storage. At most one frame is parked in the writer, independent of
        // how many frames the peer used to spend its advertised credit.
        if !self.pending_data.is_empty() {
            let take = self.pending_data.len().min(REQUEST_CHUNK_BYTES);
            // Bytes::from(Vec) retains the Vec's capacity. Copy only this
            // bounded chunk so each queued prefix cannot retain an entire
            // receive-window allocation; the staging allocation stays owned
            // by this entry and is covered by its wire-credit reservation.
            let bytes = Bytes::copy_from_slice(&self.pending_data[..take]);
            self.pending_data.drain(..take);
            let mut frame = Some(BodyFrame::Data(BytesCursor::new(bytes)));
            match writer.poll_send_frame(cx, poll_cx, &mut frame) {
                Poll::Pending => return Ok((true, consumed)),
                Poll::Ready(Err(error)) => return Err(error),
                Poll::Ready(Ok(())) => progress = true,
            }
        }
        if self.pending_data.is_empty() {
            if let Some(trailers) = self.pending_trailers.take() {
                let mut frame = Some(BodyFrame::Trailers(trailers));
                match writer.poll_send_frame(cx, poll_cx, &mut frame) {
                    Poll::Pending => return Ok((true, consumed)),
                    Poll::Ready(Err(error)) => return Err(error),
                    Poll::Ready(Ok(())) => progress = true,
                }
            }
            if self.end_stream {
                writer.finish(cx)?;
                self.finished = true;
                progress = true;
            }
        }
        Ok((progress, consumed))
    }
}

impl Drop for LiveRequest {
    fn drop(&mut self) {
        if !self.completion_seen {
            self.fail(IncomingBodyError::ClientAborted);
        }
    }
}

pub(super) struct StreamingRequests {
    dispatch: StreamingDispatch,
    entries: BTreeMap<u32, LiveRequest>,
    early_response_stops: HashSet<u32>,
    reserved_bytes: usize,
}

impl StreamingRequests {
    pub(super) fn new(dispatch: StreamingDispatch) -> Self {
        Self {
            dispatch,
            entries: BTreeMap::new(),
            early_response_stops: HashSet::new(),
            reserved_bytes: 0,
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.early_response_stops.is_empty()
    }

    pub(super) fn contains(&self, stream_id: u32) -> bool {
        self.entries.contains_key(&stream_id) || self.early_response_stops.contains(&stream_id)
    }

    pub(super) fn is_active(&self, stream_id: u32) -> bool {
        self.entries
            .get(&stream_id)
            .is_some_and(|entry| !entry.failed && !entry.completion_seen)
    }

    pub(super) fn fail(&mut self, stream_id: u32, error: IncomingBodyError) {
        self.early_response_stops.remove(&stream_id);
        if let Some(entry) = self.entries.get_mut(&stream_id) {
            entry.fail(error);
        }
    }

    fn reject(
        &mut self,
        conn: &mut Connection,
        stream_id: u32,
        response: Response,
        suppress_body: bool,
        end_stream: bool,
        guards: &mut HashMap<u32, Arc<InFlightRequestGuard>>,
    ) {
        queue_h2_response(
            conn,
            stream_id,
            response.into_h2_response(),
            InFlightRequestGuard::acquire(None),
            suppress_body,
            guards,
        );
        if !end_stream {
            self.early_response_stops.insert(stream_id);
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn admit(
        &mut self,
        conn: &mut Connection,
        stream_id: u32,
        headers: Vec<Header>,
        end_stream: bool,
        peer_addr: Option<SocketAddr>,
        resp_tx: &mpsc::Sender<FunnelItem>,
        signal: &ShutdownSignal,
        in_flight: &Arc<AtomicUsize>,
        runtime: &RuntimeHandle,
        response_guards: &mut HashMap<u32, Arc<InFlightRequestGuard>>,
    ) -> bool {
        let (head, declared_length) = match request_head_from_h2_headers(headers) {
            Ok(parts) => parts,
            Err(_) => {
                conn.reset_stream(stream_id, ErrorCode::ProtocolError);
                return false;
            }
        };
        if end_stream && declared_length.is_some_and(|length| length != 0) {
            conn.reset_stream(stream_id, ErrorCode::ProtocolError);
            return false;
        }
        if conn.defer_stream_receive_window(stream_id).is_err() {
            conn.reset_stream(stream_id, ErrorCode::InternalError);
            return false;
        }
        let suppress_response_body = head.method == Method::Head;
        let config = &self.dispatch.config;
        if validate_host_header(&head.headers, &config.listener.allowed_hosts).is_err() {
            self.reject(
                conn,
                stream_id,
                Response::new(421, "Misdirected Request", Vec::new()),
                suppress_response_body,
                end_stream,
                response_guards,
            );
            return false;
        }
        let mut max_body_size = config.listener.max_body_size as u64;
        if let Some(policy) = &config.request_body_policy {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| policy(&head))) {
                Ok(Ok(Some(limit))) => max_body_size = max_body_size.min(limit),
                Ok(Ok(None)) => {}
                Ok(Err(response)) => {
                    self.reject(
                        conn,
                        stream_id,
                        response,
                        suppress_response_body,
                        end_stream,
                        response_guards,
                    );
                    return false;
                }
                Err(_) => {
                    conn.reset_stream(stream_id, ErrorCode::InternalError);
                    return false;
                }
            }
        }
        if declared_length.is_some_and(|length| length > max_body_size) {
            self.reject(
                conn,
                stream_id,
                Response::new(413, "Payload Too Large", Vec::new()),
                suppress_response_body,
                end_stream,
                response_guards,
            );
            return false;
        }
        let reservation = config
            .reservation()
            .expect("validated streaming reservation");
        let Some(reserved) = self
            .reserved_bytes
            .checked_add(reservation)
            .filter(|bytes| *bytes <= config.connection_request_body_buffer_bytes.get())
        else {
            conn.reset_stream(stream_id, ErrorCode::RefusedStream);
            return false;
        };
        let (publisher, publication) = oneshot::channel();
        let failure = Arc::new(parking_lot::Mutex::new(None));
        let source_failure = Arc::clone(&failure);
        let completion_posted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let posted_by_coordinator = Arc::clone(&completion_posted);
        let queue_bytes = config.request_body_buffer_bytes.get();
        let request_timeout = config.listener.request_timeout;
        let timeout_cap = config.listener.request_timeout_header_cap;
        let drain_grace = config.listener.request_drain_grace;
        let handler = Arc::clone(&self.dispatch.handler);
        let response_sender = resp_tx.clone();
        let signal = signal.clone();
        let guard = InFlightRequestGuard::acquire(Some(in_flight));
        let coordinator = runtime.try_spawn(async move {
            let Some(cx) = Cx::current() else {
                return;
            };
            let now = cx.now();
            let (budget, source) = derive_request_budget(
                cx.budget(),
                now,
                request_timeout,
                parse_request_timeout_header(&head.headers),
                timeout_cap,
            );
            let completion = run_owned_h2_hop_with_cx(
                &cx,
                &signal,
                OwnedH2HopConfig {
                    budget,
                    started_at: now,
                    source,
                    drain_grace,
                    idle_timeout: None,
                },
                move |request_cx| async move {
                    let (writer, body) = IncomingRequestBody::framed_channel_with_limits(
                        &request_cx,
                        declared_length,
                        REQUEST_FRAME_CAPACITY,
                        queue_bytes,
                    );
                    let writer = writer
                        .max_body_size(max_body_size)
                        .max_trailers_size(REQUEST_CHUNK_BYTES);
                    if publisher
                        .send_blocking(BodySource {
                            cx: request_cx,
                            writer,
                            cancel_on_drop: true,
                            failure: source_failure,
                        })
                        .is_err()
                    {
                        return H2DispatchResponse::Buffered(invalid_h2_response_fallback());
                    }
                    H2DispatchResponse::Buffered(
                        handler(StreamingServerRequest {
                            head,
                            peer_addr,
                            body,
                        })
                        .await,
                    )
                },
            )
            .await;
            let response = match completion {
                Ok(OwnedH2HopCompletion {
                    hop: ServerHopOutcome::Ok(H2DispatchResponse::Buffered(response)),
                    ..
                }) => Some(response),
                Ok(OwnedH2HopCompletion {
                    hop: ServerHopOutcome::DeadlineExceeded,
                    ..
                }) => Some(
                    Response::new(
                        503,
                        "Service Unavailable",
                        HTTP_DEADLINE_EXHAUSTED_DIAGNOSTIC.as_bytes().to_vec(),
                    )
                    .into_h2_response(),
                ),
                Ok(OwnedH2HopCompletion {
                    hop: ServerHopOutcome::Cancelled | ServerHopOutcome::ConnectionLost,
                    ..
                }) => None,
                _ => Some(invalid_h2_response_fallback()),
            };
            // Cleanup publication uses the coordinator Cx; the cancelled request
            // Cx must not prevent its owner from reporting that close completed.
            if let Ok(permit) = response_sender.reserve(&cx).await {
                let posted = permit
                    .try_send(FunnelItem::StreamingDone {
                        stream_id,
                        response,
                        guard,
                        suppress_response_body,
                    })
                    .is_ok();
                posted_by_coordinator.store(posted, Ordering::Release);
            }
        });
        let coordinator = match coordinator {
            Ok(coordinator) => coordinator,
            Err(_) => {
                conn.reset_stream(stream_id, ErrorCode::RefusedStream);
                return false;
            }
        };
        self.reserved_bytes = reserved;
        self.entries.insert(
            stream_id,
            LiveRequest {
                publication: Some(publication),
                source: None,
                coordinator: Some(Box::pin(CatchUnwind { inner: coordinator })),
                pending_data: Vec::with_capacity(config.wire_credit()),
                pending_trailers: None,
                total_bytes: 0,
                declared_length,
                max_body_size,
                end_stream,
                finished: false,
                abandoned: false,
                failed: false,
                completion_seen: false,
                failure,
                completion_posted,
            },
        );
        true
    }

    pub(super) fn data(
        &mut self,
        stream_id: u32,
        data: Bytes,
        end_stream: bool,
        conn: &mut Connection,
    ) {
        let Some(entry) = self.entries.get_mut(&stream_id) else {
            return;
        };
        if entry.failed || entry.abandoned {
            return;
        }
        let Some(total) = entry.total_bytes.checked_add(data.len() as u64) else {
            entry.fail(IncomingBodyError::AccountingOverflow);
            conn.reset_stream(stream_id, ErrorCode::EnhanceYourCalm);
            return;
        };
        let error = if total > entry.max_body_size {
            Some(IncomingBodyError::BodyTooLarge {
                actual: Some(total),
                limit: entry.max_body_size,
            })
        } else if entry
            .declared_length
            .is_some_and(|length| total > length || (end_stream && total != length))
        {
            Some(IncomingBodyError::BadContentLength)
        } else if entry.pending_data.len().saturating_add(data.len())
            > self.dispatch.config.wire_credit()
        {
            Some(IncomingBodyError::AccountingOverflow)
        } else {
            None
        };
        if let Some(error) = error {
            let code = body_error_code(&error);
            entry.fail(error);
            conn.reset_stream(stream_id, code);
            return;
        }
        entry.total_bytes = total;
        entry.pending_data.extend_from_slice(&data);
        entry.end_stream = end_stream;
    }

    pub(super) fn trailers(
        &mut self,
        stream_id: u32,
        headers: Vec<Header>,
        end_stream: bool,
        conn: &mut Connection,
    ) {
        let Some(entry) = self.entries.get_mut(&stream_id) else {
            return;
        };
        if entry.failed || entry.abandoned {
            return;
        }
        let checked = (|| {
            if !end_stream || entry.end_stream || entry.pending_trailers.is_some() {
                return Err(IncomingBodyError::BadHeader);
            }
            if entry
                .declared_length
                .is_some_and(|length| length != entry.total_bytes)
            {
                return Err(IncomingBodyError::BadContentLength);
            }
            let bytes = headers
                .iter()
                .try_fold(0usize, |total, header| {
                    total
                        .checked_add(header.name.len())?
                        .checked_add(header.value.len())?
                        .checked_add(4)
                })
                .ok_or(IncomingBodyError::AccountingOverflow)?;
            if bytes > REQUEST_CHUNK_BYTES {
                return Err(IncomingBodyError::TrailersTooLarge);
            }
            let mut trailers = HeaderMap::new();
            for header in headers {
                crate::http::h1::codec::validate_header_field(&header.name, &header.value)
                    .map_err(|_| IncomingBodyError::BadHeader)?;
                if crate::http::h1::codec::is_forbidden_trailer(&header.name) {
                    return Err(IncomingBodyError::BadHeader);
                }
                let name = HeaderName::from_string(&header.name);
                let value = HeaderValue::from_bytes(header.value.as_bytes());
                trailers.append(name, value);
            }
            Ok(trailers)
        })();
        match checked {
            Ok(trailers) => {
                entry.pending_trailers = Some(trailers);
                entry.end_stream = true;
            }
            Err(error) => {
                let code = body_error_code(&error);
                entry.fail(error);
                conn.reset_stream(stream_id, code);
            }
        }
    }

    pub(super) fn poll(&mut self, conn: &mut Connection, poll_cx: &mut Context<'_>) -> bool {
        let mut progressed = false;
        for (&stream_id, entry) in &mut self.entries {
            match entry.poll(poll_cx) {
                Ok((progress, consumed)) => {
                    progressed |= progress;
                    if consumed != 0 {
                        match u32::try_from(consumed).ok().and_then(|bytes| {
                            conn.release_stream_receive_capacity(stream_id, bytes).ok()
                        }) {
                            Some(()) => progressed = true,
                            None => {
                                entry.fail(IncomingBodyError::AccountingOverflow);
                                conn.reset_stream(stream_id, ErrorCode::InternalError);
                                progressed = true;
                            }
                        }
                    }
                }
                Err(IncomingBodyError::ConsumerDropped) => {
                    entry.abandoned = true;
                    entry.pending_data.clear();
                    entry.pending_trailers = None;
                    if let Some(BodySource { writer, .. }) = &mut entry.source {
                        writer.fail(IncomingBodyError::ConsumerDropped);
                    }
                    progressed = true;
                }
                Err(error) => {
                    let code = body_error_code(&error);
                    entry.fail(error);
                    conn.reset_stream(stream_id, code);
                    progressed = true;
                }
            }
        }
        progressed
    }

    pub(super) fn complete(
        &mut self,
        stream_id: u32,
        conn: &mut Connection,
        poll_cx: &mut Context<'_>,
    ) -> bool {
        let Some(entry) = self.entries.get_mut(&stream_id) else {
            return false;
        };
        if let Some(publication) = &mut entry.publication
            && let Ok(source) = publication.try_recv()
        {
            entry.publication = None;
            entry.source = Some(source);
        }
        if !entry.failed {
            if let Some(source) = &entry.source
                && let Poll::Ready(Err(error)) = source.writer.poll_consumer_dropped(poll_cx)
            {
                let code = body_error_code(&error);
                entry.fail(error);
                conn.reset_stream(stream_id, code);
            }
        }
        entry.completion_seen = true;
        if let Some(source) = &mut entry.source {
            source.cancel_on_drop = false;
        }
        if !entry.failed && !entry.end_stream {
            self.early_response_stops.insert(stream_id);
        }
        !entry.failed
    }

    pub(super) fn after_flush(
        &mut self,
        conn: &mut Connection,
        response_guards: &HashMap<u32, Arc<InFlightRequestGuard>>,
    ) -> bool {
        let reservation = self
            .dispatch
            .config
            .reservation()
            .expect("validated reservation");
        self.entries.retain(|_, entry| {
            if entry.completion_seen && entry.coordinator.is_none() {
                self.reserved_bytes = self.reserved_bytes.saturating_sub(reservation);
                false
            } else {
                true
            }
        });
        let mut reset_queued = false;
        self.early_response_stops.retain(|stream_id| {
            if response_guards.contains_key(stream_id) {
                return true;
            }
            conn.reset_stream(*stream_id, ErrorCode::NoError);
            reset_queued = true;
            false
        });
        reset_queued
    }

    pub(super) async fn close(&mut self, error: IncomingBodyError) {
        for entry in self.entries.values_mut() {
            entry.fail(error.clone());
        }
        for entry in self.entries.values_mut() {
            if let Some(coordinator) = entry.coordinator.take() {
                let _ = coordinator.await;
            }
        }
    }
}

fn body_error_code(error: &IncomingBodyError) -> ErrorCode {
    match error {
        IncomingBodyError::BadContentLength
        | IncomingBodyError::BadHeader
        | IncomingBodyError::InvalidHeaderName
        | IncomingBodyError::InvalidHeaderValue
        | IncomingBodyError::BadChunkedEncoding => ErrorCode::ProtocolError,
        IncomingBodyError::BodyTooLarge { .. }
        | IncomingBodyError::TrailersTooLarge
        | IncomingBodyError::AccountingOverflow
        | IncomingBodyError::QueueFrameTooLarge { .. } => ErrorCode::EnhanceYourCalm,
        _ => ErrorCode::Cancel,
    }
}
