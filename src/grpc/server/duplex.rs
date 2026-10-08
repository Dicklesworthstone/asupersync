//! Native registered RPC dispatch with live, bounded request and response bodies.

use super::server_streaming::{
    StreamDeadline, bounded_terminal_trailers, forward_messages, poll_cancellable,
};
use super::{
    CompressionEncoding, Cx, HostPolicy, HttpResponse, Metadata, Request, Response, RuntimeHandle,
    Server, ServerStreamingConfig, ServiceHandler, ShutdownStats, Status,
    enforce_http2_metadata_blocks, grpc_content_type_is_allowed,
    grpc_request_trailer_key_is_reserved, insert_http2_metadata_entry,
};
use crate::bytes::{Buf, Bytes, BytesCursor, BytesMut};
use crate::grpc::codec::{FramedCodec, IdentityCodec, MESSAGE_HEADER_SIZE};
use crate::grpc::service::{RegisteredServerStream, ServiceDescriptor};
use crate::grpc::streaming::{Streaming, StreamingRequest};
use crate::http::body::{Body, Frame, HeaderMap};
use crate::http::h1::HttpError;
use crate::http::h1::stream::{IncomingBodyError, IncomingRequestBody, StreamingServerRequest};
use crate::http::h1::types::Method;
use crate::http::h2::listener::{
    Http2BodySender, Http2Listener, Http2ProducedResponse, Http2StreamingListenerConfig,
};
use crate::types::CancelKind;
use crate::web::request_region::ServerRequestDeadline;
use std::collections::BTreeSet;
use std::future::{Future, poll_fn};
use std::io;
use std::net::ToSocketAddrs;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

/// Explicit ingress and egress bounds for the native duplex RPC listener.
///
/// The wire-body ceiling counts gRPC prefixes and compressed bytes. The
/// server's message limit independently bounds each wire and decoded payload,
/// and `ServerConfig::max_request_body_bytes` counts decoded payloads across
/// the call. Queue limits control resident input, independently of call length.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ServerDuplexConfig {
    /// Bounded response channel, frame, trailer and terminal delivery settings.
    pub response: ServerStreamingConfig,
    /// Maximum cumulative HTTP/2 request DATA bytes, including gRPC framing.
    pub max_request_wire_bytes: usize,
    /// Resident request-body queue bytes, at least HTTP/2's 65,535-byte
    /// default window. The duplex listener advertises an initial stream window
    /// no larger than this queue, so the credit a peer may use always fits.
    pub request_body_buffer_bytes: NonZeroUsize,
    /// Aggregate input reservation available on one connection.
    pub connection_request_body_buffer_bytes: NonZeroUsize,
}

impl Default for ServerDuplexConfig {
    fn default() -> Self {
        let input = Http2StreamingListenerConfig::default();
        Self {
            response: ServerStreamingConfig {
                frame_capacity: NonZeroUsize::new(8).expect("positive frame capacity"),
                max_frame_bytes: NonZeroUsize::new(16 * 1024).expect("positive frame size"),
                max_trailer_bytes: 16 * 1024,
                terminal_timeout: Duration::from_secs(1),
            },
            max_request_wire_bytes: 16 * 1024 * 1024,
            request_body_buffer_bytes: input.request_body_buffer_bytes,
            connection_request_body_buffer_bytes: input.connection_request_body_buffer_bytes,
        }
    }
}

#[derive(Default)]
struct IngressTerminal {
    failure: Option<Status>,
    trailers: Option<Metadata>,
}

/// The sole owner of an incrementally decoded native gRPC request stream.
///
/// Polling consumes only enough input for the next message. It releases HTTP/2
/// credit as the bounded body is consumed, and retains at most one encoded
/// message plus one transport chunk. The codec additionally bounds decompressed
/// payloads and aggregate decoded bytes. No background reader is spawned.
///
/// The stream is fused after EOF or its first error. Dropping it permits an
/// early server response; the H2 owner stops the unread input after flushing
/// that response. A framing error already observed by this stream cannot be
/// hidden by a handler returning success.
pub struct RegisteredRequestStream {
    body: IncomingRequestBody,
    codec: FramedCodec<IdentityCodec>,
    buffered: BytesMut,
    pending: Option<BytesCursor>,
    initial_metadata: Metadata,
    pending_trailers: Option<Metadata>,
    terminal: Arc<parking_lot::Mutex<IngressTerminal>>,
    metadata_limit: usize,
    wire_limit: usize,
    wire_bytes: usize,
    compressed: bool,
    done: bool,
}

impl std::fmt::Debug for RegisteredRequestStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisteredRequestStream")
            .field("wire_bytes", &self.wire_bytes)
            .field("wire_limit", &self.wire_limit)
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

impl RegisteredRequestStream {
    /// Receive the next serialized message, without consuming a later message.
    /// Dropping this wait retains all partial framing in this stream owner.
    pub async fn message(&mut self) -> Result<Option<Bytes>, Status> {
        poll_fn(|cx| Pin::new(&mut *self).poll_next(cx))
            .await
            .transpose()
    }

    /// Snapshot trailers after validated request EOF. Before EOF, including
    /// after merely receiving a trailer frame, this returns `None`.
    #[must_use]
    pub fn trailers(&self) -> Option<Metadata> {
        self.terminal.lock().trailers.clone()
    }

    fn fail(&mut self, status: Status) -> Poll<Option<Result<Bytes, Status>>> {
        self.done = true;
        self.buffered.clear();
        self.pending = None;
        let mut terminal = self.terminal.lock();
        if terminal.failure.is_none() {
            terminal.failure = Some(status.clone());
        }
        Poll::Ready(Some(Err(status)))
    }

    fn decode_trailers(&self, fields: &HeaderMap) -> Result<Metadata, Status> {
        let mut trailers = Metadata::new();
        let mut names = BTreeSet::new();
        for (name, value) in fields.iter() {
            let name = name.as_str();
            if grpc_request_trailer_key_is_reserved(name)
                || !names.insert(name.to_ascii_lowercase())
                || self.initial_metadata.get(name).is_some()
            {
                return Err(Status::invalid_argument(
                    "reserved or duplicate gRPC request trailer metadata",
                ));
            }
            let value = value
                .to_str()
                .map_err(|_| Status::invalid_argument("non-ASCII gRPC request trailer"))?;
            insert_http2_metadata_entry(&mut trailers, name, value)?;
        }
        enforce_http2_metadata_blocks(&self.initial_metadata, &trailers, self.metadata_limit)?;
        Ok(trailers)
    }
}

impl Streaming for RegisteredRequestStream {
    type Message = Bytes;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Bytes, Status>>> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(None);
        }
        // Limit work even for a stream of empty DATA frames. A yielded turn
        // does not consume the message being assembled.
        for _ in 0..32 {
            if this.buffered.len() >= MESSAGE_HEADER_SIZE {
                if this.buffered[0] > 1 || (this.buffered[0] == 1 && !this.compressed) {
                    return this.fail(Status::invalid_argument(
                        "invalid or unnegotiated gRPC compressed flag",
                    ));
                }
                // The codec refuses the declared wire length before waiting
                // for its payload. A configured compression algorithm still
                // permits individual uncompressed messages per gRPC framing.
                match this.codec.decode_message(&mut this.buffered) {
                    Ok(Some(message)) => return Poll::Ready(Some(Ok(message))),
                    Ok(None) => {}
                    Err(error) => return this.fail(error.into_status()),
                }
            }
            if let Some(pending) = &mut this.pending {
                let target = if this.buffered.len() < MESSAGE_HEADER_SIZE {
                    MESSAGE_HEADER_SIZE
                } else {
                    let payload = u32::from_be_bytes([
                        this.buffered[1],
                        this.buffered[2],
                        this.buffered[3],
                        this.buffered[4],
                    ]);
                    let Some(target) = usize::try_from(payload)
                        .ok()
                        .and_then(|length| length.checked_add(MESSAGE_HEADER_SIZE))
                    else {
                        return this.fail(Status::resource_exhausted("gRPC frame length overflow"));
                    };
                    target
                };
                let take = target
                    .saturating_sub(this.buffered.len())
                    .min(pending.remaining());
                this.buffered.extend_from_slice(&pending.chunk()[..take]);
                pending.advance(take);
                if !pending.has_remaining() {
                    this.pending = None;
                }
                continue;
            }
            match Pin::new(&mut this.body).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(Frame::Data(data)))) => {
                    if this.pending_trailers.is_some() {
                        return this.fail(Status::invalid_argument("gRPC DATA follows trailers"));
                    }
                    let Some(total) = this
                        .wire_bytes
                        .checked_add(data.remaining())
                        .filter(|total| *total <= this.wire_limit)
                    else {
                        return this.fail(Status::resource_exhausted(
                            "gRPC request wire limit exceeded",
                        ));
                    };
                    this.wire_bytes = total;
                    this.pending = Some(data);
                }
                Poll::Ready(Some(Ok(Frame::Trailers(fields)))) => {
                    if this.pending_trailers.is_some() || !this.buffered.is_empty() {
                        return this.fail(Status::invalid_argument(
                            "truncated gRPC message before trailers",
                        ));
                    }
                    match this.decode_trailers(&fields) {
                        Ok(trailers) => this.pending_trailers = Some(trailers),
                        Err(status) => return this.fail(status),
                    }
                }
                Poll::Ready(Some(Err(error))) => return this.fail(body_status(error)),
                Poll::Ready(None) => {
                    if !this.buffered.is_empty() {
                        return this.fail(Status::invalid_argument(
                            "incomplete gRPC message at request EOF",
                        ));
                    }
                    this.done = true;
                    this.terminal.lock().trailers =
                        Some(this.pending_trailers.take().unwrap_or_default());
                    return Poll::Ready(None);
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

fn body_status(error: IncomingBodyError) -> Status {
    match error {
        IncomingBodyError::BodyTooLarge { .. }
        | IncomingBodyError::TrailersTooLarge
        | IncomingBodyError::AccountingOverflow
        | IncomingBodyError::QueueFrameTooLarge { .. } => {
            Status::resource_exhausted(error.to_string())
        }
        IncomingBodyError::Cancelled {
            kind: CancelKind::Timeout | CancelKind::Deadline,
        } => Status::deadline_exceeded("gRPC request deadline exceeded"),
        IncomingBodyError::Cancelled {
            kind: CancelKind::PollQuota | CancelKind::CostBudget,
        } => Status::resource_exhausted("gRPC request budget exhausted"),
        IncomingBodyError::Cancelled { .. } => Status::cancelled("gRPC request cancelled"),
        IncomingBodyError::ClientAborted | IncomingBodyError::SourceDisconnected => {
            Status::unavailable("gRPC request transport disconnected")
        }
        _ => Status::invalid_argument(error.to_string()),
    }
}

type DuplexFuture = Pin<Box<dyn Future<Output = Http2ProducedResponse> + Send + 'static>>;

impl Server {
    /// Bind all four registered RPC kinds with live input and bounded output.
    ///
    /// Drive the returned listener with `run_streaming_produced`. A response
    /// stream can own its request stream and produce messages before request
    /// EOF. HTTP/2 flow control bounds both directions independently. The same
    /// actual request child owns the handler, input, producer and descendants
    /// until response completion and region drain.
    ///
    /// Auth/request interceptors run once on a metadata envelope with an empty
    /// payload; they may add extensions and metadata, but cannot replace the
    /// streaming payload. Response interceptors see terminal trailers on an
    /// empty response. Application initial response metadata is not supported
    /// by this lane. Existing unary and server-streaming listeners are unchanged.
    /// One deadline captured when the admitted handler receives HEADERS covers input, handler setup,
    /// output polls and backpressure. Early handler completion stops unread input
    /// after response drain; an observed input error always prevents success.
    pub async fn bind_registered_duplex_http2<A>(
        self: &Arc<Self>,
        addr: A,
        host_policy: HostPolicy,
        config: ServerDuplexConfig,
    ) -> io::Result<
        Http2Listener<impl Fn(StreamingServerRequest) -> DuplexFuture + Send + Sync + 'static>,
    >
    where
        A: ToSocketAddrs + Send + 'static,
    {
        let (handler, input) = self.registered_duplex_handler(host_policy, config)?;
        Http2Listener::bind_streaming_produced_with_config(addr, handler, input)
            .await
            .map(|listener| self.with_http2_keepalive(listener))
    }

    /// [`Self::bind_registered_duplex_http2`] on a Unix-domain socket
    /// listener; drive it with `Http2Listener::run_streaming_produced`. See
    /// [`Server::bind_registered_http2_unix`] for the transport's terms.
    ///
    /// # Errors
    /// The same refusals as the TCP form, before any connection is accepted.
    #[cfg(unix)]
    pub fn bind_registered_duplex_http2_unix(
        self: &Arc<Self>,
        listener: crate::net::unix::UnixListener,
        host_policy: HostPolicy,
        config: ServerDuplexConfig,
    ) -> io::Result<
        Http2Listener<impl Fn(StreamingServerRequest) -> DuplexFuture + Send + Sync + 'static>,
    > {
        // The input configuration is checked when the listener starts running.
        let (handler, input) = self.registered_duplex_handler(host_policy, config)?;
        Ok(
            self.with_http2_keepalive(Http2Listener::from_unix_listener_streaming(
                listener, handler, input,
            )),
        )
    }

    fn registered_duplex_handler(
        self: &Arc<Self>,
        host_policy: HostPolicy,
        config: ServerDuplexConfig,
    ) -> io::Result<(
        impl Fn(StreamingServerRequest) -> DuplexFuture + Send + Sync + 'static,
        Http2StreamingListenerConfig,
    )> {
        config.response.validate()?;
        self.validate_http2_transport_config()?;
        self.streaming_output_codec(self.config.send_compression)
            .map_err(io::Error::other)?;
        if self.services.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no registered gRPC service",
            ));
        }
        let mut input = Http2StreamingListenerConfig::default();
        input.listener = self
            .http2_listener_config(host_policy)
            .max_body_size(config.max_request_wire_bytes);
        // Live request bodies are queued, so advertise no more stream credit
        // than the queue can hold. The server's default 1 MiB window would
        // otherwise exceed the default 65,535-byte queue and refuse the bind.
        let queue = u32::try_from(config.request_body_buffer_bytes.get()).unwrap_or(u32::MAX);
        input.listener.settings.initial_window_size =
            input.listener.settings.initial_window_size.min(queue);
        input.request_body_buffer_bytes = config.request_body_buffer_bytes;
        input.connection_request_body_buffer_bytes = config.connection_request_body_buffer_bytes;
        let server = Arc::clone(self);
        let handler = move |request: StreamingServerRequest| -> DuplexFuture {
            let server = Arc::clone(&server);
            let config = config.clone();
            Box::pin(async move { server.dispatch_http2_duplex(request, config).await })
        };
        Ok((handler, input))
    }

    /// Bind and run the native registered duplex listener through shutdown.
    pub async fn serve_duplex_http2<A>(
        self: &Arc<Self>,
        runtime: &RuntimeHandle,
        addr: A,
        host_policy: HostPolicy,
        config: ServerDuplexConfig,
    ) -> io::Result<ShutdownStats>
    where
        A: ToSocketAddrs + Send + 'static,
    {
        self.bind_registered_duplex_http2(addr, host_policy, config)
            .await?
            .run_streaming_produced(runtime)
            .await
    }

    fn resolve_duplex_method(
        &self,
        path: &str,
    ) -> Result<(Arc<dyn ServiceHandler>, bool, bool), Status> {
        let (service_name, name) = path
            .strip_prefix('/')
            .and_then(|route| route.split_once('/'))
            .filter(|(service, name)| {
                !service.is_empty() && !name.is_empty() && !name.contains('/')
            })
            .ok_or_else(|| Status::unimplemented("invalid registered gRPC method path"))?;
        let service = self
            .services
            .get(service_name)
            .ok_or_else(|| Status::unimplemented("gRPC service is not registered"))?;
        let ServiceDescriptor { methods, .. } = service.descriptor();
        let method = methods
            .iter()
            .find(|method| method.path == path && method.name == name)
            .ok_or_else(|| Status::unimplemented("gRPC method is not registered"))?;
        Ok((
            Arc::clone(service),
            method.client_streaming,
            method.server_streaming,
        ))
    }

    fn decode_live_request(
        &self,
        request: StreamingServerRequest,
        wire_limit: usize,
    ) -> Result<(String, Request<RegisteredRequestStream>), Status> {
        if request.head.method != Method::Post {
            return Err(Status::invalid_argument("gRPC over HTTP/2 requires POST"));
        }
        let mut metadata = Metadata::new();
        let mut content_type = None;
        let mut encoding = CompressionEncoding::Identity;
        let mut names = BTreeSet::new();
        for (name, value) in &request.head.headers {
            // Repeated metadata (grpc-go's metadata.Pairs, split cookies) is
            // legal, and the unary lane accepts it. Only fields that must have
            // a single value are refused when repeated.
            let single_valued = ["content-type", "grpc-encoding", "grpc-timeout", "te"]
                .iter()
                .any(|key| name.eq_ignore_ascii_case(key));
            if single_valued && !names.insert(name.to_ascii_lowercase()) {
                return Err(Status::invalid_argument(
                    "duplicate gRPC initial metadata key",
                ));
            }
            if name.eq_ignore_ascii_case("content-type") {
                content_type = Some(value.as_str());
            }
            if name.eq_ignore_ascii_case("grpc-encoding") {
                encoding = CompressionEncoding::from_header_value(value)
                    .ok_or_else(|| Status::unimplemented("unsupported gRPC request compression"))?;
            }
            insert_http2_metadata_entry(&mut metadata, name, value)?;
        }
        if !content_type.is_some_and(grpc_content_type_is_allowed) {
            return Err(Status::invalid_argument(
                "missing or invalid gRPC content-type",
            ));
        }
        enforce_http2_metadata_blocks(&metadata, &Metadata::new(), self.config.max_metadata_size)?;
        if !self.config.accept_compression.contains(&encoding) {
            return Err(Status::unimplemented(
                "gRPC request compression is not accepted",
            ));
        }
        let mut codec = self.framed_codec(IdentityCodec);
        if encoding != CompressionEncoding::Identity {
            let decompressor = encoding.frame_decompressor().ok_or_else(|| {
                Status::unimplemented("gRPC request compression is not compiled in")
            })?;
            codec = codec.with_frame_hooks(None, Some(decompressor));
        }
        let stream = RegisteredRequestStream {
            body: request.body,
            codec,
            buffered: BytesMut::new(),
            pending: None,
            initial_metadata: metadata.clone(),
            pending_trailers: None,
            terminal: Arc::new(parking_lot::Mutex::new(IngressTerminal::default())),
            metadata_limit: self.config.max_metadata_size,
            wire_limit,
            wire_bytes: 0,
            compressed: encoding != CompressionEncoding::Identity,
            done: false,
        };
        Ok((request.head.uri, Request::with_metadata(stream, metadata)))
    }

    async fn dispatch_http2_duplex(
        self: Arc<Self>,
        request: StreamingServerRequest,
        config: ServerDuplexConfig,
    ) -> Http2ProducedResponse {
        let resolved = self.resolve_duplex_method(&request.head.uri);
        let (service, client_streaming, server_streaming) = match resolved {
            Ok(method) => method,
            Err(status) => {
                return Http2ProducedResponse::buffered(Self::http2_status_response(&status));
            }
        };
        let (path, request) = match self.decode_live_request(request, config.max_request_wire_bytes)
        {
            Ok(request) => request,
            Err(status) => {
                return Http2ProducedResponse::buffered(Self::http2_status_response(&status));
            }
        };
        let Some(cx) = Cx::current() else {
            return Http2ProducedResponse::buffered(Self::http2_status_response(
                &Status::internal("gRPC duplex requires a runtime context"),
            ));
        };
        let deadline = StreamDeadline::capture(&cx, request.metadata(), &self.config);
        // Attenuate the actual scheduler-admitted child in place. Every clone
        // held by its input and future descendants sees this budget, while
        // task identity, spawn gateway, cancellation and pending-spawn counter
        // remain attached to the same owned region.
        {
            let mut inner = cx.inner.write();
            inner.budget = deadline.budget(inner.budget);
        }
        let compression = self.response_compression(request.metadata());
        let (codec, encoding) = match self.streaming_output_codec(compression) {
            Ok(codec) => codec,
            Err(status) => {
                return Http2ProducedResponse::buffered(Self::http2_status_response(&status));
            }
        };
        let mut head = HttpResponse::new(200, "OK", Vec::new())
            .with_header("content-type", "application/grpc");
        if let Some(encoding) = encoding {
            head.headers
                .push(("grpc-encoding".to_owned(), encoding.to_owned()));
        }
        Http2ProducedResponse::streaming(
            head,
            config.response.frame_capacity,
            config.response.max_frame_bytes,
            move |cx, sender| async move {
                self.run_duplex(
                    cx,
                    sender,
                    service,
                    path,
                    request,
                    client_streaming,
                    server_streaming,
                    codec,
                    config.response,
                    deadline,
                )
                .await
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_duplex(
        self: Arc<Self>,
        cx: Cx,
        mut sender: Http2BodySender,
        service: Arc<dyn ServiceHandler>,
        path: String,
        request: Request<RegisteredRequestStream>,
        client_streaming: bool,
        server_streaming: bool,
        codec: FramedCodec<IdentityCodec>,
        config: ServerStreamingConfig,
        deadline: StreamDeadline,
    ) -> Result<Http2BodySender, HttpError> {
        let terminal = Arc::clone(&request.get_ref().terminal);
        let envelope = request.snapshot(Bytes::new());
        let mut input = request.into_inner();
        let owner = cx.clone();
        let mut partial = false;
        let mut failure = None;
        let output = &mut sender;
        let partial_frame = &mut partial;
        let transport_error = &mut failure;
        let call_deadline = &deadline;
        let input_terminal = Arc::clone(&terminal);
        let dispatch = self.dispatch_intercepted(
            envelope,
            move |request| async move {
                if !request.get_ref().is_empty() {
                    return Err(Status::internal(
                        "interceptor replaced a live gRPC request payload",
                    ));
                }
                let call_cx = owner.clone();
                let stream = poll_cancellable(
                    &owner,
                    &call_cx,
                    async {
                        if client_streaming {
                            let request = request.map(|_| input);
                            if server_streaming {
                                service
                                    .call_bidirectional_streaming(&call_cx, &path, request)
                                    .await
                            } else {
                                let response = service
                                    .call_client_streaming(&call_cx, &path, request)
                                    .await?;
                                single_response(response)
                            }
                        } else {
                            let message = input.message().await?.ok_or_else(|| {
                                Status::invalid_argument("unary-input RPC contains no message")
                            })?;
                            if input.message().await?.is_some() {
                                return Err(Status::invalid_argument(
                                    "unary-input RPC contains multiple messages",
                                ));
                            }
                            let trailers = input.trailers().unwrap_or_default();
                            let request = request.map(|_| message);
                            if server_streaming {
                                service
                                    .call_server_streaming(&call_cx, &path, request, trailers)
                                    .await
                            } else {
                                single_response(
                                    service
                                        .call_unary(&call_cx, &path, request, trailers)
                                        .await?,
                                )
                            }
                        }
                    },
                    Some(call_deadline),
                )
                .await??;
                if let Some(status) = input_terminal.lock().failure.clone() {
                    return Err(status);
                }
                let result = forward_messages(
                    &owner,
                    &call_cx,
                    stream,
                    codec,
                    output,
                    partial_frame,
                    transport_error,
                    config.max_frame_bytes.get(),
                    call_deadline,
                )
                .await;
                if let Some(status) = input_terminal.lock().failure.clone() {
                    return Err(status);
                }
                result
            },
            true,
        );
        let operation = super::poll_with_current_cx(cx.clone(), dispatch);
        let outcome = match crate::util::future::catch_unwind(std::panic::AssertUnwindSafe(
            operation,
        ))
        .await
        {
            Ok(result) => result,
            Err(_) => Err(Status::internal("gRPC duplex handler or stream panicked")),
        };
        // Read the ingress failure only after the operation that records it
        // has finished; an observed input error outranks the handler result.
        let observed_failure = terminal.lock().failure.clone();
        let mut result = observed_failure.map_or(outcome, Err);
        if result.is_ok() && deadline.expired() {
            cx.cancel_with(CancelKind::Timeout, Some("gRPC duplex deadline exceeded"));
            result = Err(Status::deadline_exceeded("gRPC duplex deadline exceeded"));
        }
        if let Some(error) = failure {
            return Err(error);
        }
        if partial {
            return Err(HttpError::Io(io::Error::new(
                io::ErrorKind::Interrupted,
                "gRPC response stopped inside a message frame",
            )));
        }
        let trailers = bounded_terminal_trailers(result, config.max_trailer_bytes);
        send_terminal(&cx, &mut sender, trailers, config.terminal_timeout).await?;
        Ok(sender)
    }
}

/// Only terminal protocol cleanup is masked, one synchronous channel poll at
/// a time. The independent bounded timer stays active after the actual request
/// Cx is cancelled. User work is already retired; H2 retains and closes its
/// child region before publishing producer completion.
async fn send_terminal(
    cx: &Cx,
    sender: &mut Http2BodySender,
    trailers: HeaderMap,
    timeout: Duration,
) -> Result<(), HttpError> {
    let clock = cx.timer_driver().ok_or_else(|| {
        HttpError::Io(io::Error::other(
            "native gRPC terminal drain requires a timer driver",
        ))
    })?;
    let at = clock.now() + timeout;
    let mut timer = ServerRequestDeadline::new(clock.clone(), at);
    let mut send = std::pin::pin!(sender.send_trailers(cx, trailers));
    poll_fn(|task| {
        if clock.now() >= at || Pin::new(&mut timer).poll(task).is_ready() {
            return Poll::Ready(Err(HttpError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "gRPC duplex terminal trailer delivery timed out",
            ))));
        }
        cx.masked(|| send.as_mut().poll(task))
    })
    .await
}

fn single_response(response: Response<Bytes>) -> Result<RegisteredServerStream, Status> {
    let trailers = response.metadata().clone();
    let mut stream = StreamingRequest::open();
    stream.push(response.into_inner())?;
    stream.close();
    Ok(RegisteredServerStream::new(stream).with_trailers(trailers))
}

#[cfg(test)]
mod tests;
