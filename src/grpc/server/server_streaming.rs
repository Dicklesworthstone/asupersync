//! Registered unary-input/server-streaming RPCs on the native H2 producer lane.
//!
//! This is an additive transport lane: existing unary bind/serve methods retain
//! their signatures and behavior. Client-streaming and bidi methods are refused.
//! Application initial metadata is not supported by this lane; application
//! trailers are explicit on `RegisteredServerStream`.

use super::{
    Bytes, BytesMut, CallContext, CompressionEncoding, Cx, FramedCodec, GrpcError, HostPolicy,
    Http2Listener, HttpRequest, HttpResponse, Metadata, Response, RuntimeHandle,
    Server, ServerConfig, ServiceHandler, ShutdownStats, Status,
    grpc_request_trailer_key_is_reserved,
};
use crate::grpc::codec::IdentityCodec;
use crate::grpc::service::RegisteredServerStream;
use crate::grpc::status::Code;
use crate::grpc::streaming::{MetadataValue, Request};
use crate::http::body::{HeaderMap, HeaderName, HeaderValue};
use crate::http::h1::HttpError;
use crate::http::h2::listener::{Http2BodySender, Http2ProducedResponse};
use crate::time::{Sleep, TimerDriverHandle};
use crate::types::{Budget, CancelKind, Time};
use crate::web::request_region::{RequestBudgetSource, ServerRequestRegion};
use base64::Engine as _;
use std::future::{Future, poll_fn};
use std::io;
use std::net::ToSocketAddrs;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};

/// Explicit transport-retention and terminal-delivery bounds for server streams.
#[derive(Debug, Clone, Copy)]
pub struct ServerStreamingConfig {
    /// Frames retained in the H2 producer channel, independently of peer credit.
    pub frame_capacity: NonZeroUsize,
    /// Maximum DATA bytes in a producer frame. Larger gRPC messages are split.
    pub max_frame_bytes: NonZeroUsize,
    /// Maximum sum of trailer field-name and encoded field-value bytes.
    ///
    /// Includes status/message/details. Must be at least 13, enough for any
    /// bare gRPC status code. This is not an HPACK allocation bound.
    pub max_trailer_bytes: usize,
    /// Additional bounded grace for queuing terminal trailers after the call.
    /// Bounds queueing, not subsequent wire drain or acknowledgement; those
    /// remain subject to the H2 transport's own shutdown and timeout policy.
    /// Queueing a trailer is not an acknowledgement that the peer received it.
    pub terminal_timeout: Duration,
}

impl ServerStreamingConfig {
    fn validate(self) -> io::Result<()> {
        if self
            .frame_capacity
            .get()
            .checked_mul(self.max_frame_bytes.get())
            .is_none()
            || self.max_trailer_bytes < 13
            || self.terminal_timeout.is_zero()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid gRPC streaming buffer, trailer, or terminal-timeout bound",
            ));
        }
        Ok(())
    }
}

type ProducedGrpcFuture =
    Pin<Box<dyn Future<Output = Http2ProducedResponse> + Send + 'static>>;

/// Freeze the request's absolute deadline before it waits for producer admission.
/// Keep its clock with it: a later task-local context must not change time domains.
struct StreamDeadline {
    at: Option<Time>,
    clock: Option<TimerDriverHandle>,
    source: RequestBudgetSource,
}

impl StreamDeadline {
    fn capture(cx: &Cx, metadata: &Metadata, config: &ServerConfig) -> Self {
        let clock = cx.timer_driver();
        let now = clock
            .as_ref()
            .map_or_else(crate::time::wall_now, TimerDriverHandle::now);
        let wall_now = Instant::now();
        // Reuse the established parser, malformed-header fallback, and cap
        // policy rather than maintaining a second grpc-timeout interpretation.
        let context = CallContext::from_metadata_at_with_max_deadline(
            metadata.clone(),
            config.default_timeout,
            config.max_request_deadline,
            None,
            wall_now,
        );
        let call_deadline = context
            .deadline()
            .map(|_| now + context.remaining_at(wall_now).unwrap_or(Duration::ZERO));
        let source = if super::grpc_timeout_from_metadata(metadata).is_some() {
            RequestBudgetSource::HeaderClamped
        } else if config.default_timeout.is_some() {
            RequestBudgetSource::ServerConfig
        } else {
            RequestBudgetSource::Inherited
        };
        Self {
            at: earlier_deadline(cx.budget().deadline, call_deadline),
            clock,
            source,
        }
    }

    fn now(&self) -> Time {
        self.clock
            .as_ref()
            .map_or_else(crate::time::wall_now, TimerDriverHandle::now)
    }

    fn expired(&self) -> bool {
        self.at.is_some_and(|at| self.now() >= at)
    }

    fn budget(&self, mut inherited: Budget) -> Budget {
        inherited.deadline = earlier_deadline(inherited.deadline, self.at);
        inherited
    }

    fn timer(&self) -> Option<Sleep> {
        self.at.map(|at| match &self.clock {
            Some(clock) => Sleep::with_timer_driver(at, clock.clone()),
            None => crate::time::sleep_until(at),
        })
    }
}

fn earlier_deadline(first: Option<Time>, second: Option<Time>) -> Option<Time> {
    match (first, second) {
        (Some(first), Some(second)) => Some(first.min(second)),
        (Some(at), None) | (None, Some(at)) => Some(at),
        (None, None) => None,
    }
}

impl Server {
    /// Bind registered unary and server-streaming methods to native HTTP/2.
    ///
    /// Drive the returned listener with `Http2Listener::run_produced`, not
    /// `run`. Unary calls delegate to the existing registered-unary pipeline.
    /// Streaming calls invoke `ServiceHandler::call_server_streaming` only
    /// inside the H2 response producer's live request context.
    ///
    /// Request/auth interceptors run once. The existing deadline wrapper covers
    /// factory setup, every stream poll, and all DATA backpressure waits; it is
    /// not restarted per message. On successful completion response interceptors
    /// receive an empty-message response containing the **terminal trailers**.
    /// Adding a body there is rejected rather than silently ignored. Error hooks
    /// retain the existing dispatch pipeline's behavior.
    /// The absolute call deadline is captured when the decoded request reaches
    /// this adapter. Waiting for producer admission cannot restart that budget.
    /// Earlier request-header/body reception remains the H2 listener's policy.
    ///
    /// The source is pulled one message at a time. H2 drains the bounded channel
    /// only with peer credit. At most the configured channel, one connection
    /// frame, and one encoded message can be ahead of credit, plus existing codec
    /// buffering. This is bounded prefetch, not zero-prefetch credit admission.
    /// Memory already owned by the application stream is outside that bound.
    ///
    /// A terminal status follows only complete gRPC frames. Cancellation during
    /// a partially queued message fails the H2 producer instead of pretending
    /// that truncated framing is a clean gRPC completion. Source destruction
    /// retires local captures; independently spawned tasks remain region-owned.
    /// Factory, poll and terminal-destruction panics become gRPC `INTERNAL`
    /// only at a complete-message boundary; uncertain partial framing still
    /// fails the H2 producer. The process's panic hook is not changed.
    ///
    /// # Errors
    /// Invalid transport or streaming limits and unavailable compression refuse
    /// before binding. Otherwise returns the listener's original bind error.
    pub async fn bind_registered_streaming_http2<A>(
        self: &Arc<Self>,
        addr: A,
        host_policy: HostPolicy,
        streaming: ServerStreamingConfig,
    ) -> io::Result<
        Http2Listener<impl Fn(HttpRequest) -> ProducedGrpcFuture + Send + Sync + 'static>,
    >
    where
        A: ToSocketAddrs + Send + 'static,
    {
        streaming.validate()?;
        self.validate_http2_transport_config()?;
        if self.services.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no registered gRPC service",
            ));
        }
        self.streaming_output_codec().map_err(io::Error::other)?;
        let server = Arc::clone(self);
        let handler = move |request: HttpRequest| -> ProducedGrpcFuture {
            let server = Arc::clone(&server);
            Box::pin(async move { server.dispatch_http2_streaming(request, streaming).await })
        };
        Http2Listener::bind_produced_with_config(
            addr,
            handler,
            self.http2_listener_config(host_policy),
        )
        .await
    }

    /// Bind and run the mixed unary/server-streaming registered-service lane.
    ///
    /// # Errors
    /// Retains setup, bind and accept-loop errors from the native listener.
    pub async fn serve_streaming_http2<A>(
        self: &Arc<Self>,
        runtime: &RuntimeHandle,
        addr: A,
        host_policy: HostPolicy,
        streaming: ServerStreamingConfig,
    ) -> io::Result<ShutdownStats>
    where
        A: ToSocketAddrs + Send + 'static,
    {
        self.bind_registered_streaming_http2(addr, host_policy, streaming)
            .await?
            .run_produced(runtime)
            .await
    }

    fn resolve_registered_server_stream(
        &self,
        path: &str,
    ) -> Result<Arc<dyn ServiceHandler>, Status> {
        let (name, method_name) = path
            .strip_prefix('/')
            .and_then(|route| route.split_once('/'))
            .filter(|(name, method)| !name.is_empty() && !method.is_empty() && !method.contains('/'))
            .ok_or_else(|| Status::unimplemented("invalid registered gRPC method path"))?;
        let service = self
            .services
            .get(name)
            .ok_or_else(|| Status::unimplemented("gRPC service is not registered"))?;
        let method = service
            .descriptor()
            .methods
            .iter()
            .find(|method| method.path == path && method.name == method_name)
            .ok_or_else(|| Status::unimplemented("gRPC method is not registered"))?;
        if method.client_streaming || !method.server_streaming {
            return Err(Status::unimplemented(
                "method is not a unary-input server stream",
            ));
        }
        Ok(Arc::clone(service))
    }

    async fn dispatch_http2_streaming(
        self: Arc<Self>,
        request: HttpRequest,
        config: ServerStreamingConfig,
    ) -> Http2ProducedResponse {
        if self.resolve_registered_unary(&request.uri).is_ok() {
            return Http2ProducedResponse::buffered(
                self.dispatch_http2_registered_unary(request).await,
            );
        }
        let service = match self.resolve_registered_server_stream(&request.uri) {
            Ok(service) => service,
            Err(status) => {
                return Http2ProducedResponse::buffered(Self::http2_status_response(&status));
            }
        };
        let (path, request, trailers) = match self.decode_http2_unary_request(request) {
            Ok(request) => request,
            Err(status) => {
                return Http2ProducedResponse::buffered(Self::http2_status_response(&status));
            }
        };
        let Some(request_cx) = Cx::current() else {
            return Http2ProducedResponse::buffered(Self::http2_status_response(
                &Status::internal("gRPC server streaming requires a runtime context"),
            ));
        };
        let deadline = StreamDeadline::capture(&request_cx, request.metadata(), &self.config);
        let (codec, encoding) = match self.streaming_output_codec() {
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
        // Do not call user code or create its stream here. The handler context
        // is retired before H2 starts the distinct response-producer context.
        Http2ProducedResponse::streaming(
            head,
            config.frame_capacity,
            config.max_frame_bytes,
            move |cx, sender| async move {
                self.run_registered_server_stream(
                    cx, sender, service, path, request, trailers, codec, config, deadline,
                )
                .await
            },
        )
    }

    fn streaming_output_codec(
        &self,
    ) -> Result<(FramedCodec<IdentityCodec>, Option<&'static str>), Status> {
        let mut codec = self.framed_codec(IdentityCodec);
        let encoding = match self.config.send_compression {
            Some(CompressionEncoding::Gzip) => {
                let compressor = CompressionEncoding::Gzip
                    .frame_compressor()
                    .ok_or_else(|| Status::unimplemented("response compression is not compiled in"))?;
                codec = codec.with_frame_hooks(Some(compressor), None);
                Some("gzip")
            }
            Some(CompressionEncoding::Identity) | None => None,
        };
        Ok((codec, encoding))
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_registered_server_stream(
        self: Arc<Self>,
        cx: Cx,
        mut sender: Http2BodySender,
        service: Arc<dyn ServiceHandler>,
        path: String,
        request: Request<Bytes>,
        trailers: Metadata,
        codec: FramedCodec<IdentityCodec>,
        config: ServerStreamingConfig,
        deadline: StreamDeadline,
    ) -> Result<Http2BodySender, HttpError> {
        // Only the live producer supplies cancellation/spawn authority. The
        // earlier handler contributed a deadline, never an escaped request Cx.
        // Tighten before canonical dispatch creates its own per-call context,
        // so even service code inspecting Cx::budget sees the admission delay.
        let region = ServerRequestRegion::mint_from_connection(
            "h2-grpc-stream",
            deadline.budget(cx.budget()),
            deadline.now(),
            &cx,
        );
        let mut partial_frame = false;
        let mut transport_error = None;
        let owner = cx.clone();
        let output = &mut sender;
        let partial = &mut partial_frame;
        let failure = &mut transport_error;
        let call_deadline = &deadline;
        let dispatch = self.dispatch_unary(request, move |request| async move {
            let call_cx = Cx::current().unwrap_or_else(|| owner.clone());
            let stream = poll_cancellable(
                &owner,
                &call_cx,
                async {
                    service
                        .call_server_streaming(&call_cx, &path, request, trailers)
                        .await
                },
                Some(call_deadline),
            )
            .await??;
            forward_messages(
                &owner,
                &call_cx,
                stream,
                codec,
                output,
                partial,
                failure,
                config.max_frame_bytes.get(),
                call_deadline,
            )
            .await
        });
        let source = region.instrumented(deadline.source, dispatch);
        // Catch both user polling and terminal destruction. Catching only the
        // H2 producer outside this adapter loses gRPC INTERNAL attribution.
        let mut result = match crate::util::future::catch_unwind(std::panic::AssertUnwindSafe(source))
            .await
        {
            Ok(result) => result,
            Err(_payload) => {
                cx.trace("grpc.server_stream.panicked");
                Err(Status::internal("gRPC server stream panicked"))
            }
        };
        // A synchronous response interceptor may have used the remaining time.
        // Do not accept its late success merely because no further await ran.
        if result.is_ok() && deadline.expired() {
            region.cancel_timeout("gRPC streaming deadline exceeded");
            result = Err(Status::deadline_exceeded("gRPC stream deadline exceeded"));
        }
        region.finish(if result.is_ok() { "ok" } else { "err" });
        if let Some(error) = transport_error {
            return Err(error); // Preserve the actual transport failure.
        }
        if partial_frame {
            return Err(HttpError::Io(io::Error::new(
                io::ErrorKind::Interrupted,
                "gRPC response interrupted while queuing a message frame",
            )));
        }
        let trailers = bounded_terminal_trailers(result, config.max_trailer_bytes);
        match crate::time::timeout(
            config.terminal_timeout,
            sender.send_trailers(&cx, trailers),
        )
        .await
        {
            Ok(Ok(())) => Ok(sender),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(HttpError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "gRPC terminal trailer delivery timed out",
            ))),
        }
    }
}

fn cancellation_status(cx: &Cx) -> Status {
    match cx.cancel_reason().map(|reason| reason.kind) {
        Some(CancelKind::Timeout | CancelKind::Deadline) => {
            Status::deadline_exceeded("gRPC stream deadline exceeded")
        }
        Some(CancelKind::PollQuota | CancelKind::CostBudget) => {
            Status::resource_exhausted("gRPC stream budget exhausted")
        }
        _ => Status::cancelled("gRPC stream cancelled"),
    }
}

async fn poll_cancellable<F: Future>(
    owner: &Cx,
    call: &Cx,
    future: F,
    deadline: Option<&StreamDeadline>,
) -> Result<F::Output, Status> {
    let mut owner_cancelled = std::pin::pin!(owner.cancelled());
    let mut call_cancelled = std::pin::pin!(call.cancelled());
    let mut future = std::pin::pin!(future);
    let mut deadline_timer = std::pin::pin!(deadline.and_then(StreamDeadline::timer));
    poll_fn(|task_cx| {
        if owner.checkpoint().is_err() || owner_cancelled.as_mut().poll(task_cx).is_ready() {
            // The contexts can alias on the no-deadline path. Snapshot the
            // attribution before propagation and never replace a deadline or
            // budget cause with a generic parent-cancel cause.
            let status = cancellation_status(owner);
            let kind = owner
                .cancel_reason()
                .map_or(CancelKind::ParentCancelled, |reason| reason.kind);
            call.cancel_with(kind, Some("gRPC response owner cancelled"));
            return Poll::Ready(Err(status));
        }
        if call.checkpoint().is_err() || call_cancelled.as_mut().poll(task_cx).is_ready() {
            return Poll::Ready(Err(cancellation_status(call)));
        }
        if deadline.is_some_and(StreamDeadline::expired)
            || deadline_timer
                .as_mut()
                .as_pin_mut()
                .is_some_and(|timer| timer.poll(task_cx).is_ready())
        {
            call.cancel_with(CancelKind::Timeout, Some("gRPC streaming deadline exceeded"));
            return Poll::Ready(Err(Status::deadline_exceeded(
                "gRPC stream deadline exceeded",
            )));
        }
        future.as_mut().poll(task_cx).map(Ok)
    })
    .await
}

#[allow(clippy::too_many_arguments)]
async fn forward_messages(
    owner: &Cx,
    cx: &Cx,
    stream: RegisteredServerStream,
    mut codec: FramedCodec<IdentityCodec>,
    sender: &mut Http2BodySender,
    partial_frame: &mut bool,
    transport_error: &mut Option<HttpError>,
    max_frame_bytes: usize,
    deadline: &StreamDeadline,
) -> Result<Response<Bytes>, Status> {
    let (mut stream, trailers) = stream.into_parts();
    let mut messages_this_turn = 0;
    loop {
        let next = poll_cancellable(
            owner,
            cx,
            poll_fn(|task_cx| stream.as_mut().poll_next(task_cx)),
            Some(deadline),
        )
        .await?;
        let Some(message) = next else {
            break;
        };
        let message = message?;
        let mut frame = BytesMut::new();
        codec
            .encode_message(&message, &mut frame)
            .map_err(GrpcError::into_status)?;
        drop(message);
        // The frame is complete in memory before sending any prefix. If an
        // enclosing deadline drops this future between chunks, the owner sees
        // this latch and refuses to append status trailers to truncated framing.
        *partial_frame = true;
        for chunk in frame.chunks(max_frame_bytes) {
            match poll_cancellable(owner, cx, sender.send_chunk(cx, chunk), Some(deadline)).await? {
                Ok(()) => {}
                Err(error) => {
                    *transport_error = Some(error);
                    return Err(Status::unavailable("HTTP/2 response body transport failed"));
                }
            }
        }
        *partial_frame = false;
        messages_this_turn += 1;
        if messages_this_turn == 32 {
            crate::runtime::yield_now().await;
            messages_this_turn = 0;
        }
    }
    drop(stream); // No successful terminal status before stream destruction.
    Ok(Response::with_metadata(Bytes::new(), trailers))
}

fn append_header(headers: &mut HeaderMap, name: &str, value: String) {
    headers.append(
        HeaderName::from_string(name),
        HeaderValue::from_string(value),
    );
}

fn bare_status(code: Code) -> HeaderMap {
    let mut headers = HeaderMap::new();
    append_header(&mut headers, "grpc-status", code.as_i32().to_string());
    headers
}

fn base64_len(bytes: usize) -> Option<usize> {
    bytes
        .checked_div(3)?
        .checked_mul(4)?
        .checked_add(match bytes % 3 {
            0 => 0,
            1 => 2,
            _ => 3,
        })
}

fn encoded_metadata_len(metadata: &Metadata) -> Option<usize> {
    let mut total = 0usize;
    for (name, value) in metadata.iter() {
        let length = match value {
            MetadataValue::Ascii(value) => value.len(),
            MetadataValue::Binary(value) => base64_len(value.len())?,
        };
        total = total.checked_add(name.len())?.checked_add(length)?;
    }
    Some(total)
}

fn bounded_terminal_trailers(result: Result<Response<Bytes>, Status>, limit: usize) -> HeaderMap {
    match result {
        Ok(response) => {
            if !response.get_ref().is_empty() {
                return bare_status(Code::Internal);
            }
            if response
                .metadata()
                .iter()
                .any(|(name, _)| grpc_request_trailer_key_is_reserved(name))
            {
                return bare_status(Code::Internal);
            }
            if encoded_metadata_len(response.metadata())
                .and_then(|bytes| bytes.checked_add(12))
                .is_none_or(|bytes| bytes > limit)
            {
                return bare_status(Code::ResourceExhausted);
            }
            let mut headers = HeaderMap::new();
            for (name, value) in response.metadata().iter() {
                let value = match value {
                    MetadataValue::Ascii(value) => value.clone(),
                    MetadataValue::Binary(value) => {
                        base64::engine::general_purpose::STANDARD_NO_PAD.encode(value)
                    }
                };
                append_header(&mut headers, name, value);
            }
            append_header(&mut headers, "grpc-status", "0".to_owned());
            headers
        }
        Err(status) => {
            if status.code() == Code::Ok {
                return bare_status(Code::Internal);
            }
            // Bound expansion BEFORE percent/base64 encoding or allocating the
            // transport header block. Conservative sizing is intentional.
            let message = status.message().len().checked_mul(3).and_then(|bytes| {
                bytes.checked_add(if status.message().is_empty() { 0 } else { 12 })
            });
            let details = status.details().map_or(Some(0), |details| {
                base64_len(details.len()).and_then(|bytes| bytes.checked_add(23))
            });
            if message
                .zip(details)
                .and_then(|(message, details)| message.checked_add(details))
                .and_then(|bytes| bytes.checked_add(13))
                .is_none_or(|bytes| bytes > limit)
            {
                return bare_status(Code::ResourceExhausted);
            }
            let mut headers = HeaderMap::new();
            for (name, value) in Server::http2_status_response(&status).trailers {
                append_header(&mut headers, &name, value);
            }
            headers
        }
    }
}

#[cfg(test)]
mod tests;
