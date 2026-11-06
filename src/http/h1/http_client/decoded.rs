//! Explicit progressive decoding with pool admission held through validation.

use super::{
    ClientError, ClientRequestBuilder, HttpClient, Method, ParsedUrl,
    PooledClientIncomingBody, PooledClientStreamingResponse, PooledStreamDeadline,
    PooledStreamOwner, cancellation_reported_as_cancelled, check_cx, has_header,
};
use crate::Cx;
use crate::bytes::BytesCursor;
use crate::http::body::{Body, ContentDecodeError, ContentDecodeLimits, ContentDecodedBody, Frame, SizeHint};
use crate::http::decode::{ContentDecodePlan, ContentDecoder, declared_empty, invalidated_field};
use crate::http::h1::codec::HttpError;
use crate::http::h1::stream::ResponseHead;
use parking_lot::Mutex;
use std::fmt;
use std::future::{Future, poll_fn};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

const STREAM_CODINGS: &str = if cfg!(feature = "compression") {
    if cfg!(feature = "zstd") { "gzip, deflate, br, zstd" } else { "gzip, deflate, br" }
} else if cfg!(feature = "zstd") {
    "zstd"
} else {
    "identity"
};

/// A progressively decoded response retaining pool admission until validation.
///
/// `head` describes the decoded representation: after a non-identity transform,
/// encoded Content-Length, Content-Encoding, and payload digests are removed.
/// Origin cache validators remain unchanged. HEAD, successful CONNECT, and
/// bodyless statuses preserve their representation metadata. Encoded partial
/// responses are refused before returning the head.
///
/// Data remains provisional until successful body completion. A checksum,
/// truncated stream, resource refusal, source error, or cancellation can follow
/// earlier chunks. The body holds the original absolute request deadline and
/// pool admission through decoder finalization and releases a reusable socket
/// only after successful completion. Drop or failure closes an owned socket;
/// there is no background reader or abandoned-response drain task.
#[derive(Debug)]
#[non_exhaustive]
pub struct DecodedClientStreamingResponse {
    /// Final response status and representation headers.
    pub head: ResponseHead,
    /// Decoded frames and sanitized terminal trailers.
    pub body: DecodedClientIncomingBody,
    /// Whether the peer withheld or interrupted the upload; never reusable.
    pub body_withheld: bool,
}

/// A decoded HTTP/1 response with one owner for transport and pool retirement.
///
/// Limits count encoded input and every decoded stage independently. The
/// client's receive-body limit still applies. See [`ContentDecodeLimits`] for
/// codec working storage: a small returned frame does not imply a small pending
/// expansion buffer. Trailers follow successful decoder finalization; receiving
/// a trailer frame or `None` marks successful completion and releases admission.
///
/// Terminal failures retain typed [`ContentDecodeError`] causes. Cancellation
/// and the original request timeout appear as `Body(ClientError::Cancelled)`
/// and `Body(ClientError::DeadlineExceeded)`, including while decoded output is
/// queued. A source-side receive limit remains a typed HTTP body error. After
/// any terminal result, subsequent polls return `None`.
#[must_use = "consume or drop the body to retire its connection admission"]
pub struct DecodedClientIncomingBody {
    decoder: Option<ContentDecodedBody<RetainedEncodedBody>>,
    completed: CompletedBody,
    owner: PooledStreamOwner,
}

impl fmt::Debug for DecodedClientIncomingBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecodedClientIncomingBody")
            .field("complete", &self.decoder.is_none())
            .finish_non_exhaustive()
    }
}

// Exactly one terminal handoff, not a frame queue. The decoder deliberately
// drops its source at encoded EOF; retain that source's pool lease here until
// the *decoded* EOF/checksum verdict. No lock is taken on ordinary data polls.
type CompletedBody = Arc<Mutex<Option<PooledClientIncomingBody>>>;

struct RetainedEncodedBody {
    body: Option<PooledClientIncomingBody>,
    completed: CompletedBody,
    cx: Cx,
}

impl RetainedEncodedBody {
    fn park_completed(&mut self) {
        let body = self.body.take();
        let mut completed = self.completed.lock();
        debug_assert!(completed.is_none());
        *completed = body;
    }
}

impl Body for RetainedEncodedBody {
    type Data = BytesCursor;
    type Error = ClientError;

    fn poll_frame(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Option<Result<Frame<BytesCursor>, ClientError>>> {
        let this = self.get_mut();
        let Some(pooled) = this.body.as_mut() else {
            return Poll::Ready(None);
        };
        let Some(body) = pooled.body.as_mut() else {
            this.park_completed();
            return Poll::Ready(None);
        };
        let result = Pin::new(body).poll_frame(task);
        match result {
            Poll::Ready(Some(Err(error))) => {
                let error = cancellation_reported_as_cancelled::<()>(
                    &this.cx, Err(ClientError::from(error)),
                ).expect_err("an input error remains an error");
                drop(this.body.take());
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(frame) => {
                if frame.is_none()
                    || this.body.as_ref().and_then(|pooled| pooled.body.as_ref())
                        .is_some_and(Body::is_end_stream)
                {
                    this.park_completed();
                }
                Poll::Ready(frame.map(|frame| frame.map_err(ClientError::from)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.as_ref().map_or_else(|| SizeHint::with_exact(0), Body::size_hint)
    }
}

impl DecodedClientIncomingBody {
    fn retire(&mut self, success: bool) {
        // Mark terminal before dropping sources or waking arbitrary pool
        // waiters. Never run their destructors/callbacks under the holder lock.
        let decoder = self.decoder.take();
        self.owner.retire();
        drop(decoder);
        let completed = self.completed.lock().take();
        if let Some(mut completed) = completed {
            completed.retire(success);
        }
    }
}

impl Drop for DecodedClientIncomingBody {
    fn drop(&mut self) {
        self.retire(false);
    }
}

impl Body for DecodedClientIncomingBody {
    type Data = BytesCursor;
    type Error = ContentDecodeError<ClientError>;

    fn poll_frame(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Option<Result<Frame<BytesCursor>, Self::Error>>> {
        let this = self.get_mut();
        if this.decoder.is_none() {
            return Poll::Ready(None);
        }
        if let Some(error) = this.owner.poll_stop(task) {
            this.retire(false);
            return Poll::Ready(Some(Err(ContentDecodeError::Body(error))));
        }
        let decoder = this.decoder.as_mut().expect("decoder checked above");
        let result = Pin::new(&mut *decoder).poll_frame(task);
        let finished = decoder.is_end_stream();
        if matches!(&result, Poll::Ready(Some(Err(_)))) {
            this.retire(false);
        } else if result.is_ready() && finished {
            this.retire(true);
        }
        result
    }

    fn is_end_stream(&self) -> bool {
        self.decoder.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        self.decoder.as_ref().map_or_else(|| SizeHint::with_exact(0), Body::size_hint)
    }
}

fn decode_response(
    mut response: PooledClientStreamingResponse,
    owner: PooledStreamOwner,
    method: &Method,
    limits: ContentDecodeLimits,
) -> Result<DecodedClientStreamingResponse, ClientError> {
    let map_error = |error| ClientError::HttpError(HttpError::Io(error));
    let decoder = ContentDecoder::for_response(method, response.head.status, &response.head.headers)
        .map_err(map_error)?;
    let transformed = decoder.as_ref().is_some_and(|decoder| !decoder.is_identity());
    let empty = declared_empty(&response.head.headers) && response.body.size_hint().exact() == Some(0);
    let decoder = match decoder {
        Some(decoder) if !empty => decoder,
        _ => ContentDecoder::from_fields(std::iter::empty()).map_err(map_error)?,
    };
    let plan = ContentDecodePlan::new(decoder, limits).map_err(map_error)?;
    if response.body.size_hint().lower() > u64::try_from(limits.max_encoded_bytes()).unwrap_or(u64::MAX) {
        return Err(ClientError::HttpError(HttpError::BodyTooLarge));
    }
    if transformed {
        response.head.headers.retain(|(name, _)| !invalidated_field(name));
    }
    // The request-level owner was created before pool wait/redirects and is
    // retained intact. The raw body's duplicate timer/registration can retire.
    response.body.owner.retire();
    let completed = Arc::new(Mutex::new(None));
    let source = RetainedEncodedBody {
        body: Some(response.body),
        completed: Arc::clone(&completed),
        cx: owner.cx.clone(),
    };
    Ok(DecodedClientStreamingResponse {
        head: response.head,
        body: DecodedClientIncomingBody {
            decoder: Some(ContentDecodedBody::from_plan(source, plan)),
            completed,
            owner,
        },
        body_withheld: response.body_withheld,
    })
}

async fn drive_head<T>(
    owner: &mut PooledStreamOwner,
    future: impl Future<Output = Result<T, ClientError>>,
) -> Result<T, ClientError> {
    let mut future = std::pin::pin!(future);
    poll_fn(|task| {
        if let Some(error) = owner.poll_stop(task) {
            return Poll::Ready(Err(error));
        }
        future.as_mut().poll(task)
    }).await
}

impl HttpClient {
    /// Stream and explicitly decode a response while retaining pool admission.
    ///
    /// Advertises only compiled-in codecs when neither the request nor client
    /// defaults specify Accept-Encoding or Range. An explicitly supplied
    /// Accept-Encoding is preserved, but this method still decodes the returned
    /// representation. Unsupported codecs and encoded partial responses fail
    /// explicitly. With no codec features, identity remains available.
    ///
    /// Pooling, redirects, cookies, proxies and safe stale-reuse retries follow
    /// [`Self::request_streaming_pooled`]. The absolute request deadline remains
    /// active through decoding, including pending output after wire EOF.
    /// Existing buffered decompression configuration and raw streaming methods
    /// retain their behavior. The mandatory limits are independent of the
    /// client's encoded receive ceiling; all applicable bounds remain in force.
    ///
    /// This API is progressive: wait for successful completion before committing
    /// side effects based on the downloaded bytes.
    pub async fn request_streaming_decoded(
        &self,
        cx: &Cx,
        method: Method,
        url: &str,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        limits: ContentDecodeLimits,
    ) -> Result<DecodedClientStreamingResponse, ClientError> {
        self.request_streaming_decoded_timeout(cx, method, url, headers, body, limits, None).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn request_streaming_decoded_timeout(
        &self,
        cx: &Cx,
        method: Method,
        url: &str,
        mut headers: Vec<(String, String)>,
        body: Vec<u8>,
        limits: ContentDecodeLimits,
        timeout: Option<Duration>,
    ) -> Result<DecodedClientStreamingResponse, ClientError> {
        check_cx(cx)?;
        let timeout = self.config.request_timeout.into_iter().chain(timeout).min();
        let deadline = PooledStreamDeadline::capture(cx, timeout);
        let mut owner = PooledStreamOwner::new(cx.clone(), &deadline);
        let parsed = ParsedUrl::parse(url)?;
        self.advertise_stream_decoding(&mut headers);
        let (method, response) = drive_head(&mut owner,
            self.execute_with_redirects_pooled_streaming_method(cx, method, parsed, headers, body, &deadline),
        ).await?;
        decode_response(response, owner, &method, limits)
    }

    /// Send a one-shot streaming upload and progressively decode its response.
    ///
    /// Uses the framing and ownership contract of [`Self::request_with_body`].
    /// Upload sources are never replayed by redirects or retries. Response
    /// decoding and terminal connection retirement follow
    /// [`Self::request_streaming_decoded`].
    pub async fn request_with_body_decoded<B>(
        &self,
        cx: &Cx,
        method: Method,
        url: &str,
        headers: Vec<(String, String)>,
        body: B,
        limits: ContentDecodeLimits,
    ) -> Result<DecodedClientStreamingResponse, ClientError>
    where
        B: Body,
        B::Error: fmt::Display,
    {
        self.request_with_body_decoded_timeout(cx, method, url, headers, body, limits, None).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn request_with_body_decoded_timeout<B>(
        &self,
        cx: &Cx,
        method: Method,
        url: &str,
        mut headers: Vec<(String, String)>,
        body: B,
        limits: ContentDecodeLimits,
        timeout: Option<Duration>,
    ) -> Result<DecodedClientStreamingResponse, ClientError>
    where
        B: Body,
        B::Error: fmt::Display,
    {
        check_cx(cx)?;
        let effective = self.config.request_timeout.into_iter().chain(timeout).min();
        let deadline = PooledStreamDeadline::capture(cx, effective);
        let mut owner = PooledStreamOwner::new(cx.clone(), &deadline);
        self.advertise_stream_decoding(&mut headers);
        let response = drive_head(&mut owner,
            self.request_with_body_timeout(cx, method.clone(), url, headers, body, timeout),
        ).await?;
        decode_response(response, owner, &method, limits)
    }

    fn advertise_stream_decoding(&self, headers: &mut Vec<(String, String)>) {
        if !has_header(headers, "accept-encoding")
            && !has_header(&self.config.default_headers, "accept-encoding")
            && !has_header(headers, "range")
            && !has_header(&self.config.default_headers, "range")
        {
            headers.push(("Accept-Encoding".to_owned(), STREAM_CODINGS.to_owned()));
        }
    }
}

impl ClientRequestBuilder<'_> {
    /// Send this request and progressively decode its pooled response.
    ///
    /// Retains builder headers, buffered upload, and the tightest total timeout.
    /// See [`HttpClient::request_streaming_decoded`] for negotiation, limits,
    /// provisional output, and connection ownership through codec completion.
    ///
    /// ```no_run
    /// use asupersync::http::{Client, body::{Body, ContentDecodeLimits}};
    /// use std::{future::poll_fn, pin::Pin};
    /// # async fn download(cx: &asupersync::Cx) -> Result<(), Box<dyn std::error::Error>> {
    /// let response = Client::new().get("https://example.invalid/archive")
    ///     .send_streaming_decoded(cx, ContentDecodeLimits::new(8 * 1024 * 1024, 32 * 1024 * 1024)).await?;
    /// let mut body = response.body;
    /// while let Some(frame) = poll_fn(|task| Pin::new(&mut body).poll_frame(task)).await {
    ///     let frame = frame?; // Bytes remain provisional until successful EOF.
    ///     # let _ = frame;
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn send_streaming_decoded(
        self,
        cx: &Cx,
        limits: ContentDecodeLimits,
    ) -> Result<DecodedClientStreamingResponse, ClientError> {
        self.client.request_streaming_decoded_timeout(
            cx, self.method, &self.url, self.headers, self.body, limits, self.timeout,
        ).await
    }

    /// Stream a one-shot request body and decode the response on demand.
    /// A buffered body already configured on this builder is refused.
    pub async fn send_with_body_decoded<B>(
        self,
        cx: &Cx,
        body: B,
        limits: ContentDecodeLimits,
    ) -> Result<DecodedClientStreamingResponse, ClientError>
    where
        B: Body,
        B::Error: fmt::Display,
    {
        if !self.body.is_empty() {
            return Err(ClientError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a streaming request cannot also contain a buffered body",
            )));
        }
        self.client.request_with_body_decoded_timeout(
            cx, self.method, &self.url, self.headers, body, limits, self.timeout,
        ).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::Buf;
    use crate::runtime::RuntimeBuilder;
    use crate::time::{TimerDriverHandle, VirtualClock};
    use crate::types::{Budget, RegionId, TaskId, Time};
    use std::io::{Read, Write};
    use std::num::NonZeroUsize;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Wake, Waker};
    use std::time::Instant;

    #[derive(Default)]
    struct WakeCount(AtomicUsize);

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    // Exercise the owned timer after HTTP framing has completed. Identity is
    // intentional: this lifetime boundary must work even without codec features.
    #[test]
    fn decoded_body_keeps_tightest_original_deadline_after_wire_eof() {
        for (budget_at, client_timeout, call_timeout) in [(110, 30, 20), (130, 10, 20), (130, 20, 10)] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let peer = std::thread::spawn(move || {
                let until = Instant::now() + Duration::from_secs(5);
                let mut socket = loop {
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < until => {
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        other => panic!("bounded decoded-client accept failed: {other:?}"),
                    }
                };
                socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    assert!(head.len() < 16 * 1024);
                    let mut byte = [0];
                    socket.read_exact(&mut byte).unwrap();
                    head.push(byte[0]);
                }
                socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nabcdefgh").unwrap();
                let mut byte = [0];
                match socket.read(&mut byte) {
                    Ok(0) => {}
                    Err(error) if matches!(error.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted) => {}
                    other => panic!("expired decoded body must close its reserved socket: {other:?}"),
                }
            });
            let runtime = RuntimeBuilder::current_thread()
                .with_reactor(crate::runtime::reactor::create_reactor().unwrap())
                .build().unwrap();
            let driver = runtime.request_cx_with_budget(Budget::INFINITE);
            let clock = Arc::new(VirtualClock::starting_at(Time::from_nanos(100)));
            let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
            let owner = Cx::new_with_drivers(
                RegionId::new_for_test(0, 1), TaskId::new_for_test(301, 0),
                Budget::INFINITE.with_deadline(Time::from_nanos(budget_at)),
                None, None, None, Some(timer.clone()), None,
            );
            let foreign_clock = Arc::new(VirtualClock::starting_at(Time::from_secs(1_000_000)));
            let foreign_timer = TimerDriverHandle::with_virtual_clock(foreign_clock);
            let foreign = Cx::new_with_drivers(
                RegionId::new_for_test(0, 1), TaskId::new_for_test(302, 0),
                Budget::INFINITE, None, None, None, Some(foreign_timer.clone()), None,
            );
            let client = HttpClient::builder()
                .request_timeout(Duration::from_nanos(client_timeout)).build();
            runtime.block_on_with_cx(driver, async {
                let mut response = client.get(&url)
                    .timeout(Duration::from_nanos(call_timeout))
                    .send_streaming_decoded(&owner,
                        ContentDecodeLimits::new(8, 8).with_chunk_size(NonZeroUsize::new(1).unwrap()),
                    ).await.unwrap();
                let mut provisional = Vec::new();
                loop {
                    let frame = poll_fn(|task| Pin::new(&mut response.body).poll_frame(task)).await;
                    let Some(Ok(Frame::Data(data))) = frame else { panic!("expected provisional data: {frame:?}"); };
                    provisional.extend_from_slice(data.chunk());
                    if response.body.completed.lock().is_some() { break; }
                }
                assert!(b"abcdefgh".starts_with(&provisional));
                assert!(!response.body.is_end_stream(), "decoded terminal verdict is still outstanding");
                assert_eq!(client.pool_stats().idle_connections, 0);
                assert_eq!(client.pool_stats().total_connections, 1);
                assert_eq!(timer.pending_count(), 1, "only the outer original deadline remains");
                let _ambient = Cx::set_current(Some(foreign));
                assert_eq!(foreign_timer.process_timers(), 0);
                clock.advance(9);
                assert_eq!(timer.process_timers(), 0);
                let wakes = Arc::new(WakeCount::default());
                let waker = Waker::from(Arc::clone(&wakes));
                let mut task = Context::from_waker(&waker);
                assert!(response.body.owner.poll_stop(&mut task).is_none());
                clock.advance(1);
                assert_eq!(timer.process_timers(), 1);
                assert!(wakes.0.load(Ordering::SeqCst) > 0);
                assert!(matches!(Pin::new(&mut response.body).poll_frame(&mut task),
                    Poll::Ready(Some(Err(ContentDecodeError::Body(ClientError::DeadlineExceeded))))));
                assert!(matches!(Pin::new(&mut response.body).poll_frame(&mut task), Poll::Ready(None)));
                assert_eq!(client.pool_stats().total_connections, 0);
                assert!(owner.inner.read().cancel_waker_registrations.is_empty());
                assert_eq!(timer.pending_count(), 0);
                assert_eq!(foreign_timer.pending_count(), 0);
            });
            peer.join().unwrap();
            assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
        }
    }
}
