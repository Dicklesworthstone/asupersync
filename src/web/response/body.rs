//! Supervise an arbitrary pull-driven Body using the existing response queue.

use super::{Http1StreamPlan, Http1StreamResponder, Http2StreamPlan, Http2StreamResponder, Response, StatusCode};
use crate::bytes::{Buf, Bytes};
use crate::cx::Cx;
use crate::http::body::{Body, Frame, HeaderMap};
use crate::http::encode::BodyCancellation;
use crate::http::h1::{BodyKind, HttpError, OutgoingBodySender};
use crate::http::h2::listener::Http2BodySender;
use std::fmt;
use std::future::{Future, poll_fn};
use std::num::NonZeroUsize;
use std::task::Poll;

impl Http1StreamResponder {
    /// Send an arbitrary streaming Body through this request's supervised queue.
    ///
    /// The response head must have no buffered body or Transfer-Encoding. An
    /// authored Content-Length is validated and adopted by the existing exact
    /// length producer; otherwise framing is chunked. DATA is split at
    /// `max_frame_bytes`, and source polling stops behind queue backpressure.
    /// At most one source frame is held outside that existing bounded queue.
    /// No additional channel, task, or eager collection is introduced.
    ///
    /// Source trailers wait for source EOF, and are allowed only with chunked
    /// framing. Source failures/cancellation fail the producer, so the listener
    /// closes the response instead of publishing a successful terminator.
    /// HEAD keeps the existing listener rule: the source is never polled.
    /// Compose with [`crate::web::StreamingCompression::encode_response`] for
    /// explicit, negotiated compression and mandatory source/output limits.
    #[must_use]
    pub fn body<B>(self, mut head: Response, capacity: NonZeroUsize, max_frame_bytes: NonZeroUsize, body: B) -> Response
    where
        B: Body + Send + 'static,
        B::Data: Send,
        B::Error: fmt::Display + Send,
    {
        if !head.body.is_empty() || head.has_header("transfer-encoding") {
            return refusal("streamed response requires a body-free head without transfer framing");
        }
        let mut length = None;
        for (_, value) in head.headers.iter().filter(|(name, _)| name.eq_ignore_ascii_case("content-length")) {
            let Ok(parsed) = crate::web::extract::parse_content_length(value) else {
                return refusal("invalid streamed response Content-Length");
            };
            if length.replace(parsed as u64).is_some_and(|previous| previous != parsed as u64) {
                return refusal("conflicting streamed response Content-Length");
            }
        }
        if length.is_some() && head.has_header("trailer") {
            return refusal("fixed-length streamed responses cannot declare trailers");
        }
        head.remove_header("content-length");
        let plan = Http1StreamPlan {
            body_kind: length.map_or(BodyKind::Chunked, BodyKind::ContentLength),
            capacity,
            max_frame_bytes,
            producer: Box::new(move |cx, sender| Box::pin(drive_body(cx, sender, body, max_frame_bytes))),
        };
        if self.slot.register(plan).is_err() { return refusal("HTTP/1 streamed response already registered"); }
        head
    }
}

impl Http2StreamResponder {
    /// Send an arbitrary Body through the existing supervised HTTP/2 DATA queue.
    ///
    /// The final head follows the existing produced-response rules: no buffered
    /// bytes or Transfer-Encoding, and no Content-Length on body-bearing
    /// responses. DATA is split at `max_frame_bytes`; source trailers are sent
    /// only after successful source EOF. Source failures/cancellation reset the
    /// response through the listener's normal producer-failure path.
    ///
    /// At most one source frame is held outside the existing bounded channel.
    /// The source is not polled at registration or on suppressed HEAD responses.
    #[must_use]
    pub fn body<B>(self, head: Response, capacity: NonZeroUsize, max_frame_bytes: NonZeroUsize, body: B) -> Response
    where
        B: Body + Send + 'static,
        B::Data: Send,
        B::Error: fmt::Display + Send,
    {
        if !head.body.is_empty() || head.has_header("transfer-encoding") {
            return refusal("streamed response requires a body-free head without transfer framing");
        }
        let plan = Http2StreamPlan {
            capacity,
            max_frame_bytes,
            producer: Box::new(move |cx, sender| Box::pin(drive_body(cx, sender, body, max_frame_bytes))),
        };
        if self.slot.register(plan).is_err() { return refusal("HTTP/2 streamed response already registered"); }
        head
    }
}

trait BodySink: Send {
    fn data<'a>(&'a mut self, cx: &'a Cx, data: Bytes) -> impl Future<Output = Result<(), HttpError>> + Send + 'a;
    fn trailers<'a>(&'a mut self, cx: &'a Cx, trailers: HeaderMap) -> impl Future<Output = Result<(), HttpError>> + Send + 'a;
    fn finish(&mut self, cx: &Cx) -> Result<(), HttpError>;
}

impl BodySink for OutgoingBodySender {
    fn data<'a>(&'a mut self, cx: &'a Cx, data: Bytes) -> impl Future<Output = Result<(), HttpError>> + Send + 'a {
        self.send_bytes(cx, data)
    }
    fn trailers<'a>(&'a mut self, cx: &'a Cx, trailers: HeaderMap) -> impl Future<Output = Result<(), HttpError>> + Send + 'a {
        self.send_trailers(cx, trailers)
    }
    fn finish(&mut self, cx: &Cx) -> Result<(), HttpError> { OutgoingBodySender::finish(self, cx) }
}

impl BodySink for Http2BodySender {
    fn data<'a>(&'a mut self, cx: &'a Cx, data: Bytes) -> impl Future<Output = Result<(), HttpError>> + Send + 'a {
        self.send_bytes(cx, data)
    }
    fn trailers<'a>(&'a mut self, cx: &'a Cx, trailers: HeaderMap) -> impl Future<Output = Result<(), HttpError>> + Send + 'a {
        self.send_trailers(cx, trailers)
    }
    fn finish(&mut self, cx: &Cx) -> Result<(), HttpError> { Http2BodySender::finish(self, cx) }
}

async fn drive_body<B, S>(cx: Cx, mut sender: S, body: B, max_frame_bytes: NonZeroUsize) -> Result<S, HttpError>
where
    B: Body + Send,
    B::Data: Send,
    B::Error: fmt::Display + Send,
    S: BodySink,
{
    let mut body = Box::pin(body);
    let mut cancellation = BodyCancellation::new(&cx);
    let mut trailers = None;
    let mut operations = 0;
    loop {
        if operations >= 32 {
            crate::runtime::yield_now().await;
            operations = 0;
        }
        let next = poll_fn(|task| {
            cancellation.register(task);
            if cancellation.check().is_err() { return Poll::Ready(Err(HttpError::BodyCancelled)); }
            match body.as_mut().poll_frame(task) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(frame) => Poll::Ready(Ok(frame)),
            }
        }).await?;
        let Some(frame) = next else { break; };
        operations += 1;
        match frame.map_err(|error| HttpError::Io(std::io::Error::other(error.to_string())))? {
            Frame::Data(mut data) => {
                if trailers.is_some() { return Err(HttpError::BadHeader); }
                while data.has_remaining() {
                    let bytes = data.copy_to_bytes(data.remaining().min(max_frame_bytes.get()));
                    sender.data(&cx, bytes).await?;
                    operations += 1;
                    if operations >= 32 {
                        crate::runtime::yield_now().await;
                        operations = 0;
                    }
                }
            }
            Frame::Trailers(frame) => {
                if trailers.replace(frame).is_some() { return Err(HttpError::BadHeader); }
            }
        }
    }
    if let Some(trailers) = trailers { sender.trailers(&cx, trailers).await?; }
    sender.finish(&cx)?;
    Ok(sender)
}

fn refusal(message: &'static str) -> Response {
    Response::new(StatusCode::INTERNAL_SERVER_ERROR, message)
}
