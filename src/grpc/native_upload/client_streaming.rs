//! Native streaming uploads with exactly one, trailer-validated response.

use super::NativeBidiStream;
use crate::cx::Cx;
use crate::grpc::client::GrpcClient;
use crate::grpc::codec::Codec;
use crate::grpc::status::{Code, Status};
use crate::grpc::streaming::{Metadata, Request, Response, Streaming};
use crate::io::{AsyncRead, AsyncWrite};
use std::fmt;
use std::future::poll_fn;
use std::task::{Context, Poll};

/// An owned native client-streaming RPC, including its uncollected response.
///
/// Uploads a `Streaming` source through the existing native duplex transport.
/// [`Self::response`] drives both directions and returns exactly one message,
/// only after the peer's final gRPC status has been validated as OK. Initial
/// metadata is returned on the response; trailers remain separately available
/// through [`Self::trailers`]. No task, response queue or second protocol engine
/// is created. The dedicated connection retires before a result is returned.
///
/// Dropping a borrowing response wait preserves the upload cursors and a message
/// already received while waiting for trailers. Dropping this owner retires the
/// transport, producer and uncollected message under the supplied context. It
/// does not certify remote quiescence or run asynchronous producer cleanup.
///
/// A successful server response may precede request EOF. As permitted by gRPC,
/// that ends the call and retires the unused source; it does not prove that the
/// server consumed every source item. A source error, deadline or cancellation
/// observed before terminal success remains a failure, even after a response
/// message arrived. Receiving a second message is a protocol error and closes
/// the call immediately rather than reading an unbounded invalid response.
pub struct NativeClientStreamingCall<IO, C: Codec, S> {
    stream: NativeBidiStream<IO, C, S>,
    first: Option<C::Decode>,
    collected: bool,
}

impl<IO, C: Codec, S> fmt::Debug for NativeClientStreamingCall<IO, C, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeClientStreamingCall")
            .field("response_buffered", &self.first.is_some())
            .field("collected", &self.collected)
            .finish_non_exhaustive()
    }
}

impl<C: Codec> GrpcClient<C> {
    /// Start a real HTTP/2 streaming upload that expects one response.
    ///
    /// Setup delegates to [`Self::into_native_bidi_streaming`], preserving its
    /// explicit context, TLS/ALPN, interceptors, flow control, message limits,
    /// timeout and keepalive behavior. Setup does not poll the source or wait
    /// for the response. Call [`NativeClientStreamingCall::response`] to drive
    /// the upload and validate the complete response, including final trailers.
    ///
    /// The source can borrow and need not be `Unpin`. At most one outbound
    /// message occupies the existing duplex upload slot. This does not buffer
    /// the whole upload or retry an ambiguous request. Legacy loopback sink APIs
    /// remain unchanged; this method uses the codec's actual wire message types.
    pub async fn into_native_client_streaming<S>(
        self,
        cx: &Cx,
        path: &str,
        request: Request<S>,
    ) -> Result<
        NativeClientStreamingCall<impl AsyncRead + AsyncWrite + Unpin + Send + 'static, C, S>,
        Status,
    >
    where
        S: Streaming<Message = C::Encode>,
    {
        let stream = self.into_native_bidi_streaming(cx, path, request).await?;
        Ok(NativeClientStreamingCall {
            stream,
            first: None,
            collected: false,
        })
    }
}

impl<IO, C, S> NativeClientStreamingCall<IO, C, S>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
    C: Codec,
    S: Streaming<Message = C::Encode>,
{
    /// Upload requests and collect the single complete, successful response.
    ///
    /// A first response message alone is not success: polling continues until
    /// final status, and any later peer/producer error is returned instead.
    /// Zero or multiple messages with an otherwise successful response are
    /// `Internal` errors. The retained first message is not lost when this
    /// borrowing future is dropped and recreated. After a terminal result has
    /// been collected, another call returns `FailedPrecondition` without I/O.
    pub async fn response(&mut self) -> Result<Response<C::Decode>, Status> {
        poll_fn(|task| self.poll_response(task)).await
    }

    /// Initial response metadata, never merged with trailing metadata.
    #[must_use]
    pub fn initial_metadata(&self) -> Option<&Metadata> {
        self.stream.initial_metadata()
    }

    /// Trailers retained after terminal collection, including on peer failure.
    #[must_use]
    pub fn trailers(&self) -> Option<&Metadata> {
        self.stream.trailers()
    }

    /// Final RPC classification, including local response-cardinality errors.
    #[must_use]
    pub fn status(&self) -> Option<&Status> {
        self.stream.status()
    }

    /// Cancel this call without cancelling its parent context.
    ///
    /// Retires the transport, producer and any buffered response. An outstanding
    /// response wait subsequently returns `Cancelled`. Repeated cancellation or
    /// cancellation after terminal collection does not rewrite the result.
    pub fn cancel(&mut self) {
        if !self.collected {
            let _ambient = Cx::set_current(Some(self.stream.cx.clone()));
            let first = self.first.take();
            self.stream.cancel();
            drop(first);
        }
    }

    fn fail(&mut self, status: Status) -> Status {
        let _ambient = Cx::set_current(Some(self.stream.cx.clone()));
        self.collected = true;
        let first = self.first.take();
        let status = self.stream.finish(status);
        drop(first);
        status
    }

    fn poll_response(&mut self, task: &mut Context<'_>) -> Poll<Result<Response<C::Decode>, Status>> {
        if self.collected {
            return Poll::Ready(Err(Status::failed_precondition(
                "native client-streaming response already collected",
            )));
        }
        let _ambient = Cx::set_current(Some(self.stream.cx.clone()));
        loop {
            // NativeBidiStream bounds ready progress across polls, so retaining
            // the first response does not bypass its cooperative poll budget.
            match self.stream.poll_message(task) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(message))) => {
                    if self.first.is_some() {
                        let status = self.fail(Status::internal(
                            "native client-streaming RPC returned more than one response message",
                        ));
                        // Retire the connection before invoking either message's
                        // destructor. The ambient guard also covers unwinding.
                        drop(message);
                        return Poll::Ready(Err(status));
                    }
                    self.first = Some(message);
                }
                Poll::Ready(Some(Err(status))) => {
                    return Poll::Ready(Err(self.fail(status)));
                }
                Poll::Ready(None) => {
                    let status = self.stream.status().cloned().unwrap_or_else(|| {
                        Status::internal("native client-streaming RPC has no terminal status")
                    });
                    if status.code() != Code::Ok {
                        return Poll::Ready(Err(self.fail(status)));
                    }
                    let Some(message) = self.first.take() else {
                        return Poll::Ready(Err(self.fail(Status::internal(
                            "native client-streaming RPC returned no response message",
                        ))));
                    };
                    self.collected = true;
                    let metadata = self.stream.initial_metadata().cloned()
                        .unwrap_or_else(Metadata::new);
                    return Poll::Ready(Ok(Response::with_metadata(message, metadata)));
                }
            }
        }
    }
}

impl<IO, C: Codec, S> Drop for NativeClientStreamingCall<IO, C, S> {
    fn drop(&mut self) {
        let _ambient = Cx::set_current(Some(self.stream.cx.clone()));
        // All owners are removed before user destructors run. Locals unwind
        // under the ambient guard even if a producer/message destructor panics.
        let first = self.first.take();
        let source = self.stream.source.take();
        let call = self.stream.call.take();
        drop(call);
        drop(source);
        drop(first);
    }
}

#[cfg(test)]
mod tests;
