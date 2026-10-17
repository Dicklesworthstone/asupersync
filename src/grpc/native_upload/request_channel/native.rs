//! Connect the request channel to the native transport's existing owner.

use super::{NativeRequestSender, NativeRequestStream, native_request_channel};
use crate::cx::Cx;
use crate::grpc::client::GrpcClient;
use crate::grpc::codec::Codec;
use crate::grpc::native_upload::{NativeBidiStream, NativeClientStreamingCall};
use crate::grpc::status::Status;
use crate::grpc::streaming::Request;
use crate::io::{AsyncRead, AsyncWrite};
use std::sync::Arc;

impl<C: Codec> GrpcClient<C>
where
    C::Encode: Send,
{
    /// Start a native bidirectional RPC with a bounded request sender.
    ///
    /// Request metadata and extensions use the same interceptor and connection
    /// path as `into_native_bidi_streaming`. `capacity` bounds queued message
    /// objects, not their heap allocations; transport message-size limits apply
    /// when each request is encoded. Invalid capacity refuses before connecting.
    ///
    /// Drive `responses.message()` concurrently with capacity-waiting sends,
    /// using an explicitly owned producer task or polling both futures. This
    /// method does not spawn a driver. `sender.close()` drains accepted requests
    /// before half-close; dropping an open sender aborts instead. A producer
    /// task should use `sender.send_with_cx(&child_cx, message)` so its own abort
    /// also interrupts a full-queue wait without cancelling the RPC parent.
    /// A producer
    /// failure wakes and terminates this call even when the peer grants zero
    /// upload credit, without waiting for another request-source poll.
    ///
    /// Terminal response status closes the input queue and wakes blocked sends.
    /// A send refusal reports local input closure; inspect the response owner
    /// for the peer's actual status. Accepted input is not proof of remote
    /// delivery, and an early peer terminal may discard unconsumed input.
    pub async fn into_native_bidi_channel(
        self,
        cx: &Cx,
        path: &str,
        request: Request<()>,
        capacity: usize,
    ) -> Result<(
        NativeRequestSender<C::Encode>,
        NativeBidiStream<impl AsyncRead + AsyncWrite + Unpin + Send + 'static, C, NativeRequestStream<C::Encode>>,
    ), Status> {
        let (sender, source) = native_request_channel(cx, capacity)?;
        let control = Arc::clone(&sender.control);
        let mut responses = self.into_native_bidi_streaming(cx, path, request.map(|()| source)).await?;
        responses.request_control = Some(control);
        Ok((sender, responses))
    }

    /// Start a bounded native upload with one trailer-validated response.
    ///
    /// This has the same sender/backpressure and out-of-band failure semantics
    /// as `into_native_bidi_channel`. Poll `call.response()` while producing
    /// requests; it drives both directions and does not report the first reply
    /// as success until final gRPC status is validated. A late peer error is
    /// preserved. Dropping a borrowing response wait preserves all call state;
    /// dropping the owner retires the socket and wakes a blocked producer.
    /// Legacy codec-free client-streaming methods remain unchanged.
    pub async fn into_native_client_streaming_channel(
        self,
        cx: &Cx,
        path: &str,
        request: Request<()>,
        capacity: usize,
    ) -> Result<(
        NativeRequestSender<C::Encode>,
        NativeClientStreamingCall<impl AsyncRead + AsyncWrite + Unpin + Send + 'static, C, NativeRequestStream<C::Encode>>,
    ), Status> {
        let (sender, source) = native_request_channel(cx, capacity)?;
        let control = Arc::clone(&sender.control);
        let call = self.into_native_client_streaming(cx, path, request.map(|()| source)).await?;
        Ok((sender, call.with_request_control(control)))
    }
}

#[cfg(test)]
#[path = "native_inline_tests.rs"]
mod tests;
