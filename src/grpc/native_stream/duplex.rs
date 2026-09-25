//! Bounded request streaming through the existing native call owner.

use super::*;

/// Progress on either direction of a native client-streaming or bidi RPC.
#[derive(Debug)]
pub enum NativeDuplexEvent<T> {
    /// The initial headers, one queued message, or the requested half-close
    /// have left the local HTTP/2 and transport write queues. This permits the
    /// next request message; it is not an application acknowledgement.
    RequestFlushed,
    /// One complete response message. Consume these while uploading so a peer
    /// that sends responses before granting more request credit can progress.
    Message(T),
}

/// A client-streaming or bidirectional RPC on one fresh, owned H2 transport.
///
/// Call [`Self::next_event`] until `RequestFlushed`, then queue a request with
/// [`Self::queue_message`] or half-close with [`Self::close_requests`]. Continue
/// consuming events in either direction. The peer may respond before upload
/// finishes. After half-close, consume through `Ok(None)` to observe successful
/// trailers; an error is returned once and retained by [`Self::status`].
///
/// Only one encoded request is admitted at a time. A full slot refuses before
/// invoking the codec. All writes, reads and H2 window updates are driven by
/// `next_event`; dropping that borrowing wait retains their exact cursors.
/// Dropping the owner closes its dedicated transport and starts no detached
/// work. Cancellation and deadlines use the explicit constructor Cx, observed
/// at each poll. They do not certify remote handler cleanup or RST delivery.
///
/// The underlying [`NativeServerStream`] enforces send/receive message limits,
/// metadata limits, and bounded control-frame read-ahead. The encoded request
/// slot is at most the send limit plus its five-byte prefix; one outbound H2
/// frame is additional. Codec/transport internals and returned values have
/// their own allocation contracts. Responses are decoded before more network
/// reads, so uploading does not collect an unbounded response queue.
///
/// Supply an already authenticated TLS transport with h2 ALPN for HTTPS. The
/// authority and scheme are routing labels, not authentication. This supports
/// streaming requests without changing the legacy codec-free `GrpcClient`
/// methods or introducing a background connection driver.
pub struct NativeDuplexStream<IO, C> {
    inner: NativeServerStream<IO, C>,
    request_pending: bool,
    request_closed: bool,
}

impl<IO, C> fmt::Debug for NativeDuplexStream<IO, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeDuplexStream")
            .field("call", &self.inner)
            .field("request_pending", &self.request_pending)
            .field("request_closed", &self.request_closed)
            .finish()
    }
}

impl<IO, C> NativeDuplexStream<IO, C>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: Codec,
{
    /// Prepare initial metadata without closing the request side or doing I/O.
    /// The unit request carries metadata; subsequent messages use the codec.
    ///
    /// # Errors
    /// The same configuration, cancellation, metadata and deadline refusals as
    /// [`NativeServerStream::new`] apply before any transport bytes are sent.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cx: &Cx,
        io: IO,
        authority: &str,
        path: &str,
        request: Request<()>,
        codec: C,
        config: NativeStreamConfig,
    ) -> Result<Self, Status> {
        let inner = NativeServerStream::new_request(
            cx,
            io,
            authority,
            path,
            request.map(|()| None),
            codec,
            config,
            None,
            false,
        )?;
        Ok(Self {
            inner,
            request_pending: true,
            request_closed: false,
        })
    }

    /// Whether one message or half-close can be admitted without waiting.
    #[must_use]
    pub fn request_ready(&self) -> bool {
        !self.request_pending
            && !self.request_closed
            && self.inner.final_status.is_none()
            && !self.inner.response.ended
    }

    fn check_request(&mut self) -> Result<(), Status> {
        if !self.request_ready() {
            return Err(Status::failed_precondition(
                "native gRPC request slot is unavailable",
            ));
        }
        if let Err(status) = check_cancellation(&self.inner.cx) {
            return Err(self.inner.finish(status));
        }
        if self
            .inner
            .deadline
            .zip(self.inner.clock.as_ref())
            .is_some_and(|(at, clock)| clock.now() >= at)
        {
            return Err(self.inner.finish(Status::deadline_exceeded(
                "native gRPC stream deadline exceeded",
            )));
        }
        Ok(())
    }

    /// Encode and admit exactly one message, without network I/O.
    ///
    /// A successful call transfers the encoded bytes into this owner. Do not
    /// resubmit the message when a later `next_event` wait is dropped: resume
    /// that wait instead. A busy/closed slot refuses before codec invocation.
    /// Encoding and compression use the existing configured message limits.
    pub fn queue_message(&mut self, message: &C::Encode) -> Result<(), Status> {
        let _ambient = Cx::set_current(Some(self.inner.cx.clone()));
        self.check_request()?;
        let mut bytes = BytesMut::new();
        self.inner
            .codec
            .encode_message(message, &mut bytes)
            .map_err(GrpcError::into_status)?;
        // A synchronous application codec may consume the entire allowance.
        self.check_request()?;
        self.inner
            .connection
            .as_mut()
            .expect("live duplex connection")
            .send_data(self.inner.stream_id, bytes.freeze(), false)
            .map_err(|error| Status::internal(format!("queue gRPC message: {error}")))?;
        self.request_pending = true;
        Ok(())
    }

    /// Queue request END_STREAM after the preceding message was flushed.
    /// This is an HTTP/2 half-close: responses and terminal trailers remain live.
    pub fn close_requests(&mut self) -> Result<(), Status> {
        self.check_request()?;
        self.inner
            .connection
            .as_mut()
            .expect("live duplex connection")
            .send_data(self.inner.stream_id, Bytes::new(), true)
            .map_err(|error| Status::internal(format!("half-close gRPC request: {error}")))?;
        self.request_closed = true;
        self.request_pending = true;
        Ok(())
    }

    /// Progress both directions and observe a send boundary or a response.
    /// The borrowing wait may be dropped and recreated without repeating bytes.
    pub async fn next_event(&mut self) -> Result<Option<NativeDuplexEvent<C::Decode>>, Status> {
        poll_fn(|task| self.poll_event(task)).await.transpose()
    }

    /// Initial response metadata, distinct from terminal trailers.
    #[must_use]
    pub fn initial_metadata(&self) -> Option<&Metadata> {
        self.inner.initial_metadata()
    }

    /// Terminal metadata once received.
    #[must_use]
    pub fn trailers(&self) -> Option<&Metadata> {
        self.inner.trailers()
    }

    /// Exact final status after terminal consumption, cancellation or failure.
    #[must_use]
    pub fn status(&self) -> Option<&Status> {
        self.inner.status()
    }

    /// Retained response DATA, excluding transport/codec-owned allocations.
    #[must_use]
    pub fn buffered_data_bytes(&self) -> usize {
        self.inner.buffered_data_bytes()
    }

    /// Retire the dedicated transport without cancelling the parent task.
    pub fn cancel(&mut self) {
        self.inner.cancel();
    }

    fn poll_event(
        &mut self,
        task: &mut Context<'_>,
    ) -> Poll<Option<Result<NativeDuplexEvent<C::Decode>, Status>>> {
        let _ambient = Cx::set_current(Some(self.inner.cx.clone()));
        let inner = &mut self.inner;
        if inner.final_status.is_some() {
            return Poll::Ready(None);
        }
        if inner.ready_messages == POLL_STEPS {
            inner.ready_messages = 0;
            task.waker().wake_by_ref();
            return Poll::Pending;
        }
        for _ in 0..POLL_STEPS {
            if let Err(error) = inner.gate(task) {
                return Poll::Ready(Some(Err(inner.finish(error))));
            }
            if inner.response.initial.is_some() {
                match inner.codec.decode_message_with_encoding(
                    &mut inner.body,
                    inner.response.encoding.as_deref(),
                ) {
                    Ok(Some(message)) => {
                        if let Err(error) = inner.gate(task) {
                            return Poll::Ready(Some(Err(inner.finish(error))));
                        }
                        inner.ready_messages += 1;
                        return Poll::Ready(Some(Ok(NativeDuplexEvent::Message(message))));
                    }
                    Ok(None) => {}
                    Err(error) => return Poll::Ready(Some(Err(inner.finish(error.into_status())))),
                }
            }
            if inner.response.ended {
                let status = if inner.body.is_empty() {
                    inner
                        .response
                        .terminal
                        .take()
                        .unwrap_or_else(|| Status::internal("missing gRPC terminal status"))
                } else {
                    Status::internal("truncated gRPC message before stream termination")
                };
                let ok = status.code() == Code::Ok;
                let status = inner.finish(status);
                return Poll::Ready(if ok { None } else { Some(Err(status)) });
            }
            if self.request_pending {
                match inner.poll_outbound(task) {
                    Poll::Ready(Err(error)) => return Poll::Ready(Some(Err(inner.finish(error)))),
                    Poll::Ready(Ok(())) => {
                        inner.unflushed_read_frames = 0;
                        if !inner
                            .connection
                            .as_ref()
                            .expect("live duplex connection")
                            .has_pending_frames_for_stream(inner.stream_id)
                        {
                            self.request_pending = false;
                            inner.ready_messages += 1;
                            return Poll::Ready(Some(Ok(NativeDuplexEvent::RequestFlushed)));
                        }
                    }
                    Poll::Pending => {}
                }
            }
            match inner.poll_received(task) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Some(Err(inner.finish(error)))),
                Poll::Pending => {
                    // poll_received also drives writes. A transport can become
                    // writable between the two polls, then park its read while
                    // the peer waits for our next message. Publish that send
                    // boundary now instead of depending on another read wake.
                    if self.request_pending
                        && inner.outbound_flushed
                        && !inner
                            .connection
                            .as_ref()
                            .expect("live duplex connection")
                            .has_pending_frames_for_stream(inner.stream_id)
                    {
                        self.request_pending = false;
                        inner.ready_messages += 1;
                        return Poll::Ready(Some(Ok(NativeDuplexEvent::RequestFlushed)));
                    }
                    return Poll::Pending;
                }
            }
        }
        task.waker().wake_by_ref();
        Poll::Pending
    }
}

#[cfg(test)]
mod tests;
