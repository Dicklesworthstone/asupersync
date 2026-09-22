//! Connection attempts as ordered observations, followed by the real byte stream.
//!
//! Each attempt uses a dedicated logical journal stream, not fabricated network
//! traffic. Its vectored write fingerprints the request and target stream ID;
//! its read records success or the real connector's error kind/native code.
//! Existing group codecs, encryption, wakeups and completion checks apply.

use super::{
    CaptureTimeline, GroupEffect, GroupRecordingIo, GroupReplayIo, GroupSessionCaptureError,
    IoCaptureLimits, IoOperation, RecordingGroupSession, ReplayGroupSession,
};
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::time::TimeSource;
use parking_lot::Mutex;
use std::fmt;
use std::future::{Future, poll_fn};
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

const REQUEST_DOMAIN: &[u8] = b"asupersync.connect.v1\0";
const CONNECTED: u8 = 1;

/// Distinct session identities for one attempt's journal and successful stream.
///
/// Use new identities for every retry, even when dialing the same endpoint.
/// They share the namespace of ordinary `register`/`open` calls. Identity alone
/// is not a peer-authentication policy; the request key must bind that policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionAttempt {
    journal: u64,
    stream: u64,
}

/// The request journal must never also be the resulting byte stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("connection journal and data stream identities must differ")]
pub struct ConnectionIdentityError;

impl ConnectionAttempt {
    /// Select two distinct identities. No allocation, source call or I/O occurs.
    pub const fn new(journal: u64, stream: u64) -> Result<Self, ConnectionIdentityError> {
        if journal == stream {
            Err(ConnectionIdentityError)
        } else {
            Ok(Self { journal, stream })
        }
    }

    /// Identity reserved for the two logical connection observations.
    #[must_use]
    pub const fn journal_stream(self) -> u64 { self.journal }

    /// Identity used only when the source connector succeeds.
    #[must_use]
    pub const fn data_stream(self) -> u64 { self.stream }

    fn effect(self, operation: IoOperation) -> GroupEffect {
        GroupEffect::Io { stream: self.journal, operation }
    }
}

enum ConnectionInner<T> {
    Recording(GroupRecordingIo<T>),
    // Capture refusal must not turn a successful real connection into an error
    // or drop its provider. The complete session is already invalidated.
    Unrecorded(T),
}

/// The real connector's stream, with transparent byte capture when admitted.
///
/// Capture limits/collisions do not change successful connection results. Such
/// refusals invalidate `RecordingGroupSession::finish`, while this stream still
/// forwards normally. Return the provider with `into_inner` after draining its
/// users. Dropping an admitted owner instead abandons the entire capture.
pub struct RecordingConnection<T> {
    inner: ConnectionInner<T>,
}

impl<T> fmt::Debug for RecordingConnection<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordingConnection").finish_non_exhaustive()
    }
}

impl<T> RecordingConnection<T> {
    /// Finish this stream's window and return its original provider unchanged.
    /// This is not a network shutdown or proof that the whole capture succeeded.
    pub fn into_inner(self) -> T {
        match self.inner {
            ConnectionInner::Recording(io) => io.into_inner(),
            ConnectionInner::Unrecorded(io) => io,
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for RecordingConnection<T> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().inner {
            ConnectionInner::Recording(io) => Pin::new(io).poll_read(cx, buf),
            ConnectionInner::Unrecorded(io) => Pin::new(io).poll_read(cx, buf),
        }
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for RecordingConnection<T> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match &mut self.get_mut().inner {
            ConnectionInner::Recording(io) => Pin::new(io).poll_write(cx, buf),
            ConnectionInner::Unrecorded(io) => Pin::new(io).poll_write(cx, buf),
        }
    }
    fn poll_write_vectored(self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[IoSlice<'_>]) -> Poll<io::Result<usize>> {
        match &mut self.get_mut().inner {
            ConnectionInner::Recording(io) => Pin::new(io).poll_write_vectored(cx, bufs),
            ConnectionInner::Unrecorded(io) => Pin::new(io).poll_write_vectored(cx, bufs),
        }
    }
    fn is_write_vectored(&self) -> bool {
        match &self.inner {
            ConnectionInner::Recording(io) => io.is_write_vectored(),
            ConnectionInner::Unrecorded(io) => io.is_write_vectored(),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().inner {
            ConnectionInner::Recording(io) => Pin::new(io).poll_flush(cx),
            ConnectionInner::Unrecorded(io) => Pin::new(io).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().inner {
            ConnectionInner::Recording(io) => Pin::new(io).poll_shutdown(cx),
            ConnectionInner::Unrecorded(io) => Pin::new(io).poll_shutdown(cx),
        }
    }
}

// No source error object or arbitrary destructor is stored under this mutex.
#[derive(Clone, Copy)]
enum Completion {
    Connected,
    Failed { kind: io::ErrorKind, raw: Option<i32> },
}
struct Journal(Arc<Mutex<Option<Completion>>>);
impl AsyncRead for Journal {
    fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 { return Poll::Ready(Ok(())); }
        let result = self.0.lock().take();
        match result {
            None => Poll::Pending,
            Some(Completion::Connected) => {
                buf.put_slice(&[CONNECTED]);
                Poll::Ready(Ok(()))
            }
            Some(Completion::Failed { kind, raw }) => {
                Poll::Ready(Err(raw.map_or_else(|| io::Error::from(kind), io::Error::from_raw_os_error)))
            }
        }
    }
}
impl AsyncWrite for Journal {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_write_vectored(self: Pin<&mut Self>, _: &mut Context<'_>, bufs: &[IoSlice<'_>]) -> Poll<io::Result<usize>> {
        Poll::Ready(bufs.iter().try_fold(0usize, |total, buf| total.checked_add(buf.len()))
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput)))
    }
    fn is_write_vectored(&self) -> bool { true }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
}

// The connector is an opaque, caller-authorized effect provider. Its internals
// cannot also use this session's providers, or replay would wait for effects
// hidden inside a factory that offline execution intentionally never invokes.
// Guards reject that overlap, but never hold a lock while running source code.
struct OpaqueConnect<F> {
    future: Option<Pin<Box<F>>>,
    timeline: Arc<CaptureTimeline>,
    effect: GroupEffect,
}
impl<F: Future> Future for OpaqueConnect<F> {
    type Output = F::Output;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let guard = this.timeline.begin();
        let result = this.future.as_mut().expect("owned connector future").as_mut().poll(cx);
        if let Some(guard) = guard { guard.finish(this.effect, false); }
        result
    }
}
impl<F> Drop for OpaqueConnect<F> {
    fn drop(&mut self) {
        let guard = self.timeline.begin();
        drop(self.future.take());
        if let Some(guard) = guard { guard.finish(self.effect, false); }
    }
}

impl<S: TimeSource + ?Sized> RecordingGroupSession<S> {
    fn connection_capture_failure(&self, error: GroupSessionCaptureError) {
        self.timeline.state.lock().failure.get_or_insert(error);
    }

    fn begin_connection(
        &self,
        attempt: ConnectionAttempt,
        request: &[u8],
        max_request_bytes: usize,
        completion: Arc<Mutex<Option<Completion>>>,
    ) -> Option<GroupRecordingIo<Journal>> {
        let offered = REQUEST_DOMAIN.len().checked_add(8).and_then(|n| n.checked_add(request.len()));
        if request.len() > max_request_bytes || offered.is_none() {
            self.connection_capture_failure(GroupSessionCaptureError::Limit("connection request bytes"));
            return None;
        }
        // A journal has precisely two operations. Data limits remain unchanged;
        // the group's global stream/effect limits include these logical records.
        let limits = IoCaptureLimits::new(2, 1, offered.expect("checked request extent"), 3);
        let mut journal = match self.register_with_limits(attempt.journal, Journal(completion), limits) {
            Ok(journal) => journal,
            Err(refusal) => {
                self.connection_capture_failure(refusal.error);
                return None;
            }
        };
        let target = attempt.stream.to_le_bytes();
        let request = [IoSlice::new(REQUEST_DOMAIN), IoSlice::new(&target), IoSlice::new(request)];
        let result = Pin::new(&mut journal).poll_write_vectored(&mut Context::from_waker(Waker::noop()), &request);
        if !matches!(result, Poll::Ready(Ok(n)) if Some(n) == offered) {
            self.connection_capture_failure(GroupSessionCaptureError::Coverage);
        }
        Some(journal)
    }

    /// Observe a real asynchronous connection attempt, including failed retries.
    ///
    /// `connect` is invoked once, on the first poll, and supplies an already
    /// authorized opaque connector (TCP, TLS, a tunnel, or an application dialer).
    /// Bind every behavior-affecting target/protocol/authentication option into
    /// the stable `request` key. Request bytes are fingerprinted, not logged.
    /// The wrapper grants no capability and does not weaken peer authentication.
    ///
    /// Native errors are returned unchanged; replay preserves their kind/native
    /// code, not custom error strings/payloads. Capture-limit and ID-collision
    /// failures never replace a real result: a successful provider still forwards
    /// normally, but `finish` refuses the entire window. Return successful owners
    /// with `RecordingConnection::into_inner` after their users drain.
    ///
    /// Each attempt consumes one journal identity and two timeline effects; a
    /// success also consumes its data identity. `max_request_bytes` bounds extra
    /// request hashing, not execution. Journals use private limits of two ops,
    /// one read byte and three vectored slices, independently of data-stream
    /// limits. Import limits must admit both. One pinned source future is owned
    /// per active attempt; provider memory and runtime admission are separate.
    ///
    /// Source construction, polls, destruction and capability queries must not
    /// use THIS session's wrapped providers. Such overlap refuses capture. Other
    /// tasks may use the session between source polls. No lock crosses a callback
    /// or `Pending`. Dropping an attempted connection drops its source future and
    /// refuses capture rather than inventing a cancellation result. No task is
    /// spawned/detached and the source's cancellation semantics are unchanged.
    /// Pending counts/wakeup timing and DNS/TLS internals are not reproduced.
    pub async fn connect_with<T, F, Fut>(
        &self,
        attempt: ConnectionAttempt,
        request: &[u8],
        max_request_bytes: usize,
        connect: F,
    ) -> io::Result<RecordingConnection<T>>
    where
        T: AsyncWrite,
        F: FnOnce() -> Fut,
        Fut: Future<Output = io::Result<T>>,
    {
        let completion = Arc::new(Mutex::new(None));
        let journal = self.begin_connection(attempt, request, max_request_bytes, Arc::clone(&completion));
        let effect = attempt.effect(IoOperation::Read);
        let future = {
            let guard = self.timeline.begin();
            let future = connect();
            if let Some(guard) = guard { guard.finish(effect, false); }
            future
        };
        let mut source = OpaqueConnect { future: Some(Box::pin(future)), timeline: Arc::clone(&self.timeline), effect };
        let result = (&mut source).await;
        // The source future must really be destroyed before completion is
        // recorded. Destructor effects/panics cannot escape that boundary.
        drop(source);
        let result = match result {
            Ok(io) => {
                let inner = if journal.is_some() {
                    let guard = self.timeline.begin();
                    let registered = self.register(attempt.stream, io);
                    if let Some(guard) = guard { guard.finish(effect, false); }
                    match registered {
                        Ok(io) => ConnectionInner::Recording(io),
                        Err(refusal) => {
                            self.connection_capture_failure(refusal.error);
                            ConnectionInner::Unrecorded(refusal.io)
                        }
                    }
                } else {
                    ConnectionInner::Unrecorded(io)
                };
                *completion.lock() = Some(Completion::Connected);
                Ok(RecordingConnection { inner })
            }
            Err(error) => {
                *completion.lock() = Some(Completion::Failed { kind: error.kind(), raw: error.raw_os_error() });
                Err(error)
            }
        };
        if let Some(mut journal) = journal {
            let mut byte = [0];
            let mut buf = ReadBuf::new(&mut byte);
            let observed = Pin::new(&mut journal).poll_read(&mut Context::from_waker(Waker::noop()), &mut buf);
            let valid = match (&result, observed) {
                (Ok(_), Poll::Ready(Ok(()))) => buf.filled() == [CONNECTED],
                (Err(original), Poll::Ready(Err(recorded))) => original.kind() == recorded.kind()
                    && original.raw_os_error() == recorded.raw_os_error(),
                _ => false,
            };
            if !valid { self.connection_capture_failure(GroupSessionCaptureError::Coverage); }
            journal.into_inner();
        }
        result
    }
}

impl ReplayGroupSession {
    fn connection_replay_failure(&self, attempt: ConnectionAttempt, operation: IoOperation) -> io::Error {
        // Use the existing failure/fanout path. Even when the next effect's
        // category happens to match, finish(false) cannot consume that turn.
        let error = match self.timeline.enter(attempt.effect(operation)) {
            Err(error) => error,
            Ok(guard) => guard.finish(false).expect_err("invalid connection evidence cannot commit"),
        };
        io::Error::new(io::ErrorKind::InvalidData, error)
    }

    /// Reproduce one recorded connection outcome without any live connector.
    ///
    /// The same `ConnectionAttempt` and exact request key are required. An early
    /// attempt or completion parks on the shared timeline, including clock,
    /// entropy and other connection prerequisites. Failed attempts return the
    /// recorded I/O error; successful attempts open only their bound data stream.
    /// There is no socket creation, DNS, TLS, factory invocation or RNG fallback.
    ///
    /// Reused/unknown identities, changed requests, malformed success records
    /// and missing data streams invalidate the group, even if their errors are
    /// ignored. Dropping an attempted connection with unconsumed evidence also
    /// invalidates replay. As with `open`, all users must drain before requiring
    /// `verify_complete`, `run` or `run_send` to accept the consumer's result.
    pub async fn connect(&self, attempt: ConnectionAttempt, request: &[u8]) -> io::Result<GroupReplayIo> {
        let mut journal = self.open(attempt.journal)
            .map_err(|_| self.connection_replay_failure(attempt, IoOperation::WriteVectored))?;
        let target = attempt.stream.to_le_bytes();
        let offered = REQUEST_DOMAIN.len().checked_add(target.len()).and_then(|n| n.checked_add(request.len()))
            .ok_or_else(|| self.connection_replay_failure(attempt, IoOperation::WriteVectored))?;
        let request = [IoSlice::new(REQUEST_DOMAIN), IoSlice::new(&target), IoSlice::new(request)];
        let written = poll_fn(|cx| Pin::new(&mut journal).poll_write_vectored(cx, &request)).await?;
        if written != offered {
            return Err(self.connection_replay_failure(attempt, IoOperation::WriteVectored));
        }
        let mut byte = [0];
        let count = poll_fn(|cx| {
            let mut buf = ReadBuf::new(&mut byte);
            Pin::new(&mut journal).poll_read(cx, &mut buf).map(|result| result.map(|()| buf.filled().len()))
        }).await?;
        let remaining = self.timeline.state.lock().slots[journal.index].remaining;
        if count != 1 || byte[0] != CONNECTED || remaining != 0 {
            return Err(self.connection_replay_failure(attempt, IoOperation::Read));
        }
        self.open(attempt.stream)
            .map_err(|_| self.connection_replay_failure(attempt, IoOperation::Read))
    }
}

#[cfg(test)]
mod tests;
