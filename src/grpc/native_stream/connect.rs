//! Connection establishment for the existing demand-driven stream owner.

use super::{
    CallDeadline, NativeServerStream, NativeStreamConfig, check_cancellation,
    io_status, request_headers,
};
use crate::cx::{CancelWakerToken, Cx};
use crate::grpc::codec::Codec;
use crate::grpc::{Request, Status};
use crate::net::TcpStream;
use crate::time::{Sleep, TimerDriverHandle};
use crate::types::Time;
use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

/// A resolved TCP destination, logical HTTP authority, and setup time limit.
///
/// This is a connection factory for [`NativeServerStream`], not another stream
/// implementation or connection pool. It performs no DNS resolution and starts
/// no detached tasks. Each call owns a fresh TCP connection. The address chooses
/// where bytes go; the authority is an HTTP routing label, not authentication.
///
/// The setup timeout covers dialing, codec setup and initial response headers.
/// It is separate from the optional whole-call timeout: a Watch with no call
/// deadline can continue after successful setup. Every phase observes one
/// absolute setup deadline, met with the request and caller's whole-call bound.
/// A dropped setup future closes any connection it has acquired. It does not
/// cancel the parent or promise acknowledged remote cleanup.
#[derive(Debug, Clone)]
pub struct NativeStreamEndpoint {
    address: SocketAddr,
    authority: String,
    setup_timeout: Duration,
}

impl NativeStreamEndpoint {
    /// Describe a resolved endpoint without performing network I/O.
    ///
    /// # Errors
    /// Rejects port zero, an empty/non-HTTP authority, authorities over 64 KiB,
    /// or a zero setup timeout. Call configuration may impose a tighter bound.
    pub fn new(
        address: SocketAddr,
        authority: impl Into<String>,
        setup_timeout: Duration,
    ) -> Result<Self, Status> {
        let authority = authority.into();
        if address.port() == 0 || setup_timeout.is_zero() || authority.is_empty()
            || authority.len() > 64 * 1024
            || authority.bytes().any(|byte| {
                !byte.is_ascii_graphic() || matches!(byte, b'/' | b'\\' | b'?' | b'#' | b'@')
            })
        {
            return Err(Status::invalid_argument("invalid native streaming endpoint"));
        }
        Ok(Self { address, authority, setup_timeout })
    }

    /// Connect over plaintext TCP and wait for the response's initial headers.
    ///
    /// Requires I/O and a timer driver on the explicit `cx`. Another task's
    /// ambient context cannot supply either. Configuration and metadata are
    /// validated before dialing; user codec encoding runs after connection and
    /// before sending request bytes. An encoding error closes that connection.
    ///
    /// This method accepts only `config.scheme == "http"`. It never silently
    /// downgrades an HTTPS request. A successful return means headers arrived,
    /// NOT that the RPC succeeded: consume `message()` through its final status.
    /// Dropping the setup wait is not resumable; only borrowing waits on the
    /// returned stream retain progress. No request retry is performed.
    ///
    /// ```no_run
    /// use asupersync::{Cx, bytes::Bytes};
    /// use asupersync::grpc::{Request, Status, codec::IdentityCodec};
    /// use asupersync::grpc::native_stream::{NativeStreamEndpoint, NativeStreamConfig};
    /// use std::time::Duration;
    ///
    /// async fn call(cx: &Cx) -> Result<(), Status> {
    ///     let endpoint = NativeStreamEndpoint::new(
    ///         "127.0.0.1:50051".parse().unwrap(), "localhost:50051",
    ///         Duration::from_secs(5),
    ///     )?;
    ///     let mut stream = endpoint.connect_tcp(
    ///         cx, "/example.Service/Watch", Request::new(Bytes::new()),
    ///         IdentityCodec, NativeStreamConfig::default(),
    ///     ).await?;
    ///     while let Some(message) = stream.message().await? {
    ///         cx.trace(&format!("received {} bytes", message.len()));
    ///     }
    ///     Ok(())
    /// }
    /// ```
    pub async fn connect_tcp<C: Codec>(
        &self,
        cx: &Cx,
        path: &str,
        request: Request<C::Encode>,
        codec: C,
        config: NativeStreamConfig,
    ) -> Result<NativeServerStream<TcpStream, C>, Status> {
        if config.scheme != "http" {
            return Err(Status::invalid_argument("plaintext streaming requires the http scheme"));
        }
        let (admitted, mut setup) = self.admit(cx, path, &request, &config)?;
        let remaining = setup.remaining();
        let io = setup.run(async {
            TcpStream::connect_timeout(self.address, remaining).await.map_err(io_status)
        }).await?;
        let mut stream = NativeServerStream::new_admitted(
            cx, io, &self.authority, path, request, codec, config, Some(admitted),
        )?;
        setup.run(async { stream.headers().await.map(|_| ()) }).await?;
        Ok(stream)
    }

    fn admit<T>(
        &self,
        cx: &Cx,
        path: &str,
        request: &Request<T>,
        config: &NativeStreamConfig,
    ) -> Result<(CallDeadline, Setup), Status> {
        check_cancellation(cx)?;
        if !cx.has_io() || cx.io_driver_handle().is_none() {
            return Err(Status::failed_precondition("native streaming connect requires explicit I/O authority"));
        }
        let clock = cx.timer_driver().ok_or_else(|| {
            Status::failed_precondition("native streaming setup requires an explicit timer driver")
        })?;
        let started = clock.now();
        config.validate()?;
        config.frame_hooks()?;
        let admitted = CallDeadline::capture(cx, request.metadata(), config.timeout)?;
        request_headers(&self.authority, path, request.metadata(), config, admitted.at.map(|at| (at, started)))?;
        let until = admitted.at.map_or(started + self.setup_timeout, |at| {
            at.min(started + self.setup_timeout)
        });
        let setup = Setup::new(cx.clone(), clock, until);
        setup.check()?;
        Ok((admitted, setup))
    }
}

// One retained timer and cancellation registration cover every setup phase.
// Neither phase transitions nor dropped nested waits restart either budget.
struct Setup {
    cx: Cx,
    clock: TimerDriverHandle,
    until: Time,
    timer: Pin<Box<Sleep>>,
    cancelled: Option<CancelWakerToken>,
}

impl Setup {
    fn new(cx: Cx, clock: TimerDriverHandle, until: Time) -> Self {
        Self {
            cx, until,
            timer: Box::pin(Sleep::with_timer_driver(until, clock.clone())),
            clock, cancelled: None,
        }
    }

    fn check(&self) -> Result<(), Status> {
        check_cancellation(&self.cx)?;
        if self.clock.now() >= self.until {
            return Err(Status::deadline_exceeded("native gRPC connection setup deadline exceeded"));
        }
        Ok(())
    }

    fn remaining(&self) -> Duration {
        Duration::from_nanos(self.until.duration_since(self.clock.now()))
    }

    fn gate(&mut self, task: &mut Context<'_>) -> Result<(), Status> {
        self.check()?;
        self.cancelled = Some(self.cx.refresh_cancel_waker(self.cancelled, task.waker()));
        self.check()?;
        if self.timer.as_mut().poll(task).is_ready() {
            return Err(Status::deadline_exceeded("native gRPC connection setup deadline exceeded"));
        }
        Ok(())
    }

    async fn run<T, F>(&mut self, future: F) -> Result<T, Status>
    where
        F: Future<Output = Result<T, Status>>,
    {
        let mut future = std::pin::pin!(future);
        poll_fn(|task| {
            let _ambient = Cx::set_current(Some(self.cx.clone()));
            if let Err(error) = self.gate(task) { return Poll::Ready(Err(error)); }
            match future.as_mut().poll(task) {
                Poll::Ready(result) => {
                    // Even a synchronous stage cannot publish a late success.
                    // A losing returned transport is dropped here, not leaked.
                    Poll::Ready(self.check().and(result))
                }
                Poll::Pending => Poll::Pending,
            }
        }).await
    }
}

impl Drop for Setup {
    fn drop(&mut self) {
        if let Some(token) = self.cancelled.take() { self.cx.clear_cancel_waker(token); }
    }
}

#[cfg(test)]
mod tests;
