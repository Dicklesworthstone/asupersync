//! Connection establishment for the existing demand-driven stream owner.

use super::{
    CallDeadline, NativeDuplexStream, NativeServerStream, NativeStreamConfig, check_cancellation,
    io_status, request_headers,
};
use crate::cx::{CancelWakerToken, Cx};
use crate::grpc::codec::Codec;
use crate::grpc::{Request, Status};
use crate::net::TcpStream;
use crate::time::{Sleep, TimerDriverHandle};
#[cfg(feature = "tls")]
use crate::tls::{TlsConnector, TlsStream};
use crate::types::Time;
use std::future::{Future, poll_fn};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

/// A TCP destination, logical HTTP authority, and setup time limit.
///
/// This is a connection factory for [`NativeServerStream`] and
/// [`NativeDuplexStream`]. Each call owns a fresh TCP connection, with no
/// background stream driver or pool. The destination chooses where bytes go;
/// the authority is an HTTP routing label, not authentication.
///
/// The setup timeout covers resolution, dialing, optional TLS, codec setup and
/// initial headers. Server-stream setup waits for response headers; duplex
/// setup flushes request headers so callers can begin uploading immediately.
/// It is separate from the optional whole-call timeout: a Watch with no call
/// deadline can continue after successful setup. Every phase observes one
/// absolute setup deadline, met with the request and caller's whole-call bound.
/// A dropped setup future closes any connection it has acquired. It does not
/// cancel the parent or promise acknowledged remote cleanup.
#[derive(Debug, Clone)]
pub struct NativeStreamEndpoint {
    destination: Destination,
    authority: String,
    setup_timeout: Duration,
}

#[derive(Debug, Clone)]
enum Destination {
    Address(SocketAddr),
    Host(String, u16),
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
        if address.port() == 0
            || setup_timeout.is_zero()
            || authority.is_empty()
            || authority.len() > 64 * 1024
            || authority.bytes().any(|byte| {
                !byte.is_ascii_graphic() || matches!(byte, b'/' | b'\\' | b'?' | b'#' | b'@')
            })
        {
            return Err(Status::invalid_argument(
                "invalid native streaming endpoint",
            ));
        }
        Ok(Self {
            destination: Destination::Address(address),
            authority,
            setup_timeout,
        })
    }

    /// Resolve a hostname when each call connects, within its setup deadline.
    ///
    /// `host` is an ASCII DNS name or unbracketed IP literal, without a port.
    /// Use an IDNA-encoded name for international hostnames. HTTP authority and
    /// TLS identity remain explicit and independent of this dial destination.
    /// Resolution uses the native offloaded system resolver, preserving its
    /// hosts-file/search-domain behavior. Dropping or timing out setup discards
    /// its result; an OS lookup already running on a blocking worker can finish
    /// afterward. No socket is opened from that abandoned result.
    ///
    /// Resolved addresses are attempted in order under one absolute deadline.
    /// An unreachable first address may consume the budget; this method does
    /// not promise Happy Eyeballs or retry a started RPC.
    ///
    /// # Errors
    /// Rejects invalid host syntax, port zero, an invalid HTTP authority, or a
    /// zero setup timeout before resolution or network I/O.
    pub fn from_host(
        host: impl Into<String>,
        port: u16,
        authority: impl Into<String>,
        setup_timeout: Duration,
    ) -> Result<Self, Status> {
        let host = host.into();
        let dns = host.strip_suffix('.').unwrap_or(&host);
        if host.parse::<IpAddr>().is_err()
            && (dns.is_empty()
                || dns.len() > 253
                || !dns.split('.').all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && !label.starts_with('-')
                        && !label.ends_with('-')
                        && label
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                }))
        {
            return Err(Status::invalid_argument(
                "invalid native streaming hostname",
            ));
        }
        let mut endpoint = Self::new(
            SocketAddr::from(([0, 0, 0, 0], port)),
            authority,
            setup_timeout,
        )?;
        endpoint.destination = Destination::Host(host, port);
        Ok(endpoint)
    }

    async fn dial(&self, setup: &mut Setup) -> Result<TcpStream, Status> {
        let remaining = setup.remaining();
        setup
            .run(async {
                match &self.destination {
                    Destination::Address(address) => {
                        TcpStream::connect_timeout(*address, remaining).await
                    }
                    Destination::Host(host, port) => {
                        TcpStream::connect_timeout((host.clone(), *port), remaining).await
                    }
                }
                .map_err(io_status)
            })
            .await
    }

    /// Connect over plaintext TCP and wait for the response's initial headers.
    ///
    /// Requires a native I/O driver, an enabled I/O capability mask, and a timer
    /// driver on the explicit `cx`; no virtual `IoCap` is needed. Another task's
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
            return Err(Status::invalid_argument(
                "plaintext streaming requires the http scheme",
            ));
        }
        let (admitted, mut setup) = self.admit(cx, path, &request, &config)?;
        let io = self.dial(&mut setup).await?;
        let mut stream = NativeServerStream::new_admitted(
            cx,
            io,
            &self.authority,
            path,
            request,
            codec,
            config,
            Some(admitted),
        )?;
        setup
            .run(async { stream.headers().await.map(|_| ()) })
            .await?;
        Ok(stream)
    }

    /// Connect with a caller-owned TLS policy and require negotiated HTTP/2.
    ///
    /// The endpoint destination selects the socket, `server_name` selects the TLS
    /// identity, and the endpoint's authority selects HTTP routing. The supplied
    /// connector retains its certificate, client-authentication and pinning
    /// policy; no trust store or verifier is substituted here. Configure it to
    /// offer `h2` ALPN. TLS success without `h2` refuses before any gRPC bytes.
    /// This method accepts only the `https` scheme and never retries plaintext.
    ///
    /// One setup deadline covers resolution, TCP, handshake, codec setup and initial headers.
    /// The original whole-call deadline then remains on the returned stream,
    /// including time spent connecting. With no whole-call deadline, a Watch
    /// may outlive the setup interval after its headers have arrived. A shorter
    /// timeout configured on the TLS connector remains effective too.
    ///
    /// Each stage is polled under the explicit `cx`, not an unrelated ambient
    /// task. Dropping setup retires its acquired transport, without cancelling
    /// the parent or promising acknowledged remote cleanup. Synchronous codec
    /// callbacks cannot be preempted; late results are rejected at the boundary.
    /// Existing plaintext and preconnected-transport APIs are unchanged.
    ///
    /// # Errors
    /// Invalid scheme, server name, configuration, metadata or missing explicit
    /// capabilities refuse before dialing. TLS/certificate/ALPN failures return
    /// `UNAVAILABLE`; observed cancellation or elapsed setup takes precedence.
    /// A successful return proves initial headers, not a successful RPC: consume
    /// `message()` through the terminal status as for [`Self::connect_tcp`].
    ///
    /// ```no_run
    /// use asupersync::{Cx, bytes::Bytes, tls::TlsConnector};
    /// use asupersync::grpc::{Request, Status, codec::IdentityCodec};
    /// use asupersync::grpc::native_stream::{NativeStreamEndpoint, NativeStreamConfig};
    /// use std::time::Duration;
    ///
    /// async fn watch(cx: &Cx, connector: &TlsConnector) -> Result<(), Status> {
    ///     // The deployment supplies the resolved address and trust policy.
    ///     let endpoint = NativeStreamEndpoint::new(
    ///         "127.0.0.1:8443".parse().unwrap(), "service.example:8443",
    ///         Duration::from_secs(5),
    ///     )?;
    ///     let mut stream = endpoint.connect_tls(
    ///         cx, "service.example", connector, "/example.Service/Watch",
    ///         Request::new(Bytes::new()), IdentityCodec,
    ///         NativeStreamConfig { scheme: "https", ..Default::default() },
    ///     ).await?;
    ///     while let Some(message) = stream.message().await? {
    ///         cx.trace(&format!("received {} bytes", message.len()));
    ///     }
    ///     Ok(())
    /// }
    /// ```
    #[cfg(feature = "tls")]
    #[allow(clippy::too_many_arguments)] // Keep TLS authority explicit at this boundary.
    pub async fn connect_tls<C: Codec>(
        &self,
        cx: &Cx,
        server_name: &str,
        connector: &TlsConnector,
        path: &str,
        request: Request<C::Encode>,
        codec: C,
        config: NativeStreamConfig,
    ) -> Result<NativeServerStream<TlsStream<TcpStream>, C>, Status> {
        if config.scheme != "https" {
            return Err(Status::invalid_argument(
                "TLS streaming requires the https scheme",
            ));
        }
        TlsConnector::validate_domain(server_name)
            .map_err(|_| Status::invalid_argument("invalid gRPC TLS server name"))?;
        let (admitted, mut setup) = self.admit(cx, path, &request, &config)?;
        let tcp = self.dial(&mut setup).await?;
        let tls = setup
            .run(async {
                let tls = connector
                    .connect(server_name, tcp)
                    .await
                    .map_err(|_| Status::unavailable("native gRPC TLS handshake failed"))?;
                if tls.alpn_protocol() != Some(b"h2".as_slice()) {
                    return Err(Status::unavailable(
                        "native gRPC TLS peer did not negotiate h2",
                    ));
                }
                Ok(tls)
            })
            .await?;
        let mut stream = setup
            .run(async {
                NativeServerStream::new_admitted(
                    cx,
                    tls,
                    &self.authority,
                    path,
                    request,
                    codec,
                    config,
                    Some(admitted),
                )
            })
            .await?;
        setup
            .run(async { stream.headers().await.map(|_| ()) })
            .await?;
        Ok(stream)
    }

    /// Connect a client-streaming or bidi call and flush its request headers.
    ///
    /// This returns without waiting for response headers, allowing servers to
    /// wait for the upload before replying. Consume the initial
    /// [`super::NativeDuplexEvent::RequestFlushed`] event, then queue messages
    /// while driving both directions with [`NativeDuplexStream::next_event`].
    /// No response events are consumed during setup. A successful connection
    /// does not prove RPC success; consume through terminal trailers.
    ///
    /// The same explicit I/O/timer authority, metadata validation, HTTP scheme
    /// restriction, setup cancellation and absolute deadlines as
    /// [`Self::connect_tcp`] apply. The whole-call deadline includes setup.
    pub async fn connect_duplex_tcp<C: Codec>(
        &self,
        cx: &Cx,
        path: &str,
        request: Request<()>,
        codec: C,
        config: NativeStreamConfig,
    ) -> Result<NativeDuplexStream<TcpStream, C>, Status> {
        if config.scheme != "http" {
            return Err(Status::invalid_argument(
                "plaintext streaming requires the http scheme",
            ));
        }
        let (admitted, mut setup) = self.admit(cx, path, &request, &config)?;
        let io = self.dial(&mut setup).await?;
        let mut stream = setup
            .run(async {
                NativeDuplexStream::new_admitted(
                    cx,
                    io,
                    &self.authority,
                    path,
                    request,
                    codec,
                    config,
                    Some(admitted),
                )
            })
            .await?;
        setup.run(stream.flush_initial_headers()).await?;
        Ok(stream)
    }

    /// Connect a streaming request with the supplied TLS policy and h2 ALPN.
    ///
    /// Identity, certificate, client-authentication and ALPN checks match
    /// [`Self::connect_tls`]. This accepts only HTTPS and never falls back to
    /// plaintext. Setup flushes request headers instead of waiting for the
    /// peer's response; upload begins as described by [`Self::connect_duplex_tcp`].
    /// One absolute setup budget covers resolution, TCP, TLS and header flush.
    #[cfg(feature = "tls")]
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_duplex_tls<C: Codec>(
        &self,
        cx: &Cx,
        server_name: &str,
        connector: &TlsConnector,
        path: &str,
        request: Request<()>,
        codec: C,
        config: NativeStreamConfig,
    ) -> Result<NativeDuplexStream<TlsStream<TcpStream>, C>, Status> {
        if config.scheme != "https" {
            return Err(Status::invalid_argument(
                "TLS streaming requires the https scheme",
            ));
        }
        TlsConnector::validate_domain(server_name)
            .map_err(|_| Status::invalid_argument("invalid gRPC TLS server name"))?;
        let (admitted, mut setup) = self.admit(cx, path, &request, &config)?;
        let tcp = self.dial(&mut setup).await?;
        let tls = setup
            .run(async {
                let tls = connector
                    .connect(server_name, tcp)
                    .await
                    .map_err(|_| Status::unavailable("native gRPC TLS handshake failed"))?;
                if tls.alpn_protocol() != Some(b"h2".as_slice()) {
                    return Err(Status::unavailable(
                        "native gRPC TLS peer did not negotiate h2",
                    ));
                }
                Ok(tls)
            })
            .await?;
        let mut stream = setup
            .run(async {
                NativeDuplexStream::new_admitted(
                    cx,
                    tls,
                    &self.authority,
                    path,
                    request,
                    codec,
                    config,
                    Some(admitted),
                )
            })
            .await?;
        setup.run(stream.flush_initial_headers()).await?;
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
        // Native tasks carry a reactor, not the optional virtual/browser IoCap.
        // The raw driver accessor is also used for inheritance and does not
        // apply attenuation, so require the explicit context's IO mask here.
        if !cx.runtime_mask.has(crate::cx::cap::CapMask::IO) || cx.io_driver_handle().is_none() {
            return Err(Status::failed_precondition(
                "native streaming connect requires explicit I/O authority",
            ));
        }
        let clock = cx.timer_driver().ok_or_else(|| {
            Status::failed_precondition("native streaming setup requires an explicit timer driver")
        })?;
        let started = clock.now();
        config.validate()?;
        config.frame_hooks()?;
        let admitted = CallDeadline::capture(cx, request.metadata(), config.timeout)?;
        request_headers(
            &self.authority,
            path,
            request.metadata(),
            config,
            admitted.at.map(|at| (at, started)),
        )?;
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
            cx,
            until,
            timer: Box::pin(Sleep::with_timer_driver(until, clock.clone())),
            clock,
            cancelled: None,
        }
    }

    fn check(&self) -> Result<(), Status> {
        check_cancellation(&self.cx)?;
        if self.clock.now() >= self.until {
            return Err(Status::deadline_exceeded(
                "native gRPC connection setup deadline exceeded",
            ));
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
            return Err(Status::deadline_exceeded(
                "native gRPC connection setup deadline exceeded",
            ));
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
            if let Err(error) = self.gate(task) {
                return Poll::Ready(Err(error));
            }
            match future.as_mut().poll(task) {
                Poll::Ready(result) => {
                    // Even a synchronous stage cannot publish a late success.
                    // A losing returned transport is dropped here, not leaked.
                    Poll::Ready(self.check().and(result))
                }
                Poll::Pending => Poll::Pending,
            }
        })
        .await
    }
}

impl Drop for Setup {
    fn drop(&mut self) {
        if let Some(token) = self.cancelled.take() {
            self.cx.clear_cancel_waker(token);
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(all(test, feature = "tls"))]
mod tls_tests;
