//! HTTP/1.1 and HTTP/2 on one port.
//!
//! [`Http1Listener`] and [`Http2Listener`] each own a socket and speak one
//! protocol, so a service that must answer both (a TLS endpoint where
//! browsers negotiate `h2` and other clients `http/1.1`, gRPC next to a
//! REST API, a proxy sending cleartext HTTP/2 with prior knowledge) needed two
//! ports. [`HttpAutoListener`] accepts each connection once, decides its
//! protocol, and hands it to an HTTP/1.1 or an HTTP/2 listener that serve the
//! same handler with their own configuration, limits, drain and statistics:
//!
//! - over TLS, by the ALPN protocol the client negotiated (`h2`, else
//!   HTTP/1.1, including clients that send no ALPN);
//! - in cleartext, by the first bytes: the HTTP/2 connection preface means
//!   HTTP/2 with prior knowledge, anything else HTTP/1.1. The bytes read to
//!   decide are replayed to the chosen protocol.
//!
//! ```ignore
//! let app = Router::new().route("/", get(FnHandler::new(index))).into_http_handler();
//! let listener = HttpAutoListener::bind("0.0.0.0:8443", app, config).await?
//!     .with_tls(acceptor); // advertising ALPN ["h2", "http/1.1"]
//! let stats = listener.run(&runtime_handle).await?;
//! ```

use super::handoff::{HandoffQueue, Prefixed};
use crate::cx::Cx;
use crate::http::h1::listener::{Http1Listener, Http1ListenerConfig};
use crate::http::h1::server::IntoHttp1Response;
use crate::http::h1::types::Request;
use crate::http::h2::connection::CLIENT_PREFACE;
use crate::http::h2::listener::{Http2Listener, Http2ListenerConfig, IntoHttp2Response};
use crate::io::AsyncReadExt;
use crate::net::tcp::listener::TcpListener;
use crate::net::tcp::stream::TcpStream;
use crate::runtime::RuntimeHandle;
use crate::server::shutdown::{ShutdownSignal, ShutdownStats};
#[cfg(feature = "tls")]
use crate::tls::TlsAcceptor;
use crate::types::Time;
use std::future::Future;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Duration;

/// Configuration of an [`HttpAutoListener`]: one configuration per protocol,
/// and the bounds on deciding a connection's protocol.
#[derive(Debug, Clone)]
pub struct HttpAutoListenerConfig {
    /// The HTTP/1.1 listener's configuration (host policy, limits, drain).
    pub http1: Http1ListenerConfig,
    /// The HTTP/2 listener's configuration (host policy, limits, drain).
    pub http2: Http2ListenerConfig,
    /// How long a connection may take to complete its TLS handshake, or to
    /// send enough bytes to tell HTTP/2's preface from an HTTP/1.1 request,
    /// before it is dropped. Default 10 seconds.
    pub detect_timeout: Duration,
    /// Connections whose protocol is being decided at once; more are dropped
    /// as they arrive. Default 1024.
    pub max_detecting: usize,
}

impl Default for HttpAutoListenerConfig {
    fn default() -> Self {
        Self {
            http1: Http1ListenerConfig::default(),
            http2: Http2ListenerConfig::default(),
            detect_timeout: Duration::from_secs(10),
            max_detecting: 1024,
        }
    }
}

impl HttpAutoListenerConfig {
    /// Sets the HTTP/1.1 listener's configuration.
    #[must_use]
    pub fn http1(mut self, config: Http1ListenerConfig) -> Self {
        self.http1 = config;
        self
    }

    /// Sets the HTTP/2 listener's configuration.
    #[must_use]
    pub fn http2(mut self, config: Http2ListenerConfig) -> Self {
        self.http2 = config;
        self
    }

    /// Sets the protocol-detection deadline.
    #[must_use]
    pub const fn detect_timeout(mut self, timeout: Duration) -> Self {
        self.detect_timeout = timeout;
        self
    }

    /// Sets how many connections may be in protocol detection at once.
    #[must_use]
    pub const fn max_detecting(mut self, max: usize) -> Self {
        self.max_detecting = max;
        self
    }
}

/// What each protocol's listener reported after the drain.
#[derive(Debug, Clone)]
pub struct HttpAutoShutdownStats {
    /// The HTTP/1.1 listener's shutdown statistics.
    pub http1: ShutdownStats,
    /// The HTTP/2 listener's shutdown statistics.
    pub http2: ShutdownStats,
}

/// One TCP listener serving HTTP/1.1 and HTTP/2; see the
/// [module documentation](self).
///
/// Each protocol's listener applies its own configuration: its host policy,
/// `max_connections` (so the port admits up to the sum), body limits and
/// drain timeouts. HTTP/1.1 protocol upgrades fail closed on these
/// connections, as on `Http1Listener::run_tls`, because the public upgrade
/// callback is typed to a raw TCP stream.
pub struct HttpAutoListener<F> {
    listener: TcpListener,
    handler: Arc<F>,
    config: HttpAutoListenerConfig,
    shutdown_signal: ShutdownSignal,
    #[cfg(feature = "tls")]
    tls_acceptor: Option<TlsAcceptor>,
}

impl<F, Fut, R> HttpAutoListener<F>
where
    F: Fn(Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = R> + Send + 'static,
    R: IntoHttp1Response + IntoHttp2Response + Send + 'static,
{
    /// Binds `addr` and serves `handler` over both protocols.
    ///
    /// # Errors
    /// The bind error.
    pub async fn bind<A: ToSocketAddrs + Send + 'static>(
        addr: A,
        handler: F,
        config: HttpAutoListenerConfig,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self::from_listener(listener, handler, config))
    }

    /// Serves `handler` over both protocols on an existing listener.
    #[must_use]
    pub fn from_listener(
        listener: TcpListener,
        handler: F,
        config: HttpAutoListenerConfig,
    ) -> Self {
        Self {
            listener,
            handler: Arc::new(handler),
            config,
            shutdown_signal: ShutdownSignal::new(),
            #[cfg(feature = "tls")]
            tls_acceptor: None,
        }
    }

    /// Serves every connection over TLS and picks its protocol by ALPN. The
    /// acceptor should advertise `h2` and `http/1.1`; a client that
    /// negotiates anything but `h2`, or no ALPN, is served HTTP/1.1. Its
    /// handshake is bounded by the acceptor's handshake timeout, else by
    /// [`HttpAutoListenerConfig::detect_timeout`].
    #[cfg(feature = "tls")]
    #[must_use]
    pub fn with_tls(mut self, acceptor: TlsAcceptor) -> Self {
        self.tls_acceptor = Some(acceptor);
        self
    }

    /// The bound address.
    ///
    /// # Errors
    /// The socket's error.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// The signal that stops accepting: `begin_drain` on it drains both
    /// protocols' listeners, each within its own drain timeouts.
    #[must_use]
    pub fn shutdown_signal(&self) -> ShutdownSignal {
        self.shutdown_signal.clone()
    }

    /// Accepts until the shutdown signal begins draining, then drains both
    /// protocols' listeners and returns their statistics.
    ///
    /// # Errors
    /// A non-transient accept error (after draining the connections already
    /// handed over), or either listener's error.
    pub async fn run(self, runtime: &RuntimeHandle) -> io::Result<HttpAutoShutdownStats> {
        let http1_queue = Arc::new(HandoffQueue::default());
        let http2_queue = Arc::new(HandoffQueue::default());
        let handler = Arc::clone(&self.handler);
        let http1_drain = self.config.http1.drain_timeout;
        let http1 = Http1Listener::from_handoff(
            Arc::clone(&http1_queue),
            move |request: Request| (*handler)(request),
            self.config.http1.clone(),
        );
        let handler = Arc::clone(&self.handler);
        let http2_drain = self.config.http2.drain_timeout;
        let http2 = Http2Listener::from_handoff(
            Arc::clone(&http2_queue),
            move |request: Request| (*handler)(request),
            self.config.http2.clone(),
        );
        let http1_manager = http1.connection_manager().clone();
        let http2_manager = http2.connection_manager().clone();
        let http1_runtime = runtime.clone();
        let http1_run = runtime
            .try_spawn(async move { http1.run(&http1_runtime).await })
            .map_err(|error| io::Error::other(format!("spawn HTTP/1.1 listener: {error}")))?;
        let http2_runtime = runtime.clone();
        let http2_run = runtime
            .try_spawn(async move { http2.run(&http2_runtime).await })
            .map_err(|error| io::Error::other(format!("spawn HTTP/2 listener: {error}")))?;

        let detecting = Arc::new(AtomicUsize::new(0));
        let accept_result = self
            .accept_loop(runtime, &http1_queue, &http2_queue, &detecting)
            .await;

        let _ = self
            .shutdown_signal
            .begin_drain(http1_drain.max(http2_drain));
        let _ = http1_manager.begin_drain(http1_drain);
        let _ = http2_manager.begin_drain(http2_drain);
        let http1_stats = http1_run.await;
        let http2_stats = http2_run.await;
        accept_result?;
        Ok(HttpAutoShutdownStats {
            http1: http1_stats?,
            http2: http2_stats?,
        })
    }

    async fn accept_loop(
        &self,
        runtime: &RuntimeHandle,
        http1_queue: &Arc<HandoffQueue>,
        http2_queue: &Arc<HandoffQueue>,
        detecting: &Arc<AtomicUsize>,
    ) -> io::Result<()> {
        let mut shutdown = self.shutdown_signal.subscribe();
        let mut transient_streak: u32 = 0;
        loop {
            if self.shutdown_signal.is_shutting_down() {
                return Ok(());
            }
            let accepted = {
                let mut accept = pin!(self.listener.accept());
                let mut stop = pin!(shutdown.wait());
                std::future::poll_fn(|cx| {
                    if self.shutdown_signal.is_shutting_down() || stop.as_mut().poll(cx).is_ready()
                    {
                        return Poll::Ready(None);
                    }
                    accept.as_mut().poll(cx).map(Some)
                })
                .await
            };
            let Some(accepted) = accepted else {
                return Ok(());
            };
            let (stream, peer) = match accepted {
                Ok(connection) => {
                    transient_streak = 0;
                    connection
                }
                Err(error) if is_transient_accept_error(&error) => {
                    // Back off so a persistent condition (EMFILE) does not spin.
                    transient_streak = transient_streak.saturating_add(1);
                    let delay = Duration::from_millis(2_u64 << transient_streak.min(5));
                    crate::time::sleep(now(), delay).await;
                    continue;
                }
                Err(error) => return Err(error),
            };
            if detecting.fetch_add(1, Ordering::AcqRel) >= self.config.max_detecting {
                detecting.fetch_sub(1, Ordering::AcqRel);
                drop(stream);
                continue;
            }
            // Owned by the detection future, so the slot is released even if
            // the future is dropped without running.
            let slot = DetectionSlot(Arc::clone(detecting));
            let detection = Detection {
                http1: Arc::clone(http1_queue),
                http2: Arc::clone(http2_queue),
                #[cfg(feature = "tls")]
                tls: self.tls_acceptor.clone(),
                timeout: self.config.detect_timeout,
                shutdown: self.shutdown_signal.clone(),
            };
            // A spawn failure drops the future, and with it the connection and
            // its detection slot.
            let _ = runtime.try_spawn(detection.hand_off(stream, peer, slot));
        }
    }
}

fn now() -> Time {
    Cx::current()
        .and_then(|cx| cx.timer_driver())
        .map_or_else(crate::time::wall_now, |timer| timer.now())
}

fn is_transient_accept_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::Interrupted
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::TimedOut
            | io::ErrorKind::OutOfMemory
    ) || matches!(error.raw_os_error(), Some(23 | 24 | 105))
}

/// One accepted connection on its way to a protocol's listener.
struct Detection {
    http1: Arc<HandoffQueue>,
    http2: Arc<HandoffQueue>,
    #[cfg(feature = "tls")]
    tls: Option<TlsAcceptor>,
    timeout: Duration,
    shutdown: ShutdownSignal,
}

impl Detection {
    async fn hand_off(self, stream: TcpStream, peer: SocketAddr, slot: DetectionSlot) {
        let _slot = slot;
        #[cfg(feature = "tls")]
        if let Some(acceptor) = &self.tls {
            let bound = acceptor.handshake_timeout().unwrap_or(self.timeout);
            let Ok(Ok(tls)) = crate::time::timeout(now(), bound, acceptor.accept(stream)).await
            else {
                return;
            };
            let http2 = tls.alpn_protocol() == Some(b"h2".as_slice());
            self.push(http2, Box::new(tls), peer);
            return;
        }
        let mut stream = stream;
        let mut seen = Vec::with_capacity(CLIENT_PREFACE.len());
        let decided = crate::time::timeout(
            now(),
            self.timeout,
            read_until_decided(&mut stream, &mut seen),
        )
        .await;
        let Ok(Ok(Some(http2))) = decided else {
            return;
        };
        self.push(http2, Box::new(Prefixed::new(seen, stream)), peer);
    }

    fn push(&self, http2: bool, stream: super::handoff::HandoffStream, peer: SocketAddr) {
        // A connection decided after the drain began is closed, not queued
        // for a listener that no longer accepts.
        if self.shutdown.is_shutting_down() {
            return;
        }
        let queue = if http2 { &self.http2 } else { &self.http1 };
        queue.push(stream, Some(peer));
    }
}

/// Reads until the bytes stop matching HTTP/2's connection preface
/// (`Some(false)`: HTTP/1.1) or match all of it (`Some(true)`). `None` when
/// the peer closes first.
async fn read_until_decided(
    stream: &mut TcpStream,
    seen: &mut Vec<u8>,
) -> io::Result<Option<bool>> {
    let mut buf = [0_u8; 24];
    loop {
        let wanted = CLIENT_PREFACE.len() - seen.len();
        let read = AsyncReadExt::read(stream, &mut buf[..wanted]).await?;
        if read == 0 {
            return Ok(None);
        }
        seen.extend_from_slice(&buf[..read]);
        if !CLIENT_PREFACE.starts_with(seen) {
            return Ok(Some(false));
        }
        if seen.len() == CLIENT_PREFACE.len() {
            return Ok(Some(true));
        }
    }
}

/// Releases a detection slot when the detection ends, however it ends.
struct DetectionSlot(Arc<AtomicUsize>);

impl Drop for DetectionSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}
