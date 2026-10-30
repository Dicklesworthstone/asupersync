//! Live request bodies and produced responses over one HTTP/1.1 + HTTP/2 port.

use super::{
    AutoCoordinator, HandoffQueue, Http1Listener, Http2Listener, Http2Options,
    HttpAutoListenerConfig, HttpAutoShutdownStats, ProtocolService, TaskSpawner,
    acknowledge_coordinator_cancellation,
};
use crate::cx::Cx;
use crate::http::h1::server::Http1StreamingConfig;
use crate::http::h1::stream::{Http1ProducedResponse, StreamingServerRequest};
use crate::http::h2::listener::{Http2ProducedResponse, Http2StreamingListenerConfig};
use crate::net::tcp::listener::TcpListener;
use crate::runtime::RuntimeHandle;
use crate::server::shutdown::ShutdownSignal;
#[cfg(feature = "tls")]
use crate::tls::TlsAcceptor;
use std::future::Future;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

/// One port with live request ingress and supervised response producers.
///
/// Protocol selection, detection limits, TLS ALPN, shutdown, and retained task
/// retirement use the same coordinator as [super::HttpAutoListener]. Each
/// protocol uses its existing streaming implementation, including request
/// admission, bounded body queues, flow control, response trailers, and the
/// request-region close barrier before successful final response framing.
///
/// The two handlers have the protocols' established signatures. HTTP/1.1 takes
/// a Cx and StreamingServerRequest and returns Http1ProducedResponse; HTTP/2
/// takes StreamingServerRequest and returns Http2ProducedResponse. The HTTP/2
/// handler runs under its request Cx, available through Cx::current. A handler
/// may move the incoming body into its response producer to stream a duplex
/// exchange without collecting the complete upload or response.
///
/// HTTP/1.1 retains its one-response connection policy for produced responses.
/// HTTP/2 retains multiplexing and per-stream admission. Neither protocol's
/// handler, body policy, or buffered response adapter is silently selected for
/// the other protocol. Existing buffered listeners are unaffected.
pub struct HttpAutoStreamingListener<F1, F2> {
    coordinator: AutoCoordinator,
    http1_handler: Arc<F1>,
    http2_handler: Arc<F2>,
    http1_streaming: Http1StreamingConfig,
    http2_streaming: Http2StreamingListenerConfig,
    http2_options: Http2Options,
}

impl<F1, F2, Fut1, Fut2> HttpAutoStreamingListener<F1, F2>
where
    F1: Fn(Cx, StreamingServerRequest) -> Fut1 + Send + Sync + 'static,
    F2: Fn(StreamingServerRequest) -> Fut2 + Send + Sync + 'static,
    Fut1: Future<Output = Http1ProducedResponse> + Send + 'static,
    Fut2: Future<Output = Http2ProducedResponse> + Send + 'static,
{
    /// Bind a shared port with explicit handlers for both streaming protocols.
    ///
    /// Connection limits and deadlines come from the supplied configuration.
    /// Streaming queue and unread-body limits start at their protocol defaults;
    /// complete Router-produced configurations can be attached with
    /// [Self::with_http1_streaming_config] and
    /// [Self::with_http2_streaming_config].
    pub async fn bind<A: ToSocketAddrs + Send + 'static>(
        addr: A,
        http1_handler: F1,
        http2_handler: F2,
        config: HttpAutoListenerConfig,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self::from_listener(listener, http1_handler, http2_handler, config))
    }

    /// Prepare streaming dispatch on an existing socket without starting tasks.
    #[must_use]
    pub fn from_listener(
        listener: TcpListener,
        http1_handler: F1,
        http2_handler: F2,
        config: HttpAutoListenerConfig,
    ) -> Self {
        let http1_streaming = Http1StreamingConfig::from(config.http1.http_config.clone());
        let mut http2_streaming = Http2StreamingListenerConfig::default();
        http2_streaming.listener = config.http2.clone();
        Self {
            coordinator: AutoCoordinator {
                listener,
                config,
                shutdown_signal: ShutdownSignal::new(),
                #[cfg(feature = "tls")]
                tls_acceptor: None,
            },
            http1_handler: Arc::new(http1_handler),
            http2_handler: Arc::new(http2_handler),
            http1_streaming,
            http2_streaming,
            http2_options: Http2Options::default(),
        }
    }

    /// Serve under runtime ownership and await both protocols' retirement.
    ///
    /// Each protocol task owns its connections and actual request regions.
    /// Shutdown closes admission, cancels pending protocol detection, and
    /// drains both streaming protocols under their configured budgets.
    /// Dropping this future requests cleanup but does not certify its completion.
    pub async fn run(self, runtime: &RuntimeHandle) -> io::Result<HttpAutoShutdownStats> {
        let result = self.run_with(TaskSpawner::Root(runtime.clone())).await;
        acknowledge_coordinator_cancellation();
        result
    }

    /// Keep listener, detection, connection and request tasks in cx's region.
    ///
    /// Owner cancellation or either protocol task ending stops acceptance and
    /// drains its sibling. The returned statistics follow actual retained-task
    /// retirement. A context without runtime spawn wiring is refused.
    pub async fn run_in(self, cx: &Cx) -> io::Result<HttpAutoShutdownStats> {
        let result = self.run_with(TaskSpawner::Owned(cx.clone())).await;
        acknowledge_coordinator_cancellation();
        result
    }

    async fn run_with(self, spawner: TaskSpawner) -> io::Result<HttpAutoShutdownStats> {
        // Refuse invalid ingress reservations before either protocol can start.
        self.http2_streaming.validate()?;
        let http1_queue = Arc::new(HandoffQueue::default());
        let http2_queue = Arc::new(HandoffQueue::default());
        let handler = self.http1_handler;
        let http1 = Http1Listener::from_handoff(
            Arc::clone(&http1_queue),
            move |cx: Cx, request: StreamingServerRequest| (*handler)(cx, request),
            self.coordinator.config.http1.clone(),
        )
        .with_streaming_config(self.http1_streaming);
        let handler = self.http2_handler;
        let http2 = self.http2_options.apply(Http2Listener::from_handoff_streaming_produced(
            Arc::clone(&http2_queue),
            move |request: StreamingServerRequest| (*handler)(request),
            self.http2_streaming,
        ));
        let http1 = ProtocolService {
            queue: http1_queue,
            manager: http1.connection_manager().clone(),
            run: move |child: TaskSpawner| async move {
                // Even the runtime-root entry uses real request subregions,
                // including their finalizer barrier before final wire framing.
                let cx = match child {
                    TaskSpawner::Owned(cx) => cx,
                    TaskSpawner::Root(_) => Cx::current().ok_or_else(|| {
                        io::Error::other("streaming HTTP/1.1 task has no runtime context")
                    })?,
                };
                http1.run_produced_owned_in(&cx).await
            },
        };
        let http2 = ProtocolService {
            queue: http2_queue,
            manager: http2.connection_manager().clone(),
            run: move |child: TaskSpawner| async move {
                match child {
                    TaskSpawner::Root(runtime) => http2.run_streaming_produced(&runtime).await,
                    TaskSpawner::Owned(cx) => http2.run_streaming_produced_in(&cx).await,
                }
            },
        };
        self.coordinator.run(spawner, http1, http2).await
    }
}

impl<F1, F2> HttpAutoStreamingListener<F1, F2> {
    /// Preserve the complete HTTP/1.1 streaming and route-admission policy.
    ///
    /// Its connection configuration replaces the HTTP/1.1 connection settings.
    /// Listener capacity, shutdown budgets, and time source remain those from
    /// HttpAutoListenerConfig::http1.
    #[must_use]
    pub fn with_http1_streaming_config(mut self, config: Http1StreamingConfig) -> Self {
        self.coordinator.config.http1.http_config = config.connection.clone();
        self.http1_streaming = config;
        self
    }

    /// Preserve the complete HTTP/2 streaming and route-admission policy.
    ///
    /// Its embedded listener configuration replaces HttpAutoListenerConfig::http2,
    /// including its drain budgets and host policy. Explicit http2_* builder
    /// overrides remain authoritative regardless of builder call order.
    #[must_use]
    pub fn with_http2_streaming_config(mut self, config: Http2StreamingListenerConfig) -> Self {
        self.coordinator.config.http2 = config.listener.clone();
        self.http2_streaming = config;
        self
    }

    /// Negotiate h2 or HTTP/1.1 over TLS before handing off the same transport.
    ///
    /// The acceptor must advertise h2; absent ALPN selects HTTP/1.1.
    /// Handshakes use the acceptor's timeout or the detection timeout.
    #[cfg(feature = "tls")]
    #[must_use]
    pub fn with_tls(mut self, acceptor: TlsAcceptor) -> Self {
        self.coordinator.tls_acceptor = Some(acceptor);
        self
    }

    /// Bound receipt of the HTTP/2 preface after TLS or cleartext selection.
    #[must_use]
    pub fn http2_preface_timeout(mut self, timeout: Duration) -> Self {
        self.http2_options.preface_timeout = Some(timeout);
        self
    }

    /// Bound HTTP/2 transport writes, flushes and shutdown without progress.
    #[must_use]
    pub fn http2_write_progress_timeout(mut self, timeout: Duration) -> Self {
        self.http2_options.write_progress_timeout = Some(timeout);
        self
    }

    /// Bound response DATA stalls caused by exhausted HTTP/2 flow-control credit.
    #[must_use]
    pub fn http2_flow_control_progress_timeout(mut self, timeout: Duration) -> Self {
        self.http2_options.flow_control_progress_timeout = Some(timeout);
        self
    }

    /// Enable HTTP/2 connection keepalive; off by default.
    #[must_use]
    pub fn http2_keepalive(mut self, interval: Duration, timeout: Duration) -> Self {
        self.http2_options.keepalive = Some((interval, timeout));
        self
    }

    /// Bound admitted HTTP/2 requests across this listener's connections.
    #[must_use]
    pub fn http2_max_in_flight_requests(mut self, max: NonZeroUsize) -> Self {
        self.http2_options.max_in_flight_requests = Some(max);
        self
    }

    /// Bound admitted HTTP/2 request coordinators on each connection.
    #[must_use]
    pub fn http2_max_connection_in_flight_requests(mut self, max: NonZeroUsize) -> Self {
        self.http2_options.max_connection_in_flight_requests = Some(max);
        self
    }

    /// Return the shared TCP address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.coordinator.listener.local_addr()
    }

    /// Stop acceptance and drain both protocols with one shared shutdown signal.
    #[must_use]
    pub fn shutdown_signal(&self) -> ShutdownSignal {
        self.coordinator.shutdown_signal.clone()
    }
}
