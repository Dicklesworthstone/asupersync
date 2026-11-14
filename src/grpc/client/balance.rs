//! Endpoint-set routing for native gRPC calls.
//!
//! Selection is synchronous and shared by every clone. Each RPC selects one
//! available endpoint and retains that channel for its entire lifetime. A
//! failed or cancelled call is never replayed against another endpoint.

use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::sync::{Arc, Mutex};

use crate::cx::Cx;
use crate::io::{AsyncRead, AsyncWrite};

use super::super::codec::{Codec, IdentityCodec};
use super::super::native_stream::{
    CallDeadline, NativeDuplexStream, NativeServerStream, check_cancellation,
};
use super::super::status::Status;
use super::super::streaming::{Request, Response};
use super::{Channel, ClientInterceptor, GrpcClient, channel_target_is_loopback, lock_unpoisoned};

/// Maximum endpoints accepted by one [`BalancedChannel`].
///
/// The bound limits the synchronous scan when endpoints are unavailable. It
/// does not limit the number of calls; configure each channel's unary
/// admission limits to bound concurrent unary exchanges and queued callers.
pub const MAX_BALANCED_ENDPOINTS: usize = 1024;

struct EndpointSet {
    channels: Vec<Channel>,
    routing: Mutex<Routing>,
}

struct Routing {
    available: Vec<bool>,
    next: usize,
}

/// A fixed set of native channels with shared round-robin selection.
///
/// Each configured channel retains its own TLS identity, proxy, connection
/// policy, compression, limits, idle unary pool and unary admission budgets.
/// Cloning this set shares those channels, the selection cursor, and explicit
/// availability. A call selects once; a transport failure, application status,
/// admission refusal or cancellation never causes a second selection.
///
/// Endpoints are initially available. Availability is an operator or health
/// controller decision, not an inferred transport health check. Disabling an
/// endpoint excludes it from later selections without interrupting a call
/// that already selected it. Re-enabling it restores eligibility. No probe,
/// discovery task or automatic failure-based ejection is started.
///
/// Unary admission is local to the selected endpoint. A saturated endpoint
/// queues or refuses according to its own channel configuration; the balancer
/// does not move an admitted call to a less busy server. Native streaming
/// calls retain dedicated connections and do not consume unary admission.
#[derive(Clone)]
pub struct BalancedChannel {
    inner: Arc<EndpointSet>,
}

impl fmt::Debug for BalancedChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let routing = lock_unpoisoned(&self.inner.routing);
        f.debug_struct("BalancedChannel")
            .field("channels", &self.inner.channels)
            .field("available", &routing.available)
            .field("next", &routing.next)
            .finish()
    }
}

impl BalancedChannel {
    /// Build a set containing between one and [`MAX_BALANCED_ENDPOINTS`]
    /// native channels, preserving their supplied order.
    ///
    /// The constructor is lazy: it opens no sockets. Empty or oversized sets
    /// and deterministic `loopback` channels return `INVALID_ARGUMENT`.
    /// Repeated destinations are permitted; separately built channels may
    /// intentionally use different transport identities or admission policy.
    pub fn new(channels: Vec<Channel>) -> Result<Self, Status> {
        if channels.is_empty() || channels.len() > MAX_BALANCED_ENDPOINTS {
            return Err(Status::invalid_argument(format!(
                "balanced gRPC requires 1..={MAX_BALANCED_ENDPOINTS} endpoints"
            )));
        }
        if channels
            .iter()
            .any(|channel| channel_target_is_loopback(channel.uri()))
        {
            return Err(Status::invalid_argument(
                "balanced gRPC requires native channels, not deterministic loopback",
            ));
        }
        let available = vec![true; channels.len()];
        Ok(Self {
            inner: Arc::new(EndpointSet {
                channels,
                routing: Mutex::new(Routing { available, next: 0 }),
            }),
        })
    }

    /// Configured channels in stable endpoint-index order.
    #[must_use]
    pub fn endpoints(&self) -> &[Channel] {
        &self.inner.channels
    }

    /// The channel at one stable endpoint index, if present.
    #[must_use]
    pub fn endpoint(&self, index: usize) -> Option<&Channel> {
        self.inner.channels.get(index)
    }

    /// Current routing availability, or `None` for an unknown endpoint index.
    ///
    /// This is a selection snapshot, not a statement about a live connection.
    #[must_use]
    pub fn is_available(&self, index: usize) -> Option<bool> {
        lock_unpoisoned(&self.inner.routing)
            .available
            .get(index)
            .copied()
    }

    /// Change an endpoint's eligibility for future selections across clones.
    ///
    /// Returns `INVALID_ARGUMENT` for an unknown index. Calls that already
    /// selected the endpoint keep their transport and original deadline.
    pub fn set_available(&self, index: usize, available: bool) -> Result<(), Status> {
        let mut routing = lock_unpoisoned(&self.inner.routing);
        let slot = routing
            .available
            .get_mut(index)
            .ok_or_else(|| Status::invalid_argument("unknown balanced gRPC endpoint index"))?;
        *slot = available;
        Ok(())
    }

    fn select(&self) -> Result<Channel, Status> {
        let mut routing = lock_unpoisoned(&self.inner.routing);
        let count = self.inner.channels.len();
        for offset in 0..count {
            // Both operands are bounded by MAX_BALANCED_ENDPOINTS.
            let index = (routing.next + offset) % count;
            if routing.available[index] {
                routing.next = (index + 1) % count;
                return Ok(self.inner.channels[index].clone());
            }
        }
        Err(Status::unavailable(
            "no balanced gRPC endpoint is available",
        ))
    }
}

/// Concurrent native gRPC calls over a [`BalancedChannel`].
///
/// Each call obtains a fresh codec from the supplied factory, so even a
/// non-`Clone` codec can be transferred into an owned stream. The factory
/// runs once after selection under the explicit caller context, outside the
/// routing lock. Clones share routing, channels and the factory, but each
/// retains its own interceptor list. No codec or transport is shared between
/// different streaming calls.
///
/// A call captures one absolute deadline before invoking its codec factory
/// or interceptors. The deadline is the minimum of the request timeout, the
/// selected channel timeout and the caller's budget. An interceptor can
/// tighten it; it cannot extend or remove it. The outgoing timeout shrinks
/// after encoding and unary admission. Synchronous user code cannot be
/// preempted, but an expired call refuses before subsequent network I/O.
/// Cancellation, timers and I/O authority always belong to the supplied `Cx`.
///
/// ```no_run
/// use asupersync::{Cx, bytes::Bytes};
/// use asupersync::grpc::{BalancedChannel, BalancedGrpcClient, Channel, Request, Status};
///
/// async fn echo(cx: &Cx) -> Result<Bytes, Status> {
///     let first = Channel::builder("http://localhost:50051")
///         .reuse_connections(4).connect().await.map_err(|error| error.into_status())?;
///     let second = Channel::builder("http://localhost:50052")
///         .reuse_connections(4).connect().await.map_err(|error| error.into_status())?;
///     let endpoints = BalancedChannel::new(vec![first, second])?;
///     let client = BalancedGrpcClient::new(endpoints);
///     Ok(client.unary(cx, "/example.Echo/Call", Request::new(Bytes::new()))
///         .await?.into_inner())
/// }
/// ```
pub struct BalancedGrpcClient<C = IdentityCodec> {
    channel: BalancedChannel,
    codec_factory: Arc<dyn Fn() -> C + Send + Sync>,
    client_interceptors: Vec<Arc<dyn ClientInterceptor>>,
}

impl<C> Clone for BalancedGrpcClient<C> {
    fn clone(&self) -> Self {
        Self {
            channel: self.channel.clone(),
            codec_factory: Arc::clone(&self.codec_factory),
            client_interceptors: self.client_interceptors.clone(),
        }
    }
}

impl<C> fmt::Debug for BalancedGrpcClient<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BalancedGrpcClient")
            .field("channel", &self.channel)
            .field("interceptor_count", &self.client_interceptors.len())
            .finish_non_exhaustive()
    }
}

impl BalancedGrpcClient<IdentityCodec> {
    /// Create a client whose messages are already-serialized bytes.
    #[must_use]
    pub fn new(channel: BalancedChannel) -> Self {
        Self::with_codec_factory(channel, || IdentityCodec)
    }
}

impl<C: Codec> BalancedGrpcClient<C> {
    /// Create a client with a thread-safe factory for one fresh codec per RPC.
    ///
    /// The factory must return an independent codec instance suitable for one
    /// call. It need not be `Clone`, and it is never invoked while the routing
    /// lock is held. Its work consumes the call's deadline allowance.
    #[must_use]
    pub fn with_codec_factory(
        channel: BalancedChannel,
        factory: impl Fn() -> C + Send + Sync + 'static,
    ) -> Self {
        Self {
            channel,
            codec_factory: Arc::new(factory),
            client_interceptors: Vec::new(),
        }
    }

    /// Shared endpoint set and availability controls.
    #[must_use]
    pub fn channel(&self) -> &BalancedChannel {
        &self.channel
    }

    /// Append an interceptor run once for every call made by this client.
    #[must_use]
    pub fn with_interceptor<I: ClientInterceptor + 'static>(mut self, interceptor: I) -> Self {
        self.client_interceptors.push(Arc::new(interceptor));
        self
    }

    /// Append an interceptor without changing clones already made.
    pub fn add_interceptor<I: ClientInterceptor + 'static>(&mut self, interceptor: I) {
        self.client_interceptors.push(Arc::new(interceptor));
    }

    /// Number of interceptors applied by this client.
    #[must_use]
    pub fn interceptor_count(&self) -> usize {
        self.client_interceptors.len()
    }

    fn start<T>(
        &self,
        cx: &Cx,
        path: &str,
        request: &Request<T>,
    ) -> Result<(GrpcClient<C>, CallDeadline), Status> {
        check_cancellation(cx)?;
        super::validate_rpc_path(path)?;
        if !cx.runtime_mask.has(crate::cx::cap::CapMask::IO) || cx.io_driver_handle().is_none() {
            return Err(Status::failed_precondition(
                "balanced gRPC calls require runtime I/O authority",
            ));
        }
        let channel = self.channel.select()?;
        let deadline = CallDeadline::capture(cx, request.metadata(), channel.config().timeout)?;
        let codec = (self.codec_factory)();
        check_cancellation(cx)?;
        deadline.check()?;
        let mut client = GrpcClient::with_codec(channel, codec);
        client.client_interceptors = self.client_interceptors.clone();
        check_cancellation(cx)?;
        deadline.check()?;
        Ok((client, deadline))
    }

    /// Make one typed unary call on the next available endpoint.
    ///
    /// The selected channel's idle pool and unary admission are shared with
    /// other calls through its clones. Refusals and transport/application
    /// errors never reselect an endpoint or replay the RPC at another server.
    /// The channel's existing recovery from a stale pooled connection is
    /// preserved only when that attempt provably did not process the request.
    pub async fn unary(
        &self,
        cx: &Cx,
        path: &str,
        request: Request<C::Encode>,
    ) -> Result<Response<C::Decode>, Status> {
        with_context(cx, async {
            let (mut client, mut deadline) = self.start(cx, path, &request)?;
            let metadata = client.build_admitted_metadata(cx, &request, path, &mut deadline)?;
            client
                .native_unary(path, metadata, request.into_inner(), Some(deadline))
                .await
        })
        .await
    }

    /// Start a server-streaming call on one selected endpoint.
    ///
    /// The returned owner retains its codec, context and original deadline;
    /// dropping it closes its dedicated transport. Poll `message()` through
    /// the terminal status. Availability changes affect only later calls.
    pub async fn server_streaming(
        &self,
        cx: &Cx,
        path: &str,
        request: Request<C::Encode>,
    ) -> Result<
        NativeServerStream<impl AsyncRead + AsyncWrite + Unpin + Send + 'static + use<C>, C>,
        Status,
    > {
        with_context(cx, async {
            let (client, deadline) = self.start(cx, path, &request)?;
            client
                .native_server_streaming_admitted(cx, path, request, Some(deadline))
                .await
        })
        .await
    }

    /// Start a client-streaming or bidirectional call on one selected endpoint.
    ///
    /// The unit request supplies metadata. Use the owner's `queue_message`,
    /// `next_event` and `close_requests` methods to drive bounded upload and
    /// receive progress. It owns a dedicated connection; no background task,
    /// automatic replay or unary admission slot is created.
    pub async fn duplex(
        &self,
        cx: &Cx,
        path: &str,
        request: Request<()>,
    ) -> Result<
        NativeDuplexStream<impl AsyncRead + AsyncWrite + Unpin + Send + 'static + use<C>, C>,
        Status,
    > {
        with_context(cx, async {
            let (client, deadline) = self.start(cx, path, &request)?;
            client
                .native_duplex_admitted(cx, path, request, Some(deadline))
                .await
        })
        .await
    }
}

async fn with_context<T>(cx: &Cx, future: impl Future<Output = T>) -> T {
    let mut future = pin!(future);
    poll_fn(|task| {
        let _current = cx.clone().set_current_restricted();
        future.as_mut().poll(task)
    })
    .await
}

#[cfg(test)]
#[path = "balance_tests.rs"]
mod tests;
