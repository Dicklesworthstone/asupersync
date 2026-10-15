//! Callable, authenticated gRPC Health Check and Watch on registered transports.
//!
//! [`HealthService::rpc_service`] opts an existing health registry into real
//! protobuf dispatch. Register the returned service with [`super::Server`] and
//! use `bind_registered_streaming_http2` / `serve_streaming_http2` for Watch.
//! Existing `HealthService` registration and in-process methods are unchanged.
//!
//! Authentication and status policy come from the supplied registry. In
//! particular, its default requires authentication, and an unknown named Check
//! retains the existing `PERMISSION_DENIED` anti-enumeration policy rather than
//! the standard protocol's `NOT_FOUND`. Watch reports `SERVICE_UNKNOWN` and
//! stays subscribed. Empty-name checks and watches keep the registry's existing
//! aggregate-status semantics. This adapter implements Check and Watch, not List.
//!
//! Watch has a fixed active-subscription cap shared by clones. It uses the
//! registry's latest-status observation, not an unbounded update queue: a slow
//! consumer may see coalesced transitions. The native streaming transport owns
//! cancellation, framing, deadlines and bounded outbound buffering. Direct
//! consumers of the service hook own polling and dropping the returned stream.

use super::health::{
    HealthCheckRequest, HealthCheckResponse, HealthService, HealthWatchStream,
    MAX_SERVICE_NAME_LEN,
};
use super::service::{
    NamedService, RegisteredServerStream, ServiceDescriptor, ServiceHandler,
    ServiceHandlerFuture, ServiceStreamingFuture,
};
use super::status::Status;
use super::streaming::{Metadata, Request, Streaming};
use crate::bytes::Bytes;
use crate::cx::Cx;
use crate::types::CancelKind;
use prost::Message as _;
use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

/// Maximum serialized HealthCheckRequest admitted before protobuf decoding.
///
/// Unknown protobuf fields are accepted within this bound. The decoded service
/// name independently obeys [`MAX_SERVICE_NAME_LEN`]. Transport framing and
/// metadata retain the server's own limits.
pub const MAX_HEALTH_RPC_REQUEST_BYTES: usize = 4096;

const CHECK_PATH: &str = "/grpc.health.v1.Health/Check";
const WATCH_PATH: &str = "/grpc.health.v1.Health/Watch";

// Private wire types preserve the established public health message structs.
// An enum's int32 representation is identical on the protobuf wire.
#[derive(Clone, PartialEq, prost::Message)]
struct WireRequest {
    #[prost(string, tag = "1")]
    service: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct WireResponse {
    #[prost(int32, tag = "1")]
    status: i32,
}

struct WatchAdmission {
    capacity: usize,
    active: AtomicUsize,
}

struct WatchSlot(Arc<WatchAdmission>);

impl WatchAdmission {
    fn acquire(self: &Arc<Self>) -> Result<WatchSlot, Status> {
        let mut active = self.active.load(Ordering::Relaxed);
        loop {
            if active >= self.capacity {
                return Err(Status::resource_exhausted("health watch capacity exhausted"));
            }
            match self.active.compare_exchange_weak(
                active,
                active + 1, // Strict comparison above also excludes usize overflow.
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(WatchSlot(Arc::clone(self))),
                Err(observed) => active = observed,
            }
        }
    }
}

impl Drop for WatchSlot {
    fn drop(&mut self) {
        let previous = self.0.active.fetch_sub(1, Ordering::Relaxed);
        debug_assert!(previous > 0, "health watch admission underflow");
    }
}

/// Cloneable callable view of one existing health registry and watch budget.
///
/// Construct with [`HealthService::rpc_service`]. Clones share the subscription
/// cap; separately constructed views have independent caps. A zero cap disables
/// Watch without disabling Check. Saturation refuses immediately without a
/// waiter queue. A slot covers the returned source's lifetime, including time
/// spent blocked behind the native response producer. It does not account for
/// application-owned request buffers or transport buffers after source drop.
#[derive(Clone)]
pub struct HealthRpcService {
    health: HealthService,
    admission: Arc<WatchAdmission>,
}

impl fmt::Debug for HealthRpcService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HealthRpcService")
            .field("watch_capacity", &self.watch_capacity())
            .field("active_watches", &self.active_watches())
            .finish_non_exhaustive()
    }
}

impl HealthService {
    /// Expose authenticated protobuf Check/Watch through registered gRPC routing.
    ///
    /// Register this view instead of the legacy metadata-only `HealthService`.
    /// Both use the same registry: status and reporter changes immediately feed
    /// existing watches. No socket, task, watch or new authentication authority
    /// is created here. Use the server's registered streaming listener for Watch.
    ///
    /// ```
    /// use asupersync::grpc::{HealthService, Server, ServingStatus};
    /// use asupersync::grpc::health::HealthAuthMode;
    ///
    /// // Supply a deployment-owned credential, not this example value.
    /// let health = HealthService::with_auth_mode(
    ///     HealthAuthMode::bearer_token("example-only"),
    /// );
    /// let rpc = health.rpc_service(128);
    /// let server = Server::builder().add_service(rpc.clone()).build();
    /// health.set_status("package.Service", ServingStatus::Serving);
    /// assert_eq!(rpc.active_watches(), 0); // Registration starts no work.
    /// assert!(server.get_service("grpc.health.v1.Health").is_some());
    /// ```
    #[must_use]
    pub fn rpc_service(&self, max_watches: usize) -> HealthRpcService {
        HealthRpcService {
            health: self.clone(),
            admission: Arc::new(WatchAdmission {
                capacity: max_watches,
                active: AtomicUsize::new(0),
            }),
        }
    }
}

impl HealthRpcService {
    /// Currently retained Watch sources across every clone of this view.
    #[must_use]
    pub fn active_watches(&self) -> usize {
        self.admission.active.load(Ordering::Relaxed)
    }

    /// Maximum concurrent Watch sources; zero deliberately refuses Watch.
    #[must_use]
    pub fn watch_capacity(&self) -> usize {
        self.admission.capacity
    }
}

fn checkpoint(cx: &Cx) -> Result<(), Status> {
    cx.checkpoint().map_err(|_| match cx.cancel_reason().map(|reason| reason.kind) {
        Some(CancelKind::Timeout | CancelKind::Deadline) => {
            Status::deadline_exceeded("health RPC deadline exceeded")
        }
        Some(CancelKind::PollQuota | CancelKind::CostBudget) => {
            Status::resource_exhausted("health RPC budget exhausted")
        }
        _ => Status::cancelled("health RPC cancelled"),
    })
}

fn decode_request(request: Request<Bytes>) -> Result<Request<HealthCheckRequest>, Status> {
    if request.get_ref().len() > MAX_HEALTH_RPC_REQUEST_BYTES {
        return Err(Status::resource_exhausted("health request exceeds its byte limit"));
    }
    let decoded = WireRequest::decode(request.get_ref().as_ref())
        .map_err(|_| Status::invalid_argument("invalid health request protobuf"))?;
    if decoded.service.len() > MAX_SERVICE_NAME_LEN {
        return Err(Status::invalid_argument("health service name exceeds its byte limit"));
    }
    Ok(request.map(|_| HealthCheckRequest::new(decoded.service)))
}

fn encode_response(response: HealthCheckResponse) -> Bytes {
    Bytes::from(
        WireResponse {
            status: response.status as i32,
        }
        .encode_to_vec(),
    )
}

impl NamedService for HealthRpcService {
    const NAME: &'static str = HealthService::NAME;
}

impl ServiceHandler for HealthRpcService {
    fn descriptor(&self) -> &ServiceDescriptor {
        self.health.descriptor()
    }

    fn method_names(&self) -> Vec<&str> {
        self.health.method_names()
    }

    fn call_unary<'a>(
        &'a self,
        cx: &'a Cx,
        path: &'a str,
        request: Request<Bytes>,
        _trailing_metadata: Metadata,
    ) -> ServiceHandlerFuture<'a> {
        Box::pin(async move {
            checkpoint(cx)?;
            if path != CHECK_PATH {
                return Err(Status::unimplemented("unknown unary health method"));
            }
            let request = decode_request(request)?;
            // Never call the unauthenticated in-process check() entry point.
            let response = self.health.check_async(&request).await?;
            checkpoint(cx)?; // A custom auth callback may cancel its owner.
            Ok(response.map(encode_response))
        })
    }

    fn call_server_streaming<'a>(
        &'a self,
        cx: &'a Cx,
        path: &'a str,
        request: Request<Bytes>,
        _trailing_metadata: Metadata,
    ) -> ServiceStreamingFuture<'a> {
        Box::pin(async move {
            checkpoint(cx)?;
            if path != WATCH_PATH {
                return Err(Status::unimplemented("unknown streaming health method"));
            }
            let request = decode_request(request)?;
            // Authentication happens before capacity refusal, and before any
            // watch waiter can be registered. This future creates no worker.
            let source = self.health.watch_async(&request).await?.into_inner();
            checkpoint(cx)?;
            let slot = self.admission.acquire()?;
            Ok(RegisteredServerStream::new(EncodedWatch {
                source,
                _slot: slot,
            }))
        })
    }
}

// Field order retires the source's registered waiter BEFORE releasing its slot.
struct EncodedWatch {
    source: HealthWatchStream,
    _slot: WatchSlot,
}

impl Streaming for EncodedWatch {
    type Message = Bytes;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Bytes, Status>>> {
        Pin::new(&mut self.get_mut().source)
            .poll_next(cx)
            .map(|item| item.map(|result| result.map(encode_response)))
    }
}

#[cfg(test)]
mod tests;
