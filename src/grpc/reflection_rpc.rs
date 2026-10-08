//! Callable protobuf server reflection on the native registered duplex listener.
//!
//! [`ReflectionService::rpc_service`] opts an existing registry into the v1
//! protocol. [`ReflectionRpcService::v1alpha`] exposes the same catalog under
//! the older v1alpha service name. Register either or both with `ServerBuilder`
//! and serve via `bind_registered_duplex_http2` / `serve_duplex_http2`.
//!
//! The registry's existing `ListServices` authorization gate protects EVERY
//! query, under the explicit request context. The default remains locked and
//! even anonymous development mode requires the registry's REMOTE capability.
//! Server interceptors remain responsible for authenticating request metadata.
//! Supplying descriptors explicitly authorizes their ENTIRE contents for
//! disclosure after that gate, including imported types and non-listed services.
//! No descriptors are fabricated from Rust method names. The legacy registry
//! and its metadata-only service registration are unchanged.
//!
//! Each response poll consumes at most one request; it never prefetches a
//! second message or spawns a worker. Native framing, request trailers, reset,
//! and connection shutdown remain owned by the existing duplex transport.
//! This adapter adds per-message/per-stream bounds and a shared active-stream
//! cap, plus cancellation/deadline wakes. The request's `host` is echoed, not
//! interpreted as a tenant or an authorization selector: one catalog is served.

use super::reflection::ReflectionService;
use super::reflection_descriptor::ReflectionDescriptorSet;
use super::service::{MethodDescriptor, NamedService, RegisteredServerStream, ServiceDescriptor, ServiceHandler, ServiceStreamingFuture};
use super::streaming::{Request, Streaming};
use super::{RegisteredRequestStream, Status};
use crate::bytes::Bytes;
use crate::cx::Cx;
use crate::types::CancelKind;
use prost::Message as _;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

mod wire;
use wire::{Query, Reply, WireRequest, WireResponse};

const V1_PATH: &str = "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo";
const ALPHA_PATH: &str = "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo";

/// Bounds applied in addition to the native transport's own message/body limits.
#[derive(Debug, Clone, Copy)]
pub struct ReflectionRpcConfig {
    /// Concurrent response sources across all clones and both protocol versions.
    /// Zero deliberately disables reflection admission.
    pub max_streams: usize,
    /// Maximum serialized query bytes, checked before protobuf decoding.
    pub max_request_bytes: usize,
    /// Maximum serialized response bytes, including the echoed query.
    pub max_response_bytes: usize,
    /// Maximum query messages admitted in one bidirectional RPC.
    pub max_queries_per_stream: usize,
}

impl Default for ReflectionRpcConfig {
    fn default() -> Self {
        Self {
            max_streams: 64,
            max_request_bytes: 16 * 1024,
            max_response_bytes: super::DEFAULT_MAX_MESSAGE_SIZE,
            max_queries_per_stream: 1024,
        }
    }
}

struct Shared {
    registry: ReflectionService,
    descriptors: ReflectionDescriptorSet,
    config: ReflectionRpcConfig,
    active: AtomicUsize,
}

/// Cloneable v1 server-reflection service with an immutable descriptor catalog.
///
/// Construct through [`ReflectionService::rpc_service`]. Clones and the v1alpha
/// view share admission. Creating another service from the registry creates a
/// separate cap. No socket, stream or task is created by registration.
#[derive(Clone)]
pub struct ReflectionRpcService {
    shared: Arc<Shared>,
}

/// v1alpha wire-compatible view of a [`ReflectionRpcService`].
/// Register it explicitly; no unsupported route silently falls back to another version.
#[derive(Clone, Debug)]
pub struct ReflectionRpcV1AlphaService {
    rpc: ReflectionRpcService,
}

impl std::fmt::Debug for ReflectionRpcService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReflectionRpcService")
            .field("config", &self.shared.config)
            .field("active_streams", &self.active_streams())
            .finish_non_exhaustive()
    }
}

impl ReflectionService {
    /// Bind an explicit descriptor catalog to authenticated native reflection.
    ///
    /// Use a `FileDescriptorSet` produced with `protoc --include_imports`:
    /// `ReflectionDescriptorSet::decode(encoded)` preserves exact file bytes.
    /// Register application handlers with this registry to populate ListServices;
    /// supplying descriptors alone does not claim those handlers are callable.
    /// The registry's `with_auth` / `allow_anonymous` policy is preserved. Every
    /// wire query uses its `ListServices` gate, including descriptor lookups.
    /// To expose reflection's own schema, include its standard proto descriptor
    /// and explicitly register the desired RPC view in the registry too.
    pub fn rpc_service(
        &self,
        descriptors: ReflectionDescriptorSet,
        config: ReflectionRpcConfig,
    ) -> Result<ReflectionRpcService, Status> {
        if config.max_request_bytes == 0 || config.max_response_bytes == 0
            || config.max_queries_per_stream == 0 {
            return Err(Status::invalid_argument("reflection message and query limits must be positive"));
        }
        Ok(ReflectionRpcService {
            shared: Arc::new(Shared {
                registry: self.clone(), descriptors, config, active: AtomicUsize::new(0),
            }),
        })
    }
}

impl ReflectionRpcService {
    /// Older protocol view sharing this service's catalog, auth policy and cap.
    #[must_use]
    pub fn v1alpha(&self) -> ReflectionRpcV1AlphaService {
        ReflectionRpcV1AlphaService { rpc: self.clone() }
    }

    /// Number of admitted response sources not yet terminated or dropped.
    #[must_use]
    pub fn active_streams(&self) -> usize {
        self.shared.active.load(Ordering::Acquire)
    }

    fn authorize(&self, cx: &Cx) -> Result<Vec<String>, Status> {
        checkpoint(cx)?;
        let _ambient = cx.clone().set_current_restricted();
        let services = self.shared.registry.list_services()?;
        checkpoint(cx)?; // The owner-supplied callback can cancel the request.
        Ok(services)
    }

    fn open_stream<S>(&self, cx: &Cx, source: S) -> Result<RegisteredServerStream, Status>
    where S: Streaming<Message = Bytes> + Send + 'static,
    {
        self.authorize(cx)?; // Auth precedes capacity refusal and source polling.
        let deadline = match cx.budget().deadline {
            Some(at) => {
                let timer = cx.timer_driver().ok_or_else(||
                    Status::failed_precondition("reflection deadline needs a timer driver"))?;
                Some(Box::pin(crate::time::Sleep::with_timer_driver(at, timer)))
            }
            None => None,
        };
        self.shared.active.try_update(Ordering::AcqRel, Ordering::Acquire, |active| {
            active.checked_add(1).filter(|next| *next <= self.shared.config.max_streams)
        }).map_err(|_| Status::resource_exhausted("reflection stream capacity exhausted"))?;
        let slot = Slot(Arc::clone(&self.shared));
        let observer = cx.clone();
        Ok(RegisteredServerStream::new(ReflectionStream {
            source: Some(Box::pin(source)),
            rpc: self.clone(),
            cx: cx.clone(),
            cancelled: Some(Box::pin(async move { observer.cancelled().await; })),
            deadline,
            slot: Some(slot),
            queries: 0,
            done: false,
        }))
    }

    fn answer(&self, cx: &Cx, bytes: &Bytes) -> Result<Bytes, Status> {
        let services = self.authorize(cx)?;
        if bytes.len() > self.shared.config.max_request_bytes {
            return Err(Status::resource_exhausted("reflection query byte limit exceeded"));
        }
        let request = WireRequest::decode(bytes.as_ref())
            .map_err(|_| Status::invalid_argument("invalid reflection request protobuf"))?;
        let reply = self.reply(&request, services).unwrap_or_else(|status| {
            Reply::Error(wire::ErrorReply { code: status.code() as i32, message: status.message().to_owned() })
        });
        let response = WireResponse {
            valid_host: request.host.clone(), original_request: Some(request), reply: Some(reply),
        };
        if response.encoded_len() > self.shared.config.max_response_bytes {
            return Err(Status::resource_exhausted("reflection response byte limit exceeded"));
        }
        checkpoint(cx)?;
        Ok(Bytes::from(response.encode_to_vec()))
    }

    fn reply(&self, request: &WireRequest, services: Vec<String>) -> Result<Reply, Status> {
        let catalog = &self.shared.descriptors;
        match request.query.as_ref() {
            Some(Query::FileByName(name)) => self.files_reply(catalog.file_by_name(name)?),
            Some(Query::FileContainingSymbol(symbol)) => self.files_reply(catalog.file_containing_symbol(symbol)?),
            Some(Query::FileContainingExtension(extension)) => self.files_reply(
                catalog.file_containing_extension(&extension.containing_type, extension.number)?),
            Some(Query::AllExtensionNumbers(name)) => Ok(Reply::Extensions(wire::ExtensionNumbers {
                base_type_name: name.clone(), numbers: catalog.extension_numbers(name)?,
            })),
            Some(Query::ListServices(_)) => {
                let mut total = 0usize;
                let mut result = Vec::new();
                for name in services {
                    total = total.checked_add(name.len()).filter(|total| *total <= self.shared.config.max_response_bytes)
                        .ok_or_else(|| Status::resource_exhausted("reflection service list exceeds byte limit"))?;
                    result.push(wire::Service { name });
                }
                Ok(Reply::Services(wire::Services { services: result }))
            }
            None => Err(Status::invalid_argument("reflection query is missing")),
        }
    }

    fn files_reply(&self, files: Vec<Bytes>) -> Result<Reply, Status> {
        // Refuse payloads larger than the output limit BEFORE copying raw files
        // into the protobuf reply. Final framing/echo overhead is checked too.
        let mut total = 0usize;
        for file in &files {
            total = total.checked_add(file.len()).filter(|total| *total <= self.shared.config.max_response_bytes)
                .ok_or_else(|| Status::resource_exhausted("reflection descriptors exceed response limit"))?;
        }
        Ok(Reply::Files(wire::Files { files: files.iter().map(|file| file.as_ref().to_vec()).collect() }))
    }
}

fn checkpoint(cx: &Cx) -> Result<(), Status> {
    cx.checkpoint().map_err(|_| match cx.cancel_reason().map(|reason| reason.kind) {
        Some(CancelKind::Timeout | CancelKind::Deadline) => Status::deadline_exceeded("reflection deadline exceeded"),
        Some(CancelKind::PollQuota | CancelKind::CostBudget) => Status::resource_exhausted("reflection budget exhausted"),
        _ => Status::cancelled("reflection cancelled"),
    })
}

struct Slot(Arc<Shared>);
impl Drop for Slot {
    fn drop(&mut self) {
        let previous = self.0.active.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "reflection stream admission underflow");
    }
}

type CancelWait = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

struct ReflectionStream {
    // Source retires before the slot, including implicit field drop on unwind.
    source: Option<Pin<Box<dyn Streaming<Message = Bytes> + Send + 'static>>>,
    rpc: ReflectionRpcService,
    cx: Cx,
    cancelled: Option<CancelWait>,
    deadline: Option<Pin<Box<crate::time::Sleep>>>,
    slot: Option<Slot>,
    queries: usize,
    done: bool,
}

impl ReflectionStream {
    fn finish(&mut self) {
        self.done = true;
        self.source = None;
        self.cancelled = None;
        self.deadline = None;
        self.slot = None;
    }

    fn fail(&mut self, status: Status) -> Poll<Option<Result<Bytes, Status>>> {
        self.finish();
        Poll::Ready(Some(Err(status)))
    }
}

impl Streaming for ReflectionStream {
    type Message = Bytes;

    fn poll_next(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Option<Result<Bytes, Status>>> {
        let this = self.get_mut();
        if this.done { return Poll::Ready(None); }
        let _ambient = this.cx.clone().set_current_restricted();
        if let Err(status) = checkpoint(&this.cx) { return this.fail(status); }
        // Register then recheck so an otherwise idle request has a cancellation wake.
        let _ = this.cancelled.as_mut().expect("live cancellation observer").as_mut().poll(task);
        if let Err(status) = checkpoint(&this.cx) { return this.fail(status); }
        if this.deadline.as_mut().is_some_and(|timer| timer.as_mut().poll_deadline(task).is_ready()) {
            return this.fail(Status::deadline_exceeded("reflection deadline exceeded"));
        }
        match this.source.as_mut().expect("live reflection input").as_mut().poll_next(task) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => { this.finish(); Poll::Ready(None) }
            Poll::Ready(Some(Err(status))) => this.fail(status),
            Poll::Ready(Some(Ok(bytes))) => {
                if this.queries >= this.rpc.shared.config.max_queries_per_stream {
                    return this.fail(Status::resource_exhausted("reflection query count exceeded"));
                }
                this.queries += 1;
                match this.rpc.answer(&this.cx, &bytes) {
                    Ok(response) => Poll::Ready(Some(Ok(response))),
                    Err(status) => this.fail(status),
                }
            }
        }
    }
}

impl Drop for ReflectionStream {
    fn drop(&mut self) {
        let _ambient = self.cx.clone().set_current_restricted();
        self.finish();
    }
}

fn registered_call<'a>(
    rpc: &'a ReflectionRpcService, cx: &'a Cx, path: &'a str,
    request: Request<RegisteredRequestStream>, expected: &'static str,
) -> ServiceStreamingFuture<'a> {
    // Own the explicit context through construction, polling and destruction,
    // including an unpolled or refused request body.
    Box::pin(cx.with_ambient_fn(move || async move {
        checkpoint(cx)?;
        if path != expected { return Err(Status::unimplemented("unknown reflection method")); }
        rpc.open_stream(cx, request.into_inner())
    }))
}

impl NamedService for ReflectionRpcService {
    const NAME: &'static str = "grpc.reflection.v1.ServerReflection";
}
impl ServiceHandler for ReflectionRpcService {
    fn descriptor(&self) -> &ServiceDescriptor {
        static METHODS: &[MethodDescriptor] = &[MethodDescriptor::bidi_streaming("ServerReflectionInfo", V1_PATH)];
        static DESC: ServiceDescriptor = ServiceDescriptor::new("ServerReflection", "grpc.reflection.v1", METHODS);
        &DESC
    }
    fn method_names(&self) -> Vec<&str> { vec!["ServerReflectionInfo"] }
    fn call_bidirectional_streaming<'a>(
        &'a self, cx: &'a Cx, path: &'a str, request: Request<RegisteredRequestStream>,
    ) -> ServiceStreamingFuture<'a> {
        registered_call(self, cx, path, request, V1_PATH)
    }
}

impl NamedService for ReflectionRpcV1AlphaService {
    const NAME: &'static str = "grpc.reflection.v1alpha.ServerReflection";
}
impl ServiceHandler for ReflectionRpcV1AlphaService {
    fn descriptor(&self) -> &ServiceDescriptor {
        static METHODS: &[MethodDescriptor] = &[MethodDescriptor::bidi_streaming("ServerReflectionInfo", ALPHA_PATH)];
        static DESC: ServiceDescriptor = ServiceDescriptor::new("ServerReflection", "grpc.reflection.v1alpha", METHODS);
        &DESC
    }
    fn method_names(&self) -> Vec<&str> { vec!["ServerReflectionInfo"] }
    fn call_bidirectional_streaming<'a>(
        &'a self, cx: &'a Cx, path: &'a str, request: Request<RegisteredRequestStream>,
    ) -> ServiceStreamingFuture<'a> {
        registered_call(&self.rpc, cx, path, request, ALPHA_PATH)
    }
}

#[cfg(test)]
mod tests;
