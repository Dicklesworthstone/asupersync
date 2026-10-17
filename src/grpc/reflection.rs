//! gRPC reflection service support.
//!
//! This module provides an in-process reflection registry that can expose
//! service and method descriptors for discovery-oriented tooling.

use parking_lot::RwLock;
use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::cx::Cx;

use super::service::{MethodDescriptor, NamedService, ServiceDescriptor, ServiceHandler};
use super::status::Status;
use super::streaming::{Request, Response};

/// Auth callback for [`ReflectionService`].
///
/// Called once per reflection RPC with the ambient capability context
/// (resolved via `Cx::current()`) and the method name (`"ListServices"` or
/// `"DescribeService"`). Returning `Err(Status)` rejects the RPC; the
/// returned status is propagated verbatim to the caller, so prefer
/// [`Status::unauthenticated`] / [`Status::permission_denied`] for
/// production-meaningful errors. (br-asupersync-3tzd9v)
pub type ReflectionAuthCallback = Arc<dyn Fn(&Cx, &str) -> Result<(), Status> + Send + Sync>;

/// Reflection metadata for a single gRPC method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReflectedMethod {
    /// Method name (e.g. `Check`).
    pub name: String,
    /// Fully-qualified RPC path (e.g. `/grpc.health.v1.Health/Check`).
    pub path: String,
    /// Whether this method accepts a request stream.
    pub client_streaming: bool,
    /// Whether this method returns a response stream.
    pub server_streaming: bool,
}

/// Reflection metadata for a single gRPC service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReflectedService {
    /// Fully-qualified service name (e.g. `grpc.health.v1.Health`).
    pub name: String,
    /// Methods exposed by this service.
    pub methods: Vec<ReflectedMethod>,
}

/// Request for listing all known services.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReflectionListServicesRequest;

/// Response containing all known service names.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReflectionListServicesResponse {
    /// Sorted list of fully-qualified service names.
    pub services: Vec<String>,
}

/// Request for describing a specific service.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReflectionDescribeServiceRequest {
    /// Fully-qualified service name.
    pub service: String,
}

impl ReflectionDescribeServiceRequest {
    /// Create a new describe request.
    #[must_use]
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }
}

/// Response containing descriptor information for a single service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReflectionDescribeServiceResponse {
    /// Reflected service details.
    pub service: ReflectedService,
}

/// br-asupersync-mi4hzh: tri-state auth mode for `ReflectionService`.
///
/// Pre-fix the auth slot was `Option<ReflectionAuthCallback>` with `None`
/// silently meaning "open to anyone", which made `ReflectionService::new()`
/// expose the entire service catalog to unauthenticated callers in any
/// production deployment that forgot to chain `.with_auth(...)`. The
/// fix-side default is now `Locked` — every RPC rejects until the
/// caller explicitly chooses either `.with_auth(...)` (production) or
/// `.allow_anonymous()` (dev / test).
#[derive(Clone, Default)]
enum ReflectionAuthMode {
    /// Safe-by-default. Every reflection RPC returns
    /// `PermissionDenied` until the caller picks a mode.
    #[default]
    Locked,
    /// Production: auth callback gates every RPC.
    Required(ReflectionAuthCallback),
    /// Dev / test: explicit opt-in to no-auth mode. Callers that want
    /// the legacy "open" behaviour for grpcurl / BloomRPC must invoke
    /// `.allow_anonymous()` so the choice is grep-able and auditable.
    Anonymous,
}

/// Reflection registry and service facade.
///
/// The registry stores a deterministic snapshot of service descriptors and can
/// be used directly or registered in [`crate::grpc::ServerBuilder`] via
/// `enable_reflection()`.
#[derive(Clone, Default)]
pub struct ReflectionService {
    services: Arc<RwLock<BTreeMap<String, ReflectedService>>>,
    /// br-asupersync-mi4hzh: see `ReflectionAuthMode` — defaults to
    /// `Locked` so production deployments cannot accidentally expose
    /// the schema by forgetting `.with_auth(...)`.
    auth: ReflectionAuthMode,
}

impl fmt::Debug for ReflectionService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Don't print the auth callback (it's a dyn Fn) — just the
        // auth mode label, so logs distinguish the production-hardened
        // configuration from the dev opt-in.
        let auth_label = match &self.auth {
            ReflectionAuthMode::Locked => "Locked (no auth opt-in)",
            ReflectionAuthMode::Required(_) => "Required(<fn>)",
            ReflectionAuthMode::Anonymous => "Anonymous (dev only)",
        };
        f.debug_struct("ReflectionService")
            .field("services", &self.services)
            .field("auth", &auth_label)
            .finish()
    }
}

impl ReflectionService {
    /// Create an empty reflection registry in the SAFE-BY-DEFAULT
    /// `Locked` mode (br-asupersync-mi4hzh).
    ///
    /// Every reflection RPC will return `PermissionDenied` until the
    /// caller explicitly chooses one of:
    ///
    /// * [`Self::with_auth`] — production. Install a callback that
    ///   gates every RPC against the ambient `Cx` (macaroon check,
    ///   peer-identity allowlist, etc).
    /// * [`Self::allow_anonymous`] — dev / test. Explicit opt-in to
    ///   the legacy "open" mode for grpcurl / BloomRPC / debug
    ///   tooling. The choice is grep-able and auditable.
    ///
    /// Pre-fix, `new()` defaulted to `auth = None`, silently
    /// equivalent to `Anonymous`, which exposed the full service
    /// catalog to any caller who could reach the gRPC port whenever
    /// a developer forgot the `.with_auth(...)` chain. The default
    /// is now fail-closed.
    #[must_use]
    pub fn new() -> Self {
        Self {
            services: Arc::new(RwLock::new(BTreeMap::new())),
            auth: ReflectionAuthMode::Locked,
        }
    }

    /// Install an auth callback that gates every reflection RPC.
    ///
    /// The callback receives the ambient capability context (resolved via
    /// `Cx::current()` at the point of the RPC call) and the reflection
    /// method name (`"ListServices"` or `"DescribeService"`). Returning
    /// `Ok(())` permits the call; returning `Err(Status)` rejects it with
    /// the supplied status. If `Cx::current()` returns `None` while a
    /// callback is installed, the RPC is rejected with `PermissionDenied`
    /// because reflection always requires an explicit REMOTE capability.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let reflection = ReflectionService::new()
    ///     .with_auth(|cx, _method| {
    ///         let key = root_key();
    ///         let ctx = VerificationContext::new();
    ///         cx.verify_capability(&key, "grpc:reflection", &ctx)
    ///             .map_err(|_| Status::permission_denied("reflection denied"))
    ///     });
    /// ```
    /// (br-asupersync-3tzd9v / br-asupersync-mi4hzh)
    #[must_use]
    pub fn with_auth<F>(mut self, callback: F) -> Self
    where
        F: Fn(&Cx, &str) -> Result<(), Status> + Send + Sync + 'static,
    {
        self.auth = ReflectionAuthMode::Required(Arc::new(callback));
        self
    }

    /// Explicit opt-in to anonymous (no-auth) mode for development,
    /// CI tooling, and debug consoles (br-asupersync-mi4hzh).
    ///
    /// **Do not use in production.** Reflection RPCs called against
    /// an `allow_anonymous()` service still require an ambient REMOTE
    /// capability, but skip the production auth callback and expose the
    /// full service catalog — every method name, streaming kind, descriptor
    /// file — to any remote-capable caller who can reach the gRPC port.
    ///
    /// Calling this method is the auditable, grep-able way to ship a
    /// dev / test endpoint. CI deployments and security reviewers can
    /// search for `.allow_anonymous()` to find every place the
    /// fail-closed default was overridden.
    #[must_use]
    pub fn allow_anonymous(mut self) -> Self {
        self.auth = ReflectionAuthMode::Anonymous;
        self
    }

    /// Returns whether an auth callback is currently installed.
    /// Useful in tests and operator dashboards to confirm production
    /// hardening is in place. Returns false for both `Locked` (which
    /// rejects everything) and `Anonymous` (which skips the callback but
    /// still requires REMOTE) — only `Required(_)` reports `true`.
    /// (br-asupersync-3tzd9v /
    /// br-asupersync-mi4hzh)
    #[must_use]
    pub fn auth_installed(&self) -> bool {
        matches!(self.auth, ReflectionAuthMode::Required(_))
    }

    /// Run the auth gate for `method` (br-asupersync-mi4hzh).
    ///
    /// Returns:
    /// * `Locked` → `Status::permission_denied` with a message that
    ///   names both opt-ins so operators understand the fix.
    /// * `Required(cb)` → require a REMOTE `Cx`, then run the callback.
    /// * `Anonymous` → require a REMOTE `Cx`, then permit the call.
    #[allow(dead_code)]
    pub(crate) fn check_auth(&self, method: &str) -> Result<(), Status> {
        fn current_remote_cx(method: &str) -> Result<Cx, Status> {
            let Some(cx) = Cx::current() else {
                return Err(Status::permission_denied(format!(
                    "reflection.{method}: requires REMOTE capability"
                )));
            };
            if !cx.has_remote() {
                return Err(Status::permission_denied(format!(
                    "reflection.{method}: requires REMOTE capability"
                )));
            }
            Ok(cx)
        }

        match &self.auth {
            ReflectionAuthMode::Locked => Err(Status::permission_denied(format!(
                "reflection.{method}: service is in Locked mode — call \
                 .with_auth(...) for production or .allow_anonymous() for \
                 dev/test before serving reflection RPCs"
            ))),
            ReflectionAuthMode::Anonymous => {
                current_remote_cx(method)?;
                Ok(())
            }
            ReflectionAuthMode::Required(auth) => {
                let cx = current_remote_cx(method)?;
                auth(&cx, method)
            }
        }
    }

    /// Build a reflection registry from existing handlers.
    #[must_use]
    pub fn from_handlers<'a, I>(handlers: I) -> Self
    where
        I: IntoIterator<Item = &'a dyn ServiceHandler>,
    {
        let reflection = Self::new();
        for handler in handlers {
            reflection.register_handler(handler);
        }
        reflection
    }

    /// Register descriptor metadata for a service.
    pub fn register_descriptor(&self, descriptor: &ServiceDescriptor) {
        let reflected = ReflectedService {
            name: descriptor.full_name(),
            methods: descriptor
                .methods
                .iter()
                .map(|method| ReflectedMethod {
                    name: method.name.to_string(),
                    path: method.path.to_string(),
                    client_streaming: method.client_streaming,
                    server_streaming: method.server_streaming,
                })
                .collect(),
        };
        self.services
            .write()
            .insert(reflected.name.clone(), reflected);
    }

    /// Register a handler's descriptor metadata.
    pub fn register_handler(&self, handler: &dyn ServiceHandler) {
        self.register_descriptor(handler.descriptor());
    }

    /// Returns all registered service names in deterministic order.
    ///
    /// Returns `Ok` of the list when no auth callback is installed, OR
    /// when the installed callback approves. Returns `Err(Status)` if the
    /// callback rejects. (br-asupersync-3tzd9v)
    pub fn list_services(&self) -> Result<Vec<String>, Status> {
        self.check_auth("ListServices")?;
        Ok(self.services.read().keys().cloned().collect())
    }

    /// Returns reflection metadata for one service.
    ///
    /// Auth-gated identically to [`Self::list_services`]. (br-asupersync-3tzd9v)
    pub fn describe_service(&self, service: &str) -> Result<ReflectedService, Status> {
        self.check_auth("DescribeService")?;
        self.services
            .read()
            .get(service)
            .cloned()
            .ok_or_else(|| Status::not_found(format!("service '{service}' not found")))
    }

    /// Async helper for list-services RPC-style usage. Auth-gated.
    /// (br-asupersync-3tzd9v)
    #[must_use]
    pub fn list_services_async(
        &self,
        _request: &Request<ReflectionListServicesRequest>,
    ) -> Pin<
        Box<dyn Future<Output = Result<Response<ReflectionListServicesResponse>, Status>> + Send>,
    > {
        let result = self
            .list_services()
            .map(|services| ReflectionListServicesResponse { services });
        Box::pin(async move { result.map(Response::new) })
    }

    /// Async helper for describe-service RPC-style usage. Auth-gated.
    /// (br-asupersync-3tzd9v)
    #[must_use]
    pub fn describe_service_async(
        &self,
        request: &Request<ReflectionDescribeServiceRequest>,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Response<ReflectionDescribeServiceResponse>, Status>> + Send,
        >,
    > {
        let result = self
            .describe_service(&request.get_ref().service)
            .map(|service| ReflectionDescribeServiceResponse { service });
        Box::pin(async move { result.map(Response::new) })
    }
}

impl NamedService for ReflectionService {
    const NAME: &'static str = "grpc.reflection.v1alpha.ServerReflection";
}

impl ServiceHandler for ReflectionService {
    fn descriptor(&self) -> &ServiceDescriptor {
        static METHODS: &[MethodDescriptor] = &[MethodDescriptor::bidi_streaming(
            "ServerReflectionInfo",
            "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
        )];
        static DESC: ServiceDescriptor =
            ServiceDescriptor::new("ServerReflection", "grpc.reflection.v1alpha", METHODS);
        &DESC
    }

    fn method_names(&self) -> Vec<&str> {
        vec!["ServerReflectionInfo"]
    }
}

#[cfg(test)]
#[path = "reflection_inline_tests.rs"]
mod tests;
