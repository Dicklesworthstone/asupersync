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
#[derive(Clone)]
enum ReflectionAuthMode {
    /// Safe-by-default. Every reflection RPC returns
    /// `PermissionDenied` until the caller picks a mode.
    Locked,
    /// Production: auth callback gates every RPC.
    Required(ReflectionAuthCallback),
    /// Dev / test: explicit opt-in to no-auth mode. Callers that want
    /// the legacy "open" behaviour for grpcurl / BloomRPC must invoke
    /// `.allow_anonymous()` so the choice is grep-able and auditable.
    Anonymous,
}

impl Default for ReflectionAuthMode {
    fn default() -> Self {
        Self::Locked
    }
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
    /// callback is installed, the RPC is rejected with
    /// `Status::unauthenticated` because the capability boundary is missing.
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
    /// an `allow_anonymous()` service expose the full service catalog
    /// — every method name, streaming kind, descriptor file — to any
    /// caller who can reach the gRPC port.
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
    /// rejects everything) and `Anonymous` (which allows everything)
    /// — only `Required(_)` reports `true`. (br-asupersync-3tzd9v /
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
    /// * `Required(cb)` → run the callback. If `Cx::current()` is
    ///   missing, fail-closed with `Status::unauthenticated`.
    /// * `Anonymous` → `Ok(())`.
    #[allow(dead_code)]
    fn check_auth(&self, method: &str) -> Result<(), Status> {
        match &self.auth {
            ReflectionAuthMode::Locked => Err(Status::permission_denied(format!(
                "reflection.{method}: service is in Locked mode — call \
                 .with_auth(...) for production or .allow_anonymous() for \
                 dev/test before serving reflection RPCs"
            ))),
            ReflectionAuthMode::Required(auth) => {
                let Some(cx) = Cx::current() else {
                    return Err(Status::unauthenticated(
                        "reflection: auth callback installed but no Cx in scope",
                    ));
                };
                auth(&cx, method)
            }
            ReflectionAuthMode::Anonymous => Ok(()),
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
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use insta::assert_json_snapshot;
    use serde_json::{Value, json};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    struct EchoService;

    impl ServiceHandler for EchoService {
        fn descriptor(&self) -> &ServiceDescriptor {
            static METHODS: &[MethodDescriptor] = &[
                MethodDescriptor::unary("Ping", "/pkg.Echo/Ping"),
                MethodDescriptor::server_streaming("Watch", "/pkg.Echo/Watch"),
            ];
            static DESC: ServiceDescriptor = ServiceDescriptor::new("Echo", "pkg", METHODS);
            &DESC
        }

        fn method_names(&self) -> Vec<&str> {
            vec!["Ping", "Watch"]
        }
    }

    struct EnumShapeService;

    impl ServiceHandler for EnumShapeService {
        fn descriptor(&self) -> &ServiceDescriptor {
            static METHODS: &[MethodDescriptor] = &[
                MethodDescriptor::unary("Unary", "/pkg.EnumShape/Unary"),
                MethodDescriptor::server_streaming("ServerStream", "/pkg.EnumShape/ServerStream"),
                MethodDescriptor::client_streaming("ClientStream", "/pkg.EnumShape/ClientStream"),
                MethodDescriptor::bidi_streaming("BidiStream", "/pkg.EnumShape/BidiStream"),
            ];
            static DESC: ServiceDescriptor = ServiceDescriptor::new("EnumShape", "pkg", METHODS);
            &DESC
        }

        fn method_names(&self) -> Vec<&str> {
            vec!["Unary", "ServerStream", "ClientStream", "BidiStream"]
        }
    }

    fn method_kind(method: &ReflectedMethod) -> &'static str {
        match (method.client_streaming, method.server_streaming) {
            (false, false) => "unary",
            (false, true) => "server_streaming",
            (true, false) => "client_streaming",
            (true, true) => "bidi_streaming",
        }
    }

    fn reflected_service_snapshot(service: &ReflectedService) -> Value {
        json!({
            "service": service.name,
            "methods": service.methods.iter().map(|method| {
                json!({
                    "name": method.name,
                    "path": method.path,
                    "kind": method_kind(method),
                })
            }).collect::<Vec<_>>(),
        })
    }

    #[test]
    fn reflection_register_list_and_describe() {
        init_test("reflection_register_list_and_describe");
        let reflection = ReflectionService::new().allow_anonymous();
        let echo = EchoService;
        reflection.register_handler(&echo);

        // br-asupersync-3tzd9v: default = no auth, list_services Oks.
        let services = reflection.list_services().expect("no auth installed");
        crate::assert_with_log!(
            services == vec!["pkg.Echo".to_string()],
            "service list",
            vec!["pkg.Echo".to_string()],
            services
        );

        let described = reflection
            .describe_service("pkg.Echo")
            .expect("service exists");
        crate::assert_with_log!(
            described.methods.len() == 2,
            "method count",
            2,
            described.methods.len()
        );
        crate::assert_with_log!(
            described.methods[0].name == "Ping",
            "first method name",
            "Ping",
            &described.methods[0].name
        );
        crate::assert_with_log!(
            described.methods[1].server_streaming,
            "server streaming flag",
            true,
            described.methods[1].server_streaming
        );
        crate::test_complete!("reflection_register_list_and_describe");
    }

    #[test]
    fn reflection_describe_missing_service() {
        init_test("reflection_describe_missing_service");
        let reflection = ReflectionService::new().allow_anonymous();
        let err = reflection
            .describe_service("pkg.Missing")
            .expect_err("missing service should fail");
        crate::assert_with_log!(
            err.code() == super::super::status::Code::NotFound,
            "not found code",
            super::super::status::Code::NotFound,
            err.code()
        );
        crate::test_complete!("reflection_describe_missing_service");
    }

    #[test]
    fn reflection_async_helpers() {
        init_test("reflection_async_helpers");
        let reflection = ReflectionService::new().allow_anonymous();
        let echo = EchoService;
        reflection.register_handler(&echo);

        let list = futures_lite::future::block_on(
            reflection.list_services_async(&Request::new(ReflectionListServicesRequest)),
        )
        .expect("list succeeds");
        crate::assert_with_log!(
            list.get_ref().services == vec!["pkg.Echo".to_string()],
            "async list",
            vec!["pkg.Echo".to_string()],
            &list.get_ref().services
        );

        let describe = futures_lite::future::block_on(reflection.describe_service_async(
            &Request::new(ReflectionDescribeServiceRequest::new("pkg.Echo")),
        ))
        .expect("describe succeeds");
        crate::assert_with_log!(
            describe.get_ref().service.name == "pkg.Echo",
            "async describe name",
            "pkg.Echo",
            &describe.get_ref().service.name
        );
        crate::test_complete!("reflection_async_helpers");
    }

    #[test]
    fn reflection_service_traits() {
        init_test("reflection_service_traits");
        let reflection = ReflectionService::new().allow_anonymous();
        crate::assert_with_log!(
            ReflectionService::NAME == "grpc.reflection.v1alpha.ServerReflection",
            "service name",
            "grpc.reflection.v1alpha.ServerReflection",
            ReflectionService::NAME
        );
        let desc = reflection.descriptor();
        crate::assert_with_log!(
            desc.full_name() == "grpc.reflection.v1alpha.ServerReflection",
            "descriptor full name",
            "grpc.reflection.v1alpha.ServerReflection",
            desc.full_name()
        );
        let methods = reflection.method_names();
        crate::assert_with_log!(
            methods == vec!["ServerReflectionInfo"],
            "method names match the descriptor-exposed RPCs",
            vec!["ServerReflectionInfo"],
            methods
        );
        crate::test_complete!("reflection_service_traits");
    }

    #[test]
    fn reflection_descriptor_enum_output_snapshot() {
        init_test("reflection_descriptor_enum_output_snapshot");
        let reflection = ReflectionService::new().allow_anonymous();
        let enum_shape = EnumShapeService;
        reflection.register_handler(&enum_shape);

        let described = reflection
            .describe_service("pkg.EnumShape")
            .expect("enum-shape service exists");

        assert_json_snapshot!(
            "grpc_reflection_descriptor_enum_output",
            reflected_service_snapshot(&described)
        );
        crate::test_complete!("reflection_descriptor_enum_output_snapshot");
    }

    // br-asupersync-3tzd9v: opt-in auth callback regression tests.

    #[test]
    fn auth_default_is_open() {
        init_test("auth_default_is_open");
        let reflection = ReflectionService::new().allow_anonymous();
        reflection.register_handler(&EchoService);
        assert!(!reflection.auth_installed(), "default must be no auth");
        // Both entry points succeed without an ambient Cx because no auth
        // callback is installed.
        assert!(reflection.list_services().is_ok());
        assert!(reflection.describe_service("pkg.Echo").is_ok());
        crate::test_complete!("auth_default_is_open");
    }

    #[test]
    fn auth_callback_can_reject() {
        init_test("auth_callback_can_reject");
        let reflection = ReflectionService::new()
            .register_for_test()
            .with_auth(|_cx, method| Err(Status::permission_denied(format!("denied: {method}"))));
        assert!(reflection.auth_installed());
        // No ambient Cx → check_auth short-circuits on the missing-Cx
        // branch and returns Unauthenticated. That's still a rejection
        // (which is what we want: defense in depth — auth-required
        // service must run inside a Cx).
        let err_list = reflection.list_services().expect_err("auth must reject");
        assert_eq!(err_list.code(), super::super::status::Code::Unauthenticated);
        let err_desc = reflection
            .describe_service("pkg.Echo")
            .expect_err("auth must reject");
        assert_eq!(err_desc.code(), super::super::status::Code::Unauthenticated);
        crate::test_complete!("auth_callback_can_reject");
    }

    #[test]
    fn auth_method_name_is_passed_to_callback() {
        init_test("auth_method_name_is_passed_to_callback");
        // Use a Cx so the callback is actually invoked rather than being
        // short-circuited by the missing-Cx branch. We assert the method
        // name routed to the callback distinguishes the two RPCs.
        let saw_list = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let saw_describe = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let saw_list_clone = saw_list.clone();
        let saw_describe_clone = saw_describe.clone();
        let reflection =
            ReflectionService::new()
                .register_for_test()
                .with_auth(move |_cx, method| {
                    match method {
                        "ListServices" => {
                            saw_list_clone.store(true, std::sync::atomic::Ordering::Relaxed)
                        }
                        "DescribeService" => {
                            saw_describe_clone.store(true, std::sync::atomic::Ordering::Relaxed)
                        }
                        _ => {}
                    }
                    Ok(())
                });
        let cx = Cx::for_testing();
        // Install cx as the ambient Cx for the duration of the calls so
        // check_auth's Cx::current() finds it (instead of returning the
        // missing-Cx Unauthenticated error).
        let _guard = Cx::set_current(Some(cx));
        let _ = reflection.list_services();
        let _ = reflection.describe_service("pkg.Echo");
        drop(_guard);
        assert!(
            saw_list.load(std::sync::atomic::Ordering::Relaxed),
            "callback must see ListServices"
        );
        assert!(
            saw_describe.load(std::sync::atomic::Ordering::Relaxed),
            "callback must see DescribeService"
        );
        crate::test_complete!("auth_method_name_is_passed_to_callback");
    }

    /// Test helper: register a single Echo service descriptor and return
    /// the service for further chaining. (Used by the auth tests to keep
    /// noise out of the assertion statements.)
    impl ReflectionService {
        fn register_for_test(self) -> Self {
            self.register_handler(&EchoService);
            self
        }
    }

    // =====================================================================
    // br-asupersync-mi4hzh: fail-closed default tests. ReflectionService::new()
    // returns a service in Locked mode that rejects every RPC until the
    // caller chains either .with_auth(...) (production) or .allow_anonymous()
    // (dev / test).
    // =====================================================================

    #[test]
    fn mi4hzh_locked_default_rejects_list_services() {
        init_test("mi4hzh_locked_default_rejects_list_services");
        let reflection = ReflectionService::new().register_for_test();
        // No .with_auth, no .allow_anonymous. Must reject.
        let err = reflection
            .list_services()
            .expect_err("Locked mode must reject ListServices");
        assert_eq!(err.code(), super::super::status::Code::PermissionDenied);
        // Diagnostic message names both opt-ins so operators can fix.
        let msg = err.message();
        assert!(
            msg.contains(".with_auth") && msg.contains(".allow_anonymous"),
            "PermissionDenied message must name both opt-ins: {msg}"
        );
        crate::test_complete!("mi4hzh_locked_default_rejects_list_services");
    }

    #[test]
    fn mi4hzh_locked_default_rejects_describe_service() {
        init_test("mi4hzh_locked_default_rejects_describe_service");
        let reflection = ReflectionService::new().register_for_test();
        let err = reflection
            .describe_service("pkg.Echo")
            .expect_err("Locked mode must reject DescribeService");
        assert_eq!(err.code(), super::super::status::Code::PermissionDenied);
        crate::test_complete!("mi4hzh_locked_default_rejects_describe_service");
    }

    #[test]
    fn mi4hzh_allow_anonymous_unlocks_dev_mode() {
        init_test("mi4hzh_allow_anonymous_unlocks_dev_mode");
        let reflection = ReflectionService::new()
            .register_for_test()
            .allow_anonymous();
        // Locked → Anonymous → both RPCs succeed.
        assert!(reflection.list_services().is_ok());
        assert!(reflection.describe_service("pkg.Echo").is_ok());
        // auth_installed() reports false for both Locked and Anonymous —
        // only Required(_) is true (production-hardened).
        assert!(!reflection.auth_installed());
        crate::test_complete!("mi4hzh_allow_anonymous_unlocks_dev_mode");
    }

    #[test]
    fn mi4hzh_with_auth_reports_installed() {
        init_test("mi4hzh_with_auth_reports_installed");
        let reflection = ReflectionService::new()
            .register_for_test()
            .with_auth(|_cx, _method| Ok(()));
        assert!(reflection.auth_installed());
        crate::test_complete!("mi4hzh_with_auth_reports_installed");
    }
}
