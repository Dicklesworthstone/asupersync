//! SPORK Application layer: `AppSpec` + `AppHandle`.
//!
//! An application is a region-owned supervision tree described by an [`AppSpec`],
//! compiled and spawned into a root region, and managed through an [`AppHandle`].
//!
//! # Lifecycle
//!
//! ```text
//! AppSpec::new("my_app")
//!     .with_budget(budget)
//!     .child(child_spec)
//!     .start(&mut state, &cx, parent_region)
//!     -> Result<AppHandle, AppStartError>
//!
//! handle.stop(&mut state)   // cancel root → drain → finalize → quiescence
//! handle.join(&state)       // poll terminal outcome of root region
//! ```
//!
//! # Invariants
//!
//! - **Close implies quiescence**: no live tasks, no pending obligations, finalizers empty.
//! - **Cancel-correct stop**: request → drain → finalize, never silent data loss.
//! - **No ambient authority**: `AppSpec` cannot reach globals; all capabilities flow through `Cx`.
//! - **Leak reporting**: unresolved `AppHandle` drops emit structured diagnostics without
//!   panicking in `Drop`, preserving supervision-tree isolation.

use crate::cx::Cx;
use crate::cx::registry::RegistryHandle;
use crate::record::region::RegionState;
use crate::runtime::region_table::RegionCreateError;
use crate::runtime::state::RuntimeState;
use crate::supervision::{
    ChildSpec, CompiledSupervisor, RestartPolicy, StartTieBreak, SupervisorBuilder,
    SupervisorCompileError, SupervisorHandle, SupervisorSpawnError,
};
use crate::types::{Budget, CancelKind, CancelReason, RegionId};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub use managed_execution::{
    ManagedApp, ManagedAppBindError, ManagedAppBinding, ManagedAppGroupReport, ManagedAppHandle,
    ManagedAppTree, ManagedAppTreeHandle, ManagedAppTreeReport, ManagedAppWorkError,
};

mod resources;
pub use resources::{
    ManagedAppResourceBinding, ManagedAppResourceError, ManagedAppResourceRequirement,
    ManagedAppResources,
};

/// Executing bindings for the declarative manifest, separate from the legacy
/// state-threaded lowering so existing application contracts remain intact.
mod managed_execution {
    use super::{
        AppBudgetSpecV1, AppCxCapabilityV1, AppFeatureFlagV1, AppJobTriggerV1,
        AppRequiredCapabilitiesV1, AppRouteMethodV1, AppSpecV1, AppSpecV1CompileError,
        AppSpecV1WorkUnitKind, BTreeMap, BTreeSet, Budget, CancelKind, CancelReason, ChildSpec, Cx,
        RegistryHandle, RuntimeState, SupervisorBuilder, runtime_restart_policy,
    };
    use super::resources::ResourceCatalog;
    use super::{
        ManagedAppResourceBinding, ManagedAppResourceError, ManagedAppResourceRequirement,
        ManagedAppResources,
    };
    use crate::channel::mpsc;
    use crate::cx::{ChildRegion, ChildRegionSpec, cap};
    use crate::runtime::{JoinError, SpawnError, TaskHandle};
    use crate::supervision::{
        ManagedChildBinding, ManagedChildFactory, ManagedGeneration, ManagedRestartMode,
        ManagedSupervisor, ManagedSupervisorBindError, ManagedSupervisorHandle,
        ManagedSupervisorReport, SupervisionConfig,
    };
    use crate::types::{CapabilityBudget, CapabilityBudgetRequirements, Outcome};
    use crate::web::extract::Request;
    use crate::web::handler::Handler;
    use crate::web::{MethodRouter, Response, Router, StatusCode};
    use parking_lot::Mutex;
    use std::future::{Future, poll_fn};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::Poll;
    use std::time::Duration;

    /// The web router's view of a route path: empty segments dropped and
    /// parameter names erased. `/users`, `/users/` and `//users` are one route to
    /// the router (it merges them, the later handler replacing the earlier), and
    /// `/users/:id` and `/users/:uid` are one route too (the first registered
    /// shadows the other), so AppSpec duplicate detection and method merging key
    /// on this shape, not on the raw path (br-asupersync-mopkmt).
    fn route_shape(path: &str) -> String {
        let mut shape = String::new();
        for segment in path.split('/').filter(|segment| !segment.is_empty()) {
            shape.push('/');
            if segment.starts_with(':') {
                shape.push(':');
            } else {
                shape.push_str(segment);
            }
        }
        if shape.is_empty() {
            shape.push('/');
        }
        shape
    }

    type SignalReceiver = Arc<Mutex<Option<mpsc::Receiver<()>>>>;

    // Own the receiver while waiting, without a non-Send lock guard across await.
    // Dropping a generation restores its source before a replacement starts.
    struct SignalReceiverLease {
        slot: SignalReceiver,
        receiver: Option<mpsc::Receiver<()>>,
    }

    impl SignalReceiverLease {
        fn take<E>(slot: &SignalReceiver) -> Result<Self, ManagedAppWorkError<E>> {
            let receiver = slot
                .lock()
                .take()
                .ok_or(ManagedAppWorkError::SignalReceiverUnavailable)?;
            Ok(Self {
                slot: Arc::clone(slot),
                receiver: Some(receiver),
            })
        }
    }

    impl Drop for SignalReceiverLease {
        fn drop(&mut self) {
            if let Some(receiver) = self.receiver.take() {
                // Release the slot lock before retiring a displaced receiver.
                let retired = self.slot.lock().replace(receiver);
                drop(retired);
            }
        }
    }

    struct SignalBinding {
        source: String,
        receiver: SignalReceiver,
    }

    enum BindingKind<E> {
        Route(Arc<dyn Handler>),
        Worker(
            ManagedRestartMode,
            Arc<dyn ManagedChildFactory<E>>,
            Option<SignalBinding>,
        ),
        ResourceRoute {
            requirements: Vec<ManagedAppResourceRequirement>,
            handler: Arc<ResourceRouteFn>,
        },
        ResourceWorker {
            mode: ManagedRestartMode,
            requirements: Vec<ManagedAppResourceRequirement>,
            factory: Arc<ResourceWorkerFn<E>>,
            signal: Option<SignalBinding>,
        },
    }

    type ResourceRouteFn = dyn Fn(Cx, Request, ManagedAppResources)
        -> Pin<Box<dyn Future<Output = Response> + Send + 'static>> + Send + Sync;
    type ResourceWorkerFn<E> = dyn Fn(Cx, ManagedGeneration, ManagedAppResources)
        -> crate::supervision::ManagedChildFuture<E> + Send + Sync;

    struct ResourceRoute {
        handler: Arc<ResourceRouteFn>,
        resources: ManagedAppResources,
    }

    impl Handler for ResourceRoute {
        fn call(
            &self,
            cx: &Cx,
            request: Request,
        ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
            (self.handler)(cx.clone(), request, self.resources.clone())
        }
    }

    impl<E: Send + 'static> BindingKind<E> {
        fn resource_requirements(&self) -> &[ManagedAppResourceRequirement] {
            match self {
                Self::ResourceRoute { requirements, .. }
                | Self::ResourceWorker { requirements, .. } => requirements,
                Self::Route(_) | Self::Worker(..) => &[],
            }
        }

        fn bind_resources(self, resources: ManagedAppResources) -> Self {
            match self {
                Self::ResourceRoute { handler, .. } => Self::Route(Arc::new(ResourceRoute {
                    handler,
                    resources,
                })),
                Self::ResourceWorker { mode, factory, signal, .. } => Self::Worker(
                    mode,
                    Arc::new(move |cx, generation| {
                        factory(cx, generation, resources.clone())
                    }),
                    signal,
                ),
                plain => plain,
            }
        }
    }

    /// Explicit Rust implementation of one manifest work-unit name.
    ///
    /// Bindings use the compiler's qualified child names, such as
    /// `api.route.health` and `api.actor.cache`; handler symbols remain useful
    /// metadata and are never resolved through a global registry.
    pub struct ManagedAppBinding<E> {
        name: String,
        kind: BindingKind<E>,
    }

    impl<E> ManagedAppBinding<E> {
        /// Bind an HTTP handler to the method and path declared by a route.
        #[must_use]
        pub fn route(name: impl Into<String>, handler: impl Handler) -> Self {
            Self {
                name: name.into(),
                kind: BindingKind::Route(Arc::new(handler)),
            }
        }

        /// Bind an actor or job to a retained, explicitly restartable factory.
        #[must_use]
        pub fn worker(
            name: impl Into<String>,
            mode: ManagedRestartMode,
            factory: impl ManagedChildFactory<E>,
        ) -> Self {
            Self {
                name: name.into(),
                kind: BindingKind::Worker(mode, Arc::new(factory), None),
            }
        }

        /// Bind a route to its manifest-scoped typed resource view.
        ///
        /// Supply one type requirement for every resource named by the route
        /// or its service. Binding checks the complete view before any work is
        /// admitted. The handler receives the same restricted invocation `Cx`
        /// as ordinary managed routes; handles do not grant missing drivers.
        #[must_use]
        pub fn route_with_resources<F, Fut>(
            name: impl Into<String>,
            requirements: Vec<ManagedAppResourceRequirement>,
            handler: F,
        ) -> Self
        where
            F: Fn(Cx, Request, ManagedAppResources) -> Fut + Send + Sync + 'static,
            Fut: Future<Output = Response> + Send + 'static,
        {
            Self {
                name: name.into(),
                kind: BindingKind::ResourceRoute {
                    requirements,
                    handler: Arc::new(move |cx, request, resources| {
                        Box::pin(handler(cx, request, resources))
                    }),
                },
            }
        }

        /// Bind an actor or startup/interval job to real named resources.
        ///
        /// The view is physically limited to the service/entry-point resource
        /// union. Its handles remain shared across supervised generations.
        /// Per-invocation budgets, authority and drain behavior are unchanged.
        #[must_use]
        pub fn worker_with_resources<F, Fut>(
            name: impl Into<String>,
            mode: ManagedRestartMode,
            requirements: Vec<ManagedAppResourceRequirement>,
            factory: F,
        ) -> Self
        where
            F: Fn(Cx, ManagedGeneration, ManagedAppResources) -> Fut + Send + Sync + 'static,
            Fut: Future<Output = Outcome<(), E>> + Send + 'static,
        {
            Self {
                name: name.into(),
                kind: BindingKind::ResourceWorker {
                    mode,
                    requirements,
                    factory: Arc::new(move |cx, generation, resources| {
                        Box::pin(factory(cx, generation, resources))
                    }),
                    signal: None,
                },
            }
        }

        /// Bind a serial signalled job to both a bounded signal channel and
        /// its manifest-scoped typed resources. Signal consumption and drain
        /// semantics match [`Self::signal_worker`].
        #[must_use]
        pub fn signal_worker_with_resources<F, Fut>(
            name: impl Into<String>,
            source: impl Into<String>,
            receiver: mpsc::Receiver<()>,
            mode: ManagedRestartMode,
            requirements: Vec<ManagedAppResourceRequirement>,
            factory: F,
        ) -> Self
        where
            F: Fn(Cx, ManagedGeneration, ManagedAppResources) -> Fut + Send + Sync + 'static,
            Fut: Future<Output = Outcome<(), E>> + Send + 'static,
        {
            Self {
                name: name.into(),
                kind: BindingKind::ResourceWorker {
                    mode,
                    requirements,
                    factory: Arc::new(move |cx, generation, resources| {
                        Box::pin(factory(cx, generation, resources))
                    }),
                    signal: Some(SignalBinding {
                        source: source.into(),
                        receiver: Arc::new(Mutex::new(Some(receiver))),
                    }),
                },
            }
        }

        /// Bind an externally signalled background job to a bounded channel.
        ///
        /// The qualified job name and source must match the manifest's
        /// `Signal { source }` declaration. Each received unit notification
        /// admits one invocation with the declared budget and capabilities.
        /// Invocations do not overlap: the next notification is received only
        /// after the previous invocation and its region have fully drained.
        ///
        /// Keep the sender to publish notifications through MPSC's existing
        /// cancel-safe reserve/send API. The channel's capacity bounds pending
        /// signals; successful send means queued, while job outcomes appear in
        /// the supervisor report. An invocation consumes its notification even
        /// when it fails. Queued notifications remain available across a
        /// supervised restart, and stop discards notifications not yet run.
        ///
        /// Dropping every sender drains queued notifications, then completes
        /// the worker normally. Temporary and Transient modes stop on that EOF.
        /// Permanent mode applies its usual restart policy to the closed source,
        /// so it can exhaust the configured restart intensity without new work.
        /// Source ownership and cancellation remain with the managed application;
        /// this method installs no process-global signal handlers.
        #[must_use]
        pub fn signal_worker(
            name: impl Into<String>,
            source: impl Into<String>,
            receiver: mpsc::Receiver<()>,
            mode: ManagedRestartMode,
            factory: impl ManagedChildFactory<E>,
        ) -> Self {
            Self {
                name: name.into(),
                kind: BindingKind::Worker(
                    mode,
                    Arc::new(factory),
                    Some(SignalBinding {
                        source: source.into(),
                        receiver: Arc::new(Mutex::new(Some(receiver))),
                    }),
                ),
            }
        }
    }

    /// Rejection before managed application publication or task admission.
    #[derive(Debug)]
    #[non_exhaustive]
    pub enum ManagedAppBindError {
        /// Invalid manifest or unsupported legacy restart-policy mapping.
        Compile(AppSpecV1CompileError),
        /// A qualified work-unit name was supplied more than once.
        Duplicate(String),
        /// A manifest work unit has no supplied implementation.
        Missing(String),
        /// A binding names no work unit in the manifest.
        Unexpected(String),
        /// A route received a worker binding, or a worker received a handler.
        KindMismatch(String),
        /// A named resource, typed requirement, or scoped view is invalid.
        Resource(ManagedAppResourceError),
        /// A declared group has no explicit supervision configuration.
        MissingGroupConfig(String),
        /// A supervision configuration names no declared group.
        UnexpectedGroupConfig(String),
        /// A declaration needs an adapter this execution API does not provide.
        Unsupported { unit: String, reason: &'static str },
        /// A runtime effect or driver is absent from the caller's authority.
        Capability {
            unit: String,
            capability: AppCxCapabilityV1,
        },
        /// A required Cargo feature was not enabled in this build.
        Feature {
            unit: String,
            feature: AppFeatureFlagV1,
        },
        /// A budget cannot be represented or is already exhausted.
        Budget { name: String, reason: &'static str },
        /// The compiled managed topology was refused.
        Supervisor(ManagedSupervisorBindError),
        /// The runtime refused the controller task.
        Spawn(SpawnError),
    }

    impl std::fmt::Display for ManagedAppBindError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "managed AppSpec binding failed: {self:?}")
        }
    }
    impl std::error::Error for ManagedAppBindError {}

    /// Domain and infrastructure failures from an executed application worker.
    #[derive(Debug)]
    #[non_exhaustive]
    pub enum ManagedAppWorkError<E> {
        /// The supplied worker returned its application error.
        Domain(E),
        /// Budget-region admission or quiescent close failed.
        Region(crate::cx::ChildRegionError),
        /// The runtime refused the actual workload task.
        Spawn(SpawnError),
        /// The actual workload task could not be joined.
        Join(JoinError),
        /// The workload's region finalizers reported unsuccessful cleanup.
        Cleanup(crate::record::task::TaskOutcome),
        /// A managed generation could not take exclusive signal-source ownership.
        SignalReceiverUnavailable,
        /// Waiting for a signal failed before an invocation was admitted.
        SignalReceive(mpsc::RecvError),
        /// A nested group stopped with a controller error. Its full terminal
        /// report, including the original domain failures, is retained in the
        /// corresponding [`ManagedAppGroupReport`].
        GroupFailed(String),
        /// A retained, already validated group could not be reconstructed.
        GroupBinding(ManagedSupervisorBindError),
    }

    type AppFactory<E> = Arc<dyn ManagedChildFactory<ManagedAppWorkError<E>>>;
    type CleanupObserver =
        Arc<dyn Fn(ManagedGeneration) -> Option<crate::record::task::TaskOutcome> + Send + Sync>;
    type WorkCleanup = Arc<Mutex<Option<(ManagedGeneration, crate::record::task::TaskOutcome)>>>;

    struct AppFactoryRef<E>(AppFactory<E>);

    impl<E: 'static> ManagedChildFactory<ManagedAppWorkError<E>> for AppFactoryRef<E> {
        fn start(
            &self,
            cx: Cx,
            generation: ManagedGeneration,
        ) -> crate::supervision::ManagedChildFuture<ManagedAppWorkError<E>> {
            self.0.start(cx, generation)
        }

        fn retired(&self) {
            self.0.retired();
        }
    }

    // AppSpec generates only plain child topology. Retain its real factories
    // separately from legacy ChildStart callbacks so a parent can reconstruct
    // a nested controller without moving or duplicating a live generation.
    struct AppGroupTemplate<E> {
        name: String,
        restart: super::RestartPolicy,
        stop_on_child_failure: bool,
        config: SupervisionConfig,
        children: Vec<AppChildTemplate<E>>,
    }

    struct AppChildTemplate<E> {
        name: String,
        mode: ManagedRestartMode,
        factory: AppFactory<E>,
        cleanup: Option<CleanupObserver>,
    }

    impl<E: 'static> AppGroupTemplate<E> {
        fn push(
            &mut self,
            name: String,
            mode: ManagedRestartMode,
            factory: impl ManagedChildFactory<ManagedAppWorkError<E>>,
            cleanup: Option<CleanupObserver>,
        ) {
            self.children.push(AppChildTemplate {
                name,
                mode,
                factory: Arc::new(factory),
                cleanup,
            });
        }

        fn bind(
            &self,
        ) -> Result<ManagedSupervisor<ManagedAppWorkError<E>>, ManagedSupervisorBindError> {
            let mut builder =
                SupervisorBuilder::new(self.name.clone()).with_restart_policy(self.restart);
            let mut bindings = Vec::with_capacity(self.children.len());
            for child in &self.children {
                builder = builder.child(ChildSpec::new(
                    child.name.clone(),
                    |_scope: &crate::cx::Scope<'static>, _state: &mut RuntimeState, _cx: &Cx| {
                        Err(SpawnError::RuntimeUnavailable)
                    },
                ));
                let binding = ManagedChildBinding::new(
                    child.name.clone(),
                    child.mode,
                    AppFactoryRef(Arc::clone(&child.factory)),
                );
                bindings.push(match &child.cleanup {
                    Some(observer) => binding.with_cleanup_observer(Arc::clone(observer)),
                    None => binding,
                });
            }
            let supervisor = builder
                .compile()
                .map_err(ManagedSupervisorBindError::Topology)?
                .bind_managed(bindings, self.config.clone())?;
            Ok(if self.stop_on_child_failure {
                supervisor.with_stop_on_child_failure()
            } else {
                supervisor
            })
        }
    }

    type GroupReports<E> = Arc<Mutex<BTreeMap<String, ManagedAppGroupReport<E>>>>;

    struct AppGroupFactory<E> {
        group: String,
        template: AppGroupTemplate<E>,
        reports: GroupReports<E>,
    }

    impl<E: Send + 'static> ManagedChildFactory<ManagedAppWorkError<E>> for AppGroupFactory<E> {
        fn start(
            &self,
            cx: Cx,
            generation: ManagedGeneration,
        ) -> crate::supervision::ManagedChildFuture<ManagedAppWorkError<E>> {
            let supervisor = self.template.bind();
            let group = self.group.clone();
            let reports = Arc::clone(&self.reports);
            Box::pin(async move {
                let supervisor = match supervisor {
                    Ok(supervisor) => supervisor,
                    Err(error) => return Outcome::Err(ManagedAppWorkError::GroupBinding(error)),
                };
                let report = supervisor.run(&cx).await;
                if report.escalations != 0 {
                    // The nested close barrier has applied its parent-region
                    // escalation. Acknowledge that request before returning the
                    // typed failure to the root. The separate cleanup observer
                    // still forbids replacement after any failed inner cleanup.
                    let _ = cx.checkpoint();
                }
                let outcome = match &report.outcome {
                    Outcome::Ok(()) => Outcome::Ok(()),
                    Outcome::Err(_) => Outcome::Err(ManagedAppWorkError::GroupFailed(group.clone())),
                    Outcome::Cancelled(reason) => Outcome::Cancelled(reason.clone()),
                    Outcome::Panicked(payload) => Outcome::Panicked(payload.clone()),
                };
                let retired = reports.lock().insert(
                    group.clone(),
                    ManagedAppGroupReport {
                        name: group,
                        generation,
                        report,
                    },
                );
                // E can run arbitrary Drop code. Neither report replacement nor
                // a destructor panic may run while the publication lock is held.
                drop(retired);
                outcome
            })
        }
    }

    struct WorkPolicy {
        name: String,
        required: AppRequiredCapabilitiesV1,
        budget: Option<AppBudgetSpecV1>,
        interval: Option<Duration>,
        signal: Option<SignalReceiver>,
        cleanup: WorkCleanup,
        resource_capabilities: Vec<AppCxCapabilityV1>,
    }

    impl WorkPolicy {
        fn validate_runtime(&self, cx: &Cx) -> Result<(), ManagedAppBindError> {
            let caps = cx.capabilities();
            for capability in &self.required.cx_capabilities {
                let present = match capability {
                    AppCxCapabilityV1::Pure | AppCxCapabilityV1::Trace => true,
                    AppCxCapabilityV1::Spawn => caps.spawn,
                    AppCxCapabilityV1::Time => caps.time && cx.timer_driver().is_some(),
                    AppCxCapabilityV1::Entropy => caps.entropy,
                    AppCxCapabilityV1::Io | AppCxCapabilityV1::Net => {
                        caps.io && cx.io_driver_handle().is_some()
                    }
                    AppCxCapabilityV1::Remote => caps.remote && cx.has_remote(),
                    AppCxCapabilityV1::Registry => cx.registry_handle().is_some(),
                    AppCxCapabilityV1::Blocking => {
                        caps.spawn && cx.blocking_pool_handle().is_some()
                    }
                    // These families have no generic Cx driver bit. Only an
                    // explicitly supplied, kind-matched named handle admits
                    // them. Independent Io/Time/Spawn/etc checks still apply.
                    AppCxCapabilityV1::Database
                    | AppCxCapabilityV1::Messaging
                    | AppCxCapabilityV1::Tls
                    | AppCxCapabilityV1::Quic
                    | AppCxCapabilityV1::BrowserHost => {
                        self.resource_capabilities.contains(capability)
                    }
                };
                if !present {
                    return Err(ManagedAppBindError::Capability {
                        unit: self.name.clone(),
                        capability: capability.clone(),
                    });
                }
            }
            if (self.interval.is_some()
                || cx.budget().deadline.is_some()
                || self
                    .budget
                    .as_ref()
                    .is_some_and(|b| b.deadline_ms.is_some()))
                && cx.timer_driver().is_none()
            {
                return Err(ManagedAppBindError::Capability {
                    unit: self.name.clone(),
                    capability: AppCxCapabilityV1::Time,
                });
            }
            cx.plan_child_capability_budget(self.envelope(), CapabilityBudgetRequirements::NONE)
                .map_err(|_| ManagedAppBindError::Budget {
                    name: self.name.clone(),
                    reason: "capability envelope is exhausted",
                })?;
            Ok(())
        }

        fn envelope(&self) -> CapabilityBudget {
            let mut budget = CapabilityBudget::UNSPECIFIED;
            if let Some(spec) = &self.budget {
                budget.io_bytes = spec.io_bytes;
                budget.memory_bytes = spec.memory_bytes;
            }
            budget
        }

        fn region_spec(&self, cx: &Cx) -> ChildRegionSpec {
            let mut budget = Budget::INFINITE;
            if let Some(spec) = &self.budget {
                if let Some(polls) = spec.poll_quota {
                    budget.poll_quota = u32::try_from(polls).expect("validated AppSpec poll quota");
                }
                if let Some(ms) = spec.deadline_ms {
                    budget.deadline = Some(cx.now_for_observability() + Duration::from_millis(ms));
                }
            }
            let mut spec = ChildRegionSpec::inherit().with_budget(budget);
            spec.capability_budget = Some(self.envelope());
            spec
        }

        fn restrict(&self, mut cx: Cx, registry: Option<RegistryHandle>) -> Cx {
            use cap::CapSetRuntimeMask;
            let has = |wanted| self.required.cx_capabilities.contains(&wanted);
            let mut mask = cap::CapMask::all();
            if !has(AppCxCapabilityV1::Spawn) && !has(AppCxCapabilityV1::Blocking) {
                mask = mask.intersect(<cap::CapSet<false, true, true, true, true>>::MASK);
            }
            if !has(AppCxCapabilityV1::Time) {
                mask = mask.intersect(<cap::CapSet<true, false, true, true, true>>::MASK);
            }
            if !has(AppCxCapabilityV1::Entropy) {
                mask = mask.intersect(<cap::CapSet<true, true, false, true, true>>::MASK);
            }
            if !has(AppCxCapabilityV1::Io) && !has(AppCxCapabilityV1::Net) {
                mask = mask.intersect(<cap::CapSet<true, true, true, false, true>>::MASK);
            }
            if !has(AppCxCapabilityV1::Remote) {
                mask = mask.intersect(<cap::CapSet<true, true, true, true, false>>::MASK);
            }
            cx.runtime_mask = cx.runtime_mask.intersect(mask);
            cx.with_registry_handle(if has(AppCxCapabilityV1::Registry) {
                registry
            } else {
                None
            })
        }
    }

    async fn poll_restricted<F: Future>(cx: &Cx, future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        poll_fn(|task| {
            let _current = Cx::set_current(Some(cx.clone()));
            future.as_mut().poll(task)
        })
        .await
    }

    // Installing a scheduler deadline alone does not create a wake source for
    // an otherwise parked task. This timer owns the declared limit, requests
    // cancellation of the whole work region, and still joins actual cleanup.
    // Ready work has priority over same-poll cancellation/deadline observation.
    async fn join_work<T: Send + 'static>(
        task: &mut TaskHandle<T>,
        region: &ChildRegion,
        requester: &Cx,
    ) -> Result<T, JoinError> {
        let mut join = std::pin::pin!(task.join(requester));
        let mut cancelled = std::pin::pin!(requester.cancelled());
        let mut deadline = region.cx().budget().deadline.map(|deadline| {
            Box::pin(region.cx().timer_driver().map_or_else(
                || crate::time::Sleep::new(deadline),
                |timer| crate::time::Sleep::with_timer_driver(deadline, timer),
            ))
        });
        let mut requested = false;
        poll_fn(|poll_cx| {
            if let Poll::Ready(result) = join.as_mut().poll(poll_cx) {
                return Poll::Ready(result);
            }
            if !requested
                && cancelled.as_mut().poll(poll_cx).is_ready()
                && requester.checkpoint().is_err()
            {
                requested = true;
                let reason = requester
                    .cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("AppSpec work cancelled"));
                let _ = region.cancel(reason);
            }
            if !requested
                && deadline
                    .as_mut()
                    .is_some_and(|timer| timer.as_mut().poll_deadline(poll_cx).is_ready())
            {
                requested = true;
                let _ = region.cancel(CancelReason::with_origin(
                    CancelKind::Deadline,
                    region.region_id(),
                    region.cx().now_for_observability(),
                ));
            }
            Poll::Pending
        })
        .await
    }

    type RouteSlot = Arc<Mutex<Option<Cx>>>;

    struct RoutePublication(RouteSlot);
    impl Drop for RoutePublication {
        fn drop(&mut self) {
            let retired = self.0.lock().take();
            drop(retired);
        }
    }

    struct AppRoute {
        slot: RouteSlot,
        policy: Arc<WorkPolicy>,
        handler: Arc<dyn Handler>,
    }

    impl Handler for AppRoute {
        fn call(
            &self,
            requester: &Cx,
            request: Request,
        ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
            let requester = requester.clone();
            Box::pin(async move {
                let Some(owner) = self.slot.lock().clone() else {
                    return Response::empty(StatusCode::SERVICE_UNAVAILABLE);
                };
                if owner.is_cancel_requested() {
                    return Response::empty(StatusCode::SERVICE_UNAVAILABLE);
                }
                let region = match owner
                    .open_child_region(self.policy.region_spec(&owner))
                    .await
                {
                    Ok(region) => region,
                    Err(_) => return Response::empty(StatusCode::SERVICE_UNAVAILABLE),
                };
                let policy = Arc::clone(&self.policy);
                let handler = Arc::clone(&self.handler);
                let registry = owner.registry_handle();
                let spawned = region.cx().spawn(move |cx| async move {
                    let restricted = policy.restrict(cx, registry);
                    let future = {
                        let _current = Cx::set_current(Some(restricted.clone()));
                        handler.call(&restricted, request)
                    };
                    poll_restricted(&restricted, future).await
                });
                let result = match spawned {
                    Ok(mut task) => join_work(&mut task, &region, &requester).await,
                    Err(_) => Err(JoinError::Cancelled(CancelReason::resource_unavailable())),
                };
                let clean = region.close_with_outcome().await.is_ok_and(|closed| {
                    closed
                        .cleanup_outcome
                        .is_none_or(|outcome| matches!(outcome, Outcome::Ok(())))
                });
                if clean {
                    result.unwrap_or_else(|_| Response::empty(StatusCode::INTERNAL_SERVER_ERROR))
                } else {
                    Response::empty(StatusCode::INTERNAL_SERVER_ERROR)
                }
            })
        }
    }

    async fn wait_signal<E>(
        owner: &Cx,
        signal: &SignalReceiver,
    ) -> Result<bool, ManagedAppWorkError<E>> {
        // Do not consume another queued notification after generation cancel.
        if owner.checkpoint().is_err() {
            return Err(ManagedAppWorkError::SignalReceive(mpsc::RecvError::Cancelled));
        }
        let mut lease = SignalReceiverLease::take::<E>(signal)?;
        if owner.checkpoint().is_err() {
            return Err(ManagedAppWorkError::SignalReceive(mpsc::RecvError::Cancelled));
        }
        // The receiver remains owned by the lease across this cancellation-
        // aware wait, with no lock guard, timer, or busy polling across await.
        let receiver = lease
            .receiver
            .as_mut()
            .expect("signal lease owns its receiver");
        match receiver.recv(owner).await {
            Ok(()) => Ok(true),
            Err(mpsc::RecvError::Disconnected) => Ok(false),
            Err(error) => Err(ManagedAppWorkError::SignalReceive(error)),
        }
    }

    async fn run_worker<E: Send + 'static>(
        owner: Cx,
        generation: ManagedGeneration,
        policy: Arc<WorkPolicy>,
        factory: Arc<dyn ManagedChildFactory<E>>,
    ) -> Outcome<(), ManagedAppWorkError<E>> {
        loop {
            if let Some(signal) = &policy.signal {
                let received = wait_signal::<E>(&owner, signal).await;
                if owner.checkpoint().is_err() {
                    return Outcome::Cancelled(
                        owner
                            .cancel_reason()
                            .unwrap_or_else(|| CancelReason::user("AppSpec worker cancelled")),
                    );
                }
                match received {
                    Ok(true) => {}
                    Ok(false) => return Outcome::Ok(()),
                    Err(error) => return Outcome::Err(error),
                }
            } else if let Some(interval) = policy.interval {
                wait_interval(&owner, interval).await;
            }
            if owner.checkpoint().is_err() {
                return Outcome::Cancelled(
                    owner
                        .cancel_reason()
                        .unwrap_or_else(|| CancelReason::user("AppSpec worker cancelled")),
                );
            }
            let region = match owner.open_child_region(policy.region_spec(&owner)).await {
                Ok(region) => region,
                Err(error) => return Outcome::Err(ManagedAppWorkError::Region(error)),
            };
            let body_policy = Arc::clone(&policy);
            let body_factory = Arc::clone(&factory);
            let registry = owner.registry_handle();
            let task = region.cx().spawn(move |cx| async move {
                let identity = ManagedGeneration {
                    number: generation.number,
                    region: cx.region_id(),
                    task: cx.task_id(),
                };
                let restricted = body_policy.restrict(cx, registry);
                let future = {
                    let _current = Cx::set_current(Some(restricted.clone()));
                    body_factory.start(restricted.clone(), identity)
                };
                poll_restricted(&restricted, future).await
            });
            let mut outcome = match task {
                Ok(mut task) => match join_work(&mut task, &region, &owner).await {
                    Ok(Outcome::Ok(())) => Outcome::Ok(()),
                    Ok(Outcome::Err(error)) => Outcome::Err(ManagedAppWorkError::Domain(error)),
                    Ok(Outcome::Cancelled(reason)) | Err(JoinError::Cancelled(reason)) => {
                        Outcome::Cancelled(reason)
                    }
                    Ok(Outcome::Panicked(payload)) | Err(JoinError::Panicked(payload)) => {
                        Outcome::Panicked(payload)
                    }
                    Err(error) => Outcome::Err(ManagedAppWorkError::Join(error)),
                },
                Err(error) => Outcome::Err(ManagedAppWorkError::Spawn(error)),
            };
            match region.close_with_outcome().await {
                Ok(closed) => {
                    if let Some(cleanup) = closed.cleanup_outcome {
                        if !cleanup.is_ok() {
                            let retired = policy
                                .cleanup
                                .lock()
                                .replace((generation, cleanup.clone()));
                            drop(retired);
                        }
                        if !matches!(cleanup, Outcome::Ok(()))
                            && !matches!(outcome, Outcome::Panicked(_))
                        {
                            outcome = match cleanup {
                                Outcome::Panicked(payload) => Outcome::Panicked(payload),
                                other => Outcome::Err(ManagedAppWorkError::Cleanup(other)),
                            };
                        }
                    }
                }
                Err(error) if !matches!(outcome, Outcome::Panicked(_)) => {
                    outcome = Outcome::Err(ManagedAppWorkError::Region(error))
                }
                Err(_) => {}
            }
            if (policy.interval.is_none() && policy.signal.is_none())
                || !matches!(outcome, Outcome::Ok(()))
            {
                return outcome;
            }
        }
    }

    async fn wait_interval(owner: &Cx, interval: Duration) {
        let next = owner.now_for_observability() + interval;
        let wake_at = owner
            .budget()
            .deadline
            .map_or(next, |deadline| next.min(deadline));
        let timer = owner.timer_driver().map_or_else(
            || crate::time::Sleep::new(wake_at),
            |driver| crate::time::Sleep::with_timer_driver(wake_at, driver),
        );
        let mut timer = std::pin::pin!(timer);
        let mut cancelled = std::pin::pin!(owner.cancelled());
        poll_fn(|task| {
            if cancelled.as_mut().poll(task).is_ready() && owner.checkpoint().is_err() {
                return Poll::Ready(());
            }
            // An inherited deadline must wake the controller even when the
            // next interval is far away; run_worker checkpoints before admission.
            timer.as_mut().poll_deadline(task)
        })
        .await;
    }

    /// Prepared, executing AppSpec with real routes and managed workers.
    ///
    /// The current mapping supports one supervisor group, actors, startup jobs,
    /// and non-overlapping interval and explicitly bound signal jobs.
    /// Routes run only while their managed
    /// generation is active. Their method/path comes from the manifest; each
    /// invocation owns a child region and drains before returning its response.
    /// A handler that acknowledges cancellation can finish cleanup and return
    /// a response, following the normal task-join contract. New requests after
    /// route retirement receive 503. Interval jobs wait their declared delay
    /// before the first invocation and between fully drained invocations.
    /// A `Stop` group drains all workers and routes after the first child domain
    /// failure or panic, retains that failure in its terminal report, and does
    /// not admit a replacement. Normal success/cancellation follows the bound
    /// worker's restart mode.
    /// Poll/deadline limits and memory/I/O capability envelopes derive from the
    /// declared budget and can only tighten parent limits. Capability envelopes
    /// govern participating runtime primitives, not arbitrary Rust allocations.
    /// The existing five Cx effect bits are attenuated; tracing remains an
    /// ungated diagnostic capability, as on other restricted Cx values.
    ///
    /// Signal jobs require `ManagedAppBinding::signal_worker` with the exact
    /// declared source name. Named resources require the explicit typed
    /// resource entry point; SLO and observability adapters remain unsupported.
    /// The legacy `compile_with_child_specs` and `CompiledApp::start` are unchanged.
    pub struct ManagedApp<E> {
        template: AppGroupTemplate<E>,
        router: Arc<Router>,
        policies: Vec<Arc<WorkPolicy>>,
        routes: Vec<RouteSlot>,
    }

    impl<E: Send + 'static> ManagedApp<E> {
        fn validate_start(&self, cx: &Cx) -> Result<(), ManagedAppBindError> {
            if !cx.capabilities().spawn {
                return Err(ManagedAppBindError::Capability {
                    unit: "application controller".to_string(),
                    capability: AppCxCapabilityV1::Spawn,
                });
            }
            for policy in &self.policies {
                policy.validate_runtime(cx)?;
            }
            Ok(())
        }

        /// Inspect or install the actual router; inactive routes return 503.
        #[must_use]
        pub fn router(&self) -> Arc<Router> {
            Arc::clone(&self.router)
        }

        /// Run until every worker stops or the owner requests cancellation.
        /// The report is produced only after managed-region quiescence.
        pub async fn run(
            self,
            cx: &Cx,
        ) -> Result<ManagedSupervisorReport<ManagedAppWorkError<E>>, ManagedAppBindError> {
            self.validate_start(cx)?;
            let supervisor = self
                .template
                .bind()
                .map_err(ManagedAppBindError::Supervisor)?;
            Ok(supervisor.run(cx).await)
        }

        /// Start a region-owned controller after checking every declaration.
        pub fn start(self, cx: &Cx) -> Result<ManagedAppHandle<E>, ManagedAppBindError> {
            self.validate_start(cx)?;
            let controller = self
                .template
                .bind()
                .map_err(ManagedAppBindError::Supervisor)?
                .spawn(cx)
                .map_err(ManagedAppBindError::Spawn)?;
            Ok(ManagedAppHandle {
                controller,
                router: self.router,
                routes: self.routes,
            })
        }
    }

    /// Cancellation owner and router for a started managed application.
    ///
    /// Dropping this handle requests controller cancellation; `join` observes
    /// actual worker and request-region drain through the retained controller.
    pub struct ManagedAppHandle<E> {
        controller: ManagedSupervisorHandle<ManagedAppWorkError<E>>,
        router: Arc<Router>,
        routes: Vec<RouteSlot>,
    }

    impl<E> ManagedAppHandle<E> {
        /// Router backed by this application's live route generations.
        #[must_use]
        pub fn router(&self) -> Arc<Router> {
            Arc::clone(&self.router)
        }
        /// Whether every declared route has an active generation.
        #[must_use]
        pub fn routes_ready(&self) -> bool {
            self.routes.iter().all(|slot| {
                slot.lock()
                    .as_ref()
                    .is_some_and(|cx| !cx.is_cancel_requested())
            })
        }
        /// Request application stop; joining still awaits all owned cleanup.
        pub fn abort(&self) {
            self.controller.abort();
        }
        /// Await the controller's terminal report after region quiescence.
        pub async fn join(
            &mut self,
        ) -> Result<ManagedSupervisorReport<ManagedAppWorkError<E>>, JoinError> {
            self.controller.join().await
        }
    }

    /// Latest fully drained execution of one nested AppSpec group.
    #[derive(Debug)]
    pub struct ManagedAppGroupReport<E> {
        /// Manifest group name.
        pub name: String,
        /// The root controller's generation that owned this group execution.
        /// Descendant generation numbers start afresh within each execution;
        /// their task and region identities remain distinct.
        pub generation: ManagedGeneration,
        /// Actual nested controller result, with original worker domain errors.
        pub report: ManagedSupervisorReport<ManagedAppWorkError<E>>,
    }

    /// Terminal application tree receipt, available after every region drains.
    #[derive(Debug)]
    pub struct ManagedAppTreeReport<E> {
        /// Named root group's controller, including its direct work units and
        /// the `group:<name>` children representing other manifest groups.
        pub root: ManagedSupervisorReport<ManagedAppWorkError<E>>,
        /// Latest completed execution per nested group, in manifest order.
        /// Storage is bounded by the number of groups, not restart count. A
        /// group cancelled before its factory runs has no new nested report;
        /// the root receipt retains that exact failed admission/generation.
        pub groups: Vec<ManagedAppGroupReport<E>>,
    }

    /// Explicit executable hierarchy for the flat AppSpec v1 group list.
    ///
    /// The named root group owns its declared work units and one Transient
    /// managed child for every other group, in manifest order. Nested groups
    /// apply their own restart policy and intensity configuration. Their normal
    /// completion or voluntary cancellation does not restart the whole group;
    /// a terminal controller error or panic is a failure seen by the root.
    /// Root OneForAll replacement drains affected groups before reconstructing
    /// them; root Stop drains the complete tree after the first child failure.
    /// Existing supervisor escalation still targets the owning parent region.
    ///
    /// This additive mapping does not add parent edges to the v1 wire schema.
    /// Route publication slots and signal receivers survive replacement, but
    /// old generations fully drain before replacement publishes those routes.
    /// Budgets and capabilities are checked for every work unit before start.
    ///
    /// Named resources require [`AppSpecV1::bind_managed_groups_with_resources`].
    /// SLO and observability adapters retain their explicit refusals.
    /// Use [`AppSpecV1::bind_managed_groups`] for groups without resources.
    pub struct ManagedAppTree<E> {
        app: ManagedApp<E>,
        reports: GroupReports<E>,
        group_order: Vec<String>,
    }

    fn take_group_reports<E>(
        reports: &GroupReports<E>,
        order: &[String],
    ) -> Vec<ManagedAppGroupReport<E>> {
        let mut completed = {
            let mut publication = reports.lock();
            std::mem::take(&mut *publication)
        };
        order
            .iter()
            .filter_map(|name| completed.remove(name))
            .collect()
    }

    impl<E: Send + 'static> ManagedAppTree<E> {
        /// Router covering routes from every group; inactive routes return 503.
        #[must_use]
        pub fn router(&self) -> Arc<Router> {
            self.app.router()
        }

        /// Run the root controller and collect the bounded nested receipts.
        pub async fn run(self, cx: &Cx) -> Result<ManagedAppTreeReport<E>, ManagedAppBindError> {
            let root = self.app.run(cx).await?;
            Ok(ManagedAppTreeReport {
                root,
                groups: take_group_reports(&self.reports, &self.group_order),
            })
        }

        /// Validate all work-unit authority before admitting the root task.
        pub fn start(self, cx: &Cx) -> Result<ManagedAppTreeHandle<E>, ManagedAppBindError> {
            Ok(ManagedAppTreeHandle {
                app: self.app.start(cx)?,
                reports: self.reports,
                group_order: self.group_order,
            })
        }
    }

    /// Cancellation owner for a started application group tree.
    /// Dropping it requests cancellation; joining observes actual tree drain.
    pub struct ManagedAppTreeHandle<E> {
        app: ManagedAppHandle<E>,
        reports: GroupReports<E>,
        group_order: Vec<String>,
    }

    impl<E> ManagedAppTreeHandle<E> {
        /// Router shared by all current group generations.
        #[must_use]
        pub fn router(&self) -> Arc<Router> {
            self.app.router()
        }

        /// Whether every declared route currently has an active generation.
        #[must_use]
        pub fn routes_ready(&self) -> bool {
            self.app.routes_ready()
        }

        /// Request stop of the whole tree; cleanup remains joinable.
        pub fn abort(&self) {
            self.app.abort();
        }

        /// Await root quiescence, then transfer the complete bounded receipts.
        pub async fn join(&mut self) -> Result<ManagedAppTreeReport<E>, JoinError> {
            let root = self.app.join().await?;
            Ok(ManagedAppTreeReport {
                root,
                groups: take_group_reports(&self.reports, &self.group_order),
            })
        }
    }

    fn feature_enabled(feature: &AppFeatureFlagV1) -> bool {
        match feature {
            AppFeatureFlagV1::NativeRuntime => cfg!(feature = "native-runtime"),
            AppFeatureFlagV1::WasmRuntime => cfg!(feature = "wasm-runtime"),
            AppFeatureFlagV1::BrowserIo => cfg!(feature = "browser-io"),
            AppFeatureFlagV1::BrowserTrace => cfg!(feature = "browser-trace"),
            AppFeatureFlagV1::DeterministicMode => cfg!(feature = "deterministic-mode"),
            AppFeatureFlagV1::MessagingFabric => cfg!(feature = "messaging-fabric"),
            AppFeatureFlagV1::Metrics => cfg!(feature = "metrics"),
            AppFeatureFlagV1::TracingIntegration => cfg!(feature = "tracing-integration"),
            AppFeatureFlagV1::Sqlite => cfg!(feature = "sqlite"),
            AppFeatureFlagV1::Postgres => cfg!(feature = "postgres"),
            AppFeatureFlagV1::Mysql => cfg!(feature = "mysql"),
            AppFeatureFlagV1::Tls => cfg!(feature = "tls"),
            AppFeatureFlagV1::TlsNativeRoots => cfg!(feature = "tls-native-roots"),
            AppFeatureFlagV1::TlsWebpkiRoots => cfg!(feature = "tls-webpki-roots"),
            AppFeatureFlagV1::Quic => cfg!(feature = "quic"),
            AppFeatureFlagV1::Http3 => cfg!(feature = "http3"),
            AppFeatureFlagV1::Kafka => cfg!(feature = "kafka"),
            AppFeatureFlagV1::IoUring => cfg!(feature = "io-uring"),
            AppFeatureFlagV1::TokioCompat => cfg!(feature = "tokio-compat"),
        }
    }

    impl AppSpecV1 {
        /// Bind manifest routes and workers to actual managed execution.
        /// All names, kinds, budgets, features and unsupported mappings are
        /// checked before factories can run. Runtime authority is checked again
        /// against the context supplied to `ManagedApp::start` or `run`.
        #[allow(clippy::too_many_lines)]
        pub fn bind_managed<E: Send + 'static>(
            self,
            bindings: Vec<ManagedAppBinding<E>>,
            config: SupervisionConfig,
        ) -> Result<ManagedApp<E>, ManagedAppBindError> {
            let configs = BTreeMap::from([(self.supervision.root_group.clone(), config)]);
            Ok(self.bind_managed_impl(bindings, configs, false, None)?.app)
        }

        /// Bind a single group with explicit typed, caller-owned resources.
        ///
        /// Supply exactly one resource binding per manifest declaration. Each
        /// resource-aware work binding must list the Rust types for the union
        /// of its service-level and entry-point resource names. Each resource's
        /// capability must also be explicitly declared by that entry point;
        /// service resource inheritance never grants additional Cx authority.
        /// Missing handles, wrong types and incompatible declarations fail
        /// before any factory runs. Resource feature flags are checked too.
        ///
        /// Values are shared handles, not automatically initialized or shut
        /// down pools. Retained routers, factories and cloned resource views
        /// can keep those handles alive after application join.
        pub fn bind_managed_with_resources<E: Send + 'static>(
            self,
            bindings: Vec<ManagedAppBinding<E>>,
            resources: Vec<ManagedAppResourceBinding>,
            config: SupervisionConfig,
        ) -> Result<ManagedApp<E>, ManagedAppBindError> {
            let configs = BTreeMap::from([(self.supervision.root_group.clone(), config)]);
            Ok(self
                .bind_managed_impl(bindings, configs, false, Some(resources))?
                .app)
        }

        /// Bind every manifest group through the explicit hierarchy documented
        /// by [`ManagedAppTree`]. Supply exactly one intensity/backoff config
        /// per declared group; non-Stop restart policies must match the manifest.
        /// No factory runs until all names, routes, features, budgets and group
        /// configurations pass preflight. The legacy single-group entry point
        /// remains unchanged, including its refusal of multiple groups.
        pub fn bind_managed_groups<E: Send + 'static>(
            self,
            bindings: Vec<ManagedAppBinding<E>>,
            configs: BTreeMap<String, SupervisionConfig>,
        ) -> Result<ManagedAppTree<E>, ManagedAppBindError> {
            self.bind_managed_impl(bindings, configs, true, None)
        }

        /// Bind every group with the typed resource contract of
        /// [`Self::bind_managed_with_resources`]. Handles remain shared across
        /// supervised replacements; views contain only each work unit's
        /// physically selected allowlist. All preflight checks finish before
        /// admitting the root controller.
        pub fn bind_managed_groups_with_resources<E: Send + 'static>(
            self,
            bindings: Vec<ManagedAppBinding<E>>,
            resources: Vec<ManagedAppResourceBinding>,
            configs: BTreeMap<String, SupervisionConfig>,
        ) -> Result<ManagedAppTree<E>, ManagedAppBindError> {
            self.bind_managed_impl(bindings, configs, true, Some(resources))
        }

        #[allow(clippy::too_many_lines)]
        fn bind_managed_impl<E: Send + 'static>(
            self,
            bindings: Vec<ManagedAppBinding<E>>,
            mut configs: BTreeMap<String, SupervisionConfig>,
            grouped: bool,
            resources: Option<Vec<ManagedAppResourceBinding>>,
        ) -> Result<ManagedAppTree<E>, ManagedAppBindError> {
            let plan = self.compiler_plan().map_err(ManagedAppBindError::Compile)?;
            let resource_catalog = resources
                .map(|bindings| ResourceCatalog::bind(&self.resources, bindings))
                .transpose()
                .map_err(ManagedAppBindError::Resource)?;
            if resource_catalog.is_some() {
                for resource in &self.resources {
                    if let Some(feature) = &resource.feature_flag
                        && !feature_enabled(feature)
                    {
                        return Err(ManagedAppBindError::Feature {
                            unit: format!("resource:{}", resource.name),
                            feature: feature.clone(),
                        });
                    }
                }
            }
            let service_resources: BTreeMap<_, _> = self
                .services
                .iter()
                .map(|service| (service.name.clone(), service.resources.clone()))
                .collect();
            if (!grouped && plan.service_groups.len() != 1)
                || !plan.observability_sinks.is_empty()
            {
                return Err(ManagedAppBindError::Unsupported {
                    unit: plan.app_name,
                    reason: if grouped {
                        "explicit observability adapters are not yet supported"
                    } else {
                        "managed binding requires one group and explicit observability adapters are not yet supported"
                    },
                });
            }
            let mut templates = BTreeMap::new();
            let mut group_order = Vec::new();
            for group in &plan.service_groups {
                let config = configs.remove(&group.name).ok_or_else(|| {
                    ManagedAppBindError::MissingGroupConfig(group.name.clone())
                })?;
                let stop_on_child_failure =
                    matches!(&group.restart_policy, super::AppRestartPolicyV1::Stop);
                let restart = if stop_on_child_failure {
                    super::RestartPolicy::OneForOne
                } else {
                    runtime_restart_policy(&group.restart_policy)
                        .map_err(ManagedAppBindError::Compile)?
                };
                let config = if stop_on_child_failure {
                    config.with_restart_policy(restart)
                } else {
                    config
                };
                let is_root = group.name == plan.root_group;
                if !is_root {
                    group_order.push(group.name.clone());
                }
                templates.insert(
                    group.name.clone(),
                    AppGroupTemplate {
                        name: if is_root {
                            plan.app_name.clone()
                        } else {
                            group.name.clone()
                        },
                        restart,
                        stop_on_child_failure,
                        config,
                        children: Vec::new(),
                    },
                );
            }
            if let Some((name, _)) = configs.into_iter().next() {
                return Err(ManagedAppBindError::UnexpectedGroupConfig(name));
            }
            let mut supplied = BTreeMap::new();
            for binding in bindings {
                let name = binding.name.clone();
                if supplied.insert(name.clone(), binding.kind).is_some() {
                    return Err(ManagedAppBindError::Duplicate(name));
                }
            }
            let budgets: BTreeMap<_, _> = plan
                .budgets
                .into_iter()
                .map(|b| (b.name.clone(), b))
                .collect();
            let mut policies = Vec::new();
            // Keyed by route shape (see `route_shape`): one method router per
            // route the web router will match, registered under the first
            // path seen for it.
            let mut methods: BTreeMap<String, (String, MethodRouter)> = BTreeMap::new();
            let mut route_keys = BTreeSet::new();
            let mut routes = Vec::new();
            for child in plan.children {
                let kind = supplied
                    .remove(&child.name)
                    .ok_or_else(|| ManagedAppBindError::Missing(child.name.clone()))?;
                if child.slo_hook.is_some() {
                    return Err(ManagedAppBindError::Unsupported {
                        unit: child.name,
                        reason: "SLO hooks need an explicit runtime adapter",
                    });
                }
                let resource_view = if let Some(catalog) = &resource_catalog {
                    let mut names: BTreeSet<_> =
                        child.required_capabilities.resources.iter().cloned().collect();
                    if let Some(inherited) = service_resources.get(&child.service) {
                        names.extend(inherited.iter().cloned());
                    }
                    catalog
                        .for_work(
                            &child.name,
                            &names,
                            kind.resource_requirements(),
                            &child.required_capabilities.cx_capabilities,
                        )
                        .map_err(ManagedAppBindError::Resource)?
                } else {
                    if !child.required_capabilities.resources.is_empty()
                        || !kind.resource_requirements().is_empty()
                    {
                        return Err(ManagedAppBindError::Unsupported {
                            unit: child.name,
                            reason: "named resources require an explicit typed resource binding",
                        });
                    }
                    ManagedAppResources::default()
                };
                let resource_capabilities = resource_view.capabilities();
                let kind = kind.bind_resources(resource_view);
                for feature in &child.required_capabilities.feature_flags {
                    if !feature_enabled(feature) {
                        return Err(ManagedAppBindError::Feature {
                            unit: child.name.clone(),
                            feature: feature.clone(),
                        });
                    }
                }
                let supplied_signal = match &kind {
                    BindingKind::Worker(_, _, signal) => signal.as_ref(),
                    BindingKind::Route(_) => None,
                    BindingKind::ResourceRoute { .. } | BindingKind::ResourceWorker { .. } => {
                        unreachable!("typed resource adapters have been bound")
                    }
                };
                let interval = match &child.trigger {
                    None | Some(AppJobTriggerV1::Startup) => None,
                    Some(AppJobTriggerV1::Interval { every_ms }) if *every_ms > 0 => {
                        Some(Duration::from_millis(*every_ms))
                    }
                    Some(AppJobTriggerV1::Signal { source }) => {
                        let Some(signal) = supplied_signal else {
                            return Err(ManagedAppBindError::Unsupported {
                                unit: child.name,
                                reason: "signal trigger requires an explicit signal_worker binding",
                            });
                        };
                        if child.kind != AppSpecV1WorkUnitKind::BackgroundJob
                            || source.trim().is_empty()
                            || signal.source != *source
                        {
                            return Err(ManagedAppBindError::KindMismatch(child.name));
                        }
                        None
                    }
                    Some(_) => {
                        return Err(ManagedAppBindError::Unsupported {
                            unit: child.name,
                            reason: "zero intervals are not supported",
                        });
                    }
                };
                if supplied_signal.is_some()
                    && !matches!(&child.trigger, Some(AppJobTriggerV1::Signal { .. }))
                {
                    return Err(ManagedAppBindError::KindMismatch(child.name));
                }
                let signal = supplied_signal.map(|binding| Arc::clone(&binding.receiver));
                let budget = child
                    .budget
                    .as_ref()
                    .and_then(|name| budgets.get(name))
                    .cloned();
                if let Some(budget) = &budget {
                    if budget
                        .poll_quota
                        .is_some_and(|n| n == 0 || n > u64::from(u32::MAX))
                        || budget.deadline_ms == Some(0)
                        || budget.io_bytes == Some(0)
                        || budget.memory_bytes == Some(0)
                    {
                        return Err(ManagedAppBindError::Budget {
                            name: budget.name.clone(),
                            reason: "zero or unrepresentable execution limit",
                        });
                    }
                }
                let policy = Arc::new(WorkPolicy {
                    name: child.name.clone(),
                    required: child.required_capabilities,
                    budget,
                    interval,
                    signal,
                    cleanup: Arc::new(Mutex::new(None)),
                    resource_capabilities,
                });
                let template = templates
                    .get_mut(&child.group)
                    .expect("compiler assigns every child to a declared group");
                match (child.kind, kind) {
                    (AppSpecV1WorkUnitKind::Route, BindingKind::Route(handler)) => {
                        let route = child.route.expect("compiler includes route binding");
                        let method_key = format!("{:?}", route.method);
                        let shape = route_shape(&route.path);
                        if !route_keys.insert((shape.clone(), method_key)) {
                            return Err(ManagedAppBindError::Duplicate(child.name));
                        }
                        let slot = Arc::new(Mutex::new(None));
                        let app_handler = AppRoute {
                            slot: Arc::clone(&slot),
                            policy: Arc::clone(&policy),
                            handler,
                        };
                        let (path, method) = methods
                            .remove(&shape)
                            .unwrap_or_else(|| (route.path.clone(), MethodRouter::default()));
                        let method = match route.method {
                            AppRouteMethodV1::Get => method.get(app_handler),
                            AppRouteMethodV1::Post => method.post(app_handler),
                            AppRouteMethodV1::Put => method.put(app_handler),
                            AppRouteMethodV1::Patch => method.patch(app_handler),
                            AppRouteMethodV1::Delete => method.delete(app_handler),
                            AppRouteMethodV1::Head => method.head(app_handler),
                            AppRouteMethodV1::Options => method.options(app_handler),
                        };
                        methods.insert(shape, (path, method));
                        let publication = Arc::clone(&slot);
                        template.push(
                            child.name,
                            ManagedRestartMode::Permanent,
                            move |cx: Cx, _generation| {
                                let slot = Arc::clone(&publication);
                                async move {
                                    let _publication = RoutePublication(Arc::clone(&slot));
                                    *slot.lock() = Some(cx.clone());
                                    cx.cancelled().await;
                                    let _ = cx.checkpoint();
                                    Outcome::Cancelled(cx.cancel_reason().unwrap_or_else(|| {
                                        CancelReason::user("AppSpec route stopped")
                                    }))
                                }
                            },
                            None,
                        );
                        routes.push(slot);
                    }
                    (
                        AppSpecV1WorkUnitKind::Actor | AppSpecV1WorkUnitKind::BackgroundJob,
                        BindingKind::Worker(mode, factory, _),
                    ) => {
                        let work_policy = Arc::clone(&policy);
                        let cleanup = Arc::clone(&policy.cleanup);
                        template.push(
                            child.name,
                            mode,
                            move |cx, generation| {
                                run_worker(
                                    cx,
                                    generation,
                                    Arc::clone(&work_policy),
                                    Arc::clone(&factory),
                                )
                            },
                            Some(Arc::new(move |generation| {
                                cleanup
                                    .lock()
                                    .as_ref()
                                    .filter(|(observed, _)| *observed == generation)
                                    .map(|(_, outcome)| outcome.clone())
                            })),
                        );
                    }
                    _ => return Err(ManagedAppBindError::KindMismatch(child.name)),
                }
                policies.push(policy);
            }
            if let Some((name, _)) = supplied.into_iter().next() {
                return Err(ManagedAppBindError::Unexpected(name));
            }
            let mut template = templates
                .remove(&plan.root_group)
                .expect("validated root group exists");
            let reports = Arc::new(Mutex::new(BTreeMap::new()));
            for name in &group_order {
                let nested = templates.remove(name).expect("declared group exists");
                nested.bind().map_err(ManagedAppBindError::Supervisor)?;
                let group_name = name.clone();
                let cleanup_reports = Arc::clone(&reports);
                template.push(
                    format!("group:{name}"),
                    ManagedRestartMode::Transient,
                    AppGroupFactory {
                        group: name.clone(),
                        template: nested,
                        reports: Arc::clone(&reports),
                    },
                    Some(Arc::new(move |generation| {
                        let reports = cleanup_reports.lock();
                        let completed = reports.get(&group_name)?;
                        if completed.generation != generation {
                            return None;
                        }
                        completed
                            .report
                            .cleanup_outcome
                            .iter()
                            .chain(
                                completed
                                    .report
                                    .children
                                    .iter()
                                    .filter_map(|child| child.cleanup_outcome.as_ref()),
                            )
                            .filter(|outcome| !outcome.is_ok())
                            .max_by_key(|outcome| outcome.severity())
                            .cloned()
                    })),
                );
            }
            template.bind().map_err(ManagedAppBindError::Supervisor)?;
            let mut router = Router::new().without_default_trace();
            for (path, method) in methods.into_values() {
                router = router.route(&path, method);
            }
            Ok(ManagedAppTree {
                app: ManagedApp {
                    template,
                    router: Arc::new(router),
                    policies,
                    routes,
                },
                reports,
                group_order,
            })
        }
    }
}

/// Schema discriminator for the declarative AppSpec v1 contract.
pub const APPSPEC_V1_SCHEMA_VERSION: &str = "asupersync.appspec.v1";

// ---------------------------------------------------------------------------
// Declarative AppSpec v1
// ---------------------------------------------------------------------------

/// Versioned, serde-friendly application topology contract.
///
/// This is the fail-closed data model used by generated manifests and external
/// tooling. It intentionally sits beside the builder-style [`AppSpec`]; runtime
/// compilation from this declarative shape belongs to the follow-on compiler
/// layer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppSpecV1 {
    /// Schema discriminator. Must equal [`APPSPEC_V1_SCHEMA_VERSION`].
    pub schema_version: String,
    /// Stable application name used in traces and supervision diagnostics.
    pub name: String,
    /// Service topology for routes, actors, and background jobs.
    pub services: Vec<AppServiceSpecV1>,
    /// Named resources that routes, actors, jobs, and sinks may require.
    pub resources: Vec<AppResourceSpecV1>,
    /// Named budget presets referenced by services and work units.
    pub budgets: Vec<AppBudgetSpecV1>,
    /// Named SLO policy hooks referenced by routes and jobs.
    pub slo_hooks: Vec<AppSloHookSpecV1>,
    /// Explicit supervision topology over declared services.
    pub supervision: AppSupervisionSpecV1,
    /// Observability sinks and the capabilities they require.
    pub observability: Vec<AppObservabilitySinkSpecV1>,
    /// Compatibility policy for this v1 manifest.
    pub compatibility: AppCompatibilityPolicyV1,
}

impl AppSpecV1 {
    /// Validate cross-field invariants that serde alone cannot express.
    pub fn validate(&self) -> Result<(), AppSpecV1ValidationError> {
        if self.schema_version != APPSPEC_V1_SCHEMA_VERSION {
            return Err(AppSpecV1ValidationError::UnsupportedSchemaVersion {
                found: self.schema_version.clone(),
            });
        }

        validate_nonempty("app.name", &self.name)?;

        let budget_names = unique_names(
            "budgets",
            self.budgets.iter().map(|budget| budget.name.as_str()),
        )?;
        for budget in &self.budgets {
            budget.validate()?;
        }

        let resource_names = unique_names(
            "resources",
            self.resources.iter().map(|resource| resource.name.as_str()),
        )?;

        let slo_hook_names = unique_names(
            "slo_hooks",
            self.slo_hooks.iter().map(|hook| hook.name.as_str()),
        )?;
        for hook in &self.slo_hooks {
            hook.validate(&budget_names)?;
        }

        let service_names = unique_names(
            "services",
            self.services.iter().map(|service| service.name.as_str()),
        )?;

        let group_names = unique_names(
            "supervision.groups",
            self.supervision
                .groups
                .iter()
                .map(|group| group.name.as_str()),
        )?;
        if !group_names.contains(self.supervision.root_group.as_str()) {
            return Err(AppSpecV1ValidationError::UnknownReference {
                field: "supervision.root_group",
                name: self.supervision.root_group.clone(),
            });
        }

        for service in &self.services {
            service.validate(
                &budget_names,
                &resource_names,
                &slo_hook_names,
                &group_names,
            )?;
        }

        for group in &self.supervision.groups {
            group.validate(&service_names)?;
        }
        validate_supervision_assignments(&self.services, &self.supervision.groups)?;

        unique_names(
            "observability",
            self.observability.iter().map(|sink| sink.name.as_str()),
        )?;
        for sink in &self.observability {
            sink.required_capabilities
                .validate(&format!("observability.{}", sink.name), &resource_names)?;
        }

        if !self.compatibility.fail_closed_unknown_fields {
            return Err(AppSpecV1ValidationError::CompatibilityPolicy {
                reason: "v1 manifests must fail closed on unknown fields",
            });
        }
        if !self.compatibility.fail_closed_unknown_capabilities {
            return Err(AppSpecV1ValidationError::CompatibilityPolicy {
                reason: "v1 manifests must fail closed on unknown capabilities",
            });
        }
        if !self.compatibility.future_schema_requires_new_version {
            return Err(AppSpecV1ValidationError::CompatibilityPolicy {
                reason: "v1 manifests must use a new schema version for future widening",
            });
        }

        Ok(())
    }

    /// Build the deterministic compiler plan for this declarative manifest.
    ///
    /// The plan is pure data. It names every route, actor, background job, and
    /// observability sink the runtime compiler must wire, but it does not try to
    /// resolve handler strings into Rust functions.
    pub fn compiler_plan(&self) -> Result<AppSpecV1CompilerPlan, AppSpecV1CompileError> {
        self.validate().map_err(AppSpecV1CompileError::Validation)?;

        let services = self
            .services
            .iter()
            .map(|service| (service.name.as_str(), service))
            .collect::<BTreeMap<_, _>>();
        let root_group = self
            .supervision
            .groups
            .iter()
            .find(|group| group.name == self.supervision.root_group)
            .expect("validate ensures root group exists");

        let mut service_groups = Vec::with_capacity(self.supervision.groups.len());
        let mut children = Vec::new();
        for group in &self.supervision.groups {
            service_groups.push(AppSpecV1CompiledGroup {
                name: group.name.clone(),
                services: group.services.clone(),
                restart_policy: group.restart_policy.clone(),
            });

            for service_name in &group.services {
                let service = services
                    .get(service_name.as_str())
                    .expect("validate ensures group service exists");
                children.extend(service.routes.iter().map(|route| AppSpecV1CompiledChild {
                    name: format!("{}.route.{}", service.name, route.name),
                    service: service.name.clone(),
                    group: group.name.clone(),
                    kind: AppSpecV1WorkUnitKind::Route,
                    entrypoint: route.handler.clone(),
                    budget: route.budget.clone().or_else(|| service.budget.clone()),
                    slo_hook: route.slo_hook.clone(),
                    route: Some(AppSpecV1RouteBinding {
                        method: route.method.clone(),
                        path: route.path.clone(),
                    }),
                    trigger: None,
                    required_capabilities: route.required_capabilities.clone(),
                }));
                children.extend(service.actors.iter().map(|actor| AppSpecV1CompiledChild {
                    name: format!("{}.actor.{}", service.name, actor.name),
                    service: service.name.clone(),
                    group: group.name.clone(),
                    kind: AppSpecV1WorkUnitKind::Actor,
                    entrypoint: actor.entrypoint.clone(),
                    budget: actor.budget.clone().or_else(|| service.budget.clone()),
                    slo_hook: None,
                    route: None,
                    trigger: None,
                    required_capabilities: actor.required_capabilities.clone(),
                }));
                children.extend(
                    service
                        .background_jobs
                        .iter()
                        .map(|job| AppSpecV1CompiledChild {
                            name: format!("{}.job.{}", service.name, job.name),
                            service: service.name.clone(),
                            group: group.name.clone(),
                            kind: AppSpecV1WorkUnitKind::BackgroundJob,
                            entrypoint: job.entrypoint.clone(),
                            budget: job.budget.clone().or_else(|| service.budget.clone()),
                            slo_hook: job.slo_hook.clone(),
                            route: None,
                            trigger: Some(job.trigger.clone()),
                            required_capabilities: job.required_capabilities.clone(),
                        }),
                );
            }
        }

        Ok(AppSpecV1CompilerPlan {
            app_name: self.name.clone(),
            root_group: root_group.name.clone(),
            root_restart_policy: root_group.restart_policy.clone(),
            service_groups,
            children,
            observability_sinks: self
                .observability
                .iter()
                .map(|sink| AppSpecV1CompiledObservabilitySink {
                    name: sink.name.clone(),
                    kind: sink.kind.clone(),
                    required_capabilities: sink.required_capabilities.clone(),
                })
                .collect(),
            budgets: self.budgets.clone(),
            no_claim_boundaries: vec![
                "Does not resolve handler symbols into Rust functions.".to_string(),
                "Does not start runtime tasks without caller-supplied ChildSpec factories."
                    .to_string(),
                "Does not prove handler cancel-correctness or region quiescence.".to_string(),
            ],
        })
    }

    /// Lower this manifest into the existing builder-style [`AppSpec`].
    ///
    /// Callers must supply one explicit [`ChildSpec`] per compiled work unit.
    /// The compiler checks names and ordering, then leaves task startup logic in
    /// those caller-provided factories instead of inventing hidden global wiring.
    pub fn compile_with_child_specs<I>(self, children: I) -> Result<AppSpec, AppSpecV1CompileError>
    where
        I: IntoIterator<Item = ChildSpec>,
    {
        let plan = self.compiler_plan()?;
        if plan.service_groups.len() != 1 {
            return Err(AppSpecV1CompileError::UnsupportedRuntimeMapping {
                reason: "builder AppSpec v1 lowering supports exactly one supervision group",
            });
        }
        let restart_policy = runtime_restart_policy(&plan.root_restart_policy)?;

        let mut provided = BTreeMap::new();
        for child in children {
            let name = child.name.as_str().to_string();
            if provided.insert(name.clone(), child).is_some() {
                return Err(AppSpecV1CompileError::DuplicateChildSpec { name });
            }
        }

        let expected_names = plan
            .children
            .iter()
            .map(|child| child.name.as_str())
            .collect::<BTreeSet<_>>();
        if let Some(unexpected) = provided
            .keys()
            .find(|name| !expected_names.contains(name.as_str()))
            .cloned()
        {
            return Err(AppSpecV1CompileError::UnexpectedChildSpec { name: unexpected });
        }

        let mut app = AppSpec::new(plan.app_name).with_restart_policy(restart_policy);
        for child in &plan.children {
            let child_spec = provided.remove(&child.name).ok_or_else(|| {
                AppSpecV1CompileError::MissingChildSpec {
                    name: child.name.clone(),
                }
            })?;
            app = app.child(child_spec);
        }

        Ok(app)
    }

    /// Validate this manifest and render its generated supervision topology.
    ///
    /// Convenience wrapper over [`compiler_plan`](Self::compiler_plan) and
    /// [`AppSpecV1CompilerPlan::topology_report`]. Fails closed with the same
    /// validation diagnostics as the compiler.
    pub fn topology_report(&self) -> Result<String, AppSpecV1CompileError> {
        Ok(self.compiler_plan()?.topology_report())
    }
}

/// Deterministic compiler projection for an [`AppSpecV1`] manifest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AppSpecV1CompilerPlan {
    /// Application name copied to the builder-style [`AppSpec`].
    pub app_name: String,
    /// Root supervision group chosen by the manifest.
    pub root_group: String,
    /// Restart policy declared by the root group.
    pub root_restart_policy: AppRestartPolicyV1,
    /// Declared supervision groups in manifest order.
    pub service_groups: Vec<AppSpecV1CompiledGroup>,
    /// Work units requiring caller-supplied child factories.
    pub children: Vec<AppSpecV1CompiledChild>,
    /// Observability sinks that must be wired by the caller/runtime layer.
    pub observability_sinks: Vec<AppSpecV1CompiledObservabilitySink>,
    /// Budget declarations available to the caller-provided child factories.
    pub budgets: Vec<AppBudgetSpecV1>,
    /// Explicit scope limits for this compiler stage.
    pub no_claim_boundaries: Vec<String>,
}

impl AppSpecV1CompilerPlan {
    /// Render the generated supervision topology as a deterministic, human- and
    /// agent-readable report.
    ///
    /// The output is pure data: the same plan always renders byte-identical text,
    /// regardless of build flags or environment. It walks the supervision groups
    /// in declaration order, lists each service's route/actor/job work units with
    /// their effective budget, SLO hook, trigger, and explicit authority
    /// requirements, then the observability sinks and the compiler's no-claim
    /// boundaries. It is suitable for documentation snapshots and as an artifact
    /// row consumed by the lab fixture/proof layer.
    #[must_use]
    pub fn topology_report(&self) -> String {
        let mut out = String::new();
        out.push_str("# AppSpec v1 generated topology\n");
        out.push_str(&format!("app: {}\n", self.app_name));
        out.push_str(&format!(
            "root_group: {} ({})\n",
            self.root_group,
            serde_unit_token(&self.root_restart_policy),
        ));
        if !self.budgets.is_empty() {
            let names = self
                .budgets
                .iter()
                .map(|budget| budget.name.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!("budgets: {names}\n"));
        }

        out.push_str("\nsupervision:\n");
        for group in &self.service_groups {
            out.push_str(&format!(
                "  group {} ({})\n",
                group.name,
                serde_unit_token(&group.restart_policy),
            ));
            for service in &group.services {
                out.push_str(&format!("    service {service}\n"));
                let mut any = false;
                for child in self
                    .children
                    .iter()
                    .filter(|child| child.group == group.name && child.service == *service)
                {
                    any = true;
                    out.push_str(&render_child_line(child));
                }
                if !any {
                    out.push_str("      (no work units)\n");
                }
            }
        }

        out.push_str("\nobservability:\n");
        if self.observability_sinks.is_empty() {
            out.push_str("  (none)\n");
        } else {
            for sink in &self.observability_sinks {
                out.push_str(&format!(
                    "  sink {} ({})  caps={}\n",
                    sink.name,
                    serde_unit_token(&sink.kind),
                    render_required_capabilities(&sink.required_capabilities),
                ));
            }
        }

        out.push_str("\nno-claim boundaries:\n");
        for boundary in &self.no_claim_boundaries {
            out.push_str(&format!("  - {boundary}\n"));
        }
        out
    }
}

/// Render a serde unit-variant enum to its canonical token (e.g. `one_for_one`).
fn serde_unit_token<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| "?".to_string())
}

/// Render explicit authority requirements as `cx:..|feat:..|res:..`.
///
/// Validation guarantees `cx_capabilities` is non-empty, so the `cx:` segment is
/// always present; the `feat:` and `res:` segments are omitted when empty.
fn render_required_capabilities(caps: &AppRequiredCapabilitiesV1) -> String {
    let cx = caps
        .cx_capabilities
        .iter()
        .map(serde_unit_token)
        .collect::<Vec<_>>()
        .join(",");
    let mut parts = vec![format!("cx:{cx}")];
    if !caps.feature_flags.is_empty() {
        let feat = caps
            .feature_flags
            .iter()
            .map(serde_unit_token)
            .collect::<Vec<_>>()
            .join(",");
        parts.push(format!("feat:{feat}"));
    }
    if !caps.resources.is_empty() {
        parts.push(format!("res:{}", caps.resources.join(",")));
    }
    parts.join("|")
}

/// Render a background-job trigger as a compact deterministic token.
fn render_job_trigger(trigger: &AppJobTriggerV1) -> String {
    match trigger {
        AppJobTriggerV1::Startup => "startup".to_string(),
        AppJobTriggerV1::Interval { every_ms } => format!("interval(every_ms={every_ms})"),
        AppJobTriggerV1::Signal { source } => format!("signal(source={source})"),
    }
}

/// Render a single compiled work unit as one topology-report line.
fn render_child_line(child: &AppSpecV1CompiledChild) -> String {
    let caps = render_required_capabilities(&child.required_capabilities);
    let budget = child.budget.as_deref().unwrap_or("-");
    match child.kind {
        AppSpecV1WorkUnitKind::Route => {
            let route = child
                .route
                .as_ref()
                .expect("compiler_plan attaches a route binding to every route work unit");
            let slo = child.slo_hook.as_deref().unwrap_or("-");
            format!(
                "      route  {}  {} {} -> {}  budget={}  slo={}  caps={}\n",
                child.name,
                serde_unit_token(&route.method),
                route.path,
                child.entrypoint,
                budget,
                slo,
                caps,
            )
        }
        AppSpecV1WorkUnitKind::Actor => format!(
            "      actor  {}  -> {}  budget={}  caps={}\n",
            child.name, child.entrypoint, budget, caps,
        ),
        AppSpecV1WorkUnitKind::BackgroundJob => {
            let trigger = child
                .trigger
                .as_ref()
                .expect("compiler_plan attaches a trigger to every background-job work unit");
            let slo = child.slo_hook.as_deref().unwrap_or("-");
            format!(
                "      job    {}  trigger={} -> {}  budget={}  slo={}  caps={}\n",
                child.name,
                render_job_trigger(trigger),
                child.entrypoint,
                budget,
                slo,
                caps,
            )
        }
    }
}

/// Compiled supervision group metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AppSpecV1CompiledGroup {
    /// Group name.
    pub name: String,
    /// Services assigned to the group.
    pub services: Vec<String>,
    /// Group restart policy.
    pub restart_policy: AppRestartPolicyV1,
}

/// Kind of runtime work unit extracted from the manifest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AppSpecV1WorkUnitKind {
    /// Route handler work unit.
    Route,
    /// Long-lived actor work unit.
    Actor,
    /// Background job work unit.
    BackgroundJob,
}

/// Compiled child-factory requirement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AppSpecV1CompiledChild {
    /// Stable child name used by the builder and supplied [`ChildSpec`].
    pub name: String,
    /// Owning service name.
    pub service: String,
    /// Owning supervision group.
    pub group: String,
    /// Work unit kind.
    pub kind: AppSpecV1WorkUnitKind,
    /// Handler, actor, or job symbol from the manifest.
    pub entrypoint: String,
    /// Effective budget name, if any.
    pub budget: Option<String>,
    /// SLO hook name, if any.
    pub slo_hook: Option<String>,
    /// Route binding for route work units.
    pub route: Option<AppSpecV1RouteBinding>,
    /// Trigger binding for background-job work units.
    pub trigger: Option<AppJobTriggerV1>,
    /// Authority requirements for the work unit.
    pub required_capabilities: AppRequiredCapabilitiesV1,
}

/// Route-specific compiler binding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AppSpecV1RouteBinding {
    /// HTTP method.
    pub method: AppRouteMethodV1,
    /// Absolute route path.
    pub path: String,
}

/// Compiled observability sink requirement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AppSpecV1CompiledObservabilitySink {
    /// Sink name.
    pub name: String,
    /// Sink kind.
    pub kind: AppObservabilitySinkKindV1,
    /// Authority requirements for the sink.
    pub required_capabilities: AppRequiredCapabilitiesV1,
}

/// Error lowering declarative AppSpec v1 data into runtime builder inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AppSpecV1CompileError {
    /// Manifest validation failed before compilation.
    Validation(AppSpecV1ValidationError),
    /// The caller supplied two child factories with the same name.
    DuplicateChildSpec {
        /// Duplicate child name.
        name: String,
    },
    /// The manifest requires a child factory the caller did not supply.
    MissingChildSpec {
        /// Missing child name.
        name: String,
    },
    /// The caller supplied a child factory that no manifest work unit needs.
    UnexpectedChildSpec {
        /// Unexpected child name.
        name: String,
    },
    /// The manifest uses a topology not yet representable by builder `AppSpec`.
    UnsupportedRuntimeMapping {
        /// Stable reason string.
        reason: &'static str,
    },
}

impl std::fmt::Display for AppSpecV1CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Validation(error) => write!(f, "AppSpec v1 validation failed: {error}"),
            Self::DuplicateChildSpec { name } => {
                write!(f, "duplicate AppSpec v1 child factory {name:?}")
            }
            Self::MissingChildSpec { name } => {
                write!(f, "missing AppSpec v1 child factory {name:?}")
            }
            Self::UnexpectedChildSpec { name } => {
                write!(f, "unexpected AppSpec v1 child factory {name:?}")
            }
            Self::UnsupportedRuntimeMapping { reason } => write!(f, "{reason}"),
        }
    }
}

impl std::error::Error for AppSpecV1CompileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Validation(error) => Some(error),
            Self::DuplicateChildSpec { .. }
            | Self::MissingChildSpec { .. }
            | Self::UnexpectedChildSpec { .. }
            | Self::UnsupportedRuntimeMapping { .. } => None,
        }
    }
}

fn runtime_restart_policy(
    policy: &AppRestartPolicyV1,
) -> Result<RestartPolicy, AppSpecV1CompileError> {
    match policy {
        AppRestartPolicyV1::OneForOne => Ok(RestartPolicy::OneForOne),
        AppRestartPolicyV1::OneForAll => Ok(RestartPolicy::OneForAll),
        AppRestartPolicyV1::Stop => Err(AppSpecV1CompileError::UnsupportedRuntimeMapping {
            reason: "stop-on-child-failure groups need a dedicated runtime policy before lowering",
        }),
    }
}

/// Declarative service with all entry points and required app resources.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppServiceSpecV1 {
    /// Stable service name.
    pub name: String,
    /// HTTP-style request routes owned by this service.
    pub routes: Vec<AppRouteSpecV1>,
    /// Long-lived actors owned by this service.
    pub actors: Vec<AppActorSpecV1>,
    /// Background jobs owned by this service.
    pub background_jobs: Vec<AppBackgroundJobSpecV1>,
    /// Resource names used by the service as a whole.
    pub resources: Vec<String>,
    /// Optional named budget for the service root.
    pub budget: Option<String>,
    /// Optional supervision group this service expects to belong to.
    pub supervision_group: Option<String>,
}

impl AppServiceSpecV1 {
    fn validate(
        &self,
        budget_names: &BTreeSet<&str>,
        resource_names: &BTreeSet<&str>,
        slo_hook_names: &BTreeSet<&str>,
        group_names: &BTreeSet<&str>,
    ) -> Result<(), AppSpecV1ValidationError> {
        validate_nonempty("service.name", &self.name)?;
        validate_optional_reference("service.budget", self.budget.as_deref(), budget_names)?;
        validate_optional_reference(
            "service.supervision_group",
            self.supervision_group.as_deref(),
            group_names,
        )?;
        for resource in &self.resources {
            validate_reference("service.resources", resource, resource_names)?;
        }

        unique_names(
            "service.routes",
            self.routes.iter().map(|route| route.name.as_str()),
        )?;
        for route in &self.routes {
            route.validate(&self.name, budget_names, resource_names, slo_hook_names)?;
        }

        unique_names(
            "service.actors",
            self.actors.iter().map(|actor| actor.name.as_str()),
        )?;
        for actor in &self.actors {
            actor.validate(&self.name, budget_names, resource_names)?;
        }

        unique_names(
            "service.background_jobs",
            self.background_jobs.iter().map(|job| job.name.as_str()),
        )?;
        for job in &self.background_jobs {
            job.validate(&self.name, budget_names, resource_names, slo_hook_names)?;
        }

        Ok(())
    }
}

/// Request route declaration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppRouteSpecV1 {
    /// Stable route name, unique within the service.
    pub name: String,
    /// HTTP method shape for the route.
    pub method: AppRouteMethodV1,
    /// Absolute route path, for example `/health`.
    pub path: String,
    /// Handler symbol or adapter entry point.
    pub handler: String,
    /// Required `Cx` capabilities, feature flags, and resource names.
    pub required_capabilities: AppRequiredCapabilitiesV1,
    /// Optional named budget for this route.
    pub budget: Option<String>,
    /// Optional named SLO policy hook.
    pub slo_hook: Option<String>,
}

impl AppRouteSpecV1 {
    fn validate(
        &self,
        service: &str,
        budget_names: &BTreeSet<&str>,
        resource_names: &BTreeSet<&str>,
        slo_hook_names: &BTreeSet<&str>,
    ) -> Result<(), AppSpecV1ValidationError> {
        validate_nonempty("route.name", &self.name)?;
        validate_nonempty("route.handler", &self.handler)?;
        if !self.path.starts_with('/') {
            return Err(AppSpecV1ValidationError::InvalidRoutePath {
                service: service.to_string(),
                route: self.name.clone(),
                path: self.path.clone(),
            });
        }
        validate_optional_reference("route.budget", self.budget.as_deref(), budget_names)?;
        validate_optional_reference("route.slo_hook", self.slo_hook.as_deref(), slo_hook_names)?;
        self.required_capabilities.validate(
            &format!("service.{service}.route.{}", self.name),
            resource_names,
        )
    }
}

/// Route method surface recognized by AppSpec v1.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AppRouteMethodV1 {
    /// HTTP GET.
    Get,
    /// HTTP POST.
    Post,
    /// HTTP PUT.
    Put,
    /// HTTP PATCH.
    Patch,
    /// HTTP DELETE.
    Delete,
    /// HTTP HEAD.
    Head,
    /// HTTP OPTIONS.
    Options,
}

/// Long-lived actor declaration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppActorSpecV1 {
    /// Stable actor name, unique within the service.
    pub name: String,
    /// Actor entry point symbol.
    pub entrypoint: String,
    /// Optional bounded mailbox capacity.
    pub mailbox_capacity: Option<u32>,
    /// Required `Cx` capabilities, feature flags, and resource names.
    pub required_capabilities: AppRequiredCapabilitiesV1,
    /// Optional named budget for the actor.
    pub budget: Option<String>,
}

impl AppActorSpecV1 {
    fn validate(
        &self,
        service: &str,
        budget_names: &BTreeSet<&str>,
        resource_names: &BTreeSet<&str>,
    ) -> Result<(), AppSpecV1ValidationError> {
        validate_nonempty("actor.name", &self.name)?;
        validate_nonempty("actor.entrypoint", &self.entrypoint)?;
        validate_optional_reference("actor.budget", self.budget.as_deref(), budget_names)?;
        self.required_capabilities.validate(
            &format!("service.{service}.actor.{}", self.name),
            resource_names,
        )
    }
}

/// Background job declaration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppBackgroundJobSpecV1 {
    /// Stable job name, unique within the service.
    pub name: String,
    /// Job entry point symbol.
    pub entrypoint: String,
    /// Trigger policy.
    pub trigger: AppJobTriggerV1,
    /// Required `Cx` capabilities, feature flags, and resource names.
    pub required_capabilities: AppRequiredCapabilitiesV1,
    /// Optional named budget for the job.
    pub budget: Option<String>,
    /// Optional named SLO policy hook.
    pub slo_hook: Option<String>,
}

impl AppBackgroundJobSpecV1 {
    fn validate(
        &self,
        service: &str,
        budget_names: &BTreeSet<&str>,
        resource_names: &BTreeSet<&str>,
        slo_hook_names: &BTreeSet<&str>,
    ) -> Result<(), AppSpecV1ValidationError> {
        validate_nonempty("background_job.name", &self.name)?;
        validate_nonempty("background_job.entrypoint", &self.entrypoint)?;
        validate_optional_reference(
            "background_job.budget",
            self.budget.as_deref(),
            budget_names,
        )?;
        validate_optional_reference(
            "background_job.slo_hook",
            self.slo_hook.as_deref(),
            slo_hook_names,
        )?;
        self.required_capabilities.validate(
            &format!("service.{service}.background_job.{}", self.name),
            resource_names,
        )
    }
}

/// Supported background-job trigger contracts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AppJobTriggerV1 {
    /// The job is started once during service startup.
    Startup,
    /// The job is driven by an interval in milliseconds.
    Interval {
        /// Interval duration in milliseconds.
        every_ms: u64,
    },
    /// The job is externally signalled by a declared resource or actor.
    Signal {
        /// Signal source name.
        source: String,
    },
}

/// Resource declaration referenced by capability requirements.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppResourceSpecV1 {
    /// Stable resource name.
    pub name: String,
    /// Resource kind.
    pub kind: AppResourceKindV1,
    /// Capability that gates access to the resource.
    pub capability: AppCxCapabilityV1,
    /// Optional feature flag required to enable this resource.
    pub feature_flag: Option<AppFeatureFlagV1>,
}

/// Resource families recognized by AppSpec v1.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AppResourceKindV1 {
    /// CPU-bound work budget.
    Cpu,
    /// Memory budget or pool.
    Memory,
    /// Timer or virtual-clock access.
    Timer,
    /// File-system access.
    FileSystem,
    /// Network socket access.
    Socket,
    /// Database connection or pool.
    Database,
    /// Message bus or broker surface.
    MessageBus,
    /// Remote node or cluster boundary.
    RemoteNode,
    /// Browser host bridge boundary.
    BrowserHost,
}

/// Named budget preset.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppBudgetSpecV1 {
    /// Stable budget name.
    pub name: String,
    /// Optional maximum poll quota.
    pub poll_quota: Option<u64>,
    /// Optional deadline in milliseconds.
    pub deadline_ms: Option<u64>,
    /// Optional I/O byte budget.
    pub io_bytes: Option<u64>,
    /// Optional memory budget.
    pub memory_bytes: Option<u64>,
}

impl AppBudgetSpecV1 {
    fn validate(&self) -> Result<(), AppSpecV1ValidationError> {
        validate_nonempty("budget.name", &self.name)?;
        if self.poll_quota.is_none()
            && self.deadline_ms.is_none()
            && self.io_bytes.is_none()
            && self.memory_bytes.is_none()
        {
            return Err(AppSpecV1ValidationError::EmptyBudget {
                name: self.name.clone(),
            });
        }
        Ok(())
    }
}

/// SLO policy hook declaration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppSloHookSpecV1 {
    /// Stable hook name.
    pub name: String,
    /// Hook kind.
    pub kind: AppSloHookKindV1,
    /// Target selector interpreted by the later compiler layer.
    pub target: String,
    /// Optional named budget associated with this policy hook.
    pub budget: Option<String>,
}

impl AppSloHookSpecV1 {
    fn validate(&self, budget_names: &BTreeSet<&str>) -> Result<(), AppSpecV1ValidationError> {
        validate_nonempty("slo_hook.name", &self.name)?;
        validate_nonempty("slo_hook.target", &self.target)?;
        validate_optional_reference("slo_hook.budget", self.budget.as_deref(), budget_names)
    }
}

/// SLO hook families recognized by AppSpec v1.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AppSloHookKindV1 {
    /// Latency threshold hook.
    Latency,
    /// Error-rate threshold hook.
    ErrorRate,
    /// Throughput threshold hook.
    Throughput,
    /// Saturation threshold hook.
    Saturation,
}

/// Explicit supervision topology over services.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppSupervisionSpecV1 {
    /// Name of the root supervision group.
    pub root_group: String,
    /// Supervision groups in deterministic declaration order.
    pub groups: Vec<AppSupervisionGroupSpecV1>,
}

/// Supervision group declaration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppSupervisionGroupSpecV1 {
    /// Stable group name.
    pub name: String,
    /// Services supervised by this group.
    pub services: Vec<String>,
    /// Restart policy for children in this group.
    pub restart_policy: AppRestartPolicyV1,
}

impl AppSupervisionGroupSpecV1 {
    fn validate(&self, service_names: &BTreeSet<&str>) -> Result<(), AppSpecV1ValidationError> {
        validate_nonempty("supervision.group.name", &self.name)?;
        if self.services.is_empty() {
            return Err(AppSpecV1ValidationError::EmptySupervisionGroup {
                name: self.name.clone(),
            });
        }
        for service in &self.services {
            validate_reference("supervision.group.services", service, service_names)?;
        }
        Ok(())
    }
}

/// Restart policy names available in AppSpec v1.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AppRestartPolicyV1 {
    /// Stop the group after child failure.
    Stop,
    /// Restart one failed child.
    OneForOne,
    /// Restart all children in the group.
    OneForAll,
}

/// Observability sink declaration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppObservabilitySinkSpecV1 {
    /// Stable sink name.
    pub name: String,
    /// Sink kind.
    pub kind: AppObservabilitySinkKindV1,
    /// Required `Cx` capabilities, feature flags, and resources for the sink.
    pub required_capabilities: AppRequiredCapabilitiesV1,
}

/// Observability sink families recognized by AppSpec v1.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AppObservabilitySinkKindV1 {
    /// Structured trace sink.
    Trace,
    /// Metrics sink.
    Metrics,
    /// Evidence ledger sink.
    Evidence,
}

/// Required authority declaration for one route, actor, job, or sink.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppRequiredCapabilitiesV1 {
    /// Explicit `Cx` capability families required by the entry point.
    pub cx_capabilities: Vec<AppCxCapabilityV1>,
    /// Cargo feature flags required by the entry point.
    pub feature_flags: Vec<AppFeatureFlagV1>,
    /// Named resources required by the entry point.
    pub resources: Vec<String>,
}

impl AppRequiredCapabilitiesV1 {
    fn validate(
        &self,
        owner: &str,
        resource_names: &BTreeSet<&str>,
    ) -> Result<(), AppSpecV1ValidationError> {
        if self.cx_capabilities.is_empty() {
            return Err(AppSpecV1ValidationError::AmbientAuthority {
                owner: owner.to_string(),
            });
        }

        let contains_pure = self.cx_capabilities.contains(&AppCxCapabilityV1::Pure);
        if contains_pure
            && (self.cx_capabilities.len() > 1
                || !self.feature_flags.is_empty()
                || !self.resources.is_empty())
        {
            return Err(AppSpecV1ValidationError::PureAuthorityHasEffects {
                owner: owner.to_string(),
            });
        }

        for resource in &self.resources {
            validate_reference("required_capabilities.resources", resource, resource_names)?;
        }

        Ok(())
    }
}

/// Capability families that may be required from `Cx`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AppCxCapabilityV1 {
    /// Explicitly declares a pure entry point with no effects.
    Pure,
    /// Structured task spawning.
    Spawn,
    /// Time or timer driver access.
    Time,
    /// I/O driver access.
    Io,
    /// Network access.
    Net,
    /// Trace emission.
    Trace,
    /// Entropy capability.
    Entropy,
    /// Name registry access.
    Registry,
    /// Remote execution or cluster capability.
    Remote,
    /// Blocking pool access.
    Blocking,
    /// Database client capability.
    Database,
    /// Messaging or FABRIC capability.
    Messaging,
    /// TLS capability.
    Tls,
    /// QUIC/HTTP3 capability.
    Quic,
    /// Browser host bridge capability.
    BrowserHost,
}

/// Cargo feature flags recognized by AppSpec v1.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AppFeatureFlagV1 {
    /// `native-runtime`.
    NativeRuntime,
    /// `wasm-runtime`.
    WasmRuntime,
    /// `browser-io`.
    BrowserIo,
    /// `browser-trace`.
    BrowserTrace,
    /// `deterministic-mode`.
    DeterministicMode,
    /// `messaging-fabric`.
    MessagingFabric,
    /// `metrics`.
    Metrics,
    /// `tracing-integration`.
    TracingIntegration,
    /// `sqlite`.
    Sqlite,
    /// `postgres`.
    Postgres,
    /// `mysql`.
    Mysql,
    /// `tls`.
    Tls,
    /// `tls-native-roots`.
    TlsNativeRoots,
    /// `tls-webpki-roots`.
    TlsWebpkiRoots,
    /// `quic`.
    Quic,
    /// `http3`.
    Http3,
    /// `kafka`.
    Kafka,
    /// `io-uring`.
    IoUring,
    /// `tokio-compat`.
    TokioCompat,
}

/// Compatibility policy embedded in each v1 manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppCompatibilityPolicyV1 {
    /// Unknown top-level or nested fields must be rejected.
    pub fail_closed_unknown_fields: bool,
    /// Unknown capability or feature strings must be rejected by serde.
    pub fail_closed_unknown_capabilities: bool,
    /// Future schema widening must use a new schema discriminator.
    pub future_schema_requires_new_version: bool,
}

/// Validation failure for [`AppSpecV1`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AppSpecV1ValidationError {
    /// The manifest used an unsupported schema discriminator.
    UnsupportedSchemaVersion {
        /// Actual schema string.
        found: String,
    },
    /// A required name-like field was empty.
    EmptyName {
        /// Field path that failed validation.
        field: &'static str,
    },
    /// A collection had a duplicate name.
    DuplicateName {
        /// Collection that must have unique names.
        collection: &'static str,
        /// Duplicate name.
        name: String,
    },
    /// A reference pointed at an undeclared budget, resource, SLO hook, or group.
    UnknownReference {
        /// Field path that contained the reference.
        field: &'static str,
        /// Missing referenced name.
        name: String,
    },
    /// A route path was not absolute.
    InvalidRoutePath {
        /// Owning service name.
        service: String,
        /// Route name.
        route: String,
        /// Invalid path value.
        path: String,
    },
    /// An entry point did not declare any explicit authority.
    AmbientAuthority {
        /// Entry point or sink that hid its authority requirements.
        owner: String,
    },
    /// A `pure` declaration was combined with effectful authority.
    PureAuthorityHasEffects {
        /// Entry point or sink with the invalid declaration.
        owner: String,
    },
    /// A budget declared no limiting dimension.
    EmptyBudget {
        /// Budget name.
        name: String,
    },
    /// A supervision group declared no services.
    EmptySupervisionGroup {
        /// Group name.
        name: String,
    },
    /// A declared service was not assigned to any supervision group.
    MissingSupervisionAssignment {
        /// Service name.
        service: String,
    },
    /// A declared service was assigned to more than one supervision group.
    DuplicateSupervisionAssignment {
        /// Service name.
        service: String,
        /// First group that listed the service.
        first_group: String,
        /// Second group that listed the service.
        second_group: String,
    },
    /// `service.supervision_group` disagreed with group membership.
    SupervisionGroupMismatch {
        /// Service name.
        service: String,
        /// Group declared on the service.
        declared_group: String,
        /// Group that actually lists the service.
        actual_group: String,
    },
    /// The embedded compatibility policy is weaker than v1 allows.
    CompatibilityPolicy {
        /// Human-readable reason.
        reason: &'static str,
    },
}

impl std::fmt::Display for AppSpecV1ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedSchemaVersion { found } => {
                write!(f, "unsupported AppSpec schema version {found:?}")
            }
            Self::EmptyName { field } => write!(f, "{field} must be nonempty"),
            Self::DuplicateName { collection, name } => {
                write!(f, "{collection} contains duplicate name {name:?}")
            }
            Self::UnknownReference { field, name } => {
                write!(f, "{field} references undeclared name {name:?}")
            }
            Self::InvalidRoutePath {
                service,
                route,
                path,
            } => write!(
                f,
                "route {service}.{route} path {path:?} must start with '/'"
            ),
            Self::AmbientAuthority { owner } => {
                write!(f, "{owner} must declare at least one Cx capability")
            }
            Self::PureAuthorityHasEffects { owner } => {
                write!(f, "{owner} declares pure plus effectful authority")
            }
            Self::EmptyBudget { name } => write!(f, "budget {name:?} has no limits"),
            Self::EmptySupervisionGroup { name } => {
                write!(f, "supervision group {name:?} has no services")
            }
            Self::MissingSupervisionAssignment { service } => {
                write!(
                    f,
                    "service {service:?} is not assigned to a supervision group"
                )
            }
            Self::DuplicateSupervisionAssignment {
                service,
                first_group,
                second_group,
            } => write!(
                f,
                "service {service:?} is assigned to both supervision groups {first_group:?} and {second_group:?}"
            ),
            Self::SupervisionGroupMismatch {
                service,
                declared_group,
                actual_group,
            } => write!(
                f,
                "service {service:?} declares supervision group {declared_group:?} but is assigned to {actual_group:?}"
            ),
            Self::CompatibilityPolicy { reason } => write!(f, "{reason}"),
        }
    }
}

impl std::error::Error for AppSpecV1ValidationError {}

fn validate_nonempty(field: &'static str, value: &str) -> Result<(), AppSpecV1ValidationError> {
    if value.trim().is_empty() {
        return Err(AppSpecV1ValidationError::EmptyName { field });
    }
    Ok(())
}

fn unique_names<'a>(
    collection: &'static str,
    names: impl IntoIterator<Item = &'a str>,
) -> Result<BTreeSet<&'a str>, AppSpecV1ValidationError> {
    let mut seen = BTreeSet::new();
    for name in names {
        validate_nonempty(collection, name)?;
        if !seen.insert(name) {
            return Err(AppSpecV1ValidationError::DuplicateName {
                collection,
                name: name.to_string(),
            });
        }
    }
    Ok(seen)
}

fn validate_reference(
    field: &'static str,
    name: &str,
    known_names: &BTreeSet<&str>,
) -> Result<(), AppSpecV1ValidationError> {
    validate_nonempty(field, name)?;
    if !known_names.contains(name) {
        return Err(AppSpecV1ValidationError::UnknownReference {
            field,
            name: name.to_string(),
        });
    }
    Ok(())
}

fn validate_optional_reference(
    field: &'static str,
    name: Option<&str>,
    known_names: &BTreeSet<&str>,
) -> Result<(), AppSpecV1ValidationError> {
    if let Some(name) = name {
        validate_reference(field, name, known_names)?;
    }
    Ok(())
}

fn validate_supervision_assignments(
    services: &[AppServiceSpecV1],
    groups: &[AppSupervisionGroupSpecV1],
) -> Result<(), AppSpecV1ValidationError> {
    let mut assignments = BTreeMap::new();
    for group in groups {
        for service in &group.services {
            if let Some(first_group) = assignments.insert(service.as_str(), group.name.as_str()) {
                return Err(AppSpecV1ValidationError::DuplicateSupervisionAssignment {
                    service: service.clone(),
                    first_group: first_group.to_string(),
                    second_group: group.name.clone(),
                });
            }
        }
    }

    for service in services {
        let Some(actual_group) = assignments.get(service.name.as_str()).copied() else {
            return Err(AppSpecV1ValidationError::MissingSupervisionAssignment {
                service: service.name.clone(),
            });
        };

        if let Some(declared_group) = &service.supervision_group {
            if declared_group != actual_group {
                return Err(AppSpecV1ValidationError::SupervisionGroupMismatch {
                    service: service.name.clone(),
                    declared_group: declared_group.clone(),
                    actual_group: actual_group.to_string(),
                });
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// CompiledApp
// ---------------------------------------------------------------------------

/// A compiled application: topology validated, start order computed, ready to spawn.
///
/// Produced by [`AppSpec::compile`]. The compilation step validates the child DAG
/// (no cycles, no duplicate names) and computes the deterministic start order —
/// all without touching runtime state.
pub struct CompiledApp {
    /// Application name.
    name: String,
    /// Optional budget override.
    budget: Option<Budget>,
    /// Compiled supervisor (validated DAG, computed start order).
    compiled_supervisor: CompiledSupervisor,
    /// Optional registry capability to inject into the app's root `Cx`.
    ///
    /// When present, child contexts inherit the registry via scope propagation,
    /// enabling named service registration (bd-2ukjr).
    registry: Option<RegistryHandle>,
}

impl std::fmt::Debug for CompiledApp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledApp")
            .field("name", &self.name)
            .field("budget", &self.budget)
            .finish_non_exhaustive()
    }
}

impl CompiledApp {
    fn collect_region_tree(state: &RuntimeState, root_region: RegionId) -> Vec<(RegionId, usize)> {
        let mut regions = Vec::new();
        let mut pending = vec![(root_region, 0_usize)];

        while let Some((region_id, depth)) = pending.pop() {
            let Some(record) = state.region(region_id) else {
                continue;
            };
            let children = record.child_ids();
            regions.push((region_id, depth));
            for child in children {
                pending.push((child, depth + 1));
            }
        }

        regions
    }

    fn force_complete_tree_tasks(state: &mut RuntimeState, root_region: RegionId) -> usize {
        // Startup may already have registered tasks into the freshly created
        // region tree even though no scheduler ever got a chance to poll them.
        // Complete those records explicitly so region close can reach quiescence.
        let startup_tasks: Vec<_> = Self::collect_region_tree(state, root_region)
            .into_iter()
            .flat_map(|(region_id, _)| {
                state
                    .region(region_id)
                    .map(crate::record::RegionRecord::task_ids)
                    .unwrap_or_default()
            })
            .collect();
        let mut completed = 0;
        for task_id in startup_tasks {
            let reason = state
                .task(task_id)
                .and_then(|task| task.cancel_reason().cloned())
                .unwrap_or_else(CancelReason::shutdown);
            let _ = state.complete_task(task_id, crate::types::Outcome::Cancelled(reason));
            // This helper receives only `&mut RuntimeState` and cannot know
            // whether its caller owns an outer runtime-state mutex guard.
            // Failed-start cleanup therefore suppresses direct completion
            // observers rather than risking callback re-entry under that
            // caller-owned lock. Waiters are unreachable before workers start.
            let _waiters = state
                .task_completed(task_id)
                .into_waiters_without_observers();
            completed += 1;
        }
        completed
    }

    fn cleanup_failed_start(state: &mut RuntimeState, root_region: RegionId) {
        let cancel_effects = state.cancel_request(root_region, &CancelReason::shutdown(), None);
        Self::force_complete_tree_tasks(state, root_region);

        let mut previous_region_count = usize::MAX;
        while state.region(root_region).is_some() {
            let current_region_count = state.regions_len();
            let mut made_progress = current_region_count != previous_region_count;
            previous_region_count = current_region_count;

            let mut regions = Self::collect_region_tree(state, root_region);
            regions.sort_by_key(|(_, depth)| std::cmp::Reverse(*depth));
            for &(region_id, _) in &regions {
                if let Some(region) = state.region(region_id) {
                    region.begin_close(None);
                }
                state.advance_region_state(region_id);
            }

            for (region_id, _) in regions {
                made_progress |= state.drive_failed_start_async_finalizer_inline(region_id);
            }

            // Failed-start cleanup runs before any scheduler worker can poll
            // the temporary app tree. Any tasks still present here are therefore
            // unreachable and must be force-resolved to avoid leaked regions.
            if Self::force_complete_tree_tasks(state, root_region) > 0 {
                made_progress = true;
            }

            if state.regions_len() != current_region_count {
                made_progress = true;
            }
            if !made_progress {
                break;
            }
        }
        let (_, cancel_wakes) = cancel_effects.into_parts();
        cancel_wakes.suppress();
    }

    fn build_app_root_cx(
        state: &RuntimeState,
        parent_cx: &Cx,
        root_region: RegionId,
        budget: Budget,
        registry_override: Option<RegistryHandle>,
    ) -> Cx {
        // br-asupersync-u3gsst — root-Cx bootstrap path: the root task
        // has no runtime-allocated arena slot yet (it IS the bootstrap),
        // so we mint a synthetic ID via the crate-internal helper. All
        // other production task IDs come from the runtime's task arena.
        let task_id = crate::types::id::next_bootstrap_task_id();
        let timer_driver = parent_cx.timer_driver();
        let logical_clock = state
            .logical_clock_mode()
            .build_handle(timer_driver.clone());
        let mut root_cx = Cx::new_with_drivers(
            root_region,
            task_id,
            budget,
            Some(parent_cx.child_observability(root_region, task_id)),
            parent_cx.io_driver_handle(),
            parent_cx.io_cap_handle(),
            timer_driver,
            Some(parent_cx.child_entropy(task_id)),
        )
        .with_logical_clock(logical_clock)
        .with_registry_handle(registry_override.or_else(|| parent_cx.registry_handle()))
        .with_remote_cap_handle(parent_cx.remote_cap_handle())
        .with_blocking_pool_handle(parent_cx.blocking_pool_handle())
        .with_evidence_sink(parent_cx.evidence_sink_handle())
        .with_macaroon_handle(parent_cx.macaroon_handle());
        if let Some(pressure) = parent_cx.pressure_handle() {
            root_cx = root_cx.with_pressure(pressure);
        }
        root_cx.set_trace_buffer(
            parent_cx
                .trace_buffer()
                .unwrap_or_else(|| state.trace_handle()),
        );
        root_cx
    }

    /// Application name.
    #[must_use]
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The compiled supervisor for the app's root supervisor.
    #[must_use]
    #[inline]
    pub fn compiled_supervisor(&self) -> &CompiledSupervisor {
        &self.compiled_supervisor
    }

    /// Allocate a root region and spawn the compiled application.
    ///
    /// If a registry handle was configured (via [`AppSpec::with_registry`]),
    /// it is injected into the `Cx` passed to the supervisor so all child
    /// contexts inherit the registry capability.
    pub fn start(
        self,
        state: &mut RuntimeState,
        cx: &Cx,
        parent_region: RegionId,
    ) -> Result<AppHandle, AppSpawnError> {
        let parent_budget = self.budget.unwrap_or(Budget::INFINITE);
        let root_region = state
            .create_child_region(parent_region, parent_budget)
            .map_err(AppSpawnError::RegionCreate)?;

        let effective_budget = state
            .region(root_region)
            .map_or(parent_budget, crate::record::RegionRecord::budget);

        let registry_for_handle = self.registry.clone();
        let app_cx = Self::build_app_root_cx(
            state,
            cx,
            root_region,
            effective_budget,
            registry_for_handle.clone(),
        );

        let supervisor =
            match self
                .compiled_supervisor
                .spawn(state, &app_cx, root_region, effective_budget)
            {
                Ok(s) => s,
                Err(e) => {
                    Self::cleanup_failed_start(state, root_region);
                    return Err(AppSpawnError::SpawnFailed(e));
                }
            };

        app_cx.trace("app_started");

        Ok(AppHandle {
            name: self.name,
            root_region,
            runtime_instance_id: state.instance_id(),
            supervisor,
            registry: registry_for_handle,
            resolved: false,
        })
    }
}

// ---------------------------------------------------------------------------
// AppSpec (builder)
// ---------------------------------------------------------------------------

/// Pure-data description of an application topology.
///
/// Constructed via builder methods, then started with [`AppSpec::start`].
/// The spec compiles an inner [`SupervisorBuilder`] and spawns it into a
/// newly-created root region.
pub struct AppSpec {
    /// Application name (traces / diagnostics).
    name: String,
    /// Optional budget override for the app root region.
    budget: Option<Budget>,
    /// Inner supervisor builder accumulating children and policy.
    supervisor: SupervisorBuilder,
    /// Optional registry capability to inject into the app's root `Cx`.
    ///
    /// When set, the registry handle is attached to the `Cx` during
    /// [`start`](Self::start) so child contexts inherit naming capability.
    registry: Option<RegistryHandle>,
}

impl std::fmt::Debug for AppSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppSpec")
            .field("name", &self.name)
            .field("budget", &self.budget)
            .finish_non_exhaustive()
    }
}

impl AppSpec {
    /// Create a new application spec with the given name.
    ///
    /// The name is used for trace events and diagnostic output, and is also
    /// forwarded to the inner supervisor.
    pub fn new(name: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            supervisor: SupervisorBuilder::new(name.clone()),
            name,
            budget: None,
            registry: None,
        }
    }

    /// Override the root region's budget (defaults to parent budget if unset).
    #[must_use]
    pub fn with_budget(mut self, budget: Budget) -> Self {
        self.budget = Some(budget);
        self.supervisor = self.supervisor.with_budget(budget);
        self
    }

    /// Attach a registry capability to this application.
    ///
    /// The registry handle is injected into the root `Cx` at start time so
    /// all child contexts inherit naming capability. Named services can then
    /// register via [`NameRegistry`](crate::cx::NameRegistry) using the
    /// handle propagated through `cx.registry_handle()`.
    #[must_use]
    pub fn with_registry(mut self, registry: RegistryHandle) -> Self {
        self.registry = Some(registry);
        self
    }

    /// Set the restart policy for the root supervisor.
    #[must_use]
    pub fn with_restart_policy(mut self, policy: RestartPolicy) -> Self {
        self.supervisor = self.supervisor.with_restart_policy(policy);
        self
    }

    /// Set the tie-break strategy for deterministic start ordering.
    #[must_use]
    pub fn with_tie_break(mut self, tie_break: StartTieBreak) -> Self {
        self.supervisor = self.supervisor.with_tie_break(tie_break);
        self
    }

    /// Add a child specification to the application's root supervisor.
    #[must_use]
    pub fn child(mut self, child: ChildSpec) -> Self {
        self.supervisor = self.supervisor.child(child);
        self
    }

    /// Compile the application spec into a [`CompiledApp`].
    ///
    /// Validates the child DAG, computes deterministic start order.
    /// No runtime state is touched.
    pub fn compile(self) -> Result<CompiledApp, AppCompileError> {
        let compiled_supervisor = self
            .supervisor
            .compile()
            .map_err(AppCompileError::SupervisorCompile)?;

        Ok(CompiledApp {
            name: self.name,
            budget: self.budget,
            compiled_supervisor,
            registry: self.registry,
        })
    }

    /// Compile, allocate a root region, and spawn the application supervisor.
    ///
    /// Convenience method that chains [`AppSpec::compile`] and [`CompiledApp::start`].
    pub fn start(
        self,
        state: &mut RuntimeState,
        cx: &Cx,
        parent_region: RegionId,
    ) -> Result<AppHandle, AppStartError> {
        let compiled = self.compile().map_err(AppStartError::CompileFailed)?;
        compiled
            .start(state, cx, parent_region)
            .map_err(AppStartError::SpawnFailed)
    }
}

// ---------------------------------------------------------------------------
// AppHandle
// ---------------------------------------------------------------------------

/// Handle to a running application.
///
/// Owns the root region and provides `stop` / `join` lifecycle operations.
///
/// # Drop semantics
///
/// Reports a leak on drop if neither `stop` nor `join` has been called. Call
/// [`AppHandle::into_raw`] to opt out of this guarantee when you know what you're
/// doing.
pub struct AppHandle {
    /// Application name.
    name: String,
    /// Root region allocated by `AppSpec::start`.
    root_region: RegionId,
    /// Runtime state instance that owns the root region.
    runtime_instance_id: u64,
    /// Supervisor state from spawn.
    supervisor: SupervisorHandle,
    /// Registry capability handle, if the app was started with one.
    registry: Option<RegistryHandle>,
    /// Whether the handle has been resolved (stop/join/into_raw called).
    resolved: bool,
}

impl std::fmt::Debug for AppHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppHandle")
            .field("name", &self.name)
            .field("root_region", &self.root_region)
            .field("runtime_instance_id", &self.runtime_instance_id)
            .field("resolved", &self.resolved)
            .finish_non_exhaustive()
    }
}

impl Drop for AppHandle {
    fn drop(&mut self) {
        if !self.resolved {
            // br-supervision-fix.2 — Log resource leak instead of panicking
            // to preserve supervision tree stability. Panicking in Drop
            // during normal operation violates process isolation invariants.
            #[cfg(feature = "tracing-integration")]
            tracing::error!(
                app_name = %self.name,
                region_id = ?self.root_region,
                "APP HANDLE LEAKED: app was dropped without stop() or join(). \
                 Call stop(), join(), or into_raw() to resolve."
            );
        }
    }
}

impl AppHandle {
    fn runtime_matches(&self, state: &RuntimeState) -> bool {
        state.instance_id() == self.runtime_instance_id
    }

    /// Application name.
    #[must_use]
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The root region owned by this application.
    #[must_use]
    #[inline]
    pub fn root_region(&self) -> RegionId {
        self.root_region
    }

    /// The supervisor handle for the app's root supervisor.
    #[must_use]
    #[inline]
    pub fn supervisor(&self) -> &SupervisorHandle {
        &self.supervisor
    }

    /// The registry capability handle, if the app was started with one.
    #[must_use]
    pub fn registry(&self) -> Option<&RegistryHandle> {
        self.registry.as_ref()
    }

    /// Request cancellation of the application root region.
    ///
    /// This initiates the cancel-correct shutdown sequence:
    /// close → drain → finalize → quiescence.
    ///
    /// After calling `stop`, the region will transition through its lifecycle
    /// states. Use [`AppHandle::is_stopped`] or poll the region state to
    /// determine when quiescence is reached.
    pub fn stop(&mut self, state: &mut RuntimeState) -> Result<StoppedApp, AppStopError> {
        let reason = CancelReason::new(CancelKind::Shutdown);

        if !self.runtime_matches(state) {
            return Err(AppStopError::WrongRuntime {
                region: self.root_region,
            });
        }

        let Some(region_record) = state.region(self.root_region) else {
            if state.region_was_closed(self.root_region) {
                self.resolved = true;
                return Ok(StoppedApp {
                    name: self.name.clone(),
                    root_region: self.root_region,
                });
            }
            // Defuse drop bomb — caller has no recourse if the region is gone.
            self.resolved = true;
            return Err(AppStopError::RegionNotFound(self.root_region));
        };

        let current_state = region_record.state();
        if current_state == RegionState::Closed {
            // Already stopped.
            self.resolved = true;
            return Ok(StoppedApp {
                name: self.name.clone(),
                root_region: self.root_region,
            });
        }

        // Properly propagate cancel through the runtime state.
        let effects = state.cancel_request(self.root_region, &reason, None);
        state.defer_cancel_dispatch(effects);

        self.resolved = true;
        Ok(StoppedApp {
            name: self.name.clone(),
            root_region: self.root_region,
        })
    }

    /// Check whether the app's root region has reached terminal (Closed) state.
    #[must_use]
    pub fn is_stopped(&self, state: &RuntimeState) -> bool {
        if !self.runtime_matches(state) {
            return false;
        }

        state.region(self.root_region).map_or_else(
            || state.region_was_closed(self.root_region),
            |r| r.state() == RegionState::Closed,
        )
    }

    /// Check whether the app's root region is quiescent (no live tasks,
    /// no pending obligations, no finalizers).
    pub fn is_quiescent(&self, state: &RuntimeState) -> bool {
        if !self.runtime_matches(state) {
            return false;
        }

        state.region(self.root_region).map_or_else(
            || state.region_was_closed(self.root_region),
            crate::record::RegionRecord::is_quiescent,
        )
    }

    /// Wait for the application's root region to reach a terminal state.
    ///
    /// Returns the terminal region state once the app has fully stopped.
    ///
    /// In the current synchronous Phase 0 implementation, this does not drive
    /// the runtime forward on its own. Callers must first drive shutdown to
    /// completion; otherwise this returns [`AppStopError::RegionNotStopped`]
    /// instead of falsely reporting success. In that case, the handle remains
    /// usable so the caller can keep polling or call [`AppHandle::stop`].
    pub fn join(&mut self, state: &RuntimeState) -> Result<StoppedApp, AppStopError> {
        if !self.runtime_matches(state) {
            return Err(AppStopError::WrongRuntime {
                region: self.root_region,
            });
        }

        let Some(region_record) = state.region(self.root_region) else {
            if state.region_was_closed(self.root_region) {
                self.resolved = true;
                return Ok(StoppedApp {
                    name: self.name.clone(),
                    root_region: self.root_region,
                });
            }
            // Defuse drop bomb — caller has no recourse if the region is gone.
            self.resolved = true;
            return Err(AppStopError::RegionNotFound(self.root_region));
        };

        // Phase 0: synchronous check. Region must already be in terminal state
        // or the caller must have driven the runtime to completion.
        let region_state = region_record.state();
        if region_state == RegionState::Closed {
            self.resolved = true;
            return Ok(StoppedApp {
                name: self.name.clone(),
                root_region: self.root_region,
            });
        }

        Err(AppStopError::RegionNotStopped {
            region: self.root_region,
            state: region_state,
        })
    }

    /// Escape hatch: consume the handle without requiring stop/join.
    ///
    /// Returns the raw region ID. The caller assumes responsibility for
    /// lifecycle management of the root region.
    #[must_use]
    pub fn into_raw(mut self) -> RawAppHandle {
        self.resolved = true;
        RawAppHandle {
            name: std::mem::take(&mut self.name),
            root_region: self.root_region,
        }
    }
}

// ---------------------------------------------------------------------------
// StoppedApp / RawAppHandle
// ---------------------------------------------------------------------------

/// Result of stopping or joining an application.
#[derive(Debug)]
pub struct StoppedApp {
    /// Application name.
    pub name: String,
    /// Root region (may still be draining/finalizing).
    pub root_region: RegionId,
}

/// Raw handle obtained via [`AppHandle::into_raw`].
///
/// No drop bomb — the caller assumes responsibility for the root region.
#[derive(Debug)]
pub struct RawAppHandle {
    /// Application name.
    pub name: String,
    /// Root region ID.
    pub root_region: RegionId,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Error compiling an application spec.
#[derive(Debug)]
pub enum AppCompileError {
    /// Supervisor topology validation failed (duplicate names, cycles, etc.).
    SupervisorCompile(SupervisorCompileError),
}

impl std::fmt::Display for AppCompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SupervisorCompile(e) => write!(f, "app compile failed: {e}"),
        }
    }
}

impl std::error::Error for AppCompileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SupervisorCompile(e) => Some(e),
        }
    }
}

/// Error spawning a compiled application into the runtime.
#[derive(Debug)]
pub enum AppSpawnError {
    /// Root region creation failed.
    RegionCreate(RegionCreateError),
    /// Supervisor spawn failed (child start error, etc.).
    SpawnFailed(SupervisorSpawnError),
}

impl std::fmt::Display for AppSpawnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RegionCreate(e) => write!(f, "app root region create failed: {e}"),
            Self::SpawnFailed(e) => write!(f, "app spawn failed: {e}"),
        }
    }
}

impl std::error::Error for AppSpawnError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::RegionCreate(e) => Some(e),
            Self::SpawnFailed(e) => Some(e),
        }
    }
}

/// Error starting an application (convenience wrapper for compile + spawn).
#[derive(Debug)]
pub enum AppStartError {
    /// Compilation phase failed.
    CompileFailed(AppCompileError),
    /// Spawn phase failed.
    SpawnFailed(AppSpawnError),
}

impl std::fmt::Display for AppStartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CompileFailed(e) => write!(f, "{e}"),
            Self::SpawnFailed(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for AppStartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CompileFailed(e) => Some(e),
            Self::SpawnFailed(e) => Some(e),
        }
    }
}

/// Error stopping an application.
#[derive(Debug)]
pub enum AppStopError {
    /// The handle was used with a different runtime state than the one that
    /// created the app root region.
    WrongRuntime {
        /// The app root region stored on the handle.
        region: RegionId,
    },
    /// The root region no longer exists in the runtime state.
    RegionNotFound(RegionId),
    /// The root region exists, but has not yet reached `Closed`.
    RegionNotStopped {
        /// The app root region that was queried.
        region: RegionId,
        /// The current lifecycle state observed for that region.
        state: RegionState,
    },
}

impl std::fmt::Display for AppStopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongRuntime { region } => {
                write!(
                    f,
                    "app root region {region:?} belongs to a different runtime state"
                )
            }
            Self::RegionNotFound(id) => write!(f, "app root region {id:?} not found"),
            Self::RegionNotStopped { region, state } => {
                write!(
                    f,
                    "app root region {region:?} is not stopped yet (state: {state:?})"
                )
            }
        }
    }
}

impl std::error::Error for AppStopError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "app_inline_tests.rs"]
mod tests;
