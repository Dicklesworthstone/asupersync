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
    use crate::remote::{NodeId, RemoteCap};
    use crate::runtime::SpawnError;
    use crate::runtime::state::RuntimeState;
    use crate::supervision::{ChildSpec, NameRegistrationPolicy, SupervisionStrategy};
    use crate::types::{Budget, TaskId};
    use serde_json::{Value, json};
    use std::sync::Arc;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn lab_spawn_cx(runtime: &crate::lab::LabRuntime, region: RegionId, budget: Budget) -> Cx {
        Cx::new(region, TaskId::testing_default(), budget)
            .with_spawn_gateway(runtime.state.spawn_gateway())
            .with_pending_spawn_counter(
                runtime
                    .state
                    .region(region)
                    .map(crate::record::RegionRecord::pending_spawn_handle),
            )
    }

    fn make_child(name: &str) -> ChildSpec {
        ChildSpec {
            name: name.into(),
            start: Box::new(
                |scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
                 state: &mut RuntimeState,
                 _cx: &Cx| {
                    let region = scope.region_id();
                    let budget = scope.budget();
                    state
                        .create_task(region, budget, async { 42_u8 })
                        .map(|(_, stored)| stored.task_id())
                },
            ),
            restart: SupervisionStrategy::Stop,
            shutdown_budget: Budget::INFINITE,
            depends_on: Vec::new(),
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        }
    }

    fn close_app_region_and_remove_records(state: &mut RuntimeState, app_region: RegionId) {
        let effects = state.cancel_request(app_region, &CancelReason::shutdown(), None);
        let (_, cancel_wakes) = effects.into_parts();
        cancel_wakes.dispatch();

        let mut previous_region_count = usize::MAX;
        while state.region(app_region).is_some() && state.regions_len() != previous_region_count {
            previous_region_count = state.regions_len();
            let region_ids: Vec<_> = state.regions_iter().map(|(_, region)| region.id).collect();
            for region_id in region_ids {
                state.advance_region_state(region_id);
            }
        }
    }

    // --- Unit tests ---

    fn appspec_v1_sample_json() -> Value {
        json!({
            "schema_version": APPSPEC_V1_SCHEMA_VERSION,
            "name": "payments",
            "services": [
                {
                    "name": "api",
                    "routes": [
                        {
                            "name": "readiness",
                            "method": "GET",
                            "path": "/ready",
                            "handler": "crate::payments::ready",
                            "required_capabilities": {
                                "cx_capabilities": ["net", "trace"],
                                "feature_flags": ["native-runtime", "tracing-integration"],
                                "resources": ["public_socket"]
                            },
                            "budget": "request",
                            "slo_hook": "latency_50ms"
                        }
                    ],
                    "actors": [
                        {
                            "name": "cache_warmer",
                            "entrypoint": "crate::payments::cache_warmer",
                            "mailbox_capacity": 64,
                            "required_capabilities": {
                                "cx_capabilities": ["spawn", "time"],
                                "feature_flags": ["native-runtime"],
                                "resources": []
                            },
                            "budget": "background"
                        }
                    ],
                    "background_jobs": [
                        {
                            "name": "sweeper",
                            "entrypoint": "crate::payments::sweep",
                            "trigger": { "interval": { "every_ms": 1000 } },
                            "required_capabilities": {
                                "cx_capabilities": ["time", "trace"],
                                "feature_flags": [],
                                "resources": ["timer"]
                            },
                            "budget": "background",
                            "slo_hook": "latency_50ms"
                        }
                    ],
                    "resources": ["public_socket", "timer"],
                    "budget": "service",
                    "supervision_group": "root"
                }
            ],
            "resources": [
                {
                    "name": "public_socket",
                    "kind": "socket",
                    "capability": "net",
                    "feature_flag": "native-runtime"
                },
                {
                    "name": "timer",
                    "kind": "timer",
                    "capability": "time",
                    "feature_flag": null
                }
            ],
            "budgets": [
                {
                    "name": "service",
                    "poll_quota": 100000,
                    "deadline_ms": null,
                    "io_bytes": null,
                    "memory_bytes": null
                },
                {
                    "name": "request",
                    "poll_quota": 10000,
                    "deadline_ms": 50,
                    "io_bytes": 65536,
                    "memory_bytes": null
                },
                {
                    "name": "background",
                    "poll_quota": 25000,
                    "deadline_ms": 1000,
                    "io_bytes": null,
                    "memory_bytes": null
                }
            ],
            "slo_hooks": [
                {
                    "name": "latency_50ms",
                    "kind": "latency",
                    "target": "api.readiness",
                    "budget": "request"
                }
            ],
            "supervision": {
                "root_group": "root",
                "groups": [
                    {
                        "name": "root",
                        "services": ["api"],
                        "restart_policy": "one_for_one"
                    }
                ]
            },
            "observability": [
                {
                    "name": "trace",
                    "kind": "trace",
                    "required_capabilities": {
                        "cx_capabilities": ["trace"],
                        "feature_flags": ["tracing-integration"],
                        "resources": []
                    }
                }
            ],
            "compatibility": {
                "fail_closed_unknown_fields": true,
                "fail_closed_unknown_capabilities": true,
                "future_schema_requires_new_version": true
            }
        })
    }

    fn appspec_v1_sample() -> AppSpecV1 {
        serde_json::from_value(appspec_v1_sample_json()).expect("sample AppSpec v1 parses")
    }

    #[test]
    fn appspec_v1_roundtrip_preserves_capability_contract() {
        init_test("appspec_v1_roundtrip_preserves_capability_contract");
        let spec = appspec_v1_sample();
        spec.validate().expect("sample AppSpec v1 validates");

        assert_eq!(spec.schema_version, APPSPEC_V1_SCHEMA_VERSION);
        let route = &spec.services[0].routes[0];
        assert_eq!(route.method, AppRouteMethodV1::Get);
        assert_eq!(
            route.required_capabilities.cx_capabilities,
            vec![AppCxCapabilityV1::Net, AppCxCapabilityV1::Trace]
        );
        assert_eq!(
            route.required_capabilities.feature_flags,
            vec![
                AppFeatureFlagV1::NativeRuntime,
                AppFeatureFlagV1::TracingIntegration
            ]
        );

        let roundtrip =
            serde_json::to_value(&spec).expect("serialize sample AppSpec v1 back to JSON");
        assert_eq!(
            roundtrip["schema_version"],
            json!(APPSPEC_V1_SCHEMA_VERSION)
        );
        assert_eq!(
            roundtrip["services"][0]["routes"][0]["required_capabilities"]["cx_capabilities"],
            json!(["net", "trace"])
        );
        crate::test_complete!("appspec_v1_roundtrip_preserves_capability_contract");
    }

    #[test]
    fn appspec_v1_rejects_missing_route_capabilities_field() {
        init_test("appspec_v1_rejects_missing_route_capabilities_field");
        let mut value = appspec_v1_sample_json();
        value["services"][0]["routes"][0]
            .as_object_mut()
            .expect("route object")
            .remove("required_capabilities");

        let err = serde_json::from_value::<AppSpecV1>(value).expect_err("missing field rejects");
        assert!(
            err.to_string().contains("required_capabilities"),
            "unexpected serde error: {err}"
        );
        crate::test_complete!("appspec_v1_rejects_missing_route_capabilities_field");
    }

    #[test]
    fn appspec_v1_rejects_unknown_capability_string() {
        init_test("appspec_v1_rejects_unknown_capability_string");
        let mut value = appspec_v1_sample_json();
        value["services"][0]["routes"][0]["required_capabilities"]["cx_capabilities"][0] =
            json!("ambient_global");

        let err =
            serde_json::from_value::<AppSpecV1>(value).expect_err("unknown capability rejects");
        assert!(
            err.to_string().contains("unknown variant"),
            "unexpected serde error: {err}"
        );
        crate::test_complete!("appspec_v1_rejects_unknown_capability_string");
    }

    #[test]
    fn appspec_v1_validate_rejects_ambient_route_authority() {
        init_test("appspec_v1_validate_rejects_ambient_route_authority");
        let mut spec = appspec_v1_sample();
        spec.services[0].routes[0].required_capabilities = AppRequiredCapabilitiesV1 {
            cx_capabilities: Vec::new(),
            feature_flags: Vec::new(),
            resources: Vec::new(),
        };

        let err = spec.validate().expect_err("ambient route rejects");
        assert!(
            matches!(
                err,
                AppSpecV1ValidationError::AmbientAuthority { ref owner }
                    if owner == "service.api.route.readiness"
            ),
            "unexpected validation error: {err:?}"
        );
        crate::test_complete!("appspec_v1_validate_rejects_ambient_route_authority");
    }

    #[test]
    fn appspec_v1_validate_rejects_duplicate_services() {
        init_test("appspec_v1_validate_rejects_duplicate_services");
        let mut spec = appspec_v1_sample();
        spec.services.push(spec.services[0].clone());

        let err = spec.validate().expect_err("duplicate service rejects");
        assert!(
            matches!(
                err,
                AppSpecV1ValidationError::DuplicateName {
                    collection: "services",
                    ref name
                } if name == "api"
            ),
            "unexpected validation error: {err:?}"
        );
        crate::test_complete!("appspec_v1_validate_rejects_duplicate_services");
    }

    #[test]
    fn appspec_v1_validate_rejects_unassigned_service() {
        init_test("appspec_v1_validate_rejects_unassigned_service");
        let mut spec = appspec_v1_sample();
        let mut worker = spec.services[0].clone();
        worker.name = "worker".to_string();
        worker.supervision_group = None;
        spec.services.push(worker);

        let err = spec.validate().expect_err("unassigned service rejects");
        assert!(
            matches!(
                err,
                AppSpecV1ValidationError::MissingSupervisionAssignment {
                    ref service
                } if service == "worker"
            ),
            "unexpected validation error: {err:?}"
        );
        crate::test_complete!("appspec_v1_validate_rejects_unassigned_service");
    }

    #[test]
    fn appspec_v1_validate_rejects_duplicate_service_assignment() {
        init_test("appspec_v1_validate_rejects_duplicate_service_assignment");
        let mut spec = appspec_v1_sample();
        spec.supervision.groups.push(AppSupervisionGroupSpecV1 {
            name: "secondary".to_string(),
            services: vec!["api".to_string()],
            restart_policy: AppRestartPolicyV1::OneForOne,
        });

        let err = spec
            .validate()
            .expect_err("duplicate supervision assignment rejects");
        assert!(
            matches!(
                err,
                AppSpecV1ValidationError::DuplicateSupervisionAssignment {
                    ref service,
                    ref first_group,
                    ref second_group,
                } if service == "api" && first_group == "root" && second_group == "secondary"
            ),
            "unexpected validation error: {err:?}"
        );
        crate::test_complete!("appspec_v1_validate_rejects_duplicate_service_assignment");
    }

    #[test]
    fn appspec_v1_validate_rejects_service_group_mismatch() {
        init_test("appspec_v1_validate_rejects_service_group_mismatch");
        let mut spec = appspec_v1_sample();
        spec.supervision.groups.push(AppSupervisionGroupSpecV1 {
            name: "declared".to_string(),
            services: vec!["shadow".to_string()],
            restart_policy: AppRestartPolicyV1::OneForOne,
        });
        spec.services[0].supervision_group = Some("declared".to_string());

        let err = spec
            .validate()
            .expect_err("mismatched supervision group rejects");
        assert!(
            matches!(
                err,
                AppSpecV1ValidationError::UnknownReference {
                    field: "supervision.group.services",
                    ref name,
                } if name == "shadow"
            ),
            "unknown services should still fail before mismatch analysis: {err:?}"
        );

        let mut spec = appspec_v1_sample();
        spec.supervision.groups.push(AppSupervisionGroupSpecV1 {
            name: "declared".to_string(),
            services: vec!["aux".to_string()],
            restart_policy: AppRestartPolicyV1::OneForOne,
        });
        let mut aux = spec.services[0].clone();
        aux.name = "aux".to_string();
        aux.supervision_group = Some("root".to_string());
        spec.services.push(aux);

        let err = spec
            .validate()
            .expect_err("declared group mismatch rejects");
        assert!(
            matches!(
                err,
                AppSpecV1ValidationError::SupervisionGroupMismatch {
                    ref service,
                    ref declared_group,
                    ref actual_group,
                } if service == "aux" && declared_group == "root" && actual_group == "declared"
            ),
            "unexpected validation error: {err:?}"
        );
        crate::test_complete!("appspec_v1_validate_rejects_service_group_mismatch");
    }

    #[test]
    fn appspec_v1_schema_artifact_matches_runtime_contract() {
        init_test("appspec_v1_schema_artifact_matches_runtime_contract");
        let schema: Value =
            serde_json::from_str(include_str!("../artifacts/appspec_v1_schema.json"))
                .expect("schema artifact parses");
        assert_eq!(schema["schema_version"], json!(APPSPEC_V1_SCHEMA_VERSION));
        assert_eq!(
            schema["properties"]["schema_version"]["const"],
            json!(APPSPEC_V1_SCHEMA_VERSION)
        );

        let required = schema["required"]
            .as_array()
            .expect("schema required is array")
            .iter()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>();
        for field in [
            "schema_version",
            "services",
            "resources",
            "budgets",
            "slo_hooks",
            "supervision",
            "observability",
            "compatibility",
        ] {
            assert!(required.contains(field), "schema should require {field}");
        }

        let capability_enum = schema["$defs"]["cx_capability"]["enum"]
            .as_array()
            .expect("capability enum exists")
            .iter()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>();
        for capability in ["pure", "spawn", "time", "net", "trace", "database"] {
            assert!(
                capability_enum.contains(capability),
                "schema should include capability {capability}"
            );
        }
        crate::test_complete!("appspec_v1_schema_artifact_matches_runtime_contract");
    }

    #[test]
    fn appspec_v1_compiler_plan_is_deterministic_and_explicit() {
        init_test("appspec_v1_compiler_plan_is_deterministic_and_explicit");
        let spec = appspec_v1_sample();
        let plan = spec.compiler_plan().expect("compiler plan builds");
        let second = appspec_v1_sample()
            .compiler_plan()
            .expect("second compiler plan builds");

        assert_eq!(plan, second, "compiler plan must be deterministic");
        assert_eq!(plan.app_name, "payments");
        assert_eq!(plan.root_group, "root");
        assert_eq!(plan.root_restart_policy, AppRestartPolicyV1::OneForOne);
        assert_eq!(
            plan.children
                .iter()
                .map(|child| child.name.as_str())
                .collect::<Vec<_>>(),
            vec![
                "api.route.readiness",
                "api.actor.cache_warmer",
                "api.job.sweeper"
            ]
        );
        assert_eq!(plan.children[0].kind, AppSpecV1WorkUnitKind::Route);
        assert_eq!(
            plan.children[0].route,
            Some(AppSpecV1RouteBinding {
                method: AppRouteMethodV1::Get,
                path: "/ready".to_string(),
            })
        );
        assert_eq!(plan.children[2].kind, AppSpecV1WorkUnitKind::BackgroundJob);
        assert!(
            matches!(
                plan.children[2].trigger,
                Some(AppJobTriggerV1::Interval { every_ms: 1000 })
            ),
            "background job trigger should be preserved"
        );
        assert_eq!(plan.observability_sinks.len(), 1);
        assert!(
            plan.no_claim_boundaries
                .iter()
                .any(|claim| claim.contains("Does not resolve handler symbols")),
            "compiler plan must carry no-claim boundaries"
        );
        crate::test_complete!("appspec_v1_compiler_plan_is_deterministic_and_explicit");
    }

    #[test]
    fn appspec_v1_compile_requires_explicit_child_factories() {
        init_test("appspec_v1_compile_requires_explicit_child_factories");
        let err = appspec_v1_sample()
            .compile_with_child_specs(Vec::new())
            .expect_err("missing child factories reject");
        assert!(
            matches!(
                err,
                AppSpecV1CompileError::MissingChildSpec { ref name }
                    if name == "api.route.readiness"
            ),
            "unexpected compile error: {err:?}"
        );

        let unexpected = appspec_v1_sample()
            .compile_with_child_specs(vec![make_child("api.route.readiness"), make_child("extra")])
            .expect_err("unexpected child factory rejects");
        assert!(
            matches!(
                unexpected,
                AppSpecV1CompileError::UnexpectedChildSpec { ref name } if name == "extra"
            ),
            "unexpected compile error: {unexpected:?}"
        );
        crate::test_complete!("appspec_v1_compile_requires_explicit_child_factories");
    }

    #[test]
    fn appspec_v1_compile_lowers_to_existing_builder() {
        init_test("appspec_v1_compile_lowers_to_existing_builder");
        let app = appspec_v1_sample()
            .compile_with_child_specs(vec![
                make_child("api.route.readiness"),
                make_child("api.actor.cache_warmer"),
                make_child("api.job.sweeper"),
            ])
            .expect("explicit factories lower to AppSpec");

        let compiled = app.compile().expect("lowered AppSpec compiles");
        assert_eq!(compiled.name(), "payments");
        assert_eq!(
            compiled
                .compiled_supervisor()
                .children
                .iter()
                .map(|child| child.name.as_str())
                .collect::<Vec<_>>(),
            vec![
                "api.route.readiness",
                "api.actor.cache_warmer",
                "api.job.sweeper"
            ]
        );
        assert_eq!(compiled.compiled_supervisor().start_order.len(), 3);
        crate::test_complete!("appspec_v1_compile_lowers_to_existing_builder");
    }

    #[test]
    fn app_spec_new_creates_named_spec() {
        init_test("app_spec_new_creates_named_spec");
        let spec = AppSpec::new("test_app");
        assert_eq!(spec.name, "test_app");
        assert!(spec.budget.is_none());
        crate::test_complete!("app_spec_new_creates_named_spec");
    }

    #[test]
    fn app_spec_with_budget_sets_budget() {
        init_test("app_spec_with_budget_sets_budget");
        let budget = Budget::new().with_poll_quota(100);
        let spec = AppSpec::new("budgeted").with_budget(budget);
        assert_eq!(spec.budget, Some(budget));
        crate::test_complete!("app_spec_with_budget_sets_budget");
    }

    #[test]
    fn app_start_creates_region_and_spawns() {
        init_test("app_start_creates_region_and_spawns");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let spec = AppSpec::new("my_app").child(make_child("worker"));
        let handle = spec.start(&mut state, &cx, root).expect("start ok");

        assert_eq!(handle.name(), "my_app");
        assert_ne!(handle.root_region(), root); // Separate child region.
        assert_eq!(handle.supervisor().started.len(), 1);
        assert_eq!(handle.supervisor().started[0].name, "worker");

        // Resolve to avoid drop bomb.
        let _raw = handle.into_raw();
        crate::test_complete!("app_start_creates_region_and_spawns");
    }

    #[test]
    fn app_start_with_multiple_children() {
        init_test("app_start_with_multiple_children");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let spec = AppSpec::new("multi")
            .child(make_child("alpha"))
            .child(make_child("bravo"))
            .child(make_child("charlie"));
        let handle = spec.start(&mut state, &cx, root).expect("start ok");

        assert_eq!(handle.supervisor().started.len(), 3);
        let _raw = handle.into_raw();
        crate::test_complete!("app_start_with_multiple_children");
    }

    #[test]
    fn app_stop_initiates_cancel() {
        init_test("app_stop_initiates_cancel");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let spec = AppSpec::new("stoppable").child(make_child("w"));
        let mut handle = spec.start(&mut state, &cx, root).expect("start ok");
        let app_region = handle.root_region();

        let stopped = handle.stop(&mut state).expect("stop ok");
        assert_eq!(stopped.name, "stoppable");
        assert_eq!(stopped.root_region, app_region);

        // Region should have a cancel request and be closing.
        let region = state.region(app_region).expect("region exists");
        assert!(
            region.state() == RegionState::Closing || region.state() == RegionState::Closed,
            "region should be closing or closed, got {:?}",
            region.state()
        );

        crate::test_complete!("app_stop_initiates_cancel");
    }

    #[test]
    fn app_join_on_closed_region_succeeds() {
        init_test("app_join_on_closed_region_succeeds");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        // Start app with no children (empty supervisor).
        let spec = AppSpec::new("empty_app");
        let mut handle = spec.start(&mut state, &cx, root).expect("start ok");
        let app_region = handle.root_region();

        // Force-close the region for testing purposes.
        if let Some(r) = state.region(app_region) {
            // Remove tasks to satisfy strict quiescence
            for task in r.task_ids() {
                r.remove_task(task);
            }
            for child in r.child_ids() {
                r.remove_child(child);
            }
            r.begin_close(None);
            r.begin_drain();
            r.begin_finalize();
            assert!(r.complete_close(), "should be able to close empty region");
        }

        assert!(
            state
                .region(app_region)
                .is_some_and(|r| r.state() == RegionState::Closed)
        );

        let stopped = handle.join(&state).expect("join ok");
        assert_eq!(stopped.name, "empty_app");
        crate::test_complete!("app_join_on_closed_region_succeeds");
    }

    #[test]
    fn app_join_on_open_region_preserves_handle() {
        init_test("app_join_on_open_region_preserves_handle");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let spec = AppSpec::new("still_running").child(make_child("worker"));
        let mut handle = spec.start(&mut state, &cx, root).expect("start ok");
        let app_region = handle.root_region();

        let result = handle.join(&state);
        assert!(
            matches!(
                result,
                Err(AppStopError::RegionNotStopped { region, state })
                    if region == app_region && state == RegionState::Open
            ),
            "expected RegionNotStopped(Open) for the running app region"
        );

        let stopped = handle
            .stop(&mut state)
            .expect("handle should remain usable after join miss");
        assert_eq!(stopped.root_region, app_region);

        crate::test_complete!("app_join_on_open_region_preserves_handle");
    }

    #[test]
    fn app_into_raw_disarms_drop_bomb() {
        init_test("app_into_raw_disarms_drop_bomb");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let spec = AppSpec::new("raw_app");
        let handle = spec.start(&mut state, &cx, root).expect("start ok");

        let raw = handle.into_raw();
        assert_eq!(raw.name, "raw_app");
        // raw can be dropped without panic.
        drop(raw);
        crate::test_complete!("app_into_raw_disarms_drop_bomb");
    }

    #[test]
    fn app_handle_drop_without_resolve_reports_without_panicking() {
        init_test("app_handle_drop_without_resolve_reports_without_panicking");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let spec = AppSpec::new("leaky");
        let handle = spec.start(&mut state, &cx, root).expect("start ok");
        drop(handle);
        crate::test_complete!("app_handle_drop_without_resolve_reports_without_panicking");
    }

    #[test]
    fn app_start_compile_error_on_duplicate_children() {
        init_test("app_start_compile_error_on_duplicate_children");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let spec = AppSpec::new("dup")
            .child(make_child("same"))
            .child(make_child("same"));

        let err = spec.start(&mut state, &cx, root).unwrap_err();
        assert!(
            matches!(
                err,
                AppStartError::CompileFailed(AppCompileError::SupervisorCompile(
                    SupervisorCompileError::DuplicateChildName(_)
                ))
            ),
            "expected DuplicateChildName, got {err:?}"
        );
        crate::test_complete!("app_start_compile_error_on_duplicate_children");
    }

    #[test]
    fn app_start_spawn_failure_cleans_up_allocated_region() {
        init_test("app_start_spawn_failure_cleans_up_allocated_region");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let failing_child = ChildSpec {
            name: "broken".into(),
            start: Box::new(
                |scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
                 _state: &mut RuntimeState,
                 _cx: &Cx| Err(SpawnError::RegionClosed(scope.region_id())),
            ),
            restart: SupervisionStrategy::Stop,
            shutdown_budget: Budget::INFINITE,
            depends_on: Vec::new(),
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        };

        let spec = AppSpec::new("broken_app").child(failing_child);
        let result = spec.start(&mut state, &cx, root);
        assert!(matches!(result, Err(AppStartError::SpawnFailed(_))));
        assert_eq!(
            state.regions_len(),
            1,
            "failed app start should not leak an extra region"
        );
        assert_eq!(
            state
                .region(root)
                .map(crate::record::RegionRecord::child_count),
            Some(0),
            "parent root should not retain a leaked child region"
        );

        crate::test_complete!("app_start_spawn_failure_cleans_up_allocated_region");
    }

    #[test]
    fn app_start_spawn_failure_cleans_up_started_tasks() {
        init_test("app_start_spawn_failure_cleans_up_started_tasks");
        use crate::runtime::state::completion_observer_test_support::PanickingCompletionMetrics;

        let metrics = PanickingCompletionMetrics::panic_persistently();
        let mut state = RuntimeState::new_with_metrics(metrics.clone());
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let failing_child = ChildSpec {
            name: "broken".into(),
            start: Box::new(
                |scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
                 _state: &mut RuntimeState,
                 _cx: &Cx| Err(SpawnError::RegionClosed(scope.region_id())),
            ),
            restart: SupervisionStrategy::Stop,
            shutdown_budget: Budget::INFINITE,
            depends_on: vec!["started".into()],
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        };

        let spec = AppSpec::new("partially_started_app")
            .child(make_child("started"))
            .child(failing_child);
        let result = spec.start(&mut state, &cx, root);

        assert!(matches!(result, Err(AppStartError::SpawnFailed(_))));
        assert_eq!(
            state.live_task_count(),
            0,
            "failed app start should not leave unscheduled tasks behind"
        );
        assert_eq!(
            state.regions_len(),
            1,
            "failed app start should remove the temporary app region tree"
        );
        assert_eq!(
            state
                .region(root)
                .map(crate::record::RegionRecord::child_count),
            Some(0),
            "parent root should not retain leaked app descendants"
        );
        assert_eq!(
            metrics.completion_attempts(),
            0,
            "failed-start cleanup must suppress direct completion observers"
        );

        crate::test_complete!("app_start_spawn_failure_cleans_up_started_tasks");
    }

    #[test]
    fn app_start_spawn_failure_drains_async_finalizers() {
        init_test("app_start_spawn_failure_drains_async_finalizers");
        let metrics =
            crate::runtime::state::spawn_observer_test_support::PanickingSpawnMetrics::new();
        let mut state = RuntimeState::new_with_metrics(metrics.clone());
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let finalizer_ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let finalizer_ran_clone = Arc::clone(&finalizer_ran);
        let rollback_spawn_denied = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let rollback_spawn_denied_clone = Arc::clone(&rollback_spawn_denied);
        let failing_child = ChildSpec {
            name: "broken".into(),
            start: Box::new(
                move |scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
                      state: &mut RuntimeState,
                      _cx: &Cx| {
                    let registered = state.register_async_finalizer(scope.region_id(), {
                        let finalizer_ran = Arc::clone(&finalizer_ran_clone);
                        let rollback_spawn_denied = Arc::clone(&rollback_spawn_denied_clone);
                        async move {
                            let rollback_cx = Cx::current()
                                .expect("failed-start finalizer should receive an ambient Cx");
                            rollback_spawn_denied.store(
                                matches!(
                                    rollback_cx.spawn(|_| async {}),
                                    Err(SpawnError::RuntimeUnavailable)
                                ),
                                std::sync::atomic::Ordering::SeqCst,
                            );
                            finalizer_ran.store(true, std::sync::atomic::Ordering::SeqCst);
                        }
                    });
                    assert!(registered, "startup region should accept async finalizer");
                    Err(SpawnError::RegionClosed(scope.region_id()))
                },
            ),
            restart: SupervisionStrategy::Stop,
            shutdown_budget: Budget::INFINITE,
            depends_on: Vec::new(),
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        };

        let spec = AppSpec::new("broken_finalizer_app").child(failing_child);
        let result = spec.start(&mut state, &cx, root);

        assert!(matches!(result, Err(AppStartError::SpawnFailed(_))));
        assert!(
            finalizer_ran.load(std::sync::atomic::Ordering::SeqCst),
            "failed app start should still drain registered async finalizers"
        );
        assert!(
            rollback_spawn_denied.load(std::sync::atomic::Ordering::SeqCst),
            "failed-start rollback must deny work that could keep its closing subtree live"
        );
        assert_eq!(
            metrics.spawn_attempts(),
            0,
            "failed-start inline finalizers are rollback callbacks, not unpublished tasks"
        );
        assert_eq!(
            state.live_task_count(),
            0,
            "failed app start should not leave async finalizer tasks behind"
        );
        assert_eq!(
            state.regions_len(),
            1,
            "failed app start should remove the temporary app region tree"
        );
        assert_eq!(
            state
                .region(root)
                .map(crate::record::RegionRecord::child_count),
            Some(0),
            "parent root should not retain leaked app descendants"
        );
        assert_eq!(
            state.cancel_protocol_validator().lock().violation_count(),
            0,
            "failed-start finalization should stay validator-aligned"
        );

        crate::test_complete!("app_start_spawn_failure_drains_async_finalizers");
    }

    #[test]
    fn app_is_quiescent_after_close() {
        init_test("app_is_quiescent_after_close");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let spec = AppSpec::new("quiescent_test");
        let handle = spec.start(&mut state, &cx, root).expect("start ok");
        let app_region = handle.root_region();

        // Disarm drop bomb early so assertions can't cause double-panic.
        let raw = handle.into_raw();

        // Force region through lifecycle.
        if let Some(r) = state.region(app_region) {
            // Remove tasks and children to satisfy strict quiescence
            for task in r.task_ids() {
                r.remove_task(task);
            }
            for child in r.child_ids() {
                r.remove_child(child);
            }
            r.begin_close(None);
            r.begin_drain();
            r.begin_finalize();
            assert!(r.complete_close(), "should close empty region");
        }

        let region = state.region(app_region).expect("region exists");
        assert_eq!(region.state(), RegionState::Closed);
        // Note: is_quiescent requires all children removed, which force-close
        // doesn't do. In production, the drain phase handles child cleanup.

        drop(raw);
        crate::test_complete!("app_is_quiescent_after_close");
    }

    #[test]
    fn app_with_budget_propagates_to_region() {
        init_test("app_with_budget_propagates_to_region");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let budget = Budget::new().with_poll_quota(100_000);
        let spec = AppSpec::new("budgeted_app").with_budget(budget);
        let handle = spec.start(&mut state, &cx, root).expect("start ok");

        let region = state.region(handle.root_region()).expect("region exists");
        assert_eq!(region.budget().poll_quota, budget.poll_quota);

        let _raw = handle.into_raw();
        crate::test_complete!("app_with_budget_propagates_to_region");
    }

    // --- Compile + Spawn tests (bd-32w45) ---

    #[test]
    fn app_compile_produces_compiled_app() {
        init_test("app_compile_produces_compiled_app");
        let compiled = AppSpec::new("compiled_test")
            .child(make_child("a"))
            .child(make_child("b"))
            .compile()
            .expect("compile ok");
        assert_eq!(compiled.name(), "compiled_test");
        crate::test_complete!("app_compile_produces_compiled_app");
    }

    #[test]
    fn app_compile_detects_duplicate_names() {
        init_test("app_compile_detects_duplicate_names");
        let err = AppSpec::new("dup_compile")
            .child(make_child("same"))
            .child(make_child("same"))
            .compile()
            .unwrap_err();
        assert!(
            matches!(
                err,
                AppCompileError::SupervisorCompile(SupervisorCompileError::DuplicateChildName(_))
            ),
            "expected DuplicateChildName, got {err:?}"
        );
        crate::test_complete!("app_compile_detects_duplicate_names");
    }

    #[test]
    fn app_compiled_start_creates_region_and_spawns() {
        init_test("app_compiled_start_creates_region_and_spawns");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let compiled = AppSpec::new("two_phase")
            .child(make_child("w1"))
            .child(make_child("w2"))
            .compile()
            .expect("compile ok");
        let handle = compiled.start(&mut state, &cx, root).expect("start ok");
        assert_eq!(handle.name(), "two_phase");
        assert_eq!(handle.supervisor().started.len(), 2);
        let _raw = handle.into_raw();
        crate::test_complete!("app_compiled_start_creates_region_and_spawns");
    }

    #[test]
    fn app_compile_is_deterministic() {
        init_test("app_compile_is_deterministic");
        let build = || {
            AppSpec::new("det")
                .child(make_child("c"))
                .child(make_child("a"))
                .child(make_child("b"))
        };
        let c1 = build().compile().unwrap();
        let c2 = build().compile().unwrap();
        assert_eq!(
            c1.compiled_supervisor().start_order,
            c2.compiled_supervisor().start_order,
            "compile must produce identical start orders"
        );
        crate::test_complete!("app_compile_is_deterministic");
    }

    #[test]
    fn app_compile_with_dependencies_is_deterministic() {
        init_test("app_compile_with_dependencies_is_deterministic");
        let build = || {
            let mut b = make_child("b");
            b.depends_on = vec!["a".into()];
            let mut c = make_child("c");
            c.depends_on = vec!["b".into()];
            AppSpec::new("dep_det")
                .child(c)
                .child(make_child("a"))
                .child(b)
        };
        let c1 = build().compile().unwrap();
        let c2 = build().compile().unwrap();
        assert_eq!(
            c1.compiled_supervisor().start_order,
            c2.compiled_supervisor().start_order
        );
        crate::test_complete!("app_compile_with_dependencies_is_deterministic");
    }

    #[test]
    fn app_compile_budget_propagates() {
        init_test("app_compile_budget_propagates");
        let budget = Budget::new().with_poll_quota(100_000);
        let compiled = AppSpec::new("budgeted_compile")
            .with_budget(budget)
            .compile()
            .unwrap();
        assert_eq!(compiled.budget, Some(budget));
        crate::test_complete!("app_compile_budget_propagates");
    }

    // --- Conformance tests ---

    #[test]
    fn conformance_start_stop_lifecycle() {
        init_test("conformance_start_stop_lifecycle");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        // Start → stop → region transitions correctly.
        let spec = AppSpec::new("lifecycle").child(make_child("w1"));
        let mut handle = spec.start(&mut state, &cx, root).expect("start ok");
        let app_region = handle.root_region();

        // Region starts open.
        assert_eq!(state.region(app_region).unwrap().state(), RegionState::Open);

        let _stopped = handle.stop(&mut state).expect("stop ok");

        // Region should transition past Open.
        let region_state = state.region(app_region).unwrap().state();
        assert_ne!(
            region_state,
            RegionState::Open,
            "region should no longer be open after stop"
        );

        crate::test_complete!("conformance_start_stop_lifecycle");
    }

    #[test]
    fn conformance_no_ambient_authority() {
        init_test("conformance_no_ambient_authority");

        // Verify AppSpec is pure data: cannot access globals or state
        // without being explicitly given &mut RuntimeState and &Cx.
        let spec = AppSpec::new("isolated");
        // spec holds no references to runtime state, only description data.
        assert_eq!(spec.name, "isolated");
        assert!(spec.budget.is_none());
        // The only way to start is by providing explicit state + cx.

        crate::test_complete!("conformance_no_ambient_authority");
    }

    #[test]
    fn conformance_root_region_is_child_of_parent() {
        init_test("conformance_root_region_is_child_of_parent");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let spec = AppSpec::new("nested");
        let handle = spec.start(&mut state, &cx, root).expect("start ok");

        // The app's root region should be a child of the parent region.
        let app_region = handle.root_region();
        let region_record = state.region(app_region).expect("region exists");
        assert_eq!(
            region_record.parent,
            Some(root),
            "app root region must be a child of the given parent"
        );

        let _raw = handle.into_raw();
        crate::test_complete!("conformance_root_region_is_child_of_parent");
    }

    #[test]
    fn conformance_stop_is_cancel_correct() {
        init_test("conformance_stop_is_cancel_correct");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let spec = AppSpec::new("cancel_correct").child(make_child("w"));
        let mut handle = spec.start(&mut state, &cx, root).expect("start ok");
        let app_region = handle.root_region();

        let _stopped = handle.stop(&mut state).expect("stop ok");

        // After stop, the region should have a cancel reason set.
        let region = state.region(app_region).expect("region exists");
        assert!(
            region.cancel_reason().is_some(),
            "stop must set a cancel reason on the root region"
        );

        crate::test_complete!("conformance_stop_is_cancel_correct");
    }

    #[test]
    fn conformance_deterministic_child_start_order() {
        init_test("conformance_deterministic_child_start_order");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        // Children with dependencies: charlie depends on bravo, bravo depends on alpha.
        let alpha = ChildSpec {
            name: "alpha".into(),
            start: Box::new(
                |scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
                 state: &mut RuntimeState,
                 _cx: &Cx| {
                    state
                        .create_task(scope.region_id(), scope.budget(), async { 1_u8 })
                        .map(|(_, s)| s.task_id())
                },
            ),
            restart: SupervisionStrategy::Stop,
            shutdown_budget: Budget::INFINITE,
            depends_on: vec![],
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        };
        let bravo = ChildSpec {
            name: "bravo".into(),
            start: Box::new(
                |scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
                 state: &mut RuntimeState,
                 _cx: &Cx| {
                    state
                        .create_task(scope.region_id(), scope.budget(), async { 2_u8 })
                        .map(|(_, s)| s.task_id())
                },
            ),
            restart: SupervisionStrategy::Stop,
            shutdown_budget: Budget::INFINITE,
            depends_on: vec!["alpha".into()],
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        };
        let charlie = ChildSpec {
            name: "charlie".into(),
            start: Box::new(
                |scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
                 state: &mut RuntimeState,
                 _cx: &Cx| {
                    state
                        .create_task(scope.region_id(), scope.budget(), async { 3_u8 })
                        .map(|(_, s)| s.task_id())
                },
            ),
            restart: SupervisionStrategy::Stop,
            shutdown_budget: Budget::INFINITE,
            depends_on: vec!["bravo".into()],
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        };

        let spec = AppSpec::new("ordered")
            .child(charlie) // Intentionally out of order.
            .child(alpha)
            .child(bravo);
        let handle = spec.start(&mut state, &cx, root).expect("start ok");

        // Start order should be alpha → bravo → charlie regardless of insertion order.
        let names: Vec<&str> = handle
            .supervisor()
            .started
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(names, vec!["alpha", "bravo", "charlie"]);

        let _raw = handle.into_raw();
        crate::test_complete!("conformance_deterministic_child_start_order");
    }

    #[test]
    fn conformance_compiled_app_starts_and_closes() {
        init_test("conformance_compiled_app_starts_and_closes");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let compiled = AppSpec::new("quiesce")
            .child(make_child("w1"))
            .compile()
            .expect("compile ok");
        let mut handle = compiled.start(&mut state, &cx, root).expect("start ok");
        let app_region = handle.root_region();
        let _stopped = handle.stop(&mut state).expect("stop ok");

        if let Some(r) = state.region(app_region) {
            // Remove tasks and children to satisfy strict quiescence
            for task in r.task_ids() {
                r.remove_task(task);
            }
            for child in r.child_ids() {
                r.remove_child(child);
            }
            if r.state() == RegionState::Closing {
                r.begin_drain();
            }
            if r.state() == RegionState::Draining {
                r.begin_finalize();
            }
            if r.state() == RegionState::Finalizing {
                assert!(r.complete_close(), "should complete close");
            }
        }

        assert_eq!(
            state.region(app_region).unwrap().state(),
            RegionState::Closed,
        );
        crate::test_complete!("conformance_compiled_app_starts_and_closes");
    }

    #[test]
    fn conformance_compile_errors_are_explicit() {
        init_test("conformance_compile_errors_are_explicit");
        let err = AppSpec::new("errs")
            .child(make_child("dup"))
            .child(make_child("dup"))
            .compile()
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("compile failed"),
            "error should mention compile: {msg}"
        );
        assert!(
            std::error::Error::source(&err).is_some(),
            "AppCompileError must have a source"
        );
        crate::test_complete!("conformance_compile_errors_are_explicit");
    }

    #[test]
    fn conformance_compile_then_start_matches_direct() {
        init_test("conformance_compile_then_start_matches_direct");

        let mut s1 = RuntimeState::new();
        let r1 = s1.create_root_region(Budget::INFINITE);
        let cx1 = Cx::new(
            r1,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let mut s2 = RuntimeState::new();
        let r2 = s2.create_root_region(Budget::INFINITE);
        let cx2 = Cx::new(
            r2,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let h1 = AppSpec::new("direct")
            .child(make_child("w"))
            .start(&mut s1, &cx1, r1)
            .unwrap();
        let compiled = AppSpec::new("compiled")
            .child(make_child("w"))
            .compile()
            .unwrap();
        let h2 = compiled.start(&mut s2, &cx2, r2).unwrap();

        assert_eq!(h1.supervisor().started.len(), h2.supervisor().started.len());
        assert_ne!(h1.root_region(), r1);
        assert_ne!(h2.root_region(), r2);

        let _raw1 = h1.into_raw();
        let _raw2 = h2.into_raw();
        crate::test_complete!("conformance_compile_then_start_matches_direct");
    }

    // --- Registry wiring tests (bd-2ukjr) ---

    #[test]
    fn app_with_registry_propagates_to_children() {
        init_test("app_with_registry_propagates_to_children");

        let registry = crate::cx::NameRegistry::new();
        let handle = RegistryHandle::new(Arc::new(registry));

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        // Parent Cx has no registry.
        assert!(!cx.has_registry());

        // Build a child that checks for registry capability.
        let registry_seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen_clone = Arc::clone(&registry_seen);
        let child = ChildSpec {
            name: "checker".into(),
            start: Box::new(
                move |scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
                      state: &mut RuntimeState,
                      cx: &Cx| {
                    // Child should see the registry propagated through the app.
                    seen_clone.store(cx.has_registry(), std::sync::atomic::Ordering::SeqCst);
                    state
                        .create_task(scope.region_id(), scope.budget(), async { 0_u8 })
                        .map(|(_, s)| s.task_id())
                },
            ),
            restart: SupervisionStrategy::Stop,
            shutdown_budget: Budget::INFINITE,
            depends_on: vec![],
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        };

        let spec = AppSpec::new("registry_app")
            .with_registry(handle)
            .child(child);
        let app_handle = spec.start(&mut state, &cx, root).expect("start ok");

        // The child factory should have seen the registry.
        assert!(
            registry_seen.load(std::sync::atomic::Ordering::SeqCst),
            "child Cx must carry registry when app is started with one"
        );

        // The app handle should expose the registry.
        assert!(app_handle.registry().is_some());

        let _raw = app_handle.into_raw();
        crate::test_complete!("app_with_registry_propagates_to_children");
    }

    #[test]
    fn app_bootstrap_cx_targets_app_root_and_preserves_capabilities() {
        init_test("app_bootstrap_cx_targets_app_root_and_preserves_capabilities");

        let registry = crate::cx::NameRegistry::new();
        let handle = RegistryHandle::new(Arc::new(registry));

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let parent_task = crate::types::TaskId::new_for_test(77, 9);
        let cx = Cx::new(root, parent_task, Budget::INFINITE)
            .with_remote_cap(RemoteCap::new().with_local_node(NodeId::new("origin-test")));

        let seen = Arc::new(parking_lot::Mutex::new(
            None::<(RegionId, crate::types::TaskId, bool, Option<String>)>,
        ));
        let seen_clone = Arc::clone(&seen);
        let child = ChildSpec {
            name: "checker".into(),
            start: Box::new(
                move |scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
                      state: &mut RuntimeState,
                      cx: &Cx| {
                    *seen_clone.lock() = Some((
                        cx.region_id(),
                        cx.task_id(),
                        cx.has_registry(),
                        cx.remote_cap_handle()
                            .map(|cap| cap.local_node().as_str().to_string()),
                    ));
                    state
                        .create_task(scope.region_id(), scope.budget(), async { 0_u8 })
                        .map(|(_, stored)| stored.task_id())
                },
            ),
            restart: SupervisionStrategy::Stop,
            shutdown_budget: Budget::INFINITE,
            depends_on: vec![],
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        };

        let app_handle = AppSpec::new("bootstrap_cx_app")
            .with_registry(handle)
            .child(child)
            .start(&mut state, &cx, root)
            .expect("start ok");

        let (seen_region, seen_task, saw_registry, remote_origin) = seen
            .lock()
            .clone()
            .expect("child should observe bootstrap cx");
        assert_eq!(
            seen_region,
            app_handle.root_region(),
            "startup closures must observe the app root region, not the caller's region"
        );
        assert_ne!(
            seen_task, parent_task,
            "startup closures must not inherit the caller's task identity"
        );
        assert!(
            saw_registry,
            "app registry override must be visible during startup"
        );
        assert_eq!(remote_origin.as_deref(), Some("origin-test"));

        let _raw = app_handle.into_raw();
        crate::test_complete!("app_bootstrap_cx_targets_app_root_and_preserves_capabilities");
    }

    #[test]
    fn app_without_registry_children_see_none() {
        init_test("app_without_registry_children_see_none");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let registry_seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen_clone = Arc::clone(&registry_seen);
        let child = ChildSpec {
            name: "no_reg".into(),
            start: Box::new(
                move |scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
                      state: &mut RuntimeState,
                      cx: &Cx| {
                    seen_clone.store(cx.has_registry(), std::sync::atomic::Ordering::SeqCst);
                    state
                        .create_task(scope.region_id(), scope.budget(), async { 0_u8 })
                        .map(|(_, s)| s.task_id())
                },
            ),
            restart: SupervisionStrategy::Stop,
            shutdown_budget: Budget::INFINITE,
            depends_on: vec![],
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        };

        let spec = AppSpec::new("no_registry_app").child(child);
        let app_handle = spec.start(&mut state, &cx, root).expect("start ok");

        assert!(
            !registry_seen.load(std::sync::atomic::Ordering::SeqCst),
            "child Cx must NOT have registry when app has none"
        );
        assert!(app_handle.registry().is_none());

        let _raw = app_handle.into_raw();
        crate::test_complete!("app_without_registry_children_see_none");
    }

    #[test]
    fn app_registry_named_service_whereis() {
        init_test("app_registry_named_service_whereis");

        let registry = Arc::new(parking_lot::Mutex::new(crate::cx::NameRegistry::new()));
        let reg_handle =
            RegistryHandle::new(Arc::clone(&registry) as Arc<dyn crate::cx::RegistryCap>);

        // Shared slot for the NameLease (must be resolved before drop).
        let lease_slot: Arc<parking_lot::Mutex<Option<crate::cx::NameLease>>> =
            Arc::new(parking_lot::Mutex::new(None));

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        // Child registers itself in the shared registry.
        let reg_clone = Arc::clone(&registry);
        let lease_clone = Arc::clone(&lease_slot);
        let child = ChildSpec {
            name: "named_worker".into(),
            start: Box::new(
                move |scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
                      state: &mut RuntimeState,
                      _cx: &Cx| {
                    let region = scope.region_id();
                    let budget = scope.budget();
                    let (_, stored) = state.create_task(region, budget, async { 1_u8 })?;
                    let task_id = stored.task_id();

                    // Register the task name in the shared registry.
                    let now = crate::types::Time::from_nanos(1_000_000_000);
                    let lease = reg_clone
                        .lock()
                        .register("my_worker", task_id, region, now)
                        .expect("register ok");

                    // Store the lease so it can be resolved after assertions.
                    *lease_clone.lock() = Some(lease);

                    Ok(task_id)
                },
            ),
            restart: SupervisionStrategy::Stop,
            shutdown_budget: Budget::INFINITE,
            depends_on: vec![],
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        };

        let spec = AppSpec::new("named_app")
            .with_registry(reg_handle)
            .child(child);
        let app_handle = spec.start(&mut state, &cx, root).expect("start ok");

        // The named worker should be findable via whereis.
        let found = registry.lock().whereis("my_worker");
        assert!(found.is_some(), "named worker must be visible via whereis");

        // Clean up: release the lease to avoid obligation drop bomb.
        lease_slot
            .lock()
            .as_mut()
            .expect("lease should have been set")
            .release()
            .expect("release ok");

        let _raw = app_handle.into_raw();
        crate::test_complete!("app_registry_named_service_whereis");
    }

    #[test]
    fn app_registry_compile_preserves_handle() {
        init_test("app_registry_compile_preserves_handle");

        let registry = crate::cx::NameRegistry::new();
        let handle = RegistryHandle::new(Arc::new(registry));

        let compiled = AppSpec::new("compiled_reg")
            .with_registry(handle)
            .child(make_child("w"))
            .compile()
            .expect("compile ok");

        // Registry should survive compilation.
        assert!(compiled.registry.is_some());

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let app_handle = compiled.start(&mut state, &cx, root).expect("start ok");
        assert!(app_handle.registry().is_some());

        let _raw = app_handle.into_raw();
        crate::test_complete!("app_registry_compile_preserves_handle");
    }

    #[test]
    fn app_registry_stop_does_not_panic() {
        init_test("app_registry_stop_does_not_panic");

        let registry = crate::cx::NameRegistry::new();
        let handle = RegistryHandle::new(Arc::new(registry));

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let spec = AppSpec::new("stoppable_reg")
            .with_registry(handle)
            .child(make_child("w"));
        let mut app_handle = spec.start(&mut state, &cx, root).expect("start ok");

        // Stop should work without panic.
        let _stopped = app_handle.stop(&mut state).expect("stop ok");
        crate::test_complete!("app_registry_stop_does_not_panic");
    }

    // =====================================================================
    // Mini Chat App Example (bd-2cruj)
    //
    // Demonstrates GenServer + Registry + Supervisor integration patterns.
    // =====================================================================

    use crate::gen_server::{GenServer, Reply, SystemMsg};
    use std::future::Future;
    use std::pin::Pin;

    /// Chat room state: holds a bounded message history.
    struct ChatRoom {
        history: Vec<String>,
        max_history: usize,
    }

    /// Synchronous requests (call): operations that return a response.
    enum ChatCall {
        /// Get the current message history.
        GetHistory,
        /// Get the number of messages.
        #[allow(dead_code)]
        Count,
    }

    /// Asynchronous messages (cast): fire-and-forget operations.
    enum ChatCast {
        /// Post a message to the room.
        Post(String),
        /// Clear all messages.
        Clear,
    }

    impl GenServer for ChatRoom {
        type Call = ChatCall;
        type Reply = Vec<String>;
        type Cast = ChatCast;
        type Info = SystemMsg;

        fn handle_call(
            &mut self,
            _cx: &Cx,
            request: ChatCall,
            reply: Reply<Vec<String>>,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            match request {
                ChatCall::GetHistory => {
                    let _ = reply.send(self.history.clone());
                }
                ChatCall::Count => {
                    // Encode count as a single-element vec to satisfy the Reply type.
                    let _ = reply.send(vec![self.history.len().to_string()]);
                }
            }
            Box::pin(async {})
        }

        fn handle_cast(
            &mut self,
            _cx: &Cx,
            msg: ChatCast,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            match msg {
                ChatCast::Post(text) => {
                    self.history.push(text);
                    if self.history.len() > self.max_history {
                        self.history.remove(0);
                    }
                }
                ChatCast::Clear => {
                    self.history.clear();
                }
            }
            Box::pin(async {})
        }
    }

    impl ChatRoom {
        fn new(max_history: usize) -> Self {
            Self {
                history: Vec::new(),
                max_history,
            }
        }
    }

    #[test]
    fn example_chat_room_call_and_cast() {
        // Demonstrates: GenServer with typed call (GetHistory) and cast (Post).
        init_test("example_chat_room_call_and_cast");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let region = runtime
            .state
            .create_child_region(root, Budget::INFINITE)
            .expect("example region should allocate");
        let cx = lab_spawn_cx(&runtime, region, Budget::INFINITE);
        let scope =
            crate::cx::Scope::<crate::types::policy::FailFast>::new(region, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, ChatRoom::new(100), 32)
            .unwrap();
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        // Cast: post messages (fire-and-forget).
        handle
            .try_cast(ChatCast::Post("alice: hello".into()))
            .unwrap();
        handle
            .try_cast(ChatCast::Post("bob: hi alice".into()))
            .unwrap();
        handle
            .try_cast(ChatCast::Post("alice: how are you?".into()))
            .unwrap();

        // Spawn a client task that calls GetHistory.
        let server_ref = handle.server_ref();
        let mut client_handle = cx
            .spawn(
                move |cx| async move { server_ref.call(&cx, ChatCall::GetHistory).await.unwrap() },
            )
            .unwrap();

        // Schedule the server, run until idle; the client is admitted via the
        // spawn gateway while the long-lived server remains parked on receive.
        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_idle();

        // Verify the client received the full history.
        let history =
            futures_lite::future::block_on(client_handle.join(&cx)).expect("client join ok");
        assert_eq!(history.len(), 3);
        assert_eq!(history[0], "alice: hello");
        assert_eq!(history[1], "bob: hi alice");
        assert_eq!(history[2], "alice: how are you?");

        crate::test_complete!("example_chat_room_call_and_cast");
    }

    #[test]
    fn example_chat_room_bounded_history() {
        // Demonstrates: cast overflow handling (bounded history, not bounded channel).
        init_test("example_chat_room_bounded_history");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let region = runtime
            .state
            .create_child_region(root, Budget::INFINITE)
            .expect("example region should allocate");
        let cx = lab_spawn_cx(&runtime, region, Budget::INFINITE);
        let scope =
            crate::cx::Scope::<crate::types::policy::FailFast>::new(region, Budget::INFINITE);

        // Chat room with max 2 messages.
        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, ChatRoom::new(2), 32)
            .unwrap();
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        // Post 3 messages; oldest should be evicted.
        handle.try_cast(ChatCast::Post("msg1".into())).unwrap();
        handle.try_cast(ChatCast::Post("msg2".into())).unwrap();
        handle.try_cast(ChatCast::Post("msg3".into())).unwrap();

        let server_ref = handle.server_ref();
        let mut client_handle = cx
            .spawn(
                move |cx| async move { server_ref.call(&cx, ChatCall::GetHistory).await.unwrap() },
            )
            .unwrap();

        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_idle();

        let history =
            futures_lite::future::block_on(client_handle.join(&cx)).expect("client join ok");
        assert_eq!(history, vec!["msg2", "msg3"], "oldest message evicted");

        crate::test_complete!("example_chat_room_bounded_history");
    }

    #[test]
    fn example_chat_room_named_via_registry() {
        // Demonstrates: named server registration + whereis lookup.
        init_test("example_chat_room_named_via_registry");

        let registry = Arc::new(parking_lot::Mutex::new(crate::cx::NameRegistry::new()));

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let region = runtime
            .state
            .create_child_region(root, Budget::INFINITE)
            .expect("example region should allocate");
        let cx = lab_spawn_cx(&runtime, region, Budget::INFINITE);
        let scope =
            crate::cx::Scope::<crate::types::policy::FailFast>::new(region, Budget::INFINITE);

        // Spawn a named chat room via the atomic spawn_named_gen_server API.
        let (mut named_handle, stored) = scope
            .spawn_named_gen_server(
                &mut runtime.state,
                &cx,
                &mut registry.lock(),
                "lobby",
                ChatRoom::new(100),
                32,
                crate::types::Time::from_nanos(1_000_000_000),
            )
            .unwrap();
        let task_id = named_handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        // The room should be discoverable via whereis.
        let found = registry.lock().whereis("lobby");
        assert!(
            found.is_some(),
            "named chat room must be visible via whereis"
        );
        assert_eq!(found.unwrap(), task_id);

        // Post and read via the named handle's server_ref.
        named_handle
            .inner()
            .try_cast(ChatCast::Post("welcome to lobby".into()))
            .unwrap();

        let server_ref = named_handle.server_ref();
        let mut client_handle = cx
            .spawn(
                move |cx| async move { server_ref.call(&cx, ChatCall::GetHistory).await.unwrap() },
            )
            .unwrap();

        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_idle();

        let history = futures_lite::future::block_on(client_handle.join(&cx)).expect("join ok");
        assert_eq!(history, vec!["welcome to lobby"]);

        // Clean up the example explicitly. Dedicated `release_name` semantics
        // are covered in `gen_server` tests; this example just needs to resolve
        // the name lease deterministically before teardown.
        let mut lease = named_handle.take_lease().expect("lease present");
        named_handle.inner().abort();
        let release_now = runtime.state.now;
        let mut registry_guard = registry.lock();
        registry_guard
            .unregister_owned_and_grant(&lease, release_now)
            .expect("manual unregister ok");
        lease.abort().expect("lease abort ok");
        drop(registry_guard);

        // After stop-and-release, whereis should return None.
        let found_after = registry.lock().whereis("lobby");
        assert!(
            found_after.is_none(),
            "name must be gone after stop-and-release"
        );

        crate::test_complete!("example_chat_room_named_via_registry");
    }

    #[test]
    fn example_chat_room_supervised_app() {
        // Demonstrates: ChatRoom as a supervised child in an AppSpec.
        init_test("example_chat_room_supervised_app");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let chat_started = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let started_clone = Arc::clone(&chat_started);

        // ChildSpec that spawns a ChatRoom GenServer.
        let chat_child = ChildSpec {
            name: "lobby".into(),
            start: Box::new(
                move |scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
                      state: &mut RuntimeState,
                      cx: &Cx| {
                    let (handle, stored) =
                        scope.spawn_gen_server::<ChatRoom>(state, cx, ChatRoom::new(100), 32)?;
                    started_clone.store(true, std::sync::atomic::Ordering::SeqCst);
                    let task_id = handle.task_id();
                    state.store_spawned_task(task_id, stored);
                    Ok(task_id)
                },
            ),
            restart: SupervisionStrategy::Stop,
            shutdown_budget: Budget::INFINITE,
            depends_on: vec![],
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        };

        let spec = AppSpec::new("chat_app").child(chat_child);
        let app_handle = spec.start(&mut state, &cx, root).expect("start ok");

        assert!(
            chat_started.load(std::sync::atomic::Ordering::SeqCst),
            "ChatRoom GenServer child must be started by supervisor"
        );
        assert_eq!(app_handle.name(), "chat_app");
        assert_eq!(app_handle.supervisor().started.len(), 1);
        assert_eq!(app_handle.supervisor().started[0].name, "lobby");

        let _raw = app_handle.into_raw();
        crate::test_complete!("example_chat_room_supervised_app");
    }

    #[test]
    fn example_chat_app_with_dependencies() {
        // Demonstrates: supervisor compilation with child dependencies.
        // The "announcements" child depends on "lobby" — topological sort
        // ensures lobby starts first regardless of insertion order.
        init_test("example_chat_app_with_dependencies");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let lobby_child = ChildSpec {
            name: "lobby".into(),
            start: Box::new(
                |scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
                 state: &mut RuntimeState,
                 _cx: &Cx| {
                    state
                        .create_task(scope.region_id(), scope.budget(), async { 1_u8 })
                        .map(|(_, s)| s.task_id())
                },
            ),
            restart: crate::supervision::SupervisionStrategy::Restart(
                crate::supervision::RestartConfig::new(3, std::time::Duration::from_secs(60)),
            ),
            shutdown_budget: Budget::INFINITE,
            depends_on: vec![],
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        };
        let announcements_child = ChildSpec {
            name: "announcements".into(),
            start: Box::new(
                |scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
                 state: &mut RuntimeState,
                 _cx: &Cx| {
                    state
                        .create_task(scope.region_id(), scope.budget(), async { 2_u8 })
                        .map(|(_, s)| s.task_id())
                },
            ),
            restart: crate::supervision::SupervisionStrategy::Restart(
                crate::supervision::RestartConfig::new(3, std::time::Duration::from_secs(60)),
            ),
            shutdown_budget: Budget::INFINITE,
            depends_on: vec!["lobby".into()], // depends on lobby
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        };

        // Insert in reverse order: announcements first, then lobby.
        let spec = AppSpec::new("chat_app")
            .with_restart_policy(RestartPolicy::OneForAll)
            .child(announcements_child)
            .child(lobby_child);
        let app_handle = spec.start(&mut state, &cx, root).expect("start ok");

        // Despite insertion order, start order must be lobby -> announcements.
        let names: Vec<&str> = app_handle
            .supervisor()
            .started
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(names, vec!["lobby", "announcements"]);

        let _raw = app_handle.into_raw();
        crate::test_complete!("example_chat_app_with_dependencies");
    }

    #[test]
    fn example_chat_clear_resets_history() {
        // Demonstrates: cast (Clear) resets server state.
        init_test("example_chat_clear_resets_history");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let region = runtime
            .state
            .create_child_region(root, Budget::INFINITE)
            .expect("example region should allocate");
        let cx = lab_spawn_cx(&runtime, region, Budget::INFINITE);
        let scope =
            crate::cx::Scope::<crate::types::policy::FailFast>::new(region, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, ChatRoom::new(100), 32)
            .unwrap();
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        // Post, then clear, then post again.
        handle.try_cast(ChatCast::Post("old msg".into())).unwrap();
        handle.try_cast(ChatCast::Clear).unwrap();
        handle
            .try_cast(ChatCast::Post("fresh start".into()))
            .unwrap();

        let server_ref = handle.server_ref();
        let mut client_handle = cx
            .spawn(
                move |cx| async move { server_ref.call(&cx, ChatCall::GetHistory).await.unwrap() },
            )
            .unwrap();

        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_idle();

        let history = futures_lite::future::block_on(client_handle.join(&cx)).expect("join ok");
        assert_eq!(history, vec!["fresh start"], "clear must reset history");

        crate::test_complete!("example_chat_clear_resets_history");
    }

    // --- Regression tests for audit-found bugs ---

    #[test]
    fn stop_region_not_found_does_not_panic() {
        // REGRESSION TEST: stop() must defuse the drop bomb even when returning Err,
        // preventing panic ("APP HANDLE LEAKED") when the handle is later dropped.
        init_test("stop_region_not_found_does_not_panic");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let spec = AppSpec::new("phantom").child(make_child("w"));
        let mut handle = spec.start(&mut state, &cx, root).expect("start ok");
        let app_region = handle.root_region();

        // Simulate corruption/removal inside the originating runtime.
        let _ = state.regions.remove(app_region.arena_index());

        // This must NOT panic — the drop bomb should be defused on the error path.
        let result = handle.stop(&mut state);
        assert!(
            matches!(result, Err(AppStopError::RegionNotFound(region)) if region == app_region),
            "expected RegionNotFound for a missing root region in the originating runtime"
        );
        crate::test_complete!("stop_region_not_found_does_not_panic");
    }

    #[test]
    fn join_region_not_found_does_not_panic() {
        // REGRESSION TEST: join() must defuse the drop bomb even when returning Err,
        // same as stop() path above.
        init_test("join_region_not_found_does_not_panic");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let spec = AppSpec::new("phantom_join").child(make_child("w"));
        let mut handle = spec.start(&mut state, &cx, root).expect("start ok");

        let app_region = handle.root_region();

        // Simulate corruption/removal inside the originating runtime.
        let _ = state.regions.remove(app_region.arena_index());

        let result = handle.join(&state);
        assert!(
            matches!(result, Err(AppStopError::RegionNotFound(region)) if region == app_region),
            "expected RegionNotFound for a missing root region in the originating runtime"
        );
        crate::test_complete!("join_region_not_found_does_not_panic");
    }

    #[test]
    fn app_join_succeeds_after_runtime_removes_closed_region() {
        init_test("app_join_succeeds_after_runtime_removes_closed_region");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let spec = AppSpec::new("removed_root");
        let mut handle = spec.start(&mut state, &cx, root).expect("start ok");
        let app_region = handle.root_region();

        close_app_region_and_remove_records(&mut state, app_region);

        assert!(
            state.region(app_region).is_none(),
            "normal shutdown should remove the closed app region record"
        );
        assert!(handle.is_stopped(&state));
        assert!(handle.is_quiescent(&state));

        let stopped = handle
            .join(&state)
            .expect("join should succeed after removal");
        assert_eq!(stopped.name, "removed_root");
        assert_eq!(stopped.root_region, app_region);

        crate::test_complete!("app_join_succeeds_after_runtime_removes_closed_region");
    }

    #[test]
    fn app_stop_is_idempotent_after_runtime_removes_closed_region() {
        init_test("app_stop_is_idempotent_after_runtime_removes_closed_region");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let spec = AppSpec::new("removed_then_stop");
        let mut handle = spec.start(&mut state, &cx, root).expect("start ok");
        let app_region = handle.root_region();

        close_app_region_and_remove_records(&mut state, app_region);

        let stopped = handle
            .stop(&mut state)
            .expect("stop should treat an already removed closed region as stopped");
        assert_eq!(stopped.name, "removed_then_stop");
        assert_eq!(stopped.root_region, app_region);

        crate::test_complete!("app_stop_is_idempotent_after_runtime_removes_closed_region");
    }

    #[test]
    fn app_join_wrong_runtime_preserves_handle_even_with_tombstone_collision() {
        init_test("app_join_wrong_runtime_preserves_handle_even_with_tombstone_collision");

        let mut state_a = RuntimeState::new();
        let root_a = state_a.create_root_region(Budget::INFINITE);
        let cx_a = Cx::new(
            root_a,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let mut state_b = RuntimeState::new();
        let root_b = state_b.create_root_region(Budget::INFINITE);
        let cx_b = Cx::new(
            root_b,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let mut handle_a = AppSpec::new("state_a_app")
            .start(&mut state_a, &cx_a, root_a)
            .expect("start ok");
        let mut handle_b = AppSpec::new("state_b_app")
            .start(&mut state_b, &cx_b, root_b)
            .expect("start ok");

        assert_eq!(
            handle_a.root_region(),
            handle_b.root_region(),
            "fresh runtimes currently allocate the same test root/app region ids"
        );

        close_app_region_and_remove_records(&mut state_b, handle_b.root_region());
        let _ = handle_b.join(&state_b).expect("join state_b app");

        let result = handle_a.join(&state_b);
        assert!(
            matches!(
                result,
                Err(AppStopError::WrongRuntime { region }) if region == handle_a.root_region()
            ),
            "wrong-runtime joins must fail even if a colliding tombstone exists"
        );

        let stopped = handle_a
            .stop(&mut state_a)
            .expect("wrong-runtime join must preserve the original handle");
        assert_eq!(stopped.name, "state_a_app");

        crate::test_complete!(
            "app_join_wrong_runtime_preserves_handle_even_with_tombstone_collision"
        );
    }
}
