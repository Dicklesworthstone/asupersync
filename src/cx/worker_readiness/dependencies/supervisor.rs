//! Bind the existing supervisor DAG to initialization and live readiness edges.
//!
//! The existing topology compiler and managed controller remain authoritative.
//! This adapter wires their named edges into `WorkerDependencies::run`; it does
//! not create a second scheduler, restart tracker, or mutable graph. It inherits
//! `worker_readiness`'s experimental `test-internals` feature gate.

use super::{DependencyError, DependencyScopeConfig, DependencyScopeError, DependencyScopeReport};
use super::WorkerDependencies;
use super::super::{initialized_worker, notify, WorkerReadiness, WorkerReadinessPhase};
use crate::cx::{Cx, Scope};
use crate::runtime::{RuntimeState, SpawnError};
use crate::supervision::{
    ChildName, ChildSpec, ChildStart, CompiledSupervisor, ManagedChildBinding, ManagedChildFactory, ManagedGeneration,
    ManagedRestartMode, ManagedSupervisor, ManagedSupervisorBindError, SupervisionConfig,
    SupervisorBuilder,
};
use crate::types::{Budget, Outcome, TaskId, policy::FailFast};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::Future;
use std::sync::Arc;

/// Metadata admission bounds, checked before recompilation or edge allocation.
/// Caller-owned names, factories, payloads and live task resources are separate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitializedTopologyLimits {
    /// Maximum children AND supplied bindings. Zero accepts only an empty graph.
    pub max_children: usize,
    /// Maximum declared edges, counting repeated declarations before deduplication.
    pub max_edges: usize,
}

/// Invalid initialized binding; no initializer, run or classifier was invoked.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum InitializedBindError {
    /// Caller-selected metadata ceiling was exceeded.
    #[error("initialized supervisor exceeds its {0} limit")]
    Limit(&'static str),
    /// Original compiler or managed-binding refusal, without weakening validation.
    #[error("initialized supervisor binding: {0:?}")]
    Managed(ManagedSupervisorBindError),
    /// This adapter cannot promise readiness for a child the controller never starts.
    #[error("initialized supervisor cannot bind deferred child {0}")]
    Deferred(ChildName),
    /// Bounded dependency observation could not be constructed.
    #[error("initialized supervisor dependencies: {0}")]
    Dependencies(DependencyError),
}

/// The full result delivered to a child's explicit supervisor-outcome classifier.
/// No application error is cloned, stringified or replaced with a generic retry.
pub type InitializedRunResult<E> = Result<DependencyScopeReport<(), E>, DependencyScopeError>;

type BindFactory<E> = Box<
    dyn FnOnce(WorkerDependencies, Budget) -> ManagedChildBinding<E> + Send,
>;

/// Typed initialization/run pair erased only after their shared state is bound.
///
/// Each entry may use a different resource and work-error type. Its classifier
/// maps the complete post-drain result into the common supervisor error type.
/// That explicit application decision controls existing managed restart modes.
pub struct InitializedChildBinding<E> {
    name: ChildName,
    readiness: WorkerReadiness,
    bind: BindFactory<E>,
}

impl<E> fmt::Debug for InitializedChildBinding<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InitializedChildBinding")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

// A declarative spec must carry the incumbent legacy slot, but this path never
// uses it. Refuse mistaken legacy execution; never manufacture a successful ID.
struct InitializedOnly;

impl ChildStart for InitializedOnly {
    fn start(
        &mut self,
        _: &Scope<'static, FailFast>,
        _: &mut RuntimeState,
        _: &Cx,
    ) -> Result<TaskId, SpawnError> {
        Err(SpawnError::RuntimeUnavailable)
    }
}

// A Temporary factory can remain retained after its only attempt. Withdraw its
// readiness even on classifier panic or abandoned driving future. Never infer
// finality for Transient from its returned outcome: a concurrent controller
// shutdown can select a collateral restart under OneForAll/RestForOne. Only the
// managed controller owns that decision; factory Drop closes reusable views.
struct TerminalReadiness {
    readiness: WorkerReadiness,
    close: bool,
}

impl Drop for TerminalReadiness {
    fn drop(&mut self) {
        if !self.close {
            return;
        }
        {
            let mut state = self.readiness.shared.state.lock();
            state.factory_alive = false;
            if state.snapshot.phase != WorkerReadinessPhase::InvalidGeneration {
                state.snapshot.phase = if state.active {
                    WorkerReadinessPhase::Stopping
                } else {
                    WorkerReadinessPhase::Closed
                };
            }
        }
        notify(&self.readiness.shared);
    }
}

impl<E: Send + 'static> InitializedChildBinding<E> {
    /// Bind one initialize/run handoff and an explicit post-drain classification.
    ///
    /// `classify` receives startup refusal OR the full work/task/close report.
    /// It runs only after `WorkerDependencies::run` returns. Inspect `close`,
    /// cancellation and cleanup as well as the application outcome. Returning
    /// `Err` opts into Transient restart; returning `Ok`/`Cancelled` does not.
    /// Classification panics follow the existing managed panic/restart policy.
    ///
    /// Dependencies gate INITIALIZATION, not merely the subsequent run loop.
    /// The initializer receives the actual inner task/region identity; its
    /// generation number is inherited from the enclosing managed attempt. The
    /// controller's report identifies the outer task, not that inner work task.
    /// Classification follows the close attempt; a failed close does NOT prove
    /// quiescence. The existing managed outer-region barrier gates replacement.
    /// No factory, region or effect is started by constructing this binding.
    pub fn new<R, W, I, IF, U, UF, C>(
        name: impl Into<ChildName>,
        mode: ManagedRestartMode,
        initialize: I,
        run: U,
        classify: C,
    ) -> Self
    where
        R: Send + 'static,
        W: Send + 'static,
        I: Fn(Cx, ManagedGeneration) -> IF + Send + Sync + 'static,
        IF: Future<Output = Outcome<R, W>> + Send + 'static,
        U: Fn(Cx, ManagedGeneration, R) -> UF + Send + Sync + 'static,
        UF: Future<Output = Outcome<(), W>> + Send + 'static,
        C: Fn(InitializedRunResult<W>) -> Outcome<(), E> + Send + Sync + 'static,
    {
        let name = name.into();
        let binding_name = name.clone();
        let (worker, readiness) = initialized_worker(initialize, run);
        let worker = Arc::new(worker);
        let terminal = readiness.clone();
        let classify = Arc::new(classify);
        let bind: BindFactory<E> = Box::new(move |dependencies, shutdown_budget| {
            let factory = move |cx: Cx, generation: ManagedGeneration| {
                let dependencies = dependencies.clone();
                let worker = Arc::clone(&worker);
                let classify = Arc::clone(&classify);
                // Own retirement before the first poll, including cancellation
                // or a notifier panic between factory construction and polling.
                let retirement = TerminalReadiness {
                    readiness: terminal.clone(),
                    close: mode == ManagedRestartMode::Temporary,
                };
                async move {
                    let _terminal = retirement;
                    let result = dependencies.run(
                        &cx,
                        DependencyScopeConfig::new(shutdown_budget),
                        move |inner, _selected| {
                            let identity = ManagedGeneration {
                                number: generation.number,
                                region: inner.region_id(),
                                task: inner.task_id(),
                            };
                            worker.start(inner, identity)
                        },
                    ).await;
                    classify(result)
                }
            };
            ManagedChildBinding::new(binding_name, mode, factory)
        });
        Self { name, readiness, bind }
    }

    /// Observe this binding even before binding/spawning the whole topology.
    /// Dropping this view never requests worker cancellation.
    #[must_use]
    pub fn readiness(&self) -> WorkerReadiness {
        self.readiness.clone()
    }

    /// Produce matching declarative metadata for the existing topology builder.
    /// Add dependencies and shutdown budgets with ordinary `ChildSpec` methods,
    /// then use `CompiledSupervisor::bind_initialized`. This spec intentionally
    /// refuses the legacy `ChildStart` path instead of creating a dummy task.
    #[must_use]
    pub fn spec(&self) -> ChildSpec {
        ChildSpec::new(self.name.clone(), InitializedOnly)
    }
}

/// Named views and one coherent whole-graph startup barrier, not a runtime owner.
/// Snapshot/error indices from `all()` use the lexical order returned by `names()`.
#[derive(Debug, Clone)]
pub struct SupervisorReadiness {
    named: BTreeMap<ChildName, WorkerReadiness>,
    all: WorkerDependencies,
}

impl SupervisorReadiness {
    /// The common all-ready barrier. May become stale immediately after observation.
    #[must_use]
    pub fn all(&self) -> &WorkerDependencies {
        &self.all
    }

    /// Observe a child by its exact compiled name.
    #[must_use]
    pub fn child(&self, name: &str) -> Option<&WorkerReadiness> {
        self.named.get(name)
    }

    /// Stable lexical names corresponding to the whole-graph barrier's indices.
    pub fn names(&self) -> impl ExactSizeIterator<Item = &str> {
        self.named.keys().map(|name| name.as_str())
    }
}

impl CompiledSupervisor {
    /// Bind eager initialized workers to THIS topology's existing dependency DAG.
    ///
    /// Reuse compiler validation, tie-breaks, modes, intensity and restart policy.
    /// A graph edge both gates initialization and invalidates an executing
    /// dependent attempt when its selected prerequisite generation leaves Ready.
    /// No hidden topological loop, detached watcher or new restart tracker exists.
    ///
    /// The returned managed owner uses ordinary `run`/`spawn` and can be admitted
    /// by the existing dynamic supervisor. Keep that owner's join/region barrier;
    /// `SupervisorReadiness` alone neither owns workers nor proves quiescence.
    /// Deferred children are refused explicitly. Repeated declared edges are
    /// counted against the bound, then deduplicated as in the original compiler.
    ///
    /// # Errors
    /// Returns metadata-limit, topology, binding, deferred-child or dependency
    /// allocation errors. Existing managed registration/configuration refusals
    /// remain errors; no validation path invokes application factories.
    pub fn bind_initialized<E: Send + 'static>(
        self,
        bindings: Vec<InitializedChildBinding<E>>,
        config: SupervisionConfig,
        limits: InitializedTopologyLimits,
    ) -> Result<(ManagedSupervisor<E>, SupervisorReadiness), InitializedBindError> {
        if self.children.len() > limits.max_children || bindings.len() > limits.max_children {
            return Err(InitializedBindError::Limit("children"));
        }
        let mut edges = 0usize;
        for child in &self.children {
            edges = edges.checked_add(child.depends_on.len())
                .ok_or(InitializedBindError::Limit("edges"))?;
            if edges > limits.max_edges {
                return Err(InitializedBindError::Limit("edges"));
            }
        }

        // CompiledSupervisor fields are public. Never trust a supplied order or
        // graph after mutation, and never index by it before authoritative compile.
        let supplied_order = self.start_order;
        let mut builder = SupervisorBuilder::new(self.name)
            .with_tie_break(self.tie_break)
            .with_restart_policy(self.restart_policy);
        if let Some(budget) = self.budget {
            builder = builder.with_budget(budget);
        }
        for child in self.children {
            builder = builder.child(child);
        }
        let compiled = builder.compile().map_err(|error| {
            InitializedBindError::Managed(ManagedSupervisorBindError::Topology(error))
        })?;
        if compiled.start_order != supplied_order {
            return Err(InitializedBindError::Managed(ManagedSupervisorBindError::StartOrder));
        }
        let mut by_name = BTreeMap::new();
        for binding in bindings {
            if !compiled.children.iter().any(|child| child.name == binding.name) {
                return Err(InitializedBindError::Managed(ManagedSupervisorBindError::Unknown(binding.name)));
            }
            let name = binding.name.clone();
            if by_name.insert(name.clone(), binding).is_some() {
                return Err(InitializedBindError::Managed(ManagedSupervisorBindError::Duplicate(name)));
            }
        }
        for child in &compiled.children {
            if !child.start_immediately {
                return Err(InitializedBindError::Deferred(child.name.clone()));
            }
            if !by_name.contains_key(&child.name) {
                return Err(InitializedBindError::Managed(ManagedSupervisorBindError::Missing(child.name.clone())));
            }
        }
        let named: BTreeMap<_, _> = by_name.iter()
            .map(|(name, binding)| (name.clone(), binding.readiness.clone())).collect();
        let all = WorkerDependencies::new(named.values().cloned().collect(), limits.max_children)
            .map_err(InitializedBindError::Dependencies)?;
        let mut managed = Vec::with_capacity(compiled.children.len());
        for child in &compiled.children {
            let mut seen = BTreeSet::new();
            let dependencies = child.depends_on.iter().filter(|name| seen.insert(*name))
                .map(|name| named.get(name).expect("compiler validated dependency").clone())
                .collect();
            let dependencies = WorkerDependencies::new(dependencies, limits.max_children)
                .map_err(InitializedBindError::Dependencies)?;
            let binding = by_name.remove(&child.name).expect("all bindings validated");
            managed.push((binding.bind)(dependencies, child.shutdown_budget));
        }
        // The incumbent validates registration policy, restart configuration and
        // its topology again. No user initializer/run/classifier has been invoked.
        let owner = compiled.bind_managed(managed, config).map_err(InitializedBindError::Managed)?;
        Ok((owner, SupervisorReadiness { named, all }))
    }
}

#[cfg(test)]
mod tests;

mod launch;
pub use launch::{
    InitializedExit, InitializedStartCause, InitializedStartConfig, InitializedStartError,
    InitializedSupervisor, RunningInitializedSupervisor,
};
