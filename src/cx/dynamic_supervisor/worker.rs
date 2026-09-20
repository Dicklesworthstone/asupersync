//! Direct worker factories over the existing executing managed controller.

use super::{DynamicChildId, DynamicSupervisor, DynamicSupervisorError};
use crate::cx::{Cx, Scope};
use crate::runtime::{RuntimeState, SpawnError};
use crate::supervision::{
    ChildName, ChildSpec, ChildStart, ManagedChildBinding, ManagedChildFactory,
    ManagedRestartMode, ManagedSupervisorBindError, SupervisionConfig, SupervisorBuilder,
};
use crate::types::{Budget, TaskId, policy::FailFast};

/// Explicit restart and budget policy for one dynamically admitted worker.
///
/// A retained factory is called again only by the real managed controller, after
/// the preceding generation and its region finalizers have drained. The factory
/// receives that generation's actual task Cx and generational task/region IDs.
/// Restart counters are per dynamic child, not reset when another child starts.
#[derive(Debug, Clone)]
pub struct DynamicWorkerConfig {
    /// Permanent, transient or temporary eligibility under the managed contract.
    pub restart_mode: ManagedRestartMode,
    /// Existing restart intensity, backoff, escalation and storm policy.
    /// The policy is preserved; with a single worker the three sibling strategies
    /// all select that worker, never other dynamic children.
    pub supervision: SupervisionConfig,
    /// Optional worker-controller region envelope, met with parent authority.
    pub budget: Option<Budget>,
    /// Existing generation shutdown budget; never an arbitrary-future deadline.
    pub shutdown_budget: Budget,
}

impl DynamicWorkerConfig {
    /// Retain explicit restart policy and inherit the parent budget by default.
    #[must_use]
    pub fn new(restart_mode: ManagedRestartMode, supervision: SupervisionConfig) -> Self {
        Self {
            restart_mode,
            supervision,
            budget: None,
            shutdown_budget: Budget::INFINITE,
        }
    }

    /// Request a stricter controller/worker budget without relaxing the parent's.
    #[must_use]
    pub fn with_budget(mut self, budget: Budget) -> Self {
        self.budget = Some(budget);
        self
    }

    /// Set the budget used by the existing managed generation-drain protocol.
    #[must_use]
    pub fn with_shutdown_budget(mut self, budget: Budget) -> Self {
        self.shutdown_budget = budget;
        self
    }
}

// ChildSpec's legacy slot is required by the topology compiler. This private
// specification is immediately consumed by bind_managed, which owns the actual
// factory separately and never calls ChildStart. It cannot escape via this API.
// Refuse a mistaken legacy invocation instead of inventing a successful TaskId.
struct ManagedOnly;

impl ChildStart for ManagedOnly {
    fn start(
        &mut self,
        _scope: &Scope<'static, FailFast>,
        _state: &mut RuntimeState,
        _cx: &Cx,
    ) -> Result<TaskId, SpawnError> {
        Err(SpawnError::RuntimeUnavailable)
    }
}

impl<E: Send + 'static> DynamicSupervisor<E> {
    /// Admit a directly supplied worker factory with real generation restarts.
    ///
    /// No legacy RuntimeState callback, placeholder task or detached execution
    /// is required from the caller. Bounds and configuration are checked before
    /// any region admission or factory invocation. The receipt is submission,
    /// not application readiness; terminal output uses the ordinary child APIs.
    pub async fn start_worker(
        &mut self,
        name: impl Into<ChildName>,
        config: DynamicWorkerConfig,
        factory: impl ManagedChildFactory<E>,
    ) -> Result<DynamicChildId, DynamicSupervisorError> {
        let name = name.into();
        self.check_admission(&name)?;
        let mut builder = SupervisorBuilder::new(name.clone())
            .with_restart_policy(config.supervision.restart_policy)
            .child(ChildSpec::new(name.clone(), ManagedOnly)
                .with_shutdown_budget(config.shutdown_budget));
        if let Some(budget) = config.budget {
            builder = builder.with_budget(budget);
        }
        let compiled = builder.compile().map_err(|error| {
            DynamicSupervisorError::WorkerConfiguration(ManagedSupervisorBindError::Topology(error))
        })?;
        let managed = compiled.bind_managed(
            vec![ManagedChildBinding::new(name.clone(), config.restart_mode, factory)],
            config.supervision,
        ).map_err(DynamicSupervisorError::WorkerConfiguration)?;
        self.start_child(name, managed).await
    }
}
