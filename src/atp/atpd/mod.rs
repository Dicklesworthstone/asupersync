//! atpd AppSpec supervision tree contract.
//!
//! `AtpdAppSpec` is a pure-data description of the daemon root application.
//! It mirrors the project `AppSpec` lifecycle: construct, compile, start in a
//! root region, drain, stop, and join. Runtime wiring can consume this contract
//! without inventing a second daemon topology.

pub mod state;

use super::supervision::{
    AtpdChildRole, AtpdChildSpec, AtpdRegionId, AtpdRestartPolicy, AtpdStopAction, AtpdTopology,
    AtpdTopologyError,
};
use std::fmt;

#[allow(unused_imports)]
pub use state::{
    ATPD_STATE_SCHEMA_VERSION, AtpdExportMode, AtpdIntegrityReport, AtpdPersistentState,
    AtpdQuotaMismatch, AtpdSchemaVersion, AtpdStateCollection, AtpdStateError, AtpdStateExport,
    AtpdStateRecord, AtpdStateSettings, StateExportPolicy, StateSensitivity, required_collections,
};

/// Lifecycle phases for the daemon root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtpdLifecyclePhase {
    /// AppSpec data has been constructed but not compiled.
    Constructed,
    /// Topology has been validated and ordered.
    Compiled,
    /// Root region is starting children in compiled order.
    Starting,
    /// All eager children are running.
    Running,
    /// Shutdown requested; transfers are draining or persisting resume state.
    Draining,
    /// All children stopped and name leases released.
    Stopped,
    /// Startup or shutdown failed.
    Failed,
}

/// atpd root AppSpec declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtpdAppSpec {
    /// AppSpec name.
    pub name: &'static str,
    /// Root supervisor region.
    pub root_region: AtpdRegionId,
    /// Child declarations.
    pub children: Vec<AtpdChildSpec>,
}

impl AtpdAppSpec {
    /// Build the default always-on atpd AppSpec.
    #[must_use]
    pub fn default_daemon(root_region: AtpdRegionId) -> Self {
        let mut next_region = root_region.get() + 1;
        let mut next = || {
            let region = AtpdRegionId::new(next_region);
            next_region += 1;
            region
        };

        let children = vec![
            AtpdChildSpec::new(
                AtpdChildRole::IdentityManager,
                next(),
                root_region,
                vec![],
                AtpdRestartPolicy::CriticalEscalate,
                vec![AtpdStopAction::ReleaseNameLease, AtpdStopAction::StopChild],
            ),
            AtpdChildSpec::new(
                AtpdChildRole::PeerDirectory,
                next(),
                root_region,
                vec![AtpdChildRole::IdentityManager],
                AtpdRestartPolicy::Restart {
                    max_restarts: 5,
                    window_secs: 60,
                },
                vec![AtpdStopAction::ReleaseNameLease, AtpdStopAction::StopChild],
            ),
            AtpdChildSpec::new(
                AtpdChildRole::PathManager,
                next(),
                root_region,
                vec![AtpdChildRole::IdentityManager, AtpdChildRole::PeerDirectory],
                AtpdRestartPolicy::Restart {
                    max_restarts: 5,
                    window_secs: 60,
                },
                vec![AtpdStopAction::ReleaseNameLease, AtpdStopAction::StopChild],
            ),
            AtpdChildSpec::new(
                AtpdChildRole::ReceiveService,
                next(),
                root_region,
                vec![AtpdChildRole::IdentityManager, AtpdChildRole::PathManager],
                AtpdRestartPolicy::Restart {
                    max_restarts: 3,
                    window_secs: 60,
                },
                vec![AtpdStopAction::ReleaseNameLease, AtpdStopAction::StopChild],
            ),
            AtpdChildSpec::new(
                AtpdChildRole::TransferSupervisor,
                next(),
                root_region,
                vec![
                    AtpdChildRole::IdentityManager,
                    AtpdChildRole::PathManager,
                    AtpdChildRole::ReceiveService,
                ],
                AtpdRestartPolicy::Restart {
                    max_restarts: 3,
                    window_secs: 60,
                },
                vec![
                    AtpdStopAction::DrainTransfers {
                        require_resume_state: true,
                    },
                    AtpdStopAction::ReleaseNameLease,
                    AtpdStopAction::StopChild,
                ],
            ),
            AtpdChildSpec::new(
                AtpdChildRole::CacheSeeder,
                next(),
                root_region,
                vec![AtpdChildRole::TransferSupervisor],
                AtpdRestartPolicy::Restart {
                    max_restarts: 3,
                    window_secs: 60,
                },
                vec![AtpdStopAction::ReleaseNameLease, AtpdStopAction::StopChild],
            ),
            AtpdChildSpec::new(
                AtpdChildRole::InboxMailbox,
                next(),
                root_region,
                vec![AtpdChildRole::IdentityManager, AtpdChildRole::PeerDirectory],
                AtpdRestartPolicy::Restart {
                    max_restarts: 3,
                    window_secs: 60,
                },
                vec![AtpdStopAction::ReleaseNameLease, AtpdStopAction::StopChild],
            ),
            AtpdChildSpec::new(
                AtpdChildRole::DiagnosticsEndpoint,
                next(),
                root_region,
                vec![
                    AtpdChildRole::IdentityManager,
                    AtpdChildRole::PeerDirectory,
                    AtpdChildRole::PathManager,
                    AtpdChildRole::TransferSupervisor,
                    AtpdChildRole::InboxMailbox,
                ],
                AtpdRestartPolicy::DisableOptional,
                vec![AtpdStopAction::ReleaseNameLease, AtpdStopAction::StopChild],
            ),
        ];

        Self {
            name: "atpd",
            root_region,
            children,
        }
    }

    /// Add the optional relay role.
    #[must_use]
    pub fn with_relay(mut self) -> Self {
        let region = self.next_available_region();
        self.children.push(AtpdChildSpec::new(
            AtpdChildRole::RelayService,
            region,
            self.root_region,
            vec![AtpdChildRole::IdentityManager, AtpdChildRole::PathManager],
            AtpdRestartPolicy::DisableOptional,
            vec![AtpdStopAction::ReleaseNameLease, AtpdStopAction::StopChild],
        ));
        self
    }

    /// Add the optional rendezvous role.
    #[must_use]
    pub fn with_rendezvous(mut self) -> Self {
        let region = self.next_available_region();
        self.children.push(AtpdChildSpec::new(
            AtpdChildRole::RendezvousService,
            region,
            self.root_region,
            vec![AtpdChildRole::IdentityManager, AtpdChildRole::PeerDirectory],
            AtpdRestartPolicy::DisableOptional,
            vec![AtpdStopAction::ReleaseNameLease, AtpdStopAction::StopChild],
        ));
        self
    }

    /// Compile the AppSpec-shaped daemon topology.
    pub fn compile(self) -> Result<CompiledAtpdAppSpec, AtpdTopologyError> {
        let topology = AtpdTopology {
            root_region: self.root_region,
            children: self.children,
        };
        topology.validate()?;
        let start_order = topology.start_order()?;
        let stop_order = topology.stop_order()?;
        Ok(CompiledAtpdAppSpec {
            name: self.name,
            topology,
            start_order,
            stop_order,
            lifecycle: AtpdLifecyclePhase::Compiled,
        })
    }

    fn next_available_region(&self) -> AtpdRegionId {
        let max_region = self
            .children
            .iter()
            .map(|child| child.region.get())
            .max()
            .unwrap_or(self.root_region.get());
        AtpdRegionId::new(max_region + 1)
    }
}

/// Compiled atpd AppSpec with deterministic lifecycle plans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledAtpdAppSpec {
    /// AppSpec name.
    pub name: &'static str,
    /// Validated topology.
    pub topology: AtpdTopology,
    /// Deterministic start order.
    pub start_order: Vec<AtpdChildRole>,
    /// Deterministic stop order.
    pub stop_order: Vec<AtpdChildRole>,
    /// Current lifecycle phase for plan-level tests.
    pub lifecycle: AtpdLifecyclePhase,
}

impl CompiledAtpdAppSpec {
    /// Produce the start events that runtime wiring must emit in order.
    #[must_use]
    pub fn start_events(&self) -> Vec<AtpdLifecycleEvent> {
        self.start_order
            .iter()
            .copied()
            .map(|role| AtpdLifecycleEvent {
                phase: AtpdLifecyclePhase::Starting,
                role: Some(role),
                action: AtpdLifecycleAction::StartChild,
            })
            .collect()
    }

    /// Produce shutdown events: drain transfers, release leases, stop children.
    #[must_use]
    pub fn shutdown_events(&self) -> Vec<AtpdLifecycleEvent> {
        let mut events = Vec::new();
        for role in &self.stop_order {
            let child = self
                .topology
                .children
                .iter()
                .find(|child| child.role == *role)
                .expect("compiled stop order only contains known children");
            for action in &child.stop_actions {
                events.push(AtpdLifecycleEvent {
                    phase: AtpdLifecyclePhase::Draining,
                    role: Some(*role),
                    action: AtpdLifecycleAction::from(action),
                });
            }
        }
        events.push(AtpdLifecycleEvent {
            phase: AtpdLifecyclePhase::Stopped,
            role: None,
            action: AtpdLifecycleAction::JoinRoot,
        });
        events
    }

    /// Return the restart policy for a child role.
    #[must_use]
    pub fn restart_policy(&self, role: AtpdChildRole) -> Option<AtpdRestartPolicy> {
        self.topology
            .children
            .iter()
            .find(|child| child.role == role)
            .map(|child| child.restart)
    }

    /// Verify every child has a root-scoped name lease.
    #[must_use]
    pub fn has_root_scoped_name_leases(&self) -> bool {
        self.topology
            .children
            .iter()
            .all(|child| child.lease.root_scoped && child.lease.name == child.role.service_name())
    }

    /// Verify shutdown stops every child and joins the root.
    #[must_use]
    pub fn shutdown_covers_every_child(&self) -> bool {
        self.stop_order.len() == self.topology.children.len()
            && self
                .topology
                .children
                .iter()
                .all(|child| self.stop_order.contains(&child.role))
            && self
                .shutdown_events()
                .iter()
                .any(|event| event.action == AtpdLifecycleAction::JoinRoot)
    }
}

/// A deterministic lifecycle event for logs/tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AtpdLifecycleEvent {
    /// Daemon phase.
    pub phase: AtpdLifecyclePhase,
    /// Child role, if the event targets a child.
    pub role: Option<AtpdChildRole>,
    /// Action performed in that phase.
    pub action: AtpdLifecycleAction,
}

/// Lifecycle actions emitted by the plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtpdLifecycleAction {
    /// Start one child.
    StartChild,
    /// Drain transfer actors and require resume state.
    DrainTransfers,
    /// Release a name lease.
    ReleaseNameLease,
    /// Stop one child.
    StopChild,
    /// Join the root AppSpec handle.
    JoinRoot,
}

impl From<&AtpdStopAction> for AtpdLifecycleAction {
    fn from(value: &AtpdStopAction) -> Self {
        match value {
            AtpdStopAction::StopChild => Self::StopChild,
            AtpdStopAction::DrainTransfers { .. } => Self::DrainTransfers,
            AtpdStopAction::ReleaseNameLease => Self::ReleaseNameLease,
        }
    }
}

impl fmt::Display for AtpdLifecycleAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::StartChild => "start_child",
            Self::DrainTransfers => "drain_transfers",
            Self::ReleaseNameLease => "release_name_lease",
            Self::StopChild => "stop_child",
            Self::JoinRoot => "join_root",
        })
    }
}
