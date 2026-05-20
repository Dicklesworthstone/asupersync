//! ATP daemon supervision topology primitives.
//!
//! These types are pure data used by `atpd` to describe its AppSpec-shaped
//! supervision tree before any runtime state is allocated.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Region that owns one atpd child.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AtpdRegionId(u64);

impl AtpdRegionId {
    /// Construct a region id.
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Return the raw region id.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Stable child roles in the atpd root supervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AtpdChildRole {
    /// Owns local daemon identity, signing keys, and capability roots.
    IdentityManager,
    /// Tracks known peers and authenticated peer metadata.
    PeerDirectory,
    /// Owns path candidates, path selection, and network observation.
    PathManager,
    /// Accepts inbound offers and receive-side grants.
    ReceiveService,
    /// Supervises per-transfer actors.
    TransferSupervisor,
    /// Owns verified cache state and seeding decisions.
    CacheSeeder,
    /// Owns local inbox, encrypted mailbox, and store-and-forward state.
    InboxMailbox,
    /// Exposes local diagnostics and structured health state.
    DiagnosticsEndpoint,
    /// Optional relay role.
    RelayService,
    /// Optional rendezvous role.
    RendezvousService,
}

impl AtpdChildRole {
    /// Stable service name used for name leases and diagnostics.
    #[must_use]
    pub const fn service_name(self) -> &'static str {
        match self {
            Self::IdentityManager => "identity_manager",
            Self::PeerDirectory => "peer_directory",
            Self::PathManager => "path_manager",
            Self::ReceiveService => "receive_service",
            Self::TransferSupervisor => "transfer_supervisor",
            Self::CacheSeeder => "cache_seeder",
            Self::InboxMailbox => "inbox_mailbox",
            Self::DiagnosticsEndpoint => "diagnostics_endpoint",
            Self::RelayService => "relay_service",
            Self::RendezvousService => "rendezvous_service",
        }
    }

    /// Whether this role is optional in the base atpd AppSpec.
    #[must_use]
    pub const fn is_optional(self) -> bool {
        matches!(self, Self::RelayService | Self::RendezvousService)
    }
}

/// Restart policy applied to one atpd child.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtpdRestartPolicy {
    /// A failure escalates to the atpd root supervisor.
    CriticalEscalate,
    /// Restart within a bounded window.
    Restart {
        /// Maximum restarts in the configured window.
        max_restarts: u8,
        /// Restart window in seconds.
        window_secs: u64,
    },
    /// Optional child is disabled after failure.
    DisableOptional,
}

/// Name lease attached to a child at start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtpdNameLease {
    /// Stable service name.
    pub name: &'static str,
    /// Lease is scoped to the daemon root.
    pub root_scoped: bool,
}

/// Stop behavior for one child during daemon shutdown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtpdStopAction {
    /// Stop the child after its dependents have stopped.
    StopChild,
    /// Drain live transfer actors and require resume state for unfinished work.
    DrainTransfers {
        /// Resume state must be durable before shutdown can complete.
        require_resume_state: bool,
    },
    /// Release a daemon-local registry/name lease.
    ReleaseNameLease,
}

/// Child specification in the atpd AppSpec-shaped topology.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtpdChildSpec {
    /// Child role.
    pub role: AtpdChildRole,
    /// Region that owns the child.
    pub region: AtpdRegionId,
    /// Parent region. Must equal the atpd root region.
    pub parent_region: AtpdRegionId,
    /// Dependencies that must start first.
    pub depends_on: Vec<AtpdChildRole>,
    /// Restart policy for this child.
    pub restart: AtpdRestartPolicy,
    /// Name lease acquired at start.
    pub lease: AtpdNameLease,
    /// Stop actions for this child.
    pub stop_actions: Vec<AtpdStopAction>,
}

impl AtpdChildSpec {
    /// Construct a child spec.
    #[must_use]
    pub fn new(
        role: AtpdChildRole,
        region: AtpdRegionId,
        parent_region: AtpdRegionId,
        depends_on: Vec<AtpdChildRole>,
        restart: AtpdRestartPolicy,
        stop_actions: Vec<AtpdStopAction>,
    ) -> Self {
        Self {
            role,
            region,
            parent_region,
            depends_on,
            restart,
            lease: AtpdNameLease {
                name: role.service_name(),
                root_scoped: true,
            },
            stop_actions,
        }
    }
}

/// Validation errors for the atpd topology.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtpdTopologyError {
    /// Child role appeared twice.
    DuplicateRole(AtpdChildRole),
    /// Child region appeared twice.
    DuplicateRegion(AtpdRegionId),
    /// Child parent does not equal the atpd root.
    DetachedChild {
        /// Child role.
        role: AtpdChildRole,
        /// Observed parent.
        parent: AtpdRegionId,
        /// Expected root.
        expected: AtpdRegionId,
    },
    /// Child dependency is missing from the topology.
    MissingDependency {
        /// Child role.
        role: AtpdChildRole,
        /// Missing dependency role.
        dependency: AtpdChildRole,
    },
    /// Required role is absent.
    MissingRequiredRole(AtpdChildRole),
    /// Topology contains a dependency cycle.
    DependencyCycle,
    /// Transfer supervisor is missing drain/resume stop behavior.
    TransferDrainMissing,
}

impl fmt::Display for AtpdTopologyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateRole(role) => write!(f, "duplicate atpd role {role:?}"),
            Self::DuplicateRegion(region) => write!(f, "duplicate atpd region {}", region.get()),
            Self::DetachedChild {
                role,
                parent,
                expected,
            } => write!(
                f,
                "atpd child {role:?} is parented by {}, expected {}",
                parent.get(),
                expected.get()
            ),
            Self::MissingDependency { role, dependency } => {
                write!(f, "atpd child {role:?} depends on missing {dependency:?}")
            }
            Self::MissingRequiredRole(role) => write!(f, "missing required atpd role {role:?}"),
            Self::DependencyCycle => f.write_str("atpd dependency cycle"),
            Self::TransferDrainMissing => {
                f.write_str("transfer supervisor must drain or persist resume state")
            }
        }
    }
}

impl std::error::Error for AtpdTopologyError {}

/// Pure topology used to compile deterministic start/stop plans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtpdTopology {
    /// Root supervisor region.
    pub root_region: AtpdRegionId,
    /// Child specs in declaration order.
    pub children: Vec<AtpdChildSpec>,
}

impl AtpdTopology {
    /// Required daemon roles.
    pub const REQUIRED_ROLES: [AtpdChildRole; 8] = [
        AtpdChildRole::IdentityManager,
        AtpdChildRole::PeerDirectory,
        AtpdChildRole::PathManager,
        AtpdChildRole::ReceiveService,
        AtpdChildRole::TransferSupervisor,
        AtpdChildRole::CacheSeeder,
        AtpdChildRole::InboxMailbox,
        AtpdChildRole::DiagnosticsEndpoint,
    ];

    /// Validate topology invariants.
    pub fn validate(&self) -> Result<(), AtpdTopologyError> {
        let mut roles = BTreeSet::new();
        let mut regions = BTreeSet::new();
        for child in &self.children {
            if !roles.insert(child.role) {
                return Err(AtpdTopologyError::DuplicateRole(child.role));
            }
            if !regions.insert(child.region) {
                return Err(AtpdTopologyError::DuplicateRegion(child.region));
            }
            if child.parent_region != self.root_region {
                return Err(AtpdTopologyError::DetachedChild {
                    role: child.role,
                    parent: child.parent_region,
                    expected: self.root_region,
                });
            }
        }

        for required in Self::REQUIRED_ROLES {
            if !roles.contains(&required) {
                return Err(AtpdTopologyError::MissingRequiredRole(required));
            }
        }

        for child in &self.children {
            for dependency in &child.depends_on {
                if !roles.contains(dependency) {
                    return Err(AtpdTopologyError::MissingDependency {
                        role: child.role,
                        dependency: *dependency,
                    });
                }
            }
        }

        let transfer = self
            .children
            .iter()
            .find(|child| child.role == AtpdChildRole::TransferSupervisor)
            .expect("required role already checked");
        if !transfer
            .stop_actions
            .iter()
            .any(|action| matches!(action, AtpdStopAction::DrainTransfers { .. }))
        {
            return Err(AtpdTopologyError::TransferDrainMissing);
        }

        self.start_order().map(|_| ())
    }

    /// Compute deterministic dependency-respecting start order.
    pub fn start_order(&self) -> Result<Vec<AtpdChildRole>, AtpdTopologyError> {
        let children: BTreeMap<AtpdChildRole, &AtpdChildSpec> = self
            .children
            .iter()
            .map(|child| (child.role, child))
            .collect();
        let mut started = BTreeSet::new();
        let mut order = Vec::with_capacity(self.children.len());

        while order.len() < self.children.len() {
            let before = order.len();
            for child in &self.children {
                if started.contains(&child.role) {
                    continue;
                }
                if child
                    .depends_on
                    .iter()
                    .all(|dependency| started.contains(dependency))
                {
                    if !children.contains_key(&child.role) {
                        return Err(AtpdTopologyError::MissingRequiredRole(child.role));
                    }
                    started.insert(child.role);
                    order.push(child.role);
                }
            }
            if before == order.len() {
                return Err(AtpdTopologyError::DependencyCycle);
            }
        }

        Ok(order)
    }

    /// Deterministic stop order: dependents stop before dependencies.
    pub fn stop_order(&self) -> Result<Vec<AtpdChildRole>, AtpdTopologyError> {
        let mut order = self.start_order()?;
        order.reverse();
        Ok(order)
    }

    /// Return true if every child is rooted under the daemon root region.
    #[must_use]
    pub fn no_detached_children(&self) -> bool {
        self.children
            .iter()
            .all(|child| child.parent_region == self.root_region)
    }
}
