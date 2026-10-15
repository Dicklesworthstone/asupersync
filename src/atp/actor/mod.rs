//! ATP transfer actor ownership topology.
//!
//! These types describe the region-owned actor tree for one ATP transfer. The
//! model is intentionally data-only: daemon, relay, mailbox, and SDK code can
//! build on it without introducing shared mutable transfer maps or detached
//! background work.

use std::collections::BTreeSet;
use std::fmt;

/// Stable id for the single actor that owns one transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TransferActorId(u64);

impl TransferActorId {
    /// Construct an actor id.
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Return the raw actor id.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Stable id for a transfer-owned region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TransferRegionId(u64);

impl TransferRegionId {
    /// Construct a transfer region id.
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

/// Stable obligation id for calls that require a reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TransferObligationId(u64);

impl TransferObligationId {
    /// Construct an obligation id.
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Return the raw obligation id.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Role of a transfer child region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TransferChildRole {
    /// Path race and candidate probing.
    PathRace,
    /// Quarantine writer and commit finalizer.
    Writer,
    /// Repair-symbol decode or encode work.
    Repair,
    /// Online relay forwarding.
    Relay,
    /// Store-and-forward encrypted mailbox.
    Mailbox,
    /// Multi-source peer-assisted transfer.
    Swarm,
    /// Bounded shutdown/finalizer lane.
    Finalizer,
}

impl TransferChildRole {
    /// Stable machine-readable role code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::PathRace => "path_race",
            Self::Writer => "writer",
            Self::Repair => "repair",
            Self::Relay => "relay",
            Self::Mailbox => "mailbox",
            Self::Swarm => "swarm",
            Self::Finalizer => "finalizer",
        }
    }
}

/// A child region owned by the transfer actor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferChildRegion {
    /// Child region id.
    pub id: TransferRegionId,
    /// Parent region id. Must be the actor region.
    pub parent: TransferRegionId,
    /// Child role.
    pub role: TransferChildRole,
}

impl TransferChildRegion {
    /// Construct a transfer child region record.
    #[must_use]
    pub const fn new(
        id: TransferRegionId,
        parent: TransferRegionId,
        role: TransferChildRole,
    ) -> Self {
        Self { id, parent, role }
    }
}

/// Region ownership topology for one transfer actor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferActorTopology {
    /// Parent region that supervises this transfer actor.
    pub supervisor_region: TransferRegionId,
    /// Region that owns the actor state machine.
    pub actor_region: TransferRegionId,
    /// Child regions spawned by the actor for bounded transfer work.
    pub child_regions: Vec<TransferChildRegion>,
}

impl TransferActorTopology {
    /// Construct an actor topology without child regions.
    #[must_use]
    pub const fn new(supervisor_region: TransferRegionId, actor_region: TransferRegionId) -> Self {
        Self {
            supervisor_region,
            actor_region,
            child_regions: Vec::new(),
        }
    }

    /// Add a child region to the topology.
    #[must_use]
    pub fn with_child(mut self, id: TransferRegionId, role: TransferChildRole) -> Self {
        self.child_regions
            .push(TransferChildRegion::new(id, self.actor_region, role));
        self
    }

    /// Validate that every transfer child is owned by the actor region.
    pub fn validate(&self) -> Result<(), TransferTopologyError> {
        if self.supervisor_region == self.actor_region {
            return Err(TransferTopologyError::ActorRegionEqualsSupervisor {
                region: self.actor_region,
            });
        }

        let mut seen = BTreeSet::new();
        for child in &self.child_regions {
            if child.id == self.supervisor_region || child.id == self.actor_region {
                return Err(TransferTopologyError::ChildRegionAliasesOwner { child: child.id });
            }
            if child.parent != self.actor_region {
                return Err(TransferTopologyError::DetachedChild {
                    child: child.id,
                    parent: child.parent,
                    expected_parent: self.actor_region,
                });
            }
            if !seen.insert(child.id) {
                return Err(TransferTopologyError::DuplicateChild { child: child.id });
            }
        }

        Ok(())
    }

    /// Whether the topology contains any detached child region.
    #[must_use]
    pub fn has_detached_child(&self) -> bool {
        self.child_regions
            .iter()
            .any(|child| child.parent != self.actor_region)
    }
}

/// Topology validation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferTopologyError {
    /// Actor region must be a child of, not equal to, the supervisor region.
    ActorRegionEqualsSupervisor {
        /// Aliased region id.
        region: TransferRegionId,
    },
    /// Child region id aliases the actor or supervisor owner.
    ChildRegionAliasesOwner {
        /// Aliased child region id.
        child: TransferRegionId,
    },
    /// Child region is not parented by the actor region.
    DetachedChild {
        /// Child region id.
        child: TransferRegionId,
        /// Observed parent region id.
        parent: TransferRegionId,
        /// Required actor-region parent id.
        expected_parent: TransferRegionId,
    },
    /// Child region appears more than once.
    DuplicateChild {
        /// Duplicate child region id.
        child: TransferRegionId,
    },
}

impl fmt::Display for TransferTopologyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ActorRegionEqualsSupervisor { region } => {
                write!(f, "actor region {} equals supervisor region", region.get())
            }
            Self::ChildRegionAliasesOwner { child } => {
                write!(f, "child region {} aliases a topology owner", child.get())
            }
            Self::DetachedChild {
                child,
                parent,
                expected_parent,
            } => write!(
                f,
                "child region {} is parented by {}, expected {}",
                child.get(),
                parent.get(),
                expected_parent.get()
            ),
            Self::DuplicateChild { child } => {
                write!(f, "duplicate child region {}", child.get())
            }
        }
    }
}

impl std::error::Error for TransferTopologyError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topology_accepts_actor_owned_children() {
        let topology =
            TransferActorTopology::new(TransferRegionId::new(1), TransferRegionId::new(2))
                .with_child(TransferRegionId::new(3), TransferChildRole::PathRace)
                .with_child(TransferRegionId::new(4), TransferChildRole::Writer);

        assert!(topology.validate().is_ok());
        assert!(!topology.has_detached_child());
    }

    #[test]
    fn topology_rejects_detached_children() {
        let mut topology =
            TransferActorTopology::new(TransferRegionId::new(1), TransferRegionId::new(2));
        topology.child_regions.push(TransferChildRegion::new(
            TransferRegionId::new(3),
            TransferRegionId::new(99),
            TransferChildRole::Relay,
        ));

        assert!(matches!(
            topology.validate(),
            Err(TransferTopologyError::DetachedChild { .. })
        ));
        assert!(topology.has_detached_child());
    }
}
