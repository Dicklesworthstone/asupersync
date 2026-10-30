//! Coalesced observations of the independently authenticated membership policy.

use super::{
    MembershipControlError, MembershipStamp, OwnedMembershipController, OwnedMembershipError,
};
use crate::remote::NodeId;

/// Latest accepted state of one provisioned member, including controller closure.
///
/// This is an observation, not a lease, live-contact proof, route or transport
/// grant. Storage is one current stamp and one retained Alive transition per
/// provisioned member. Intermediate statements may coalesce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct OwnedMembershipObservation {
    /// Last authenticated statement; None means no statement has been accepted.
    pub stamp: Option<MembershipStamp>,
    /// Most recent authenticated transition into Alive: first admission,
    /// recovery from another state, or a strictly newer Alive incarnation.
    ///
    /// Higher-sequence Alive heartbeats preserve this stamp. It remains visible
    /// through a later loss, so check the current stamp before acting on it.
    /// This preserves a rapid Alive -> Suspect -> Alive recovery even when a
    /// reader does not poll between those statements.
    pub last_alive_transition: Option<MembershipStamp>,
    /// Terminal controller closure. Retained stamps convey no ongoing authority.
    pub closed: bool,
}

/// Fixed-member observation access with no task, socket, lease or grant.
///
/// Clones and simultaneous waiters are caller-owned resources. Observers do not
/// keep controller admission open and cannot prevent its explicit closure.
#[derive(Clone)]
pub struct OwnedMembershipObserver {
    controller: OwnedMembershipController,
    node: NodeId,
}

impl std::fmt::Debug for OwnedMembershipObserver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedMembershipObserver")
            .field("node", &self.node)
            .field("observation", &self.snapshot())
            .finish()
    }
}

impl OwnedMembershipController {
    /// Observe one provisioned member without granting authority or creating work.
    ///
    /// Unknown members are refused even before the first authenticated statement.
    /// A closed controller remains observable and immediately reports closure.
    pub fn observe_member(
        &self,
        node: &NodeId,
    ) -> Result<OwnedMembershipObserver, OwnedMembershipError> {
        if self.shared.state.lock().policy.observation(node).is_none() {
            return Err(MembershipControlError::UnknownMember.into());
        }
        Ok(OwnedMembershipObserver { controller: self.clone(), node: node.clone() })
    }
}

impl OwnedMembershipObserver {
    /// Provisioned logical member, never a newly discovered transport destination.
    #[must_use]
    pub fn node(&self) -> &NodeId {
        &self.node
    }

    /// Read one coherent current-state/recovery/closure snapshot.
    #[must_use]
    pub fn snapshot(&self) -> OwnedMembershipObservation {
        let state = self.controller.shared.state.lock();
        let (stamp, last_alive_transition) = state.policy.observation(&self.node)
            .expect("an observed provisioned member cannot be removed");
        OwnedMembershipObservation { stamp, last_alive_transition, closed: state.closed }
    }

    /// Wait for a changed snapshot or terminal controller closure.
    ///
    /// The predicate-aware notification wait closes the snapshot-to-registration
    /// race. Dropping this future unregisters its waiter and leaves membership
    /// unchanged. The calling task supplies cancellation and deadlines.
    pub async fn changed(&self, after: OwnedMembershipObservation) -> OwnedMembershipObservation {
        self.controller.shared.changed.wait_until(|| {
            let current = self.snapshot();
            current.closed || current != after
        }).await;
        self.snapshot()
    }
}
