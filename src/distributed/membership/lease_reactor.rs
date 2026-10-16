//! Suspicion → obligation-revocation mapping for the lease manager (bead
//! `asupersync-dist-otp-completeness-8y37kz.4.3`; the parent's novel
//! contribution).
//!
//! # Design note: SWIM suspicion mapped onto the obligation model
//!
//! Failure detection drives lease lifecycle *without inventing a new failure
//! path*. A node's SWIM membership state maps directly onto what the lease
//! manager should do with the leases granted to it:
//!
//! | Membership kind | Lease action |
//! |-----------------|--------------|
//! | `Alive`   | [`LeaseAction::Resume`] — grant and hold leases normally. |
//! | `Suspect` | [`LeaseAction::PauseGrants`] — stop issuing *new* grants; existing obligations are not yet discharged (a refutation can still rescue them). |
//! | `Dead` / `Left` | [`LeaseAction::Revoke`] — revoke the node's leases through the **normal** obligation protocol (commit/abort). The abort runs no compensation by itself; the lease owner runs any cleanup, such as a saga step's compensation. |
//!
//! Because `Dead`/`Left` revoke via the existing obligation discharge path, no
//! novel "node died" failure path is required — death is just another reason an
//! obligation is aborted, and the structured-concurrency leak invariants (no
//! obligation leaks) continue to hold.
//!
//! This module owns the *decision* layer only: it consumes the watchable
//! membership stream ([`MembershipView`]) and emits per-node lease actions. The
//! `remote.rs` lease manager subscribes by calling [`MembershipLeaseReactor::poll`]
//! and *enacts* each action (pause grants / revoke via obligations / resume).
//! Keeping the decision pure makes the suspicion→revocation mapping exhaustively
//! testable without the lease manager or the obligation runtime.

use super::swim::MembershipKind;
use super::view::MembershipView;
use crate::remote::NodeId;
use std::collections::BTreeSet;

/// The lease action a membership transition implies for a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseAction {
    /// The node is healthy: resume normal lease granting.
    Resume,
    /// The node is suspected: pause issuing *new* lease grants to it (a
    /// refutation may still rescue its existing leases).
    PauseGrants,
    /// The node is confirmed dead/left: revoke its leases through the obligation
    /// protocol (the lease owner runs any compensation; aborting runs none).
    Revoke,
}

/// The lease action implied by a membership kind.
#[must_use]
pub fn lease_action_for(kind: MembershipKind) -> LeaseAction {
    match kind {
        MembershipKind::Alive => LeaseAction::Resume,
        MembershipKind::Suspect => LeaseAction::PauseGrants,
        MembershipKind::Dead | MembershipKind::Left => LeaseAction::Revoke,
    }
}

/// Turns a watchable membership stream into idempotent lease actions for the
/// lease manager to enact.
///
/// Tracks a cursor over the [`MembershipView`] event log plus the set of nodes
/// currently paused / revoked, so repeated transitions do not re-emit redundant
/// actions. Revocation is **terminal**: once a node is revoked it is never
/// resumed (death is final; a rejoining node arrives as a fresh member /
/// incarnation).
#[derive(Debug, Clone, Default)]
pub struct MembershipLeaseReactor {
    cursor: usize,
    paused: BTreeSet<NodeId>,
    revoked: BTreeSet<NodeId>,
}

impl MembershipLeaseReactor {
    /// A reactor with no observed history.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Consumes membership events appended since the last poll and returns the
    /// `(node, action)` pairs the lease manager should enact, in stream order.
    ///
    /// If the view compacted events this reactor had not seen yet, they are
    /// gone: the reactor then reconciles from the current snapshot instead, in
    /// node id order. A node ever seen `Dead` or `Left` is revoked even if it
    /// has since rejoined under the same id, as it would have been had the
    /// reactor seen the events.
    pub fn poll(&mut self, view: &MembershipView) -> Vec<(NodeId, LeaseAction)> {
        let mut actions = Vec::new();
        if self.cursor < view.compact_base() {
            for (node, kind) in view.members() {
                let action = if view.has_departed(node) {
                    LeaseAction::Revoke
                } else {
                    lease_action_for(kind)
                };
                self.enact(node, action, &mut actions);
            }
        } else {
            for event in view.events_since(self.cursor) {
                self.enact(&event.node, lease_action_for(event.kind), &mut actions);
            }
        }
        self.cursor = view.event_count();
        actions
    }

    fn enact(
        &mut self,
        node: &NodeId,
        action: LeaseAction,
        actions: &mut Vec<(NodeId, LeaseAction)>,
    ) {
        if self.revoked.contains(node) {
            return; // terminal: ignore anything after revocation
        }
        match action {
            LeaseAction::Revoke => {
                self.revoked.insert(node.clone());
                self.paused.remove(node);
                actions.push((node.clone(), LeaseAction::Revoke));
            }
            LeaseAction::PauseGrants => {
                if self.paused.insert(node.clone()) {
                    actions.push((node.clone(), LeaseAction::PauseGrants));
                }
            }
            LeaseAction::Resume => {
                if self.paused.remove(node) {
                    actions.push((node.clone(), LeaseAction::Resume));
                }
            }
        }
    }

    /// Whether new grants to `node` are currently paused (suspected).
    #[must_use]
    pub fn is_paused(&self, node: &NodeId) -> bool {
        self.paused.contains(node)
    }

    /// Whether `node`'s leases have been revoked (confirmed dead/left).
    #[must_use]
    pub fn is_revoked(&self, node: &NodeId) -> bool {
        self.revoked.contains(node)
    }
}

#[cfg(test)]
#[path = "lease_reactor_inline_tests.rs"]
mod tests;
