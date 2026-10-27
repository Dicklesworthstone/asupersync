use super::{MembershipView, SwimDriverError, SwimDriverStats};
use crate::distributed::membership::{MembershipEvent, MembershipKind};
use crate::remote::NodeId;
use crate::sync::Notify;
use parking_lot::Mutex;
use std::collections::BTreeSet;
use std::sync::Arc;

/// Driver lifetime, separate from any peer's observed membership state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwimDriverStatus {
    /// Bound and configured, but no runtime loop has been polled.
    Prepared,
    /// Servicing traffic and protocol maintenance.
    Running,
    /// No new probes are admitted; a local Leave fanout is being sent.
    Leaving,
    /// Every Leave datagram was accepted locally; peer delivery is not proved.
    Left,
    /// Context cancellation stopped the loop without claiming graceful Leave.
    Cancelled,
    /// The loop returned a typed failure; do not treat the view as fresh.
    Failed,
    /// The owner/future was dropped; no graceful protocol completion is claimed.
    Dropped,
}
impl SwimDriverStatus {
    /// Whether no more driver observations will be published.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Left | Self::Cancelled | Self::Failed | Self::Dropped)
    }
}

/// A bounded, point-in-time failure-detector view, NOT an authority decision.
#[derive(Debug, Clone)]
pub struct SwimObservation {
    /// Monotone publication version; changes may coalesce between observations.
    pub revision: u64,
    /// Source driver lifetime. Terminal views must not be treated as live probes.
    pub status: SwimDriverStatus,
    /// Current peer states and a bounded suffix of membership transitions.
    /// Check `compact_base()` against your event cursor before consuming a tail.
    /// Lag requires snapshot reconciliation, not silently skipping revocations.
    pub membership: MembershipView,
    /// Actual local packet/queue counters; kernel acceptance is not delivery.
    pub stats: SwimDriverStats,
}

pub(super) struct ObservationState {
    state: Mutex<ObservedState>,
    retained: usize,
    changed: Notify,
}

struct ObservedState {
    observation: SwimObservation,
    contacted: BTreeSet<NodeId>,
}
impl ObservationState {
    pub(super) fn new(retained: usize) -> Self {
        Self {
            state: Mutex::new(ObservedState {
                observation: SwimObservation {
                    revision: 0,
                    status: SwimDriverStatus::Prepared,
                    membership: MembershipView::new(),
                    stats: SwimDriverStats::default(),
                },
                contacted: BTreeSet::new(),
            }),
            retained,
            changed: Notify::new(),
        }
    }

    pub(super) fn publish(
        &self,
        events: Vec<MembershipEvent>,
        contacts: impl IntoIterator<Item = NodeId>,
        status: SwimDriverStatus,
        stats: SwimDriverStats,
    ) -> Result<(), SwimDriverError> {
        {
            let mut state = self.state.lock();
            let mut contacts = contacts.into_iter().peekable();
            if events.is_empty() && contacts.peek().is_none()
                && state.observation.status == status && state.observation.stats == stats
            {
                return Ok(());
            }
            let revision = state.observation.revision.checked_add(1).ok_or(SwimDriverError::ObservationExhausted)?;
            state.observation.membership.event_count().checked_add(events.len())
                .ok_or(SwimDriverError::ObservationExhausted)?;
            let invalidated: BTreeSet<_> = events.iter()
                .filter(|event| event.kind != MembershipKind::Alive)
                .map(|event| event.node.clone())
                .collect();
            for event in events {
                // Suspicion/departure invalidates old contact evidence. A later
                // Alive rumor alone cannot reuse a pre-failure packet.
                if event.kind != MembershipKind::Alive {
                    state.contacted.remove(&event.node);
                }
                // Compact every append, rather than retaining a whole batch in
                // the shared log while the producer drains a burst.
                state.observation.membership.apply(event);
                let keep_from = state.observation.membership.event_count().saturating_sub(self.retained);
                state.observation.membership.compact(keep_from);
            }
            for node in contacts {
                // Only known, currently Alive sources can remove a local veto.
                // A turn can receive a packet before its maintenance tick
                // discovers a failure. Conservatively require a later turn's
                // contact after any invalidation in this batch.
                if !invalidated.contains(&node)
                    && state.observation.membership.kind_of(&node) == Some(MembershipKind::Alive)
                {
                    state.contacted.insert(node);
                }
            }
            state.observation.revision = revision;
            state.observation.status = status;
            state.observation.stats = stats;
        }
        self.notify();
        Ok(())
    }

    pub(super) fn finish(&self, status: SwimDriverStatus, stats: SwimDriverStats) {
        {
            let mut state = self.state.lock();
            state.observation.status = status;
            state.observation.stats = stats;
            // Even at sequence exhaustion the terminal status makes every wait
            // ready. Never wrap a revision back to an old observer's version.
            state.observation.revision = state.observation.revision.saturating_add(1);
        }
        self.notify();
    }

    fn notify(&self) {
        // Observer callbacks do not get to strand the detector's teardown. The
        // existing Notify implementation detaches its fanout before dispatch.
        if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.changed.notify_waiters();
        })) {
            std::mem::forget(payload); // a hostile panic payload can panic on drop
        }
    }

    pub(super) fn finish_if_active(&self, status: SwimDriverStatus, stats: SwimDriverStats) {
        let active = !self.state.lock().observation.status.is_terminal();
        if active { self.finish(status, stats); }
    }
}

/// Cloneable observation handle. It owns no socket, timer, or runtime task.
///
/// State/log storage is bounded by the driver's topology/event limits. Copies
/// retained by consumers and simultaneous Notify waiters are caller-owned
/// resources, not covered by those limits. This interface intentionally does
/// not grant leases, authenticate peers, or drive the decision control plane.
#[derive(Clone)]
pub struct SwimObserver {
    pub(super) shared: Arc<ObservationState>,
}
impl std::fmt::Debug for SwimObserver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.shared.state.lock();
        f.debug_struct("SwimObserver")
            .field("revision", &state.observation.revision)
            .field("status", &state.observation.status)
            .finish_non_exhaustive()
    }
}
impl SwimObserver {
    /// Read a coalesced snapshot without advancing the detector.
    #[must_use]
    pub fn snapshot(&self) -> SwimObservation { self.shared.state.lock().observation.clone() }

    /// Whether a running detector currently observes direct contact with an
    /// Alive peer. This is a liveness hint, never authenticated authority.
    ///
    /// A configured seed or a rumor naming the peer is insufficient: an accepted
    /// packet must arrive from its configured address. Suspicion/departure clears
    /// this evidence; recovery needs another direct packet. Prepared, leaving and
    /// terminal drivers always return false, including while their last snapshot
    /// still contains Alive peers. Event-log compaction cannot lose this state.
    ///
    /// Source addresses can be spoofed on an untrusted network. This method may
    /// only tighten independently authenticated admission, never issue grants,
    /// replace pins, or certify remote process identity or continuing liveness.
    /// The lookup holds one short lock and does not clone the membership log.
    #[must_use]
    pub fn has_live_contact(&self, node: &NodeId) -> bool {
        let state = self.shared.state.lock();
        state.observation.status == SwimDriverStatus::Running
            && state.observation.membership.kind_of(node) == Some(MembershipKind::Alive)
            && state.contacted.contains(node)
    }

    /// Wait for a different publication version or terminal driver status.
    ///
    /// Register/check races are handled by the existing Notify predicate wait.
    /// Dropping this wait unregisters its waiter, not the detector. The caller
    /// supplies any deadline/cancellation by composing it in its own task.
    pub async fn changed(&self, after: u64) -> SwimObservation {
        self.shared.changed.wait_until(|| {
            let state = self.shared.state.lock();
            state.observation.revision != after || state.observation.status.is_terminal()
        }).await;
        self.snapshot()
    }
}
