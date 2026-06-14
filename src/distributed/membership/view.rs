//! Watchable membership view + peer process-group (bead
//! `asupersync-dist-otp-completeness-8y37kz.4.2`, AC3).
//!
//! The pure [`swim::Swim`](super::swim::Swim) state machine emits
//! [`MembershipEvent`]s via `drain_events` (single-consumer) and exposes its own
//! alive set. [`MembershipView`] decouples *observers* from that driver: a
//! driver feeds it the Swim's drained events, and any number of observers query
//! the current membership snapshot — the **peer process-group** ([`alive_peers`])
//! — and consume the **watchable event stream** by tracking a cursor into the
//! append-only log ([`events_since`]).
//!
//! This is the seam the lease manager (bead `.4.3`) subscribes to: it advances a
//! cursor over the event stream and reacts — `Suspect` pauses new lease grants
//! to a node, `Dead`/`Left` revoke its leases through the obligation protocol —
//! without coupling to the Swim's internals (see the suspicion → obligation
//! revocation design note in [`super`]).
//!
//! Pure and transport-free; an async broadcast-push wrapper over a runtime
//! channel can layer on top, but observers can already watch via the cursor.
//!
//! [`alive_peers`]: MembershipView::alive_peers
//! [`events_since`]: MembershipView::events_since

use super::swim::{MembershipEvent, MembershipKind};
use crate::remote::NodeId;
use std::collections::BTreeMap;

/// An aggregated, observable view of cluster membership.
#[derive(Debug, Clone, Default)]
pub struct MembershipView {
    /// Latest known kind per node.
    states: BTreeMap<NodeId, MembershipKind>,
    /// Append-only event log; observers track a cursor into it.
    log: Vec<MembershipEvent>,
}

impl MembershipView {
    /// An empty view.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Applies one membership event: updates the node's latest state and appends
    /// it to the watchable event log.
    pub fn apply(&mut self, event: MembershipEvent) {
        self.states.insert(event.node.clone(), event.kind);
        self.log.push(event);
    }

    /// Applies a batch of events (e.g. the result of `Swim::drain_events`).
    pub fn apply_all(&mut self, events: impl IntoIterator<Item = MembershipEvent>) {
        for event in events {
            self.apply(event);
        }
    }

    /// The latest known kind of `node`, if any has been observed.
    #[must_use]
    pub fn kind_of(&self, node: &NodeId) -> Option<MembershipKind> {
        self.states.get(node).copied()
    }

    /// The peer process-group: nodes currently believed `Alive`, in id order.
    #[must_use]
    pub fn alive_peers(&self) -> Vec<NodeId> {
        self.states
            .iter()
            .filter(|&(_, kind)| *kind == MembershipKind::Alive)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// The total number of events observed (the end cursor of the stream).
    #[must_use]
    pub fn event_count(&self) -> usize {
        self.log.len()
    }

    /// The watchable event stream: events appended at or after `cursor`. An
    /// observer remembers the returned slice's length plus its old cursor as its
    /// new cursor, so it never re-processes an event. A cursor past the end
    /// yields an empty slice.
    #[must_use]
    pub fn events_since(&self, cursor: usize) -> &[MembershipEvent] {
        let start = cursor.min(self.log.len());
        &self.log[start..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(s: &str) -> NodeId {
        NodeId::new(s)
    }

    fn event(n: &str, kind: MembershipKind, incarnation: u64) -> MembershipEvent {
        MembershipEvent {
            node: node(n),
            kind,
            incarnation,
        }
    }

    #[test]
    fn tracks_latest_state_and_process_group() {
        let mut view = MembershipView::new();
        view.apply(event("a", MembershipKind::Alive, 0));
        view.apply(event("b", MembershipKind::Alive, 0));
        view.apply(event("c", MembershipKind::Alive, 0));
        assert_eq!(view.alive_peers(), vec![node("a"), node("b"), node("c")]);

        // b becomes suspect then dead; the process-group shrinks.
        view.apply(event("b", MembershipKind::Suspect, 0));
        assert_eq!(view.kind_of(&node("b")), Some(MembershipKind::Suspect));
        assert_eq!(view.alive_peers(), vec![node("a"), node("c")]);
        view.apply(event("b", MembershipKind::Dead, 0));
        assert_eq!(view.kind_of(&node("b")), Some(MembershipKind::Dead));
        assert_eq!(view.alive_peers(), vec![node("a"), node("c")]);
    }

    #[test]
    fn cursor_stream_delivers_each_event_once() {
        let mut view = MembershipView::new();
        let mut cursor = 0;
        view.apply(event("a", MembershipKind::Alive, 0));
        view.apply(event("a", MembershipKind::Suspect, 0));

        let fresh = view.events_since(cursor);
        assert_eq!(fresh.len(), 2);
        cursor = view.event_count();

        // Nothing new yet.
        assert!(view.events_since(cursor).is_empty());

        // A new transition is delivered exactly once to the advancing cursor.
        view.apply(event("a", MembershipKind::Dead, 1));
        let fresh = view.events_since(cursor);
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].kind, MembershipKind::Dead);
        cursor = view.event_count();
        assert!(view.events_since(cursor).is_empty());
    }

    #[test]
    fn cursor_past_end_is_empty() {
        let view = MembershipView::new();
        assert!(view.events_since(99).is_empty());
    }
}
