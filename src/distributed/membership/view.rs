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
    /// Retained suffix of the append-only event log; observers track an
    /// absolute cursor into the stream (see [`base`](Self::base)).
    log: Vec<MembershipEvent>,
    /// Number of events dropped from the front of the stream by
    /// [`compact`](Self::compact). Cursors stay absolute across the whole
    /// stream's history, so `log[i]` has absolute index `base + i`. Without
    /// compaction this stays `0` and the view behaves as a plain append-only
    /// log.
    base: usize,
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

    /// The total number of events observed (the end cursor of the stream),
    /// including any prefix already dropped by [`compact`](Self::compact).
    #[must_use]
    pub fn event_count(&self) -> usize {
        self.base + self.log.len()
    }

    /// The absolute cursor below which events have been dropped by
    /// [`compact`](Self::compact). An observer whose cursor is `< compact_base`
    /// has missed events and should reconcile against the current
    /// [`alive_peers`](Self::alive_peers) snapshot.
    #[must_use]
    pub fn compact_base(&self) -> usize {
        self.base
    }

    /// The watchable event stream: events appended at or after `cursor` (an
    /// absolute stream index). An observer remembers its old cursor plus the
    /// returned slice's length as its new cursor, so it never re-processes an
    /// event. A cursor past the end yields an empty slice; a cursor below
    /// [`compact_base`](Self::compact_base) (the observer fell behind a
    /// compaction) yields the full retained suffix so it can resynchronize.
    #[must_use]
    pub fn events_since(&self, cursor: usize) -> &[MembershipEvent] {
        let start = cursor.saturating_sub(self.base).min(self.log.len());
        &self.log[start..]
    }

    /// Drops the consumed event prefix strictly below `low_watermark` (an
    /// absolute cursor — typically the minimum cursor across all live
    /// observers), bounding the otherwise unbounded append-only log under
    /// long-lived cluster churn. This is a no-op when nothing is below the
    /// watermark. Observers whose cursor falls below the new
    /// [`compact_base`](Self::compact_base) will receive the full retained
    /// suffix from [`events_since`](Self::events_since) and should reconcile
    /// against [`alive_peers`](Self::alive_peers) (aasraf).
    pub fn compact(&mut self, low_watermark: usize) {
        let drop = low_watermark.saturating_sub(self.base).min(self.log.len());
        if drop > 0 {
            self.log.drain(0..drop);
            self.base += drop;
        }
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

    #[test]
    fn compact_bounds_log_and_keeps_absolute_cursors() {
        let mut view = MembershipView::new();
        for kind in [
            MembershipKind::Alive,
            MembershipKind::Suspect,
            MembershipKind::Dead,
        ] {
            view.apply(event("a", kind, 0));
        }
        view.apply(event("b", MembershipKind::Alive, 0));
        assert_eq!(view.event_count(), 4);

        // A caller up to cursor 2 compacts the consumed prefix.
        view.compact(2);
        assert_eq!(view.compact_base(), 2, "two events dropped from the front");
        // The total stream cursor is unchanged — cursors stay absolute.
        assert_eq!(view.event_count(), 4);
        // An observer at the watermark still sees exactly the un-consumed tail.
        let tail = view.events_since(2);
        assert_eq!(tail.len(), 2);
        assert_eq!(tail[0].kind, MembershipKind::Dead);

        // A laggard below the new base gets the full retained suffix to resync.
        assert_eq!(view.events_since(0).len(), 2);

        // Compaction never drops un-consumed events and is idempotent below base.
        view.compact(2);
        assert_eq!(view.compact_base(), 2);
        // The membership snapshot is untouched by log compaction.
        assert_eq!(view.kind_of(&node("a")), Some(MembershipKind::Dead));
        assert_eq!(view.kind_of(&node("b")), Some(MembershipKind::Alive));
    }
}
