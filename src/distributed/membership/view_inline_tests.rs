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

    #[test]
    fn departures_survive_compaction() {
        let mut view = MembershipView::new();
        view.apply(event("a", MembershipKind::Dead, 0));
        view.apply(event("a", MembershipKind::Alive, 1));
        view.apply(event("b", MembershipKind::Left, 0));
        view.apply(event("c", MembershipKind::Suspect, 0));
        view.compact(view.event_count());
        assert!(view.events_since(0).is_empty());

        assert!(view.has_departed(&node("a")), "rejoined under the same id");
        assert!(view.has_departed(&node("b")));
        assert!(!view.has_departed(&node("c")));
        let members: Vec<_> = view.members().collect();
        assert_eq!(
            members,
            vec![
                (&node("a"), MembershipKind::Alive),
                (&node("b"), MembershipKind::Left),
                (&node("c"), MembershipKind::Suspect),
            ]
        );
    }
