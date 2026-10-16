    use super::*;

    fn node(s: &str) -> NodeId {
        NodeId::new(s)
    }

    fn event(n: &str, kind: MembershipKind) -> super::super::swim::MembershipEvent {
        super::super::swim::MembershipEvent {
            node: node(n),
            kind,
            incarnation: 0,
        }
    }

    #[test]
    fn kind_maps_to_action() {
        assert_eq!(lease_action_for(MembershipKind::Alive), LeaseAction::Resume);
        assert_eq!(
            lease_action_for(MembershipKind::Suspect),
            LeaseAction::PauseGrants
        );
        assert_eq!(lease_action_for(MembershipKind::Dead), LeaseAction::Revoke);
        assert_eq!(lease_action_for(MembershipKind::Left), LeaseAction::Revoke);
    }

    #[test]
    fn suspect_pauses_then_dead_revokes() {
        let mut view = MembershipView::new();
        let mut reactor = MembershipLeaseReactor::new();

        view.apply(event("a", MembershipKind::Alive));
        view.apply(event("a", MembershipKind::Suspect));
        let actions = reactor.poll(&view);
        assert_eq!(actions, vec![(node("a"), LeaseAction::PauseGrants)]);
        assert!(reactor.is_paused(&node("a")));

        view.apply(event("a", MembershipKind::Dead));
        let actions = reactor.poll(&view);
        assert_eq!(actions, vec![(node("a"), LeaseAction::Revoke)]);
        assert!(reactor.is_revoked(&node("a")));
        assert!(!reactor.is_paused(&node("a")));
    }

    #[test]
    fn refutation_resumes_grants() {
        let mut view = MembershipView::new();
        let mut reactor = MembershipLeaseReactor::new();
        view.apply(event("a", MembershipKind::Suspect));
        let _ = reactor.poll(&view);
        assert!(reactor.is_paused(&node("a")));
        // Refutation: a is alive again -> resume grants.
        view.apply(event("a", MembershipKind::Alive));
        let actions = reactor.poll(&view);
        assert_eq!(actions, vec![(node("a"), LeaseAction::Resume)]);
        assert!(!reactor.is_paused(&node("a")));
    }

    #[test]
    fn revocation_is_terminal() {
        let mut view = MembershipView::new();
        let mut reactor = MembershipLeaseReactor::new();
        view.apply(event("a", MembershipKind::Dead));
        assert_eq!(reactor.poll(&view), vec![(node("a"), LeaseAction::Revoke)]);
        // A late/stale Alive must not resurrect a revoked node's leases.
        view.apply(event("a", MembershipKind::Alive));
        assert!(reactor.poll(&view).is_empty());
        assert!(reactor.is_revoked(&node("a")));
    }

    #[test]
    fn repeated_suspect_is_idempotent() {
        let mut view = MembershipView::new();
        let mut reactor = MembershipLeaseReactor::new();
        view.apply(event("a", MembershipKind::Suspect));
        assert_eq!(
            reactor.poll(&view),
            vec![(node("a"), LeaseAction::PauseGrants)]
        );
        // Same suspicion observed again -> no duplicate action.
        view.apply(event("a", MembershipKind::Suspect));
        assert!(reactor.poll(&view).is_empty());
    }

    /// A view that compacts past the reactor's cursor (the SWIM driver's
    /// observation keeps a bounded suffix) used to drop those events
    /// silently, so a node that died while the reactor lagged kept its leases.
    #[test]
    fn a_lagging_reactor_reconciles_from_the_snapshot() {
        let mut view = MembershipView::new();
        let mut reactor = MembershipLeaseReactor::new();
        view.apply(event("a", MembershipKind::Suspect));
        view.apply(event("d", MembershipKind::Suspect));
        assert_eq!(reactor.poll(&view).len(), 2);

        view.apply(event("a", MembershipKind::Alive));
        view.apply(event("b", MembershipKind::Dead));
        view.apply(event("c", MembershipKind::Suspect));
        view.apply(event("e", MembershipKind::Left));
        view.apply(event("e", MembershipKind::Alive));
        view.compact(view.event_count());
        assert_eq!(
            reactor.poll(&view),
            vec![
                (node("a"), LeaseAction::Resume),
                (node("b"), LeaseAction::Revoke),
                (node("c"), LeaseAction::PauseGrants),
                (node("e"), LeaseAction::Revoke),
            ]
        );
        assert!(reactor.is_paused(&node("d")), "d is still suspect");
        assert!(reactor.is_revoked(&node("e")), "e left, then rejoined");

        // Back in step: later events are consumed from the log again.
        view.apply(event("c", MembershipKind::Dead));
        assert_eq!(reactor.poll(&view), vec![(node("c"), LeaseAction::Revoke)]);
        assert!(reactor.poll(&view).is_empty());
    }
