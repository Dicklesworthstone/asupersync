    use super::*;

    fn node(s: &str) -> NodeId {
        NodeId::new(s)
    }

    fn cfg() -> SwimConfig {
        SwimConfig::default()
    }

    // ---- config ----------------------------------------------------------

    #[test]
    fn default_config_is_valid_with_cited_defaults() {
        let c = cfg();
        assert!(c.validate().is_ok());
        assert_eq!(c.probe_interval_ms, 1000);
        assert_eq!(c.probe_timeout_ms, 500);
        assert_eq!(c.indirect_probe_count, 3);
        assert_eq!(c.suspicion_mult, 4);
        assert_eq!(c.suspicion_max_timeout_mult, 6);
        assert_eq!(c.gossip_retransmit_mult, 4);
        assert_eq!(c.awareness_max, 8);
        assert_eq!(c.max_members, 65_536);
    }

    #[test]
    fn config_validation_rejects_each_bad_field() {
        let bad = |f: &dyn Fn(&mut SwimConfig)| {
            let mut c = cfg();
            f(&mut c);
            c.validate()
        };
        assert_eq!(
            bad(&|c| c.probe_interval_ms = 0),
            Err(SwimConfigError::ZeroProbeInterval)
        );
        assert_eq!(
            bad(&|c| c.probe_timeout_ms = 0),
            Err(SwimConfigError::ZeroProbeTimeout)
        );
        assert_eq!(
            bad(&|c| c.probe_timeout_ms = c.probe_interval_ms),
            Err(SwimConfigError::ProbeTimeoutNotLessThanInterval)
        );
        assert_eq!(
            bad(&|c| c.suspicion_mult = 0),
            Err(SwimConfigError::ZeroSuspicionMult)
        );
        assert_eq!(
            bad(&|c| c.suspicion_max_timeout_mult = 0),
            Err(SwimConfigError::ZeroSuspicionMaxTimeoutMult)
        );
        assert_eq!(
            bad(&|c| c.gossip_retransmit_mult = 0),
            Err(SwimConfigError::ZeroGossipRetransmitMult)
        );
        assert_eq!(
            bad(&|c| c.max_piggyback = 0),
            Err(SwimConfigError::ZeroMaxPiggyback)
        );
        assert_eq!(
            bad(&|c| c.awareness_max = 0),
            Err(SwimConfigError::AwarenessMaxTooSmall)
        );
        assert_eq!(
            bad(&|c| c.max_members = 0),
            Err(SwimConfigError::ZeroMaxMembers)
        );
    }

    #[test]
    fn members_capped_at_max_members_fail_closed() {
        // SWIM gossip is unauthenticated, so a flood of fabricated node ids must
        // not grow the members table (or the re-flood amplification) without
        // limit. New members past `max_members` are rejected fail-closed, while
        // updates to already-tracked members still apply (qe0zdf).
        let mut config = cfg();
        config.max_members = 3;
        let mut s = Swim::new(node("local"), config, 1);

        // Fill the table up to the cap via the join path.
        for p in ["a", "b", "c"] {
            s.add_peer(0, node(p));
        }
        assert_eq!(s.member_count(), 3);
        let _ = s.drain_events();

        // A brand-new node past the cap is rejected: not tracked, no event.
        s.add_peer(0, node("d"));
        assert_eq!(s.member_count(), 3, "join past the cap must be rejected");
        assert!(
            s.state_of(&node("d")).is_none(),
            "rejected node must not be tracked",
        );

        // The gossip-driven path (the actual attack vector) is bounded too: a
        // superseding Alive rumor about a fabricated node past the cap adopts
        // nothing and emits no membership event to re-flood.
        s.apply_rumor(0, &Rumor::alive(node("evil"), 9));
        assert_eq!(
            s.member_count(),
            3,
            "gossip about a new node past the cap is dropped"
        );
        assert!(s.state_of(&node("evil")).is_none());
        let events = s.drain_events();
        assert!(
            events
                .iter()
                .all(|e| e.node != node("d") && e.node != node("evil")),
            "no membership event for a rejected node (nothing to amplify)",
        );

        // An update to an already-tracked member still applies even at the cap.
        s.apply_rumor(0, &Rumor::suspect(node("a"), 1, node("b")));
        assert_eq!(
            s.state_of(&node("a")),
            Some(MemberState::Suspect),
            "updates to existing members are unaffected by the cap",
        );
        assert_eq!(s.member_count(), 3);
    }

    // ---- precedence (exhaustive) -----------------------------------------

    #[test]
    fn rumor_precedence_table() {
        let n = node("x");
        let a = node("a");
        let alive1 = Rumor::alive(n.clone(), 1);
        let alive2 = Rumor::alive(n.clone(), 2);
        let suspect1 = Rumor::suspect(n.clone(), 1, a.clone());
        let suspect2 = Rumor::suspect(n.clone(), 2, a.clone());
        let dead1 = Rumor::confirm(n.clone(), 1, a.clone());
        let leave1 = Rumor::leave(n.clone(), 1);

        // Alive overrides alive/suspect only at strictly higher incarnation.
        assert!(alive2.supersedes(&alive1));
        assert!(!alive1.supersedes(&alive2));
        assert!(alive2.supersedes(&suspect1));
        assert!(!alive1.supersedes(&suspect1));

        // Suspect overrides alive at >= incarnation; suspect at > incarnation.
        assert!(suspect1.supersedes(&alive1));
        assert!(suspect2.supersedes(&suspect1));
        assert!(!suspect1.supersedes(&suspect2));

        // Death/leave overrides any non-terminal at any incarnation.
        assert!(dead1.supersedes(&alive2));
        assert!(dead1.supersedes(&suspect2));
        assert!(leave1.supersedes(&alive2));
        assert!(!alive2.supersedes(&dead1));
        assert!(!suspect2.supersedes(&dead1));

        // Among terminals, confirm outranks leave at equal incarnation.
        assert!(dead1.supersedes(&leave1));
        assert!(!leave1.supersedes(&dead1));
    }

    // ---- ping/ack --------------------------------------------------------

    #[test]
    fn ping_is_acked_and_sender_is_learned() {
        let mut s = Swim::new(node("self"), cfg(), 1);
        let out = s.handle(0, node("peer"), Packet::new(Payload::Ping { seq: 42 }));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].to, node("peer"));
        assert_eq!(out[0].packet.payload, Payload::Ack { seq: 42 });
        // Sender learned as alive.
        assert_eq!(s.state_of(&node("peer")), Some(MemberState::Alive));
        let events = s.drain_events();
        assert!(
            events
                .iter()
                .any(|e| e.node == node("peer") && e.kind == MembershipKind::Alive)
        );
    }

    #[test]
    fn tick_starts_a_probe_period() {
        let mut s = Swim::new(node("self"), cfg(), 7);
        s.add_peer(0, node("a"));
        let _ = s.drain_events();
        let out = s.tick(0);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].to, node("a"));
        assert!(matches!(out[0].packet.payload, Payload::Ping { .. }));
    }

    #[test]
    fn direct_ack_keeps_target_alive_and_improves_health() {
        let mut s = Swim::new(node("self"), cfg(), 7);
        s.add_peer(0, node("a"));
        let _ = s.drain_events();
        let out = s.tick(0);
        let Payload::Ping { seq } = out[0].packet.payload else {
            panic!("expected ping");
        };
        // Target acks within RTT.
        let _ = s.handle(100, node("a"), Packet::new(Payload::Ack { seq }));
        // Drive past the period end: no suspicion should be raised.
        let _ = s.tick(1000);
        let events = s.drain_events();
        assert!(!events.iter().any(|e| e.kind == MembershipKind::Suspect));
        assert_eq!(s.state_of(&node("a")), Some(MemberState::Alive));
    }

    // ---- indirect probe + suspicion --------------------------------------

    #[test]
    fn unacked_probe_escalates_to_indirect_then_suspects() {
        let mut s = Swim::new(node("self"), cfg(), 3);
        for p in ["a", "b", "c"] {
            s.add_peer(0, node(p));
        }
        let _ = s.drain_events();
        let out = s.tick(0);
        let target = out[0].to.clone();
        let Payload::Ping { .. } = out[0].packet.payload else {
            panic!("expected ping");
        };

        // No ack within RTT -> indirect ping-reqs go to other peers.
        let out2 = s.tick(500);
        assert!(!out2.is_empty(), "expected indirect ping-reqs");
        for o in &out2 {
            assert_ne!(o.to, target, "helper must not be the target");
            match &o.packet.payload {
                Payload::PingReq { target: t, .. } => assert_eq!(*t, target),
                other => panic!("expected ping-req, got {other:?}"),
            }
        }

        // Still no ack by period end -> target suspected.
        let _ = s.tick(1000);
        assert_eq!(s.state_of(&target), Some(MemberState::Suspect));
        let events = s.drain_events();
        assert!(
            events
                .iter()
                .any(|e| e.node == target && e.kind == MembershipKind::Suspect)
        );
    }

    #[test]
    fn suspect_escalates_to_dead_after_timeout() {
        let mut s = Swim::new(node("self"), cfg(), 5);
        s.add_peer(0, node("a"));
        // Suspect "a" via gossip from an accuser.
        let pkt = Packet {
            payload: Payload::Ping { seq: 1 },
            gossip: vec![Rumor::suspect(node("a"), 0, node("acc"))],
        };
        let _ = s.handle(0, node("acc"), pkt);
        assert_eq!(s.state_of(&node("a")), Some(MemberState::Suspect));
        let _ = s.drain_events();

        // One accuser => full suspicion window (max). For n=3, min=4000,
        // max=24000ms. Before the window it stays suspect...
        let _ = s.tick(10_000);
        assert_eq!(s.state_of(&node("a")), Some(MemberState::Suspect));
        // ...after the window it is confirmed dead.
        let _ = s.tick(30_000);
        assert_eq!(s.state_of(&node("a")), Some(MemberState::Dead));
        let events = s.drain_events();
        assert!(
            events
                .iter()
                .any(|e| e.node == node("a") && e.kind == MembershipKind::Dead)
        );
    }

    #[test]
    fn independent_confirmations_shrink_the_window() {
        let mut s = Swim::new(node("self"), cfg(), 5);
        s.add_peer(0, node("a"));
        // The creator plus k=3 independent confirmations at the same
        // incarnation collapses the window to its minimum (4000ms here).
        for acc in ["acc1", "acc2", "acc3", "acc4"] {
            let pkt = Packet {
                payload: Payload::Ping { seq: 1 },
                gossip: vec![Rumor::suspect(node("a"), 0, node(acc))],
            };
            let _ = s.handle(0, node(acc), pkt);
        }
        let _ = s.drain_events();
        // With >= k confirmations the window is the minimum (4000ms), so by
        // 5000ms the node is already dead — far sooner than the lone-accuser
        // case (which survives past 10_000ms above).
        let _ = s.tick(5_000);
        assert_eq!(s.state_of(&node("a")), Some(MemberState::Dead));
    }

    #[test]
    fn a_suspicion_at_a_newer_incarnation_gets_its_own_window() {
        // "a" refuted a Suspect(0) with Alive(1), and this node missed the
        // refutation. A later Suspect(1) from another accuser is a new
        // suspicion: it must not inherit the old start time, nor count the old
        // accuser as a confirmation (which would cut the window to 14_000 ms,
        // measured from t = 0, and kill "a" one millisecond after it arrives).
        let mut s = Swim::new(node("self"), cfg(), 5);
        s.add_peer(0, node("a"));
        let suspect = |incarnation, accuser: &str| Packet {
            payload: Payload::Ping { seq: 1 },
            gossip: vec![Rumor::suspect(node("a"), incarnation, node(accuser))],
        };
        let _ = s.handle(0, node("acc1"), suspect(0, "acc1"));
        let _ = s.handle(20_000, node("acc2"), suspect(1, "acc2"));
        let _ = s.tick(20_001);
        assert_eq!(s.state_of(&node("a")), Some(MemberState::Suspect));
        let member = &s.members[&node("a")];
        assert_eq!(member.suspect_since, 20_000);
        assert_eq!(member.suspect_from, BTreeSet::from([node("acc2")]));
        // The lone accuser's full window (24_000 ms for n < 10) runs from 20_000.
        let _ = s.tick(44_000);
        assert_eq!(s.state_of(&node("a")), Some(MemberState::Dead));
    }

    // ---- refutation ------------------------------------------------------

    #[test]
    fn alive_rumor_with_higher_incarnation_refutes_suspicion() {
        let mut s = Swim::new(node("self"), cfg(), 5);
        s.add_peer(0, node("a"));
        let _ = s.handle(
            0,
            node("acc"),
            Packet {
                payload: Payload::Ping { seq: 1 },
                gossip: vec![Rumor::suspect(node("a"), 0, node("acc"))],
            },
        );
        assert_eq!(s.state_of(&node("a")), Some(MemberState::Suspect));
        let _ = s.drain_events();

        // "a" refutes by bumping its incarnation and flooding Alive.
        let _ = s.handle(
            10,
            node("a"),
            Packet {
                payload: Payload::Ping { seq: 2 },
                gossip: vec![Rumor::alive(node("a"), 1)],
            },
        );
        assert_eq!(s.state_of(&node("a")), Some(MemberState::Alive));
        let events = s.drain_events();
        assert!(
            events
                .iter()
                .any(|e| e.node == node("a") && e.kind == MembershipKind::Alive)
        );
    }

    #[test]
    fn self_suspicion_triggers_incarnation_bump_and_alive_flood() {
        let mut s = Swim::new(node("self"), cfg(), 9);
        assert_eq!(s.incarnation(), 0);
        let out = s.handle(
            0,
            node("acc"),
            Packet {
                payload: Payload::Ping { seq: 5 },
                gossip: vec![Rumor::suspect(node("self"), 0, node("acc"))],
            },
        );
        // Incarnation bumped past the accusation.
        assert_eq!(s.incarnation(), 1);
        // The ack response piggybacks the refuting Alive(self, 1).
        let ack = &out[0];
        assert!(ack.packet.gossip.iter().any(|r| matches!(
            r,
            Rumor::Alive { node: nn, incarnation: 1 } if nn == &node("self")
        )));
        // We never track ourselves as a member.
        assert_eq!(s.state_of(&node("self")), None);
    }

    #[test]
    fn self_suspicion_with_max_incarnation_is_rejected_at_ingress() {
        // `u64::MAX` is a reserved incarnation sentinel: a crafted rumor carrying
        // it about the local node is dropped at ingress, not refuted. Adopting it
        // would pin the node — the refutation bump can only `saturating_add(1)` to
        // `u64::MAX`, which loses the same-incarnation precedence tie to the
        // planted `Suspect`, so the node would be confirmed Dead while alive.
        let mut s = Swim::new(node("self"), cfg(), 9);
        let out = s.handle(
            0,
            node("acc"),
            Packet {
                payload: Payload::Ping { seq: 5 },
                gossip: vec![Rumor::suspect(node("self"), u64::MAX, node("acc"))],
            },
        );
        // The forged suspicion is ignored: incarnation is untouched (no wrap, no
        // panic, no pinning at the ceiling).
        assert_eq!(s.incarnation(), 0);
        // Nothing to refute — no Alive at the reserved ceiling is emitted.
        let ack = &out[0];
        assert!(!ack.packet.gossip.iter().any(|r| matches!(
            r,
            Rumor::Alive { node: nn, incarnation } if nn == &node("self") && *incarnation == u64::MAX
        )));
    }

    #[test]
    fn self_refutation_ceiling_stays_open_below_the_reserved_sentinel() {
        // The dead-zone is closed: the highest suspicion a peer can actually plant
        // is `u64::MAX - 1` (the sentinel itself is rejected at ingress), and the
        // node can always out-incarnate it by bumping to `u64::MAX`, which strictly
        // supersedes a same-node `Suspect{u64::MAX - 1}`.
        let mut s = Swim::new(node("self"), cfg(), 9);
        let out = s.handle(
            0,
            node("acc"),
            Packet {
                payload: Payload::Ping { seq: 7 },
                gossip: vec![Rumor::suspect(node("self"), u64::MAX - 1, node("acc"))],
            },
        );
        // Bumped strictly above the planted suspicion, saturating exactly at the
        // ceiling.
        assert_eq!(s.incarnation(), u64::MAX);
        let refutation = Rumor::alive(node("self"), u64::MAX);
        let planted = Rumor::suspect(node("self"), u64::MAX - 1, node("acc"));
        assert!(
            refutation.supersedes(&planted),
            "Alive at the ceiling must out-incarnate the highest plantable suspicion"
        );
        // The refuting Alive rides out on the ack.
        let ack = &out[0];
        assert!(ack.packet.gossip.iter().any(|r| matches!(
            r,
            Rumor::Alive { node: nn, incarnation } if nn == &node("self") && *incarnation == u64::MAX
        )));
    }

    #[test]
    fn ping_req_relay_table_capped_fail_closed() {
        // SWIM gossip is unauthenticated, so a flood of spoofed `PingReq` packets
        // must not grow the in-flight relay table (`forwards`) — or its relayed
        // `Ping` re-emission — without bound within a probe-timeout window. Relays
        // past `max_members` are dropped fail-closed (qe0zdf).
        let mut config = cfg();
        config.max_members = 2;
        let mut s = Swim::new(node("local"), config, 1);

        // Each distinct target we are asked to relay to allocates one forward and
        // emits one relayed Ping — up to the cap.
        let out1 = s.handle(
            0,
            node("req"),
            Packet::new(Payload::PingReq {
                seq: 1,
                target: node("t1"),
            }),
        );
        let out2 = s.handle(
            0,
            node("req"),
            Packet::new(Payload::PingReq {
                seq: 2,
                target: node("t2"),
            }),
        );
        assert!(
            out1.iter()
                .any(|o| matches!(o.packet.payload, Payload::Ping { .. }))
                && out2
                    .iter()
                    .any(|o| matches!(o.packet.payload, Payload::Ping { .. })),
            "relays within the cap emit a Ping to the target"
        );

        // The next relay past the cap is dropped: no forward is recorded and no
        // Ping is emitted to amplify.
        let out3 = s.handle(
            0,
            node("req"),
            Packet::new(Payload::PingReq {
                seq: 3,
                target: node("t3"),
            }),
        );
        assert!(
            !out3
                .iter()
                .any(|o| matches!(o.packet.payload, Payload::Ping { .. })),
            "a PingReq past the relay cap must not emit a relayed Ping"
        );
    }

    // ---- gossip dissemination -------------------------------------------

    #[test]
    fn suspicion_is_piggybacked_for_dissemination() {
        let mut s = Swim::new(node("self"), cfg(), 3);
        for p in ["a", "b"] {
            s.add_peer(0, node(p));
        }
        let out = s.tick(0);
        let target = out[0].to.clone();
        let _ = s.tick(500);
        let _ = s.tick(1000); // suspect target

        // The target is still within its suspicion window...
        assert_eq!(s.state_of(&target), Some(MemberState::Suspect));
        // ...and the next protocol period's probe piggybacks the suspicion.
        let later = s.tick(3000);
        let carried = later.iter().any(|o| {
            o.packet
                .gossip
                .iter()
                .any(|r| matches!(r, Rumor::Suspect { node: nn, .. } if *nn == target))
        });
        assert!(
            carried,
            "suspicion must be piggybacked on outbound probe traffic"
        );
    }

    #[test]
    fn declare_leave_floods_leave_rumor() {
        let mut s = Swim::new(node("self"), cfg(), 1);
        s.add_peer(0, node("a"));
        s.declare_leave();
        assert_eq!(s.incarnation(), 1);
        // The leave rumor rides out on the next packet.
        let out = s.handle(0, node("a"), Packet::new(Payload::Ping { seq: 1 }));
        assert!(out[0].packet.gossip.iter().any(|r| matches!(
            r,
            Rumor::Leave { node: nn, .. } if nn == &node("self")
        )));
    }

    #[test]
    fn dead_is_terminal_and_not_resurrected_by_alive() {
        let mut s = Swim::new(node("self"), cfg(), 1);
        s.add_peer(0, node("a"));
        let _ = s.handle(
            0,
            node("acc"),
            Packet {
                payload: Payload::Ping { seq: 1 },
                gossip: vec![Rumor::confirm(node("a"), 5, node("acc"))],
            },
        );
        assert_eq!(s.state_of(&node("a")), Some(MemberState::Dead));
        // A stale (or even higher) Alive must not resurrect a dead node.
        let _ = s.handle(
            1,
            node("b"),
            Packet {
                payload: Payload::Ping { seq: 2 },
                gossip: vec![Rumor::alive(node("a"), 99)],
            },
        );
        assert_eq!(s.state_of(&node("a")), Some(MemberState::Dead));
    }

    #[test]
    fn indirect_helper_relays_ack_to_requester() {
        // Acting as a helper: receive a ping-req, ping the target, then on the
        // target's ack relay it back to the requester.
        let mut s = Swim::new(node("helper"), cfg(), 1);
        let out = s.handle(
            0,
            node("req"),
            Packet::new(Payload::PingReq {
                seq: 77,
                target: node("tgt"),
            }),
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].to, node("tgt"));
        let Payload::Ping { seq: helper_seq } = out[0].packet.payload else {
            panic!("expected ping to target");
        };
        // Target acks the helper.
        let relayed = s.handle(
            10,
            node("tgt"),
            Packet::new(Payload::Ack { seq: helper_seq }),
        );
        assert_eq!(relayed.len(), 1);
        assert_eq!(relayed[0].to, node("req"));
        assert_eq!(relayed[0].packet.payload, Payload::Ack { seq: 77 });
    }

    #[test]
    fn helper_nacks_requester_when_target_silent() {
        let mut s = Swim::new(node("helper"), cfg(), 1);
        let _ = s.handle(
            0,
            node("req"),
            Packet::new(Payload::PingReq {
                seq: 88,
                target: node("tgt"),
            }),
        );
        // Target never acks; after the probe timeout the helper nacks. (The
        // same tick may also open a new probe period, so select the nack.)
        let out = s.tick(600);
        let nack = out
            .iter()
            .find(|o| matches!(o.packet.payload, Payload::Nack { .. }))
            .expect("helper should nack the requester");
        assert_eq!(nack.to, node("req"));
        assert_eq!(nack.packet.payload, Payload::Nack { seq: 88 });
    }
