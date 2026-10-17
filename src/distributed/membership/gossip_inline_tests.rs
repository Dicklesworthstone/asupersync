    use super::*;

    fn node(s: &str) -> NodeId {
        NodeId::new(s)
    }

    #[test]
    fn retransmit_limit_scales_with_cluster() {
        let mut g = GossipBuffer::new(4);
        g.set_cluster_size(4, 7); // ceil(log10(8)) = 1 => 4
        assert_eq!(g.retransmit_limit(), 4);
        g.set_cluster_size(4, 100); // ceil(log10(101)) = 3 => 12
        assert_eq!(g.retransmit_limit(), 12);
        g.set_cluster_size(4, 0); // ceil(log10(1)) = 0 -> floored to 1 => 4
        assert_eq!(g.retransmit_limit(), 4);
    }

    #[test]
    fn fresher_rumor_supersedes_and_resets_counter() {
        let mut g = GossipBuffer::new(3);
        g.queue(Rumor::alive(node("a"), 1));
        // Transmit it once.
        let _ = g.select(8);
        // A suspicion at the same incarnation supersedes alive.
        g.queue(Rumor::suspect(node("a"), 1, node("b")));
        assert_eq!(g.len(), 1);
        let out = g.select(8);
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0], Rumor::Suspect { .. }));
    }

    #[test]
    fn stale_rumor_is_dropped() {
        let mut g = GossipBuffer::new(3);
        g.queue(Rumor::suspect(node("a"), 5, node("b")));
        // An older alive (lower incarnation) must not overwrite the suspicion.
        g.queue(Rumor::alive(node("a"), 4));
        let out = g.select(8);
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0], Rumor::Suspect { .. }));
    }

    #[test]
    fn rumor_is_evicted_after_retransmit_limit() {
        let mut g = GossipBuffer::new(2);
        g.queue(Rumor::alive(node("a"), 1));
        assert_eq!(g.select(8).len(), 1); // transmit 1
        assert_eq!(g.select(8).len(), 1); // transmit 2 -> hits limit, evicted
        assert!(g.is_empty());
        assert!(g.select(8).is_empty());
    }

    #[test]
    fn select_prefers_fewest_transmits() {
        let mut g = GossipBuffer::new(10);
        g.queue(Rumor::alive(node("a"), 1));
        // Give "a" a head start in transmissions.
        let _ = g.select(8);
        let _ = g.select(8);
        g.queue(Rumor::alive(node("b"), 1));
        // With max=1, the less-transmitted "b" must be chosen.
        let out = g.select(1);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].node().as_str(), "b");
    }

    #[test]
    fn empty_and_zero_budget() {
        let mut g = GossipBuffer::new(3);
        assert!(g.select(8).is_empty());
        g.queue(Rumor::alive(node("a"), 1));
        assert!(g.select(0).is_empty());
        assert_eq!(g.len(), 1);
    }
