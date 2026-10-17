    use super::*;

    fn ids(n: usize) -> Vec<NodeId> {
        (0..n).map(|i| NodeId::new(format!("n{i}"))).collect()
    }

    #[test]
    fn cluster_stabilizes_with_no_faults() {
        let nodes = ids(5);
        let mut cluster =
            VirtualCluster::new(&nodes, SwimConfig::default(), ClusterConfig::default(), 7);
        cluster.advance(10_000);
        // No deaths: everyone still sees everyone else alive (no false positives).
        assert!(cluster.all_living_agree_alive(&nodes));
    }

    #[test]
    fn a_zero_tick_still_advances_virtual_time() {
        let config = ClusterConfig {
            tick_ms: 0,
            ..ClusterConfig::default()
        };
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut cluster = VirtualCluster::new(&ids(3), SwimConfig::default(), config, 7);
            cluster.advance(50);
            let _ = tx.send(cluster.now());
        });
        let now = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("advance with tick_ms = 0 must return");
        assert_eq!(now, 50);
    }

    #[test]
    fn seven_node_kill_two_converges_to_dead() {
        // Parent AC2 (death half): kill 2 of 7, the survivors converge on Dead.
        let nodes = ids(7);
        let mut cluster =
            VirtualCluster::new(&nodes, SwimConfig::default(), ClusterConfig::default(), 42);
        cluster.advance(3_000); // settle
        cluster.kill(&nodes[5]);
        cluster.kill(&nodes[6]);
        // Advance well past the suspicion window (max ~24s for small clusters).
        cluster.advance(120_000);
        assert!(cluster.all_living_agree_dead(&[nodes[5].clone(), nodes[6].clone()]));
    }

    #[test]
    fn partition_heal_refutes_suspicion() {
        // Parent AC2 (heal half): a transient partition that heals before the
        // suspicion timeout must not leave anyone permanently dead.
        let nodes = ids(5);
        let mut cluster =
            VirtualCluster::new(&nodes, SwimConfig::default(), ClusterConfig::default(), 11);
        cluster.advance(3_000);
        // Split off the last two nodes.
        let majority = [nodes[0].clone(), nodes[1].clone(), nodes[2].clone()];
        let minority = [nodes[3].clone(), nodes[4].clone()];
        cluster.partition_groups(&[&majority, &minority]);
        // Hold the partition briefly (under the suspicion timeout), then heal.
        cluster.advance(3_000);
        cluster.heal();
        cluster.advance(15_000);
        // Refutation restored everyone; no node was wrongly confirmed dead.
        assert!(cluster.all_living_agree_alive(&nodes));
    }

    #[test]
    fn killed_node_traffic_is_dropped() {
        let nodes = ids(3);
        let mut cluster =
            VirtualCluster::new(&nodes, SwimConfig::default(), ClusterConfig::default(), 5);
        cluster.advance(1_000);
        cluster.kill(&nodes[2]);
        // The killed node no longer responds, so survivors confirm it dead.
        cluster.advance(120_000);
        assert_eq!(cluster.view(&nodes[0], &nodes[2]), Some(MemberState::Dead));
        assert_eq!(cluster.view(&nodes[1], &nodes[2]), Some(MemberState::Dead));
    }
