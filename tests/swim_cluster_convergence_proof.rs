//! Runnable convergence proof for SWIM membership (bead
//! `asupersync-dist-otp-completeness-8y37kz.4.2`, parent AC2).
//!
//! Drives the deterministic [`VirtualCluster`] — the lab virtual transport over
//! the pure `.4.1` SWIM state machine — through node death and a transient
//! partition, asserting the documented convergence behaviour:
//!
//! - kill 2 of 7 nodes => every survivor converges on `Dead` for both;
//! - a partition that heals before the suspicion timeout refutes (nobody is
//!   wrongly confirmed dead);
//! - a fault-free cluster stays stable (no false positives).
//!
//! Run with: `cargo test --test swim_cluster_convergence_proof --features test-internals`
//! (a focused integration-test binary that links the library compiled without
//! `#[cfg(test)]`, so it executes reliably despite unrelated in-tree test WIP).

use asupersync::distributed::membership::{ClusterConfig, SwimConfig, VirtualCluster};
use asupersync::remote::NodeId;

fn ids(n: usize) -> Vec<NodeId> {
    (0..n).map(|i| NodeId::new(format!("n{i}"))).collect()
}

#[test]
fn seven_node_kill_two_converges_to_dead() {
    let nodes = ids(7);
    let mut cluster =
        VirtualCluster::new(&nodes, SwimConfig::default(), ClusterConfig::default(), 42);
    cluster.advance(3_000); // settle
    cluster.kill(&nodes[5]);
    cluster.kill(&nodes[6]);
    cluster.advance(120_000); // well past the suspicion window
    assert!(
        cluster.all_living_agree_dead(&[nodes[5].clone(), nodes[6].clone()]),
        "survivors did not all converge to Dead for the killed nodes"
    );
}

#[test]
fn no_fault_cluster_stays_stable() {
    let nodes = ids(5);
    let mut cluster =
        VirtualCluster::new(&nodes, SwimConfig::default(), ClusterConfig::default(), 7);
    cluster.advance(15_000);
    assert!(
        cluster.all_living_agree_alive(&nodes),
        "a fault-free cluster produced a false positive"
    );
}

#[test]
fn partition_heal_refutes_suspicion() {
    let nodes = ids(5);
    let mut cluster =
        VirtualCluster::new(&nodes, SwimConfig::default(), ClusterConfig::default(), 11);
    cluster.advance(3_000);
    let majority = [nodes[0].clone(), nodes[1].clone(), nodes[2].clone()];
    let minority = [nodes[3].clone(), nodes[4].clone()];
    cluster.partition_groups(&[&majority, &minority]);
    cluster.advance(3_000); // hold the partition, under the suspicion timeout
    cluster.heal();
    cluster.advance(20_000);
    assert!(
        cluster.all_living_agree_alive(&nodes),
        "partition heal did not refute suspicion; a node was wrongly killed"
    );
}
