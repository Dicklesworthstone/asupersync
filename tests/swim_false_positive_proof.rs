//! Runnable false-positive-rate proof for SWIM membership under packet loss
//! (bead `asupersync-dist-otp-completeness-8y37kz.4.2`, parent AC5).
//!
//! Runs a fault-free 5-node cluster under seeded packet loss across a corpus of
//! seeds and measures false positives. SWIM's incarnation refutation plus the
//! suspicion window must prevent any healthy node from being wrongly *confirmed
//! dead*; transient suspicions are permitted (they refute). The measured
//! false-positive death rate at mild (3%) loss is therefore zero.
//!
//! Run with: `cargo test --test swim_false_positive_proof --features test-internals`.

use asupersync::distributed::membership::{ClusterConfig, MemberState, SwimConfig, VirtualCluster};
use asupersync::remote::NodeId;

fn ids(n: usize) -> Vec<NodeId> {
    (0..n).map(|i| NodeId::new(format!("n{i}"))).collect()
}

#[test]
fn no_false_positive_deaths_under_mild_loss() {
    let nodes = ids(5);
    let seeds = 20u64;
    let mut false_positive_deaths = 0usize;
    let mut transient_suspects = 0usize;

    for seed in 0..seeds {
        let config = ClusterConfig {
            loss_permille: 30, // 3% per-message drop, no induced node faults
            ..ClusterConfig::default()
        };
        let mut cluster = VirtualCluster::new(&nodes, SwimConfig::default(), config, seed);
        cluster.advance(60_000);

        for viewer in &nodes {
            for subject in &nodes {
                if viewer == subject {
                    continue;
                }
                match cluster.view(viewer, subject) {
                    Some(MemberState::Dead | MemberState::Left) => false_positive_deaths += 1,
                    Some(MemberState::Suspect) => transient_suspects += 1,
                    _ => {}
                }
            }
        }
    }

    assert_eq!(
        false_positive_deaths, 0,
        "false-positive deaths under 3% loss across {seeds} seeds: {false_positive_deaths} \
         (transient suspicions observed and allowed: {transient_suspects})"
    );
}
