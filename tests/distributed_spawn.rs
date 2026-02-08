use asupersync::cx::Cx;
use asupersync::lab::network::{DistributedHarness, NetworkConfig};
use asupersync::remote::{spawn_remote, ComputationName, NodeId, RemoteInput};
use std::time::Duration;

#[test]
fn test_distributed_spawn_virtual_runtime() {
    // 1. Setup harness
    let config = NetworkConfig {
        default_conditions: asupersync::lab::network::NetworkConditions::local(),
        ..NetworkConfig::default()
    };
    let mut harness = DistributedHarness::new(config);
    let node_a = harness.add_node("node-a");
    let node_b = harness.add_node("node-b");

    // 2. Create Cx for Node A with virtual runtime
    // We need to look up the node to get its "SimNode" which has the virtual runtime factories
    let sim_node_a = harness.node(&node_a).expect("Node A not found");
    let cap = sim_node_a.create_cap();

    // Create a context for testing that carries this capability
    let cx = Cx::for_testing().with_remote_cap(cap);

    // 3. Spawn remote task on Node B (from Node A's perspective)
    println!("Spawning remote task from A to B...");
    let handle = spawn_remote(
        &cx,
        node_b.clone(),
        ComputationName::new("test-computation"),
        RemoteInput::new(vec![]),
    )
    .expect("spawn_remote failed");

    // 4. Drive the simulation until completion
    println!("Driving simulation...");
    let mut finished = false;
    // Run for up to 1 second of simulated time
    for _ in 0..100 {
        // Step the harness by 10ms
        harness.run_for(Duration::from_millis(10));

        // Check if finished
        match handle.try_join() {
            Ok(Some(result)) => {
                println!("Remote task finished with result: {:?}", result);
                assert!(result.is_success());
                finished = true;
                break;
            }
            Ok(None) => {
                // Still running
            }
            Err(e) => {
                panic!("Remote task failed: {:?}", e);
            }
        }
    }

    assert!(finished, "Remote task did not complete in time");

    // 5. Verify harness trace
    let trace = harness.trace();
    // We expect a SpawnRequest sent A -> B
    let sent = trace.iter().any(|e| {
        if let asupersync::lab::network::HarnessTraceKind::MessageSent { from, to, msg_type } =
            &e.kind
        {
            from == &node_a && to == &node_b && msg_type == "SpawnRequest"
        } else {
            false
        }
    });
    assert!(sent, "SpawnRequest not found in trace");

    // We expect a ResultDelivery sent B -> A
    let result_sent = trace.iter().any(|e| {
        if let asupersync::lab::network::HarnessTraceKind::MessageSent { from, to, msg_type } =
            &e.kind
        {
            from == &node_b && to == &node_a && msg_type == "ResultDelivery"
        } else {
            false
        }
    });
    assert!(result_sent, "ResultDelivery not found in trace");
}
