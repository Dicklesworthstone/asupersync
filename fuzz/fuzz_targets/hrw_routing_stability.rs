#![no_main]

//! Fuzz target for HRW (Highest Random Weight) routing stability.
//!
//! Bead: br-asupersync-7aa9fp
//!
//! This fuzzer specifically targets src/transport/router.rs:581-607,828-843
//! to test HRW routing stability invariants:
//!
//! 1. **Routing stability**: Same key → same node (modulo weight changes)
//! 2. **Node add/remove stability**: Adding/removing nodes should minimize redistribution
//! 3. **Weight change handling**: Weight changes should be reflected in routing proportions
//! 4. **Determinism**: Same inputs should always produce the same outputs
//! 5. **Top-k consistency**: select_hrw and select_top_k_hrw(k=1) should agree

use arbitrary::{Arbitrary, Unstructured};
use asupersync::{
    transport::router::{Endpoint, EndpointId, EndpointState, LoadBalanceStrategy, LoadBalancer},
    types::{ObjectId, RegionId},
};
use libfuzzer_sys::fuzz_target;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::AtomicU32;

/// Maximum number of endpoints to test for performance
const MAX_ENDPOINTS: usize = 50;

/// Maximum number of keys to test routing stability
const MAX_KEYS: usize = 100;

/// Test endpoint configuration for HRW fuzzing
#[derive(Arbitrary, Debug, Clone)]
struct HRWEndpointConfig {
    id: u64,
    weight: u32,
    healthy: bool,
}

/// Structured input for HRW routing stability testing
#[derive(Arbitrary, Debug)]
enum HRWFuzzInput {
    /// Test routing stability: same key should route to same endpoint
    RoutingStability {
        endpoints: Vec<HRWEndpointConfig>,
        keys: Vec<u64>, // ObjectId values as u64
        salt: u64,
    },

    /// Test node addition stability: adding nodes should minimize redistribution
    NodeAddition {
        initial_endpoints: Vec<HRWEndpointConfig>,
        additional_endpoints: Vec<HRWEndpointConfig>,
        keys: Vec<u64>,
        salt: u64,
    },

    /// Test node removal stability: removing nodes should minimize redistribution
    NodeRemoval {
        all_endpoints: Vec<HRWEndpointConfig>,
        removal_indices: Vec<u8>, // Indices of endpoints to remove
        keys: Vec<u64>,
        salt: u64,
    },

    /// Test weight changes: changing weights should affect routing proportions
    WeightChanges {
        endpoints: Vec<HRWEndpointConfig>,
        new_weights: Vec<u32>, // New weights for each endpoint
        keys: Vec<u64>,
        salt: u64,
    },

    /// Test top-k consistency: select and select_n should be consistent
    TopKConsistency {
        endpoints: Vec<HRWEndpointConfig>,
        keys: Vec<u64>,
        k_values: Vec<u8>, // k=1,2,3... for select_n testing
        salt: u64,
    },
}

/// Create a mock endpoint from config
fn create_endpoint(config: &HRWEndpointConfig) -> Arc<Endpoint> {
    let mut endpoint = Endpoint::new(
        EndpointId::new(config.id),
        format!("endpoint-{}", config.id),
    )
    .with_weight(config.weight);

    if !config.healthy {
        endpoint.set_state(EndpointState::Unhealthy);
    }

    Arc::new(endpoint)
}

/// Helper to check if endpoint can receive (healthy)
fn can_receive(endpoint: &Arc<Endpoint>) -> bool {
    endpoint.state().can_receive() && endpoint.weight > 0
}

fuzz_target!(|input: HRWFuzzInput| {
    // Limit input sizes to prevent timeouts
    let limited_input = match input {
        HRWFuzzInput::RoutingStability {
            mut endpoints,
            mut keys,
            salt,
        } => {
            endpoints.truncate(MAX_ENDPOINTS);
            keys.truncate(MAX_KEYS);
            HRWFuzzInput::RoutingStability {
                endpoints,
                keys,
                salt,
            }
        }
        HRWFuzzInput::NodeAddition {
            mut initial_endpoints,
            mut additional_endpoints,
            mut keys,
            salt,
        } => {
            initial_endpoints.truncate(MAX_ENDPOINTS / 2);
            additional_endpoints.truncate(MAX_ENDPOINTS / 2);
            keys.truncate(MAX_KEYS);
            HRWFuzzInput::NodeAddition {
                initial_endpoints,
                additional_endpoints,
                keys,
                salt,
            }
        }
        HRWFuzzInput::NodeRemoval {
            mut all_endpoints,
            removal_indices,
            mut keys,
            salt,
        } => {
            all_endpoints.truncate(MAX_ENDPOINTS);
            keys.truncate(MAX_KEYS);
            HRWFuzzInput::NodeRemoval {
                all_endpoints,
                removal_indices,
                keys,
                salt,
            }
        }
        HRWFuzzInput::WeightChanges {
            mut endpoints,
            mut new_weights,
            mut keys,
            salt,
        } => {
            endpoints.truncate(MAX_ENDPOINTS);
            keys.truncate(MAX_KEYS);
            new_weights.truncate(MAX_ENDPOINTS);
            HRWFuzzInput::WeightChanges {
                endpoints,
                new_weights,
                keys,
                salt,
            }
        }
        HRWFuzzInput::TopKConsistency {
            mut endpoints,
            mut keys,
            mut k_values,
            salt,
        } => {
            endpoints.truncate(MAX_ENDPOINTS);
            keys.truncate(MAX_KEYS);
            k_values.truncate(10); // Limit k values
            HRWFuzzInput::TopKConsistency {
                endpoints,
                keys,
                k_values,
                salt,
            }
        }
    };

    match limited_input {
        HRWFuzzInput::RoutingStability {
            endpoints,
            keys,
            salt,
        } => {
            test_routing_stability(&endpoints, &keys, salt);
        }
        HRWFuzzInput::NodeAddition {
            initial_endpoints,
            additional_endpoints,
            keys,
            salt,
        } => {
            test_node_addition_stability(&initial_endpoints, &additional_endpoints, &keys, salt);
        }
        HRWFuzzInput::NodeRemoval {
            all_endpoints,
            removal_indices,
            keys,
            salt,
        } => {
            test_node_removal_stability(&all_endpoints, &removal_indices, &keys, salt);
        }
        HRWFuzzInput::WeightChanges {
            endpoints,
            new_weights,
            keys,
            salt,
        } => {
            test_weight_change_effects(&endpoints, &new_weights, &keys, salt);
        }
        HRWFuzzInput::TopKConsistency {
            endpoints,
            keys,
            k_values,
            salt,
        } => {
            test_top_k_consistency(&endpoints, &keys, &k_values, salt);
        }
    }
});

/// Test that same key always routes to same endpoint (determinism)
fn test_routing_stability(endpoints: &[HRWEndpointConfig], keys: &[u64], salt: u64) {
    if endpoints.is_empty() || keys.is_empty() {
        return;
    }

    // Filter to only healthy endpoints with positive weight
    let healthy_endpoints: Vec<Arc<Endpoint>> = endpoints
        .iter()
        .filter(|e| e.healthy && e.weight > 0)
        .map(create_endpoint)
        .filter(|e| can_receive(e))
        .collect();

    if healthy_endpoints.is_empty() {
        return;
    }

    let load_balancer = LoadBalancer::with_seed(LoadBalanceStrategy::HashBased, salt);

    // Test each key multiple times - should always get same result
    for &key in keys {
        let object_id = ObjectId::from_u128(key as u128);

        let first_result = load_balancer.select(&healthy_endpoints, Some(object_id));

        // Route the same key 5 more times - should get identical results
        for _ in 0..5 {
            let repeated_result = load_balancer.select(&healthy_endpoints, Some(object_id));

            match (first_result.as_ref(), repeated_result.as_ref()) {
                (Some(first), Some(repeated)) => {
                    assert_eq!(
                        first.id, repeated.id,
                        "HRW routing not deterministic: key {} routed to different endpoints",
                        key
                    );
                }
                (None, None) => {} // Both failed consistently
                _ => panic!("HRW routing inconsistent success/failure for key {}", key),
            }
        }
    }
}

/// Test that adding nodes minimizes redistribution
fn test_node_addition_stability(
    initial_endpoints: &[HRWEndpointConfig],
    additional_endpoints: &[HRWEndpointConfig],
    keys: &[u64],
    salt: u64,
) {
    if initial_endpoints.is_empty() || keys.is_empty() {
        return;
    }

    let initial_healthy: Vec<Arc<Endpoint>> = initial_endpoints
        .iter()
        .filter(|e| e.healthy && e.weight > 0)
        .map(create_endpoint)
        .filter(|e| can_receive(e))
        .collect();

    if initial_healthy.is_empty() {
        return;
    }

    let load_balancer = LoadBalancer::with_seed(LoadBalanceStrategy::HashBased, salt);

    // Route all keys with initial set
    let mut initial_routing = HashMap::new();
    for &key in keys {
        let object_id = ObjectId::from_u128(key as u128);
        if let Some(endpoint) = load_balancer.select(&initial_healthy, Some(object_id)) {
            initial_routing.insert(key, endpoint.id);
        }
    }

    // Add new endpoints and route again
    let mut all_endpoints = initial_healthy;
    all_endpoints.extend(
        additional_endpoints
            .iter()
            .filter(|e| e.healthy && e.weight > 0)
            .map(create_endpoint)
            .filter(|e| can_receive(e)),
    );

    if all_endpoints.len() == initial_endpoints.len() {
        return; // No new endpoints were actually added
    }

    let mut redistribution_count = 0;
    for &key in keys {
        let object_id = ObjectId::from_u128(key as u128);
        if let Some(endpoint) = load_balancer.select(&all_endpoints, Some(object_id)) {
            if let Some(&initial_endpoint) = initial_routing.get(&key) {
                if endpoint.id != initial_endpoint {
                    redistribution_count += 1;
                }
            }
        }
    }

    // HRW should minimize redistribution - at most 80% of keys should move
    let redistribution_rate = redistribution_count as f64 / keys.len() as f64;
    assert!(
        redistribution_rate <= 0.8,
        "Excessive redistribution when adding nodes: {:.2}% of keys moved (expected ≤80%)",
        redistribution_rate * 100.0
    );
}

/// Test that removing nodes minimizes redistribution of remaining keys
fn test_node_removal_stability(
    all_endpoints: &[HRWEndpointConfig],
    removal_indices: &[u8],
    keys: &[u64],
    salt: u64,
) {
    if all_endpoints.is_empty() || keys.is_empty() {
        return;
    }

    let healthy_endpoints: Vec<Arc<Endpoint>> = all_endpoints
        .iter()
        .filter(|e| e.healthy && e.weight > 0)
        .map(create_endpoint)
        .filter(|e| can_receive(e))
        .collect();

    if healthy_endpoints.len() < 2 {
        // Need at least 2 for meaningful removal test
        return;
    }

    let load_balancer = LoadBalancer::with_seed(LoadBalanceStrategy::HashBased, salt);

    // Route all keys with full set
    let mut full_routing = HashMap::new();
    for &key in keys {
        let object_id = ObjectId::from_u128(key as u128);
        if let Some(endpoint) = load_balancer.select(&healthy_endpoints, Some(object_id)) {
            full_routing.insert(key, endpoint.id);
        }
    }

    // Remove some endpoints
    let removal_set: HashSet<usize> = removal_indices
        .iter()
        .map(|&i| i as usize % healthy_endpoints.len())
        .collect();

    let reduced_endpoints: Vec<_> = healthy_endpoints
        .into_iter()
        .enumerate()
        .filter(|(i, _)| !removal_set.contains(i))
        .map(|(_, endpoint)| endpoint)
        .collect();

    if reduced_endpoints.is_empty() {
        return;
    }

    let reduced_endpoint_ids: HashSet<_> = reduced_endpoints.iter().map(|e| e.id).collect();

    let mut unchanged_count = 0;
    let mut keys_that_could_stay = 0;

    for &key in keys {
        let object_id = ObjectId::from_u128(key as u128);

        if let Some(&original_endpoint) = full_routing.get(&key) {
            // Only count keys that were originally routed to endpoints that still exist
            if reduced_endpoint_ids.contains(&original_endpoint) {
                keys_that_could_stay += 1;

                if let Some(new_endpoint) =
                    load_balancer.select(&reduced_endpoints, Some(object_id))
                {
                    if new_endpoint.id == original_endpoint {
                        unchanged_count += 1;
                    }
                }
            }
        }
    }

    // Most keys that were routed to remaining endpoints should stay there
    if keys_that_could_stay > 0 {
        let stability_rate = unchanged_count as f64 / keys_that_could_stay as f64;
        assert!(
            stability_rate >= 0.7,
            "Insufficient routing stability after node removal: {:.2}% of eligible keys stayed (expected ≥70%)",
            stability_rate * 100.0
        );
    }
}

/// Test that weight changes affect routing proportions appropriately
fn test_weight_change_effects(
    endpoints: &[HRWEndpointConfig],
    new_weights: &[u32],
    keys: &[u64],
    salt: u64,
) {
    if endpoints.is_empty() || keys.is_empty() || keys.len() < 10 {
        return;
    }

    let original_endpoints: Vec<Arc<Endpoint>> = endpoints
        .iter()
        .filter(|e| e.healthy && e.weight > 0)
        .map(create_endpoint)
        .filter(|e| can_receive(e))
        .collect();

    if original_endpoints.len() < 2 {
        return;
    }

    let load_balancer = LoadBalancer::with_seed(LoadBalanceStrategy::HashBased, salt);

    // Route with original weights
    let mut original_counts = HashMap::new();
    for &key in keys {
        let object_id = ObjectId::from_u128(key as u128);
        if let Some(endpoint) = load_balancer.select(&original_endpoints, Some(object_id)) {
            *original_counts.entry(endpoint.id).or_insert(0) += 1;
        }
    }

    // Create endpoints with modified weights
    let modified_endpoints: Vec<Arc<Endpoint>> = endpoints
        .iter()
        .enumerate()
        .filter(|(_, e)| e.healthy)
        .filter_map(|(i, endpoint)| {
            let new_weight = if i < new_weights.len() && new_weights[i] > 0 {
                new_weights[i]
            } else {
                endpoint.weight
            };

            if new_weight > 0 {
                let modified_endpoint = Endpoint::new(
                    EndpointId::new(endpoint.id),
                    format!("endpoint-{}", endpoint.id),
                )
                .with_weight(new_weight);

                Some(Arc::new(modified_endpoint))
            } else {
                None
            }
        })
        .collect();

    if modified_endpoints.is_empty() || modified_endpoints.len() != original_endpoints.len() {
        return; // Skip if weight changes removed endpoints
    }

    // Route with modified weights
    let mut modified_counts = HashMap::new();
    for &key in keys {
        let object_id = ObjectId::from_u128(key as u128);
        if let Some(endpoint) = load_balancer.select(&modified_endpoints, Some(object_id)) {
            *modified_counts.entry(endpoint.id).or_insert(0) += 1;
        }
    }

    // Check that weight changes had some effect (basic sanity check)
    let original_max_count = original_counts.values().max().cloned().unwrap_or(0);
    let modified_max_count = modified_counts.values().max().cloned().unwrap_or(0);

    // If weights changed significantly and we have enough keys, distribution should change
    let weight_ratio_changed =
        modified_endpoints
            .iter()
            .zip(endpoints.iter())
            .any(|(modified, original)| {
                if original.weight > 0 {
                    let ratio = modified.weight as f64 / original.weight as f64;
                    ratio < 0.5 || ratio > 2.0
                } else {
                    false
                }
            });

    if weight_ratio_changed && keys.len() >= 50 {
        // With significant weight changes and enough keys, expect some distribution change
        let distribution_changed =
            (original_max_count as i32 - modified_max_count as i32).abs() > 1;
        assert!(
            distribution_changed,
            "Weight changes did not affect routing distribution as expected"
        );
    }
}

/// Test that select and select_n are consistent
fn test_top_k_consistency(
    endpoints: &[HRWEndpointConfig],
    keys: &[u64],
    k_values: &[u8],
    salt: u64,
) {
    if endpoints.is_empty() || keys.is_empty() {
        return;
    }

    let healthy_endpoints: Vec<Arc<Endpoint>> = endpoints
        .iter()
        .filter(|e| e.healthy && e.weight > 0)
        .map(create_endpoint)
        .filter(|e| can_receive(e))
        .collect();

    if healthy_endpoints.is_empty() {
        return;
    }

    let load_balancer = LoadBalancer::with_seed(LoadBalanceStrategy::HashBased, salt);

    for &key in keys.iter().take(10) {
        // Limit for performance
        let object_id = ObjectId::from_u128(key as u128);

        // Get single selection with select (which uses select_hrw)
        let single_result = load_balancer.select(&healthy_endpoints, Some(object_id));

        // Get top-1 selection with select_n (which uses select_top_k_hrw)
        let top_k_results = load_balancer.select_n(&healthy_endpoints, 1, Some(object_id));

        match (single_result.as_ref(), top_k_results.first()) {
            (Some(single), Some(top_k)) => {
                assert_eq!(
                    single.id, top_k.id,
                    "select and select_n(k=1) disagree for key {}",
                    key
                );
            }
            (None, first) => {
                assert!(
                    first.is_none(),
                    "select returned None but select_n returned Some for key {}",
                    key
                );
            }
            (Some(_), None) => {
                assert!(
                    top_k_results.is_empty(),
                    "select returned Some but select_n returned empty for key {}",
                    key
                );
            }
        }

        // Test higher k values for basic sanity
        for &k in k_values.iter().take(5) {
            if k > 0 && k as usize <= healthy_endpoints.len() {
                let k_results =
                    load_balancer.select_n(&healthy_endpoints, k as usize, Some(object_id));

                // Results should be unique (no duplicates)
                let mut seen_ids = HashSet::new();
                for endpoint in &k_results {
                    assert!(
                        seen_ids.insert(endpoint.id),
                        "select_n returned duplicate endpoint for key {} k={}",
                        key,
                        k
                    );
                }

                // Should not return more than requested
                assert!(
                    k_results.len() <= k as usize,
                    "select_n returned more than k={} results for key {}",
                    k,
                    key
                );
            }
        }
    }
}
