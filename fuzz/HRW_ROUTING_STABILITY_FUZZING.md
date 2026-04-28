# HRW Routing Stability Fuzzing

**Bead**: br-asupersync-7aa9fp  
**Target**: src/transport/router.rs:581-607,828-843  

## Overview

This document describes the HRW (Highest Random Weight) routing stability fuzzer that tests the consistency and stability invariants of the load balancing implementation in the transport router.

## Fuzzer Target

**File**: `fuzz_targets/hrw_routing_stability.rs`  
**Cargo Target**: `hrw_routing_stability`  

The fuzzer specifically targets the HRW routing decisions in:
- Lines 581-607: `select_hrw()` in single endpoint selection
- Lines 828-843: `select_top_k_hrw()` in multi-endpoint selection

## Running the Fuzzer

```bash
cd fuzz
cargo +nightly fuzz run hrw_routing_stability

# With specific parameters
cargo +nightly fuzz run hrw_routing_stability -- -max_total_time=300 -jobs=4

# To minimize found crashes
cargo +nightly fuzz tmin hrw_routing_stability artifacts/hrw_routing_stability/crash-xyz
```

## Test Invariants

The fuzzer validates five key HRW routing stability invariants:

### 1. Routing Determinism
**Property**: Same key → same node (with same endpoints and weights)  
**Test**: Routes the same ObjectId multiple times and verifies identical results  
**Importance**: Critical for sticky sessions and consistent routing behavior  

### 2. Node Addition Stability  
**Property**: Adding nodes should minimize redistribution of existing keys  
**Test**: Routes keys before and after adding endpoints, measures redistribution rate  
**Threshold**: ≤80% of keys should move when nodes are added  
**Importance**: Minimizes cache invalidation and connection churn during scale-out  

### 3. Node Removal Stability
**Property**: Removing nodes should minimize redistribution of keys to remaining nodes  
**Test**: Routes keys, removes some endpoints, re-routes to remaining endpoints  
**Threshold**: ≥70% of eligible keys should stay on the same remaining endpoint  
**Importance**: Ensures graceful degradation and minimal disruption during node failures  

### 4. Weight Change Effects
**Property**: Weight changes should affect routing proportions appropriately  
**Test**: Routes with original weights, modifies weights, verifies distribution changes  
**Importance**: Ensures load balancing responds correctly to capacity changes  

### 5. Top-K Consistency
**Property**: `select()` and `select_n(k=1)` should agree, no duplicates in top-k results  
**Test**: Compares single selection vs. top-1 multi-selection results  
**Importance**: API consistency between single and multi-selection methods  

## Input Structure

The fuzzer uses structured input generation with `arbitrary::Arbitrary`:

```rust
enum HRWFuzzInput {
    RoutingStability { endpoints, keys, salt },
    NodeAddition { initial_endpoints, additional_endpoints, keys, salt },
    NodeRemoval { all_endpoints, removal_indices, keys, salt },
    WeightChanges { endpoints, new_weights, keys, salt },
    TopKConsistency { endpoints, keys, k_values, salt },
}
```

### Endpoint Configuration
```rust
struct HRWEndpointConfig {
    id: u64,        // Endpoint identifier
    weight: u32,    // Load balancing weight
    healthy: bool,  // Whether endpoint can receive traffic
}
```

## Performance Limits

To prevent fuzzer timeouts:
- **Max endpoints**: 50 per test
- **Max keys**: 100 per test  
- **Max k-values**: 10 for top-k testing
- **Test iterations**: Limited per test case

## Implementation Details

### Key Design Decisions

1. **Structured Input**: Uses `arbitrary::Arbitrary` for controlled test generation rather than raw byte manipulation
2. **Endpoint Mocking**: Creates realistic `Endpoint` structs with proper state management
3. **Salt Determinism**: Uses explicit seeds for reproducible routing decisions
4. **Threshold Tuning**: Redistribution thresholds based on HRW mathematical properties

### Endpoint Creation
```rust
fn create_endpoint(config: &HRWEndpointConfig) -> Arc<Endpoint> {
    let mut endpoint = Endpoint::new(
        EndpointId::new(config.id),
        format!("endpoint-{}", config.id)
    ).with_weight(config.weight);

    if !config.healthy {
        endpoint.set_state(EndpointState::Unhealthy);
    }

    Arc::new(endpoint)
}
```

### Load Balancer Setup
```rust
let load_balancer = LoadBalancer::with_seed(LoadBalanceStrategy::HashBased, salt);
```

## Expected Findings

### Likely Issues to Detect
1. **Non-deterministic routing**: Floating point precision issues in HRW scoring
2. **Excessive redistribution**: Suboptimal hash ring implementation
3. **API inconsistencies**: Differences between single and multi-selection paths
4. **Weight handling bugs**: Edge cases with zero weights or overflow
5. **Endpoint state bugs**: Incorrect healthy/unhealthy filtering

### Performance Regressions
- Unexpectedly slow routing decisions
- Memory allocation patterns under stress
- Cache locality issues with large endpoint sets

## Integration with HRW Implementation

The fuzzer directly exercises:

**`src/distributed/consistent_hash.rs`**:
- `select_hrw()` - Single endpoint HRW selection
- `select_top_k_hrw()` - Multi-endpoint HRW selection  
- `hrw_score()` - Core HRW scoring function

**`src/transport/router.rs`**:
- `LoadBalancer::select()` - Single endpoint selection (line 581-607)
- `LoadBalancer::select_n()` - Multi-endpoint selection (line 828-843)

## Relationship to Other Fuzzing

This fuzzer complements:
- **`transport_router.rs`**: Tests broader router functionality (not HRW-specific)
- **`consistent_hash_ring.rs`**: Tests persistent hash ring (different from transient HRW)

The HRW fuzzer focuses specifically on routing stability under dynamic membership changes, which is critical for production load balancing reliability.

## Maintenance

### When to Update
- Changes to HRW scoring algorithm (`hrw_score` function)
- Modifications to LoadBalancer selection logic
- Endpoint state management changes
- Performance threshold adjustments based on production observations

### Regression Testing
Run this fuzzer in CI/CD pipelines with:
- Fixed seed corpus for deterministic regression detection
- Performance benchmarks to detect algorithmic regressions
- Crash reproduction for previously found bugs

## References

- **Bead**: br-asupersync-7aa9jp (original HRW routing stability task)
- **RFC**: Highest Random Weight (HRW) / Rendezvous Hashing algorithm
- **Implementation**: `src/distributed/consistent_hash.rs`
- **Usage**: `src/transport/router.rs` LoadBalancer HashBased strategy