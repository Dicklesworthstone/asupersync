# Macaroon ↔ Obligation Recovery E2E Integration

This document describes the comprehensive e2e test implementation for cx/macaroon ↔ obligation/recovery integration, focusing on capability attenuation persistence through recovery checkpoints.

## Module Integration

Located in: `src/real_cx_macaroon_obligation_recovery_e2e_tests.rs`

### Core Subsystems

1. **`cx::macaroon`** - Capability tokens with chained HMAC caveats
   - Decentralized attenuation (any holder can add restrictions)
   - HMAC chain signatures for integrity verification
   - First-party caveats (time bounds, scope limits, usage counts)
   - Binary serialization with length-prefixed encoding

2. **`obligation::recovery`** - Self-stabilizing recovery protocol
   - Convergence from any state after failures
   - Conflict resolution (abort-wins policy)
   - Stale obligation timeout handling
   - Linearity violation detection and repair

## Key Integration Features

### Capability Persistence

Tests that macaroon attenuations survive recovery cycles:
1. **Checkpoint Creation** → Capability state snapshot before failure
2. **Recovery Protocol** → Obligation convergence drives system to quiescence
3. **State Restoration** → Capability context rebuilt from checkpoint
4. **Attenuation Verification** → All caveats preserved correctly

### Recovery Scenarios

**Recovery Flow:** `Capability State → Checkpoint → Failure → Recovery → Verification`

**Capability Patterns:**
- **Time-bounded**: `TimeBefore(deadline_ns)` caveats survive time advancement
- **Scope-limited**: `RegionScope(region_id)` restrictions preserved
- **Usage-counted**: `MaxUses(n)` counters maintained through recovery
- **Compound**: Multiple caveats work together consistently

### Attenuation Integrity Guarantees

Verifies that recovery cannot bypass capability restrictions:
- **No Privilege Escalation**: Recovery cannot widen capability scope
- **Attenuation Preservation**: Child capabilities remain properly restricted
- **Verification Consistency**: Identical tokens verify identically before/after
- **Temporal Consistency**: Time-based caveats respect virtual clock

## Test Scenarios

### `test_time_bounded_capability_recovery()`
**Time-Based Attenuation Persistence**

Tests time-bounded capability tokens survive recovery:
1. Create macaroon with `TimeBefore(deadline)` caveat
2. Store capability in mock persistent storage
3. Perform recovery cycle (checkpoint → failure → restore)
4. Verify capability still respects time bounds correctly

**Verification Points:**
- Valid capabilities remain valid after recovery
- Time bounds are preserved exactly
- Virtual clock advancement still affects validity
- Recovery doesn't reset or corrupt timestamps

### `test_expired_capability_after_recovery()`
**Expiry State Preservation**

Tests that expired capabilities remain expired after recovery:
1. Create capability with near-future deadline
2. Advance virtual time past expiration
3. Verify capability fails verification before recovery
4. Perform recovery cycle
5. Confirm capability still fails verification after recovery

**Expiry Properties:**
- Expired capabilities never become valid again
- Time advancement is irreversible
- Recovery cannot resurrect expired tokens
- Expiry state consistent across recovery cycles

### `test_region_scoped_capability_recovery()`
**Scope-Based Attenuation Persistence**

Tests region-scoped capability tokens:
1. Create macaroon with `RegionScope(region_id)` caveat
2. Verify works only within specified region
3. Perform recovery with scope verification
4. Confirm scope restrictions still enforced

**Scope Properties:**
- Region boundaries preserved through recovery
- Scope verification logic unchanged
- No cross-region capability leakage
- Scope context reconstruction accurate

### `test_usage_limited_capability_recovery()`
**Usage Counter Persistence**

Tests usage-limited capability tokens:
1. Create macaroon with `MaxUses(count)` caveat
2. Store with usage counter state
3. Recovery cycle with counter verification
4. Verify usage limits still enforced correctly

**Counter Properties:**
- Usage counters survive recovery cycles
- Counter decrements preserved accurately
- Exhausted capabilities remain exhausted
- Counter overflow/underflow protection maintained

### `test_compound_attenuation_recovery()`
**Multi-Caveat Integration**

Tests capabilities with multiple simultaneous restrictions:
1. Create macaroon with time + scope + usage caveats
2. Verify all caveats evaluated correctly
3. Recovery cycle with compound verification
4. Confirm all restrictions still active

**Compound Properties:**
- All caveats evaluated as conjunction (AND)
- No caveat interference during recovery
- Partial caveat satisfaction insufficient
- Caveat evaluation order irrelevant

### `test_multiple_capabilities_recovery()`
**Bulk Capability Management**

Tests multiple capability types simultaneously:
1. Create diverse capability token set
2. Store all capabilities in recovery system
3. Perform bulk recovery operation
4. Verify each capability type works correctly

**Bulk Properties:**
- Independent capability recovery
- No cross-capability interference
- Consistent recovery behavior across types
- Bulk operation atomicity guarantees

### `test_recovery_under_obligation_load()`
**Load Testing During Recovery**

Tests capability verification under recovery stress:
1. Create many pending obligations (50+)
2. Store capability requiring verification
3. Recovery cycle with high obligation load
4. Verify capability works despite recovery stress

**Load Properties:**
- Recovery scalability with obligation count
- Capability verification unaffected by load
- Recovery governor rate limiting respected
- No capability corruption under stress

### `test_capability_attenuation_integrity()`
**Parent-Child Attenuation Relationship**

Tests that attenuation hierarchy survives recovery:
1. Create parent capability token
2. Create child token by adding caveat
3. Verify child is more restrictive than parent
4. Recovery cycle for both tokens
5. Confirm attenuation relationship preserved

**Attenuation Properties:**
- Child always more restrictive than parent
- Direct attenuation verification preserved
- No attenuation corruption during recovery
- HMAC chain integrity maintained

### `test_recovery_checkpoint_consistency()`
**Checkpoint State Consistency**

Tests multiple checkpoint/restore cycles:
1. Create capability with time-dependent caveats
2. Create sequential checkpoints over time
3. Restore from various checkpoint points
4. Verify capability state consistent with checkpoint time

**Checkpoint Properties:**
- Checkpoint isolation (no cross-contamination)
- Temporal consistency with virtual clock
- Checkpoint ordering preserved
- State divergence detection

### `test_corrupted_capability_recovery_robustness()`
**Recovery from Corrupted State**

Tests recovery robustness against capability corruption:
1. Create valid capability token
2. Checkpoint clean state
3. Simulate capability corruption (invalid caveat)
4. Verify corrupted capability fails
5. Restore from clean checkpoint
6. Confirm capability works again

**Corruption Properties:**
- Corruption detection during verification
- Clean checkpoint restoration
- No silent capability corruption
- Recovery protocol fault isolation

## Test Infrastructure

### `MockCapabilityStore`
Simulated persistent capability storage:
- HashMap-based token storage with thread-safe access
- Root key management for verification
- Checkpoint creation/restoration functionality
- Capability corruption simulation for robustness testing

### `RecoveryScenario`
Integrated test harness for macaroon/recovery scenarios:
- CRDT obligation ledger for realistic recovery protocol
- Recovery governor with configurable policies
- Virtual time management for time-based caveats
- Verification context building with region/task scope

### `CapabilityCheckpoint`
Recovery checkpoint with capability state snapshots:
- Complete token state preservation
- Verification context snapshots
- Temporal consistency tracking
- Checkpoint ordering and identification

### `VerificationContext`
Runtime context for caveat evaluation:
- Virtual time for temporal caveats
- Region/task scope for spatial caveats
- Usage counters for quantitative caveats
- Extensible context for custom predicates

## Real-Service E2E Benefits

### No Mock-Reality Divergence
- Uses actual `MacaroonToken` with real HMAC verification
- Authentic `RecoveryGovernor` with real convergence protocols
- Production-representative capability storage patterns
- Real cryptographic operations and timing

### Integration Bug Detection
- Capability corruption during recovery cycles
- Attenuation bypass via recovery manipulation
- Checkpoint inconsistency across time boundaries
- Caveat evaluation errors under recovery stress

### Production Scenario Modeling
- Realistic failure/recovery patterns
- Authentic capability usage patterns
- Production-scale capability storage
- Complex multi-capability recovery scenarios

## Key Properties Verified

### Cryptographic Integrity
- HMAC chain preservation through recovery
- Signature verification consistency
- No cryptographic corruption during checkpointing
- Root key protection throughout recovery

### Temporal Consistency
- Virtual time advancement irreversibility
- Time-based caveat evaluation accuracy
- Checkpoint temporal ordering
- Deadline preservation across recovery

### Capability Security
- Attenuation monotonicity (only narrowing allowed)
- No privilege escalation via recovery
- Scope boundary enforcement
- Usage limit preservation

### System Robustness
- Recovery convergence under capability load
- Checkpoint state isolation
- Corruption detection and recovery
- Graceful degradation under failures

## Usage

Run the e2e tests with:

```bash
# Run all macaroon-recovery e2e tests
cargo test --lib --features real-service-e2e real_cx_macaroon_obligation_recovery_e2e_tests

# Run specific integration test
cargo test --lib --features real-service-e2e test_compound_attenuation_recovery

# Run with detailed capability logging
cargo test --lib --features real-service-e2e test_recovery_under_obligation_load -- --nocapture
```

### Debugging Failed Tests

When macaroon-recovery integration fails, the structured logging provides:
- Capability verification results with caveat-by-caveat evaluation
- Recovery protocol actions with obligation state transitions
- Checkpoint creation/restoration events with state snapshots
- Attenuation hierarchy verification with HMAC chain details

Example debugging workflow:
1. Review capability verification logs for specific caveat failures
2. Check recovery protocol actions for unexpected obligation state changes
3. Verify checkpoint consistency across temporal boundaries
4. Analyze attenuation hierarchy for privilege escalation attempts

## Advanced Scenarios

### Third-Party Caveat Integration
Tests macaroon third-party caveats with recovery:
- Discharge macaroon handling during recovery
- Binding verification preservation
- Third-party service integration
- Distributed caveat evaluation

### Cross-Region Capability Migration
Tests capability scope changes during recovery:
- Region boundary updates
- Scope migration without privilege escalation
- Cross-region capability consistency
- Migration rollback capabilities

### Capability Revocation During Recovery
Tests capability invalidation scenarios:
- Revocation list updates during recovery
- Revoked capability detection
- Revocation timestamp consistency
- Emergency revocation protocols

### Performance Under Capability Load
Tests recovery behavior with many capabilities:
- Bulk capability verification during recovery
- Capability storage scalability
- Recovery time bounds with capability count
- Memory usage characteristics

This comprehensive e2e testing ensures that the runtime's capability authorization system and obligation recovery infrastructure work together correctly under all realistic operational scenarios, with cryptographic guarantees of attenuation integrity and temporal consistency.