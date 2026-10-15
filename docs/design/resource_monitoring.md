# Resource Monitoring and Degradation Triggers

## Overview

This design defines a resource monitoring system that builds on the existing `ResourceAccounting` infrastructure to implement threshold-based degradation triggers. The system monitors key runtime resources (file descriptors, memory, task count, obligation count, queue depths) and triggers graceful degradation through existing admission control mechanisms when thresholds are exceeded.

The design reuses existing primitives from `observability::resource_accounting`, `spectral_health`, `bulkhead`, and `load_shed` without introducing new abstractions. Resource monitoring operates at both per-region and per-runtime granularity, with operator override capabilities via Cx macaroon attenuation.

## Resource Metrics and Emission Cadence

### Core Metrics

Building on `ResourceAccounting::snapshot()`, the following metrics are monitored:

**Obligation Metrics (per-kind):**
- `reserved_count`, `committed_count`, `aborted_count`, `leaked_count` for each `ObligationKind`
- Total active obligations: `reserved_count + committed_count`
- Obligation leak rate: `leaked_count` delta over time window

**Budget Metrics:**
- `poll_quota_consumed`, `cost_quota_consumed` 
- `deadline_miss_count` for latency SLA violations
- Budget exhaustion rate: quota consumption velocity

**Admission Control Metrics:**
- Current vs limit for `Child`, `Task`, `Obligation`, `HeapBytes`
- Queue depth at admission control boundaries
- Rejection rate per `AdmissionKind`

**System Resources:**
- File descriptor count (via `/proc/self/fd` count)
- Memory usage (RSS from `/proc/self/status`)
- Task count from `TaskTable::active_count()`
- Region count from `RegionTable::active_count()`

### Emission Cadence

**High-frequency (100ms):** Critical safety metrics that can spike rapidly
- Active obligation count
- Admission control queue depths
- Budget exhaustion rates

**Medium-frequency (1s):** Resource utilization trends
- Memory usage, file descriptor count
- Task and region counts
- Obligation leak rates

**Low-frequency (10s):** Baseline health indicators
- High-water marks from `ResourceSnapshot::high_water_marks()`
- Long-term trend analysis for capacity planning

## Threshold-Based Degradation Triggers

### Threshold Types

**Soft Thresholds (80% of limit):**
- Trigger proactive shedding via `load_shed` admission control
- Reduce concurrency limits in `bulkhead` components
- Begin throttling non-critical operations

**Hard Thresholds (95% of limit):**
- Emergency admission rejection for new work
- Cancel low-priority background tasks
- Trigger resource reclamation (GC hints, cache eviction)

### Hysteresis and Decay

**Hysteresis (10% gap):**
- Soft threshold: trigger at 80%, clear at 70%
- Hard threshold: trigger at 95%, clear at 85%
- Prevents thrashing around threshold boundaries

**Exponential Decay (30s half-life):**
- Recent spikes weighted higher than historical averages
- Smooths transient bursts while preserving responsiveness
- Formula: `smoothed_value = 0.977 * prev_value + 0.023 * current_value` (per 100ms)

### Per-Resource Triggers

**File Descriptors:**
- Soft: 80% of `ulimit -n`, reduce connection pooling
- Hard: 95% of `ulimit -n`, reject new connections

**Memory (RSS):**
- Soft: 80% of cgroup limit, enable aggressive cache eviction  
- Hard: 95% of cgroup limit, OOM prevention via admission rejection

**Active Obligations:**
- Soft: 80% of per-region obligation limit, throttle new obligation creation
- Hard: 95% of limit, reject obligation reservation requests

**Task Count:**
- Soft: 80% of `TaskTable` capacity, reduce `spawn_blocking` concurrency
- Hard: 95% of capacity, reject new task spawns

## Integration with Existing Systems

### Spectral Health Integration

The `spectral_health` R1/R2 scoring system provides health assessment that feeds into degradation decisions:

**R1 Score (Responsiveness):**
- Factor in deadline miss rates from budget metrics
- High deadline miss count reduces R1 score
- R1 < 0.7 triggers soft degradation, R1 < 0.4 triggers hard degradation

**R2 Score (Resource Utilization):**
- Incorporate admission control queue depths and rejection rates
- High queue depths or rejection rates reduce R2 score  
- R2 < 0.6 triggers load shedding, R2 < 0.3 triggers emergency admission control

**Combined Health Score:**
- Overall health = min(R1, R2) for conservative assessment
- Health score drives degradation policy selection

### Bulkhead Integration

The `bulkhead` concurrency limiter integrates through dynamic limit adjustment:

**Concurrency Reduction:**
- Soft threshold: reduce bulkhead limits by 20%
- Hard threshold: reduce bulkhead limits by 50%
- Recovery: gradually restore limits as resources recover

**Per-Service Isolation:**
- Critical services maintain higher bulkhead limits during degradation
- Non-critical services get more aggressive limit reductions
- Service priority via Cx capability attestation

### Load Shed Integration

The `load_shed` admission controller provides the primary degradation mechanism:

**Admission Probability:**
- Normal operation: 100% admission
- Soft degradation: admission probability = (1.0 - threshold_excess) * base_rate
- Hard degradation: admission probability = 0.1 (emergency only)

**Request Classification:**
- High-priority requests (Cx capability present): bypass load shedding
- Normal requests: subject to probability-based admission
- Background requests: first to be shed during degradation

**Backpressure Signaling:**
- Rejected requests include `Retry-After` headers with exponential backoff
- Client libraries can implement circuit breaker patterns
- WebSocket connections gracefully close with degradation reason

## Granularity: Per-Region vs Per-Runtime

### Per-Runtime Monitoring (Global)

**System Resources:**
- File descriptors, memory usage tracked globally
- Single threshold enforcement for process-wide limits
- Coordinates degradation across all regions

**Implementation:**
- `RuntimeState::resource_monitor()` singleton
- Atomic counters for cross-region aggregation
- Global admission control at runtime entry points

### Per-Region Monitoring (Granular)

**Obligation Tracking:**
- Each region maintains separate obligation counts via `RegionTable`
- Region-specific thresholds based on expected workload
- Isolation prevents one region's resource exhaustion from affecting others

**Budget Enforcement:**
- Per-region budget allocation from global pool
- Region closure triggers resource reclamation
- Parent-child region hierarchies for budget inheritance

**Hybrid Approach:**
- Global monitoring for system resources (memory, FDs)
- Per-region monitoring for logical resources (obligations, tasks)
- Degradation policies consider both global and regional health

### Resource Attribution

**Task Attribution:**
- Tasks inherit region context via `Cx` propagation
- Resource consumption attributed to originating region
- Cross-region resource transfers tracked explicitly

**Admission Control Points:**
- Runtime entry: global resource check
- Region entry: region-specific resource check  
- Operation entry: combined global + regional assessment

## Operator Override via Cx Capabilities

### Capability-Based Bypass

Operators can override degradation via Cx macaroon capabilities:

**Emergency Override Capability:**
- `emergency.resource_override` capability in Cx macaroon
- Bypasses all admission control and degradation triggers
- Limited time validity (default: 5 minutes) with explicit expiration

**Priority Service Capability:**
- `priority.high` capability reduces degradation impact
- High-priority requests maintain 90% admission during soft degradation
- 50% admission during hard degradation (vs 10% for normal requests)

### Override Implementation

**Capability Verification:**
```rust
impl LoadShedding {
    fn should_admit(&self, cx: &Cx) -> bool {
        // Check for emergency override
        if cx.has_capability("emergency.resource_override") {
            return true;
        }
        
        // Check priority level
        let priority_weight = if cx.has_capability("priority.high") { 0.9 } else { 1.0 };
        let admission_probability = self.base_probability * priority_weight;
        
        thread_rng().gen::<f64>() < admission_probability
    }
}
```

**Capability Attenuation:**
- Operators issue time-limited capability macaroons
- Capabilities automatically attenuate (reduce scope) as they propagate
- Emergency overrides require fresh operator attestation

**Audit Trail:**
- All capability-based overrides logged to audit trail
- Resource monitoring alerts when overrides are active
- Automatic capability revocation on resource recovery

### Configuration Interface

**Static Configuration:**
- Base thresholds configured in `RuntimeConfig`
- Per-resource limits and degradation policies
- Default capability timeout and attenuation rules

**Dynamic Adjustment:**
- Operators can adjust thresholds via admin API
- Configuration changes require capability attestation
- Hot reconfiguration without service restart

**Monitoring Integration:**
- Resource metrics exposed via observability endpoints
- Degradation state visible in health checks
- Integration with external monitoring systems (Prometheus, etc.)