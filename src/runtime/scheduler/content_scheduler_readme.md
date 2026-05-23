# Content-Aware Scheduler Framework

This document describes the content-aware scheduler framework implemented for ATP-E2, providing priority-based scheduling decisions for data transfers with pressure feedback and evidence logging.

## Overview

The content-aware scheduler is a generic framework that makes intelligent decisions about what content (chunks, streams, repair data) to send next. It supports:

- **Priority Classes**: Deterministic ordering based on content type (control, manifest, proof, data, etc.)
- **Pressure Feedback**: Network, disk, CPU, and memory pressure influence decisions
- **Evidence Logging**: Complete decision audit trail for debugging and replay
- **Stream Integration**: Automatic priority mapping to QUIC/stream-level schedulers
- **Fairness**: Stream-level fairness tracking and enforcement

## Architecture

### Core Components

1. **ContentScheduler** (`src/runtime/scheduler/content.rs`)
   - Priority-based content scheduling with efficiency optimization
   - System pressure integration and throttling
   - Evidence generation for every scheduling decision

2. **StreamPriorityScheduler** (`src/runtime/scheduler/stream_priority.rs`)
   - QUIC stream priority assignment from content classes
   - Stream reuse and fairness tracking
   - Integration between content and stream scheduling

3. **SchedulerIntegration** 
   - Unified API combining content and stream scheduling
   - Automatic stream assignment for content items
   - Statistics and monitoring support

### Priority Classes

The scheduler supports 8 priority classes (highest to lowest):

1. **Control** - Protocol commands and control messages
2. **Manifest** - Directory listings and file metadata  
3. **AckBitmap** - ACK messages and missing chunk bitmaps
4. **Proof** - Cryptographic proofs and verification data
5. **Data** - Bulk data payload
6. **Repair** - Error correction and repair data
7. **Prefetch** - Prefetched content for future use
8. **Telemetry** - Background metrics and telemetry

## Usage Examples

### Basic Content Scheduling

```rust
use asupersync::runtime::scheduler::{
    ContentScheduler, ContentItem, ContentId, PriorityClass
};

let mut scheduler = ContentScheduler::new();

// Schedule different types of content
let control = ContentItem::new(
    ContentId::new(1), 
    PriorityClass::Control, 
    100, // size
    1.0, // cost 
    10.0 // utility
);

let data = ContentItem::new(
    ContentId::new(2), 
    PriorityClass::Data, 
    1024, 
    2.0, 
    5.0
);

scheduler.schedule(control);
scheduler.schedule(data);

// Get next content to send
if let Some((content, evidence)) = scheduler.next_content(now) {
    println!("Sending content {} with reason {:?}", 
             content.id, evidence.reason);
}
```

### Integrated Content and Stream Scheduling

```rust
use asupersync::runtime::scheduler::SchedulerIntegration;

let mut integrated = SchedulerIntegration::new();

// Schedule content with automatic stream assignment
integrated.schedule_content(content_item, now);

// Get content with stream priority
if let Some((content, stream_assignment, evidence)) = integrated.next_content(now) {
    println!("Content {} assigned to stream {} with priority {:?}",
             content.id, stream_assignment.stream_id, stream_assignment.priority);
}
```

### Pressure Feedback

```rust
use asupersync::runtime::scheduler::PressureSnapshot;

let pressure = PressureSnapshot {
    network: 0.8,  // High network pressure
    disk: 0.2,     // Low disk pressure
    cpu: 0.5,      // Medium CPU pressure
    memory: 0.1,   // Low memory pressure
    measured_at: now,
};

scheduler.update_pressure(pressure);

// Scheduler will throttle or adjust decisions based on pressure
```

## Decision Logic

### Priority-Based Scheduling

1. **Priority Class**: Higher priority classes always win
2. **Efficiency Ratio**: Within same class, utility/cost ratio determines order  
3. **FIFO Order**: For identical efficiency, first-scheduled wins
4. **Deterministic Tie-Breaking**: Content ID provides final ordering

### Efficiency Calculation

```rust
efficiency = utility_score / cost_estimate
```

Higher efficiency content is preferred within the same priority class.

### Pressure Throttling

When system pressure exceeds thresholds (80% by default), the scheduler may:
- Throttle low-priority content
- Prefer smaller items to reduce load
- Delay non-critical operations

## Evidence Logging

Every scheduling decision generates evidence containing:

- **Decision ID**: Unique identifier for this decision
- **Selected Content**: The chosen content item
- **Reason**: Why this content was selected (priority, efficiency, FIFO, etc.)
- **Rejected Alternatives**: Up to 3 alternative items considered
- **Pressure Snapshot**: System state at decision time
- **Fairness State**: Stream usage tracking
- **Timestamp**: When decision was made
- **Replay Artifact**: Optional pointer for debugging

## Testing Coverage

The scheduler includes comprehensive tests covering:

### Unit Tests
- Priority class ordering
- FIFO tie-breaking
- Efficiency-based selection
- Pressure throttling
- Evidence logging completeness

### Property Tests
- FIFO ordering invariants
- Priority class ordering invariants
- Deterministic behavior with same inputs

### Integration Tests
- Directory transfer simulation (manifest-first)
- Small-file-first policies
- Prefix-first delivery for early usability
- Sparse missing chunk handling
- Relay-expensive repair scheduling
- Multi-peer rarity considerations
- Disk-stalled receiver scenarios
- Cancellation behavior

### Performance Tests
- Scheduling 1000+ items
- Processing throughput
- Memory usage patterns

## Stream Priority Mapping

Content priority classes map to QUIC stream priorities:

- **Control/Manifest** → Critical (3)
- **AckBitmap/Proof** → Important (2)  
- **Data/Repair** → Normal (1)
- **Prefetch/Telemetry** → Background (0)

This ensures control traffic is never starved by bulk data transfers.

## Monitoring and Observability

### Statistics Available

```rust
let stats = integrated.stats();
println!("Pending content: {}", stats.pending_content_count);
println!("Active streams: {}", stats.active_stream_count);
println!("Evidence log size: {}", stats.evidence_log_size);
```

### Evidence Analysis

```rust
let evidence_log = scheduler.evidence_log();
for evidence in evidence_log {
    println!("Decision {}: selected {} due to {:?}",
             evidence.decision_id, 
             evidence.selected, 
             evidence.reason);
}
```

## Performance Characteristics

- **Scheduling**: O(log n) insertion into priority heap
- **Selection**: O(log n) extraction from heap  
- **Memory**: O(n) for n scheduled items
- **Evidence**: Configurable retention (default: all decisions)

The scheduler is designed for high throughput with thousands of concurrent content items.

## Integration Points

### ATP Transfer Brain
The scheduler integrates with ATP's transfer brain for:
- Chunk selection based on peer availability
- Repair scheduling with ROI calculations
- Path quality feedback

### QUIC Stream Scheduler  
Stream priority assignments flow to:
- Native QUIC stream scheduling
- Bandwidth allocation between streams
- Congestion control decisions

### Runtime Pressure Monitoring
Pressure feedback comes from:
- Network congestion detection
- Disk I/O monitoring
- CPU utilization tracking  
- Memory pressure sensors

## Configuration

### Default Settings
- Max concurrent streams: 256
- Pressure throttle threshold: 80%
- Evidence retention: Unlimited (configurable)
- Stream reuse: Enabled for same priority

### Tuning Parameters
- Priority class weights
- Efficiency calculation weights
- Pressure response curves
- Fairness enforcement policies

## Future Extensions

The framework is designed to support:
- Custom priority policies
- Machine learning-based decisions
- Adaptive efficiency scoring
- Cross-transfer coordination
- Historical performance learning

## Related Components

- **ATP Transfer Brain**: Higher-level transfer coordination
- **QUIC Stream Scheduler**: Stream-level bandwidth allocation
- **Runtime Pressure Governor**: System pressure monitoring
- **Evidence Ledger**: Decision audit and replay system