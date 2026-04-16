# OpenTelemetry Structured Concurrency Integration Design

## Overview

This document specifies the design for native OpenTelemetry tracing integration in asupersync, providing unprecedented observability into structured concurrency execution without manual instrumentation.

## Background

Asupersync's structured concurrency creates natural observability boundaries through:
- **Region hierarchy**: Ownership tree of execution scopes
- **Task lifecycle**: Spawn, execution, completion/cancellation  
- **Cancellation protocol**: Request → drain → finalize lifecycle
- **Obligation tracking**: Resource management with commit/abort semantics

Current state includes foundational observability infrastructure:
- `SpanId` and `DiagnosticContext` types in the `Cx` context
- OpenTelemetry metrics provider (`OtelMetrics`)
- Structured logging via `LogCollector`
- Task/region identity tracking

## Design Goals

1. **Zero Manual Instrumentation**: Automatic span creation for all structured concurrency operations
2. **Hierarchical Tracing**: Perfect parent-child relationships matching structured concurrency ownership
3. **Performance**: <2% runtime overhead via lazy span creation and efficient storage
4. **Rich Context**: Spans contain structured concurrency semantic information
5. **Integration**: Works with existing `Cx` context and observability infrastructure

## Span Hierarchy Design

### Span Types

| Span Type | Lifecycle | Parent | Key Attributes |
|-----------|-----------|---------|----------------|
| **Region** | Region creation → quiescence | Parent region | `region_id`, `region_limits`, `child_count` |
| **Task** | Task spawn → completion/cancel | Parent region | `task_id`, `task_name`, `spawn_location` |
| **Operation** | IO/timer/channel start → complete | Current task | `operation_type`, `resource_id`, `timeout` |
| **Cancel** | Cancel request → drain complete | Cancelling entity | `cancel_reason`, `affected_entities`, `drain_time` |

### Span Hierarchy Example

```
Region(root) [trace_id=T1]
├── Region(http_server) [parent=root]
│   ├── Task(accept_connections) [parent=http_server]
│   │   ├── Operation(tcp_accept) [parent=accept_connections]
│   │   └── Operation(spawn_handler) [parent=accept_connections]
│   ├── Task(handle_request_123) [parent=http_server]
│   │   ├── Operation(read_request) [parent=handle_request_123]
│   │   ├── Region(process_auth) [parent=http_server]
│   │   │   ├── Task(validate_token) [parent=process_auth]
│   │   │   └── Operation(db_query) [parent=validate_token]
│   │   └── Operation(write_response) [parent=handle_request_123]
│   └── Cancel(shutdown_requested) [parent=http_server]
│       ├── Cancel(drain_connections) [parent=shutdown_requested]
│       └── Cancel(close_regions) [parent=shutdown_requested]
```

## Implementation Strategy

### 1. Span Context Storage

Extend `ObservabilityState` in `Cx` to include OpenTelemetry span context:

```rust
#[derive(Debug, Clone)]
pub struct ObservabilityState {
    // Existing fields...
    collector: Option<LogCollector>,
    context: DiagnosticContext,
    trace: Option<TraceBufferHandle>,
    
    // New OpenTelemetry integration
    otel_context: Option<OtelContext>,
    span_stack: Vec<ActiveSpan>,
    lazy_spans: HashMap<EntityId, PendingSpan>,
}

#[derive(Debug, Clone)]
pub struct OtelContext {
    trace_id: opentelemetry::TraceId,
    parent_span_id: Option<opentelemetry::SpanId>,
    trace_flags: opentelemetry::TraceFlags,
    trace_state: opentelemetry::TraceState,
}

#[derive(Debug)]
pub struct ActiveSpan {
    span: opentelemetry::trace::Span,
    span_type: SpanType,
    entity_id: EntityId,
    start_time: Time,
}
```

### 2. Lazy Span Creation

Implement lazy span creation to minimize overhead:

```rust
#[derive(Debug)]
pub struct PendingSpan {
    span_type: SpanType,
    entity_id: EntityId,
    attributes: HashMap<String, opentelemetry::Value>,
    start_time: Time,
    parent_context: Option<OtelContext>,
}

impl PendingSpan {
    fn materialize(&self, tracer: &opentelemetry::trace::Tracer) -> opentelemetry::trace::Span {
        let mut span_builder = tracer.span_builder(self.span_name());
        span_builder = span_builder.with_start_time(self.start_time.into());
        
        if let Some(parent) = &self.parent_context {
            span_builder = span_builder.with_parent_context(&parent.as_context());
        }
        
        for (key, value) in &self.attributes {
            span_builder = span_builder.with_attributes([opentelemetry::KeyValue::new(key.clone(), value.clone())]);
        }
        
        span_builder.start(tracer)
    }
}
```

### 3. Integration Points

#### Region Creation Hook

In `RegionTable::create_region()`:

```rust
pub fn create_region(
    &mut self,
    parent: Option<RegionId>,
    limits: RegionLimits,
    cx: &Cx,
) -> Result<RegionId, RegionCreateError> {
    let region_id = self.allocate_region_id();
    
    // Existing region creation logic...
    
    // Create region span
    if let Some(tracer) = cx.otel_tracer() {
        cx.create_region_span(region_id, parent, &limits);
    }
    
    Ok(region_id)
}
```

#### Task Spawn Hook

In `TaskTable::spawn_task()`:

```rust
pub fn spawn<T>(
    &mut self,
    region: RegionId,
    future: T,
    cx: &Cx,
) -> Result<TaskId, SpawnError> 
where
    T: Future + Send + 'static,
{
    let task_id = self.allocate_task_id();
    
    // Existing task spawn logic...
    
    // Create task span  
    if let Some(tracer) = cx.otel_tracer() {
        cx.create_task_span(task_id, region, std::any::type_name::<T>());
    }
    
    Ok(task_id)
}
```

#### Operation Span Creation

New method in `Cx` for IO/timer/channel operations:

```rust
impl<Caps> Cx<Caps> {
    pub fn enter_operation_span<T>(&self, operation_type: &str, resource_id: &str) -> OperationSpanGuard<T> {
        if let Some(tracer) = self.otel_tracer() {
            let span = self.create_operation_span(operation_type, resource_id);
            OperationSpanGuard::new(span, self.observability.clone())
        } else {
            OperationSpanGuard::noop()
        }
    }
}

pub struct OperationSpanGuard<T> {
    span: Option<opentelemetry::trace::Span>,
    observability: Arc<parking_lot::RwLock<ObservabilityState>>,
    _phantom: std::marker::PhantomData<T>,
}

impl<T> Drop for OperationSpanGuard<T> {
    fn drop(&mut self) {
        if let Some(span) = self.span.take() {
            span.end();
        }
    }
}
```

### 4. Context Propagation Strategy

#### Automatic Parent-Child Relationships

Context propagation leverages the existing structured concurrency guarantees:

1. **Region spans**: Inherit from parent region context in `Cx`
2. **Task spans**: Inherit from region context where task is spawned  
3. **Operation spans**: Inherit from current task context
4. **Cancel spans**: Inherit from entity being cancelled

#### Cross-Async-Boundary Propagation

```rust
impl<Caps> Cx<Caps> {
    pub fn fork_for_child_region(&self, child_region: RegionId) -> Self {
        let mut child_cx = self.clone();
        
        // Update observability state to inherit span context
        {
            let mut obs = child_cx.observability.write();
            obs.context = obs.context.fork()
                .with_region_id(child_region)
                .with_parent_span_id(obs.context.span_id());
                
            // Propagate OpenTelemetry context
            if let Some(otel_ctx) = &obs.otel_context {
                obs.otel_context = Some(otel_ctx.fork_for_child());
            }
        }
        
        child_cx
    }
}
```

### 5. Performance Optimization

#### Sampling Strategy

```rust
#[derive(Debug, Clone)]
pub struct OtelStructuredConcurrencyConfig {
    /// Global trace sampling rate (0.0-1.0)
    pub global_sample_rate: f64,
    
    /// Per-span-type sampling rates
    pub span_type_rates: HashMap<SpanType, f64>,
    
    /// Always sample these span types regardless of global rate
    pub always_sample: HashSet<SpanType>,
    
    /// Maximum concurrent active spans to prevent memory exhaustion
    pub max_active_spans: usize,
    
    /// Lazy span materialization threshold (materialize after N operations)
    pub lazy_threshold: usize,
}

impl Default for OtelStructuredConcurrencyConfig {
    fn default() -> Self {
        let mut always_sample = HashSet::new();
        always_sample.insert(SpanType::Cancel); // Always trace cancellation
        
        Self {
            global_sample_rate: 0.1, // 10% sampling by default
            span_type_rates: HashMap::new(),
            always_sample,
            max_active_spans: 10_000,
            lazy_threshold: 5,
        }
    }
}
```

#### Efficient Span Storage

```rust
/// Lock-free span storage optimized for structured concurrency
#[derive(Debug)]
pub struct SpanStorage {
    /// Ring buffer for active spans
    active_spans: parking_lot::RwLock<HashMap<EntityId, ActiveSpan>>,
    
    /// Pending spans awaiting materialization
    pending_spans: parking_lot::RwLock<HashMap<EntityId, PendingSpan>>,
    
    /// Span context cache for context propagation
    context_cache: parking_lot::RwLock<HashMap<EntityId, OtelContext>>,
    
    /// Performance counters
    stats: SpanStorageStats,
}

#[derive(Debug, Default)]
pub struct SpanStorageStats {
    pub spans_created: std::sync::atomic::AtomicU64,
    pub spans_materialized: std::sync::atomic::AtomicU64,
    pub context_cache_hits: std::sync::atomic::AtomicU64,
    pub context_cache_misses: std::sync::atomic::AtomicU64,
}
```

### 6. Span Attributes Schema

#### Region Spans

```yaml
span.name: "region_lifecycle"
attributes:
  asupersync.entity.type: "region"
  asupersync.entity.id: "R12345"
  asupersync.region.parent_id: "R12340" # Optional
  asupersync.region.limits.max_tasks: 1000
  asupersync.region.limits.max_obligations: 500
  asupersync.region.child_count: 3
  asupersync.region.state: "active" | "draining" | "closed"
```

#### Task Spans

```yaml
span.name: "task_execution"  
attributes:
  asupersync.entity.type: "task"
  asupersync.entity.id: "T67890"
  asupersync.task.region_id: "R12345"
  asupersync.task.name: "HttpRequestHandler"
  asupersync.task.spawn_location: "src/server.rs:142"
  asupersync.task.outcome: "completed" | "cancelled" | "panicked"
  asupersync.task.cancel_reason: "parent_cancelled" # If cancelled
```

#### Operation Spans

```yaml
span.name: "io_operation"
attributes:
  asupersync.entity.type: "operation" 
  asupersync.operation.type: "tcp_read" | "timer_sleep" | "channel_send"
  asupersync.operation.resource_id: "TcpStream-192.168.1.100:8080"
  asupersync.operation.timeout_ms: 5000
  asupersync.operation.outcome: "completed" | "timeout" | "cancelled"
  asupersync.operation.bytes_transferred: 1024 # For IO operations
```

#### Cancel Spans

```yaml
span.name: "cancellation_event"
attributes:
  asupersync.entity.type: "cancel"
  asupersync.cancel.reason: "user_requested" | "timeout" | "parent_cancelled"
  asupersync.cancel.initiator_id: "T67890"
  asupersync.cancel.affected_regions: ["R12345", "R12346"]
  asupersync.cancel.affected_tasks: ["T67891", "T67892"]
  asupersync.cancel.drain_duration_ms: 150
```

### 7. Configuration and Integration

#### Runtime Builder Integration

```rust
use asupersync::runtime::RuntimeBuilder;
use asupersync::observability::otel::OtelStructuredConcurrencyConfig;

let otel_config = OtelStructuredConcurrencyConfig::default()
    .with_global_sample_rate(0.05) // 5% sampling
    .with_span_type_sample_rate(SpanType::Cancel, 1.0); // Always sample cancellation

let runtime = RuntimeBuilder::new()
    .with_otel_structured_concurrency(otel_config)
    .build()?;
```

#### Tracer Integration

```rust
use opentelemetry::global;
use opentelemetry_sdk::trace::TracerProvider;

// Set up OpenTelemetry tracer
let tracer_provider = TracerProvider::builder()
    .with_batch_exporter(/* your exporter */)
    .build();
global::set_tracer_provider(tracer_provider);

// Runtime automatically uses global tracer
let runtime = RuntimeBuilder::new()
    .with_otel_structured_concurrency(otel_config)
    .build()?;
```

## Success Metrics

### Performance Requirements

- **Overhead**: <2% runtime performance impact with 10% sampling
- **Memory**: <1MB additional memory usage per 1000 active spans
- **Latency**: <10μs per span creation operation

### Observability Goals

- **Complete Hierarchy**: 100% of structured concurrency operations traced
- **Context Propagation**: Perfect parent-child relationships
- **Rich Context**: All relevant structured concurrency semantics captured
- **Backend Compatibility**: Works with Jaeger, Zipkin, and other OTel receivers

### Test Coverage

- **Unit Tests**: Span creation, context propagation, sampling logic
- **Integration Tests**: Full trace collection with various backends
- **Performance Tests**: Overhead measurement and regression detection
- **Chaos Tests**: Trace integrity under cancellation and failure scenarios

## Implementation Phases

### Phase 1: Core Infrastructure (Week 1)
- [ ] Extend `ObservabilityState` with OTel context storage
- [ ] Implement lazy span creation mechanism
- [ ] Basic region and task span creation hooks
- [ ] Unit tests for span lifecycle

### Phase 2: Context Propagation (Week 2)  
- [ ] Implement context propagation through structured concurrency
- [ ] Parent-child relationship establishment
- [ ] Cross-async-boundary context threading
- [ ] Integration tests for span hierarchy

### Phase 3: Operation and Cancel Spans (Week 3)
- [ ] Operation span creation for IO/timer/channel operations  
- [ ] Cancellation event tracing
- [ ] Span attribute schema implementation
- [ ] End-to-end trace validation

### Phase 4: Performance and Production (Week 4)
- [ ] Sampling strategy implementation
- [ ] Performance optimization and measurement
- [ ] Configuration and runtime integration
- [ ] Documentation and examples

## Migration Strategy

### Backward Compatibility

The implementation maintains full backward compatibility:
- Existing code continues to work without changes
- OTel integration is opt-in via feature flags and configuration
- No changes to public APIs or structured concurrency semantics
- Graceful degradation when OTel is not configured

### Incremental Adoption

Teams can adopt incrementally:
1. **Start with sampling**: Enable with low sample rates
2. **Add backend integration**: Connect to existing observability infrastructure  
3. **Increase coverage**: Gradually increase sampling rates
4. **Custom dashboards**: Build structured concurrency specific visualizations

This design provides production-grade distributed tracing for structured concurrency with minimal performance overhead and zero code changes required for adoption.