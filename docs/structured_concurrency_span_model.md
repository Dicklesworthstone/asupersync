# Structured Concurrency Span Model Design

## Overview

This document defines the span model for OpenTelemetry integration with asupersync's structured concurrency primitives. The model ensures that every structured concurrency operation creates appropriate spans with perfect hierarchical relationships.

## Span Model Principles

### 1. Ownership-Based Hierarchy

Spans follow the structured concurrency ownership tree exactly:
- **Region spans** own all child region and task spans
- **Task spans** are owned by their parent region span  
- **Operation spans** are owned by the task that initiated them
- **Cancellation spans** are owned by the entity that initiated cancellation

### 2. Automatic Lifecycle Tracking

Spans are created and closed automatically at structured concurrency boundaries:
- **Region spans**: `region_create()` → `region_quiescence()`
- **Task spans**: `task_spawn()` → `task_complete()/task_cancel()`
- **Operation spans**: `operation_start()` → `operation_complete()/operation_cancel()`
- **Cancel spans**: `cancel_request()` → `cancel_drain_complete()`

### 3. Context Propagation Guarantees

Span context flows through structured concurrency exactly as `Cx` does:
- Child regions inherit span context from parent region
- Tasks inherit span context from spawning region
- Operations inherit span context from executing task
- Cancellation inherits span context from cancelled entity

## Span Type Definitions

### Region Spans

**Purpose**: Track region lifecycle from creation to quiescence

**Lifecycle**:
```rust
// Span creation
fn create_region(&mut self, parent: Option<RegionId>, limits: RegionLimits, cx: &Cx) {
    cx.create_region_span(region_id, parent, &limits);
}

// Span completion
fn close_region(&mut self, region_id: RegionId, cx: &Cx) {
    cx.complete_region_span(region_id, RegionOutcome::Quiescence);
}
```

**Attributes**:
```yaml
span.name: "asupersync.region"
span.kind: SPAN_KIND_INTERNAL
attributes:
  asupersync.entity.type: "region"
  asupersync.entity.id: "R12345"
  asupersync.region.parent_id: "R12340"  # Optional
  asupersync.region.limits.max_tasks: 1000
  asupersync.region.limits.max_obligations: 500
  asupersync.region.outcome: "quiescence" | "cancelled" | "panicked"
  asupersync.region.child_regions: 3
  asupersync.region.child_tasks: 15
  asupersync.region.duration_ms: 1250
```

**Events**:
- `region.task_spawned`: When a task is spawned in the region
- `region.child_region_created`: When a child region is created
- `region.cancellation_requested`: When cancellation is requested
- `region.draining_started`: When the region starts draining
- `region.quiescence_achieved`: When all children complete

### Task Spans

**Purpose**: Track task execution from spawn to completion

**Lifecycle**:
```rust
// Span creation
fn spawn_task<T>(&mut self, region: RegionId, future: T, cx: &Cx) -> TaskId {
    let task_id = self.allocate_task_id();
    cx.create_task_span(task_id, region, std::any::type_name::<T>(), source_location);
    task_id
}

// Span completion
fn complete_task(&mut self, task_id: TaskId, outcome: TaskOutcome, cx: &Cx) {
    cx.complete_task_span(task_id, outcome);
}
```

**Attributes**:
```yaml
span.name: "asupersync.task"
span.kind: SPAN_KIND_INTERNAL
attributes:
  asupersync.entity.type: "task"
  asupersync.entity.id: "T67890"
  asupersync.task.region_id: "R12345"
  asupersync.task.name: "HttpRequestHandler"
  asupersync.task.future_type: "impl Future<Output=Response>"
  asupersync.task.spawn_location: "src/server.rs:142:25"
  asupersync.task.outcome: "completed" | "cancelled" | "panicked"
  asupersync.task.cancel_reason: "parent_cancelled" | "timeout" | "explicit"
  asupersync.task.poll_count: 15
  asupersync.task.duration_ms: 85
```

**Events**:
- `task.polled`: Each time the task future is polled
- `task.yielded`: When the task yields execution
- `task.cancellation_received`: When task observes cancellation signal
- `task.panicked`: If the task panics (with panic message)

### Operation Spans

**Purpose**: Track individual I/O and timer operations with cancellation semantics

**Lifecycle**:
```rust
impl Cx {
    pub fn enter_operation_span(&self, operation_type: &str, resource_id: &str) -> OperationSpanGuard {
        let span = self.create_operation_span(operation_type, resource_id);
        OperationSpanGuard::new(span, self.clone())
    }
}

// RAII guard ensures span completion
impl Drop for OperationSpanGuard {
    fn drop(&mut self) {
        self.cx.complete_operation_span(self.operation_id, self.outcome);
    }
}
```

**Attributes**:
```yaml
span.name: "asupersync.operation"
span.kind: SPAN_KIND_CLIENT  # Most operations are outbound
attributes:
  asupersync.entity.type: "operation"
  asupersync.operation.type: "tcp_read" | "timer_sleep" | "channel_send" | "file_write"
  asupersync.operation.resource_id: "TcpStream-192.168.1.100:8080"
  asupersync.operation.timeout_ms: 5000
  asupersync.operation.outcome: "completed" | "timeout" | "cancelled" | "error"
  asupersync.operation.bytes_transferred: 1024  # For IO operations
  asupersync.operation.error_kind: "connection_reset"  # If error
  asupersync.operation.duration_ms: 45
```

**Events**:
- `operation.started`: Operation initiation with parameters
- `operation.progress`: For long-running operations (bytes transferred, etc.)
- `operation.cancelled`: When operation is cancelled
- `operation.error`: Error details if operation fails

### Cancellation Spans

**Purpose**: Track cancellation propagation and drain operations

**Lifecycle**:
```rust
// Cancellation span creation
fn request_cancellation(&mut self, target: EntityId, reason: CancelReason, cx: &Cx) {
    let cancel_id = self.next_cancel_id();
    cx.create_cancellation_span(cancel_id, target, reason);
    
    // Span completes when drain is finished
    self.propagate_cancellation_with_span(target, cancel_id, cx);
}

fn complete_cancellation_drain(&mut self, cancel_id: u64, affected_entities: &[EntityId], cx: &Cx) {
    cx.complete_cancellation_span(cancel_id, affected_entities);
}
```

**Attributes**:
```yaml
span.name: "asupersync.cancellation"
span.kind: SPAN_KIND_INTERNAL
attributes:
  asupersync.entity.type: "cancellation"
  asupersync.cancel.id: "C42"
  asupersync.cancel.target_id: "R12345"
  asupersync.cancel.target_type: "region"
  asupersync.cancel.reason: "user_requested" | "timeout" | "parent_cancelled" | "error"
  asupersync.cancel.initiator_id: "T67890"
  asupersync.cancel.affected_regions: ["R12345", "R12346"]
  asupersync.cancel.affected_tasks: ["T67891", "T67892"]  
  asupersync.cancel.drain_duration_ms: 150
  asupersync.cancel.drain_outcome: "completed" | "timeout" | "forced"
```

**Events**:
- `cancel.propagation_started`: When cancellation begins propagating
- `cancel.entity_notified`: Each entity that receives cancellation signal
- `cancel.entity_drained`: Each entity that completes draining
- `cancel.drain_timeout`: If drain takes longer than timeout
- `cancel.forced_termination`: If entities are forcibly terminated

## Context Propagation Model

### Span Context Storage

Extend `ObservabilityState` to include OpenTelemetry span context:

```rust
#[derive(Debug, Clone)]
pub struct ObservabilityState {
    // Existing fields
    collector: Option<LogCollector>,
    context: DiagnosticContext,
    trace: Option<TraceBufferHandle>,
    
    // OpenTelemetry span context
    otel_span_context: Option<SpanContext>,
    active_span_id: Option<EntityId>,
    span_stack: Vec<SpanEntry>,
}

#[derive(Debug, Clone)]
pub struct SpanContext {
    trace_id: opentelemetry::TraceId,
    span_id: opentelemetry::SpanId,
    trace_flags: opentelemetry::TraceFlags,
    trace_state: opentelemetry::TraceState,
    is_remote: bool,
}

#[derive(Debug, Clone)]
pub struct SpanEntry {
    entity_id: EntityId,
    span_type: SpanType,
    span_context: SpanContext,
}
```

### Context Inheritance Rules

1. **Region Inheritance**:
   ```rust
   impl Cx {
       pub fn fork_for_child_region(&self, child_region: RegionId) -> Self {
           let mut child_cx = self.clone();
           
           // Region spans inherit from parent region span
           if let Some(parent_span_context) = self.current_span_context() {
               child_cx.set_parent_span_context(parent_span_context);
           }
           
           child_cx
       }
   }
   ```

2. **Task Inheritance**:
   ```rust
   impl Cx {
       pub fn fork_for_task(&self, task_id: TaskId) -> Self {
           let mut task_cx = self.clone();
           
           // Task spans inherit from region span
           if let Some(region_span_context) = self.region_span_context() {
               task_cx.set_parent_span_context(region_span_context);
           }
           
           task_cx
       }
   }
   ```

3. **Operation Inheritance**:
   ```rust
   impl Cx {
       pub fn enter_operation_span(&self, op_type: &str) -> OperationSpanGuard {
           // Operation spans inherit from current task span
           let parent_context = self.task_span_context();
           OperationSpanGuard::new(op_type, parent_context, self.clone())
       }
   }
   ```

### Span Context APIs

```rust
impl Cx {
    /// Gets the current active span context (highest on stack).
    pub fn current_span_context(&self) -> Option<SpanContext> {
        let obs = self.observability.read();
        obs.span_stack.last().map(|entry| entry.span_context.clone())
    }
    
    /// Gets the span context for the current region.
    pub fn region_span_context(&self) -> Option<SpanContext> {
        let obs = self.observability.read();
        obs.span_stack.iter()
            .find(|entry| matches!(entry.entity_id, EntityId::Region(_)))
            .map(|entry| entry.span_context.clone())
    }
    
    /// Gets the span context for the current task.
    pub fn task_span_context(&self) -> Option<SpanContext> {
        let obs = self.observability.read();
        obs.span_stack.iter()
            .find(|entry| matches!(entry.entity_id, EntityId::Task(_)))
            .map(|entry| entry.span_context.clone())
    }
    
    /// Pushes a new span context onto the stack.
    pub fn push_span_context(&self, entity_id: EntityId, span_type: SpanType, span_context: SpanContext) {
        let mut obs = self.observability.write();
        obs.span_stack.push(SpanEntry {
            entity_id,
            span_type,
            span_context,
        });
    }
    
    /// Pops the span context for the given entity.
    pub fn pop_span_context(&self, entity_id: EntityId) {
        let mut obs = self.observability.write();
        obs.span_stack.retain(|entry| entry.entity_id != entity_id);
    }
}
```

## Integration with Structured Concurrency Runtime

### Region Table Integration

```rust
impl RegionTable {
    pub fn create_region(
        &mut self,
        parent: Option<RegionId>,
        limits: RegionLimits,
        cx: &Cx,
    ) -> Result<RegionId, RegionCreateError> {
        let region_id = self.allocate_region_id();
        
        // Create region record (existing logic)
        let region = RegionRecord::new(region_id, parent, limits);
        self.regions.insert(region_id, region);
        
        // Create region span
        if cx.has_otel_tracer() {
            let parent_span_context = parent
                .and_then(|pid| cx.span_context_for_region(pid));
                
            cx.create_region_span(
                region_id,
                parent_span_context,
                &limits,
            );
        }
        
        Ok(region_id)
    }
    
    pub fn close_region(&mut self, region_id: RegionId, cx: &Cx) -> Result<(), RegionError> {
        // Ensure quiescence (existing logic)
        let region = self.regions.get(&region_id)
            .ok_or(RegionError::NotFound(region_id))?;
            
        if !region.is_quiescent() {
            return Err(RegionError::NotQuiescent(region_id));
        }
        
        // Close region span
        if cx.has_otel_tracer() {
            cx.complete_region_span(region_id, RegionOutcome::Quiescence);
        }
        
        // Remove region record
        self.regions.remove(&region_id);
        Ok(())
    }
}
```

### Task Table Integration

```rust
impl TaskTable {
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
        
        // Create task record (existing logic)
        let task = TaskRecord::new(task_id, region, std::any::type_name::<T>());
        self.tasks.insert(task_id, task);
        
        // Create task span
        if cx.has_otel_tracer() {
            let region_span_context = cx.span_context_for_region(region);
            let source_location = std::panic::Location::caller();
            
            cx.create_task_span(
                task_id,
                region,
                region_span_context,
                std::any::type_name::<T>(),
                source_location,
            );
        }
        
        Ok(task_id)
    }
    
    pub fn complete_task(&mut self, task_id: TaskId, outcome: TaskOutcome, cx: &Cx) {
        // Complete task span first
        if cx.has_otel_tracer() {
            cx.complete_task_span(task_id, outcome);
        }
        
        // Remove task record (existing logic)
        self.tasks.remove(&task_id);
    }
}
```

### I/O Operation Integration

```rust
// Example: TCP read operation with span
async fn tcp_read(stream: &mut TcpStream, buf: &mut [u8], cx: &Cx) -> io::Result<usize> {
    let _span_guard = cx.enter_operation_span(
        "tcp_read",
        &format!("TcpStream-{}", stream.peer_addr()?),
    );
    
    // Perform the actual read
    let bytes_read = stream.read(buf).await?;
    
    // Span automatically completed by drop guard
    Ok(bytes_read)
}

// Example: Timer operation with span  
async fn sleep(duration: Duration, cx: &Cx) {
    let _span_guard = cx.enter_operation_span(
        "timer_sleep",
        &format!("duration_ms={}", duration.as_millis()),
    );
    
    // Perform the actual sleep
    crate::time::sleep(duration).await;
    
    // Span automatically completed by drop guard
}
```

## Performance Optimization

### Lazy Span Materialization

Spans are created as lightweight records and materialized only when:
1. They accumulate enough operations (configurable threshold)
2. They complete their lifecycle
3. A child span needs to reference them

```rust
#[derive(Debug)]
pub enum SpanState {
    Pending {
        attributes: Vec<KeyValue>,
        start_time: Time,
        operation_count: u64,
    },
    Active {
        span: Box<dyn opentelemetry::trace::Span>,
        start_time: Time,
    },
    Completed,
}
```

### Sampling Strategy

```rust
#[derive(Debug, Clone)]
pub struct SpanSamplingConfig {
    /// Global sampling rate for all spans
    pub global_rate: f64,
    
    /// Per-span-type sampling overrides
    pub span_type_rates: HashMap<SpanType, f64>,
    
    /// Always sample certain span types
    pub always_sample: HashSet<SpanType>,
    
    /// Sample based on trace importance
    pub importance_threshold: f64,
}

impl SpanSamplingConfig {
    pub fn should_sample(&self, span_type: SpanType, importance: f64) -> bool {
        // Always sample if configured
        if self.always_sample.contains(&span_type) {
            return true;
        }
        
        // Check importance threshold
        if importance >= self.importance_threshold {
            return true;
        }
        
        // Use configured rate
        let rate = self.span_type_rates.get(&span_type)
            .copied()
            .unwrap_or(self.global_rate);
            
        fastrand::f64() < rate
    }
}
```

### Memory Management

```rust
#[derive(Debug)]
pub struct SpanMemoryConfig {
    /// Maximum number of concurrent active spans
    pub max_active_spans: usize,
    
    /// Maximum number of pending spans awaiting materialization
    pub max_pending_spans: usize,
    
    /// Cleanup completed spans after this duration
    pub span_retention: Duration,
    
    /// Maximum attribute value length
    pub max_attribute_length: usize,
}
```

## Testing Strategy

### Unit Tests

Test individual span creation and lifecycle:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::trace::noop::NoopTracer;
    
    #[test]
    fn test_region_span_lifecycle() {
        let tracer = NoopTracer::new();
        let storage = SpanStorage::new(Default::default());
        
        let region_id = RegionId::new(1);
        let entity_id = EntityId::Region(region_id);
        
        // Create pending span
        storage.create_pending_span(
            SpanType::Region,
            entity_id,
            "test_region".to_string(),
            Time::ZERO,
            None,
        );
        
        // Materialize and end span
        storage.materialize_span(entity_id, &tracer);
        storage.end_span(entity_id, &tracer);
        
        let (created, materialized, _, _, _, _) = storage.stats();
        assert_eq!(created, 1);
        assert_eq!(materialized, 1);
    }
}
```

### Integration Tests

Test span hierarchy and context propagation:

```rust
#[cfg(test)]
mod integration_tests {
    use super::*;
    
    #[tokio::test]
    async fn test_hierarchical_spans() {
        let runtime = RuntimeBuilder::new()
            .with_otel_structured_concurrency(Default::default())
            .build()
            .unwrap();
            
        runtime.region(|cx| async move {
            // Region span created automatically
            
            let task_handle = cx.spawn(|cx| async move {
                // Task span created automatically
                
                let _guard = cx.enter_operation_span("test_op", "resource_1");
                // Operation span created automatically
                
                crate::time::sleep(Duration::from_millis(10), &cx).await;
                // Timer operation span created
                
                "result"
            });
            
            task_handle.await
        }).await;
        
        // Verify span hierarchy was created correctly
        // (Would need access to collected spans for verification)
    }
}
```

This span model provides comprehensive observability for structured concurrency operations while maintaining the performance and correctness guarantees of the asupersync runtime.