//! Runtime Integration for Cancellation Tracing
//!
//! This module provides integration points for the cancellation tracer with the
//! asupersync runtime. It shows how the tracer would be wired into the task and
//! region lifecycle to provide comprehensive cancellation monitoring.
//!
//! NOTE: This is a foundation module that will be fully activated when
//! asupersync-6r9mk9 (Cancel-Correctness Property Oracle) is completed.

use crate::observability::cancellation_tracer::{
    CancellationTracer, CancellationTracerConfig, EntityType, TraceId,
};
use crate::record::region::RegionState;
use crate::types::{CancelKind, CancelReason, RegionId, TaskId};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

/// Integration hooks for cancellation tracing in the runtime.
#[derive(Debug)]
pub struct CancellationTracerIntegration {
    tracer: Arc<CancellationTracer>,
    /// Active traces by task ID.
    task_traces: Arc<RwLock<HashMap<TaskId, TraceId>>>,
    /// Active traces by region ID.
    region_traces: Arc<RwLock<HashMap<RegionId, TraceId>>>,
}

impl CancellationTracerIntegration {
    /// Creates a new tracer integration with the given configuration.
    pub fn new(config: CancellationTracerConfig) -> Self {
        Self {
            tracer: Arc::new(CancellationTracer::new(config)),
            task_traces: Arc::new(RwLock::new(HashMap::new())),
            region_traces: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Gets a reference to the underlying tracer.
    pub fn tracer(&self) -> &Arc<CancellationTracer> {
        &self.tracer
    }

    /// Called when a task cancellation is initiated.
    ///
    /// This should be called from TaskRecord::request_cancel_with_budget()
    /// when the state transitions to CancelRequested.
    pub fn on_task_cancel_initiated(
        &self,
        task_id: TaskId,
        cancel_reason: &CancelReason,
        cancel_kind: CancelKind,
        parent_task: Option<TaskId>,
    ) {
        // Check if this is part of an existing trace
        let (trace_id, _is_new_trace) = if let Some(parent) = parent_task {
            if let Some(&parent_trace_id) = self.task_traces.read().get(&parent) {
                (parent_trace_id, false)
            } else {
                let trace_id = self.tracer.start_trace(
                    format!("{task_id:?}"),
                    EntityType::Task,
                    cancel_reason,
                    cancel_kind,
                );
                (trace_id, true)
            }
        } else {
            let trace_id = self.tracer.start_trace(
                format!("{task_id:?}"),
                EntityType::Task,
                cancel_reason,
                cancel_kind,
            );
            (trace_id, true)
        };

        // Record the step
        let parent_entity = parent_task.map(|id| format!("{id:?}"));
        self.tracer.record_step(
            trace_id,
            format!("{task_id:?}"),
            EntityType::Task,
            cancel_reason,
            cancel_kind,
            "CancelRequested".to_string(),
            parent_entity,
            false, // Not yet completed
        );

        // Track the trace for this task
        self.task_traces.write().insert(task_id, trace_id);
    }

    /// Called when a task acknowledges cancellation.
    ///
    /// This should be called from TaskRecord::acknowledge_cancel()
    /// when the state transitions to Cancelling.
    pub fn on_task_cancel_acknowledged(
        &self,
        task_id: TaskId,
        cancel_reason: &CancelReason,
        cancel_kind: CancelKind,
    ) {
        if let Some(&trace_id) = self.task_traces.read().get(&task_id) {
            self.tracer.record_step(
                trace_id,
                format!("{task_id:?}"),
                EntityType::Task,
                cancel_reason,
                cancel_kind,
                "Cancelling".to_string(),
                None,  // No parent for acknowledgment step
                false, // Still propagating
            );
        }
    }

    /// Called when a task enters finalizing phase.
    ///
    /// This should be called when TaskState transitions to Finalizing.
    pub fn on_task_finalizing(
        &self,
        task_id: TaskId,
        cancel_reason: &CancelReason,
        cancel_kind: CancelKind,
    ) {
        if let Some(&trace_id) = self.task_traces.read().get(&task_id) {
            self.tracer.record_step(
                trace_id,
                format!("{task_id:?}"),
                EntityType::Task,
                cancel_reason,
                cancel_kind,
                "Finalizing".to_string(),
                None,
                false, // Still finalizing
            );
        }
    }

    /// Called when a task completes cancellation.
    ///
    /// This should be called from TaskRecord::complete() when the task
    /// reaches terminal state with Cancelled outcome.
    pub fn on_task_cancel_completed(&self, task_id: TaskId) {
        if let Some(trace_id) = self.task_traces.write().remove(&task_id) {
            // Check if this was the root task of the trace
            let should_complete_trace = {
                let task_traces = self.task_traces.read();
                let region_traces = self.region_traces.read();

                // If no other tasks or regions reference this trace, complete it
                !task_traces.values().any(|&id| id == trace_id)
                    && !region_traces.values().any(|&id| id == trace_id)
            };

            if should_complete_trace {
                self.tracer.complete_trace(trace_id);
            }
        }
    }

    /// Called when a region begins cancellation.
    ///
    /// This should be called from RegionRecord::begin_close() when cancellation
    /// is propagated to child regions.
    pub fn on_region_cancel_initiated(
        &self,
        region_id: RegionId,
        cancel_reason: &CancelReason,
        cancel_kind: CancelKind,
        parent_region: Option<RegionId>,
    ) {
        // Check if this is part of an existing trace
        let (trace_id, _is_new_trace) = if let Some(parent) = parent_region {
            if let Some(&parent_trace_id) = self.region_traces.read().get(&parent) {
                (parent_trace_id, false)
            } else {
                let trace_id = self.tracer.start_trace(
                    format!("{region_id:?}"),
                    EntityType::Region,
                    cancel_reason,
                    cancel_kind,
                );
                (trace_id, true)
            }
        } else {
            let trace_id = self.tracer.start_trace(
                format!("{region_id:?}"),
                EntityType::Region,
                cancel_reason,
                cancel_kind,
            );
            (trace_id, true)
        };

        // Record the step
        let parent_entity = parent_region.map(|id| format!("{id:?}"));
        self.tracer.record_step(
            trace_id,
            format!("{region_id:?}"),
            EntityType::Region,
            cancel_reason,
            cancel_kind,
            "Closing".to_string(),
            parent_entity,
            false,
        );

        // Track the trace for this region
        self.region_traces.write().insert(region_id, trace_id);
    }

    /// Called when a region state transitions during cancellation.
    pub fn on_region_state_transition(
        &self,
        region_id: RegionId,
        _from_state: RegionState,
        to_state: RegionState,
        cancel_reason: Option<&CancelReason>,
        cancel_kind: Option<CancelKind>,
    ) {
        if let Some(&trace_id) = self.region_traces.read().get(&region_id) {
            // Only record if this is a cancellation-related transition
            if matches!(
                to_state,
                RegionState::Closing | RegionState::Draining | RegionState::Finalizing
            ) {
                if let (Some(reason), Some(kind)) = (cancel_reason, cancel_kind) {
                    self.tracer.record_step(
                        trace_id,
                        format!("{region_id:?}"),
                        EntityType::Region,
                        reason,
                        kind,
                        format!("{to_state:?}"),
                        None,
                        to_state == RegionState::Closed, // Complete when closed
                    );
                }
            }
        }
    }

    /// Called when a region closes completely.
    ///
    /// This should be called when RegionState reaches Closed.
    pub fn on_region_closed(&self, region_id: RegionId) {
        if let Some(trace_id) = self.region_traces.write().remove(&region_id) {
            // Check if this was the root region of the trace
            let should_complete_trace = {
                let task_traces = self.task_traces.read();
                let region_traces = self.region_traces.read();

                // If no other tasks or regions reference this trace, complete it
                !task_traces.values().any(|&id| id == trace_id)
                    && !region_traces.values().any(|&id| id == trace_id)
            };

            if should_complete_trace {
                self.tracer.complete_trace(trace_id);
            }
        }
    }

    /// Gets traces currently being tracked for tasks.
    pub fn active_task_traces(&self) -> HashMap<TaskId, TraceId> {
        self.task_traces.read().clone()
    }

    /// Gets traces currently being tracked for regions.
    pub fn active_region_traces(&self) -> HashMap<RegionId, TraceId> {
        self.region_traces.read().clone()
    }

    /// Cleanup orphaned traces (for maintenance).
    pub fn cleanup_orphaned_traces(&self) {
        // This would be called periodically to clean up traces that may have
        // been orphaned due to unexpected termination or other edge cases.
        // Implementation would check for traces older than a threshold and
        // complete them if no active references exist.
    }
}

/// Example integration points showing where hooks would be called.
#[cfg(feature = "test-internals")]
pub mod integration_examples {

    /// Example of how TaskRecord::request_cancel_with_budget would be modified.
    ///
    /// ```rust,ignore
    /// impl TaskRecord {
    ///     pub fn request_cancel_with_budget(
    ///         &mut self,
    ///         reason: CancelReason,
    ///         cleanup_budget: Budget,
    ///         tracer: Option<&CancellationTracerIntegration>,
    ///     ) -> bool {
    ///         // ... existing logic ...
    ///
    ///         match &mut self.state {
    ///             TaskState::Created | TaskState::Running => {
    ///                 self.state = TaskState::CancelRequested {
    ///                     reason: reason.clone(),
    ///                     cleanup_budget,
    ///                 };
    ///                 self.phase.store(TaskPhase::CancelRequested);
    ///
    ///                 // NEW: Hook for cancellation tracing
    ///                 if let Some(tracer) = tracer {
    ///                     tracer.on_task_cancel_initiated(
    ///                         self.id,
    ///                         &reason,
    ///                         reason.kind,
    ///                         None, // Would need parent task context
    ///                     );
    ///                 }
    ///
    ///                 true
    ///             }
    ///             // ... other cases ...
    ///         }
    ///     }
    /// }
    /// ```
    pub fn example_task_integration() {
        // This is just documentation - the actual integration would happen
        // in the TaskRecord and RegionRecord implementations.
    }

    /// Example of how RegionRecord::begin_close would be modified.
    ///
    /// ```rust,ignore
    /// impl RegionRecord {
    ///     pub fn begin_close(
    ///         &mut self,
    ///         reason: Option<CancelReason>,
    ///         tracer: Option<&CancellationTracerIntegration>,
    ///     ) {
    ///         // ... existing logic ...
    ///
    ///         if let Some(reason) = &reason {
    ///             // NEW: Hook for cancellation tracing
    ///             if let Some(tracer) = tracer {
    ///                 tracer.on_region_cancel_initiated(
    ///                     self.id,
    ///                     reason,
    ///                     reason.kind,
    ///                     self.parent_id, // Parent region for trace propagation
    ///                 );
    ///             }
    ///         }
    ///
    ///         // ... rest of implementation ...
    ///     }
    /// }
    /// ```
    pub fn example_region_integration() {
        // This is just documentation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integration_creation() {
        let config = CancellationTracerConfig::default();
        let integration = CancellationTracerIntegration::new(config);

        let stats = integration.tracer().stats();
        assert_eq!(stats.traces_collected, 0);
    }

    #[test]
    fn test_task_cancel_flow() {
        let config = CancellationTracerConfig::default();
        let integration = CancellationTracerIntegration::new(config);

        let task_id = TaskId::new(1);
        let cancel_reason = CancelReason::with_user_reason("test".to_string());
        let cancel_kind = CancelKind::User;

        // Initiate cancellation
        integration.on_task_cancel_initiated(task_id, &cancel_reason, cancel_kind, None);

        // Task should be tracked
        let active_traces = integration.active_task_traces();
        assert!(active_traces.contains_key(&task_id));

        // Acknowledge cancellation
        integration.on_task_cancel_acknowledged(task_id, &cancel_reason, cancel_kind);

        // Enter finalizing
        integration.on_task_finalizing(task_id, &cancel_reason, cancel_kind);

        // Complete cancellation
        integration.on_task_cancel_completed(task_id);

        // Task should no longer be tracked
        let active_traces = integration.active_task_traces();
        assert!(!active_traces.contains_key(&task_id));

        // Should have recorded a complete trace
        let stats = integration.tracer().stats();
        assert_eq!(stats.traces_collected, 1);
        assert!(stats.steps_recorded >= 3); // At least 3 steps recorded
    }

    #[test]
    fn test_region_cancel_flow() {
        let config = CancellationTracerConfig::default();
        let integration = CancellationTracerIntegration::new(config);

        let region_id = RegionId::new_for_test(1, 0);
        let cancel_reason = CancelReason::with_user_reason("region test".to_string());
        let cancel_kind = CancelKind::User;

        // Initiate region cancellation
        integration.on_region_cancel_initiated(region_id, &cancel_reason, cancel_kind, None);

        // Region should be tracked
        let active_traces = integration.active_region_traces();
        assert!(active_traces.contains_key(&region_id));

        // Transition through states
        integration.on_region_state_transition(
            region_id,
            RegionState::Open,
            RegionState::Closing,
            Some(&cancel_reason),
            Some(cancel_kind),
        );

        integration.on_region_state_transition(
            region_id,
            RegionState::Closing,
            RegionState::Draining,
            Some(&cancel_reason),
            Some(cancel_kind),
        );

        integration.on_region_state_transition(
            region_id,
            RegionState::Draining,
            RegionState::Finalizing,
            Some(&cancel_reason),
            Some(cancel_kind),
        );

        // Close region
        integration.on_region_closed(region_id);

        // Region should no longer be tracked
        let active_traces = integration.active_region_traces();
        assert!(!active_traces.contains_key(&region_id));

        // Should have recorded a complete trace
        let stats = integration.tracer().stats();
        assert_eq!(stats.traces_collected, 1);
        assert!(stats.steps_recorded >= 3);
    }
}
